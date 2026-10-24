//! Dynamic admission webhooks (admission.k8s.io/v1).
//!
//! The REST handlers are synchronous and must not await, so [`run`] wraps them: it dry-runs the
//! request through `ApiServer::handle` (authorization, built-in admission and validation, no
//! persistence), sends the resulting object through the matching mutating then validating
//! webhooks, and tells the transport to execute the real request, with the mutated object as
//! the body if a webhook patched it. The webhook calls are the only awaits.

use crate::api::{ApiServer, Reply, Req, Route};
use crate::object::{obj, ApiError, Selector};
use crate::patch;
use alloc::boxed::Box;
use alloc::format;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_crypto::tls::ClientConfig;
use kr_crypto::x509;
use kr_fmt::json::{self, Value};
use kr_net::dns::SystemResolver;
use kr_net::http1::client::{Client as Http, Config as HttpConfig};
use kr_net::tcp::{HostsResolver, IpAddr, Resolver};
use kr_net::tls::TlsConnector;

const GROUP: &str = "admissionregistration.k8s.io";

/// Replacement for the original request, when a webhook mutated the object.
pub struct Rewrite {
    pub method: &'static str,
    pub body: Vec<u8>,
}

// ---- matching ----

fn strs<'a>(v: &'a Value, key: &str) -> Vec<&'a str> {
    v.get(key).and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default()
}

fn resource_matches(entries: &[&str], plural: &str, sub: Option<&str>) -> bool {
    entries.iter().any(|e| match e.split_once('/') {
        None => sub.is_none() && (*e == "*" || *e == plural),
        Some(("*", "*")) => true,
        Some((r, s)) => sub.is_some_and(|x| s == "*" || s == x) && (r == "*" || r == plural),
    })
}

fn rule_matches(rule: &Value, rt: &Route, op: &str) -> bool {
    let any = |key: &str, want: &str| {
        let l = strs(rule, key);
        l.iter().any(|x| *x == "*" || *x == want)
    };
    let scope_ok = match rule.get("scope").and_then(Value::as_str).unwrap_or("*") {
        "Cluster" => !rt.res.namespaced,
        "Namespaced" => rt.res.namespaced,
        _ => true,
    };
    any("operations", op) && any("apiGroups", rt.res.group) && any("apiVersions", rt.res.version) && resource_matches(&strs(rule, "resources"), rt.res.plural, rt.sub.as_deref()) && scope_ok
}

fn rules_match(wh: &Value, rt: &Route, op: &str) -> bool {
    wh.get("rules").and_then(Value::as_array).is_some_and(|r| r.iter().any(|r| rule_matches(r, rt, op)))
}

/// LabelSelector (matchLabels/matchExpressions) as an equivalent [`Selector`]; empty/absent
/// selects everything.
fn label_selector(v: Option<&Value>) -> Option<Selector> {
    let Some(v) = v else { return Some(Selector::default()) };
    let mut parts: Vec<String> = Vec::new();
    for (k, x) in v.get("matchLabels").and_then(Value::as_object).unwrap_or(&[]) {
        parts.push(format!("{k}={}", x.as_str().unwrap_or("")));
    }
    for e in v.get("matchExpressions").and_then(Value::as_array).unwrap_or(&[]) {
        let key = e.get("key").and_then(Value::as_str)?;
        let vals = strs(e, "values").join(",");
        parts.push(match e.get("operator").and_then(Value::as_str)? {
            "In" => format!("{key} in ({vals})"),
            "NotIn" => format!("{key} notin ({vals})"),
            "Exists" => key.to_string(),
            "DoesNotExist" => format!("!{key}"),
            _ => return None,
        });
    }
    Selector::parse(&parts.join(",")).ok()
}

// ---- matchConditions: a small CEL subset ----

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Str(String),
    Num(f64),
    Id(String),
    Op(&'static str),
}

fn lex(s: &str) -> Result<Vec<Tok>, String> {
    let b: Vec<char> = s.chars().collect();
    let (mut i, mut out) = (0, Vec::new());
    while i < b.len() {
        let c = b[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '"' || c == '\'' {
            let mut v = String::new();
            i += 1;
            while i < b.len() && b[i] != c {
                if b[i] == '\\' && i + 1 < b.len() {
                    i += 1;
                    v.push(match b[i] {
                        'n' => '\n',
                        't' => '\t',
                        o => o,
                    });
                } else {
                    v.push(b[i]);
                }
                i += 1;
            }
            if i >= b.len() {
                return Err("unterminated string".into());
            }
            i += 1;
            out.push(Tok::Str(v));
        } else if c.is_ascii_digit() {
            let st = i;
            while i < b.len() && (b[i].is_ascii_digit() || b[i] == '.') {
                i += 1;
            }
            let n: String = b[st..i].iter().collect();
            if matches!(b.get(i), Some('u')) {
                i += 1;
            }
            out.push(Tok::Num(n.parse().map_err(|_| "bad number")?));
        } else if c.is_alphabetic() || c == '_' {
            let st = i;
            while i < b.len() && (b[i].is_alphanumeric() || b[i] == '_') {
                i += 1;
            }
            out.push(Tok::Id(b[st..i].iter().collect()));
        } else {
            let two: String = b[i..(i + 2).min(b.len())].iter().collect();
            let op = ["||", "&&", "==", "!=", "<=", ">="].into_iter().find(|o| *o == two);
            if let Some(op) = op {
                out.push(Tok::Op(op));
                i += 2;
            } else {
                let op = ["<", ">", "!", "(", ")", "[", "]", ".", ",", "+"].into_iter().find(|o| o.starts_with(c)).ok_or_else(|| format!("unexpected character {c:?}"))?;
                out.push(Tok::Op(op));
                i += 1;
            }
        }
    }
    Ok(out)
}

enum E {
    Lit(Value),
    Var(String),
    Field(Box<E>, String),
    Index(Box<E>, Box<E>),
    Method(Box<E>, String, Vec<E>),
    Func(String, Vec<E>),
    Not(Box<E>),
    Bin(&'static str, Box<E>, Box<E>),
    List(Vec<E>),
}

struct P {
    t: Vec<Tok>,
    i: usize,
}

impl P {
    fn peek_op(&self, op: &str) -> bool {
        matches!(self.t.get(self.i), Some(Tok::Op(o)) if *o == op)
    }
    fn eat(&mut self, op: &str) -> bool {
        let r = self.peek_op(op);
        if r {
            self.i += 1;
        }
        r
    }
    fn expect(&mut self, op: &str) -> Result<(), String> {
        if self.eat(op) {
            Ok(())
        } else {
            Err(format!("expected {op:?}"))
        }
    }
    fn or(&mut self) -> Result<E, String> {
        let mut l = self.and()?;
        while self.eat("||") {
            l = E::Bin("||", Box::new(l), Box::new(self.and()?));
        }
        Ok(l)
    }
    fn and(&mut self) -> Result<E, String> {
        let mut l = self.rel()?;
        while self.eat("&&") {
            l = E::Bin("&&", Box::new(l), Box::new(self.rel()?));
        }
        Ok(l)
    }
    fn rel(&mut self) -> Result<E, String> {
        let l = self.add()?;
        for op in ["==", "!=", "<=", ">=", "<", ">"] {
            if self.eat(op) {
                return Ok(E::Bin(op, Box::new(l), Box::new(self.add()?)));
            }
        }
        if matches!(self.t.get(self.i), Some(Tok::Id(i)) if i == "in") {
            self.i += 1;
            return Ok(E::Bin("in", Box::new(l), Box::new(self.add()?)));
        }
        Ok(l)
    }
    fn add(&mut self) -> Result<E, String> {
        let mut l = self.unary()?;
        while self.eat("+") {
            l = E::Bin("+", Box::new(l), Box::new(self.unary()?));
        }
        Ok(l)
    }
    fn unary(&mut self) -> Result<E, String> {
        if self.eat("!") {
            return Ok(E::Not(Box::new(self.unary()?)));
        }
        self.postfix()
    }
    fn args(&mut self) -> Result<Vec<E>, String> {
        let mut a = Vec::new();
        while !self.peek_op(")") {
            a.push(self.or()?);
            if !self.eat(",") {
                break;
            }
        }
        self.expect(")")?;
        Ok(a)
    }
    fn postfix(&mut self) -> Result<E, String> {
        let mut e = self.primary()?;
        loop {
            if self.eat(".") {
                let Some(Tok::Id(n)) = self.t.get(self.i).cloned() else { return Err("expected field name".into()) };
                self.i += 1;
                e = if self.eat("(") { E::Method(Box::new(e), n, self.args()?) } else { E::Field(Box::new(e), n) };
            } else if self.eat("[") {
                let k = self.or()?;
                self.expect("]")?;
                e = E::Index(Box::new(e), Box::new(k));
            } else {
                return Ok(e);
            }
        }
    }
    fn primary(&mut self) -> Result<E, String> {
        let t = self.t.get(self.i).cloned().ok_or("unexpected end of expression")?;
        self.i += 1;
        match t {
            Tok::Str(s) => Ok(E::Lit(Value::String(s))),
            Tok::Num(n) => Ok(E::Lit(Value::Number(json::Number::from_f64(n).ok_or("bad number")?))),
            Tok::Id(i) => match i.as_str() {
                "true" => Ok(E::Lit(Value::Bool(true))),
                "false" => Ok(E::Lit(Value::Bool(false))),
                "null" => Ok(E::Lit(Value::Null)),
                _ if self.eat("(") => Ok(E::Func(i, self.args()?)),
                _ => Ok(E::Var(i)),
            },
            Tok::Op("(") => {
                let e = self.or()?;
                self.expect(")")?;
                Ok(e)
            }
            Tok::Op("[") => {
                let mut a = Vec::new();
                while !self.peek_op("]") {
                    a.push(self.or()?);
                    if !self.eat(",") {
                        break;
                    }
                }
                self.expect("]")?;
                Ok(E::List(a))
            }
            Tok::Op(o) => Err(format!("unexpected {o:?}")),
        }
    }
}

fn num_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        _ => a == b,
    }
}

fn truth(v: Result<Value, String>) -> Result<bool, String> {
    match v? {
        Value::Bool(b) => Ok(b),
        _ => Err("expected a boolean".into()),
    }
}

fn eval(e: &E, vars: &[(&str, &Value)]) -> Result<Value, String> {
    Ok(match e {
        E::Lit(v) => v.clone(),
        E::Var(n) => vars.iter().find(|(k, _)| k == n).map(|(_, v)| (*v).clone()).ok_or_else(|| format!("undeclared reference to {n:?}"))?,
        E::Field(b, n) => eval(b, vars)?.get(n).cloned().ok_or_else(|| format!("no such key: {n}"))?,
        E::Index(b, k) => match (eval(b, vars)?, eval(k, vars)?) {
            (o @ Value::Object(_), Value::String(k)) => o.get(&k).cloned().ok_or_else(|| format!("no such key: {k}"))?,
            (Value::Array(a), Value::Number(n)) => a.get(n.as_f64() as usize).cloned().ok_or("index out of bounds")?,
            _ => return Err("invalid index".into()),
        },
        E::Not(x) => Value::Bool(!truth(eval(x, vars))?),
        E::List(a) => Value::Array(a.iter().map(|x| eval(x, vars)).collect::<Result<_, _>>()?),
        E::Func(f, a) => match (f.as_str(), a.as_slice()) {
            ("has", [E::Field(b, n)]) => Value::Bool(matches!(eval(b, vars)?, o @ Value::Object(_) if o.get(n).is_some())),
            ("size", [x]) => size(&eval(x, vars)?)?,
            _ => return Err(format!("unsupported function {f}")),
        },
        E::Method(b, m, a) => {
            let recv = eval(b, vars)?;
            if m == "size" && a.is_empty() {
                return size(&recv);
            }
            let (Value::String(s), [arg]) = (&recv, a.as_slice()) else { return Err(format!("unsupported method {m}")) };
            let Value::String(arg) = eval(arg, vars)? else { return Err("expected a string argument".into()) };
            Value::Bool(match m.as_str() {
                "startsWith" => s.starts_with(&arg),
                "endsWith" => s.ends_with(&arg),
                "contains" => s.contains(&arg),
                _ => return Err(format!("unsupported method {m}")),
            })
        }
        E::Bin(op, l, r) => match *op {
            "&&" | "||" => {
                let want = *op == "||";
                let (a, b) = (truth(eval(l, vars)), truth(eval(r, vars)));
                // Either side decides the result even if the other errored (CEL commutativity).
                if a == Ok(want) || b == Ok(want) {
                    Value::Bool(want)
                } else {
                    {
                        a?;
                        b?;
                        Value::Bool(!want)
                    }
                }
            }
            _ => {
                let (a, b) = (eval(l, vars)?, eval(r, vars)?);
                match *op {
                    "==" => Value::Bool(num_eq(&a, &b)),
                    "!=" => Value::Bool(!num_eq(&a, &b)),
                    "in" => Value::Bool(match &b {
                        Value::Array(x) => x.iter().any(|y| num_eq(&a, y)),
                        Value::Object(_) => a.as_str().is_some_and(|k| b.get(k).is_some()),
                        _ => return Err("invalid 'in' operand".into()),
                    }),
                    "+" => match (&a, &b) {
                        (Value::String(x), Value::String(y)) => Value::String(format!("{x}{y}")),
                        (Value::Number(x), Value::Number(y)) => Value::Number(json::Number::from_f64(x.as_f64() + y.as_f64()).ok_or("bad number")?),
                        _ => return Err("invalid '+' operands".into()),
                    },
                    _ => {
                        let ord = match (&a, &b) {
                            (Value::Number(x), Value::Number(y)) => x.as_f64().partial_cmp(&y.as_f64()),
                            (Value::String(x), Value::String(y)) => Some(x.cmp(y)),
                            _ => None,
                        }
                        .ok_or("invalid comparison")?;
                        Value::Bool(match *op {
                            "<" => ord.is_lt(),
                            "<=" => ord.is_le(),
                            ">" => ord.is_gt(),
                            _ => ord.is_ge(),
                        })
                    }
                }
            }
        },
    })
}

fn size(v: &Value) -> Result<Value, String> {
    let n = match v {
        Value::String(s) => s.chars().count(),
        Value::Array(a) => a.len(),
        Value::Object(o) => o.len(),
        _ => return Err("size() of unsupported type".into()),
    };
    Ok(Value::Number(json::Number::from_u64(n as u64)))
}

/// Evaluates a boolean CEL expression over `vars` (supported subset: `== != < <= > >= ! && || in +`,
/// field/index access, `has()`, `size()`, string `startsWith/endsWith/contains`, literals).
pub fn cel_bool(expr: &str, vars: &[(&str, &Value)]) -> Result<bool, String> {
    let mut p = P { t: lex(expr)?, i: 0 };
    let e = p.or()?;
    if p.i != p.t.len() {
        return Err("unexpected trailing tokens".into());
    }
    truth(eval(&e, vars))
}

// ---- calling ----

struct WhResolver(HostsResolver);

impl Resolver for WhResolver {
    async fn resolve(&self, host: &str) -> kr_net::Result<Vec<IpAddr>> {
        let l = self.0.lookup(host);
        if !l.is_empty() {
            return Ok(l);
        }
        SystemResolver::system().resolve(host).await
    }
}

fn failed(name: &str, why: &str) -> ApiError {
    ApiError::new(500, "InternalError", format!("Internal error occurred: failed calling webhook \"{name}\": {why}"))
}

struct Ctx<'a> {
    api: &'a ApiServer,
    rt: &'a Route,
    op: &'static str,
    user: crate::api::User,
    dry: bool,
    ns: Option<Value>,
}

enum Outcome {
    Skipped,
    Called(Value),
}

impl Ctx<'_> {
    fn gvk(&self) -> Value {
        obj(alloc::vec![("group", Value::from(self.rt.res.group)), ("version", Value::from(self.rt.res.version)), ("kind", Value::from(self.rt.res.kind))])
    }

    fn request(&self, cur: &Value, old: &Value) -> Value {
        let gvr = obj(alloc::vec![("group", Value::from(self.rt.res.group)), ("version", Value::from(self.rt.res.version)), ("resource", Value::from(self.rt.res.plural))]);
        let src = if cur.is_null() { old } else { cur };
        let name = self.rt.name.clone().or_else(|| src.pointer(&["metadata", "name"]).and_then(Value::as_str).map(String::from)).unwrap_or_default();
        let ns = if self.rt.res.plural == "namespaces" { name.clone() } else { self.rt.namespace.clone().unwrap_or_default() };
        let opts = match self.op {
            "CREATE" => "CreateOptions",
            "UPDATE" => "UpdateOptions",
            _ => "DeleteOptions",
        };
        let mut r = obj(alloc::vec![
            ("uid", Value::String(self.api.wh_uid())),
            ("kind", self.gvk()),
            ("resource", gvr.clone()),
        ]);
        if let Some(s) = &self.rt.sub {
            r.set("subResource", Value::from(s.as_str()));
        }
        r.set("requestKind", self.gvk());
        r.set("requestResource", gvr);
        if let Some(s) = &self.rt.sub {
            r.set("requestSubResource", Value::from(s.as_str()));
        }
        r.set("name", Value::String(name));
        if !ns.is_empty() {
            r.set("namespace", Value::String(ns));
        }
        r.set("operation", Value::from(self.op));
        r.set("userInfo", obj(alloc::vec![("username", Value::from(self.user.name.as_str())), ("groups", Value::Array(self.user.groups.iter().map(|g| Value::from(g.as_str())).collect()))]));
        r.set("object", cur.clone());
        r.set("oldObject", old.clone());
        r.set("dryRun", Value::Bool(self.dry));
        r.set("options", obj(alloc::vec![("kind", Value::from(opts)), ("apiVersion", Value::from("meta.k8s.io/v1"))]));
        r
    }

    /// Selectors and matchConditions. `Err` is an evaluation failure (failurePolicy applies).
    fn selected(&self, wh: &Value, cur: &Value, old: &Value, request: &Value) -> Result<bool, String> {
        if !rules_match(wh, self.rt, self.op) {
            return Ok(false);
        }
        let Some(ns_sel) = label_selector(wh.get("namespaceSelector")) else { return Ok(false) };
        if !ns_sel.is_empty() {
            let target = if self.rt.res.plural == "namespaces" { Some(if cur.is_null() { old } else { cur }) } else if self.rt.res.namespaced { self.ns.as_ref() } else { None };
            if target.is_some_and(|t| !ns_sel.matches(t)) {
                return Ok(false);
            }
        }
        let Some(obj_sel) = label_selector(wh.get("objectSelector")) else { return Ok(false) };
        if !obj_sel.is_empty() && !((!cur.is_null() && obj_sel.matches(cur)) || (!old.is_null() && obj_sel.matches(old))) {
            return Ok(false);
        }
        for c in wh.get("matchConditions").and_then(Value::as_array).unwrap_or(&[]) {
            let ex = c.get("expression").and_then(Value::as_str).unwrap_or("true");
            if !cel_bool(ex, &[("object", cur), ("oldObject", old), ("request", request)])? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn call(&self, wh: &Value, review: &str) -> Result<Value, String> {
        let cc = wh.get("clientConfig").ok_or("no clientConfig")?;
        let (url, hosts) = if let Some(u) = cc.get("url").and_then(Value::as_str) {
            (u.to_string(), String::new())
        } else {
            let svc = cc.get("service").ok_or("clientConfig has neither url nor service")?;
            let (sn, sns) = (svc.get("name").and_then(Value::as_str).unwrap_or(""), svc.get("namespace").and_then(Value::as_str).unwrap_or(""));
            let port = svc.get("port").and_then(Value::as_u64).unwrap_or(443);
            let path = svc.get("path").and_then(Value::as_str).unwrap_or("/");
            let s = self.api.wh_object("", "v1", "services", Some(sns), sn).ok_or_else(|| format!("service \"{sn}\" not found"))?;
            let ip = s.pointer(&["spec", "clusterIP"]).and_then(Value::as_str).filter(|i| i.contains('.')).ok_or("service has no cluster IP")?;
            let host = format!("{sn}.{sns}.svc");
            (format!("https://{host}:{port}{path}"), format!("{ip} {host}\n"))
        };
        let roots = match cc.get("caBundle").and_then(Value::as_str) {
            Some(b) => x509::pem_decode_all(core::str::from_utf8(&kr_fmt::base64::decode(b).map_err(|_| "invalid caBundle")?).map_err(|_| "invalid caBundle")?, "CERTIFICATE").map_err(|_| "invalid caBundle")?,
            None => Vec::new(),
        };
        let cfg = Rc::new(ClientConfig { pinned_ca: None, roots, client_cert: None, alpn: alloc::vec![b"http/1.1".to_vec()] });
        let secs = wh.get("timeoutSeconds").and_then(Value::as_u64).unwrap_or(10).clamp(1, 30);
        let http = Http::with_connector(
            TlsConnector::new(WhResolver(HostsResolver::from_contents(&hosts)), cfg),
            HttpConfig { max_redirects: 0, max_idle: 0, connect_timeout_ms: secs * 1000, head_timeout_ms: secs * 1000, read_timeout_ms: secs * 1000, user_agent: "kr-apiserver".to_string(), ..HttpConfig::default() },
        );
        let fut = async {
            let mut resp = http.request("POST", &url, &[("Content-Type", "application/json"), ("Accept", "application/json")], review.as_bytes()).await.map_err(|e| format!("Post \"{url}\": {e:?}"))?;
            if resp.status != 200 {
                return Err(format!("Post \"{url}\": webhook returned status {}", resp.status));
            }
            resp.read_to_end(8 << 20).await.map_err(|e| format!("reading response: {e:?}"))
        };
        let body = kr_rt::exec::timeout(secs * 1000, fut).await.map_err(|_| format!("Post \"{url}\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"))??;
        json::parse(&body).map_err(|_| "webhook response is not valid JSON".to_string())
    }

    /// Calls `wh` if it applies. `Ok(Skipped)` also covers errors ignored by `failurePolicy: Ignore`.
    async fn invoke(&self, wh: &Value, cur: &Value, old: &Value) -> Result<Outcome, ApiError> {
        let name = wh.get("name").and_then(Value::as_str).unwrap_or("");
        let ignore = wh.get("failurePolicy").and_then(Value::as_str) == Some("Ignore");
        let fail = |why: &str| if ignore { Ok(Outcome::Skipped) } else { Err(failed(name, why)) };
        let request = self.request(cur, old);
        match self.selected(wh, cur, old, &request) {
            Ok(false) => return Ok(Outcome::Skipped),
            Ok(true) => {}
            Err(e) => return fail(&e),
        }
        if self.dry && !matches!(wh.get("sideEffects").and_then(Value::as_str), Some("None" | "NoneOnDryRun")) {
            return Err(ApiError::bad_request(format!("admission webhook \"{name}\" does not support dry run")));
        }
        let uid = request.get("uid").and_then(Value::as_str).unwrap_or("").to_string();
        let review = json::to_string(&obj(alloc::vec![("apiVersion", Value::from("admission.k8s.io/v1")), ("kind", Value::from("AdmissionReview")), ("request", request)]));
        let resp = match self.call(wh, &review).await {
            Ok(r) => r,
            Err(e) => return fail(&e),
        };
        let Some(r) = resp.get("response") else { return fail("webhook response has no \"response\"") };
        if r.get("uid").and_then(Value::as_str) != Some(uid.as_str()) {
            return fail("expected response.uid to match request.uid");
        }
        if r.get("allowed").and_then(Value::as_bool) != Some(true) {
            let st = r.get("status");
            let s = |k: &str| st.and_then(|s| s.get(k)).and_then(Value::as_str).filter(|m| !m.is_empty());
            let denied = format!("admission webhook \"{name}\" denied the request");
            let msg = match s("message").or_else(|| s("reason")) {
                Some(m) => format!("{denied}: {m}"),
                None => format!("{denied} without explanation"),
            };
            let code = st.and_then(|s| s.get("code")).and_then(Value::as_u64).filter(|c| (400..600).contains(c)).unwrap_or(403) as u16;
            let reason = match code {
                400 => "BadRequest",
                401 => "Unauthorized",
                403 => "Forbidden",
                404 => "NotFound",
                409 => "Conflict",
                422 => "Invalid",
                500 => "InternalError",
                _ => "Failure",
            };
            return Err(ApiError::new(code, reason, msg));
        }
        Ok(Outcome::Called(r.clone()))
    }
}

fn gather(api: &ApiServer, plural: &str, rt: &Route, op: &str) -> Vec<Value> {
    let mut cfgs = api.wh_list(GROUP, "v1", plural);
    cfgs.sort_by(|a, b| a.pointer(&["metadata", "name"]).and_then(Value::as_str).cmp(&b.pointer(&["metadata", "name"]).and_then(Value::as_str)));
    cfgs.iter().flat_map(|c| c.get("webhooks").and_then(Value::as_array).unwrap_or(&[]).iter().cloned().collect::<Vec<_>>()).filter(|w| rules_match(w, rt, op)).collect()
}

/// Runs webhook admission for a write request. `Ok(None)`: execute the request unchanged.
/// `Err(reply)`: the request is rejected (or failed built-in admission) with that reply.
pub async fn run(api: &ApiServer, req: &Req<'_>) -> Result<Option<Rewrite>, Reply> {
    let op = match req.method {
        "POST" => "CREATE",
        "PUT" | "PATCH" => "UPDATE",
        "DELETE" => "DELETE",
        _ => return Ok(None),
    };
    let Some(rt) = api.wh_route(req.path) else { return Ok(None) };
    if rt.res.group == GROUP || !matches!(rt.sub.as_deref(), None | Some("status")) || (rt.name.is_none() && op != "CREATE") {
        return Ok(None);
    }
    let muts = gather(api, "mutatingwebhookconfigurations", &rt, op);
    let vals = gather(api, "validatingwebhookconfigurations", &rt, op);
    if muts.is_empty() && vals.is_empty() {
        return Ok(None);
    }
    let user = api.authenticate(req).map_err(Reply::err)?;
    let dry = req.query.split('&').any(|p| p == "dryRun=All");
    let q2 = if req.query.is_empty() { "dryRun=All".to_string() } else { format!("{}&dryRun=All", req.query) };
    let dreq = Req { method: req.method, path: req.path, query: &q2, content_type: req.content_type, accept: None, body: req.body, user: Some(user.clone()), bearer: req.bearer, headers: req.headers, authz_verb: None };
    let result = match api.handle(&dreq) {
        Reply::Json(c, b) if c < 300 => json::parse(b.as_bytes()).map_err(|_| Reply::err(ApiError::new(500, "InternalError", "bad admission result")))?,
        other => return Err(other),
    };
    let name = rt.name.clone().unwrap_or_default();
    let (obj0, old) = match op {
        "DELETE" => (Value::Null, result),
        "UPDATE" => (result, api.get_value(&rt, &name).map(|(_, v)| v).unwrap_or(Value::Null)),
        _ => (result, Value::Null),
    };
    let ns = rt.namespace.as_deref().and_then(|n| api.wh_object("", "v1", "namespaces", None, n));
    let ctx = Ctx { api, rt: &rt, op, user, dry, ns };
    let mut cur = obj0.clone();
    for wh in &muts {
        let Outcome::Called(r) = ctx.invoke(wh, &cur, &old).await.map_err(Reply::err)? else { continue };
        let wname = wh.get("name").and_then(Value::as_str).unwrap_or("");
        let Some(p) = r.get("patch").and_then(Value::as_str).filter(|p| !p.is_empty() && !cur.is_null()) else { continue };
        let applied = (|| {
            if r.get("patchType").and_then(Value::as_str) != Some("JSONPatch") {
                return Err("unsupported patchType".to_string());
            }
            let ops = json::parse(&kr_fmt::base64::decode(p).map_err(|_| "invalid patch encoding")?).map_err(|_| "invalid patch")?;
            let mut n = cur.clone();
            patch::json_patch(&mut n, &ops).map_err(|e| e.0)?;
            Ok(n)
        })();
        match applied {
            Ok(n) => cur = n,
            Err(e) if wh.get("failurePolicy").and_then(Value::as_str) == Some("Ignore") => {
                let _ = e;
            }
            Err(e) => return Err(Reply::err(failed(wname, &format!("error applying patch: {e}")))),
        }
    }
    for wh in &vals {
        ctx.invoke(wh, &cur, &old).await.map_err(Reply::err)?;
    }
    if cur == obj0 || cur.is_null() {
        return Ok(None);
    }
    if op == "UPDATE" {
        if let Some(rv) = old.pointer(&["metadata", "resourceVersion"]).cloned() {
            cur.entry_object("metadata").set("resourceVersion", rv);
        }
    }
    Ok(Some(Rewrite { method: if op == "CREATE" { "POST" } else { "PUT" }, body: json::to_string(&cur).into_bytes() }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cel() {
        let o = json::parse_str(r#"{"metadata":{"name":"skip-me","labels":{"a":"b"}},"spec":{"n":3}}"#).unwrap();
        let n = Value::Null;
        let v = [("object", &o), ("oldObject", &n)];
        let t = |e: &str| cel_bool(e, &v);
        assert_eq!(t("object.metadata.name == 'skip-me'"), Ok(true));
        assert_eq!(t("!(object.metadata.name.startsWith(\"skip\"))"), Ok(false));
        assert_eq!(t("has(object.metadata.labels) && !has(object.spec.x)"), Ok(true));
        assert_eq!(t("object.spec.n >= 3 && object.metadata.labels['a'] in ['b','c']"), Ok(true));
        assert_eq!(t("oldObject.metadata.name == 'x' || true"), Ok(true));
        assert!(t("oldObject.metadata.name == 'x'").is_err());
        assert_eq!(t("size(object.metadata.name) == 7 && object.metadata.name.contains('p-')"), Ok(true));
        assert!(t("1 +").is_err());
    }
}
