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
use core::cell::RefCell;
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

pub(crate) fn rule_matches(rule: &Value, rt: &Route, op: &str, exact: bool) -> bool {
    let any = |key: &str, want: &str| {
        let l = strs(rule, key);
        l.iter().any(|x| *x == "*" || *x == want)
    };
    let scope_ok = match rule.get("scope").and_then(Value::as_str).unwrap_or("*") {
        "Cluster" => !rt.res.namespaced,
        "Namespaced" => rt.res.namespaced,
        _ => true,
    };
    any("operations", op) && any("apiGroups", rt.res.group) && (!exact || any("apiVersions", rt.res.version)) && resource_matches(&strs(rule, "resources"), rt.res.plural, rt.sub.as_deref()) && scope_ok
}

/// `matchPolicy: Equivalent` (the default) matches the same group and resource in any version
/// (kr serves one version per resource, so no conversion is involved); `Exact` needs the version.
fn rules_match(wh: &Value, rt: &Route, op: &str) -> bool {
    let exact = wh.get("matchPolicy").and_then(Value::as_str) == Some("Exact");
    wh.get("rules").and_then(Value::as_array).is_some_and(|r| r.iter().any(|r| rule_matches(r, rt, op, exact)))
}

/// LabelSelector (matchLabels/matchExpressions) as an equivalent [`Selector`]; empty/absent
/// selects everything.
pub(crate) fn label_selector(v: Option<&Value>) -> Option<Selector> {
    let Some(v) = v else { return Some(Selector::default()) };
    Selector::parse(&label_selector_string(v)?).ok()
}

/// A LabelSelector object in `labelSelector=` query syntax; `None` for unknown operators.
pub fn label_selector_string(v: &Value) -> Option<String> {
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
    Some(parts.join(","))
}
pub use crate::cel::cel_bool;

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

/// Kind (group, version, kind) of `object` when it is not the resource's own.
type Kind = (&'static str, &'static str, &'static str);

struct Ctx<'a> {
    api: &'a ApiServer,
    rt: &'a Route,
    op: &'static str,
    user: crate::api::User,
    dry: bool,
    ns: Option<Value>,
    kind: Option<Kind>,
    /// The request `options` object, when it is not Create/Update/DeleteOptions (CONNECT).
    options: Option<Value>,
    /// Response `warnings`, in order.
    warns: &'a RefCell<Vec<String>>,
}

enum Outcome {
    Skipped,
    Called(Value),
}

impl Ctx<'_> {
    fn gvk(&self) -> Value {
        let (g, v, k) = self.kind.unwrap_or((self.rt.res.group, self.rt.res.version, self.rt.res.kind));
        obj(alloc::vec![("group", Value::from(g)), ("version", Value::from(v)), ("kind", Value::from(k))])
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
        r.set("options", self.options.clone().unwrap_or_else(|| obj(alloc::vec![("kind", Value::from(opts)), ("apiVersion", Value::from("meta.k8s.io/v1"))])));
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
        // Like upstream, the request carries its timeout: `?timeout=1s`.
        let secs = wh.get("timeoutSeconds").and_then(Value::as_u64).unwrap_or(10).clamp(1, 30);
        let url = format!("{url}{}timeout={secs}s", if url.contains('?') { '&' } else { '?' });
        let roots = match cc.get("caBundle").and_then(Value::as_str) {
            Some(b) => x509::pem_decode_all(core::str::from_utf8(&kr_fmt::base64::decode(b).map_err(|_| "invalid caBundle")?).map_err(|_| "invalid caBundle")?, "CERTIFICATE").map_err(|_| "invalid caBundle")?,
            None => Vec::new(),
        };
        let cfg = Rc::new(ClientConfig { pinned_ca: None, roots, client_cert: None, alpn: alloc::vec![b"http/1.1".to_vec()], tls12: false });
        let http = Http::with_connector(
            TlsConnector::new(WhResolver(HostsResolver::from_contents(&hosts)), cfg),
            HttpConfig { max_redirects: 0, max_idle: 0, connect_timeout_ms: secs * 1000, head_timeout_ms: secs * 1000, read_timeout_ms: secs * 1000, user_agent: "kr-apiserver".to_string(), ..HttpConfig::default() },
        );
        let fut = async {
            let mut resp = http.request("POST", &url, &[("Content-Type", "application/json"), ("Accept", "application/json")], review.as_bytes()).await.map_err(|e| if format!("{e:?}").contains("Timeout") { format!("Post \"{url}\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)") } else { format!("Post \"{url}\": {e:?}") })?;
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
        self.warns.borrow_mut().extend(strs(r, "warnings").into_iter().map(String::from));
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


/// Kinds whose changes invalidate [`Configs`] (see `ApiServer::wh_stamp`).
pub(crate) const CONFIG_PLURALS: [&str; 6] = ["mutatingwebhookconfigurations", "validatingwebhookconfigurations", "validatingadmissionpolicies", "validatingadmissionpolicybindings", "mutatingadmissionpolicies", "mutatingadmissionpolicybindings"];

/// The parsed admission configuration: every mutating and every validating webhook, in
/// configuration-name order, and the admission policies with their bindings.
pub struct Configs {
    muts: Vec<Value>,
    vals: Vec<Value>,
    vaps: Vec<crate::policy::Bound>,
    maps: Vec<crate::policy::Bound>,
}

/// Parsed configurations, rebuilt only when a configuration object was added, changed or removed.
fn configs(api: &ApiServer) -> Rc<Configs> {
    let stamp = api.wh_stamp();
    if let Some((s, c)) = api.wh_cache.borrow().as_ref() {
        if *s == stamp {
            return c.clone();
        }
    }
    let load = |plural: &str| {
        let mut cfgs = api.wh_list(GROUP, "v1", plural);
        cfgs.sort_by(|a, b| a.pointer(&["metadata", "name"]).and_then(Value::as_str).cmp(&b.pointer(&["metadata", "name"]).and_then(Value::as_str)));
        cfgs.iter().flat_map(|c| c.get("webhooks").and_then(Value::as_array).unwrap_or(&[]).iter().cloned().collect::<Vec<_>>()).collect::<Vec<_>>()
    };
    let pol = |p: &str, b: &str| crate::policy::bind(api.wh_list(GROUP, "v1", p), api.wh_list(GROUP, "v1", b));
    let c = Rc::new(Configs {
        muts: load("mutatingwebhookconfigurations"),
        vals: load("validatingwebhookconfigurations"),
        vaps: pol("validatingadmissionpolicies", "validatingadmissionpolicybindings"),
        maps: pol("mutatingadmissionpolicies", "mutatingadmissionpolicybindings"),
    });
    *api.wh_cache.borrow_mut() = Some((stamp, c.clone()));
    c
}

/// Whether any webhook or admission policy may apply to `op` on `rt`.
fn any_admission(api: &ApiServer, rt: &Route, op: &str) -> bool {
    let c = configs(api);
    c.muts.iter().chain(&c.vals).any(|w| rules_match(w, rt, op)) || crate::policy::may_apply(&c.vaps, rt, op) || crate::policy::may_apply(&c.maps, rt, op)
}

fn gather(api: &ApiServer, mutating: bool, rt: &Route, op: &str) -> Vec<Value> {
    let c = configs(api);
    let l = if mutating { &c.muts } else { &c.vals };
    l.iter().filter(|w| rules_match(w, rt, op)).cloned().collect()
}

/// How the request is presented to webhooks.
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    /// The resource itself (or `/status`): dry-run through the built-in handler.
    Resource,
    /// `*/scale` update: like `Resource`, with a Scale object and the current Scale as old.
    Scale,
    /// `pods/binding`, `pods/eviction`, `serviceaccounts/token`: the request body is the object.
    Body(Kind),
    /// `pods/exec`, `attach`, `portforward`: no object, the options come from the query.
    Connect,
}

fn options_object(sub: &str, query: &str) -> Value {
    let q = crate::api::Query::parse(query).unwrap_or_else(|_| crate::api::Query::parse("").unwrap());
    let flag = |k: &str| Value::Bool(matches!(q.get(k), Some("true" | "1")));
    let strings = |k: &str| Value::Array(q.all(k).into_iter().map(Value::from).collect());
    if sub == "portforward" {
        let ports = q.all("ports").into_iter().flat_map(|p| p.split(',')).filter_map(|p| p.trim().parse::<u64>().ok()).map(|p| Value::Number(json::Number::from_u64(p))).collect();
        return obj(alloc::vec![("kind", Value::from("PodPortForwardOptions")), ("apiVersion", Value::from("v1")), ("ports", Value::Array(ports))]);
    }
    let mut o = obj(alloc::vec![
        ("kind", Value::from(if sub == "exec" { "PodExecOptions" } else { "PodAttachOptions" })),
        ("apiVersion", Value::from("v1")),
        ("stdin", flag("stdin")),
        ("stdout", flag("stdout")),
        ("stderr", flag("stderr")),
        ("tty", flag("tty")),
    ]);
    if let Some(c) = q.get("container") {
        o.set("container", Value::from(c));
    }
    if sub == "exec" {
        o.set("command", strings("command"));
    }
    o
}

/// Applies the patch of a mutating webhook's response to `cur`. `(called, changed)`.
async fn mutate(ctx: &Ctx<'_>, wh: &Value, cur: &mut Value, old: &Value) -> Result<(bool, bool), Reply> {
    let Outcome::Called(r) = ctx.invoke(wh, cur, old).await.map_err(Reply::err)? else { return Ok((false, false)) };
    let wname = wh.get("name").and_then(Value::as_str).unwrap_or("");
    let Some(p) = r.get("patch").and_then(Value::as_str).filter(|p| !p.is_empty() && !cur.is_null()) else { return Ok((true, false)) };
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
        Ok(n) => {
            let changed = n != *cur;
            *cur = n;
            Ok((true, changed))
        }
        Err(_) if wh.get("failurePolicy").and_then(Value::as_str) == Some("Ignore") => Ok((true, false)),
        Err(e) => Err(Reply::err(failed(wname, &format!("error applying patch: {e}")))),
    }
}

/// What [`run`] tells the transport to do.
pub enum Run {
    /// Execute the request, as given or rewritten.
    Pass(Option<Rewrite>),
    /// The request was already executed (DELETE collection, item by item): this is the answer.
    Done(Reply),
}

/// Webhook admission of one object: `rt` addresses it, `req` is the request to dry-run (and to
/// execute if admitted).
async fn admit(api: &ApiServer, req: &Req<'_>, rt: &Route, op: &'static str, mode: Mode, user: &crate::api::User, warns: &RefCell<Vec<String>>) -> Result<Option<Rewrite>, Reply> {
    let muts = gather(api, true, rt, op);
    let vals = gather(api, false, rt, op);
    if !any_admission(api, rt, op) {
        return Ok(None);
    }
    let dry = req.query.split('&').any(|p| p == "dryRun=All");
    let name = rt.name.clone().unwrap_or_default();
    let sub = rt.sub.as_deref().unwrap_or("");
    let (mut kind, mut options) = (None, None);
    let (obj0, old) = match mode {
        Mode::Connect => {
            let o = options_object(sub, req.query);
            let k = o.get("kind").and_then(Value::as_str).unwrap_or("");
            kind = Some(("", "v1", if k == "PodExecOptions" { "PodExecOptions" } else if k == "PodAttachOptions" { "PodAttachOptions" } else { "PodPortForwardOptions" }));
            options = Some(o);
            (Value::Null, Value::Null)
        }
        Mode::Body(k) => {
            kind = Some(k);
            let b = if req.body.is_empty() { obj(alloc::vec![]) } else { json::parse(req.body).map_err(|_| Reply::err(ApiError::bad_request("invalid request body")))? };
            (b, Value::Null)
        }
        Mode::Resource | Mode::Scale => {
            let q2 = if req.query.is_empty() { "dryRun=All".to_string() } else { format!("{}&dryRun=All", req.query) };
            let dreq = Req { method: req.method, path: req.path, query: &q2, content_type: req.content_type, accept: None, body: req.body, user: Some(user.clone()), bearer: req.bearer, headers: req.headers, authz_verb: req.authz_verb };
            let result = match api.handle_w(&dreq).0 {
                Reply::Json(c, b) if c < 300 => json::parse(b.as_bytes()).map_err(|_| Reply::err(ApiError::new(500, "InternalError", "bad admission result")))?,
                other => return Err(other),
            };
            if mode == Mode::Scale {
                kind = Some(("autoscaling", "v1", "Scale"));
                let greq = Req { method: "GET", path: req.path, query: "", content_type: None, accept: None, body: b"", user: Some(user.clone()), bearer: req.bearer, headers: req.headers, authz_verb: None };
                let old = match api.handle(&greq) {
                    Reply::Json(200, b) => json::parse(b.as_bytes()).unwrap_or(Value::Null),
                    _ => Value::Null,
                };
                (result, old)
            } else {
                match op {
                    "DELETE" => (Value::Null, result),
                    "UPDATE" => (result, api.get_value(rt, &name).map(|(_, v)| v).unwrap_or(Value::Null)),
                    _ => (result, Value::Null),
                }
            }
        }
    };
    let ns = rt.namespace.as_deref().and_then(|n| api.wh_object("", "v1", "namespaces", None, n));
    let ctx = Ctx { api, rt, op, user: user.clone(), dry, ns, kind, options, warns };
    let mut cur = obj0.clone();
    let cfg = configs(api);
    let preq = |cur: &Value| crate::policy::Req { rt, op, request: ctx.request(cur, &old), ns: ctx.ns.as_ref(), warns };
    if !cur.is_null() {
        crate::policy::mutate(api, &cfg.maps, &preq(&cur), &mut cur, &old).map_err(Reply::err)?;
    }
    // reinvocationPolicy: IfNeeded webhooks that ran before a later webhook changed the object
    // run once more (never recursively).
    let (mut ran, mut stale): (Vec<usize>, Vec<usize>) = (Vec::new(), Vec::new());
    for (i, wh) in muts.iter().enumerate() {
        let (called, changed) = mutate(&ctx, wh, &mut cur, &old).await?;
        if called && wh.get("reinvocationPolicy").and_then(Value::as_str) == Some("IfNeeded") {
            ran.push(i);
        }
        if changed {
            for j in ran.iter().copied().filter(|j| *j != i) {
                if !stale.contains(&j) {
                    stale.push(j);
                }
            }
        }
    }
    stale.sort_unstable();
    for i in stale {
        mutate(&ctx, &muts[i], &mut cur, &old).await?;
    }
    crate::policy::validate(api, &cfg.vaps, &preq(&cur), &cur, &old).map_err(Reply::err)?;
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

/// Runs webhook admission for a request. `Ok(Pass(None))`: execute it unchanged. `Err(reply)`: it
/// is rejected (or failed built-in admission). The warnings go to the client either way.
pub async fn run(api: &ApiServer, req: &Req<'_>) -> (Result<Run, Reply>, Vec<String>) {
    let warns = RefCell::new(Vec::new());
    let r = run_inner(api, req, &warns).await;
    (r, warns.into_inner())
}

async fn run_inner(api: &ApiServer, req: &Req<'_>, warns: &RefCell<Vec<String>>) -> Result<Run, Reply> {
    let Some(rt) = api.wh_route(req.path) else { return Ok(Run::Pass(None)) };
    if rt.res.group == GROUP {
        return Ok(Run::Pass(None));
    }
    let named = rt.name.is_some();
    let sub = rt.sub.as_deref();
    let (op, mode): (&'static str, Mode) = match (req.method, sub) {
        (_, Some(s)) if !rt.res.subresources.contains(&s) => return Ok(Run::Pass(None)),
        ("GET" | "POST", Some("exec" | "attach" | "portforward")) if named => ("CONNECT", Mode::Connect),
        ("POST", Some("binding")) if named => ("CREATE", Mode::Body(("", "v1", "Binding"))),
        ("POST", Some("eviction")) if named => ("CREATE", Mode::Body(("policy", "v1", "Eviction"))),
        ("POST", Some("token")) if named => ("CREATE", Mode::Body(("authentication.k8s.io", "v1", "TokenRequest"))),
        ("PUT" | "PATCH", Some("scale")) if named => ("UPDATE", Mode::Scale),
        (_, Some(s)) if s != "status" => return Ok(Run::Pass(None)),
        ("POST", _) => ("CREATE", Mode::Resource),
        ("PUT" | "PATCH", _) if named => ("UPDATE", Mode::Resource),
        ("DELETE", _) => ("DELETE", Mode::Resource),
        _ => return Ok(Run::Pass(None)),
    };
    if !named && op != "CREATE" && op != "DELETE" {
        return Ok(Run::Pass(None));
    }
    if !any_admission(api, &rt, op) {
        return Ok(Run::Pass(None));
    }
    let user = api.authenticate(req).map_err(Reply::err)?;
    // Admission runs after authorization (as upstream): the dry-run paths authorize through
    // `handle`, the others (CONNECT, body-only subresources) must check here, so a caller
    // without access never reaches a webhook.
    if matches!(mode, Mode::Connect | Mode::Body(_)) {
        api.authorize_request(req, &user).map_err(Reply::err)?;
    }
    if named || op != "DELETE" {
        return admit(api, req, &rt, op, mode, &user, warns).await.map(Run::Pass);
    }
    // DELETE collection: admission and deletion per item, as upstream does. A denied item stays
    // (the first denial is the answer); the other items are still deleted.
    if rt.res.namespaced && rt.namespace.is_none() {
        return Ok(Run::Pass(None));
    }
    let lq = ["labelSelector", "fieldSelector"].iter().filter_map(|k| crate::api::Query::parse(req.query).ok().and_then(|q| q.get(k).map(|v| format!("{k}={}", v.replace('%', "%25").replace('&', "%26").replace('=', "%3D").replace('+', "%2B"))))).collect::<Vec<_>>().join("&");
    let lreq = Req { method: "GET", path: req.path, query: &lq, content_type: None, accept: None, body: b"", user: Some(user.clone()), bearer: req.bearer, headers: req.headers, authz_verb: Some("deletecollection") };
    let list = match api.handle(&lreq) {
        Reply::Json(c, b) if c < 300 => json::parse(b.as_bytes()).map_err(|_| Reply::err(ApiError::new(500, "InternalError", "bad list result")))?,
        other => return Err(other),
    };
    let dry = req.query.split('&').any(|p| p == "dryRun=All");
    let (mut deleted, mut first_err) = (Vec::new(), None);
    for item in list.get("items").and_then(Value::as_array).unwrap_or(&[]) {
        let Some(n) = item.pointer(&["metadata", "name"]).and_then(Value::as_str) else { continue };
        let path = format!("{}/{}", req.path.trim_end_matches('/'), n);
        let irt = Route { res: rt.res, namespace: rt.namespace.clone(), name: Some(n.to_string()), sub: None };
        let ireq = Req { method: "DELETE", path: &path, query: if dry { "dryRun=All" } else { "" }, content_type: req.content_type, accept: None, body: req.body, user: Some(user.clone()), bearer: req.bearer, headers: req.headers, authz_verb: Some("deletecollection") };
        match admit(api, &ireq, &irt, "DELETE", Mode::Resource, &user, warns).await {
            Ok(_) => match api.handle(&ireq) {
                Reply::Json(c, b) if c < 300 => deleted.push(json::parse(b.as_bytes()).ok().filter(|v| v.get("kind").and_then(Value::as_str) != Some("Status")).unwrap_or_else(|| item.clone())),
                Reply::Json(404, _) => {}
                other => {
                    first_err.get_or_insert(other);
                }
            },
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }
    if let Some(e) = first_err {
        return Err(e);
    }
    Ok(Run::Done(Reply::Json(
        200,
        json::to_string(&obj(alloc::vec![
            ("kind", Value::String(format!("{}List", rt.res.kind))),
            ("apiVersion", Value::String(rt.res.group_version())),
            ("metadata", obj(alloc::vec![("resourceVersion", Value::String(api.revision().to_string()))])),
            ("items", Value::Array(deleted)),
        ])),
    )))
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
