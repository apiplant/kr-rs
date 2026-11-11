//! A small CEL subset shared by admission webhook matchConditions and CRD
//! `x-kubernetes-validations`. Supported: `== != < <= > >= ! && || in + - * / % ?:`, field and
//! index access, `has() size() matches() int() double() string()`, string methods
//! (`startsWith endsWith contains matches size lowerAscii upperAscii trim`), the comprehension
//! macros `all exists exists_one filter map`, string/number/bool/null/list/map literals, and
//! object construction (`Object{spec: Object.spec{replicas: 3}}`, `JSONPatch{op: "add", ...}`)
//! for MutatingAdmissionPolicy, which evaluates to plain JSON objects. [`Program::type_warnings`]
//! is a small static checker for the operator overloads (admission policy `status.typeChecking`).

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_fmt::json::{self, Number, Value};

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
        let raw = b[i] == 'r' && i + 1 < b.len() && (b[i + 1] == '"' || b[i + 1] == '\'');
    if raw {
        i += 1;
    }
    let c = b[i];
    if c.is_whitespace() {
        i += 1;
    } else if c == '"' || c == '\'' {
        let quote = c;
        let triple = i + 2 < b.len() && b[i + 1] == quote && b[i + 2] == quote;
        if triple {
            i += 3;
        } else {
            i += 1;
        }
        let mut v = String::new();
        let mut closed = false;
        while i < b.len() {
            if triple {
                if i + 2 < b.len() && b[i] == quote && b[i + 1] == quote && b[i + 2] == quote {
                    i += 3;
                    closed = true;
                    break;
                }
            } else if b[i] == quote {
                i += 1;
                closed = true;
                break;
            }
            if !raw && b[i] == '\\' && i + 1 < b.len() {
                i += 1;
                v.push(match b[i] {
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    o => o,
                });
                i += 1;
            } else {
                v.push(b[i]);
                i += 1;
            }
        }
        if !closed {
            return Err("unterminated string".into());
        }
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
                let op = ["<", ">", "!", "(", ")", "[", "]", "{", "}", ".", ",", "+", "-", "*", "/", "%", "?", ":"].into_iter().find(|o| o.starts_with(c)).ok_or_else(|| format!("unexpected character {c:?}"))?;
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
    Map(Vec<(E, E)>),
    /// `Object{...}`, `Object.spec{...}`, `JSONPatch{...}`: the type path and field initialisers.
    Struct(String, Vec<(String, E)>),
    Cond(Box<E>, Box<E>, Box<E>),
}

/// Roots of the object-construction type paths (`Object.spec.template{...}`).
const TYPE_ROOTS: [&str; 2] = ["Object", "JSONPatch"];

/// `Object.spec.x` as a dotted name, when `e` is such a type path.
fn type_path(e: &E) -> Option<String> {
    match e {
        E::Var(n) if TYPE_ROOTS.contains(&n.as_str()) => Some(n.clone()),
        E::Field(b, n) => type_path(b).map(|p| format!("{p}.{n}")),
        _ => None,
    }
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
    fn expr(&mut self) -> Result<E, String> {
        let c = self.or()?;
        if self.eat("?") {
            let a = self.expr()?;
            self.expect(":")?;
            let b = self.expr()?;
            return Ok(E::Cond(Box::new(c), Box::new(a), Box::new(b)));
        }
        Ok(c)
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
        let mut l = self.mul()?;
        loop {
            let op = if self.eat("+") {
                "+"
            } else if self.eat("-") {
                "-"
            } else {
                return Ok(l);
            };
            l = E::Bin(op, Box::new(l), Box::new(self.mul()?));
        }
    }
    fn mul(&mut self) -> Result<E, String> {
        let mut l = self.unary()?;
        loop {
            let op = if self.eat("*") {
                "*"
            } else if self.eat("/") {
                "/"
            } else if self.eat("%") {
                "%"
            } else {
                return Ok(l);
            };
            l = E::Bin(op, Box::new(l), Box::new(self.unary()?));
        }
    }
    fn unary(&mut self) -> Result<E, String> {
        if self.eat("!") {
            return Ok(E::Not(Box::new(self.unary()?)));
        }
        if self.eat("-") {
            return Ok(E::Bin("-", Box::new(E::Lit(Value::Number(Number::from_i64(0)))), Box::new(self.unary()?)));
        }
        self.postfix()
    }
    fn args(&mut self) -> Result<Vec<E>, String> {
        let mut a = Vec::new();
        while !self.peek_op(")") {
            a.push(self.expr()?);
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
                let k = self.expr()?;
                self.expect("]")?;
                e = E::Index(Box::new(e), Box::new(k));
            } else if let (true, Some(ty)) = (self.peek_op("{"), type_path(&e)) {
                self.i += 1;
                let mut fields = Vec::new();
                while !self.peek_op("}") {
                    let Some(Tok::Id(n)) = self.t.get(self.i).cloned() else { return Err("expected a field name".into()) };
                    self.i += 1;
                    self.expect(":")?;
                    fields.push((n, self.expr()?));
                    if !self.eat(",") {
                        break;
                    }
                }
                self.expect("}")?;
                e = E::Struct(ty, fields);
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
            Tok::Num(n) => Ok(E::Lit(Value::Number(num(n)?))),
            Tok::Id(i) => match i.as_str() {
                "true" => Ok(E::Lit(Value::Bool(true))),
                "false" => Ok(E::Lit(Value::Bool(false))),
                "null" => Ok(E::Lit(Value::Null)),
                _ if self.eat("(") => Ok(E::Func(i, self.args()?)),
                _ => Ok(E::Var(i)),
            },
            Tok::Op("(") => {
                let e = self.expr()?;
                self.expect(")")?;
                Ok(e)
            }
            Tok::Op("[") => {
                let mut a = Vec::new();
                while !self.peek_op("]") {
                    a.push(self.expr()?);
                    if !self.eat(",") {
                        break;
                    }
                }
                self.expect("]")?;
                Ok(E::List(a))
            }
            Tok::Op("{") => {
                let mut m = Vec::new();
                while !self.peek_op("}") {
                    let k = self.expr()?;
                    self.expect(":")?;
                    m.push((k, self.expr()?));
                    if !self.eat(",") {
                        break;
                    }
                }
                self.expect("}")?;
                Ok(E::Map(m))
            }
            Tok::Op(o) => Err(format!("unexpected {o:?}")),
        }
    }
}

fn num(n: f64) -> Result<Number, String> {
    if n > -9e15 && n < 9e15 && n == (n as i64) as f64 {
        Ok(Number::from_i64(n as i64))
    } else {
        Number::from_f64(n).ok_or_else(|| "bad number".to_string())
    }
}

fn num_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| num_eq(p, q)),
        _ => a == b,
    }
}

fn truth(v: Result<Value, String>) -> Result<bool, String> {
    match v? {
        Value::Bool(b) => Ok(b),
        _ => Err("expected a boolean".into()),
    }
}

type Vars<'a> = [(&'a str, &'a Value)];

const MACROS: [&str; 5] = ["all", "exists", "exists_one", "filter", "map"];
const METHODS: [&str; 8] = ["size", "startsWith", "endsWith", "contains", "matches", "lowerAscii", "upperAscii", "trim"];
/// CEL strings-extension methods.
const STR_METHODS: [&str; 8] = ["substring", "indexOf", "lastIndexOf", "split", "replace", "charAt", "join", "reverse"];
/// Kubernetes IP/CIDR library methods (receivers are canonical strings).
const IP_METHODS: [&str; 11] = ["family", "isUnspecified", "isLoopback", "isLinkLocalMulticast", "isLinkLocalUnicast", "isGlobalUnicast", "containsIP", "containsCIDR", "ip", "masked", "prefixLength"];
const FUNCS: [&str; 13] = ["has", "size", "matches", "int", "double", "string", "isURL", "duration", "type", "isIP", "ip", "isCIDR", "cidr"];
/// Bare identifiers that evaluate to a type value (a string holding the type name).
const TYPE_NAMES: [&str; 9] = ["int", "uint", "double", "string", "bool", "list", "map", "null_type", "bytes"];

/// Rejects references and calls the evaluator does not support (done once, at compile time).
fn check(e: &E, scope: &mut Vec<String>) -> Result<(), String> {
    match e {
        E::Lit(_) => Ok(()),
        E::Var(n) => {
            if scope.contains(n) || TYPE_NAMES.contains(&n.as_str()) {
                Ok(())
            } else {
                Err(format!("undeclared reference to '{n}'"))
            }
        }
        E::Field(b, _) | E::Not(b) => check(b, scope),
        E::Index(a, b) | E::Bin(_, a, b) => {
            check(a, scope)?;
            check(b, scope)
        }
        E::List(v) => v.iter().try_for_each(|x| check(x, scope)),
        E::Map(m) => m.iter().try_for_each(|(k, v)| {
            check(k, scope)?;
            check(v, scope)
        }),
        E::Struct(ty, f) => {
            if !(ty == "JSONPatch" || ty == "Object" || ty.starts_with("Object.")) {
                return Err(format!("undeclared reference to '{ty}'"));
            }
            f.iter().try_for_each(|(_, v)| check(v, scope))
        }
        E::Cond(a, b, c) => {
            check(a, scope)?;
            check(b, scope)?;
            check(c, scope)
        }
        E::Func(f, a) => {
            if !FUNCS.contains(&f.as_str()) {
                return Err(format!("undeclared reference to '{f}' (unsupported function)"));
            }
            if f == "has" && !matches!(a.as_slice(), [E::Field(..)]) {
                return Err("has() requires a field selection".into());
            }
            a.iter().try_for_each(|x| check(x, scope))
        }
        E::Method(b, m, a) => {
            check(b, scope)?;
            if MACROS.contains(&m.as_str()) {
                let [E::Var(x), body] = a.as_slice() else { return Err(format!("{m}() requires an iteration variable and an expression")) };
                if (m == "map" || m == "filter" || m == "all" || m == "exists" || m == "exists_one") && a.len() != 2 {
                    return Err(format!("{m}() takes two arguments"));
                }
                scope.push(x.clone());
                let r = check(body, scope);
                scope.pop();
                r
            } else if METHODS.contains(&m.as_str()) || STR_METHODS.contains(&m.as_str()) || IP_METHODS.contains(&m.as_str()) {
                a.iter().try_for_each(|x| check(x, scope))
            } else {
                Err(format!("undeclared reference to '{m}' (unsupported method)"))
            }
        }
    }
}

fn with<'a>(vars: &Vars<'a>, name: &'a str, v: &'a Value) -> Vec<(&'a str, &'a Value)> {
    let mut x: Vec<(&str, &Value)> = vars.iter().filter(|(k, _)| *k != name).copied().collect();
    x.push((name, v));
    x
}

fn items(v: &Value) -> Result<Vec<Value>, String> {
    match v {
        Value::Array(a) => Ok(a.clone()),
        Value::Object(o) => Ok(o.iter().map(|(k, _)| Value::String(k.clone())).collect()),
        _ => Err("comprehension over a non-collection".into()),
    }
}

fn eval(e: &E, vars: &Vars) -> Result<Value, String> {
    Ok(match e {
        E::Lit(v) => v.clone(),
        E::Var(n) => match vars.iter().rev().find(|(k, _)| k == n) {
            Some((_, v)) => (*v).clone(),
            None if TYPE_NAMES.contains(&n.as_str()) => Value::String(n.clone()),
            None => return Err(format!("undeclared reference to {n:?}")),
        },
        E::Field(b, n) => eval(b, vars)?.get(n).cloned().ok_or_else(|| format!("no such key: {n}"))?,
        E::Index(b, k) => match (eval(b, vars)?, eval(k, vars)?) {
            (o @ Value::Object(_), Value::String(k)) => o.get(&k).cloned().ok_or_else(|| format!("no such key: {k}"))?,
            (Value::Array(a), Value::Number(n)) => a.get(n.as_f64() as usize).cloned().ok_or("index out of bounds")?,
            _ => return Err("invalid index".into()),
        },
        E::Not(x) => Value::Bool(!truth(eval(x, vars))?),
        E::List(a) => Value::Array(a.iter().map(|x| eval(x, vars)).collect::<Result<_, _>>()?),
        E::Map(m) => {
            let mut o: Vec<(String, Value)> = Vec::new();
            for (k, v) in m {
                let Value::String(k) = eval(k, vars)? else { return Err("map keys must be strings".into()) };
                let v = eval(v, vars)?;
                o.retain(|(x, _)| *x != k);
                o.push((k, v));
            }
            Value::Object(o)
        }
        E::Struct(_, f) => Value::Object(f.iter().map(|(k, v)| Ok((k.clone(), eval(v, vars)?))).collect::<Result<_, String>>()?),
        E::Cond(c, a, b) => {
            if truth(eval(c, vars))? {
                eval(a, vars)?
            } else {
                eval(b, vars)?
            }
        }
        E::Func(f, a) => match (f.as_str(), a.as_slice()) {
            ("has", [E::Field(b, n)]) => Value::Bool(matches!(eval(b, vars)?, o @ Value::Object(_) if o.get(n).is_some())),
            ("size", [x]) => size(&eval(x, vars)?)?,
            ("matches", [s, re]) => matches_re(&eval(s, vars)?, &eval(re, vars)?)?,
            ("int", [x]) => match eval(x, vars)? {
                Value::Number(n) => Value::Number(Number::from_i64(n.as_f64() as i64)),
                Value::String(s) => Value::Number(Number::from_i64(s.trim().parse::<i64>().map_err(|_| "invalid int()")?)),
                _ => return Err("int() of unsupported type".into()),
            },
            ("double", [x]) => match eval(x, vars)? {
                Value::Number(n) => Value::Number(Number::from_f64(n.as_f64()).ok_or("bad number")?),
                Value::String(s) => Value::Number(Number::from_f64(s.trim().parse::<f64>().map_err(|_| "invalid double()")?).ok_or("bad number")?),
                _ => return Err("double() of unsupported type".into()),
            },
            ("string", [x]) => Value::String(match eval(x, vars)? {
                Value::String(s) => s,
                Value::Bool(b) => b.to_string(),
                Value::Number(n) if n.is_integer() => n.as_i64().map(|i| i.to_string()).unwrap_or_else(|| json::to_string(&Value::Number(n))),
                Value::Number(n) => n.as_f64().to_string(),
                _ => return Err("string() of unsupported type".into()),
            }),
            ("type", [x]) => Value::String(
                match eval(x, vars)? {
                    Value::Null => "null_type",
                    Value::Bool(_) => "bool",
                    Value::Number(n) if n.is_integer() => "int",
                    Value::Number(_) => "double",
                    Value::String(_) => "string",
                    Value::Array(_) => "list",
                    Value::Object(_) => "map",
                }
                .to_string(),
            ),
            ("isIP", [x]) => Value::Bool(matches!(eval(x, vars)?, Value::String(s) if parse_ip(&s).is_some())),
            ("isCIDR", [x]) => Value::Bool(matches!(eval(x, vars)?, Value::String(s) if parse_cidr(&s).is_some())),
            ("ip", [x]) => match eval(x, vars)? {
                Value::String(s) => Value::String(fmt_ip(parse_ip(&s).ok_or_else(|| format!("ParseAddr({s:?}): invalid IP address"))?)),
                _ => return Err("ip() requires a string".into()),
            },
            ("cidr", [x]) => match eval(x, vars)? {
                Value::String(s) => Value::String(fmt_cidr(parse_cidr(&s).ok_or_else(|| format!("network address parse error during conversion from string: {s:?}"))?)),
                _ => return Err("cidr() requires a string".into()),
            },
            ("isURL", [x]) => {
                let s = eval(x, vars)?;
                Value::Bool(s.as_str().map(is_url).unwrap_or(false))
            }
            ("duration", [x]) => {
                let s = eval(x, vars)?;
                let txt = s.as_str().ok_or("duration() requires a string")?;
                Value::Number(Number::from_f64(parse_duration(txt).ok_or("invalid duration")?).ok_or("bad number")?)
            }
            _ => return Err(format!("unsupported function {f}")),
        },
        E::Method(b, m, a) => {
            let recv = eval(b, vars)?;
            if MACROS.contains(&m.as_str()) {
                let [E::Var(x), body] = a.as_slice() else { return Err(format!("{m}() requires an iteration variable and an expression")) };
                let its = items(&recv)?;
                let (mut yes, mut out) = (0usize, Vec::new());
                for it in &its {
                    let v2 = with(vars, x, it);
                    match m.as_str() {
                        "map" => out.push(eval(body, &v2)?),
                        "all" | "exists" | "exists_one" | "filter" => {
                            if truth(eval(body, &v2))? {
                                yes += 1;
                                out.push(it.clone());
                            } else if m == "all" {
                                return Ok(Value::Bool(false));
                            }
                        }
                        _ => {}
                    }
                }
                return Ok(match m.as_str() {
                    "all" => Value::Bool(true),
                    "exists" => Value::Bool(yes > 0),
                    "exists_one" => Value::Bool(yes == 1),
                    _ => Value::Array(out),
                });
            }
            if m == "size" && a.is_empty() {
                return size(&recv);
            }
            if let (Value::Array(l), "join") = (&recv, m.as_str()) {
                let args = a.iter().map(|x| eval(x, vars)).collect::<Result<Vec<_>, _>>()?;
                let sep = match args.as_slice() {
                    [] => "",
                    [Value::String(x)] => x.as_str(),
                    _ => return Err("join() takes an optional string separator".into()),
                };
                let parts = l.iter().map(|x| x.as_str().ok_or("join() requires a list of strings")).collect::<Result<Vec<_>, _>>()?;
                return Ok(Value::String(parts.join(sep)));
            }
            let Value::String(s) = &recv else { return Err(format!("unsupported method {m}")) };
            if STR_METHODS.contains(&m.as_str()) {
                let args = a.iter().map(|x| eval(x, vars)).collect::<Result<Vec<_>, _>>()?;
                return str_method(m, s, &args);
            }
            if IP_METHODS.contains(&m.as_str()) {
                let args = a.iter().map(|x| eval(x, vars)).collect::<Result<Vec<_>, _>>()?;
                return ip_method(m, s, &args);
            }
            if a.is_empty() {
                return Ok(Value::String(match m.as_str() {
                    "lowerAscii" => s.to_ascii_lowercase(),
                    "upperAscii" => s.to_ascii_uppercase(),
                    "trim" => s.trim().to_string(),
                    _ => return Err(format!("unsupported method {m}")),
                }));
            }
            let [arg] = a.as_slice() else { return Err(format!("unsupported method {m}")) };
            let arg = eval(arg, vars)?;
            if m == "matches" {
                return matches_re(&recv, &arg);
            }
            let Value::String(arg) = arg else { return Err("expected a string argument".into()) };
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
                        (Value::Array(x), Value::Array(y)) => Value::Array(x.iter().chain(y).cloned().collect()),
                        (Value::Number(x), Value::Number(y)) => Value::Number(num(x.as_f64() + y.as_f64())?),
                        _ => return Err("invalid '+' operands".into()),
                    },
                    "-" | "*" | "/" | "%" => {
                        let (Value::Number(x), Value::Number(y)) = (&a, &b) else { return Err(format!("invalid '{op}' operands")) };
                        let (x, y) = (x.as_f64(), y.as_f64());
                        let int = matches!((&a, &b), (Value::Number(p), Value::Number(q)) if p.is_integer() && q.is_integer());
                        Value::Number(num(match *op {
                            "-" => x - y,
                            "*" => x * y,
                            "/" | "%" if y == 0.0 && int => return Err("division by zero".into()),
                            "/" if int => ((x / y) as i64) as f64,
                            "/" => x / y,
                            _ if int => x % y,
                            _ => return Err("invalid '%' operands".into()),
                        })?)
                    }
                    _ => {
                        let ord = match (&a, &b) {
                            (Value::Number(x), Value::Number(y)) => x.as_f64().partial_cmp(&y.as_f64()),
                            (Value::String(x), Value::String(y)) => match (parse_duration(x), parse_duration(y)) {
                                (Some(nx), Some(ny)) => nx.partial_cmp(&ny),
                                _ => Some(x.cmp(y)),
                            },
                            (Value::String(x), Value::Number(y)) => parse_duration(x).and_then(|nx| nx.partial_cmp(&y.as_f64())),
                            (Value::Number(x), Value::String(y)) => parse_duration(y).and_then(|ny| x.as_f64().partial_cmp(&ny)),
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

fn find_chars(h: &[char], n: &[char], from: usize) -> Option<usize> {
    (from..=h.len().checked_sub(n.len())?).find(|&i| h[i..i + n.len()] == *n)
}

fn str_method(m: &str, s: &str, args: &[Value]) -> Result<Value, String> {
    let c: Vec<char> = s.chars().collect();
    let int = |v: &Value| match v {
        Value::Number(n) if n.is_integer() => Ok(n.as_f64() as i64),
        _ => Err(format!("{m}() requires an int argument")),
    };
    let st = |v: &Value| v.as_str().map(|x| x.chars().collect::<Vec<char>>()).ok_or_else(|| format!("{m}() requires a string argument"));
    let idx = |i: i64| Value::Number(Number::from_i64(i));
    let strv = |x: &[char]| Value::String(x.iter().collect());
    Ok(match (m, args) {
        ("substring", [a]) | ("substring", [a, _]) => {
            let b = int(a)?;
            let e = match args.get(1) {
                Some(e) => int(e)?,
                None => c.len() as i64,
            };
            if b < 0 || e < b || e > c.len() as i64 {
                return Err(format!("substring range [{b}, {e}] out of bounds for length {}", c.len()));
            }
            strv(&c[b as usize..e as usize])
        }
        ("indexOf", [n]) | ("indexOf", [n, _]) => {
            let off = match args.get(1) {
                Some(o) => int(o)?,
                None => 0,
            };
            if off < 0 || off > c.len() as i64 {
                return Err("indexOf() offset out of range".into());
            }
            idx(find_chars(&c, &st(n)?, off as usize).map_or(-1, |i| i as i64))
        }
        ("lastIndexOf", [n]) | ("lastIndexOf", [n, _]) => {
            let n = st(n)?;
            let off = match args.get(1) {
                Some(o) => int(o)?,
                None => c.len() as i64,
            };
            if off < 0 || off > c.len() as i64 {
                return Err("lastIndexOf() offset out of range".into());
            }
            idx((0..=(off as usize).min(c.len().saturating_sub(n.len())))
                .rev()
                .find(|&i| i + n.len() <= c.len() && c[i..i + n.len()] == *n)
                .map_or(-1, |i| i as i64))
        }
        ("charAt", [i]) => {
            let i = int(i)?;
            if i < 0 || i > c.len() as i64 {
                return Err("charAt() index out of range".into());
            }
            strv(c.get(i as usize..i as usize + 1).unwrap_or(&[]))
        }
        ("reverse", []) => Value::String(c.iter().rev().collect()),
        ("split", [sep]) | ("split", [sep, _]) => {
            let sep = st(sep)?;
            let limit = match args.get(1) {
                Some(n) => int(n)?,
                None => -1,
            };
            if limit == 0 {
                return Ok(Value::Array(Vec::new()));
            }
            let (mut out, mut at) = (Vec::new(), 0);
            if sep.is_empty() {
                out = c.iter().map(|x| Value::String(x.to_string())).collect();
                if limit > 0 && out.len() > limit as usize {
                    let rest: String = c[limit as usize - 1..].iter().collect();
                    out.truncate(limit as usize - 1);
                    out.push(Value::String(rest));
                }
                return Ok(Value::Array(out));
            }
            while limit < 0 || (out.len() as i64) < limit - 1 {
                let Some(i) = find_chars(&c, &sep, at) else { break };
                out.push(strv(&c[at..i]));
                at = i + sep.len();
            }
            out.push(strv(&c[at..]));
            Value::Array(out)
        }
        ("replace", [o, n]) | ("replace", [o, n, _]) => {
            let (o, n) = (st(o)?, st(n)?);
            let limit = match args.get(2) {
                Some(l) => int(l)?,
                None => -1,
            };
            let (mut out, mut at, mut done) = (String::new(), 0, 0);
            while !o.is_empty() && (limit < 0 || done < limit) {
                let Some(i) = find_chars(&c, &o, at) else { break };
                out.extend(&c[at..i]);
                out.extend(&n);
                at = i + o.len();
                done += 1;
            }
            out.extend(&c[at..]);
            Value::String(out)
        }
        _ => return Err(format!("unsupported arguments to {m}()")),
    })
}

/// An IP address as (bits, is_v6); IPv4 lives in the low 32 bits.
type Ip = (u128, bool);

fn parse_v4(s: &str) -> Option<u32> {
    let mut n = 0u32;
    let mut parts = 0;
    for p in s.split('.') {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|c| c.is_ascii_digit()) || (p.len() > 1 && p.starts_with('0')) {
            return None;
        }
        n = (n << 8) | p.parse::<u32>().ok().filter(|v| *v < 256)?;
        parts += 1;
    }
    (parts == 4).then_some(n)
}

fn parse_groups(s: &str, out: &mut Vec<u16>) -> Option<()> {
    if s.is_empty() {
        return Some(());
    }
    let n = s.split(':').count();
    for (i, g) in s.split(':').enumerate() {
        if i + 1 == n && g.contains('.') {
            let v = parse_v4(g)?;
            out.push((v >> 16) as u16);
            out.push(v as u16);
        } else if !g.is_empty() && g.len() <= 4 && g.bytes().all(|c| c.is_ascii_hexdigit()) {
            out.push(u16::from_str_radix(g, 16).ok()?);
        } else {
            return None;
        }
    }
    Some(())
}

fn parse_ip(s: &str) -> Option<Ip> {
    if !s.contains(':') {
        return parse_v4(s).map(|v| (v as u128, false));
    }
    let (mut head, mut tail) = (Vec::new(), Vec::new());
    let g = match s.split_once("::") {
        Some((h, t)) => {
            parse_groups(h, &mut head)?;
            parse_groups(t, &mut tail)?;
            if head.len() + tail.len() > 7 {
                return None;
            }
            let mut g = head;
            g.resize(8 - tail.len(), 0);
            g.extend(tail);
            g
        }
        None => {
            parse_groups(s, &mut head)?;
            head
        }
    };
    (g.len() == 8).then(|| (g.iter().fold(0u128, |a, x| (a << 16) | *x as u128), true))
}

fn fmt_ip((bits, v6): Ip) -> String {
    if !v6 {
        let b = bits as u32;
        return format!("{}.{}.{}.{}", b >> 24, (b >> 16) & 255, (b >> 8) & 255, b & 255);
    }
    let g: Vec<u16> = (0..8).map(|i| (bits >> (112 - 16 * i)) as u16).collect();
    // RFC 5952: compress the longest run (>= 2) of zero groups, the first on ties.
    let (mut best, mut i) = ((0, 0), 0);
    while i < 8 {
        if g[i] == 0 {
            let st = i;
            while i < 8 && g[i] == 0 {
                i += 1;
            }
            if i - st > best.1 {
                best = (st, i - st);
            }
        } else {
            i += 1;
        }
    }
    let hex = |r: &[u16]| r.iter().map(|x| format!("{x:x}")).collect::<Vec<_>>().join(":");
    if best.1 < 2 {
        return hex(&g);
    }
    format!("{}::{}", hex(&g[..best.0]), hex(&g[best.0 + best.1..]))
}

fn parse_cidr(s: &str) -> Option<(Ip, u32)> {
    let (a, p) = s.split_once('/')?;
    let ip = parse_ip(a)?;
    if p.is_empty() || p.len() > 3 || !p.bytes().all(|c| c.is_ascii_digit()) || (p.len() > 1 && p.starts_with('0')) {
        return None;
    }
    let p: u32 = p.parse().ok()?;
    (p <= if ip.1 { 128 } else { 32 }).then_some((ip, p))
}

fn fmt_cidr((ip, p): (Ip, u32)) -> String {
    format!("{}/{p}", fmt_ip(ip))
}

fn net_bits((bits, v6): Ip, p: u32) -> u128 {
    let host = (if v6 { 128 } else { 32 }) - p;
    bits.checked_shr(host).unwrap_or(0).checked_shl(host).unwrap_or(0)
}

fn ip_method(m: &str, s: &str, args: &[Value]) -> Result<Value, String> {
    if let Some((ip @ (bits, v6), p)) = parse_cidr(s) {
        let arg_s = || match args {
            [Value::String(x)] => Ok(x.as_str()),
            _ => Err(format!("{m}() requires a string argument")),
        };
        return Ok(match m {
            "ip" => Value::String(fmt_ip(ip)),
            "masked" => Value::String(fmt_cidr(((net_bits(ip, p), v6), p))),
            "prefixLength" => Value::Number(Number::from_i64(p as i64)),
            "family" => Value::Number(Number::from_i64(if v6 { 6 } else { 4 })),
            "containsIP" => {
                let x = parse_ip(arg_s()?).ok_or("containsIP() requires a valid IP")?;
                Value::Bool(x.1 == v6 && net_bits(x, p) == net_bits((bits, v6), p))
            }
            "containsCIDR" => {
                let (x, xp) = parse_cidr(arg_s()?).ok_or("containsCIDR() requires a valid CIDR")?;
                Value::Bool(x.1 == v6 && xp >= p && net_bits(x, p) == net_bits((bits, v6), p))
            }
            _ => return Err(format!("{m}() is not supported on a CIDR")),
        });
    }
    let (bits, v6) = parse_ip(s).ok_or_else(|| format!("{m}() receiver {s:?} is not an IP or CIDR"))?;
    let top = |n: u32| (bits >> (128 - n)) as u32;
    let b4 = bits as u32;
    let multicast = if v6 { top(8) == 0xff } else { b4 >> 28 == 0xe };
    let ll_uni = if v6 { top(10) == 0x3fa } else { b4 >> 16 == 0xa9fe };
    let ll_multi = if v6 { top(16) == 0xff02 } else { b4 >> 8 == 0xe00000 };
    let loopback = if v6 { bits == 1 } else { b4 >> 24 == 127 };
    Ok(match m {
        "family" => Value::Number(Number::from_i64(if v6 { 6 } else { 4 })),
        "isUnspecified" => Value::Bool(bits == 0),
        "isLoopback" => Value::Bool(loopback),
        "isLinkLocalMulticast" => Value::Bool(ll_multi),
        "isLinkLocalUnicast" => Value::Bool(ll_uni),
        "isGlobalUnicast" => Value::Bool(bits != 0 && !loopback && !multicast && !ll_uni && !(!v6 && b4 == u32::MAX)),
        _ => return Err(format!("{m}() requires a CIDR receiver")),
    })
}

fn matches_re(s: &Value, re: &Value) -> Result<Value, String> {
    let (Value::String(s), Value::String(re)) = (s, re) else { return Err("matches() requires strings".into()) };
    Ok(Value::Bool(crate::regex::Regex::new(re).map_err(|e| format!("invalid regex: {e}"))?.is_match(s)?))
}

fn is_url(s: &str) -> bool {
    // Minimal URL validity check: scheme://host...
    let Some((scheme, rest)) = s.split_once("://") else { return false };
    if scheme.is_empty() || !scheme.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.') {
        return false;
    }
    if rest.is_empty() || rest.contains(' ') || rest.contains('\t') || rest.contains('\n') {
        return false;
    }
    // host part before first '/' '?' '#'
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.split('@').last().unwrap_or("");
    let host = host.split(':').next().unwrap_or("");
    if host.is_empty() { return false; }
    // allow IPv6 brackets
    if host.starts_with('[') {
        return host.ends_with(']');
    }
    true
}

fn parse_duration(s: &str) -> Option<f64> {
    // Supports forms like "1s", "1m", "1h", "1.5s", "100ms", "0s", and bare seconds.
    let s = s.trim();
    if s.is_empty() { return None; }
    // split numeric prefix and unit suffix
    let mut i = 0;
    for (idx, c) in s.char_indices() {
        if c.is_ascii_digit() || c == '.' || c == '-' || c == '+' {
            i = idx + c.len_utf8();
        } else {
            break;
        }
    }
    if i == 0 { return None; }
    let (num, unit) = s.split_at(i);
    let n: f64 = num.parse().ok()?;
    let mult: f64 = match unit.trim() {
        "" | "s" | "sec" | "second" | "seconds" => 1.0,
        "ms" | "millisecond" | "milliseconds" => 1e-3,
        "us" | "microsecond" | "microseconds" | "µs" => 1e-6,
        "ns" | "nanosecond" | "nanoseconds" => 1e-9,
        "m" | "min" | "minute" | "minutes" => 60.0,
        "h" | "hr" | "hour" | "hours" => 3600.0,
        "d" | "day" | "days" => 86400.0,
        _ => return None,
    };
    Some(n * mult * 1e9) // nanoseconds
}

fn size(v: &Value) -> Result<Value, String> {
    let n = match v {
        Value::String(s) => s.chars().count(),
        Value::Array(a) => a.len(),
        Value::Object(o) => o.len(),
        _ => return Err("size() of unsupported type".into()),
    };
    Ok(Value::Number(Number::from_u64(n as u64)))
}

/// CEL type names, as in cel-go's messages; `dyn` is unknown.
type Ty = &'static str;

fn lit_ty(v: &Value) -> Ty {
    match v {
        Value::Null => "null_type",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_integer() => "int",
        Value::Number(_) => "double",
        Value::String(_) => "string",
        Value::Array(_) => "list",
        Value::Object(_) => "map",
    }
}

fn numeric(t: Ty) -> bool {
    matches!(t, "int" | "uint" | "double")
}

/// `object.spec.replicas` as ("object", ["spec", "replicas"]).
fn select_path(e: &E) -> Option<(&str, Vec<&str>)> {
    match e {
        E::Var(n) => Some((n.as_str(), Vec::new())),
        E::Field(b, n) => select_path(b).map(|(r, mut p)| {
            p.push(n.as_str());
            (r, p)
        }),
        _ => None,
    }
}

/// Field types come from `resolve(root, path)` (`None`: unknown). Operators whose operand types
/// are both known and have no overload are reported, like cel-go's checker.
fn ty(e: &E, resolve: &dyn Fn(&str, &[&str]) -> Option<Ty>, warns: &mut Vec<String>) -> Ty {
    let t = |x: &E, w: &mut Vec<String>| ty(x, resolve, w);
    match e {
        E::Lit(v) => lit_ty(v),
        E::Var(_) | E::Field(..) => match select_path(e) {
            Some((root, path)) => resolve(root, &path).unwrap_or("dyn"),
            None => {
                if let E::Field(b, _) = e {
                    t(b, warns);
                }
                "dyn"
            }
        },
        E::Index(a, b) => {
            t(a, warns);
            t(b, warns);
            "dyn"
        }
        E::Not(x) => {
            t(x, warns);
            "bool"
        }
        E::List(v) => {
            v.iter().for_each(|x| {
                t(x, warns);
            });
            "list"
        }
        E::Map(m) => {
            for (k, v) in m {
                t(k, warns);
                t(v, warns);
            }
            "map"
        }
        E::Struct(_, f) => {
            f.iter().for_each(|(_, v)| {
                t(v, warns);
            });
            "dyn"
        }
        E::Cond(c, a, b) => {
            t(c, warns);
            let (x, y) = (t(a, warns), t(b, warns));
            if x == y { x } else { "dyn" }
        }
        E::Func(f, a) => {
            a.iter().for_each(|x| {
                t(x, warns);
            });
            match f.as_str() {
                "size" | "int" => "int",
                "type" | "ip" | "cidr" => "dyn",
                "double" => "double",
                "string" => "string",
                _ => "bool",
            }
        }
        E::Method(b, m, a) => {
            t(b, warns);
            a.iter().skip(if MACROS.contains(&m.as_str()) { 1 } else { 0 }).for_each(|x| {
                t(x, warns);
            });
            match m.as_str() {
                "size" | "family" | "prefixLength" => "int",
                "ip" | "masked" => "dyn",
                "substring" | "replace" | "charAt" | "join" | "reverse" => "string",
                "indexOf" | "lastIndexOf" => "int",
                "split" => "list",
                "lowerAscii" | "upperAscii" | "trim" => "string",
                "filter" | "map" => "list",
                _ => "bool",
            }
        }
        E::Bin(op, l, r) => {
            let (a, b) = (t(l, warns), t(r, warns));
            let known = a != "dyn" && b != "dyn";
            let bad = |w: &mut Vec<String>| w.push(format!("found no matching overload for '_{op}_' applied to '({a}, {b})'"));
            match *op {
                "<" | "<=" | ">" | ">=" => {
                    if known && a != b && !(numeric(a) && numeric(b)) || known && !(numeric(a) || matches!(a, "string" | "bool" | "bytes")) {
                        bad(warns);
                    }
                    "bool"
                }
                "&&" | "||" => {
                    if known && (a != "bool" || b != "bool") {
                        bad(warns);
                    }
                    "bool"
                }
                "==" | "!=" | "in" => "bool",
                "+" => {
                    if !known {
                        return "dyn";
                    }
                    if a == b && matches!(a, "int" | "uint" | "double" | "string" | "list" | "bytes") {
                        a
                    } else {
                        bad(warns);
                        "dyn"
                    }
                }
                _ => {
                    if !known {
                        return "dyn";
                    }
                    if a == b && numeric(a) && !(*op == "%" && a == "double") {
                        a
                    } else {
                        bad(warns);
                        "dyn"
                    }
                }
            }
        }
    }
}

/// A parsed expression.
pub struct Program {
    e: E,
    uses: Vec<String>,
}

impl Program {
    /// Parses `expr` and checks that it only uses supported constructs and the variables `vars`.
    pub fn compile(expr: &str, vars: &[&str]) -> Result<Program, String> {
        let p = Program::parse(expr)?;
        check(&p.e, &mut vars.iter().map(|s| s.to_string()).collect())?;
        Ok(p)
    }

    fn parse(expr: &str) -> Result<Program, String> {
        let t = lex(expr)?;
        let uses = t.iter().filter_map(|t| if let Tok::Id(i) = t { Some(i.clone()) } else { None }).collect();
        let mut p = P { t, i: 0 };
        let e = p.expr()?;
        if p.i != p.t.len() {
            return Err("unexpected trailing tokens".into());
        }
        Ok(Program { e, uses })
    }

    /// Overload errors a type checker would report, given the field types `resolve` knows.
    pub fn type_warnings(&self, resolve: &dyn Fn(&str, &[&str]) -> Option<&'static str>) -> Vec<String> {
        let mut w = Vec::new();
        ty(&self.e, resolve, &mut w);
        w
    }

    /// The static type of the expression (`dyn` when unknown).
    pub fn static_type(&self, resolve: &dyn Fn(&str, &[&str]) -> Option<&'static str>) -> &'static str {
        ty(&self.e, resolve, &mut Vec::new())
    }

    /// Whether the expression mentions the identifier `name`.
    pub fn uses(&self, name: &str) -> bool {
        self.uses.iter().any(|u| u == name)
    }

    pub fn eval(&self, vars: &[(&str, &Value)]) -> Result<Value, String> {
        eval(&self.e, vars)
    }

    pub fn eval_bool(&self, vars: &[(&str, &Value)]) -> Result<bool, String> {
        truth(self.eval(vars))
    }
}

/// Evaluates a boolean CEL expression over `vars` (see the module docs for the subset).
pub fn cel_bool(expr: &str, vars: &[(&str, &Value)]) -> Result<bool, String> {
    Program::parse(expr)?.eval_bool(vars)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extended() {
        let o = json::parse_str(r#"{"l":[1,2,3],"s":"Hello","m":{"a":1},"n":5,"u":"https://example.com/a?b=1"}"#).unwrap();
        let v = [("self", &o)];
        let t = |e: &str| cel_bool(e, &v);
        assert_eq!(t("self.l.all(x, x > 0) && self.l.exists(x, x == 2)"), Ok(true));
        assert_eq!(t("self.l.exists_one(x, x > 2) && self.l.filter(x, x > 1).size() == 2"), Ok(true));
        assert_eq!(t("self.l.map(x, x * 2)[2] == 6"), Ok(true));
        assert_eq!(t("self.s.matches('^H.*o$') && self.s.lowerAscii() == 'hello'"), Ok(true));
        assert_eq!(t("self.n % 2 == 1 ? self.n - 1 == 4 : false"), Ok(true));
        assert_eq!(t("-self.n < 0 && 7 / 2 == 3 && 1.5 * 2 == 3"), Ok(true));
        assert_eq!(t("self.m.all(k, k == 'a')"), Ok(true));
        assert_eq!(t("isURL(self.u)"), Ok(true));
        assert_eq!(t("isURL('not a url')"), Ok(false));
        assert_eq!(t("duration('1m') == duration('60s')"), Ok(true));
        assert_eq!(t("duration('2m') > duration('1m')"), Ok(true));
        assert_eq!(t("'2m' >= '1m'"), Ok(true));
        assert!(Program::compile("self.n > 1", &["self"]).is_ok());
        assert!(Program::compile("foo(self)", &["self"]).is_err());
        assert!(Program::compile("other > 1", &["self"]).is_err());
        assert!(Program::compile("self.l.all(x, y > 1)", &["self"]).is_err());
        assert!(Program::compile("self.foo()", &["self"]).is_err());
        assert!(Program::compile("self.n > oldSelf.n", &["self", "oldSelf"]).unwrap().uses("oldSelf"));
    }

    #[test]
    fn type_and_ip_library() {
        let o = |j: &str| json::parse_str(j).unwrap();
        let t = |e: &str, j: &str| cel_bool(e, &[("self", &o(j))]);
        let proto = "type(self.protocol) == int ? self.protocol in [6, 17, 132] : self.protocol in ['TCP', 'UDP', 'SCTP']";
        assert_eq!(t(proto, r#"{"protocol":6}"#), Ok(true));
        assert_eq!(t(proto, r#"{"protocol":"TCP"}"#), Ok(true));
        assert_eq!(t(proto, r#"{"protocol":"ICMP"}"#), Ok(false));
        assert_eq!(t(proto, r#"{"protocol":7}"#), Ok(false));
        assert_eq!(t("int('5') == 5 && type(1.5) == double && type([]) == list && type({}) == map", "{}"), Ok(true));
        assert_eq!(t("type(self.a) == string", r#"{"a":"x"}"#), Ok(true));
        let masked = "cidr(self.cidr) == cidr(self.cidr).masked()";
        assert_eq!(t(masked, r#"{"cidr":"10.0.0.0/24"}"#), Ok(true));
        assert_eq!(t(masked, r#"{"cidr":"10.0.0.5/24"}"#), Ok(false));
        assert_eq!(t("cidr(self.cidr).ip().family() != 6", r#"{"cidr":"10.0.0.5/24"}"#), Ok(true));
        assert_eq!(t("cidr(self.cidr).ip().family() != 6", r#"{"cidr":"fd00::/8"}"#), Ok(false));
        let ll = "!cidr('169.254.0.0/16').containsIP(cidr(self.cidr).ip())";
        assert_eq!(t(ll, r#"{"cidr":"10.0.0.5/24"}"#), Ok(true));
        assert_eq!(t(ll, r#"{"cidr":"169.254.1.1/32"}"#), Ok(false));
        assert_eq!(t("cidr('fe80::/10').containsIP('fe80::1')", "{}"), Ok(true));
        assert_eq!(t("cidr('10.0.0.0/8').containsCIDR('10.1.0.0/16') && !cidr('10.1.0.0/16').containsCIDR('10.0.0.0/8')", "{}"), Ok(true));
        assert_eq!(t("self.all(n, isCIDR(n) || isIP(n))", r#"["10.0.0.0/8","::1","1.2.3.4"]"#), Ok(true));
        assert_eq!(t("self.all(n, isCIDR(n) || isIP(n))", r#"["10.0.0.0/8","nope"]"#), Ok(false));
        assert_eq!(t("cidr(self.cidr).prefixLength() <= 26", r#"{"cidr":"10.0.0.0/24"}"#), Ok(true));
        assert_eq!(t("cidr(self.cidr).prefixLength() <= 26", r#"{"cidr":"10.0.0.0/27"}"#), Ok(false));
        assert!(t("ip('1.2.3')== ip('1.2.3')", "{}").is_err());
        assert!(t("cidr('10.0.0.0/33') == cidr('10.0.0.0/8')", "{}").is_err());
        assert_eq!(t("!isIP('1.2.3.256') && !isCIDR('10.0.0.0') && !isIP('::g')", "{}"), Ok(true));
        assert_eq!(t("ip('2001:0db8:0:0:0:0:0:1') == ip('2001:db8::1') && ip('2001:db8::1') == '2001:db8::1'", "{}"), Ok(true));
        assert_eq!(t("ip('::1').isLoopback() && ip('0.0.0.0').isUnspecified() && ip('8.8.8.8').isGlobalUnicast() && ip('fe80::1').isLinkLocalUnicast() && ip('224.0.0.1').isLinkLocalMulticast()", "{}"), Ok(true));
        assert!(Program::compile("type(self.p) == int ? 1 : 2", &["self"]).is_ok());
        assert!(Program::compile("int > 1", &["self"]).is_ok());
        let w = Program::compile(proto, &["self"]).unwrap().type_warnings(&|_, _| None);
        assert!(w.is_empty());
    }

    #[test]
    fn string_extensions() {
        let o = |j: &str| json::parse_str(j).unwrap();
        let t = |e: &str, j: &str| cel_bool(e, &[("self", &o(j))]);
        let rule = "self == '' || isIP(self) || (self.startsWith('[') && self.contains(']:') && isIP(self.substring(1, self.lastIndexOf(']:'))) && self.substring(self.lastIndexOf(']:') + 2).matches('^[0-9]{1,5}$') && int(self.substring(self.lastIndexOf(']:') + 2)) >= 1 && int(self.substring(self.lastIndexOf(']:') + 2)) <= 65535) || (self.matches('^[0-9.]+:[0-9]{1,5}$') && isIP(self.split(':')[0]) && int(self.split(':')[1]) >= 1 && int(self.split(':')[1]) <= 65535)";
        assert!(Program::compile(rule, &["self"]).is_ok());
        for (v, want) in [("", true), ("10.0.0.1", true), ("[fd00::1]:179", true), ("10.0.0.1:179", true), ("10.0.0.1:99999", false), ("junk", false)] {
            assert_eq!(t(rule, &format!("\"{v}\"")), Ok(want), "{v}");
        }
        assert_eq!(t("int('179') == 179", "\"\""), Ok(true));
        let c = "'hello world'.substring(6) == 'world' && 'hello'.substring(1, 3) == 'el' && 'abca'.indexOf('a', 1) == 3 && 'abc'.indexOf('z') == -1 && 'abca'.lastIndexOf('a') == 3 && 'abca'.lastIndexOf('a', 2) == 0 && 'a,b,c'.split(',').size() == 3 && 'a,b,c'.split(',', 2)[1] == 'b,c' && 'aaa'.replace('a', 'b', 2) == 'bba' && 'aaa'.replace('a', 'c') == 'ccc' && 'abc'.charAt(1) == 'b' && ['a','b'].join('-') == 'a-b' && ['a','b'].join() == 'ab' && 'abc'.reverse() == 'cba'";
        assert_eq!(t(c, "{}"), Ok(true));
        assert!(t("'abc'.substring(2, 5) == ''", "{}").is_err());
        assert!(t("'abc'.substring(-1) == ''", "{}").is_err());
    }

    #[test]
    fn construction_and_maps() {
        let o = json::parse_str(r#"{"n":2}"#).unwrap();
        let p = Program::compile(r#"Object{spec: Object.spec{replicas: object.n * 2}, metadata: Object.metadata{annotations: {"a": "b", "c": string(object.n)}}}"#, &["object"]).unwrap();
        let v = p.eval(&[("object", &o)]).unwrap();
        assert_eq!(json::to_string(&v), r#"{"spec":{"replicas":4},"metadata":{"annotations":{"a":"b","c":"2"}}}"#);
        let j = Program::compile(r#"[JSONPatch{op: "add", path: "/x", value: 1}]"#, &[]).unwrap().eval(&[]).unwrap();
        assert_eq!(json::to_string(&j), r#"[{"op":"add","path":"/x","value":1}]"#);
        assert!(Program::compile("Foo{a: 1}", &[]).is_err(), "only Object and JSONPatch types");
        assert!(Program::compile("{1: 2}", &[]).unwrap().eval(&[]).is_err());
    }

    #[test]
    fn overload_warnings() {
        let r = |root: &str, path: &[&str]| -> Option<Ty> { (root == "object" && path == ["spec", "replicas"]).then_some("int") };
        let w = |e: &str| Program::compile(e, &["object"]).unwrap().type_warnings(&r);
        assert!(w("object.spec.replicas > 1").is_empty());
        assert_eq!(w("object.spec.replicas > '1'"), ["found no matching overload for '_>_' applied to '(int, string)'"]);
        assert_eq!(w("'got ' + object.spec.replicas"), ["found no matching overload for '_+_' applied to '(string, int)'"]);
        assert!(w("'got ' + string(object.spec.replicas)").is_empty());
        assert!(w("object.spec.other > '1'").is_empty(), "unknown fields are dyn");
        assert!(w("object.spec.replicas > 1.5").is_empty(), "cross-type numeric comparison");
    }
}
