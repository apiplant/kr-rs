//! A small CEL subset shared by admission webhook matchConditions and CRD
//! `x-kubernetes-validations`. Supported: `== != < <= > >= ! && || in + - * / % ?:`, field and
//! index access, `has() size() matches() int() double() string()`, string methods
//! (`startsWith endsWith contains matches size lowerAscii upperAscii trim`), the comprehension
//! macros `all exists exists_one filter map`, and string/number/bool/null/list literals.

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
                        'r' => '\r',
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
                let op = ["<", ">", "!", "(", ")", "[", "]", ".", ",", "+", "-", "*", "/", "%", "?", ":"].into_iter().find(|o| o.starts_with(c)).ok_or_else(|| format!("unexpected character {c:?}"))?;
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
    Cond(Box<E>, Box<E>, Box<E>),
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
const FUNCS: [&str; 6] = ["has", "size", "matches", "int", "double", "string"];

/// Rejects references and calls the evaluator does not support (done once, at compile time).
fn check(e: &E, scope: &mut Vec<String>) -> Result<(), String> {
    match e {
        E::Lit(_) => Ok(()),
        E::Var(n) => {
            if scope.contains(n) {
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
            } else if METHODS.contains(&m.as_str()) {
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
        E::Var(n) => vars.iter().rev().find(|(k, _)| k == n).map(|(_, v)| (*v).clone()).ok_or_else(|| format!("undeclared reference to {n:?}"))?,
        E::Field(b, n) => eval(b, vars)?.get(n).cloned().ok_or_else(|| format!("no such key: {n}"))?,
        E::Index(b, k) => match (eval(b, vars)?, eval(k, vars)?) {
            (o @ Value::Object(_), Value::String(k)) => o.get(&k).cloned().ok_or_else(|| format!("no such key: {k}"))?,
            (Value::Array(a), Value::Number(n)) => a.get(n.as_f64() as usize).cloned().ok_or("index out of bounds")?,
            _ => return Err("invalid index".into()),
        },
        E::Not(x) => Value::Bool(!truth(eval(x, vars))?),
        E::List(a) => Value::Array(a.iter().map(|x| eval(x, vars)).collect::<Result<_, _>>()?),
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
            let Value::String(s) = &recv else { return Err(format!("unsupported method {m}")) };
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

fn matches_re(s: &Value, re: &Value) -> Result<Value, String> {
    let (Value::String(s), Value::String(re)) = (s, re) else { return Err("matches() requires strings".into()) };
    Ok(Value::Bool(crate::regex::Regex::new(re).map_err(|e| format!("invalid regex: {e}"))?.is_match(s)?))
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
        let o = json::parse_str(r#"{"l":[1,2,3],"s":"Hello","m":{"a":1},"n":5}"#).unwrap();
        let v = [("self", &o)];
        let t = |e: &str| cel_bool(e, &v);
        assert_eq!(t("self.l.all(x, x > 0) && self.l.exists(x, x == 2)"), Ok(true));
        assert_eq!(t("self.l.exists_one(x, x > 2) && self.l.filter(x, x > 1).size() == 2"), Ok(true));
        assert_eq!(t("self.l.map(x, x * 2)[2] == 6"), Ok(true));
        assert_eq!(t("self.s.matches('^H.*o$') && self.s.lowerAscii() == 'hello'"), Ok(true));
        assert_eq!(t("self.n % 2 == 1 ? self.n - 1 == 4 : false"), Ok(true));
        assert_eq!(t("-self.n < 0 && 7 / 2 == 3 && 1.5 * 2 == 3"), Ok(true));
        assert_eq!(t("self.m.all(k, k == 'a')"), Ok(true));
        assert!(Program::compile("self.n > 1", &["self"]).is_ok());
        assert!(Program::compile("foo(self)", &["self"]).is_err());
        assert!(Program::compile("other > 1", &["self"]).is_err());
        assert!(Program::compile("self.l.all(x, y > 1)", &["self"]).is_err());
        assert!(Program::compile("self.foo()", &["self"]).is_err());
        assert!(Program::compile("self.n > oldSelf.n", &["self", "oldSelf"]).unwrap().uses("oldSelf"));
    }
}
