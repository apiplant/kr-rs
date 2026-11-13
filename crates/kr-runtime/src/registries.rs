//! `registries.yaml` (k3s format) and `KR_REGISTRY_MIRRORS`: mirror endpoints, repository
//! rewrites, per-host credentials and TLS settings (ADR-027, ADR-044).
//!
//! ```yaml
//! mirrors:
//!   docker.io:                      # or "*" for every registry
//!     endpoint: [https://cache:5000, http://10.0.0.4:5000]
//!     rewrite: {"^library/(.*)": "mirror/$1"}
//! configs:
//!   cache:5000:
//!     auth: {username: u, password: p}   # or token / identitytoken
//!     tls: {ca_file: /etc/ca.pem, cert_file: c.pem, key_file: k.pem, insecure_skip_verify: false}
//! ```
use crate::auth::registry_key;
use crate::store::{Error, Result};
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_fmt::json::Value;
use kr_net::registry::Credential;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TlsCfg {
    pub ca_file: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub insecure: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostCfg {
    pub auth: Option<Credential>,
    pub tls: TlsCfg,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mirror {
    pub endpoints: Vec<String>,
    /// (regex, replacement) applied to the repository name, in order, first match wins.
    pub rewrites: Vec<(String, String)>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Registries {
    pub mirrors: Vec<(String, Mirror)>,
    /// Keyed by canonical `host[:port]`.
    pub configs: Vec<(String, HostCfg)>,
}

/// One place to try for a pull, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    /// `host[:port]`.
    pub host: String,
    pub plain_http: bool,
    pub repository: String,
    pub is_mirror: bool,
    /// Path under which the endpoint serves `/v2/` (empty for the usual root).
    pub base_path: String,
}

/// An endpoint: (`host[:port]`, plain http, repository prefix, base path). A path `/v2/<prefix>`
/// (the form Harbor, Artifactory and Nexus proxy projects use) puts `<prefix>/` in front of the
/// repository name; a bare `/v2` is the registry root; any other path is the base the registry's
/// `/v2/` API is served under.
fn endpoint(e: &str) -> Option<(String, bool, String, String)> {
    let e = e.trim();
    let (plain, host) = match e.split_once("://") {
        Some(("http", h)) => (true, h),
        Some(("https", h)) => (false, h),
        Some(_) => return None,
        None => (false, e),
    };
    let (host, path) = match host.split_once('/') {
        Some((h, p)) => (h, p.trim_matches('/')),
        None => (host, ""),
    };
    let (prefix, base) = match path {
        "" | "v2" => ("", ""),
        p => match p.strip_prefix("v2/") {
            Some(x) => (x, ""),
            None => ("", p),
        },
    };
    let clean = |s: &str| !s.split('/').any(|c| c == "." || c == ".." || c.is_empty() && !s.is_empty());
    (!host.is_empty() && clean(prefix) && clean(base) && !host.contains(['?', '#', '@'])).then(|| (host.to_string(), plain, prefix.to_string(), if base.is_empty() { String::new() } else { alloc::format!("/{base}") }))
}

fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).filter(|x| !x.is_empty()).map(|x| x.to_string())
}

impl Registries {
    pub fn parse(yaml: &str) -> Result<Registries> {
        let root = kr_fmt::yaml::parse(yaml).map_err(|_| Error::Image("registries.yaml is not valid YAML"))?;
        let mut out = Registries::default();
        if root.is_null() {
            return Ok(out);
        }
        if root.as_object().is_none() {
            return Err(Error::Image("registries.yaml must be a mapping"));
        }
        if let Some(m) = root.get("mirrors").and_then(Value::as_object) {
            for (reg, v) in m {
                let mut mirror = Mirror::default();
                match v.get("endpoint") {
                    Some(Value::String(e)) => mirror.endpoints.extend(endpoint(e).map(|(h, p, x, b)| fmt_ep(&h, p, &x, &b))),
                    Some(Value::Array(a)) => mirror.endpoints.extend(a.iter().filter_map(Value::as_str).filter_map(endpoint).map(|(h, p, x, b)| fmt_ep(&h, p, &x, &b))),
                    _ => {}
                }
                if let Some(rw) = v.get("rewrite").and_then(Value::as_object) {
                    for (re, to) in rw {
                        let to = to.as_str().ok_or(Error::Image("registries.yaml: rewrite replacement must be a string"))?;
                        Regex::new(re).ok_or(Error::Image("registries.yaml: unsupported rewrite regex"))?;
                        mirror.rewrites.push((re.clone(), to.to_string()));
                    }
                }
                let key = if reg == "*" { "*".to_string() } else { registry_key(reg) };
                out.mirrors.push((key, mirror));
            }
        }
        if let Some(c) = root.get("configs").and_then(Value::as_object) {
            for (host, v) in c {
                let mut cfg = HostCfg::default();
                if let Some(a) = v.get("auth") {
                    cfg.auth = Some(Credential {
                        username: s(a, "username").unwrap_or_default(),
                        password: s(a, "password").unwrap_or_default(),
                        identity_token: s(a, "identitytoken"),
                        token: s(a, "token"),
                    });
                }
                if let Some(t) = v.get("tls") {
                    cfg.tls = TlsCfg {
                        ca_file: s(t, "ca_file"),
                        cert_file: s(t, "cert_file"),
                        key_file: s(t, "key_file"),
                        insecure: t.get("insecure_skip_verify").and_then(Value::as_bool).unwrap_or(false),
                    };
                }
                // `*` is the default for every registry that has no entry of its own.
                let key = if host == "*" { "*".to_string() } else { registry_key(host) };
                out.configs.push((key, cfg));
            }
        }
        Ok(out)
    }

    /// `KR_REGISTRY_MIRRORS` (`registry=url,registry=url`): one endpoint per entry.
    pub fn parse_env(v: &str) -> Registries {
        let mut out = Registries::default();
        for e in v.split(',') {
            let Some((from, to)) = e.trim().split_once('=') else { continue };
            let Some((h, p, x, b)) = endpoint(to) else { continue };
            let key = registry_key(from);
            let ep = fmt_ep(&h, p, &x, &b);
            match out.mirrors.iter_mut().find(|(k, _)| *k == key) {
                Some((_, m)) => m.endpoints.push(ep),
                None => out.mirrors.push((key, Mirror { endpoints: alloc::vec![ep], rewrites: Vec::new() })),
            }
        }
        out
    }

    /// `self` (the file) wins over `other` (the environment) per mirror key and per config host.
    pub fn merge_under(mut self, other: Registries) -> Registries {
        for (k, m) in other.mirrors {
            if !self.mirrors.iter().any(|(x, _)| *x == k) {
                self.mirrors.push((k, m));
            }
        }
        for (k, c) in other.configs {
            if !self.configs.iter().any(|(x, _)| *x == k) {
                self.configs.push((k, c));
            }
        }
        self
    }

    /// Where the file lives: `$KR_REGISTRIES_YAML`, else `/etc/kr/registries.yaml` for root,
    /// else `<store root>/registries.yaml`.
    pub fn file_path() -> Option<String> {
        if let Some(p) = crate::store::env_var("KR_REGISTRIES_YAML").filter(|p| !p.is_empty()) {
            return Some(p);
        }
        if kr_sys::fs::getuid() == 0 {
            return Some("/etc/kr/registries.yaml".to_string());
        }
        crate::store::default_root().ok().map(|r| alloc::format!("{}/registries.yaml", r.trim_end_matches('/')))
    }

    /// File + environment, merged. A missing file is fine; an unreadable or invalid one is an
    /// error (a typo must not silently send pulls to the wrong place).
    pub fn load() -> Result<Registries> {
        let env = crate::store::env_var("KR_REGISTRY_MIRRORS").map(|v| Registries::parse_env(&v)).unwrap_or_default();
        let Some(p) = Self::file_path() else { return Ok(env) };
        let mut c = p.into_bytes();
        c.push(0);
        match kr_sys::fs::read_file(&c, 1 << 20) {
            Ok(b) => {
                let t = core::str::from_utf8(&b).map_err(|_| Error::Image("registries.yaml is not UTF-8"))?;
                Ok(Registries::parse(t)?.merge_under(env))
            }
            Err(kr_sys::Errno(2)) => Ok(env),
            Err(e) => Err(Error::Io("read registries.yaml", e)),
        }
    }

    pub fn host_cfg(&self, host: &str) -> Option<&HostCfg> {
        let k = registry_key(host);
        self.configs.iter().find(|(h, _)| *h == k).or_else(|| self.configs.iter().find(|(h, _)| h == "*")).map(|(_, c)| c)
    }

    /// Mirrors for `registry` in order, then the upstream itself.
    pub fn attempts(&self, registry: &str, repository: &str) -> Vec<Attempt> {
        let key = registry_key(registry);
        let m = self.mirrors.iter().find(|(k, _)| *k == key).or_else(|| self.mirrors.iter().find(|(k, _)| k == "*")).map(|(_, m)| m);
        let mut out = Vec::new();
        if let Some(m) = m {
            let repo = m.rewrites.iter().find_map(|(re, to)| Regex::new(re)?.replace(repository, to)).unwrap_or_else(|| repository.to_string());
            for e in &m.endpoints {
                if let Some((host, plain_http, prefix, base_path)) = endpoint(e) {
                    let repository = if prefix.is_empty() { repo.clone() } else { alloc::format!("{prefix}/{repo}") };
                    out.push(Attempt { host, plain_http, repository, is_mirror: true, base_path });
                }
            }
        }
        out.push(Attempt { host: registry.to_string(), plain_http: false, repository: repository.to_string(), is_mirror: false, base_path: String::new() });
        out
    }
}

fn fmt_ep(host: &str, plain: bool, prefix: &str, base: &str) -> String {
    let path = if !prefix.is_empty() { alloc::format!("/v2/{prefix}") } else { String::from(base) };
    alloc::format!("{}://{host}{path}", if plain { "http" } else { "https" })
}

// ---- a small backtracking regex: literals . [] \d\w\s * + ? () | ^ $ ----

enum Node {
    Char(u8),
    Any,
    Class(Vec<(u8, u8)>, bool),
    Start,
    End,
    Group(usize, Vec<Vec<Node>>),
    /// `(?:...)`: grouping without a capture.
    NonCap(Vec<Vec<Node>>),
    /// `(?=...)` / `(?!...)`: a look-ahead (negated when true).
    Look(Vec<Vec<Node>>, bool),
    /// (node, min, max, lazy)
    Repeat(Box<Node>, usize, usize, bool),
}

pub struct Regex {
    alts: Vec<Vec<Node>>,
    groups: usize,
}

type Caps = Vec<Option<(usize, usize)>>;

struct P<'a> {
    s: &'a [u8],
    i: usize,
    groups: usize,
}

impl P<'_> {
    fn alt(&mut self, depth: usize) -> Option<Vec<Vec<Node>>> {
        if depth > 16 {
            return None;
        }
        let mut alts = alloc::vec![Vec::new()];
        while let Some(&c) = self.s.get(self.i) {
            self.i += 1;
            let node = match c {
                b')' => {
                    if depth == 0 {
                        return None;
                    }
                    self.i -= 1;
                    return Some(alts);
                }
                b'|' => {
                    alts.push(Vec::new());
                    continue;
                }
                b'(' => {
                    // `(?:`, `(?=` and `(?!` are supported; flags such as `(?i)` and look-behind are not.
                    let kind = if self.s.get(self.i) == Some(&b'?') {
                        let k = *self.s.get(self.i + 1)?;
                        if !matches!(k, b':' | b'=' | b'!') {
                            return None;
                        }
                        self.i += 2;
                        k
                    } else {
                        b'('
                    };
                    let idx = if kind == b'(' {
                        self.groups += 1;
                        self.groups
                    } else {
                        0
                    };
                    let inner = self.alt(depth + 1)?;
                    if self.s.get(self.i) != Some(&b')') {
                        return None;
                    }
                    self.i += 1;
                    match kind {
                        b'(' => Node::Group(idx, inner),
                        b':' => Node::NonCap(inner),
                        k => Node::Look(inner, k == b'!'),
                    }
                }
                b'^' => Node::Start,
                b'$' => Node::End,
                b'.' => Node::Any,
                b'[' => self.class()?,
                b'\\' => self.escape(false)?,
                b'*' | b'+' | b'?' | b'{' => return None,
                c => Node::Char(c),
            };
            let (node, adv) = match self.s.get(self.i) {
                Some(b'*') => (Node::Repeat(Box::new(node), 0, usize::MAX, false), 1),
                Some(b'+') => (Node::Repeat(Box::new(node), 1, usize::MAX, false), 1),
                Some(b'?') => (Node::Repeat(Box::new(node), 0, 1, false), 1),
                Some(b'{') => {
                    let (min, max, len) = self.braces()?;
                    (Node::Repeat(Box::new(node), min, max, false), len)
                }
                _ => {
                    alts.last_mut()?.push(node);
                    continue;
                }
            };
            self.i += adv;
            let node = match node {
                Node::Repeat(n, min, max, _) if self.s.get(self.i) == Some(&b'?') => {
                    self.i += 1; // lazy: `*?`, `+?`, `??`, `{n,m}?`
                    Node::Repeat(n, min, max, true)
                }
                n => n,
            };
            alts.last_mut()?.push(node);
        }
        (depth == 0).then_some(alts)
    }

    /// `{n}`, `{n,}` or `{n,m}` at the cursor: (min, max, bytes consumed). Counts stay small.
    fn braces(&self) -> Option<(usize, usize, usize)> {
        let rest = self.s.get(self.i + 1..)?;
        let end = rest.iter().position(|&b| b == b'}')?;
        let body = core::str::from_utf8(&rest[..end]).ok()?;
        let num = |t: &str| (!t.is_empty() && t.len() <= 3 && t.bytes().all(|b| b.is_ascii_digit())).then(|| t.parse::<usize>().ok()).flatten();
        let (min, max) = match body.split_once(',') {
            None => (num(body)?, num(body)?),
            Some((a, "")) => (num(a)?, usize::MAX),
            Some((a, b)) => (num(a)?, num(b)?),
        };
        (min <= max && max <= 1000 || max == usize::MAX).then_some((min, max, end + 2))
    }

    fn escape(&mut self, in_class: bool) -> Option<Node> {
        let c = *self.s.get(self.i)?;
        self.i += 1;
        let cls = |r: &[(u8, u8)], neg| Node::Class(r.to_vec(), neg);
        Some(match c {
            b'd' => cls(&[(b'0', b'9')], false),
            b'D' => cls(&[(b'0', b'9')], true),
            b'w' => cls(&[(b'a', b'z'), (b'A', b'Z'), (b'0', b'9'), (b'_', b'_')], false),
            b'W' => cls(&[(b'a', b'z'), (b'A', b'Z'), (b'0', b'9'), (b'_', b'_')], true),
            b's' => cls(&[(b' ', b' '), (b'\t', b'\r')], false),
            b'S' => cls(&[(b' ', b' '), (b'\t', b'\r')], true),
            b'n' => Node::Char(b'\n'),
            b't' => Node::Char(b'\t'),
            b'b' | b'B' | b'A' | b'z' | b'1'..=b'9' if !in_class => return None,
            c if c.is_ascii_alphanumeric() => return None,
            c => Node::Char(c),
        })
    }

    fn class(&mut self) -> Option<Node> {
        let neg = self.s.get(self.i) == Some(&b'^');
        if neg {
            self.i += 1;
        }
        let mut r: Vec<(u8, u8)> = Vec::new();
        let mut first = true;
        loop {
            let c = *self.s.get(self.i)?;
            self.i += 1;
            if c == b']' && !first {
                return Some(Node::Class(r, neg));
            }
            first = false;
            let lo = if c == b'\\' {
                match self.escape(true)? {
                    Node::Char(c) => c,
                    Node::Class(rs, false) => {
                        r.extend(rs);
                        continue;
                    }
                    _ => return None,
                }
            } else {
                c
            };
            if self.s.get(self.i) == Some(&b'-') && self.s.get(self.i + 1).is_some_and(|&n| n != b']') {
                let hi = self.s[self.i + 1];
                self.i += 2;
                if hi < lo {
                    return None;
                }
                r.push((lo, hi));
            } else {
                r.push((lo, lo));
            }
        }
    }
}

fn single(n: &Node, s: &[u8], pos: usize) -> Option<usize> {
    match n {
        Node::Char(c) => (s.get(pos) == Some(c)).then_some(pos + 1),
        Node::Any => (pos < s.len()).then_some(pos + 1),
        Node::Class(r, neg) => {
            let c = *s.get(pos)?;
            (r.iter().any(|&(a, b)| a <= c && c <= b) != *neg).then_some(pos + 1)
        }
        Node::Start => (pos == 0).then_some(pos),
        Node::End => (pos == s.len()).then_some(pos),
        _ => None,
    }
}

fn m_seq(nodes: &[Node], s: &[u8], pos: usize, caps: &mut Caps, k: &mut dyn FnMut(usize, &mut Caps) -> bool, fuel: &mut u32) -> bool {
    if *fuel == 0 {
        return false;
    }
    *fuel -= 1;
    let Some((first, rest)) = nodes.split_first() else { return k(pos, caps) };
    match first {
        Node::Group(i, alts) => {
            for alt in alts {
                let mut inner = |p: usize, c: &mut Caps| {
                    let old = c[*i];
                    c[*i] = Some((pos, p));
                    if m_seq(rest, s, p, c, k, &mut 1_000_000) {
                        true
                    } else {
                        c[*i] = old;
                        false
                    }
                };
                if m_seq(alt, s, pos, caps, &mut inner, fuel) {
                    return true;
                }
            }
            false
        }
        Node::NonCap(alts) => {
            for alt in alts {
                let mut inner = |p: usize, c: &mut Caps| m_seq(rest, s, p, c, k, &mut 1_000_000);
                if m_seq(alt, s, pos, caps, &mut inner, fuel) {
                    return true;
                }
            }
            false
        }
        Node::Look(alts, negate) => {
            let mut found = false;
            for alt in alts {
                let mut scratch = caps.clone();
                if m_seq(alt, s, pos, &mut scratch, &mut |_, _| true, fuel) {
                    found = true;
                    break;
                }
            }
            found != *negate && m_seq(rest, s, pos, caps, k, fuel)
        }
        Node::Repeat(n, min, max, lazy) => rep(n, *min, *max, *lazy, 0, rest, s, pos, caps, k, fuel),
        n => match single(n, s, pos) {
            Some(np) => m_seq(rest, s, np, caps, k, fuel),
            None => false,
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn rep(n: &Node, min: usize, max: usize, lazy: bool, count: usize, rest: &[Node], s: &[u8], pos: usize, caps: &mut Caps, k: &mut dyn FnMut(usize, &mut Caps) -> bool, fuel: &mut u32) -> bool {
    // A lazy repeat tries to stop first, a greedy one to go on first.
    if lazy && count >= min && m_seq(rest, s, pos, caps, k, fuel) {
        return true;
    }
    if count < max {
        let mut next = |p: usize, c: &mut Caps| (p != pos || count < min) && rep(n, min, max, lazy, count + 1, rest, s, p, c, k, &mut 1_000_000);
        if m_seq(core::slice::from_ref(n), s, pos, caps, &mut next, fuel) {
            return true;
        }
    }
    !lazy && count >= min && m_seq(rest, s, pos, caps, k, fuel)
}

impl Regex {
    pub fn new(pat: &str) -> Option<Regex> {
        let mut p = P { s: pat.as_bytes(), i: 0, groups: 0 };
        let alts = p.alt(0)?;
        Some(Regex { alts, groups: p.groups })
    }

    /// Leftmost match: (start, end, captures).
    fn find(&self, s: &[u8]) -> Option<(usize, usize, Caps)> {
        self.find_from(s, 0)
    }

    fn find_from(&self, s: &[u8], from: usize) -> Option<(usize, usize, Caps)> {
        for start in from..=s.len() {
            let mut caps: Caps = alloc::vec![None; self.groups + 1];
            for alt in &self.alts {
                let mut end = None;
                let mut fuel = 1_000_000;
                if m_seq(alt, s, start, &mut caps, &mut |p, _| {
                    end = Some(p);
                    true
                }, &mut fuel) {
                    return Some((start, end?, caps));
                }
            }
        }
        None
    }

    pub fn is_match(&self, s: &str) -> bool {
        self.find(s.as_bytes()).is_some()
    }

    /// Replaces the first match with `to` (`\1`..`\9` and `$1`..`$9` insert groups); `None`
    /// when the pattern does not match.
    /// Replaces every non-overlapping match (like Go's `ReplaceAllString`, which containerd uses);
    /// `None` when nothing matches.
    pub fn replace(&self, s: &str, to: &str) -> Option<String> {
        let b = s.as_bytes();
        let t = to.as_bytes();
        let mut out = String::new();
        let (mut pos, mut copied, mut any) = (0usize, 0usize, false);
        while pos <= b.len() {
            let Some((st, en, caps)) = self.find_from(b, pos) else { break };
            any = true;
            out.push_str(&s[copied..st]);
            let mut i = 0;
            let mut lit = Vec::new();
            while i < t.len() {
                if (t[i] == b'\\' || t[i] == b'$') && t.get(i + 1).is_some_and(u8::is_ascii_digit) {
                    let g = (t[i + 1] - b'0') as usize;
                    if g == 0 {
                        lit.extend_from_slice(&b[st..en]);
                    } else if let Some(Some((a, e))) = caps.get(g) {
                        lit.extend_from_slice(&b[*a..*e]);
                    }
                    i += 2;
                } else {
                    lit.push(t[i]);
                    i += 1;
                }
            }
            out.push_str(&String::from_utf8_lossy(&lit));
            copied = en;
            // An empty match moves on by one character so the loop ends.
            pos = if en == st {
                let step = s[en..].chars().next().map_or(1, char::len_utf8);
                out.push_str(&s[en..(en + step).min(s.len())]);
                copied = (en + step).min(s.len());
                en + step
            } else {
                en
            };
        }
        any.then(|| {
            out.push_str(&s[copied.min(s.len())..]);
            out
        })
    }}

#[cfg(test)]
mod tests {
    use super::*;

    const Y: &str = r#"
mirrors:
  docker.io:
    endpoint:
      - "https://cache.local:5000"
      - "http://10.0.0.4:5000"
    rewrite:
      "^library/(.*)": "mirror/$1"
  "*":
    endpoint: "http://fallback:5000"
configs:
  cache.local:5000:
    auth:
      username: bob
      password: s3cret
    tls:
      ca_file: /etc/ca.pem
      cert_file: /etc/c.pem
      key_file: /etc/k.pem
      insecure_skip_verify: true
  10.0.0.4:5000:
    auth:
      token: tok
"#;

    #[test]
    fn parses_yaml() {
        let r = Registries::parse(Y).unwrap();
        assert_eq!(r.mirrors.len(), 2);
        assert_eq!(r.mirrors[0].1.endpoints, ["https://cache.local:5000", "http://10.0.0.4:5000"]);
        let c = r.host_cfg("cache.local:5000").unwrap();
        assert_eq!(c.auth.as_ref().unwrap().username, "bob");
        assert!(c.tls.insecure);
        assert_eq!(c.tls.ca_file.as_deref(), Some("/etc/ca.pem"));
        assert_eq!(r.host_cfg("10.0.0.4:5000").unwrap().auth.as_ref().unwrap().token.as_deref(), Some("tok"));
        assert!(r.host_cfg("other").is_none());
        // a path prefix on a mirror endpoint goes in front of the repository
        let p = Registries::parse("mirrors:\n  docker.io:\n    endpoint:\n      - https://harbor.local/v2/proxy\n      - https://plain.local/v2\n").unwrap();
        let a = p.attempts("docker.io", "library/nginx");
        assert_eq!((a[0].host.as_str(), a[0].repository.as_str()), ("harbor.local", "proxy/library/nginx"));
        assert_eq!((a[1].host.as_str(), a[1].repository.as_str()), ("plain.local", "library/nginx"));
        // any other path is the base the registry's /v2/ API lives under
        let q = Registries::parse("mirrors:\n  docker.io:\n    endpoint: https://repo.local/artifactory/api/docker/hub/\n").unwrap();
        let a = q.attempts("docker.io", "library/nginx");
        assert_eq!((a[0].host.as_str(), a[0].base_path.as_str(), a[0].repository.as_str()), ("repo.local", "/artifactory/api/docker/hub", "library/nginx"));
        assert!(a[1].base_path.is_empty());
        assert!(endpoint("https://h/a/../b").is_none());
        // a `*` entry is the default for registries without their own entry
        let w = Registries::parse("configs:\n  \"*\":\n    auth:\n      username: all\n  cache.local:\n    auth:\n      username: own\n").unwrap();
        assert_eq!(w.host_cfg("anything.io").unwrap().auth.as_ref().unwrap().username, "all");
        assert_eq!(w.host_cfg("cache.local").unwrap().auth.as_ref().unwrap().username, "own");
        assert!(Registries::parse("").unwrap().mirrors.is_empty());
        assert!(Registries::parse("mirrors:\n  a:\n    rewrite:\n      \"(?i)x\": y\n").is_err());
    }

    #[test]
    fn ordering_and_rewrite() {
        let r = Registries::parse(Y).unwrap();
        let a = r.attempts("docker.io", "library/nginx");
        assert_eq!(a.len(), 3);
        assert_eq!((a[0].host.as_str(), a[0].plain_http, a[0].repository.as_str()), ("cache.local:5000", false, "mirror/nginx"));
        assert_eq!((a[1].host.as_str(), a[1].plain_http), ("10.0.0.4:5000", true));
        assert!(!a[2].is_mirror && a[2].repository == "library/nginx" && a[2].host == "docker.io");
        // no rewrite match keeps the name; "*" covers other registries
        assert_eq!(r.attempts("docker.io", "acme/app")[0].repository, "acme/app");
        let b = r.attempts("quay.io", "x/y");
        assert_eq!((b[0].host.as_str(), b.len()), ("fallback:5000", 2));
        assert_eq!(Registries::default().attempts("quay.io", "x").len(), 1);
    }

    #[test]
    fn env_merge_file_wins() {
        let env = Registries::parse_env("docker.io=http://envmirror:1,quay.io=https://q:2, bad");
        let file = Registries::parse(Y).unwrap();
        let m = file.merge_under(env);
        assert_eq!(m.attempts("docker.io", "a/b")[0].host, "cache.local:5000");
        assert_eq!(m.attempts("quay.io", "a/b")[0].host, "q:2");
    }

    #[test]
    fn regex() {
        let r = Regex::new("^(rancher|k3s)/(.*)$").unwrap();
        assert_eq!(r.replace("rancher/pause", "x/\\2-\\1").unwrap(), "x/pause-rancher");
        assert!(r.replace("other/pause", "x").is_none());
        let r = Regex::new("a+b?c[0-9]\\.").unwrap();
        assert!(r.is_match("zaaac7."));
        assert!(!r.is_match("ac."));
        // non-capturing groups, look-ahead, lazy quantifiers and replace-all
        assert_eq!(Regex::new("^(?:docker\\.io|quay\\.io)/(.+)$").unwrap().replace("quay.io/a/b", "m/\\1").unwrap(), "m/a/b");
        assert_eq!(Regex::new("^lib/(?!skip)(.*)$").unwrap().replace("lib/x", "y/\\1").unwrap(), "y/x");
        assert!(Regex::new("^lib/(?!skip)(.*)$").unwrap().replace("lib/skip", "y").is_none());
        assert!(Regex::new("^a(?=b)").unwrap().is_match("ab") && !Regex::new("^a(?=b)").unwrap().is_match("ac"));
        assert_eq!(Regex::new("a.*?b").unwrap().replace("aXbYb", "_").unwrap(), "_Yb".replace("Yb", "Yb"));
        assert_eq!(Regex::new("o").unwrap().replace("foo/bar-o", "0").unwrap(), "f00/bar-0");
        assert!(Regex::new("(?i)x").is_none() && Regex::new("(?<=a)b").is_none() && Regex::new("(a").is_none() && Regex::new("a{2").is_none() && Regex::new("a{3,2}").is_none() && Regex::new("a{x}").is_none());
        let r = Regex::new("^lib/(a{2,3})-([0-9]{2})$").unwrap();
        assert_eq!(r.replace("lib/aaa-42", "\\2\\1").unwrap(), "42aaa");
        assert!(r.replace("lib/a-42", "x").is_none() && r.replace("lib/aaaa-42", "x").is_none() && r.replace("lib/aa-4", "x").is_none());
        assert!(Regex::new("x{2,}y").unwrap().is_match("xxxy") && !Regex::new("^x{2,}y").unwrap().is_match("xy"));
    }
}
