//! Minimal absolute-URL parsing and redirect-target resolution (http/https only).

use crate::tcp::{parse_ipv4, parse_ipv6};
use crate::{Error, Result};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    pub scheme: Scheme,
    /// Host without brackets (IPv6 literals appear bare).
    pub host: String,
    pub port: u16,
    /// Path plus query, always starting with `/`. Must already be percent-encoded.
    pub path: String,
}

fn host_ok(h: &str) -> bool {
    !h.is_empty() && h.len() <= 253 && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

impl Url {
    pub fn parse(s: &str) -> Result<Url> {
        let (scheme, rest) = if let Some(r) = strip_prefix_ci(s, "http://") {
            (Scheme::Http, r)
        } else if let Some(r) = strip_prefix_ci(s, "https://") {
            (Scheme::Https, r)
        } else {
            return Err(Error::BadUrl("unsupported scheme"));
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (auth, tail) = rest.split_at(end);
        if auth.contains('@') {
            return Err(Error::BadUrl("userinfo not supported"));
        }
        let (host, port_s) = if let Some(r) = auth.strip_prefix('[') {
            let close = r.find(']').ok_or(Error::BadUrl("unterminated IPv6 literal"))?;
            let host = &r[..close];
            if parse_ipv6(host).is_none() {
                return Err(Error::BadUrl("bad IPv6 literal"));
            }
            let after = &r[close + 1..];
            match after.strip_prefix(':') {
                Some(p) => (host, Some(p)),
                None if after.is_empty() => (host, None),
                None => return Err(Error::BadUrl("garbage after IPv6 literal")),
            }
        } else {
            match auth.rsplit_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (auth, None),
            }
        };
        if !host_ok(host) && !host.contains(':') {
            return Err(Error::BadUrl("bad host"));
        }
        // An all-numeric dotted host must be a valid quad (rejects 1.2.3.256 style ambiguity).
        if host.bytes().all(|b| b.is_ascii_digit() || b == b'.') && parse_ipv4(host).is_none() {
            return Err(Error::BadUrl("bad IPv4 literal"));
        }
        let port = match port_s {
            None => scheme.default_port(),
            Some(p) => {
                if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(Error::BadUrl("bad port"));
                }
                p.parse::<u16>().ok().filter(|p| *p != 0).ok_or(Error::BadUrl("bad port"))?
            }
        };
        let tail = tail.split('#').next().unwrap_or("");
        let path = if tail.is_empty() {
            "/".to_string()
        } else if tail.starts_with('?') {
            alloc::format!("/{tail}")
        } else {
            tail.to_string()
        };
        if !path.bytes().all(|b| b > 0x20 && b < 0x7f) {
            return Err(Error::BadUrl("path contains unencoded characters"));
        }
        Ok(Url { scheme, host: host.to_ascii_lowercase(), port, path })
    }

    /// Value for the `Host` header: brackets for IPv6, port omitted when default.
    pub fn host_header(&self) -> String {
        let h = if self.host.contains(':') { alloc::format!("[{}]", self.host) } else { self.host.clone() };
        if self.port == self.scheme.default_port() {
            h
        } else {
            alloc::format!("{h}:{}", self.port)
        }
    }

    pub fn same_origin(&self, o: &Url) -> bool {
        self.scheme == o.scheme && self.host == o.host && self.port == o.port
    }

    /// Resolves a `Location` value against `self` (RFC 3986 5.2, without userinfo support).
    pub fn join(&self, loc: &str) -> Result<Url> {
        if loc.is_empty() || loc.bytes().any(|b| b <= 0x20 || b >= 0x7f) {
            return Err(Error::BadUrl("bad Location"));
        }
        if strip_prefix_ci(loc, "http://").is_some() || strip_prefix_ci(loc, "https://").is_some() {
            return Url::parse(loc);
        }
        if loc.contains("://") {
            return Err(Error::BadUrl("unsupported scheme"));
        }
        if let Some(r) = loc.strip_prefix("//") {
            return Url::parse(&alloc::format!("{}://{r}", self.scheme.as_str()));
        }
        let loc = loc.split('#').next().unwrap_or("");
        let path = if loc.starts_with('/') {
            normalize(loc)
        } else if loc.starts_with('?') {
            let base = self.path.split('?').next().unwrap_or("/");
            alloc::format!("{base}{loc}")
        } else if loc.is_empty() {
            self.path.clone()
        } else {
            let base = self.path.split('?').next().unwrap_or("/");
            let dir = &base[..base.rfind('/').map(|i| i + 1).unwrap_or(0)];
            normalize(&alloc::format!("{dir}{loc}"))
        };
        Ok(Url { path, ..self.clone() })
    }
}

fn strip_prefix_ci<'a>(s: &'a str, p: &str) -> Option<&'a str> {
    if s.len() >= p.len() && s.is_char_boundary(p.len()) && s[..p.len()].eq_ignore_ascii_case(p) {
        Some(&s[p.len()..])
    } else {
        None
    }
}

/// Removes `.` and `..` segments from the path part, keeping the query.
fn normalize(p: &str) -> String {
    let (path, query) = match p.split_once('?') {
        Some((a, b)) => (a, Some(b)),
        None => (p, None),
    };
    let mut out: Vec<&str> = Vec::new();
    let segs: Vec<&str> = path.split('/').collect();
    for s in segs.iter() {
        match *s {
            "." => {}
            ".." => {
                if out.len() > 1 {
                    out.pop();
                }
            }
            s => out.push(s),
        }
    }
    let mut r = out.join("/");
    if path.ends_with("/.") || path.ends_with("/..") {
        r.push('/');
    }
    if !r.starts_with('/') {
        r.insert(0, '/');
    }
    if let Some(q) = query {
        r.push('?');
        r.push_str(q);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        let u = Url::parse("http://Example.COM:8080/a/b?c=d#frag").unwrap();
        assert_eq!((u.scheme, u.host.as_str(), u.port, u.path.as_str()), (Scheme::Http, "example.com", 8080, "/a/b?c=d"));
        assert_eq!(u.host_header(), "example.com:8080");
        let u = Url::parse("https://h").unwrap();
        assert_eq!((u.port, u.path.as_str(), u.host_header().as_str()), (443, "/", "h"));
        assert_eq!(Url::parse("http://h?x=1").unwrap().path, "/?x=1");
        let u = Url::parse("http://[::1]:5000/v2/").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("::1", 5000));
        assert_eq!(u.host_header(), "[::1]:5000");
        assert_eq!(Url::parse("HTTP://127.0.0.1/").unwrap().port, 80);
        for bad in [
            "ftp://x/", "x", "http://", "http:///p", "http://u@h/", "http://h:/", "http://h:0/", "http://h:99999/", "http://h:8a/",
            "http://[::1/", "http://[zz]/", "http://[::1]x/", "http://h/a b", "http://1.2.3.256/", "http://h_/\x01", "http://ho st/",
        ] {
            let r = Url::parse(bad);
            // "h_" is a legal (if odd) host; only the control char fails there.
            assert!(r.is_err(), "{bad}");
        }
    }

    #[test]
    fn join() {
        let b = Url::parse("http://h:81/a/b/c?q=1").unwrap();
        assert_eq!(b.join("/x/y").unwrap().path, "/x/y");
        assert_eq!(b.join("d").unwrap().path, "/a/b/d");
        assert_eq!(b.join("../d").unwrap().path, "/a/d");
        assert_eq!(b.join("../../../../d").unwrap().path, "/d");
        assert_eq!(b.join("./d?z=1").unwrap().path, "/a/b/d?z=1");
        assert_eq!(b.join("?z=2").unwrap().path, "/a/b/c?z=2");
        assert_eq!(b.join("//o:9/p").unwrap().port, 9);
        assert_eq!(b.join("//o/p").unwrap().scheme, Scheme::Http);
        assert_eq!(b.join("https://o/p").unwrap().scheme, Scheme::Https);
        assert_eq!(b.join("/x//y/./z/..").unwrap().path, "/x//y/");
        assert!(b.join("").is_err());
        assert!(b.join("ftp://x/").is_err());
        assert!(b.join("a b").is_err());
        assert!(b.join("/a\r\nHost: evil").is_err());
        assert!(b.same_origin(&b.join("/z").unwrap()));
        assert!(!b.same_origin(&b.join("//h:82/").unwrap()));
    }
}
