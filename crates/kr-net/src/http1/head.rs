//! Strict HTTP/1.1 message-head parser (RFC 9112), zero-copy over the input buffer.
//!
//! Strictness (ADR-015): lines end in CRLF (a bare LF or bare CR anywhere is an error rather
//! than being normalised), obs-fold is rejected, whitespace before the header colon is
//! rejected, control characters are rejected, and every limit is enforced even on partial input.

use crate::{Error, Result};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Whole head (start line + headers + blank line).
    pub max_head: usize,
    /// One line, excluding CRLF.
    pub max_line: usize,
    pub max_headers: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_head: 16 * 1024, max_line: 8 * 1024, max_headers: 100 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header<'a> {
    pub name: &'a str,
    pub value: &'a str,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Request<'a> {
    pub method: &'a str,
    pub target: &'a str,
    /// HTTP/1.`minor`.
    pub minor: u8,
    pub headers: Vec<Header<'a>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Response<'a> {
    pub minor: u8,
    pub status: u16,
    pub reason: &'a str,
    pub headers: Vec<Header<'a>>,
}

/// `Ok(None)` means the head is incomplete: read more and call again with the longer buffer.
/// `Ok(Some((head, n)))` means `n` bytes were consumed.
pub type Parsed<T> = Result<Option<(T, usize)>>;

pub fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

pub fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(is_tchar)
}

/// Validates a header value: HTAB, SP, VCHAR and obs-text only (no CTLs, no CR/LF, no DEL).
pub fn valid_field_value(v: &[u8]) -> bool {
    v.iter().all(|&b| b == b'\t' || (0x20..=0x7e).contains(&b) || b >= 0x80)
}

fn next_line(buf: &[u8], pos: usize, lim: &Limits) -> Result<Option<(usize, usize)>> {
    // Returns (line_end, next_pos) with the CRLF excluded from the line.
    let rest = &buf[pos..];
    match rest.iter().position(|&b| b == b'\n') {
        Some(i) => {
            if i == 0 || rest[i - 1] != b'\r' {
                return Err(Error::Parse("bare LF"));
            }
            let line = &rest[..i - 1];
            if line.len() > lim.max_line {
                return Err(Error::TooLarge("line"));
            }
            if line.contains(&b'\r') {
                return Err(Error::Parse("bare CR"));
            }
            Ok(Some((pos + i - 1, pos + i + 1)))
        }
        None => {
            if rest.len() > lim.max_line + 1 {
                return Err(Error::TooLarge("line"));
            }
            // A CR is only acceptable as the very last byte (its LF may not have arrived).
            if rest.len() > 1 && rest[..rest.len() - 1].contains(&b'\r') {
                return Err(Error::Parse("bare CR"));
            }
            Ok(None)
        }
    }
}

fn parse_minor(v: &[u8]) -> Result<u8> {
    match v {
        b"HTTP/1.1" => Ok(1),
        b"HTTP/1.0" => Ok(0),
        _ => Err(Error::Parse("unsupported HTTP version")),
    }
}

fn target_ok(t: &[u8]) -> bool {
    !t.is_empty() && t.iter().all(|&b| b > 0x20 && b < 0x7f)
}

type StartParser<'a, S> = fn(&'a [u8]) -> Result<S>;

/// Shared head scanner. Returns the start-line value, headers and the consumed length.
fn parse_head<'a, S>(buf: &'a [u8], lim: &Limits, start: StartParser<'a, S>) -> Parsed<(S, Vec<Header<'a>>)> {
    let mut pos = 0;
    let (line_end, next) = match next_line(buf, pos, lim)? {
        Some(x) => x,
        None => return incomplete(buf, lim),
    };
    let start_val = start(&buf[pos..line_end])?;
    pos = next;
    let mut headers = Vec::new();
    loop {
        if pos > lim.max_head {
            return Err(Error::TooLarge("head"));
        }
        let (line_end, next) = match next_line(buf, pos, lim)? {
            Some(x) => x,
            None => return incomplete(buf, lim),
        };
        let line = &buf[pos..line_end];
        pos = next;
        if line.is_empty() {
            if pos > lim.max_head {
                return Err(Error::TooLarge("head"));
            }
            return Ok(Some(((start_val, headers), pos)));
        }
        if line[0] == b' ' || line[0] == b'\t' {
            return Err(Error::Parse("obs-fold"));
        }
        let colon = line.iter().position(|&b| b == b':').ok_or(Error::Parse("header without colon"))?;
        let name = &line[..colon];
        // A space before the colon fails the token check, which is what RFC 9112 5.1 demands.
        if name.is_empty() || !name.iter().all(|&b| is_tchar(b)) {
            return Err(Error::Parse("bad header name"));
        }
        let mut v = &line[colon + 1..];
        while let [b' ' | b'\t', rest @ ..] = v {
            v = rest;
        }
        while let [rest @ .., b' ' | b'\t'] = v {
            v = rest;
        }
        if !valid_field_value(v) {
            return Err(Error::Parse("bad header value"));
        }
        if headers.len() >= lim.max_headers {
            return Err(Error::TooLarge("header count"));
        }
        headers.push(Header {
            // Both slices were validated as ASCII / checked UTF-8 just now.
            name: core::str::from_utf8(name).map_err(|_| Error::Parse("bad header name"))?,
            value: core::str::from_utf8(v).map_err(|_| Error::Parse("header value not UTF-8"))?,
        });
    }
}

fn incomplete<T>(buf: &[u8], lim: &Limits) -> Result<Option<T>> {
    if buf.len() >= lim.max_head {
        Err(Error::TooLarge("head"))
    } else {
        Ok(None)
    }
}

pub fn parse_request<'a>(buf: &'a [u8], lim: &Limits) -> Parsed<Request<'a>> {
    fn start(l: &[u8]) -> Result<(&str, &str, u8)> {
        let sp1 = l.iter().position(|&b| b == b' ').ok_or(Error::Parse("bad request line"))?;
        let method = &l[..sp1];
        let rest = &l[sp1 + 1..];
        let sp2 = rest.iter().position(|&b| b == b' ').ok_or(Error::Parse("bad request line"))?;
        let (target, ver) = (&rest[..sp2], &rest[sp2 + 1..]);
        if method.is_empty() || !method.iter().all(|&b| is_tchar(b)) {
            return Err(Error::Parse("bad method"));
        }
        if !target_ok(target) {
            return Err(Error::Parse("bad request target"));
        }
        let minor = parse_minor(ver)?;
        // ASCII was verified above.
        Ok((
            core::str::from_utf8(method).map_err(|_| Error::Parse("bad method"))?,
            core::str::from_utf8(target).map_err(|_| Error::Parse("bad request target"))?,
            minor,
        ))
    }
    Ok(parse_head(buf, lim, start)?.map(|(((method, target, minor), headers), n)| {
        (Request { method, target, minor, headers }, n)
    }))
    .and_then(|r| {
        if let Some((req, _)) = &r {
            // HTTP/1.1 requires exactly one Host (RFC 9112 3.2); duplicates enable cache/host confusion.
            let hosts = req.headers.iter().filter(|h| h.name.eq_ignore_ascii_case("host")).count();
            if req.minor == 1 && hosts != 1 {
                return Err(Error::Parse("missing or duplicate Host"));
            }
        }
        Ok(r)
    })
}

pub fn parse_response<'a>(buf: &'a [u8], lim: &Limits) -> Parsed<Response<'a>> {
    fn start(l: &[u8]) -> Result<(u8, u16, &str)> {
        if l.len() < 12 || l[8] != b' ' {
            return Err(Error::Parse("bad status line"));
        }
        let minor = parse_minor(&l[..8])?;
        let code = &l[9..12];
        if !code.iter().all(u8::is_ascii_digit) {
            return Err(Error::Parse("bad status code"));
        }
        let status = (code[0] - b'0') as u16 * 100 + (code[1] - b'0') as u16 * 10 + (code[2] - b'0') as u16;
        if status < 100 {
            return Err(Error::Parse("bad status code"));
        }
        // RFC 9112 requires "SP reason" even if the phrase is empty; a few servers omit the SP
        // when there is no phrase, which is unambiguous, so only that case is tolerated.
        let reason = match &l[12..] {
            [] => &l[12..],
            [b' ', r @ ..] => r,
            _ => return Err(Error::Parse("bad status line")),
        };
        if !valid_field_value(reason) {
            return Err(Error::Parse("bad reason phrase"));
        }
        Ok((minor, status, core::str::from_utf8(reason).map_err(|_| Error::Parse("reason not UTF-8"))?))
    }
    Ok(parse_head(buf, lim, start)?.map(|(((minor, status, reason), headers), n)| {
        (Response { minor, status, reason, headers }, n)
    }))
}

// ---------- framing ----------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    /// No body.
    None,
    Length(u64),
    Chunked,
    /// Response body delimited by connection close.
    UntilClose,
}

fn header_values<'a, 'b>(h: &'b [Header<'a>], name: &'b str) -> impl Iterator<Item = &'a str> + 'b {
    h.iter().filter(move |x| x.name.eq_ignore_ascii_case(name)).map(|x| x.value)
}

/// Returns `(content_length, chunked)` after enforcing the anti-smuggling rules:
/// * Transfer-Encoding together with Content-Length is rejected (RFC 9112 6.1);
/// * Content-Length must be 1*DIGIT; repeated or comma-listed values must all be identical;
/// * the only supported transfer coding is a single, final `chunked`.
fn body_headers(minor: u8, headers: &[Header<'_>]) -> Result<(Option<u64>, bool)> {
    let mut cl: Option<u64> = None;
    for v in header_values(headers, "content-length") {
        for part in v.split(',') {
            let part = part.trim_matches(|c| c == ' ' || c == '\t');
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::Parse("bad Content-Length"));
            }
            let n: u64 = part.parse().map_err(|_| Error::Parse("Content-Length overflow"))?;
            match cl {
                Some(prev) if prev != n => return Err(Error::Smuggling("conflicting Content-Length")),
                _ => cl = Some(n),
            }
        }
    }
    let mut te_count = 0;
    let mut chunked_last = false;
    let mut other = false;
    for v in header_values(headers, "transfer-encoding") {
        for coding in v.split(',') {
            let coding = coding.trim_matches(|c| c == ' ' || c == '\t');
            if coding.is_empty() {
                return Err(Error::Parse("empty transfer coding"));
            }
            te_count += 1;
            if chunked_last {
                // anything after chunked
                return Err(Error::Parse("coding after chunked"));
            }
            if coding.eq_ignore_ascii_case("chunked") {
                chunked_last = true;
            } else {
                other = true;
            }
        }
    }
    if te_count > 0 {
        if cl.is_some() {
            return Err(Error::Smuggling("both Transfer-Encoding and Content-Length"));
        }
        if minor == 0 {
            return Err(Error::Smuggling("Transfer-Encoding in HTTP/1.0 message"));
        }
        if other || !chunked_last {
            return Err(Error::Parse("unsupported transfer coding"));
        }
        return Ok((None, true));
    }
    Ok((cl, false))
}

pub fn request_framing(req: &Request<'_>) -> Result<Framing> {
    Ok(match body_headers(req.minor, &req.headers)? {
        (_, true) => Framing::Chunked,
        (Some(0) | None, _) => Framing::None,
        (Some(n), _) => Framing::Length(n),
    })
}

pub fn response_framing(method: &str, resp: &Response<'_>) -> Result<Framing> {
    let (cl, chunked) = body_headers(resp.minor, &resp.headers)?;
    if method.eq_ignore_ascii_case("HEAD") || (100..200).contains(&resp.status) || resp.status == 204 || resp.status == 304 {
        return Ok(Framing::None);
    }
    Ok(match (cl, chunked) {
        (_, true) => Framing::Chunked,
        (Some(0), _) => Framing::None,
        (Some(n), _) => Framing::Length(n),
        (None, _) => Framing::UntilClose,
    })
}

/// Whether the connection may be reused after this message (RFC 9112 9.3).
pub fn keep_alive(minor: u8, headers: &[Header<'_>]) -> bool {
    let mut ka = minor >= 1;
    for v in header_values(headers, "connection") {
        for t in v.split(',') {
            let t = t.trim_matches(|c| c == ' ' || c == '\t');
            if t.eq_ignore_ascii_case("close") {
                return false;
            }
            if t.eq_ignore_ascii_case("keep-alive") {
                ka = true;
            }
        }
    }
    ka
}

#[cfg(test)]
mod tests {
    use super::*;

    const L: Limits = Limits { max_head: 16384, max_line: 8192, max_headers: 100 };

    fn req(s: &str) -> Result<Request<'_>> {
        parse_request(s.as_bytes(), &L).and_then(|o| o.map(|x| x.0).ok_or(Error::Parse("partial")))
    }
    fn resp(s: &str) -> Result<Response<'_>> {
        parse_response(s.as_bytes(), &L).and_then(|o| o.map(|x| x.0).ok_or(Error::Parse("partial")))
    }

    #[test]
    fn basic_request() {
        let s = "GET /a?b=1 HTTP/1.1\r\nHost: x\r\nAccept:  a/b \t\r\n\r\nBODY";
        let (r, n) = parse_request(s.as_bytes(), &L).unwrap().unwrap();
        assert_eq!((r.method, r.target, r.minor), ("GET", "/a?b=1", 1));
        assert_eq!(r.headers[1], Header { name: "Accept", value: "a/b" });
        assert_eq!(&s[n..], "BODY");
    }

    #[test]
    fn basic_response() {
        let r = resp("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").unwrap();
        assert_eq!((r.status, r.reason), (404, "Not Found"));
        assert_eq!(resp("HTTP/1.1 200 \r\n\r\n").unwrap().reason, "");
        assert_eq!(resp("HTTP/1.1 200\r\n\r\n").unwrap().status, 200);
        assert!(resp("HTTP/1.1 20 OK\r\n\r\n").is_err());
        assert!(resp("HTTP/1.1 2000 OK\r\n\r\n").is_err());
        assert!(resp("HTTP/1.1 099 OK\r\n\r\n").is_err());
        assert!(resp("HTTP/2.0 200 OK\r\n\r\n").is_err());
        assert!(resp("HTTP/1.1  200 OK\r\n\r\n").is_err());
        assert!(resp("HTTP/1.1 200OK\r\n\r\n").is_err());
    }

    #[test]
    fn partial_at_every_prefix() {
        let s = "GET / HTTP/1.1\r\nHost: x\r\nA: b\r\n\r\n";
        for i in 0..s.len() {
            assert_eq!(parse_request(&s.as_bytes()[..i], &L), Ok(None), "prefix {i}");
        }
        assert!(parse_request(s.as_bytes(), &L).unwrap().is_some());
    }

    #[test]
    fn rejects_obs_fold() {
        assert_eq!(req("GET / HTTP/1.1\r\nHost: x\r\nA: b\r\n c\r\n\r\n"), Err(Error::Parse("obs-fold")));
        assert_eq!(req("GET / HTTP/1.1\r\n Host: x\r\n\r\n"), Err(Error::Parse("obs-fold")));
        assert_eq!(req("GET / HTTP/1.1\r\nHost: x\r\nA: b\r\n\tc\r\n\r\n"), Err(Error::Parse("obs-fold")));
    }

    #[test]
    fn bare_cr_and_lf() {
        assert!(req("GET / HTTP/1.1\nHost: x\n\n").is_err());
        assert!(req("GET / HTTP/1.1\r\nHost: x\nA: b\r\n\r\n").is_err());
        assert!(req("GET / HTTP/1.1\r\nHost: x\r\nA: b\rc\r\n\r\n").is_err());
        assert!(req("GET / HTTP/1.1\rHost: x\r\n\r\n").is_err());
        // bare CR detected before the LF has arrived
        assert!(parse_request(b"GET / HTTP/1.1\r\nHost: x\r\nA: b\rc", &L).is_err());
        // trailing CR alone is just incomplete
        assert_eq!(parse_request(b"GET / HTTP/1.1\r\nHost: x\r", &L), Ok(None));
        assert!(resp("HTTP/1.1 200 OK\r\nA: b\r\r\n\r\n").is_err());
    }

    #[test]
    fn bad_syntax() {
        assert!(req("GET /  HTTP/1.1\r\nHost: x\r\n\r\n").is_err()); // double SP
        assert!(req("GET / HTTP/1.1 \r\nHost: x\r\n\r\n").is_err());
        assert!(req("GET /\x01 HTTP/1.1\r\nHost: x\r\n\r\n").is_err());
        assert!(req("G*T / HTTP/1.1\r\nHost: x\r\n\r\n").is_ok()); // '*' is a tchar
        assert!(req("G(T / HTTP/1.1\r\nHost: x\r\n\r\n").is_err());
        assert!(req("\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n").is_err());
        assert!(req("GET / HTTP/1.1\r\nHost : x\r\n\r\n").is_err()); // space before colon
        assert!(req("GET / HTTP/1.1\r\nHost\t: x\r\n\r\n").is_err());
        assert!(req("GET / HTTP/1.1\r\n: x\r\n\r\n").is_err());
        assert!(req("GET / HTTP/1.1\r\nHost x\r\n\r\n").is_err());
        assert!(req("GET / HTTP/1.1\r\nHost: x\0y\r\n\r\n").is_err());
        assert!(req("GET / HTTP/1.1\r\nHost: x\x7f\r\n\r\n").is_err());
        assert!(req("GET / HTTP/1.1\r\nHost: x\x01\r\n\r\n").is_err());
        assert!(req("GET / HTTP/1.1\r\n\r\n").is_err()); // no Host
        assert!(req("GET / HTTP/1.1\r\nHost: a\r\nhost: b\r\n\r\n").is_err());
        assert!(req("GET / HTTP/1.0\r\n\r\n").is_ok());
        assert!(req("GET / HTTP/1.2\r\nHost: x\r\n\r\n").is_err());
        assert!(req("GET / http/1.1\r\nHost: x\r\n\r\n").is_err());
    }

    #[test]
    fn limits() {
        let lim = Limits { max_head: 200, max_line: 40, max_headers: 3 };
        fn pr<'a>(s: &'a str, lim: &Limits) -> Parsed<Request<'a>> {
            parse_request(s.as_bytes(), lim)
        }
        let p = |s: &str| pr(s, &lim).map(|o| o.map(|x| x.1));
        assert!(p("GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap().is_some());
        // header count
        assert_eq!(p("GET / HTTP/1.1\r\nHost: x\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n"), Err(Error::TooLarge("header count")));
        // line length, complete and incomplete
        let long = "x".repeat(50);
        assert_eq!(p(&std::format!("GET / HTTP/1.1\r\nHost: x\r\nA: {long}\r\n\r\n")), Err(Error::TooLarge("line")));
        assert_eq!(p(&std::format!("GET / HTTP/1.1\r\nHost: x\r\nA: {long}")), Err(Error::TooLarge("line")));
        // total head: many short lines without a terminator
        let lim2 = Limits { max_head: 50, max_line: 40, max_headers: 100 };
        let s = "GET / HTTP/1.1\r\nHost: x\r\nA: 1\r\nB: 2\r\nC: 3\r\nD: 4\r\nE: 5\r\n\r\n";
        assert_eq!(parse_request(s.as_bytes(), &lim2), Err(Error::TooLarge("head")));
        assert_eq!(parse_request(&s.as_bytes()[..50], &lim2), Err(Error::TooLarge("head")));
        // unlimited garbage with no newline is cut off by the line limit
        assert!(p(&"a".repeat(100)).is_err());
    }

    fn fr(s: &str) -> Result<Framing> {
        request_framing(&req(s)?)
    }

    #[test]
    fn smuggling() {
        let h = "POST / HTTP/1.1\r\nHost: x\r\n";
        assert_eq!(
            fr(&std::format!("{h}Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n")),
            Err(Error::Smuggling("both Transfer-Encoding and Content-Length"))
        );
        assert!(matches!(fr(&std::format!("{h}Transfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n")), Err(Error::Smuggling(_))));
        assert!(matches!(fr(&std::format!("{h}Content-Length: 5\r\nContent-Length: 6\r\n\r\n")), Err(Error::Smuggling(_))));
        assert!(matches!(fr(&std::format!("{h}Content-Length: 5, 6\r\n\r\n")), Err(Error::Smuggling(_))));
        assert_eq!(fr(&std::format!("{h}Content-Length: 5\r\nContent-Length: 5\r\n\r\n")), Ok(Framing::Length(5)));
        assert_eq!(fr(&std::format!("{h}Content-Length: 5, 5\r\n\r\n")), Ok(Framing::Length(5)));
        for bad in ["+5", "-5", "0x5", "5 5", "", " ", "5.0", "99999999999999999999999"] {
            assert!(fr(&std::format!("{h}Content-Length: {bad}\r\n\r\n")).is_err(), "{bad:?}");
        }
        // TE variants
        assert_eq!(fr(&std::format!("{h}Transfer-Encoding: Chunked\r\n\r\n")), Ok(Framing::Chunked));
        assert_eq!(fr(&std::format!("{h}Transfer-Encoding: chunked \r\n\r\n")), Ok(Framing::Chunked));
        assert!(fr(&std::format!("{h}Transfer-Encoding: gzip, chunked\r\n\r\n")).is_err());
        assert!(fr(&std::format!("{h}Transfer-Encoding: chunked, gzip\r\n\r\n")).is_err());
        assert!(fr(&std::format!("{h}Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n")).is_err());
        assert!(fr(&std::format!("{h}Transfer-Encoding: identity\r\n\r\n")).is_err());
        assert!(fr(&std::format!("{h}Transfer-Encoding: chunk\r\n\r\n")).is_err());
        assert!(fr(&std::format!("{h}Transfer-Encoding: \r\n\r\n")).is_err());
        assert!(fr(&std::format!("{h}Transfer-Encoding: chunked,\r\n\r\n")).is_err());
        assert!(fr("POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n").is_err());
        // underscore / whitespace-tricked names are different fields, not Content-Length
        assert!(fr(&std::format!("{h}Content_Length: 5\r\n\r\n")).is_ok());
        assert!(fr(&std::format!("{h}Content-Length : 5\r\n\r\n")).is_err());
        assert_eq!(fr(&std::format!("{h}\r\n")), Ok(Framing::None));
        assert_eq!(fr(&std::format!("{h}Content-Length: 0\r\n\r\n")), Ok(Framing::None));
    }

    #[test]
    fn response_framing_rules() {
        let f = |m: &str, s: &str| response_framing(m, &resp(s).unwrap());
        assert_eq!(f("GET", "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n"), Ok(Framing::Length(4)));
        assert_eq!(f("HEAD", "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n"), Ok(Framing::None));
        assert_eq!(f("GET", "HTTP/1.1 204 No Content\r\n\r\n"), Ok(Framing::None));
        assert_eq!(f("GET", "HTTP/1.1 304 Not Modified\r\nContent-Length: 9\r\n\r\n"), Ok(Framing::None));
        assert_eq!(f("GET", "HTTP/1.1 200 OK\r\n\r\n"), Ok(Framing::UntilClose));
        assert_eq!(f("GET", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"), Ok(Framing::Chunked));
        assert!(f("GET", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n").is_err());
    }

    #[test]
    fn keep_alive_rules() {
        let k = |s: &str| keep_alive(1, &req(s).unwrap().headers);
        assert!(k("GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert!(!k("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"));
        assert!(!k("GET / HTTP/1.1\r\nHost: x\r\nConnection: Keep-Alive, Close\r\n\r\n"));
        assert!(!keep_alive(0, &[]));
        assert!(keep_alive(0, &[Header { name: "connection", value: "keep-alive" }]));
    }
}
