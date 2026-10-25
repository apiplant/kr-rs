//! `pods/<name>[:port]/proxy[/path]`: a one-shot HTTP/1.1 request relayed to the pod's IP.
//! The response is read to the end (`Connection: close`), so the call is bounded by its timeouts.

use alloc::string::String;
use alloc::vec::Vec;
use kr_net::http1::server::Response;

const TIMEOUT_MS: u64 = 10_000;
const MAX_BODY: usize = 64 << 20;

/// Relays one request to `ip:port`; connection failures are 503, malformed replies 502.
pub fn forward(method: &str, ip: [u8; 4], port: u16, path: &str, query: &str, content_type: Option<&str>, accept: Option<&str>, body: &[u8]) -> Response {
    let fail = |code: u16, msg: &str| Response::new(code, msg.as_bytes().to_vec());
    let Ok(fd) = kr_sys::socket(kr_sys::AF_INET, kr_sys::SOCK_STREAM | kr_sys::SOCK_CLOEXEC, 0) else { return fail(503, "cannot create socket") };
    // struct timeval { tv_sec, tv_usec }: bounds connect, writes and each read.
    let mut tv = [0u8; 16];
    tv[..8].copy_from_slice(&((TIMEOUT_MS / 1000) as i64).to_ne_bytes());
    let _ = kr_sys::setsockopt(fd.raw(), 1, 20, &tv); // SO_RCVTIMEO
    let _ = kr_sys::setsockopt(fd.raw(), 1, 21, &tv); // SO_SNDTIMEO
    if kr_sys::connect(fd.raw(), &kr_sys::SockaddrIn::new(ip, port)).is_err() {
        return fail(503, "error trying to reach the pod");
    }
    let target = if query.is_empty() { String::from(path) } else { alloc::format!("{path}?{query}") };
    let mut req = alloc::format!("{method} {target} HTTP/1.1\r\nHost: {}.{}.{}.{}:{port}\r\nConnection: close\r\nUser-Agent: kr-apiserver\r\n", ip[0], ip[1], ip[2], ip[3]);
    if let Some(ct) = content_type {
        req.push_str(&alloc::format!("Content-Type: {ct}\r\n"));
    }
    if let Some(a) = accept {
        req.push_str(&alloc::format!("Accept: {a}\r\n"));
    }
    if !body.is_empty() || matches!(method, "POST" | "PUT" | "PATCH") {
        req.push_str(&alloc::format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    let mut out = req.into_bytes();
    out.extend_from_slice(body);
    if kr_sys::fs::write_all(fd.raw(), &out).is_err() {
        return fail(503, "error sending the request to the pod");
    }
    let mut raw = Vec::new();
    let _ = kr_sys::fs::read_to_end(fd.raw(), &mut raw, MAX_BODY);
    parse_response(&raw).unwrap_or_else(|| fail(502, "invalid response from the pod"))
}

fn parse_response(raw: &[u8]) -> Option<Response> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = core::str::from_utf8(&raw[..end]).ok()?;
    let mut lines = head.split("\r\n");
    let status: u16 = lines.next()?.split(' ').nth(1)?.parse().ok()?;
    let mut headers = Vec::new();
    let mut chunked = false;
    for l in lines {
        let Some((k, v)) = l.split_once(':') else { continue };
        let (k, v) = (k.trim(), v.trim());
        if k.eq_ignore_ascii_case("transfer-encoding") {
            chunked = v.eq_ignore_ascii_case("chunked");
        } else if k.eq_ignore_ascii_case("content-type") || k.eq_ignore_ascii_case("location") {
            headers.push((String::from(k), String::from(v)));
        }
    }
    let rest = &raw[end + 4..];
    let body = if chunked { dechunk(rest)? } else { rest.to_vec() };
    let mut r = Response::new(status, body);
    r.headers = headers;
    Some(r)
}

fn dechunk(mut d: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let nl = d.windows(2).position(|w| w == b"\r\n")?;
        let size = usize::from_str_radix(core::str::from_utf8(&d[..nl]).ok()?.split(';').next()?.trim(), 16).ok()?;
        d = &d[nl + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(d.get(..size)?);
        d = d.get(size + 2..)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_and_chunked() {
        let r = parse_response(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nhi").unwrap();
        assert_eq!(r.status, 200);
        let c = parse_response(b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n").unwrap();
        assert!(matches!(c.body, kr_net::http1::server::Body::Full(ref b) if b == b"abcde"));
    }
}
