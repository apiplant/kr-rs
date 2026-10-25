//! `pods|services/<name>[:port]/proxy[/path]`: a one-shot HTTP/1.1 request relayed to the pod's
//! IP (or a Service endpoint), over TLS for the `https` scheme. The response is read to the end
//! (`Connection: close`) within one overall timeout, on the event loop (non-blocking sockets).
//! Absolute links of HTML responses are rewritten to go through the proxy again.

use alloc::string::String;
use alloc::rc::Rc;
use alloc::vec::Vec;
use kr_crypto::tls::ClientConfig;
use kr_net::http1::server::Response;
use kr_net::http1::Transport;
use kr_net::tcp::{IpAddr, SocketAddr};

/// Whole-exchange budget: connect, send and read the full reply.
const TIMEOUT_MS: u64 = 30_000;
const MAX_BODY: usize = 64 << 20;

/// Where [`forward`] sends a request; built synchronously by the API handler (authorization and
/// the pod lookup), sent by the transport with [`forward`] so the event loop never blocks.
pub struct Target {
    pub method: String,
    pub ip: [u8; 4],
    pub port: u16,
    /// Speak TLS to the backend, without verifying its certificate.
    pub tls: bool,
    /// The proxy URL up to `/proxy`, put in front of rewritten links.
    pub prefix: String,
    pub path: String,
    pub query: String,
    pub content_type: Option<String>,
    pub accept: Option<String>,
    pub body: Vec<u8>,
}

/// Addresses the API server must never proxy to: `status.podIP` is written by nodes, and these
/// would reach the server's own host instead of a pod (upstream's `IsProxyableIP`).
pub fn proxyable(ip: [u8; 4]) -> bool {
    !(ip[0] == 127 || ip == [0, 0, 0, 0] || (ip[0] == 169 && ip[1] == 254) || ip[0] >= 224)
}

/// Relays one request; connection failures are 503, malformed or late replies 502/504.
pub async fn forward(t: Target) -> Response {
    let fail = |code: u16, msg: &str| Response::new(code, msg.as_bytes().to_vec());
    if !proxyable(t.ip) {
        return fail(400, "address not allowed");
    }
    match kr_rt::exec::timeout(TIMEOUT_MS, exchange(&t)).await {
        Ok(Ok(raw)) => parse_response(&raw, &t.prefix).unwrap_or_else(|| fail(502, "invalid response from the pod")),
        Ok(Err(msg)) => fail(503, msg),
        Err(_) => fail(504, "timeout waiting for the pod"),
    }
}

async fn exchange(t: &Target) -> Result<Vec<u8>, &'static str> {
    let sock = kr_net::tcp::connect_addr(SocketAddr { ip: IpAddr::V4(t.ip), port: t.port }, TIMEOUT_MS).await.map_err(|_| "error trying to reach the pod")?;
    if t.tls {
        let cfg = Rc::new(ClientConfig { roots: Vec::new(), pinned_ca: None, client_cert: None, alpn: alloc::vec![b"http/1.1".to_vec()], tls12: false });
        let host = alloc::format!("{}.{}.{}.{}", t.ip[0], t.ip[1], t.ip[2], t.ip[3]);
        let tls = kr_net::tls::TlsStream::connect_insecure(sock, cfg, &host).await.map_err(|_| "error establishing TLS with the pod")?;
        return roundtrip(tls, t).await;
    }
    roundtrip(sock, t).await
}

async fn roundtrip<T: Transport>(mut sock: T, t: &Target) -> Result<Vec<u8>, &'static str> {
    let (ip, port) = (t.ip, t.port);
    let target = if t.query.is_empty() { t.path.clone() } else { alloc::format!("{}?{}", t.path, t.query) };
    let mut req = alloc::format!("{} {target} HTTP/1.1\r\nHost: {}.{}.{}.{}:{port}\r\nConnection: close\r\nUser-Agent: kr-apiserver\r\n", t.method, ip[0], ip[1], ip[2], ip[3]);
    if let Some(ct) = &t.content_type {
        req.push_str(&alloc::format!("Content-Type: {ct}\r\n"));
    }
    if let Some(a) = &t.accept {
        req.push_str(&alloc::format!("Accept: {a}\r\n"));
    }
    if !t.body.is_empty() || matches!(t.method.as_str(), "POST" | "PUT" | "PATCH") {
        req.push_str(&alloc::format!("Content-Length: {}\r\n", t.body.len()));
    }
    req.push_str("\r\n");
    let mut out = req.into_bytes();
    out.extend_from_slice(&t.body);
    sock.write_all(&out).await.map_err(|_| "error sending the request to the pod")?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        match sock.read(&mut buf).await {
            Ok(0) => return Ok(raw),
            Ok(n) if raw.len() + n <= MAX_BODY => raw.extend_from_slice(&buf[..n]),
            Ok(_) => return Err("response from the pod is too large"),
            Err(_) => return Ok(raw),
        }
    }
}

fn parse_response(raw: &[u8], prefix: &str) -> Option<Response> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = core::str::from_utf8(&raw[..end]).ok()?;
    let mut lines = head.split("\r\n");
    let status: u16 = lines.next()?.split(' ').nth(1)?.parse().ok()?;
    let mut headers = Vec::new();
    let mut chunked = false;
    let mut html = false;
    for l in lines {
        let Some((k, v)) = l.split_once(':') else { continue };
        let (k, v) = (k.trim(), v.trim());
        if k.eq_ignore_ascii_case("transfer-encoding") {
            chunked = v.eq_ignore_ascii_case("chunked");
        } else if k.eq_ignore_ascii_case("content-type") || k.eq_ignore_ascii_case("location") {
            html |= k.eq_ignore_ascii_case("content-type") && v.len() >= 9 && v.as_bytes()[..9].eq_ignore_ascii_case(b"text/html");
            headers.push((String::from(k), String::from(v)));
        }
    }
    let rest = &raw[end + 4..];
    let mut body = if chunked { dechunk(rest)? } else { rest.to_vec() };
    if html && !prefix.is_empty() {
        body = rewrite_links(&body, prefix);
    }
    let mut r = Response::new(status, body);
    r.headers = headers;
    Some(r)
}

/// Puts `prefix` in front of absolute `href`, `src` and `action` attribute values inside tags.
fn rewrite_links(body: &[u8], prefix: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 64);
    let (mut i, mut in_tag) = (0, false);
    while i < body.len() {
        let b = body[i];
        out.push(b);
        i += 1;
        match b {
            b'<' => in_tag = true,
            b'>' => in_tag = false,
            b' ' | b'\t' | b'\n' | b'\r' if in_tag => {
                for name in [&b"href="[..], b"src=", b"action="] {
                    let rest = &body[i..];
                    if rest.len() > name.len() + 1 && rest[..name.len()].eq_ignore_ascii_case(name) && matches!(rest[name.len()], b'"' | b'\'') && rest[name.len() + 1] == b'/' && rest.get(name.len() + 2) != Some(&b'/') {
                        out.extend_from_slice(&rest[..name.len() + 1]);
                        out.extend_from_slice(prefix.as_bytes());
                        i += name.len() + 1;
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    out
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
        let r = parse_response(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nhi", "/p").unwrap();
        assert_eq!(r.status, 200);
        let c = parse_response(b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n", "/p").unwrap();
        assert!(matches!(c.body, kr_net::http1::server::Body::Full(ref b) if b == b"abcde"));
    }

    #[test]
    fn html_links_go_through_the_proxy() {
        let r = parse_response(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<a href=\"/rewriteme\">test</a> <img SRC='/x.png'> <a href=\"//cdn/x\">/ href=\"/no\"</a>", "/api/v1/namespaces/n/pods/p/proxy").unwrap();
        let kr_net::http1::server::Body::Full(b) = r.body else { panic!() };
        assert_eq!(core::str::from_utf8(&b).unwrap(), "<a href=\"/api/v1/namespaces/n/pods/p/proxy/rewriteme\">test</a> <img SRC='/api/v1/namespaces/n/pods/p/proxy/x.png'> <a href=\"//cdn/x\">/ href=\"/no\"</a>");
        // Other content types are left alone.
        let r = parse_response(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n<a href=\"/x\">", "/p").unwrap();
        assert!(matches!(r.body, kr_net::http1::server::Body::Full(ref b) if b == b"<a href=\"/x\">"));
    }

    #[test]
    fn host_addresses_are_not_proxied() {
        for ip in [[127, 0, 0, 1], [0, 0, 0, 0], [169, 254, 169, 254], [224, 0, 0, 1]] {
            assert!(!proxyable(ip), "{ip:?}");
        }
        assert!(proxyable([10, 88, 0, 7]) && proxyable([172, 17, 0, 3]));
    }
}
