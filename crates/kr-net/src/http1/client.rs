//! Keep-alive HTTP/1.1 client with redirects, timeouts and a streaming body reader.

use super::body::ChunkedDecoder;
use super::head::{self, Framing, Limits};
use super::url::{Scheme, Url};
use super::{Connector, TcpConnector, Transport};
use crate::{Error, Result};
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;
use kr_rt::exec::timeout;

#[derive(Clone, Debug)]
pub struct Config {
    pub connect_timeout_ms: u64,
    /// Budget for sending the request and receiving the response head.
    pub head_timeout_ms: u64,
    /// Idle limit for each read while streaming a body.
    pub read_timeout_ms: u64,
    pub max_redirects: u32,
    pub limits: Limits,
    pub user_agent: String,
    /// Idle connections kept for reuse.
    pub max_idle: usize,
    /// Idle connections older than this are dropped instead of reused (0 disables pooling).
    pub idle_timeout_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            connect_timeout_ms: 10_000,
            head_timeout_ms: 30_000,
            read_timeout_ms: 30_000,
            max_redirects: 5,
            limits: Limits::default(),
            user_agent: "kr-net/0.0.1".to_string(),
            max_idle: 4,
            idle_timeout_ms: 90_000,
        }
    }
}

type Key = (Scheme, String, u16);

struct Pool<T> {
    /// (key, connection, time it went idle in ms).
    idle: Vec<(Key, T, u64)>,
    max: usize,
    idle_ms: u64,
}

impl<T> Pool<T> {
    /// Drops every connection idle for longer than the timeout.
    fn expire(&mut self, now: u64) {
        let idle_ms = self.idle_ms;
        self.idle.retain(|(_, _, since)| now.saturating_sub(*since) <= idle_ms);
    }
    fn take(&mut self, key: &Key, now: u64) -> Option<T> {
        self.expire(now);
        let i = self.idle.iter().rposition(|(k, _, _)| k == key)?;
        Some(self.idle.remove(i).1)
    }
    fn put(&mut self, key: Key, c: T, now: u64) {
        self.expire(now);
        if self.max == 0 || self.idle_ms == 0 {
            return;
        }
        if self.idle.len() >= self.max {
            self.idle.remove(0);
        }
        self.idle.push((key, c, now));
    }
}

pub struct Client<C: Connector = TcpConnector> {
    connector: C,
    cfg: Config,
    pool: Rc<RefCell<Pool<C::Conn>>>,
}

impl Client<TcpConnector> {
    pub fn new() -> Self {
        Self::with_connector(TcpConnector::default(), Config::default())
    }
}

impl Default for Client<TcpConnector> {
    fn default() -> Self {
        Self::new()
    }
}

struct Head {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    framing: Framing,
    keep_alive: bool,
    /// Bytes read past the head.
    rest: Vec<u8>,
}

fn idempotent(method: &str) -> bool {
    method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD")
}

fn build_request(method: &str, url: &Url, headers: &[(String, String)], body: &[u8], ua: &str) -> Result<Vec<u8>> {
    if !head::is_token(method) {
        return Err(Error::Parse("bad method"));
    }
    let mut r = Vec::with_capacity(256 + body.len().min(4096));
    let mut push = |s: &str| r.extend_from_slice(s.as_bytes());
    push(method);
    push(" ");
    push(&url.path);
    push(" HTTP/1.1\r\nHost: ");
    push(&url.host_header());
    push("\r\nUser-Agent: ");
    push(ua);
    push("\r\nAccept-Encoding: identity\r\n");
    for (n, v) in headers {
        if !head::is_token(n) || !head::valid_field_value(v.as_bytes()) {
            return Err(Error::Parse("bad request header"));
        }
        // These are owned by the client; letting callers set them would allow framing mismatches.
        for reserved in ["host", "content-length", "transfer-encoding", "connection"] {
            if n.eq_ignore_ascii_case(reserved) {
                return Err(Error::Parse("reserved request header"));
            }
        }
        push(n);
        push(": ");
        push(v);
        push("\r\n");
    }
    if !body.is_empty() || ["POST", "PUT", "PATCH"].iter().any(|m| method.eq_ignore_ascii_case(m)) {
        push("Content-Length: ");
        push(&body.len().to_string());
        push("\r\n");
    }
    push("\r\n");
    Ok(r)
}

/// Sends the request and reads the response head. The error carries whether any response byte
/// arrived (a reused connection that died silently is retried only when none did).
async fn exchange<T: Transport>(
    conn: &mut T,
    req: &[u8],
    body: &[u8],
    method: &str,
    lim: &Limits,
) -> core::result::Result<Head, (Error, bool)> {
    conn.write_all(req).await.map_err(|e| (e, false))?;
    if !body.is_empty() {
        conn.write_all(body).await.map_err(|e| (e, false))?;
    }
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut got = false;
    let mut interim = 0;
    loop {
        let step = match head::parse_response(&buf, lim) {
            Err(e) => return Err((e, got)),
            Ok(None) => None,
            Ok(Some((r, n))) => {
                if r.status == 101 {
                    return Err((Error::Parse("unexpected 101 Switching Protocols"), true));
                }
                if (100..200).contains(&r.status) {
                    interim += 1;
                    if interim > 8 {
                        return Err((Error::Parse("too many interim responses"), true));
                    }
                    Some((n, None))
                } else {
                    let framing = head::response_framing(method, &r).map_err(|e| (e, true))?;
                    let ka = head::keep_alive(r.minor, &r.headers) && framing != Framing::UntilClose;
                    Some((
                        n,
                        Some(Head {
                            status: r.status,
                            reason: r.reason.to_string(),
                            headers: r.headers.iter().map(|h| (h.name.to_string(), h.value.to_string())).collect(),
                            framing,
                            keep_alive: ka,
                            rest: Vec::new(),
                        }),
                    ))
                }
            }
        };
        match step {
            Some((n, None)) => {
                buf.drain(..n);
                continue;
            }
            Some((n, Some(mut h))) => {
                buf.drain(..n);
                h.rest = buf;
                return Ok(h);
            }
            None => {}
        }
        let mut tmp = [0u8; 4096];
        let n = conn.read(&mut tmp).await.map_err(|e| (e, got))?;
        if n == 0 {
            return Err((Error::UnexpectedEof, got));
        }
        got = true;
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

impl<C: Connector> Client<C> {
    pub fn with_connector(connector: C, cfg: Config) -> Self {
        let (max, idle_ms) = (cfg.max_idle, cfg.idle_timeout_ms);
        Client { connector, cfg, pool: Rc::new(RefCell::new(Pool { idle: Vec::new(), max, idle_ms })) }
    }

    pub fn connector(&self) -> &C {
        &self.connector
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    async fn send_once(&self, method: &str, url: &Url, headers: &[(String, String)], body: &[u8]) -> Result<(C::Conn, Head)> {
        let req = build_request(method, url, headers, body, &self.cfg.user_agent)?;
        let key: Key = (url.scheme, url.host.clone(), url.port);
        let mut reused = self.pool.borrow_mut().take(&key, kr_rt::exec::now_ms());
        loop {
            let was_reused = reused.is_some();
            let mut conn = match reused.take() {
                Some(c) => c,
                None => self.connector.connect(url, self.cfg.connect_timeout_ms).await?,
            };
            let r = match timeout(self.cfg.head_timeout_ms, exchange(&mut conn, &req, body, method, &self.cfg.limits)).await {
                Ok(r) => r,
                Err(_) => Err((Error::Timeout, true)),
            };
            match r {
                Ok(h) => return Ok((conn, h)),
                // A pooled connection may have been closed by the server while idle.
                Err((_, false)) if was_reused && idempotent(method) => continue,
                Err((e, _)) => return Err(e),
            }
        }
    }

    /// Performs a request, following up to `max_redirects` same-scheme redirects. The returned
    /// [`Response`] streams its body; `https` URLs fail with [`Error::TlsUnsupported`] unless
    /// the connector supports them.
    pub async fn request(&self, method: &str, url: &str, headers: &[(&str, &str)], body: &[u8]) -> Result<Response<C::Conn>> {
        let mut url = Url::parse(url)?;
        let mut method = method.to_string();
        let mut headers: Vec<(String, String)> = headers.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
        let mut body: Vec<u8> = body.to_vec();
        let mut hops = 0;
        loop {
            let (conn, head) = self.send_once(&method, &url, &headers, &body).await?;
            let mut resp = Response::new(self.pool.clone(), (url.scheme, url.host.clone(), url.port), conn, head, self.cfg.read_timeout_ms, &method);
            if !is_redirect(resp.status) {
                return Ok(resp);
            }
            let Some(loc) = resp.header("location").map(|s| s.to_string()) else { return Ok(resp) };
            if hops >= self.cfg.max_redirects {
                return Err(Error::TooManyRedirects);
            }
            hops += 1;
            let next = url.join(&loc)?;
            if next.scheme != url.scheme {
                return Err(Error::RedirectScheme);
            }
            if !next.same_origin(&url) {
                headers.retain(|(n, _)| !["authorization", "cookie", "proxy-authorization"].iter().any(|s| n.eq_ignore_ascii_case(s)));
            }
            let to_get = resp.status == 303 || (matches!(resp.status, 301 | 302) && method.eq_ignore_ascii_case("POST"));
            if to_get && !method.eq_ignore_ascii_case("HEAD") {
                method = "GET".to_string();
                body.clear();
            }
            // Best effort: finish reading so the connection can be reused.
            let _ = resp.drain(64 * 1024).await;
            drop(resp);
            url = next;
        }
    }

    pub async fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<Response<C::Conn>> {
        self.request("GET", url, headers, &[]).await
    }
}

enum BodyState {
    Length(u64),
    Chunked(ChunkedDecoder),
    UntilClose,
    Done,
}

/// A response whose head has been read. The body is pulled with [`Response::read_chunk`];
/// when it is fully consumed a keep-alive connection returns to the client's pool. Dropping an
/// unfinished response closes the connection.
pub struct Response<T: Transport> {
    pub status: u16,
    pub reason: String,
    headers: Vec<(String, String)>,
    conn: Option<T>,
    pool: Rc<RefCell<Pool<T>>>,
    key: Key,
    buf: Vec<u8>,
    pos: usize,
    state: BodyState,
    content_length: Option<u64>,
    keep_alive: bool,
    read_timeout_ms: u64,
}

impl<T: Transport> Response<T> {
    fn new(pool: Rc<RefCell<Pool<T>>>, key: Key, conn: T, head: Head, read_timeout_ms: u64, _method: &str) -> Self {
        let (state, content_length) = match head.framing {
            Framing::None => (BodyState::Done, Some(0)),
            Framing::Length(n) => (BodyState::Length(n), Some(n)),
            Framing::Chunked => (BodyState::Chunked(ChunkedDecoder::new()), None),
            Framing::UntilClose => (BodyState::UntilClose, None),
        };
        let mut r = Response {
            status: head.status,
            reason: head.reason,
            headers: head.headers,
            conn: Some(conn),
            pool,
            key,
            buf: head.rest,
            pos: 0,
            state,
            content_length,
            keep_alive: head.keep_alive,
            read_timeout_ms,
        };
        if matches!(r.state, BodyState::Done) {
            r.release();
        }
        r
    }

    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// First header with this name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// The declared body length, when the framing is Content-Length (or there is no body).
    pub fn content_length(&self) -> Option<u64> {
        self.content_length
    }

    pub fn is_complete(&self) -> bool {
        matches!(self.state, BodyState::Done)
    }

    /// Returns the connection to the pool if it is clean and keep-alive.
    fn release(&mut self) {
        self.state = BodyState::Done;
        // Unconsumed bytes would be a pipelined/garbage response: do not reuse.
        if self.keep_alive && self.pos == self.buf.len() {
            if let Some(c) = self.conn.take() {
                self.pool.borrow_mut().put(self.key.clone(), c, kr_rt::exec::now_ms());
            }
        }
        self.conn = None;
    }

    async fn fill(&mut self) -> Result<usize> {
        let conn = self.conn.as_mut().ok_or(Error::UnexpectedEof)?;
        self.buf.clear();
        self.pos = 0;
        self.buf.resize(16 * 1024, 0);
        let r = match timeout(self.read_timeout_ms, conn.read(&mut self.buf)).await {
            Ok(r) => r,
            Err(_) => Err(Error::Timeout),
        };
        match r {
            Ok(n) => {
                self.buf.truncate(n);
                Ok(n)
            }
            Err(e) => {
                self.buf.clear();
                self.conn = None; // state unknown after a failed/timed-out read
                Err(e)
            }
        }
    }

    /// Reads body bytes into `out`; `Ok(0)` means the body is complete. Truncated Content-Length
    /// or chunked bodies fail with [`Error::UnexpectedEof`].
    pub async fn read_chunk(&mut self, out: &mut [u8]) -> Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if matches!(self.state, BodyState::Done) {
                return Ok(0);
            }
            if self.pos == self.buf.len() && self.fill().await? == 0 {
                return match self.state {
                    BodyState::UntilClose => {
                        self.keep_alive = false;
                        self.release();
                        Ok(0)
                    }
                    _ => {
                        self.conn = None;
                        self.state = BodyState::Done;
                        Err(Error::UnexpectedEof)
                    }
                };
            }
            let input = &self.buf[self.pos..];
            match &mut self.state {
                BodyState::Length(rem) => {
                    let n = (*rem).min(input.len() as u64).min(out.len() as u64) as usize;
                    out[..n].copy_from_slice(&input[..n]);
                    *rem -= n as u64;
                    let finished = *rem == 0;
                    self.pos += n;
                    if finished {
                        self.release();
                    }
                    return Ok(n);
                }
                BodyState::UntilClose => {
                    let n = input.len().min(out.len());
                    out[..n].copy_from_slice(&input[..n]);
                    self.pos += n;
                    return Ok(n);
                }
                BodyState::Chunked(d) => {
                    let (c, p) = match d.decode(input, out) {
                        Ok(x) => x,
                        Err(e) => {
                            self.conn = None;
                            self.state = BodyState::Done;
                            return Err(e);
                        }
                    };
                    let finished = d.is_done();
                    self.pos += c;
                    if finished {
                        self.release();
                    }
                    if p > 0 || finished {
                        return Ok(p);
                    }
                }
                BodyState::Done => return Ok(0),
            }
        }
    }

    /// Reads the whole body, failing with [`Error::TooLarge`] beyond `limit` bytes.
    pub async fn read_to_end(&mut self, limit: usize) -> Result<Vec<u8>> {
        if let Some(n) = self.content_length {
            if n > limit as u64 {
                return Err(Error::TooLarge("body"));
            }
        }
        let mut out = Vec::new();
        let mut tmp = [0u8; 8192];
        loop {
            let n = self.read_chunk(&mut tmp).await?;
            if n == 0 {
                return Ok(out);
            }
            if out.len() + n > limit {
                return Err(Error::TooLarge("body"));
            }
            out.extend_from_slice(&tmp[..n]);
        }
    }

    /// Discards up to `max` more body bytes; returns whether the body completed (so the
    /// connection could be reused).
    pub async fn drain(&mut self, max: usize) -> Result<bool> {
        let mut seen = 0;
        let mut tmp = [0u8; 4096];
        loop {
            let n = self.read_chunk(&mut tmp).await?;
            if n == 0 {
                return Ok(true);
            }
            seen += n;
            if seen > max {
                return Ok(false);
            }
        }
    }
}

#[cfg(test)]
mod pool_tests {
    use super::*;

    fn key() -> Key {
        (Scheme::Http, "h".to_string(), 80)
    }

    #[test]
    fn idle_connections_expire() {
        let mut p: Pool<u8> = Pool { idle: Vec::new(), max: 4, idle_ms: 100 };
        p.put(key(), 1, 1000);
        p.put(key(), 2, 1050);
        // newest first, both still fresh
        assert_eq!(p.take(&key(), 1100), Some(2));
        p.put(key(), 3, 1100);
        // 1 is now 200ms old: dropped, never handed out
        assert_eq!(p.take(&key(), 1200), Some(3));
        assert_eq!(p.take(&key(), 1200), None);
        assert!(p.idle.is_empty());
        p.put(key(), 4, 2000);
        assert_eq!(p.take(&key(), 2101), None);
    }

    #[test]
    fn zero_timeout_disables_pooling() {
        let mut p: Pool<u8> = Pool { idle: Vec::new(), max: 4, idle_ms: 0 };
        p.put(key(), 1, 0);
        assert!(p.idle.is_empty());
    }
}
