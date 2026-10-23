//! Async HTTP/1.1 server on the single-threaded executor (for hosting an API server).
//!
//! One task per connection, requests handled strictly in order (a pipelining client gets its
//! answers in order; the next request is only parsed after the previous response is complete).
//! Parsing reuses the strict [`head`] parser, so the request-smuggling defences apply unchanged:
//! conflicting or doubled framing, obs-fold and bare LF/CR are answered with `400` and the
//! connection is closed.
//!
//! Streaming responses ([`Body::Stream`]) are sent with chunked coding and flushed per chunk.
//! While waiting for the next chunk the server also reads the socket, so a client that goes
//! away is noticed at once and the stream is dropped (a Kubernetes `watch` must not leak).
//! Bytes read meanwhile (a pipelined next request) are kept for the following request.
//!
//! [`Body::Upgrade`] switches protocols: after the `101` head is written the connection is handed
//! to an [`UpgradeHandler`] as a type-erased [`Conn`] (see [`super::upgrade`]); no HTTP timeouts
//! apply from then on.

use super::body::{encode_chunk, encode_end, ChunkedDecoder};
use super::head::{self, is_token, keep_alive, parse_request, request_framing, valid_field_value, Framing, Limits};
use super::upgrade::{ConnIo, Shared};
use super::Transport;
use crate::tls::TlsStream;
use crate::{Error, Result};
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::future::{poll_fn, Future};
use core::pin::{pin, Pin};
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll};
use kr_rt::exec::{sleep, spawn, timeout, Async};
use kr_sys::{self as sys, Errno, Fd};

pub use super::upgrade::{Conn as UpgradedConn, UpgradeFuture, UpgradeHandler};

/// Connections in the lingering-close drain at once; above it, close immediately.
const MAX_LINGER: usize = 256;
const LINGER_MS: u64 = 1_000;
static LINGERING: AtomicUsize = AtomicUsize::new(0);
/// Pipelined bytes buffered while a stream is running; above this we stop reading (the client
/// then only gets disconnect detection through write errors).
const MAX_PIPELINE_BUF: usize = 64 * 1024;

#[cfg(target_arch = "x86_64")]
const NR_GETSOCKNAME: usize = 51;
#[cfg(target_arch = "x86_64")]
const NR_GETPEERNAME: usize = 52;
#[cfg(target_arch = "aarch64")]
const NR_GETSOCKNAME: usize = 204;
#[cfg(target_arch = "aarch64")]
const NR_GETPEERNAME: usize = 205;

const IPPROTO_TCP: i32 = 6;
const TCP_NODELAY: i32 = 1;

// ---------- public types ----------

/// Who is on the other end.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerInfo {
    /// Remote IPv4 address and port (`None` if it could not be determined).
    pub addr: Option<([u8; 4], u16)>,
    /// True when the connection is TLS.
    pub tls: bool,
    /// The verified client certificate chain (DER, leaf first), if the client presented one.
    pub client_certs: Option<Vec<Vec<u8>>>,
    /// The negotiated ALPN protocol, if any.
    pub alpn: Option<Vec<u8>>,
}

/// A fully read request.
#[derive(Clone, Debug)]
pub struct Request {
    pub method: String,
    /// Path and query, exactly as received.
    pub target: String,
    pub headers: Vec<(String, String)>,
    /// Decoded body (Content-Length or chunked), at most [`ServerConfig::max_body`] bytes.
    pub body: Vec<u8>,
    pub peer: PeerInfo,
}

impl Request {
    /// First header named `name` (ASCII case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// The target up to (excluding) `?`.
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or("")
    }

    /// The target after `?` (empty if there is none).
    pub fn query(&self) -> &str {
        self.target.split_once('?').map_or("", |(_, q)| q)
    }
}

/// A source of body chunks for a streaming response. Dropping it cancels the stream; that is
/// how the server reports a vanished client.
pub trait ResponseStream {
    /// `Ready(Some(chunk))` is written and flushed at once (empty chunks are ignored),
    /// `Ready(None)` ends the response, `Pending` must have registered the waker in `cx`.
    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<Vec<u8>>>;
}

pub enum Body {
    /// Sent with `Content-Length`.
    Full(Vec<u8>),
    /// Sent with `Transfer-Encoding: chunked` (HTTP/1.0 clients get a close-delimited body).
    Stream(Box<dyn ResponseStream>),
    /// Protocol switch. The response must have status `101` and carry an `Upgrade` header (the
    /// server adds `Connection: Upgrade`, `Date` and drops framing headers). After the head is
    /// written the handler owns the connection. Only honoured for HTTP/1.1 requests; anything
    /// else (including a non-101 status or a missing `Upgrade` header) becomes an error response.
    Upgrade(Box<dyn UpgradeHandler>),
}

pub struct Response {
    pub status: u16,
    /// Handler headers. Invalid names/values are dropped, as are the ones the server owns
    /// (`Content-Length`, `Transfer-Encoding`, `Date`; `Connection: close` is honoured).
    pub headers: Vec<(String, String)>,
    pub body: Body,
}

impl Response {
    pub fn new(status: u16, body: Vec<u8>) -> Response {
        Response { status, headers: Vec::new(), body: Body::Full(body) }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Response {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

pub type HandlerFuture = Pin<Box<dyn Future<Output = Response>>>;

pub trait Handler {
    fn handle(&self, req: Request) -> HandlerFuture;
}

impl<F> Handler for F
where
    F: Fn(Request) -> HandlerFuture,
{
    fn handle(&self, req: Request) -> HandlerFuture {
        self(req)
    }
}

pub struct ServerConfig {
    /// Request line + headers, bytes. Larger heads get `431`.
    pub max_head: usize,
    /// Request body, bytes. Larger bodies get `413`.
    pub max_body: usize,
    /// Keep-alive wait for the first byte of the next request; the connection is then closed.
    pub idle_timeout_ms: u64,
    /// Whole request head (and the TLS handshake) once the first byte arrived; `408` on expiry.
    pub head_timeout_ms: u64,
    /// Per-read deadline while reading a request body; `408` on expiry.
    pub body_timeout_ms: u64,
    /// Per-write deadline (a stalled reader is disconnected).
    pub write_timeout_ms: u64,
    /// Connections above this are accepted and closed at once.
    pub max_connections: usize,
    pub tls: Option<Rc<kr_crypto::tls::ServerConfig>>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            max_head: 16 * 1024,
            max_body: 3 * 1024 * 1024,
            idle_timeout_ms: 120_000,
            head_timeout_ms: 10_000,
            body_timeout_ms: 30_000,
            write_timeout_ms: 30_000,
            max_connections: 1024,
            tls: None,
        }
    }
}

// ---------- listening ----------

/// A non-blocking, close-on-exec listening IPv4 socket with `SO_REUSEADDR`.
pub fn listen(addr: [u8; 4], port: u16, backlog: i32) -> Result<Async<Fd>> {
    let fd = sys::socket(sys::AF_INET, sys::SOCK_STREAM | sys::SOCK_NONBLOCK | sys::SOCK_CLOEXEC, 0)?;
    sys::setsockopt(fd.raw(), sys::SOL_SOCKET, sys::SO_REUSEADDR, &1i32.to_ne_bytes())?;
    sys::bind(fd.raw(), &sys::SockaddrIn::new(addr, port))?;
    sys::listen(fd.raw(), backlog)?;
    Ok(Async::new(fd)?)
}

/// The bound local address of a listener (useful after binding port 0).
pub fn local_addr(l: &Async<Fd>) -> Option<([u8; 4], u16)> {
    sockname(NR_GETSOCKNAME, l.get_ref().raw())
}

fn sockname(nr: usize, fd: i32) -> Option<([u8; 4], u16)> {
    let mut sa = [0u8; 28];
    let mut len: u32 = sa.len() as u32;
    // SAFETY: `sa`/`len` are valid writable locals of the sizes passed; getsockname/getpeername
    // write at most `len` bytes and update `len`.
    let r = unsafe { sys::syscall3(nr, fd as usize, sa.as_mut_ptr() as usize, &mut len as *mut u32 as usize) };
    if r < 0 || len < 8 || u16::from_ne_bytes([sa[0], sa[1]]) != sys::AF_INET as u16 {
        return None;
    }
    Some(([sa[4], sa[5], sa[6], sa[7]], u16::from_be_bytes([sa[2], sa[3]])))
}

// ---------- accept loop ----------

/// Accepts connections forever, one task per connection. Returns only on a fatal listener error.
pub async fn serve(listener: Async<Fd>, cfg: Rc<ServerConfig>, handler: Rc<dyn Handler>) -> Result<()> {
    let active = Rc::new(Cell::new(0usize));
    loop {
        match listener.accept().await {
            Ok(sock) => {
                if active.get() >= cfg.max_connections {
                    drop(sock); // over the cap: close at once, never stall the accept loop
                    continue;
                }
                active.set(active.get() + 1);
                let guard = ConnGuard(active.clone());
                spawn(connection(sock, cfg.clone(), handler.clone(), guard));
            }
            // Listener itself is broken (closed fd, not a socket, not listening).
            Err(Errno(e)) if e == 9 || e == 22 || e == 88 => return Err(Error::Io(Errno(e))),
            // Transient (EMFILE, ECONNABORTED, ...): back off briefly instead of spinning.
            Err(_) => sleep(10).await,
        }
    }
}

struct ConnGuard(Rc<Cell<usize>>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.set(self.0.get() - 1);
    }
}

// ---------- connection plumbing ----------

enum Conn {
    Plain(Async<Fd>),
    Tls(Box<TlsStream<Async<Fd>>>),
}

impl Conn {
    fn sock(&self) -> &Async<Fd> {
        match self {
            Conn::Plain(s) => s,
            Conn::Tls(t) => t.get_ref(),
        }
    }

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            Conn::Plain(s) => Transport::read(s, buf).await,
            Conn::Tls(t) => t.read(buf).await,
        }
    }

    async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        match self {
            Conn::Plain(s) => Transport::write_all(s, buf).await,
            Conn::Tls(t) => t.write_all(buf).await,
        }
    }

    /// Write with the configured deadline.
    async fn send(&mut self, buf: &[u8], ms: u64) -> core::result::Result<(), ()> {
        match timeout(ms, self.write_all(buf)).await {
            Ok(Ok(())) => Ok(()),
            _ => Err(()),
        }
    }

    /// Ends the connection. `linger` drains what the peer still sends (see [`linger_close`]).
    async fn close(&mut self, linger: bool) {
        if let Conn::Tls(t) = self {
            let _ = timeout(LINGER_MS, t.shutdown()).await;
        }
        if linger {
            linger_close(self.sock()).await;
        }
    }
}

/// Signals EOF with `shutdown(SHUT_WR)` and discards whatever the peer still sends for up to a
/// second, so closing with unread data does not become a TCP RST that destroys our response.
async fn linger_close(c: &Async<Fd>) {
    struct Slot;
    impl Drop for Slot {
        fn drop(&mut self) {
            LINGERING.fetch_sub(1, Ordering::Relaxed);
        }
    }
    if LINGERING.fetch_add(1, Ordering::Relaxed) >= MAX_LINGER {
        LINGERING.fetch_sub(1, Ordering::Relaxed);
        return;
    }
    let _slot = Slot;
    if sys::shutdown(c.get_ref().raw(), sys::SHUT_WR).is_err() {
        return;
    }
    let _ = timeout(LINGER_MS, async {
        let mut tmp = [0u8; 4096];
        loop {
            match c.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await;
}

/// Why reading a request stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fail {
    /// Peer went away, idle timeout or I/O error: close without a response.
    Close,
    /// Answer with this status, then close.
    Status(u16),
}

fn status_for(e: &Error) -> u16 {
    match e {
        Error::TooLarge(_) => 431,
        Error::Parse("unsupported HTTP version") => 505,
        Error::Parse("unsupported transfer coding") => 501,
        _ => 400,
    }
}

/// Reads more bytes into `buf` under a deadline; `on_timeout` is the failure for expiry.
async fn fill(conn: &mut Conn, buf: &mut Vec<u8>, ms: u64, on_timeout: Fail) -> core::result::Result<(), Fail> {
    let mut tmp = [0u8; 8192];
    match timeout(ms, conn.read(&mut tmp)).await {
        Err(_) => Err(on_timeout),
        Ok(Err(_)) | Ok(Ok(0)) => Err(Fail::Close),
        Ok(Ok(n)) => {
            buf.extend_from_slice(&tmp[..n]);
            Ok(())
        }
    }
}

struct Head {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    minor: u8,
    framing: Framing,
    keep_alive: bool,
    expect_continue: bool,
    consumed: usize,
}

fn to_head(req: &head::Request<'_>, consumed: usize) -> core::result::Result<Head, Fail> {
    let framing = request_framing(req).map_err(|e| Fail::Status(status_for(&e)))?;
    let mut expect_continue = false;
    for h in req.headers.iter().filter(|h| h.name.eq_ignore_ascii_case("expect")) {
        if h.value.eq_ignore_ascii_case("100-continue") {
            expect_continue = true;
        } else {
            return Err(Fail::Status(417));
        }
    }
    Ok(Head {
        method: req.method.to_string(),
        target: req.target.to_string(),
        headers: req.headers.iter().map(|h| (h.name.to_string(), h.value.to_string())).collect(),
        minor: req.minor,
        framing,
        keep_alive: keep_alive(req.minor, &req.headers),
        expect_continue,
        consumed,
    })
}

async fn read_head(conn: &mut Conn, buf: &mut Vec<u8>, cfg: &ServerConfig) -> core::result::Result<Head, Fail> {
    if buf.is_empty() {
        // Keep-alive wait: silence here is not an error, just close.
        fill(conn, buf, cfg.idle_timeout_ms, Fail::Close).await?;
    }
    let lim = Limits { max_head: cfg.max_head, max_line: cfg.max_head.min(8 * 1024), max_headers: 100 };
    let ms = cfg.head_timeout_ms;
    let r = timeout(ms, async {
        loop {
            let parsed = match parse_request(buf, &lim) {
                Ok(Some((req, n))) => Some(to_head(&req, n)?),
                Ok(None) => None,
                Err(e) => return Err(Fail::Status(status_for(&e))),
            };
            match parsed {
                Some(h) => return Ok(h),
                None => fill(conn, buf, ms, Fail::Status(408)).await?,
            }
        }
    })
    .await;
    match r {
        Ok(r) => r,
        Err(_) => Err(Fail::Status(408)),
    }
}

async fn read_body(conn: &mut Conn, buf: &mut Vec<u8>, framing: Framing, cfg: &ServerConfig) -> core::result::Result<Vec<u8>, Fail> {
    let mut body = Vec::new();
    match framing {
        Framing::None => {}
        Framing::Length(n) => {
            if n > cfg.max_body as u64 {
                return Err(Fail::Status(413));
            }
            let n = n as usize;
            while buf.len() < n {
                fill(conn, buf, cfg.body_timeout_ms, Fail::Status(408)).await?;
            }
            body.extend(buf.drain(..n));
        }
        Framing::Chunked => {
            let mut dec = ChunkedDecoder::new();
            let mut out = [0u8; 8192];
            while !dec.is_done() {
                if buf.is_empty() {
                    fill(conn, buf, cfg.body_timeout_ms, Fail::Status(408)).await?;
                }
                let (c, p) = dec.decode(buf, &mut out).map_err(|_| Fail::Status(400))?;
                buf.drain(..c);
                if body.len() + p > cfg.max_body {
                    return Err(Fail::Status(413));
                }
                body.extend_from_slice(&out[..p]);
            }
        }
        Framing::UntilClose => return Err(Fail::Status(400)),
    }
    Ok(body)
}

async fn connection(sock: Async<Fd>, cfg: Rc<ServerConfig>, handler: Rc<dyn Handler>, _guard: ConnGuard) {
    let _ = sys::setsockopt(sock.get_ref().raw(), IPPROTO_TCP, TCP_NODELAY, &1i32.to_ne_bytes());
    let mut peer = PeerInfo { addr: sockname(NR_GETPEERNAME, sock.get_ref().raw()), ..PeerInfo::default() };
    let mut conn = match &cfg.tls {
        None => Conn::Plain(sock),
        Some(tls) => match timeout(cfg.head_timeout_ms, TlsStream::accept(sock, tls.clone())).await {
            Ok(Ok(s)) => {
                let c = s.connection();
                peer.tls = true;
                peer.alpn = c.alpn().map(|a| a.to_vec());
                peer.client_certs = Some(c.peer_certificates().to_vec()).filter(|v| !v.is_empty());
                Conn::Tls(Box::new(s))
            }
            _ => return, // failed or timed-out handshake: just close
        },
    };
    let mut up = None;
    let linger = run(&mut conn, &cfg, &*handler, &peer, &mut up).await;
    if let Some((h, leftover)) = up {
        run_upgraded(&mut conn, h, leftover).await;
        conn.close(true).await;
        return;
    }
    if let Some(linger) = linger {
        conn.close(linger).await;
    }
}

/// The request loop. Returns `Some(linger)` when the connection should be closed gracefully,
/// `None` when it is already unusable.
async fn run(
    conn: &mut Conn,
    cfg: &ServerConfig,
    handler: &dyn Handler,
    peer: &PeerInfo,
    up: &mut Option<(Box<dyn UpgradeHandler>, Vec<u8>)>,
) -> Option<bool> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let head = match read_head(conn, &mut buf, cfg).await {
            Ok(h) => h,
            Err(Fail::Close) => return Some(false),
            Err(Fail::Status(s)) => return error_close(conn, cfg, s).await,
        };
        buf.drain(..head.consumed);
        // Refuse before 100-continue so the client does not upload a doomed body.
        if let Framing::Length(n) = head.framing {
            if n > cfg.max_body as u64 {
                return error_close(conn, cfg, 413).await;
            }
        }
        if head.expect_continue && head.minor == 1 && head.framing != Framing::None {
            if conn.send(b"HTTP/1.1 100 Continue\r\n\r\n", cfg.write_timeout_ms).await.is_err() {
                return None;
            }
        }
        let body = match read_body(conn, &mut buf, head.framing, cfg).await {
            Ok(b) => b,
            Err(Fail::Close) => return Some(false),
            Err(Fail::Status(s)) => return error_close(conn, cfg, s).await,
        };
        let is_head = head.method == "HEAD";
        let (minor, keep) = (head.minor, head.keep_alive);
        let req = Request { method: head.method, target: head.target, headers: head.headers, body, peer: peer.clone() };
        let mut resp = handler.handle(req).await;
        if let Body::Upgrade(h) = resp.body {
            if minor == 1 && resp.status == 101 {
                match send_upgrade_head(conn, cfg, &resp.headers).await {
                    Ok(true) => {
                        *up = Some((h, core::mem::take(&mut buf)));
                        return Some(false);
                    }
                    Ok(false) => return error_close(conn, cfg, 500).await,
                    Err(()) => return None,
                }
            }
            resp.body = Body::Full(Vec::new());
            resp.status = if minor == 1 { 500 } else { 400 };
        }
        match send_response(conn, cfg, resp, is_head, minor, keep, &mut buf).await {
            Ok(true) => {}
            Ok(false) => return Some(true),
            Err(()) => return None,
        }
    }
}

async fn error_close(conn: &mut Conn, cfg: &ServerConfig, status: u16) -> Option<bool> {
    let mut body = Vec::new();
    body.extend_from_slice(reason(status).as_bytes());
    body.push(b'\n');
    let resp = Response::new(status, body).with_header("Content-Type", "text/plain");
    let mut scratch = Vec::new();
    match send_response(conn, cfg, resp, false, 1, false, &mut scratch).await {
        Ok(_) => Some(true),
        Err(()) => None,
    }
}

// ---------- responses ----------

/// Writes `resp`. Returns `Ok(true)` if the connection may serve another request.
async fn send_response(
    conn: &mut Conn,
    cfg: &ServerConfig,
    resp: Response,
    is_head: bool,
    minor: u8,
    keep: bool,
    rbuf: &mut Vec<u8>,
) -> core::result::Result<bool, ()> {
    let Response { mut status, headers, body } = resp;
    let mut body = body;
    if !(200..=599).contains(&status) {
        // A handler may not send interim or nonsense statuses.
        status = 500;
        body = Body::Full(Vec::new());
    }
    if matches!(body, Body::Upgrade(_)) {
        status = 500; // unreachable via `run`, which intercepts upgrades
        body = Body::Full(Vec::new());
    }
    let no_body_status = status == 204 || status == 304;
    let mut keep = keep;
    let mut out: Vec<u8> = Vec::with_capacity(256);
    out.extend_from_slice(b"HTTP/1.1 ");
    push_num(&mut out, status as u64);
    out.push(b' ');
    out.extend_from_slice(reason(status).as_bytes());
    out.extend_from_slice(b"\r\nDate: ");
    out.extend_from_slice(http_date().as_bytes());
    out.extend_from_slice(b"\r\n");
    for (k, v) in &headers {
        if !is_token(k) || !valid_field_value(v.as_bytes()) {
            continue; // CR/LF injection and other junk is never emitted
        }
        if k.eq_ignore_ascii_case("connection") {
            if v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")) {
                keep = false;
            }
            continue;
        }
        if k.eq_ignore_ascii_case("content-length")
            || k.eq_ignore_ascii_case("transfer-encoding")
            || k.eq_ignore_ascii_case("date")
            || k.eq_ignore_ascii_case("keep-alive")
            || k.eq_ignore_ascii_case("upgrade")
        {
            continue;
        }
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    let mut stream: Option<(Box<dyn ResponseStream>, bool)> = None;
    match body {
        Body::Full(data) => {
            if !no_body_status {
                out.extend_from_slice(b"Content-Length: ");
                push_num(&mut out, data.len() as u64);
                out.extend_from_slice(b"\r\n");
            }
            finish_head(&mut out, keep, minor);
            if !is_head && !no_body_status {
                out.extend_from_slice(&data);
            }
        }
        Body::Upgrade(_) => unreachable!("replaced above"),
        Body::Stream(s) => {
            let sends_body = !is_head && !no_body_status;
            let chunked = minor >= 1;
            if sends_body {
                if chunked {
                    out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
                } else {
                    keep = false; // HTTP/1.0: the body is delimited by closing
                }
            }
            finish_head(&mut out, keep, minor);
            if sends_body {
                stream = Some((s, chunked));
            }
        }
    }
    conn.send(&out, cfg.write_timeout_ms).await?;
    if let Some((s, chunked)) = stream {
        if !stream_body(conn, cfg, s, chunked, rbuf).await {
            return Err(());
        }
    }
    Ok(keep)
}

/// Writes the `101` head. `Ok(false)` if the handler's headers lack `Upgrade`.
async fn send_upgrade_head(conn: &mut Conn, cfg: &ServerConfig, headers: &[(String, String)]) -> core::result::Result<bool, ()> {
    let mut out: Vec<u8> = Vec::with_capacity(256);
    out.extend_from_slice(b"HTTP/1.1 101 Switching Protocols\r\nDate: ");
    out.extend_from_slice(http_date().as_bytes());
    out.extend_from_slice(b"\r\nConnection: Upgrade\r\n");
    let mut has_upgrade = false;
    for (k, v) in headers {
        if !is_token(k) || !valid_field_value(v.as_bytes()) {
            continue;
        }
        if k.eq_ignore_ascii_case("connection")
            || k.eq_ignore_ascii_case("content-length")
            || k.eq_ignore_ascii_case("transfer-encoding")
            || k.eq_ignore_ascii_case("date")
            || k.eq_ignore_ascii_case("keep-alive")
        {
            continue;
        }
        has_upgrade |= k.eq_ignore_ascii_case("upgrade");
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if !has_upgrade {
        return Ok(false);
    }
    out.extend_from_slice(b"\r\n");
    conn.send(&out, cfg.write_timeout_ms).await.map(|_| true)
}

/// Runs the handler and the pump (transport <-> shared buffers) side by side until both are
/// done. The pump has no deadlines; it ends when the handler drops/closes its [`Conn`] (after
/// flushing) or the transport fails.
async fn run_upgraded(conn: &mut Conn, h: Box<dyn UpgradeHandler>, leftover: Vec<u8>) {
    let sh = Shared::new(leftover);
    let mut hf = Some(h.upgrade(Box::new(ConnIo { sh: sh.clone() })));
    let mut pump = pin!(pump(conn, &sh));
    let mut pump_done = false;
    poll_fn(|cx| {
        if let Some(f) = hf.as_mut() {
            if f.as_mut().poll(cx).is_ready() {
                hf = None;
                sh.borrow_mut().request_close();
            }
        }
        if !pump_done && pump.as_mut().poll(cx).is_ready() {
            pump_done = true;
        }
        if hf.is_none() && pump_done {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
}

async fn pump(conn: &mut Conn, sh: &Rc<RefCell<Shared>>) {
    let mut tmp = [0u8; 8192];
    loop {
        let batch = {
            let mut s = sh.borrow_mut();
            if s.tx.is_empty() {
                None
            } else {
                s.writing = true;
                Some(core::mem::take(&mut s.tx))
            }
        };
        if let Some(data) = batch {
            // Never raced against anything, so a partial write is never abandoned.
            let r = conn.write_all(&data).await;
            let mut s = sh.borrow_mut();
            match r {
                Ok(()) => s.tx_done(),
                Err(e) => {
                    s.fail_tx(e);
                    s.finish();
                    return;
                }
            }
            continue;
        }
        if sh.borrow().close_req {
            break;
        }
        let ev = poll_fn(|cx| {
            {
                let mut s = sh.borrow_mut();
                if !s.tx.is_empty() || s.close_req {
                    return Poll::Ready(None);
                }
                s.pump_waker = Some(cx.waker().clone());
                if s.rx_eof || s.rx_failed() || s.rx_len() >= super::upgrade::RX_CAP {
                    return Poll::Pending;
                }
            }
            // A fresh read per poll is fine: Transport reads are cancel-safe.
            let mut rd = pin!(conn.read(&mut tmp));
            rd.as_mut().poll(cx).map(Some)
        })
        .await;
        match ev {
            None => {}
            Some(Ok(0)) => sh.borrow_mut().set_eof(),
            Some(Ok(n)) => sh.borrow_mut().push_rx(&tmp[..n]),
            Some(Err(e)) => sh.borrow_mut().set_rx_err(e),
        }
    }
    sh.borrow_mut().finish();
}

fn finish_head(out: &mut Vec<u8>, keep: bool, minor: u8) {
    if !keep {
        out.extend_from_slice(b"Connection: close\r\n");
    } else if minor == 0 {
        out.extend_from_slice(b"Connection: keep-alive\r\n");
    }
    out.extend_from_slice(b"\r\n");
}

enum Ev {
    Item(Option<Vec<u8>>),
    Read(Result<usize>),
}

/// Pumps `stream` to the client, flushing every chunk. Returns false if the connection died
/// (client gone or write failure), in which case `stream` has been dropped.
async fn stream_body(conn: &mut Conn, cfg: &ServerConfig, mut stream: Box<dyn ResponseStream>, chunked: bool, rbuf: &mut Vec<u8>) -> bool {
    let mut tmp = [0u8; 2048];
    let mut out: Vec<u8> = Vec::new();
    loop {
        let ev = {
            let mut next = pin!(poll_fn(|cx| stream.poll_next(cx)));
            if rbuf.len() >= MAX_PIPELINE_BUF {
                Ev::Item(next.await)
            } else {
                // Racing a socket read against the next chunk is what notices a dead client.
                // Dropping the unfinished read loses no data (Transport is cancel-safe).
                let mut rd = pin!(conn.read(&mut tmp));
                poll_fn(|cx| {
                    if let Poll::Ready(v) = next.as_mut().poll(cx) {
                        return Poll::Ready(Ev::Item(v));
                    }
                    if let Poll::Ready(r) = rd.as_mut().poll(cx) {
                        return Poll::Ready(Ev::Read(r));
                    }
                    Poll::Pending
                })
                .await
            }
        };
        match ev {
            Ev::Read(Ok(n)) if n > 0 => rbuf.extend_from_slice(&tmp[..n]),
            Ev::Read(_) => return false, // EOF or error: dropping `stream` cancels the watch
            Ev::Item(Some(chunk)) => {
                if chunk.is_empty() {
                    continue;
                }
                out.clear();
                if chunked {
                    encode_chunk(&mut out, &chunk);
                } else {
                    out.extend_from_slice(&chunk);
                }
                if conn.send(&out, cfg.write_timeout_ms).await.is_err() {
                    return false;
                }
            }
            Ev::Item(None) => {
                if chunked {
                    out.clear();
                    encode_end(&mut out);
                    return conn.send(&out, cfg.write_timeout_ms).await.is_ok();
                }
                return true;
            }
        }
    }
}

fn push_num(out: &mut Vec<u8>, mut n: u64) {
    let mut d = [0u8; 20];
    let mut i = d.len();
    loop {
        i -= 1;
        d[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(&d[i..]);
}

fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        417 => "Expectation Failed",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "Status",
    }
}

/// RFC 9110 IMF-fixdate of the current CLOCK_REALTIME, e.g. `Sun, 06 Nov 1994 08:49:37 GMT`.
fn http_date() -> String {
    let secs = sys::clock_gettime(0).map(|t| t.tv_sec).unwrap_or(0);
    imf_fixdate(secs)
}

fn imf_fixdate(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    // Civil-from-days (Howard Hinnant), days since 1970-01-01.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    const WD: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MON: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let wd = WD[((days + 4).rem_euclid(7)) as usize];
    alloc::format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        wd,
        d,
        MON[(m - 1) as usize],
        y,
        tod / 3600,
        tod % 3600 / 60,
        tod % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn date_format() {
        assert_eq!(imf_fixdate(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(imf_fixdate(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(imf_fixdate(951_782_400), "Tue, 29 Feb 2000 00:00:00 GMT");
    }

    #[test]
    fn request_helpers() {
        let r = Request {
            method: "GET".into(),
            target: "/api/v1/pods?watch=true&x=1".into(),
            headers: alloc::vec![("Content-Type".into(), "a".into())],
            body: Vec::new(),
            peer: PeerInfo::default(),
        };
        assert_eq!(r.path(), "/api/v1/pods");
        assert_eq!(r.query(), "watch=true&x=1");
        assert_eq!(r.header("content-type"), Some("a"));
        assert_eq!(r.header("nope"), None);
    }
}
