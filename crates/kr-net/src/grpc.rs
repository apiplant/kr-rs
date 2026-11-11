//! A minimal gRPC layer over [`h2`](crate::h2): unary and server-streaming calls, as client and
//! server, over unix sockets (the Kubernetes device plugin API).

use crate::h2::conn::{Conn, Ev, Hdrs, Stream};
use alloc::format;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::Cell;
use core::future::Future;
use kr_rt::exec::{spawn, Async};
use kr_sys::Fd;

pub const OK: u32 = 0;
pub const CANCELLED: u32 = 1;
pub const UNKNOWN: u32 = 2;
pub const DEADLINE_EXCEEDED: u32 = 4;
pub const PERMISSION_DENIED: u32 = 7;
pub const RESOURCE_EXHAUSTED: u32 = 8;
pub const UNIMPLEMENTED: u32 = 12;
pub const INTERNAL: u32 = 13;
pub const UNAVAILABLE: u32 = 14;
pub const UNAUTHENTICATED: u32 = 16;

/// Largest accepted message payload.
pub const MAX_MESSAGE: usize = 16 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub code: u32,
    pub message: String,
}

impl Status {
    pub fn new(code: u32, message: &str) -> Status {
        Status { code, message: message.to_string() }
    }
    pub fn ok() -> Status {
        Status::new(OK, "")
    }
}

fn frame_msg(msg: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(5 + msg.len());
    v.push(0);
    v.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    v.extend_from_slice(msg);
    v
}

/// Reassembles length-prefixed messages from DATA chunks.
struct Asm {
    buf: Vec<u8>,
    pos: usize,
}

impl Asm {
    fn new() -> Asm {
        Asm { buf: Vec::new(), pos: 0 }
    }
    fn push(&mut self, d: &[u8]) {
        self.buf.extend_from_slice(d);
    }
    fn partial(&self) -> bool {
        self.pos < self.buf.len()
    }
    fn next(&mut self) -> Result<Option<Vec<u8>>, Status> {
        let b = &self.buf[self.pos..];
        if b.len() < 5 {
            return Ok(None);
        }
        match b[0] {
            0 => {}
            1 => return Err(Status::new(UNIMPLEMENTED, "compressed messages are not supported")),
            _ => return Err(Status::new(INTERNAL, "bad message flag")),
        }
        let len = u32::from_be_bytes([b[1], b[2], b[3], b[4]]) as usize;
        if len > MAX_MESSAGE {
            return Err(Status::new(RESOURCE_EXHAUSTED, "message too large"));
        }
        if b.len() < 5 + len {
            return Ok(None);
        }
        let m = b[5..5 + len].to_vec();
        self.pos += 5 + len;
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        }
        Ok(Some(m))
    }
}

fn pct_encode(s: &str) -> Vec<u8> {
    let mut o = Vec::new();
    for &c in s.as_bytes() {
        if (0x20..=0x7e).contains(&c) && c != b'%' {
            o.push(c);
        } else {
            o.extend_from_slice(format!("%{c:02X}").as_bytes());
        }
    }
    o
}

fn pct_decode(s: &[u8]) -> String {
    let mut o = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' && i + 2 < s.len() {
            let h = core::str::from_utf8(&s[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok());
            if let Some(b) = h {
                o.push(b);
                i += 3;
                continue;
            }
        }
        o.push(s[i]);
        i += 1;
    }
    String::from_utf8_lossy(&o).into_owned()
}

fn get<'a>(h: &'a Hdrs, name: &[u8]) -> Option<&'a [u8]> {
    h.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_slice())
}

fn status_headers(st: &Status, hdrs: &mut Vec<(Vec<u8>, Vec<u8>)>) {
    hdrs.push((b"grpc-status".to_vec(), st.code.to_string().into_bytes()));
    if !st.message.is_empty() {
        hdrs.push((b"grpc-message".to_vec(), pct_encode(&st.message)));
    }
}

// ---------------------------------------------------------------- server

/// Reply channel for one request.
pub struct Responder {
    stream: Rc<Stream>,
    started: Cell<bool>,
    done: Cell<bool>,
}

impl Responder {
    fn refs(h: &[(Vec<u8>, Vec<u8>)]) -> Vec<(&[u8], &[u8])> {
        h.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect()
    }

    /// Sends one response message (headers go out first time). `Err` when the client
    /// cancelled or the connection died.
    pub async fn send(&self, msg: &[u8]) -> Result<(), Status> {
        let gone = || Status::new(CANCELLED, "stream closed");
        if self.done.get() || self.stream.is_dead() {
            return Err(gone());
        }
        if !self.started.replace(true) {
            let h = [(&b":status"[..], &b"200"[..]), (b"content-type", b"application/grpc")];
            self.stream.send_headers(&h, false).map_err(|_| gone())?;
        }
        self.stream.send_data(&frame_msg(msg), false).await.map_err(|_| gone())
    }

    fn finish_now(&self, status: &Status) {
        if self.done.replace(true) {
            return;
        }
        let mut h: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        if !self.started.replace(true) {
            h.push((b":status".to_vec(), b"200".to_vec()));
            h.push((b"content-type".to_vec(), b"application/grpc".to_vec()));
        }
        status_headers(status, &mut h);
        let _ = self.stream.send_headers(&Self::refs(&h), true);
    }

    /// Sends the trailers (a trailers-only response if nothing was sent yet).
    pub async fn finish(self, status: Status) {
        self.finish_now(&status);
    }

    pub fn cancelled(&self) -> bool {
        self.stream.is_dead()
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        self.finish_now(&Status::new(UNKNOWN, "handler returned without a status"));
    }
}

async fn read_request(s: &Stream) -> Result<Vec<u8>, Status> {
    let mut asm = Asm::new();
    let mut msg = None;
    loop {
        if let Some(m) = asm.next()? {
            if msg.is_some() {
                return Err(Status::new(UNIMPLEMENTED, "only unary requests are supported"));
            }
            msg = Some(m);
            continue;
        }
        match s.recv().await {
            Ev::Headers(_) => {}
            Ev::Data(d) => asm.push(&d),
            Ev::End => {
                if asm.partial() {
                    return Err(Status::new(INTERNAL, "truncated message"));
                }
                return msg.ok_or_else(|| Status::new(INTERNAL, "missing request message"));
            }
            Ev::Reset(_) | Ev::Closed => return Err(Status::new(CANCELLED, "cancelled")),
        }
    }
}

async fn handle_request<H, F>(stream: Stream, handler: Rc<H>)
where
    H: Fn(String, Vec<u8>, Responder) -> F + 'static,
    F: Future<Output = ()> + 'static,
{
    let Ev::Headers(h) = stream.recv().await else { return };
    let stream = Rc::new(stream);
    let plain = |code: &str| {
        let hh = [(&b":status"[..], code.as_bytes())];
        let _ = stream.send_headers(&hh, true);
    };
    if get(&h, b":method") != Some(b"POST") {
        return plain("405");
    }
    if !get(&h, b"content-type").is_some_and(|c| c.starts_with(b"application/grpc")) {
        return plain("415");
    }
    let path = String::from_utf8_lossy(get(&h, b":path").unwrap_or(b"")).into_owned();
    let resp = Responder { stream: stream.clone(), started: Cell::new(false), done: Cell::new(false) };
    match read_request(&stream).await {
        Ok(msg) => handler(path, msg, resp).await,
        Err(st) => {
            if st.code != CANCELLED {
                resp.finish(st).await;
            }
        }
    }
}

/// Accepts connections on `listener` (already non-blocking) and serves requests until aborted.
pub async fn serve<H, F>(listener: Async<Fd>, handler: Rc<H>)
where
    H: Fn(String, Vec<u8>, Responder) -> F + 'static,
    F: Future<Output = ()> + 'static,
{
    loop {
        let io = match listener.accept().await {
            Ok(io) => io,
            Err(_) => {
                kr_rt::exec::sleep(100).await;
                continue;
            }
        };
        let handler = handler.clone();
        spawn(async move {
            let conn = Conn::server(io);
            while let Some(s) = conn.accept().await {
                spawn(handle_request(s, handler.clone()));
            }
        });
    }
}

// ---------------------------------------------------------------- client

pub struct Client {
    conn: Rc<Conn>,
}

pub struct Streaming {
    stream: Stream,
    asm: Asm,
    got_headers: bool,
    done: bool,
}

fn http_status(code: &[u8]) -> Status {
    let c = match code {
        b"400" => INTERNAL,
        b"401" => UNAUTHENTICATED,
        b"403" => PERMISSION_DENIED,
        b"404" => UNIMPLEMENTED,
        b"429" | b"502" | b"503" | b"504" => UNAVAILABLE,
        _ => UNKNOWN,
    };
    Status::new(c, &format!("http status {}", String::from_utf8_lossy(code)))
}

fn trailer_status(h: &Hdrs) -> Status {
    match get(h, b"grpc-status").and_then(|v| core::str::from_utf8(v).ok()).and_then(|v| v.parse::<u32>().ok()) {
        Some(code) => Status { code, message: get(h, b"grpc-message").map(pct_decode).unwrap_or_default() },
        None => Status::new(UNKNOWN, "missing grpc-status"),
    }
}

impl Streaming {
    /// Next message; `None` after OK trailers, `Some(Err)` on any failure (then `None`).
    pub async fn next(&mut self) -> Option<Result<Vec<u8>, Status>> {
        loop {
            if self.done {
                return None;
            }
            match self.asm.next() {
                Ok(Some(m)) => return Some(Ok(m)),
                Ok(None) => {}
                Err(e) => {
                    self.done = true;
                    return Some(Err(e));
                }
            }
            let fail = |s: &mut Streaming, st: Status| {
                s.done = true;
                Some(Err(st))
            };
            match self.stream.recv().await {
                Ev::Headers(h) => {
                    let first = !self.got_headers;
                    self.got_headers = true;
                    if first {
                        match get(&h, b":status") {
                            Some(b"200") => {}
                            Some(c) if get(&h, b"grpc-status").is_none() => return fail(self, http_status(c)),
                            None => return fail(self, Status::new(INTERNAL, "missing :status")),
                            _ => {}
                        }
                        if get(&h, b"grpc-status").is_none() {
                            continue;
                        }
                    }
                    self.done = true;
                    let st = trailer_status(&h);
                    if st.code == OK {
                        if self.asm.partial() {
                            return Some(Err(Status::new(INTERNAL, "truncated message")));
                        }
                        return None;
                    }
                    return Some(Err(st));
                }
                Ev::Data(d) => self.asm.push(&d),
                Ev::End => return fail(self, Status::new(INTERNAL, "stream ended without grpc-status")),
                Ev::Reset(c) => return fail(self, Status::new(if c == 8 { CANCELLED } else { UNAVAILABLE }, &format!("stream reset ({c})"))),
                Ev::Closed => return fail(self, Status::new(UNAVAILABLE, "connection closed")),
            }
        }
    }
}

impl Client {
    pub async fn connect_unix(path: &[u8]) -> Result<Client, Status> {
        let unavailable = |_| Status::new(UNAVAILABLE, "connect failed");
        let fd = kr_sys::ns::unix_connect(path).map_err(unavailable)?;
        kr_sys::ns::set_nonblocking(fd.raw()).map_err(unavailable)?;
        let io = Async::new(fd).map_err(unavailable)?;
        Ok(Client::from_io(io))
    }

    /// Wraps an already connected non-blocking socket.
    pub fn from_io(io: Async<Fd>) -> Client {
        Client { conn: Conn::client(io) }
    }

    pub fn is_closed(&self) -> bool {
        self.conn.is_closed()
    }

    async fn start(&self, method: &str, req: &[u8], timeout_ms: u64) -> Result<Streaming, Status> {
        let unavailable = |_| Status::new(UNAVAILABLE, "connection closed");
        let to = format!("{timeout_ms}m");
        let mut h: Vec<(&[u8], &[u8])> = alloc::vec![
            (b":method", b"POST"),
            (b":scheme", b"http"),
            (b":path", method.as_bytes()),
            (b":authority", b"localhost"),
            (b"content-type", b"application/grpc"),
            (b"te", b"trailers"),
            (b"user-agent", b"kr"),
        ];
        if timeout_ms > 0 {
            h.push((b"grpc-timeout", to.as_bytes()));
        }
        let stream = self.conn.open(&h, false).await.map_err(unavailable)?;
        stream.send_data(&frame_msg(req), true).await.map_err(unavailable)?;
        Ok(Streaming { stream, asm: Asm::new(), got_headers: false, done: false })
    }

    /// One request, one response. `timeout_ms == 0` means no deadline.
    pub async fn unary(&self, method: &str, req: &[u8], timeout_ms: u64) -> Result<Vec<u8>, Status> {
        let call = async {
            let mut s = self.start(method, req, timeout_ms).await?;
            let msg = match s.next().await {
                Some(r) => r?,
                None => return Err(Status::new(INTERNAL, "no response message")),
            };
            match s.next().await {
                None => Ok(msg),
                Some(Ok(_)) => Err(Status::new(INTERNAL, "multiple response messages")),
                Some(Err(e)) => Err(e),
            }
        };
        if timeout_ms == 0 {
            return call.await;
        }
        match kr_rt::exec::timeout(timeout_ms, call).await {
            Ok(r) => r,
            Err(_) => Err(Status::new(DEADLINE_EXCEEDED, "deadline exceeded")),
        }
    }

    pub async fn server_stream(&self, method: &str, req: &[u8]) -> Result<Streaming, Status> {
        self.start(method, req, 0).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use kr_rt::exec::{block_on, sleep, timeout, JoinHandle};
    use std::sync::{Mutex, MutexGuard};

    // The executor is a process-wide singleton: tests using it must not overlap.
    static LOCK: Mutex<()> = Mutex::new(());
    fn lock() -> MutexGuard<'static, ()> {
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn sock_path(name: &str) -> std::string::String {
        let p = std::env::temp_dir().join(std::format!("krg-{}-{name}.sock", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p.to_str().unwrap().into()
    }

    fn listener(path: &str) -> Async<Fd> {
        let fd = kr_sys::ns::unix_listen(path.as_bytes()).unwrap();
        kr_sys::ns::set_nonblocking(fd.raw()).unwrap();
        Async::new(fd).unwrap()
    }

    fn pair() -> (Async<Fd>, Async<Fd>) {
        let (a, b) = kr_sys::ns::socketpair().unwrap();
        kr_sys::ns::set_nonblocking(a.raw()).unwrap();
        kr_sys::ns::set_nonblocking(b.raw()).unwrap();
        (Async::new(a).unwrap(), Async::new(b).unwrap())
    }

    /// Spawns the test service; `cancels` counts handlers that observed a cancellation.
    fn start_server(path: &str, cancels: Rc<Cell<u32>>) -> JoinHandle<()> {
        let l = listener(path);
        let h = Rc::new(move |path: String, req: Vec<u8>, r: Responder| {
            let cancels = cancels.clone();
            async move {
                match path.as_str() {
                    "/t.Svc/Echo" => {
                        r.send(&req).await.unwrap();
                        r.finish(Status::ok()).await
                    }
                    "/t.Svc/Slow" => {
                        sleep(30).await;
                        r.send(&req).await.unwrap();
                        r.finish(Status::ok()).await
                    }
                    "/t.Svc/Many" => {
                        for i in 0..1000u32 {
                            if r.send(&i.to_be_bytes()).await.is_err() {
                                return;
                            }
                        }
                        r.finish(Status::ok()).await
                    }
                    "/t.Svc/Stream" => {
                        for i in 0..3u8 {
                            let mut m = req.clone();
                            m.push(i);
                            r.send(&m).await.unwrap();
                        }
                        r.finish(Status::ok()).await
                    }
                    "/t.Svc/Err" => r.finish(Status::new(5, "not found: \u{fc} 100%\n")).await,
                    "/t.Svc/NoFinish" => {}
                    "/t.Svc/Hang" | "/t.Svc/Wait" => {
                        if path.ends_with("Wait") {
                            r.send(b"first").await.unwrap();
                        }
                        while !r.cancelled() {
                            sleep(10).await;
                        }
                        cancels.set(cancels.get() + 1);
                    }
                    _ => r.finish(Status::new(UNIMPLEMENTED, "unknown method")).await,
                }
            }
        });
        spawn(serve(l, h))
    }

    fn run<F: Future<Output = ()> + 'static>(f: F) {
        block_on(async move {
            timeout(30_000, f).await.expect("test timed out");
        });
    }

    #[test]
    fn unary_stream_errors() {
        let _g = lock();
        let path = sock_path("basic");
        run(async move {
            let cancels = Rc::new(Cell::new(0));
            let srv = start_server(&path, cancels);
            let c = Client::connect_unix(path.as_bytes()).await.unwrap();
            assert_eq!(c.unary("/t.Svc/Echo", b"hello", 5000).await.unwrap(), b"hello");
            assert_eq!(c.unary("/t.Svc/Echo", b"", 0).await.unwrap(), b"");
            let e = c.unary("/t.Svc/Err", b"", 5000).await.unwrap_err();
            assert_eq!(e, Status::new(5, "not found: \u{fc} 100%\n"));
            assert_eq!(c.unary("/t.Svc/Nope", b"", 5000).await.unwrap_err().code, UNIMPLEMENTED);
            assert_eq!(c.unary("/t.Svc/NoFinish", b"", 5000).await.unwrap_err().code, UNKNOWN);
            let mut s = c.server_stream("/t.Svc/Many", b"").await.unwrap();
            let mut n = 0u32;
            while let Some(m) = s.next().await {
                assert_eq!(m.unwrap(), n.to_be_bytes());
                n += 1;
            }
            assert_eq!(n, 1000);
            assert!(s.next().await.is_none());
            let mut s = c.server_stream("/t.Svc/Stream", b"x").await.unwrap();
            assert_eq!(s.next().await.unwrap().unwrap(), b"x\0");
            srv.abort();
        });
    }

    #[test]
    fn large_and_concurrent() {
        let _g = lock();
        let path = sock_path("big");
        run(async move {
            let srv = start_server(&path, Rc::new(Cell::new(0)));
            let c = Rc::new(Client::connect_unix(path.as_bytes()).await.unwrap());
            let big: Vec<u8> = (0..3 << 20).map(|i| (i * 7 + i / 251) as u8).collect();
            assert!(c.unary("/t.Svc/Echo", &big, 20_000).await.unwrap() == big);
            // 250 concurrent calls: more than the 100-stream limit, so some wait their turn.
            let hs: Vec<_> = (0..250u32)
                .map(|i| {
                    let c = c.clone();
                    spawn(async move { c.unary("/t.Svc/Slow", &i.to_be_bytes(), 20_000).await.unwrap() == i.to_be_bytes() })
                })
                .collect();
            for h in hs {
                assert!(h.await.unwrap());
            }
            srv.abort();
        });
    }

    #[test]
    fn timeout_and_cancel() {
        let _g = lock();
        let path = sock_path("cancel");
        run(async move {
            let cancels = Rc::new(Cell::new(0));
            let srv = start_server(&path, cancels.clone());
            let c = Client::connect_unix(path.as_bytes()).await.unwrap();
            let e = c.unary("/t.Svc/Hang", b"", 100).await.unwrap_err();
            assert_eq!(e.code, DEADLINE_EXCEEDED);
            let mut s = c.server_stream("/t.Svc/Wait", b"").await.unwrap();
            assert_eq!(s.next().await.unwrap().unwrap(), b"first");
            drop(s);
            for _ in 0..100 {
                if cancels.get() == 2 {
                    break;
                }
                sleep(10).await;
            }
            assert_eq!(cancels.get(), 2);
            // the connection is still usable
            assert_eq!(c.unary("/t.Svc/Echo", b"y", 5000).await.unwrap(), b"y");
            srv.abort();
        });
    }

    #[test]
    fn connection_drop_mid_stream() {
        let _g = lock();
        run(async {
            let (a, b) = pair();
            let c = Client::from_io(a);
            let srv = Conn::server(b);
            let call = spawn(async move {
                let mut s = c.server_stream("/x", b"").await.unwrap();
                assert_eq!(s.next().await.unwrap().unwrap(), b"one");
                let e = s.next().await.unwrap().unwrap_err();
                assert_eq!(e.code, UNAVAILABLE);
                assert!(s.next().await.is_none());
                assert!(c.unary("/x", b"", 1000).await.is_err());
                assert!(c.is_closed());
            });
            let st = srv.accept().await.unwrap();
            let h = [(&b":status"[..], &b"200"[..])];
            st.send_headers(&h, false).unwrap();
            st.send_data(&frame_msg(b"one"), false).await.unwrap();
            sleep(50).await;
            drop(st);
            drop(srv);
            call.await.unwrap();
        });
    }

    #[test]
    fn trailers_only_and_compressed() {
        let _g = lock();
        run(async {
            let (a, b) = pair();
            let c = Client::from_io(a);
            let srv = Conn::server(b);
            let t = spawn(async move {
                let st = srv.accept().await.unwrap();
                let h = [(&b":status"[..], &b"200"[..]), (b"grpc-status", b"12"), (b"grpc-message", b"no%20way")];
                st.send_headers(&h, true).unwrap();
                let st = srv.accept().await.unwrap();
                let h = [(&b":status"[..], &b"200"[..])];
                st.send_headers(&h, false).unwrap();
                st.send_data(&[1, 0, 0, 0, 0], true).await.unwrap();
                sleep(100).await;
            });
            let e = c.unary("/a", b"", 2000).await.unwrap_err();
            assert_eq!(e, Status::new(12, "no way"));
            let e = c.unary("/a", b"", 2000).await.unwrap_err();
            assert_eq!(e.code, UNIMPLEMENTED);
            t.await.unwrap();
        });
    }

    fn xorshift(s: &mut u64) -> u64 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        *s
    }

    #[test]
    fn garbage_never_panics() {
        let _g = lock();
        run(async {
            let mut seed = 0x9e3779b97f4a7c15u64;
            for it in 0..300 {
                let (a, b) = pair();
                let srv = Conn::server(b);
                let mut data = Vec::new();
                data.extend_from_slice(crate::h2::frame::PREFACE);
                let n = 1 + xorshift(&mut seed) % 40;
                for _ in 0..n {
                    if it % 2 == 0 {
                        // random bytes
                        for _ in 0..(xorshift(&mut seed) % 64) {
                            data.push(xorshift(&mut seed) as u8);
                        }
                    } else {
                        // well-formed frame headers with random type/flags/stream/payload
                        let len = (xorshift(&mut seed) % 40) as usize;
                        let ty = (xorshift(&mut seed) % 12) as u8;
                        let sid = (xorshift(&mut seed) % 5) as u32;
                        data.extend_from_slice(&[0, 0, len as u8, ty, xorshift(&mut seed) as u8]);
                        data.extend_from_slice(&sid.to_be_bytes());
                        for _ in 0..len {
                            data.push(xorshift(&mut seed) as u8);
                        }
                    }
                }
                let _ = a.write_all(&data).await;
                for _ in 0..5 {
                    kr_rt::exec::yield_now().await;
                }
                while let Ok(Some(_)) = timeout(1, srv.accept()).await {}
                drop(srv);
            }
        });
    }

    fn have_grpc() -> bool {
        std::process::Command::new("python3")
            .args(["-c", "import grpc"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn script(name: &str) -> std::string::String {
        std::format!("{}/tests-data/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn interop_python_server() {
        if !have_grpc() {
            return;
        }
        let _g = lock();
        let path = sock_path("pysrv");
        let mut child = std::process::Command::new("python3").args([&script("grpc_server.py"), path.as_str()]).spawn().unwrap();
        for _ in 0..100 {
            if std::path::Path::new(&path).exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        run(async move {
            let c = Client::connect_unix(path.as_bytes()).await.unwrap();
            assert_eq!(c.unary("/t.Svc/Echo", b"hello", 10_000).await.unwrap(), b"hello");
            let big: Vec<u8> = (0..3 << 20).map(|i| (i * 7 + i / 251) as u8).collect();
            assert!(c.unary("/t.Svc/Echo", &big, 20_000).await.unwrap() == big);
            let mut s = c.server_stream("/t.Svc/Stream", b"ab").await.unwrap();
            for i in 0..3u8 {
                assert_eq!(s.next().await.unwrap().unwrap(), vec![b'a', b'b', i]);
            }
            assert!(s.next().await.is_none());
            let e = c.unary("/t.Svc/Err", b"", 10_000).await.unwrap_err();
            assert_eq!(e, Status::new(5, "nope \u{fc} 100%"));
            assert_eq!(c.unary("/t.Svc/Missing", b"", 10_000).await.unwrap_err().code, UNIMPLEMENTED);
        });
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn interop_python_client() {
        if !have_grpc() {
            return;
        }
        let _g = lock();
        let path = sock_path("pycli");
        run(async move {
            let srv = start_server(&path, Rc::new(Cell::new(0)));
            let mut child = std::process::Command::new("python3")
                .args([&script("grpc_client.py"), path.as_str()])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let status = loop {
                if let Some(s) = child.try_wait().unwrap() {
                    break s;
                }
                sleep(10).await;
            };
            let mut out = std::string::String::new();
            let mut err = std::string::String::new();
            use std::io::Read;
            child.stdout.take().unwrap().read_to_string(&mut out).unwrap();
            child.stderr.take().unwrap().read_to_string(&mut err).unwrap();
            assert!(status.success() && out.contains("CLIENT-OK"), "python client failed: {out} {err}");
            srv.abort();
        });
    }
}
