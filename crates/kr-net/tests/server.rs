//! HTTP/1.1 server tests: the executor serves real loopback sockets, std threads are the clients.
//!
//! kr-rt is built with its `host` feature (see Cargo.toml). The executor keeps global state, so
//! every test serialises on `LOCK`.

use kr_crypto::tls::{ClientAuth, ClientConfig, ServerConfig as TlsServerConfig};
use kr_crypto::x509::{self, CertParams, Name, SigningKey};
use kr_net::http1::server::{listen, local_addr, serve, Body, Handler, PeerInfo, Request, Response, ResponseStream, ServerConfig};
use kr_net::http1::Transport;
use kr_net::tcp::{connect_addr, IpAddr, SocketAddr};
use kr_net::tls::TlsStream;
use kr_rt::exec::{block_on, sleep, spawn, Sleep};
use std::future::Future;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

static LOCK: Mutex<()> = Mutex::new(());

// ---------- harness ----------

/// Wraps a synchronous function as a handler.
fn sync_handler<F: Fn(Request) -> Response + 'static>(f: F) -> Rc<dyn Handler> {
    Rc::new(move |req: Request| -> Pin<Box<dyn Future<Output = Response>>> {
        let r = f(req);
        Box::pin(async move { r })
    })
}

/// Serves on an ephemeral loopback port while `client(port)` runs on a std thread.
fn with_server<T, C>(cfg: ServerConfig, mk: impl FnOnce() -> Rc<dyn Handler> + 'static, client: C) -> T
where
    T: Send + 'static,
    C: FnOnce(u16) -> T + Send + 'static,
{
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    block_on(async move {
        let l = listen([127, 0, 0, 1], 0, 128).unwrap();
        let port = local_addr(&l).unwrap().1;
        let srv = spawn(serve(l, Rc::new(cfg), mk()));
        let (tx, rx) = mpsc::channel();
        let th = std::thread::spawn(move || {
            let _ = tx.send(client(port));
        });
        let r = loop {
            match rx.try_recv() {
                Ok(r) => break r,
                Err(mpsc::TryRecvError::Empty) => sleep(2).await,
                Err(mpsc::TryRecvError::Disconnected) => {
                    th.join().expect("client thread panicked");
                    panic!("client vanished");
                }
            }
        };
        srv.abort();
        r
    })
}

fn cfg() -> ServerConfig {
    ServerConfig { idle_timeout_ms: 5_000, head_timeout_ms: 2_000, ..ServerConfig::default() }
}

fn connect(port: u16) -> TcpStream {
    let s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

#[derive(Debug)]
struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Resp {
    fn header(&self, n: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.as_str())
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

fn read_line(r: &mut impl BufRead) -> Option<String> {
    let mut l = String::new();
    if r.read_line(&mut l).ok()? == 0 {
        return None;
    }
    Some(l.trim_end_matches("\r\n").to_string())
}

fn read_resp_head(r: &mut impl BufRead) -> Option<Resp> {
    let status_line = read_line(r)?;
    let status: u16 = status_line.split(' ').nth(1)?.parse().ok()?;
    let mut headers = Vec::new();
    loop {
        let l = read_line(r)?;
        if l.is_empty() {
            break;
        }
        let (k, v) = l.split_once(':').unwrap();
        headers.push((k.to_string(), v.trim().to_string()));
    }
    Some(Resp { status, headers, body: Vec::new() })
}

/// Reads one response; `head_only` for replies to HEAD.
fn read_resp(r: &mut impl BufRead, head_only: bool) -> Option<Resp> {
    let mut resp = read_resp_head(r)?;
    if head_only || resp.status == 204 || resp.status == 304 {
        return Some(resp);
    }
    if resp.header("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        loop {
            let n = usize::from_str_radix(read_line(r)?.trim(), 16).unwrap();
            let mut data = vec![0; n];
            r.read_exact(&mut data).unwrap();
            assert_eq!(read_line(r)?, "");
            if n == 0 {
                break;
            }
            resp.body.extend(data);
        }
    } else if let Some(n) = resp.header("content-length") {
        resp.body = vec![0; n.parse().unwrap()];
        r.read_exact(&mut resp.body).unwrap();
    } else {
        r.read_to_end(&mut resp.body).unwrap();
    }
    Some(resp)
}

/// Sends raw bytes, then reads until the server closes.
fn raw_exchange(port: u16, bytes: &[u8]) -> Vec<u8> {
    let mut s = connect(port);
    s.write_all(bytes).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out); // a reset after the response still leaves what we got
    out
}

fn status_of(raw: &[u8]) -> u16 {
    std::str::from_utf8(&raw[..raw.len().min(12)]).unwrap().split(' ').nth(1).unwrap().parse().unwrap()
}

fn echo() -> Rc<dyn Handler> {
    sync_handler(|req| {
        let body = format!("{} {} {}:{}", req.method, req.target, req.body.len(), String::from_utf8_lossy(&req.body));
        Response::new(200, body.into_bytes())
    })
}

// ---------- streaming helper ----------

struct Ticker {
    n: u32,
    max: u32,
    delay: u64,
    sleep: Option<Pin<Box<Sleep>>>,
    drops: Arc<AtomicUsize>,
}

impl ResponseStream for Ticker {
    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<Vec<u8>>> {
        if self.sleep.is_none() {
            if self.n >= self.max {
                return Poll::Ready(None);
            }
            self.sleep = Some(Box::pin(sleep(self.delay)));
        }
        match self.sleep.as_mut().unwrap().as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => {
                self.sleep = None;
                self.n += 1;
                Poll::Ready(Some(format!("{{\"n\":{}}}\n", self.n).into_bytes()))
            }
        }
    }
}

impl Drop for Ticker {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

fn ticker_handler(max: u32, delay: u64, drops: Arc<AtomicUsize>) -> Rc<dyn Handler> {
    sync_handler(move |req| {
        if req.path() == "/watch" {
            let t = Ticker { n: 0, max, delay, sleep: None, drops: drops.clone() };
            Response { status: 200, headers: vec![("Content-Type".into(), "application/json".into())], body: Body::Stream(Box::new(t)) }
        } else {
            Response::new(200, b"plain".to_vec())
        }
    })
}

// ---------- tests ----------

#[test]
fn get_and_post_bodies() {
    with_server(cfg(), echo, |port| {
        let mut s = connect(port);
        let mut r = BufReader::new(s.try_clone().unwrap());
        s.write_all(b"GET /a/b?x=1 HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
        let g = read_resp(&mut r, false).unwrap();
        assert_eq!((g.status, g.text().as_str()), (200, "GET /a/b?x=1 0:"));
        assert!(g.header("date").unwrap().ends_with(" GMT"));
        assert_eq!(g.header("content-length"), Some("15"));

        s.write_all(b"POST /p HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\n\r\nhello").unwrap();
        assert_eq!(read_resp(&mut r, false).unwrap().text(), "POST /p 5:hello");

        s.write_all(b"POST /c HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n4;ext=1\r\ndefg\r\n0\r\n\r\n").unwrap();
        assert_eq!(read_resp(&mut r, false).unwrap().text(), "POST /c 7:abcdefg");
    });
}

#[test]
fn keep_alive_many_requests_one_connection() {
    with_server(cfg(), echo, |port| {
        let mut s = connect(port);
        let mut r = BufReader::new(s.try_clone().unwrap());
        for i in 0..5 {
            s.write_all(format!("GET /{i} HTTP/1.1\r\nHost: t\r\n\r\n").as_bytes()).unwrap();
            let resp = read_resp(&mut r, false).unwrap();
            assert_eq!(resp.text(), format!("GET /{i} 0:"));
            assert_eq!(resp.header("connection"), None, "keep-alive is the default");
        }
        // Connection: close is honoured and echoed.
        s.write_all(b"GET /z HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n").unwrap();
        let resp = read_resp(&mut r, false).unwrap();
        assert_eq!(resp.header("connection"), Some("close"));
        let mut rest = Vec::new();
        r.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty(), "closed after Connection: close");
    });
}

#[test]
fn pipelined_requests_answered_in_order() {
    with_server(cfg(), echo, |port| {
        let mut s = connect(port);
        let mut reqs = Vec::new();
        for i in 0..4 {
            reqs.extend_from_slice(format!("POST /{i} HTTP/1.1\r\nHost: t\r\nContent-Length: 1\r\n\r\n{i}").as_bytes());
        }
        reqs.extend_from_slice(b"GET /last HTTP/1.1\r\nHost: t\r\n\r\n");
        s.write_all(&reqs).unwrap();
        let mut r = BufReader::new(s);
        for i in 0..4 {
            assert_eq!(read_resp(&mut r, false).unwrap().text(), format!("POST /{i} 1:{i}"));
        }
        assert_eq!(read_resp(&mut r, false).unwrap().text(), "GET /last 0:");
    });
}

#[test]
fn oversized_body_is_413() {
    let c = ServerConfig { max_body: 16, ..cfg() };
    with_server(c, echo, |port| {
        // Declared length too large: refused without reading the body.
        let raw = raw_exchange(port, b"POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 100\r\n\r\n0123456789");
        assert_eq!(status_of(&raw), 413);
        assert!(String::from_utf8_lossy(&raw).contains("Connection: close"));
        // Chunked: discovered while decoding.
        let raw = raw_exchange(
            port,
            b"POST / HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n0123456789abcdef\r\n10\r\n0123456789abcdef\r\n0\r\n\r\n",
        );
        assert_eq!(status_of(&raw), 413);
        // Exactly at the limit is fine.
        let mut s = connect(port);
        s.write_all(b"POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 16\r\n\r\n0123456789abcdef").unwrap();
        let mut r = BufReader::new(s);
        assert_eq!(read_resp(&mut r, false).unwrap().status, 200);
    });
}

#[test]
fn smuggling_and_malformed_requests_get_4xx() {
    with_server(cfg(), echo, |port| {
        let cases: Vec<(&str, &[u8], u16)> = vec![
            ("CL+TE", b"POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 400),
            ("dup CL", b"POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\nabcde", 400),
            ("obs-fold", b"GET / HTTP/1.1\r\nHost: t\r\nX-A: b\r\n  folded\r\n\r\n", 400),
            ("bare LF", b"GET / HTTP/1.1\nHost: t\n\n", 400),
            ("no Host", b"GET / HTTP/1.1\r\n\r\n", 400),
            ("space before colon", b"GET / HTTP/1.1\r\nHost : t\r\n\r\n", 400),
            ("bad chunk", b"POST / HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", 400),
            ("TE gzip", b"POST / HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", 501),
            ("TE identity", b"POST / HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: identity\r\n\r\n", 501),
            ("h2 prior knowledge", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 505),
            ("HTTP/3", b"GET / HTTP/3.0\r\nHost: t\r\n\r\n", 505),
        ];
        for (name, bytes, want) in cases {
            let raw = raw_exchange(port, bytes);
            assert_eq!(status_of(&raw), want, "{name}: {}", String::from_utf8_lossy(&raw));
            assert!(String::from_utf8_lossy(&raw).contains("Connection: close"), "{name}");
        }
        // 431: header block over max_head.
        let mut big = b"GET / HTTP/1.1\r\nHost: t\r\n".to_vec();
        for i in 0..2000 {
            big.extend_from_slice(format!("X-{i}: {}\r\n", "a".repeat(40)).as_bytes());
        }
        big.extend_from_slice(b"\r\n");
        let raw = raw_exchange(port, &big);
        assert_eq!(status_of(&raw), 431);
    });
}

#[test]
fn smuggled_second_request_is_never_processed() {
    // The CL+TE request must not leak its tail as a second request.
    let seen = Arc::new(AtomicUsize::new(0));
    let s2 = seen.clone();
    let mk = move || {
        sync_handler(move |_| {
            s2.fetch_add(1, Ordering::SeqCst);
            Response::new(200, vec![])
        })
    };
    with_server(cfg(), mk, |port| {
        let raw = raw_exchange(
            port,
            b"POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 30\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: t\r\n\r\n",
        );
        assert_eq!(status_of(&raw), 400);
    });
    assert_eq!(seen.load(Ordering::SeqCst), 0);
}

#[test]
fn header_injection_in_response_is_not_emitted() {
    let mk = || {
        sync_handler(|_| Response {
            status: 200,
            headers: vec![
                ("X-Evil".into(), "a\r\nSet-Cookie: pwn=1".into()),
                ("X-Evil2".into(), "a\nb".into()),
                ("Bad\r\nName".into(), "v".into()),
                ("Bad Name".into(), "v".into()),
                ("".into(), "v".into()),
                ("Content-Length".into(), "999".into()),
                ("Transfer-Encoding".into(), "chunked".into()),
                ("X-Ok".into(), "1".into()),
            ],
            body: Body::Full(b"body".to_vec()),
        })
    };
    with_server(cfg(), mk, |port| {
        let raw = raw_exchange(port, b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
        let text = String::from_utf8_lossy(&raw).into_owned();
        assert!(!text.contains("Set-Cookie"), "{text}");
        assert!(!text.contains("Evil"), "{text}");
        assert!(!text.contains("Bad"), "{text}");
        assert!(!text.contains("999") && !text.contains("chunked"), "{text}");
        assert!(text.contains("X-Ok: 1\r\n") && text.contains("Content-Length: 4\r\n"), "{text}");
        let mut r = BufReader::new(&raw[..]);
        let resp = read_resp(&mut r, false).unwrap();
        assert_eq!((resp.status, resp.text().as_str()), (200, "body"));
    });
}

#[test]
fn streaming_response_arrives_incrementally() {
    let drops = Arc::new(AtomicUsize::new(0));
    let d2 = drops.clone();
    with_server(cfg(), move || ticker_handler(3, 150, d2), move |port| {
        let mut s = connect(port);
        let mut r = BufReader::new(s.try_clone().unwrap());
        let t0 = Instant::now();
        s.write_all(b"GET /watch HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
        let head = read_resp_head(&mut r).unwrap();
        assert_eq!(head.header("transfer-encoding"), Some("chunked"));
        assert_eq!(head.header("content-length"), None);
        // Head is flushed before the first chunk exists.
        assert!(t0.elapsed() < Duration::from_millis(120), "head must not wait for data");
        let mut times = Vec::new();
        for i in 1..=3 {
            let n = usize::from_str_radix(&read_line(&mut r).unwrap(), 16).unwrap();
            let mut data = vec![0; n + 2];
            r.read_exact(&mut data).unwrap();
            assert_eq!(String::from_utf8_lossy(&data), format!("{{\"n\":{i}}}\n\r\n"));
            times.push(t0.elapsed());
        }
        assert_eq!(read_line(&mut r).unwrap(), "0");
        assert_eq!(read_line(&mut r).unwrap(), "");
        for w in times.windows(2) {
            assert!(w[1] - w[0] >= Duration::from_millis(100), "chunks must arrive one by one: {times:?}");
        }
        // The connection stays usable after the stream ended.
        s.write_all(b"GET /other HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
        assert_eq!(read_resp(&mut r, false).unwrap().text(), "plain");
        assert_eq!(drops.load(Ordering::SeqCst), 1, "finished stream is dropped");
    });
}

#[test]
fn stream_is_dropped_when_client_disconnects() {
    let drops = Arc::new(AtomicUsize::new(0));
    let d2 = drops.clone();
    with_server(cfg(), move || ticker_handler(u32::MAX, 20, d2), move |port| {
        let mut s = connect(port);
        let mut r = BufReader::new(s.try_clone().unwrap());
        s.write_all(b"GET /watch HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
        read_resp_head(&mut r).unwrap();
        let n = usize::from_str_radix(&read_line(&mut r).unwrap(), 16).unwrap();
        let mut data = vec![0; n + 2];
        r.read_exact(&mut data).unwrap();
        assert_eq!(drops.load(Ordering::SeqCst), 0, "stream alive while the client reads");
        drop(r);
        let _ = s.shutdown(Shutdown::Both);
        drop(s);
        let t0 = Instant::now();
        while drops.load(Ordering::SeqCst) == 0 {
            assert!(t0.elapsed() < Duration::from_secs(3), "stream leaked after disconnect");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn head_has_no_body() {
    with_server(cfg(), || sync_handler(|_| Response::new(200, b"hello".to_vec())), |port| {
        let mut s = connect(port);
        let mut r = BufReader::new(s.try_clone().unwrap());
        s.write_all(b"HEAD /x HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
        let h = read_resp(&mut r, true).unwrap();
        assert_eq!((h.status, h.header("content-length")), (200, Some("5")));
        // If body bytes had followed the head, this second response would be corrupt.
        s.write_all(b"GET /x HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
        assert_eq!(read_resp(&mut r, false).unwrap().text(), "hello");
    });
}

#[test]
fn head_on_stream_and_204_send_no_body() {
    let drops = Arc::new(AtomicUsize::new(0));
    let d2 = drops.clone();
    let mk = move || {
        let inner = ticker_handler(3, 10, d2);
        sync_handler(move |req| {
            if req.path() == "/none" {
                Response::new(204, b"ignored".to_vec())
            } else {
                futures_now(inner.handle(req))
            }
        })
    };
    with_server(cfg(), mk, move |port| {
        let mut s = connect(port);
        let mut r = BufReader::new(s.try_clone().unwrap());
        s.write_all(b"HEAD /watch HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
        let h = read_resp(&mut r, true).unwrap();
        assert_eq!(h.header("transfer-encoding"), None);
        s.write_all(b"GET /none HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
        let n = read_resp(&mut r, false).unwrap();
        assert_eq!((n.status, n.header("content-length")), (204, None));
        s.write_all(b"GET /other HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
        assert_eq!(read_resp(&mut r, false).unwrap().text(), "plain");
        assert_eq!(drops.load(Ordering::SeqCst), 1, "unsent stream dropped");
    });
}

/// Polls an immediately-ready handler future once.
fn futures_now<T>(mut f: Pin<Box<dyn Future<Output = T>>>) -> T {
    let w = std::task::Waker::noop();
    match f.as_mut().poll(&mut Context::from_waker(w)) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("handler not ready"),
    }
}

#[test]
fn expect_100_continue() {
    let c = ServerConfig { max_body: 8, ..cfg() };
    with_server(c, echo, |port| {
        let mut s = connect(port);
        let mut r = BufReader::new(s.try_clone().unwrap());
        s.write_all(b"POST /u HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n").unwrap();
        // The interim response must come before we send any body.
        assert_eq!(read_line(&mut r).unwrap(), "HTTP/1.1 100 Continue");
        assert_eq!(read_line(&mut r).unwrap(), "");
        s.write_all(b"data").unwrap();
        assert_eq!(read_resp(&mut r, false).unwrap().text(), "POST /u 4:data");
        // Too large: refused with 413 and no 100.
        let raw = raw_exchange(port, b"POST /u HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\nContent-Length: 400\r\n\r\n");
        assert_eq!(status_of(&raw), 413);
        // Unknown expectation.
        let raw = raw_exchange(port, b"POST /u HTTP/1.1\r\nHost: t\r\nExpect: magic\r\nContent-Length: 1\r\n\r\n");
        assert_eq!(status_of(&raw), 417);
    });
}

#[test]
fn timeouts_and_connection_cap() {
    let c = ServerConfig { idle_timeout_ms: 300, head_timeout_ms: 300, body_timeout_ms: 300, max_connections: 2, ..cfg() };
    with_server(c, echo, |port| {
        // Slow head -> 408.
        let mut s = connect(port);
        s.write_all(b"GET / HTT").unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        assert_eq!(status_of(&out), 408);
        drop(s); // an open socket would keep the server's lingering close (and its slot) busy
        // Stalled body -> 408.
        let mut s = connect(port);
        s.write_all(b"POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 10\r\n\r\nabc").unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        assert_eq!(status_of(&out), 408);
        drop(s);
        // Idle keep-alive connection is closed silently.
        let mut s = connect(port);
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        assert!(out.is_empty());

        // Connection cap: two held connections fill it, the third is closed at once.
        let mut a = connect(port);
        let b = connect(port);
        std::thread::sleep(Duration::from_millis(100));
        let mut c3 = connect(port);
        let _ = c3.write_all(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n");
        let mut out = Vec::new();
        let _ = c3.read_to_end(&mut out);
        assert!(out.is_empty(), "over-cap connection must be closed without service");
        // Held ones still work.
        a.write_all(b"GET /a HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
        assert_eq!(read_resp(&mut BufReader::new(a.try_clone().unwrap()), false).unwrap().status, 200);
        drop(b);
        drop(a);
        // Slots are released.
        std::thread::sleep(Duration::from_millis(150));
        let mut d = connect(port);
        d.write_all(b"GET /d HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
        assert_eq!(read_resp(&mut BufReader::new(d), false).unwrap().status, 200);
    });
}

#[test]
fn http10_close_delimited_stream_and_keepalive_header() {
    let drops = Arc::new(AtomicUsize::new(0));
    let d2 = drops.clone();
    with_server(cfg(), move || ticker_handler(2, 10, d2), |port| {
        let raw = raw_exchange(port, b"GET /watch HTTP/1.0\r\n\r\n");
        let text = String::from_utf8_lossy(&raw).into_owned();
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert!(!text.contains("chunked") && text.contains("Connection: close"), "{text}");
        assert!(text.ends_with("{\"n\":1}\n{\"n\":2}\n"), "{text}");
    });
}

// ---------- TLS ----------

fn key(seed: u8) -> SigningKey {
    SigningKey::Ed25519(kr_crypto::ed25519::SigningKey::from_seed(&[seed; 32]))
}

fn cert(cn: &str, serial: u8, subject_key: &SigningKey, ca: bool, server: bool, client: bool, issuer: (&Name, &SigningKey)) -> Vec<u8> {
    let p = CertParams {
        serial: [serial; 16],
        subject: Name { common_name: cn.into(), organizations: if client { vec!["system:masters".into()] } else { vec![] } },
        not_before: 1_000_000_000,
        not_after: 4_000_000_000,
        is_ca: ca,
        server,
        client,
        dns_names: if server { vec!["localhost".into()] } else { vec![] },
        ip_addrs: vec![],
        public_key: subject_key.public(),
    };
    x509::issue(&p, issuer.0, issuer.1)
}

async fn tls_get(port: u16, cfg: ClientConfig) -> String {
    let sock = connect_addr(SocketAddr { ip: IpAddr::V4([127, 0, 0, 1]), port }, 2000).await.unwrap();
    let mut t = TlsStream::connect(sock, Rc::new(cfg), "localhost").await.unwrap();
    t.write_all(b"GET /who?q=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match t.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    String::from_utf8(out).unwrap()
}

fn who(peer: &PeerInfo) -> String {
    let (n, cn) = match &peer.client_certs {
        Some(c) => {
            let cert = x509::Certificate::parse(&c[0]).unwrap();
            (c.len(), String::from_utf8_lossy(cert.common_name().unwrap()).into_owned())
        }
        None => (0, "-".into()),
    };
    format!("tls={} certs={n} cn={cn} alpn={}", peer.tls, peer.alpn.as_deref().map_or("-".into(), |a| String::from_utf8_lossy(a).into_owned()))
}

#[test]
fn tls_serves_requests_and_exposes_client_certs() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ca_key = key(1);
    let ca_name = Name { common_name: "test-ca".into(), organizations: vec![] };
    let ca = cert("test-ca", 1, &ca_key, true, false, false, (&ca_name, &ca_key));
    let srv_cert = cert("localhost", 2, &key(2), false, true, false, (&ca_name, &ca_key));
    let cli_cert = cert("alice", 3, &key(3), false, false, true, (&ca_name, &ca_key));

    let mk_tls = |auth: ClientAuth| {
        Rc::new(TlsServerConfig { cert_chain: vec![srv_cert.clone()], key: key(2), client_auth: auth, alpn: vec![b"http/1.1".to_vec()] })
    };
    let client_cfg = |with_cert: bool| ClientConfig {
        pinned_ca: None,
        roots: vec![ca.clone()],
        client_cert: with_cert.then(|| (vec![cli_cert.clone()], key(3))),
        alpn: vec![b"http/1.1".to_vec()],
        tls12: false,
    };
    let handler = || sync_handler(|req| Response::new(200, format!("{} {} {}", req.path(), req.query(), who(&req.peer)).into_bytes()));

    // Optional client auth: with and without a certificate.
    let (tls_a, tls_b) = (mk_tls(ClientAuth::Optional(vec![ca.clone()])), mk_tls(ClientAuth::Required(vec![ca.clone()])));
    let (cc_with, cc_without, cc_with2) = (client_cfg(true), client_cfg(false), client_cfg(true));
    let (r1, r2, r3) = block_on(async move {
        let mut results = Vec::new();
        for (tls, cc_list) in [(tls_a, vec![cc_with, cc_without]), (tls_b, vec![cc_with2])] {
            let l = listen([127, 0, 0, 1], 0, 16).unwrap();
            let port = local_addr(&l).unwrap().1;
            let c = ServerConfig { tls: Some(tls), ..cfg() };
            let srv = spawn(serve(l, Rc::new(c), handler()));
            for cc in cc_list {
                results.push(tls_get(port, cc).await);
            }
            srv.abort();
        }
        let mut it = results.into_iter();
        (it.next().unwrap(), it.next().unwrap(), it.next().unwrap())
    });
    assert!(r1.starts_with("HTTP/1.1 200"), "{r1}");
    assert!(r1.ends_with("/who q=1 tls=true certs=1 cn=alice alpn=http/1.1"), "{r1}");
    assert!(r2.ends_with("/who q=1 tls=true certs=0 cn=- alpn=http/1.1"), "{r2}");
    assert!(r3.ends_with("tls=true certs=1 cn=alice alpn=http/1.1"), "{r3}");
}

#[test]
fn tls_failed_handshake_just_closes() {
    let ca_key = key(1);
    let ca_name = Name { common_name: "test-ca".into(), organizations: vec![] };
    let srv_cert = cert("localhost", 2, &key(2), false, true, false, (&ca_name, &ca_key));
    let tls = Rc::new(TlsServerConfig { cert_chain: vec![srv_cert], key: key(2), client_auth: ClientAuth::None, alpn: vec![] });
    let c = ServerConfig { tls: Some(tls), ..cfg() };
    with_server(c, echo, |port| {
        // Plaintext HTTP to a TLS port: closed, nothing useful sent back.
        let mut s = connect(port);
        let _ = s.write_all(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n");
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        assert!(!String::from_utf8_lossy(&out).contains("HTTP/1.1 200"));
    });
}
