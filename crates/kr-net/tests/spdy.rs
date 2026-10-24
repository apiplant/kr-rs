//! SPDY/3.1 end to end over real loopback sockets: the server side is `kr_net::spdy::Session`
//! driven from an upgraded HTTP connection, once tunneled in binary WebSocket messages
//! (`SPDY/3.1+portforward.k8s.io`, KEP-4006) and once as a direct `Upgrade: SPDY/3.1`. The
//! clients are hand-written on std threads. The direct test replays header blocks compressed by
//! a real zlib (python, SPDY dictionary); the other uses our stored-block encoder.

use kr_net::http1::server::{listen, local_addr, serve, Body, Handler, HandlerFuture, Request, Response, ServerConfig};
use kr_net::http1::upgrade::{Conn, UpgradeFuture};
use kr_net::http1::websocket::{handshake, Message, WebSocket, WsConfig};
use kr_net::http1::Transport;
use kr_net::spdy::{self, parse_frame, status, write_control, write_data, Event, Frame, HeaderDecoder, HeaderEncoder, Session};
use kr_rt::exec::{block_on, sleep, spawn};
use std::future::Future;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::{mpsc, Mutex};
use std::time::Duration;

static LOCK: Mutex<()> = Mutex::new(());

const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const MASK: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
const TUNNEL: &str = "SPDY/3.1+portforward.k8s.io";

// python: compressobj(9, DEFLATED, 15, 9, 0, SPDY_DICT) + Z_SYNC_FLUSH per block.
const Z1: &str = "78f9e3c6a7c202253a703a2b294a4dcc851625aca9a0808614cb45e01c6061606100a4398b20d198094ade8c0600000000ffff";
const Z2: &str = "c2aa19540e2512d60b000000ffff";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

// ---------- server ----------

/// Replies to every stream, echoes data upper-cased, mirrors FIN, and tells the client
/// about resets with a marker so tests can observe them.
fn serve_session(s: &mut Session) -> bool {
    while let Some(ev) = s.poll_event() {
        match ev {
            Event::StreamOpened { id, headers, fin } => {
                if headers.iter().any(|(k, v)| k == "streamtype" && v == "refuse") {
                    s.reset_with(id, status::REFUSED_STREAM);
                    continue;
                }
                s.reply(id, &[]);
                if fin {
                    s.data(id, b"", true);
                }
            }
            Event::Data { id, bytes, fin } => {
                s.data(id, &bytes.to_ascii_uppercase(), fin);
                s.consume(id, bytes.len());
            }
            Event::Reset { .. } => {}
            Event::GoAway { .. } => return false,
        }
    }
    true
}

async fn run_ws(c: Box<dyn Conn>) {
    let mut ws = WebSocket::new(c, WsConfig::default());
    let mut s = Session::new();
    loop {
        match ws.recv().await {
            Ok(Message::Binary(b)) => {
                if s.feed(&b).is_err() {
                    let _ = ws.send_binary(&s.take_output()).await;
                    return;
                }
            }
            Ok(Message::Text(_)) => {}
            _ => return,
        }
        let keep = serve_session(&mut s);
        if s.has_output() {
            let _ = ws.send_binary(&s.take_output()).await;
        }
        if !keep {
            let _ = ws.close(1000, "").await;
            return;
        }
    }
}

async fn run_raw(mut c: Box<dyn Conn>) {
    let mut s = Session::new();
    let mut buf = vec![0u8; 8192];
    loop {
        let Ok(n) = c.read(&mut buf).await else { return };
        if n == 0 {
            return;
        }
        let r = s.feed(&buf[..n]);
        let keep = serve_session(&mut s);
        if s.has_output() {
            let _ = c.write_all(&s.take_output()).await;
        }
        if r.is_err() || !keep {
            return;
        }
    }
}

fn handler() -> Rc<dyn Handler> {
    Rc::new(move |req: Request| -> HandlerFuture {
        let resp = if req.header("upgrade").is_some_and(|u| u.eq_ignore_ascii_case("SPDY/3.1")) {
            Response {
                status: 101,
                headers: vec![("Upgrade".into(), "SPDY/3.1".into()), ("X-Stream-Protocol-Version".into(), "portforward.k8s.io".into())],
                body: Body::Upgrade(Box::new(|c: Box<dyn Conn>| -> UpgradeFuture { Box::pin(run_raw(c)) })),
            }
        } else {
            match handshake(&req, &[TUNNEL]) {
                Ok(h) => {
                    assert_eq!(h.protocol.as_deref(), Some(TUNNEL));
                    h.into_response(Box::new(|c: Box<dyn Conn>| -> UpgradeFuture { Box::pin(run_ws(c)) }))
                }
                Err(r) => r,
            }
        };
        Box::pin(async move { resp }) as Pin<Box<dyn Future<Output = Response>>>
    })
}

fn with_server<T, C>(client: C) -> T
where
    T: Send + 'static,
    C: FnOnce(u16) -> T + Send + 'static,
{
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    block_on(async move {
        let l = listen([127, 0, 0, 1], 0, 128).unwrap();
        let port = local_addr(&l).unwrap().1;
        let cfg = ServerConfig { idle_timeout_ms: 5_000, head_timeout_ms: 2_000, ..ServerConfig::default() };
        let srv = spawn(serve(l, Rc::new(cfg), handler()));
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

// ---------- client ----------

fn masked_binary(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x82];
    match payload.len() {
        n if n < 126 => v.push(0x80 | n as u8),
        n if n <= 0xFFFF => {
            v.push(0x80 | 126);
            v.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            v.push(0x80 | 127);
            v.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    v.extend_from_slice(&MASK);
    v.extend(payload.iter().enumerate().map(|(i, b)| b ^ MASK[i & 3]));
    v
}

/// A SPDY client over either transport; `read_frame` yields owned frames.
struct Client {
    s: TcpStream,
    ws: bool,
    /// Raw bytes from the socket (WebSocket frames or SPDY bytes).
    raw: Vec<u8>,
    /// SPDY bytes after WebSocket unwrapping.
    spdy: Vec<u8>,
    dec: HeaderDecoder,
}

#[derive(Debug, PartialEq)]
enum Got {
    Reply(u32, Vec<(String, String)>),
    Data(u32, u8, Vec<u8>),
    Rst(u32, u32),
    WindowUpdate(u32, u32),
    GoAway(u32),
    Ping(u32),
}

impl Client {
    fn connect(port: u16, ws: bool) -> Client {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let req = if ws {
            format!("GET /portforward HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {TUNNEL}\r\n\r\n")
        } else {
            "POST /portforward HTTP/1.1\r\nHost: x\r\nUpgrade: SPDY/3.1\r\nConnection: Upgrade\r\nX-Stream-Protocol-Version: portforward.k8s.io\r\n\r\n".to_string()
        };
        s.write_all(req.as_bytes()).unwrap();
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            assert_eq!(s.read(&mut b).unwrap(), 1);
            head.push(b[0]);
        }
        let head = String::from_utf8(head).unwrap();
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        if ws {
            assert!(head.contains("Sec-WebSocket-Protocol: SPDY/3.1+portforward.k8s.io"), "{head}");
        } else {
            assert!(head.contains("Upgrade: SPDY/3.1"), "{head}");
        }
        Client { s, ws, raw: Vec::new(), spdy: Vec::new(), dec: HeaderDecoder::new() }
    }

    fn send(&mut self, bytes: &[u8]) {
        if self.ws {
            self.s.write_all(&masked_binary(bytes)).unwrap();
        } else {
            self.s.write_all(bytes).unwrap();
        }
    }

    fn fill(&mut self) -> bool {
        let mut tmp = [0u8; 16384];
        match self.s.read(&mut tmp) {
            Ok(0) => false,
            Ok(n) => {
                if self.ws {
                    self.raw.extend_from_slice(&tmp[..n]);
                    // Unwrap complete (unmasked, binary) server messages.
                    loop {
                        if self.raw.len() < 2 {
                            break;
                        }
                        assert_eq!(self.raw[1] & 0x80, 0);
                        let (len, hl) = match self.raw[1] & 0x7f {
                            126 if self.raw.len() >= 4 => (u16::from_be_bytes([self.raw[2], self.raw[3]]) as usize, 4),
                            127 if self.raw.len() >= 10 => (u64::from_be_bytes(self.raw[2..10].try_into().unwrap()) as usize, 10),
                            126 | 127 => break,
                            n => (n as usize, 2),
                        };
                        if self.raw.len() < hl + len {
                            break;
                        }
                        match self.raw[0] & 0x0f {
                            2 => self.spdy.extend_from_slice(&self.raw[hl..hl + len]),
                            8 => {} // close
                            op => panic!("unexpected opcode {op}"),
                        }
                        self.raw.drain(..hl + len);
                    }
                } else {
                    self.spdy.extend_from_slice(&tmp[..n]);
                }
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => false,
            Err(e) => panic!("read: {e}"),
        }
    }

    /// Next SPDY frame, or `None` at EOF.
    fn recv(&mut self) -> Option<Got> {
        loop {
            if let Some((f, n)) = parse_frame(&self.spdy).unwrap() {
                let got = match f {
                    Frame::Data { stream, flags, data } => Got::Data(stream, flags, data.to_vec()),
                    Frame::Control { ty, payload, .. } => {
                        let id = u32::from_be_bytes(payload[..4].try_into().unwrap());
                        match ty {
                            spdy::SYN_REPLY => Got::Reply(id, self.dec.decode(&payload[4..]).unwrap()),
                            spdy::RST_STREAM => Got::Rst(id, u32::from_be_bytes(payload[4..8].try_into().unwrap())),
                            spdy::WINDOW_UPDATE => Got::WindowUpdate(id, u32::from_be_bytes(payload[4..8].try_into().unwrap())),
                            spdy::GOAWAY => Got::GoAway(u32::from_be_bytes(payload[4..8].try_into().unwrap())),
                            spdy::PING => Got::Ping(id),
                            t => panic!("unexpected control type {t}"),
                        }
                    }
                };
                self.spdy.drain(..n);
                return Some(got);
            }
            if !self.fill() {
                return None;
            }
        }
    }

    fn syn_stream(&mut self, id: u32, block: &[u8]) {
        let mut p = id.to_be_bytes().to_vec();
        p.extend_from_slice(&[0; 6]);
        p.extend_from_slice(block);
        let mut out = Vec::new();
        write_control(&mut out, spdy::SYN_STREAM, 0, &p);
        self.send(&out);
    }

    fn data(&mut self, id: u32, flags: u8, d: &[u8]) {
        let mut out = Vec::new();
        write_data(&mut out, id, flags, d);
        self.send(&out);
    }

    fn window_update(&mut self, id: u32, delta: u32) {
        let mut out = Vec::new();
        write_control(&mut out, spdy::WINDOW_UPDATE, 0, &[&id.to_be_bytes()[..], &delta.to_be_bytes()[..]].concat());
        self.send(&out);
    }
}

/// The scenario shared by both transports; `open` sends the two SYN_STREAMs (ids 1, 3).
fn scenario(port: u16, ws: bool, open: impl FnOnce(&mut Client)) {
    let mut c = Client::connect(port, ws);
    open(&mut c);
    // SYN_REPLY for the error stream, then the data stream.
    assert_eq!(c.recv(), Some(Got::Reply(1, vec![])));
    assert_eq!(c.recv(), Some(Got::Reply(3, vec![])));

    // A PING is echoed.
    let mut p = Vec::new();
    write_control(&mut p, spdy::PING, 0, &1u32.to_be_bytes());
    c.send(&p);
    assert_eq!(c.recv(), Some(Got::Ping(1)));

    // 300 KB through flow control in both directions (window 64 KiB, so this needs updates).
    let total = 300_000usize;
    let payload: Vec<u8> = (0..total).map(|i| b'a' + (i % 26) as u8).collect();
    let (mut sent, mut window, mut echoed) = (0usize, 65536usize, Vec::new());
    while echoed.len() < total {
        while window > 0 && sent < total {
            let n = window.min(9000).min(total - sent);
            c.data(3, 0, &payload[sent..sent + n]);
            sent += n;
            window -= n;
        }
        match c.recv().expect("server closed early") {
            Got::WindowUpdate(3, d) => window += d as usize,
            Got::Data(3, flags, d) => {
                assert_eq!(flags, 0);
                if !d.is_empty() {
                    c.window_update(3, d.len() as u32);
                }
                echoed.extend_from_slice(&d);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(echoed, payload.to_ascii_uppercase());

    // Half-close: FIN is mirrored.
    c.data(3, spdy::FLAG_FIN, b"");
    loop {
        match c.recv() {
            Some(Got::Data(3, fl, d)) => {
                assert!(d.is_empty());
                assert_eq!(fl, spdy::FLAG_FIN);
                break;
            }
            Some(Got::WindowUpdate(..)) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    // The error stream is reset; reusing its id is not an error.
    let mut r = Vec::new();
    write_control(&mut r, spdy::RST_STREAM, 0, &[&1u32.to_be_bytes()[..], &status::CANCEL.to_be_bytes()[..]].concat());
    c.send(&r);
    c.data(1, 0, b"late");
    assert_eq!(c.recv(), Some(Got::Rst(1, status::INVALID_STREAM)));

    // GOAWAY ends the session.
    let mut g = Vec::new();
    write_control(&mut g, spdy::GOAWAY, 0, &[0u8; 8]);
    c.send(&g);
    while c.recv().is_some() {}
}

#[test]
fn websocket_tunnel() {
    with_server(|port| {
        scenario(port, true, |c| {
            let mut e = HeaderEncoder::new();
            for (id, ty) in [(1, "error"), (3, "data")] {
                let b = e.encode(&[("streamtype", ty), ("port", "8080"), ("requestid", "0")]);
                c.syn_stream(id, &b);
            }
        });
    });
}

#[test]
fn direct_upgrade_with_real_zlib_blocks() {
    with_server(|port| {
        scenario(port, false, |c| {
            c.syn_stream(1, &unhex(Z1));
            c.syn_stream(3, &unhex(Z2));
        });
    });
}

#[test]
fn refused_stream_and_protocol_error() {
    with_server(|port| {
        let mut c = Client::connect(port, true);
        let mut e = HeaderEncoder::new();
        c.syn_stream(1, &e.encode(&[("streamtype", "refuse")]));
        assert_eq!(c.recv(), Some(Got::Rst(1, status::REFUSED_STREAM)));
        // A stream with a garbage header block kills the connection with GOAWAY.
        c.syn_stream(3, b"garbage");
        assert_eq!(c.recv(), Some(Got::GoAway(status::PROTOCOL_ERROR)));
    });
}
