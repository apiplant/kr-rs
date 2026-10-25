//! WebSocket server tests over real loopback sockets. The server runs on the executor; the
//! clients are hand-written (masking frames themselves) on std threads, plus one async client
//! over TLS. The executor keeps global state, so every test serialises on `LOCK`.

use kr_crypto::tls::{ClientAuth, ClientConfig, ServerConfig as TlsServerConfig};
use kr_crypto::x509::{self, CertParams, Name, SigningKey};
use kr_net::http1::channel::{self, ClientMsg, Protocol, EXEC_PROTOCOLS};
use kr_net::http1::server::{listen, local_addr, serve, Handler, HandlerFuture, Request, Response, ServerConfig};
use kr_net::http1::upgrade::{Conn, UpgradeFuture};
use kr_net::http1::websocket::{handshake, Message, WebSocket, WsConfig};
use kr_net::http1::Transport;
use kr_net::tcp::{connect_addr, IpAddr, SocketAddr};
use kr_net::tls::TlsStream;
use kr_rt::exec::{block_on, sleep, spawn};
use std::future::poll_fn;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::{mpsc, Mutex};
use std::task::Poll;
use std::time::Duration;

static LOCK: Mutex<()> = Mutex::new(());

const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
const MASK: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

// ---------- server side ----------

async fn echo(c: Box<dyn Conn>, cfg: WsConfig) {
    let mut ws = WebSocket::new(c, cfg);
    loop {
        let ok = match ws.recv().await {
            Ok(Message::Text(t)) => ws.send_text(&t).await.is_ok(),
            Ok(Message::Binary(b)) => ws.send_binary(&b).await.is_ok(),
            Ok(Message::Close { .. }) | Err(_) => false,
        };
        if !ok {
            break;
        }
    }
}

/// exec-like: stdin -> upper-cased stdout, resize -> stderr note, v5 close of stdin -> status.
async fn exec(c: Box<dyn Conn>, proto: Protocol) {
    let mut ws = WebSocket::new(c, WsConfig::default());
    while let Ok(m) = ws.recv().await {
        let Message::Binary(b) = m else { break };
        match channel::decode_client(proto, &b) {
            Ok(ClientMsg::Stdin(d)) => {
                if d == b"exit\n" {
                    let _ = ws.send_binary(&channel::error_frame(&channel::status_exit(3))).await;
                    let _ = ws.close(1000, "").await;
                    break;
                }
                let _ = ws.send_binary(&channel::stdout_frame(&d.to_ascii_uppercase())).await;
            }
            Ok(ClientMsg::Resize(s)) => {
                let _ = ws.send_binary(&channel::stderr_frame(format!("size {}x{}", s.width, s.height).as_bytes())).await;
            }
            Ok(ClientMsg::CloseStream(0)) => {
                let _ = ws.send_binary(&channel::error_frame(&channel::status_success())).await;
                let _ = ws.close(1000, "").await;
                break;
            }
            _ => {}
        }
    }
}

/// Selects reads against timer-driven writes through `poll_recv` / `poll_flush`.
async fn ticker(c: Box<dyn Conn>) {
    let mut ws = WebSocket::new(c, WsConfig::default());
    let mut timer = Box::pin(sleep(20));
    loop {
        let ev = poll_fn(|cx| {
            if timer.as_mut().poll(cx).is_ready() {
                return Poll::Ready(None);
            }
            ws.poll_recv(cx).map(Some)
        })
        .await;
        match ev {
            None => {
                ws.queue_text("tick").unwrap();
                poll_fn(|cx| ws.poll_flush(cx)).await.unwrap();
                timer = Box::pin(sleep(20));
            }
            Some(Ok(Message::Text(t))) if t == "stop" => {
                let _ = ws.close(1000, "stopped").await;
                break;
            }
            Some(Ok(_)) => {}
            Some(Err(_)) => break,
        }
    }
}

use std::future::Future;

fn handler(wscfg: WsConfig) -> Rc<dyn Handler> {
    Rc::new(move |req: Request| -> HandlerFuture {
        let resp = match req.path() {
            "/echo" => match handshake(&req, &[]) {
                Ok(h) => h.into_response(Box::new(move |c: Box<dyn Conn>| -> UpgradeFuture { Box::pin(echo(c, wscfg)) })),
                Err(r) => r,
            },
            "/exec" => match handshake(&req, &EXEC_PROTOCOLS) {
                Ok(h) => match h.protocol.as_deref().and_then(Protocol::from_token) {
                    Some(p) => h.into_response(Box::new(move |c: Box<dyn Conn>| -> UpgradeFuture { Box::pin(exec(c, p)) })),
                    None => Response::new(400, b"no subprotocol".to_vec()),
                },
                Err(r) => r,
            },
            "/tick" => match handshake(&req, &[]) {
                Ok(h) => h.into_response(Box::new(|c: Box<dyn Conn>| -> UpgradeFuture { Box::pin(ticker(c)) })),
                Err(r) => r,
            },
            _ => Response::new(404, Vec::new()),
        };
        Box::pin(async move { resp }) as Pin<Box<dyn Future<Output = Response>>>
    })
}

fn with_server<T, C>(cfg: ServerConfig, wscfg: WsConfig, client: C) -> T
where
    T: Send + 'static,
    C: FnOnce(u16) -> T + Send + 'static,
{
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    block_on(async move {
        let l = listen([127, 0, 0, 1], 0, 128).unwrap();
        let port = local_addr(&l).unwrap().1;
        let srv = spawn(serve(l, Rc::new(cfg), handler(wscfg)));
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

// ---------- client codec (pure) ----------

fn masked_frame(fin: bool, op: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![if fin { 0x80 } else { 0 } | op];
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

/// Parses one unmasked server frame from the front of `buf`.
fn parse_server_frame(buf: &mut Vec<u8>) -> Option<(bool, u8, Vec<u8>)> {
    if buf.len() < 2 {
        return None;
    }
    assert_eq!(buf[1] & 0x80, 0, "server frames must not be masked");
    let (len, hl) = match buf[1] & 0x7F {
        126 if buf.len() >= 4 => (u16::from_be_bytes([buf[2], buf[3]]) as usize, 4),
        127 if buf.len() >= 10 => (u64::from_be_bytes(buf[2..10].try_into().unwrap()) as usize, 10),
        126 | 127 => return None,
        n => (n as usize, 2),
    };
    if buf.len() < hl + len {
        return None;
    }
    let f = (buf[0] & 0x80 != 0, buf[0] & 0x0F, buf[hl..hl + len].to_vec());
    buf.drain(..hl + len);
    Some(f)
}

fn upgrade_request(path: &str, extra: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Version: 13\r\n{extra}\r\n"
    )
}

// ---------- sync client ----------

struct Client {
    s: TcpStream,
    buf: Vec<u8>,
}

impl Client {
    fn raw(port: u16, req: &[u8]) -> (String, Client) {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(req).unwrap();
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            assert_eq!(s.read(&mut b).unwrap(), 1, "eof in head: {}", String::from_utf8_lossy(&head));
            head.push(b[0]);
        }
        (String::from_utf8(head).unwrap(), Client { s, buf: Vec::new() })
    }

    fn connect(port: u16, path: &str, extra: &str) -> (String, Client) {
        Client::raw(port, upgrade_request(path, extra).as_bytes())
    }

    fn send(&mut self, fin: bool, op: u8, payload: &[u8]) {
        self.s.write_all(&masked_frame(fin, op, payload)).unwrap();
    }

    /// Next frame, or `None` at EOF.
    fn recv(&mut self) -> Option<(bool, u8, Vec<u8>)> {
        loop {
            if let Some(f) = parse_server_frame(&mut self.buf) {
                return Some(f);
            }
            let mut tmp = [0u8; 4096];
            match self.s.read(&mut tmp) {
                Ok(0) => return None,
                Ok(n) => self.buf.extend_from_slice(&tmp[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => return None,
                Err(e) => panic!("read: {e}"),
            }
        }
    }

    fn expect_close(&mut self, code: u16) {
        let (fin, op, p) = self.recv().expect("close frame");
        assert!(fin && op == 8, "op {op}");
        assert_eq!(u16::from_be_bytes([p[0], p[1]]), code);
        assert_eq!(self.recv(), None, "connection must end after close");
    }
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

// ---------- tests ----------

#[test]
fn handshake_accepts_and_rejects() {
    with_server(cfg(), WsConfig::default(), |port| {
        let (head, mut c) = Client::connect(port, "/echo", "");
        assert!(head.starts_with("HTTP/1.1 101 "), "{head}");
        assert_eq!(header(&head, "sec-websocket-accept"), Some(ACCEPT));
        assert_eq!(header(&head, "upgrade"), Some("websocket"));
        assert_eq!(header(&head, "connection"), Some("Upgrade"));
        assert_eq!(header(&head, "sec-websocket-protocol"), None);
        c.send(true, 1, b"hi");
        assert_eq!(c.recv(), Some((true, 1, b"hi".to_vec())));

        // Wrong version: 426 advertising 13, and the connection stays usable for HTTP.
        let req = upgrade_request("/echo", "").replace("Version: 13", "Version: 8");
        let (head, _) = Client::raw(port, req.as_bytes());
        assert!(head.starts_with("HTTP/1.1 426 "), "{head}");
        assert_eq!(header(&head, "sec-websocket-version"), Some("13"));

        let req = upgrade_request("/echo", "").replace(KEY, "c2hvcnQ=");
        assert!(Client::raw(port, req.as_bytes()).0.starts_with("HTTP/1.1 400 "));
        let req = upgrade_request("/echo", "").replace("Upgrade: websocket\r\n", "");
        assert!(Client::raw(port, req.as_bytes()).0.starts_with("HTTP/1.1 400 "));
        let req = upgrade_request("/echo", "").replace("GET", "POST");
        assert!(Client::raw(port, req.as_bytes()).0.starts_with("HTTP/1.1 405 "));
        let req = upgrade_request("/echo", "").replace("HTTP/1.1", "HTTP/1.0");
        assert!(Client::raw(port, req.as_bytes()).0.starts_with("HTTP/1.1 4"));
    });
}

#[test]
fn fragmented_messages_echo_as_one() {
    with_server(cfg(), WsConfig::default(), |port| {
        let (_, mut c) = Client::connect(port, "/echo", "");
        c.send(false, 1, b"Hello, ");
        c.send(false, 0, b"frag");
        c.send(true, 0, b"mented world");
        assert_eq!(c.recv(), Some((true, 1, b"Hello, fragmented world".to_vec())));
        // Large binary in three fragments, with 16- and 64-bit lengths on the wire.
        let big: Vec<u8> = (0..200_000u32).map(|i| (i * 7) as u8).collect();
        c.send(false, 2, &big[..300]);
        c.send(false, 0, &big[300..70_000]);
        c.send(true, 0, &big[70_000..]);
        let mut got = Vec::new();
        loop {
            let (fin, op, p) = c.recv().unwrap();
            assert!(op == 2 || op == 0);
            got.extend(p);
            if fin {
                break;
            }
        }
        assert_eq!(got, big);
        // Invalid UTF-8 in a text message: 1007.
        c.send(true, 1, &[0xff, 0xfe]);
        c.expect_close(1007);
    });
}

#[test]
fn ping_gets_pong_even_inside_a_fragmented_message() {
    with_server(cfg(), WsConfig::default(), |port| {
        let (_, mut c) = Client::connect(port, "/echo", "");
        c.send(true, 9, b"are you there");
        assert_eq!(c.recv(), Some((true, 10, b"are you there".to_vec())));
        c.send(false, 1, b"ab");
        c.send(true, 9, b"mid");
        c.send(true, 10, b"unsolicited pong is ignored");
        c.send(true, 0, b"cd");
        assert_eq!(c.recv(), Some((true, 10, b"mid".to_vec())));
        assert_eq!(c.recv(), Some((true, 1, b"abcd".to_vec())));
        // Oversized control payload is a protocol error.
        c.send(true, 9, &[0; 126]);
        c.expect_close(1002);
    });
}

#[test]
fn close_handshake_echoes_code_then_ends() {
    with_server(cfg(), WsConfig::default(), |port| {
        let (_, mut c) = Client::connect(port, "/echo", "");
        let mut p = 1000u16.to_be_bytes().to_vec();
        p.extend_from_slice(b"bye");
        c.send(true, 8, &p);
        c.expect_close(1000);

        let (_, mut c) = Client::connect(port, "/echo", "");
        c.send(true, 8, &[]); // no status code at all
        let (_, op, p) = c.recv().unwrap();
        assert_eq!((op, p.len()), (8, 0));
        assert_eq!(c.recv(), None);

        let (_, mut c) = Client::connect(port, "/echo", "");
        c.send(true, 8, &[0x03, 0xED]); // 1005 must not appear on the wire
        c.expect_close(1002);
    });
}

#[test]
fn oversized_message_gets_1009() {
    with_server(cfg(), WsConfig { max_message: 1024 }, |port| {
        let (_, mut c) = Client::connect(port, "/echo", "");
        c.send(true, 2, &[1; 1024]);
        assert_eq!(c.recv().unwrap().2.len(), 1024);
        c.send(true, 2, &[1; 1025]);
        c.expect_close(1009);
        // Many small fragments that add up are refused too.
        let (_, mut c) = Client::connect(port, "/echo", "");
        c.send(false, 2, &[0; 200]);
        for _ in 0..7 {
            c.send(false, 0, &[0; 200]);
        }
        c.expect_close(1009);
    });
}

#[test]
fn unmasked_client_frame_gets_1002() {
    with_server(cfg(), WsConfig::default(), |port| {
        let (_, mut c) = Client::connect(port, "/echo", "");
        c.s.write_all(&[0x81, 0x02, b'h', b'i']).unwrap();
        c.expect_close(1002);
    });
}

#[test]
fn subprotocol_prefers_v5_over_v4() {
    with_server(cfg(), WsConfig::default(), |port| {
        for (offer, want) in [
            ("v4.channel.k8s.io, v5.channel.k8s.io", Some("v5.channel.k8s.io")),
            ("v5.channel.k8s.io,v4.channel.k8s.io", Some("v5.channel.k8s.io")),
            ("v3.channel.k8s.io, v4.channel.k8s.io", Some("v4.channel.k8s.io")),
            ("channel.k8s.io", Some("channel.k8s.io")),
        ] {
            let (head, _) = Client::connect(port, "/exec", &format!("Sec-WebSocket-Protocol: {offer}\r\n"));
            assert!(head.starts_with("HTTP/1.1 101 "), "{head}");
            assert_eq!(header(&head, "sec-websocket-protocol"), want, "{offer}");
        }
        // The route above answers 400 when nothing matches.
        let (head, _) = Client::connect(port, "/exec", "Sec-WebSocket-Protocol: nope\r\n");
        assert!(head.starts_with("HTTP/1.1 400 "), "{head}");
    });
}

#[test]
fn channel_round_trip_stdin_stdout_status() {
    with_server(cfg(), WsConfig::default(), |port| {
        let (head, mut c) = Client::connect(port, "/exec", "Sec-WebSocket-Protocol: v5.channel.k8s.io, v4.channel.k8s.io\r\n");
        assert_eq!(header(&head, "sec-websocket-protocol"), Some("v5.channel.k8s.io"));
        c.send(true, 2, &channel::encode(channel::STDIN, b"hello\n"));
        assert_eq!(c.recv(), Some((true, 2, channel::encode(channel::STDOUT, b"HELLO\n"))));
        c.send(true, 2, &channel::encode(channel::RESIZE, br#"{"Width":80,"Height":24}"#));
        assert_eq!(c.recv(), Some((true, 2, channel::encode(channel::STDERR, b"size 80x24"))));
        // v5: closing stdin makes the "process" finish; status on channel 3, then close.
        c.send(true, 2, &channel::close_frame(0));
        let (_, op, p) = c.recv().unwrap();
        assert_eq!((op, p[0]), (2, channel::ERROR));
        assert_eq!(&p[1..], channel::status_success().as_bytes());
        c.expect_close(1000);

        // v4: a non-zero exit is reported as a Failure status.
        let (head, mut c) = Client::connect(port, "/exec", "Sec-WebSocket-Protocol: v4.channel.k8s.io\r\n");
        assert_eq!(header(&head, "sec-websocket-protocol"), Some("v4.channel.k8s.io"));
        c.send(true, 2, &channel::encode(channel::STDIN, b"exit\n"));
        let (_, _, p) = c.recv().unwrap();
        assert_eq!(p[0], channel::ERROR);
        let st = String::from_utf8(p[1..].to_vec()).unwrap();
        assert!(st.contains("\"reason\":\"NonZeroExitCode\"") && st.contains("\"message\":\"3\""), "{st}");
        c.expect_close(1000);
    });
}

#[test]
fn poll_api_selects_reads_against_timer_writes() {
    with_server(cfg(), WsConfig::default(), |port| {
        let (_, mut c) = Client::connect(port, "/tick", "");
        for _ in 0..3 {
            assert_eq!(c.recv(), Some((true, 1, b"tick".to_vec())));
        }
        // Messages sent while ticks are in flight are not lost.
        c.send(true, 1, b"noise");
        c.send(true, 1, b"stop");
        loop {
            let (_, op, p) = c.recv().unwrap();
            if op == 8 {
                assert_eq!(&p[..2], &1000u16.to_be_bytes());
                assert_eq!(&p[2..], b"stopped");
                break;
            }
            assert_eq!(p, b"tick");
        }
    });
}

#[test]
fn no_http_timeouts_after_upgrade_and_pipelined_frame_is_kept() {
    let c = ServerConfig { idle_timeout_ms: 150, head_timeout_ms: 150, body_timeout_ms: 150, write_timeout_ms: 150, ..cfg() };
    with_server(c, WsConfig::default(), |port| {
        // The first frame rides in the same segment as the request head.
        let mut req = upgrade_request("/echo", "").into_bytes();
        req.extend(masked_frame(true, 1, b"early"));
        let (head, mut c) = Client::raw(port, &req);
        assert!(head.starts_with("HTTP/1.1 101 "));
        assert_eq!(c.recv(), Some((true, 1, b"early".to_vec())));
        std::thread::sleep(Duration::from_millis(600));
        c.send(true, 1, b"late");
        assert_eq!(c.recv(), Some((true, 1, b"late".to_vec())));
    });
}

// ---------- TLS ----------

fn key(seed: u8) -> SigningKey {
    SigningKey::Ed25519(kr_crypto::ed25519::SigningKey::from_seed(&[seed; 32]))
}

fn cert(cn: &str, serial: u8, subject_key: &SigningKey, ca: bool, server: bool, issuer: (&Name, &SigningKey)) -> Vec<u8> {
    let p = CertParams {
        serial: [serial; 16],
        subject: Name { common_name: cn.into(), organizations: vec![] },
        not_before: 1_000_000_000,
        not_after: 4_000_000_000,
        is_ca: ca,
        server,
        client: false,
        dns_names: if server { vec!["localhost".into()] } else { vec![] },
        ip_addrs: vec![],
        public_key: subject_key.public(),
    };
    x509::issue(&p, issuer.0, issuer.1)
}

/// Reads until `buf` holds a full frame, then returns it.
async fn tls_frame(t: &mut TlsStream<kr_rt::exec::Async<kr_sys::Fd>>, buf: &mut Vec<u8>) -> Option<(bool, u8, Vec<u8>)> {
    loop {
        if let Some(f) = parse_server_frame(buf) {
            return Some(f);
        }
        let mut tmp = [0u8; 4096];
        match t.read(&mut tmp).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
}

#[test]
fn websocket_over_tls() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ca_key = key(1);
    let ca_name = Name { common_name: "test-ca".into(), organizations: vec![] };
    let ca = cert("test-ca", 1, &ca_key, true, false, (&ca_name, &ca_key));
    let srv_cert = cert("localhost", 2, &key(2), false, true, (&ca_name, &ca_key));
    let tls = Rc::new(TlsServerConfig { cert_chain: vec![srv_cert], key: key(2), client_auth: ClientAuth::None, alpn: vec![b"http/1.1".to_vec()] });
    let cc = ClientConfig { pinned_ca: None, roots: vec![ca], client_cert: None, alpn: vec![b"http/1.1".to_vec()], tls12: false };
    let out = block_on(async move {
        let l = listen([127, 0, 0, 1], 0, 16).unwrap();
        let port = local_addr(&l).unwrap().1;
        let c = ServerConfig { tls: Some(tls), ..cfg() };
        let srv = spawn(serve(l, Rc::new(c), handler(WsConfig::default())));
        let sock = connect_addr(SocketAddr { ip: IpAddr::V4([127, 0, 0, 1]), port }, 2000).await.unwrap();
        let mut t = TlsStream::connect(sock, Rc::new(cc), "localhost").await.unwrap();
        t.write_all(upgrade_request("/exec", "Sec-WebSocket-Protocol: v4.channel.k8s.io\r\n").as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let mut tmp = [0u8; 1024];
            let n = t.read(&mut tmp).await.unwrap();
            assert!(n > 0);
            buf.extend_from_slice(&tmp[..n]);
        }
        let end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let head = String::from_utf8(buf[..end].to_vec()).unwrap();
        buf.drain(..end);
        // Fragmented stdin, then exit.
        let m = channel::encode(channel::STDIN, b"tls ok\n");
        t.write_all(&masked_frame(false, 2, &m[..3])).await.unwrap();
        t.write_all(&masked_frame(true, 0, &m[3..])).await.unwrap();
        let f1 = tls_frame(&mut t, &mut buf).await;
        t.write_all(&masked_frame(true, 2, &channel::encode(channel::STDIN, b"exit\n"))).await.unwrap();
        let f2 = tls_frame(&mut t, &mut buf).await;
        let f3 = tls_frame(&mut t, &mut buf).await;
        srv.abort();
        (head, f1, f2, f3)
    });
    let (head, f1, f2, f3) = out;
    assert!(head.starts_with("HTTP/1.1 101 "), "{head}");
    assert_eq!(header(&head, "sec-websocket-accept"), Some(ACCEPT));
    assert_eq!(header(&head, "sec-websocket-protocol"), Some("v4.channel.k8s.io"));
    assert_eq!(f1, Some((true, 2, channel::encode(channel::STDOUT, b"TLS OK\n"))));
    assert_eq!(f2.as_ref().map(|f| (f.1, f.2[0])), Some((2, channel::ERROR)));
    assert_eq!(f3.map(|f| (f.1, f.2[..2].to_vec())), Some((8, 1000u16.to_be_bytes().to_vec())));
}
