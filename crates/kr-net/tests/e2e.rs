//! End-to-end tests: kr-net's executor + client against real sockets served by std threads.
//!
//! kr-rt is built with its `host` feature (see Cargo.toml) so the std test harness provides the
//! allocator, panic handler and libc. The executor is single-threaded and keeps global state, so
//! every test serialises on `LOCK`.

use kr_net::http1::{Client, Config};
use kr_net::registry::{Descriptor, Digest, Reference, Registry};
use kr_net::sha256::{hex, sha256, Sha256};
use kr_net::Error;
use kr_rt::exec::block_on;
use std::collections::HashMap;
use std::future::Future;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

static LOCK: Mutex<()> = Mutex::new(());

fn run<F: Future + 'static>(f: F) -> F::Output
where
    F::Output: 'static,
{
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    block_on(f)
}

// ---------- tiny std HTTP server ----------

#[allow(dead_code)]
struct Req {
    method: String,
    path: String,
    headers: HashMap<String, String>,
}

enum Act {
    /// Write these bytes and keep the connection open for the next request.
    Send(Vec<u8>),
    /// Write these bytes, then close.
    SendClose(Vec<u8>),
    /// Never answer.
    Hang,
}

struct Server {
    port: u16,
    conns: Arc<AtomicUsize>,
    log: Arc<Mutex<Vec<String>>>,
}

fn read_head(s: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).ok()? == 0 {
            return None;
        }
        buf.push(b[0]);
    }
    Some(buf)
}

fn start<H>(handler: H) -> Server
where
    H: Fn(&Req, u16) -> Act + Send + Sync + 'static,
{
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let conns = Arc::new(AtomicUsize::new(0));
    let log = Arc::new(Mutex::new(Vec::new()));
    let (c2, l2) = (conns.clone(), log.clone());
    let handler = Arc::new(handler);
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            c2.fetch_add(1, Ordering::SeqCst);
            let (h, log) = (handler.clone(), l2.clone());
            std::thread::spawn(move || {
                while let Some(head) = read_head(&mut s) {
                    let text = String::from_utf8_lossy(&head).into_owned();
                    let mut lines = text.split("\r\n");
                    let first = lines.next().unwrap().to_string();
                    let mut it = first.split(' ');
                    let (method, path) = (it.next().unwrap().to_string(), it.next().unwrap().to_string());
                    let headers: HashMap<String, String> = lines
                        .filter_map(|l| l.split_once(':'))
                        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
                        .collect();
                    if let Some(n) = headers.get("content-length").and_then(|v| v.parse::<usize>().ok()) {
                        let mut body = vec![0; n];
                        if s.read_exact(&mut body).is_err() {
                            return;
                        }
                    }
                    log.lock().unwrap().push(format!("{method} {path}"));
                    let req = Req { method, path, headers };
                    match h(&req, port) {
                        Act::Send(b) => {
                            if s.write_all(&b).is_err() {
                                return;
                            }
                        }
                        Act::SendClose(b) => {
                            let _ = s.write_all(&b);
                            return;
                        }
                        Act::Hang => {
                            std::thread::sleep(Duration::from_secs(30));
                            return;
                        }
                    }
                }
            });
        }
    });
    Server { port, conns, log }
}

fn resp(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut v = format!("HTTP/1.1 {status}\r\n").into_bytes();
    for (k, val) in headers {
        v.extend_from_slice(format!("{k}: {val}\r\n").as_bytes());
    }
    v.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    v.extend_from_slice(body);
    v
}

fn chunked(status: &str, headers: &[(&str, &str)], body: &[u8], chunk: usize) -> Vec<u8> {
    let mut v = format!("HTTP/1.1 {status}\r\nTransfer-Encoding: chunked\r\n").into_bytes();
    for (k, val) in headers {
        v.extend_from_slice(format!("{k}: {val}\r\n").as_bytes());
    }
    v.extend_from_slice(b"\r\n");
    for c in body.chunks(chunk) {
        v.extend_from_slice(format!("{:x};ext=1\r\n", c.len()).as_bytes());
        v.extend_from_slice(c);
        v.extend_from_slice(b"\r\n");
    }
    v.extend_from_slice(b"0\r\nX-Trailer: ignored\r\n\r\n");
    v
}

fn fast_cfg() -> Config {
    Config { connect_timeout_ms: 2000, head_timeout_ms: 5000, read_timeout_ms: 5000, ..Config::default() }
}

fn client() -> Client {
    Client::with_connector(kr_net::http1::TcpConnector::default(), fast_cfg())
}

// ---------- HTTP client behaviour ----------

#[test]
fn keepalive_chunked_and_streaming() {
    let body: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    let b2 = body.clone();
    let srv = start(move |r, _| match r.path.as_str() {
        "/cl" => Act::Send(resp("200 OK", &[("Content-Type", "x/y")], &b2)),
        "/chunked" => Act::Send(chunked("200 OK", &[], &b2, 4096)),
        "/empty" => Act::Send(resp("204 No Content", &[], b"")),
        _ => Act::Send(resp("404 Not Found", &[], b"nope")),
    });
    let port = srv.port;
    let want = body.clone();
    run(async move {
        let c = client();
        for path in ["cl", "chunked", "empty", "cl", "missing"] {
            let mut r = c.get(&format!("http://127.0.0.1:{port}/{path}"), &[]).await.unwrap();
            match path {
                "cl" => {
                    assert_eq!((r.status, r.header("content-type")), (200, Some("x/y")));
                    assert_eq!(r.content_length(), Some(100_000));
                    // stream through a small buffer
                    let mut got = Vec::new();
                    let mut buf = [0u8; 777];
                    loop {
                        let n = r.read_chunk(&mut buf).await.unwrap();
                        if n == 0 {
                            break;
                        }
                        got.extend_from_slice(&buf[..n]);
                    }
                    assert_eq!(got, want);
                }
                "chunked" => assert_eq!(r.read_to_end(1 << 20).await.unwrap(), want),
                "empty" => assert_eq!((r.status, r.read_to_end(10).await.unwrap().len()), (204, 0)),
                _ => assert_eq!((r.status, r.read_to_end(10).await.unwrap()), (404, b"nope".to_vec())),
            }
        }
        // body size limits are enforced
        let mut r = c.get(&format!("http://127.0.0.1:{port}/cl"), &[]).await.unwrap();
        assert_eq!(r.read_to_end(1000).await, Err(Error::TooLarge("body")));
    });
    // all six requests reused a single keep-alive connection
    assert_eq!(srv.conns.load(Ordering::SeqCst), 1);
}

#[test]
fn stale_keepalive_connection_is_retried() {
    let srv = start(|_, _| Act::SendClose(resp("200 OK", &[], b"hi")));
    let port = srv.port;
    run(async move {
        let c = client();
        for _ in 0..3 {
            let mut r = c.get(&format!("http://127.0.0.1:{port}/"), &[]).await.unwrap();
            assert_eq!(r.read_to_end(10).await.unwrap(), b"hi");
            // give the server thread time to close its side
            kr_rt::exec::sleep(30).await;
        }
    });
    assert_eq!(srv.conns.load(Ordering::SeqCst), 3);
}

#[test]
fn redirects() {
    let srv = start(|r, port| match r.path.as_str() {
        "/a" => Act::Send(resp("302 Found", &[("Location", "/b")], b"")),
        "/b" => Act::Send(resp("301 Moved", &[("Location", "c/d?x=1")], b"moved")),
        "/c/d" | "/c/d?x=1" => Act::Send(resp("200 OK", &[], b"end")),
        "/loop" => Act::Send(resp("302 Found", &[("Location", "/loop")], b"")),
        "/five/0" | "/five/1" | "/five/2" | "/five/3" | "/five/4" => {
            let n: u32 = r.path[6..].parse().unwrap();
            Act::Send(resp("307 Temporary Redirect", &[("Location", &format!("/five/{}", n + 1))], b""))
        }
        "/five/5" => Act::Send(resp("200 OK", &[], b"five")),
        "/auth" => Act::Send(resp("302 Found", &[("Location", &format!("http://localhost:{port}/echo"))], b"")),
        "/echo" => {
            let has = r.headers.contains_key("authorization");
            Act::Send(resp("200 OK", &[], if has { b"auth" } else { b"noauth" }))
        }
        "/https" => Act::Send(resp("302 Found", &[("Location", "https://127.0.0.1/x")], b"")),
        "/nolocation" => Act::Send(resp("302 Found", &[], b"x")),
        _ => Act::Send(resp("404 Not Found", &[], b"")),
    });
    let port = srv.port;
    run(async move {
        let c = client();
        let u = |p: &str| format!("http://127.0.0.1:{port}{p}");
        let mut r = c.get(&u("/a"), &[]).await.unwrap();
        assert_eq!(r.read_to_end(10).await.unwrap(), b"end");
        let mut r = c.get(&u("/five/0"), &[]).await.unwrap();
        assert_eq!(r.read_to_end(10).await.unwrap(), b"five");
        assert_eq!(c.get(&u("/five/1"), &[]).await.map(|_| ()), Ok(()));
        assert_eq!(c.get(&u("/loop"), &[]).await.map(|_| ()), Err(Error::TooManyRedirects));
        assert_eq!(c.get(&u("/https"), &[]).await.map(|_| ()), Err(Error::RedirectScheme));
        // 302 without Location is just returned
        assert_eq!(c.get(&u("/nolocation"), &[]).await.unwrap().status, 302);
        // Authorization is stripped when the redirect changes origin (127.0.0.1 -> localhost)
        let mut r = c.get(&u("/auth"), &[("Authorization", "Bearer s3cret")]).await.unwrap();
        assert_eq!(r.read_to_end(10).await.unwrap(), b"noauth");
    });
}

#[test]
fn hostile_responses_are_rejected() {
    let srv = start(|r, _| match r.path.as_str() {
        "/smuggle" => Act::SendClose(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".to_vec()),
        "/dupcl" => Act::SendClose(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabc".to_vec()),
        "/fold" => Act::SendClose(b"HTTP/1.1 200 OK\r\nX: a\r\n b\r\nContent-Length: 0\r\n\r\n".to_vec()),
        "/barelf" => Act::SendClose(b"HTTP/1.1 200 OK\nContent-Length: 0\n\n".to_vec()),
        "/hugehdr" => {
            let mut v = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
            v.extend(std::iter::repeat_n(b'a', 20_000));
            v.extend_from_slice(b"\r\n\r\n");
            Act::SendClose(v)
        }
        "/badchunk" => Act::SendClose(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n".to_vec()),
        "/trunc" => Act::SendClose(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc".to_vec()),
        "/truncchunk" => Act::SendClose(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab".to_vec()),
        "/closedelim" => Act::SendClose(b"HTTP/1.0 200 OK\r\n\r\nuntil close".to_vec()),
        "/interim" => Act::Send(
            [&b"HTTP/1.1 100 Continue\r\n\r\n"[..], &resp("200 OK", &[], b"after100")[..]].concat(),
        ),
        _ => Act::SendClose(vec![]),
    });
    let port = srv.port;
    run(async move {
        let c = client();
        let u = |p: &str| format!("http://127.0.0.1:{port}{p}");
        let err = |p: &'static str| {
            let c = &c;
            let u = u(p);
            async move {
                match c.get(&u, &[]).await {
                    Err(e) => e,
                    Ok(mut r) => r.read_to_end(1 << 20).await.unwrap_err(),
                }
            }
        };
        assert!(matches!(err("/smuggle").await, Error::Smuggling(_)));
        assert!(matches!(err("/dupcl").await, Error::Smuggling(_)));
        assert_eq!(err("/fold").await, Error::Parse("obs-fold"));
        assert_eq!(err("/barelf").await, Error::Parse("bare LF"));
        assert_eq!(err("/hugehdr").await, Error::TooLarge("line"));
        assert!(matches!(err("/badchunk").await, Error::Parse(_)));
        assert_eq!(err("/trunc").await, Error::UnexpectedEof);
        assert_eq!(err("/truncchunk").await, Error::UnexpectedEof);
        assert_eq!(err("/nothing").await, Error::UnexpectedEof);
        let mut r = c.get(&u("/closedelim"), &[]).await.unwrap();
        assert_eq!(r.read_to_end(100).await.unwrap(), b"until close");
        let mut r = c.get(&u("/interim"), &[]).await.unwrap();
        assert_eq!((r.status, r.read_to_end(100).await.unwrap()), (200, b"after100".to_vec()));
        // request-side injection attempts never reach the wire
        let url = u("/");
        assert!(c.request("GET", &url, &[("X", "a\r\nHost: evil")], b"").await.is_err());
        assert!(c.request("GET", &url, &[("Content-Length", "5")], b"").await.is_err());
        assert!(c.request("GE T", &url, &[], b"").await.is_err());
        assert!(c.request("GET", "http://127.0.0.1/a b", &[], b"").await.is_err());
    });
}

#[test]
fn timeouts_and_connect_errors() {
    let srv = start(|_, _| Act::Hang);
    let port = srv.port;
    // a port with nothing listening
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    run(async move {
        let cfg = Config { head_timeout_ms: 200, ..fast_cfg() };
        let c = Client::with_connector(kr_net::http1::TcpConnector::default(), cfg);
        let t = kr_rt::exec::now_ms();
        assert_eq!(c.get(&format!("http://127.0.0.1:{port}/"), &[]).await.map(|_| ()), Err(Error::Timeout));
        assert!(kr_rt::exec::now_ms() - t < 3000);
        // ECONNREFUSED
        assert_eq!(c.get(&format!("http://127.0.0.1:{dead}/"), &[]).await.map(|_| ()), Err(Error::Io(kr_sys::Errno(111))));
        assert_eq!(c.get("https://127.0.0.1/", &[]).await.map(|_| ()), Err(Error::TlsUnsupported));
        assert_eq!(c.get("http://no-such-host.invalid/", &[]).await.map(|_| ()), Err(Error::Resolve));
        assert_eq!(c.get("ftp://x/", &[]).await.map(|_| ()), Err(Error::BadUrl("unsupported scheme")));
    });
}

#[test]
fn ipv6_connect() {
    let Ok(l) = TcpListener::bind("[::1]:0") else {
        eprintln!("no IPv6 loopback; skipping");
        return;
    };
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = l.accept() {
            let _ = read_head(&mut s);
            let _ = s.write_all(&resp("200 OK", &[], b"v6"));
        }
    });
    run(async move {
        let c = client();
        let mut r = c.get(&format!("http://[::1]:{port}/"), &[]).await.unwrap();
        assert_eq!(r.read_to_end(10).await.unwrap(), b"v6");
    });
}

// ---------- registry flow ----------

struct Fixture {
    layer1: Vec<u8>,
    layer2: Vec<u8>,
    config: Vec<u8>,
    manifest: Vec<u8>,
    index: Vec<u8>,
}

fn dg(b: &[u8]) -> String {
    format!("sha256:{}", hex(&sha256(b)))
}

fn fixture() -> Fixture {
    let layer1: Vec<u8> = (0..300_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    let layer2 = b"second layer".to_vec();
    let config = br#"{"architecture":"amd64","os":"linux","config":{"Cmd":["sh"]}}"#.to_vec();
    let manifest = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{{"mediaType":"application/vnd.docker.container.image.v1+json","digest":"{}","size":{}}},"layers":[{{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","digest":"{}","size":{}}},{{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","digest":"{}","size":{}}}]}}"#,
        dg(&config), config.len(), dg(&layer1), layer1.len(), dg(&layer2), layer2.len()
    )
    .into_bytes();
    // the other-arch manifest is deliberately broken (config digest 0) so picking it would fail
    let other = format!(
        r#"{{"schemaVersion":2,"config":{{"mediaType":"a","digest":"sha256:{}","size":1}},"layers":[]}}"#,
        "0".repeat(64)
    )
    .into_bytes();
    let (mine, theirs) = if cfg!(target_arch = "aarch64") { ("arm64", "amd64") } else { ("amd64", "arm64") };
    let index = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[
        {{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{}","size":{},"platform":{{"architecture":"{theirs}","os":"linux"}}}},
        {{"mediaType":"application/vnd.docker.distribution.manifest.v2+json","digest":"{}","size":{},"platform":{{"architecture":"{mine}","os":"linux"}}}}]}}"#,
        dg(&other), other.len(), dg(&manifest), manifest.len()
    )
    .into_bytes();
    Fixture { layer1, layer2, config, manifest, index }
}

fn registry_server(f: Arc<Fixture>, corrupt_layer2: bool) -> Server {
    start(move |r, port| {
        let p = r.path.as_str();
        let authed = r.headers.get("authorization").map(String::as_str) == Some("Bearer tok123");
        if let Some(q) = p.strip_prefix("/token?") {
            assert_eq!(q, "service=fake%20svc&scope=repository%3Atest%2Fapp%3Apull", "token query");
            return Act::Send(resp("200 OK", &[("Content-Type", "application/json")], br#"{"token":"tok123","expires_in":300}"#));
        }
        if p == "/v2/" {
            return Act::Send(resp("200 OK", &[], b"{}"));
        }
        if !p.starts_with("/v2/test/app/") && !p.starts_with("/cdn/") {
            return Act::Send(resp("404 Not Found", &[], b""));
        }
        if !authed && p.starts_with("/v2/") {
            let ch = format!(r#"Bearer realm="http://127.0.0.1:{port}/token",service="fake svc",scope="repository:test/app:pull""#);
            return Act::Send(resp("401 Unauthorized", &[("WWW-Authenticate", &ch)], b"{}"));
        }
        let accept = r.headers.get("accept").cloned().unwrap_or_default();
        let mf = |ct: &str, b: &[u8]| {
            let d = dg(b);
            Act::Send(resp("200 OK", &[("Content-Type", ct), ("Docker-Content-Digest", &d)], b))
        };
        match p.trim_start_matches("/v2/test/app/") {
            "manifests/latest" => {
                assert!(accept.contains("application/vnd.oci.image.index.v1+json"), "{accept}");
                assert!(accept.contains("application/vnd.docker.distribution.manifest.list.v2+json"), "{accept}");
                assert!(accept.contains("application/vnd.oci.image.manifest.v1+json"), "{accept}");
                assert!(accept.contains("application/vnd.docker.distribution.manifest.v2+json"), "{accept}");
                mf("application/vnd.oci.image.index.v1+json", &f.index)
            }
            m if m == format!("manifests/{}", dg(&f.manifest)) => mf("application/vnd.docker.distribution.manifest.v2+json", &f.manifest),
            b if b == format!("blobs/{}", dg(&f.config)) => Act::Send(resp("200 OK", &[], &f.config)),
            b if b == format!("blobs/{}", dg(&f.layer1)) => Act::Send(chunked("200 OK", &[], &f.layer1, 9000)),
            b if b == format!("blobs/{}", dg(&f.layer2)) => {
                Act::Send(resp("307 Temporary Redirect", &[("Location", &format!("/cdn/{}", dg(&f.layer2)))], b""))
            }
            _ if p.starts_with("/cdn/") => {
                // the redirect target must not receive the bearer token's origin-specific state
                let mut b = f.layer2.clone();
                if corrupt_layer2 {
                    b[0] ^= 1;
                }
                Act::Send(resp("200 OK", &[], &b))
            }
            _ => Act::Send(resp("404 Not Found", &[], b"")),
        }
    })
}

/// Pulls via `reg_ref`, verifying digests; shared by the fake-server and docker tests.
async fn pull_all(reg_ref: &str) -> Result<(Vec<(Descriptor, usize, String)>, usize), Error> {
    let r = Reference::parse(reg_ref).unwrap();
    let mut reg = Registry::with_client(Client::with_connector(kr_net::http1::TcpConnector::default(), fast_cfg()));
    let image = reg.resolve(&r).await?;
    let cfg = reg.fetch_config(&r, &image).await?;
    let mut out = Vec::new();
    for l in &image.manifest.layers {
        // independent hash in the sink, to compare with the digest that pull_blob verified
        let mut h = Sha256::new();
        let mut n = 0usize;
        let mut sink = |d: &[u8]| {
            h.update(d);
            n += d.len();
            Ok(())
        };
        reg.pull_blob(&r, l, &mut sink).await?;
        out.push((l.clone(), n, format!("sha256:{}", hex(&h.finalize()))));
    }
    Ok((out, cfg.len()))
}

#[test]
fn registry_pull_with_bearer_auth_index_and_redirect() {
    let f = Arc::new(fixture());
    let srv = registry_server(f.clone(), false);
    let port = srv.port;
    let f2 = f.clone();
    run(async move {
        let (layers, cfg_len) = pull_all(&format!("127.0.0.1:{port}/test/app")).await.unwrap();
        assert_eq!(cfg_len, f2.config.len());
        assert_eq!(layers.len(), 2);
        assert_eq!(layers[0].1, f2.layer1.len());
        assert_eq!(layers[0].2, dg(&f2.layer1));
        assert_eq!(layers[0].0.digest.as_str(), dg(&f2.layer1));
        assert_eq!(layers[1].2, dg(&f2.layer2));

        // pinned by digest: skips the index entirely
        let mut reg = Registry::new();
        let r = Reference::parse(&format!("127.0.0.1:{port}/test/app@{}", dg(&f2.manifest))).unwrap();
        let img = reg.resolve(&r).await.unwrap();
        assert_eq!(img.digest.as_str(), dg(&f2.manifest));
        assert_eq!(img.manifest.layers.len(), 2);
        // wrong digest in the pin is detected
        let bad = format!("127.0.0.1:{port}/test/app@sha256:{}", "ab".repeat(32));
        let r = Reference::parse(&bad).unwrap();
        assert_eq!(reg.resolve(&r).await.map(|_| ()), Err(Error::Status(404)));
    });
    let log = srv.log.lock().unwrap().clone();
    // one anonymous token fetch per Registry instance (two instances above)
    assert_eq!(log.iter().filter(|l| l.starts_with("GET /token")).count(), 2);
    assert!(log.iter().any(|l| l.starts_with("GET /cdn/")));
}

#[test]
fn registry_detects_corruption() {
    let f = Arc::new(fixture());
    let srv = registry_server(f.clone(), true);
    let port = srv.port;
    run(async move {
        assert_eq!(pull_all(&format!("127.0.0.1:{port}/test/app")).await.map(|_| ()), Err(Error::DigestMismatch));
    });
}

#[test]
fn registry_https_needs_tls() {
    run(async {
        let mut reg = Registry::new();
        let r = Reference::parse("registry.example.invalid/x/y:1").unwrap();
        assert_eq!(reg.resolve(&r).await.map(|_| ()), Err(Error::TlsUnsupported));
        let d = Descriptor { media_type: "x".into(), digest: Digest::parse(&format!("sha512:{}", "a".repeat(128))).unwrap(), size: 1 };
        let mut v = Vec::new();
        assert_eq!(reg.pull_blob(&r, &d, &mut v).await, Err(Error::UnsupportedDigest));
    });
}

// ---------- real registry:2 (ignored; needs docker/podman + network for the first pull) ----------

fn tool_works(t: &str) -> bool {
    Command::new(t).arg("--version").output().is_ok_and(|o| o.status.success())
}

struct Cleanup(&'static str, &'static str);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = Command::new(self.0).args(["rm", "-f", self.1]).output();
    }
}

fn sh(tool: &str, args: &[&str]) -> bool {
    Command::new(tool).args(args).output().is_ok_and(|o| {
        if !o.status.success() {
            eprintln!("{tool} {args:?} failed: {}", String::from_utf8_lossy(&o.stderr));
        }
        o.status.success()
    })
}

#[test]
#[ignore = "needs docker/podman (falls back to the std fake registry when neither exists)"]
fn real_registry_busybox_roundtrip() {
    let Some(tool) = ["docker", "podman"].into_iter().find(|t| tool_works(t)) else {
        eprintln!("no container tool: exercising the std fake registry instead");
        registry_pull_with_bearer_auth_index_and_redirect();
        return;
    };
    const NAME: &str = "krnet-test-registry";
    let _ = Command::new(tool).args(["rm", "-f", NAME]).output();
    if !sh(tool, &["run", "-d", "--rm", "-p", "127.0.0.1:5000:5000", "--name", NAME, "registry:2"]) {
        eprintln!("cannot start registry:2 (offline or port 5000 busy); skipping");
        return;
    }
    let _guard = Cleanup(tool, NAME);
    let up = (0..100).any(|_| {
        std::thread::sleep(Duration::from_millis(200));
        TcpStream::connect("127.0.0.1:5000").is_ok()
    });
    assert!(up, "registry did not come up");
    if !sh(tool, &["pull", "busybox"]) {
        eprintln!("cannot pull busybox (offline?); skipping");
        return;
    }
    let target = "localhost:5000/busybox:krnet";
    assert!(sh(tool, &["tag", "busybox", target]));
    let mut push = vec!["push"];
    if tool == "podman" {
        push.push("--tls-verify=false");
    }
    push.push(target);
    assert!(sh(tool, &push));

    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (layers, cfg_len) = block_on(pull_all("localhost:5000/busybox:krnet")).unwrap();
    assert!(cfg_len > 0 && !layers.is_empty());
    for (d, n, got) in &layers {
        assert_eq!(*n as u64, d.size);
        assert_eq!(got, d.digest.as_str());
    }
    eprintln!("pulled {} layer(s), {} bytes", layers.len(), layers.iter().map(|l| l.1).sum::<usize>());
}
