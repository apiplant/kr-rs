//! TLS 1.3 interop against the `openssl` CLI (and curl), over real loopback sockets.
//! Skipped when `openssl` is not installed.
use kr_crypto::tls::{ClientAuth, ClientConfig, Connection, ServerConfig};
use kr_crypto::x509::{self, CertParams, Name, SigningKey};
use kr_crypto::{ed25519, p256};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn rng(buf: &mut [u8]) {
    let mut f = std::fs::File::open("/dev/urandom").unwrap();
    f.read_exact(buf).unwrap();
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn have_openssl() -> bool {
    Command::new("openssl").arg("version").output().is_ok()
}

struct Files {
    dir: std::path::PathBuf,
    ca: Vec<u8>,
    srv_cert: Vec<u8>,
    srv_key: SigningKey,
    cli_cert: Vec<u8>,
    cli_key: SigningKey,
}

fn setup(tag: &str, ed_server: bool) -> Files {
    let dir = std::env::temp_dir().join(format!("kr-tls-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let t = now();
    let mut seed = [0u8; 32];
    rng(&mut seed);
    let ca_key = SigningKey::P256(p256::SecretKey::from_bytes(&[(seed[0] & 0x7f) | 1; 32]).unwrap());
    let ca_name = Name { common_name: "kr-test-ca".into(), organizations: vec![] };
    let p = |name: &Name, pk, ca, server, client| CertParams {
        serial: seed[..16].try_into().unwrap(),
        subject: name.clone(),
        not_before: t - 60,
        not_after: t + 3600,
        is_ca: ca,
        server,
        client,
        dns_names: vec!["localhost".into()],
        ip_addrs: vec![vec![127, 0, 0, 1]],
        public_key: pk,
    };
    let ca = x509::issue(&p(&ca_name, ca_key.public(), true, false, false), &ca_name, &ca_key);
    let srv_key = if ed_server { SigningKey::Ed25519(ed25519::SigningKey::from_seed(&seed)) } else { SigningKey::P256(p256::SecretKey::from_bytes(&[(seed[1] & 0x7f) | 1; 32]).unwrap()) };
    let srv_name = Name { common_name: "localhost".into(), organizations: vec![] };
    let srv_cert = x509::issue(&p(&srv_name, srv_key.public(), false, true, false), &ca_name, &ca_key);
    let cli_key = SigningKey::P256(p256::SecretKey::from_bytes(&[(seed[2] & 0x7f) | 1; 32]).unwrap());
    let cli_name = Name { common_name: "alice".into(), organizations: vec!["system:masters".into()] };
    let cli_cert = x509::issue(&p(&cli_name, cli_key.public(), false, false, true), &ca_name, &ca_key);
    for (f, label, der) in [("ca.pem", "CERTIFICATE", &ca), ("srv.pem", "CERTIFICATE", &srv_cert), ("cli.pem", "CERTIFICATE", &cli_cert)] {
        std::fs::write(dir.join(f), x509::pem_encode(label, der)).unwrap();
    }
    std::fs::write(dir.join("srv.key"), x509::pem_encode("PRIVATE KEY", &x509::private_key_to_pkcs8(&srv_key))).unwrap();
    std::fs::write(dir.join("cli.key"), x509::pem_encode("PRIVATE KEY", &x509::private_key_to_pkcs8(&cli_key))).unwrap();
    Files { dir, ca, srv_cert, srv_key, cli_cert, cli_key }
}

/// Drives a kr Connection over a blocking socket until `done` returns true.
fn drive(conn: &mut Connection, sock: &mut TcpStream, mut done: impl FnMut(&mut Connection) -> bool) {
    sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut buf = [0u8; 16384];
    loop {
        let out = conn.take_output();
        if !out.is_empty() {
            sock.write_all(&out).unwrap();
        }
        if done(conn) {
            return;
        }
        let n = sock.read(&mut buf).expect("socket read");
        if n == 0 {
            return;
        }
        if let Err(e) = conn.feed(&buf[..n]) {
            let out = conn.take_output();
            let _ = sock.write_all(&out);
            panic!("tls error: {e:?}");
        }
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn kr_client_vs_s_server(tag: &str, extra: &[&str], ed_server: bool, expect_suite: u16) {
    let f = setup(tag, ed_server);
    let port = free_port();
    let mut srv = Command::new("openssl")
        .args(["s_server", "-quiet", "-tls1_3", "-accept", &port.to_string(), "-naccept", "1"])
        .arg("-cert").arg(f.dir.join("srv.pem")).arg("-key").arg(f.dir.join("srv.key"))
        .arg("-Verify").arg("1").arg("-CAfile").arg(f.dir.join("ca.pem"))
        .args(["-alpn", "http/1.1"])
        .args(extra)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().unwrap();
    let mut sock = (0..100).find_map(|_| { std::thread::sleep(Duration::from_millis(30)); TcpStream::connect(("127.0.0.1", port)).ok() }).expect("connect");
    let cfg = Rc::new(ClientConfig { pinned_ca: None, roots: vec![f.ca.clone()], client_cert: Some((vec![f.cli_cert.clone()], f.cli_key)), alpn: vec![b"http/1.1".to_vec()], tls12: false });
    let mut c = Connection::client(cfg, b"localhost", rng, now());
    drive(&mut c, &mut sock, |c| !c.is_handshaking());
    assert_eq!(c.cipher_suite(), expect_suite);
    assert_eq!(c.alpn(), Some(&b"http/1.1"[..]));
    // s_server -quiet echoes what it receives on stdout; send a line, then reply via its stdin.
    c.write(b"hello from kr\n").unwrap();
    drive(&mut c, &mut sock, |c| !c.has_output());
    srv.stdin.as_mut().unwrap().write_all(b"hello from openssl\n").unwrap();
    let mut got = Vec::new();
    drive(&mut c, &mut sock, |c| {
        let mut b = [0u8; 256];
        let n = c.read(&mut b);
        got.extend_from_slice(&b[..n]);
        got.ends_with(b"\n")
    });
    assert_eq!(got, b"hello from openssl\n");
    c.close();
    sock.write_all(&c.take_output()).unwrap();
    drop(srv.stdin.take());
    let out = srv.wait_with_output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("hello from kr"), "s_server stdout: {}", String::from_utf8_lossy(&out.stdout));
}

#[test]
fn client_vs_openssl_default() {
    if have_openssl() {
        kr_client_vs_s_server("default", &[], false, 0x1303);
    }
}

#[test]
fn client_vs_openssl_aes_only() {
    if have_openssl() {
        kr_client_vs_s_server("aes", &["-ciphersuites", "TLS_AES_128_GCM_SHA256"], false, 0x1301);
    }
}

#[test]
fn client_vs_openssl_p256_only_hrr() {
    if have_openssl() {
        // We offer an X25519 share; the server only does P-256 and must send HelloRetryRequest.
        kr_client_vs_s_server("hrr", &["-groups", "P-256"], false, 0x1303);
    }
}

#[test]
fn client_vs_openssl_ed25519_server() {
    if have_openssl() {
        kr_client_vs_s_server("ed", &[], true, 0x1303);
    }
}

/// openssl s_client (and curl) against our server, with mutual TLS.
#[test]
fn openssl_and_curl_vs_kr_server() {
    if !have_openssl() {
        return;
    }
    let f = setup("s", false);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let cfg = Rc::new(ServerConfig {
        cert_chain: vec![f.srv_cert.clone()],
        key: f.srv_key,
        client_auth: ClientAuth::Required(vec![f.ca.clone()]),
        alpn: vec![b"http/1.1".to_vec()],
    });
    let dir = f.dir.clone();
    let clients = std::thread::spawn(move || {
        let mut results = Vec::new();
        for groups in ["X25519", "P-256"] {
            let mut cmd = Command::new("openssl");
            cmd.args(["s_client", "-quiet", "-tls1_3", "-groups", groups, "-connect", &format!("127.0.0.1:{port}"), "-servername", "localhost", "-verify_return_error", "-verify_hostname", "localhost"])
                .arg("-CAfile").arg(dir.join("ca.pem")).arg("-cert").arg(dir.join("cli.pem")).arg("-key").arg(dir.join("cli.key"))
                .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
            let mut ch = cmd.spawn().unwrap();
            ch.stdin.as_mut().unwrap().write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
            let out = ch.wait_with_output().unwrap();
            results.push((groups.to_string(), String::from_utf8_lossy(&out.stdout).to_string(), String::from_utf8_lossy(&out.stderr).to_string()));
        }
        let curl = Command::new("curl")
            .args(["-sS", "--tlsv1.3", "--http1.1", &format!("https://localhost:{port}/")])
            .arg("--cacert").arg(dir.join("ca.pem")).arg("--cert").arg(dir.join("cli.pem")).arg("--key").arg(dir.join("cli.key"))
            .output();
        if let Ok(o) = curl {
            results.push(("curl".into(), String::from_utf8_lossy(&o.stdout).to_string(), String::from_utf8_lossy(&o.stderr).to_string()));
        }
        results
    });
    let rounds = if Command::new("curl").arg("--version").output().is_ok() { 3 } else { 2 };
    for _ in 0..rounds {
        let (mut sock, _) = listener.accept().unwrap();
        let mut s = Connection::server(cfg.clone(), rng, now());
        let mut req = Vec::new();
        drive(&mut s, &mut sock, |s| {
            let mut b = [0u8; 1024];
            let n = s.read(&mut b);
            req.extend_from_slice(&b[..n]);
            req.windows(4).any(|w| w == b"\r\n\r\n")
        });
        let cn = x509::Certificate::parse(&s.peer_certificates()[0]).unwrap().common_name().unwrap().to_vec();
        let body = format!("hello {}", String::from_utf8_lossy(&cn));
        s.write(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).unwrap();
        s.close();
        sock.write_all(&s.take_output()).unwrap();
    }
    for (who, out, err) in clients.join().unwrap() {
        assert!(out.contains("hello alice"), "{who}: stdout={out} stderr={err}");
    }
}

/// Go's crypto/tls via the real kubectl binary: `kubectl version` against our server with mTLS.
#[test]
fn kubectl_vs_kr_server() {
    if !have_openssl() || Command::new("kubectl").arg("version").arg("--client").output().is_err() {
        return;
    }
    let f = setup("kubectl", false);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let cfg = Rc::new(ServerConfig {
        cert_chain: vec![f.srv_cert.clone()],
        key: f.srv_key,
        client_auth: ClientAuth::Required(vec![f.ca.clone()]),
        alpn: vec![b"http/1.1".to_vec()],
    });
    let dir = f.dir.clone();
    let kubectl = std::thread::spawn(move || {
        Command::new("kubectl")
            .args(["version", "-o", "json", "--request-timeout=10s", &format!("--server=https://127.0.0.1:{port}")])
            .arg(format!("--certificate-authority={}", dir.join("ca.pem").display()))
            .arg(format!("--client-certificate={}", dir.join("cli.pem").display()))
            .arg(format!("--client-key={}", dir.join("cli.key").display()))
            .env("KUBECONFIG", "/dev/null")
            .output()
            .unwrap()
    });
    let (mut sock, _) = listener.accept().unwrap();
    let mut s = Connection::server(cfg, rng, now());
    let mut req = Vec::new();
    drive(&mut s, &mut sock, |s| {
        let mut b = [0u8; 4096];
        let n = s.read(&mut b);
        req.extend_from_slice(&b[..n]);
        req.windows(4).any(|w| w == b"\r\n\r\n")
    });
    assert!(req.starts_with(b"GET /version"), "{}", String::from_utf8_lossy(&req));
    let body = r#"{"major":"1","minor":"31","gitVersion":"v1.31.0-kr","platform":"linux/amd64"}"#;
    s.write(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).unwrap();
    s.close();
    sock.write_all(&s.take_output()).unwrap();
    let out = kubectl.join().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("v1.31.0-kr"), "stdout={stdout} stderr={}", String::from_utf8_lossy(&out.stderr));
}

/// kr client against an RSA server: RSA CA (sha256WithRSA) -> RSA leaf, RSA-PSS CertificateVerify.
#[test]
fn client_vs_openssl_rsa_chain() {
    if !have_openssl() {
        return;
    }
    let dir = std::env::temp_dir().join(format!("kr-tls-rsa-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sh = |script: &str| {
        let o = Command::new("sh").arg("-c").arg(script).current_dir(&dir).output().unwrap();
        assert!(o.status.success(), "{script}: {}", String::from_utf8_lossy(&o.stderr));
    };
    sh("openssl req -x509 -newkey rsa:3072 -nodes -keyout ca.key -out ca.pem -days 2 -subj /CN=rsa-ca -sha256 2>/dev/null");
    sh("openssl req -newkey rsa:2048 -nodes -keyout srv.key -out srv.csr -subj /CN=localhost 2>/dev/null");
    sh("printf 'subjectAltName=DNS:localhost\\nextendedKeyUsage=serverAuth\\nbasicConstraints=critical,CA:FALSE\\nkeyUsage=critical,digitalSignature,keyEncipherment\\n' > ext && \
        openssl x509 -req -in srv.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out srv.pem -days 1 -sha384 -extfile ext 2>/dev/null");
    let port = free_port();
    let mut srv = Command::new("openssl")
        .args(["s_server", "-quiet", "-tls1_3", "-accept", &port.to_string(), "-naccept", "1", "-cert", "srv.pem", "-key", "srv.key"])
        .current_dir(&dir)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().unwrap();
    let mut sock = (0..100).find_map(|_| { std::thread::sleep(Duration::from_millis(30)); TcpStream::connect(("127.0.0.1", port)).ok() }).expect("connect");
    let ca = x509::pem_decode_all(&std::fs::read_to_string(dir.join("ca.pem")).unwrap(), "CERTIFICATE").unwrap();
    let cfg = Rc::new(ClientConfig { pinned_ca: None, roots: ca, client_cert: None, alpn: vec![], tls12: false });
    let mut c = Connection::client(cfg, b"localhost", rng, now());
    drive(&mut c, &mut sock, |c| !c.is_handshaking());
    let leaf = x509::Certificate::parse(&c.peer_certificates()[0]).unwrap();
    assert!(matches!(leaf.public_key, Some(x509::PublicKey::Rsa(_))));
    c.write(b"rsa ok\n").unwrap();
    drive(&mut c, &mut sock, |c| !c.has_output());
    std::thread::sleep(Duration::from_millis(300));
    c.close();
    sock.write_all(&c.take_output()).unwrap();
    drop(srv.stdin.take());
    let out = srv.wait_with_output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("rsa ok"));
}

// ---- TLS 1.2 client (opt-in) against `openssl s_server -tls1_2` ----

/// An RSA CA and leaf for localhost, made with the openssl CLI (kr only verifies RSA).
fn rsa_files(dir: &std::path::Path) -> Vec<u8> {
    let run = |args: &[&str]| assert!(Command::new("openssl").args(args).current_dir(dir).output().unwrap().status.success(), "openssl {args:?}");
    run(&["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "rca.key", "-out", "rca.pem", "-days", "1", "-subj", "/CN=kr-rsa-ca"]);
    run(&["req", "-newkey", "rsa:2048", "-nodes", "-keyout", "rsrv.key", "-out", "rsrv.csr", "-subj", "/CN=localhost"]);
    std::fs::write(dir.join("ext.cnf"), "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n").unwrap();
    run(&["x509", "-req", "-in", "rsrv.csr", "-CA", "rca.pem", "-CAkey", "rca.key", "-CAcreateserial", "-out", "rsrv.pem", "-days", "1", "-extfile", "ext.cnf"]);
    let pem = std::fs::read_to_string(dir.join("rca.pem")).unwrap();
    x509::pem_decode_all(&pem, "CERTIFICATE").unwrap().remove(0)
}

/// Runs `s_server` with `args` (TLS 1.2 only) and a kr client with `tls12`; returns the
/// connection after a round trip, or the handshake error.
fn kr12_vs_s_server(tag: &str, rsa: bool, tls12: bool, extra: &[&str]) -> Result<u16, String> {
    let f = setup(tag, false);
    let (cert, key, ca) = if rsa {
        let ca = rsa_files(&f.dir);
        ("rsrv.pem", "rsrv.key", ca)
    } else {
        ("srv.pem", "srv.key", f.ca.clone())
    };
    let port = free_port();
    let mut srv = Command::new("openssl")
        .args(["s_server", "-quiet", "-tls1_2", "-accept", &port.to_string(), "-naccept", "1"])
        .arg("-cert").arg(f.dir.join(cert)).arg("-key").arg(f.dir.join(key))
        .args(extra)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().unwrap();
    let mut sock = (0..100).find_map(|_| { std::thread::sleep(Duration::from_millis(30)); TcpStream::connect(("127.0.0.1", port)).ok() }).expect("connect");
    let cfg = Rc::new(ClientConfig { pinned_ca: None, roots: vec![ca], client_cert: None, alpn: vec![], tls12 });
    let mut c = Connection::client(cfg, b"localhost", rng, now());
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drive(&mut c, &mut sock, |c| !c.is_handshaking());
        c.write(b"hello from kr\n").unwrap();
        drive(&mut c, &mut sock, |c| !c.has_output());
        srv.stdin.as_mut().unwrap().write_all(b"hello from openssl\n").unwrap();
        let mut got = Vec::new();
        drive(&mut c, &mut sock, |c| {
            let mut b = [0u8; 256];
            let n = c.read(&mut b);
            got.extend_from_slice(&b[..n]);
            got.ends_with(b"\n")
        });
        assert_eq!(got, b"hello from openssl\n");
    }));
    let _ = srv.kill();
    let out = srv.wait_with_output().unwrap();
    match r {
        Ok(()) => {
            assert!(String::from_utf8_lossy(&out.stdout).contains("hello from kr"));
            Ok(c.cipher_suite())
        }
        Err(e) => Err(e.downcast_ref::<String>().cloned().unwrap_or_default()),
    }
}

#[test]
fn tls12_client_ecdsa_chacha_and_aes() {
    if have_openssl() {
        assert_eq!(kr12_vs_s_server("12chacha", false, true, &["-cipher", "ECDHE-ECDSA-CHACHA20-POLY1305"]), Ok(0xcca9));
        assert_eq!(kr12_vs_s_server("12aes", false, true, &["-cipher", "ECDHE-ECDSA-AES128-GCM-SHA256"]), Ok(0xc02b));
        assert_eq!(kr12_vs_s_server("12p256", false, true, &["-groups", "P-256"]).map(|_| ()), Ok(()));
    }
}

#[test]
fn tls12_client_rsa_server() {
    if have_openssl() {
        assert_eq!(kr12_vs_s_server("12rsa", true, true, &["-cipher", "ECDHE-RSA-AES128-GCM-SHA256"]), Ok(0xc02f));
        assert_eq!(kr12_vs_s_server("12rsacc", true, true, &["-cipher", "ECDHE-RSA-CHACHA20-POLY1305"]), Ok(0xcca8));
    }
}

#[test]
fn tls12_refused_unless_enabled_and_without_ems() {
    if have_openssl() {
        // A 1.3-only hello: the 1.2-only server answers protocol_version (70) itself.
        let e = kr12_vs_s_server("12off", false, false, &[]).unwrap_err();
        assert!(e.contains("ProtocolVersion") || e.contains("Peer(70)"), "{e}");
        let e = kr12_vs_s_server("12noems", false, true, &["-no_ems"]).unwrap_err();
        assert!(e.contains("HandshakeFailure"), "{e}");
    }
}
