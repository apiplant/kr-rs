//! `kr agent --server https://<host>:6443 --token K10<ca-sha256>::<id>.<secret>`
//!
//! Joins a cluster: fetches the CA over TLS pinned to the hash in the token, exchanges the
//! bootstrap token for node certificates (`POST /kr/join`), then runs the kubelet, service
//! proxy and cluster DNS against the remote API server, and serves the kubelet API on :10250
//! for the API server's logs/exec/port-forward proxy. Data: `--data`, else `$KR_ROOT/agent`,
//! else `/var/lib/kr/agent` (root) or `~/.local/share/kr/agent`.

use crate::pki;
use crate::server::{cgroups_available, load_pem, mkdir_p, node_name};
use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use kr_apiserver::client::{Client, Remote, RemoteAuth};
use kr_crypto::x509::{self, SigningKey};
use kr_rt::{eprint, print, Args};
use kr_sys::{fs, ns};

fn fail(msg: &str) -> i32 {
    eprint(b"kr agent: ");
    eprint(msg.as_bytes());
    eprint(b"\n");
    1
}

fn data_dir() -> String {
    let env = kr_runtime::store::env_var;
    if let Some(r) = env("KR_ROOT").filter(|v| !v.is_empty()) {
        return format!("{r}/agent");
    }
    if ns::getuid() == 0 {
        return "/var/lib/kr/agent".into();
    }
    format!("{}/.local/share/kr/agent", env("HOME").unwrap_or_else(|| "/tmp".into()))
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Fetches /cacerts trusting only a CA whose SHA-256 matches the token's pin.
async fn fetch_ca(server: &str, pin: [u8; 32]) -> Result<Vec<u8>, String> {
    let cfg = Rc::new(kr_crypto::tls::ClientConfig { roots: Vec::new(), pinned_ca: Some(pin), client_cert: None, alpn: alloc::vec![b"http/1.1".to_vec()] });
    let conn = kr_net::tls::TlsConnector::new(kr_net::dns::SystemResolver::system(), cfg);
    let client = kr_net::http1::Client::with_connector(conn, kr_net::http1::Config::default());
    let mut r = client.get(&format!("{server}/cacerts"), &[]).await.map_err(|_| String::from("cannot reach the server (or its CA does not match the token)"))?;
    let body = r.read_to_end(1 << 20).await.map_err(|_| String::from("reading /cacerts failed"))?;
    let pem = core::str::from_utf8(&body).map_err(|_| String::from("bad /cacerts"))?;
    let der = x509::pem_decode_all(pem, "CERTIFICATE").ok().and_then(|mut v| (!v.is_empty()).then(|| v.remove(0))).ok_or("no CA in /cacerts")?;
    if kr_crypto::sha2::sha256(&der) != pin {
        return Err("the server's CA does not match the token".into());
    }
    Ok(der)
}

async fn join(server: &str, token: &str, pki_dir: &str, name: &str, ip: [u8; 4]) -> Result<(), String> {
    let (hash, secret) = token.trim().strip_prefix("K10").and_then(|t| t.split_once("::")).ok_or("token must look like K10<hash>::<id>.<secret>")?;
    let pin = unhex32(hash).ok_or("bad CA hash in token")?;
    let ca = fetch_ca(server, pin).await?;
    let ca_pem = x509::pem_encode("CERTIFICATE", &ca);
    let client_key = pki::new_key();
    let serving_key = pki::new_key();
    let b64 = |k: &SigningKey| kr_fmt::base64::encode(&k.public().spki());
    let body = format!(
        r#"{{"nodeName":"{name}","clientKey":"{}","servingKey":"{}","addresses":["{}.{}.{}.{}"]}}"#,
        b64(&client_key),
        b64(&serving_key),
        ip[0],
        ip[1],
        ip[2],
        ip[3]
    );
    let remote = Remote::new(server, RemoteAuth::Bearer(secret.into()), &ca_pem).map_err(|e| e.message)?;
    let req = kr_fmt::json::parse(body.as_bytes()).map_err(|_| String::from("internal: bad join request"))?;
    let r = remote.create("/kr/join", &req).await.map_err(|e| format!("join refused: {} {}", e.code, e.message))?;
    let s = |f: &str| r.get(f).and_then(kr_fmt::json::Value::as_str).map(String::from).ok_or(format!("join response lacks {f}"));
    mkdir_p(pki_dir)?;
    let key_pem = |k: &SigningKey| x509::pem_encode("PRIVATE KEY", &x509::private_key_to_pkcs8(k));
    for (file, data, mode) in [
        ("ca.pem", ca_pem.clone(), 0o644),
        ("node.pem", s("clientCert")?, 0o644),
        ("node.key", key_pem(&client_key), 0o600),
        ("serving.pem", s("servingCert")?, 0o644),
        ("serving.key", key_pem(&serving_key), 0o600),
    ] {
        pki::write_new(&pki::path(pki_dir, file), data.as_bytes(), mode)?;
    }
    Ok(())
}

pub fn main(mut args: Args) -> i32 {
    let (mut server, mut token, mut data) = (None, None, None);
    while let Some(a) = args.next() {
        let v = args.next().and_then(|v| core::str::from_utf8(v).ok()).map(String::from);
        match (a, v) {
            (b"--server", Some(v)) => server = Some(v),
            (b"--token", Some(v)) => token = Some(v),
            (b"--data", Some(v)) => data = Some(v),
            _ => return fail("usage: kr agent --server https://HOST:6443 --token TOKEN [--data DIR]"),
        }
    }
    let Some(server) = server.map(|s| String::from(s.trim_end_matches('/'))) else { return fail("--server is required") };
    let data = data.unwrap_or_else(data_dir);
    let pki_dir = format!("{data}/pki");
    let name = node_name();
    // Our address as seen on the path to the server.
    let host = server.trim_start_matches("https://").split(':').next().unwrap_or("");
    let ip = kr_apiserver::object::parse_ipv4(host).and_then(|a| ns::route_source(a).ok()).or_else(|| ns::route_source([1, 1, 1, 1]).ok()).unwrap_or([127, 0, 0, 1]);
    let joined = ns::open(&pki::path(&pki_dir, "node.pem"), ns::O_RDONLY, 0).is_ok();
    if !joined {
        let Some(token) = token else { return fail("--token is required for the first join") };
        let (sv, pd, nm) = (server.clone(), pki_dir.clone(), name.clone());
        if let Err(e) = kr_rt::exec::block_on(async move { join(&sv, &token, &pd, &nm, ip).await }) {
            return fail(&e);
        }
        print(format!("kr agent: joined as node {name}\n").as_bytes());
    }
    let read = |f: &str| fs::read_file(&pki::path(&pki_dir, f), 1 << 20).ok().and_then(|b| String::from_utf8(b).ok());
    let (Some(ca_pem), Some(chain), Some(key)) = (read("ca.pem"), read("node.pem"), read("node.key")) else { return fail("node credentials are missing") };
    let remote = match Remote::new(&server, RemoteAuth::ClientCert { chain, key }, &ca_pem) {
        Ok(r) => r,
        Err(e) => return fail(&e.message),
    };
    let serving = || -> Result<Rc<kr_crypto::tls::ServerConfig>, String> {
        let chain = load_pem(&pki_dir, "serving.pem", "CERTIFICATE")?;
        let key = x509::private_key_from_pkcs8(&load_pem(&pki_dir, "serving.key", "PRIVATE KEY")?.pop().ok_or("empty key")?).map_err(|_| "bad serving key")?;
        let roots = load_pem(&pki_dir, "ca.pem", "CERTIFICATE")?;
        Ok(Rc::new(kr_crypto::tls::ServerConfig { cert_chain: chain, key, client_auth: kr_crypto::tls::ClientAuth::Required(roots), alpn: alloc::vec![b"http/1.1".to_vec()] }))
    };
    let tls = match serving() {
        Ok(t) => t,
        Err(e) => return fail(&e),
    };
    let store = match kr_runtime::store::Store::open(None) {
        Ok(s) => s,
        Err(_) => return fail("cannot open the image store"),
    };
    let cfg = kr_kubelet::Config { node_name: name.clone(), root: String::from(store.root()), network: ns::getuid() == 0, cgroups: cgroups_available(), node_ip: ip };
    let kubelet = kr_kubelet::Kubelet::new(remote, cfg, store);
    print(format!("kr agent: node {name} ({}.{}.{}.{}) -> {server}\n", ip[0], ip[1], ip[2], ip[3]).as_bytes());
    kr_rt::exec::block_on(async move {
        let proxy: Rc<dyn kr_apiserver::api::NodeProxy> = Rc::new(kr_kubelet::stream::Proxy(kubelet.clone()));
        kr_rt::exec::spawn(kr_kubelet::remote::serve(proxy, name, tls));
        kubelet.run().await;
    });
    0
}
