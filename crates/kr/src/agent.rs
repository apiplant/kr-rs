//! `kr agent --server https://<host>:6443 --token-file FILE` (or `KR_TOKEN=K10<ca-sha256>::<id>.<secret>`)
//!
//! The token is needed only for the first join. `--token VALUE` also works but leaves the
//! secret readable by every local user in /proc/<pid>/cmdline, so it prints a warning.
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
use kr_rt::{eprint, print};
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

pub(crate) fn unhex32(s: &str) -> Option<[u8; 32]> {
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
pub(crate) async fn fetch_ca(server: &str, pin: [u8; 32]) -> Result<Vec<u8>, String> {
    let cfg = Rc::new(kr_crypto::tls::ClientConfig { roots: Vec::new(), pinned_ca: Some(pin), client_cert: None, alpn: alloc::vec![b"http/1.1".to_vec()], tls12: false });
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

async fn join(server: &str, token: &str, pki_dir: &str, name: &str, ip: [u8; 16]) -> Result<(), String> {
    let (hash, secret) = token.trim().strip_prefix("K10").and_then(|t| t.split_once("::")).ok_or("token must look like K10<hash>::<id>.<secret>")?;
    let pin = unhex32(hash).ok_or("bad CA hash in token")?;
    let ca = fetch_ca(server, pin).await?;
    let ca_pem = x509::pem_encode("CERTIFICATE", &ca);
    let remote = Remote::new(server, RemoteAuth::Bearer(secret.into()), &ca_pem).map_err(|e| e.message)?;
    let files = request_certs(&remote, name, ip).await?;
    mkdir_p(pki_dir)?;
    pki::write_new(&pki::path(pki_dir, "ca.pem"), ca_pem.as_bytes(), 0o644)?;
    for (file, data, mode) in &files {
        pki::write_new(&pki::path(pki_dir, file), data.as_bytes(), *mode)?;
    }
    Ok(())
}

/// New client and serving keys, certified by `POST /kr/join` (first join with the bootstrap
/// token, rotation with the current node certificate). Returns (file, PEM, mode).
async fn request_certs(remote: &Remote, name: &str, ip: [u8; 16]) -> Result<[(&'static str, String, u32); 4], String> {
    let client_key = pki::new_key();
    let serving_key = pki::new_key();
    let b64 = |k: &SigningKey| kr_fmt::base64::encode(&k.public().spki());
    let body = format!(
        r#"{{"nodeName":"{name}","clientKey":"{}","servingKey":"{}","addresses":["{}"]}}"#,
        b64(&client_key),
        b64(&serving_key),
        kr_net::tcp::fmt_ip16(ip)
    );
    let req = kr_fmt::json::parse(body.as_bytes()).map_err(|_| String::from("internal: bad join request"))?;
    let r = remote.create("/kr/join", &req).await.map_err(|e| format!("join refused: {} {}", e.code, e.message))?;
    let s = |f: &str| r.get(f).and_then(kr_fmt::json::Value::as_str).map(String::from).ok_or(format!("join response lacks {f}"));
    let key_pem = |k: &SigningKey| x509::pem_encode("PRIVATE KEY", &x509::private_key_to_pkcs8(k));
    Ok([("node.pem", s("clientCert")?, 0o644), ("node.key", key_pem(&client_key), 0o600), ("serving.pem", s("servingCert")?, 0o644), ("serving.key", key_pem(&serving_key), 0o600)])
}

/// (not_before, not_after) of the first certificate in a PEM file.
fn validity(pki_dir: &str, file: &str) -> Option<(i64, i64)> {
    let der = load_pem(pki_dir, file, "CERTIFICATE").ok()?.into_iter().next()?;
    let c = x509::Certificate::parse(&der).ok()?;
    Some((c.not_before, c.not_after))
}

fn serving_config(pki_dir: &str) -> Result<Rc<kr_crypto::tls::ServerConfig>, String> {
    let chain = load_pem(pki_dir, "serving.pem", "CERTIFICATE")?;
    let key = x509::private_key_from_pkcs8(&load_pem(pki_dir, "serving.key", "PRIVATE KEY")?.pop().ok_or("empty key")?).map_err(|_| "bad serving key")?;
    let roots = load_pem(pki_dir, "ca.pem", "CERTIFICATE")?;
    Ok(Rc::new(kr_crypto::tls::ServerConfig { cert_chain: chain, key, client_auth: kr_crypto::tls::ClientAuth::Required(roots), alpn: alloc::vec![b"http/1.1".to_vec()] }))
}

/// Renews the node certificates at 2/3 of their lifetime (KNOWN_ISSUES #82): new keys via
/// `/kr/join`, files replaced atomically, then the API client and the kubelet server switch.
async fn rotate(remote: Remote, pki_dir: String, name: String, ip: [u8; 16], serving: Rc<core::cell::RefCell<Rc<kr_crypto::tls::ServerConfig>>>) {
    loop {
        let (nb, na) = validity(&pki_dir, "node.pem").unwrap_or((0, 0));
        let due = nb + (na - nb) * 2 / 3;
        let wait = (due - pki::now()).clamp(0, 3600);
        if wait > 0 {
            kr_rt::exec::sleep(wait as u64 * 1000).await;
            continue;
        }
        match renew(&remote, &pki_dir, &name, ip).await {
            Ok(()) => match serving_config(&pki_dir) {
                Ok(cfg) => {
                    *serving.borrow_mut() = cfg;
                    print(b"kr agent: node certificates rotated\n");
                    // Clock skew must not turn this into a busy loop.
                    kr_rt::exec::sleep(30_000).await;
                }
                Err(e) => eprint(format!("kr agent: reloading serving certificate: {e}\n").as_bytes()),
            },
            Err(e) => {
                eprint(format!("kr agent: certificate rotation failed (retrying in 60s): {e}\n").as_bytes());
                kr_rt::exec::sleep(60_000).await;
            }
        }
    }
}

/// Follows a CA rotation (`kr pki rotate --ca`): the cluster publishes its CA bundle at
/// `/kr/ca-bundle`; when it differs from `pki/ca.pem` the agent stores it and trusts it from the
/// next connection on (and for the clients of its kubelet API), so no file has to be copied by hand.
async fn track_ca(remote: Remote, pki_dir: String, serving: Rc<core::cell::RefCell<Rc<kr_crypto::tls::ServerConfig>>>) {
    loop {
        kr_rt::exec::sleep(60_000).await;
        let Ok(doc) = remote.get("/kr/ca-bundle").await else { continue };
        let Some(bundle) = doc.get("caBundle").and_then(kr_fmt::json::Value::as_str) else { continue };
        let read = |f: &str| fs::read_file(&pki::path(&pki_dir, f), 1 << 20).ok().and_then(|b| String::from_utf8(b).ok());
        let Some(cur) = read("ca.pem") else { continue };
        if bundle.trim() == cur.trim() || x509::pem_decode_all(bundle, "CERTIFICATE").map_or(true, |v| v.is_empty()) {
            continue;
        }
        let tmp = "ca.pem.new";
        let _ = fs::unlinkat(fs::AT_FDCWD, &pki::path(&pki_dir, tmp), 0);
        if pki::write_new(&pki::path(&pki_dir, tmp), bundle.as_bytes(), 0o644).is_err() || fs::renameat2(fs::AT_FDCWD, &pki::path(&pki_dir, tmp), fs::AT_FDCWD, &pki::path(&pki_dir, "ca.pem"), 0).is_err() {
            continue;
        }
        let (Some(chain), Some(key)) = (read("node.pem"), read("node.key")) else { continue };
        if let Err(e) = remote.set_roots(bundle, &chain, &key) {
            eprint(format!("kr agent: new CA bundle: {}\n", e.message).as_bytes());
            continue;
        }
        if let Ok(cfg) = serving_config(&pki_dir) {
            *serving.borrow_mut() = cfg;
        }
        print(b"kr agent: the cluster CA bundle changed; trusting the new one\n");
    }
}

async fn renew(remote: &Remote, pki_dir: &str, name: &str, ip: [u8; 16]) -> Result<(), String> {
    let files = request_certs(remote, name, ip).await?;
    for (file, data, mode) in &files {
        let tmp = format!("{file}.new");
        let _ = fs::unlinkat(fs::AT_FDCWD, &pki::path(pki_dir, &tmp), 0);
        pki::write_new(&pki::path(pki_dir, &tmp), data.as_bytes(), *mode)?;
        fs::renameat2(fs::AT_FDCWD, &pki::path(pki_dir, &tmp), fs::AT_FDCWD, &pki::path(pki_dir, file), 0).map_err(|e| format!("rename {file}: errno {}", e.0))?;
    }
    let (chain, key) = (files[0].1.as_str(), files[1].1.as_str());
    remote.set_client_cert(chain, key).map_err(|e| e.message)
}

/// Reads the join token from a file that only its owner can read.
/// Follows the `kubernetes` endpoints (one per API server in HA) so that requests can fail
/// over to any server, and saves the list for the next start.
async fn track_servers(remote: Remote, file: String) {
    let mut saved = String::new();
    loop {
        if let Ok(ep) = remote.get("/api/v1/namespaces/default/endpoints/kubernetes").await {
            let mut urls = Vec::new();
            for sub in ep.get("subsets").and_then(kr_fmt::json::Value::as_array).map(|a| a.to_vec()).unwrap_or_default() {
                let port = sub.pointer(&["ports"]).and_then(kr_fmt::json::Value::as_array).and_then(|p| p.first()).and_then(|p| p.get("port")).and_then(kr_fmt::json::Value::as_u64).unwrap_or(6443);
                for a in sub.get("addresses").and_then(kr_fmt::json::Value::as_array).map(|a| a.to_vec()).unwrap_or_default() {
                    if let Some(ip) = a.get("ip").and_then(kr_fmt::json::Value::as_str).and_then(kr_net::tcp::parse_ip16) {
                        urls.push(format!("https://{}:{port}", kr_net::tcp::url_host(ip)));
                    }
                }
            }
            let text = urls.join("\n");
            if !urls.is_empty() && text != saved {
                remote.set_servers(&urls);
                let tmp = format!("{file}.tmp\0");
                let _ = fs::unlinkat(fs::AT_FDCWD, tmp.as_bytes(), 0);
                let dst = format!("{file}\0");
                if pki::write_new(tmp.as_bytes(), text.as_bytes(), 0o644).is_ok() && fs::renameat2(fs::AT_FDCWD, tmp.as_bytes(), fs::AT_FDCWD, dst.as_bytes(), 0).is_ok() {
                    saved = text;
                }
            }
        }
        kr_rt::exec::sleep(30_000).await;
    }
}

pub(crate) fn read_token_file(path: &str) -> Result<String, String> {
    let c = format!("{path}\0");
    let st = fs::newfstatat(fs::AT_FDCWD, c.as_bytes(), 0).map_err(|e| format!("token file {path}: errno {}", e.0))?;
    if st.mode & 0o077 != 0 {
        return Err(format!("token file {path} is accessible by other users (mode {:o}); chmod 600 it", st.mode & 0o777));
    }
    let b = fs::read_file(c.as_bytes(), 4096).map_err(|e| format!("token file {path}: errno {}", e.0))?;
    String::from_utf8(b).map(|t| String::from(t.trim())).map_err(|_| format!("token file {path} is not UTF-8"))
}

pub fn main(mut args: crate::install::Argv) -> i32 {
    crate::offload::start(false); // image unpacking in workers (ADR-052)
    if kr_runtime::store::env_var("KR_TLS_RESUMPTION").as_deref() == Some("off") {
        kr_net::tls::set_resumption(false);
    }
    let (mut server, mut token, mut token_file, mut data) = (None, None, None, None);
    let mut inst = crate::install::Install::default();
    while let Some(a) = args.next() {
        // `--flag=value` and `--flag value` are both accepted.
        let (a, inline) = match a.iter().position(|&c| c == b'=') {
            Some(i) if a.starts_with(b"--") => (&a[..i], Some(&a[i + 1..])),
            _ => (a, None),
        };
        let v = inline.or_else(|| args.next()).and_then(|v| core::str::from_utf8(v).ok()).map(String::from);
        if let Some(val) = &v {
            if inst.take(a, val) {
                continue;
            }
        }
        match (a, v) {
            (b"--server", Some(v)) => server = Some(v),
            (b"--token", Some(v)) => {
                eprint(b"kr agent: warning: --token exposes the join token to local users via the process list; use --token-file or KR_TOKEN\n");
                token = Some(v)
            }
            (b"--token-file", Some(v)) => token_file = Some(v),
            (b"--data" | b"--data-dir", Some(v)) => data = Some(v),
            _ => return fail("usage: kr agent --server https://HOST:6443 [--token-file FILE | --token TOKEN] [--data DIR] [--config FILE] [--node-name NAME] [--node-label K=V]... [--node-taint K=V:EFFECT]... [--node-ip IP] [--node-external-ip IP] [--disable network-policy|coredns]...   (or KR_TOKEN in the environment)"),
        }
    }
    if let Err(e) = crate::install::publish(&inst) {
        return fail(&e);
    }
    let disabled = crate::install::disabled().unwrap_or_default();
    let Some(server) = server.map(|s| String::from(s.trim_end_matches('/'))) else { return fail("--server is required") };
    let data = data.unwrap_or_else(data_dir);
    let pki_dir = format!("{data}/pki");
    let name = node_name();
    // Our address as seen on the path to the server.
    let rest = server.trim_start_matches("https://");
    let host = match rest.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => rest.split(':').next().unwrap_or(""),
    };
    let ip = crate::install::node_ip().unwrap_or_else(|| kr_net::tcp::parse_ip16(host)
        .and_then(|d| match kr_sys::unmap4(d) {
            Some(v4) => ns::route_source(v4).ok().map(kr_sys::map4),
            None => ns::route_source6(d),
        })
        .unwrap_or_else(crate::server::primary_addr));
    let joined = ns::open(&pki::path(&pki_dir, "node.pem"), ns::O_RDONLY, 0).is_ok();
    if !joined {
        let token = match (token, token_file) {
            (Some(t), _) => t,
            (None, Some(f)) => match read_token_file(&f) {
                Ok(t) => t,
                Err(e) => return fail(&e),
            },
            (None, None) => match kr_runtime::store::env_var("KR_TOKEN").filter(|t| !t.trim().is_empty()) {
                Some(t) => t,
                None => return fail("a join token is required for the first join (--token-file FILE or KR_TOKEN)"),
            },
        };
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
    // HA: every API server, as last seen; lets the agent start while --server is down.
    let servers_file = format!("{data}/servers");
    if let Some(list) = fs::read_file(&pki::path(&data, "servers"), 64 << 10).ok().and_then(|b| String::from_utf8(b).ok()) {
        let mut urls = alloc::vec![server.clone()];
        urls.extend(list.lines().map(String::from).filter(|u| *u != server));
        remote.set_servers(&urls);
    }
    let tls = match serving_config(&pki_dir) {
        Ok(t) => Rc::new(core::cell::RefCell::new(t)),
        Err(e) => return fail(&e),
    };
    let store = match kr_runtime::store::Store::open(None) {
        Ok(s) => s,
        Err(_) => return fail("cannot open the image store"),
    };
    crate::ctr_import::import_startup(&store, Some(&format!("{data}/images")));
    let (labels, taints) = match crate::install::node_settings() {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    let cfg = kr_kubelet::Config { labels, taints, external_ip: crate::install::external_ip(), disabled, node_name: name.clone(), root: String::from(store.root()), network: ns::getuid() == 0, cgroups: cgroups_available(), node_ip: ip, vxlan: !matches!(kr_runtime::store::env_var("KR_NET_BACKEND").as_deref(), Some("host-gw" | "wireguard")), wireguard: kr_runtime::store::env_var("KR_NET_BACKEND").as_deref() == Some("wireguard"), eviction_memory_bytes: kr_kubelet::evict::threshold_from_env(), control_plane: false };
    let rotation = (remote.clone(), pki_dir.clone(), name.clone(), ip, tls.clone());
    let tracker = remote.clone();
    let (ca_remote, ca_dir, ca_tls) = (remote.clone(), pki_dir.clone(), tls.clone());
    let kubelet = kr_kubelet::Kubelet::new(remote, cfg, store);
    print(format!("kr agent: node {name} ({}) -> {server}\n", kr_net::tcp::fmt_ip16(ip)).as_bytes());
    kr_rt::exec::block_on(async move {
        let proxy: Rc<dyn kr_apiserver::api::NodeProxy> = Rc::new(kr_kubelet::stream::Proxy(kubelet.clone()));
        kr_rt::exec::spawn(kr_kubelet::remote::serve(proxy, name, tls));
        let (r, d, n, ip, s) = rotation;
        kr_rt::exec::spawn(rotate(r, d, n, ip, s));
        kr_rt::exec::spawn(track_servers(tracker, servers_file));
        kr_rt::exec::spawn(track_ca(ca_remote, ca_dir, ca_tls));
        kubelet.run().await;
    });
    0
}
