//! `kr token create [--ttl 24h] [--data DIR] [--server URL]`
//!
//! Mints an expiring join token (KNOWN_ISSUES #82): a bootstrap-token Secret with
//! `expiration`, created through the API with the server's admin certificate. Prints
//! `K10<ca-sha256>::<id>.<secret>` for `kr agent --token`. The API server rejects the token
//! once it expires.

use crate::pki;
use alloc::format;
use alloc::string::String;
use kr_apiserver::client::{Client, Remote, RemoteAuth};
use kr_crypto::x509;
use kr_rt::{eprint, print, Args};
use kr_sys::fs;

fn fail(msg: &str) -> i32 {
    eprint(b"kr token: ");
    eprint(msg.as_bytes());
    eprint(b"\n");
    1
}

const USAGE: &str = "usage: kr token create [--ttl DURATION (default 24h, 0 = never)] [--data DIR] [--server https://127.0.0.1:6443]";

pub fn main(mut args: Args) -> i32 {
    if args.next() != Some(b"create".as_slice()) {
        return fail(USAGE);
    }
    let (mut ttl, mut data, mut server) = (86400i64, crate::server::data_dir(), String::from("https://127.0.0.1:6443"));
    while let Some(a) = args.next() {
        let Some(v) = args.next().and_then(|v| core::str::from_utf8(v).ok()) else { return fail(USAGE) };
        match a {
            b"--ttl" => match kr_fmt::quantity::parse_duration(v) {
                Ok(ns) if ns >= 0 => ttl = ns / 1_000_000_000,
                _ => return fail("--ttl: expected a duration like 30m or 24h"),
            },
            b"--data" => data = String::from(v),
            b"--server" => server = String::from(v.trim_end_matches('/')),
            _ => return fail(USAGE),
        }
    }
    let read = |f: &str| fs::read_file(&pki::path(&format!("{data}/pki"), f), 1 << 20).ok().and_then(|b| String::from_utf8(b).ok());
    let (Some(ca_pem), Some(chain), Some(key)) = (read("ca.pem"), read("admin.pem"), read("admin.key")) else { return fail("cannot read the server's admin credentials (run on the server, or pass --data)") };
    let Some(ca_der) = x509::pem_decode_all(&ca_pem, "CERTIFICATE").ok().and_then(|v| v.into_iter().next()) else { return fail("bad ca.pem") };
    let remote = match Remote::new(&server, RemoteAuth::ClientCert { chain, key }, &ca_pem) {
        Ok(r) => r,
        Err(e) => return fail(&e.message),
    };
    let mut rnd = [0u8; 22];
    kr_sys::getrandom(&mut rnd);
    const ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let t: String = rnd.iter().map(|b| ALPHA[*b as usize % ALPHA.len()] as char).collect();
    let (id, secret) = (&t[..6], &t[6..]);
    let b64 = |s: &str| kr_fmt::base64::encode(s.as_bytes());
    let expiration = if ttl > 0 { format!(r#","expiration":"{}""#, b64(&kr_apiserver::object::rfc3339(pki::now() + ttl))) } else { String::new() };
    let body = format!(
        r#"{{"apiVersion":"v1","kind":"Secret","metadata":{{"name":"bootstrap-token-{id}","namespace":"kube-system"}},"type":"bootstrap.kubernetes.io/token","data":{{"token-id":"{}","token-secret":"{}","usage-bootstrap-authentication":"{}","auth-extra-groups":"{}"{expiration}}}}}"#,
        b64(id),
        b64(secret),
        b64("true"),
        b64("system:bootstrappers:kr:default-node-token")
    );
    let Ok(obj) = kr_fmt::json::parse(body.as_bytes()) else { return fail("internal: bad secret") };
    let r = kr_rt::exec::block_on(async move { remote.create("/api/v1/namespaces/kube-system/secrets", &obj).await });
    if let Err(e) = r {
        return fail(&format!("creating the token: {} {}", e.code, e.message));
    }
    let hash: String = kr_crypto::sha2::sha256(&ca_der).iter().map(|b| format!("{b:02x}")).collect();
    print(format!("K10{hash}::{id}.{secret}\n").as_bytes());
    0
}
