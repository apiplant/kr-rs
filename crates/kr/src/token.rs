//! `kr token create|list|delete|generate|rotate` (KNOWN_ISSUES #82, #365).
//!
//! `create` mints an expiring join token: a bootstrap-token Secret with `expiration`, created
//! through the API with the server's admin certificate. It prints `K10<ca-sha256>::<id>.<secret>`
//! for `kr agent --token`. The API server rejects the token once it expires.
//! `list` / `delete` manage those Secrets, `generate` prints a fresh random token string
//! without storing it, and `rotate` replaces the server's own join token (`node-token`).

use crate::pki;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use kr_apiserver::client::{Client, Remote, RemoteAuth};
use kr_crypto::x509;
use kr_fmt::json::Value;
use kr_rt::{eprint, print, Args};
use kr_sys::fs;

fn fail(msg: &str) -> i32 {
    eprint(b"kr token: ");
    eprint(msg.as_bytes());
    eprint(b"\n");
    1
}

const USAGE: &str = "usage: kr token create [--ttl DURATION (default 24h, 0 = never)] [options]\n       kr token list [options]\n       kr token delete ID... [options]\n       kr token generate\n       kr token rotate [--new-token K10<hash>::<id>.<secret> | <id>.<secret>] [options]\noptions: [--data DIR] [--server URL (default: this machine's server)]";
const SECRETS: &str = "/api/v1/namespaces/kube-system/secrets";
const ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// A random `<id>.<secret>` bootstrap token (6 + 16 characters of [a-z0-9]).
fn random_token() -> (String, String) {
    let mut rnd = [0u8; 22];
    kr_sys::getrandom(&mut rnd);
    let t: String = rnd.iter().map(|b| ALPHA[*b as usize % ALPHA.len()] as char).collect();
    (String::from(&t[..6]), String::from(&t[6..]))
}

/// Checks the `<id>.<secret>` shape the API server accepts.
fn valid_id_secret(id: &str, secret: &str) -> bool {
    let ok = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    ok(id, 6) && ok(secret, 16)
}

/// `new` is `K10<hash>::<id>.<secret>` or `<id>.<secret>`; returns (id, secret).
fn parse_new_token(new: &str, hash: &str) -> Result<(String, String), &'static str> {
    let (h, idsec) = match new.strip_prefix("K10") {
        Some(t) => t.split_once("::").ok_or("token must look like K10<hash>::<id>.<secret>")?,
        None => (hash, new),
    };
    if h != hash {
        return Err("the token pins a different CA than this cluster's");
    }
    let shape = "token must look like <id>.<secret> (6 and 16 characters of a-z0-9)";
    let (id, secret) = idsec.split_once('.').ok_or(shape)?;
    if !valid_id_secret(id, secret) {
        return Err(shape);
    }
    Ok((String::from(id), String::from(secret)))
}

fn fmt_left(s: i64) -> String {
    if s >= 86400 {
        format!("{}d{}h", s / 86400, s % 86400 / 3600)
    } else if s >= 3600 {
        format!("{}h{}m", s / 3600, s % 3600 / 60)
    } else {
        format!("{}m{}s", s / 60, s % 60)
    }
}

/// One bootstrap-token Secret as a table row: id, expiry, usages, description.
fn row(sec: &Value, now: i64) -> Option<(String, String)> {
    if sec.get("type").and_then(Value::as_str) != Some("bootstrap.kubernetes.io/token") {
        return None;
    }
    let field = |f: &str| sec.pointer(&["data", f]).and_then(Value::as_str).and_then(|v| kr_fmt::base64::decode(v).ok()).and_then(|b| String::from_utf8(b).ok());
    let id = field("token-id")?;
    let expires = match field("expiration") {
        None => String::from("<forever>"),
        Some(e) => match kr_apiserver::printers::parse_rfc3339(&e) {
            Some(t) if t <= now => format!("expired {e}"),
            Some(t) => format!("{} ({e})", fmt_left(t - now)),
            None => e,
        },
    };
    let mut usages: Vec<&str> = Vec::new();
    for (key, name) in [("usage-bootstrap-authentication", "authentication"), ("usage-bootstrap-signing", "signing")] {
        if field(key).as_deref() == Some("true") {
            usages.push(name);
        }
    }
    let usages = if usages.is_empty() { String::from("<none>") } else { usages.join(",") };
    let line = format!("{id}\t{expires}\t{usages}\t{}", field("description").unwrap_or_default());
    Some((id, line))
}

/// The table printed by `kr token list` (tab separated, header first).
fn table(list: &Value, now: i64, current: Option<&str>) -> String {
    let mut out = String::from("ID\tTTL\tUSAGES\tDESCRIPTION\n");
    for sec in list.get("items").and_then(Value::as_array).unwrap_or(&[]) {
        if let Some((id, line)) = row(sec, now) {
            out.push_str(&line);
            if current == Some(id.as_str()) {
                out.push_str(" (server join token)");
            }
            out.push('\n');
        }
    }
    out
}

/// (hash, id, secret) of the server's join token file.
fn current_node_token(data: &str) -> Result<(String, String, String), String> {
    let t = fs::read_file(&pki::path(data, "node-token"), 4096).ok().and_then(|b| String::from_utf8(b).ok()).ok_or("cannot read node-token (run on the server, or pass --data)")?;
    let (hash, idsec) = t.trim().strip_prefix("K10").and_then(|t| t.split_once("::")).ok_or("bad node-token")?;
    let (id, secret) = idsec.split_once('.').ok_or("bad node-token")?;
    Ok((String::from(hash), String::from(id), String::from(secret)))
}

fn secret_body(id: &str, secret: &str, expiration: Option<i64>) -> String {
    let b64 = |s: &str| kr_fmt::base64::encode(s.as_bytes());
    let expiration = match expiration {
        Some(t) => format!(r#","expiration":"{}""#, b64(&kr_apiserver::object::rfc3339(t))),
        None => String::new(),
    };
    format!(
        r#"{{"apiVersion":"v1","kind":"Secret","metadata":{{"name":"bootstrap-token-{id}","namespace":"kube-system"}},"type":"bootstrap.kubernetes.io/token","data":{{"token-id":"{}","token-secret":"{}","usage-bootstrap-authentication":"{}","auth-extra-groups":"{}"{expiration}}}}}"#,
        b64(id),
        b64(secret),
        b64("true"),
        b64("system:bootstrappers:kr:default-node-token")
    )
}

pub fn main(mut args: Args) -> i32 {
    let Some(cmd) = args.next() else { return fail(USAGE) };
    let cmd = match core::str::from_utf8(cmd) {
        Ok(c @ ("create" | "list" | "delete" | "generate" | "rotate")) => c,
        _ => return fail(USAGE),
    };
    let (mut ttl, mut data, mut server, mut new_token) = (86400i64, crate::server::data_dir(), None::<String>, None::<String>);
    let mut ids: Vec<String> = Vec::new();
    while let Some(a) = args.next() {
        if cmd == "delete" && !a.starts_with(b"--") {
            let Ok(id) = core::str::from_utf8(a) else { return fail(USAGE) };
            ids.push(String::from(id));
            continue;
        }
        let Some(v) = args.next().and_then(|v| core::str::from_utf8(v).ok()) else { return fail(USAGE) };
        match a {
            b"--ttl" if cmd == "create" => match kr_fmt::quantity::parse_duration(v) {
                Ok(ns) if ns >= 0 => ttl = ns / 1_000_000_000,
                _ => return fail("--ttl: expected a duration like 30m or 24h"),
            },
            b"--new-token" if cmd == "rotate" => new_token = Some(String::from(v)),
            b"--data" if cmd != "generate" => data = String::from(v),
            b"--server" if cmd != "generate" => server = Some(String::from(v.trim_end_matches('/'))),
            _ => return fail(USAGE),
        }
    }
    if cmd == "generate" {
        let (id, secret) = random_token();
        print(format!("{id}.{secret}\n").as_bytes());
        return 0;
    }
    if cmd == "delete" && ids.is_empty() {
        return fail(USAGE);
    }
    let server = server.unwrap_or_else(|| crate::server::local_url(&data));
    let read = |f: &str| fs::read_file(&pki::path(&format!("{data}/pki"), f), 1 << 20).ok().and_then(|b| String::from_utf8(b).ok());
    let (Some(ca_pem), Some(chain), Some(key)) = (read("ca.pem"), read("admin.pem"), read("admin.key")) else { return fail("cannot read the server's admin credentials (run on the server, or pass --data)") };
    let Some(ca_der) = x509::pem_decode_all(&ca_pem, "CERTIFICATE").ok().and_then(|v| v.into_iter().next()) else { return fail("bad ca.pem") };
    let remote = match Remote::new(&server, RemoteAuth::ClientCert { chain, key }, &ca_pem).map(alloc::rc::Rc::new) {
        Ok(r) => r,
        Err(e) => return fail(&e.message),
    };
    let hash: String = kr_crypto::sha2::sha256(&ca_der).iter().map(|b| format!("{b:02x}")).collect();
    match cmd {
        "create" => {
            let (id, secret) = random_token();
            let body = secret_body(&id, &secret, if ttl > 0 { Some(pki::now() + ttl) } else { None });
            let Ok(obj) = kr_fmt::json::parse(body.as_bytes()) else { return fail("internal: bad secret") };
            if let Err(e) = kr_rt::exec::block_on({ let r = remote.clone(); async move { r.create(SECRETS, &obj).await } }) {
                return fail(&format!("creating the token: {} {}", e.code, e.message));
            }
            print(format!("K10{hash}::{id}.{secret}\n").as_bytes());
            0
        }
        "list" => {
            let current = current_node_token(&data).ok().map(|t| t.1);
            match kr_rt::exec::block_on({ let r = remote.clone(); async move { r.list(SECRETS, "").await } }) {
                Ok(l) => {
                    print(table(&l, pki::now(), current.as_deref()).as_bytes());
                    0
                }
                Err(e) => fail(&format!("listing tokens: {} {}", e.code, e.message)),
            }
        }
        "delete" => {
            let mut rc = 0;
            for id in ids {
                // Accept a full token too: only the id part names the Secret.
                let id = id.rsplit("::").next().unwrap_or(&id).split('.').next().unwrap_or("");
                if id.is_empty() || !id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) {
                    rc = fail(&format!("bad token id {id:?}"));
                    continue;
                }
                let path = format!("{SECRETS}/bootstrap-token-{id}");
                match kr_rt::exec::block_on({ let (r, p) = (remote.clone(), path.clone()); async move { r.delete(&p).await } }) {
                    Ok(_) => print(format!("bootstrap token \"{id}\" deleted\n").as_bytes()),
                    Err(e) => rc = fail(&format!("deleting {id}: {} {}", e.code, e.message)),
                }
            }
            rc
        }
        _ => rotate(&data, &remote, &hash, new_token),
    }
}

/// Replaces the server's join token: new `node-token` file, new Secret, old Secret deleted. The
/// running server follows the file within a few seconds (`keysync::watch_pki`); in HA the file
/// is replicated through key sync so every server serves the new token.
fn rotate(data: &str, remote: &alloc::rc::Rc<Remote>, hash: &str, new_token: Option<String>) -> i32 {
    let (old_id, _, _) = match current_node_token(data).map(|(_, id, s)| (id, s, ())) {
        Ok(t) => t,
        Err(e) => return fail(&e),
    };
    let (id, secret) = match new_token {
        Some(t) => match parse_new_token(&t, hash) {
            Ok(v) => v,
            Err(e) => return fail(e),
        },
        None => random_token(),
    };
    let token = format!("K10{hash}::{id}.{secret}\n");
    let Ok(obj) = kr_fmt::json::parse(secret_body(&id, &secret, None).as_bytes()) else { return fail("internal: bad secret") };
    // Secret first: a failure here leaves the old token fully working.
    if id != old_id {
        if let Err(e) = kr_rt::exec::block_on({ let (r, o) = (remote.clone(), obj.clone()); async move { r.create(SECRETS, &o).await } }) {
            if e.code != 409 {
                return fail(&format!("creating the token: {} {}", e.code, e.message));
            }
        }
    }
    let path = format!("{data}/node-token");
    let tmp = format!("{path}.new");
    let c = |s: &str| {
        let mut v = Vec::from(s.as_bytes());
        v.push(0);
        v
    };
    let _ = fs::unlinkat(fs::AT_FDCWD, &c(&tmp), 0);
    if let Err(e) = pki::write_new(&c(&tmp), token.as_bytes(), 0o600) {
        return fail(&e);
    }
    if let Err(e) = fs::renameat2(fs::AT_FDCWD, &c(&tmp), fs::AT_FDCWD, &c(&path), 0) {
        return fail(&format!("write {path}: errno {}", e.0));
    }
    if let Err(e) = crate::rotate::replicate_current(data, None, &["node-token"]) {
        return fail(&e);
    }
    if id != old_id {
        let old = format!("{SECRETS}/bootstrap-token-{old_id}");
        if let Err(e) = kr_rt::exec::block_on({ let (r, p) = (remote.clone(), old.clone()); async move { r.delete(&p).await } }) {
            if e.code != 404 {
                return fail(&format!("deleting the old token: {} {}", e.code, e.message));
            }
        }
    }
    print(token.as_bytes());
    0
}
