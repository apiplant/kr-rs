//! `kr secrets-encrypt status|rotate-key|reencrypt|disable [--data DIR]` and the server's loading of
//! `<data>/encryption-config.json` (ADR-047, KNOWN_ISSUES #157).
//!
//! `status` and `rotate-key` only read or edit files and are safe next to a running server (a
//! restart applies a new config). `reencrypt` and `disable` rewrite the datastore: STOP the
//! server first. They rewrite `db/` as one snapshot with the first key (or plaintext), emptying the log, so old
//! ciphertext does not remain in it either. A single-server datastore only: an HA cluster keeps old
//! ciphertext in its Raft log until compaction (see KNOWN_ISSUES).

use crate::{pki, server};
use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use kr_apiserver::encrypt::{Config, Encryptor, FILE};
use kr_rt::{eprint, print, Args};
use kr_store::{Codec, Store};
use kr_sys::fs;

const USAGE: &str = "usage: kr secrets-encrypt status|rotate-key|reencrypt|disable [--data DIR] [--online [--server URL]]
  reencrypt --online  rewrites every stored object of the configured resources through the running API
                      server (no stop; in HA too, once every server runs the same key set)";

fn fail(msg: &str) -> i32 {
    eprint(b"kr secrets-encrypt: ");
    eprint(msg.as_bytes());
    eprint(b"\n");
    1
}

fn rng(b: &mut [u8]) {
    kr_sys::getrandom(b)
}

fn read_config(data: &str) -> Result<Option<Config>, String> {
    match fs::read_file(&pki::path(data, FILE), 1 << 20) {
        Ok(b) => Config::parse(&b).map(Some).map_err(|e| format!("{data}/{FILE}: {e}")),
        Err(kr_sys::Errno(2)) => Ok(None),
        Err(e) => Err(format!("read {data}/{FILE}: errno {}", e.0)),
    }
}

/// Replaces the config atomically (mode 0600).
fn write_config(data: &str, cfg: &Config) -> Result<(), String> {
    let tmp = pki::path(data, "encryption-config.json.tmp");
    let _ = fs::unlinkat(fs::AT_FDCWD, &tmp, 0);
    pki::write_new(&tmp, cfg.to_json().as_bytes(), 0o600)?;
    fs::renameat2(fs::AT_FDCWD, &tmp, fs::AT_FDCWD, &pki::path(data, FILE), 0).map_err(|e| format!("rename: errno {}", e.0))
}

/// The server's startup: the codec for the datastore, or `None` for no encryption.
/// A missing file is created with a fresh key unless `on` is false or `may_create` is false (a
/// joining server receives the file from the cluster; creating its own would split the keys).
pub fn load(data: &str, on: bool, may_create: bool) -> Result<Option<Rc<dyn Codec>>, String> {
    let cfg = match read_config(data)? {
        Some(c) => c,
        None if on && may_create => {
            let c = Config::generate(rng, pki::now());
            write_config(data, &c)?;
            print(format!("kr server: secrets encryption at rest enabled ({data}/{FILE}); back this file up with the datastore\n").as_bytes());
            c
        }
        None => return Ok(None),
    };
    Ok(Some(Rc::new(Encryptor::new(&cfg, rng))))
}

fn count_stored(data: &str, cfg: &Config) -> Result<Vec<(String, usize)>, String> {
    let db = format!("{data}/db");
    let snap = fs::read_file(&pki::path(&db, "snapshot"), usize::MAX >> 1).ok();
    let log = fs::read_file(&pki::path(&db, "log"), usize::MAX >> 1).unwrap_or_default();
    let st = Store::from_files(snap.as_deref(), &log).map_err(|e| format!("datastore: {e:?}"))?;
    let mut out: Vec<(String, usize)> = Vec::new();
    for p in cfg.prefixes() {
        for kv in st.list(&p, None, 0).0 {
            let label = match kv.value.strip_prefix(b"k8s:enc:aesgcm:v1:".as_slice()) {
                Some(r) => String::from_utf8_lossy(&r[..r.iter().position(|b| *b == b':').unwrap_or(0)]).into_owned(),
                None => String::from("plaintext"),
            };
            match out.iter_mut().find(|(l, _)| *l == label) {
                Some(e) => e.1 += 1,
                None => out.push((label, 1)),
            }
        }
    }
    Ok(out)
}

fn status(data: &str) -> Result<(), String> {
    let Some(cfg) = read_config(data)? else {
        print(b"secrets encryption: not configured (no encryption-config.json); values are stored in plaintext\n");
        return Ok(());
    };
    let mut s = format!("resources: {}\nwrites: {}\nkeys:\n", cfg.resources.join(", "), if cfg.identity_first { "plaintext (identity first; disabling)" } else { "encrypted with the first key" });
    for (i, k) in cfg.keys.iter().enumerate() {
        s.push_str(&format!("  {}{}\n", k.name, if i == 0 && !cfg.identity_first { "  (writes)" } else { "" }));
    }
    match count_stored(data, &cfg) {
        Ok(c) if c.is_empty() => s.push_str("stored objects: none\n"),
        Ok(c) => {
            s.push_str("stored objects (single-server datastore, as of its last written state):\n");
            for (l, n) in c {
                s.push_str(&format!("  {l}: {n}\n"));
            }
        }
        Err(_) => s.push_str("stored objects: not counted (no single-server datastore here)\n"),
    }
    print(s.as_bytes());
    Ok(())
}

fn reencrypt(data: &str, cfg: &Config) -> Result<usize, String> {
    if ns_exists(&format!("{data}/raft")) {
        return Err("this is an HA cluster: re-encrypting its Raft log is not supported yet (KNOWN_ISSUES); no-op update the Secrets with kubectl instead".into());
    }
    let codec: Rc<dyn Codec> = Rc::new(Encryptor::new(cfg, rng));
    let mut st = Store::open_with(&format!("{data}/db"), Some(codec)).map_err(|e| format!("open the datastore (is the server still running, or is the key wrong?): {e:?}"))?;
    let n: usize = cfg.prefixes().iter().map(|p| st.count(p)).sum();
    st.rewrite_log().map_err(|e| format!("rewrite: {e:?}"))?;
    Ok(n)
}

/// Rewrites every object of the configured resources through the API with the current key
/// (`?krReencrypt=true` makes the server write even though nothing else changed).
fn reencrypt_online(data: &str, cfg: &Config, server: &str) -> Result<usize, String> {
    use kr_apiserver::client::{Remote, RemoteAuth};
    let read = |f: &str| fs::read_file(&pki::path(&format!("{data}/pki"), f), 1 << 20).ok().and_then(|b| String::from_utf8(b).ok());
    let (Some(ca_pem), Some(chain), Some(key)) = (read("ca.pem"), read("admin.pem"), read("admin.key")) else {
        return Err("cannot read the server's admin credentials (run on the server, or pass --data)".into());
    };
    let remote = Remote::new(server, RemoteAuth::ClientCert { chain, key }, &ca_pem).map_err(|e| e.message)?;
    let resources = cfg.resources.clone();
    kr_rt::exec::block_on(async move {
        use kr_apiserver::client::Client;
        let mut done = 0usize;
        for spec in &resources {
            let (plural, group) = spec.split_once('.').unwrap_or((spec.as_str(), ""));
            let Some(res) = kr_apiserver::resources::RESOURCES.iter().find(|r| r.plural == plural && r.group == group) else {
                return Err(format!("{spec}: not a built-in resource; rewrite custom resources with no-op updates (kubectl) instead"));
            };
            let api_version = if group.is_empty() { String::from(res.version) } else { format!("{group}/{}", res.version) };
            let root = if group.is_empty() { format!("/api/{}", res.version) } else { format!("/apis/{api_version}") };
            let base = format!("{root}/{plural}");
            let list = remote.list(&base, "").await.map_err(|e| format!("list {spec}: {} {}", e.code, e.message))?;
            for item in list.get("items").and_then(kr_fmt::json::Value::as_array).unwrap_or(&[]) {
                let name = kr_apiserver::client::meta(item, "name");
                let ns = kr_apiserver::client::meta(item, "namespace");
                let path = if res.namespaced { format!("{root}/namespaces/{ns}/{plural}/{name}") } else { format!("{base}/{name}") };
                // The list gives items without kind/apiVersion; a conflict (changed meanwhile) is retried once with a fresh copy.
                for attempt in 0..2 {
                    let mut obj = if attempt == 0 { item.clone() } else { remote.get(&path).await.map_err(|e| format!("get {path}: {} {}", e.code, e.message))? };
                    obj.set("apiVersion", kr_fmt::json::Value::from(api_version.as_str()));
                    obj.set("kind", kr_fmt::json::Value::from(res.kind));
                    match remote.update(&format!("{path}?krReencrypt=true"), &obj).await {
                        Ok(_) => {
                            done += 1;
                            break;
                        }
                        Err(e) if e.code == 409 && attempt == 0 => continue,
                        Err(e) if e.code == 404 => break, // deleted meanwhile
                        Err(e) => return Err(format!("{path}: {} {}", e.code, e.message)),
                    }
                }
            }
        }
        Ok(done)
    })
}

fn ns_exists(p: &str) -> bool {
    fs::newfstatat(fs::AT_FDCWD, &pki::path(p, ""), fs::AT_SYMLINK_NOFOLLOW).is_ok()
}

pub fn main(mut args: Args) -> i32 {
    let Some(cmd) = args.next().map(|c| c.to_vec()) else { return fail(USAGE) };
    let mut data = server::data_dir();
    let (mut online, mut server_url) = (false, String::from("https://127.0.0.1:6443"));
    while let Some(a) = args.next() {
        if a == b"--online" {
            online = true;
            continue;
        }
        match (a, args.next().and_then(|v| core::str::from_utf8(v).ok())) {
            (b"--data", Some(d)) => data = String::from(d),
            (b"--server", Some(u)) => server_url = String::from(u.trim_end_matches('/')),
            _ => return fail(USAGE),
        }
    }
    let run = || -> Result<(), String> {
        let need = || read_config(&data)?.ok_or_else(|| format!("no {data}/{FILE}: start `kr server` once to create it"));
        match cmd.as_slice() {
            b"status" => status(&data),
            b"rotate-key" => {
                let mut cfg = need()?;
                let name = cfg.rotate(rng, pki::now());
                write_config(&data, &cfg)?;
                print(format!("added key {name} as the first key; restart `kr server` to use it, then run `kr secrets-encrypt reencrypt --online` (server running) to rewrite stored Secrets with it\n").as_bytes());
                Ok(())
            }
            b"reencrypt" if online => {
                let cfg = need()?;
                let n = reencrypt_online(&data, &cfg, &server_url)?;
                print(format!("rewrote {n} objects through the running server; they now use {} (in HA the old ciphertext stays in the Raft log until the next snapshot)\n", if cfg.identity_first { "plaintext" } else { &cfg.keys[0].name }).as_bytes());
                Ok(())
            }
            b"reencrypt" => {
                let cfg = need()?;
                let n = reencrypt(&data, &cfg)?;
                print(format!("rewrote the datastore: {n} objects now use {}\n", if cfg.identity_first { "plaintext" } else { &cfg.keys[0].name }).as_bytes());
                Ok(())
            }
            b"disable" => {
                let mut cfg = need()?;
                cfg.identity_first = true;
                write_config(&data, &cfg)?;
                let n = reencrypt(&data, &cfg)?;
                print(format!("{n} objects rewritten as plaintext; keys stay in {data}/{FILE} for reading. Start the server with the config as is, or delete the file together with --secrets-encryption off\n").as_bytes());
                Ok(())
            }
            _ => Err(String::from(USAGE)),
        }
    };
    match run() {
        Ok(()) => 0,
        Err(e) => fail(&e),
    }
}
