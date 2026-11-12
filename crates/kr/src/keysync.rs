//! HA key synchronisation, the file side (ADR-058): the applier every HA server runs, and the
//! helpers the CLI uses to publish a new generation and wait until all servers applied it.

use crate::{pki, rotate, server};
use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use kr_apiserver::cluster::keysync::{mode_of, Ack};
use kr_apiserver::cluster::Cluster;
use kr_fmt::json::Value;
use kr_rt::{eprint, print};
use kr_sys::fs;

/// Present while the leaf certificates still have to be issued again after a CA key change.
const REISSUE_MARKER: &str = "pki/.reissue";

fn cstr(s: &str) -> Vec<u8> {
    let mut v = Vec::from(s.as_bytes());
    v.push(0);
    v
}

fn read(data: &str, f: &str) -> Option<String> {
    fs::read_file(&cstr(&format!("{data}/{f}")), 1 << 20).ok().and_then(|b| String::from_utf8(b).ok())
}

fn digest(text: Option<String>) -> String {
    text.map(|t| kr_crypto::sha2::sha256(t.as_bytes())[..6].iter().map(|b| format!("{b:02x}")).collect()).unwrap_or_default()
}

/// The secret of the server token (the key-sync record is sealed under it).
pub fn token_secret(data: &str) -> Option<String> {
    read(data, "server-token")?.trim().split_once("::server:").map(|(_, s)| String::from(s))
}

/// Replaces `path` through a temporary file of the given mode (atomic, never half written).
fn put_file(data: &str, f: &str, text: &str, mode: u32) -> Result<(), String> {
    let path = format!("{data}/{f}");
    if let Some((dir, _)) = path.rsplit_once('/') {
        server::mkdir_p(dir)?;
    }
    let tmp = format!("{path}.new");
    let _ = fs::unlinkat(fs::AT_FDCWD, &cstr(&tmp), 0);
    pki::write_new(&cstr(&tmp), text.as_bytes(), mode)?;
    fs::renameat2(fs::AT_FDCWD, &cstr(&tmp), fs::AT_FDCWD, &cstr(&path), 0).map_err(|e| format!("write {path}: errno {}", e.0))
}

/// Writes the files of a record that differ from what is on disk; returns their names.
fn write_files(data: &str, files: &[(String, String)]) -> Result<Vec<String>, String> {
    let mut changed = Vec::new();
    for (f, content) in files {
        let Some(mode) = mode_of(f) else { continue };
        if read(data, f).as_deref() == Some(content.as_str()) {
            continue;
        }
        if f == "pki/ca.key" {
            // Written before the key, so a crash in between still reissues on the next pass.
            put_file(data, REISSUE_MARKER, "1\n", 0o600)?;
        }
        put_file(data, f, content, mode)?;
        changed.push(f.clone());
    }
    Ok(changed)
}

/// The signer from the files on disk: `sa.key` signs, every key in `sa-old.pem` verifies.
pub fn load_signer(data: &str) -> Result<(kr_apiserver::tokens::Signer, [u8; 32], String), String> {
    use kr_crypto::x509;
    let pki_dir = format!("{data}/pki");
    let pem = |f: &str| read(data, &format!("pki/{f}")).ok_or_else(|| format!("cannot read {pki_dir}/{f}"));
    let der = x509::pem_decode_all(&pem("sa.key")?, "PRIVATE KEY").ok().and_then(|mut v| v.pop()).ok_or("sa.key empty")?;
    let x509::SigningKey::P256(key) = x509::private_key_from_pkcs8(&der).map_err(|_| "sa.key unsupported")? else {
        return Err("sa.key must be a P-256 key".into());
    };
    let secret = key.to_bytes();
    let mut signer = kr_apiserver::tokens::Signer::new(key);
    if let Some(text) = read(data, "pki/sa-old.pem") {
        for der in x509::pem_decode_all(&text, "PRIVATE KEY").unwrap_or_default() {
            if let Ok(x509::SigningKey::P256(k)) = x509::private_key_from_pkcs8(&der) {
                signer.add_verify_key(&k);
            }
        }
    }
    Ok((signer, secret, pem("ca.pem")?))
}

fn my_ack(data: &str, gen: u64) -> Ack {
    let cfg = read(data, kr_apiserver::encrypt::FILE).and_then(|t| kr_apiserver::encrypt::Config::parse(t.as_bytes()).ok());
    let (keys, writes) = match &cfg {
        Some(c) => (c.keys.iter().map(|k| k.name.clone()).collect(), if c.identity_first { String::new() } else { c.keys.first().map(|k| k.name.clone()).unwrap_or_default() }),
        None => (Vec::new(), String::new()),
    };
    Ack { gen, keys, writes, ca: digest(read(data, "pki/ca.pem")), sa: digest(read(data, "pki/sa.key")) }
}

/// Applies a record: files first, then what can reload without a restart.
fn apply(api: &kr_apiserver::api::ApiServer, data: &str, rec: &kr_apiserver::cluster::keysync::Record) -> Result<(), String> {
    let changed = write_files(data, &rec.files)?;
    let touched = |f: &str| rec.file(f).is_some();
    // Reading before writing: the encryption config goes first, so the codec can read the keys.
    if touched(kr_apiserver::encrypt::FILE) {
        api.reload_encryption().map_err(|e| format!("encryption reload: {e}"))?;
    }
    if touched("pki/sa.key") || touched("pki/sa-old.pem") {
        let (signer, secret, ca_pem) = load_signer(data)?;
        kr_net::tls::set_ticket_secret(crate::server::ticket_secret(&secret));
        api.reload_service_accounts(signer, ca_pem);
    }
    if changed.iter().any(|f| f == "pki/ca.key" || f == "pki/ca.pem") {
        if let Ok((name, key, der)) = pki::load_ca(&format!("{data}/pki")) {
            api.set_ca(name, key, der);
        }
    }
    if !changed.is_empty() {
        print(format!("kr server: key sync generation {} applied ({}); {}\n", rec.gen, changed.join(", "), if changed.iter().any(|f| f.starts_with("pki/ca")) { "restart this server to trust and use the new CA" } else { "no restart needed" }).as_bytes());
    }
    Ok(())
}

fn reissue_pending(data: &str, port: u16) {
    if read(data, REISSUE_MARKER).is_none() {
        return;
    }
    match rotate::reissue(data, port) {
        Ok(()) => {
            let _ = fs::unlinkat(fs::AT_FDCWD, &cstr(&format!("{data}/{REISSUE_MARKER}")), 0);
            print(b"kr server: certificates issued again with the new CA; restart this server to use them\n");
        }
        Err(e) => eprint(format!("kr server: re-issuing the certificates failed: {e}; will retry\n").as_bytes()),
    }
}

async fn send_ack(data: &str, port: u16, ack: &Ack) -> Result<(), String> {
    use kr_apiserver::client::{Client, Remote, RemoteAuth};
    let pki_dir = format!("{data}/pki");
    let r = |f: &str| read(&pki_dir, f).ok_or_else(|| format!("cannot read {f}"));
    let remote = Remote::new(&format!("https://127.0.0.1:{port}"), RemoteAuth::ClientCert { chain: r("server.pem")?, key: r("server.key")? }, &r("ca.pem")?).map_err(|e| e.message)?;
    let body = kr_fmt::json::parse(ack.to_json().as_bytes()).map_err(|_| "ack")?;
    remote.create("/kr/keysync/ack", &body).await.map(|_| ()).map_err(|e| format!("{} {}", e.code, e.message))
}

/// The applier: every second, apply a newer record and acknowledge it.
pub async fn run(c: Rc<Cluster>, api: Rc<kr_apiserver::api::ApiServer>, data: String, port: u16) {
    let mut acked: u64 = 0;
    loop {
        kr_rt::exec::sleep(1000).await;
        let Some(secret) = token_secret(&data) else { continue };
        let gen = c.keysync_gen(&api);
        let mut local: u64 = read(&data, "keysync-gen").and_then(|t| t.trim().parse().ok()).unwrap_or(0);
        if gen > local {
            match c.keysync_record(&api, &secret) {
                Some(Ok(rec)) => match apply(&api, &data, &rec) {
                    Ok(()) => {
                        let _ = put_file(&data, "keysync-gen", &format!("{}\n", rec.gen), 0o600);
                        local = rec.gen;
                        // New joiners get the current material.
                        if let Ok(js) = server::join_secrets(&data) {
                            c.set_join_secrets(js);
                        }
                    }
                    Err(e) => {
                        eprint(format!("kr server: applying key sync generation {}: {e}; will retry\n", rec.gen).as_bytes());
                        continue;
                    }
                },
                Some(Err(e)) => {
                    eprint(format!("kr server: key sync record: {e}\n").as_bytes());
                    continue;
                }
                None => {}
            }
        }
        reissue_pending(&data, port);
        if local > 0 && acked < local {
            match send_ack(&data, port, &my_ack(&data, local)).await {
                Ok(()) => acked = local,
                Err(e) => eprint(format!("kr server: acknowledging key sync generation {local}: {e}; will retry\n").as_bytes()),
            }
        }
    }
}

// ---- CLI side ----

/// Publishes `files` as the next generation through the running server; returns the generation.
pub fn push(data: &str, server: &str, files: &[(&str, String)]) -> Result<u64, String> {
    use kr_apiserver::client::Client;
    let remote = crate::secrets_encrypt::admin_remote(data, server)?;
    let body = Value::Object(alloc::vec![(String::from("files"), Value::Object(files.iter().map(|(k, v)| (String::from(*k), Value::from(v.as_str()))).collect()))]);
    kr_rt::exec::block_on(async move { remote.create("/kr/keysync", &body).await.map_err(|e| format!("{} {}", e.code, e.message)) })
        .map_err(|e| format!("replicating to the cluster: {e}"))
        .and_then(|v| v.get("gen").and_then(Value::as_u64).ok_or_else(|| String::from("no generation in the answer")))
}

/// The cluster-wide view: generation, voters and what each server last acknowledged.
pub fn status(data: &str, server: &str) -> Result<Value, String> {
    use kr_apiserver::client::Client;
    let remote = crate::secrets_encrypt::admin_remote(data, server)?;
    kr_rt::exec::block_on(async move { remote.create("/kr/keysync/status", &Value::Object(Vec::new())).await.map_err(|e| format!("{} {}", e.code, e.message)) })
}

/// Waits until every voter acknowledged `gen`.
pub fn wait_acked(data: &str, server: &str, gen: u64, secs: u64) -> Result<(), String> {
    let deadline = kr_rt::exec::now_ms() + secs * 1000;
    loop {
        let st = status(data, server)?;
        let voters: Vec<u64> = st.get("voters").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_u64).collect()).unwrap_or_default();
        let servers = st.get("servers").and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
        let missing: Vec<String> = voters
            .iter()
            .filter(|v| !servers.iter().any(|s| s.get("id").and_then(Value::as_u64) == Some(**v) && s.get("gen").and_then(Value::as_u64).is_some_and(|g| g >= gen)))
            .map(|v| format!("{v}"))
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        if kr_rt::exec::now_ms() >= deadline {
            return Err(format!("generation {gen} was published but server(s) {} did not apply it within {secs} s (is every server running?)", missing.join(", ")));
        }
        kr_rt::exec::block_on(kr_rt::exec::sleep(1000));
    }
}
