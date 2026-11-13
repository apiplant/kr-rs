//! `kr pki rotate` / `kr certificate rotate`: issues the leaf certificates of a server again
//! (ADR-043). The CA and (unless asked) the service-account key stay. Run it on the server's
//! machine, then restart `kr server`: pods keep running (ADR-036).
//!
//! Replaced: `pki/apiserver.*` (serving certificate), `pki/kubelet-client.*`, `pki/admin.*` with
//! `admin.kubeconfig`, and in HA `pki/server.*` (Raft transport). The old files are moved to
//! `pki/rotated-<time>/`. Agents' node certificates rotate by themselves (ADR-013).

use crate::{pki, server};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use kr_rt::{eprint, print, Args};
use kr_sys::fs;

const USAGE: &[u8] = b"usage: kr pki rotate [--data DIR] [--port 6443] [--service-account-key] [--ca prepare|activate|finish [--yes]]
  Issues the API server serving certificate, the server and admin client certificates and
  admin.kubeconfig again (same names and addresses, new keys, 365 days). Restart `kr server` after.
  --service-account-key  also replace pki/sa.key (single server only). The old key is kept in
                         pki/sa-old.pem, so tokens issued so far keep verifying until you delete that
                         file and restart; new tokens are signed with the new key
  --ca prepare           (server stopped, single server) creates a new CA and puts both in ca.pem (old
                         first, signing unchanged). Then copy pki/ca.pem to every agent's pki/ca.pem and
                         restart the server and the agents.
  --ca activate          signs with the new CA from now on: re-issues the server certificates and
                         admin.kubeconfig and updates node-token. Old client certificates stay valid.
                         Restart the server; nodes renew their certificates with the new CA.
  --ca finish --yes      drops the old CA from ca.pem once every node certificate was renewed
                         (a node certificate of the old CA stops working); copy ca.pem to the agents.
";

fn cstr(s: &str) -> Vec<u8> {
    let mut v = Vec::from(s.as_bytes());
    v.push(0);
    v
}

fn exists(p: &str) -> bool {
    fs::newfstatat(fs::AT_FDCWD, &cstr(p), fs::AT_SYMLINK_NOFOLLOW).is_ok()
}

/// The port in `server: https://HOST:PORT` of an existing kubeconfig.
pub fn kubeconfig_port(text: &str) -> Option<u16> {
    let line = text.lines().find_map(|l| l.trim().strip_prefix("server:"))?;
    line.trim().rsplit(':').next()?.trim_matches('/').parse().ok()
}

pub fn main(mut args: Args) -> i32 {
    let (mut data, mut port, mut sa) = (None, None, false);
    let (mut ca_phase, mut yes) = (None::<String>, false);
    while let Some(a) = args.next() {
        match a {
            b"--service-account-key" => sa = true,
            b"--ca" => {
                let Some(v) = args.next().and_then(|v| core::str::from_utf8(v).ok()) else { return usage("--ca needs prepare, activate or finish") };
                if !matches!(v, "prepare" | "activate" | "finish") {
                    return usage("--ca needs prepare, activate or finish");
                }
                ca_phase = Some(String::from(v));
            }
            b"--yes" => yes = true,
            b"--data" | b"--port" => {
                let Some(v) = args.next().and_then(|v| core::str::from_utf8(v).ok()) else { return usage("flag needs a value") };
                if a == b"--data" {
                    data = Some(String::from(v));
                } else {
                    match v.parse::<u16>() {
                        Ok(p) => port = Some(p),
                        Err(_) => return usage("bad --port"),
                    }
                }
            }
            _ => return usage("unknown argument"),
        }
    }
    let data = data.unwrap_or_else(server::data_dir);
    if let Some(phase) = ca_phase {
        return match rotate_ca(&data, port, &phase, yes) {
            Ok(()) => 0,
            Err(e) => {
                eprint(format!("kr pki rotate --ca {phase}: {e}\n").as_bytes());
                1
            }
        };
    }
    match run(&data, port, sa) {
        Ok(()) => 0,
        Err(e) => {
            eprint(format!("kr pki rotate: {e}\n").as_bytes());
            1
        }
    }
}

fn usage(m: &str) -> i32 {
    eprint(format!("kr pki rotate: {m}\n").as_bytes());
    eprint(USAGE);
    2
}

fn read_text(p: &str) -> Result<String, String> {
    fs::read_file(&cstr(p), 1 << 20).map_err(|e| format!("read {p}: errno {}", e.0)).and_then(|b| String::from_utf8(b).map_err(|_| format!("{p} is not UTF-8")))
}

/// Replaces `path` with `text` through a temporary file of the given mode.
fn put(path: &str, text: &str, mode: u32) -> Result<(), String> {
    let tmp = format!("{path}.new");
    let _ = fs::unlinkat(fs::AT_FDCWD, &cstr(&tmp), 0);
    pki::write_new(&cstr(&tmp), text.as_bytes(), mode)?;
    fs::renameat2(fs::AT_FDCWD, &cstr(&tmp), fs::AT_FDCWD, &cstr(path), 0).map_err(|e| format!("write {path}: errno {}", e.0))
}

fn certs_of(pem: &str) -> Result<Vec<Vec<u8>>, String> {
    kr_crypto::x509::pem_decode_all(pem, "CERTIFICATE").map_err(|_| String::from("bad PEM"))
}

/// Cluster CA rotation in three steps (see the USAGE text). Single server, server stopped.
fn rotate_ca(data: &str, port: Option<u16>, phase: &str, yes: bool) -> Result<(), String> {
    use kr_crypto::x509;
    let pki_dir = format!("{data}/pki");
    if exists(&format!("{data}/raft")) {
        return Err("CA rotation in an HA cluster is not supported yet (docs/KNOWN_ISSUES.md)".into());
    }
    pki::load_ca(&pki_dir)?;
    let (ca_pem, ca_key) = (format!("{pki_dir}/ca.pem"), format!("{pki_dir}/ca.key"));
    let (next_pem, next_key) = (format!("{pki_dir}/ca-next.pem"), format!("{pki_dir}/ca-next.key"));
    let (old_pem, old_key) = (format!("{pki_dir}/ca-old.pem"), format!("{pki_dir}/ca-old.key"));
    match phase {
        "prepare" => {
            if exists(&next_pem) || exists(&old_pem) {
                return Err("a rotation is already under way (pki/ca-next.pem or pki/ca-old.pem exists); run activate or finish".into());
            }
            let tmp = format!("{pki_dir}/next-ca");
            let _ = fs::unlinkat(fs::AT_FDCWD, &cstr(&format!("{tmp}/ca.pem")), 0);
            let _ = fs::unlinkat(fs::AT_FDCWD, &cstr(&format!("{tmp}/ca.key")), 0);
            pki::create_ca(&tmp, "kr-cluster-ca".into(), 3650)?;
            let new_cert = read_text(&format!("{tmp}/ca.pem"))?;
            for (from, to) in [(format!("{tmp}/ca.pem"), &next_pem), (format!("{tmp}/ca.key"), &next_key)] {
                fs::renameat2(fs::AT_FDCWD, &cstr(&from), fs::AT_FDCWD, &cstr(to), 0).map_err(|e| format!("move {from}: errno {}", e.0))?;
            }
            let _ = fs::unlinkat(fs::AT_FDCWD, &cstr(&tmp), fs::AT_REMOVEDIR);
            let old = read_text(&ca_pem)?;
            put(&ca_pem, &format!("{old}{new_cert}"), 0o644)?;
            print(format!("prepared: pki/ca.pem now holds the old and the new CA (the old one still signs).\n1. copy {ca_pem} to pki/ca.pem on every agent\n2. restart the server, then the agents (rolling)\n3. run `kr pki rotate --ca activate`\n").as_bytes());
        }
        "activate" => {
            if !exists(&next_pem) {
                return Err("run `kr pki rotate --ca prepare` first".into());
            }
            let bundle = read_text(&ca_pem)?;
            let next = read_text(&next_pem)?;
            let next_der = certs_of(&next)?.into_iter().next().ok_or("ca-next.pem is empty")?;
            let certs = certs_of(&bundle)?;
            if !certs.contains(&next_der) {
                return Err("pki/ca.pem does not contain the new CA: was it replaced after prepare?".into());
            }
            let old_der = certs.iter().find(|c| **c != next_der).ok_or("pki/ca.pem has no old CA")?.clone();
            // Keep the old CA aside; sign with the new one (first in the bundle, ca.key).
            let old_key_text = read_text(&ca_key)?;
            put(&old_pem, &x509::pem_encode("CERTIFICATE", &old_der), 0o644)?;
            put(&old_key, &old_key_text, 0o600)?;
            put(&ca_pem, &format!("{next}{}", x509::pem_encode("CERTIFICATE", &old_der)), 0o644)?;
            put(&ca_key, &read_text(&next_key)?, 0o600)?;
            let _ = fs::unlinkat(fs::AT_FDCWD, &cstr(&next_pem), 0);
            let _ = fs::unlinkat(fs::AT_FDCWD, &cstr(&next_key), 0);
            // New joins pin the new CA.
            let token_path = format!("{data}/node-token");
            let token = read_text(&token_path)?;
            let (_, rest) = token.trim().split_once("::").ok_or("bad node-token")?;
            let hash: String = kr_crypto::sha2::sha256(&next_der).iter().map(|b| format!("{b:02x}")).collect();
            put(&token_path, &format!("K10{hash}::{rest}\n"), 0o600)?;
            run(data, port, false)?;
            print(b"activated: the new CA signs from now on; restart the server. Nodes keep their old certificates until they renew (the server still trusts the old CA); run `kr pki rotate --ca finish --yes` after every node certificate was renewed.\n");
        }
        _ => {
            if !exists(&old_pem) {
                return Err("nothing to finish: run prepare and activate first".into());
            }
            if !yes {
                return Err("this drops the old CA: a node certificate or kubelet certificate signed by it stops working. Run again with --yes once every node renewed".into());
            }
            let first = certs_of(&read_text(&ca_pem)?)?.into_iter().next().ok_or("pki/ca.pem is empty")?;
            put(&ca_pem, &x509::pem_encode("CERTIFICATE", &first), 0o644)?;
            let aside = format!("{pki_dir}/rotated-ca-{}", pki::now());
            server::mkdir_p(&aside)?;
            for (f, name) in [(&old_pem, "ca.pem"), (&old_key, "ca.key")] {
                fs::renameat2(fs::AT_FDCWD, &cstr(f), fs::AT_FDCWD, &cstr(&format!("{aside}/{name}")), 0).map_err(|e| format!("move {f}: errno {}", e.0))?;
            }
            print(format!("finished: pki/ca.pem holds only the new CA (the old CA and key are in {aside}). Copy it to the agents and restart the server.\n").as_bytes());
        }
    }
    Ok(())
}

fn run(data: &str, port: Option<u16>, sa: bool) -> Result<(), String> {
    let pki_dir = format!("{data}/pki");
    if !exists(&format!("{pki_dir}/ca.pem")) {
        return Err(format!("{pki_dir}/ca.pem not found: is {data} a kr server data dir?"));
    }
    pki::load_ca(&pki_dir)?;
    let ha = exists(&format!("{data}/raft"));
    if sa && ha {
        return Err("--service-account-key in HA would leave the other servers with the old key; not supported yet (docs/KNOWN_ISSUES.md)".into());
    }
    let port = port
        .or_else(|| fs::read_file(&cstr(&format!("{data}/admin.kubeconfig")), 1 << 20).ok().and_then(|b| kubeconfig_port(&String::from_utf8_lossy(&b))))
        .unwrap_or(6443);
    let aside = format!("{pki_dir}/rotated-{}", pki::now());
    server::mkdir_p(&aside)?;
    let mut moved: Vec<(String, String)> = Vec::new();
    let mut files: Vec<String> = ["apiserver", "kubelet-client", "admin"].iter().flat_map(|n| [format!("pki/{n}.pem"), format!("pki/{n}.key")]).collect();
    if ha {
        files.push("pki/server.pem".into());
        files.push("pki/server.key".into());
    }
    files.push("admin.kubeconfig".into());
    if sa {
        files.push("pki/sa.key".into());
    }
    let result = (|| {
        for f in &files {
            let (from, to) = (format!("{data}/{f}"), format!("{aside}/{}", f.rsplit('/').next().unwrap_or(f)));
            if exists(&from) {
                fs::renameat2(fs::AT_FDCWD, &cstr(&from), fs::AT_FDCWD, &cstr(&to), 0).map_err(|e| format!("move {f}: errno {}", e.0))?;
                moved.push((from, to));
            }
        }
        server::bootstrap(data, port, ha)?;
        if ha {
            server::server_identity(data, server::primary_addr())?;
        }
        Ok::<(), String>(())
    })();
    if let Err(e) = result {
        // Put the old files back so the server still starts.
        for (from, to) in moved.iter().rev() {
            let _ = fs::unlinkat(fs::AT_FDCWD, &cstr(from), 0);
            let _ = fs::renameat2(fs::AT_FDCWD, &cstr(to), fs::AT_FDCWD, &cstr(from), 0);
        }
        return Err(format!("{e} (nothing was changed)"));
    }
    if sa {
        // Keep the old signing key as a verify-only key (the overlap k3s's rotate-ca also offers).
        let old = fs::read_file(&cstr(&format!("{aside}/sa.key")), 1 << 16).map_err(|e| format!("read the old sa.key: errno {}", e.0))?;
        let path = format!("{pki_dir}/sa-old.pem");
        let mut text = fs::read_file(&cstr(&path), 1 << 20).unwrap_or_default();
        text.extend_from_slice(&old);
        // A temporary file with mode 0600, then renamed over the old list.
        let tmp = format!("{path}.new");
        let _ = fs::unlinkat(fs::AT_FDCWD, &cstr(&tmp), 0);
        pki::write_new(&cstr(&tmp), &text, 0o600).map_err(|e| format!("cannot write pki/sa-old.pem ({e}); the old key is in {aside}"))?;
        fs::renameat2(fs::AT_FDCWD, &cstr(&tmp), fs::AT_FDCWD, &cstr(&path), 0).map_err(|e| format!("cannot write pki/sa-old.pem (errno {}); the old key is in {aside}", e.0))?;
    }
    print(format!("rotated {} files; the old ones are in {aside}\nrestart `kr server` to serve the new certificate; admin.kubeconfig was written again ({data}/admin.kubeconfig)\n", moved.len()).as_bytes());
    Ok(())
}
