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

const USAGE: &[u8] = b"usage: kr pki rotate [--data DIR] [--port 6443] [--service-account-key] [--ca]
  Issues the API server serving certificate, the server and admin client certificates and
  admin.kubeconfig again (same names and addresses, new keys, 365 days). Restart `kr server` after.
  --service-account-key  also replace pki/sa.key (single server only; every token issued so far stops
                         verifying and pods get new ones when the kubelet refreshes them)
  --ca                   not implemented: see docs/KNOWN_ISSUES.md (CA rotation)
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
    while let Some(a) = args.next() {
        match a {
            b"--service-account-key" => sa = true,
            b"--ca" => {
                eprint(b"kr pki rotate: CA rotation is not implemented (docs/KNOWN_ISSUES.md); the leaf certificates can be rotated without --ca\n");
                return 2;
            }
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
    print(format!("rotated {} files; the old ones are in {aside}\nrestart `kr server` to serve the new certificate; admin.kubeconfig was written again ({data}/admin.kubeconfig)\n", moved.len()).as_bytes());
    Ok(())
}
