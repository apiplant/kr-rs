//! `kr snapshot save|restore` and scheduled snapshots (`kr server --snapshot-interval`).
//!
//! The archive is a tarball (`kr_store::bundle`) holding `kr-snapshot/store` (a `Store::image`,
//! the `KRSNAP1` format of ADR-006), `META`, and the key material a restore on a new machine
//! needs: `pki/ca.pem`, `pki/ca.key`, `pki/sa.key`, `node-token`, `server-token` and, when secrets encryption is on, `encryption-config.json` (ADR-043, ADR-047).
//!
//! A running server is captured from its files, read-only: a single-server `db/` (snapshot +
//! log, the log's torn tail is ignored) or an HA `raft/` (copied to a scratch directory, replayed
//! with `kr-raft`'s own storage code on top of the Raft snapshot). Neither needs the server to
//! cooperate, and neither writes into the live directories.

use crate::{pki, server};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use kr_rt::{eprint, print, Args};
use kr_store::bundle::{self, Member};
use kr_store::Store;
use kr_sys::{fs, ns, Errno};

const USAGE: &[u8] = b"usage:
  kr snapshot save <file> [--data DIR] [--committed-only]
  kr snapshot restore <file> [--data DIR] [--force]
";
const PREFIX: &str = "kr-snapshot/";
/// (path relative to the data dir, mode, required)
const KEYS: [(&str, u32, bool); 6] = [("pki/ca.pem", 0o644, true), ("pki/ca.key", 0o600, true), ("pki/sa.key", 0o600, true), ("node-token", 0o600, false), ("server-token", 0o600, false), ("encryption-config.json", 0o600, false)];
/// State a restore replaces (and `--force` moves aside).
const STATE: [&str; 9] = ["db", "raft", "pki", "server-id", "node-token", "server-token", "admin.kubeconfig", "db.imported", "encryption-config.json"];
const LIMIT: usize = 1 << 31;

fn utf8(b: &[u8]) -> Result<String, String> {
    core::str::from_utf8(b).map(String::from).map_err(|_| String::from("argument is not UTF-8"))
}

fn cstr(s: &str) -> Vec<u8> {
    let mut v = Vec::from(s.as_bytes());
    v.push(0);
    v
}

/// The whole file, `None` if it does not exist.
fn read_opt(p: &str) -> Result<Option<Vec<u8>>, String> {
    match fs::read_file(&cstr(p), LIMIT) {
        Ok(b) => Ok(Some(b)),
        Err(Errno(fs::ENOENT)) => Ok(None),
        Err(e) => Err(format!("read {p}: errno {}", e.0)),
    }
}

fn exists(p: &str) -> bool {
    fs::newfstatat(fs::AT_FDCWD, &cstr(p), fs::AT_SYMLINK_NOFOLLOW).is_ok()
}

/// Reads `files` of `dir` twice around each other; a compaction in between (the snapshot file
/// was replaced) makes the read inconsistent, so it is repeated.
fn stable_read(dir: &str, files: &[&str]) -> Result<Vec<Option<Vec<u8>>>, String> {
    for _ in 0..8 {
        let first = read_opt(&format!("{dir}/{}", files[0]))?;
        let mut rest = Vec::new();
        for f in &files[1..] {
            rest.push(read_opt(&format!("{dir}/{f}"))?);
        }
        if read_opt(&format!("{dir}/{}", files[0]))? == first {
            let mut all = alloc::vec![first];
            all.extend(rest);
            return Ok(all);
        }
    }
    Err(format!("{dir} keeps changing under compaction; try again"))
}

/// The store image and its revision, plus whether it came from an HA data dir.
pub fn capture_store(data: &str, committed_only: bool) -> Result<(Vec<u8>, u64, bool), String> {
    let raft = format!("{data}/raft");
    if exists(&format!("{raft}/log")) || exists(&format!("{raft}/hardstate")) || exists(&format!("{raft}/snapshot")) {
        let f = stable_read(&raft, &["snapshot", "log", "hardstate"])?;
        let scratch = format!("{data}/snapshot.tmp.{}", fs::getpid());
        let _ = remove_dir(data, &format!("snapshot.tmp.{}", fs::getpid()));
        server::mkdir_p(&scratch)?;
        let r = (|| {
            for (name, content) in ["snapshot", "log", "hardstate"].iter().zip(&f) {
                if let Some(c) = content {
                    pki::write_new(&pki::path(&scratch, name), c, 0o600)?;
                }
            }
            replay_raft(&scratch, committed_only)
        })();
        let _ = remove_dir(data, &format!("snapshot.tmp.{}", fs::getpid()));
        let (img, rev) = r?;
        return Ok((img, rev, true));
    }
    let db = format!("{data}/db");
    let f = stable_read(&db, &["snapshot", "log"])?;
    if f[0].is_none() && f[1].is_none() {
        return Err(format!("no datastore in {db}"));
    }
    let s = Store::from_files(f[0].as_deref(), f[1].as_deref().unwrap_or(&[])).map_err(|e| format!("datastore: {e:?}"))?;
    Ok((s.image(), s.revision(), false))
}

fn remove_dir(parent: &str, name: &str) -> Result<(), Errno> {
    let d = fs::openat(fs::AT_FDCWD, &cstr(parent), fs::O_RDONLY | fs::O_DIRECTORY | fs::O_CLOEXEC, 0)?;
    fs::remove_all(d.raw(), &cstr(name))
}

/// Raft snapshot + log entries on top of it, applied to a store like a follower would.
fn replay_raft(dir: &str, committed_only: bool) -> Result<(Vec<u8>, u64), String> {
    let (_st, loaded) = kr_raft::storage::Storage::open(dir).map_err(|e| format!("raft storage: {e:?}"))?;
    let mut store = Store::replicated();
    if let Some(s) = &loaded.snapshot {
        store.restore(&s.data).map_err(|e| format!("raft snapshot: {e:?}"))?;
    }
    for e in &loaded.entries {
        if committed_only && e.index > loaded.hard_state.commit {
            break;
        }
        if e.kind == kr_raft::EntryKind::Normal && !e.data.is_empty() {
            if let Err(err) = store.apply_records(&e.data) {
                eprint(format!("kr snapshot: warning: log entry {} does not apply ({err:?}); the archive ends before it\n", e.index).as_bytes());
                break;
            }
        }
    }
    Ok((store.image(), store.revision()))
}

/// Everything the archive holds.
pub fn build(data: &str, committed_only: bool) -> Result<(Vec<u8>, u64), String> {
    let (img, rev, ha) = capture_store(data, committed_only)?;
    let now = pki::now();
    let meta = format!("kr-snapshot 1\nmode={}\nrevision={rev}\ncreated={now}\nstore-bytes={}\n", if ha { "ha" } else { "single" }, img.len());
    let m = |n: &str, mode: u32, data: Vec<u8>| Member { name: format!("{PREFIX}{n}"), mode, data };
    let mut members = alloc::vec![m("META", 0o600, meta.into_bytes()), m("store", 0o600, img)];
    for (f, mode, required) in KEYS {
        match read_opt(&format!("{data}/{f}"))? {
            Some(b) => members.push(m(f, mode.min(0o600), b)),
            None if required => return Err(format!("{data}/{f} is missing; is {data} a kr server data dir?")),
            None => {}
        }
    }
    Ok((bundle::encode(&members, now.max(0) as u64), rev))
}

/// Writes `bytes` to `file` (mode 0600) atomically: temp file, fsync, rename.
pub fn write_file(file: &str, bytes: &[u8]) -> Result<(), String> {
    let tmp = format!("{file}.tmp");
    let _ = fs::unlinkat(fs::AT_FDCWD, &cstr(&tmp), 0);
    pki::write_new(&cstr(&tmp), bytes, 0o600)?;
    let fd = fs::openat(fs::AT_FDCWD, &cstr(&tmp), fs::O_RDONLY | fs::O_CLOEXEC, 0).map_err(|e| format!("open {tmp}: errno {}", e.0))?;
    fs::fsync(fd.raw()).map_err(|e| format!("fsync {tmp}: errno {}", e.0))?;
    fs::renameat2(fs::AT_FDCWD, &cstr(&tmp), fs::AT_FDCWD, &cstr(file), 0).map_err(|e| format!("rename {tmp}: errno {}", e.0))
}

pub fn main(mut args: Args) -> i32 {
    let sub = args.next();
    let r = match sub {
        Some(b"save") => save(args),
        Some(b"restore") => restore(args),
        _ => Err((String::from("unknown subcommand"), true)),
    };
    match r {
        Ok(()) => 0,
        Err((e, usage)) => {
            eprint(b"kr snapshot: ");
            eprint(e.as_bytes());
            eprint(b"\n");
            if usage {
                eprint(USAGE);
            }
            if usage { 2 } else { 1 }
        }
    }
}

type R = Result<(), (String, bool)>;

fn parse(mut args: Args, flags: &[&str]) -> Result<(String, Option<String>, Vec<String>), (String, bool)> {
    let u = |e: String| (e, true);
    let file = utf8(args.next().ok_or_else(|| u("missing <file>".into()))?).map_err(u)?;
    let (mut data, mut set) = (None, Vec::new());
    while let Some(a) = args.next() {
        let a = utf8(a).map_err(u)?;
        if a == "--data" {
            data = Some(utf8(args.next().ok_or_else(|| u("--data needs a value".into()))?).map_err(u)?);
        } else if flags.contains(&a.as_str()) {
            set.push(a);
        } else {
            return Err(u(format!("unknown flag {a}")));
        }
    }
    Ok((file, data, set))
}

fn save(args: Args) -> R {
    let (file, data, flags) = parse(args, &["--committed-only"])?;
    let data = data.unwrap_or_else(server::data_dir);
    let (bytes, rev) = build(&data, !flags.is_empty()).map_err(|e| (e, false))?;
    write_file(&file, &bytes).map_err(|e| (e, false))?;
    print(format!("{file}: revision {rev}, {} bytes (contains the cluster CA and service-account keys: keep it private)\n", bytes.len()).as_bytes());
    Ok(())
}

fn restore(args: Args) -> R {
    let (file, data, flags) = parse(args, &["--force"])?;
    let (data, force) = (data.unwrap_or_else(server::data_dir), !flags.is_empty());
    let e = |m: String| (m, false);
    let raw = read_opt(&file).map_err(e)?.ok_or_else(|| e(format!("{file}: no such file")))?;
    let members = bundle::decode(&raw).map_err(|x| e(format!("{file}: {x:?}")))?;
    let get = |n: &str| members.iter().find(|m| m.name.strip_prefix(PREFIX) == Some(n));
    let meta = get("META").map(|m| String::from_utf8_lossy(&m.data).into_owned()).unwrap_or_default();
    if !meta.starts_with("kr-snapshot 1\n") {
        return Err(e(format!("{file} is not a kr snapshot (or a newer format)")));
    }
    let store = get("store").ok_or_else(|| e("archive has no store".into()))?;
    // Validate everything before touching the data dir.
    Store::in_memory().restore(&store.data).map_err(|x| e(format!("the datastore image is damaged: {x:?}")))?;
    for (f, _, required) in KEYS {
        if required && get(f).is_none() {
            return Err(e(format!("archive lacks {f}")));
        }
    }
    for m in &members {
        let n = m.name.strip_prefix(PREFIX).unwrap_or("");
        if n != "META" && n != "store" && !KEYS.iter().any(|k| k.0 == n) {
            return Err(e(format!("unexpected archive member {}", m.name)));
        }
    }
    // Refuse a running server (it holds the kubelet lock for its root).
    if let Ok(st) = kr_runtime::store::Store::open(None) {
        if let Ok(fd) = ns::open(&cstr(&format!("{}/kubelet.lock", st.root())), ns::O_RDWR | ns::O_CREAT | kr_sys::O_CLOEXEC, 0o600) {
            if ns::flock_exclusive_nb(fd.raw()).is_err() {
                return Err(e("a kr server or agent is running on this machine; stop it first".into()));
            }
        }
    }
    server::mkdir_p(&data).map_err(e)?;
    let present: Vec<&str> = STATE.iter().copied().filter(|s| exists(&format!("{data}/{s}"))).collect();
    if !present.is_empty() {
        if !force {
            return Err(e(format!("{data} is not empty ({}); stop the server and pass --force to move that state aside", present.join(", "))));
        }
        let aside = format!("{data}/pre-restore-{}", pki::now());
        server::mkdir_p(&aside).map_err(e)?;
        for s in &present {
            fs::renameat2(fs::AT_FDCWD, &cstr(&format!("{data}/{s}")), fs::AT_FDCWD, &cstr(&format!("{aside}/{s}")), 0).map_err(|x| e(format!("move {s} aside: errno {}", x.0)))?;
        }
        print(format!("previous state moved to {aside}\n").as_bytes());
    }
    server::mkdir_p(&format!("{data}/db")).map_err(e)?;
    server::mkdir_p(&format!("{data}/pki")).map_err(e)?;
    let w = |rel: &str, bytes: &[u8], mode: u32| pki::write_new(&pki::path(&data, rel), bytes, mode).map_err(e);
    w("db/snapshot", &store.data, 0o644)?;
    w("db/log", &[], 0o644)?;
    for (f, mode, _) in KEYS {
        if let Some(m) = get(f) {
            w(f, &m.data, mode)?;
        }
    }
    pki::load_ca(&format!("{data}/pki")).map_err(|x| e(format!("restored CA is unusable: {x}")))?;
    let rev = meta.lines().find_map(|l| l.strip_prefix("revision=")).unwrap_or("?");
    print(format!("restored revision {rev} into {data}\nstart it with `kr server` (single server) or `kr server --cluster-init` (new one-member HA cluster); serving certificates and admin.kubeconfig are issued again on start\n").as_bytes());
    Ok(())
}

/// `30`, `30s`, `15m`, `6h`, `1d` in seconds.
pub fn parse_duration(s: &str) -> Option<u64> {
    let (n, mul) = match s.as_bytes().last()? {
        b's' => (&s[..s.len() - 1], 1),
        b'm' => (&s[..s.len() - 1], 60),
        b'h' => (&s[..s.len() - 1], 3600),
        b'd' => (&s[..s.len() - 1], 86400),
        _ => (s, 1),
    };
    n.parse::<u64>().ok().filter(|v| *v > 0).and_then(|v| v.checked_mul(mul))
}

/// Writes `<data>/snapshots/kr-snapshot-<unix time>.tar` every `interval_s` seconds and keeps
/// the newest `keep`.
pub async fn schedule(data: String, interval_s: u64, keep: usize) {
    let dir = format!("{data}/snapshots");
    loop {
        kr_rt::exec::sleep(interval_s.saturating_mul(1000)).await;
        let r = server::mkdir_p(&dir).and_then(|_| build(&data, false)).and_then(|(b, rev)| {
            let f = format!("{dir}/kr-snapshot-{:012}.tar", pki::now());
            write_file(&f, &b).map(|_| (f, rev))
        });
        match r {
            Ok((f, rev)) => print(format!("kr server: wrote snapshot {f} (revision {rev})\n").as_bytes()),
            Err(e) => eprint(format!("kr server: scheduled snapshot failed: {e}\n").as_bytes()),
        }
        prune(&dir, keep);
    }
}

fn prune(dir: &str, keep: usize) {
    let Ok(fd) = fs::openat(fs::AT_FDCWD, &cstr(dir), fs::O_RDONLY | fs::O_DIRECTORY | fs::O_CLOEXEC, 0) else { return };
    let mut names: Vec<Vec<u8>> = fs::read_dir(&fd).filter_map(|e| e.ok()).map(|e| e.name).filter(|n| n.starts_with(b"kr-snapshot-") && n.ends_with(b".tar")).collect();
    names.sort();
    let n = names.len().saturating_sub(keep);
    for name in &names[..n] {
        let mut c = name.clone();
        c.push(0);
        let _ = fs::unlinkat(fd.raw(), &c, 0);
    }
}
