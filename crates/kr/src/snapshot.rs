//! `kr snapshot save|restore|list|delete` and scheduled snapshots (`kr server --snapshot-interval`),
//! optionally also to S3-compatible storage (`--snapshot-s3*` on the server, `--s3*` on the CLI;
//! ADR-061).
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
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_net::registry::RegConnector;
use kr_net::s3::{Creds, S3Config, S3};
use kr_rt::{eprint, print, Args};
use kr_store::bundle::{self, Member};
use kr_store::Store;
use kr_sys::{fs, ns, Errno};

const USAGE: &[u8] = b"usage:
  kr snapshot save [<file>] [--data DIR] [--committed-only] [S3]   (<file> is optional with --s3: upload only)
  kr snapshot restore <file> [--data DIR] [--force]
  kr snapshot restore --s3 <name> [S3] [--data DIR] [--force]
  kr snapshot list [--data DIR] [S3]
  kr snapshot delete <name> [--data DIR] [S3]    (the S3 object with --s3, else the local snapshot)
S3: --s3 [--s3-endpoint HOST[:PORT]|URL] --s3-bucket B [--s3-folder DIR] [--s3-region R] [--s3-access-key K] [--s3-secret-key S]
    [--s3-session-token T] [--s3-insecure] [--s3-endpoint-ca FILE] [--s3-skip-ssl-verify]
    (credentials default to $KR_S3_ACCESS_KEY / $KR_S3_SECRET_KEY / $KR_S3_SESSION_TOKEN, then the AWS_* variables)
";
const PREFIX: &str = "kr-snapshot/";
/// (path relative to the data dir, mode, required)
const KEYS: [(&str, u32, bool); 7] = [("pki/ca.pem", 0o644, true), ("pki/ca.key", 0o600, true), ("pki/sa.key", 0o600, true), ("pki/sa-old.pem", 0o600, false), ("node-token", 0o600, false), ("server-token", 0o600, false), ("encryption-config.json", 0o600, false)];
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

/// `--snapshot-s3*` (server) or `--s3*` (CLI) options, collected while parsing arguments.
#[derive(Default, Clone)]
pub struct S3Opts {
    enabled: bool,
    endpoint: String,
    endpoint_ca: Option<String>,
    bucket: String,
    folder: String,
    region: String,
    access_key: Option<String>,
    secret_key: Option<String>,
    session_token: Option<String>,
    insecure: bool,
    skip_verify: bool,
}

/// What a validated [`S3Opts`] resolves to.
#[derive(Clone)]
pub struct S3Settings {
    cfg: S3Config,
    ca_pem: Option<String>,
    skip_verify: bool,
}

/// Flags without a value (they must not swallow the next argument).
pub fn is_s3_bool_flag(flag: &[u8], prefix: &str) -> bool {
    flag == prefix.as_bytes() || flag == format!("{prefix}-insecure").as_bytes() || flag == format!("{prefix}-skip-ssl-verify").as_bytes()
}

impl S3Opts {
    /// Takes `flag` (with `val`, from `--flag=val` or the next argument) if it is one of ours.
    pub fn flag(&mut self, prefix: &str, flag: &str, val: Option<&str>) -> Result<bool, String> {
        let Some(sfx) = flag.strip_prefix(prefix) else { return Ok(false) };
        let need = || val.map(String::from).ok_or_else(|| format!("{flag} needs a value"));
        let boolean = || match val {
            None | Some("true") => Ok(true),
            Some("false") => Ok(false),
            Some(_) => Err(format!("{flag} takes true or false")),
        };
        match sfx {
            "" => self.enabled = boolean()?,
            "-insecure" => self.insecure = boolean()?,
            "-skip-ssl-verify" => self.skip_verify = boolean()?,
            "-endpoint" => self.endpoint = need()?,
            "-endpoint-ca" => self.endpoint_ca = Some(need()?),
            "-bucket" => self.bucket = need()?,
            "-folder" => self.folder = need()?,
            "-region" => self.region = need()?,
            "-access-key" => self.access_key = Some(need()?),
            "-secret-key" => self.secret_key = Some(need()?),
            "-session-token" => self.session_token = Some(need()?),
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Whether any S3 option was given at all (without `--s3` they would be ignored silently).
    fn touched(&self) -> bool {
        self.enabled || !self.bucket.is_empty() || !self.endpoint.is_empty() || self.access_key.is_some() || self.secret_key.is_some()
    }

    pub fn finish(self, prefix: &str) -> Result<Option<S3Settings>, String> {
        if !self.enabled {
            return if self.touched() { Err(format!("S3 options need {prefix}")) } else { Ok(None) };
        }
        if self.bucket.is_empty() {
            return Err(format!("{prefix} needs {prefix}-bucket"));
        }
        let env = |names: &[&str]| names.iter().find_map(|n| kr_runtime::store::env_var(n).filter(|v| !v.is_empty()));
        let access_key = self.access_key.or_else(|| env(&["KR_S3_ACCESS_KEY", "AWS_ACCESS_KEY_ID"])).ok_or("no S3 access key (--*-access-key or $KR_S3_ACCESS_KEY)")?;
        let secret_key = self.secret_key.or_else(|| env(&["KR_S3_SECRET_KEY", "AWS_SECRET_ACCESS_KEY"])).ok_or("no S3 secret key (--*-secret-key or $KR_S3_SECRET_KEY)")?;
        let session_token = self.session_token.or_else(|| env(&["KR_S3_SESSION_TOKEN", "AWS_SESSION_TOKEN"]));
        let ca_pem = match &self.endpoint_ca {
            Some(f) => Some(String::from_utf8(read_opt(f)?.ok_or_else(|| format!("{f}: no such file"))?).map_err(|_| format!("{f} is not UTF-8 PEM"))?),
            None => None,
        };
        let cfg = S3Config {
            endpoint: self.endpoint,
            bucket: self.bucket,
            folder: self.folder.trim_matches('/').into(),
            region: if self.region.is_empty() { "us-east-1".into() } else { self.region },
            creds: Creds { access_key, secret_key, session_token },
            insecure: self.insecure,
        };
        Ok(Some(S3Settings { cfg, ca_pem, skip_verify: self.skip_verify }))
    }
}

impl S3Settings {
    fn client(&self) -> Result<S3<RegConnector>, String> {
        // Trust anchors: $KR_CA_BUNDLE or the system bundle, plus the endpoint CA.
        let mut pem = match kr_runtime::store::env_var("KR_CA_BUNDLE") {
            Some(p) => String::from_utf8(read_opt(&p)?.unwrap_or_default()).unwrap_or_default(),
            None => ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"].iter().find_map(|p| read_opt(p).ok().flatten()).and_then(|b| String::from_utf8(b).ok()).unwrap_or_default(),
        };
        if let Some(ca) = &self.ca_pem {
            pem.push('\n');
            pem.push_str(ca);
        }
        let conn = RegConnector::new(&pem, None, self.skip_verify).map_err(|e| format!("S3 TLS setup: {e:?}"))?;
        Ok(S3::new(conn, self.cfg.clone(), pki::now))
    }

    fn describe(&self, name: &str) -> String {
        let folder = if self.cfg.folder.is_empty() { String::new() } else { format!("{}/", self.cfg.folder) };
        format!("s3://{}/{folder}{name}", self.cfg.bucket)
    }
}

/// `kr-snapshot-<zero padded unix time>.tar`
fn snapshot_name(t: i64) -> String {
    format!("kr-snapshot-{t:012}.tar")
}

fn name_time(name: &str) -> Option<i64> {
    name.strip_prefix("kr-snapshot-")?.strip_suffix(".tar")?.parse().ok()
}

pub fn main(mut args: Args) -> i32 {
    let sub = args.next();
    let r = match sub {
        Some(b"save") => save(args),
        Some(b"restore") => restore(args),
        Some(b"list") => list(args),
        Some(b"delete") => delete(args),
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

struct Parsed {
    pos: Option<String>,
    data: Option<String>,
    flags: Vec<String>,
    s3: Option<S3Settings>,
}

fn parse(mut args: Args, flags: &[&str]) -> Result<Parsed, (String, bool)> {
    let u = |e: String| (e, true);
    let (mut pos, mut data, mut set, mut opts) = (None, None, Vec::new(), S3Opts::default());
    while let Some(a) = args.next() {
        let a = utf8(a).map_err(u)?;
        let (name, inline) = match a.split_once('=') {
            Some((n, v)) if a.starts_with("--") => (n.to_string(), Some(v.to_string())),
            _ => (a.clone(), None),
        };
        if name == "--data" {
            data = Some(match inline {
                Some(v) => v,
                None => utf8(args.next().ok_or_else(|| u("--data needs a value".into()))?).map_err(u)?,
            });
        } else if flags.contains(&name.as_str()) {
            set.push(name);
        } else if name.starts_with("--s3") {
            let val = match inline {
                Some(v) => Some(v),
                None if is_s3_bool_flag(name.as_bytes(), "--s3") => None,
                None => Some(utf8(args.next().ok_or_else(|| u(format!("{name} needs a value")))?).map_err(u)?),
            };
            if !opts.flag("--s3", &name, val.as_deref()).map_err(u)? {
                return Err(u(format!("unknown flag {name}")));
            }
        } else if name.starts_with("--") {
            return Err(u(format!("unknown flag {name}")));
        } else if pos.is_none() {
            pos = Some(a);
        } else {
            return Err(u(format!("unexpected argument {a}")));
        }
    }
    let s3 = opts.finish("--s3").map_err(u)?;
    Ok(Parsed { pos, data, flags: set, s3 })
}

fn save(args: Args) -> R {
    let p = parse(args, &["--committed-only"])?;
    if p.pos.is_none() && p.s3.is_none() {
        return Err(("missing <file>".into(), true));
    }
    let data = p.data.unwrap_or_else(server::data_dir);
    let (bytes, rev) = build(&data, !p.flags.is_empty()).map_err(|e| (e, false))?;
    if let Some(file) = &p.pos {
        write_file(file, &bytes).map_err(|e| (e, false))?;
        print(format!("{file}: revision {rev}, {} bytes (contains the cluster CA and service-account keys: keep it private)\n", bytes.len()).as_bytes());
    }
    if let Some(s3) = &p.s3 {
        let name = snapshot_name(pki::now());
        let c = s3.client().map_err(|e| (e, false))?;
        let (n, len) = (name.clone(), bytes.len());
        kr_rt::exec::block_on(async move { c.put(&n, &bytes).await }).map_err(|e| (e, false))?;
        print(format!("{}: revision {rev}, {len} bytes (contains the cluster CA and service-account keys; protect the bucket)\n", s3.describe(&name)).as_bytes());
    }
    Ok(())
}

fn list(args: Args) -> R {
    let p = parse(args, &[])?;
    if p.pos.is_some() {
        return Err(("list takes no <file>".into(), true));
    }
    let data = p.data.unwrap_or_else(server::data_dir);
    let mut rows: Vec<(String, String, u64, String)> = Vec::new();
    let dir = format!("{data}/snapshots");
    if let Ok(fd) = fs::openat(fs::AT_FDCWD, &cstr(&dir), fs::O_RDONLY | fs::O_DIRECTORY | fs::O_CLOEXEC, 0) {
        for e in fs::read_dir(&fd).filter_map(|e| e.ok()) {
            let name = String::from_utf8_lossy(&e.name).into_owned();
            if let Some(t) = name_time(&name) {
                let size = fs::newfstatat(fs::AT_FDCWD, &cstr(&format!("{dir}/{name}")), fs::AT_SYMLINK_NOFOLLOW).map_or(0, |s| s.size.max(0) as u64);
                rows.push((name.clone(), kr_net::s3::amz_date(t), size, format!("{dir}/{name}")));
            }
        }
    }
    if let Some(s3) = &p.s3 {
        let c = s3.client().map_err(|e| (e, false))?;
        for o in kr_rt::exec::block_on(async move { c.list("kr-snapshot-").await }).map_err(|e| (e, false))? {
            if let Some(t) = name_time(&o.name) {
                rows.push((o.name.clone(), kr_net::s3::amz_date(t), o.size, s3.describe(&o.name)));
            }
        }
    }
    rows.sort();
    print(format!("{:<30} {:<17} {:>12}  LOCATION\n", "NAME", "CREATED", "SIZE").as_bytes());
    for (name, created, size, loc) in &rows {
        print(format!("{name:<30} {created:<17} {size:>12}  {loc}\n").as_bytes());
    }
    Ok(())
}

fn delete(args: Args) -> R {
    let p = parse(args, &[])?;
    let name = p.pos.ok_or_else(|| ("missing <name>".to_string(), true))?;
    if name_time(&name).is_none() {
        return Err((format!("{name} is not a snapshot name (kr-snapshot-<time>.tar; see `kr snapshot list`)"), false));
    }
    if let Some(s3) = &p.s3 {
        let c = s3.client().map_err(|e| (e, false))?;
        let n = name.clone();
        kr_rt::exec::block_on(async move { c.delete(&n).await }).map_err(|e| (e, false))?;
        print(format!("deleted {}\n", s3.describe(&name)).as_bytes());
    } else {
        let data = p.data.unwrap_or_else(server::data_dir);
        let f = format!("{data}/snapshots/{name}");
        fs::unlinkat(fs::AT_FDCWD, &cstr(&f), 0).map_err(|e| (format!("delete {f}: errno {}", e.0), false))?;
        print(format!("deleted {f}\n").as_bytes());
    }
    Ok(())
}

fn restore(args: Args) -> R {
    let p = parse(args, &["--force"])?;
    let file = p.pos.ok_or_else(|| ("missing <file> (or <name> with --s3)".to_string(), true))?;
    let (data, force) = (p.data.unwrap_or_else(server::data_dir), !p.flags.is_empty());
    let e = |m: String| (m, false);
    let raw = match &p.s3 {
        Some(s3) => {
            let c = s3.client().map_err(e)?;
            let f = file.clone();
            let b = kr_rt::exec::block_on(async move { c.get(&f).await }).map_err(e)?;
            print(format!("downloaded {} ({} bytes)\n", s3.describe(&file), b.len()).as_bytes());
            b
        }
        None => read_opt(&file).map_err(e)?.ok_or_else(|| e(format!("{file}: no such file")))?,
    };
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
/// the newest `keep`; with `s3` the same archive is uploaded and the bucket folder pruned alike.
/// When scheduled snapshots are taken.
pub enum When {
    /// Every this many seconds after the start.
    Every(u64),
    /// At the times a cron expression matches (UTC).
    Cron(kr_runtime::cron::Cron),
}

pub async fn schedule(data: String, when: When, dir: Option<String>, keep: usize, s3: Option<S3Settings>) {
    let dir = dir.unwrap_or_else(|| format!("{data}/snapshots"));
    loop {
        let wait_s = match &when {
            When::Every(s) => *s,
            When::Cron(c) => {
                let now = pki::now();
                match c.next_after(now) {
                    Some(t) => (t - now) as u64,
                    None => {
                        eprint(b"kr server: --snapshot-cron never matches a date; no scheduled snapshots\n");
                        return;
                    }
                }
            }
        };
        kr_rt::exec::sleep(wait_s.saturating_mul(1000)).await;
        let name = snapshot_name(pki::now());
        let f = format!("{dir}/{name}");
        // Reading the datastore, replaying it, building and writing the archive is all disk
        // and CPU work: a copy-on-write fork does it (ADR-065), inline if the fork fails.
        let want_bytes = s3.is_some();
        let job = || encode_built(build_and_write(&data, &dir, &f), want_bytes);
        let built = match kr_rt::offload::fork(job) {
            Some(child) => child.result().await.map_or_else(|| Err(String::from("snapshot process died")), |b| decode_built(&b)),
            None => decode_built(&job()),
        };
        match &built {
            Ok((_, rev)) => print(format!("kr server: wrote snapshot {f} (revision {rev})\n").as_bytes()),
            Err(e) => eprint(format!("kr server: scheduled snapshot failed: {e}\n").as_bytes()),
        }
        prune(&dir, keep);
        if let (Some(s3), Ok((b, rev))) = (&s3, &built) {
            match upload(s3, &name, b, keep).await {
                Ok(pruned) => print(format!("kr server: uploaded snapshot {} (revision {rev}){}\n", s3.describe(&name), if pruned > 0 { format!(", pruned {pruned} old") } else { String::new() }).as_bytes()),
                Err(e) => eprint(format!("kr server: snapshot upload to S3 failed: {e}\n").as_bytes()),
            }
        }
    }
}

fn build_and_write(data: &str, dir: &str, f: &str) -> Result<(Vec<u8>, u64), String> {
    let (b, rev) = build(data, false)?;
    server::mkdir_p(dir).and_then(|_| write_file(f, &b))?;
    Ok((b, rev))
}

/// `1 | rev | archive (only when wanted)` or `0 | error message`.
fn encode_built(r: Result<(Vec<u8>, u64), String>, with_bytes: bool) -> Vec<u8> {
    match r {
        Ok((b, rev)) => {
            let mut out = alloc::vec![1u8];
            out.extend_from_slice(&rev.to_le_bytes());
            if with_bytes {
                out.extend_from_slice(&b);
            }
            out
        }
        Err(e) => {
            let mut out = alloc::vec![0u8];
            out.extend_from_slice(e.as_bytes());
            out
        }
    }
}

fn decode_built(b: &[u8]) -> Result<(Vec<u8>, u64), String> {
    match b.split_first() {
        Some((1, rest)) if rest.len() >= 8 => Ok((rest[8..].to_vec(), u64::from_le_bytes(rest[..8].try_into().unwrap()))),
        Some((0, msg)) => Err(String::from_utf8_lossy(msg).into_owned()),
        _ => Err(String::from("bad snapshot result")),
    }
}

async fn upload(s3: &S3Settings, name: &str, bytes: &[u8], keep: usize) -> Result<usize, String> {
    let c = s3.client()?;
    c.put(name, bytes).await?;
    Ok(c.prune("kr-snapshot-", ".tar", keep).await?.len())
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

