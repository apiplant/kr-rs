//! On-disk image store (ADR-017).
//!
//! ```text
//! <root>/blobs/sha256/<hex>              content-addressed blobs (written atomically)
//! <root>/images/<config-hex>/manifest.json
//!                            config.json
//!                            rootfs/     flattened layers
//! <root>/refs/<escaped-ref>              file containing the config hex digest
//! <root>/containers/<id>/{upper,work,merged}
//! ```
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use kr_net::registry::{Digest, Reference};
use kr_net::sha256::{hex, Sha256};
use kr_sys::fs::{self, AT_FDCWD};
use kr_sys::{Errno, Fd};

/// Every failure in the runtime's store/unpack/pull path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A syscall failed; the first field names the operation.
    Io(&'static str, Errno),
    Net(kr_net::Error),
    Archive(kr_archive::Error),
    Json(&'static str),
    /// A layer tried to do something that would escape the rootfs or is otherwise refused.
    Unsafe(&'static str),
    /// A decompression-bomb limit was exceeded.
    Limit(&'static str),
    /// The image is not usable (unsupported media type, malformed manifest, ...).
    Image(&'static str),
    /// A blob did not hash to its digest.
    Digest,
    /// The store root could not be determined.
    NoRoot,
}

pub type Result<T> = core::result::Result<T, Error>;

impl From<Errno> for Error {
    fn from(e: Errno) -> Self {
        Error::Io("io", e)
    }
}
impl From<kr_net::Error> for Error {
    fn from(e: kr_net::Error) -> Self {
        Error::Net(e)
    }
}
impl From<kr_archive::Error<Error>> for Error {
    fn from(e: kr_archive::Error<Error>) -> Self {
        match e {
            kr_archive::Error::Sink(e) => e,
            other => Error::Archive(other.erase()),
        }
    }
}

/// Adds an operation name to a bare `Errno`.
pub(crate) trait Ctx<T> {
    fn ctx(self, what: &'static str) -> Result<T>;
}
impl<T> Ctx<T> for core::result::Result<T, Errno> {
    fn ctx(self, what: &'static str) -> Result<T> {
        self.map_err(|e| Error::Io(what, e))
    }
}

/// NUL-terminated copy of `s` for the syscall wrappers. Fails if `s` contains a NUL.
pub fn cpath(s: &str) -> Result<Vec<u8>> {
    if s.as_bytes().contains(&0) {
        return Err(Error::Unsafe("NUL in path"));
    }
    let mut v = Vec::with_capacity(s.len() + 1);
    v.extend_from_slice(s.as_bytes());
    v.push(0);
    Ok(v)
}

/// Image identity: the lowercase hex of the config digest (the directory name under `images/`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ImageId(pub String);

impl ImageId {
    pub fn hex(&self) -> &str {
        &self.0
    }
    /// `sha256:<hex>`.
    pub fn digest(&self) -> String {
        format!("sha256:{}", self.0)
    }
    fn valid(&self) -> bool {
        self.0.len() == 64 && self.0.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
}
impl core::fmt::Display for ImageId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "sha256:{}", self.0)
    }
}

/// The runtime-relevant part of an OCI image config.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImageConfig {
    /// `KEY=value` strings.
    pub env: Vec<String>,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub working_dir: String,
    /// `user[:group]`, names or numeric ids; empty means root.
    pub user: String,
}

fn str_list(v: Option<&kr_fmt::json::Value>) -> Result<Vec<String>> {
    match v {
        None => Ok(Vec::new()),
        Some(v) if v.is_null() => Ok(Vec::new()),
        Some(v) => {
            let a = v.as_array().ok_or(Error::Json("config list is not an array"))?;
            a.iter()
                .map(|x| x.as_str().map(|s| s.to_string()).ok_or(Error::Json("config list item is not a string")))
                .collect()
        }
    }
}

impl ImageConfig {
    /// Parses an OCI/docker image config blob (`{"config": {"Env": [...], ...}}`).
    pub fn parse(json: &[u8]) -> Result<ImageConfig> {
        let v = kr_fmt::json::parse(json).map_err(|_| Error::Json("invalid config json"))?;
        if v.as_object().is_none() {
            return Err(Error::Json("config is not an object"));
        }
        let Some(c) = v.get("config").filter(|c| !c.is_null()) else {
            return Ok(ImageConfig::default());
        };
        if c.as_object().is_none() {
            return Err(Error::Json("config.config is not an object"));
        }
        let s = |k: &str| -> Result<String> {
            match c.get(k) {
                None => Ok(String::new()),
                Some(x) if x.is_null() => Ok(String::new()),
                Some(x) => x.as_str().map(|s| s.to_string()).ok_or(Error::Json("config field is not a string")),
            }
        };
        Ok(ImageConfig {
            env: str_list(c.get("Env"))?,
            entrypoint: str_list(c.get("Entrypoint"))?,
            cmd: str_list(c.get("Cmd"))?,
            working_dir: s("WorkingDir")?,
            user: s("User")?,
        })
    }
}

/// Paths of one container's overlay directories (no trailing NUL; use [`cpath`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerDirs {
    pub id: String,
    pub root: String,
    pub upper: String,
    pub work: String,
    pub merged: String,
}

/// Reads one variable from the process environment through `/proc/self/environ` (kr-rt has no
/// environment accessor and the store only needs a handful of startup variables).
pub fn env_var(name: &str) -> Option<String> {
    let data = fs::read_file(b"/proc/self/environ\0", 4 << 20).ok()?;
    for kv in data.split(|&b| b == 0) {
        if let Some(i) = kv.iter().position(|&b| b == b'=') {
            if &kv[..i] == name.as_bytes() {
                return core::str::from_utf8(&kv[i + 1..]).ok().map(|s| s.to_string());
            }
        }
    }
    None
}

/// ADR-017 store root rules: `$KR_ROOT`; else `/var/lib/kr` for root; else
/// `$XDG_DATA_HOME/kr`; else `$HOME/.local/share/kr`.
pub fn root_from(get: &dyn Fn(&str) -> Option<String>, uid: u32) -> Result<String> {
    let nonempty_abs = |k: &str| get(k).filter(|v| v.starts_with('/'));
    if let Some(r) = get("KR_ROOT").filter(|v| !v.is_empty()) {
        return Ok(r);
    }
    if uid == 0 {
        return Ok("/var/lib/kr".to_string());
    }
    if let Some(x) = nonempty_abs("XDG_DATA_HOME") {
        return Ok(format!("{}/kr", x.trim_end_matches('/')));
    }
    if let Some(h) = nonempty_abs("HOME") {
        return Ok(format!("{}/.local/share/kr", h.trim_end_matches('/')));
    }
    Err(Error::NoRoot)
}

/// Escapes an image reference into a single safe file name.
pub fn escape_ref(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for (i, b) in s.bytes().enumerate() {
        let ok = b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || (b == b'.' && i != 0);
        if ok {
            o.push(b as char);
        } else {
            o.push('%');
            o.push(char::from_digit((b >> 4) as u32, 16).unwrap());
            o.push(char::from_digit((b & 15) as u32, 16).unwrap());
        }
    }
    o
}

fn valid_container_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id != "."
        && id != ".."
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

static TMP_SEQ: AtomicU32 = AtomicU32::new(0);

fn tmp_suffix() -> String {
    format!(".tmp.{}.{}", fs::getpid(), TMP_SEQ.fetch_add(1, Ordering::Relaxed))
}

/// `mkdir -p` (mode applied to directories that are created).
pub fn mkdir_p(path: &str, mode: u32) -> Result<()> {
    let mut cur = String::new();
    if path.starts_with('/') {
        cur.push('/');
    }
    for comp in path.split('/').filter(|c| !c.is_empty()) {
        if !cur.is_empty() && !cur.ends_with('/') {
            cur.push('/');
        }
        cur.push_str(comp);
        match fs::mkdirat(AT_FDCWD, &cpath(&cur)?, mode) {
            Ok(()) | Err(Errno(fs::EEXIST)) => {}
            Err(e) => return Err(Error::Io("mkdir", e)),
        }
    }
    Ok(())
}

/// Writes `data` to `path` atomically (tmp file + fsync + rename over).
pub fn write_file_atomic(path: &str, data: &[u8]) -> Result<()> {
    let tmp = format!("{}{}", path, tmp_suffix());
    let ct = cpath(&tmp)?;
    let fd = fs::openat(AT_FDCWD, &ct, fs::O_WRONLY | fs::O_CREAT | fs::O_EXCL | fs::O_CLOEXEC, 0o644).ctx("create tmp")?;
    let r = (|| -> Result<()> {
        fs::write_all(fd.raw(), data).ctx("write")?;
        fs::fsync(fd.raw()).ctx("fsync")?;
        fs::renameat2(AT_FDCWD, &ct, AT_FDCWD, &cpath(path)?, 0).ctx("rename")
    })();
    if r.is_err() {
        let _ = fs::unlinkat(AT_FDCWD, &ct, 0);
    }
    r
}

/// Streams a blob into the store; nothing becomes visible until [`BlobWriter::commit`] has
/// verified the digest. Dropping an uncommitted writer removes its temporary file.
pub struct BlobWriter {
    fd: Option<Fd>,
    tmp: Vec<u8>,
    dest: Vec<u8>,
    dir: Vec<u8>,
    hash: Sha256,
    len: u64,
}

impl BlobWriter {
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        let fd = self.fd.as_ref().ok_or(Error::Image("blob writer closed"))?;
        fs::write_all(fd.raw(), data).ctx("write blob")?;
        self.hash.update(data);
        self.len += data.len() as u64;
        Ok(())
    }

    pub fn len(&self) -> u64 {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Verifies the sha256 of everything written against `expected`, fsyncs and renames the
    /// blob into place. An already-present blob is left alone.
    pub fn commit(mut self) -> Result<()> {
        let h = core::mem::replace(&mut self.hash, Sha256::new()).finalize();
        let got = hex(&h);
        let want = self.dest_hex();
        if got != want {
            return Err(Error::Digest);
        }
        let fd = self.fd.take().ok_or(Error::Image("blob writer closed"))?;
        fs::fsync(fd.raw()).ctx("fsync blob")?;
        drop(fd);
        match fs::renameat2(AT_FDCWD, &self.tmp, AT_FDCWD, &self.dest, fs::RENAME_NOREPLACE) {
            Ok(()) => {}
            Err(Errno(fs::EEXIST)) => {
                let _ = fs::unlinkat(AT_FDCWD, &self.tmp, 0);
            }
            Err(e) => return Err(Error::Io("rename blob", e)),
        }
        self.tmp.clear(); // committed: nothing to clean up on drop
        if let Ok(d) = fs::openat(AT_FDCWD, &self.dir, fs::O_RDONLY | fs::O_DIRECTORY | fs::O_CLOEXEC, 0) {
            let _ = fs::fsync(d.raw());
        }
        Ok(())
    }

    fn dest_hex(&self) -> String {
        let d = &self.dest[..self.dest.len() - 1];
        let name = d.rsplit(|&b| b == b'/').next().unwrap_or(&[]);
        String::from_utf8_lossy(name).into_owned()
    }
}

impl Drop for BlobWriter {
    fn drop(&mut self) {
        if !self.tmp.is_empty() {
            let _ = fs::unlinkat(AT_FDCWD, &self.tmp, 0);
        }
    }
}

/// Handle to an opened store root.
#[derive(Clone, Debug)]
pub struct Store {
    root: String,
}

fn digest_hex(d: &Digest) -> Result<&str> {
    d.as_str().strip_prefix("sha256:").ok_or(Error::Net(kr_net::Error::UnsupportedDigest))
}

impl Store {
    /// Opens (creating if needed) the store at `root`, or at the default location from
    /// [`root_from`] (reading the environment) when `root` is `None`.
    pub fn open(root: Option<&str>) -> Result<Store> {
        let root = match root {
            Some(r) => r.to_string(),
            None => root_from(&env_var, fs::getuid())?,
        };
        let root = if root.len() > 1 { root.trim_end_matches('/').to_string() } else { root };
        if !root.starts_with('/') {
            return Err(Error::Unsafe("store root must be absolute"));
        }
        let s = Store { root };
        for d in ["", "blobs/sha256", "images", "refs", "containers"] {
            mkdir_p(&s.join(d), 0o755)?;
        }
        Ok(s)
    }

    pub fn root(&self) -> &str {
        &self.root
    }

    fn join(&self, rel: &str) -> String {
        if rel.is_empty() {
            self.root.clone()
        } else {
            format!("{}/{}", self.root.trim_end_matches('/'), rel)
        }
    }

    // ---- blobs ----

    pub fn blob_path(&self, d: &Digest) -> Result<String> {
        Ok(self.join(&format!("blobs/sha256/{}", digest_hex(d)?)))
    }

    pub fn has_blob(&self, d: &Digest) -> bool {
        match self.blob_path(d).and_then(|p| cpath(&p)) {
            Ok(p) => fs::newfstatat(AT_FDCWD, &p, fs::AT_SYMLINK_NOFOLLOW).is_ok_and(|s| s.is_file()),
            Err(_) => false,
        }
    }

    /// Re-hashes a stored blob. `Ok(false)` if it is missing or corrupt (a corrupt one is
    /// deleted so the next pull fetches it again).
    pub fn verify_blob(&self, d: &Digest) -> Result<bool> {
        let want = digest_hex(d)?;
        let p = cpath(&self.blob_path(d)?)?;
        let fd = match fs::openat(AT_FDCWD, &p, fs::O_RDONLY | fs::O_NOFOLLOW | fs::O_CLOEXEC, 0) {
            Ok(f) => f,
            Err(Errno(fs::ENOENT)) => return Ok(false),
            Err(e) => return Err(Error::Io("open blob", e)),
        };
        let mut h = Sha256::new();
        let mut buf = alloc::vec![0u8; 64 * 1024];
        loop {
            let n = kr_sys::read(fd.raw(), &mut buf).ctx("read blob")?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        if hex(&h.finalize()) == want {
            Ok(true)
        } else {
            let _ = fs::unlinkat(AT_FDCWD, &p, 0);
            Ok(false)
        }
    }

    /// Starts writing the blob that must hash to `d`.
    pub fn blob_writer(&self, d: &Digest) -> Result<BlobWriter> {
        let dest = cpath(&self.blob_path(d)?)?;
        let dir = self.join("blobs/sha256");
        let tmp = cpath(&format!("{}/.{}{}", dir, digest_hex(d)?, tmp_suffix()))?;
        let fd = fs::openat(AT_FDCWD, &tmp, fs::O_WRONLY | fs::O_CREAT | fs::O_EXCL | fs::O_CLOEXEC, 0o644)
            .ctx("create blob tmp")?;
        Ok(BlobWriter { fd: Some(fd), tmp, dest, dir: cpath(&dir)?, hash: Sha256::new(), len: 0 })
    }

    /// Stores a small in-memory blob, verifying it against `d`.
    pub fn put_blob(&self, d: &Digest, data: &[u8]) -> Result<()> {
        let mut w = self.blob_writer(d)?;
        w.write(data)?;
        w.commit()
    }

    pub fn open_blob(&self, d: &Digest) -> Result<Fd> {
        let p = cpath(&self.blob_path(d)?)?;
        fs::openat(AT_FDCWD, &p, fs::O_RDONLY | fs::O_NOFOLLOW | fs::O_CLOEXEC, 0).ctx("open blob")
    }

    // ---- images ----

    pub fn image_dir(&self, id: &ImageId) -> Result<String> {
        if !id.valid() {
            return Err(Error::Image("bad image id"));
        }
        Ok(self.join(&format!("images/{}", id.0)))
    }

    pub fn rootfs_path(&self, id: &ImageId) -> Result<String> {
        Ok(format!("{}/rootfs", self.image_dir(id)?))
    }

    /// True once the flattened rootfs has been renamed into place.
    pub fn has_image(&self, id: &ImageId) -> bool {
        match self.rootfs_path(id).and_then(|p| cpath(&p)) {
            Ok(p) => fs::newfstatat(AT_FDCWD, &p, fs::AT_SYMLINK_NOFOLLOW).is_ok_and(|s| s.is_dir()),
            Err(_) => false,
        }
    }

    pub fn image_config(&self, id: &ImageId) -> Result<ImageConfig> {
        let p = cpath(&format!("{}/config.json", self.image_dir(id)?))?;
        let data = fs::read_file(&p, 4 << 20).ctx("read config.json")?;
        ImageConfig::parse(&data)
    }

    /// Canonical key under which `r` is stored in `refs/`.
    fn ref_key(r: &str) -> String {
        match Reference::parse(r) {
            Ok(p) => p.to_string(),
            Err(_) => r.to_string(),
        }
    }

    fn ref_path(&self, r: &str) -> String {
        self.join(&format!("refs/{}", escape_ref(&Self::ref_key(r))))
    }

    pub fn set_ref(&self, r: &str, id: &ImageId) -> Result<()> {
        if !id.valid() {
            return Err(Error::Image("bad image id"));
        }
        write_file_atomic(&self.ref_path(r), format!("{}\n", id.0).as_bytes())
    }

    pub fn resolve_ref(&self, r: &str) -> Option<ImageId> {
        let data = fs::read_file(&cpath(&self.ref_path(r)).ok()?, 256).ok()?;
        let id = ImageId(core::str::from_utf8(&data).ok()?.trim().to_string());
        if id.valid() {
            Some(id)
        } else {
            None
        }
    }

    /// Looks up a pulled image: `(id, config, NUL-terminated rootfs path)`.
    pub fn image(&self, r: &str) -> Option<(ImageId, ImageConfig, Vec<u8>)> {
        let id = self.resolve_ref(r)?;
        if !self.has_image(&id) {
            return None;
        }
        let cfg = self.image_config(&id).ok()?;
        let rootfs = cpath(&self.rootfs_path(&id).ok()?).ok()?;
        Some((id, cfg, rootfs))
    }

    // ---- containers ----

    /// Creates `containers/<id>/{upper,work,merged}`. Fails with `EEXIST` if the id is in use.
    pub fn create_container(&self, id: &str) -> Result<ContainerDirs> {
        if !valid_container_id(id) {
            return Err(Error::Unsafe("bad container id"));
        }
        let root = self.join(&format!("containers/{id}"));
        fs::mkdirat(AT_FDCWD, &cpath(&root)?, 0o755).ctx("mkdir container")?;
        let d = ContainerDirs {
            id: id.to_string(),
            upper: format!("{root}/upper"),
            work: format!("{root}/work"),
            merged: format!("{root}/merged"),
            root,
        };
        let r = [&d.upper, &d.work, &d.merged]
            .iter()
            .try_for_each(|p| fs::mkdirat(AT_FDCWD, &cpath(p)?, 0o755).ctx("mkdir container dir"));
        if r.is_err() {
            let _ = self.delete_container(id);
        }
        r.map(|_| d)
    }

    /// Recursively deletes `containers/<id>` (the caller must have unmounted `merged`).
    pub fn delete_container(&self, id: &str) -> Result<()> {
        if !valid_container_id(id) {
            return Err(Error::Unsafe("bad container id"));
        }
        let dir = cpath(&self.join("containers"))?;
        let fd = fs::openat(AT_FDCWD, &dir, fs::O_PATH | fs::O_DIRECTORY | fs::O_CLOEXEC, 0).ctx("open containers")?;
        fs::remove_all(fd.raw(), &cpath(id)?).ctx("remove container")
    }
}
