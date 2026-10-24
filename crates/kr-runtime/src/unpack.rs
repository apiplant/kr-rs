//! Safe OCI layer extraction into a flattened rootfs directory (ADR-014, ADR-017).
//!
//! Threat model: the layer is attacker-controlled. `kr_archive::tar::sanitize` is only a lexical
//! first filter; the guard is the kernel. Every path is resolved with
//! `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)` relative to the rootfs directory fd, so `..`
//! and absolute symlinks (even ones planted by earlier entries) resolve *inside* the rootfs.
//! The parent directory is resolved that way, and the final component is then operated on with
//! an `*at` call that never follows a final symlink (`O_NOFOLLOW` / `O_EXCL` / `unlinkat` /
//! `AT_SYMLINK_NOFOLLOW`).
use crate::store::{cpath, Ctx, Error, Result};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_archive::gzip::GzDecoder;
use kr_archive::tar::{self, Entry, Event, Kind, TarReader, Whiteout};
use kr_net::sha256::{hex, Sha256};
use kr_sys::fs::{self, ENOENT, ENOTDIR};
use kr_sys::{Errno, Fd, Timespec};

/// Decompression-bomb and path limits (exceeding any is an error).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum uncompressed (tar stream) bytes per layer.
    pub max_bytes: u64,
    /// Maximum uncompressed bytes over all layers of one image (enforced by the pull).
    pub max_image_bytes: u64,
    /// Maximum tar entries per layer.
    pub max_entries: u64,
    /// Paths and link targets must be shorter than this (PATH_MAX).
    pub max_path: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_bytes: 8 << 30, max_image_bytes: 8 << 30, max_entries: 1_000_000, max_path: 4096 }
    }
}

/// What a layer contained.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub entries: u64,
    pub files: u64,
    pub dirs: u64,
    pub symlinks: u64,
    pub hardlinks: u64,
    pub fifos: u64,
    pub whiteouts: u64,
    /// Char/block device nodes, skipped (rootless; ADR-017).
    pub skipped_devices: u64,
    /// Reserved `.wh..wh.*` names, skipped.
    pub skipped_reserved: u64,
    /// Uncompressed bytes read from the layer.
    pub bytes: u64,
    /// Lower-case hex sha256 of the uncompressed tar stream (the OCI `diff_id`).
    pub diff_id: String,
}

const ATFLAG_NOFOLLOW: i32 = fs::AT_SYMLINK_NOFOLLOW;

fn fnv(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

fn split(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => ("", path),
    }
}

fn cname(s: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len() + 1);
    v.extend_from_slice(s.as_bytes());
    v.push(0);
    v
}

fn valid_name(n: &str) -> bool {
    !n.is_empty() && n != "." && n != ".." && !n.contains('/') && !n.contains('\0')
}

struct Fixup {
    mode: u32,
    mtime: i64,
    xattrs: Vec<(String, Vec<u8>)>,
}

struct Cur {
    fd: Fd,
    uid: u32,
    gid: u32,
    mode: u32,
    mtime: i64,
    xattrs: Vec<(String, Vec<u8>)>,
    parent: Fd,
    name: Vec<u8>,
}

struct Unpacker<'a> {
    root: i32,
    lim: &'a Limits,
    rootless: bool,
    st: Stats,
    /// Hashes of every path (and ancestor) created by this layer; protects them from the
    /// layer's own whiteouts.
    created: BTreeSet<u64>,
    dirs: BTreeMap<String, Fixup>,
    cur: Option<Cur>,
}

fn ts(sec: i64) -> [Timespec; 2] {
    [Timespec { tv_sec: 0, tv_nsec: fs::UTIME_OMIT }, Timespec { tv_sec: sec, tv_nsec: 0 }]
}

fn ignorable_perm(e: Errno) -> bool {
    matches!(e.0, fs::EPERM | fs::EINVAL | fs::EACCES | fs::ENOTSUP | fs::ENODATA)
}

impl<'a> Unpacker<'a> {
    fn new(root: i32, lim: &'a Limits) -> Self {
        Unpacker {
            root,
            lim,
            rootless: fs::getuid() != 0,
            st: Stats::default(),
            created: BTreeSet::new(),
            dirs: BTreeMap::new(),
            cur: None,
        }
    }

    fn mask_mode(&self, mode: u32) -> u32 {
        let m = mode & 0o7777;
        if self.rootless {
            m & !0o6000
        } else {
            m
        }
    }

    fn mark_created(&mut self, path: &str) {
        self.created.insert(fnv(path));
        for (i, b) in path.bytes().enumerate() {
            if b == b'/' {
                self.created.insert(fnv(&path[..i]));
            }
        }
    }

    /// Opens `parent` (a sanitized relative dir path, "" = rootfs) as an `O_PATH` fd confined to
    /// the root. With `create`, missing ancestors are created as `0755`.
    fn open_dir(&self, parent: &str, create: bool) -> Result<Fd> {
        let open = |p: &str| -> core::result::Result<Fd, Errno> {
            let c = if p.is_empty() { b".\0".to_vec() } else { cname(p) };
            fs::open_in_root(self.root, &c, fs::O_PATH | fs::O_DIRECTORY, 0)
        };
        match open(parent) {
            Ok(f) => Ok(f),
            Err(Errno(ENOENT)) if create => {
                let mut prefix = String::new();
                for comp in parent.split('/') {
                    let pp = prefix.clone();
                    if !prefix.is_empty() {
                        prefix.push('/');
                    }
                    prefix.push_str(comp);
                    match open(&prefix) {
                        Ok(_) => {}
                        Err(Errno(ENOENT)) => {
                            let pf = open(&pp).ctx("open parent")?;
                            fs::mkdirat(pf.raw(), &cname(comp), 0o755).ctx("mkdir parent")?;
                        }
                        Err(e) => return Err(Error::Io("open parent", e)),
                    }
                }
                open(parent).ctx("open parent")
            }
            Err(e) => Err(Error::Io("open parent", e)),
        }
    }

    fn chown(&self, pf: i32, name: &[u8], uid: u32, gid: u32) -> Result<()> {
        match fs::fchownat(pf, name, uid, gid, ATFLAG_NOFOLLOW) {
            Ok(()) => Ok(()),
            Err(e) if ignorable_perm(e) => Ok(()),
            Err(e) => Err(Error::Io("fchownat", e)),
        }
    }

    fn set_xattrs(&self, fd: i32, xattrs: &[(String, Vec<u8>)]) -> Result<()> {
        for (k, v) in xattrs {
            // overlayfs' own markers must never come from an image
            if k.starts_with("trusted.overlay.") || k.starts_with("user.overlay.") || k.contains('\0') {
                continue;
            }
            match fs::fsetxattr(fd, &cname(k), v, 0) {
                Ok(()) => {}
                Err(e) if ignorable_perm(e) => {}
                Err(e) => return Err(Error::Io("fsetxattr", e)),
            }
        }
        Ok(())
    }

    fn event(&mut self, ev: Event<'_>) -> Result<()> {
        match ev {
            Event::Entry(e) => self.entry(e),
            Event::Data(d) => {
                if let Some(c) = &self.cur {
                    fs::write_all(c.fd.raw(), d).ctx("write file")?;
                }
                Ok(())
            }
            Event::End => self.end_entry(),
        }
    }

    fn end_entry(&mut self) -> Result<()> {
        if let Some(c) = self.cur.take() {
            self.chown(c.parent.raw(), &c.name, c.uid, c.gid)?;
            fs::fchmod(c.fd.raw(), self.mask_mode(c.mode)).ctx("fchmod")?;
            self.set_xattrs(c.fd.raw(), &c.xattrs)?;
            fs::futimens(c.fd.raw(), &ts(c.mtime)).ctx("futimens")?;
        }
        Ok(())
    }

    fn entry(&mut self, e: &Entry) -> Result<()> {
        if self.st.entries >= self.lim.max_entries {
            return Err(Error::Limit("too many entries"));
        }
        self.st.entries += 1;
        if e.path.len() >= self.lim.max_path || e.linkname.len() >= self.lim.max_path {
            return Err(Error::Limit("path too long"));
        }
        let norm = tar::sanitize(&e.path).map_err(|_| Error::Unsafe("entry path escapes the root"))?;
        let path = norm.as_str();

        if let Some(w) = tar::whiteout(path) {
            self.st.whiteouts += 1;
            return match w {
                Whiteout::Opaque(d) => self.opaque(&d),
                Whiteout::Remove(t) => self.remove(&t),
            };
        }
        if tar::is_reserved_whiteout(path) {
            self.st.skipped_reserved += 1;
            return Ok(());
        }
        if path.is_empty() {
            // the layer root ("./"): only its metadata matters
            if e.kind == Kind::Dir {
                self.st.dirs += 1;
                self.dirs.insert(String::new(), Fixup { mode: e.mode, mtime: e.mtime, xattrs: e.xattrs.clone() });
            }
            return Ok(());
        }
        let (parent, name) = split(path);
        if !valid_name(name) {
            return Err(Error::Unsafe("bad entry name"));
        }
        let cn = cname(name);
        match e.kind {
            Kind::CharDev | Kind::BlockDev => {
                self.st.skipped_devices += 1;
                return Ok(());
            }
            Kind::Dir => {
                let pf = self.open_dir(parent, true)?;
                match fs::newfstatat(pf.raw(), &cn, ATFLAG_NOFOLLOW) {
                    Ok(s) if s.is_dir() => {}
                    Ok(_) => {
                        fs::remove_all(pf.raw(), &cn).ctx("replace with dir")?;
                        fs::mkdirat(pf.raw(), &cn, 0o700).ctx("mkdirat")?;
                    }
                    Err(Errno(ENOENT)) => fs::mkdirat(pf.raw(), &cn, 0o700).ctx("mkdirat")?,
                    Err(e) => return Err(Error::Io("fstatat", e)),
                }
                self.chown(pf.raw(), &cn, e.uid, e.gid)?;
                self.dirs.insert(path.to_string(), Fixup { mode: e.mode, mtime: e.mtime, xattrs: e.xattrs.clone() });
                self.st.dirs += 1;
            }
            Kind::File => {
                let pf = self.open_dir(parent, true)?;
                fs::remove_all(pf.raw(), &cn).ctx("replace file")?;
                let how = fs::OpenHow {
                    flags: (fs::O_WRONLY | fs::O_CREAT | fs::O_EXCL | fs::O_NOFOLLOW | fs::O_CLOEXEC) as u64,
                    mode: 0o600,
                    resolve: fs::RESOLVE_IN_ROOT | fs::RESOLVE_NO_MAGICLINKS,
                };
                let fd = fs::openat2(pf.raw(), &cn, &how).ctx("create file")?;
                self.st.files += 1;
                self.cur = Some(Cur {
                    fd,
                    uid: e.uid,
                    gid: e.gid,
                    mode: e.mode,
                    mtime: e.mtime,
                    xattrs: e.xattrs.clone(),
                    parent: pf,
                    name: cn,
                });
            }
            Kind::Symlink => {
                let target = cpath(&e.linkname)?;
                if e.linkname.is_empty() {
                    return Err(Error::Unsafe("empty symlink target"));
                }
                let pf = self.open_dir(parent, true)?;
                fs::remove_all(pf.raw(), &cn).ctx("replace symlink")?;
                fs::symlinkat(&target, pf.raw(), &cn).ctx("symlinkat")?;
                self.chown(pf.raw(), &cn, e.uid, e.gid)?;
                match fs::utimensat(pf.raw(), Some(&cn), &ts(e.mtime), ATFLAG_NOFOLLOW) {
                    Ok(()) => {}
                    Err(x) if ignorable_perm(x) => {}
                    Err(x) => return Err(Error::Io("utimensat", x)),
                }
                self.st.symlinks += 1;
            }
            Kind::Hardlink => {
                let t = tar::sanitize(&e.linkname).map_err(|_| Error::Unsafe("hardlink target escapes the root"))?;
                let (tparent, tname) = split(t.as_str());
                if !valid_name(tname) {
                    return Err(Error::Unsafe("bad hardlink target"));
                }
                let tcn = cname(tname);
                let tpf = self.open_dir(tparent, false)?;
                // the target must exist (and is not followed if it is a symlink)
                fs::newfstatat(tpf.raw(), &tcn, ATFLAG_NOFOLLOW).ctx("hardlink target")?;
                let pf = self.open_dir(parent, true)?;
                fs::remove_all(pf.raw(), &cn).ctx("replace hardlink")?;
                fs::linkat(tpf.raw(), &tcn, pf.raw(), &cn, 0).ctx("linkat")?;
                self.st.hardlinks += 1;
            }
            Kind::Fifo => {
                let pf = self.open_dir(parent, true)?;
                fs::remove_all(pf.raw(), &cn).ctx("replace fifo")?;
                fs::mknodat(pf.raw(), &cn, fs::S_IFIFO | (self.mask_mode(e.mode) & 0o777), 0).ctx("mknodat")?;
                self.st.fifos += 1;
            }
        }
        self.mark_created(path);
        Ok(())
    }

    /// `.wh.<name>`: delete `target` from the lower layers (not what this layer created).
    fn remove(&mut self, target: &str) -> Result<()> {
        let (parent, name) = split(target);
        if !valid_name(name) || self.created.contains(&fnv(target)) {
            return Ok(());
        }
        let pf = match self.open_dir(parent, false) {
            Ok(f) => f,
            Err(Error::Io(_, Errno(ENOENT))) | Err(Error::Io(_, Errno(ENOTDIR))) => return Ok(()),
            Err(e) => return Err(e),
        };
        fs::remove_all(pf.raw(), &cname(name)).ctx("whiteout")
    }

    /// `.wh..wh..opq`: empty `dir` of everything that did not come from this layer.
    fn opaque(&mut self, dir: &str) -> Result<()> {
        let d = if dir.is_empty() {
            fs::open_in_root(self.root, b".\0", fs::O_RDONLY | fs::O_DIRECTORY, 0).ctx("open root")?
        } else {
            let (parent, name) = split(dir);
            if !valid_name(name) {
                return Ok(());
            }
            let pf = match self.open_dir(parent, false) {
                Ok(f) => f,
                Err(Error::Io(_, Errno(ENOENT))) | Err(Error::Io(_, Errno(ENOTDIR))) => return Ok(()),
                Err(e) => return Err(e),
            };
            let how = fs::OpenHow {
                flags: (fs::O_RDONLY | fs::O_DIRECTORY | fs::O_NOFOLLOW | fs::O_CLOEXEC) as u64,
                mode: 0,
                resolve: fs::RESOLVE_IN_ROOT | fs::RESOLVE_NO_MAGICLINKS,
            };
            match fs::openat2(pf.raw(), &cname(name), &how) {
                Ok(d) => d,
                Err(Errno(ENOENT)) | Err(Errno(ENOTDIR)) | Err(Errno(fs::ELOOP)) => return Ok(()),
                Err(e) => return Err(Error::Io("open opaque dir", e)),
            }
        };
        let _ = fs::fchmod(d.raw(), 0o700);
        let mut kids = Vec::new();
        for k in fs::read_dir(&d) {
            kids.push(k.ctx("readdir")?);
        }
        for k in kids {
            let n = String::from_utf8_lossy(&k.name).into_owned();
            let full = if dir.is_empty() { n } else { alloc::format!("{dir}/{n}") };
            if self.created.contains(&fnv(&full)) {
                continue;
            }
            fs::remove_all(d.raw(), &k.cname()).ctx("opaque remove")?;
        }
        Ok(())
    }

    /// Applies directory modes, mtimes and xattrs after all children exist.
    fn finish(&mut self) -> Result<Stats> {
        let dirs = core::mem::take(&mut self.dirs);
        for (path, fx) in dirs {
            let fd = if path.is_empty() {
                fs::open_in_root(self.root, b".\0", fs::O_RDONLY | fs::O_DIRECTORY, 0).ctx("open root")?
            } else {
                let (parent, name) = split(&path);
                let pf = match self.open_dir(parent, false) {
                    Ok(f) => f,
                    Err(_) => continue,
                };
                let how = fs::OpenHow {
                    flags: (fs::O_RDONLY | fs::O_DIRECTORY | fs::O_NOFOLLOW | fs::O_CLOEXEC) as u64,
                    mode: 0,
                    resolve: fs::RESOLVE_IN_ROOT | fs::RESOLVE_NO_MAGICLINKS,
                };
                match fs::openat2(pf.raw(), &cname(name), &how) {
                    Ok(d) => d,
                    // replaced by a non-directory (or removed) later in the layer
                    Err(_) => continue,
                }
            };
            self.set_xattrs(fd.raw(), &fx.xattrs)?;
            // rootless: keep the owner able to enter/modify every directory so that later layers,
            // whiteouts and `rm -rf` of the store keep working (documented in KNOWN_ISSUES).
            let mut mode = self.mask_mode(fx.mode);
            if self.rootless {
                mode |= 0o700;
            }
            fs::fchmod(fd.raw(), mode).ctx("fchmod dir")?;
            fs::futimens(fd.raw(), &ts(fx.mtime)).ctx("futimens dir")?;
        }
        Ok(self.st.clone())
    }
}

fn run(root: i32, src: &mut dyn FnMut(&mut [u8]) -> Result<usize>, lim: &Limits, gzip: bool) -> Result<Stats> {
    let mut u = Unpacker::new(root, lim);
    let mut tr = TarReader::new();
    let mut gz = GzDecoder::new();
    let mut buf = alloc::vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    let mut hash = Sha256::new();
    loop {
        let n = src(&mut buf)?;
        if n == 0 {
            break;
        }
        if gzip {
            gz.feed(&buf[..n], &mut |out: &[u8]| -> Result<()> {
                total += out.len() as u64;
                if total > lim.max_bytes {
                    return Err(Error::Limit("layer exceeds the uncompressed size limit"));
                }
                hash.update(out);
                tr.feed(out, &mut |ev| u.event(ev)).map_err(Error::from)
            })?;
        } else {
            total += n as u64;
            if total > lim.max_bytes {
                return Err(Error::Limit("layer exceeds the uncompressed size limit"));
            }
            hash.update(&buf[..n]);
            tr.feed(&buf[..n], &mut |ev| u.event(ev)).map_err(Error::from)?;
        }
    }
    if gzip {
        gz.finish().map_err(Error::Archive)?;
    }
    tr.finish().map_err(Error::Archive)?;
    u.st.bytes = total;
    u.st.diff_id = hex(&hash.finalize());
    u.finish()
}

/// Streams a gzip-compressed tar layer from `src` (called until it returns 0) into the
/// directory `rootfs_dirfd`, applying whiteouts against what is already there.
///
/// `rootfs_dirfd` must be a directory fd (`O_RDONLY|O_DIRECTORY` or `O_PATH`). On error the
/// rootfs is in an unspecified state and must be discarded.
pub fn unpack_layer(
    rootfs_dirfd: i32,
    src: &mut dyn FnMut(&mut [u8]) -> Result<usize>,
    limits: &Limits,
) -> Result<Stats> {
    run(rootfs_dirfd, src, limits, true)
}

/// Like [`unpack_layer`] for an uncompressed tar stream.
pub fn unpack_tar_layer(
    rootfs_dirfd: i32,
    src: &mut dyn FnMut(&mut [u8]) -> Result<usize>,
    limits: &Limits,
) -> Result<Stats> {
    run(rootfs_dirfd, src, limits, false)
}

/// Unpacks a layer file/fd (`gzip` selects the compression).
pub fn unpack_layer_fd(rootfs_dirfd: i32, layer_fd: i32, gzip: bool, limits: &Limits) -> Result<Stats> {
    let mut src = |b: &mut [u8]| -> Result<usize> {
        loop {
            match kr_sys::read(layer_fd, b) {
                Err(Errno(kr_sys::EINTR)) => continue,
                r => return r.ctx("read layer"),
            }
        }
    };
    run(rootfs_dirfd, &mut src, limits, gzip)
}
