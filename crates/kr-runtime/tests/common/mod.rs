#![allow(dead_code)]
//! Shared test helpers: hand-built tar/gzip fixtures and a sandbox directory.
use kr_runtime::store::{cpath, Error};
use kr_runtime::unpack::{unpack_layer, Limits, Stats};
use kr_sys::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static SEQ: AtomicUsize = AtomicUsize::new(0);

/// `<tmp>/krrt-<pid>-<n>/{root,outside}`; removed on drop.
pub struct Sandbox {
    pub base: PathBuf,
    pub root: PathBuf,
    pub outside: PathBuf,
    pub rootfd: kr_sys::Fd,
}

impl Sandbox {
    pub fn new() -> Sandbox {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let base = std::env::temp_dir().join(format!("krrt-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret"), b"top secret").unwrap();
        let rootfd = fs::openat(fs::AT_FDCWD, &cpath(root.to_str().unwrap()).unwrap(), fs::O_RDONLY | fs::O_DIRECTORY | fs::O_CLOEXEC, 0).unwrap();
        Sandbox { base, root, outside, rootfd }
    }

    pub fn outside_abs(&self) -> String {
        self.outside.to_str().unwrap().to_string()
    }

    /// Path of `outside` as seen from inside the root (`/tmp/krrt-../outside`), plus the dir
    /// entries that make that path exist in the tar.
    pub fn mirror_outside(&self, t: &mut Tar) {
        let mut acc = String::new();
        for c in self.outside_abs().split('/').filter(|c| !c.is_empty()) {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(c);
            t.dir(&acc, 0o755);
        }
    }

    pub fn unpack(&self, tar: &Tar) -> Result<Stats, Error> {
        self.unpack_with(tar, &Limits::default())
    }

    pub fn unpack_with(&self, tar: &Tar, lim: &Limits) -> Result<Stats, Error> {
        self.unpack_gz(&gzip_stored(&tar.finish()), lim)
    }

    pub fn unpack_gz(&self, gz: &[u8], lim: &Limits) -> Result<Stats, Error> {
        let mut pos = 0usize;
        let mut src = |b: &mut [u8]| -> Result<usize, Error> {
            // odd chunk size on purpose
            let n = (gz.len() - pos).min(b.len()).min(1237);
            b[..n].copy_from_slice(&gz[pos..pos + n]);
            pos += n;
            Ok(n)
        };
        unpack_layer(self.rootfd.raw(), &mut src, lim)
    }

    /// Every file under `base` except `root/`, with contents, for before/after comparison.
    pub fn outside_snapshot(&self) -> Vec<(String, Vec<u8>)> {
        let mut v = Vec::new();
        walk(&self.base, &self.base, &self.root, &mut v);
        v.sort();
        v
    }
}

fn walk(base: &Path, p: &Path, skip: &Path, out: &mut Vec<(String, Vec<u8>)>) {
    for e in std::fs::read_dir(p).unwrap() {
        let e = e.unwrap();
        let path = e.path();
        if path == skip {
            continue;
        }
        let rel = path.strip_prefix(base).unwrap().to_str().unwrap().to_string();
        let md = std::fs::symlink_metadata(&path).unwrap();
        if md.is_dir() {
            out.push((format!("{rel}/"), vec![]));
            walk(base, &path, skip, out);
        } else if md.file_type().is_symlink() {
            out.push((rel, b"<symlink>".to_vec()));
        } else {
            out.push((rel, std::fs::read(&path).unwrap()));
        }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        // directories may have been chmod'ed by the unpacker
        fn fix(p: &Path) {
            if let Ok(rd) = std::fs::read_dir(p) {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755));
                for e in rd.flatten() {
                    if e.file_type().is_ok_and(|t| t.is_dir()) {
                        fix(&e.path());
                    }
                }
            }
        }
        fix(&self.base);
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

// ---------- tar ----------

pub struct Tar {
    buf: Vec<u8>,
    pub mtime: u64,
}

fn oct(dst: &mut [u8], v: u64) {
    let s = format!("{:0width$o}", v, width = dst.len() - 1);
    let n = dst.len() - 1;
    dst[..n].copy_from_slice(s.as_bytes());
    dst[n] = 0;
}

impl Tar {
    pub fn new() -> Tar {
        Tar { buf: Vec::new(), mtime: 1_600_000_000 }
    }

    fn header(&mut self, name: &str, ty: u8, mode: u32, link: &str, size: usize) {
        let mut name_field = name.to_string();
        if name.len() > 100 {
            // GNU long name record
            let mut data = name.as_bytes().to_vec();
            data.push(0);
            self.header("././@LongLink", b'L', 0o644, "", data.len());
            self.buf.extend_from_slice(&data);
            self.buf.resize(self.buf.len().div_ceil(512) * 512, 0);
            name_field = name[..100].to_string();
        }
        let mut link_field = link.to_string();
        if link.len() > 100 {
            let mut data = link.as_bytes().to_vec();
            data.push(0);
            self.header("././@LongLink", b'K', 0o644, "", data.len());
            self.buf.extend_from_slice(&data);
            self.buf.resize(self.buf.len().div_ceil(512) * 512, 0);
            link_field = link[..100].to_string();
        }
        let link = link_field.as_str();
        let mut h = [0u8; 512];
        h[..name_field.len()].copy_from_slice(name_field.as_bytes());
        oct(&mut h[100..108], mode as u64);
        oct(&mut h[108..116], 0);
        oct(&mut h[116..124], 0);
        oct(&mut h[124..136], size as u64);
        oct(&mut h[136..148], self.mtime);
        h[148..156].fill(b' ');
        h[156] = ty;
        assert!(link.len() <= 100);
        h[157..157 + link.len()].copy_from_slice(link.as_bytes());
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        let s = format!("{:06o}\0 ", sum);
        h[148..156].copy_from_slice(s.as_bytes());
        self.buf.extend_from_slice(&h);
    }

    pub fn file(&mut self, name: &str, mode: u32, data: &[u8]) -> &mut Self {
        self.header(name, b'0', mode, "", data.len());
        self.buf.extend_from_slice(data);
        self.buf.resize(self.buf.len().div_ceil(512) * 512, 0);
        self
    }
    pub fn dir(&mut self, name: &str, mode: u32) -> &mut Self {
        let n = if name.is_empty() { "./".to_string() } else { format!("{name}/") };
        self.header(&n, b'5', mode, "", 0);
        self
    }
    pub fn symlink(&mut self, name: &str, target: &str) -> &mut Self {
        self.header(name, b'2', 0o777, target, 0);
        self
    }
    pub fn hardlink(&mut self, name: &str, target: &str) -> &mut Self {
        self.header(name, b'1', 0o644, target, 0);
        self
    }
    pub fn node(&mut self, name: &str, ty: u8) -> &mut Self {
        self.header(name, ty, 0o644, "", 0);
        self
    }
    pub fn raw_file_header(&mut self, name: &str, size: usize) -> &mut Self {
        self.header(name, b'0', 0o644, "", size);
        self
    }
    pub fn raw(&mut self, data: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(data);
        self
    }

    pub fn finish(&self) -> Vec<u8> {
        let mut v = self.buf.clone();
        v.extend_from_slice(&[0u8; 1024]);
        v
    }
}

// ---------- gzip ----------

/// A valid gzip stream using stored (uncompressed) deflate blocks.
pub fn gzip_stored(data: &[u8]) -> Vec<u8> {
    let mut v = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
    let mut chunks: Vec<&[u8]> = data.chunks(65535).collect();
    if chunks.is_empty() {
        chunks.push(&[]);
    }
    let n = chunks.len();
    for (i, c) in chunks.into_iter().enumerate() {
        v.push(if i + 1 == n { 1 } else { 0 });
        v.extend_from_slice(&(c.len() as u16).to_le_bytes());
        v.extend_from_slice(&(!(c.len() as u16)).to_le_bytes());
        v.extend_from_slice(c);
    }
    v.extend_from_slice(&kr_archive::crc32::crc32(data).to_le_bytes());
    v.extend_from_slice(&(data.len() as u32).to_le_bytes());
    v
}

/// Real compression through the system gzip, if installed.
pub fn gzip_system(data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut c = Command::new("gzip").arg("-c").stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().ok()?;
    let mut stdin = c.stdin.take()?;
    let data = data.to_vec();
    let t = std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });
    let out = c.wait_with_output().ok()?;
    t.join().ok()?;
    out.status.success().then_some(out.stdout)
}
