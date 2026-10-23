//! Streaming tar reader (ustar, pax, GNU long names), OCI whiteout helpers
//! and path sanitizing.
//!
//! # Reading
//!
//! ```ignore
//! let mut r = TarReader::new();
//! r.feed(chunk, &mut |ev| { match ev { Event::Entry(e) => .., Event::Data(d) => .., Event::End => .. } Ok::<(), ()>(()) })?;
//! r.finish()?;
//! ```
//!
//! For each member the callback sees `Entry`, zero or more `Data` chunks
//! (only for regular files, borrowed from the input), then `End`.
//!
//! Supported: ustar (with `prefix`), pax `x`/`g` headers (`path`, `linkpath`,
//! `size`, `uid`, `gid`, `mtime`, `SCHILY.xattr.*`), GNU `L`/`K` long
//! name/link records, base-256 numeric fields, header checksum verification.
//! Precedence is pax > GNU long > header. Global (`g`) pax headers only
//! provide defaults for `uid`, `gid`, `mtime` and xattrs; `path`, `linkpath`
//! and `size` in a global header are ignored. Sparse files and unknown type
//! flags are rejected. Strings must be valid UTF-8. `mtime` fractions are
//! truncated.
//!
//! # Security
//!
//! [`sanitize`] is lexical only. The runtime MUST ALSO guard symlink
//! traversal at extraction time (never follow symlinks in parent
//! directories, e.g. `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` or
//! `O_NOFOLLOW` component walks), and must validate `linkname` targets of
//! symlinks/hardlinks itself. That is outside this crate.

use crate::Error;
use alloc::string::String;
use alloc::vec::Vec;

const BLOCK: usize = 512;
const META_LIMIT: u64 = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
    Hardlink,
    CharDev,
    BlockDev,
    Fifo,
}

/// A tar member header after pax/GNU overrides are applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub kind: Kind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: i64,
    /// Number of data bytes that follow (always 0 for non-files).
    pub size: u64,
    pub linkname: String,
    pub devmajor: u32,
    pub devminor: u32,
    /// `SCHILY.xattr.<name>` pax records as (name, value).
    pub xattrs: Vec<(String, Vec<u8>)>,
}

#[derive(Debug)]
pub enum Event<'a> {
    Entry(&'a Entry),
    Data(&'a [u8]),
    /// All data of the current entry has been delivered.
    End,
}

#[derive(Default, Clone)]
struct Pax {
    path: Option<String>,
    linkpath: Option<String>,
    size: Option<u64>,
    uid: Option<u64>,
    gid: Option<u64>,
    mtime: Option<i64>,
    xattrs: Vec<(String, Vec<u8>)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MetaKind {
    PaxLocal,
    PaxGlobal,
    LongName,
    LongLink,
}

enum St {
    Header,
    Data { rem: u64, pad: u64 },
    Meta { kind: MetaKind, rem: u64, pad: u64 },
    Skip(u64),
    Ended,
    Failed,
}

/// Push-based tar parser.
pub struct TarReader {
    st: St,
    hdr: [u8; BLOCK],
    hlen: usize,
    zero_blocks: u8,
    meta: Vec<u8>,
    global: Pax,
    local: Pax,
    long_name: Option<String>,
    long_link: Option<String>,
}

impl Default for TarReader {
    fn default() -> Self {
        Self::new()
    }
}

impl TarReader {
    pub fn new() -> Self {
        TarReader {
            st: St::Header,
            hdr: [0; BLOCK],
            hlen: 0,
            zero_blocks: 0,
            meta: Vec::new(),
            global: Pax::default(),
            local: Pax::default(),
            long_name: None,
            long_link: None,
        }
    }

    /// True after the end-of-archive marker (two zero blocks) was seen.
    pub fn is_ended(&self) -> bool {
        matches!(self.st, St::Ended)
    }

    /// Call after the last `feed`: fails if input stopped mid-header,
    /// mid-entry or after a dangling pax/GNU record. Ending at a header
    /// boundary without zero blocks is accepted.
    pub fn finish(&self) -> Result<(), Error> {
        match self.st {
            St::Ended => Ok(()),
            St::Header
                if self.hlen == 0
                    && self.local.is_empty()
                    && self.long_name.is_none()
                    && self.long_link.is_none() =>
            {
                Ok(())
            }
            St::Failed => Err(Error::Failed),
            _ => Err(Error::Truncated),
        }
    }

    pub fn feed<E>(
        &mut self,
        mut input: &[u8],
        cb: &mut dyn FnMut(Event<'_>) -> Result<(), E>,
    ) -> Result<(), Error<E>> {
        let r = self.feed_inner(&mut input, cb);
        if r.is_err() {
            self.st = St::Failed;
        }
        r
    }

    fn feed_inner<E>(
        &mut self,
        input: &mut &[u8],
        cb: &mut dyn FnMut(Event<'_>) -> Result<(), E>,
    ) -> Result<(), Error<E>> {
        while !input.is_empty() {
            match self.st {
                St::Ended => {
                    *input = &[];
                }
                St::Failed => return Err(Error::Failed),
                St::Skip(n) => {
                    let k = (n.min(input.len() as u64)) as usize;
                    *input = &input[k..];
                    self.st = if n == k as u64 { St::Header } else { St::Skip(n - k as u64) };
                }
                St::Data { rem, pad } => {
                    let k = (rem.min(input.len() as u64)) as usize;
                    cb(Event::Data(&input[..k])).map_err(Error::Sink)?;
                    *input = &input[k..];
                    let rem = rem - k as u64;
                    if rem == 0 {
                        cb(Event::End).map_err(Error::Sink)?;
                        self.st = if pad > 0 { St::Skip(pad) } else { St::Header };
                    } else {
                        self.st = St::Data { rem, pad };
                    }
                }
                St::Meta { kind, rem, pad } => {
                    let k = (rem.min(input.len() as u64)) as usize;
                    self.meta.extend_from_slice(&input[..k]);
                    *input = &input[k..];
                    let rem = rem - k as u64;
                    if rem == 0 {
                        self.finish_meta(kind)?;
                        self.st = if pad > 0 { St::Skip(pad) } else { St::Header };
                    } else {
                        self.st = St::Meta { kind, rem, pad };
                    }
                }
                St::Header => {
                    if self.hlen == 0 && input.len() >= BLOCK {
                        let mut b = [0u8; BLOCK];
                        b.copy_from_slice(&input[..BLOCK]);
                        *input = &input[BLOCK..];
                        self.on_block(&b, cb)?;
                    } else {
                        let k = (BLOCK - self.hlen).min(input.len());
                        self.hdr[self.hlen..self.hlen + k].copy_from_slice(&input[..k]);
                        self.hlen += k;
                        *input = &input[k..];
                        if self.hlen == BLOCK {
                            self.hlen = 0;
                            let b = self.hdr;
                            self.on_block(&b, cb)?;
                        }
                    }
                }
            }
        }
        // A zero-size final state transition may be pending (e.g. rem == 0
        // entries are handled in on_block), nothing else to do.
        Ok(())
    }

    fn finish_meta<E>(&mut self, kind: MetaKind) -> Result<(), Error<E>> {
        let buf = core::mem::take(&mut self.meta);
        match kind {
            MetaKind::LongName | MetaKind::LongLink => {
                let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                let s = String::from_utf8(buf[..end].to_vec()).map_err(|_| Error::InvalidUtf8)?;
                if kind == MetaKind::LongName {
                    self.long_name = Some(s);
                } else {
                    self.long_link = Some(s);
                }
            }
            MetaKind::PaxLocal => parse_pax(&buf, &mut self.local, false)?,
            MetaKind::PaxGlobal => parse_pax(&buf, &mut self.global, true)?,
        }
        Ok(())
    }

    fn on_block<E>(
        &mut self,
        b: &[u8; BLOCK],
        cb: &mut dyn FnMut(Event<'_>) -> Result<(), E>,
    ) -> Result<(), Error<E>> {
        if b.iter().all(|&x| x == 0) {
            self.zero_blocks += 1;
            if self.zero_blocks >= 2 {
                self.st = St::Ended;
            }
            return Ok(());
        }
        self.zero_blocks = 0;
        verify_checksum(b)?;
        let typeflag = b[156];
        let hsize = parse_u64(&b[124..136])?;

        let meta_kind = match typeflag {
            b'x' => Some(MetaKind::PaxLocal),
            b'g' => Some(MetaKind::PaxGlobal),
            b'L' => Some(MetaKind::LongName),
            b'K' => Some(MetaKind::LongLink),
            _ => None,
        };
        if let Some(kind) = meta_kind {
            if hsize > META_LIMIT {
                return Err(Error::MetaTooLarge);
            }
            self.meta.clear();
            let pad = padding(hsize);
            if hsize == 0 {
                self.finish_meta(kind)?;
                if pad > 0 {
                    self.st = St::Skip(pad);
                }
            } else {
                self.st = St::Meta { kind, rem: hsize, pad };
            }
            return Ok(());
        }

        let mut kind = match typeflag {
            0 | b'0' | b'7' => Kind::File,
            b'1' => Kind::Hardlink,
            b'2' => Kind::Symlink,
            b'3' => Kind::CharDev,
            b'4' => Kind::BlockDev,
            b'5' => Kind::Dir,
            b'6' => Kind::Fifo,
            t => return Err(Error::UnsupportedType(t)),
        };

        let local = core::mem::take(&mut self.local);
        let long_name = self.long_name.take();
        let long_link = self.long_link.take();
        let g = &self.global;

        // Path.
        let path = if let Some(p) = local.path {
            p
        } else if let Some(p) = long_name {
            p
        } else {
            let name = cstr(&b[0..100])?;
            let posix = &b[257..263] == b"ustar\0";
            let prefix = if posix { cstr(&b[345..500])? } else { "" };
            if prefix.is_empty() {
                String::from(name)
            } else {
                let mut s = String::from(prefix);
                s.push('/');
                s.push_str(name);
                s
            }
        };
        let linkname = if let Some(p) = local.linkpath {
            p
        } else if let Some(p) = long_link {
            p
        } else {
            String::from(cstr(&b[157..257])?)
        };
        if kind == Kind::File && path.ends_with('/') {
            kind = Kind::Dir;
        }

        let to_u32 = |v: u64| u32::try_from(v).map_err(|_| Error::<E>::BadNumber);
        let uid = to_u32(match local.uid.or(g.uid) {
            Some(v) => v,
            None => parse_u64(&b[108..116])?,
        })?;
        let gid = to_u32(match local.gid.or(g.gid) {
            Some(v) => v,
            None => parse_u64(&b[116..124])?,
        })?;
        let mtime = match local.mtime.or(g.mtime) {
            Some(v) => v,
            None => parse_i64(&b[136..148])?,
        };
        let mode = (parse_u64(&b[100..108])? & 0o7777) as u32;
        let (devmajor, devminor) = if matches!(kind, Kind::CharDev | Kind::BlockDev) {
            (to_u32(parse_u64(&b[329..337])?)?, to_u32(parse_u64(&b[337..345])?)?)
        } else {
            (0, 0)
        };
        let size = if kind == Kind::File { local.size.unwrap_or(hsize) } else { 0 };

        let mut xattrs = g.xattrs.clone();
        for (k, v) in local.xattrs {
            match xattrs.iter_mut().find(|(n, _)| *n == k) {
                Some(slot) => slot.1 = v,
                None => xattrs.push((k, v)),
            }
        }

        let entry = Entry { path, kind, mode, uid, gid, mtime, size, linkname, devmajor, devminor, xattrs };
        cb(Event::Entry(&entry)).map_err(Error::Sink)?;
        if size == 0 {
            cb(Event::End).map_err(Error::Sink)?;
            self.st = St::Header;
        } else {
            self.st = St::Data { rem: size, pad: padding(size) };
        }
        Ok(())
    }
}

impl Pax {
    fn is_empty(&self) -> bool {
        self.path.is_none()
            && self.linkpath.is_none()
            && self.size.is_none()
            && self.uid.is_none()
            && self.gid.is_none()
            && self.mtime.is_none()
            && self.xattrs.is_empty()
    }
}

fn padding(size: u64) -> u64 {
    (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64
}

fn cstr<E>(f: &[u8]) -> Result<&str, Error<E>> {
    let end = f.iter().position(|&b| b == 0).unwrap_or(f.len());
    core::str::from_utf8(&f[..end]).map_err(|_| Error::InvalidUtf8)
}

fn verify_checksum<E>(b: &[u8; BLOCK]) -> Result<(), Error<E>> {
    let stored = parse_u64::<E>(&b[148..156]).map_err(|_| Error::BadChecksum)?;
    let mut unsigned = 0u64;
    let mut signed = 0i64;
    for (i, &x) in b.iter().enumerate() {
        let x = if (148..156).contains(&i) { b' ' } else { x };
        unsigned += x as u64;
        signed += x as i8 as i64;
    }
    if stored == unsigned || stored as i64 == signed {
        Ok(())
    } else {
        Err(Error::BadChecksum)
    }
}

/// Octal or GNU base-256 unsigned field.
fn parse_u64<E>(f: &[u8]) -> Result<u64, Error<E>> {
    if f[0] & 0x80 != 0 {
        if f[0] & 0x40 != 0 {
            return Err(Error::BadNumber); // negative
        }
        let mut v = (f[0] & 0x3f) as u64;
        for &x in &f[1..] {
            v = v.checked_mul(256).ok_or(Error::BadNumber)? | x as u64;
        }
        return Ok(v);
    }
    let mut i = 0;
    while i < f.len() && f[i] == b' ' {
        i += 1;
    }
    let mut v = 0u64;
    while i < f.len() && (b'0'..=b'7').contains(&f[i]) {
        v = v.checked_mul(8).ok_or(Error::BadNumber)? | (f[i] - b'0') as u64;
        i += 1;
    }
    if i < f.len() && f[i] != 0 && f[i] != b' ' {
        return Err(Error::BadNumber);
    }
    Ok(v)
}

fn parse_i64<E>(f: &[u8]) -> Result<i64, Error<E>> {
    if f[0] & 0x80 != 0 && f[0] & 0x40 != 0 {
        // Negative base-256 (two's complement over the whole field).
        let mut v: i64 = -1;
        for &x in &f[f.len().saturating_sub(8)..] {
            v = (v << 8) | x as i64;
        }
        if f.len() > 8 && f[1..f.len() - 8].iter().any(|&x| x != 0xff) {
            return Err(Error::BadNumber);
        }
        return Ok(v);
    }
    i64::try_from(parse_u64::<E>(f)?).map_err(|_| Error::BadNumber)
}

fn dec_u64<E>(s: &[u8]) -> Result<u64, Error<E>> {
    if s.is_empty() {
        return Err(Error::BadPax);
    }
    let mut v = 0u64;
    for &c in s {
        if !c.is_ascii_digit() {
            return Err(Error::BadPax);
        }
        v = v.checked_mul(10).and_then(|v| v.checked_add((c - b'0') as u64)).ok_or(Error::BadPax)?;
    }
    Ok(v)
}

fn utf8<E>(v: &[u8]) -> Result<String, Error<E>> {
    String::from_utf8(v.to_vec()).map_err(|_| Error::InvalidUtf8)
}

fn parse_pax<E>(mut buf: &[u8], p: &mut Pax, global: bool) -> Result<(), Error<E>> {
    while !buf.is_empty() {
        let sp = buf.iter().position(|&b| b == b' ').ok_or(Error::BadPax)?;
        let len = dec_u64::<E>(&buf[..sp])? as usize;
        if len <= sp + 1 || len > buf.len() || buf[len - 1] != b'\n' {
            return Err(Error::BadPax);
        }
        let rec = &buf[sp + 1..len - 1];
        buf = &buf[len..];
        let eq = rec.iter().position(|&b| b == b'=').ok_or(Error::BadPax)?;
        let (key, val) = (&rec[..eq], &rec[eq + 1..]);
        match key {
            b"path" if !global => p.path = Some(utf8(val)?),
            b"linkpath" if !global => p.linkpath = Some(utf8(val)?),
            b"size" if !global => p.size = Some(dec_u64(val)?),
            b"uid" => p.uid = Some(dec_u64(val)?),
            b"gid" => p.gid = Some(dec_u64(val)?),
            b"mtime" => {
                let (neg, rest) = match val.split_first() {
                    Some((b'-', r)) => (true, r),
                    _ => (false, val),
                };
                let int = rest.split(|&c| c == b'.').next().unwrap_or(&[]);
                let v = i64::try_from(dec_u64::<E>(int)?).map_err(|_| Error::BadPax)?;
                p.mtime = Some(if neg { -v } else { v });
            }
            k if k.starts_with(b"SCHILY.xattr.") => {
                let name = utf8(&k[b"SCHILY.xattr.".len()..])?;
                match p.xattrs.iter_mut().find(|(n, _)| *n == name) {
                    Some(slot) => slot.1 = val.to_vec(),
                    None => p.xattrs.push((name, val.to_vec())),
                }
            }
            _ => {}
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Paths and OCI whiteouts
// ---------------------------------------------------------------------------

/// A relative, lexically normalized path: no leading `/`, no `.`/`..`/empty
/// components, no trailing slash. The empty string denotes the root
/// (e.g. the `./` entry in many layers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedPath(String);

impl NormalizedPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }
    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.0.split('/').filter(|c| !c.is_empty())
    }
    pub fn into_string(self) -> String {
        self.0
    }
}

/// Normalize a tar member path. Rejects absolute paths, NUL bytes and any
/// `..` that would climb above the root (`a/../b` is fine, `a/../../b` is
/// not). `.`, empty components and trailing slashes are dropped.
///
/// This is purely lexical: the extractor must still defend against symlinks
/// planted by earlier entries (see the module docs).
pub fn sanitize(path: &str) -> Result<NormalizedPath, Error> {
    if path.starts_with('/') || path.contains('\0') {
        return Err(Error::UnsafePath);
    }
    let mut out = String::with_capacity(path.len());
    for comp in path.split('/') {
        match comp {
            "" | "." => {}
            ".." => match out.rfind('/') {
                Some(i) => out.truncate(i),
                None if !out.is_empty() => out.clear(),
                None => return Err(Error::UnsafePath),
            },
            c => {
                if !out.is_empty() {
                    out.push('/');
                }
                out.push_str(c);
            }
        }
    }
    Ok(NormalizedPath(out))
}

/// OCI layer whiteout classification of a (preferably sanitized) path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Whiteout {
    /// `dir/.wh..wh..opq`: hide all lower-layer content of `dir` (empty
    /// string = the root). Content from the same layer is kept.
    Opaque(String),
    /// `dir/.wh.name`: delete `dir/name` from lower layers. The whiteout
    /// entry itself must not be extracted.
    Remove(String),
}

const WH_PREFIX: &str = ".wh.";
const WH_OPAQUE: &str = ".wh..wh..opq";

/// Classify `path` as an OCI whiteout. Other names starting with `.wh..wh.`
/// are reserved metadata (see [`is_reserved_whiteout`]) and return `None`.
pub fn whiteout(path: &str) -> Option<Whiteout> {
    let trimmed = path.trim_end_matches('/');
    let (dir, base) = match trimmed.rfind('/') {
        Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
        None => ("", trimmed),
    };
    if base == WH_OPAQUE {
        return Some(Whiteout::Opaque(String::from(dir)));
    }
    let name = base.strip_prefix(WH_PREFIX)?;
    if name.is_empty() || name.starts_with(".wh.") {
        return None;
    }
    let mut s = String::from(dir);
    if !s.is_empty() {
        s.push('/');
    }
    s.push_str(name);
    Some(Whiteout::Remove(s))
}

/// True for `.wh..wh.*` names that are not a plain opaque marker (e.g.
/// `.wh..wh.plnk`, `.wh..wh.aufs`); extractors should skip these.
pub fn is_reserved_whiteout(path: &str) -> bool {
    let base = path.trim_end_matches('/').rsplit('/').next().unwrap_or("");
    base.starts_with(".wh..wh.") && base != WH_OPAQUE
}
