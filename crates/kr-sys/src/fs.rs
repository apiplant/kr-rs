//! Filesystem syscalls used by layer unpacking and the image store (ADR-017).
//!
//! Every path argument is a NUL-terminated byte slice (a poor man's `&CStr`). The slice must end
//! in exactly one NUL and contain no other NUL byte, otherwise the call fails with `EINVAL`
//! before reaching the kernel: an interior NUL would silently truncate the path, which is a
//! classic traversal bug.
extern crate alloc;

use super::{check, syscall0, syscall2, syscall3, syscall4, syscall5, Errno, Fd, Result, Timespec};
use alloc::vec::Vec;
use core::marker::PhantomData;

// ---- errno values ----
pub const EPERM: i32 = 1;
pub const ENOENT: i32 = 2;
pub const EACCES: i32 = 13;
pub const EEXIST: i32 = 17;
pub const EXDEV: i32 = 18;
pub const ENOTDIR: i32 = 20;
pub const EISDIR: i32 = 21;
pub const EINVAL: i32 = 22;
pub const ENOTEMPTY: i32 = 39;
pub const ELOOP: i32 = 40;
pub const ENODATA: i32 = 61;
pub const ENOTSUP: i32 = 95;

// ---- open(2) flags ----
pub const O_RDONLY: i32 = 0;
pub const O_WRONLY: i32 = 1;
pub const O_RDWR: i32 = 2;
pub const O_CREAT: i32 = 0o100;
pub const O_EXCL: i32 = 0o200;
pub const O_TRUNC: i32 = 0o1000;
pub const O_PATH: i32 = 0o10000000;
pub const O_CLOEXEC: i32 = 0o2000000;
#[cfg(target_arch = "x86_64")]
pub const O_DIRECTORY: i32 = 0o200000;
#[cfg(target_arch = "x86_64")]
pub const O_NOFOLLOW: i32 = 0o400000;
#[cfg(target_arch = "aarch64")]
pub const O_DIRECTORY: i32 = 0o40000;
#[cfg(target_arch = "aarch64")]
pub const O_NOFOLLOW: i32 = 0o100000;

// ---- openat2(2) resolve flags ----
pub const RESOLVE_NO_XDEV: u64 = 0x01;
pub const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
pub const RESOLVE_NO_SYMLINKS: u64 = 0x04;
pub const RESOLVE_BENEATH: u64 = 0x08;
pub const RESOLVE_IN_ROOT: u64 = 0x10;

// ---- *at flags ----
pub const AT_FDCWD: i32 = -100;
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
pub const AT_REMOVEDIR: i32 = 0x200;
pub const AT_SYMLINK_FOLLOW: i32 = 0x400;
pub const AT_EMPTY_PATH: i32 = 0x1000;
pub const RENAME_NOREPLACE: u32 = 1;
pub const RENAME_EXCHANGE: u32 = 2;
pub const UTIME_NOW: i64 = (1 << 30) - 1;
pub const UTIME_OMIT: i64 = (1 << 30) - 2;

// ---- st_mode ----
pub const S_IFMT: u32 = 0o170000;
pub const S_IFIFO: u32 = 0o010000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;

// ---- d_type ----
pub const DT_UNKNOWN: u8 = 0;
pub const DT_DIR: u8 = 4;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;

#[cfg(target_arch = "x86_64")]
mod nr {
    pub const FSTAT: usize = 5;
    pub const FTRUNCATE: usize = 77;
    pub const FSYNC: usize = 74;
    pub const FCHMOD: usize = 91;
    pub const FCHMODAT: usize = 268;
    pub const GETUID: usize = 102;
    pub const GETPID: usize = 39;
    pub const GETPPID: usize = 110;
    pub const FSETXATTR: usize = 190;
    pub const GETDENTS64: usize = 217;
    pub const OPENAT: usize = 257;
    pub const MKDIRAT: usize = 258;
    pub const MKNODAT: usize = 259;
    pub const FCHOWNAT: usize = 260;
    pub const NEWFSTATAT: usize = 262;
    pub const UNLINKAT: usize = 263;
    pub const LINKAT: usize = 265;
    pub const SYMLINKAT: usize = 266;
    pub const READLINKAT: usize = 267;
    pub const UTIMENSAT: usize = 280;
    pub const RENAMEAT2: usize = 316;
    pub const OPENAT2: usize = 437;
}

#[cfg(target_arch = "aarch64")]
mod nr {
    pub const FSTAT: usize = 80;
    pub const FTRUNCATE: usize = 46;
    pub const FSYNC: usize = 82;
    pub const FCHMOD: usize = 52;
    pub const FCHMODAT: usize = 53;
    pub const GETUID: usize = 174;
    pub const GETPID: usize = 172;
    pub const GETPPID: usize = 173;
    pub const FSETXATTR: usize = 7;
    pub const GETDENTS64: usize = 61;
    pub const OPENAT: usize = 56;
    pub const MKDIRAT: usize = 34;
    pub const MKNODAT: usize = 33;
    pub const FCHOWNAT: usize = 54;
    pub const NEWFSTATAT: usize = 79;
    pub const UNLINKAT: usize = 35;
    pub const LINKAT: usize = 37;
    pub const SYMLINKAT: usize = 36;
    pub const READLINKAT: usize = 78;
    pub const UTIMENSAT: usize = 88;
    pub const RENAMEAT2: usize = 276;
    pub const OPENAT2: usize = 437;
}

/// Validates a NUL-terminated path (exactly one NUL, at the end) and returns its address.
fn cp(p: &[u8]) -> Result<usize> {
    match p.iter().position(|&b| b == 0) {
        Some(i) if i + 1 == p.len() => Ok(p.as_ptr() as usize),
        _ => Err(Errno(EINVAL)),
    }
}

/// `open_how` for openat2(2).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct OpenHow {
    pub flags: u64,
    pub mode: u64,
    pub resolve: u64,
}

pub fn openat(dirfd: i32, path: &[u8], flags: i32, mode: u32) -> Result<Fd> {
    let p = cp(path)?;
    // SAFETY: `p` is a valid NUL-terminated string that outlives the call.
    check(unsafe { syscall4(nr::OPENAT, dirfd as usize, p, flags as usize, mode as usize) }).map(|r| Fd(r as i32))
}

pub fn openat2(dirfd: i32, path: &[u8], how: &OpenHow) -> Result<Fd> {
    let p = cp(path)?;
    // SAFETY: `p` is NUL-terminated; `how` is a valid repr(C) open_how of the stated size.
    check(unsafe {
        syscall4(nr::OPENAT2, dirfd as usize, p, how as *const OpenHow as usize, core::mem::size_of::<OpenHow>())
    })
    .map(|r| Fd(r as i32))
}

/// openat2 confined to `root` (a directory fd): the kernel treats `root` as `/`, so `..` and
/// absolute symlinks cannot escape, and magic links are refused. `O_CLOEXEC` is always added.
pub fn open_in_root(root: i32, path: &[u8], flags: i32, mode: u32) -> Result<Fd> {
    let how = OpenHow {
        flags: (flags | O_CLOEXEC) as u64,
        mode: mode as u64,
        resolve: RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
    };
    openat2(root, path, &how)
}

pub fn mkdirat(dirfd: i32, path: &[u8], mode: u32) -> Result<()> {
    let p = cp(path)?;
    // SAFETY: `p` is NUL-terminated.
    check(unsafe { syscall3(nr::MKDIRAT, dirfd as usize, p, mode as usize) }).map(|_| ())
}

pub fn mknodat(dirfd: i32, path: &[u8], mode: u32, dev: u64) -> Result<()> {
    let p = cp(path)?;
    // SAFETY: `p` is NUL-terminated.
    check(unsafe { syscall4(nr::MKNODAT, dirfd as usize, p, mode as usize, dev as usize) }).map(|_| ())
}

/// Creates a symlink `linkpath` (relative to `newdirfd`) containing `target` verbatim.
pub fn symlinkat(target: &[u8], newdirfd: i32, linkpath: &[u8]) -> Result<()> {
    let t = cp(target)?;
    let l = cp(linkpath)?;
    // SAFETY: both are NUL-terminated.
    check(unsafe { syscall3(nr::SYMLINKAT, t, newdirfd as usize, l) }).map(|_| ())
}

pub fn linkat(olddirfd: i32, oldpath: &[u8], newdirfd: i32, newpath: &[u8], flags: i32) -> Result<()> {
    let o = cp(oldpath)?;
    let n = cp(newpath)?;
    // SAFETY: both are NUL-terminated.
    check(unsafe { syscall5(nr::LINKAT, olddirfd as usize, o, newdirfd as usize, n, flags as usize) }).map(|_| ())
}

/// `flags` is 0 or [`AT_REMOVEDIR`].
pub fn unlinkat(dirfd: i32, path: &[u8], flags: i32) -> Result<()> {
    let p = cp(path)?;
    // SAFETY: `p` is NUL-terminated.
    check(unsafe { syscall3(nr::UNLINKAT, dirfd as usize, p, flags as usize) }).map(|_| ())
}

pub fn renameat2(olddirfd: i32, oldpath: &[u8], newdirfd: i32, newpath: &[u8], flags: u32) -> Result<()> {
    let o = cp(oldpath)?;
    let n = cp(newpath)?;
    // SAFETY: both are NUL-terminated.
    check(unsafe { syscall5(nr::RENAMEAT2, olddirfd as usize, o, newdirfd as usize, n, flags as usize) }).map(|_| ())
}

/// Reads a symlink into `buf`; returns the byte count (not NUL-terminated).
pub fn readlinkat(dirfd: i32, path: &[u8], buf: &mut [u8]) -> Result<usize> {
    let p = cp(path)?;
    // SAFETY: `p` is NUL-terminated; `buf` is a valid writable region.
    check(unsafe { syscall4(nr::READLINKAT, dirfd as usize, p, buf.as_mut_ptr() as usize, buf.len()) })
}

/// Fails with `EBADF` on `O_PATH` descriptors.
pub fn fchmod(fd: i32, mode: u32) -> Result<()> {
    // SAFETY: integer-only arguments.
    check(unsafe { syscall2(nr::FCHMOD, fd as usize, mode as usize) }).map(|_| ())
}

/// Pass `AT_SYMLINK_NOFOLLOW` to change a symlink itself. `u32::MAX` leaves an id unchanged.
pub fn fchownat(dirfd: i32, path: &[u8], uid: u32, gid: u32, flags: i32) -> Result<()> {
    let p = cp(path)?;
    // SAFETY: `p` is NUL-terminated.
    check(unsafe { syscall5(nr::FCHOWNAT, dirfd as usize, p, uid as usize, gid as usize, flags as usize) })
        .map(|_| ())
}

/// `times` is `[atime, mtime]`; use `tv_nsec = UTIME_OMIT` to leave one unchanged. With
/// `path = None` this is futimens(dirfd).
pub fn utimensat(dirfd: i32, path: Option<&[u8]>, times: &[Timespec; 2], flags: i32) -> Result<()> {
    let p = match path {
        Some(p) => cp(p)?,
        None => 0,
    };
    // SAFETY: `p` is null or NUL-terminated; `times` points at two repr(C) timespecs.
    check(unsafe { syscall4(nr::UTIMENSAT, dirfd as usize, p, times.as_ptr() as usize, flags as usize) })
        .map(|_| ())
}

pub fn futimens(fd: i32, times: &[Timespec; 2]) -> Result<()> {
    utimensat(fd, None, times, 0)
}

/// Sets an extended attribute on an open (non-`O_PATH`) descriptor. `name` is NUL-terminated.
pub fn fsetxattr(fd: i32, name: &[u8], value: &[u8], flags: i32) -> Result<()> {
    let n = cp(name)?;
    // SAFETY: `n` is NUL-terminated; `value` is a valid readable region.
    check(unsafe { syscall5(nr::FSETXATTR, fd as usize, n, value.as_ptr() as usize, value.len(), flags as usize) })
        .map(|_| ())
}

pub fn ftruncate(fd: i32, len: u64) -> Result<()> {
    // SAFETY: integer-only arguments.
    check(unsafe { syscall2(nr::FTRUNCATE, fd as usize, len as usize) }).map(|_| ())
}

pub fn fsync(fd: i32) -> Result<()> {
    // SAFETY: integer-only argument.
    check(unsafe { syscall2(nr::FSYNC, fd as usize, 0) }).map(|_| ())
}

pub fn getuid() -> u32 {
    // SAFETY: getuid takes no arguments and cannot fail.
    unsafe { syscall0(nr::GETUID) as u32 }
}

pub fn getpid() -> u32 {
    // SAFETY: getpid takes no arguments and cannot fail.
    unsafe { syscall0(nr::GETPID) as u32 }
}

pub fn getppid() -> u32 {
    // SAFETY: getppid takes no arguments and cannot fail.
    unsafe { syscall0(nr::GETPPID) as u32 }
}

// ---- stat ----

/// Kernel `struct stat` on x86_64 (144 bytes).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy)]
struct RawStat {
    st_dev: u64,
    st_ino: u64,
    st_nlink: u64,
    st_mode: u32,
    st_uid: u32,
    st_gid: u32,
    _pad0: u32,
    st_rdev: u64,
    st_size: i64,
    st_blksize: i64,
    st_blocks: i64,
    st_atime: i64,
    st_atime_nsec: i64,
    st_mtime: i64,
    st_mtime_nsec: i64,
    st_ctime: i64,
    st_ctime_nsec: i64,
    _unused: [i64; 3],
}

/// Kernel `struct stat` of the asm-generic ABI used by aarch64 (128 bytes).
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Clone, Copy)]
struct RawStat {
    st_dev: u64,
    st_ino: u64,
    st_mode: u32,
    st_nlink: u32,
    st_uid: u32,
    st_gid: u32,
    st_rdev: u64,
    _pad1: u64,
    st_size: i64,
    st_blksize: i32,
    _pad2: i32,
    st_blocks: i64,
    st_atime: i64,
    st_atime_nsec: i64,
    st_mtime: i64,
    st_mtime_nsec: i64,
    st_ctime: i64,
    st_ctime_nsec: i64,
    _unused: [u32; 2],
}

#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<RawStat>() == 144);
#[cfg(target_arch = "aarch64")]
const _: () = assert!(core::mem::size_of::<RawStat>() == 128);

/// Architecture-independent subset of `struct stat`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stat {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub nlink: u64,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u64,
    pub size: i64,
    pub blksize: i64,
    pub blocks: i64,
    pub atime_sec: i64,
    pub atime_nsec: i64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
}

impl Stat {
    pub fn file_type(&self) -> u32 {
        self.mode & S_IFMT
    }
    pub fn is_dir(&self) -> bool {
        self.file_type() == S_IFDIR
    }
    pub fn is_file(&self) -> bool {
        self.file_type() == S_IFREG
    }
    pub fn is_symlink(&self) -> bool {
        self.file_type() == S_IFLNK
    }
}

#[allow(clippy::unnecessary_cast)] // field widths differ between architectures
impl From<RawStat> for Stat {
    fn from(r: RawStat) -> Stat {
        Stat {
            dev: r.st_dev,
            ino: r.st_ino,
            mode: r.st_mode,
            nlink: r.st_nlink as u64,
            uid: r.st_uid,
            gid: r.st_gid,
            rdev: r.st_rdev,
            size: r.st_size,
            blksize: r.st_blksize as i64,
            blocks: r.st_blocks,
            atime_sec: r.st_atime,
            atime_nsec: r.st_atime_nsec,
            mtime_sec: r.st_mtime,
            mtime_nsec: r.st_mtime_nsec,
            ctime_sec: r.st_ctime,
            ctime_nsec: r.st_ctime_nsec,
        }
    }
}

fn raw_stat_zero() -> core::mem::MaybeUninit<RawStat> {
    core::mem::MaybeUninit::zeroed()
}

/// stat/lstat relative to `dirfd`. Use `AT_SYMLINK_NOFOLLOW` for lstat semantics.
pub fn newfstatat(dirfd: i32, path: &[u8], flags: i32) -> Result<Stat> {
    let p = cp(path)?;
    let mut st = raw_stat_zero();
    // SAFETY: `p` is NUL-terminated; `st` is a writable buffer of the kernel's struct stat size.
    check(unsafe { syscall4(nr::NEWFSTATAT, dirfd as usize, p, st.as_mut_ptr() as usize, flags as usize) })?;
    // SAFETY: the kernel fully initialised the struct on success (and zero is valid anyway).
    Ok(Stat::from(unsafe { st.assume_init() }))
}

pub fn fstat(fd: i32) -> Result<Stat> {
    let mut st = raw_stat_zero();
    // SAFETY: `st` is a writable buffer of the kernel's struct stat size.
    check(unsafe { syscall2(nr::FSTAT, fd as usize, st.as_mut_ptr() as usize) })?;
    // SAFETY: initialised by the kernel on success; all-zero is valid regardless.
    Ok(Stat::from(unsafe { st.assume_init() }))
}

// ---- directories ----

/// Raw getdents64(2): fills `buf` with `linux_dirent64` records and returns the byte count
/// (0 = end of directory).
pub fn getdents64(fd: i32, buf: &mut [u8]) -> Result<usize> {
    // SAFETY: `buf` is a valid writable region.
    check(unsafe { syscall3(nr::GETDENTS64, fd as usize, buf.as_mut_ptr() as usize, buf.len()) })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub ino: u64,
    /// `DT_*` value; `DT_UNKNOWN` means the filesystem did not say (use `newfstatat`).
    pub kind: u8,
    /// Name without NUL. `.` and `..` are never returned.
    pub name: Vec<u8>,
}

impl DirEntry {
    /// The name with a trailing NUL, ready to pass to the `*at` calls.
    pub fn cname(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.name.len() + 1);
        v.extend_from_slice(&self.name);
        v.push(0);
        v
    }
}

/// Iterator over the entries of an open directory (`.`/`..` skipped).
pub struct ReadDir<'a> {
    fd: i32,
    buf: [u8; 8192],
    pos: usize,
    len: usize,
    done: bool,
    _fd: PhantomData<&'a Fd>,
}

/// Lists a directory opened for reading (not `O_PATH`).
pub fn read_dir(fd: &Fd) -> ReadDir<'_> {
    ReadDir { fd: fd.raw(), buf: [0; 8192], pos: 0, len: 0, done: false, _fd: PhantomData }
}

impl Iterator for ReadDir<'_> {
    type Item = Result<DirEntry>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.done {
                return None;
            }
            if self.pos >= self.len {
                match getdents64(self.fd, &mut self.buf) {
                    Ok(0) => {
                        self.done = true;
                        return None;
                    }
                    Ok(n) => {
                        self.pos = 0;
                        self.len = n;
                    }
                    Err(e) => {
                        self.done = true;
                        return Some(Err(e));
                    }
                }
            }
            let rec = &self.buf[self.pos..self.len];
            // linux_dirent64: u64 d_ino; i64 d_off; u16 d_reclen; u8 d_type; char d_name[]
            if rec.len() < 19 {
                self.done = true;
                return Some(Err(Errno(EINVAL)));
            }
            let reclen = u16::from_ne_bytes([rec[16], rec[17]]) as usize;
            if reclen < 19 || reclen > rec.len() {
                self.done = true;
                return Some(Err(Errno(EINVAL)));
            }
            let ino = u64::from_ne_bytes([rec[0], rec[1], rec[2], rec[3], rec[4], rec[5], rec[6], rec[7]]);
            let kind = rec[18];
            let nameb = &rec[19..reclen];
            let end = nameb.iter().position(|&b| b == 0).unwrap_or(nameb.len());
            let name = &nameb[..end];
            self.pos += reclen;
            if name == b"." || name == b".." {
                continue;
            }
            return Some(Ok(DirEntry { ino, kind, name: name.to_vec() }));
        }
    }
}

const REMOVE_MAX_DEPTH: usize = 512;

/// Recursively removes the entry `name` (one path component, NUL-terminated) of `dirfd`. A
/// symlink is unlinked, never followed. Missing entries are not an error. Directories that the
/// caller owns but cannot enter or write are made `0700` first.
/// chmod of `name` (one component under `dirfd`) without following a symlink: pins the inode with
/// an `O_PATH|O_NOFOLLOW` fd and changes it through its /proc magic link.
fn chmod_nofollow(dirfd: i32, name: &[u8], mode: u32) -> Result<()> {
    let how = OpenHow {
        flags: (O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
    };
    let p = openat2(dirfd, name, &how)?;
    let mut path = b"/proc/self/fd/".to_vec();
    let mut buf = [0u8; 20];
    let mut n = p.raw() as u32;
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    path.extend_from_slice(&buf[i..]);
    path.push(0);
    // SAFETY: path is NUL-terminated and outlives the call.
    check(unsafe { syscall4(nr::FCHMODAT, AT_FDCWD as usize, path.as_ptr() as usize, mode as usize, 0) }).map(|_| ())
}

pub fn remove_all(dirfd: i32, name: &[u8]) -> Result<()> {
    remove_depth(dirfd, name, 0)
}

fn is_single_component(name: &[u8]) -> bool {
    let n = &name[..name.len().saturating_sub(1)];
    !n.is_empty() && n != b"." && n != b".." && !n.contains(&b'/')
}

fn remove_depth(dirfd: i32, name: &[u8], depth: usize) -> Result<()> {
    cp(name)?;
    if !is_single_component(name) {
        return Err(Errno(EINVAL));
    }
    if depth > REMOVE_MAX_DEPTH {
        return Err(Errno(ELOOP));
    }
    match unlinkat(dirfd, name, 0) {
        Ok(()) => return Ok(()),
        Err(Errno(ENOENT)) => return Ok(()),
        Err(Errno(EISDIR)) | Err(Errno(EPERM)) => {}
        Err(e) => return Err(e),
    }
    let how = OpenHow {
        flags: (O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
    };
    let d = match openat2(dirfd, name, &how) {
        Ok(d) => d,
        Err(Errno(ENOENT)) => return Ok(()),
        // Unreadable dir we own (overlayfs leaves `work/work` as mode 000): make it accessible.
        Err(Errno(EACCES)) => {
            chmod_nofollow(dirfd, name, 0o700)?;
            openat2(dirfd, name, &how)?
        }
        Err(e) => return Err(e),
    };
    let _ = fchmod(d.raw(), 0o700);
    let mut kids = Vec::new();
    for e in read_dir(&d) {
        kids.push(e?);
    }
    for k in &kids {
        let c = k.cname();
        let is_dir = match k.kind {
            DT_DIR => true,
            DT_UNKNOWN => newfstatat(d.raw(), &c, AT_SYMLINK_NOFOLLOW).map(|s| s.is_dir()).unwrap_or(false),
            _ => false,
        };
        if is_dir {
            remove_depth(d.raw(), &c, depth + 1)?;
        } else {
            match unlinkat(d.raw(), &c, 0) {
                Ok(()) | Err(Errno(ENOENT)) => {}
                Err(e) => return Err(e),
            }
        }
    }
    drop(d);
    match unlinkat(dirfd, name, AT_REMOVEDIR) {
        Ok(()) | Err(Errno(ENOENT)) => Ok(()),
        Err(e) => Err(e),
    }
}

// ---- helpers ----

/// Writes all of `buf`, retrying on short writes and `EINTR`.
pub fn write_all(fd: i32, mut buf: &[u8]) -> Result<()> {
    while !buf.is_empty() {
        match super::write(fd, buf) {
            Ok(0) => return Err(Errno(5)), // EIO: a zero-length write made no progress
            Ok(n) => buf = &buf[n..],
            Err(Errno(super::EINTR)) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Appends everything readable from `fd` to `out`; fails with `EFBIG` once more than `limit`
/// bytes were read.
pub fn read_to_end(fd: i32, out: &mut Vec<u8>, limit: usize) -> Result<usize> {
    let mut total = 0usize;
    let mut chunk = [0u8; 8192];
    loop {
        match super::read(fd, &mut chunk) {
            Ok(0) => return Ok(total),
            Ok(n) => {
                total += n;
                if total > limit {
                    return Err(Errno(27)); // EFBIG
                }
                out.extend_from_slice(&chunk[..n]);
            }
            Err(Errno(super::EINTR)) => {}
            Err(e) => return Err(e),
        }
    }
}

/// Reads a whole file by NUL-terminated path.
pub fn read_file(path: &[u8], limit: usize) -> Result<Vec<u8>> {
    let fd = openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0)?;
    let mut v = Vec::new();
    read_to_end(fd.raw(), &mut v, limit)?;
    Ok(v)
}

