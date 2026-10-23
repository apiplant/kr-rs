//! Namespace / process syscalls (clone3, mount, pivot_root, ...), used by kr-runtime::container.

use super::{check, nr, syscall1, syscall2, syscall3, syscall4, syscall5, Errno, Fd, Result};

#[cfg(target_arch = "x86_64")]
mod n {
    pub const CLONE3: usize = 435;
    pub const WAIT4: usize = 61;
    pub const EXECVE: usize = 59;
    pub const MOUNT: usize = 165;
    pub const UMOUNT2: usize = 166;
    pub const PIVOT_ROOT: usize = 155;
    pub const CHDIR: usize = 80;
    pub const SETHOSTNAME: usize = 170;
    pub const GETUID: usize = 102;
    pub const GETGID: usize = 104;
    pub const PRCTL: usize = 157;
    pub const MKDIRAT: usize = 258;
    pub const KILL: usize = 62;
    pub const UNLINKAT: usize = 263;
    pub const CAPSET: usize = 126;
    pub const NANOSLEEP: usize = 35;
    pub const IOCTL: usize = 16;
    pub const SECCOMP: usize = 317;
    pub const SETRESUID: usize = 117;
    pub const SETRESGID: usize = 119;
    pub const SETGROUPS: usize = 116;
    pub const RT_SIGPROCMASK: usize = 14;
    pub const SIGNALFD4: usize = 289;
    pub const WAITID: usize = 247;
}

#[cfg(target_arch = "aarch64")]
mod n {
    pub const CLONE3: usize = 435;
    pub const WAIT4: usize = 260;
    pub const EXECVE: usize = 221;
    pub const MOUNT: usize = 40;
    pub const UMOUNT2: usize = 39;
    pub const PIVOT_ROOT: usize = 41;
    pub const CHDIR: usize = 49;
    pub const SETHOSTNAME: usize = 161;
    pub const GETUID: usize = 174;
    pub const GETGID: usize = 176;
    pub const PRCTL: usize = 167;
    pub const MKDIRAT: usize = 34;
    pub const KILL: usize = 129;
    pub const UNLINKAT: usize = 35;
    pub const CAPSET: usize = 91;
    pub const NANOSLEEP: usize = 101;
    pub const IOCTL: usize = 29;
    pub const SECCOMP: usize = 277;
    pub const SETRESUID: usize = 147;
    pub const SETRESGID: usize = 149;
    pub const SETGROUPS: usize = 159;
    pub const RT_SIGPROCMASK: usize = 135;
    pub const SIGNALFD4: usize = 74;
    pub const WAITID: usize = 95;
}

pub const CLONE_NEWNS: u64 = 0x0002_0000;
pub const CLONE_NEWCGROUP: u64 = 0x0200_0000;
pub const CLONE_NEWUTS: u64 = 0x0400_0000;
pub const CLONE_NEWIPC: u64 = 0x0800_0000;
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
pub const CLONE_NEWPID: u64 = 0x2000_0000;
pub const CLONE_NEWNET: u64 = 0x4000_0000;
pub const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

pub const SIGKILL: i32 = 9;
pub const SIGCHLD: i32 = 17;
pub const SIGINT: i32 = 2;
pub const SIGTERM: i32 = 15;
pub const CLONE_PIDFD: u64 = 0x1000;

pub const MS_RDONLY: usize = 1;
pub const MS_NOSUID: usize = 2;
pub const MS_NODEV: usize = 4;
pub const MS_NOEXEC: usize = 8;
pub const MS_REMOUNT: usize = 32;
pub const MS_BIND: usize = 4096;
pub const MS_REC: usize = 16384;
pub const MS_PRIVATE: usize = 1 << 18;
pub const MNT_DETACH: usize = 2;

pub const PR_SET_PDEATHSIG: usize = 1;
pub const PR_SET_NO_NEW_PRIVS: usize = 38;
pub const PR_CAPBSET_DROP: usize = 24;
pub const PR_CAP_AMBIENT: usize = 47;
pub const PR_CAP_AMBIENT_CLEAR_ALL: usize = 4;
pub const O_DIRECTORY: i32 = 0o200000;

pub const O_RDONLY: i32 = 0;
pub const O_WRONLY: i32 = 1;
pub const O_CREAT: i32 = 0o100;
pub const AT_FDCWD: i32 = -100;

/// `struct clone_args` (Linux 5.7+ layout, including `cgroup`).
#[repr(C)]
#[derive(Default)]
pub struct CloneArgs {
    pub flags: u64,
    pub pidfd: u64,
    pub child_tid: u64,
    pub parent_tid: u64,
    pub exit_signal: u64,
    pub stack: u64,
    pub stack_size: u64,
    pub tls: u64,
    pub set_tid: u64,
    pub set_tid_size: u64,
    pub cgroup: u64,
}

/// Rejects paths that are not NUL-terminated, so the kernel never reads past the slice.
fn c(p: &[u8]) -> Result<usize> {
    if p.last() == Some(&0) {
        Ok(p.as_ptr() as usize)
    } else {
        Err(Errno(22))
    }
}

/// Fork-like clone3 (no CLONE_VM, no new stack): returns 0 in the child, the child pid in the
/// parent.
///
/// # Safety
/// The child runs on a copy of the parent's memory. With the single-threaded runtime (ADR-005)
/// that copy is consistent; the caller must not rely on other threads' state in the child.
pub unsafe fn clone3(args: &mut CloneArgs) -> Result<i32> {
    args.stack = 0;
    args.stack_size = 0;
    // SAFETY: args points to a valid clone_args for the duration of the call; without a new stack
    // the child resumes here with duplicated memory, exactly like fork(2).
    check(unsafe { syscall2(n::CLONE3, args as *mut CloneArgs as usize, core::mem::size_of::<CloneArgs>()) })
        .map(|r| r as i32)
}

/// Blocks until `pid` exits; returns the raw wait status.
pub fn wait4(pid: i32) -> Result<i32> {
    let mut status: i32 = 0;
    loop {
        // SAFETY: status is a valid writable i32; rusage is NULL.
        match check(unsafe { syscall4(n::WAIT4, pid as usize, &mut status as *mut i32 as usize, 0, 0) }) {
            Err(Errno(4)) => continue, // EINTR
            r => return r.map(|_| status),
        }
    }
}

/// Converts a wait status to a shell-style exit code (128+signal when killed).
pub fn exit_code(status: i32) -> i32 {
    if status & 0x7f == 0 {
        (status >> 8) & 0xff
    } else {
        128 + (status & 0x7f)
    }
}

/// `argv` and `envp` must be NULL-terminated arrays of NUL-terminated strings.
pub fn execve(path: &[u8], argv: &[*const u8], envp: &[*const u8]) -> Errno {
    if argv.last() != Some(&core::ptr::null()) || envp.last() != Some(&core::ptr::null()) {
        return Errno(22);
    }
    let p = match c(path) {
        Ok(p) => p,
        Err(e) => return e,
    };
    // SAFETY: all three pointers reference NUL/NULL-terminated data owned by the caller; execve only
    // returns on failure.
    let r = unsafe { syscall3(n::EXECVE, p, argv.as_ptr() as usize, envp.as_ptr() as usize) };
    check(r).err().unwrap_or(Errno(0))
}

/// `mount(2)`. `source`, `fstype` and `data` may be None (NULL).
pub fn mount(source: Option<&[u8]>, target: &[u8], fstype: Option<&[u8]>, flags: usize, data: Option<&[u8]>) -> Result<()> {
    let opt = |o: Option<&[u8]>| o.map_or(Ok(0), c);
    let (s, t, f, d) = (opt(source)?, c(target)?, opt(fstype)?, opt(data)?);
    // SAFETY: every non-NULL pointer is a NUL-terminated string borrowed for the call.
    check(unsafe { syscall5(n::MOUNT, s, t, f, flags, d) }).map(|_| ())
}

pub fn umount2(target: &[u8], flags: usize) -> Result<()> {
    // SAFETY: target is NUL-terminated.
    check(unsafe { syscall2(n::UMOUNT2, c(target)?, flags) }).map(|_| ())
}

pub fn pivot_root(new_root: &[u8], put_old: &[u8]) -> Result<()> {
    // SAFETY: both paths are NUL-terminated.
    check(unsafe { syscall2(n::PIVOT_ROOT, c(new_root)?, c(put_old)?) }).map(|_| ())
}

pub fn chdir(path: &[u8]) -> Result<()> {
    // SAFETY: path is NUL-terminated.
    check(unsafe { syscall1(n::CHDIR, c(path)?) }).map(|_| ())
}

pub fn sethostname(name: &[u8]) -> Result<()> {
    // SAFETY: (ptr, len) describe a valid byte slice; no NUL is required.
    check(unsafe { syscall2(n::SETHOSTNAME, name.as_ptr() as usize, name.len()) }).map(|_| ())
}

pub fn getuid() -> u32 {
    // SAFETY: no arguments; cannot fail.
    unsafe { super::syscall0(n::GETUID) as u32 }
}

pub fn getgid() -> u32 {
    // SAFETY: no arguments; cannot fail.
    unsafe { super::syscall0(n::GETGID) as u32 }
}

pub fn prctl(option: usize, arg2: usize) -> Result<()> {
    // SAFETY: only integer options are used by callers (no pointer arguments).
    check(unsafe { syscall5(n::PRCTL, option, arg2, 0, 0, 0) }).map(|_| ())
}

pub fn kill(pid: i32, sig: i32) -> Result<()> {
    // SAFETY: integer arguments only.
    check(unsafe { syscall2(n::KILL, pid as usize, sig as usize) }).map(|_| ())
}

/// `mkdir(path, mode)`; EEXIST is reported to the caller.
pub fn mkdir(path: &[u8], mode: u32) -> Result<()> {
    // SAFETY: path is NUL-terminated.
    check(unsafe { syscall3(n::MKDIRAT, AT_FDCWD as usize, c(path)?, mode as usize) }).map(|_| ())
}

pub fn rmdir(path: &[u8]) -> Result<()> {
    // SAFETY: path is NUL-terminated; 0x200 = AT_REMOVEDIR.
    check(unsafe { syscall3(n::UNLINKAT, AT_FDCWD as usize, c(path)?, 0x200) }).map(|_| ())
}

/// `open(path, flags, mode)` relative to the cwd. Mount-setup helper only: no RESOLVE_* guards, so
/// never use it on paths that container-controlled content can influence (use `fs::openat2`).
pub fn open(path: &[u8], flags: i32, mode: u32) -> Result<Fd> {
    // SAFETY: path is NUL-terminated.
    check(unsafe {
        syscall4(nr::OPENAT, AT_FDCWD as usize, c(path)?, (flags | super::O_CLOEXEC) as usize, mode as usize)
    })
    .map(|fd| Fd(fd as i32))
}

/// Writes `data` to a (small, procfs/cgroupfs-style) file in one `write` call.
pub fn write_file(path: &[u8], data: &[u8]) -> Result<()> {
    let fd = open(path, O_WRONLY, 0)?;
    let n = super::write(fd.raw(), data)?;
    if n == data.len() {
        Ok(())
    } else {
        Err(Errno(5))
    }
}

/// Sets effective = permitted = `keep` and clears the inheritable set (capset v3, 64-bit masks).
pub fn capset(keep: u64) -> Result<()> {
    let header: [u32; 2] = [0x2008_0522, 0]; // _LINUX_CAPABILITY_VERSION_3, current thread
    let (lo, hi) = (keep as u32, (keep >> 32) as u32);
    let data: [u32; 6] = [lo, lo, 0, hi, hi, 0]; // {effective, permitted, inheritable} x 2
    // SAFETY: header and data are valid repr-compatible arrays matching the v3 ABI.
    check(unsafe { syscall2(n::CAPSET, header.as_ptr() as usize, data.as_ptr() as usize) }).map(|_| ())
}

/// One classic-BPF instruction (`struct sock_filter`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

/// Installs a seccomp filter for the calling thread (SECCOMP_SET_MODE_FILTER). Requires
/// NO_NEW_PRIVS or CAP_SYS_ADMIN.
pub fn seccomp_set_filter(prog: &[SockFilter]) -> Result<()> {
    if prog.is_empty() || prog.len() > u16::MAX as usize {
        return Err(Errno(22));
    }
    let fprog = SockFprog { len: prog.len() as u16, filter: prog.as_ptr() };
    // SAFETY: fprog points at `prog`, which outlives the call; the kernel copies the program.
    check(unsafe { syscall3(n::SECCOMP, 1, 0, &fprog as *const SockFprog as usize) }).map(|_| ())
}

/// Blocking sleep (for short retry loops outside the executor).
pub fn nanosleep(ts: &super::Timespec) -> Result<()> {
    // SAFETY: ts is a valid timespec; the remaining-time pointer is NULL.
    check(unsafe { syscall2(n::NANOSLEEP, ts as *const super::Timespec as usize, 0) }).map(|_| ())
}

const SIOCGIFFLAGS: usize = 0x8913;
const SIOCSIFFLAGS: usize = 0x8914;
const IFF_UP: u16 = 0x1;

/// Brings an interface up (SIOCGIFFLAGS/SIOCSIFFLAGS). Needs CAP_NET_ADMIN in the netns owner.
pub fn link_up(name: &[u8]) -> Result<()> {
    if name.is_empty() || name.len() >= 16 {
        return Err(Errno(22));
    }
    // struct ifreq: char ifr_name[16]; union { short ifr_flags; ... } (40 bytes total).
    let mut ifr = [0u8; 40];
    ifr[..name.len()].copy_from_slice(name);
    let sock = super::socket(super::AF_INET, 2 | super::O_CLOEXEC, 0)?; // SOCK_DGRAM
    // SAFETY: ifr is a writable 40-byte ifreq for both ioctls.
    check(unsafe { syscall3(n::IOCTL, sock.raw() as usize, SIOCGIFFLAGS, ifr.as_mut_ptr() as usize) })?;
    let flags = u16::from_ne_bytes([ifr[16], ifr[17]]) | IFF_UP;
    ifr[16..18].copy_from_slice(&flags.to_ne_bytes());
    // SAFETY: as above.
    check(unsafe { syscall3(n::IOCTL, sock.raw() as usize, SIOCSIFFLAGS, ifr.as_mut_ptr() as usize) }).map(|_| ())
}

/// Sets real, effective and saved gid. Call before `setresuid`.
pub fn setresgid(gid: u32) -> Result<()> {
    // SAFETY: plain integer arguments.
    check(unsafe { syscall3(n::SETRESGID, gid as usize, gid as usize, gid as usize) }).map(|_| ())
}

pub fn setresuid(uid: u32) -> Result<()> {
    // SAFETY: plain integer arguments.
    check(unsafe { syscall3(n::SETRESUID, uid as usize, uid as usize, uid as usize) }).map(|_| ())
}

/// Replaces the supplementary group list.
pub fn setgroups(groups: &[u32]) -> Result<()> {
    // SAFETY: groups is a valid array of gid_t for the given length.
    check(unsafe { syscall2(n::SETGROUPS, groups.len(), groups.as_ptr() as usize) }).map(|_| ())
}

fn sigmask(sigs: &[i32]) -> u64 {
    sigs.iter().fold(0u64, |m, &s| m | 1 << (s - 1))
}

/// Blocks (`block`) or unblocks the given signals for the calling thread.
pub fn sigprocmask(block: bool, sigs: &[i32]) -> Result<()> {
    let set = sigmask(sigs);
    let how = if block { 0 } else { 1 }; // SIG_BLOCK / SIG_UNBLOCK
    // SAFETY: set is a valid 8-byte sigset; old set pointer is NULL.
    check(unsafe { syscall4(n::RT_SIGPROCMASK, how, &set as *const u64 as usize, 0, 8) }).map(|_| ())
}

/// Unblocks every signal (the mask survives fork and execve, so a child must reset it).
pub fn sigmask_reset() -> Result<()> {
    let set = 0u64;
    // SAFETY: set is a valid 8-byte sigset. how = SIG_SETMASK.
    check(unsafe { syscall4(n::RT_SIGPROCMASK, 2, &set as *const u64 as usize, 0, 8) }).map(|_| ())
}

/// A non-blocking, close-on-exec signalfd for `sigs` (which must be blocked first).
pub fn signalfd(sigs: &[i32]) -> Result<Fd> {
    let set = sigmask(sigs);
    // SAFETY: set is a valid 8-byte sigset. Flags: SFD_NONBLOCK | SFD_CLOEXEC.
    check(unsafe { syscall4(n::SIGNALFD4, usize::MAX, &set as *const u64 as usize, 8, 0o4000 | super::O_CLOEXEC as usize) })
        .map(|fd| Fd(fd as i32))
}

/// Reads one pending signal number from a signalfd (`struct signalfd_siginfo` is 128 bytes).
pub fn signalfd_read(fd: &Fd) -> Result<i32> {
    let mut info = [0u8; 128];
    let n = super::read(fd.raw(), &mut info)?;
    if n < 4 {
        return Err(Errno(5));
    }
    Ok(u32::from_ne_bytes([info[0], info[1], info[2], info[3]]) as i32)
}

/// Sends `sig` through a pidfd, which cannot hit a recycled pid.
pub fn pidfd_send_signal(pidfd: &Fd, sig: i32) -> Result<()> {
    // SAFETY: plain integer arguments; info is NULL.
    check(unsafe { syscall4(424, pidfd.raw() as usize, sig as usize, 0, 0) }).map(|_| ())
}

/// Non-blocking reap of the process behind `pidfd`: Ok(None) while it is still running,
/// otherwise its shell-style exit code.
pub fn pidfd_try_wait(pidfd: &Fd) -> Result<Option<i32>> {
    // siginfo_t is 128 bytes: si_signo, si_errno, si_code (i32 each), pad, si_pid, si_uid, si_status.
    let mut info = [0u8; 128];
    const P_PIDFD: usize = 3;
    const WEXITED: usize = 4;
    const WNOHANG: usize = 1;
    // SAFETY: info is a writable siginfo_t-sized buffer; rusage is NULL.
    check(unsafe {
        syscall5(n::WAITID, P_PIDFD, pidfd.raw() as usize, info.as_mut_ptr() as usize, WEXITED | WNOHANG, 0)
    })?;
    let rd = |o: usize| i32::from_ne_bytes([info[o], info[o + 1], info[o + 2], info[o + 3]]);
    if rd(16) == 0 {
        return Ok(None); // si_pid == 0: still running
    }
    let (code, status) = (rd(8), rd(24));
    Ok(Some(match code {
        1 => status & 0xff,  // CLD_EXITED
        _ => 128 + status,   // CLD_KILLED / CLD_DUMPED
    }))
}

/// Interface index by name (SIOCGIFINDEX), in the caller's network namespace.
pub fn ifindex(name: &[u8]) -> Result<i32> {
    if name.is_empty() || name.len() >= 16 {
        return Err(Errno(22));
    }
    let mut ifr = [0u8; 40];
    ifr[..name.len()].copy_from_slice(name);
    let sock = super::socket(super::AF_INET, 2 | super::O_CLOEXEC, 0)?; // SOCK_DGRAM
    // SAFETY: ifr is a writable 40-byte ifreq; the kernel stores ifr_ifindex at offset 16.
    check(unsafe { syscall3(n::IOCTL, sock.raw() as usize, 0x8933, ifr.as_mut_ptr() as usize) })?;
    Ok(i32::from_ne_bytes([ifr[16], ifr[17], ifr[18], ifr[19]]))
}
