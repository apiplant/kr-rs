//! Raw Linux syscalls and thin typed wrappers. No libc.
#![no_std]

use core::arch::asm;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Errno(pub i32);

pub type Result<T> = core::result::Result<T, Errno>;

pub const EAGAIN: i32 = 11;
pub const EINTR: i32 = 4;

pub const EINPROGRESS: i32 = 115;
pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 10;
pub const SO_ERROR: i32 = 4;
pub const AT_FDCWD: i32 = -100;
pub const O_RDONLY: i32 = 0;
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_NONBLOCK: i32 = 0o4000;
pub const SOCK_CLOEXEC: i32 = 0o2000000;
pub const SOL_SOCKET: i32 = 1;
pub const SO_REUSEADDR: i32 = 2;

pub const EPOLLIN: u32 = 0x1;
pub const EPOLLOUT: u32 = 0x4;
pub const EPOLLERR: u32 = 0x8;
pub const EPOLLHUP: u32 = 0x10;
pub const EPOLLRDHUP: u32 = 0x2000;
pub const EPOLLET: u32 = 1 << 31;
pub const EPIPE: i32 = 32;
pub const CLOCK_MONOTONIC: i32 = 1;
pub const EPOLL_CTL_ADD: i32 = 1;
pub const EPOLL_CTL_DEL: i32 = 2;
pub const EPOLL_CLOEXEC: i32 = 0o2000000;

pub const PROT_NONE: usize = 0;
pub const PROT_READ: usize = 1;
pub const PROT_WRITE: usize = 2;
pub const PROT_EXEC: usize = 4;
pub const MAP_PRIVATE: usize = 0x02;
pub const MAP_ANONYMOUS: usize = 0x20;
pub const SHUT_WR: i32 = 1;
pub const O_NONBLOCK: i32 = 0o4000;
pub const O_CLOEXEC: i32 = 0o2000000;

#[cfg(target_arch = "x86_64")]
mod nr {
    pub const READ: usize = 0;
    pub const WRITE: usize = 1;
    pub const CLOSE: usize = 3;
    pub const MMAP: usize = 9;
    pub const MUNMAP: usize = 11;
    pub const SOCKET: usize = 41;
    pub const CONNECT: usize = 42;
    pub const GETSOCKOPT: usize = 55;
    pub const OPENAT: usize = 257;
    pub const BIND: usize = 49;
    pub const SHUTDOWN: usize = 48;
    pub const PIPE2: usize = 293;
    pub const LISTEN: usize = 50;
    pub const SETSOCKOPT: usize = 54;
    pub const EXIT_GROUP: usize = 231;
    pub const CLOCK_GETTIME: usize = 228;
    pub const EPOLL_CTL: usize = 233;
    pub const ACCEPT4: usize = 288;
    pub const EPOLL_CREATE1: usize = 291;
    pub const EPOLL_WAIT: usize = 232;
}

#[cfg(target_arch = "aarch64")]
mod nr {
    pub const READ: usize = 63;
    pub const WRITE: usize = 64;
    pub const CLOSE: usize = 57;
    pub const MMAP: usize = 222;
    pub const MUNMAP: usize = 215;
    pub const SOCKET: usize = 198;
    pub const CONNECT: usize = 203;
    pub const GETSOCKOPT: usize = 209;
    pub const OPENAT: usize = 56;
    pub const BIND: usize = 200;
    pub const SHUTDOWN: usize = 210;
    pub const PIPE2: usize = 59;
    pub const LISTEN: usize = 201;
    pub const SETSOCKOPT: usize = 208;
    pub const EXIT_GROUP: usize = 94;
    pub const CLOCK_GETTIME: usize = 113;
    pub const EPOLL_CTL: usize = 21;
    pub const ACCEPT4: usize = 242;
    pub const EPOLL_CREATE1: usize = 20;
    pub const EPOLL_PWAIT: usize = 22;
}

// ---- raw syscalls ----

#[cfg(target_arch = "x86_64")]
mod raw {
    use super::asm;
    // SAFETY (all): the caller guarantees the syscall number and arguments are valid for the
    // kernel ABI; rcx and r11 are clobbered by `syscall` and declared as such.
    #[inline(always)]
    pub unsafe fn syscall0(n: usize) -> isize {
        let r;
        asm!("syscall", inlateout("rax") n => r, out("rcx") _, out("r11") _, options(nostack));
        r
    }
    #[inline(always)]
    pub unsafe fn syscall1(n: usize, a: usize) -> isize {
        let r;
        asm!("syscall", inlateout("rax") n => r, in("rdi") a, out("rcx") _, out("r11") _, options(nostack));
        r
    }
    #[inline(always)]
    pub unsafe fn syscall2(n: usize, a: usize, b: usize) -> isize {
        let r;
        asm!("syscall", inlateout("rax") n => r, in("rdi") a, in("rsi") b, out("rcx") _, out("r11") _, options(nostack));
        r
    }
    #[inline(always)]
    pub unsafe fn syscall3(n: usize, a: usize, b: usize, c: usize) -> isize {
        let r;
        asm!("syscall", inlateout("rax") n => r, in("rdi") a, in("rsi") b, in("rdx") c, out("rcx") _, out("r11") _, options(nostack));
        r
    }
    #[inline(always)]
    pub unsafe fn syscall4(n: usize, a: usize, b: usize, c: usize, d: usize) -> isize {
        let r;
        asm!("syscall", inlateout("rax") n => r, in("rdi") a, in("rsi") b, in("rdx") c, in("r10") d, out("rcx") _, out("r11") _, options(nostack));
        r
    }
    #[inline(always)]
    pub unsafe fn syscall5(n: usize, a: usize, b: usize, c: usize, d: usize, e: usize) -> isize {
        let r;
        asm!("syscall", inlateout("rax") n => r, in("rdi") a, in("rsi") b, in("rdx") c, in("r10") d, in("r8") e, out("rcx") _, out("r11") _, options(nostack));
        r
    }
    #[inline(always)]
    pub unsafe fn syscall6(n: usize, a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> isize {
        let r;
        asm!("syscall", inlateout("rax") n => r, in("rdi") a, in("rsi") b, in("rdx") c, in("r10") d, in("r8") e, in("r9") f, out("rcx") _, out("r11") _, options(nostack));
        r
    }
}

#[cfg(target_arch = "aarch64")]
mod raw {
    use super::asm;
    // SAFETY (all): caller guarantees valid syscall number/arguments; `svc 0` follows the
    // aarch64 Linux ABI (x8 = number, x0..x5 = args, x0 = result).
    #[inline(always)]
    pub unsafe fn syscall0(n: usize) -> isize {
        let r;
        asm!("svc 0", in("x8") n, lateout("x0") r, options(nostack));
        r
    }
    #[inline(always)]
    pub unsafe fn syscall1(n: usize, a: usize) -> isize {
        let r;
        asm!("svc 0", in("x8") n, inlateout("x0") a => r, options(nostack));
        r
    }
    #[inline(always)]
    pub unsafe fn syscall2(n: usize, a: usize, b: usize) -> isize {
        let r;
        asm!("svc 0", in("x8") n, inlateout("x0") a => r, in("x1") b, options(nostack));
        r
    }
    #[inline(always)]
    pub unsafe fn syscall3(n: usize, a: usize, b: usize, c: usize) -> isize {
        let r;
        asm!("svc 0", in("x8") n, inlateout("x0") a => r, in("x1") b, in("x2") c, options(nostack));
        r
    }
    #[inline(always)]
    pub unsafe fn syscall4(n: usize, a: usize, b: usize, c: usize, d: usize) -> isize {
        let r;
        asm!("svc 0", in("x8") n, inlateout("x0") a => r, in("x1") b, in("x2") c, in("x3") d, options(nostack));
        r
    }
    #[inline(always)]
    pub unsafe fn syscall5(n: usize, a: usize, b: usize, c: usize, d: usize, e: usize) -> isize {
        let r;
        asm!("svc 0", in("x8") n, inlateout("x0") a => r, in("x1") b, in("x2") c, in("x3") d, in("x4") e, options(nostack));
        r
    }
    #[inline(always)]
    pub unsafe fn syscall6(n: usize, a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> isize {
        let r;
        asm!("svc 0", in("x8") n, inlateout("x0") a => r, in("x1") b, in("x2") c, in("x3") d, in("x4") e, in("x5") f, options(nostack));
        r
    }
}

pub use raw::{syscall0, syscall1, syscall2, syscall3, syscall4, syscall5, syscall6};

#[inline(always)]
fn check(r: isize) -> Result<usize> {
    if (-4095..0).contains(&r) {
        Err(Errno(-r as i32))
    } else {
        Ok(r as usize)
    }
}

// ---- structs ----

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockaddrIn {
    pub sin_family: u16,
    /// Network byte order.
    pub sin_port: u16,
    /// Network byte order.
    pub sin_addr: u32,
    pub sin_zero: [u8; 8],
}

impl SockaddrIn {
    pub fn new(addr: [u8; 4], port: u16) -> Self {
        SockaddrIn {
            sin_family: AF_INET as u16,
            sin_port: port.to_be(),
            sin_addr: u32::from_ne_bytes(addr),
            sin_zero: [0; 8],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockaddrIn6 {
    pub sin6_family: u16,
    /// Network byte order.
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: [u8; 16],
    pub sin6_scope_id: u32,
}

impl SockaddrIn6 {
    pub fn new(addr: [u8; 16], port: u16) -> Self {
        SockaddrIn6 { sin6_family: AF_INET6 as u16, sin6_port: port.to_be(), sin6_flowinfo: 0, sin6_addr: addr, sin6_scope_id: 0 }
    }
}

#[cfg(target_arch = "x86_64")]
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct EpollEvent {
    pub events: u32,
    pub data: u64,
}

#[cfg(not(target_arch = "x86_64"))]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EpollEvent {
    pub events: u32,
    pub data: u64,
}

impl EpollEvent {
    pub const fn zeroed() -> Self {
        EpollEvent { events: 0, data: 0 }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

// ---- typed wrappers ----

pub fn read(fd: i32, buf: &mut [u8]) -> Result<usize> {
    // SAFETY: buf is a valid writable region of buf.len() bytes.
    check(unsafe { syscall3(nr::READ, fd as usize, buf.as_mut_ptr() as usize, buf.len()) })
}

pub fn write(fd: i32, buf: &[u8]) -> Result<usize> {
    // SAFETY: buf is a valid readable region of buf.len() bytes.
    check(unsafe { syscall3(nr::WRITE, fd as usize, buf.as_ptr() as usize, buf.len()) })
}

pub fn close(fd: i32) -> Result<()> {
    // SAFETY: close takes only an integer; at worst it fails with EBADF.
    check(unsafe { syscall1(nr::CLOSE, fd as usize) }).map(|_| ())
}

pub fn exit_group(code: i32) -> ! {
    // SAFETY: exit_group never returns and takes only an integer.
    unsafe {
        syscall1(nr::EXIT_GROUP, code as usize);
        loop {
            core::hint::spin_loop();
        }
    }
}

/// # Safety
/// Same contract as mmap(2): the caller must uphold aliasing and lifetime rules for the
/// returned mapping, and `addr` with MAP_FIXED must not clobber live memory.
pub unsafe fn mmap(addr: usize, len: usize, prot: usize, flags: usize, fd: i32, off: usize) -> Result<usize> {
    // SAFETY: forwarded to the caller's contract.
    check(unsafe { syscall6(nr::MMAP, addr, len, prot, flags, fd as usize, off) })
}

/// # Safety
/// `addr..addr+len` must be a mapping owned by the caller and no longer referenced.
pub unsafe fn munmap(addr: usize, len: usize) -> Result<()> {
    // SAFETY: forwarded to the caller's contract.
    check(unsafe { syscall2(nr::MUNMAP, addr, len) }).map(|_| ())
}

pub fn socket(domain: i32, ty: i32, proto: i32) -> Result<Fd> {
    // SAFETY: integer-only arguments.
    check(unsafe { syscall3(nr::SOCKET, domain as usize, ty as usize, proto as usize) }).map(|r| Fd(r as i32))
}

pub fn setsockopt(fd: i32, level: i32, name: i32, val: &[u8]) -> Result<()> {
    // SAFETY: val is a valid readable region of val.len() bytes.
    check(unsafe {
        syscall5(nr::SETSOCKOPT, fd as usize, level as usize, name as usize, val.as_ptr() as usize, val.len())
    })
    .map(|_| ())
}

pub fn bind(fd: i32, addr: &SockaddrIn) -> Result<()> {
    // SAFETY: addr points to a valid repr(C) sockaddr_in of the stated size.
    check(unsafe {
        syscall3(nr::BIND, fd as usize, addr as *const _ as usize, core::mem::size_of::<SockaddrIn>())
    })
    .map(|_| ())
}

/// Non-blocking sockets return `Err(Errno(EINPROGRESS))` while the handshake is pending.
pub fn connect(fd: i32, addr: &SockaddrIn) -> Result<()> {
    // SAFETY: addr points to a valid repr(C) sockaddr_in of the stated size.
    check(unsafe {
        syscall3(nr::CONNECT, fd as usize, addr as *const _ as usize, core::mem::size_of::<SockaddrIn>())
    })
    .map(|_| ())
}

pub fn connect6(fd: i32, addr: &SockaddrIn6) -> Result<()> {
    // SAFETY: addr points to a valid repr(C) sockaddr_in6 of the stated size.
    check(unsafe {
        syscall3(nr::CONNECT, fd as usize, addr as *const _ as usize, core::mem::size_of::<SockaddrIn6>())
    })
    .map(|_| ())
}

/// Reads and clears the pending socket error (`SO_ERROR`); `Ok(0)` means none.
pub fn socket_error(fd: i32) -> Result<i32> {
    let mut val: i32 = 0;
    let mut len: u32 = 4;
    // SAFETY: val/len are valid writable locals of the sizes the kernel expects.
    check(unsafe {
        syscall5(
            nr::GETSOCKOPT,
            fd as usize,
            SOL_SOCKET as usize,
            SO_ERROR as usize,
            &mut val as *mut i32 as usize,
            &mut len as *mut u32 as usize,
        )
    })?;
    Ok(val)
}

/// Opens a file read-only. `path` must be NUL-terminated (checked).
pub fn open_read(path: &[u8]) -> Result<Fd> {
    if path.last() != Some(&0) {
        return Err(Errno(22)); // EINVAL
    }
    // SAFETY: path is a valid NUL-terminated byte string for the duration of the call.
    check(unsafe {
        syscall4(nr::OPENAT, AT_FDCWD as usize, path.as_ptr() as usize, (O_RDONLY | O_CLOEXEC) as usize, 0)
    })
    .map(|r| Fd(r as i32))
}

/// `how` is `SHUT_WR` (or 0 = SHUT_RD, 2 = SHUT_RDWR).
pub fn shutdown(fd: i32, how: i32) -> Result<()> {
    // SAFETY: integer-only arguments.
    check(unsafe { syscall2(nr::SHUTDOWN, fd as usize, how as usize) }).map(|_| ())
}

/// Returns `(read_end, write_end)`.
pub fn pipe2(flags: i32) -> Result<(Fd, Fd)> {
    let mut fds = [0i32; 2];
    // SAFETY: fds is a valid writable array of two c_ints.
    check(unsafe { syscall2(nr::PIPE2, fds.as_mut_ptr() as usize, flags as usize) })?;
    Ok((Fd(fds[0]), Fd(fds[1])))
}

pub fn listen(fd: i32, backlog: i32) -> Result<()> {
    // SAFETY: integer-only arguments.
    check(unsafe { syscall2(nr::LISTEN, fd as usize, backlog as usize) }).map(|_| ())
}

/// Accepts without retrieving the peer address.
pub fn accept4(fd: i32, flags: i32) -> Result<Fd> {
    // SAFETY: null addr/addrlen are explicitly permitted by accept4(2).
    check(unsafe { syscall4(nr::ACCEPT4, fd as usize, 0, 0, flags as usize) }).map(|r| Fd(r as i32))
}

pub fn epoll_create1(flags: i32) -> Result<Fd> {
    // SAFETY: integer-only arguments.
    check(unsafe { syscall1(nr::EPOLL_CREATE1, flags as usize) }).map(|r| Fd(r as i32))
}

pub fn epoll_ctl(epfd: i32, op: i32, fd: i32, ev: Option<&mut EpollEvent>) -> Result<()> {
    let p = match ev {
        Some(e) => e as *mut EpollEvent as usize,
        None => 0,
    };
    // SAFETY: p is null or points to a valid EpollEvent (null is allowed for EPOLL_CTL_DEL).
    check(unsafe { syscall4(nr::EPOLL_CTL, epfd as usize, op as usize, fd as usize, p) }).map(|_| ())
}

pub fn epoll_wait(epfd: i32, events: &mut [EpollEvent], timeout_ms: i32) -> Result<usize> {
    let p = events.as_mut_ptr() as usize;
    let n = events.len();
    #[cfg(target_arch = "x86_64")]
    // SAFETY: events is a valid writable array of n entries.
    let r = unsafe { syscall4(nr::EPOLL_WAIT, epfd as usize, p, n, timeout_ms as usize) };
    #[cfg(target_arch = "aarch64")]
    // SAFETY: as above; a null sigmask is permitted by epoll_pwait(2).
    let r = unsafe { syscall6(nr::EPOLL_PWAIT, epfd as usize, p, n, timeout_ms as usize, 0, 8) };
    check(r)
}

pub fn clock_gettime(clock: i32) -> Result<Timespec> {
    let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: ts is a valid writable repr(C) timespec (two i64) for the duration of the call.
    check(unsafe { syscall2(nr::CLOCK_GETTIME, clock as usize, &mut ts as *mut Timespec as usize) })?;
    Ok(ts)
}

/// Owned file descriptor, closed on drop.
pub struct Fd(pub i32);

impl Fd {
    pub fn raw(&self) -> i32 {
        self.0
    }
    /// Releases ownership without closing.
    pub fn into_raw(self) -> i32 {
        let fd = self.0;
        core::mem::forget(self);
        fd
    }
}

impl Drop for Fd {
    fn drop(&mut self) {
        let _ = close(self.0);
    }
}
