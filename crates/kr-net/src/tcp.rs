//! Async TCP connect and minimal name resolution (literals + `/etc/hosts`; no DNS).

use crate::{Error, Result};
use alloc::string::String;
use alloc::vec::Vec;
use kr_rt::exec::{now_ms, timeout, Async};
use kr_sys::{self as sys, Errno, Fd};

// ---------- addresses ----------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketAddr {
    pub ip: IpAddr,
    pub port: u16,
}

impl IpAddr {
    /// Parses an IPv4 or IPv6 literal (no brackets, no zone id).
    pub fn parse(s: &str) -> Option<IpAddr> {
        if s.contains(':') {
            parse_ipv6(s).map(IpAddr::V6)
        } else {
            parse_ipv4(s).map(IpAddr::V4)
        }
    }

    pub fn is_loopback(&self) -> bool {
        match self {
            IpAddr::V4(a) => a[0] == 127,
            IpAddr::V6(a) => a[..15].iter().all(|b| *b == 0) && a[15] == 1,
        }
    }
}

/// RFC 5952 text: lowercase hex groups, the longest run of two or more zero groups as `::`.
pub fn ipv6_string(a: [u8; 16]) -> String {
    let g: [u16; 8] = core::array::from_fn(|i| u16::from_be_bytes([a[2 * i], a[2 * i + 1]]));
    let (mut best, mut best_len, mut i) = (0usize, 0usize, 0usize);
    while i < 8 {
        if g[i] == 0 {
            let start = i;
            while i < 8 && g[i] == 0 {
                i += 1;
            }
            if i - start > best_len && i - start > 1 {
                best = start;
                best_len = i - start;
            }
        } else {
            i += 1;
        }
    }
    let mut out = String::new();
    let mut i = 0;
    while i < 8 {
        if best_len > 0 && i == best {
            out.push_str("::");
            i += best_len;
            continue;
        }
        if !out.is_empty() && !out.ends_with(':') {
            out.push(':');
        }
        out.push_str(&alloc::format!("{:x}", g[i]));
        i += 1;
    }
    out
}

/// Strict dotted quad: four decimal parts of 1-3 digits, no leading zeros, each <= 255.
pub fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut n = 0;
    for part in s.split('.') {
        if n == 4 || part.is_empty() || part.len() > 3 || (part.len() > 1 && part.starts_with('0')) {
            return None;
        }
        if !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        out[n] = part.parse::<u16>().ok().filter(|v| *v <= 255)? as u8;
        n += 1;
    }
    (n == 4).then_some(out)
}

/// RFC 4291 text form, including `::` compression and an embedded IPv4 tail.
pub fn parse_ipv6(s: &str) -> Option<[u8; 16]> {
    let (head, tail) = match s.find("::") {
        Some(i) => {
            if s[i + 2..].contains("::") {
                return None;
            }
            (&s[..i], Some(&s[i + 2..]))
        }
        None => (s, None),
    };
    fn groups(part: &str, out: &mut Vec<u16>, allow_v4_tail: bool) -> Option<()> {
        if part.is_empty() {
            return Some(());
        }
        let items: Vec<&str> = part.split(':').collect();
        for (i, g) in items.iter().enumerate() {
            if allow_v4_tail && i == items.len() - 1 && g.contains('.') {
                let v4 = parse_ipv4(g)?;
                out.push(u16::from_be_bytes([v4[0], v4[1]]));
                out.push(u16::from_be_bytes([v4[2], v4[3]]));
            } else {
                if g.is_empty() || g.len() > 4 || !g.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return None;
                }
                out.push(u16::from_str_radix(g, 16).ok()?);
            }
        }
        Some(())
    }
    let mut h = Vec::new();
    let mut t = Vec::new();
    match tail {
        None => {
            groups(head, &mut h, true)?;
            if h.len() != 8 {
                return None;
            }
        }
        Some(tl) => {
            groups(head, &mut h, false)?;
            groups(tl, &mut t, true)?;
            if h.len() + t.len() > 7 {
                return None; // "::" must stand for at least one group
            }
        }
    }
    let mut all = [0u16; 8];
    all[..h.len()].copy_from_slice(&h);
    let start = 8 - t.len();
    all[start..].copy_from_slice(&t);
    let mut out = [0u8; 16];
    for (i, g) in all.iter().enumerate() {
        out[i * 2..i * 2 + 2].copy_from_slice(&g.to_be_bytes());
    }
    Some(out)
}

// ---------- resolution ----------

/// Name resolution hook. Only [`HostsResolver`] exists today; a real DNS resolver (UDP, then
/// TCP fallback) can implement this trait later without touching callers.
#[allow(async_fn_in_trait)]
pub trait Resolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>>;
}

/// Literals plus `/etc/hosts` (and a built-in `localhost`). No DNS.
#[derive(Clone, Debug, Default)]
pub struct HostsResolver {
    hosts: String,
}

impl HostsResolver {
    /// Loads `/etc/hosts`; a missing or unreadable file yields an empty table.
    pub fn system() -> Self {
        Self::from_file(b"/etc/hosts\0")
    }

    /// `path` must be NUL-terminated.
    pub fn from_file(path: &[u8]) -> Self {
        let mut data = Vec::new();
        if let Ok(fd) = sys::open_read(path) {
            let mut buf = [0u8; 4096];
            while let Ok(n) = sys::read(fd.raw(), &mut buf) {
                if n == 0 || data.len() > 1 << 20 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
            }
        }
        HostsResolver { hosts: String::from_utf8_lossy(&data).into_owned() }
    }

    pub fn from_contents(contents: &str) -> Self {
        HostsResolver { hosts: contents.into() }
    }

    /// Synchronous lookup: literal, then hosts file, then built-in `localhost`.
    pub fn lookup(&self, host: &str) -> Vec<IpAddr> {
        let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
        if let Some(ip) = IpAddr::parse(host) {
            return alloc::vec![ip];
        }
        let mut out = Vec::new();
        for line in self.hosts.lines() {
            let line = line.split('#').next().unwrap_or("");
            let mut f = line.split_ascii_whitespace();
            let Some(addr) = f.next() else { continue };
            if f.any(|n| n.eq_ignore_ascii_case(host)) {
                if let Some(ip) = IpAddr::parse(addr) {
                    out.push(ip);
                }
            }
        }
        if out.is_empty() && host.eq_ignore_ascii_case("localhost") {
            out.push(IpAddr::V4([127, 0, 0, 1]));
            out.push(IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
        }
        out
    }
}

impl Resolver for HostsResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        let v = self.lookup(host);
        if v.is_empty() {
            Err(Error::Resolve)
        } else {
            Ok(v)
        }
    }
}

// ---------- connect ----------

/// A connected, non-blocking, reactor-registered TCP socket.
pub type TcpStream = Async<Fd>;

/// Non-blocking connect to one address, bounded by `timeout_ms`.
pub async fn connect_addr(addr: SocketAddr, timeout_ms: u64) -> Result<TcpStream> {
    let flags = sys::SOCK_STREAM | sys::SOCK_NONBLOCK | sys::SOCK_CLOEXEC;
    let (fd, r) = match addr.ip {
        IpAddr::V4(a) => {
            let fd = sys::socket(sys::AF_INET, flags, 0)?;
            let r = sys::connect(fd.raw(), &sys::SockaddrIn::new(a, addr.port));
            (fd, r)
        }
        IpAddr::V6(a) => {
            let fd = sys::socket(sys::AF_INET6, flags, 0)?;
            let r = sys::connect6(fd.raw(), &sys::SockaddrIn6::new(a, addr.port));
            (fd, r)
        }
    };
    match r {
        Ok(()) => return Ok(Async::new(fd)?),
        // EINTR: Linux continues the handshake asynchronously, like EINPROGRESS.
        Err(Errno(sys::EINPROGRESS)) | Err(Errno(sys::EINTR)) => {}
        Err(e) => return Err(Error::Io(e)),
    }
    let stream = Async::new(fd)?;
    timeout(timeout_ms, stream.wait_writable()).await.map_err(|_| Error::Timeout)?;
    match sys::socket_error(stream.get_ref().raw())? {
        0 => Ok(stream),
        e => Err(Error::Io(Errno(e))),
    }
}

/// Resolves `host` and tries each address in turn within a single overall `timeout_ms` budget.
pub async fn connect<R: Resolver>(r: &R, host: &str, port: u16, timeout_ms: u64) -> Result<TcpStream> {
    let ips = r.resolve(host).await?;
    let start = now_ms();
    let mut last = Error::Resolve;
    for ip in ips {
        let left = timeout_ms.saturating_sub(now_ms().saturating_sub(start));
        if left == 0 {
            return Err(Error::Timeout);
        }
        match connect_addr(SocketAddr { ip, port }, left).await {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4() {
        assert_eq!(parse_ipv4("127.0.0.1"), Some([127, 0, 0, 1]));
        assert_eq!(parse_ipv4("255.255.255.255"), Some([255; 4]));
        for bad in ["", "1.2.3", "1.2.3.4.5", "256.0.0.1", "01.2.3.4", "1.2.3.", "a.b.c.d", "1..2.3", "+1.2.3.4", " 1.2.3.4"] {
            assert_eq!(parse_ipv4(bad), None, "{bad}");
        }
    }

    #[test]
    fn ipv6() {
        let lo = parse_ipv6("::1").unwrap();
        assert_eq!(lo[15], 1);
        assert!(lo[..15].iter().all(|b| *b == 0));
        assert_eq!(parse_ipv6("::").unwrap(), [0; 16]);
        let a = parse_ipv6("2001:db8::ff00:42:8329").unwrap();
        assert_eq!(&a[..4], &[0x20, 0x01, 0x0d, 0xb8]);
        assert_eq!(&a[12..], &[0x00, 0x42, 0x83, 0x29]);
        assert_eq!(parse_ipv6("1:2:3:4:5:6:7:8").unwrap()[15], 8);
        let m = parse_ipv6("::ffff:1.2.3.4").unwrap();
        assert_eq!(&m[10..], &[0xff, 0xff, 1, 2, 3, 4]);
        for bad in ["", ":", ":::", "1::2::3", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "12345::", "g::1", "1:2:3:4:5:6:7::8", "::1.2.3", "1.2.3.4"] {
            assert_eq!(parse_ipv6(bad), None, "{bad}");
        }
    }

    #[test]
    fn hosts_lookup() {
        let r = HostsResolver::from_contents("# c\n127.0.0.1 localhost lo\n10.0.0.5 registry.local reg # tail\n::1 ip6-localhost\nbad line\n");
        assert_eq!(r.lookup("registry.local"), alloc::vec![IpAddr::V4([10, 0, 0, 5])]);
        assert_eq!(r.lookup("REG"), alloc::vec![IpAddr::V4([10, 0, 0, 5])]);
        assert_eq!(r.lookup("[::1]").len(), 1);
        assert_eq!(r.lookup("1.2.3.4"), alloc::vec![IpAddr::V4([1, 2, 3, 4])]);
        assert!(r.lookup("nope").is_empty());
        assert!(!HostsResolver::default().lookup("localhost").is_empty());
        assert!(IpAddr::V4([127, 1, 2, 3]).is_loopback());
        assert!(IpAddr::parse("::1").unwrap().is_loopback());
    }
}

// ---------- SIGPIPE-free writes ----------

#[cfg(target_arch = "x86_64")]
const SYS_SENDTO: usize = 44;
#[cfg(target_arch = "aarch64")]
const SYS_SENDTO: usize = 206;
const MSG_NOSIGNAL: usize = 0x4000;
const ENOTSOCK: i32 = 88;

/// `send(2)` with `MSG_NOSIGNAL`: a write to a socket whose peer is gone fails with `EPIPE`
/// instead of raising SIGPIPE (which would kill the whole server). Stream sockets only.
fn send_nosignal(fd: i32, buf: &[u8]) -> core::result::Result<usize, Errno> {
    // SAFETY: sendto(fd, buf, len, MSG_NOSIGNAL, NULL, 0) reads at most `buf.len()` bytes from
    // the valid slice and has no other memory effects.
    let r = unsafe { sys::syscall6(SYS_SENDTO, fd as usize, buf.as_ptr() as usize, buf.len(), MSG_NOSIGNAL, 0, 0) };
    if r < 0 {
        Err(Errno(-r as i32))
    } else {
        Ok(r as usize)
    }
}

/// Writes all of `buf` to a non-blocking stream socket (e.g. one end of a socketpair), never
/// raising SIGPIPE. `Err` once the peer is gone or the socket failed.
pub async fn write_all_nosignal(sock: &Async<Fd>, mut buf: &[u8]) -> core::result::Result<(), Errno> {
    while !buf.is_empty() {
        match send_nosignal(sock.get_ref().raw(), buf) {
            Ok(0) => return Err(Errno(sys::EPIPE)),
            Ok(n) => buf = &buf[n..],
            Err(Errno(sys::EAGAIN)) => sock.wait_writable().await,
            Err(Errno(sys::EINTR)) => {}
            Err(Errno(ENOTSOCK)) => return sock.write_all(buf).await, // a pipe: no SIGPIPE-free send
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
