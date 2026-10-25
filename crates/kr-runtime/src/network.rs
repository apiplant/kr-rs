//! Built-in bridge network (KNOWN_ISSUES #50, ADR-019): replaces the CNI bridge + host-local
//! plugins. Requires real root on the host; rootless containers keep loopback-only networking.
//!
//! Layout: bridge `kr0` owns the gateway address of a /16; each container gets one address from
//! a file-based IPAM, a veth pair whose peer is created directly inside the container's netns as
//! `eth0`, and a default route via the gateway. Outbound traffic is masqueraded by an nftables
//! table `ip kr`. Everything is programmed over netlink; no `ip`/`nft`/`iptables` binaries.

use alloc::vec::Vec;
use kr_net::netlink::{self, Netlink};
use kr_sys::ns;
use kr_sys::Errno;

pub const BRIDGE: &[u8] = b"kr0";
/// The cluster pod network; each node gets a /24 of it (`spec.podCIDR`).
pub const CLUSTER_CIDR: ([u8; 4], u8) = ([10, 88, 0, 0], 16);
/// Defaults for standalone use (`kr ctr`): the first /24.
pub const SUBNET: [u8; 4] = [10, 88, 0, 0];
pub const PREFIX: u8 = 24;
pub const GATEWAY: [u8; 4] = [10, 88, 0, 1];

/// A node's pod subnet: bridge gateway is the first address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PodNet {
    pub subnet: [u8; 4],
    pub prefix: u8,
    pub gateway: [u8; 4],
}

impl Default for PodNet {
    fn default() -> Self {
        PodNet { subnet: SUBNET, prefix: PREFIX, gateway: GATEWAY }
    }
}

impl PodNet {
    /// Parses "a.b.c.d/len" (IPv4, prefix 8..=30).
    pub fn parse(cidr: &str) -> Option<PodNet> {
        let (ip, len) = cidr.split_once('/')?;
        let prefix: u8 = len.parse().ok().filter(|l| (8..=30).contains(l))?;
        let mut a = [0u8; 4];
        let mut parts = ip.split('.');
        for o in a.iter_mut() {
            *o = parts.next()?.parse().ok()?;
        }
        let mask = u32::MAX << (32 - prefix);
        let net = u32::from_be_bytes(a) & mask;
        Some(PodNet { subnet: net.to_be_bytes(), prefix, gateway: (net + 1).to_be_bytes() })
    }
}
const NFT_TABLE: &[u8] = b"kr";

/// What the container child configures on its `eth0`.
#[derive(Clone, Copy, Debug)]
pub struct NetConfig {
    pub ip: [u8; 4],
    pub prefix: u8,
    pub gateway: [u8; 4],
}

fn exists_ok(r: Result<(), Errno>) -> Result<(), Errno> {
    match r {
        Err(Errno(17)) => Ok(()),
        r => r,
    }
}

/// Creates (idempotently) the bridge, its gateway address, IPv4 forwarding and the NAT table.
pub fn setup_host() -> Result<(), Errno> {
    setup_host_with(&PodNet::default())
}

pub fn setup_host_with(pn: &PodNet) -> Result<(), Errno> {
    let nl = Netlink::route()?;
    exists_ok(nl.bridge_add(BRIDGE))?;
    let br = netlink::ifindex(BRIDGE)?;
    exists_ok(nl.addr_add(br, pn.gateway, pn.prefix))?;
    nl.link_up(br)?;
    ns::write_file(b"/proc/sys/net/ipv4/ip_forward\0", b"1")?;
    kr_net::nft::ensure_masquerade(&kr_net::nft::Masquerade { table: NFT_TABLE, cidr: CLUSTER_CIDR.0, prefix: CLUSTER_CIDR.1, bridge: BRIDGE })
}

/// Host-side veth name for a container: `krv` + 8 hex digits of an FNV-1a hash of its id.
pub fn host_ifname(id: &[u8]) -> [u8; 11] {
    let h = id.iter().fold(0x811c_9dc5u32, |h, &b| (h ^ b as u32).wrapping_mul(0x0100_0193));
    let mut n = *b"krv00000000";
    for i in 0..8 {
        n[3 + i] = b"0123456789abcdef"[(h >> (28 - 4 * i) & 0xf) as usize];
    }
    n
}

/// MTU for new pod interfaces (0: kernel default). An overlay (VXLAN) sets it to the tunnel's
/// MTU so pods never send packets that do not fit once encapsulated.
static POD_MTU: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

pub fn set_pod_mtu(mtu: u32) {
    POD_MTU.store(mtu, core::sync::atomic::Ordering::Relaxed);
}

/// Parent side, after clone and before releasing the child: creates the veth pair with the peer
/// inside `pid`'s netns and plugs the host end into the bridge.
pub fn attach(pid: i32, id: &[u8]) -> Result<(), Errno> {
    let nl = Netlink::route()?;
    let host = host_ifname(id);
    nl.veth_add(&host, b"eth0", pid, POD_MTU.load(core::sync::atomic::Ordering::Relaxed))?;
    let r = (|| {
        let idx = netlink::ifindex(&host)?;
        nl.link_set_master(idx, netlink::ifindex(BRIDGE)?)?;
        nl.link_up(idx)
    })();
    if r.is_err() {
        if let Ok(idx) = netlink::ifindex(&host) {
            let _ = nl.link_del(idx);
        }
    }
    r
}

/// Child side, inside the container netns (before capabilities are dropped).
pub fn configure_child(c: &NetConfig) -> Result<(), Errno> {
    let nl = Netlink::route()?;
    let idx = netlink::ifindex(b"eth0")?;
    nl.addr_add(idx, c.ip, c.prefix)?;
    nl.link_up(idx)?;
    nl.route_add([0; 4], 0, Some(c.gateway), idx)
}

/// An allocated address; `release` frees it. Leases are files `<dir>/<a.b.c.d>` created with
/// O_EXCL, so concurrent kr processes never hand out the same address.
pub struct Lease {
    pub ip: [u8; 4],
    path: Vec<u8>,
}

impl Lease {
    pub fn release(self) {
        let _ = kr_sys::fs::unlinkat(ns::AT_FDCWD, &self.path, 0);
    }
}

fn dotted(ip: [u8; 4]) -> Vec<u8> {
    let mut v = Vec::new();
    for (i, o) in ip.iter().enumerate() {
        if i > 0 {
            v.push(b'.');
        }
        let mut b = [0u8; 3];
        let mut n = *o;
        let mut k = 3;
        loop {
            k -= 1;
            b[k] = b'0' + n % 10;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        v.extend_from_slice(&b[k..]);
    }
    v
}

/// Allocates the lowest free address after the gateway. `dir` must exist; `owner` (the
/// container id) is written into the lease for debugging.
pub fn allocate(dir: &[u8], owner: &[u8]) -> Result<Lease, Errno> {
    allocate_in(dir, owner, &PodNet::default())
}

pub fn allocate_in(dir: &[u8], owner: &[u8], pn: &PodNet) -> Result<Lease, Errno> {
    let base = u32::from_be_bytes(pn.subnet);
    let size = 1u32 << (32 - pn.prefix);
    let gw = u32::from_be_bytes(pn.gateway);
    for host in 1..size - 1 {
        let ip = (base + host).to_be_bytes();
        if base + host == gw {
            continue;
        }
        let mut path = dir.to_vec();
        path.push(b'/');
        path.extend_from_slice(&dotted(ip));
        path.push(0);
        const O_EXCL: i32 = 0o200;
        match ns::open(&path, ns::O_WRONLY | ns::O_CREAT | O_EXCL, 0o600) {
            Ok(fd) => {
                let _ = kr_sys::write(fd.raw(), owner);
                return Ok(Lease { ip, path });
            }
            Err(Errno(17)) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(Errno(28)) // ENOSPC: subnet exhausted
}

/// Start time (clock ticks since boot, field 22 of `/proc/<pid>/stat`) of a live process.
fn proc_start(pid: u32) -> Option<u64> {
    let mut p = alloc::format!("/proc/{pid}/stat").into_bytes();
    p.push(0);
    let b = kr_sys::fs::read_file(&p, 4096).ok()?;
    // comm (field 2) may contain spaces and parentheses: fields resume after the last ')'.
    let rest = &b[b.iter().rposition(|c| *c == b')')? + 2..];
    let mut f = core::str::from_utf8(rest).ok()?.split(' ');
    // A zombie (killed, not yet reaped by its parent) no longer runs.
    if matches!(f.next()?, "Z" | "X") {
        return None;
    }
    f.nth(18)?.parse().ok()
}

/// Lease owner for a standalone container: `<id> pid=<pid>:<start>` of this process, so that a
/// lease left by a SIGKILLed `kr ctr run` can be recognised ([`owner_alive`]).
pub fn process_owner(id: &[u8]) -> Vec<u8> {
    let pid = kr_sys::fs::getpid();
    let mut o = id.to_vec();
    o.extend_from_slice(alloc::format!(" pid={pid}:{}", proc_start(pid).unwrap_or(0)).as_bytes());
    o
}

/// For an owner written by [`process_owner`]: whether that process still runs (same pid and
/// start time, so a reused pid does not count). `None` for other owners (pod uids).
pub fn owner_alive(owner: &[u8]) -> Option<bool> {
    let s = core::str::from_utf8(owner).ok()?;
    let (pid, start) = s.rsplit_once(" pid=")?.1.split_once(':')?;
    let (pid, start): (u32, u64) = (pid.parse().ok()?, start.parse().ok()?);
    Some(proc_start(pid) == Some(start))
}

/// Garbage-collects leases whose owner (the id recorded in the file) fails `keep`, e.g. leases
/// of sandboxes that died with a SIGKILLed kr. Returns how many were removed. Non-lease names
/// (anything not a dotted quad) are left alone.
pub fn gc(dir: &[u8], keep: impl Fn(&[u8]) -> bool) -> usize {
    let mut d = dir.to_vec();
    d.push(0);
    let Ok(fd) = ns::open(&d, ns::O_RDONLY | ns::O_DIRECTORY, 0) else { return 0 };
    let names: Vec<Vec<u8>> = kr_sys::fs::read_dir(&fd).filter_map(Result::ok).map(|e| e.name).filter(|n| !n.is_empty() && n.iter().all(|b| b.is_ascii_digit() || *b == b'.')).collect();
    let mut removed = 0;
    for name in names {
        let mut path = dir.to_vec();
        path.push(b'/');
        path.extend_from_slice(&name);
        path.push(0);
        let Ok(f) = ns::open(&path, ns::O_RDONLY, 0) else { continue };
        let mut buf = [0u8; 256];
        let n = kr_sys::read(f.raw(), &mut buf).unwrap_or(0);
        if !keep(&buf[..n]) && kr_sys::fs::unlinkat(ns::AT_FDCWD, &path, 0).is_ok() {
            removed += 1;
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gc_removes_only_stale_leases() {
        let mut dir = b"/tmp/kr-ipam-gc-test-".to_vec();
        dir.extend_from_slice(&dec_pid());
        let mut c = dir.clone();
        c.push(0);
        let _ = ns::mkdir(&c, 0o700);
        let pn = PodNet::default();
        let a = allocate_in(&dir, b"live-pod", &pn).unwrap();
        let b = allocate_in(&dir, b"dead-pod", &pn).unwrap();
        let c2 = allocate_in(&dir, b"dead-pod-2", &pn).unwrap();
        assert_eq!(gc(&dir, |o| o == b"live-pod"), 2);
        // The freed addresses are reusable; the live one is not handed out again.
        let again = allocate_in(&dir, b"new", &pn).unwrap();
        assert_eq!(again.ip, b.ip);
        assert_ne!(again.ip, a.ip);
        assert_eq!(gc(&dir, |_| false), 2);
        let _ = (c2, a);
        let _ = ns::rmdir(&c);
    }

    #[test]
    fn process_owners_are_alive_only_while_their_process_runs() {
        let me = process_owner(b"ctr-1");
        assert_eq!(owner_alive(&me), Some(true));
        assert_eq!(owner_alive(b"0b7d6f0e-pod-uid"), None);
        // Same pid, different start time: a reused pid.
        let s = core::str::from_utf8(&me).unwrap();
        let (head, _) = s.rsplit_once(':').unwrap();
        assert_eq!(owner_alive(alloc::format!("{head}:1").as_bytes()), Some(false));
        assert_eq!(owner_alive(b"ctr-2 pid=999999999:5"), Some(false));
    }

    fn dec_pid() -> Vec<u8> {
        let mut v = Vec::new();
        let mut n = kr_sys::fs::getpid();
        while n > 0 {
            v.insert(0, b'0' + (n % 10) as u8);
            n /= 10;
        }
        v
    }

    #[test]
    fn ifname_fits_and_is_stable() {
        let a = host_ifname(b"ctr-1");
        assert!(a.len() < 16);
        assert_eq!(a, host_ifname(b"ctr-1"));
        assert_ne!(a, host_ifname(b"ctr-2"));
        assert!(a.starts_with(b"krv"));
    }

    #[test]
    fn dotted_quad() {
        assert_eq!(dotted([10, 88, 0, 2]), b"10.88.0.2");
        assert_eq!(dotted([255, 0, 100, 9]), b"255.0.100.9");
    }
}
