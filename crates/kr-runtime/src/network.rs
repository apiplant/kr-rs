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

/// Parent side, after clone and before releasing the child: creates the veth pair with the peer
/// inside `pid`'s netns and plugs the host end into the bridge.
pub fn attach(pid: i32, id: &[u8]) -> Result<(), Errno> {
    let nl = Netlink::route()?;
    let host = host_ifname(id);
    nl.veth_add(&host, b"eth0", pid)?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
