//! WireGuard pod-network backend (ADR-062): the kernel `wireguard` device is created through
//! rtnetlink and configured through the generic netlink family "wireguard".

use super::*;
use alloc::string::String;
use alloc::vec::Vec;

pub const GENL_ID_CTRL: u16 = 0x10;
const NETLINK_GENERIC: i32 = 16;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const WG_CMD_SET_DEVICE: u8 = 1;
const WGDEVICE_A_IFINDEX: u16 = 1;
const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
const WGDEVICE_A_FLAGS: u16 = 5;
const WGDEVICE_A_LISTEN_PORT: u16 = 6;
const WGDEVICE_A_PEERS: u16 = 8;
const WGDEVICE_F_REPLACE_PEERS: u32 = 1;
const WGPEER_A_PUBLIC_KEY: u16 = 1;
const WGPEER_A_FLAGS: u16 = 3;
const WGPEER_A_ENDPOINT: u16 = 4;
const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
const WGPEER_A_ALLOWEDIPS: u16 = 9;
const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 2;
const WGALLOWEDIP_A_FAMILY: u16 = 1;
const WGALLOWEDIP_A_IPADDR: u16 = 2;
const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;

pub const DEFAULT_PORT: u16 = 51820;
pub const KEEPALIVE: u16 = 25;
/// Overhead of WireGuard over an IPv4 / IPv6 underlay (outer IP + UDP + WireGuard header).
pub const OVERHEAD_V4: u32 = 60;
pub const OVERHEAD_V6: u32 = 80;

/// One peer: its public key, UDP endpoint (16-byte IP form + port) and the pod CIDRs it owns.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Peer {
    pub key: [u8; 32],
    pub endpoint: ([u8; 16], u16),
    /// (address in 16-byte form, prefix length); IPv4 addresses are v4-mapped with prefix 96+len.
    pub allowed: Vec<([u8; 16], u8)>,
}

/// Tunnel MTU for an underlay of `uplink` bytes (v6 underlay costs 80, v4 60).
pub fn tunnel_mtu(uplink: u32, v6_underlay: bool) -> u32 {
    uplink.saturating_sub(if v6_underlay { OVERHEAD_V6 } else { OVERHEAD_V4 })
}

/// A new X25519 private key (clamped) and its public key.
pub fn generate_key() -> ([u8; 32], [u8; 32]) {
    let mut sk = [0u8; 32];
    kr_sys::getrandom(&mut sk);
    sk[0] &= 248;
    sk[31] = (sk[31] & 127) | 64;
    (sk, kr_crypto::x25519::public_key(&sk))
}

/// Reads the base64 private key at `path`, or creates it (mode 0600, never overwritten).
pub fn load_or_create_key(path: &str) -> Result<[u8; 32], Errno> {
    let mut p = Vec::from(path.as_bytes());
    p.push(0);
    if let Ok(data) = kr_sys::fs::read_file(&p, 4096) {
        let text = core::str::from_utf8(&data).map_err(|_| Errno(22))?;
        let raw = kr_fmt::base64::decode(text.trim()).map_err(|_| Errno(22))?;
        return raw.try_into().map_err(|_| Errno(22));
    }
    let (sk, _) = generate_key();
    let fd = kr_sys::ns::open(&p, kr_sys::ns::O_WRONLY | kr_sys::ns::O_CREAT | kr_sys::fs::O_EXCL, 0o600)?;
    let mut text = kr_fmt::base64::encode(&sk);
    text.push('\n');
    kr_sys::fs::write_all(fd.raw(), text.as_bytes())?;
    Ok(sk)
}

pub fn key_b64(k: &[u8; 32]) -> String {
    kr_fmt::base64::encode(k)
}

pub fn parse_key(s: &str) -> Option<[u8; 32]> {
    kr_fmt::base64::decode(s.trim()).ok()?.try_into().ok()
}

/// RTM_NEWLINK creating a `wireguard` device.
pub fn link_msg(name: &[u8], mtu: u32) -> NlBuf {
    let mut b = NlBuf::new();
    b.begin(RTM_NEWLINK, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
    b.raw(&ifinfo(0, 0, 0));
    b.attr_str(IFLA_IFNAME, name);
    b.attr_u32(IFLA_MTU, mtu);
    b.nest_begin(IFLA_LINKINFO);
    b.attr_str(IFLA_INFO_KIND, b"wireguard");
    b.nest_end();
    b.end();
    b
}

fn genl_header(b: &mut NlBuf, cmd: u8, version: u8) {
    b.raw(&[cmd, version, 0, 0]);
}

/// CTRL_CMD_GETFAMILY for `name`.
pub fn getfamily_msg(name: &[u8]) -> NlBuf {
    let mut b = NlBuf::new();
    b.begin(GENL_ID_CTRL, NLM_F_ACK);
    genl_header(&mut b, CTRL_CMD_GETFAMILY, 1);
    b.attr_str(CTRL_ATTR_FAMILY_NAME, name);
    b.end();
    b
}

/// The family id out of a CTRL_CMD_GETFAMILY reply message.
pub fn parse_family_id(m: &[u8]) -> Option<u16> {
    let mut off = 20;
    while off + 4 <= m.len() {
        let len = u16::from_ne_bytes([m[off], m[off + 1]]) as usize;
        let ty = u16::from_ne_bytes([m[off + 2], m[off + 3]]) & 0x3fff;
        if len < 4 || off + len > m.len() {
            return None;
        }
        if ty == CTRL_ATTR_FAMILY_ID && len >= 6 {
            return Some(u16::from_ne_bytes([m[off + 4], m[off + 5]]));
        }
        off += align4(len);
    }
    None
}

fn sockaddr(ip: [u8; 16], port: u16) -> Vec<u8> {
    let mut v = Vec::new();
    match kr_sys::unmap4(ip) {
        Some(a) => {
            v.extend_from_slice(&(AF_INET as u16).to_ne_bytes());
            v.extend_from_slice(&port.to_be_bytes());
            v.extend_from_slice(&a);
            v.extend_from_slice(&[0; 8]);
        }
        None => {
            v.extend_from_slice(&(AF_INET6 as u16).to_ne_bytes());
            v.extend_from_slice(&port.to_be_bytes());
            v.extend_from_slice(&[0; 4]); // flowinfo
            v.extend_from_slice(&ip);
            v.extend_from_slice(&[0; 4]); // scope id
        }
    }
    v
}

/// WG_CMD_SET_DEVICE: private key, listen port and the complete peer list (peers not listed are
/// removed; each listed peer has its allowed IPs replaced).
pub fn set_device_msg(family: u16, ifindex: u32, private: &[u8; 32], port: u16, peers: &[Peer]) -> NlBuf {
    let mut b = NlBuf::new();
    b.begin(family, NLM_F_ACK);
    genl_header(&mut b, WG_CMD_SET_DEVICE, 1);
    b.attr_u32(WGDEVICE_A_IFINDEX, ifindex);
    b.attr(WGDEVICE_A_PRIVATE_KEY, private);
    b.attr(WGDEVICE_A_LISTEN_PORT, &port.to_ne_bytes());
    b.attr_u32(WGDEVICE_A_FLAGS, WGDEVICE_F_REPLACE_PEERS);
    b.nest_begin(WGDEVICE_A_PEERS);
    for (i, p) in peers.iter().enumerate() {
        b.nest_begin(i as u16);
        b.attr(WGPEER_A_PUBLIC_KEY, &p.key);
        b.attr_u32(WGPEER_A_FLAGS, WGPEER_F_REPLACE_ALLOWEDIPS);
        b.attr(WGPEER_A_ENDPOINT, &sockaddr(p.endpoint.0, p.endpoint.1));
        b.attr(WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, &KEEPALIVE.to_ne_bytes());
        b.nest_begin(WGPEER_A_ALLOWEDIPS);
        for (j, (ip, len)) in p.allowed.iter().enumerate() {
            b.nest_begin(j as u16);
            match kr_sys::unmap4(*ip) {
                Some(a) => {
                    b.attr(WGALLOWEDIP_A_FAMILY, &(AF_INET as u16).to_ne_bytes());
                    b.attr(WGALLOWEDIP_A_IPADDR, &a);
                    b.attr(WGALLOWEDIP_A_CIDR_MASK, &[len.saturating_sub(96)]);
                }
                None => {
                    b.attr(WGALLOWEDIP_A_FAMILY, &(AF_INET6 as u16).to_ne_bytes());
                    b.attr(WGALLOWEDIP_A_IPADDR, ip);
                    b.attr(WGALLOWEDIP_A_CIDR_MASK, &[*len]);
                }
            }
            b.nest_end();
        }
        b.nest_end();
        b.nest_end();
    }
    b.nest_end();
    b.end();
    b
}

/// Sorts peers by key (so equal sets compare equal) and drops duplicate keys.
pub fn normalize(mut peers: Vec<Peer>) -> Vec<Peer> {
    peers.sort();
    peers.dedup_by(|a, b| a.key == b.key);
    peers
}

/// A hint for a failed device creation / configuration.
pub fn explain(e: Errno) -> &'static str {
    match e.0 {
        95 | 2 | 19 => "the kernel has no WireGuard support (load the wireguard module: modprobe wireguard)",
        1 | 13 => "creating a WireGuard device needs root (CAP_NET_ADMIN)",
        _ => "netlink request failed",
    }
}

impl Netlink {
    /// Creates the WireGuard device when missing and returns its ifindex.
    pub fn wireguard_ensure(&self, name: &[u8], mtu: u32) -> Result<i32, Errno> {
        if let Ok(i) = ifindex(name) {
            return Ok(i);
        }
        self.transact(&link_msg(name, mtu))?;
        ifindex(name)
    }

    /// Configures the device through generic netlink (the family id is resolved on each call).
    pub fn wireguard_set(&self, ifindex: i32, private: &[u8; 32], port: u16, peers: &[Peer]) -> Result<(), Errno> {
        let g = Netlink::open(NETLINK_GENERIC)?;
        let replies = g.request(&getfamily_msg(b"wireguard"))?;
        let fam = replies.iter().find_map(|m| parse_family_id(m)).ok_or(Errno(95))?;
        g.transact(&set_device_msg(fam, ifindex as u32, private, port, peers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u16at(m: &[u8], o: usize) -> u16 {
        u16::from_ne_bytes([m[o], m[o + 1]])
    }

    #[test]
    fn getfamily_layout() {
        let b = getfamily_msg(b"wireguard");
        let mut want = Vec::new();
        want.extend_from_slice(&36u32.to_ne_bytes());
        want.extend_from_slice(&0x10u16.to_ne_bytes());
        want.extend_from_slice(&5u16.to_ne_bytes()); // REQUEST | ACK
        want.extend_from_slice(&1u32.to_ne_bytes());
        want.extend_from_slice(&0u32.to_ne_bytes());
        want.extend_from_slice(&[3, 1, 0, 0]);
        want.extend_from_slice(&14u16.to_ne_bytes());
        want.extend_from_slice(&2u16.to_ne_bytes());
        want.extend_from_slice(b"wireguard\0\0\0");
        assert_eq!(b.bytes(), &want[..]);
    }

    #[test]
    fn family_id_is_parsed_from_a_reply() {
        let mut m = alloc::vec![0u8; 16];
        m.extend_from_slice(&[3, 2, 0, 0]);
        m.extend_from_slice(&[10, 0, 2, 0]);
        m.extend_from_slice(b"wireg\0\0\0");
        m.extend_from_slice(&[6, 0, 1, 0, 0x2a, 0, 0, 0]);
        assert_eq!(parse_family_id(&m), Some(42));
        assert_eq!(parse_family_id(&m[..20]), None);
    }

    #[test]
    fn link_message_names_the_wireguard_kind() {
        let b = link_msg(b"kr.wg", 1420);
        let m = b.bytes();
        assert_eq!(u16at(m, 4), RTM_NEWLINK);
        assert_eq!(u32::from_ne_bytes(m[0..4].try_into().unwrap()) as usize, m.len());
        assert!(m.windows(10).any(|w| w == b"wireguard\0"));
        assert!(m.windows(4).any(|w| w == 1420u32.to_ne_bytes()));
    }

    #[test]
    fn set_device_layout() {
        let peer = Peer { key: [7; 32], endpoint: (kr_sys::map4([192, 168, 1, 2]), 51820), allowed: alloc::vec![(kr_sys::map4([10, 88, 1, 0]), 96 + 24)] };
        let b = set_device_msg(0x20, 5, &[1; 32], 51820, &[peer]);
        let m = b.bytes();
        assert_eq!(u16at(m, 4), 0x20);
        assert_eq!(&m[16..20], &[1, 1, 0, 0]); // WG_CMD_SET_DEVICE, version 1
        assert_eq!(u32::from_ne_bytes(m[0..4].try_into().unwrap()) as usize, m.len());
        assert_eq!(&m[20..28], &[8, 0, 1, 0, 5, 0, 0, 0]); // ifindex
        assert_eq!(&m[28..32], &[36, 0, 3, 0]); // private key
        assert_eq!(&m[32..64], &[1u8; 32]);
        assert_eq!(&m[64..68], &[6, 0, 6, 0]); // listen port
        assert_eq!(&m[68..70], &51820u16.to_ne_bytes());
        assert_eq!(&m[72..80], &[8, 0, 5, 0, 1, 0, 0, 0]); // flags: REPLACE_PEERS
        assert_eq!(u16at(m, 82), 8 | 0x8000); // nested peers
        assert!(m.windows(8).any(|w| w == [2u8, 0, 0xca, 0x6c, 192, 168, 1, 2])); // sockaddr_in
        assert!(m.windows(4).any(|w| w == [10, 88, 1, 0]));
        assert!(m.windows(5).any(|w| w == [5, 0, 3, 0, 24])); // mask 24
        assert!(m.windows(6).any(|w| w == [6, 0, 5, 0, 25, 0])); // keepalive 25
    }

    #[test]
    fn ipv6_allowed_ip_and_endpoint() {
        let ip6 = [0xfd, 0, 0, 0x88, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let peer = Peer { key: [1; 32], endpoint: (ip6, 1), allowed: alloc::vec![(ip6, 64)] };
        let m = set_device_msg(0x20, 1, &[0; 32], 1, &[peer]).bytes().to_vec();
        assert!(m.windows(5).any(|w| w == [5, 0, 3, 0, 64]));
        assert!(m.windows(16).any(|w| w == ip6));
        assert!(m.windows(4).any(|w| w == [10, 0, 0, 1])); // AF_INET6 sockaddr: family 10, port 0x0001
    }

    #[test]
    fn peers_are_sorted_and_deduplicated() {
        let p = |k: u8, c: u8| Peer { key: [k; 32], endpoint: (kr_sys::map4([1, 1, 1, c]), 1), allowed: Vec::new() };
        let n = normalize(alloc::vec![p(9, 1), p(2, 2), p(9, 3)]);
        assert_eq!(n.len(), 2);
        assert_eq!(n[0].key, [2; 32]);
        assert_eq!(normalize(alloc::vec![p(2, 2), p(9, 1)]), normalize(alloc::vec![p(9, 1), p(2, 2)]));
    }

    #[test]
    fn mtu_accounts_for_the_underlay() {
        assert_eq!(tunnel_mtu(1500, false), 1440);
        assert_eq!(tunnel_mtu(1500, true), 1420);
        assert_eq!(tunnel_mtu(10, true), 0);
    }

    #[test]
    fn key_pair_and_file_handling() {
        let (sk, pk) = generate_key();
        assert_eq!(kr_crypto::x25519::public_key(&sk), pk);
        assert_eq!(parse_key(&key_b64(&pk)), Some(pk));
        assert_eq!(parse_key("short"), None);
        let mut r = [0u8; 8];
        kr_sys::getrandom(&mut r);
        let dir = alloc::format!("{}/../../target/wg-test-{}", env!("CARGO_MANIFEST_DIR"), u64::from_ne_bytes(r));
        std::fs::create_dir_all(&dir).unwrap();
        let path = alloc::format!("{dir}/wireguard.key");
        let k1 = load_or_create_key(&path).unwrap();
        let k2 = load_or_create_key(&path).unwrap();
        assert_eq!(k1, k2);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::write(&path, "garbage").unwrap();
        assert!(load_or_create_key(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
