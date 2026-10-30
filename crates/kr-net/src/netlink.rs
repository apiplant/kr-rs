//! Netlink: a message builder, a blocking request/ack socket and the rtnetlink operations the
//! container network needs (links, bridge, veth, addresses, routes). Replaces `ip(8)`.
//!
//! Requests are small and rare (container start/stop), so the socket is blocking and every
//! message is sent with NLM_F_ACK; `transact` returns the first kernel error.

use alloc::vec::Vec;
use kr_sys::{Errno, Fd};

pub const NETLINK_ROUTE: i32 = 0;
pub const NETLINK_NETFILTER: i32 = 12;
const AF_NETLINK: i32 = 16;
const SOCK_RAW: i32 = 3;

pub const NLM_F_REQUEST: u16 = 0x1;
pub const NLM_F_ACK: u16 = 0x4;
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLA_F_NESTED: u16 = 0x8000;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

/// Builds one or more netlink messages into a single buffer (one `send`, e.g. an nft batch).
#[derive(Default)]
pub struct NlBuf {
    buf: Vec<u8>,
    msg: Option<usize>,
    nests: Vec<usize>,
    seq: u32,
    acks: usize,
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

impl NlBuf {
    pub fn new() -> NlBuf {
        NlBuf { seq: 1, ..Default::default() }
    }

    /// Starts a message. NLM_F_REQUEST is always set; with NLM_F_ACK, `transact` waits for its ack.
    pub fn begin(&mut self, ty: u16, flags: u16) {
        assert!(self.msg.is_none(), "nested netlink message");
        let flags = flags | NLM_F_REQUEST;
        if flags & NLM_F_ACK != 0 {
            self.acks += 1;
        }
        self.msg = Some(self.buf.len());
        self.buf.extend_from_slice(&0u32.to_ne_bytes()); // len, patched in `end`
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        self.buf.extend_from_slice(&flags.to_ne_bytes());
        self.buf.extend_from_slice(&self.seq.to_ne_bytes());
        self.buf.extend_from_slice(&0u32.to_ne_bytes()); // port id: kernel assigns
        self.seq += 1;
    }

    /// Appends a fixed header (ifinfomsg, nfgenmsg, ...), padded to 4 bytes.
    pub fn raw(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
        self.buf.resize(align4(self.buf.len()), 0);
    }

    pub fn attr(&mut self, ty: u16, data: &[u8]) {
        let len = 4 + data.len();
        assert!(len <= u16::MAX as usize);
        self.buf.extend_from_slice(&(len as u16).to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        self.raw(data);
    }

    pub fn attr_u32(&mut self, ty: u16, v: u32) {
        self.attr(ty, &v.to_ne_bytes());
    }

    /// Big-endian u32 (nftables expects network byte order for most integers).
    pub fn attr_u32_be(&mut self, ty: u16, v: u32) {
        self.attr(ty, &v.to_be_bytes());
    }

    /// NUL-terminated string attribute.
    pub fn attr_str(&mut self, ty: u16, s: &[u8]) {
        let mut v = Vec::with_capacity(s.len() + 1);
        v.extend_from_slice(s);
        v.push(0);
        self.attr(ty, &v);
    }

    /// Opens a nested attribute (NLA_F_NESTED is set); close with `nest_end`.
    pub fn nest_begin(&mut self, ty: u16) {
        self.nests.push(self.buf.len());
        self.buf.extend_from_slice(&0u16.to_ne_bytes());
        self.buf.extend_from_slice(&(ty | NLA_F_NESTED).to_ne_bytes());
    }

    pub fn nest_end(&mut self) {
        let start = self.nests.pop().expect("nest_end without nest_begin");
        let len = self.buf.len() - start;
        assert!(len <= u16::MAX as usize);
        self.buf[start..start + 2].copy_from_slice(&(len as u16).to_ne_bytes());
    }

    pub fn end(&mut self) {
        assert!(self.nests.is_empty(), "unclosed nested attribute");
        let start = self.msg.take().expect("end without begin");
        let len = (self.buf.len() - start) as u32;
        self.buf[start..start + 4].copy_from_slice(&len.to_ne_bytes());
    }

    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }
}

pub struct Netlink {
    fd: Fd,
}

impl Netlink {
    pub fn open(protocol: i32) -> Result<Netlink, Errno> {
        Ok(Netlink { fd: kr_sys::socket(AF_NETLINK, SOCK_RAW | kr_sys::SOCK_CLOEXEC, protocol)? })
    }

    /// Sends `msgs` and waits for every requested ack. Returns the first error the kernel reports
    /// (the rest of the replies are still drained, so the socket stays usable).
    pub fn transact(&self, msgs: &NlBuf) -> Result<(), Errno> {
        assert!(msgs.msg.is_none(), "unterminated netlink message");
        let n = kr_sys::write(self.fd.raw(), msgs.bytes())?;
        if n != msgs.bytes().len() {
            return Err(Errno(5));
        }
        let mut pending = msgs.acks;
        let mut first_err = None;
        let mut buf = alloc::vec![0u8; 32 * 1024];
        while pending > 0 {
            let n = match kr_sys::read(self.fd.raw(), &mut buf) {
                Err(Errno(4)) => continue,
                r => r?,
            };
            let mut off = 0;
            while off + 16 <= n {
                let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
                let ty = u16::from_ne_bytes([buf[off + 4], buf[off + 5]]);
                if len < 16 || off + len > n {
                    return Err(Errno(74)); // EBADMSG
                }
                match ty {
                    NLMSG_ERROR if len >= 20 => {
                        let e = i32::from_ne_bytes(buf[off + 16..off + 20].try_into().unwrap());
                        if e != 0 && first_err.is_none() {
                            first_err = Some(Errno(-e));
                        }
                        pending -= 1;
                    }
                    NLMSG_DONE => pending = pending.saturating_sub(1),
                    _ => {}
                }
                off += align4(len);
            }
            if pending == 0 {
                break;
            }
        }
        first_err.map_or(Ok(()), Err)
    }
}

// ---- rtnetlink ----

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;
const NLM_F_DUMP: u16 = 0x300;
/// Routing protocol number of routes installed by kr (so only they are reconciled).
pub const RTPROT_KR: u8 = 200;

const IFLA_IFNAME: u16 = 3;
const IFLA_MASTER: u16 = 10;
const IFLA_LINKINFO: u16 = 18;
const IFLA_NET_NS_PID: u16 = 19;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const VETH_INFO_PEER: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_ADDRESS: u16 = 1;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const IFF_UP: u32 = 1;
const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const IFA_FLAGS: u16 = 8;
const IFA_F_NODAD: u32 = 0x02;

/// struct ifinfomsg.
fn ifinfo(index: i32, flags: u32, change: u32) -> [u8; 16] {
    let mut h = [0u8; 16];
    h[0] = AF_UNSPEC;
    h[4..8].copy_from_slice(&index.to_ne_bytes());
    h[8..12].copy_from_slice(&flags.to_ne_bytes());
    h[12..16].copy_from_slice(&change.to_ne_bytes());
    h
}

impl Netlink {
    pub fn route() -> Result<Netlink, Errno> {
        Netlink::open(NETLINK_ROUTE)
    }

    fn one(&self, f: impl FnOnce(&mut NlBuf)) -> Result<(), Errno> {
        let mut b = NlBuf::new();
        f(&mut b);
        b.end();
        self.transact(&b)
    }

    /// Creates a bridge; EEXIST is returned as-is so callers can treat it as success.
    pub fn bridge_add(&self, name: &[u8]) -> Result<(), Errno> {
        self.one(|b| {
            b.begin(RTM_NEWLINK, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
            b.raw(&ifinfo(0, 0, 0));
            b.attr_str(IFLA_IFNAME, name);
            b.nest_begin(IFLA_LINKINFO);
            b.attr_str(IFLA_INFO_KIND, b"bridge");
            b.nest_end();
        })
    }

    /// Creates a veth pair: `host` in our netns, `peer` directly inside the netns of `peer_pid`.
    /// `mtu` (0: kernel default) applies to both ends.
    pub fn veth_add(&self, host: &[u8], peer: &[u8], peer_pid: i32, mtu: u32) -> Result<(), Errno> {
        self.one(|b| {
            b.begin(RTM_NEWLINK, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
            b.raw(&ifinfo(0, 0, 0));
            b.attr_str(IFLA_IFNAME, host);
            if mtu > 0 {
                b.attr_u32(IFLA_MTU, mtu);
            }
            b.nest_begin(IFLA_LINKINFO);
            b.attr_str(IFLA_INFO_KIND, b"veth");
            b.nest_begin(IFLA_INFO_DATA);
            b.nest_begin(VETH_INFO_PEER);
            b.raw(&ifinfo(0, 0, 0));
            b.attr_str(IFLA_IFNAME, peer);
            if mtu > 0 {
                b.attr_u32(IFLA_MTU, mtu);
            }
            b.attr_u32(IFLA_NET_NS_PID, peer_pid as u32);
            b.nest_end();
            b.nest_end();
            b.nest_end();
        })
    }

    pub fn link_del(&self, index: i32) -> Result<(), Errno> {
        self.one(|b| {
            b.begin(RTM_DELLINK, NLM_F_ACK);
            b.raw(&ifinfo(index, 0, 0));
        })
    }

    pub fn link_up(&self, index: i32) -> Result<(), Errno> {
        self.one(|b| {
            b.begin(RTM_NEWLINK, NLM_F_ACK);
            b.raw(&ifinfo(index, IFF_UP, IFF_UP));
        })
    }

    /// Sets the link-layer address of `index`. On a bridge this also pins it: a bridge whose
    /// address was never set takes the lowest address of its ports, so adding a port changed the
    /// gateway's MAC and every pod kept sending to the old one until its ARP entry expired.
    pub fn link_set_mac(&self, index: i32, mac: [u8; 6]) -> Result<(), Errno> {
        self.one(|b| {
            b.begin(RTM_NEWLINK, NLM_F_ACK);
            b.raw(&ifinfo(index, 0, 0));
            b.attr(IFLA_ADDRESS, &mac);
        })
    }

    /// Attaches `index` to the bridge `master`.
    pub fn link_set_master(&self, index: i32, master: i32) -> Result<(), Errno> {
        self.one(|b| {
            b.begin(RTM_NEWLINK, NLM_F_ACK);
            b.raw(&ifinfo(index, 0, 0));
            b.attr_u32(IFLA_MASTER, master as u32);
        })
    }

    /// Adds an IPv4 address; EEXIST when already present.
    pub fn addr_add(&self, index: i32, addr: [u8; 4], prefix: u8) -> Result<(), Errno> {
        self.one(|b| {
            b.begin(RTM_NEWADDR, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
            let mut h = [0u8; 8]; // struct ifaddrmsg
            h[0] = AF_INET;
            h[1] = prefix;
            h[4..8].copy_from_slice(&(index as u32).to_ne_bytes());
            b.raw(&h);
            b.attr(IFA_LOCAL, &addr);
            b.attr(IFA_ADDRESS, &addr);
        })
    }

    /// Adds an IPv6 address without duplicate address detection (pod addresses are unique by
    /// construction; DAD would leave them tentative for a second); EEXIST when present.
    pub fn addr_add6(&self, index: i32, addr: [u8; 16], prefix: u8) -> Result<(), Errno> {
        self.one(|b| {
            b.begin(RTM_NEWADDR, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
            let mut h = [0u8; 8]; // struct ifaddrmsg
            h[0] = AF_INET6;
            h[1] = prefix;
            h[4..8].copy_from_slice(&(index as u32).to_ne_bytes());
            b.raw(&h);
            b.attr(IFA_LOCAL, &addr);
            b.attr(IFA_ADDRESS, &addr);
            b.attr_u32(IFA_FLAGS, IFA_F_NODAD);
        })
    }

    /// Adds an IPv6 route `dst/prefix` via `gateway` (`::/0` for the default route).
    pub fn route_add6(&self, dst: [u8; 16], prefix: u8, gateway: Option<[u8; 16]>, oif: i32) -> Result<(), Errno> {
        self.route_add6_proto(dst, prefix, gateway, oif, 3)
    }

    pub fn route_add6_proto(&self, dst: [u8; 16], prefix: u8, gateway: Option<[u8; 16]>, oif: i32, proto: u8) -> Result<(), Errno> {
        self.one(|b| {
            b.begin(RTM_NEWROUTE, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
            let scope = if gateway.is_some() { 0 } else { 253 };
            b.raw(&[AF_INET6, prefix, 0, 0, 254, proto, scope, 1, 0, 0, 0, 0]);
            if prefix > 0 {
                b.attr(RTA_DST, &dst);
            }
            if let Some(gw) = gateway {
                b.attr(RTA_GATEWAY, &gw);
            }
            if oif > 0 {
                b.attr_u32(RTA_OIF, oif as u32);
            }
        })
    }

    /// Adds an IPv4 route `dst/prefix` via `gateway` (0.0.0.0/0 for the default route).
    pub fn route_add(&self, dst: [u8; 4], prefix: u8, gateway: Option<[u8; 4]>, oif: i32) -> Result<(), Errno> {
        self.route_add_proto(dst, prefix, gateway, oif, 3)
    }

    /// `route_add` with an explicit routing protocol (`RTPROT_KR` marks kr-managed routes).
    pub fn route_add_proto(&self, dst: [u8; 4], prefix: u8, gateway: Option<[u8; 4]>, oif: i32, proto: u8) -> Result<(), Errno> {
        self.one(|b| {
            b.begin(RTM_NEWROUTE, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
            // struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type, flags
            let scope = if gateway.is_some() { 0 } else { 253 }; // universe / link
            let h = [AF_INET, prefix, 0, 0, 254, proto, scope, 1, 0, 0, 0, 0];
            b.raw(&h);
            if prefix > 0 {
                b.attr(RTA_DST, &dst);
            }
            if let Some(gw) = gateway {
                b.attr(RTA_GATEWAY, &gw);
            }
            // oif 0: let the kernel pick the interface from the gateway.
            if oif > 0 {
                b.attr_u32(RTA_OIF, oif as u32);
            }
        })
    }
}

impl Netlink {
    /// Deletes the main-table route `dst/prefix` installed with protocol `proto`.
    pub fn route_del(&self, dst: [u8; 4], prefix: u8, proto: u8) -> Result<(), Errno> {
        self.one(|b| {
            b.begin(RTM_DELROUTE, NLM_F_ACK);
            b.raw(&[AF_INET, prefix, 0, 0, 254, proto, 0, 1, 0, 0, 0, 0]);
            b.attr(RTA_DST, &dst);
        })
    }

    /// Dumps the main-table IPv4 routes whose protocol is `proto` as (dst, prefix, gateway).
    pub fn routes_by_proto(&self, proto: u8) -> Result<Vec<([u8; 4], u8, Option<[u8; 4]>)>, Errno> {
        let mut b = NlBuf::new();
        b.begin(RTM_GETROUTE, NLM_F_DUMP);
        b.raw(&[AF_INET, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b.end();
        let n = kr_sys::write(self.fd.raw(), b.bytes())?;
        if n != b.bytes().len() {
            return Err(Errno(5));
        }
        let mut out = Vec::new();
        let mut buf = alloc::vec![0u8; 32 * 1024];
        loop {
            let n = match kr_sys::read(self.fd.raw(), &mut buf) {
                Err(Errno(4)) => continue,
                r => r?,
            };
            let mut off = 0;
            while off + 16 <= n {
                let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
                let ty = u16::from_ne_bytes([buf[off + 4], buf[off + 5]]);
                if len < 16 || off + len > n {
                    return Err(Errno(74));
                }
                match ty {
                    NLMSG_DONE => return Ok(out),
                    NLMSG_ERROR => return Err(Errno(5)),
                    RTM_NEWROUTE => {
                        if let Some(r) = parse_route(&buf[off + 16..off + len], proto) {
                            out.push(r);
                        }
                    }
                    _ => {}
                }
                off += align4(len);
            }
        }
    }
}

/// Parses an rtmsg payload; None unless it is a main-table route of protocol `proto`.
fn parse_route(m: &[u8], proto: u8) -> Option<([u8; 4], u8, Option<[u8; 4]>)> {
    if m.len() < 12 || m[0] != AF_INET || m[4] != 254 || m[5] != proto {
        return None;
    }
    let (mut dst, mut gw) = ([0u8; 4], None);
    let mut o = 12;
    while o + 4 <= m.len() {
        let l = u16::from_ne_bytes([m[o], m[o + 1]]) as usize;
        let t = u16::from_ne_bytes([m[o + 2], m[o + 3]]) & 0x3fff;
        if l < 4 || o + l > m.len() {
            break;
        }
        if l == 8 && t == RTA_DST {
            dst.copy_from_slice(&m[o + 4..o + 8]);
        } else if l == 8 && t == RTA_GATEWAY {
            gw = Some([m[o + 4], m[o + 5], m[o + 6], m[o + 7]]);
        }
        o += align4(l);
    }
    Some((dst, m[1], gw))
}

impl Netlink {
    /// `ip route add local <dst>/<prefix> dev <oif> table local`: makes a whole range locally
    /// deliverable and bindable (used for the Service CIDR). EEXIST when present.
    pub fn route_add_local(&self, dst: [u8; 4], prefix: u8, oif: i32) -> Result<(), Errno> {
        self.one(|b| {
            b.begin(RTM_NEWROUTE, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
            // rtmsg: family, dst_len, src_len, tos, table=local(255), proto=boot, scope=host, type=local
            b.raw(&[AF_INET, prefix, 0, 0, 255, 3, 254, 2, 0, 0, 0, 0]);
            b.attr(RTA_DST, &dst);
            b.attr_u32(RTA_OIF, oif as u32);
        })
    }
}

impl Netlink {
    /// `ip -6 route add local <dst>/<prefix> dev <oif> table local` (the IPv6 Service CIDR).
    pub fn route_add_local6(&self, dst: [u8; 16], prefix: u8, oif: i32) -> Result<(), Errno> {
        self.one(|b| {
            b.begin(RTM_NEWROUTE, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
            b.raw(&[AF_INET6, prefix, 0, 0, 255, 3, 254, 2, 0, 0, 0, 0]);
            b.attr(RTA_DST, &dst);
            b.attr_u32(RTA_OIF, oif as u32);
        })
    }
}

// ---- VXLAN overlay: link, neighbour (ARP) and FDB entries ----

const RTM_NEWNEIGH: u16 = 28;
const RTM_DELNEIGH: u16 = 29;
const RTM_GETNEIGH: u16 = 30;
const AF_BRIDGE: u8 = 7;
const NUD_PERMANENT: u16 = 0x80;
const NTF_SELF: u8 = 2;
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
const IFLA_ADDRESS: u16 = 1;
const IFLA_MTU: u16 = 4;
const IFLA_VXLAN_ID: u16 = 1;
const IFLA_VXLAN_LOCAL: u16 = 4;
const IFLA_VXLAN_LEARNING: u16 = 7;
const IFLA_VXLAN_PORT: u16 = 15;
const RTNH_F_ONLINK: u8 = 4;

/// Stable, locally administered VTEP MAC derived from the node's IPv4 address.
pub fn vtep_mac(ip: [u8; 4]) -> [u8; 6] {
    [0x02, 0x4b, ip[0], ip[1], ip[2], ip[3]]
}

/// `aa:bb:..` formatting of a MAC (the Node annotation form).
pub fn mac_string(m: [u8; 6]) -> alloc::string::String {
    alloc::format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
}

pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut it = s.split(':');
    for o in out.iter_mut() {
        *o = u8::from_str_radix(it.next()?, 16).ok()?;
    }
    it.next().is_none().then_some(out)
}

/// RTM_NEWLINK creating a non-learning VXLAN device bound to `local`.
fn vxlan_msg(name: &[u8], vni: u32, port: u16, local: [u8; 4], mtu: u32, mac: [u8; 6]) -> NlBuf {
    let mut b = NlBuf::new();
    b.begin(RTM_NEWLINK, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
    b.raw(&ifinfo(0, 0, 0));
    b.attr_str(IFLA_IFNAME, name);
    b.attr(IFLA_ADDRESS, &mac);
    b.attr_u32(IFLA_MTU, mtu);
    b.nest_begin(IFLA_LINKINFO);
    b.attr_str(IFLA_INFO_KIND, b"vxlan");
    b.nest_begin(IFLA_INFO_DATA);
    b.attr_u32(IFLA_VXLAN_ID, vni);
    b.attr(IFLA_VXLAN_LOCAL, &local);
    b.attr(IFLA_VXLAN_LEARNING, &[0]);
    b.attr(IFLA_VXLAN_PORT, &port.to_be_bytes());
    b.nest_end();
    b.nest_end();
    b.end();
    b
}

/// ARP entry (family AF_INET, `dst` -> `mac`) or FDB entry (AF_BRIDGE, `mac` -> remote `dst`),
/// both permanent.
fn neigh_msg(ty: u16, fdb: bool, ifindex: i32, dst: [u8; 4], mac: [u8; 6]) -> NlBuf {
    let mut b = NlBuf::new();
    let flags = if ty == RTM_NEWNEIGH { NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE } else { NLM_F_ACK };
    b.begin(ty, flags);
    // struct ndmsg: family, pad1, pad2, ifindex, state, flags, type
    let mut h = [0u8; 12];
    h[0] = if fdb { AF_BRIDGE } else { AF_INET };
    h[4..8].copy_from_slice(&ifindex.to_ne_bytes());
    h[8..10].copy_from_slice(&NUD_PERMANENT.to_ne_bytes());
    h[10] = if fdb { NTF_SELF } else { 0 };
    b.raw(&h);
    b.attr(NDA_DST, &dst);
    b.attr(NDA_LLADDR, &mac);
    b.end();
    b
}

/// Parses an ndmsg payload: (ifindex, state, dst, mac) of IPv4-destination entries of `family`.
fn parse_neigh(m: &[u8], family: u8) -> Option<(i32, u16, [u8; 4], [u8; 6])> {
    if m.len() < 12 || m[0] != family {
        return None;
    }
    let ifindex = i32::from_ne_bytes(m[4..8].try_into().unwrap());
    let state = u16::from_ne_bytes([m[8], m[9]]);
    let (mut dst, mut mac) = (None, None);
    let mut o = 12;
    while o + 4 <= m.len() {
        let l = u16::from_ne_bytes([m[o], m[o + 1]]) as usize;
        let t = u16::from_ne_bytes([m[o + 2], m[o + 3]]) & 0x3fff;
        if l < 4 || o + l > m.len() {
            break;
        }
        if l == 8 && t == NDA_DST {
            dst = Some([m[o + 4], m[o + 5], m[o + 6], m[o + 7]]);
        } else if l == 10 && t == NDA_LLADDR {
            mac = Some([m[o + 4], m[o + 5], m[o + 6], m[o + 7], m[o + 8], m[o + 9]]);
        }
        o += align4(l);
    }
    Some((ifindex, state, dst?, mac?))
}

impl Netlink {
    /// Creates the VXLAN device; EEXIST when present.
    pub fn vxlan_add(&self, name: &[u8], vni: u32, port: u16, local: [u8; 4], mtu: u32, mac: [u8; 6]) -> Result<(), Errno> {
        self.transact(&vxlan_msg(name, vni, port, local, mtu, mac))
    }

    /// Adds (or replaces) a permanent ARP entry `ip` -> `mac` on `ifindex`.
    pub fn neigh_add(&self, ifindex: i32, ip: [u8; 4], mac: [u8; 6]) -> Result<(), Errno> {
        self.transact(&neigh_msg(RTM_NEWNEIGH, false, ifindex, ip, mac))
    }

    /// Adds (or replaces) a permanent IPv6 neighbour entry `ip` -> `mac` on `ifindex`.
    pub fn neigh_add6(&self, ifindex: i32, ip: [u8; 16], mac: [u8; 6]) -> Result<(), Errno> {
        let mut b = NlBuf::new();
        b.begin(RTM_NEWNEIGH, NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE);
        let mut h = [0u8; 12];
        h[0] = AF_INET6;
        h[4..8].copy_from_slice(&ifindex.to_ne_bytes());
        h[8..10].copy_from_slice(&NUD_PERMANENT.to_ne_bytes());
        b.raw(&h);
        b.attr(NDA_DST, &ip);
        b.attr(NDA_LLADDR, &mac);
        b.end();
        self.transact(&b)
    }

    /// Adds or replaces an IPv6 route `dst/prefix` via `gateway` on `oif` with RTNH_F_ONLINK
    /// (the gateway is a VXLAN peer's VTEP address, covered by no connected route).
    pub fn route_replace6_onlink(&self, dst: [u8; 16], prefix: u8, gateway: [u8; 16], oif: i32, proto: u8) -> Result<(), Errno> {
        self.one(|b| {
            b.begin(RTM_NEWROUTE, NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE);
            b.raw(&[AF_INET6, prefix, 0, 0, 254, proto, 0, 1, RTNH_F_ONLINK, 0, 0, 0]);
            b.attr(RTA_DST, &dst);
            b.attr(RTA_GATEWAY, &gateway);
            b.attr_u32(RTA_OIF, oif as u32);
        })
    }

    pub fn neigh_del(&self, ifindex: i32, ip: [u8; 4], mac: [u8; 6]) -> Result<(), Errno> {
        self.transact(&neigh_msg(RTM_DELNEIGH, false, ifindex, ip, mac))
    }

    /// Removes the (any state) ARP entry for `ip` on `ifindex`; ENOENT when there is none.
    pub fn neigh_flush(&self, ifindex: i32, ip: [u8; 4]) -> Result<(), Errno> {
        self.one(|b| {
            b.begin(RTM_DELNEIGH, NLM_F_ACK);
            let mut h = [0u8; 12];
            h[0] = AF_INET;
            h[4..8].copy_from_slice(&ifindex.to_ne_bytes());
            b.raw(&h);
            b.attr(NDA_DST, &ip);
        })
    }

    /// Adds (or replaces) a forwarding entry: frames for `mac` go to the VTEP at `dst`.
    pub fn fdb_add(&self, ifindex: i32, mac: [u8; 6], dst: [u8; 4]) -> Result<(), Errno> {
        self.transact(&neigh_msg(RTM_NEWNEIGH, true, ifindex, dst, mac))
    }

    pub fn fdb_del(&self, ifindex: i32, mac: [u8; 6], dst: [u8; 4]) -> Result<(), Errno> {
        self.transact(&neigh_msg(RTM_DELNEIGH, true, ifindex, dst, mac))
    }

    /// Permanent ARP entries on `ifindex` as (ip, mac).
    pub fn neighs(&self, ifindex: i32) -> Result<Vec<([u8; 4], [u8; 6])>, Errno> {
        Ok(self.dump_neigh(AF_INET)?.into_iter().filter(|e| e.0 == ifindex && e.1 & NUD_PERMANENT != 0).map(|e| (e.2, e.3)).collect())
    }

    /// FDB entries with a remote destination on `ifindex` as (mac, dst).
    pub fn fdbs(&self, ifindex: i32) -> Result<Vec<([u8; 6], [u8; 4])>, Errno> {
        Ok(self.dump_neigh(AF_BRIDGE)?.into_iter().filter(|e| e.0 == ifindex).map(|e| (e.3, e.2)).collect())
    }

    fn dump_neigh(&self, family: u8) -> Result<Vec<(i32, u16, [u8; 4], [u8; 6])>, Errno> {
        let mut b = NlBuf::new();
        b.begin(RTM_GETNEIGH, NLM_F_DUMP);
        let mut h = [0u8; 12];
        h[0] = family;
        b.raw(&h);
        b.end();
        let n = kr_sys::write(self.fd.raw(), b.bytes())?;
        if n != b.bytes().len() {
            return Err(Errno(5));
        }
        let mut out = Vec::new();
        let mut buf = alloc::vec![0u8; 32 * 1024];
        loop {
            let n = match kr_sys::read(self.fd.raw(), &mut buf) {
                Err(Errno(4)) => continue,
                r => r?,
            };
            let mut off = 0;
            while off + 16 <= n {
                let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
                let ty = u16::from_ne_bytes([buf[off + 4], buf[off + 5]]);
                if len < 16 || off + len > n {
                    return Err(Errno(74));
                }
                match ty {
                    NLMSG_DONE => return Ok(out),
                    NLMSG_ERROR => return Err(Errno(5)),
                    RTM_NEWNEIGH => {
                        if let Some(r) = parse_neigh(&buf[off + 16..off + len], family) {
                            out.push(r);
                        }
                    }
                    _ => {}
                }
                off += align4(len);
            }
        }
    }

    /// A route via `gateway` on `oif` with RTNH_F_ONLINK: the gateway is reachable on the
    /// link without a covering connected route (VXLAN peers' VTEP addresses).
    pub fn route_add_onlink(&self, dst: [u8; 4], prefix: u8, gateway: [u8; 4], oif: i32, proto: u8) -> Result<(), Errno> {
        self.one(|b| {
            b.begin(RTM_NEWROUTE, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
            b.raw(&[AF_INET, prefix, 0, 0, 254, proto, 0, 1, RTNH_F_ONLINK, 0, 0, 0]);
            b.attr(RTA_DST, &dst);
            b.attr(RTA_GATEWAY, &gateway);
            b.attr_u32(RTA_OIF, oif as u32);
        })
    }
}

/// Interface index by name (SIOCGIFINDEX).
pub fn ifindex(name: &[u8]) -> Result<i32, Errno> {
    kr_sys::ns::ifindex(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_route_filters_by_proto() {
        let mut m = alloc::vec![AF_INET, 24, 0, 0, 254, RTPROT_KR, 0, 1, 0, 0, 0, 0];
        m.extend_from_slice(&[8, 0, 1, 0, 10, 88, 1, 0]); // RTA_DST
        m.extend_from_slice(&[8, 0, 5, 0, 192, 168, 0, 2]); // RTA_GATEWAY
        assert_eq!(parse_route(&m, RTPROT_KR), Some(([10, 88, 1, 0], 24, Some([192, 168, 0, 2]))));
        assert_eq!(parse_route(&m, 3), None);
        m[4] = 255; // other table
        assert_eq!(parse_route(&m, RTPROT_KR), None);
    }

    #[test]
    fn vxlan_link_encoding() {
        let b = vxlan_msg(b"kr.vxlan", 1, 8472, [192, 168, 0, 2], 1450, vtep_mac([192, 168, 0, 2]));
        let m = b.bytes();
        assert_eq!(u16::from_ne_bytes([m[4], m[5]]), RTM_NEWLINK);
        assert_eq!(u32::from_ne_bytes(m[0..4].try_into().unwrap()) as usize, m.len());
        let has = |needle: &[u8]| m.windows(needle.len()).any(|w| w == needle);
        assert!(has(b"vxlan\0"));
        assert!(has(&[8, 0, IFLA_VXLAN_ID as u8, 0, 1, 0, 0, 0]));
        assert!(has(&[8, 0, IFLA_VXLAN_LOCAL as u8, 0, 192, 168, 0, 2]));
        assert!(has(&[5, 0, IFLA_VXLAN_LEARNING as u8, 0, 0])); // nolearning
        assert!(has(&[6, 0, IFLA_VXLAN_PORT as u8, 0, 0x21, 0x18])); // 8472 big-endian
        assert!(has(&[8, 0, IFLA_MTU as u8, 0, 0xaa, 0x05, 0, 0]));
        assert!(has(&[10, 0, 1, 0, 0x02, 0x4b, 192, 168, 0, 2]));
    }

    #[test]
    fn neigh_and_fdb_encoding() {
        let mac = [2, 0x4b, 10, 0, 0, 3];
        let n = neigh_msg(RTM_NEWNEIGH, false, 7, [10, 88, 2, 0], mac);
        let m = n.bytes();
        assert_eq!((m[16], i32::from_ne_bytes(m[20..24].try_into().unwrap())), (AF_INET, 7));
        assert_eq!(u16::from_ne_bytes([m[24], m[25]]), NUD_PERMANENT);
        assert_eq!(m[26], 0);
        let f = neigh_msg(RTM_NEWNEIGH, true, 7, [10, 0, 0, 3], mac);
        let m = f.bytes();
        assert_eq!((m[16], m[26]), (AF_BRIDGE, NTF_SELF));
        assert_eq!(&m[28..36], &[8, 0, 1, 0, 10, 0, 0, 3]); // NDA_DST
        assert_eq!(&m[36..42], &[10, 0, 2, 0, 2, 0x4b]); // NDA_LLADDR header
        assert_eq!(parse_neigh(&m[16..], AF_BRIDGE), Some((7, NUD_PERMANENT, [10, 0, 0, 3], mac)));
        assert_eq!(parse_neigh(&m[16..], AF_INET), None);
    }

    #[test]
    fn mac_text() {
        let m = vtep_mac([10, 0, 0, 3]);
        assert_eq!(mac_string(m), "02:4b:0a:00:00:03");
        assert_eq!(parse_mac("02:4b:0a:00:00:03"), Some(m));
        assert_eq!(parse_mac("02:4b:0a:00:00"), None);
    }

    #[test]
    fn builder_lengths_and_nesting() {
        let mut b = NlBuf::new();
        b.begin(RTM_NEWLINK, NLM_F_ACK);
        b.raw(&ifinfo(0, 0, 0));
        b.nest_begin(IFLA_LINKINFO);
        b.attr_str(IFLA_INFO_KIND, b"veth"); // 4 + 5 -> padded to 12
        b.nest_end();
        b.end();
        let m = b.bytes();
        assert_eq!(m.len(), 16 + 16 + 4 + 12);
        assert_eq!(u32::from_ne_bytes(m[0..4].try_into().unwrap()) as usize, m.len());
        assert_eq!(u16::from_ne_bytes([m[32], m[33]]), 16); // nest len
        assert_eq!(u16::from_ne_bytes([m[34], m[35]]), IFLA_LINKINFO | NLA_F_NESTED);
        assert_eq!(u16::from_ne_bytes([m[36], m[37]]), 9); // attr len excludes padding
        assert_eq!(b.acks, 1);
    }

    #[test]
    fn multiple_messages_in_one_buffer() {
        let mut b = NlBuf::new();
        b.begin(0x10, 0);
        b.raw(&[0, 0, 0, 0]);
        b.end();
        b.begin(RTM_NEWLINK, NLM_F_ACK);
        b.end();
        assert_eq!(b.bytes().len(), 20 + 16);
        assert_eq!(b.acks, 1);
        // sequence numbers increase
        assert_eq!(u32::from_ne_bytes(b.bytes()[8..12].try_into().unwrap()), 1);
        assert_eq!(u32::from_ne_bytes(b.bytes()[28..32].try_into().unwrap()), 2);
    }
}
