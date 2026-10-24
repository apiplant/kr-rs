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
    pub fn veth_add(&self, host: &[u8], peer: &[u8], peer_pid: i32) -> Result<(), Errno> {
        self.one(|b| {
            b.begin(RTM_NEWLINK, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
            b.raw(&ifinfo(0, 0, 0));
            b.attr_str(IFLA_IFNAME, host);
            b.nest_begin(IFLA_LINKINFO);
            b.attr_str(IFLA_INFO_KIND, b"veth");
            b.nest_begin(IFLA_INFO_DATA);
            b.nest_begin(VETH_INFO_PEER);
            b.raw(&ifinfo(0, 0, 0));
            b.attr_str(IFLA_IFNAME, peer);
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
