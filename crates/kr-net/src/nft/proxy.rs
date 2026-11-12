//! The Service datapath in the kernel (kube-proxy's nftables mode, ADR-054): one table
//! `inet kr-proxy`, replaced atomically whenever the Services or their endpoints change.
//!
//! Traffic to a ClusterIP, a NodePort, an external or load balancer address, or a hostPort is
//! DNAT'd to one ready endpoint in the `prerouting` (pods) and `output` (the host itself) hooks, so
//! the connection keeps its client address: NetworkPolicy sees the real client, source IPs reach
//! the backends, and established connections survive a kubelet restart (conntrack holds the NAT).
//! Only traffic that would not find its way back is masqueraded (clients outside the pod network
//! reaching a NodePort, a pod reaching itself through a Service).
//!
//! Layout: chain `services` holds one rule per frontend and jumps to the service's chain;
//! a service chain picks an endpoint with `numgen random` (rule `j` of `K` fires with probability
//! `1/(K-j)`, so the choice is uniform) or, with ClientIP affinity, `jhash(saddr) mod K`; an
//! endpoint chain does the DNAT. A Service port without ready endpoints gets no rule: the packet
//! reaches the node's own stack, which refuses it (the ClusterIP range is a local route).

use super::*;

pub const PROXY_TABLE: &[u8] = b"kr-proxy";
/// The packet mark that asks the `postrouting` chain to masquerade.
pub const MASQ_MARK: u32 = 0x4000;

const NFT_META_MARK: u32 = 3; // NFT_META_MARK
const NFT_MSG_DELCHAIN: u16 = 5; // NFT_MSG_DELCHAIN
const NFT_MSG_DELRULE: u16 = 8; // NFT_MSG_DELRULE
const NFTA_META_SREG: u16 = 3; // NFTA_META_SREG
const NFT_REG_2: u32 = 2; // NFT_REG_2
const NF_INET_PRE_ROUTING: u32 = 0; // NF_INET_PRE_ROUTING
const NF_INET_LOCAL_OUT: u32 = 3; // NF_INET_LOCAL_OUT
const NFPROTO_INET: u8 = 1; // NFPROTO_INET
const NFTA_NAT_TYPE: u16 = 1; // NFTA_NAT_TYPE
const NFTA_NAT_FAMILY: u16 = 2; // NFTA_NAT_FAMILY
const NFTA_NAT_REG_ADDR_MIN: u16 = 3; // NFTA_NAT_REG_ADDR_MIN
const NFTA_NAT_REG_PROTO_MIN: u16 = 5; // NFTA_NAT_REG_PROTO_MIN
const NFTA_NAT_FLAGS: u16 = 7; // NFTA_NAT_FLAGS
const NFT_NAT_DNAT: u32 = 1; // NFT_NAT_DNAT
/// NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED.
const NAT_RANGE: u32 = 3;
const NFTA_NG_DREG: u16 = 1; // NFTA_NG_DREG
const NFTA_NG_MODULUS: u16 = 2; // NFTA_NG_MODULUS
const NFTA_NG_TYPE: u16 = 3; // NFTA_NG_TYPE
const NFT_NG_RANDOM: u32 = 1; // NFT_NG_RANDOM
const NFTA_HASH_SREG: u16 = 1; // NFTA_HASH_SREG
const NFTA_HASH_DREG: u16 = 2; // NFTA_HASH_DREG
const NFTA_HASH_LEN: u16 = 3; // NFTA_HASH_LEN
const NFTA_HASH_MODULUS: u16 = 4; // NFTA_HASH_MODULUS
const NFTA_FIB_DREG: u16 = 1; // NFTA_FIB_DREG
const NFTA_FIB_RESULT: u16 = 2; // NFTA_FIB_RESULT
const NFTA_FIB_FLAGS: u16 = 3; // NFTA_FIB_FLAGS
const NFT_FIB_RESULT_ADDRTYPE: u32 = 3; // NFT_FIB_RESULT_ADDRTYPE
const NFTA_FIB_F_DADDR: u32 = 2; // NFTA_FIB_F_DADDR
const RTN_LOCAL: u32 = 2; // RTN_LOCAL
const NFT_PAYLOAD_TRANSPORT: u32 = 2; // NFT_PAYLOAD_TRANSPORT_HEADER

/// How traffic to a frontend is treated.
#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum Policy {
    /// ClusterIP, hostPort: DNAT only (the client address is kept).
    Plain,
    /// NodePort and external addresses with `externalTrafficPolicy: Cluster`: also masquerade
    /// clients outside the pod network (the reply must come back through this node).
    External,
    /// `externalTrafficPolicy: Local`: only endpoints on this node, no masquerade; dropped when there
    /// is none.
    ExternalLocal,
}

/// What a client connects to.
#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum Frontend {
    /// A specific destination address (16 bytes; IPv4 as `::ffff:a.b.c.d`).
    Addr { ip: [u8; 16], proto: u8, port: u16, policy: Policy },
    /// Any address of this host (`fib daddr type local`), or only `ip`, for NodePorts and hostPorts.
    Local { v6: bool, ip: Option<[u8; 16]>, proto: u8, port: u16, policy: Policy },
}

/// One endpoint (16 bytes; IPv4 as `::ffff:a.b.c.d`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub struct Backend {
    pub ip: [u8; 16],
    pub port: u16,
    /// The endpoint runs on this node.
    pub local: bool,
}

/// One Service port in one address family.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Svc {
    pub v6: bool,
    pub frontends: alloc::vec::Vec<Frontend>,
    pub backends: alloc::vec::Vec<Backend>,
    /// `sessionAffinity: ClientIP`: the same client address picks the same endpoint while the
    /// endpoint set is unchanged.
    pub affinity: bool,
}

/// Everything the table is built from.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Model {
    pub svcs: alloc::vec::Vec<Svc>,
    pub pod_net4: ([u8; 4], u8),
    pub pod_net6: ([u8; 16], u8),
}

fn unmap(ip: &[u8; 16]) -> Option<[u8; 4]> {
    if ip[..10] == [0; 10] && ip[10] == 0xff && ip[11] == 0xff {
        Some([ip[12], ip[13], ip[14], ip[15]])
    } else {
        None
    }
}

fn addr_bytes(ip: &[u8; 16], v6: bool) -> alloc::vec::Vec<u8> {
    if v6 {
        ip.to_vec()
    } else {
        unmap(ip).map(|a| a.to_vec()).unwrap_or_else(|| ip[12..].to_vec())
    }
}

// ---- message building (no per-message acks: a batch of thousands would overflow the reply buffer;
// errors are always reported, and one final acked message marks completion) ----

fn nmsg(b: &mut NlBuf, ty: u16, flags: u16) {
    msg(b, ty, flags, NFPROTO_INET, 0);
}

fn chain(b: &mut NlBuf, name: &str, base: Option<(&[u8], u32, u32)>) {
    nmsg(b, NFT_MSG_NEWCHAIN, NLM_F_CREATE);
    b.attr_str(NFTA_CHAIN_TABLE, PROXY_TABLE);
    b.attr_str(NFTA_CHAIN_NAME, name.as_bytes());
    if let Some((ty, hook, prio)) = base {
        b.nest_begin(NFTA_CHAIN_HOOK);
        b.attr_u32_be(NFTA_HOOK_HOOKNUM, hook);
        b.attr_u32_be(NFTA_HOOK_PRIORITY, prio);
        b.nest_end();
        b.attr_str(NFTA_CHAIN_TYPE, ty);
    }
    b.end();
}

fn add_rule(b: &mut NlBuf, chain: &str, exprs: impl FnOnce(&mut NlBuf)) {
    nmsg(b, NFT_MSG_NEWRULE, NLM_F_CREATE | NLM_F_APPEND);
    b.attr_str(NFTA_RULE_TABLE, PROXY_TABLE);
    b.attr_str(NFTA_RULE_CHAIN, chain.as_bytes());
    b.nest_begin(NFTA_RULE_EXPRESSIONS);
    exprs(b);
    b.nest_end();
    b.end();
}

fn jump(b: &mut NlBuf, chain: &str) {
    verdict(b, NFT_JUMP, Some(chain.as_bytes()));
}

fn immediate(b: &mut NlBuf, reg: u32, data: &[u8]) {
    expr_begin(b, b"immediate");
    b.attr_u32_be(NFTA_IMMEDIATE_DREG, reg);
    data_value(b, NFTA_IMMEDIATE_DATA, data);
    expr_end(b);
}

fn fam_guard(b: &mut NlBuf, v6: bool) {
    meta(b, NFT_META_NFPROTO);
    cmp(b, NFT_CMP_EQ, &[if v6 { NFPROTO_IPV6 } else { NFPROTO_IPV4 }]);
}

fn match_dest(b: &mut NlBuf, f: &Frontend) {
    let (v6, ip, proto, port) = match *f {
        Frontend::Addr { ip, proto, port, .. } => (unmap(&ip).is_none(), Some(ip), proto, port),
        Frontend::Local { v6, ip, proto, port, .. } => (v6, ip, proto, port),
    };
    fam_guard(b, v6);
    meta(b, NFT_META_L4PROTO);
    cmp(b, NFT_CMP_EQ, &[proto]);
    payload(b, NFT_PAYLOAD_TRANSPORT, 2, 2);
    cmp(b, NFT_CMP_EQ, &port.to_be_bytes());
    match (f, ip) {
        (Frontend::Addr { .. }, Some(ip)) | (Frontend::Local { .. }, Some(ip)) => {
            let a = addr_bytes(&ip, v6);
            payload(b, NFT_PAYLOAD_NETWORK_HEADER, if v6 { 24 } else { 16 }, a.len() as u32);
            cmp(b, NFT_CMP_EQ, &a);
        }
        _ => {}
    }
    if matches!(f, Frontend::Local { ip: None, .. }) {
        expr_begin(b, b"fib");
        b.attr_u32_be(NFTA_FIB_DREG, NFT_REG_1);
        b.attr_u32_be(NFTA_FIB_RESULT, NFT_FIB_RESULT_ADDRTYPE);
        b.attr_u32_be(NFTA_FIB_FLAGS, NFTA_FIB_F_DADDR);
        expr_end(b);
        cmp(b, NFT_CMP_EQ, &RTN_LOCAL.to_ne_bytes());
    }
}

fn policy_of(f: &Frontend) -> Policy {
    match f {
        Frontend::Addr { policy, .. } | Frontend::Local { policy, .. } => *policy,
    }
}

/// `mark = mark | MASQ_MARK`.
fn set_masq_mark(b: &mut NlBuf) {
    meta(b, NFT_META_MARK);
    expr_begin(b, b"bitwise");
    b.attr_u32_be(NFTA_BITWISE_SREG, NFT_REG_1);
    b.attr_u32_be(NFTA_BITWISE_DREG, NFT_REG_1);
    b.attr_u32_be(NFTA_BITWISE_LEN, 4);
    data_value(b, NFTA_BITWISE_MASK, &(!MASQ_MARK).to_ne_bytes());
    data_value(b, NFTA_BITWISE_XOR, &MASQ_MARK.to_ne_bytes());
    expr_end(b);
    expr_begin(b, b"meta");
    b.attr_u32_be(NFTA_META_KEY, NFT_META_MARK);
    b.attr_u32_be(NFTA_META_SREG, NFT_REG_1);
    expr_end(b);
}

/// Picks one of `targets` (chain names) uniformly, or by client address.
fn dispatch(b: &mut NlBuf, chain_name: &str, targets: &[alloc::string::String], v6: bool, affinity: bool) {
    let k = targets.len() as u32;
    for (j, t) in targets.iter().enumerate() {
        let last = j + 1 == targets.len();
        add_rule(b, chain_name, |b| {
            if !last {
                if affinity {
                    payload(b, NFT_PAYLOAD_NETWORK_HEADER, if v6 { 8 } else { 12 }, if v6 { 16 } else { 4 });
                    expr_begin(b, b"hash");
                    b.attr_u32_be(NFTA_HASH_SREG, NFT_REG_1);
                    b.attr_u32_be(NFTA_HASH_DREG, NFT_REG_1);
                    b.attr_u32_be(NFTA_HASH_LEN, if v6 { 16 } else { 4 });
                    b.attr_u32_be(NFTA_HASH_MODULUS, k);
                    expr_end(b);
                    cmp(b, NFT_CMP_EQ, &(j as u32).to_ne_bytes());
                } else {
                    expr_begin(b, b"numgen");
                    b.attr_u32_be(NFTA_NG_DREG, NFT_REG_1);
                    b.attr_u32_be(NFTA_NG_MODULUS, k - j as u32);
                    b.attr_u32_be(NFTA_NG_TYPE, NFT_NG_RANDOM);
                    expr_end(b);
                    cmp(b, NFT_CMP_EQ, &0u32.to_ne_bytes());
                }
            }
            jump(b, t);
        });
    }
}

fn dnat(b: &mut NlBuf, be: &Backend, v6: bool) {
    immediate(b, NFT_REG_1, &addr_bytes(&be.ip, v6));
    immediate(b, NFT_REG_2, &be.port.to_be_bytes());
    expr_begin(b, b"nat");
    b.attr_u32_be(NFTA_NAT_TYPE, NFT_NAT_DNAT);
    b.attr_u32_be(NFTA_NAT_FAMILY, if v6 { NFPROTO_IPV6 as u32 } else { NFPROTO_IPV4 as u32 });
    b.attr_u32_be(NFTA_NAT_REG_ADDR_MIN, NFT_REG_1);
    b.attr_u32_be(NFTA_NAT_REG_PROTO_MIN, NFT_REG_2);
    b.attr_u32_be(NFTA_NAT_FLAGS, NAT_RANGE);
    expr_end(b);
}

/// Bytes after which a batch is sent and a new one started (the kernel refuses a message larger
/// than the socket's send buffer, and the default is about 200 KB).
const CHUNK: usize = 128 * 1024;

fn begin() -> NlBuf {
    let mut b = NlBuf::new();
    batch_msg(&mut b, NFNL_MSG_BATCH_BEGIN);
    b
}

/// Ends the batch with one acknowledged message (when it comes back the batch is in) and sends it.
fn send(mut b: NlBuf, nl: &Netlink) -> Result<(), Errno> {
    nmsg(&mut b, NFT_MSG_NEWTABLE, NLM_F_CREATE | NLM_F_ACK);
    b.attr_str(NFTA_TABLE_NAME, PROXY_TABLE);
    b.end();
    batch_msg(&mut b, NFNL_MSG_BATCH_END);
    nl.transact(&b)
}

/// Table, base chains and the chain `services` (empty), replacing any older table.
fn reset(nl: &Netlink) -> Result<(), Errno> {
    let mut b = begin();
    // Create (a no-op when present), delete, create again: replaces the old table atomically.
    nmsg(&mut b, NFT_MSG_NEWTABLE, NLM_F_CREATE);
    b.attr_str(NFTA_TABLE_NAME, PROXY_TABLE);
    b.end();
    nmsg(&mut b, NFT_MSG_DELTABLE, 0);
    b.attr_str(NFTA_TABLE_NAME, PROXY_TABLE);
    b.end();
    nmsg(&mut b, NFT_MSG_NEWTABLE, NLM_F_CREATE | NLM_F_EXCL);
    b.attr_str(NFTA_TABLE_NAME, PROXY_TABLE);
    b.end();
    chain(&mut b, "prerouting", Some((b"nat", NF_INET_PRE_ROUTING, (-100i32) as u32)));
    chain(&mut b, "output", Some((b"nat", NF_INET_LOCAL_OUT, (-100i32) as u32)));
    chain(&mut b, "postrouting", Some((b"nat", NF_INET_POST_ROUTING, 100)));
    chain(&mut b, "services", None);
    add_rule(&mut b, "prerouting", |b| jump(b, "services"));
    add_rule(&mut b, "output", |b| jump(b, "services"));
    // Connections that asked for it are masqueraded when they leave.
    add_rule(&mut b, "postrouting", |b| {
        meta(b, NFT_META_MARK);
        bitwise_and(b, &MASQ_MARK.to_ne_bytes());
        cmp(b, NFT_CMP_NEQ, &[0u8; 4]);
        expr_begin(b, b"masq");
        expr_end(b);
    });
    send(b, nl)
}

fn ep_names(g: u32, i: usize, s: &Svc) -> alloc::vec::Vec<alloc::string::String> {
    (0..s.backends.len()).map(|j| alloc::format!("g{g}e{i}_{j}")).collect()
}

fn live(s: &Svc) -> bool {
    !s.backends.is_empty() && !s.frontends.is_empty()
}

fn wants(s: &Svc, p: Policy) -> bool {
    s.frontends.iter().any(|f| policy_of(f) == p)
}

/// Adds the chains and rules of service `i` to generation `g` (rules in `g<g>services`).
fn emit_service(b: &mut NlBuf, g: u32, i: usize, s: &Svc, m: &Model) {
    let v6 = s.v6;
    let eps = ep_names(g, i, s);
    for (j, be) in s.backends.iter().enumerate() {
        chain(b, &eps[j], None);
        let a = addr_bytes(&be.ip, v6);
        // A client that is the endpoint itself (a pod reaching its own Service) would be
        // answered directly and the reply dropped by its own stack: masquerade it.
        add_rule(b, &eps[j], |b| {
            payload(b, NFT_PAYLOAD_NETWORK_HEADER, if v6 { 8 } else { 12 }, a.len() as u32);
            cmp(b, NFT_CMP_EQ, &a);
            set_masq_mark(b);
        });
        add_rule(b, &eps[j], |b| dnat(b, be, v6));
    }
    let name = alloc::format!("g{g}s{i}");
    chain(b, &name, None);
    dispatch(b, &name, &eps, v6, s.affinity);
    // The same for the endpoints on this node only (`externalTrafficPolicy: Local`).
    let lname = alloc::format!("g{g}l{i}");
    if wants(s, Policy::ExternalLocal) {
        let local: alloc::vec::Vec<alloc::string::String> = s.backends.iter().enumerate().filter(|(_, be)| be.local).map(|(j, _)| eps[j].clone()).collect();
        chain(b, &lname, None);
        if local.is_empty() {
            add_rule(b, &lname, |b| verdict(b, NF_DROP, None));
        } else {
            dispatch(b, &lname, &local, v6, s.affinity);
        }
    }
    // Traffic from outside the pod network must come back through this node.
    let xname = alloc::format!("g{g}x{i}");
    if wants(s, Policy::External) {
        chain(b, &xname, None);
        let (net, plen) = if v6 { (m.pod_net6.0.to_vec(), m.pod_net6.1) } else { (m.pod_net4.0.to_vec(), m.pod_net4.1) };
        add_rule(b, &xname, |b| {
            payload(b, NFT_PAYLOAD_NETWORK_HEADER, if v6 { 8 } else { 12 }, net.len() as u32);
            let mask = mask_of(plen, net.len());
            bitwise_and(b, &mask);
            let masked: alloc::vec::Vec<u8> = net.iter().zip(&mask).map(|(a, m)| a & m).collect();
            cmp(b, NFT_CMP_NEQ, &masked);
            set_masq_mark(b);
        });
        add_rule(b, &xname, |b| jump(b, &name));
    }
    let services = alloc::format!("g{g}services");
    for f in &s.frontends {
        let target = match policy_of(f) {
            Policy::Plain => &name,
            Policy::External => &xname,
            Policy::ExternalLocal => &lname,
        };
        add_rule(b, &services, |b| {
            match_dest(b, f);
            jump(b, target);
        });
    }
}

/// Every chain name generation `g` of `m` has, rules first (`flush`) and then deletable.
fn chain_names(g: u32, m: &Model) -> alloc::vec::Vec<alloc::string::String> {
    let mut v = alloc::vec![alloc::format!("g{g}services")];
    for (i, s) in m.svcs.iter().enumerate().filter(|(_, s)| live(s)) {
        v.extend(ep_names(g, i, s));
        v.push(alloc::format!("g{g}s{i}"));
        if wants(s, Policy::ExternalLocal) {
            v.push(alloc::format!("g{g}l{i}"));
        }
        if wants(s, Policy::External) {
            v.push(alloc::format!("g{g}x{i}"));
        }
    }
    v
}

/// The Service datapath of one node: remembers the generation in the kernel.
#[derive(Default)]
pub struct Datapath {
    gen: u32,
    ready: bool,
    cur: Option<Model>,
}

impl Datapath {
    pub fn new() -> Datapath {
        Datapath::default()
    }

    /// Makes the kernel's rules those of `m`. The new rules are added next to the old ones in
    /// batches of a bounded size, one small batch points the `services` chain at them, and the old
    /// ones are removed: traffic never sees a half-built table, and a Service table of any size
    /// fits whatever the socket buffer. After an error the next call starts from scratch.
    pub fn apply(&mut self, m: &Model) -> Result<(), Errno> {
        if self.ready && self.cur.as_ref() == Some(m) {
            return Ok(());
        }
        let r = self.apply_inner(m);
        if r.is_err() {
            self.ready = false;
            self.cur = None;
        }
        r
    }

    fn apply_inner(&mut self, m: &Model) -> Result<(), Errno> {
        let nl = Netlink::open(NETLINK_NETFILTER)?;
        nl.grow_buffers(2 * CHUNK);
        if !self.ready {
            reset(&nl)?;
            self.ready = true;
            self.cur = None;
            self.gen = 0;
        }
        let g = self.gen + 1;
        // 1. The new generation.
        let services = alloc::format!("g{g}services");
        let mut b = begin();
        chain(&mut b, &services, None);
        for (i, s) in m.svcs.iter().enumerate().filter(|(_, s)| live(s)) {
            emit_service(&mut b, g, i, s, m);
            if b.bytes().len() > CHUNK {
                send(core::mem::replace(&mut b, begin()), &nl)?;
            }
        }
        send(b, &nl)?;
        // 2. The switch: `services` jumps to the new generation, in one transaction.
        let mut b = begin();
        nmsg(&mut b, NFT_MSG_DELRULE, 0);
        b.attr_str(NFTA_RULE_TABLE, PROXY_TABLE);
        b.attr_str(NFTA_RULE_CHAIN, b"services");
        b.end();
        add_rule(&mut b, "services", |b| jump(b, &services));
        send(b, &nl)?;
        // 3. The old generation (unreferenced now): empty every chain, then delete them.
        if let Some(old) = self.cur.take() {
            let names = chain_names(self.gen, &old);
            for del in [false, true] {
                let mut b = begin();
                for n in &names {
                    if del {
                        nmsg(&mut b, NFT_MSG_DELCHAIN, 0);
                        b.attr_str(NFTA_CHAIN_TABLE, PROXY_TABLE);
                        b.attr_str(NFTA_CHAIN_NAME, n.as_bytes());
                    } else {
                        nmsg(&mut b, NFT_MSG_DELRULE, 0);
                        b.attr_str(NFTA_RULE_TABLE, PROXY_TABLE);
                        b.attr_str(NFTA_RULE_CHAIN, n.as_bytes());
                    }
                    b.end();
                    if b.bytes().len() > CHUNK {
                        send(core::mem::replace(&mut b, begin()), &nl)?;
                    }
                }
                send(b, &nl)?;
            }
        }
        self.gen = g;
        self.cur = Some(m.clone());
        Ok(())
    }
}

/// Removes table `inet kr-proxy` (a missing table is success).
pub fn delete() -> Result<(), Errno> {
    let mut b = NlBuf::new();
    batch_msg(&mut b, NFNL_MSG_BATCH_BEGIN);
    nmsg(&mut b, NFT_MSG_DELTABLE, NLM_F_ACK);
    b.attr_str(NFTA_TABLE_NAME, PROXY_TABLE);
    b.end();
    batch_msg(&mut b, NFNL_MSG_BATCH_END);
    match Netlink::open(NETLINK_NETFILTER)?.transact(&b) {
        Err(Errno(2)) => Ok(()),
        r => r,
    }
}
