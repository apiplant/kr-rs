//! nftables over NETLINK_NETFILTER (no `nft` binary): the NAT + forward rules the container
//! bridge needs, programmed as one atomic batch.
//!
//! Constants come from `linux/netfilter/nf_tables.h` and `nfnetlink.h`; each carries the uapi name.

use crate::netlink::{NlBuf, Netlink, NETLINK_NETFILTER, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL};
use kr_sys::Errno;

/// NLM_F_APPEND: add the rule at the end of the chain (keeps rule order).
const NLM_F_APPEND: u16 = 0x800;

const NFNL_SUBSYS_NFTABLES: u16 = 10; // NFNL_SUBSYS_NFTABLES
const NFNL_MSG_BATCH_BEGIN: u16 = 0x10; // NFNL_MSG_BATCH_BEGIN (NLMSG_MIN_TYPE)
const NFNL_MSG_BATCH_END: u16 = 0x11; // NFNL_MSG_BATCH_END (NLMSG_MIN_TYPE + 1)
const NFPROTO_UNSPEC: u8 = 0; // NFPROTO_UNSPEC (batch messages)
const NFPROTO_IPV4: u8 = 2; // NFPROTO_IPV4

const NFT_MSG_NEWTABLE: u16 = 0; // NFT_MSG_NEWTABLE
const NFT_MSG_DELTABLE: u16 = 2; // NFT_MSG_DELTABLE
const NFT_MSG_NEWCHAIN: u16 = 3; // NFT_MSG_NEWCHAIN
const NFT_MSG_NEWRULE: u16 = 6; // NFT_MSG_NEWRULE

const NFTA_TABLE_NAME: u16 = 1; // NFTA_TABLE_NAME
const NFTA_CHAIN_TABLE: u16 = 1; // NFTA_CHAIN_TABLE
const NFTA_CHAIN_NAME: u16 = 3; // NFTA_CHAIN_NAME
const NFTA_CHAIN_HOOK: u16 = 4; // NFTA_CHAIN_HOOK
const NFTA_CHAIN_TYPE: u16 = 7; // NFTA_CHAIN_TYPE
const NFTA_HOOK_HOOKNUM: u16 = 1; // NFTA_HOOK_HOOKNUM
const NFTA_HOOK_PRIORITY: u16 = 2; // NFTA_HOOK_PRIORITY
const NF_INET_FORWARD: u32 = 2; // NF_INET_FORWARD
const NF_INET_POST_ROUTING: u32 = 4; // NF_INET_POST_ROUTING

const NFTA_RULE_TABLE: u16 = 1; // NFTA_RULE_TABLE
const NFTA_RULE_CHAIN: u16 = 2; // NFTA_RULE_CHAIN
const NFTA_RULE_EXPRESSIONS: u16 = 4; // NFTA_RULE_EXPRESSIONS
const NFTA_LIST_ELEM: u16 = 1; // NFTA_LIST_ELEM
const NFTA_EXPR_NAME: u16 = 1; // NFTA_EXPR_NAME
const NFTA_EXPR_DATA: u16 = 2; // NFTA_EXPR_DATA
const NFTA_DATA_VALUE: u16 = 1; // NFTA_DATA_VALUE
const NFTA_DATA_VERDICT: u16 = 2; // NFTA_DATA_VERDICT
const NFTA_VERDICT_CODE: u16 = 1; // NFTA_VERDICT_CODE

const NFTA_META_DREG: u16 = 1; // NFTA_META_DREG
const NFTA_META_KEY: u16 = 2; // NFTA_META_KEY
const NFT_META_IIFNAME: u32 = 6; // NFT_META_IIFNAME
const NFT_META_OIFNAME: u32 = 7; // NFT_META_OIFNAME
const NFTA_CMP_SREG: u16 = 1; // NFTA_CMP_SREG
const NFTA_CMP_OP: u16 = 2; // NFTA_CMP_OP
const NFTA_CMP_DATA: u16 = 3; // NFTA_CMP_DATA
const NFT_CMP_EQ: u32 = 0; // NFT_CMP_EQ
const NFT_CMP_NEQ: u32 = 1; // NFT_CMP_NEQ
const NFTA_PAYLOAD_DREG: u16 = 1; // NFTA_PAYLOAD_DREG
const NFTA_PAYLOAD_BASE: u16 = 2; // NFTA_PAYLOAD_BASE
const NFTA_PAYLOAD_OFFSET: u16 = 3; // NFTA_PAYLOAD_OFFSET
const NFTA_PAYLOAD_LEN: u16 = 4; // NFTA_PAYLOAD_LEN
const NFT_PAYLOAD_NETWORK_HEADER: u32 = 1; // NFT_PAYLOAD_NETWORK_HEADER
const NFTA_BITWISE_SREG: u16 = 1; // NFTA_BITWISE_SREG
const NFTA_BITWISE_DREG: u16 = 2; // NFTA_BITWISE_DREG
const NFTA_BITWISE_LEN: u16 = 3; // NFTA_BITWISE_LEN
const NFTA_BITWISE_MASK: u16 = 4; // NFTA_BITWISE_MASK
const NFTA_BITWISE_XOR: u16 = 5; // NFTA_BITWISE_XOR
const NFTA_CT_DREG: u16 = 1; // NFTA_CT_DREG
const NFTA_CT_KEY: u16 = 2; // NFTA_CT_KEY
const NFT_CT_STATE: u32 = 0; // NFT_CT_STATE
const NFTA_IMMEDIATE_DREG: u16 = 1; // NFTA_IMMEDIATE_DREG
const NFTA_IMMEDIATE_DATA: u16 = 2; // NFTA_IMMEDIATE_DATA
const NFT_REG_VERDICT: u32 = 0; // NFT_REG_VERDICT
const NFT_REG_1: u32 = 1; // NFT_REG_1
const NF_ACCEPT: u32 = 1; // NF_ACCEPT (netfilter.h)
/// NF_CT_STATE_BIT(IP_CT_ESTABLISHED) | NF_CT_STATE_BIT(IP_CT_RELATED) = (1<<1) | (1<<2).
const CT_ESTABLISHED_RELATED: u32 = 0x6;
const IFNAMSIZ: usize = 16; // IFNAMSIZ

/// Parameters of the container-bridge NAT table.
pub struct Masquerade<'a> {
    /// Table name (family `ip`).
    pub table: &'a [u8],
    /// Container network address.
    pub cidr: [u8; 4],
    /// Container network prefix length (0..=32).
    pub prefix: u8,
    /// Bridge interface name.
    pub bridge: &'a [u8],
}

/// Starts an nftables message: type, flags and nfgenmsg {family, version 0, res_id BE}.
fn msg(b: &mut NlBuf, ty: u16, flags: u16, family: u8, res_id: u16) {
    b.begin((NFNL_SUBSYS_NFTABLES << 8) | ty, flags);
    let r = res_id.to_be_bytes();
    b.raw(&[family, 0, r[0], r[1]]);
}

/// Batch begin/end: raw type (not shifted), res_id = NFNL_SUBSYS_NFTABLES.
fn batch_msg(b: &mut NlBuf, ty: u16) {
    b.begin(ty, 0);
    let r = NFNL_SUBSYS_NFTABLES.to_be_bytes();
    b.raw(&[NFPROTO_UNSPEC, 0, r[0], r[1]]);
    b.end();
}

/// NUL-padded 16-byte interface name as the kernel compares it.
fn ifname(name: &[u8]) -> [u8; IFNAMSIZ] {
    let mut v = [0u8; IFNAMSIZ];
    let n = name.len().min(IFNAMSIZ - 1);
    v[..n].copy_from_slice(&name[..n]);
    v
}

fn new_table(b: &mut NlBuf, table: &[u8], flags: u16) {
    msg(b, NFT_MSG_NEWTABLE, flags, NFPROTO_IPV4, 0);
    b.attr_str(NFTA_TABLE_NAME, table);
    b.end();
}

fn new_chain(b: &mut NlBuf, table: &[u8], name: &[u8], ty: &[u8], hook: u32, prio: u32) {
    msg(b, NFT_MSG_NEWCHAIN, NLM_F_ACK | NLM_F_CREATE, NFPROTO_IPV4, 0);
    b.attr_str(NFTA_CHAIN_TABLE, table);
    b.attr_str(NFTA_CHAIN_NAME, name);
    b.nest_begin(NFTA_CHAIN_HOOK);
    b.attr_u32_be(NFTA_HOOK_HOOKNUM, hook);
    b.attr_u32_be(NFTA_HOOK_PRIORITY, prio);
    b.nest_end();
    b.attr_str(NFTA_CHAIN_TYPE, ty);
    b.end();
}

/// Opens an expression element (`name` + nested data); close with `expr_end`.
fn expr_begin(b: &mut NlBuf, name: &[u8]) {
    b.nest_begin(NFTA_LIST_ELEM);
    b.attr_str(NFTA_EXPR_NAME, name);
    b.nest_begin(NFTA_EXPR_DATA);
}

fn expr_end(b: &mut NlBuf) {
    b.nest_end();
    b.nest_end();
}

fn data_value(b: &mut NlBuf, ty: u16, v: &[u8]) {
    b.nest_begin(ty);
    b.attr(NFTA_DATA_VALUE, v);
    b.nest_end();
}

/// `meta load <key> => reg1`.
fn meta(b: &mut NlBuf, key: u32) {
    expr_begin(b, b"meta");
    b.attr_u32_be(NFTA_META_DREG, NFT_REG_1);
    b.attr_u32_be(NFTA_META_KEY, key);
    expr_end(b);
}

/// `cmp <op> reg1, data`.
fn cmp(b: &mut NlBuf, op: u32, data: &[u8]) {
    expr_begin(b, b"cmp");
    b.attr_u32_be(NFTA_CMP_SREG, NFT_REG_1);
    b.attr_u32_be(NFTA_CMP_OP, op);
    data_value(b, NFTA_CMP_DATA, data);
    expr_end(b);
}

/// `reg1 = reg1 & mask` over `mask.len()` bytes (xor is zero).
fn bitwise_and(b: &mut NlBuf, mask: &[u8]) {
    expr_begin(b, b"bitwise");
    b.attr_u32_be(NFTA_BITWISE_SREG, NFT_REG_1);
    b.attr_u32_be(NFTA_BITWISE_DREG, NFT_REG_1);
    b.attr_u32_be(NFTA_BITWISE_LEN, mask.len() as u32);
    data_value(b, NFTA_BITWISE_MASK, mask);
    data_value(b, NFTA_BITWISE_XOR, &alloc::vec![0u8; mask.len()]);
    expr_end(b);
}

fn verdict_accept(b: &mut NlBuf) {
    expr_begin(b, b"immediate");
    b.attr_u32_be(NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
    b.nest_begin(NFTA_IMMEDIATE_DATA);
    b.nest_begin(NFTA_DATA_VERDICT);
    b.attr_u32_be(NFTA_VERDICT_CODE, NF_ACCEPT);
    b.nest_end();
    b.nest_end();
    expr_end(b);
}

/// Appends a rule to `chain`; `exprs` writes the expression list.
fn rule(b: &mut NlBuf, table: &[u8], chain: &[u8], exprs: impl FnOnce(&mut NlBuf)) {
    msg(b, NFT_MSG_NEWRULE, NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND, NFPROTO_IPV4, 0);
    b.attr_str(NFTA_RULE_TABLE, table);
    b.attr_str(NFTA_RULE_CHAIN, chain);
    b.nest_begin(NFTA_RULE_EXPRESSIONS);
    exprs(b);
    b.nest_end();
    b.end();
}

/// Netmask for a prefix length (clamped to 32).
fn netmask(prefix: u8) -> [u8; 4] {
    let p = prefix.min(32) as u32;
    (if p == 0 { 0u32 } else { u32::MAX << (32 - p) }).to_be_bytes()
}

/// Builds the whole idempotent batch for `m`.
fn masquerade_batch(m: &Masquerade) -> NlBuf {
    let mask = netmask(m.prefix);
    let mut net = [0u8; 4];
    for i in 0..4 {
        net[i] = m.cidr[i] & mask[i];
    }
    let bridge = ifname(m.bridge);
    let mut b = NlBuf::new();
    batch_msg(&mut b, NFNL_MSG_BATCH_BEGIN);
    // Create (no-op if present), delete, create again: atomically replaces any old table.
    new_table(&mut b, m.table, NLM_F_ACK | NLM_F_CREATE);
    msg(&mut b, NFT_MSG_DELTABLE, NLM_F_ACK, NFPROTO_IPV4, 0);
    b.attr_str(NFTA_TABLE_NAME, m.table);
    b.end();
    new_table(&mut b, m.table, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
    new_chain(&mut b, m.table, b"postrouting", b"nat", NF_INET_POST_ROUTING, 100);
    new_chain(&mut b, m.table, b"forward", b"filter", NF_INET_FORWARD, 0);
    // ip saddr <cidr> oifname != <bridge> masquerade
    rule(&mut b, m.table, b"postrouting", |b| {
        expr_begin(b, b"payload");
        b.attr_u32_be(NFTA_PAYLOAD_DREG, NFT_REG_1);
        b.attr_u32_be(NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
        b.attr_u32_be(NFTA_PAYLOAD_OFFSET, 12); // saddr in the IPv4 header
        b.attr_u32_be(NFTA_PAYLOAD_LEN, 4);
        expr_end(b);
        bitwise_and(b, &mask);
        cmp(b, NFT_CMP_EQ, &net);
        meta(b, NFT_META_OIFNAME);
        cmp(b, NFT_CMP_NEQ, &bridge);
        expr_begin(b, b"masq");
        expr_end(b);
    });
    // iifname <bridge> accept
    rule(&mut b, m.table, b"forward", |b| {
        meta(b, NFT_META_IIFNAME);
        cmp(b, NFT_CMP_EQ, &bridge);
        verdict_accept(b);
    });
    // oifname <bridge> ct state established,related accept
    rule(&mut b, m.table, b"forward", |b| {
        meta(b, NFT_META_OIFNAME);
        cmp(b, NFT_CMP_EQ, &bridge);
        expr_begin(b, b"ct");
        b.attr_u32_be(NFTA_CT_DREG, NFT_REG_1);
        b.attr_u32_be(NFTA_CT_KEY, NFT_CT_STATE);
        expr_end(b);
        bitwise_and(b, &CT_ESTABLISHED_RELATED.to_ne_bytes()); // ct state is host-endian
        cmp(b, NFT_CMP_NEQ, &[0u8; 4]);
        verdict_accept(b);
    });
    batch_msg(&mut b, NFNL_MSG_BATCH_END);
    b
}

/// Idempotently (re)creates table `ip <table>` with a NAT postrouting chain masquerading
/// `cidr/prefix` leaving through anything but `bridge`, and a forward chain accepting traffic
/// from the bridge and established/related traffic back to it.
pub fn ensure_masquerade(m: &Masquerade) -> Result<(), Errno> {
    let b = masquerade_batch(m);
    Netlink::open(NETLINK_NETFILTER)?.transact(&b)
}

/// Deletes table `ip <table>`; a missing table (ENOENT) is success.
pub fn delete_table(table: &[u8]) -> Result<(), Errno> {
    let mut b = NlBuf::new();
    batch_msg(&mut b, NFNL_MSG_BATCH_BEGIN);
    msg(&mut b, NFT_MSG_DELTABLE, NLM_F_ACK, NFPROTO_IPV4, 0);
    b.attr_str(NFTA_TABLE_NAME, table);
    b.end();
    batch_msg(&mut b, NFNL_MSG_BATCH_END);
    match Netlink::open(NETLINK_NETFILTER)?.transact(&b) {
        Err(Errno(2)) => Ok(()), // ENOENT
        r => r,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn u16at(b: &[u8], o: usize) -> u16 {
        u16::from_ne_bytes([b[o], b[o + 1]])
    }

    /// Splits a buffer into (type, flags, whole message) triples.
    fn messages(buf: &[u8]) -> Vec<(u16, u16, &[u8])> {
        let mut v = Vec::new();
        let mut off = 0;
        while off < buf.len() {
            let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
            v.push((u16at(buf, off + 4), u16at(buf, off + 6), &buf[off..off + len]));
            off += (len + 3) & !3;
        }
        v
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    fn sample() -> NlBuf {
        masquerade_batch(&Masquerade { table: b"kr", cidr: [10, 88, 0, 0], prefix: 16, bridge: b"kr0" })
    }

    #[test]
    fn batch_layout() {
        let b = sample();
        let m = messages(b.bytes());
        let t = |x: u16| (NFNL_SUBSYS_NFTABLES << 8) | x;
        let types: Vec<u16> = m.iter().map(|x| x.0).collect();
        assert_eq!(
            types,
            [0x10, t(0), t(2), t(0), t(3), t(3), t(6), t(6), t(6), 0x11]
        );
        // begin/end carry no ACK and res_id = 10 big-endian
        assert_eq!(m[0].1 & NLM_F_ACK, 0);
        assert_eq!(m[9].1 & NLM_F_ACK, 0);
        assert_eq!(&m[0].2[16..20], &[0, 0, 0, 10]);
        assert_eq!(&m[9].2[16..20], &[0, 0, 0, 10]);
        for x in &m[1..9] {
            assert_ne!(x.1 & NLM_F_ACK, 0);
            assert_eq!(&x.2[16..20], &[2, 0, 0, 0]); // NFPROTO_IPV4, version 0, res_id 0
        }
    }

    #[test]
    fn rule_payloads() {
        let b = sample();
        let m = messages(b.bytes());
        // postrouting rule: saddr 10.88.0.0 masked with /16, oifname "kr0" padded to 16.
        let r = m[6].2;
        assert!(contains(r, &[255, 255, 0, 0]));
        assert!(contains(r, &[10, 88, 0, 0]));
        assert!(contains(r, b"masq\0"));
        assert!(contains(r, b"payload\0"));
        let mut name = [0u8; 16];
        name[..3].copy_from_slice(b"kr0");
        assert!(contains(r, &name));
        // ct rule: mask 6 in host order, cmp neq 0.
        let r = m[8].2;
        assert!(contains(r, b"ct\0"));
        assert!(contains(r, &6u32.to_ne_bytes()));
        assert!(contains(r, &NFT_CMP_NEQ.to_be_bytes()));
        // accept verdict is NF_ACCEPT big-endian.
        assert!(contains(m[7].2, &1u32.to_be_bytes()));
    }

    #[test]
    fn netmasks() {
        assert_eq!(netmask(0), [0; 4]);
        assert_eq!(netmask(24), [255, 255, 255, 0]);
        assert_eq!(netmask(32), [255; 4]);
        assert_eq!(netmask(20), [255, 255, 240, 0]);
    }

    /// Needs root (CAP_NET_ADMIN); run in a privileged container with `--ignored`.
    #[test]
    #[ignore]
    fn kernel_roundtrip() {
        let m = Masquerade { table: b"kr_test", cidr: [10, 88, 0, 0], prefix: 16, bridge: b"kr0" };
        ensure_masquerade(&m).unwrap();
        ensure_masquerade(&m).unwrap();
        if let Ok(v) = std::env::var("KR_NFT_KEEP") {
            if !v.is_empty() {
                return; // leave the table for inspection
            }
        }
        delete_table(b"kr_test").unwrap();
        delete_table(b"kr_test").unwrap(); // ENOENT is fine
    }
}
