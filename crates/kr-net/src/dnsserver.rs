//! The cluster DNS server (replaces CoreDNS): answers `<zone>` (normally `cluster.local`) from a
//! [`Zone`] implemented by the caller on top of Kubernetes objects, and forwards everything else.
//!
//! * [`handle`] is a sans-I/O core: wire bytes in, [`Answer`] out. It follows the Kubernetes DNS
//!   specification (services, headless services, StatefulSet hostnames, SRV, `pod` names in
//!   "insecure" mode, PTR for the cluster CIDRs, ExternalName CNAMEs, NXDOMAIN vs NODATA with
//!   SOA, TTL 30). Parsing is strict: anything malformed is [`Answer::Drop`]ped, never a panic.
//! * [`serve_udp`] / [`serve_tcp`] drive it on pre-bound sockets and forward [`Answer::Forward`]
//!   queries to the upstream resolvers with a fresh random id, validating the reply (id and
//!   question) like the stub resolver in `dns.rs`. At most [`MAX_INFLIGHT`] forwards run at once.
//!
//! The wire codec (`read_name`, header layout, strict label rules) mirrors `dns.rs`, whose
//! helpers are private to that module.
//!
//! Safety: everything but the two `recvfrom`/`sendto` syscall wrappers (kr-sys has no
//! unconnected-UDP calls) is under `forbid(unsafe_code)`.

use crate::tcp::{connect_addr, parse_ipv4, SocketAddr};
use alloc::string::ToString;
use kr_rt::exec::{now_ms, sleep, spawn, timeout, Async};
use kr_sys::Fd;

/// The only module that needs `unsafe`: `recvfrom(2)` / `sendto(2)` on an unconnected UDP socket.
mod udp_sys {
    #![allow(unsafe_code)]
    use kr_sys::{self as sys, Errno};

    #[cfg(target_arch = "x86_64")]
    const NR_SENDTO: usize = 44;
    #[cfg(target_arch = "x86_64")]
    const NR_RECVFROM: usize = 45;
    #[cfg(not(target_arch = "x86_64"))]
    const NR_SENDTO: usize = 206;
    #[cfg(not(target_arch = "x86_64"))]
    const NR_RECVFROM: usize = 207;

    fn check(r: isize) -> Result<usize, Errno> {
        if (-4095..0).contains(&r) {
            Err(Errno(-r as i32))
        } else {
            Ok(r as usize)
        }
    }

    /// Receives one datagram; returns (length, length of the sockaddr written to `addr`).
    pub fn recvfrom(fd: i32, buf: &mut [u8], addr: &mut [u8; 28]) -> Result<(usize, usize), Errno> {
        let mut alen: u32 = 28;
        // SAFETY: `buf` and `addr` are valid writable buffers of the lengths passed, `alen` is a
        // valid in/out u32; the kernel writes at most that many bytes.
        let r = unsafe { sys::syscall6(NR_RECVFROM, fd as usize, buf.as_mut_ptr() as usize, buf.len(), 0, addr.as_mut_ptr() as usize, &mut alen as *mut u32 as usize) };
        Ok((check(r)?, (alen as usize).min(28)))
    }

    pub fn sendto(fd: i32, buf: &[u8], addr: &[u8; 28], alen: usize) -> Result<usize, Errno> {
        // SAFETY: `buf` and `addr` are valid readable buffers of the lengths passed.
        let r = unsafe { sys::syscall6(NR_SENDTO, fd as usize, buf.as_ptr() as usize, buf.len(), 0, addr.as_ptr() as usize, alen.min(28)) };
        check(r)
    }
}

pub use imp::*;

#[forbid(unsafe_code)]
mod imp {
    use super::*;
    use alloc::rc::Rc;
    use alloc::string::String;
    use alloc::vec::Vec;
    use core::cell::Cell;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll};
    use kr_sys::{self as sys, Errno};

    const TYPE_A: u16 = 1;
    const TYPE_CNAME: u16 = 5;
    const TYPE_SOA: u16 = 6;
    const TYPE_PTR: u16 = 12;
    const TYPE_SRV: u16 = 33;
    const TYPE_OPT: u16 = 41;
    const TYPE_IXFR: u16 = 251;
    const TYPE_AXFR: u16 = 252;
    const TYPE_ANY: u16 = 255;
    const CLASS_IN: u16 = 1;

    /// TTL of every answer, and the SOA `minimum` (negative-caching TTL).
    pub const TTL: u32 = 30;
    /// Largest UDP payload we ever send, even if the client advertises more.
    pub const MAX_EDNS_UDP: usize = 1232;
    /// Concurrent upstream forwards; beyond this clients get SERVFAIL.
    pub const MAX_INFLIGHT: usize = 256;
    /// Per-upstream-server timeout.
    pub const UPSTREAM_TIMEOUT_MS: u64 = 2000;
    const MAX_TCP_CONNS: usize = 512;
    const TCP_IDLE_MS: u64 = 10_000;

    // ---------- the zone interface ----------

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct PortRecord {
        /// Port name (without the leading `_`), lowercase; unnamed ports get no SRV.
        pub name: String,
        /// `"tcp"` or `"udp"`.
        pub proto: String,
        pub port: u16,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ServiceRecord {
        /// `None` for a headless service.
        pub cluster_ip: Option<[u8; 4]>,
        pub ports: Vec<PortRecord>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct EndpointRecord {
        pub ip: [u8; 4],
        /// `hostname` of a StatefulSet-style endpoint.
        pub hostname: Option<String>,
        /// Ports of this endpoint (target ports), used for SRV of headless services.
        pub ports: Vec<PortRecord>,
    }

    /// The cluster data the server answers from. All `ns`/`name` arguments are lowercase.
    pub trait Zone {
        /// `"cluster.local"` (case and a trailing dot are ignored).
        fn domain(&self) -> &str;
        fn service(&self, ns: &str, name: &str) -> Option<ServiceRecord>;
        /// Ready endpoints of a headless service.
        fn endpoints(&self, ns: &str, name: &str) -> Vec<EndpointRecord>;
        fn external_name(&self, ns: &str, name: &str) -> Option<String>;
        fn namespace_exists(&self, ns: &str) -> bool;
        /// ip -> fully qualified name (service or pod), for PTR.
        fn reverse(&self, ip: [u8; 4]) -> Option<String>;
    }

    #[derive(Debug, PartialEq, Eq)]
    pub enum Answer {
        Response(Vec<u8>),
        /// Not ours: forward the query upstream unchanged and relay the reply.
        Forward,
        /// Malformed: say nothing.
        Drop,
    }

    // ---------- query parsing ----------

    struct Edns {
        udp: u16,
        version: u8,
    }

    struct Query {
        id: u16,
        flags: u16,
        /// Lowercased dotted name, no trailing dot ("" is the root).
        qname: String,
        qtype: u16,
        qclass: u16,
        qend: usize,
        edns: Option<Edns>,
    }

    enum Bad {
        Drop,
        /// Reply with just a header and this rcode.
        Rcode(u16),
    }

    fn be16(m: &[u8], p: usize) -> Option<u16> {
        Some(u16::from_be_bytes([*m.get(p)?, *m.get(p + 1)?]))
    }

    /// Reads a (possibly compressed) name at `pos`; returns (lowercased dotted name, next pos).
    /// Same rules as `dns.rs`: backward pointers only, bounded jumps, graphic labels only.
    fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
        let mut name = String::new();
        let mut next = None;
        let mut jumps = 0;
        loop {
            let len = *msg.get(pos)? as usize;
            match len & 0xc0 {
                0x00 => {
                    if len == 0 {
                        pos += 1;
                        break;
                    }
                    let label = msg.get(pos + 1..pos + 1 + len)?;
                    if !name.is_empty() {
                        name.push('.');
                    }
                    for &b in label {
                        if !b.is_ascii_graphic() || b == b'.' {
                            return None;
                        }
                        name.push(b.to_ascii_lowercase() as char);
                    }
                    if name.len() > 253 {
                        return None;
                    }
                    pos += 1 + len;
                }
                0xc0 => {
                    let target = ((len & 0x3f) << 8) | *msg.get(pos + 1)? as usize;
                    if next.is_none() {
                        next = Some(pos + 2);
                    }
                    jumps += 1;
                    if jumps > 64 || target >= pos {
                        return None;
                    }
                    pos = target;
                }
                _ => return None,
            }
        }
        Some((name, next.unwrap_or(pos)))
    }

    /// End of the (uncompressed) question name at offset 12, i.e. where QTYPE starts.
    fn question_name_end(msg: &[u8]) -> Option<usize> {
        let mut pos = 12;
        loop {
            let len = *msg.get(pos)? as usize;
            if len == 0 {
                return Some(pos + 1);
            }
            if len & 0xc0 != 0 {
                return None;
            }
            pos += 1 + len;
        }
    }

    fn parse(msg: &[u8]) -> Result<Query, Bad> {
        if msg.len() < 12 {
            return Err(Bad::Drop);
        }
        let id = be16(msg, 0).ok_or(Bad::Drop)?;
        let flags = be16(msg, 2).ok_or(Bad::Drop)?;
        if flags & 0x8000 != 0 {
            return Err(Bad::Drop); // a response, not a query
        }
        if (flags >> 11) & 0xf != 0 {
            return Err(Bad::Rcode(4)); // NOTIMP
        }
        let counts: Vec<u16> = (0..4).filter_map(|i| be16(msg, 4 + 2 * i)).collect();
        if counts[0] != 1 || counts[1] != 0 || counts[2] != 0 {
            return Err(Bad::Rcode(1)); // FORMERR
        }
        let nar = counts[3] as usize;
        let (qname, _) = read_name(msg, 12).ok_or(Bad::Drop)?;
        let nend = question_name_end(msg).ok_or(Bad::Drop)?;
        let qtype = be16(msg, nend).ok_or(Bad::Drop)?;
        let qclass = be16(msg, nend + 2).ok_or(Bad::Drop)?;
        let qend = nend + 4;
        let mut pos = qend;
        let mut edns = None;
        let mut formerr = false;
        for _ in 0..nar {
            let (owner, p) = read_name(msg, pos).ok_or(Bad::Drop)?;
            let h = msg.get(p..p + 10).ok_or(Bad::Drop)?;
            let ty = u16::from_be_bytes([h[0], h[1]]);
            let class = u16::from_be_bytes([h[2], h[3]]);
            let version = h[5];
            let rdlen = u16::from_be_bytes([h[8], h[9]]) as usize;
            let rdata = msg.get(p + 10..p + 10 + rdlen).ok_or(Bad::Drop)?;
            pos = p + 10 + rdlen;
            if ty == TYPE_OPT {
                // options must be well-formed TLVs
                let mut o = 0;
                while o < rdata.len() {
                    let l = be16(rdata, o + 2).ok_or(Bad::Drop)? as usize;
                    o += 4 + l;
                }
                if o != rdata.len() {
                    return Err(Bad::Drop);
                }
                if !owner.is_empty() || edns.is_some() {
                    formerr = true;
                }
                edns = Some(Edns { udp: class, version });
            }
        }
        if pos != msg.len() {
            return Err(Bad::Drop);
        }
        if formerr {
            return Err(Bad::Rcode(1));
        }
        Ok(Query { id, flags, qname, qtype, qclass, qend, edns })
    }

    /// Header-only reply with `rcode` (opcode and RD echoed).
    fn short_reply(msg: &[u8], rcode: u16) -> Vec<u8> {
        let mut r = Vec::with_capacity(12);
        r.extend_from_slice(&msg[..2]);
        let flags = be16(msg, 2).unwrap_or(0);
        let f = 0x8000 | (flags & 0x7900) | 0x0080 | (rcode & 0xf);
        r.extend_from_slice(&f.to_be_bytes());
        r.extend_from_slice(&[0; 8]);
        r
    }

    /// A reply with the given rcode that echoes the question when one can be parsed.
    pub fn error_reply(query: &[u8], rcode: u16) -> Vec<u8> {
        if query.len() < 12 {
            return Vec::new();
        }
        let mut r = short_reply(query, rcode);
        if let Some(qend) = question_name_end(query).map(|e| e + 4).filter(|e| *e <= query.len()) {
            r[4..6].copy_from_slice(&1u16.to_be_bytes());
            r.extend_from_slice(&query[12..qend]);
        }
        r
    }

    // ---------- response model and encoder ----------

    enum Data {
        A([u8; 4]),
        /// CNAME / PTR target.
        Name(String),
        Srv { weight: u16, port: u16, target: String },
        Soa(String),
    }

    struct Rr {
        /// `None`: the question name.
        owner: Option<String>,
        rtype: u16,
        data: Data,
    }

    struct Reply {
        rcode: u16,
        aa: bool,
        answers: Vec<Rr>,
        authority: Vec<Rr>,
        additional: Vec<Rr>,
    }

    impl Reply {
        fn new(rcode: u16) -> Reply {
            Reply { rcode, aa: true, answers: Vec::new(), authority: Vec::new(), additional: Vec::new() }
        }
    }

    struct Enc {
        buf: Vec<u8>,
        names: Vec<(String, u16)>,
    }

    impl Enc {
        fn name(&mut self, name: &str, compress: bool) {
            let mut rest = name.trim_end_matches('.');
            loop {
                if rest.is_empty() {
                    self.buf.push(0);
                    return;
                }
                if compress {
                    if let Some((_, off)) = self.names.iter().find(|(n, _)| n == rest) {
                        self.buf.extend_from_slice(&(0xc000 | *off).to_be_bytes());
                        return;
                    }
                }
                if self.buf.len() < 0x3fff {
                    self.names.push((rest.to_string(), self.buf.len() as u16));
                }
                let (label, tail) = rest.split_once('.').unwrap_or((rest, ""));
                let l = label.len().min(63);
                self.buf.push(l as u8);
                self.buf.extend_from_slice(&label.as_bytes()[..l]);
                rest = tail;
            }
        }

        fn rr(&mut self, rr: &Rr) {
            match &rr.owner {
                None => self.buf.extend_from_slice(&[0xc0, 12]),
                Some(n) => self.name(n, true),
            }
            self.buf.extend_from_slice(&rr.rtype.to_be_bytes());
            self.buf.extend_from_slice(&CLASS_IN.to_be_bytes());
            self.buf.extend_from_slice(&TTL.to_be_bytes());
            let lenpos = self.buf.len();
            self.buf.extend_from_slice(&[0, 0]);
            match &rr.data {
                Data::A(ip) => self.buf.extend_from_slice(ip),
                Data::Name(n) => self.name(n, true),
                Data::Srv { weight, port, target } => {
                    self.buf.extend_from_slice(&0u16.to_be_bytes());
                    self.buf.extend_from_slice(&weight.to_be_bytes());
                    self.buf.extend_from_slice(&port.to_be_bytes());
                    self.name(target, false); // RFC 2782: no compression of the SRV target
                }
                Data::Soa(dom) => {
                    self.name(&alloc::format!("ns.dns.{dom}"), true);
                    self.name(&alloc::format!("hostmaster.{dom}"), true);
                    for v in [1u32, 7200, 1800, 86400, TTL] {
                        self.buf.extend_from_slice(&v.to_be_bytes());
                    }
                }
            }
            let rdlen = (self.buf.len() - lenpos - 2) as u16;
            self.buf[lenpos..lenpos + 2].copy_from_slice(&rdlen.to_be_bytes());
        }
    }

    /// Encodes `rep` within `limit` bytes. Whole records only: when answers (or authority) do
    /// not fit, TC is set; additional records that do not fit are silently dropped.
    fn encode(q: &Query, msg: &[u8], rep: &Reply, limit: usize) -> Vec<u8> {
        let reserve = if q.edns.is_some() { 11 } else { 0 };
        let mut e = Enc { buf: Vec::with_capacity(limit.min(1500)), names: Vec::new() };
        e.buf.extend_from_slice(&[0u8; 12]);
        e.buf.extend_from_slice(&msg[12..q.qend]);
        let (mut off, mut rest) = (12usize, q.qname.as_str());
        while !rest.is_empty() {
            e.names.push((rest.to_string(), off as u16));
            let (label, tail) = rest.split_once('.').unwrap_or((rest, ""));
            off += 1 + label.len();
            rest = tail;
        }
        let mut counts = [0u16; 3];
        let mut tc = false;
        'sections: for (i, rrs) in [&rep.answers, &rep.authority, &rep.additional].into_iter().enumerate() {
            for rr in rrs.iter() {
                let (blen, nlen) = (e.buf.len(), e.names.len());
                e.rr(rr);
                if e.buf.len() + reserve > limit {
                    e.buf.truncate(blen);
                    e.names.truncate(nlen);
                    tc = i < 2;
                    if tc {
                        break 'sections;
                    }
                    break;
                }
                counts[i] += 1;
            }
        }
        let ar = counts[2] + (reserve > 0) as u16;
        if reserve > 0 {
            let ext_rcode = (rep.rcode >> 4) as u32;
            e.buf.push(0);
            e.buf.extend_from_slice(&TYPE_OPT.to_be_bytes());
            e.buf.extend_from_slice(&(MAX_EDNS_UDP as u16).to_be_bytes());
            e.buf.extend_from_slice(&(ext_rcode << 24).to_be_bytes());
            e.buf.extend_from_slice(&[0, 0]);
        }
        let mut flags = 0x8000 | 0x0080 | (q.flags & 0x0100) | (rep.rcode & 0xf);
        if rep.aa {
            flags |= 0x0400;
        }
        if tc {
            flags |= 0x0200;
        }
        e.buf[0..2].copy_from_slice(&q.id.to_be_bytes());
        e.buf[2..4].copy_from_slice(&flags.to_be_bytes());
        e.buf[4..6].copy_from_slice(&1u16.to_be_bytes());
        e.buf[6..8].copy_from_slice(&counts[0].to_be_bytes());
        e.buf[8..10].copy_from_slice(&counts[1].to_be_bytes());
        e.buf[10..12].copy_from_slice(&ar.to_be_bytes());
        e.buf
    }

    fn udp_limit(q: &Query) -> usize {
        match &q.edns {
            Some(e) => (e.udp as usize).clamp(512, MAX_EDNS_UDP),
            None => 512,
        }
    }

    // ---------- the lookup ----------

    fn soa(dom: &str) -> Rr {
        Rr { owner: Some(dom.to_string()), rtype: TYPE_SOA, data: Data::Soa(dom.to_string()) }
    }

    fn negative(rcode: u16, dom: &str) -> Reply {
        let mut r = Reply::new(rcode);
        r.authority.push(soa(dom));
        r
    }

    fn nxdomain(dom: &str) -> Reply {
        negative(3, dom)
    }

    fn nodata(dom: &str) -> Reply {
        negative(0, dom)
    }

    fn wants_a(qtype: u16) -> bool {
        qtype == TYPE_A || qtype == TYPE_ANY
    }

    fn dashed(ip: [u8; 4]) -> String {
        alloc::format!("{}-{}-{}-{}", ip[0], ip[1], ip[2], ip[3])
    }

    fn a_rr(owner: Option<String>, ip: [u8; 4]) -> Rr {
        Rr { owner, rtype: TYPE_A, data: Data::A(ip) }
    }

    fn in_cluster_cidr(ip: [u8; 4]) -> bool {
        ip[0] == 10 && ((ip[1] & 0xf0) == 96 || ip[1] == 88) // 10.96.0.0/12, 10.88.0.0/16
    }

    /// `None` means "not ours: forward".
    fn lookup(q: &Query, zone: &dyn Zone) -> Option<Reply> {
        if q.qclass != CLASS_IN {
            return None;
        }
        let dom = zone.domain().trim_matches('.').to_ascii_lowercase();
        if let Some(r) = q.qname.strip_suffix(".in-addr.arpa") {
            return reverse(q, zone, &dom, r);
        }
        let rel = if q.qname == dom {
            ""
        } else {
            q.qname.strip_suffix(dom.as_str())?.strip_suffix('.')?
        };
        if q.qtype == TYPE_AXFR || q.qtype == TYPE_IXFR {
            return Some(Reply { aa: false, ..Reply::new(5) });
        }
        if rel.is_empty() {
            let mut r = Reply::new(0);
            if q.qtype == TYPE_SOA || q.qtype == TYPE_ANY {
                r.answers.push(soa(&dom));
                return Some(r);
            }
            return Some(nodata(&dom));
        }
        let labels: Vec<&str> = rel.split('.').collect();
        let (kind, l) = labels.split_last()?;
        Some(match *kind {
            "svc" => svc(q, zone, &dom, l),
            "pod" => pod(q, zone, &dom, l),
            _ => nxdomain(&dom),
        })
    }

    fn reverse(q: &Query, zone: &dyn Zone, dom: &str, r: &str) -> Option<Reply> {
        let mut parts: Vec<&str> = r.split('.').collect();
        parts.reverse();
        let ip = parse_ipv4(&parts.join("."))?;
        if !in_cluster_cidr(ip) {
            return None;
        }
        Some(match zone.reverse(ip) {
            None => nxdomain(dom),
            Some(name) if q.qtype == TYPE_PTR || q.qtype == TYPE_ANY => {
                let mut rep = Reply::new(0);
                rep.answers.push(Rr { owner: None, rtype: TYPE_PTR, data: Data::Name(name.trim_end_matches('.').to_ascii_lowercase()) });
                rep
            }
            Some(_) => nodata(dom),
        })
    }

    fn pod(q: &Query, zone: &dyn Zone, dom: &str, l: &[&str]) -> Reply {
        match l {
            [] => nodata(dom),
            [ns] => {
                if zone.namespace_exists(ns) {
                    nodata(dom)
                } else {
                    nxdomain(dom)
                }
            }
            [ip, _ns] => match parse_ipv4(&ip.replace('-', ".")) {
                Some(addr) if wants_a(q.qtype) => {
                    let mut r = Reply::new(0);
                    r.answers.push(a_rr(None, addr));
                    r
                }
                Some(_) => nodata(dom),
                None => nxdomain(dom),
            },
            _ => nxdomain(dom),
        }
    }

    fn svc(q: &Query, zone: &dyn Zone, dom: &str, l: &[&str]) -> Reply {
        match l {
            [] => nodata(dom),
            [ns] => {
                if zone.namespace_exists(ns) {
                    nodata(dom)
                } else {
                    nxdomain(dom)
                }
            }
            [name, ns] => {
                if let Some(target) = zone.external_name(ns, name) {
                    let target = target.trim_end_matches('.').to_ascii_lowercase();
                    let mut r = Reply::new(0);
                    r.answers.push(Rr { owner: None, rtype: TYPE_CNAME, data: Data::Name(target.clone()) });
                    if q.qtype != TYPE_CNAME {
                        chase(q, zone, target, &mut r);
                    }
                    return r;
                }
                let Some(s) = zone.service(ns, name) else { return nxdomain(dom) };
                if !wants_a(q.qtype) {
                    return nodata(dom);
                }
                let mut r = Reply::new(0);
                match s.cluster_ip {
                    Some(ip) => r.answers.push(a_rr(None, ip)),
                    None => r.answers.extend(zone.endpoints(ns, name).into_iter().map(|e| a_rr(None, e.ip))),
                }
                if r.answers.is_empty() {
                    return nodata(dom);
                }
                r
            }
            [host, name, ns] => {
                match zone.service(ns, name) {
                    Some(ServiceRecord { cluster_ip: None, .. }) if zone.external_name(ns, name).is_none() => {}
                    _ => return nxdomain(dom),
                }
                let hits: Vec<EndpointRecord> = zone.endpoints(ns, name).into_iter().filter(|e| endpoint_label(e) == *host || e.hostname.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(host))).collect();
                if hits.is_empty() {
                    return nxdomain(dom);
                }
                if !wants_a(q.qtype) {
                    return nodata(dom);
                }
                let mut r = Reply::new(0);
                r.answers.extend(hits.iter().map(|e| a_rr(None, e.ip)));
                r
            }
            [port, proto, name, ns] if port.starts_with('_') && proto.starts_with('_') => srv(q, zone, dom, &port[1..], &proto[1..], name, ns),
            _ => nxdomain(dom),
        }
    }

    /// Appends the records of an in-cluster CNAME target to `r`, as CoreDNS does: stub resolvers
    /// such as musl's do not chase a CNAME by querying again. ExternalName hops are followed
    /// here (at most 8, so loops end) and only the final, non-alias target is looked up.
    /// Targets outside the cluster domain are left to the client.
    fn chase(q: &Query, zone: &dyn Zone, mut target: String, r: &mut Reply) {
        let dom = zone.domain().trim_matches('.').to_ascii_lowercase();
        for _ in 0..8 {
            let Some(rel) = target.strip_suffix(dom.as_str()).and_then(|t| t.strip_suffix('.')) else { return };
            let labels: Vec<&str> = rel.split('.').collect();
            if let [name, ns, "svc"] = labels.as_slice() {
                if let Some(next) = zone.external_name(ns, name) {
                    let next = next.trim_end_matches('.').to_ascii_lowercase();
                    r.answers.push(Rr { owner: Some(target.clone()), rtype: TYPE_CNAME, data: Data::Name(next.clone()) });
                    target = next;
                    continue;
                }
            }
            let sub = Query { id: q.id, flags: q.flags, qname: target.clone(), qtype: q.qtype, qclass: q.qclass, qend: q.qend, edns: None };
            if let Some(rep) = lookup(&sub, zone) {
                for mut rr in rep.answers {
                    rr.owner.get_or_insert_with(|| target.clone());
                    r.answers.push(rr);
                }
            }
            return;
        }
    }

    /// Label naming an endpoint under its service: hostname if set, else the dashed IP.
    fn endpoint_label(e: &EndpointRecord) -> String {
        match &e.hostname {
            Some(h) => h.to_ascii_lowercase(),
            None => dashed(e.ip),
        }
    }

    fn srv(q: &Query, zone: &dyn Zone, dom: &str, port: &str, proto: &str, name: &str, ns: &str) -> Reply {
        let Some(s) = zone.service(ns, name) else { return nxdomain(dom) };
        if zone.external_name(ns, name).is_some() {
            return nxdomain(dom);
        }
        let matches = |p: &PortRecord| p.name.eq_ignore_ascii_case(port) && p.proto.eq_ignore_ascii_case(proto);
        // (target name, ip, port)
        let mut targets: Vec<(String, [u8; 4], u16)> = Vec::new();
        match s.cluster_ip {
            Some(ip) => {
                if let Some(p) = s.ports.iter().find(|p| matches(p)) {
                    targets.push((alloc::format!("{name}.{ns}.svc.{dom}"), ip, p.port));
                }
            }
            None => {
                for e in zone.endpoints(ns, name) {
                    if let Some(p) = e.ports.iter().find(|p| matches(p)) {
                        targets.push((alloc::format!("{}.{name}.{ns}.svc.{dom}", endpoint_label(&e)), e.ip, p.port));
                    }
                }
            }
        }
        if targets.is_empty() {
            return nxdomain(dom);
        }
        if q.qtype != TYPE_SRV && q.qtype != TYPE_ANY {
            return nodata(dom);
        }
        let weight = (100 / targets.len() as u16).max(1);
        let mut r = Reply::new(0);
        for (target, ip, port) in targets {
            r.additional.push(a_rr(Some(target.clone()), ip));
            r.answers.push(Rr { owner: None, rtype: TYPE_SRV, data: Data::Srv { weight, port, target } });
        }
        r
    }

    // ---------- the sans-I/O entry point ----------

    /// Answers one DNS message. `tcp` lifts the UDP size limits.
    pub fn handle(query: &[u8], zone: &dyn Zone, tcp: bool) -> Answer {
        let q = match parse(query) {
            Ok(q) => q,
            Err(Bad::Drop) => return Answer::Drop,
            Err(Bad::Rcode(rc)) => return Answer::Response(short_reply(query, rc)),
        };
        let Some(mut rep) = lookup(&q, zone) else { return Answer::Forward };
        if q.edns.as_ref().is_some_and(|e| e.version > 0) {
            rep = Reply::new(16); // BADVERS, carried in the OPT record
        }
        let limit = if tcp { 65535 } else { udp_limit(&q) };
        Answer::Response(encode(&q, query, &rep, limit))
    }

    // ---------- forwarding ----------

    fn random_id() -> u16 {
        let mut b = [0u8; 2];
        sys::getrandom(&mut b);
        u16::from_be_bytes(b)
    }

    /// (lowercased name, qtype, qclass) of a message's single question.
    fn question_key(msg: &[u8]) -> Option<(String, u16, u16)> {
        let (name, pos) = read_name(msg, 12)?;
        Some((name, be16(msg, pos)?, be16(msg, pos + 2)?))
    }

    /// Accepts an upstream reply only if it is a response with our id and echoes our question.
    fn valid_reply(msg: &[u8], id: u16, key: &(String, u16, u16)) -> bool {
        msg.len() >= 12 && be16(msg, 0) == Some(id) && msg[2] & 0x80 != 0 && be16(msg, 4) == Some(1) && question_key(msg).as_ref() == Some(key)
    }

    async fn ask_udp(server: SocketAddr, q: &[u8], id: u16, key: &(String, u16, u16)) -> Option<Vec<u8>> {
        use crate::tcp::IpAddr;
        let flags = 2 /* SOCK_DGRAM */ | sys::SOCK_NONBLOCK | sys::SOCK_CLOEXEC;
        let fd = match server.ip {
            IpAddr::V4(a) => {
                let fd = sys::socket(sys::AF_INET, flags, 0).ok()?;
                sys::connect(fd.raw(), &sys::SockaddrIn::new(a, server.port)).ok()?;
                fd
            }
            IpAddr::V6(a) => {
                let fd = sys::socket(sys::AF_INET6, flags, 0).ok()?;
                sys::connect6(fd.raw(), &sys::SockaddrIn6::new(a, server.port)).ok()?;
                fd
            }
        };
        let sock = Async::new(fd).ok()?;
        sock.write(q).await.ok()?;
        let deadline = now_ms() + UPSTREAM_TIMEOUT_MS;
        let mut buf = alloc::vec![0u8; 16384];
        loop {
            let left = deadline.saturating_sub(now_ms());
            let n = match timeout(left, sock.read(&mut buf)).await {
                Ok(Ok(n)) => n,
                _ => return None, // timeout, or ECONNREFUSED from an ICMP unreachable
            };
            if valid_reply(&buf[..n], id, key) {
                buf.truncate(n);
                return Some(buf);
            }
            // spoofed or stray datagram: keep waiting for the real one until the deadline
        }
    }

    async fn read_exact(c: &Async<Fd>, buf: &mut [u8], deadline: u64) -> bool {
        let mut got = 0;
        while got < buf.len() {
            let left = deadline.saturating_sub(now_ms());
            match timeout(left, c.read(&mut buf[got..])).await {
                Ok(Ok(n)) if n > 0 => got += n,
                _ => return false,
            }
        }
        true
    }

    async fn read_frame(c: &Async<Fd>, ms: u64) -> Option<Vec<u8>> {
        let deadline = now_ms() + ms;
        let mut l = [0u8; 2];
        if !read_exact(c, &mut l, deadline).await {
            return None;
        }
        let mut m = alloc::vec![0u8; u16::from_be_bytes(l) as usize];
        if m.is_empty() || !read_exact(c, &mut m, deadline).await {
            return None;
        }
        Some(m)
    }

    async fn write_frame(c: &Async<Fd>, m: &[u8]) -> bool {
        let mut f = Vec::with_capacity(m.len() + 2);
        f.extend_from_slice(&(m.len() as u16).to_be_bytes());
        f.extend_from_slice(m);
        c.write_all(&f).await.is_ok()
    }

    async fn ask_tcp(server: SocketAddr, q: &[u8], id: u16, key: &(String, u16, u16)) -> Option<Vec<u8>> {
        let conn = connect_addr(server, UPSTREAM_TIMEOUT_MS).await.ok()?;
        if !write_frame(&conn, q).await {
            return None;
        }
        let m = read_frame(&conn, UPSTREAM_TIMEOUT_MS).await?;
        valid_reply(&m, id, key).then_some(m)
    }

    /// Forwards `query` to the upstreams in order and returns the reply with the client's id
    /// restored; SERVFAIL if no server gave a usable answer.
    pub async fn forward(query: &[u8], upstream: &[SocketAddr], tcp: bool) -> Vec<u8> {
        let Some(key) = question_key(query) else { return error_reply(query, 2) };
        let client_id = [query[0], query[1]];
        let mut last: Option<Vec<u8>> = None;
        for &srv in upstream {
            let id = random_id();
            let mut q = query.to_vec();
            q[0..2].copy_from_slice(&id.to_be_bytes());
            let r = if tcp { ask_tcp(srv, &q, id, &key).await } else { ask_udp(srv, &q, id, &key).await };
            if let Some(mut m) = r {
                m[0..2].copy_from_slice(&client_id);
                if matches!(m[3] & 0xf, 2 | 5) {
                    last = Some(m); // SERVFAIL / REFUSED: try the next server
                    continue;
                }
                return m;
            }
        }
        last.unwrap_or_else(|| error_reply(query, 2))
    }

    /// Makes a reply fit the client's UDP size, else answers with an empty TC=1 message.
    fn fit_udp(query: &[u8], mut reply: Vec<u8>) -> Vec<u8> {
        let limit = parse(query).map(|q| udp_limit(&q)).unwrap_or(512);
        if reply.len() <= limit {
            return reply;
        }
        let end = question_name_end(&reply).map(|e| e + 4).filter(|e| *e <= reply.len()).unwrap_or(12);
        reply.truncate(end);
        reply[2] |= 0x02; // TC
        reply[6..12].fill(0);
        reply
    }

    struct Guard(Rc<Cell<usize>>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.set(self.0.get() - 1);
        }
    }
    fn acquire(c: &Rc<Cell<usize>>) -> Option<Guard> {
        (c.get() < MAX_INFLIGHT).then(|| {
            c.set(c.get() + 1);
            Guard(c.clone())
        })
    }

    struct YieldNow(bool);
    impl Future for YieldNow {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.0 {
                return Poll::Ready(());
            }
            self.0 = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    // ---------- servers ----------

    /// Serves DNS over a bound, non-blocking UDP socket until it fails. `upstream` addresses
    /// include their port (normally 53).
    pub async fn serve_udp(sock: Async<Fd>, zone: Rc<dyn Zone>, upstream: Vec<SocketAddr>) {
        let sock = Rc::new(sock);
        let upstream: Rc<[SocketAddr]> = upstream.into();
        let inflight = Rc::new(Cell::new(0usize));
        let fd = sock.get_ref().raw();
        let mut buf = alloc::vec![0u8; 4096];
        let mut addr = [0u8; 28];
        let mut served = 0u32;
        loop {
            let (n, alen) = match udp_sys::recvfrom(fd, &mut buf, &mut addr) {
                Ok(v) => v,
                Err(Errno(sys::EAGAIN)) => {
                    sock.wait_readable().await;
                    continue;
                }
                Err(Errno(sys::EINTR)) => continue,
                Err(Errno(9)) | Err(Errno(88)) => return, // EBADF / ENOTSOCK
                Err(_) => {
                    sleep(10).await;
                    continue;
                }
            };
            served += 1;
            if served % 32 == 0 {
                YieldNow(false).await;
            }
            let q = &buf[..n];
            match handle(q, &*zone, false) {
                Answer::Drop => {}
                Answer::Response(r) => {
                    let _ = udp_sys::sendto(fd, &r, &addr, alen);
                }
                Answer::Forward => {
                    let Some(guard) = acquire(&inflight) else {
                        let _ = udp_sys::sendto(fd, &error_reply(q, 2), &addr, alen);
                        continue;
                    };
                    let (q, sock, upstream, client) = (q.to_vec(), sock.clone(), upstream.clone(), addr);
                    spawn(async move {
                        let _guard = guard;
                        let reply = fit_udp(&q, forward(&q, &upstream, false).await);
                        let _ = udp_sys::sendto(sock.get_ref().raw(), &reply, &client, alen);
                    });
                }
            }
        }
    }

    /// Accepts TCP clients on a bound, listening, non-blocking socket; one task per connection,
    /// serving length-prefixed queries until the client goes idle for 10 s.
    pub async fn serve_tcp(listener: Async<Fd>, zone: Rc<dyn Zone>, upstream: Vec<SocketAddr>) {
        let upstream: Rc<[SocketAddr]> = upstream.into();
        let inflight = Rc::new(Cell::new(0usize));
        let conns = Rc::new(Cell::new(0usize));
        loop {
            let conn = match listener.accept().await {
                Ok(c) => c,
                Err(Errno(9)) | Err(Errno(22)) | Err(Errno(88)) => return, // EBADF / EINVAL / ENOTSOCK
                Err(_) => {
                    sleep(10).await;
                    continue;
                }
            };
            if conns.get() >= MAX_TCP_CONNS {
                continue; // dropped: closes
            }
            conns.set(conns.get() + 1);
            let (zone, upstream, inflight, conns) = (zone.clone(), upstream.clone(), inflight.clone(), conns.clone());
            spawn(async move {
                tcp_conn(&conn, &*zone, &upstream, &inflight).await;
                conns.set(conns.get() - 1);
            });
        }
    }

    async fn tcp_conn(conn: &Async<Fd>, zone: &dyn Zone, upstream: &[SocketAddr], inflight: &Rc<Cell<usize>>) {
        while let Some(q) = read_frame(conn, TCP_IDLE_MS).await {
            let reply = match handle(&q, zone, true) {
                Answer::Drop => return,
                Answer::Response(r) => r,
                Answer::Forward => match acquire(inflight) {
                    Some(_g) => forward(&q, upstream, true).await,
                    None => error_reply(&q, 2),
                },
            };
            if !write_frame(conn, &reply).await {
                return;
            }
        }
    }
}
