//! A stub DNS resolver (RFC 1035): A/AAAA over UDP with TCP fallback, configured from
//! `/etc/resolv.conf` (`nameserver`, `search`, `options ndots:N timeout:N attempts:N`).
//!
//! Spoofing defences of a stub resolver: random query ids and kernel-random source ports
//! (connected UDP sockets also drop datagrams from other addresses), and answers are only
//! accepted if the question section echoes ours. Responses are parsed strictly with bounded
//! name decompression. There is no cache.

use crate::tcp::{connect_addr, HostsResolver, IpAddr, Resolver, SocketAddr};
use crate::{Error, Result};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_rt::exec::{now_ms, timeout, Async};
use kr_sys::{self as sys, Errno};

const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const MAX_UDP: usize = 1232; // EDNS-safe size; we do not send OPT, so servers cap at 512
const MAX_CNAME_HOPS: usize = 8;

#[derive(Clone, Debug)]
pub struct Config {
    pub nameservers: Vec<IpAddr>,
    pub search: Vec<String>,
    pub ndots: usize,
    pub timeout_ms: u64,
    pub attempts: u32,
}

impl Default for Config {
    fn default() -> Self {
        // glibc defaults; with no nameserver line, use the local resolver.
        Config { nameservers: alloc::vec![IpAddr::V4([127, 0, 0, 1])], search: Vec::new(), ndots: 1, timeout_ms: 5000, attempts: 2 }
    }
}

impl Config {
    pub fn parse(text: &str) -> Config {
        let mut c = Config { nameservers: Vec::new(), ..Config::default() };
        for line in text.lines() {
            let line = line.split(['#', ';']).next().unwrap_or("");
            let mut f = line.split_ascii_whitespace();
            match f.next() {
                Some("nameserver") => {
                    if let Some(ip) = f.next().and_then(|a| IpAddr::parse(a.split('%').next().unwrap_or(a))) {
                        if c.nameservers.len() < 3 {
                            c.nameservers.push(ip);
                        }
                    }
                }
                Some("search") | Some("domain") => {
                    c.search = f.filter(|d| *d != ".").take(6).map(|d| d.trim_end_matches('.').to_string()).collect();
                }
                Some("options") => {
                    for o in f {
                        let num = |p: &str| o.strip_prefix(p).and_then(|v| v.parse::<u64>().ok());
                        if let Some(n) = num("ndots:") {
                            c.ndots = n.min(15) as usize;
                        } else if let Some(n) = num("timeout:") {
                            c.timeout_ms = n.clamp(1, 30) * 1000;
                        } else if let Some(n) = num("attempts:") {
                            c.attempts = n.clamp(1, 5) as u32;
                        }
                    }
                }
                _ => {}
            }
        }
        if c.nameservers.is_empty() {
            c.nameservers = Config::default().nameservers;
        }
        c
    }

    pub fn system() -> Config {
        match sys::open_read(b"/etc/resolv.conf\0") {
            Ok(fd) => {
                let mut data = Vec::new();
                let mut buf = [0u8; 4096];
                while let Ok(n) = sys::read(fd.raw(), &mut buf) {
                    if n == 0 || data.len() > 64 * 1024 {
                        break;
                    }
                    data.extend_from_slice(&buf[..n]);
                }
                Config::parse(&String::from_utf8_lossy(&data))
            }
            Err(_) => Config::default(),
        }
    }

    /// Candidate FQDNs in query order (resolv.conf semantics).
    fn candidates(&self, name: &str) -> Vec<String> {
        if let Some(abs) = name.strip_suffix('.') {
            return alloc::vec![abs.to_string()];
        }
        let dots = name.bytes().filter(|&b| b == b'.').count();
        let searched = self.search.iter().map(|d| alloc::format!("{name}.{d}"));
        let mut out: Vec<String> = Vec::new();
        if dots >= self.ndots {
            out.push(name.to_string());
            out.extend(searched);
        } else {
            out.extend(searched);
            out.push(name.to_string());
        }
        out
    }
}

/// Validates a host name for querying: LDH-ish labels of 1..=63 bytes, 253 total.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
}

fn encode_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(18 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // RD
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QDCOUNT=1
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&CLASS_IN.to_be_bytes());
    q
}

/// Reads a (possibly compressed) name at `pos`; returns (lowercased dotted name, next pos).
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
                    if !(b.is_ascii_graphic()) || b == b'.' {
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
                // Pointers must go backwards, so chains are finite even without the bound.
                if jumps > 64 || target >= pos {
                    return None;
                }
                pos = target;
            }
            _ => return None, // extended label types
        }
    }
    Some((name, next.unwrap_or(pos)))
}

#[derive(Debug, PartialEq, Eq)]
enum Answer {
    Addrs(Vec<IpAddr>),
    /// NXDOMAIN or no data for this type.
    Empty,
    Truncated,
    /// SERVFAIL / REFUSED etc.: try the next server.
    Fail,
}

fn parse_response(msg: &[u8], id: u16, name: &str, qtype: u16) -> Option<Answer> {
    if msg.len() < 12 || u16::from_be_bytes([msg[0], msg[1]]) != id {
        return None; // not ours: ignore
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    if flags & 0x8000 == 0 || (flags >> 11) & 0xf != 0 {
        return None; // not a response, or not a standard query
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]);
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    if qd != 1 {
        return None;
    }
    let (qname, mut pos) = read_name(msg, 12)?;
    let qt = u16::from_be_bytes([*msg.get(pos)?, *msg.get(pos + 1)?]);
    let qc = u16::from_be_bytes([*msg.get(pos + 2)?, *msg.get(pos + 3)?]);
    pos += 4;
    if !qname.eq_ignore_ascii_case(name) || qt != qtype || qc != CLASS_IN {
        return None; // question does not echo ours
    }
    if flags & 0x0200 != 0 {
        return Some(Answer::Truncated);
    }
    match flags & 0xf {
        0 => {}
        3 => return Some(Answer::Empty), // NXDOMAIN
        _ => return Some(Answer::Fail),
    }
    let mut records = Vec::new();
    for _ in 0..an {
        let (owner, p) = read_name(msg, pos)?;
        let h = msg.get(p..p + 10)?;
        let (ty, class) = (u16::from_be_bytes([h[0], h[1]]), u16::from_be_bytes([h[2], h[3]]));
        let rdlen = u16::from_be_bytes([h[8], h[9]]) as usize;
        let rd_start = p + 10;
        let rdata = msg.get(rd_start..rd_start + rdlen)?;
        pos = rd_start + rdlen;
        if class == CLASS_IN {
            records.push((owner, ty, rd_start, rdata));
        }
    }
    // Follow the CNAME chain from the queried name, then collect addresses of the final owner.
    let mut current = qname;
    for _ in 0..MAX_CNAME_HOPS {
        match records.iter().find(|(o, t, _, _)| *t == TYPE_CNAME && *o == current) {
            Some((_, _, start, _)) => current = read_name(msg, *start)?.0,
            None => break,
        }
    }
    let addrs: Vec<IpAddr> = records
        .iter()
        .filter(|(o, t, _, _)| *o == current && *t == qtype)
        .filter_map(|(_, _, _, rd)| match (qtype, rd.len()) {
            (TYPE_A, 4) => Some(IpAddr::V4((*rd).try_into().unwrap())),
            (TYPE_AAAA, 16) => Some(IpAddr::V6((*rd).try_into().unwrap())),
            _ => None,
        })
        .collect();
    Some(if addrs.is_empty() { Answer::Empty } else { Answer::Addrs(addrs) })
}

fn random_id() -> u16 {
    let mut b = [0u8; 2];
    sys::getrandom(&mut b);
    u16::from_be_bytes(b)
}

async fn query_udp(server: IpAddr, query: &[u8], id: u16, name: &str, qtype: u16, deadline_ms: u64) -> Result<Answer> {
    const SOCK_DGRAM: i32 = 2;
    let flags = SOCK_DGRAM | sys::SOCK_NONBLOCK | sys::SOCK_CLOEXEC;
    let fd = match server {
        IpAddr::V4(a) => {
            let fd = sys::socket(sys::AF_INET, flags, 0)?;
            sys::connect(fd.raw(), &sys::SockaddrIn::new(a, 53))?;
            fd
        }
        IpAddr::V6(a) => {
            let fd = sys::socket(sys::AF_INET6, flags, 0)?;
            sys::connect6(fd.raw(), &sys::SockaddrIn6::new(a, 53))?;
            fd
        }
    };
    let sock = Async::new(fd)?;
    sock.write(query).await?;
    let mut buf = alloc::vec![0u8; MAX_UDP];
    loop {
        let left = deadline_ms.saturating_sub(now_ms());
        let n = match timeout(left, sock.read(&mut buf)).await {
            Err(_) => return Err(Error::Timeout),
            Ok(Err(Errno(111))) => return Ok(Answer::Fail), // ECONNREFUSED (ICMP port unreachable)
            Ok(r) => r?,
        };
        if let Some(a) = parse_response(&buf[..n], id, name, qtype) {
            return Ok(a);
        }
        // Mismatched datagram: keep waiting for ours until the deadline.
    }
}

async fn query_tcp(server: IpAddr, query: &[u8], id: u16, name: &str, qtype: u16, timeout_ms: u64) -> Result<Answer> {
    let sock = connect_addr(SocketAddr { ip: server, port: 53 }, timeout_ms).await?;
    let mut framed = (query.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(query);
    sock.write_all(&framed).await?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let deadline = now_ms() + timeout_ms;
    loop {
        if buf.len() >= 2 {
            let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            if buf.len() >= 2 + len {
                return Ok(parse_response(&buf[2..2 + len], id, name, qtype).unwrap_or(Answer::Fail));
            }
        }
        let left = deadline.saturating_sub(now_ms());
        let n = timeout(left, sock.read(&mut tmp)).await.map_err(|_| Error::Timeout)??;
        if n == 0 {
            return Err(Error::UnexpectedEof);
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// `/etc/hosts` first, then DNS.
#[derive(Clone, Debug)]
pub struct SystemResolver {
    hosts: HostsResolver,
    cfg: Config,
}

impl SystemResolver {
    pub fn system() -> Self {
        SystemResolver { hosts: HostsResolver::system(), cfg: Config::system() }
    }

    pub fn new(hosts: HostsResolver, cfg: Config) -> Self {
        SystemResolver { hosts, cfg }
    }

    async fn lookup_type(&self, fqdn: &str, qtype: u16) -> Result<Answer> {
        let mut last = Err(Error::Resolve);
        for _ in 0..self.cfg.attempts {
            for &server in &self.cfg.nameservers {
                let id = random_id();
                let q = encode_query(id, fqdn, qtype);
                let deadline = now_ms() + self.cfg.timeout_ms;
                let r = match query_udp(server, &q, id, fqdn, qtype, deadline).await {
                    Ok(Answer::Truncated) => query_tcp(server, &q, id, fqdn, qtype, self.cfg.timeout_ms).await,
                    r => r,
                };
                match r {
                    Ok(a @ (Answer::Addrs(_) | Answer::Empty)) => return Ok(a),
                    other => last = other,
                }
            }
        }
        last
    }
}

impl Resolver for SystemResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        let local = self.hosts.lookup(host);
        if !local.is_empty() {
            return Ok(local);
        }
        let host = host.trim_end_matches('.');
        if !valid_name(host) {
            return Err(Error::Resolve);
        }
        for fqdn in self.cfg.candidates(host) {
            if !valid_name(&fqdn) {
                continue;
            }
            // IPv4 first (the common case for registries and clusters), then IPv6.
            for qtype in [TYPE_A, TYPE_AAAA] {
                if let Ok(Answer::Addrs(a)) = self.lookup_type(&fqdn, qtype).await {
                    return Ok(a);
                }
            }
        }
        Err(Error::Resolve)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(id: u16, name: &str, qtype: u16, answers: &[(&[u8], u16, &[u8])], flags: u16) -> Vec<u8> {
        let mut m = encode_query(id, name, qtype);
        m[2..4].copy_from_slice(&(0x8180u16 | flags).to_be_bytes());
        m[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
        for (owner, ty, rdata) in answers {
            m.extend_from_slice(owner);
            m.extend_from_slice(&ty.to_be_bytes());
            m.extend_from_slice(&CLASS_IN.to_be_bytes());
            m.extend_from_slice(&300u32.to_be_bytes());
            m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            m.extend_from_slice(rdata);
        }
        m
    }

    #[test]
    fn a_with_cname_chain_and_compression() {
        // question name at offset 12 -> pointer 0xc00c
        let cname_target = b"\x04edge\x03cdn\x03net\x00";
        let mut target_ptr_owner = Vec::new();
        let m0 = response(7, "registry-1.docker.io", TYPE_A, &[(b"\xc0\x0c", TYPE_CNAME, cname_target)], 0);
        // the CNAME rdata starts at a known offset; point the A record owner at it
        let rd_off = m0.len() - cname_target.len();
        target_ptr_owner.extend_from_slice(&(0xc000u16 | rd_off as u16).to_be_bytes());
        let m = response(7, "registry-1.docker.io", TYPE_A, &[(b"\xc0\x0c", TYPE_CNAME, cname_target), (&target_ptr_owner, TYPE_A, &[1, 2, 3, 4]), (b"\xc0\x0c", TYPE_A, &[9, 9, 9, 9])], 0);
        // The A record for the original name is ignored: the name is an alias.
        assert_eq!(parse_response(&m, 7, "registry-1.docker.io", TYPE_A), Some(Answer::Addrs(alloc::vec![IpAddr::V4([1, 2, 3, 4])])));
    }

    #[test]
    fn rejects_foreign_and_malformed() {
        let m = response(7, "a.example", TYPE_A, &[(b"\xc0\x0c", TYPE_A, &[1, 2, 3, 4])], 0);
        assert_eq!(parse_response(&m, 8, "a.example", TYPE_A), None); // wrong id
        assert_eq!(parse_response(&m, 7, "b.example", TYPE_A), None); // wrong question
        assert_eq!(parse_response(&m, 7, "a.example", TYPE_AAAA), None);
        assert_eq!(parse_response(&m[..m.len() - 2], 7, "a.example", TYPE_A), None); // truncated rdata
        // forward / self pointer loops
        let mut l = encode_query(1, "x", TYPE_A);
        l[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        l[12] = 0xc0;
        l[13] = 12;
        assert_eq!(parse_response(&l, 1, "x", TYPE_A), None);
        let tc = response(7, "a.example", TYPE_A, &[], 0x0200);
        assert_eq!(parse_response(&tc, 7, "a.example", TYPE_A), Some(Answer::Truncated));
        let nx = response(7, "a.example", TYPE_A, &[], 3);
        assert_eq!(parse_response(&nx, 7, "a.example", TYPE_A), Some(Answer::Empty));
    }

    #[test]
    fn resolv_conf_and_search_order() {
        let c = Config::parse("# c\nnameserver 10.0.0.10\nnameserver fe80::1%eth0\nsearch default.svc.cluster.local svc.cluster.local\noptions ndots:5 timeout:2\n");
        assert_eq!(c.nameservers.len(), 2);
        assert_eq!((c.ndots, c.timeout_ms), (5, 2000));
        assert_eq!(c.candidates("api")[0], "api.default.svc.cluster.local");
        assert_eq!(c.candidates("registry-1.docker.io")[0], "registry-1.docker.io.default.svc.cluster.local");
        assert_eq!(c.candidates("example.com.")[..], ["example.com".to_string()]);
        let d = Config::parse("search lan\n");
        assert_eq!(d.candidates("registry-1.docker.io")[0], "registry-1.docker.io");
        assert!(!valid_name("a..b") && !valid_name("bad name") && valid_name("k8s-rs.io"));
    }
}
