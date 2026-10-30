//! Cluster DNS server tests: the sans-I/O core against a fake zone (decoded with an independent
//! reader), malformed-input robustness, and real loopback UDP/TCP end to end including
//! forwarding to a fake upstream and a live check with python3 (`dig` is not installed here).

use kr_net::dnsserver::*;
use kr_net::http1::server::{listen, local_addr};
use kr_net::tcp::{IpAddr, SocketAddr};
use kr_rt::exec::{block_on, sleep, spawn};
use kr_sys::Fd;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::fd::IntoRawFd;
use std::rc::Rc;
use std::sync::{mpsc, Mutex};
use std::time::Duration;

static LOCK: Mutex<()> = Mutex::new(());

const WEB6: [u8; 16] = [0xfd, 0, 0, 0x96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a];
const DB06: [u8; 16] = [0xfd, 0, 0, 0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];

// ---------- fake zone ----------

fn port(name: &str, proto: &str, p: u16) -> PortRecord {
    PortRecord { name: name.into(), proto: proto.into(), port: p }
}

struct Fake;
impl Zone for Fake {
    fn domain(&self) -> &str {
        "cluster.local"
    }
    fn service(&self, ns: &str, name: &str) -> Option<ServiceRecord> {
        match (ns, name) {
            ("default", "web") => Some(ServiceRecord { cluster_ip: Some([10, 96, 0, 10]), cluster_ip6: Some(WEB6), ports: vec![port("http", "tcp", 80)] }),
            ("default", "db") | ("default", "big") => Some(ServiceRecord { cluster_ip: None, cluster_ip6: None, ports: vec![port("sql", "tcp", 5432)] }),
            ("default", "ext" | "alias" | "alias2" | "loop") => Some(ServiceRecord { cluster_ip: None, cluster_ip6: None, ports: vec![] }),
            _ => None,
        }
    }
    fn endpoints(&self, ns: &str, name: &str) -> Vec<EndpointRecord> {
        let ports = vec![port("sql", "tcp", 5432)];
        match (ns, name) {
            ("default", "db") => vec![
                EndpointRecord { ip: [10, 88, 0, 5], ip6: Some(DB06), hostname: Some("db-0".into()), ports: ports.clone() },
                EndpointRecord { ip: [10, 88, 0, 6], ip6: None, hostname: Some("db-1".into()), ports },
            ],
            ("default", "big") => (0..50).map(|i| EndpointRecord { ip: [10, 88, 1, i as u8], ip6: None, hostname: None, ports: ports.clone() }).collect(),
            _ => vec![],
        }
    }
    fn external_name(&self, ns: &str, name: &str) -> Option<String> {
        match (ns, name) {
            ("default", "ext") => Some("example.com.".to_string()),
            ("default", "alias") => Some("web.default.svc.cluster.local.".to_string()),
            ("default", "alias2") => Some("alias.default.svc.cluster.local.".to_string()),
            ("default", "loop") => Some("loop.default.svc.cluster.local.".to_string()),
            _ => None,
        }
    }
    fn namespace_exists(&self, ns: &str) -> bool {
        ns == "default" || ns == "kube-system"
    }
    fn reverse(&self, ip: [u8; 4]) -> Option<String> {
        (ip == [10, 96, 0, 10]).then(|| "web.default.svc.cluster.local.".to_string())
    }
}

// ---------- wire helpers (independent of the implementation) ----------

fn query_id(id: u16, name: &str, ty: u16, edns: Option<u16>) -> Vec<u8> {
    let mut q = id.to_be_bytes().to_vec();
    q.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, edns.is_some() as u8]);
    for l in name.split('.').filter(|l| !l.is_empty()) {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&ty.to_be_bytes());
    q.extend_from_slice(&[0, 1]);
    if let Some(sz) = edns {
        q.extend_from_slice(&[0, 0, 41]);
        q.extend_from_slice(&sz.to_be_bytes());
        q.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    }
    q
}
fn query(name: &str, ty: u16) -> Vec<u8> {
    query_id(0x1234, name, ty, None)
}

#[derive(Debug, Clone)]
struct Rec {
    name: String,
    ty: u16,
    ttl: u32,
    rdata: Vec<u8>,
    rd_off: usize,
}
struct Msg {
    raw: Vec<u8>,
    flags: u16,
    qname: String,
    an: Vec<Rec>,
    ns: Vec<Rec>,
    ar: Vec<Rec>,
}
impl Msg {
    fn rcode(&self) -> u16 {
        self.flags & 0xf
    }
    fn tc(&self) -> bool {
        self.flags & 0x200 != 0
    }
    fn aa(&self) -> bool {
        self.flags & 0x400 != 0
    }
    fn opt(&self) -> Option<&Rec> {
        self.ar.iter().find(|r| r.ty == 41)
    }
    fn rdname(&self, r: &Rec, skip: usize) -> String {
        name_at(&self.raw, r.rd_off + skip).0
    }
}
fn name_at(m: &[u8], mut pos: usize) -> (String, usize) {
    let (mut s, mut next) = (String::new(), None);
    loop {
        let l = m[pos] as usize;
        if l == 0 {
            pos += 1;
            break;
        }
        if l & 0xc0 == 0xc0 {
            next.get_or_insert(pos + 2);
            pos = ((l & 0x3f) << 8) | m[pos + 1] as usize;
            continue;
        }
        if !s.is_empty() {
            s.push('.');
        }
        s.push_str(std::str::from_utf8(&m[pos + 1..pos + 1 + l]).unwrap());
        pos += 1 + l;
    }
    (s, next.unwrap_or(pos))
}
fn decode(m: &[u8]) -> Msg {
    let u16at = |p: usize| u16::from_be_bytes([m[p], m[p + 1]]) as usize;
    assert_eq!(u16at(4), 1);
    let (qname, mut pos) = name_at(m, 12);
    pos += 4;
    let mut secs = [vec![], vec![], vec![]];
    for (i, n) in [u16at(6), u16at(8), u16at(10)].into_iter().enumerate() {
        for _ in 0..n {
            let (name, p) = name_at(m, pos);
            let (ty, ttl, rdlen) = (u16at(p) as u16, u32::from_be_bytes(m[p + 4..p + 8].try_into().unwrap()), u16at(p + 8));
            secs[i].push(Rec { name, ty, ttl, rdata: m[p + 10..p + 10 + rdlen].to_vec(), rd_off: p + 10 });
            pos = p + 10 + rdlen;
        }
    }
    assert_eq!(pos, m.len(), "trailing bytes");
    let [an, ns, ar] = secs;
    Msg { raw: m.to_vec(), flags: u16at(2) as u16, qname, an, ns, ar }
}
fn ask(name: &str, ty: u16) -> Msg {
    ask_raw(&query(name, ty), false)
}
fn ask_raw(q: &[u8], tcp: bool) -> Msg {
    match handle(q, &Fake, tcp) {
        Answer::Response(r) => decode(&r),
        _ => panic!("no response"),
    }
}
fn ips(recs: &[Rec]) -> Vec<[u8; 4]> {
    recs.iter().filter(|r| r.ty == 1).map(|r| r.rdata[..].try_into().unwrap()).collect()
}
fn assert_soa(m: &Msg) {
    assert_eq!(m.ns.len(), 1);
    assert_eq!(m.ns[0].ty, 6);
    assert_eq!(m.ns[0].name, "cluster.local");
    let minimum = u32::from_be_bytes(m.ns[0].rdata[m.ns[0].rdata.len() - 4..].try_into().unwrap());
    assert_eq!(minimum, 30);
}

// ---------- zone logic ----------

#[test]
fn clusterip_a_and_nodata_for_other_types() {
    let m = ask("web.default.svc.cluster.local", 1);
    assert_eq!((m.rcode(), m.aa(), m.an.len()), (0, true, 1));
    assert_eq!(ips(&m.an), [[10, 96, 0, 10]]);
    assert_eq!(m.an[0].ttl, 30);
    assert_eq!(m.raw[0..2], [0x12, 0x34]);
    for ty in [16u16, 15] {
        let m = ask("web.default.svc.cluster.local", ty); // TXT / MX
        assert_eq!((m.rcode(), m.an.len()), (0, 0), "type {ty}");
        assert_soa(&m);
    }
}

#[test]
fn aaaa_for_dual_stack_services_and_headless_endpoints() {
    let m = ask("web.default.svc.cluster.local", 28);
    assert_eq!((m.rcode(), m.aa(), m.an.len()), (0, true, 1));
    assert_eq!((m.an[0].ty, &m.an[0].rdata[..]), (28, &WEB6[..]));
    // A still answers only the IPv4 address.
    assert_eq!(ips(&ask("web.default.svc.cluster.local", 1).an), [[10, 96, 0, 10]]);
    // Headless: only the endpoint that has an IPv6 address; the other gives NODATA-free partial.
    let m = ask("db.default.svc.cluster.local", 28);
    assert_eq!(m.an.iter().map(|r| r.rdata.clone()).collect::<Vec<_>>(), vec![DB06.to_vec()]);
    let m = ask("db-0.db.default.svc.cluster.local", 28);
    assert_eq!(m.an.len(), 1);
    let m = ask("db-1.db.default.svc.cluster.local", 28);
    assert_eq!((m.rcode(), m.an.len()), (0, 0));
    assert_soa(&m);
}

#[test]
fn nxdomain_cases() {
    for n in ["nope.default.svc.cluster.local", "web.nowhere.svc.cluster.local", "nowhere.svc.cluster.local", "a.b.c.d.e.svc.cluster.local", "x.cluster.local", "hostx.web.default.svc.cluster.local", "_http._tcp.nope.default.svc.cluster.local", "_nope._tcp.web.default.svc.cluster.local", "300-1-1-1.default.pod.cluster.local"] {
        let m = ask(n, 1);
        assert_eq!(m.rcode(), 3, "{n}");
        assert_soa(&m);
    }
    // existing intermediate names are NODATA
    for n in ["default.svc.cluster.local", "svc.cluster.local", "default.pod.cluster.local", "cluster.local"] {
        let m = ask(n, 1);
        assert_eq!((m.rcode(), m.an.len()), (0, 0), "{n}");
        assert_soa(&m);
    }
}

#[test]
fn apex_soa() {
    let m = ask("cluster.local", 6);
    assert_eq!((m.an.len(), m.an[0].ty, m.an[0].ttl), (1, 6, 30));
    assert_eq!(m.rdname(&m.an[0], 0), "ns.dns.cluster.local");
}

#[test]
fn headless_and_statefulset_hostnames() {
    let m = ask("db.default.svc.cluster.local", 1);
    assert_eq!(ips(&m.an), [[10, 88, 0, 5], [10, 88, 0, 6]]);
    let m = ask("db-1.db.default.svc.cluster.local", 1);
    assert_eq!(ips(&m.an), [[10, 88, 0, 6]]);
    assert_eq!(ask("db-9.db.default.svc.cluster.local", 1).rcode(), 3);
    assert_eq!(ask("db-0.db.default.svc.cluster.local", 28).an.len(), 1);
    // endpoints without hostname are addressable by dashed IP
    assert_eq!(ips(&ask("10-88-1-7.big.default.svc.cluster.local", 1).an), [[10, 88, 1, 7]]);
}

#[test]
fn externalname_cname() {
    for ty in [1u16, 28, 5] {
        let m = ask("ext.default.svc.cluster.local", ty);
        assert_eq!((m.rcode(), m.an.len(), m.an[0].ty), (0, 1, 5), "type {ty}");
        assert_eq!(m.rdname(&m.an[0], 0), "example.com");
    }
}

/// In-cluster ExternalName targets are resolved in the same answer (musl does not chase a
/// CNAME); chains are followed, loops end.
#[test]
fn externalname_in_cluster_target_is_chased() {
    let m = ask("alias.default.svc.cluster.local", 1);
    assert_eq!(m.rcode(), 0);
    assert_eq!(m.an.iter().map(|r| r.ty).collect::<Vec<_>>(), [5, 1]);
    assert_eq!(m.an[1].name, "web.default.svc.cluster.local");
    assert_eq!(ips(&m.an), [[10, 96, 0, 10]]);
    let m = ask("alias2.default.svc.cluster.local", 1);
    assert_eq!(m.an.iter().map(|r| r.ty).collect::<Vec<_>>(), [5, 5, 1]);
    assert_eq!(ips(&m.an), [[10, 96, 0, 10]]);
    // Only the alias when the CNAME itself is asked for; AAAA gets the chain and the target's
    // IPv6 ClusterIP.
    assert_eq!(ask("alias.default.svc.cluster.local", 5).an.len(), 1);
    assert_eq!(ask("alias.default.svc.cluster.local", 28).an.iter().map(|r| r.ty).collect::<Vec<_>>(), [5, 28]);
    let m = ask("loop.default.svc.cluster.local", 1);
    assert!(m.an.len() <= 9 && m.an.iter().all(|r| r.ty == 5));
}

#[test]
fn srv_with_additional_a() {
    let m = ask("_http._tcp.web.default.svc.cluster.local", 33);
    assert_eq!(m.an.len(), 1);
    let r = &m.an[0];
    assert_eq!(r.ty, 33);
    assert_eq!(u16::from_be_bytes([r.rdata[4], r.rdata[5]]), 80);
    assert_eq!(m.rdname(r, 6), "web.default.svc.cluster.local");
    assert_eq!(m.ar.len(), 1);
    assert_eq!((m.ar[0].name.as_str(), m.ar[0].rdata.clone()), ("web.default.svc.cluster.local", vec![10, 96, 0, 10]));
    // headless: one SRV per endpoint, targets resolvable through the additional section
    let m = ask("_sql._tcp.db.default.svc.cluster.local", 33);
    assert_eq!(m.an.len(), 2);
    assert_eq!(m.rdname(&m.an[0], 6), "db-0.db.default.svc.cluster.local");
    assert_eq!(ips(&m.ar), [[10, 88, 0, 5], [10, 88, 0, 6]]);
    let t = ask(&m.rdname(&m.an[1], 6), 1);
    assert_eq!(ips(&t.an), [[10, 88, 0, 6]]);
    // other type on an SRV name: NODATA
    assert_eq!(ask("_http._tcp.web.default.svc.cluster.local", 1).an.len(), 0);
}

#[test]
fn pod_and_ptr() {
    let m = ask("10-1-2-3.default.pod.cluster.local", 1);
    assert_eq!(ips(&m.an), [[10, 1, 2, 3]]);
    let m = ask("10.0.96.10.in-addr.arpa", 12);
    assert_eq!((m.an.len(), m.an[0].ty), (1, 12));
    assert_eq!(m.rdname(&m.an[0], 0), "web.default.svc.cluster.local");
    assert_eq!(ask("10.0.96.10.in-addr.arpa", 1).an.len(), 0); // NODATA
    let m = ask("99.0.96.10.in-addr.arpa", 12);
    assert_eq!(m.rcode(), 3);
    assert_soa(&m);
    assert_eq!(ask("1.0.88.10.in-addr.arpa", 12).rcode(), 3); // pod CIDR, unknown ip
    // outside the cluster CIDRs: forward
    assert_eq!(handle(&query("8.8.8.8.in-addr.arpa", 12), &Fake, false), Answer::Forward);
    assert_eq!(handle(&query("1.0.0.11.in-addr.arpa", 12), &Fake, false), Answer::Forward);
}

#[test]
fn forwarding_decision() {
    assert_eq!(handle(&query("example.com", 1), &Fake, false), Answer::Forward);
    assert_eq!(handle(&query("fakecluster.local", 1), &Fake, false), Answer::Forward); // label boundary
    assert_eq!(handle(&query("local", 1), &Fake, true), Answer::Forward);
}

#[test]
fn case_insensitive_and_case_preserved() {
    let m = ask("WeB.Default.SVC.Cluster.LOCAL", 1);
    assert_eq!(ips(&m.an), [[10, 96, 0, 10]]);
    assert_eq!(m.qname, "WeB.Default.SVC.Cluster.LOCAL");
    assert_eq!(m.an[0].name, "WeB.Default.SVC.Cluster.LOCAL");
    assert_eq!(ips(&ask("DB-0.DB.default.svc.cluster.local", 1).an), [[10, 88, 0, 5]]);
}

#[test]
fn edns_echo_and_truncation() {
    let big = "big.default.svc.cluster.local";
    // plain UDP: 512 bytes, TC, whole records only
    let r = match handle(&query(big, 1), &Fake, false) {
        Answer::Response(r) => r,
        _ => panic!(),
    };
    assert!(r.len() <= 512);
    let m = decode(&r);
    assert!(m.tc() && !m.an.is_empty() && m.an.len() < 50 && m.opt().is_none());
    // EDNS 4096 is capped at 1232, which fits all 50 compressed records (~860 bytes); OPT echoed
    let r = match handle(&query_id(7, big, 1, Some(4096)), &Fake, false) {
        Answer::Response(r) => r,
        _ => panic!(),
    };
    let m = decode(&r);
    assert!(!m.tc() && m.an.len() == 50 && r.len() <= 1232);
    let o = m.opt().unwrap();
    assert_eq!(o.name, "");
    assert_eq!(u16::from_be_bytes([m.raw[o.rd_off - 8], m.raw[o.rd_off - 7]]), 1232); // payload size
    // EDNS 700 truncates to 700 with TC, OPT still present
    let r = match handle(&query_id(7, big, 1, Some(700)), &Fake, false) {
        Answer::Response(r) => r,
        _ => panic!(),
    };
    let m = decode(&r);
    assert!(m.tc() && r.len() <= 700 && r.len() > 650 && m.opt().is_some());
    // EDNS size below 512 is raised to 512
    let r = match handle(&query_id(7, big, 1, Some(100)), &Fake, false) {
        Answer::Response(r) => r,
        _ => panic!(),
    };
    assert!(r.len() <= 512 && r.len() > 400);
    // TCP: everything, no TC
    let m = ask_raw(&query(big, 1), true);
    assert!(!m.tc());
    assert_eq!(m.an.len(), 50);
    // a small answer with EDNS has an OPT and no TC
    let m = ask_raw(&query_id(7, "web.default.svc.cluster.local", 1, Some(1232)), false);
    assert!(!m.tc() && m.opt().is_some() && m.an.len() == 1);
    // EDNS version 1 -> BADVERS (ext rcode 1 in the OPT ttl)
    let mut q = query_id(7, "web.default.svc.cluster.local", 1, Some(1232));
    let n = q.len();
    q[n - 5] = 1; // version byte
    let m = ask_raw(&q, false);
    assert_eq!((m.rcode(), m.opt().unwrap().ttl >> 24), (0, 1));
}

#[test]
fn odd_but_valid_queries() {
    // non-query opcode: NOTIMP; two questions: FORMERR; response bit: dropped
    let mut q = query("web.default.svc.cluster.local", 1);
    q[2] = 0x28; // opcode NOTIFY
    match handle(&q, &Fake, false) {
        Answer::Response(r) => assert_eq!(r[3] & 0xf, 4),
        _ => panic!(),
    }
    let mut q = query("web.default.svc.cluster.local", 1);
    q[5] = 2;
    match handle(&q, &Fake, false) {
        Answer::Response(r) => assert_eq!(r[3] & 0xf, 1),
        _ => panic!(),
    }
    let mut q = query("web.default.svc.cluster.local", 1);
    q[2] |= 0x80;
    assert_eq!(handle(&q, &Fake, false), Answer::Drop);
    // AXFR is refused
    assert_eq!(ask("cluster.local", 252).rcode(), 5);
}

#[test]
fn malformed_never_panics() {
    let base = [
        query("web.default.svc.cluster.local", 1),
        query_id(9, "big.default.svc.cluster.local", 1, Some(4096)),
        query("example.com", 28),
        query("10.0.96.10.in-addr.arpa", 12),
    ];
    // every prefix
    for b in &base {
        for n in 0..b.len() {
            let _ = handle(&b[..n], &Fake, false);
            let _ = handle(&b[..n], &Fake, true);
        }
    }
    // compression loops and forward pointers in the question
    let mut l = query("x.y", 1);
    l[12] = 0xc0;
    l[13] = 12;
    assert_eq!(handle(&l, &Fake, false), Answer::Drop);
    let mut l = query("x.y", 1);
    l[12] = 0xc0;
    l[13] = 40;
    assert_eq!(handle(&l, &Fake, false), Answer::Drop);
    // a pointer inside the additional section pointing at itself
    let mut l = query_id(1, "web.default.svc.cluster.local", 1, Some(512));
    let p = l.len() - 11;
    l[p] = 0xc0;
    l[p + 1] = p as u8;
    assert_eq!(handle(&l, &Fake, false), Answer::Drop);
    // trailing garbage, huge counts, bad label bytes
    let mut t = query("web.default.svc.cluster.local", 1);
    t.push(0);
    assert_eq!(handle(&t, &Fake, false), Answer::Drop);
    let mut h = query("web.default.svc.cluster.local", 1);
    h[10] = 0xff;
    h[11] = 0xff;
    assert_eq!(handle(&h, &Fake, false), Answer::Drop);
    let mut s = query("web.default.svc.cluster.local", 1);
    s[13] = b' ';
    assert_eq!(handle(&s, &Fake, false), Answer::Drop);
    // 0xff-filled and random mutations
    let mut seed = 0x9e3779b97f4a7c15u64;
    let mut rnd = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..20000 {
        let mut m = base[(rnd() % 4) as usize].clone();
        for _ in 0..1 + rnd() % 4 {
            let i = (rnd() as usize) % m.len();
            m[i] = rnd() as u8;
        }
        if rnd() % 4 == 0 {
            m.truncate((rnd() as usize) % m.len());
        }
        let _ = handle(&m, &Fake, rnd() % 2 == 0);
    }
    assert!(matches!(handle(&[0xff; 600], &Fake, false), Answer::Drop | Answer::Response(_)));
}

// ---------- real sockets ----------

fn dns_reply(q: &[u8], rdata: [u8; 4]) -> Vec<u8> {
    // echo header+question as a response with one A record
    let mut r = q.to_vec();
    r[2] = 0x81;
    r[3] = 0x80;
    r[7] = 1;
    r.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
    r.extend_from_slice(&rdata);
    r
}

/// Fake upstream on 127.0.0.1: UDP and TCP on the same port. Answers every A query with
/// 9.9.9.9; with `spoof`, UDP sends a wrong-id forged reply first.
fn fake_upstream(spoof: bool) -> u16 {
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = tcp.local_addr().unwrap().port();
    let udp = UdpSocket::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        let mut b = [0u8; 2048];
        loop {
            let Ok((n, from)) = udp.recv_from(&mut b) else { return };
            if spoof {
                let mut f = dns_reply(&b[..n], [6, 6, 6, 6]);
                f[0] ^= 0xff;
                udp.send_to(&f, from).unwrap();
            }
            udp.send_to(&dns_reply(&b[..n], [9, 9, 9, 9]), from).unwrap();
        }
    });
    std::thread::spawn(move || {
        for s in tcp.incoming() {
            let Ok(mut s) = s else { return };
            std::thread::spawn(move || {
                let mut l = [0u8; 2];
                while s.read_exact(&mut l).is_ok() {
                    let mut q = vec![0u8; u16::from_be_bytes(l) as usize];
                    s.read_exact(&mut q).unwrap();
                    let r = dns_reply(&q, [9, 9, 9, 9]);
                    s.write_all(&(r.len() as u16).to_be_bytes()).unwrap();
                    s.write_all(&r).unwrap();
                }
            });
        }
    });
    port
}

/// Runs the UDP and TCP servers (zone `Fake`, one live upstream and one dead) while `client`
/// runs on a std thread. `client(udp_port, tcp_port)`.
fn with_servers<T: Send + 'static>(spoof: bool, upstream_ports: Vec<u16>, client: impl FnOnce(u16, u16) -> T + Send + 'static) -> T {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let up = if upstream_ports.is_empty() { vec![fake_upstream(spoof)] } else { upstream_ports };
    block_on(async move {
        let u = UdpSocket::bind("127.0.0.1:0").unwrap();
        u.set_nonblocking(true).unwrap();
        let uport = u.local_addr().unwrap().port();
        let usock = kr_rt::exec::Async::new(Fd(u.into_raw_fd())).unwrap();
        let l = listen([127, 0, 0, 1], 0, 128).unwrap();
        let tport = local_addr(&l).unwrap().1;
        let upstream: Vec<SocketAddr> = up.iter().map(|p| SocketAddr { ip: IpAddr::V4([127, 0, 0, 1]), port: *p }).collect();
        let zone: Rc<dyn Zone> = Rc::new(Fake);
        let h1 = spawn(serve_udp(usock, zone.clone(), upstream.clone()));
        let h2 = spawn(serve_tcp(l, zone, upstream));
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(client(uport, tport));
        });
        let r = loop {
            match rx.try_recv() {
                Ok(r) => break r,
                Err(mpsc::TryRecvError::Empty) => sleep(2).await,
                Err(_) => panic!("client died"),
            }
        };
        h1.abort();
        h2.abort();
        r
    })
}

fn udp_ask(port: u16, q: &[u8]) -> Vec<u8> {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.send_to(q, ("127.0.0.1", port)).unwrap();
    let mut b = vec![0u8; 4096];
    let n = s.recv(&mut b).unwrap();
    b.truncate(n);
    b
}

fn tcp_ask(s: &mut TcpStream, q: &[u8]) -> Vec<u8> {
    s.write_all(&(q.len() as u16).to_be_bytes()).unwrap();
    s.write_all(q).unwrap();
    let mut l = [0u8; 2];
    s.read_exact(&mut l).unwrap();
    let mut r = vec![0u8; u16::from_be_bytes(l) as usize];
    s.read_exact(&mut r).unwrap();
    r
}

#[test]
fn e2e_local_answers_udp_and_tcp() {
    with_servers(false, vec![], |up, tp| {
        let m = decode(&udp_ask(up, &query("web.default.svc.cluster.local", 1)));
        assert_eq!(ips(&m.an), [[10, 96, 0, 10]]);
        let m = decode(&udp_ask(up, &query("big.default.svc.cluster.local", 1)));
        assert!(m.tc());
        let mut s = TcpStream::connect(("127.0.0.1", tp)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let m = decode(&tcp_ask(&mut s, &query("big.default.svc.cluster.local", 1)));
        assert!(!m.tc());
        assert_eq!(m.an.len(), 50);
        // pipelined second query on the same connection, and garbage drops UDP silently
        let m = decode(&tcp_ask(&mut s, &query("nope.default.svc.cluster.local", 1)));
        assert_eq!(m.rcode(), 3);
        let g = UdpSocket::bind("127.0.0.1:0").unwrap();
        g.send_to(&[1, 2, 3], ("127.0.0.1", up)).unwrap();
        let m = decode(&udp_ask(up, &query("web.default.svc.cluster.local", 1)));
        assert_eq!(m.an.len(), 1);
    });
}

#[test]
fn e2e_forwarding_with_id_restore_and_spoof_resistance() {
    with_servers(true, vec![], |up, tp| {
        let q = query_id(0xbeef, "example.org", 1, None);
        let r = udp_ask(up, &q);
        assert_eq!(r[0..2], [0xbe, 0xef]); // client id restored
        assert_eq!(ips(&decode(&r).an), [[9, 9, 9, 9]]); // not the forged 6.6.6.6
        let mut s = TcpStream::connect(("127.0.0.1", tp)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let r = tcp_ask(&mut s, &query_id(0x0102, "example.org", 1, None));
        assert_eq!(r[0..2], [1, 2]);
        assert_eq!(ips(&decode(&r).an), [[9, 9, 9, 9]]);
    });
}

#[test]
fn e2e_dead_upstream_fails_over_then_servfail() {
    let dead = {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap().port() // closed again on drop: ICMP port unreachable
    };
    let live = fake_upstream(false);
    with_servers(false, vec![dead, live], |up, _| {
        let m = decode(&udp_ask(up, &query("example.org", 1)));
        assert_eq!(ips(&m.an), [[9, 9, 9, 9]]);
    });
    with_servers(false, vec![dead], |up, tp| {
        let m = decode(&udp_ask(up, &query("example.org", 1)));
        assert_eq!(m.rcode(), 2);
        assert_eq!(m.qname, "example.org");
        let mut s = TcpStream::connect(("127.0.0.1", tp)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(decode(&tcp_ask(&mut s, &query("example.org", 1))).rcode(), 2);
    });
}

#[test]
fn e2e_many_concurrent_forwards() {
    with_servers(false, vec![], |up, _| {
        let hs: Vec<_> = (0..40u16)
            .map(|i| {
                std::thread::spawn(move || {
                    let r = udp_ask(up, &query_id(i, "example.org", 1, None));
                    assert_eq!(u16::from_be_bytes([r[0], r[1]]), i);
                    ips(&decode(&r).an)
                })
            })
            .collect();
        for h in hs {
            assert_eq!(h.join().unwrap(), [[9, 9, 9, 9]]);
        }
    });
}

const PY: &str = r#"
import socket, struct, sys
up, tp = int(sys.argv[1]), int(sys.argv[2])
def q(name, ty, id=0x4242):
    b = struct.pack('>HHHHHH', id, 0x0100, 1, 0, 0, 0)
    for l in name.split('.'): b += bytes([len(l)]) + l.encode()
    return b + b'\0' + struct.pack('>HH', ty, 1)
def udp(p):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
    s.sendto(p, ('127.0.0.1', up)); return s.recv(4096)
def tcp(p):
    s = socket.create_connection(('127.0.0.1', tp), 5)
    s.sendall(struct.pack('>H', len(p)) + p)
    n = struct.unpack('>H', s.recv(2))[0]; d = b''
    while len(d) < n: d += s.recv(n - len(d))
    return d
r = udp(q('web.default.svc.cluster.local', 1))
assert r[:2] == b'\x42\x42' and r[3] & 15 == 0 and r[-4:] == bytes([10, 96, 0, 10]), r
assert udp(q('nope.default.svc.cluster.local', 1))[3] & 15 == 3
r = udp(q('big.default.svc.cluster.local', 1)); assert r[2] & 2 and len(r) <= 512
r = tcp(q('big.default.svc.cluster.local', 1)); assert not r[2] & 2 and struct.unpack('>H', r[6:8])[0] == 50
r = tcp(q('_http._tcp.web.default.svc.cluster.local', 33)); assert struct.unpack('>H', r[6:8])[0] == 1
r = udp(q('example.org', 1)); assert r[-4:] == bytes([9, 9, 9, 9])
print('OK')
"#;

#[test]
fn live_python_client() {
    let have = std::process::Command::new("python3").arg("-c").arg("pass").status().map(|s| s.success()).unwrap_or(false);
    if !have {
        eprintln!("python3 missing; skipping");
        return;
    }
    let out = with_servers(false, vec![], |up, tp| std::process::Command::new("python3").args(["-I", "-c", PY, &up.to_string(), &tp.to_string()]).output().unwrap());
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "OK");
}
