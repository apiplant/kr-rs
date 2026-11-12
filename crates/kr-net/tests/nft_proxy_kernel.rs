//! Loads the Service datapath (`nft::proxy`) into a kernel and drives traffic through it. Needs
//! nf_tables and `unshare -Urn` (no real root): run `tools/test/nft-proxy.sh`, which builds the
//! network namespaces and calls `apply` below with a scenario name.
use kr_net::nft::proxy::*;
use kr_net::nft::{NpAllow, NpChain, NpPort, PolFam};

fn ip4(a: [u8; 4]) -> [u8; 16] {
    kr_sys::map4(a)
}

fn be(a: [u8; 4], port: u16, local: bool) -> Backend {
    Backend { ip: ip4(a), port, local }
}

fn model(svcs: Vec<Svc>) -> Model {
    Model { svcs, pod_net4: ([10, 88, 0, 0], 16), pod_net6: ([0xfd, 0, 0, 0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 32) }
}

const CIP: [u8; 4] = [10, 96, 0, 50];
const B1: [u8; 4] = [10, 88, 1, 2];
const B2: [u8; 4] = [10, 88, 2, 2];

#[test]
#[ignore]
fn apply() {
    let scenario = std::env::var("KR_NFT_SCENARIO").unwrap_or_default();
    let m = match scenario.as_str() {
        // One endpoint behind a ClusterIP and a NodePort.
        "basic" => model(vec![Svc {
            v6: false,
            frontends: vec![
                Frontend::Addr { ip: ip4(CIP), proto: 6, port: 8080, policy: Policy::Plain },
                Frontend::Local { v6: false, ip: None, proto: 6, port: 30080, policy: Policy::External },
            ],
            backends: vec![be(B1, 9090, false)],
            affinity: false,
        }]),
        // Two endpoints: traffic spreads over both; with affinity one client sticks to one.
        "spread" => model(vec![Svc { v6: false, frontends: vec![Frontend::Addr { ip: ip4(CIP), proto: 6, port: 8080, policy: Policy::Plain }], backends: vec![be(B1, 9090, false), be(B2, 9090, false)], affinity: false }]),
        "affinity" => model(vec![Svc { v6: false, frontends: vec![Frontend::Addr { ip: ip4(CIP), proto: 6, port: 8080, policy: Policy::Plain }], backends: vec![be(B1, 9090, false), be(B2, 9090, false)], affinity: true }]),
        // externalTrafficPolicy: Local with no endpoint on this node: dropped.
        "local-none" => model(vec![Svc { v6: false, frontends: vec![Frontend::Local { v6: false, ip: None, proto: 6, port: 30080, policy: Policy::ExternalLocal }], backends: vec![be(B1, 9090, false)], affinity: false }]),
        // The endpoint is local: served, no masquerade.
        "local-one" => model(vec![Svc { v6: false, frontends: vec![Frontend::Local { v6: false, ip: None, proto: 6, port: 30080, policy: Policy::ExternalLocal }], backends: vec![be(B1, 9090, true)], affinity: false }]),
        // IPv6: a ClusterIP and a NodePort towards an IPv6 endpoint.
        "v6" => {
            let c6 = [0xfd, 0, 0, 0x96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x50];
            let b6 = [0xfd, 0, 0, 0x88, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2];
            model(vec![Svc {
                v6: true,
                frontends: vec![Frontend::Addr { ip: c6, proto: 6, port: 8080, policy: Policy::Plain }, Frontend::Local { v6: true, ip: None, proto: 6, port: 30080, policy: Policy::External }],
                backends: vec![Backend { ip: b6, port: 9090, local: false }],
                affinity: false,
            }])
        }
        "empty" => model(vec![]),
        // NetworkPolicy tables (ADR-049) in the same kernel; the Service of "basic" next to them.
        s if s.starts_with("pol-") => {
            let allow_a = |port: Option<u16>| NpAllow { peer: Some((vec![10, 88, 0, 2], 32)), ports: port.map(|p| vec![NpPort { proto: 6, lo: p, hi: p }]).unwrap_or_default() };
            let ingress_b = |allows: Vec<NpAllow>| NpChain { name: "i4_0".into(), ip: B1.to_vec(), ingress: true, allows };
            let chains = match s {
                // B accepts only A, on 9090 only.
                "pol-a-9090" => vec![ingress_b(vec![allow_a(Some(9090))])],
                // B accepts A and two other pods on 9090: three peers with the same ports become a set.
                "pol-set" => vec![ingress_b(vec![
                    allow_a(Some(9090)),
                    NpAllow { peer: Some((vec![10, 88, 9, 1], 32)), ports: vec![NpPort { proto: 6, lo: 9090, hi: 9090 }] },
                    NpAllow { peer: Some((vec![10, 88, 9, 2], 32)), ports: vec![NpPort { proto: 6, lo: 9090, hi: 9090 }] },
                ])],
                // B accepts nobody.
                "pol-deny-all" => vec![ingress_b(vec![])],
                // A may only talk to B (egress); B itself has no ingress policy.
                "pol-egress" => vec![NpChain { name: "e4_0".into(), ip: vec![10, 88, 0, 2], ingress: false, allows: vec![NpAllow { peer: Some((B1.to_vec(), 32)), ports: vec![] }] }],
                other => panic!("unknown scenario {other:?}"),
            };
            kr_net::nft::ensure_netpol(PolFam::Inet, &chains).unwrap_or_else(|e| panic!("netpol batch refused: errno {}", e.0));
            // The Service goes with it: policy decides after the DNAT, on the real client.
            model(vec![Svc { v6: false, frontends: vec![Frontend::Addr { ip: ip4(CIP), proto: 6, port: 8080, policy: Policy::Plain }], backends: vec![be(B1, 9090, false)], affinity: false }])
        }
        s => panic!("unknown scenario {s:?}"),
    };
    apply_model(&m);
}

fn apply_model(m: &Model) {
    Datapath::new().apply(m).unwrap_or_else(|e| panic!("nft batch refused: errno {}", e.0));
}

fn big(n: u32, backends: u8) -> Model {
    let svcs: Vec<Svc> = (0..n)
        .map(|i| Svc {
            v6: false,
            frontends: vec![Frontend::Addr { ip: ip4([10, 96, (i >> 8) as u8, i as u8]), proto: 6, port: 443, policy: Policy::Plain }, Frontend::Local { v6: false, ip: None, proto: 6, port: 30000 + (i % 2000) as u16, policy: Policy::External }],
            backends: (0..backends).map(|j| be([10, 88, j + 1, 2], 8443, false)).collect(),
            affinity: i % 2 == 0,
        })
        .collect();
    model(svcs)
}

/// Model after model on one Datapath: each switch adds the new generation, repoints `services`
/// and removes the old one (the last model is what the kernel must end up with).
#[test]
#[ignore]
fn apply_sequence() {
    let mut d = Datapath::new();
    for m in [big(40, 3), big(500, 2), big(3, 1), model(vec![]), big(3000, 3), big(10, 3)] {
        let t = std::time::Instant::now();
        d.apply(&m).unwrap_or_else(|e| panic!("errno {}", e.0));
        eprintln!("{} services: {:?}", m.svcs.len(), t.elapsed());
        d.apply(&m).unwrap(); // unchanged: nothing sent
    }
    // The end state serves 10.96.0.1:443 from 10.88.{1,2,3}.2.
    d.apply(&model(vec![Svc { v6: false, frontends: vec![Frontend::Addr { ip: ip4(CIP), proto: 6, port: 8080, policy: Policy::Plain }], backends: vec![be(B1, 9090, false)], affinity: false }])).unwrap();
}


/// IPv6 routes of protocol `RTPROT_KR`: add, dump, delete (the host-gw route cleanup). Run inside
/// a namespace that has `d0` with fd00::1/64 (see tools/test/nft-proxy.sh).
#[test]
#[ignore]
fn ipv6_routes_by_proto() {
    use kr_net::netlink::{Netlink, RTPROT_KR};
    let nl = Netlink::route().unwrap();
    let net = [0xfd, 0, 0, 0x55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let gw = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    nl.route_add6_proto(net, 64, Some(gw), 0, RTPROT_KR).unwrap();
    assert_eq!(nl.routes6_by_proto(RTPROT_KR).unwrap(), vec![(net, 64, Some(gw))]);
    nl.route_del6(net, 64, RTPROT_KR).unwrap();
    assert!(nl.routes6_by_proto(RTPROT_KR).unwrap().is_empty());
}
