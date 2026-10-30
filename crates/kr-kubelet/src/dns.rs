//! Cluster DNS (CoreDNS replacement): kr-net's authoritative server answering from a snapshot
//! of Services, Endpoints, Namespaces and Pods refreshed every second, bound on the kube-dns
//! ClusterIP (10.96.0.10:53, UDP and TCP) in the node network namespace. Other names are
//! forwarded to the host's resolvers (from the host namespace, so it also works rootless).

use crate::proxy::NodeNet;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;
use kr_apiserver::client::{meta, Client};
use kr_fmt::json::Value;
use kr_net::dnsserver::{self, EndpointRecord, PortRecord, ServiceRecord, Zone};
use kr_net::tcp::{IpAddr, SocketAddr};
use kr_rt::exec::Async;

pub const DNS_IP: [u8; 4] = [10, 96, 0, 10];

#[derive(Default)]
struct Snapshot {
    services: Vec<Value>,
    endpoints: Vec<Value>,
    namespaces: Vec<String>,
    pods: Vec<([u8; 4], Option<[u8; 16]>, String, String)>, // (ip, ipv6, namespace, name)
}

#[derive(Default)]
pub struct ClusterZone {
    snap: RefCell<Snapshot>,
}

fn ip4(s: &str) -> Option<[u8; 4]> {
    kr_apiserver::object::parse_ipv4(s)
}

fn port_records(ports: &[Value]) -> Vec<PortRecord> {
    ports
        .iter()
        .filter_map(|p| {
            Some(PortRecord {
                name: p.get("name").and_then(Value::as_str).unwrap_or("").to_ascii_lowercase(),
                proto: p.get("protocol").and_then(Value::as_str).unwrap_or("TCP").to_ascii_lowercase(),
                port: p.get("port").and_then(Value::as_u64)? as u16,
            })
        })
        .collect()
}

impl ClusterZone {
    fn find<'a>(list: &'a [Value], ns: &str, name: &str) -> Option<&'a Value> {
        list.iter().find(|o| meta(o, "namespace").eq_ignore_ascii_case(ns) && meta(o, "name").eq_ignore_ascii_case(name))
    }

    pub async fn refresh<C: Client>(&self, c: &C) {
        let items = |v: Result<Value, _>| v.ok().and_then(|l| l.get("items").and_then(Value::as_array).map(|a| a.to_vec())).unwrap_or_default();
        let services = items(c.list("/api/v1/services", "").await);
        let endpoints = items(c.list("/api/v1/endpoints", "").await);
        let namespaces = items(c.list("/api/v1/namespaces", "").await).iter().map(|n| meta(n, "name").to_string()).collect();
        let pods = items(c.list("/api/v1/pods", "").await)
            .iter()
            .filter_map(|p| {
                let ip6 = p.pointer(&["status", "podIPs"]).and_then(Value::as_array).and_then(|a| a.iter().filter_map(|x| x.get("ip").and_then(Value::as_str)).find_map(kr_net::tcp::parse_ipv6));
                Some((ip4(p.pointer(&["status", "podIP"])?.as_str()?)?, ip6, meta(p, "namespace").to_string(), meta(p, "name").to_string()))
            })
            .collect();
        *self.snap.borrow_mut() = Snapshot { services, endpoints, namespaces, pods };
    }
}

impl Zone for ClusterZone {
    fn domain(&self) -> &str {
        "cluster.local"
    }

    fn service(&self, ns: &str, name: &str) -> Option<ServiceRecord> {
        let snap = self.snap.borrow();
        let s = Self::find(&snap.services, ns, name)?;
        if s.pointer(&["spec", "type"]).and_then(Value::as_str) == Some("ExternalName") {
            return None;
        }
        let cips: Vec<&str> = s.pointer(&["spec", "clusterIPs"]).and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        let cips = if cips.is_empty() { alloc::vec![s.pointer(&["spec", "clusterIP"]).and_then(Value::as_str).unwrap_or("")] } else { cips };
        Some(ServiceRecord { cluster_ip: cips.iter().find_map(|c| ip4(c)), cluster_ip6: cips.iter().find_map(|c| kr_net::tcp::parse_ipv6(c)), ports: port_records(s.pointer(&["spec", "ports"]).and_then(Value::as_array).unwrap_or(&[])) })
    }

    fn endpoints(&self, ns: &str, name: &str) -> Vec<EndpointRecord> {
        let snap = self.snap.borrow();
        let Some(e) = Self::find(&snap.endpoints, ns, name) else { return Vec::new() };
        let mut out = Vec::new();
        for sub in e.get("subsets").and_then(Value::as_array).unwrap_or(&[]) {
            let ports = port_records(sub.get("ports").and_then(Value::as_array).unwrap_or(&[]));
            for a in sub.get("addresses").and_then(Value::as_array).unwrap_or(&[]) {
                if let Some(ip) = a.get("ip").and_then(Value::as_str).and_then(ip4) {
                    let ip6 = snap.pods.iter().find(|(p, _, _, _)| *p == ip).and_then(|(_, a6, _, _)| *a6);
                    out.push(EndpointRecord { ip, ip6, hostname: a.get("hostname").and_then(Value::as_str).map(String::from), ports: ports.clone() });
                }
            }
        }
        out
    }

    fn external_name(&self, ns: &str, name: &str) -> Option<String> {
        let snap = self.snap.borrow();
        let s = Self::find(&snap.services, ns, name)?;
        (s.pointer(&["spec", "type"]).and_then(Value::as_str) == Some("ExternalName")).then(|| s.pointer(&["spec", "externalName"]).and_then(Value::as_str).unwrap_or("").to_string())
    }

    fn namespace_exists(&self, ns: &str) -> bool {
        self.snap.borrow().namespaces.iter().any(|n| n.eq_ignore_ascii_case(ns))
    }

    fn reverse(&self, ip: [u8; 4]) -> Option<String> {
        let snap = self.snap.borrow();
        for s in &snap.services {
            if s.pointer(&["spec", "clusterIP"]).and_then(Value::as_str).and_then(ip4) == Some(ip) {
                return Some(alloc::format!("{}.{}.svc.cluster.local", meta(s, "name"), meta(s, "namespace")));
            }
        }
        snap.pods.iter().find(|(p, _, _, _)| *p == ip).map(|(_, _, ns, _)| alloc::format!("{}-{}-{}-{}.{ns}.pod.cluster.local", ip[0], ip[1], ip[2], ip[3]))
    }
}

/// Binds the DNS sockets and serves until the process ends.
pub async fn run<C: Client + Clone + 'static>(c: C, net: Rc<NodeNet>) {
    let upstream: Vec<SocketAddr> = kr_net::dns::Config::system()
        .nameservers
        .into_iter()
        .filter(|ip| !matches!(ip, IpAddr::V4(a) if *a == DNS_IP))
        .map(|ip| SocketAddr { ip, port: 53 })
        .collect();
    let zone = Rc::new(ClusterZone::default());
    zone.refresh(&c).await;
    let (udp, tcp) = loop {
        match (net.listen(2, kr_sys::map4(DNS_IP), 53), net.listen(1, kr_sys::map4(DNS_IP), 53)) {
            (Ok(u), Ok(t)) => break (u, t),
            _ => kr_rt::exec::sleep(1000).await, // the service route may not exist yet
        }
    };
    let (Ok(udp), Ok(tcp)) = (Async::new(udp), Async::new(tcp)) else { return };
    let z: Rc<dyn Zone> = zone.clone();
    kr_rt::exec::spawn(dnsserver::serve_udp(udp, z.clone(), upstream.clone()));
    kr_rt::exec::spawn(dnsserver::serve_tcp(tcp, z, upstream));
    loop {
        kr_rt::exec::sleep(1000).await;
        zone.refresh(&c).await;
    }
}
