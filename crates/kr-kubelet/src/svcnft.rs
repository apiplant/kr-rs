//! Services, EndpointSlices and hostPorts -> the model of the kernel datapath
//! (`kr_net::nft::proxy`, ADR-054). A pure function of the API lists, so it is unit tested.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use kr_fmt::json::Value;
use kr_net::nft::proxy::{Backend, Frontend, Limit, Model, Policy, Svc};

type Ip = [u8; 16];

fn ip16(s: &str) -> Option<Ip> {
    kr_apiserver::object::parse_ipv4(s).map(kr_sys::map4).or_else(|| kr_net::tcp::parse_ipv6(s))
}

fn is6(ip: &Ip) -> bool {
    kr_sys::unmap4(*ip).is_none()
}

fn meta<'a>(o: &'a Value, f: &str) -> &'a str {
    kr_apiserver::client::meta(o, f)
}

fn proto_of(p: Option<&str>) -> Option<u8> {
    match p {
        Some("UDP") => Some(17),
        Some("TCP") | None => Some(6),
        _ => None, // SCTP: not supported
    }
}

fn str_list<'a>(v: Option<&'a Value>) -> impl Iterator<Item = &'a str> {
    v.and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str)
}

/// The ready endpoints of Service port `pname` as `(address, port, on this node)`.
fn endpoints(svc: &Value, ep: Option<&Value>, slices: &[&Value], pname: &str, node: &str) -> Vec<(Ip, u16, bool)> {
    let mut out = Vec::new();
    let port_of = |ports: Option<&Value>, key: &str| -> Option<u16> {
        ports.and_then(Value::as_array)?.iter().find(|p| p.get("name").and_then(Value::as_str).unwrap_or("") == pname).and_then(|p| p.get(key)).and_then(Value::as_u64).map(|p| p as u16)
    };
    // EndpointSlices win: a Service without a selector may have only hand-written ones.
    for sl in slices {
        let Some(tp) = port_of(sl.get("ports"), "port") else { continue };
        for e in sl.get("endpoints").and_then(Value::as_array).unwrap_or(&[]) {
            if e.pointer(&["conditions", "ready"]).and_then(Value::as_bool) == Some(false) {
                continue;
            }
            let local = e.get("nodeName").and_then(Value::as_str) == Some(node);
            for a in str_list(e.get("addresses")) {
                if let Some(ip) = ip16(a) {
                    out.push((ip, tp, local));
                }
            }
        }
    }
    if slices.is_empty() {
        for sub in ep.and_then(|e| e.get("subsets")).and_then(Value::as_array).unwrap_or(&[]) {
            let Some(tp) = port_of(sub.get("ports"), "port") else { continue };
            for a in sub.get("addresses").and_then(Value::as_array).unwrap_or(&[]) {
                if let Some(ip) = a.get("ip").and_then(Value::as_str).and_then(ip16) {
                    out.push((ip, tp, a.get("nodeName").and_then(Value::as_str) == Some(node)));
                }
            }
        }
    }
    let _ = svc;
    out
}

/// `spec.loadBalancerSourceRanges` as (address, prefix over 128 bits); `None` when the Service
/// has none (everyone may connect).
fn source_ranges(s: &Value) -> Option<Vec<(Ip, u8)>> {
    if s.pointer(&["spec", "type"]).and_then(Value::as_str) != Some("LoadBalancer") {
        return None;
    }
    let list = s.pointer(&["spec", "loadBalancerSourceRanges"]).and_then(Value::as_array).filter(|a| !a.is_empty())?;
    Some(
        list.iter()
            .filter_map(Value::as_str)
            .filter_map(|c| {
                let (a, p) = c.trim().split_once('/')?;
                let ip = ip16(a)?;
                let pre: u8 = p.parse().ok()?;
                Some((ip, if is6(&ip) { pre.min(128) } else { 96 + pre.min(32) }))
            })
            .collect(),
    )
}

pub fn build(svcs: &[Value], eps: &[Value], slices: &[Value], pods: &[Value], node: &str) -> Model {
    let by_name = |o: &Value| (alloc::string::String::from(meta(o, "namespace")), alloc::string::String::from(meta(o, "name")));
    let ep_of: BTreeMap<_, _> = eps.iter().map(|e| (by_name(e), e)).collect();
    let mut slices_of: BTreeMap<_, Vec<&Value>> = BTreeMap::new();
    for sl in slices {
        if let Some(n) = sl.pointer(&["metadata", "labels", "kubernetes.io/service-name"]).and_then(Value::as_str) {
            slices_of.entry((alloc::string::String::from(meta(sl, "namespace")), alloc::string::String::from(n))).or_default().push(sl);
        }
    }
    let mut out: Vec<Svc> = Vec::new();
    for s in svcs {
        // Served by kr itself (cluster DNS), or no virtual IP at all.
        if s.pointer(&["metadata", "annotations", "kr.io/builtin"]).is_some() || s.pointer(&["spec", "type"]).and_then(Value::as_str) == Some("ExternalName") {
            continue;
        }
        let mut cips: Vec<Ip> = str_list(s.pointer(&["spec", "clusterIPs"])).filter_map(ip16).collect();
        if cips.is_empty() {
            cips.extend(s.pointer(&["spec", "clusterIP"]).and_then(Value::as_str).and_then(ip16));
        }
        let key = by_name(s);
        let (ep, own) = (ep_of.get(&key).copied(), slices_of.get(&key).map_or(&[][..], |v| v.as_slice()));
        let affinity = s.pointer(&["spec", "sessionAffinity"]).and_then(Value::as_str) == Some("ClientIP");
        let local_only = s.pointer(&["spec", "externalTrafficPolicy"]).and_then(Value::as_str) == Some("Local");
        let ext_policy = if local_only { Policy::ExternalLocal } else { Policy::External };
        let mut externals: Vec<Ip> = str_list(s.pointer(&["spec", "externalIPs"])).filter_map(ip16).collect();
        let mut ingress: Vec<Ip> = Vec::new();
        for ing in s.pointer(&["status", "loadBalancer", "ingress"]).and_then(Value::as_array).unwrap_or(&[]) {
            let ip = ing.get("ip").and_then(Value::as_str).and_then(ip16);
            externals.extend(ip);
            ingress.extend(ip);
        }
        let ranges = source_ranges(s);
        for p in s.pointer(&["spec", "ports"]).and_then(Value::as_array).unwrap_or(&[]) {
            let Some(proto) = proto_of(p.get("protocol").and_then(Value::as_str)) else { continue };
            let Some(port) = p.get("port").and_then(Value::as_u64).map(|p| p as u16) else { continue };
            let pname = p.get("name").and_then(Value::as_str).unwrap_or("");
            let node_port = p.get("nodePort").and_then(Value::as_u64).filter(|n| *n > 0).map(|n| n as u16);
            let all = endpoints(s, ep, own, pname, node);
            for v6 in [false, true] {
                let mut backends: Vec<Backend> = all.iter().filter(|(ip, _, _)| is6(ip) == v6).map(|&(ip, port, local)| Backend { ip, port, local }).collect();
                backends.sort();
                backends.dedup();
                let mut frontends: Vec<Frontend> = Vec::new();
                for ip in cips.iter().filter(|ip| is6(ip) == v6) {
                    frontends.push(Frontend::Addr { ip: *ip, proto, port, policy: Policy::Plain });
                }
                for ip in externals.iter().filter(|ip| is6(ip) == v6) {
                    frontends.push(Frontend::Addr { ip: *ip, proto, port, policy: ext_policy });
                }
                // A NodePort belongs to the family of the Service's addresses.
                if let Some(np) = node_port {
                    if cips.iter().any(|ip| is6(ip) == v6) {
                        frontends.push(Frontend::Local { v6, ip: None, proto, port: np, policy: ext_policy });
                    }
                }
                // loadBalancerSourceRanges restrict the load-balancer addresses (not the cluster IP,
                // the external IPs or the node ports), as kube-proxy and klipper-lb do.
                let limits: Vec<Limit> = match &ranges {
                    Some(r) => ingress.iter().filter(|ip| is6(ip) == v6).map(|ip| Limit { ip: *ip, proto, port, ranges: r.iter().filter(|(a, _)| is6(a) == v6).copied().collect() }).collect(),
                    None => Vec::new(),
                };
                if !frontends.is_empty() && !backends.is_empty() {
                    out.push(Svc { v6, frontends, backends, affinity, limits });
                }
            }
        }
    }
    host_ports(pods, node, &mut out);
    Model { svcs: out, pod_net4: kr_net::cidr::pod_cidr(), pod_net6: ([0xfd, 0, 0, 0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 32) }
}

/// One frontend per container hostPort of a running pod on this node, backed by the pod address.
fn host_ports(pods: &[Value], node: &str, out: &mut Vec<Svc>) {
    for p in pods {
        if p.pointer(&["status", "phase"]).and_then(Value::as_str) != Some("Running")
            || p.pointer(&["metadata", "deletionTimestamp"]).is_some()
            || p.pointer(&["spec", "hostNetwork"]).and_then(Value::as_bool) == Some(true)
            || p.pointer(&["spec", "nodeName"]).and_then(Value::as_str).is_some_and(|n| n != node)
        {
            continue;
        }
        let mut ips: Vec<Ip> = p.pointer(&["status", "podIPs"]).and_then(Value::as_array).into_iter().flatten().filter_map(|x| x.get("ip").and_then(Value::as_str)).filter_map(ip16).collect();
        if ips.is_empty() {
            ips.extend(p.pointer(&["status", "podIP"]).and_then(Value::as_str).and_then(ip16));
        }
        for c in p.pointer(&["spec", "containers"]).and_then(Value::as_array).unwrap_or(&[]) {
            for pt in c.get("ports").and_then(Value::as_array).unwrap_or(&[]) {
                let (Some(hp), Some(cp)) = (pt.get("hostPort").and_then(Value::as_u64), pt.get("containerPort").and_then(Value::as_u64)) else { continue };
                let Some(proto) = proto_of(pt.get("protocol").and_then(Value::as_str)).filter(|_| hp != 0) else { continue };
                let host_ip = pt.get("hostIP").and_then(Value::as_str).filter(|s| !s.is_empty()).and_then(ip16);
                for pip in &ips {
                    // An explicit hostIP picks the family; otherwise every address family of the pod.
                    if host_ip.is_some_and(|h| is6(&h) != is6(pip)) {
                        continue;
                    }
                    out.push(Svc {
                        v6: is6(pip),
                        frontends: alloc::vec![Frontend::Local { v6: is6(pip), ip: host_ip, proto, port: hp as u16, policy: Policy::Plain }],
                        backends: alloc::vec![Backend { ip: *pip, port: cp as u16, local: true }],
                        affinity: false,
                        ..Default::default()
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn j(s: &str) -> Value {
        kr_fmt::json::parse_str(s).unwrap()
    }

    #[test]
    fn services_become_frontends_and_ready_backends() {
        let svc = j(r#"{"metadata":{"namespace":"d","name":"web"},"spec":{"type":"NodePort","clusterIPs":["10.96.0.20","fd00:96::20"],"externalTrafficPolicy":"Local","externalIPs":["203.0.113.5"],"sessionAffinity":"ClientIP","ports":[{"name":"http","port":80,"nodePort":30080,"protocol":"TCP"},{"name":"dns","port":53,"protocol":"UDP"},{"name":"s","port":1,"protocol":"SCTP"}]},"status":{"loadBalancer":{"ingress":[{"ip":"198.51.100.9"}]}}}"#);
        let slice = j(r#"{"metadata":{"namespace":"d","name":"web-x","labels":{"kubernetes.io/service-name":"web"}},"ports":[{"name":"http","port":8080},{"name":"dns","port":5353}],"endpoints":[{"addresses":["10.88.1.5","fd00:88:0:1::5"],"nodeName":"n1","conditions":{"ready":true}},{"addresses":["10.88.2.5"],"nodeName":"n2"},{"addresses":["10.88.3.5"],"conditions":{"ready":false}}]}"#);
        let m = build(&[svc], &[], &[slice], &[], "n1");
        // http v4, http v6, dns v4, dns v6 (no endpoint of v6 for... fd00:88:0:1::5 serves both ports)
        assert_eq!(m.svcs.len(), 4, "{:?}", m.svcs);
        let http4 = m.svcs.iter().find(|s| !s.v6 && s.frontends.iter().any(|f| matches!(f, Frontend::Local { port: 30080, .. }))).unwrap();
        assert!(http4.affinity);
        assert_eq!(http4.backends.len(), 2); // the not-ready one is left out
        assert_eq!(http4.backends.iter().filter(|b| b.local).count(), 1);
        assert!(http4.frontends.contains(&Frontend::Addr { ip: kr_sys::map4([10, 96, 0, 20]), proto: 6, port: 80, policy: Policy::Plain }));
        assert!(http4.frontends.contains(&Frontend::Addr { ip: kr_sys::map4([203, 0, 113, 5]), proto: 6, port: 80, policy: Policy::ExternalLocal }));
        assert!(http4.frontends.contains(&Frontend::Addr { ip: kr_sys::map4([198, 51, 100, 9]), proto: 6, port: 80, policy: Policy::ExternalLocal }));
        assert!(http4.frontends.contains(&Frontend::Local { v6: false, ip: None, proto: 6, port: 30080, policy: Policy::ExternalLocal }));
        let dns6 = m.svcs.iter().find(|s| s.v6 && s.frontends.iter().any(|f| matches!(f, Frontend::Addr { proto: 17, .. }))).unwrap();
        assert_eq!(dns6.backends.len(), 1);
        assert_eq!(dns6.backends[0].port, 5353);
    }

    #[test]
    fn builtin_and_endpointless_services_get_no_rule() {
        let dns = j(r#"{"metadata":{"namespace":"kube-system","name":"kube-dns","annotations":{"kr.io/builtin":"dns"}},"spec":{"clusterIP":"10.96.0.10","ports":[{"port":53,"protocol":"UDP"}]}}"#);
        let empty = j(r#"{"metadata":{"namespace":"d","name":"none"},"spec":{"clusterIP":"10.96.0.30","ports":[{"port":80}]}}"#);
        assert!(build(&[dns, empty], &[], &[], &[], "n1").svcs.is_empty());
    }

    #[test]
    fn endpoints_objects_serve_services_without_slices() {
        let svc = j(r#"{"metadata":{"namespace":"d","name":"old"},"spec":{"clusterIP":"10.96.0.31","ports":[{"port":80}]}}"#);
        let ep = j(r#"{"metadata":{"namespace":"d","name":"old"},"subsets":[{"addresses":[{"ip":"10.88.1.9","nodeName":"n1"}],"ports":[{"port":9000}]}]}"#);
        let m = build(&[svc], &[ep], &[], &[], "n1");
        assert_eq!(m.svcs.len(), 1);
        assert_eq!(m.svcs[0].backends, alloc::vec![Backend { ip: kr_sys::map4([10, 88, 1, 9]), port: 9000, local: true }]);
    }

    #[test]
    fn host_ports_of_running_pods_on_this_node() {
        let pod = |phase: &str, node: &str, hip: &str| j(&alloc::format!(r#"{{"status":{{"phase":"{phase}","podIP":"10.88.0.5"}},"spec":{{"nodeName":"{node}","containers":[{{"ports":[{{"containerPort":8080,"hostPort":9090,"hostIP":"{hip}","protocol":"UDP"}},{{"containerPort":1}}]}}]}}}}"#));
        let m = build(&[], &[], &[], &[pod("Running", "n1", ""), pod("Pending", "n1", ""), pod("Running", "n2", ""), pod("Running", "n1", "127.0.0.1")], "n1");
        assert_eq!(m.svcs.len(), 2);
        assert_eq!(m.svcs[0].frontends, alloc::vec![Frontend::Local { v6: false, ip: None, proto: 17, port: 9090, policy: Policy::Plain }]);
        assert_eq!(m.svcs[1].frontends, alloc::vec![Frontend::Local { v6: false, ip: Some(kr_sys::map4([127, 0, 0, 1])), proto: 17, port: 9090, policy: Policy::Plain }]);
        assert_eq!(m.svcs[0].backends, alloc::vec![Backend { ip: kr_sys::map4([10, 88, 0, 5]), port: 8080, local: true }]);
    }
}
