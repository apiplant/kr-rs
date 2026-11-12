//! Built-in NetworkPolicy enforcement (k3s's kube-router policy controller, ADR-049).
//!
//! Root nodes with the built-in bridge only. Every few seconds the pods, namespaces and
//! NetworkPolicies are listed, the policy -> per-pod allow-list computation ([`compute`], pure)
//! runs, and when the result changed it is programmed atomically as table `inet kr-netpol`
//! (routed traffic, e.g. between nodes) and `bridge kr-netpol` (traffic between pods of this
//! node on `kr0`). Disabled with `KR_NETWORK_POLICY=off` and whenever an external CNI is
//! configured (`KR_CNI_CONF_DIR`: Calico and friends enforce policies themselves).
//!
//! Semantics follow upstream: policies are additive allow-lists per direction; a pod selected
//! by a policy of a direction accepts/emits only what some rule allows; unselected pods stay
//! open. Traffic is matched on pod IPs. Traffic to or from the node itself (probes, the
//! userspace Service proxy, DNS on the ClusterIP) never crosses the forward hooks, so it is
//! never filtered (issues #165 and the NEW ones in the docs).

use alloc::string::{String, ToString};
use alloc::rc::Rc;
use alloc::vec::Vec;
use kr_apiserver::client::{meta, Client};
use kr_fmt::json::Value;
use kr_net::nft::{NpAllow, NpChain, NpPort, PolFam};

type Labels = Vec<(String, String)>;
type Net = (Vec<u8>, u8);

struct PodInfo {
    ns: String,
    labels: Labels,
    ips: Vec<Vec<u8>>,
    /// (name, IP protocol, number)
    ports: Vec<(String, u8, u16)>,
    local: bool,
}

fn proto_num(p: &str) -> u8 {
    match p {
        "UDP" => 17,
        "SCTP" => 132,
        _ => 6,
    }
}

fn labels_of(v: Option<&Value>) -> Labels {
    v.and_then(Value::as_object).unwrap_or(&[]).iter().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))).collect()
}

/// Label selector match (`None` = absent selector, handled by the caller).
pub fn selector_matches(sel: &Value, labels: &Labels) -> bool {
    let get = |k: &str| labels.iter().find(|(x, _)| x == k).map(|(_, v)| v.as_str());
    for (k, want) in sel.get("matchLabels").and_then(Value::as_object).unwrap_or(&[]) {
        if get(k) != want.as_str() {
            return false;
        }
    }
    for e in sel.get("matchExpressions").and_then(Value::as_array).unwrap_or(&[]) {
        let key = e.get("key").and_then(Value::as_str).unwrap_or("");
        let vals: Vec<&str> = e.get("values").and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(Value::as_str).collect();
        let ok = match e.get("operator").and_then(Value::as_str).unwrap_or("") {
            "In" => get(key).is_some_and(|x| vals.contains(&x)),
            "NotIn" => get(key).is_none_or(|x| !vals.contains(&x)),
            "Exists" => get(key).is_some(),
            "DoesNotExist" => get(key).is_none(),
            _ => false,
        };
        if !ok {
            return false;
        }
    }
    true
}

fn parse_pod(p: &Value, node: &str) -> Option<PodInfo> {
    if p.pointer(&["spec", "hostNetwork"]).and_then(Value::as_bool).unwrap_or(false) {
        return None;
    }
    if matches!(p.pointer(&["status", "phase"]).and_then(Value::as_str), Some("Succeeded" | "Failed")) {
        return None;
    }
    let mut ips: Vec<Vec<u8>> = Vec::new();
    let list = p.pointer(&["status", "podIPs"]).and_then(Value::as_array).unwrap_or(&[]);
    for s in list.iter().filter_map(|x| x.get("ip").and_then(Value::as_str)).chain(p.pointer(&["status", "podIP"]).and_then(Value::as_str)) {
        let b = kr_net::tcp::parse_ipv4(s).map(|a| a.to_vec()).or_else(|| kr_net::tcp::parse_ipv6(s).map(|a| a.to_vec()));
        if let Some(b) = b {
            if !ips.contains(&b) {
                ips.push(b);
            }
        }
    }
    if ips.is_empty() {
        return None;
    }
    let mut ports = Vec::new();
    for c in p.pointer(&["spec", "containers"]).and_then(Value::as_array).unwrap_or(&[]) {
        for cp in c.get("ports").and_then(Value::as_array).unwrap_or(&[]) {
            if let (Some(n), Some(num)) = (cp.get("name").and_then(Value::as_str), cp.get("containerPort").and_then(Value::as_u64)) {
                ports.push((n.to_string(), proto_num(cp.get("protocol").and_then(Value::as_str).unwrap_or("TCP")), num as u16));
            }
        }
    }
    Some(PodInfo {
        ns: meta(p, "namespace").to_string(),
        labels: labels_of(p.pointer(&["metadata", "labels"])),
        ips,
        ports,
        local: p.pointer(&["spec", "nodeName"]).and_then(Value::as_str) == Some(node),
    })
}

/// Parses `a.b.c.d/n` or an IPv6 CIDR.
pub fn parse_cidr(s: &str) -> Option<Net> {
    let (a, n) = match s.split_once('/') {
        Some((a, n)) => (a, Some(n.parse::<u8>().ok()?)),
        None => (s, None),
    };
    let addr = kr_net::tcp::parse_ipv4(a).map(|x| x.to_vec()).or_else(|| kr_net::tcp::parse_ipv6(a).map(|x| x.to_vec()))?;
    let n = n.unwrap_or(addr.len() as u8 * 8);
    (n as usize <= addr.len() * 8).then(|| {
        let mut addr = addr;
        mask(&mut addr, n);
        (addr, n)
    })
}

fn mask(a: &mut [u8], prefix: u8) {
    for (i, b) in a.iter_mut().enumerate() {
        let bits = (prefix as i32 - 8 * i as i32).clamp(0, 8);
        *b &= if bits == 0 { 0 } else { 0xffu8 << (8 - bits) };
    }
}

fn contains(outer: &Net, inner: &Net) -> bool {
    if outer.0.len() != inner.0.len() || outer.1 > inner.1 {
        return false;
    }
    let mut a = inner.0.clone();
    mask(&mut a, outer.1);
    a == outer.0
}

/// `net` minus `ex` as a list of CIDRs (ipBlock `except`).
pub fn subtract(net: &Net, ex: &Net) -> Vec<Net> {
    if net.0.len() != ex.0.len() || contains(ex, net) {
        return if net.0.len() != ex.0.len() { alloc::vec![net.clone()] } else { Vec::new() };
    }
    if !contains(net, ex) {
        return alloc::vec![net.clone()]; // disjoint
    }
    // split net into two halves and recurse into the one holding ex, keeping the other
    let bit = net.1 as usize;
    let mut lo = net.clone();
    lo.1 += 1;
    let mut hi = lo.clone();
    hi.0[bit / 8] |= 0x80 >> (bit % 8);
    let (with, other) = if contains(&lo, ex) { (lo, hi) } else { (hi, lo) };
    let mut v = subtract(&with, ex);
    v.push(other);
    v
}

/// Peer networks of one `from`/`to` entry, with the pod they stand for (for named egress
/// ports). `None` network = any peer. Only addresses of `v6`'s family.
fn peer_nets<'a>(peer: &Value, pol_ns: &str, pods: &'a [PodInfo], nss: &[(String, Labels)], v6: bool) -> Vec<(Option<Net>, Option<&'a PodInfo>)> {
    let len = if v6 { 16 } else { 4 };
    let mut out = Vec::new();
    if let Some(b) = peer.get("ipBlock") {
        if let Some(net) = b.get("cidr").and_then(Value::as_str).and_then(parse_cidr).filter(|n| n.0.len() == len) {
            let mut nets = alloc::vec![net];
            for e in b.get("except").and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(Value::as_str).filter_map(parse_cidr) {
                nets = nets.iter().flat_map(|n| subtract(n, &e)).collect();
            }
            out.extend(nets.into_iter().map(|n| (Some(n), None)));
        }
        return out;
    }
    let ps = peer.get("podSelector");
    let nsel = peer.get("namespaceSelector");
    for p in pods {
        let ns_ok = match nsel {
            None => p.ns == pol_ns,
            Some(sel) => nss.iter().find(|(n, _)| *n == p.ns).is_some_and(|(_, l)| selector_matches(sel, l)),
        };
        if !ns_ok || !ps.is_none_or(|s| selector_matches(s, &p.labels)) {
            continue;
        }
        for ip in p.ips.iter().filter(|i| i.len() == len) {
            out.push((Some((ip.clone(), len as u8 * 8)), Some(p)));
        }
    }
    out
}

/// Ports of a rule resolved against `target` for named ports. `None`: no port restriction.
/// `Some(empty)`: restricted to ports that resolve to nothing.
fn rule_ports(ports: Option<&[Value]>, target: Option<&PodInfo>) -> Option<Vec<NpPort>> {
    let ports = ports.filter(|p| !p.is_empty())?;
    let mut out = Vec::new();
    for p in ports {
        let proto = proto_num(p.get("protocol").and_then(Value::as_str).unwrap_or("TCP"));
        let end = p.get("endPort").and_then(Value::as_u64).map(|e| e as u16);
        let np = match p.get("port") {
            None => Some(NpPort { proto, lo: 0, hi: 0 }),
            Some(v) => match (v.as_u64(), v.as_str()) {
                (Some(n), _) => Some(NpPort { proto, lo: n as u16, hi: end.unwrap_or(n as u16).max(n as u16) }),
                (_, Some(name)) => target.and_then(|t| t.ports.iter().find(|(n, pr, _)| n == name && *pr == proto)).map(|(_, _, n)| NpPort { proto, lo: *n, hi: *n }),
                _ => None,
            },
        };
        if let Some(np) = np {
            if !out.contains(&np) {
                out.push(np);
            }
        }
    }
    Some(out)
}

/// The policy -> per-pod allow-lists computation. Inputs are the API lists' `items`.
pub fn compute(pod_objs: &[Value], ns_objs: &[Value], policies: &[Value], node: &str) -> Vec<NpChain> {
    let pods: Vec<PodInfo> = pod_objs.iter().filter_map(|p| parse_pod(p, node)).collect();
    let nss: Vec<(String, Labels)> = ns_objs
        .iter()
        .map(|n| {
            let name = meta(n, "name").to_string();
            let mut l = labels_of(n.pointer(&["metadata", "labels"]));
            if !l.iter().any(|(k, _)| k == "kubernetes.io/metadata.name") {
                l.push((String::from("kubernetes.io/metadata.name"), name.clone()));
            }
            (name, l)
        })
        .collect();
    let mut chains: Vec<NpChain> = Vec::new();
    for t in pods.iter().filter(|p| p.local) {
        for ip in &t.ips {
            let v6 = ip.len() == 16;
            for ingress in [true, false] {
                let mut selected = false;
                let mut allows: Vec<NpAllow> = Vec::new();
                for pol in policies.iter().filter(|p| meta(p, "namespace") == t.ns) {
                    let spec = match pol.get("spec") {
                        Some(s) => s,
                        None => continue,
                    };
                    let empty = Value::Object(Vec::new());
                    if !selector_matches(spec.get("podSelector").unwrap_or(&empty), &t.labels) {
                        continue;
                    }
                    let types: Vec<&str> = match spec.get("policyTypes").and_then(Value::as_array) {
                        Some(a) if !a.is_empty() => a.iter().filter_map(Value::as_str).collect(),
                        _ if spec.get("egress").is_some() => alloc::vec!["Ingress", "Egress"],
                        _ => alloc::vec!["Ingress"],
                    };
                    let (ty, key, peers_key) = if ingress { ("Ingress", "ingress", "from") } else { ("Egress", "egress", "to") };
                    if !types.contains(&ty) {
                        continue;
                    }
                    selected = true;
                    for rule in spec.get(key).and_then(Value::as_array).unwrap_or(&[]) {
                        let peers = rule.get(peers_key).and_then(Value::as_array).unwrap_or(&[]);
                        let rports = rule.get("ports").and_then(Value::as_array);
                        let mut push = |peer: Option<Net>, target: Option<&PodInfo>| {
                            // ingress: named ports are the selected pod's; egress: the peer's
                            let tgt = if ingress { Some(t) } else { target };
                            match rule_ports(rports, tgt) {
                                None => allows.push(NpAllow { peer, ports: Vec::new() }),
                                Some(p) if !p.is_empty() => allows.push(NpAllow { peer, ports: p }),
                                Some(_) => {}
                            }
                        };
                        if peers.is_empty() {
                            push(None, None);
                        }
                        for peer in peers {
                            for (net, tp) in peer_nets(peer, &t.ns, &pods, &nss, v6) {
                                push(net, tp);
                            }
                        }
                    }
                }
                if selected {
                    allows.sort();
                    allows.dedup();
                    let name = alloc::format!("{}{}_{}", if ingress { "i" } else { "e" }, if v6 { 6 } else { 4 }, chains.len());
                    chains.push(NpChain { name, ip: ip.clone(), ingress, allows });
                }
            }
        }
    }
    chains
}

fn items<E>(v: Result<Value, E>) -> Option<Vec<Value>> {
    v.ok().and_then(|l| l.get("items").and_then(Value::as_array).map(|a| a.to_vec()))
}

/// Whether enforcement runs: not with an external CNI, not with `KR_NETWORK_POLICY=off`.
pub fn enabled() -> bool {
    if crate::cni::conf_dir().is_some() {
        return false;
    }
    !matches!(kr_runtime::store::env_var("KR_NETWORK_POLICY").as_deref(), Some("off" | "0" | "false"))
}

fn program(chains: &[NpChain]) -> bool {
    let mut ok = true;
    for fam in [PolFam::Inet, PolFam::Bridge] {
        if let Err(e) = kr_net::nft::ensure_netpol(fam, chains) {
            ok = false;
            let which = if fam == PolFam::Inet { "inet" } else { "bridge" };
            kr_rt::eprint(alloc::format!("kubelet: network policy table {which} kr-netpol: errno {}\n", e.0).as_bytes());
        }
    }
    ok
}

/// Controller loop (root nodes with the built-in bridge). Returns at once when disabled; then
/// removes tables a previous run (with enforcement on) left behind.
pub async fn run<C: Client + Clone + 'static>(c: C, node: String) {
    if !enabled() {
        for fam in [PolFam::Inet, PolFam::Bridge] {
            let _ = kr_net::nft::delete_netpol(fam);
        }
        return;
    }
    // Pods, namespaces and policies are watched: a change recomputes the rules within about half a
    // second (bursts coalesce); the periodic pass repairs missed events and tables
    // somebody flushed.
    let wake = Rc::new(crate::Notify::default());
    for path in ["/api/v1/pods", "/api/v1/namespaces", "/apis/networking.k8s.io/v1/networkpolicies"] {
        let (c, wake) = (c.clone(), wake.clone());
        kr_rt::exec::spawn(async move {
            loop {
                if let Ok(mut w) = c.watch(path, "").await {
                    while w.next().await.is_some() {
                        wake.notify();
                    }
                }
                kr_rt::exec::sleep(1000).await;
            }
        });
    }
    let mut last: Option<Vec<NpChain>> = None;
    loop {
        let got = (
            items(c.list("/api/v1/pods", "").await),
            items(c.list("/api/v1/namespaces", "").await),
            items(c.list("/apis/networking.k8s.io/v1/networkpolicies", "").await),
        );
        // a failed list keeps the current rules
        if let (Some(pods), Some(nss), Some(pols)) = got {
            let chains = compute(&pods, &nss, &pols, &node);
            if last.as_ref() != Some(&chains) && program(&chains) {
                last = Some(chains);
            }
        }
        wake.wait(30_000).await;
        kr_rt::exec::sleep(500).await; // let a burst of changes finish; bounds the work under churn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn j(s: &str) -> Value {
        kr_fmt::json::parse(s.as_bytes()).unwrap()
    }

    fn pod(ns: &str, name: &str, ip: &str, labels: &str, node: &str) -> Value {
        j(&alloc::format!(
            r#"{{"metadata":{{"namespace":"{ns}","name":"{name}","labels":{labels}}},"spec":{{"nodeName":"{node}","containers":[{{"name":"c","ports":[{{"name":"http","containerPort":8080}},{{"name":"dns","containerPort":53,"protocol":"UDP"}}]}}]}},"status":{{"podIP":"{ip}","podIPs":[{{"ip":"{ip}"}}]}}}}"#
        ))
    }

    fn nsobj(n: &str, labels: &str) -> Value {
        j(&alloc::format!(r#"{{"metadata":{{"name":"{n}","labels":{labels}}}}}"#))
    }

    fn pol(ns: &str, spec: &str) -> Value {
        j(&alloc::format!(r#"{{"metadata":{{"namespace":"{ns}","name":"p"}},"spec":{spec}}}"#))
    }

    fn world() -> (Vec<Value>, Vec<Value>) {
        (
            alloc::vec![
                pod("a", "web", "10.88.0.2", r#"{"app":"web"}"#, "n1"),
                pod("a", "client", "10.88.0.3", r#"{"app":"client"}"#, "n1"),
                pod("a", "other", "10.88.0.4", r#"{"app":"other"}"#, "n2"),
                pod("b", "far", "10.88.1.5", r#"{"app":"client"}"#, "n2"),
                pod("a", "v6", "fd00::7", r#"{"app":"client"}"#, "n2"),
            ],
            alloc::vec![nsobj("a", r#"{"team":"x"}"#), nsobj("b", r#"{"team":"y"}"#)],
        )
    }

    fn net(a: [u8; 4], p: u8) -> Option<Net> {
        Some((a.to_vec(), p))
    }

    fn chain<'a>(c: &'a [NpChain], ip: [u8; 4], ingress: bool) -> Option<&'a NpChain> {
        c.iter().find(|x| x.ip == ip && x.ingress == ingress)
    }

    #[test]
    fn unselected_pods_are_open() {
        let (p, n) = world();
        assert!(compute(&p, &n, &[], "n1").is_empty());
        let pl = [pol("a", r#"{"podSelector":{"matchLabels":{"app":"nothing"}}}"#)];
        assert!(compute(&p, &n, &pl, "n1").is_empty());
        // other namespace's policy does not select
        let pl = [pol("b", r#"{"podSelector":{}}"#)];
        assert!(compute(&p, &n, &pl, "n1").is_empty());
    }

    #[test]
    fn default_deny_ingress_only() {
        let (p, n) = world();
        let pl = [pol("a", r#"{"podSelector":{}}"#)];
        let c = compute(&p, &n, &pl, "n1");
        // web and client (local, ns a); no egress chain, empty allow list = deny all
        assert_eq!(c.len(), 2);
        assert!(c.iter().all(|x| x.ingress && x.allows.is_empty()));
        assert!(chain(&c, [10, 88, 0, 2], true).is_some() && chain(&c, [10, 88, 0, 3], true).is_some());
    }

    #[test]
    fn policy_types_egress_and_defaults() {
        let (p, n) = world();
        let c = compute(&p, &n, &[pol("a", r#"{"podSelector":{"matchLabels":{"app":"web"}},"policyTypes":["Egress"]}"#)], "n1");
        assert_eq!(c.len(), 1);
        assert!(!c[0].ingress && c[0].allows.is_empty());
        // an egress section without policyTypes selects both directions
        let c = compute(&p, &n, &[pol("a", r#"{"podSelector":{"matchLabels":{"app":"web"}},"egress":[{}]}"#)], "n1");
        assert_eq!(c.len(), 2);
        assert_eq!(chain(&c, [10, 88, 0, 2], false).unwrap().allows, alloc::vec![NpAllow { peer: None, ports: Vec::new() }]);
        assert!(chain(&c, [10, 88, 0, 2], true).unwrap().allows.is_empty());
    }

    #[test]
    fn pod_selector_peer_and_additive() {
        let (p, n) = world();
        let pl = [
            pol("a", r#"{"podSelector":{"matchLabels":{"app":"web"}},"ingress":[{"from":[{"podSelector":{"matchLabels":{"app":"client"}}}]}]}"#),
            pol("a", r#"{"podSelector":{"matchExpressions":[{"key":"app","operator":"In","values":["web"]}]},"ingress":[{"from":[{"podSelector":{"matchLabels":{"app":"other"}}}]}]}"#),
        ];
        let c = compute(&p, &n, &pl, "n1");
        assert_eq!(c.len(), 1);
        let a = &c[0].allows;
        // client (same ns, v4), other: additive; the v6 pod and the other namespace's pod are not peers
        assert_eq!(a.len(), 2);
        assert!(a.iter().any(|x| x.peer == net([10, 88, 0, 3], 32)));
        assert!(a.iter().any(|x| x.peer == net([10, 88, 0, 4], 32)));
    }

    #[test]
    fn namespace_selector_and_and() {
        let (p, n) = world();
        let c = compute(&p, &n, &[pol("a", r#"{"podSelector":{"matchLabels":{"app":"web"}},"ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"team":"y"}}}]}]}"#)], "n1");
        assert_eq!(c[0].allows.len(), 1);
        assert_eq!(c[0].allows[0].peer, net([10, 88, 1, 5], 32));
        // AND: namespaceSelector + podSelector in one peer
        let c = compute(&p, &n, &[pol("a", r#"{"podSelector":{"matchLabels":{"app":"web"}},"ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"team":"y"}},"podSelector":{"matchLabels":{"app":"zzz"}}}]}]}"#)], "n1");
        assert!(c[0].allows.is_empty());
        // two peers = OR
        let c = compute(&p, &n, &[pol("a", r#"{"podSelector":{"matchLabels":{"app":"web"}},"ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"team":"y"}}},{"podSelector":{"matchLabels":{"app":"other"}}}]}]}"#)], "n1");
        assert_eq!(c[0].allows.len(), 2);
        // well-known namespace label
        let c = compute(&p, &n, &[pol("a", r#"{"podSelector":{"matchLabels":{"app":"web"}},"ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"b"}}}]}]}"#)], "n1");
        assert_eq!(c[0].allows[0].peer, net([10, 88, 1, 5], 32));
    }

    #[test]
    fn empty_from_allows_all_and_ports() {
        let (p, n) = world();
        let c = compute(&p, &n, &[pol("a", r#"{"podSelector":{"matchLabels":{"app":"web"}},"ingress":[{"ports":[{"port":80},{"protocol":"UDP","port":1000,"endPort":2000},{"protocol":"SCTP"}]}]}"#)], "n1");
        assert_eq!(c[0].allows.len(), 1);
        let a = &c[0].allows[0];
        assert_eq!(a.peer, None);
        assert_eq!(a.ports, alloc::vec![NpPort { proto: 6, lo: 80, hi: 80 }, NpPort { proto: 17, lo: 1000, hi: 2000 }, NpPort { proto: 132, lo: 0, hi: 0 }]);
    }

    #[test]
    fn named_ports() {
        let (p, n) = world();
        // ingress: resolved against the selected pod
        let c = compute(&p, &n, &[pol("a", r#"{"podSelector":{"matchLabels":{"app":"web"}},"ingress":[{"ports":[{"port":"http"},{"port":"dns","protocol":"UDP"},{"port":"nope"}]}]}"#)], "n1");
        assert_eq!(c[0].allows[0].ports, alloc::vec![NpPort { proto: 6, lo: 8080, hi: 8080 }, NpPort { proto: 17, lo: 53, hi: 53 }]);
        // ports that resolve to nothing allow nothing
        let c = compute(&p, &n, &[pol("a", r#"{"podSelector":{"matchLabels":{"app":"web"}},"ingress":[{"ports":[{"port":"nope"}]}]}"#)], "n1");
        assert!(c[0].allows.is_empty());
        // egress: the peer pod's named port; ipBlock peers cannot resolve names
        let c = compute(&p, &n, &[pol("a", r#"{"podSelector":{"matchLabels":{"app":"web"}},"policyTypes":["Egress"],"egress":[{"to":[{"podSelector":{"matchLabels":{"app":"other"}}},{"ipBlock":{"cidr":"10.0.0.0/8"}}],"ports":[{"port":"http"}]}]}"#)], "n1");
        assert_eq!(c[0].allows.len(), 1);
        assert_eq!(c[0].allows[0].peer, net([10, 88, 0, 4], 32));
    }

    #[test]
    fn ipblock_except_and_families() {
        let (p, n) = world();
        let c = compute(&p, &n, &[pol("a", r#"{"podSelector":{"matchLabels":{"app":"web"}},"ingress":[{"from":[{"ipBlock":{"cidr":"10.0.0.0/8","except":["10.1.0.0/16"]}},{"ipBlock":{"cidr":"fd00::/8"}}]}]}"#)], "n1");
        assert_eq!(c.len(), 1); // web has a v4 address only: the v6 block is ignored
        let nets: Vec<&Net> = c[0].allows.iter().filter_map(|a| a.peer.as_ref()).collect();
        assert_eq!(nets.len(), 8); // /8 minus a /16 = one block per prefix length 9..=16
        let covered = |ip: [u8; 4]| nets.iter().any(|x| contains(x, &(ip.to_vec(), 32)));
        assert!(covered([10, 0, 0, 1]) && covered([10, 2, 0, 1]) && covered([10, 255, 255, 255]));
        assert!(!covered([10, 1, 2, 3]) && !covered([11, 0, 0, 1]));
    }

    #[test]
    fn subtract_cases() {
        let a = parse_cidr("10.0.0.0/8").unwrap();
        assert!(subtract(&a, &parse_cidr("10.0.0.0/8").unwrap()).is_empty());
        assert!(subtract(&a, &parse_cidr("0.0.0.0/0").unwrap()).is_empty());
        assert_eq!(subtract(&a, &parse_cidr("11.0.0.0/8").unwrap()), alloc::vec![a.clone()]);
        let r = subtract(&a, &parse_cidr("10.128.0.0/9").unwrap());
        assert_eq!(r, alloc::vec![parse_cidr("10.0.0.0/9").unwrap()]);
        assert_eq!(parse_cidr("10.1.2.3/8"), Some((alloc::vec![10, 0, 0, 0], 8)));
        assert_eq!(parse_cidr("10.0.0.0/33"), None);
    }

    #[test]
    fn v6_pods_get_v6_chains() {
        let (p, n) = world();
        let c = compute(&p, &n, &[pol("a", r#"{"podSelector":{"matchLabels":{"app":"client"}},"ingress":[{"from":[{"podSelector":{"matchLabels":{"app":"client"}}}]}]}"#)], "n2");
        // local pods on n2 in ns a: other (v4, not client) and v6 (client)
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].ip.len(), 16);
        assert_eq!(c[0].allows.len(), 1);
        assert_eq!(c[0].allows[0].peer.as_ref().unwrap().0.len(), 16);
    }

    #[test]
    fn host_network_and_finished_pods_are_ignored() {
        let mut hn = pod("a", "hn", "10.88.0.9", "{}", "n1");
        if let Some(sp) = hn.as_object_mut().and_then(|o| o.iter_mut().find(|(k, _)| k == "spec")) {
            sp.1.as_object_mut().unwrap().push((String::from("hostNetwork"), Value::Bool(true)));
        }
        let done = j(r#"{"metadata":{"namespace":"a","name":"d"},"spec":{"nodeName":"n1"},"status":{"phase":"Succeeded","podIP":"10.88.0.8"}}"#);
        let c = compute(&[hn, done], &[nsobj("a", "{}")], &[pol("a", r#"{"podSelector":{}}"#)], "n1");
        assert!(c.is_empty());
    }

    #[test]
    fn disabled_with_external_cni_or_switch() {
        // enabled() reads the process environment: only the default can be asserted here.
        assert!(enabled());
    }
}
