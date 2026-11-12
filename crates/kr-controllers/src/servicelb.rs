//! ServiceLB: the load-balancer controller of kr, in the spirit of k3s ServiceLB.
//!
//! kr's Service proxy already listens on every node for a Service's NodePort, so a
//! `type: LoadBalancer` Service is reachable at the node addresses. This controller only
//! publishes them in `status.loadBalancer.ingress`:
//!
//! * `externalTrafficPolicy: Cluster` (default): the InternalIP of every Ready node.
//! * `externalTrafficPolicy: Local`: the InternalIP of the Ready nodes that run a ready endpoint
//!   of the Service (from its EndpointSlices); none when there is none.
//!
//! Only Services with no `spec.loadBalancerClass` or [`CLASS`] are handled; a Service of another
//! class belongs to another load-balancer implementation and is never touched. A Service whose
//! type is no longer `LoadBalancer` gets its ingress cleared. Requires `allocateLoadBalancerNodePorts`
//! (the default) so that the proxy has a node port to listen on.

use crate::endpoints::SERVICE_LABEL;
use crate::util::*;
use crate::Config;
use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_apiserver::client::{Client, Result};
use kr_fmt::json::Value;

/// The `spec.loadBalancerClass` this controller implements (an unset class is handled too).
pub const CLASS: &str = "kr.io/servicelb";

pub async fn run<C: Client + Clone + 'static>(c: C, cfg: Config) {
    let q = Queue::new();
    let mut g = Guard::default();
    let tr = alloc::rc::Rc::new(core::cell::RefCell::new(Tracker::default()));
    for path in [services(None), "/api/v1/nodes".to_string(), endpointslices(None)] {
        let (q2, tr2) = (q.clone(), tr.clone());
        let kind = path.clone();
        g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), path, String::new(), cfg, move |ev, o| {
            let mut t = tr2.borrow_mut();
            let keys = if kind.ends_with("/services") {
                t.service(ev, o)
            } else if kind.ends_with("/nodes") {
                t.node(ev, o)
            } else {
                t.slice(o)
            };
            for k in keys {
                q2.add(&k);
            }
        })));
    }
    let (c2, q2) = (c.clone(), q.clone());
    drive(
        &cfg,
        &q,
        move |key| {
            let c = c2.clone();
            async move {
                match key.split_once('/') {
                    Some((ns, n)) => sync_one(&c, Some((ns, n))).await?,
                    None => sync(&c).await?,
                }
                Ok(None)
            }
        },
        move || {
            q2.add("*");
            async {}
        },
    )
    .await
}

/// Turns watch events into the queue keys that need re-evaluation: `ns/name` for one Service, `*`
/// for all (a Ready node set or address change). Keeps a small cache to tell relevant events
/// (a node heartbeat changes nothing that is published) from irrelevant ones, and to find the
/// Services whose port clash outcome may change.
#[derive(Default)]
pub struct Tracker {
    nodes: alloc::collections::BTreeMap<String, (bool, Vec<String>)>,
    ports: alloc::collections::BTreeMap<String, Vec<(String, i64)>>,
}

impl Tracker {
    pub fn service(&mut self, ev: &str, svc: &Value) -> Vec<String> {
        let key = alloc::format!("{}/{}", namespace(svc), name(svc));
        let mut out = alloc::vec![key.clone()];
        let new = if ev == "DELETED" || str_at(svc, &["spec", "type"]) != "LoadBalancer" { Vec::new() } else { lb_ports(svc) };
        let old = self.ports.get(&key).cloned().unwrap_or_default();
        // Another Service holding or wanting one of these ports may win or lose it now.
        for (k, ps) in &self.ports {
            if *k != key && ps.iter().any(|p| old.contains(p) || new.contains(p)) {
                out.push(k.clone());
            }
        }
        if new.is_empty() {
            self.ports.remove(&key);
        } else {
            self.ports.insert(key, new);
        }
        out
    }

    pub fn node(&mut self, ev: &str, n: &Value) -> Vec<String> {
        let fp = (ev != "DELETED" && node_ready(n) && !deleting(n), if ev == "DELETED" { Vec::new() } else { node_ips(n) });
        let changed = match self.nodes.get(name(n)) {
            Some(old) => *old != fp,
            None => fp.0,
        };
        if fp.0 { self.nodes.insert(name(n).to_string(), fp) } else { self.nodes.remove(name(n)) };
        if changed { alloc::vec!["*".to_string()] } else { Vec::new() }
    }

    pub fn slice(&mut self, s: &Value) -> Vec<String> {
        let svc = str_at(s, &["metadata", "labels", SERVICE_LABEL]);
        if svc.is_empty() { Vec::new() } else { alloc::vec![alloc::format!("{}/{}", namespace(s), svc)] }
    }
}

fn node_ready(n: &Value) -> bool {
    n.pointer(&["status", "conditions"]).and_then(Value::as_array).unwrap_or(&[]).iter().any(|c| str_at(c, &["type"]) == "Ready" && str_at(c, &["status"]) == "True")
}

/// The addresses a node is published with: its ExternalIPs when it has any, else its
/// InternalIPs (as k3s ServiceLB does).
fn node_ips(n: &Value) -> Vec<String> {
    let of = |ty: &str| -> Vec<String> {
        n.pointer(&["status", "addresses"]).and_then(Value::as_array).unwrap_or(&[]).iter().filter(|a| str_at(a, &["type"]) == ty).map(|a| str_at(a, &["address"]).to_string()).collect()
    };
    let ext = of("ExternalIP");
    if ext.is_empty() { of("InternalIP") } else { ext }
}

/// (protocol, port) pairs of a Service's ports.
fn lb_ports(svc: &Value) -> Vec<(String, i64)> {
    svc.pointer(&["spec", "ports"])
        .and_then(Value::as_array)
        .unwrap_or(&[])
        .iter()
        .map(|p| (if str_at(p, &["protocol"]).is_empty() { "TCP".to_string() } else { str_at(p, &["protocol"]).to_string() }, p.get("port").and_then(Value::as_i64).unwrap_or(0)))
        .collect()
}

/// The LoadBalancer Services that lose a port clash: the nodes' proxies listen on one address per
/// (protocol, port), so of two Services asking for the same one only the older (then the first by
/// namespace/name) is served; the other gets no ingress, as with klipper-lb whose second pod
/// stays Pending on the port.
fn losers(svcs: &[Value]) -> BTreeSet<(String, String)> {
    let mut lbs: Vec<&Value> = svcs.iter().filter(|s| ours(s) && !deleting(s) && str_at(s, &["spec", "type"]) == "LoadBalancer").collect();
    lbs.sort_by_key(|s| (str_at(s, &["metadata", "creationTimestamp"]).to_string(), namespace(s).to_string(), name(s).to_string()));
    let mut taken: BTreeSet<(String, i64)> = BTreeSet::new();
    let mut out = BTreeSet::new();
    for s in lbs {
        let ports = lb_ports(s);
        if ports.iter().any(|p| taken.contains(p)) {
            out.insert((namespace(s).to_string(), name(s).to_string()));
        } else {
            taken.extend(ports);
        }
    }
    out
}

/// Whether this controller owns the Service's load balancer.
fn ours(svc: &Value) -> bool {
    matches!(str_at(svc, &["spec", "loadBalancerClass"]), "" | CLASS)
}

fn ingress_of(svc: &Value) -> usize {
    svc.pointer(&["status", "loadBalancer", "ingress"]).and_then(Value::as_array).map_or(0, |a| a.len())
}

/// The ingress addresses of `svc` given the Ready nodes and all EndpointSlices.
fn addresses(svc: &Value, nodes: &[Value], slices: &[Value]) -> Vec<String> {
    let local = str_at(svc, &["spec", "externalTrafficPolicy"]) == "Local";
    let mut with_endpoints: BTreeSet<&str> = BTreeSet::new();
    if local {
        for s in slices.iter().filter(|s| namespace(s) == namespace(svc) && str_at(s, &["metadata", "labels", SERVICE_LABEL]) == name(svc)) {
            for e in s.get("endpoints").and_then(Value::as_array).unwrap_or(&[]) {
                if e.pointer(&["conditions", "ready"]).and_then(Value::as_bool) != Some(false) {
                    with_endpoints.insert(str_at(e, &["nodeName"]));
                }
            }
        }
    }
    let mut ips: Vec<String> = nodes.iter().filter(|n| node_ready(n) && !deleting(n) && (!local || with_endpoints.contains(name(n)))).flat_map(|n| node_ips(n)).collect();
    ips.sort();
    ips.dedup();
    ips
}

/// One pass over all Services.
pub async fn sync<C: Client>(c: &C) -> Result<()> {
    sync_one(c, None).await
}

/// One pass over `only` (namespace, name) or, with `None`, over all Services. The port clashes
/// are still computed from the whole list (a cheap in-memory list), but only the selected
/// Services are written, and the EndpointSlices are read per namespace.
pub async fn sync_one<C: Client>(c: &C, only: Option<(&str, &str)>) -> Result<()> {
    let svcs = items(&c.list(&services(None), "").await?);
    if !svcs.iter().any(|s| ours(s) && (str_at(s, &["spec", "type"]) == "LoadBalancer" || ingress_of(s) > 0)) {
        return Ok(());
    }
    let nodes = items(&c.list("/api/v1/nodes", "").await?);
    let slices = items(&c.list(&endpointslices(only.map(|o| o.0)), "").await?);
    let clashing = losers(&svcs);
    for svc in svcs.iter().filter(|s| ours(s) && !deleting(s) && only.map_or(true, |(ns, n)| namespace(s) == ns && name(s) == n)) {
        let want = if clashing.contains(&(namespace(svc).to_string(), name(svc).to_string())) {
            Vec::new()
        } else if str_at(svc, &["spec", "type"]) == "LoadBalancer" {
            addresses(svc, &nodes, &slices)
        } else if ingress_of(svc) > 0 {
            Vec::new()
        } else {
            continue;
        };
        let path = alloc::format!("{}/{}", services(Some(namespace(svc))), name(svc));
        put_status(c, &path, |cur| {
            let mut st = cur.get("status").cloned().unwrap_or_else(|| obj(Vec::new()));
            let mut lb = obj(Vec::new());
            if !want.is_empty() {
                lb.set("ingress", Value::Array(want.iter().map(|ip| obj(alloc::vec![("ip", Value::from(ip.as_str()))])).collect()));
            }
            st.set("loadBalancer", lb);
            st
        })
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::*;
    use kr_apiserver::client::InProcess;

    fn node(nm: &str, ip: &str, ready: bool) -> Value {
        v(&alloc::format!(
            r#"{{"metadata":{{"name":"{nm}"}},"status":{{"addresses":[{{"type":"InternalIP","address":"{ip}"}},{{"type":"Hostname","address":"{nm}"}}],"conditions":[{{"type":"Ready","status":"{}"}}]}}}}"#,
            if ready { "True" } else { "False" }
        ))
    }

    #[test]
    fn cluster_policy_uses_all_ready_nodes() {
        let nodes = [node("a", "10.0.0.2", true), node("b", "10.0.0.1", true), node("c", "10.0.0.3", false)];
        let svc = v(r#"{"metadata":{"name":"s","namespace":"d"},"spec":{"type":"LoadBalancer"}}"#);
        assert_eq!(addresses(&svc, &nodes, &[]), ["10.0.0.1", "10.0.0.2"]);
    }

    #[test]
    fn local_policy_uses_nodes_with_ready_endpoints() {
        let nodes = [node("a", "10.0.0.1", true), node("b", "10.0.0.2", true), node("c", "10.0.0.3", true)];
        let svc = v(r#"{"metadata":{"name":"s","namespace":"d"},"spec":{"type":"LoadBalancer","externalTrafficPolicy":"Local"}}"#);
        let slices = [
            v(r#"{"metadata":{"name":"s-1","namespace":"d","labels":{"kubernetes.io/service-name":"s"}},"endpoints":[{"nodeName":"b","conditions":{"ready":true}},{"nodeName":"c","conditions":{"ready":false}}]}"#),
            v(r#"{"metadata":{"name":"o-1","namespace":"d","labels":{"kubernetes.io/service-name":"other"}},"endpoints":[{"nodeName":"a"}]}"#),
        ];
        assert_eq!(addresses(&svc, &nodes, &slices), ["10.0.0.2"]);
        assert!(addresses(&svc, &nodes, &[]).is_empty());
    }

    #[test]
    fn external_addresses_win_over_internal_ones() {
        let n = v(r#"{"metadata":{"name":"a"},"status":{"addresses":[{"type":"InternalIP","address":"10.0.0.1"},{"type":"ExternalIP","address":"203.0.113.9"}],"conditions":[{"type":"Ready","status":"True"}]}}"#);
        let svc = v(r#"{"metadata":{"name":"s","namespace":"d"},"spec":{"type":"LoadBalancer"}}"#);
        assert_eq!(addresses(&svc, &[n], &[]), ["203.0.113.9"]);
    }

    #[test]
    fn the_older_service_keeps_a_clashing_port() {
        let mk = |n: &str, ts: &str, port: i64, proto: &str| v(&alloc::format!(r#"{{"metadata":{{"name":"{n}","namespace":"d","creationTimestamp":"{ts}"}},"spec":{{"type":"LoadBalancer","ports":[{{"port":{port},"protocol":"{proto}"}}]}}}}"#));
        let svcs = [mk("new", "2026-02-01T00:00:00Z", 80, "TCP"), mk("old", "2026-01-01T00:00:00Z", 80, "TCP"), mk("udp", "2026-03-01T00:00:00Z", 80, "UDP"), mk("other", "2026-03-01T00:00:00Z", 81, "TCP")];
        let l = losers(&svcs);
        assert_eq!(l.into_iter().map(|(_, n)| n).collect::<Vec<_>>(), ["new"]);
    }

    #[test]
    fn tracker_limits_work_to_affected_services() {
        let lb = |n: &str, port: i64| v(&alloc::format!(r#"{{"metadata":{{"name":"{n}","namespace":"d"}},"spec":{{"type":"LoadBalancer","ports":[{{"port":{port}}}]}}}}"#));
        let mut t = Tracker::default();
        assert_eq!(t.service("ADDED", &lb("a", 80)), ["d/a"]);
        assert_eq!(t.service("ADDED", &lb("b", 81)), ["d/b"]);
        // A Service wanting a taken port re-evaluates the holder; an unrelated one does not.
        assert_eq!(t.service("ADDED", &lb("c", 80)), ["d/c", "d/a"]);
        // Deleting the holder frees the port for the others.
        let mut out = t.service("DELETED", &lb("a", 80));
        out.sort();
        assert_eq!(out, ["d/a", "d/c"]);
        assert_eq!(t.service("MODIFIED", &lb("b", 81)), ["d/b"]);
        let s = v(r#"{"metadata":{"name":"s-1","namespace":"d","labels":{"kubernetes.io/service-name":"b"}}}"#);
        assert_eq!(t.slice(&s), ["d/b"]);
        assert!(t.slice(&v(r#"{"metadata":{"name":"x","namespace":"d"}}"#)).is_empty());
    }

    #[test]
    fn tracker_ignores_node_heartbeats() {
        let mut t = Tracker::default();
        assert_eq!(t.node("ADDED", &node("a", "10.0.0.1", true)), ["*"]);
        assert!(t.node("MODIFIED", &node("a", "10.0.0.1", true)).is_empty());
        assert!(t.node("ADDED", &node("b", "10.0.0.2", false)).is_empty());
        assert_eq!(t.node("MODIFIED", &node("a", "10.0.0.9", true)), ["*"]);
        assert_eq!(t.node("MODIFIED", &node("a", "10.0.0.9", false)), ["*"]);
        assert_eq!(t.node("DELETED", &node("b", "10.0.0.2", true)), Vec::<String>::new());
    }

    #[test]
    fn class_selection() {
        assert!(ours(&v(r#"{"spec":{}}"#)));
        assert!(ours(&v(r#"{"spec":{"loadBalancerClass":"kr.io/servicelb"}}"#)));
        assert!(!ours(&v(r#"{"spec":{"loadBalancerClass":"metallb.io/x"}}"#)));
    }

    #[test]
    fn sync_publishes_ingress_and_skips_foreign_classes() {
        let _l = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let api = alloc::rc::Rc::new(kr_apiserver::api::ApiServer::new(kr_store::Store::in_memory(), || T0, rng, "127.0.0.1:6443".to_string()).unwrap());
        let c = InProcess::new(api, "test");
        kr_rt::exec::block_on(async move {
            c.create("/api/v1/namespaces", &v(r#"{"metadata":{"name":"d"}}"#)).await.unwrap();
            for (n, ip) in [("n1", "10.0.0.1"), ("n2", "10.0.0.2")] {
                c.create("/api/v1/nodes", &v(&alloc::format!(r#"{{"metadata":{{"name":"{n}"}}}}"#))).await.unwrap();
                let st = node(n, ip, true).get("status").cloned().unwrap();
                put_status(&c, &alloc::format!("/api/v1/nodes/{n}"), |_| st.clone()).await.unwrap();
            }
            let mk = |n: &str, extra: &str| {
                v(&alloc::format!(r#"{{"metadata":{{"name":"{n}"}},"spec":{{"type":"LoadBalancer","ports":[{{"port":80}}],"selector":{{"a":"b"}}{extra}}}}}"#))
            };
            c.create("/api/v1/namespaces/d/services", &mk("mine", "")).await.unwrap();
            c.create("/api/v1/namespaces/d/services", &mk("foreign", r#","loadBalancerClass":"metallb.io/x""#)).await.unwrap();
            sync(&c).await.unwrap();
            let mine = c.get("/api/v1/namespaces/d/services/mine").await.unwrap();
            let ips: Vec<&str> = mine.pointer(&["status", "loadBalancer", "ingress"]).and_then(Value::as_array).unwrap().iter().map(|i| str_at(i, &["ip"])).collect();
            assert_eq!(ips, ["10.0.0.1", "10.0.0.2"]);
            let foreign = c.get("/api/v1/namespaces/d/services/foreign").await.unwrap();
            assert_eq!(ingress_of(&foreign), 0);
            // Changing the type away from LoadBalancer clears the ingress.
            c.patch("/api/v1/namespaces/d/services/mine", MERGE, &v(r#"{"spec":{"type":"ClusterIP"}}"#)).await.unwrap();
            sync(&c).await.unwrap();
            assert_eq!(ingress_of(&c.get("/api/v1/namespaces/d/services/mine").await.unwrap()), 0);
        });
    }
}
