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
    for path in [services(None), "/api/v1/nodes".to_string(), endpointslices(None)] {
        let q2 = q.clone();
        g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), path, String::new(), cfg, move |_, _| q2.add("*"))));
    }
    let (c2, q2) = (c.clone(), q.clone());
    drive(
        &cfg,
        &q,
        move |_| {
            let c = c2.clone();
            async move {
                sync(&c).await?;
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

fn node_ready(n: &Value) -> bool {
    n.pointer(&["status", "conditions"]).and_then(Value::as_array).unwrap_or(&[]).iter().any(|c| str_at(c, &["type"]) == "Ready" && str_at(c, &["status"]) == "True")
}

fn internal_ips(n: &Value) -> Vec<String> {
    n.pointer(&["status", "addresses"])
        .and_then(Value::as_array)
        .unwrap_or(&[])
        .iter()
        .filter(|a| str_at(a, &["type"]) == "InternalIP")
        .map(|a| str_at(a, &["address"]).to_string())
        .collect()
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
    let mut ips: Vec<String> = nodes.iter().filter(|n| node_ready(n) && !deleting(n) && (!local || with_endpoints.contains(name(n)))).flat_map(internal_ips).collect();
    ips.sort();
    ips.dedup();
    ips
}

/// One pass over all Services.
pub async fn sync<C: Client>(c: &C) -> Result<()> {
    let svcs = items(&c.list(&services(None), "").await?);
    if !svcs.iter().any(|s| ours(s) && (str_at(s, &["spec", "type"]) == "LoadBalancer" || ingress_of(s) > 0)) {
        return Ok(());
    }
    let nodes = items(&c.list("/api/v1/nodes", "").await?);
    let slices = items(&c.list(&endpointslices(None), "").await?);
    for svc in svcs.iter().filter(|s| ours(s) && !deleting(s)) {
        let want = if str_at(svc, &["spec", "type"]) == "LoadBalancer" {
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
