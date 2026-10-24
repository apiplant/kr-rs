//! The scheduler: binds pods with an empty `spec.nodeName` to a node.
//!
//! For each pending pod (only `schedulerName` empty or `default-scheduler`) the nodes are
//! filtered on
//!
//! * the `Ready` condition being `True`,
//! * `spec.unschedulable` (modelled as upstream does, a `node.kubernetes.io/unschedulable:
//!   NoSchedule` taint that a pod may tolerate),
//! * `spec.nodeSelector` against node labels,
//! * `NoSchedule`/`NoExecute` taints against the pod's tolerations,
//! * resources: the requests of the pods already bound to the node plus this pod must fit in
//!   `status.allocatable` (cpu, memory, and `pods` when the node advertises it).
//!
//! Survivors are scored by the least-requested fraction (average free share of cpu and memory
//! after placement, higher is better); ties go to the node with fewer pods, then by name. The
//! pod is bound with `POST pods/{name}/binding`. When nothing fits the pod gets
//! `PodScheduled=False, reason Unschedulable` (merge patch on `pods/{name}/status`, only when it
//! changed) and is retried after `Config::retry_ms`; node events also wake all pending pods.

use crate::util::*;
use crate::Config;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_apiserver::client::{Client, Result};
use kr_fmt::json::Value;
use kr_fmt::quantity::Quantity;

/// Sentinel key: every pending pod.
const ALL: &str = "*";

pub async fn run<C: Client + Clone + 'static>(c: C, cfg: Config) {
    let q = Queue::new();
    let mut g = Guard::default();
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), pods(None), String::from("fieldSelector=spec.nodeName%3D"), cfg, move |_, o| q2.add(&key_of(o)))));
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), String::from("/api/v1/nodes"), String::new(), cfg, move |_, _| q2.add(ALL))));
    let c2 = c.clone();
    let q2 = q.clone();
    drive(
        &cfg,
        &q,
        move |key| {
            let c = c2.clone();
            let q = q2.clone();
            async move {
                if key == ALL {
                    for p in items(&c.list(&pods(None), "fieldSelector=spec.nodeName%3D").await?) {
                        q.add(&key_of(&p));
                    }
                    return Ok(None);
                }
                let (ns, n) = split_key(&key);
                schedule_one(&c, &cfg, ns, n).await
            }
        },
        || {
            q.add(ALL);
            async {}
        },
    )
    .await
}

async fn schedule_one<C: Client>(c: &C, cfg: &Config, ns: &str, name: &str) -> Result<Option<u64>> {
    let path = alloc::format!("{}/{name}", pods(Some(ns)));
    let pod = match c.get(&path).await {
        Ok(p) => p,
        Err(e) if e.code == 404 => return Ok(None),
        Err(e) => return Err(e),
    };
    if !str_at(&pod, &["spec", "nodeName"]).is_empty() || deleting(&pod) || pod_terminal(&pod) {
        return Ok(None);
    }
    if !matches!(str_at(&pod, &["spec", "schedulerName"]), "" | "default-scheduler") {
        return Ok(None);
    }
    let nodes = items(&c.list("/api/v1/nodes", "").await?);
    let all_pods = items(&c.list(&pods(None), "").await?);
    match pick(&pod, &nodes, &all_pods) {
        Ok(node) => {
            let body = obj(alloc::vec![
                ("apiVersion", Value::from("v1")),
                ("kind", Value::from("Binding")),
                ("metadata", obj(alloc::vec![("name", Value::from(name))])),
                ("target", obj(alloc::vec![("apiVersion", Value::from("v1")), ("kind", Value::from("Node")), ("name", Value::from(node))])),
            ]);
            match c.create(&alloc::format!("{path}/binding"), &body).await {
                Ok(_) => Ok(None),
                Err(e) if e.code == 409 || e.code == 404 => Ok(None), // already bound / gone
                Err(e) => Err(e),
            }
        }
        Err(msg) => {
            mark_unschedulable(c, cfg, &path, &pod, &msg).await?;
            Ok(Some(cfg.retry_ms))
        }
    }
}

async fn mark_unschedulable<C: Client>(c: &C, cfg: &Config, path: &str, pod: &Value, msg: &str) -> Result<()> {
    let mut conds: Vec<Value> = pod.pointer(&["status", "conditions"]).and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
    if let Some(old) = conds.iter().find(|x| str_at(x, &["type"]) == "PodScheduled") {
        if str_at(old, &["status"]) == "False" && str_at(old, &["reason"]) == "Unschedulable" && str_at(old, &["message"]) == msg {
            return Ok(());
        }
    }
    set_condition(
        &mut conds,
        obj(alloc::vec![
            ("type", Value::from("PodScheduled")),
            ("status", Value::from("False")),
            ("reason", Value::from("Unschedulable")),
            ("message", Value::from(msg)),
            ("lastTransitionTime", Value::String(kr_apiserver::object::rfc3339((cfg.now)()))),
        ]),
    );
    let patch = obj(alloc::vec![("status", obj(alloc::vec![("conditions", Value::Array(conds))]))]);
    match c.patch(&alloc::format!("{path}/status"), MERGE, &patch).await {
        Err(e) if e.code == 404 => Ok(()),
        r => r.map(|_| ()),
    }
}

// ---- filtering and scoring (pure) ----

#[derive(Default, Clone, Copy)]
struct Res {
    cpu_milli: i128,
    mem: i128,
}

fn cpu_milli(v: Option<&Value>) -> i128 {
    v.and_then(Value::as_str).and_then(|s| Quantity::parse(s).ok()).and_then(|q| q.milli_value()).unwrap_or(0)
}

fn bytes(v: Option<&Value>) -> i128 {
    v.and_then(Value::as_str).and_then(|s| Quantity::parse(s).ok()).and_then(|q| q.value()).unwrap_or(0)
}

/// Effective pod requests: the larger of the container sum and the biggest init container.
fn requests(pod: &Value) -> Res {
    let of = |c: &Value| Res { cpu_milli: cpu_milli(c.pointer(&["resources", "requests", "cpu"])), mem: bytes(c.pointer(&["resources", "requests", "memory"])) };
    let mut sum = Res::default();
    for c in pod.pointer(&["spec", "containers"]).and_then(Value::as_array).unwrap_or(&[]) {
        let r = of(c);
        sum.cpu_milli += r.cpu_milli;
        sum.mem += r.mem;
    }
    for c in pod.pointer(&["spec", "initContainers"]).and_then(Value::as_array).unwrap_or(&[]) {
        let r = of(c);
        sum.cpu_milli = sum.cpu_milli.max(r.cpu_milli);
        sum.mem = sum.mem.max(r.mem);
    }
    sum
}

fn node_ready(n: &Value) -> bool {
    n.pointer(&["status", "conditions"]).and_then(Value::as_array).is_some_and(|c| c.iter().any(|x| str_at(x, &["type"]) == "Ready" && str_at(x, &["status"]) == "True"))
}

/// Upstream toleration matching: the effect must match (empty tolerates all), an empty key with
/// operator `Exists` tolerates every taint, otherwise keys must be equal and for `Equal`
/// (the default) so must the values.
pub fn tolerates(tol: &Value, taint: &Value) -> bool {
    let eff = str_at(tol, &["effect"]);
    if !eff.is_empty() && eff != str_at(taint, &["effect"]) {
        return false;
    }
    let key = str_at(tol, &["key"]);
    let op = match str_at(tol, &["operator"]) {
        "" => "Equal",
        o => o,
    };
    if key.is_empty() {
        return op == "Exists";
    }
    if key != str_at(taint, &["key"]) {
        return false;
    }
    match op {
        "Exists" => true,
        "Equal" => str_at(tol, &["value"]) == str_at(taint, &["value"]),
        _ => false,
    }
}

pub fn untolerated_taint(pod: &Value, node: &Value) -> bool {
    let tols = pod.pointer(&["spec", "tolerations"]).and_then(Value::as_array).unwrap_or(&[]);
    let mut taints: Vec<Value> = node.pointer(&["spec", "taints"]).and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
    if node.pointer(&["spec", "unschedulable"]).and_then(Value::as_bool) == Some(true) {
        taints.push(obj(alloc::vec![("key", Value::from("node.kubernetes.io/unschedulable")), ("effect", Value::from("NoSchedule"))]));
    }
    taints.iter().filter(|t| matches!(str_at(t, &["effect"]), "NoSchedule" | "NoExecute")).any(|t| !tols.iter().any(|tol| tolerates(tol, t)))
}

pub fn selector_matches(pod: &Value, node: &Value) -> bool {
    let Some(sel) = pod.pointer(&["spec", "nodeSelector"]).and_then(Value::as_object) else { return true };
    sel.iter().all(|(k, v)| node.pointer(&["metadata", "labels", k]).and_then(Value::as_str) == v.as_str())
}

/// (hostIP, protocol, hostPort) of every container port that asks for a host port.
fn host_ports(pod: &Value) -> Vec<(String, String, u64)> {
    let mut out = Vec::new();
    for c in pod.pointer(&["spec", "containers"]).and_then(Value::as_array).unwrap_or(&[]) {
        for p in c.get("ports").and_then(Value::as_array).unwrap_or(&[]) {
            let hp = p.get("hostPort").and_then(Value::as_u64).unwrap_or(0);
            if hp > 0 {
                let ip = match str_at(p, &["hostIP"]) {
                    "" => "0.0.0.0",
                    s => s,
                };
                let proto = match str_at(p, &["protocol"]) {
                    "" => "TCP",
                    s => s,
                };
                out.push((ip.to_string(), proto.to_string(), hp));
            }
        }
    }
    out
}

/// NodePorts filter: same port and protocol, and equal or wildcard hostIPs.
fn port_conflict(pod: &Value, other: &Value) -> bool {
    let theirs = host_ports(other);
    host_ports(pod).iter().any(|(ip, pr, port)| theirs.iter().any(|(i2, p2, o)| o == port && p2 == pr && (ip == i2 || ip == "0.0.0.0" || i2 == "0.0.0.0")))
}

/// Chooses a node name, or explains (`0/N nodes are available: ...`) why none fits.
fn pick(pod: &Value, nodes: &[Value], all_pods: &[Value]) -> core::result::Result<String, String> {
    let want = requests(pod);
    let (mut not_ready, mut taint, mut selector, mut cpu, mut mem, mut count, mut ports) = (0, 0, 0, 0, 0, 0, 0);
    let mut best: Option<(i128, usize, &str)> = None; // (score, pods on node, name)
    for n in nodes {
        let nname = name(n);
        if !node_ready(n) {
            not_ready += 1;
            continue;
        }
        if !selector_matches(pod, n) {
            selector += 1;
            continue;
        }
        if untolerated_taint(pod, n) {
            taint += 1;
            continue;
        }
        if all_pods.iter().any(|p| str_at(p, &["spec", "nodeName"]) == nname && !pod_terminal(p) && port_conflict(pod, p)) {
            ports += 1;
            continue;
        }
        let mut used = Res::default();
        let mut npods = 0usize;
        for p in all_pods.iter().filter(|p| str_at(p, &["spec", "nodeName"]) == nname && !pod_terminal(p)) {
            let r = requests(p);
            used.cpu_milli += r.cpu_milli;
            used.mem += r.mem;
            npods += 1;
        }
        let alloc_cpu = cpu_milli(n.pointer(&["status", "allocatable", "cpu"]));
        let alloc_mem = bytes(n.pointer(&["status", "allocatable", "memory"]));
        if used.cpu_milli + want.cpu_milli > alloc_cpu {
            cpu += 1;
            continue;
        }
        if used.mem + want.mem > alloc_mem {
            mem += 1;
            continue;
        }
        if let Some(max) = n.pointer(&["status", "allocatable", "pods"]).and_then(Value::as_str).and_then(|s| s.parse::<usize>().ok()) {
            if npods + 1 > max {
                count += 1;
                continue;
            }
        }
        // Least requested: average free permille of cpu and memory after placement.
        let free = |alloc: i128, used: i128, req: i128| if alloc > 0 { (alloc - used - req) * 1000 / alloc } else { 0 };
        let score = (free(alloc_cpu, used.cpu_milli, want.cpu_milli) + free(alloc_mem, used.mem, want.mem)) / 2;
        let better = match best {
            None => true,
            Some((bs, bp, bn)) => (score, core::cmp::Reverse(npods), core::cmp::Reverse(nname)) > (bs, core::cmp::Reverse(bp), core::cmp::Reverse(bn)),
        };
        if better {
            best = Some((score, npods, nname));
        }
    }
    if let Some((_, _, n)) = best {
        return Ok(n.to_string());
    }
    let mut reasons: Vec<String> = Vec::new();
    for (n, what) in [
        (not_ready, "node(s) were not ready"),
        (selector, "node(s) didn't match Pod's node selector"),
        (taint, "node(s) had untolerated taint"),
        (cpu, "Insufficient cpu"),
        (mem, "Insufficient memory"),
        (count, "Too many pods"),
        (ports, "node(s) didn't have free ports for the requested pod ports"),
    ] {
        if n > 0 {
            reasons.push(alloc::format!("{n} {what}"));
        }
    }
    Err(alloc::format!("0/{} nodes are available: {}.", nodes.len(), if reasons.is_empty() { String::from("no nodes registered") } else { reasons.join(", ") }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_fmt::json::parse_str;

    fn v(s: &str) -> Value {
        parse_str(s).unwrap()
    }

    #[test]
    fn toleration_rules() {
        let taint = v(r#"{"key":"k","value":"v","effect":"NoSchedule"}"#);
        assert!(tolerates(&v(r#"{"key":"k","value":"v","effect":"NoSchedule"}"#), &taint));
        assert!(tolerates(&v(r#"{"key":"k","operator":"Exists"}"#), &taint));
        assert!(tolerates(&v(r#"{"operator":"Exists"}"#), &taint));
        assert!(!tolerates(&v(r#"{"key":"k","value":"x"}"#), &taint));
        assert!(!tolerates(&v(r#"{"key":"k","value":"v","effect":"NoExecute"}"#), &taint));
        assert!(!tolerates(&v(r#"{"value":"v"}"#), &taint)); // empty key needs Exists
        assert!(!tolerates(&v(r#"{"key":"other","operator":"Exists"}"#), &taint));
    }

    #[test]
    fn picks_least_requested_then_fewest_pods_then_name() {
        let node = |n: &str| v(&alloc::format!(r#"{{"metadata":{{"name":"{n}"}},"status":{{"conditions":[{{"type":"Ready","status":"True"}}],"allocatable":{{"cpu":"4","memory":"8Gi"}}}}}}"#));
        let pod = v(r#"{"spec":{"containers":[{"resources":{"requests":{"cpu":"1","memory":"1Gi"}}}]}}"#);
        let busy = v(r#"{"spec":{"nodeName":"a","containers":[{"resources":{"requests":{"cpu":"2"}}}]}}"#);
        let nodes = [node("a"), node("b"), node("c")];
        assert_eq!(pick(&pod, &nodes, &[busy]).unwrap(), "b"); // a is busier; b and c tie, name wins
        let big = v(r#"{"spec":{"containers":[{"resources":{"requests":{"cpu":"5"}}}]}}"#);
        assert!(pick(&big, &nodes, &[]).unwrap_err().contains("Insufficient cpu"));
    }

    #[test]
    fn node_ports_filter() {
        let pp = |ip: &str, proto: &str| v(&alloc::format!(r#"{{"spec":{{"nodeName":"a","containers":[{{"ports":[{{"hostPort":80,"hostIP":"{ip}","protocol":"{proto}"}}]}}]}}}}"#));
        assert!(!port_conflict(&pp("10.0.0.1", "TCP"), &pp("10.0.0.2", "TCP")));
        assert!(!port_conflict(&pp("10.0.0.1", "TCP"), &pp("10.0.0.1", "UDP")));
        assert!(port_conflict(&pp("10.0.0.1", "TCP"), &pp("10.0.0.1", "TCP")));
        assert!(port_conflict(&pp("", "TCP"), &pp("10.0.0.2", "TCP")));
        assert!(!port_conflict(&v(r#"{"spec":{"containers":[{"ports":[{"containerPort":80}]}]}}"#), &pp("", "TCP")));
    }
}
