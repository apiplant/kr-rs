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
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use core::cell::RefCell;
use alloc::vec::Vec;
use kr_apiserver::client::{Client, Result};
use kr_fmt::json::Value;
use kr_fmt::quantity::Quantity;

/// Sentinel key: every pending pod.
const ALL: &str = "*";

/// How long a node/pod snapshot is reused across scheduling decisions.
const SNAPSHOT_MS: u64 = 1000;

/// Nodes and pods as of `at`, shared by the decisions of one burst: listing every pod for every
/// pod made a 1000-replica Deployment quadratic. Bindings made since are applied to it.
struct Snapshot {
    at: u64,
    nodes: Rc<Vec<Value>>,
    pods: Rc<Vec<Value>>,
}

type Snap = Rc<RefCell<Option<Snapshot>>>;

async fn snapshot<C: Client>(c: &C, snap: &Snap) -> Result<(Rc<Vec<Value>>, Rc<Vec<Value>>)> {
    let now = kr_rt::exec::now_ms();
    if let Some(s) = snap.borrow().as_ref().filter(|s| now.saturating_sub(s.at) < SNAPSHOT_MS) {
        return Ok((s.nodes.clone(), s.pods.clone()));
    }
    let nodes = Rc::new(items(&c.list("/api/v1/nodes", "").await?));
    let pods = Rc::new(items(&c.list(&pods(None), "").await?));
    *snap.borrow_mut() = Some(Snapshot { at: kr_rt::exec::now_ms(), nodes: nodes.clone(), pods: pods.clone() });
    Ok((nodes, pods))
}

/// Records a binding in the snapshot, so the next decisions count the pod on its node.
fn bound(snap: &Snap, pod: &Value, node: &str) {
    let mut b = snap.borrow_mut();
    let Some(s) = b.as_mut() else { return };
    let pods = Rc::make_mut(&mut s.pods);
    let uid = str_at(pod, &["metadata", "uid"]);
    let mut p = pod.clone();
    p.entry_object("spec").set("nodeName", Value::from(node));
    match pods.iter_mut().find(|x| str_at(x, &["metadata", "uid"]) == uid) {
        Some(x) => *x = p,
        None => pods.push(p),
    }
}

pub async fn run<C: Client + Clone + 'static>(c: C, cfg: Config) {
    let q = Queue::new();
    let mut g = Guard::default();
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), pods(None), String::from("fieldSelector=spec.nodeName%3D"), cfg, move |_, o| q2.add(&key_of(o)))));
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), String::from("/api/v1/nodes"), String::new(), cfg, move |_, _| q2.add(ALL))));
    let c2 = c.clone();
    let q2 = q.clone();
    let snap: Snap = Rc::new(RefCell::new(None));
    drive(
        &cfg,
        &q,
        move |key| {
            let c = c2.clone();
            let q = q2.clone();
            let snap = snap.clone();
            async move {
                if key == ALL {
                    for p in items(&c.list(&pods(None), "fieldSelector=spec.nodeName%3D").await?) {
                        q.add(&key_of(&p));
                    }
                    return Ok(None);
                }
                let (ns, n) = split_key(&key);
                schedule_one(&c, &cfg, &snap, ns, n).await
            }
        },
        || {
            q.add(ALL);
            async {}
        },
    )
    .await
}

async fn schedule_one<C: Client>(c: &C, cfg: &Config, snap: &Snap, ns: &str, name: &str) -> Result<Option<u64>> {
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
    let (nodes, all_pods) = snapshot(c, snap).await?;
    if let Some(why) = unbound_claim(c, ns, &pod).await? {
        let msg = alloc::format!("0/{} nodes are available: {why}.", nodes.len());
        mark_unschedulable(c, cfg, &path, &pod, &msg).await?;
        return Ok(Some(cfg.retry_ms));
    }
    let pinned = volume_affinity(c, ns, &pod).await?;
    let picked = pick(&pod, &nodes, &all_pods, &pinned);
    // Preemption plan (owned: the snapshot is released before any await).
    let plan: Option<(String, Vec<Value>)> = if picked.is_err() { preemption(&pod, &nodes, &all_pods, &pinned).map(|(n, v)| (str_at(n, &["metadata", "name"]).to_string(), v.into_iter().cloned().collect())) } else { None };
    drop(all_pods);
    match picked {
        Ok(node) => {
            let body = obj(alloc::vec![
                ("apiVersion", Value::from("v1")),
                ("kind", Value::from("Binding")),
                ("metadata", obj(alloc::vec![("name", Value::from(name))])),
                ("target", obj(alloc::vec![("apiVersion", Value::from("v1")), ("kind", Value::from("Node")), ("name", Value::from(node.as_str()))])),
            ]);
            match c.create(&alloc::format!("{path}/binding"), &body).await {
                Ok(_) => {
                    emit_event(c, cfg, &pod, "Normal", "Scheduled", &alloc::format!("Successfully assigned {ns}/{name} to {node}")).await;
                    bound(snap, &pod, &node);
                    Ok(None)
                }
                Err(e) if e.code == 409 || e.code == 404 => Ok(None), // already bound / gone
                Err(e) => Err(e),
            }
        }
        Err(msg) => {
            mark_unschedulable(c, cfg, &path, &pod, &msg).await?;
            if let Some((node, victims)) = plan {
                preempt(c, cfg, &path, &pod, &node, &victims.iter().collect::<Vec<_>>()).await?;
            }
            Ok(Some(cfg.retry_ms))
        }
    }
}

/// Evicts the victims (marking them with `DisruptionTarget`) and nominates the pod to the node.
async fn preempt<C: Client>(c: &C, cfg: &Config, path: &str, pod: &Value, node: &str, victims: &[&Value]) -> Result<()> {
    let msg = alloc::format!("default-scheduler: preempting to accommodate a higher priority pod {}/{}", namespace(pod), name(pod));
    for v in victims.iter().filter(|v| !deleting(v)) {
        let vpath = alloc::format!("{}/{}", pods(Some(namespace(v))), name(v));
        let mut conds: Vec<Value> = v.pointer(&["status", "conditions"]).and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
        set_condition(
            &mut conds,
            obj(alloc::vec![
                ("type", Value::from("DisruptionTarget")),
                ("status", Value::from("True")),
                ("reason", Value::from("PreemptionByScheduler")),
                ("message", Value::from(msg.as_str())),
                ("lastTransitionTime", Value::String(kr_apiserver::object::rfc3339((cfg.now)()))),
            ]),
        );
        let patch = obj(alloc::vec![("status", obj(alloc::vec![("conditions", Value::Array(conds))]))]);
        match c.patch(&alloc::format!("{vpath}/status"), MERGE, &patch).await {
            Ok(_) => {}
            Err(e) if e.code == 404 => continue,
            Err(e) => return Err(e),
        }
        delete_ok(c, &vpath).await?;
        emit_event(c, cfg, v, "Normal", "Preempted", &alloc::format!("Preempted by pod {} on node {node}", uid(pod))).await;
    }
    if str_at(pod, &["status", "nominatedNodeName"]) != node {
        let patch = obj(alloc::vec![("status", obj(alloc::vec![("nominatedNodeName", Value::from(node))]))]);
        match c.patch(&alloc::format!("{path}/status"), MERGE, &patch).await {
            Err(e) if e.code != 404 => return Err(e),
            _ => {}
        }
    }
    Ok(())
}

/// Why the pod's claims block scheduling: a missing PVC, or an unbound one whose class is not
/// `WaitForFirstConsumer` (those are bound by the PV controller regardless of any pod).
async fn unbound_claim<C: Client>(c: &C, ns: &str, pod: &Value) -> Result<Option<String>> {
    for vol in pod.pointer(&["spec", "volumes"]).and_then(Value::as_array).unwrap_or(&[]) {
        let claim = str_at(vol, &["persistentVolumeClaim", "claimName"]);
        if claim.is_empty() {
            continue;
        }
        let Some(pvc) = get_opt(c, &alloc::format!("{}/{claim}", pvcs(Some(ns)))).await? else {
            return Ok(Some(alloc::format!("persistentvolumeclaim \"{claim}\" not found")));
        };
        if str_at(&pvc, &["status", "phase"]) == "Bound" {
            continue;
        }
        let class = str_at(&pvc, &["spec", "storageClassName"]);
        let sc = if class.is_empty() { None } else { get_opt(c, &alloc::format!("/apis/storage.k8s.io/v1/storageclasses/{class}")).await? };
        if sc.is_none_or(|k| str_at(&k, &["volumeBindingMode"]) != "WaitForFirstConsumer") {
            return Ok(Some("pod has unbound immediate PersistentVolumeClaims".to_string()));
        }
    }
    Ok(None)
}

/// Node affinities (as pod-spec style `affinity` holders) of the PVs bound to the pod's PVCs. An
/// unbound claim (WaitForFirstConsumer) restricts nothing.
async fn volume_affinity<C: Client>(c: &C, ns: &str, pod: &Value) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for vol in pod.pointer(&["spec", "volumes"]).and_then(Value::as_array).unwrap_or(&[]) {
        let claim = str_at(vol, &["persistentVolumeClaim", "claimName"]);
        if claim.is_empty() {
            continue;
        }
        let Some(pvc) = get_opt(c, &alloc::format!("{}/{claim}", pvcs(Some(ns)))).await? else { continue };
        let pv_name = str_at(&pvc, &["spec", "volumeName"]);
        if pv_name.is_empty() {
            continue;
        }
        let Some(pv) = get_opt(c, &alloc::format!("/api/v1/persistentvolumes/{pv_name}")).await? else { continue };
        if let Some(req) = pv.pointer(&["spec", "nodeAffinity", "required"]) {
            let na = obj(alloc::vec![("requiredDuringSchedulingIgnoredDuringExecution", req.clone())]);
            out.push(obj(alloc::vec![("affinity", obj(alloc::vec![("nodeAffinity", na)]))]));
        }
    }
    Ok(out)
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
        Ok(_) => {
            emit_event(c, cfg, pod, "Warning", "FailedScheduling", msg).await;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Records a scheduling event for the pod (best effort).
async fn emit_event<C: Client>(c: &C, cfg: &Config, pod: &Value, ty: &str, reason: &str, msg: &str) {
    let (ns, now) = (namespace(pod), Value::String(kr_apiserver::object::rfc3339((cfg.now)())));
    let ev = obj(alloc::vec![
        ("apiVersion", Value::from("v1")),
        ("kind", Value::from("Event")),
        ("metadata", obj(alloc::vec![("generateName", Value::String(alloc::format!("{}.", name(pod)))), ("namespace", Value::from(ns))])),
        ("involvedObject", obj(alloc::vec![("apiVersion", Value::from("v1")), ("kind", Value::from("Pod")), ("namespace", Value::from(ns)), ("name", Value::from(name(pod))), ("uid", Value::from(uid(pod)))])),
        ("type", Value::from(ty)),
        ("reason", Value::from(reason)),
        ("message", Value::from(msg)),
        ("source", obj(alloc::vec![("component", Value::from("default-scheduler"))])),
        ("reportingComponent", Value::from("default-scheduler")),
        ("firstTimestamp", now.clone()),
        ("lastTimestamp", now),
        ("count", num(1)),
    ]);
    let _ = c.create(&alloc::format!("/api/v1/namespaces/{ns}/events"), &ev).await;
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

fn qty(v: Option<&Value>) -> i128 {
    match v {
        Some(Value::String(s)) => Quantity::parse(s).ok().and_then(|q| q.value()).unwrap_or(0),
        Some(n) => n.as_i64().unwrap_or(0) as i128,
        None => 0,
    }
}

/// Requests of extended resources (everything but cpu, memory and ephemeral storage): the sum
/// over the containers, at least the biggest init container. A container that only sets a limit
/// requests that much.
fn ext_requests(pod: &Value) -> BTreeMap<String, i128> {
    let of = |c: &Value| -> BTreeMap<String, i128> {
        let mut m = BTreeMap::new();
        for field in ["limits", "requests"] {
            for (k, v) in c.pointer(&["resources", field]).and_then(Value::as_object).unwrap_or(&[]) {
                if !matches!(k.as_str(), "cpu" | "memory" | "ephemeral-storage") {
                    m.insert(k.clone(), qty(Some(v)));
                }
            }
        }
        m
    };
    let mut sum: BTreeMap<String, i128> = BTreeMap::new();
    for c in pod.pointer(&["spec", "containers"]).and_then(Value::as_array).unwrap_or(&[]) {
        for (k, v) in of(c) {
            *sum.entry(k).or_insert(0) += v;
        }
    }
    for c in pod.pointer(&["spec", "initContainers"]).and_then(Value::as_array).unwrap_or(&[]) {
        for (k, v) in of(c) {
            let e = sum.entry(k).or_insert(0);
            *e = (*e).max(v);
        }
    }
    sum
}

fn priority(pod: &Value) -> i64 {
    int_at(pod, &["spec", "priority"], 0)
}

/// Why a pod does not fit the node's resources.
enum Lack {
    Cpu,
    Mem,
    Pods,
    Ext(String),
}

/// Resource filter: the pod on top of the `on_node` pods must fit `status.allocatable`. Returns
/// what the node has in use (without the pod) and the pod count, for scoring.
fn fit(pod: &Value, n: &Value, on_node: &[&Value]) -> core::result::Result<(Res, usize), Lack> {
    let want = requests(pod);
    let want_ext = ext_requests(pod);
    let mut used = Res::default();
    let mut used_ext: BTreeMap<String, i128> = BTreeMap::new();
    for p in on_node {
        let r = requests(p);
        used.cpu_milli += r.cpu_milli;
        used.mem += r.mem;
        for (k, v) in ext_requests(p) {
            *used_ext.entry(k).or_insert(0) += v;
        }
    }
    let alloc_cpu = cpu_milli(n.pointer(&["status", "allocatable", "cpu"]));
    let alloc_mem = bytes(n.pointer(&["status", "allocatable", "memory"]));
    if used.cpu_milli + want.cpu_milli > alloc_cpu {
        return Err(Lack::Cpu);
    }
    if used.mem + want.mem > alloc_mem {
        return Err(Lack::Mem);
    }
    for (k, w) in &want_ext {
        let have = qty(n.pointer(&["status", "allocatable", k.as_str()]));
        if *w > 0 && used_ext.get(k).copied().unwrap_or(0) + w > have {
            return Err(Lack::Ext(k.clone()));
        }
    }
    if let Some(max) = n.pointer(&["status", "allocatable", "pods"]).and_then(Value::as_str).and_then(|s| s.parse::<usize>().ok()) {
        if on_node.len() + 1 > max {
            return Err(Lack::Pods);
        }
    }
    Ok((used, on_node.len()))
}

/// Pods that count against a node for `pod`: the ones bound there, and the ones nominated to it
/// by a preemption that are at least as important (the room is kept for them).
fn on_node<'a>(pod: &Value, nname: &str, all_pods: &'a [Value]) -> Vec<&'a Value> {
    all_pods
        .iter()
        .filter(|p| {
            if pod_terminal(p) {
                return false;
            }
            if str_at(p, &["spec", "nodeName"]) == nname {
                return true;
            }
            str_at(p, &["spec", "nodeName"]).is_empty() && str_at(p, &["status", "nominatedNodeName"]) == nname && uid(p) != uid(pod) && priority(p) >= priority(pod)
        })
        .collect()
}

/// Node-level filters that preemption cannot fix.
fn node_eligible(pod: &Value, n: &Value, pinned: &[Value]) -> bool {
    node_ready(n) && selector_matches(pod, n) && pod.get("spec").is_none_or(|s| node_affinity_matches(s, n)) && pinned.iter().all(|s| node_affinity_matches(s, n)) && !untolerated_taint(pod, n)
}

/// Preemption: the node where evicting the fewest (then least important) lower-priority pods
/// makes room for `pod`, with those victims. Victims are reprieved from the most important
/// down while the pod still fits.
fn preemption<'a>(pod: &Value, nodes: &'a [Value], all_pods: &'a [Value], pinned: &[Value]) -> Option<(&'a Value, Vec<&'a Value>)> {
    if str_at(pod, &["spec", "preemptionPolicy"]) == "Never" {
        return None;
    }
    let prio = priority(pod);
    let mut best: Option<((usize, i64, &str), &Value, Vec<&Value>)> = None;
    for n in nodes {
        if !node_eligible(pod, n, pinned) {
            continue;
        }
        let nname = name(n);
        let here = on_node(pod, nname, all_pods);
        let (mut lower, keep): (Vec<&Value>, Vec<&Value>) = here.into_iter().partition(|p| str_at(p, &["spec", "nodeName"]) == nname && priority(p) < prio);
        if lower.is_empty() || fit(pod, n, &keep).is_err() {
            continue;
        }
        lower.sort_by_key(|p| core::cmp::Reverse(priority(p)));
        let mut kept = keep;
        let mut victims = Vec::new();
        for p in lower {
            kept.push(p);
            if fit(pod, n, &kept).is_err() {
                kept.pop();
                victims.push(p);
            }
        }
        let top = victims.iter().map(|p| priority(p)).max().unwrap_or(0);
        let key = (victims.len(), top, nname);
        if best.as_ref().is_none_or(|(k, ..)| key < *k) {
            best = Some((key, n, victims));
        }
    }
    best.map(|(_, n, v)| (n, v))
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
fn pick(pod: &Value, nodes: &[Value], all_pods: &[Value], pinned: &[Value]) -> core::result::Result<String, String> {
    let want = requests(pod);
    let (mut volume, mut not_ready, mut taint, mut selector, mut cpu, mut mem, mut count, mut ports) = (0, 0, 0, 0, 0, 0, 0, 0);
    let mut best: Option<(i128, usize, &str)> = None; // (score, pods on node, name)
    let mut ext: BTreeMap<String, usize> = BTreeMap::new();
    for n in nodes {
        let nname = name(n);
        if !node_ready(n) {
            not_ready += 1;
            continue;
        }
        if !selector_matches(pod, n) || !pod.get("spec").is_none_or(|s| node_affinity_matches(s, n)) {
            selector += 1;
            continue;
        }
        if !pinned.iter().all(|s| node_affinity_matches(s, n)) {
            volume += 1;
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
        let here = on_node(pod, nname, all_pods);
        let (used, npods) = match fit(pod, n, &here) {
            Ok(r) => r,
            Err(Lack::Cpu) => {
                cpu += 1;
                continue;
            }
            Err(Lack::Mem) => {
                mem += 1;
                continue;
            }
            Err(Lack::Pods) => {
                count += 1;
                continue;
            }
            Err(Lack::Ext(k)) => {
                *ext.entry(k).or_insert(0) += 1;
                continue;
            }
        };
        let alloc_cpu = cpu_milli(n.pointer(&["status", "allocatable", "cpu"]));
        let alloc_mem = bytes(n.pointer(&["status", "allocatable", "memory"]));
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
        (volume, "node(s) had volume node affinity conflict"),
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
    for (k, n) in &ext {
        reasons.push(alloc::format!("{n} Insufficient {k}"));
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
        assert_eq!(pick(&pod, &nodes, &[busy], &[]).unwrap(), "b"); // a is busier; b and c tie, name wins
        let big = v(r#"{"spec":{"containers":[{"resources":{"requests":{"cpu":"5"}}}]}}"#);
        assert!(pick(&big, &nodes, &[], &[]).unwrap_err().contains("Insufficient cpu"));
    }

    #[test]
    fn volume_node_affinity_pins_the_pod() {
        let node = |n: &str| v(&alloc::format!(r#"{{"metadata":{{"name":"{n}","labels":{{"kubernetes.io/hostname":"{n}"}}}},"status":{{"conditions":[{{"type":"Ready","status":"True"}}],"allocatable":{{"cpu":"4","memory":"8Gi"}}}}}}"#));
        let pod = v(r#"{"spec":{"containers":[{}]}}"#);
        let nodes = [node("a"), node("b")];
        let pin = |n: &str| v(&alloc::format!(r#"{{"affinity":{{"nodeAffinity":{{"requiredDuringSchedulingIgnoredDuringExecution":{{"nodeSelectorTerms":[{{"matchExpressions":[{{"key":"kubernetes.io/hostname","operator":"In","values":["{n}"]}}]}}]}}}}}}}}"#));
        assert_eq!(pick(&pod, &nodes, &[], &[pin("b")]).unwrap(), "b");
        assert!(pick(&pod, &nodes, &[], &[pin("b"), pin("a")]).unwrap_err().contains("volume node affinity conflict"));
        assert!(pick(&pod, &nodes, &[], &[]).is_ok()); // unbound WaitForFirstConsumer claim: no pin
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
