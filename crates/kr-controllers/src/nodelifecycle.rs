//! The node lifecycle controller: notices nodes whose kubelet stopped heartbeating and reacts
//! the way upstream's node-lifecycle and taint-eviction controllers do.
//!
//! * A node whose newest sign of life (Lease `renewTime`, the Ready condition's
//!   `lastHeartbeatTime`, or its creation) is older than [`GRACE`] seconds gets its conditions set
//!   to `Unknown` (`NodeStatusUnknown`) and the `node.kubernetes.io/unreachable` taints
//!   (`NoSchedule` and `NoExecute`).
//! * The pods on it are marked not Ready (so Endpoints drop them) and deleted once the time they
//!   tolerate the `NoExecute` taint is over: `tolerationSeconds` of a matching toleration, a
//!   matching toleration without seconds means never, no matching toleration means
//!   [`DEFAULT_TOLERATION`] (what upstream's DefaultTolerationSeconds admission would add).
//! * When the heartbeat is back, the taints are removed (the kubelet restores the conditions).
//!
//! Pods are only deleted, never force-deleted: the kubelet finishes them when it returns, and the
//! workload controllers already ignore pods that are being deleted.

use crate::scheduler::tolerates;
use crate::util::*;
use crate::Config;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_apiserver::client::{Client, Result};
use kr_fmt::json::Value;

/// Seconds without a heartbeat before a node is considered unreachable (upstream: 50 s).
pub const GRACE: i64 = 40;
/// Seconds a pod without its own toleration survives on an unreachable node.
pub const DEFAULT_TOLERATION: i64 = 300;
const UNREACHABLE: &str = "node.kubernetes.io/unreachable";
const CONDITIONS: [&str; 4] = ["Ready", "MemoryPressure", "DiskPressure", "PIDPressure"];

pub async fn run<C: Client + Clone + 'static>(c: C, cfg: Config) {
    loop {
        kr_rt::exec::sleep(5_000).await;
        if (cfg.now)() > 0 {
            let _ = tick(&c, (cfg.now)()).await;
        }
    }
}

/// Unix seconds of a (Micro)Time such as `2026-11-01T16:25:12.000000Z`.
fn time_of(s: &str) -> Option<i64> {
    match s.split_once('.') {
        Some((head, _)) => parse_time(&alloc::format!("{head}Z")),
        None => parse_time(s),
    }
}

fn last_heartbeat(node: &Value, lease: Option<&Value>) -> i64 {
    let mut best = parse_time(str_at(node, &["metadata", "creationTimestamp"])).unwrap_or(0);
    if let Some(l) = lease {
        best = best.max(time_of(str_at(l, &["spec", "renewTime"])).unwrap_or(0));
    }
    for cond in node.pointer(&["status", "conditions"]).and_then(Value::as_array).unwrap_or(&[]) {
        if str_at(cond, &["type"]) == "Ready" && str_at(cond, &["status"]) == "True" {
            best = best.max(time_of(str_at(cond, &["lastHeartbeatTime"])).unwrap_or(0));
        }
    }
    best
}

fn taint(effect: &str, now: i64) -> Value {
    obj(alloc::vec![("key", Value::from(UNREACHABLE)), ("effect", Value::from(effect)), ("timeAdded", Value::from(rfc3339(now).as_str()))])
}

fn taints_of(node: &Value) -> Vec<Value> {
    node.pointer(&["spec", "taints"]).and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default()
}

async fn tick<C: Client>(c: &C, now: i64) -> Result<()> {
    let nodes = items(&c.list("/api/v1/nodes", "").await?);
    let leases = items(&c.list("/apis/coordination.k8s.io/v1/namespaces/kube-node-lease/leases", "").await.unwrap_or(Value::Null));
    let mut dead: Vec<(String, Vec<Value>)> = Vec::new();
    for node in nodes.iter().filter(|n| !deleting(n)) {
        let nm = name(node);
        let lease = leases.iter().find(|l| name(l) == nm);
        let stale = now - last_heartbeat(node, lease) > GRACE;
        let taints = taints_of(node);
        let has = taints.iter().any(|t| str_at(t, &["key"]) == UNREACHABLE);
        let path = alloc::format!("/api/v1/nodes/{nm}");
        if stale {
            put_status(c, &path, |cur| unknown_status(cur, now)).await?;
            if !has {
                let mut want: Vec<Value> = taints.clone();
                want.push(taint("NoSchedule", now));
                want.push(taint("NoExecute", now));
                let spec = obj(alloc::vec![("taints", Value::Array(want))]);
                c.patch(&path, MERGE, &obj(alloc::vec![("spec", spec)])).await?;
            }
            let fresh = if has { taints } else { taints_of(&c.get(&path).await?) };
            dead.push((nm.to_string(), fresh));
        } else if has {
            let want: Vec<Value> = taints.into_iter().filter(|t| str_at(t, &["key"]) != UNREACHABLE).collect();
            let spec = obj(alloc::vec![("taints", if want.is_empty() { Value::Null } else { Value::Array(want) })]);
            c.patch(&path, MERGE, &obj(alloc::vec![("spec", spec)])).await?;
        }
    }
    if dead.is_empty() {
        return Ok(());
    }
    for pod in items(&c.list("/api/v1/pods", "").await?) {
        let Some((_, taints)) = dead.iter().find(|(n, _)| n == str_at(&pod, &["spec", "nodeName"])) else { continue };
        if pod_terminal(&pod) || deleting(&pod) {
            continue;
        }
        let path = alloc::format!("{}/{}", pods(Some(namespace(&pod))), name(&pod));
        if pod_ready(&pod) {
            put_status(c, &path, not_ready).await?;
        }
        let Some(added) = taints.iter().find(|t| str_at(t, &["key"]) == UNREACHABLE && str_at(t, &["effect"]) == "NoExecute") else { continue };
        let since = parse_time(str_at(added, &["timeAdded"])).unwrap_or(now);
        if let Some(secs) = toleration_seconds(&pod, added) {
            if now - since >= secs {
                delete_ok(c, &path).await?;
            }
        }
    }
    Ok(())
}

/// How long the pod tolerates `taint`: `None` forever, `Some(0)` not at all.
fn toleration_seconds(pod: &Value, taint: &Value) -> Option<i64> {
    let tols = pod.pointer(&["spec", "tolerations"]).and_then(Value::as_array).unwrap_or(&[]);
    let mut best: Option<Option<i64>> = None;
    for t in tols.iter().filter(|t| tolerates(t, taint)) {
        let s = t.get("tolerationSeconds").and_then(Value::as_i64);
        best = Some(match (best, s) {
            (None, s) => s,
            (Some(None), _) | (_, None) => None,
            (Some(Some(a)), Some(b)) => Some(a.max(b)),
        });
    }
    match best {
        None => Some(DEFAULT_TOLERATION),
        Some(s) => s,
    }
}

fn unknown_status(cur: &Value, now: i64) -> Value {
    let mut st = cur.get("status").cloned().unwrap_or_else(|| obj(Vec::new()));
    let mut conds: Vec<Value> = st.get("conditions").and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
    for ty in CONDITIONS {
        let old = conds.iter().find(|c| str_at(c, &["type"]) == ty).cloned();
        if old.as_ref().is_some_and(|o| str_at(o, &["status"]) == "Unknown") {
            continue;
        }
        let beat = old.as_ref().map(|o| str_at(o, &["lastHeartbeatTime"]).to_string()).unwrap_or_else(|| rfc3339(now));
        set_condition(
            &mut conds,
            obj(alloc::vec![
                ("type", Value::from(ty)),
                ("status", Value::from("Unknown")),
                ("reason", Value::from("NodeStatusUnknown")),
                ("message", Value::from("Kubelet stopped posting node status.")),
                ("lastHeartbeatTime", Value::from(beat.as_str())),
                ("lastTransitionTime", Value::from(rfc3339(now).as_str())),
            ]),
        );
    }
    st.set("conditions", Value::Array(conds));
    st
}

fn not_ready(cur: &Value) -> Value {
    let mut st = cur.get("status").cloned().unwrap_or_else(|| obj(Vec::new()));
    let mut conds: Vec<Value> = st.get("conditions").and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
    for c in conds.iter_mut() {
        if matches!(str_at(c, &["type"]), "Ready" | "ContainersReady") && str_at(c, &["status"]) == "True" {
            c.set("status", Value::from("False"));
            c.set("reason", Value::from("NodeNotReady"));
        }
    }
    st.set("conditions", Value::Array(conds));
    st
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_fmt::json;

    fn j(s: &str) -> Value {
        json::parse(s.as_bytes()).unwrap()
    }

    #[test]
    fn microtime_parses() {
        assert_eq!(time_of("2026-11-01T16:25:12.000000Z"), parse_time("2026-11-01T16:25:12Z"));
        assert!(time_of("2026-11-01T16:25:12.000000Z").is_some());
    }

    #[test]
    fn toleration_windows() {
        let t = j(r#"{"key":"node.kubernetes.io/unreachable","effect":"NoExecute"}"#);
        assert_eq!(toleration_seconds(&j(r#"{"spec":{}}"#), &t), Some(DEFAULT_TOLERATION));
        let forever = j(r#"{"spec":{"tolerations":[{"key":"node.kubernetes.io/unreachable","operator":"Exists","effect":"NoExecute"}]}}"#);
        assert_eq!(toleration_seconds(&forever, &t), None);
        let secs = j(r#"{"spec":{"tolerations":[{"key":"node.kubernetes.io/unreachable","operator":"Exists","tolerationSeconds":7}]}}"#);
        assert_eq!(toleration_seconds(&secs, &t), Some(7));
    }

    #[test]
    fn heartbeat_prefers_newest_signal() {
        let node = j(r#"{"metadata":{"creationTimestamp":"2026-11-01T16:00:00Z"},"status":{"conditions":[{"type":"Ready","status":"True","lastHeartbeatTime":"2026-11-01T16:10:00Z"}]}}"#);
        let lease = j(r#"{"spec":{"renewTime":"2026-11-01T16:20:00.000000Z"}}"#);
        assert_eq!(last_heartbeat(&node, Some(&lease)), parse_time("2026-11-01T16:20:00Z").unwrap());
        assert_eq!(last_heartbeat(&node, None), parse_time("2026-11-01T16:10:00Z").unwrap());
    }

    #[test]
    fn unknown_conditions_and_pod_not_ready() {
        let node = j(r#"{"status":{"conditions":[{"type":"Ready","status":"True","lastHeartbeatTime":"2026-11-01T16:00:00Z"}]}}"#);
        let st = unknown_status(&node, 1_800_000_000);
        let conds = st.get("conditions").and_then(Value::as_array).unwrap();
        assert_eq!(conds.len(), 4);
        assert!(conds.iter().all(|c| str_at(c, &["status"]) == "Unknown"));
        let pod = j(r#"{"status":{"conditions":[{"type":"Ready","status":"True"},{"type":"PodScheduled","status":"True"}]}}"#);
        let st = not_ready(&pod);
        assert!(!pod_ready(&obj(alloc::vec![("status", st)])));
    }
}
