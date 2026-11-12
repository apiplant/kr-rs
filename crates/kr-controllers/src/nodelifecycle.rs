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
//! # Eviction rate limiting
//! Like upstream, the `NoExecute` taint (which starts the evictions) is added through a token
//! bucket per zone (`topology.kubernetes.io/zone`; unlabelled nodes form one zone): burst 1,
//! [`PRIMARY_RATE_MILLI`] per second normally. A zone is *partially disrupted* when at least 3
//! of its nodes and [`UNHEALTHY_PERCENT`] of them are unhealthy: then the rate drops to
//! [`SECONDARY_RATE_MILLI`] (clusters of up to [`LARGE_CLUSTER`] nodes stop evicting instead).
//! A zone with no healthy node is *fully disrupted* and stops, unless every zone is: then the
//! problem is probably the control plane's own network and the normal rate applies. The
//! `NoSchedule` taint, the Unknown conditions and the pods' NotReady marks are never limited.
//!
//! Pods are only deleted, never force-deleted: the kubelet finishes them when it returns, and the
//! workload controllers already ignore pods that are being deleted.

use crate::scheduler::tolerates;
use crate::util::*;
use crate::Config;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_apiserver::client::{Client, Result};
use alloc::collections::BTreeMap;
use kr_fmt::json::Value;

/// Evictions (tainted nodes) per second per zone, in thousandths (upstream: 0.1/s).
pub const PRIMARY_RATE_MILLI: i64 = 100;
/// Rate of a partially disrupted zone (upstream: 0.01/s).
pub const SECONDARY_RATE_MILLI: i64 = 10;
/// Percentage of unhealthy nodes that makes a zone (of at least 3 unhealthy nodes) disrupted.
pub const UNHEALTHY_PERCENT: usize = 55;
/// Zones up to this size stop evicting when partially disrupted instead of slowing down.
pub const LARGE_CLUSTER: usize = 50;
const ZONE_LABEL: &str = "topology.kubernetes.io/zone";
const BURST_MILLI: i64 = 1000;

/// The eviction knobs; tests change them.
#[derive(Clone, Copy)]
pub struct Limits {
    pub primary_milli: i64,
    pub secondary_milli: i64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { primary_milli: PRIMARY_RATE_MILLI, secondary_milli: SECONDARY_RATE_MILLI }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ZoneState {
    Normal,
    Partial,
    Full,
}

/// Classifies a zone from its healthy and unhealthy node counts (upstream's ComputeZoneState).
pub fn zone_state(ready: usize, unready: usize) -> ZoneState {
    if ready == 0 && unready > 0 {
        ZoneState::Full
    } else if unready >= 3 && unready * 100 >= UNHEALTHY_PERCENT * (ready + unready) {
        ZoneState::Partial
    } else {
        ZoneState::Normal
    }
}

/// Evictions per second (thousandths) of a zone.
fn zone_rate(l: &Limits, st: ZoneState, size: usize, all_full: bool) -> i64 {
    match st {
        ZoneState::Normal => l.primary_milli,
        ZoneState::Partial if size > LARGE_CLUSTER => l.secondary_milli,
        ZoneState::Partial => 0,
        ZoneState::Full if all_full => l.primary_milli,
        ZoneState::Full => 0,
    }
}

/// Token buckets of the zones, kept across ticks.
#[derive(Default)]
pub struct Evictor {
    zones: BTreeMap<String, (i64, i64)>, // zone -> (tokens in thousandths, last refill time)
    rates: BTreeMap<String, i64>,
}

impl Evictor {
    /// Recomputes the per-zone rates from `(zone, healthy)` of every node and refills buckets.
    fn update(&mut self, l: &Limits, nodes: &[(String, bool)], now: i64) {
        let mut counts: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
        for (z, ok) in nodes {
            let e = counts.entry(z.as_str()).or_default();
            if *ok {
                e.0 += 1;
            } else {
                e.1 += 1;
            }
        }
        let all_full = !counts.is_empty() && counts.values().all(|&(r, u)| zone_state(r, u) == ZoneState::Full);
        self.rates.clear();
        for (z, &(r, u)) in &counts {
            self.rates.insert(z.to_string(), zone_rate(l, zone_state(r, u), r + u, all_full));
        }
        for (z, rate) in &self.rates {
            let b = self.zones.entry(z.clone()).or_insert((BURST_MILLI, now));
            b.0 = (b.0 + rate * (now - b.1).max(0)).min(BURST_MILLI);
            b.1 = now;
        }
    }

    /// Takes the token for evicting one node of `zone`.
    fn allow(&mut self, zone: &str) -> bool {
        match self.zones.get_mut(zone) {
            Some(b) if b.0 >= BURST_MILLI => {
                b.0 -= BURST_MILLI;
                true
            }
            _ => false,
        }
    }
}

/// Seconds without a heartbeat before a node is considered unreachable (upstream: 50 s).
pub const GRACE: i64 = 40;
/// Seconds a pod without its own toleration survives on an unreachable node.
pub const DEFAULT_TOLERATION: i64 = 300;
const UNREACHABLE: &str = "node.kubernetes.io/unreachable";
const CONDITIONS: [&str; 4] = ["Ready", "MemoryPressure", "DiskPressure", "PIDPressure"];

pub async fn run<C: Client + Clone + 'static>(c: C, cfg: Config) {
    let mut ev = Evictor::default();
    loop {
        kr_rt::exec::sleep(5_000).await;
        if (cfg.now)() > 0 {
            let _ = tick(&c, (cfg.now)(), &mut ev, &Limits::default()).await;
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

async fn tick<C: Client>(c: &C, now: i64, ev: &mut Evictor, limits: &Limits) -> Result<()> {
    let nodes = items(&c.list("/api/v1/nodes", "").await?);
    let leases = items(&c.list("/apis/coordination.k8s.io/v1/namespaces/kube-node-lease/leases", "").await.unwrap_or(Value::Null));
    let mut dead: Vec<(String, Vec<Value>)> = Vec::new();
    let health: Vec<(String, bool)> = nodes
        .iter()
        .filter(|n| !deleting(n))
        .map(|n| {
            let l = leases.iter().find(|l| name(l) == name(n));
            (str_at(n, &["metadata", "labels", ZONE_LABEL]).to_string(), now - last_heartbeat(n, l) <= GRACE)
        })
        .collect();
    ev.update(limits, &health, now);
    for node in nodes.iter().filter(|n| !deleting(n)) {
        let nm = name(node);
        let lease = leases.iter().find(|l| name(l) == nm);
        let stale = now - last_heartbeat(node, lease) > GRACE;
        let taints = taints_of(node);
        let has = taints.iter().any(|t| str_at(t, &["key"]) == UNREACHABLE);
        let has_exec = taints.iter().any(|t| str_at(t, &["key"]) == UNREACHABLE && str_at(t, &["effect"]) == "NoExecute");
        let has_sched = taints.iter().any(|t| str_at(t, &["key"]) == UNREACHABLE && str_at(t, &["effect"]) == "NoSchedule");
        let path = alloc::format!("/api/v1/nodes/{nm}");
        if stale {
            put_status(c, &path, |cur| unknown_status(cur, now)).await?;
            let zone = str_at(node, &["metadata", "labels", ZONE_LABEL]);
            let add_exec = !has_exec && ev.allow(zone);
            if !has_sched || add_exec {
                let mut want: Vec<Value> = taints.clone();
                if !has_sched {
                    want.push(taint("NoSchedule", now));
                }
                if add_exec {
                    want.push(taint("NoExecute", now));
                }
                let spec = obj(alloc::vec![("taints", Value::Array(want))]);
                c.patch(&path, MERGE, &obj(alloc::vec![("spec", spec)])).await?;
            }
            let fresh = if has_sched && !add_exec { taints } else { taints_of(&c.get(&path).await?) };
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
    fn zone_states() {
        assert_eq!(zone_state(5, 0), ZoneState::Normal);
        assert_eq!(zone_state(0, 0), ZoneState::Normal);
        assert_eq!(zone_state(0, 1), ZoneState::Full);
        assert_eq!(zone_state(1, 1), ZoneState::Normal); // fewer than 3 unhealthy
        assert_eq!(zone_state(2, 2), ZoneState::Normal);
        assert_eq!(zone_state(3, 3), ZoneState::Normal); // 50%
        assert_eq!(zone_state(2, 3), ZoneState::Partial);
        assert_eq!(zone_state(4, 3), ZoneState::Normal); // 3/7 = 42%
        assert_eq!(zone_state(3, 4), ZoneState::Partial);
        assert_eq!(zone_state(5, 3), ZoneState::Normal);
        assert_eq!(zone_state(10, 3), ZoneState::Normal);
    }

    #[test]
    fn rates_follow_zone_state() {
        let l = Limits::default();
        assert_eq!(zone_rate(&l, ZoneState::Normal, 3, false), 100);
        assert_eq!(zone_rate(&l, ZoneState::Partial, 10, false), 0);
        assert_eq!(zone_rate(&l, ZoneState::Partial, 100, false), 10);
        assert_eq!(zone_rate(&l, ZoneState::Full, 4, false), 0);
        assert_eq!(zone_rate(&l, ZoneState::Full, 4, true), 100);
    }

    fn zones(spec: &[(&str, usize, usize)]) -> Vec<(String, bool)> {
        let mut v = Vec::new();
        for (z, ok, bad) in spec {
            v.extend((0..*ok).map(|_| (z.to_string(), true)));
            v.extend((0..*bad).map(|_| (z.to_string(), false)));
        }
        v
    }

    #[test]
    fn token_bucket_refills_at_the_zone_rate() {
        let l = Limits::default();
        let mut ev = Evictor::default();
        let n = zones(&[("a", 3, 1)]);
        ev.update(&l, &n, 100);
        assert!(ev.allow("a")); // burst of one
        assert!(!ev.allow("a"));
        ev.update(&l, &n, 105); // 0.5 token
        assert!(!ev.allow("a"));
        ev.update(&l, &n, 110);
        assert!(ev.allow("a"));
        assert!(!ev.allow("a"));
        assert!(!ev.allow("unknown-zone"));
    }

    #[test]
    fn disrupted_zones_stop_unless_all_are() {
        let l = Limits::default();
        let mut ev = Evictor::default();
        // zone a: 3 of 4 unhealthy (small cluster: stops); zone b healthy.
        ev.update(&l, &zones(&[("a", 4, 0), ("b", 4, 0)]), 100);
        assert!(ev.allow("a")); // drain the initial burst
        assert!(ev.allow("b"));
        ev.update(&l, &zones(&[("a", 1, 3), ("b", 3, 0)]), 1000);
        assert!(!ev.allow("a"));
        assert!(ev.allow("b"));
        // zone a fully down, b healthy: a stops.
        ev.update(&l, &zones(&[("a", 0, 2), ("b", 3, 0)]), 2000);
        assert!(!ev.allow("a"));
        assert!(ev.allow("b"));
        // every zone fully down: the normal rate applies again.
        ev.update(&l, &zones(&[("a", 0, 2), ("b", 0, 3)]), 3000);
        assert!(ev.allow("a"));
        assert!(ev.allow("b"));
    }

    #[test]
    fn large_partial_zone_uses_the_secondary_rate() {
        let l = Limits::default();
        let mut ev = Evictor::default();
        let n = zones(&[("a", 20, 40)]);
        ev.update(&l, &n, 100);
        assert!(ev.allow("a"));
        ev.update(&l, &n, 150); // 0.5 token at 0.01/s: nowhere near one
        assert!(!ev.allow("a"));
        ev.update(&l, &n, 250);
        assert!(ev.allow("a"));
    }

    fn node_json(nm: &str, zone: &str, beat: i64) -> Value {
        j(&alloc::format!(
            r#"{{"metadata":{{"name":"{nm}","labels":{{"topology.kubernetes.io/zone":"{zone}"}}}},"status":{{"conditions":[{{"type":"Ready","status":"True","lastHeartbeatTime":"{}"}}]}}}}"#,
            rfc3339(beat)
        ))
    }

    #[test]
    fn tick_rate_limits_the_noexecute_taint_per_zone() {
        use crate::tests::*;
        use kr_apiserver::client::InProcess;
        let _l = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let api = alloc::rc::Rc::new(kr_apiserver::api::ApiServer::new(kr_store::Store::in_memory(), || T0, rng, "127.0.0.1:6443".to_string()).unwrap());
        let c = InProcess::new(api, "test");
        kr_rt::exec::block_on(async move {
            // Four stale nodes in zone a, one fresh node in zone b.
            for n in ["a1", "a2", "a3", "a4"] {
                c.create("/api/v1/nodes", &node_json(n, "a", T0 - 1000)).await.unwrap();
            }
            c.create("/api/v1/nodes", &node_json("b1", "b", T0)).await.unwrap();
            // The API server drops status on create: give the nodes their heartbeats.
            for (n, z, beat) in [("a1", "a", T0), ("a2", "a", T0), ("a3", "a", T0), ("a4", "a", T0), ("b1", "b", T0 + 1000)] {
                let st = node_json(n, z, beat).get("status").cloned().unwrap();
                put_status(&c, &alloc::format!("/api/v1/nodes/{n}"), |_| st.clone()).await.unwrap();
            }
            let mut ev = Evictor::default();
            let l = Limits::default();
            let tainted = |c: InProcess| async move {
                let mut out = Vec::new();
                for n in items(&c.list("/api/v1/nodes", "").await.unwrap()) {
                    let ne = n.pointer(&["spec", "taints"]).and_then(Value::as_array).unwrap_or(&[]).iter().any(|t| str_at(t, &["effect"]) == "NoExecute");
                    let ns = n.pointer(&["spec", "taints"]).and_then(Value::as_array).unwrap_or(&[]).iter().any(|t| str_at(t, &["effect"]) == "NoSchedule");
                    out.push((name(&n).to_string(), ns, ne));
                }
                out
            };
            tick(&c, T0 + 1000, &mut ev, &l).await.unwrap();
            let t = tainted(c.clone()).await;
            // All four are NoSchedule-tainted at once, but only one got NoExecute (the burst).
            assert_eq!(t.iter().filter(|x| x.1).count(), 4);
            assert_eq!(t.iter().filter(|x| x.2).count(), 1);
            // Zone a is fully disrupted while zone b is healthy: no refill however long we wait.
            tick(&c, T0 + 1030, &mut ev, &l).await.unwrap();
            assert_eq!(tainted(c.clone()).await.iter().filter(|x| x.2).count(), 1);
        });
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
