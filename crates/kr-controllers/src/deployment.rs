//! The Deployment controller: one ReplicaSet per pod template, rolled over per strategy.
//!
//! * **Template hash.** `pod-template-hash` is FNV-1a (32 bit) over the canonical JSON of
//!   `spec.template` (object keys sorted), rendered like upstream's `SafeEncodeString` into the
//!   alphabet `[bcdfghjklmnpqrstvwxz2456789]`. Equal templates give equal hashes, which is all
//!   that is required; it does not reproduce upstream's values.
//! * **New ReplicaSet.** `<deployment>-<hash>`, found by its `pod-template-hash` label among the
//!   ReplicaSets the deployment controls, or created (owned, with the hash added to its labels,
//!   selector and template labels). Created at 0 replicas and scaled by the strategy below.
//!   Every ReplicaSet carries the `deployment.kubernetes.io/revision` annotation (the new one
//!   gets max(old)+1, so rolling back to an old template bumps its revision).
//! * **Recreate.** Scale every old ReplicaSet to 0, wait (re-check every `Config::retry_ms`)
//!   until none of their pods is left, then scale the new one to `spec.replicas`.
//! * **RollingUpdate** (default). `maxSurge`/`maxUnavailable` are int-or-percent, default 25%,
//!   surge rounded up and unavailable rounded down; both 0 means unavailable 1. Like upstream:
//!   first scale the new ReplicaSet up within `desired + maxSurge` in total, otherwise first
//!   clean up unhealthy old replicas and then scale old ReplicaSets down (oldest first) while
//!   `available >= desired - maxUnavailable`, using the ready counts from ReplicaSet status.
//!   One step per reconcile; the resulting ReplicaSet events trigger the next.
//! * **History.** Old ReplicaSets at 0 replicas and 0 pods beyond `revisionHistoryLimit`
//!   (default 10) are deleted, oldest revision first.
//! * **Status.** `replicas`, `updatedReplicas`, `readyReplicas`, `availableReplicas`,
//!   `unavailableReplicas`, `observedGeneration` and conditions `Available` and `Progressing`
//!   (`NewReplicaSetAvailable` once complete), written through `deployments/{name}/status`
//!   only when something other than a timestamp changed.
//!
//! Not modelled: pausing, progress deadlines, proportional scaling during a rollout, adoption
//! of orphan ReplicaSets.

use crate::util::*;
use crate::Config;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_apiserver::client::{Client, Result};
use kr_fmt::json::{self, Value};

pub const REVISION: &str = "deployment.kubernetes.io/revision";
pub const HASH_LABEL: &str = "pod-template-hash";

pub async fn run<C: Client + Clone + 'static>(c: C, cfg: Config) {
    let q = Queue::new();
    let mut g = Guard::default();
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), deployments(None), String::new(), cfg, move |_, o| q2.add(&key_of(o)))));
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), replicasets(None), String::new(), cfg, move |_, rs| {
        if let Some(r) = controller_ref(rs).filter(|r| str_at(r, &["kind"]) == "Deployment") {
            q2.add(&alloc::format!("{}/{}", namespace(rs), str_at(r, &["name"])));
        }
    })));
    let (c2, c3, q3) = (c.clone(), c.clone(), q.clone());
    drive(
        &cfg,
        &q,
        move |key| {
            let c = c2.clone();
            async move {
                let (ns, n) = split_key(&key);
                reconcile(&c, &cfg, ns, n).await
            }
        },
        move || {
            let (c, q) = (c3.clone(), q3.clone());
            async move {
                if let Ok(l) = c.list(&deployments(None), "").await {
                    for d in items(&l) {
                        q.add(&key_of(&d));
                    }
                }
            }
        },
    )
    .await
}

/// The `pod-template-hash` of a pod template.
pub fn template_hash(template: &Value) -> String {
    let h = fnv1a32(json::to_string(&canonical(template)).as_bytes());
    safe_encode(&h.to_string())
}

/// Resolves an int-or-percent against `total`.
pub fn resolve_intstr(v: Option<&Value>, total: i64, default: &str, round_up: bool) -> i64 {
    let s: String = match v {
        Some(Value::Number(n)) => return n.as_i64().unwrap_or(0).max(0),
        Some(Value::String(s)) => s.clone(),
        _ => default.to_string(),
    };
    match s.strip_suffix('%') {
        Some(p) => {
            let p: i64 = p.parse().unwrap_or(0);
            let x = total * p;
            (if round_up { (x + 99) / 100 } else { x / 100 }).max(0)
        }
        None => s.parse::<i64>().unwrap_or(0).max(0),
    }
}

/// `(maxSurge, maxUnavailable)` for a rolling update; if both come out 0 unavailable is 1.
pub fn fenceposts(d: &Value, desired: i64) -> (i64, i64) {
    let ru = d.pointer(&["spec", "strategy", "rollingUpdate"]);
    let surge = resolve_intstr(ru.and_then(|r| r.get("maxSurge")), desired, "25%", true);
    let mut unavail = resolve_intstr(ru.and_then(|r| r.get("maxUnavailable")), desired, "25%", false);
    if surge == 0 && unavail == 0 {
        unavail = 1;
    }
    (surge, unavail)
}

fn revision_of(rs: &Value) -> i64 {
    rs.pointer(&["metadata", "annotations", REVISION]).and_then(Value::as_str).and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn spec_replicas(rs: &Value) -> i64 {
    int_at(rs, &["spec", "replicas"], 1)
}

fn status_of(rs: &Value, f: &str) -> i64 {
    int_at(rs, &["status", f], 0)
}

async fn scale<C: Client>(c: &C, ns: &str, rs: &mut Value, n: i64) -> Result<()> {
    let patch = obj(alloc::vec![("spec", obj(alloc::vec![("replicas", num(n))]))]);
    c.patch(&alloc::format!("{}/{}", replicasets(Some(ns)), name(rs)), MERGE, &patch).await?;
    rs.entry_object("spec").set("replicas", num(n));
    Ok(())
}

fn new_replicaset(d: &Value, hash: &str, revision: i64) -> Value {
    let mut template = d.pointer(&["spec", "template"]).cloned().unwrap_or(Value::Null);
    template.entry_object("metadata").entry_object("labels").set(HASH_LABEL, Value::from(hash));
    let mut selector = d.pointer(&["spec", "selector"]).cloned().unwrap_or(Value::Null);
    if !matches!(selector, Value::Object(_)) {
        selector = Value::Object(Vec::new());
    }
    selector.entry_object("matchLabels").set(HASH_LABEL, Value::from(hash));
    let labels = template.pointer(&["metadata", "labels"]).cloned().unwrap_or(Value::Null);
    let mut spec = alloc::vec![("replicas", num(0)), ("selector", selector), ("template", template)];
    if let Some(m) = d.pointer(&["spec", "minReadySeconds"]) {
        spec.push(("minReadySeconds", m.clone()));
    }
    obj(alloc::vec![
        ("apiVersion", Value::from("apps/v1")),
        ("kind", Value::from("ReplicaSet")),
        (
            "metadata",
            obj(alloc::vec![
                ("name", Value::String(alloc::format!("{}-{hash}", name(d)))),
                ("namespace", Value::from(namespace(d))),
                ("labels", labels),
                ("annotations", obj(alloc::vec![(REVISION, Value::String(revision.to_string()))])),
                ("ownerReferences", Value::Array(alloc::vec![owner_ref(d, "apps/v1", "Deployment")])),
            ])
        ),
        ("spec", obj(spec)),
    ])
}

pub async fn reconcile<C: Client>(c: &C, cfg: &Config, ns: &str, dname: &str) -> Result<Option<u64>> {
    let d = match c.get(&alloc::format!("{}/{dname}", deployments(Some(ns)))).await {
        Ok(d) => d,
        Err(e) if e.code == 404 => return Ok(None),
        Err(e) => return Err(e),
    };
    if deleting(&d) {
        return Ok(None);
    }
    let desired = int_at(&d, &["spec", "replicas"], 1).max(0);
    let d_uid = uid(&d).to_string();
    let hash = template_hash(d.pointer(&["spec", "template"]).unwrap_or(&Value::Null));

    let mut olds: Vec<Value> = Vec::new();
    let mut new_rs: Option<Value> = None;
    for rs in items(&c.list(&replicasets(Some(ns)), "").await?) {
        if controller_ref(&rs).is_none_or(|r| str_at(r, &["uid"]) != d_uid) || deleting(&rs) {
            continue;
        }
        if str_at(&rs, &["metadata", "labels", HASH_LABEL]) == hash {
            new_rs = Some(rs);
        } else {
            olds.push(rs);
        }
    }
    olds.sort_by(|a, b| (str_at(a, &["metadata", "creationTimestamp"]), revision_of(a), name(a)).cmp(&(str_at(b, &["metadata", "creationTimestamp"]), revision_of(b), name(b))));
    let want_rev = olds.iter().map(revision_of).max().unwrap_or(0) + 1;

    let mut new_rs = match new_rs {
        Some(mut rs) => {
            if revision_of(&rs) < want_rev {
                let patch = obj(alloc::vec![("metadata", obj(alloc::vec![("annotations", obj(alloc::vec![(REVISION, Value::String(want_rev.to_string()))]))]))]);
                c.patch(&alloc::format!("{}/{}", replicasets(Some(ns)), name(&rs)), MERGE, &patch).await?;
                rs.entry_object("metadata").entry_object("annotations").set(REVISION, Value::String(want_rev.to_string()));
            }
            rs
        }
        None => match c.create(&replicasets(Some(ns)), &new_replicaset(&d, &hash, want_rev)).await {
            Ok(rs) => rs,
            Err(e) if e.code == 409 => return Ok(Some(0)), // stale list; look again
            Err(e) => return Err(e),
        },
    };

    let recreate = str_at(&d, &["spec", "strategy", "type"]) == "Recreate";
    let mut wait = None;
    if recreate {
        for old in olds.iter_mut().filter(|o| spec_replicas(o) > 0) {
            scale(c, ns, old, 0).await?;
        }
        let old_uids: Vec<&str> = olds.iter().map(uid).collect();
        let left = items(&c.list(&pods(Some(ns)), "").await?).iter().filter(|p| !pod_terminal(p) && controller_ref(p).is_some_and(|r| old_uids.contains(&str_at(r, &["uid"])))).count();
        if left > 0 {
            wait = Some(cfg.retry_ms);
        } else if spec_replicas(&new_rs) != desired {
            scale(c, ns, &mut new_rs, desired).await?;
        }
    } else {
        rolling(c, ns, &d, desired, &mut new_rs, &mut olds).await?;
    }

    cleanup_history(c, ns, &d, &olds).await?;
    write_status(c, cfg, ns, dname, desired, &new_rs, &olds).await?;
    Ok(wait)
}

/// One rolling-update step (see the module docs).
async fn rolling<C: Client>(c: &C, ns: &str, d: &Value, desired: i64, new_rs: &mut Value, olds: &mut [Value]) -> Result<()> {
    let (surge, max_unavail) = fenceposts(d, desired);
    let total: i64 = olds.iter().map(spec_replicas).sum::<i64>() + spec_replicas(new_rs);
    let cur = spec_replicas(new_rs);
    if cur > desired {
        return scale(c, ns, new_rs, desired).await;
    }
    if cur < desired {
        let room = desired + surge - total;
        if room > 0 {
            return scale(c, ns, new_rs, desired.min(cur + room)).await;
        }
    }
    let min_available = desired - max_unavail;
    let new_unavailable = spec_replicas(new_rs) - status_of(new_rs, "availableReplicas");
    let max_scaled_down = total - min_available - new_unavailable;
    if max_scaled_down <= 0 {
        return Ok(());
    }
    // Unhealthy old replicas go first.
    let mut cleaned = 0;
    for old in olds.iter_mut() {
        if cleaned >= max_scaled_down {
            break;
        }
        let (spec, avail) = (spec_replicas(old), status_of(old, "availableReplicas"));
        if spec == 0 || spec <= avail {
            continue;
        }
        let n = (spec - avail).min(max_scaled_down - cleaned);
        scale(c, ns, old, spec - n).await?;
        cleaned += n;
    }
    // Then healthy ones, as long as availability stays above the floor.
    let available: i64 = olds.iter().map(|o| status_of(o, "availableReplicas")).sum::<i64>() + status_of(new_rs, "availableReplicas");
    let mut budget = available - min_available;
    for old in olds.iter_mut() {
        if budget <= 0 {
            break;
        }
        let spec = spec_replicas(old);
        if spec == 0 {
            continue;
        }
        let n = spec.min(budget);
        scale(c, ns, old, spec - n).await?;
        budget -= n;
    }
    Ok(())
}

async fn cleanup_history<C: Client>(c: &C, ns: &str, d: &Value, olds: &[Value]) -> Result<()> {
    let limit = int_at(d, &["spec", "revisionHistoryLimit"], 10).max(0) as usize;
    let mut dead: Vec<&Value> = olds.iter().filter(|o| spec_replicas(o) == 0 && status_of(o, "replicas") == 0).collect();
    if dead.len() <= limit {
        return Ok(());
    }
    dead.sort_by_key(|o| (revision_of(o), name(o).to_string()));
    for o in dead.iter().take(dead.len() - limit) {
        match c.delete(&alloc::format!("{}/{}", replicasets(Some(ns)), name(o))).await {
            Ok(_) => {}
            Err(e) if e.code == 404 => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn cond_same(a: &Value, b: &Value) -> bool {
    ["type", "status", "reason", "message"].iter().all(|f| str_at(a, &[f]) == str_at(b, &[f]))
}

async fn write_status<C: Client>(c: &C, cfg: &Config, ns: &str, dname: &str, desired: i64, new_rs: &Value, olds: &[Value]) -> Result<()> {
    let all = || olds.iter().chain(core::iter::once(new_rs));
    let replicas: i64 = all().map(|r| status_of(r, "replicas")).sum();
    let ready: i64 = all().map(|r| status_of(r, "readyReplicas")).sum();
    let available: i64 = all().map(|r| status_of(r, "availableReplicas")).sum();
    let updated = status_of(new_rs, "replicas");
    let path = alloc::format!("{}/{dname}", deployments(Some(ns)));
    retry_conflict(|| async {
        let mut d = match c.get(&path).await {
            Ok(d) => d,
            Err(e) if e.code == 404 => return Ok(()),
            Err(e) => return Err(e),
        };
        let (_, max_unavail) = fenceposts(&d, desired);
        let max_unavail = if str_at(&d, &["spec", "strategy", "type"]) == "Recreate" { 0 } else { max_unavail };
        let now = kr_apiserver::object::rfc3339((cfg.now)());
        let complete = updated == desired && replicas == desired && available == desired && spec_replicas(new_rs) == desired;
        let avail_ok = available >= desired - max_unavail;
        let rs_name = name(new_rs);
        let old_conds: Vec<Value> = d.pointer(&["status", "conditions"]).and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
        let mut conds = old_conds.clone();
        for (ty, status, reason, msg) in [
            (
                "Available",
                avail_ok,
                if avail_ok { "MinimumReplicasAvailable" } else { "MinimumReplicasUnavailable" },
                if avail_ok { "Deployment has minimum availability." } else { "Deployment does not have minimum availability." }.to_string(),
            ),
            (
                "Progressing",
                true,
                if complete { "NewReplicaSetAvailable" } else { "ReplicaSetUpdated" },
                if complete { alloc::format!("ReplicaSet \"{rs_name}\" has successfully progressed.") } else { alloc::format!("ReplicaSet \"{rs_name}\" is progressing.") },
            ),
        ] {
            let status = if status { "True" } else { "False" };
            let mut cond = obj(alloc::vec![("type", Value::from(ty)), ("status", Value::from(status)), ("reason", Value::from(reason)), ("message", Value::String(msg)), ("lastUpdateTime", Value::String(now.clone())), ("lastTransitionTime", Value::String(now.clone()))]);
            if let Some(old) = old_conds.iter().find(|o| str_at(o, &["type"]) == ty) {
                if cond_same(old, &cond) {
                    continue; // unchanged: keep the stored timestamps
                }
                if str_at(old, &["status"]) == status {
                    cond.set("lastTransitionTime", Value::from(str_at(old, &["lastTransitionTime"])));
                }
            }
            set_condition(&mut conds, cond);
        }
        let gen = int_at(&d, &["metadata", "generation"], 0);
        let nums = [("replicas", replicas), ("updatedReplicas", updated), ("readyReplicas", ready), ("availableReplicas", available), ("unavailableReplicas", (desired - available).max(0)), ("observedGeneration", gen)];
        let same = nums.iter().all(|(f, v)| d.pointer(&["status", f]).and_then(Value::as_i64) == Some(*v)) && conds.len() == old_conds.len() && conds.iter().zip(&old_conds).all(|(a, b)| a == b);
        if same {
            return Ok(());
        }
        let st = d.entry_object("status");
        for (f, v) in nums {
            st.set(f, num(v));
        }
        st.set("conditions", Value::Array(conds));
        c.update(&alloc::format!("{path}/status"), &d).await.map(|_| ())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_fmt::json::parse_str;

    #[test]
    fn intstr_rounding() {
        let p = |s: &str| Value::from(s);
        assert_eq!(resolve_intstr(Some(&p("25%")), 10, "25%", true), 3);
        assert_eq!(resolve_intstr(Some(&p("25%")), 10, "25%", false), 2);
        assert_eq!(resolve_intstr(None, 3, "25%", false), 0);
        assert_eq!(resolve_intstr(Some(&Value::from(2u64)), 10, "25%", true), 2);
        let d = parse_str(r#"{"spec":{"rollingUpdate":null}}"#).unwrap();
        assert_eq!(fenceposts(&d, 3), (1, 0));
        let d = parse_str(r#"{"spec":{"strategy":{"rollingUpdate":{"maxSurge":0,"maxUnavailable":"0%"}}}}"#).unwrap();
        assert_eq!(fenceposts(&d, 3), (0, 1));
    }

    #[test]
    fn hash_is_stable_and_order_independent() {
        let a = parse_str(r#"{"metadata":{"labels":{"a":"b"}},"spec":{"containers":[{"name":"x","image":"i:1"}]}}"#).unwrap();
        let b = parse_str(r#"{"spec":{"containers":[{"image":"i:1","name":"x"}]},"metadata":{"labels":{"a":"b"}}}"#).unwrap();
        let c = parse_str(r#"{"metadata":{"labels":{"a":"b"}},"spec":{"containers":[{"name":"x","image":"i:2"}]}}"#).unwrap();
        assert_eq!(template_hash(&a), template_hash(&b));
        assert_ne!(template_hash(&a), template_hash(&c));
        assert!(template_hash(&a).bytes().all(|x| b"bcdfghjklmnpqrstvwxz2456789".contains(&x)));
    }
}
