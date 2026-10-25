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
//!   `available >= desired - maxUnavailable`, using the available counts from ReplicaSet status
//!   (a pod is available after being Ready for `minReadySeconds`; the ReplicaSets compute it and
//!   inherit `spec.minReadySeconds`).
//!   One step per reconcile; the resulting ReplicaSet events trigger the next.
//! * **History.** Old ReplicaSets at 0 replicas and 0 pods beyond `revisionHistoryLimit`
//!   (default 10) are deleted, oldest revision first.
//! * **Status.** `replicas`, `updatedReplicas`, `readyReplicas`, `availableReplicas`,
//!   `unavailableReplicas`, `observedGeneration` and conditions `Available` and `Progressing`,
//!   written through `deployments/{name}/status` only when something other than a timestamp
//!   changed. `Progressing` follows upstream: `NewReplicaSetCreated` / `FoundNewReplicaSet` /
//!   `ReplicaSetUpdated` (True, `lastUpdateTime` refreshed whenever the replica counts move),
//!   `NewReplicaSetAvailable` once complete, `ProgressDeadlineExceeded` (False) when no
//!   progress was made for `progressDeadlineSeconds` (default 600), and `DeploymentPaused`
//!   (Unknown) while paused.
//! * **Pause.** With `spec.paused` no ReplicaSet is created and no rollout step is taken; only a
//!   plain scale of the single live ReplicaSet to `spec.replicas` happens. Resuming continues.
//!
//! Not modelled: proportional scaling during a rollout, adoption of orphan ReplicaSets.

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
        match controller_ref(rs) {
            Some(r) if str_at(r, &["kind"]) == "Deployment" => q2.add(&alloc::format!("{}/{}", namespace(rs), str_at(r, &["name"]))),
            Some(_) => {}
            // An orphan may be adopted by any Deployment of the namespace.
            None => q2.add(&alloc::format!("{}/*", namespace(rs))),
        }
    })));
    let (c2, q2, c3, q3) = (c.clone(), q.clone(), c.clone(), q.clone());
    drive(
        &cfg,
        &q,
        move |key| {
            let (c, q) = (c2.clone(), q2.clone());
            async move {
                let (ns, n) = split_key(&key);
                if n == "*" {
                    for d in items(&c.list(&deployments(Some(ns)), "").await?) {
                        q.add(&key_of(&d));
                    }
                    return Ok(None);
                }
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
    let sel = d.pointer(&["spec", "selector"]).and_then(parse_selector).map(|(_, s)| s);
    for rs in items(&c.list(&replicasets(Some(ns)), "").await?) {
        if deleting(&rs) {
            continue;
        }
        // Orphan ReplicaSets that match the selector become old ReplicaSets of this Deployment.
        let rs = match controller_ref(&rs) {
            None if sel.as_ref().is_some_and(|s| s.matches(&rs)) => match adopt(c, &replicasets(Some(ns)), &d, "apps/v1", "Deployment", &rs).await? {
                Some(rs) => rs,
                None => continue,
            },
            _ => rs,
        };
        if controller_ref(&rs).is_none_or(|r| str_at(r, &["uid"]) != d_uid) {
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

    let paused = d.pointer(&["spec", "paused"]).and_then(Value::as_bool) == Some(true);
    let mut created = false;
    let mut new_rs = match new_rs {
        Some(mut rs) => {
            if revision_of(&rs) < want_rev {
                let patch = obj(alloc::vec![("metadata", obj(alloc::vec![("annotations", obj(alloc::vec![(REVISION, Value::String(want_rev.to_string()))]))]))]);
                c.patch(&alloc::format!("{}/{}", replicasets(Some(ns)), name(&rs)), MERGE, &patch).await?;
                rs.entry_object("metadata").entry_object("annotations").set(REVISION, Value::String(want_rev.to_string()));
            }
            let min_ready = d.pointer(&["spec", "minReadySeconds"]).cloned().unwrap_or(num(0));
            if rs.pointer(&["spec", "minReadySeconds"]).and_then(Value::as_i64).unwrap_or(0) != min_ready.as_i64().unwrap_or(0) {
                let patch = obj(alloc::vec![("spec", obj(alloc::vec![("minReadySeconds", min_ready.clone())]))]);
                c.patch(&alloc::format!("{}/{}", replicasets(Some(ns)), name(&rs)), MERGE, &patch).await?;
                rs.entry_object("spec").set("minReadySeconds", min_ready);
            }
            Some(rs)
        }
        None if paused => None,
        None => match c.create(&replicasets(Some(ns)), &new_replicaset(&d, &hash, want_rev)).await {
            Ok(rs) => {
                created = true;
                Some(rs)
            }
            Err(e) if e.code == 409 => return Ok(Some(0)), // stale list; look again
            Err(e) => return Err(e),
        },
    };

    // The Deployment mirrors its new ReplicaSet's revision (kubectl rollout and clients read it).
    let rev = new_rs.as_ref().map_or(want_rev - 1, revision_of).to_string();
    if new_rs.is_some() && str_at(&d, &["metadata", "annotations", REVISION]) != rev {
        let patch = obj(alloc::vec![("metadata", obj(alloc::vec![("annotations", obj(alloc::vec![(REVISION, Value::String(rev))]))]))]);
        c.patch(&alloc::format!("{}/{dname}", deployments(Some(ns))), MERGE, &patch).await?;
    }

    let recreate = str_at(&d, &["spec", "strategy", "type"]) == "Recreate";
    let mut wait = None;
    if paused {
        // No rollout: only a plain scale when a single ReplicaSet is live.
        let live = olds.iter().filter(|o| spec_replicas(o) > 0).count() + new_rs.as_ref().map_or(0, |n| (spec_replicas(n) > 0) as usize);
        if live <= 1 {
            match new_rs.as_mut().filter(|n| spec_replicas(n) > 0 || live == 0) {
                Some(n) if spec_replicas(n) != desired => scale(c, ns, n, desired).await?,
                Some(_) => {}
                None => {
                    if let Some(o) = olds.iter_mut().find(|o| spec_replicas(o) > 0).filter(|o| spec_replicas(o) != desired) {
                        scale(c, ns, o, desired).await?;
                    }
                }
            }
        }
    } else if let Some(new_rs) = new_rs.as_mut() {
        if recreate {
            for old in olds.iter_mut().filter(|o| spec_replicas(o) > 0) {
                scale(c, ns, old, 0).await?;
            }
            let old_uids: Vec<&str> = olds.iter().map(uid).collect();
            let left = items(&c.list(&pods(Some(ns)), "").await?).iter().filter(|p| !pod_terminal(p) && controller_ref(p).is_some_and(|r| old_uids.contains(&str_at(r, &["uid"])))).count();
            if left > 0 {
                wait = Some(cfg.retry_ms);
            } else if spec_replicas(new_rs) != desired {
                scale(c, ns, new_rs, desired).await?;
            }
        } else {
            rolling(c, ns, &d, desired, new_rs, &mut olds).await?;
        }
    }

    cleanup_history(c, ns, &d, &olds).await?;
    let w = write_status(c, cfg, ns, dname, desired, new_rs.as_ref(), &olds, paused, created).await?;
    Ok(match (wait, w) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    })
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

/// Writes the status; returns when to look again (the progress deadline).
#[allow(clippy::too_many_arguments)]
async fn write_status<C: Client>(c: &C, cfg: &Config, ns: &str, dname: &str, desired: i64, new_rs: Option<&Value>, olds: &[Value], paused: bool, created: bool) -> Result<Option<u64>> {
    let all = || olds.iter().chain(new_rs);
    let replicas: i64 = all().map(|r| status_of(r, "replicas")).sum();
    let ready: i64 = all().map(|r| status_of(r, "readyReplicas")).sum();
    let available: i64 = all().map(|r| status_of(r, "availableReplicas")).sum();
    let updated = new_rs.map_or(0, |r| status_of(r, "replicas"));
    let path = alloc::format!("{}/{dname}", deployments(Some(ns)));
    let wait = core::cell::Cell::new(None);
    retry_conflict(|| async {
        let mut d = match c.get(&path).await {
            Ok(d) => d,
            Err(e) if e.code == 404 => return Ok(()),
            Err(e) => return Err(e),
        };
        let (_, max_unavail) = fenceposts(&d, desired);
        let max_unavail = if str_at(&d, &["spec", "strategy", "type"]) == "Recreate" { 0 } else { max_unavail };
        let now_s = (cfg.now)();
        let now = kr_apiserver::object::rfc3339(now_s);
        let complete = new_rs.is_some_and(|n| updated == desired && replicas == desired && available == desired && spec_replicas(n) == desired);
        let avail_ok = available >= desired - max_unavail;
        let rs_name = new_rs.map_or("", name);
        let old_conds: Vec<Value> = d.pointer(&["status", "conditions"]).and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
        let mut conds = old_conds.clone();
        let cond = obj(alloc::vec![
            ("type", Value::from("Available")),
            ("status", Value::from(if avail_ok { "True" } else { "False" })),
            ("reason", Value::from(if avail_ok { "MinimumReplicasAvailable" } else { "MinimumReplicasUnavailable" })),
            ("message", Value::from(if avail_ok { "Deployment has minimum availability." } else { "Deployment does not have minimum availability." })),
            ("lastUpdateTime", Value::String(now.clone())),
            ("lastTransitionTime", Value::String(now.clone())),
        ]);
        let cond = merge_cond(&old_conds, cond);
        set_condition(&mut conds, cond);

        // Progressing.
        let old_prog = old_conds.iter().find(|o| str_at(o, &["type"]) == "Progressing");
        let old_reason = old_prog.map_or("", |o| str_at(o, &["reason"]));
        let moved = [("replicas", replicas), ("updatedReplicas", updated), ("readyReplicas", ready), ("availableReplicas", available)].iter().any(|(f, v)| d.pointer(&["status", f]).and_then(Value::as_i64).unwrap_or(0) != *v);
        let progress = created || moved || old_prog.is_none() || matches!(old_reason, "NewReplicaSetAvailable" | "DeploymentPaused");
        let deadline = int_at(&d, &["spec", "progressDeadlineSeconds"], 600).max(1);
        let (status, reason, msg, fresh) = if paused {
            ("Unknown", "DeploymentPaused", "Deployment is paused".to_string(), false)
        } else if complete {
            ("True", "NewReplicaSetAvailable", alloc::format!("ReplicaSet \"{rs_name}\" has successfully progressed."), false)
        } else if progress {
            wait.set(Some(deadline as u64 * 1000 + 50));
            let (r, m) = if created {
                ("NewReplicaSetCreated", alloc::format!("Created new replica set \"{rs_name}\""))
            } else if old_prog.is_none() {
                ("FoundNewReplicaSet", alloc::format!("Found new replica set \"{rs_name}\""))
            } else {
                ("ReplicaSetUpdated", alloc::format!("ReplicaSet \"{rs_name}\" is progressing."))
            };
            ("True", r, m, true)
        } else {
            let last = old_prog.and_then(|o| parse_time(str_at(o, &["lastUpdateTime"]))).unwrap_or(now_s);
            if old_reason == "ProgressDeadlineExceeded" || now_s - last >= deadline {
                ("False", "ProgressDeadlineExceeded", alloc::format!("ReplicaSet \"{rs_name}\" has timed out progressing."), false)
            } else {
                wait.set(Some(((last + deadline - now_s).max(0) as u64) * 1000 + 50));
                let o = old_prog.cloned().unwrap_or(Value::Null);
                (if str_at(&o, &["status"]) == "False" { "False" } else { "True" }, if old_reason.is_empty() { "ReplicaSetUpdated" } else { old_reason }, str_at(&o, &["message"]).to_string(), false)
            }
        };
        let mut cond = obj(alloc::vec![("type", Value::from("Progressing")), ("status", Value::from(status)), ("reason", Value::from(reason)), ("message", Value::String(msg)), ("lastUpdateTime", Value::String(now.clone())), ("lastTransitionTime", Value::String(now.clone()))]);
        if let Some(old) = old_prog {
            if !fresh && cond_same(old, &cond) {
                cond = old.clone();
            } else if str_at(old, &["status"]) == status {
                cond.set("lastTransitionTime", Value::from(str_at(old, &["lastTransitionTime"])));
            }
        }
        set_condition(&mut conds, cond);
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
    .await?;
    Ok(wait.get())
}

/// A condition keeping the stored one (timestamps included) while nothing but timestamps differ.
fn merge_cond(old: &[Value], mut cond: Value) -> Value {
    let ty = str_at(&cond, &["type"]);
    if let Some(o) = old.iter().find(|o| str_at(o, &["type"]) == ty) {
        if cond_same(o, &cond) {
            return o.clone();
        }
        if str_at(o, &["status"]) == str_at(&cond, &["status"]) {
            cond.set("lastTransitionTime", Value::from(str_at(o, &["lastTransitionTime"])));
        }
    }
    cond
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
