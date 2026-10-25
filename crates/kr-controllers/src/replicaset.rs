//! The ReplicaSet controller: keeps `spec.replicas` (default 1) pods that match `spec.selector`
//! and are controlled by the ReplicaSet.
//!
//! Per reconcile (from fresh reads):
//!
//! 1. list the namespace's pods matching the selector; pods with a `deletionTimestamp` or in a
//!    terminal phase are ignored for counting;
//! 2. matching pods without any controller owner are *adopted* (merge patch of
//!    `ownerReferences`); pods controlled by something else are left alone;
//! 3. too few: create pods from `spec.template` (`generateName: <rs>-`, template labels and
//!    annotations, controller owner reference); too many: delete the most expendable first
//!    (unscheduled, then not running, then not ready, then newest);
//! 4. write `status` (`replicas`, `readyReplicas`, `availableReplicas`, `fullyLabeledReplicas`,
//!    `observedGeneration`) with a PUT of the full object to `replicasets/{name}/status`, only
//!    if it differs from what is stored. `availableReplicas` counts the ready pods that have been
//!    ready for `spec.minReadySeconds` (Ready condition's `lastTransitionTime`); the reconcile
//!    is repeated when the first of the others gets there.
//!
//! Pod events map to the owning ReplicaSet; events of orphan pods wake every ReplicaSet in the
//! namespace (key `<ns>/*`) so that adoption happens.

use crate::util::*;
use crate::Config;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Reverse;
use kr_apiserver::client::{Client, Result};
use kr_fmt::json::Value;

const MAX_BURST: usize = 500;

/// What differs between ReplicaSets and ReplicationControllers.
#[derive(Clone, Copy)]
struct Kind {
    kind: &'static str,
    api_version: &'static str,
    path: fn(Option<&str>) -> String,
    /// `spec.selector` is a plain label map (defaulting to the template labels).
    map_selector: bool,
}

const RS_KIND: Kind = Kind { kind: "ReplicaSet", api_version: "apps/v1", path: replicasets, map_selector: false };
const RC_KIND: Kind = Kind { kind: "ReplicationController", api_version: "v1", path: replicationcontrollers, map_selector: true };

pub async fn run<C: Client + Clone + 'static>(c: C, cfg: Config) {
    run_kind(c, cfg, RS_KIND).await
}

pub async fn run_rc<C: Client + Clone + 'static>(c: C, cfg: Config) {
    run_kind(c, cfg, RC_KIND).await
}

async fn run_kind<C: Client + Clone + 'static>(c: C, cfg: Config, k: Kind) {
    let q = Queue::new();
    let mut g = Guard::default();
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), (k.path)(None), String::new(), cfg, move |_, o| q2.add(&key_of(o)))));
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), pods(None), String::new(), cfg, move |_, p| match controller_ref(p) {
        Some(r) if str_at(r, &["kind"]) == k.kind => q2.add(&alloc::format!("{}/{}", namespace(p), str_at(r, &["name"]))),
        Some(_) => {}
        None => q2.add(&alloc::format!("{}/*", namespace(p))),
    })));
    let (c2, q2) = (c.clone(), q.clone());
    let (c3, q3) = (c.clone(), q.clone());
    drive(
        &cfg,
        &q,
        move |key| {
            let (c, q) = (c2.clone(), q2.clone());
            async move {
                let (ns, n) = split_key(&key);
                if n == "*" {
                    for rs in items(&c.list(&(k.path)(Some(ns)), "").await?) {
                        q.add(&key_of(&rs));
                    }
                    return Ok(None);
                }
                reconcile_kind(&c, &cfg, k, ns, n).await
            }
        },
        move || {
            let (c, q) = (c3.clone(), q3.clone());
            async move {
                if let Ok(l) = c.list(&(k.path)(None), "").await {
                    for rs in items(&l) {
                        q.add(&key_of(&rs));
                    }
                }
            }
        },
    )
    .await
}

fn phase_rank(p: &Value) -> u8 {
    match str_at(p, &["status", "phase"]) {
        "Running" => 2,
        "Pending" | "" => 0,
        _ => 1,
    }
}

/// Lower sorts first and is deleted first.
fn deletion_rank(p: &Value) -> (bool, u8, bool, Reverse<String>, Reverse<u64>) {
    let rv = str_at(p, &["metadata", "resourceVersion"]).parse::<u64>().unwrap_or(0);
    (!str_at(p, &["spec", "nodeName"]).is_empty(), phase_rank(p), pod_ready(p), Reverse(String::from(str_at(p, &["metadata", "creationTimestamp"]))), Reverse(rv))
}

fn fully_labeled(rs: &Value, p: &Value) -> bool {
    rs.pointer(&["spec", "template", "metadata", "labels"]).and_then(Value::as_object).unwrap_or(&[]).iter().all(|(k, v)| p.pointer(&["metadata", "labels", k]) == Some(v))
}

pub async fn reconcile<C: Client>(c: &C, cfg: &Config, ns: &str, name: &str) -> Result<Option<u64>> {
    reconcile_kind(c, cfg, RS_KIND, ns, name).await
}

async fn reconcile_kind<C: Client>(c: &C, cfg: &Config, k: Kind, ns: &str, name: &str) -> Result<Option<u64>> {
    let rs = match c.get(&alloc::format!("{}/{name}", (k.path)(Some(ns)))).await {
        Ok(r) => r,
        Err(e) if e.code == 404 => return Ok(None),
        Err(e) => return Err(e),
    };
    if deleting(&rs) {
        return Ok(None);
    }
    let desired = int_at(&rs, &["spec", "replicas"], 1).max(0) as usize;
    let parsed = if k.map_selector {
        let m = rs.pointer(&["spec", "selector"]).or_else(|| rs.pointer(&["spec", "template", "metadata", "labels"]));
        m.and_then(|m| parse_selector(&obj(alloc::vec![("matchLabels", m.clone())])))
    } else {
        rs.get("spec").and_then(|s| s.get("selector")).and_then(parse_selector)
    };
    let Some((_, sel)) = parsed else { return Ok(None) };
    // All of the namespace's pods: matching ones are claimed, controlled ones that no longer
    // match are released.
    let list = c.list(&pods(Some(ns)), "").await?;
    let rs_uid = uid(&rs);

    let mut owned: Vec<Value> = Vec::new();
    for p in items(&list) {
        let matches = sel.matches(&p);
        let live = !deleting(&p) && !pod_terminal(&p);
        match controller_ref(&p) {
            Some(r) if str_at(r, &["uid"]) == rs_uid && live => {
                if matches {
                    owned.push(p);
                } else {
                    release_owner(c, &pods(Some(ns)), rs_uid, &p).await?;
                }
            }
            Some(_) => {}
            None if matches && live => {
                if let Some(p) = adopt(c, k, &rs, &p).await? {
                    owned.push(p);
                }
            }
            None => {}
        }
    }

    let mut failure: Option<String> = None;
    if owned.len() < desired {
        let tpl = rs.pointer(&["spec", "template"]).cloned().unwrap_or(Value::Null);
        for _ in 0..(desired - owned.len()).min(MAX_BURST) {
            match c.create(&pods(Some(ns)), &pod_from_template(k, &rs, &tpl)).await {
                Ok(_) => {}
                // Refused (quota, admission): surfaced as the ReplicaFailure condition.
                Err(e) if e.code == 403 => {
                    failure = Some(e.message);
                    break;
                }
                Err(e) => return Err(e),
            }
        }
    } else if owned.len() > desired {
        owned.sort_by_key(deletion_rank);
        for p in owned.iter().take(owned.len() - desired) {
            match c.delete(&alloc::format!("{}/{}", pods(Some(ns)), name_of(p))).await {
                Ok(_) => {}
                Err(e) if e.code == 404 => {}
                Err(e) => return Err(e),
            }
        }
    }

    let ready = owned.iter().filter(|p| pod_ready(p)).count();
    let labeled = owned.iter().filter(|p| fully_labeled(&rs, p)).count();
    let (now, min_ready) = ((cfg.now)(), int_at(&rs, &["spec", "minReadySeconds"], 0));
    let available = owned.iter().filter(|p| pod_available(p, min_ready, now)).count();
    let soonest = owned.iter().filter_map(|p| available_in(p, min_ready, now)).min();
    write_status(c, k, ns, name, [owned.len(), ready, available, labeled], failure.as_deref(), now).await?;
    let retry = failure.map(|_| 5000);
    Ok([soonest.map(|s| s as u64 * 1000 + 50), retry].into_iter().flatten().min())
}

fn name_of(p: &Value) -> &str {
    name(p)
}

fn pod_from_template(k: Kind, rs: &Value, tpl: &Value) -> Value {
    let mut meta = alloc::vec![("generateName", Value::String(alloc::format!("{}-", name(rs)))), ("namespace", Value::from(namespace(rs)))];
    for f in ["labels", "annotations"] {
        if let Some(v) = tpl.pointer(&["metadata", f]) {
            meta.push((f, v.clone()));
        }
    }
    meta.push(("ownerReferences", Value::Array(alloc::vec![owner_ref(rs, k.api_version, k.kind)])));
    obj(alloc::vec![("apiVersion", Value::from("v1")), ("kind", Value::from("Pod")), ("metadata", obj(meta)), ("spec", tpl.get("spec").cloned().unwrap_or(Value::Null))])
}

/// Adds the controller reference to an orphan. `None` when the pod vanished or was adopted by
/// someone else in the meantime.
async fn adopt<C: Client>(c: &C, k: Kind, rs: &Value, p: &Value) -> Result<Option<Value>> {
    let mut refs: Vec<Value> = p.pointer(&["metadata", "ownerReferences"]).and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
    refs.push(owner_ref(rs, k.api_version, k.kind));
    // Guard against a concurrent adoption with the pod's resourceVersion.
    let meta = obj(alloc::vec![("ownerReferences", Value::Array(refs)), ("resourceVersion", Value::from(str_at(p, &["metadata", "resourceVersion"])))]);
    match c.patch(&alloc::format!("{}/{}", pods(Some(namespace(p))), name(p)), MERGE, &obj(alloc::vec![("metadata", meta)])).await {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.code == 404 || e.code == 409 => Ok(None),
        Err(e) => Err(e),
    }
}

async fn write_status<C: Client>(c: &C, k: Kind, ns: &str, name: &str, [replicas, ready, available, labeled]: [usize; 4], failure: Option<&str>, now: i64) -> Result<()> {
    let path = alloc::format!("{}/{name}", (k.path)(Some(ns)));
    retry_conflict(|| async {
        let mut rs = match c.get(&path).await {
            Ok(r) => r,
            Err(e) if e.code == 404 => return Ok(()),
            Err(e) => return Err(e),
        };
        let gen = int_at(&rs, &["metadata", "generation"], 0);
        let mut want = obj(alloc::vec![
            ("replicas", num(replicas as i64)),
            ("fullyLabeledReplicas", num(labeled as i64)),
            ("readyReplicas", num(ready as i64)),
            ("availableReplicas", num(available as i64)),
            ("observedGeneration", num(gen)),
        ]);
        // ReplicaFailure follows the last pod creation: set with its error, cleared on success.
        let mut conds: Vec<Value> = rs.pointer(&["status", "conditions"]).and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
        let old = conds.iter().position(|x| str_at(x, &["type"]) == "ReplicaFailure");
        match (failure, old) {
            (Some(msg), o) if o.is_none_or(|i| str_at(&conds[i], &["message"]) != msg) => {
                let cond = obj(alloc::vec![
                    ("type", Value::from("ReplicaFailure")),
                    ("status", Value::from("True")),
                    ("lastTransitionTime", Value::String(rfc3339(now))),
                    ("reason", Value::from("FailedCreate")),
                    ("message", Value::from(msg)),
                ]);
                set_condition(&mut conds, cond);
            }
            (None, Some(i)) => {
                conds.remove(i);
            }
            _ => {}
        }
        if !conds.is_empty() {
            want.set("conditions", Value::Array(conds));
        }
        let same = rs.get("status").map(canonical) == Some(canonical(&want));
        if same {
            return Ok(());
        }
        rs.set("status", want);
        c.update(&alloc::format!("{path}/status"), &rs).await.map(|_| ())
    })
    .await
}
