//! The DaemonSet controller: one pod per eligible node.
//!
//! A node is *eligible* when the pod template (plus the standard DaemonSet tolerations) passes
//! the scheduler's predicates that apply to DaemonSets: `nodeSelector`, required node affinity
//! (`nodeSelectorTerms` with `matchExpressions` In/NotIn/Exists/DoesNotExist/Gt/Lt and
//! `matchFields` on `metadata.name`) and every `NoSchedule`/`NoExecute` taint being tolerated.
//! Readiness and resources of the node are not considered (the standard tolerations cover
//! `not-ready`, `unreachable` and `unschedulable`).
//!
//! Pods are bound directly: `spec.nodeName` is set at creation (the scheduler never sees them),
//! and they carry the standard tolerations, `controller-revision-hash` (the ControllerRevision
//! `<ds>-<hash>` of the template) and `pod-template-generation`.
//!
//! Per reconcile: pods controlled by the DaemonSet (matching orphans are adopted) are grouped by
//! node. Eligible node without a pod: create one (unless a terminating pod is still there).
//! Pods on ineligible or vanished nodes, extra pods on a node (the oldest healthy one is kept)
//! and Failed/Succeeded pods are deleted. Then the update strategy:
//!
//! * `RollingUpdate` (default): `maxUnavailable` (int or percent of the desired count, rounded
//!   up, default 1, 0 means 1). Like upstream, nodes without an available pod count as
//!   unavailable; old pods that are not available are replaced at once, old available ones are
//!   deleted while the unavailable count stays below the maximum.
//! * `OnDelete`: old pods are only replaced after someone deletes them.
//!
//! Status: `desiredNumberScheduled`, `currentNumberScheduled`, `numberMisscheduled`,
//! `numberReady`, `numberAvailable` (= ready), `numberUnavailable`, `updatedNumberScheduled`,
//! `observedGeneration`, `collisionCount`. Not modelled: `maxSurge`, `minReadySeconds`, creation
//! back-off for crash-looping pods.

use crate::scheduler::{selector_matches, untolerated_taint};
use crate::util::*;
use crate::Config;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_apiserver::client::{Client, Result};
use kr_fmt::json::Value;

pub const REVISION_LABEL: &str = "controller-revision-hash";
pub const GENERATION_LABEL: &str = "pod-template-generation";

pub async fn run<C: Client + Clone + 'static>(c: C, cfg: Config) {
    let q = Queue::new();
    let mut g = Guard::default();
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), daemonsets(None), String::new(), cfg, move |_, o| q2.add(&key_of(o)))));
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), pods(None), String::new(), cfg, move |_, p| match controller_ref(p) {
        Some(r) if str_at(r, &["kind"]) == "DaemonSet" => q2.add(&alloc::format!("{}/{}", namespace(p), str_at(r, &["name"]))),
        Some(_) => {}
        None => q2.add("*/*"),
    })));
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), NODES.to_string(), String::new(), cfg, move |_, _| q2.add("*/*"))));
    let (c2, q2) = (c.clone(), q.clone());
    let (c3, q3) = (c.clone(), q.clone());
    drive(
        &cfg,
        &q,
        move |key| {
            let (c, q) = (c2.clone(), q2.clone());
            async move {
                let (ns, n) = split_key(&key);
                if ns == "*" {
                    for d in items(&c.list(&daemonsets(None), "").await?) {
                        q.add(&key_of(&d));
                    }
                    return Ok(None);
                }
                reconcile(&c, ns, n).await
            }
        },
        move || {
            let (c, q) = (c3.clone(), q3.clone());
            async move {
                if let Ok(l) = c.list(&daemonsets(None), "").await {
                    for d in items(&l) {
                        q.add(&key_of(&d));
                    }
                }
            }
        },
    )
    .await
}

fn toleration(key: &str, effect: &str) -> Value {
    obj(alloc::vec![("key", Value::from(key)), ("operator", Value::from("Exists")), ("effect", Value::from(effect))])
}

/// Upstream's `AddOrUpdateDaemonPodTolerations`: template tolerations plus the standard ones.
pub fn daemon_tolerations(spec: &Value) -> Vec<Value> {
    let mut tols: Vec<Value> = spec.get("tolerations").and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
    let mut std = alloc::vec![
        toleration("node.kubernetes.io/not-ready", "NoExecute"),
        toleration("node.kubernetes.io/unreachable", "NoExecute"),
        toleration("node.kubernetes.io/disk-pressure", "NoSchedule"),
        toleration("node.kubernetes.io/memory-pressure", "NoSchedule"),
        toleration("node.kubernetes.io/pid-pressure", "NoSchedule"),
        toleration("node.kubernetes.io/unschedulable", "NoSchedule"),
    ];
    if spec.get("hostNetwork").and_then(Value::as_bool) == Some(true) {
        std.push(toleration("node.kubernetes.io/network-unavailable", "NoSchedule"));
    }
    for t in std {
        if !tols.iter().any(|x| str_at(x, &["key"]) == str_at(&t, &["key"]) && str_at(x, &["effect"]) == str_at(&t, &["effect"])) {
            tols.push(t);
        }
    }
    tols
}

/// Whether a DaemonSet pod with this template spec belongs on `node`.
pub fn node_eligible(template_spec: &Value, node: &Value) -> bool {
    let mut spec = template_spec.clone();
    spec.set("tolerations", Value::Array(daemon_tolerations(template_spec)));
    let pod = obj(alloc::vec![("spec", spec.clone())]);
    selector_matches(&pod, node) && node_affinity_matches(&spec, node) && !untolerated_taint(&pod, node)
}

fn pod_hash(p: &Value) -> &str {
    str_at(p, &["metadata", "labels", REVISION_LABEL])
}

fn available(p: &Value) -> bool {
    running_ready(p) && !deleting(p)
}

pub async fn reconcile<C: Client>(c: &C, ns: &str, dname: &str) -> Result<Option<u64>> {
    let path = alloc::format!("{}/{dname}", daemonsets(Some(ns)));
    let Some(ds) = get_opt(c, &path).await? else { return Ok(None) };
    if deleting(&ds) {
        return Ok(None);
    }
    let Some((sel_str, sel)) = ds.get("spec").and_then(|s| s.get("selector")).and_then(parse_selector) else { return Ok(None) };
    let template = ds.pointer(&["spec", "template"]).cloned().unwrap_or(Value::Null);
    let tspec = template.get("spec").cloned().unwrap_or(Value::Null);
    let (rev, revs) = ensure_revision(c, &ds, "DaemonSet", &template).await?;
    let generation = int_at(&ds, &["metadata", "generation"], 1).to_string();

    let nodes = items(&c.list(NODES, "").await?);
    let list = c.list(&pods(Some(ns)), &alloc::format!("labelSelector={}", enc(&sel_str))).await?;
    let mut by_node: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let mut to_delete: Vec<String> = Vec::new();
    for p in items(&list).into_iter().filter(|p| sel.matches(p)) {
        let mine = match controller_ref(&p) {
            Some(r) => str_at(r, &["uid"]) == uid(&ds),
            None => false,
        };
        let p = if mine {
            p
        } else if controller_ref(&p).is_none() {
            match adopt(c, &pods(Some(ns)), &ds, "apps/v1", "DaemonSet", &p).await? {
                Some(p) => p,
                None => continue,
            }
        } else {
            continue;
        };
        if pod_terminal(&p) && !deleting(&p) {
            to_delete.push(name(&p).to_string());
            continue;
        }
        by_node.entry(str_at(&p, &["spec", "nodeName"]).to_string()).or_default().push(p);
    }

    let mut desired = 0i64;
    let mut current = 0i64;
    let mut misscheduled = 0i64;
    let mut to_create: Vec<String> = Vec::new();
    let mut unavailable = 0i64;
    let mut old_available: Vec<String> = Vec::new();
    let node_names: Vec<&str> = nodes.iter().map(name).collect();
    for n in &nodes {
        let eligible = node_eligible(&tspec, n);
        let mut here = by_node.remove(name(n)).unwrap_or_default();
        if !eligible {
            misscheduled += here.iter().filter(|p| !deleting(p)).count() as i64;
            to_delete.extend(here.iter().filter(|p| !deleting(p)).map(|p| name(p).to_string()));
            continue;
        }
        desired += 1;
        // Keep the best pod on the node: live before terminating, available first, oldest.
        here.sort_by_key(|p| (deleting(p), !available(p), str_at(p, &["metadata", "creationTimestamp"]).to_string(), name(p).to_string()));
        if here.is_empty() {
            to_create.push(name(n).to_string());
            unavailable += 1;
            continue;
        }
        for extra in here.iter().skip(1).filter(|p| !deleting(p)) {
            to_delete.push(name(extra).to_string());
        }
        let keep = &here[0];
        if deleting(keep) {
            unavailable += 1; // wait for it to go before creating the replacement
            continue;
        }
        current += 1;
        if !available(keep) {
            unavailable += 1;
            if pod_hash(keep) != rev {
                to_delete.push(name(keep).to_string());
            }
        } else if pod_hash(keep) != rev {
            old_available.push(name(keep).to_string());
        }
    }
    // Pods on nodes that no longer exist.
    for (n, ps) in &by_node {
        if !node_names.contains(&n.as_str()) {
            misscheduled += ps.iter().filter(|p| !deleting(p)).count() as i64;
            to_delete.extend(ps.iter().filter(|p| !deleting(p)).map(|p| name(p).to_string()));
        }
    }
    // Rolling update: replace old available pods within the unavailability budget.
    if str_at(&ds, &["spec", "updateStrategy", "type"]) != "OnDelete" {
        let max = crate::deployment::resolve_intstr(ds.pointer(&["spec", "updateStrategy", "rollingUpdate", "maxUnavailable"]), desired, "1", true).max(1);
        old_available.sort();
        for n in old_available {
            if unavailable >= max {
                break;
            }
            to_delete.push(n);
            unavailable += 1;
        }
    }

    for n in &to_create {
        let tols = Value::Array(daemon_tolerations(&tspec));
        let mut pod = pod_from_template(&ds, "apps/v1", "DaemonSet", &template, None, &alloc::format!("{dname}-"), &[(REVISION_LABEL, &rev), (GENERATION_LABEL, &generation)], &[]);
        let spec = pod.entry_object("spec");
        spec.set("tolerations", tols);
        spec.set("nodeName", Value::from(n.as_str()));
        c.create(&pods(Some(ns)), &pod).await?;
    }
    to_delete.sort();
    to_delete.dedup();
    for n in &to_delete {
        delete_ok(c, &alloc::format!("{}/{n}", pods(Some(ns)))).await?;
    }

    // Status from the snapshot.
    let all: Vec<Value> = items(&list).into_iter().filter(|p| controlled_by(p, uid(&ds)) && !deleting(p) && !pod_terminal(p)).collect();
    let on_eligible = |p: &&Value| nodes.iter().any(|n| name(n) == str_at(p, &["spec", "nodeName"]) && node_eligible(&tspec, n));
    let ready = all.iter().filter(on_eligible).filter(|p| running_ready(p)).count() as i64;
    let updated = all.iter().filter(on_eligible).filter(|p| pod_hash(p) == rev).count() as i64;
    put_status(c, &path, |o| {
        obj(alloc::vec![
            ("desiredNumberScheduled", num(desired)),
            ("currentNumberScheduled", num(current)),
            ("numberMisscheduled", num(misscheduled)),
            ("numberReady", num(ready)),
            ("numberAvailable", num(ready)),
            ("numberUnavailable", num((desired - ready).max(0))),
            ("updatedNumberScheduled", num(updated)),
            ("observedGeneration", num(int_at(o, &["metadata", "generation"], 0))),
            ("collisionCount", num(0)),
        ])
    })
    .await?;

    let limit = int_at(&ds, &["spec", "revisionHistoryLimit"], 10).max(0) as usize;
    let mut live: Vec<&str> = alloc::vec![rev.as_str()];
    live.extend(all.iter().map(pod_hash));
    trim_revisions(c, ns, &revs, &live, limit).await?;
    Ok(None)
}
