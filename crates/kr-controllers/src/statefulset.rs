//! The StatefulSet controller: ordered, identity-stable pods `<sts>-<ordinal>`.
//!
//! Per reconcile (from fresh reads):
//!
//! 1. **Revisions.** The pod template hashes to a ControllerRevision `<sts>-<hash>` (see
//!    [`ensure_revision`]); that is the *update revision*. The *current revision* is
//!    `status.currentRevision` (the update revision on first sight). Pods carry their revision in
//!    `controller-revision-hash`. Revisions nobody references beyond `revisionHistoryLimit`
//!    (default 10) are deleted.
//! 2. **Pods.** Pods controlled by the set (matching orphans named `<sts>-<n>` are adopted) are
//!    indexed by ordinal. Ordinals `0..replicas` are processed in order:
//!    a missing pod is created (ordinals below `rollingUpdate.partition` from the current
//!    revision, the rest from the update revision), a Failed/Succeeded one is deleted so it is
//!    recreated, and PVCs from `volumeClaimTemplates` (`<template>-<sts>-<ordinal>`, created once,
//!    never deleted, no provisioning) are ensured first. With `OrderedReady` (default) the pass
//!    stops after creating a pod, and at the first pod that is terminating or not Running and
//!    Ready; `Parallel` never waits.
//! 3. **Scale down.** Pods with ordinal `>= replicas` ("condemned") are deleted from the highest
//!    ordinal, one at a time under `OrderedReady`, only once every lower pod is healthy.
//! 4. **Update.** `RollingUpdate` walks ordinals from `replicas-1` down to `partition`; the
//!    first pod with a different revision is deleted (it comes back from the update revision) and
//!    the pass ends; a pod that is not healthy stops the walk. `OnDelete` never deletes.
//! 5. **Status**: `replicas`, `readyReplicas`, `availableReplicas` (= ready, `minReadySeconds`
//!    is not modelled), `currentReplicas`, `updatedReplicas`, `currentRevision`, `updateRevision`,
//!    `observedGeneration`, `collisionCount`. Counts come from the pods read at the start of the
//!    pass; the writes of the pass wake the controller again. Once a RollingUpdate has every
//!    replica updated and ready, `currentRevision` becomes the update revision.
//!
//! Not modelled: `persistentVolumeClaimRetentionPolicy` (PVCs are always retained),
//! `minReadySeconds`, `ordinals.start`, pod identity repair beyond creation.

use crate::util::*;
use crate::Config;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_apiserver::client::{Client, Result};
use kr_fmt::json::Value;

pub const POD_NAME_LABEL: &str = "statefulset.kubernetes.io/pod-name";
pub const REVISION_LABEL: &str = "controller-revision-hash";
pub const POD_INDEX_LABEL: &str = "apps.kubernetes.io/pod-index";

pub async fn run<C: Client + Clone + 'static>(c: C, cfg: Config) {
    let q = Queue::new();
    let mut g = Guard::default();
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), statefulsets(None), String::new(), cfg, move |_, o| q2.add(&key_of(o)))));
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), pods(None), String::new(), cfg, move |_, p| match controller_ref(p) {
        Some(r) if str_at(r, &["kind"]) == "StatefulSet" => q2.add(&alloc::format!("{}/{}", namespace(p), str_at(r, &["name"]))),
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
                    for s in items(&c.list(&statefulsets(Some(ns)), "").await?) {
                        q.add(&key_of(&s));
                    }
                    return Ok(None);
                }
                reconcile(&c, ns, n).await
            }
        },
        move || {
            let (c, q) = (c3.clone(), q3.clone());
            async move {
                if let Ok(l) = c.list(&statefulsets(None), "").await {
                    for s in items(&l) {
                        q.add(&key_of(&s));
                    }
                }
            }
        },
    )
    .await
}

/// `<sts>-<ordinal>` -> ordinal.
fn ordinal(sts: &str, pod: &str) -> Option<usize> {
    let rest = pod.strip_prefix(sts)?.strip_prefix('-')?;
    if rest.is_empty() || (rest.len() > 1 && rest.starts_with('0')) {
        return None;
    }
    rest.parse().ok()
}

fn healthy(p: &Value) -> bool {
    running_ready(p) && !deleting(p)
}

fn pod_revision(p: &Value) -> &str {
    str_at(p, &["metadata", "labels", REVISION_LABEL])
}

fn claim_name(tpl: &Value, sts: &str, ord: usize) -> String {
    alloc::format!("{}-{sts}-{ord}", str_at(tpl, &["metadata", "name"]))
}

fn build_pod(sts: &Value, template: &Value, rev: &str, ord: usize) -> Value {
    let n = alloc::format!("{}-{ord}", name(sts));
    let idx = ord.to_string();
    let mut pod = pod_from_template(sts, "apps/v1", "StatefulSet", template, Some(&n), "", &[(POD_NAME_LABEL, &n), (REVISION_LABEL, rev), (POD_INDEX_LABEL, &idx)], &[]);
    let spec = pod.entry_object("spec");
    spec.set("hostname", Value::from(n.as_str()));
    let svc = str_at(sts, &["spec", "serviceName"]);
    if !svc.is_empty() {
        spec.set("subdomain", Value::from(svc));
    }
    let vcts = sts.pointer(&["spec", "volumeClaimTemplates"]).and_then(Value::as_array).unwrap_or(&[]);
    if !vcts.is_empty() {
        let mut vols: Vec<Value> = spec.get("volumes").and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
        for t in vcts {
            let vname = str_at(t, &["metadata", "name"]);
            vols.retain(|v| str_at(v, &["name"]) != vname);
            vols.push(obj(alloc::vec![("name", Value::from(vname)), ("persistentVolumeClaim", obj(alloc::vec![("claimName", Value::String(claim_name(t, name(sts), ord)))]))]));
        }
        spec.set("volumes", Value::Array(vols));
    }
    pod
}

async fn ensure_claims<C: Client>(c: &C, sts: &Value, ord: usize) -> Result<()> {
    let ns = namespace(sts);
    for t in sts.pointer(&["spec", "volumeClaimTemplates"]).and_then(Value::as_array).unwrap_or(&[]) {
        let cname = claim_name(t, name(sts), ord);
        let mut labels = sts.pointer(&["spec", "selector", "matchLabels"]).cloned().unwrap_or(Value::Object(Vec::new()));
        for (k, v) in t.pointer(&["metadata", "labels"]).and_then(Value::as_object).unwrap_or(&[]) {
            labels.set(k, v.clone());
        }
        let pvc = obj(alloc::vec![
            ("apiVersion", Value::from("v1")),
            ("kind", Value::from("PersistentVolumeClaim")),
            ("metadata", obj(alloc::vec![("name", Value::String(cname)), ("namespace", Value::from(ns)), ("labels", labels)])),
            ("spec", t.get("spec").cloned().unwrap_or(Value::Object(Vec::new()))),
        ]);
        match c.create(&pvcs(Some(ns)), &pvc).await {
            Ok(_) => {}
            Err(e) if e.code == 409 => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

pub async fn reconcile<C: Client>(c: &C, ns: &str, sname: &str) -> Result<Option<u64>> {
    let path = alloc::format!("{}/{sname}", statefulsets(Some(ns)));
    let Some(sts) = get_opt(c, &path).await? else { return Ok(None) };
    if deleting(&sts) {
        return Ok(None);
    }
    let replicas = int_at(&sts, &["spec", "replicas"], 1).max(0) as usize;
    let Some((sel_str, sel)) = sts.get("spec").and_then(|s| s.get("selector")).and_then(parse_selector) else { return Ok(None) };
    let template = sts.pointer(&["spec", "template"]).cloned().unwrap_or(Value::Null);
    let parallel = str_at(&sts, &["spec", "podManagementPolicy"]) == "Parallel";
    let on_delete = str_at(&sts, &["spec", "updateStrategy", "type"]) == "OnDelete";
    let partition = if on_delete { 0 } else { int_at(&sts, &["spec", "updateStrategy", "rollingUpdate", "partition"], 0).max(0) as usize };

    // Revisions.
    let (update_rev, revs) = ensure_revision(c, &sts, "StatefulSet", &template).await?;
    let mut current_rev = str_at(&sts, &["status", "currentRevision"]).to_string();
    if current_rev.is_empty() || !revs.iter().any(|r| name(r) == current_rev) {
        current_rev = update_rev.clone();
    }

    // Pods by ordinal.
    let list = c.list(&pods(Some(ns)), &alloc::format!("labelSelector={}", enc(&sel_str))).await?;
    let mut by_ord: BTreeMap<usize, Value> = BTreeMap::new();
    for p in items(&list).into_iter().filter(|p| sel.matches(p)) {
        let Some(ord) = ordinal(sname, name(&p)) else { continue };
        match controller_ref(&p) {
            Some(r) if str_at(r, &["uid"]) == uid(&sts) => {
                by_ord.insert(ord, p);
            }
            Some(_) => {}
            None => {
                if let Some(p) = adopt(c, &pods(Some(ns)), &sts, "apps/v1", "StatefulSet", &p).await? {
                    by_ord.insert(ord, p);
                }
            }
        }
    }

    let wait = step(c, &sts, &by_ord, replicas, partition, parallel, on_delete, &update_rev, &current_rev, &revs).await?;

    // Status from the snapshot.
    let in_range = || by_ord.iter().filter(|(o, _)| **o < replicas).map(|(_, p)| p);
    let count = |f: &dyn Fn(&Value) -> bool| in_range().filter(|p| f(p)).count() as i64;
    let total = in_range().count() as i64;
    let ready = count(&|p| running_ready(p));
    let current = count(&|p| pod_revision(p) == current_rev);
    let updated = count(&|p| pod_revision(p) == update_rev);
    let done = !on_delete && updated == replicas as i64 && ready == replicas as i64;
    let (status_current, status_current_n) = if done { (update_rev.clone(), updated) } else { (current_rev.clone(), current) };
    put_status(c, &path, |o| {
        obj(alloc::vec![
            ("replicas", num(total)),
            ("readyReplicas", num(ready)),
            ("availableReplicas", num(ready)),
            ("currentReplicas", num(status_current_n)),
            ("updatedReplicas", num(updated)),
            ("currentRevision", Value::from(status_current.as_str())),
            ("updateRevision", Value::from(update_rev.as_str())),
            ("observedGeneration", num(int_at(o, &["metadata", "generation"], 0))),
            ("collisionCount", num(0)),
        ])
    })
    .await?;

    // History: keep the revisions in use.
    let limit = int_at(&sts, &["spec", "revisionHistoryLimit"], 10).max(0) as usize;
    let mut live: Vec<&str> = alloc::vec![update_rev.as_str(), status_current.as_str()];
    live.extend(by_ord.values().map(pod_revision));
    trim_revisions(c, ns, &revs, &live, limit).await?;
    Ok(wait)
}

fn revision_template(revs: &[Value], rev: &str, fallback: &Value) -> Value {
    revs.iter().find(|r| name(r) == rev).and_then(|r| r.pointer(&["data", "spec", "template"])).cloned().unwrap_or_else(|| fallback.clone())
}

/// One pass of creations, deletions and updates. `Some(ms)` asks to be run again.
#[allow(clippy::too_many_arguments)]
async fn step<C: Client>(c: &C, sts: &Value, by_ord: &BTreeMap<usize, Value>, replicas: usize, partition: usize, parallel: bool, on_delete: bool, update_rev: &str, current_rev: &str, revs: &[Value]) -> Result<Option<u64>> {
    let ns = namespace(sts);
    let template = sts.pointer(&["spec", "template"]).cloned().unwrap_or(Value::Null);
    let pod_path = |n: &str| alloc::format!("{}/{n}", pods(Some(ns)));

    for ord in 0..replicas {
        match by_ord.get(&ord) {
            None => {
                ensure_claims(c, sts, ord).await?;
                let (rev, tpl) = if !on_delete && ord < partition { (current_rev, revision_template(revs, current_rev, &template)) } else { (update_rev, template.clone()) };
                match c.create(&pods(Some(ns)), &build_pod(sts, &tpl, rev, ord)).await {
                    Ok(_) => {}
                    Err(e) if e.code == 409 => return Ok(Some(0)), // stale list
                    Err(e) => return Err(e),
                }
                if !parallel {
                    return Ok(None);
                }
            }
            Some(p) => {
                if deleting(p) {
                    if parallel {
                        continue;
                    }
                    return Ok(None);
                }
                if pod_terminal(p) {
                    delete_ok(c, &pod_path(name(p))).await?;
                    if !parallel {
                        return Ok(None);
                    }
                    continue;
                }
                ensure_claims(c, sts, ord).await?;
                if !parallel && !healthy(p) {
                    return Ok(None);
                }
            }
        }
    }

    // Scale down: condemned pods, highest ordinal first.
    let condemned: Vec<&Value> = by_ord.range(replicas..).rev().map(|(_, p)| p).collect();
    if !condemned.is_empty() {
        for p in condemned {
            if deleting(p) {
                if parallel {
                    continue;
                }
                return Ok(None);
            }
            delete_ok(c, &pod_path(name(p))).await?;
            if !parallel {
                return Ok(None);
            }
        }
        return Ok(None);
    }

    // Rolling update, highest ordinal first.
    if !on_delete {
        for ord in (partition..replicas).rev() {
            let Some(p) = by_ord.get(&ord) else { return Ok(None) };
            if pod_revision(p) != update_rev && !deleting(p) {
                delete_ok(c, &pod_path(name(p))).await?;
                return Ok(None);
            }
            if !healthy(p) {
                return Ok(None);
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn ordinals() {
        assert_eq!(ordinal("web", "web-0"), Some(0));
        assert_eq!(ordinal("web", "web-12"), Some(12));
        assert_eq!(ordinal("web", "web-01"), None);
        assert_eq!(ordinal("web", "web-x"), None);
        assert_eq!(ordinal("web", "webx-1"), None);
        assert_eq!(ordinal("web", "web-"), None);
    }
}
