//! The garbage collector: deletes objects whose owners are gone (background propagation).
//!
//! A sweep runs every `Config::gc_ms` and immediately after a watch sees an owner kind lose an
//! object. For each dependent kind (pods, ReplicaSets, ControllerRevisions, Jobs, EndpointSlices) it lists the
//! objects first, then resolves every `ownerReferences` entry to a resource through
//! `kr_apiserver::resources::RESOURCES` (by `apiVersion` and `kind`) and lists that resource
//! once per sweep to learn which uids exist. A dependent is deleted when it has at least one
//! owner reference and *every* owner whose kind is known is absent; references to kinds that
//! are not in the table are treated as alive. Listing dependents before owners means an owner
//! created in between is seen, so a freshly created pair is never collected by mistake.
//!
//! Deleting a Deployment therefore removes its ReplicaSets in one sweep and their pods in the
//! next (the ReplicaSet deletions are DELETED events that trigger it).
//!
//! Owners deleted with `propagationPolicy` Orphan or Foreground (the API server keeps them with
//! the `orphan` / `foregroundDeletion` finalizer) are handled in the same sweep. Orphan removes
//! the owner's reference from every dependent, then the finalizer. Foreground deletes the
//! dependents that have no other owner (the others just lose the reference) and removes the
//! finalizer once none are left; the owner is waiting for them until then.

use crate::util::*;
use crate::Config;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::Cell;
use kr_apiserver::client::Client;
use kr_apiserver::resources::{Resource, RESOURCES};
use kr_fmt::json::Value;

/// Kinds whose objects may be garbage collected.
const DEPENDENTS: &[&str] = &["pods", "replicasets", "controllerrevisions", "jobs", "endpointslices"];
/// Owner kinds watched for deletions.
const OWNERS: &[(&str, &str)] = &[("", "services"), ("", "replicationcontrollers"), ("apps", "deployments"), ("apps", "replicasets"), ("apps", "statefulsets"), ("apps", "daemonsets"), ("batch", "jobs"), ("batch", "cronjobs")];

fn res(group: &str, plural: &str) -> Option<&'static Resource> {
    RESOURCES.iter().find(|r| r.group == group && r.plural == plural)
}

fn list_path(r: &Resource) -> String {
    api_path(r.group, r.version, None, r.plural)
}

fn owner_resource(api_version: &str, kind: &str) -> Option<&'static Resource> {
    let (g, v) = api_version.split_once('/').unwrap_or(("", api_version));
    RESOURCES.iter().find(|r| r.group == g && r.version == v && r.kind == kind)
}

pub async fn run<C: Client + Clone + 'static>(c: C, cfg: Config) {
    let notify = Notify::default();
    // Set while a foreground deletion waits for its dependents: their deletions wake the sweep.
    let waiting = Rc::new(Cell::new(false));
    let mut g = Guard::default();
    for (group, plural) in OWNERS {
        let Some(r) = res(group, plural) else { continue };
        let n = notify.clone();
        g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), list_path(r), String::new(), cfg, move |ev, o| {
            if ev == "DELETED" || has_propagation_finalizer(o) {
                n.notify();
            }
        })));
    }
    if let Some(r) = res("", "pods") {
        let (n, w) = (notify.clone(), waiting.clone());
        g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), list_path(r), String::new(), cfg, move |ev, _| {
            if ev == "DELETED" && w.get() {
                n.notify();
            }
        })));
    }
    loop {
        waiting.set(propagate(&c).await);
        sweep(&c).await;
        let _ = kr_rt::exec::timeout(cfg.gc_ms, notify.notified()).await;
    }
}

const ORPHAN: &str = "orphan";
const FOREGROUND: &str = "foregroundDeletion";

fn has_propagation_finalizer(o: &Value) -> bool {
    deleting(o) && o.pointer(&["metadata", "finalizers"]).and_then(Value::as_array).is_some_and(|f| f.iter().any(|x| matches!(x.as_str(), Some(ORPHAN | FOREGROUND))))
}

fn object_path(r: &Resource, o: &Value) -> String {
    alloc::format!("{}/{}", api_path(r.group, r.version, if r.namespaced { Some(namespace(o)) } else { None }, r.plural), name(o))
}

/// The object's references without the ones to `owner_uid`.
fn refs_without(o: &Value, owner_uid: &str) -> Vec<Value> {
    o.pointer(&["metadata", "ownerReferences"]).and_then(Value::as_array).map(|a| a.iter().filter(|r| str_at(r, &["uid"]) != owner_uid).cloned().collect()).unwrap_or_default()
}

/// Finishes Orphan and Foreground deletions; true while some foreground owner still waits for
/// dependents to go away.
pub async fn propagate<C: Client>(c: &C) -> bool {
    let mut owners: Vec<(&'static Resource, Value)> = Vec::new();
    for (group, plural) in OWNERS {
        let Some(r) = res(group, plural) else { continue };
        if let Ok(l) = c.list(&list_path(r), "").await {
            owners.extend(items(&l).into_iter().filter(has_propagation_finalizer).map(|o| (r, o)));
        }
    }
    if owners.is_empty() {
        return false;
    }
    let mut dependents: Vec<(&'static Resource, Value)> = Vec::new();
    for plural in DEPENDENTS {
        if let Some(r) = RESOURCES.iter().find(|r| r.plural == *plural) {
            if let Ok(l) = c.list(&list_path(r), "").await {
                dependents.extend(items(&l).into_iter().map(|o| (r, o)));
            }
        }
    }
    let mut waiting = false;
    for (or, owner) in &owners {
        let owner_uid = uid(owner);
        let fins: Vec<&str> = owner.pointer(&["metadata", "finalizers"]).and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        let orphan = fins.contains(&ORPHAN);
        let mine: Vec<&(&'static Resource, Value)> = dependents.iter().filter(|(_, d)| d.pointer(&["metadata", "ownerReferences"]).and_then(Value::as_array).is_some_and(|a| a.iter().any(|r| str_at(r, &["uid"]) == owner_uid))).collect();
        let mut remaining = 0;
        for (r, d) in mine {
            let sole = refs_without(d, owner_uid).is_empty();
            if orphan || !sole {
                // A merge patch with null drops the field once no reference is left.
                let left = refs_without(d, owner_uid);
                let refs = if left.is_empty() { Value::Null } else { Value::Array(left) };
                let patch = obj(alloc::vec![("metadata", obj(alloc::vec![("ownerReferences", refs)]))]);
                if c.patch(&object_path(r, d), MERGE, &patch).await.is_err_and(|e| e.code != 404) {
                    remaining += 1;
                }
            } else {
                // Foreground: the owner waits for this one, whether it is deleted now or already going.
                remaining += 1;
                if !deleting(d) {
                    let _ = c.delete(&object_path(r, d)).await;
                }
            }
        }
        if remaining > 0 {
            waiting |= !orphan;
            continue;
        }
        let keep: Vec<Value> = fins.iter().filter(|f| !matches!(**f, ORPHAN | FOREGROUND)).map(|f| Value::from(*f)).collect();
        let patch = obj(alloc::vec![("metadata", obj(alloc::vec![("finalizers", Value::Array(keep))]))]);
        let _ = c.patch(&object_path(or, owner), MERGE, &patch).await;
    }
    waiting
}

/// One pass; returns the number of objects deleted.
pub async fn sweep<C: Client>(c: &C) -> usize {
    let mut deleted = 0;
    let mut dependents: Vec<(&'static Resource, Vec<Value>)> = Vec::new();
    for plural in DEPENDENTS {
        if let Some(r) = RESOURCES.iter().find(|r| r.plural == *plural) {
            if let Ok(l) = c.list(&list_path(r), "").await {
                dependents.push((r, items(&l)));
            }
        }
    }
    // uids per owner resource (group/plural), listed lazily after the dependents.
    let mut alive: BTreeMap<(&str, &str), Option<BTreeSet<String>>> = BTreeMap::new();
    for (r, objs) in &dependents {
        for o in objs {
            if deleting(o) {
                continue; // already on its way out (graceful pod deletion)
            }
            let Some(refs) = o.pointer(&["metadata", "ownerReferences"]).and_then(Value::as_array) else { continue };
            if refs.is_empty() {
                continue;
            }
            let mut orphaned = true;
            for oref in refs {
                let Some(or) = owner_resource(str_at(oref, &["apiVersion"]), str_at(oref, &["kind"])) else {
                    orphaned = false;
                    continue;
                };
                if !alive.contains_key(&(or.group, or.plural)) {
                    let set = c.list(&list_path(or), "").await.ok().map(|l| items(&l).iter().map(|x| uid(x).to_string()).collect());
                    alive.insert((or.group, or.plural), set);
                }
                match &alive[&(or.group, or.plural)] {
                    Some(set) if !set.contains(str_at(oref, &["uid"])) => {}
                    _ => orphaned = false, // alive, or unknown (list failed)
                }
            }
            if !orphaned {
                continue;
            }
            let ns = if r.namespaced { Some(namespace(o)) } else { None };
            if c.delete(&alloc::format!("{}/{}", api_path(r.group, r.version, ns, r.plural), name(o))).await.is_ok() {
                deleted += 1;
            }
        }
    }
    deleted
}
