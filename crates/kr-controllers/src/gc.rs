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

use crate::util::*;
use crate::Config;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_apiserver::client::Client;
use kr_apiserver::resources::{Resource, RESOURCES};
use kr_fmt::json::Value;

/// Kinds whose objects may be garbage collected.
const DEPENDENTS: &[&str] = &["pods", "replicasets", "controllerrevisions", "jobs", "endpointslices"];
/// Owner kinds watched for deletions.
const OWNERS: &[(&str, &str)] = &[("", "services"), ("apps", "deployments"), ("apps", "replicasets"), ("apps", "statefulsets"), ("apps", "daemonsets"), ("batch", "jobs"), ("batch", "cronjobs")];

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
    let mut g = Guard::default();
    for (group, plural) in OWNERS {
        let Some(r) = res(group, plural) else { continue };
        let n = notify.clone();
        g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), list_path(r), String::new(), cfg, move |ev, _| {
            if ev == "DELETED" {
                n.notify();
            }
        })));
    }
    loop {
        sweep(&c).await;
        let _ = kr_rt::exec::timeout(cfg.gc_ms, notify.notified()).await;
    }
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
