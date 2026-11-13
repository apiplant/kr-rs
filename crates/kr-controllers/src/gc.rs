//! The garbage collector: deletes objects whose owners are gone (background propagation).
//!
//! A sweep runs every `Config::gc_ms` and immediately after a watch sees an owner kind lose an
//! object. For each kind (`kinds`: every stored built-in and the custom resources of every
//! established CRD) it lists the objects first, then resolves every `ownerReferences` entry to
//! one of those kinds (by API group and `kind`) and lists that resource
//! once per sweep to learn which uids exist. A dependent is deleted when it has at least one
//! owner reference and *every* owner whose kind is known is absent; references to kinds that
//! are not served are treated as alive. Listing dependents before owners means an owner
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

/// Built-in resources never collected: views and reviews that are not stored, and events
/// (nothing owns them; they expire by TTL).
const SKIP: &[&str] = &["metrics.k8s.io", "authentication.k8s.io", "authorization.k8s.io"];
/// Owner kinds watched for deletions (others are seen by the periodic sweep).
const OWNERS: &[(&str, &str)] = &[("", "services"), ("", "replicationcontrollers"), ("apps", "deployments"), ("apps", "replicasets"), ("apps", "statefulsets"), ("apps", "daemonsets"), ("batch", "jobs"), ("batch", "cronjobs")];
const CRDS: &str = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions";

/// A collectable resource: a built-in or a custom resource (served storage version of a CRD).
#[derive(Clone, Debug, PartialEq)]
pub struct Kind {
    pub group: String,
    pub version: String,
    pub kind: String,
    pub plural: String,
    pub namespaced: bool,
}

impl Kind {
    fn of(r: &Resource) -> Kind {
        Kind { group: r.group.into(), version: r.version.into(), kind: r.kind.into(), plural: r.plural.into(), namespaced: r.namespaced }
    }
    fn list_path(&self) -> String {
        api_path(&self.group, &self.version, None, &self.plural)
    }
    fn object_path(&self, o: &Value) -> String {
        alloc::format!("{}/{}", api_path(&self.group, &self.version, if self.namespaced { Some(namespace(o)) } else { None }, &self.plural), name(o))
    }
    fn owns(&self) -> bool {
        OWNERS.iter().any(|(g, p)| *g == self.group && *p == self.plural)
    }
}

/// Every kind the collector handles, as dependents and as owners: the stored built-ins and
/// the custom resources of established CRDs. Upstream builds the same set from discovery.
pub async fn kinds<C: Client>(c: &C) -> Vec<Kind> {
    let mut out: Vec<Kind> = Vec::new();
    for r in RESOURCES {
        if SKIP.contains(&r.group) || r.plural == "events" || out.iter().any(|k| k.group == r.group && k.plural == r.plural) {
            continue;
        }
        out.push(Kind::of(r));
    }
    if let Ok(l) = c.list(CRDS, "").await {
        for crd in items(&l) {
            let established = crd.pointer(&["status", "conditions"]).and_then(Value::as_array).is_none_or(|a| a.iter().any(|x| str_at(x, &["type"]) == "Established" && str_at(x, &["status"]) == "True"));
            if !established || deleting(&crd) {
                continue;
            }
            let Some(ver) = crd.pointer(&["spec", "versions"]).and_then(Value::as_array).and_then(|vs| {
                vs.iter().find(|v| v.pointer(&["storage"]).and_then(Value::as_bool) == Some(true) && v.pointer(&["served"]).and_then(Value::as_bool) != Some(false)).or_else(|| vs.iter().find(|v| v.pointer(&["served"]).and_then(Value::as_bool) != Some(false)))
            }) else {
                continue;
            };
            out.push(Kind {
                group: str_at(&crd, &["spec", "group"]).to_string(),
                version: str_at(ver, &["name"]).to_string(),
                kind: str_at(&crd, &["spec", "names", "kind"]).to_string(),
                plural: str_at(&crd, &["spec", "names", "plural"]).to_string(),
                namespaced: str_at(&crd, &["spec", "scope"]) != "Cluster",
            });
        }
    }
    out
}

fn res(group: &str, plural: &str) -> Option<&'static Resource> {
    RESOURCES.iter().find(|r| r.group == group && r.plural == plural)
}

fn list_path(r: &Resource) -> String {
    api_path(r.group, r.version, None, r.plural)
}

/// The kind an owner reference names. The version is ignored: every served version of a
/// resource lists the same objects (and uids).
fn owner_kind<'a>(kinds: &'a [Kind], api_version: &str, kind: &str) -> Option<&'a Kind> {
    let g = api_version.split_once('/').map_or("", |(g, _)| g);
    kinds.iter().find(|k| k.group == g && k.kind == kind)
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
        let kinds = kinds(&c).await;
        waiting.set(propagate_in(&c, &kinds).await);
        sweep_in(&c, &kinds).await;
        expire_tokens(&c, (cfg.now)()).await;
        let _ = kr_rt::exec::timeout(cfg.gc_ms, notify.notified()).await;
    }
}

/// Deletes bootstrap-token Secrets (`kube-system`, type `bootstrap.kubernetes.io/token`) whose
/// `data.expiration` has passed; returns how many were deleted. Expired tokens already fail
/// authentication, this only stops them accumulating.
pub async fn expire_tokens<C: Client>(c: &C, now: i64) -> usize {
    let base = api_path("", "v1", Some("kube-system"), "secrets");
    let Ok(l) = c.list(&base, "").await else { return 0 };
    let mut n = 0;
    for s in items(&l) {
        if str_at(&s, &["type"]) != "bootstrap.kubernetes.io/token" || deleting(&s) {
            continue;
        }
        let exp = s.pointer(&["data", "expiration"]).and_then(Value::as_str).and_then(|v| kr_fmt::base64::decode(v).ok()).and_then(|b| String::from_utf8(b).ok()).and_then(|e| parse_time(&e));
        if exp.is_some_and(|e| now > e) && c.delete(&alloc::format!("{base}/{}", name(&s))).await.is_ok() {
            n += 1;
        }
    }
    n
}

const ORPHAN: &str = "orphan";
const FOREGROUND: &str = "foregroundDeletion";

fn has_propagation_finalizer(o: &Value) -> bool {
    deleting(o) && o.pointer(&["metadata", "finalizers"]).and_then(Value::as_array).is_some_and(|f| f.iter().any(|x| matches!(x.as_str(), Some(ORPHAN | FOREGROUND))))
}

/// The object's references without the ones to `owner_uid`.
fn refs_without(o: &Value, owner_uid: &str) -> Vec<Value> {
    o.pointer(&["metadata", "ownerReferences"]).and_then(Value::as_array).map(|a| a.iter().filter(|r| str_at(r, &["uid"]) != owner_uid).cloned().collect()).unwrap_or_default()
}

/// Finishes Orphan and Foreground deletions; true while some foreground owner still waits for
/// dependents to go away.
pub async fn propagate<C: Client>(c: &C) -> bool {
    let kinds = kinds(c).await;
    propagate_in(c, &kinds).await
}

async fn propagate_in<C: Client>(c: &C, kinds: &[Kind]) -> bool {
    let mut listed: Vec<(&Kind, Vec<Value>)> = Vec::new();
    for k in kinds {
        if let Ok(l) = c.list(&k.list_path(), "").await {
            listed.push((k, items(&l)));
        }
    }
    let owners: Vec<(&Kind, &Value)> = listed.iter().flat_map(|(k, os)| os.iter().filter(|o| has_propagation_finalizer(o)).map(move |o| (*k, o))).collect();
    if owners.is_empty() {
        return false;
    }
    let mut waiting = false;
    for (ok, owner) in &owners {
        let owner_uid = uid(owner);
        let fins: Vec<&str> = owner.pointer(&["metadata", "finalizers"]).and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        let orphan = fins.contains(&ORPHAN);
        let mine = listed.iter().flat_map(|(k, os)| os.iter().map(move |o| (*k, o))).filter(|(_, d)| d.pointer(&["metadata", "ownerReferences"]).and_then(Value::as_array).is_some_and(|a| a.iter().any(|r| str_at(r, &["uid"]) == owner_uid)));
        let mut remaining = 0;
        for (k, d) in mine {
            let sole = refs_without(d, owner_uid).is_empty();
            if orphan || !sole {
                // A merge patch with null drops the field once no reference is left.
                let left = refs_without(d, owner_uid);
                let refs = if left.is_empty() { Value::Null } else { Value::Array(left) };
                let patch = obj(alloc::vec![("metadata", obj(alloc::vec![("ownerReferences", refs)]))]);
                if c.patch(&k.object_path(d), MERGE, &patch).await.is_err_and(|e| e.code != 404) {
                    remaining += 1;
                }
            } else {
                // Foreground: the owner waits for this one, whether it is deleted now or already going.
                remaining += 1;
                if !deleting(d) {
                    // Dependents that own things themselves (ReplicaSet -> pods) go foreground too,
                    // so the whole tree is gone before the root is.
                    let p = k.object_path(d);
                    let _ = c.delete(&if k.owns() { alloc::format!("{p}?propagationPolicy=Foreground") } else { p }).await;
                }
            }
        }
        if remaining > 0 {
            waiting |= !orphan;
            continue;
        }
        let keep: Vec<Value> = fins.iter().filter(|f| !matches!(**f, ORPHAN | FOREGROUND)).map(|f| Value::from(*f)).collect();
        let patch = obj(alloc::vec![("metadata", obj(alloc::vec![("finalizers", Value::Array(keep))]))]);
        let _ = c.patch(&ok.object_path(owner), MERGE, &patch).await;
    }
    waiting
}

/// One pass; returns the number of objects deleted.
pub async fn sweep<C: Client>(c: &C) -> usize {
    let kinds = kinds(c).await;
    sweep_in(c, &kinds).await
}

async fn sweep_in<C: Client>(c: &C, kinds: &[Kind]) -> usize {
    let mut deleted = 0;
    let mut dependents: Vec<(&Kind, Vec<Value>)> = Vec::new();
    for k in kinds {
        if let Ok(l) = c.list(&k.list_path(), "").await {
            dependents.push((k, items(&l)));
        }
    }
    // uids per owner kind (group/plural), listed lazily after the dependents.
    let mut alive: BTreeMap<(String, String), Option<BTreeSet<String>>> = BTreeMap::new();
    for (k, objs) in &dependents {
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
                let Some(ok) = owner_kind(kinds, str_at(oref, &["apiVersion"]), str_at(oref, &["kind"])) else {
                    orphaned = false; // a kind not served (yet): treated as alive
                    continue;
                };
                let key = (ok.group.clone(), ok.plural.clone());
                if !alive.contains_key(&key) {
                    let set = c.list(&ok.list_path(), "").await.ok().map(|l| items(&l).iter().map(|x| uid(x).to_string()).collect());
                    alive.insert(key.clone(), set);
                }
                match &alive[&key] {
                    Some(set) if !set.contains(str_at(oref, &["uid"])) => {}
                    _ => orphaned = false, // alive, or unknown (list failed)
                }
            }
            if orphaned && c.delete(&k.object_path(o)).await.is_ok() {
                deleted += 1;
            }
        }
    }
    deleted
}
