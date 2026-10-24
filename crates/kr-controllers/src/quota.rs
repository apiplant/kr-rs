//! The ResourceQuota controller: recomputes `status.used` for every quota in a namespace and
//! keeps `status.hard` in step with `spec.hard`, like upstream's quota controller.
//!
//! Admission (`kr-apiserver::api`) refuses creations that would exceed a quota, but usage also
//! drifts the other way: objects are deleted, pods terminate (a terminal pod counts nothing),
//! a Service changes type, a quota's `spec.hard` grows or shrinks. The controller therefore
//! recomputes usage from the namespace's objects: for every quota it charges only the names
//! `spec.hard` tracks, only for objects the quota's scopes select ([`kr_apiserver::quota`]
//! holds the accounting), and writes `status` when it differs.
//!
//! Level-triggered like the rest: any event on any namespaced object marks its namespace key
//! `<ns>/*` (45-ish watch loops, one per namespaced resource — cheap in-process); the periodic
//! resync marks every namespace that still has quotas.

use crate::util::*;
use crate::Config;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use kr_apiserver::client::{Client, Result};
use kr_apiserver::quota as q;
use kr_apiserver::resources::{Resource, RESOURCES};
use kr_fmt::json::Value;
use kr_fmt::quantity::Quantity;

pub async fn run<C: Client + Clone + 'static>(c: C, cfg: Config) {
    let queue = Queue::new();
    let mut g = Guard::default();
    for r in RESOURCES.iter().filter(|r| r.namespaced) {
        let (c2, q2) = (c.clone(), queue.clone());
        g.0.push(kr_rt::exec::spawn(watch_loop(c2, api_path(r.group, r.version, None, r.plural), String::new(), cfg, move |_, o| q2.add(&alloc::format!("{}/*", namespace(o))))));
    }
    let (c2, q2) = (c.clone(), queue.clone());
    let (c3, q3) = (c.clone(), queue.clone());
    drive(
        &cfg,
        &queue,
        move |key| {
            let (c, _) = (c2.clone(), q2.clone());
            async move {
                let (ns, who) = split_key(&key);
                if ns.is_empty() || who != "*" {
                    return Ok(None);
                }
                reconcile(&c, ns).await?;
                Ok(None)
            }
        },
        move || {
            let (c, q) = (c3.clone(), q3.clone());
            async move {
                // Resync: every namespace that still has a quota is re-evaluated.
                if let Ok(l) = c.list("/api/v1/resourcequotas", "").await {
                    for quota in items(&l) {
                        q.add(&alloc::format!("{}/*", namespace(&quota)));
                    }
                }
            }
        },
    )
    .await
}

/// Usage accumulated per quota: names from `spec.hard` (zeros included), quantities exact.
type Used = Vec<BTreeMap<String, Quantity>>;

async fn reconcile<C: Client>(c: &C, ns: &str) -> Result<()> {
    let path = api_path("", "v1", Some(ns), "resourcequotas");
    let quotas = items(&c.list(&path, "").await?);
    if quotas.is_empty() {
        return Ok(());
    }
    // The union of everything the quotas track decides which resources must be listed.
    let mut names: Vec<String> = Vec::new();
    for quota in &quotas {
        for (name, _) in q::hard(quota) {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    names.sort();
    let mut sources: Vec<&'static Resource> = Vec::new();
    for n in &names {
        if let Some(r) = q::source_of(n) {
            if !sources.iter().any(|s| s.plural == r.plural && s.group == r.group) {
                sources.push(r);
            }
        }
    }
    let mut used: Used = quotas.iter().map(|quota| q::hard(quota).into_iter().map(|(name, _)| (name, q::zero())).collect()).collect();
    for src in sources {
        let objs = items(&c.list(&api_path(src.group, src.version, Some(ns), src.plural), "").await?);
        for o in &objs {
            let u = q::usage(src.plural, src.group, o);
            for (i, quota) in quotas.iter().enumerate() {
                if !q::matches_scopes(quota, src.plural, o) {
                    continue;
                }
                for (k, v) in &u {
                    if !q::tracked(quota, k) {
                        continue;
                    }
                    let e = used[i].entry(k.clone()).or_insert_with(q::zero);
                    *e = q::add(e, v);
                }
            }
        }
    }
    for (i, quota) in quotas.iter().enumerate() {
        if deleting(quota) {
            continue;
        }
        let quota_path = alloc::format!("{path}/{}", name(quota));
        let st = want_status(quota, &used[i]);
        put_status(c, &quota_path, |_| st.clone()).await?;
    }
    Ok(())
}

/// The `status` the quota should carry: `hard` as a sorted copy of `spec.hard` (values kept as
/// stored) and `used` as sorted canonical quantity strings.
fn want_status(quota: &Value, used: &BTreeMap<String, Quantity>) -> Value {
    let mut hard: Vec<(String, Value)> = quota
        .pointer(&["spec", "hard"])
        .and_then(Value::as_object)
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();
    hard.sort_by(|a, b| a.0.cmp(&b.0));
    obj(alloc::vec![
        ("hard", Value::Object(hard)),
        ("used", Value::Object(used.iter().map(|(k, v)| (k.clone(), Value::String(v.to_canonical_string()))).collect())),
    ])
}