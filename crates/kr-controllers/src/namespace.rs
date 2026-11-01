//! The namespace controller: finishes the deletion of `Terminating` namespaces.
//!
//! `DELETE /namespaces/{n}` only sets `deletionTimestamp` and `status.phase: Terminating` (the
//! API server also refuses new content then). For such a namespace this controller discovers
//! every namespaced resource (`/api/v1`, and the preferred version of each group in `/apis`,
//! which includes CRD-defined resources), deletes all objects of them and re-checks every
//! `Config::retry_ms` until nothing is left (pods terminate gracefully on their nodes first;
//! objects with finalizers stay until those are removed). Then it drops the `kubernetes`
//! entry from `spec.finalizers` with `PUT namespaces/{n}/finalize`, upon which the API server
//! deletes the namespace. While content remains, the `NamespaceContentRemaining` condition says
//! how many objects are left.

use crate::util::*;
use crate::Config;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_apiserver::client::{Client, Result};
use kr_fmt::json::Value;

pub async fn run<C: Client + Clone + 'static>(c: C, cfg: Config) {
    let q = Queue::new();
    let mut g = Guard::default();
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), "/api/v1/namespaces".to_string(), String::new(), cfg, move |_, o| {
        if deleting(o) {
            q2.add(&key_of(o))
        }
    })));
    let (c2, c3, q3) = (c.clone(), c.clone(), q.clone());
    drive(
        &cfg,
        &q,
        move |key| {
            let c = c2.clone();
            async move { reconcile(&c, &cfg, split_key(&key).1).await }
        },
        move || {
            let (c, q) = (c3.clone(), q3.clone());
            async move {
                if let Ok(l) = c.list("/api/v1/namespaces", "").await {
                    for n in items(&l).iter().filter(|n| deleting(n)) {
                        q.add(&key_of(n));
                    }
                }
            }
        },
    )
    .await
}

/// List paths (`/api/v1/namespaces/{ns}/{plural}`) of every deletable namespaced resource.
/// The second value lists the group versions whose discovery failed.
async fn namespaced_resources<C: Client>(c: &C, ns: &str) -> Result<(Vec<String>, Vec<String>)> {
    let mut failed: Vec<String> = Vec::new();
    let mut lists: Vec<(String, Value)> = alloc::vec![("/api/v1".to_string(), c.get("/api/v1").await?)];
    if let Ok(groups) = c.get("/apis").await {
        for g in groups.get("groups").and_then(Value::as_array).unwrap_or(&[]) {
            let gv = str_at(g, &["preferredVersion", "groupVersion"]);
            if gv.is_empty() {
                continue;
            }
            match c.get(&alloc::format!("/apis/{gv}")).await {
                Ok(l) => lists.push((alloc::format!("/apis/{gv}"), l)),
                Err(_) => failed.push(gv.to_string()),
            }
        }
    }
    let mut out = Vec::new();
    for (base, l) in lists {
        for r in l.get("resources").and_then(Value::as_array).unwrap_or(&[]) {
            let n = str_at(r, &["name"]);
            let verbs = r.get("verbs").and_then(Value::as_array).unwrap_or(&[]);
            let has = |v: &str| verbs.iter().any(|x| x.as_str() == Some(v));
            if r.get("namespaced").and_then(Value::as_bool) == Some(true) && !n.contains('/') && has("list") && has("delete") {
                out.push(alloc::format!("{base}/namespaces/{ns}/{n}"));
            }
        }
    }
    Ok((out, failed))
}

pub async fn reconcile<C: Client>(c: &C, cfg: &Config, ns: &str) -> Result<Option<u64>> {
    let path = alloc::format!("/api/v1/namespaces/{ns}");
    let Some(n) = get_opt(c, &path).await? else { return Ok(None) };
    if !deleting(&n) {
        return Ok(None);
    }
    // Ordered deletion: pods go first; nothing else is touched while any pod (e.g. one held by a
    // finalizer) is left.
    let pods = alloc::format!("/api/v1/namespaces/{ns}/pods");
    if let Ok(l) = c.list(&pods, "").await {
        let left = items(&l);
        if !left.is_empty() {
            for o in left.iter().filter(|o| !deleting(o)) {
                delete_ok(c, &alloc::format!("{pods}/{}", name(o))).await?;
            }
            let now = (cfg.now)();
            let msg = alloc::format!("Some resources are remaining: pods. has {} resource instances", left.len());
            put_conditions(c, &path, condition("NamespaceDeletionContentFailure", true, "ContentDeletionFailed", &msg, now)).await?;
            put_conditions(c, &path, condition("NamespaceContentRemaining", true, "SomeResourcesRemain", &msg, now)).await?;
            return Ok(Some(cfg.retry_ms));
        }
    }
    let mut remaining = 0usize;
    let mut by_resource: Vec<(String, usize)> = Vec::new();
    let mut with_fin: Vec<(String, usize)> = Vec::new();
    let mut failed_delete: Vec<String> = Vec::new();
    let (lists, bad_groups) = namespaced_resources(c, ns).await?;
    for list in lists {
        let Ok(l) = c.list(&list, "").await else { continue };
        let res = list.rsplit('/').next().unwrap_or("").to_string();
        let (mut n_all, mut n_fin) = (0, 0);
        for o in items(&l) {
            n_all += 1;
            if !deleting(&o) {
                if delete_ok(c, &alloc::format!("{list}/{}", name(&o))).await.is_err() {
                    failed_delete.push(alloc::format!("{res}/{}", name(&o)));
                }
            } else if o.pointer(&["metadata", "finalizers"]).and_then(Value::as_array).is_some_and(|f| !f.is_empty()) {
                n_fin += 1;
            }
        }
        remaining += n_all;
        if n_all > 0 {
            by_resource.push((res.clone(), n_all));
        }
        if n_fin > 0 {
            with_fin.push((res, n_fin));
        }
    }
    let now = (cfg.now)();
    let listing = |v: &[(String, usize)]| v.iter().map(|(r, n)| alloc::format!("{r}. has {n} resource instances")).collect::<Vec<_>>().join(", ");
    let existing: Vec<String> = n.pointer(&["status", "conditions"]).and_then(Value::as_array).unwrap_or(&[]).iter().map(|x| str_at(x, &["type"]).to_string()).collect();
    let states: [(&str, bool, &str, String); 4] = [
        ("NamespaceDeletionDiscoveryFailure", !bad_groups.is_empty(), "DiscoveryFailed", alloc::format!("Discovery failed for some groups, {} failing: unable to retrieve the complete list of server APIs: {}", bad_groups.len(), bad_groups.join(", "))),
        ("NamespaceDeletionContentFailure", !failed_delete.is_empty(), "ContentDeletionFailed", alloc::format!("Failed to delete all resource types, {} remaining: {}", failed_delete.len(), failed_delete.join(", "))),
        ("NamespaceContentRemaining", remaining > 0, "SomeResourcesRemain", alloc::format!("Some resources are remaining: {}", listing(&by_resource))),
        ("NamespaceFinalizersRemaining", !with_fin.is_empty(), "SomeFinalizersRemain", alloc::format!("Some content in the namespace has finalizers remaining: {}", with_fin.iter().map(|(r, n)| alloc::format!("{r} in {n} resource instances")).collect::<Vec<_>>().join(", "))),
    ];
    for (ty, on, reason, msg) in &states {
        if *on || existing.iter().any(|e| e == ty) {
            put_conditions(c, &path, condition(ty, *on, reason, if *on { msg } else { "All content successfully deleted, may be waiting on finalization" }, now)).await?;
        }
    }
    if remaining > 0 || !bad_groups.is_empty() {
        return Ok(Some(cfg.retry_ms));
    }
    // Empty: drop our finalizer; the API server removes the namespace once none is left.
    retry_conflict(|| async {
        let Some(mut n) = get_opt(c, &path).await? else { return Ok(()) };
        let fin: Vec<Value> = n.pointer(&["spec", "finalizers"]).and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
        if !fin.iter().any(|f| f.as_str() == Some("kubernetes")) {
            return Ok(());
        }
        let keep: Vec<Value> = fin.into_iter().filter(|f| f.as_str() != Some("kubernetes")).collect();
        n.entry_object("spec").set("finalizers", Value::Array(keep));
        c.update(&alloc::format!("{path}/finalize"), &n).await.map(|_| ())
    })
    .await?;
    Ok(None)
}

async fn put_conditions<C: Client>(c: &C, path: &str, cond: Value) -> Result<()> {
    put_status(c, path, |o| {
        let mut st = o.get("status").cloned().unwrap_or(Value::Null);
        let old: Vec<Value> = st.get("conditions").and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
        let mut conds = old.clone();
        set_condition(&mut conds, merge_condition(&old, cond.clone()));
        st.set("conditions", Value::Array(conds));
        st
    })
    .await
}
