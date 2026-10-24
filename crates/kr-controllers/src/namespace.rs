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
async fn namespaced_resources<C: Client>(c: &C, ns: &str) -> Result<Vec<String>> {
    let mut lists: Vec<(String, Value)> = alloc::vec![("/api/v1".to_string(), c.get("/api/v1").await?)];
    if let Ok(groups) = c.get("/apis").await {
        for g in groups.get("groups").and_then(Value::as_array).unwrap_or(&[]) {
            let gv = str_at(g, &["preferredVersion", "groupVersion"]);
            if gv.is_empty() {
                continue;
            }
            if let Ok(l) = c.get(&alloc::format!("/apis/{gv}")).await {
                lists.push((alloc::format!("/apis/{gv}"), l));
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
    Ok(out)
}

pub async fn reconcile<C: Client>(c: &C, cfg: &Config, ns: &str) -> Result<Option<u64>> {
    let path = alloc::format!("/api/v1/namespaces/{ns}");
    let Some(n) = get_opt(c, &path).await? else { return Ok(None) };
    if !deleting(&n) {
        return Ok(None);
    }
    let mut remaining = 0usize;
    for list in namespaced_resources(c, ns).await? {
        let Ok(l) = c.list(&list, "").await else { continue };
        for o in items(&l) {
            remaining += 1;
            if !deleting(&o) {
                delete_ok(c, &alloc::format!("{list}/{}", name(&o))).await?;
            }
        }
    }
    let now = (cfg.now)();
    if remaining > 0 {
        let msg = alloc::format!("Some resources are remaining: {remaining} object(s)");
        put_conditions(c, &path, condition("NamespaceContentRemaining", true, "SomeResourcesRemain", &msg, now)).await?;
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
