//! The CRD finalizer controller: finishes the deletion of `Terminating` CustomResourceDefinitions.
//!
//! `DELETE customresourcedefinitions/{n}` only sets `deletionTimestamp` (the API server added the
//! `customresourcecleanup.apiextensions.k8s.io` finalizer at creation) and refuses new custom
//! resources. For such a CRD this controller deletes every instance (all served versions share
//! storage, so the storage version's list is enough) and re-checks every `Config::retry_ms` until
//! none is left (instances with their own finalizers stay until those are removed). Then it
//! removes the finalizer, upon which the API server deletes the CRD and unregisters its resource.

use crate::util::*;
use crate::Config;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_apiserver::client::{Client, Result};
use kr_fmt::json::Value;

const CRDS: &str = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions";
const FINALIZER: &str = "customresourcecleanup.apiextensions.k8s.io";

pub async fn run<C: Client + Clone + 'static>(c: C, cfg: Config) {
    let q = Queue::new();
    let mut g = Guard::default();
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), CRDS.to_string(), String::new(), cfg, move |_, o| {
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
                if let Ok(l) = c.list(CRDS, "").await {
                    for n in items(&l).iter().filter(|n| deleting(n)) {
                        q.add(&key_of(n));
                    }
                }
            }
        },
    )
    .await
}

/// The collection path of the CRD's instances (cluster-wide for namespaced CRDs).
fn list_path(crd: &Value) -> String {
    let versions = crd.pointer(&["spec", "versions"]).and_then(Value::as_array).unwrap_or(&[]);
    let version = versions.iter().find(|v| v.get("storage").and_then(Value::as_bool) == Some(true)).map(|v| str_at(v, &["name"])).unwrap_or("");
    alloc::format!("/apis/{}/{version}/{}", str_at(crd, &["spec", "group"]), str_at(crd, &["spec", "names", "plural"]))
}

pub async fn reconcile<C: Client>(c: &C, cfg: &Config, crd_name: &str) -> Result<Option<u64>> {
    let path = alloc::format!("{CRDS}/{crd_name}");
    let Some(crd) = get_opt(c, &path).await? else { return Ok(None) };
    let ours = crd.pointer(&["metadata", "finalizers"]).and_then(Value::as_array).is_some_and(|f| f.iter().any(|f| f.as_str() == Some(FINALIZER)));
    if !deleting(&crd) || !ours {
        return Ok(None);
    }
    let list = list_path(&crd);
    let mut remaining = 0usize;
    if let Ok(l) = c.list(&list, "").await {
        for o in items(&l) {
            remaining += 1;
            if !deleting(&o) {
                let ns = namespace(&o);
                let p = if ns.is_empty() {
                    alloc::format!("{list}/{}", name(&o))
                } else {
                    let (base, plural) = list.rsplit_once('/').unwrap_or((&list, ""));
                    alloc::format!("{base}/namespaces/{ns}/{plural}/{}", name(&o))
                };
                delete_ok(c, &p).await?;
            }
        }
    }
    if remaining > 0 {
        return Ok(Some(cfg.retry_ms));
    }
    // Empty: drop our finalizer; the API server removes the CRD and unregisters its resource.
    retry_conflict(|| async {
        let Some(mut o) = get_opt(c, &path).await? else { return Ok(()) };
        let keep: Vec<Value> = o.pointer(&["metadata", "finalizers"]).and_then(Value::as_array).unwrap_or(&[]).iter().filter(|f| f.as_str() != Some(FINALIZER)).cloned().collect();
        o.entry_object("metadata").set("finalizers", Value::Array(keep));
        c.update(&path, &o).await.map(|_| ())
    })
    .await?;
    Ok(None)
}
