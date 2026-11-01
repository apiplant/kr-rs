//! The storage version migrator: runs `StorageVersionMigration` objects.
//!
//! A migration names a resource (`spec.resource.group`/`resource`). For a custom resource it
//! rewrites every object through the CRD's storage version (read, then PUT back unchanged), so
//! each is stored with that apiVersion; built-in kinds have a single stored form and succeed at
//! once. The result is the `Succeeded` or `Failed` condition.

use crate::util::*;
use crate::Config;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_apiserver::client::{Client, Result};
use kr_fmt::json::Value;

const SVMS: &str = "/apis/storagemigration.k8s.io/v1/storageversionmigrations";
const CRDS: &str = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions";

pub async fn run<C: Client + Clone + 'static>(c: C, cfg: Config) {
    let q = Queue::new();
    let mut g = Guard::default();
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), SVMS.to_string(), String::new(), cfg, move |_, o| q2.add(&key_of(o)))));
    let (c2, c3, q3) = (c.clone(), c.clone(), q.clone());
    drive(
        &cfg,
        &q,
        move |key| {
            let c = c2.clone();
            async move { reconcile(&c, &cfg, split_key(&key).1).await.map(|()| None) }
        },
        move || {
            let (c, q) = (c3.clone(), q3.clone());
            async move {
                if let Ok(l) = c.list(SVMS, "").await {
                    for m in items(&l) {
                        q.add(&key_of(&m));
                    }
                }
            }
        },
    )
    .await
}

fn finished(m: &Value) -> bool {
    m.pointer(&["status", "conditions"]).and_then(Value::as_array).is_some_and(|cs| cs.iter().any(|c| matches!(str_at(c, &["type"]), "Succeeded" | "Failed") && str_at(c, &["status"]) == "True"))
}

pub async fn reconcile<C: Client>(c: &C, cfg: &Config, name: &str) -> Result<()> {
    let path = alloc::format!("{SVMS}/{name}");
    let Some(m) = get_opt(c, &path).await? else { return Ok(()) };
    if finished(&m) || deleting(&m) {
        return Ok(());
    }
    let (group, resource) = (str_at(&m, &["spec", "resource", "group"]).to_string(), str_at(&m, &["spec", "resource", "resource"]).to_string());
    let now = (cfg.now)();
    let result = migrate(c, &group, &resource).await;
    let cond = match result {
        Ok(n) => condition("Succeeded", true, "Migrated", &alloc::format!("{n} object(s) rewritten"), now),
        Err(e) => condition("Failed", true, "MigrationFailed", &alloc::format!("{}", e.message), now),
    };
    put_status(c, &path, |o| {
        let mut st = o.get("status").filter(|s| s.as_object().is_some()).cloned().unwrap_or(Value::Object(Vec::new()));
        let old: Vec<Value> = st.get("conditions").and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
        let mut conds = old.clone();
        set_condition(&mut conds, merge_condition(&old, cond.clone()));
        st.set("conditions", Value::Array(conds));
        st
    })
    .await
}

/// Rewrites the objects of a custom resource at its storage version; the number rewritten.
async fn migrate<C: Client>(c: &C, group: &str, resource: &str) -> Result<usize> {
    let crds = c.list(CRDS, "").await?;
    let Some(crd) = items(&crds).into_iter().find(|d| str_at(d, &["spec", "group"]) == group && str_at(d, &["spec", "names", "plural"]) == resource) else {
        return Ok(0); // built-in kind: one stored form
    };
    let storage = crd.pointer(&["spec", "versions"]).and_then(Value::as_array).and_then(|vs| vs.iter().find(|v| v.get("storage").and_then(Value::as_bool) == Some(true))).map(|v| str_at(v, &["name"]).to_string()).unwrap_or_default();
    if storage.is_empty() {
        return Ok(0);
    }
    let base = alloc::format!("/apis/{group}/{storage}");
    let namespaced = str_at(&crd, &["spec", "scope"]) == "Namespaced";
    let mut n = 0;
    for mut o in items(&c.list(&alloc::format!("{base}/{resource}"), "").await?) {
        o.set("apiVersion", Value::String(alloc::format!("{group}/{storage}")));
        let path = if namespaced { alloc::format!("{base}/namespaces/{}/{resource}/{}", namespace(&o), name(&o)) } else { alloc::format!("{base}/{resource}/{}", name(&o)) };
        match c.update(&path, &o).await {
            Ok(_) => n += 1,
            Err(e) if e.code == 404 => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}
