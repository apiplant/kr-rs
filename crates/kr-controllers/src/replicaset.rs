//! The ReplicaSet controller: keeps `spec.replicas` (default 1) pods that match `spec.selector`
//! and are controlled by the ReplicaSet.
//!
//! Per reconcile (from fresh reads):
//!
//! 1. list the namespace's pods matching the selector; pods with a `deletionTimestamp` or in a
//!    terminal phase are ignored for counting;
//! 2. matching pods without any controller owner are *adopted* (merge patch of
//!    `ownerReferences`); pods controlled by something else are left alone;
//! 3. too few: create pods from `spec.template` (`generateName: <rs>-`, template labels and
//!    annotations, controller owner reference); too many: delete the most expendable first
//!    (unscheduled, then not running, then not ready, then newest);
//! 4. write `status` (`replicas`, `readyReplicas`, `availableReplicas`, `fullyLabeledReplicas`,
//!    `observedGeneration`) with a PUT of the full object to `replicasets/{name}/status`, only
//!    if it differs from what is stored. `availableReplicas` equals `readyReplicas`
//!    (`minReadySeconds` is not modelled).
//!
//! Pod events map to the owning ReplicaSet; events of orphan pods wake every ReplicaSet in the
//! namespace (key `<ns>/*`) so that adoption happens.

use crate::util::*;
use crate::Config;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Reverse;
use kr_apiserver::client::{Client, Result};
use kr_fmt::json::Value;

const MAX_BURST: usize = 500;

pub async fn run<C: Client + Clone + 'static>(c: C, cfg: Config) {
    let q = Queue::new();
    let mut g = Guard::default();
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), replicasets(None), String::new(), cfg, move |_, o| q2.add(&key_of(o)))));
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), pods(None), String::new(), cfg, move |_, p| match controller_ref(p) {
        Some(r) if str_at(r, &["kind"]) == "ReplicaSet" => q2.add(&alloc::format!("{}/{}", namespace(p), str_at(r, &["name"]))),
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
                    for rs in items(&c.list(&replicasets(Some(ns)), "").await?) {
                        q.add(&key_of(&rs));
                    }
                    return Ok(None);
                }
                reconcile(&c, ns, n).await?;
                Ok(None)
            }
        },
        move || {
            let (c, q) = (c3.clone(), q3.clone());
            async move {
                if let Ok(l) = c.list(&replicasets(None), "").await {
                    for rs in items(&l) {
                        q.add(&key_of(&rs));
                    }
                }
            }
        },
    )
    .await
}

fn phase_rank(p: &Value) -> u8 {
    match str_at(p, &["status", "phase"]) {
        "Running" => 2,
        "Pending" | "" => 0,
        _ => 1,
    }
}

/// Lower sorts first and is deleted first.
fn deletion_rank(p: &Value) -> (bool, u8, bool, Reverse<String>, Reverse<u64>) {
    let rv = str_at(p, &["metadata", "resourceVersion"]).parse::<u64>().unwrap_or(0);
    (!str_at(p, &["spec", "nodeName"]).is_empty(), phase_rank(p), pod_ready(p), Reverse(String::from(str_at(p, &["metadata", "creationTimestamp"]))), Reverse(rv))
}

fn fully_labeled(rs: &Value, p: &Value) -> bool {
    rs.pointer(&["spec", "template", "metadata", "labels"]).and_then(Value::as_object).unwrap_or(&[]).iter().all(|(k, v)| p.pointer(&["metadata", "labels", k]) == Some(v))
}

pub async fn reconcile<C: Client>(c: &C, ns: &str, name: &str) -> Result<()> {
    let rs = match c.get(&alloc::format!("{}/{name}", replicasets(Some(ns)))).await {
        Ok(r) => r,
        Err(e) if e.code == 404 => return Ok(()),
        Err(e) => return Err(e),
    };
    if deleting(&rs) {
        return Ok(());
    }
    let desired = int_at(&rs, &["spec", "replicas"], 1).max(0) as usize;
    let Some((sel_str, sel)) = rs.get("spec").and_then(|s| s.get("selector")).and_then(parse_selector) else { return Ok(()) };
    let list = c.list(&pods(Some(ns)), &alloc::format!("labelSelector={}", enc(&sel_str))).await?;
    let rs_uid = uid(&rs);

    let mut owned: Vec<Value> = Vec::new();
    for p in items(&list).into_iter().filter(|p| sel.matches(p) && !deleting(p) && !pod_terminal(p)) {
        match controller_ref(&p) {
            Some(r) if str_at(r, &["uid"]) == rs_uid => owned.push(p),
            Some(_) => {}
            None => {
                if let Some(p) = adopt(c, &rs, &p).await? {
                    owned.push(p);
                }
            }
        }
    }

    if owned.len() < desired {
        let tpl = rs.pointer(&["spec", "template"]).cloned().unwrap_or(Value::Null);
        for _ in 0..(desired - owned.len()).min(MAX_BURST) {
            c.create(&pods(Some(ns)), &pod_from_template(&rs, &tpl)).await?;
        }
    } else if owned.len() > desired {
        owned.sort_by_key(deletion_rank);
        for p in owned.iter().take(owned.len() - desired) {
            match c.delete(&alloc::format!("{}/{}", pods(Some(ns)), name_of(p))).await {
                Ok(_) => {}
                Err(e) if e.code == 404 => {}
                Err(e) => return Err(e),
            }
        }
    }

    let ready = owned.iter().filter(|p| pod_ready(p)).count();
    let labeled = owned.iter().filter(|p| fully_labeled(&rs, p)).count();
    write_status(c, ns, name, owned.len(), ready, labeled).await
}

fn name_of(p: &Value) -> &str {
    name(p)
}

fn pod_from_template(rs: &Value, tpl: &Value) -> Value {
    let mut meta = alloc::vec![("generateName", Value::String(alloc::format!("{}-", name(rs)))), ("namespace", Value::from(namespace(rs)))];
    for f in ["labels", "annotations"] {
        if let Some(v) = tpl.pointer(&["metadata", f]) {
            meta.push((f, v.clone()));
        }
    }
    meta.push(("ownerReferences", Value::Array(alloc::vec![owner_ref(rs, "apps/v1", "ReplicaSet")])));
    obj(alloc::vec![("apiVersion", Value::from("v1")), ("kind", Value::from("Pod")), ("metadata", obj(meta)), ("spec", tpl.get("spec").cloned().unwrap_or(Value::Null))])
}

/// Adds the controller reference to an orphan. `None` when the pod vanished or was adopted by
/// someone else in the meantime.
async fn adopt<C: Client>(c: &C, rs: &Value, p: &Value) -> Result<Option<Value>> {
    let mut refs: Vec<Value> = p.pointer(&["metadata", "ownerReferences"]).and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
    refs.push(owner_ref(rs, "apps/v1", "ReplicaSet"));
    // Guard against a concurrent adoption with the pod's resourceVersion.
    let meta = obj(alloc::vec![("ownerReferences", Value::Array(refs)), ("resourceVersion", Value::from(str_at(p, &["metadata", "resourceVersion"])))]);
    match c.patch(&alloc::format!("{}/{}", pods(Some(namespace(p))), name(p)), MERGE, &obj(alloc::vec![("metadata", meta)])).await {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.code == 404 || e.code == 409 => Ok(None),
        Err(e) => Err(e),
    }
}

async fn write_status<C: Client>(c: &C, ns: &str, name: &str, replicas: usize, ready: usize, labeled: usize) -> Result<()> {
    let path = alloc::format!("{}/{name}", replicasets(Some(ns)));
    retry_conflict(|| async {
        let mut rs = match c.get(&path).await {
            Ok(r) => r,
            Err(e) if e.code == 404 => return Ok(()),
            Err(e) => return Err(e),
        };
        let gen = int_at(&rs, &["metadata", "generation"], 0);
        let mut want = obj(alloc::vec![
            ("replicas", num(replicas as i64)),
            ("fullyLabeledReplicas", num(labeled as i64)),
            ("readyReplicas", num(ready as i64)),
            ("availableReplicas", num(ready as i64)),
            ("observedGeneration", num(gen)),
        ]);
        if let Some(conds) = rs.pointer(&["status", "conditions"]) {
            want.set("conditions", conds.clone());
        }
        let same = ["replicas", "fullyLabeledReplicas", "readyReplicas", "availableReplicas", "observedGeneration"].iter().all(|f| rs.pointer(&["status", f]).and_then(Value::as_i64) == want.get(f).and_then(Value::as_i64));
        if same {
            return Ok(());
        }
        rs.set("status", want);
        c.update(&alloc::format!("{path}/status"), &rs).await.map(|_| ())
    })
    .await
}
