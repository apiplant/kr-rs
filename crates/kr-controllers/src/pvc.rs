//! The PersistentVolume controller with a built-in local-path provisioner (like k3s's
//! local-path-provisioner). One level-triggered pass over all claims and volumes:
//!
//! * **Protection**: every PVC carries the finalizer `kubernetes.io/pvc-protection`; a deleted
//!   PVC loses it only when no non-terminal pod uses it.
//! * **PV protection**: every PV carries `kubernetes.io/pv-protection`; a deleted PV loses it
//!   unless it is `Bound` to a claim that still exists.
//! * **Static binding**: an unbound PVC takes the smallest Available PV with the same
//!   `storageClassName`, enough capacity, a superset of its access modes and no other claim (or a
//!   `claimRef` naming this PVC).
//! * **Dynamic provisioning**: otherwise, for a class whose provisioner is `kr.io/local-path`, a
//!   PV `pvc-<uid>` with `hostPath` `<STORAGE_ROOT>/pvc-<uid>` and a required node affinity for
//!   one node is created. `WaitForFirstConsumer` waits until a pod using the claim is scheduled
//!   and provisions on that pod's node; `Immediate` picks the first node by name. The kubelet
//!   creates the directory on first use.
//! * **External provisioners**: a claim whose class names another provisioner gets the
//!   `volume.kubernetes.io/storage-provisioner` annotation (and `selected-node` for
//!   `WaitForFirstConsumer`); the provisioner creates the PV with a `claimRef`, bound as above.
//! * **Generic ephemeral volumes**: the claim `<pod>-<volume>` of an `ephemeral.volumeClaimTemplate`
//!   is created owned by the pod.
//! * **Reclaim**: when the claim of a PV is gone, `Delete` deletes the PV (the kubelet then
//!   removes the directory), anything else marks it `Released`. PVs of another provisioner are
//!   only marked `Released`: that provisioner deletes them.

use crate::util::*;
use crate::Config;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_apiserver::client::{Client, Result, STORAGE_ROOT};
use kr_fmt::json::{parse_str, Value};
use kr_fmt::quantity::Quantity;

pub const PROVISIONER: &str = "kr.io/local-path";
pub const PROTECTION: &str = "kubernetes.io/pvc-protection";
const PV_PROTECTION: &str = "kubernetes.io/pv-protection";
const ANN_PROVISIONER: &str = "volume.kubernetes.io/storage-provisioner";
const ANN_PROVISIONER_BETA: &str = "volume.beta.kubernetes.io/storage-provisioner";
const ANN_SELECTED_NODE: &str = "volume.kubernetes.io/selected-node";
const PVS: &str = "/api/v1/persistentvolumes";
const CLASSES: &str = "/apis/storage.k8s.io/v1/storageclasses";

pub async fn run<C: Client + Clone + 'static>(c: C, cfg: Config) {
    let q = Queue::new();
    let mut g = Guard::default();
    for path in [pvcs(None), PVS.to_string(), pods(None)] {
        let q2 = q.clone();
        g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), path, String::new(), cfg, move |_, _| q2.add("all"))));
    }
    let (c2, q3) = (c.clone(), q.clone());
    drive(
        &cfg,
        &q,
        move |_| {
            let c = c2.clone();
            async move { sync(&c).await.map(|()| None) }
        },
        move || {
            q3.add("all");
            async {}
        },
    )
    .await
}

fn uses(pod: &Value, ns: &str, claim: &str) -> bool {
    namespace(pod) == ns
        && pod.pointer(&["spec", "volumes"]).and_then(Value::as_array).is_some_and(|vs| vs.iter().any(|v| volume_claim(pod, v) == claim))
}

/// `spec.<field>.storage` (PV capacity) or `spec.<field>.requests.storage` (PVC) in bytes.
fn storage(o: &Value, field: &str) -> i128 {
    o.pointer(&["spec", field, "storage"])
        .or_else(|| o.pointer(&["spec", field, "requests", "storage"]))
        .and_then(Value::as_str)
        .and_then(|s| Quantity::parse(s).ok())
        .and_then(|q| q.value())
        .unwrap_or(0)
}

fn modes(o: &Value) -> Vec<&str> {
    o.pointer(&["spec", "accessModes"]).and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default()
}

/// `spec.volumeMode`, `Filesystem` when unset.
fn volume_mode(o: &Value) -> &str {
    match str_at(o, &["spec", "volumeMode"]) {
        "" => "Filesystem",
        m => m,
    }
}

fn claim_matches(pv: &Value, pvc: &Value) -> bool {
    let r = |k: &str| str_at(pv, &["spec", "claimRef", k]);
    r("name") == name(pvc) && r("namespace") == namespace(pvc) && (r("uid").is_empty() || r("uid") == uid(pvc))
}

async fn sync<C: Client>(c: &C) -> Result<()> {
    let claims = items(&c.list(&pvcs(None), "").await?);
    let pod_list = items(&c.list(&pods(None), "").await?);
    let mut vols = items(&c.list(PVS, "").await?);
    let classes = items(&c.list(CLASSES, "").await?);
    let mut claims = claims;
    ephemeral_claims(c, &pod_list, &mut claims).await?;
    for pvc in &claims {
        sync_pvc(c, pvc, &pod_list, &mut vols, &classes).await?;
    }
    for pv in &vols {
        sync_pv(c, pv, &claims).await?;
    }
    Ok(())
}

/// Generic ephemeral volumes: creates `<pod>-<volume>` from `volumeClaimTemplate`, owned by the pod
/// (garbage collection deletes it with the pod). A claim of that name not owned by the pod is
/// left alone: the kubelet then refuses the volume.
async fn ephemeral_claims<C: Client>(c: &C, pod_list: &[Value], claims: &mut Vec<Value>) -> Result<()> {
    for pod in pod_list.iter().filter(|p| !pod_terminal(p) && !deleting(p)) {
        for vol in pod.pointer(&["spec", "volumes"]).and_then(Value::as_array).unwrap_or(&[]) {
            let Some(t) = vol.pointer(&["ephemeral", "volumeClaimTemplate"]) else { continue };
            let nm = volume_claim(pod, vol);
            if claims.iter().any(|p| namespace(p) == namespace(pod) && name(p) == nm) {
                continue;
            }
            let mut meta: Vec<(&str, Value)> = alloc::vec![("name", Value::from(nm.as_str())), ("ownerReferences", Value::Array(alloc::vec![owner_ref(pod, "v1", "Pod")]))];
            for k in ["labels", "annotations"] {
                if let Some(m) = t.pointer(&["metadata", k]) {
                    meta.push((k, m.clone()));
                }
            }
            let new = obj(alloc::vec![("apiVersion", Value::from("v1")), ("kind", Value::from("PersistentVolumeClaim")), ("metadata", obj(meta)), ("spec", t.get("spec").cloned().unwrap_or_else(|| obj(Vec::new())))]);
            match c.create(&pvcs(Some(namespace(pod))), &new).await {
                Ok(v) => claims.push(v),
                Err(e) if e.code == 409 => {}
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}

async fn set_finalizer<C: Client>(c: &C, path: &str, fin_name: &str, want: bool) -> Result<()> {
    retry_conflict(|| async {
        let Some(mut o) = get_opt(c, path).await? else { return Ok(()) };
        let fin: Vec<Value> = o.pointer(&["metadata", "finalizers"]).and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
        if fin.iter().any(|f| f.as_str() == Some(fin_name)) == want {
            return Ok(());
        }
        let mut fin: Vec<Value> = fin.into_iter().filter(|f| f.as_str() != Some(fin_name)).collect();
        if want {
            fin.push(Value::from(fin_name));
        }
        o.entry_object("metadata").set("finalizers", Value::Array(fin));
        c.update(path, &o).await.map(|_| ())
    })
    .await
}

fn claim_ref(pvc: &Value) -> Value {
    obj(alloc::vec![
        ("apiVersion", Value::from("v1")),
        ("kind", Value::from("PersistentVolumeClaim")),
        ("namespace", Value::from(namespace(pvc))),
        ("name", Value::from(name(pvc))),
        ("uid", Value::from(uid(pvc))),
    ])
}

async fn sync_pvc<C: Client>(c: &C, pvc: &Value, pod_list: &[Value], vols: &mut Vec<Value>, classes: &[Value]) -> Result<()> {
    let (ns, nm) = (namespace(pvc), name(pvc));
    let path = alloc::format!("{}/{nm}", pvcs(Some(ns)));
    let users: Vec<&Value> = pod_list.iter().filter(|p| !pod_terminal(p) && uses(p, ns, nm)).collect();
    if deleting(pvc) {
        if users.is_empty() {
            set_finalizer(c, &path, PROTECTION, false).await?;
        }
        return Ok(());
    }
    let has_fin = pvc.pointer(&["metadata", "finalizers"]).and_then(Value::as_array).is_some_and(|a| a.iter().any(|f| f.as_str() == Some(PROTECTION)));
    if !has_fin {
        set_finalizer(c, &path, PROTECTION, true).await?;
    }
    let bound = str_at(pvc, &["spec", "volumeName"]);
    if !bound.is_empty() {
        if str_at(pvc, &["status", "phase"]) != "Bound" {
            if let Some(pv) = get_opt(c, &alloc::format!("{PVS}/{bound}")).await? {
                if claim_matches(&pv, pvc) {
                    mark_bound(c, &path, &pv).await?;
                }
            }
        }
        return Ok(());
    }
    let class = str_at(pvc, &["spec", "storageClassName"]);
    let want = storage(pvc, "resources");
    let pvc_modes = modes(pvc);
    // Static binding: the claim's own pre-bound PV, else the smallest fit.
    let mut best: Option<usize> = None;
    for (i, pv) in vols.iter().enumerate() {
        let claimed = !str_at(pv, &["spec", "claimRef", "name"]).is_empty();
        let ok = if claimed { claim_matches(pv, pvc) } else { !matches!(str_at(pv, &["status", "phase"]), "Released" | "Failed") };
        let pv_modes = modes(pv);
        if ok && !deleting(pv) && str_at(pv, &["spec", "storageClassName"]) == class && volume_mode(pv) == volume_mode(pvc) && storage(pv, "capacity") >= want && pvc_modes.iter().all(|m| pv_modes.contains(m)) {
            let mine = best.is_some_and(|b| !str_at(&vols[b], &["spec", "claimRef", "name"]).is_empty());
            if !mine && (claimed || best.is_none_or(|b| storage(&vols[b], "capacity") > storage(pv, "capacity"))) {
                best = Some(i);
            }
        }
    }
    if let Some(i) = best {
        let meta = obj(alloc::vec![("resourceVersion", Value::from(str_at(&vols[i], &["metadata", "resourceVersion"])))]);
        let patch = obj(alloc::vec![("metadata", meta), ("spec", obj(alloc::vec![("claimRef", claim_ref(pvc))]))]);
        match c.patch(&alloc::format!("{PVS}/{}", name(&vols[i])), MERGE, &patch).await {
            Ok(pv) => {
                bind(c, &path, &pv).await?;
                vols[i] = pv;
            }
            Err(e) if e.code == 409 || e.code == 404 => {} // lost a race; the next pass retries
            Err(e) => return Err(e),
        }
        return Ok(());
    }
    // A class served by an external provisioner (a CSI driver's external-provisioner sidecar): it acts
    // on claims annotated with its name, once a node is chosen when binding waits for a consumer.
    if let Some(sc) = classes.iter().find(|k| !class.is_empty() && name(k) == class) {
        let prov = str_at(sc, &["provisioner"]);
        if !prov.is_empty() && prov != PROVISIONER && prov != "kubernetes.io/no-provisioner" {
            let mut ann: Vec<(&str, Value)> = Vec::new();
            for k in [ANN_PROVISIONER, ANN_PROVISIONER_BETA] {
                if str_at(pvc, &["metadata", "annotations", k]) != prov {
                    ann.push((k, Value::from(prov)));
                }
            }
            if str_at(sc, &["volumeBindingMode"]) == "WaitForFirstConsumer" && str_at(pvc, &["metadata", "annotations", ANN_SELECTED_NODE]).is_empty() {
                match users.iter().map(|p| str_at(p, &["spec", "nodeName"])).find(|n| !n.is_empty()) {
                    Some(n) => ann.push((ANN_SELECTED_NODE, Value::from(n))),
                    None => ann.clear(), // wait for a scheduled pod
                }
            }
            if !ann.is_empty() {
                let patch = obj(alloc::vec![("metadata", obj(alloc::vec![("annotations", obj(ann))]))]);
                match c.patch(&path, MERGE, &patch).await {
                    Ok(_) => {}
                    Err(e) if e.code == 409 || e.code == 404 => {}
                    Err(e) => return Err(e),
                }
            }
            return Ok(());
        }
    }
    // Dynamic provisioning.
    let Some(sc) = classes.iter().find(|k| name(k) == class && str_at(k, &["provisioner"]) == PROVISIONER) else { return Ok(()) };
    if volume_mode(pvc) == "Block" {
        return Ok(()); // a directory cannot back a block volume
    }
    let node = match users.iter().map(|p| str_at(p, &["spec", "nodeName"])).find(|n| !n.is_empty()) {
        Some(n) => n.to_string(),
        None if str_at(sc, &["volumeBindingMode"]) == "Immediate" => {
            let mut names: Vec<String> = items(&c.list(NODES, "").await?).iter().map(|n| name(n).to_string()).collect();
            names.sort();
            match names.into_iter().next() {
                Some(n) => n,
                None => return Ok(()),
            }
        }
        None => return Ok(()), // WaitForFirstConsumer: no scheduled pod yet
    };
    let pv_name = alloc::format!("pvc-{}", uid(pvc));
    let reclaim = match str_at(sc, &["reclaimPolicy"]) {
        "" => "Delete",
        r => r,
    };
    let requested = pvc.pointer(&["spec", "resources", "requests", "storage"]).cloned().unwrap_or_else(|| Value::from("1Gi"));
    let mut pv = parse_str(r#"{"apiVersion":"v1","kind":"PersistentVolume","metadata":{"annotations":{"pv.kubernetes.io/provisioned-by":"kr.io/local-path"}},"spec":{"volumeMode":"Filesystem"}}"#)
        .map_err(|_| kr_apiserver::object::ApiError::new(500, "InternalError", "template"))?;
    pv.entry_object("metadata").set("name", Value::from(pv_name.as_str()));
    let spec = pv.entry_object("spec");
    spec.set("capacity", obj(alloc::vec![("storage", requested)]));
    spec.set("accessModes", pvc.pointer(&["spec", "accessModes"]).cloned().unwrap_or(Value::Array(Vec::new())));
    spec.set("persistentVolumeReclaimPolicy", Value::from(reclaim));
    spec.set("storageClassName", Value::from(class));
    spec.set("claimRef", claim_ref(pvc));
    spec.set("hostPath", obj(alloc::vec![("path", Value::String(alloc::format!("{STORAGE_ROOT}/{pv_name}"))), ("type", Value::from("DirectoryOrCreate"))]));
    let expr = obj(alloc::vec![("key", Value::from("kubernetes.io/hostname")), ("operator", Value::from("In")), ("values", Value::Array(alloc::vec![Value::String(node)]))]);
    let term = obj(alloc::vec![("matchExpressions", Value::Array(alloc::vec![expr]))]);
    spec.set("nodeAffinity", obj(alloc::vec![("required", obj(alloc::vec![("nodeSelectorTerms", Value::Array(alloc::vec![term]))]))]));
    let pv = match c.create(PVS, &pv).await {
        Ok(v) => v,
        Err(e) if e.code == 409 => c.get(&alloc::format!("{PVS}/{pv_name}")).await?,
        Err(e) => return Err(e),
    };
    bind(c, &path, &pv).await?;
    vols.push(pv);
    Ok(())
}

async fn set_phase<C: Client>(c: &C, path: &str, phase: &'static str) -> Result<()> {
    put_status(c, path, move |o| {
        let mut st = o.get("status").cloned().unwrap_or_else(|| obj(Vec::new()));
        st.set("phase", Value::from(phase));
        st
    })
    .await
}

/// Both sides of a binding: the PV phase, then the PVC's `volumeName` and status.
async fn bind<C: Client>(c: &C, pvc_path: &str, pv: &Value) -> Result<()> {
    set_phase(c, &alloc::format!("{PVS}/{}", name(pv)), "Bound").await?;
    let patch = obj(alloc::vec![("spec", obj(alloc::vec![("volumeName", Value::from(name(pv)))]))]);
    c.patch(pvc_path, MERGE, &patch).await?;
    mark_bound(c, pvc_path, pv).await
}

async fn mark_bound<C: Client>(c: &C, pvc_path: &str, pv: &Value) -> Result<()> {
    let capacity = pv.pointer(&["spec", "capacity"]).cloned().unwrap_or(Value::Null);
    let access = pv.pointer(&["spec", "accessModes"]).cloned().unwrap_or(Value::Null);
    put_status(c, pvc_path, |o| {
        let mut st = o.get("status").cloned().unwrap_or_else(|| obj(Vec::new()));
        st.set("phase", Value::from("Bound"));
        st.set("accessModes", access.clone());
        st.set("capacity", capacity.clone());
        st
    })
    .await
}

async fn sync_pv<C: Client>(c: &C, pv: &Value, claims: &[Value]) -> Result<()> {
    let path = alloc::format!("{PVS}/{}", name(pv));
    let phase = str_at(pv, &["status", "phase"]);
    if deleting(pv) {
        if phase != "Bound" || !claims.iter().any(|p| claim_matches(pv, p)) {
            set_finalizer(c, &path, PV_PROTECTION, false).await?;
        }
        return Ok(());
    }
    let has_fin = pv.pointer(&["metadata", "finalizers"]).and_then(Value::as_array).is_some_and(|a| a.iter().any(|f| f.as_str() == Some(PV_PROTECTION)));
    if !has_fin {
        set_finalizer(c, &path, PV_PROTECTION, true).await?;
    }
    if str_at(pv, &["spec", "claimRef", "name"]).is_empty() {
        // New PVs start Pending (API defaulting); unclaimed ones become Available.
        if phase.is_empty() || phase == "Pending" {
            set_phase(c, &path, "Available").await?;
        }
        return Ok(());
    }
    match claims.iter().find(|p| claim_matches(pv, p)) {
        Some(p) => {
            if phase != "Bound" && str_at(p, &["spec", "volumeName"]) == name(pv) {
                set_phase(c, &path, "Bound").await?;
            }
        }
        None if phase == "Released" => {}
        // A volume another provisioner created is deleted by that provisioner (it sees `Released`).
        None if str_at(pv, &["spec", "persistentVolumeReclaimPolicy"]) == "Delete" && matches!(str_at(pv, &["metadata", "annotations", "pv.kubernetes.io/provisioned-by"]), "" | PROVISIONER) => delete_ok(c, &path).await?,
        None => set_phase(c, &path, "Released").await?,
    }
    Ok(())
}
