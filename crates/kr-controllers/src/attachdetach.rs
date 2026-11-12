//! The attach/detach controller: for every non-terminal scheduled pod that uses a PVC bound to a
//! CSI PersistentVolume of a driver with `attachRequired` (the default), a `VolumeAttachment`
//! named [`va_name`] exists; the external-attacher sidecar fulfils it. Attachments this
//! controller created (label [`LABEL`]) that are no longer wanted are deleted (the attacher
//! detaches and drops its finalizer). Level-triggered, every 3 s.
//!
//! An unwanted attachment is kept while its node still lists the volume in
//! `status.volumesInUse` (the kubelet has it mounted); only after [`MAX_WAIT_MS`] of waiting
//! (upstream's 6 minute max-wait-for-unmount) is it deleted anyway.

use crate::util::*;
use alloc::collections::{BTreeMap, BTreeSet};
use core::cell::RefCell;
use alloc::string::{String, ToString};
use kr_apiserver::client::{Client, Result};
use kr_fmt::json::Value;

pub const LABEL: &str = "kr.io/attach-controller";
/// Annotation: wall-clock seconds when the attachment was first found unwanted (the wait for the
/// unmount survives a restart of the controller).
const SINCE: &str = "kr.io/unwanted-since";
const VAS: &str = "/apis/storage.k8s.io/v1/volumeattachments";
/// How long a volume the node still reports in use blocks the detach.
pub const MAX_WAIT_MS: u64 = 6 * 60 * 1000;
const DRIVERS: &str = "/apis/storage.k8s.io/v1/csidrivers";

/// Name of the VolumeAttachment for a volume on a node (as upstream: `csi-` + sha256 hex).
pub fn va_name(handle: &str, driver: &str, node: &str) -> String {
    let h = kr_crypto::sha2::sha256(alloc::format!("{handle}{driver}{node}").as_bytes());
    let mut s = String::from("csi-");
    for b in h {
        s.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
        s.push(char::from(b"0123456789abcdef"[usize::from(b & 15)]));
    }
    s
}

pub async fn run<C: Client + Clone + 'static>(c: C, wall: fn() -> i64) {
    let waiting = RefCell::new(BTreeMap::new());
    loop {
        kr_rt::exec::sleep(3_000).await;
        let _ = tick_at(&c, &waiting, kr_rt::exec::now_ms(), wall().max(0) as u64).await;
    }
}

/// Whether the node of `va` still reports its volume as in use.
async fn in_use<C: Client>(c: &C, va: &Value) -> bool {
    let (node, pv) = (str_at(va, &["spec", "nodeName"]), str_at(va, &["spec", "source", "persistentVolumeName"]));
    let (Ok(Some(node)), Ok(Some(pv))) = (get_opt(c, &alloc::format!("/api/v1/nodes/{node}")).await, get_opt(c, &alloc::format!("/api/v1/persistentvolumes/{pv}")).await) else { return false };
    let vol = alloc::format!("kubernetes.io/csi/{}^{}", str_at(&pv, &["spec", "csi", "driver"]), str_at(&pv, &["spec", "csi", "volumeHandle"]));
    node.pointer(&["status", "volumesInUse"]).and_then(Value::as_array).is_some_and(|a| a.iter().any(|v| v.as_str() == Some(vol.as_str())))
}

fn find<'a>(l: &'a [Value], ns: &str, n: &str) -> Option<&'a Value> {
    l.iter().find(|o| name(o) == n && namespace(o) == ns)
}

/// `node.status.volumesAttached` (upstream's attach/detach controller writes it): the volumes
/// whose attachment on the node is `status.attached`, until the attachment is gone. Only nodes
/// whose list changed are patched.
async fn publish_attached<C: Client>(c: &C, pvs: &[Value], vas: &[Value]) {
    let mut by_node: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for va in vas.iter().filter(|v| str_at(v, &["status", "attached"]) == "true" || v.pointer(&["status", "attached"]).and_then(Value::as_bool) == Some(true)) {
        let Some(pv) = pvs.iter().find(|p| name(p) == str_at(va, &["spec", "source", "persistentVolumeName"])) else { continue };
        let vol = alloc::format!("kubernetes.io/csi/{}^{}", str_at(pv, &["spec", "csi", "driver"]), str_at(pv, &["spec", "csi", "volumeHandle"]));
        by_node.entry(str_at(va, &["spec", "nodeName"]).to_string()).or_default().insert(vol);
    }
    let Ok(nodes) = c.list("/api/v1/nodes", "").await else { return };
    for n in items(&nodes) {
        let have: BTreeSet<String> = n.pointer(&["status", "volumesAttached"]).and_then(Value::as_array).unwrap_or(&[]).iter().map(|v| str_at(v, &["name"]).to_string()).collect();
        let want = by_node.remove(name(&n)).unwrap_or_default();
        if have == want {
            continue;
        }
        let list: alloc::vec::Vec<Value> = want.iter().map(|v| obj(alloc::vec![("name", Value::from(v.as_str())), ("devicePath", Value::from(""))])).collect();
        let patch = obj(alloc::vec![("status", obj(alloc::vec![("volumesAttached", Value::Array(list))]))]);
        let _ = c.patch(&alloc::format!("/api/v1/nodes/{}/status", name(&n)), MERGE, &patch).await;
    }
}

#[cfg(test)]
async fn tick<C: Client>(c: &C) -> Result<()> {
    tick_at(c, &RefCell::new(BTreeMap::new()), 0, 1_700_000_000).await
}

/// `waiting`: attachment name -> when it was first found unwanted (ms).
async fn tick_at<C: Client>(c: &C, waiting: &RefCell<BTreeMap<String, u64>>, now: u64, wall: u64) -> Result<()> {
    let pvs = items(&c.list("/api/v1/persistentvolumes", "").await?);
    let mut want: BTreeSet<String> = BTreeSet::new();
    let mut create = alloc::vec::Vec::new();
    if pvs.iter().any(|p| p.pointer(&["spec", "csi"]).is_some()) {
        let claims = items(&c.list(&pvcs(None), "").await?);
        let mut drivers: alloc::vec::Vec<(String, bool)> = alloc::vec::Vec::new();
        for pod in items(&c.list(&pods(None), "").await?) {
            let node = str_at(&pod, &["spec", "nodeName"]);
            if node.is_empty() || pod_terminal(&pod) {
                continue;
            }
            for vol in pod.pointer(&["spec", "volumes"]).and_then(Value::as_array).unwrap_or(&[]) {
                let claim = str_at(vol, &["persistentVolumeClaim", "claimName"]);
                let Some(pvc) = find(&claims, namespace(&pod), claim) else { continue };
                if claim.is_empty() || str_at(pvc, &["status", "phase"]) != "Bound" {
                    continue;
                }
                let pv_name = str_at(pvc, &["spec", "volumeName"]);
                let Some(pv) = pvs.iter().find(|p| name(p) == pv_name) else { continue };
                let (driver, handle) = (str_at(pv, &["spec", "csi", "driver"]), str_at(pv, &["spec", "csi", "volumeHandle"]));
                if driver.is_empty() {
                    continue;
                }
                let required = match drivers.iter().find(|(d, _)| d == driver) {
                    Some((_, r)) => *r,
                    None => {
                        let r = match get_opt(c, &alloc::format!("{DRIVERS}/{driver}")).await {
                            Ok(Some(d)) => d.pointer(&["spec", "attachRequired"]).and_then(Value::as_bool).unwrap_or(true),
                            Ok(None) => true,
                            Err(_) => continue,
                        };
                        drivers.push((driver.to_string(), r));
                        r
                    }
                };
                if required && want.insert(va_name(handle, driver, node)) {
                    create.push((va_name(handle, driver, node), driver.to_string(), node.to_string(), pv_name.to_string()));
                }
            }
        }
    }
    let existing = items(&c.list(VAS, "").await?);
    publish_attached(c, &pvs, &existing).await;
    for (n, driver, node, pv) in create {
        if existing.iter().any(|v| name(v) == n) {
            continue;
        }
        let labels = obj(alloc::vec![(LABEL, Value::from("true"))]);
        let source = obj(alloc::vec![("persistentVolumeName", Value::from(pv.as_str()))]);
        let spec = obj(alloc::vec![("attacher", Value::from(driver.as_str())), ("nodeName", Value::from(node.as_str())), ("source", source)]);
        let meta = obj(alloc::vec![("name", Value::from(n.as_str())), ("labels", labels)]);
        let _ = c.create(VAS, &obj(alloc::vec![("metadata", meta), ("spec", spec)])).await; // 409: already there
    }
    for va in existing {
        let ours = str_at(&va, &["metadata", "labels", LABEL]) == "true";
        if want.contains(name(&va)) {
            waiting.borrow_mut().remove(name(&va));
        } else if ours && name(&va).starts_with("csi-") && !deleting(&va) {
            let known = waiting.borrow().get(name(&va)).copied();
            let since = match known {
                Some(t) => t,
                None => {
                    // First time this run: the wall-clock stamp an earlier run (or leader) left on
                    // the attachment says how long it has been unwanted; without one, stamp it now.
                    let t = match str_at(&va, &["metadata", "annotations", SINCE]).parse::<u64>() {
                        Ok(stamp) => now.saturating_sub(wall.saturating_sub(stamp) * 1000),
                        Err(_) => {
                            let p = obj(alloc::vec![("metadata", obj(alloc::vec![("annotations", obj(alloc::vec![(SINCE, Value::String(wall.to_string()))]))]))]);
                            let _ = c.patch(&alloc::format!("{VAS}/{}", name(&va)), MERGE, &p).await;
                            now
                        }
                    };
                    waiting.borrow_mut().insert(name(&va).to_string(), t);
                    t
                }
            };
            if now.saturating_sub(since) < MAX_WAIT_MS && in_use(c, &va).await {
                continue; // still mounted on the node: wait for the kubelet to unmount
            }
            let _ = delete_ok(c, &alloc::format!("{VAS}/{}", name(&va))).await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::*;
    use kr_apiserver::client::InProcess;

    const WALL: u64 = 1_700_000_000;
    const PV: &str = "/api/v1/persistentvolumes";
    const CLAIMS: &str = "/api/v1/namespaces/default/persistentvolumeclaims";

    #[test]
    fn name_vector() {
        // sha256("abc")
        assert_eq!(va_name("a", "b", "c"), "csi-ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(va_name("a", "b", "c"), va_name("a", "b", "c"));
        assert_ne!(va_name("a", "b", "c"), va_name("a", "b", "d"));
    }

    async fn setup(c: &InProcess, pv_spec: &str) {
        c.create(PV, &v(&alloc::format!(r#"{{"metadata":{{"name":"pv1"}},"spec":{{"capacity":{{"storage":"1Gi"}},"accessModes":["ReadWriteOnce"],{pv_spec}}}}}"#))).await.unwrap();
        let claim = v(r#"{"metadata":{"name":"data"},"spec":{"accessModes":["ReadWriteOnce"],"volumeName":"pv1","resources":{"requests":{"storage":"1Gi"}}}}"#);
        c.create(CLAIMS, &claim).await.unwrap();
        put_status(c, &alloc::format!("{CLAIMS}/data"), |_| v(r#"{"phase":"Bound"}"#)).await.unwrap();
    }

    fn pod(node: &str, phase: &str) -> Value {
        let n = if node.is_empty() { String::new() } else { alloc::format!(r#""nodeName":"{node}","#) };
        v(&alloc::format!(r#"{{"metadata":{{"name":"app"}},"spec":{{{n}"containers":[{{"name":"c","image":"x"}}],"volumes":[{{"name":"d","persistentVolumeClaim":{{"claimName":"data"}}}}]}},"status":{{"phase":"{phase}"}}}}"#))
    }

    const CSI: &str = r#""csi":{"driver":"d.io","volumeHandle":"h1"}"#;

    async fn vas(c: &InProcess) -> usize {
        items(&c.list(VAS, "").await.unwrap()).len()
    }

    #[test]
    fn creates_attachment_and_collects_it() {
        scenario(|c| async move {
            setup(&c, CSI).await;
            c.create(PODS, &pod("n1", "Running")).await.unwrap();
            tick(&c).await.unwrap();
            tick(&c).await.unwrap(); // idempotent
            let list = items(&c.list(VAS, "").await.unwrap());
            assert_eq!(list.len(), 1);
            assert_eq!(name(&list[0]), va_name("h1", "d.io", "n1"));
            assert_eq!(str_at(&list[0], &["spec", "attacher"]), "d.io");
            assert_eq!(str_at(&list[0], &["spec", "nodeName"]), "n1");
            assert_eq!(str_at(&list[0], &["spec", "source", "persistentVolumeName"]), "pv1");
            assert_eq!(str_at(&list[0], &["metadata", "labels", LABEL]), "true");
            c.delete(&alloc::format!("{PODS}/app")).await.unwrap();
            wait_until("pod gone", || async { get_opt(&c, &alloc::format!("{PODS}/app")).await.unwrap().is_none() }).await;
            tick(&c).await.unwrap();
            assert_eq!(vas(&c).await, 0);
        });
    }

    #[test]
    fn attach_not_required() {
        scenario(|c| async move {
            setup(&c, CSI).await;
            c.create(DRIVERS, &v(r#"{"metadata":{"name":"d.io"},"spec":{"attachRequired":false}}"#)).await.unwrap();
            c.create(PODS, &pod("n1", "Running")).await.unwrap();
            tick(&c).await.unwrap();
            assert_eq!(vas(&c).await, 0);
        });
    }

    #[test]
    fn hostpath_unscheduled_and_terminal_get_nothing() {
        scenario(|c| async move {
            setup(&c, r#""hostPath":{"path":"/x"}"#).await;
            c.create(PODS, &pod("n1", "Running")).await.unwrap();
            tick(&c).await.unwrap();
            assert_eq!(vas(&c).await, 0);
            c.delete(&alloc::format!("{PODS}/app")).await.unwrap();
            c.delete(&alloc::format!("{PV}/pv1")).await.unwrap();
            wait_until("pv gone", || async { get_opt(&c, &alloc::format!("{PV}/pv1")).await.unwrap().is_none() }).await;
            wait_until("pod gone", || async { get_opt(&c, &alloc::format!("{PODS}/app")).await.unwrap().is_none() }).await;
            c.delete(&alloc::format!("{CLAIMS}/data")).await.unwrap();
            wait_until("claim gone", || async { get_opt(&c, &alloc::format!("{CLAIMS}/data")).await.unwrap().is_none() }).await;
            setup(&c, CSI).await;
            c.create(PODS, &pod("", "Pending")).await.unwrap();
            tick(&c).await.unwrap();
            assert_eq!(vas(&c).await, 0);
            c.delete(&alloc::format!("{PODS}/app")).await.unwrap();
            wait_until("pod gone", || async { get_opt(&c, &alloc::format!("{PODS}/app")).await.unwrap().is_none() }).await;
            c.create(PODS, &pod("n1", "Succeeded")).await.unwrap();
            tick(&c).await.unwrap();
            assert_eq!(vas(&c).await, 0);
        });
    }

    #[test]
    fn detach_waits_for_volumes_in_use() {
        scenario(|c| async move {
            setup(&c, CSI).await;
            c.create("/api/v1/nodes", &v(r#"{"metadata":{"name":"n1"}}"#)).await.unwrap();
            c.create(PODS, &pod("n1", "Running")).await.unwrap();
            tick(&c).await.unwrap();
            put_status(&c, "/api/v1/nodes/n1", |_| v(r#"{"volumesInUse":["kubernetes.io/csi/d.io^h1"]}"#)).await.unwrap();
            c.delete(&alloc::format!("{PODS}/app")).await.unwrap();
            wait_until("pod gone", || async { get_opt(&c, &alloc::format!("{PODS}/app")).await.unwrap().is_none() }).await;
            let waiting = RefCell::new(BTreeMap::new());
            tick_at(&c, &waiting, 1_000, 1_700_000_000).await.unwrap();
            tick_at(&c, &waiting, 1_000 + MAX_WAIT_MS - 1, 1_700_000_000).await.unwrap();
            assert_eq!(vas(&c).await, 1);
            // The node stops reporting it: detach right away.
            put_status(&c, "/api/v1/nodes/n1", |_| v(r#"{"volumesInUse":[]}"#)).await.unwrap();
            tick_at(&c, &waiting, 2_000, 1_700_000_000).await.unwrap();
            assert_eq!(vas(&c).await, 0);
        });
    }

    #[test]
    fn detach_is_forced_after_the_max_wait() {
        scenario(|c| async move {
            setup(&c, CSI).await;
            c.create("/api/v1/nodes", &v(r#"{"metadata":{"name":"n1"}}"#)).await.unwrap();
            c.create(PODS, &pod("n1", "Running")).await.unwrap();
            tick(&c).await.unwrap();
            put_status(&c, "/api/v1/nodes/n1", |_| v(r#"{"volumesInUse":["kubernetes.io/csi/d.io^h1"]}"#)).await.unwrap();
            c.delete(&alloc::format!("{PODS}/app")).await.unwrap();
            wait_until("pod gone", || async { get_opt(&c, &alloc::format!("{PODS}/app")).await.unwrap().is_none() }).await;
            let waiting = RefCell::new(BTreeMap::new());
            tick_at(&c, &waiting, 1_000, 1_700_000_000).await.unwrap();
            assert_eq!(vas(&c).await, 1);
            tick_at(&c, &waiting, 1_000 + MAX_WAIT_MS, 1_700_000_000).await.unwrap();
            assert_eq!(vas(&c).await, 0);
        });
    }

    #[test]
    fn unlabelled_attachment_is_left_alone() {
        scenario(|c| async move {
            let va = v(r#"{"metadata":{"name":"csi-foreign"},"spec":{"attacher":"d.io","nodeName":"n1","source":{"persistentVolumeName":"pv1"}}}"#);
            c.create(VAS, &va).await.unwrap();
            tick(&c).await.unwrap();
            assert_eq!(vas(&c).await, 1);
        });
    }

    #[test]
    fn attached_volumes_are_published_on_the_node() {
        scenario(|c| async move {
            c.create("/api/v1/nodes", &v(r#"{"metadata":{"name":"n1"}}"#)).await.unwrap();
            setup(&c, CSI).await;
            c.create(PODS, &pod("n1", "Running")).await.unwrap();
            tick(&c).await.unwrap();
            let node = |c: &InProcess| {
                let c = c.clone();
                async move { c.get("/api/v1/nodes/n1").await.unwrap() }
            };
            // Created but not attached yet: nothing listed.
            assert!(node(&c).await.pointer(&["status", "volumesAttached"]).and_then(Value::as_array).is_none_or(|a| a.is_empty()));
            let va = alloc::format!("{VAS}/{}", va_name("h1", "d.io", "n1"));
            put_status(&c, &va, |_| v(r#"{"attached":true}"#)).await.unwrap();
            tick(&c).await.unwrap();
            let got = node(&c).await;
            let list = got.pointer(&["status", "volumesAttached"]).and_then(Value::as_array).unwrap().clone();
            assert_eq!(list.len(), 1);
            assert_eq!(str_at(&list[0], &["name"]), "kubernetes.io/csi/d.io^h1");
            // Detached (the attachment is gone): the list empties.
            c.delete(&alloc::format!("{PODS}/app")).await.unwrap();
            wait_until("pod gone", || async { get_opt(&c, &alloc::format!("{PODS}/app")).await.unwrap().is_none() }).await;
            tick(&c).await.unwrap();
            wait_until("attachment gone", || async { get_opt(&c, &va).await.unwrap().is_none() }).await;
            tick(&c).await.unwrap();
            assert!(node(&c).await.pointer(&["status", "volumesAttached"]).and_then(Value::as_array).is_none_or(|a| a.is_empty()));
        });
    }

    #[test]
    fn the_unmount_wait_survives_a_restart() {
        scenario(|c| async move {
            c.create("/api/v1/nodes", &v(r#"{"metadata":{"name":"n1"}}"#)).await.unwrap();
            setup(&c, CSI).await;
            c.create(PODS, &pod("n1", "Running")).await.unwrap();
            tick(&c).await.unwrap();
            put_status(&c, "/api/v1/nodes/n1", |_| v(r#"{"volumesInUse":["kubernetes.io/csi/d.io^h1"]}"#)).await.unwrap();
            c.delete(&alloc::format!("{PODS}/app")).await.unwrap();
            wait_until("pod gone", || async { get_opt(&c, &alloc::format!("{PODS}/app")).await.unwrap().is_none() }).await;
            let va = alloc::format!("{VAS}/{}", va_name("h1", "d.io", "n1"));
            // First controller: finds it unwanted, stamps it, keeps it (still in use).
            tick_at(&c, &RefCell::new(BTreeMap::new()), 10_000_000, WALL).await.unwrap();
            let stamped = c.get(&va).await.unwrap();
            let stamp: u64 = str_at(&stamped, &["metadata", "annotations", SINCE]).parse().expect("a stamp");
            assert_eq!(stamp, WALL);
            assert_eq!(vas(&c).await, 1);
            // A new controller (empty memory) a little later still knows: back-date the stamp past
            // the maximum wait and it detaches at once.
            let old = (stamp - MAX_WAIT_MS / 1000 - 5).to_string();
            let p = obj(alloc::vec![("metadata", obj(alloc::vec![("annotations", obj(alloc::vec![(SINCE, Value::String(old))]))]))]);
            c.patch(&va, MERGE, &p).await.unwrap();
            tick_at(&c, &RefCell::new(BTreeMap::new()), 10_000_000, WALL).await.unwrap();
            wait_until("attachment gone", || async { get_opt(&c, &va).await.unwrap().is_none() }).await;
        });
    }
}
