//! The attach/detach controller: for every non-terminal scheduled pod that uses a PVC bound to a
//! CSI PersistentVolume of a driver with `attachRequired` (the default), a `VolumeAttachment`
//! named [`va_name`] exists; the external-attacher sidecar fulfils it. Attachments this
//! controller created (label [`LABEL`]) that are no longer wanted are deleted (the attacher
//! detaches and drops its finalizer). Level-triggered, every 3 s.

use crate::util::*;
use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use kr_apiserver::client::{Client, Result};
use kr_fmt::json::Value;

pub const LABEL: &str = "kr.io/attach-controller";
const VAS: &str = "/apis/storage.k8s.io/v1/volumeattachments";
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

pub async fn run<C: Client + Clone + 'static>(c: C) {
    loop {
        kr_rt::exec::sleep(3_000).await;
        let _ = tick(&c).await;
    }
}

fn find<'a>(l: &'a [Value], ns: &str, n: &str) -> Option<&'a Value> {
    l.iter().find(|o| name(o) == n && namespace(o) == ns)
}

async fn tick<C: Client>(c: &C) -> Result<()> {
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
        if ours && name(&va).starts_with("csi-") && !deleting(&va) && !want.contains(name(&va)) {
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
    fn unlabelled_attachment_is_left_alone() {
        scenario(|c| async move {
            let va = v(r#"{"metadata":{"name":"csi-foreign"},"spec":{"attacher":"d.io","nodeName":"n1","source":{"persistentVolumeName":"pv1"}}}"#);
            c.create(VAS, &va).await.unwrap();
            tick(&c).await.unwrap();
            assert_eq!(vas(&c).await, 1);
        });
    }
}
