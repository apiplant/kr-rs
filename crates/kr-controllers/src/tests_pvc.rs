//! PVC controller scenarios: dynamic provisioning, reclaim, static binding, pvc-protection and
//! volume node affinity in the scheduler.

use crate::tests::*;
use crate::util::*;
use alloc::string::ToString;
use kr_apiserver::client::{Client, InProcess};
use kr_fmt::json::Value;
use kr_rt::exec::sleep;

const CLAIMS: &str = "/api/v1/namespaces/default/persistentvolumeclaims";
const PVS: &str = "/api/v1/persistentvolumes";
const CLASSES: &str = "/apis/storage.k8s.io/v1/storageclasses";

async fn class(c: &InProcess, reclaim: &str) {
    let sc = v(&alloc::format!(r#"{{"metadata":{{"name":"local-path"}},"provisioner":"kr.io/local-path","reclaimPolicy":"{reclaim}","volumeBindingMode":"WaitForFirstConsumer"}}"#));
    c.create(CLASSES, &sc).await.unwrap();
}

fn claim(name: &str, class: &str) -> Value {
    v(&alloc::format!(r#"{{"metadata":{{"name":"{name}"}},"spec":{{"storageClassName":"{class}","accessModes":["ReadWriteOnce"],"resources":{{"requests":{{"storage":"1Gi"}}}}}}}}"#))
}

fn pod_with(name: &str, claim: &str) -> Value {
    v(&alloc::format!(r#"{{"metadata":{{"name":"{name}"}},"spec":{{"containers":[{{"name":"c","image":"x"}}],"volumes":[{{"name":"d","persistentVolumeClaim":{{"claimName":"{claim}"}}}}]}}}}"#))
}

async fn phase(c: &InProcess, path: &str) -> String {
    match get_opt(c, path).await.unwrap() {
        Some(o) => str_at(&o, &["status", "phase"]).to_string(),
        None => "<gone>".to_string(),
    }
}

use alloc::string::String;

#[test]
fn dynamic_provisioning_and_delete_reclaim() {
    scenario(|c| async move {
        class(&c, "Delete").await;
        c.create("/api/v1/nodes", &node("n1", r#"{"kubernetes.io/hostname":"n1"}"#, "[]", "4")).await.unwrap();
        let pvc = c.create(CLAIMS, &claim("data", "local-path")).await.unwrap();
        let pv_name = alloc::format!("pvc-{}", uid(&pvc));
        // WaitForFirstConsumer: nothing happens without a pod, but the claim is protected.
        sleep(400).await;
        assert!(get_opt(&c, &alloc::format!("{PVS}/{pv_name}")).await.unwrap().is_none());
        let cur = c.get(&alloc::format!("{CLAIMS}/data")).await.unwrap();
        assert_eq!(cur.pointer(&["metadata", "finalizers"]).and_then(Value::as_array).map(|a| a.len()), Some(1));
        assert_eq!(str_at(&cur, &["status", "phase"]), "Pending"); // API default until bound

        c.create(PODS, &pod_with("app", "data")).await.unwrap();
        wait_until("claim bound", || async { phase(&c, &alloc::format!("{CLAIMS}/data")).await == "Bound" }).await;
        wait_until("pv bound", || async { phase(&c, &alloc::format!("{PVS}/{pv_name}")).await == "Bound" }).await;
        let pv = c.get(&alloc::format!("{PVS}/{pv_name}")).await.unwrap();
        let cur = c.get(&alloc::format!("{CLAIMS}/data")).await.unwrap();
        assert_eq!(str_at(&cur, &["spec", "volumeName"]), pv_name);
        assert_eq!(str_at(&cur, &["status", "capacity", "storage"]), "1Gi");
        assert_eq!(str_at(&pv, &["spec", "hostPath", "path"]), alloc::format!("/var/lib/kr/storage/{pv_name}"));
        assert_eq!(str_at(&pv, &["spec", "claimRef", "uid"]), uid(&pvc));
        assert_eq!(str_at(&pv, &["spec", "persistentVolumeReclaimPolicy"]), "Delete");
        assert!(kr_fmt::json::to_string(pv.pointer(&["spec", "nodeAffinity"]).unwrap()).contains(r#""values":["n1"]"#));

        // Deleting the claim while the pod uses it waits (pvc-protection); then the PV goes.
        c.delete(&alloc::format!("{CLAIMS}/data")).await.unwrap();
        sleep(300).await;
        assert!(get_opt(&c, &alloc::format!("{CLAIMS}/data")).await.unwrap().is_some());
        c.delete(&alloc::format!("{PODS}/app?gracePeriodSeconds=0")).await.unwrap();
        wait_until("claim gone", || async { get_opt(&c, &alloc::format!("{CLAIMS}/data")).await.unwrap().is_none() }).await;
        wait_until("pv deleted", || async { get_opt(&c, &alloc::format!("{PVS}/{pv_name}")).await.unwrap().is_none() }).await;
    });
}

#[test]
fn retain_releases_the_volume() {
    scenario(|c| async move {
        class(&c, "Retain").await;
        c.create("/api/v1/nodes", &node("n1", r#"{"kubernetes.io/hostname":"n1"}"#, "[]", "4")).await.unwrap();
        let pvc = c.create(CLAIMS, &claim("data", "local-path")).await.unwrap();
        let pv_name = alloc::format!("pvc-{}", uid(&pvc));
        c.create(PODS, &pod_with("app", "data")).await.unwrap();
        wait_until("bound", || async { phase(&c, &alloc::format!("{PVS}/{pv_name}")).await == "Bound" }).await;
        c.delete(&alloc::format!("{PODS}/app?gracePeriodSeconds=0")).await.unwrap();
        c.delete(&alloc::format!("{CLAIMS}/data")).await.unwrap();
        wait_until("released", || async { phase(&c, &alloc::format!("{PVS}/{pv_name}")).await == "Released" }).await;
    });
}

#[test]
fn static_binding_picks_the_smallest_fit() {
    scenario(|c| async move {
        let pv = |n: &str, size: &str, class: &str| {
            v(&alloc::format!(r#"{{"metadata":{{"name":"{n}"}},"spec":{{"capacity":{{"storage":"{size}"}},"accessModes":["ReadWriteOnce","ReadOnlyMany"],"storageClassName":"{class}","hostPath":{{"path":"/data/{n}"}}}}}}"#))
        };
        c.create(PVS, &pv("big", "10Gi", "manual")).await.unwrap();
        c.create(PVS, &pv("small", "2Gi", "manual")).await.unwrap();
        c.create(PVS, &pv("tiny", "500Mi", "manual")).await.unwrap();
        c.create(PVS, &pv("other", "2Gi", "fast")).await.unwrap();
        wait_until("available", || async { phase(&c, &alloc::format!("{PVS}/small")).await == "Available" }).await;
        c.create(CLAIMS, &claim("c1", "manual")).await.unwrap();
        wait_until("c1 bound", || async { phase(&c, &alloc::format!("{CLAIMS}/c1")).await == "Bound" }).await;
        let c1 = c.get(&alloc::format!("{CLAIMS}/c1")).await.unwrap();
        assert_eq!(str_at(&c1, &["spec", "volumeName"]), "small");
        assert_eq!(str_at(&c1, &["status", "capacity", "storage"]), "2Gi");
        assert_eq!(phase(&c, &alloc::format!("{PVS}/small")).await, "Bound");
        // The next claim cannot reuse it.
        c.create(CLAIMS, &claim("c2", "manual")).await.unwrap();
        wait_until("c2 bound", || async { phase(&c, &alloc::format!("{CLAIMS}/c2")).await == "Bound" }).await;
        assert_eq!(str_at(&c.get(&alloc::format!("{CLAIMS}/c2")).await.unwrap(), &["spec", "volumeName"]), "big");
        // Too large for anything left: stays pending.
        let huge = v(r#"{"metadata":{"name":"c3"},"spec":{"storageClassName":"manual","accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"100Gi"}}}}"#);
        c.create(CLAIMS, &huge).await.unwrap();
        sleep(400).await;
        assert_eq!(phase(&c, &alloc::format!("{CLAIMS}/c3")).await, "Pending");
        // Deleting a claim releases a Retain-less static PV (default policy Retain).
        c.delete(&alloc::format!("{CLAIMS}/c1")).await.unwrap();
        wait_until("released", || async { phase(&c, &alloc::format!("{PVS}/small")).await == "Released" }).await;
    });
}

#[test]
fn pod_follows_its_volume_to_the_node() {
    scenario(|c| async move {
        class(&c, "Delete").await;
        c.create("/api/v1/nodes", &node("n1", r#"{"kubernetes.io/hostname":"n1"}"#, "[]", "4")).await.unwrap();
        c.create(CLAIMS, &claim("data", "local-path")).await.unwrap();
        c.create(PODS, &pod_with("first", "data")).await.unwrap();
        wait_until("bound", || async { phase(&c, &alloc::format!("{CLAIMS}/data")).await == "Bound" }).await;
        // A second node appears (emptier, so it would win on score); the pod must still use n1.
        c.create("/api/v1/nodes", &node("n0", r#"{"kubernetes.io/hostname":"n0"}"#, "[]", "64")).await.unwrap();
        c.create(PODS, &pod_with("second", "data")).await.unwrap();
        wait_until("scheduled", || async { !str_at(&c.get(&alloc::format!("{PODS}/second")).await.unwrap(), &["spec", "nodeName"]).is_empty() }).await;
        assert_eq!(str_at(&c.get(&alloc::format!("{PODS}/second")).await.unwrap(), &["spec", "nodeName"]), "n1");
    });
}

#[test]
fn pv_protection_finalizer_blocks_delete_while_bound() {
    scenario(|c| async move {
        class(&c, "Retain").await;
        c.create("/api/v1/nodes", &node("n1", r#"{"kubernetes.io/hostname":"n1"}"#, "[]", "4")).await.unwrap();
        let pvc = c.create(CLAIMS, &claim("data", "local-path")).await.unwrap();
        let pv_name = alloc::format!("pvc-{}", uid(&pvc));
        c.create(PODS, &pod_with("app", "data")).await.unwrap();
        wait_until("pv bound", || async { phase(&c, &alloc::format!("{PVS}/{pv_name}")).await == "Bound" }).await;
        let pv = c.get(&alloc::format!("{PVS}/{pv_name}")).await.unwrap();
        assert!(kr_fmt::json::to_string(pv.pointer(&["metadata", "finalizers"]).unwrap()).contains("kubernetes.io/pv-protection"));
        // Deleting a bound PV waits; once the claim is gone it is released.
        c.delete(&alloc::format!("{PVS}/{pv_name}")).await.unwrap();
        sleep(300).await;
        assert!(get_opt(&c, &alloc::format!("{PVS}/{pv_name}")).await.unwrap().is_some());
        c.delete(&alloc::format!("{PODS}/app?gracePeriodSeconds=0")).await.unwrap();
        c.delete(&alloc::format!("{CLAIMS}/data")).await.unwrap();
        wait_until("pv gone", || async { get_opt(&c, &alloc::format!("{PVS}/{pv_name}")).await.unwrap().is_none() }).await;
    });
}

#[test]
fn immediate_or_missing_claim_blocks_scheduling() {
    scenario(|c| async move {
        c.create("/api/v1/nodes", &node("n1", "{}", "[]", "4")).await.unwrap();
        // Missing claim.
        c.create(PODS, &pod_with("app", "later")).await.unwrap();
        wait_until("not found", || async { sched_msg(&c.get(&alloc::format!("{PODS}/app")).await.unwrap()).contains("persistentvolumeclaim \"later\" not found") }).await;
        // Unbound claim of a class with no provisioner and Immediate binding.
        let sc = v(r#"{"metadata":{"name":"slow"},"provisioner":"example.com/none","volumeBindingMode":"Immediate"}"#);
        c.create(CLASSES, &sc).await.unwrap();
        c.create(CLAIMS, &claim("later", "slow")).await.unwrap();
        wait_until("unbound immediate", || async { sched_msg(&c.get(&alloc::format!("{PODS}/app")).await.unwrap()).contains("0/1 nodes are available: pod has unbound immediate PersistentVolumeClaims.") }).await;
        // A matching PV binds the claim and the pod schedules.
        let pv = v(r#"{"metadata":{"name":"pv1"},"spec":{"storageClassName":"slow","accessModes":["ReadWriteOnce"],"capacity":{"storage":"1Gi"},"hostPath":{"path":"/x"}}}"#);
        c.create(PVS, &pv).await.unwrap();
        wait_until("scheduled", || async { str_at(&c.get(&alloc::format!("{PODS}/app")).await.unwrap(), &["spec", "nodeName"]) == "n1" }).await;
    });
}

fn sched_msg(p: &Value) -> String {
    p.pointer(&["status", "conditions"]).and_then(Value::as_array).and_then(|a| a.iter().find(|k| str_at(k, &["type"]) == "PodScheduled")).map(|k| str_at(k, &["message"]).to_string()).unwrap_or_default()
}
