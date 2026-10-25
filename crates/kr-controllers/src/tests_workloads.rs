//! End-to-end tests of the StatefulSet, DaemonSet, Job, CronJob and Endpoints controllers.
//! They share the harness of `tests.rs`: all controllers run on an in-process API server, the
//! fake kubelet starts bound pods (Running, Ready, with a pod IP), can hold pods back, finish
//! them as Succeeded/Failed (`FINISH` and the pod annotation `test/outcome`) and delay the end
//! of graceful deletions; `CLOCK` is the fake wall clock of the controllers and the server.

use crate::tests::*;
use crate::util::*;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use kr_apiserver::client::{Client, InProcess};
use kr_fmt::json::Value;
use kr_rt::exec::sleep;

const STS: &str = "/apis/apps/v1/namespaces/default/statefulsets";
const DS: &str = "/apis/apps/v1/namespaces/default/daemonsets";
const REVS: &str = "/apis/apps/v1/namespaces/default/controllerrevisions";
const JOBS: &str = "/apis/batch/v1/namespaces/default/jobs";
const CRONJOBS: &str = "/apis/batch/v1/namespaces/default/cronjobs";
const PVCS: &str = "/api/v1/namespaces/default/persistentvolumeclaims";
const SVCS: &str = "/api/v1/namespaces/default/services";
const EPS: &str = "/api/v1/namespaces/default/endpoints";
const SLICES: &str = "/apis/discovery.k8s.io/v1/namespaces/default/endpointslices";
const NODES: &str = "/api/v1/nodes";

async fn all_pods(c: &InProcess) -> Vec<Value> {
    let mut p = items(&c.list(PODS, "").await.unwrap());
    p.sort_by(|a, b| name(a).cmp(name(b)));
    p
}

async fn live_names(c: &InProcess) -> Vec<String> {
    live_pods(c).await.iter().map(|p| name(p).to_string()).collect::<Vec<_>>().tap_sort()
}

trait TapSort {
    fn tap_sort(self) -> Self;
}
impl TapSort for Vec<String> {
    fn tap_sort(mut self) -> Self {
        self.sort();
        self
    }
}

async fn get(c: &InProcess, path: &str) -> Value {
    c.get(path).await.unwrap()
}

async fn pod(c: &InProcess, n: &str) -> Option<Value> {
    c.get(&alloc::format!("{PODS}/{n}")).await.ok()
}

async fn pod_is_deleting(c: &InProcess, n: &str) -> bool {
    pod(c, n).await.is_some_and(|p| deleting(&p))
}

async fn merge(c: &InProcess, path: &str, patch: &str) {
    c.patch(path, MERGE, &v(patch)).await.unwrap();
}

fn images(p: &Value) -> String {
    p.pointer(&["spec", "containers"]).and_then(Value::as_array).map(|a| str_at(&a[0], &["image"]).to_string()).unwrap_or_default()
}

// ====================================================================================
// StatefulSet
// ====================================================================================

fn sts(replicas: u32, image: &str, extra: &str) -> Value {
    v(&alloc::format!(
        r#"{{"metadata":{{"name":"web"}},"spec":{{"replicas":{replicas},"serviceName":"web"{extra},"selector":{{"matchLabels":{{"app":"web"}}}},
        "template":{{"metadata":{{"labels":{{"app":"web"}}}},"spec":{{"containers":[{{"name":"c","image":"{image}"}}]}}}},
        "volumeClaimTemplates":[{{"metadata":{{"name":"data"}},"spec":{{"storageClassName":"wffc","accessModes":["ReadWriteOnce"],"resources":{{"requests":{{"storage":"1Gi"}}}}}}}}]}}}}"#
    ))
}

/// Claims of the StatefulSet tests use a class that binds on first consumer, so pods schedule.
async fn wffc_class(c: &InProcess) {
    let sc = v(r#"{"metadata":{"name":"wffc"},"provisioner":"example.com/none","volumeBindingMode":"WaitForFirstConsumer"}"#);
    c.create("/apis/storage.k8s.io/v1/storageclasses", &sc).await.unwrap();
}

async fn set_sts_image(c: &InProcess, image: &str) {
    merge(c, &alloc::format!("{STS}/web"), &alloc::format!(r#"{{"spec":{{"template":{{"spec":{{"containers":[{{"name":"c","image":"{image}"}}]}}}}}}}}"#)).await;
}

async fn sts_status(c: &InProcess, f: &str) -> i64 {
    int_at(&get(c, &alloc::format!("{STS}/web")).await, &["status", f], -1)
}

async fn all_ready(c: &InProcess, names: &[&str]) -> bool {
    let live = live_pods(c).await;
    live.len() == names.len() && names.iter().all(|n| live.iter().any(|p| name(p) == *n && running_ready(p)))
}

#[test]
fn statefulset_ordered_creation_identity_and_scale_down() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        hold(&["web-0"]);
        wffc_class(&c).await;
        let created = c.create(STS, &sts(3, "i:1", "")).await.unwrap();
        wait_until("web-0 exists", || async { pod(&c, "web-0").await.is_some() }).await;
        sleep(250).await;
        assert_eq!(live_names(&c).await, ["web-0"], "ordinal 1 waits for web-0 to be Running and Ready");

        release(&["web-0"]);
        wait_until("3 ready pods", || all_ready(&c, &["web-0", "web-1", "web-2"])).await;

        // Identity.
        let rev = str_at(&get(&c, &alloc::format!("{STS}/web")).await, &["status", "updateRevision"]).to_string();
        assert!(rev.starts_with("web-") && rev.len() > 5, "{rev}");
        for i in 0..3 {
            let n = alloc::format!("web-{i}");
            let p = pod(&c, &n).await.unwrap();
            assert_eq!(str_at(&p, &["metadata", "labels", "statefulset.kubernetes.io/pod-name"]), n);
            assert_eq!(str_at(&p, &["metadata", "labels", "controller-revision-hash"]), rev);
            assert_eq!(str_at(&p, &["metadata", "labels", "app"]), "web");
            assert_eq!(str_at(&p, &["spec", "hostname"]), n);
            assert_eq!(str_at(&p, &["spec", "subdomain"]), "web");
            let r = controller_ref(&p).unwrap();
            assert_eq!((str_at(r, &["kind"]), str_at(r, &["uid"])), ("StatefulSet", uid(&created)));
            let vol = &p.pointer(&["spec", "volumes"]).and_then(Value::as_array).unwrap()[0];
            assert_eq!((str_at(vol, &["name"]), str_at(vol, &["persistentVolumeClaim", "claimName"])), ("data", alloc::format!("data-web-{i}").as_str()));
            assert!(c.get(&alloc::format!("{PVCS}/data-web-{i}")).await.is_ok(), "PVC data-web-{i}");
        }
        wait_until("status", || async {
            let s = get(&c, &alloc::format!("{STS}/web")).await;
            ["replicas", "readyReplicas", "currentReplicas", "updatedReplicas", "availableReplicas"].iter().all(|f| int_at(&s, &["status", f], -1) == 3)
                && str_at(&s, &["status", "currentRevision"]) == rev
                && int_at(&s, &["status", "observedGeneration"], -1) == 1
        })
        .await;
        let revs = items(&c.list(REVS, "").await.unwrap());
        assert_eq!(revs.len(), 1);
        assert_eq!((name(&revs[0]), int_at(&revs[0], &["revision"], 0)), (rev.as_str(), 1));
        assert_eq!(str_at(controller_ref(&revs[0]).unwrap(), &["kind"]), "StatefulSet");

        // Scale down from the top, one pod at a time.
        hold_delete(&["web-2", "web-1"]);
        merge(&c, &alloc::format!("{STS}/web/scale"), r#"{"spec":{"replicas":1}}"#).await;
        wait_until("web-2 terminating", || pod_is_deleting(&c, "web-2")).await;
        sleep(250).await;
        assert!(!pod_is_deleting(&c, "web-1").await, "web-1 must wait until web-2 is gone");
        release_delete(&["web-2"]);
        wait_until("web-1 terminating", || pod_is_deleting(&c, "web-1")).await;
        assert!(!pod_is_deleting(&c, "web-0").await);
        release_delete(&["web-1"]);
        wait_until("only web-0 left", || async { live_names(&c).await == ["web-0"] && all_pods(&c).await.len() == 1 }).await;
        wait_until("status replicas 1", || async { sts_status(&c, "replicas").await == 1 && sts_status(&c, "readyReplicas").await == 1 }).await;
        assert_eq!(items(&c.list(PVCS, "").await.unwrap()).len(), 3, "PVCs are retained");
        assert_eq!(items(&c.list(REVS, "").await.unwrap()).len(), 1);

        // Deleting the set collects pods and revisions.
        c.delete(&alloc::format!("{STS}/web")).await.unwrap();
        wait_until("gc", || async { all_pods(&c).await.is_empty() && items(&c.list(REVS, "").await.unwrap()).is_empty() }).await;
    });
}

#[test]
fn statefulset_parallel_does_not_wait() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        hold(&["web-0"]);
        wffc_class(&c).await;
        c.create(STS, &sts(3, "i:1", r#","podManagementPolicy":"Parallel""#)).await.unwrap();
        wait_until("all pods created at once", || async { all_pods(&c).await.len() == 3 }).await;
        wait_until("2 ready", || async { sts_status(&c, "readyReplicas").await == 2 && sts_status(&c, "replicas").await == 3 }).await;
        // A failed pod is replaced.
        release(&["web-0"]);
        wait_until("3 ready", || all_ready(&c, &["web-0", "web-1", "web-2"])).await;
    });
}

#[test]
fn statefulset_rolling_update_with_partition() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        wffc_class(&c).await;
        c.create(STS, &sts(3, "i:1", r#","updateStrategy":{"type":"RollingUpdate","rollingUpdate":{"partition":2}}"#)).await.unwrap();
        wait_until("3 ready", || all_ready(&c, &["web-0", "web-1", "web-2"])).await;
        wait_until("rev1 current", || async {
            let s = get(&c, &alloc::format!("{STS}/web")).await;
            !str_at(&s, &["status", "currentRevision"]).is_empty() && str_at(&s, &["status", "currentRevision"]) == str_at(&s, &["status", "updateRevision"]) && int_at(&s, &["status", "readyReplicas"], 0) == 3
        })
        .await;
        let rev1 = str_at(&get(&c, &alloc::format!("{STS}/web")).await, &["status", "updateRevision"]).to_string();

        set_sts_image(&c, "i:2").await;
        wait_until("web-2 updated", || async { pod(&c, "web-2").await.is_some_and(|p| images(&p) == "i:2" && running_ready(&p) && !deleting(&p)) }).await;
        sleep(300).await;
        for n in ["web-0", "web-1"] {
            let p = pod(&c, n).await.unwrap();
            assert_eq!((images(&p), str_at(&p, &["metadata", "labels", "controller-revision-hash"])), ("i:1".to_string(), rev1.as_str()), "{n} is below the partition");
        }
        let s = get(&c, &alloc::format!("{STS}/web")).await;
        let rev2 = str_at(&s, &["status", "updateRevision"]).to_string();
        assert_ne!(rev1, rev2);
        assert_eq!(str_at(&pod(&c, "web-2").await.unwrap(), &["metadata", "labels", "controller-revision-hash"]), rev2);
        wait_until("partial status", || async {
            let s = get(&c, &alloc::format!("{STS}/web")).await;
            (int_at(&s, &["status", "updatedReplicas"], -1), int_at(&s, &["status", "currentReplicas"], -1), int_at(&s, &["status", "readyReplicas"], -1)) == (1, 2, 3) && str_at(&s, &["status", "currentRevision"]) == rev1
        })
        .await;
        assert_eq!(items(&c.list(REVS, "").await.unwrap()).len(), 2);

        // Lower the partition one step at a time.
        merge(&c, &alloc::format!("{STS}/web"), r#"{"spec":{"updateStrategy":{"rollingUpdate":{"partition":1}}}}"#).await;
        wait_until("web-1 updated", || async { pod(&c, "web-1").await.is_some_and(|p| images(&p) == "i:2" && running_ready(&p) && !deleting(&p)) }).await;
        sleep(300).await;
        assert_eq!(images(&pod(&c, "web-0").await.unwrap()), "i:1");
        merge(&c, &alloc::format!("{STS}/web"), r#"{"spec":{"updateStrategy":{"rollingUpdate":{"partition":0}}}}"#).await;
        wait_until("all updated", || async {
            let s = get(&c, &alloc::format!("{STS}/web")).await;
            all_ready(&c, &["web-0", "web-1", "web-2"]).await
                && live_pods(&c).await.iter().all(|p| images(p) == "i:2")
                && str_at(&s, &["status", "currentRevision"]) == rev2
                && (int_at(&s, &["status", "currentReplicas"], -1), int_at(&s, &["status", "updatedReplicas"], -1)) == (3, 3)
        })
        .await;
    });
}

#[test]
fn statefulset_rolling_update_deletes_highest_ordinal_first() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        wffc_class(&c).await;
        c.create(STS, &sts(3, "i:1", "")).await.unwrap();
        wait_until("3 ready", || all_ready(&c, &["web-0", "web-1", "web-2"])).await;
        hold_delete(&["web-2"]);
        set_sts_image(&c, "i:2").await;
        wait_until("web-2 terminating", || pod_is_deleting(&c, "web-2")).await;
        sleep(300).await;
        assert!(!pod_is_deleting(&c, "web-1").await && !pod_is_deleting(&c, "web-0").await, "one pod at a time, highest first");
        release_delete(&["web-2"]);
        wait_until("web-1 replaced after web-2", || async {
            let (p2, p1) = (pod(&c, "web-2").await, pod(&c, "web-1").await);
            p2.is_some_and(|p| images(&p) == "i:2" && running_ready(&p)) && p1.is_some_and(|p| deleting(&p) || images(&p) == "i:2")
        })
        .await;
        wait_until("all updated", || async { all_ready(&c, &["web-0", "web-1", "web-2"]).await && live_pods(&c).await.iter().all(|p| images(p) == "i:2") }).await;
    });
}

#[test]
fn statefulset_on_delete_only_replaces_deleted_pods() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        wffc_class(&c).await;
        c.create(STS, &sts(3, "i:1", r#","updateStrategy":{"type":"OnDelete"}"#)).await.unwrap();
        wait_until("3 ready", || all_ready(&c, &["web-0", "web-1", "web-2"])).await;
        set_sts_image(&c, "i:2").await;
        sleep(400).await;
        assert!(live_pods(&c).await.iter().all(|p| images(p) == "i:1"), "OnDelete never replaces on its own");
        let old_rev = str_at(&get(&c, &alloc::format!("{STS}/web")).await, &["status", "currentRevision"]).to_string();
        c.delete(&alloc::format!("{PODS}/web-1")).await.unwrap();
        wait_until("web-1 back on the new template", || async { pod(&c, "web-1").await.is_some_and(|p| images(&p) == "i:2" && running_ready(&p) && !deleting(&p)) }).await;
        assert_eq!(images(&pod(&c, "web-0").await.unwrap()), "i:1");
        assert_eq!(images(&pod(&c, "web-2").await.unwrap()), "i:1");
        let s = get(&c, &alloc::format!("{STS}/web")).await;
        assert_eq!((str_at(&s, &["status", "currentRevision"]), int_at(&s, &["status", "updatedReplicas"], -1)), (old_rev.as_str(), 1));
    });
}

// ====================================================================================
// DaemonSet
// ====================================================================================

fn ds(image: &str, spec_extra: &str, strategy: &str) -> Value {
    v(&alloc::format!(
        r#"{{"metadata":{{"name":"agent"}},"spec":{{"selector":{{"matchLabels":{{"app":"agent"}}}}{strategy},
        "template":{{"metadata":{{"labels":{{"app":"agent"}}}},"spec":{{"containers":[{{"name":"c","image":"{image}"}}]{spec_extra}}}}}}}}}"#
    ))
}

async fn ds_nodes(c: &InProcess) -> Vec<String> {
    let mut n: Vec<String> = live_pods(c).await.iter().map(|p| str_at(p, &["spec", "nodeName"]).to_string()).collect();
    n.sort();
    n
}

async fn ds_status(c: &InProcess, f: &str) -> i64 {
    int_at(&get(c, &alloc::format!("{DS}/agent")).await, &["status", f], -1)
}

const GPU_TAINT: &str = r#"[{"key":"dedicated","value":"gpu","effect":"NoSchedule"}]"#;

#[test]
fn daemonset_covers_nodes_and_respects_taints() {
    scenario(|c| async move {
        for n in ["n1", "n2"] {
            c.create(NODES, &node(n, "{}", "[]", "4")).await.unwrap();
        }
        c.create(NODES, &node("n3", "{}", GPU_TAINT, "4")).await.unwrap();
        let created = c.create(DS, &ds("a:1", "", "")).await.unwrap();

        wait_until("pods on the 2 untainted nodes", || async { ds_nodes(&c).await == ["n1", "n2"] }).await;
        sleep(250).await;
        assert_eq!(ds_nodes(&c).await, ["n1", "n2"], "the tainted node stays empty");
        wait_until("status", || async {
            let s = get(&c, &alloc::format!("{DS}/agent")).await;
            ["desiredNumberScheduled", "currentNumberScheduled", "numberReady", "numberAvailable", "updatedNumberScheduled"].iter().all(|f| int_at(&s, &["status", f], -1) == 2)
                && int_at(&s, &["status", "numberMisscheduled"], -1) == 0
                && int_at(&s, &["status", "observedGeneration"], -1) == 1
        })
        .await;
        // Bound at creation, owned, labelled, with the standard tolerations.
        let revs = items(&c.list(REVS, "").await.unwrap());
        assert_eq!(revs.len(), 1);
        for p in live_pods(&c).await {
            let r = controller_ref(&p).unwrap();
            assert_eq!((str_at(r, &["kind"]), str_at(r, &["uid"])), ("DaemonSet", uid(&created)));
            assert_eq!(str_at(&p, &["metadata", "labels", "controller-revision-hash"]), name(&revs[0]));
            assert_eq!(str_at(&p, &["metadata", "labels", "pod-template-generation"]), "1");
            let tols = p.pointer(&["spec", "tolerations"]).and_then(Value::as_array).unwrap();
            for (k, e) in [
                ("node.kubernetes.io/not-ready", "NoExecute"),
                ("node.kubernetes.io/unreachable", "NoExecute"),
                ("node.kubernetes.io/disk-pressure", "NoSchedule"),
                ("node.kubernetes.io/memory-pressure", "NoSchedule"),
                ("node.kubernetes.io/pid-pressure", "NoSchedule"),
                ("node.kubernetes.io/unschedulable", "NoSchedule"),
            ] {
                assert!(tols.iter().any(|t| str_at(t, &["key"]) == k && str_at(t, &["effect"]) == e && str_at(t, &["operator"]) == "Exists"), "toleration {k}");
            }
        }

        // Tolerating the taint adds the third node (and rolls the others to the new template).
        merge(&c, &alloc::format!("{DS}/agent"), r#"{"spec":{"template":{"spec":{"tolerations":[{"key":"dedicated","operator":"Exists"}]}}}}"#).await;
        wait_until("3 nodes covered by the new revision", || async {
            let s = get(&c, &alloc::format!("{DS}/agent")).await;
            ds_nodes(&c).await == ["n1", "n2", "n3"]
                && ["desiredNumberScheduled", "currentNumberScheduled", "numberReady", "updatedNumberScheduled"].iter().all(|f| int_at(&s, &["status", f], -1) == 3)
        })
        .await;

        // A deleted pod comes back; a removed node loses its pod; a new node gets one; a
        // cordoned node keeps its pod.
        let victim = live_pods(&c).await.into_iter().find(|p| str_at(p, &["spec", "nodeName"]) == "n1").unwrap();
        c.delete(&alloc::format!("{PODS}/{}", name(&victim))).await.unwrap();
        wait_until("n1 pod recreated", || async { ds_nodes(&c).await == ["n1", "n2", "n3"] && live_pods(&c).await.iter().all(|p| name(p) != name(&victim)) }).await;
        c.delete(&alloc::format!("{NODES}/n2")).await.unwrap();
        wait_until("n2 pod removed", || async { ds_nodes(&c).await == ["n1", "n3"] }).await;
        c.create(NODES, &node("n4", "{}", "[]", "4")).await.unwrap();
        wait_until("n4 pod", || async { ds_nodes(&c).await == ["n1", "n3", "n4"] && ds_status(&c, "desiredNumberScheduled").await == 3 }).await;
        merge(&c, &alloc::format!("{NODES}/n1"), r#"{"spec":{"unschedulable":true}}"#).await;
        sleep(300).await;
        assert_eq!(ds_nodes(&c).await, ["n1", "n3", "n4"]);
    });
}

#[test]
fn daemonset_node_affinity() {
    let aff = r#","affinity":{"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[
        {"matchExpressions":[{"key":"disk","operator":"In","values":["ssd","hdd"]},{"key":"zone","operator":"NotIn","values":["b"]}]},
        {"matchExpressions":[{"key":"disk","operator":"DoesNotExist"}]}]}}}"#;
    scenario(move |c| async move {
        c.create(NODES, &node("n1", r#"{"disk":"ssd","zone":"a"}"#, "[]", "4")).await.unwrap();
        c.create(NODES, &node("n2", r#"{"disk":"hdd","zone":"b"}"#, "[]", "4")).await.unwrap();
        c.create(NODES, &node("n3", r#"{"zone":"c"}"#, "[]", "4")).await.unwrap();
        c.create(DS, &ds("a:1", aff, "")).await.unwrap();
        wait_until("n1 and n3", || async { ds_nodes(&c).await == ["n1", "n3"] && ds_status(&c, "numberReady").await == 2 }).await;
        assert_eq!(ds_status(&c, "desiredNumberScheduled").await, 2);
        // n3 gets a disk label: no term matches any more, its pod goes away.
        merge(&c, &alloc::format!("{NODES}/n3"), r#"{"metadata":{"labels":{"disk":"nvme"}}}"#).await;
        wait_until("n3 pod removed", || async { ds_nodes(&c).await == ["n1"] && ds_status(&c, "desiredNumberScheduled").await == 1 }).await;
    });
}

#[test]
fn node_eligibility_table() {
    let n = |labels: &str, taints: &str| node("x", labels, taints, "1");
    let spec = |s: &str| v(&alloc::format!("{{{s}}}"));
    let term = |exprs: &str| alloc::format!(r#""affinity":{{"nodeAffinity":{{"requiredDuringSchedulingIgnoredDuringExecution":{{"nodeSelectorTerms":[{{"matchExpressions":[{exprs}]}}]}}}}}}"#);
    let cases: Vec<(String, Value, bool)> = alloc::vec![
        ("".into(), n("{}", "[]"), true),
        (r#""nodeSelector":{"a":"b"}"#.into(), n(r#"{"a":"b"}"#, "[]"), true),
        (r#""nodeSelector":{"a":"b"}"#.into(), n(r#"{"a":"c"}"#, "[]"), false),
        (term(r#"{"key":"k","operator":"In","values":["1","2"]}"#), n(r#"{"k":"2"}"#, "[]"), true),
        (term(r#"{"key":"k","operator":"In","values":["1","2"]}"#), n("{}", "[]"), false),
        (term(r#"{"key":"k","operator":"NotIn","values":["1"]}"#), n("{}", "[]"), true),
        (term(r#"{"key":"k","operator":"NotIn","values":["1"]}"#), n(r#"{"k":"1"}"#, "[]"), false),
        (term(r#"{"key":"k","operator":"Exists"}"#), n(r#"{"k":""}"#, "[]"), true),
        (term(r#"{"key":"k","operator":"Exists"}"#), n("{}", "[]"), false),
        (term(r#"{"key":"k","operator":"DoesNotExist"}"#), n("{}", "[]"), true),
        (term(r#"{"key":"k","operator":"DoesNotExist"}"#), n(r#"{"k":"v"}"#, "[]"), false),
        (term(r#"{"key":"k","operator":"Gt","values":["3"]}"#), n(r#"{"k":"5"}"#, "[]"), true),
        (term(r#"{"key":"k","operator":"Lt","values":["3"]}"#), n(r#"{"k":"5"}"#, "[]"), false),
        // Expressions of one term are ANDed.
        (term(r#"{"key":"a","operator":"Exists"},{"key":"b","operator":"Exists"}"#), n(r#"{"a":"1"}"#, "[]"), false),
        // matchFields on the node name.
        (r#""affinity":{"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{"matchFields":[{"key":"metadata.name","operator":"In","values":["x"]}]}]}}}"#.into(), n("{}", "[]"), true),
        // Taints.
        ("".into(), n("{}", GPU_TAINT), false),
        (r#""tolerations":[{"key":"dedicated","operator":"Equal","value":"gpu","effect":"NoSchedule"}]"#.into(), n("{}", GPU_TAINT), true),
        (r#""tolerations":[{"operator":"Exists"}]"#.into(), n("{}", GPU_TAINT), true),
        ("".into(), n("{}", r#"[{"key":"node.kubernetes.io/not-ready","effect":"NoExecute"}]"#), true),
        ("".into(), n("{}", r#"[{"key":"node.kubernetes.io/unreachable","effect":"NoExecute"}]"#), true),
        ("".into(), n("{}", r#"[{"key":"node.kubernetes.io/disk-pressure","effect":"NoSchedule"}]"#), true),
        ("".into(), n("{}", r#"[{"key":"node.kubernetes.io/network-unavailable","effect":"NoSchedule"}]"#), false),
        (r#""hostNetwork":true"#.into(), n("{}", r#"[{"key":"node.kubernetes.io/network-unavailable","effect":"NoSchedule"}]"#), true),
    ];
    for (s, node, want) in &cases {
        assert_eq!(crate::daemonset::node_eligible(&spec(s), node), *want, "spec {{{s}}} on {}", kr_fmt::json::to_string(node));
    }
}

fn ds_rolling(max: &str, expect_old: usize) {
    let strategy = if max.is_empty() { String::new() } else { alloc::format!(r#","updateStrategy":{{"type":"RollingUpdate","rollingUpdate":{{"maxUnavailable":{max}}}}}"#) };
    let max = max.to_string();
    scenario(move |c| async move {
        for n in ["n1", "n2", "n3", "n4"] {
            c.create(NODES, &node(n, "{}", "[]", "4")).await.unwrap();
        }
        c.create(DS, &ds("a:1", "", &strategy)).await.unwrap();
        wait_until("4 ready", || async { ds_status(&c, "numberReady").await == 4 }).await;
        // New pods never become ready, so the budget stays used up.
        HOLD_ALL.store(true, Ordering::SeqCst);
        merge(&c, &alloc::format!("{DS}/agent"), r#"{"spec":{"template":{"spec":{"containers":[{"name":"c","image":"a:2"}]}}}}"#).await;
        wait_until("budget used", || async {
            let live = live_pods(&c).await;
            live.iter().filter(|p| images(p) == "a:2").count() == 4 - expect_old && live.iter().filter(|p| images(p) == "a:1").count() == expect_old
        })
        .await;
        sleep(400).await;
        let live = live_pods(&c).await;
        assert_eq!(live.iter().filter(|p| images(p) == "a:1").count(), expect_old, "maxUnavailable={max} limits how many old pods are taken down");
        assert_eq!(live.len(), 4);
        HOLD_ALL.store(false, Ordering::SeqCst);
        wait_until("rollout done", || async {
            let s = get(&c, &alloc::format!("{DS}/agent")).await;
            live_pods(&c).await.iter().all(|p| images(p) == "a:2") && int_at(&s, &["status", "updatedNumberScheduled"], -1) == 4 && int_at(&s, &["status", "numberReady"], -1) == 4
        })
        .await;
    });
}

#[test]
fn daemonset_rolling_update_default_max_unavailable_is_one() {
    ds_rolling("", 3);
}

#[test]
fn daemonset_rolling_update_max_unavailable_percent() {
    ds_rolling(r#""50%""#, 2);
}

#[test]
fn daemonset_on_delete() {
    scenario(|c| async move {
        for n in ["n1", "n2"] {
            c.create(NODES, &node(n, "{}", "[]", "4")).await.unwrap();
        }
        c.create(DS, &ds("a:1", "", r#","updateStrategy":{"type":"OnDelete"}"#)).await.unwrap();
        wait_until("2 ready", || async { ds_status(&c, "numberReady").await == 2 }).await;
        merge(&c, &alloc::format!("{DS}/agent"), r#"{"spec":{"template":{"spec":{"containers":[{"name":"c","image":"a:2"}]}}}}"#).await;
        sleep(400).await;
        assert!(live_pods(&c).await.iter().all(|p| images(p) == "a:1"));
        let victim = live_pods(&c).await.remove(0);
        c.delete(&alloc::format!("{PODS}/{}", name(&victim))).await.unwrap();
        wait_until("replacement on the new template", || async {
            let live = live_pods(&c).await;
            live.len() == 2 && live.iter().filter(|p| images(p) == "a:2").count() == 1 && ds_status(&c, "updatedNumberScheduled").await == 1
        })
        .await;
    });
}

// ====================================================================================
// Job
// ====================================================================================

fn job(name: &str, spec_extra: &str, restart: &str, outcome: &str) -> Value {
    v(&alloc::format!(
        r#"{{"metadata":{{"name":"{name}"}},"spec":{{{spec_extra}"template":{{"metadata":{{"annotations":{{"test/outcome":"{outcome}"}}}},
        "spec":{{"restartPolicy":"{restart}","containers":[{{"name":"c","image":"i"}}]}}}}}}}}"#
    ))
}

async fn job_pods(c: &InProcess, n: &str) -> Vec<Value> {
    let mut p: Vec<Value> = all_pods(c).await.into_iter().filter(|p| str_at(p, &["metadata", "labels", "job-name"]) == n).collect();
    p.sort_by(|a, b| name(a).cmp(name(b)));
    p
}

async fn jstat(c: &InProcess, n: &str, f: &str) -> i64 {
    int_at(&get(c, &alloc::format!("{JOBS}/{n}")).await, &["status", f], -1)
}

async fn jcond(c: &InProcess, n: &str, ty: &str) -> bool {
    has_condition(&get(c, &alloc::format!("{JOBS}/{n}")).await, ty)
}

#[test]
fn job_completions_and_parallelism() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        let created = c.create(JOBS, &job("batch", r#""completions":5,"parallelism":2,"#, "Never", "succeed")).await.unwrap();
        wait_until("2 active", || async { jstat(&c, "batch", "active").await == 2 && jstat(&c, "batch", "ready").await == 2 }).await;
        sleep(300).await;
        let pods = job_pods(&c, "batch").await;
        assert_eq!(pods.len(), 2, "never more than parallelism");
        let j = get(&c, &alloc::format!("{JOBS}/batch")).await;
        assert_eq!((int_at(&j, &["status", "succeeded"], -1), int_at(&j, &["status", "failed"], -1)), (0, 0));
        assert_eq!(str_at(&j, &["status", "startTime"]), rfc3339(T0));
        for p in &pods {
            for (k, val) in [("batch.kubernetes.io/controller-uid", uid(&created)), ("controller-uid", uid(&created)), ("batch.kubernetes.io/job-name", "batch"), ("job-name", "batch")] {
                assert_eq!(str_at(p, &["metadata", "labels", k]), val, "label {k}");
            }
            let r = controller_ref(p).unwrap();
            assert_eq!((str_at(r, &["kind"]), str_at(r, &["uid"])), ("Job", uid(&created)));
        }

        FINISH.store(true, Ordering::SeqCst);
        wait_until("complete", || jcond(&c, "batch", "Complete")).await;
        let j = get(&c, &alloc::format!("{JOBS}/batch")).await;
        assert_eq!((int_at(&j, &["status", "succeeded"], -1), int_at(&j, &["status", "active"], -1), int_at(&j, &["status", "failed"], -1)), (5, 0, 0));
        assert_eq!(str_at(&j, &["status", "completionTime"]), rfc3339(T0));
        assert!(has_condition(&j, "SuccessCriteriaMet") && !has_condition(&j, "Failed"));
        sleep(300).await;
        let pods = job_pods(&c, "batch").await;
        assert_eq!(pods.len(), 5, "finished pods are kept");
        assert!(pods.iter().all(|p| str_at(p, &["status", "phase"]) == "Succeeded"));
    });
}

#[test]
fn job_work_queue_completes_after_first_success() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        c.create(JOBS, &job("queue", r#""parallelism":2,"#, "Never", "succeed")).await.unwrap();
        wait_until("2 active", || async { jstat(&c, "queue", "active").await == 2 }).await;
        FINISH.store(true, Ordering::SeqCst);
        wait_until("complete", || jcond(&c, "queue", "Complete")).await;
        sleep(200).await;
        assert_eq!(job_pods(&c, "queue").await.len(), 2, "no new pods once a pod succeeded");
        assert_eq!(jstat(&c, "queue", "active").await, 0);
    });
}

#[test]
fn job_backoff_limit() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        FINISH.store(true, Ordering::SeqCst);
        c.create(JOBS, &job("flaky", r#""backoffLimit":2,"completions":1,"#, "Never", "fail")).await.unwrap();
        wait_until("failed", || jcond(&c, "flaky", "Failed")).await;
        let j = get(&c, &alloc::format!("{JOBS}/flaky")).await;
        let f = cond(&j, "Failed").unwrap();
        assert_eq!((str_at(f, &["status"]), str_at(f, &["reason"])), ("True", "BackoffLimitExceeded"));
        assert_eq!(int_at(&j, &["status", "failed"], -1), 3, "limit 2 means 3 failures");
        assert!(!has_condition(&j, "Complete"));
        sleep(400).await;
        let pods = job_pods(&c, "flaky").await;
        assert_eq!(pods.len(), 3, "no pod after the job failed");
        assert!(pods.iter().all(|p| str_at(p, &["status", "phase"]) == "Failed"));
    });
}

#[test]
fn job_backoff_limit_deletes_active_pods() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        // Two parallel pods; the template fails, but only after FINISH. Make the job fail by
        // marking one pod Failed by hand while the other keeps running.
        c.create(JOBS, &job("mixed", r#""backoffLimit":0,"completions":2,"parallelism":2,"#, "Never", "none")).await.unwrap();
        wait_until("2 active", || async { jstat(&c, "mixed", "active").await == 2 }).await;
        let victim = job_pods(&c, "mixed").await.remove(0);
        merge(&c, &alloc::format!("{PODS}/{}/status", name(&victim)), r#"{"status":{"phase":"Failed"}}"#).await;
        wait_until("failed", || jcond(&c, "mixed", "Failed")).await;
        wait_until("the running pod is deleted, the failed one kept", || async { let l = live_pods(&c).await; l.len() == 1 && str_at(&l[0], &["status", "phase"]) == "Failed" }).await;
        assert_eq!(jstat(&c, "mixed", "active").await, 0);
    });
}

#[test]
fn job_indexed_completion() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        c.create(JOBS, &job("idx", r#""completions":4,"parallelism":2,"completionMode":"Indexed","#, "Never", "succeed")).await.unwrap();
        wait_until("2 active", || async { jstat(&c, "idx", "active").await == 2 }).await;
        sleep(200).await;
        let pods = job_pods(&c, "idx").await;
        let idx: Vec<&str> = pods.iter().map(|p| str_at(p, &["metadata", "annotations", "batch.kubernetes.io/job-completion-index"])).collect();
        assert_eq!(idx, ["0", "1"], "lowest indexes first");
        for p in &pods {
            let i = str_at(p, &["metadata", "annotations", "batch.kubernetes.io/job-completion-index"]);
            assert_eq!(str_at(p, &["metadata", "labels", "batch.kubernetes.io/job-completion-index"]), i);
            assert!(name(p).starts_with(&alloc::format!("idx-{i}-")), "{}", name(p));
            assert_eq!(str_at(p, &["spec", "hostname"]), alloc::format!("idx-{i}"));
            let env = p.pointer(&["spec", "containers"]).and_then(Value::as_array).unwrap()[0].get("env").and_then(Value::as_array).unwrap();
            let e = env.iter().find(|e| str_at(e, &["name"]) == "JOB_COMPLETION_INDEX").unwrap();
            assert_eq!(str_at(e, &["valueFrom", "fieldRef", "fieldPath"]), "metadata.annotations['batch.kubernetes.io/job-completion-index']");
        }
        FINISH.store(true, Ordering::SeqCst);
        wait_until("complete", || jcond(&c, "idx", "Complete")).await;
        let j = get(&c, &alloc::format!("{JOBS}/idx")).await;
        assert_eq!((str_at(&j, &["status", "completedIndexes"]), int_at(&j, &["status", "succeeded"], -1)), ("0-3", 4));
        let pods = job_pods(&c, "idx").await;
        assert_eq!(pods.len(), 4);
        let mut idx: Vec<&str> = pods.iter().map(|p| str_at(p, &["metadata", "annotations", "batch.kubernetes.io/job-completion-index"])).collect();
        idx.sort();
        assert_eq!(idx, ["0", "1", "2", "3"], "each index ran exactly once");
    });
}

#[test]
fn job_ttl_after_finished() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        FINISH.store(true, Ordering::SeqCst);
        c.create(JOBS, &job("ttl", r#""completions":1,"ttlSecondsAfterFinished":30,"#, "Never", "succeed")).await.unwrap();
        wait_until("complete", || jcond(&c, "ttl", "Complete")).await;
        sleep(300).await;
        assert!(c.get(&alloc::format!("{JOBS}/ttl")).await.is_ok());
        advance_clock(29);
        sleep(400).await;
        assert!(c.get(&alloc::format!("{JOBS}/ttl")).await.is_ok(), "29s after finishing is too early");
        advance_clock(2);
        wait_until("job deleted", || async { c.get(&alloc::format!("{JOBS}/ttl")).await.is_err() }).await;
        wait_until("pods collected", || async { all_pods(&c).await.is_empty() }).await;
    });
}

#[test]
fn job_active_deadline() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        c.create(JOBS, &job("slow", r#""activeDeadlineSeconds":10,"#, "Never", "succeed")).await.unwrap();
        wait_until("running", || async { jstat(&c, "slow", "active").await == 1 }).await;
        advance_clock(9);
        sleep(400).await;
        assert!(!jcond(&c, "slow", "Failed").await);
        advance_clock(2);
        wait_until("failed", || jcond(&c, "slow", "Failed")).await;
        let j = get(&c, &alloc::format!("{JOBS}/slow")).await;
        assert_eq!(str_at(cond(&j, "Failed").unwrap(), &["reason"]), "DeadlineExceeded");
        wait_until("active pods removed", || async { live_pods(&c).await.is_empty() }).await;
        assert_eq!(jstat(&c, "slow", "active").await, 0);
    });
}

#[test]
fn job_suspend_and_resume() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        c.create(JOBS, &job("pause", r#""suspend":true,"#, "Never", "succeed")).await.unwrap();
        wait_until("suspended", || jcond(&c, "pause", "Suspended")).await;
        sleep(300).await;
        assert!(all_pods(&c).await.is_empty());
        assert_eq!(str_at(&get(&c, &alloc::format!("{JOBS}/pause")).await, &["status", "startTime"]), "");
        merge(&c, &alloc::format!("{JOBS}/pause"), r#"{"spec":{"suspend":false}}"#).await;
        wait_until("running", || async { jstat(&c, "pause", "active").await == 1 && !jcond(&c, "pause", "Suspended").await }).await;
        assert_eq!(str_at(&get(&c, &alloc::format!("{JOBS}/pause")).await, &["status", "startTime"]), rfc3339(T0));
        merge(&c, &alloc::format!("{JOBS}/pause"), r#"{"spec":{"suspend":true}}"#).await;
        wait_until("suspended again, pods gone", || async { jcond(&c, "pause", "Suspended").await && live_pods(&c).await.is_empty() }).await;
    });
}

#[test]
fn job_rejects_restart_policy_always() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        // The API server rejects it at admission (as upstream); the controller's
        // InvalidRestartPolicy path remains as defence in depth.
        let e = c.create(JOBS, &job("bad", "", "Always", "succeed")).await.unwrap_err();
        assert_eq!(e.code, 422);
        assert!(all_pods(&c).await.is_empty());
    });
}

// ====================================================================================
// CronJob
// ====================================================================================

fn cronjob(schedule: &str, extra: &str, outcome: &str) -> Value {
    v(&alloc::format!(
        r#"{{"metadata":{{"name":"tick"}},"spec":{{"schedule":"{schedule}"{extra},"jobTemplate":{{"spec":{{"backoffLimit":0,"template":{{"metadata":{{"annotations":{{"test/outcome":"{outcome}"}}}},
        "spec":{{"restartPolicy":"Never","containers":[{{"name":"c","image":"i"}}]}}}}}}}}}}}}"#
    ))
}

async fn cron_jobs(c: &InProcess) -> Vec<String> {
    let mut n: Vec<String> = items(&c.list(JOBS, "").await.unwrap()).iter().map(|j| name(j).to_string()).collect();
    n.sort();
    n
}

fn jn(t: i64) -> String {
    alloc::format!("tick-{}", t / 60)
}

async fn has_job(c: &InProcess, t: i64) -> bool {
    c.get(&alloc::format!("{JOBS}/{}", jn(t))).await.is_ok()
}

async fn cj(c: &InProcess) -> Value {
    get(c, &alloc::format!("{CRONJOBS}/tick")).await
}

async fn active_names(c: &InProcess) -> Vec<String> {
    let mut a: Vec<String> = cj(c).await.pointer(&["status", "active"]).and_then(Value::as_array).unwrap_or(&[]).iter().map(|r| str_at(r, &["name"]).to_string()).collect();
    a.sort();
    a
}

#[test]
fn cronjob_allow_creates_jobs_on_schedule() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        let created = c.create(CRONJOBS, &cronjob("* * * * *", "", "succeed")).await.unwrap();
        sleep(400).await;
        assert!(cron_jobs(&c).await.is_empty(), "nothing is due yet");

        advance_clock(60);
        let t1 = T0 + 60;
        wait_until("first job", || has_job(&c, t1)).await;
        let j = get(&c, &alloc::format!("{JOBS}/{}", jn(t1))).await;
        assert_eq!(str_at(&j, &["metadata", "annotations", "batch.kubernetes.io/cronjob-scheduled-timestamp"]), rfc3339(t1));
        let r = controller_ref(&j).unwrap();
        assert_eq!((str_at(r, &["kind"]), str_at(r, &["uid"])), ("CronJob", uid(&created)));
        wait_until("status", || async {
            let s = cj(&c).await;
            str_at(&s, &["status", "lastScheduleTime"]) == rfc3339(t1) && active_names(&c).await == [jn(t1)]
        })
        .await;
        let a = &cj(&c).await.pointer(&["status", "active"]).and_then(Value::as_array).unwrap()[0].clone();
        assert_eq!((str_at(a, &["kind"]), str_at(a, &["uid"])), ("Job", uid(&j)));

        // Allow: the next one starts while the first is still running.
        advance_clock(60);
        let t2 = T0 + 120;
        wait_until("second job", || async { has_job(&c, t2).await && active_names(&c).await.len() == 2 }).await;
        sleep(300).await;
        assert_eq!(cron_jobs(&c).await.len(), 2, "one job per schedule time");

        // Both finish: active drains and lastSuccessfulTime is recorded.
        FINISH.store(true, Ordering::SeqCst);
        wait_until("drained", || async { active_names(&c).await.is_empty() && !str_at(&cj(&c).await, &["status", "lastSuccessfulTime"]).is_empty() }).await;
        assert_eq!(str_at(&cj(&c).await, &["status", "lastSuccessfulTime"]), rfc3339(T0 + 120));

        // Several missed minutes: only the latest one is started.
        advance_clock(300);
        let t3 = T0 + 420;
        wait_until("latest missed time", || has_job(&c, t3)).await;
        sleep(300).await;
        assert!(!has_job(&c, T0 + 180).await && !has_job(&c, T0 + 360).await);
        assert_eq!(cron_jobs(&c).await.len(), 3);
    });
}

#[test]
fn cronjob_forbid_skips_while_active() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        c.create(CRONJOBS, &cronjob("* * * * *", r#","concurrencyPolicy":"Forbid""#, "succeed")).await.unwrap();
        advance_clock(60);
        wait_until("first job", || has_job(&c, T0 + 60)).await;
        advance_clock(120);
        sleep(500).await;
        assert_eq!(cron_jobs(&c).await, [jn(T0 + 60)], "Forbid: the running job blocks new ones");
        FINISH.store(true, Ordering::SeqCst);
        wait_until("job for the latest time once idle", || has_job(&c, T0 + 180)).await;
        assert!(!has_job(&c, T0 + 120).await);
    });
}

#[test]
fn cronjob_replace_deletes_active_job() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        c.create(CRONJOBS, &cronjob("* * * * *", r#","concurrencyPolicy":"Replace""#, "succeed")).await.unwrap();
        advance_clock(60);
        wait_until("first job running", || async { has_job(&c, T0 + 60).await && jstat(&c, &jn(T0 + 60), "active").await == 1 }).await;
        advance_clock(60);
        wait_until("replaced", || async { cron_jobs(&c).await == [jn(T0 + 120)] }).await;
        wait_until("status follows", || async { active_names(&c).await == [jn(T0 + 120)] }).await;
        wait_until("old job's pods collected", || async { job_pods(&c, &jn(T0 + 60)).await.is_empty() }).await;
    });
}

#[test]
fn cronjob_history_limits() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        FINISH.store(true, Ordering::SeqCst);
        c.create(CRONJOBS, &cronjob("* * * * *", r#","successfulJobsHistoryLimit":1,"failedJobsHistoryLimit":0"#, "succeed")).await.unwrap();
        for i in 1..=4 {
            advance_clock(60);
            wait_until("job runs and finishes", || async { has_job(&c, T0 + 60 * i).await && jcond(&c, &jn(T0 + 60 * i), "Complete").await }).await;
        }
        wait_until("only the newest successful job is kept", || async { cron_jobs(&c).await == [jn(T0 + 240)] }).await;
    });
}

#[test]
fn cronjob_failed_history_limit() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        FINISH.store(true, Ordering::SeqCst);
        c.create(CRONJOBS, &cronjob("* * * * *", "", "fail")).await.unwrap();
        for i in 1..=3 {
            advance_clock(60);
            wait_until("job fails", || async { has_job(&c, T0 + 60 * i).await && jcond(&c, &jn(T0 + 60 * i), "Failed").await }).await;
        }
        wait_until("one failed job kept (default limit 1)", || async { cron_jobs(&c).await == [jn(T0 + 180)] }).await;
        assert!(cj(&c).await.pointer(&["status", "lastSuccessfulTime"]).is_none());
    });
}

#[test]
fn cronjob_suspend() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        c.create(CRONJOBS, &cronjob("* * * * *", r#","suspend":true"#, "succeed")).await.unwrap();
        advance_clock(180);
        sleep(500).await;
        assert!(cron_jobs(&c).await.is_empty());
        merge(&c, &alloc::format!("{CRONJOBS}/tick"), r#"{"spec":{"suspend":false}}"#).await;
        wait_until("resumed with the latest time", || has_job(&c, T0 + 180)).await;
        assert_eq!(cron_jobs(&c).await.len(), 1);
    });
}

#[test]
fn cronjob_starting_deadline() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        c.create(CRONJOBS, &cronjob("0 * * * *", r#","startingDeadlineSeconds":30"#, "succeed")).await.unwrap();
        advance_clock(3600 + 120); // 09:02, the 09:00 run is 120s late
        sleep(500).await;
        assert!(cron_jobs(&c).await.is_empty(), "missed the 30s deadline");
        advance_clock(3490); // 10:00:10
        wait_until("10:00 run started in time", || has_job(&c, T0 + 7200)).await;
        assert_eq!(cron_jobs(&c).await.len(), 1);
    });
}

#[test]
fn cronjob_unsupported_time_zone_and_bad_schedule() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        c.create(CRONJOBS, &cronjob("* * * * *", r#","timeZone":"America/New_York""#, "succeed")).await.unwrap();
        wait_until("time zone condition", || async { has_condition(&cj(&c).await, "UnknownTimeZone") }).await;
        advance_clock(180);
        sleep(500).await;
        assert!(cron_jobs(&c).await.is_empty());
        // UTC spelled out works.
        merge(&c, &alloc::format!("{CRONJOBS}/tick"), r#"{"spec":{"timeZone":"UTC"}}"#).await;
        wait_until("runs and condition cleared", || async { has_job(&c, T0 + 180).await && !has_condition(&cj(&c).await, "UnknownTimeZone") }).await;
        merge(&c, &alloc::format!("{CRONJOBS}/tick"), r#"{"spec":{"schedule":"not a cron"}}"#).await;
        wait_until("schedule condition", || async { has_condition(&cj(&c).await, "InvalidSchedule") }).await;
    });
}

// ====================================================================================
// Endpoints and EndpointSlices
// ====================================================================================

fn svc(extra: &str) -> Value {
    v(&alloc::format!(
        r#"{{"metadata":{{"name":"web"}},"spec":{{"selector":{{"app":"web"}},"ports":[{{"name":"http","port":80,"targetPort":"web"}},{{"name":"metrics","port":9090,"targetPort":9091}}]{extra}}}}}"#
    ))
}

fn web_pod(n: &str, port: u16) -> Value {
    v(&alloc::format!(r#"{{"metadata":{{"name":"{n}","labels":{{"app":"web"}}}},"spec":{{"containers":[{{"name":"c","image":"i","ports":[{{"name":"web","containerPort":{port}}}]}}]}}}}"#))
}

async fn set_ready(c: &InProcess, n: &str, ready: bool) {
    let s = if ready { "True" } else { "False" };
    merge(c, &alloc::format!("{PODS}/{n}/status"), &alloc::format!(r#"{{"status":{{"conditions":[{{"type":"Ready","status":"{s}"}}]}}}}"#)).await;
}

async fn pod_ip(c: &InProcess, n: &str) -> String {
    str_at(&get(c, &alloc::format!("{PODS}/{n}")).await, &["status", "podIP"]).to_string()
}

async fn slices(c: &InProcess) -> Vec<Value> {
    let mut s = items(&c.list(SLICES, "labelSelector=kubernetes.io%2Fservice-name%3Dweb").await.unwrap());
    s.sort_by(|a, b| name(a).cmp(name(b)));
    s
}

/// `(ip, ready, serving, terminating)` of every slice endpoint, sorted by ip.
async fn slice_eps(c: &InProcess) -> Vec<(String, bool, bool, bool)> {
    let mut out = Vec::new();
    for s in slices(c).await {
        for e in s.get("endpoints").and_then(Value::as_array).unwrap_or(&[]) {
            let f = |k: &str| e.pointer(&["conditions", k]).and_then(Value::as_bool).unwrap();
            out.push((e.pointer(&["addresses"]).and_then(Value::as_array).unwrap()[0].as_str().unwrap().to_string(), f("ready"), f("serving"), f("terminating")));
        }
    }
    out.sort();
    out
}

/// `(ready ips, not-ready ips)` over all subsets of the Endpoints.
async fn ep_addrs(c: &InProcess, n: &str) -> (Vec<String>, Vec<String>) {
    let (mut r, mut u) = (Vec::new(), Vec::new());
    let Ok(ep) = c.get(&alloc::format!("{EPS}/{n}")).await else { return (r, u) };
    for s in ep.get("subsets").and_then(Value::as_array).unwrap_or(&[]) {
        for (k, out) in [("addresses", &mut r), ("notReadyAddresses", &mut u)] {
            for a in s.get(k).and_then(Value::as_array).unwrap_or(&[]) {
                out.push(str_at(a, &["ip"]).to_string());
            }
        }
    }
    r.sort();
    u.sort();
    (r, u)
}

#[test]
fn endpoints_named_ports_readiness_and_terminating() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        let service = c.create(SVCS, &svc("")).await.unwrap();
        // No pods yet: Endpoints exist without subsets, one placeholder slice without endpoints.
        wait_until("empty objects", || async { c.get(&alloc::format!("{EPS}/web")).await.is_ok() && slices(&c).await.len() == 1 }).await;
        assert!(slices(&c).await[0].get("endpoints").and_then(Value::as_array).unwrap().is_empty());

        c.create(PODS, &web_pod("a", 8080)).await.unwrap();
        c.create(PODS, &web_pod("b", 8081)).await.unwrap();
        wait_until("both published", || async { ep_addrs(&c, "web").await.0.len() == 2 && slice_eps(&c).await.len() == 2 }).await;
        let (ip_a, ip_b) = (pod_ip(&c, "a").await, pod_ip(&c, "b").await);

        // Named targetPort resolves per pod: two different port sets give two subsets / slices.
        let ep = get(&c, &alloc::format!("{EPS}/web")).await;
        let subsets = ep.get("subsets").and_then(Value::as_array).unwrap();
        assert_eq!(subsets.len(), 2);
        for (pod_name, ip, port) in [("a", &ip_a, 8080), ("b", &ip_b, 8081)] {
            let s = subsets.iter().find(|s| s.pointer(&["addresses"]).and_then(Value::as_array).unwrap()[0].get("ip").and_then(Value::as_str) == Some(ip.as_str())).unwrap();
            let addr = &s.get("addresses").and_then(Value::as_array).unwrap()[0];
            assert_eq!((str_at(addr, &["nodeName"]), str_at(addr, &["targetRef", "kind"]), str_at(addr, &["targetRef", "name"])), ("n1", "Pod", pod_name));
            let ports = s.get("ports").and_then(Value::as_array).unwrap();
            assert_eq!(ports.len(), 2);
            assert_eq!((str_at(&ports[0], &["name"]), ports[0].get("port").and_then(Value::as_i64), str_at(&ports[0], &["protocol"])), ("http", Some(port), "TCP"));
            assert_eq!((str_at(&ports[1], &["name"]), ports[1].get("port").and_then(Value::as_i64)), ("metrics", Some(9091)));
        }
        assert_eq!(str_at(&ep, &["metadata", "name"]), "web");
        let ss = slices(&c).await;
        assert_eq!(ss.len(), 2);
        for s in &ss {
            assert!(name(s).starts_with("web-"));
            assert_eq!(str_at(s, &["addressType"]), "IPv4");
            assert_eq!(str_at(s, &["metadata", "labels", "kubernetes.io/service-name"]), "web");
            let r = controller_ref(s).unwrap();
            assert_eq!((str_at(r, &["kind"]), str_at(r, &["uid"])), ("Service", uid(&service)));
            assert_eq!(s.get("ports").and_then(Value::as_array).unwrap().len(), 2);
        }
        let ports_of = |ip: &str| -> i64 {
            let s = ss.iter().find(|s| s.get("endpoints").and_then(Value::as_array).unwrap().iter().any(|e| e.get("addresses").and_then(Value::as_array).unwrap()[0].as_str() == Some(ip))).unwrap();
            s.get("ports").and_then(Value::as_array).unwrap()[0].get("port").and_then(Value::as_i64).unwrap()
        };
        assert_eq!((ports_of(&ip_a), ports_of(&ip_b)), (8080, 8081));
        assert_eq!(slice_eps(&c).await, alloc::vec![(ip_a.clone(), true, true, false), (ip_b.clone(), true, true, false)].tap_sorted());

        // Ready -> NotReady -> Ready.
        set_ready(&c, "a", false).await;
        wait_until("a not ready", || async { ep_addrs(&c, "web").await == (alloc::vec![ip_b.clone()], alloc::vec![ip_a.clone()]) }).await;
        wait_until("slice a not ready", || async { slice_eps(&c).await.contains(&(ip_a.clone(), false, false, false)) }).await;
        assert!(slice_eps(&c).await.contains(&(ip_b.clone(), true, true, false)));
        set_ready(&c, "a", true).await;
        wait_until("a ready again", || async { ep_addrs(&c, "web").await == (alloc::vec![ip_a.clone(), ip_b.clone()].tap_sorted(), alloc::vec![]) && slice_eps(&c).await.contains(&(ip_a.clone(), true, true, false)) }).await;

        // Terminating: out of Endpoints, still in the slice as serving+terminating, not ready.
        hold_delete(&["a"]);
        c.delete(&alloc::format!("{PODS}/a")).await.unwrap();
        wait_until("a terminating", || async { slice_eps(&c).await.contains(&(ip_a.clone(), false, true, true)) && ep_addrs(&c, "web").await == (alloc::vec![ip_b.clone()], alloc::vec![]) }).await;
        release_delete(&["a"]);
        wait_until("a gone", || async { slice_eps(&c).await == [(ip_b.clone(), true, true, false)] && ep_addrs(&c, "web").await.0 == [ip_b.clone()] }).await;

        // Deleting the Service removes Endpoints and slices.
        c.delete(&alloc::format!("{SVCS}/web")).await.unwrap();
        wait_until("cleanup", || async { c.get(&alloc::format!("{EPS}/web")).await.is_err() && slices(&c).await.is_empty() }).await;
    });
}

trait TapSorted {
    fn tap_sorted(self) -> Self;
}
impl<T: Ord> TapSorted for Vec<T> {
    fn tap_sorted(mut self) -> Self {
        self.sort();
        self
    }
}

#[test]
fn endpoints_skip_pods_without_ip_and_honour_publish_not_ready() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        c.create(SVCS, &svc(r#","publishNotReadyAddresses":true"#)).await.unwrap();
        hold(&["pending"]);
        c.create(PODS, &web_pod("pending", 8080)).await.unwrap();
        c.create(PODS, &web_pod("up", 8080)).await.unwrap();
        c.create(PODS, &v(r#"{"metadata":{"name":"other","labels":{"app":"other"}},"spec":{"containers":[{"name":"c","image":"i"}]}}"#)).await.unwrap();
        wait_until("up published", || async { ep_addrs(&c, "web").await.0.len() == 1 }).await;
        sleep(300).await;
        assert_eq!(ep_addrs(&c, "web").await.0, [pod_ip(&c, "up").await], "no IP, no endpoint; other labels, no endpoint");
        // Not ready, but published as ready.
        set_ready(&c, "up", false).await;
        wait_until("still ready in the slice", || async { slice_eps(&c).await.len() == 1 }).await;
        sleep(300).await;
        let ip = pod_ip(&c, "up").await;
        assert_eq!(ep_addrs(&c, "web").await, (alloc::vec![ip.clone()], alloc::vec![]));
        assert_eq!(slice_eps(&c).await, [(ip, true, true, false)]);
        release(&["pending"]);
        wait_until("pending pod joins once it has an IP", || async { ep_addrs(&c, "web").await.0.len() == 2 }).await;
    });
}

#[test]
fn endpoints_leave_selectorless_services_alone() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        c.create(SVCS, &v(r#"{"metadata":{"name":"manual"},"spec":{"ports":[{"port":80}]}}"#)).await.unwrap();
        let ep = c.create(EPS, &v(r#"{"metadata":{"name":"manual"},"subsets":[{"addresses":[{"ip":"192.168.1.1"}],"ports":[{"port":80}]}]}"#)).await.unwrap();
        c.create(PODS, &web_pod("a", 8080)).await.unwrap();
        // A selector service next to it proves the controllers ran.
        c.create(SVCS, &svc("")).await.unwrap();
        wait_until("web published", || async { ep_addrs(&c, "web").await.0.len() == 1 }).await;
        sleep(400).await;
        let after = get(&c, &alloc::format!("{EPS}/manual")).await;
        assert_eq!(str_at(&after, &["metadata", "resourceVersion"]), str_at(&ep, &["metadata", "resourceVersion"]), "untouched");
        let all = items(&c.list(SLICES, "").await.unwrap());
        assert!(all.iter().all(|s| str_at(s, &["metadata", "labels", "kubernetes.io/service-name"]) == "web"), "no slice for the selectorless service");
    });
}

#[test]
fn job_failed_pod_replacement_backs_off_exponentially() {
    scenario_with(|c| crate::Config { job_backoff_ms: 2000, ..c }, |c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        FINISH.store(true, Ordering::SeqCst);
        c.create(JOBS, &job("slow", r#""backoffLimit":5,"completions":1,"#, "Never", "fail")).await.unwrap();
        wait_until("first failure", || async { job_pods(&c, "slow").await.len() == 1 && jstat(&c, "slow", "failed").await == 1 }).await;
        sleep(400).await;
        assert_eq!(job_pods(&c, "slow").await.len(), 1, "2 s delay after the first failure");
        advance_clock(1);
        sleep(400).await;
        assert_eq!(job_pods(&c, "slow").await.len(), 1);
        advance_clock(1);
        wait_until("second pod", || async { job_pods(&c, "slow").await.len() == 2 }).await;
        // Second failure: 4 s.
        wait_until("second failure", || async { jstat(&c, "slow", "failed").await == 2 }).await;
        advance_clock(3);
        sleep(400).await;
        assert_eq!(job_pods(&c, "slow").await.len(), 2, "4 s delay after the second failure");
        advance_clock(1);
        wait_until("third pod", || async { job_pods(&c, "slow").await.len() == 3 }).await;
    });
}

const NS_DOOMED: &str = "/api/v1/namespaces/doomed";

#[test]
fn namespace_deletion_is_asynchronous_and_empties_everything() {
    scenario(|c| async move {
        c.create(NODES, &node("n1", "{}", "[]", "8")).await.unwrap();
        c.create("/api/v1/namespaces", &v(r#"{"metadata":{"name":"doomed"}}"#)).await.unwrap();
        let crd = v(r#"{"metadata":{"name":"widgets.x.io"},"spec":{"group":"x.io","scope":"Namespaced","names":{"plural":"widgets","singular":"widget","kind":"Widget"},
            "versions":[{"name":"v1","served":true,"storage":true,"schema":{"openAPIV3Schema":{"type":"object","x-kubernetes-preserve-unknown-fields":true}}}]}}"#);
        c.create("/apis/apiextensions.k8s.io/v1/customresourcedefinitions", &crd).await.unwrap();
        c.create("/apis/x.io/v1/namespaces/doomed/widgets", &v(r#"{"apiVersion":"x.io/v1","kind":"Widget","metadata":{"name":"w1"},"spec":{"a":1}}"#)).await.unwrap();
        c.create("/api/v1/namespaces/doomed/configmaps", &v(r#"{"metadata":{"name":"cm"},"data":{"a":"b"}}"#)).await.unwrap();
        let dep = v(r#"{"metadata":{"name":"web"},"spec":{"replicas":2,"selector":{"matchLabels":{"app":"web"}},"template":{"metadata":{"labels":{"app":"web"}},"spec":{"containers":[{"name":"c","image":"i"}]}}}}"#);
        c.create("/apis/apps/v1/namespaces/doomed/deployments", &dep).await.unwrap();
        let pods_path = "/api/v1/namespaces/doomed/pods";
        wait_until("2 running pods", || async { items(&c.list(pods_path, "").await.unwrap()).iter().filter(|p| str_at(p, &["status", "phase"]) == "Running").count() == 2 }).await;
        let names: Vec<String> = items(&c.list(pods_path, "").await.unwrap()).iter().map(|p| name(p).to_string()).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        hold_delete(&refs);

        let r = c.delete(NS_DOOMED).await.unwrap();
        assert!(r.pointer(&["metadata", "deletionTimestamp"]).is_some());
        assert_eq!(str_at(&r, &["status", "phase"]), "Terminating");
        let e = c.create("/api/v1/namespaces/doomed/configmaps", &v(r#"{"metadata":{"name":"late"}}"#)).await.unwrap_err();
        assert_eq!(e.code, 403);
        assert!(e.message.contains("unable to create new content in namespace doomed because it is being terminated"), "{}", e.message);

        // Pods are deleted first: the rest of the content waits for them.
        wait_until("pods terminating and failure condition set", || async {
            let ns = c.get(NS_DOOMED).await.unwrap();
            let failed = ns.pointer(&["status", "conditions"]).and_then(Value::as_array).is_some_and(|cs| cs.iter().any(|x| str_at(x, &["type"]) == "NamespaceDeletionContentFailure"));
            failed && items(&c.list(pods_path, "").await.unwrap()).iter().all(|p| p.pointer(&["metadata", "deletionTimestamp"]).is_some())
        })
        .await;
        sleep(400).await;
        assert!(c.get("/api/v1/namespaces/doomed/configmaps/cm").await.is_ok(), "other content waits for the pods");
        let ns = c.get(NS_DOOMED).await.unwrap();
        assert_eq!(str_at(&ns, &["status", "phase"]), "Terminating", "waits for the pods");
        assert!(!items(&c.list(pods_path, "").await.unwrap()).is_empty());
        release_delete(&refs);
        wait_until("namespace gone", || async { c.get(NS_DOOMED).await.is_err() }).await;
        assert_eq!(c.get(NS_DOOMED).await.unwrap_err().code, 404);
    });
}

#[test]
fn crd_deletion_removes_instances_then_the_crd() {
    scenario(|c| async move {
        let crds = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions";
        let crd = v(r#"{"metadata":{"name":"gadgets.x.io"},"spec":{"group":"x.io","scope":"Namespaced","names":{"plural":"gadgets","singular":"gadget","kind":"Gadget"},
            "versions":[{"name":"v1","served":true,"storage":true,"schema":{"openAPIV3Schema":{"type":"object","x-kubernetes-preserve-unknown-fields":true}}}]}}"#);
        let made = c.create(crds, &crd).await.unwrap();
        assert_eq!(made.pointer(&["metadata", "finalizers"]).and_then(Value::as_array).map(|f| f.len()), Some(1));
        let g = "/apis/x.io/v1/namespaces/default/gadgets";
        let body = |n: &str, fin: &str| v(&alloc::format!(r#"{{"apiVersion":"x.io/v1","kind":"Gadget","metadata":{{"name":"{n}","finalizers":[{fin}]}},"spec":{{"a":1}}}}"#));
        c.create(g, &body("plain", "")).await.unwrap();
        c.create(g, &body("held", r#""x.io/hold""#)).await.unwrap();

        let r = c.delete(&alloc::format!("{crds}/gadgets.x.io")).await.unwrap();
        assert!(r.pointer(&["metadata", "deletionTimestamp"]).is_some());
        assert_eq!(c.create(g, &body("late", "")).await.unwrap_err().code, 405);
        wait_until("plain instance deleted", || async { c.get(&alloc::format!("{g}/plain")).await.is_err() }).await;
        sleep(400).await;
        assert!(c.get(&alloc::format!("{g}/held")).await.unwrap().pointer(&["metadata", "deletionTimestamp"]).is_some());
        assert!(c.get(&alloc::format!("{crds}/gadgets.x.io")).await.is_ok(), "waits for the finalizer of the instance");

        let mut held = c.get(&alloc::format!("{g}/held")).await.unwrap();
        held.entry_object("metadata").set("finalizers", Value::Array(Vec::new()));
        c.update(&alloc::format!("{g}/held"), &held).await.unwrap();
        wait_until("crd gone", || async { c.get(&alloc::format!("{crds}/gadgets.x.io")).await.is_err() }).await;
        assert_eq!(c.list(g, "").await.unwrap_err().code, 404);
    });
}
