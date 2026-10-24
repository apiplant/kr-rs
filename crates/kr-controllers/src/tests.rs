//! End-to-end tests: the controllers run against an in-process API server over an in-memory
//! store. There is no kubelet, so a tiny fake one marks bound pods Running/Ready. Time is the
//! real monotonic clock, so everything runs with millisecond-scale intervals.
//!
//! The executor is a process-wide singleton, so tests take a lock and run one at a time.

use crate::util::*;
use crate::{run_all_with, Config};
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::future::Future;
use alloc::collections::BTreeSet;
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use kr_apiserver::api::ApiServer;
use kr_apiserver::client::{Client, InProcess};
use kr_fmt::json::{parse_str, Value};
use kr_rt::exec::{block_on, sleep, spawn};
use std::sync::Mutex;

pub(crate) static LOCK: Mutex<()> = Mutex::new(());

/// The fake clock behind `Config::now` and the API server's clock; tests move it.
pub(crate) static CLOCK: AtomicI64 = AtomicI64::new(T0);
/// 2027-01-15 08:00:00 UTC.
pub(crate) const T0: i64 = 1_800_000_000;
/// While false, pods that carry the annotation `test/outcome` stay Running; once true the fake
/// kubelet turns them into `Succeeded` (`succeed`) or `Failed` (`fail`).
pub(crate) static FINISH: AtomicBool = AtomicBool::new(false);
/// Pods the fake kubelet leaves alone (they stay Pending, without an IP).
pub(crate) static HOLD: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
/// Terminating pods whose deletion the fake kubelet does not finish yet.
pub(crate) static HOLD_DELETE: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
/// While true the fake kubelet starts no pod at all.
pub(crate) static HOLD_ALL: AtomicBool = AtomicBool::new(false);
static NEXT_IP: AtomicU64 = AtomicU64::new(1);

pub(crate) fn hold(names: &[&str]) {
    HOLD.lock().unwrap_or_else(|e| e.into_inner()).extend(names.iter().map(|n| n.to_string()));
}
pub(crate) fn release(names: &[&str]) {
    let mut h = HOLD.lock().unwrap_or_else(|e| e.into_inner());
    for n in names {
        h.remove(*n);
    }
}
pub(crate) fn hold_delete(names: &[&str]) {
    HOLD_DELETE.lock().unwrap_or_else(|e| e.into_inner()).extend(names.iter().map(|n| n.to_string()));
}
pub(crate) fn release_delete(names: &[&str]) {
    let mut h = HOLD_DELETE.lock().unwrap_or_else(|e| e.into_inner());
    for n in names {
        h.remove(*n);
    }
}
pub(crate) fn advance_clock(secs: i64) {
    CLOCK.fetch_add(secs, Ordering::SeqCst);
}

pub(crate) fn rng(b: &mut [u8]) {
    static N: AtomicU64 = AtomicU64::new(1);
    let mut x = N.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed) | 1;
    for byte in b {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        *byte = (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8;
    }
}

pub(crate) fn cfg() -> Config {
    Config { resync_ms: 150, gc_ms: 60, backoff_ms: 30, retry_ms: 60, now: || CLOCK.load(Ordering::SeqCst) }
}

pub(crate) fn v(s: &str) -> Value {
    parse_str(s).unwrap_or_else(|e| panic!("bad test json {s}: {e}"))
}

/// Runs `f` with the controllers and a fake kubelet running; stops them afterwards.
pub(crate) fn scenario<F, Fut>(f: F)
where
    F: FnOnce(InProcess) -> Fut + 'static,
    Fut: Future<Output = ()> + 'static,
{
    let _l = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    CLOCK.store(T0, Ordering::SeqCst);
    FINISH.store(false, Ordering::SeqCst);
    HOLD_ALL.store(false, Ordering::SeqCst);
    HOLD.lock().unwrap_or_else(|e| e.into_inner()).clear();
    HOLD_DELETE.lock().unwrap_or_else(|e| e.into_inner()).clear();
    NEXT_IP.store(1, Ordering::SeqCst);
    let api = Rc::new(ApiServer::new(kr_store::Store::in_memory(), || CLOCK.load(Ordering::SeqCst), rng, "127.0.0.1:6443".to_string()).unwrap());
    let c = InProcess::new(api, "test");
    block_on(async move {
        let ctl = spawn(run_all_with(c.clone(), cfg()));
        let kubelet = spawn(kubelet(c.clone()));
        f(c).await;
        ctl.abort();
        kubelet.abort();
    });
}

/// The fake kubelet. Per pod: finish graceful deletions (`gracePeriodSeconds=0`) unless held;
/// start bound pods that are not held (Running, Ready, with a pod IP); and, once `FINISH` is
/// set, end Running pods annotated `test/outcome` as Succeeded or Failed.
async fn kubelet(c: InProcess) {
    loop {
        if let Ok(l) = c.list("/api/v1/pods", "").await {
            for p in items(&l) {
                let path = alloc::format!("/api/v1/namespaces/{}/pods/{}", namespace(&p), name(&p));
                let held = HOLD.lock().unwrap_or_else(|e| e.into_inner()).contains(name(&p));
                if deleting(&p) {
                    if !HOLD_DELETE.lock().unwrap_or_else(|e| e.into_inner()).contains(name(&p)) {
                        // Containers "stopped": finish the graceful deletion like a kubelet does.
                        let _ = c.delete(&alloc::format!("{path}?gracePeriodSeconds=0")).await;
                    }
                    continue;
                }
                if str_at(&p, &["spec", "nodeName"]).is_empty() || held || (HOLD_ALL.load(Ordering::SeqCst) && str_at(&p, &["status", "phase"]).is_empty()) {
                    continue;
                }
                match str_at(&p, &["status", "phase"]) {
                    "" | "Pending" => {
                        let ip = alloc::format!("10.244.0.{}", NEXT_IP.fetch_add(1, Ordering::SeqCst));
                        let st = v(&alloc::format!(r#"{{"status":{{"phase":"Running","podIP":"{ip}","podIPs":[{{"ip":"{ip}"}}],"conditions":[{{"type":"Ready","status":"True"}}]}}}}"#));
                        let _ = c.patch(&alloc::format!("{path}/status"), MERGE, &st).await;
                    }
                    "Running" if FINISH.load(Ordering::SeqCst) => {
                        let phase = match str_at(&p, &["metadata", "annotations", "test/outcome"]) {
                            "succeed" => "Succeeded",
                            "fail" => "Failed",
                            _ => continue,
                        };
                        let st = v(&alloc::format!(r#"{{"status":{{"phase":"{phase}","conditions":[{{"type":"Ready","status":"False"}}]}}}}"#));
                        let _ = c.patch(&alloc::format!("{path}/status"), MERGE, &st).await;
                    }
                    _ => {}
                }
            }
        }
        sleep(10).await;
    }
}

pub(crate) async fn wait_until<Fut: Future<Output = bool>>(what: &str, mut f: impl FnMut() -> Fut) {
    for _ in 0..800 {
        if f().await {
            return;
        }
        sleep(10).await;
    }
    panic!("timed out waiting for: {what}");
}

pub(crate) fn node(name: &str, labels: &str, taints: &str, cpu: &str) -> Value {
    v(&alloc::format!(
        r#"{{"metadata":{{"name":"{name}","labels":{labels}}},"spec":{{"taints":{taints}}},"status":{{"conditions":[{{"type":"Ready","status":"True"}}],"allocatable":{{"cpu":"{cpu}","memory":"8Gi","pods":"110"}}}}}}"#
    ))
}

const DEPLOYMENTS: &str = "/apis/apps/v1/namespaces/default/deployments";
const RS: &str = "/apis/apps/v1/namespaces/default/replicasets";
pub(crate) const PODS: &str = "/api/v1/namespaces/default/pods";

fn deployment(replicas: u32, image: &str, extra_spec: &str) -> Value {
    v(&alloc::format!(
        r#"{{"metadata":{{"name":"web"}},"spec":{{"replicas":{replicas}{extra_spec},"selector":{{"matchLabels":{{"app":"web"}}}},"template":{{"metadata":{{"labels":{{"app":"web"}}}},"spec":{{"containers":[{{"name":"c","image":"{image}","resources":{{"requests":{{"cpu":"100m","memory":"64Mi"}}}}}}]}}}}}}}}"#
    ))
}

pub(crate) async fn live_pods(c: &InProcess) -> Vec<Value> {
    items(&c.list(PODS, "").await.unwrap()).into_iter().filter(|p| !deleting(p)).collect()
}

async fn replicasets_now(c: &InProcess) -> Vec<Value> {
    items(&c.list(RS, "").await.unwrap())
}

async fn set_image(c: &InProcess, image: &str) {
    let patch = v(&alloc::format!(r#"{{"spec":{{"template":{{"spec":{{"containers":[{{"name":"c","image":"{image}","resources":{{"requests":{{"cpu":"100m","memory":"64Mi"}}}}}}]}}}}}}}}"#));
    c.patch(&alloc::format!("{DEPLOYMENTS}/web"), MERGE, &patch).await.unwrap();
}

async fn scale_to(c: &InProcess, n: u32) {
    c.patch(&alloc::format!("{DEPLOYMENTS}/web/scale"), MERGE, &v(&alloc::format!(r#"{{"spec":{{"replicas":{n}}}}}"#))).await.unwrap();
}

pub(crate) fn cond<'a>(o: &'a Value, ty: &str) -> Option<&'a Value> {
    o.pointer(&["status", "conditions"])?.as_array()?.iter().find(|c| str_at(c, &["type"]) == ty)
}

async fn deployment_status(c: &InProcess) -> Value {
    c.get(&alloc::format!("{DEPLOYMENTS}/web")).await.unwrap()
}

/// All counts settled and the Deployment reports completion.
async fn complete(c: &InProcess, n: i64) -> bool {
    let d = deployment_status(c).await;
    let gen = int_at(&d, &["metadata", "generation"], -1);
    int_at(&d, &["status", "observedGeneration"], -2) == gen
        && ["replicas", "updatedReplicas", "readyReplicas", "availableReplicas"].iter().all(|f| int_at(&d, &["status", f], -1) == n)
        && int_at(&d, &["status", "unavailableReplicas"], -1) == 0
        && cond(&d, "Progressing").is_some_and(|c| str_at(c, &["reason"]) == "NewReplicaSetAvailable" && str_at(c, &["status"]) == "True")
        && cond(&d, "Available").is_some_and(|c| str_at(c, &["status"]) == "True")
}

#[test]
fn deployment_lifecycle() {
    scenario(|c| async move {
        c.create("/api/v1/nodes", &node("n1", "{}", "[]", "4")).await.unwrap();
        let d = c.create(DEPLOYMENTS, &deployment(3, "nginx:1", "")).await.unwrap();

        // 1 RS, 3 pods, all bound, all owned correctly.
        wait_until("3 bound pods", || async { let p = live_pods(&c).await; p.len() == 3 && p.iter().all(|p| str_at(p, &["spec", "nodeName"]) == "n1") }).await;
        let rss = replicasets_now(&c).await;
        assert_eq!(rss.len(), 1);
        let rs = &rss[0];
        let r = controller_ref(rs).unwrap();
        assert_eq!((str_at(r, &["kind"]), str_at(r, &["uid"]), r.get("blockOwnerDeletion").and_then(Value::as_bool)), ("Deployment", uid(&d), Some(true)));
        assert_eq!(str_at(rs, &["metadata", "annotations", "deployment.kubernetes.io/revision"]), "1");
        let hash = str_at(rs, &["metadata", "labels", "pod-template-hash"]).to_string();
        assert!(name(rs) == alloc::format!("web-{hash}"));
        for p in live_pods(&c).await {
            let r = controller_ref(&p).unwrap();
            assert_eq!((str_at(r, &["kind"]), str_at(r, &["uid"])), ("ReplicaSet", uid(rs)));
            assert_eq!(str_at(&p, &["metadata", "labels", "pod-template-hash"]), hash);
            assert!(name(&p).starts_with(&alloc::format!("{}-", name(rs))));
        }
        wait_until("deployment complete at 3", || complete(&c, 3)).await;

        scale_to(&c, 5).await;
        wait_until("5 pods", || async { live_pods(&c).await.len() == 5 }).await;
        wait_until("complete at 5", || complete(&c, 5)).await;
        scale_to(&c, 1).await;
        wait_until("1 pod", || async { live_pods(&c).await.len() == 1 }).await;
        wait_until("complete at 1", || complete(&c, 1)).await;
        scale_to(&c, 3).await;
        wait_until("complete at 3 again", || complete(&c, 3)).await;
        assert_eq!(replicasets_now(&c).await.len(), 1);

        // Rolling update.
        set_image(&c, "nginx:2").await;
        wait_until("rollout", || async {
            let rss = replicasets_now(&c).await;
            rss.len() == 2 && rss.iter().all(|r| {
                let new = str_at(r, &["spec", "template", "spec", "containers"]).is_empty() && r.pointer(&["spec", "template", "spec", "containers"]).and_then(Value::as_array).is_some_and(|cs| str_at(&cs[0], &["image"]) == "nginx:2");
                int_at(r, &["spec", "replicas"], -1) == if new { 3 } else { 0 }
            })
        })
        .await;
        wait_until("complete after rollout", || complete(&c, 3)).await;
        let pods = live_pods(&c).await;
        assert_eq!(pods.len(), 3);
        assert!(pods.iter().all(|p| str_at(p, &["spec", "containers"]).is_empty() && p.pointer(&["spec", "containers"]).and_then(Value::as_array).is_some_and(|cs| str_at(&cs[0], &["image"]) == "nginx:2")));
        let mut revs: Vec<String> = replicasets_now(&c).await.iter().map(|r| str_at(r, &["metadata", "annotations", "deployment.kubernetes.io/revision"]).to_string()).collect();
        revs.sort();
        assert_eq!(revs, ["1", "2"]);

        // Deleting the Deployment garbage-collects the ReplicaSets and pods.
        c.delete(&alloc::format!("{DEPLOYMENTS}/web")).await.unwrap();
        wait_until("gc", || async { replicasets_now(&c).await.is_empty() && items(&c.list(PODS, "").await.unwrap()).is_empty() }).await;
    });
}

#[test]
fn recreate_strategy_and_history_limit() {
    scenario(|c| async move {
        c.create("/api/v1/nodes", &node("n1", "{}", "[]", "4")).await.unwrap();
        c.create(DEPLOYMENTS, &deployment(2, "app:1", r#","strategy":{"type":"Recreate"},"revisionHistoryLimit":1"#)).await.unwrap();
        wait_until("complete at 2", || complete(&c, 2)).await;
        set_image(&c, "app:2").await;
        wait_until("complete after 2nd image", || async { replicasets_now(&c).await.len() == 2 && complete(&c, 2).await }).await;
        set_image(&c, "app:3").await;
        // Three templates, history limit 1: the oldest scaled-down ReplicaSet is deleted.
        wait_until("history trimmed", || async {
            let rss = replicasets_now(&c).await;
            rss.len() == 2 && complete(&c, 2).await && rss.iter().filter(|r| int_at(r, &["spec", "replicas"], -1) == 0).count() == 1
        })
        .await;
        let rss = replicasets_now(&c).await;
        let revs: Vec<&str> = rss.iter().map(|r| str_at(r, &["metadata", "annotations", "deployment.kubernetes.io/revision"])).collect();
        assert!(revs.contains(&"3") && revs.contains(&"2") && !revs.contains(&"1"), "{revs:?}");
        let pods = live_pods(&c).await;
        assert!(pods.len() == 2 && pods.iter().all(|p| p.pointer(&["spec", "containers"]).and_then(Value::as_array).is_some_and(|cs| str_at(&cs[0], &["image"]) == "app:3")));
    });
}

fn bare_pod(name: &str, spec_extra: &str) -> Value {
    v(&alloc::format!(r#"{{"metadata":{{"name":"{name}"}},"spec":{{{spec_extra}"containers":[{{"name":"c","image":"i","resources":{{"requests":{{"cpu":"2"}}}}}}]}}}}"#))
}

/// A pod that fits nowhere gets PodScheduled=False, then binds once `fixing_node` appears.
fn unschedulable_case(first: Value, pod: Value, fixing: Value, expect_msg: &'static str) {
    scenario(move |c| async move {
        let pname = name(&pod).to_string();
        c.create("/api/v1/nodes", &first).await.unwrap();
        c.create(PODS, &pod).await.unwrap();
        let path = alloc::format!("{PODS}/{pname}");
        wait_until("Unschedulable condition", || async {
            let p = c.get(&path).await.unwrap();
            cond(&p, "PodScheduled").is_some_and(|k| str_at(k, &["status"]) == "False" && str_at(k, &["reason"]) == "Unschedulable" && str_at(k, &["message"]).contains(expect_msg))
        })
        .await;
        assert_eq!(str_at(&c.get(&path).await.unwrap(), &["spec", "nodeName"]), "");
        sleep(100).await; // still pending across retries
        assert_eq!(str_at(&c.get(&path).await.unwrap(), &["spec", "nodeName"]), "");
        let want = name(&fixing).to_string();
        c.create("/api/v1/nodes", &fixing).await.unwrap();
        wait_until("bound to the fitting node", || async { str_at(&c.get(&path).await.unwrap(), &["spec", "nodeName"]) == want }).await;
    });
}

#[test]
fn unschedulable_node_selector() {
    unschedulable_case(node("n1", "{}", "[]", "4"), bare_pod("p", r#""nodeSelector":{"disk":"ssd"},"#), node("n2", r#"{"disk":"ssd"}"#, "[]", "4"), "node selector");
}

#[test]
fn unschedulable_taint() {
    let taint = r#"[{"key":"dedicated","value":"gpu","effect":"NoSchedule"}]"#;
    unschedulable_case(node("n1", "{}", taint, "4"), bare_pod("p", ""), node("n2", "{}", "[]", "4"), "untolerated taint");
}

#[test]
fn tolerated_taint_schedules() {
    scenario(|c| async move {
        c.create("/api/v1/nodes", &node("n1", "{}", r#"[{"key":"dedicated","value":"gpu","effect":"NoSchedule"}]"#, "4")).await.unwrap();
        c.create(PODS, &bare_pod("p", r#""tolerations":[{"key":"dedicated","operator":"Equal","value":"gpu","effect":"NoSchedule"}],"#)).await.unwrap();
        wait_until("bound", || async { str_at(&c.get(&alloc::format!("{PODS}/p")).await.unwrap(), &["spec", "nodeName"]) == "n1" }).await;
    });
}

#[test]
fn unschedulable_insufficient_cpu() {
    unschedulable_case(node("n1", "{}", "[]", "1"), bare_pod("p", ""), node("n2", "{}", "[]", "4"), "Insufficient cpu");
}

#[test]
fn spreads_by_least_requested_and_accounts_requests() {
    scenario(|c| async move {
        c.create("/api/v1/nodes", &node("n1", "{}", "[]", "4")).await.unwrap();
        c.create("/api/v1/nodes", &node("n2", "{}", "[]", "4")).await.unwrap();
        for i in 0..4 {
            c.create(PODS, &bare_pod(&alloc::format!("p{i}"), "")).await.unwrap();
        }
        // 4 pods x 2 cpu on 2 nodes x 4 cpu: exactly two each, and a fifth does not fit.
        wait_until("4 bound", || async { live_pods(&c).await.iter().all(|p| !str_at(p, &["spec", "nodeName"]).is_empty()) }).await;
        let pods = live_pods(&c).await;
        assert_eq!(pods.iter().filter(|p| str_at(p, &["spec", "nodeName"]) == "n1").count(), 2);
        c.create(PODS, &bare_pod("extra", "")).await.unwrap();
        wait_until("extra unschedulable", || async { cond(&c.get(&alloc::format!("{PODS}/extra")).await.unwrap(), "PodScheduled").is_some() }).await;
    });
}

#[test]
fn replicaset_adopts_orphans() {
    scenario(|c| async move {
        c.create("/api/v1/nodes", &node("n1", "{}", "[]", "64")).await.unwrap();
        let mk = |n: &str, extra: &str| v(&alloc::format!(r#"{{"metadata":{{"name":"{n}","labels":{{"app":"x"}}{extra}}},"spec":{{"containers":[{{"name":"c","image":"i"}}]}}}}"#));
        c.create(PODS, &mk("orphan-a", "")).await.unwrap();
        c.create(PODS, &mk("orphan-b", "")).await.unwrap();
        // Controlled by something else: neither adopted nor counted.
        c.create(PODS, &mk("foreign", r#","ownerReferences":[{"apiVersion":"example.com/v1","kind":"Foo","name":"f","uid":"u-1","controller":true}]"#)).await.unwrap();
        let rs = c
            .create(
                RS,
                &v(r#"{"metadata":{"name":"adopter"},"spec":{"replicas":2,"selector":{"matchLabels":{"app":"x"}},"template":{"metadata":{"labels":{"app":"x"}},"spec":{"containers":[{"name":"c","image":"i"}]}}}}"#),
            )
            .await
            .unwrap();
        wait_until("orphans adopted", || async {
            let mine = ["orphan-a", "orphan-b"];
            let mut ok = true;
            for n in mine {
                let p = c.get(&alloc::format!("{PODS}/{n}")).await.unwrap();
                ok &= controller_ref(&p).is_some_and(|r| str_at(r, &["uid"]) == uid(&rs) && str_at(r, &["name"]) == "adopter");
            }
            ok
        })
        .await;
        wait_until("status", || async {
            let r = c.get(&alloc::format!("{RS}/adopter")).await.unwrap();
            int_at(&r, &["status", "replicas"], -1) == 2 && int_at(&r, &["status", "readyReplicas"], -1) == 2 && int_at(&r, &["status", "fullyLabeledReplicas"], -1) == 2 && int_at(&r, &["status", "observedGeneration"], -1) == 1
        })
        .await;
        sleep(200).await;
        assert_eq!(live_pods(&c).await.len(), 3, "no extra pods were created");
        let foreign = c.get(&alloc::format!("{PODS}/foreign")).await.unwrap();
        assert_eq!(str_at(controller_ref(&foreign).unwrap(), &["kind"]), "Foo");

        // Scale down deletes one of the adopted pods, never the foreign one.
        c.patch(&alloc::format!("{RS}/adopter/scale"), MERGE, &v(r#"{"spec":{"replicas":1}}"#)).await.unwrap();
        wait_until("one removed", || async { live_pods(&c).await.len() == 2 }).await;
        assert!(c.get(&alloc::format!("{PODS}/foreign")).await.is_ok());
    });
}

#[test]
fn replicationcontroller_creates_pods() {
    scenario(|c| async move {
        c.create("/api/v1/nodes", &node("n1", "{}", "[]", "64")).await.unwrap();
        let rc_path = "/api/v1/namespaces/default/replicationcontrollers";
        let rc = c
            .create(
                rc_path,
                &v(r#"{"metadata":{"name":"rc1"},"spec":{"replicas":2,"selector":{"app":"y"},"template":{"metadata":{"labels":{"app":"y"}},"spec":{"containers":[{"name":"c","image":"i"}]}}}}"#),
            )
            .await
            .unwrap();
        wait_until("2 pods", || async { live_pods(&c).await.len() == 2 }).await;
        for p in live_pods(&c).await {
            let r = controller_ref(&p).unwrap();
            assert_eq!(str_at(r, &["kind"]), "ReplicationController");
            assert_eq!(str_at(r, &["apiVersion"]), "v1");
            assert_eq!(str_at(r, &["uid"]), uid(&rc));
        }
        wait_until("status", || async {
            let r = c.get(&alloc::format!("{rc_path}/rc1")).await.unwrap();
            int_at(&r, &["status", "replicas"], -1) == 2 && int_at(&r, &["status", "readyReplicas"], -1) == 2
        })
        .await;
    });
}

fn quota_used(q: &Value, name: &str) -> Option<String> {
    q.pointer(&["status", "used", name]).and_then(Value::as_str).map(String::from)
}

#[test]
fn quota_status_tracks_usage() {
    scenario(|c| async move {
        let qp = "/api/v1/namespaces/default/resourcequotas";
        c.create(qp, &v(r#"{"metadata":{"name":"q"},"spec":{"hard":{"configmaps":"10","count/secrets":"10"}}}"#)).await.unwrap();
        for n in ["a", "b"] {
            c.create("/api/v1/namespaces/default/configmaps", &v(&alloc::format!(r#"{{"metadata":{{"name":"{n}"}}}}"#))).await.unwrap();
        }
        c.create("/api/v1/namespaces/default/secrets", &v(r#"{"metadata":{"name":"s"}}"#)).await.unwrap();
        wait_until("used counts", || async {
            let q = c.get(&alloc::format!("{qp}/q")).await.unwrap();
            quota_used(&q, "configmaps").as_deref() == Some("2") && quota_used(&q, "count/secrets").as_deref() == Some("1") && q.pointer(&["status", "hard", "configmaps"]).is_some()
        })
        .await;
        c.delete("/api/v1/namespaces/default/configmaps/a").await.unwrap();
        wait_until("used drops after delete", || async { quota_used(&c.get(&alloc::format!("{qp}/q")).await.unwrap(), "configmaps").as_deref() == Some("1") }).await;
    });
}

#[test]
fn quota_admission_rejects_over_limit() {
    scenario(|c| async move {
        let qp = "/api/v1/namespaces/default/resourcequotas";
        c.create(qp, &v(r#"{"metadata":{"name":"q"},"spec":{"hard":{"secrets":"1"}}}"#)).await.unwrap();
        let sp = "/api/v1/namespaces/default/secrets";
        c.create(sp, &v(r#"{"metadata":{"name":"s1"}}"#)).await.unwrap();
        // Back to back: admission counts from the store, not from the controller's status.
        let e = c.create(sp, &v(r#"{"metadata":{"name":"s2"}}"#)).await.unwrap_err();
        assert_eq!(e.code, 403, "{}", e.message);
        assert!(e.message.contains("exceeded quota: q, requested: secrets=1, used: secrets=1, limited: secrets=1"), "{}", e.message);
        c.delete(&alloc::format!("{sp}/s1")).await.unwrap();
        c.create(sp, &v(r#"{"metadata":{"name":"s2"}}"#)).await.unwrap();
    });
}

#[test]
fn quota_admission_requires_tracked_resources() {
    scenario(|c| async move {
        c.create("/api/v1/namespaces/default/resourcequotas", &v(r#"{"metadata":{"name":"q"},"spec":{"hard":{"requests.cpu":"1"}}}"#)).await.unwrap();
        let pp = "/api/v1/namespaces/default/pods";
        let e = c.create(pp, &v(r#"{"metadata":{"name":"p1"},"spec":{"containers":[{"name":"c","image":"i"}]}}"#)).await.unwrap_err();
        assert_eq!(e.code, 403);
        assert!(e.message.contains("must specify requests.cpu"), "{}", e.message);
        c.create(pp, &v(r#"{"metadata":{"name":"p2"},"spec":{"containers":[{"name":"c","image":"i","resources":{"requests":{"cpu":"600m"}}}]}}"#)).await.unwrap();
        let e = c.create(pp, &v(r#"{"metadata":{"name":"p3"},"spec":{"containers":[{"name":"c","image":"i","resources":{"requests":{"cpu":"500m"}}}]}}"#)).await.unwrap_err();
        assert!(e.message.contains("exceeded quota: q, requested: requests.cpu=500m, used: requests.cpu=600m, limited: requests.cpu=1"), "{}", e.message);
    });
}

#[test]
fn quota_scopes_select_pods() {
    scenario(|c| async move {
        let qp = "/api/v1/namespaces/default/resourcequotas";
        c.create(qp, &v(r#"{"metadata":{"name":"be"},"spec":{"hard":{"pods":"5"},"scopes":["BestEffort"]}}"#)).await.unwrap();
        let pp = "/api/v1/namespaces/default/pods";
        c.create(pp, &v(r#"{"metadata":{"name":"best"},"spec":{"containers":[{"name":"c","image":"i"}]}}"#)).await.unwrap();
        c.create(pp, &v(r#"{"metadata":{"name":"burst"},"spec":{"containers":[{"name":"c","image":"i","resources":{"requests":{"cpu":"100m"}}}]}}"#)).await.unwrap();
        wait_until("only the best-effort pod counts", || async { quota_used(&c.get(&alloc::format!("{qp}/be")).await.unwrap(), "pods").as_deref() == Some("1") }).await;
    });
}
