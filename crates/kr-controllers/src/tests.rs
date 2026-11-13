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

std::thread_local! {
    /// The API server of the running scenario (for tests that feed it metrics).
    pub(crate) static API: core::cell::RefCell<Option<Rc<ApiServer>>> = const { core::cell::RefCell::new(None) };
}

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
    Config { resync_ms: 150, gc_ms: 60, backoff_ms: 30, retry_ms: 60, job_backoff_ms: 0, now: || CLOCK.load(Ordering::SeqCst), evict: crate::nodelifecycle::Limits::default(), hpa_ms: 100, disabled: Default::default(), helm_image: None }
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
    scenario_with(|c| c, f)
}

/// Like [`scenario`] with the timing config adjusted by `tweak`.
pub(crate) fn scenario_with<F, Fut>(tweak: fn(Config) -> Config, f: F)
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
    API.with(|a| *a.borrow_mut() = Some(api.clone()));
    let c = InProcess::new(api, "test");
    block_on(async move {
        let ctl = spawn(run_all_with(c.clone(), tweak(cfg())));
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
                if str_at(&p, &["spec", "nodeName"]).is_empty() || held || (HOLD_ALL.load(Ordering::SeqCst) && matches!(str_at(&p, &["status", "phase"]), "" | "Pending")) {
                    continue;
                }
                match str_at(&p, &["status", "phase"]) {
                    "" | "Pending" => {
                        let ip = alloc::format!("10.244.0.{}", NEXT_IP.fetch_add(1, Ordering::SeqCst));
                        let ready_at = rfc3339(CLOCK.load(Ordering::SeqCst));
                        let st = v(&alloc::format!(r#"{{"status":{{"phase":"Running","startTime":"{ready_at}","podIP":"{ip}","podIPs":[{{"ip":"{ip}"}}],"conditions":[{{"type":"Ready","status":"True","lastTransitionTime":"{ready_at}"}}]}}}}"#));
                        let _ = c.patch(&alloc::format!("{path}/status"), MERGE, &st).await;
                    }
                    "Running" if FINISH.load(Ordering::SeqCst) => {
                        let phase = match str_at(&p, &["metadata", "annotations", "test/outcome"]) {
                            "succeed" => "Succeeded",
                            "fail" => "Failed",
                            _ => continue,
                        };
                        let fin = rfc3339(CLOCK.load(Ordering::SeqCst));
                        let st = v(&alloc::format!(r#"{{"status":{{"phase":"{phase}","conditions":[{{"type":"Ready","status":"False"}}],"containerStatuses":[{{"name":"c","state":{{"terminated":{{"exitCode":1,"finishedAt":"{fin}"}}}}}}]}}}}"#));
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
    // 30 s: generous for a loaded single-CPU machine (the arm64 CI host), instant when it works.
    for _ in 0..3000 {
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
fn replicaset_releases_non_matching_pods() {
    scenario(|c| async move {
        c.create("/api/v1/nodes", &node("n1", "{}", "[]", "64")).await.unwrap();
        let rs = c
            .create(RS, &v(r#"{"metadata":{"name":"rel"},"spec":{"replicas":2,"selector":{"matchLabels":{"app":"x"}},"template":{"metadata":{"labels":{"app":"x"}},"spec":{"containers":[{"name":"c","image":"i"}]}}}}"#))
            .await
            .unwrap();
        wait_until("2 pods", || async { live_pods(&c).await.len() == 2 }).await;
        let victim = name(&live_pods(&c).await[0]).to_string();
        let path = alloc::format!("{PODS}/{victim}");
        c.patch(&path, MERGE, &v(r#"{"metadata":{"labels":{"app":"y"}}}"#)).await.unwrap();
        wait_until("released and replaced", || async {
            let p = c.get(&path).await.unwrap();
            controller_ref(&p).is_none() && live_pods(&c).await.len() == 3
        })
        .await;
        // Matching again: adopted back, so the set is one too many and shrinks.
        c.patch(&path, MERGE, &v(r#"{"metadata":{"labels":{"app":"x"}}}"#)).await.unwrap();
        wait_until("adopted", || async { c.get(&path).await.ok().and_then(|p| controller_ref(&p).map(|r| str_at(r, &["uid"]) == uid(&rs))).unwrap_or(false) || c.get(&path).await.is_err() }).await;
        wait_until("two again", || async { live_pods(&c).await.len() == 2 }).await;
    });
}

#[test]
fn delete_with_orphan_propagation_keeps_dependents() {
    scenario(|c| async move {
        c.create("/api/v1/nodes", &node("n1", "{}", "[]", "64")).await.unwrap();
        let rs = c
            .create(RS, &v(r#"{"metadata":{"name":"orph"},"spec":{"replicas":2,"selector":{"matchLabels":{"app":"o"}},"template":{"metadata":{"labels":{"app":"o"}},"spec":{"containers":[{"name":"c","image":"i"}]}}}}"#))
            .await
            .unwrap();
        wait_until("2 pods", || async { live_pods(&c).await.len() == 2 }).await;
        c.delete(&alloc::format!("{RS}/orph?propagationPolicy=Orphan")).await.unwrap();
        wait_until("rs gone", || async { c.get(&alloc::format!("{RS}/orph")).await.is_err() }).await;
        sleep(300).await;
        let pods = live_pods(&c).await;
        assert_eq!(pods.len(), 2, "orphaned pods survive");
        assert!(pods.iter().all(|p| controller_ref(p).is_none() && !p.pointer(&["metadata", "ownerReferences"]).and_then(Value::as_array).is_some_and(|a| a.iter().any(|r| str_at(r, &["uid"]) == uid(&rs)))));
    });
}

#[test]
fn delete_with_foreground_propagation_waits_for_dependents() {
    scenario(|c| async move {
        c.create("/api/v1/nodes", &node("n1", "{}", "[]", "64")).await.unwrap();
        c.create(RS, &v(r#"{"metadata":{"name":"fg"},"spec":{"replicas":2,"selector":{"matchLabels":{"app":"f"}},"template":{"metadata":{"labels":{"app":"f"}},"spec":{"containers":[{"name":"c","image":"i"}]}}}}"#)).await.unwrap();
        wait_until("2 pods", || async { live_pods(&c).await.len() == 2 }).await;
        let names: Vec<String> = live_pods(&c).await.iter().map(|p| name(p).to_string()).collect();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        hold_delete(&names);
        c.delete(&alloc::format!("{RS}/fg?propagationPolicy=Foreground")).await.unwrap();
        let rs = c.get(&alloc::format!("{RS}/fg")).await.unwrap();
        assert!(deleting(&rs), "kept with a deletionTimestamp");
        sleep(400).await;
        assert!(c.get(&alloc::format!("{RS}/fg")).await.is_ok(), "waits while its pods are terminating");
        release_delete(&names);
        wait_until("rs and pods gone", || async { c.get(&alloc::format!("{RS}/fg")).await.is_err() && all_pods_empty(&c).await }).await;
    });
}

async fn all_pods_empty(c: &InProcess) -> bool {
    items(&c.list(PODS, "").await.unwrap()).is_empty()
}

#[test]
fn scheduler_preempts_lower_priority_pods() {
    scenario(|c| async move {
        let mut n = node("n1", "{}", "[]", "64");
        n.entry_object("status").entry_object("allocatable").set("example.com/slot", Value::from("2"));
        c.create("/api/v1/nodes", &n).await.unwrap();
        for (name, value) in [("lo", 10), ("hi", 1000)] {
            c.create("/apis/scheduling.k8s.io/v1/priorityclasses", &v(&alloc::format!(r#"{{"metadata":{{"name":"{name}"}},"value":{value}}}"#))).await.unwrap();
        }
        let mk = |n: &str, class: &str, slots: &str| v(&alloc::format!(r#"{{"metadata":{{"name":"{n}"}},"spec":{{"priorityClassName":"{class}","containers":[{{"name":"c","image":"i","resources":{{"requests":{{"example.com/slot":"{slots}"}},"limits":{{"example.com/slot":"{slots}"}}}}}}]}}}}"#));
        c.create(PODS, &mk("victim", "lo", "1")).await.unwrap();
        c.create(PODS, &mk("bystander", "hi", "1")).await.unwrap();
        wait_until("both bound", || async {
            let mut bound = true;
            for n in ["victim", "bystander"] {
                bound &= !str_at(&c.get(&alloc::format!("{PODS}/{n}")).await.unwrap(), &["spec", "nodeName"]).is_empty();
            }
            bound
        })
        .await;
        assert_eq!(int_at(&c.get(&alloc::format!("{PODS}/victim")).await.unwrap(), &["spec", "priority"], -1), 10);

        c.create(PODS, &mk("preemptor", "hi", "1")).await.unwrap();
        wait_until("preemptor bound after the victim went", || async {
            let p = c.get(&alloc::format!("{PODS}/preemptor")).await.unwrap();
            str_at(&p, &["spec", "nodeName"]) == "n1" && c.get(&alloc::format!("{PODS}/victim")).await.is_err()
        })
        .await;
        let p = c.get(&alloc::format!("{PODS}/preemptor")).await.unwrap();
        assert_eq!(str_at(&p, &["status", "nominatedNodeName"]), "n1");
        assert!(c.get(&alloc::format!("{PODS}/bystander")).await.is_ok(), "equal priority is never preempted");
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

#[test]
fn deployment_paused_blocks_rollout_until_resumed() {
    scenario(|c| async move {
        c.create("/api/v1/nodes", &node("n1", "{}", "[]", "4")).await.unwrap();
        c.create(DEPLOYMENTS, &deployment(2, "app:1", "")).await.unwrap();
        wait_until("complete at 2", || complete(&c, 2)).await;
        c.patch(&alloc::format!("{DEPLOYMENTS}/web"), MERGE, &v(r#"{"spec":{"paused":true}}"#)).await.unwrap();
        set_image(&c, "app:2").await;
        wait_until("DeploymentPaused", || async { cond(&deployment_status(&c).await, "Progressing").is_some_and(|p| str_at(p, &["reason"]) == "DeploymentPaused") }).await;
        sleep(400).await;
        assert_eq!(replicasets_now(&c).await.len(), 1, "no new ReplicaSet while paused");
        // Scaling still works while paused.
        scale_to(&c, 3).await;
        wait_until("scaled while paused", || async { live_pods(&c).await.len() == 3 && int_at(&replicasets_now(&c).await[0], &["spec", "replicas"], 0) == 3 }).await;
        assert_eq!(replicasets_now(&c).await.len(), 1);
        c.patch(&alloc::format!("{DEPLOYMENTS}/web"), MERGE, &v(r#"{"spec":{"paused":false}}"#)).await.unwrap();
        wait_until("rolled out after resume", || async { replicasets_now(&c).await.len() == 2 && complete(&c, 3).await }).await;
        assert!(live_pods(&c).await.iter().all(|p| p.pointer(&["spec", "containers"]).and_then(Value::as_array).is_some_and(|cs| str_at(&cs[0], &["image"]) == "app:2")));
    });
}

#[test]
fn deployment_progress_deadline_exceeded_then_recovers() {
    scenario(|c| async move {
        c.create("/api/v1/nodes", &node("n1", "{}", "[]", "4")).await.unwrap();
        HOLD_ALL.store(true, Ordering::SeqCst);
        c.create(DEPLOYMENTS, &deployment(2, "app:1", r#","progressDeadlineSeconds":20"#)).await.unwrap();
        // Wait for the replica counts too: a count that changes after the clock moves is
        // progress, and would rightly restart the deadline (the test raced on loaded machines).
        wait_until("Progressing=True with 2 updated replicas", || async {
            let d = deployment_status(&c).await;
            cond(&d, "Progressing").is_some_and(|p| str_at(p, &["status"]) == "True" && str_at(p, &["reason"]) != "NewReplicaSetAvailable") && int_at(&d, &["status", "replicas"], 0) == 2 && int_at(&d, &["status", "updatedReplicas"], 0) == 2
        })
        .await;
        let d = deployment_status(&c).await;
        assert_eq!(str_at(cond(&d, "Available").unwrap(), &["reason"]), "MinimumReplicasUnavailable");
        sleep(300).await;
        advance_clock(10);
        sleep(400).await;
        assert_eq!(str_at(cond(&deployment_status(&c).await, "Progressing").unwrap(), &["status"]), "True", "not yet due");
        advance_clock(15);
        wait_until("deadline exceeded", || async { cond(&deployment_status(&c).await, "Progressing").is_some_and(|p| str_at(p, &["status"]) == "False" && str_at(p, &["reason"]) == "ProgressDeadlineExceeded") }).await;
        HOLD_ALL.store(false, Ordering::SeqCst);
        wait_until("recovered", || complete(&c, 2)).await;
    });
}

#[test]
fn deployment_min_ready_seconds_gates_availability() {
    scenario(|c| async move {
        c.create("/api/v1/nodes", &node("n1", "{}", "[]", "4")).await.unwrap();
        c.create(DEPLOYMENTS, &deployment(2, "app:1", r#","minReadySeconds":30"#)).await.unwrap();
        wait_until("2 ready, none available", || async {
            let d = deployment_status(&c).await;
            int_at(&d, &["status", "readyReplicas"], 0) == 2 && int_at(&d, &["status", "availableReplicas"], -1) == 0
        })
        .await;
        sleep(300).await;
        let d = deployment_status(&c).await;
        assert_eq!(int_at(&d, &["status", "availableReplicas"], -1), 0);
        assert_eq!(str_at(cond(&d, "Available").unwrap(), &["status"]), "False");
        assert_eq!(int_at(&replicasets_now(&c).await[0], &["status", "availableReplicas"], -1), 0);
        advance_clock(31);
        wait_until("available after minReadySeconds", || complete(&c, 2)).await;
    });
}

#[test]
fn pdb_status_and_eviction() {
    scenario(|c| async move {
        let pp = "/api/v1/namespaces/default/pods";
        let bp = "/apis/policy/v1/namespaces/default/poddisruptionbudgets";
        for n in ["a", "b", "c"] {
            c.create(pp, &v(&alloc::format!(r#"{{"metadata":{{"name":"{n}","labels":{{"app":"x"}}}},"spec":{{"nodeName":"n1","containers":[{{"name":"c","image":"i"}}]}}}}"#))).await.unwrap();
        }
        c.create(bp, &v(r#"{"metadata":{"name":"b"},"spec":{"minAvailable":2,"selector":{"matchLabels":{"app":"x"}}}}"#)).await.unwrap();
        wait_until("pdb status", || async {
            let b = c.get(&alloc::format!("{bp}/b")).await.unwrap();
            int_at(&b, &["status", "disruptionsAllowed"], -1) == 1 && int_at(&b, &["status", "currentHealthy"], -1) == 3 && int_at(&b, &["status", "desiredHealthy"], -1) == 2 && int_at(&b, &["status", "expectedPods"], -1) == 3 && int_at(&b, &["status", "observedGeneration"], -1) == 1
        })
        .await;
        let ev = |n: &str| alloc::format!(r#"{{"apiVersion":"policy/v1","kind":"Eviction","metadata":{{"name":"{n}","namespace":"default"}},"deleteOptions":{{"gracePeriodSeconds":0}}}}"#);
        c.create(&alloc::format!("{pp}/a/eviction"), &v(&ev("a"))).await.unwrap();
        let b = c.get(&alloc::format!("{bp}/b")).await.unwrap();
        assert!(b.pointer(&["status", "disruptedPods", "a"]).is_some());
        let e = c.create(&alloc::format!("{pp}/b/eviction"), &v(&ev("b"))).await.unwrap_err();
        assert_eq!(e.code, 429, "{}", e.message);
        wait_until("pod a gone", || async { c.get(&alloc::format!("{pp}/a")).await.is_err() }).await;
        // Two healthy pods left and two wanted: nothing may be evicted until a replacement is Ready.
        wait_until("allowance 0", || async {
            let b = c.get(&alloc::format!("{bp}/b")).await.unwrap();
            int_at(&b, &["status", "currentHealthy"], -1) == 2 && int_at(&b, &["status", "disruptionsAllowed"], -1) == 0 && b.pointer(&["status", "disruptedPods"]).is_none()
        })
        .await;
        c.create(pp, &v(r#"{"metadata":{"name":"d","labels":{"app":"x"}},"spec":{"nodeName":"n1","containers":[{"name":"c","image":"i"}]}}"#)).await.unwrap();
        wait_until("allowance back", || async { int_at(&c.get(&alloc::format!("{bp}/b")).await.unwrap(), &["status", "disruptionsAllowed"], -1) == 1 }).await;
    });
}

#[test]
fn expired_bootstrap_tokens_are_deleted() {
    scenario(|c| async move {
        let b64 = |s: &str| kr_fmt::base64::encode(s.as_bytes());
        let mk = |id: &str, exp: &str| alloc::format!(r#"{{"metadata":{{"name":"bootstrap-token-{id}"}},"type":"bootstrap.kubernetes.io/token","data":{{"token-id":"{}","expiration":"{}"}}}}"#, b64(id), b64(exp));
        let p = "/api/v1/namespaces/kube-system/secrets";
        c.create(p, &parse_str(&mk("aaaaaa", "2001-01-01T00:00:00Z")).unwrap()).await.unwrap();
        c.create(p, &parse_str(&mk("bbbbbb", "2999-01-01T00:00:00Z")).unwrap()).await.unwrap();
        c.create(p, &parse_str(r#"{"metadata":{"name":"other"},"type":"Opaque"}"#).unwrap()).await.unwrap();
        assert_eq!(crate::gc::expire_tokens(&c, 1_700_000_000).await, 1);
        let names: Vec<String> = items(&c.list(p, "").await.unwrap()).iter().map(|s| name(s).to_string()).collect();
        assert!(!names.iter().any(|n| n == "bootstrap-token-aaaaaa") && names.iter().any(|n| n == "bootstrap-token-bbbbbb") && names.iter().any(|n| n == "other"));
    });
}

// ---- HorizontalPodAutoscaler ----

const HPAS: &str = "/apis/autoscaling/v2/namespaces/default/horizontalpodautoscalers";

/// One scrape of every live pod: each has used `rate` cores more over the last 15 virtual seconds.
fn feed(api: &ApiServer, pods: &[Value], cum: &mut alloc::collections::BTreeMap<String, f64>, rate: f64) {
    use kr_apiserver::metrics::{CtrSample, Scrape};
    let ts = CLOCK.load(Ordering::SeqCst) * 1000;
    let ctrs: Vec<CtrSample> = pods
        .iter()
        .map(|p| {
            let c = cum.entry(name(p).to_string()).or_insert(0.0);
            *c += rate * 15.0;
            CtrSample { ns: "default".into(), pod: name(p).to_string(), container: "c".into(), cpu_secs: *c, mem: 32 << 20, ts_ms: ts }
        })
        .collect();
    api.metrics.apply("n1", &Scrape { node_cpu: Some((ctrs.iter().map(|c| c.cpu_secs).sum(), ts)), node_mem: Some(1 << 30), ctrs, error: false });
}

/// Steps the virtual clock 15 s per round (the controller period in virtual time), feeding metrics.
async fn drive_metrics(c: &InProcess, rate: f64, rounds: usize) {
    let api = API.with(|a| a.borrow().clone().unwrap());
    let mut cum = alloc::collections::BTreeMap::new();
    for _ in 0..rounds {
        let pods = live_pods(c).await;
        feed(&api, &pods, &mut cum, rate);
        advance_clock(15);
        sleep(130).await;
    }
}

async fn deployment_replicas(c: &InProcess) -> i64 {
    int_at(&deployment_status(c).await, &["spec", "replicas"], -1)
}

#[test]
fn hpa_scales_a_deployment_up_to_max_and_back_down() {
    scenario(|c| async move {
        c.create("/api/v1/nodes", &node("n1", "{}", "[]", "16")).await.unwrap();
        c.create(DEPLOYMENTS, &deployment(2, "nginx:1", "")).await.unwrap();
        wait_until("2 running pods", || async { live_pods(&c).await.iter().filter(|p| str_at(p, &["status", "phase"]) == "Running").count() == 2 }).await;
        let hpa = v(r#"{"metadata":{"name":"web"},"spec":{"scaleTargetRef":{"apiVersion":"apps/v1","kind":"Deployment","name":"web"},"minReplicas":2,"maxReplicas":6,"metrics":[{"type":"Resource","resource":{"name":"cpu","target":{"type":"Utilization","averageUtilization":50}}}],"behavior":{"scaleDown":{"stabilizationWindowSeconds":0}}}}"#);
        c.create(HPAS, &hpa).await.unwrap();

        // 90% of the requests against a 50% target: up to the maximum.
        let cc = c.clone();
        let feeder = spawn(async move { drive_metrics(&cc, 0.09, 60).await });
        wait_until("scaled up to 6", || async { deployment_replicas(&c).await == 6 }).await;
        wait_until("6 pods running", || async { live_pods(&c).await.iter().filter(|p| str_at(p, &["status", "phase"]) == "Running").count() == 6 }).await;
        let h = c.get(&alloc::format!("{HPAS}/web")).await.unwrap();
        assert!(int_at(&h, &["status", "desiredReplicas"], -1) >= 4, "{h:?}");
        assert_eq!(str_at(cond(&h, "ScalingActive").unwrap(), &["status"]), "True");
        assert_eq!(str_at(cond(&h, "AbleToScale").unwrap(), &["status"]), "True");
        assert!(h.pointer(&["status", "currentMetrics"]).and_then(Value::as_array).is_some_and(|m| !m.is_empty()), "{h:?}");
        feeder.abort();

        // Load drops to 10%: back to the minimum (no stabilization window in this HPA).
        let cc = c.clone();
        let feeder = spawn(async move { drive_metrics(&cc, 0.01, 80).await });
        wait_until("scaled down to 2", || async { deployment_replicas(&c).await == 2 }).await;
        feeder.abort();
        let h = c.get(&alloc::format!("{HPAS}/web")).await.unwrap();
        assert!(h.pointer(&["status", "conditions"]).and_then(Value::as_array).is_some_and(|c| !c.is_empty()));
        assert!(h.pointer(&["status", "lastScaleTime"]).is_some());
    });
}

#[test]
fn hpa_v1_form_unsupported_metrics_and_missing_targets_report_conditions() {
    scenario(|c| async move {
        c.create("/api/v1/nodes", &node("n1", "{}", "[]", "16")).await.unwrap();
        c.create(DEPLOYMENTS, &deployment(2, "nginx:1", "")).await.unwrap();
        wait_until("2 running pods", || async { live_pods(&c).await.iter().filter(|p| str_at(p, &["status", "phase"]) == "Running").count() == 2 }).await;
        // An autoscaling/v1 object: a CPU percentage instead of metrics.
        let v1 = v(r#"{"apiVersion":"autoscaling/v1","kind":"HorizontalPodAutoscaler","metadata":{"name":"old"},"spec":{"scaleTargetRef":{"apiVersion":"apps/v1","kind":"Deployment","name":"web"},"minReplicas":2,"maxReplicas":3,"targetCPUUtilizationPercentage":50}}"#);
        c.create("/apis/autoscaling/v1/namespaces/default/horizontalpodautoscalers", &v1).await.unwrap();
        // Only unsupported metric types, and a target that does not exist.
        c.create(HPAS, &v(r#"{"metadata":{"name":"custom"},"spec":{"scaleTargetRef":{"apiVersion":"apps/v1","kind":"Deployment","name":"web"},"minReplicas":1,"maxReplicas":3,"metrics":[{"type":"Pods","pods":{"metric":{"name":"qps"},"target":{"type":"AverageValue","averageValue":"10"}}}]}}"#)).await.unwrap();
        c.create(HPAS, &v(r#"{"metadata":{"name":"nothing"},"spec":{"scaleTargetRef":{"apiVersion":"apps/v1","kind":"Deployment","name":"nope"},"minReplicas":1,"maxReplicas":3}}"#)).await.unwrap();
        let cc = c.clone();
        let feeder = spawn(async move { drive_metrics(&cc, 0.09, 40).await });
        wait_until("v1 HPA scaled to its maximum", || async { deployment_replicas(&c).await == 3 }).await;
        let h = c.get("/apis/autoscaling/v1/namespaces/default/horizontalpodautoscalers/old").await.unwrap();
        assert!(h.pointer(&["status", "currentCPUUtilizationPercentage"]).is_some() || int_at(&h, &["status", "desiredReplicas"], 0) >= 2, "{h:?}");
        let custom = c.get(&alloc::format!("{HPAS}/custom")).await.unwrap();
        let active = cond(&custom, "ScalingActive").unwrap();
        assert_eq!(str_at(active, &["status"]), "False");
        // A Pods metric is supported now; without a metrics adapter it fails to be read.
        assert_eq!(str_at(active, &["reason"]), "FailedGetPodsMetric");
        assert!(str_at(active, &["message"]).contains("unable to get metric qps"), "{active:?}");
        let nothing = c.get(&alloc::format!("{HPAS}/nothing")).await.unwrap();
        let able = cond(&nothing, "AbleToScale").unwrap();
        assert_eq!((str_at(able, &["status"]), str_at(able, &["reason"])), ("False", "FailedGetScale"));
        feeder.abort();
    });
}

// ---- custom and external metrics through an adapter ----

std::thread_local! {
    /// What the stand-in metrics adapter answers: (path prefix, MetricValueList items JSON).
    static ADAPTER: core::cell::RefCell<Vec<(String, String)>> = const { core::cell::RefCell::new(Vec::new()) };
}

/// The in-process client, except that `custom.metrics.k8s.io` and `external.metrics.k8s.io` are
/// answered by [`ADAPTER`] (a real adapter would be an APIService behind the aggregator).
#[derive(Clone)]
struct WithAdapter(InProcess);

impl WithAdapter {
    fn answer(path: &str) -> Option<Value> {
        if !(path.starts_with("/apis/custom.metrics.k8s.io") || path.starts_with("/apis/external.metrics.k8s.io")) {
            return None;
        }
        ADAPTER.with(|a| a.borrow().iter().find(|(p, _)| path.starts_with(p.as_str())).map(|(_, items)| v(&alloc::format!(r#"{{"kind":"MetricValueList","items":{items}}}"#))))
    }
}

impl Client for WithAdapter {
    async fn get(&self, path: &str) -> kr_apiserver::client::Result<Value> {
        match Self::answer(path) {
            Some(l) => Ok(l),
            None if path.starts_with("/apis/custom.metrics.k8s.io") || path.starts_with("/apis/external.metrics.k8s.io") => Err(kr_apiserver::object::ApiError::new(404, "NotFound", alloc::format!("path \"{path}\" not found"))),
            None => self.0.get(path).await,
        }
    }
    async fn list(&self, path: &str, query: &str) -> kr_apiserver::client::Result<Value> {
        match Self::answer(path) {
            Some(l) => Ok(l),
            None if path.starts_with("/apis/custom.metrics.k8s.io") || path.starts_with("/apis/external.metrics.k8s.io") => Err(kr_apiserver::object::ApiError::new(404, "NotFound", alloc::format!("path \"{path}\" not found"))),
            None => self.0.list(path, query).await,
        }
    }
    async fn create(&self, path: &str, obj: &Value) -> kr_apiserver::client::Result<Value> {
        self.0.create(path, obj).await
    }
    async fn update(&self, path: &str, obj: &Value) -> kr_apiserver::client::Result<Value> {
        self.0.update(path, obj).await
    }
    async fn patch(&self, path: &str, content_type: &str, patch: &Value) -> kr_apiserver::client::Result<Value> {
        self.0.patch(path, content_type, patch).await
    }
    async fn delete(&self, path: &str) -> kr_apiserver::client::Result<Value> {
        self.0.delete(path).await
    }
    async fn watch(&self, path: &str, query: &str) -> kr_apiserver::client::Result<kr_apiserver::client::Watch> {
        self.0.watch(path, query).await
    }
}

/// [`scenario`] with the controllers talking to the API through [`WithAdapter`].
fn scenario_adapter<F, Fut>(f: F)
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
    ADAPTER.with(|a| a.borrow_mut().clear());
    let api = Rc::new(ApiServer::new(kr_store::Store::in_memory(), || CLOCK.load(Ordering::SeqCst), rng, "127.0.0.1:6443".to_string()).unwrap());
    API.with(|a| *a.borrow_mut() = Some(api.clone()));
    let c = InProcess::new(api, "test");
    block_on(async move {
        let ctl = spawn(run_all_with(WithAdapter(c.clone()), cfg()));
        let kubelet = spawn(kubelet(c.clone()));
        f(c).await;
        ctl.abort();
        kubelet.abort();
    });
}

fn adapter(prefix: &str, items: &str) {
    ADAPTER.with(|a| {
        let mut a = a.borrow_mut();
        a.retain(|(p, _)| p != prefix);
        a.push((prefix.to_string(), items.to_string()));
    });
}

#[test]
fn hpa_scales_on_pods_and_external_metrics_and_reports_events_and_history() {
    scenario_adapter(|c| async move {
        c.create("/api/v1/nodes", &node("n1", "{}", "[]", "32")).await.unwrap();
        c.create(DEPLOYMENTS, &deployment(2, "nginx:1", "")).await.unwrap();
        wait_until("2 running pods", || async { live_pods(&c).await.iter().filter(|p| str_at(p, &["status", "phase"]) == "Running").count() == 2 }).await;
        // Every pod reports 30 qps against a target of 10 per pod: x3.
        let pods = live_pods(&c).await;
        let items: Vec<String> = pods.iter().map(|p| alloc::format!(r#"{{"describedObject":{{"kind":"Pod","name":"{}"}},"metric":{{"name":"qps"}},"value":"30"}}"#, name(p))).collect();
        adapter("/apis/custom.metrics.k8s.io/v1beta1/namespaces/default/pods/*/qps", &alloc::format!("[{}]", items.join(",")));
        // An external queue holding 100 messages, 50 wanted per pod: also asks for more.
        adapter("/apis/external.metrics.k8s.io/v1beta1/namespaces/default/queue_depth", r#"[{"metricName":"queue_depth","value":"100"}]"#);
        let hpa = v(r#"{"metadata":{"name":"web"},"spec":{"scaleTargetRef":{"apiVersion":"apps/v1","kind":"Deployment","name":"web"},"minReplicas":2,"maxReplicas":5,"metrics":[{"type":"Pods","pods":{"metric":{"name":"qps"},"target":{"type":"AverageValue","averageValue":"10"}}},{"type":"External","external":{"metric":{"name":"queue_depth"},"target":{"type":"AverageValue","averageValue":"50"}}}]}}"#);
        c.create(HPAS, &hpa).await.unwrap();
        let cc = c.clone();
        let feeder = spawn(async move { drive_metrics(&cc, 0.01, 20).await });
        // qps asks for ceil(30/10 * 2) = 6, the queue for ceil(100/50) = 2: the maximum wins, bounded by maxReplicas.
        wait_until("scaled to the maximum of 5", || async { deployment_replicas(&c).await == 5 }).await;
        feeder.abort();
        let h = c.get(&alloc::format!("{HPAS}/web")).await.unwrap();
        let cm = h.pointer(&["status", "currentMetrics"]).and_then(Value::as_array).unwrap();
        let pods_m = cm.iter().find(|m| str_at(m, &["type"]) == "Pods").unwrap();
        assert_eq!(str_at(pods_m, &["pods", "metric", "name"]), "qps");
        assert_eq!(str_at(pods_m, &["pods", "current", "averageValue"]), "30");
        let ext = cm.iter().find(|m| str_at(m, &["type"]) == "External").unwrap();
        assert!(str_at(ext, &["external", "current", "averageValue"]) == "50" || str_at(ext, &["external", "current", "averageValue"]) == "34", "{ext:?}");
        assert_eq!(str_at(cond(&h, "ScalingActive").unwrap(), &["status"]), "True");
        // An Event for the rescale, and the history persisted for the next run.
        let evs = items_of(&c.list("/api/v1/namespaces/default/events", "").await.unwrap());
        assert!(evs.iter().any(|e| str_at(e, &["reason"]) == "SuccessfulRescale" && str_at(e, &["involvedObject", "name"]) == "web" && str_at(e, &["message"]).starts_with("New size:")), "{evs:?}");
        let hist = str_at(&h, &["status", "krHistory"]);
        assert!(hist.contains("\"recs\":[[") && hist.contains("\"events\":[["), "{hist}");
    });
}

fn items_of(l: &Value) -> Vec<Value> {
    items(l)
}

#[test]
fn hpa_never_scales_down_when_a_metric_cannot_be_read() {
    scenario_adapter(|c| async move {
        c.create("/api/v1/nodes", &node("n1", "{}", "[]", "32")).await.unwrap();
        c.create(DEPLOYMENTS, &deployment(4, "nginx:1", "")).await.unwrap();
        wait_until("4 running pods", || async { live_pods(&c).await.iter().filter(|p| str_at(p, &["status", "phase"]) == "Running").count() == 4 }).await;
        // CPU is idle (would scale down to 1), but the external metric has no adapter: keep 4.
        let hpa = v(r#"{"metadata":{"name":"web"},"spec":{"scaleTargetRef":{"apiVersion":"apps/v1","kind":"Deployment","name":"web"},"minReplicas":1,"maxReplicas":8,"metrics":[{"type":"Resource","resource":{"name":"cpu","target":{"type":"Utilization","averageUtilization":50}}},{"type":"External","external":{"metric":{"name":"missing"},"target":{"type":"Value","value":"10"}}}],"behavior":{"scaleDown":{"stabilizationWindowSeconds":0}}}}"#);
        c.create(HPAS, &hpa).await.unwrap();
        let cc = c.clone();
        let feeder = spawn(async move { drive_metrics(&cc, 0.005, 14).await });
        wait_until("the HPA has evaluated", || async {
            let h = c.get(&alloc::format!("{HPAS}/web")).await.unwrap();
            cond(&h, "ScalingActive").is_some_and(|c| str_at(c, &["message"]).contains("another metric failed"))
        })
        .await;
        sleep(300).await;
        assert_eq!(deployment_replicas(&c).await, 4, "an unreadable metric blocks scale-down");
        feeder.abort();
    });
}

#[test]
fn gc_collects_claims_and_configmaps_of_deleted_owners() {
    scenario(|c| async move {
        let p = c.create(PODS, &kr_fmt::json::parse_str(r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"owner","namespace":"default"},"spec":{"containers":[{"name":"c","image":"x"}]}}"#).unwrap()).await.unwrap();
        let uid = str_at(&p, &["metadata", "uid"]).to_string();
        let owned = |kind: &str, name: &str| {
            let spec = if kind == "PersistentVolumeClaim" { r#","spec":{"accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"1Mi"}}}"# } else { "" };
            kr_fmt::json::parse_str(&alloc::format!(r#"{{"apiVersion":"v1","kind":"{kind}","metadata":{{"name":"{name}","namespace":"default","ownerReferences":[{{"apiVersion":"v1","kind":"Pod","name":"owner","uid":"{uid}","controller":true,"blockOwnerDeletion":true}}]}}{spec}}}"#)).unwrap()
        };
        const PVCS: &str = "/api/v1/namespaces/default/persistentvolumeclaims";
        const CMS: &str = "/api/v1/namespaces/default/configmaps";
        c.create(PVCS, &owned("PersistentVolumeClaim", "owner-v")).await.unwrap();
        c.create(CMS, &owned("ConfigMap", "owner-cm")).await.unwrap();
        // Owner alive: nothing is collected.
        kr_rt::exec::sleep(300).await;
        assert!(c.get(&alloc::format!("{PVCS}/owner-v")).await.is_ok());
        c.delete(&alloc::format!("{PODS}/owner")).await.unwrap();
        wait_until("claim and configmap collected", || async {
            let gone = |o: Result<Value, _>| o.is_err() || o.is_ok_and(|v: Value| !str_at(&v, &["metadata", "deletionTimestamp"]).is_empty());
            gone(c.get(&alloc::format!("{PVCS}/owner-v")).await) && gone(c.get(&alloc::format!("{CMS}/owner-cm")).await)
        })
        .await;
    });
}
