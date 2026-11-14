//! Helm controller scenarios (ADR-061): Jobs, supporting objects, upgrade on change, uninstall on delete.

use crate::helm::{chart_configs, charts, DEFAULT_IMAGE, FINALIZER};
use crate::tests::*;
use crate::util::*;
use alloc::string::ToString;
use core::sync::atomic::Ordering;
use kr_apiserver::client::{Client, InProcess};
use kr_fmt::json::Value;

const NS: &str = "kube-system";
const CHART_LABEL: &str = "helmcharts.helm.cattle.io/chart";
const CRB: &str = "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/helm-kube-system-web";

fn job_path(n: &str) -> alloc::string::String {
    alloc::format!("{}/{n}", jobs(Some(NS)))
}

async fn get_ok(c: &InProcess, p: &str) -> Option<Value> {
    c.get(p).await.ok()
}

async fn sys_pods(c: &InProcess) -> alloc::vec::Vec<Value> {
    items(&c.list(&pods(Some(NS)), "").await.unwrap()).into_iter().filter(|p| !deleting(p)).collect()
}

fn hash_of(j: &Value) -> alloc::string::String {
    str_at(j, &["metadata", "annotations", "helmcharts.helm.cattle.io/configHash"]).to_string()
}

/// Whether `p` is a pod of `job`. Select by the owner's uid, not by the chart label or Job name:
/// after a Job is deleted (upgrade, uninstall) its pod can stay around for a GC cycle, carrying the
/// same label, and a replacement Job can reuse the name.
fn pod_of_job(p: &Value, job: &Value) -> bool {
    controller_ref(p).is_some_and(|r| str_at(r, &["kind"]) == "Job" && str_at(r, &["uid"]) == str_at(job, &["metadata", "uid"]))
}

#[test]
fn install_upgrade_and_uninstall() {
    scenario(|c| async move {
        c.create("/api/v1/nodes", &node("n1", "{}", "[]", "8")).await.unwrap();
        wait_until("CRDs served", || async { c.get(&charts(None)).await.is_ok() && c.get(&chart_configs(None)).await.is_ok() }).await;
        let chart = v(r#"{"apiVersion":"helm.cattle.io/v1","kind":"HelmChart","metadata":{"name":"web","namespace":"kube-system"},"spec":{"chart":"nginx","repo":"https://example.test/charts","version":"1.0.0","targetNamespace":"web","createNamespace":true,"valuesContent":"replicas: 1\n"}}"#);
        c.create(&charts(Some(NS)), &chart).await.unwrap();
        let cp = alloc::format!("{}/web", charts(Some(NS)));

        // Install Job, support objects, finalizer, status.
        wait_until("install job", || async { get_ok(&c, &job_path("helm-install-web")).await.is_some() }).await;
        let j1 = c.get(&job_path("helm-install-web")).await.unwrap();
        assert_eq!(str_at(&j1, &["spec", "template", "spec", "serviceAccountName"]), "helm-web");
        let cont = &j1.pointer(&["spec", "template", "spec", "containers"]).and_then(Value::as_array).unwrap()[0];
        assert_eq!(str_at(cont, &["image"]), DEFAULT_IMAGE);
        assert!(get_ok(&c, "/api/v1/namespaces/kube-system/serviceaccounts/helm-web").await.is_some());
        assert!(get_ok(&c, CRB).await.is_some());
        let cm = c.get("/api/v1/namespaces/kube-system/configmaps/chart-values-web").await.unwrap();
        assert_eq!(str_at(&cm, &["data", "values-01_HelmChart.yaml"]), "replicas: 1\n");
        wait_until("finalizer and status", || async {
            let o = c.get(&cp).await.unwrap();
            o.pointer(&["metadata", "finalizers"]).and_then(Value::as_array).is_some_and(|f| f.iter().any(|x| x.as_str() == Some(FINALIZER))) && str_at(&o, &["status", "jobName"]) == "helm-install-web" && cond(&o, "JobCreated").is_some()
        })
        .await;

        // A HelmChartConfig changes the values: the Job is replaced (upgrade).
        let h1 = hash_of(&j1);
        c.create(&chart_configs(Some(NS)), &v(r#"{"apiVersion":"helm.cattle.io/v1","kind":"HelmChartConfig","metadata":{"name":"web","namespace":"kube-system"},"spec":{"valuesContent":"replicas: 3\n"}}"#)).await.unwrap();
        wait_until("job replaced for the config", || async { get_ok(&c, &job_path("helm-install-web")).await.is_some_and(|j| hash_of(&j) != h1) }).await;
        wait_until("values updated", || async {
            let cm = c.get("/api/v1/namespaces/kube-system/configmaps/chart-values-web").await.unwrap();
            str_at(&cm, &["data", "values-02_HelmChartConfig.yaml"]) == "replicas: 3\n"
        })
        .await;

        // A new chart version replaces it again.
        let h2 = hash_of(&c.get(&job_path("helm-install-web")).await.unwrap());
        let mut cur = c.get(&cp).await.unwrap();
        cur.entry_object("spec").set("version", Value::from("1.1.0"));
        c.update(&cp, &cur).await.unwrap();
        wait_until("job replaced for the version", || async { get_ok(&c, &job_path("helm-install-web")).await.is_some_and(|j| hash_of(&j) != h2) }).await;

        // Deleting the chart runs the uninstall Job first; the chart stays until it completed.
        c.delete(&cp).await.unwrap();
        wait_until("uninstall job", || async { get_ok(&c, &job_path("helm-delete-web")).await.is_some() }).await;
        assert!(get_ok(&c, &job_path("helm-install-web")).await.is_none(), "install job removed");
        let del = c.get(&job_path("helm-delete-web")).await.unwrap();
        let args = del.pointer(&["spec", "template", "spec", "containers"]).and_then(Value::as_array).unwrap()[0].get("args").and_then(Value::as_array).unwrap().to_vec();
        assert_eq!(args.len(), 1);
        assert_eq!(args[0].as_str(), Some("delete"));
        assert!(get_ok(&c, &cp).await.is_some(), "chart waits for the uninstall");
        // Let the Job's pod succeed.
        wait_until("uninstall pod", || async { sys_pods(&c).await.iter().any(|p| pod_of_job(p, &del)) }).await;
        let pods = sys_pods(&c).await;
        let pod = pods.iter().find(|p| pod_of_job(p, &del)).unwrap();
        c.patch(&alloc::format!("/api/v1/namespaces/{NS}/pods/{}", name(pod)), "application/merge-patch+json", &v(r#"{"metadata":{"annotations":{"test/outcome":"succeed"}}}"#)).await.unwrap();
        FINISH.store(true, Ordering::SeqCst);
        wait_until("chart gone", || async { get_ok(&c, &cp).await.is_none() }).await;
        wait_until("binding removed", || async { get_ok(&c, CRB).await.is_none() }).await;
    });
}

#[test]
fn disabled_controller_does_nothing() {
    scenario_with(
        |mut cfg| {
            cfg.disabled.helm_controller = true;
            cfg
        },
        |c| async move {
            kr_rt::exec::sleep(300).await;
            assert!(c.get(&charts(None)).await.is_err(), "no CRD without the controller");
        },
    );
}
