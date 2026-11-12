//! The Helm controller (ADR-061): `helm.cattle.io/v1` `HelmChart` and `HelmChartConfig`, the same
//! resources and the same mechanism as k3s's helm-controller. kr does not render charts: for each
//! HelmChart the controller runs a Job (default image [`DEFAULT_IMAGE`], `rancher/klipper-helm`)
//! that runs `helm` against the cluster.
//!
//! * install/upgrade: Job `helm-install-<name>` in the HelmChart's namespace. A hash of the
//!   HelmChart spec, the HelmChartConfig spec and the image is stored on the Job
//!   (`helmcharts.helm.cattle.io/configHash`); when it changes the Job is replaced, which
//!   upgrades the release.
//! * uninstall: the HelmChart carries the finalizer [`FINALIZER`]; deleting it runs Job
//!   `helm-delete-<name>` and only then lets the HelmChart go.
//! * supporting objects (owned by the HelmChart): ServiceAccount `helm-<name>`, ConfigMap
//!   `chart-values-<name>` (`values-01_HelmChart.yaml`, `values-02_HelmChartConfig.yaml`, mounted at
//!   `/config`), Secret `chart-content-<name>` for `spec.chartContent` (mounted at `/chart`), and
//!   the ClusterRoleBinding `helm-<namespace>-<name>` to `cluster-admin`.
//! * `status.jobName` and the conditions `JobCreated` and `Failed`.
//!
//! The CRDs are installed when the controller starts.

use crate::util::*;
use crate::Config;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_apiserver::client::{Client, Result};
use kr_fmt::json::{self, Value};

pub const GROUP: &str = "helm.cattle.io";
const API_VERSION: &str = "helm.cattle.io/v1";
pub const DEFAULT_IMAGE: &str = "rancher/klipper-helm:v0.9.4-build20250113";
pub const FINALIZER: &str = "wrangler.cattle.io/helm-chart-remove";
const LABEL: &str = "helmcharts.helm.cattle.io/chart";
const HASH_ANN: &str = "helmcharts.helm.cattle.io/configHash";
const CRDS: &str = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions";

pub fn charts(ns: Option<&str>) -> String {
    api_path(GROUP, "v1", ns, "helmcharts")
}

pub fn chart_configs(ns: Option<&str>) -> String {
    api_path(GROUP, "v1", ns, "helmchartconfigs")
}

fn crd(kind: &str, plural: &str, singular: &str, status: bool) -> Value {
    let subs = if status { r#","subresources":{"status":{}}"# } else { "" };
    json::parse_str(&alloc::format!(
        r#"{{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{{"name":"{plural}.{GROUP}"}},"spec":{{"group":"{GROUP}","names":{{"kind":"{kind}","plural":"{plural}","singular":"{singular}"}},"scope":"Namespaced","versions":[{{"name":"v1","served":true,"storage":true{subs},"schema":{{"openAPIV3Schema":{{"type":"object","x-kubernetes-preserve-unknown-fields":true}}}}}}]}}}}"#
    ))
    .unwrap_or(Value::Null)
}

/// Creates the two CRDs if they do not exist.
async fn install_crds<C: Client>(c: &C) {
    for body in [crd("HelmChart", "helmcharts", "helmchart", true), crd("HelmChartConfig", "helmchartconfigs", "helmchartconfig", false)] {
        let _ = c.create(CRDS, &body).await;
    }
}

pub async fn run<C: Client + Clone + 'static>(c: C, cfg: Config) {
    let image = cfg.helm_image.unwrap_or(DEFAULT_IMAGE);
    install_crds(&c).await;
    let q = Queue::new();
    let mut g = Guard::default();
    for (path, query, kind) in [(charts(None), "", 0), (chart_configs(None), "", 0), (jobs(None), "labelSelector=helmcharts.helm.cattle.io/chart", 1)] {
        let q2 = q.clone();
        g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), path, query.to_string(), cfg, move |_, o| {
            if kind == 0 {
                q2.add(&key_of(o));
            } else {
                q2.add(&alloc::format!("{}/{}", namespace(o), str_at(o, &["metadata", "labels", LABEL])));
            }
        })));
    }
    let (c2, c3, q3) = (c.clone(), c.clone(), q.clone());
    drive(
        &cfg,
        &q,
        move |key| {
            let c = c2.clone();
            async move { reconcile(&c, &cfg, image, &key).await }
        },
        move || {
            let (c, q) = (c3.clone(), q3.clone());
            async move {
                if let Ok(l) = c.list(&charts(None), "").await {
                    for o in items(&l) {
                        q.add(&key_of(&o));
                    }
                }
            }
        },
    )
    .await
}

// ---- pure builders ----

fn s(v: &str) -> Value {
    Value::from(v)
}

fn arr(v: Vec<Value>) -> Value {
    Value::Array(v)
}

fn pair(k: &str, v: &str) -> Value {
    obj(alloc::vec![("name", s(k)), ("value", s(v))])
}

fn spec_str<'a>(chart: &'a Value, k: &str) -> &'a str {
    str_at(chart, &["spec", k])
}

fn spec_bool(chart: &Value, k: &str) -> bool {
    chart.pointer(&["spec", k]).and_then(Value::as_bool).unwrap_or(false)
}

/// A scalar rendered the way `helm --set` wants it.
fn scalar(v: &Value) -> String {
    match v {
        Value::String(x) => x.clone(),
        Value::Number(n) => n.raw().to_string(),
        Value::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

pub fn job_name(action: &str, name: &str) -> String {
    alloc::format!("helm-{action}-{name}")
}

fn sa_name(name: &str) -> String {
    alloc::format!("helm-{name}")
}

fn crb_name(ns: &str, name: &str) -> String {
    alloc::format!("helm-{ns}-{name}")
}

fn image_of<'a>(chart: &'a Value, default: &'a str) -> &'a str {
    Some(spec_str(chart, "jobImage")).filter(|i| !i.is_empty()).unwrap_or(default)
}

/// Identifies the desired state of the release: changes when the chart, its configuration or the
/// image changes.
pub fn config_hash(chart: &Value, cfgobj: Option<&Value>, image: &str) -> String {
    let mut all = Value::Object(Vec::new());
    all.set("chart", canonical(chart.get("spec").unwrap_or(&Value::Null)));
    all.set("config", canonical(cfgobj.and_then(|c| c.get("spec")).unwrap_or(&Value::Null)));
    all.set("image", s(image));
    let text = json::to_string(&all);
    let (a, b) = (fnv1a32(text.as_bytes()), fnv1a32(alloc::format!("{text}#").as_bytes()));
    alloc::format!("{a:08x}{b:08x}")
}

fn values_data(chart: &Value, cfgobj: Option<&Value>) -> Value {
    let mut d = Value::Object(Vec::new());
    if !spec_str(chart, "valuesContent").is_empty() {
        d.set("values-01_HelmChart.yaml", s(spec_str(chart, "valuesContent")));
    }
    if let Some(c) = cfgobj.filter(|c| !str_at(c, &["spec", "valuesContent"]).is_empty()) {
        d.set("values-02_HelmChartConfig.yaml", s(str_at(c, &["spec", "valuesContent"])));
    }
    d
}

fn failure_policy<'a>(chart: &'a Value, cfgobj: Option<&'a Value>) -> &'a str {
    cfgobj.map(|c| str_at(c, &["spec", "failurePolicy"])).filter(|p| !p.is_empty()).unwrap_or_else(|| spec_str(chart, "failurePolicy"))
}

/// The install (`action` = "install") or uninstall ("delete") Job.
pub fn build_job(chart: &Value, cfgobj: Option<&Value>, action: &str, default_image: &str) -> Value {
    let (ns, name) = (namespace(chart), self::name(chart));
    let image = image_of(chart, default_image);
    let target = Some(spec_str(chart, "targetNamespace")).filter(|t| !t.is_empty()).unwrap_or(ns);
    let has_content = !spec_str(chart, "chartContent").is_empty();
    let chart_ref = if has_content { alloc::format!("/chart/{name}.tgz") } else { spec_str(chart, "chart").to_string() };
    let mut args = alloc::vec![s(action)];
    if action == "install" {
        if spec_bool(chart, "createNamespace") {
            args.push(s("--create-namespace"));
        }
        if !spec_str(chart, "timeout").is_empty() {
            args.push(s("--timeout"));
            args.push(s(spec_str(chart, "timeout")));
        }
        if let Some(set) = chart.pointer(&["spec", "set"]).and_then(Value::as_object) {
            let mut kv: Vec<(&String, String)> = set.iter().map(|(k, v)| (k, scalar(v))).collect();
            kv.sort();
            for (k, v) in kv {
                args.push(s("--set"));
                args.push(s(&alloc::format!("{k}={v}")));
            }
        }
    }
    let mut env = alloc::vec![
        pair("NAME", name),
        pair("VERSION", spec_str(chart, "version")),
        pair("REPO", spec_str(chart, "repo")),
        pair("HELM_DRIVER", "secret"),
        pair("CHART_NAMESPACE", ns),
        pair("CHART", &chart_ref),
        pair("HELM_VERSION", spec_str(chart, "helmVersion")),
        pair("TARGET_NAMESPACE", target),
        pair("FAILURE_POLICY", failure_policy(chart, cfgobj)),
    ];
    if spec_bool(chart, "authPassCredentials") {
        env.push(pair("AUTH_PASS_CREDENTIALS", "true"));
    }
    if spec_bool(chart, "insecureSkipTLSVerify") {
        env.push(pair("INSECURE_SKIP_TLS_VERIFY", "true"));
    }
    if spec_bool(chart, "plainHTTP") {
        env.push(pair("PLAIN_HTTP", "true"));
    }
    let mut mounts = alloc::vec![obj(alloc::vec![("name", s("values")), ("mountPath", s("/config"))])];
    let mut volumes = alloc::vec![obj(alloc::vec![("name", s("values")), ("configMap", obj(alloc::vec![("name", s(&alloc::format!("chart-values-{name}")))]))])];
    if has_content {
        mounts.push(obj(alloc::vec![("name", s("content")), ("mountPath", s("/chart"))]));
        volumes.push(obj(alloc::vec![("name", s("content")), ("secret", obj(alloc::vec![("secretName", s(&alloc::format!("chart-content-{name}")))]))]));
    }
    let auth = str_at(chart, &["spec", "authSecret", "name"]);
    if !auth.is_empty() {
        mounts.push(obj(alloc::vec![("name", s("auth")), ("mountPath", s("/auth")), ("readOnly", Value::Bool(true))]));
        volumes.push(obj(alloc::vec![("name", s("auth")), ("secret", obj(alloc::vec![("secretName", s(auth))]))]));
    }
    let ca_cm = Some(str_at(chart, &["spec", "repoCAConfigMap", "name"])).filter(|n| !n.is_empty()).map(String::from).or_else(|| (!spec_str(chart, "repoCA").is_empty()).then(|| alloc::format!("chart-cas-{name}")));
    if let Some(cm) = ca_cm {
        mounts.push(obj(alloc::vec![("name", s("ca")), ("mountPath", s("/ca-file")), ("readOnly", Value::Bool(true))]));
        volumes.push(obj(alloc::vec![("name", s("ca")), ("configMap", obj(alloc::vec![("name", s(&cm))]))]));
        env.push(pair("REPO_CA_FILE", "/ca-file/ca.crt"));
    }
    let mut container = obj(alloc::vec![("name", s("helm")), ("image", s(image)), ("imagePullPolicy", s("IfNotPresent")), ("args", arr(args)), ("env", arr(env)), ("volumeMounts", arr(mounts))]);
    if let Some(sc) = chart.pointer(&["spec", "securityContext"]).filter(|v| v.as_object().is_some()) {
        container.set("securityContext", sc.clone());
    }
    let mut pod = obj(alloc::vec![("restartPolicy", s("OnFailure")), ("serviceAccountName", s(&sa_name(name))), ("containers", arr(alloc::vec![container])), ("volumes", arr(volumes))]);
    if let Some(sc) = chart.pointer(&["spec", "podSecurityContext"]).filter(|v| v.as_object().is_some()) {
        pod.set("securityContext", sc.clone());
    }
    if spec_bool(chart, "bootstrap") {
        // Charts that bring up the cluster itself (CNI, cloud provider): host network, and no
        // taint of a node that is not ready yet keeps the Job away.
        pod.set("hostNetwork", Value::Bool(true));
        pod.set("dnsPolicy", s("ClusterFirstWithHostNet"));
        let tol = |k: &str, e: &str| obj(alloc::vec![("key", s(k)), ("operator", s("Exists")), ("effect", s(e))]);
        pod.set(
            "tolerations",
            arr(alloc::vec![
                tol("node.kubernetes.io/not-ready", "NoSchedule"),
                tol("node.kubernetes.io/unreachable", "NoSchedule"),
                tol("node.cloudprovider.kubernetes.io/uninitialized", "NoSchedule"),
                tol("CriticalAddonsOnly", "NoExecute"),
                tol("node-role.kubernetes.io/control-plane", "NoSchedule"),
                tol("node-role.kubernetes.io/etcd", "NoExecute"),
            ]),
        );
    }
    let labels = obj(alloc::vec![(LABEL, s(name))]);
    let backoff = chart.pointer(&["spec", "backOffLimit"]).and_then(Value::as_i64).unwrap_or(1000);
    obj(alloc::vec![
        ("apiVersion", s("batch/v1")),
        ("kind", s("Job")),
        (
            "metadata",
            obj(alloc::vec![
                ("name", s(&job_name(action, name))),
                ("namespace", s(ns)),
                ("labels", labels.clone()),
                ("annotations", obj(alloc::vec![(HASH_ANN, s(&config_hash(chart, cfgobj, image)))])),
                ("ownerReferences", arr(alloc::vec![owner_ref(chart, API_VERSION, "HelmChart")])),
            ])
        ),
        ("spec", obj(alloc::vec![("backoffLimit", num(backoff)), ("template", obj(alloc::vec![("metadata", obj(alloc::vec![("labels", labels)])), ("spec", pod)]))])),
    ])
}

fn job_done(job: &Value) -> bool {
    int_at(job, &["status", "succeeded"], 0) > 0 || has_condition(job, "Complete")
}

fn job_failed(job: &Value) -> bool {
    has_condition(job, "Failed")
}

fn status_of(o: &Value, job: &str, failed: bool, now: i64) -> Value {
    let old = o.pointer(&["status", "conditions"]).and_then(Value::as_array).unwrap_or(&[]);
    let created = merge_condition(old, condition("JobCreated", true, "JobCreated", &alloc::format!("Job {job} created"), now));
    let fail = merge_condition(old, condition("Failed", failed, if failed { "JobFailed" } else { "JobNotFailed" }, "", now));
    obj(alloc::vec![("jobName", s(job)), ("conditions", arr(alloc::vec![created, fail]))])
}

// ---- reconcile ----

fn api_ns_path(coll: &str, name: &str) -> String {
    alloc::format!("{coll}/{name}")
}

async fn create_if_absent<C: Client>(c: &C, coll: &str, body: &Value) -> Result<()> {
    match c.create(coll, body).await {
        Ok(_) => Ok(()),
        Err(e) if e.code == 409 => Ok(()),
        Err(e) => Err(e),
    }
}

/// Creates a ConfigMap or Secret, or updates its `data` when it differs; `None` deletes it.
async fn upsert_data<C: Client>(c: &C, coll: &str, kind: &str, ns: &str, name: &str, data: Option<Value>, owner: &Value) -> Result<()> {
    let path = api_ns_path(coll, name);
    let existing = get_opt(c, &path).await?;
    let Some(data) = data else {
        if existing.is_some() {
            delete_ok(c, &path).await?;
        }
        return Ok(());
    };
    match existing {
        None => {
            let body = obj(alloc::vec![
                ("apiVersion", s("v1")),
                ("kind", s(kind)),
                ("metadata", obj(alloc::vec![("name", s(name)), ("namespace", s(ns)), ("ownerReferences", arr(alloc::vec![owner_ref(owner, API_VERSION, "HelmChart")]))])),
                ("data", data),
            ]);
            create_if_absent(c, coll, &body).await
        }
        Some(mut cur) => {
            if cur.get("data").map(canonical) == Some(canonical(&data)) {
                return Ok(());
            }
            cur.set("data", data);
            c.update(&path, &cur).await.map(|_| ())
        }
    }
}

async fn ensure_support<C: Client>(c: &C, chart: &Value, cfgobj: Option<&Value>) -> Result<()> {
    let (ns, name) = (namespace(chart), self::name(chart));
    let sa = obj(alloc::vec![
        ("apiVersion", s("v1")),
        ("kind", s("ServiceAccount")),
        ("metadata", obj(alloc::vec![("name", s(&sa_name(name))), ("namespace", s(ns)), ("ownerReferences", arr(alloc::vec![owner_ref(chart, API_VERSION, "HelmChart")]))])),
    ]);
    create_if_absent(c, &api_path("", "v1", Some(ns), "serviceaccounts"), &sa).await?;
    let crb = obj(alloc::vec![
        ("apiVersion", s("rbac.authorization.k8s.io/v1")),
        ("kind", s("ClusterRoleBinding")),
        ("metadata", obj(alloc::vec![("name", s(&crb_name(ns, name)))])),
        ("roleRef", obj(alloc::vec![("apiGroup", s("rbac.authorization.k8s.io")), ("kind", s("ClusterRole")), ("name", s("cluster-admin"))])),
        ("subjects", arr(alloc::vec![obj(alloc::vec![("kind", s("ServiceAccount")), ("name", s(&sa_name(name))), ("namespace", s(ns))])])),
    ]);
    create_if_absent(c, "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", &crb).await?;
    let cms = api_path("", "v1", Some(ns), "configmaps");
    upsert_data(c, &cms, "ConfigMap", ns, &alloc::format!("chart-values-{name}"), Some(values_data(chart, cfgobj)), chart).await?;
    let ca = spec_str(chart, "repoCA");
    let ca_data = (!ca.is_empty()).then(|| obj(alloc::vec![("ca.crt", s(ca))]));
    upsert_data(c, &cms, "ConfigMap", ns, &alloc::format!("chart-cas-{name}"), ca_data, chart).await?;
    let content = spec_str(chart, "chartContent");
    let content_data = (!content.is_empty()).then(|| obj(alloc::vec![(&*alloc::format!("{name}.tgz"), s(content))]));
    upsert_data(c, &api_path("", "v1", Some(ns), "secrets"), "Secret", ns, &alloc::format!("chart-content-{name}"), content_data, chart).await
}

async fn set_finalizer<C: Client>(c: &C, path: &str, want: bool) -> Result<()> {
    retry_conflict(|| async {
        let Some(mut o) = get_opt(c, path).await? else { return Ok(()) };
        let fin: Vec<Value> = o.pointer(&["metadata", "finalizers"]).and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
        if fin.iter().any(|f| f.as_str() == Some(FINALIZER)) == want {
            return Ok(());
        }
        let mut fin: Vec<Value> = fin.into_iter().filter(|f| f.as_str() != Some(FINALIZER)).collect();
        if want {
            fin.push(s(FINALIZER));
        }
        o.entry_object("metadata").set("finalizers", Value::Array(fin));
        c.update(path, &o).await.map(|_| ())
    })
    .await
}

fn has_finalizer(o: &Value) -> bool {
    o.pointer(&["metadata", "finalizers"]).and_then(Value::as_array).is_some_and(|f| f.iter().any(|x| x.as_str() == Some(FINALIZER)))
}

pub async fn reconcile<C: Client>(c: &C, cfg: &Config, default_image: &str, key: &str) -> Result<Option<u64>> {
    let (ns, name) = split_key(key);
    if ns.is_empty() || name.is_empty() {
        return Ok(None);
    }
    let path = api_ns_path(&charts(Some(ns)), name);
    let Some(chart) = get_opt(c, &path).await? else { return Ok(None) };
    let cfgobj = get_opt(c, &api_ns_path(&chart_configs(Some(ns)), name)).await?;
    let jobs_coll = jobs(Some(ns));
    let install_path = api_ns_path(&jobs_coll, &job_name("install", name));
    let delete_path = api_ns_path(&jobs_coll, &job_name("delete", name));
    if deleting(&chart) {
        if !has_finalizer(&chart) {
            return Ok(None);
        }
        // The install Job must not run next to the uninstall.
        if get_opt(c, &install_path).await?.is_some() {
            delete_ok(c, &install_path).await?;
            return Ok(Some(500));
        }
        ensure_support(c, &chart, cfgobj.as_ref()).await?;
        match get_opt(c, &delete_path).await? {
            None => {
                create_if_absent(c, &jobs_coll, &build_job(&chart, cfgobj.as_ref(), "delete", default_image)).await?;
                Ok(Some(2000))
            }
            Some(job) if job_done(&job) => {
                delete_ok(c, &delete_path).await?;
                delete_ok(c, &api_ns_path("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", &crb_name(ns, name))).await?;
                set_finalizer(c, &path, false).await?;
                Ok(None)
            }
            Some(job) => {
                let failed = job_failed(&job);
                let now = (cfg.now)();
                let jn = job_name("delete", name);
                put_status(c, &path, |o| status_of(o, &jn, failed, now)).await?;
                Ok(Some(if failed { 30_000 } else { 2000 }))
            }
        }
    } else {
        set_finalizer(c, &path, true).await?;
        ensure_support(c, &chart, cfgobj.as_ref()).await?;
        let image = image_of(&chart, default_image);
        let want = config_hash(&chart, cfgobj.as_ref(), image);
        match get_opt(c, &install_path).await? {
            None => {
                create_if_absent(c, &jobs_coll, &build_job(&chart, cfgobj.as_ref(), "install", default_image)).await?;
                Ok(Some(500))
            }
            Some(job) if str_at(&job, &["metadata", "annotations", HASH_ANN]) != want => {
                // Spec or values changed: replace the Job, which upgrades the release.
                delete_ok(c, &install_path).await?;
                Ok(Some(500))
            }
            Some(job) => {
                let failed = job_failed(&job);
                let now = (cfg.now)();
                let jn = job_name("install", name);
                put_status(c, &path, |o| status_of(o, &jn, failed, now)).await?;
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::v;

    fn chart() -> Value {
        v(r#"{"apiVersion":"helm.cattle.io/v1","kind":"HelmChart","metadata":{"name":"traefik","namespace":"kube-system","uid":"u1"},"spec":{"chart":"traefik","repo":"https://traefik.github.io/charts","version":"30.1.0","targetNamespace":"ingress","createNamespace":true,"set":{"b":2,"a":"x","c":true},"valuesContent":"replicas: 2\n","bootstrap":true}}"#)
    }

    #[test]
    fn job_shape() {
        let job = build_job(&chart(), None, "install", DEFAULT_IMAGE);
        let t = |p: &[&str]| str_at(&job, p).to_string();
        assert_eq!(t(&["metadata", "name"]), "helm-install-traefik");
        let c = job.pointer(&["spec", "template", "spec", "containers"]).and_then(Value::as_array).unwrap()[0].clone();
        assert_eq!(str_at(&c, &["image"]), DEFAULT_IMAGE);
        let args: Vec<&str> = c.get("args").and_then(Value::as_array).unwrap().iter().filter_map(Value::as_str).collect();
        assert_eq!(args, ["install", "--create-namespace", "--set", "a=x", "--set", "b=2", "--set", "c=true"]);
        let env = c.get("env").and_then(Value::as_array).unwrap();
        let e = |n: &str| env.iter().find(|x| str_at(x, &["name"]) == n).map(|x| str_at(x, &["value"]).to_string());
        assert_eq!(e("NAME").as_deref(), Some("traefik"));
        assert_eq!(e("CHART").as_deref(), Some("traefik"));
        assert_eq!(e("REPO").as_deref(), Some("https://traefik.github.io/charts"));
        assert_eq!(e("VERSION").as_deref(), Some("30.1.0"));
        assert_eq!(e("TARGET_NAMESPACE").as_deref(), Some("ingress"));
        assert_eq!(e("CHART_NAMESPACE").as_deref(), Some("kube-system"));
        assert_eq!(e("HELM_DRIVER").as_deref(), Some("secret"));
        assert_eq!(job.pointer(&["spec", "template", "spec", "hostNetwork"]).and_then(Value::as_bool), Some(true));
        assert_eq!(job.pointer(&["spec", "backoffLimit"]).and_then(Value::as_i64), Some(1000));
        let del = build_job(&chart(), None, "delete", DEFAULT_IMAGE);
        let dargs = del.pointer(&["spec", "template", "spec", "containers"]).and_then(Value::as_array).unwrap()[0].get("args").and_then(Value::as_array).unwrap().len();
        assert_eq!(dargs, 1);
    }

    #[test]
    fn chart_content_and_secrets() {
        let mut ch = v(r#"{"metadata":{"name":"x","namespace":"default","uid":"u"},"spec":{"chartContent":"H4sIAAAA","authSecret":{"name":"creds"},"repoCA":"PEM","jobImage":"my/helm:1"}}"#);
        ch.set("kind", Value::from("HelmChart"));
        let job = build_job(&ch, None, "install", DEFAULT_IMAGE);
        let pod = job.pointer(&["spec", "template", "spec"]).unwrap();
        let c = &pod.get("containers").and_then(Value::as_array).unwrap()[0];
        assert_eq!(str_at(c, &["image"]), "my/helm:1");
        let env = c.get("env").and_then(Value::as_array).unwrap();
        assert!(env.iter().any(|x| str_at(x, &["name"]) == "CHART" && str_at(x, &["value"]) == "/chart/x.tgz"));
        let vols: Vec<&str> = pod.get("volumes").and_then(Value::as_array).unwrap().iter().map(|x| str_at(x, &["name"])).collect();
        assert_eq!(vols, ["values", "content", "auth", "ca"]);
    }

    #[test]
    fn hash_follows_spec_values_and_image() {
        let a = config_hash(&chart(), None, "i:1");
        assert_eq!(a, config_hash(&chart(), None, "i:1"));
        assert_ne!(a, config_hash(&chart(), None, "i:2"));
        let cfg = v(r#"{"spec":{"valuesContent":"x: 1"}}"#);
        assert_ne!(a, config_hash(&chart(), Some(&cfg), "i:1"));
        let mut other = chart();
        other.entry_object("spec").set("version", Value::from("31.0.0"));
        assert_ne!(a, config_hash(&other, None, "i:1"));
        // Key order of the spec does not matter.
        let reordered = v(r#"{"metadata":{"name":"traefik","namespace":"kube-system","uid":"u1"},"spec":{"bootstrap":true,"valuesContent":"replicas: 2\n","set":{"c":true,"a":"x","b":2},"createNamespace":true,"targetNamespace":"ingress","version":"30.1.0","repo":"https://traefik.github.io/charts","chart":"traefik"}}"#);
        assert_eq!(a, config_hash(&reordered, None, "i:1"));
    }

    #[test]
    fn values_come_from_chart_and_config() {
        let cfg = v(r#"{"spec":{"valuesContent":"y: 2"}}"#);
        let d = values_data(&chart(), Some(&cfg));
        assert_eq!(str_at(&d, &["values-01_HelmChart.yaml"]), "replicas: 2\n");
        assert_eq!(str_at(&d, &["values-02_HelmChartConfig.yaml"]), "y: 2");
        assert!(values_data(&v(r#"{"spec":{}}"#), None).as_object().unwrap().is_empty());
    }
}
