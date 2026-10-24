//! API defaulting: the subset of upstream `SetDefaults_*` (pkg/apis/*/v1/defaults.go) that
//! clients and the conformance suite observe. Runs on create and on every non-status update,
//! like upstream, which defaults on each decode. Only fills absent fields.

use alloc::string::String;
use alloc::vec::Vec;
use kr_fmt::json::{Number, Value};

fn int(n: i64) -> Value {
    Value::Number(Number::from_i64(n))
}

fn s(v: &str) -> Value {
    Value::String(String::from(v))
}

/// Sets `key` when absent (or null).
fn def(o: &mut Value, key: &str, v: Value) {
    if o.get(key).is_none_or(Value::is_null) {
        o.set(key, v);
    }
}

fn each(o: &mut Value, key: &str, mut f: impl FnMut(&mut Value)) {
    if let Some(a) = o.get_mut(key).and_then(Value::as_array_mut) {
        a.iter_mut().for_each(&mut f);
    }
}

fn obj<'a>(o: &'a mut Value, key: &str) -> Option<&'a mut Value> {
    o.get_mut(key).filter(|v| matches!(v, Value::Object(_)))
}

/// Applies the defaults for `kind` (identified by its resource plural and group).
pub fn apply(group: &str, plural: &str, o: &mut Value) {
    match (group, plural) {
        ("", "pods") => pod_spec(o.entry_object("spec")),
        ("", "podtemplates") => template(o),
        ("", "replicationcontrollers") => {
            let sp = o.entry_object("spec");
            def(sp, "replicas", int(1));
            if sp.get("selector").is_none() {
                if let Some(l) = sp.pointer(&["template", "metadata", "labels"]).cloned() {
                    sp.set("selector", l);
                }
            }
            template(sp);
        }
        ("", "services") => service(o),
        ("", "secrets") => def(o, "type", s("Opaque")),
        ("", "persistentvolumeclaims") => {
            let sp = o.entry_object("spec");
            def(sp, "volumeMode", s("Filesystem"));
        }
        ("apps", "deployments") => {
            let sp = o.entry_object("spec");
            def(sp, "replicas", int(1));
            def(sp, "revisionHistoryLimit", int(10));
            def(sp, "progressDeadlineSeconds", int(600));
            let st = sp.entry_object("strategy");
            def(st, "type", s("RollingUpdate"));
            if st.get("type").and_then(Value::as_str) == Some("RollingUpdate") {
                let ru = st.entry_object("rollingUpdate");
                def(ru, "maxUnavailable", s("25%"));
                def(ru, "maxSurge", s("25%"));
            }
            template(sp);
        }
        ("apps", "replicasets") => {
            let sp = o.entry_object("spec");
            def(sp, "replicas", int(1));
            template(sp);
        }
        ("apps", "daemonsets") => {
            let sp = o.entry_object("spec");
            def(sp, "revisionHistoryLimit", int(10));
            let st = sp.entry_object("updateStrategy");
            def(st, "type", s("RollingUpdate"));
            if st.get("type").and_then(Value::as_str) == Some("RollingUpdate") {
                let ru = st.entry_object("rollingUpdate");
                def(ru, "maxUnavailable", int(1));
                def(ru, "maxSurge", int(0));
            }
            template(sp);
        }
        ("apps", "statefulsets") => {
            let sp = o.entry_object("spec");
            def(sp, "replicas", int(1));
            def(sp, "revisionHistoryLimit", int(10));
            def(sp, "podManagementPolicy", s("OrderedReady"));
            let st = sp.entry_object("updateStrategy");
            def(st, "type", s("RollingUpdate"));
            if st.get("type").and_then(Value::as_str) == Some("RollingUpdate") {
                def(st.entry_object("rollingUpdate"), "partition", int(0));
            }
            let rp = sp.entry_object("persistentVolumeClaimRetentionPolicy");
            def(rp, "whenDeleted", s("Retain"));
            def(rp, "whenScaled", s("Retain"));
            each(sp, "volumeClaimTemplates", |c| def(c.entry_object("spec"), "volumeMode", s("Filesystem")));
            template(sp);
        }
        ("batch", "jobs") => job_spec(o.entry_object("spec")),
        ("batch", "cronjobs") => {
            let sp = o.entry_object("spec");
            def(sp, "concurrencyPolicy", s("Allow"));
            def(sp, "suspend", Value::Bool(false));
            def(sp, "successfulJobsHistoryLimit", int(3));
            def(sp, "failedJobsHistoryLimit", int(1));
            job_spec(sp.entry_object("jobTemplate").entry_object("spec"));
        }
        _ => {}
    }
}

fn template(sp: &mut Value) {
    if let Some(t) = obj(sp, "template") {
        pod_spec(t.entry_object("spec"));
    }
}

fn job_spec(sp: &mut Value) {
    let (c, p) = (sp.get("completions").is_some_and(|v| !v.is_null()), sp.get("parallelism").is_some_and(|v| !v.is_null()));
    if !c && !p {
        sp.set("completions", int(1));
        sp.set("parallelism", int(1));
    }
    def(sp, "parallelism", int(1));
    def(sp, "backoffLimit", int(6));
    def(sp, "completionMode", s("NonIndexed"));
    def(sp, "suspend", Value::Bool(false));
    let failed = sp.get("podFailurePolicy").is_some_and(|v| !v.is_null());
    def(sp, "podReplacementPolicy", s(if failed { "Failed" } else { "TerminatingOrFailed" }));
    template(sp);
}

/// `SetDefaults_PodSpec` and everything under it.
pub fn pod_spec(sp: &mut Value) {
    def(sp, "dnsPolicy", s("ClusterFirst"));
    def(sp, "restartPolicy", s("Always"));
    def(sp, "terminationGracePeriodSeconds", int(30));
    def(sp, "securityContext", Value::Object(Vec::new()));
    def(sp, "schedulerName", s("default-scheduler"));
    def(sp, "enableServiceLinks", Value::Bool(true));
    if sp.get("hostNetwork").and_then(Value::as_bool) == Some(true) {
        // Host-network pods expose their container ports on the host.
        for key in ["initContainers", "containers"] {
            each(sp, key, |c| {
                each(c, "ports", |p| {
                    if let Some(cp) = p.get("containerPort").cloned() {
                        def(p, "hostPort", cp);
                    }
                })
            });
        }
    }
    for key in ["initContainers", "containers", "ephemeralContainers"] {
        each(sp, key, container);
    }
    each(sp, "volumes", volume);
}

fn container(c: &mut Value) {
    def(c, "terminationMessagePath", s("/dev/termination-log"));
    def(c, "terminationMessagePolicy", s("File"));
    if c.get("imagePullPolicy").is_none() {
        let img = c.get("image").and_then(Value::as_str).unwrap_or("");
        let name = img.split('@').next().unwrap_or("");
        let tag = name.rsplit('/').next().and_then(|last| last.split_once(':')).map(|(_, t)| t);
        let always = !img.contains('@') && tag.is_none_or(|t| t == "latest");
        c.set("imagePullPolicy", s(if always { "Always" } else { "IfNotPresent" }));
    }
    each(c, "ports", |p| def(p, "protocol", s("TCP")));
    for probe in ["livenessProbe", "readinessProbe", "startupProbe"] {
        if let Some(p) = obj(c, probe) {
            def(p, "timeoutSeconds", int(1));
            def(p, "periodSeconds", int(10));
            def(p, "successThreshold", int(1));
            def(p, "failureThreshold", int(3));
            if let Some(h) = obj(p, "httpGet") {
                def(h, "path", s("/"));
                def(h, "scheme", s("HTTP"));
            }
        }
    }
    for hook in ["postStart", "preStop"] {
        if let Some(h) = c.get_mut("lifecycle").and_then(|l| l.get_mut(hook)).and_then(|h| h.get_mut("httpGet")) {
            def(h, "path", s("/"));
            def(h, "scheme", s("HTTP"));
        }
    }
    each(c, "env", |e| {
        if let Some(f) = e.get_mut("valueFrom").and_then(|v| v.get_mut("fieldRef")) {
            def(f, "apiVersion", s("v1"));
        }
    });
    // Requests default to limits.
    if let Some(r) = obj(c, "resources") {
        if let Some(Value::Object(lim)) = r.get("limits").cloned() {
            let req = r.entry_object("requests");
            for (k, v) in lim {
                def(req, &k, v);
            }
        }
    }
}

fn volume(v: &mut Value) {
    const SOURCES: &[&str] = &[
        "hostPath", "emptyDir", "gcePersistentDisk", "awsElasticBlockStore", "gitRepo", "secret", "nfs", "iscsi", "glusterfs", "persistentVolumeClaim", "rbd", "flexVolume", "cinder", "cephfs",
        "flocker", "downwardAPI", "fc", "azureFile", "configMap", "vsphereVolume", "quobyte", "azureDisk", "photonPersistentDisk", "projected", "portworxVolume", "scaleIO", "storageos", "csi",
        "ephemeral", "image",
    ];
    if !SOURCES.iter().any(|k| v.get(k).is_some_and(|x| !x.is_null())) {
        v.set("emptyDir", Value::Object(Vec::new()));
    }
    for key in ["secret", "configMap", "downwardAPI", "projected"] {
        if let Some(src) = obj(v, key) {
            def(src, "defaultMode", int(0o644));
        }
    }
    if let Some(h) = obj(v, "hostPath") {
        def(h, "type", s(""));
    }
    if let Some(d) = obj(v, "downwardAPI") {
        each(d, "items", |i| {
            if let Some(f) = obj(i, "fieldRef") {
                def(f, "apiVersion", s("v1"));
            }
        });
    }
    if let Some(p) = obj(v, "projected") {
        each(p, "sources", |src| {
            if let Some(t) = obj(src, "serviceAccountToken") {
                def(t, "expirationSeconds", int(3600));
            }
            if let Some(d) = obj(src, "downwardAPI") {
                each(d, "items", |i| {
                    if let Some(f) = obj(i, "fieldRef") {
                        def(f, "apiVersion", s("v1"));
                    }
                });
            }
        });
    }
}

fn service(o: &mut Value) {
    let sp = o.entry_object("spec");
    def(sp, "type", s("ClusterIP"));
    def(sp, "sessionAffinity", s("None"));
    let ty = sp.get("type").and_then(Value::as_str).map(String::from).unwrap_or_default();
    if ty != "ExternalName" {
        def(sp, "internalTrafficPolicy", s("Cluster"));
    }
    if ty == "NodePort" || ty == "LoadBalancer" {
        def(sp, "externalTrafficPolicy", s("Cluster"));
    }
    if ty == "LoadBalancer" {
        def(sp, "allocateLoadBalancerNodePorts", Value::Bool(true));
    }
    if sp.get("sessionAffinity").and_then(Value::as_str) == Some("ClientIP") {
        let cfg = sp.entry_object("sessionAffinityConfig").entry_object("clientIP");
        def(cfg, "timeoutSeconds", int(10800));
    }
    each(sp, "ports", |p| {
        def(p, "protocol", s("TCP"));
        if let Some(port) = p.get("port").cloned() {
            def(p, "targetPort", port);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_fmt::json;

    #[test]
    fn pod_defaults() {
        let mut p = json::parse_str(r#"{"spec":{"containers":[{"name":"a","image":"busybox","ports":[{"containerPort":80}],"readinessProbe":{"httpGet":{"port":80}}},{"name":"b","image":"nginx:1.27"}],"volumes":[{"name":"v"},{"name":"s","secret":{"secretName":"x"}}]}}"#).unwrap();
        apply("", "pods", &mut p);
        assert_eq!(p.pointer(&["spec", "terminationGracePeriodSeconds"]).and_then(Value::as_i64), Some(30));
        assert_eq!(p.pointer(&["spec", "dnsPolicy"]).and_then(Value::as_str), Some("ClusterFirst"));
        let c = p.pointer(&["spec", "containers"]).unwrap();
        assert_eq!(c.at(0).unwrap().get("imagePullPolicy").and_then(Value::as_str), Some("Always"));
        assert_eq!(c.at(1).unwrap().get("imagePullPolicy").and_then(Value::as_str), Some("IfNotPresent"));
        assert_eq!(c.at(0).unwrap().pointer(&["readinessProbe", "httpGet", "scheme"]).and_then(Value::as_str), Some("HTTP"));
        let v = p.pointer(&["spec", "volumes"]).unwrap();
        assert!(v.at(0).unwrap().get("emptyDir").is_some());
        assert_eq!(v.at(1).unwrap().pointer(&["secret", "defaultMode"]).and_then(Value::as_i64), Some(420));
    }

    #[test]
    fn job_and_service_defaults() {
        let mut j = json::parse_str(r#"{"spec":{"template":{"spec":{"containers":[]}}}}"#).unwrap();
        apply("batch", "jobs", &mut j);
        assert_eq!(j.pointer(&["spec", "completions"]).and_then(Value::as_i64), Some(1));
        assert_eq!(j.pointer(&["spec", "backoffLimit"]).and_then(Value::as_i64), Some(6));
        assert!(j.pointer(&["spec", "manualSelector"]).is_none());
        let mut s = json::parse_str(r#"{"spec":{"ports":[{"port":80}]}}"#).unwrap();
        apply("", "services", &mut s);
        assert_eq!(s.pointer(&["spec", "ports"]).and_then(|p| p.at(0)).and_then(|p| p.get("targetPort")).and_then(Value::as_i64), Some(80));
    }
}
