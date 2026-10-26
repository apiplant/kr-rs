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

fn quantity_of(v: Option<&Value>) -> Option<kr_fmt::quantity::Quantity> {
    use kr_fmt::quantity::{Format, Quantity};
    v.and_then(Value::as_str).and_then(|s| Quantity::parse(s).ok()).or_else(|| v.and_then(Value::as_i64).map(|n| Quantity::from_i64(n, Format::DecimalSI)))
}

/// Pod QoS class, as upstream: Guaranteed when every container (init included) has cpu and
/// memory limits and any request equals its limit; BestEffort when no container sets any cpu or
/// memory request or limit; otherwise Burstable.
pub fn qos_class(pod: &Value) -> &'static str {
    let (mut any, mut guaranteed, mut n) = (false, true, 0);
    for key in ["initContainers", "containers"] {
        for c in pod.pointer(&["spec", key]).and_then(Value::as_array).unwrap_or(&[]) {
            n += 1;
            for res in ["cpu", "memory"] {
                let q = |kind: &str| quantity_of(c.pointer(&["resources", kind, res])).and_then(|q| q.milli_value());
                let (req, lim) = (q("requests").filter(|v| *v != 0), q("limits").filter(|v| *v != 0));
                any |= req.is_some() || lim.is_some();
                match lim {
                    None => guaranteed = false,
                    Some(l) => guaranteed &= req.is_none_or(|r| r == l),
                }
            }
        }
    }
    if n > 0 && guaranteed {
        "Guaranteed"
    } else if any {
        "Burstable"
    } else {
        "BestEffort"
    }
}

/// core/v1 and events.k8s.io/v1 Events are two views of one object: the fields of one API are
/// copied to the other's when that is not set (as upstream's conversion does).
fn event(o: &mut Value) {
    let copy = |o: &mut Value, from: &[&str], to: &[&str]| {
        if o.pointer(to).is_none_or(Value::is_null) {
            if let Some(v) = o.pointer(from).filter(|v| !v.is_null()).cloned() {
                let (last, parents) = to.split_last().unwrap();
                let mut cur = &mut *o;
                for p in parents {
                    cur = cur.entry_object(p);
                }
                cur.set(last, v);
            }
        }
    };
    for (a, b) in [("involvedObject", "regarding"), ("message", "note")] {
        copy(o, &[a], &[b]);
        copy(o, &[b], &[a]);
    }
    copy(o, &["source", "component"], &["reportingController"]);
    copy(o, &["reportingController"], &["source", "component"]);
    copy(o, &["reportingComponent"], &["reportingController"]);
    copy(o, &["source", "host"], &["reportingInstance"]);
    copy(o, &["reportingInstance"], &["source", "host"]);
}

/// Applies the defaults for `kind` (identified by its resource plural and group).
pub fn apply(group: &str, plural: &str, o: &mut Value) {
    match (group, plural) {
        ("", "pods") => {
            pod_spec(o.entry_object("spec"));
            def(o.entry_object("status"), "phase", s("Pending"));
            let qos = qos_class(o);
            def(o.entry_object("status"), "qosClass", s(qos));
        }
        ("", "podtemplates") => template(o),
        ("", "events") | ("events.k8s.io", "events") => event(o),
        ("certificates.k8s.io", "podcertificaterequests") => def(o.entry_object("spec"), "maxExpirationSeconds", int(86400)),
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
            def(o.entry_object("status"), "phase", s("Pending"));
        }
        ("", "persistentvolumes") => {
            def(o.entry_object("spec"), "persistentVolumeReclaimPolicy", s("Retain"));
            def(o.entry_object("spec"), "volumeMode", s("Filesystem"));
            def(o.entry_object("status"), "phase", s("Pending"));
        }
        ("", "endpoints") => each(o, "subsets", |ss| each(ss, "ports", |p| def(p, "protocol", s("TCP")))),
        ("discovery.k8s.io", "endpointslices") => each(o, "ports", |p| def(p, "protocol", s("TCP"))),
        ("networking.k8s.io", "networkpolicies") => {
            let sp = o.entry_object("spec");
            each(sp, "ingress", |r| each(r, "ports", |p| def(p, "protocol", s("TCP"))));
            each(sp, "egress", |r| each(r, "ports", |p| def(p, "protocol", s("TCP"))));
            let has_egress = sp.get("egress").is_some_and(|v| !v.is_null());
            if sp.get("policyTypes").is_none_or(|v| v.as_array().is_none_or(|a| a.is_empty())) {
                let mut t = alloc::vec![s("Ingress")];
                if has_egress {
                    t.push(s("Egress"));
                }
                sp.set("policyTypes", Value::Array(t));
            }
        }
        ("storage.k8s.io", "storageclasses") => {
            def(o, "reclaimPolicy", s("Delete"));
            def(o, "volumeBindingMode", s("Immediate"));
        }
        ("storage.k8s.io", "csidrivers") => {
            let sp = o.entry_object("spec");
            def(sp, "attachRequired", Value::Bool(true));
            def(sp, "podInfoOnMount", Value::Bool(false));
            def(sp, "storageCapacity", Value::Bool(false));
            def(sp, "requiresRepublish", Value::Bool(false));
            def(sp, "seLinuxMount", Value::Bool(false));
            def(sp, "fsGroupPolicy", s("ReadWriteOnceWithFSType"));
            def(sp, "volumeLifecycleModes", Value::Array(alloc::vec![s("Persistent")]));
        }
        ("scheduling.k8s.io", "priorityclasses") => def(o, "preemptionPolicy", s("PreemptLowerPriority")),
        ("rbac.authorization.k8s.io", "rolebindings" | "clusterrolebindings") => each(o, "subjects", |sub| {
            match sub.get("kind").and_then(Value::as_str) {
                Some("ServiceAccount") => def(sub, "apiGroup", s("")),
                Some("User" | "Group") => def(sub, "apiGroup", s("rbac.authorization.k8s.io")),
                _ => {}
            }
        }),
        ("admissionregistration.k8s.io", "validatingwebhookconfigurations") => webhooks(o, false),
        ("admissionregistration.k8s.io", "mutatingwebhookconfigurations") => webhooks(o, true),
        ("admissionregistration.k8s.io", "validatingadmissionpolicies") => {
            let sp = o.entry_object("spec");
            def(sp, "failurePolicy", s("Fail"));
            if let Some(m) = obj(sp, "matchConstraints") {
                def(m, "matchPolicy", s("Equivalent"));
                def(m, "namespaceSelector", Value::Object(Vec::new()));
                def(m, "objectSelector", Value::Object(Vec::new()));
            }
        }
        ("flowcontrol.apiserver.k8s.io", "flowschemas") => def(o.entry_object("spec"), "matchingPrecedence", int(1000)),
        ("flowcontrol.apiserver.k8s.io", "prioritylevelconfigurations") => {
            let sp = o.entry_object("spec");
            if sp.get("type").and_then(Value::as_str) == Some("Limited") {
                let l = sp.entry_object("limited");
                def(l, "nominalConcurrencyShares", int(30));
                def(l, "lendablePercent", int(0));
                if let Some(r) = obj(l, "limitResponse") {
                    if r.get("type").and_then(Value::as_str) == Some("Queue") {
                        let q = r.entry_object("queuing");
                        def(q, "queues", int(64));
                        def(q, "handSize", int(8));
                        def(q, "queueLengthLimit", int(50));
                    }
                }
            }
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

fn webhooks(o: &mut Value, mutating: bool) {
    each(o, "webhooks", |w| {
        def(w, "failurePolicy", s("Fail"));
        def(w, "matchPolicy", s("Equivalent"));
        def(w, "namespaceSelector", Value::Object(Vec::new()));
        def(w, "objectSelector", Value::Object(Vec::new()));
        def(w, "timeoutSeconds", int(10));
        if mutating {
            def(w, "reinvocationPolicy", s("Never"));
        }
        each(w, "rules", |r| def(r, "scope", s("*")));
    });
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

    fn run(g: &str, p: &str, j: &str) -> Value {
        let mut v = json::parse_str(j).unwrap();
        apply(g, p, &mut v);
        v
    }

    fn st<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
        v.pointer(path).and_then(Value::as_str)
    }

    fn proto(v: &Value, path: &[&str]) -> Option<String> {
        let mut cur = v;
        for k in path {
            cur = if let Ok(i) = k.parse::<usize>() { cur.at(i)? } else { cur.get(k)? };
        }
        cur.get("protocol").and_then(Value::as_str).map(String::from)
    }

    #[test]
    fn networking_storage_core_extras() {
        let v = run("networking.k8s.io", "networkpolicies", r#"{"spec":{"egress":[{"ports":[{"port":1}]}]}}"#);
        assert_eq!(v.pointer(&["spec", "policyTypes"]).and_then(|a| a.at(1)).and_then(Value::as_str), Some("Egress"));
        assert_eq!(proto(&v, &["spec", "egress", "0", "ports", "0"]).as_deref(), Some("TCP"));
        let v = run("networking.k8s.io", "networkpolicies", r#"{"spec":{}}"#);
        assert_eq!(v.pointer(&["spec", "policyTypes"]).and_then(Value::as_array).map(|a| a.len()), Some(1));
        let v = run("storage.k8s.io", "storageclasses", r#"{}"#);
        assert_eq!(st(&v, &["reclaimPolicy"]), Some("Delete"));
        assert_eq!(st(&v, &["volumeBindingMode"]), Some("Immediate"));
        let v = run("storage.k8s.io", "csidrivers", r#"{"spec":{}}"#);
        assert_eq!(v.pointer(&["spec", "attachRequired"]).and_then(Value::as_bool), Some(true));
        assert_eq!(v.pointer(&["spec", "podInfoOnMount"]).and_then(Value::as_bool), Some(false));
        assert_eq!(st(&v, &["spec", "fsGroupPolicy"]), Some("ReadWriteOnceWithFSType"));
        assert_eq!(v.pointer(&["spec", "volumeLifecycleModes"]).and_then(|a| a.at(0)).and_then(Value::as_str), Some("Persistent"));
        let v = run("", "persistentvolumes", r#"{"spec":{}}"#);
        assert_eq!(st(&v, &["spec", "persistentVolumeReclaimPolicy"]), Some("Retain"));
        assert_eq!(st(&v, &["spec", "volumeMode"]), Some("Filesystem"));
        assert_eq!(st(&v, &["status", "phase"]), Some("Pending"));
        let v = run("", "persistentvolumeclaims", r#"{"spec":{}}"#);
        assert_eq!(st(&v, &["status", "phase"]), Some("Pending"));
        let v = run("", "endpoints", r#"{"subsets":[{"ports":[{"port":1}]}]}"#);
        assert_eq!(proto(&v, &["subsets", "0", "ports", "0"]).as_deref(), Some("TCP"));
        let v = run("discovery.k8s.io", "endpointslices", r#"{"ports":[{"port":1}]}"#);
        assert_eq!(proto(&v, &["ports", "0"]).as_deref(), Some("TCP"));
        let v = run("scheduling.k8s.io", "priorityclasses", r#"{}"#);
        assert_eq!(st(&v, &["preemptionPolicy"]), Some("PreemptLowerPriority"));
    }

    #[test]
    fn rbac_webhooks_flowcontrol() {
        let v = run("rbac.authorization.k8s.io", "rolebindings", r#"{"subjects":[{"kind":"User"},{"kind":"ServiceAccount"}]}"#);
        let s0 = v.get("subjects").and_then(|a| a.at(0)).unwrap();
        let s1 = v.get("subjects").and_then(|a| a.at(1)).unwrap();
        assert_eq!(s0.get("apiGroup").and_then(Value::as_str), Some("rbac.authorization.k8s.io"));
        assert_eq!(s1.get("apiGroup").and_then(Value::as_str), Some(""));
        let v = run("admissionregistration.k8s.io", "mutatingwebhookconfigurations", r#"{"webhooks":[{"rules":[{}]}]}"#);
        let w = v.get("webhooks").and_then(|a| a.at(0)).unwrap();
        assert_eq!(w.get("failurePolicy").and_then(Value::as_str), Some("Fail"));
        assert_eq!(w.get("matchPolicy").and_then(Value::as_str), Some("Equivalent"));
        assert_eq!(w.get("timeoutSeconds").and_then(Value::as_i64), Some(10));
        assert_eq!(w.get("reinvocationPolicy").and_then(Value::as_str), Some("Never"));
        assert!(w.get("namespaceSelector").is_some() && w.get("objectSelector").is_some());
        assert_eq!(w.get("rules").and_then(|r| r.at(0)).and_then(|r| r.get("scope")).and_then(Value::as_str), Some("*"));
        let v = run("admissionregistration.k8s.io", "validatingwebhookconfigurations", r#"{"webhooks":[{}]}"#);
        assert!(v.get("webhooks").and_then(|a| a.at(0)).unwrap().get("reinvocationPolicy").is_none());
        let v = run("admissionregistration.k8s.io", "validatingadmissionpolicies", r#"{"spec":{"matchConstraints":{}}}"#);
        assert_eq!(st(&v, &["spec", "failurePolicy"]), Some("Fail"));
        assert_eq!(st(&v, &["spec", "matchConstraints", "matchPolicy"]), Some("Equivalent"));
        let v = run("flowcontrol.apiserver.k8s.io", "flowschemas", r#"{"spec":{}}"#);
        assert_eq!(v.pointer(&["spec", "matchingPrecedence"]).and_then(Value::as_i64), Some(1000));
        let v = run("flowcontrol.apiserver.k8s.io", "prioritylevelconfigurations", r#"{"spec":{"type":"Limited","limited":{"limitResponse":{"type":"Queue"}}}}"#);
        assert_eq!(v.pointer(&["spec", "limited", "nominalConcurrencyShares"]).and_then(Value::as_i64), Some(30));
        assert_eq!(v.pointer(&["spec", "limited", "lendablePercent"]).and_then(Value::as_i64), Some(0));
        assert_eq!(v.pointer(&["spec", "limited", "limitResponse", "queuing", "queues"]).and_then(Value::as_i64), Some(64));
        assert_eq!(v.pointer(&["spec", "limited", "limitResponse", "queuing", "handSize"]).and_then(Value::as_i64), Some(8));
        assert_eq!(v.pointer(&["spec", "limited", "limitResponse", "queuing", "queueLengthLimit"]).and_then(Value::as_i64), Some(50));
    }
}
