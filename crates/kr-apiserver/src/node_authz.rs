//! Node authorizer + NodeRestriction (KNOWN_ISSUES #81): a kubelet identity
//! (`system:node:<name>` in `system:nodes`) may read only the secrets, configmaps and
//! PVCs referenced by pods bound to it, write only its own Node, Lease and pods, and mint
//! tokens only for service accounts its pods run as.
//!
//! As upstream, the authorizer runs before RBAC. `Allow` grants, `NoOpinion` defers to RBAC.
//! `Deny` is NodeRestriction's job upstream (admission); here it is decided up front, since
//! every write it guards is identified by URL or the created object's name.

use crate::rbac::Attrs;
use alloc::string::String;
use alloc::vec::Vec;
use kr_fmt::json::Value;

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    NoOpinion,
}

/// The node name of a kubelet identity.
pub fn node_name<'a>(user: &'a str, groups: &[String]) -> Option<&'a str> {
    let n = user.strip_prefix("system:node:")?;
    (!n.is_empty() && groups.iter().any(|g| g == "system:nodes")).then_some(n)
}

/// Lookups the decision needs: a pod by (namespace, name), and the pods of a namespace.
pub trait Pods {
    fn get(&self, ns: &str, name: &str) -> Option<Value>;
    fn in_namespace(&self, ns: &str) -> Vec<Value>;
}

fn bound_to(pod: &Value, node: &str) -> bool {
    pod.pointer(&["spec", "nodeName"]).and_then(Value::as_str) == Some(node)
}

const WRITE: &[&str] = &["create", "update", "patch", "delete", "deletecollection"];

/// `body_name` is the `metadata.name` of the object being created, for POSTs.
pub fn decide(node: &str, a: &Attrs, body_name: Option<&str>, pods: &dyn Pods) -> Decision {
    if !a.resource_request {
        return Decision::NoOpinion;
    }
    let write = WRITE.contains(&a.verb.as_str());
    let target = if a.name.is_empty() { body_name.unwrap_or("") } else { a.name.as_str() };
    match (a.api_group.as_str(), a.resource.as_str(), a.subresource.as_str()) {
        ("", kind @ ("secrets" | "configmaps" | "persistentvolumeclaims"), "") => {
            // Single-object reads of something a local pod uses.
            if a.verb != "get" || a.name.is_empty() {
                return if write { Decision::Deny } else { Decision::NoOpinion };
            }
            let used = pods.in_namespace(&a.namespace).iter().any(|p| bound_to(p, node) && references(p, kind, &a.name));
            if used { Decision::Allow } else { Decision::NoOpinion }
        }
        ("", "serviceaccounts", "token") => {
            let used = pods.in_namespace(&a.namespace).iter().any(|p| bound_to(p, node) && p.pointer(&["spec", "serviceAccountName"]).and_then(Value::as_str) == Some(a.name.as_str()));
            if used { Decision::Allow } else { Decision::Deny }
        }
        ("", "pods", sub @ ("" | "status")) if write => {
            if sub.is_empty() && a.verb == "create" {
                return Decision::Deny; // no mirror pods
            }
            match pods.get(&a.namespace, &a.name) {
                Some(p) if bound_to(&p, node) => Decision::NoOpinion,
                _ => Decision::Deny,
            }
        }
        ("", "nodes", "" | "status") if write => {
            if target == node { Decision::NoOpinion } else { Decision::Deny }
        }
        ("coordination.k8s.io", "leases", "") if a.namespace == "kube-node-lease" => {
            if target == node || (!write && a.name.is_empty()) { Decision::NoOpinion } else { Decision::Deny }
        }
        _ => Decision::NoOpinion,
    }
}

/// Does `pod` reference the named secret / configmap / PVC?
fn references(pod: &Value, kind: &str, name: &str) -> bool {
    let found = core::cell::Cell::new(false);
    let hit = |v: Option<&Value>| found.set(found.get() | (v.and_then(Value::as_str) == Some(name)));
    let spec = pod.get("spec");
    let arr = |v: Option<&Value>, k: &str| -> Vec<Value> { v.and_then(|v| v.get(k)).and_then(Value::as_array).map(<[Value]>::to_vec).unwrap_or_default() };
    let pod_name = pod.pointer(&["metadata", "name"]).and_then(Value::as_str).unwrap_or("");
    for vol in arr(spec, "volumes") {
        match kind {
            "secrets" => {
                hit(vol.pointer(&["secret", "secretName"]));
                for k in ["csi", "flexVolume", "cephfs", "rbd", "iscsi", "scaleIO", "storageos", "azureFile"] {
                    hit(vol.pointer(&[k, "nodePublishSecretRef", "name"]));
                    hit(vol.pointer(&[k, "secretRef", "name"]));
                    hit(vol.pointer(&[k, "secretName"]));
                }
            }
            "configmaps" => hit(vol.pointer(&["configMap", "name"])),
            _ => {
                hit(vol.pointer(&["persistentVolumeClaim", "claimName"]));
                if vol.get("ephemeral").is_some() {
                    let vname = vol.get("name").and_then(Value::as_str).unwrap_or("");
                    found.set(found.get() | (alloc::format!("{pod_name}-{vname}") == name));
                }
            }
        }
        for src in arr(vol.get("projected"), "sources") {
            match kind {
                "secrets" => hit(src.pointer(&["secret", "name"])),
                "configmaps" => hit(src.pointer(&["configMap", "name"])),
                _ => {}
            }
        }
    }
    if kind == "secrets" {
        for s in arr(spec, "imagePullSecrets") {
            hit(s.get("name"));
        }
    }
    let (key_ref, from_ref) = match kind {
        "secrets" => ("secretKeyRef", "secretRef"),
        "configmaps" => ("configMapKeyRef", "configMapRef"),
        _ => return found.get(),
    };
    for list in ["initContainers", "containers", "ephemeralContainers"] {
        for c in arr(spec, list) {
            for e in arr(Some(&c), "env") {
                hit(e.get("valueFrom").and_then(|v| v.get(key_ref)).and_then(|r| r.get("name")));
            }
            for e in arr(Some(&c), "envFrom") {
                hit(e.get(from_ref).and_then(|r| r.get("name")));
            }
        }
    }
    found.get()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_fmt::json;

    struct P(Vec<Value>);
    impl Pods for P {
        fn get(&self, ns: &str, name: &str) -> Option<Value> {
            self.0.iter().find(|p| p.pointer(&["metadata", "namespace"]).and_then(Value::as_str) == Some(ns) && p.pointer(&["metadata", "name"]).and_then(Value::as_str) == Some(name)).cloned()
        }
        fn in_namespace(&self, ns: &str) -> Vec<Value> {
            self.0.iter().filter(|p| p.pointer(&["metadata", "namespace"]).and_then(Value::as_str) == Some(ns)).cloned().collect()
        }
    }

    fn attrs(verb: &str, group: &str, res: &str, sub: &str, ns: &str, name: &str) -> Attrs {
        Attrs { verb: verb.into(), api_group: group.into(), resource: res.into(), subresource: sub.into(), namespace: ns.into(), name: name.into(), resource_request: true, path: String::new() }
    }

    fn pods() -> P {
        P(alloc::vec![
            json::parse_str(r#"{"metadata":{"namespace":"a","name":"web"},"spec":{"nodeName":"n1","serviceAccountName":"sa1","volumes":[{"name":"v","secret":{"secretName":"s1"}},{"name":"p","projected":{"sources":[{"configMap":{"name":"kube-root-ca.crt"}}]}}],"containers":[{"envFrom":[{"secretRef":{"name":"s2"}}],"env":[{"name":"X","valueFrom":{"configMapKeyRef":{"name":"c1","key":"k"}}}]}]}}"#).unwrap(),
            json::parse_str(r#"{"metadata":{"namespace":"a","name":"db"},"spec":{"nodeName":"n2","volumes":[{"name":"v","secret":{"secretName":"s3"}}]}}"#).unwrap(),
        ])
    }

    #[test]
    fn identity() {
        let g = alloc::vec![String::from("system:nodes")];
        assert_eq!(node_name("system:node:n1", &g), Some("n1"));
        assert_eq!(node_name("system:node:n1", &[]), None);
        assert_eq!(node_name("alice", &g), None);
    }

    #[test]
    fn reads_scoped_to_own_pods() {
        let p = pods();
        let d = |verb: &str, res: &str, name: &str| decide("n1", &attrs(verb, "", res, "", "a", name), None, &p);
        assert_eq!(d("get", "secrets", "s1"), Decision::Allow);
        assert_eq!(d("get", "secrets", "s2"), Decision::Allow);
        assert_eq!(d("get", "configmaps", "c1"), Decision::Allow);
        assert_eq!(d("get", "configmaps", "kube-root-ca.crt"), Decision::Allow);
        assert_eq!(d("get", "secrets", "s3"), Decision::NoOpinion); // n2's pod
        assert_eq!(d("list", "secrets", ""), Decision::NoOpinion);
        assert_eq!(d("update", "secrets", "s1"), Decision::Deny);
    }

    #[test]
    fn writes_scoped_to_self() {
        let p = pods();
        assert_eq!(decide("n1", &attrs("patch", "", "pods", "status", "a", "web"), None, &p), Decision::NoOpinion);
        assert_eq!(decide("n1", &attrs("patch", "", "pods", "status", "a", "db"), None, &p), Decision::Deny);
        assert_eq!(decide("n1", &attrs("delete", "", "pods", "", "a", "db"), None, &p), Decision::Deny);
        assert_eq!(decide("n1", &attrs("create", "", "pods", "", "a", ""), Some("x"), &p), Decision::Deny);
        assert_eq!(decide("n1", &attrs("update", "", "nodes", "status", "", "n2"), None, &p), Decision::Deny);
        assert_eq!(decide("n1", &attrs("create", "", "nodes", "", "", ""), Some("n1"), &p), Decision::NoOpinion);
        assert_eq!(decide("n1", &attrs("create", "", "nodes", "", "", ""), Some("n2"), &p), Decision::Deny);
        assert_eq!(decide("n1", &attrs("update", "coordination.k8s.io", "leases", "", "kube-node-lease", "n2"), None, &p), Decision::Deny);
        assert_eq!(decide("n1", &attrs("create", "", "serviceaccounts", "token", "a", "sa1"), None, &p), Decision::Allow);
        assert_eq!(decide("n1", &attrs("create", "", "serviceaccounts", "token", "a", "default"), None, &p), Decision::Deny);
    }
}
