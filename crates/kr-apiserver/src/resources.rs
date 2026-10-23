//! The built-in resource table: everything discovery advertises and the generic REST handlers
//! serve. Objects are stored as JSON under `/registry/<group>/<resource>/[<ns>/]<name>`.

#[derive(Debug)]
pub struct Resource {
    /// "" for the core group.
    pub group: &'static str,
    pub version: &'static str,
    pub kind: &'static str,
    pub plural: &'static str,
    pub singular: &'static str,
    pub namespaced: bool,
    pub short: &'static [&'static str],
    /// Subresources served (status, scale).
    pub subresources: &'static [&'static str],
    /// Categories for `kubectl get all`.
    pub categories: &'static [&'static str],
}

impl Resource {
    pub fn group_version(&self) -> String {
        if self.group.is_empty() {
            self.version.to_string()
        } else {
            alloc::format!("{}/{}", self.group, self.version)
        }
    }

    /// Store key prefix for this resource (ending in `/`).
    pub fn prefix(&self) -> String {
        let g = if self.group.is_empty() { "core" } else { self.group };
        alloc::format!("/registry/{g}/{}/", self.plural)
    }

    pub fn key(&self, namespace: Option<&str>, name: &str) -> String {
        match namespace {
            Some(ns) if self.namespaced => alloc::format!("{}{ns}/{name}", self.prefix()),
            _ => alloc::format!("{}{name}", self.prefix()),
        }
    }

    /// Names must be DNS-1123 subdomains for most kinds; a few require a DNS-1123 label.
    pub fn name_is_label(&self) -> bool {
        matches!(self.plural, "namespaces" | "services")
    }
}

use alloc::string::{String, ToString};

macro_rules! r {
    ($g:expr, $v:expr, $kind:expr, $plural:expr, $singular:expr, $ns:expr, [$($s:expr),*], [$($sub:expr),*], [$($cat:expr),*]) => {
        Resource { group: $g, version: $v, kind: $kind, plural: $plural, singular: $singular, namespaced: $ns, short: &[$($s),*], subresources: &[$($sub),*], categories: &[$($cat),*] }
    };
}

pub static RESOURCES: &[Resource] = &[
    // core/v1
    r!("", "v1", "Namespace", "namespaces", "namespace", false, ["ns"], ["status", "finalize"], []),
    r!("", "v1", "Node", "nodes", "node", false, ["no"], ["status"], []),
    r!("", "v1", "Pod", "pods", "pod", true, ["po"], ["status", "binding"], ["all"]),
    r!("", "v1", "Service", "services", "service", true, ["svc"], ["status"], ["all"]),
    r!("", "v1", "Endpoints", "endpoints", "endpoints", true, ["ep"], [], []),
    r!("", "v1", "ConfigMap", "configmaps", "configmap", true, ["cm"], [], []),
    r!("", "v1", "Secret", "secrets", "secret", true, [], [], []),
    r!("", "v1", "ServiceAccount", "serviceaccounts", "serviceaccount", true, ["sa"], [], []),
    r!("", "v1", "Event", "events", "event", true, ["ev"], [], []),
    r!("", "v1", "PersistentVolumeClaim", "persistentvolumeclaims", "persistentvolumeclaim", true, ["pvc"], ["status"], []),
    r!("", "v1", "PersistentVolume", "persistentvolumes", "persistentvolume", false, ["pv"], ["status"], []),
    r!("", "v1", "ResourceQuota", "resourcequotas", "resourcequota", true, ["quota"], ["status"], []),
    r!("", "v1", "LimitRange", "limitranges", "limitrange", true, ["limits"], [], []),
    // apps/v1
    r!("apps", "v1", "Deployment", "deployments", "deployment", true, ["deploy"], ["status", "scale"], ["all"]),
    r!("apps", "v1", "ReplicaSet", "replicasets", "replicaset", true, ["rs"], ["status", "scale"], ["all"]),
    r!("apps", "v1", "StatefulSet", "statefulsets", "statefulset", true, ["sts"], ["status", "scale"], ["all"]),
    r!("apps", "v1", "DaemonSet", "daemonsets", "daemonset", true, ["ds"], ["status"], ["all"]),
    r!("apps", "v1", "ControllerRevision", "controllerrevisions", "controllerrevision", true, [], [], []),
    // batch/v1
    r!("batch", "v1", "Job", "jobs", "job", true, [], ["status"], ["all"]),
    r!("batch", "v1", "CronJob", "cronjobs", "cronjob", true, ["cj"], ["status"], ["all"]),
    // coordination / discovery / networking / policy / scheduling
    r!("coordination.k8s.io", "v1", "Lease", "leases", "lease", true, [], [], []),
    r!("discovery.k8s.io", "v1", "EndpointSlice", "endpointslices", "endpointslice", true, [], [], []),
    r!("networking.k8s.io", "v1", "Ingress", "ingresses", "ingress", true, ["ing"], ["status"], []),
    r!("networking.k8s.io", "v1", "NetworkPolicy", "networkpolicies", "networkpolicy", true, ["netpol"], [], []),
    r!("policy", "v1", "PodDisruptionBudget", "poddisruptionbudgets", "poddisruptionbudget", true, ["pdb"], ["status"], []),
    r!("scheduling.k8s.io", "v1", "PriorityClass", "priorityclasses", "priorityclass", false, ["pc"], [], []),
    // rbac.authorization.k8s.io/v1
    r!("rbac.authorization.k8s.io", "v1", "Role", "roles", "role", true, [], [], []),
    r!("rbac.authorization.k8s.io", "v1", "RoleBinding", "rolebindings", "rolebinding", true, [], [], []),
    r!("rbac.authorization.k8s.io", "v1", "ClusterRole", "clusterroles", "clusterrole", false, [], [], []),
    r!("rbac.authorization.k8s.io", "v1", "ClusterRoleBinding", "clusterrolebindings", "clusterrolebinding", false, [], [], []),
];

/// Looks up a resource by group, version and plural.
pub fn find(group: &str, version: &str, plural: &str) -> Option<&'static Resource> {
    RESOURCES.iter().find(|r| r.group == group && r.version == version && r.plural == plural)
}

/// Groups in discovery order (core first), each with its versions.
pub fn groups() -> alloc::vec::Vec<&'static str> {
    let mut out: alloc::vec::Vec<&'static str> = alloc::vec::Vec::new();
    for r in RESOURCES {
        if !r.group.is_empty() && !out.contains(&r.group) {
            out.push(r.group);
        }
    }
    out
}
