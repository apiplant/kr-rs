//! RBAC authorization (rbac.authorization.k8s.io/v1) and the bootstrap policy.
//!
//! A request is allowed if any rule reachable from the user's ClusterRoleBindings, or from
//! RoleBindings in the request namespace, matches its attributes. Deny is the default; there are
//! no deny rules (as upstream).

use crate::api::User;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_fmt::json::Value;

/// What a request does, derived from its URL and method.
#[derive(Debug, Clone, Default)]
pub struct Attrs {
    pub verb: String,
    /// Resource requests:
    pub api_group: String,
    pub resource: String,
    pub subresource: String,
    pub namespace: String,
    pub name: String,
    /// Non-resource requests (discovery, /healthz, ...):
    pub path: String,
    pub resource_request: bool,
}

fn has(list: Option<&Value>, want: &str) -> bool {
    list.and_then(Value::as_array).is_some_and(|a| a.iter().filter_map(Value::as_str).any(|v| v == "*" || v == want))
}

fn rule_matches(rule: &Value, a: &Attrs) -> bool {
    if !has(rule.get("verbs"), &a.verb) {
        return false;
    }
    if !a.resource_request {
        // nonResourceURLs: exact, or prefix with a trailing "*".
        return rule.get("nonResourceURLs").and_then(Value::as_array).is_some_and(|urls| {
            urls.iter().filter_map(Value::as_str).any(|u| u == "*" || u == a.path || (u.ends_with('*') && a.path.starts_with(&u[..u.len() - 1])))
        });
    }
    if !has(rule.get("apiGroups"), &a.api_group) {
        return false;
    }
    let full = if a.subresource.is_empty() { a.resource.clone() } else { alloc::format!("{}/{}", a.resource, a.subresource) };
    let res_ok = rule.get("resources").and_then(Value::as_array).is_some_and(|rs| {
        rs.iter().filter_map(Value::as_str).any(|r| r == "*" || r == full || (r.ends_with("/*") && a.subresource.is_empty() == false && &r[..r.len() - 2] == a.resource) || (r.starts_with("*/") && &r[2..] == a.subresource))
    });
    if !res_ok {
        return false;
    }
    match rule.get("resourceNames").and_then(Value::as_array) {
        Some(names) if !names.is_empty() => !a.name.is_empty() && names.iter().filter_map(Value::as_str).any(|n| n == a.name),
        _ => true,
    }
}

fn subject_matches(s: &Value, u: &User, binding_ns: &str) -> bool {
    let name = s.get("name").and_then(Value::as_str).unwrap_or("");
    match s.get("kind").and_then(Value::as_str) {
        Some("User") => name == u.name,
        Some("Group") => u.groups.iter().any(|g| g == name),
        Some("ServiceAccount") => {
            let ns = s.get("namespace").and_then(Value::as_str).filter(|n| !n.is_empty()).unwrap_or(binding_ns);
            u.name == alloc::format!("system:serviceaccount:{ns}:{name}")
        }
        _ => false,
    }
}

/// Inputs: every ClusterRoleBinding, the RoleBindings of the request namespace, and a role
/// lookup `(kind, namespace, name) -> rules`.
pub fn allowed(u: &User, a: &Attrs, crbs: &[Value], rbs: &[Value], role_rules: &dyn Fn(&str, &str, &str) -> Option<Vec<Value>>) -> bool {
    let check = |binding: &Value, ns: &str, role_ns: &str| -> bool {
        let subjects = binding.get("subjects").and_then(Value::as_array).unwrap_or(&[]);
        if !subjects.iter().any(|s| subject_matches(s, u, ns)) {
            return false;
        }
        let kind = binding.pointer(&["roleRef", "kind"]).and_then(Value::as_str).unwrap_or("");
        let name = binding.pointer(&["roleRef", "name"]).and_then(Value::as_str).unwrap_or("");
        let rns = if kind == "Role" { role_ns } else { "" };
        role_rules(kind, rns, name).is_some_and(|rules| rules.iter().any(|r| rule_matches(r, a)))
    };
    if crbs.iter().any(|b| check(b, "", "")) {
        return true;
    }
    // RoleBindings grant only within their namespace (never cluster-scoped or non-resource).
    a.resource_request && !a.namespace.is_empty() && rbs.iter().any(|b| check(b, &a.namespace, &a.namespace))
}

// ---- bootstrap policy (a subset of upstream's) ----

fn rule(groups: &[&str], resources: &[&str], verbs: &[&str]) -> String {
    let q = |v: &[&str]| v.iter().map(|x| alloc::format!("\"{x}\"")).collect::<Vec<_>>().join(",");
    alloc::format!(r#"{{"apiGroups":[{}],"resources":[{}],"verbs":[{}]}}"#, q(groups), q(resources), q(verbs))
}

fn nonres(urls: &[&str], verbs: &[&str]) -> String {
    let q = |v: &[&str]| v.iter().map(|x| alloc::format!("\"{x}\"")).collect::<Vec<_>>().join(",");
    alloc::format!(r#"{{"nonResourceURLs":[{}],"verbs":[{}]}}"#, q(urls), q(verbs))
}

const READ: &[&str] = &["get", "list", "watch"];
const WRITE: &[&str] = &["create", "delete", "deletecollection", "patch", "update"];

/// (ClusterRole name, rules JSON array).
pub fn bootstrap_roles() -> Vec<(&'static str, String)> {
    let all = [READ, WRITE].concat();
    let workloads_core = &["pods", "pods/attach", "pods/exec", "pods/portforward", "pods/proxy", "pods/log", "replicationcontrollers", "services", "services/proxy", "endpoints", "persistentvolumeclaims", "configmaps", "secrets", "serviceaccounts", "events"];
    let apps = &["deployments", "deployments/scale", "replicasets", "replicasets/scale", "statefulsets", "statefulsets/scale", "daemonsets", "controllerrevisions"];
    let batch = &["jobs", "cronjobs"];
    let view_core = &["pods", "pods/log", "pods/status", "replicationcontrollers", "services", "endpoints", "persistentvolumeclaims", "configmaps", "serviceaccounts", "events", "namespaces", "limitranges", "resourcequotas"];
    let edit = alloc::format!(
        "[{},{},{},{},{},{}]",
        rule(&[""], workloads_core, &all),
        rule(&["apps"], apps, &all),
        rule(&["batch"], batch, &all),
        rule(&["networking.k8s.io"], &["ingresses", "networkpolicies"], &all),
        rule(&["policy"], &["poddisruptionbudgets"], &all),
        rule(&["discovery.k8s.io"], &["endpointslices"], READ)
    );
    let admin = alloc::format!("{},{}]", &edit[..edit.len() - 1], rule(&["rbac.authorization.k8s.io"], &["roles", "rolebindings"], &all));
    let view = alloc::format!(
        "[{},{},{},{}]",
        rule(&[""], view_core, READ),
        rule(&["apps"], apps, READ),
        rule(&["batch"], batch, READ),
        rule(&["networking.k8s.io", "policy", "discovery.k8s.io"], &["*"], READ)
    );
    alloc::vec![
        ("cluster-admin", alloc::format!("[{},{}]", rule(&["*"], &["*"], &["*"]), nonres(&["*"], &["*"]))),
        ("admin", admin),
        ("edit", edit),
        ("view", view),
        ("system:discovery", alloc::format!("[{}]", nonres(&["/api", "/api/*", "/apis", "/apis/*", "/healthz", "/livez", "/readyz", "/openapi", "/openapi/*", "/version", "/version/"], &["get"]))),
        ("system:public-info-viewer", alloc::format!("[{}]", nonres(&["/healthz", "/livez", "/readyz", "/version", "/version/"], &["get"]))),
        ("system:basic-user", alloc::format!("[{}]", rule(&["authorization.k8s.io"], &["selfsubjectaccessreviews", "selfsubjectrulesreviews"], &["create"]))),
        ("system:service-account-issuer-discovery", alloc::format!("[{}]", nonres(&["/.well-known/openid-configuration", "/.well-known/openid-configuration/", "/openid/v1/jwks", "/openid/v1/jwks/"], &["get"]))),
    ]
}

/// (ClusterRoleBinding name, role, subjects JSON array).
pub fn bootstrap_bindings() -> Vec<(&'static str, &'static str, &'static str)> {
    alloc::vec![
        ("cluster-admin", "cluster-admin", r#"[{"kind":"Group","apiGroup":"rbac.authorization.k8s.io","name":"system:masters"}]"#),
        ("system:discovery", "system:discovery", r#"[{"kind":"Group","apiGroup":"rbac.authorization.k8s.io","name":"system:authenticated"}]"#),
        ("system:basic-user", "system:basic-user", r#"[{"kind":"Group","apiGroup":"rbac.authorization.k8s.io","name":"system:authenticated"}]"#),
        ("system:public-info-viewer", "system:public-info-viewer", r#"[{"kind":"Group","apiGroup":"rbac.authorization.k8s.io","name":"system:authenticated"},{"kind":"Group","apiGroup":"rbac.authorization.k8s.io","name":"system:unauthenticated"}]"#),
        ("system:service-account-issuer-discovery", "system:service-account-issuer-discovery", r#"[{"kind":"Group","apiGroup":"rbac.authorization.k8s.io","name":"system:serviceaccounts"}]"#),
    ]
}

/// Maps an HTTP method to a Kubernetes verb.
pub fn verb(method: &str, has_name: bool, watch: bool) -> String {
    match method {
        "GET" | "HEAD" if watch => "watch",
        "GET" | "HEAD" if has_name => "get",
        "GET" | "HEAD" => "list",
        "POST" => "create",
        "PUT" => "update",
        "PATCH" => "patch",
        "DELETE" if has_name => "delete",
        "DELETE" => "deletecollection",
        other => return other.to_ascii_lowercase(),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_fmt::json::parse_str;

    fn user(name: &str, groups: &[&str]) -> User {
        User { name: name.into(), groups: groups.iter().map(|g| String::from(*g)).collect() }
    }

    fn attrs(verb: &str, group: &str, res: &str, ns: &str) -> Attrs {
        Attrs { verb: verb.into(), api_group: group.into(), resource: res.into(), namespace: ns.into(), resource_request: true, ..Default::default() }
    }

    #[test]
    fn bindings_and_rules() {
        let roles = bootstrap_roles();
        let lookup = |kind: &str, ns: &str, name: &str| -> Option<Vec<Value>> {
            if kind == "ClusterRole" {
                roles.iter().find(|(n, _)| *n == name).map(|(_, r)| parse_str(r).unwrap().as_array().unwrap().to_vec())
            } else if ns == "dev" && name == "pod-reader" {
                Some(alloc::vec![parse_str(r#"{"apiGroups":[""],"resources":["pods"],"verbs":["get","list"],"resourceNames":[]}"#).unwrap()])
            } else {
                None
            }
        };
        let crbs: Vec<Value> = bootstrap_bindings().iter().map(|(n, r, s)| parse_str(&alloc::format!(r#"{{"metadata":{{"name":"{n}"}},"roleRef":{{"kind":"ClusterRole","name":"{r}"}},"subjects":{s}}}"#)).unwrap()).collect();
        let rb = parse_str(r#"{"metadata":{"namespace":"dev"},"roleRef":{"kind":"Role","name":"pod-reader"},"subjects":[{"kind":"ServiceAccount","name":"bot"}]}"#).unwrap();
        let admin = user("kubernetes-admin", &["system:masters", "system:authenticated"]);
        let bot = user("system:serviceaccount:dev:bot", &["system:serviceaccounts", "system:serviceaccounts:dev", "system:authenticated"]);
        assert!(allowed(&admin, &attrs("delete", "apps", "deployments", "x"), &crbs, &[], &lookup));
        assert!(allowed(&bot, &attrs("list", "", "pods", "dev"), &crbs, &[rb.clone()], &lookup));
        assert!(!allowed(&bot, &attrs("delete", "", "pods", "dev"), &crbs, &[rb.clone()], &lookup));
        assert!(!allowed(&bot, &attrs("list", "", "pods", "prod"), &crbs, &[], &lookup));
        assert!(!allowed(&bot, &attrs("list", "", "secrets", "dev"), &crbs, &[rb], &lookup));
        let discovery = Attrs { verb: "get".into(), path: "/apis/apps/v1".into(), ..Default::default() };
        assert!(allowed(&bot, &discovery, &crbs, &[], &lookup));
        let anon = user("system:anonymous", &["system:unauthenticated"]);
        assert!(!allowed(&anon, &discovery, &crbs, &[], &lookup));
        assert!(allowed(&anon, &Attrs { verb: "get".into(), path: "/version".into(), ..Default::default() }, &crbs, &[], &lookup));
    }
}
