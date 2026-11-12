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

/// Every rule the user gets from the ClusterRoleBindings and the RoleBindings of `ns` (those
/// RoleBindings are in `rbs`): what a SelfSubjectRulesReview reports.
pub fn rules_for(u: &User, crbs: &[Value], rbs: &[Value], ns: &str, role_rules: &dyn Fn(&str, &str, &str) -> Option<Vec<Value>>) -> Vec<Value> {
    let mut out = Vec::new();
    let mut take = |binding: &Value, bns: &str, role_ns: &str| {
        let subjects = binding.get("subjects").and_then(Value::as_array).unwrap_or(&[]);
        if !subjects.iter().any(|s| subject_matches(s, u, bns)) {
            return;
        }
        let kind = binding.pointer(&["roleRef", "kind"]).and_then(Value::as_str).unwrap_or("");
        let name = binding.pointer(&["roleRef", "name"]).and_then(Value::as_str).unwrap_or("");
        let rns = if kind == "Role" { role_ns } else { "" };
        out.extend(role_rules(kind, rns, name).unwrap_or_default());
    };
    crbs.iter().for_each(|b| take(b, "", ""));
    if !ns.is_empty() {
        rbs.iter().for_each(|b| take(b, ns, ns));
    }
    out
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

fn metrics_rule() -> String {
    rule(&["metrics.k8s.io"], &["pods", "nodes"], &["get", "list", "watch"])
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
        "[{},{},{},{},{},{},{}]",
        rule(&[""], workloads_core, &all),
        rule(&["apps"], apps, &all),
        rule(&["batch"], batch, &all),
        rule(&["networking.k8s.io"], &["ingresses", "networkpolicies"], &all),
        rule(&["policy"], &["poddisruptionbudgets"], &all),
        rule(&["discovery.k8s.io"], &["endpointslices"], READ),
        metrics_rule()
    );
    let admin = alloc::format!("{},{}]", &edit[..edit.len() - 1], rule(&["rbac.authorization.k8s.io"], &["roles", "rolebindings"], &all));
    let view = alloc::format!(
        "[{},{},{},{},{}]",
        rule(&[""], view_core, READ),
        rule(&["apps"], apps, READ),
        rule(&["batch"], batch, READ),
        rule(&["networking.k8s.io", "policy", "discovery.k8s.io"], &["*"], READ),
        metrics_rule()
    );
    alloc::vec![
        ("cluster-admin", alloc::format!("[{},{}]", rule(&["*"], &["*"], &["*"]), nonres(&["*"], &["*"]))),
        ("admin", admin),
        ("edit", edit),
        ("view", view),
        // Upstream aggregates this into view/edit/admin by label; kr has no aggregation
        // controller, so the rule is inlined in those roles as well (KNOWN_ISSUES #200).
        ("system:aggregated-metrics-reader", alloc::format!("[{}]", metrics_rule())),
        ("system:monitoring", alloc::format!("[{}]", nonres(&["/metrics", "/metrics/*", "/healthz", "/healthz/*", "/livez", "/livez/*", "/readyz", "/readyz/*"], &["get"]))),
        ("system:discovery", alloc::format!("[{}]", nonres(&["/api", "/api/*", "/apis", "/apis/*", "/healthz", "/livez", "/readyz", "/openapi", "/openapi/*", "/version", "/version/"], &["get"]))),
        ("system:auth-delegator", alloc::format!("[{},{}]", rule(&["authentication.k8s.io"], &["tokenreviews"], &["create"]), rule(&["authorization.k8s.io"], &["subjectaccessreviews"], &["create"]))),
        ("system:public-info-viewer", alloc::format!("[{}]", nonres(&["/healthz", "/livez", "/readyz", "/version", "/version/"], &["get"]))),
        ("system:basic-user", alloc::format!("[{},{}]", rule(&["authorization.k8s.io"], &["selfsubjectaccessreviews", "selfsubjectrulesreviews"], &["create"]), rule(&["authentication.k8s.io"], &["selfsubjectreviews"], &["create"]))),
        // Node agents (kubelet + proxy). Secrets, configmaps and PVCs come from the Node
        // authorizer (node_authz), scoped to the node's own pods.
        (
            "system:node",
            alloc::format!(
                "[{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}]",
                rule(&[""], &["pods", "services", "endpoints", "namespaces"], READ),
                rule(&[""], &["pods"], &["delete"]),
                rule(&[""], &["pods/status", "nodes/status"], &["get", "patch", "update"]),
                rule(&[""], &["nodes"], &["get", "list", "watch", "create", "patch", "update"]),
                rule(&[""], &["events"], &["create", "patch", "update"]),
                rule(&["events.k8s.io"], &["events"], &["create", "patch", "update"]),
                rule(&[""], &["serviceaccounts/token"], &["create"]),
                rule(&["coordination.k8s.io"], &["leases"], &["get", "create", "update", "patch"]),
                rule(&["discovery.k8s.io"], &["endpointslices"], READ),
                rule(&[""], &["serviceaccounts"], &["get"]),
                rule(&["certificates.k8s.io"], &["podcertificaterequests"], &["create", "get", "list", "watch", "delete"]),
                rule(&["certificates.k8s.io"], &["clustertrustbundles"], READ),
                nonres(&["/api", "/api/*", "/apis", "/apis/*", "/version", "/healthz"], &["get"]),
                // Volumes (CSI, ADR-041): the claim status is further scoped by node_authz;
                // a node writes only its own CSINode (node_authz denies the others).
                rule(&[""], &["persistentvolumeclaims/status"], &["get", "patch", "update"]),
                rule(&[""], &["persistentvolumes"], READ),
                rule(&["storage.k8s.io"], &["volumeattachments", "csidrivers"], READ),
                rule(&["storage.k8s.io"], &["csinodes"], &["get", "create", "update", "patch", "delete"]),
                rule(&["storage.k8s.io"], &["storageclasses"], &["get", "list", "watch"]),
                rule(&["node.k8s.io"], &["runtimeclasses"], READ),
                rule(&["certificates.k8s.io"], &["certificatesigningrequests"], &["create", "get", "list", "watch"])
            ),
        ),
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
        ("system:node", "system:node", r#"[{"kind":"Group","apiGroup":"rbac.authorization.k8s.io","name":"system:nodes"}]"#),
    ]
}

/// Validation of a `certificatesigningrequests/approval` or `/status` write (KNOWN_ISSUES
/// #173), as upstream's strategies: only `Approved`/`Denied`/`Failed` conditions through
/// `approval`, never both Approved and Denied, no change once a certificate is issued, and
/// a new Approved/Denied needs the `approve` verb on the `signers` resource (name = signer
/// or `<domain>/*`); `status` may not touch Approved/Denied. A `kube-apiserver-client` request
/// naming `system:masters` can be approved by a `system:masters` member only. Err is
/// (status code, message). `can` answers an authorization question for the caller.
pub fn csr_update_check(sub: &str, old: &Value, new: &Value, masters: bool, can: &dyn Fn(&Attrs) -> bool) -> core::result::Result<(), (u16, String)> {
    let conds = |v: &Value| -> Vec<(String, String)> {
        let c = v.pointer(&["status", "conditions"]).and_then(Value::as_array).unwrap_or(&[]);
        c.iter().map(|c| (c.get("type").and_then(Value::as_str).unwrap_or("").to_string(), c.get("status").and_then(Value::as_str).unwrap_or("").to_string())).collect()
    };
    let (oc, nc) = (conds(old), conds(new));
    let issued = old.pointer(&["status", "certificate"]).and_then(Value::as_str).is_some_and(|c| !c.is_empty());
    let decided = |c: &[(String, String)], t: &str| c.iter().any(|(ty, st)| ty == t && st == "True");
    let added = |t: &str| nc.iter().any(|(ty, _)| ty == t) && !oc.iter().any(|(ty, _)| ty == t);
    let changes = |t: &str| oc.iter().filter(|(ty, _)| ty == t).ne(nc.iter().filter(|(ty, _)| ty == t));
    let bad = |m: &str| Err((422, m.to_string()));
    if sub == "approval" {
        if nc.iter().any(|(t, _)| !matches!(t.as_str(), "Approved" | "Denied" | "Failed")) {
            return bad("status.conditions: only Approved, Denied and Failed conditions are allowed through approval");
        }
        if (decided(&nc, "Approved") && decided(&nc, "Denied")) || (nc.iter().any(|(t, _)| t == "Approved") && nc.iter().any(|(t, _)| t == "Denied")) {
            return bad("status.conditions: Approved and Denied conditions are mutually exclusive");
        }
    } else if added("Approved") || added("Denied") || changes("Approved") || changes("Denied") {
        return bad("status.conditions: Approved and Denied can only be set through the approval subresource");
    }
    if issued && oc != nc {
        return bad("status.conditions: cannot update a CertificateSigningRequest whose certificate is issued");
    }
    if sub == "approval" && (added("Approved") || added("Denied")) {
        let signer = old.pointer(&["spec", "signerName"]).and_then(Value::as_str).unwrap_or("");
        let mut a = Attrs { verb: "approve".into(), api_group: "certificates.k8s.io".into(), resource: "signers".into(), name: signer.to_string(), resource_request: true, ..Default::default() };
        let mut ok = can(&a);
        if !ok {
            if let Some((domain, _)) = signer.split_once('/') {
                a.name = alloc::format!("{domain}/*");
                ok = can(&a);
            }
        }
        if !ok {
            return Err((403, alloc::format!("user not permitted to approve requests with signerName \"{signer}\"")));
        }
        if added("Approved") && signer == "kubernetes.io/kube-apiserver-client" && !masters && csr_names_masters(old) {
            return Err((403, "only system:masters may approve a client certificate for the system:masters group".to_string()));
        }
    }
    Ok(())
}

/// Does the PKCS#10 request in `spec.request` ask for `O=system:masters`? The subject is parsed
/// (organization values in UTF-8, printable, IA5, T61, BMP and universal strings); a request
/// whose subject cannot be parsed counts as naming it (fail closed).
fn csr_names_masters(csr: &Value) -> bool {
    let Some(b64) = csr.pointer(&["spec", "request"]).and_then(Value::as_str) else { return false };
    let Ok(pem) = kr_fmt::base64::decode(b64) else { return false };
    let Ok(ders) = kr_crypto::x509::pem_decode_all(&String::from_utf8_lossy(&pem), "CERTIFICATE REQUEST") else { return false };
    ders.iter().any(|d| match csr_organizations(d) {
        Some(orgs) => orgs.iter().any(|o| o == "system:masters"),
        None => true,
    })
}

/// One DER element: (tag, content, rest).
fn der(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let l0 = *b.get(1)?;
    let (len, off) = if l0 < 0x80 {
        (l0 as usize, 2)
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 3 {
            return None;
        }
        (b.get(2..2 + n)?.iter().fold(0usize, |a, x| a << 8 | *x as usize), 2 + n)
    };
    Some((tag, b.get(off..off.checked_add(len)?)?, &b[off + len..]))
}

/// The `O` (organization) values of the subject of a DER PKCS#10 request.
fn csr_organizations(req: &[u8]) -> Option<Vec<String>> {
    let (t, req, _) = der(req)?;
    let (t2, info, _) = der(req).filter(|_| t == 0x30)?;
    if t2 != 0x30 {
        return None;
    }
    let (tv, _, rest) = der(info)?; // version
    if tv != 0x02 {
        return None;
    }
    let (ts, mut name, _) = der(rest)?;
    if ts != 0x30 {
        return None;
    }
    let mut out = Vec::new();
    while !name.is_empty() {
        let (tset, mut set, rest) = der(name)?;
        if tset != 0x31 {
            return None;
        }
        name = rest;
        while !set.is_empty() {
            let (tseq, atv, rest) = der(set)?;
            if tseq != 0x30 {
                return None;
            }
            set = rest;
            let (to, oid, v) = der(atv)?;
            let (tval, val, _) = der(v)?;
            if to != 0x06 {
                return None;
            }
            if oid == [0x55, 0x04, 0x0a] {
                let text = match tval {
                    0x0c | 0x13 | 0x16 | 0x14 => String::from_utf8_lossy(val).into_owned(),
                    0x1e if val.len() % 2 == 0 => val.chunks(2).map(|c| char::from_u32((c[0] as u32) << 8 | c[1] as u32).unwrap_or('\u{fffd}')).collect(),
                    0x1c if val.len() % 4 == 0 => val.chunks(4).map(|c| char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]])).unwrap_or('\u{fffd}')).collect(),
                    _ => return None,
                };
                out.push(text);
            }
        }
    }
    Some(out)
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

    #[test]
    fn metrics_reader_in_view_edit_admin() {
        for (n, r) in bootstrap_roles() {
            if ["view", "edit", "admin", "system:aggregated-metrics-reader"].contains(&n) {
                assert!(r.contains(r#""apiGroups":["metrics.k8s.io"],"resources":["pods","nodes"]"#), "{n}");
            }
        }
    }

    #[test]
    fn node_role_volume_rules() {
        let roles = bootstrap_roles();
        let lookup = |kind: &str, _: &str, name: &str| -> Option<Vec<Value>> {
            (kind == "ClusterRole").then(|| roles.iter().find(|(n, _)| *n == name).map(|(_, r)| parse_str(r).unwrap().as_array().unwrap().to_vec())).flatten()
        };
        let crbs: Vec<Value> = bootstrap_bindings().iter().map(|(n, r, s)| parse_str(&alloc::format!(r#"{{"metadata":{{"name":"{n}"}},"roleRef":{{"kind":"ClusterRole","name":"{r}"}},"subjects":{s}}}"#)).unwrap()).collect();
        let node = user("system:node:n1", &["system:nodes", "system:authenticated"]);
        let ok = |v: &str, g: &str, r: &str, sub: &str| {
            let mut a = attrs(v, g, r, "");
            a.subresource = sub.into();
            allowed(&node, &a, &crbs, &[], &lookup)
        };
        assert!(ok("patch", "", "persistentvolumeclaims", "status"));
        assert!(ok("update", "", "persistentvolumeclaims", "status"));
        assert!(!ok("patch", "", "persistentvolumeclaims", ""));
        for r in ["volumeattachments", "csidrivers"] {
            assert!(ok("get", "storage.k8s.io", r, "") && ok("list", "storage.k8s.io", r, "") && ok("watch", "storage.k8s.io", r, ""));
            assert!(!ok("create", "storage.k8s.io", r, ""));
        }
        for v in ["create", "update", "patch", "get", "delete"] {
            assert!(ok(v, "storage.k8s.io", "csinodes", ""));
        }
        assert!(ok("get", "storage.k8s.io", "storageclasses", "") && !ok("delete", "storage.k8s.io", "storageclasses", ""));
        assert!(ok("watch", "", "persistentvolumes", "") && !ok("delete", "", "persistentvolumes", ""));
        assert!(ok("list", "node.k8s.io", "runtimeclasses", "") && !ok("create", "node.k8s.io", "runtimeclasses", ""));
        for v in ["create", "get", "list", "watch"] {
            assert!(ok(v, "certificates.k8s.io", "certificatesigningrequests", ""));
        }
        assert!(!ok("update", "certificates.k8s.io", "certificatesigningrequests", "approval"));
        assert!(!ok("approve", "certificates.k8s.io", "signers", ""));
    }

    fn csr(signer: &str, conds: &str, cert: &str) -> Value {
        parse_str(&alloc::format!(r#"{{"spec":{{"signerName":"{signer}","request":""}},"status":{{"conditions":{conds},"certificate":"{cert}"}}}}"#)).unwrap()
    }

    #[test]
    fn csr_approval_rules() {
        let none = |_: &Attrs| false;
        let all = |_: &Attrs| true;
        let only = |n: &'static str| move |a: &Attrs| a.verb == "approve" && a.resource == "signers" && a.name == n;
        let approved = r#"[{"type":"Approved","status":"True"}]"#;
        let old = csr("example.com/x", "[]", "");
        let new = csr("example.com/x", approved, "");
        assert!(csr_update_check("approval", &old, &new, false, &all).is_ok());
        assert_eq!(csr_update_check("approval", &old, &new, false, &none).unwrap_err().0, 403);
        assert!(csr_update_check("approval", &old, &new, false, &only("example.com/x")).is_ok());
        assert!(csr_update_check("approval", &old, &new, false, &only("example.com/*")).is_ok());
        assert_eq!(csr_update_check("approval", &old, &new, false, &only("other.com/*")).unwrap_err().0, 403);
        // other condition types, Approved + Denied
        let odd = csr("example.com/x", r#"[{"type":"Foo","status":"True"}]"#, "");
        assert_eq!(csr_update_check("approval", &old, &odd, true, &all).unwrap_err().0, 422);
        let both = csr("example.com/x", r#"[{"type":"Approved","status":"True"},{"type":"Denied","status":"True"}]"#, "");
        assert_eq!(csr_update_check("approval", &old, &both, true, &all).unwrap_err().0, 422);
        // issued: frozen
        let issued = csr("example.com/x", approved, "AAAA");
        let denied = csr("example.com/x", r#"[{"type":"Approved","status":"True"},{"type":"Failed","status":"True"}]"#, "AAAA");
        assert_eq!(csr_update_check("approval", &issued, &denied, true, &all).unwrap_err().0, 422);
        assert!(csr_update_check("approval", &issued, &issued, true, &all).is_ok());
        // status cannot approve; can set the certificate
        assert_eq!(csr_update_check("status", &old, &new, true, &all).unwrap_err().0, 422);
        assert!(csr_update_check("status", &new, &csr("example.com/x", approved, "AAAA"), false, &none).is_ok());
    }

    fn tlv(tag: u8, c: &[u8]) -> Vec<u8> {
        let mut v = alloc::vec![tag, c.len() as u8];
        v.extend_from_slice(c);
        v
    }

    fn req_with_org(tag: u8, org: &[u8]) -> Vec<u8> {
        let atv = |oid: &[u8], t: u8, val: &[u8]| tlv(0x31, &tlv(0x30, &[tlv(0x06, oid), tlv(t, val)].concat()));
        let name = tlv(0x30, &[atv(&[0x55, 0x04, 0x03], 0x0c, b"alice"), atv(&[0x55, 0x04, 0x0a], tag, org)].concat());
        tlv(0x30, &tlv(0x30, &[tlv(0x02, &[0]), name].concat()))
    }

    #[test]
    fn csr_subject_parsing() {
        let utf = req_with_org(0x0c, b"system:masters");
        assert_eq!(csr_organizations(&utf).unwrap(), ["system:masters"]);
        let bmp: Vec<u8> = "system:masters".encode_utf16().flat_map(|c| c.to_be_bytes()).collect();
        assert_eq!(csr_organizations(&req_with_org(0x1e, &bmp)).unwrap(), ["system:masters"]);
        assert_eq!(csr_organizations(&req_with_org(0x0c, b"dev")).unwrap(), ["dev"]);
        // A CN that merely mentions the group is not an organization.
        let atv = tlv(0x31, &tlv(0x30, &[tlv(0x06, &[0x55, 0x04, 0x03]), tlv(0x0c, b"system:masters")].concat()));
        let cn = tlv(0x30, &tlv(0x30, &[tlv(0x02, &[0]), tlv(0x30, &atv)].concat()));
        assert!(csr_organizations(&cn).unwrap().is_empty());
        assert!(csr_organizations(b"\x30\x03abc").is_none());
        let mk = |der: &[u8]| {
            let b64 = kr_fmt::base64::encode(kr_crypto::x509::pem_encode("CERTIFICATE REQUEST", der).as_bytes());
            parse_str(&alloc::format!(r#"{{"spec":{{"request":"{b64}"}}}}"#)).unwrap()
        };
        assert!(csr_names_masters(&mk(&req_with_org(0x1e, &bmp))));
        assert!(!csr_names_masters(&mk(&req_with_org(0x0c, b"dev"))));
        assert!(!csr_names_masters(&mk(&cn)));
        assert!(csr_names_masters(&mk(b"\x30\x03abc"))); // unparsable: fail closed
    }

    #[test]
    fn csr_masters_restriction() {
        let k = kr_crypto::x509::pem_encode("CERTIFICATE REQUEST", b"\x30\x03subject system:masters");
        let b64 = kr_fmt::base64::encode(k.as_bytes());
        let mk = |signer: &str| parse_str(&alloc::format!(r#"{{"spec":{{"signerName":"{signer}","request":"{b64}"}},"status":{{"conditions":[]}}}}"#)).unwrap();
        let ap = parse_str(r#"{"spec":{},"status":{"conditions":[{"type":"Approved","status":"True"}]}}"#).unwrap();
        let mut new = mk("kubernetes.io/kube-apiserver-client");
        new.set("status", ap.get("status").unwrap().clone());
        let old = mk("kubernetes.io/kube-apiserver-client");
        let all = |_: &Attrs| true;
        assert_eq!(csr_update_check("approval", &old, &new, false, &all).unwrap_err().0, 403);
        assert!(csr_update_check("approval", &old, &new, true, &all).is_ok());
        // other signers are not restricted
        let (old2, mut new2) = (mk("example.com/x"), mk("example.com/x"));
        new2.set("status", ap.get("status").unwrap().clone());
        assert!(csr_update_check("approval", &old2, &new2, false, &all).is_ok());
    }
}
