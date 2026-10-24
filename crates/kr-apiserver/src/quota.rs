//! ResourceQuota accounting shared by the admission step (`api.rs`) and the status controller
//! (`kr-controllers`): what one object contributes (`usage`), whether a quota's scopes select it,
//! which resources a quota tracks (`hard`, `tracked`), what an update changes (`delta`), what an
//! object must name explicitly (`missing`), the quota spec's validation and the upstream-shaped
//! admission error messages. Quantities are exact (`kr_fmt::quantity`).
//!
//! Semantics follow upstream's `pkg/quota/v1`: a terminal pod counts nothing, a pod's compute
//! usage is max(sum(containers), max(initContainers)) + overhead, scoped quotas only count pods,
//! and an `ExternalName` Service (no IP, no ports) is not limited by quota at all.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_fmt::json::Value;
use kr_fmt::quantity::{Format, Quantity};

/// Every legal `spec.scopes` / `scopeSelector.scopeName` value.
const SCOPES: &[&str] = &["Terminating", "NotTerminating", "BestEffort", "NotBestEffort", "PriorityClass", "CrossNamespacePodAffinity"];
/// Every legal `scopeSelector` operator.
const SCOPE_OPS: &[&str] = &["DoesNotExist", "Exists", "In", "NotIn"];

pub fn zero() -> Quantity {
    Quantity::from_i64(0, Format::DecimalSI)
}

pub fn count(n: i64) -> Quantity {
    Quantity::from_i64(n, Format::DecimalSI)
}

pub fn add(a: &Quantity, b: &Quantity) -> Quantity {
    let s = a.scaled_value(-9).unwrap_or(0) + b.scaled_value(-9).unwrap_or(0);
    Quantity::new(s, -9, if a.is_zero() { b.format() } else { a.format() })
}

/// A quantity value: a string (`"64Mi"`) or an unqueried-but-exact JSON number from YAML merging
/// (`pods: 2`). `Number::raw()` preserves the source text, so parsing stays exact.
fn qty(v: Option<&Value>) -> Option<Quantity> {
    match v? {
        Value::String(s) => Quantity::parse(s).ok(),
        Value::Number(n) => Quantity::parse(n.raw()).ok(),
        _ => None,
    }
}

fn list<'a>(spec: &'a Value, key: &str) -> &'a [Value] {
    spec.get(key).and_then(Value::as_array).unwrap_or(&[])
}

fn terminal(pod: &Value) -> bool {
    matches!(pod.pointer(&["status", "phase"]).and_then(Value::as_str), Some("Succeeded" | "Failed"))
}

/// Upstream rule: max(sum(containers), max(initContainers)) + overhead.
fn pod_resource(spec: &Value, kind: &str, res: &str) -> Quantity {
    let of = |c: &Value| qty(c.pointer(&["resources", kind, res])).unwrap_or_else(zero);
    let sum = list(spec, "containers").iter().fold(zero(), |a, c| add(&a, &of(c)));
    let v = list(spec, "initContainers").iter().map(of).fold(sum, |a, b| if b > a { b } else { a });
    add(&v, &qty(spec.pointer(&["overhead", res])).unwrap_or_else(zero))
}

/// What one object contributes to a namespace's quota usage.
pub fn usage(plural: &str, group: &str, obj: &Value) -> Vec<(String, Quantity)> {
    let mut out = Vec::new();
    if plural == "pods" && terminal(obj) {
        return out;
    }
    // Upstream: an ExternalName Service uses no IP and no ports, so quota does not limit it
    // (it contributes neither its own count nor nodeports/loadbalancers).
    if plural == "services" && obj.pointer(&["spec", "type"]).and_then(Value::as_str) == Some("ExternalName") {
        return out;
    }
    out.push((if group.is_empty() { format!("count/{plural}") } else { format!("count/{plural}.{group}") }, count(1)));
    if group.is_empty() && matches!(plural, "pods" | "services" | "secrets" | "configmaps" | "replicationcontrollers" | "resourcequotas" | "persistentvolumeclaims") {
        out.push((plural.to_string(), count(1)));
    }
    match (plural, group) {
        ("pods", "") => {
            let spec = obj.get("spec").unwrap_or(&Value::Null);
            for res in ["cpu", "memory", "ephemeral-storage"] {
                let (req, lim) = (pod_resource(spec, "requests", res), pod_resource(spec, "limits", res));
                out.push((res.to_string(), req));
                out.push((format!("requests.{res}"), req));
                out.push((format!("limits.{res}"), lim));
            }
        }
        ("services", "") => {
            let ty = obj.pointer(&["spec", "type"]).and_then(Value::as_str).unwrap_or("ClusterIP");
            let ports = list(obj.get("spec").unwrap_or(&Value::Null), "ports").iter().filter(|p| p.get("nodePort").and_then(Value::as_i64).is_some_and(|n| n != 0)).count();
            let np = if matches!(ty, "NodePort" | "LoadBalancer") { ports } else { 0 };
            out.push(("services.nodeports".to_string(), count(np as i64)));
            out.push(("services.loadbalancers".to_string(), count((ty == "LoadBalancer") as i64)));
        }
        ("persistentvolumeclaims", "") => {
            out.push(("requests.storage".to_string(), qty(obj.pointer(&["spec", "resources", "requests", "storage"])).unwrap_or_else(zero)));
        }
        _ => {}
    }
    out
}

/// `new` minus `old` for the same object: what a usage-changing update adds (and a leader
/// over quota counts only positive shares; negative deltas are always allowed).
pub fn delta(plural: &str, group: &str, new: &Value, old: &Value) -> Vec<(String, Quantity)> {
    let o = usage(plural, group, old);
    usage(plural, group, new)
        .into_iter()
        .map(|(k, n)| {
            let d = n.scaled_value(-9).unwrap_or(0) - o.iter().find(|(ok, _)| ok == &k).map(|(_, q)| q.scaled_value(-9).unwrap_or(0)).unwrap_or(0);
            (k, Quantity::new(d, -9, n.format()))
        })
        .collect()
}

/// `spec.hard` as canonical (name, Quantity) pairs sorted by name. The spec is validated at
/// admission, so a stored quota's hard always parses; unparseable values count as absent.
pub fn hard(quota: &Value) -> Vec<(String, Quantity)> {
    let mut out: Vec<(String, Quantity)> = quota
        .pointer(&["spec", "hard"])
        .and_then(Value::as_object)
        .map(|m| m.iter().filter_map(|(k, v)| qty(Some(v)).map(|q| (k.clone(), q))).collect())
        .unwrap_or_default();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// `a=1, b=200m` (sorted names) for quota admission messages.
pub fn pairs(list: &[(String, Quantity)]) -> String {
    let mut l = list.to_vec();
    l.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = String::new();
    for (k, q) in l {
        if !out.is_empty() {
            out.push_str(", ");
        }
        out.push_str(&format!("{}={}", k, q.to_canonical_string()));
    }
    out
}

/// Upstream message when a create/update would exceed a tracked name:
/// `exceeded quota: <name>, requested: <pairs>, used: <pairs>, limited: <pairs>`.
pub fn exceeded_msg(quota: &Value, requested: &[(String, Quantity)], used: &[(String, Quantity)], limited: &[(String, Quantity)]) -> String {
    format!(
        "exceeded quota: {}, requested: {}, used: {}, limited: {}",
        name(quota),
        pairs(requested),
        pairs(used),
        pairs(limited)
    )
}

/// Upstream message when the object must name a tracked resource explicitly:
/// `failed quota: <name>: must specify <n1>,<n2>`.
pub fn must_specify_msg(quota: &Value, missing: &[String]) -> String {
    format!("failed quota: {}: must specify {}", name(quota), missing.join(","))
}

fn name(o: &Value) -> &str {
    o.pointer(&["metadata", "name"]).and_then(Value::as_str).unwrap_or("")
}

/// ResourceQuota spec validation (upstream `ValidateResourceQuota`): every `spec.hard` value is a
/// quantity, scopes are known names (unique), and scopeSelector operators are legal — with
/// `Exists`/`DoesNotExist` only, except on `PriorityClass`. Everything else is accepted.
pub fn validate(quota: &Value) -> Result<(), String> {
    let spec = quota.get("spec").unwrap_or(&Value::Null);
    if let Some(hard) = spec.get("hard").and_then(Value::as_object) {
        for (k, v) in hard {
            if qty(Some(v)).is_none() {
                return Err(format!("spec.hard[{k}]: Invalid value: {}: quantity must match the regular expression ^([+-]?[0-9.]+)([eEinumkKMGTP]*[-+]?[0-9]*)$", json_text(v)));
            }
        }
    }
    for (i, scope) in list(spec, "scopes").iter().enumerate() {
        let Some(s) = scope.as_str() else {
            return Err(format!("spec.scopes[{i}]: Unsupported value: {}: enabled values: {}", json_text(scope), supported(SCOPES)));
        };
        if !SCOPES.contains(&s) {
            return Err(format!("spec.scopes[{i}]: Unsupported value: {s:?}: supported values: {}", supported(SCOPES)));
        }
        if list(spec, "scopes").iter().filter(|x| x.as_str() == Some(s)).count() > 1 {
            return Err(format!("spec.scopes[{i}]: Invalid value: {s:?}: duplicate scope"));
        }
    }
    for (i, e) in spec.pointer(&["scopeSelector", "matchExpressions"]).and_then(Value::as_array).unwrap_or(&[]).iter().enumerate() {
        let scope = e.get("scopeName").and_then(Value::as_str).unwrap_or("");
        let op = e.get("operator").and_then(Value::as_str).unwrap_or("");
        if !SCOPE_OPS.contains(&op) {
            return Err(format!("spec.scopeSelector.matchExpressions[{i}].operator: Unsupported value: {op:?}: supported values: {}", supported(SCOPE_OPS)));
        }
        if !SCOPES.contains(&scope) {
            return Err(format!("spec.scopeSelector.matchExpressions[{i}].scopeName: Unsupported value: {scope:?}: supported values: {}", supported(SCOPES)));
        }
        if scope != "PriorityClass" && !matches!(op, "Exists" | "DoesNotExist") {
            return Err(format!("spec.scopeSelector.matchExpressions[{i}].operator: Invalid value: {op:?}: may only use `DoesNotExist` or `Exists` when scopeName is not `PriorityClass`"));
        }
    }
    Ok(())
}

/// A quoted JSON rendering of `v` for error values.
fn json_text(v: &Value) -> String {
    kr_fmt::json::to_string(v)
}

/// `["a", "b"]`-style list of the supported values.
fn supported(vs: &[&str]) -> String {
    let mut quoted: Vec<String> = vs.iter().map(|v| format!("\"{v}\"")).collect();
    quoted.sort();
    quoted.join(", ")
}

fn best_effort(pod: &Value) -> bool {
    let spec = pod.get("spec").unwrap_or(&Value::Null);
    let any = |c: &Value| ["requests", "limits"].iter().any(|k| c.pointer(&["resources", k]).and_then(Value::as_object).is_some_and(|o| !o.is_empty()));
    !list(spec, "containers").iter().chain(list(spec, "initContainers")).any(any)
}

/// Does `scope` with operator `op`/`values` select the pod?
fn scope_matches(scope: &str, op: &str, values: &[&str], pod: &Value) -> bool {
    let spec = pod.get("spec").unwrap_or(&Value::Null);
    let (base, class) = match scope {
        "Terminating" => (spec.get("activeDeadlineSeconds").is_some_and(|v| !v.is_null()), false),
        "NotTerminating" => (spec.get("activeDeadlineSeconds").is_none_or(Value::is_null), false),
        "BestEffort" => (best_effort(pod), false),
        "NotBestEffort" => (!best_effort(pod), false),
        "PriorityClass" => (spec.get("priorityClassName").and_then(Value::as_str).is_some_and(|s| !s.is_empty()), true),
        "CrossNamespacePodAffinity" => (false, false),
        _ => return false,
    };
    if class {
        let pc = spec.get("priorityClassName").and_then(Value::as_str).unwrap_or("");
        return match op {
            "In" => values.contains(&pc),
            "NotIn" => !values.contains(&pc),
            "DoesNotExist" => !base,
            _ => base,
        };
    }
    match op {
        "DoesNotExist" | "NotIn" => !base,
        "In" => base,
        _ => base,
    }
}

/// `spec.scopes` and `spec.scopeSelector` must all select the object. A scoped quota only
/// counts pods.
pub fn matches_scopes(quota: &Value, plural: &str, obj: &Value) -> bool {
    let spec = quota.get("spec").unwrap_or(&Value::Null);
    let scopes = list(spec, "scopes");
    let exprs = spec.pointer(&["scopeSelector", "matchExpressions"]).and_then(Value::as_array).unwrap_or(&[]);
    if scopes.is_empty() && exprs.is_empty() {
        return true;
    }
    if plural != "pods" {
        return false;
    }
    scopes.iter().filter_map(Value::as_str).all(|s| scope_matches(s, "Exists", &[], obj))
        && exprs.iter().all(|e| {
            let vals: Vec<&str> = list(e, "values").iter().filter_map(Value::as_str).collect();
            scope_matches(e.get("scopeName").and_then(Value::as_str).unwrap_or(""), e.get("operator").and_then(Value::as_str).unwrap_or("Exists"), &vals, obj)
        })
}

pub fn tracked(quota: &Value, name: &str) -> bool {
    quota.pointer(&["spec", "hard", name]).is_some()
}

/// Tracked names the object fails to name explicitly: the cpu/memory variants missing on some
/// container of a (non-terminal) pod, and `requests.storage` missing on a PVC. Upstream refuses
/// such objects because their usage could not be computed reliably.
pub fn missing(quota: &Value, plural: &str, obj: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if plural == "persistentvolumeclaims" {
        if tracked(quota, "requests.storage") && obj.pointer(&["spec", "resources", "requests", "storage"]).is_none_or(|v| qty(Some(v)).is_none()) {
            out.push(String::from("requests.storage"));
        }
        return out;
    }
    if plural != "pods" || terminal(obj) {
        return out;
    }
    let spec = obj.get("spec").unwrap_or(&Value::Null);
    for (name, kind, res) in [("cpu", "requests", "cpu"), ("limits.cpu", "limits", "cpu"), ("limits.memory", "limits", "memory"), ("memory", "requests", "memory"), ("requests.cpu", "requests", "cpu"), ("requests.memory", "requests", "memory")] {
        if tracked(quota, name) && list(spec, "containers").iter().chain(list(spec, "initContainers")).any(|c| c.pointer(&["resources", kind, res]).is_none()) {
            out.push(name.to_string());
        }
    }
    out.sort();
    out
}

/// Which store resource holds a quota resource name (`None` when the name carries usage that no
/// object list can supply). Compute names come from pods, service names from services, storage
/// from PVCs; the rest are the plain object counts (`secrets`, `count/replicasets.apps`, ...).
pub fn source_of(name: &str) -> Option<&'static crate::resources::Resource> {
    use crate::resources;
    if let Some(rest) = name.strip_prefix("count/") {
        return match rest.split_once('.') {
            Some((plural, group)) => resources::find(group, "v1", plural),
            None => resources::find("", "v1", rest),
        };
    }
    let (plural, group) = match name {
        "pods" | "cpu" | "memory" | "ephemeral-storage" | "requests.cpu" | "requests.memory" | "requests.ephemeral-storage" | "limits.cpu" | "limits.memory" | "limits.ephemeral-storage" => ("pods", ""),
        "services" | "services.nodeports" | "services.loadbalancers" => ("services", ""),
        "persistentvolumeclaims" | "requests.storage" => ("persistentvolumeclaims", ""),
        "replicationcontrollers" | "resourcequotas" | "secrets" | "configmaps" => (name, ""),
        _ => return None,
    };
    resources::find(group, "v1", plural)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Value {
        kr_fmt::json::parse_str(s).unwrap()
    }
    fn get(u: &[(String, Quantity)], n: &str) -> String {
        u.iter().find(|(k, _)| k == n).map(|(_, q)| q.to_canonical_string()).unwrap_or_else(|| "none".to_string())
    }

    #[test]
    fn pod_usage_with_init_containers() {
        let p = v(r#"{"spec":{"containers":[{"resources":{"requests":{"cpu":"100m","memory":"64Mi"},"limits":{"cpu":"200m"}}},{"resources":{"requests":{"cpu":"150m"}}}],
            "initContainers":[{"resources":{"requests":{"cpu":"500m","memory":"32Mi"}}}],"overhead":{"cpu":"10m"}}}"#);
        let u = usage("pods", "", &p);
        assert_eq!(get(&u, "pods"), "1");
        assert_eq!(get(&u, "count/pods"), "1");
        assert_eq!(get(&u, "requests.cpu"), "510m");
        assert_eq!(get(&u, "cpu"), "510m");
        assert_eq!(get(&u, "requests.memory"), "64Mi");
        assert_eq!(get(&u, "limits.cpu"), "210m");
        assert_eq!(get(&u, "limits.memory"), "0");
        let done = v(r#"{"status":{"phase":"Succeeded"},"spec":{}}"#);
        assert!(usage("pods", "", &done).is_empty());
    }

    #[test]
    fn count_names() {
        let o = v("{}");
        assert_eq!(get(&usage("secrets", "", &o), "count/secrets"), "1");
        assert_eq!(get(&usage("secrets", "", &o), "secrets"), "1");
        let u = usage("replicasets", "apps", &o);
        assert_eq!(u.len(), 1);
        assert_eq!(get(&u, "count/replicasets.apps"), "1");
        let s = v(r#"{"spec":{"type":"NodePort","ports":[{"nodePort":30000},{"nodePort":30001}]}}"#);
        assert_eq!(get(&usage("services", "", &s), "services.nodeports"), "2");
        assert_eq!(get(&usage("services", "", &s), "services.loadbalancers"), "0");
        // ExternalName services use no IP/ports: not counted at all.
        let ex = v(r#"{"spec":{"type":"ExternalName","externalName":"x.example"}}"#);
        assert!(usage("services", "", &ex).is_empty());
        let c = v(r#"{"spec":{"resources":{"requests":{"storage":"1Gi"}}}}"#);
        assert_eq!(get(&usage("persistentvolumeclaims", "", &c), "requests.storage"), "1Gi");
        // Numeric quantities (an unquoted YAML scalar) are exact, but stay decimal.
        let n = v(r#"{"spec":{"resources":{"requests":{"storage":1073741824}}}}"#);
        assert_eq!(get(&usage("persistentvolumeclaims", "", &n), "requests.storage"), "1073741824");
    }

    #[test]
    fn deltas_and_messages() {
        let load = v(r#"{"spec":{"type":"LoadBalancer","ports":[{"nodePort":30080}]}}"#);
        let cluster = v(r#"{"spec":{"type":"ClusterIP"}}"#);
        let d = delta("services", "", &load, &cluster);
        assert_eq!(get(&d, "services"), "0");
        assert_eq!(get(&d, "services.nodeports"), "1");
        assert_eq!(get(&d, "services.loadbalancers"), "1");
        assert_eq!(get(&delta("services", "", &cluster, &load), "services.nodeports"), "-1");
        // Messages, upstream wording: sorted pairs and sorted missing names.
        let q = v(r#"{"metadata":{"name":"compute"},"spec":{"hard":{"requests.cpu":"1","pods":"2"}}}"#);
        let req = alloc::vec![("pods".to_string(), count(1)), ("requests.cpu".to_string(), Quantity::from_milli(100))];
        let used = alloc::vec![("pods".to_string(), count(2)), ("requests.cpu".to_string(), Quantity::from_milli(900))];
        let lim = hard(&q);
        assert_eq!(exceeded_msg(&q, &req, &used, &lim), "exceeded quota: compute, requested: pods=1, requests.cpu=100m, used: pods=2, requests.cpu=900m, limited: pods=2, requests.cpu=1");
        assert_eq!(must_specify_msg(&q, &["requests.cpu".to_string()]), "failed quota: compute: must specify requests.cpu");
    }

    #[test]
    fn hard_and_validate() {
        // Numbers (YAML plain scalars merge to JSON numbers) parse, too.
        let q = v(r#"{"spec":{"hard":{"pods":2,"cpu":"500m","bad":"x"},"scopes":["BestEffort","Terminating"]}}"#);
        let h = hard(&q);
        assert_eq!(format!("{:?}", h.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>()), "[\"cpu\", \"pods\"]");
        let bad = q.get("spec").unwrap().get("hard").unwrap().get("bad").unwrap().clone();
        assert_eq!(validate(&q).unwrap_err(), alloc::format!("spec.hard[bad]: Invalid value: {bad}: quantity must match the regular expression ^([+-]?[0-9.]+)([eEinumkKMGTP]*[-+]?[0-9]*)$"));
        assert!(validate(&v(r#"{"spec":{"scopes":["BestEffort"]}}"#)).is_ok());
        assert!(validate(&v(r#"{"spec":{"scopes":["BestEffort","BestEffort"]}}"#)).unwrap_err().contains("duplicate scope"));
        assert!(validate(&v(r#"{"spec":{"scopes":["BestEffortx"]}}"#)).unwrap_err().contains("Unsupported value: \"BestEffortx\""));
        assert!(validate(&v(r#"{"spec":{"scopeSelector":{"matchExpressions":[{"scopeName":"Terminating","operator":"In"}]}}}"#)).unwrap_err().contains("may only use"));
        assert!(validate(&v(r#"{"spec":{"scopeSelector":{"matchExpressions":[{"scopeName":"PriorityClass","operator":"Gt"}]}}}"#)).unwrap_err().contains("Unsupported value"));
    }

    #[test]
    fn scopes() {
        let be = v(r#"{"spec":{"containers":[{}]}}"#);
        let nbe = v(r#"{"spec":{"containers":[{"resources":{"limits":{"cpu":"1"}}}],"activeDeadlineSeconds":5,"priorityClassName":"high"}}"#);
        let q = |s: &str| v(&format!(r#"{{"spec":{{{s}}}}}"#));
        assert!(matches_scopes(&q(r#""scopes":["BestEffort","NotTerminating"]"#), "pods", &be));
        assert!(!matches_scopes(&q(r#""scopes":["BestEffort"]"#), "pods", &nbe));
        assert!(matches_scopes(&q(r#""scopes":["NotBestEffort","Terminating"]"#), "pods", &nbe));
        assert!(!matches_scopes(&q(r#""scopes":["BestEffort"]"#), "configmaps", &be));
        assert!(matches_scopes(&q("\"hard\":{}"), "configmaps", &be));
        let sel = |op: &str, vals: &str| q(&format!(r#""scopeSelector":{{"matchExpressions":[{{"scopeName":"PriorityClass","operator":"{op}","values":[{vals}]}}]}}"#));
        assert!(matches_scopes(&sel("In", r#""high""#), "pods", &nbe));
        assert!(!matches_scopes(&sel("In", r#""high""#), "pods", &be));
        assert!(matches_scopes(&sel("NotIn", r#""high""#), "pods", &be));
        assert!(matches_scopes(&sel("Exists", ""), "pods", &nbe));
        assert!(matches_scopes(&sel("DoesNotExist", ""), "pods", &be));
    }

    #[test]
    fn must_specify() {
        let q = v(r#"{"spec":{"hard":{"requests.cpu":"1","limits.memory":"1Gi","pods":"2","requests.storage":"10Gi"}}}"#);
        let p = v(r#"{"spec":{"containers":[{"resources":{"limits":{"cpu":"1"}}}]}}"#);
        assert_eq!(missing(&q, "pods", &p), ["limits.memory", "requests.cpu"]);
        assert!(tracked(&q, "pods") && !tracked(&q, "cpu"));
        let pvc = v(r#"{}"#);
        assert_eq!(missing(&q, "persistentvolumeclaims", &pvc), ["requests.storage"]);
        let q2 = v(r#"{"spec":{"hard":{"services":"1"}}}"#);
        assert!(missing(&q2, "persistentvolumeclaims", &pvc).is_empty());
    }

    #[test]
    fn sources() {
        for (name, plural, group) in [("cpu", "pods", ""), ("limits.memory", "pods", ""), ("services.nodeports", "services", ""), ("requests.storage", "persistentvolumeclaims", ""), ("count/pods", "pods", ""), ("count/replicasets.apps", "replicasets", "apps"), ("count/endpoints", "endpoints", ""), ("configmaps", "configmaps", "")] {
            assert!(source_of(name).is_some_and(|r| r.plural == plural && r.group == group), "{name}");
        }
        assert!(source_of("unknown").is_none());
    }
}
