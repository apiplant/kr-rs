//! CustomResourceDefinitions: validation and status of the CRD itself, the dynamic resources
//! it registers, and the structural-schema subset applied to custom objects (defaulting,
//! pruning, validation).

use crate::object::{is_dns_label, is_dns_subdomain, rfc3339, ApiError};
use crate::resources::Resource;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_fmt::json::{self, Number, Value};

pub const GROUP: &str = "apiextensions.k8s.io";

pub fn is_crd(r: &Resource) -> bool {
    r.group == GROUP && r.plural == "customresourcedefinitions"
}

/// One served version of a CRD.
pub struct Custom {
    pub res: &'static Resource,
    pub crd: String,
    pub schema: Option<Value>,
    /// (specReplicasPath, statusReplicasPath, labelSelectorPath) when `scale` is enabled.
    pub scale: Option<[String; 3]>,
    /// The CRD converts between versions with a webhook (unsupported).
    pub webhook: bool,
}

impl Custom {
    pub fn status(&self) -> bool {
        self.res.subresources.contains(&"status")
    }
}

fn leak(s: &str) -> &'static str {
    Box::leak(s.to_string().into_boxed_str())
}

fn strs(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

fn str_at<'a>(v: &'a Value, p: &[&str]) -> &'a str {
    v.pointer(p).and_then(Value::as_str).unwrap_or("")
}

fn leak_all(v: &[String]) -> &'static [&'static str] {
    Box::leak(v.iter().map(|s| leak(s)).collect::<Vec<_>>().into_boxed_slice())
}

fn is_true(v: Option<&Value>) -> bool {
    v.and_then(Value::as_bool) == Some(true)
}

/// Validates and completes a CRD (names defaults, status). `old` is the stored CRD on update.
pub fn admit(o: &mut Value, old: Option<&Value>, now: i64) -> Result<(), ApiError> {
    let mut errs: Vec<String> = Vec::new();
    let name = str_at(o, &["metadata", "name"]).to_string();
    let group = str_at(o, &["spec", "group"]).to_string();
    let kind = str_at(o, &["spec", "names", "kind"]).to_string();
    let plural = str_at(o, &["spec", "names", "plural"]).to_string();
    let mut singular = str_at(o, &["spec", "names", "singular"]).to_string();
    let mut list_kind = str_at(o, &["spec", "names", "listKind"]).to_string();
    if singular.is_empty() {
        singular = kind.to_lowercase();
    }
    if list_kind.is_empty() && !kind.is_empty() {
        list_kind = alloc::format!("{kind}List");
    }
    if group.is_empty() || !group.contains('.') || !is_dns_subdomain(&group) {
        errs.push("spec.group: Invalid value: must be a DNS subdomain with at least one dot".into());
    }
    for (f, v) in [("plural", &plural), ("singular", &singular)] {
        if !is_dns_label(v) {
            errs.push(alloc::format!("spec.names.{f}: Invalid value: {v:?}: must be a lowercase DNS label"));
        }
    }
    for (f, v) in [("kind", &kind), ("listKind", &list_kind)] {
        if !is_dns_label(&v.to_lowercase()) {
            errs.push(alloc::format!("spec.names.{f}: Invalid value: {v:?}: must be a valid DNS label when lowercased"));
        }
    }
    if kind == list_kind {
        errs.push("spec.names.listKind: Invalid value: kind and listKind may not be the same".into());
    }
    if name != alloc::format!("{plural}.{group}") {
        errs.push(alloc::format!("metadata.name: Invalid value: {name:?}: must be spec.names.plural+\".\"+spec.group"));
    }
    let scope = str_at(o, &["spec", "scope"]);
    if !matches!(scope, "Namespaced" | "Cluster") {
        errs.push(alloc::format!("spec.scope: Unsupported value: {scope:?}: supported values: \"Cluster\", \"Namespaced\""));
    }
    if crate::resources::RESOURCES.iter().any(|r| r.group == group && r.plural == plural) {
        errs.push(alloc::format!("spec.names.plural: Invalid value: {plural:?}: conflicts with a built-in resource"));
    }
    let versions = o.pointer(&["spec", "versions"]).and_then(Value::as_array).unwrap_or(&[]);
    if versions.is_empty() {
        errs.push("spec.versions: Required value: must have exactly one version marked as storage version".into());
    }
    let mut storage = String::new();
    let mut storage_count = 0;
    for (i, v) in versions.iter().enumerate() {
        let vn = str_at(v, &["name"]);
        if !is_dns_label(vn) {
            errs.push(alloc::format!("spec.versions[{i}].name: Invalid value: {vn:?}: must be a DNS label"));
        }
        if versions[..i].iter().any(|p| str_at(p, &["name"]) == vn) {
            errs.push(alloc::format!("spec.versions[{i}].name: Duplicate value: {vn:?}"));
        }
        if is_true(v.get("storage")) {
            storage_count += 1;
            storage = vn.to_string();
        }
    }
    if !versions.is_empty() && storage_count != 1 {
        errs.push("spec.versions: Invalid value: must have exactly one version marked as storage version".into());
    }
    if let Some(old) = old {
        for (f, p) in [("spec.group", &["spec", "group"][..]), ("spec.scope", &["spec", "scope"]), ("spec.names.plural", &["spec", "names", "plural"]), ("spec.names.kind", &["spec", "names", "kind"])] {
            if old.pointer(p) != o.pointer(p) {
                errs.push(alloc::format!("{f}: Invalid value: field is immutable"));
            }
        }
    }
    if !errs.is_empty() {
        return Err(ApiError::invalid(alloc::format!("CustomResourceDefinition.{GROUP} \"{name}\" is invalid: {}", errs.join(", "))));
    }
    let names = o.entry_object("spec").entry_object("names");
    names.set("singular", Value::from(singular.as_str()));
    names.set("listKind", Value::from(list_kind.as_str()));
    let names = names.clone();
    if o.pointer(&["spec", "conversion", "strategy"]).is_none() {
        o.entry_object("spec").entry_object("conversion").set("strategy", Value::from("None"));
    }
    let mut stored = strs(old.and_then(|o| o.pointer(&["status", "storedVersions"])));
    if !stored.contains(&storage) {
        stored.push(storage);
    }
    let cond = |ty: &str, reason: &str, message: &str| {
        let prev = old.and_then(|o| o.pointer(&["status", "conditions"])).and_then(Value::as_array).and_then(|c| c.iter().find(|c| str_at(c, &["type"]) == ty && str_at(c, &["status"]) == "True"));
        let at = prev.map(|c| str_at(c, &["lastTransitionTime"]).to_string()).unwrap_or_else(|| rfc3339(now));
        crate::object::obj(alloc::vec![
            ("type", Value::from(ty)),
            ("status", Value::from("True")),
            ("lastTransitionTime", Value::String(at)),
            ("reason", Value::from(reason)),
            ("message", Value::from(message)),
        ])
    };
    let st = o.entry_object("status");
    st.set("acceptedNames", names);
    st.set("storedVersions", Value::Array(stored.iter().map(|s| Value::from(s.as_str())).collect()));
    st.set(
        "conditions",
        Value::Array(alloc::vec![
            cond("NamesAccepted", "NoConflicts", "no conflicts found"),
            cond("Established", "InitialNamesAccepted", "the initial names have been accepted"),
        ]),
    );
    Ok(())
}

/// Version priority as in kube-aware ordering: GA over beta over alpha, higher numbers first.
pub fn version_rank(v: &str) -> (u8, u32, u32) {
    let Some(rest) = v.strip_prefix('v') else { return (0, 0, 0) };
    let d = rest.chars().take_while(char::is_ascii_digit).count();
    let Ok(major) = rest[..d].parse::<u32>() else { return (0, 0, 0) };
    let tail = &rest[d..];
    if tail.is_empty() {
        return (3, major, 0);
    }
    for (p, class) in [("beta", 2), ("alpha", 1)] {
        if let Some(n) = tail.strip_prefix(p).and_then(|n| n.parse::<u32>().ok()) {
            return (class, major, n);
        }
    }
    (0, 0, 0)
}

/// The served versions of a stored CRD as resources, in priority order. Resources identical to
/// one in `existing` are reused (registered resources are leaked, so updates must not churn).
pub fn build(crd: &Value, existing: &[Custom]) -> Vec<Custom> {
    let group = str_at(crd, &["spec", "group"]);
    let names = |f: &str| str_at(crd, &["spec", "names", f]);
    let namespaced = str_at(crd, &["spec", "scope"]) == "Namespaced";
    let short = strs(crd.pointer(&["spec", "names", "shortNames"]));
    let cats = strs(crd.pointer(&["spec", "names", "categories"]));
    let webhook = str_at(crd, &["spec", "conversion", "strategy"]) == "Webhook";
    let mut vs: Vec<&Value> = crd.pointer(&["spec", "versions"]).and_then(Value::as_array).unwrap_or(&[]).iter().filter(|v| is_true(v.get("served"))).collect();
    vs.sort_by(|a, b| version_rank(str_at(b, &["name"])).cmp(&version_rank(str_at(a, &["name"]))).then(str_at(a, &["name"]).cmp(str_at(b, &["name"]))));
    let mut out = Vec::new();
    for v in vs {
        let vn = str_at(v, &["name"]);
        let mut subs: Vec<&'static str> = Vec::new();
        if v.pointer(&["subresources", "status"]).is_some() {
            subs.push("status");
        }
        let scale = v.pointer(&["subresources", "scale"]).map(|s| {
            subs.push("scale");
            let p = |f: &str, d: &str| {
                let x = str_at(s, &[f]);
                if x.is_empty() { d.to_string() } else { x.to_string() }
            };
            [p("specReplicasPath", ".spec.replicas"), p("statusReplicasPath", ".status.replicas"), p("labelSelectorPath", "")]
        });
        let same = existing.iter().map(|c| c.res).find(|r| {
            r.group == group
                && r.version == vn
                && r.kind == names("kind")
                && r.plural == names("plural")
                && r.singular == names("singular")
                && r.namespaced == namespaced
                && r.short.iter().copied().eq(short.iter().map(String::as_str))
                && r.categories.iter().copied().eq(cats.iter().map(String::as_str))
                && r.subresources == subs.as_slice()
        });
        let res: &'static Resource = same.unwrap_or_else(|| {
            Box::leak(Box::new(Resource {
                group: leak(group),
                version: leak(vn),
                kind: leak(names("kind")),
                plural: leak(names("plural")),
                singular: leak(names("singular")),
                namespaced,
                short: leak_all(&short),
                subresources: Box::leak(subs.into_boxed_slice()),
                categories: leak_all(&cats),
            }))
        });
        out.push(Custom { res, crd: str_at(crd, &["metadata", "name"]).to_string(), schema: v.pointer(&["schema", "openAPIV3Schema"]).cloned(), scale, webhook });
    }
    out
}

/// Path like `.spec.replicas` as segments.
pub fn path_segs(p: &str) -> Vec<&str> {
    p.trim_start_matches('.').split('.').filter(|s| !s.is_empty()).collect()
}

// ---- structural schema subset ----

/// Applies defaults and drops fields the schema does not declare (unless
/// `x-kubernetes-preserve-unknown-fields`). The root keeps apiVersion, kind and metadata.
pub fn prune(s: &Value, v: &mut Value, root: bool) {
    match v {
        Value::Object(fields) => {
            let props = s.get("properties").and_then(Value::as_object);
            let addl = s.get("additionalProperties");
            let preserve = is_true(s.get("x-kubernetes-preserve-unknown-fields"));
            let known = |k: &str| props.is_some_and(|p| p.iter().any(|(n, _)| n == k));
            if let Some(p) = props {
                for (k, ps) in p {
                    if !root || k != "metadata" {
                        if let (Some(d), false) = (ps.get("default"), fields.iter().any(|(n, _)| n == k)) {
                            fields.push((k.clone(), d.clone()));
                        }
                    }
                }
            }
            if (props.is_some() || s.get("type").and_then(Value::as_str) == Some("object")) && !preserve && !matches!(addl, Some(Value::Bool(true)) | Some(Value::Object(_))) {
                fields.retain(|(k, _)| known(k) || (root && matches!(k.as_str(), "apiVersion" | "kind" | "metadata")));
            }
            for (k, fv) in fields.iter_mut() {
                if root && k == "metadata" {
                    continue;
                }
                match props.and_then(|p| p.iter().find(|(n, _)| n == k)) {
                    Some((_, ps)) => prune(ps, fv, false),
                    None => {
                        if let Some(a @ Value::Object(_)) = addl {
                            prune(a, fv, false)
                        }
                    }
                }
            }
        }
        Value::Array(items) => {
            if let Some(is) = s.get("items") {
                for it in items {
                    prune(is, it, false);
                }
            }
        }
        _ => {}
    }
}

fn join(path: &str, k: &str) -> String {
    if path.is_empty() { k.to_string() } else { alloc::format!("{path}.{k}") }
}

/// Validates `v` against the subset of OpenAPI v3 kr enforces: type, nullable, int-or-string,
/// required, properties, additionalProperties, items, enum, min/max, min/maxLength, min/maxItems.
pub fn validate(s: &Value, v: &Value, path: &str, errs: &mut Vec<String>) {
    let at = if path.is_empty() { "<root>" } else { path };
    if v.is_null() {
        if !is_true(s.get("nullable")) && s.get("type").is_some() {
            errs.push(alloc::format!("{at}: Invalid value: \"null\": {at} must be of type {}: \"null\"", str_at(s, &["type"])));
        }
        return;
    }
    if is_true(s.get("x-kubernetes-int-or-string")) {
        if !(v.as_str().is_some() || v.as_number().is_some_and(Number::is_integer)) {
            errs.push(alloc::format!("{at}: Invalid value: {at} must be an integer or a string"));
        }
    } else if let Some(t) = s.get("type").and_then(Value::as_str) {
        let ok = match t {
            "string" => v.as_str().is_some(),
            "integer" => v.as_number().is_some_and(Number::is_integer),
            "number" => v.as_number().is_some(),
            "boolean" => v.as_bool().is_some(),
            "object" => matches!(v, Value::Object(_)),
            "array" => matches!(v, Value::Array(_)),
            _ => true,
        };
        if !ok {
            errs.push(alloc::format!("{at}: Invalid value: {at} must be of type {t}"));
            return;
        }
    }
    if let Some(e) = s.get("enum").and_then(Value::as_array) {
        if !e.contains(v) {
            let allowed: Vec<String> = e.iter().map(json::to_string).collect();
            errs.push(alloc::format!("{at}: Unsupported value: {}: supported values: {}", json::to_string(v), allowed.join(", ")));
        }
    }
    match v {
        Value::Object(fields) => {
            for r in strs(s.get("required")) {
                if !fields.iter().any(|(k, _)| *k == r) {
                    errs.push(alloc::format!("{}: Required value", join(path, &r)));
                }
            }
            let props = s.get("properties").and_then(Value::as_object);
            for (k, fv) in fields {
                match props.and_then(|p| p.iter().find(|(n, _)| n == k)) {
                    Some((_, ps)) => validate(ps, fv, &join(path, k), errs),
                    None => {
                        if let Some(a @ Value::Object(_)) = s.get("additionalProperties") {
                            validate(a, fv, &join(path, k), errs)
                        }
                    }
                }
            }
        }
        Value::Array(items) => {
            if let Some(n) = s.get("minItems").and_then(Value::as_u64) {
                if (items.len() as u64) < n {
                    errs.push(alloc::format!("{at}: Invalid value: must have at least {n} items"));
                }
            }
            if let Some(n) = s.get("maxItems").and_then(Value::as_u64) {
                if (items.len() as u64) > n {
                    errs.push(alloc::format!("{at}: Too many: {}: must have at most {n} items", items.len()));
                }
            }
            if let Some(is) = s.get("items") {
                for (i, it) in items.iter().enumerate() {
                    validate(is, it, &alloc::format!("{path}[{i}]"), errs);
                }
            }
        }
        Value::String(x) => {
            let n = x.chars().count() as u64;
            if let Some(m) = s.get("minLength").and_then(Value::as_u64).filter(|m| n < *m) {
                errs.push(alloc::format!("{at}: Invalid value: should be at least {m} chars long"));
            }
            if let Some(m) = s.get("maxLength").and_then(Value::as_u64).filter(|m| n > *m) {
                errs.push(alloc::format!("{at}: Too long: may not be more than {m} bytes"));
            }
        }
        Value::Number(n) => {
            if let Some(m) = s.get("minimum").and_then(Value::as_f64).filter(|m| n.as_f64() < *m) {
                errs.push(alloc::format!("{at}: Invalid value: should be greater than or equal to {m}"));
            }
            if let Some(m) = s.get("maximum").and_then(Value::as_f64).filter(|m| n.as_f64() > *m) {
                errs.push(alloc::format!("{at}: Invalid value: should be less than or equal to {m}"));
            }
        }
        _ => {}
    }
}
