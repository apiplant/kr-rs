//! CustomResourceDefinitions: validation and status of the CRD itself, the dynamic resources
//! it registers, and the structural-schema subset applied to custom objects (defaulting,
//! pruning, validation).

use crate::object::{is_dns_label, is_dns_subdomain, rfc3339, ApiError};
use crate::resources::Resource;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use crate::cel::Program;
use crate::regex::Regex;
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
    /// The CRD converts between versions with a webhook: its `clientConfig`. `None`: only
    /// apiVersion changes.
    pub webhook: Option<Value>,
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
        if let Some(sc) = v.pointer(&["schema", "openAPIV3Schema"]) {
            check_schema(sc, &alloc::format!("spec.versions[{i}].schema.openAPIV3Schema"), Pos::Root, &mut errs);
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
    let mut conds = alloc::vec![
        cond("NamesAccepted", "NoConflicts", "no conflicts found"),
        cond("Established", "InitialNamesAccepted", "the initial names have been accepted"),
    ];
    if o.pointer(&["metadata", "deletionTimestamp"]).is_some() {
        conds.push(terminating(old, now));
    }
    // Conditions other than the server-managed ones are kept as written (status updates).
    let written = o.pointer(&["status", "conditions"]).and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
    conds.extend(written.into_iter().filter(|c| !matches!(str_at(c, &["type"]), "NamesAccepted" | "Established" | "Terminating")));
    if old.is_none() {
        // Upstream adds the cleanup finalizer at creation; the controller removes it once the
        // custom resources are gone.
        let m = o.entry_object("metadata");
        let mut fin: Vec<Value> = m.get("finalizers").and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
        if !fin.iter().any(|f| f.as_str() == Some(FINALIZER)) {
            fin.push(Value::from(FINALIZER));
            m.set("finalizers", Value::Array(fin));
        }
    }
    let st = o.entry_object("status");
    st.set("acceptedNames", names);
    st.set("storedVersions", Value::Array(stored.iter().map(|s| Value::from(s.as_str())).collect()));
    st.set("conditions", Value::Array(conds));
    Ok(())
}

/// The finalizer that keeps a CRD until its custom resources are deleted.
pub const FINALIZER: &str = "customresourcecleanup.apiextensions.k8s.io";

/// The `Terminating` condition of a CRD whose deletion is in progress (keeps an earlier transition time).
pub fn terminating(old: Option<&Value>, now: i64) -> Value {
    let prev = old.and_then(|o| o.pointer(&["status", "conditions"])).and_then(Value::as_array).and_then(|c| c.iter().find(|c| str_at(c, &["type"]) == "Terminating"));
    let at = prev.map(|c| str_at(c, &["lastTransitionTime"]).to_string()).unwrap_or_else(|| rfc3339(now));
    crate::object::obj(alloc::vec![
        ("type", Value::from("Terminating")),
        ("status", Value::from("True")),
        ("lastTransitionTime", Value::String(at)),
        ("reason", Value::from("InstanceDeletionInProgress")),
        ("message", Value::from("CustomResource deletion is in progress")),
    ])
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
    let webhook = (str_at(crd, &["spec", "conversion", "strategy"]) == "Webhook").then(|| crd.pointer(&["spec", "conversion", "webhook", "clientConfig"]).cloned().unwrap_or(Value::Null));
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
        out.push(Custom { res, crd: str_at(crd, &["metadata", "name"]).to_string(), schema: v.pointer(&["schema", "openAPIV3Schema"]).cloned(), scale, webhook: webhook.clone() });
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

fn tname(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn is_date(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' || ![0, 1, 2, 3, 5, 6, 8, 9].iter().all(|i| b[*i].is_ascii_digit()) {
        return false;
    }
    let (y, m, d): (u32, u32, u32) = (s[0..4].parse().unwrap_or(0), s[5..7].parse().unwrap_or(0), s[8..10].parse().unwrap_or(0));
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&d)
}

fn is_date_time(s: &str) -> bool {
    let Some((d, t)) = s.split_once(['T', 't']) else { return false };
    if !is_date(d) {
        return false;
    }
    let (clock, zone) = match t.find(['Z', 'z', '+', '-']) {
        Some(i) => t.split_at(i),
        None => return false,
    };
    let clock = clock.split_once('.').map_or(clock, |(c, frac)| if !frac.is_empty() && frac.bytes().all(|b| b.is_ascii_digit()) { c } else { "x" });
    let parts: Vec<&str> = clock.split(':').collect();
    let num = |p: &str, max: u32| p.len() == 2 && p.parse::<u32>().is_ok_and(|n| n <= max);
    if parts.len() != 3 || !num(parts[0], 23) || !num(parts[1], 59) || !num(parts[2], 60) {
        return false;
    }
    if zone.eq_ignore_ascii_case("z") {
        return true;
    }
    match zone[1..].split_once(':') {
        Some((h, m)) => num(h, 23) && num(m, 59),
        None => false,
    }
}

fn is_base64(s: &str) -> bool {
    let t = s.trim_end_matches('=');
    s.len() % 4 == 0 && s.len() - t.len() <= 2 && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

fn is_uuid(s: &str) -> bool {
    let p: Vec<&str> = s.split('-').collect();
    p.len() == 5 && p.iter().zip([8, 4, 4, 4, 12]).all(|(x, n)| x.len() == n && x.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn is_hostname(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    !s.is_empty() && s.len() <= 253 && s.split('.').all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}

fn is_uri(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once(':') else { return false };
    scheme.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && scheme.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
        && !rest.is_empty()
        && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Loose `format` check for strings; unknown formats are accepted.
fn string_format_ok(f: &str, s: &str) -> bool {
    match f {
        "date" => is_date(s),
        "date-time" => is_date_time(s),
        "byte" => is_base64(s),
        "uuid" => is_uuid(s),
        "ipv4" => s.parse::<core::net::Ipv4Addr>().is_ok(),
        "ipv6" => s.parse::<core::net::Ipv6Addr>().is_ok(),
        "hostname" => is_hostname(s),
        "uri" => is_uri(s),
        _ => true,
    }
}

fn validation_rules(s: &Value, v: &Value, old: Option<&Value>, at: &str, errs: &mut Vec<String>) {
    let Some(rules) = s.get("x-kubernetes-validations").and_then(Value::as_array) else { return };
    let null = Value::Null;
    for r in rules {
        let rule = str_at(r, &["rule"]);
        let Ok(p) = Program::compile(rule, &["self", "oldSelf"]) else { continue };
        // Transition rules only run when there is an old value at this node.
        if p.uses("oldSelf") && old.is_none() {
            continue;
        }
        let vars = [("self", v), ("oldSelf", old.unwrap_or(&null))];
        match p.eval_bool(&vars) {
            Ok(true) => {}
            Ok(false) => {
                let mut msg = str_at(r, &["message"]).to_string();
                let me = str_at(r, &["messageExpression"]);
                if !me.is_empty() {
                    if let Some(Value::String(m)) = Program::compile(me, &["self", "oldSelf"]).ok().and_then(|p| p.eval(&vars).ok()) {
                        msg = m;
                    }
                }
                if msg.is_empty() {
                    msg = alloc::format!("failed rule: {rule}");
                }
                errs.push(alloc::format!("{at}: Invalid value: {:?}: {msg}", tname(v)));
            }
            Err(e) => errs.push(alloc::format!("{at}: Invalid value: {:?}: rule evaluation error: {e}", tname(v))),
        }
    }
}

fn is_multiple(n: &Number, m: f64) -> bool {
    if m == 0.0 {
        return true;
    }
    let q = n.as_f64() / m;
    if n.is_integer() && m == (m as i64) as f64 {
        return n.as_i64().is_none_or(|i| i % (m as i64) == 0);
    }
    let r = (q + if q < 0.0 { -0.5 } else { 0.5 }) as i64 as f64;
    let d = q - r;
    d < 1e-9 && d > -1e-9
}

/// Validates `v` against the OpenAPI v3 subset kr enforces: type, nullable, int-or-string,
/// enum, required, properties, additionalProperties, items, numeric/string/array/object bounds,
/// pattern, format, uniqueItems, list-type set/map, allOf/anyOf/oneOf/not and CEL
/// `x-kubernetes-validations`. `old` is the stored value at the same node (for `oldSelf`).
pub fn validate(s: &Value, v: &Value, old: Option<&Value>, path: &str, errs: &mut Vec<String>) {
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
            if let Some(n) = s.get("minProperties").and_then(Value::as_u64).filter(|n| (fields.len() as u64) < *n) {
                errs.push(alloc::format!("{at}: Invalid value: should have at least {n} properties"));
            }
            if let Some(n) = s.get("maxProperties").and_then(Value::as_u64).filter(|n| (fields.len() as u64) > *n) {
                errs.push(alloc::format!("{at}: Invalid value: should have at most {n} properties"));
            }
            let props = s.get("properties").and_then(Value::as_object);
            for (k, fv) in fields {
                let o = old.and_then(|o| o.get(k));
                match props.and_then(|p| p.iter().find(|(n, _)| n == k)) {
                    Some((_, ps)) => validate(ps, fv, o, &join(path, k), errs),
                    None => {
                        if let Some(a @ Value::Object(_)) = s.get("additionalProperties") {
                            validate(a, fv, o, &join(path, k), errs)
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
            let list_type = str_at(s, &["x-kubernetes-list-type"]);
            let keys = strs(s.get("x-kubernetes-list-map-keys"));
            if is_true(s.get("uniqueItems")) || list_type == "set" {
                for (i, it) in items.iter().enumerate() {
                    if items[..i].iter().any(|p| p == it) {
                        errs.push(alloc::format!("{path}[{i}]: Duplicate value: {}", json::to_string(it)));
                    }
                }
            }
            if list_type == "map" {
                let key = |it: &Value| -> Vec<Value> { keys.iter().map(|k| it.get(k).cloned().unwrap_or(Value::Null)).collect() };
                for (i, it) in items.iter().enumerate() {
                    if items[..i].iter().any(|p| key(p) == key(it)) {
                        let k: Vec<String> = keys.iter().zip(key(it)).map(|(n, x)| alloc::format!("\"{n}\":{}", json::to_string(&x))).collect();
                        errs.push(alloc::format!("{path}[{i}]: Duplicate value: map[{}]", k.join(",")));
                    }
                }
            }
            if let Some(is) = s.get("items") {
                for (i, it) in items.iter().enumerate() {
                    let o = match (list_type, old.and_then(Value::as_array)) {
                        ("map", Some(prev)) => {
                            let key = |x: &Value| -> Vec<Value> { keys.iter().map(|k| x.get(k).cloned().unwrap_or(Value::Null)).collect() };
                            prev.iter().find(|p| key(p) == key(it))
                        }
                        ("set", Some(prev)) => prev.iter().find(|p| *p == it),
                        _ => None,
                    };
                    validate(is, it, o, &alloc::format!("{path}[{i}]"), errs);
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
            if let Some(p) = s.get("pattern").and_then(Value::as_str) {
                match Regex::new(p).and_then(|r| r.is_match(x)) {
                    Ok(true) => {}
                    Ok(false) => errs.push(alloc::format!("{at}: Invalid value: {x:?}: {at} in body should match '{p}'")),
                    Err(e) => errs.push(alloc::format!("{at}: Invalid value: {x:?}: pattern '{p}' could not be evaluated: {e}")),
                }
            }
            if let Some(f) = s.get("format").and_then(Value::as_str).filter(|f| !string_format_ok(f, x)) {
                errs.push(alloc::format!("{at}: Invalid value: {x:?}: {at} in body must be of type {f}: {x:?}"));
            }
        }
        Value::Number(n) => {
            let excl = |f: &str| is_true(s.get(f));
            if let Some(m) = s.get("minimum").and_then(Value::as_f64) {
                let x = n.as_f64();
                if excl("exclusiveMinimum") && x <= m {
                    errs.push(alloc::format!("{at}: Invalid value: should be greater than {m}"));
                } else if x < m {
                    errs.push(alloc::format!("{at}: Invalid value: should be greater than or equal to {m}"));
                }
            }
            if let Some(m) = s.get("maximum").and_then(Value::as_f64) {
                let x = n.as_f64();
                if excl("exclusiveMaximum") && x >= m {
                    errs.push(alloc::format!("{at}: Invalid value: should be less than {m}"));
                } else if x > m {
                    errs.push(alloc::format!("{at}: Invalid value: should be less than or equal to {m}"));
                }
            }
            if let Some(m) = s.get("multipleOf").and_then(Value::as_f64).filter(|m| !is_multiple(n, *m)) {
                errs.push(alloc::format!("{at}: Invalid value: should be a multiple of {m}"));
            }
            let range = match str_at(s, &["format"]) {
                "int32" => Some((i32::MIN as f64, i32::MAX as f64)),
                "int64" => Some((i64::MIN as f64, i64::MAX as f64)),
                _ => None,
            };
            if range.filter(|(lo, hi)| !n.is_integer() || n.as_f64() < *lo || n.as_f64() > *hi).is_some() {
                errs.push(alloc::format!("{at}: Invalid value: {}: {at} in body must be of type {}", json::to_string(v), str_at(s, &["format"])));
            }
        }
        _ => {}
    }
    for sub in s.get("allOf").and_then(Value::as_array).unwrap_or(&[]) {
        validate(sub, v, old, path, errs);
    }
    let passes = |sub: &Value| {
        let mut e = Vec::new();
        validate(sub, v, old, path, &mut e);
        e.is_empty()
    };
    if let Some(subs) = s.get("anyOf").and_then(Value::as_array) {
        if !subs.iter().any(passes) {
            errs.push(alloc::format!("{at}: Invalid value: {:?}: must validate at least one schema (anyOf)", tname(v)));
        }
    }
    if let Some(subs) = s.get("oneOf").and_then(Value::as_array) {
        match subs.iter().filter(|x| passes(x)).count() {
            1 => {}
            0 => errs.push(alloc::format!("{at}: Invalid value: {:?}: must validate one and only one schema (oneOf). None validated", tname(v))),
            n => errs.push(alloc::format!("{at}: Invalid value: {:?}: must validate one and only one schema (oneOf). {n} validated", tname(v))),
        }
    }
    if let Some(sub) = s.get("not").filter(|n| matches!(n, Value::Object(_))) {
        if passes(sub) {
            errs.push(alloc::format!("{at}: Invalid value: {:?}: must not validate the schema (not)", tname(v)));
        }
    }
    validation_rules(s, v, old, at, errs);
}

// ---- structural schema check of the CRD itself ----

const UNSUPPORTED: [&str; 5] = ["$ref", "definitions", "dependencies", "additionalItems", "patternProperties"];

/// Where a schema node sits, for the "type" requirement message.
#[derive(Clone, Copy, PartialEq)]
enum Pos {
    Root,
    Props,
    Items,
    Addl,
    /// Inside allOf/anyOf/oneOf/not: value validation only.
    Logic,
}

/// Upstream-like structural schema rules plus compile checks of `pattern` and CEL rules.
fn check_schema(s: &Value, path: &str, pos: Pos, errs: &mut Vec<String>) {
    let Value::Object(_) = s else { return };
    let ios = is_true(s.get("x-kubernetes-int-or-string"));
    let preserve = is_true(s.get("x-kubernetes-preserve-unknown-fields"));
    let ty = s.get("type").and_then(Value::as_str).unwrap_or("");
    if pos == Pos::Logic {
        for k in ["type", "default", "additionalProperties", "nullable"] {
            if s.get(k).is_some() {
                errs.push(alloc::format!("{path}.{k}: Forbidden: must be empty to be structural"));
            }
        }
    } else if ty.is_empty() && !ios && !preserve {
        errs.push(match pos {
            Pos::Root => alloc::format!("{path}.type: Required value: must not be empty at the root"),
            Pos::Props => alloc::format!("{path}.type: Required value: must not be empty for specified object fields"),
            Pos::Items => alloc::format!("{path}.type: Required value: must not be empty for specified array items"),
            _ => alloc::format!("{path}.type: Required value: must not be empty for specified additionalProperties"),
        });
    } else if pos == Pos::Root && !ty.is_empty() && ty != "object" {
        errs.push(alloc::format!("{path}.type: Invalid value: {ty:?}: must be object at the root"));
    }
    if ios && !ty.is_empty() {
        errs.push(alloc::format!("{path}.type: Forbidden: must be empty to be structural when x-kubernetes-int-or-string is true"));
    }
    if !ty.is_empty() && !matches!(ty, "object" | "array" | "string" | "integer" | "number" | "boolean") {
        errs.push(alloc::format!("{path}.type: Unsupported value: {ty:?}: supported values: \"array\", \"boolean\", \"integer\", \"number\", \"object\", \"string\""));
    }
    if s.get("properties").is_some() && s.get("additionalProperties").is_some() {
        errs.push(alloc::format!("{path}.additionalProperties: Forbidden: additionalProperties and properties are mutual exclusive"));
    }
    for k in UNSUPPORTED {
        if s.get(k).is_some() {
            errs.push(alloc::format!("{path}.{k}: Forbidden: {k} is not supported"));
        }
    }
    if ty == "array" && s.get("items").is_none() {
        errs.push(alloc::format!("{path}.items: Required value: must be specified"));
    }
    if let Some(p) = s.get("pattern").and_then(Value::as_str) {
        if let Err(e) = Regex::new(p) {
            errs.push(alloc::format!("{path}.pattern: Invalid value: {p:?}: {e}"));
        }
    }
    if let Some(rules) = s.get("x-kubernetes-validations").and_then(Value::as_array) {
        for (i, r) in rules.iter().enumerate() {
            let rule = str_at(r, &["rule"]);
            let rp = alloc::format!("{path}.x-kubernetes-validations[{i}]");
            if rule.is_empty() {
                errs.push(alloc::format!("{rp}.rule: Required value: rule is not specified"));
            } else if let Err(e) = Program::compile(rule, &["self", "oldSelf"]) {
                errs.push(alloc::format!("{rp}.rule: Invalid value: {rule:?}: compilation failed: {e}"));
            }
            let me = str_at(r, &["messageExpression"]);
            if !me.is_empty() {
                if let Err(e) = Program::compile(me, &["self", "oldSelf"]) {
                    errs.push(alloc::format!("{rp}.messageExpression: Invalid value: {me:?}: compilation failed: {e}"));
                }
            }
        }
    }
    let inner = if pos == Pos::Logic { Pos::Logic } else { Pos::Props };
    if let Some(p) = s.get("properties").and_then(Value::as_object) {
        for (k, ps) in p {
            check_schema(ps, &alloc::format!("{path}.properties[{k}]"), inner, errs);
        }
    }
    match s.get("additionalProperties") {
        Some(a @ Value::Object(_)) => check_schema(a, &alloc::format!("{path}.additionalProperties"), if pos == Pos::Logic { Pos::Logic } else { Pos::Addl }, errs),
        _ => {}
    }
    match s.get("items") {
        Some(i @ Value::Object(_)) => check_schema(i, &alloc::format!("{path}.items"), if pos == Pos::Logic { Pos::Logic } else { Pos::Items }, errs),
        Some(Value::Array(_)) => errs.push(alloc::format!("{path}.items: Invalid value: must be a schema, not an array")),
        _ => {}
    }
    for k in ["allOf", "anyOf", "oneOf"] {
        // The canonical int-or-string form lists the two types in anyOf/oneOf.
        if ios && k != "allOf" {
            continue;
        }
        for (i, sub) in s.get(k).and_then(Value::as_array).unwrap_or(&[]).iter().enumerate() {
            check_schema(sub, &alloc::format!("{path}.{k}[{i}]"), Pos::Logic, errs);
        }
    }
    if let Some(n) = s.get("not") {
        check_schema(n, &alloc::format!("{path}.not"), Pos::Logic, errs);
    }
}
