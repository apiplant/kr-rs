//! Object metadata rules shared by every resource: validation, server-set fields on create and
//! update, label selectors, and Kubernetes `Status` errors.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_fmt::json::{self, Number, Value};

/// An API error rendered as a `meta/v1 Status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub code: u16,
    pub reason: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn new(code: u16, reason: &'static str, message: impl Into<String>) -> Self {
        ApiError { code, reason, message: message.into() }
    }
    pub fn bad_request(m: impl Into<String>) -> Self {
        Self::new(400, "BadRequest", m)
    }
    pub fn invalid(m: impl Into<String>) -> Self {
        Self::new(422, "Invalid", m)
    }
    pub fn not_found(kind: &str, name: &str) -> Self {
        Self::new(404, "NotFound", alloc::format!("{kind} \"{name}\" not found"))
    }
    pub fn already_exists(kind: &str, name: &str) -> Self {
        Self::new(409, "AlreadyExists", alloc::format!("{kind} \"{name}\" already exists"))
    }
    pub fn conflict(kind: &str, name: &str) -> Self {
        Self::new(409, "Conflict", alloc::format!("Operation cannot be fulfilled on {kind} \"{name}\": the object has been modified; please apply your changes to the latest version and try again"))
    }
    pub fn to_status_json(&self) -> String {
        json::to_string(&status_value(self.code, self.reason, &self.message))
    }
}

pub fn status_value(code: u16, reason: &str, message: &str) -> Value {
    obj(alloc::vec![
        ("kind", Value::from("Status")),
        ("apiVersion", Value::from("v1")),
        ("metadata", Value::Object(Vec::new())),
        ("status", Value::from(if code < 400 { "Success" } else { "Failure" })),
        ("message", Value::from(message)),
        ("reason", Value::from(reason)),
        ("code", Value::Number(Number::from_u64(code as u64))),
    ])
}

pub fn obj(fields: Vec<(&str, Value)>) -> Value {
    Value::Object(fields.into_iter().map(|(k, v)| (k.into(), v)).collect())
}

// ---- name and label validation (k8s.io/apimachinery/pkg/util/validation) ----

fn is_alnum_lower(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit()
}

/// DNS-1123 label: 1..=63 chars of [a-z0-9-], alphanumeric at both ends.
pub fn is_dns_label(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= 63 && is_alnum_lower(b[0]) && is_alnum_lower(b[b.len() - 1]) && b.iter().all(|&c| is_alnum_lower(c) || c == b'-')
}

/// Path-segment name: non-empty, not "." or "..", no '/' or '%'.
pub fn is_path_segment(s: &str) -> bool {
    !s.is_empty() && s != "." && s != ".." && !s.contains(['/', '%']) && s.len() <= 253
}

/// DNS-1123 subdomain: dot-separated [a-z0-9-] parts, alphanumeric at both ends, at most
/// 253 chars. Unlike labels, parts have no 63-char limit (upstream's regex has none).
pub fn is_dns_subdomain(s: &str) -> bool {
    s.len() <= 253
        && s.split('.').all(|p| {
            let b = p.as_bytes();
            !b.is_empty() && is_alnum_lower(b[0]) && is_alnum_lower(b[b.len() - 1]) && b.iter().all(|&c| is_alnum_lower(c) || c == b'-')
        })
}

/// Label/annotation key: optional DNS-subdomain prefix, then a "qualified name" (<= 63 chars,
/// [A-Za-z0-9-_.], alphanumeric at both ends).
pub fn is_qualified_key(k: &str) -> bool {
    let (prefix, name) = match k.rsplit_once('/') {
        Some((p, n)) => (Some(p), n),
        None => (None, k),
    };
    let b = name.as_bytes();
    let name_ok = !b.is_empty()
        && b.len() <= 63
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
        && b.iter().all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'));
    name_ok && prefix.is_none_or(|p| !p.is_empty() && is_dns_subdomain(p))
}

/// Label value: empty, or <= 63 chars like a qualified name.
pub fn is_label_value(v: &str) -> bool {
    let b = v.as_bytes();
    b.is_empty()
        || (b.len() <= 63 && b[0].is_ascii_alphanumeric() && b[b.len() - 1].is_ascii_alphanumeric() && b.iter().all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.')))
}

const MAX_ANNOTATIONS: usize = 256 * 1024;

/// Validates metadata.labels and metadata.annotations.
pub fn validate_meta_maps(meta: &Value) -> Result<(), ApiError> {
    if let Some(l) = meta.get("labels") {
        let o = l.as_object().ok_or_else(|| ApiError::invalid("metadata.labels must be an object"))?;
        for (k, v) in o {
            let v = v.as_str().ok_or_else(|| ApiError::invalid(alloc::format!("label {k}: value must be a string")))?;
            if !is_qualified_key(k) || !is_label_value(v) {
                return Err(ApiError::invalid(alloc::format!("metadata.labels: invalid label {k}={v}")));
            }
        }
    }
    if let Some(a) = meta.get("annotations") {
        let o = a.as_object().ok_or_else(|| ApiError::invalid("metadata.annotations must be an object"))?;
        let mut total = 0;
        for (k, v) in o {
            let v = v.as_str().ok_or_else(|| ApiError::invalid(alloc::format!("annotation {k}: value must be a string")))?;
            if !is_qualified_key(k) {
                return Err(ApiError::invalid(alloc::format!("metadata.annotations: invalid key {k}")));
            }
            total += k.len() + v.len();
        }
        if total > MAX_ANNOTATIONS {
            return Err(ApiError::invalid("metadata.annotations: total size exceeds 256 KiB"));
        }
    }
    Ok(())
}

/// Strict dotted-quad IPv4 parser.
pub fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut parts = s.split('.');
    for o in out.iter_mut() {
        let p = parts.next()?;
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) || (p.len() > 1 && p.starts_with('0')) {
            return None;
        }
        *o = p.parse::<u16>().ok().filter(|v| *v <= 255)? as u8;
    }
    parts.next().is_none().then_some(out)
}

// ---- time ----

/// RFC 3339 UTC timestamp with second precision ("2026-10-23T16:00:00Z").
pub fn rfc3339(unix: i64) -> String {
    let days = unix.div_euclid(86400);
    let secs = unix.rem_euclid(86400);
    // Civil-from-days (H. Hinnant).
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (m <= 2) as i64;
    alloc::format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", secs / 3600, secs / 60 % 60, secs % 60)
}

// ---- server-set fields ----

/// Random UUID v4 from `rng`.
pub fn uuid4(rng: fn(&mut [u8])) -> String {
    let mut b = [0u8; 16];
    rng(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = |x: &[u8]| x.iter().map(|v| alloc::format!("{v:02x}")).collect::<String>();
    alloc::format!("{}-{}-{}-{}-{}", h(&b[..4]), h(&b[4..6]), h(&b[6..8]), h(&b[8..10]), h(&b[10..]))
}

/// The 5-character random suffix used by `generateName` (no vowels, like upstream).
pub fn name_suffix(rng: fn(&mut [u8])) -> String {
    const ALPHA: &[u8] = b"bcdfghjklmnpqrstvwxz2456789";
    let mut b = [0u8; 5];
    rng(&mut b);
    // 27 symbols; the modulo bias (256 % 27) is irrelevant for name uniqueness.
    b.iter().map(|x| ALPHA[*x as usize % ALPHA.len()] as char).collect()
}

/// What the request addressed (from the URL), checked against the body.
pub struct Target<'a> {
    pub api_version: &'a str,
    pub kind: &'a str,
    pub namespace: Option<&'a str>,
    pub name_is_label: bool,
}

pub struct Clock {
    pub now: i64,
    pub rng: fn(&mut [u8]),
}

fn meta_str<'a>(o: &'a Value, f: &str) -> Option<&'a str> {
    o.get("metadata")?.get(f)?.as_str()
}

fn check_type(o: &Value, t: &Target) -> Result<(), ApiError> {
    if !matches!(o, Value::Object(_)) {
        return Err(ApiError::bad_request("request body must be a JSON object"));
    }
    if o.has_duplicate_keys() {
        return Err(ApiError::bad_request("duplicate keys in request body"));
    }
    match (o.get("apiVersion").and_then(Value::as_str), o.get("kind").and_then(Value::as_str)) {
        (Some(v), Some(k)) if v == t.api_version && k == t.kind => Ok(()),
        (None, None) => Ok(()),
        (v, k) => Err(ApiError::bad_request(alloc::format!(
            "the body is {}/{} but the URL addresses {}/{}",
            v.unwrap_or("?"),
            k.unwrap_or("?"),
            t.api_version,
            t.kind
        ))),
    }
}

/// Normalises a new object: type fields, name (or generateName), namespace, uid,
/// creationTimestamp, generation, and resourceVersion = `rev` (the revision it will get).
pub fn prepare_create(o: &mut Value, t: &Target, clock: &Clock, rev: u64) -> Result<String, ApiError> {
    check_type(o, t)?;
    o.set("apiVersion", Value::from(t.api_version));
    o.set("kind", Value::from(t.kind));
    let meta = o.entry_object("metadata");
    let mut name = meta.get("name").and_then(Value::as_str).unwrap_or("").to_string();
    if name.is_empty() {
        if let Some(g) = meta.get("generateName").and_then(Value::as_str) {
            let base: String = g.chars().take(58).collect();
            name = alloc::format!("{base}{}", name_suffix(clock.rng));
            meta.set("name", Value::from(name.as_str()));
        }
    }
    // RBAC objects only need to be valid path segments (upstream allows "system:..." names).
    let path_segment = matches!(t.kind, "Role" | "ClusterRole" | "RoleBinding" | "ClusterRoleBinding");
    let ok = if path_segment {
        is_path_segment(&name)
    } else if t.name_is_label {
        is_dns_label(&name)
    } else {
        is_dns_subdomain(&name) && !name.is_empty()
    };
    if !ok {
        return Err(ApiError::invalid(alloc::format!("metadata.name: invalid value {name:?}: must be a {}", if path_segment { "valid path segment" } else if t.name_is_label { "lowercase RFC 1123 label" } else { "lowercase RFC 1123 subdomain" })));
    }
    match (t.namespace, meta.get("namespace").and_then(Value::as_str)) {
        (Some(url), Some(body)) if url != body => {
            return Err(ApiError::bad_request("the namespace of the provided object does not match the namespace sent on the request"));
        }
        (Some(url), _) => meta.set("namespace", Value::from(url)),
        (None, _) => {
            meta.remove("namespace");
        }
    }
    validate_meta_maps(meta)?;
    meta.set("uid", Value::String(uuid4(clock.rng)));
    meta.set("creationTimestamp", Value::String(rfc3339(clock.now)));
    meta.set("resourceVersion", Value::String(rev.to_string()));
    meta.remove("deletionTimestamp");
    meta.remove("deletionGracePeriodSeconds");
    meta.remove("managedFields");
    meta.remove("selfLink");
    if o.get("spec").is_some() {
        o.get_mut("metadata").unwrap().set("generation", Value::Number(Number::from_u64(1)));
    }
    Ok(name)
}

/// Carries server-owned fields from `old` into `new` for an update and validates it.
/// `status_only`: the status subresource (only .status may change); otherwise .status is kept
/// from `old` when `has_status` (the main resource ignores status changes).
pub fn prepare_update(old: &Value, new: &mut Value, t: &Target, rev: u64, has_status: bool, status_only: bool) -> Result<(), ApiError> {
    check_type(new, t)?;
    let name = meta_str(old, "name").unwrap_or("").to_string();
    if let Some(n) = meta_str(new, "name") {
        if n != name {
            return Err(ApiError::bad_request("metadata.name does not match the URL"));
        }
    }
    if let Some(want) = meta_str(new, "resourceVersion") {
        if !want.is_empty() && Some(want) != meta_str(old, "resourceVersion") {
            return Err(ApiError::conflict(t.kind, &name));
        }
    }
    if let Some(uid) = meta_str(new, "uid") {
        if Some(uid) != meta_str(old, "uid") {
            return Err(ApiError::new(409, "Conflict", "Precondition failed: UID in precondition does not match the object"));
        }
    }
    if status_only {
        // Everything but status comes from the stored object.
        let status = new.remove("status");
        *new = old.clone();
        match status {
            Some(s) => new.set("status", s),
            None => {
                new.remove("status");
            }
        }
    } else if has_status {
        match old.get("status") {
            Some(s) => new.set("status", s.clone()),
            None => {
                new.remove("status");
            }
        }
    }
    new.set("apiVersion", Value::from(t.api_version));
    new.set("kind", Value::from(t.kind));
    let generation = old.pointer(&["metadata", "generation"]).and_then(Value::as_u64);
    let spec_changed = old.get("spec") != new.get("spec");
    let om = old.get("metadata").cloned().unwrap_or(Value::Object(Vec::new()));
    let meta = new.entry_object("metadata");
    for f in ["name", "namespace", "uid", "creationTimestamp", "deletionTimestamp", "deletionGracePeriodSeconds"] {
        match om.get(f) {
            Some(v) => meta.set(f, v.clone()),
            None => {
                meta.remove(f);
            }
        }
    }
    meta.remove("managedFields");
    meta.remove("selfLink");
    validate_meta_maps(meta)?;
    meta.set("resourceVersion", Value::String(rev.to_string()));
    if let Some(g) = generation {
        meta.set("generation", Value::Number(Number::from_u64(if spec_changed { g + 1 } else { g })));
    }
    Ok(())
}

// ---- label selectors ----

#[derive(Debug, PartialEq, Eq)]
enum Req {
    Eq(String, String),
    Ne(String, String),
    In(String, Vec<String>),
    NotIn(String, Vec<String>),
    Exists(String),
    NotExists(String),
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Selector(Vec<Req>);

impl Selector {
    /// Parses `a=b,c!=d,e in (x,y),f notin (z),g,!h`.
    pub fn parse(s: &str) -> Result<Selector, ApiError> {
        let bad = || ApiError::bad_request(alloc::format!("unable to parse label selector {s:?}"));
        let mut reqs = Vec::new();
        // Split on commas outside parentheses.
        let mut parts = Vec::new();
        let (mut depth, mut start) = (0i32, 0);
        for (i, c) in s.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                ',' if depth == 0 => {
                    parts.push(&s[start..i]);
                    start = i + 1;
                }
                _ => {}
            }
            if depth < 0 || depth > 1 {
                return Err(bad());
            }
        }
        parts.push(&s[start..]);
        for p in parts.into_iter().map(str::trim).filter(|p| !p.is_empty()) {
            let set = |rest: &str| -> Result<Vec<String>, ApiError> {
                let inner = rest.trim().strip_prefix('(').and_then(|r| r.strip_suffix(')')).ok_or_else(bad)?;
                Ok(inner.split(',').map(|v| v.trim().to_string()).filter(|v| !v.is_empty()).collect())
            };
            let r = if let Some(k) = p.strip_prefix('!') {
                Req::NotExists(k.trim().to_string())
            } else if let Some((k, v)) = p.split_once("!=") {
                Req::Ne(k.trim().into(), v.trim().into())
            } else if let Some((k, v)) = p.split_once("==").or_else(|| p.split_once('=')) {
                Req::Eq(k.trim().into(), v.trim().into())
            } else if let Some((k, rest)) = p.split_once(" notin ") {
                Req::NotIn(k.trim().into(), set(rest)?)
            } else if let Some((k, rest)) = p.split_once(" in ") {
                Req::In(k.trim().into(), set(rest)?)
            } else {
                Req::Exists(p.to_string())
            };
            let key = match &r {
                Req::Eq(k, _) | Req::Ne(k, _) | Req::In(k, _) | Req::NotIn(k, _) | Req::Exists(k) | Req::NotExists(k) => k,
            };
            if !is_qualified_key(key) {
                return Err(bad());
            }
            reqs.push(r);
        }
        Ok(Selector(reqs))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Matches an object's metadata.labels.
    pub fn matches(&self, o: &Value) -> bool {
        let labels = o.pointer(&["metadata", "labels"]);
        let get = |k: &str| labels.and_then(|l| l.get(k)).and_then(Value::as_str);
        self.0.iter().all(|r| match r {
            Req::Eq(k, v) => get(k) == Some(v.as_str()),
            Req::Ne(k, v) => get(k) != Some(v.as_str()),
            Req::In(k, vs) => get(k).is_some_and(|x| vs.iter().any(|v| v == x)),
            Req::NotIn(k, vs) => get(k).is_none_or(|x| !vs.iter().any(|v| v == x)),
            Req::Exists(k) => get(k).is_some(),
            Req::NotExists(k) => get(k).is_none(),
        })
    }
}

/// Field selectors: only `metadata.name` and `metadata.namespace` with `=`/`==`/`!=`
/// (plus `spec.nodeName` / `status.phase` for pods, which the kubelet needs).
#[derive(Debug, Default)]
pub struct FieldSelector(Vec<(Vec<String>, bool, String)>);

impl FieldSelector {
    pub fn parse(s: &str) -> Result<FieldSelector, ApiError> {
        let mut out = Vec::new();
        for p in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let (k, neg, v) = if let Some((k, v)) = p.split_once("!=") {
                (k, true, v)
            } else if let Some((k, v)) = p.split_once("==").or_else(|| p.split_once('=')) {
                (k, false, v)
            } else {
                return Err(ApiError::bad_request(alloc::format!("invalid field selector {p:?}")));
            };
            // The union of upstream's per-resource field labels (selectable fields).
            const FIELDS: &[&str] = &[
                "metadata.name", "metadata.namespace",
                // pods
                "spec.nodeName", "spec.restartPolicy", "spec.schedulerName", "spec.serviceAccountName", "spec.hostNetwork", "status.phase", "status.podIP", "status.nominatedNodeName",
                // nodes
                "spec.unschedulable",
                // events
                "involvedObject.kind", "involvedObject.namespace", "involvedObject.name", "involvedObject.uid", "involvedObject.apiVersion", "involvedObject.resourceVersion", "involvedObject.fieldPath", "reason", "reportingComponent", "source", "type",
                // secrets / services / namespaces / replicasets / jobs
                "spec.clusterIP", "spec.type", "status.replicas", "status.successful",
            ];
            let f = k.trim();
            if !FIELDS.contains(&f) {
                return Err(ApiError::bad_request(alloc::format!("field label not supported: {f}")));
            }
            let path: Vec<String> = f.split('.').map(String::from).collect();
            out.push((path, neg, v.trim().to_string()));
        }
        Ok(FieldSelector(out))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn matches(&self, o: &Value) -> bool {
        self.0.iter().all(|(path, neg, v)| {
            let refs: Vec<&str> = path.iter().map(String::as_str).collect();
            // Non-string fields compare in their string form; absent booleans are "false".
            let got = match o.pointer(&refs) {
                Some(Value::String(x)) => x.clone(),
                Some(Value::Bool(b)) => b.to_string(),
                Some(Value::Number(n)) => n.raw().to_string(),
                Some(_) => String::new(),
                None if path.last().is_some_and(|l| l == "unschedulable" || l == "hostNetwork") => "false".into(),
                None if path.last().is_some_and(|l| l == "replicas" || l == "successful") => "0".into(),
                None => String::new(),
            };
            (got == *v) != *neg
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_fmt::json::parse_str;

    fn rng(b: &mut [u8]) {
        for (i, x) in b.iter_mut().enumerate() {
            *x = (i * 37 + 11) as u8;
        }
    }

    #[test]
    fn names_and_labels() {
        assert!(is_dns_label("a-b-1") && !is_dns_label("-a") && !is_dns_label("A") && !is_dns_label(&"a".repeat(64)));
        assert!(is_dns_subdomain("a.b-c.d") && !is_dns_subdomain("a..b") && !is_dns_subdomain("a_b"));
        assert!(is_qualified_key("app.kubernetes.io/name") && is_qualified_key("Tier_1") && !is_qualified_key("/x") && !is_qualified_key("a/b/c"));
        assert!(is_label_value("") && is_label_value("v1.2_x") && !is_label_value("-x"));
    }

    #[test]
    fn rfc3339_known_points() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_800_000_000), "2027-01-15T08:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn create_then_update() {
        let t = Target { api_version: "v1", kind: "ConfigMap", namespace: Some("default"), name_is_label: false };
        let clock = Clock { now: 1_800_000_000, rng };
        let mut o = parse_str(r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"generateName":"cfg-","labels":{"a":"b"}},"data":{"k":"v"}}"#).unwrap();
        let name = prepare_create(&mut o, &t, &clock, 7).unwrap();
        assert!(name.starts_with("cfg-") && name.len() == 9);
        assert_eq!(o.pointer(&["metadata", "namespace"]).unwrap().as_str(), Some("default"));
        assert_eq!(o.pointer(&["metadata", "resourceVersion"]).unwrap().as_str(), Some("7"));
        assert_eq!(uuid4(rng).len(), 36);
        // update: uid carried over, stale resourceVersion conflicts
        let mut n = o.clone();
        n.get_mut("metadata").unwrap().set("uid", Value::from("other"));
        assert_eq!(prepare_update(&o, &mut n, &t, 8, false, false).unwrap_err().code, 409);
        let mut n = parse_str(r#"{"metadata":{"name":"x","resourceVersion":"6"},"data":{}}"#).unwrap();
        n.get_mut("metadata").unwrap().set("name", Value::from(name.as_str()));
        assert_eq!(prepare_update(&o, &mut n, &t, 8, false, false).unwrap_err().reason, "Conflict");
        // wrong namespace in body
        let mut bad = parse_str(r#"{"metadata":{"name":"a","namespace":"other"}}"#).unwrap();
        assert_eq!(prepare_create(&mut bad, &t, &clock, 9).unwrap_err().code, 400);
        // duplicate keys are rejected
        let mut dup = parse_str(r#"{"metadata":{"name":"a","name":"b"}}"#).unwrap();
        assert_eq!(prepare_create(&mut dup, &t, &clock, 9).unwrap_err().code, 400);
    }

    #[test]
    fn generation_and_status() {
        let t = Target { api_version: "apps/v1", kind: "Deployment", namespace: Some("d"), name_is_label: false };
        let clock = Clock { now: 0, rng };
        let mut o = parse_str(r#"{"metadata":{"name":"web"},"spec":{"replicas":1},"status":{"replicas":0}}"#).unwrap();
        prepare_create(&mut o, &t, &clock, 1).unwrap();
        let mut n = parse_str(r#"{"metadata":{"name":"web"},"spec":{"replicas":3},"status":{"replicas":99}}"#).unwrap();
        prepare_update(&o, &mut n, &t, 2, true, false).unwrap();
        assert_eq!(n.pointer(&["metadata", "generation"]).unwrap().as_u64(), Some(2));
        assert_eq!(n.pointer(&["status", "replicas"]).unwrap().as_u64(), Some(0)); // main resource ignores status
        let mut s = parse_str(r#"{"metadata":{"name":"web"},"spec":{"replicas":7},"status":{"replicas":3}}"#).unwrap();
        prepare_update(&n, &mut s, &t, 3, true, true).unwrap();
        assert_eq!(s.pointer(&["spec", "replicas"]).unwrap().as_u64(), Some(3)); // status update ignores spec
        assert_eq!(s.pointer(&["status", "replicas"]).unwrap().as_u64(), Some(3));
        assert_eq!(s.pointer(&["metadata", "generation"]).unwrap().as_u64(), Some(2));
    }

    #[test]
    fn selectors() {
        let o = parse_str(r#"{"metadata":{"name":"a","namespace":"n","labels":{"app":"web","tier":"fe"}}}"#).unwrap();
        for (s, want) in [("app=web", true), ("app==web,tier!=be", true), ("app in (web, api)", true), ("tier notin (fe)", false), ("app,!missing", true), ("missing", false), ("", true)] {
            assert_eq!(Selector::parse(s).unwrap().matches(&o), want, "{s}");
        }
        assert!(Selector::parse("a in (b").is_err());
        assert!(FieldSelector::parse("metadata.name=a,metadata.namespace!=x").unwrap().matches(&o));
        assert!(FieldSelector::parse("spec.secret=1").is_err());
    }
}
