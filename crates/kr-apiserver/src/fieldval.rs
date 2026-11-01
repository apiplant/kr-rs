//! Server-side field validation (`fieldValidation=Ignore|Warn|Strict`): finds the fields of a
//! request body the schema does not know (built-in kinds via the generated protobuf field
//! tables, custom resources via the pruning rules) and duplicate JSON keys.
//!
//! Paths follow upstream: `spec.containers[0].imagee`, map keys as `metadata.labels.key`.

use crate::proto_schema as s;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_fmt::json::Value;

/// What to do with unknown and duplicate fields.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Ignore,
    Warn,
    Strict,
}

impl Mode {
    pub fn parse(s: Option<&str>) -> Mode {
        match s {
            Some("Ignore") => Mode::Ignore,
            Some("Strict") => Mode::Strict,
            _ => Mode::Warn,
        }
    }
}

const MAX_DEPTH: usize = 64;

fn name_of(f: &s::Field) -> &'static str {
    &s::NAMES[f.name_off as usize..f.name_off as usize + f.name_len as usize]
}

fn fields_of(idx: u16) -> &'static [s::Field] {
    &s::FIELDS[s::MSG_START[idx as usize] as usize..s::MSG_START[idx as usize + 1] as usize]
}

/// The field called `key` in message `idx`, looking through inline (embedded) messages.
fn lookup(idx: u16, key: &str, depth: usize) -> Option<&'static s::Field> {
    if depth > 8 {
        return None;
    }
    for f in fields_of(idx) {
        if f.kind & s::F_INLINE != 0 && f.kind & s::K_MASK == s::K_MESSAGE {
            if let Some(g) = lookup(f.arg, key, depth + 1) {
                return Some(g);
            }
        } else if name_of(f) == key {
            return Some(f);
        }
    }
    None
}

/// Messages with a hand-written JSON form: their content is not validated.
fn opaque(idx: u16) -> bool {
    matches!(idx, s::M_TIME | s::M_MICRO_TIME | s::M_DURATION | s::M_FIELDS_V1 | s::M_INT_OR_STRING | s::M_QUANTITY | s::M_RAW_EXTENSION | s::M_EXT_JSON | s::M_SCHEMA_OR_ARRAY | s::M_SCHEMA_OR_BOOL | s::M_SCHEMA_OR_STRINGS)
}

fn join(path: &str, k: &str) -> String {
    if path.is_empty() { k.to_string() } else { format!("{path}.{k}") }
}

fn message(v: &Value, idx: u16, path: &str, root: bool, out: &mut Vec<String>, depth: usize) {
    if opaque(idx) || depth > MAX_DEPTH {
        return;
    }
    if let Value::Object(fields) = v {
        for (k, fv) in fields {
            if root && (k == "kind" || k == "apiVersion") {
                continue;
            }
            let p = join(path, k);
            match lookup(idx, k, 0) {
                None => out.push(p),
                Some(f) => field(fv, f, &p, out, depth),
            }
        }
    }
}

fn field(v: &Value, f: &s::Field, path: &str, out: &mut Vec<String>, depth: usize) {
    match f.kind & s::K_MASK {
        s::K_MESSAGE => {
            if f.kind & s::F_REPEATED != 0 {
                if let Value::Array(items) = v {
                    for (i, it) in items.iter().enumerate() {
                        message(it, f.arg, &format!("{path}[{i}]"), false, out, depth + 1);
                    }
                }
            } else {
                message(v, f.arg, path, false, out, depth + 1);
            }
        }
        s::K_MAP => {
            let (_, _, vk, va) = s::MAPS[f.arg as usize];
            if vk == s::K_MESSAGE {
                if let Value::Object(entries) = v {
                    for (k, ev) in entries {
                        message(ev, va, &join(path, k), false, out, depth + 1);
                    }
                }
            }
        }
        _ => {}
    }
}

/// Unknown field paths of `v` as a built-in `kind` of `api_version`; `None` when the schema
/// has no such kind.
pub fn unknown_builtin(api_version: &str, kind: &str, v: &Value) -> Option<Vec<String>> {
    let idx = s::KINDS.iter().find(|k| k.0 == api_version && k.1 == kind)?.2;
    let mut out = Vec::new();
    message(v, idx, "", true, &mut out, 0);
    Some(out)
}

fn json_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn go_type(kind: u8, repeated: bool) -> String {
    let base = match kind {
        s::K_STRING => "string",
        s::K_BYTES => "[]uint8",
        s::K_INT32 => "int32",
        s::K_INT64 => "int64",
        s::K_BOOL => "bool",
        s::K_DOUBLE => "float64",
        s::K_FLOAT => "float32",
        s::K_UINT32 => "uint32",
        s::K_UINT64 => "uint64",
        s::K_MAP => "map[string]object",
        _ => "object",
    };
    if repeated { format!("[]{base}") } else { base.to_string() }
}

/// Whether the non-null scalar `v` decodes into a field of `kind` (Go `encoding/json` rules).
fn scalar_ok(v: &Value, kind: u8) -> bool {
    match (kind, v) {
        (s::K_STRING, Value::String(_)) | (s::K_BOOL, Value::Bool(_)) => true,
        (s::K_BYTES, Value::String(b)) => b.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=' | b'-' | b'_')),
        (s::K_DOUBLE | s::K_FLOAT, Value::Number(_)) => true,
        (s::K_INT32 | s::K_INT64 | s::K_UINT32 | s::K_UINT64, Value::Number(n)) => {
            let (lo, hi) = match kind {
                s::K_INT32 => (i32::MIN as i128, i32::MAX as i128),
                s::K_INT64 => (i64::MIN as i128, i64::MAX as i128),
                s::K_UINT32 => (0, u32::MAX as i128),
                _ => (0, u64::MAX as i128),
            };
            // Integral floats such as `3.0` are accepted (Go would reject them).
            let f = n.as_f64();
            let i = match (n.as_i64(), n.as_u64()) {
                (Some(i), _) => i as i128,
                (_, Some(u)) => u as i128,
                _ if f.is_finite() && f == (f as i64) as f64 => f as i64 as i128,
                _ => return false,
            };
            (lo..=hi).contains(&i)
        }
        _ => false,
    }
}

fn type_err(v: &Value, root: &str, path: &str, go: &str) -> String {
    format!("json: cannot unmarshal {} into Go struct field {root}.{path} of type {go}", json_type(v))
}

fn type_message(v: &Value, idx: u16, root: &str, path: &str, depth: usize) -> Option<String> {
    if depth > MAX_DEPTH {
        return None;
    }
    let (ok, go) = match idx {
        s::M_TIME => (matches!(v, Value::String(_)), "v1.Time"),
        s::M_MICRO_TIME => (matches!(v, Value::String(_)), "v1.MicroTime"),
        s::M_DURATION => (matches!(v, Value::String(_)), "v1.Duration"),
        s::M_INT_OR_STRING => (matches!(v, Value::String(_)) || matches!(v, Value::Number(n) if n.is_integer()), "intstr.IntOrString"),
        s::M_QUANTITY => (matches!(v, Value::String(_) | Value::Number(_)), "resource.Quantity"),
        // Free-form JSON, and CRD schema unions (an object, or an array / a bool; the CRD
        // structural checks validate their contents).
        s::M_RAW_EXTENSION | s::M_FIELDS_V1 | s::M_EXT_JSON => return None,
        s::M_SCHEMA_OR_ARRAY | s::M_SCHEMA_OR_BOOL | s::M_SCHEMA_OR_STRINGS => (matches!(v, Value::Object(_) | Value::Array(_) | Value::Bool(_)), "object"),
        _ => (matches!(v, Value::Object(_)), "object"),
    };
    if !ok {
        return Some(type_err(v, root, path, go));
    }
    if let (Value::Object(fields), false) = (v, opaque(idx)) {
        for (k, fv) in fields {
            if let Some(f) = lookup(idx, k, 0) {
                if let Some(e) = type_field(fv, f, root, &join(path, k), depth) {
                    return Some(e);
                }
            }
        }
    }
    None
}

fn type_item(v: &Value, kind: u8, arg: u16, root: &str, path: &str, depth: usize) -> Option<String> {
    if matches!(v, Value::Null) {
        return None;
    }
    if kind == s::K_MESSAGE {
        return type_message(v, arg, root, path, depth + 1);
    }
    if scalar_ok(v, kind) { None } else { Some(type_err(v, root, path, &go_type(kind, false))) }
}

fn type_field(v: &Value, f: &s::Field, root: &str, path: &str, depth: usize) -> Option<String> {
    if matches!(v, Value::Null) {
        return None;
    }
    let kind = f.kind & s::K_MASK;
    if kind == s::K_MAP {
        let Value::Object(entries) = v else { return Some(type_err(v, root, path, &go_type(kind, false))) };
        let (_, _, vk, va) = s::MAPS[f.arg as usize];
        return entries.iter().find_map(|(k, ev)| type_item(ev, vk, va, root, &join(path, k), depth));
    }
    if f.kind & s::F_REPEATED != 0 {
        let Value::Array(items) = v else { return Some(type_err(v, root, path, &go_type(kind, true))) };
        return items.iter().find_map(|it| type_item(it, kind, f.arg, root, path, depth));
    }
    type_item(v, kind, f.arg, root, path, depth)
}

/// The first JSON type error of `v` as a built-in `kind` of `api_version` (what Go's decoder
/// would reject, without the `cannot be handled` prefix); `None` when well-typed or the schema
/// has no such kind. Unknown fields are not type errors.
pub fn type_error(api_version: &str, kind: &str, v: &Value) -> Option<String> {
    let idx = s::KINDS.iter().find(|k| k.0 == api_version && k.1 == kind)?.2;
    let Value::Object(fields) = v else { return None };
    fields.iter().find_map(|(k, fv)| lookup(idx, k, 0).and_then(|f| type_field(fv, f, kind, k, 0)))
}

/// Unknown fields of a custom resource's `metadata` (the CRD schema never describes it).
pub fn unknown_meta(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let (Some(m), Some(pod)) = (v.get("metadata"), s::KINDS.iter().find(|k| k.1 == "Pod")) {
        if let Some(f) = lookup(pod.2, "metadata", 0) {
            field(m, f, "metadata", &mut out, 0);
        }
    }
    out
}

/// Fields present in `orig` but dropped from `pruned` (what CRD pruning removed).
pub fn pruned_paths(orig: &Value, pruned: &Value, path: &str, out: &mut Vec<String>) {
    match (orig, pruned) {
        (Value::Object(a), Value::Object(_)) => {
            for (k, av) in a {
                let p = join(path, k);
                match pruned.get(k) {
                    None => out.push(p),
                    Some(pv) => pruned_paths(av, pv, &p, out),
                }
            }
        }
        (Value::Array(a), Value::Array(b)) => {
            for (i, (x, y)) in a.iter().zip(b).enumerate() {
                pruned_paths(x, y, &format!("{path}[{i}]"), out);
            }
        }
        _ => {}
    }
}

/// Paths of duplicated object keys, at any depth.
pub fn duplicates(v: &Value, path: &str, out: &mut Vec<String>) {
    match v {
        Value::Object(fields) => {
            for (i, (k, fv)) in fields.iter().enumerate() {
                let p = join(path, k);
                if fields[..i].iter().any(|(x, _)| x == k) {
                    out.push(p.clone());
                }
                duplicates(fv, &p, out);
            }
        }
        Value::Array(items) => {
            for (i, it) in items.iter().enumerate() {
                duplicates(it, &format!("{path}[{i}]"), out);
            }
        }
        _ => {}
    }
}

/// `unknown field "x"` messages for the paths in `new` that `old` did not already have.
pub fn messages(new: Vec<String>, old: &[String]) -> Vec<String> {
    new.into_iter().filter(|p| !old.contains(p)).map(|p| format!("unknown field \"{p}\"")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_fmt::json;

    fn unk(api: &str, kind: &str, body: &str) -> Vec<String> {
        unknown_builtin(api, kind, &json::parse(body.as_bytes()).unwrap()).unwrap()
    }

    #[test]
    fn nested_containers() {
        let u = unk("v1", "Pod", r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"a","labelz":{}},"spec":{"containers":[{"name":"c","image":"i"},{"name":"d","imagee":"x","ports":[{"containerPort":1,"portt":2}]}],"foo":1}}"#);
        assert_eq!(u, ["metadata.labelz", "spec.containers[1].imagee", "spec.containers[1].ports[0].portt", "spec.foo"]);
    }

    #[test]
    fn maps_and_opaque() {
        let u = unk("v1", "Pod", r#"{"metadata":{"labels":{"any":"x"},"annotations":{"a.b/c":"d"},"creationTimestamp":null},"spec":{"nodeSelector":{"k":"v"},"containers":[{"name":"c","resources":{"limits":{"cpu":"1","weird":"2"},"requests":{"memory":"1Gi"}}}]}}"#);
        assert!(u.is_empty(), "{u:?}");
    }

    #[test]
    fn int_or_string_and_raw() {
        let u = unk("v1", "Service", r#"{"spec":{"ports":[{"port":1,"targetPort":{"x":1}}],"selector":{"a":"b"}}}"#);
        assert!(u.is_empty(), "{u:?}");
        let u = unk("apps/v1", "ControllerRevision", r#"{"revision":1,"data":{"anything":{"goes":[1]}}}"#);
        assert!(u.is_empty(), "{u:?}");
        let u = unk("apps/v1", "Deployment", r#"{"spec":{"selector":{"matchLabels":{"a":"b"}},"template":{"metadata":{"labels":{"a":"b"}},"spec":{"containers":[{"name":"c","bogus":1}]}}}}"#);
        assert_eq!(u, ["spec.template.spec.containers[0].bogus"]);
    }

    fn ty(api: &str, kind: &str, body: &str) -> Option<String> {
        type_error(api, kind, &json::parse(body.as_bytes()).unwrap())
    }

    #[test]
    fn type_errors() {
        let e = ty("v1", "Pod", r#"{"spec":{"containers":"x"}}"#).unwrap();
        assert!(e.contains("cannot unmarshal string into Go struct field Pod.spec.containers of type []object"), "{e}");
        let e = ty("v1", "Pod", r#"{"spec":{"containers":[{"name":5}]}}"#).unwrap();
        assert!(e.contains("number into Go struct field Pod.spec.containers.name of type string"), "{e}");
        assert!(ty("v1", "Pod", r#"{"spec":{"containers":[{"name":"c","ports":[{"containerPort":4294967296}]}]}}"#).is_some());
        assert!(ty("v1", "Pod", r#"{"spec":{"containers":[{"name":"c","ports":[{"containerPort":80}]}]}}"#).is_none());
        assert!(ty("v1", "Pod", r#"{"metadata":{"labels":{"a":1}}}"#).is_some());
        assert!(ty("v1", "Pod", r#"{"spec":{"hostNetwork":"yes"}}"#).is_some());
    }

    #[test]
    fn type_special_forms() {
        for t in ["80", r#""http""#] {
            assert!(ty("v1", "Service", &format!(r#"{{"spec":{{"ports":[{{"port":1,"targetPort":{t}}}]}}}}"#)).is_none());
        }
        assert!(ty("v1", "Service", r#"{"spec":{"ports":[{"port":1,"targetPort":true}]}}"#).is_some());
        assert!(ty("v1", "Pod", r#"{"spec":{"containers":[{"name":"c","resources":{"limits":{"cpu":1,"memory":"1Gi"}}}]}}"#).is_none());
        assert!(ty("v1", "Pod", r#"{"metadata":{"creationTimestamp":"2020-01-01T00:00:00Z"}}"#).is_none());
        assert!(ty("v1", "Pod", r#"{"metadata":{"creationTimestamp":5}}"#).is_some());
    }

    #[test]
    fn type_null_and_unknown() {
        assert!(ty("v1", "Pod", r#"{"metadata":null,"spec":{"containers":null,"hostNetwork":null,"nodeSelector":{"a":null},"bogus":[1]}}"#).is_none());
    }

    #[test]
    fn dups() {
        let v = json::parse(br#"{"a":{"b":1,"b":2},"l":[{"x":1,"x":1}]}"#).unwrap();
        let mut o = Vec::new();
        duplicates(&v, "", &mut o);
        assert_eq!(o, ["a.b", "l[0].x"]);
    }
}

/// The CEL type of the field at `path` in a built-in kind (`apps/v1`, `Deployment`), from the
/// protobuf tables: `int`, `uint`, `double`, `string`, `bool`, `bytes`, `list`, `map`, or `None`
/// where unknown or free-form (objects, times, quantities, int-or-string are dynamic).
pub fn cel_type(api_version: &str, kind: &str, path: &[&str]) -> Option<&'static str> {
    let mut idx = s::KINDS.iter().find(|k| k.0 == api_version && k.1 == kind)?.2;
    let mut it = path.iter().peekable();
    while let Some(key) = it.next() {
        if opaque(idx) {
            return None;
        }
        let f = lookup(idx, key, 0)?;
        let last = it.peek().is_none();
        if f.kind & s::F_REPEATED != 0 {
            return last.then_some("list");
        }
        match f.kind & s::K_MASK {
            s::K_MESSAGE => idx = f.arg,
            s::K_MAP => return last.then_some("map"),
            k if last => {
                return Some(match k {
                    s::K_STRING => "string",
                    s::K_BYTES => "bytes",
                    s::K_INT32 | s::K_INT64 => "int",
                    s::K_UINT32 | s::K_UINT64 => "uint",
                    s::K_BOOL => "bool",
                    s::K_DOUBLE | s::K_FLOAT => "double",
                    _ => return None,
                })
            }
            _ => return None,
        }
    }
    None
}

#[cfg(test)]
mod cel_type_tests {
    use super::cel_type;

    #[test]
    fn deployment_fields() {
        assert_eq!(cel_type("apps/v1", "Deployment", &["spec", "replicas"]), Some("int"));
        assert_eq!(cel_type("apps/v1", "Deployment", &["metadata", "name"]), Some("string"));
        assert_eq!(cel_type("apps/v1", "Deployment", &["spec", "template", "spec", "containers"]), Some("list"));
        assert_eq!(cel_type("apps/v1", "Deployment", &["metadata", "labels"]), Some("map"));
        assert_eq!(cel_type("apps/v1", "Deployment", &["metadata", "creationTimestamp"]), None);
        assert_eq!(cel_type("apps/v1", "Deployment", &["spec", "nope"]), None);
    }
}

// ---- value checks from the generated tables: `+enum` values and required strings ----

fn enum_values(idx: u16, num: u16) -> Option<&'static str> {
    s::ENUMS.binary_search_by(|e| (e.0, e.1).cmp(&(idx, num))).ok().map(|i| s::ENUMS[i].2)
}

fn is_required(idx: u16, num: u16) -> bool {
    s::REQUIRED.binary_search(&(idx, num)).is_ok()
}

fn values_message(idx: u16, v: &Value, path: &str, out: &mut Vec<String>, depth: usize) {
    if opaque(idx) || depth > MAX_DEPTH {
        return;
    }
    let Value::Object(entries) = v else { return };
    for f in fields_of(idx) {
        if f.kind & s::F_INLINE != 0 && f.kind & s::K_MASK == s::K_MESSAGE {
            values_message(f.arg, v, path, out, depth + 1);
            continue;
        }
        let name = name_of(f);
        let p = join(path, name);
        let fv = entries.iter().find(|(k, _)| k == name).map(|(_, x)| x);
        let repeated = f.kind & s::F_REPEATED != 0;
        match f.kind & s::K_MASK {
            s::K_STRING if !repeated => {
                let text = fv.and_then(Value::as_str).unwrap_or("");
                if text.is_empty() {
                    // A string that is present but not a string is a type error, reported elsewhere.
                    if is_required(idx, f.num) && !matches!(fv, Some(x) if x.as_str().is_none() && !matches!(x, Value::Null)) {
                        out.push(format!("{p}: Required value"));
                    }
                } else if let Some(vals) = enum_values(idx, f.num) {
                    if !vals.split('|').any(|x| x == text) {
                        let list: Vec<String> = vals.split('|').map(|x| format!("\"{x}\"")).collect();
                        out.push(format!("{p}: Unsupported value: \"{text}\": supported values: {}", list.join(", ")));
                    }
                }
            }
            s::K_INT32 | s::K_INT64 if !repeated => {
                if let Some(Value::Number(n)) = fv {
                    let i = n.as_i64();
                    if matches!(name, "containerPort" | "port" | "hostPort" | "nodePort" | "endPort" | "healthCheckNodePort") && i.is_some_and(|i| !(0..=65535).contains(&i) || (i == 0 && name == "containerPort")) {
                        out.push(format!("{p}: Invalid value: {}: must be between 1 and 65535, inclusive", n.raw()));
                    } else if matches!(name, "replicas" | "minReadySeconds" | "terminationGracePeriodSeconds" | "activeDeadlineSeconds" | "backoffLimit" | "parallelism" | "completions" | "revisionHistoryLimit" | "ttlSecondsAfterFinished" | "successfulJobsHistoryLimit" | "failedJobsHistoryLimit" | "maxReplicas" | "minReplicas") && i.is_some_and(|i| i < 0) && !(name == "terminationGracePeriodSeconds" && i == Some(-1)) {
                        out.push(format!("{p}: Invalid value: {}: must be greater than or equal to 0", n.raw()));
                    }
                }
            }
            s::K_MESSAGE if f.arg == s::M_QUANTITY && !repeated => {
                if let Some(Value::String(q)) = fv {
                    if kr_fmt::quantity::Quantity::parse(q).is_err() {
                        out.push(format!("{p}: Invalid value: \"{q}\": quantities must match the regular expression '^([+-]?[0-9.]+)([eEinumkKMGTP]*[-+]?[0-9]*)$'"));
                    }
                }
            }
            s::K_MESSAGE => match fv {
                Some(Value::Array(items)) if repeated => {
                    for (i, it) in items.iter().enumerate() {
                        values_message(f.arg, it, &format!("{p}[{i}]"), out, depth + 1);
                    }
                }
                Some(x @ Value::Object(_)) if !repeated => values_message(f.arg, x, &p, out, depth + 1),
                _ => {}
            },
            s::K_MAP => {
                let (_, _, vk, va) = s::MAPS[f.arg as usize];
                if let (s::K_MESSAGE, Some(Value::Object(m))) = (vk, fv) {
                    for (k, ev) in m {
                        if va == s::M_QUANTITY {
                            if let Value::String(q) = ev {
                                if kr_fmt::quantity::Quantity::parse(q).is_err() {
                                    out.push(format!("{}: Invalid value: \"{q}\": quantities must match the regular expression '^([+-]?[0-9.]+)([eEinumkKMGTP]*[-+]?[0-9]*)$'", join(&p, k)));
                                }
                            }
                            continue;
                        }
                        values_message(va, ev, &join(&p, k), out, depth + 1);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Enum and required-string violations of a built-in object (`spec` and other top-level
/// fields; `metadata` and `status` are not checked), worded like upstream's validation.
/// `None` when the schema has no such kind.
pub fn value_errors(api_version: &str, kind: &str, v: &Value) -> Option<Vec<String>> {
    let idx = s::KINDS.iter().find(|k| k.0 == api_version && k.1 == kind)?.2;
    let Value::Object(entries) = v else { return Some(Vec::new()) };
    let mut out = Vec::new();
    for f in fields_of(idx) {
        let name = name_of(f);
        if f.kind & s::K_MASK != s::K_MESSAGE || matches!(name, "metadata" | "status" | "") {
            continue;
        }
        let Some((_, fv)) = entries.iter().find(|(k, _)| k == name) else { continue };
        let p = String::from(name);
        match fv {
            Value::Array(items) if f.kind & s::F_REPEATED != 0 => {
                for (i, it) in items.iter().enumerate() {
                    values_message(f.arg, it, &format!("{p}[{i}]"), &mut out, 1);
                }
            }
            Value::Object(_) => values_message(f.arg, fv, &p, &mut out, 1),
            _ => {}
        }
    }
    cross_field(api_version, kind, v, &mut out);
    // Container and volume names: DNS labels, unique (pods and the templates of workloads).
    let spec = entries.iter().find(|(k, _)| k == "spec").map(|(_, x)| x);
    if let Some(spec) = spec {
        pod_spec_names(spec, "spec", &mut out);
        if let Some(t) = spec.pointer(&["template", "spec"]) {
            pod_spec_names(t, "spec.template.spec", &mut out);
        }
        if let Some(t) = spec.pointer(&["jobTemplate", "spec", "template", "spec"]) {
            pod_spec_names(t, "spec.jobTemplate.spec.template.spec", &mut out);
        }
    }
    let mut seen = Vec::new();
    out.retain(|e| !seen.contains(e) && { seen.push(e.clone()); true });
    Some(out)
}

#[cfg(test)]
mod value_tests {
    use super::*;

    #[test]
    fn enums_and_required() {
        let v = kr_fmt::json::parse_str(r#"{"spec":{"restartPolicy":"Sometimes","containers":[{"name":"","image":"x"}]}}"#).unwrap();
        let e = value_errors("v1", "Pod", &v).unwrap();
        assert!(e.iter().any(|x| x == "spec.restartPolicy: Unsupported value: \"Sometimes\": supported values: \"Always\", \"OnFailure\", \"Never\""), "{e:?}");
        assert!(e.iter().any(|x| x == "spec.containers[0].name: Required value"), "{e:?}");
        let ok = kr_fmt::json::parse_str(r#"{"spec":{"restartPolicy":"Never","containers":[{"name":"c","image":"x"}]}}"#).unwrap();
        assert!(value_errors("v1", "Pod", &ok).unwrap().is_empty());
        let pod = kr_fmt::json::parse_str(r#"{"spec":{"hostname":"A","volumes":[{"name":"a"},{"name":"b","emptyDir":{},"secret":{"secretName":"s"}}],"containers":[{"name":"c","livenessProbe":{"exec":{"command":["x"]},"httpGet":{"port":80},"periodSeconds":-1},"readinessProbe":{},"env":[{"name":"1A"}]}],"affinity":{"nodeAffinity":{"preferredDuringSchedulingIgnoredDuringExecution":[{"weight":101}]}}}}"#).unwrap();
        let e = value_errors("v1", "Pod", &pod).unwrap();
        for want in ["spec.hostname: Invalid value", "volumes[0]: Required value: must specify a volume type", "volumes[1]: Forbidden", "livenessProbe: Forbidden: may not specify more than 1", "readinessProbe: Required value: must specify a handler type", "periodSeconds: Invalid value: -1", "env[0].name: Invalid value", "weight: Invalid value: 101"] {
            assert!(e.iter().any(|x| x.contains(want)), "{want}: {e:?}");
        }
        let more = kr_fmt::json::parse_str(r#"{"spec":{"containers":[{"name":"c","resources":{"requests":{"cpu":"2"},"limits":{"cpu":"1"}},"ports":[{"name":"1234","containerPort":80}]}],"topologySpreadConstraints":[{"maxSkew":0}],"tolerations":[{"operator":"Exists","value":"x","key":"k"}],"dnsConfig":{"nameservers":["x"]},"hostAliases":[{"ip":"nope"}]}}"#).unwrap();
        let e = value_errors("v1", "Pod", &more).unwrap();
        for want in ["must be less than or equal to cpu limit", "ports[0].name: Invalid value", "maxSkew: Invalid value: 0", "value must be empty when `operator` is 'Exists'", "nameservers[0]: Invalid value", "hostAliases[0].ip: Invalid value"] {
            assert!(e.iter().any(|x| x.contains(want)), "{want}: {e:?}");
        }
        let dep = kr_fmt::json::parse_str(r#"{"spec":{"selector":{"matchLabels":{"a":"b"},"matchExpressions":[{"key":"k","operator":"In"}]},"template":{"metadata":{"labels":{"a":"c"}}}}}"#).unwrap();
        let e = value_errors("apps/v1", "Deployment", &dep).unwrap();
        assert!(e.iter().any(|x| x.contains("`selector` does not match template `labels`")) && e.iter().any(|x| x.contains("matchExpressions[0].values: Required value")), "{e:?}");
        let svc = kr_fmt::json::parse_str(r#"{"spec":{"ports":[{"port":80},{"name":"b","port":80}]}}"#).unwrap();
        assert!(value_errors("v1", "Service", &svc).unwrap().iter().any(|x| x == "spec.ports[0].name: Required value"));
        let bad = kr_fmt::json::parse_str(r#"{"spec":{"containers":[{"name":"A_b","ports":[{"containerPort":70000}],"resources":{"limits":{"cpu":"abc"}}},{"name":"A_b"}],"volumes":[{"name":"v"},{"name":"v"}]}}"#).unwrap();
        let e = value_errors("v1", "Pod", &bad).unwrap();
        for want in ["spec.containers[0].name: Invalid value", "spec.containers[1].name: Duplicate value: \"A_b\"", "spec.volumes[1].name: Duplicate value", "containerPort: Invalid value: 70000: must be between 1 and 65535", "limits.cpu: Invalid value: \"abc\""] {
            assert!(e.iter().any(|x| x.contains(want)), "{want}: {e:?}");
        }
    }
}

fn dns_label(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty() && b.len() <= 63 && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-') && b[0] != b'-' && b[b.len() - 1] != b'-'
}

fn pod_spec_names(spec: &Value, prefix: &str, out: &mut Vec<String>) {
    for (f, label) in [("hostname", true), ("subdomain", true), ("serviceAccountName", false), ("priorityClassName", false), ("runtimeClassName", false)] {
        if let Some(n) = spec.get(f).and_then(Value::as_str).filter(|n| !n.is_empty()) {
            if !(if label { dns_label(n) } else { dns_subdomain(n) }) {
                out.push(format!("{prefix}.{f}: Invalid value: \"{n}\": a lowercase RFC 1123 {} must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character", if label { "label" } else { "subdomain" }));
            }
        }
    }
    for (i, v) in spec.get("volumes").and_then(Value::as_array).unwrap_or(&[]).iter().enumerate() {
        let n = v.as_object().map_or(0, |o| o.iter().filter(|(k, x)| k != "name" && !x.is_null()).count());
        if n == 0 {
            out.push(format!("{prefix}.volumes[{i}]: Required value: must specify a volume type"));
        } else if n > 1 {
            out.push(format!("{prefix}.volumes[{i}]: Forbidden: may not specify more than 1 volume type"));
        }
    }
    for list in ["initContainers", "containers"] {
        for (i, c) in spec.get(list).and_then(Value::as_array).unwrap_or(&[]).iter().enumerate() {
            let cp = format!("{prefix}.{list}[{i}]");
            if let Some(res) = c.get("resources") {
                for (name, q) in res.get("requests").and_then(Value::as_object).unwrap_or(&[]) {
                    let (Some(req), Some(lim)) = (q.as_str().and_then(|x| kr_fmt::quantity::Quantity::parse(x).ok()), res.pointer(&["limits", name]).and_then(Value::as_str).and_then(|x| kr_fmt::quantity::Quantity::parse(x).ok())) else { continue };
                    if req > lim {
                        out.push(format!("{cp}.resources.requests: Invalid value: \"{}\": must be less than or equal to {name} limit of {}", req.to_canonical_string(), lim.to_canonical_string()));
                    }
                }
                for kind in ["requests", "limits"] {
                    for (name, q) in res.get(kind).and_then(Value::as_object).unwrap_or(&[]) {
                        if q.as_str().and_then(|x| kr_fmt::quantity::Quantity::parse(x).ok()).is_some_and(|x| x.mantissa() < 0) {
                            out.push(format!("{cp}.resources.{kind}[{name}]: Invalid value: \"{}\": must be greater than or equal to 0", q.as_str().unwrap_or("")));
                        }
                    }
                }
            }
            for (j, p) in c.get("ports").and_then(Value::as_array).unwrap_or(&[]).iter().enumerate() {
                if let Some(n) = p.get("name").and_then(Value::as_str).filter(|n| !n.is_empty() && (n.len() > 15 || !n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') || n.bytes().all(|b| b.is_ascii_digit()))) {
                    out.push(format!("{cp}.ports[{j}].name: Invalid value: \"{n}\": must be no more than 15 characters, consist of lower-case alphanumeric characters or '-', and contain at least one letter"));
                }
            }
            for pr in ["livenessProbe", "readinessProbe", "startupProbe"] {
                if let Some(probe @ Value::Object(_)) = c.get(pr) {
                    handler_errors(probe, &format!("{cp}.{pr}"), &["exec", "httpGet", "tcpSocket", "grpc"], out);
                    for (f, min) in [("initialDelaySeconds", 0), ("timeoutSeconds", 0), ("periodSeconds", 0), ("successThreshold", 1), ("failureThreshold", 1)] {
                        if let Some(n) = probe.get(f).and_then(Value::as_i64).filter(|n| *n < min) {
                            out.push(format!("{cp}.{pr}.{f}: Invalid value: {n}: must be greater than or equal to {min}"));
                        }
                    }
                }
            }
            for (h, key) in [("postStart", "postStart"), ("preStop", "preStop")] {
                if let Some(hd @ Value::Object(_)) = c.pointer(&["lifecycle", key]) {
                    handler_errors(hd, &format!("{cp}.lifecycle.{h}"), &["exec", "httpGet", "tcpSocket", "sleep"], out);
                }
            }
            for (j, e) in c.get("env").and_then(Value::as_array).unwrap_or(&[]).iter().enumerate() {
                if let Some(n) = e.get("name").and_then(Value::as_str).filter(|n| !n.is_empty()) {
                    let ok = n.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')) && !n.as_bytes()[0].is_ascii_digit();
                    if !ok {
                        out.push(format!("{cp}.env[{j}].name: Invalid value: \"{n}\": a valid environment variable name must consist of alphabetic characters, digits, '_', '-', or '.', and must not start with a digit"));
                    }
                }
            }
        }
    }
    for (i, t) in spec.get("topologySpreadConstraints").and_then(Value::as_array).unwrap_or(&[]).iter().enumerate() {
        if let Some(n) = t.get("maxSkew").and_then(Value::as_i64).filter(|n| *n < 1) {
            out.push(format!("{prefix}.topologySpreadConstraints[{i}].maxSkew: Invalid value: {n}: must be greater than zero"));
        }
        if let Some(n) = t.get("minDomains").and_then(Value::as_i64).filter(|n| *n < 1) {
            out.push(format!("{prefix}.topologySpreadConstraints[{i}].minDomains: Invalid value: {n}: must be greater than zero"));
        }
        if let Some(sel) = t.get("labelSelector") {
            selector_errors(sel, &format!("{prefix}.topologySpreadConstraints[{i}].labelSelector"), out);
        }
    }
    for (i, t) in spec.get("tolerations").and_then(Value::as_array).unwrap_or(&[]).iter().enumerate() {
        let (op, key, val) = (t.get("operator").and_then(Value::as_str).unwrap_or(""), t.get("key").and_then(Value::as_str).unwrap_or(""), t.get("value").and_then(Value::as_str).unwrap_or(""));
        if op == "Exists" && !val.is_empty() {
            out.push(format!("{prefix}.tolerations[{i}].operator: Invalid value: \"Exists\": value must be empty when `operator` is 'Exists'"));
        }
        if key.is_empty() && !matches!(op, "Exists") {
            out.push(format!("{prefix}.tolerations[{i}].operator: Invalid value: \"{op}\": operator must be Exists when `key` is empty"));
        }
        if !matches!(op, "" | "Exists" | "Equal") {
            out.push(format!("{prefix}.tolerations[{i}].operator: Unsupported value: \"{op}\": supported values: \"Equal\", \"Exists\""));
        }
    }
    for (i, h) in spec.get("hostAliases").and_then(Value::as_array).unwrap_or(&[]).iter().enumerate() {
        if let Some(ip) = h.get("ip").and_then(Value::as_str).filter(|ip| crate::object::parse_ipv4(ip).is_none() && kr_net::tcp::parse_ip16(ip).is_none()) {
            out.push(format!("{prefix}.hostAliases[{i}].ip: Invalid value: \"{ip}\": must be a valid IP address"));
        }
    }
    if let Some(dc) = spec.get("dnsConfig") {
        let ns = dc.get("nameservers").and_then(Value::as_array).unwrap_or(&[]);
        if ns.len() > 3 {
            out.push(format!("{prefix}.dnsConfig.nameservers: Invalid value: {}: must not have more than 3 nameservers", ns.len()));
        }
        for (i, n) in ns.iter().filter_map(Value::as_str).enumerate() {
            if kr_net::tcp::parse_ip16(n).is_none() {
                out.push(format!("{prefix}.dnsConfig.nameservers[{i}]: Invalid value: \"{n}\": must be a valid IP address"));
            }
        }
        if dc.get("searches").and_then(Value::as_array).is_some_and(|a| a.len() > 32) {
            out.push(format!("{prefix}.dnsConfig.searches: Invalid value: must not have more than 32 search paths"));
        }
    }
    if let Some(ns) = spec.get("nodeSelector").and_then(Value::as_object) {
        for (k, v) in ns {
            if !crate::object::is_qualified_key(k) || v.as_str().is_some_and(|v| !crate::object::is_label_value(v)) {
                out.push(format!("{prefix}.nodeSelector: Invalid value: \"{k}\": not a valid label"));
            }
        }
    }
    for (f, min) in [("runAsUser", 0), ("runAsGroup", 0), ("fsGroup", 0)] {
        if let Some(n) = spec.pointer(&["securityContext", f]).and_then(Value::as_i64).filter(|n| *n < min) {
            out.push(format!("{prefix}.securityContext.{f}: Invalid value: {n}: must be greater than or equal to {min}"));
        }
    }
    for (i, t) in spec.pointer(&["affinity", "nodeAffinity", "preferredDuringSchedulingIgnoredDuringExecution"]).and_then(Value::as_array).unwrap_or(&[]).iter().enumerate() {
        weight_error(t, &format!("{prefix}.affinity.nodeAffinity.preferredDuringSchedulingIgnoredDuringExecution[{i}]"), out);
    }
    for kind in ["podAffinity", "podAntiAffinity"] {
        for (i, t) in spec.pointer(&["affinity", kind, "preferredDuringSchedulingIgnoredDuringExecution"]).and_then(Value::as_array).unwrap_or(&[]).iter().enumerate() {
            weight_error(t, &format!("{prefix}.affinity.{kind}.preferredDuringSchedulingIgnoredDuringExecution[{i}]"), out);
        }
    }
    for list in ["initContainers", "containers", "ephemeralContainers", "volumes"] {
        let items = spec.get(list).and_then(Value::as_array).unwrap_or(&[]);
        let mut seen: Vec<&str> = Vec::new();
        for (i, it) in items.iter().enumerate() {
            let Some(n) = it.get("name").and_then(Value::as_str).filter(|n| !n.is_empty()) else { continue };
            if !dns_label(n) {
                out.push(format!("{prefix}.{list}[{i}].name: Invalid value: \"{n}\": a lowercase RFC 1123 label must consist of lower case alphanumeric characters or '-', and must start and end with an alphanumeric character"));
            }
            if seen.contains(&n) {
                out.push(format!("{prefix}.{list}[{i}].name: Duplicate value: \"{n}\""));
            }
            seen.push(n);
        }
    }
}

fn label_match(sel: &Value, labels: &Value) -> bool {
    let get = |k: &str| labels.get(k).and_then(Value::as_str);
    for (k, want) in sel.get("matchLabels").and_then(Value::as_object).unwrap_or(&[]) {
        if get(k) != want.as_str() {
            return false;
        }
    }
    for e in sel.get("matchExpressions").and_then(Value::as_array).unwrap_or(&[]) {
        let key = e.get("key").and_then(Value::as_str).unwrap_or("");
        let vals: Vec<&str> = e.get("values").and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(Value::as_str).collect();
        let ok = match e.get("operator").and_then(Value::as_str).unwrap_or("") {
            "In" => get(key).is_some_and(|x| vals.contains(&x)),
            "NotIn" => get(key).is_none_or(|x| !vals.contains(&x)),
            "Exists" => get(key).is_some(),
            "DoesNotExist" => get(key).is_none(),
            _ => true,
        };
        if !ok {
            return false;
        }
    }
    true
}

fn selector_errors(sel: &Value, path: &str, out: &mut Vec<String>) {
    for (k, v) in sel.get("matchLabels").and_then(Value::as_object).unwrap_or(&[]) {
        if !crate::object::is_qualified_key(k) {
            out.push(format!("{path}.matchLabels: Invalid value: \"{k}\": name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character"));
        }
        if let Some(v) = v.as_str().filter(|v| !crate::object::is_label_value(v)) {
            out.push(format!("{path}.matchLabels: Invalid value: \"{v}\": a valid label must be an empty string or consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character"));
        }
    }
    for (i, e) in sel.get("matchExpressions").and_then(Value::as_array).unwrap_or(&[]).iter().enumerate() {
        if let Some(k) = e.get("key").and_then(Value::as_str).filter(|k| !crate::object::is_qualified_key(k)) {
            out.push(format!("{path}.matchExpressions[{i}].key: Invalid value: \"{k}\": name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character"));
        }
        for v in e.get("values").and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(Value::as_str).filter(|v| !crate::object::is_label_value(v)) {
            out.push(format!("{path}.matchExpressions[{i}].values: Invalid value: \"{v}\": a valid label must be an empty string or consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character"));
        }
    }
    for (i, e) in sel.get("matchExpressions").and_then(Value::as_array).unwrap_or(&[]).iter().enumerate() {
        let n = e.get("values").and_then(Value::as_array).map_or(0, |a| a.len());
        match e.get("operator").and_then(Value::as_str).unwrap_or("") {
            "In" | "NotIn" if n == 0 => out.push(format!("{path}.matchExpressions[{i}].values: Required value: must be specified when `operator` is 'In' or 'NotIn'")),
            "Exists" | "DoesNotExist" if n > 0 => out.push(format!("{path}.matchExpressions[{i}].values: Forbidden: may not be specified when `operator` is 'Exists' or 'DoesNotExist'")),
            "In" | "NotIn" | "Exists" | "DoesNotExist" => {}
            "" => {}
            op => out.push(format!("{path}.matchExpressions[{i}].operator: Invalid value: \"{op}\": not a valid selector operator")),
        }
    }
}

/// Rules that look at several fields: workload selectors against template labels, selector
/// expressions, Service port naming, a pod's containers.
fn cross_field(api_version: &str, kind: &str, v: &Value, out: &mut Vec<String>) {
    let Some(spec) = v.get("spec") else { return };
    match (api_version, kind) {
        ("apps/v1", "Deployment" | "ReplicaSet" | "StatefulSet" | "DaemonSet") => {
            match spec.get("selector") {
                None | Some(Value::Null) => out.push(String::from("spec.selector: Required value")),
                Some(sel) => {
                    selector_errors(sel, "spec.selector", out);
                    let empty = sel.get("matchLabels").and_then(Value::as_object).is_none_or(|m| m.is_empty()) && sel.get("matchExpressions").and_then(Value::as_array).is_none_or(|m| m.is_empty());
                    if empty {
                        out.push(String::from("spec.selector: Invalid value: empty selector is invalid for this kind"));
                    } else if !label_match(sel, spec.pointer(&["template", "metadata", "labels"]).unwrap_or(&Value::Null)) {
                        out.push(format!("spec.template.metadata.labels: Invalid value: {}: `selector` does not match template `labels`", kr_fmt::json::to_string(spec.pointer(&["template", "metadata", "labels"]).unwrap_or(&Value::Null))));
                    }
                }
            }
        }
        ("v1", "Pod") => {
            if spec.get("containers").and_then(Value::as_array).is_none_or(|c| c.is_empty()) {
                out.push(String::from("spec.containers: Required value"));
            }
        }
        ("v1", "Service") => {
            let ports = spec.get("ports").and_then(Value::as_array).unwrap_or(&[]);
            let mut names: Vec<&str> = Vec::new();
            let mut pairs: Vec<(String, String)> = Vec::new();
            for (i, p) in ports.iter().enumerate() {
                let name = p.get("name").and_then(Value::as_str).unwrap_or("");
                if ports.len() > 1 && name.is_empty() {
                    out.push(format!("spec.ports[{i}].name: Required value"));
                } else if !name.is_empty() {
                    if !dns_label(name) {
                        out.push(format!("spec.ports[{i}].name: Invalid value: \"{name}\": a lowercase RFC 1123 label must consist of lower case alphanumeric characters or '-', and must start and end with an alphanumeric character"));
                    }
                    if names.contains(&name) {
                        out.push(format!("spec.ports[{i}].name: Duplicate value: \"{name}\""));
                    }
                    names.push(name);
                }
                let pair = (p.get("port").map(|x| kr_fmt::json::to_string(x)).unwrap_or_default(), p.get("protocol").and_then(Value::as_str).unwrap_or("TCP").to_string());
                if pairs.contains(&pair) {
                    out.push(format!("spec.ports[{i}]: Duplicate value: {{\"port\":{},\"protocol\":\"{}\"}}", pair.0, pair.1));
                }
                pairs.push(pair);
            }
        }
        _ => {}
    }
    // Any selector in the usual places.
    for path in [&["selector"][..], &["podSelector"], &["namespaceSelector"], &["objectSelector"]] {
        if let Some(sel @ Value::Object(_)) = spec.pointer(path) {
            if sel.get("matchExpressions").is_some() {
                selector_errors(sel, &format!("spec.{}", path[0]), out);
            }
        }
    }
}

fn dns_subdomain(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty() && b.len() <= 253 && n.split('.').all(dns_label_part)
}

fn dns_label_part(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty() && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-') && b[0] != b'-' && b[b.len() - 1] != b'-'
}

fn weight_error(term: &Value, path: &str, out: &mut Vec<String>) {
    if let Some(w) = term.get("weight").and_then(Value::as_i64).filter(|w| !(1..=100).contains(w)) {
        out.push(format!("{path}.weight: Invalid value: {w}: must be in the range 1-100"));
    }
}

/// Exactly one of `kinds` must be set (probes, lifecycle handlers).
fn handler_errors(h: &Value, path: &str, kinds: &[&str], out: &mut Vec<String>) {
    let n = kinds.iter().filter(|k| h.get(k).is_some_and(|x| !x.is_null())).count();
    if n == 0 {
        out.push(format!("{path}: Required value: must specify a handler type"));
    } else if n > 1 {
        out.push(format!("{path}: Forbidden: may not specify more than 1 handler type"));
    }
}
