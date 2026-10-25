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
    matches!(idx, s::M_TIME | s::M_MICRO_TIME | s::M_DURATION | s::M_FIELDS_V1 | s::M_INT_OR_STRING | s::M_QUANTITY | s::M_RAW_EXTENSION)
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
        s::M_RAW_EXTENSION | s::M_FIELDS_V1 => return None,
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
