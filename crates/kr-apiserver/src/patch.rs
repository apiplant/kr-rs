//! PATCH semantics: JSON Merge Patch (RFC 7386), JSON Patch (RFC 6902) and Kubernetes
//! strategic merge patch (the subset `kubectl apply`/`edit`/`patch` produce).
//!
//! Strategic merge needs per-field list strategies that upstream reads from Go struct tags. kr
//! has no generated types, so the list merge keys for the built-in kinds are in a table keyed
//! by field name (and, for `ports`, by whether we are inside a container). Lists not in the
//! table are replaced, which is also upstream's default.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_fmt::json::Value;

#[derive(Debug, PartialEq, Eq)]
pub struct PatchError(pub String);

fn err<T>(m: &str) -> Result<T, PatchError> {
    Err(PatchError(m.to_string()))
}

// ---------------------------------------------------------------- RFC 7386

pub fn merge_patch(target: &mut Value, patch: &Value) {
    match patch {
        Value::Object(fields) => {
            if !matches!(target, Value::Object(_)) {
                *target = Value::Object(Vec::new());
            }
            for (k, v) in fields {
                if v.is_null() {
                    target.remove(k);
                } else {
                    let mut cur = target.remove(k).unwrap_or(Value::Null);
                    merge_patch(&mut cur, v);
                    target.set(k, cur);
                }
            }
        }
        other => *target = other.clone(),
    }
}

// ---------------------------------------------------------------- RFC 6902

/// Decodes an RFC 6901 pointer into reference tokens.
fn pointer_tokens(p: &str) -> Result<Vec<String>, PatchError> {
    if p.is_empty() {
        return Ok(Vec::new());
    }
    let Some(rest) = p.strip_prefix('/') else { return err("JSON pointer must start with '/'") };
    rest.split('/')
        .map(|t| {
            let b = t.as_bytes();
            if b.iter().enumerate().any(|(i, &c)| c == b'~' && !matches!(b.get(i + 1), Some(b'0' | b'1'))) {
                return err("bad ~ escape in JSON pointer");
            }
            Ok(t.replace("~1", "/").replace("~0", "~"))
        })
        .collect()
}

fn array_index(tok: &str, len: usize, allow_end: bool) -> Result<usize, PatchError> {
    if tok == "-" && allow_end {
        return Ok(len);
    }
    if tok.is_empty() || (tok.len() > 1 && tok.starts_with('0')) || !tok.bytes().all(|b| b.is_ascii_digit()) {
        return err("bad array index");
    }
    let i: usize = tok.parse().map_err(|_| PatchError("bad array index".into()))?;
    if i > len || (i == len && !allow_end) {
        return err("array index out of range");
    }
    Ok(i)
}

fn resolve_mut<'a>(doc: &'a mut Value, toks: &[String]) -> Result<&'a mut Value, PatchError> {
    let mut cur = doc;
    for t in toks {
        cur = match cur {
            Value::Object(_) => cur.get_mut(t).ok_or_else(|| PatchError(alloc::format!("path not found: {t}")))?,
            Value::Array(a) => {
                let i = array_index(t, a.len(), false)?;
                &mut a[i]
            }
            _ => return err("path traverses a scalar"),
        };
    }
    Ok(cur)
}

fn op_add(doc: &mut Value, toks: &[String], v: Value) -> Result<(), PatchError> {
    let Some((last, parent)) = toks.split_last() else {
        *doc = v;
        return Ok(());
    };
    match resolve_mut(doc, parent)? {
        o @ Value::Object(_) => {
            o.set(last, v);
            Ok(())
        }
        Value::Array(a) => {
            let i = array_index(last, a.len(), true)?;
            a.insert(i, v);
            Ok(())
        }
        _ => err("add target parent is a scalar"),
    }
}

fn op_remove(doc: &mut Value, toks: &[String]) -> Result<Value, PatchError> {
    let Some((last, parent)) = toks.split_last() else { return err("cannot remove the root") };
    match resolve_mut(doc, parent)? {
        o @ Value::Object(_) => o.remove(last).ok_or_else(|| PatchError("remove: path not found".into())),
        Value::Array(a) => {
            let i = array_index(last, a.len(), false)?;
            Ok(a.remove(i))
        }
        _ => err("remove target parent is a scalar"),
    }
}

pub fn json_patch(doc: &mut Value, ops: &Value) -> Result<(), PatchError> {
    let Some(ops) = ops.as_array() else { return err("JSON patch must be an array") };
    if ops.len() > 10_000 {
        return err("too many patch operations");
    }
    for op in ops {
        let name = op.get("op").and_then(Value::as_str).ok_or_else(|| PatchError("op missing".into()))?;
        let path = pointer_tokens(op.get("path").and_then(Value::as_str).ok_or_else(|| PatchError("path missing".into()))?)?;
        let value = || op.get("value").cloned().ok_or_else(|| PatchError("value missing".into()));
        let from = || -> Result<Vec<String>, PatchError> { pointer_tokens(op.get("from").and_then(Value::as_str).ok_or_else(|| PatchError("from missing".into()))?) };
        match name {
            "add" => op_add(doc, &path, value()?)?,
            "remove" => {
                op_remove(doc, &path)?;
            }
            "replace" => {
                let v = value()?;
                *resolve_mut(doc, &path)? = v;
            }
            "move" => {
                let f = from()?;
                if path.len() > f.len() && path[..f.len()] == f[..] {
                    return err("cannot move a value into itself");
                }
                let v = op_remove(doc, &f)?;
                op_add(doc, &path, v)?;
            }
            "copy" => {
                let v = resolve_mut(doc, &from()?)?.clone();
                op_add(doc, &path, v)?;
            }
            "test" => {
                if *resolve_mut(doc, &path)? != value()? {
                    return err("test operation failed");
                }
            }
            _ => return err("unknown op"),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- strategic merge

const CONTAINER_LISTS: &[&str] = &["containers", "initContainers", "ephemeralContainers"];

/// Merge key for a list field, given the field names on the path to it.
pub(crate) fn merge_key(path: &[&str], field: &str) -> Option<&'static str> {
    Some(match field {
        "containers" | "initContainers" | "ephemeralContainers" | "env" | "volumes" | "imagePullSecrets" | "resourceClaims" | "schedulingGates" | "secrets" => "name",
        "ports" if path.iter().any(|p| CONTAINER_LISTS.contains(p)) => "containerPort",
        "ports" => "port",
        "volumeMounts" => "mountPath",
        "volumeDevices" => "devicePath",
        "hostAliases" => "ip",
        "conditions" | "addresses" => "type",
        "ownerReferences" => "uid",
        "taints" => "key",
        "topologySpreadConstraints" => "topologyKey",
        "readinessGates" => "conditionType",
        _ => return None,
    })
}

/// Primitive lists with merge (set union) semantics.
pub(crate) fn primitive_merge(field: &str) -> bool {
    field == "finalizers"
}

fn key_of<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v.get(key)
}

/// Applies a strategic merge patch to `target` (a JSON object).
pub fn strategic_merge(target: &mut Value, patch: &Value) -> Result<(), PatchError> {
    let mut path = Vec::new();
    smp_map(target, patch, &mut path)
}

fn smp_map<'p>(target: &mut Value, patch: &'p Value, path: &mut Vec<&'p str>) -> Result<(), PatchError> {
    let Some(fields) = patch.as_object() else { return err("strategic merge patch must be an object") };
    match patch.get("$patch").and_then(Value::as_str) {
        Some("replace") => {
            let mut p = patch.clone();
            p.remove("$patch");
            *target = p;
            return Ok(());
        }
        Some("delete") => {
            *target = Value::Null;
            return Ok(());
        }
        Some(_) => return err("unknown $patch directive"),
        None => {}
    }
    if !matches!(target, Value::Object(_)) {
        *target = Value::Object(Vec::new());
    }
    for (k, v) in fields {
        if k == "$patch" || k == "$retainKeys" || k.starts_with("$setElementOrder/") || k.starts_with("$deleteFromPrimitiveList/") {
            continue;
        }
        if v.is_null() {
            target.remove(k);
            continue;
        }
        let mut cur = target.remove(k).unwrap_or(Value::Null);
        match v {
            Value::Object(_) => {
                path.push(k);
                smp_map(&mut cur, v, path)?;
                path.pop();
                if cur.is_null() {
                    continue; // $patch: delete on a map
                }
            }
            Value::Array(items) => {
                if let Some(mk) = merge_key(path, k) {
                    path.push(k);
                    smp_list(&mut cur, items, mk, path)?;
                    path.pop();
                } else if primitive_merge(k) {
                    let mut list = cur.as_array().map(|a| a.to_vec()).unwrap_or_default();
                    for it in items {
                        if !list.contains(it) {
                            list.push(it.clone());
                        }
                    }
                    cur = Value::Array(list);
                } else {
                    cur = v.clone();
                }
            }
            _ => cur = v.clone(),
        }
        target.set(k, cur);
    }
    // Directives that refer to sibling fields, applied after the merge.
    for (k, v) in fields {
        if let Some(field) = k.strip_prefix("$deleteFromPrimitiveList/") {
            let del = v.as_array().unwrap_or(&[]);
            if let Some(Value::Array(a)) = target.get_mut(field) {
                a.retain(|x| !del.contains(x));
            }
        } else if let Some(field) = k.strip_prefix("$setElementOrder/") {
            let Some(order) = v.as_array() else { continue };
            let mk = merge_key(path, field);
            if let Some(Value::Array(a)) = target.get_mut(field) {
                reorder(a, order, mk);
            }
        }
    }
    if let Some(keep) = patch.get("$retainKeys").and_then(Value::as_array) {
        let keep: Vec<&str> = keep.iter().filter_map(Value::as_str).collect();
        if let Some(o) = target.as_object_mut() {
            o.retain(|(k, _)| keep.contains(&k.as_str()));
        }
    }
    Ok(())
}

fn smp_list<'p>(cur: &mut Value, items: &'p [Value], mk: &str, path: &mut Vec<&'p str>) -> Result<(), PatchError> {
    if items.iter().any(|i| i.get("$patch").and_then(Value::as_str) == Some("replace")) {
        *cur = Value::Array(items.iter().filter(|i| i.get("$patch").is_none()).cloned().collect());
        return Ok(());
    }
    let mut list = cur.as_array().map(|a| a.to_vec()).unwrap_or_default();
    for it in items {
        let Some(key) = key_of(it, mk) else {
            if it.as_object().is_some() {
                return err("list element is missing its merge key");
            }
            list.push(it.clone());
            continue;
        };
        let pos = list.iter().position(|e| key_of(e, mk) == Some(key));
        if it.get("$patch").and_then(Value::as_str) == Some("delete") {
            if let Some(i) = pos {
                list.remove(i);
            }
            continue;
        }
        match pos {
            Some(i) => {
                let mut e = core::mem::replace(&mut list[i], Value::Null);
                smp_map(&mut e, it, path)?;
                list[i] = e;
            }
            None => {
                let mut e = Value::Object(Vec::new());
                smp_map(&mut e, it, path)?;
                list.push(e);
            }
        }
    }
    *cur = Value::Array(list);
    Ok(())
}

/// Orders `list` like `order` (by merge key, or by value for primitives); others keep their
/// relative order at the end.
fn reorder(list: &mut Vec<Value>, order: &[Value], mk: Option<&str>) {
    let ident = |v: &Value| -> Option<Value> {
        match mk {
            Some(k) => v.get(k).cloned(),
            None => Some(v.clone()),
        }
    };
    let mut out = Vec::with_capacity(list.len());
    for o in order {
        let want = ident(o);
        if let Some(i) = list.iter().position(|e| ident(e) == want) {
            out.push(list.remove(i));
        }
    }
    out.append(list);
    *list = out;
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_fmt::json::{parse_str, to_string};

    fn j(s: &str) -> Value {
        parse_str(s).unwrap()
    }

    #[test]
    fn rfc7386_examples() {
        let mut t = j(r#"{"a":"b","c":{"d":"e","f":"g"}}"#);
        merge_patch(&mut t, &j(r#"{"a":"z","c":{"f":null}}"#));
        assert_eq!(t, j(r#"{"a":"z","c":{"d":"e"}}"#));
        let mut t = j(r#"{"a":[{"b":"c"}]}"#);
        merge_patch(&mut t, &j(r#"{"a":[1]}"#));
        assert_eq!(t, j(r#"{"a":[1]}"#));
    }

    #[test]
    fn rfc6902_ops() {
        let mut d = j(r#"{"foo":["bar","baz"],"a/b":1,"m~n":2}"#);
        json_patch(
            &mut d,
            &j(r#"[{"op":"add","path":"/foo/1","value":"qux"},{"op":"remove","path":"/foo/0"},{"op":"replace","path":"/a~1b","value":3},
                   {"op":"copy","from":"/m~0n","path":"/x"},{"op":"move","from":"/x","path":"/y"},{"op":"add","path":"/foo/-","value":"end"},
                   {"op":"test","path":"/y","value":2}]"#),
        )
        .unwrap();
        assert_eq!(d, j(r#"{"foo":["qux","baz","end"],"a/b":3,"m~n":2,"y":2}"#));
        assert!(json_patch(&mut d, &j(r#"[{"op":"test","path":"/y","value":3}]"#)).is_err());
        assert!(json_patch(&mut d, &j(r#"[{"op":"remove","path":"/foo/9"}]"#)).is_err());
        assert!(json_patch(&mut d, &j(r#"[{"op":"move","from":"/foo","path":"/foo/0"}]"#)).is_err());
        assert!(json_patch(&mut d, &j(r#"[{"op":"add","path":"/foo/01","value":1}]"#)).is_err());
    }

    #[test]
    fn strategic_containers_and_ports() {
        let mut d = j(r#"{"spec":{"template":{"spec":{"containers":[
            {"name":"web","image":"nginx:1","ports":[{"containerPort":80,"name":"http"}],"env":[{"name":"A","value":"1"}]},
            {"name":"side","image":"busybox"}]}}}}"#);
        // What `kubectl apply` sends after changing web's image and adding a port + env, deleting side.
        let p = j(r#"{"spec":{"template":{"spec":{
            "$setElementOrder/containers":[{"name":"web"}],
            "containers":[{"name":"web","image":"nginx:2","ports":[{"containerPort":443}],"env":[{"name":"B","value":"2"}]},
                          {"name":"side","$patch":"delete"}]}}}}"#);
        strategic_merge(&mut d, &p).unwrap();
        let c = d.pointer(&["spec", "template", "spec", "containers"]).unwrap().as_array().unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].get("image").unwrap().as_str(), Some("nginx:2"));
        assert_eq!(c[0].get("ports").unwrap().as_array().unwrap().len(), 2);
        assert_eq!(c[0].get("env").unwrap().as_array().unwrap().len(), 2);
    }

    #[test]
    fn strategic_service_ports_use_port_key() {
        let mut d = j(r#"{"spec":{"ports":[{"port":80,"targetPort":8080}]}}"#);
        strategic_merge(&mut d, &j(r#"{"spec":{"ports":[{"port":80,"targetPort":9090},{"port":443}]}}"#)).unwrap();
        assert_eq!(to_string(&d), r#"{"spec":{"ports":[{"port":80,"targetPort":9090},{"port":443}]}}"#);
    }

    #[test]
    fn strategic_directives() {
        let mut d = j(r#"{"metadata":{"finalizers":["a","b"],"labels":{"x":"1","y":"2"}},"spec":{"strategy":{"type":"RollingUpdate","rollingUpdate":{"maxSurge":1}}}}"#);
        let p = j(r#"{"metadata":{"$deleteFromPrimitiveList/finalizers":["a"],"finalizers":["c"],"labels":{"y":null}},
                     "spec":{"strategy":{"$retainKeys":["type"],"type":"Recreate"}}}"#);
        strategic_merge(&mut d, &p).unwrap();
        assert_eq!(to_string(&d), r#"{"metadata":{"finalizers":["b","c"],"labels":{"x":"1"}},"spec":{"strategy":{"type":"Recreate"}}}"#);
        // $patch: replace on a map and on a list
        let mut d = j(r#"{"data":{"a":"1","b":"2"},"spec":{"containers":[{"name":"a"},{"name":"b"}]}}"#);
        strategic_merge(&mut d, &j(r#"{"data":{"$patch":"replace","c":"3"},"spec":{"containers":[{"name":"z"},{"$patch":"replace"}]}}"#)).unwrap();
        assert_eq!(to_string(&d), r#"{"data":{"c":"3"},"spec":{"containers":[{"name":"z"}]}}"#);
    }
}
