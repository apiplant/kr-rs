//! Server-side apply: `metadata.managedFields` bookkeeping in the style of upstream's
//! structured-merge-diff, scoped to what kubectl and the conformance suite use.
//!
//! A field set is a `FieldsV1` tree: `f:name` for map/struct fields, `k:{...}` for elements of
//! associative lists, `v:<json>` for set elements and `.` for "the node itself". A node
//! without children is a leaf. Atomic lists and scalars are leaves.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_fmt::json::{self, Value};

/// How a list is merged and owned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListKind {
    Atomic,
    Map(Vec<String>),
    Set,
    /// Not a list: an object marked `x-kubernetes-map-type: atomic`, owned and replaced as one field.
    AtomicMap,
}

/// Looks up the kind of the list at a field-name path (the list's own name is last).
pub type Lists<'a> = &'a dyn Fn(&[&str]) -> ListKind;

/// List kinds of the built-in types, from the strategic merge patch tables.
pub fn builtin_lists(path: &[&str]) -> ListKind {
    let Some((field, parent)) = path.split_last() else { return ListKind::Atomic };
    if let Some(k) = crate::patch::merge_key(parent, field) {
        let mut keys = alloc::vec![k.to_string()];
        if *field == "ports" {
            keys.push("protocol".to_string());
        }
        keys.sort();
        ListKind::Map(keys)
    } else if crate::patch::primitive_merge(field) {
        ListKind::Set
    } else {
        ListKind::Atomic
    }
}

/// List kinds from a CRD's openAPI schema (`x-kubernetes-list-type`).
pub fn schema_lists(schema: &Value, path: &[&str]) -> ListKind {
    let mut s = schema;
    for name in path {
        if let Some(i) = s.get("items") {
            s = i;
        }
        s = match s.get("properties").and_then(|p| p.get(name)).or_else(|| s.get("additionalProperties").filter(|a| a.as_object().is_some())) {
            Some(n) => n,
            None => return ListKind::Atomic,
        };
    }
    if s.get("x-kubernetes-map-type").and_then(Value::as_str) == Some("atomic") {
        return ListKind::AtomicMap;
    }
    match s.get("x-kubernetes-list-type").and_then(Value::as_str) {
        Some("map") => {
            let mut keys: Vec<String> = s.get("x-kubernetes-list-map-keys").and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
            keys.sort();
            if keys.is_empty() {
                ListKind::Atomic
            } else {
                ListKind::Map(keys)
            }
        }
        Some("set") => ListKind::Set,
        _ => ListKind::Atomic,
    }
}

/// Which top-level `status` handling applies to a write.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scope {
    /// Everything but `status` (the main resource of a kind that has a status subresource).
    NoStatus,
    /// Only `status`.
    StatusOnly,
    All,
}

const IGNORED_META: &[&str] = &["name", "namespace", "uid", "creationTimestamp", "resourceVersion", "generation", "selfLink", "managedFields", "deletionTimestamp", "deletionGracePeriodSeconds"];

fn empty() -> Value {
    Value::Object(Vec::new())
}

fn is_empty(v: &Value) -> bool {
    v.as_object().is_some_and(|o| o.is_empty())
}

/// The key object (`{"name":"c"}`) identifying a map-list element.
fn item_key(item: &Value, keys: &[String]) -> Option<Value> {
    let mut o = Vec::new();
    for k in keys {
        let v = match item.get(k) {
            Some(v) => v.clone(),
            None if k == "protocol" => Value::from("TCP"),
            None => return None,
        };
        o.push((k.clone(), v));
    }
    Some(Value::Object(o))
}

fn key_matches(item: &Value, key: &Value) -> bool {
    key.as_object().is_some_and(|ks| {
        ks.iter().all(|(k, v)| match item.get(k) {
            Some(x) => x == v,
            None => k == "protocol" && v.as_str() == Some("TCP"),
        })
    })
}

/// The fields of `v` that differ from `old` (all of them when `old` is None).
pub fn fields(v: &Value, old: Option<&Value>, lists: Lists, scope: Scope) -> Value {
    let mut names = Vec::new();
    walk(v, old, &mut names, lists, scope).unwrap_or_else(empty)
}

fn walk(v: &Value, old: Option<&Value>, names: &mut Vec<String>, lists: Lists, scope: Scope) -> Option<Value> {
    match v {
        Value::Object(fs) if !fs.is_empty() => {
            if !names.is_empty() {
                let nm: Vec<&str> = names.iter().map(String::as_str).collect();
                if lists(&nm) == ListKind::AtomicMap {
                    return (old != Some(v)).then(empty);
                }
            }
            let mut out = Vec::new();
            for (k, c) in fs {
                if names.is_empty() {
                    match scope {
                        Scope::NoStatus if k == "status" => continue,
                        Scope::StatusOnly if k != "status" => continue,
                        _ => {}
                    }
                }
                if names.len() == 1 && names[0] == "metadata" && IGNORED_META.contains(&k.as_str()) {
                    continue;
                }
                names.push(k.clone());
                let sub = walk(c, old.and_then(|o| o.get(k)), names, lists, scope);
                names.pop();
                if let Some(s) = sub {
                    out.push((alloc::format!("f:{k}"), s));
                }
            }
            (!out.is_empty()).then_some(Value::Object(out))
        }
        Value::Array(items) => {
            let nm: Vec<&str> = names.iter().map(String::as_str).collect();
            match lists(&nm) {
                ListKind::Atomic | ListKind::AtomicMap => (old != Some(v)).then(empty),
                ListKind::Set => {
                    let prev = old.and_then(Value::as_array).unwrap_or(&[]);
                    let out: Vec<(String, Value)> = items.iter().filter(|i| !prev.contains(i)).map(|i| (alloc::format!("v:{}", json::to_string(i)), empty())).collect();
                    (!out.is_empty()).then_some(Value::Object(out))
                }
                ListKind::Map(keys) => {
                    let prev = old.and_then(Value::as_array).unwrap_or(&[]);
                    let mut out = Vec::new();
                    for it in items {
                        let Some(key) = item_key(it, &keys) else { continue };
                        let before = prev.iter().find(|p| key_matches(p, &key));
                        let mut node = Vec::new();
                        if before.is_none() {
                            node.push((".".to_string(), empty()));
                        }
                        if it.as_object().is_some_and(|o| !o.is_empty()) {
                            if let Some(Value::Object(cs)) = walk(it, before, names, lists, scope) {
                                node.extend(cs);
                            }
                        }
                        if !node.is_empty() {
                            out.push((alloc::format!("k:{}", json::to_string(&key)), Value::Object(node)));
                        }
                    }
                    (!out.is_empty()).then_some(Value::Object(out))
                }
            }
        }
        // Empty maps and scalars are leaves.
        _ => (old != Some(v)).then(empty),
    }
}

/// `a` plus everything in `b`.
pub fn union(a: &Value, b: &Value) -> Value {
    let mut out: Vec<(String, Value)> = a.as_object().map(|o| o.to_vec()).unwrap_or_default();
    for (k, bc) in b.as_object().unwrap_or(&[]) {
        match out.iter_mut().find(|(ak, _)| ak == k) {
            Some((_, ac)) => *ac = union(ac, bc),
            None => out.push((k.clone(), bc.clone())),
        }
    }
    Value::Object(out)
}

/// `a` without the fields in `b` (a leaf in `b` removes the whole subtree of `a`).
pub fn difference(a: &Value, b: &Value) -> Value {
    let mut out = Vec::new();
    for (k, ac) in a.as_object().unwrap_or(&[]) {
        match b.get(k) {
            None => out.push((k.clone(), ac.clone())),
            Some(bc) if is_empty(bc) => {}
            Some(_) if is_empty(ac) => out.push((k.clone(), ac.clone())),
            Some(bc) => {
                let d = difference(ac, bc);
                if !is_empty(&d) {
                    out.push((k.clone(), d));
                }
            }
        }
    }
    Value::Object(out)
}

/// The child of `obj` addressed by one set key.
fn child<'a>(obj: &'a Value, key: &str) -> Option<&'a Value> {
    if let Some(f) = key.strip_prefix("f:") {
        obj.get(f)
    } else if let Some(k) = key.strip_prefix("k:") {
        let kv = json::parse_str(k).ok()?;
        obj.as_array()?.iter().find(|i| key_matches(i, &kv))
    } else if let Some(v) = key.strip_prefix("v:") {
        let want = json::parse_str(v).ok()?;
        obj.as_array()?.iter().find(|i| **i == want)
    } else {
        None
    }
}

fn resolve<'a>(obj: &'a Value, path: &[String]) -> Option<&'a Value> {
    let mut cur = obj;
    for k in path {
        if k == "." {
            continue;
        }
        cur = child(cur, k)?;
    }
    Some(cur)
}

/// Drops the parts of `set` that no longer exist in `obj`.
pub fn prune(set: &Value, obj: &Value) -> Value {
    let mut out = Vec::new();
    for (k, c) in set.as_object().unwrap_or(&[]) {
        if k == "." {
            out.push((k.clone(), c.clone()));
            continue;
        }
        let Some(o) = child(obj, k) else { continue };
        if is_empty(c) {
            out.push((k.clone(), c.clone()));
        } else {
            let p = prune(c, o);
            if !is_empty(&p) {
                out.push((k.clone(), p));
            }
        }
    }
    Value::Object(out)
}

/// All leaf paths of a set.
pub fn leaves(set: &Value) -> Vec<Vec<String>> {
    fn go(s: &Value, pre: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
        for (k, c) in s.as_object().unwrap_or(&[]) {
            pre.push(k.clone());
            if is_empty(c) {
                out.push(pre.clone());
            } else {
                go(c, pre, out);
            }
            pre.pop();
        }
    }
    let mut out = Vec::new();
    go(set, &mut Vec::new(), &mut out);
    out
}

fn contains(set: &Value, path: &[String]) -> bool {
    let mut cur = set;
    for k in path {
        match cur.get(k) {
            Some(c) => cur = c,
            None => return false,
        }
    }
    true
}

fn insert_path(set: &mut Value, path: &[String]) {
    let Some((k, rest)) = path.split_first() else { return };
    if set.get(k).is_none() {
        set.set(k, empty());
    }
    insert_path(set.get_mut(k).unwrap(), rest);
}

/// Human path as in upstream conflict messages: `.spec.containers[name="c"].image`.
pub fn path_string(path: &[String]) -> String {
    let mut s = String::new();
    for k in path {
        if let Some(f) = k.strip_prefix("f:") {
            s.push('.');
            s.push_str(f);
        } else if let Some(kv) = k.strip_prefix("k:") {
            s.push('[');
            if let Ok(Value::Object(o)) = json::parse_str(kv) {
                let parts: Vec<String> = o.iter().map(|(n, v)| alloc::format!("{n}={}", json::to_string(v))).collect();
                s.push_str(&parts.join(","));
            }
            s.push(']');
        } else if let Some(v) = k.strip_prefix("v:") {
            s.push_str(&alloc::format!("[={v}]"));
        }
    }
    if s.is_empty() {
        s.push('.');
    }
    s
}

// ---------------------------------------------------------------- entries

#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub manager: String,
    pub apply: bool,
    pub api_version: String,
    pub time: String,
    pub subresource: String,
    pub fields: Value,
}

impl Entry {
    fn same_identity(&self, manager: &str, apply: bool, sub: &str) -> bool {
        self.manager == manager && self.apply == apply && self.subresource == sub
    }

    pub fn to_value(&self) -> Value {
        let mut o = empty();
        o.set("manager", Value::from(self.manager.as_str()));
        o.set("operation", Value::from(if self.apply { "Apply" } else { "Update" }));
        o.set("apiVersion", Value::from(self.api_version.as_str()));
        if !self.time.is_empty() {
            o.set("time", Value::from(self.time.as_str()));
        }
        o.set("fieldsType", Value::from("FieldsV1"));
        o.set("fieldsV1", self.fields.clone());
        if !self.subresource.is_empty() {
            o.set("subresource", Value::from(self.subresource.as_str()));
        }
        o
    }
}

/// Parses stored `metadata.managedFields` (entries that do not parse are dropped).
pub fn parse_entries(mf: Option<&Value>) -> Vec<Entry> {
    let mut out = Vec::new();
    for e in mf.and_then(Value::as_array).unwrap_or(&[]) {
        let s = |k: &str| e.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let Some(fields) = e.get("fieldsV1").filter(|f| f.as_object().is_some()) else { continue };
        out.push(Entry { manager: s("manager"), apply: e.get("operation").and_then(Value::as_str) == Some("Apply"), api_version: s("apiVersion"), time: s("time"), subresource: s("subresource"), fields: fields.clone() });
    }
    out
}

/// Validates client-sent `metadata.managedFields` (the content is otherwise ignored).
pub fn validate_client(mf: &Value) -> Result<(), String> {
    let Some(items) = mf.as_array() else { return Err("metadata.managedFields: Invalid value: must be a list".to_string()) };
    for (i, e) in items.iter().enumerate() {
        let bad = |m: &str| Err(alloc::format!("metadata.managedFields[{i}]: Invalid value: {m}"));
        if e.as_object().is_none() {
            return bad("must be an object");
        }
        if is_empty(e) {
            continue; // `[{}]` is the reset idiom
        }
        if e.get("manager").and_then(Value::as_str).is_none_or(str::is_empty) {
            return bad("manager must be non-empty");
        }
        if !matches!(e.get("operation").and_then(Value::as_str), Some("Apply" | "Update")) {
            return bad("operation must be Apply or Update");
        }
        if e.get("fieldsType").is_some_and(|t| t.as_str() != Some("FieldsV1")) {
            return bad("fieldsType must be FieldsV1");
        }
        if e.get("fieldsV1").is_some_and(|f| f.as_object().is_none()) {
            return bad("fieldsV1 must be an object");
        }
        for k in ["apiVersion", "time", "subresource"] {
            if e.get(k).is_some_and(|v| !v.is_null() && v.as_str().is_none()) {
                return bad(&alloc::format!("{k} must be a string"));
            }
        }
    }
    Ok(())
}

/// True for the `[]` / `[{}]` reset requests.
pub fn is_reset(mf: &Value) -> bool {
    mf.as_array().is_some_and(|a| a.is_empty() || (a.len() == 1 && is_empty(&a[0])))
}

/// `obj` without what changes on a rewrite that alters nothing: `resourceVersion` and the
/// managedFields timestamps, with map keys in sorted order (rewrites may reorder them).
pub fn comparable(obj: &Value) -> Value {
    fn sorted(v: &Value) -> Value {
        match v {
            Value::Object(fs) => {
                let mut out: Vec<(String, Value)> = fs.iter().map(|(k, c)| (k.clone(), sorted(c))).collect();
                out.sort_by(|a, b| a.0.cmp(&b.0));
                Value::Object(out)
            }
            Value::Array(a) => Value::Array(a.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    let mut o = obj.clone();
    if let Some(m) = o.get_mut("metadata") {
        m.remove("resourceVersion");
        if let Some(Value::Array(mf)) = m.get_mut("managedFields") {
            for e in mf.iter_mut() {
                e.remove("time");
            }
        }
    }
    sorted(&o)
}

/// Records an Update by `manager`: it owns `changed`, everyone else loses it.
pub fn record_update(entries: &mut Vec<Entry>, changed: &Value, manager: &str, sub: &str, api_version: &str, now: &str) {
    if is_empty(changed) {
        return;
    }
    for e in entries.iter_mut() {
        if !e.same_identity(manager, false, sub) {
            e.fields = difference(&e.fields, changed);
        }
    }
    match entries.iter_mut().find(|e| e.same_identity(manager, false, sub)) {
        Some(e) => {
            e.fields = union(&e.fields, changed);
            e.api_version = api_version.to_string();
            e.time = now.to_string();
        }
        None => entries.push(Entry { manager: manager.to_string(), apply: false, api_version: api_version.to_string(), time: now.to_string(), subresource: sub.to_string(), fields: changed.clone() }),
    }
}

/// Writes `entries` (pruned against `obj`, empty ones dropped) into `obj.metadata.managedFields`.
pub fn store(obj: &mut Value, mut entries: Vec<Entry>) {
    for e in entries.iter_mut() {
        e.fields = prune(&e.fields, obj);
    }
    entries.retain(|e| !is_empty(&e.fields));
    let meta = obj.entry_object("metadata");
    if entries.is_empty() {
        meta.remove("managedFields");
    } else {
        meta.set("managedFields", Value::Array(entries.iter().map(Entry::to_value).collect()));
    }
}

// ---------------------------------------------------------------- apply

/// Merges the applied configuration into `target` with list-type aware semantics.
fn merge(target: &mut Value, applied: &Value, names: &mut Vec<String>, lists: Lists) {
    match applied {
        Value::Object(fs) => {
            if !names.is_empty() {
                let nm: Vec<&str> = names.iter().map(String::as_str).collect();
                if lists(&nm) == ListKind::AtomicMap {
                    *target = applied.clone();
                    return;
                }
            }
            if !matches!(target, Value::Object(_)) {
                *target = empty();
            }
            for (k, v) in fs {
                if v.is_null() {
                    target.remove(k);
                    continue;
                }
                let mut cur = target.remove(k).unwrap_or(Value::Null);
                names.push(k.clone());
                merge(&mut cur, v, names, lists);
                names.pop();
                target.set(k, cur);
            }
        }
        Value::Array(items) => {
            let nm: Vec<&str> = names.iter().map(String::as_str).collect();
            let kind = lists(&nm);
            if matches!(kind, ListKind::Atomic | ListKind::AtomicMap) {
                *target = applied.clone();
                return;
            }
            let mut list = target.as_array().map(<[Value]>::to_vec).unwrap_or_default();
            for it in items {
                match &kind {
                    ListKind::Set => {
                        if !list.contains(it) {
                            list.push(it.clone());
                        }
                    }
                    ListKind::Map(keys) => {
                        let Some(key) = item_key(it, keys) else {
                            list.push(it.clone());
                            continue;
                        };
                        match list.iter().position(|e| key_matches(e, &key)) {
                            Some(i) => {
                                let mut e = core::mem::replace(&mut list[i], Value::Null);
                                merge(&mut e, it, names, lists);
                                list[i] = e;
                            }
                            None => {
                                let mut e = empty();
                                merge(&mut e, it, names, lists);
                                list.push(e);
                            }
                        }
                    }
                    ListKind::Atomic | ListKind::AtomicMap => {}
                }
            }
            *target = Value::Array(list);
        }
        other => *target = other.clone(),
    }
}

/// Removes the value at `path`; returns true when `obj` is left an empty map (so its parent
/// should drop it).
fn remove_at(obj: &mut Value, path: &[String]) -> bool {
    let Some((k, rest)) = path.split_first() else { return false };
    if k == "." {
        return false;
    }
    if let Some(f) = k.strip_prefix("f:") {
        if rest.is_empty() {
            obj.remove(f);
        } else {
            let gone = match obj.get_mut(f) {
                Some(c) => remove_at(c, rest),
                None => return false,
            };
            if gone {
                obj.remove(f);
            }
        }
        return obj.as_object().is_some_and(|o| o.is_empty());
    }
    // A list element addressed by k:/v:.
    let Some(arr) = obj.as_array() else { return false };
    let pos = if let Some(kk) = k.strip_prefix("k:") {
        json::parse_str(kk).ok().and_then(|kv| arr.iter().position(|i| key_matches(i, &kv)))
    } else if let Some(v) = k.strip_prefix("v:") {
        json::parse_str(v).ok().and_then(|want| arr.iter().position(|i| *i == want))
    } else {
        None
    };
    let Some(pos) = pos else { return false };
    if rest.is_empty() || (rest.len() == 1 && rest[0] == ".") {
        obj.as_array_mut().unwrap().remove(pos);
    } else if let Some(el) = obj.as_array_mut().unwrap().get_mut(pos) {
        remove_at(el, rest);
    }
    false
}

#[derive(Debug)]
pub struct Applied {
    pub object: Value,
    pub entries: Vec<Entry>,
    /// The manager's field set (what the apply owns).
    pub owned: Value,
}

/// The fields a fresh apply of `applied` owns.
pub fn applied_fields(applied: &Value, lists: Lists, scope: Scope) -> Value {
    fields(applied, None, lists, scope)
}

/// Applies `applied` (the manager's full intent) on top of `live`.
#[allow(clippy::too_many_arguments)]
pub fn apply(live: &Value, applied: &Value, mut entries: Vec<Entry>, manager: &str, force: bool, api_version: &str, now: &str, lists: Lists, scope: Scope) -> Result<Applied, String> {
    let sa = applied_fields(applied, lists, scope);
    let own = |e: &Entry| e.apply && e.manager == manager;
    // Conflicts with other managers: shared fields whose live value differs from the applied one.
    let mut report: Vec<(String, String, Vec<String>)> = Vec::new();
    let mut taken: Vec<Value> = Vec::new();
    for e in entries.iter() {
        let mut conf = empty();
        let mut paths = Vec::new();
        if !own(e) {
            for l in leaves(&sa) {
                if l.last().is_some_and(|k| k == ".") || !contains(&e.fields, &l) {
                    continue;
                }
                if resolve(live, &l) != resolve(applied, &l) {
                    paths.push(path_string(&l));
                    insert_path(&mut conf, &l);
                }
            }
        }
        if !paths.is_empty() {
            match report.iter_mut().find(|r| r.0 == e.manager && r.1 == e.api_version) {
                Some(r) => r.2.extend(paths),
                None => report.push((e.manager.clone(), e.api_version.clone(), paths)),
            }
        }
        taken.push(conf);
    }
    if !report.is_empty() && !force {
        let n: usize = report.iter().map(|r| r.2.len()).sum();
        let parts: Vec<String> = report
            .iter()
            .map(|(m, v, ps)| if ps.len() == 1 { alloc::format!("conflict with \"{m}\" using {v}: {}", ps[0]) } else { alloc::format!("conflicts with \"{m}\" using {v}:\n- {}", ps.join("\n- ")) })
            .collect();
        return Err(alloc::format!("Apply failed with {n} conflict{}: {}", if n == 1 { "" } else { "s" }, parts.join("\n")));
    }
    for (e, t) in entries.iter_mut().zip(&taken) {
        e.fields = difference(&e.fields, t);
    }
    // Fields this manager applied before and now omits are removed unless somebody else owns them.
    let mut object = live.clone();
    let prev = entries.iter().find(|e| own(e)).map(|e| e.fields.clone()).unwrap_or_else(empty);
    for l in leaves(&prev) {
        if contains(&sa, &l) || entries.iter().any(|e| !own(e) && contains(&e.fields, &l)) {
            continue;
        }
        remove_at(&mut object, &l);
    }
    merge(&mut object, applied, &mut Vec::new(), lists);
    entries.retain(|e| !own(e));
    entries.push(Entry { manager: manager.to_string(), apply: true, api_version: api_version.to_string(), time: now.to_string(), subresource: String::new(), fields: sa.clone() });
    Ok(Applied { object, entries, owned: sa })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_fmt::json::{parse_str, to_string};

    fn j(s: &str) -> Value {
        parse_str(s).unwrap()
    }

    fn f(v: &str) -> String {
        to_string(&fields(&j(v), None, &builtin_lists, Scope::All))
    }

    #[test]
    fn maps_and_scalars() {
        assert_eq!(f(r#"{"metadata":{"name":"x","labels":{"app":"a"}},"spec":{"replicas":2}}"#), r#"{"f:metadata":{"f:labels":{"f:app":{}}},"f:spec":{"f:replicas":{}}}"#);
    }

    #[test]
    fn keyed_and_atomic_lists() {
        let s = f(r#"{"spec":{"containers":[{"name":"c","image":"i","ports":[{"containerPort":80}],"args":["a"]}]}}"#);
        assert_eq!(s, r#"{"f:spec":{"f:containers":{"k:{\"name\":\"c\"}":{".":{},"f:name":{},"f:image":{},"f:ports":{"k:{\"containerPort\":80,\"protocol\":\"TCP\"}":{".":{},"f:containerPort":{}}},"f:args":{}}}}}"#);
    }

    #[test]
    fn set_lists_and_diff() {
        let old = j(r#"{"metadata":{"finalizers":["a"]},"spec":{"replicas":1,"paused":false}}"#);
        let new = j(r#"{"metadata":{"finalizers":["a","b"]},"spec":{"replicas":2,"paused":false}}"#);
        let d = fields(&new, Some(&old), &builtin_lists, Scope::All);
        assert_eq!(to_string(&d), r#"{"f:metadata":{"f:finalizers":{"v:\"b\"":{}}},"f:spec":{"f:replicas":{}}}"#);
    }

    #[test]
    fn crd_schema_lists() {
        let s = j(r#"{"properties":{"spec":{"properties":{"l":{"type":"array","x-kubernetes-list-type":"map","x-kubernetes-list-map-keys":["id"],"items":{"properties":{"sub":{"type":"array","x-kubernetes-list-type":"set"}}}}}}}}"#);
        assert_eq!(schema_lists(&s, &["spec", "l"]), ListKind::Map(alloc::vec!["id".to_string()]));
        assert_eq!(schema_lists(&s, &["spec", "l", "sub"]), ListKind::Set);
        assert_eq!(schema_lists(&s, &["spec", "zz"]), ListKind::Atomic);
    }

    #[test]
    fn ownership_transfers_on_update() {
        let mut e = Vec::new();
        record_update(&mut e, &j(r#"{"f:spec":{"f:replicas":{},"f:paused":{}}}"#), "a", "", "v1", "t");
        record_update(&mut e, &j(r#"{"f:spec":{"f:replicas":{}}}"#), "b", "", "v1", "t");
        record_update(&mut e, &j(r#"{"f:spec":{"f:x":{}}}"#), "a", "", "v1", "t");
        assert_eq!(e.len(), 2);
        assert_eq!(to_string(&e[0].fields), r#"{"f:spec":{"f:paused":{},"f:x":{}}}"#);
        assert_eq!(to_string(&e[1].fields), r#"{"f:spec":{"f:replicas":{}}}"#);
    }

    fn ap(live: &Value, a: &str, entries: Vec<Entry>, m: &str, force: bool) -> Result<Applied, String> {
        apply(live, &j(a), entries, m, force, "v1", "t", &builtin_lists, Scope::All)
    }

    #[test]
    fn apply_removes_dropped_fields_and_conflicts() {
        let live = j(r#"{"metadata":{"labels":{"a":"1","b":"2"}},"spec":{"replicas":1}}"#);
        let r = ap(&live, r#"{"metadata":{"labels":{"a":"1","b":"2"}},"spec":{"replicas":1}}"#, Vec::new(), "m1", false).unwrap();
        let r2 = ap(&r.object, r#"{"metadata":{"labels":{"a":"1"}}}"#, r.entries.clone(), "m1", false).unwrap();
        assert_eq!(to_string(&r2.object), r#"{"metadata":{"labels":{"a":"1"}}}"#);
        // Another manager owns replicas with a different value.
        let mut e = r.entries.clone();
        record_update(&mut e, &j(r#"{"f:spec":{"f:replicas":{}}}"#), "other", "scale", "apps/v1", "t");
        let mut live = r.object.clone();
        live.entry_object("spec").set("replicas", Value::from(5i64));
        let err = ap(&live, r#"{"spec":{"replicas":3}}"#, e.clone(), "m1", false).unwrap_err();
        assert_eq!(err, r#"Apply failed with 1 conflict: conflict with "other" using apps/v1: .spec.replicas"#);
        let ok = ap(&live, r#"{"spec":{"replicas":3}}"#, e.clone(), "m1", true).unwrap();
        assert_eq!(ok.object.pointer(&["spec", "replicas"]).and_then(Value::as_i64), Some(3));
        assert!(is_empty(&ok.entries.iter().find(|x| x.manager == "other").unwrap().fields));
        // Dropping a field another manager also owns keeps the value.
        let mut e2 = r.entries.clone();
        record_update(&mut e2, &j(r#"{"f:spec":{"f:replicas":{}}}"#), "m2", "", "v1", "t");
        let r3 = ap(&r.object, r#"{"metadata":{"labels":{"a":"1","b":"2"}}}"#, e2, "m1", false).unwrap();
        assert_eq!(r3.object.pointer(&["spec", "replicas"]).and_then(Value::as_i64), Some(1));
    }

    #[test]
    fn apply_merges_keyed_lists_and_removes_items() {
        let live = j(r#"{"spec":{"containers":[{"name":"x","image":"old"}]}}"#);
        let r = ap(&live, r#"{"spec":{"containers":[{"name":"c","image":"i"}]}}"#, Vec::new(), "m", false).unwrap();
        assert_eq!(r.object.pointer(&["spec", "containers"]).unwrap().as_array().unwrap().len(), 2);
        let r2 = ap(&r.object, r#"{"spec":{"containers":[{"name":"d","image":"j"}]}}"#, r.entries, "m", false).unwrap();
        let names: Vec<&str> = r2.object.pointer(&["spec", "containers"]).unwrap().as_array().unwrap().iter().filter_map(|c| c.get("name").and_then(Value::as_str)).collect();
        assert_eq!(names, ["x", "d"]);
    }
}
