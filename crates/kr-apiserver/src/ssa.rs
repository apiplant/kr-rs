//! Server-side apply: `metadata.managedFields` bookkeeping in the style of upstream's
//! structured-merge-diff, scoped to what kubectl and the conformance suite use.
//!
//! A field set is a `FieldsV1` tree: `f:name` for map/struct fields, `k:{...}` for elements of
//! associative lists, `v:<json>` for set elements and `.` for "the node itself". A node
//! without children is a leaf. Atomic lists and scalars are leaves.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use crate::proto_schema as ps;
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

/// Fields of the built-in types that are atomic structs or maps (`+structType=atomic`,
/// `+mapType=atomic`): LabelSelector and NodeSelector values, object references, the env
/// source selectors, a Service's `selector`, a pod's `nodeSelector`. Owned and replaced as one.
const ATOMIC_STRUCTS: &[&str] = &[
    "selector", "labelSelector", "namespaceSelector", "podSelector", "objectSelector", "nodeSelector", "preference",
    "fieldRef", "resourceFieldRef", "secretKeyRef", "configMapKeyRef", "fileKeyRef",
    "requiredDuringSchedulingIgnoredDuringExecution", "scaleTargetRef", "claimRef", "dataSource", "dataSourceRef", "involvedObject", "regarding", "related",
];

const CONTAINER_LISTS: &[&str] = &["containers", "initContainers", "ephemeralContainers"];

/// Name based fallback for built-in kinds without generated tables ([`generated_lists`] serves the rest).
/// List kinds of the built-in types, following the upstream OpenAPI markers
/// (`+listType`, `+listMapKey`, `+mapType`, `+structType`) for the common fields. The strategic
/// merge tables are only the starting point: they disagree with upstream for NetworkPolicy and
/// EndpointSlice `ports`, node `taints`, `readinessGates`, namespace `spec.finalizers` and
/// `topologySpreadConstraints` keys.
pub fn builtin_lists(path: &[&str]) -> ListKind {
    let Some((field, parent)) = path.split_last() else { return ListKind::Atomic };
    if ATOMIC_STRUCTS.contains(field) {
        return ListKind::AtomicMap;
    }
    let map = |keys: &[&str]| {
        let mut k: Vec<String> = keys.iter().map(|s| s.to_string()).collect();
        k.sort();
        ListKind::Map(k)
    };
    let last = parent.last().copied().unwrap_or("");
    match *field {
        // metadata.finalizers is a set; Namespace spec.finalizers is atomic.
        "finalizers" if last == "metadata" => ListKind::Set,
        "finalizers" => ListKind::Atomic,
        // Unsure: upstream marks these without a listType, so they are atomic.
        "taints" | "readinessGates" => ListKind::Atomic,
        "topologySpreadConstraints" => map(&["topologyKey", "whenUnsatisfiable"]),
        "podIPs" | "hostIPs" => map(&["ip"]),
        "claims" => map(&["name"]),
        // Service.spec.ports (port+protocol); NetworkPolicy and Endpoints ports are atomic.
        "ports" if parent.iter().any(|p| CONTAINER_LISTS.contains(p)) => map(&["containerPort", "protocol"]),
        "ports" if last == "spec" => map(&["port", "protocol"]),
        "ports" => ListKind::Atomic,
        // Node status addresses are keyed by type; EndpointSlice endpoint addresses are a set.
        "addresses" if last == "status" => map(&["type"]),
        "addresses" if last == "endpoints" => ListKind::Set,
        "addresses" => ListKind::Atomic,
        f => match crate::patch::merge_key(parent, f) {
            Some(k) => map(&[k]),
            None => ListKind::Atomic,
        },
    }
}

/// Message index of the top-level kind `kind` of `api_version` (`v1`, `apps/v1`, ...) in the
/// generated tables.
pub fn root_message(api_version: &str, kind: &str) -> Option<u16> {
    ps::KINDS.iter().find(|k| k.0 == api_version && k.1 == kind).map(|k| k.2)
}

fn field_name(f: &ps::Field) -> &'static str {
    &ps::NAMES[f.name_off as usize..f.name_off as usize + f.name_len as usize]
}

/// The field `name` of message `m`, looking through inlined (embedded) messages; with the message
/// that declares it.
fn find_field(m: u16, name: &str) -> Option<(u16, &'static ps::Field)> {
    for f in &ps::FIELDS[ps::MSG_START[m as usize] as usize..ps::MSG_START[m as usize + 1] as usize] {
        if f.kind & ps::F_INLINE != 0 {
            if let Some(r) = find_field(f.arg, name) {
                return Some(r);
            }
        } else if field_name(f) == name {
            return Some((m, f));
        }
    }
    None
}

/// List kinds of a built-in type from the generated tables (`tools/gen_k8s_proto_schema.py`, from
/// the upstream `+listType` / `+listMapKey` / `+mapType` / `+structType` markers, i.e. the data
/// behind upstream's OpenAPI `x-kubernetes-*` extensions). `root` is [`root_message`]; `path`
/// the field names from the object (map keys count as names, list items as their list's name).
/// An unknown field is atomic.
pub fn generated_lists(root: u16, path: &[&str]) -> ListKind {
    enum Cur {
        Msg(u16),
        /// A map field: the next name is a key; the values are this message, if any.
        Map(Option<u16>),
        End,
    }
    let mut cur = Cur::Msg(root);
    let mut last = None;
    for name in path {
        match cur {
            Cur::Msg(m) => {
                let Some((owner, f)) = find_field(m, name) else { return ListKind::Atomic };
                last = Some((owner, f.num));
                cur = match f.kind & ps::K_MASK {
                    ps::K_MESSAGE => Cur::Msg(f.arg),
                    ps::K_MAP => {
                        let (_, _, vk, va) = ps::MAPS[f.arg as usize];
                        Cur::Map((vk & ps::K_MASK == ps::K_MESSAGE).then_some(va))
                    }
                    _ => Cur::End,
                };
            }
            Cur::Map(v) => {
                last = None;
                cur = v.map_or(Cur::End, Cur::Msg);
            }
            Cur::End => return ListKind::Atomic,
        }
    }
    let Some(key) = last else { return ListKind::Atomic };
    match ps::LISTS.binary_search_by(|e| (e.0, e.1).cmp(&key)) {
        Ok(i) => match ps::LISTS[i].2 {
            1 => ListKind::Map(ps::LISTS[i].3.split(',').map(String::from).collect()),
            2 => ListKind::Set,
            _ => ListKind::AtomicMap,
        },
        Err(_) => ListKind::Atomic,
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
            // A key property with a `default` has it when an item omits it (`name=<json>`).
            let item = s.get("items");
            for k in keys.iter_mut() {
                if let Some(d) = item.and_then(|i| i.get("properties")).and_then(|p| p.get(k.as_str())).and_then(|p| p.get("default")) {
                    *k = alloc::format!("{k}={}", json::to_string(d));
                }
            }
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

/// A list-map key as `name` or `name=<json default>`.
fn key_spec(k: &str) -> (&str, Option<Value>) {
    match k.split_once('=') {
        Some((n, d)) => (n, json::parse_str(d).ok()),
        None => (k, None),
    }
}

/// The key object (`{"name":"c"}`) identifying a map-list element; a key the item omits takes
/// its schema default (`protocol` is `TCP` where no default is known).
fn item_key(item: &Value, keys: &[String]) -> Option<Value> {
    let mut o = Vec::new();
    for k in keys {
        let (name, def) = key_spec(k);
        let v = match item.get(name) {
            Some(v) => v.clone(),
            None => match def {
                Some(d) => d,
                None if name == "protocol" => Value::from("TCP"),
                None => return None,
            },
        };
        o.push((name.to_string(), v));
    }
    Some(Value::Object(o))
}

fn key_matches(item: &Value, key: &Value) -> bool {
    key.as_object().is_some_and(|ks| {
        ks.iter().all(|(k, v)| match item.get(k) {
            Some(x) => x == v,
            None => (k == "protocol" && v.as_str() == Some("TCP")) || v.as_str() == Some(""),
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
            for (i, (k, c)) in fs.iter().enumerate() {
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
                let sub = walk(c, old.and_then(|o| o.get_hinted(k, i)), names, lists, scope);
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
                // An empty set or keyed list is a value like any empty collection: owned as a leaf.
                ListKind::Set | ListKind::Map(_) if items.is_empty() => (old != Some(v)).then(empty),
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
                        let before = prev.iter().find(|p| item_key(p, &keys).as_ref() == Some(&key));
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

/// Keys in byte order at every level, as Go renders the field sets (clients that decode the
/// object into a map and encode it again must get the same bytes).
fn sort_keys(v: &Value) -> Value {
    match v {
        Value::Object(f) => {
            let mut f: Vec<(String, Value)> = f.iter().map(|(k, v)| (k.clone(), sort_keys(v))).collect();
            f.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(f)
        }
        v => v.clone(),
    }
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
        o.set("fieldsV1", sort_keys(&self.fields));
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
                        match list.iter().position(|e| item_key(e, keys).as_ref() == Some(&key)) {
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
                // An empty set or keyed list changes none of the items others own.
                if resolve(applied, &l).and_then(Value::as_array).is_some_and(<[Value]>::is_empty) {
                    let nm: Vec<&str> = l.iter().filter_map(|k| k.strip_prefix("f:")).collect();
                    if matches!(lists(&nm), ListKind::Set | ListKind::Map(_)) {
                        continue;
                    }
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
        // Key fields go with their item; an item stays while another manager owns part of it.
        if let Some(pk) = l.len().checked_sub(2).and_then(|i| l[i].strip_prefix("k:")) {
            let is_key = l.last().and_then(|x| x.strip_prefix("f:")).is_some_and(|n| json::parse_str(pk).ok().is_some_and(|k| k.get(n).is_some()));
            if is_key {
                continue;
            }
        }
        if l.last().is_some_and(|k| k == ".") && entries.iter().any(|e| !own(e) && contains(&e.fields, &l[..l.len() - 1])) {
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
    fn builtin_atomic_structs() {
        assert_eq!(builtin_lists(&["spec", "selector"]), ListKind::AtomicMap);
        assert_eq!(builtin_lists(&["spec", "template", "spec", "containers", "env", "valueFrom", "secretKeyRef"]), ListKind::AtomicMap);
        let a = j(r#"{"spec":{"selector":{"matchLabels":{"a":"1"}}}}"#);
        let fs = fields(&a, None, &builtin_lists, Scope::All);
        assert_eq!(json::to_string(&fs), r#"{"f:spec":{"f:selector":{}}}"#);
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
    fn apply_merges_webhooks_by_name() {
        // cainjector applies a sparse webhook object carrying only `clientConfig.caBundle`;
        // the rest of the entry (rules, sideEffects, service) must survive.
        let live = j(r#"{"webhooks":[{"name":"w","rules":[{"apiGroups":["x"]}],"sideEffects":"None","clientConfig":{"service":{"name":"s"}}}]}"#);
        let r = ap(&live, r#"{"webhooks":[{"name":"w","clientConfig":{"caBundle":"abc"}}]}"#, Vec::new(), "m", false).unwrap();
        let w = r.object.pointer(&["webhooks"]).unwrap().as_array().unwrap()[0].clone();
        assert_eq!(w.get("sideEffects").and_then(Value::as_str), Some("None"));
        assert_eq!(w.pointer(&["clientConfig", "service", "name"]).and_then(Value::as_str), Some("s"));
        assert_eq!(w.pointer(&["clientConfig", "caBundle"]).and_then(Value::as_str), Some("abc"));
        assert_eq!(w.get("rules").and_then(Value::as_array).map(|a| a.len()), Some(1));
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

    fn crd_lists(schema: &'static Value) -> impl Fn(&[&str]) -> ListKind {
        move |p| schema_lists(schema, p)
    }

    #[test]
    fn two_managers_env_vars_and_removal() {
        let live = j(r#"{"spec":{"containers":[{"name":"c","image":"i"}]}}"#);
        let a = ap(&live, r#"{"spec":{"containers":[{"name":"c","image":"i","env":[{"name":"A","value":"1"}]}]}}"#, Vec::new(), "m1", false).unwrap();
        let b = ap(&a.object, r#"{"spec":{"containers":[{"name":"c","env":[{"name":"B","value":"2"}]}]}}"#, a.entries, "m2", false).unwrap();
        let env = b.object.pointer(&["spec", "containers"]).unwrap().as_array().unwrap()[0].get("env").unwrap().as_array().unwrap().len();
        assert_eq!(env, 2);
        let m2 = b.entries.iter().find(|e| e.manager == "m2").unwrap();
        assert_eq!(to_string(&sort_keys(&m2.fields)), r#"{"f:spec":{"f:containers":{"k:{\"name\":\"c\"}":{".":{},"f:env":{"k:{\"name\":\"B\"}":{".":{},"f:name":{},"f:value":{}}},"f:name":{}}}}}"#);
        // m1 drops its env var: only A goes, B and the container stay.
        let c = ap(&b.object, r#"{"spec":{"containers":[{"name":"c","image":"i"}]}}"#, b.entries.clone(), "m1", false).unwrap();
        let ct = c.object.pointer(&["spec", "containers"]).unwrap().as_array().unwrap()[0].clone();
        let env = ct.get("env").unwrap().as_array().unwrap();
        assert_eq!(env.len(), 1);
        assert_eq!(env[0].get("name").and_then(Value::as_str), Some("B"));
        // Same env var, different value: conflict, then force takes it.
        let err = ap(&c.object, r#"{"spec":{"containers":[{"name":"c","env":[{"name":"B","value":"9"}]}]}}"#, c.entries.clone(), "m1", false).unwrap_err();
        assert!(err.contains(r#"conflict with "m2" using v1: .spec.containers[name="c"].env[name="B"].value"#), "{err}");
        let f = ap(&c.object, r#"{"spec":{"containers":[{"name":"c","env":[{"name":"B","value":"9"}]}]}}"#, c.entries, "m1", true).unwrap();
        assert!(f.entries.iter().find(|e| e.manager == "m2").is_none_or(|e| !contains(&e.fields, &["f:spec".to_string(), "f:containers".to_string(), "k:{\"name\":\"c\"}".to_string(), "f:env".to_string(), "k:{\"name\":\"B\"}".to_string(), "f:value".to_string()])));
    }

    #[test]
    fn atomic_list_change_and_finalizer_sets() {
        let live = j(r#"{"spec":{"tolerations":[{"key":"a"}]}}"#);
        let a = ap(&live, r#"{"spec":{"tolerations":[{"key":"a"}]}}"#, Vec::new(), "m1", false).unwrap();
        assert_eq!(to_string(&a.owned), r#"{"f:spec":{"f:tolerations":{}}}"#);
        // m2 replaces the whole atomic list: conflict, forced replace.
        assert!(ap(&a.object, r#"{"spec":{"tolerations":[{"key":"b"}]}}"#, a.entries.clone(), "m2", false).is_err());
        let b = ap(&a.object, r#"{"spec":{"tolerations":[{"key":"b"}]}}"#, a.entries, "m2", true).unwrap();
        assert_eq!(to_string(b.object.pointer(&["spec", "tolerations"]).unwrap()), r#"[{"key":"b"}]"#);
        // finalizers: each manager owns its own values.
        let f1 = ap(&j("{}"), r#"{"metadata":{"finalizers":["x"]}}"#, Vec::new(), "m1", false).unwrap();
        let f2 = ap(&f1.object, r#"{"metadata":{"finalizers":["y"]}}"#, f1.entries, "m2", false).unwrap();
        assert_eq!(to_string(f2.object.pointer(&["metadata", "finalizers"]).unwrap()), r#"["x","y"]"#);
        assert_eq!(to_string(&f2.entries.iter().find(|e| e.manager == "m2").unwrap().fields), r#"{"f:metadata":{"f:finalizers":{"v:\"y\"":{}}}}"#);
        let f3 = ap(&f2.object, r#"{"metadata":{"finalizers":[]}}"#, f2.entries, "m2", false).unwrap();
        assert_eq!(to_string(f3.object.pointer(&["metadata", "finalizers"]).unwrap()), r#"["x"]"#);
        // Namespace spec.finalizers is atomic; NetworkPolicy ports are atomic, Service ports keyed.
        assert_eq!(builtin_lists(&["spec", "finalizers"]), ListKind::Atomic);
        assert_eq!(builtin_lists(&["spec", "ingress", "ports"]), ListKind::Atomic);
        assert_eq!(builtin_lists(&["spec", "ports"]), ListKind::Map(alloc::vec!["port".to_string(), "protocol".to_string()]));
    }

    #[test]
    fn crd_list_map_two_managers() {
        let schema: &'static Value = alloc::boxed::Box::leak(alloc::boxed::Box::new(j(r#"{"properties":{"spec":{"properties":{"items":{"type":"array","x-kubernetes-list-type":"map","x-kubernetes-list-map-keys":["id"],"items":{"properties":{"cfg":{"type":"object","x-kubernetes-map-type":"atomic"}}}},"tags":{"type":"array","x-kubernetes-list-type":"set"}}}}}"#)));
        let l = crd_lists(schema);
        let run = |live: &Value, a: &str, e: Vec<Entry>, m: &str| apply(live, &j(a), e, m, false, "v1", "t", &l, Scope::All);
        let a = run(&j("{}"), r#"{"spec":{"items":[{"id":"1","cfg":{"a":1}}],"tags":["x"]}}"#, Vec::new(), "m1").unwrap();
        assert_eq!(to_string(&a.owned), r#"{"f:spec":{"f:items":{"k:{\"id\":\"1\"}":{".":{},"f:id":{},"f:cfg":{}}},"f:tags":{"v:\"x\"":{}}}}"#);
        let b = run(&a.object, r#"{"spec":{"items":[{"id":"2"}],"tags":["y"]}}"#, a.entries, "m2").unwrap();
        assert_eq!(b.object.pointer(&["spec", "items"]).unwrap().as_array().unwrap().len(), 2);
        assert_eq!(b.object.pointer(&["spec", "tags"]).unwrap().as_array().unwrap().len(), 2);
        // m2 drops item 2: only its item is removed.
        let c = run(&b.object, r#"{"spec":{"tags":["y"]}}"#, b.entries, "m2").unwrap();
        assert_eq!(c.object.pointer(&["spec", "items"]).unwrap().as_array().unwrap().len(), 1);
        // The atomic cfg conflicts as a whole.
        assert!(run(&c.object, r#"{"spec":{"items":[{"id":"1","cfg":{"b":2}}]}}"#, c.entries, "m2").is_err());
    }

    fn gen(av: &str, kind: &str, path: &[&str]) -> ListKind {
        generated_lists(root_message(av, kind).unwrap_or_else(|| panic!("no kind {kind}")), path)
    }

    fn keys(k: &[&str]) -> ListKind {
        ListKind::Map(k.iter().map(|s| s.to_string()).collect())
    }

    /// The generated table agrees with the markers in k8s.io/api v0.37.0 (the source of upstream's
    /// OpenAPI `x-kubernetes-list-type`, `x-kubernetes-list-map-keys`, `x-kubernetes-map-type`).
    #[test]
    fn generated_lists_follow_the_upstream_markers() {
        let pod = |p: &[&str]| gen("v1", "Pod", p);
        // The fields #146 was unsure about.
        assert_eq!(pod(&["spec", "containers", "envFrom"]), ListKind::Atomic);
        assert_eq!(pod(&["spec", "containers", "envFrom", "secretRef"]), ListKind::Atomic, "granular struct, not an atomic one");
        assert_eq!(pod(&["spec", "containers", "envFrom", "configMapRef"]), ListKind::Atomic);
        assert_eq!(gen("apps/v1", "StatefulSet", &["spec", "volumeClaimTemplates"]), ListKind::Atomic);
        assert_eq!(pod(&["spec", "containers", "env", "valueFrom", "secretKeyRef"]), ListKind::AtomicMap);
        assert_eq!(pod(&["spec", "containers", "env", "valueFrom", "configMapKeyRef"]), ListKind::AtomicMap);
        // Keyed and set lists.
        assert_eq!(pod(&["spec", "containers"]), keys(&["name"]));
        assert_eq!(pod(&["spec", "initContainers", "env"]), keys(&["name"]));
        assert_eq!(pod(&["spec", "containers", "ports"]), keys(&["containerPort", "protocol=\"TCP\""]));
        assert_eq!(pod(&["spec", "containers", "volumeMounts"]), keys(&["mountPath"]));
        assert_eq!(pod(&["spec", "volumes"]), keys(&["name"]));
        assert_eq!(pod(&["spec", "imagePullSecrets"]), keys(&["name=\"\""]));
        assert_eq!(pod(&["spec", "topologySpreadConstraints"]), keys(&["topologyKey", "whenUnsatisfiable"]));
        assert_eq!(pod(&["status", "conditions"]), keys(&["type"]));
        assert_eq!(pod(&["status", "podIPs"]), keys(&["ip"]));
        assert_eq!(pod(&["metadata", "finalizers"]), ListKind::Set);
        assert_eq!(pod(&["metadata", "ownerReferences"]), keys(&["uid"]));
        // Atomic lists and maps.
        assert_eq!(pod(&["spec", "tolerations"]), ListKind::Atomic);
        assert_eq!(pod(&["spec", "readinessGates"]), ListKind::Atomic);
        assert_eq!(pod(&["spec", "nodeSelector"]), ListKind::AtomicMap);
        assert_eq!(pod(&["metadata", "labels"]), ListKind::Atomic);
        assert_eq!(pod(&["metadata", "labels", "app"]), ListKind::Atomic);
        assert_eq!(pod(&["spec", "affinity", "nodeAffinity", "requiredDuringSchedulingIgnoredDuringExecution"]), ListKind::AtomicMap);
        assert_eq!(pod(&["spec", "unknownField"]), ListKind::Atomic);
        assert_eq!(gen("apps/v1", "Deployment", &["spec", "selector"]), ListKind::AtomicMap);
        assert_eq!(gen("apps/v1", "Deployment", &["spec", "template", "spec", "containers"]), keys(&["name"]));
        assert_eq!(gen("apps/v1", "Deployment", &["spec", "template", "spec", "containers", "ports"]), keys(&["containerPort", "protocol=\"TCP\""]));
        assert_eq!(gen("v1", "Service", &["spec", "ports"]), keys(&["port", "protocol=\"TCP\""]));
        assert_eq!(gen("v1", "Service", &["spec", "selector"]), ListKind::AtomicMap);
        assert_eq!(gen("v1", "Node", &["spec", "taints"]), ListKind::Atomic);
        assert_eq!(gen("v1", "Node", &["status", "addresses"]), keys(&["type"]));
        assert_eq!(gen("v1", "Namespace", &["spec", "finalizers"]), ListKind::Atomic);
        assert_eq!(gen("networking.k8s.io/v1", "NetworkPolicy", &["spec", "ingress", "ports"]), ListKind::Atomic);
        assert_eq!(gen("discovery.k8s.io/v1", "EndpointSlice", &["endpoints", "addresses"]), ListKind::Set);
        assert_eq!(root_message("v1", "NoSuchKind"), None);
    }

    #[test]
    fn empty_set_and_keyed_lists_are_owned_and_do_not_conflict() {
        let l = |p: &[&str]| gen("v1", "Pod", p);
        let owned = fields(&j(r#"{"metadata":{"finalizers":[]},"spec":{"containers":[],"tolerations":[]}}"#), None, &l, Scope::All);
        assert_eq!(to_string(&owned), r#"{"f:metadata":{"f:finalizers":{}},"f:spec":{"f:containers":{},"f:tolerations":{}}}"#);
        // No change when the list was already empty.
        assert!(is_empty(&fields(&j(r#"{"metadata":{"finalizers":[]}}"#), Some(&j(r#"{"metadata":{"finalizers":[]}}"#)), &l, Scope::All)));
    }

    #[test]
    fn crd_list_map_key_defaults_are_applied_to_keys() {
        let schema: &'static Value = alloc::boxed::Box::leak(alloc::boxed::Box::new(j(r#"{"properties":{"spec":{"properties":{"ports":{"type":"array","x-kubernetes-list-type":"map","x-kubernetes-list-map-keys":["port","proto"],"items":{"properties":{"port":{"type":"integer"},"proto":{"type":"string","default":"TCP"},"x":{"type":"string"}}}}}}}}"#)));
        let l = crd_lists(schema);
        assert_eq!(schema_lists(schema, &["spec", "ports"]), keys(&["port", "proto=\"TCP\""]));
        // An item without `proto` has the same key as one that spells the default out.
        let a = apply(&j("{}"), &j(r#"{"spec":{"ports":[{"port":80,"x":"a"}]}}"#), Vec::new(), "m1", false, "v1", "t", &l, Scope::All).unwrap();
        assert_eq!(to_string(&a.owned), r#"{"f:spec":{"f:ports":{"k:{\"port\":80,\"proto\":\"TCP\"}":{".":{},"f:port":{},"f:x":{}}}}}"#);
        let b = apply(&a.object, &j(r#"{"spec":{"ports":[{"port":80,"proto":"TCP","x":"b"}]}}"#), a.entries, "m1", false, "v1", "t", &l, Scope::All).unwrap();
        assert_eq!(b.object.pointer(&["spec", "ports"]).unwrap().as_array().unwrap().len(), 1);
    }
}
