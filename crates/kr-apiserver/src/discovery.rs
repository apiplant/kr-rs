//! Legacy discovery documents: `/api`, `/api/v1`, `/apis`, `/apis/<group>/<version>`.
//! (Aggregated discovery is not served; kubectl falls back to these.)

use crate::resources::{self, Resource, RESOURCES};
use alloc::string::String;
use alloc::vec::Vec;
use kr_fmt::json::{self, Value};

fn s(v: &str) -> Value {
    Value::String(v.into())
}

fn obj(fields: Vec<(&str, Value)>) -> Value {
    Value::Object(fields.into_iter().map(|(k, v)| (k.into(), v)).collect())
}

fn strings(v: &[&str]) -> Value {
    Value::Array(v.iter().map(|x| s(x)).collect())
}

const VERBS: &[&str] = &["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"];

fn resource_entries(r: &Resource) -> Vec<Value> {
    let mut out = alloc::vec![obj(alloc::vec![
        ("name", s(r.plural)),
        ("singularName", s(r.singular)),
        ("namespaced", Value::Bool(r.namespaced)),
        ("kind", s(r.kind)),
        ("verbs", strings(VERBS)),
        ("shortNames", strings(r.short)),
        ("categories", strings(r.categories)),
        ("storageVersionHash", s("")),
    ])];
    for sub in r.subresources {
        let (kind, group, version) = if *sub == "scale" { ("Scale", "autoscaling", "v1") } else { (r.kind, "", "") };
        let mut fields = alloc::vec![
            ("name", Value::String(alloc::format!("{}/{sub}", r.plural))),
            ("singularName", s("")),
            ("namespaced", Value::Bool(r.namespaced)),
            ("kind", s(kind)),
            ("verbs", strings(&["get", "patch", "update"])),
        ];
        if !group.is_empty() {
            fields.push(("group", s(group)));
            fields.push(("version", s(version)));
        }
        out.push(obj(fields));
    }
    out
}

/// APIResourceList for one group/version.
pub fn resource_list(extra: &[&'static Resource], group: &str, version: &str) -> Option<String> {
    let items: Vec<Value> = RESOURCES.iter().chain(extra.iter().copied()).filter(|r| r.group == group && r.version == version).flat_map(resource_entries).collect();
    if items.is_empty() {
        return None;
    }
    let gv = if group.is_empty() { String::from(version) } else { alloc::format!("{group}/{version}") };
    Some(json::to_string(&obj(alloc::vec![
        ("kind", s("APIResourceList")),
        ("apiVersion", s("v1")),
        ("groupVersion", Value::String(gv)),
        ("resources", Value::Array(items)),
    ])))
}

/// `/api`: the core group's versions.
pub fn core_versions(server_address: &str) -> String {
    json::to_string(&obj(alloc::vec![
        ("kind", s("APIVersions")),
        ("versions", strings(&["v1"])),
        ("serverAddressByClientCIDRs", Value::Array(alloc::vec![obj(alloc::vec![("clientCIDR", s("0.0.0.0/0")), ("serverAddress", s(server_address))])])),
    ]))
}

fn group_doc(extra: &[&'static Resource], g: &str) -> Value {
    let vers: Vec<Value> = resources::versions(extra, g).into_iter().map(|v| obj(alloc::vec![("groupVersion", Value::String(alloc::format!("{g}/{v}"))), ("version", s(v))])).collect();
    obj(alloc::vec![("name", s(g)), ("versions", Value::Array(vers.clone())), ("preferredVersion", vers[0].clone())])
}

/// `/apis`: APIGroupList.
pub fn group_list(extra: &[&'static Resource]) -> String {
    let groups: Vec<Value> = resources::groups(extra).into_iter().map(|g| group_doc(extra, g)).collect();
    json::to_string(&obj(alloc::vec![("kind", s("APIGroupList")), ("apiVersion", s("v1")), ("groups", Value::Array(groups))]))
}

/// `/apis/<group>`: APIGroup.
pub fn group(extra: &[&'static Resource], name: &str) -> Option<String> {
    if !resources::groups(extra).contains(&name) {
        return None;
    }
    let Value::Object(mut f) = group_doc(extra, name) else { return None };
    f.insert(0, ("apiVersion".into(), s("v1")));
    f.insert(0, ("kind".into(), s("APIGroup")));
    Some(json::to_string(&Value::Object(f)))
}
