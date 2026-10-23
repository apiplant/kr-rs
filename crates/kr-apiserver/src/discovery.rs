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
pub fn resource_list(group: &str, version: &str) -> Option<String> {
    let items: Vec<Value> = RESOURCES.iter().filter(|r| r.group == group && r.version == version).flat_map(resource_entries).collect();
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

/// `/apis`: APIGroupList.
pub fn group_list() -> String {
    let groups: Vec<Value> = resources::groups()
        .into_iter()
        .map(|g| {
            let gv = alloc::format!("{g}/v1");
            let ver = obj(alloc::vec![("groupVersion", Value::String(gv)), ("version", s("v1"))]);
            obj(alloc::vec![("name", s(g)), ("versions", Value::Array(alloc::vec![ver.clone()])), ("preferredVersion", ver)])
        })
        .collect();
    json::to_string(&obj(alloc::vec![("kind", s("APIGroupList")), ("apiVersion", s("v1")), ("groups", Value::Array(groups))]))
}

/// `/apis/<group>`: APIGroup.
pub fn group(name: &str) -> Option<String> {
    if !resources::groups().contains(&name) {
        return None;
    }
    let ver = obj(alloc::vec![("groupVersion", Value::String(alloc::format!("{name}/v1"))), ("version", s("v1"))]);
    Some(json::to_string(&obj(alloc::vec![
        ("kind", s("APIGroup")),
        ("apiVersion", s("v1")),
        ("name", s(name)),
        ("versions", Value::Array(alloc::vec![ver.clone()])),
        ("preferredVersion", ver),
    ])))
}
