//! A minimal OpenAPI v3 surface: enough for kubectl's capability probes (server-side field
//! validation via the `fieldValidation` query parameter), not full schemas. kubectl then
//! sends `fieldValidation=Strict` instead of validating client-side; kr accepts unknown fields
//! (KNOWN_ISSUES: no typed schemas yet).

use crate::resources::{self, Resource, RESOURCES};
use alloc::string::String;
use alloc::vec::Vec;
use kr_fmt::json::{self, Value};

fn o(fields: Vec<(&str, Value)>) -> Value {
    Value::Object(fields.into_iter().map(|(k, v)| (k.into(), v)).collect())
}

fn gv_path(group: &str, version: &str) -> String {
    if group.is_empty() { alloc::format!("api/{version}") } else { alloc::format!("apis/{group}/{version}") }
}

/// `/openapi/v3`: index of group-version documents.
pub fn index(extra: &[&'static Resource]) -> String {
    let mut paths = alloc::vec![(String::from("api/v1"), o(alloc::vec![("serverRelativeURL", Value::from("/openapi/v3/api/v1?hash=kr"))]))];
    for (g, v) in resources::group_versions(extra) {
        let p = gv_path(g, v);
        let url = alloc::format!("/openapi/v3/{p}?hash=kr");
        paths.push((p, o(alloc::vec![("serverRelativeURL", Value::String(url))])));
    }
    json::to_string(&o(alloc::vec![("paths", Value::Object(paths))]))
}

fn op(r: &Resource, action: &str) -> Value {
    let param = |name: &str| o(alloc::vec![("name", Value::from(name)), ("in", Value::from("query")), ("schema", o(alloc::vec![("type", Value::from("string"))]))]);
    o(alloc::vec![
        ("operationId", Value::String(alloc::format!("{action}{}", r.kind))),
        ("parameters", Value::Array(alloc::vec![param("fieldValidation"), param("dryRun"), param("fieldManager")])),
        ("responses", o(alloc::vec![("200", o(alloc::vec![("description", Value::from("OK"))]))])),
        ("x-kubernetes-action", Value::from(action)),
        ("x-kubernetes-group-version-kind", o(alloc::vec![("group", Value::from(r.group)), ("version", Value::from(r.version)), ("kind", Value::from(r.kind))])),
    ])
}

/// `/openapi/v3/<gv path>`: operations per resource (no component schemas).
pub fn group_version(extra: &[&'static Resource], path: &str) -> Option<String> {
    let mut paths = Vec::new();
    for r in RESOURCES.iter().chain(extra.iter().copied()).filter(|r| gv_path(r.group, r.version) == path) {
        let base = if r.namespaced { alloc::format!("/{path}/namespaces/{{namespace}}/{}", r.plural) } else { alloc::format!("/{path}/{}", r.plural) };
        paths.push((base.clone(), o(alloc::vec![("post", op(r, "post")), ("get", op(r, "list"))])));
        paths.push((alloc::format!("{base}/{{name}}"), o(alloc::vec![("get", op(r, "get")), ("put", op(r, "put")), ("patch", op(r, "patch")), ("delete", op(r, "delete"))])));
    }
    if paths.is_empty() {
        return None;
    }
    Some(json::to_string(&o(alloc::vec![
        ("openapi", Value::from("3.0.0")),
        ("info", o(alloc::vec![("title", Value::from("Kubernetes")), ("version", Value::from("v1.37.0-kr"))])),
        ("paths", Value::Object(paths)),
        ("components", o(alloc::vec![("schemas", Value::Object(Vec::new()))])),
    ])))
}
