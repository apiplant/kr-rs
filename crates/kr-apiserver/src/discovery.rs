//! Legacy discovery documents: `/api`, `/api/v1`, `/apis`, `/apis/<group>/<version>`.
//! Also aggregated discovery (`apidiscovery.k8s.io/v2`) for `/api` and `/apis`.

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
        let (kind, group, version) = match *sub {
            "scale" => ("Scale", "autoscaling", "v1"),
            "eviction" => ("Eviction", "policy", "v1"),
            _ => (r.kind, "", ""),
        };
        let mut fields = alloc::vec![
            ("name", Value::String(alloc::format!("{}/{sub}", r.plural))),
            ("singularName", s("")),
            ("namespaced", Value::Bool(r.namespaced)),
            ("kind", s(kind)),
            ("verbs", if *sub == "eviction" { strings(&["create"]) } else { strings(&["get", "patch", "update"]) }),
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


/// Outcome of negotiating the `Accept` header for `/api` and `/apis`.
#[derive(Debug, PartialEq, Eq)]
pub enum Negotiated {
    /// Serve the legacy document.
    Legacy,
    /// Serve the aggregated JSON document in this apidiscovery version ("v2" or "v2beta1":
    /// older client-go asks for v2beta1 and rejects a v2 answer).
    Aggregated(&'static str),
    /// Only the (unsupported) protobuf aggregated form was requested.
    NotAcceptable,
}

fn q_of(params: &[&str]) -> u32 {
    for p in params {
        if let Some(q) = p.trim().strip_prefix("q=") {
            let q = q.trim();
            let (i, f) = q.split_once('.').unwrap_or((q, ""));
            let mut v = i.parse::<u32>().unwrap_or(0) * 1000;
            let mut mul = 100;
            for c in f.chars().take(3) {
                v += c.to_digit(10).unwrap_or(0) * mul;
                mul /= 10;
            }
            return v;
        }
    }
    1000
}

/// Picks the response form from an `Accept` header: the highest-q (then first) supported media type wins.
pub fn negotiate(accept: Option<&str>) -> Negotiated {
    let Some(accept) = accept else { return Negotiated::Legacy };
    let mut best: Option<(u32, Negotiated)> = None;
    let mut proto_agg = false;
    for item in accept.split(',') {
        let mut parts = item.split(';').map(str::trim);
        let mt = parts.next().unwrap_or("");
        let params: Vec<&str> = parts.collect();
        let has = |k: &str, v: &str| params.iter().any(|p| p.strip_prefix(k).and_then(|x| x.strip_prefix('=')).is_some_and(|x| x == v));
        let ver = if has("v", "v2") { Some("v2") } else if has("v", "v2beta1") { Some("v2beta1") } else { None };
        let agg = has("g", "apidiscovery.k8s.io") && has("as", "APIGroupDiscoveryList") && ver.is_some();
        let q = q_of(&params);
        let kind = match mt {
            "application/json" if agg => Negotiated::Aggregated(ver.unwrap_or("v2")),
            "application/vnd.kubernetes.protobuf" if agg => {
                proto_agg = true;
                continue;
            }
            "application/json" | "*/*" | "application/*" => Negotiated::Legacy,
            _ => continue,
        };
        if q > 0 && best.as_ref().is_none_or(|(bq, _)| q > *bq) {
            best = Some((q, kind));
        }
    }
    match best {
        Some((_, k)) => k,
        None if proto_agg => Negotiated::NotAcceptable,
        None => Negotiated::Legacy,
    }
}

pub fn agg_content_type(ver: &str) -> String {
    alloc::format!("application/json;g=apidiscovery.k8s.io;v={ver};as=APIGroupDiscoveryList")
}

/// Quoted ETag for a body (two FNV-style 64-bit hashes).
pub fn etag(body: &str) -> String {
    let (mut a, mut b) = (0xcbf29ce484222325u64, 0x84222325cbf29ce4u64);
    for &c in body.as_bytes() {
        a = (a ^ c as u64).wrapping_mul(0x100000001b3);
        b = (b ^ c as u64).wrapping_mul(0x100000001b3).rotate_left(5);
    }
    alloc::format!("\"{a:016X}{b:016X}\"")
}

fn agg_resource(r: &Resource) -> Value {
    let rk = |kind: &str, g: &str, v: &str| obj(alloc::vec![("group", s(g)), ("version", s(v)), ("kind", s(kind))]);
    let subs: Vec<Value> = r
        .subresources
        .iter()
        .map(|sub| {
            let resp = match *sub {
                "scale" => rk("Scale", "autoscaling", "v1"),
                "eviction" => rk("Eviction", "policy", "v1"),
                _ => rk(r.kind, r.group, r.version),
            };
            let verbs = if *sub == "eviction" { strings(&["create"]) } else { strings(&["get", "patch", "update"]) };
            obj(alloc::vec![("subresource", s(sub)), ("responseKind", resp), ("verbs", verbs)])
        })
        .collect();
    obj(alloc::vec![
        ("resource", s(r.plural)),
        ("responseKind", rk(r.kind, r.group, r.version)),
        ("scope", s(if r.namespaced { "Namespaced" } else { "Cluster" })),
        ("singularResource", s(r.singular)),
        ("verbs", strings(VERBS)),
        ("shortNames", strings(r.short)),
        ("categories", strings(r.categories)),
        ("subresources", Value::Array(subs)),
    ])
}

fn agg_group(extra: &[&'static Resource], g: &str) -> Value {
    let vs = if g.is_empty() { alloc::vec!["v1"] } else { resources::versions(extra, g) };
    let versions: Vec<Value> = vs
        .into_iter()
        .map(|v| {
            let res: Vec<Value> = RESOURCES.iter().chain(extra.iter().copied()).filter(|r| r.group == g && r.version == v).map(agg_resource).collect();
            obj(alloc::vec![("version", s(v)), ("resources", Value::Array(res)), ("freshness", s("Current"))])
        })
        .collect();
    obj(alloc::vec![("metadata", obj(alloc::vec![("name", s(g))])), ("versions", Value::Array(versions))])
}

/// Aggregated discovery for `/api` (`core == true`, the core group only) or `/apis` (all other groups).
pub fn aggregated(extra: &[&'static Resource], core: bool, ver: &str) -> String {
    let items: Vec<Value> = if core { alloc::vec![agg_group(extra, "")] } else { resources::groups(extra).into_iter().filter(|g| !g.is_empty()).map(|g| agg_group(extra, g)).collect() };
    json::to_string(&obj(alloc::vec![
        ("kind", s("APIGroupDiscoveryList")),
        ("apiVersion", Value::String(alloc::format!("apidiscovery.k8s.io/{ver}"))),
        ("metadata", obj(alloc::vec![])),
        ("items", Value::Array(items)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const JSON_AGG: &str = "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList";

    #[test]
    fn negotiation() {
        assert_eq!(negotiate(None), Negotiated::Legacy);
        assert_eq!(negotiate(Some("application/json")), Negotiated::Legacy);
        assert_eq!(negotiate(Some(JSON_AGG)), Negotiated::Aggregated("v2"));
        let both = "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList,application/json;g=apidiscovery.k8s.io;v=v2beta1;as=APIGroupDiscoveryList,application/json";
        assert_eq!(negotiate(Some(both)), Negotiated::Aggregated("v2"));
        let q = "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList;q=0.5,application/json;q=0.9";
        assert_eq!(negotiate(Some(q)), Negotiated::Legacy);
        let proto = "application/vnd.kubernetes.protobuf;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList";
        assert_eq!(negotiate(Some(proto)), Negotiated::NotAcceptable);
        assert_eq!(negotiate(Some(&alloc::format!("{proto},{JSON_AGG}"))), Negotiated::Aggregated("v2"));
        assert_eq!(negotiate(Some(&alloc::format!("{proto},application/json"))), Negotiated::Legacy);
    }

    #[test]
    fn shape() {
        let core = aggregated(&[], true, "v2");
        assert!(core.contains("\"kind\":\"APIGroupDiscoveryList\"") && core.contains("apidiscovery.k8s.io/v2"));
        let v = json::parse_str(&core).unwrap();
        let items = v.get("items").and_then(|i| i.as_array()).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].get("metadata").and_then(|m| m.get("name")).and_then(|n| n.as_str()), Some(""));
        assert!(core.contains("\"scope\":\"Namespaced\"") && core.contains("\"freshness\":\"Current\"") && core.contains("\"singularResource\":\"pod\""));
        let apis = aggregated(&[], false, "v2");
        assert!(apis.contains("\"name\":\"apps\"") && !apis.contains("\"name\":\"\""));
    }

    #[test]
    fn etag_stable() {
        assert_eq!(etag("a"), etag("a"));
        assert_ne!(etag("a"), etag("b"));
    }

    #[test]
    fn crd_included() {
        static R: Resource = Resource { group: "example.com", version: "v1", kind: "Widget", plural: "widgets", singular: "widget", namespaced: false, short: &["wd"], subresources: &["status"], categories: &[] };
        let d = aggregated(&[&R], false, "v2");
        assert!(d.contains("\"name\":\"example.com\"") && d.contains("\"resource\":\"widgets\"") && d.contains("\"scope\":\"Cluster\"") && d.contains("\"kind\":\"Widget\""));
    }
}

#[cfg(test)]
mod v2beta1_tests {
    use super::*;

    #[test]
    fn older_clients_get_the_version_they_asked_for() {
        let old = "application/json;g=apidiscovery.k8s.io;v=v2beta1;as=APIGroupDiscoveryList,application/json";
        assert_eq!(negotiate(Some(old)), Negotiated::Aggregated("v2beta1"));
        assert!(aggregated(&[], true, "v2beta1").contains("\"apiVersion\":\"apidiscovery.k8s.io/v2beta1\""));
        assert_eq!(agg_content_type("v2beta1"), "application/json;g=apidiscovery.k8s.io;v=v2beta1;as=APIGroupDiscoveryList");
    }
}
