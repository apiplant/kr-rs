//! API aggregation: an `apiregistration.k8s.io` APIService whose `spec.service` is set is served
//! by the extension API server behind that Service.
//!
//! Requests under `/apis/<group>/<version>/...` are authenticated here and forwarded over TLS
//! (the extension's certificate verified against `spec.caBundle`) with the caller's identity in
//! the request-header authentication headers; the extension authorizes through the delegated
//! `SubjectAccessReview` API. The front proxy client certificate comes from a CA published, with the
//! header names, in the `extension-apiserver-authentication` ConfigMap of `kube-system`.
//! [`probe_all`] is the availability controller: it discovers each extension's resources,
//! reports the `Available` condition and feeds the discovery documents ([`merge_groups`],
//! [`merge_aggregated`]).

use crate::api::{ApiServer, Reply, Req, User};
use crate::object::{obj, ApiError};
use alloc::format;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_crypto::tls::ClientConfig;
use kr_crypto::x509::{self, CertParams, Name, SigningKey};
use kr_fmt::json::{self, Value};
use kr_net::http1::client::{Client as Http, Config as HttpConfig};
use kr_net::http1::server::Response;
use kr_net::tcp::HostsResolver;
use kr_net::tls::TlsConnector;

pub const GROUP: &str = "apiregistration.k8s.io";
const STORE_KEY: &str = "/kr/front-proxy";
/// Largest response relayed from an extension API server.
const MAX_BODY: usize = 64 << 20;

/// The CA that vouches for the aggregator to extension API servers, and its client certificate.
pub struct FrontProxy {
    pub ca_pem: String,
    chain: Vec<Vec<u8>>,
    seed: [u8; 32],
}

impl FrontProxy {
    fn client_config(&self, roots: Vec<Vec<u8>>) -> ClientConfig {
        ClientConfig { pinned_ca: None, roots, client_cert: Some((self.chain.clone(), SigningKey::Ed25519(kr_crypto::ed25519::SigningKey::from_seed(&self.seed)))), alpn: alloc::vec![b"http/1.1".to_vec()], tls12: false }
    }

    fn generate(now: i64, rng: fn(&mut [u8])) -> FrontProxy {
        let (mut ca_seed, mut cl_seed, mut s1, mut s2) = ([0u8; 32], [0u8; 32], [0u8; 16], [0u8; 16]);
        rng(&mut ca_seed);
        rng(&mut cl_seed);
        rng(&mut s1);
        rng(&mut s2);
        let ca_key = SigningKey::Ed25519(kr_crypto::ed25519::SigningKey::from_seed(&ca_seed));
        let cl_key = SigningKey::Ed25519(kr_crypto::ed25519::SigningKey::from_seed(&cl_seed));
        let ca_name = Name { common_name: String::from("front-proxy-ca"), organizations: Vec::new() };
        let params = |serial, subject: Name, ca, client, key: &SigningKey| CertParams { serial, subject, not_before: now - 3600, not_after: now + 10 * 365 * 86400, is_ca: ca, server: false, client, dns_names: Vec::new(), ip_addrs: Vec::new(), public_key: key.public() };
        let ca = x509::issue(&params(s1, ca_name.clone(), true, false, &ca_key), &ca_name, &ca_key);
        let cl_name = Name { common_name: String::from("front-proxy-client"), organizations: Vec::new() };
        let cl = x509::issue(&params(s2, cl_name, false, true, &cl_key), &ca_name, &ca_key);
        FrontProxy { ca_pem: x509::pem_encode("CERTIFICATE", &ca), chain: alloc::vec![cl], seed: cl_seed }
    }

    fn to_json(&self) -> String {
        let mut s = String::from("{\"ca\":");
        json::write_str(&self.ca_pem, &mut s);
        s.push_str(",\"cert\":");
        json::write_str(&x509::pem_encode("CERTIFICATE", &self.chain[0]), &mut s);
        s.push_str(",\"seed\":");
        json::write_str(&kr_fmt::base64::encode(&self.seed), &mut s);
        s.push('}');
        s
    }

    fn from_json(v: &Value) -> Option<FrontProxy> {
        let ca_pem = v.get("ca")?.as_str()?.to_string();
        let cert = x509::pem_decode_all(v.get("cert")?.as_str()?, "CERTIFICATE").ok()?.into_iter().next()?;
        let seed: [u8; 32] = kr_fmt::base64::decode(v.get("seed")?.as_str()?).ok()?.try_into().ok()?;
        Some(FrontProxy { ca_pem, chain: alloc::vec![cert], seed })
    }
}

impl ApiServer {
    /// The front proxy credentials: loaded from the store, created (and stored) on first use.
    pub(crate) fn front_proxy(&self) -> Rc<FrontProxy> {
        if let Some(f) = self.front.borrow().as_ref() {
            return f.clone();
        }
        let stored = self.store.borrow().get(STORE_KEY).and_then(|kv| json::parse(&kv.value).ok()).and_then(|v| FrontProxy::from_json(&v));
        let fp = Rc::new(match stored {
            Some(f) => f,
            None => {
                let f = FrontProxy::generate(self.now(), self.rng());
                if self.writable() {
                    let _ = self.store.borrow_mut().create(STORE_KEY, f.to_json().into_bytes());
                }
                f
            }
        });
        *self.front.borrow_mut() = Some(fp.clone());
        fp
    }
}

/// One served group version of an extension API server.
pub struct AggGroup {
    pub group: String,
    pub version: String,
    pub group_priority: i64,
    pub version_priority: i64,
    /// The extension's `APIResourceList` for this group version.
    pub resources: Value,
}

/// The `extension-apiserver-authentication` ConfigMap `data`.
pub(crate) fn auth_configmap(client_ca: &str, fp: &FrontProxy) -> String {
    let mut s = String::from(r#"{"metadata":{"name":"extension-apiserver-authentication","namespace":"kube-system"},"data":{"client-ca-file":"#);
    json::write_str(client_ca, &mut s);
    s.push_str(r#","requestheader-client-ca-file":"#);
    json::write_str(&fp.ca_pem, &mut s);
    s.push_str(r#","requestheader-allowed-names":"[\"front-proxy-client\"]","requestheader-extra-headers-prefix":"[\"X-Remote-Extra-\"]","requestheader-group-headers":"[\"X-Remote-Group\"]","requestheader-username-headers":"[\"X-Remote-User\"]"}}"#);
    s
}

fn service_of(apisvc: &Value) -> Option<(String, String, u64)> {
    let svc = apisvc.pointer(&["spec", "service"])?;
    let s = |k: &str| svc.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    Some((s("namespace"), s("name"), svc.get("port").and_then(Value::as_u64).unwrap_or(443)))
}

/// The stored APIService serving `/apis/<group>/<version>`, if it is backed by a Service.
fn apiservice_for(api: &ApiServer, group: &str, version: &str) -> Option<Value> {
    let a = api.wh_object(GROUP, "v1", "apiservices", None, &format!("{version}.{group}"))?;
    service_of(&a).map(|_| a)
}

/// What the extension answered.
pub struct Relayed {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

/// Sends a request to the extension API server behind `apisvc`, as `user`.
pub async fn forward(api: &ApiServer, apisvc: &Value, method: &str, path_query: &str, headers: &[(&str, &str)], body: &[u8], user: &User, secs: u64) -> Result<Relayed, String> {
    let (ns, name, port) = service_of(apisvc).ok_or("APIService has no service")?;
    let svc = api.wh_object("", "v1", "services", Some(&ns), &name).ok_or_else(|| format!("service \"{name}\" not found"))?;
    let ip = svc.pointer(&["spec", "clusterIP"]).and_then(Value::as_str).filter(|i| i.contains('.')).ok_or("service has no cluster IP")?;
    let host = format!("{name}.{ns}.svc");
    let url = format!("https://{host}:{port}{path_query}");
    let roots = match apisvc.pointer(&["spec", "caBundle"]).and_then(Value::as_str) {
        Some(b) => x509::pem_decode_all(core::str::from_utf8(&kr_fmt::base64::decode(b).map_err(|_| "invalid caBundle")?).map_err(|_| "invalid caBundle")?, "CERTIFICATE").map_err(|_| "invalid caBundle")?,
        None => Vec::new(),
    };
    let cfg = Rc::new(api.front_proxy().client_config(roots));
    let http = Http::with_connector(
        TlsConnector::new(crate::webhook::WhResolver(HostsResolver::from_contents(&format!("{ip} {host}\n"))), cfg),
        HttpConfig { max_redirects: 0, max_idle: 0, connect_timeout_ms: secs * 1000, head_timeout_ms: secs * 1000, read_timeout_ms: secs * 1000, user_agent: "kube-aggregator".to_string(), ..HttpConfig::default() },
    );
    let groups: Vec<String> = user.groups.clone();
    let mut hdrs: Vec<(&str, &str)> = alloc::vec![("X-Remote-User", user.name.as_str())];
    hdrs.extend(groups.iter().map(|g| ("X-Remote-Group", g.as_str())));
    hdrs.extend_from_slice(headers);
    let fut = async {
        let mut resp = http.request(method, &url, &hdrs, body).await.map_err(|e| format!("{e:?}"))?;
        let status = resp.status;
        let content_type = resp.header("content-type").unwrap_or("application/json").to_string();
        let body = resp.read_to_end(MAX_BODY).await.map_err(|e| format!("reading response: {e:?}"))?;
        Ok::<Relayed, String>(Relayed { status, content_type, body })
    };
    kr_rt::exec::timeout(secs * 1000, fut).await.map_err(|_| String::from("timeout"))?
}

fn unavailable(msg: String) -> Reply {
    Reply::err(ApiError::new(503, "ServiceUnavailable", format!("error trying to reach service: {msg}")))
}

/// Serves a request for an aggregated API: `Some(reply)` when `/apis/<group>/<version>` belongs
/// to an APIService backed by a Service.
pub async fn proxy(api: &ApiServer, req: &Req<'_>) -> Option<Reply> {
    let path = req.path.trim_end_matches('/');
    let mut segs = path.trim_start_matches('/').split('/');
    if segs.next() != Some("apis") {
        return None;
    }
    let (group, version) = (segs.next()?, segs.next()?);
    let apisvc = apiservice_for(api, group, version)?;
    let user = match api.authenticate(req) {
        Ok(u) => u,
        Err(e) => return Some(Reply::err(e)),
    };
    if req.query.split('&').any(|p| p == "watch=true" || p == "watch=1") {
        return Some(Reply::err(ApiError::new(501, "NotImplemented", "watches of aggregated APIs are not supported")));
    }
    let available = apisvc.pointer(&["status", "conditions"]).and_then(Value::as_array).is_some_and(|c| c.iter().any(|x| x.get("type").and_then(Value::as_str) == Some("Available") && x.get("status").and_then(Value::as_str) == Some("True")));
    if !available {
        return Some(Reply::err(ApiError::new(503, "ServiceUnavailable", format!("the server is currently unable to handle the request (APIService {version}.{group} is not available)"))));
    }
    let pq = if req.query.is_empty() { req.path.to_string() } else { format!("{}?{}", req.path, req.query) };
    let mut hdrs: Vec<(&str, &str)> = Vec::new();
    if let Some(a) = req.accept {
        hdrs.push(("Accept", a));
    }
    if let Some(c) = req.content_type {
        hdrs.push(("Content-Type", c));
    }
    Some(match forward(api, &apisvc, req.method, &pq, &hdrs, req.body, &user, 30).await {
        Ok(r) => Reply::Http(Response::new(r.status, r.body).with_header("Content-Type", &r.content_type)),
        Err(e) => unavailable(e),
    })
}

/// The availability controller: probes every Service-backed APIService once, keeps its
/// `Available` condition current and refreshes the discovery cache.
pub async fn probe_all(api: &ApiServer) {
    let system = User { name: String::from("system:kube-aggregator"), groups: alloc::vec![String::from("system:masters")] };
    let mut found: Vec<AggGroup> = Vec::new();
    for a in api.wh_list(GROUP, "v1", "apiservices") {
        if service_of(&a).is_none() {
            continue;
        }
        let s = |k: &str| a.pointer(&["spec", k]).and_then(Value::as_str).unwrap_or("").to_string();
        let (group, version) = (s("group"), s("version"));
        let name = a.pointer(&["metadata", "name"]).and_then(Value::as_str).unwrap_or("").to_string();
        let (status, reason, message, list) = match forward(api, &a, "GET", &format!("/apis/{group}/{version}"), &[("Accept", "application/json")], b"", &system, 5).await {
            Ok(r) if r.status == 200 => match json::parse(&r.body) {
                Ok(v) => ("True", "Passed", String::from("all checks passed"), Some(v)),
                Err(_) => ("False", "FailedDiscoveryCheck", String::from("failed to parse the discovery document"), None),
            },
            Ok(r) => ("False", "FailedDiscoveryCheck", format!("failing or missing response from /apis/{group}/{version}: status {}", r.status), None),
            Err(e) => ("False", "FailedDiscoveryCheck", format!("failing or missing response: {e}"), None),
        };
        if let Some(resources) = list {
            let n = |k: &str| a.pointer(&["spec", k]).and_then(Value::as_i64).unwrap_or(0);
            found.push(AggGroup { group, version, group_priority: n("groupPriorityMinimum"), version_priority: n("versionPriority"), resources });
        }
        let current = a.pointer(&["status", "conditions"]).and_then(Value::as_array).and_then(|c| c.iter().find(|x| x.get("type").and_then(Value::as_str) == Some("Available")));
        if current.is_some_and(|c| c.get("status").and_then(Value::as_str) == Some(status) && c.get("reason").and_then(Value::as_str) == Some(reason)) {
            continue;
        }
        let cond = obj(alloc::vec![
            ("type", Value::from("Available")),
            ("status", Value::from(status)),
            ("reason", Value::from(reason)),
            ("message", Value::String(message)),
            ("lastTransitionTime", Value::String(crate::object::rfc3339(api.now()))),
        ]);
        let mut conds: Vec<Value> = a.pointer(&["status", "conditions"]).and_then(Value::as_array).map(|c| c.iter().filter(|x| x.get("type").and_then(Value::as_str) != Some("Available")).cloned().collect()).unwrap_or_default();
        conds.push(cond);
        let patch = json::to_string(&obj(alloc::vec![("status", obj(alloc::vec![("conditions", Value::Array(conds))]))]));
        let path = format!("/apis/{GROUP}/v1/apiservices/{name}/status");
        let r = Req { method: "PATCH", path: &path, query: "", content_type: Some("application/merge-patch+json"), accept: None, body: patch.as_bytes(), user: Some(system.clone()), bearer: None, headers: &[], authz_verb: None };
        let _ = api.handle(&r);
    }
    *api.agg.borrow_mut() = found;
}

/// Adds the aggregated groups to the legacy `/apis` document.
pub fn merge_groups(api: &ApiServer, doc: &mut Value) {
    let agg = api.agg.borrow();
    if agg.is_empty() {
        return;
    }
    let Some(groups) = doc.get_mut("groups").and_then(Value::as_array_mut) else { return };
    for name in agg.iter().map(|g| g.group.as_str()).collect::<Vec<_>>().into_iter().fold(Vec::new(), |mut v, g| {
        if !v.contains(&g) {
            v.push(g);
        }
        v
    }) {
        if groups.iter().any(|g| g.get("name").and_then(Value::as_str) == Some(name)) {
            continue;
        }
        groups.push(group_doc(&agg, name));
    }
}

/// The `APIGroup` of an aggregated group, `None` when it is not one.
pub fn group_doc_for(api: &ApiServer, name: &str) -> Option<Value> {
    let agg = api.agg.borrow();
    agg.iter().any(|g| g.group == name).then(|| {
        let mut d = group_doc(&agg, name);
        d.set("kind", Value::from("APIGroup"));
        d.set("apiVersion", Value::from("v1"));
        d
    })
}

fn group_doc(agg: &[AggGroup], name: &str) -> Value {
    let mut vs: Vec<&AggGroup> = agg.iter().filter(|g| g.group == name).collect();
    vs.sort_by(|a, b| b.version_priority.cmp(&a.version_priority).then(a.version.cmp(&b.version)));
    let versions: Vec<Value> = vs.iter().map(|g| obj(alloc::vec![("groupVersion", Value::String(format!("{name}/{}", g.version))), ("version", Value::String(g.version.clone()))])).collect();
    obj(alloc::vec![("name", Value::String(name.to_string())), ("versions", Value::Array(versions.clone())), ("preferredVersion", versions.first().cloned().unwrap_or(Value::Null))])
}

/// Adds the aggregated groups to an `APIGroupDiscoveryList` (`/apis`, aggregated discovery).
pub fn merge_aggregated(api: &ApiServer, doc: &mut Value) {
    let agg = api.agg.borrow();
    let Some(items) = doc.get_mut("items").and_then(Value::as_array_mut) else { return };
    let mut names: Vec<&str> = Vec::new();
    for g in agg.iter() {
        if !names.contains(&g.group.as_str()) {
            names.push(g.group.as_str());
        }
    }
    for name in names {
        let mut vs: Vec<&AggGroup> = agg.iter().filter(|g| g.group == name).collect();
        vs.sort_by(|a, b| b.version_priority.cmp(&a.version_priority).then(a.version.cmp(&b.version)));
        let versions: Vec<Value> = vs
            .iter()
            .map(|g| {
                let resources: Vec<Value> = g.resources.get("resources").and_then(Value::as_array).unwrap_or(&[]).iter().filter(|r| !r.get("name").and_then(Value::as_str).unwrap_or("").contains('/')).map(|r| agg_resource(&g.group, &g.version, r, &g.resources)).collect();
                obj(alloc::vec![("version", Value::String(g.version.clone())), ("resources", Value::Array(resources)), ("freshness", Value::from("Current"))])
            })
            .collect();
        items.retain(|i| i.pointer(&["metadata", "name"]).and_then(Value::as_str) != Some(name));
        items.push(obj(alloc::vec![("metadata", obj(alloc::vec![("name", Value::String(name.to_string()))])), ("versions", Value::Array(versions))]));
    }
}

fn agg_resource(group: &str, version: &str, r: &Value, list: &Value) -> Value {
    let s = |k: &str| r.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let name = s("name");
    let rk = |kind: String, g: &str, v: &str| obj(alloc::vec![("group", Value::String(g.to_string())), ("version", Value::String(v.to_string())), ("kind", Value::String(kind))]);
    let prefix = format!("{name}/");
    let subs: Vec<Value> = list
        .get("resources")
        .and_then(Value::as_array)
        .unwrap_or(&[])
        .iter()
        .filter_map(|x| {
            let n = x.get("name").and_then(Value::as_str)?;
            let sub = n.strip_prefix(prefix.as_str())?;
            let kind = x.get("kind").and_then(Value::as_str).unwrap_or("").to_string();
            Some(obj(alloc::vec![("subresource", Value::String(sub.to_string())), ("responseKind", rk(kind, group, version)), ("verbs", x.get("verbs").cloned().unwrap_or(Value::Array(Vec::new())))]))
        })
        .collect();
    obj(alloc::vec![
        ("resource", Value::String(name)),
        ("responseKind", rk(s("kind"), group, version)),
        ("scope", Value::from(if r.get("namespaced").and_then(Value::as_bool) == Some(true) { "Namespaced" } else { "Cluster" })),
        ("singularResource", Value::String(s("singularName"))),
        ("verbs", r.get("verbs").cloned().unwrap_or(Value::Array(Vec::new()))),
        ("shortNames", r.get("shortNames").cloned().unwrap_or(Value::Array(Vec::new()))),
        ("categories", r.get("categories").cloned().unwrap_or(Value::Array(Vec::new()))),
        ("subresources", Value::Array(subs)),
    ])
}
