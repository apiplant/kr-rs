//! Request handling: routing, the generic REST verbs over `kr-store`, list/watch, and
//! authorization. Independent of the HTTP layer: [`ApiServer::handle`] maps a [`Req`] to a
//! [`Reply`], and `server.rs` adapts that to `kr-net`'s HTTP server.
//!
//! Concurrency model: everything runs on one executor thread, and each handler runs to
//! completion without awaiting, so a read-modify-write (get, patch, update) is atomic with
//! respect to other requests. Every mutation is fsynced (`Store::sync`) before the reply.

use crate::discovery;
use crate::object::{self, obj, ApiError, Clock, FieldSelector, Selector, Target};
use crate::patch;
use crate::proto;
use crate::resources::{self, Resource};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;
use core::pin::Pin;
use core::task::{Context, Poll};
use kr_fmt::json::{self, Number, Value};
use kr_fmt::quantity::Quantity;
use kr_store::{Error as StoreError, Event, EventKind, Kv, Store, Watcher};

/// The authenticated caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub groups: Vec<String>,
}

pub struct Req<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub content_type: Option<&'a str>,
    pub accept: Option<&'a str>,
    pub body: &'a [u8],
    /// Identity from the transport (verified client certificate), if any.
    pub user: Option<User>,
    /// `Authorization: Bearer <token>` value, if any.
    pub bearer: Option<&'a str>,
    /// All request headers (needed for protocol upgrades such as WebSocket exec).
    pub headers: &'a [(String, String)],
    /// RBAC verb when it differs from what `method` implies (a webhook-mutated PATCH is
    /// replayed as a PUT but must still be authorized as "patch").
    pub authz_verb: Option<&'static str>,
}

/// Serves pod subresources that live on the node (log, exec, attach, portforward). In single
/// node mode the in-process kubelet implements it; agents will be reached over HTTPS.
pub trait NodeProxy {
    /// `node`/`node_ip`: where the pod runs (from `spec.nodeName` and the Node's InternalIP).
    #[allow(clippy::too_many_arguments)]
    fn pod_subresource(&self, sub: &str, namespace: &str, pod: &str, node: &str, node_ip: Option<[u8; 4]>, query: &str, headers: &[(String, String)]) -> Result<kr_net::http1::server::Response, ApiError>;
}

pub enum Reply {
    /// Status code and JSON body.
    Json(u16, String),
    /// A watch: newline-delimited JSON events.
    Watch(WatchStream),
    /// A raw HTTP response (node proxy: logs, exec upgrades).
    Http(kr_net::http1::server::Response),
}

impl Reply {
    fn aggregated_discovery(req: &Req, extra: &[&'static Resource], core: bool) -> Reply {
        use kr_net::http1::server::Response;
        let ver = match discovery::negotiate(req.accept) {
            discovery::Negotiated::Aggregated(v) => v,
            _ => return Reply::Http(Response::new(406, Vec::new())),
        };
        let body = discovery::aggregated(extra, core, ver);
        let tag = discovery::etag(&body);
        let matched = req.headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("if-none-match") && v.split(',').any(|t| t.trim() == tag || t.trim() == "*"));
        let resp = if matched { Response::new(304, Vec::new()) } else { Response::new(200, body.into_bytes()) };
        Reply::Http(resp.with_header("Content-Type", &discovery::agg_content_type(ver)).with_header("ETag", &tag))
    }

    pub(crate) fn err(e: ApiError) -> Reply {
        Reply::Json(e.code, e.to_status_json())
    }
    fn ok(v: &Value) -> Reply {
        Reply::Json(200, json::to_string(v))
    }
}

pub struct ApiServer {
    store: RefCell<Store>,
    now: fn() -> i64,
    rng: fn(&mut [u8]),
    server_address: String,
    version: String,
    /// ServiceAccount token signer and the cluster CA PEM (for kube-root-ca.crt).
    sa: RefCell<Option<(crate::tokens::Signer, String)>>,
    node_proxy: RefCell<Option<alloc::rc::Rc<dyn NodeProxy>>>,
    /// Cluster CA (name, key, DER) for issuing node certificates at join.
    ca: RefCell<Option<(kr_crypto::x509::Name, kr_crypto::x509::SigningKey, Vec<u8>)>>,
    /// Lifetime of issued node certificates, seconds (agents renew at 2/3).
    node_cert_secs: core::cell::Cell<i64>,
    /// Served versions of established CustomResourceDefinitions.
    custom: RefCell<Vec<crate::crd::Custom>>,
    /// Group commit: writes reach the log synchronously, fsync happens off the event loop.
    committer: crate::durable::Committer,
    /// `fieldValidation` of the request being handled (`Ignore` outside `handle`).
    fv_mode: core::cell::Cell<crate::fieldval::Mode>,
    /// Warnings for the response of the request being handled.
    warnings: RefCell<Vec<String>>,
}

/// Default namespaces created on first start.
const SYSTEM_NAMESPACES: &[&str] = &["default", "kube-system", "kube-public", "kube-node-lease"];

type R<T> = Result<T, ApiError>;

fn store_err(e: StoreError, kind: &str, name: &str) -> ApiError {
    match e {
        StoreError::Exists => ApiError::already_exists(kind, name),
        StoreError::NotFound => ApiError::not_found(kind, name),
        StoreError::Conflict { .. } => ApiError::conflict(kind, name),
        StoreError::TooLarge => ApiError::new(413, "RequestEntityTooLarge", "object too large"),
        StoreError::Compacted { .. } => ApiError::new(410, "Expired", "too old resource version"),
        _ => ApiError::new(500, "InternalError", "storage error"),
    }
}

/// Percent-decodes a query component (`+` is a space, as in form encoding).
fn url_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let h = core::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(h, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

struct Query(Vec<(String, String)>);

impl Query {
    fn parse(q: &str) -> R<Query> {
        let mut v = Vec::new();
        for kv in q.split('&').filter(|p| !p.is_empty()) {
            let (k, val) = kv.split_once('=').unwrap_or((kv, ""));
            let bad = || ApiError::bad_request("malformed query string");
            v.push((url_decode(k).ok_or_else(bad)?, url_decode(val).ok_or_else(bad)?));
        }
        Ok(Query(v))
    }
    fn get(&self, k: &str) -> Option<&str> {
        self.0.iter().rev().find(|(x, _)| x == k).map(|(_, v)| v.as_str())
    }
    fn flag(&self, k: &str) -> bool {
        matches!(self.get(k), Some("true" | "1"))
    }
}

/// A parsed resource URL.
pub(crate) struct Route {
    pub(crate) res: &'static Resource,
    pub(crate) namespace: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) sub: Option<String>,
}

fn is_masters(u: &User) -> bool {
    u.groups.iter().any(|g| g == "system:masters")
}

impl ApiServer {
    pub fn new(mut store: Store, now: fn() -> i64, rng: fn(&mut [u8]), server_address: String) -> Result<ApiServer, ApiError> {
        let ns = resources::find("", "v1", "namespaces").unwrap();
        let clock = Clock { now: now(), rng };
        for name in SYSTEM_NAMESPACES {
            let key = ns.key(None, name);
            if store.get(&key).is_some() {
                continue;
            }
            let mut o = obj(alloc::vec![("metadata", obj(alloc::vec![("name", Value::from(*name))])), ("spec", obj(alloc::vec![("finalizers", Value::Array(alloc::vec![Value::from("kubernetes")]))])), ("status", obj(alloc::vec![("phase", Value::from("Active"))]))]);
            let t = Target { api_version: "v1", kind: "Namespace", namespace: None, name_is_label: true };
            object::prepare_create(&mut o, &t, &clock, store.revision() + 1)?;
            store.create(&key, json::to_string(&o).into_bytes()).map_err(|e| store_err(e, "Namespace", name))?;
        }
        store.sync().map_err(|_| ApiError::new(500, "InternalError", "storage sync failed"))?;
        let api = ApiServer { store: RefCell::new(store), now, rng, server_address, version: String::from("v1.37.0-kr"), sa: RefCell::new(None), node_proxy: RefCell::new(None), ca: RefCell::new(None), node_cert_secs: core::cell::Cell::new(365 * 86400), custom: RefCell::new(Vec::new()), committer: crate::durable::Committer::new(), fv_mode: core::cell::Cell::new(crate::fieldval::Mode::Ignore), warnings: RefCell::new(Vec::new()) };
        if let Some(r) = resources::find(crate::crd::GROUP, "v1", "customresourcedefinitions") {
            let (crds, _) = api.store.borrow().list(&r.prefix(), None, 0);
            for kv in crds {
                if let Ok(v) = json::parse(&kv.value) {
                    api.register_crd(&v);
                }
            }
        }
        for ns in SYSTEM_NAMESPACES {
            api.ensure_default_sa(ns);
        }
        api.sync()?;
        Ok(api)
    }

    fn extra(&self) -> Vec<&'static Resource> {
        self.custom.borrow().iter().map(|c| c.res).collect()
    }

    /// (Re)registers the served versions of a stored CRD.
    fn register_crd(&self, crd: &Value) {
        let name = crd.pointer(&["metadata", "name"]).and_then(Value::as_str).unwrap_or("");
        let mut all = self.custom.borrow_mut();
        let fresh = crate::crd::build(crd, &all);
        all.retain(|c| c.crd != name);
        all.extend(fresh);
    }

    /// Removes a CRD's resources and every stored object of its kind.
    fn unregister_crd(&self, crd: &Value) {
        let name = crd.pointer(&["metadata", "name"]).and_then(Value::as_str).unwrap_or("");
        let res = self.custom.borrow().iter().find(|c| c.crd == name).map(|c| c.res);
        self.custom.borrow_mut().retain(|c| c.crd != name);
        if let Some(r) = res {
            let mut store = self.store.borrow_mut();
            let (items, _) = store.list(&r.prefix(), None, 0);
            for it in items {
                let _ = store.delete(&it.key, None);
            }
        }
    }

    /// Defaulting, pruning, validation and generation rules for a custom object.
    fn admit_custom(&self, rt: &Route, o: &mut Value, old: Option<&Value>, status: bool) -> R<()> {
        let custom = self.custom.borrow();
        let Some(c) = custom.iter().find(|c| core::ptr::eq(c.res, rt.res)) else { return Ok(()) };
        if let Some(s) = &c.schema {
            if self.fv_mode.get() != crate::fieldval::Mode::Ignore {
                let mut p = o.clone();
                crate::crd::prune(s, &mut p, true);
                let mut gone = Vec::new();
                crate::fieldval::pruned_paths(o, &p, "", &mut gone);
                gone.retain(|g| !g.starts_with("metadata"));
                gone.extend(crate::fieldval::unknown_meta(o));
                let old_meta = old.map(crate::fieldval::unknown_meta).unwrap_or_default();
                self.fv_report(crate::fieldval::messages(gone, &old_meta))?;
            }
            crate::crd::prune(s, o, true);
            let mut errs = Vec::new();
            crate::crd::validate(s, o, "", &mut errs);
            if !errs.is_empty() {
                let name = o.pointer(&["metadata", "name"]).and_then(Value::as_str).unwrap_or("");
                return Err(ApiError::invalid(alloc::format!("{}.{} \"{name}\" is invalid: {}", rt.res.kind, rt.res.group, errs.join(", "))));
            }
        }
        let has_status = c.status();
        let gen_of = |v: &Value| v.pointer(&["metadata", "generation"]).and_then(Value::as_u64).unwrap_or(1);
        match old {
            None => {
                if has_status {
                    o.remove("status");
                }
                o.entry_object("metadata").set("generation", Value::Number(Number::from_u64(1)));
            }
            Some(old) if !status => {
                let strip = |v: &Value| {
                    let mut v = v.clone();
                    v.remove("metadata");
                    if has_status {
                        v.remove("status");
                    }
                    v
                };
                let g = gen_of(old) + u64::from(strip(old) != strip(o));
                o.entry_object("metadata").set("generation", Value::Number(Number::from_u64(g)));
            }
            Some(_) => {}
        }
        Ok(())
    }

    /// Rewrites apiVersion in a response to the requested version (conversion strategy None).
    fn convert_reply(&self, rt: &Route, reply: Reply) -> Reply {
        let multi = {
            let custom = self.custom.borrow();
            let Some(c) = custom.iter().find(|c| core::ptr::eq(c.res, rt.res)) else { return reply };
            custom.iter().filter(|x| x.crd == c.crd).count() > 1
        };
        let Reply::Json(code, body) = reply else { return reply };
        if !multi || code >= 300 {
            return Reply::Json(code, body);
        }
        let Ok(mut v) = json::parse(body.as_bytes()) else { return Reply::Json(code, body) };
        let gv = rt.res.group_version();
        let kind = v.get("kind").and_then(Value::as_str).unwrap_or("").to_string();
        if kind == rt.res.kind {
            v.set("apiVersion", Value::from(gv.as_str()));
        } else if kind == alloc::format!("{}List", rt.res.kind) {
            v.set("apiVersion", Value::from(gv.as_str()));
            if let Some(items) = v.get_mut("items").and_then(Value::as_array_mut) {
                for it in items {
                    it.set("apiVersion", Value::from(gv.as_str()));
                }
            }
        } else {
            return Reply::Json(code, body);
        }
        Reply::Json(code, json::to_string(&v))
    }

    /// Enables node joining (`POST /kr/join`) with the cluster CA.
    pub fn set_node_cert_lifetime(&self, secs: i64) {
        self.node_cert_secs.set(secs.max(60));
    }

    pub fn set_ca(&self, name: kr_crypto::x509::Name, key: kr_crypto::x509::SigningKey, ca_der: Vec<u8>) {
        *self.ca.borrow_mut() = Some((name, key, ca_der));
    }

    /// Creates a bootstrap token Secret (`<id>.<secret>`) if it does not exist.
    pub fn ensure_bootstrap_token(&self, id: &str, secret: &str) -> Result<(), ApiError> {
        let r = resources::find("", "v1", "secrets").unwrap();
        let b64 = |v: &str| kr_fmt::base64::encode(v.as_bytes());
        let body = alloc::format!(
            r#"{{"metadata":{{"name":"bootstrap-token-{id}"}},"type":"bootstrap.kubernetes.io/token","data":{{"token-id":"{}","token-secret":"{}","usage-bootstrap-authentication":"{}","auth-extra-groups":"{}"}}}}"#,
            b64(id),
            b64(secret),
            b64("true"),
            b64("system:bootstrappers:kr:default-node-token")
        );
        self.bootstrap_object(r, Some("kube-system"), &alloc::format!("bootstrap-token-{id}"), "Secret", &body);
        self.sync()
    }

    /// Bootstrap token authentication (`<6 [a-z0-9]>.<16 [a-z0-9]>`).
    fn bootstrap_user(&self, token: &str) -> Option<User> {
        let (id, secret) = token.split_once('.')?;
        let ok = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        if !ok(id, 6) || !ok(secret, 16) {
            return None;
        }
        let r = resources::find("", "v1", "secrets").unwrap();
        let kv = self.store.borrow().get(&r.key(Some("kube-system"), &alloc::format!("bootstrap-token-{id}")))?;
        let sec = json::parse(&kv.value).ok()?;
        if sec.get("type").and_then(Value::as_str) != Some("bootstrap.kubernetes.io/token") {
            return None;
        }
        let field = |f: &str| sec.pointer(&["data", f]).and_then(Value::as_str).and_then(|v| kr_fmt::base64::decode(v).ok()).and_then(|b| String::from_utf8(b).ok());
        if !kr_crypto::ct_eq(field("token-secret")?.as_bytes(), secret.as_bytes()) || field("usage-bootstrap-authentication").as_deref() != Some("true") {
            return None;
        }
        if let Some(exp) = field("expiration").and_then(|e| crate::printers::parse_rfc3339(&e)) {
            if (self.now)() > exp {
                return None;
            }
        }
        let mut groups = alloc::vec![String::from("system:bootstrappers")];
        groups.extend(field("auth-extra-groups").unwrap_or_default().split(',').filter(|g| g.starts_with("system:bootstrappers:")).map(String::from));
        groups.push("system:authenticated".into());
        Some(User { name: alloc::format!("system:bootstrap:{id}"), groups })
    }

    /// `POST /kr/join`: a bootstrapping node exchanges its public keys for a client
    /// certificate (`system:node:<name>` in `system:nodes`) and a kubelet serving certificate.
    /// A node authenticated by its current certificate may call it again to rotate (new
    /// keys, same name).
    fn join(&self, req: &Req, user: &User) -> R<Reply> {
        let renewing = crate::node_authz::node_name(&user.name, &user.groups);
        if renewing.is_none() && !user.groups.iter().any(|g| g == "system:bootstrappers") {
            return Err(ApiError::new(403, "Forbidden", "join requires a bootstrap token or a node certificate"));
        }
        let b = self.parse_body(req)?;
        let name = b.get("nodeName").and_then(Value::as_str).filter(|n| object::is_dns_subdomain(n)).ok_or_else(|| ApiError::invalid("nodeName must be a DNS subdomain"))?;
        if renewing.is_some_and(|n| n != name) {
            return Err(ApiError::new(403, "Forbidden", "a node may only renew its own certificates"));
        }
        let key = |f: &str| -> R<kr_crypto::x509::PublicKey> {
            let der = b.get(f).and_then(Value::as_str).and_then(|v| kr_fmt::base64::decode(v).ok()).ok_or_else(|| ApiError::invalid(alloc::format!("{f}: base64 SPKI required")))?;
            match kr_crypto::x509::PublicKey::from_spki(&der) {
                Ok(Some(k @ (kr_crypto::x509::PublicKey::P256(_) | kr_crypto::x509::PublicKey::Ed25519(_)))) => Ok(k),
                _ => Err(ApiError::invalid(alloc::format!("{f}: unsupported key"))),
            }
        };
        let (client_key, serving_key) = (key("clientKey")?, key("servingKey")?);
        let ips: Vec<Vec<u8>> = b.get("addresses").and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(Value::as_str).filter_map(object::parse_ipv4).map(|a| a.to_vec()).collect();
        let guard = self.ca.borrow();
        let (ca_name, ca_key, ca_der) = guard.as_ref().ok_or_else(|| ApiError::new(503, "ServiceUnavailable", "node joining is not enabled"))?;
        let now = (self.now)();
        let mut serial = [0u8; 16];
        (self.rng)(&mut serial);
        let subject = kr_crypto::x509::Name { common_name: alloc::format!("system:node:{name}"), organizations: alloc::vec!["system:nodes".into()] };
        let mut p = kr_crypto::x509::CertParams { serial, subject, not_before: now - (self.node_cert_secs.get() / 10).min(300), not_after: now + self.node_cert_secs.get(), is_ca: false, server: false, client: true, dns_names: Vec::new(), ip_addrs: Vec::new(), public_key: client_key };
        let client = kr_crypto::x509::issue(&p, ca_name, ca_key);
        (self.rng)(&mut p.serial);
        p.client = false;
        p.server = true;
        p.dns_names = alloc::vec![name.to_string()];
        p.ip_addrs = ips;
        p.public_key = serving_key;
        let serving = kr_crypto::x509::issue(&p, ca_name, ca_key);
        let pem = |d: &[u8]| kr_crypto::x509::pem_encode("CERTIFICATE", d);
        let mut out = String::from("{\"clientCert\":");
        json::write_str(&pem(&client), &mut out);
        out.push_str(",\"servingCert\":");
        json::write_str(&pem(&serving), &mut out);
        out.push_str(",\"ca\":");
        json::write_str(&pem(ca_der), &mut out);
        out.push('}');
        Ok(Reply::Json(200, out))
    }

    pub fn set_node_proxy(&self, p: alloc::rc::Rc<dyn NodeProxy>) {
        *self.node_proxy.borrow_mut() = Some(p);
    }

    /// Enables ServiceAccount tokens (TokenRequest, bearer auth, admission) and creates the
    /// bootstrap RBAC policy and kube-root-ca.crt ConfigMaps.
    pub fn set_service_accounts(&self, signer: crate::tokens::Signer, ca_pem: String) -> Result<(), ApiError> {
        *self.sa.borrow_mut() = Some((signer, ca_pem));
        let crr = resources::find("rbac.authorization.k8s.io", "v1", "clusterroles").unwrap();
        let crbr = resources::find("rbac.authorization.k8s.io", "v1", "clusterrolebindings").unwrap();
        for (name, rules) in crate::rbac::bootstrap_roles() {
            let body = alloc::format!(r#"{{"metadata":{{"name":"{name}","labels":{{"kubernetes.io/bootstrapping":"rbac-defaults"}}}},"rules":{rules}}}"#);
            self.bootstrap_object(crr, None, name, "ClusterRole", &body);
        }
        for (name, role, subjects) in crate::rbac::bootstrap_bindings() {
            let body = alloc::format!(r#"{{"metadata":{{"name":"{name}","labels":{{"kubernetes.io/bootstrapping":"rbac-defaults"}}}},"roleRef":{{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"{role}"}},"subjects":{subjects}}}"#);
            self.bootstrap_object(crbr, None, name, "ClusterRoleBinding", &body);
        }
        // The default ServiceCIDR (the allocator's range) and the mandatory API priority and
        // fairness objects; kr does not enforce APF, these exist for API clients.
        let scr = resources::find("networking.k8s.io", "v1", "servicecidrs").unwrap();
        self.bootstrap_object(scr, None, "kubernetes", "ServiceCIDR", r#"{"metadata":{"name":"kubernetes"},"spec":{"cidrs":["10.96.0.0/16"]},"status":{"conditions":[{"type":"Ready","status":"True","reason":"","message":"Kubernetes Service CIDR is ready","lastTransitionTime":"1970-01-01T00:00:00Z"}]}}"#);
        let plr = resources::find("flowcontrol.apiserver.k8s.io", "v1", "prioritylevelconfigurations").unwrap();
        let fsr = resources::find("flowcontrol.apiserver.k8s.io", "v1", "flowschemas").unwrap();
        let mandatory = r#"{"apf.kubernetes.io/autoupdate-spec":"true"}"#;
        self.bootstrap_object(plr, None, "exempt", "PriorityLevelConfiguration", &alloc::format!(r#"{{"metadata":{{"name":"exempt","annotations":{mandatory}}},"spec":{{"type":"Exempt","exempt":{{"nominalConcurrencyShares":0,"lendablePercent":0}}}}}}"#));
        self.bootstrap_object(plr, None, "catch-all", "PriorityLevelConfiguration", &alloc::format!(r#"{{"metadata":{{"name":"catch-all","annotations":{mandatory}}},"spec":{{"type":"Limited","limited":{{"nominalConcurrencyShares":5,"lendablePercent":0,"limitResponse":{{"type":"Reject"}}}}}}}}"#));
        self.bootstrap_object(fsr, None, "exempt", "FlowSchema", &alloc::format!(r#"{{"metadata":{{"name":"exempt","annotations":{mandatory}}},"spec":{{"priorityLevelConfiguration":{{"name":"exempt"}},"matchingPrecedence":1,"rules":[{{"subjects":[{{"kind":"Group","group":{{"name":"system:masters"}}}}],"resourceRules":[{{"verbs":["*"],"apiGroups":["*"],"resources":["*"],"clusterScope":true,"namespaces":["*"]}}],"nonResourceRules":[{{"verbs":["*"],"nonResourceURLs":["*"]}}]}}]}}}}"#));
        self.bootstrap_object(fsr, None, "catch-all", "FlowSchema", &alloc::format!(r#"{{"metadata":{{"name":"catch-all","annotations":{mandatory}}},"spec":{{"priorityLevelConfiguration":{{"name":"catch-all"}},"matchingPrecedence":10000,"distinguisherMethod":{{"type":"ByUser"}},"rules":[{{"subjects":[{{"kind":"Group","group":{{"name":"system:unauthenticated"}}}},{{"kind":"Group","group":{{"name":"system:authenticated"}}}}],"resourceRules":[{{"verbs":["*"],"apiGroups":["*"],"resources":["*"],"clusterScope":true,"namespaces":["*"]}}],"nonResourceRules":[{{"verbs":["*"],"nonResourceURLs":["*"]}}]}}]}}}}"#));
        let scr = resources::find("storage.k8s.io", "v1", "storageclasses").unwrap();
        self.bootstrap_object(scr, None, "local-path", "StorageClass", r#"{"metadata":{"name":"local-path","annotations":{"storageclass.kubernetes.io/is-default-class":"true"}},"provisioner":"kr.io/local-path","reclaimPolicy":"Delete","volumeBindingMode":"WaitForFirstConsumer"}"#);
        let nsr = resources::find("", "v1", "namespaces").unwrap();
        let (namespaces, _) = self.store.borrow().list(&nsr.prefix(), None, 0);
        for kv in namespaces {
            if let Some(name) = kv.key.rsplit('/').next() {
                self.ensure_root_ca(name);
            }
        }
        self.sync()
    }

    /// Creates an object if missing (bootstrap data; never overwrites user changes).
    fn bootstrap_object(&self, res: &Resource, ns: Option<&str>, name: &str, kind: &str, body: &str) {
        let key = res.key(ns, name);
        if self.store.borrow().get(&key).is_some() {
            return;
        }
        let Ok(mut o) = json::parse(body.as_bytes()) else { return };
        let gv = res.group_version();
        let t = Target { api_version: &gv, kind, namespace: ns, name_is_label: false };
        let rev = self.store.borrow().revision() + 1;
        if object::prepare_create(&mut o, &t, &self.clock(), rev).is_ok() {
            let _ = self.store.borrow_mut().create(&key, json::to_string(&o).into_bytes());
        }
    }

    /// The `kube-root-ca.crt` ConfigMap every namespace gets (root CA publisher).
    fn ensure_root_ca(&self, ns: &str) {
        let Some(pem) = self.sa.borrow().as_ref().map(|(_, p)| p.clone()) else { return };
        let cm = resources::find("", "v1", "configmaps").unwrap();
        let mut body = String::from(r#"{"metadata":{"name":"kube-root-ca.crt"},"data":{"ca.crt":"#);
        json::write_str(&pem, &mut body);
        body.push_str("}}");
        self.bootstrap_object(cm, Some(ns), "kube-root-ca.crt", "ConfigMap", &body);
    }

    /// Client certificate user, else a valid ServiceAccount token, else anonymous.
    pub(crate) fn authenticate(&self, req: &Req) -> R<User> {
        if let Some(u) = &req.user {
            return Ok(u.clone());
        }
        let Some(token) = req.bearer else {
            return Ok(User { name: "system:anonymous".into(), groups: alloc::vec!["system:unauthenticated".into()] });
        };
        let unauthorized = || ApiError::new(401, "Unauthorized", "Unauthorized");
        if let Some(u) = self.bootstrap_user(token) {
            return Ok(u);
        }
        let sa = self.sa.borrow();
        let (signer, _) = sa.as_ref().ok_or_else(unauthorized)?;
        let c = signer.verify(token, (self.now)()).ok_or_else(unauthorized)?;
        if !c.audiences.iter().any(|a| crate::tokens::API_AUDIENCES.contains(&a.as_str())) {
            return Err(unauthorized());
        }
        // Revocation: the ServiceAccount (and a bound pod) must still exist with the same uid.
        let store = self.store.borrow();
        let uid_of = |plural: &str, name: &str| -> Option<String> {
            let r = resources::find("", "v1", plural)?;
            let kv = store.get(&r.key(Some(&c.namespace), name))?;
            json::parse(&kv.value).ok()?.pointer(&["metadata", "uid"]).and_then(Value::as_str).map(String::from)
        };
        if uid_of("serviceaccounts", &c.sa_name).as_deref() != Some(c.sa_uid.as_str()) {
            return Err(unauthorized());
        }
        if let Some((pod, puid)) = &c.pod {
            if uid_of("pods", pod).as_deref() != Some(puid.as_str()) {
                return Err(unauthorized());
            }
        }
        Ok(User {
            name: alloc::format!("system:serviceaccount:{}:{}", c.namespace, c.sa_name),
            groups: alloc::vec!["system:serviceaccounts".into(), alloc::format!("system:serviceaccounts:{}", c.namespace), "system:authenticated".into()],
        })
    }

    /// RBAC decision for `a` (system:masters short-circuits).
    /// `body_name`: the created object's name, for POSTs (node identities only).
    fn authorize(&self, user: &User, a: &crate::rbac::Attrs, body_name: Option<&str>) -> bool {
        use crate::node_authz::Decision;
        if is_masters(user) {
            return true;
        }
        if let Some(node) = crate::node_authz::node_name(&user.name, &user.groups) {
            match crate::node_authz::decide(node, a, body_name, &StorePods(self)) {
                Decision::Allow => return true,
                Decision::Deny => return false,
                Decision::NoOpinion => {}
            }
        }
        let store = self.store.borrow();
        let list = |group: &str, plural: &str, ns: Option<&str>| -> Vec<Value> {
            let Some(r) = resources::find(group, "v1", plural) else { return Vec::new() };
            let prefix = match ns {
                Some(n) => alloc::format!("{}{n}/", r.prefix()),
                None => r.prefix(),
            };
            store.list(&prefix, None, 0).0.iter().filter_map(|kv| json::parse(&kv.value).ok()).collect()
        };
        let rbac = "rbac.authorization.k8s.io";
        let crbs = list(rbac, "clusterrolebindings", None);
        let rbs = if a.namespace.is_empty() { Vec::new() } else { list(rbac, "rolebindings", Some(&a.namespace)) };
        let lookup = |kind: &str, ns: &str, name: &str| -> Option<Vec<Value>> {
            let (plural, nsopt) = if kind == "Role" { ("roles", Some(ns)) } else { ("clusterroles", None) };
            let r = resources::find(rbac, "v1", plural)?;
            let kv = store.get(&r.key(nsopt, name))?;
            json::parse(&kv.value).ok()?.get("rules").and_then(Value::as_array).map(|a| a.to_vec())
        };
        crate::rbac::allowed(user, a, &crbs, &rbs, &lookup)
    }

    fn forbidden(user: &User, a: &crate::rbac::Attrs) -> ApiError {
        let what = if a.resource_request {
            let res = if a.subresource.is_empty() { a.resource.clone() } else { alloc::format!("{}/{}", a.resource, a.subresource) };
            let scope = if a.namespace.is_empty() { String::from("at the cluster scope") } else { alloc::format!("in the namespace \"{}\"", a.namespace) };
            alloc::format!("cannot {} resource \"{res}\" in API group \"{}\" {scope}", a.verb, a.api_group)
        } else {
            alloc::format!("cannot {} path \"{}\"", a.verb, a.path)
        };
        ApiError::new(403, "Forbidden", alloc::format!("User \"{}\" {what}", user.name))
    }

    fn clock(&self) -> Clock {
        Clock { now: (self.now)(), rng: self.rng }
    }

    pub fn handle(&self, req: &Req) -> Reply {
        let (reply, warnings) = self.handle_w(req);
        match reply {
            Reply::Json(code, body) if !warnings.is_empty() => {
                let mut r = kr_net::http1::server::Response::new(code, body.into_bytes()).with_header("Content-Type", "application/json");
                for w in warnings {
                    let esc = w.replace('\\', "\\\\").replace('"', "\\\"");
                    r = r.with_header("Warning", &alloc::format!("299 - \"{esc}\""));
                }
                Reply::Http(r)
            }
            r => r,
        }
    }

    /// Like [`Self::handle`], with the `fieldValidation` warnings returned apart from the reply.
    pub(crate) fn handle_w(&self, req: &Req) -> (Reply, Vec<String>) {
        let write = matches!(req.method, "POST" | "PUT" | "PATCH");
        let mode = if write { crate::fieldval::Mode::parse(Query::parse(req.query).ok().as_ref().and_then(|q| q.get("fieldValidation"))) } else { crate::fieldval::Mode::Ignore };
        self.fv_mode.set(mode);
        self.warnings.borrow_mut().clear();
        let reply = match self.route(req) {
            Ok(r) => r,
            Err(e) => Reply::err(e),
        };
        self.fv_mode.set(crate::fieldval::Mode::Ignore);
        (reply, core::mem::take(&mut *self.warnings.borrow_mut()))
    }

    /// Applies `fieldValidation` to unknown/duplicate field messages: reject (Strict), warn
    /// (Warn) or ignore.
    fn fv_report(&self, msgs: Vec<String>) -> R<()> {
        if msgs.is_empty() {
            return Ok(());
        }
        match self.fv_mode.get() {
            crate::fieldval::Mode::Ignore => Ok(()),
            crate::fieldval::Mode::Warn => {
                self.warnings.borrow_mut().extend(msgs);
                Ok(())
            }
            crate::fieldval::Mode::Strict => Err(ApiError::bad_request(alloc::format!("strict decoding error: {}", msgs.join(", ")))),
        }
    }

    /// Unknown fields of a built-in kind's object (those `old` already had are not reported).
    fn fv_builtin(&self, rt: &Route, new: &Value, old: Option<&Value>) -> R<()> {
        if self.fv_mode.get() == crate::fieldval::Mode::Ignore {
            return Ok(());
        }
        let gv = rt.res.group_version();
        let Some(u) = crate::fieldval::unknown_builtin(&gv, rt.res.kind, new) else { return Ok(()) };
        let o = old.and_then(|o| crate::fieldval::unknown_builtin(&gv, rt.res.kind, o)).unwrap_or_default();
        self.fv_report(crate::fieldval::messages(u, &o))
    }

    /// Parses a resource URL (for the webhook layer).
    pub(crate) fn wh_route(&self, path: &str) -> Option<Route> {
        let path = path.trim_end_matches('/');
        let segs: Vec<&str> = path.split('/').skip(1).collect();
        let extra = self.extra();
        match segs.as_slice() {
            ["api", "v1", rest @ ..] if !rest.is_empty() => parse_route(&extra, "", "v1", rest),
            ["apis", g, v, rest @ ..] if !rest.is_empty() => parse_route(&extra, g, v, rest),
            _ => None,
        }
    }

    /// A stored object by plural/namespace/name (core or any group).
    pub(crate) fn wh_object(&self, group: &str, version: &str, plural: &str, ns: Option<&str>, name: &str) -> Option<Value> {
        let r = resources::find(group, version, plural)?;
        json::parse(&self.store.borrow().get(&r.key(ns, name))?.value).ok()
    }

    /// All stored objects of a cluster-scoped kind.
    pub(crate) fn wh_list(&self, group: &str, version: &str, plural: &str) -> Vec<Value> {
        let Some(r) = resources::find(group, version, plural) else { return Vec::new() };
        let (items, _) = self.store.borrow().list(&r.prefix(), None, 0);
        items.iter().filter_map(|kv| json::parse(&kv.value).ok()).collect()
    }

    pub(crate) fn wh_uid(&self) -> String {
        object::uuid4(self.rng)
    }

    fn route(&self, req: &Req) -> R<Reply> {
        let path = req.path.trim_end_matches('/');
        let user = self.authenticate(req)?;
        // Node bootstrap endpoints (outside RBAC: the CA is public; join checks its caller).
        if path == "/cacerts" && req.method == "GET" {
            let pem = self.ca.borrow().as_ref().map(|(_, _, der)| kr_crypto::x509::pem_encode("CERTIFICATE", der)).ok_or_else(|| ApiError::not_found("cacerts", "ca"))?;
            return Ok(Reply::Json(200, pem));
        }
        if path == "/kr/join" && req.method == "POST" {
            return self.join(req, &user);
        }
        let q = Query::parse(req.query)?;
        let segs: Vec<&str> = path.split('/').skip(1).collect();
        // Resource URL? Then authorize on resource attributes; otherwise on the path.
        let extra = self.extra();
        let resource = match segs.as_slice() {
            ["api", "v1", rest @ ..] if !rest.is_empty() => parse_route(&extra, "", "v1", rest),
            ["apis", g, v, rest @ ..] if !rest.is_empty() => parse_route(&extra, g, v, rest),
            _ => None,
        };
        let attrs = match &resource {
            Some(rt) => crate::rbac::Attrs {
                verb: req.authz_verb.map(String::from).unwrap_or_else(|| crate::rbac::verb(req.method, rt.name.is_some(), q.flag("watch"))),
                api_group: rt.res.group.into(),
                resource: rt.res.plural.into(),
                subresource: rt.sub.clone().unwrap_or_default(),
                namespace: rt.namespace.clone().unwrap_or_default(),
                name: rt.name.clone().unwrap_or_default(),
                resource_request: true,
                path: String::new(),
            },
            // Review APIs are virtual resources (create-only, not in the storage table).
            None if path.starts_with("/apis/authorization.k8s.io/v1/") || path.starts_with("/apis/authentication.k8s.io/v1/") => crate::rbac::Attrs {
                verb: "create".into(),
                api_group: segs.get(1).copied().unwrap_or("").into(),
                resource: segs.last().copied().unwrap_or("").into(),
                resource_request: true,
                ..Default::default()
            },
            None => crate::rbac::Attrs { verb: req.method.to_ascii_lowercase(), path: if path.is_empty() { "/".into() } else { path.into() }, ..Default::default() },
        };
        let body_name = match &resource {
            Some(rt) if req.method == "POST" && crate::node_authz::node_name(&user.name, &user.groups).is_some() => {
                self.parse_body(req).ok().and_then(|v| v.pointer(&["metadata", "name"]).and_then(Value::as_str).map(String::from)).or_else(|| rt.name.clone())
            }
            _ => None,
        };
        if !self.authorize(&user, &attrs, body_name.as_deref()) {
            if user.name == "system:anonymous" {
                return Err(ApiError::new(401, "Unauthorized", "Unauthorized"));
            }
            return Err(Self::forbidden(&user, &attrs));
        }
        match path {
            "/healthz" | "/livez" | "/readyz" => return Ok(Reply::Json(200, String::from("\"ok\""))),
            "/version" => {
                return Ok(Reply::ok(&obj(alloc::vec![
                    ("major", Value::from("1")),
                    ("minor", Value::from("37")),
                    ("gitVersion", Value::from(self.version.as_str())),
                    ("platform", Value::from(if cfg!(target_arch = "aarch64") { "linux/arm64" } else { "linux/amd64" })),
                ])))
            }
            _ => {}
        }
        match segs.as_slice() {
            [".well-known", "openid-configuration"] => {
                return Ok(Reply::Json(200, alloc::format!(
                    r#"{{"issuer":"{iss}","jwks_uri":"{iss}/openid/v1/jwks","response_types_supported":["id_token"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["ES256"]}}"#,
                    iss = crate::tokens::ISSUER
                )))
            }
            ["openid", "v1", "jwks"] => {
                return self.sa.borrow().as_ref().map(|(s, _)| Reply::Json(200, s.jwks())).ok_or_else(|| ApiError::not_found("jwks", "jwks"));
            }
            ["apis", "authorization.k8s.io", "v1", "selfsubjectaccessreviews"] if req.method == "POST" => return self.self_subject_access_review(req, &user),
            ["api"] | ["apis"] if req.method == "GET" && discovery::negotiate(req.accept) != discovery::Negotiated::Legacy => return Ok(Reply::aggregated_discovery(req, &extra, segs.len() == 1 && segs[0] == "api")),
            ["api"] => return Ok(Reply::Json(200, discovery::core_versions(&self.server_address))),
            ["api", "v1"] => return Ok(Reply::Json(200, discovery::resource_list(&extra, "", "v1").unwrap())),
            ["apis"] => return Ok(Reply::Json(200, discovery::group_list(&extra))),
            ["openapi", "v3"] => return Ok(Reply::Json(200, crate::openapi::index(&extra))),
            ["openapi", "v3", rest @ ..] => {
                let p = rest.join("/");
                return crate::openapi::group_version(&extra, &p).map(|b| Reply::Json(200, b)).ok_or_else(|| ApiError::not_found("openapi", &p));
            }
            ["apis", g] => return discovery::group(&extra, g).map(|b| Reply::Json(200, b)).ok_or_else(|| ApiError::not_found("group", g)),
            ["apis", g, v] => return discovery::resource_list(&extra, g, v).map(|b| Reply::Json(200, b)).ok_or_else(|| ApiError::not_found("groupVersion", v)),
            _ => {}
        }
        let (group, version, rest) = match segs.as_slice() {
            ["api", "v1", rest @ ..] => ("", "v1", rest),
            ["apis", g, v, rest @ ..] => (*g, *v, rest),
            _ => return Err(ApiError::not_found("path", path)),
        };
        let _ = (group, version, rest);
        let route = resource.ok_or_else(|| ApiError::not_found("path", path))?;
        let reply = self.dispatch(req, &route, &q)?;
        Ok(self.convert_reply(&route, reply))
    }

    fn dispatch(&self, req: &Req, rt: &Route, q: &Query) -> R<Reply> {
        let sub = rt.sub.as_deref();
        if let Some(s) = sub {
            if !rt.res.subresources.contains(&s) {
                return Err(ApiError::not_found("subresource", s));
            }
        }
        match (req.method, &rt.name, sub) {
            ("GET" | "POST", Some(n), Some(sub @ ("log" | "exec" | "attach" | "portforward"))) => {
                let (_, pod) = self.get_value(rt, n)?;
                let node = pod.pointer(&["spec", "nodeName"]).and_then(Value::as_str).unwrap_or("").to_string();
                if node.is_empty() {
                    return Err(ApiError::bad_request(alloc::format!("pod {n} is not scheduled to a node yet")));
                }
                let node_ip = resources::find("", "v1", "nodes")
                    .and_then(|r| self.store.borrow().get(&r.key(None, &node)))
                    .and_then(|kv| json::parse(&kv.value).ok())
                    .and_then(|v| {
                        v.pointer(&["status", "addresses"])?.as_array()?.iter().find(|a| a.get("type").and_then(Value::as_str) == Some("InternalIP"))?.get("address")?.as_str().and_then(object::parse_ipv4)
                    });
                let proxy = self.node_proxy.borrow().clone().ok_or_else(|| ApiError::new(503, "ServiceUnavailable", "no node agent to serve this request"))?;
                let ns = rt.namespace.clone().unwrap_or_default();
                proxy.pod_subresource(sub, &ns, n, &node, node_ip, req.query, req.headers).map(Reply::Http)
            }
            ("GET", None, None) if q.flag("watch") => self.watch(rt, q),
            ("GET", None, None) => self.list(req, rt, q),
            ("GET", Some(n), Some("scale")) => self.get_scale(rt, n),
            ("GET", Some(n), None) if wants_table(req.accept) => {
                let kv = self.get_kv(rt, n)?;
                let rev = self.store.borrow().revision();
                Ok(Reply::Json(200, self.table(rt.res, &[kv], rev, None)))
            }
            ("GET", Some(n), _) => {
                let (_, v) = self.get_value(rt, n)?;
                Ok(Reply::ok(&v))
            }
            ("POST", None, None) => self.create(req, rt, q),
            ("POST", Some(n), Some("binding")) => self.bind(req, rt, n),
            ("POST", Some(n), Some("token")) => self.token_request(req, rt, n),
            ("PUT", Some(n), Some("scale")) => self.update_scale(req, rt, n, false),
            ("PATCH", Some(n), Some("scale")) => self.update_scale(req, rt, n, true),
            ("PUT", Some(n), Some("ephemeralcontainers")) => {
                let (kv, old) = self.get_value(rt, n)?;
                let mut new = self.parse_body(req)?;
                eph_only(&old, &mut new)?;
                self.update(req, rt, n, false, q, Some((kv, old, new)))
            }
            ("PATCH", Some(n), Some("ephemeralcontainers")) => self.patch(req, rt, n, false, q, true),
            ("PUT", Some(n), s) => self.update(req, rt, n, s == Some("status"), q, None),
            ("PATCH", Some(n), s) => self.patch(req, rt, n, s == Some("status"), q, false),
            ("DELETE", Some(n), None) => self.delete(req, rt, n, q),
            ("DELETE", None, None) => self.delete_collection(rt, q),
            _ => Err(ApiError::new(405, "MethodNotAllowed", alloc::format!("method {} not allowed here", req.method))),
        }
    }

    // ---- reads ----

    fn get_kv(&self, rt: &Route, name: &str) -> R<Kv> {
        self.store.borrow().get(&rt.res.key(rt.namespace.as_deref(), name)).ok_or_else(|| ApiError::not_found(rt.res.singular, name))
    }

    pub(crate) fn get_value(&self, rt: &Route, name: &str) -> R<(Kv, Value)> {
        let kv = self.get_kv(rt, name)?;
        let v = json::parse(&kv.value).map_err(|_| ApiError::new(500, "InternalError", "stored object is corrupt"))?;
        Ok((kv, v))
    }

    fn list_prefix(&self, rt: &Route) -> String {
        match &rt.namespace {
            Some(ns) if rt.res.namespaced => alloc::format!("{}{ns}/", rt.res.prefix()),
            _ => rt.res.prefix(),
        }
    }

    fn list(&self, req: &Req, rt: &Route, q: &Query) -> R<Reply> {
        let ls = Selector::parse(q.get("labelSelector").unwrap_or(""))?;
        let fs = FieldSelector::parse(q.get("fieldSelector").unwrap_or(""))?;
        let limit: usize = q.get("limit").and_then(|l| l.parse().ok()).unwrap_or(0);
        let prefix = self.list_prefix(rt);
        let start_after = match q.get("continue").filter(|c| !c.is_empty()) {
            Some(c) => {
                let k = kr_fmt::base64::decode_url(c).ok().and_then(|b| String::from_utf8(b).ok()).ok_or_else(|| ApiError::bad_request("invalid continue token"))?;
                if !k.starts_with(&prefix) {
                    return Err(ApiError::bad_request("continue token does not match this list"));
                }
                Some(k)
            }
            None => None,
        };
        let store = self.store.borrow();
        let rev = store.revision();
        let mut items: Vec<Kv> = Vec::new();
        let mut cursor = start_after;
        let mut more = false;
        // Fetch in pages so selectors can filter without returning short pages early.
        loop {
            let want = if limit == 0 { 0 } else { (limit - items.len()).max(1) * 2 };
            let (page, has_more) = store.list(&prefix, cursor.as_deref(), want);
            for kv in &page {
                cursor = Some(kv.key.to_string());
                if !ls.is_empty() || !fs.is_empty() {
                    let Ok(v) = json::parse(&kv.value) else { continue };
                    if !ls.matches(&v) || !fs.matches(&v) {
                        continue;
                    }
                }
                items.push(kv.clone());
                if limit != 0 && items.len() == limit {
                    break;
                }
            }
            if limit != 0 && items.len() == limit {
                more = has_more || page.last().map(|k| &*k.key) != cursor.as_deref();
                more = more || store.list(&prefix, cursor.as_deref(), 1).0.len() == 1;
                break;
            }
            if !has_more {
                break;
            }
        }
        drop(store);
        let cont = if more { cursor.map(|c| kr_fmt::base64::encode_url(c.as_bytes())) } else { None };
        if wants_table(req.accept) {
            return Ok(Reply::Json(200, self.table(rt.res, &items, rev, cont.as_deref())));
        }
        // Splice the stored JSON directly: no re-encoding of items.
        let mut out = String::with_capacity(64 + items.iter().map(|k| k.value.len() + 1).sum::<usize>());
        out.push_str("{\"kind\":");
        json::write_str(&alloc::format!("{}List", rt.res.kind), &mut out);
        out.push_str(",\"apiVersion\":");
        json::write_str(&rt.res.group_version(), &mut out);
        out.push_str(",\"metadata\":{\"resourceVersion\":\"");
        out.push_str(&rev.to_string());
        out.push('"');
        if let Some(c) = &cont {
            out.push_str(",\"continue\":");
            json::write_str(c, &mut out);
        }
        out.push_str("},\"items\":[");
        for (i, kv) in items.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(core::str::from_utf8(&kv.value).unwrap_or("null"));
        }
        out.push_str("]}");
        Ok(Reply::Json(200, out))
    }

    fn table(&self, res: &Resource, items: &[Kv], rev: u64, cont: Option<&str>) -> String {
        let now = (self.now)();
        let col = |name: &str, ty: &str, fmt: &str, desc: &str, prio: u64| {
            obj(alloc::vec![("name", Value::from(name)), ("type", Value::from(ty)), ("format", Value::from(fmt)), ("description", Value::from(desc)), ("priority", Value::Number(Number::from_u64(prio)))])
        };
        let mut cols = alloc::vec![col("Name", "string", "name", "Name must be unique within a namespace.", 0)];
        let extra = crate::printers::columns(res.kind);
        for (n, _) in extra {
            cols.push(col(n, "string", "", "", 0));
        }
        cols.push(col("Age", "string", "", "CreationTimestamp", 0));
        let rows: Vec<Value> = items
            .iter()
            .filter_map(|kv| json::parse(&kv.value).ok())
            .map(|o| {
                let meta = o.get("metadata").cloned().unwrap_or(Value::Object(Vec::new()));
                let name = meta.get("name").and_then(Value::as_str).unwrap_or("").to_string();
                let mut cells = alloc::vec![Value::String(name)];
                for (_, f) in extra {
                    cells.push(Value::String(f(&o)));
                }
                let created = meta.get("creationTimestamp").and_then(Value::as_str).and_then(crate::printers::parse_rfc3339);
                cells.push(Value::String(created.map(|c| crate::printers::human_duration(now - c)).unwrap_or_else(|| "<unknown>".into())));
                let partial = obj(alloc::vec![("kind", Value::from("PartialObjectMetadata")), ("apiVersion", Value::from("meta.k8s.io/v1")), ("metadata", meta)]);
                obj(alloc::vec![("cells", Value::Array(cells)), ("object", partial)])
            })
            .collect();
        let mut meta = alloc::vec![("resourceVersion", Value::String(rev.to_string()))];
        if let Some(c) = cont {
            meta.push(("continue", Value::from(c)));
        }
        json::to_string(&obj(alloc::vec![
            ("kind", Value::from("Table")),
            ("apiVersion", Value::from("meta.k8s.io/v1")),
            ("metadata", obj(meta)),
            ("columnDefinitions", Value::Array(cols)),
            ("rows", Value::Array(rows)),
        ]))
    }

    // ---- writes ----

    fn parse_body(&self, req: &Req) -> R<Value> {
        self.parse_body_as(req, None)
    }

    fn parse_body_as(&self, req: &Req, fallback: Option<(&'static str, &'static str)>) -> R<Value> {
        let ct = req.content_type.unwrap_or("application/json");
        if ct.starts_with("application/cbor") {
            // No CBOR decoder; clients retry with JSON on 415.
            return Err(ApiError::new(415, "UnsupportedMediaType", alloc::format!("the body of the request was in an unknown format - accepted media types include: application/json, application/yaml, application/vnd.kubernetes.protobuf (got {ct})")));
        }
        let v = if ct.starts_with("application/vnd.kubernetes.protobuf") {
            proto::decode_body_as(req.body, fallback).map_err(|e| {
                if e == "protobuf: unsupported kind" {
                    ApiError::new(415, "UnsupportedMediaType", "protobuf is not supported for this kind; use application/json")
                } else {
                    ApiError::bad_request(e)
                }
            })?
        } else if ct.starts_with("application/yaml") || ct.starts_with("application/apply-patch+yaml") {
            let s = core::str::from_utf8(req.body).map_err(|_| ApiError::bad_request("body is not UTF-8"))?;
            kr_fmt::yaml::parse(s).map_err(|_| ApiError::bad_request("invalid YAML body"))?
        } else {
            json::parse(req.body).map_err(|_| ApiError::bad_request("invalid JSON body"))?
        };
        if v.has_duplicate_keys() && self.fv_mode.get() != crate::fieldval::Mode::Ignore {
            let mut d = Vec::new();
            crate::fieldval::duplicates(&v, "", &mut d);
            self.fv_report(d.into_iter().map(|p| alloc::format!("duplicate field \"{p}\"")).collect())?;
        }
        Ok(v)
    }

    fn target<'a>(&self, rt: &'a Route) -> (String, Target<'a>) {
        let gv = rt.res.group_version();
        // SAFETY of lifetimes: `gv` is returned alongside and the Target borrows it below.
        (gv, Target { api_version: "", kind: rt.res.kind, namespace: rt.namespace.as_deref().filter(|_| rt.res.namespaced), name_is_label: rt.res.name_is_label() })
    }

    fn check_namespace(&self, rt: &Route, creating_name: &str) -> R<()> {
        if !rt.res.namespaced {
            return Ok(());
        }
        let ns = rt.namespace.as_deref().ok_or_else(|| ApiError::bad_request("namespace is required"))?;
        let nsr = resources::find("", "v1", "namespaces").unwrap();
        let kv = self.store.borrow().get(&nsr.key(None, ns)).ok_or_else(|| ApiError::not_found("namespaces", ns))?;
        let v = json::parse(&kv.value).unwrap_or(Value::Null);
        if v.pointer(&["metadata", "deletionTimestamp"]).is_some() {
            return Err(ApiError::new(403, "Forbidden", alloc::format!("{} \"{creating_name}\" is forbidden: unable to create new content in namespace {ns} because it is being terminated", rt.res.singular)));
        }
        Ok(())
    }

    /// Writes buffered records to the log (page cache). Durability comes from [`Self::commit`],
    /// which the HTTP layer awaits before answering a write.
    fn sync(&self) -> R<()> {
        self.store.borrow_mut().write_out().map(|_| ()).map_err(|_| ApiError::new(500, "InternalError", "storage write failed"))
    }

    pub fn durable_rev(&self) -> u64 {
        self.committer.durable_rev()
    }

    /// The store's current revision (a request that advanced it wrote something).
    pub fn revision(&self) -> u64 {
        self.store.borrow().revision()
    }

    /// Resolves once every write up to `rev` is fsynced (group commit, fsync off the event loop).
    pub async fn commit(&self, rev: u64) -> Result<(), ()> {
        let fd = self.store.borrow().log_fd();
        let written = || self.store.borrow_mut().write_out().unwrap_or(0);
        if self.store.borrow_mut().write_out().is_err() {
            return Err(());
        }
        self.committer.wait(rev, fd, written).await
    }

    /// Rewrites the log into a snapshot when it has grown far beyond the live data. Blocking
    /// (snapshot write + fsyncs); call it rarely, from a background task.
    pub fn maybe_compact(&self) {
        let mut s = self.store.borrow_mut();
        if s.log_oversized() {
            let _ = s.compact(0);
        }
    }

    fn create(&self, req: &Req, rt: &Route, q: &Query) -> R<Reply> {
        let mut o = self.parse_body(req)?;
        self.create_value(&mut o, rt, q).map(|v| Reply::Json(201, json::to_string(&v)))
    }

    fn create_value(&self, o: &mut Value, rt: &Route, q: &Query) -> R<Value> {
        self.fv_builtin(rt, o, None)?;
        let (gv, mut t) = self.target(rt);
        t.api_version = &gv;
        let rev = self.store.borrow().revision() + 1;
        let name = object::prepare_create(o, &t, &self.clock(), rev)?;
        self.check_namespace(rt, &name)?;
        crate::defaults::apply(rt.res.group, rt.res.plural, o);
        let is_crd = crate::crd::is_crd(rt.res);
        if is_crd {
            crate::crd::admit(o, None, (self.now)())?;
        }
        self.admit_custom(rt, o, None, false)?;
        if rt.res.plural == "pods" {
            let ns = rt.namespace.clone().unwrap_or_default();
            self.admit_pod(o, &ns)?;
        }
        if rt.res.plural == "jobs" {
            admit_job(o, &name)?;
        }
        if rt.res.plural == "services" {
            self.admit_service(o, None)?;
        }
        if rt.res.plural == "nodes" {
            self.admit_node(o)?;
        }
        if rt.res.plural == "persistentvolumeclaims" {
            self.default_storage_class(o);
        }
        if rt.res.plural == "namespaces" {
            o.entry_object("spec").set("finalizers", Value::Array(alloc::vec![Value::from("kubernetes")]));
            o.entry_object("status").set("phase", Value::from("Active"));
        }
        if rt.res.plural == "resourcequotas" {
            crate::quota::validate(o).map_err(ApiError::invalid)?;
        }
        self.admit_quota(rt, o, None)?;
        if q.get("dryRun") == Some("All") {
            return Ok(o.clone());
        }
        let key = rt.res.key(rt.namespace.as_deref(), &name);
        let kv = self.store.borrow_mut().create(&key, json::to_string(o).into_bytes()).map_err(|e| store_err(e, rt.res.singular, &name))?;
        debug_assert_eq!(kv.mod_rev, rev);
        if is_crd {
            self.register_crd(o);
        }
        if rt.res.plural == "namespaces" {
            self.ensure_default_sa(&name);
            self.ensure_root_ca(&name);
            let _ = self.sync();
        }
        self.sync()?;
        Ok(o.clone())
    }

    /// PUT, or the final step of PATCH (`patched` carries the already-patched object).
    fn update(&self, req: &Req, rt: &Route, name: &str, status: bool, q: &Query, patched: Option<(Kv, Value, Value)>) -> R<Reply> {
        let (kv, old, mut new) = match patched {
            Some(p) => p,
            None => {
                let (kv, old) = self.get_value(rt, name)?;
                let new = self.parse_body(req)?;
                (kv, old, new)
            }
        };
        let (gv, mut t) = self.target(rt);
        t.api_version = &gv;
        let rev = self.store.borrow().revision() + 1;
        self.fv_builtin(rt, &new, Some(&old))?;
        let has_status = rt.res.subresources.contains(&"status");
        object::prepare_update(&old, &mut new, &t, rev, has_status, status)?;
        if !status {
            crate::defaults::apply(rt.res.group, rt.res.plural, &mut new);
        }
        if crate::crd::is_crd(rt.res) {
            crate::crd::admit(&mut new, Some(&old), (self.now)())?;
        }
        self.admit_custom(rt, &mut new, Some(&old), status)?;
        if rt.res.plural == "services" && !status {
            self.admit_service(&mut new, Some(&old))?;
        }
        if rt.res.plural == "resourcequotas" && !status {
            crate::quota::validate(&new).map_err(ApiError::invalid)?;
        }
        // Usage can change on update only for these kinds (a Service type/port change moves
        // nodeports/loadbalancers, a PVC may grow); pods fix their resources at create.
        if matches!(rt.res.plural, "services" | "persistentvolumeclaims") && !status {
            self.admit_quota(rt, &new, Some(&old))?;
        }
        if q.get("dryRun") == Some("All") {
            return Ok(Reply::ok(&new));
        }
        // Finalizers removed from an object that is being deleted: complete the deletion.
        let deleting = new.pointer(&["metadata", "deletionTimestamp"]).is_some();
        let no_finalizers = new.pointer(&["metadata", "finalizers"]).and_then(Value::as_array).is_none_or(|f| f.is_empty());
        let no_spec_finalizers = rt.res.plural != "namespaces" || new.pointer(&["spec", "finalizers"]).and_then(Value::as_array).is_none_or(|f| f.is_empty());
        if deleting && no_finalizers && no_spec_finalizers {
            self.store.borrow_mut().delete(&kv.key, Some(kv.mod_rev)).map_err(|e| store_err(e, rt.res.singular, name))?;
            self.sync()?;
            return Ok(Reply::ok(&new));
        }
        self.store.borrow_mut().update(&kv.key, json::to_string(&new).into_bytes(), Some(kv.mod_rev)).map_err(|e| store_err(e, rt.res.singular, name))?;
        if crate::crd::is_crd(rt.res) {
            self.register_crd(&new);
        }
        self.sync()?;
        Ok(Reply::ok(&new))
    }

    fn patch(&self, req: &Req, rt: &Route, name: &str, status: bool, q: &Query, eph: bool) -> R<Reply> {
        let ct = req.content_type.unwrap_or("");
        let p = self.parse_body(req)?;
        let existing = self.get_value(rt, name);
        if ct.starts_with("application/apply-patch") {
            // Server-side apply, simplified: create if absent, otherwise strategic-merge the
            // applied configuration (no managedFields/field ownership; KNOWN_ISSUES).
            if let Err(e) = &existing {
                if e.code == 404 {
                    let mut o = p;
                    return self.create_value(&mut o, rt, q).map(|v| Reply::Json(201, json::to_string(&v)));
                }
            }
        }
        let (kv, old) = existing?;
        let custom = self.custom.borrow().iter().any(|c| core::ptr::eq(c.res, rt.res));
        if custom && ct.starts_with("application/strategic-merge-patch+json") {
            return Err(ApiError::new(415, "UnsupportedMediaType", "the body of the request was in an unknown format - accepted media types include: application/json-patch+json, application/merge-patch+json, application/apply-patch+yaml"));
        }
        let mut new = old.clone();
        let r = if ct.starts_with("application/json-patch+json") {
            patch::json_patch(&mut new, &p)
        } else if ct.starts_with("application/merge-patch+json") {
            patch::merge_patch(&mut new, &p);
            Ok(())
        } else if custom && ct.starts_with("application/apply-patch") {
            patch::merge_patch(&mut new, &p);
            Ok(())
        } else if ct.starts_with("application/strategic-merge-patch+json") || ct.starts_with("application/apply-patch") {
            patch::strategic_merge(&mut new, &p)
        } else {
            return Err(ApiError::new(415, "UnsupportedMediaType", alloc::format!("unsupported patch type {ct:?}")));
        };
        r.map_err(|e| ApiError::invalid(e.0))?;
        if eph {
            eph_only(&old, &mut new)?;
        }
        // A patch never carries a resourceVersion precondition unless it sets one explicitly.
        if p.pointer(&["metadata", "resourceVersion"]).is_none() {
            if let Some(m) = new.get_mut("metadata") {
                m.remove("resourceVersion");
            }
        }
        self.update(req, rt, name, status, q, Some((kv, old, new)))
    }

    fn delete(&self, req: &Req, rt: &Route, name: &str, q: &Query) -> R<Reply> {
        let (kv, mut v) = self.get_value(rt, name)?;
        // DeleteOptions arrive as JSON or (client-go default for typed clients) protobuf.
        let opts = if req.body.is_empty() { Value::Null } else { self.parse_body_as(req, Some(("v1", "DeleteOptions"))).map_err(|e| ApiError::bad_request(alloc::format!("invalid DeleteOptions: {}", e.message)))? };
        {
            if let Some(pre) = opts.get("preconditions") {
                if let Some(uid) = pre.get("uid").and_then(Value::as_str) {
                    if v.pointer(&["metadata", "uid"]).and_then(Value::as_str) != Some(uid) {
                        return Err(ApiError::conflict(rt.res.singular, name));
                    }
                }
                if let Some(rv) = pre.get("resourceVersion").and_then(Value::as_str) {
                    if kv.mod_rev.to_string() != rv {
                        return Err(ApiError::conflict(rt.res.singular, name));
                    }
                }
            }
        }
        if q.get("dryRun") == Some("All") {
            return Ok(Reply::ok(&v));
        }
        if rt.res.plural == "namespaces" {
            return self.delete_namespace(&kv, v, name);
        }
        // Graceful pod deletion: a bound pod only gets a deletionTimestamp; its kubelet stops
        // the containers and then deletes it with gracePeriodSeconds=0.
        let grace = q.get("gracePeriodSeconds").and_then(|g| g.parse::<i64>().ok()).or_else(|| opts.get("gracePeriodSeconds").and_then(Value::as_i64));
        let bound = v.pointer(&["spec", "nodeName"]).and_then(Value::as_str).is_some_and(|n| !n.is_empty());
        if rt.res.plural == "pods" && bound && grace != Some(0) {
            if v.pointer(&["metadata", "deletionTimestamp"]).is_none() {
                let g = grace.or_else(|| v.pointer(&["spec", "terminationGracePeriodSeconds"]).and_then(Value::as_i64)).unwrap_or(30).max(1);
                let rev = self.store.borrow().revision() + 1;
                let m = v.entry_object("metadata");
                m.set("deletionTimestamp", Value::String(object::rfc3339((self.now)() + g)));
                m.set("deletionGracePeriodSeconds", Value::Number(Number::from_i64(g)));
                m.set("resourceVersion", Value::String(rev.to_string()));
                self.store.borrow_mut().update(&kv.key, json::to_string(&v).into_bytes(), Some(kv.mod_rev)).map_err(|e| store_err(e, rt.res.singular, name))?;
                self.sync()?;
            }
            return Ok(Reply::ok(&v));
        }
        let has_finalizers = v.pointer(&["metadata", "finalizers"]).and_then(Value::as_array).is_some_and(|f| !f.is_empty());
        if has_finalizers {
            if v.pointer(&["metadata", "deletionTimestamp"]).is_none() {
                let rev = self.store.borrow().revision() + 1;
                let m = v.entry_object("metadata");
                m.set("deletionTimestamp", Value::String(object::rfc3339((self.now)())));
                m.set("deletionGracePeriodSeconds", Value::Number(Number::from_u64(0)));
                m.set("resourceVersion", Value::String(rev.to_string()));
                self.store.borrow_mut().update(&kv.key, json::to_string(&v).into_bytes(), Some(kv.mod_rev)).map_err(|e| store_err(e, rt.res.singular, name))?;
                self.sync()?;
            }
            return Ok(Reply::Json(202, json::to_string(&v)));
        }
        self.store.borrow_mut().delete(&kv.key, Some(kv.mod_rev)).map_err(|e| store_err(e, rt.res.singular, name))?;
        if crate::crd::is_crd(rt.res) {
            self.unregister_crd(&v);
        }
        self.sync()?;
        Ok(Reply::ok(&v))
    }

    /// Namespace deletion (upstream semantics): the namespace only becomes `Terminating`
    /// (`deletionTimestamp`, `status.phase`). The namespace controller empties it and removes
    /// the `kubernetes` finalizer through `namespaces/{name}/finalize`; `update` then deletes it.
    fn delete_namespace(&self, kv: &Kv, mut v: Value, name: &str) -> R<Reply> {
        if SYSTEM_NAMESPACES.contains(&name) && name != "kube-public" {
            return Err(ApiError::new(403, "Forbidden", alloc::format!("namespace {name} is a system namespace and cannot be deleted")));
        }
        if v.pointer(&["metadata", "deletionTimestamp"]).is_some() {
            return Ok(Reply::ok(&v));
        }
        let rev = self.store.borrow().revision() + 1;
        let m = v.entry_object("metadata");
        m.set("deletionTimestamp", Value::String(object::rfc3339((self.now)())));
        m.set("deletionGracePeriodSeconds", Value::Number(Number::from_u64(0)));
        m.set("resourceVersion", Value::String(rev.to_string()));
        v.entry_object("status").set("phase", Value::from("Terminating"));
        self.store.borrow_mut().update(&kv.key, json::to_string(&v).into_bytes(), Some(kv.mod_rev)).map_err(|e| store_err(e, "namespace", name))?;
        self.sync()?;
        Ok(Reply::ok(&v))
    }

    fn delete_collection(&self, rt: &Route, q: &Query) -> R<Reply> {
        let ls = Selector::parse(q.get("labelSelector").unwrap_or(""))?;
        let fs = FieldSelector::parse(q.get("fieldSelector").unwrap_or(""))?;
        let prefix = self.list_prefix(rt);
        let (items, _) = self.store.borrow().list(&prefix, None, 0);
        let mut deleted = Vec::new();
        for kv in items {
            let Ok(v) = json::parse(&kv.value) else { continue };
            if ls.matches(&v) && fs.matches(&v) {
                if self.store.borrow_mut().delete(&kv.key, Some(kv.mod_rev)).is_ok() {
                    deleted.push(v);
                }
            }
        }
        self.sync()?;
        Ok(Reply::ok(&obj(alloc::vec![
            ("kind", Value::String(alloc::format!("{}List", rt.res.kind))),
            ("apiVersion", Value::String(rt.res.group_version())),
            ("metadata", obj(alloc::vec![("resourceVersion", Value::String(self.store.borrow().revision().to_string()))])),
            ("items", Value::Array(deleted)),
        ])))
    }

    /// `pods/binding`: assigns a node once (the scheduler's write path).
    fn bind(&self, req: &Req, rt: &Route, name: &str) -> R<Reply> {
        let b = self.parse_body(req)?;
        let node = b.pointer(&["target", "name"]).and_then(Value::as_str).filter(|n| !n.is_empty()).ok_or_else(|| ApiError::invalid("target.name is required"))?;
        let (kv, old) = self.get_value(rt, name)?;
        if old.pointer(&["spec", "nodeName"]).and_then(Value::as_str).is_some_and(|n| !n.is_empty()) {
            return Err(ApiError::new(409, "Conflict", alloc::format!("pod {name} is already assigned to a node")));
        }
        let mut new = old.clone();
        new.entry_object("spec").set("nodeName", Value::from(node));
        let rev = self.store.borrow().revision() + 1;
        new.entry_object("metadata").set("resourceVersion", Value::String(rev.to_string()));
        self.store.borrow_mut().update(&kv.key, json::to_string(&new).into_bytes(), Some(kv.mod_rev)).map_err(|e| store_err(e, "pod", name))?;
        self.sync()?;
        Ok(Reply::Json(201, json::to_string(&object::status_value(201, "", "Success"))))
    }

    /// Service defaulting and allocation: type, ports (protocol, targetPort), ClusterIP from
    /// the service CIDR, NodePorts. On update (`old`), allocated values are kept.
    fn admit_service(&self, o: &mut Value, old: Option<&Value>) -> R<()> {
        let spec = o.entry_object("spec");
        let ty = spec.get("type").and_then(Value::as_str).unwrap_or("ClusterIP").to_string();
        if !matches!(ty.as_str(), "ClusterIP" | "NodePort" | "LoadBalancer" | "ExternalName") {
            return Err(ApiError::invalid(alloc::format!("spec.type: Unsupported value: {ty:?}")));
        }
        spec.set("type", Value::from(ty.as_str()));
        if ty == "ExternalName" {
            if spec.get("externalName").and_then(Value::as_str).is_none_or(str::is_empty) {
                return Err(ApiError::invalid("spec.externalName: Required value"));
            }
            // No allocations for ExternalName (a type change releases them).
            for k in ["clusterIP", "clusterIPs", "ipFamilies", "ipFamilyPolicy", "internalTrafficPolicy"] {
                spec.remove(k);
            }
            if let Some(Value::Array(ports)) = spec.get_mut("ports") {
                for p in ports.iter_mut() {
                    p.remove("nodePort");
                }
            }
            return Ok(());
        }
        if spec.get("sessionAffinity").is_none() {
            spec.set("sessionAffinity", Value::from("None"));
        }
        for (k, v) in [("internalTrafficPolicy", "Cluster"), ("ipFamilyPolicy", "SingleStack")] {
            if spec.get(k).is_none() {
                spec.set(k, Value::from(v));
            }
        }
        spec.set("ipFamilies", Value::Array(alloc::vec![Value::from("IPv4")]));
        let ports = match spec.get_mut("ports") {
            Some(Value::Array(p)) if !p.is_empty() => p,
            _ => return Err(ApiError::invalid("spec.ports: Required value")),
        };
        let multi = ports.len() > 1;
        for p in ports.iter_mut() {
            let port = p.get("port").and_then(Value::as_u64).filter(|v| (1..=65535).contains(v)).ok_or_else(|| ApiError::invalid("spec.ports[].port: must be between 1 and 65535"))?;
            if multi && p.get("name").and_then(Value::as_str).is_none_or(str::is_empty) {
                return Err(ApiError::invalid("spec.ports[].name: Required value (multiple ports)"));
            }
            if p.get("protocol").is_none() {
                p.set("protocol", Value::from("TCP"));
            }
            if p.get("targetPort").is_none() {
                p.set("targetPort", Value::Number(Number::from_u64(port)));
            }
        }
        let old_spec = old.and_then(|o| o.get("spec"));
        // ClusterIP: immutable once set.
        let want = o.pointer(&["spec", "clusterIP"]).and_then(Value::as_str).unwrap_or("").to_string();
        let old_ip = old_spec.and_then(|s| s.get("clusterIP")).and_then(Value::as_str).map(String::from);
        let ip = match (old_ip, want.as_str()) {
            (Some(o), "") => o,
            (Some(o), w) if w != o => return Err(ApiError::invalid("spec.clusterIP: field is immutable")),
            (Some(o), _) => o,
            (None, "None") => "None".into(),
            (None, "") => self.allocate_cluster_ip()?,
            (None, w) => {
                let a = crate::object::parse_ipv4(w).ok_or_else(|| ApiError::invalid("spec.clusterIP: must be a valid IPv4 address"))?;
                if a[0] != 10 || a[1] != 96 {
                    return Err(ApiError::invalid("spec.clusterIP: not in the service CIDR 10.96.0.0/16"));
                }
                if self.cluster_ips_in_use().contains(&a) {
                    return Err(ApiError::invalid(alloc::format!("spec.clusterIP: Invalid value: {w:?}: provided IP is already allocated")));
                }
                w.into()
            }
        };
        let spec = o.get_mut("spec").unwrap();
        spec.set("clusterIP", Value::String(ip.clone()));
        spec.set("clusterIPs", Value::Array(alloc::vec![Value::String(ip)]));
        if ty == "NodePort" || ty == "LoadBalancer" {
            let mut used = self.node_ports_in_use();
            let old_ports: Vec<Value> = old_spec.and_then(|s| s.get("ports")).and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
            if let Some(Value::Array(ports)) = spec.get_mut("ports") {
                for p in ports.iter_mut() {
                    if p.get("nodePort").and_then(Value::as_u64).is_some() {
                        continue;
                    }
                    // Keep the previous allocation for the same port on updates.
                    let prev = old_ports.iter().find(|op| op.get("port") == p.get("port") && op.get("protocol") == p.get("protocol")).and_then(|op| op.get("nodePort")).and_then(Value::as_u64);
                    let np = match prev {
                        Some(n) => n as u16,
                        None => {
                            let n = (30000u16..=32767).find(|n| !used.contains(n)).ok_or_else(|| ApiError::new(422, "Invalid", "no free NodePorts"))?;
                            used.push(n);
                            n
                        }
                    };
                    p.set("nodePort", Value::Number(Number::from_u64(np as u64)));
                }
            }
        }
        Ok(())
    }

    /// Assigns each new Node a /24 of the cluster pod CIDR 10.88.0.0/16 (`spec.podCIDR`).
    /// DefaultStorageClass admission: a PVC without `storageClassName` (unset, not "") gets the
    /// default class (annotation `storageclass.kubernetes.io/is-default-class: "true"`).
    fn default_storage_class(&self, o: &mut Value) {
        if o.pointer(&["spec", "storageClassName"]).is_some() {
            return;
        }
        let Some(r) = resources::find("storage.k8s.io", "v1", "storageclasses") else { return };
        let (items, _) = self.store.borrow().list(&r.prefix(), None, 0);
        let mut names: Vec<String> = items
            .iter()
            .filter_map(|kv| json::parse(&kv.value).ok())
            .filter(|c| c.pointer(&["metadata", "annotations", "storageclass.kubernetes.io/is-default-class"]).and_then(Value::as_str) == Some("true"))
            .filter_map(|c| c.pointer(&["metadata", "name"]).and_then(Value::as_str).map(String::from))
            .collect();
        names.sort();
        if let Some(n) = names.into_iter().next() {
            o.entry_object("spec").set("storageClassName", Value::String(n));
        }
    }

    fn admit_node(&self, o: &mut Value) -> R<()> {
        if o.pointer(&["spec", "podCIDR"]).and_then(Value::as_str).is_some_and(|c| !c.is_empty()) {
            return Ok(());
        }
        let r = resources::find("", "v1", "nodes").unwrap();
        let (items, _) = self.store.borrow().list(&r.prefix(), None, 0);
        let used: Vec<String> = items.iter().filter_map(|kv| json::parse(&kv.value).ok()).filter_map(|n| n.pointer(&["spec", "podCIDR"]).and_then(Value::as_str).map(String::from)).collect();
        let cidr = (0u16..256).map(|i| alloc::format!("10.88.{i}.0/24")).find(|c| !used.contains(c)).ok_or_else(|| ApiError::new(422, "Invalid", "pod CIDR exhausted"))?;
        let spec = o.entry_object("spec");
        spec.set("podCIDR", Value::String(cidr.clone()));
        spec.set("podCIDRs", Value::Array(alloc::vec![Value::String(cidr)]));
        Ok(())
    }

    // ---- ResourceQuota admission ----

    /// ResourceQuota admission. On create (`old = None`) every quota whose scopes select the
    /// object must allow its usage (`used + usage <= hard`, else 403 Forbidden with the
    /// upstream message), and a tracked cpu/memory name the pod fails to specify is refused.
    /// On update only the usage delta matters — which is why only Services and PVCs re-enter
    /// admission here: they are the kinds whose usage an update can move.
    fn admit_quota(&self, rt: &Route, obj: &Value, old: Option<&Value>) -> R<()> {
        let Some(ns) = rt.namespace.as_deref() else { return Ok(()) };
        let qr = resources::find("", "v1", "resourcequotas").unwrap();
        let quotas: Vec<Value> = {
            let store = self.store.borrow();
            store.list(&alloc::format!("{}{ns}/", qr.prefix()), None, 0).0.iter().filter_map(|kv| json::parse(&kv.value).ok()).collect()
        };
        if quotas.is_empty() || quotas.iter().all(|q| crate::quota::hard(q).is_empty()) {
            return Ok(());
        }
        let deltas = match old {
            None => crate::quota::usage(rt.res.plural, rt.res.group, obj),
            Some(old) => crate::quota::delta(rt.res.plural, rt.res.group, obj, old),
        };
        for q in quotas {
            // "must specify" is decided before usage: without the resources named, the delta
            // cannot be charged (only meaningful on create, against scope-selecting quotas).
            if old.is_none() {
                let must = crate::quota::missing(&q, rt.res.plural, obj);
                if !must.is_empty() && crate::quota::matches_scopes(&q, rt.res.plural, obj) {
                    return Err(forbidden_obj(rt, obj, crate::quota::must_specify_msg(&q, &must)));
                }
            }
            let tracked: Vec<(String, Quantity)> = deltas.iter().filter(|(k, _)| crate::quota::tracked(&q, k)).cloned().collect();
            if tracked.is_empty() || !crate::quota::matches_scopes(&q, rt.res.plural, obj) {
                continue;
            }
            let names: Vec<String> = tracked.iter().map(|(n, _)| n.clone()).collect();
            let used = self.quota_usage(ns, &q, &names);
            let hard = crate::quota::hard(&q);
            for (k, d) in &tracked {
                let limit = hard.iter().find(|(h, _)| h == k).map(|(_, x)| *x).unwrap_or_else(crate::quota::zero);
                let have = used.iter().find(|(u, _)| u == k).map(|(_, x)| *x).unwrap_or_else(crate::quota::zero);
                if crate::quota::add(&have, d) > limit {
                    let used_now: Vec<(String, Quantity)> = tracked.iter().filter(|(t, _)| used.iter().any(|(u, _)| u == t)).map(|(t, _)| (t.clone(), used.iter().find(|(u, _)| u == t).map(|(_, x)| *x).unwrap_or_else(crate::quota::zero))).collect();
                    let limited: Vec<(String, Quantity)> = hard.iter().filter(|(h, _)| tracked.iter().any(|(t, _)| t == h)).cloned().collect();
                    return Err(forbidden_obj(rt, obj, crate::quota::exceeded_msg(&q, &tracked, &used_now, &limited)));
                }
            }
        }
        Ok(())
    }

    /// Current namespace usage of `names` by the objects that `quota`'s scopes select: the
    /// resources those names imply are listed and charged (upstream computes usage the same
    /// way, over the namespace's objects).
    fn quota_usage(&self, ns: &str, quota: &Value, names: &[String]) -> Vec<(String, Quantity)> {
        let mut sources: Vec<&'static Resource> = Vec::new();
        for n in names {
            if let Some(r) = crate::quota::source_of(n) {
                if !sources.iter().any(|s| s.plural == r.plural && s.group == r.group) {
                    sources.push(r);
                }
            }
        }
        let mut used: Vec<(String, Quantity)> = Vec::new();
        let store = self.store.borrow();
        for src in sources {
            for kv in store.list(&alloc::format!("{}{ns}/", src.prefix()), None, 0).0.iter() {
                let Ok(o) = json::parse(&kv.value) else { continue };
                if !crate::quota::matches_scopes(quota, src.plural, &o) {
                    continue;
                }
                for (k, v) in crate::quota::usage(src.plural, src.group, &o) {
                    if names.contains(&k) {
                        match used.iter_mut().find(|(x, _)| x == &k) {
                            Some((_, q)) => *q = crate::quota::add(q, &v),
                            None => used.push((k, v)),
                        }
                    }
                }
            }
        }
        used
    }

    fn services(&self) -> Vec<Value> {
        let r = resources::find("", "v1", "services").unwrap();
        let (items, _) = self.store.borrow().list(&r.prefix(), None, 0);
        items.iter().filter_map(|kv| json::parse(&kv.value).ok()).collect()
    }

    fn cluster_ips_in_use(&self) -> Vec<[u8; 4]> {
        self.services().iter().filter_map(|s| s.pointer(&["spec", "clusterIP"]).and_then(Value::as_str).and_then(crate::object::parse_ipv4)).collect()
    }

    fn node_ports_in_use(&self) -> Vec<u16> {
        self.services()
            .iter()
            .flat_map(|s| s.pointer(&["spec", "ports"]).and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default())
            .filter_map(|p| p.get("nodePort").and_then(Value::as_u64).map(|n| n as u16))
            .collect()
    }

    /// Lowest free address in 10.96.0.0/16 from .11 up (.1 = kubernetes, .10 = DNS).
    fn allocate_cluster_ip(&self) -> R<String> {
        let used = self.cluster_ips_in_use();
        (11u32..65535)
            .map(|n| [10, 96, (n >> 8) as u8, n as u8])
            .find(|a| a[3] != 0 && a[3] != 255 && !used.contains(a))
            .map(|a| alloc::format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]))
            .ok_or_else(|| ApiError::new(422, "Invalid", "service CIDR exhausted"))
    }

    /// Creates `default/kubernetes` (pointing at `advertise:port`) and `kube-system/kube-dns`.
    pub fn ensure_builtin_services(&self, advertise: [u8; 4], port: u16) -> Result<(), ApiError> {
        let svc = resources::find("", "v1", "services").unwrap();
        let ep = resources::find("", "v1", "endpoints").unwrap();
        let ip = alloc::format!("{}.{}.{}.{}", advertise[0], advertise[1], advertise[2], advertise[3]);
        self.bootstrap_object(svc, Some("default"), "kubernetes", "Service", r#"{"metadata":{"name":"kubernetes","labels":{"component":"apiserver","provider":"kubernetes"}},"spec":{"type":"ClusterIP","clusterIP":"10.96.0.1","clusterIPs":["10.96.0.1"],"ipFamilies":["IPv4"],"ipFamilyPolicy":"SingleStack","sessionAffinity":"None","internalTrafficPolicy":"Cluster","ports":[{"name":"https","port":443,"protocol":"TCP","targetPort":6443}]}}"#);
        // The endpoints follow the API server's current address (re-written on every start).
        let body = alloc::format!(r#"{{"metadata":{{"name":"kubernetes","labels":{{"endpointslice.kubernetes.io/skip-mirror":"true"}}}},"subsets":[{{"addresses":[{{"ip":"{ip}"}}],"ports":[{{"name":"https","port":{port},"protocol":"TCP"}}]}}]}}"#);
        let key = ep.key(Some("default"), "kubernetes");
        let _ = self.store.borrow_mut().delete(&key, None);
        self.bootstrap_object(ep, Some("default"), "kubernetes", "Endpoints", &body);
        self.bootstrap_object(svc, Some("kube-system"), "kube-dns", "Service", r#"{"metadata":{"name":"kube-dns","labels":{"k8s-app":"kube-dns","kubernetes.io/name":"CoreDNS"},"annotations":{"kr.io/builtin":"dns"}},"spec":{"type":"ClusterIP","clusterIP":"10.96.0.10","clusterIPs":["10.96.0.10"],"ipFamilies":["IPv4"],"ipFamilyPolicy":"SingleStack","sessionAffinity":"None","internalTrafficPolicy":"Cluster","ports":[{"name":"dns","port":53,"protocol":"UDP","targetPort":53},{"name":"dns-tcp","port":53,"protocol":"TCP","targetPort":53}]}}"#);
        self.sync()
    }

    /// `serviceaccounts/<name>/token` (TokenRequest).
    fn token_request(&self, req: &Req, rt: &Route, name: &str) -> R<Reply> {
        let (_, sa) = self.get_value(rt, name)?;
        let ns = rt.namespace.clone().unwrap_or_default();
        let tr = if req.body.is_empty() { obj(alloc::vec![]) } else { self.parse_body(req)? };
        let spec = tr.get("spec").cloned().unwrap_or(Value::Null);
        let audiences: Vec<String> = match spec.get("audiences").and_then(Value::as_array) {
            Some(a) if !a.is_empty() => a.iter().filter_map(Value::as_str).map(String::from).collect(),
            _ => alloc::vec![String::from(crate::tokens::ISSUER)],
        };
        // upstream: default 1 h, minimum 10 min, maximum capped (we cap at 48 h).
        let ttl = spec.get("expirationSeconds").and_then(Value::as_i64).unwrap_or(3600);
        if ttl < 600 {
            return Err(ApiError::invalid("spec.expirationSeconds: may not specify a duration less than 10 minutes"));
        }
        let ttl = ttl.min(48 * 3600);
        let pod = match spec.get("boundObjectRef") {
            Some(b) if b.get("kind").and_then(Value::as_str) == Some("Pod") => {
                let pname = b.get("name").and_then(Value::as_str).unwrap_or("");
                let pr = resources::find("", "v1", "pods").unwrap();
                let kv = self.store.borrow().get(&pr.key(Some(&ns), pname)).ok_or_else(|| ApiError::not_found("pods", pname))?;
                let puid = json::parse(&kv.value).ok().and_then(|v| v.pointer(&["metadata", "uid"]).and_then(Value::as_str).map(String::from)).unwrap_or_default();
                if let Some(want) = b.get("uid").and_then(Value::as_str) {
                    if want != puid {
                        return Err(ApiError::conflict("pod", pname));
                    }
                }
                Some((pname.to_string(), puid))
            }
            Some(_) => return Err(ApiError::invalid("boundObjectRef: only Pod is supported")),
            None => None,
        };
        let sa_uid = sa.pointer(&["metadata", "uid"]).and_then(Value::as_str).unwrap_or("").to_string();
        let now = (self.now)();
        let token = {
            let guard = self.sa.borrow();
            let (signer, _) = guard.as_ref().ok_or_else(|| ApiError::new(503, "ServiceUnavailable", "ServiceAccount tokens are not configured"))?;
            signer.issue(&ns, name, &sa_uid, pod.as_ref().map(|(n, u)| (n.as_str(), u.as_str())), &audiences, now, ttl)
        };
        let mut out = tr.clone();
        out.set("kind", Value::from("TokenRequest"));
        out.set("apiVersion", Value::from("authentication.k8s.io/v1"));
        out.entry_object("status").set("token", Value::String(token));
        out.entry_object("status").set("expirationTimestamp", Value::String(object::rfc3339(now + ttl)));
        Ok(Reply::Json(201, json::to_string(&out)))
    }

    /// `kubectl auth can-i`: evaluates the caller's own permissions.
    fn self_subject_access_review(&self, req: &Req, user: &User) -> R<Reply> {
        let mut r = self.parse_body(req)?;
        let ra = r.pointer(&["spec", "resourceAttributes"]).cloned();
        let nra = r.pointer(&["spec", "nonResourceAttributes"]).cloned();
        let s = |v: &Option<Value>, f: &str| v.as_ref().and_then(|x| x.get(f)).and_then(Value::as_str).unwrap_or("").to_string();
        let attrs = if ra.is_some() {
            crate::rbac::Attrs {
                verb: s(&ra, "verb"),
                api_group: s(&ra, "group"),
                resource: s(&ra, "resource"),
                subresource: s(&ra, "subresource"),
                namespace: s(&ra, "namespace"),
                name: s(&ra, "name"),
                resource_request: true,
                path: String::new(),
            }
        } else {
            crate::rbac::Attrs { verb: s(&nra, "verb"), path: s(&nra, "path"), ..Default::default() }
        };
        let ok = self.authorize(user, &attrs, None);
        r.set("apiVersion", Value::from("authorization.k8s.io/v1"));
        r.set("kind", Value::from("SelfSubjectAccessReview"));
        r.set("status", obj(alloc::vec![("allowed", Value::Bool(ok))]));
        Ok(Reply::Json(201, json::to_string(&r)))
    }

    /// ServiceAccount admission for pods: default `serviceAccountName`, require it to exist,
    /// and inject the projected `kube-api-access-*` volume unless automounting is disabled.
    fn admit_pod(&self, o: &mut Value, ns: &str) -> R<()> {
        let spec = o.entry_object("spec");
        let sa_name = spec.get("serviceAccountName").and_then(Value::as_str).filter(|s| !s.is_empty()).or_else(|| spec.get("serviceAccount").and_then(Value::as_str)).unwrap_or("default").to_string();
        spec.set("serviceAccountName", Value::String(sa_name.clone()));
        let sar = resources::find("", "v1", "serviceaccounts").unwrap();
        let Some(kv) = self.store.borrow().get(&sar.key(Some(ns), &sa_name)) else {
            return Err(ApiError::new(403, "Forbidden", alloc::format!("error looking up service account {ns}/{sa_name}: serviceaccount \"{sa_name}\" not found")));
        };
        if self.sa.borrow().is_none() {
            return Ok(());
        }
        let sa = json::parse(&kv.value).unwrap_or(Value::Null);
        let automount = o.pointer(&["spec", "automountServiceAccountToken"]).and_then(Value::as_bool).or_else(|| sa.get("automountServiceAccountToken").and_then(Value::as_bool)).unwrap_or(true);
        const MOUNT: &str = "/var/run/secrets/kubernetes.io/serviceaccount";
        let already = |c: &Value| c.get("volumeMounts").and_then(Value::as_array).is_some_and(|m| m.iter().any(|v| v.get("mountPath").and_then(Value::as_str) == Some(MOUNT)));
        if !automount {
            return Ok(());
        }
        let vname = alloc::format!("kube-api-access-{}", object::name_suffix(self.rng));
        let vol = json::parse(alloc::format!(
            r#"{{"name":"{vname}","projected":{{"defaultMode":420,"sources":[{{"serviceAccountToken":{{"expirationSeconds":3607,"path":"token"}}}},{{"configMap":{{"name":"kube-root-ca.crt","items":[{{"key":"ca.crt","path":"ca.crt"}}]}}}},{{"downwardAPI":{{"items":[{{"path":"namespace","fieldRef":{{"apiVersion":"v1","fieldPath":"metadata.namespace"}}}}]}}}}]}}}}"#
        ).as_bytes())
        .unwrap();
        let mount = json::parse(alloc::format!(r#"{{"name":"{vname}","readOnly":true,"mountPath":"{MOUNT}"}}"#).as_bytes()).unwrap();
        let spec = o.get_mut("spec").unwrap();
        let mut injected = false;
        for key in ["initContainers", "containers"] {
            if let Some(Value::Array(cs)) = spec.get_mut(key) {
                for c in cs.iter_mut() {
                    if already(c) {
                        continue;
                    }
                    match c.get_mut("volumeMounts") {
                        Some(Value::Array(m)) => m.push(mount.clone()),
                        _ => c.set("volumeMounts", Value::Array(alloc::vec![mount.clone()])),
                    }
                    injected = true;
                }
            }
        }
        if injected {
            match spec.get_mut("volumes") {
                Some(Value::Array(v)) => v.push(vol),
                _ => spec.set("volumes", Value::Array(alloc::vec![vol])),
            }
        }
        Ok(())
    }

    /// Creates the `default` ServiceAccount in a namespace (the ServiceAccount controller's job).
    fn ensure_default_sa(&self, ns: &str) {
        let Some(sa) = resources::find("", "v1", "serviceaccounts") else { return };
        let key = sa.key(Some(ns), "default");
        if self.store.borrow().get(&key).is_some() {
            return;
        }
        let mut o = obj(alloc::vec![("metadata", obj(alloc::vec![("name", Value::from("default"))]))]);
        let t = Target { api_version: "v1", kind: "ServiceAccount", namespace: Some(ns), name_is_label: false };
        let rev = self.store.borrow().revision() + 1;
        if object::prepare_create(&mut o, &t, &self.clock(), rev).is_ok() {
            let _ = self.store.borrow_mut().create(&key, json::to_string(&o).into_bytes());
        }
    }

    // ---- scale ----

    fn scale_of(&self, rt: &Route, v: &Value) -> Value {
        let meta = v.get("metadata").cloned().unwrap_or(Value::Object(Vec::new()));
        let paths = self.scale_paths(rt);
        let spec_replicas = v.pointer(&crate::crd::path_segs(&paths[0])).cloned().unwrap_or(Value::Number(Number::from_u64(1)));
        let status_replicas = v.pointer(&crate::crd::path_segs(&paths[1])).cloned().unwrap_or(Value::Number(Number::from_u64(0)));
        let custom_selector = Some(paths[2].as_str()).filter(|p| !p.is_empty()).map(|p| v.pointer(&crate::crd::path_segs(p)).and_then(Value::as_str).unwrap_or("").to_string());
        let selector = custom_selector.or_else(|| v.pointer(&["spec", "selector", "matchLabels"]).and_then(Value::as_object).map(|m| m.iter().map(|(k, v)| alloc::format!("{k}={}", v.as_str().unwrap_or(""))).collect::<Vec<_>>().join(","))).unwrap_or_default();
        let mut m = obj(alloc::vec![]);
        for f in ["name", "namespace", "uid", "resourceVersion", "creationTimestamp"] {
            if let Some(x) = meta.get(f) {
                m.set(f, x.clone());
            }
        }
        let _ = rt;
        obj(alloc::vec![
            ("kind", Value::from("Scale")),
            ("apiVersion", Value::from("autoscaling/v1")),
            ("metadata", m),
            ("spec", obj(alloc::vec![("replicas", spec_replicas)])),
            ("status", obj(alloc::vec![("replicas", status_replicas), ("selector", Value::String(selector))])),
        ])
    }

    /// (spec replicas, status replicas, selector) paths of the scale subresource.
    fn scale_paths(&self, rt: &Route) -> [String; 3] {
        let custom = self.custom.borrow();
        match custom.iter().find(|c| core::ptr::eq(c.res, rt.res)).and_then(|c| c.scale.clone()) {
            Some(p) => p,
            None => [".spec.replicas".into(), ".status.replicas".into(), String::new()],
        }
    }

    fn get_scale(&self, rt: &Route, name: &str) -> R<Reply> {
        let (_, v) = self.get_value(rt, name)?;
        Ok(Reply::ok(&self.scale_of(rt, &v)))
    }

    fn update_scale(&self, req: &Req, rt: &Route, name: &str, is_patch: bool) -> R<Reply> {
        let (kv, old) = self.get_value(rt, name)?;
        let mut scale = self.scale_of(rt, &old);
        let body = self.parse_body(req)?;
        if is_patch {
            let ct = req.content_type.unwrap_or("");
            if ct.starts_with("application/json-patch+json") {
                patch::json_patch(&mut scale, &body).map_err(|e| ApiError::invalid(e.0))?;
            } else {
                patch::merge_patch(&mut scale, &body);
            }
        } else {
            scale = body;
        }
        let replicas = scale.pointer(&["spec", "replicas"]).and_then(Value::as_i64).filter(|r| *r >= 0).ok_or_else(|| ApiError::invalid("spec.replicas must be a non-negative integer"))?;
        let mut new = old.clone();
        let segs = crate::crd::path_segs(&self.scale_paths(rt)[0]).into_iter().map(String::from).collect::<Vec<_>>();
        let mut cur = &mut new;
        for (i, seg) in segs.iter().enumerate() {
            if i + 1 == segs.len() {
                cur.set(seg, Value::Number(Number::from_i64(replicas)));
            } else {
                cur = cur.entry_object(seg);
            }
        }
        if let Some(m) = new.get_mut("metadata") {
            m.remove("resourceVersion");
        }
        let q = Query(Vec::new());
        match self.update(req, rt, name, false, &q, Some((kv, old, new)))? {
            Reply::Json(200, s) => {
                let v = json::parse(s.as_bytes()).unwrap_or(Value::Null);
                Ok(Reply::ok(&self.scale_of(rt, &v)))
            }
            other => Ok(other),
        }
    }

    // ---- watch ----

    fn watch(&self, rt: &Route, q: &Query) -> R<Reply> {
        let ls = Selector::parse(q.get("labelSelector").unwrap_or(""))?;
        let fs = FieldSelector::parse(q.get("fieldSelector").unwrap_or(""))?;
        let prefix = self.list_prefix(rt);
        let rv = q.get("resourceVersion").unwrap_or("");
        let mut store = self.store.borrow_mut();
        let mut initial = VecDeque::new();
        // WatchList (sendInitialEvents=true): current state as ADDED events, then a BOOKMARK
        // annotated k8s.io/initial-events-end, then live events (kubectl wait/delete use it).
        let send_initial = q.flag("sendInitialEvents");
        let after = match rv {
            _ if send_initial => {
                let (items, _) = store.list(&prefix, None, 0);
                for kv in items {
                    if let Ok(v) = json::parse(&kv.value) {
                        if ls.matches(&v) && fs.matches(&v) {
                            initial.push_back(event_line("ADDED", &kv.value));
                        }
                    }
                }
                let rev = store.revision();
                let mark = alloc::format!(
                    r#"{{"kind":"{}","apiVersion":"{}","metadata":{{"resourceVersion":"{rev}","annotations":{{"k8s.io/initial-events-end":"true"}}}}}}"#,
                    rt.res.kind,
                    rt.res.group_version()
                );
                initial.push_back(event_line("BOOKMARK", mark.as_bytes()));
                rev
            }
            "" | "0" => {
                // "Get state and start at most recent": synthetic ADDED events first.
                let (items, _) = store.list(&prefix, None, 0);
                for kv in items {
                    if let Ok(v) = json::parse(&kv.value) {
                        if ls.matches(&v) && fs.matches(&v) {
                            initial.push_back(event_line("ADDED", &kv.value));
                        }
                    }
                }
                store.revision()
            }
            n => n.parse::<u64>().map_err(|_| ApiError::bad_request("invalid resourceVersion"))?,
        };
        let watcher = match store.watch(&prefix, after) {
            Ok(w) => Some(w),
            Err(StoreError::Compacted { .. }) => {
                // Kubernetes reports this inside the stream as an ERROR event with 410.
                let st = json::to_string(&object::status_value(410, "Expired", "too old resource version"));
                initial.push_back(alloc::format!("{{\"type\":\"ERROR\",\"object\":{st}}}\n").into_bytes());
                None
            }
            Err(_) => return Err(ApiError::new(500, "InternalError", "watch failed")),
        };
        let timeout_s: u64 = q.get("timeoutSeconds").and_then(|t| t.parse().ok()).unwrap_or(1800).min(3600);
        Ok(Reply::Watch(WatchStream { watcher, initial, ls, fs, deadline: Some(Box::pin(kr_rt::exec::sleep(timeout_s * 1000))) }))
    }
}

/// Job defaulting and validation (upstream batch/v1 defaults + generated selector).
fn admit_job(o: &mut Value, name: &str) -> R<()> {
    let uid = o.pointer(&["metadata", "uid"]).and_then(Value::as_str).unwrap_or("").to_string();
    let spec = o.entry_object("spec");
    let rp = spec.pointer(&["template", "spec", "restartPolicy"]).and_then(Value::as_str).unwrap_or("");
    if rp != "Never" && rp != "OnFailure" {
        return Err(ApiError::invalid(alloc::format!("spec.template.spec.restartPolicy: Required value: valid values: \"OnFailure\", \"Never\" (got {rp:?})")));
    }
    let manual = spec.get("manualSelector").and_then(Value::as_bool) == Some(true);
    if !manual {
        if spec.get("selector").is_some() {
            return Err(ApiError::invalid("spec.selector: `selector` will be auto-generated (set manualSelector: true to provide one)"));
        }
        let labels = spec.entry_object("template").entry_object("metadata").entry_object("labels");
        for (k, v) in [("batch.kubernetes.io/controller-uid", uid.as_str()), ("batch.kubernetes.io/job-name", name), ("controller-uid", uid.as_str()), ("job-name", name)] {
            labels.set(k, Value::from(v));
        }
        spec.set("selector", obj(alloc::vec![("matchLabels", obj(alloc::vec![("batch.kubernetes.io/controller-uid", Value::from(uid.as_str()))]))]));
    }
    let unset = |spec: &Value, f: &str| spec.get(f).is_none_or(Value::is_null);
    if unset(spec, "completions") && unset(spec, "parallelism") {
        spec.set("completions", Value::Number(Number::from_u64(1)));
    }
    for (f, v) in [("parallelism", Value::Number(Number::from_u64(1))), ("backoffLimit", Value::Number(Number::from_u64(6))), ("completionMode", Value::from("NonIndexed")), ("suspend", Value::Bool(false))] {
        if unset(spec, f) {
            spec.set(f, v);
        }
    }
    Ok(())
}

/// An admission denial carrying the upstream object prefix (`pods "nginx" is forbidden: ...`).
fn forbidden_obj(rt: &Route, obj: &Value, detail: String) -> ApiError {
    let name = obj.pointer(&["metadata", "name"]).and_then(Value::as_str).unwrap_or("");
    ApiError::new(403, "Forbidden", alloc::format!("{} \"{name}\" is forbidden: {}", rt.res.singular, detail))
}

fn event_line(ty: &str, obj: &[u8]) -> Vec<u8> {
    let mut l = Vec::with_capacity(obj.len() + 32);
    l.extend_from_slice(b"{\"type\":\"");
    l.extend_from_slice(ty.as_bytes());
    l.extend_from_slice(b"\",\"object\":");
    l.extend_from_slice(obj);
    l.extend_from_slice(b"}\n");
    l
}

fn wants_table(accept: Option<&str>) -> bool {
    accept.is_some_and(|a| a.split(',').next().is_some_and(|first| first.contains("as=Table")))
}

fn parse_route(extra: &[&'static Resource], group: &str, version: &str, rest: &[&str]) -> Option<Route> {
    let ok_seg = |s: &str| !s.is_empty() && s != "." && s != "..";
    if !rest.iter().all(|s| ok_seg(s)) {
        return None;
    }
    let (namespace, rest) = match rest {
        ["namespaces", ns, r, tail @ ..] if !matches!(*r, "status" | "finalize") => (Some(ns.to_string()), {
            let mut v = alloc::vec![*r];
            v.extend_from_slice(tail);
            v
        }),
        _ => (None, rest.to_vec()),
    };
    let (plural, name, sub) = match rest.as_slice() {
        [p] => (*p, None, None),
        [p, n] => (*p, Some(n.to_string()), None),
        [p, n, s] => (*p, Some(n.to_string()), Some(s.to_string())),
        _ => return None,
    };
    let res = resources::find_in(extra, group, version, plural)?;
    if namespace.is_some() && !res.namespaced {
        return None;
    }
    // Namespaced resources addressed without a namespace: only list/watch across namespaces.
    if namespace.is_none() && res.namespaced && name.is_some() {
        return None;
    }
    Some(Route { res, namespace, name, sub })
}

/// A watch response: queued initial events, then live store events converted to watch lines,
/// filtered by selectors with enter/leave semantics. Ends at the timeout or when the store
/// closes the watcher (overflow).
pub struct WatchStream {
    watcher: Option<Watcher>,
    initial: VecDeque<Vec<u8>>,
    ls: Selector,
    fs: FieldSelector,
    deadline: Option<Pin<Box<kr_rt::exec::Sleep>>>,
}

impl WatchStream {
    fn convert(ls: &Selector, fs: &FieldSelector, e: &Event) -> Option<Vec<u8>> {
        let filtered = !ls.is_empty() || !fs.is_empty();
        let matches = |kv: &Kv| -> bool { !filtered || json::parse(&kv.value).is_ok_and(|v| ls.matches(&v) && fs.matches(&v)) };
        match e.kind {
            EventKind::Delete => matches(&e.kv).then(|| event_line("DELETED", &with_rv(&e.kv))),
            EventKind::Put => {
                let now = matches(&e.kv);
                let before = e.prev.as_ref().is_some_and(&matches);
                match (e.prev.is_some(), before, now) {
                    (_, true, true) => Some(event_line("MODIFIED", &e.kv.value)),
                    (_, false, true) => Some(event_line("ADDED", &e.kv.value)),
                    (true, true, false) => Some(event_line("DELETED", &e.kv.value)),
                    _ => None,
                }
            }
        }
    }

    /// Next chunk of the response body; `None` ends the stream.
    pub fn poll_chunk(&mut self, cx: &mut Context<'_>) -> Poll<Option<Vec<u8>>> {
        if let Some(l) = self.initial.pop_front() {
            return Poll::Ready(Some(l));
        }
        if let Some(d) = self.deadline.as_mut() {
            if d.as_mut().poll(cx).is_ready() {
                return Poll::Ready(None);
            }
        }
        let Some(w) = self.watcher.as_mut() else { return Poll::Ready(None) };
        // Batch everything already queued into one chunk.
        let mut out: Vec<u8> = Vec::new();
        loop {
            match w.poll_next(cx) {
                Poll::Ready(Some(e)) => {
                    if let Some(l) = Self::convert(&self.ls, &self.fs, &e) {
                        out.extend_from_slice(&l);
                    }
                    if out.len() > 256 * 1024 {
                        return Poll::Ready(Some(out));
                    }
                }
                Poll::Ready(None) => {
                    self.watcher = None;
                    return Poll::Ready(if out.is_empty() { None } else { Some(out) });
                }
                Poll::Pending => return if out.is_empty() { Poll::Pending } else { Poll::Ready(Some(out)) },
            }
        }
    }
}

use core::future::Future;

/// The deleted object as last stored, but with resourceVersion = the deletion revision.
fn with_rv(kv: &Kv) -> Vec<u8> {
    match json::parse(&kv.value) {
        Ok(mut v) => {
            if let Some(m) = v.get_mut("metadata") {
                m.set("resourceVersion", Value::String(kv.mod_rev.to_string()));
            }
            json::to_string(&v).into_bytes()
        }
        Err(_) => kv.value.to_vec(),
    }
}

/// Pod lookups for the Node authorizer, straight from the store.
struct StorePods<'a>(&'a ApiServer);

impl crate::node_authz::Pods for StorePods<'_> {
    fn get(&self, ns: &str, name: &str) -> Option<Value> {
        let r = resources::find("", "v1", "pods")?;
        json::parse(&self.0.store.borrow().get(&r.key(Some(ns), name))?.value).ok()
    }
    fn persistent_volume(&self, name: &str) -> Option<Value> {
        let r = resources::find("", "v1", "persistentvolumes")?;
        json::parse(&self.0.store.borrow().get(&r.key(None, name))?.value).ok()
    }
    fn in_namespace(&self, ns: &str) -> Vec<Value> {
        let Some(r) = resources::find("", "v1", "pods") else { return Vec::new() };
        let prefix = alloc::format!("{}{ns}/", r.prefix());
        self.0.store.borrow().list(&prefix, None, 0).0.iter().filter_map(|kv| json::parse(&kv.value).ok()).collect()
    }
}

/// pods/ephemeralcontainers: only spec.ephemeralContainers may change, and existing entries are immutable.
fn eph_only(old: &Value, new: &mut Value) -> R<()> {
    let ephs = new.pointer(&["spec", "ephemeralContainers"]).cloned();
    let prev = old.pointer(&["spec", "ephemeralContainers"]).and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
    let now = ephs.as_ref().and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
    for p in &prev {
        let n = p.get("name").and_then(Value::as_str);
        if !now.iter().any(|c| c.get("name").and_then(Value::as_str) == n && c.as_object().is_some_and(|o| o.iter().all(|(k, v)| p.get(k) == Some(v)))) {
            return Err(ApiError::invalid("Forbidden: existing ephemeral containers may not be changed or removed"));
        }
    }
    let used = |n: &str| ["initContainers", "containers"].iter().any(|k| old.pointer(&["spec", k]).and_then(Value::as_array).is_some_and(|a| a.iter().any(|c| c.get("name").and_then(Value::as_str) == Some(n))));
    for c in &now {
        let n = c.get("name").and_then(Value::as_str).unwrap_or("");
        if n.is_empty() || (used(n) && !prev.iter().any(|p| p.get("name").and_then(Value::as_str) == Some(n))) {
            return Err(ApiError::invalid(alloc::format!("spec.ephemeralContainers: Duplicate value: {n:?}")));
        }
    }
    let mut out = old.clone();
    if let Some(e) = ephs {
        out.entry_object("spec").set("ephemeralContainers", e);
    }
    *new = out;
    Ok(())
}
