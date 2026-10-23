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
use crate::resources::{self, Resource, RESOURCES};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;
use core::pin::Pin;
use core::task::{Context, Poll};
use kr_fmt::json::{self, Number, Value};
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
    pub user: Option<User>,
}

pub enum Reply {
    /// Status code and JSON body.
    Json(u16, String),
    /// A watch: newline-delimited JSON events.
    Watch(WatchStream),
}

impl Reply {
    fn err(e: ApiError) -> Reply {
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
struct Route {
    res: &'static Resource,
    namespace: Option<String>,
    name: Option<String>,
    sub: Option<String>,
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
        Ok(ApiServer { store: RefCell::new(store), now, rng, server_address, version: String::from("v1.31.0-kr") })
    }

    fn clock(&self) -> Clock {
        Clock { now: (self.now)(), rng: self.rng }
    }

    pub fn handle(&self, req: &Req) -> Reply {
        match self.route(req) {
            Ok(r) => r,
            Err(e) => Reply::err(e),
        }
    }

    fn route(&self, req: &Req) -> R<Reply> {
        let path = req.path.trim_end_matches('/');
        match path {
            "/healthz" | "/livez" | "/readyz" => return Ok(Reply::Json(200, String::from("\"ok\""))),
            "/version" => {
                return Ok(Reply::ok(&obj(alloc::vec![
                    ("major", Value::from("1")),
                    ("minor", Value::from("31")),
                    ("gitVersion", Value::from(self.version.as_str())),
                    ("platform", Value::from(if cfg!(target_arch = "aarch64") { "linux/arm64" } else { "linux/amd64" })),
                ])))
            }
            _ => {}
        }
        let user = req.user.as_ref().ok_or_else(|| ApiError::new(401, "Unauthorized", "Unauthorized"))?;
        // Authorization: only system:masters until RBAC lands (KNOWN_ISSUES).
        if !is_masters(user) {
            return Err(ApiError::new(403, "Forbidden", alloc::format!("User \"{}\" cannot {} {}: kr allows only system:masters until RBAC is implemented", user.name, req.method, path)));
        }
        let segs: Vec<&str> = path.split('/').skip(1).collect();
        match segs.as_slice() {
            ["api"] => return Ok(Reply::Json(200, discovery::core_versions(&self.server_address))),
            ["api", "v1"] => return Ok(Reply::Json(200, discovery::resource_list("", "v1").unwrap())),
            ["apis"] => return Ok(Reply::Json(200, discovery::group_list())),
            ["openapi", "v3"] => return Ok(Reply::Json(200, crate::openapi::index())),
            ["openapi", "v3", rest @ ..] => {
                let p = rest.join("/");
                return crate::openapi::group_version(&p).map(|b| Reply::Json(200, b)).ok_or_else(|| ApiError::not_found("openapi", &p));
            }
            ["apis", g] => return discovery::group(g).map(|b| Reply::Json(200, b)).ok_or_else(|| ApiError::not_found("group", g)),
            ["apis", g, v] => return discovery::resource_list(g, v).map(|b| Reply::Json(200, b)).ok_or_else(|| ApiError::not_found("groupVersion", v)),
            _ => {}
        }
        let (group, version, rest) = match segs.as_slice() {
            ["api", "v1", rest @ ..] => ("", "v1", rest),
            ["apis", g, v, rest @ ..] => (*g, *v, rest),
            _ => return Err(ApiError::not_found("path", path)),
        };
        let route = parse_route(group, version, rest).ok_or_else(|| ApiError::not_found("path", path))?;
        let q = Query::parse(req.query)?;
        self.dispatch(req, &route, &q)
    }

    fn dispatch(&self, req: &Req, rt: &Route, q: &Query) -> R<Reply> {
        let sub = rt.sub.as_deref();
        if let Some(s) = sub {
            if !rt.res.subresources.contains(&s) {
                return Err(ApiError::not_found("subresource", s));
            }
        }
        match (req.method, &rt.name, sub) {
            ("GET", None, None) if q.flag("watch") => self.watch(rt, q),
            ("GET", None, None) => self.list(req, rt, q),
            ("GET", Some(n), Some("scale")) => self.get_scale(rt, n),
            ("GET", Some(n), _) => {
                let (_, v) = self.get_value(rt, n)?;
                Ok(Reply::ok(&v))
            }
            ("POST", None, None) => self.create(req, rt, q),
            ("PUT", Some(n), Some("scale")) => self.update_scale(req, rt, n, false),
            ("PATCH", Some(n), Some("scale")) => self.update_scale(req, rt, n, true),
            ("PUT", Some(n), s) => self.update(req, rt, n, s == Some("status"), q, None),
            ("PATCH", Some(n), s) => self.patch(req, rt, n, s == Some("status"), q),
            ("DELETE", Some(n), None) => self.delete(req, rt, n, q),
            ("DELETE", None, None) => self.delete_collection(rt, q),
            _ => Err(ApiError::new(405, "MethodNotAllowed", alloc::format!("method {} not allowed here", req.method))),
        }
    }

    // ---- reads ----

    fn get_kv(&self, rt: &Route, name: &str) -> R<Kv> {
        self.store.borrow().get(&rt.res.key(rt.namespace.as_deref(), name)).ok_or_else(|| ApiError::not_found(rt.res.singular, name))
    }

    fn get_value(&self, rt: &Route, name: &str) -> R<(Kv, Value)> {
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
        let ct = req.content_type.unwrap_or("application/json");
        if ct.starts_with("application/cbor") {
            // No CBOR decoder; clients retry with JSON on 415.
            return Err(ApiError::new(415, "UnsupportedMediaType", alloc::format!("the body of the request was in an unknown format - accepted media types include: application/json, application/yaml, application/vnd.kubernetes.protobuf (got {ct})")));
        }
        let v = if ct.starts_with("application/vnd.kubernetes.protobuf") {
            proto::decode_body(req.body).map_err(ApiError::bad_request)?
        } else if ct.starts_with("application/yaml") || ct.starts_with("application/apply-patch+yaml") {
            let s = core::str::from_utf8(req.body).map_err(|_| ApiError::bad_request("body is not UTF-8"))?;
            kr_fmt::yaml::parse(s).map_err(|_| ApiError::bad_request("invalid YAML body"))?
        } else {
            json::parse(req.body).map_err(|_| ApiError::bad_request("invalid JSON body"))?
        };
        if v.has_duplicate_keys() {
            return Err(ApiError::bad_request("duplicate keys in request body"));
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

    fn sync(&self) -> R<()> {
        self.store.borrow_mut().sync().map_err(|_| ApiError::new(500, "InternalError", "storage sync failed"))
    }

    fn create(&self, req: &Req, rt: &Route, q: &Query) -> R<Reply> {
        let mut o = self.parse_body(req)?;
        self.create_value(&mut o, rt, q).map(|v| Reply::Json(201, json::to_string(&v)))
    }

    fn create_value(&self, o: &mut Value, rt: &Route, q: &Query) -> R<Value> {
        let (gv, mut t) = self.target(rt);
        t.api_version = &gv;
        let rev = self.store.borrow().revision() + 1;
        let name = object::prepare_create(o, &t, &self.clock(), rev)?;
        self.check_namespace(rt, &name)?;
        if rt.res.plural == "namespaces" {
            o.entry_object("spec").set("finalizers", Value::Array(alloc::vec![Value::from("kubernetes")]));
            o.entry_object("status").set("phase", Value::from("Active"));
        }
        if q.get("dryRun") == Some("All") {
            return Ok(o.clone());
        }
        let key = rt.res.key(rt.namespace.as_deref(), &name);
        let kv = self.store.borrow_mut().create(&key, json::to_string(o).into_bytes()).map_err(|e| store_err(e, rt.res.singular, &name))?;
        debug_assert_eq!(kv.mod_rev, rev);
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
        let has_status = rt.res.subresources.contains(&"status");
        object::prepare_update(&old, &mut new, &t, rev, has_status, status)?;
        if q.get("dryRun") == Some("All") {
            return Ok(Reply::ok(&new));
        }
        // Finalizers removed from an object that is being deleted: complete the deletion.
        let deleting = new.pointer(&["metadata", "deletionTimestamp"]).is_some();
        let no_finalizers = new.pointer(&["metadata", "finalizers"]).and_then(Value::as_array).is_none_or(|f| f.is_empty());
        if deleting && no_finalizers && rt.res.plural != "namespaces" {
            self.store.borrow_mut().delete(&kv.key, Some(kv.mod_rev)).map_err(|e| store_err(e, rt.res.singular, name))?;
            self.sync()?;
            return Ok(Reply::ok(&new));
        }
        self.store.borrow_mut().update(&kv.key, json::to_string(&new).into_bytes(), Some(kv.mod_rev)).map_err(|e| store_err(e, rt.res.singular, name))?;
        self.sync()?;
        Ok(Reply::ok(&new))
    }

    fn patch(&self, req: &Req, rt: &Route, name: &str, status: bool, q: &Query) -> R<Reply> {
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
        let mut new = old.clone();
        let r = if ct.starts_with("application/json-patch+json") {
            patch::json_patch(&mut new, &p)
        } else if ct.starts_with("application/merge-patch+json") {
            patch::merge_patch(&mut new, &p);
            Ok(())
        } else if ct.starts_with("application/strategic-merge-patch+json") || ct.starts_with("application/apply-patch") {
            patch::strategic_merge(&mut new, &p)
        } else {
            return Err(ApiError::new(415, "UnsupportedMediaType", alloc::format!("unsupported patch type {ct:?}")));
        };
        r.map_err(|e| ApiError::invalid(e.0))?;
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
        if !req.body.is_empty() {
            let opts = json::parse(req.body).map_err(|_| ApiError::bad_request("invalid DeleteOptions"))?;
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
        self.sync()?;
        Ok(Reply::ok(&v))
    }

    /// Namespace deletion: everything inside is removed synchronously (there is no namespace
    /// controller yet), then the namespace itself.
    fn delete_namespace(&self, kv: &Kv, v: Value, name: &str) -> R<Reply> {
        if SYSTEM_NAMESPACES.contains(&name) && name != "kube-public" {
            return Err(ApiError::new(403, "Forbidden", alloc::format!("namespace {name} is a system namespace and cannot be deleted")));
        }
        let mut store = self.store.borrow_mut();
        for r in RESOURCES.iter().filter(|r| r.namespaced) {
            let prefix = alloc::format!("{}{name}/", r.prefix());
            let (items, _) = store.list(&prefix, None, 0);
            for it in items {
                let _ = store.delete(&it.key, None);
            }
        }
        store.delete(&kv.key, None).map_err(|e| store_err(e, "namespace", name))?;
        drop(store);
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

    // ---- scale ----

    fn scale_of(&self, rt: &Route, v: &Value) -> Value {
        let meta = v.get("metadata").cloned().unwrap_or(Value::Object(Vec::new()));
        let spec_replicas = v.pointer(&["spec", "replicas"]).cloned().unwrap_or(Value::Number(Number::from_u64(1)));
        let status_replicas = v.pointer(&["status", "replicas"]).cloned().unwrap_or(Value::Number(Number::from_u64(0)));
        let selector = v.pointer(&["spec", "selector", "matchLabels"]).and_then(Value::as_object).map(|m| m.iter().map(|(k, v)| alloc::format!("{k}={}", v.as_str().unwrap_or(""))).collect::<Vec<_>>().join(",")).unwrap_or_default();
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
        new.entry_object("spec").set("replicas", Value::Number(Number::from_i64(replicas)));
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
        let after = match rv {
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

fn parse_route(group: &str, version: &str, rest: &[&str]) -> Option<Route> {
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
    let res = resources::find(group, version, plural)?;
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
