//! Shared machinery for the control loops: the work queue, the list-then-watch loop, the
//! reconcile driver, conflict retries and small JSON helpers.
//!
//! Every controller is level-triggered. Watch events only say "this key may need work"; the
//! reconciler then reads fresh state with `get`/`list` (cheap in-process) and converges it.
//! Reconcilers must therefore be idempotent and must not write when nothing changed, otherwise
//! their own writes would wake them forever.

use crate::Config;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::future::{poll_fn, Future};
use core::task::{Poll, Waker};
use kr_apiserver::client::{Client, Result, WatchEvent};
use kr_apiserver::object::{ApiError, Selector};
use kr_fmt::json::Value;
use kr_rt::exec::{self, JoinHandle};

// ---- wake-up primitive ----

#[derive(Default)]
struct NotifyInner {
    flag: Cell<bool>,
    waker: RefCell<Option<Waker>>,
}

/// A one-slot, single-waiter notification (a permit is remembered until consumed).
#[derive(Clone, Default)]
pub struct Notify(Rc<NotifyInner>);

impl Notify {
    pub fn notify(&self) {
        self.0.flag.set(true);
        let w = self.0.waker.borrow_mut().take();
        if let Some(w) = w {
            w.wake();
        }
    }

    pub async fn notified(&self) {
        poll_fn(|cx| {
            if self.0.flag.replace(false) {
                return Poll::Ready(());
            }
            *self.0.waker.borrow_mut() = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }
}

// ---- work queue ----

/// Set of dirty keys plus keys scheduled for later. Keys are `namespace/name` strings (or
/// a controller-specific sentinel such as `*`).
#[derive(Clone, Default)]
pub struct Queue {
    dirty: Rc<RefCell<BTreeSet<String>>>,
    later: Rc<RefCell<BTreeMap<String, u64>>>,
    pub notify: Notify,
}

impl Queue {
    pub fn new() -> Queue {
        Queue::default()
    }

    pub fn add(&self, key: &str) {
        self.dirty.borrow_mut().insert(key.to_string());
        self.notify.notify();
    }

    pub fn add_after(&self, key: &str, ms: u64) {
        let at = exec::now_ms() + ms;
        let mut l = self.later.borrow_mut();
        let e = l.entry(key.to_string()).or_insert(at);
        *e = (*e).min(at);
    }

    fn take(&self) -> Vec<String> {
        let now = exec::now_ms();
        let mut l = self.later.borrow_mut();
        let due: Vec<String> = l.iter().filter(|(_, at)| **at <= now).map(|(k, _)| k.clone()).collect();
        let mut d = self.dirty.borrow_mut();
        for k in due {
            l.remove(&k);
            d.insert(k);
        }
        core::mem::take(&mut *d).into_iter().collect()
    }

    fn has_dirty(&self) -> bool {
        !self.dirty.borrow().is_empty()
    }

    fn next_due(&self) -> Option<u64> {
        self.later.borrow().values().copied().min()
    }
}

/// Aborts the tasks it owns when dropped, so dropping a controller's future stops the watchers
/// it spawned.
#[derive(Default)]
pub struct Guard(pub Vec<JoinHandle<()>>);

impl Drop for Guard {
    fn drop(&mut self) {
        for h in &self.0 {
            h.abort();
        }
    }
}

/// Runs the reconcile loop forever. `reconcile(key)` returns `Ok(Some(ms))` to be called again
/// after `ms`, `Ok(None)` when done and `Err` to retry after the backoff. `resync` marks every
/// key dirty and runs every `cfg.resync_ms`.
pub async fn drive<R, RF, S, SF>(cfg: &Config, q: &Queue, mut reconcile: R, mut resync: S)
where
    R: FnMut(String) -> RF,
    RF: Future<Output = Result<Option<u64>>>,
    S: FnMut() -> SF,
    SF: Future<Output = ()>,
{
    let mut next_resync = 0u64;
    loop {
        let now = exec::now_ms();
        if now >= next_resync {
            resync().await;
            next_resync = exec::now_ms() + cfg.resync_ms;
        }
        for key in q.take() {
            match reconcile(key.clone()).await {
                Ok(None) => {}
                Ok(Some(ms)) => q.add_after(&key, ms),
                Err(_) => q.add_after(&key, cfg.backoff_ms),
            }
            // In-process calls never suspend: without this, a long queue (1000 pods to
            // schedule) would hold the executor and stall the API server.
            exec::yield_now().await;
        }
        if q.has_dirty() {
            continue;
        }
        let mut until = next_resync;
        if let Some(d) = q.next_due() {
            until = until.min(d);
        }
        let wait = until.saturating_sub(exec::now_ms());
        let _ = exec::timeout(wait, q.notify.notified()).await;
    }
}

// ---- list + watch ----

/// Lists `path`, reports every item as `ADDED`, then watches from the list's resourceVersion
/// and reports events. When the watch ends or reports ERROR it starts over; failures back off.
pub async fn watch_loop<C: Client>(c: C, path: String, query: String, cfg: Config, mut on_event: impl FnMut(&str, &Value)) {
    loop {
        let mut failed = true;
        if let Ok(list) = c.list(&path, &query).await {
            let rv = list.pointer(&["metadata", "resourceVersion"]).and_then(Value::as_str).unwrap_or("").to_string();
            if let Some(items) = list.get("items").and_then(Value::as_array) {
                for it in items {
                    on_event("ADDED", it);
                }
            }
            let q = if query.is_empty() { alloc::format!("resourceVersion={rv}") } else { alloc::format!("{query}&resourceVersion={rv}") };
            if let Ok(mut w) = c.watch(&path, &q).await {
                failed = false;
                while let Some(WatchEvent { kind, object }) = w.next().await {
                    match kind.as_str() {
                        "ERROR" => {
                            failed = true;
                            break;
                        }
                        "BOOKMARK" => {}
                        k => on_event(k, &object),
                    }
                }
            }
        }
        if failed {
            exec::sleep(cfg.backoff_ms).await;
        }
    }
}

/// Runs `f` again while it fails with 409 Conflict (read-modify-write loops).
pub async fn retry_conflict<T, F, Fut>(mut f: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut tries = 0;
    loop {
        match f().await {
            Err(e) if is_conflict(&e) && tries < 8 => tries += 1,
            r => return r,
        }
    }
}

pub fn is_conflict(e: &ApiError) -> bool {
    e.code == 409 && e.reason == "Conflict"
}

pub fn not_found_ok<T: Default>(r: Result<T>) -> Result<T> {
    match r {
        Err(e) if e.code == 404 => Ok(T::default()),
        r => r,
    }
}

// ---- paths ----

pub const MERGE: &str = "application/merge-patch+json";

pub fn api_path(group: &str, version: &str, ns: Option<&str>, plural: &str) -> String {
    let base = if group.is_empty() { alloc::format!("/api/{version}") } else { alloc::format!("/apis/{group}/{version}") };
    match ns {
        Some(ns) => alloc::format!("{base}/namespaces/{ns}/{plural}"),
        None => alloc::format!("{base}/{plural}"),
    }
}

pub fn pods(ns: Option<&str>) -> String {
    api_path("", "v1", ns, "pods")
}
pub fn replicasets(ns: Option<&str>) -> String {
    api_path("apps", "v1", ns, "replicasets")
}
pub fn replicationcontrollers(ns: Option<&str>) -> String {
    api_path("", "v1", ns, "replicationcontrollers")
}
pub fn deployments(ns: Option<&str>) -> String {
    api_path("apps", "v1", ns, "deployments")
}
pub fn statefulsets(ns: Option<&str>) -> String {
    api_path("apps", "v1", ns, "statefulsets")
}
pub fn daemonsets(ns: Option<&str>) -> String {
    api_path("apps", "v1", ns, "daemonsets")
}
pub fn controllerrevisions(ns: Option<&str>) -> String {
    api_path("apps", "v1", ns, "controllerrevisions")
}
pub fn jobs(ns: Option<&str>) -> String {
    api_path("batch", "v1", ns, "jobs")
}
pub fn cronjobs(ns: Option<&str>) -> String {
    api_path("batch", "v1", ns, "cronjobs")
}
pub fn services(ns: Option<&str>) -> String {
    api_path("", "v1", ns, "services")
}
pub fn endpoints(ns: Option<&str>) -> String {
    api_path("", "v1", ns, "endpoints")
}
pub fn endpointslices(ns: Option<&str>) -> String {
    api_path("discovery.k8s.io", "v1", ns, "endpointslices")
}
pub fn pvcs(ns: Option<&str>) -> String {
    api_path("", "v1", ns, "persistentvolumeclaims")
}
pub const NODES: &str = "/api/v1/nodes";

/// Percent-encodes a query value.
pub fn enc(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/') {
            o.push(b as char);
        } else {
            o.push_str(&alloc::format!("%{b:02X}"));
        }
    }
    o
}

pub fn split_key(key: &str) -> (&str, &str) {
    key.split_once('/').unwrap_or(("", key))
}

// ---- object helpers ----

pub fn str_at<'a>(o: &'a Value, path: &[&str]) -> &'a str {
    o.pointer(path).and_then(Value::as_str).unwrap_or("")
}
pub fn int_at(o: &Value, path: &[&str], default: i64) -> i64 {
    o.pointer(path).and_then(Value::as_i64).unwrap_or(default)
}
pub fn name(o: &Value) -> &str {
    str_at(o, &["metadata", "name"])
}
pub fn namespace(o: &Value) -> &str {
    str_at(o, &["metadata", "namespace"])
}
pub fn uid(o: &Value) -> &str {
    str_at(o, &["metadata", "uid"])
}
pub fn key_of(o: &Value) -> String {
    alloc::format!("{}/{}", namespace(o), name(o))
}
pub fn deleting(o: &Value) -> bool {
    o.pointer(&["metadata", "deletionTimestamp"]).is_some()
}
pub fn items(list: &Value) -> Vec<Value> {
    list.get("items").and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default()
}

pub fn obj(fields: Vec<(&str, Value)>) -> Value {
    kr_apiserver::object::obj(fields)
}
pub fn num(n: i64) -> Value {
    Value::Number(kr_fmt::json::Number::from_i64(n))
}

/// The `ownerReferences` entry with `controller: true`.
pub fn controller_ref(o: &Value) -> Option<&Value> {
    o.pointer(&["metadata", "ownerReferences"])?.as_array()?.iter().find(|r| r.get("controller").and_then(Value::as_bool) == Some(true))
}

pub fn owner_ref(owner: &Value, api_version: &str, kind: &str) -> Value {
    obj(alloc::vec![
        ("apiVersion", Value::from(api_version)),
        ("kind", Value::from(kind)),
        ("name", Value::from(name(owner))),
        ("uid", Value::from(uid(owner))),
        ("controller", Value::Bool(true)),
        ("blockOwnerDeletion", Value::Bool(true)),
    ])
}

/// Converts a `LabelSelector` (`matchLabels` and `matchExpressions`) to selector-string syntax.
pub fn selector_string(sel: &Value) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(m) = sel.get("matchLabels").and_then(Value::as_object) {
        for (k, v) in m {
            parts.push(alloc::format!("{k}={}", v.as_str().unwrap_or("")));
        }
    }
    if let Some(e) = sel.get("matchExpressions").and_then(Value::as_array) {
        for x in e {
            let key = str_at(x, &["key"]);
            let vals: Vec<&str> = x.get("values").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
            parts.push(match str_at(x, &["operator"]) {
                "In" => alloc::format!("{key} in ({})", vals.join(",")),
                "NotIn" => alloc::format!("{key} notin ({})", vals.join(",")),
                "Exists" => key.to_string(),
                "DoesNotExist" => alloc::format!("!{key}"),
                _ => String::new(),
            });
        }
    }
    parts.retain(|p| !p.is_empty());
    parts.join(",")
}

/// Parses a `LabelSelector`; an empty selector matches nothing (`None`).
pub fn parse_selector(sel: &Value) -> Option<(String, Selector)> {
    let s = selector_string(sel);
    if s.is_empty() {
        return None;
    }
    let p = Selector::parse(&s).ok()?;
    Some((s, p))
}

/// FNV-1a, 32 bit.
pub fn fnv1a32(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in data {
        h ^= *b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// Upstream's `rand.SafeEncodeString`: maps every character into `[bcdfghjklmnpqrstvwxz2456789]`.
pub fn safe_encode(s: &str) -> String {
    const ALPHA: &[u8] = b"bcdfghjklmnpqrstvwxz2456789";
    s.bytes().map(|b| ALPHA[b as usize % ALPHA.len()] as char).collect()
}

/// Recursively sorts object keys so that equal documents serialise identically.
pub fn canonical(v: &Value) -> Value {
    match v {
        Value::Object(o) => {
            let mut o: Vec<(String, Value)> = o.iter().map(|(k, v)| (k.clone(), canonical(v))).collect();
            o.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(o)
        }
        Value::Array(a) => Value::Array(a.iter().map(canonical).collect()),
        v => v.clone(),
    }
}

/// True when the pod's `Ready` condition is `True`.
pub fn pod_ready(p: &Value) -> bool {
    p.pointer(&["status", "conditions"]).and_then(Value::as_array).is_some_and(|c| c.iter().any(|x| str_at(x, &["type"]) == "Ready" && str_at(x, &["status"]) == "True"))
}

/// True when the pod is Ready and has been for `min_ready` seconds (the Ready condition's
/// `lastTransitionTime`; without one a pod only counts when `min_ready` is 0).
pub fn pod_available(p: &Value, min_ready: i64, now: i64) -> bool {
    pod_ready(p) && (min_ready <= 0 || ready_since(p).is_some_and(|t| now - t >= min_ready))
}

/// Seconds until a Ready pod becomes available (`None` when it already is, or is not ready).
pub fn available_in(p: &Value, min_ready: i64, now: i64) -> Option<i64> {
    if !pod_ready(p) || pod_available(p, min_ready, now) {
        return None;
    }
    Some(ready_since(p).map_or(min_ready, |t| t + min_ready - now).max(0))
}

fn ready_since(p: &Value) -> Option<i64> {
    let c = p.pointer(&["status", "conditions"])?.as_array()?.iter().find(|x| str_at(x, &["type"]) == "Ready")?;
    parse_time(str_at(c, &["lastTransitionTime"]))
}

pub fn pod_terminal(p: &Value) -> bool {
    matches!(str_at(p, &["status", "phase"]), "Succeeded" | "Failed")
}

/// Sets (or inserts) the condition of `ty` in a conditions array value.
pub fn set_condition(conds: &mut Vec<Value>, cond: Value) {
    let ty = str_at(&cond, &["type"]).to_string();
    match conds.iter().position(|c| str_at(c, &["type"]) == ty) {
        Some(i) => conds[i] = cond,
        None => conds.push(cond),
    }
}

// ---- shared helpers for the workload controllers ----

pub use kr_apiserver::object::rfc3339;

/// Unix seconds of an RFC 3339 `...Z` timestamp.
pub fn parse_time(s: &str) -> Option<i64> {
    kr_apiserver::printers::parse_rfc3339(s)
}

/// True when the pod is `Running` and its `Ready` condition holds.
pub fn running_ready(p: &Value) -> bool {
    str_at(p, &["status", "phase"]) == "Running" && pod_ready(p)
}

/// True when the object's controller owner reference has this uid.
pub fn controlled_by(o: &Value, owner_uid: &str) -> bool {
    controller_ref(o).is_some_and(|r| str_at(r, &["uid"]) == owner_uid)
}

/// DELETE that treats 404 as success.
pub async fn delete_ok<C: Client>(c: &C, path: &str) -> Result<()> {
    match c.delete(path).await {
        Ok(_) => Ok(()),
        Err(e) if e.code == 404 => Ok(()),
        Err(e) => Err(e),
    }
}

/// GET that maps 404 to `None`.
pub async fn get_opt<C: Client>(c: &C, path: &str) -> Result<Option<Value>> {
    match c.get(path).await {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.code == 404 => Ok(None),
        Err(e) => Err(e),
    }
}

/// Reads the object at `path`, derives the wanted `.status` from it with `want` and writes it
/// through `<path>/status` only if it differs (compared canonically). A vanished object is fine.
pub async fn put_status<C: Client>(c: &C, path: &str, want: impl Fn(&Value) -> Value) -> Result<()> {
    retry_conflict(|| async {
        let Some(mut o) = get_opt(c, path).await? else { return Ok(()) };
        let st = want(&o);
        if o.get("status").map(canonical) == Some(canonical(&st)) {
            return Ok(());
        }
        o.set("status", st);
        c.update(&alloc::format!("{path}/status"), &o).await.map(|_| ())
    })
    .await
}

/// Adds the controller reference to an orphan. `None` when the object vanished or was adopted
/// by someone else in the meantime (the patch carries the resourceVersion).
pub async fn adopt<C: Client>(c: &C, path: &str, owner: &Value, api_version: &str, kind: &str, o: &Value) -> Result<Option<Value>> {
    let mut refs: Vec<Value> = o.pointer(&["metadata", "ownerReferences"]).and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
    refs.push(owner_ref(owner, api_version, kind));
    let meta = obj(alloc::vec![("ownerReferences", Value::Array(refs)), ("resourceVersion", Value::from(str_at(o, &["metadata", "resourceVersion"])))]);
    match c.patch(&alloc::format!("{path}/{}", name(o)), MERGE, &obj(alloc::vec![("metadata", meta)])).await {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.code == 404 || e.code == 409 => Ok(None),
        Err(e) => Err(e),
    }
}

/// Drops the owner's reference from an object that no longer matches the owner's selector.
/// A vanished or concurrently changed object is fine (the next pass sees the new state).
pub async fn release_owner<C: Client>(c: &C, path: &str, owner_uid: &str, o: &Value) -> Result<()> {
    let refs: Vec<Value> = o.pointer(&["metadata", "ownerReferences"]).and_then(Value::as_array).map(|a| a.iter().filter(|r| str_at(r, &["uid"]) != owner_uid).cloned().collect()).unwrap_or_default();
    let refs = if refs.is_empty() { Value::Null } else { Value::Array(refs) };
    let meta = obj(alloc::vec![("ownerReferences", refs), ("resourceVersion", Value::from(str_at(o, &["metadata", "resourceVersion"])))]);
    match c.patch(&alloc::format!("{path}/{}", name(o)), MERGE, &obj(alloc::vec![("metadata", meta)])).await {
        Ok(_) => Ok(()),
        Err(e) if e.code == 404 || e.code == 409 => Ok(()),
        Err(e) => Err(e),
    }
}

/// A pod built from `tpl` (a pod template) and owned by `owner`. `name` is either a fixed name
/// or a `generateName` prefix. Extra labels and annotations are merged over the template's.
pub fn pod_from_template(owner: &Value, api_version: &str, kind: &str, tpl: &Value, fixed_name: Option<&str>, generate_prefix: &str, labels: &[(&str, &str)], annotations: &[(&str, &str)]) -> Value {
    let mut meta = Value::Object(Vec::new());
    match fixed_name {
        Some(n) => meta.set("name", Value::from(n)),
        None => meta.set("generateName", Value::from(generate_prefix)),
    }
    meta.set("namespace", Value::from(namespace(owner)));
    for (field, extra) in [("labels", labels), ("annotations", annotations)] {
        let mut m = tpl.pointer(&["metadata", field]).cloned().unwrap_or(Value::Null);
        if !extra.is_empty() && !matches!(m, Value::Object(_)) {
            m = Value::Object(Vec::new());
        }
        for (k, v) in extra {
            m.set(k, Value::from(*v));
        }
        if !m.is_null() {
            meta.set(field, m);
        }
    }
    meta.set("ownerReferences", Value::Array(alloc::vec![owner_ref(owner, api_version, kind)]));
    obj(alloc::vec![("apiVersion", Value::from("v1")), ("kind", Value::from("Pod")), ("metadata", meta), ("spec", tpl.get("spec").cloned().unwrap_or(Value::Null))])
}

/// One `matchExpressions` / `matchFields` requirement against an optional value.
fn expr_matches(e: &Value, value: Option<&str>) -> bool {
    let vals: Vec<&str> = e.get("values").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    match str_at(e, &["operator"]) {
        "In" => value.is_some_and(|v| vals.contains(&v)),
        "NotIn" => value.is_none_or(|v| !vals.contains(&v)),
        "Exists" => value.is_some(),
        "DoesNotExist" => value.is_none(),
        op @ ("Gt" | "Lt") => match (value.and_then(|v| v.parse::<i64>().ok()), vals.first().and_then(|v| v.parse::<i64>().ok())) {
            (Some(a), Some(b)) => (op == "Gt" && a > b) || (op == "Lt" && a < b),
            _ => false,
        },
        _ => false,
    }
}

/// `requiredDuringSchedulingIgnoredDuringExecution` node affinity of a pod spec against a node:
/// the terms are ORed, the expressions and fields of a term ANDed, an empty term matches
/// nothing. No affinity matches every node.
pub fn node_affinity_matches(spec: &Value, node: &Value) -> bool {
    let Some(req) = spec.pointer(&["affinity", "nodeAffinity", "requiredDuringSchedulingIgnoredDuringExecution"]) else { return true };
    let terms = req.get("nodeSelectorTerms").and_then(Value::as_array).unwrap_or(&[]);
    terms.iter().any(|t| {
        let exprs = t.get("matchExpressions").and_then(Value::as_array).unwrap_or(&[]);
        let fields = t.get("matchFields").and_then(Value::as_array).unwrap_or(&[]);
        !(exprs.is_empty() && fields.is_empty())
            && exprs.iter().all(|e| expr_matches(e, node.pointer(&["metadata", "labels", str_at(e, &["key"])]).and_then(Value::as_str)))
            && fields.iter().all(|e| expr_matches(e, if str_at(e, &["key"]) == "metadata.name" { Some(name(node)) } else { None }))
    })
}

/// Joins `a, b, c` style ordinal sets such as `0-2,4` (job `completedIndexes`).
pub fn compress_indexes(idx: &[i64]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < idx.len() {
        let mut j = i;
        while j + 1 < idx.len() && idx[j + 1] == idx[j] + 1 {
            j += 1;
        }
        if !out.is_empty() {
            out.push(',');
        }
        if j > i {
            out.push_str(&alloc::format!("{}-{}", idx[i], idx[j]));
        } else {
            out.push_str(&idx[i].to_string());
        }
        i = j + 1;
    }
    out
}

/// Merges an optional old condition's `lastTransitionTime` into `cond`: kept while the status
/// is unchanged, and the whole old condition is returned unchanged when nothing differs.
pub fn merge_condition(old: &[Value], mut cond: Value) -> Value {
    let ty = str_at(&cond, &["type"]);
    if let Some(o) = old.iter().find(|o| str_at(o, &["type"]) == ty) {
        if ["status", "reason", "message"].iter().all(|f| str_at(o, &[f]) == str_at(&cond, &[f])) {
            return o.clone();
        }
        if str_at(o, &["status"]) == str_at(&cond, &["status"]) {
            cond.set("lastTransitionTime", Value::from(str_at(o, &["lastTransitionTime"])));
        }
    }
    cond
}

pub fn condition(ty: &str, status: bool, reason: &str, message: &str, now: i64) -> Value {
    let t = Value::String(rfc3339(now));
    obj(alloc::vec![
        ("type", Value::from(ty)),
        ("status", Value::from(if status { "True" } else { "False" })),
        ("lastProbeTime", t.clone()),
        ("lastTransitionTime", t),
        ("reason", Value::from(reason)),
        ("message", Value::from(message)),
    ])
}

pub fn has_condition(o: &Value, ty: &str) -> bool {
    o.pointer(&["status", "conditions"]).and_then(Value::as_array).is_some_and(|c| c.iter().any(|x| str_at(x, &["type"]) == ty && str_at(x, &["status"]) == "True"))
}

// ---- ControllerRevisions (StatefulSet, DaemonSet) ----

/// Finds or creates the ControllerRevision `<owner>-<hash of template>` for `owner`, bumping
/// its `revision` above every other one when the template is reused (rollback). Returns the
/// revision's name and all revisions controlled by the owner (including the new one).
pub async fn ensure_revision<C: Client>(c: &C, owner: &Value, kind: &str, template: &Value) -> Result<(String, Vec<Value>)> {
    let ns = namespace(owner);
    let rname = alloc::format!("{}-{}", name(owner), crate::deployment::template_hash(template));
    let mut revs: Vec<Value> = items(&c.list(&controllerrevisions(Some(ns)), "").await?).into_iter().filter(|r| controlled_by(r, uid(owner))).collect();
    let max = revs.iter().map(|r| int_at(r, &["revision"], 0)).max().unwrap_or(0);
    match revs.iter_mut().find(|r| name(r) == rname) {
        Some(r) => {
            if int_at(r, &["revision"], 0) < max {
                let patch = obj(alloc::vec![("revision", num(max + 1))]);
                *r = c.patch(&alloc::format!("{}/{rname}", controllerrevisions(Some(ns))), MERGE, &patch).await?;
            }
        }
        None => {
            let mut labels = owner.pointer(&["spec", "selector", "matchLabels"]).cloned().unwrap_or(Value::Object(Vec::new()));
            let hash = rname[name(owner).len() + 1..].to_string();
            labels.set("controller.kubernetes.io/hash", Value::String(hash.clone()));
            labels.set("controller-revision-hash", Value::String(hash));
            let rev = obj(alloc::vec![
                ("apiVersion", Value::from("apps/v1")),
                ("kind", Value::from("ControllerRevision")),
                (
                    "metadata",
                    obj(alloc::vec![
                        ("name", Value::from(rname.as_str())),
                        ("namespace", Value::from(ns)),
                        ("labels", labels),
                        ("ownerReferences", Value::Array(alloc::vec![owner_ref(owner, "apps/v1", kind)])),
                    ])
                ),
                ("data", obj(alloc::vec![("spec", obj(alloc::vec![("template", template.clone())]))])),
                ("revision", num(max + 1)),
            ]);
            match c.create(&controllerrevisions(Some(ns)), &rev).await {
                Ok(r) => revs.push(r),
                Err(e) if e.code == 409 => revs.push(c.get(&alloc::format!("{}/{rname}", controllerrevisions(Some(ns)))).await?),
                Err(e) => return Err(e),
            }
        }
    }
    Ok((rname, revs))
}

/// Deletes the oldest revisions not named in `live` beyond `limit`.
pub async fn trim_revisions<C: Client>(c: &C, ns: &str, revs: &[Value], live: &[&str], limit: usize) -> Result<()> {
    let mut dead: Vec<&Value> = revs.iter().filter(|r| !live.contains(&name(r))).collect();
    if dead.len() <= limit {
        return Ok(());
    }
    dead.sort_by_key(|r| (int_at(r, &["revision"], 0), name(r).to_string()));
    for r in dead.iter().take(dead.len() - limit) {
        delete_ok(c, &alloc::format!("{}/{}", controllerrevisions(Some(ns)), name(r))).await?;
    }
    Ok(())
}
