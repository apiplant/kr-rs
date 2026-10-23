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
pub fn deployments(ns: Option<&str>) -> String {
    api_path("apps", "v1", ns, "deployments")
}

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
