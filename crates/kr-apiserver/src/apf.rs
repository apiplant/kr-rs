//! API priority and fairness: every request is classified by the first matching `FlowSchema`
//! (lowest `matchingPrecedence`) into a `PriorityLevelConfiguration`. A level has a concurrency
//! limit (its share of [`TOTAL_SEATS`]); requests over it wait in per-flow queues served round
//! robin (`limitResponse: Queue`) or are refused with 429 (`Reject`, or a full queue, or a wait
//! over [`MAX_WAIT_MS`]). A request takes `width` seats (a LIST costs one seat per 100 objects it
//! may return, at most [`MAX_WIDTH`]); a level may use seats other levels lend (`lendablePercent`)
//! up to its `borrowingLimitPercent` while they are idle. The `Exempt` level never waits. Long-running requests (watches,
//! exec/attach/port-forward/proxy, `kr` internals) and requests forwarded by another server are
//! not subject to it. Responses carry `X-Kubernetes-PF-FlowSchema-UID` / `-PriorityLevel-UID`.

use crate::api::{ApiServer, Req, User};
use crate::object::ApiError;
use crate::resources;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::rc::{Rc, Weak};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use kr_fmt::json::Value;

/// Default concurrent seats shared among the limited levels by `nominalConcurrencyShares`
/// (upstream's default `--max-requests-inflight` + `--max-mutating-requests-inflight`);
/// `KR_APF_SEATS` overrides it.
const DEFAULT_SEATS: u64 = 600;
/// Most seats one request takes.
const MAX_WIDTH: usize = 10;
/// Objects per seat of a LIST.
const OBJECTS_PER_SEAT: usize = 100;
/// A queued request is refused after this long.
const MAX_WAIT_MS: u64 = 15_000;
/// The configuration is re-read at most this often.
const RELOAD_MS: u64 = 1_000;

struct Slot {
    width: usize,
    granted: Cell<bool>,
    waker: RefCell<Option<Waker>>,
}

struct Wait(Rc<Slot>);

impl Future for Wait {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0.granted.get() {
            return Poll::Ready(());
        }
        *self.0.waker.borrow_mut() = Some(cx.waker().clone());
        Poll::Pending
    }
}

#[derive(Default)]
struct LState {
    queues: BTreeMap<String, VecDeque<Rc<Slot>>>,
    queued: usize,
    /// Round-robin position over the flow queues.
    rr: usize,
}

pub struct Level {
    name: String,
    uid: String,
    exempt: bool,
    limit: usize,
    /// Seats of the limit other levels may borrow while idle.
    lendable: usize,
    /// Most seats above `limit` this level may borrow.
    borrow_max: usize,
    /// Seats in use.
    inflight: Cell<usize>,
    /// Requests this level refused and admitted (since the level was built).
    rejected: Cell<u64>,
    admitted: Cell<u64>,
    pool: Rc<Pool>,
    reject: bool,
    max_queued: usize,
    /// The settings this level was built from (a changed object builds a new level).
    sig: String,
    state: RefCell<LState>,
}

/// The levels that lend and borrow seats among each other.
#[derive(Default)]
pub struct Pool {
    levels: RefCell<Vec<Weak<Level>>>,
}

impl Pool {
    /// Lendable seats that nobody uses: each level's lendable part, less what its own requests
    /// occupy above its guaranteed seats, less what levels borrowed above their limit.
    fn free(&self) -> usize {
        let (mut cap, mut used) = (0usize, 0usize);
        for l in self.levels.borrow().iter().filter_map(Weak::upgrade) {
            let n = l.inflight.get();
            cap += l.lendable;
            used += n.saturating_sub(l.limit - l.lendable).min(l.lendable) + n.saturating_sub(l.limit);
        }
        cap.saturating_sub(used)
    }
}

impl Level {
    /// Whether `w` more seats are available: within the limit, or borrowed from idle lenders.
    fn can_take(&self, w: usize) -> bool {
        let new = self.inflight.get() + w;
        if new <= self.limit {
            return true;
        }
        let need = new - self.limit.max(self.inflight.get());
        new - self.limit <= self.borrow_max && self.pool.free() >= need
    }

    /// Hands the freed seats to the next queued requests (round robin over flows), here and in
    /// the levels that may now borrow what this one gave back.
    fn release(&self, width: usize) {
        self.inflight.set(self.inflight.get().saturating_sub(width));
        self.dispatch(&mut self.state.borrow_mut());
        let others: Vec<Rc<Level>> = self.pool.levels.borrow().iter().filter_map(Weak::upgrade).collect();
        for o in others.iter().filter(|o| !core::ptr::eq(&***o, self)) {
            if let Ok(mut st) = o.state.try_borrow_mut() {
                o.dispatch(&mut st);
            }
        }
    }

    fn dispatch(&self, st: &mut LState) {
        while st.queued > 0 {
            let keys: Vec<String> = st.queues.keys().cloned().collect();
            let key = keys[st.rr % keys.len()].clone();
            let q = st.queues.get_mut(&key).unwrap();
            if !q.front().is_some_and(|s| self.can_take(s.width)) {
                break;
            }
            st.rr = st.rr.wrapping_add(1);
            let slot = q.pop_front();
            if q.is_empty() {
                st.queues.remove(&key);
            }
            let Some(slot) = slot else { continue };
            st.queued -= 1;
            self.inflight.set(self.inflight.get() + slot.width);
            slot.granted.set(true);
            let waker = slot.waker.borrow_mut().take();
            if let Some(w) = waker {
                w.wake();
            }
        }
    }
}

/// A seat in a priority level, returned when dropped.
pub struct Permit(Option<(Rc<Level>, usize)>);

impl Drop for Permit {
    fn drop(&mut self) {
        if let Some((l, w)) = self.0.take() {
            l.release(w);
        }
    }
}

#[derive(Clone)]
enum Distinguisher {
    None,
    ByUser,
    ByNamespace,
}

struct Subject {
    kind: String,
    name: String,
    ns: String,
}

struct Rule {
    subjects: Vec<Subject>,
    resource_rules: Vec<ResourceRule>,
    non_resource: Vec<(Vec<String>, Vec<String>)>,
}

struct ResourceRule {
    verbs: Vec<String>,
    groups: Vec<String>,
    resources: Vec<String>,
    namespaces: Vec<String>,
    cluster_scope: bool,
}

struct Flow {
    name: String,
    uid: String,
    precedence: i64,
    level: String,
    dist: Distinguisher,
    rules: Vec<Rule>,
}

#[derive(Default)]
struct Config {
    flows: Vec<Flow>,
    levels: BTreeMap<String, Rc<Level>>,
}

impl Apf {
    /// Prometheus text for `/metrics`: per priority level its seat limit, seats in use, seats
    /// borrowed from other levels, queued requests, and the requests admitted and refused.
    pub fn metrics(&self) -> String {
        use core::fmt::Write;
        let mut o = String::new();
        let cfg = self.cfg.borrow();
        let gauge = |o: &mut String, name: &str, help: &str, f: &dyn Fn(&Level) -> u64, ty: &str| {
            let _ = write!(o, "# HELP {name} {help}\n# TYPE {name} {ty}\n");
            for l in cfg.levels.values().filter(|l| !l.exempt) {
                let _ = writeln!(o, "{name}{{priority_level=\"{}\"}} {}", l.name, f(l));
            }
        };
        gauge(&mut o, "kr_apf_seats_limit", "Seats a priority level may use before borrowing.", &|l| l.limit as u64, "gauge");
        gauge(&mut o, "kr_apf_seats_in_use", "Seats in use by requests being served.", &|l| l.inflight.get() as u64, "gauge");
        gauge(&mut o, "kr_apf_seats_borrowed", "Seats in use above the level's limit (borrowed from idle levels).", &|l| l.inflight.get().saturating_sub(l.limit) as u64, "gauge");
        gauge(&mut o, "kr_apf_queued_requests", "Requests waiting for seats.", &|l| l.state.try_borrow().map_or(0, |s| s.queued as u64), "gauge");
        gauge(&mut o, "kr_apf_admitted_requests_total", "Requests admitted since the level was built.", &|l| l.admitted.get(), "counter");
        gauge(&mut o, "kr_apf_rejected_requests_total", "Requests refused with 429 since the level was built.", &|l| l.rejected.get(), "counter");
        o
    }
}

pub struct Apf {
    cfg: RefCell<Config>,
    loaded_ms: Cell<u64>,
    /// Total seats (0 until `KR_APF_SEATS` is read).
    seats: Cell<u64>,
    pool: Rc<Pool>,
}

/// `KR_APF_SEATS`: a positive number, else the default.
fn parse_seats(v: Option<&str>) -> u64 {
    v.and_then(|s| s.trim().parse::<u64>().ok()).filter(|&n| n > 0).unwrap_or(DEFAULT_SEATS)
}

fn env_seats() -> u64 {
    let data = kr_sys::fs::read_file(b"/proc/self/environ\0", 4 << 20).unwrap_or_default();
    let v = data.split(|&b| b == 0).find_map(|kv| kv.strip_prefix(b"KR_APF_SEATS="));
    parse_seats(v.and_then(|v| core::str::from_utf8(v).ok()))
}

impl Default for Apf {
    fn default() -> Self {
        Apf { cfg: RefCell::new(Config::default()), loaded_ms: Cell::new(0), seats: Cell::new(0), pool: Rc::new(Pool::default()) }
    }
}

fn strs(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect()).unwrap_or_default()
}

fn has(list: &[String], x: &str) -> bool {
    list.iter().any(|e| e == "*" || e == x)
}

fn parse_flow(o: &Value) -> Option<Flow> {
    let s = |p: &[&str]| o.pointer(p).and_then(Value::as_str).map(String::from);
    let dist = match s(&["spec", "distinguisherMethod", "type"]).as_deref() {
        Some("ByUser") => Distinguisher::ByUser,
        Some("ByNamespace") => Distinguisher::ByNamespace,
        _ => Distinguisher::None,
    };
    let mut rules = Vec::new();
    for r in o.pointer(&["spec", "rules"]).and_then(Value::as_array).unwrap_or(&[]) {
        let subjects = r
            .get("subjects")
            .and_then(Value::as_array)
            .unwrap_or(&[])
            .iter()
            .map(|x| {
                let kind = x.get("kind").and_then(Value::as_str).unwrap_or("").to_string();
                let t = |k: &str, f: &str| x.pointer(&[k, f]).and_then(Value::as_str).unwrap_or("").to_string();
                match kind.as_str() {
                    "User" => Subject { name: t("user", "name"), ns: String::new(), kind },
                    "Group" => Subject { name: t("group", "name"), ns: String::new(), kind },
                    _ => Subject { name: t("serviceAccount", "name"), ns: t("serviceAccount", "namespace"), kind },
                }
            })
            .collect();
        let resource_rules = r
            .get("resourceRules")
            .and_then(Value::as_array)
            .unwrap_or(&[])
            .iter()
            .map(|x| ResourceRule { verbs: strs(x.get("verbs")), groups: strs(x.get("apiGroups")), resources: strs(x.get("resources")), namespaces: strs(x.get("namespaces")), cluster_scope: x.get("clusterScope").and_then(Value::as_bool).unwrap_or(false) })
            .collect();
        let non_resource = r.get("nonResourceRules").and_then(Value::as_array).unwrap_or(&[]).iter().map(|x| (strs(x.get("verbs")), strs(x.get("nonResourceURLs")))).collect();
        rules.push(Rule { subjects, resource_rules, non_resource });
    }
    Some(Flow {
        name: s(&["metadata", "name"])?,
        uid: s(&["metadata", "uid"]).unwrap_or_default(),
        precedence: o.pointer(&["spec", "matchingPrecedence"]).and_then(Value::as_i64).unwrap_or(1000),
        level: s(&["spec", "priorityLevelConfiguration", "name"])?,
        dist,
        rules,
    })
}

/// What the request addresses, in the terms of a FlowSchema rule.
struct Info {
    verb: &'static str,
    resource: bool,
    group: String,
    res: String,
    sub: String,
    ns: String,
    path: String,
    ver: String,
}

fn info(req: &Req) -> Info {
    let segs: Vec<&str> = req.path.trim_matches('/').split('/').collect();
    let watch = req.query.split('&').any(|p| p == "watch=true" || p == "watch=1" || p == "watch");
    let (mut group, mut rest): (String, &[&str]) = (String::new(), &[]);
    let mut resource = true;
    let mut ver = "";
    match segs.first().copied() {
        Some("api") if segs.len() >= 3 => {
            ver = segs[1];
            rest = &segs[2..]
        }
        Some("apis") if segs.len() >= 4 => {
            group = segs[1].to_string();
            ver = segs[2];
            rest = &segs[3..];
        }
        _ => resource = false,
    }
    let (mut ns, mut res, mut name, mut sub) = (String::new(), "", "", "");
    if rest.first() == Some(&"watch") {
        rest = &rest[1..];
    }
    if resource && !rest.is_empty() {
        if rest[0] == "namespaces" && rest.len() >= 3 {
            ns = rest[1].to_string();
            res = rest[2];
            name = rest.get(3).copied().unwrap_or("");
            sub = rest.get(4).copied().unwrap_or("");
        } else {
            res = rest[0];
            name = rest.get(1).copied().unwrap_or("");
            sub = rest.get(2).copied().unwrap_or("");
        }
    }
    let verb = match req.method {
        "GET" | "HEAD" if watch || segs.get(if group.is_empty() { 2 } else { 3 }) == Some(&"watch") => "watch",
        "GET" | "HEAD" if name.is_empty() && resource => "list",
        "GET" | "HEAD" => "get",
        "POST" => "create",
        "PUT" => "update",
        "PATCH" => "patch",
        "DELETE" if name.is_empty() => "deletecollection",
        "DELETE" => "delete",
        _ => "get",
    };
    Info { verb, resource: resource && !res.is_empty(), group, res: res.to_string(), sub: sub.to_string(), ns, path: req.path.to_string(), ver: ver.to_string() }
}

fn subject_matches(s: &Subject, user: &User) -> bool {
    match s.kind.as_str() {
        "User" => s.name == "*" || s.name == user.name,
        "Group" => s.name == "*" || user.groups.iter().any(|g| *g == s.name),
        _ => {
            let Some(rest) = user.name.strip_prefix("system:serviceaccount:") else { return false };
            let (ns, name) = rest.split_once(':').unwrap_or((rest, ""));
            (s.ns == "*" || s.ns == ns) && (s.name == "*" || s.name == name)
        }
    }
}

fn url_matches(pats: &[String], path: &str) -> bool {
    pats.iter().any(|p| p == "*" || p == path || p.strip_suffix('*').is_some_and(|pre| path.starts_with(pre)))
}

fn rule_matches(r: &Rule, user: &User, i: &Info) -> bool {
    if !r.subjects.iter().any(|s| subject_matches(s, user)) {
        return false;
    }
    if i.resource {
        r.resource_rules.iter().any(|rr| {
            let res_ok = has(&rr.resources, &i.res) || (!i.sub.is_empty() && (has(&rr.resources, &alloc::format!("{}/{}", i.res, i.sub)) || rr.resources.iter().any(|x| *x == alloc::format!("*/{}", i.sub))));
            let scope_ok = if i.ns.is_empty() { rr.cluster_scope } else { has(&rr.namespaces, &i.ns) };
            has(&rr.verbs, i.verb) && has(&rr.groups, &i.group) && res_ok && scope_ok
        })
    } else {
        r.non_resource.iter().any(|(verbs, urls)| has(verbs, i.verb) && url_matches(urls, &i.path))
    }
}

/// Requests APF leaves alone: long-running ones, kr's own endpoints and probes of the server.
fn skipped(req: &Req, i: &Info) -> bool {
    i.verb == "watch" || req.path.starts_with("/kr/") || matches!(i.sub.as_str(), "exec" | "attach" | "portforward" | "proxy") || (i.sub == "log" && req.query.split('&').any(|p| p == "follow=true"))
}

impl Apf {
    fn reload(&self, api: &ApiServer) {
        let now = kr_rt::exec::now_ms();
        if self.loaded_ms.get() != 0 && now.saturating_sub(self.loaded_ms.get()) < RELOAD_MS {
            return;
        }
        self.loaded_ms.set(now);
        let g = "flowcontrol.apiserver.k8s.io";
        let mut flows: Vec<Flow> = api.wh_list(g, "v1", "flowschemas").iter().filter_map(parse_flow).collect();
        flows.sort_by(|a, b| a.precedence.cmp(&b.precedence).then(a.name.cmp(&b.name)));
        let objs = api.wh_list(g, "v1", "prioritylevelconfigurations");
        let shares = |o: &Value| o.pointer(&["spec", "limited", "nominalConcurrencyShares"]).and_then(Value::as_u64).unwrap_or(30);
        let total: u64 = objs.iter().filter(|o| o.pointer(&["spec", "type"]).and_then(Value::as_str) == Some("Limited")).map(shares).sum::<u64>().max(1);
        if self.seats.get() == 0 {
            self.seats.set(env_seats());
        }
        let total_seats = self.seats.get();
        let mut cfg = self.cfg.borrow_mut();
        let mut levels = BTreeMap::new();
        for o in &objs {
            let Some(name) = o.pointer(&["metadata", "name"]).and_then(Value::as_str) else { continue };
            let exempt = o.pointer(&["spec", "type"]).and_then(Value::as_str) == Some("Exempt");
            let lim = |k: &str| o.pointer(&["spec", "limited", "limitResponse", "queuing", k]).and_then(Value::as_u64);
            let reject = o.pointer(&["spec", "limited", "limitResponse", "type"]).and_then(Value::as_str) == Some("Reject");
            let limit = (total_seats * shares(o)).div_ceil(total).max(1) as usize;
            let lendable = (limit * (o.pointer(&["spec", "limited", "lendablePercent"]).and_then(Value::as_u64).unwrap_or(0).min(100) as usize) / 100).min(limit);
            let borrow_max = o.pointer(&["spec", "limited", "borrowingLimitPercent"]).and_then(Value::as_u64).map_or(usize::MAX, |p| limit.saturating_mul(p as usize) / 100);
            let max_queued = (lim("queues").unwrap_or(64) * lim("queueLengthLimit").unwrap_or(50)) as usize;
            let uid = o.pointer(&["metadata", "uid"]).and_then(Value::as_str).unwrap_or("").to_string();
            let sig = alloc::format!("{uid}/{exempt}/{reject}/{limit}/{lendable}/{borrow_max}/{max_queued}");
            let level = match cfg.levels.get(name) {
                Some(old) if old.sig == sig => old.clone(),
                _ => {
                    let inflight = Cell::new(cfg.levels.get(name).map_or(0, |o| o.inflight.get()));
                    Rc::new(Level { name: name.to_string(), uid, exempt, limit, lendable, borrow_max, inflight, rejected: Cell::new(0), admitted: Cell::new(0), pool: self.pool.clone(), reject, max_queued, sig, state: RefCell::new(LState::default()) })
                },
            };
            levels.insert(name.to_string(), level);
        }
        *self.pool.levels.borrow_mut() = levels.values().filter(|l| !l.exempt).map(Rc::downgrade).collect();
        cfg.levels = levels;
        cfg.flows = flows;
    }
}

/// Seats a request takes: 1, except a LIST, which takes one per [`OBJECTS_PER_SEAT`] objects it
/// may return (the stored count, bounded by `limit=`), at most [`MAX_WIDTH`].
fn width_of(api: &ApiServer, i: &Info, req: &Req) -> usize {
    if i.verb != "list" || !i.resource || !i.sub.is_empty() {
        return 1;
    }
    let Some(r) = api.all_resources().into_iter().find(|r| r.group == i.group && r.version == i.ver && r.plural == i.res) else { return 1 };
    let prefix = if i.ns.is_empty() { r.prefix() } else { alloc::format!("{}{}/", r.prefix(), i.ns) };
    let mut n = api.store.borrow().count(&prefix);
    if let Some(l) = req.query.split('&').find_map(|p| p.strip_prefix("limit=")).and_then(|v| v.parse::<usize>().ok()).filter(|&l| l > 0) {
        n = n.min(l);
    }
    width_for(n)
}

fn width_for(objects: usize) -> usize {
    objects.div_ceil(OBJECTS_PER_SEAT).clamp(1, MAX_WIDTH)
}

/// Classifies `req` and waits for a seat. `Ok` carries the permit (None when the request is not
/// subject to APF) and the (flow schema, priority level) UIDs for the response headers.
pub async fn admit(api: &ApiServer, req: &Req<'_>) -> Result<(Permit, Option<(String, String)>), ApiError> {
    let i = info(req);
    if skipped(req, &i) {
        return Ok((Permit(None), None));
    }
    api.apf.reload(api);
    let user = api.authenticate(req).unwrap_or(User { name: "system:anonymous".into(), groups: alloc::vec!["system:unauthenticated".into()] });
    let (level, ids, flow_key) = {
        let cfg = api.apf.cfg.borrow();
        // No flow schema matches (or its level is missing): the request is not throttled.
        let Some(f) = cfg.flows.iter().find(|f| f.rules.iter().any(|r| rule_matches(r, &user, &i))) else { return Ok((Permit(None), None)) };
        let Some(level) = cfg.levels.get(&f.level).cloned() else { return Ok((Permit(None), None)) };
        let key = match f.dist {
            Distinguisher::ByUser => alloc::format!("{}/{}", f.name, user.name),
            Distinguisher::ByNamespace => alloc::format!("{}/{}", f.name, i.ns),
            Distinguisher::None => f.name.clone(),
        };
        let ids = (f.uid.clone(), level.uid.clone());
        (level, ids, key)
    };
    if level.exempt {
        return Ok((Permit(None), Some(ids)));
    }
    let too_many = |why: &str| {
        level.rejected.set(level.rejected.get() + 1);
        ApiError::new(429, "TooManyRequests", alloc::format!("Too many requests ({why}), please try again later."))
    };
    let width = width_of(api, &i, req).min(level.limit.max(1));
    let slot = {
        let mut st = level.state.borrow_mut();
        if st.queued == 0 && level.can_take(width) {
            level.inflight.set(level.inflight.get() + width);
            level.admitted.set(level.admitted.get() + 1);
            return Ok((Permit(Some((level.clone(), width))), Some(ids)));
        }
        if level.reject {
            return Err(too_many(&alloc::format!("priority level {} is at its limit", level.name)));
        }
        if st.queued >= level.max_queued {
            return Err(too_many(&alloc::format!("the queue of priority level {} is full", level.name)));
        }
        let slot = Rc::new(Slot { width, granted: Cell::new(false), waker: RefCell::new(None) });
        st.queues.entry(flow_key.clone()).or_default().push_back(slot.clone());
        st.queued += 1;
        slot
    };
    let waited = kr_rt::exec::timeout(MAX_WAIT_MS, Wait(slot.clone())).await;
    if waited.is_err() && !slot.granted.get() {
        let mut st = level.state.borrow_mut();
        if let Some(q) = st.queues.get_mut(&flow_key) {
            if let Some(pos) = q.iter().position(|s| Rc::ptr_eq(s, &slot)) {
                q.remove(pos);
                st.queued -= 1;
            }
            if st.queues.get(&flow_key).is_some_and(VecDeque::is_empty) {
                st.queues.remove(&flow_key);
            }
        }
        return Err(too_many(&alloc::format!("timed out waiting in priority level {}", level.name)));
    }
    level.admitted.set(level.admitted.get() + 1);
    Ok((Permit(Some((level, width))), Some(ids)))
}

/// The suggested FlowSchemas and PriorityLevelConfigurations (created when missing).
pub(crate) fn seed(api: &ApiServer) {
    let g = "flowcontrol.apiserver.k8s.io";
    let (Some(plr), Some(fsr)) = (resources::find(g, "v1", "prioritylevelconfigurations"), resources::find(g, "v1", "flowschemas")) else { return };
    let ann = r#""annotations":{"apf.kubernetes.io/autoupdate-spec":"true"}"#;
    let put = |res, name: &str, kind: &str, body: String| {
        api.bootstrap_object(res, None, name, kind, &body);
        api.reconcile_spec(res, name, &body);
    };
    put(plr, "exempt", "PriorityLevelConfiguration", alloc::format!(r#"{{"metadata":{{"name":"exempt",{ann}}},"spec":{{"type":"Exempt","exempt":{{"nominalConcurrencyShares":0,"lendablePercent":0}}}}}}"#));
    // (name, shares, lendable %, queues, hand size, queue length limit); queues 0 = Reject.
    for (name, shares, lend, queues, hand) in [("node-high", 40, 25, 64, 6), ("system", 30, 33, 64, 6), ("leader-election", 10, 0, 16, 4), ("workload-high", 40, 50, 128, 6), ("workload-low", 100, 90, 128, 6), ("global-default", 20, 50, 128, 6), ("catch-all", 5, 0, 0, 0)] {
        let resp = if queues == 0 { r#"{"type":"Reject"}"#.to_string() } else { alloc::format!(r#"{{"type":"Queue","queuing":{{"queues":{queues},"handSize":{hand},"queueLengthLimit":50}}}}"#) };
        put(plr, name, "PriorityLevelConfiguration", alloc::format!(r#"{{"metadata":{{"name":"{name}",{ann}}},"spec":{{"type":"Limited","limited":{{"nominalConcurrencyShares":{shares},"lendablePercent":{lend},"limitResponse":{resp}}}}}}}"#));
    }
    let all_res = r#"{"verbs":["*"],"apiGroups":["*"],"resources":["*"],"clusterScope":true,"namespaces":["*"]}"#;
    let all_non = r#"{"verbs":["*"],"nonResourceURLs":["*"]}"#;
    let group = |g: &str| alloc::format!(r#"{{"kind":"Group","group":{{"name":"{g}"}}}}"#);
    let user = |u: &str| alloc::format!(r#"{{"kind":"User","user":{{"name":"{u}"}}}}"#);
    let rule = |subjects: &[String], res: &str, non: &str| alloc::format!(r#"{{"subjects":[{}],"resourceRules":[{res}],"nonResourceRules":[{non}]}}"#, subjects.join(","));
    let lease_rule = r#"{"verbs":["get","create","update"],"apiGroups":["","coordination.k8s.io"],"resources":["endpoints","configmaps","leases"],"clusterScope":false,"namespaces":["kube-system"]}"#;
    let authed = [group("system:authenticated"), group("system:unauthenticated")];
    // (name, precedence, level, distinguisher, rules)
    let flows: Vec<(&str, i64, &str, &str, String)> = alloc::vec![
        ("exempt", 1, "exempt", "", rule(&[group("system:masters")], all_res, all_non)),
        ("probes", 2, "exempt", "", rule(&authed, "", r#"{"verbs":["get"],"nonResourceURLs":["/healthz*","/livez*","/readyz*"]}"#)),
        ("system-leader-election", 100, "leader-election", "ByUser", rule(&[user("system:kube-controller-manager"), user("system:kube-scheduler")], lease_rule, "")),
        ("workload-leader-election", 200, "leader-election", "ByUser", rule(&[group("system:authenticated")], lease_rule, "")),
        ("system-node-high", 400, "node-high", "ByUser", rule(&[group("system:nodes")], r#"{"verbs":["*"],"apiGroups":["*"],"resources":["nodes","nodes/status"],"clusterScope":true,"namespaces":["*"]}"#, "")),
        ("system-nodes", 500, "system", "ByUser", rule(&[group("system:nodes")], all_res, all_non)),
        ("kube-controller-manager", 800, "workload-high", "ByNamespace", rule(&[user("system:kube-controller-manager")], all_res, all_non)),
        ("kube-scheduler", 800, "workload-high", "ByNamespace", rule(&[user("system:kube-scheduler")], all_res, all_non)),
        ("kube-system-service-accounts", 900, "workload-high", "ByNamespace", rule(&[r#"{"kind":"ServiceAccount","serviceAccount":{"name":"*","namespace":"kube-system"}}"#.to_string()], all_res, all_non)),
        ("service-accounts", 9000, "workload-low", "ByUser", rule(&[group("system:serviceaccounts")], all_res, all_non)),
        ("global-default", 9900, "global-default", "ByUser", rule(&[group("system:authenticated")], all_res, all_non)),
        ("catch-all", 10000, "catch-all", "ByUser", rule(&authed, all_res, all_non)),
    ];
    for (name, prec, level, dist, rules) in flows {
        let d = if dist.is_empty() { String::new() } else { alloc::format!(r#","distinguisherMethod":{{"type":"{dist}"}}"#) };
        put(fsr, name, "FlowSchema", alloc::format!(r#"{{"metadata":{{"name":"{name}",{ann}}},"spec":{{"priorityLevelConfiguration":{{"name":"{level}"}},"matchingPrecedence":{prec}{d},"rules":[{rules}]}}}}"#));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req<'a>(method: &'a str, path: &'a str, query: &'a str) -> Req<'a> {
        Req { method, path, query, content_type: None, accept: None, body: b"", user: None, bearer: None, headers: &[], authz_verb: None }
    }

    fn flow(json: &str) -> Flow {
        parse_flow(&kr_fmt::json::parse(json.as_bytes()).unwrap()).unwrap()
    }

    #[test]
    fn requests_are_classified_by_subject_and_resource() {
        let f = flow(
            r#"{"metadata":{"name":"nodes"},"spec":{"priorityLevelConfiguration":{"name":"system"},"matchingPrecedence":500,"rules":[{"subjects":[{"kind":"Group","group":{"name":"system:nodes"}}],"resourceRules":[{"verbs":["get","list"],"apiGroups":[""],"resources":["pods","pods/status"],"clusterScope":false,"namespaces":["kube-system"]}],"nonResourceRules":[{"verbs":["get"],"nonResourceURLs":["/healthz*"]}]}]}}"#,
        );
        let node = User { name: "system:node:a".into(), groups: alloc::vec!["system:nodes".into()] };
        let other = User { name: "bob".into(), groups: alloc::vec!["system:authenticated".into()] };
        let m = |u: &User, method, path, q| rule_matches(&f.rules[0], u, &info(&req(method, path, q)));
        assert!(m(&node, "GET", "/api/v1/namespaces/kube-system/pods", ""));
        assert!(m(&node, "GET", "/api/v1/namespaces/kube-system/pods/p/status", ""));
        assert!(!m(&node, "GET", "/api/v1/namespaces/default/pods", "")); // other namespace
        assert!(!m(&node, "DELETE", "/api/v1/namespaces/kube-system/pods/p", "")); // verb
        assert!(!m(&other, "GET", "/api/v1/namespaces/kube-system/pods", "")); // subject
        assert!(m(&node, "GET", "/healthz/ping", ""));
        assert_eq!(info(&req("GET", "/api/v1/pods", "watch=true")).verb, "watch");
        assert_eq!(info(&req("DELETE", "/apis/apps/v1/namespaces/d/deployments", "")).verb, "deletecollection");
        let i = info(&req("GET", "/apis/apps/v1/namespaces/d/deployments/x/scale", ""));
        assert_eq!((i.group.as_str(), i.res.as_str(), i.sub.as_str(), i.ns.as_str(), i.verb), ("apps", "deployments", "scale", "d", "get"));
    }

    #[test]
    fn long_running_requests_are_skipped() {
        let w = req("GET", "/api/v1/pods", "watch=1");
        assert!(skipped(&w, &info(&w)));
        let e = req("POST", "/api/v1/namespaces/d/pods/p/exec", "");
        assert!(skipped(&e, &info(&e)));
        let l = req("GET", "/api/v1/namespaces/d/pods", "");
        assert!(!skipped(&l, &info(&l)));
    }

    #[test]
    fn freed_seats_go_to_flows_in_turn() {
        let level = Rc::new(Level { name: "l".into(), uid: String::new(), exempt: false, limit: 1, lendable: 0, borrow_max: 0, inflight: Cell::new(0), rejected: Cell::new(0), admitted: Cell::new(0), pool: Rc::new(Pool::default()), reject: false, max_queued: 10, sig: String::new(), state: RefCell::new(LState::default()) });
        let slot = || Rc::new(Slot { width: 1, granted: Cell::new(false), waker: RefCell::new(None) });
        let (a1, a2, b1) = (slot(), slot(), slot());
        {
            let mut st = level.state.borrow_mut();
            level.inflight.set(1);
            st.queues.entry("a".into()).or_default().extend([a1.clone(), a2.clone()]);
            st.queues.entry("b".into()).or_default().push_back(b1.clone());
            st.queued = 3;
        }
        level.release(1); // a1 first (flow "a"), then the other flow before a's second request
        assert!(a1.granted.get() && !b1.granted.get() && !a2.granted.get());
        level.release(1);
        assert!(b1.granted.get() && !a2.granted.get());
        level.release(1);
        assert!(a2.granted.get());
        assert_eq!(level.inflight.get(), 1);
    }

    fn lvl(pool: &Rc<Pool>, limit: usize, lendable: usize, borrow_max: usize) -> Rc<Level> {
        let l = Rc::new(Level { name: "l".into(), uid: String::new(), exempt: false, limit, lendable, borrow_max, inflight: Cell::new(0), rejected: Cell::new(0), admitted: Cell::new(0), pool: pool.clone(), reject: false, max_queued: 10, sig: String::new(), state: RefCell::new(LState::default()) });
        pool.levels.borrow_mut().push(Rc::downgrade(&l));
        l
    }

    #[test]
    fn list_width_follows_the_object_count() {
        assert_eq!((width_for(0), width_for(100), width_for(101), width_for(550), width_for(100_000)), (1, 1, 2, 6, MAX_WIDTH));
        let i = info(&req("GET", "/apis/apps/v1/namespaces/d/deployments", ""));
        assert_eq!((i.ver.as_str(), i.verb), ("v1", "list"));
        assert_eq!(info(&req("GET", "/api/v1/pods", "")).ver, "v1");
    }

    #[test]
    fn seats_default_and_override() {
        assert_eq!((parse_seats(None), parse_seats(Some("")), parse_seats(Some("0")), parse_seats(Some("x"))), (600, 600, 600, 600));
        assert_eq!(parse_seats(Some(" 1200\n")), 1200);
    }

    #[test]
    fn levels_borrow_idle_seats_and_give_them_back() {
        let pool = Rc::new(Pool::default());
        let a = lvl(&pool, 10, 0, usize::MAX); // lends nothing
        let b = lvl(&pool, 10, 5, usize::MAX); // lends 5
        let c = lvl(&pool, 10, 0, 3); // borrows at most 3
        assert!(a.can_take(10));
        // a may borrow b's 5 idle lendable seats, no more
        assert!(a.can_take(15) && !a.can_take(16));
        a.inflight.set(15);
        assert!(!a.can_take(1)); // nothing left to borrow
        assert!(!c.can_take(11)); // b's seats are all lent
        // b uses its own non-lendable seats: lending is unaffected
        b.inflight.set(5);
        assert!(b.can_take(5) && !b.can_take(6));
        // a gives back: c may borrow up to its own limit of 3
        a.release(15);
        assert!(c.can_take(13) && !c.can_take(14));
        // a queued wide request waits for the lent seats and is granted on release
        a.inflight.set(15);
        let w = Rc::new(Slot { width: 3, granted: Cell::new(false), waker: RefCell::new(None) });
        c.inflight.set(10);
        {
            let mut st = c.state.borrow_mut();
            st.queues.entry("f".into()).or_default().push_back(w.clone());
            st.queued = 1;
        }
        c.dispatch(&mut c.state.borrow_mut());
        assert!(!w.granted.get()); // a holds all of b's lendable seats
        a.release(5); // a is back within its limit: 5 seats free again
        assert!(w.granted.get() && c.inflight.get() == 13);
    }
}
