//! API audit log (ADR-046), the counterpart of kube-apiserver's audit backend (log).
//!
//! A [`Policy`] (`audit.k8s.io/v1` Policy YAML; first matching rule wins, no match means level
//! `None`) decides per request how much to record. Events are `audit.k8s.io/v1` Event JSON lines
//! written by an [`Auditor`] to a file with size-based rotation (`audit-<time>.log` backups, the
//! oldest beyond `maxbackup` removed) or to stdout. Writes go to an in-memory buffer; it is
//! flushed when it grows past 64 KiB and by a one second timer, so a request never waits for the
//! file. Secrets, TokenReviews and token requests are never recorded above `Metadata`.
//!
//! The transport calls [`begin`] before and [`finish`] after a request; the pod-security `audit`
//! mode annotations are added in [`finish`] from the request body (no state is shared between
//! interleaved requests).

use crate::api::{ApiServer, Req, User};
use crate::object::rfc3339;
use alloc::format;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;
use kr_fmt::json::{self, Value};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Level {
    None,
    Metadata,
    Request,
    RequestResponse,
}

impl Level {
    fn parse(s: &str) -> Option<Level> {
        Some(match s {
            "None" => Level::None,
            "Metadata" => Level::Metadata,
            "Request" => Level::Request,
            "RequestResponse" => Level::RequestResponse,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct ResRule {
    pub group: String,
    pub resources: Vec<String>,
    pub names: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub level: Level,
    pub users: Vec<String>,
    pub groups: Vec<String>,
    pub verbs: Vec<String>,
    pub resources: Vec<ResRule>,
    pub namespaces: Vec<String>,
    pub urls: Vec<String>,
    pub omit_stages: Vec<String>,
    pub omit_managed_fields: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub rules: Vec<Rule>,
    pub omit_stages: Vec<String>,
    pub omit_managed_fields: bool,
}

/// What a request is, for rule matching.
#[derive(Clone, Debug, Default)]
pub struct Attrs {
    pub user: String,
    pub groups: Vec<String>,
    pub verb: String,
    pub resource_request: bool,
    pub group: String,
    pub version: String,
    /// `pods` or `pods/log`.
    pub resource: String,
    pub subresource: String,
    pub namespace: String,
    pub name: String,
    pub path: String,
}

/// The outcome of evaluating a policy for a request.
#[derive(Clone, Debug, PartialEq)]
pub struct Decision {
    pub level: Level,
    pub omit_stages: Vec<String>,
    pub omit_managed_fields: bool,
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(Value::as_str).map(String::from).collect()
}

impl Policy {
    /// The built-in policy: probes and metrics are not logged, everything else at `Metadata`
    /// (also reads of secrets, configmaps and tokenreviews, which never log bodies). The
    /// `RequestReceived` stage is omitted to halve the volume.
    pub fn builtin() -> Policy {
        let rule = |level, urls: &[&str]| Rule { level, users: Vec::new(), groups: Vec::new(), verbs: Vec::new(), resources: Vec::new(), namespaces: Vec::new(), urls: urls.iter().map(|s| s.to_string()).collect(), omit_stages: Vec::new(), omit_managed_fields: None };
        Policy { rules: alloc::vec![rule(Level::None, &["/healthz*", "/livez*", "/readyz*", "/metrics"]), rule(Level::Metadata, &[])], omit_stages: alloc::vec![String::from("RequestReceived")], omit_managed_fields: false }
    }

    pub fn parse(src: &str) -> Result<Policy, String> {
        let doc = kr_fmt::yaml::parse(src).map_err(|e| format!("audit policy: {e}"))?;
        if doc.get("kind").and_then(Value::as_str) != Some("Policy") {
            return Err(String::from("audit policy: kind must be Policy"));
        }
        let mut rules = Vec::new();
        for (i, r) in doc.get("rules").and_then(Value::as_array).unwrap_or(&[]).iter().enumerate() {
            let lv = r.get("level").and_then(Value::as_str).unwrap_or("");
            let level = Level::parse(lv).ok_or_else(|| format!("audit policy: rules[{i}].level: Invalid value: {lv:?}: must be one of None, Metadata, Request, RequestResponse"))?;
            let resources: Vec<ResRule> = r.get("resources").and_then(Value::as_array).unwrap_or(&[]).iter().map(|x| ResRule { group: x.get("group").and_then(Value::as_str).unwrap_or("").to_string(), resources: strings(x.get("resources")), names: strings(x.get("resourceNames")) }).collect();
            let urls = strings(r.get("nonResourceURLs"));
            if !urls.is_empty() && (!resources.is_empty() || !strings(r.get("namespaces")).is_empty()) {
                return Err(format!("audit policy: rules[{i}]: nonResourceURLs cannot be combined with resources or namespaces"));
            }
            for u in &urls {
                if !u.starts_with('/') && !u.starts_with('*') {
                    return Err(format!("audit policy: rules[{i}].nonResourceURLs: Invalid value: {u:?}: must start with /"));
                }
            }
            rules.push(Rule { level, users: strings(r.get("users")), groups: strings(r.get("userGroups")), verbs: strings(r.get("verbs")), resources, namespaces: strings(r.get("namespaces")), urls, omit_stages: strings(r.get("omitStages")), omit_managed_fields: r.get("omitManagedFields").and_then(Value::as_bool) });
        }
        Ok(Policy { rules, omit_stages: strings(doc.get("omitStages")), omit_managed_fields: doc.get("omitManagedFields").and_then(Value::as_bool).unwrap_or(false) })
    }

    /// Whether any rule looks at the user (so the identity is needed to pick a level).
    fn needs_user(&self) -> bool {
        self.rules.iter().any(|r| !r.users.is_empty() || !r.groups.is_empty())
    }

    pub fn evaluate(&self, a: &Attrs) -> Decision {
        for r in &self.rules {
            if rule_matches(r, a) {
                let mut omit = self.omit_stages.clone();
                omit.extend(r.omit_stages.iter().cloned());
                return Decision { level: r.level, omit_stages: omit, omit_managed_fields: r.omit_managed_fields.unwrap_or(self.omit_managed_fields) };
            }
        }
        Decision { level: Level::None, omit_stages: Vec::new(), omit_managed_fields: self.omit_managed_fields }
    }
}

fn rule_matches(r: &Rule, a: &Attrs) -> bool {
    if !r.users.is_empty() && !r.users.contains(&a.user) {
        return false;
    }
    if !r.groups.is_empty() && !r.groups.iter().any(|g| a.groups.contains(g)) {
        return false;
    }
    if !r.verbs.is_empty() && !r.verbs.iter().any(|v| v == "*" || *v == a.verb) {
        return false;
    }
    if !r.namespaces.is_empty() && !(a.resource_request && r.namespaces.iter().any(|n| *n == a.namespace)) {
        return false;
    }
    if !r.urls.is_empty() {
        return !a.resource_request && r.urls.iter().any(|u| glob(u, &a.path));
    }
    if !r.resources.is_empty() {
        return a.resource_request && r.resources.iter().any(|rr| res_matches(rr, a));
    }
    true
}

fn res_matches(rr: &ResRule, a: &Attrs) -> bool {
    if rr.group != "*" && rr.group != a.group {
        return false;
    }
    if !rr.names.is_empty() && !rr.names.contains(&a.name) {
        return false;
    }
    if rr.resources.is_empty() {
        return true;
    }
    rr.resources.iter().any(|p| {
        let (pr, ps) = p.split_once('/').unwrap_or((p.as_str(), ""));
        let base = a.resource.split('/').next().unwrap_or("");
        (pr == "*" || pr == base) && if p.contains('/') { if ps == "*" { !a.subresource.is_empty() } else { ps == a.subresource } } else { a.subresource.is_empty() }
    })
}

/// `*` at the end matches any suffix; otherwise exact.
fn glob(pat: &str, s: &str) -> bool {
    match pat.strip_suffix('*') {
        Some(p) => s.starts_with(p),
        None => pat == s,
    }
}

// ---- request classification ----

/// Derives rule-matching attributes from the HTTP request line.
pub fn attrs_of(method: &str, path: &str, query: &str) -> Attrs {
    let mut a = Attrs { path: path.to_string(), ..Default::default() };
    let lower = method.to_ascii_lowercase();
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let (group, version, mut rest): (&str, &str, &[&str]) = match segs.as_slice() {
        ["api", v, rest @ ..] if !rest.is_empty() => ("", v, rest),
        ["apis", g, v, rest @ ..] if !rest.is_empty() => (g, v, rest),
        _ => {
            a.verb = lower;
            return a;
        }
    };
    let mut watch = query.split('&').any(|p| matches!(p, "watch=true" | "watch=1" | "watch"));
    if rest[0] == "watch" && rest.len() > 1 {
        watch = true;
        rest = &rest[1..];
    }
    if rest[0] == "namespaces" && rest.len() >= 3 && !matches!(rest[2], "status" | "finalize") {
        a.namespace = rest[1].to_string();
        rest = &rest[2..];
    } else if rest[0] == "namespaces" && rest.len() >= 2 {
        a.namespace = rest[1].to_string();
    }
    a.resource_request = true;
    a.group = group.to_string();
    a.version = version.to_string();
    let base = rest[0];
    a.name = rest.get(1).map(|s| s.to_string()).unwrap_or_default();
    a.subresource = rest.get(2..).map(|s| s.join("/")).unwrap_or_default();
    a.resource = if a.subresource.is_empty() { base.to_string() } else { format!("{base}/{}", a.subresource) };
    a.verb = match method {
        "GET" | "HEAD" if watch => "watch",
        "GET" | "HEAD" if a.name.is_empty() => "list",
        "GET" | "HEAD" => "get",
        "POST" => "create",
        "PUT" => "update",
        "PATCH" => "patch",
        "DELETE" if a.name.is_empty() => "deletecollection",
        "DELETE" => "delete",
        _ => &lower,
    }
    .to_string();
    a
}

/// Kinds whose bodies carry credentials: recorded at `Metadata` at most.
fn sensitive(a: &Attrs) -> bool {
    let base = a.resource.split('/').next().unwrap_or("");
    (a.group.is_empty() && base == "secrets") || (a.group == "authentication.k8s.io" && base == "tokenreviews") || (a.group.is_empty() && base == "serviceaccounts" && a.subresource == "token")
}

fn sensitive_kind(v: &Value) -> bool {
    matches!(v.get("kind").and_then(Value::as_str), Some("Secret" | "SecretList" | "TokenRequest" | "TokenReview"))
}

// ---- the writer ----

struct Sink {
    /// Empty: stdout.
    path: String,
    fd: Option<kr_sys::Fd>,
    size: u64,
    warned: bool,
}

pub struct Auditor {
    pub policy: Policy,
    sink: RefCell<Sink>,
    buf: RefCell<Vec<u8>>,
    max_bytes: u64,
    max_backup: usize,
}

/// The one-second flusher ([`spawn_flusher`]) writes the buffer; a request only flushes inline when
/// events pile up faster than that (a write() to a file can block for seconds under write-back
/// pressure, and this keeps it off the request path in the normal case, #223).
const FLUSH_AT: usize = 4 * 1024 * 1024;

impl Auditor {
    /// `path` `-` is stdout; the directory is created. `max_mb` 0 disables rotation.
    pub fn open(policy: Policy, path: &str, max_mb: u64, max_backup: usize) -> Auditor {
        let stdout = path == "-";
        let sink = Sink { path: if stdout { String::new() } else { path.to_string() }, fd: None, size: 0, warned: false };
        Auditor { policy, sink: RefCell::new(sink), buf: RefCell::new(Vec::new()), max_bytes: max_mb.saturating_mul(1024 * 1024), max_backup }
    }

    fn emit(&self, ev: &Value) {
        let mut b = self.buf.borrow_mut();
        b.extend_from_slice(json::to_string(ev).as_bytes());
        b.push(b'\n');
        let big = b.len() >= FLUSH_AT;
        drop(b);
        if big {
            self.flush();
        }
    }

    /// Writes the buffered events (rotating first if the file would exceed its limit).
    pub fn flush(&self) {
        let data = core::mem::take(&mut *self.buf.borrow_mut());
        if data.is_empty() {
            return;
        }
        let mut s = self.sink.borrow_mut();
        if s.path.is_empty() {
            let _ = kr_sys::fs::write_all(1, &data);
            return;
        }
        if s.fd.is_none() {
            self.open_file(&mut s);
        }
        if self.max_bytes > 0 && s.size > 0 && s.size + data.len() as u64 > self.max_bytes {
            self.rotate(&mut s);
        }
        let t0 = kr_rt::exec::now_ms();
        kr_rt::exec::phase("audit: write");
        let ok = match &s.fd {
            Some(fd) => kr_sys::fs::write_all(fd.raw(), &data).is_ok(),
            None => false,
        };
        // A write() to a file can block for seconds when the disk is under write-back pressure.
        let took = kr_rt::exec::now_ms().saturating_sub(t0);
        if took >= 100 {
            kr_rt::eprint(alloc::format!("kr server: audit log write of {} bytes blocked the event loop for {took} ms\n", data.len()).as_bytes());
        }
        if ok {
            s.size += data.len() as u64;
        } else if !s.warned {
            s.warned = true;
            kr_rt::eprint(b"kr server: audit log write failed; events are dropped\n");
        }
    }

    fn open_file(&self, s: &mut Sink) {
        if let Some((dir, _)) = s.path.rsplit_once('/') {
            mkdir_p(dir);
        }
        let mut p = s.path.clone().into_bytes();
        p.push(0);
        s.fd = kr_sys::fs::openat(kr_sys::fs::AT_FDCWD, &p, kr_sys::fs::O_WRONLY | kr_sys::fs::O_CREAT | 0o2000 | kr_sys::fs::O_CLOEXEC, 0o600).ok();
        s.size = s.fd.as_ref().and_then(|f| kr_sys::fs::fstat(f.raw()).ok()).map(|st| st.size as u64).unwrap_or(0);
    }

    fn rotate(&self, s: &mut Sink) {
        s.fd = None;
        let (dir, file) = s.path.rsplit_once('/').unwrap_or((".", s.path.as_str()));
        let (stem, ext) = file.rsplit_once('.').map(|(a, b)| (a.to_string(), format!(".{b}"))).unwrap_or((file.to_string(), String::new()));
        let ts = ts_name();
        let backup = format!("{dir}/{stem}-{ts}{ext}");
        let (mut from, mut to) = (s.path.clone().into_bytes(), backup.into_bytes());
        from.push(0);
        to.push(0);
        let _ = kr_sys::fs::renameat2(kr_sys::fs::AT_FDCWD, &from, kr_sys::fs::AT_FDCWD, &to, 0);
        if self.max_backup > 0 {
            for old in old_backups(dir, &stem, &ext).into_iter().skip(self.max_backup) {
                let mut p = format!("{dir}/{old}").into_bytes();
                p.push(0);
                let _ = kr_sys::fs::unlinkat(kr_sys::fs::AT_FDCWD, &p, 0);
            }
        }
        self.open_file(s);
    }
}

/// Backup file names of `stem-<time>ext` in `dir`, newest first.
fn old_backups(dir: &str, stem: &str, ext: &str) -> Vec<String> {
    let mut d = dir.to_string().into_bytes();
    d.push(0);
    let Ok(fd) = kr_sys::fs::openat(kr_sys::fs::AT_FDCWD, &d, kr_sys::fs::O_RDONLY | kr_sys::fs::O_DIRECTORY, 0) else { return Vec::new() };
    let prefix = format!("{stem}-");
    let mut v: Vec<String> = kr_sys::fs::read_dir(&fd).filter_map(|e| e.ok()).filter_map(|e| String::from_utf8(e.name.clone()).ok()).filter(|n| n.starts_with(&prefix) && n.ends_with(ext)).collect();
    v.sort();
    v.reverse();
    v
}

fn mkdir_p(dir: &str) {
    let mut cur = String::new();
    for part in dir.split('/').filter(|p| !p.is_empty()) {
        cur.push('/');
        cur.push_str(part);
        let mut c = cur.clone().into_bytes();
        c.push(0);
        let _ = kr_sys::ns::mkdir(&c, 0o700);
    }
}

/// Wall clock as (unix seconds, microseconds).
fn wall() -> (i64, u32) {
    kr_sys::clock_gettime(0).map(|t| (t.tv_sec, (t.tv_nsec / 1000) as u32)).unwrap_or((0, 0))
}

/// `2026-01-02T03:04:05.123456Z` (MicroTime).
fn micro_ts() -> String {
    let (s, us) = wall();
    let t = rfc3339(s);
    format!("{}.{us:06}Z", &t[..t.len() - 1])
}

/// Backup name part: `2026-01-02T03-04-05.123` (sorts like the time, as lumberjack's).
fn ts_name() -> String {
    let (s, us) = wall();
    let t = rfc3339(s);
    format!("{}.{:03}", t[..t.len() - 1].replace(':', "-"), us / 1000)
}

/// Starts the one second flush timer (call inside the executor).
pub fn spawn_flusher(a: Rc<Auditor>) {
    kr_rt::exec::spawn(async move {
        loop {
            kr_rt::exec::sleep(1000).await;
            a.flush();
        }
    });
}

// ---- hub on the ApiServer ----

/// The audit writer and the Pod Security configuration, owned by the [`ApiServer`].
#[derive(Default)]
pub struct Hub {
    auditor: RefCell<Option<Rc<Auditor>>>,
    pub psa: RefCell<crate::psa::Config>,
    /// The caller of the write being handled, for Pod Security user exemptions.
    pub user: RefCell<String>,
}

impl Hub {
    pub fn set_auditor(&self, a: Rc<Auditor>) {
        *self.auditor.borrow_mut() = Some(a);
    }
    /// Resolves the caller of a write, only when the configuration exempts users.
    pub(crate) fn set_user(&self, api: &ApiServer, req: &Req, write: bool) {
        if write && !self.psa.borrow().users.is_empty() {
            *self.user.borrow_mut() = api.authenticate(req).map(|u| u.name).unwrap_or_default();
        }
    }
    fn auditor(&self) -> Option<Rc<Auditor>> {
        self.auditor.borrow().clone()
    }
}

// ---- per-request hooks ----

/// A request being audited.
pub struct Pending {
    auditor: Rc<Auditor>,
    id: String,
    received: String,
    attrs: Attrs,
    decision: Option<Decision>,
    uri: String,
    ua: String,
    ip: Option<String>,
    ctype: String,
    headers: Vec<(String, String)>,
    bearer: Option<String>,
    user_cert: Option<User>,
    body: Vec<u8>,
    /// The caller before impersonation.
    base: User,
}

/// Called by the transport when a request arrives. `None` when auditing is off or the policy
/// says `None` for it (when the policy needs the identity, it is resolved here).
pub fn begin(api: &ApiServer, req: &kr_net::http1::server::Request, cert_user: Option<User>) -> Option<Pending> {
    let auditor = api.audit.auditor()?;
    if req.header(crate::cluster::forward::IDENTITY).is_some() {
        return None; // audited by the server that received the client's request
    }
    let mut attrs = attrs_of(&req.method, req.path(), req.query());
    let early = if auditor.policy.needs_user() { None } else { Some(auditor.policy.evaluate(&attrs)) };
    if early.as_ref().is_some_and(|d| d.level == Level::None) {
        return None;
    }
    let mut p = Pending {
        auditor,
        id: crate::object::uuid4(|b| kr_sys::getrandom(b)),
        received: micro_ts(),
        attrs: Attrs::default(),
        decision: early,
        uri: match req.query() {
            "" => req.path().to_string(),
            q => format!("{}?{q}", req.path()),
        },
        ua: req.header("user-agent").unwrap_or("").to_string(),
        ip: req.peer.addr.map(|(a, _)| format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])),
        ctype: req.header("content-type").unwrap_or("").to_string(),
        headers: req.headers.clone(),
        bearer: req.header("authorization").and_then(|a| a.strip_prefix("Bearer ").or_else(|| a.strip_prefix("bearer "))).map(|s| s.trim().to_string()),
        user_cert: cert_user,
        body: Vec::new(),
        base: User { name: String::new(), groups: Vec::new() },
    };
    let anon = || User { name: String::from("system:anonymous"), groups: alloc::vec![String::from("system:unauthenticated")] };
    let fin = identity(api, &p, true).unwrap_or_else(anon);
    p.base = if p.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("impersonate-user")) { identity(api, &p, false).unwrap_or_else(anon) } else { fin.clone() };
    attrs.user = fin.name;
    attrs.groups = fin.groups;
    let decision = match p.decision.take() {
        Some(d) => d,
        None => p.auditor.policy.evaluate(&attrs),
    };
    if decision.level == Level::None {
        return None;
    }
    // Bodies only matter above Metadata and only for writes.
    if decision.level >= Level::Request && matches!(req.method.as_str(), "POST" | "PUT" | "PATCH") || attrs.resource_request && attrs.verb == "create" {
        p.body = req.body.clone();
    }
    p.attrs = attrs;
    p.decision = Some(decision);
    if !p.decision.as_ref().unwrap().omit_stages.iter().any(|s| s == "RequestReceived") {
        let ev = event(api, &p, "RequestReceived", None, None);
        p.auditor.emit(&ev);
    }
    Some(p)
}

/// The caller; `final_` = after impersonation.
fn identity(api: &ApiServer, p: &Pending, final_: bool) -> Option<User> {
    let hs: Vec<(String, String)> = if final_ { p.headers.clone() } else { p.headers.iter().filter(|(k, _)| !k.to_ascii_lowercase().starts_with("impersonate-")).cloned().collect() };
    let r = Req { method: "GET", path: "/", query: "", content_type: None, accept: None, body: &[], user: p.user_cert.clone(), bearer: p.bearer.as_deref(), headers: &hs, authz_verb: None };
    api.authenticate(&r).ok()
}

/// Called when the response is ready. A streaming or upgraded response is recorded as
/// `ResponseStarted` (the end of a stream is not observed).
pub fn finish(api: &ApiServer, p: Option<Pending>, resp: &kr_net::http1::server::Response) {
    let Some(p) = p else { return };
    let d = p.decision.clone().unwrap();
    let streaming = !matches!(resp.body, kr_net::http1::server::Body::Full(_));
    let stage = if streaming { "ResponseStarted" } else { "ResponseComplete" };
    if d.omit_stages.iter().any(|s| s == stage) {
        return;
    }
    let ev = event(api, &p, stage, Some(resp), Some(&d));
    p.auditor.emit(&ev);
}

/// A JSON, YAML or Kubernetes protobuf body as a value.
fn decode(ctype: &str, b: &[u8]) -> Option<Value> {
    if ctype.starts_with("application/vnd.kubernetes.protobuf") {
        crate::proto::decode_body(b).ok()
    } else if ctype.contains("yaml") {
        kr_fmt::yaml::parse(core::str::from_utf8(b).ok()?).ok()
    } else {
        json::parse(b).ok()
    }
}

fn obj(fields: Vec<(&str, Value)>) -> Value {
    crate::object::obj(fields)
}

fn sv(s: &str) -> Value {
    Value::String(s.to_string())
}

fn strip_managed(v: &mut Value) {
    if let Some(m) = v.get("metadata").is_some().then(|| v.entry_object("metadata")) {
        m.remove("managedFields");
    }
    if let Value::Object(o) = v {
        for (k, item) in o.iter_mut() {
            if k == "items" {
                if let Value::Array(a) = item {
                    a.iter_mut().for_each(strip_managed);
                }
            }
        }
    }
}

/// Builds one `audit.k8s.io/v1` Event.
fn event(api: &ApiServer, p: &Pending, stage: &str, resp: Option<&kr_net::http1::server::Response>, d: Option<&Decision>) -> Value {
    let a = &p.attrs;
    let level = p.decision.as_ref().map(|d| d.level).unwrap_or(Level::Metadata);
    let user = &p.base;
    let mut user_v = obj(alloc::vec![("username", sv(&user.name))]);
    if !user.groups.is_empty() {
        user_v.set("groups", Value::Array(user.groups.iter().map(|g| sv(g)).collect()));
    }
    let mut ev = obj(alloc::vec![
        ("kind", sv("Event")),
        ("apiVersion", sv("audit.k8s.io/v1")),
        ("level", sv(match level {
            Level::None => "None",
            Level::Metadata => "Metadata",
            Level::Request => "Request",
            Level::RequestResponse => "RequestResponse",
        })),
        ("auditID", sv(&p.id)),
        ("stage", sv(stage)),
        ("requestURI", sv(&p.uri)),
        ("verb", sv(&a.verb)),
        ("user", user_v),
    ]);
    // Impersonation: the headers name who the request acts as.
    let imp = |n: &str| p.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.clone()).collect::<Vec<_>>();
    if let Some(who) = imp("Impersonate-User").into_iter().next() {
        let groups = imp("Impersonate-Group");
        let mut iu = obj(alloc::vec![("username", sv(&who))]);
        if !groups.is_empty() {
            iu.set("groups", Value::Array(groups.iter().map(|g| sv(g)).collect()));
        }
        ev.set("impersonatedUser", iu);
    }
    if let Some(ip) = &p.ip {
        ev.set("sourceIPs", Value::Array(alloc::vec![sv(ip)]));
    }
    if !p.ua.is_empty() {
        ev.set("userAgent", sv(&p.ua));
    }
    if a.resource_request {
        let base = a.resource.split('/').next().unwrap_or("");
        let mut r = obj(alloc::vec![("resource", sv(base))]);
        if !a.namespace.is_empty() {
            r.set("namespace", sv(&a.namespace));
        }
        if !a.name.is_empty() {
            r.set("name", sv(&a.name));
        }
        if !a.group.is_empty() {
            r.set("apiGroup", sv(&a.group));
        }
        r.set("apiVersion", sv(&a.version));
        if !a.subresource.is_empty() {
            r.set("subresource", sv(&a.subresource));
        }
        ev.set("objectRef", r);
    }
    let mut annotations: Vec<(String, String)> = Vec::new();
    if let Some(r) = resp {
        let code = r.status;
        let mut st = obj(alloc::vec![("metadata", obj(Vec::new())), ("code", Value::from(code as u64))]);
        let rbody: Option<Value> = match &r.body {
            kr_net::http1::server::Body::Full(b) => decode(r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-type")).map(|(_, v)| v.as_str()).unwrap_or("application/json"), b),
            _ => None,
        };
        if code >= 400 {
            st.set("status", sv("Failure"));
            if let Some(b) = rbody.as_ref().filter(|b| b.get("kind").and_then(Value::as_str) == Some("Status")) {
                for k in ["reason", "message"] {
                    if let Some(x) = b.get(k).and_then(Value::as_str) {
                        st.set(k, sv(x));
                    }
                }
            }
        } else {
            st.set("status", sv("Success"));
        }
        ev.set("responseStatus", st);
        if a.resource_request && !matches!(code, 401 | 403) {
            annotations.push((String::from("authorization.k8s.io/decision"), String::from("allow")));
        } else if code == 403 {
            annotations.push((String::from("authorization.k8s.io/decision"), String::from("forbid")));
        }
        if let (Some(d), true) = (d, level >= Level::Request) {
            // Request body (JSON; other encodings are not recorded).
            let sens = sensitive(a);
            if !sens && !p.body.is_empty() {
                if let Some(mut b) = decode(&p.ctype, &p.body) {
                    if !sensitive_kind(&b) {
                        if d.omit_managed_fields {
                            strip_managed(&mut b);
                        }
                        ev.set("requestObject", b);
                    }
                }
            }
            if level == Level::RequestResponse && !sens && code < 400 {
                if let Some(mut b) = rbody {
                    if !sensitive_kind(&b) && b.get("kind").and_then(Value::as_str) != Some("Table") {
                        if d.omit_managed_fields {
                            strip_managed(&mut b);
                        }
                        ev.set("responseObject", b);
                    }
                }
            }
        }
        // Pod Security `audit` mode: violations of the namespace's audit level on creation.
        if a.verb == "create" && !p.body.is_empty() {
            psa_annotations(api, p, &mut annotations);
        }
    }
    if !annotations.is_empty() {
        ev.set("annotations", Value::Object(annotations.into_iter().map(|(k, v)| (k, Value::String(v))).collect()));
    }
    ev.set("requestReceivedTimestamp", sv(&p.received));
    ev.set("stageTimestamp", sv(&micro_ts()));
    ev
}

fn psa_annotations(api: &ApiServer, p: &Pending, out: &mut Vec<(String, String)>) {
    let a = &p.attrs;
    let pod = a.group.is_empty() && a.resource == "pods";
    let tpath = if pod { None } else { crate::psa::template_path(&a.group, &a.resource) };
    if !pod && tpath.is_none() {
        return;
    }
    let Some(o) = decode(&p.ctype, &p.body) else { return };
    let (spec, meta) = match tpath {
        None => (o.get("spec"), o.get("metadata")),
        Some(path) => {
            let t = o.pointer(path);
            (t.and_then(|t| t.get("spec")), t.and_then(|t| t.get("metadata")))
        }
    };
    let Some(spec) = spec else { return };
    let nsobj = api.wh_object("", "v1", "namespaces", None, &a.namespace);
    let cfg = api.audit.psa.borrow();
    let d = crate::psa::check(&cfg, &a.user, &a.namespace, nsobj.as_ref(), spec, meta.unwrap_or(&Value::Null), !pod);
    out.extend(d.audit);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pol(s: &str) -> Policy {
        Policy::parse(s).unwrap()
    }

    #[test]
    fn classify() {
        let a = attrs_of("GET", "/api/v1/namespaces/ns/pods/p/log", "");
        assert_eq!((a.verb.as_str(), a.namespace.as_str(), a.resource.as_str(), a.name.as_str()), ("get", "ns", "pods/log", "p"));
        let a = attrs_of("GET", "/apis/apps/v1/deployments", "watch=true");
        assert_eq!((a.verb.as_str(), a.group.as_str(), a.namespace.as_str()), ("watch", "apps", ""));
        assert_eq!(attrs_of("GET", "/api/v1/namespaces", "").verb, "list");
        let a = attrs_of("DELETE", "/api/v1/namespaces/foo", "");
        assert_eq!((a.verb.as_str(), a.namespace.as_str(), a.resource.as_str()), ("delete", "foo", "namespaces"));
        let a = attrs_of("PUT", "/api/v1/namespaces/foo/status", "");
        assert_eq!(a.resource, "namespaces/status");
        let a = attrs_of("GET", "/healthz", "");
        assert!(!a.resource_request && a.verb == "get");
    }

    const POLICY: &str = "apiVersion: audit.k8s.io/v1\nkind: Policy\nomitStages: [RequestReceived]\nrules:\n- level: None\n  nonResourceURLs: [\"/healthz*\", \"/version\"]\n- level: None\n  users: [\"system:kube-proxy\"]\n  verbs: [watch]\n  resources:\n  - group: \"\"\n    resources: [endpoints, services]\n- level: Metadata\n  resources:\n  - group: \"\"\n    resources: [secrets, configmaps]\n- level: RequestResponse\n  resources:\n  - group: \"\"\n    resources: [pods]\n  namespaces: [prod]\n  omitStages: [ResponseStarted]\n- level: Request\n  userGroups: [\"system:masters\"]\n  resources:\n  - group: apps\n    resources: [\"*\"]\n  - group: \"\"\n    resources: [\"pods/*\"]\n- level: Metadata\n";

    fn at(p: &Policy, user: &str, groups: &[&str], method: &str, path: &str, q: &str) -> Level {
        let mut a = attrs_of(method, path, q);
        a.user = user.to_string();
        a.groups = groups.iter().map(|s| s.to_string()).collect();
        p.evaluate(&a).level
    }

    #[test]
    fn policy_matching() {
        let p = pol(POLICY);
        assert_eq!(at(&p, "u", &[], "GET", "/healthz", ""), Level::None);
        assert_eq!(at(&p, "u", &[], "GET", "/version", ""), Level::None);
        assert_eq!(at(&p, "u", &[], "GET", "/readyz", ""), Level::Metadata); // falls to the last rule
        assert_eq!(at(&p, "system:kube-proxy", &[], "GET", "/api/v1/services", "watch=true"), Level::None);
        assert_eq!(at(&p, "system:kube-proxy", &[], "GET", "/api/v1/services", ""), Level::Metadata);
        assert_eq!(at(&p, "u", &[], "GET", "/api/v1/namespaces/prod/secrets/s", ""), Level::Metadata);
        assert_eq!(at(&p, "u", &[], "POST", "/api/v1/namespaces/prod/pods", ""), Level::RequestResponse);
        assert_eq!(at(&p, "u", &[], "POST", "/api/v1/namespaces/dev/pods", ""), Level::Metadata);
        assert_eq!(at(&p, "a", &["system:masters"], "POST", "/apis/apps/v1/namespaces/dev/deployments", ""), Level::Request);
        assert_eq!(at(&p, "a", &["system:masters"], "GET", "/api/v1/namespaces/dev/pods/x/log", ""), Level::Request);
        assert_eq!(at(&p, "a", &["system:masters"], "GET", "/api/v1/namespaces/dev/pods/x", ""), Level::Metadata);
        // Policy stages merge: rule + policy-level.
        let mut a = attrs_of("POST", "/api/v1/namespaces/prod/pods", "");
        a.user = "u".into();
        assert_eq!(p.evaluate(&a).omit_stages, ["RequestReceived", "ResponseStarted"]);
        // No match at all is None.
        assert_eq!(pol("kind: Policy\nrules: []").evaluate(&a).level, Level::None);
        // resourceNames.
        let p = pol("kind: Policy\nrules:\n- level: Request\n  resources:\n  - group: \"\"\n    resources: [configmaps]\n    resourceNames: [a]\n");
        assert_eq!(at(&p, "u", &[], "GET", "/api/v1/namespaces/n/configmaps/a", ""), Level::Request);
        assert_eq!(at(&p, "u", &[], "GET", "/api/v1/namespaces/n/configmaps/b", ""), Level::None);
    }

    #[test]
    fn policy_errors_and_builtin() {
        assert!(Policy::parse("kind: Other").is_err());
        assert!(Policy::parse("kind: Policy\nrules:\n- level: Loud\n").is_err());
        assert!(Policy::parse("kind: Policy\nrules:\n- level: None\n  nonResourceURLs: [healthz]\n").is_err());
        let b = Policy::builtin();
        assert_eq!(at(&b, "u", &[], "GET", "/metrics", ""), Level::None);
        assert_eq!(at(&b, "u", &[], "GET", "/livez/etcd", ""), Level::None);
        assert_eq!(at(&b, "u", &[], "GET", "/api/v1/namespaces/n/secrets", ""), Level::Metadata);
        assert_eq!(at(&b, "u", &[], "POST", "/api/v1/namespaces/n/pods", ""), Level::Metadata);
    }

    #[test]
    fn secrets_are_sensitive() {
        assert!(sensitive(&attrs_of("POST", "/api/v1/namespaces/n/secrets", "")));
        assert!(sensitive(&attrs_of("GET", "/api/v1/namespaces/n/secrets/s", "")));
        assert!(sensitive(&attrs_of("POST", "/api/v1/namespaces/n/serviceaccounts/d/token", "")));
        assert!(sensitive(&attrs_of("POST", "/apis/authentication.k8s.io/v1/tokenreviews", "")));
        assert!(!sensitive(&attrs_of("POST", "/api/v1/namespaces/n/configmaps", "")));
        assert!(sensitive_kind(&json::parse(br#"{"kind":"Secret"}"#).unwrap()));
    }

    fn tmpdir(name: &str) -> String {
        let d = format!("/tmp/kr-audit-test-{name}-{}", wall().1);
        let mut c = d.clone().into_bytes();
        c.push(0);
        let _ = kr_sys::ns::mkdir(&c, 0o700);
        d
    }

    fn files(d: &str) -> Vec<String> {
        let mut c = d.to_string().into_bytes();
        c.push(0);
        let fd = kr_sys::fs::openat(kr_sys::fs::AT_FDCWD, &c, kr_sys::fs::O_RDONLY | kr_sys::fs::O_DIRECTORY, 0).unwrap();
        let mut v: Vec<String> = kr_sys::fs::read_dir(&fd).filter_map(|e| e.ok()).map(|e| String::from_utf8(e.name).unwrap()).collect();
        v.sort();
        v
    }

    #[test]
    fn rotation_keeps_backups() {
        let d = tmpdir("rot");
        let path = format!("{d}/audit.log");
        let a = Auditor::open(Policy::builtin(), &path, 1, 2);
        let line = Value::String("x".repeat(400 * 1024));
        for _ in 0..8 {
            a.emit(&line);
            a.flush();
            // Distinct backup names need distinct milliseconds.
            std::thread::sleep(std::time::Duration::from_millis(3));
        }
        let f = files(&d);
        assert!(f.contains(&String::from("audit.log")));
        let backups = f.iter().filter(|n| n.starts_with("audit-")).count();
        assert_eq!(backups, 2, "{f:?}");
        // The live file never exceeds the limit by more than one flush.
        let st = std::fs::metadata(&path).unwrap();
        assert!(st.len() <= 1024 * 1024);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn buffered_flush_writes_json_lines() {
        let d = tmpdir("buf");
        let path = format!("{d}/a/audit.log");
        let a = Auditor::open(Policy::builtin(), &path, 100, 5);
        a.emit(&obj(alloc::vec![("kind", sv("Event"))]));
        assert!(std::fs::read_to_string(&path).is_err()); // still buffered
        a.flush();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"kind\":\"Event\"}\n");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn managed_fields_stripped() {
        let mut v = json::parse(br#"{"metadata":{"name":"a","managedFields":[{}]},"items":[{"metadata":{"managedFields":[{}]}}]}"#).unwrap();
        strip_managed(&mut v);
        assert_eq!(json::to_string(&v), r#"{"metadata":{"name":"a"},"items":[{"metadata":{}}]}"#);
    }

    #[test]
    fn timestamp_format() {
        let t = micro_ts();
        assert_eq!(t.len(), 27, "{t}");
        assert!(t.ends_with('Z') && &t[19..20] == ".");
    }
}
