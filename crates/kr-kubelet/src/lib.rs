//! `kr-kubelet`: runs the pods bound to this node with kr's own runtime (no CRI, no shim).
//!
//! Level-triggered design: one sync loop wakes on any pod watch event, container exit, or a
//! 1 s tick, reads the desired pods for this node, and converges local state:
//! - a pod gets a sandbox (user/net/uts/ipc namespaces, pod IP when running as root), a pod
//!   directory with volumes and `/etc/hosts`, then its init containers in order, then its app
//!   containers;
//! - exits are handled per `restartPolicy` with CrashLoopBackOff (10 s doubling to 300 s);
//! - pods that disappear or get a deletionTimestamp are stopped (SIGTERM, then SIGKILL after
//!   the grace period), and their sandbox, IP lease and directories are removed;
//! - pod status is patched only when it changed.
//! Node registration and the Lease heartbeat live in `node`.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod node;
mod spec;

use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::future::poll_fn;
use core::task::{Poll, Waker};
use kr_apiserver::client::{meta, Client};
use kr_apiserver::object::rfc3339;
use kr_fmt::json::{self, Number, Value};
use kr_runtime::container::{self, IdMaps, Running, Sandbox, Signaller};
use kr_runtime::network::{self, Lease, NetConfig};
use kr_runtime::store::Store;

pub struct Config {
    pub node_name: String,
    /// Root of kubelet state (`<root>/pods/<uid>/...`); usually the image store root.
    pub root: String,
    /// Bridge networking and pod IPs (requires real root).
    pub network: bool,
    /// cgroup limits are applied only when kr runs in a delegated cgroup.
    pub cgroups: bool,
}

fn now() -> i64 {
    kr_sys::clock_gettime(0).map(|t| t.tv_sec).unwrap_or(0)
}

/// Removes `path` recursively. `fs::remove_all` takes a single component relative to a
/// directory fd (so it cannot be redirected), hence the parent is opened first.
fn remove_tree(path: &str) -> bool {
    let Some((parent, name)) = path.rsplit_once('/') else { return false };
    let parent = alloc::format!("{}\0", if parent.is_empty() { "/" } else { parent });
    let Ok(fd) = kr_sys::ns::open(parent.as_bytes(), kr_sys::ns::O_RDONLY | kr_sys::ns::O_DIRECTORY, 0) else { return false };
    kr_sys::fs::remove_all(fd.raw(), alloc::format!("{name}\0").as_bytes()).is_ok()
}

fn now_ms() -> u64 {
    kr_rt::exec::now_ms()
}

/// Wakes the sync loop.
#[derive(Default)]
struct Notify {
    flag: Cell<bool>,
    waker: RefCell<Option<Waker>>,
}

impl Notify {
    fn notify(&self) {
        self.flag.set(true);
        if let Some(w) = self.waker.borrow_mut().take() {
            w.wake();
        }
    }

    async fn wait(&self, max_ms: u64) {
        let wait = poll_fn(|cx| {
            if self.flag.replace(false) {
                Poll::Ready(())
            } else {
                *self.waker.borrow_mut() = Some(cx.waker().clone());
                Poll::Pending
            }
        });
        let _ = kr_rt::exec::timeout(max_ms, wait).await;
    }
}

#[derive(Clone, Debug)]
struct Term {
    exit_code: i32,
    reason: &'static str,
    started_at: i64,
    finished_at: i64,
}

#[derive(Clone, Debug)]
enum CState {
    Waiting(&'static str, String),
    Running { started_at: i64, id: String },
    Terminated(Term),
}

struct Ctr {
    name: String,
    image: String,
    init: bool,
    restart_count: u32,
    state: CState,
    last_term: Option<Term>,
    signaller: Option<Signaller>,
    /// Earliest start time (CrashLoopBackOff), ms.
    not_before: u64,
    backoff_ms: u64,
    seq: u32,
}

struct PodRt {
    ns: String,
    name: String,
    dir: String,
    sandbox: Option<Sandbox>,
    lease: Option<Lease>,
    ip: Option<[u8; 4]>,
    ctrs: Vec<Ctr>,
    start_time: i64,
    /// Kill deadline (ms) once termination started.
    kill_at: Option<u64>,
    last_status: String,
    failed_setup: Option<String>,
}

struct Exit {
    pod_uid: String,
    ctr: String,
    exit_code: i32,
    oom: bool,
    started_at: i64,
}

pub struct Kubelet<C: Client> {
    c: C,
    cfg: Config,
    store: Store,
    maps: IdMaps,
    pods: RefCell<BTreeMap<String, PodRt>>,
    exits: RefCell<Vec<Exit>>,
    notify: Notify,
}

const BACKOFF_START_MS: u64 = 10_000;
const BACKOFF_MAX_MS: u64 = 300_000;

impl<C: Client + Clone + 'static> Kubelet<C> {
    pub fn new(c: C, cfg: Config, store: Store) -> Rc<Self> {
        Rc::new(Kubelet { c, cfg, store, maps: IdMaps::for_current_user(), pods: RefCell::new(BTreeMap::new()), exits: RefCell::new(Vec::new()), notify: Notify::default() })
    }

    /// Runs registration, heartbeats, the pod watch and the sync loop (never returns).
    pub async fn run(self: Rc<Self>) {
        if self.cfg.network {
            if let Err(e) = network::setup_host() {
                kr_rt::eprint(alloc::format!("kubelet: network setup failed (errno {}); pods get no IP\n", e.0).as_bytes());
            }
        }
        node::register(&self.c, &self.cfg).await;
        let hb = self.clone();
        kr_rt::exec::spawn(async move { node::heartbeat_loop(&hb.c, &hb.cfg).await });
        let w = self.clone();
        kr_rt::exec::spawn(async move { w.watch_loop().await });
        loop {
            self.sync_all().await;
            self.notify.wait(1000).await;
        }
    }

    async fn watch_loop(&self) {
        let q = alloc::format!("fieldSelector=spec.nodeName%3D{}", self.cfg.node_name);
        loop {
            if let Ok(mut w) = self.c.watch("/api/v1/pods", &q).await {
                while w.next().await.is_some() {
                    self.notify.notify();
                }
            }
            kr_rt::exec::sleep(1000).await;
        }
    }

    async fn sync_all(self: &Rc<Self>) {
        // Container exits recorded by waiter tasks.
        let exits: Vec<Exit> = core::mem::take(&mut *self.exits.borrow_mut());
        for e in exits {
            self.on_exit(e);
        }
        let q = alloc::format!("fieldSelector=spec.nodeName%3D{}", self.cfg.node_name);
        let Ok(list) = self.c.list("/api/v1/pods", &q).await else { return };
        let desired: Vec<Value> = list.get("items").and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
        let mut seen = Vec::new();
        for pod in &desired {
            let uid = meta(pod, "uid").to_string();
            seen.push(uid.clone());
            if pod.pointer(&["metadata", "deletionTimestamp"]).is_some() {
                self.terminate(&uid, pod).await;
            } else {
                self.sync_pod(&uid, pod).await;
            }
            self.report_status(&uid, pod).await;
        }
        // Pods deleted from the API: stop immediately (the object is already gone).
        let gone: Vec<String> = self.pods.borrow().keys().filter(|k| !seen.contains(k)).cloned().collect();
        for uid in gone {
            self.kill_now(&uid);
            if self.all_stopped(&uid) {
                self.cleanup(&uid);
            }
        }
    }

    fn on_exit(&self, e: Exit) {
        let mut pods = self.pods.borrow_mut();
        let Some(p) = pods.get_mut(&e.pod_uid) else { return };
        let Some(c) = p.ctrs.iter_mut().find(|c| c.name == e.ctr) else { return };
        let reason = if e.oom { "OOMKilled" } else if e.exit_code == 0 { "Completed" } else { "Error" };
        let term = Term { exit_code: e.exit_code, reason, started_at: e.started_at, finished_at: now() };
        // A container that ran for 10 minutes resets its backoff.
        if term.finished_at - term.started_at > 600 {
            c.backoff_ms = 0;
        }
        c.state = CState::Terminated(term.clone());
        c.last_term = Some(term);
        c.signaller = None;
        // CrashLoopBackOff: every restart after an exit waits 10 s, doubling up to 5 min.
        c.backoff_ms = if c.backoff_ms == 0 { BACKOFF_START_MS } else { (c.backoff_ms * 2).min(BACKOFF_MAX_MS) };
        c.not_before = now_ms() + c.backoff_ms;
    }

    async fn sync_pod(self: &Rc<Self>, uid: &str, pod: &Value) {
        if !self.pods.borrow().contains_key(uid) {
            let rt = self.admit(uid, pod);
            self.pods.borrow_mut().insert(uid.to_string(), rt);
        }
        if self.pods.borrow()[uid].failed_setup.is_some() {
            return;
        }
        if self.pods.borrow()[uid].sandbox.is_none() {
            if let Err(e) = self.start_sandbox(uid, pod) {
                self.pods.borrow_mut().get_mut(uid).unwrap().failed_setup = Some(e);
                return;
            }
        }
        let policy = pod.pointer(&["spec", "restartPolicy"]).and_then(Value::as_str).unwrap_or("Always").to_string();
        // Init containers: strictly in order; each must succeed before the next.
        let n_init = self.pods.borrow()[uid].ctrs.iter().filter(|c| c.init).count();
        for i in 0..n_init {
            let state = self.pods.borrow()[uid].ctrs[i].state.clone();
            match state {
                CState::Terminated(t) if t.exit_code == 0 => continue,
                CState::Running { .. } => return,
                CState::Terminated(_) if policy == "Never" => return, // pod failed
                _ => {
                    self.maybe_start(uid, pod, i).await;
                    return;
                }
            }
        }
        let n = self.pods.borrow()[uid].ctrs.len();
        for i in n_init..n {
            let state = self.pods.borrow()[uid].ctrs[i].state.clone();
            let start = match &state {
                CState::Waiting(..) => true,
                CState::Running { .. } => false,
                CState::Terminated(t) => policy == "Always" || (policy == "OnFailure" && t.exit_code != 0),
            };
            if start {
                self.maybe_start(uid, pod, i).await;
            }
        }
    }

    /// Prepares local bookkeeping for a newly seen pod.
    fn admit(&self, uid: &str, pod: &Value) -> PodRt {
        let dir = alloc::format!("{}/pods/{uid}", self.cfg.root);
        let mut ctrs = Vec::new();
        for (key, init) in [("initContainers", true), ("containers", false)] {
            for c in pod.pointer(&["spec", key]).and_then(Value::as_array).unwrap_or(&[]) {
                ctrs.push(Ctr {
                    name: c.get("name").and_then(Value::as_str).unwrap_or("").into(),
                    image: c.get("image").and_then(Value::as_str).unwrap_or("").into(),
                    init,
                    restart_count: 0,
                    state: CState::Waiting("ContainerCreating", String::new()),
                    last_term: None,
                    signaller: None,
                    not_before: 0,
                    backoff_ms: 0,
                    seq: 0,
                });
            }
        }
        PodRt { ns: meta(pod, "namespace").into(), name: meta(pod, "name").into(), dir, sandbox: None, lease: None, ip: None, ctrs, start_time: now(), kill_at: None, last_status: String::new(), failed_setup: None }
    }

    fn start_sandbox(&self, uid: &str, pod: &Value) -> Result<(), String> {
        let dir = self.pods.borrow()[uid].dir.clone();
        kr_runtime::store::mkdir_p(&dir, 0o711).map_err(|_| String::from("cannot create pod directory"))?;
        let mut lease = None;
        if self.cfg.network {
            let ipam = alloc::format!("{}/ipam", self.cfg.root);
            let _ = kr_runtime::store::mkdir_p(&ipam, 0o700);
            lease = network::allocate(ipam.as_bytes(), uid.as_bytes()).ok();
        }
        let ip = lease.as_ref().map(|l: &Lease| l.ip);
        let net = ip.map(|ip| NetConfig { ip, prefix: network::PREFIX, gateway: network::GATEWAY });
        let hostname = spec::pod_hostname(pod);
        let sb = match container::start_sandbox(uid.as_bytes(), hostname.as_bytes(), &self.maps, net) {
            Ok(s) => s,
            Err(e) => {
                if let Some(l) = lease {
                    l.release();
                }
                return Err(alloc::format!("sandbox: {}: errno {}", e.step, e.errno.0));
            }
        };
        spec::write_etc_hosts(&dir, &hostname, ip).map_err(|_| String::from("cannot write /etc/hosts"))?;
        let mut pods = self.pods.borrow_mut();
        let p = pods.get_mut(uid).unwrap();
        p.sandbox = Some(sb);
        p.lease = lease;
        p.ip = ip;
        Ok(())
    }

    async fn maybe_start(self: &Rc<Self>, uid: &str, pod: &Value, i: usize) {
        let (name, image, not_before) = {
            let pods = self.pods.borrow();
            let c = &pods[uid].ctrs[i];
            (c.name.clone(), c.image.clone(), c.not_before)
        };
        if now_ms() < not_before {
            if let Some(c) = self.pods.borrow_mut().get_mut(uid).map(|p| &mut p.ctrs[i]) {
                if !matches!(c.state, CState::Waiting(..)) {
                    let msg = alloc::format!("back-off restarting failed container {name}");
                    c.state = CState::Waiting("CrashLoopBackOff", msg);
                }
            }
            return;
        }
        // Image: pull if missing (or always for :latest / pullPolicy Always on first start).
        let cspec = spec::find_container(pod, &name);
        let policy = cspec.and_then(|c| c.get("imagePullPolicy")).and_then(Value::as_str).unwrap_or("");
        let latest = !image.contains(':') || image.ends_with(":latest");
        let need_pull = self.store.image(&image).is_none() || (policy == "Always" && self.pods.borrow()[uid].ctrs[i].seq == 0) || (policy.is_empty() && latest && self.pods.borrow()[uid].ctrs[i].seq == 0);
        if need_pull && policy != "Never" {
            if let Err(e) = kr_runtime::pull::pull(&self.store, &image).await {
                self.set_waiting(uid, i, "ErrImagePull", alloc::format!("failed to pull {image}: {e:?}"));
                self.backoff(uid, i);
                return;
            }
        }
        let Some((_, img, mut rootfs)) = self.store.image(&image) else {
            self.set_waiting(uid, i, "ErrImageNeverPull", alloc::format!("image {image} not present"));
            return;
        };
        rootfs.pop();
        let built = match spec::build(&self.c, pod, cspec.unwrap_or(&Value::Null), &img, &self.pods.borrow()[uid].dir, self.pods.borrow()[uid].ip, &self.cfg.node_name).await {
            Ok(b) => b,
            Err(msg) => {
                self.set_waiting(uid, i, "CreateContainerConfigError", msg);
                self.backoff(uid, i);
                return;
            }
        };
        let seq = self.pods.borrow()[uid].ctrs[i].seq + 1;
        let cid = alloc::format!("{uid}-{name}-{seq}");
        let dirs = match self.store.create_container(&cid) {
            Ok(d) => d,
            Err(_) => {
                self.set_waiting(uid, i, "CreateContainerError", "cannot create container directories".into());
                return;
            }
        };
        let log_path = alloc::format!("{}/{name}.log\0", self.pods.borrow()[uid].dir);
        let log = kr_sys::ns::open(log_path.as_bytes(), kr_sys::ns::O_WRONLY | kr_sys::ns::O_CREAT | 0o2000 /* O_APPEND */, 0o640).ok();
        let limits = if self.cfg.cgroups { built.limits } else { Default::default() };
        let pods = self.pods.borrow();
        let p = &pods[uid];
        let run = container::RunSpec {
            rootfs: &rootfs,
            upper: dirs.upper.as_bytes(),
            work: dirs.work.as_bytes(),
            merged: dirs.merged.as_bytes(),
            argv: &built.argv,
            env: &built.env,
            cwd: built.cwd.as_bytes(),
            hostname: b"",
            id: cid.as_bytes(),
            limits,
            user: built.user.as_bytes(),
            maps: &self.maps,
            net: None,
            sandbox: p.sandbox.as_ref(),
            mounts: &built.mounts,
            log_fd: log.as_ref().map(|f| f.raw()),
        };
        let r = container::start(&run);
        drop(pods);
        drop(log);
        match r {
            Ok(running) => {
                let started = now();
                {
                    let mut pods = self.pods.borrow_mut();
                    let c = &mut pods.get_mut(uid).unwrap().ctrs[i];
                    if c.seq > 0 {
                        c.restart_count += 1;
                    }
                    c.seq = seq;
                    c.signaller = Some(running.signaller());
                    c.state = CState::Running { started_at: started, id: cid.clone() };
                }
                self.spawn_waiter(uid.to_string(), name, cid, running, started);
            }
            Err(e) => {
                let _ = self.maps.run_as_root(|| self.store.delete_container(&cid).is_ok());
                self.set_waiting(uid, i, "RunContainerError", alloc::format!("{}: errno {}", e.step, e.errno.0));
                self.pods.borrow_mut().get_mut(uid).unwrap().ctrs[i].seq = seq;
                self.backoff(uid, i);
            }
        }
    }

    fn spawn_waiter(self: &Rc<Self>, pod_uid: String, ctr: String, cid: String, running: Running, started_at: i64) {
        let me = self.clone();
        kr_rt::exec::spawn(async move {
            let (exit_code, oom) = match running.wait().await {
                Ok(e) => (e.code, e.oom_killed),
                Err(_) => (128, false),
            };
            let _ = me.maps.run_as_root(|| me.store.delete_container(&cid).is_ok());
            me.exits.borrow_mut().push(Exit { pod_uid, ctr, exit_code, oom, started_at });
            me.notify.notify();
        });
    }

    fn set_waiting(&self, uid: &str, i: usize, reason: &'static str, msg: String) {
        if let Some(p) = self.pods.borrow_mut().get_mut(uid) {
            p.ctrs[i].state = CState::Waiting(reason, msg);
        }
    }

    fn backoff(&self, uid: &str, i: usize) {
        if let Some(p) = self.pods.borrow_mut().get_mut(uid) {
            let c = &mut p.ctrs[i];
            c.backoff_ms = if c.backoff_ms == 0 { BACKOFF_START_MS } else { (c.backoff_ms * 2).min(BACKOFF_MAX_MS) };
            c.not_before = now_ms() + c.backoff_ms;
        }
    }

    /// Graceful termination for a pod with a deletionTimestamp.
    async fn terminate(&self, uid: &str, pod: &Value) {
        if !self.pods.borrow().contains_key(uid) {
            return;
        }
        let grace = pod.pointer(&["metadata", "deletionGracePeriodSeconds"]).and_then(Value::as_u64).or_else(|| pod.pointer(&["spec", "terminationGracePeriodSeconds"]).and_then(Value::as_u64)).unwrap_or(30);
        let deadline = {
            let mut pods = self.pods.borrow_mut();
            let p = pods.get_mut(uid).unwrap();
            if p.kill_at.is_none() {
                p.kill_at = Some(now_ms() + grace * 1000);
                for c in &p.ctrs {
                    if let Some(s) = &c.signaller {
                        let _ = s.send(kr_sys::ns::SIGTERM);
                    }
                }
            }
            p.kill_at.unwrap()
        };
        if now_ms() >= deadline {
            self.kill_now(uid);
        }
        if self.all_stopped(uid) {
            self.cleanup(uid);
            // Finish the deletion: the API object is removed once nothing runs.
            let path = alloc::format!("/api/v1/namespaces/{}/pods/{}", meta(pod, "namespace"), meta(pod, "name"));
            let _ = self.c.delete(&alloc::format!("{path}?gracePeriodSeconds=0")).await;
        }
    }

    fn kill_now(&self, uid: &str) {
        if let Some(p) = self.pods.borrow().get(uid) {
            for c in &p.ctrs {
                if let Some(s) = &c.signaller {
                    let _ = s.send(kr_sys::ns::SIGKILL);
                }
            }
        }
    }

    fn all_stopped(&self, uid: &str) -> bool {
        self.pods.borrow().get(uid).is_none_or(|p| p.ctrs.iter().all(|c| c.signaller.is_none()))
    }

    fn cleanup(&self, uid: &str) {
        let Some(p) = self.pods.borrow_mut().remove(uid) else { return };
        if let Some(sb) = &p.sandbox {
            sb.stop();
        }
        if let Some(l) = p.lease {
            l.release();
        }
        let _ = self.maps.run_as_root(|| remove_tree(&p.dir));
    }

    /// Builds the pod status and patches it if it changed.
    async fn report_status(&self, uid: &str, pod: &Value) {
        let (status, path) = {
            let pods = self.pods.borrow();
            let Some(p) = pods.get(uid) else { return };
            let policy = pod.pointer(&["spec", "restartPolicy"]).and_then(Value::as_str).unwrap_or("Always");
            (self.status_json(p, policy), alloc::format!("/api/v1/namespaces/{}/pods/{}/status", p.ns, p.name))
        };
        let text = json::to_string(&status);
        if self.pods.borrow().get(uid).is_some_and(|p| p.last_status == text) {
            return;
        }
        let patch = Value::Object(alloc::vec![(String::from("status"), status)]);
        if self.c.patch(&path, "application/merge-patch+json", &patch).await.is_ok() {
            if let Some(p) = self.pods.borrow_mut().get_mut(uid) {
                p.last_status = text;
            }
        }
    }

    fn status_json(&self, p: &PodRt, policy: &str) -> Value {
        let t = |s: i64| Value::String(rfc3339(s));
        let o = |f: Vec<(&str, Value)>| Value::Object(f.into_iter().map(|(k, v)| (k.into(), v)).collect());
        let state_json = |s: &CState| -> Value {
            match s {
                CState::Waiting(r, m) => o(alloc::vec![("waiting", o(alloc::vec![("reason", Value::from(*r)), ("message", Value::from(m.as_str()))]))]),
                CState::Running { started_at, .. } => o(alloc::vec![("running", o(alloc::vec![("startedAt", t(*started_at))]))]),
                CState::Terminated(tm) => o(alloc::vec![(
                    "terminated",
                    o(alloc::vec![("exitCode", Value::Number(Number::from_i64(tm.exit_code as i64))), ("reason", Value::from(tm.reason)), ("startedAt", t(tm.started_at)), ("finishedAt", t(tm.finished_at))])
                )]),
            }
        };
        let cstat = |c: &Ctr| -> Value {
            let id = match &c.state {
                CState::Running { id, .. } => alloc::format!("kr://{id}"),
                _ => String::new(),
            };
            let running = matches!(c.state, CState::Running { .. });
            let mut f = alloc::vec![
                ("name", Value::from(c.name.as_str())),
                ("image", Value::from(c.image.as_str())),
                ("imageID", Value::from("")),
                ("containerID", Value::String(id)),
                ("ready", Value::Bool(running && !c.init)),
                ("started", Value::Bool(running)),
                ("restartCount", Value::Number(Number::from_u64(c.restart_count as u64))),
                ("state", state_json(&c.state)),
            ];
            f.push(("lastState", c.last_term.as_ref().filter(|_| !matches!(c.state, CState::Terminated(_))).map(|tm| state_json(&CState::Terminated(tm.clone()))).unwrap_or(o(Vec::new()))));
            o(f)
        };
        let apps: Vec<&Ctr> = p.ctrs.iter().filter(|c| !c.init).collect();
        let inits_done = p.ctrs.iter().filter(|c| c.init).all(|c| matches!(&c.state, CState::Terminated(t) if t.exit_code == 0));
        let all_running = !apps.is_empty() && apps.iter().all(|c| matches!(c.state, CState::Running { .. }));
        let all_done = !apps.is_empty() && apps.iter().all(|c| matches!(c.state, CState::Terminated(_)));
        let failed = apps.iter().any(|c| matches!(&c.state, CState::Terminated(t) if t.exit_code != 0)) || p.ctrs.iter().any(|c| c.init && matches!(&c.state, CState::Terminated(t) if t.exit_code != 0) && policy == "Never");
        let phase = if p.failed_setup.is_some() {
            "Failed"
        } else if all_done && policy != "Always" && (policy == "Never" || !failed) {
            if failed { "Failed" } else { "Succeeded" }
        } else if failed && policy == "Never" && apps.iter().all(|c| !matches!(c.state, CState::Running { .. })) && p.ctrs.iter().any(|c| c.init && matches!(&c.state, CState::Terminated(t) if t.exit_code != 0)) {
            "Failed"
        } else if apps.iter().any(|c| matches!(c.state, CState::Running { .. })) || (inits_done && apps.iter().any(|c| c.last_term.is_some())) {
            "Running"
        } else {
            "Pending"
        };
        let cond = |ty: &str, ok: bool| o(alloc::vec![("type", Value::from(ty)), ("status", Value::from(if ok { "True" } else { "False" })), ("lastTransitionTime", t(p.start_time))]);
        let ip = p.ip.map(|a| alloc::format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]));
        let mut f = alloc::vec![
            ("phase", Value::from(phase)),
            ("conditions", Value::Array(alloc::vec![cond("PodScheduled", true), cond("Initialized", inits_done), cond("ContainersReady", all_running), cond("Ready", all_running)])),
            ("hostIP", Value::from("127.0.0.1")),
            ("startTime", t(p.start_time)),
            ("containerStatuses", Value::Array(apps.iter().map(|c| cstat(c)).collect())),
        ];
        let inits: Vec<Value> = p.ctrs.iter().filter(|c| c.init).map(cstat).collect();
        if !inits.is_empty() {
            f.push(("initContainerStatuses", Value::Array(inits)));
        }
        if let Some(ip) = ip {
            f.push(("podIP", Value::from(ip.as_str())));
            f.push(("podIPs", Value::Array(alloc::vec![o(alloc::vec![("ip", Value::from(ip.as_str()))])])));
        }
        if let Some(msg) = &p.failed_setup {
            f.push(("message", Value::from(msg.as_str())));
            f.push(("reason", Value::from("SandboxFailed")));
        }
        o(f)
    }
}
