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
#[cfg(test)]
extern crate std;

pub mod node;
pub mod dns;
mod probe;
pub mod proxy;
pub mod remote;
mod spec;
pub mod stream;

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
use kr_runtime::auth::Cred;
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
    /// The node's InternalIP (reported in Node status; peers route pod subnets to it).
    pub node_ip: [u8; 4],
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

/// Pod uids are 36-char UUIDs (the owner recorded in kubelet IP leases).
fn is_pod_uid(owner: &[u8]) -> bool {
    owner.len() == 36 && owner.iter().filter(|b| **b == b'-').count() == 4
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
    eph: bool,
    restart_count: u32,
    state: CState,
    last_term: Option<Term>,
    signaller: Option<Signaller>,
    /// Earliest start time (CrashLoopBackOff), ms.
    not_before: u64,
    backoff_ms: u64,
    seq: u32,
    /// Handle for exec probes / exec while running.
    target: Option<container::ExecTarget>,
    probes: Vec<(probe::Kind, probe::State)>,
    /// startupProbe passed (or none).
    started: bool,
    /// readinessProbe verdict (true without a readiness probe).
    ready: bool,
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
    /// Last refresh of configMap/secret/projected volumes (ms).
    volumes_synced: u64,
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
    /// Image pulls in flight or recently failed (image ref -> state).
    pulls: RefCell<BTreeMap<String, Pull>>,
    /// Images pulled successfully by this kubelet (pullPolicy Always / :latest satisfied).
    done_pulls: RefCell<Vec<String>>,
    /// Rootless pod network: a namespace pair owned by kr holding the bridge; pod sandboxes
    /// are nested inside it so pods get IPs and reach each other without real root.
    infra: RefCell<Option<Sandbox>>,
    /// This node's pod subnet (from `spec.podCIDR`).
    podnet: Cell<network::PodNet>,
}

enum PullGate {
    Ready,
    Wait,
    Start,
}

enum Pull {
    InProgress,
    Failed { msg: String, retry_at: u64 },
}

const BACKOFF_START_MS: u64 = 10_000;
const BACKOFF_MAX_MS: u64 = 300_000;

impl<C: Client + Clone + 'static> Kubelet<C> {
    pub fn new(c: C, cfg: Config, store: Store) -> Rc<Self> {
        Rc::new(Kubelet { c, cfg, store, maps: IdMaps::for_current_user(), pods: RefCell::new(BTreeMap::new()), exits: RefCell::new(Vec::new()), notify: Notify::default(), pulls: RefCell::new(BTreeMap::new()), done_pulls: RefCell::new(Vec::new()), infra: RefCell::new(None), podnet: Cell::new(network::PodNet::default()) })
    }

    /// Runs registration, heartbeats, the pod watch and the sync loop (never returns).
    pub async fn run(self: Rc<Self>) {
        // Sandboxes die with the previous kr process (even after SIGKILL), so every pod lease is
        // stale. Leases owned by anything but a pod uid (`kr ctr run` ids) are left alone.
        network::gc(alloc::format!("{}/ipam", self.cfg.root).as_bytes(), |owner| !is_pod_uid(owner));
        node::register(&self.c, &self.cfg).await;
        // The API server assigns the pod subnet at registration.
        for _ in 0..30 {
            if let Ok(n) = self.c.get(&alloc::format!("/api/v1/nodes/{}", self.cfg.node_name)).await {
                if let Some(pn) = n.pointer(&["spec", "podCIDR"]).and_then(Value::as_str).and_then(network::PodNet::parse) {
                    self.podnet.set(pn);
                    break;
                }
            }
            kr_rt::exec::sleep(1000).await;
        }
        let pn = self.podnet.get();
        if self.cfg.network {
            if let Err(e) = network::setup_host_with(&pn) {
                kr_rt::eprint(alloc::format!("kubelet: network setup failed (errno {}); pods get no IP\n", e.0).as_bytes());
            }
        } else {
            match container::start_sandbox(b"kr-pod-network", b"", &self.maps, None) {
                Ok(infra) => {
                    // ip_forward + bridge inside the infra namespaces; outbound NAT is not
                    // possible rootless (no route out), so a failure there is tolerated.
                    let ok = container::run_in_net(&infra, || {
                        let nl = match kr_net::netlink::Netlink::route() {
                            Ok(n) => n,
                            Err(_) => return 1,
                        };
                        let _ = nl.bridge_add(network::BRIDGE);
                        let Ok(br) = kr_net::netlink::ifindex(network::BRIDGE) else { return 2 };
                        let _ = nl.addr_add(br, pn.gateway, pn.prefix);
                        if nl.link_up(br).is_err() {
                            return 3;
                        }
                        let _ = kr_sys::ns::write_file(b"/proc/sys/net/ipv4/ip_forward\0", b"1");
                        0
                    });
                    match ok {
                        Ok(0) => *self.infra.borrow_mut() = Some(infra),
                        r => {
                            kr_rt::eprint(alloc::format!("kubelet: rootless pod network setup failed ({}); pods get no IP\n", r.map(|c| c.to_string()).unwrap_or_else(|e| alloc::format!("{}: errno {}", e.step, e.errno.0))).as_bytes());
                            infra.stop();
                        }
                    }
                }
                Err(e) => kr_rt::eprint(alloc::format!("kubelet: rootless pod network unavailable ({}: errno {})\n", e.step, e.errno.0).as_bytes()),
            }
        }
        // Service proxy in the node network namespace (host when root, infra when rootless).
        let net = match self.infra.borrow().as_ref() {
            Some(infra) => proxy::NodeNet::factory(infra).ok(),
            None if self.cfg.network => Some(proxy::NodeNet::Host),
            None => None,
        };
        match net {
            Some(net) => {
                let net = Rc::new(net);
                kr_rt::exec::spawn(proxy::Proxy::new(self.c.clone(), net.clone(), self.cfg.node_name.clone()).run());
                kr_rt::exec::spawn(dns::run(self.c.clone(), net));
            }
            None => kr_rt::eprint(b"kubelet: no node network; Services are not proxied\n"),
        }
        if self.cfg.network {
            let me = self.clone();
            kr_rt::exec::spawn(async move { me.route_loop().await });
        }
        let hb = self.clone();
        kr_rt::exec::spawn(async move { node::heartbeat_loop(&hb.c, &hb.cfg).await });
        let w = self.clone();
        kr_rt::exec::spawn(async move { w.watch_loop().await });
        loop {
            self.sync_all().await;
            self.notify.wait(1000).await;
        }
    }

    /// host-gw routing (root mode): a route to every other node's pod subnet via its
    /// InternalIP. Nodes must share an L2 segment (no overlay yet).
    async fn route_loop(&self) {
        use kr_net::netlink::RTPROT_KR;
        loop {
            if let (Ok(list), Ok(nl)) = (self.c.list("/api/v1/nodes", "").await, kr_net::netlink::Netlink::route()) {
                let mut want = Vec::new();
                for n in list.get("items").and_then(Value::as_array).unwrap_or(&[]) {
                    if meta(n, "name") == self.cfg.node_name {
                        continue;
                    }
                    let Some(pn) = n.pointer(&["spec", "podCIDR"]).and_then(Value::as_str).and_then(network::PodNet::parse) else { continue };
                    let ip = n.pointer(&["status", "addresses"]).and_then(Value::as_array).and_then(|a| a.iter().find(|x| x.get("type").and_then(Value::as_str) == Some("InternalIP"))).and_then(|x| x.get("address")).and_then(Value::as_str).and_then(kr_apiserver::object::parse_ipv4);
                    if let Some(gw) = ip {
                        want.push((pn.subnet, pn.prefix, gw));
                    }
                }
                let have = nl.routes_by_proto(RTPROT_KR).unwrap_or_default();
                let (add, del) = route_diff(&want, &have);
                for (d, p) in del {
                    let _ = nl.route_del(d, p, RTPROT_KR);
                }
                for (d, p, gw) in add {
                    let _ = nl.route_add_proto(d, p, Some(gw), 0, RTPROT_KR);
                }
            }
            kr_rt::exec::sleep(5000).await;
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
                self.run_probes(&uid, pod);
                self.refresh_volumes(&uid, pod).await;
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
        c.target = None;
        c.probes.clear();
        c.ready = false;
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
            if self.pods.borrow()[uid].ctrs[i].eph {
                continue;
            }
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
        // Ephemeral containers: added to a running pod, started once, never restarted.
        for e in pod.pointer(&["spec", "ephemeralContainers"]).and_then(Value::as_array).unwrap_or(&[]) {
            let name = e.get("name").and_then(Value::as_str).unwrap_or("");
            let idx = {
                let mut pods = self.pods.borrow_mut();
                let p = pods.get_mut(uid).unwrap();
                match p.ctrs.iter().position(|c| c.name == name) {
                    Some(i) => i,
                    None => {
                        p.ctrs.push(Ctr { name: name.into(), image: e.get("image").and_then(Value::as_str).unwrap_or("").into(), init: false, eph: true, restart_count: 0, state: CState::Waiting("ContainerCreating", String::new()), last_term: None, signaller: None, not_before: 0, backoff_ms: 0, seq: 0, target: None, probes: Vec::new(), started: false, ready: false });
                        p.ctrs.len() - 1
                    }
                }
            };
            let c_eph = self.pods.borrow()[uid].ctrs[idx].eph;
            if c_eph && matches!(self.pods.borrow()[uid].ctrs[idx].state, CState::Waiting(..)) {
                self.maybe_start(uid, pod, idx).await;
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
                    eph: false,
                    restart_count: 0,
                    state: CState::Waiting("ContainerCreating", String::new()),
                    last_term: None,
                    signaller: None,
                    not_before: 0,
                    backoff_ms: 0,
                    seq: 0,
                    target: None,
                    probes: Vec::new(),
                    started: false,
                    ready: false,
                });
            }
        }
        PodRt { ns: meta(pod, "namespace").into(), name: meta(pod, "name").into(), dir, sandbox: None, lease: None, ip: None, ctrs, start_time: now(), kill_at: None, last_status: String::new(), failed_setup: None, volumes_synced: now_ms() }
    }

    fn start_sandbox(&self, uid: &str, pod: &Value) -> Result<(), String> {
        let dir = self.pods.borrow()[uid].dir.clone();
        kr_runtime::store::mkdir_p(&dir, 0o711).map_err(|_| String::from("cannot create pod directory"))?;
        let mut lease = None;
        let rootless_net = self.infra.borrow().is_some();
        if self.cfg.network || rootless_net {
            let ipam = alloc::format!("{}/ipam", self.cfg.root);
            let _ = kr_runtime::store::mkdir_p(&ipam, 0o700);
            lease = network::allocate_in(ipam.as_bytes(), uid.as_bytes(), &self.podnet.get()).ok();
        }
        let ip = lease.as_ref().map(|l: &Lease| l.ip);
        let pn = self.podnet.get();
        let net = ip.map(|ip| NetConfig { ip, prefix: pn.prefix, gateway: pn.gateway });
        let hostname = spec::pod_hostname(pod);
        let started = match self.infra.borrow().as_ref() {
            Some(infra) => container::start_sandbox_in(infra, uid.as_bytes(), hostname.as_bytes(), &self.maps, net),
            None => container::start_sandbox(uid.as_bytes(), hostname.as_bytes(), &self.maps, net),
        };
        let sb = match started {
            Ok(s) => s,
            Err(e) => {
                if let Some(l) = lease {
                    l.release();
                }
                return Err(alloc::format!("sandbox: {}: errno {}", e.step, e.errno.0));
            }
        };
        spec::write_etc_hosts(&dir, &hostname, ip).map_err(|_| String::from("cannot write /etc/hosts"))?;
        spec::write_resolv_conf(&dir, pod).map_err(|_| String::from("cannot write /etc/resolv.conf"))?;
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
        // Pulls are keyed by image plus the pod's pull-credential identity, so a pull that failed
        // for lack of credentials never blocks a pod that has them.
        let key = spec::pull_key(pod, &image);
        let gate = if need_pull && policy != "Never" { self.pull_gate(&key, &image) } else { PullGate::Ready };
        if matches!(gate, PullGate::Start) {
            let creds = self.pull_creds(pod).await;
            self.start_pull(key.clone(), image.clone(), creds);
        }
        if !matches!(gate, PullGate::Ready) {
            let msg = match self.pulls.borrow().get(&key) {
                Some(Pull::Failed { msg, .. }) => Some(msg.clone()),
                _ => None,
            };
            match msg {
                Some(m) => self.set_waiting(uid, i, "ImagePullBackOff", m),
                None => self.set_waiting(uid, i, "ContainerCreating", alloc::format!("pulling image {image}")),
            }
            return;
        }
        let Some((_, img, mut rootfs)) = self.store.image(&image) else {
            self.set_waiting(uid, i, "ErrImageNeverPull", alloc::format!("image {image} not present"));
            return;
        };
        rootfs.pop();
        // Copy out first: RefCell guards in the match scrutinee would live across the await
        // and through the arms (which borrow mutably).
        let (pod_dir, pod_ip) = {
            let pods = self.pods.borrow();
            (pods[uid].dir.clone(), pods[uid].ip)
        };
        let built = match spec::build(&self.c, pod, cspec.unwrap_or(&Value::Null), &img, &pod_dir, pod_ip, &self.cfg.node_name).await {
            Ok(b) => b,
            Err(msg) => {
                self.set_waiting(uid, i, "CreateContainerConfigError", msg);
                self.backoff(uid, i);
                return;
            }
        };
        spec::apply_fs_group(&self.maps, pod, &pod_dir);
        let seq = self.pods.borrow()[uid].ctrs[i].seq + 1;
        let cid = alloc::format!("{uid}-{name}-{seq}");
        // A previous kubelet run (killed with its containers) may have left this id behind.
        let _ = self.maps.run_as_root(|| self.store.delete_container(&cid).is_ok());
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
            extra_groups: &built.extra_groups,
            readonly_root: cspec.and_then(|c| c.pointer(&["securityContext", "readOnlyRootFilesystem"])).and_then(Value::as_bool).unwrap_or(false),
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
                    c.target = Some(running.target());
                    c.state = CState::Running { started_at: started, id: cid.clone() };
                    // Probes restart with every container start.
                    let cs = cspec.cloned().unwrap_or(Value::Null);
                    c.probes = [probe::Kind::Startup, probe::Kind::Liveness, probe::Kind::Readiness]
                        .into_iter()
                        .filter(|_| !c.init && !c.eph)
                        .filter_map(|k| cs.get(k.field()).map(|p| (k, probe::State::new(p.clone(), now_ms()))))
                        .collect();
                    c.started = !c.probes.iter().any(|(k, _)| *k == probe::Kind::Startup);
                    c.ready = !c.probes.iter().any(|(k, _)| *k == probe::Kind::Readiness);
                }
                // postStart: a failing hook kills the container (restartPolicy decides the rest).
                if let Some(hook) = cspec.and_then(|c| c.pointer(&["lifecycle", "postStart"])).cloned() {
                    let (sig, target, ctr) = (running.signaller(), running.target(), cspec.cloned().unwrap_or(Value::Null));
                    let pod_target = self.pods.borrow().get(uid).and_then(|p| p.sandbox.as_ref().and_then(|s| s.target().ok()));
                    let me = self.clone();
                    kr_rt::exec::spawn(async move {
                        if !probe::run_handler(&hook, &ctr, &target, pod_target.as_ref(), &me.maps, 120_000).await {
                            let _ = sig.send(kr_sys::ns::SIGKILL);
                        }
                    });
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

    /// Pulls happen in background tasks so a slow registry never stalls the sync loop.
    /// Returns true once the image may be used (pull finished in this kubelet's lifetime, or a
    /// pull is unnecessary); false while pulling or backing off after a failure.
    /// `Start` marks the pull in progress; the caller then gathers credentials and calls
    /// [`Kubelet::start_pull`].
    fn pull_gate(&self, key: &str, image: &str) -> PullGate {
        let mut pulls = self.pulls.borrow_mut();
        match pulls.get(key) {
            Some(Pull::InProgress) => return PullGate::Wait,
            Some(Pull::Failed { retry_at, .. }) if now_ms() < *retry_at => return PullGate::Wait,
            _ => {}
        }
        // A completed pull is recorded by removing the entry and the image being present.
        if self.store.image(image).is_some() && !pulls.contains_key(key) && self.pulled_once(key) {
            return PullGate::Ready;
        }
        pulls.insert(key.to_string(), Pull::InProgress);
        PullGate::Start
    }

    fn start_pull(self: &Rc<Self>, key: String, image: String, creds: Vec<Cred>) {
        let me = self.clone();
        kr_rt::exec::spawn(async move {
            let r = kr_runtime::pull::pull_auth(&me.store, &image, &creds).await;
            let mut pulls = me.pulls.borrow_mut();
            match r {
                Ok(_) => {
                    pulls.remove(&key);
                    me.done_pulls.borrow_mut().push(key);
                }
                Err(e) => {
                    // errors carry static strings only, never credentials or tokens
                    pulls.insert(key, Pull::Failed { msg: alloc::format!("failed to pull {image}: {e:?}"), retry_at: now_ms() + 10_000 });
                }
            }
            drop(pulls);
            me.notify.notify();
        });
    }

    /// Registry credentials from the pod's `imagePullSecrets` and its ServiceAccount's.
    /// Missing or unreadable secrets are skipped (the pull then fails or goes anonymous).
    async fn pull_creds(&self, pod: &Value) -> Vec<Cred> {
        let ns = meta(pod, "namespace");
        let mut names = spec::pull_secret_names(pod);
        let sa = pod.pointer(&["spec", "serviceAccountName"]).and_then(Value::as_str).unwrap_or("default");
        if let Ok(sa) = self.c.get(&alloc::format!("/api/v1/namespaces/{ns}/serviceaccounts/{sa}")).await {
            for n in spec::pull_secret_names_of(sa.get("imagePullSecrets")) {
                if !names.contains(&n) {
                    names.push(n);
                }
            }
        }
        let mut out = Vec::new();
        for n in names {
            if let Ok(s) = self.c.get(&alloc::format!("/api/v1/namespaces/{ns}/secrets/{n}")).await {
                out.extend(kr_runtime::auth::from_secret(&s));
            }
        }
        out
    }

    fn pulled_once(&self, key: &str) -> bool {
        self.done_pulls.borrow().iter().any(|i| i == key)
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

    /// Every 20 s: republish configMap/secret/projected/downwardAPI volumes (ConfigMap and
    /// label edits; the ServiceAccount token is renewed at 80% of its lifetime).
    async fn refresh_volumes(&self, uid: &str, pod: &Value) {
        const EVERY_MS: u64 = 20_000;
        let dir = {
            let mut pods = self.pods.borrow_mut();
            let Some(p) = pods.get_mut(uid) else { return };
            if p.sandbox.is_none() || now_ms() < p.volumes_synced + EVERY_MS {
                return;
            }
            p.volumes_synced = now_ms();
            p.dir.clone()
        };
        spec::refresh_volumes(&self.c, pod, &dir).await;
        spec::apply_fs_group(&self.maps, pod, &dir);
    }

    /// Starts any due probes as background tasks; results arrive via `probe_done`.
    fn run_probes(self: &Rc<Self>, uid: &str, pod: &Value) {
        let now = now_ms();
        let mut due = Vec::new();
        {
            let mut pods = self.pods.borrow_mut();
            let Some(p) = pods.get_mut(uid) else { return };
            let pod_target = p.sandbox.as_ref().and_then(|s| s.target().ok());
            for (ci, c) in p.ctrs.iter_mut().enumerate() {
                let Some(target) = c.target.clone() else { continue };
                let started = c.started;
                for (pi, (kind, st)) in c.probes.iter_mut().enumerate() {
                    // Startup runs until it passes; liveness/readiness only after that.
                    let active = if *kind == probe::Kind::Startup { !started } else { started };
                    if active && !st.in_flight && now >= st.next_at {
                        st.in_flight = true;
                        due.push((ci, pi, c.name.clone(), st.spec.clone(), st.timeout_ms(), target.clone(), pod_target.clone()));
                    }
                }
            }
        }
        for (ci, pi, name, spec, timeout, target, pod_target) in due {
            let me = self.clone();
            let uid = uid.to_string();
            let ctr = spec::find_container(pod, &name).cloned().unwrap_or(Value::Null);
            kr_rt::exec::spawn(async move {
                let ok = probe::run(&spec, &ctr, &target, pod_target.as_ref(), &me.maps, timeout).await;
                me.probe_done(&uid, ci, pi, ok);
                me.notify.notify();
            });
        }
    }

    fn probe_done(&self, uid: &str, ci: usize, pi: usize, ok: bool) {
        let mut pods = self.pods.borrow_mut();
        let Some(c) = pods.get_mut(uid).and_then(|p| p.ctrs.get_mut(ci)) else { return };
        let Some((kind, st)) = c.probes.get_mut(pi) else { return };
        let kind = *kind;
        let Some(verdict) = st.record(ok, now_ms()) else { return };
        match (kind, verdict) {
            (probe::Kind::Startup, true) => c.started = true,
            (probe::Kind::Readiness, v) => c.ready = v,
            // Failed liveness/startup: kill; the exit is handled by the restart policy.
            (probe::Kind::Startup | probe::Kind::Liveness, false) => {
                if let Some(s) = &c.signaller {
                    let _ = s.send(kr_sys::ns::SIGKILL);
                }
            }
            (probe::Kind::Liveness, true) => {}
        }
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
                let pod_target = p.sandbox.as_ref().and_then(|s| s.target().ok());
                for c in &p.ctrs {
                    let Some(s) = c.signaller.clone() else { continue };
                    let cspec = ["containers", "initContainers"].iter().flat_map(|k| pod.pointer(&["spec", k]).and_then(Value::as_array).unwrap_or(&[]).iter()).find(|cs| cs.get("name").and_then(Value::as_str) == Some(c.name.as_str())).cloned();
                    let hook = cspec.as_ref().and_then(|cs| cs.pointer(&["lifecycle", "preStop"])).cloned();
                    match (hook, c.target.clone()) {
                        // preStop runs first (bounded by the grace period), then SIGTERM.
                        (Some(hook), Some(target)) => {
                            let (ctr, pod_target, maps) = (cspec.unwrap_or(Value::Null), pod_target.clone(), self.maps.clone());
                            kr_rt::exec::spawn(async move {
                                let _ = probe::run_handler(&hook, &ctr, &target, pod_target.as_ref(), &maps, grace * 1000).await;
                                let _ = s.send(kr_sys::ns::SIGTERM);
                            });
                        }
                        _ => {
                            let _ = s.send(kr_sys::ns::SIGTERM);
                        }
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
            (status_json(p, policy), alloc::format!("/api/v1/namespaces/{}/pods/{}/status", p.ns, p.name))
        };
        let text = json::to_string(&status);
        if self.pods.borrow().get(uid).is_some_and(|p| p.last_status == text) {
            return;
        }
        let mut status = status;
        if let Value::Object(f) = &mut status {
            f.push((String::from("qosClass"), Value::from(spec::qos_class(pod))));
        }
        let patch = Value::Object(alloc::vec![(String::from("status"), status)]);
        if self.c.patch(&path, "application/merge-patch+json", &patch).await.is_ok() {
            if let Some(p) = self.pods.borrow_mut().get_mut(uid) {
                p.last_status = text;
            }
        }
    }
}


fn status_json(p: &PodRt, policy: &str) -> Value {
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
    let inits_done = p.ctrs.iter().filter(|c| c.init).all(|c| matches!(&c.state, CState::Terminated(t) if t.exit_code == 0));
    let cstat = |c: &Ctr| -> Value {
        let id = match &c.state {
            CState::Running { id, .. } => alloc::format!("kr://{id}"),
            _ => String::new(),
        };
        let running = matches!(c.state, CState::Running { .. });
        let ready = running && c.started && c.ready;
        let mut f = alloc::vec![
            ("name", Value::from(c.name.as_str())),
            ("image", Value::from(c.image.as_str())),
            ("imageID", Value::from("")),
            ("containerID", Value::String(id)),
            ("ready", Value::Bool(if c.init { matches!(&c.state, CState::Terminated(t) if t.exit_code == 0) } else { ready && !c.eph })),
            ("started", Value::Bool(running && c.started)),
            ("restartCount", Value::Number(Number::from_u64(c.restart_count as u64))),
            ("state", match &c.state {
                CState::Waiting("ContainerCreating", m) if !c.init && !c.eph && !inits_done => state_json(&CState::Waiting("PodInitializing", m.clone())),
                s => state_json(s),
            }),
        ];
        f.push(("lastState", c.last_term.as_ref().filter(|_| !matches!(c.state, CState::Terminated(_))).map(|tm| state_json(&CState::Terminated(tm.clone()))).unwrap_or(o(Vec::new()))));
        o(f)
    };
    let apps: Vec<&Ctr> = p.ctrs.iter().filter(|c| !c.init && !c.eph).collect();
    let all_running = !apps.is_empty() && apps.iter().all(|c| matches!(c.state, CState::Running { .. }) && c.started && c.ready);
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
    let cond = |ty: &str, ok: bool, why: Option<(&str, String)>| {
        let mut f = alloc::vec![("type", Value::from(ty)), ("status", Value::from(if ok { "True" } else { "False" })), ("lastTransitionTime", t(p.start_time))];
        if let (false, Some((r, m))) = (ok, why) {
            f.push(("reason", Value::from(r)));
            if !m.is_empty() {
                f.push(("message", Value::String(m)));
            }
        }
        o(f)
    };
    let incomplete: Vec<&str> = p.ctrs.iter().filter(|c| c.init && !matches!(&c.state, CState::Terminated(t) if t.exit_code == 0)).map(|c| c.name.as_str()).collect();
    let init_why = Some(("ContainersNotInitialized", alloc::format!("containers with incomplete status: [{}]", incomplete.join(" "))));
    let notready = || Some(("ContainersNotReady", {
        let n: Vec<&str> = apps.iter().filter(|c| !(matches!(c.state, CState::Running { .. }) && c.started && c.ready)).map(|c| c.name.as_str()).collect();
        if n.is_empty() { String::new() } else { alloc::format!("containers with unready status: [{}]", n.join(" ")) }
    }));
    let ip = p.ip.map(|a| alloc::format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]));
    let mut f = alloc::vec![
        ("phase", Value::from(phase)),
        ("conditions", Value::Array(alloc::vec![cond("PodScheduled", true, None), cond("Initialized", inits_done, init_why), cond("Ready", all_running, notready()), cond("ContainersReady", all_running, notready())])),
        ("hostIP", Value::from("127.0.0.1")),
        ("startTime", t(p.start_time)),
        ("containerStatuses", Value::Array(apps.iter().map(|c| cstat(c)).collect())),
    ];
    let inits: Vec<Value> = p.ctrs.iter().filter(|c| c.init).map(cstat).collect();
    if !inits.is_empty() {
        f.push(("initContainerStatuses", Value::Array(inits)));
    }
    let ephs: Vec<Value> = p.ctrs.iter().filter(|c| c.eph).map(cstat).collect();
    if !ephs.is_empty() {
        f.push(("ephemeralContainerStatuses", Value::Array(ephs)));
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
#[cfg(test)]
mod status_tests {
    use super::*;
    use alloc::vec;

    fn ctr(name: &str, init: bool, eph: bool, state: CState) -> Ctr {
        Ctr { name: name.into(), image: "img".into(), init, eph, restart_count: 0, state, last_term: None, signaller: None, not_before: 0, backoff_ms: 0, seq: 0, target: None, probes: Vec::new(), started: true, ready: true }
    }
    fn done(code: i32) -> CState {
        CState::Terminated(Term { exit_code: code, reason: if code == 0 { "Completed" } else { "Error" }, started_at: 1, finished_at: 2 })
    }
    fn run() -> CState {
        CState::Running { started_at: 1, id: "x".into() }
    }
    fn creating() -> CState {
        CState::Waiting("ContainerCreating", String::new())
    }
    fn pod(ctrs: Vec<Ctr>) -> PodRt {
        PodRt { ns: "d".into(), name: "p".into(), dir: String::new(), sandbox: None, lease: None, ip: None, ctrs, start_time: 0, kill_at: None, last_status: String::new(), failed_setup: None, volumes_synced: 0 }
    }
    fn at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a Value> {
        path.iter().try_fold(v, |v, k| match k.parse::<usize>() {
            Ok(i) => v.as_array()?.get(i),
            Err(_) => v.get(k),
        })
    }
    fn s<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
        at(v, path).and_then(Value::as_str)
    }
    fn cond<'a>(st: &'a Value, ty: &str) -> &'a Value {
        st.get("conditions").and_then(Value::as_array).unwrap().iter().find(|c| s(c, &["type"]) == Some(ty)).unwrap()
    }

    #[test]
    fn during_init() {
        let st = status_json(&pod(vec![ctr("init1", true, false, run()), ctr("init2", true, false, creating()), ctr("run1", false, false, creating())]), "Always");
        assert_eq!(s(&st, &["phase"]), Some("Pending"));
        assert_eq!(s(&st, &["containerStatuses", "0", "state", "waiting", "reason"]), Some("PodInitializing"));
        let i = cond(&st, "Initialized");
        assert_eq!(s(i, &["status"]), Some("False"));
        assert_eq!(s(i, &["reason"]), Some("ContainersNotInitialized"));
        assert_eq!(s(i, &["message"]), Some("containers with incomplete status: [init1 init2]"));
        assert_eq!(s(cond(&st, "Ready"), &["reason"]), Some("ContainersNotReady"));
        assert_eq!(s(&st, &["initContainerStatuses", "1", "name"]), Some("init2"));
    }

    #[test]
    fn inits_done() {
        let st = status_json(&pod(vec![ctr("init1", true, false, done(0)), ctr("run1", false, false, creating())]), "Always");
        assert_eq!(at(&st, &["initContainerStatuses", "0", "ready"]), Some(&Value::Bool(true)));
        assert_eq!(s(&st, &["initContainerStatuses", "0", "state", "terminated", "reason"]), Some("Completed"));
        assert_eq!(s(cond(&st, "Initialized"), &["status"]), Some("True"));
        assert_eq!(s(&st, &["containerStatuses", "0", "state", "waiting", "reason"]), Some("ContainerCreating"));
    }

    #[test]
    fn failing_init_never() {
        let st = status_json(&pod(vec![ctr("init1", true, false, done(3)), ctr("run1", false, false, creating())]), "Never");
        assert_eq!(s(&st, &["phase"]), Some("Failed"));
        assert_eq!(s(&st, &["initContainerStatuses", "0", "state", "terminated", "reason"]), Some("Error"));
        assert_eq!(s(&st, &["containerStatuses", "0", "state", "waiting", "reason"]), Some("PodInitializing"));
    }

    #[test]
    fn failing_init_always() {
        let mut i = ctr("init1", true, false, CState::Waiting("CrashLoopBackOff", String::new()));
        i.restart_count = 2;
        i.last_term = Some(Term { exit_code: 1, reason: "Error", started_at: 1, finished_at: 2 });
        let st = status_json(&pod(vec![i, ctr("run1", false, false, creating())]), "Always");
        assert_eq!(s(&st, &["phase"]), Some("Pending"));
        assert_eq!(at(&st, &["initContainerStatuses", "0", "restartCount"]).and_then(Value::as_u64), Some(2));
        assert!(at(&st, &["initContainerStatuses", "0", "lastState", "terminated"]).is_some());
        assert_eq!(s(&st, &["containerStatuses", "0", "state", "waiting", "reason"]), Some("PodInitializing"));
    }

    #[test]
    fn ephemeral_separate() {
        let st = status_json(&pod(vec![ctr("run1", false, false, run()), ctr("dbg", false, true, run())]), "Always");
        assert_eq!(st.get("containerStatuses").and_then(Value::as_array).map(|a| a.len()), Some(1));
        assert_eq!(s(&st, &["ephemeralContainerStatuses", "0", "name"]), Some("dbg"));
        assert_eq!(at(&st, &["ephemeralContainerStatuses", "0", "ready"]), Some(&Value::Bool(false)));
        assert_eq!(s(cond(&st, "Ready"), &["status"]), Some("True"));
        let st = status_json(&pod(vec![ctr("run1", false, false, run()), ctr("dbg", false, true, creating())]), "Always");
        assert_eq!(s(cond(&st, "Ready"), &["status"]), Some("True"));
    }
}

/// Diff between wanted host-gw routes and the kr-installed ones: (to add or fix, to delete).
/// A route whose gateway changed is deleted and re-added.
fn route_diff(want: &[([u8; 4], u8, [u8; 4])], have: &[([u8; 4], u8, Option<[u8; 4]>)]) -> (Vec<([u8; 4], u8, [u8; 4])>, Vec<([u8; 4], u8)>) {
    let add = want.iter().filter(|w| !have.iter().any(|h| h.0 == w.0 && h.1 == w.1 && h.2 == Some(w.2))).copied().collect();
    let del = have.iter().filter(|h| !want.iter().any(|w| w.0 == h.0 && w.1 == h.1 && Some(w.2) == h.2)).map(|h| (h.0, h.1)).collect();
    (add, del)
}

#[cfg(test)]
mod route_tests {
    use super::route_diff;

    #[test]
    fn diff() {
        let a = ([10, 88, 1, 0], 24, [192, 168, 0, 2]);
        let b = ([10, 88, 2, 0], 24, [192, 168, 0, 3]);
        let (add, del) = route_diff(&[a, b], &[(a.0, 24, Some(a.2)), ([10, 88, 9, 0], 24, Some([1, 1, 1, 1]))]);
        assert_eq!(add, [b]);
        assert_eq!(del, [([10, 88, 9, 0], 24)]);
        // gateway change: delete then re-add
        let (add, del) = route_diff(&[a], &[(a.0, 24, Some([9, 9, 9, 9]))]);
        assert_eq!((add.len(), del.len()), (1, 1));
    }
}
