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

pub mod evict;
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
use kr_runtime::cgroup::PodCgroup;
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
    /// Pod network backend: VXLAN overlay (true) or host-gw routes (false, needs one L2 segment).
    pub vxlan: bool,
    /// Hard eviction: MemAvailable (bytes) below which the node is under memory pressure.
    pub eviction_memory_bytes: u64,
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
    message: String,
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
    /// Init container with `restartPolicy: Always`: keeps running next to the app containers.
    sidecar: bool,
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
    /// Pod-level cgroup (None when cgroups are unavailable).
    cg: Option<PodCgroup>,
    qos: &'static str,
    /// Summed memory requests (plus overhead), the eviction baseline.
    mem_request: u64,
    /// system-node-critical / system-cluster-critical or a static pod: never evicted.
    critical: bool,
    /// Set once evicted for memory pressure: containers are killed and never restarted.
    evicted: Option<String>,
    /// (hostIP, protocol, hostPort) of the containers' host ports.
    host_ports: Vec<(String, String, u64)>,
    /// Set once `activeDeadlineSeconds` passed: containers are killed and the pod is Failed.
    deadline_exceeded: bool,
    /// Last reported status and transition time (s) of each pod condition.
    conds: Vec<(String, bool, i64)>,
}

struct Exit {
    pod_uid: String,
    ctr: String,
    exit_code: i32,
    oom: bool,
    started_at: i64,
    message: String,
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
    /// Peer/backend pairs already reported as a backend mismatch.
    warned_backend: RefCell<alloc::collections::BTreeSet<String>>,
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
        Rc::new(Kubelet { c, cfg, store, maps: IdMaps::for_current_user(), pods: RefCell::new(BTreeMap::new()), exits: RefCell::new(Vec::new()), notify: Notify::default(), pulls: RefCell::new(BTreeMap::new()), done_pulls: RefCell::new(Vec::new()), infra: RefCell::new(None), podnet: Cell::new(network::PodNet::default()), warned_backend: RefCell::new(alloc::collections::BTreeSet::new()) })
    }

    /// Runs registration, heartbeats, the pod watch and the sync loop (never returns).
    pub async fn run(self: Rc<Self>) {
        if self.cfg.vxlan && self.cfg.network {
            // Before any sandbox: pod interfaces get the tunnel MTU (uplink - VXLAN overhead).
            network::set_pod_mtu(uplink_mtu().saturating_sub(50));
        }
        // Sandboxes die with the previous kr process (even after SIGKILL), so every pod lease is
        // stale. Leases of `kr ctr run` processes are kept while that process runs.
        // Containers of a killed kr survive as orphans: kill whatever is left in the pod cgroups.
        if self.cfg.cgroups {
            kr_runtime::cgroup::kill_stale_pods();
        }
        network::gc(alloc::format!("{}/ipam", self.cfg.root).as_bytes(), |owner| !is_pod_uid(owner) && network::owner_alive(owner) != Some(false));
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
                    let ok = container::run_in_net(&infra, || network::setup_infra_bridge(&pn));
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
        let ev = self.clone();
        kr_rt::exec::spawn(async move { ev.eviction_loop().await });
        loop {
            self.sync_all().await;
            self.notify.wait(1000).await;
        }
    }

    /// Every 10 s: taint the node while MemAvailable is below the threshold and evict one pod.
    async fn eviction_loop(self: &Rc<Self>) {
        let mut state = evict::PressureState::default();
        loop {
            kr_rt::exec::sleep(10_000).await;
            let pressure = evict::under_pressure(node::memory_available_ki(), self.cfg.eviction_memory_bytes);
            if let Some(on) = state.observe(pressure) {
                self.set_memory_taint(on).await;
            }
            if pressure {
                self.evict_one();
                self.notify.notify();
            }
        }
    }

    /// Evicts the best candidate (if any) and returns its uid.
    fn evict_one(&self) -> Option<String> {
        let cands: Vec<evict::Candidate> = self
            .pods
            .borrow()
            .iter()
            .filter(|(_, p)| p.evicted.is_none() && p.failed_setup.is_none() && !p.ctrs.iter().all(|c| c.signaller.is_none()))
            .map(|(uid, p)| evict::Candidate { uid: uid.clone(), qos: p.qos, usage: p.cg.as_ref().and_then(|c| c.memory_current()).unwrap_or(0), request: p.mem_request, critical: p.critical })
            .collect();
        let uid = evict::pick(&cands)?.uid.clone();
        if let Some(p) = self.pods.borrow_mut().get_mut(&uid) {
            p.evicted = Some(evict::message(self.cfg.eviction_memory_bytes));
        }
        self.kill_now(&uid);
        Some(uid)
    }

    /// Adds or removes the memory-pressure NoSchedule taint. A PUT of the node as read (its
    /// resourceVersion is the precondition), retried on conflict, so a taint someone else
    /// changes at the same time is never overwritten.
    async fn set_memory_taint(&self, on: bool) {
        let path = alloc::format!("/api/v1/nodes/{}", self.cfg.node_name);
        for _ in 0..3 {
            let Ok(mut node) = self.c.get(&path).await else { return };
            let mut taints: Vec<Value> = node.pointer(&["spec", "taints"]).and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
            let had = taints.iter().any(|t| t.get("key").and_then(Value::as_str) == Some(evict::TAINT_KEY));
            if had == on {
                return;
            }
            taints.retain(|t| t.get("key").and_then(Value::as_str) != Some(evict::TAINT_KEY));
            if on {
                let t = alloc::format!(r#"{{"key":"{}","effect":"NoSchedule"}}"#, evict::TAINT_KEY);
                taints.push(json::parse(t.as_bytes()).unwrap_or(Value::Null));
            }
            node.entry_object("spec").set("taints", Value::Array(taints));
            match self.c.update(&path, &node).await {
                Err(e) if e.code == 409 => continue,
                _ => return,
            }
        }
    }

    /// VXLAN overlay (root mode): device `kr.vxlan`, and per peer node a route to its pod
    /// subnet via the peer's VTEP address, a permanent ARP entry for that address and an FDB
    /// entry mapping the peer's VTEP MAC to its InternalIP. Works across L3.
    async fn vxlan_loop(&self) {
        use kr_net::netlink::{self, mac_string, parse_mac, vtep_mac, RTPROT_KR};
        let my_mac = mac_string(vtep_mac(self.cfg.node_ip));
        let my_ip = fmt_ip(self.cfg.node_ip);
        loop {
            if let (Ok(list), Ok(nl)) = (self.c.list("/api/v1/nodes", "").await, netlink::Netlink::route()) {
                let mut mine = None;
                let mut peers = Vec::new();
                let mut annotated = false;
                for n in list.get("items").and_then(Value::as_array).unwrap_or(&[]) {
                    let Some(pn) = n.pointer(&["spec", "podCIDR"]).and_then(Value::as_str).and_then(network::PodNet::parse) else { continue };
                    if meta(n, "name") == self.cfg.node_name {
                        let ann = |k| n.pointer(&["metadata", "annotations", k]).and_then(Value::as_str);
                        annotated = ann(VTEP_MAC_KEY) == Some(my_mac.as_str()) && ann(VTEP_IP_KEY) == Some(my_ip.as_str()) && ann(BACKEND_KEY) == Some("vxlan");
                        mine = Some(pn);
                        continue;
                    }
                    let ip = n.pointer(&["status", "addresses"]).and_then(Value::as_array).and_then(|a| a.iter().find(|x| x.get("type").and_then(Value::as_str) == Some("InternalIP"))).and_then(|x| x.get("address")).and_then(Value::as_str).and_then(kr_apiserver::object::parse_ipv4);
                    if let Some(theirs) = backend_mismatch("vxlan", n.pointer(&["metadata", "annotations", BACKEND_KEY]).and_then(Value::as_str)) {
                        self.warn_backend(&meta(n, "name"), "vxlan", theirs);
                        continue;
                    }
                    let mac = n.pointer(&["metadata", "annotations", VTEP_MAC_KEY]).and_then(Value::as_str).and_then(parse_mac);
                    if let (Some(ip), Some(mac)) = (ip, mac) {
                        peers.push((pn, ip, mac));
                    }
                }
                if !annotated && mine.is_some() {
                    let p = alloc::format!(r#"{{"metadata":{{"annotations":{{"{VTEP_MAC_KEY}":"{my_mac}","{VTEP_IP_KEY}":"{my_ip}","{BACKEND_KEY}":"vxlan"}}}}}}"#);
                    if let Ok(p) = json::parse(p.as_bytes()) {
                        let _ = self.c.patch(&alloc::format!("/api/v1/nodes/{}", self.cfg.node_name), "application/merge-patch+json", &p).await;
                    }
                }
                if let Some(idx) = mine.and_then(|pn| self.ensure_vxlan(&nl, pn.subnet)) {
                    let routes: Vec<_> = peers.iter().map(|(pn, _, _)| (pn.subnet, pn.prefix, pn.subnet)).collect();
                    let neighs: Vec<_> = peers.iter().map(|(pn, _, mac)| (pn.subnet, *mac)).collect();
                    let fdbs: Vec<_> = peers.iter().map(|(_, ip, mac)| (*mac, *ip)).collect();
                    let have_routes: Vec<_> = nl.routes_by_proto(RTPROT_KR).unwrap_or_default();
                    let (radd, rdel) = route_diff(&routes, &have_routes);
                    let (nadd, ndel) = set_diff(&neighs, &nl.neighs(idx).unwrap_or_default());
                    let (fadd, fdel) = set_diff(&fdbs, &nl.fdbs(idx).unwrap_or_default());
                    for (d, p) in rdel {
                        let _ = nl.route_del(d, p, RTPROT_KR);
                    }
                    for (ip, mac) in ndel {
                        let _ = nl.neigh_del(idx, ip, mac);
                    }
                    for (mac, ip) in fdel {
                        let _ = nl.fdb_del(idx, mac, ip);
                    }
                    for (ip, mac) in nadd {
                        let _ = nl.neigh_add(idx, ip, mac);
                    }
                    for (mac, ip) in fadd {
                        let _ = nl.fdb_add(idx, mac, ip);
                    }
                    for (d, p, gw) in radd {
                        let _ = nl.route_add_onlink(d, p, gw, idx, RTPROT_KR);
                    }
                }
            }
            kr_rt::exec::sleep(5000).await;
        }
    }

    /// Logs a backend mismatch with a peer (once per peer and backend pair).
    fn warn_backend(&self, peer: &str, mine: &str, theirs: &str) {
        let key = alloc::format!("{peer}/{theirs}");
        if self.warned_backend.borrow_mut().insert(key) {
            kr_rt::eprint(alloc::format!("kubelet: peer node {peer} uses pod network backend {theirs} but this node uses {mine}: skipping it (all nodes must use the same KR_NET_BACKEND)\n").as_bytes());
        }
    }

    /// Creates `kr.vxlan` (VNI 1, UDP 8472, MTU = uplink - 50) with the node's pod-subnet
    /// network address as a /32 and brings it up; returns its ifindex.
    fn ensure_vxlan(&self, nl: &kr_net::netlink::Netlink, subnet: [u8; 4]) -> Option<i32> {
        let name = VXLAN_DEV.as_bytes();
        let idx = match kr_net::netlink::ifindex(name) {
            Ok(i) => i,
            Err(_) => {
                let mtu = uplink_mtu().saturating_sub(50);
                nl.vxlan_add(name, 1, 8472, self.cfg.node_ip, mtu, kr_net::netlink::vtep_mac(self.cfg.node_ip)).ok()?;
                kr_net::netlink::ifindex(name).ok()?
            }
        };
        let _ = nl.addr_add(idx, subnet, 32);
        nl.link_up(idx).ok()?;
        Some(idx)
    }

    /// host-gw routing (root mode): a route to every other node's pod subnet via its
    /// InternalIP. Nodes must share an L2 segment (no overlay yet).
    async fn route_loop(&self) {
        if self.cfg.vxlan {
            return self.vxlan_loop().await;
        }
        use kr_net::netlink::RTPROT_KR;
        let mut announced = false;
        loop {
            if let (Ok(list), Ok(nl)) = (self.c.list("/api/v1/nodes", "").await, kr_net::netlink::Netlink::route()) {
                let mut want = Vec::new();
                for n in list.get("items").and_then(Value::as_array).unwrap_or(&[]) {
                    if meta(n, "name") == self.cfg.node_name {
                        let ann = n.pointer(&["metadata", "annotations", BACKEND_KEY]).and_then(Value::as_str);
                        if ann != Some("host-gw") && !announced {
                            let p = alloc::format!(r#"{{"metadata":{{"annotations":{{"{BACKEND_KEY}":"host-gw"}}}}}}"#);
                            if let Ok(p) = json::parse(p.as_bytes()) {
                                announced = self.c.patch(&alloc::format!("/api/v1/nodes/{}", self.cfg.node_name), "application/merge-patch+json", &p).await.is_ok();
                            }
                        }
                        continue;
                    }
                    if let Some(theirs) = backend_mismatch("host-gw", n.pointer(&["metadata", "annotations", BACKEND_KEY]).and_then(Value::as_str)) {
                        self.warn_backend(&meta(n, "name"), "host-gw", theirs);
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
        // Directories of deleted local-path PVs, every 30 s.
        static LAST_STORAGE_GC: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        let t = now_ms();
        if t.saturating_sub(LAST_STORAGE_GC.load(core::sync::atomic::Ordering::Relaxed)) >= 30_000 {
            LAST_STORAGE_GC.store(t, core::sync::atomic::Ordering::Relaxed);
            spec::gc_storage(&self.c).await;
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
        let term = Term { exit_code: e.exit_code, reason, started_at: e.started_at, finished_at: now(), message: e.message };
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
        // Admission: a host port already taken by a pod that was admitted first rejects the pod
        // (the scheduler keeps this from happening unless the pod was bound by hand).
        if self.pods.borrow()[uid].sandbox.is_none() && self.pods.borrow()[uid].ctrs.iter().all(|c| matches!(c.state, CState::Waiting(..))) {
            let pods = self.pods.borrow();
            let mine = &pods[uid].host_ports;
            let clash = !mine.is_empty()
                && pods.iter().any(|(u, p)| {
                    u != uid
                        && p.sandbox.is_some()
                        && p.failed_setup.is_none()
                        && p.evicted.is_none()
                        && p.ctrs.iter().any(|c| !matches!(c.state, CState::Terminated(_)))
                        && p.host_ports.iter().any(|(ip, proto, port)| mine.iter().any(|(i2, p2, port2)| proto == p2 && port == port2 && (ip == i2 || ip.is_empty() || i2.is_empty() || ip == "0.0.0.0" || i2 == "0.0.0.0")))
                });
            drop(pods);
            if clash {
                self.pods.borrow_mut().get_mut(uid).unwrap().failed_setup = Some("Pod was rejected: node(s) didn't have free ports for the requested pod ports".into());
                return;
            }
        }
        if self.pods.borrow()[uid].evicted.is_some() {
            self.kill_now(uid);
            return;
        }
        // activeDeadlineSeconds counts from the pod start and may be changed while running.
        if let Some(secs) = pod.pointer(&["spec", "activeDeadlineSeconds"]).and_then(Value::as_u64) {
            let mut pods = self.pods.borrow_mut();
            let p = pods.get_mut(uid).unwrap();
            let finished = p.ctrs.iter().filter(|c| !c.init && !c.eph).all(|c| matches!(c.state, CState::Terminated(_)));
            p.deadline_exceeded |= !finished && now() - p.start_time >= secs as i64;
        }
        if self.pods.borrow()[uid].deadline_exceeded {
            self.kill_now(uid);
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
            if self.pods.borrow()[uid].ctrs[i].sidecar {
                // Sidecar: the next init container waits for it to start; it restarts whatever its exit.
                if matches!(state, CState::Running { .. }) && self.pods.borrow()[uid].ctrs[i].started {
                    continue;
                }
                if !matches!(state, CState::Running { .. }) {
                    self.maybe_start(uid, pod, i).await;
                }
                return;
            }
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
                        p.ctrs.push(Ctr { name: name.into(), image: e.get("image").and_then(Value::as_str).unwrap_or("").into(), init: false, sidecar: false, eph: true, restart_count: 0, state: CState::Waiting("ContainerCreating", String::new()), last_term: None, signaller: None, not_before: 0, backoff_ms: 0, seq: 0, target: None, probes: Vec::new(), started: false, ready: false });
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
                    sidecar: init && c.get("restartPolicy").and_then(Value::as_str) == Some("Always"),
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
        let prio = pod.pointer(&["spec", "priorityClassName"]).and_then(Value::as_str).unwrap_or("");
        let critical = prio.starts_with("system-") && prio.ends_with("-critical") || pod.pointer(&["metadata", "annotations", "kubernetes.io/config.mirror"]).is_some();
        PodRt { ns: meta(pod, "namespace").into(), name: meta(pod, "name").into(), dir, sandbox: None, lease: None, ip: None, ctrs, start_time: now(), kill_at: None, last_status: String::new(), failed_setup: None, volumes_synced: now_ms(), cg: None, qos: spec::qos_class(pod), mem_request: spec::pod_resources(pod).1, critical, evicted: None, deadline_exceeded: false, conds: Vec::new(), host_ports: host_ports(pod) }
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
        // Pod cgroup: summed limits, the sandbox in its `pause` leaf, containers underneath.
        // Skipped silently without a delegated cgroup.
        let cg = if self.cfg.cgroups {
            let (limits, _) = spec::pod_resources(pod);
            PodCgroup::create(spec::qos_class(pod), uid, &limits).ok().inspect(|cg| {
                let _ = cg.add_sandbox(sb.pid);
            })
        } else {
            None
        };
        spec::write_etc_hosts(&dir, pod, &hostname, ip).map_err(|_| String::from("cannot write /etc/hosts"))?;
        spec::write_resolv_conf(&dir, pod).map_err(|_| String::from("cannot write /etc/resolv.conf"))?;
        let mut pods = self.pods.borrow_mut();
        let p = pods.get_mut(uid).unwrap();
        p.sandbox = Some(sb);
        p.cg = cg;
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
        // Image volumes (`volumes[].image`) need their image pulled first.
        let first = self.pods.borrow()[uid].ctrs[i].seq == 0;
        for vol in pod.pointer(&["spec", "volumes"]).and_then(Value::as_array).unwrap_or(&[]) {
            let Some(iv) = vol.get("image") else { continue };
            let vimage = iv.get("reference").and_then(Value::as_str).unwrap_or("");
            let vpolicy = iv.get("pullPolicy").and_then(Value::as_str).unwrap_or("");
            let vlatest = !vimage.contains(':') || vimage.ends_with(":latest");
            let need = self.store.image(vimage).is_none() || (first && (vpolicy == "Always" || (vpolicy.is_empty() && vlatest)));
            let vkey = spec::pull_key(pod, vimage);
            let vgate = if need && vpolicy != "Never" { self.pull_gate(&vkey, vimage) } else { PullGate::Ready };
            if matches!(vgate, PullGate::Start) {
                let creds = self.pull_creds(pod).await;
                self.start_pull(vkey.clone(), vimage.to_string(), creds);
            }
            if !matches!(vgate, PullGate::Ready) {
                let failed = match self.pulls.borrow().get(&vkey) {
                    Some(Pull::Failed { msg, .. }) => Some(msg.clone()),
                    _ => None,
                };
                match failed {
                    Some(m) => self.set_waiting(uid, i, "ImagePullBackOff", m),
                    None => self.set_waiting(uid, i, "ContainerCreating", alloc::format!("pulling image {vimage}")),
                }
                return;
            }
        }
        let built = match spec::build(&self.c, pod, cspec.unwrap_or(&Value::Null), &img, &pod_dir, pod_ip, &self.cfg.node_name, &self.store).await {
            Ok(b) => b,
            Err(msg) => {
                // A claim that is not bound yet is the pod waiting for its volume, not a config error.
                let reason = if msg.starts_with("persistentvolumeclaim") { "ContainerCreating" } else { "CreateContainerConfigError" };
                self.set_waiting(uid, i, reason, msg);
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
            cgroup_parent: p.cg.as_ref().map_or(&[][..], |c| c.rel()),
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
                        .filter(|_| (!c.init || c.sidecar) && !c.eph)
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
                    let pod_v = pod.clone();
                    kr_rt::exec::spawn(async move {
                        if !probe::run_handler(&hook, &pod_v, &ctr, &target, pod_target.as_ref(), &me.maps, 120_000).await {
                            let _ = sig.send(kr_sys::ns::SIGKILL);
                        }
                    });
                }
                let fallback_logs = cspec.and_then(|c| c.get("terminationMessagePolicy")).and_then(Value::as_str) == Some("FallbackToLogsOnError");
                self.spawn_waiter(uid.to_string(), name, cid, running, started, pod_dir, fallback_logs);
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
        // Another identity is pulling the same image (every e2e namespace is its own key): wait
        // for it rather than download it again; if it fails, this key then pulls on its own.
        let prefix = alloc::format!("{image}\0");
        if pulls.iter().any(|(k, p)| k.starts_with(&prefix) && matches!(p, Pull::InProgress)) {
            return PullGate::Wait;
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

    fn spawn_waiter(self: &Rc<Self>, pod_uid: String, ctr: String, cid: String, running: Running, started_at: i64, pod_dir: String, fallback_logs: bool) {
        let me = self.clone();
        kr_rt::exec::spawn(async move {
            let (exit_code, oom) = match running.wait().await {
                Ok(e) => (e.code, e.oom_killed),
                Err(_) => (128, false),
            };
            let _ = me.maps.run_as_root(|| me.store.delete_container(&cid).is_ok());
            let message = spec::termination_message(&pod_dir, &ctr, fallback_logs, exit_code != 0);
            me.exits.borrow_mut().push(Exit { pod_uid, ctr, exit_code, oom, started_at, message });
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
            let pod_v = pod.clone();
            kr_rt::exec::spawn(async move {
                let ok = probe::run(&spec, &pod_v, &ctr, &target, pod_target.as_ref(), &me.maps, timeout).await;
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
            // Nothing runs here for this pod (never admitted, or already cleaned up):
            // upstream kubelet force-deletes unknown terminating pods, so the object
            // does not linger after the grace period.
            let path = alloc::format!("/api/v1/namespaces/{}/pods/{}?gracePeriodSeconds=0", meta(pod, "namespace"), meta(pod, "name"));
            let _ = self.c.delete(&path).await;
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
                    // Sidecars outlive the app containers (their hooks may need them): see below.
                    if c.sidecar {
                        continue;
                    }
                    let Some(s) = c.signaller.clone() else { continue };
                    let cspec = ["containers", "initContainers"].iter().flat_map(|k| pod.pointer(&["spec", k]).and_then(Value::as_array).unwrap_or(&[]).iter()).find(|cs| cs.get("name").and_then(Value::as_str) == Some(c.name.as_str())).cloned();
                    let hook = cspec.as_ref().and_then(|cs| cs.pointer(&["lifecycle", "preStop"])).cloned();
                    match (hook, c.target.clone()) {
                        // preStop runs first (bounded by the grace period), then SIGTERM.
                        (Some(hook), Some(target)) => {
                            let (ctr, pod_target, maps, pod_v) = (cspec.unwrap_or(Value::Null), pod_target.clone(), self.maps.clone(), pod.clone());
                            kr_rt::exec::spawn(async move {
                                let _ = probe::run_handler(&hook, &pod_v, &ctr, &target, pod_target.as_ref(), &maps, grace * 1000).await;
                                let _ = s.send(kr_sys::ns::SIGTERM);
                            });
                        }
                        _ => {
                            let _ = s.send(kr_sys::ns::SIGTERM);
                        }
                    }
                }
            }
            // Sidecars stop once every other container has.
            if p.ctrs.iter().filter(|c| !c.sidecar).all(|c| c.signaller.is_none()) {
                for c in p.ctrs.iter().filter(|c| c.sidecar) {
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
            // A pod kept by finalizers stays visible: record that nothing runs any more
            // (terminal phase, terminated containers), as upstream's kubelet does.
            self.report_final_status(uid, pod).await;
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
        if let Some(cg) = &p.cg {
            cg.remove();
        }
        if let Some(l) = p.lease {
            l.release();
        }
        let _ = self.maps.run_as_root(|| remove_tree(&p.dir));
    }

    /// Builds the pod status and patches it if it changed.
    async fn report_status(&self, uid: &str, pod: &Value) {
        let (status, path) = {
            let mut pods = self.pods.borrow_mut();
            let Some(p) = pods.get_mut(uid) else { return };
            let policy = pod.pointer(&["spec", "restartPolicy"]).and_then(Value::as_str).unwrap_or("Always");
            let mut status = status_json(p, policy);
            stamp_conditions(p, &mut status, pod.pointer(&["metadata", "generation"]).and_then(Value::as_i64).unwrap_or(0));
            (status, alloc::format!("/api/v1/namespaces/{}/pods/{}/status", p.ns, p.name))
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


impl<C: Client + Clone + 'static> Kubelet<C> {
    /// Status for a pod whose containers have all stopped after deletion: `Succeeded` if every
    /// regular container exited 0, else `Failed`; not ready.
    async fn report_final_status(&self, uid: &str, pod: &Value) {
        let (mut status, path) = {
            let pods = self.pods.borrow();
            let Some(p) = pods.get(uid) else { return };
            let policy = pod.pointer(&["spec", "restartPolicy"]).and_then(Value::as_str).unwrap_or("Always");
            (status_json(p, policy), alloc::format!("/api/v1/namespaces/{}/pods/{}/status", p.ns, p.name))
        };
        let ok = self.pods.borrow().get(uid).is_some_and(|p| p.ctrs.iter().filter(|c| !c.init).all(|c| matches!(&c.state, CState::Terminated(t) if t.exit_code == 0)));
        if let Value::Object(f) = &mut status {
            f.retain(|(k, _)| k != "phase");
            f.push((String::from("phase"), Value::from(if ok { "Succeeded" } else { "Failed" })));
            f.push((String::from("qosClass"), Value::from(spec::qos_class(pod))));
            for (k, v) in f.iter_mut() {
                if k == "conditions" {
                    for c in v.as_array_mut().into_iter().flatten() {
                        if matches!(c.get("type").and_then(Value::as_str), Some("Ready" | "ContainersReady")) {
                            c.set("status", Value::from("False"));
                        }
                    }
                }
            }
        }
        let patch = Value::Object(alloc::vec![(String::from("status"), status)]);
        let _ = self.c.patch(&path, "application/merge-patch+json", &patch).await;
    }
}

/// Gives each condition the time its status last changed and stamps `observedGeneration` (the
/// pod's `metadata.generation` this status was computed for) on the status and its conditions.
fn stamp_conditions(p: &mut PodRt, status: &mut Value, generation: i64) {
    let gen = Value::Number(Number::from_i64(generation));
    let Some(Value::Array(conds)) = status.get_mut("conditions") else { return };
    for c in conds.iter_mut() {
        let ty = c.get("type").and_then(Value::as_str).unwrap_or("").to_string();
        let ok = c.get("status").and_then(Value::as_str) == Some("True");
        let at = match p.conds.iter_mut().find(|(t, _, _)| *t == ty) {
            Some(e) => {
                if e.1 != ok {
                    *e = (ty, ok, now());
                }
                e.2
            }
            None => {
                p.conds.push((ty, ok, p.start_time));
                p.start_time
            }
        };
        c.set("lastTransitionTime", Value::String(rfc3339(at)));
        c.set("observedGeneration", gen.clone());
    }
    status.set("observedGeneration", gen);
}

fn status_json(p: &PodRt, policy: &str) -> Value {
    let t = |s: i64| Value::String(rfc3339(s));
    let o = |f: Vec<(&str, Value)>| Value::Object(f.into_iter().map(|(k, v)| (k.into(), v)).collect());
    let state_json = |s: &CState| -> Value {
        match s {
            CState::Waiting(r, m) => o(alloc::vec![("waiting", o(alloc::vec![("reason", Value::from(*r)), ("message", Value::from(m.as_str()))]))]),
            CState::Running { started_at, .. } => o(alloc::vec![("running", o(alloc::vec![("startedAt", t(*started_at))]))]),
            CState::Terminated(tm) => {
                let mut f = alloc::vec![("exitCode", Value::Number(Number::from_i64(tm.exit_code as i64))), ("reason", Value::from(tm.reason)), ("startedAt", t(tm.started_at)), ("finishedAt", t(tm.finished_at))];
                if !tm.message.is_empty() {
                    f.push(("message", Value::from(tm.message.as_str())));
                }
                o(alloc::vec![("terminated", o(f))])
            }
        }
    };
    let init_ok = |c: &Ctr| if c.sidecar { matches!(c.state, CState::Running { .. }) && c.started } else { matches!(&c.state, CState::Terminated(t) if t.exit_code == 0) };
    let inits_done = p.ctrs.iter().filter(|c| c.init).all(init_ok);
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
            ("ready", Value::Bool(if c.sidecar { ready } else if c.init { init_ok(c) } else { ready && !c.eph })),
            ("started", Value::Bool(running && c.started)),
            ("restartCount", Value::Number(Number::from_u64(c.restart_count as u64))),
            ("state", match &c.state {
                CState::Waiting("ContainerCreating", m) if !c.init && !c.eph && !inits_done => state_json(&CState::Waiting("PodInitializing", m.clone())),
                // Init containers queued behind one that has not completed yet.
                CState::Waiting("ContainerCreating", m) if c.init && p.ctrs.iter().take_while(|o| !core::ptr::eq(*o, c)).any(|o| o.init && !matches!(&o.state, CState::Terminated(t) if t.exit_code == 0)) => {
                    state_json(&CState::Waiting("PodInitializing", m.clone()))
                }
                s => state_json(s),
            }),
        ];
        f.push(("lastState", c.last_term.as_ref().filter(|_| !matches!(c.state, CState::Terminated(_))).map(|tm| state_json(&CState::Terminated(tm.clone()))).unwrap_or(o(Vec::new()))));
        o(f)
    };
    let apps: Vec<&Ctr> = p.ctrs.iter().filter(|c| !c.init && !c.eph).collect();
    let all_running = !apps.is_empty() && apps.iter().all(|c| matches!(c.state, CState::Running { .. }) && c.started && c.ready);
    let all_done = !apps.is_empty() && apps.iter().all(|c| matches!(c.state, CState::Terminated(_)));
    let failed = apps.iter().any(|c| matches!(&c.state, CState::Terminated(t) if t.exit_code != 0)) || p.ctrs.iter().any(|c| c.init && !c.sidecar && matches!(&c.state, CState::Terminated(t) if t.exit_code != 0) && policy == "Never");
    let phase = if p.failed_setup.is_some() || p.evicted.is_some() || p.deadline_exceeded {
        "Failed"
    } else if all_done && policy != "Always" && (policy == "Never" || !failed) {
        if failed { "Failed" } else { "Succeeded" }
    } else if failed && policy == "Never" && apps.iter().all(|c| !matches!(c.state, CState::Running { .. })) && p.ctrs.iter().any(|c| c.init && !c.sidecar && matches!(&c.state, CState::Terminated(t) if t.exit_code != 0)) {
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
    let incomplete: Vec<&str> = p.ctrs.iter().filter(|c| c.init && !init_ok(c)).map(|c| c.name.as_str()).collect();
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
    if let Some(msg) = &p.evicted {
        f.push(("message", Value::from(msg.as_str())));
        f.push(("reason", Value::from("Evicted")));
    }
    if p.deadline_exceeded {
        f.push(("message", Value::from("Pod was active on the node longer than the specified deadline")));
        f.push(("reason", Value::from("DeadlineExceeded")));
    }
    if let Some(msg) = &p.failed_setup {
        f.push(("message", Value::from(msg.as_str())));
        f.push(("reason", Value::from(if msg.starts_with("Pod was rejected") { "HostPortConflict" } else { "SandboxFailed" })));
    }
    o(f)
}
/// (hostIP, protocol, hostPort) of every container port that asks for a host port.
fn host_ports(pod: &Value) -> Vec<(String, String, u64)> {
    let mut out = Vec::new();
    for key in ["initContainers", "containers"] {
        for c in pod.pointer(&["spec", key]).and_then(Value::as_array).unwrap_or(&[]) {
            for p in c.get("ports").and_then(Value::as_array).unwrap_or(&[]) {
                let hp = p.get("hostPort").and_then(Value::as_u64).unwrap_or(0);
                if hp > 0 {
                    let proto = p.get("protocol").and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or("TCP");
                    out.push((p.get("hostIP").and_then(Value::as_str).unwrap_or("").to_string(), proto.to_string(), hp));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod status_tests {
    use super::*;
    use alloc::vec;

    fn ctr(name: &str, init: bool, eph: bool, state: CState) -> Ctr {
        Ctr { name: name.into(), image: "img".into(), init, sidecar: false, eph, restart_count: 0, state, last_term: None, signaller: None, not_before: 0, backoff_ms: 0, seq: 0, target: None, probes: Vec::new(), started: true, ready: true }
    }
    fn done(code: i32) -> CState {
        CState::Terminated(Term { exit_code: code, reason: if code == 0 { "Completed" } else { "Error" }, started_at: 1, finished_at: 2, message: String::new() })
    }
    fn run() -> CState {
        CState::Running { started_at: 1, id: "x".into() }
    }
    fn creating() -> CState {
        CState::Waiting("ContainerCreating", String::new())
    }
    fn pod(ctrs: Vec<Ctr>) -> PodRt {
        PodRt { ns: "d".into(), name: "p".into(), dir: String::new(), sandbox: None, lease: None, ip: None, ctrs, start_time: 0, kill_at: None, last_status: String::new(), failed_setup: None, volumes_synced: 0, cg: None, qos: "BestEffort", mem_request: 0, critical: false, evicted: None, deadline_exceeded: false, conds: Vec::new(), host_ports: Vec::new() }
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
        // Queued behind init1; init1 itself is the one being created.
        assert_eq!(s(&st, &["initContainerStatuses", "1", "state", "waiting", "reason"]), Some("PodInitializing"));
        let st = status_json(&pod(vec![ctr("init1", true, false, creating()), ctr("init2", true, false, creating())]), "Always");
        assert_eq!(s(&st, &["initContainerStatuses", "0", "state", "waiting", "reason"]), Some("ContainerCreating"));
    }

    #[test]
    fn condition_times_and_generation() {
        let mut p = pod(vec![ctr("run1", false, false, creating())]);
        p.start_time = 100;
        p.ctrs[0].ready = false;
        let mut st = status_json(&p, "Always");
        stamp_conditions(&mut p, &mut st, 3);
        assert_eq!(s(cond(&st, "Ready"), &["lastTransitionTime"]), Some(rfc3339(100).as_str()));
        assert_eq!(at(&st, &["observedGeneration"]).and_then(Value::as_i64), Some(3));
        assert_eq!(at(cond(&st, "Ready"), &["observedGeneration"]).and_then(Value::as_i64), Some(3));
        p.ctrs[0].state = run();
        p.ctrs[0].ready = true;
        let mut st = status_json(&p, "Always");
        stamp_conditions(&mut p, &mut st, 4);
        assert_eq!(s(cond(&st, "Ready"), &["status"]), Some("True"));
        assert_ne!(s(cond(&st, "Ready"), &["lastTransitionTime"]), Some(rfc3339(100).as_str()));
        assert_eq!(s(cond(&st, "PodScheduled"), &["lastTransitionTime"]), Some(rfc3339(100).as_str()));
        assert_eq!(at(cond(&st, "Ready"), &["observedGeneration"]).and_then(Value::as_i64), Some(4));
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
        i.last_term = Some(Term { exit_code: 1, reason: "Error", started_at: 1, finished_at: 2, message: String::new() });
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

const VXLAN_DEV: &str = "kr.vxlan";
const VTEP_MAC_KEY: &str = "kr.io/vtep-mac";
const VTEP_IP_KEY: &str = "kr.io/vtep-ip";
const BACKEND_KEY: &str = "kr.io/net-backend";

/// The peer's backend when it differs from ours. A peer without the annotation (older kr,
/// or not registered its backend yet) is not a mismatch: VXLAN still needs its VTEP annotations.
/// host-gw routes to a VXLAN peer cannot work (and the reverse), so mismatched peers are skipped.
fn backend_mismatch<'a>(mine: &str, theirs: Option<&'a str>) -> Option<&'a str> {
    theirs.filter(|t| *t != mine)
}

fn fmt_ip(ip: [u8; 4]) -> String {
    alloc::format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

/// MTU of the interface carrying the default route (1500 when unknown).
fn uplink_mtu() -> u32 {
    let route = kr_sys::fs::read_file(b"/proc/net/route\0", 1 << 16).ok().and_then(|b| String::from_utf8(b).ok()).unwrap_or_default();
    let dev = route.lines().skip(1).find_map(|l| {
        let mut f = l.split_whitespace();
        let (dev, dst) = (f.next()?, f.next()?);
        (dst == "00000000").then(|| dev.to_string())
    });
    dev.and_then(|d| kr_sys::fs::read_file(alloc::format!("/sys/class/net/{d}/mtu\0").as_bytes(), 64).ok())
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(1500)
}

/// Generic reconcile diff: (wanted but missing, present but unwanted).
fn set_diff<T: PartialEq + Copy>(want: &[T], have: &[T]) -> (Vec<T>, Vec<T>) {
    (want.iter().filter(|w| !have.contains(w)).copied().collect(), have.iter().filter(|h| !want.contains(h)).copied().collect())
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
    use super::{backend_mismatch, route_diff, set_diff};

    #[test]
    fn backend_mismatch_detected() {
        assert_eq!(backend_mismatch("vxlan", Some("vxlan")), None);
        assert_eq!(backend_mismatch("vxlan", None), None);
        assert_eq!(backend_mismatch("vxlan", Some("host-gw")), Some("host-gw"));
        assert_eq!(backend_mismatch("host-gw", Some("vxlan")), Some("vxlan"));
    }

    #[test]
    fn set_diff_neigh_and_fdb() {
        let (a, b) = ([10, 88, 1, 0], [10, 88, 2, 0]);
        let (m1, m2) = ([2, 0x4b, 1, 1, 1, 1], [2, 0x4b, 2, 2, 2, 2]);
        let (add, del) = set_diff(&[(a, m1), (b, m2)], &[(a, m1), ([10, 88, 9, 0], m2)]);
        assert_eq!((add, del), (alloc::vec![(b, m2)], alloc::vec![([10, 88, 9, 0], m2)]));
        // changed MAC: old entry removed, new added
        let (add, del) = set_diff(&[(a, m2)], &[(a, m1)]);
        assert_eq!((add.len(), del.len()), (1, 1));
        // FDB: peer IP changed
        let (add, del) = set_diff(&[(m1, [192, 168, 0, 9])], &[(m1, [192, 168, 0, 2])]);
        assert_eq!((add.len(), del.len()), (1, 1));
    }

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
