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
pub mod imagegc;
pub mod node;
mod adopt;
pub mod cni;
mod csi;
pub mod deviceplugin;
pub mod podresources;
pub mod dns;
pub mod nodecfg;
pub mod egress;
pub mod netpol;
mod probe;
pub mod proxy;
pub mod svcnft;
pub mod remote;
mod spec;
pub mod stats;
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

/// The cluster DNS domain: `KR_CLUSTER_DOMAIN` (set the same on the server and every agent),
/// default `cluster.local`.
pub fn cluster_domain() -> String {
    kr_runtime::store::env_var("KR_CLUSTER_DOMAIN")
        .filter(|d| !d.is_empty() && d.split('.').all(|l| !l.is_empty() && l.len() < 64 && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')))
        .unwrap_or_else(|| String::from("cluster.local"))
}

pub struct Config {
    pub node_name: String,
    /// Root of kubelet state (`<root>/pods/<uid>/...`); usually the image store root.
    pub root: String,
    /// Bridge networking and pod IPs (requires real root).
    pub network: bool,
    /// cgroup limits are applied only when kr runs in a delegated cgroup.
    pub cgroups: bool,
    /// The node's InternalIP (reported in Node status; peers route pod subnets to it).
    pub node_ip: [u8; 16],
    /// Pod network backend: VXLAN overlay (true) or host-gw routes (false, needs one L2 segment).
    pub vxlan: bool,
    /// WireGuard backend (`KR_NET_BACKEND=wireguard`, ADR-062); `vxlan` is false then.
    pub wireguard: bool,
    /// Hard eviction: MemAvailable (bytes) below which the node is under memory pressure.
    pub eviction_memory_bytes: u64,
    /// The node also runs the control plane (`kr server`): it gets the control-plane role label.
    pub control_plane: bool,
    /// `--node-label`: applied at registration (see [`nodecfg`]).
    pub labels: Vec<(String, String)>,
    /// `--node-taint`.
    pub taints: Vec<nodecfg::Taint>,
    /// `--node-external-ip`: reported as an ExternalIP address.
    pub external_ip: Option<[u8; 16]>,
    /// Components turned off with `--disable` (only `coredns` matters here; ADR-060).
    pub disabled: kr_apiserver::components::Disabled,
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
/// The stdin socket / pty master a shim hands out on its unix socket.
fn fetch_io_fd(sock: &[u8]) -> Option<kr_sys::Fd> {
    let conn = kr_sys::ns::unix_connect(sock).ok()?;
    // The shim answers at once; do not let a stuck one stall the kubelet.
    let _ = kr_sys::ns::poll2(conn.raw(), -1, 2000);
    let mut b = [0u8; 1];
    kr_sys::ns::recv_fd(conn.raw(), &mut b).ok()?.1
}

fn is_pod_uid(owner: &[u8]) -> bool {
    owner.len() == 36 && owner.iter().filter(|b| **b == b'-').count() == 4
}

/// Logs a pod sync step that took 40 ms or more (the step and the pod), then restarts the lap.
fn slow_step(step: &str, pod: &Value, lap: &mut u64) {
    let t = now_ms();
    if t.saturating_sub(*lap) >= 40 {
        kr_rt::eprint(alloc::format!("kubelet: slow {step} {}ms for pod {}/{}\n", t - *lap, meta(pod, "namespace"), meta(pod, "name")).as_bytes());
    }
    *lap = t;
}

fn now_ms() -> u64 {
    kr_rt::exec::now_ms()
}

/// Wakes the sync loop.
#[derive(Default)]
pub(crate) struct Notify {
    flag: Cell<bool>,
    waker: RefCell<Option<Waker>>,
}

impl Notify {
    pub(crate) fn notify(&self) {
        self.flag.set(true);
        if let Some(w) = self.waker.borrow_mut().take() {
            w.wake();
        }
    }

    pub(crate) async fn wait(&self, max_ms: u64) {
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
    /// The container's `resources` as last applied (JSON; "" when unset): reported in the status,
    /// and compared with the spec to resize a running container in place.
    res: String,
    /// Being restarted because a resource with `resizePolicy: RestartContainer` changed.
    resize_restart: bool,
    /// When the restart for a resize escalates from SIGTERM to SIGKILL (ms).
    resize_kill_at: u64,
    /// Host pid and start ticks of the running container's init (see [`adopt`]).
    proc: Option<(i32, u64)>,
    /// The shim process holding this container's stdin socket / pty master: (shim pid, its fd, tty).
    io: Option<(i32, i32, bool)>,
    shim: i32,
}

struct PodRt {
    ns: String,
    name: String,
    dir: String,
    sandbox: Option<Sandbox>,
    lease: Option<Lease>,
    ip: Option<[u8; 4]>,
    /// IPv6 twin of `ip` (dual-stack pod network), when the pod got one.
    ip6: Option<[u8; 16]>,
    /// The node's InternalIP: status.hostIP, and the pod IP of hostNetwork pods.
    node_ip: [u8; 16],
    ctrs: Vec<Ctr>,
    start_time: i64,
    /// Kill deadline (ms) once termination started.
    kill_at: Option<u64>,
    /// When the final status of a terminating pod was reported. The API object is removed a little
    /// later (upstream: after the status manager has pushed the status), so clients can observe
    /// the terminated pod.
    stopped_at: Option<u64>,
    last_status: String,
    failed_setup: Option<String>,
    /// Last refresh of configMap/secret/projected volumes (ms).
    volumes_synced: u64,
    /// Pod-level cgroup (None when cgroups are unavailable).
    cg: Option<PodCgroup>,
    qos: &'static str,
    /// Summed memory requests (plus overhead), the eviction baseline.
    mem_request: u64,
    /// Summed CPU request (millicores), for resize feasibility.
    cpu_request: u64,
    /// `PodResizePending`: why the last resize was not applied (`Infeasible` / `Deferred`) and the message.
    resize_pending: Option<(&'static str, String)>,
    /// system-node-critical / system-cluster-critical or a static pod: never evicted.
    critical: bool,
    /// Set once evicted for memory pressure: containers are killed and never restarted.
    evicted: Option<String>,
    /// (hostIP, protocol, hostPort) of the containers' host ports.
    host_ports: Vec<(String, String, u64)>,
    /// Earliest next attempt (ms) after a failed sandbox setup.
    sandbox_retry_at: u64,
    /// Set once `activeDeadlineSeconds` passed: containers are killed and the pod is Failed.
    deadline_exceeded: bool,
    /// Last reported status and transition time (s) of each pod condition.
    conds: Vec<(String, bool, i64)>,
    /// PVC volumes as (volume, claim, host directory), for volume statistics; None until looked up.
    pvcs: Option<Vec<(String, String, String)>>,
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
    /// Pods whose first sync (sandbox + CNI, ~0.5 s each) runs as its own task.
    starting: RefCell<alloc::collections::BTreeSet<String>>,
    notify: Notify,
    devices: Rc<deviceplugin::Plugins>,
    csi: Rc<csi::Csi>,
    /// CSI volume numbers from the last `volume_stats_loop` pass (publish path -> stats), and the
    /// volumes already reported abnormal.
    vol_cache: RefCell<BTreeMap<String, csi::VolumeStats>>,
    vol_abnormal: RefCell<alloc::collections::BTreeSet<String>>,
    /// Image pulls in flight or recently failed (image ref -> state).
    pulls: RefCell<BTreeMap<String, Pull>>,
    /// Images pulled successfully by this kubelet (pullPolicy Always / :latest satisfied).
    done_pulls: RefCell<Vec<String>>,
    /// Rootless pod network: a namespace pair owned by kr holding the bridge; pod sandboxes
    /// are nested inside it so pods get IPs and reach each other without real root.
    infra: RefCell<Option<Sandbox>>,
    /// This node's pod subnet (from `spec.podCIDR`).
    podnet: Cell<network::PodNet>,
    /// Address families of the pod network (from `spec.podCIDRs`).
    fam: Cell<network::Families>,
    /// The changed-families warning was logged.
    warned_families: Cell<bool>,
    /// Peer/backend pairs already reported as a backend mismatch.
    warned_backend: RefCell<alloc::collections::BTreeSet<String>>,
    /// Container log path -> `(file size, sec, nsec)` samples: the log file keeps no per-line
    /// times, so `since*` and `timestamps` of `kubectl logs` use when the size was last seen grow.
    log_marks: RefCell<BTreeMap<String, Vec<(u64, i64, i64)>>>,
    /// Our end of the stdin socket of containers with `stdin: true`, keyed `<pod dir>/<name>`, and
    /// whether `stdinOnce` applies and whether it is a terminal master (`tty: true`). `attach -i`
    /// writes to it; shutting a socket down is EOF.
    stdin_keep: RefCell<BTreeMap<String, (Rc<kr_sys::Fd>, bool, bool)>>,
    /// Pods and containers taken over from the previous run (reported once, after the first sync).
    adopted: Cell<(u32, u32)>,
    /// Shims and re-adoption are available (kernel prerequisites met).
    survive: Cell<bool>,
    /// NetworkPolicy controller state (ADR-049): pods announce their IP before their containers start.
    netpol: Rc<netpol::Ctl>,
    /// Probe results by (namespace, pod, container, probe type, success), for `/metrics/probes`.
    probe_counts: RefCell<BTreeMap<(String, String, String, &'static str, bool), u64>>,
    started_s: i64,
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

/// Prefix of the sandbox error that means "try again later" (the pod network is full).
const NO_IP: &str = "failed to allocate a pod IP";
const BACKOFF_START_MS: u64 = 10_000;
const BACKOFF_MAX_MS: u64 = 300_000;

/// Pods whose sandbox may be started at the same time.
const MAX_STARTING: usize = 4;

impl<C: Client + Clone + 'static> Kubelet<C> {
    pub fn new(c: C, cfg: Config, store: Store) -> Rc<Self> {
        let devices = deviceplugin::Plugins::new(&deviceplugin::default_dir(&cfg.root));
        let csi = csi::Csi::new(&cfg.node_name);
        Rc::new(Kubelet { c, cfg, store, maps: IdMaps::for_current_user(), pods: RefCell::new(BTreeMap::new()), exits: RefCell::new(Vec::new()), starting: RefCell::new(alloc::collections::BTreeSet::new()), notify: Notify::default(), devices, csi, vol_cache: RefCell::new(BTreeMap::new()), vol_abnormal: RefCell::new(alloc::collections::BTreeSet::new()), pulls: RefCell::new(BTreeMap::new()), done_pulls: RefCell::new(Vec::new()), infra: RefCell::new(None), podnet: Cell::new(network::PodNet::default()), fam: Cell::new(network::Families::DUAL), warned_families: Cell::new(false), warned_backend: RefCell::new(alloc::collections::BTreeSet::new()), log_marks: RefCell::new(BTreeMap::new()), stdin_keep: RefCell::new(BTreeMap::new()), adopted: Cell::new((0, 0)), survive: Cell::new(false), netpol: Rc::new(netpol::Ctl::default()), probe_counts: RefCell::new(BTreeMap::new()), started_s: now_ms() as i64 / 1000 })
    }

    /// Runs registration, heartbeats, the pod watch and the sync loop (never returns).
    pub async fn run(self: Rc<Self>) {
        if self.cfg.vxlan && self.cfg.network {
            // Before any sandbox: pod interfaces get the tunnel MTU (uplink - VXLAN overhead).
            network::set_pod_mtu(uplink_mtu().saturating_sub(50));
        }
        if self.cfg.wireguard && self.cfg.network {
            network::set_pod_mtu(self.wg_mtu());
        }
        // Sandboxes die with the previous kr process (even after SIGKILL), so every pod lease is
        // stale. Leases of `kr ctr run` processes are kept while that process runs.
        // Containers of a killed kr survive as orphans: kill whatever is left in the pod cgroups.
        // One kubelet per root: two would adopt the same pods. The lock goes with the process.
        let lock = alloc::format!("{}/kubelet.lock\0", self.cfg.root);
        match kr_sys::ns::open(lock.as_bytes(), kr_sys::ns::O_RDWR | kr_sys::ns::O_CREAT | kr_sys::O_CLOEXEC, 0o600) {
            Ok(fd) => {
                if kr_sys::ns::flock_exclusive_nb(fd.raw()).is_err() {
                    kr_rt::eprint(alloc::format!("kubelet: another kr process already runs the pods under {}; exiting\n", self.cfg.root).as_bytes());
                    kr_sys::exit_group(1);
                }
                core::mem::forget(fd);
            }
            Err(_) => kr_rt::eprint(b"kubelet: cannot create the kubelet lock; continuing without\n"),
        }
        // Pods outlive this process and are re-adopted when their pod is seen again; what nobody
        // claims is cleaned up after the first sync.
        match container::survive_prerequisites() {
            Ok(()) => {
                container::set_survive_parent(true);
                self.survive.set(true);
            }
            Err(missing) => kr_rt::eprint(alloc::format!("kubelet: this kernel lacks {missing}; pods will not survive a restart of kr\n").as_bytes()),
        }
        if self.devices.start() {
            kr_rt::eprint(alloc::format!("kubelet: device plugins register on {}/kubelet.sock\n", self.devices.dir()).as_bytes());
            let me = self.clone();
            podresources::start(&self.devices, Rc::new(move || me.pods.borrow().iter().map(|(uid, p)| podresources::PodInfo { uid: uid.clone(), ns: p.ns.clone(), name: p.name.clone(), ctrs: p.ctrs.iter().filter(|c| !c.eph).map(|c| c.name.clone()).collect() }).collect()));
        }
        if let Some(d) = self.csi.dir() {
            kr_rt::eprint(alloc::format!("kubelet: CSI drivers register on {d}/plugins_registry\n").as_bytes());
            let (csi, c) = (self.csi.clone(), self.c.clone());
            kr_rt::exec::spawn(async move { csi.run(c).await });
        }
        node::register(&self.c, &self.cfg, &self.devices).await;
        // The API server assigns the pod subnet at registration.
        for _ in 0..30 {
            if let Ok(n) = self.c.get(&alloc::format!("/api/v1/nodes/{}", self.cfg.node_name)).await {
                if let Some((pn, fam)) = node_podnet(&n) {
                    self.podnet.set(pn);
                    self.fam.set(fam);
                    break;
                }
            }
            kr_rt::exec::sleep(1000).await;
        }
        let pn = self.podnet.get();
        if self.cfg.network {
            kr_rt::exec::phase("run: setup_host");
            if let Err(e) = network::setup_host_with(&pn, self.fam.get()) {
                kr_rt::eprint(alloc::format!("kubelet: network setup failed (errno {}); pods get no IP\n", e.0).as_bytes());
            }
        } else {
            kr_rt::exec::phase("run: rootless network");
            if let Some(infra) = self.adopt_infra() {
                *self.infra.borrow_mut() = Some(infra);
                self.announce_rootless().await;
            } else {
                // The old pod network is gone (or never existed): pods that used it cannot live on.
                self.kill_recorded(&[]);
                match container::start_sandbox(b"kr-pod-network", b"", &self.maps, None, true) {
                    Ok(infra) => {
                        // ip_forward + bridge inside the infra namespaces; egress is set up
                        // separately and optional.
                        let fam = self.fam.get();
                        let ok = container::run_in_net(&infra, || network::setup_infra_bridge(&pn, fam));
                        match ok {
                            Ok(0) => {
                                // Outbound traffic: a TUN default route served by the userspace NAT,
                                // in a helper process that survives this one.
                                let mut egress = None;
                                let (ipid, ist) = (alloc::format!("{}", infra.pid), network::proc_start(infra.pid as u32).map(|s| alloc::format!("{s}")).unwrap_or_default());
                                match network::open_egress(&infra) {
                                    Ok(tun) => match container::spawn_helper(&[b"egress", ipid.as_bytes(), ist.as_bytes()], tun.raw()) {
                                        Ok(pid) => egress = network::proc_start(pid as u32).map(|st| (pid, st)),
                                        Err(e) => kr_rt::eprint(alloc::format!("kubelet: rootless egress unavailable ({}: errno {}); pods have no outbound connectivity\n", e.step, e.errno.0).as_bytes()),
                                    },
                                    Err(e) => kr_rt::eprint(alloc::format!("kubelet: rootless egress unavailable (errno {}); pods have no outbound connectivity\n", e.0).as_bytes()),
                                }
                                if let (Some((ep, es)), Some(st)) = (egress, network::proc_start(infra.pid as u32)) {
                                    let _ = kr_runtime::store::write_file_atomic(&self.infra_file(), alloc::format!("{} {st} {ep} {es}\n", infra.pid).as_bytes());
                                }
                                *self.infra.borrow_mut() = Some(infra);
                                self.announce_rootless().await;
                            }
                            r => {
                                kr_rt::eprint(alloc::format!("kubelet: rootless pod network setup failed ({}); pods get no IP\n", r.map(|c| c.to_string()).unwrap_or_else(|e| alloc::format!("{}: errno {}", e.step, e.errno.0))).as_bytes());
                                infra.stop();
                            }
                        }
                    }
                    Err(e) => kr_rt::eprint(alloc::format!("kubelet: rootless pod network unavailable ({}: errno {})\n", e.step, e.errno.0).as_bytes()),
                }
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
                if !self.cfg.disabled.coredns {
                    kr_rt::exec::spawn(dns::run(self.c.clone(), net, self.fam.get()));
                }
            }
            None => kr_rt::eprint(b"kubelet: no node network; Services are not proxied\n"),
        }
        if self.cfg.network {
            let me = self.clone();
            kr_rt::exec::spawn(async move { me.route_loop().await });
            kr_rt::exec::spawn(netpol::run(self.c.clone(), self.cfg.node_name.clone(), self.netpol.clone()));
        }
        let hb = self.clone();
        kr_rt::exec::spawn(async move { node::heartbeat_loop(&hb.c, &hb.cfg, &hb.devices).await });
        let w = self.clone();
        kr_rt::exec::spawn(async move { w.watch_loop().await });
        let ev = self.clone();
        kr_rt::exec::spawn(async move { ev.eviction_loop().await });
        let lm = self.clone();
        kr_rt::exec::spawn(async move { lm.log_mark_loop().await });
        let vs = self.clone();
        kr_rt::exec::spawn(async move { vs.volume_stats_loop().await });
        let gc = self.clone();
        kr_rt::exec::spawn(async move { gc.image_gc_loop().await });
        let mut swept = false;
        loop {
            let listed = self.sync_all().await;
            if listed && !swept {
                swept = true;
                self.sweep_unclaimed().await;
            }
            self.notify.wait(1000).await;
        }
    }

    /// After the first sync: kills the pods nobody adopted (deleted while the kubelet was down)
    /// and frees their IPs.
    async fn sweep_unclaimed(&self) {
        kr_rt::exec::phase("sweep: devices");
        let live: Vec<String> = self.pods.borrow().keys().cloned().collect();
        self.devices.retain_pods(&live);
        for u in self.csi.pod_uids().into_iter().filter(|u| !live.contains(u)) {
            let csi = self.csi.clone();
            kr_rt::exec::spawn(async move { csi.unmount_pod(&u).await });
        }
        kr_rt::exec::yield_if_long(5).await;
        kr_rt::exec::phase("sweep: cgroups");
        if self.cfg.cgroups {
            kr_runtime::cgroup::kill_stale_pods(&|c| live.iter().any(|u| u.as_bytes() == c));
            kr_runtime::cgroup::prune_previous_base(&alloc::format!("{}/cgroup-base", self.cfg.root));
        }
        kr_rt::exec::yield_if_long(5).await;
        kr_rt::exec::phase("sweep: kill_recorded");
        self.kill_recorded(&live);
        kr_rt::exec::yield_if_long(5).await;
        kr_rt::exec::phase("sweep: remove_unclaimed_dirs");
        self.remove_unclaimed_dirs(&live).await;
        kr_rt::exec::yield_if_long(5).await;
        kr_rt::exec::phase("sweep: ipam gc");
        let (pods, ctrs) = self.adopted.get();
        kr_rt::eprint(alloc::format!("kubelet: adopted {pods} pods ({ctrs} running containers) left by the previous run\n").as_bytes());
        network::gc(alloc::format!("{}/ipam", self.cfg.root).as_bytes(), |owner| if is_pod_uid(owner) { live.iter().any(|u| u.as_bytes() == owner) } else { network::owner_alive(owner) != Some(false) });
    }

    /// Removes the pod directories and container directories (overlay layers) of pods that are
    /// gone from the API, left by a run that ended before it could clean up.
    async fn remove_unclaimed_dirs(&self, live: &[String]) {
        let list = |sub: &str| -> Vec<String> {
            let dir = alloc::format!("{}/{sub}\0", self.cfg.root);
            let Ok(fd) = kr_sys::ns::open(dir.as_bytes(), kr_sys::ns::O_RDONLY | kr_sys::ns::O_DIRECTORY, 0) else { return Vec::new() };
            kr_sys::fs::read_dir(&fd).filter_map(Result::ok).filter_map(|e| String::from_utf8(e.name).ok()).collect()
        };
        for name in list("pods") {
            if is_pod_uid(name.as_bytes()) && !live.contains(&name) {
                let dir = alloc::format!("{}/pods/{name}", self.cfg.root);
                let _ = self.maps.run_as_root(|| remove_tree(&dir));
                kr_rt::exec::yield_if_long(5).await; // a pod directory can hold a whole rootfs
            }
        }
        // Container ids are `<pod uid>-<container>-<n>`.
        for name in list("containers") {
            let uid = name.get(..36).unwrap_or("");
            if name.len() > 37 && name.as_bytes()[36] == b'-' && is_pod_uid(uid.as_bytes()) && !live.iter().any(|l| l == uid) {
                let _ = self.maps.run_as_root(|| self.store.delete_container(&name).is_ok());
                kr_rt::exec::yield_if_long(5).await;
            }
        }
    }

    /// Kills the sandbox and containers recorded in the `.adopt` file of every pod directory
    /// whose uid is not in `keep` (what cgroups cannot reach: rootless, or no cgroups), and
    /// forgets the record.
    fn kill_recorded(&self, keep: &[String]) {
        let dir = alloc::format!("{}/pods\0", self.cfg.root);
        let Ok(fd) = kr_sys::ns::open(dir.as_bytes(), kr_sys::ns::O_RDONLY | kr_sys::ns::O_DIRECTORY, 0) else { return };
        let names: Vec<String> = kr_sys::fs::read_dir(&fd).filter_map(Result::ok).filter_map(|e| String::from_utf8(e.name).ok()).filter(|n| is_pod_uid(n.as_bytes()) && !keep.contains(n)).collect();
        for uid in names {
            let path = alloc::format!("{}/pods/{uid}/{}\0", self.cfg.root, adopt::FILE);
            let Ok(raw) = kr_sys::fs::read_file(path.as_bytes(), 1 << 16) else { continue };
            let _ = kr_sys::fs::unlinkat(kr_sys::ns::AT_FDCWD, path.as_bytes(), 0);
            let Some((sb, ctrs)) = core::str::from_utf8(&raw).ok().and_then(adopt::decode) else { continue };
            let kill = |pid: i32, start: u64| {
                if network::proc_start(pid as u32) == Some(start) {
                    let _ = kr_sys::ns::kill(pid, kr_sys::ns::SIGKILL);
                }
            };
            for c in &ctrs {
                kill(c.pid, c.start);
            }
            kill(sb.pid, sb.start);
        }
    }

    /// Where the rootless infra namespace holder and the egress helper are recorded.
    fn infra_file(&self) -> String {
        alloc::format!("{}/infra.adopt", self.cfg.root)
    }

    /// The rootless pod network of the previous run, if its holder and egress helper still live.
    fn adopt_infra(&self) -> Option<Sandbox> {
        let text = kr_sys::fs::read_file(alloc::format!("{}\0", self.infra_file()).as_bytes(), 256).ok()?;
        let f: Vec<u64> = core::str::from_utf8(&text).ok()?.split_whitespace().filter_map(|x| x.parse().ok()).collect();
        let [pid, start, egress, estart] = f[..] else { return None };
        if network::proc_start(egress as u32) != Some(estart) {
            return None;
        }
        Sandbox::adopt_with_userns(pid as i32, start, false, true)
    }

    /// Every 500 ms: records when each container log file grew (see `log_marks`). Marks of
    /// containers that are gone are dropped.
    async fn log_mark_loop(&self) {
        loop {
            kr_rt::exec::sleep(500).await;
            let paths: Vec<String> = self.pods.borrow().values().flat_map(|p| p.ctrs.iter().map(move |c| alloc::format!("{}/{}.log", p.dir, c.name))).collect();
            let (sec, nsec) = kr_sys::clock_gettime(0).map(|t| (t.tv_sec, t.tv_nsec)).unwrap_or((0, 0));
            let mut marks = self.log_marks.borrow_mut();
            marks.retain(|k, _| paths.contains(k));
            for path in paths {
                let Ok(st) = kr_sys::fs::newfstatat(kr_sys::ns::AT_FDCWD, alloc::format!("{path}\0").as_bytes(), 0) else { continue };
                let size = st.size as u64;
                let m = marks.entry(path).or_default();
                match m.last() {
                    Some(l) if l.0 >= size => {}
                    _ => {
                        if m.len() >= 8192 {
                            m.drain(..1024);
                        }
                        m.push((size, sec, nsec));
                    }
                }
            }
        }
    }

    /// Every 5 minutes: free image space when the store's filesystem is fuller than the high
    /// threshold (see [`imagegc`]).
    async fn image_gc_loop(self: &Rc<Self>) {
        let t = imagegc::Thresholds::from_env();
        if t.high >= 100 {
            return;
        }
        loop {
            kr_rt::exec::sleep(300_000).await;
            self.image_gc(&t).await;
        }
    }

    async fn image_gc(self: &Rc<Self>, t: &imagegc::Thresholds) {
        let usage = || kr_sys::ns::statfs(self.store.root().as_bytes()).map(|s| imagegc::usage_percent(&s)).unwrap_or(0);
        let before = usage();
        if before < t.high || self.pulls.borrow().values().any(|p| matches!(p, Pull::InProgress)) {
            return;
        }
        // Images some pod on this node names, and images some container directory records.
        let q = alloc::format!("fieldSelector=spec.nodeName%3D{}", self.cfg.node_name);
        let Ok(list) = self.c.list("/api/v1/pods", &q).await else { return };
        let mut in_use = alloc::collections::BTreeSet::new();
        for pod in list.get("items").and_then(Value::as_array).unwrap_or(&[]) {
            for r in imagegc::pod_images(pod) {
                if let Some(id) = self.store.resolve_ref(&r) {
                    in_use.insert(id.0);
                }
            }
        }
        let Some(running) = self.store.images_in_use() else {
            // Said once, not at every check.
            static SAID: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
            if !SAID.swap(true, core::sync::atomic::Ordering::Relaxed) {
                kr_rt::eprint(alloc::format!("kubelet: image store is {before}% full but a container of an older release or `kr run` is present; image garbage collection waits (said once)\n").as_bytes());
            }
            return;
        };
        in_use.extend(running);
        let now = now_ms() as i64 / 1000;
        let (mut images, mut layers, mut blobs) = (0, 0, 0);
        for id in imagegc::candidates(&self.store.images(), &in_use, now, t.min_age) {
            let res = if kr_sys::fs::getuid() == 0 { kr_runtime::offload::remove_image(&self.store, &id).await } else {
                let out = RefCell::new(None);
                let _ = self.maps.run_as_root(|| {
                    *out.borrow_mut() = Some(self.store.remove_image(&id));
                    true
                });
                out.into_inner().unwrap_or(Err(kr_runtime::store::Error::Unsafe("cannot enter the id maps")))
            };
            match res {
                Ok((l, b)) => {
                    images += 1;
                    layers += l;
                    blobs += b;
                }
                Err(e) => kr_rt::eprint(alloc::format!("kubelet: removing image {}: {e:?}\n", id.0).as_bytes()),
            }
            if usage() <= t.low {
                break;
            }
        }
        kr_rt::eprint(alloc::format!("kubelet: image store was {before}% full; removed {images} unused images ({layers} layers, {blobs} blobs), now {}%\n", usage()).as_bytes());
    }

    /// Every 10 s: taint the node while MemAvailable is below the threshold and evict one pod.
    async fn eviction_loop(self: &Rc<Self>) {
        let mut state = evict::PressureState::default();
        let mut grace = evict::DeviceGrace::default();
        let grace_ms = evict::device_grace_ms();
        let pdb_wait_ms = evict::device_pdb_wait_ms();
        let mut blocked: BTreeMap<String, u64> = BTreeMap::new();
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
            // Pods holding a device its plugin reports unhealthy fail (reason Evicted).
            let unhealthy = self.devices.unhealthy_pods();
            let bad: Vec<String> = unhealthy.iter().map(|u| u.0.clone()).collect();
            let due = grace.due(&bad, now_ms(), grace_ms);
            blocked.retain(|u, _| bad.contains(u));
            for (uid, msg) in unhealthy.into_iter().filter(|u| due.contains(&u.0)) {
                // Through the eviction API first: a PodDisruptionBudget can hold the pod back (up
                // to the wait), a bare pod or a controller's pod is deleted and replaced where a
                // healthy device exists. Without the permission (an agent's node identity), or
                // after the wait, the pod fails in place (reason Evicted).
                let target = self.pods.borrow().get(&uid).filter(|p| p.evicted.is_none() && p.failed_setup.is_none()).map(|p| (p.ns.clone(), p.name.clone()));
                let Some((ns, name)) = target else { continue };
                let body = alloc::format!(r#"{{"apiVersion":"policy/v1","kind":"Eviction","metadata":{{"name":"{name}","namespace":"{ns}"}}}}"#);
                let body = json::parse(body.as_bytes()).unwrap_or(Value::Null);
                let answer = self.c.create(&alloc::format!("/api/v1/namespaces/{ns}/pods/{name}/eviction"), &body).await.err().map(|e| e.code);
                let mut since = blocked.get(&uid).copied();
                let action = evict::device_eviction(answer, &mut since, now_ms(), pdb_wait_ms);
                match since {
                    Some(t) => drop(blocked.insert(uid.clone(), t)),
                    None => drop(blocked.remove(&uid)),
                }
                match action {
                    evict::DeviceEviction::Evicted => {
                        kr_rt::eprint(alloc::format!("kubelet: evicted pod {ns}/{name}: {msg}\n").as_bytes());
                        continue;
                    }
                    evict::DeviceEviction::Wait => continue,
                    evict::DeviceEviction::Fail => {}
                }
                let hit = self.pods.borrow_mut().get_mut(&uid).filter(|p| p.evicted.is_none() && p.failed_setup.is_none()).map(|p| p.evicted = Some(msg)).is_some();
                if hit {
                    self.kill_now(&uid);
                    self.notify.notify();
                }
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
        let my_ip = kr_net::tcp::fmt_ip16(self.cfg.node_ip);
        loop {
            if let (Ok(list), Ok(nl)) = (self.c.list("/api/v1/nodes", "").await, netlink::Netlink::route()) {
                let mut mine = None;
                let mut peers = Vec::new();
                let mut annotated = false;
                for n in list.get("items").and_then(Value::as_array).unwrap_or(&[]) {
                    let Some((pn, nfam)) = node_podnet(n) else { continue };
                    if meta(n, "name") == self.cfg.node_name {
                        self.check_families(nfam);
                        let ann = |k| n.pointer(&["metadata", "annotations", k]).and_then(Value::as_str);
                        annotated = ann(VTEP_MAC_KEY) == Some(my_mac.as_str()) && ann(VTEP_IP_KEY) == Some(my_ip.as_str()) && ann(BACKEND_KEY) == Some("vxlan");
                        mine = Some(pn);
                        continue;
                    }
                    let ip = internal_ip(n, kr_sys::unmap4(self.cfg.node_ip).is_none());
                    if let Some(theirs) = backend_mismatch("vxlan", n.pointer(&["metadata", "annotations", BACKEND_KEY]).and_then(Value::as_str)) {
                        self.warn_backend(&meta(n, "name"), "vxlan", theirs);
                        continue;
                    }
                    let mac = n.pointer(&["metadata", "annotations", VTEP_MAC_KEY]).and_then(Value::as_str).and_then(parse_mac);
                    if let (Some(ip), Some(mac)) = (ip, mac) {
                        peers.push((pn, ip, mac, nfam));
                    }
                }
                if !annotated && mine.is_some() {
                    let p = alloc::format!(r#"{{"metadata":{{"annotations":{{"{VTEP_MAC_KEY}":"{my_mac}","{VTEP_IP_KEY}":"{my_ip}","{BACKEND_KEY}":"vxlan"}}}}}}"#);
                    if let Ok(p) = json::parse(p.as_bytes()) {
                        let _ = self.c.patch(&alloc::format!("/api/v1/nodes/{}", self.cfg.node_name), "application/merge-patch+json", &p).await;
                    }
                }
                if let Some(idx) = mine.and_then(|pn| self.ensure_vxlan(&nl, pn.subnet)) {
                    let fam = self.fam.get();
                    // Without IPv4 pods there are no IPv4 routes or ARP entries to program.
                    let routes: Vec<_> = peers.iter().filter(|p| fam.v4 && p.3.v4).map(|(pn, _, _, _)| (pn.subnet, pn.prefix, pn.subnet)).collect();
                    let neighs: Vec<_> = peers.iter().filter(|p| fam.v4 && p.3.v4).map(|(pn, _, mac, _)| (pn.subnet, *mac)).collect();
                    let fdbs: Vec<_> = peers.iter().map(|(_, ip, mac, _)| (*mac, *ip)).collect();
                    let have_routes: Vec<_> = nl.routes_by_proto(RTPROT_KR).unwrap_or_default();
                    let (radd, rdel) = route_diff(&routes, &have_routes);
                    let (nadd, ndel) = set_diff(&neighs, &nl.neighs(idx).unwrap_or_default());
                    let (fadd, fdel) = set_diff(&fdbs, &nl.fdbs(idx).unwrap_or_default());
                    // IPv6 twins of the pod subnets: one on-link route per peer via its VTEP gateway
                    // address (idempotent replace; the FDB entries above carry the frames).
                    for (pn, _, mac, _) in peers.iter().filter(|p| fam.v6 && p.3.v6) {
                        let gw = network::vtep6(pn.subnet);
                        if nl.neigh_add6(idx, gw, *mac).is_ok() {
                            let _ = nl.route_replace6_onlink(network::subnet6(pn.subnet), network::POD_PREFIX6, gw, idx, RTPROT_KR);
                        }
                    }
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

    fn wg_mtu(&self) -> u32 {
        kr_net::netlink::wireguard::tunnel_mtu(uplink_mtu(), kr_sys::unmap4(self.cfg.node_ip).is_none())
    }

    /// WireGuard overlay (root mode, ADR-062): device `kr.wg`, this node's public key and
    /// endpoint in node annotations, and per peer node a WireGuard peer (allowed IPs = its pod
    /// CIDRs) plus routes of those CIDRs via the device. Peers are only pushed to the kernel when
    /// the desired set changed.
    async fn wireguard_loop(&self) {
        use kr_net::netlink::{self, wireguard as wg, RTPROT_KR};
        let key_path = alloc::format!("{}/wireguard.key", self.cfg.root);
        let port = kr_runtime::store::env_var("KR_WIREGUARD_PORT").and_then(|v| v.parse().ok()).unwrap_or(wg::DEFAULT_PORT);
        let private = match wg::load_or_create_key(&key_path) {
            Ok(k) => k,
            Err(e) => {
                kr_rt::eprint(alloc::format!("kubelet: wireguard: cannot use the key file {key_path}: errno {}\n", e.0).as_bytes());
                return;
            }
        };
        let public = wg::key_b64(&kr_crypto::x25519::public_key(&private));
        let my_endpoint = alloc::format!("{}:{port}", kr_net::tcp::fmt_ip16(self.cfg.node_ip));
        let v6_underlay = kr_sys::unmap4(self.cfg.node_ip).is_none();
        let mut applied: Option<Vec<wg::Peer>> = None;
        let mut failed = false;
        loop {
            if let (Ok(list), Ok(nl)) = (self.c.list("/api/v1/nodes", "").await, netlink::Netlink::route()) {
                let mut mine = None;
                let mut annotated = false;
                let mut peers = Vec::new();
                for n in list.get("items").and_then(Value::as_array).unwrap_or(&[]) {
                    let Some((pn, nfam)) = node_podnet(n) else { continue };
                    let ann = |k| n.pointer(&["metadata", "annotations", k]).and_then(Value::as_str);
                    if meta(n, "name") == self.cfg.node_name {
                        self.check_families(nfam);
                        annotated = ann(WG_KEY_KEY) == Some(public.as_str()) && ann(WG_ENDPOINT_KEY) == Some(my_endpoint.as_str()) && ann(BACKEND_KEY) == Some("wireguard");
                        mine = Some(pn);
                        continue;
                    }
                    if let Some(theirs) = backend_mismatch("wireguard", ann(BACKEND_KEY)) {
                        self.warn_backend(&meta(n, "name"), "wireguard", theirs);
                        continue;
                    }
                    let Some(key) = ann(WG_KEY_KEY).and_then(wg::parse_key) else { continue };
                    let endpoint = ann(WG_ENDPOINT_KEY).and_then(parse_endpoint).or_else(|| internal_ip(n, v6_underlay).map(|ip| (ip, port)));
                    let Some(endpoint) = endpoint else { continue };
                    peers.push(wg::Peer { key, endpoint, allowed: peer_allowed(pn, nfam, self.fam.get()) });
                }
                if !annotated && mine.is_some() {
                    let p = alloc::format!(r#"{{"metadata":{{"annotations":{{"{WG_KEY_KEY}":"{public}","{WG_ENDPOINT_KEY}":"{my_endpoint}","{BACKEND_KEY}":"wireguard"}}}}}}"#);
                    if let Ok(p) = json::parse(p.as_bytes()) {
                        let _ = self.c.patch(&alloc::format!("/api/v1/nodes/{}", self.cfg.node_name), "application/merge-patch+json", &p).await;
                    }
                }
                if let Some(pn) = mine {
                    let peers = wg::normalize(peers);
                    match nl.wireguard_ensure(WG_DEV.as_bytes(), self.wg_mtu()) {
                        Err(e) => {
                            if !failed {
                                kr_rt::eprint(alloc::format!("kubelet: wireguard: cannot create {WG_DEV}: {} (errno {})\n", wg::explain(e), e.0).as_bytes());
                            }
                            failed = true;
                        }
                        Ok(idx) => {
                            failed = false;
                            if applied.as_ref() != Some(&peers) {
                                match nl.wireguard_set(idx, &private, port, &peers) {
                                    Ok(()) => applied = Some(peers.clone()),
                                    Err(e) => kr_rt::eprint(alloc::format!("kubelet: wireguard: configuring {WG_DEV}: {} (errno {})\n", wg::explain(e), e.0).as_bytes()),
                                }
                            }
                            if self.fam.get().v4 {
                                let _ = nl.addr_add(idx, pn.subnet, 32);
                            }
                            if nl.link_up(idx).is_ok() {
                                let mut want4 = Vec::new();
                                for p in &peers {
                                    for (ip, len) in &p.allowed {
                                        match kr_sys::unmap4(*ip) {
                                            Some(a) => want4.push((a, len - 96)),
                                            None => {
                                                let _ = nl.route_add6_proto(*ip, *len, None, idx, RTPROT_KR);
                                            }
                                        }
                                    }
                                }
                                let have: Vec<_> = nl.routes_by_proto(RTPROT_KR).unwrap_or_default();
                                let del: Vec<_> = have.iter().filter(|h| !want4.contains(&(h.0, h.1))).map(|h| (h.0, h.1)).collect();
                                let add: Vec<_> = want4.iter().filter(|w| !have.iter().any(|h| (h.0, h.1) == **w)).collect();
                                for (d, l) in del {
                                    let _ = nl.route_del(d, l, RTPROT_KR);
                                }
                                for (d, l) in add {
                                    let _ = nl.route_add_proto(*d, *l, None, idx, RTPROT_KR);
                                }
                            }
                        }
                    }
                }
            }
            kr_rt::exec::sleep(5000).await;
        }
    }

    /// The cluster's families for this node changed since the kubelet started (the API server was
    /// restarted with another `KR_POD_FAMILIES`): pods keep the old addresses until this kr restarts.
    fn check_families(&self, now: network::Families) {
        if now != self.fam.get() && !self.warned_families.replace(true) {
            kr_rt::eprint(alloc::format!("kubelet: the pod network families changed ({} -> {}); restart kr to apply them\n", self.fam.get().text(), now.text()).as_bytes());
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
        if self.fam.get().v4 {
            let _ = nl.addr_add(idx, subnet, 32);
        }
        nl.link_up(idx).ok()?;
        Some(idx)
    }

    /// host-gw routing (root mode): a route to every other node's pod subnet via its
    /// InternalIP. Nodes must share an L2 segment (no overlay yet).
    async fn route_loop(&self) {
        if self.cfg.wireguard {
            return self.wireguard_loop().await;
        }
        if self.cfg.vxlan {
            return self.vxlan_loop().await;
        }
        use kr_net::netlink::RTPROT_KR;
        let mut announced = false;
        loop {
            if let (Ok(list), Ok(nl)) = (self.c.list("/api/v1/nodes", "").await, kr_net::netlink::Netlink::route()) {
                let mut want = Vec::new();
                let mut want6: Vec<([u8; 16], u8, [u8; 16])> = Vec::new();
                for n in list.get("items").and_then(Value::as_array).unwrap_or(&[]) {
                    if meta(n, "name") == self.cfg.node_name {
                        if let Some((_, nfam)) = node_podnet(n) {
                            self.check_families(nfam);
                        }
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
                    let Some((pn, nfam)) = node_podnet(n) else { continue };
                    let ip = internal_ip(n, false).and_then(kr_sys::unmap4);
                    if let Some(gw) = ip.filter(|_| self.fam.get().v4 && nfam.v4) {
                        want.push((pn.subnet, pn.prefix, gw));
                    }
                    // IPv6: the peer's pod /64 via its global IPv6 address (needs one on both ends).
                    let cidr6 = n.pointer(&["spec", "podCIDRs"]).and_then(Value::as_array).and_then(|a| a.iter().filter_map(Value::as_str).find(|c| c.contains(':')));
                    let gw6 = internal_ip(n, true).filter(|_| self.fam.get().v6 && nfam.v6);
                    if let (Some((net6, len)), Some(gw6)) = (cidr6.and_then(|c| c.split_once('/')), gw6) {
                        if let (Some(d), Ok(l)) = (kr_net::tcp::parse_ipv6(net6), len.parse::<u8>()) {
                            want6.push((d, l, gw6));
                        }
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
                // The same for IPv6: routes of nodes that left or changed address are removed.
                let have6 = nl.routes6_by_proto(RTPROT_KR).unwrap_or_default();
                let (add6, del6) = route_diff(&want6, &have6);
                for (d, p) in del6 {
                    let _ = nl.route_del6(d, p, RTPROT_KR);
                }
                for (d, p, gw) in add6 {
                    let _ = nl.route_add6_proto(d, p, Some(gw), 0, RTPROT_KR);
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

    /// One pass over this node's pods. False when the pod list could not be read.
    async fn sync_all(self: &Rc<Self>) -> bool {
        // Container exits recorded by waiter tasks.
        let exits: Vec<Exit> = core::mem::take(&mut *self.exits.borrow_mut());
        for e in exits {
            self.on_exit(e);
        }
        let q = alloc::format!("fieldSelector=spec.nodeName%3D{}", self.cfg.node_name);
        kr_rt::exec::phase("sync_all: list pods");
        let Ok(list) = self.c.list("/api/v1/pods", &q).await else { return false };
        kr_rt::exec::phase("sync_all: copy list");
        let desired: Vec<Value> = list.get("items").and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
        let mut seen = Vec::new();
        let mut slice = now_ms();
        for pod in &desired {
            let uid = meta(pod, "uid").to_string();
            seen.push(uid.clone());
            let mut lap = now_ms();
            if pod.pointer(&["metadata", "deletionTimestamp"]).is_some() {
                kr_rt::exec::phase("sync_all: terminate");
                self.terminate(&uid, pod).await;
                slow_step("terminate", pod, &mut lap);
            } else if self.starting.borrow().contains(&uid) {
                // Its sandbox is being started by its own task: leave the pod alone until then.
                continue;
            } else if self.needs_sandbox(&uid) && self.starting.borrow().len() < MAX_STARTING {
                self.starting.borrow_mut().insert(uid.clone());
                let (k, u, p) = (self.clone(), uid.clone(), pod.clone());
                kr_rt::exec::spawn(async move {
                    k.sync_pod(&u, &p).await;
                    k.starting.borrow_mut().remove(&u);
                    k.notify.notify();
                });
                continue;
            } else {
                kr_rt::exec::phase("sync_all: sync_pod");
                self.sync_pod(&uid, pod).await;
                slow_step("sync_pod", pod, &mut lap);
                kr_rt::exec::phase("sync_all: apply_resize");
                self.apply_resize(&uid, pod);
                slow_step("apply_resize", pod, &mut lap);
                kr_rt::exec::phase("sync_all: run_probes");
                self.run_probes(&uid, pod);
                slow_step("run_probes", pod, &mut lap);
                kr_rt::exec::phase("sync_all: refresh_volumes");
                self.refresh_volumes(&uid, pod).await;
                slow_step("refresh_volumes", pod, &mut lap);
            }
            kr_rt::exec::phase("sync_all: report_status");
            self.report_status(&uid, pod).await;
            slow_step("report_status", pod, &mut lap);
            // The in-process client never suspends, so without this the whole pod list is one
            // poll of the event loop: give the API server and Raft a turn every few ms.
            if now_ms().saturating_sub(slice) >= 5 {
                kr_rt::exec::yield_now().await;
                slice = now_ms();
            }
        }
        kr_rt::exec::phase("sync_all: storage gc");
        // Directories of deleted local-path PVs, every 30 s.
        static LAST_STORAGE_GC: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        let t = now_ms();
        if t.saturating_sub(LAST_STORAGE_GC.load(core::sync::atomic::Ordering::Relaxed)) >= 30_000 {
            LAST_STORAGE_GC.store(t, core::sync::atomic::Ordering::Relaxed);
            spec::gc_storage(&self.c).await;
        }
        kr_rt::exec::phase("sync_all: gone pods");
        // Pods deleted from the API: stop immediately (the object is already gone).
        let gone: Vec<String> = self.pods.borrow().keys().filter(|k| !seen.contains(k)).cloned().collect();
        for uid in gone {
            self.kill_now(&uid);
            if self.all_stopped(&uid) {
                self.cleanup(&uid);
            }
        }
        true
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
        c.proc = None;
        c.io = None;
        c.probes.clear();
        c.ready = false;
        // CrashLoopBackOff: every restart after an exit waits 10 s, doubling up to 5 min.
        c.backoff_ms = if c.backoff_ms == 0 { BACKOFF_START_MS } else { (c.backoff_ms * 2).min(BACKOFF_MAX_MS) };
        c.not_before = now_ms() + c.backoff_ms;
        if c.resize_restart {
            // A resize restart is not a crash: no backoff.
            c.backoff_ms = 0;
            c.not_before = 0;
        }
        drop(pods);
        self.persist(&e.pod_uid);
    }

    /// True for a pod that has no sandbox yet (new, or waiting for one).
    fn needs_sandbox(&self, uid: &str) -> bool {
        self.pods.borrow().get(uid).is_none_or(|p| p.sandbox.is_none() && p.failed_setup.is_none())
    }

    async fn sync_pod(self: &Rc<Self>, uid: &str, pod: &Value) {
        if !self.pods.borrow().contains_key(uid) {
            kr_rt::exec::phase("sync_pod: admit");
            let mut rt = self.admit(uid, pod);
            if self.survives() {
                kr_rt::exec::phase("sync_pod: try_adopt");
                self.try_adopt(uid, pod, &mut rt);
            } else if self.cfg.cgroups {
                // Pods do not survive here, so whatever a previous run left under this uid is stray.
                kr_runtime::cgroup::kill_pod(uid);
            }
            self.pods.borrow_mut().insert(uid.to_string(), rt);
            kr_rt::exec::phase("sync_pod: persist");
            self.persist(uid);
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
            // Unsafe sysctls are refused (upstream: `--allowed-unsafe-sysctls`, none here).
            let unsafe_sysctl = pod.pointer(&["spec", "securityContext", "sysctls"]).and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(|s| s.get("name").and_then(Value::as_str)).find(|n| !kr_apiserver::psa::SAFE_SYSCTLS.contains(n)).map(String::from);
            if let Some(n) = unsafe_sysctl {
                self.pods.borrow_mut().get_mut(uid).unwrap().failed_setup = Some(alloc::format!("Pod was rejected: forbidden sysctl: \"{n}\" not allowlisted"));
                return;
            }
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
            if now_ms() < self.pods.borrow()[uid].sandbox_retry_at {
                return;
            }
            let mut lap = now_ms();
            let started = self.start_sandbox(uid, pod).await;
            slow_step("start_sandbox", pod, &mut lap);
            if let Err(e) = started {
                if e.starts_with(NO_IP) {
                    // Addresses free up as other pods end: stay in ContainerCreating and retry on
                    // the next sync (one event per pod, not one per second).
                    let first = self.pods.borrow()[uid].ctrs.first().is_some_and(|c| !matches!(&c.state, CState::Waiting(_, m) if *m == e));
                    for c in self.pods.borrow_mut().get_mut(uid).unwrap().ctrs.iter_mut() {
                        c.state = CState::Waiting("ContainerCreating", e.clone());
                    }
                    if first {
                        self.emit_event(pod, "Warning", "FailedCreatePodSandBox", &e).await;
                    }
                    return;
                }
                // As upstream, a sandbox that cannot be built (a full disk, a CNI plugin error, a
                // vanished file) is retried with a pause: the pod stays in ContainerCreating
                // instead of failing for good.
                let first = self.pods.borrow()[uid].ctrs.first().is_some_and(|c| !matches!(&c.state, CState::Waiting(_, m) if *m == e));
                {
                    let mut pods = self.pods.borrow_mut();
                    let p = pods.get_mut(uid).unwrap();
                    p.sandbox_retry_at = now_ms() + 10_000;
                    for c in p.ctrs.iter_mut() {
                        c.state = CState::Waiting("ContainerCreating", e.clone());
                    }
                }
                if first {
                    self.emit_event(pod, "Warning", "FailedCreatePodSandBox", &e).await;
                }
                return;
            }
        }
        let policy = pod.pointer(&["spec", "restartPolicy"]).and_then(Value::as_str).unwrap_or("Always").to_string();
        // Once every app container of a Never/OnFailure pod has finished for good, sidecars are
        // stopped (and not restarted).
        if policy != "Always" {
            let grace = pod.pointer(&["spec", "terminationGracePeriodSeconds"]).and_then(Value::as_u64).unwrap_or(30);
            let mut pods = self.pods.borrow_mut();
            let p = pods.get_mut(uid).unwrap();
            let done = {
                let apps: Vec<&Ctr> = p.ctrs.iter().filter(|c| !c.init && !c.eph).collect();
                !apps.is_empty() && apps.iter().all(|c| matches!(&c.state, CState::Terminated(t) if policy == "Never" || t.exit_code == 0))
            };
            if done && p.ctrs.iter().any(|c| c.sidecar) {
                for c in p.ctrs.iter_mut().filter(|c| c.sidecar) {
                    if let (CState::Running { .. }, Some(s)) = (&c.state, &c.signaller) {
                        // SIGTERM, then SIGKILL after the grace period.
                        if c.resize_kill_at == 0 {
                            c.resize_kill_at = now_ms() + grace * 1000;
                            let _ = s.send(kr_sys::ns::SIGTERM);
                        } else if now_ms() >= c.resize_kill_at {
                            let _ = s.send(9);
                        }
                    }
                }
                return;
            }
        }
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
                CState::Terminated(t) => self.pods.borrow()[uid].ctrs[i].resize_restart || policy == "Always" || (policy == "OnFailure" && t.exit_code != 0),
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
                        p.ctrs.push(Ctr { name: name.into(), image: e.get("image").and_then(Value::as_str).unwrap_or("").into(), init: false, sidecar: false, eph: true, restart_count: 0, state: CState::Waiting("ContainerCreating", String::new()), last_term: None, signaller: None, not_before: 0, backoff_ms: 0, seq: 0, target: None, probes: Vec::new(), started: false, ready: false, res: String::new(), resize_restart: false, resize_kill_at: 0, proc: None, io: None, shim: 0 });
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

    /// Lets another node's API server know pod proxy must go through this kubelet.
    async fn announce_rootless(&self) {
        let patch = Value::Object(alloc::vec![(String::from("metadata"), Value::Object(alloc::vec![(String::from("annotations"), Value::Object(alloc::vec![(String::from("kr.io/rootless"), Value::from("true"))]))]))]);
        let _ = self.c.patch(&alloc::format!("/api/v1/nodes/{}", self.cfg.node_name), "application/merge-patch+json", &patch).await;
    }

    /// Pods outlive this process: always as root, and rootless once the pod network is up.
    fn survives(&self) -> bool {
        self.survive.get() && (self.cfg.network || self.infra.borrow().is_some())
    }

    /// Writes the pod's `.adopt` record (see [`adopt`]) so a restarted kubelet can take it over.
    fn persist(&self, uid: &str) {
        if !self.survives() {
            return;
        }
        let text = {
            let pods = self.pods.borrow();
            let Some(p) = pods.get(uid) else { return };
            let Some(sb) = p.sandbox.as_ref() else { return };
            let Some(start) = kr_runtime::network::proc_start(sb.pid as u32) else { return };
            let host_net = sb.is_host_net();
            // A CNI pod has no kr lease: its address is the one the plugin returned.
            let ip = p.lease.as_ref().map(|l| l.ip).or(if host_net { None } else { p.ip });
            let ip6 = if host_net || p.lease.is_some() { None } else { p.ip6 };
            let rec = adopt::Sb { pid: sb.pid, start, host_net, ip, userns: sb.userns, ip6 };
            let ctrs: Vec<adopt::Ctr> = p
                .ctrs
                .iter()
                .filter_map(|c| match (&c.state, c.proc) {
                    (CState::Running { started_at, id }, Some((pid, start))) if c.shim > 0 => {
                        let (io_fd, tty) = c.io.map_or((-1, false), |(_, fd, tty)| (fd, tty));
                        Some(adopt::Ctr { name: c.name.clone(), pid, start, cid: id.clone(), seq: c.seq, started_at: *started_at, shim: c.shim, io_fd, tty })
                    }
                    _ => None,
                })
                .collect();
            (alloc::format!("{}/{}", p.dir, adopt::FILE), adopt::encode(&rec, &ctrs))
        };
        // The write is atomic (about 100 ms with an fsync on a busy disk, on the event loop): skip
        // it when the record is already what is on disk (every adopted pod after a restart,
        // every sync that changed nothing).
        let same = kr_sys::fs::read_file(alloc::format!("{}\0", text.0).as_bytes(), 1 << 20).is_ok_and(|old| old == text.1.as_bytes());
        if !same {
            // No fsync: the record only matters when the kr process dies (the page cache
            // survives that); after a reboot the pods are gone and nothing is adopted.
            let _ = kr_runtime::store::write_file_atomic_nosync(&text.0, text.1.as_bytes());
        }
    }

    /// Takes over the sandbox and containers a previous kubelet left running for this pod.
    /// Anything that cannot be adopted is killed, so the pod then starts from scratch.
    fn try_adopt(self: &Rc<Self>, uid: &str, pod: &Value, rt: &mut PodRt) {
        let path = alloc::format!("{}/{}\0", rt.dir, adopt::FILE);
        let Ok(raw) = kr_sys::fs::read_file(path.as_bytes(), 1 << 16) else {
            // No record: a new pod, or the kubelet died before writing it. Whatever runs in the
            // pod's cgroup then belongs to nobody.
            if self.cfg.cgroups {
                kr_runtime::cgroup::kill_pod(uid);
            }
            return;
        };
        let _ = kr_sys::fs::unlinkat(kr_sys::ns::AT_FDCWD, path.as_bytes(), 0);
        let rec = core::str::from_utf8(&raw).ok().and_then(adopt::decode);
        let adopted = rec.and_then(|(sb, ctrs)| self.adopt_pod(uid, pod, rt, sb, ctrs));
        if adopted.is_none() {
            if self.cfg.cgroups {
                kr_runtime::cgroup::kill_pod(uid);
            }
            rt.sandbox = None;
            for c in rt.ctrs.iter_mut() {
                c.state = CState::Waiting("ContainerCreating", String::new());
                c.signaller = None;
                c.target = None;
                c.proc = None;
            }
        }
    }

    fn adopt_pod(self: &Rc<Self>, uid: &str, pod: &Value, rt: &mut PodRt, sb: adopt::Sb, recs: Vec<adopt::Ctr>) -> Option<()> {
        let sandbox = Sandbox::adopt_with_userns(sb.pid, sb.start, sb.host_net, sb.userns)?;
        let pn = self.podnet.get();
        let fam = self.fam.get();
        let net = sb.ip.filter(|_| !sb.host_net).map(|ip| NetConfig::with(ip, &pn, fam));
        // With a CNI plugin the pod's address belongs to the plugin (no kr lease to take over);
        // the record carries the addresses it returned.
        let cni = cni::is_enabled() && !sb.host_net;
        if !sb.host_net && !cni {
            // The pod keeps its IP; its lease must exist so nobody else gets it.
            let ip = sb.ip?;
            rt.lease = Some(Lease::adopt(alloc::format!("{}/ipam", self.cfg.root).as_bytes(), uid.as_bytes(), ip)?);
        }
        if cni && sb.ip.is_none() && sb.ip6.is_none() {
            return None; // a record from before CNI pods were adoptable: start the pod again
        }
        rt.ip = if sb.host_net { kr_sys::unmap4(self.cfg.node_ip) } else { sb.ip.filter(|_| fam.v4 || cni) };
        rt.ip6 = if sb.host_net { Some(self.cfg.node_ip).filter(|a| kr_sys::unmap4(*a).is_none()) } else if cni { sb.ip6 } else { net.and_then(|n| n.ip6) };
        if self.cfg.cgroups {
            let (limits, _) = spec::pod_resources(pod);
            rt.cg = PodCgroup::create(spec::qos_class(pod), uid, &limits).ok();
        }
        if let Some(t) = pod.pointer(&["status", "startTime"]).and_then(Value::as_str).and_then(kr_apiserver::printers::parse_rfc3339) {
            rt.start_time = t;
        }
        // What the API server already knows: restart counts, finished containers, readiness.
        for c in rt.ctrs.iter_mut() {
            let key = if c.init { "initContainerStatuses" } else if c.eph { "ephemeralContainerStatuses" } else { "containerStatuses" };
            let Some(st) = pod.pointer(&["status", key]).and_then(Value::as_array).and_then(|a| a.iter().find(|s| s.get("name").and_then(Value::as_str) == Some(c.name.as_str()))) else { continue };
            c.restart_count = st.get("restartCount").and_then(Value::as_u64).unwrap_or(0) as u32;
            c.seq = c.restart_count + 1;
            c.ready = st.get("ready").and_then(Value::as_bool).unwrap_or(false);
            c.started = st.get("started").and_then(Value::as_bool).unwrap_or(false);
            let term = |t: &Value| {
                let t_of = |k: &str| t.get(k).and_then(Value::as_str).and_then(kr_apiserver::printers::parse_rfc3339).unwrap_or(0);
                let reason = match t.get("reason").and_then(Value::as_str) {
                    Some("Completed") => "Completed",
                    Some("OOMKilled") => "OOMKilled",
                    _ => "Error",
                };
                Term { exit_code: t.get("exitCode").and_then(Value::as_i64).unwrap_or(0) as i32, reason, started_at: t_of("startedAt"), finished_at: t_of("finishedAt"), message: t.get("message").and_then(Value::as_str).unwrap_or("").into() }
            };
            if let Some(t) = st.pointer(&["state", "terminated"]) {
                let t = term(t);
                c.state = CState::Terminated(t.clone());
                c.last_term = Some(t);
            } else if let Some(t) = st.pointer(&["lastState", "terminated"]) {
                c.last_term = Some(term(t));
            }
            c.not_before = 0;
        }
        rt.sandbox = Some(sandbox);
        // Containers that are still running.
        for r in recs {
            let Some(i) = rt.ctrs.iter().position(|c| c.name == r.name) else { continue };
            let cg = if self.cfg.cgroups { rt.cg.as_ref().and_then(|p| kr_runtime::cgroup::Cgroup::open_in(p.rel(), r.cid.as_bytes()).ok()) } else { None };
            let exit_path = alloc::format!("{}/{}.exit\0", rt.dir, r.cid);
            let Some(running) = container::Running::adopt(r.pid, r.start, r.shim, sb.host_net, cg, exit_path.clone().into_bytes()) else {
                // It ended while the kubelet was away: its shim recorded how.
                let found = container::read_exit_file(exit_path.as_bytes());
                let _ = kr_sys::fs::unlinkat(kr_sys::ns::AT_FDCWD, exit_path.as_bytes(), 0);
                let (exit_code, oom) = found.map_or((container::UNKNOWN_EXIT, false), |e| (e.code, e.oom_killed));
                let _ = self.maps.run_as_root(|| self.store.delete_container(&r.cid).is_ok());
                let c = &mut rt.ctrs[i];
                c.seq = r.seq;
                c.state = CState::Running { started_at: r.started_at, id: r.cid.clone() };
                let message = spec::termination_message(&rt.dir, &r.name, false, exit_code != 0);
                self.exits.borrow_mut().push(Exit { pod_uid: uid.to_string(), ctr: r.name.clone(), exit_code, oom, started_at: r.started_at, message });
                self.notify.notify();
                continue;
            };
            // `attach`: the shim still holds the stdin socket / pty master; take a copy.
            if r.io_fd >= 0 {
                let sock = alloc::format!("{}/{}.io", rt.dir, r.name);
                if let Some(fd) = fetch_io_fd(sock.as_bytes()) {
                    if kr_sys::ns::set_nonblocking(fd.raw()).is_ok() {
                        let once = pod.pointer(&["spec", "containers"]).and_then(Value::as_array).and_then(|a| a.iter().find(|x| x.get("name").and_then(Value::as_str) == Some(r.name.as_str()))).and_then(|c| c.get("stdinOnce")).and_then(Value::as_bool) == Some(true);
                        self.stdin_keep.borrow_mut().insert(alloc::format!("{}/{}", rt.dir, r.name), (Rc::new(fd), once, r.tty));
                    }
                } else {
                    kr_rt::eprint(alloc::format!("kubelet: cannot reattach stdin/terminal of {}/{} after the restart (attach -i unavailable until it restarts)\n", rt.name, r.name).as_bytes());
                }
            }
            let cspec = pod.pointer(&["spec", if rt.ctrs[i].init { "initContainers" } else if rt.ctrs[i].eph { "ephemeralContainers" } else { "containers" }]).and_then(Value::as_array).and_then(|a| a.iter().find(|x| x.get("name").and_then(Value::as_str) == Some(r.name.as_str()))).cloned().unwrap_or(Value::Null);
            let c = &mut rt.ctrs[i];
            c.seq = r.seq;
            c.state = CState::Running { started_at: r.started_at, id: r.cid.clone() };
            c.signaller = Some(running.signaller());
            c.target = Some(running.target().with_ctx(spec::exec_ctx(&pod, &cspec, "", &spec::seccomp_dir(&self.cfg.root))));
            c.proc = Some((r.pid, r.start));
            c.shim = r.shim;
            c.io = (r.io_fd >= 0).then_some((r.shim, r.io_fd, r.tty));
            c.probes = [probe::Kind::Startup, probe::Kind::Liveness, probe::Kind::Readiness]
                .into_iter()
                .filter(|_| (!c.init || c.sidecar) && !c.eph)
                .filter_map(|k| cspec.get(k.field()).map(|p| (k, probe::State::new(p.clone(), now_ms()))))
                .collect();
            if !c.probes.iter().any(|(k, _)| *k == probe::Kind::Startup) {
                c.started = true;
            }
            if !c.probes.iter().any(|(k, _)| *k == probe::Kind::Readiness) {
                c.ready = true;
            }
            let fallback = cspec.get("terminationMessagePolicy").and_then(Value::as_str) == Some("FallbackToLogsOnError");
            self.spawn_waiter(uid.to_string(), r.name, r.cid, running, r.started_at, rt.dir.clone(), fallback);
        }
        // Init containers that never reported a verdict and are not running died with the kubelet's
        // view of them: they run again (what an init container must tolerate anyway).
        let (p, c) = self.adopted.get();
        self.adopted.set((p + 1, c + rt.ctrs.iter().filter(|c| matches!(c.state, CState::Running { .. })).count() as u32));
        Some(())
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
                    res: c.get("resources").map(json::to_string).unwrap_or_default(),
                    resize_restart: false,
                    resize_kill_at: 0,
                    proc: None,
                    io: None,
                    shim: 0,
                });
            }
        }
        let prio = pod.pointer(&["spec", "priorityClassName"]).and_then(Value::as_str).unwrap_or("");
        let critical = prio.starts_with("system-") && prio.ends_with("-critical") || pod.pointer(&["metadata", "annotations", "kubernetes.io/config.mirror"]).is_some();
        PodRt { ns: meta(pod, "namespace").into(), name: meta(pod, "name").into(), dir, sandbox: None, lease: None, ip: None, ip6: None, node_ip: self.cfg.node_ip, ctrs, start_time: now(), kill_at: None, stopped_at: None, last_status: String::new(), failed_setup: None, volumes_synced: now_ms(), cg: None, qos: spec::qos_class(pod), mem_request: spec::pod_resources(pod).1, cpu_request: spec::cpu_request(pod), resize_pending: None, critical, evicted: None, deadline_exceeded: false, conds: Vec::new(), host_ports: host_ports(pod), sandbox_retry_at: 0, pvcs: None }
    }

    async fn start_sandbox(&self, uid: &str, pod: &Value) -> Result<(), String> {
        let dir = self.pods.borrow()[uid].dir.clone();
        kr_runtime::store::mkdir_p(&dir, 0o711).map_err(|_| String::from("cannot create pod directory"))?;
        let mut lease = None;
        let rootless_net = self.infra.borrow().is_some();
        // hostNetwork pods share the kubelet's network namespace: no veth, no pod IP lease.
        let host_net = pod.pointer(&["spec", "hostNetwork"]).and_then(Value::as_bool) == Some(true);
        let host_users = pod.pointer(&["spec", "hostUsers"]).and_then(Value::as_bool);
        let userns = if kr_sys::ns::getuid() != 0 {
            true
        } else {
            match host_users {
                Some(false) => true,
                Some(true) => false,
                None => kr_runtime::container::userns_enabled(),
            }
        };
        let use_cni = cni::is_enabled() && !host_net;
        if !use_cni && (self.cfg.network || rootless_net) && !host_net {
            let ipam = alloc::format!("{}/ipam", self.cfg.root);
            let _ = kr_runtime::store::mkdir_p(&ipam, 0o700);
            lease = match network::allocate_or_reuse(ipam.as_bytes(), uid.as_bytes(), &self.podnet.get()) {
                Ok(l) => Some(l),
                // A pod without an address would run without a network: wait for one instead.
                Err(e) => return Err(alloc::format!("{NO_IP}: no free address in the pod network (errno {})", e.0)),
            };
        }
        let ip = if host_net { kr_sys::unmap4(self.cfg.node_ip) } else { lease.as_ref().map(|l: &Lease| l.ip) };
        let pn = self.podnet.get();
        let net = if use_cni { None } else { ip.filter(|_| !host_net).map(|ip| NetConfig::with(ip, &pn, self.fam.get())) };
        // hostNetwork pods report the node's hostname (upstream: unless spec.hostname is set).
        let hostname = if host_net && pod.pointer(&["spec", "hostname"]).and_then(Value::as_str).is_none_or(str::is_empty) {
            String::from_utf8(kr_sys::fs::read_file(b"/proc/sys/kernel/hostname\0", 256).unwrap_or_default()).unwrap_or_default().trim().to_string()
        } else {
            spec::pod_hostname(pod)
        };
        let started = match self.infra.borrow().as_ref() {
            _ if host_net => container::start_host_sandbox(uid.as_bytes(), hostname.as_bytes(), &self.maps, userns),
            Some(infra) => container::start_sandbox_in(infra, uid.as_bytes(), hostname.as_bytes(), &self.maps, net, userns),
            None => container::start_sandbox(uid.as_bytes(), hostname.as_bytes(), &self.maps, net, userns),
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
        let sysctls: Vec<(String, String)> = pod
            .pointer(&["spec", "securityContext", "sysctls"])
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|s| Some((s.get("name")?.as_str()?.to_string(), s.get("value")?.as_str()?.to_string()))).collect())
            .unwrap_or_default();
        // As containerd and CRI-O do: any port may be bound without privileges inside a pod's own
        // network namespace (best effort; the sysctl is namespaced).
        if !host_net {
            let _ = sb.apply_sysctls(&[(String::from("net.ipv4.ip_unprivileged_port_start"), String::from("0"))]);
        }
        if let Err(e) = sb.apply_sysctls(&sysctls) {
            sb.stop();
            if let Some(l) = lease {
                l.release();
            }
            return Err(e);
        }
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
        // CNI: run the plugin chain to attach the pod's network namespace, then use
        // the returned addresses instead of kr's built-in IPAM/veth.
        let (cni_ip4, cni_ip6) = if use_cni {
            let cfg = cni::load_config(&cni::conf_dir().unwrap()).unwrap_or(Value::Null);
            let netns = alloc::format!("/proc/{}/ns/net", sb.pid);
            let cni_args = alloc::format!("IgnoreUnknown=1;K8S_POD_NAMESPACE={};K8S_POD_NAME={};K8S_POD_INFRA_CONTAINER_ID={uid}", meta(pod, "namespace"), meta(pod, "name"));
            match cni::cni_add(&cfg, uid, &netns, "eth0", &cni_args).await {
                Ok(r) => (r.ipv4, r.ipv6),
                Err(e) => {
                    sb.stop();
                    if let Some(l) = lease { l.release(); }
                    return Err(alloc::format!("cni add: {e}"));
                }
            }
        } else {
            (None, None)
        };
        let ip = cni_ip4.or(ip);
        let net_ip6 = cni_ip6.or(net.and_then(|n| n.ip6));
        spec::write_etc_hosts(&dir, pod, &hostname, ip, net_ip6).map_err(|_| String::from("cannot write /etc/hosts"))?;
        spec::write_resolv_conf(&dir, pod, self.infra.borrow().is_some(), self.fam.get()).map_err(|_| String::from("cannot write /etc/resolv.conf"))?;
        let mut pods = self.pods.borrow_mut();
        // The pod can be deleted while a CNI plugin runs (the loop is not blocked any more).
        let Some(p) = pods.get_mut(uid) else {
            drop(pods);
            sb.stop();
            if let Some(l) = lease {
                l.release();
            }
            return Err(String::from("pod removed during network setup"));
        };
        p.sandbox = Some(sb);
        p.cg = cg;
        p.lease = lease;
        p.ip = ip.filter(|_| host_net || self.fam.get().v4);
        p.ip6 = if host_net { Some(self.cfg.node_ip).filter(|a| kr_sys::unmap4(*a).is_none()) } else if use_cni { net_ip6 } else { net.and_then(|n| n.ip6) };
        let announce: Vec<String> = [p.ip.map(|a| kr_net::tcp::fmt_ip16(kr_sys::map4(a))), p.ip6.map(kr_net::tcp::fmt_ip16)].into_iter().flatten().collect();
        drop(pods);
        // Pre-start hook (#203): install the pod's NetworkPolicy chain from the address just
        // allocated, before any container runs, instead of waiting for the status report.
        if !host_net && !use_cni && self.cfg.network && !announce.is_empty() && netpol::enabled() {
            self.netpol.announce(meta(pod, "namespace"), meta(pod, "name"), announce);
            self.netpol.sync(&self.c, &self.cfg.node_name).await;
        }
        self.persist(uid);
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
        let Some((img_id, img, mut rootfs)) = self.store.image(&image) else {
            self.set_waiting(uid, i, "ErrImageNeverPull", alloc::format!("image {image} not present"));
            return;
        };
        rootfs.pop();
        // Copy out first: RefCell guards in the match scrutinee would live across the await
        // and through the arms (which borrow mutably).
        let (pod_dir, pod_ip, pod_ip6) = {
            let pods = self.pods.borrow();
            (pods[uid].dir.clone(), pods[uid].ip, pods[uid].ip6)
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
        let built = match spec::build(&self.c, pod, cspec.unwrap_or(&Value::Null), &img, &pod_dir, pod_ip, pod_ip6, &self.cfg.node_name, &kr_net::tcp::fmt_ip16(self.cfg.node_ip), &self.store, &self.devices, &self.csi).await {
            Ok(b) => b,
            Err(msg) => {
                // A claim that is not bound yet is the pod waiting for its volume, not a config error.
                let reason = if msg.starts_with("persistentvolumeclaim") { "ContainerCreating" } else { "CreateContainerConfigError" };
                self.set_waiting(uid, i, reason, msg);
                self.backoff(uid, i);
                return;
            }
        };
        // securityContext.capabilities: an unknown name is a config error, not a silent default.
        let caps: Option<Vec<u32>> = match cspec.and_then(|c| c.pointer(&["securityContext", "capabilities"])) {
            Some(c) => {
                let names = |f: &str| -> Vec<&str> { c.get(f).and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(Value::as_str).collect() };
                match kr_runtime::security::resolve_caps(&names("add"), &names("drop")) {
                    Ok(set) => Some(set),
                    Err(m) => {
                        self.set_waiting(uid, i, "CreateContainerConfigError", m);
                        self.backoff(uid, i);
                        return;
                    }
                }
            }
            None => None,
        };
        // securityContext.seccompProfile: Localhost files are read here; a bad one is a config error.
        let seccomp = match spec::seccomp_filter(pod, cspec.unwrap_or(&Value::Null), caps.as_deref(), &spec::seccomp_dir(&self.cfg.root)) {
            Ok(f) => f,
            Err(m) => {
                self.set_waiting(uid, i, "CreateContainerConfigError", m);
                self.backoff(uid, i);
                return;
            }
        };
        // appArmorProfile and seLinuxOptions: a profile that is not loaded is a config error.
        let lsm = match spec::lsm_for(pod, cspec.unwrap_or(&Value::Null), &spec::LsmHost::probe()) {
            Ok(l) => l,
            Err(m) => {
                self.set_waiting(uid, i, "CreateContainerConfigError", m);
                self.backoff(uid, i);
                return;
            }
        };
        let ctx_user = built.user.clone().into_bytes();
        let ctx_groups = built.extra_groups.clone();
        let ctx_privileged = cspec.and_then(|c| c.pointer(&["securityContext", "privileged"])).and_then(Value::as_bool).unwrap_or(false);
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
        self.store.set_container_image(&cid, &img_id);
        self.store.mark_used(&img_id);
        let log_path = alloc::format!("{}/{name}.log\0", self.pods.borrow()[uid].dir);
        if seq > 1 {
            // Keep the last run's output for `logs --previous` (and keep it out of this run's file).
            let cur = log_path.trim_end_matches('\0');
            let _ = kr_sys::fs::renameat2(kr_sys::ns::AT_FDCWD, log_path.as_bytes(), kr_sys::ns::AT_FDCWD, alloc::format!("{}.prev\0", cur.trim_end_matches(".log")).as_bytes(), 0);
            self.log_marks.borrow_mut().remove(cur);
        }
        let log = kr_sys::ns::open(log_path.as_bytes(), kr_sys::ns::O_WRONLY | kr_sys::ns::O_CREAT | 0o2000 /* O_APPEND */, 0o640).ok();
        // A container writes its output to this file, and one that reopens `/dev/stderr` (nginx,
        // Calico's whisker) needs write permission on it as its own user: give a numeric
        // runAsUser/USER ownership of the file (still mode 0640, so nobody else gets access).
        if kr_sys::ns::getuid() == 0 {
            if let Some(uid) = built.user.split(':').next().and_then(|u| u.parse::<u32>().ok()).filter(|u| *u != 0) {
                let _ = kr_sys::fs::fchownat(kr_sys::ns::AT_FDCWD, log_path.as_bytes(), uid, u32::MAX, 0);
            }
        }
        // `stdin: true`: the container reads one end of a socketpair that `kubectl attach -i`
        // feeds through ours; no attach is no input, not EOF. `tty: true`: a pseudo-terminal
        // instead, whose master we read into the log and `attach` writes to.
        let want_tty = cspec.and_then(|c| c.get("tty")).and_then(Value::as_bool) == Some(true);
        let tty_pair = if want_tty { kr_sys::ns::openpty().ok() } else { None };
        let stdin_pair = if !want_tty && cspec.and_then(|c| c.get("stdin")).and_then(Value::as_bool) == Some(true) { kr_sys::ns::socketpair().ok() } else { None };
        let stdin_read = stdin_pair.as_ref().map(|(_, c)| c);
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
            hooks: &built.hooks,
            log_fd: log.as_ref().map(|f| f.raw()),
            stdin_fd: stdin_read.map(|f| f.raw()),
            tty_fd: tty_pair.as_ref().map(|(_, sl)| sl.raw()),
            extra_groups: &built.extra_groups,
            readonly_root: cspec.and_then(|c| c.pointer(&["securityContext", "readOnlyRootFilesystem"])).and_then(Value::as_bool).unwrap_or(false),
            privileged: cspec.and_then(|c| c.pointer(&["securityContext", "privileged"])).and_then(Value::as_bool).unwrap_or(false),
            caps: caps.as_deref(),
            seccomp: seccomp.as_deref(),
            lsm: &lsm,
            userns: {
                let host_users = pod.pointer(&["spec", "hostUsers"]).and_then(Value::as_bool);
                if kr_sys::ns::getuid() != 0 {
                    true
                } else {
                    match host_users {
                        Some(false) => true,
                        Some(true) => false,
                        None => kr_runtime::container::userns_enabled(),
                    }
                }
            },
        };
        let detached = self.survives();
        // Descriptors a shim must keep for `attach`: our end of the stdin socket / the pty master.
        let io_fd: Option<(i32, bool)> = stdin_pair.as_ref().map(|(o, _)| (o.raw(), false)).or_else(|| tty_pair.as_ref().map(|(m, _)| (m.raw(), true)));
        let keep_fds: Vec<i32> = io_fd.map(|(f, _)| f).into_iter().collect();
        let exit_path = alloc::format!("{pod_dir}/{cid}.exit");
        let tty_log = alloc::format!("{pod_dir}/{name}.log");
        // A detached start forks the shim and returns; the shim reports once the container is set
        // up (overlay mount, hooks, exec: 50-130 ms), awaited below so that wait does not stall
        // the event loop. No `RefCell` borrow is held across it.
        let (begun, started) = if detached {
            let io_sock = alloc::format!("{pod_dir}/{name}.io");
            let io = container::ShimIo { keep_fds: &keep_fds, tty_master: tty_pair.as_ref().map(|(m, _)| m.raw()), tty_log: tty_log.as_bytes(), io_fd: io_fd.map(|(f, _)| f), io_sock: io_sock.as_bytes() };
            (Some(container::start_detached_begin(&run, exit_path.as_bytes(), &io)), None)
        } else {
            (None, Some(container::start(&run)))
        };
        drop(pods);
        let r = match (begun, started) {
            (Some(Ok(pending)), _) => pending.finish().await,
            (Some(Err(e)), _) => Err(e),
            (None, Some(r)) => r,
            (None, None) => unreachable!(),
        };
        drop(log);
        if r.is_ok() {
            let key = alloc::format!("{pod_dir}/{name}");
            let once = cspec.and_then(|c| c.get("stdinOnce")).and_then(Value::as_bool) == Some(true);
            if let Some((ours, _)) = stdin_pair {
                if kr_sys::ns::set_nonblocking(ours.raw()).is_ok() {
                    self.stdin_keep.borrow_mut().insert(key, (Rc::new(ours), once, false));
                }
            } else if let Some((master, _)) = tty_pair {
                // Terminal output goes to the log file, like a pipe's would.
                if kr_sys::ns::set_nonblocking(master.raw()).is_ok() {
                    if let Some(rd) = kr_sys::ns::dup_cloexec(master.raw()).ok().filter(|_| !detached).and_then(|d| kr_rt::exec::Async::new(d).ok()) {
                        let log_path = alloc::format!("{pod_dir}/{name}.log\0");
                        kr_rt::exec::spawn(async move {
                            let Ok(out) = kr_sys::ns::open(log_path.as_bytes(), kr_sys::ns::O_WRONLY | kr_sys::ns::O_CREAT | 0o2000, 0o640) else { return };
                            let mut buf = [0u8; 8192];
                            while let Ok(n) = rd.read(&mut buf).await {
                                if n == 0 || kr_sys::write(out.raw(), &buf[..n]).is_err() {
                                    break;
                                }
                            }
                        });
                    }
                    self.stdin_keep.borrow_mut().insert(key, (Rc::new(master), once, true));
                }
            }
        }
        match r {
            Ok(running) => {
                let started = now();
                {
                    let mut pods = self.pods.borrow_mut();
                    let c = &mut pods.get_mut(uid).unwrap().ctrs[i];
                    if c.seq > 0 {
                        c.restart_count += 1;
                    }
                    c.resize_restart = false;
                    c.seq = seq;
                    c.signaller = Some(running.signaller());
                    c.target = Some(running.target().with_ctx(container::ExecCtx { user: ctx_user, groups: ctx_groups, privileged: ctx_privileged, caps: caps.clone(), seccomp: seccomp.clone(), lsm: lsm.clone() }));
                    c.state = CState::Running { started_at: started, id: cid.clone() };
                    c.proc = kr_runtime::network::proc_start(running.pid as u32).map(|st| (running.pid, st));
                    c.shim = running.shim_pid();
                    c.io = io_fd.filter(|_| detached).map(|(fd, tty)| (running.shim_pid(), fd, tty));
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
                self.persist(uid);
                self.emit_event(pod, "Normal", "Started", &alloc::format!("Started container {name}")).await;
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
                if e.step == "join sandbox" && e.errno.0 == 3 {
                    // The pod's sandbox process is gone (killed with a previous kubelet run, or
                    // by hand): drop it so the next sync builds a new sandbox (same IP) instead
                    // of failing every restart of the container.
                    kr_rt::eprint(alloc::format!("kubelet: sandbox of pod {uid} is gone; recreating it\n").as_bytes());
                    self.pods.borrow_mut().get_mut(uid).unwrap().sandbox = None;
                    self.notify.notify();
                }
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
        spec::refresh_volumes(&self.c, &self.csi, pod, &dir).await;
        spec::apply_fs_group(&self.maps, pod, &dir);
        // Where the claims live, for volume statistics (looked up again when none was found).
        if self.pods.borrow().get(uid).is_some_and(|p| p.pvcs.as_ref().is_none_or(Vec::is_empty)) {
            let v = spec::pvc_paths(&self.c, &self.csi, pod).await;
            if let Some(p) = self.pods.borrow_mut().get_mut(uid) {
                p.pvcs = Some(v);
            }
        }
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
        let Some(p) = pods.get_mut(uid) else { return };
        let (pns, pname) = (p.ns.clone(), p.name.clone());
        let Some(c) = p.ctrs.get_mut(ci) else { return };
        let Some((kind, st)) = c.probes.get_mut(pi) else { return };
        let kind = *kind;
        let label = match kind {
            probe::Kind::Startup => "Startup",
            probe::Kind::Liveness => "Liveness",
            probe::Kind::Readiness => "Readiness",
        };
        *self.probe_counts.borrow_mut().entry((pns, pname, c.name.clone(), label, ok)).or_insert(0) += 1;
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

    /// In-place resize. A changed `resources` is checked against the node first: bigger than the
    /// node makes it `Infeasible`, not fitting next to the other pods `Deferred` (both reported as
    /// the `PodResizePending` condition, retried every sync). Otherwise a container whose changed
    /// resource has `resizePolicy: RestartContainer` is restarted with the new values and the rest
    /// get their cgroup limits updated live; the status then reports the new values.
    fn apply_resize(&self, uid: &str, pod: &Value) {
        let mut pods = self.pods.borrow_mut();
        let others: (u64, u64) = pods.iter().filter(|(u, p)| u.as_str() != uid && p.failed_setup.is_none() && p.evicted.is_none() && p.sandbox.is_some()).fold((0, 0), |a, (_, p)| (a.0 + p.cpu_request, a.1 + p.mem_request));
        let Some(p) = pods.get_mut(uid) else { return };
        // A container restarting for a resize that ignores SIGTERM is killed at the grace period.
        for c in p.ctrs.iter().filter(|c| c.resize_restart && c.resize_kill_at > 0 && now_ms() >= c.resize_kill_at) {
            if let Some(s) = &c.signaller {
                let _ = s.send(9);
            }
        }
        let mut diff = false;
        for key in ["initContainers", "containers"] {
            for c in pod.pointer(&["spec", key]).and_then(Value::as_array).unwrap_or(&[]) {
                let name = c.get("name").and_then(Value::as_str).unwrap_or("");
                let want = c.get("resources").map(json::to_string).unwrap_or_default();
                diff |= p.ctrs.iter().any(|x| x.name == name && !x.eph && x.res != want);
            }
        }
        if !diff {
            p.resize_pending = None;
            return;
        }
        // Feasibility against the node (capacity is also what is allocatable here).
        let (cap_cpu, cap_mem) = (node::cpus() as u64 * 1000, node::memory_ki() * 1024);
        let (want_cpu, want_mem) = (spec::cpu_request(pod), spec::pod_resources(pod).1);
        if want_cpu > cap_cpu || want_mem > cap_mem {
            let msg = alloc::format!("Node didn't have enough capacity: {}, requested: {}, capacity: {}", if want_cpu > cap_cpu { "cpu" } else { "memory" }, if want_cpu > cap_cpu { want_cpu } else { want_mem }, if want_cpu > cap_cpu { cap_cpu } else { cap_mem });
            p.resize_pending = Some(("Infeasible", msg));
            return;
        }
        if others.0 + want_cpu > cap_cpu || others.1 + want_mem > cap_mem {
            let msg = alloc::format!("Node didn't have enough resource: {}, requested: {}, used: {}, capacity: {}", if others.0 + want_cpu > cap_cpu { "cpu" } else { "memory" }, if others.0 + want_cpu > cap_cpu { want_cpu } else { want_mem }, if others.0 + want_cpu > cap_cpu { others.0 } else { others.1 }, if others.0 + want_cpu > cap_cpu { cap_cpu } else { cap_mem });
            p.resize_pending = Some(("Deferred", msg));
            return;
        }
        p.resize_pending = None;
        let mut changed = false;
        for key in ["initContainers", "containers"] {
            for c in pod.pointer(&["spec", key]).and_then(Value::as_array).unwrap_or(&[]) {
                let name = c.get("name").and_then(Value::as_str).unwrap_or("");
                let want = c.get("resources").map(json::to_string).unwrap_or_default();
                let rel = p.cg.as_ref().map(|cg| cg.rel().to_vec());
                let Some(ctr) = p.ctrs.iter_mut().find(|x| x.name == name && !x.eph) else { continue };
                if ctr.res == want {
                    continue;
                }
                let restart = spec::resize_needs_restart(c, &ctr.res, &want);
                if let (CState::Running { id, .. }, Some(rel)) = (&ctr.state, rel) {
                    if !restart {
                        let _ = kr_runtime::cgroup::update_container(&rel, id.as_bytes(), &spec::container_limits(pod, c));
                    }
                }
                if restart && matches!(ctr.state, CState::Running { .. }) {
                    if let Some(s) = ctr.signaller.clone() {
                        ctr.resize_restart = true;
                        let grace = pod.pointer(&["spec", "terminationGracePeriodSeconds"]).and_then(Value::as_u64).unwrap_or(30);
                        ctr.resize_kill_at = now_ms() + grace * 1000;
                        let _ = s.send(kr_sys::ns::SIGTERM);
                    }
                }
                ctr.res = want;
                changed = true;
            }
        }
        p.cpu_request = want_cpu;
        p.mem_request = want_mem;
        if let (true, Some(cg)) = (changed, &p.cg) {
            let _ = cg.update(&spec::pod_resources(pod).0);
        }
    }

    /// Records an event for the pod (best effort), as the kubelet's recorder does.
    async fn emit_event(&self, pod: &Value, ty: &str, reason: &str, message: &str) {
        let ns = meta(pod, "namespace");
        let at = Value::String(rfc3339(now()));
        let o = |f: Vec<(&str, Value)>| Value::Object(f.into_iter().map(|(k, v)| (String::from(k), v)).collect());
        let ev = o(alloc::vec![
            ("apiVersion", Value::from("v1")),
            ("kind", Value::from("Event")),
            ("metadata", o(alloc::vec![("generateName", Value::String(alloc::format!("{}.", meta(pod, "name")))), ("namespace", Value::from(ns))])),
            ("involvedObject", o(alloc::vec![("apiVersion", Value::from("v1")), ("kind", Value::from("Pod")), ("namespace", Value::from(ns)), ("name", Value::from(meta(pod, "name"))), ("uid", Value::from(meta(pod, "uid")))])),
            ("type", Value::from(ty)),
            ("reason", Value::from(reason)),
            ("message", Value::from(message)),
            ("source", o(alloc::vec![("component", Value::from("kubelet")), ("host", Value::from(self.cfg.node_name.as_str()))])),
            ("reportingComponent", Value::from("kubelet")),
            ("reportingInstance", Value::from(self.cfg.node_name.as_str())),
            ("firstTimestamp", at.clone()),
            ("lastTimestamp", at),
            ("count", Value::Number(kr_fmt::json::Number::from_i64(1))),
        ]);
        let _ = self.c.create(&alloc::format!("/api/v1/namespaces/{ns}/events"), &ev).await;
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
            let since = self.pods.borrow_mut().get_mut(uid).map(|p| *p.stopped_at.get_or_insert_with(now_ms));
            self.report_final_status(uid, pod).await;
            if since.is_some_and(|t| now_ms().saturating_sub(t) < 300) {
                return;
            }
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
        self.devices.release_pod(uid);
        let (csi, u) = (self.csi.clone(), uid.to_string());
        kr_rt::exec::spawn(async move { csi.unmount_pod(&u).await });
        self.stdin_keep.borrow_mut().retain(|k, _| !k.starts_with(&alloc::format!("{}/", p.dir)));
        if let Some(sb) = &p.sandbox {
            sb.stop();
        }
        if let Some(cg) = &p.cg {
            cg.remove();
        }
        if let Some(l) = p.lease {
            l.release();
        }
        // CNI: tear down the pod's network attachment (a plugin may call back into this process, so
        // it runs as a task, not inline).
        if cni::is_enabled() && p.sandbox.is_some() {
            if let Ok(cfg) = cni::load_config(&cni::conf_dir().unwrap()) {
                let netns = alloc::format!("/proc/{}/ns/net", p.sandbox.as_ref().map(|s| s.pid).unwrap_or(0));
                let args = alloc::format!("IgnoreUnknown=1;K8S_POD_NAMESPACE={};K8S_POD_NAME={};K8S_POD_INFRA_CONTAINER_ID={uid}", p.ns, p.name);
                let uid = uid.to_string();
                kr_rt::exec::spawn(async move {
                    let _ = cni::cni_del(&cfg, &uid, &netns, "eth0", &args).await;
                });
            }
        }
        let _ = self.maps.run_as_root(|| remove_tree(&p.dir));
    }

    /// Builds the pod status and patches it if it changed.
    async fn report_status(&self, uid: &str, pod: &Value) {
        let (status, path) = {
            let mut pods = self.pods.borrow_mut();
            let Some(p) = pods.get_mut(uid) else { return };
            let policy = pod.pointer(&["spec", "restartPolicy"]).and_then(Value::as_str).unwrap_or("Always");
            kr_rt::exec::phase("report_status: status_json");
            let mut status = status_json(p, policy);
            if let Some(r) = pod.pointer(&["spec", "resources"]).filter(|r| r.as_object().is_some_and(|m| !m.is_empty())) {
                status.set("resources", r.clone());
            }
            stamp_conditions(p, &mut status, pod.pointer(&["metadata", "generation"]).and_then(Value::as_i64).unwrap_or(0));
            keep_foreign_conditions(pod, &mut status);
            (status, alloc::format!("/api/v1/namespaces/{}/pods/{}/status", p.ns, p.name))
        };
        kr_rt::exec::phase("report_status: serialise");
        let text = json::to_string(&status);
        // The node controller marks pods of an unreachable node not Ready; when this kubelet is
        // back and the API disagrees with what it computed, write again despite the cache.
        let ready_of = |v: &Value| v.pointer(&["status", "conditions"]).or_else(|| v.get("conditions")).and_then(Value::as_array).and_then(|c| c.iter().find(|x| x.get("type").and_then(Value::as_str) == Some("Ready"))).and_then(|c| c.get("status")).and_then(Value::as_str).map(String::from);
        let api_agrees = ready_of(pod) == ready_of(&status);
        // Leftovers of an earlier status (see below) must be cleared even when nothing changed.
        let has_key = |k: &str| status.get(k).is_some();
        let leftovers = (matches!(pod.pointer(&["status", "reason"]).and_then(Value::as_str), Some("SandboxFailed" | "HostPortConflict" | "SysctlForbidden")) && !has_key("reason"))
            || (!has_key("containerStatuses") && pod.pointer(&["status", "containerStatuses"]).is_some_and(|v| !v.is_null()))
            || (!has_key("initContainerStatuses") && pod.pointer(&["status", "initContainerStatuses"]).is_some_and(|v| !v.is_null()));
        if api_agrees && !leftovers && self.pods.borrow().get(uid).is_some_and(|p| p.last_status == text) {
            return;
        }
        let mut status = status;
        if let Value::Object(f) = &mut status {
            f.push((String::from("qosClass"), Value::from(spec::qos_class(pod))));
            // A merge patch keeps fields it omits: drop what an earlier status of this kubelet
            // left behind (a failed sandbox's reason/message once the pod runs, the
            // ContainerCreating statuses of a pod that was rejected).
            let (h_reason, h_msg, h_cs, h_ics) = (f.iter().any(|(n, _)| n == "reason"), f.iter().any(|(n, _)| n == "message"), f.iter().any(|(n, _)| n == "containerStatuses"), f.iter().any(|(n, _)| n == "initContainerStatuses"));
            let stale = matches!(pod.pointer(&["status", "reason"]).and_then(Value::as_str), Some("SandboxFailed" | "HostPortConflict" | "SysctlForbidden"));
            if stale && !h_reason {
                f.push((String::from("reason"), Value::Null));
                if !h_msg {
                    f.push((String::from("message"), Value::Null));
                }
            }
            if !h_cs && pod.pointer(&["status", "containerStatuses"]).is_some() {
                f.push((String::from("containerStatuses"), Value::Null));
            }
            if !h_ics && pod.pointer(&["status", "initContainerStatuses"]).is_some() {
                f.push((String::from("initContainerStatuses"), Value::Null));
            }
        }
        let patch = Value::Object(alloc::vec![(String::from("status"), status)]);
        kr_rt::exec::phase("report_status: patch");
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
        keep_foreign_conditions(pod, &mut status);
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

/// Conditions other components set on the pod (`DisruptionTarget` from the scheduler or the
/// eviction API, ...) survive the kubelet's status writes, which replace the whole list.
fn keep_foreign_conditions(pod: &Value, status: &mut Value) {
    const OWNED: [&str; 7] = ["PodScheduled", "Initialized", "ContainersReady", "Ready", "PodReadyToStartContainers", "PodResizeInProgress", "PodResizePending"];
    let old: Vec<Value> = pod.pointer(&["status", "conditions"]).and_then(Value::as_array).map(|a| a.iter().filter(|c| !OWNED.contains(&c.get("type").and_then(Value::as_str).unwrap_or(""))).cloned().collect()).unwrap_or_default();
    if old.is_empty() {
        return;
    }
    if let Some(Value::Array(conds)) = status.get_mut("conditions") {
        conds.extend(old);
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
        if let Ok(r) = json::parse(c.res.as_bytes()) {
            if let Some(req) = r.get("requests").filter(|q| q.as_object().is_some_and(|m| !m.is_empty())) {
                f.push(("allocatedResources", req.clone()));
            }
            f.push(("resources", r));
        } else {
            f.push(("resources", o(Vec::new())));
        }
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
    let host_ip = kr_net::tcp::fmt_ip16(p.node_ip);
    let mut conditions = alloc::vec![cond("PodScheduled", true, None), cond("Initialized", inits_done, init_why), cond("Ready", all_running, notready()), cond("ContainersReady", all_running, notready())];
    if let Some((reason, msg)) = &p.resize_pending {
        conditions.push(o(alloc::vec![("type", Value::from("PodResizePending")), ("status", Value::from("True")), ("lastTransitionTime", t(p.start_time)), ("reason", Value::from(*reason)), ("message", Value::from(msg.as_str()))]));
    } else if p.ctrs.iter().any(|c| c.resize_restart) {
        conditions.push(o(alloc::vec![("type", Value::from("PodResizeInProgress")), ("status", Value::from("True")), ("lastTransitionTime", t(p.start_time))]));
    }
    let mut f = alloc::vec![
        ("phase", Value::from(phase)),
        ("conditions", Value::Array(conditions)),
        ("hostIP", Value::from(host_ip.as_str())),
        ("hostIPs", Value::Array(alloc::vec![o(alloc::vec![("ip", Value::from(host_ip.as_str()))])])),
        ("startTime", t(p.start_time)),
    ];
    // A pod rejected (or whose sandbox failed) never started a container: its waiting
    // `ContainerCreating` statuses would hide the failure reason in `kubectl get pods`.
    if p.failed_setup.is_none() {
        f.push(("containerStatuses", Value::Array(apps.iter().map(|c| cstat(c)).collect())));
    }
    let inits: Vec<Value> = p.ctrs.iter().filter(|c| c.init).map(cstat).collect();
    if !inits.is_empty() && p.failed_setup.is_none() {
        f.push(("initContainerStatuses", Value::Array(inits)));
    }
    let ephs: Vec<Value> = p.ctrs.iter().filter(|c| c.eph).map(cstat).collect();
    if !ephs.is_empty() {
        f.push(("ephemeralContainerStatuses", Value::Array(ephs)));
    }
    // podIP is the primary address: IPv4 when the pod has one, else its IPv6 (IPv6-only network).
    let ip6 = p.ip6.map(|a| network::ipv6_string(a));
    if let Some(primary) = ip.as_ref().or(ip6.as_ref()) {
        f.push(("podIP", Value::from(primary.as_str())));
        let ips: Vec<Value> = ip.iter().chain(ip6.iter()).map(|a| o(alloc::vec![("ip", Value::from(a.as_str()))])).collect();
        f.push(("podIPs", Value::Array(ips)));
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
        f.push(("reason", Value::from(if msg.contains("forbidden sysctl") { "SysctlForbidden" } else if msg.starts_with("Pod was rejected") { "HostPortConflict" } else { "SandboxFailed" })));
    }
    o(f)
}
/// (hostIP, protocol, hostPort) of every container port that asks for a host port.
fn host_ports(pod: &Value) -> Vec<(String, String, u64)> {
    let mut out = Vec::new();
    // hostNetwork: containerPort is the host port (hostPort, if set, must equal it).
    let host_net = pod.pointer(&["spec", "hostNetwork"]).and_then(Value::as_bool) == Some(true);
    for key in ["initContainers", "containers"] {
        for c in pod.pointer(&["spec", key]).and_then(Value::as_array).unwrap_or(&[]) {
            for p in c.get("ports").and_then(Value::as_array).unwrap_or(&[]) {
                let hp = p.get(if host_net { "containerPort" } else { "hostPort" }).and_then(Value::as_u64).unwrap_or(0);
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
        Ctr { name: name.into(), image: "img".into(), init, sidecar: false, eph, restart_count: 0, state, last_term: None, signaller: None, not_before: 0, backoff_ms: 0, seq: 0, target: None, probes: Vec::new(), started: true, ready: true, res: String::new(), resize_restart: false, resize_kill_at: 0, proc: None, io: None, shim: 0 }
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
        PodRt { ns: "d".into(), name: "p".into(), dir: String::new(), sandbox: None, lease: None, ip: None, ip6: None, node_ip: kr_sys::map4([10, 0, 0, 1]), ctrs, start_time: 0, kill_at: None, stopped_at: None, last_status: String::new(), failed_setup: None, volumes_synced: 0, cg: None, qos: "BestEffort", mem_request: 0, cpu_request: 0, resize_pending: None, critical: false, evicted: None, deadline_exceeded: false, conds: Vec::new(), host_ports: Vec::new(), sandbox_retry_at: 0, pvcs: None }
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
    fn host_ip_and_host_network_ports() {
        let st = status_json(&pod(vec![ctr("run1", false, false, creating())]), "Always");
        assert_eq!(s(&st, &["hostIP"]), Some("10.0.0.1"));
        assert_eq!(s(&st, &["hostIPs", "0", "ip"]), Some("10.0.0.1"));
        let hn = kr_fmt::json::parse_str(r#"{"spec":{"hostNetwork":true,"containers":[{"ports":[{"containerPort":8080}]}]}}"#).unwrap();
        assert_eq!(host_ports(&hn), vec![(String::new(), "TCP".to_string(), 8080)]);
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
    fn rejected_pod_reports_reason_without_container_statuses() {
        let mut p = pod(vec![ctr("run1", false, false, creating())]);
        p.failed_setup = Some("Pod was rejected: node(s) didn't have free ports for the requested pod ports".into());
        let st = status_json(&p, "Always");
        assert_eq!(s(&st, &["phase"]), Some("Failed"));
        assert_eq!(s(&st, &["reason"]), Some("HostPortConflict"));
        assert!(st.get("containerStatuses").is_none());
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
const WG_DEV: &str = "kr.wg";
const WG_KEY_KEY: &str = "kr.io/wireguard-public-key";
const WG_ENDPOINT_KEY: &str = "kr.io/wireguard-endpoint";

/// `ip:port` or `[ip6]:port` from the endpoint annotation, 16-byte form.
fn parse_endpoint(s: &str) -> Option<([u8; 16], u16)> {
    let (ip, port) = s.rsplit_once(':')?;
    Some((kr_net::tcp::parse_ip16(ip.trim_start_matches('[').trim_end_matches(']'))?, port.parse().ok()?))
}

/// A peer node's WireGuard allowed IPs: its pod subnet(s) of the families both sides run.
fn peer_allowed(pn: network::PodNet, nfam: network::Families, mine: network::Families) -> Vec<([u8; 16], u8)> {
    let mut v = Vec::new();
    if mine.v4 && nfam.v4 {
        v.push((kr_sys::map4(pn.subnet), 96 + pn.prefix));
    }
    if mine.v6 && nfam.v6 {
        v.push((network::subnet6(pn.subnet), network::POD_PREFIX6));
    }
    v
}

/// The peer's backend when it differs from ours. A peer without the annotation (older kr,
/// or not registered its backend yet) is not a mismatch: VXLAN still needs its VTEP annotations.
/// host-gw routes to a VXLAN peer cannot work (and the reverse), so mismatched peers are skipped.
fn backend_mismatch<'a>(mine: &str, theirs: Option<&'a str>) -> Option<&'a str> {
    theirs.filter(|t| *t != mine)
}

/// The Node's first `InternalIP` of the wanted family (IPv6 when `v6`), 16-byte form.
/// A Node's pod subnet and address families from `spec.podCIDRs` (falling back to `podCIDR`).
fn node_podnet(n: &Value) -> Option<(network::PodNet, network::Families)> {
    let list: Vec<&str> = n.pointer(&["spec", "podCIDRs"]).and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    if list.is_empty() {
        return n.pointer(&["spec", "podCIDR"]).and_then(Value::as_str).and_then(|c| network::PodNet::from_cidrs([c]));
    }
    network::PodNet::from_cidrs(list)
}

fn internal_ip(n: &Value, v6: bool) -> Option<[u8; 16]> {
    n.pointer(&["status", "addresses"]).and_then(Value::as_array)?.iter().filter(|x| x.get("type").and_then(Value::as_str) == Some("InternalIP")).filter_map(|x| x.get("address").and_then(Value::as_str).and_then(kr_net::tcp::parse_ip16)).find(|a| kr_sys::unmap4(*a).is_none() == v6)
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
fn route_diff<A: PartialEq + Copy>(want: &[(A, u8, A)], have: &[(A, u8, Option<A>)]) -> (Vec<(A, u8, A)>, Vec<(A, u8)>) {
    let add = want.iter().filter(|w| !have.iter().any(|h| h.0 == w.0 && h.1 == w.1 && h.2 == Some(w.2))).copied().collect();
    let del = have.iter().filter(|h| !want.iter().any(|w| w.0 == h.0 && w.1 == h.1 && Some(w.2) == h.2)).map(|h| (h.0, h.1)).collect();
    (add, del)
}

#[cfg(test)]
mod route_tests {
    use super::{backend_mismatch, parse_endpoint, peer_allowed, route_diff, set_diff};
    use kr_runtime::network;

    #[test]
    fn backend_mismatch_detected() {
        assert_eq!(backend_mismatch("vxlan", Some("vxlan")), None);
        assert_eq!(backend_mismatch("vxlan", None), None);
        assert_eq!(backend_mismatch("vxlan", Some("host-gw")), Some("host-gw"));
        assert_eq!(backend_mismatch("host-gw", Some("vxlan")), Some("vxlan"));
    }

    #[test]
    fn wireguard_peer_allowed_ips_follow_the_shared_families() {
        let pn = network::PodNet::parse("10.88.3.0/24").unwrap();
        let both = network::Families::DUAL;
        let v4 = network::Families { v4: true, v6: false };
        assert_eq!(peer_allowed(pn, both, both), alloc::vec![(kr_sys::map4([10, 88, 3, 0]), 120), (network::subnet6(pn.subnet), network::POD_PREFIX6)]);
        assert_eq!(peer_allowed(pn, v4, both), alloc::vec![(kr_sys::map4([10, 88, 3, 0]), 120)]);
        assert_eq!(peer_allowed(pn, both, v4).len(), 1);
    }

    #[test]
    fn wireguard_endpoint_annotation_parses() {
        assert_eq!(parse_endpoint("192.168.1.2:51820"), Some((kr_sys::map4([192, 168, 1, 2]), 51820)));
        assert_eq!(parse_endpoint("[fd00::1]:7").map(|e| e.1), Some(7));
        assert_eq!(parse_endpoint("nonsense"), None);
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
        // The same diff for IPv6 routes (stale ones go, new ones come).
        let (p1, p2, g1, g2) = ([0xfd; 16], [0xfc; 16], [1u8; 16], [2u8; 16]);
        let (add6, del6) = route_diff(&[(p1, 64, g1), (p2, 64, g2)], &[(p1, 64, Some(g1)), ([0xfb; 16], 64, Some(g2))]);
        assert_eq!((add6, del6), (alloc::vec![(p2, 64, g2)], alloc::vec![([0xfb; 16], 64)]));
        assert_eq!(add, [b]);
        assert_eq!(del, [([10, 88, 9, 0], 24)]);
        // gateway change: delete then re-add
        let (add, del) = route_diff(&[a], &[(a.0, 24, Some([9, 9, 9, 9]))]);
        assert_eq!((add.len(), del.len()), (1, 1));
    }
}
