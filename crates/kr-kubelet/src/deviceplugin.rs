//! Kubernetes Device Plugin API (v1beta1) over the in-tree gRPC layer (ADR-038).
//!
//! Plugins register on `<dir>/kubelet.sock`; per registration a manager task connects back to
//! the plugin's socket, follows `ListAndWatch` and keeps the resource's device list. Containers
//! that limit a registered resource get devices through `Allocate` (see [`Plugins::allocate`]).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use kr_fmt::json::{self, Value};
use kr_fmt::proto::{Field, Reader, Writer};
use kr_net::grpc::{self, Client, Responder, Status};
use kr_rt::exec::{sleep, spawn, Async, JoinHandle};

const REGISTER: &str = "/v1beta1.Registration/Register";
const GET_OPTIONS: &str = "/v1beta1.DevicePlugin/GetDevicePluginOptions";
const LIST_AND_WATCH: &str = "/v1beta1.DevicePlugin/ListAndWatch";
const ALLOCATE: &str = "/v1beta1.DevicePlugin/Allocate";
const PREFERRED: &str = "/v1beta1.DevicePlugin/GetPreferredAllocation";
const PRE_START: &str = "/v1beta1.DevicePlugin/PreStartContainer";
const INVALID_ARGUMENT: u32 = 3;

/// Directory for plugin sockets: the kubelet's well-known path as real root, else under `root`.
pub fn default_dir(root: &str) -> String {
    if let Some(d) = kr_runtime::store::env_var("KR_DEVICE_PLUGIN_DIR").filter(|d| d.starts_with('/')) {
        return d;
    }
    if kr_sys::ns::getuid() == 0 {
        "/var/lib/kubelet/device-plugins".to_string()
    } else {
        format!("{root}/device-plugins")
    }
}

// ------------------------------------------------------------------ protobuf

fn walk(buf: &[u8], mut f: impl FnMut(u32, &Field<'_>)) -> Result<(), ()> {
    let mut r = Reader::new(buf);
    while let Some(x) = r.next().map_err(|_| ())? {
        f(x.number, &x);
    }
    Ok(())
}

#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct Options {
    pub pre_start_required: bool,
    pub preferred_allocation: bool,
}

#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct RegisterRequest {
    pub version: String,
    pub endpoint: String,
    pub resource_name: String,
    pub options: Options,
}

pub fn decode_options(b: &[u8]) -> Result<Options, ()> {
    let mut o = Options::default();
    walk(b, |n, f| match n {
        1 => o.pre_start_required = f.as_bool().unwrap_or(false),
        2 => o.preferred_allocation = f.as_bool().unwrap_or(false),
        _ => {}
    })?;
    Ok(o)
}

pub fn decode_register(b: &[u8]) -> Result<RegisterRequest, ()> {
    let mut r = RegisterRequest::default();
    let mut opts: Option<Vec<u8>> = None;
    walk(b, |n, f| match n {
        1 => r.version = f.as_str().unwrap_or("").to_string(),
        2 => r.endpoint = f.as_str().unwrap_or("").to_string(),
        3 => r.resource_name = f.as_str().unwrap_or("").to_string(),
        4 => opts = f.as_bytes().map(<[u8]>::to_vec),
        _ => {}
    })?;
    if let Some(o) = opts {
        r.options = decode_options(&o)?;
    }
    Ok(r)
}

/// `ListAndWatchResponse` -> (device id, healthy).
pub fn decode_devices(b: &[u8]) -> Result<Vec<(String, bool)>, ()> {
    let mut out = Vec::new();
    walk(b, |n, f| {
        if n != 1 {
            return;
        }
        let (mut id, mut health) = (String::new(), String::new());
        let _ = walk(f.as_bytes().unwrap_or(&[]), |n, f| match n {
            1 => id = f.as_str().unwrap_or("").to_string(),
            2 => health = f.as_str().unwrap_or("").to_string(),
            _ => {}
        });
        if !id.is_empty() {
            out.push((id, health == "Healthy"));
        }
    })?;
    Ok(out)
}

/// `ListAndWatchResponse` -> (device id, first NUMA node of its topology hint).
pub fn decode_numa(b: &[u8]) -> Vec<(String, i64)> {
    let mut out = Vec::new();
    let _ = walk(b, |n, f| {
        if n != 1 {
            return;
        }
        let (mut id, mut node) = (String::new(), None);
        let _ = walk(f.as_bytes().unwrap_or(&[]), |n, f| match n {
            1 => id = f.as_str().unwrap_or("").to_string(),
            3 => {
                let _ = walk(f.as_bytes().unwrap_or(&[]), |n, f| {
                    if n == 1 && node.is_none() {
                        let _ = walk(f.as_bytes().unwrap_or(&[]), |n, f| {
                            if n == 1 {
                                node = f.as_varint().map(|v| v as i64);
                            }
                        });
                    }
                });
            }
            _ => {}
        });
        if let (false, Some(n)) = (id.is_empty(), node) {
            out.push((id, n));
        }
    });
    out
}

/// What one container gets from `Allocate` (and, merged, from CDI).
#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct Grant {
    pub envs: Vec<(String, String)>,
    /// (container path, host path, read only)
    pub mounts: Vec<(String, String, bool)>,
    /// (container path, host path, permissions)
    pub devices: Vec<(String, String, String)>,
    pub annotations: Vec<(String, String)>,
    pub cdi: Vec<String>,
    /// `additionalGids` of the CDI edits: supplementary groups of the container's processes (the
    /// group of the device nodes, so non-root users may open them).
    pub gids: Vec<u32>,
    /// OCI hooks of the CDI edits (run by the container runtime at their lifecycle stage).
    pub hooks: kr_runtime::hooks::Hooks,
    /// CDI hooks that cannot be honoured (unknown stage, relative path); a container that needs
    /// them must not start without them.
    pub bad_hooks: Vec<String>,
}

fn kv(b: &[u8]) -> (String, String) {
    let (mut k, mut v) = (String::new(), String::new());
    let _ = walk(b, |n, f| match n {
        1 => k = f.as_str().unwrap_or("").to_string(),
        2 => v = f.as_str().unwrap_or("").to_string(),
        _ => {}
    });
    (k, v)
}

fn decode_container_response(b: &[u8]) -> Result<Grant, ()> {
    let mut g = Grant::default();
    walk(b, |n, f| {
        let m = f.as_bytes().unwrap_or(&[]);
        match n {
            1 => g.envs.push(kv(m)),
            4 => g.annotations.push(kv(m)),
            2 | 3 => {
                let (mut cp, mut hp, mut x, mut ro) = (String::new(), String::new(), String::new(), false);
                let is_mount = n == 2;
                let _ = walk(m, |k, f| match k {
                    1 => cp = f.as_str().unwrap_or("").to_string(),
                    2 => hp = f.as_str().unwrap_or("").to_string(),
                    3 if is_mount => ro = f.as_bool().unwrap_or(false),
                    3 => x = f.as_str().unwrap_or("").to_string(),
                    _ => {}
                });
                if is_mount {
                    g.mounts.push((cp, hp, ro));
                } else {
                    g.devices.push((cp, hp, x));
                }
            }
            5 => {
                let (n, _) = kv(m);
                if !n.is_empty() {
                    g.cdi.push(n);
                }
            }
            _ => {}
        }
    })?;
    Ok(g)
}

/// `AllocateResponse` -> the first container response (we always ask for one container).
pub fn decode_allocate(b: &[u8]) -> Result<Grant, ()> {
    let mut first: Option<Result<Grant, ()>> = None;
    walk(b, |n, f| {
        if n == 1 && first.is_none() {
            first = Some(decode_container_response(f.as_bytes().unwrap_or(&[])));
        }
    })?;
    first.unwrap_or(Err(()))
}

/// Every container response of an `AllocateResponse`, in order.
pub fn decode_allocate_all(b: &[u8]) -> Result<Vec<Grant>, ()> {
    let mut out = Vec::new();
    let mut bad = false;
    walk(b, |n, f| {
        if n == 1 {
            match decode_container_response(f.as_bytes().unwrap_or(&[])) {
                Ok(g) => out.push(g),
                Err(()) => bad = true,
            }
        }
    })?;
    if bad {
        Err(())
    } else {
        Ok(out)
    }
}

/// `AllocateRequest` with one container request per entry.
fn encode_batch(containers: &[Vec<String>]) -> Vec<u8> {
    let mut w = Writer::new();
    for ids in containers {
        w.message(1, |w| {
            for i in ids {
                w.string(1, i);
            }
        });
    }
    w.into_bytes()
}

/// `PreferredAllocationRequest` for one container: pick `size` of `available`.
fn encode_preferred(available: &[String], must_include: &[String], size: usize) -> Vec<u8> {
    let mut w = Writer::new();
    w.message(1, |w| {
        for i in available {
            w.string(1, i);
        }
        for i in must_include {
            w.string(2, i);
        }
        w.varint(3, size as u64);
    });
    w.into_bytes()
}

/// First container response of a `PreferredAllocationResponse`.
fn decode_preferred(b: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = false;
    let _ = walk(b, |n, f| {
        if n == 1 && !seen {
            seen = true;
            let _ = walk(f.as_bytes().unwrap_or(&[]), |n, f| {
                if n == 1 {
                    out.push(f.as_str().unwrap_or("").to_string());
                }
            });
        }
    });
    out
}

/// Picks `n` of the free devices (id, NUMA node or -1) when the plugin gave no preference: all on
/// one NUMA node if some node has enough (the one with the fewest free devices that still fits,
/// to keep big nodes whole), else the first ones.
fn choose(free: &[(String, i64)], n: usize) -> Vec<String> {
    let mut nodes: BTreeMap<i64, Vec<&String>> = BTreeMap::new();
    for (id, node) in free {
        if *node >= 0 {
            nodes.entry(*node).or_default().push(id);
        }
    }
    if let Some(best) = nodes.values().filter(|v| v.len() >= n).min_by_key(|v| v.len()) {
        return best.iter().take(n).map(|s| (*s).clone()).collect();
    }
    free.iter().take(n).map(|d| d.0.clone()).collect()
}

fn encode_ids(ids: &[String], with_container: bool) -> Vec<u8> {
    let body = |w: &mut Writer| {
        for i in ids {
            w.string(1, i);
        }
    };
    let mut w = Writer::new();
    if with_container {
        w.message(1, body);
    } else {
        body(&mut w);
    }
    w.into_bytes()
}

// ------------------------------------------------------------------ CDI

/// CDI spec directories: `/etc/cdi` and `/var/run/cdi`, or the colon-separated absolute paths in
/// `KR_CDI_DIRS` (operator-set, like the NVIDIA toolkit's own override; tests).
fn cdi_dirs() -> Vec<String> {
    match kr_runtime::store::env_var("KR_CDI_DIRS") {
        Some(v) => v.split(':').filter(|d| d.starts_with('/')).map(String::from).collect(),
        None => alloc::vec!["/etc/cdi".to_string(), "/var/run/cdi".to_string()],
    }
}

/// Applies the `containerEdits` object of a CDI spec or device to `g`.
fn cdi_edits(e: &Value, g: &mut Grant) {
    for s in e.get("env").and_then(Value::as_array).unwrap_or(&[]) {
        if let Some((k, v)) = s.as_str().and_then(|s| s.split_once('=')) {
            g.envs.push((k.to_string(), v.to_string()));
        }
    }
    for d in e.get("deviceNodes").and_then(Value::as_array).unwrap_or(&[]) {
        let Some(p) = d.get("path").and_then(Value::as_str) else { continue };
        let host = d.get("hostPath").and_then(Value::as_str).unwrap_or(p);
        g.devices.push((p.to_string(), host.to_string(), d.get("permissions").and_then(Value::as_str).unwrap_or("rw").to_string()));
    }
    for m in e.get("mounts").and_then(Value::as_array).unwrap_or(&[]) {
        let (Some(h), Some(c)) = (m.get("hostPath").and_then(Value::as_str), m.get("containerPath").and_then(Value::as_str)) else { continue };
        let ro = m.get("options").and_then(Value::as_array).unwrap_or(&[]).iter().any(|o| o.as_str() == Some("ro"));
        g.mounts.push((c.to_string(), h.to_string(), ro));
    }
    for gid in e.get("additionalGids").and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(Value::as_u64).filter_map(|g| u32::try_from(g).ok()) {
        if !g.gids.contains(&gid) {
            g.gids.push(gid);
        }
    }
    for h in e.get("hooks").and_then(Value::as_array).unwrap_or(&[]) {
        let strs = |k: &str| -> Vec<Vec<u8>> { h.get(k).and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(Value::as_str).map(|s| s.as_bytes().to_vec()).collect() };
        let path = h.get("path").and_then(Value::as_str).unwrap_or("");
        let stage = h.get("hookName").and_then(Value::as_str).unwrap_or("");
        let hook = kr_runtime::hooks::Hook { path: path.as_bytes().to_vec(), args: strs("args"), env: strs("env"), timeout: h.get("timeout").and_then(Value::as_u64).unwrap_or(0).min(3600) as u32 };
        if !g.hooks.add(stage, hook) {
            g.bad_hooks.push(format!("{stage} {path}"));
        }
    }
}

/// RuntimeClass handlers that stand for the NVIDIA container runtime. The handler is read from the
/// pod's `RuntimeClass` object, so the class can have any name.
pub fn is_nvidia_handler(name: &str) -> bool {
    matches!(name, "nvidia" | "nvidia-cdi" | "nvidia-legacy")
}

/// What `NVIDIA_VISIBLE_DEVICES=<value>` means under an NVIDIA runtime class, as CDI device
/// names (`all`, indexes, `GPU-` UUIDs). Empty for unset, `none`, `void` and anything else.
pub fn visible_devices_to_cdi(value: &str) -> Vec<String> {
    let v = value.trim();
    if matches!(v, "" | "none" | "void" | "NONE" | "VOID") {
        return Vec::new();
    }
    v.split(',').map(str::trim).filter(|t| *t == "all" || t.starts_with("GPU-") || (!t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()))).map(|t| format!("nvidia.com/gpu={t}")).collect()
}

/// Resolves CDI device names to a grant from the host's CDI specs.
pub fn cdi_grant(names: &[String]) -> Result<Grant, String> {
    let mut g = Grant::default();
    let dirs = cdi_dirs();
    cdi_resolve(&dirs.iter().map(String::as_str).collect::<Vec<_>>(), names, &mut g)?;
    Ok(g)
}

/// Resolves `vendor/class=name` against a parsed CDI spec; true if the spec defines it.
fn cdi_apply(spec: &Value, name: &str, g: &mut Grant) -> bool {
    let Some((kind, dev)) = name.split_once('=') else { return false };
    if spec.get("kind").and_then(Value::as_str) != Some(kind) {
        return false;
    }
    let Some(d) = spec.get("devices").and_then(Value::as_array).unwrap_or(&[]).iter().find(|d| d.get("name").and_then(Value::as_str) == Some(dev)) else { return false };
    if let Some(e) = spec.get("containerEdits") {
        cdi_edits(e, g);
    }
    if let Some(e) = d.get("containerEdits") {
        cdi_edits(e, g);
    }
    true
}

fn cdi_resolve(dirs: &[&str], names: &[String], g: &mut Grant) -> Result<(), String> {
    let mut specs: Vec<Value> = Vec::new();
    let mut untrusted: Vec<String> = Vec::new();
    for dir in dirs {
        let Ok(fd) = kr_sys::ns::open(format!("{dir}\0").as_bytes(), kr_sys::ns::O_RDONLY | kr_sys::ns::O_DIRECTORY, 0) else { continue };
        let mut files: Vec<String> = kr_sys::fs::read_dir(&fd).filter_map(Result::ok).filter_map(|e| String::from_utf8(e.name).ok()).filter(|n| n.ends_with(".json") || n.ends_with(".yaml") || n.ends_with(".yml")).collect();
        files.sort();
        for f in files {
            // Specs can name programs the runtime executes as root: only root-owned (or our own),
            // not group/world-writable files count.
            let trusted = kr_sys::fs::newfstatat(kr_sys::ns::AT_FDCWD, format!("{dir}/{f}\0").as_bytes(), 0).is_ok_and(|st| (st.uid == 0 || st.uid == kr_sys::ns::getuid()) && st.mode & 0o022 == 0);
            if !trusted {
                untrusted.push(format!("{dir}/{f}"));
                continue;
            }
            let Ok(b) = kr_sys::fs::read_file(format!("{dir}/{f}\0").as_bytes(), 8 << 20) else { continue };
            let v = if f.ends_with(".json") { json::parse(&b).ok() } else { core::str::from_utf8(&b).ok().and_then(|t| kr_fmt::yaml::parse(t).ok()) };
            if let Some(v) = v {
                specs.push(v);
            }
        }
    }
    for n in names {
        if !specs.iter().any(|s| cdi_apply(s, n, g)) {
            let skipped = if untrusted.is_empty() { String::new() } else { format!(" (ignored, not owned by root or writable by others: {})", untrusted.join(", ")) };
            return Err(format!("CDI device {n} requested by the device plugin is not defined in any spec under /etc/cdi or /var/run/cdi{skipped}"));
        }
    }
    // Hooks run as root: refuse binaries others could have replaced (ADR-039, KNOWN_ISSUES #161).
    kr_runtime::hooks::check_trusted(&g.hooks)?;
    if !g.bad_hooks.is_empty() {
        return Err(format!("CDI hooks that are not supported (stage must be createRuntime, createContainer, startContainer, poststart or poststop, and the path absolute): {}", g.bad_hooks.join(", ")));
    }
    Ok(())
}

// ------------------------------------------------------------------ state

struct Res {
    devices: Vec<(String, bool)>,
    pre_start: bool,
    sock: String,
    gen: u64,
    task: Option<JoinHandle<()>>,
    /// The plugin implements `GetPreferredAllocation`.
    preferred: bool,
    /// A `ListAndWatch` stream is live (devices reported unhealthy by it are really unhealthy;
    /// after a plugin restart they are only unknown).
    connected: bool,
    /// Device id -> NUMA node from the plugin's topology hint.
    numa: BTreeMap<String, i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Alloc {
    uid: String,
    ctr: String,
    res: String,
    ids: Vec<String>,
}

#[derive(Default)]
struct State {
    res: BTreeMap<String, Res>,
    /// Every resource ever advertised (also by an earlier kubelet run): reported as 0 when gone.
    known: BTreeSet<String>,
    allocs: Vec<Alloc>,
}

pub struct Plugins {
    dir: String,
    enabled: Cell<bool>,
    st: RefCell<State>,
    /// Bumped whenever the advertised device counts may have changed.
    gen: Cell<u64>,
    seq: Cell<u64>,
    /// Open plugin connections by socket name, reused across `Allocate` calls.
    conns: RefCell<BTreeMap<String, Rc<Client>>>,
}

fn valid_resource(n: &str) -> bool {
    let Some((domain, name)) = n.split_once('/') else { return false };
    let chars = |s: &str| !s.is_empty() && s.len() < 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    chars(domain) && chars(name) && domain != "kubernetes.io" && !domain.ends_with(".kubernetes.io") && !domain.starts_with("requests.")
}

fn valid_endpoint(e: &str) -> bool {
    !e.is_empty() && !e.contains(['/', '\0']) && !e.contains("..") && e != "kubelet.sock" && e != "kr-allocations.json"
}

impl Plugins {
    pub fn new(dir: &str) -> Rc<Plugins> {
        let p = Plugins { dir: dir.to_string(), enabled: Cell::new(false), st: RefCell::new(State::default()), gen: Cell::new(1), seq: Cell::new(0), conns: RefCell::new(BTreeMap::new()) };
        p.load();
        Rc::new(p)
    }

    fn file(&self) -> String {
        format!("{}/kr-allocations.json", self.dir)
    }

    fn load(&self) {
        let Ok(b) = kr_sys::fs::read_file(format!("{}\0", self.file()).as_bytes(), 16 << 20) else { return };
        let Ok(v) = json::parse(&b) else { return };
        let mut st = self.st.borrow_mut();
        for r in v.get("resources").and_then(Value::as_array).unwrap_or(&[]) {
            if let Some(r) = r.as_str().filter(|r| valid_resource(r)) {
                st.known.insert(r.to_string());
            }
        }
        for a in v.get("allocations").and_then(Value::as_array).unwrap_or(&[]) {
            let s = |k: &str| a.get(k).and_then(Value::as_str).unwrap_or("").to_string();
            let ids: Vec<String> = a.get("devices").and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(|d| d.as_str().map(String::from)).collect();
            let al = Alloc { uid: s("pod"), ctr: s("container"), res: s("resource"), ids };
            if !al.uid.is_empty() && valid_resource(&al.res) {
                st.known.insert(al.res.clone());
                st.allocs.push(al);
            }
        }
    }

    /// Writes the allocation file; the state borrow must not be held by the caller.
    fn persist(&self) {
        if !self.enabled.get() {
            return;
        }
        let st = self.st.borrow();
        let mut s = String::from(r#"{"resources":["#);
        for (i, r) in st.known.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            json::write_str(r, &mut s);
        }
        s.push_str(r#"],"allocations":["#);
        for (i, a) in st.allocs.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(r#"{"pod":"#);
            json::write_str(&a.uid, &mut s);
            s.push_str(r#","container":"#);
            json::write_str(&a.ctr, &mut s);
            s.push_str(r#","resource":"#);
            json::write_str(&a.res, &mut s);
            s.push_str(r#","devices":["#);
            for (j, d) in a.ids.iter().enumerate() {
                if j > 0 {
                    s.push(',');
                }
                json::write_str(d, &mut s);
            }
            s.push_str("]}");
        }
        s.push_str("]}");
        drop(st);
        // Readers see the old or the new file at once; the flush to disk (about 100 ms on a busy
        // disk) happens in a worker so an Allocate does not stall the event loop (#215).
        let path = self.file();
        if kr_runtime::store::write_file_atomic_nosync(&path, s.as_bytes()).is_ok() {
            spawn(async move {
                let _ = kr_runtime::offload::fsync_file(&path).await;
            });
        }
    }

    fn bump(&self) {
        self.gen.set(self.gen.get() + 1);
    }

    /// Changes whenever the node's device counts may have changed.
    pub fn generation(&self) -> u64 {
        self.gen.get()
    }

    pub fn dir(&self) -> &str {
        &self.dir
    }

    /// Creates the directory and serves the registration socket. False if that is impossible.
    pub fn start(self: &Rc<Self>) -> bool {
        if kr_runtime::store::mkdir_p(&self.dir, 0o750).is_err() {
            return false;
        }
        let sock = format!("{}/kubelet.sock", self.dir);
        let _ = kr_sys::fs::unlinkat(kr_sys::fs::AT_FDCWD, format!("{sock}\0").as_bytes(), 0);
        let Ok(fd) = kr_sys::ns::unix_listen(sock.as_bytes()) else { return false };
        let Ok(l) = kr_sys::ns::set_nonblocking(fd.raw()).and_then(|_| Async::new(fd)) else { return false };
        self.enabled.set(true);
        let me = self.clone();
        spawn(grpc::serve(
            l,
            Rc::new(move |m: String, req: Vec<u8>, r: Responder| {
                let me = me.clone();
                async move { me.handle(m, req, r).await }
            }),
        ));
        true
    }

    async fn handle(self: Rc<Self>, method: String, req: Vec<u8>, resp: Responder) {
        if method != REGISTER {
            return resp.finish(Status::new(grpc::UNIMPLEMENTED, "unknown method")).await;
        }
        let r = match decode_register(&req) {
            Ok(r) => r,
            Err(()) => return resp.finish(Status::new(INVALID_ARGUMENT, "malformed RegisterRequest")).await,
        };
        match self.register(r) {
            Ok(()) => {
                let _ = resp.send(&[]).await;
                resp.finish(Status::ok()).await
            }
            Err(m) => resp.finish(Status::new(INVALID_ARGUMENT, &m)).await,
        }
    }

    fn register(self: &Rc<Self>, r: RegisterRequest) -> Result<(), String> {
        if r.version != "v1beta1" {
            return Err(format!("unsupported device plugin API version {:?}", r.version));
        }
        if !valid_resource(&r.resource_name) {
            return Err(format!("invalid resource name {:?}", r.resource_name));
        }
        if !valid_endpoint(&r.endpoint) {
            return Err(format!("invalid endpoint {:?}", r.endpoint));
        }
        self.seq.set(self.seq.get() + 1);
        let gen = self.seq.get();
        let name = r.resource_name.clone();
        let old = {
            let mut st = self.st.borrow_mut();
            st.known.insert(name.clone());
            let devices = st.res.get(&name).map(|o| o.devices.iter().map(|(i, _)| (i.clone(), false)).collect()).unwrap_or_default();
            st.res.insert(name.clone(), Res { devices, pre_start: r.options.pre_start_required, sock: r.endpoint.clone(), gen, task: None, preferred: r.options.preferred_allocation, connected: false, numa: BTreeMap::new() }).and_then(|o| o.task)
        };
        if let Some(t) = old {
            t.abort();
        }
        self.conns.borrow_mut().remove(&r.endpoint);
        self.persist();
        self.bump();
        let me = self.clone();
        let task = spawn(async move { me.manage(name, r.endpoint, gen).await });
        if let Some(x) = self.st.borrow_mut().res.get_mut(&r.resource_name).filter(|x| x.gen == gen) {
            x.task = Some(task);
        }
        Ok(())
    }

    /// Applies `f` to the resource if registration `gen` is still current.
    fn with_res(&self, name: &str, gen: u64, f: impl FnOnce(&mut Res)) {
        if let Some(r) = self.st.borrow_mut().res.get_mut(name).filter(|r| r.gen == gen) {
            f(r);
        }
        self.bump();
    }

    async fn manage(self: Rc<Self>, name: String, endpoint: String, gen: u64) {
        let path = format!("{}/{endpoint}", self.dir);
        let mut client = None;
        for _ in 0..50 {
            match Client::connect_unix(path.as_bytes()).await {
                Ok(c) => {
                    client = Some(c);
                    break;
                }
                Err(_) => sleep(100).await,
            }
        }
        let Some(client) = client else {
            return self.with_res(&name, gen, mark_unhealthy);
        };
        if let Some(o) = client.unary(GET_OPTIONS, &[], 5000).await.ok().and_then(|b| decode_options(&b).ok()) {
            self.with_res(&name, gen, |r| {
                r.pre_start |= o.pre_start_required;
                r.preferred |= o.preferred_allocation;
            });
        }
        if let Ok(mut s) = client.server_stream(LIST_AND_WATCH, &[]).await {
            while let Some(Ok(m)) = s.next().await {
                if let Ok(d) = decode_devices(&m) {
                    let numa: BTreeMap<String, i64> = decode_numa(&m).into_iter().collect();
                    self.with_res(&name, gen, |r| {
                        r.devices = d;
                        r.numa = numa;
                        r.connected = true;
                    });
                }
            }
        }
        self.with_res(&name, gen, mark_unhealthy);
    }

    /// (resource, capacity, allocatable) for every resource ever advertised.
    pub fn node_resources(&self) -> Vec<(String, usize, usize)> {
        let st = self.st.borrow();
        st.known.iter().map(|k| st.res.get(k).map(|r| (k.clone(), r.devices.len(), r.devices.iter().filter(|d| d.1).count())).unwrap_or((k.clone(), 0, 0))).collect()
    }

    /// Whether `resource` is managed by a device plugin (now or in an earlier run).
    pub fn manages(&self, resource: &str) -> bool {
        self.st.borrow().known.contains(resource)
    }

    /// Frees the devices of every container of a pod.
    pub fn release_pod(&self, uid: &str) {
        let n = self.st.borrow().allocs.len();
        self.st.borrow_mut().allocs.retain(|a| a.uid != uid);
        if self.st.borrow().allocs.len() != n {
            self.persist();
        }
    }

    /// Frees the devices of pods that are not in `live`.
    pub fn retain_pods(&self, live: &[String]) {
        let n = self.st.borrow().allocs.len();
        self.st.borrow_mut().allocs.retain(|a| live.contains(&a.uid));
        if self.st.borrow().allocs.len() != n {
            self.persist();
        }
    }

    /// Devices currently held by (pod, container) for `resource`.
    pub fn allocated(&self, uid: &str, ctr: &str, resource: &str) -> Vec<String> {
        self.st.borrow().allocs.iter().find(|a| a.uid == uid && a.ctr == ctr && a.res == resource).map(|a| a.ids.clone()).unwrap_or_default()
    }

    /// Reserves `n` devices for (uid, ctr): the ones it already holds, else `pick` (the plugin's
    /// preference, if all of it is still free), else healthy free ones on one NUMA node if
    /// possible. Returns the ids, whether they are new, and the plugin socket and pre-start flag.
    #[cfg(test)]
    fn reserve(&self, uid: &str, ctr: &str, resource: &str, n: usize) -> Result<(Vec<String>, bool, String, bool), String> {
        self.reserve_with(uid, ctr, resource, n, None, &[])
    }

    /// Devices held by the `reusable` containers of the pod (finished init containers): free for
    /// the next container, and preferred for it, as upstream does.
    fn reusable_ids(&self, uid: &str, resource: &str, reusable: &[String]) -> Vec<String> {
        let st = self.st.borrow();
        let healthy = |id: &String| st.res.get(resource).is_some_and(|r| r.devices.iter().any(|d| d.1 && d.0 == *id));
        st.allocs.iter().filter(|a| a.uid == uid && a.res == resource && reusable.contains(&a.ctr)).flat_map(|a| a.ids.iter()).filter(|i| healthy(i)).cloned().collect()
    }

    fn reserve_with(&self, uid: &str, ctr: &str, resource: &str, n: usize, pick: Option<&[String]>, reusable: &[String]) -> Result<(Vec<String>, bool, String, bool), String> {
        let (ids, new, sock, pre) = {
            let mut st = self.st.borrow_mut();
            let Some(r) = st.res.get(resource) else { return Err(format!("device plugin resource {resource} is not registered (yet)")) };
            let (sock, pre) = (r.sock.clone(), r.pre_start);
            if let Some(a) = st.allocs.iter().find(|a| a.uid == uid && a.ctr == ctr && a.res == resource).filter(|a| a.ids.len() == n) {
                return Ok((a.ids.clone(), false, sock, pre));
            }
            st.allocs.retain(|a| !(a.uid == uid && a.ctr == ctr && a.res == resource));
            let used: BTreeSet<&String> = st.allocs.iter().filter(|a| a.res == resource && !(a.uid == uid && reusable.contains(&a.ctr))).flat_map(|a| a.ids.iter()).collect();
            let r = &st.res[resource];
            let free: Vec<(String, i64)> = r.devices.iter().filter(|d| d.1 && !used.contains(&d.0)).map(|d| (d.0.clone(), r.numa.get(&d.0).copied().unwrap_or(-1))).collect();
            if free.len() < n {
                return Err(format!("insufficient {resource}: requested {n}, {} healthy and unallocated", free.len()));
            }
            let mut must: Vec<String> = st.allocs.iter().filter(|a| a.uid == uid && a.res == resource && reusable.contains(&a.ctr)).flat_map(|a| a.ids.iter()).filter(|i| free.iter().any(|f| f.0 == **i)).cloned().collect();
            must.dedup();
            must.truncate(n);
            let chosen = match pick {
                Some(p) if p.len() == n && p.iter().all(|i| free.iter().any(|f| f.0 == *i)) && p.iter().collect::<BTreeSet<_>>().len() == n && must.iter().all(|m| p.contains(m)) => p.to_vec(),
                _ => {
                    let rest: Vec<(String, i64)> = free.iter().filter(|f| !must.contains(&f.0)).cloned().collect();
                    let mut c = must.clone();
                    c.extend(choose(&rest, n - must.len()));
                    c
                }
            };
            st.allocs.push(Alloc { uid: uid.to_string(), ctr: ctr.to_string(), res: resource.to_string(), ids: chosen.clone() });
            (chosen, true, sock, pre)
        };
        self.persist();
        Ok((ids, new, sock, pre))
    }

    fn unreserve(&self, uid: &str, ctr: &str, resource: &str) {
        self.st.borrow_mut().allocs.retain(|a| !(a.uid == uid && a.ctr == ctr && a.res == resource));
        self.persist();
    }

    /// Asks a plugin that implements `GetPreferredAllocation` which `n` of the free devices to
    /// hand out (topology-aware choice). None if it does not, fails, or the container already
    /// holds its devices.
    async fn preferred(&self, uid: &str, ctr: &str, resource: &str, n: usize, reusable: &[String]) -> Option<Vec<String>> {
        let mut must = self.reusable_ids(uid, resource, reusable);
        must.truncate(n);
        let (sock, free) = {
            let st = self.st.borrow();
            let r = st.res.get(resource).filter(|r| r.preferred && r.connected)?;
            if st.allocs.iter().any(|a| a.uid == uid && a.ctr == ctr && a.res == resource && a.ids.len() == n) {
                return None;
            }
            let used: BTreeSet<&String> = st.allocs.iter().filter(|a| a.res == resource && !(a.uid == uid && reusable.contains(&a.ctr))).flat_map(|a| a.ids.iter()).collect();
            let free: Vec<String> = r.devices.iter().filter(|d| d.1 && !used.contains(&d.0)).map(|d| d.0.clone()).collect();
            (r.sock.clone(), free)
        };
        if free.len() <= n {
            return None;
        }
        let c = self.conn(&sock).await.ok()?;
        let b = c.unary(PREFERRED, &encode_preferred(&free, &must, n), 5000).await.ok()?;
        Some(decode_preferred(&b))
    }

    /// Allocates devices for one container and returns what to apply to it.
    /// `reusable`: the pod's init containers that ran before this container and are gone
    /// (their devices are handed on, so a pod whose init and app containers each ask for the
    /// one GPU of the node fits, as under upstream).
    pub async fn allocate(&self, uid: &str, ctr: &str, wants: &[(String, usize)], reusable: &[String]) -> Result<Grant, String> {
        let mut total = Grant::default();
        for (resource, n) in wants {
            let pick = self.preferred(uid, ctr, resource, *n, reusable).await;
            let (ids, new, sock, pre) = self.reserve_with(uid, ctr, resource, *n, pick.as_deref(), reusable)?;
            match self.call_plugin(&sock, &[ids], pre).await.and_then(|mut v| v.pop().ok_or_else(|| String::from("empty AllocateResponse"))) {
                Ok(g) => merge(&mut total, g),
                Err(m) => {
                    if new {
                        self.unreserve(uid, ctr, resource);
                    }
                    return Err(format!("device plugin {resource}: {m}"));
                }
            }
        }
        self.resolve_cdi(total)
    }

    /// One `Allocate` call for several containers of a pod that limit the same `resource`
    /// (`ctrs`: container name and device count), as upstream does. Grants come back in order.
    pub async fn allocate_batch(&self, uid: &str, resource: &str, ctrs: &[(String, usize)]) -> Result<Vec<Grant>, String> {
        let mut reserved: Vec<(Vec<String>, bool)> = Vec::new();
        let (mut sock, mut pre) = (String::new(), false);
        for (ctr, n) in ctrs {
            let pick = self.preferred(uid, ctr, resource, *n, &[]).await;
            match self.reserve_with(uid, ctr, resource, *n, pick.as_deref(), &[]) {
                Ok((ids, new, s, p)) => {
                    (sock, pre) = (s, p);
                    reserved.push((ids, new));
                }
                Err(e) => {
                    self.unreserve_new(uid, resource, ctrs, &reserved);
                    return Err(e);
                }
            }
        }
        let ids: Vec<Vec<String>> = reserved.iter().map(|r| r.0.clone()).collect();
        match self.call_plugin(&sock, &ids, pre).await {
            Ok(v) if v.len() == ctrs.len() => v.into_iter().map(|g| self.resolve_cdi(g)).collect(),
            r => {
                self.unreserve_new(uid, resource, ctrs, &reserved);
                Err(format!("device plugin {resource}: {}", r.err().unwrap_or_else(|| String::from("AllocateResponse does not match the request"))))
            }
        }
    }

    fn unreserve_new(&self, uid: &str, resource: &str, ctrs: &[(String, usize)], reserved: &[(Vec<String>, bool)]) {
        for ((c, _), (_, new)) in ctrs.iter().zip(reserved) {
            if *new {
                self.unreserve(uid, c, resource);
            }
        }
    }

    fn resolve_cdi(&self, mut total: Grant) -> Result<Grant, String> {
        let cdi = core::mem::take(&mut total.cdi);
        if !cdi.is_empty() {
            let dirs = cdi_dirs();
            cdi_resolve(&dirs.iter().map(String::as_str).collect::<Vec<_>>(), &cdi, &mut total)?;
        }
        Ok(total)
    }

    /// The connection to a plugin socket: reused while open.
    async fn conn(&self, sock: &str) -> Result<Rc<Client>, String> {
        let cached = self.conns.borrow().get(sock).filter(|c| !c.is_closed()).cloned();
        if let Some(c) = cached {
            return Ok(c);
        }
        let path = format!("{}/{sock}", self.dir);
        let c = Rc::new(Client::connect_unix(path.as_bytes()).await.map_err(|_| format!("cannot connect to {sock}"))?);
        self.conns.borrow_mut().insert(sock.to_string(), c.clone());
        Ok(c)
    }

    /// `PreStartContainer` per container, then one `Allocate` with a request per container. A
    /// stale cached connection is dropped and the call repeated once on a transport failure.
    async fn call_plugin(&self, sock: &str, ids: &[Vec<String>], pre_start: bool) -> Result<Vec<Grant>, String> {
        let mut last = String::new();
        for _ in 0..2 {
            let c = self.conn(sock).await?;
            let mut r = Ok(Vec::new());
            if pre_start {
                for i in ids {
                    if let Err(s) = c.unary(PRE_START, &encode_ids(i, false), 10_000).await {
                        r = Err(("PreStartContainer", s));
                        break;
                    }
                }
            }
            if r.is_ok() {
                r = c.unary(ALLOCATE, &encode_batch(ids), 10_000).await.map_err(|s| ("Allocate", s));
            }
            match r {
                Ok(b) => return decode_allocate_all(&b).map_err(|()| String::from("malformed AllocateResponse")),
                Err((what, s)) => {
                    last = format!("{what} failed: {} ({})", s.message, s.code);
                    if s.code != grpc::UNAVAILABLE {
                        return Err(last);
                    }
                    self.conns.borrow_mut().remove(sock);
                }
            }
        }
        Err(last)
    }

    /// Containers holding a device their plugin reported unhealthy (or no longer lists) on a live
    /// `ListAndWatch`: (pod uid, container, resource, device ids). A plugin that is merely gone
    /// (restart, upgrade) is not a reason: its devices are unknown, not broken.
    pub fn unhealthy_holders(&self) -> Vec<(String, String, String, Vec<String>)> {
        let st = self.st.borrow();
        st.allocs
            .iter()
            .filter_map(|a| {
                let r = st.res.get(&a.res).filter(|r| r.connected)?;
                let bad: Vec<String> = a.ids.iter().filter(|i| !r.devices.iter().any(|d| d.0 == **i && d.1)).cloned().collect();
                (!bad.is_empty()).then(|| (a.uid.clone(), a.ctr.clone(), a.res.clone(), bad))
            })
            .collect()
    }

    /// Per pod uid, the message for failing it because of [`Self::unhealthy_holders`].
    pub fn unhealthy_pods(&self) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = Vec::new();
        for (uid, ctr, res, ids) in self.unhealthy_holders() {
            let m = format!("container {ctr} uses {res} device {} reported unhealthy by its device plugin", ids.join(","));
            match out.iter_mut().find(|o| o.0 == uid) {
                Some(o) => {
                    o.1.push_str("; ");
                    o.1.push_str(&m);
                }
                None => out.push((uid, m)),
            }
        }
        out
    }

    /// Allocations as (pod uid, container, resource, device ids) for the PodResources
    /// API.
    pub fn holdings(&self) -> Vec<(String, String, String, Vec<String>)> {
        self.st.borrow().allocs.iter().map(|a| (a.uid.clone(), a.ctr.clone(), a.res.clone(), a.ids.clone())).collect()
    }

    /// (resource, device id, NUMA node or -1) of every healthy device (allocatable).
    pub fn allocatable_devices(&self) -> Vec<(String, String, i64)> {
        let st = self.st.borrow();
        st.res.iter().flat_map(|(n, r)| r.devices.iter().filter(|d| d.1).map(move |d| (n.clone(), d.0.clone(), r.numa.get(&d.0).copied().unwrap_or(-1)))).collect()
    }

    /// NUMA node of a device, -1 if unknown.
    pub fn numa_of(&self, resource: &str, id: &str) -> i64 {
        self.st.borrow().res.get(resource).and_then(|r| r.numa.get(id).copied()).unwrap_or(-1)
    }
}

fn merge(total: &mut Grant, g: Grant) {
    total.envs.extend(g.envs);
    total.mounts.extend(g.mounts);
    total.devices.extend(g.devices);
    total.annotations.extend(g.annotations);
    total.cdi.extend(g.cdi);
}

fn mark_unhealthy(r: &mut Res) {
    r.connected = false;
    for d in &mut r.devices {
        d.1 = false;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloc::vec;
    use kr_rt::exec::block_on;
    use std::sync::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());
    pub(crate) fn lock() -> MutexGuard<'static, ()> {
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn tmpdir(name: &str) -> String {
        let p = std::env::temp_dir().join(std::format!("krdp-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p.to_str().unwrap().into()
    }

    fn enc_options(o: &Options) -> Vec<u8> {
        let mut w = Writer::new();
        w.bool(1, o.pre_start_required).bool(2, o.preferred_allocation);
        w.into_bytes()
    }

    fn enc_register(r: &RegisterRequest) -> Vec<u8> {
        let mut w = Writer::new();
        w.string(1, &r.version).string(2, &r.endpoint).string(3, &r.resource_name).message(4, |w| {
            w.bool(1, r.options.pre_start_required).bool(2, r.options.preferred_allocation);
        });
        w.into_bytes()
    }

    fn enc_devices(d: &[(&str, &str)]) -> Vec<u8> {
        let mut w = Writer::new();
        for (id, h) in d {
            w.message(1, |w| {
                w.string(1, id).string(2, h);
            });
        }
        w.into_bytes()
    }

    fn enc_grant(g: &Grant) -> Vec<u8> {
        let mut w = Writer::new();
        w.message(1, |w| {
            for (k, v) in &g.envs {
                w.message(1, |w| {
                    w.string(1, k).string(2, v);
                });
            }
            for (c, h, ro) in &g.mounts {
                w.message(2, |w| {
                    w.string(1, c).string(2, h).bool(3, *ro);
                });
            }
            for (c, h, p) in &g.devices {
                w.message(3, |w| {
                    w.string(1, c).string(2, h).string(3, p);
                });
            }
            for (k, v) in &g.annotations {
                w.message(4, |w| {
                    w.string(1, k).string(2, v);
                });
            }
            for n in &g.cdi {
                w.message(5, |w| {
                    w.string(1, n);
                });
            }
        });
        w.into_bytes()
    }

    #[test]
    fn message_round_trips() {
        let r = RegisterRequest { version: "v1beta1".into(), endpoint: "nv.sock".into(), resource_name: "nvidia.com/gpu".into(), options: Options { pre_start_required: true, preferred_allocation: true } };
        assert_eq!(decode_register(&enc_register(&r)).unwrap(), r);
        let o = Options { pre_start_required: true, preferred_allocation: false };
        assert_eq!(decode_options(&enc_options(&o)).unwrap(), o);
        assert_eq!(decode_options(&[]).unwrap(), Options::default());
        let d = decode_devices(&enc_devices(&[("GPU-0", "Healthy"), ("GPU-1", "Unhealthy")])).unwrap();
        assert_eq!(d, vec![("GPU-0".to_string(), true), ("GPU-1".to_string(), false)]);
        let g = Grant {
            envs: vec![("NVIDIA_VISIBLE_DEVICES".into(), "GPU-0".into())],
            mounts: vec![("/usr/lib/x".into(), "/host/x".into(), true)],
            devices: vec![("/dev/nvidia0".into(), "/dev/nvidia0".into(), "rw".into())],
            annotations: vec![],
            cdi: vec!["nvidia.com/gpu=0".into()],
            ..Default::default()
        };
        assert_eq!(decode_allocate(&enc_grant(&g)).unwrap(), g);
        // Requests.
        assert_eq!(encode_ids(&["a".into(), "bc".into()], true), [0x0a, 7, 0x0a, 1, b'a', 0x0a, 2, b'b', b'c']);
        assert_eq!(encode_ids(&["a".into()], false), [0x0a, 1, b'a']);
    }

    #[test]
    fn malformed_input_is_an_error_not_a_panic() {
        assert!(decode_register(&[0x0a, 0xff]).is_err());
        assert!(decode_devices(&[0x0a, 5, 1]).is_err());
        assert!(decode_allocate(&[]).is_err());
        assert!(decode_allocate(&[0xff, 0xff, 0xff]).is_err());
        let mut seed = 7u32;
        for _ in 0..500 {
            let b: Vec<u8> = (0..40)
                .map(|_| {
                    seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                    (seed >> 24) as u8
                })
                .collect();
            let _ = decode_register(&b);
            let _ = decode_devices(&b);
            let _ = decode_allocate(&b);
            let _ = decode_options(&b);
        }
    }

    #[test]
    fn name_validation() {
        assert!(valid_resource("nvidia.com/gpu"));
        assert!(!valid_resource("gpu"));
        assert!(!valid_resource("kubernetes.io/gpu"));
        assert!(!valid_resource("foo.kubernetes.io/gpu"));
        assert!(!valid_resource("a/b/c"));
        assert!(!valid_resource("a.com/\"x"));
        assert!(valid_endpoint("nvidia.sock"));
        assert!(!valid_endpoint("../x"));
        assert!(!valid_endpoint("a/b"));
        assert!(!valid_endpoint("kubelet.sock"));
    }

    /// Plugins with one resource: devices (id, healthy, NUMA node) and holdings (uid, ctr, ids).
    pub(crate) fn plugins_with(res: &str, devs: &[(&str, bool, i64)], held: &[(&str, &str, &[&str])]) -> (Rc<Plugins>, String) {
        let dir = tmpdir("with");
        let p = Plugins::new(&dir);
        let numa = devs.iter().filter(|d| d.2 >= 0).map(|d| (d.0.to_string(), d.2)).collect();
        p.st.borrow_mut().res.insert(res.into(), Res { devices: devs.iter().map(|d| (d.0.to_string(), d.1)).collect(), pre_start: false, sock: "x.sock".into(), gen: 1, task: None, preferred: false, connected: true, numa });
        p.st.borrow_mut().known.insert(res.into());
        for (u, c, ids) in held {
            p.st.borrow_mut().allocs.push(Alloc { uid: u.to_string(), ctr: c.to_string(), res: res.into(), ids: ids.iter().map(|i| i.to_string()).collect() });
        }
        (p, dir)
    }

    fn with_devices(p: &Plugins, res: &str, devs: &[(&str, bool)]) {
        p.st.borrow_mut().res.insert(res.into(), Res { devices: devs.iter().map(|(i, h)| (i.to_string(), *h)).collect(), pre_start: false, sock: "x.sock".into(), gen: 1, task: None, preferred: false, connected: true, numa: BTreeMap::new() });
        p.st.borrow_mut().known.insert(res.into());
    }

    #[test]
    fn init_container_devices_are_handed_to_the_next_container() {
        let _g = lock();
        let dir = tmpdir("reuse");
        let p = Plugins::new(&dir);
        with_devices(&p, "x.com/gpu", &[("a", true), ("b", true)]);
        // The node's one-GPU case: init and app container each ask for the same single device.
        let one = Plugins::new(&tmpdir("reuse1"));
        with_devices(&one, "x.com/gpu", &[("a", true)]);
        assert_eq!(one.reserve_with("u", "init", "x.com/gpu", 1, None, &[]).unwrap().0, ["a"]);
        assert!(one.reserve_with("u", "app", "x.com/gpu", 1, None, &[]).unwrap_err().contains("insufficient"));
        assert_eq!(one.reserve_with("u", "app", "x.com/gpu", 1, None, &["init".to_string()]).unwrap().0, ["a"]);
        // Another pod still cannot take it, and the reusable devices come first (must_include).
        assert!(one.reserve_with("other", "app", "x.com/gpu", 1, None, &[]).is_err());
        assert_eq!(p.reserve_with("u", "init", "x.com/gpu", 1, None, &[]).unwrap().0, ["a"]);
        let (ids, _, _, _) = p.reserve_with("u", "app", "x.com/gpu", 2, None, &["init".to_string()]).unwrap();
        assert_eq!(ids, ["a", "b"]);
    }

    #[test]
    fn allocator_rules() {
        let _g = lock();
        let dir = tmpdir("alloc");
        let p = Plugins::new(&dir);
        with_devices(&p, "x.com/gpu", &[("a", true), ("b", false), ("c", true), ("d", true)]);
        let (ids, new, _, _) = p.reserve("u1", "c", "x.com/gpu", 2).unwrap();
        assert_eq!((ids.as_slice(), new), (&["a".to_string(), "c".to_string()][..], true));
        // Idempotent for the same container.
        let (again, new, _, _) = p.reserve("u1", "c", "x.com/gpu", 2).unwrap();
        assert_eq!((again, new), (ids, false));
        // Another pod gets the remaining healthy device only.
        assert!(p.reserve("u2", "c", "x.com/gpu", 2).unwrap_err().contains("insufficient"));
        assert_eq!(p.reserve("u2", "c", "x.com/gpu", 1).unwrap().0, ["d"]);
        assert!(p.reserve("u3", "c", "x.com/nope", 1).unwrap_err().contains("not registered"));
        // Release frees.
        p.release_pod("u1");
        assert_eq!(p.reserve("u3", "c", "x.com/gpu", 2).unwrap().0, ["a", "c"]);
        assert_eq!(p.node_resources(), vec![("x.com/gpu".to_string(), 4, 3)]);
        // Plugin lost: capacity stays, allocatable drops to zero.
        mark_unhealthy(p.st.borrow_mut().res.get_mut("x.com/gpu").unwrap());
        assert_eq!(p.node_resources(), vec![("x.com/gpu".to_string(), 4, 0)]);
    }

    #[test]
    fn persistence_round_trip_and_sync() {
        let _g = lock();
        let dir = tmpdir("persist");
        {
            let p = Plugins::new(&dir);
            p.enabled.set(true);
            with_devices(&p, "x.com/gpu", &[("a", true), ("b", true)]);
            p.reserve("u1", "main", "x.com/gpu", 1).unwrap();
            p.reserve("u2", "main", "x.com/gpu", 1).unwrap();
        }
        let p = Plugins::new(&dir);
        p.enabled.set(true);
        assert_eq!(p.allocated("u1", "main", "x.com/gpu"), ["a"]);
        assert_eq!(p.allocated("u2", "main", "x.com/gpu"), ["b"]);
        // Gone resource is still reported (as zero) so the node status is corrected.
        assert_eq!(p.node_resources(), vec![("x.com/gpu".to_string(), 0, 0)]);
        p.retain_pods(&["u2".to_string()]);
        assert!(p.allocated("u1", "main", "x.com/gpu").is_empty());
        let p = Plugins::new(&dir);
        assert!(p.allocated("u1", "main", "x.com/gpu").is_empty());
        assert_eq!(p.allocated("u2", "main", "x.com/gpu"), ["b"]);
    }

    #[test]
    fn cdi_yaml_file() {
        let d = tmpdir("cdiy");
        std::fs::write(std::format!("{d}/s.yaml"), "cdiVersion: 0.5.0\nkind: a.com/b\ndevices:\n- name: c\n  containerEdits:\n    env:\n    - Z=9\n    deviceNodes:\n    - path: /dev/x\n").unwrap();
        let mut g = Grant::default();
        cdi_resolve(&[d.as_str()], &["a.com/b=c".to_string()], &mut g).unwrap();
        assert!(g.envs.iter().any(|(k, v)| k == "Z" && v == "9"));
    }

    #[test]
    fn cdi_json() {
        let spec = json::parse_str(r#"{"cdiVersion":"0.5.0","kind":"nvidia.com/gpu","containerEdits":{"env":["A=1"]},"devices":[{"name":"0","containerEdits":{"env":["B=2"],"deviceNodes":[{"path":"/dev/nvidia0","permissions":"r"}],"mounts":[{"hostPath":"/h","containerPath":"/c","options":["ro","bind"]}]}}]}"#).unwrap();
        let mut g = Grant::default();
        assert!(cdi_apply(&spec, "nvidia.com/gpu=0", &mut g));
        assert!(!cdi_apply(&spec, "nvidia.com/gpu=1", &mut g));
        assert!(!cdi_apply(&spec, "other.com/gpu=0", &mut g));
        assert_eq!(g.envs, [("A".into(), "1".into()), ("B".into(), "2".into())]);
        assert_eq!(g.devices, [("/dev/nvidia0".into(), "/dev/nvidia0".into(), "r".into())]);
        assert_eq!(g.mounts, [("/c".into(), "/h".into(), true)]);
        let mut g = Grant::default();
        assert!(cdi_resolve(&["/nonexistent-cdi"], &["a.com/b=c".to_string()], &mut g).unwrap_err().contains("not defined"));
        let d = tmpdir("cdi");
        std::fs::write(std::format!("{d}/s.json"), r#"{"kind":"a.com/b","devices":[{"name":"c","containerEdits":{"env":["Z=9"]}}]}"#).unwrap();
        cdi_resolve(&[d.as_str()], &["a.com/b=c".to_string()], &mut g).unwrap();
        assert_eq!(g.envs, [("Z".into(), "9".into())]);
    }

    static ALLOCATE_CALLS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

    /// The payload of the first field of an encoded message.
    fn walk_first(b: &[u8]) -> &[u8] {
        Reader::new(b).next().unwrap().unwrap().as_bytes().unwrap()
    }

    /// Fake plugin served in-process: 4 devices, Allocate answers per request.
    fn fake_plugin(path: &str, devs: Rc<RefCell<Vec<(&'static str, &'static str)>>>) {
        let fd = kr_sys::ns::unix_listen(path.as_bytes()).unwrap();
        kr_sys::ns::set_nonblocking(fd.raw()).unwrap();
        let l = Async::new(fd).unwrap();
        let pref = path.contains("pref");
        spawn(grpc::serve(
            l,
            Rc::new(move |m: String, req: Vec<u8>, r: Responder| {
                let devs = devs.clone();
                async move {
                    match m.as_str() {
                        GET_OPTIONS => {
                            let _ = r.send(&enc_options(&Options { pre_start_required: false, preferred_allocation: pref })).await;
                            r.finish(Status::ok()).await
                        }
                        LIST_AND_WATCH => {
                            let d = devs.borrow().clone();
                            let _ = r.send(&enc_devices(&d)).await;
                            sleep(60_000).await;
                        }
                        ALLOCATE => {
                            let mut w = Writer::new();
                            let mut calls = 0;
                            let _ = walk(&req, |_, f| {
                                calls += 1;
                                let mut ids = Vec::new();
                                let _ = walk(f.as_bytes().unwrap_or(&[]), |_, f| ids.push(f.as_str().unwrap_or("").to_string()));
                                let g = Grant {
                                    envs: vec![("FAKE_VISIBLE".into(), ids.join(","))],
                                    mounts: vec![("/fake/lib".into(), "/tmp".into(), true)],
                                    devices: ids.iter().map(|i| (std::format!("/dev/fake{i}"), std::format!("/dev/null"), "rw".into())).collect(),
                                    annotations: vec![("k".into(), "v".into())],
                                    cdi: vec![],
                                    ..Default::default()
                                };
                                let e = enc_grant(&g);
                                w.bytes(1, walk_first(&e));
                            });
                            ALLOCATE_CALLS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
                            let _ = calls;
                            let _ = r.send(w.as_bytes()).await;
                            r.finish(Status::ok()).await
                        }
                        PREFERRED => {
                            // Prefers the highest ids.
                            let mut avail = Vec::new();
                            let mut size = 0;
                            let _ = walk(&req, |_, f| {
                                let _ = walk(f.as_bytes().unwrap_or(&[]), |n, f| match n {
                                    1 => avail.push(f.as_str().unwrap_or("").to_string()),
                                    3 => size = f.as_varint().unwrap_or(0) as usize,
                                    _ => {}
                                });
                            });
                            avail.sort();
                            avail.reverse();
                            let mut w = Writer::new();
                            w.message(1, |w| {
                                for i in avail.iter().take(size) {
                                    w.string(1, i);
                                }
                            });
                            let _ = r.send(w.as_bytes()).await;
                            r.finish(Status::ok()).await
                        }
                        _ => r.finish(Status::new(grpc::UNIMPLEMENTED, "x")).await,
                    }
                }
            }),
        ));
    }

    #[test]
    fn numa_choice_and_preference_codecs() {
        let free: Vec<(String, i64)> = [("a", 0), ("b", 1), ("c", 1), ("d", 0), ("e", 0)].iter().map(|(i, n)| (i.to_string(), *n)).collect();
        // Two devices fit on node 1 (the smaller node), three only on node 0.
        assert_eq!(choose(&free, 2), ["b", "c"]);
        assert_eq!(choose(&free, 3), ["a", "d", "e"]);
        // No node fits four: first four. Unknown topology: first ones.
        assert_eq!(choose(&free, 4), ["a", "b", "c", "d"]);
        let unk: Vec<(String, i64)> = [("x", -1), ("y", -1)].iter().map(|(i, n)| (i.to_string(), *n)).collect();
        assert_eq!(choose(&unk, 1), ["x"]);
        // Topology in ListAndWatch.
        let mut w = Writer::new();
        w.message(1, |w| {
            w.string(1, "g0").string(2, "Healthy").message(3, |w| {
                w.message(1, |w| {
                    w.int64(1, 1);
                });
            });
        });
        w.message(1, |w| {
            w.string(1, "g1").string(2, "Healthy");
        });
        assert_eq!(decode_numa(w.as_bytes()), [("g0".to_string(), 1)]);
        assert_eq!(decode_devices(w.as_bytes()).unwrap().len(), 2);
        assert_eq!(encode_preferred(&["a".into(), "b".into()], &[], 1), [0x0a, 8, 0x0a, 1, b'a', 0x0a, 1, b'b', 0x18, 1]);
        let mut w = Writer::new();
        w.message(1, |w| {
            w.string(1, "b");
        });
        assert_eq!(decode_preferred(w.as_bytes()), ["b"]);
        assert!(decode_preferred(&[]).is_empty());
        // reserve honours a valid pick, ignores an invalid or duplicated one.
        let (p, _d) = plugins_with("x.com/gpu", &[("a", true, 0), ("b", true, 0), ("c", true, 1)], &[]);
        assert_eq!(p.reserve_with("u", "c1", "x.com/gpu", 1, Some(&["c".to_string()]), &[]).unwrap().0, ["c"]);
        assert_eq!(p.reserve_with("u", "c2", "x.com/gpu", 1, Some(&["c".to_string()]), &[]).unwrap().0, ["a"]);
        assert_eq!(p.reserve_with("u", "c3", "x.com/gpu", 1, Some(&["zz".to_string()]), &[]).unwrap().0, ["b"]);
    }

    #[test]
    fn unhealthy_devices_name_their_holders() {
        let _g = lock();
        let (p, _d) = plugins_with("x.com/gpu", &[("a", true, -1), ("b", false, -1), ("c", true, -1)], &[("u1", "m", &["a"]), ("u2", "m", &["b", "c"]), ("u2", "n", &[])]);
        assert_eq!(p.unhealthy_holders(), [("u2".to_string(), "m".to_string(), "x.com/gpu".to_string(), vec!["b".to_string()])]);
        let pods = p.unhealthy_pods();
        assert_eq!(pods.len(), 1);
        assert!(pods[0].1.contains("x.com/gpu device b") && pods[0].1.contains("unhealthy"), "{:?}", pods);
        // A device that vanished from the list counts; a plugin that is gone does not.
        p.st.borrow_mut().res.get_mut("x.com/gpu").unwrap().devices.retain(|d| d.0 != "a");
        assert_eq!(p.unhealthy_holders().len(), 2);
        mark_unhealthy(p.st.borrow_mut().res.get_mut("x.com/gpu").unwrap());
        assert!(p.unhealthy_holders().is_empty());
    }

    #[test]
    fn preferred_allocation_batch_and_connection_reuse() {
        let _g = lock();
        let dir = tmpdir("batch");
        let p = Plugins::new(&dir);
        assert!(p.start());
        let devs = Rc::new(RefCell::new(vec![("0", "Healthy"), ("1", "Healthy"), ("2", "Healthy"), ("3", "Healthy")]));
        fake_plugin(&std::format!("{dir}/pref.sock"), devs);
        let (p2, dir2) = (p.clone(), dir.clone());
        block_on(async move {
            let c = Client::connect_unix(std::format!("{dir2}/kubelet.sock").as_bytes()).await.unwrap();
            let ok = RegisterRequest { version: "v1beta1".into(), endpoint: "pref.sock".into(), resource_name: "y.com/gpu".into(), options: Options::default() };
            c.unary(REGISTER, &enc_register(&ok), 2000).await.unwrap();
            for _ in 0..100 {
                if p2.node_resources().first().is_some_and(|r| r.1 == 4) && p2.st.borrow().res["y.com/gpu"].preferred {
                    break;
                }
                sleep(20).await;
            }
            // The plugin prefers the highest ids: that is what the container gets.
            let g = p2.allocate("pod1", "a", &[("y.com/gpu".to_string(), 2)], &[]).await.unwrap();
            assert_eq!(g.envs, [("FAKE_VISIBLE".to_string(), "3,2".to_string())]);
            // One Allocate call for two containers; the connection is shared.
            let before = ALLOCATE_CALLS.load(core::sync::atomic::Ordering::SeqCst);
            let gs = p2.allocate_batch("pod2", "y.com/gpu", &[("b".to_string(), 1), ("c".to_string(), 1)]).await.unwrap();
            assert_eq!(ALLOCATE_CALLS.load(core::sync::atomic::Ordering::SeqCst), before + 1);
            assert_eq!(gs.len(), 2);
            assert_eq!(gs[0].envs, [("FAKE_VISIBLE".to_string(), "1".to_string())]);
            assert_eq!(gs[1].envs, [("FAKE_VISIBLE".to_string(), "0".to_string())]);
            assert_eq!(p2.conns.borrow().len(), 1);
            // Not enough devices: nothing stays reserved.
            assert!(p2.allocate_batch("pod3", "y.com/gpu", &[("b".to_string(), 1)]).await.is_err());
            assert!(p2.allocated("pod3", "b", "y.com/gpu").is_empty());
        });
    }

    #[test]
    fn end_to_end_registration_and_allocation() {
        let _g = lock();
        let dir = tmpdir("e2e");
        let p = Plugins::new(&dir);
        assert!(p.start());
        let devs = Rc::new(RefCell::new(vec![("0", "Healthy"), ("1", "Healthy"), ("2", "Healthy"), ("3", "Unhealthy")]));
        fake_plugin(&std::format!("{dir}/fake.sock"), devs);
        let p2 = p.clone();
        let dir2 = dir.clone();
        block_on(async move {
            let c = Client::connect_unix(std::format!("{dir2}/kubelet.sock").as_bytes()).await.unwrap();
            // Bad version and bad names are refused.
            let bad = RegisterRequest { version: "v1".into(), endpoint: "fake.sock".into(), resource_name: "x.com/gpu".into(), options: Options::default() };
            assert_eq!(c.unary(REGISTER, &enc_register(&bad), 2000).await.unwrap_err().code, INVALID_ARGUMENT);
            let bad = RegisterRequest { version: "v1beta1".into(), endpoint: "../fake.sock".into(), resource_name: "x.com/gpu".into(), options: Options::default() };
            assert_eq!(c.unary(REGISTER, &enc_register(&bad), 2000).await.unwrap_err().code, INVALID_ARGUMENT);
            let ok = RegisterRequest { version: "v1beta1".into(), endpoint: "fake.sock".into(), resource_name: "x.com/gpu".into(), options: Options::default() };
            c.unary(REGISTER, &enc_register(&ok), 2000).await.unwrap();
            for _ in 0..100 {
                if p2.node_resources().first().is_some_and(|r| r.1 == 4) {
                    break;
                }
                sleep(20).await;
            }
            assert_eq!(p2.node_resources(), vec![("x.com/gpu".to_string(), 4, 3)]);
            let g = p2.allocate("pod1", "main", &[("x.com/gpu".to_string(), 2)], &[]).await.unwrap();
            assert_eq!(g.envs, [("FAKE_VISIBLE".to_string(), "0,1".to_string())]);
            assert_eq!(g.devices.len(), 2);
            assert_eq!(g.devices[0].0, "/dev/fake0");
            assert_eq!(g.mounts, [("/fake/lib".to_string(), "/tmp".to_string(), true)]);
            assert_eq!(g.annotations, [("k".to_string(), "v".to_string())]);
            // Only one healthy device is left.
            let e = p2.allocate("pod2", "main", &[("x.com/gpu".to_string(), 2)], &[]).await.unwrap_err();
            assert!(e.contains("insufficient"), "{e}");
            // Same container again: same devices.
            let g2 = p2.allocate("pod1", "main", &[("x.com/gpu".to_string(), 2)], &[]).await.unwrap();
            assert_eq!(g2.envs, g.envs);
            p2.release_pod("pod1");
            let g3 = p2.allocate("pod2", "main", &[("x.com/gpu".to_string(), 3)], &[]).await.unwrap();
            assert_eq!(g3.envs[0].1, "0,1,2");
            // Plugin gone: devices turn unhealthy, capacity stays.
            let before = p2.generation();
            let _ = std::fs::remove_file(std::format!("{dir2}/fake.sock"));
            drop(c);
            assert!(before > 0);
        });
        assert!(std::fs::read_to_string(std::format!("{dir}/kr-allocations.json")).unwrap().contains("pod2"));
    }
}

#[cfg(test)]
mod nvidia_rc_tests {
    use super::*;

    #[test]
    fn visible_devices() {
        assert_eq!(visible_devices_to_cdi("all"), ["nvidia.com/gpu=all"]);
        assert_eq!(visible_devices_to_cdi("0, GPU-ab"), ["nvidia.com/gpu=0", "nvidia.com/gpu=GPU-ab"]);
        assert!(visible_devices_to_cdi("none").is_empty());
        assert!(visible_devices_to_cdi("void").is_empty());
        assert!(visible_devices_to_cdi("").is_empty());
        assert!(visible_devices_to_cdi("../etc").is_empty());
        assert!(is_nvidia_handler("nvidia") && !is_nvidia_handler("runc"));
    }

    #[test]
    fn hooks_are_collected_by_stage() {
        let _g = tests::lock();
        let spec = kr_fmt::json::parse_str(r#"{"kind":"nvidia.com/gpu","containerEdits":{"hooks":[{"hookName":"createContainer","path":"/usr/bin/h","args":["h","update-ldcache"],"env":["A=1"],"timeout":5}]},"devices":[{"name":"all","containerEdits":{"hooks":[{"hookName":"createRuntime","path":"/usr/bin/h","args":["h","x"]},{"hookName":"poststop","path":"/usr/bin/h"},{"hookName":"createContainer","path":"rel"}],"additionalGids":[985,989,985]}}]}"#).unwrap();
        let mut g = Grant::default();
        assert!(cdi_apply(&spec, "nvidia.com/gpu=all", &mut g));
        assert_eq!(g.hooks.create_container.len(), 1);
        assert_eq!(g.hooks.create_container[0].args, [b"h".to_vec(), b"update-ldcache".to_vec()]);
        assert_eq!((g.hooks.create_container[0].env.clone(), g.hooks.create_container[0].timeout), (alloc::vec![b"A=1".to_vec()], 5));
        assert_eq!(g.hooks.create_runtime.len(), 1);
        assert_eq!(g.hooks.poststop.len(), 1);
        assert_eq!(g.gids, [985, 989]);
        assert_eq!(g.bad_hooks, ["createContainer rel"]);
    }
}
