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
        let p = Plugins { dir: dir.to_string(), enabled: Cell::new(false), st: RefCell::new(State::default()), gen: Cell::new(1), seq: Cell::new(0) };
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
        let _ = kr_runtime::store::write_file_atomic(&self.file(), s.as_bytes());
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
            st.res.insert(name.clone(), Res { devices, pre_start: r.options.pre_start_required, sock: r.endpoint.clone(), gen, task: None }).and_then(|o| o.task)
        };
        if let Some(t) = old {
            t.abort();
        }
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
            self.with_res(&name, gen, |r| r.pre_start |= o.pre_start_required);
        }
        if let Ok(mut s) = client.server_stream(LIST_AND_WATCH, &[]).await {
            while let Some(Ok(m)) = s.next().await {
                if let Ok(d) = decode_devices(&m) {
                    self.with_res(&name, gen, |r| r.devices = d);
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

    /// Reserves `n` devices for (uid, ctr): the ones it already holds, else healthy free ones.
    /// Returns the ids, whether they are new, and the plugin socket and pre-start flag.
    fn reserve(&self, uid: &str, ctr: &str, resource: &str, n: usize) -> Result<(Vec<String>, bool, String, bool), String> {
        let (ids, new, sock, pre) = {
            let mut st = self.st.borrow_mut();
            let Some(r) = st.res.get(resource) else { return Err(format!("device plugin resource {resource} is not registered (yet)")) };
            let (sock, pre) = (r.sock.clone(), r.pre_start);
            if let Some(a) = st.allocs.iter().find(|a| a.uid == uid && a.ctr == ctr && a.res == resource).filter(|a| a.ids.len() == n) {
                return Ok((a.ids.clone(), false, sock, pre));
            }
            st.allocs.retain(|a| !(a.uid == uid && a.ctr == ctr && a.res == resource));
            let used: BTreeSet<&String> = st.allocs.iter().filter(|a| a.res == resource).flat_map(|a| a.ids.iter()).collect();
            let free: Vec<String> = st.res[resource].devices.iter().filter(|d| d.1 && !used.contains(&d.0)).map(|d| d.0.clone()).take(n).collect();
            if free.len() < n {
                let have = st.res[resource].devices.iter().filter(|d| d.1 && !used.contains(&d.0)).count();
                return Err(format!("insufficient {resource}: requested {n}, {have} healthy and unallocated"));
            }
            st.allocs.push(Alloc { uid: uid.to_string(), ctr: ctr.to_string(), res: resource.to_string(), ids: free.clone() });
            (free, true, sock, pre)
        };
        self.persist();
        Ok((ids, new, sock, pre))
    }

    fn unreserve(&self, uid: &str, ctr: &str, resource: &str) {
        self.st.borrow_mut().allocs.retain(|a| !(a.uid == uid && a.ctr == ctr && a.res == resource));
        self.persist();
    }

    /// Allocates devices for one container and returns what to apply to it.
    pub async fn allocate(&self, uid: &str, ctr: &str, wants: &[(String, usize)]) -> Result<Grant, String> {
        let mut total = Grant::default();
        for (resource, n) in wants {
            let (ids, new, sock, pre) = self.reserve(uid, ctr, resource, *n)?;
            match self.call_plugin(&sock, &ids, pre).await {
                Ok(g) => {
                    total.envs.extend(g.envs);
                    total.mounts.extend(g.mounts);
                    total.devices.extend(g.devices);
                    total.annotations.extend(g.annotations);
                    total.cdi.extend(g.cdi);
                }
                Err(m) => {
                    if new {
                        self.unreserve(uid, ctr, resource);
                    }
                    return Err(format!("device plugin {resource}: {m}"));
                }
            }
        }
        let cdi = core::mem::take(&mut total.cdi);
        if !cdi.is_empty() {
            let dirs = cdi_dirs();
            cdi_resolve(&dirs.iter().map(String::as_str).collect::<Vec<_>>(), &cdi, &mut total)?;
        }
        Ok(total)
    }

    async fn call_plugin(&self, sock: &str, ids: &[String], pre_start: bool) -> Result<Grant, String> {
        let path = format!("{}/{sock}", self.dir);
        let c = Client::connect_unix(path.as_bytes()).await.map_err(|_| format!("cannot connect to {sock}"))?;
        if pre_start {
            c.unary(PRE_START, &encode_ids(ids, false), 10_000).await.map_err(|s| format!("PreStartContainer failed: {} ({})", s.message, s.code))?;
        }
        let b = c.unary(ALLOCATE, &encode_ids(ids, true), 10_000).await.map_err(|s| format!("Allocate failed: {} ({})", s.message, s.code))?;
        decode_allocate(&b).map_err(|()| String::from("malformed AllocateResponse"))
    }
}

fn mark_unhealthy(r: &mut Res) {
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

    fn with_devices(p: &Plugins, res: &str, devs: &[(&str, bool)]) {
        p.st.borrow_mut().res.insert(res.into(), Res { devices: devs.iter().map(|(i, h)| (i.to_string(), *h)).collect(), pre_start: false, sock: "x.sock".into(), gen: 1, task: None });
        p.st.borrow_mut().known.insert(res.into());
    }

    #[test]
    fn allocator_rules() {
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

    /// Fake plugin served in-process: 4 devices, Allocate answers per request.
    fn fake_plugin(path: &str, devs: Rc<RefCell<Vec<(&'static str, &'static str)>>>) {
        let fd = kr_sys::ns::unix_listen(path.as_bytes()).unwrap();
        kr_sys::ns::set_nonblocking(fd.raw()).unwrap();
        let l = Async::new(fd).unwrap();
        spawn(grpc::serve(
            l,
            Rc::new(move |m: String, req: Vec<u8>, r: Responder| {
                let devs = devs.clone();
                async move {
                    match m.as_str() {
                        GET_OPTIONS => {
                            let _ = r.send(&enc_options(&Options { pre_start_required: false, preferred_allocation: false })).await;
                            r.finish(Status::ok()).await
                        }
                        LIST_AND_WATCH => {
                            let d = devs.borrow().clone();
                            let _ = r.send(&enc_devices(&d)).await;
                            sleep(60_000).await;
                        }
                        ALLOCATE => {
                            let mut ids = Vec::new();
                            let _ = walk(&req, |_, f| {
                                let _ = walk(f.as_bytes().unwrap_or(&[]), |_, f| ids.push(f.as_str().unwrap_or("").to_string()));
                            });
                            let g = Grant {
                                envs: vec![("FAKE_VISIBLE".into(), ids.join(","))],
                                mounts: vec![("/fake/lib".into(), "/tmp".into(), true)],
                                devices: ids.iter().map(|i| (std::format!("/dev/fake{i}"), std::format!("/dev/null"), "rw".into())).collect(),
                                annotations: vec![("k".into(), "v".into())],
                                cdi: vec![],
                                ..Default::default()
                            };
                            let _ = r.send(&enc_grant(&g)).await;
                            r.finish(Status::ok()).await
                        }
                        _ => r.finish(Status::new(grpc::UNIMPLEMENTED, "x")).await,
                    }
                }
            }),
        ));
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
            let g = p2.allocate("pod1", "main", &[("x.com/gpu".to_string(), 2)]).await.unwrap();
            assert_eq!(g.envs, [("FAKE_VISIBLE".to_string(), "0,1".to_string())]);
            assert_eq!(g.devices.len(), 2);
            assert_eq!(g.devices[0].0, "/dev/fake0");
            assert_eq!(g.mounts, [("/fake/lib".to_string(), "/tmp".to_string(), true)]);
            assert_eq!(g.annotations, [("k".to_string(), "v".to_string())]);
            // Only one healthy device is left.
            let e = p2.allocate("pod2", "main", &[("x.com/gpu".to_string(), 2)]).await.unwrap_err();
            assert!(e.contains("insufficient"), "{e}");
            // Same container again: same devices.
            let g2 = p2.allocate("pod1", "main", &[("x.com/gpu".to_string(), 2)]).await.unwrap();
            assert_eq!(g2.envs, g.envs);
            p2.release_pod("pod1");
            let g3 = p2.allocate("pod2", "main", &[("x.com/gpu".to_string(), 3)]).await.unwrap();
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
