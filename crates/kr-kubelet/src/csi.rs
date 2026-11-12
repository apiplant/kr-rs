//! CSI node side: driver registration (kubelet plugin watcher protocol), CSINode, and
//! stage/publish of PersistentVolumes through the driver's unix socket (ADR-038 gRPC layer).
//!
//! Needs a root kubelet: the volume mounts are made by the driver and must propagate into
//! the pod's mount namespace, which a rootless kubelet cannot arrange.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use kr_apiserver::client::Client as Api;
use kr_fmt::json::{self, Value};
use kr_fmt::proto::{Field, Reader, Writer};
use kr_net::grpc::Client;
use kr_rt::exec::sleep;

const GET_INFO: &str = "/pluginregistration.Registration/GetInfo";
const NOTIFY: &str = "/pluginregistration.Registration/NotifyRegistrationStatus";
const NODE_INFO: &str = "/csi.v1.Node/NodeGetInfo";
const NODE_CAPS: &str = "/csi.v1.Node/NodeGetCapabilities";
const STAGE: &str = "/csi.v1.Node/NodeStageVolume";
const UNSTAGE: &str = "/csi.v1.Node/NodeUnstageVolume";
const PUBLISH: &str = "/csi.v1.Node/NodePublishVolume";
const UNPUBLISH: &str = "/csi.v1.Node/NodeUnpublishVolume";
const EXPAND: &str = "/csi.v1.Node/NodeExpandVolume";
#[allow(dead_code)] // for the kubelet metrics endpoint (no caller yet)
const STATS: &str = "/csi.v1.Node/NodeGetVolumeStats";
const DISABLED: &str = "CSI volumes need a root kubelet";
const NODEID_ANNOTATION: &str = "csi.volume.kubernetes.io/nodeid";
const SLOW_MS: u64 = 120_000;
const FAST_MS: u64 = 10_000;

fn walk(buf: &[u8], mut f: impl FnMut(u32, &Field<'_>)) -> Result<(), ()> {
    let mut r = Reader::new(buf);
    while let Some(x) = r.next().map_err(|_| ())? {
        f(x.number, &x);
    }
    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sha(s: &str) -> String {
    hex(&kr_crypto::sha2::sha256(s.as_bytes()))
}

fn q(s: &str) -> String {
    let mut o = String::new();
    json::write_str(s, &mut o);
    o
}

fn map_field(w: &mut Writer, field: u32, m: &[(String, String)]) {
    for (k, v) in m {
        w.message(field, |w| {
            w.string(1, k).string(2, v);
        });
    }
}

/// `PluginInfo` -> (type, name, endpoint).
fn decode_plugin_info(b: &[u8]) -> Result<(String, String, String), ()> {
    let (mut t, mut n, mut e) = Default::default();
    walk(b, |k, f| match k {
        1 => t = f.as_str().unwrap_or("").to_string(),
        2 => n = f.as_str().unwrap_or("").to_string(),
        3 => e = f.as_str().unwrap_or("").to_string(),
        _ => {}
    })?;
    Ok((t, n, e))
}

/// `NodeGetInfoResponse` -> (node id, topology segment keys, max volumes per node).
fn decode_node_info(b: &[u8]) -> Result<(String, Vec<String>, u64), ()> {
    let (mut id, mut keys, mut max) = (String::new(), Vec::new(), 0);
    walk(b, |k, f| match k {
        1 => id = f.as_str().unwrap_or("").to_string(),
        2 => max = f.as_varint().unwrap_or(0),
        3 => {
            let _ = walk(f.as_bytes().unwrap_or(&[]), |k, f| {
                if k == 1 {
                    let _ = walk(f.as_bytes().unwrap_or(&[]), |k, f| {
                        if k == 1 {
                            keys.push(f.as_str().unwrap_or("").to_string());
                        }
                    });
                }
            });
        }
        _ => {}
    })?;
    keys.sort();
    keys.dedup();
    Ok((id, keys, max))
}

/// `NodeGetCapabilitiesResponse` -> the `NodeServiceCapability.RPC.Type` values offered
/// (1 STAGE_UNSTAGE_VOLUME, 2 GET_VOLUME_STATS, 3 EXPAND_VOLUME).
fn decode_caps(b: &[u8]) -> Result<Vec<u64>, ()> {
    let mut caps = Vec::new();
    walk(b, |k, f| {
        if k == 1 {
            let _ = walk(f.as_bytes().unwrap_or(&[]), |k, f| {
                if k == 1 {
                    let _ = walk(f.as_bytes().unwrap_or(&[]), |k, f| {
                        if k == 1 {
                            caps.extend(f.as_varint());
                        }
                    });
                }
            });
        }
    })?;
    Ok(caps)
}

/// `NodeGetVolumeStatsResponse` -> (bytes, inodes) as (available, total, used).
#[allow(dead_code)] // for the kubelet metrics endpoint (no caller yet)
fn decode_stats(b: &[u8]) -> Result<([u64; 3], [u64; 3]), ()> {
    let (mut bytes, mut inodes) = ([0; 3], [0; 3]);
    walk(b, |k, f| {
        if k != 1 {
            return;
        }
        let (mut v, mut unit) = ([0u64; 3], 0);
        let _ = walk(f.as_bytes().unwrap_or(&[]), |k, f| match k {
            1..=3 => v[k as usize - 1] = f.as_varint().unwrap_or(0),
            4 => unit = f.as_varint().unwrap_or(0),
            _ => {}
        });
        match unit {
            1 => bytes = v,
            2 => inodes = v,
            _ => {}
        }
    })?;
    Ok((bytes, inodes))
}

/// Usage of one volume mounted for a pod, for a (future) kubelet metrics endpoint
/// (`kubelet_volume_stats_*`; `pod_uid` and `pv` identify the series).
#[allow(dead_code)] // for the kubelet metrics endpoint (no caller yet)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VolumeStats {
    pub pod_uid: String,
    pub pv: String,
    pub capacity_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub inodes: u64,
    pub inodes_used: u64,
    pub inodes_free: u64,
}

/// Unique volume name as the kubelet reports it in `status.volumesInUse`.
pub fn volume_name(driver: &str, handle: &str) -> String {
    format!("kubernetes.io/csi/{driver}^{handle}")
}

fn bytes_of(v: Option<&Value>) -> Option<u64> {
    let q = v.and_then(Value::as_str).and_then(|s| kr_fmt::quantity::Quantity::parse(s).ok())?;
    u64::try_from(q.value()?).ok()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Driver {
    endpoint: String,
    node_id: String,
    topology_keys: Vec<String>,
    stage: bool,
    stats: bool,
    expand: bool,
    /// `NodeGetInfo.max_volumes_per_node` (0: no limit reported).
    max_volumes: u64,
    reg_sock: String,
    reg_inode: u64,
}

pub struct Csi {
    root: Option<String>,
    node: String,
    drivers: RefCell<BTreeMap<String, Driver>>,
    /// Registration sockets that are not CSI plugins (path, inode).
    ignored: RefCell<BTreeSet<(String, u64)>>,
    /// (driver, volume handle) staged / (pod uid, pv name) published by this process.
    staged: RefCell<BTreeSet<(String, String)>>,
    published: RefCell<BTreeSet<(String, String)>>,
    warned: RefCell<BTreeSet<String>>,
    /// Last `volumesInUse` written to the node (None: never).
    reported: RefCell<Option<Vec<String>>>,
    /// CSINode and the node annotation need to be rewritten.
    dirty: Cell<bool>,
    /// NodeExpandVolume failures per (driver, volume handle): (count, retry not before ms).
    expand_backoff: RefCell<BTreeMap<(String, String), (u32, u64)>>,
}

/// The CSI access mode of a PV or claim. A node RPC carries one `VolumeCapability` (the spec has no
/// list there), so, like upstream, the first listed mode is the one sent.
fn access_mode(modes: Option<&[Value]>) -> u64 {
    match modes.and_then(|a| a.first()).and_then(Value::as_str) {
        Some("ReadOnlyMany") => 3,
        Some("ReadWriteMany") => 5,
        Some("ReadWriteOncePod") => 6,
        _ => 1,
    }
}

/// `VolumeCapability`: `block` access type (empty `BlockVolume`) or `mount` (fs type, flags).
fn capability(w: &mut Writer, field: u32, block: bool, fs_type: &str, flags: &[String], mode: u64) {
    w.message(field, |w| {
        if block {
            w.message(1, |_| {});
        } else {
            w.message(2, |w| {
                w.string(1, fs_type);
                for f in flags {
                    w.string(2, f);
                }
            });
        }
        w.message(3, |w| {
            w.varint(1, mode);
        });
    });
}

fn list(dir: &str) -> Vec<String> {
    let Ok(fd) = kr_sys::ns::open(format!("{dir}\0").as_bytes(), kr_sys::ns::O_RDONLY | kr_sys::ns::O_DIRECTORY | kr_sys::fs::O_NOFOLLOW, 0) else { return Vec::new() };
    let mut v: Vec<String> = kr_sys::fs::read_dir(&fd).filter_map(Result::ok).filter_map(|e| String::from_utf8(e.name).ok()).collect();
    v.sort();
    v
}

fn rmdir(p: &str) -> bool {
    kr_sys::ns::rmdir(format!("{p}\0").as_bytes()).is_ok()
}

fn safe_name(n: &str) -> bool {
    !n.is_empty() && !n.contains(['/', '\0']) && n != "." && n != ".."
}

impl Csi {
    /// Root kubelet directory (`/var/lib/kubelet`, or `KR_KUBELET_DIR`); disabled when not uid 0.
    pub fn new(node: &str) -> Rc<Csi> {
        let root = (kr_sys::ns::getuid() == 0).then(|| kr_runtime::store::env_var("KR_KUBELET_DIR").filter(|d| d.starts_with('/')).unwrap_or_else(|| "/var/lib/kubelet".to_string()));
        Csi::with_root(root, node)
    }

    fn with_root(root: Option<String>, node: &str) -> Rc<Csi> {
        Rc::new(Csi { root, node: node.to_string(), drivers: RefCell::new(BTreeMap::new()), ignored: RefCell::new(BTreeSet::new()), staged: RefCell::new(BTreeSet::new()), published: RefCell::new(BTreeSet::new()), warned: RefCell::new(BTreeSet::new()), reported: RefCell::new(None), dirty: Cell::new(false), expand_backoff: RefCell::new(BTreeMap::new()) })
    }

    /// The kubelet directory when CSI is enabled.
    pub fn dir(&self) -> Option<&str> {
        self.root.as_deref()
    }

    /// Pod directories that hold (or held) CSI mounts.
    pub fn pod_uids(&self) -> Vec<String> {
        self.root.as_ref().map(|r| list(&format!("{r}/pods")).into_iter().filter(|n| safe_name(n)).collect()).unwrap_or_default()
    }

    /// Logs a failure once per distinct message; true when it is new.
    fn warn(&self, msg: &str) -> bool {
        let new = self.warned.borrow_mut().insert(msg.to_string());
        if new {
            kr_rt::eprint(format!("kubelet: {msg}\n").as_bytes());
        }
        new
    }

    // -------------------------------------------------------------- registration

    /// Registration watcher: runs for the life of the kubelet.
    pub async fn run<C: Api>(self: Rc<Self>, c: C) {
        let Some(root) = &self.root else { return };
        let _ = kr_runtime::store::mkdir_p(&format!("{root}/plugins_registry"), 0o750);
        let _ = kr_runtime::store::mkdir_p(&format!("{root}/plugins"), 0o750);
        let mut n = 0u32;
        loop {
            if self.tick().await {
                self.dirty.set(true);
            }
            if self.dirty.get() && self.sync_csinode(&c).await {
                self.dirty.set(false);
            }
            self.report_in_use(&c).await;
            if n % 5 == 0 {
                self.expand_pending(&c).await;
            }
            n = n.wrapping_add(1);
            sleep(2000).await;
        }
    }

    /// One pass over the registration directory; true if the driver set changed.
    async fn tick(&self) -> bool {
        let Some(root) = &self.root else { return false };
        let dir = format!("{root}/plugins_registry");
        let mut present: BTreeMap<String, u64> = BTreeMap::new();
        for n in list(&dir).into_iter().filter(|n| n.ends_with(".sock") && safe_name(n)) {
            let p = format!("{dir}/{n}");
            if let Ok(st) = kr_sys::fs::newfstatat(kr_sys::fs::AT_FDCWD, format!("{p}\0").as_bytes(), 0) {
                present.insert(p, st.ino);
            }
        }
        let mut changed = false;
        let before = self.drivers.borrow().len();
        self.drivers.borrow_mut().retain(|_, d| present.get(&d.reg_sock).is_some_and(|i| *i == d.reg_inode));
        self.ignored.borrow_mut().retain(|k| present.get(&k.0) == Some(&k.1));
        changed |= self.drivers.borrow().len() != before;
        for (p, ino) in present {
            let known = self.drivers.borrow().values().any(|d| d.reg_sock == p && d.reg_inode == ino) || self.ignored.borrow().contains(&(p.clone(), ino));
            if known {
                continue;
            }
            match self.register(&p, ino).await {
                Ok(Some((name, d))) => {
                    self.drivers.borrow_mut().insert(name, d);
                    changed = true;
                }
                Ok(None) => {
                    self.ignored.borrow_mut().insert((p, ino));
                }
                Err(msg) => {
                    let msg = format!("CSI registration of {p} failed: {msg}");
                    if self.warn(&msg) {
                        self.notify(&p, false, &msg).await;
                    }
                }
            }
        }
        changed
    }

    async fn notify(&self, sock: &str, ok: bool, err: &str) {
        let Ok(c) = Client::connect_unix(sock.as_bytes()).await else { return };
        let mut w = Writer::new();
        w.bool(1, ok).string(2, err);
        let _ = c.unary(NOTIFY, w.as_bytes(), FAST_MS).await;
    }

    /// Ok(None) when the socket is not a CSI plugin.
    async fn register(&self, sock: &str, ino: u64) -> Result<Option<(String, Driver)>, String> {
        let c = Client::connect_unix(sock.as_bytes()).await.map_err(|_| "cannot connect".to_string())?;
        let b = c.unary(GET_INFO, &[], FAST_MS).await.map_err(|s| format!("GetInfo: {} ({})", s.message, s.code))?;
        let (ty, name, ep) = decode_plugin_info(&b).map_err(|()| "malformed PluginInfo".to_string())?;
        if ty != "CSIPlugin" {
            return Ok(None);
        }
        if name.is_empty() || !safe_name(&name) {
            return Err(format!("invalid driver name {name:?}"));
        }
        let endpoint = if ep.is_empty() { sock.to_string() } else { ep };
        let ec = Client::connect_unix(endpoint.as_bytes()).await.map_err(|_| format!("cannot connect to {endpoint}"))?;
        let b = ec.unary(NODE_INFO, &[], FAST_MS).await.map_err(|s| format!("NodeGetInfo: {} ({})", s.message, s.code))?;
        let (node_id, topology_keys, max_volumes) = decode_node_info(&b).map_err(|()| "malformed NodeGetInfoResponse".to_string())?;
        if node_id.is_empty() {
            return Err("NodeGetInfo returned no node_id".to_string());
        }
        let b = ec.unary(NODE_CAPS, &[], FAST_MS).await.map_err(|s| format!("NodeGetCapabilities: {} ({})", s.message, s.code))?;
        let caps = decode_caps(&b).map_err(|()| "malformed NodeGetCapabilitiesResponse".to_string())?;
        let (stage, stats, expand) = (caps.contains(&1), caps.contains(&2), caps.contains(&3));
        self.notify(sock, true, "").await;
        kr_rt::eprint(format!("kubelet: CSI driver {name} registered (node id {node_id}, stage {stage}, stats {stats}, expand {expand}, max volumes {max_volumes})\n").as_bytes());
        Ok(Some((name, Driver { endpoint, node_id, topology_keys, stage, stats, expand, max_volumes, reg_sock: sock.to_string(), reg_inode: ino })))
    }

    /// Rewrites the CSINode object and the node-id annotation. True on success.
    async fn sync_csinode<C: Api>(&self, c: &C) -> bool {
        let node = &self.node;
        let Ok(n) = c.get(&format!("/api/v1/nodes/{node}")).await else { return false };
        let uid = n.pointer(&["metadata", "uid"]).and_then(Value::as_str).unwrap_or("");
        let drivers: Vec<(String, Driver)> = self.drivers.borrow().iter().map(|(k, d)| (k.clone(), d.clone())).collect();
        let list: Vec<String> = drivers.iter().map(|(k, d)| format!(r#"{{"name":{},"nodeID":{},"topologyKeys":[{}]{}}}"#, q(k), q(&d.node_id), d.topology_keys.iter().map(|t| q(t)).collect::<Vec<_>>().join(","), if d.max_volumes > 0 { format!(r#","allocatable":{{"count":{}}}"#, d.max_volumes) } else { String::new() })).collect();
        let body = format!(r#"{{"apiVersion":"storage.k8s.io/v1","kind":"CSINode","metadata":{{"name":{nq},"ownerReferences":[{{"apiVersion":"v1","kind":"Node","name":{nq},"uid":{}}}]}},"spec":{{"drivers":[{}]}}}}"#, q(uid), list.join(","), nq = q(node));
        let Ok(mut obj) = json::parse(body.as_bytes()) else { return false };
        let path = format!("/apis/storage.k8s.io/v1/csinodes/{node}");
        let r = match c.get(&path).await {
            Ok(old) => {
                if let Some(rv) = old.pointer(&["metadata", "resourceVersion"]).cloned() {
                    let mut m = obj.get("metadata").cloned().unwrap_or(Value::Null);
                    m.set("resourceVersion", rv);
                    obj.set("metadata", m);
                }
                c.update(&path, &obj).await
            }
            Err(_) => c.create("/apis/storage.k8s.io/v1/csinodes", &obj).await,
        };
        if r.is_err() {
            return false;
        }
        let ids = format!("{{{}}}", drivers.iter().map(|(k, d)| format!("{}:{}", q(k), q(&d.node_id))).collect::<Vec<_>>().join(","));
        let val = if drivers.is_empty() { "null".to_string() } else { q(&ids) };
        let Ok(p) = json::parse(format!(r#"{{"metadata":{{"annotations":{{"{NODEID_ANNOTATION}":{val}}}}}}}"#).as_bytes()) else { return false };
        c.patch(&format!("/api/v1/nodes/{node}"), "application/merge-patch+json", &p).await.is_ok()
    }

    // -------------------------------------------------------------- mounting

    fn driver(&self, name: &str) -> Result<Driver, String> {
        self.drivers.borrow().get(name).cloned().ok_or_else(|| format!("CSI driver {name} is not registered on this node"))
    }

    async fn call(&self, d: &Driver, driver: &str, method: &str, body: &[u8], ms: u64) -> Result<Vec<u8>, String> {
        let op = method.rsplit('/').next().unwrap_or(method);
        let c = Client::connect_unix(d.endpoint.as_bytes()).await.map_err(|_| format!("CSI {driver} {op} failed: cannot connect to {}", d.endpoint))?;
        c.unary(method, body, ms).await.map_err(|s| format!("CSI {driver} {op} failed: {} ({})", s.message, s.code))
    }

    /// Secret referenced by `pv.spec.csi.<key>` as name -> value (empty without a reference).
    async fn secrets<C: Api>(c: &C, pv: &Value, key: &str) -> Result<Vec<(String, String)>, String> {
        let Some(r) = pv.pointer(&["spec", "csi", key]) else { return Ok(Vec::new()) };
        Self::secret_data(c, r.get("name").and_then(Value::as_str).unwrap_or(""), r.get("namespace").and_then(Value::as_str).unwrap_or("")).await
    }

    async fn secret_data<C: Api>(c: &C, name: &str, ns: &str) -> Result<Vec<(String, String)>, String> {
        if name.is_empty() || ns.is_empty() {
            return Ok(Vec::new());
        }
        let s = c.get(&format!("/api/v1/namespaces/{ns}/secrets/{name}")).await.map_err(|_| format!("secret {ns}/{name} not found"))?;
        let data = s.get("data").and_then(Value::as_object).unwrap_or(&[]);
        Ok(data.iter().filter_map(|(k, v)| Some((k.clone(), String::from_utf8(kr_fmt::base64::decode(v.as_str()?).ok()?).ok()?))).collect())
    }

    /// Stages (once) and publishes a CSI PersistentVolume for `pod`; returns the directory to
    /// bind-mount into containers.
    pub async fn mount_pv<C: Api>(&self, c: &C, pod: &Value, pv: &Value, claim_readonly: bool) -> Result<String, String> {
        let root = self.root.as_deref().ok_or(DISABLED)?;
        let s = |p: &[&str]| pv.pointer(p).and_then(Value::as_str).unwrap_or("").to_string();
        let (driver, handle, pv_name) = (s(&["spec", "csi", "driver"]), s(&["spec", "csi", "volumeHandle"]), s(&["metadata", "name"]));
        let uid = pod.pointer(&["metadata", "uid"]).and_then(Value::as_str).unwrap_or("");
        if !safe_name(&pv_name) || !safe_name(uid) {
            return Err("invalid persistent volume or pod".to_string());
        }
        let d = self.driver(&driver)?;
        let block = s(&["spec", "volumeMode"]) == "Block";
        let fs_type = Some(s(&["spec", "csi", "fsType"])).filter(|f| !f.is_empty()).unwrap_or_else(|| "ext4".to_string());
        let ro = claim_readonly || pv.pointer(&["spec", "csi", "readOnly"]).and_then(Value::as_bool).unwrap_or(false);
        let vctx: Vec<(String, String)> = pv.pointer(&["spec", "csi", "volumeAttributes"]).and_then(Value::as_object).unwrap_or(&[]).iter().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))).collect();
        let flags: Vec<String> = pv.pointer(&["spec", "mountOptions"]).and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(|v| v.as_str().map(String::from)).collect();
        let mode = access_mode(pv.pointer(&["spec", "accessModes"]).and_then(Value::as_array));

        let cd = match c.get(&format!("/apis/storage.k8s.io/v1/csidrivers/{driver}")).await {
            Ok(v) => v,
            Err(e) if e.code == 404 => Value::Null,
            Err(e) => return Err(format!("cannot read CSIDriver {driver}: {}", e.message)),
        };
        let mut publish_ctx: Vec<(String, String)> = Vec::new();
        if cd.pointer(&["spec", "attachRequired"]).and_then(Value::as_bool) != Some(false) {
            let va = format!("csi-{}", sha(&format!("{handle}{driver}{}", self.node)));
            let v = c.get(&format!("/apis/storage.k8s.io/v1/volumeattachments/{va}")).await.map_err(|_| format!("waiting for volume attachment {va}"))?;
            if v.pointer(&["status", "attached"]).and_then(Value::as_bool) != Some(true) {
                return Err(format!("waiting for volume attachment {va}"));
            }
            publish_ctx = v.pointer(&["status", "attachmentMetadata"]).and_then(Value::as_object).unwrap_or(&[]).iter().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))).collect();
        }
        let mut pctx = vctx.clone();
        if cd.pointer(&["spec", "podInfoOnMount"]).and_then(Value::as_bool) == Some(true) {
            let m = |k: &str| pod.pointer(&["metadata", k]).and_then(Value::as_str).unwrap_or("").to_string();
            let sa = pod.pointer(&["spec", "serviceAccountName"]).and_then(Value::as_str).unwrap_or("").to_string();
            pctx.extend([("csi.storage.k8s.io/pod.name".to_string(), m("name")), ("csi.storage.k8s.io/pod.namespace".to_string(), m("namespace")), ("csi.storage.k8s.io/pod.uid".to_string(), uid.to_string()), ("csi.storage.k8s.io/serviceAccount.name".to_string(), sa), ("csi.storage.k8s.io/ephemeral".to_string(), "false".to_string())]);
        }
        let cap = |w: &mut Writer, field: u32| capability(w, field, block, &fs_type, &flags, mode);

        let mut staging = String::new();
        if d.stage {
            let parent = format!("{root}/plugins/kubernetes.io/csi/{driver}/{}", sha(&handle));
            staging = format!("{parent}/globalmount");
            let key = (driver.clone(), handle.clone());
            if !self.staged.borrow().contains(&key) {
                kr_runtime::store::mkdir_p(&parent, 0o750).map_err(|_| format!("cannot create {parent}"))?;
                let secrets = Self::secrets(c, pv, "nodeStageSecretRef").await?;
                let mut w = Writer::new();
                w.string(1, &handle);
                map_field(&mut w, 2, &publish_ctx);
                w.string(3, &staging);
                cap(&mut w, 4);
                map_field(&mut w, 5, &secrets);
                map_field(&mut w, 6, &vctx);
                self.call(&d, &driver, STAGE, w.as_bytes(), SLOW_MS).await?;
                self.staged.borrow_mut().insert(key);
            }
        }

        let dir = format!("{root}/pods/{uid}/volumes/kubernetes.io~csi/{pv_name}");
        let target = format!("{dir}/mount");
        let key = (uid.to_string(), pv_name.clone());
        if !self.published.borrow().contains(&key) {
            kr_runtime::store::mkdir_p(&dir, 0o750).map_err(|_| format!("cannot create {dir}"))?;
            let data = format!(r#"{{"driverName":{},"volumeHandle":{},"specVolID":{},"nodeName":{}}}"#, q(&driver), q(&handle), q(&pv_name), q(&self.node));
            write_private(&format!("{dir}/vol_data.json"), data.as_bytes()).map_err(|_| format!("cannot write {dir}/vol_data.json"))?;
            let secrets = Self::secrets(c, pv, "nodePublishSecretRef").await?;
            let mut w = Writer::new();
            w.string(1, &handle);
            map_field(&mut w, 2, &publish_ctx);
            w.string(3, &staging).string(4, &target);
            cap(&mut w, 5);
            w.bool(6, ro);
            map_field(&mut w, 7, &secrets);
            map_field(&mut w, 8, &pctx);
            self.call(&d, &driver, PUBLISH, w.as_bytes(), SLOW_MS).await?;
            self.published.borrow_mut().insert(key);
        }
        if block && kr_runtime::devfilter::rule_for(target.as_bytes(), true).is_none() {
            self.published.borrow_mut().remove(&(uid.to_string(), pv_name.clone())); // publish again next time
            return Err(format!("CSI {driver} NodePublishVolume did not create a block device at {target}"));
        }
        // Offline expansion: a claim that grew while no pod used it is expanded now, before the
        // container starts (a failure keeps the pod waiting, retried with backoff).
        let vol_path = if d.stage { staging.as_str() } else { target.as_str() };
        self.expand_if_needed(c, &d, &driver, &handle, pv, vol_path, &staging, false).await?;
        Ok(target)
    }

    /// Ephemeral inline `csi:` volume of `pod`: published (no attach, no stage) at the pod's
    /// volume directory; the driver must list `Ephemeral` in `volumeLifecycleModes`.
    pub async fn mount_ephemeral<C: Api>(&self, c: &C, pod: &Value, vol: &Value) -> Result<String, String> {
        let root = self.root.as_deref().ok_or(DISABLED)?;
        let name = vol.get("name").and_then(Value::as_str).unwrap_or("");
        let uid = pod.pointer(&["metadata", "uid"]).and_then(Value::as_str).unwrap_or("");
        let s = |k: &str| vol.pointer(&["csi", k]).and_then(Value::as_str).unwrap_or("").to_string();
        let driver = s("driver");
        if !safe_name(name) || !safe_name(uid) || driver.is_empty() {
            return Err("invalid inline csi volume".to_string());
        }
        let d = self.driver(&driver)?;
        let cd = c.get(&format!("/apis/storage.k8s.io/v1/csidrivers/{driver}")).await.map_err(|_| format!("CSIDriver {driver} not found: inline volumes need one with volumeLifecycleModes Ephemeral"))?;
        if !cd.pointer(&["spec", "volumeLifecycleModes"]).and_then(Value::as_array).is_some_and(|m| m.iter().any(|x| x.as_str() == Some("Ephemeral"))) {
            return Err(format!("CSIDriver {driver} does not support ephemeral inline volumes (volumeLifecycleModes)"));
        }
        let handle = format!("csi-{}", sha(&format!("{uid}{name}")));
        let dir = format!("{root}/pods/{uid}/volumes/kubernetes.io~csi/{name}");
        let target = format!("{dir}/mount");
        let key = (uid.to_string(), name.to_string());
        if !self.published.borrow().contains(&key) {
            kr_runtime::store::mkdir_p(&dir, 0o750).map_err(|_| format!("cannot create {dir}"))?;
            let data = format!(r#"{{"driverName":{},"volumeHandle":{},"specVolID":{},"nodeName":{},"ephemeral":true}}"#, q(&driver), q(&handle), q(name), q(&self.node));
            write_private(&format!("{dir}/vol_data.json"), data.as_bytes()).map_err(|_| format!("cannot write {dir}/vol_data.json"))?;
            let ns = pod.pointer(&["metadata", "namespace"]).and_then(Value::as_str).unwrap_or("");
            let sref = vol.pointer(&["csi", "nodePublishSecretRef", "name"]).and_then(Value::as_str).unwrap_or("");
            let secrets = Self::secret_data(c, sref, ns).await?;
            let mut ctx: Vec<(String, String)> = vol.pointer(&["csi", "volumeAttributes"]).and_then(Value::as_object).unwrap_or(&[]).iter().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))).collect();
            if cd.pointer(&["spec", "podInfoOnMount"]).and_then(Value::as_bool) == Some(true) {
                let m = |k: &str| pod.pointer(&["metadata", k]).and_then(Value::as_str).unwrap_or("").to_string();
                let sa = pod.pointer(&["spec", "serviceAccountName"]).and_then(Value::as_str).unwrap_or("").to_string();
                ctx.extend([("csi.storage.k8s.io/pod.name".to_string(), m("name")), ("csi.storage.k8s.io/pod.namespace".to_string(), m("namespace")), ("csi.storage.k8s.io/pod.uid".to_string(), uid.to_string()), ("csi.storage.k8s.io/serviceAccount.name".to_string(), sa), ("csi.storage.k8s.io/ephemeral".to_string(), "true".to_string())]);
            }
            let fs_type = s("fsType");
            let mut w = Writer::new();
            w.string(1, &handle);
            map_field(&mut w, 2, &[]);
            w.string(3, "").string(4, &target);
            capability(&mut w, 5, false, &fs_type, &[], 1);
            w.bool(6, vol.pointer(&["csi", "readOnly"]).and_then(Value::as_bool).unwrap_or(false));
            map_field(&mut w, 7, &secrets);
            map_field(&mut w, 8, &ctx);
            let _ = &d;
            self.call(&d, &driver, PUBLISH, w.as_bytes(), SLOW_MS).await?;
            self.published.borrow_mut().insert(key);
        }
        Ok(target)
    }


    // -------------------------------------------------------------- accounting, resize, stats

    /// Sorted unique names of the volumes some pod has recorded (published or being published,
    /// until the unpublish succeeds). Read from disk so it survives a kubelet restart.
    pub fn volumes_in_use(&self) -> Vec<String> {
        let Some(root) = self.root.as_deref() else { return Vec::new() };
        let mut v: Vec<String> = self.pod_uids().iter().flat_map(|u| Self::entries(root, u)).filter(|e| !e.3).map(|(_, d, h, _)| volume_name(&d, &h)).collect();
        v.sort();
        v.dedup();
        v
    }

    /// Writes `status.volumesInUse` of the node when it changed. The attach/detach controller
    /// does not detach a volume listed there.
    async fn report_in_use<C: Api>(&self, c: &C) {
        let v = self.volumes_in_use();
        if self.reported.borrow().as_ref() == Some(&v) {
            return;
        }
        let list = format!("[{}]", v.iter().map(|n| q(n)).collect::<Vec<_>>().join(","));
        let Ok(p) = json::parse(format!(r#"{{"status":{{"volumesInUse":{list}}}}}"#).as_bytes()) else { return };
        if c.patch(&format!("/api/v1/nodes/{}/status", self.node), "application/merge-patch+json", &p).await.is_ok() {
            *self.reported.borrow_mut() = Some(v);
        }
    }

    /// Retry delay after `fails` consecutive NodeExpandVolume failures: 2 s doubling up to ~2 min.
    fn backoff_ms(fails: u32) -> u64 {
        (2_000u64 << fails.saturating_sub(1).min(6)).min(122_000)
    }

    /// Runs `NodeExpandVolume` when the claim of `pv` asks for more than `status.capacity` and the
    /// volume is big enough (the external-resizer is done). `Ok(true)`: expanded and the claim
    /// status updated; `Ok(false)`: nothing to do (or the claim is not readable); `Err`: failed or
    /// waiting for the retry backoff. A failure sets the claim condition `NodeResizeError` and an
    /// event; success removes it. `need_condition`: a filesystem volume of a running pod is only
    /// grown once the resizer set `FileSystemResizePending` (raw block has no such condition).
    #[allow(clippy::too_many_arguments)]
    async fn expand_if_needed<C: Api>(&self, c: &C, d: &Driver, driver: &str, handle: &str, pv: &Value, vol_path: &str, staging: &str, need_condition: bool) -> Result<bool, String> {
        if !d.expand {
            return Ok(false);
        }
        let g = |k: &str| pv.pointer(&["spec", "claimRef", k]).and_then(Value::as_str).unwrap_or("").to_string();
        let (ns, claim, pv_name) = (g("namespace"), g("name"), pv.pointer(&["metadata", "name"]).and_then(Value::as_str).unwrap_or("").to_string());
        if !safe_name(&ns) || !safe_name(&claim) {
            return Ok(false);
        }
        let path = format!("/api/v1/namespaces/{ns}/persistentvolumeclaims/{claim}");
        let Ok(pvc) = c.get(&path).await else { return Ok(false) };
        let conds = pvc.pointer(&["status", "conditions"]).and_then(Value::as_array).unwrap_or(&[]);
        let has = |t: &str| conds.iter().any(|x| x.get("type").and_then(Value::as_str) == Some(t) && x.get("status").and_then(Value::as_str) == Some("True"));
        let block = pv.pointer(&["spec", "volumeMode"]).and_then(Value::as_str) == Some("Block");
        let (Some(want), Some(have)) = (bytes_of(pvc.pointer(&["spec", "resources", "requests", "storage"])), bytes_of(pvc.pointer(&["status", "capacity", "storage"]))) else { return Ok(false) };
        if want <= have || bytes_of(pv.pointer(&["spec", "capacity", "storage"])).is_none_or(|p| p < want) || (need_condition && !block && !has("FileSystemResizePending")) {
            return Ok(false);
        }
        let key = (driver.to_string(), handle.to_string());
        let now = kr_rt::exec::now_ms();
        if let Some((_, next)) = self.expand_backoff.borrow().get(&key) {
            if now < *next {
                return Err(format!("expanding volume {pv_name} failed, retrying in {} s", (next - now) / 1000 + 1));
            }
        }
        let fs_type = Some(pv.pointer(&["spec", "csi", "fsType"]).and_then(Value::as_str).unwrap_or("").to_string()).filter(|f| !f.is_empty()).unwrap_or_else(|| "ext4".to_string());
        let flags: Vec<String> = pv.pointer(&["spec", "mountOptions"]).and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(|v| v.as_str().map(String::from)).collect();
        let mode = access_mode(pv.pointer(&["spec", "accessModes"]).and_then(Value::as_array));
        let secrets = Self::secrets(c, pv, "nodeExpandSecretRef").await?;
        let mut w = Writer::new();
        w.string(1, handle).string(2, vol_path);
        w.message(3, |w| {
            w.varint(1, want);
        });
        w.string(4, if d.stage { staging } else { "" });
        capability(&mut w, 5, block, &fs_type, &flags, mode);
        map_field(&mut w, 6, &secrets);
        let others = |drop: &[&str]| -> Vec<String> { conds.iter().filter(|x| !drop.contains(&x.get("type").and_then(Value::as_str).unwrap_or(""))).map(json::to_string).collect() };
        match self.call(d, driver, EXPAND, w.as_bytes(), SLOW_MS).await {
            Ok(_) => {
                self.expand_backoff.borrow_mut().remove(&key);
                let req = pvc.pointer(&["spec", "resources", "requests", "storage"]).and_then(Value::as_str).unwrap_or("");
                let p = json::parse(format!(r#"{{"status":{{"capacity":{{"storage":{}}},"conditions":[{}]}}}}"#, q(req), others(&["FileSystemResizePending", "NodeResizeError"]).join(",")).as_bytes()).map_err(|_| "bad patch".to_string())?;
                c.patch(&format!("{path}/status"), "application/merge-patch+json", &p).await.map_err(|e| format!("cannot update status of persistentvolumeclaim {ns}/{claim} after expanding {pv_name}: {} ({})", e.message, e.code))?;
                self.event(c, &ns, &claim, pvc.pointer(&["metadata", "uid"]).and_then(Value::as_str).unwrap_or(""), "Normal", "VolumeResizeSuccessful", &format!("NodeExpandVolume succeeded for volume {pv_name}")).await;
                Ok(true)
            }
            Err(e) => {
                let fails = {
                    let mut b = self.expand_backoff.borrow_mut();
                    let n = b.get(&key).map_or(0, |x| x.0) + 1;
                    b.insert(key, (n, now + Self::backoff_ms(n)));
                    n
                };
                let cond = format!(r#"{{"type":"NodeResizeError","status":"True","lastTransitionTime":{},"reason":"NodeExpandFailed","message":{}}}"#, q(&kr_apiserver::object::rfc3339(now as i64 / 1000)), q(&e));
                let mut all = others(&["NodeResizeError"]);
                all.push(cond);
                if let Ok(p) = json::parse(format!(r#"{{"status":{{"conditions":[{}]}}}}"#, all.join(",")).as_bytes()) {
                    let _ = c.patch(&format!("{path}/status"), "application/merge-patch+json", &p).await;
                }
                if fails == 1 || fails.is_power_of_two() {
                    self.event(c, &ns, &claim, pvc.pointer(&["metadata", "uid"]).and_then(Value::as_str).unwrap_or(""), "Warning", "VolumeResizeFailed", &e).await;
                }
                Err(e)
            }
        }
    }

    /// Best-effort event on a claim.
    async fn event<C: Api>(&self, c: &C, ns: &str, name: &str, uid: &str, ty: &str, reason: &str, msg: &str) {
        let at = q(&kr_apiserver::object::rfc3339(kr_rt::exec::now_ms() as i64 / 1000));
        let body = format!(
            r#"{{"apiVersion":"v1","kind":"Event","metadata":{{"generateName":{},"namespace":{}}},"involvedObject":{{"apiVersion":"v1","kind":"PersistentVolumeClaim","namespace":{},"name":{},"uid":{}}},"type":{},"reason":{},"message":{},"source":{{"component":"kubelet","host":{}}},"reportingComponent":"kubelet","reportingInstance":{},"firstTimestamp":{at},"lastTimestamp":{at},"count":1}}"#,
            q(&format!("{name}.")),
            q(ns),
            q(ns),
            q(name),
            q(uid),
            q(ty),
            q(reason),
            q(msg),
            q(&self.node),
            q(&self.node)
        );
        if let Ok(ev) = json::parse(body.as_bytes()) {
            let _ = c.create(&format!("/api/v1/namespaces/{ns}/events"), &ev).await;
        }
    }

    /// Grows the volumes of running pods whose claim waits for it (`FileSystemResizePending` set
    /// by the external-resizer, or a raw block claim whose request exceeds `status.capacity`):
    /// `NodeExpandVolume`, then the claim's `status.capacity` is set and the condition removed.
    /// Failures are retried with backoff and shown as the claim condition `NodeResizeError`.
    /// Volumes nobody has mounted are expanded when a pod mounts them ([`Csi::mount_pv`]).
    /// Returns the number expanded.
    pub async fn expand_pending<C: Api>(&self, c: &C) -> usize {
        let Some(root) = self.root.as_deref() else { return 0 };
        let mut done: BTreeSet<(String, String)> = BTreeSet::new();
        for uid in self.pod_uids() {
            for (pv_name, driver, handle, eph) in Self::entries(root, &uid) {
                let key = (driver.clone(), handle.clone());
                let Ok(d) = self.driver(&driver) else { continue };
                if eph || !d.expand || done.contains(&key) {
                    continue;
                }
                let Ok(pv) = c.get(&format!("/api/v1/persistentvolumes/{pv_name}")).await else { continue };
                let base = format!("{root}/pods/{uid}/volumes/kubernetes.io~csi/{pv_name}");
                let staging = format!("{root}/plugins/kubernetes.io/csi/{driver}/{}/globalmount", sha(&handle));
                let vol_path = if d.stage { staging.clone() } else { format!("{base}/mount") };
                match self.expand_if_needed(c, &d, &driver, &handle, &pv, &vol_path, &staging, true).await {
                    Ok(true) => {
                        done.insert(key);
                    }
                    Ok(false) => {}
                    Err(e) => {
                        self.warn(&e);
                    }
                }
            }
        }
        done.len()
    }

    /// Where the PV `pv` of pod `uid` is published (the directory the container sees).
    pub fn publish_path(&self, uid: &str, pv: &str) -> Option<String> {
        let root = self.root.as_deref()?;
        Some(format!("{root}/pods/{uid}/volumes/kubernetes.io~csi/{pv}/mount"))
    }

    /// Usage of every volume mounted for a pod: `NodeGetVolumeStats` when the driver offers
    /// GET_VOLUME_STATS, otherwise `statfs` of the publish path. Volumes that cannot be read
    /// are left out.
    #[allow(dead_code)] // for the kubelet metrics endpoint (no caller yet)
    pub async fn volume_stats(&self) -> Vec<VolumeStats> {
        let Some(root) = self.root.as_deref() else { return Vec::new() };
        let mut out = Vec::new();
        for uid in self.pod_uids() {
            for (pv, driver, handle, eph) in Self::entries(root, &uid) {
                if eph {
                    continue;
                }
                let target = format!("{root}/pods/{uid}/volumes/kubernetes.io~csi/{pv}/mount");
                let mut s = VolumeStats { pod_uid: uid.clone(), pv, ..Default::default() };
                let via_driver = match self.driver(&driver) {
                    Ok(d) if d.stats => {
                        let mut w = Writer::new();
                        w.string(1, &handle).string(2, &target);
                        if d.stage {
                            w.string(3, &format!("{root}/plugins/kubernetes.io/csi/{driver}/{}/globalmount", sha(&handle)));
                        }
                        self.call(&d, &driver, STATS, w.as_bytes(), FAST_MS).await.ok().and_then(|b| decode_stats(&b).ok())
                    }
                    _ => None,
                };
                if let Some(([avail, total, used], [ifree, itotal, iused])) = via_driver {
                    (s.available_bytes, s.capacity_bytes, s.used_bytes, s.inodes_free, s.inodes, s.inodes_used) = (avail, total, used, ifree, itotal, iused);
                } else if !is_mount_point(&target) {
                    continue; // nothing mounted there (a failed publish): statfs would report the parent filesystem
                } else if let Ok([bs, blocks, bfree, bavail, files, ffree]) = kr_sys::ns::statfs(target.as_bytes()) {
                    (s.capacity_bytes, s.available_bytes, s.used_bytes) = (blocks * bs, bavail * bs, blocks.saturating_sub(bfree) * bs);
                    (s.inodes, s.inodes_free, s.inodes_used) = (files, ffree, files.saturating_sub(ffree));
                } else {
                    continue;
                }
                out.push(s);
            }
        }
        out
    }

    // -------------------------------------------------------------- unmounting

    /// Every (pv dir name, driver, handle) recorded under a pod.
    fn entries(root: &str, uid: &str) -> Vec<(String, String, String, bool)> {
        let base = format!("{root}/pods/{uid}/volumes/kubernetes.io~csi");
        list(&base)
            .into_iter()
            .filter(|n| safe_name(n))
            .filter_map(|n| {
                let b = kr_sys::fs::read_file(format!("{base}/{n}/vol_data.json\0").as_bytes(), 1 << 16).ok()?;
                let v = json::parse(&b).ok()?;
                let g = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                Some((n, g("driverName"), g("volumeHandle"), v.get("ephemeral").and_then(Value::as_bool) == Some(true)))
            })
            .collect()
    }

    /// Unpublishes the CSI volumes of a pod and unstages those nobody else uses. Failures are
    /// logged and kept (`vol_data.json` stays) for the next sweep.
    pub async fn unmount_pod(&self, uid: &str) {
        let Some(root) = self.root.as_deref() else { return };
        if !safe_name(uid) {
            return;
        }
        let base = format!("{root}/pods/{uid}/volumes/kubernetes.io~csi");
        let mut unstaged: BTreeSet<(String, String)> = BTreeSet::new();
        for (pv, driver, handle, eph) in Self::entries(root, uid) {
            let Some(d) = self.wait_driver(&driver).await else {
                self.warn(&format!("CSI driver {driver} is not registered; cannot unmount volume {pv} of pod {uid}"));
                continue;
            };
            let target = format!("{base}/{pv}/mount");
            let mut w = Writer::new();
            w.string(1, &handle).string(2, &target);
            if let Err(e) = self.call(&d, &driver, UNPUBLISH, w.as_bytes(), FAST_MS).await {
                self.warn(&e);
                continue;
            }
            self.published.borrow_mut().remove(&(uid.to_string(), pv.clone()));
            // A block volume's publish target is a file (a mount point or device node).
            let _ = kr_sys::fs::unlinkat(kr_sys::fs::AT_FDCWD, format!("{target}\0").as_bytes(), 0);
            if !rmdir(&target) && kr_sys::fs::newfstatat(kr_sys::fs::AT_FDCWD, format!("{target}\0").as_bytes(), kr_sys::fs::AT_SYMLINK_NOFOLLOW).is_ok() {
                self.warn(&format!("cannot remove {target}"));
                continue;
            }
            let key = (driver.clone(), handle.clone());
            if d.stage && !eph && !unstaged.contains(&key) && !self.in_use(root, uid, &driver, &handle) {
                let parent = format!("{root}/plugins/kubernetes.io/csi/{driver}/{}", sha(&handle));
                let staging = format!("{parent}/globalmount");
                let mut w = Writer::new();
                w.string(1, &handle).string(2, &staging);
                if let Err(e) = self.call(&d, &driver, UNSTAGE, w.as_bytes(), SLOW_MS).await {
                    self.warn(&e);
                    continue;
                }
                rmdir(&staging);
                rmdir(&parent);
                self.staged.borrow_mut().remove(&key);
                unstaged.insert(key);
            }
            let _ = kr_sys::fs::unlinkat(kr_sys::fs::AT_FDCWD, format!("{base}/{pv}/vol_data.json\0").as_bytes(), 0);
            rmdir(&format!("{base}/{pv}"));
        }
        // Empty directories only; rmdir never descends into anything.
        let pod = format!("{root}/pods/{uid}");
        let _ = rmdir(&base) && rmdir(&format!("{pod}/volumes")) && rmdir(&pod);
    }

    async fn wait_driver(&self, name: &str) -> Option<Driver> {
        for _ in 0..30 {
            if let Ok(d) = self.driver(name) {
                return Some(d);
            }
            sleep(500).await;
        }
        None
    }

    /// Whether a pod other than `uid` still has the volume published.
    fn in_use(&self, root: &str, uid: &str, driver: &str, handle: &str) -> bool {
        list(&format!("{root}/pods")).iter().filter(|p| safe_name(p) && *p != uid).any(|p| Self::entries(root, p).iter().any(|(_, d, h, _)| d == driver && h == handle))
    }
}

fn write_private(path: &str, data: &[u8]) -> Result<(), ()> {
    let fd = kr_sys::fs::openat(kr_sys::fs::AT_FDCWD, format!("{path}\0").as_bytes(), kr_sys::fs::O_WRONLY | kr_sys::fs::O_CREAT | kr_sys::fs::O_TRUNC | kr_sys::fs::O_NOFOLLOW | kr_sys::O_CLOEXEC, 0o600).map_err(|_| ())?;
    match kr_sys::write(fd.raw(), data) {
        Ok(n) if n == data.len() => Ok(()),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_apiserver::client::{Result as ApiResult, Watch};
    use kr_apiserver::object::ApiError;
    use kr_net::grpc::{self, Responder, Status};
    use kr_rt::exec::{block_on, spawn, Async};

    // One executor-driven test at a time, shared with the device plugin tests.
    use crate::deviceplugin::tests::lock;

    fn tmpdir(name: &str) -> String {
        let p = std::env::temp_dir().join(format!("krcsi-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(p.join("plugins_registry")).unwrap();
        p.to_str().unwrap().into()
    }

    static LINK_TARGET: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    static FAIL_EXPAND: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

    type Calls = Rc<RefCell<Vec<(String, Vec<u8>)>>>;

    fn fake_driver(path: &str, stage: bool) -> Calls {
        fake_driver_with(path, if stage { &[1] } else { &[] }, 0)
    }

    /// `caps`: node capability types offered; `max`: `max_volumes_per_node`.
    fn fake_driver_with(path: &str, caps: &'static [u64], max: u64) -> Calls {
        let calls: Calls = Rc::new(RefCell::new(Vec::new()));
        let fd = kr_sys::ns::unix_listen(path.as_bytes()).unwrap();
        kr_sys::ns::set_nonblocking(fd.raw()).unwrap();
        let l = Async::new(fd).unwrap();
        let rec = calls.clone();
        spawn(grpc::serve(
            l,
            Rc::new(move |m: String, req: Vec<u8>, r: Responder| {
                let rec = rec.clone();
                async move {
                    rec.borrow_mut().push((m.clone(), req.clone()));
                    let mut w = Writer::new();
                    match m.as_str() {
                        GET_INFO => {
                            w.string(1, "CSIPlugin").string(2, "fake.csi");
                        }
                        NODE_INFO => {
                            w.string(1, "node-id-1");
                            if max > 0 {
                                w.varint(2, max);
                            }
                            w.message(3, |w| {
                                w.message(1, |w| {
                                    w.string(1, "topology.fake/zone").string(2, "z1");
                                });
                            });
                        }
                        NODE_CAPS => {
                            for t in caps {
                                w.message(1, |w| {
                                    w.message(1, |w| {
                                        w.varint(1, *t);
                                    });
                                });
                            }
                        }
                        PUBLISH if LINK_TARGET.load(core::sync::atomic::Ordering::SeqCst) => {
                            // A "block device" for the test: a link to /dev/null at the target path.
                            let t = field(&req, 4);
                            let _ = kr_sys::fs::unlinkat(kr_sys::fs::AT_FDCWD, format!("{t}\0").as_bytes(), 0);
                            let _ = kr_sys::fs::symlinkat(b"/dev/null\0", kr_sys::fs::AT_FDCWD, format!("{t}\0").as_bytes());
                        }
                        EXPAND if FAIL_EXPAND.load(core::sync::atomic::Ordering::SeqCst) => {
                            return r.finish(Status::new(13, "disk is busy")).await;
                        }
                        STATS => {
                            for (unit, v) in [(1, [400, 1000, 600]), (2, [90, 100, 10])] {
                                w.message(1, |w| {
                                    w.varint(1, v[0]).varint(2, v[1]).varint(3, v[2]).varint(4, unit);
                                });
                            }
                        }
                        _ => {}
                    }
                    let _ = r.send(w.as_bytes()).await;
                    r.finish(Status::ok()).await
                }
            }),
        ));
        calls
    }

    #[derive(Default)]
    struct Fake {
        objs: BTreeMap<String, Value>,
        log: RefCell<Vec<(String, String, String)>>,
    }

    impl Api for Fake {
        async fn get(&self, path: &str) -> ApiResult<Value> {
            self.objs.get(path).cloned().ok_or_else(|| ApiError::new(404, "NotFound", "nf"))
        }
        async fn list(&self, _: &str, _: &str) -> ApiResult<Value> {
            Err(ApiError::new(500, "x", "x"))
        }
        async fn create(&self, path: &str, obj: &Value) -> ApiResult<Value> {
            self.log.borrow_mut().push(("create".into(), path.into(), json::to_string(obj)));
            Ok(obj.clone())
        }
        async fn update(&self, path: &str, obj: &Value) -> ApiResult<Value> {
            self.log.borrow_mut().push(("update".into(), path.into(), json::to_string(obj)));
            Ok(obj.clone())
        }
        async fn patch(&self, path: &str, _: &str, p: &Value) -> ApiResult<Value> {
            self.log.borrow_mut().push(("patch".into(), path.into(), json::to_string(p)));
            Ok(p.clone())
        }
        async fn delete(&self, _: &str) -> ApiResult<Value> {
            Err(ApiError::new(500, "x", "x"))
        }
        async fn watch(&self, _: &str, _: &str) -> ApiResult<Watch> {
            Err(ApiError::new(500, "x", "x"))
        }
    }

    fn obj(s: &str) -> Value {
        json::parse_str(s).unwrap()
    }

    fn fields(b: &[u8]) -> Vec<(u32, Vec<u8>)> {
        let mut v = Vec::new();
        walk(b, |n, f| v.push((n, f.as_bytes().map(<[u8]>::to_vec).unwrap_or_else(|| f.as_varint().unwrap_or(0).to_string().into_bytes())))).unwrap();
        v
    }

    fn field(b: &[u8], n: u32) -> String {
        fields(b).into_iter().find(|f| f.0 == n).map(|f| String::from_utf8(f.1).unwrap()).unwrap_or_default()
    }

    fn pod(uid: &str) -> Value {
        obj(&format!(r#"{{"metadata":{{"name":"p-{uid}","namespace":"ns","uid":"{uid}"}},"spec":{{"serviceAccountName":"sa"}}}}"#))
    }

    fn pv() -> Value {
        obj(r#"{"metadata":{"name":"pvc-1"},"spec":{"accessModes":["ReadWriteMany"],"mountOptions":["noatime"],"csi":{"driver":"fake.csi","volumeHandle":"vol-1","fsType":"xfs","volumeAttributes":{"a":"b"},"nodeStageSecretRef":{"name":"sec","namespace":"ns"}}}}"#)
    }

    fn names(calls: &Calls) -> Vec<String> {
        calls.borrow().iter().map(|c| c.0.rsplit('/').next().unwrap().to_string()).collect()
    }

    #[test]
    fn registration_mount_and_unmount() {
        let _g = lock();
        let root = tmpdir("full");
        let calls = fake_driver(&format!("{root}/plugins_registry/fake.sock"), true);
        let csi = Csi::with_root(Some(root.clone()), "node1");
        let mut fake = Fake::default();
        fake.objs.insert("/api/v1/nodes/node1".into(), obj(r#"{"metadata":{"uid":"nuid"}}"#));
        fake.objs.insert("/apis/storage.k8s.io/v1/csidrivers/fake.csi".into(), obj(r#"{"spec":{"attachRequired":true,"podInfoOnMount":true}}"#));
        let va = format!("/apis/storage.k8s.io/v1/volumeattachments/csi-{}", sha("vol-1fake.csinode1"));
        fake.objs.insert("/api/v1/namespaces/ns/secrets/sec".into(), obj(r#"{"data":{"k":"dg=="}}"#));
        let (c2, root2) = (csi.clone(), root.clone());
        block_on(async move {
            let csi = c2;
            assert!(csi.tick().await);
            let d = csi.driver("fake.csi").unwrap();
            assert_eq!((d.node_id.as_str(), d.stage, d.topology_keys.as_slice()), ("node-id-1", true, &["topology.fake/zone".to_string()][..]));
            assert!(!csi.tick().await);
            assert!(csi.sync_csinode(&fake).await);
            let log = fake.log.borrow().clone();
            assert_eq!(log[0].0, "create");
            assert!(log[0].2.contains(r#""nodeID":"node-id-1""#) && log[0].2.contains("nuid") && log[0].2.contains("topology.fake/zone"), "{}", log[0].2);
            assert!(log[1].2.contains("csi.volume.kubernetes.io/nodeid") && log[1].2.contains("node-id-1"));

            // Not attached yet.
            let e = csi.mount_pv(&fake, &pod("u1"), &pv(), false).await.unwrap_err();
            assert_eq!(e, format!("waiting for volume attachment {}", va.rsplit('/').next().unwrap()));
            let mut fake = fake;
            fake.objs.insert(va, obj(r#"{"status":{"attached":true,"attachmentMetadata":{"devicePath":"/dev/x"}}}"#));
            let t = csi.mount_pv(&fake, &pod("u1"), &pv(), true).await.unwrap();
            assert_eq!(t, format!("{root2}/pods/u1/volumes/kubernetes.io~csi/pvc-1/mount"));
            let stage = calls.borrow().iter().find(|c| c.0 == STAGE).unwrap().1.clone();
            assert_eq!(field(&stage, 1), "vol-1");
            assert_eq!(kv_of(&stage, 2), [("devicePath".to_string(), "/dev/x".to_string())]);
            assert_eq!(field(&stage, 3), format!("{root2}/plugins/kubernetes.io/csi/fake.csi/{}/globalmount", sha("vol-1")));
            let capb = fields(&stage).into_iter().find(|f| f.0 == 4).unwrap().1;
            let mount = fields(&capb).into_iter().find(|f| f.0 == 2).unwrap().1;
            assert_eq!((field(&mount, 1), field(&mount, 2)), ("xfs".to_string(), "noatime".to_string()));
            assert_eq!(field(&fields(&capb).into_iter().find(|f| f.0 == 3).unwrap().1, 1), "5");
            assert_eq!(kv_of(&stage, 6), [("a".to_string(), "b".to_string())]);
            // Secret data comes from the API (decoded).
            assert_eq!(kv_of(&stage, 5), [("k".to_string(), "v".to_string())]);
            let publish = calls.borrow().iter().find(|c| c.0 == PUBLISH).unwrap().1.clone();
            assert_eq!(field(&publish, 4), t);
            assert_eq!(field(&publish, 3), field(&stage, 3));
            assert_eq!(field(&publish, 6), "1");
            let ctx = kv_of(&publish, 8);
            assert!(ctx.contains(&("csi.storage.k8s.io/pod.uid".to_string(), "u1".to_string())) && ctx.contains(&("csi.storage.k8s.io/ephemeral".to_string(), "false".to_string())));
            let vd = std::fs::read_to_string(format!("{root2}/pods/u1/volumes/kubernetes.io~csi/pvc-1/vol_data.json")).unwrap();
            assert!(vd.contains(r#""volumeHandle":"vol-1""#) && vd.contains(r#""nodeName":"node1""#));
            // Repeats are cached; a second pod stages nothing new.
            csi.mount_pv(&fake, &pod("u1"), &pv(), true).await.unwrap();
            csi.mount_pv(&fake, &pod("u2"), &pv(), false).await.unwrap();
            assert_eq!(names(&calls).iter().filter(|n| *n == "NodeStageVolume").count(), 1);
            assert_eq!(names(&calls).iter().filter(|n| *n == "NodePublishVolume").count(), 2);

            calls.borrow_mut().clear();
            csi.unmount_pod("u1").await;
            assert_eq!(names(&calls), ["NodeUnpublishVolume"]);
            let un = calls.borrow()[0].1.clone();
            assert_eq!((field(&un, 1), field(&un, 2)), ("vol-1".to_string(), t));
            assert!(!std::path::Path::new(&format!("{root2}/pods/u1")).exists());
            csi.unmount_pod("u2").await;
            assert_eq!(names(&calls), ["NodeUnpublishVolume", "NodeUnpublishVolume", "NodeUnstageVolume"]);
            assert_eq!(field(&calls.borrow()[2].1, 2), format!("{root2}/plugins/kubernetes.io/csi/fake.csi/{}/globalmount", sha("vol-1")));
            assert!(!std::path::Path::new(&format!("{root2}/pods/u2")).exists());

            // Socket gone: driver dropped.
            std::fs::remove_file(format!("{root2}/plugins_registry/fake.sock")).unwrap();
            assert!(csi.tick().await);
            assert!(csi.driver("fake.csi").is_err());
            let e = csi.mount_pv(&fake, &pod("u3"), &pv(), false).await.unwrap_err();
            assert_eq!(e, "CSI driver fake.csi is not registered on this node");
        });
    }

    fn kv_of(b: &[u8], n: u32) -> Vec<(String, String)> {
        fields(b).into_iter().filter(|f| f.0 == n).map(|f| (field(&f.1, 1), field(&f.1, 2))).collect()
    }

    #[test]
    fn driver_without_stage_capability_skips_stage() {
        let _g = lock();
        let root = tmpdir("nostage");
        let calls = fake_driver(&format!("{root}/plugins_registry/plain.sock"), false);
        let csi = Csi::with_root(Some(root.clone()), "node1");
        let mut fake = Fake::default();
        fake.objs.insert("/apis/storage.k8s.io/v1/csidrivers/fake.csi".into(), obj(r#"{"spec":{"attachRequired":false}}"#));
        block_on(async move {
            assert!(csi.tick().await);
            assert!(!csi.driver("fake.csi").unwrap().stage);
            csi.mount_pv(&fake, &pod("u1"), &pv(), false).await.unwrap();
            let n = names(&calls);
            assert!(!n.iter().any(|n| n.contains("Stage")) && n.contains(&"NodePublishVolume".to_string()), "{n:?}");
            let publish = calls.borrow().iter().find(|c| c.0 == PUBLISH).unwrap().1.clone();
            assert_eq!(field(&publish, 3), "");
            csi.unmount_pod("u1").await;
            assert!(!names(&calls).iter().any(|n| n.contains("Unstage")));
        });
    }

    #[test]
    fn disabled_and_malformed() {
        let _g = lock();
        let csi = Csi::with_root(None, "n");
        let f = Fake::default();
        let c2 = csi.clone();
        let e = block_on(async move { c2.mount_pv(&f, &pod("u"), &pv(), false).await }).unwrap_err();
        assert_eq!(e, DISABLED);
        assert!(decode_plugin_info(&[0x0a, 0xff]).is_err());
        assert!(decode_node_info(&[0x1a, 9]).is_err());
        assert!(decode_caps(&[0xff]).is_err());
        block_on(async move { csi.unmount_pod("u").await });
    }

    #[test]
    fn volumes_in_use_stats_and_limits() {
        let _g = lock();
        let root = tmpdir("inuse");
        let calls = fake_driver_with(&format!("{root}/plugins_registry/fake.sock"), &[1, 2, 3], 7);
        let csi = Csi::with_root(Some(root.clone()), "node1");
        let mut fake = Fake::default();
        fake.objs.insert("/api/v1/nodes/node1".into(), obj(r#"{"metadata":{"uid":"nuid"}}"#));
        fake.objs.insert("/apis/storage.k8s.io/v1/csidrivers/fake.csi".into(), obj(r#"{"spec":{"attachRequired":false}}"#));
        fake.objs.insert("/api/v1/namespaces/ns/secrets/sec".into(), obj(r#"{"data":{}}"#));
        block_on(async move {
            assert!(csi.tick().await);
            let d = csi.driver("fake.csi").unwrap();
            assert_eq!((d.stats, d.expand, d.max_volumes), (true, true, 7));
            assert!(csi.sync_csinode(&fake).await);
            assert!(fake.log.borrow()[0].2.contains(r#""allocatable":{"count":7}"#), "{}", fake.log.borrow()[0].2);

            // Nothing mounted: an empty list is reported once.
            csi.report_in_use(&fake).await;
            csi.report_in_use(&fake).await;
            let patches: Vec<String> = fake.log.borrow().iter().filter(|l| l.1.ends_with("/nodes/node1/status")).map(|l| l.2.clone()).collect();
            assert_eq!(patches, [r#"{"status":{"volumesInUse":[]}}"#]);

            csi.mount_pv(&fake, &pod("u1"), &pv(), false).await.unwrap();
            csi.mount_pv(&fake, &pod("u2"), &pv(), false).await.unwrap();
            assert_eq!(csi.volumes_in_use(), ["kubernetes.io/csi/fake.csi^vol-1"]);
            csi.report_in_use(&fake).await;
            let last = fake.log.borrow().last().unwrap().2.clone();
            assert_eq!(last, r#"{"status":{"volumesInUse":["kubernetes.io/csi/fake.csi^vol-1"]}}"#);

            let st = csi.volume_stats().await;
            assert_eq!(st.len(), 2);
            assert_eq!((st[0].pod_uid.as_str(), st[0].pv.as_str(), st[0].capacity_bytes, st[0].used_bytes, st[0].available_bytes), ("u1", "pvc-1", 1000, 600, 400));
            assert_eq!((st[0].inodes, st[0].inodes_used, st[0].inodes_free), (100, 10, 90));
            let req = calls.borrow().iter().find(|c| c.0 == STATS).unwrap().1.clone();
            assert_eq!(field(&req, 1), "vol-1");
            assert!(field(&req, 3).ends_with("/globalmount"));

            // Still in use while one pod holds it; gone after both unmount.
            csi.unmount_pod("u1").await;
            assert_eq!(csi.volumes_in_use().len(), 1);
            csi.unmount_pod("u2").await;
            assert!(csi.volumes_in_use().is_empty());
            csi.report_in_use(&fake).await;
            assert_eq!(fake.log.borrow().last().unwrap().2, r#"{"status":{"volumesInUse":[]}}"#);
        });
    }

    #[test]
    fn stats_skip_unmounted_paths() {
        let _g = lock();
        let root = tmpdir("statfs");
        let _calls = fake_driver_with(&format!("{root}/plugins_registry/fake.sock"), &[], 0);
        let csi = Csi::with_root(Some(root.clone()), "node1");
        let mut fake = Fake::default();
        fake.objs.insert("/apis/storage.k8s.io/v1/csidrivers/fake.csi".into(), obj(r#"{"spec":{"attachRequired":false}}"#));
        block_on(async move {
            csi.tick().await;
            let t = csi.mount_pv(&fake, &pod("u1"), &pv(), false).await.unwrap();
            std::fs::create_dir_all(&t).unwrap(); // the fake driver mounts nothing
            // Nothing is mounted at the publish path: statfs would describe the parent, so no stats.
            assert!(csi.volume_stats().await.is_empty());
            assert_eq!(fake.log.borrow().iter().filter(|l| l.1.contains("allocatable")).count(), 0);
            csi.unmount_pod("u1").await;
        });
    }

    #[test]
    fn mountinfo_matching() {
        let info = b"36 25 0:30 / /var/lib/kr/pods/u1/mount rw - ext4 /dev/sda rw\n37 25 0:31 / /mnt/with\\040space rw - tmpfs t rw\n";
        assert!(in_mountinfo(info, "/var/lib/kr/pods/u1/mount"));
        assert!(in_mountinfo(info, "/mnt/with space/"));
        assert!(!in_mountinfo(info, "/var/lib/kr/pods/u1"));
        assert!(!in_mountinfo(info, "/var/lib/kr/pods/u1/mount/sub"));
        assert!(is_mount_point("/proc"));
    }

    #[test]
    fn expands_volume_once_the_resizer_is_done() {
        let _g = lock();
        let root = tmpdir("expand");
        let calls = fake_driver_with(&format!("{root}/plugins_registry/fake.sock"), &[1, 3], 0);
        let csi = Csi::with_root(Some(root.clone()), "node1");
        let mut fake = Fake::default();
        fake.objs.insert("/apis/storage.k8s.io/v1/csidrivers/fake.csi".into(), obj(r#"{"spec":{"attachRequired":false}}"#));
        let pvj = r#"{"metadata":{"name":"pvc-1"},"spec":{"capacity":{"storage":"2Gi"},"claimRef":{"namespace":"ns","name":"data"},"csi":{"driver":"fake.csi","volumeHandle":"vol-1","fsType":"xfs"}}}"#;
        fake.objs.insert("/api/v1/persistentvolumes/pvc-1".into(), obj(pvj));
        let claim = |conds: &str, cap: &str| obj(&format!(r#"{{"spec":{{"resources":{{"requests":{{"storage":"2Gi"}}}}}},"status":{{"capacity":{{"storage":"{cap}"}},"conditions":[{conds}]}}}}"#));
        let path = "/api/v1/namespaces/ns/persistentvolumeclaims/data";
        let pend = r#"{"type":"FileSystemResizePending","status":"True"},{"type":"Other","status":"True"}"#;
        block_on(async move {
            csi.tick().await;
            let mut fake = fake;
            csi.mount_pv(&fake, &pod("u1"), &obj(pvj), false).await.unwrap();
            // No pending condition, or already grown: nothing happens.
            fake.objs.insert(path.into(), claim("", "1Gi"));
            assert_eq!(csi.expand_pending(&fake).await, 0);
            fake.objs.insert(path.into(), claim(pend, "2Gi"));
            assert_eq!(csi.expand_pending(&fake).await, 0);
            assert!(!names(&calls).contains(&"NodeExpandVolume".to_string()));

            fake.objs.insert(path.into(), claim(pend, "1Gi"));
            assert_eq!(csi.expand_pending(&fake).await, 1);
            let req = calls.borrow().iter().find(|c| c.0 == EXPAND).unwrap().1.clone();
            assert_eq!(field(&req, 1), "vol-1");
            assert!(field(&req, 2).ends_with("/globalmount"));
            assert_eq!(field(&fields(&req).into_iter().find(|f| f.0 == 3).unwrap().1, 1), (2u64 << 30).to_string());
            let l = fake.log.borrow().iter().find(|l| l.0 == "patch" && l.1.ends_with("/status") && l.1.contains("persistentvolumeclaims")).unwrap().clone();
            assert_eq!(l.2, r#"{"status":{"capacity":{"storage":"2Gi"},"conditions":[{"type":"Other","status":"True"}]}}"#);
            csi.unmount_pod("u1").await;
        });
    }

    fn expand_fixture(name: &str, vmode: &str) -> (String, Calls, Rc<Csi>, Fake, String) {
        let root = tmpdir(name);
        let calls = fake_driver_with(&format!("{root}/plugins_registry/fake.sock"), &[1, 3], 0);
        let csi = Csi::with_root(Some(root.clone()), "node1");
        let mut fake = Fake::default();
        fake.objs.insert("/apis/storage.k8s.io/v1/csidrivers/fake.csi".into(), obj(r#"{"spec":{"attachRequired":false}}"#));
        let pvj = format!(r#"{{"metadata":{{"name":"pvc-1"}},"spec":{{"volumeMode":"{vmode}","capacity":{{"storage":"2Gi"}},"accessModes":["ReadWriteOncePod"],"claimRef":{{"namespace":"ns","name":"data"}},"csi":{{"driver":"fake.csi","volumeHandle":"vol-1","fsType":"xfs"}}}}}}"#);
        fake.objs.insert("/api/v1/persistentvolumes/pvc-1".into(), obj(&pvj));
        fake.objs.insert("/api/v1/namespaces/ns/persistentvolumeclaims/data".into(), obj(r#"{"metadata":{"uid":"cu"},"spec":{"resources":{"requests":{"storage":"2Gi"}}},"status":{"capacity":{"storage":"1Gi"},"conditions":[{"type":"FileSystemResizePending","status":"True"}]}}"#));
        (root, calls, csi, fake, pvj)
    }

    #[test]
    fn offline_expansion_on_mount_then_failures_back_off_with_a_resize_error_condition() {
        let _g = lock();
        let (_root, calls, csi, fake, pvj) = expand_fixture("offline", "Filesystem");
        block_on(async move {
            csi.tick().await;
            // Nothing mounted before: the grown claim is expanded while the volume is staged.
            FAIL_EXPAND.store(true, core::sync::atomic::Ordering::SeqCst);
            let e = csi.mount_pv(&fake, &pod("u1"), &obj(&pvj), false).await.unwrap_err();
            assert!(e.contains("NodeExpandVolume failed") && e.contains("disk is busy"), "{e}");
            let log = fake.log.borrow().clone();
            let cond = log.iter().find(|l| l.0 == "patch" && l.2.contains("NodeResizeError")).expect("condition patched");
            assert!(cond.2.contains(r#""reason":"NodeExpandFailed""#) && cond.2.contains("FileSystemResizePending"), "{}", cond.2);
            assert!(log.iter().any(|l| l.0 == "create" && l.1.ends_with("/events") && l.2.contains("VolumeResizeFailed") && l.2.contains(r#""kind":"PersistentVolumeClaim""#)));
            // Within the backoff window the driver is not called again.
            let n = calls.borrow().iter().filter(|c| c.0 == EXPAND).count();
            assert!(csi.mount_pv(&fake, &pod("u1"), &obj(&pvj), false).await.unwrap_err().contains("retrying in"));
            assert_eq!(calls.borrow().iter().filter(|c| c.0 == EXPAND).count(), n);
            // After the delay, a working driver succeeds: capacity set, error condition gone, ReadWriteOncePod sent as SINGLE_NODE_SINGLE_WRITER.
            FAIL_EXPAND.store(false, core::sync::atomic::Ordering::SeqCst);
            csi.expand_backoff.borrow_mut().clear();
            csi.mount_pv(&fake, &pod("u1"), &obj(&pvj), false).await.unwrap();
            let req = calls.borrow().iter().rev().find(|c| c.0 == EXPAND).unwrap().1.clone();
            let cap = fields(&req).into_iter().find(|f| f.0 == 5).unwrap().1;
            assert_eq!(field(&fields(&cap).into_iter().find(|f| f.0 == 3).unwrap().1, 1), "6");
            let ok = fake.log.borrow().iter().rev().find(|l| l.0 == "patch" && l.2.contains(r#""capacity""#)).unwrap().clone();
            assert_eq!(ok.2, r#"{"status":{"capacity":{"storage":"2Gi"},"conditions":[]}}"#);
            assert!(csi.expand_backoff.borrow().is_empty());
            csi.unmount_pod("u1").await;
        });
        assert!(backoff_series());
    }

    fn backoff_series() -> bool {
        [1, 2, 3, 7, 20].map(Csi::backoff_ms) == [2_000, 4_000, 8_000, 122_000, 122_000]
    }

    #[test]
    fn raw_block_volume_is_staged_published_as_a_device_expanded_and_unlinked() {
        let _g = lock();
        let (root, calls, csi, mut fake, pvj) = expand_fixture("block", "Block");
        // A block claim has no FileSystemResizePending condition: the larger request is enough.
        fake.objs.insert("/api/v1/namespaces/ns/persistentvolumeclaims/data".into(), obj(r#"{"metadata":{"uid":"cu"},"spec":{"resources":{"requests":{"storage":"2Gi"}}},"status":{"capacity":{"storage":"1Gi"}}}"#));
        block_on(async move {
            csi.tick().await;
            // The driver creates no device node: the pod must not start with a missing device.
            LINK_TARGET.store(false, core::sync::atomic::Ordering::SeqCst);
            let e = csi.mount_pv(&fake, &pod("u1"), &obj(&pvj), false).await.unwrap_err();
            assert!(e.contains("did not create a block device"), "{e}");
            LINK_TARGET.store(true, core::sync::atomic::Ordering::SeqCst);
            let t = csi.mount_pv(&fake, &pod("u1"), &obj(&pvj), false).await.unwrap();
            assert_eq!(t, format!("{root}/pods/u1/volumes/kubernetes.io~csi/pvc-1/mount"));
            // The publish capability has the block access type (field 1) and no mount type (field 2).
            let publish = calls.borrow().iter().find(|c| c.0 == PUBLISH).unwrap().1.clone();
            let cap = fields(&fields(&publish).into_iter().find(|f| f.0 == 5).unwrap().1);
            assert!(cap.iter().any(|f| f.0 == 1) && !cap.iter().any(|f| f.0 == 2));
            // Expanded as a block capability.
            let ex = calls.borrow().iter().find(|c| c.0 == EXPAND).unwrap().1.clone();
            let cap = fields(&fields(&ex).into_iter().find(|f| f.0 == 5).unwrap().1);
            assert!(cap.iter().any(|f| f.0 == 1) && !cap.iter().any(|f| f.0 == 2));
            // Unmount removes the file (not only directories).
            csi.unmount_pod("u1").await;
            assert!(kr_sys::fs::newfstatat(kr_sys::fs::AT_FDCWD, format!("{t}\0").as_bytes(), kr_sys::fs::AT_SYMLINK_NOFOLLOW).is_err());
            LINK_TARGET.store(false, core::sync::atomic::Ordering::SeqCst);
        });
    }

    #[test]
    fn inline_ephemeral_volume_is_published_without_attach_or_stage_and_not_reported_in_use() {
        let _g = lock();
        let root = tmpdir("inline");
        let calls = fake_driver(&format!("{root}/plugins_registry/fake.sock"), true);
        let csi = Csi::with_root(Some(root.clone()), "node1");
        let mut fake = Fake::default();
        let vol = obj(r#"{"name":"scratch","csi":{"driver":"fake.csi","fsType":"ext4","readOnly":true,"volumeAttributes":{"size":"1Gi"},"nodePublishSecretRef":{"name":"s"}}}"#);
        block_on(async move {
            csi.tick().await;
            // The driver is not ephemeral-capable, or has no CSIDriver at all.
            assert!(csi.mount_ephemeral(&fake, &pod("u1"), &vol).await.unwrap_err().contains("CSIDriver"));
            fake.objs.insert("/apis/storage.k8s.io/v1/csidrivers/fake.csi".into(), obj(r#"{"spec":{"volumeLifecycleModes":["Persistent"]}}"#));
            assert!(csi.mount_ephemeral(&fake, &pod("u1"), &vol).await.unwrap_err().contains("does not support ephemeral"));
            fake.objs.insert("/apis/storage.k8s.io/v1/csidrivers/fake.csi".into(), obj(r#"{"spec":{"attachRequired":true,"podInfoOnMount":true,"volumeLifecycleModes":["Persistent","Ephemeral"]}}"#));
            fake.objs.insert("/api/v1/namespaces/ns/secrets/s".into(), obj(r#"{"data":{"k":"dg=="}}"#));
            let t = csi.mount_ephemeral(&fake, &pod("u1"), &vol).await.unwrap();
            assert!(t.ends_with("/pods/u1/volumes/kubernetes.io~csi/scratch/mount"));
            assert_eq!(names(&calls).iter().filter(|n| *n == "NodePublishVolume").count(), 1);
            assert!(!names(&calls).contains(&"NodeStageVolume".to_string()));
            let req = calls.borrow().iter().find(|c| c.0 == PUBLISH).unwrap().1.clone();
            assert!(field(&req, 1).starts_with("csi-") && field(&req, 3).is_empty() && field(&req, 4) == t);
            let ctx = kv_of(&req, 8);
            assert!(ctx.contains(&("size".into(), "1Gi".into())) && ctx.contains(&("csi.storage.k8s.io/ephemeral".into(), "true".into())) && ctx.contains(&("csi.storage.k8s.io/pod.name".into(), "p-u1".into())));
            assert_eq!(kv_of(&req, 7), [("k".to_string(), "v".to_string())]);
            assert!(csi.volumes_in_use().is_empty(), "inline volumes are not attached");
            csi.unmount_pod("u1").await;
            let n = names(&calls);
            assert!(n.contains(&"NodeUnpublishVolume".to_string()) && !n.contains(&"NodeUnstageVolume".to_string()), "{n:?}");
        });
    }
}

/// Whether `path` is a mount point (an exact mount point entry in /proc/self/mountinfo, so bind
/// mounts within one filesystem count).
fn is_mount_point(path: &str) -> bool {
    kr_sys::fs::read_file(b"/proc/self/mountinfo\0", 1 << 22).map(|i| in_mountinfo(&i, path)).unwrap_or(false)
}

fn in_mountinfo(info: &[u8], path: &str) -> bool {
    let want = path.trim_end_matches('/').as_bytes();
    info.split(|&b| b == b'\n').any(|l| {
        let Some(mp) = l.split(|&b| b == b' ').nth(4) else { return false };
        let mut o = Vec::with_capacity(mp.len());
        let mut i = 0;
        while i < mp.len() {
            if mp[i] == b'\\' && i + 3 < mp.len() && mp[i + 1..i + 4].iter().all(|b| (b'0'..=b'7').contains(b)) {
                o.push((mp[i + 1] - b'0') * 64 + (mp[i + 2] - b'0') * 8 + (mp[i + 3] - b'0'));
                i += 4;
            } else {
                o.push(mp[i]);
                i += 1;
            }
        }
        o == want
    })
}
