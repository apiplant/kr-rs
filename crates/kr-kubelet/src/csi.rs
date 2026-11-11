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

/// `NodeGetInfoResponse` -> (node id, topology segment keys).
fn decode_node_info(b: &[u8]) -> Result<(String, Vec<String>), ()> {
    let (mut id, mut keys) = (String::new(), Vec::new());
    walk(b, |k, f| match k {
        1 => id = f.as_str().unwrap_or("").to_string(),
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
    Ok((id, keys))
}

/// Whether the node offers STAGE_UNSTAGE_VOLUME.
fn decode_stage_cap(b: &[u8]) -> Result<bool, ()> {
    let mut stage = false;
    walk(b, |k, f| {
        if k == 1 {
            let _ = walk(f.as_bytes().unwrap_or(&[]), |k, f| {
                if k == 1 {
                    let _ = walk(f.as_bytes().unwrap_or(&[]), |k, f| stage |= k == 1 && f.as_varint() == Some(1));
                }
            });
        }
    })?;
    Ok(stage)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Driver {
    endpoint: String,
    node_id: String,
    topology_keys: Vec<String>,
    stage: bool,
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
    /// CSINode and the node annotation need to be rewritten.
    dirty: Cell<bool>,
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
        Rc::new(Csi { root, node: node.to_string(), drivers: RefCell::new(BTreeMap::new()), ignored: RefCell::new(BTreeSet::new()), staged: RefCell::new(BTreeSet::new()), published: RefCell::new(BTreeSet::new()), warned: RefCell::new(BTreeSet::new()), dirty: Cell::new(false) })
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
        loop {
            if self.tick().await {
                self.dirty.set(true);
            }
            if self.dirty.get() && self.sync_csinode(&c).await {
                self.dirty.set(false);
            }
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
        let (node_id, topology_keys) = decode_node_info(&b).map_err(|()| "malformed NodeGetInfoResponse".to_string())?;
        if node_id.is_empty() {
            return Err("NodeGetInfo returned no node_id".to_string());
        }
        let b = ec.unary(NODE_CAPS, &[], FAST_MS).await.map_err(|s| format!("NodeGetCapabilities: {} ({})", s.message, s.code))?;
        let stage = decode_stage_cap(&b).map_err(|()| "malformed NodeGetCapabilitiesResponse".to_string())?;
        self.notify(sock, true, "").await;
        kr_rt::eprint(format!("kubelet: CSI driver {name} registered (node id {node_id}, stage {stage})\n").as_bytes());
        Ok(Some((name, Driver { endpoint, node_id, topology_keys, stage, reg_sock: sock.to_string(), reg_inode: ino })))
    }

    /// Rewrites the CSINode object and the node-id annotation. True on success.
    async fn sync_csinode<C: Api>(&self, c: &C) -> bool {
        let node = &self.node;
        let Ok(n) = c.get(&format!("/api/v1/nodes/{node}")).await else { return false };
        let uid = n.pointer(&["metadata", "uid"]).and_then(Value::as_str).unwrap_or("");
        let drivers: Vec<(String, Driver)> = self.drivers.borrow().iter().map(|(k, d)| (k.clone(), d.clone())).collect();
        let list: Vec<String> = drivers.iter().map(|(k, d)| format!(r#"{{"name":{},"nodeID":{},"topologyKeys":[{}]}}"#, q(k), q(&d.node_id), d.topology_keys.iter().map(|t| q(t)).collect::<Vec<_>>().join(","))).collect();
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
        let (name, ns) = (r.get("name").and_then(Value::as_str).unwrap_or(""), r.get("namespace").and_then(Value::as_str).unwrap_or(""));
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
        if s(&["spec", "volumeMode"]) == "Block" {
            return Err("block volumes are not supported".to_string());
        }
        let fs_type = Some(s(&["spec", "csi", "fsType"])).filter(|f| !f.is_empty()).unwrap_or_else(|| "ext4".to_string());
        let ro = claim_readonly || pv.pointer(&["spec", "csi", "readOnly"]).and_then(Value::as_bool).unwrap_or(false);
        let vctx: Vec<(String, String)> = pv.pointer(&["spec", "csi", "volumeAttributes"]).and_then(Value::as_object).unwrap_or(&[]).iter().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))).collect();
        let flags: Vec<String> = pv.pointer(&["spec", "mountOptions"]).and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(|v| v.as_str().map(String::from)).collect();
        let mode = match pv.pointer(&["spec", "accessModes"]).and_then(Value::as_array).and_then(|a| a.first()).and_then(Value::as_str) {
            Some("ReadOnlyMany") => 3u64,
            Some("ReadWriteMany") => 5,
            _ => 1,
        };

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
        let cap = |w: &mut Writer, field: u32| {
            w.message(field, |w| {
                w.message(2, |w| {
                    w.string(1, &fs_type);
                    for f in &flags {
                        w.string(2, f);
                    }
                });
                w.message(3, |w| {
                    w.varint(1, mode);
                });
            });
        };

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
        Ok(target)
    }

    // -------------------------------------------------------------- unmounting

    /// Every (pv dir name, driver, handle) recorded under a pod.
    fn entries(root: &str, uid: &str) -> Vec<(String, String, String)> {
        let base = format!("{root}/pods/{uid}/volumes/kubernetes.io~csi");
        list(&base)
            .into_iter()
            .filter(|n| safe_name(n))
            .filter_map(|n| {
                let b = kr_sys::fs::read_file(format!("{base}/{n}/vol_data.json\0").as_bytes(), 1 << 16).ok()?;
                let v = json::parse(&b).ok()?;
                let g = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                Some((n, g("driverName"), g("volumeHandle")))
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
        for (pv, driver, handle) in Self::entries(root, uid) {
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
            if !rmdir(&target) && kr_sys::fs::newfstatat(kr_sys::fs::AT_FDCWD, format!("{target}\0").as_bytes(), kr_sys::fs::AT_SYMLINK_NOFOLLOW).is_ok() {
                self.warn(&format!("cannot remove {target}"));
                continue;
            }
            let key = (driver.clone(), handle.clone());
            if d.stage && !unstaged.contains(&key) && !self.in_use(root, uid, &driver, &handle) {
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
        list(&format!("{root}/pods")).iter().filter(|p| safe_name(p) && *p != uid).any(|p| Self::entries(root, p).iter().any(|(_, d, h)| d == driver && h == handle))
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

    type Calls = Rc<RefCell<Vec<(String, Vec<u8>)>>>;

    fn fake_driver(path: &str, stage: bool) -> Calls {
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
                    rec.borrow_mut().push((m.clone(), req));
                    let mut w = Writer::new();
                    match m.as_str() {
                        GET_INFO => {
                            w.string(1, "CSIPlugin").string(2, "fake.csi");
                        }
                        NODE_INFO => {
                            w.string(1, "node-id-1").message(3, |w| {
                                w.message(1, |w| {
                                    w.string(1, "topology.fake/zone").string(2, "z1");
                                });
                            });
                        }
                        NODE_CAPS if stage => {
                            w.message(1, |w| {
                                w.message(1, |w| {
                                    w.varint(1, 1);
                                });
                            });
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
        assert!(decode_stage_cap(&[0xff]).is_err());
        block_on(async move { csi.unmount_pod("u").await });
    }
}
