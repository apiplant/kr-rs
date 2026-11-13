//! Embedded registry mirror (ADR-067, KNOWN_ISSUES #322; k3s `--embedded-registry`): every node
//! serves the images in its store to the other nodes, read only, so an image is downloaded from
//! the registry once per cluster instead of once per node, and nodes keep pulling from each
//! other when the registry is unreachable.
//!
//! Serving: HTTPS on [`PORT`] with mutual TLS (any client certificate of the cluster CA: node and
//! server certificates). The OCI distribution API of upstream registry `R` lives under
//! `/kr/ns/R/v2/`: `manifests/<tag|digest>` from the store's references and the manifest blobs,
//! `blobs/<digest>` from the blob store. Content is addressed by digest and the puller verifies
//! every blob, so a peer can only refuse or serve the right bytes for a digest; a tag is taken on
//! trust from the peer (the nodes are trusted, as in k3s/Spegel), never for `latest`.
//!
//! Discovery: nodes report their images in `status.images` (names and size, as upstream), and a
//! node that serves sets the annotation [`ANNOTATION`] to its port. A pull asks the Ready nodes of
//! the same architecture that list the image ([`peers_for`]).

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;
use core::task::{Context, Poll};
use kr_fmt::json::Value;
use kr_net::http1::server::{self, Body, Request, Response, ResponseStream};
use kr_net::registry::{Digest, Reference};
use kr_runtime::store::Store;

/// The mirror's port (k3s uses 5001 for its peer-to-peer traffic).
pub const PORT: u16 = 5001;
/// Set on a node that serves its images: the value is the port.
pub const ANNOTATION: &str = "registry.kr.io/mirror-port";
/// Set on control-plane nodes by servers started with `--embedded-registry`: turns the mirror on
/// for the whole cluster (agents follow it, as in k3s).
pub const CLUSTER_ANNOTATION: &str = "registry.kr.io/embedded";
/// At most this many images are reported in `status.images` (upstream's default).
pub const MAX_STATUS_IMAGES: usize = 50;

const MANIFEST_TYPES: [&str; 2] = ["application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| alloc::format!("{x:02x}")).collect()
}

/// A request path below `/kr/ns/<registry>/v2/`: (registry, repository, kind, reference).
pub(crate) fn route(path: &str) -> Option<(String, String, &'static str, String)> {
    let rest = path.strip_prefix("/kr/ns/")?;
    let (registry, rest) = rest.split_once('/')?;
    let rest = rest.strip_prefix("v2/")?;
    for kind in ["manifests", "blobs"] {
        let sep = alloc::format!("/{kind}/");
        if let Some(i) = rest.rfind(&sep) {
            let (repo, r) = (&rest[..i], &rest[i + sep.len()..]);
            if repo.is_empty() || r.is_empty() || r.contains('/') {
                return None;
            }
            return Some((registry.to_string(), repo.to_string(), if kind == "blobs" { "blobs" } else { "manifests" }, r.to_string()));
        }
    }
    None
}

fn media_type(raw: &[u8]) -> String {
    kr_fmt::json::parse(raw).ok().and_then(|v| v.get("mediaType").and_then(Value::as_str).map(String::from)).filter(|t| MANIFEST_TYPES.contains(&t.as_str())).unwrap_or_else(|| String::from(MANIFEST_TYPES[0]))
}

fn not_found() -> Response {
    Response::new(404, br#"{"errors":[{"code":"MANIFEST_UNKNOWN","message":"not on this node"}]}"#.to_vec()).with_header("Content-Type", "application/json")
}

/// The manifest for `registry/repo` at `reference` (a tag or a digest), from the store.
fn manifest(store: &Store, registry: &str, repo: &str, reference: &str) -> Option<Vec<u8>> {
    if reference.starts_with("sha256:") {
        let d = Digest::parse(reference).ok()?;
        // A manifest kept as a blob by the pull; it must be an image manifest of an image here.
        let fd = store.open_blob(&d).ok()?;
        let mut raw = Vec::new();
        kr_sys::fs::read_to_end(fd.raw(), &mut raw, 4 << 20).ok()?;
        let v = kr_fmt::json::parse(&raw).ok()?;
        v.get("layers")?;
        return Some(raw);
    }
    let r = Reference::parse(&alloc::format!("{registry}/{repo}:{reference}")).ok()?;
    if !kr_runtime::pull::peer_eligible(&r) {
        return None;
    }
    let id = store.resolve_ref(&r.to_string())?;
    if !store.has_image(&id) {
        return None;
    }
    kr_sys::fs::read_file(&kr_runtime::store::cpath(&alloc::format!("{}/manifest.json", store.image_dir(&id).ok()?)).ok()?, 4 << 20).ok()
}

/// Streams a blob file in chunks.
struct FileStream(kr_sys::Fd);

impl ResponseStream for FileStream {
    fn poll_next(&mut self, _cx: &mut Context<'_>) -> Poll<Option<Vec<u8>>> {
        let mut buf = alloc::vec![0u8; 256 * 1024];
        match kr_sys::read(self.0.raw(), &mut buf) {
            Ok(0) | Err(_) => Poll::Ready(None),
            Ok(n) => {
                buf.truncate(n);
                Poll::Ready(Some(buf))
            }
        }
    }
}

pub(crate) fn handle(store: &Store, req: &Request) -> Response {
    if req.method != "GET" && req.method != "HEAD" {
        return Response::new(405, Vec::new());
    }
    let path = req.target.split('?').next().unwrap_or("");
    if path.strip_prefix("/kr/ns/").and_then(|r| r.split_once('/')).is_some_and(|(_, r)| r == "v2/" || r == "v2") {
        return Response::new(200, b"{}".to_vec()).with_header("Content-Type", "application/json");
    }
    let Some((registry, repo, kind, reference)) = route(path) else { return not_found() };
    if kind == "manifests" {
        let Some(raw) = manifest(store, &registry, &repo, &reference) else { return not_found() };
        let digest = alloc::format!("sha256:{}", hex(&kr_crypto::sha2::sha256(&raw)));
        let ct = media_type(&raw);
        let body = if req.method == "HEAD" { Vec::new() } else { raw };
        return Response::new(200, body).with_header("Content-Type", &ct).with_header("Docker-Content-Digest", &digest);
    }
    let Ok(d) = Digest::parse(&reference) else { return not_found() };
    match store.open_blob(&d) {
        Ok(fd) if req.method == "GET" => Response { status: 200, headers: alloc::vec![("Content-Type".into(), "application/octet-stream".into()), ("Docker-Content-Digest".into(), reference)], body: Body::Stream(Box::new(FileStream(fd))) },
        Ok(_) => Response::new(200, Vec::new()).with_header("Docker-Content-Digest", &reference),
        Err(_) => not_found(),
    }
}

/// Serves the mirror until the listener fails. `tls` is the node's serving identity with
/// `ClientAuth::Required(cluster CA)`; reloadable like the kubelet's.
pub async fn serve(store: Rc<Store>, tls: Rc<RefCell<Rc<kr_crypto::tls::ServerConfig>>>) -> kr_net::Result<()> {
    let listener = server::listen([0, 0, 0, 0], PORT, 128)?;
    let cfg = Rc::new(server::ServerConfig { tls_slot: Some(tls), idle_timeout_ms: 120_000, ..server::ServerConfig::default() });
    let handler = move |req: Request| -> server::HandlerFuture {
        // The TLS layer already required a certificate of the cluster CA.
        let resp = if req.peer.client_certs.as_ref().is_some_and(|c| !c.is_empty()) { handle(&store, &req) } else { Response::new(403, b"forbidden\n".to_vec()) };
        Box::pin(async move { resp })
    };
    let handler: Rc<dyn server::Handler> = Rc::new(handler);
    if let Ok(l6) = server::listen6(PORT, 128) {
        kr_rt::exec::spawn(server::serve(l6, cfg.clone(), handler.clone()));
    }
    server::serve(listener, cfg, handler).await
}

/// `status.images` for the node: one entry per image, named by its references and its manifest
/// digest (`repo@sha256:...`), largest first, at most [`MAX_STATUS_IMAGES`].
pub fn status_images(store: &Store) -> Value {
    let mut by_id: Vec<(String, Vec<String>, u64)> = Vec::new();
    for (r, id) in store.list_refs() {
        if !store.has_image(&id) {
            continue;
        }
        match by_id.iter_mut().find(|(i, _, _)| *i == id.0) {
            Some(e) => e.1.push(r),
            None => {
                let raw = store.image_dir(&id).ok().and_then(|d| kr_sys::fs::read_file(&kr_runtime::store::cpath(&alloc::format!("{d}/manifest.json")).ok()?, 4 << 20).ok());
                let mut names = alloc::vec![r.clone()];
                let mut size = 0u64;
                if let Some(raw) = raw {
                    if let Ok(p) = Reference::parse(&r) {
                        names.push(alloc::format!("{}/{}@sha256:{}", p.registry, p.repository, hex(&kr_crypto::sha2::sha256(&raw))));
                    }
                    if let Ok(v) = kr_fmt::json::parse(&raw) {
                        size = v.get("layers").and_then(Value::as_array).map(|l| l.iter().filter_map(|x| x.get("size").and_then(Value::as_u64)).sum()).unwrap_or(0);
                    }
                }
                by_id.push((id.0.clone(), names, size));
            }
        }
    }
    by_id.sort_by(|a, b| b.2.cmp(&a.2));
    by_id.truncate(MAX_STATUS_IMAGES);
    Value::Array(
        by_id
            .into_iter()
            .map(|(_, mut names, size)| {
                names.sort();
                names.dedup();
                Value::Object(alloc::vec![("names".to_string(), Value::Array(names.into_iter().map(Value::from).collect())), ("sizeBytes".to_string(), Value::from(size as i64))])
            })
            .collect(),
    )
}

/// Whether the cluster has the mirror on: a control-plane node carries [`CLUSTER_ANNOTATION`].
pub fn cluster_enabled(nodes: &[Value]) -> bool {
    nodes.iter().any(|n| n.pointer(&["metadata", "annotations", CLUSTER_ANNOTATION]).and_then(Value::as_str) == Some("true"))
}

fn ready(n: &Value) -> bool {
    n.pointer(&["status", "conditions"]).and_then(Value::as_array).is_some_and(|c| c.iter().any(|c| c.get("type").and_then(Value::as_str) == Some("Ready") && c.get("status").and_then(Value::as_str) == Some("True")))
}

/// `host:port` of the nodes that can serve `image_ref`: Ready, serving, same architecture, not
/// `me`, listing the reference in `status.images`.
pub fn peers_for(nodes: &[Value], me: &str, arch: &str, image_ref: &str) -> Vec<String> {
    let Ok(want) = Reference::parse(image_ref) else { return Vec::new() };
    let want = want.to_string();
    let mut out = Vec::new();
    for n in nodes {
        if n.pointer(&["metadata", "name"]).and_then(Value::as_str) == Some(me) || !ready(n) {
            continue;
        }
        let Some(port) = n.pointer(&["metadata", "annotations", ANNOTATION]).and_then(Value::as_str).and_then(|p| p.parse::<u16>().ok()) else { continue };
        if n.pointer(&["metadata", "labels", "kubernetes.io/arch"]).and_then(Value::as_str).is_some_and(|a| a != arch) {
            continue;
        }
        let has = n.pointer(&["status", "images"]).and_then(Value::as_array).is_some_and(|imgs| imgs.iter().any(|i| i.get("names").and_then(Value::as_array).is_some_and(|ns| ns.iter().any(|x| x.as_str() == Some(want.as_str())))));
        if !has {
            continue;
        }
        let ip = n.pointer(&["status", "addresses"]).and_then(Value::as_array).and_then(|a| a.iter().find(|x| x.get("type").and_then(Value::as_str) == Some("InternalIP")).and_then(|x| x.get("address")).and_then(Value::as_str)).and_then(kr_net::tcp::parse_ip16);
        if let Some(ip) = ip {
            out.push(alloc::format!("{}:{port}", kr_net::tcp::url_host(ip)));
        }
    }
    out
}

/// Whether pulls from upstream `registry` may use peers: it is a `mirrors:` key in
/// `registries.yaml` (or `"*"` is), as k3s requires for its embedded registry.
pub fn mirrored(registry: &str) -> bool {
    kr_runtime::registries::Registries::load().is_ok_and(|r| r.mirrors.iter().any(|(k, _)| k == "*" || k == registry))
}

type Slot = Rc<RefCell<Rc<kr_crypto::tls::ServerConfig>>>;

/// The node's mirror: serving identity, client identity for pulling from peers, and the node
/// list it follows (every 10 s).
pub struct Mirror {
    /// Serving certificate with an IP SAN and `ClientAuth::Required(cluster CA)`.
    pub server_tls: Slot,
    /// Cluster CA and a client certificate of this node (file paths).
    pub client: kr_runtime::registries::TlsCfg,
    nodes: RefCell<Vec<Value>>,
    on: core::cell::Cell<bool>,
}

impl Mirror {
    pub fn new(server_tls: Slot, client: kr_runtime::registries::TlsCfg) -> Rc<Mirror> {
        Rc::new(Mirror { server_tls, client, nodes: RefCell::new(Vec::new()), on: core::cell::Cell::new(false) })
    }

    /// Peers for a pull of `image_ref`, or `None` when the mirror is off or does not cover it.
    pub fn peers(&self, me: &str, image_ref: &str) -> Option<kr_runtime::pull::Peers> {
        if !self.on.get() {
            return None;
        }
        let r = Reference::parse(image_ref).ok()?;
        if !kr_runtime::pull::peer_eligible(&r) || !mirrored(&r.registry) {
            return None;
        }
        let hosts = peers_for(&self.nodes.borrow(), me, crate::node::arch(), image_ref);
        (!hosts.is_empty()).then(|| kr_runtime::pull::Peers { hosts, tls: self.client.clone() })
    }

    /// Follows the cluster setting; starts serving (once) and announces this node when on.
    /// `force`: this is a server started with `--embedded-registry` (it also marks the cluster).
    pub async fn run<C: kr_apiserver::client::Client>(self: Rc<Self>, c: C, me: String, root: String, force: bool) {
        loop {
            if let Ok(list) = c.list("/api/v1/nodes", "").await {
                let nodes = list.get("items").and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
                let on = force || cluster_enabled(&nodes);
                *self.nodes.borrow_mut() = nodes;
                if on && !self.on.get() {
                    match Store::open(Some(&root)) {
                        Ok(store) => {
                            let (store, tls) = (Rc::new(store), self.server_tls.clone());
                            kr_rt::exec::spawn(async move {
                                if let Err(e) = serve(store, tls).await {
                                    kr_rt::eprint(alloc::format!("kubelet: embedded registry mirror on :{PORT} failed: {e:?}\n").as_bytes());
                                }
                            });
                            self.on.set(true);
                            kr_rt::eprint(alloc::format!("kubelet: embedded registry mirror serving on :{PORT}\n").as_bytes());
                        }
                        Err(e) => kr_rt::eprint(alloc::format!("kubelet: embedded registry mirror: {e:?}\n").as_bytes()),
                    }
                }
                if self.on.get() {
                    let mine = self.nodes.borrow().iter().find(|n| n.pointer(&["metadata", "name"]).and_then(Value::as_str) == Some(me.as_str())).cloned();
                    let want_port = alloc::format!("{PORT}");
                    let has = |k: &str, v: &str| mine.as_ref().and_then(|n| n.pointer(&["metadata", "annotations", k]).and_then(Value::as_str).map(String::from)).as_deref() == Some(v);
                    if !has(ANNOTATION, &want_port) || (force && !has(CLUSTER_ANNOTATION, "true")) {
                        let cluster = if force { alloc::format!(r#","{CLUSTER_ANNOTATION}":"true""#) } else { String::new() };
                        if let Ok(p) = kr_fmt::json::parse(alloc::format!(r#"{{"metadata":{{"annotations":{{"{ANNOTATION}":"{want_port}"{cluster}}}}}}}"#).as_bytes()) {
                            let _ = c.patch(&alloc::format!("/api/v1/nodes/{me}"), "application/merge-patch+json", &p).await;
                        }
                    }
                }
            }
            kr_rt::exec::sleep(10_000).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes() {
        assert_eq!(route("/kr/ns/docker.io/v2/library/busybox/manifests/1.36"), Some(("docker.io".into(), "library/busybox".into(), "manifests", "1.36".into())));
        assert_eq!(route("/kr/ns/ghcr.io/v2/a/b/c/blobs/sha256:00"), Some(("ghcr.io".into(), "a/b/c".into(), "blobs", "sha256:00".into())));
        assert_eq!(route("/kr/ns/docker.io/v2/x/manifests/"), None);
        assert_eq!(route("/v2/x/manifests/1"), None);
    }

    fn node(name: &str, arch: &str, ready: &str, port: Option<&str>, images: &[&str]) -> Value {
        let ann = port.map(|p| alloc::format!(r#""annotations":{{"{ANNOTATION}":"{p}"}},"#)).unwrap_or_default();
        let imgs: Vec<String> = images.iter().map(|i| alloc::format!(r#"{{"names":["{i}"],"sizeBytes":1}}"#)).collect();
        kr_fmt::json::parse(alloc::format!(r#"{{"metadata":{{"name":"{name}",{ann}"labels":{{"kubernetes.io/arch":"{arch}"}}}},"status":{{"conditions":[{{"type":"Ready","status":"{ready}"}}],"addresses":[{{"type":"InternalIP","address":"10.0.0.{}"}}],"images":[{}]}}}}"#, name.len(), imgs.join(",")).as_bytes()).unwrap()
    }

    #[test]
    fn picks_ready_serving_peers_of_the_same_arch_with_the_image() {
        let img = "docker.io/library/busybox:1.36";
        let nodes = [
            node("me", "amd64", "True", Some("5001"), &[img]),
            node("a", "amd64", "True", Some("5001"), &[img]),
            node("bb", "arm64", "True", Some("5001"), &[img]),
            node("ccc", "amd64", "False", Some("5001"), &[img]),
            node("dddd", "amd64", "True", None, &[img]),
            node("eeeee", "amd64", "True", Some("5001"), &["docker.io/library/nginx:1"]),
        ];
        assert_eq!(peers_for(&nodes, "me", "amd64", "busybox:1.36"), ["10.0.0.1:5001"]);
    }
}
