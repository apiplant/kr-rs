//! Image pull: registry -> verified blobs -> flattened rootfs (ADR-013, ADR-017).
use crate::auth::{lookup, Cred};
use crate::store::{cpath, Ctx, Error, ImageConfig, ImageId, Result, Store};
use crate::unpack::{unpack_layer_fd, Limits, Stats};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_net::http1::{Client, Config};
use kr_net::registry::{Descriptor, Reference, Registry};
use crate::registries::{Registries, TlsCfg};
use kr_net::registry::RegConnector;
use kr_sys::fs::{self, AT_FDCWD};
use kr_sys::Errno;

const MAX_LAYERS: usize = 512;
const MAX_CONFIG: u64 = 4 << 20;

/// Pulls `image_ref` into `store` and returns its id. Returns immediately when the reference is
/// already present. Blobs already in the store are re-verified instead of downloaded again.
/// Default system trust store locations (Debian/Arch/Alpine, then Fedora/RHEL).
const SYSTEM_BUNDLES: &[&[u8]] = &[b"/etc/ssl/certs/ca-certificates.crt\0", b"/etc/pki/tls/certs/ca-bundle.crt\0"];

/// A registry client over TLS. Trust anchors: the system bundle (or `$KR_CA_BUNDLE`, a PEM file;
/// then loopback registries also use https), plus the host's `registries.yaml` `ca_file`, with
/// its client certificate and `insecure_skip_verify` (ADR-044).
fn registry(tls: Option<&TlsCfg>) -> Result<Registry<RegConnector>> {
    let read = |path: &str, what: &'static str| -> Result<String> {
        let mut p = path.as_bytes().to_vec();
        p.push(0);
        let b = fs::read_file(&p, 4 << 20).map_err(|_| Error::Image(what))?;
        String::from_utf8(b).map_err(|_| Error::Image("TLS file is not UTF-8 PEM"))
    };
    let custom = crate::store::env_var("KR_CA_BUNDLE");
    let mut pem = match &custom {
        Some(path) => read(path, "cannot read KR_CA_BUNDLE")?,
        None => SYSTEM_BUNDLES.iter().find_map(|p| fs::read_file(p, 4 << 20).ok()).and_then(|b| String::from_utf8(b).ok()).unwrap_or_default(),
    };
    let mut loopback_tls = custom.is_some();
    let mut client = None;
    let mut insecure = false;
    if let Some(t) = tls {
        if let Some(ca) = &t.ca_file {
            pem.push('\n');
            pem.push_str(&read(ca, "cannot read registries.yaml ca_file")?);
            loopback_tls = true;
        }
        match (&t.cert_file, &t.key_file) {
            (Some(c), Some(k)) => client = Some((read(c, "cannot read registries.yaml cert_file")?, read(k, "cannot read registries.yaml key_file")?)),
            (None, None) => {}
            _ => return Err(Error::Image("registries.yaml: cert_file and key_file go together")),
        }
        insecure = t.insecure;
        loopback_tls |= insecure || client.is_some();
    }
    let connector = RegConnector::new(&pem, client.as_ref().map(|(c, k)| (c.as_str(), k.as_str())), insecure)?;
    let mut reg = Registry::with_client(Client::with_connector(connector, Config::default()));
    if loopback_tls {
        reg.tls_for_loopback();
    }
    Ok(reg)
}

pub async fn pull(store: &Store, image_ref: &str) -> Result<ImageId> {
    pull_full(store, image_ref, &[], &Limits::default()).await
}

/// [`pull`] with explicit unpack limits.
pub async fn pull_with(store: &Store, image_ref: &str, limits: &Limits) -> Result<ImageId> {
    pull_full(store, image_ref, &[], limits).await
}

/// [`pull`] with registry credentials (from image pull secrets); the one matching the
/// image's registry is used, none means anonymous.
pub async fn pull_auth(store: &Store, image_ref: &str, creds: &[Cred]) -> Result<ImageId> {
    pull_full(store, image_ref, creds, &Limits::default()).await
}

/// Other nodes of the cluster that serve their image store (the embedded registry mirror,
/// `kr-kubelet/src/mirror.rs`): tried before any registry for the registries it covers.
#[derive(Clone, Debug, Default)]
pub struct Peers {
    /// `host:port` (IPv6 in brackets), best first.
    pub hosts: Vec<String>,
    /// Cluster CA and this node's client certificate (mutual TLS between nodes).
    pub tls: TlsCfg,
}

/// The base path under which a peer serves the `/v2/` API of upstream `registry`.
pub fn peer_base(registry: &str) -> String {
    format!("/kr/ns/{registry}")
}

/// Whether a reference may be taken from a peer: pinned by digest, or a tag other than `latest`
/// (a peer's `latest` may be older than the registry's, as in k3s).
pub fn peer_eligible(r: &Reference) -> bool {
    r.digest.is_some() || r.tag.as_deref().is_some_and(|t| t != "latest")
}

/// [`pull_auth`] trying `peers` first.
pub async fn pull_peers(store: &Store, image_ref: &str, creds: &[Cred], peers: &Peers) -> Result<ImageId> {
    if let Some(id) = store.resolve_ref(image_ref).filter(|id| store.has_image(id)) {
        return Ok(id);
    }
    let upstream = Reference::parse(image_ref)?;
    if peer_eligible(&upstream) {
        for host in &peers.hosts {
            let Ok(mut reg) = registry(Some(&peers.tls)) else { break };
            reg.set_base_path(&peer_base(&upstream.registry));
            let r = Reference { registry: host.clone(), ..upstream.clone() };
            let Ok(image) = reg.resolve(&r).await else { continue };
            if let Ok(id) = finish(store, reg, r, image, image_ref, &Limits::default()).await {
                return Ok(id);
            }
        }
    }
    pull_full(store, image_ref, creds, &Limits::default()).await
}

async fn pull_full(store: &Store, image_ref: &str, creds: &[Cred], limits: &Limits) -> Result<ImageId> {
    if let Some(id) = store.resolve_ref(image_ref) {
        if store.has_image(&id) {
            return Ok(id);
        }
    }
    let upstream = Reference::parse(image_ref)?;
    let regs = Registries::load()?;
    // Mirrors first (in order, with their own credentials, never the pod's), then the
    // upstream with the pod's credentials; the upstream's error is the one reported.
    let mut last: Option<Error> = None;
    for a in regs.attempts(&upstream.registry, &upstream.repository) {
        let hcfg = regs.host_cfg(&a.host);
        let mut reg = match registry(hcfg.map(|c| &c.tls)) {
            Ok(r) => r,
            Err(e) => {
                last = Some(e);
                continue;
            }
        };
        if a.plain_http {
            reg.allow_plain_http(&a.host);
        }
        reg.set_base_path(&a.base_path);
        let cfg_cred = hcfg.and_then(|c| c.auth.clone());
        reg.set_credential(if a.is_mirror { cfg_cred } else { lookup(creds, &upstream.registry, &upstream.repository).cloned().or(cfg_cred) });
        let r = Reference { registry: a.host.clone(), repository: a.repository.clone(), ..upstream.clone() };
        match reg.resolve(&r).await {
            Ok(image) => match finish(store, reg, r, image, image_ref, limits).await {
                Ok(id) => return Ok(id),
                // A mirror that answered the manifest but cannot deliver the blobs: the next endpoint
                // (and finally the upstream) is tried.
                Err(e) if a.is_mirror => last = Some(e),
                Err(e) => return Err(e),
            },
            Err(e) => last = Some(e.into()),
        }
    }
    Err(last.unwrap_or(Error::Image("no registry to pull from")))
}

/// Downloads the blobs of a resolved image from `reg` and installs it.
async fn finish(store: &Store, mut reg: Registry<RegConnector>, r: Reference, image: kr_net::registry::Image, image_ref: &str, limits: &Limits) -> Result<ImageId> {
    if image.manifest.layers.len() > MAX_LAYERS {
        return Err(Error::Image("too many layers"));
    }
    let cfg_desc = &image.manifest.config;
    let id = ImageId(cfg_desc.digest.as_str().strip_prefix("sha256:").ok_or(kr_net::Error::UnsupportedDigest)?.to_string());
    if store.has_image(&id) {
        store.set_ref_async(image_ref, &id).await?;
        return Ok(id);
    }
    if cfg_desc.size > MAX_CONFIG {
        return Err(Error::Image("config too large"));
    }

    ensure_blob(store, &mut reg, &r, cfg_desc).await?;
    let mut cfg_json = Vec::new();
    {
        let fd = store.open_blob(&cfg_desc.digest)?;
        fs::read_to_end(fd.raw(), &mut cfg_json, MAX_CONFIG as usize).ctx("read config blob")?;
    }
    let icfg = ImageConfig::parse(&cfg_json)?; // reject unusable configs before downloading layers
    // keep the manifest content-addressed too (best effort; the id does not depend on it)
    let _ = store.put_blob(&image.digest, &image.raw);

    let mut gz: Vec<bool> = Vec::new();
    for l in &image.manifest.layers {
        let mt = l.media_type.as_str();
        gz.push(!(mt.ends_with(".tar") && !mt.contains("gzip")));
    }
    for l in &image.manifest.layers {
        ensure_blob(store, &mut reg, &r, l).await?;
    }

    crate::offload::install_image(store, &id, &image.raw, &cfg_json, &image.manifest.layers, &gz, &icfg.diff_ids, limits).await?;
    store.set_ref_async(image_ref, &id).await?;
    Ok(id)
}

/// Writes manifest + config for `id` and unpacks `layers` (already in the store) into its
/// rootfs; shared by pulls and `import`. A concurrent installer that wins the rename is fine.
#[allow(clippy::too_many_arguments)]
pub(crate) fn install_image(store: &Store, id: &ImageId, manifest: &[u8], cfg_json: &[u8], layers: &[Descriptor], gz: &[bool], diff_ids: &[String], limits: &Limits) -> Result<()> {
    let dir = store.image_dir(id)?;
    crate::store::mkdir_p(&dir, 0o755)?;
    crate::store::write_file_atomic(&format!("{dir}/manifest.json"), manifest)?;
    crate::store::write_file_atomic(&format!("{dir}/config.json"), cfg_json)?;
    // Real root keeps one directory per layer and lets images share them (ADR-056); anything the
    // layered form cannot represent falls back to the flattened rootfs below.
    if layered_wanted() {
        match install_layers(store, &dir, layers, gz, diff_ids, limits) {
            Ok(()) => return Ok(()),
            Err(e) => kr_sys::write(2, format!("kr: image layers cannot be shared ({e:?}); unpacking a flattened rootfs\n").as_bytes()).map(|_| ()).unwrap_or(()),
        }
    }

    // Concurrent pulls of one image (other namespaces, other `kr ctr` processes) each unpack
    // into their own directory; the first rename wins.
    clear_stale_tmp(&dir);
    let pid = kr_sys::fs::getpid();
    let mut nonce = [0u8; 4];
    kr_sys::getrandom(&mut nonce);
    let tmp = format!("rootfs.tmp-{pid}-{}-{:08x}", crate::network::proc_start(pid).unwrap_or(0), u32::from_le_bytes(nonce));
    let ctmp = cpath(&tmp)?;
    let dirfd = fs::openat(AT_FDCWD, &cpath(&dir)?, fs::O_PATH | fs::O_DIRECTORY | fs::O_CLOEXEC, 0).ctx("open image dir")?;
    fs::mkdirat(dirfd.raw(), &ctmp, 0o755).ctx("mkdir rootfs.tmp")?;
    let built = build_rootfs(store, layers, gz, diff_ids, &format!("{dir}/{tmp}"), limits);
    if let Err(e) = built {
        let _ = fs::remove_all(dirfd.raw(), &ctmp);
        return Err(e);
    }
    match fs::renameat2(dirfd.raw(), &ctmp, dirfd.raw(), b"rootfs\0", fs::RENAME_NOREPLACE) {
        Ok(()) => {}
        Err(Errno(fs::EEXIST)) | Err(Errno(fs::ENOTEMPTY)) => {
            // a concurrent pull finished first
            let _ = fs::remove_all(dirfd.raw(), &ctmp);
        }
        Err(e) => {
            let _ = fs::remove_all(dirfd.raw(), &ctmp);
            return Err(Error::Io("rename rootfs", e));
        }
    }
    Ok(())
}

/// Layered images are for root (the whiteout devices and `trusted.` xattrs of lower layers); a
/// rootless store keeps flattening (ADR-017). `KR_LAYERED_STORE=off` turns it off.
fn layered_wanted() -> bool {
    fs::getuid() == 0 && !matches!(crate::store::env_var("KR_LAYERED_STORE").as_deref(), Some("off" | "0" | "false"))
}

/// An overlay option string is limited to a page: refuse image stacks that would not fit.
const MAX_LOWERDIR_BYTES: usize = 3600;

/// Unpacks every layer that is not in `layers/` yet, each into a directory of its own, and lists
/// them in `<image>/layers`.
fn install_layers(store: &Store, dir: &str, layers: &[Descriptor], gz: &[bool], diff_ids: &[String], limits: &Limits) -> Result<()> {
    if diff_ids.len() != layers.len() {
        return Err(Error::Image("config rootfs.diff_ids does not match the layer count"));
    }
    let keys: Vec<String> = diff_ids.iter().map(|d| Store::layer_key(d).ok_or(Error::Image("bad diff_id"))).collect::<Result<_>>()?;
    if keys.len() * (store.layers_dir().len() + 25) > MAX_LOWERDIR_BYTES {
        return Err(Error::Image("too many layers for one overlay mount"));
    }
    crate::store::mkdir_p(&store.layers_dir(), 0o755)?;
    clear_stale_layer_tmp(&store.layers_dir());
    let ldir = fs::openat(AT_FDCWD, &cpath(&store.layers_dir())?, fs::O_PATH | fs::O_DIRECTORY | fs::O_CLOEXEC, 0).ctx("open layers dir")?;
    for (((l, &g), want), key) in layers.iter().zip(gz).zip(diff_ids).zip(&keys) {
        if store.has_layer(key) {
            continue;
        }
        let pid = kr_sys::fs::getpid();
        let mut nonce = [0u8; 4];
        kr_sys::getrandom(&mut nonce);
        let tmp = format!("tmp-{key}-{pid}-{}-{:08x}", crate::network::proc_start(pid).unwrap_or(0), u32::from_le_bytes(nonce));
        let ctmp = cpath(&tmp)?;
        fs::mkdirat(ldir.raw(), &ctmp, 0o755).ctx("mkdir layer.tmp")?;
        let res = (|| -> Result<()> {
            let root = fs::openat(ldir.raw(), &ctmp, fs::O_RDONLY | fs::O_DIRECTORY | fs::O_CLOEXEC, 0).ctx("open layer.tmp")?;
            let blob = store.open_blob(&l.digest)?;
            let st = crate::unpack::unpack_layer_overlay_fd(root.raw(), blob.raw(), g, limits)?;
            if st.diff_id != *want && alloc::format!("sha256:{}", st.diff_id) != *want {
                return Err(Error::Image("layer diff_id does not match the config"));
            }
            Ok(())
        })();
        if let Err(e) = res {
            let _ = fs::remove_all(ldir.raw(), &ctmp);
            return Err(e);
        }
        match fs::renameat2(ldir.raw(), &ctmp, ldir.raw(), &cpath(key)?, fs::RENAME_NOREPLACE) {
            Ok(()) => {}
            Err(Errno(fs::EEXIST)) | Err(Errno(fs::ENOTEMPTY)) => {
                let _ = fs::remove_all(ldir.raw(), &ctmp); // a concurrent pull finished first
            }
            Err(e) => {
                let _ = fs::remove_all(ldir.raw(), &ctmp);
                return Err(Error::Io("rename layer", e));
            }
        }
    }
    let list: String = keys.iter().map(|k| format!("{k}\n")).collect();
    crate::store::write_file_atomic(&format!("{dir}/layers"), list.as_bytes())
}

/// Removes layer unpack directories (`tmp-<key>-<pid>-<start>-<n>`) of pulls whose process is gone.
fn clear_stale_layer_tmp(dir: &str) {
    let Ok(c) = cpath(dir) else { return };
    let Ok(fd) = fs::openat(AT_FDCWD, &c, fs::O_RDONLY | fs::O_DIRECTORY | fs::O_CLOEXEC, 0) else { return };
    let names: Vec<Vec<u8>> = fs::read_dir(&fd).filter_map(|e| e.ok()).map(|e| e.name).collect();
    for name in names {
        let Some(rest) = name.strip_prefix(b"tmp-") else { continue };
        let Ok(rest) = core::str::from_utf8(rest) else { continue };
        let mut f = rest.split('-');
        let (_key, pid, start) = (f.next(), f.next().and_then(|p| p.parse::<u32>().ok()), f.next().and_then(|s| s.parse::<u64>().ok()));
        if let (Some(pid), Some(start)) = (pid, start) {
            if crate::network::proc_start(pid) != Some(start) {
                let mut n = name.clone();
                n.push(0);
                let _ = fs::remove_all(fd.raw(), &n);
            }
        }
    }
}

/// Removes unpack directories of pulls whose process is gone (`rootfs.tmp-<pid>-<start>-<n>`,
/// and the pre-per-pull `rootfs.tmp`). Directories of live pulls are left alone.
fn clear_stale_tmp(dir: &str) {
    let Ok(c) = cpath(dir) else { return };
    let Ok(fd) = fs::openat(AT_FDCWD, &c, fs::O_RDONLY | fs::O_DIRECTORY | fs::O_CLOEXEC, 0) else { return };
    let names: Vec<Vec<u8>> = fs::read_dir(&fd).filter_map(|e| e.ok()).map(|e| e.name).collect();
    for name in names {
        let Some(rest) = name.strip_prefix(b"rootfs.tmp") else { continue };
        let stale = match core::str::from_utf8(rest).ok().and_then(|r| r.strip_prefix('-')) {
            None => rest.is_empty(),
            Some(r) => {
                let mut f = r.split('-');
                match (f.next().and_then(|p| p.parse::<u32>().ok()), f.next().and_then(|s| s.parse::<u64>().ok())) {
                    (Some(pid), Some(start)) => crate::network::proc_start(pid) != Some(start),
                    _ => false,
                }
            }
        };
        if stale {
            let mut n = name.clone();
            n.push(0);
            let _ = fs::remove_all(fd.raw(), &n);
        }
    }
}

fn build_rootfs(store: &Store, layers: &[Descriptor], gz: &[bool], diff_ids: &[String], tmp: &str, limits: &Limits) -> Result<Vec<Stats>> {
    if diff_ids.len() != layers.len() {
        return Err(Error::Image("config rootfs.diff_ids does not match the layer count"));
    }
    let root = fs::openat(AT_FDCWD, &cpath(tmp)?, fs::O_RDONLY | fs::O_DIRECTORY | fs::O_CLOEXEC, 0).ctx("open rootfs.tmp")?;
    let mut out = Vec::new();
    let (mut bytes, mut entries) = (0u64, 0u64);
    for ((l, &g), want) in layers.iter().zip(gz).zip(diff_ids) {
        let blob = store.open_blob(&l.digest)?;
        // the image-wide caps are spent down across layers
        let lim = Limits {
            max_bytes: limits.max_bytes.min(limits.max_image_bytes.saturating_sub(bytes)),
            max_entries: limits.max_entries.saturating_sub(entries),
            ..limits.clone()
        };
        let st = unpack_layer_fd(root.raw(), blob.raw(), g, &lim)?;
        if st.diff_id != *want {
            return Err(Error::Image("layer diff_id does not match the config"));
        }
        bytes += st.bytes;
        entries += st.entries;
        out.push(st);
    }
    Ok(out)
}

/// Makes sure the blob is in the store, downloading and verifying it if absent or corrupt.
async fn ensure_blob(store: &Store, reg: &mut Registry<RegConnector>, r: &Reference, d: &Descriptor) -> Result<()> {
    if !d.digest.is_sha256() {
        return Err(Error::Net(kr_net::Error::UnsupportedDigest));
    }
    if store.has_blob(&d.digest) && crate::offload::verify_blob(store, &d.digest).await? {
        return Ok(());
    }
    let mut w = store.blob_writer(&d.digest)?;
    let mut werr: Option<Error> = None;
    let res = reg
        .pull_blob_trusted(r, d, &mut |b: &[u8]| {
            w.write(b).map_err(|e| {
                werr = Some(e);
                kr_net::Error::Sink
            })
        })
        .await;
    if let Some(e) = werr {
        return Err(e);
    }
    res?;
    // The writer verifies the digest at commit; the (slow) fsync of the data goes to a worker first.
    crate::offload::fsync_file(&w.tmp_path()).await?;
    // A digest that does not match is reported like the download check always did.
    w.commit_unsynced().map_err(|e| if e == Error::Digest { Error::Net(kr_net::Error::DigestMismatch) } else { e })
}

