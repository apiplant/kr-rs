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
    let mut chosen = None;
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
        let cfg_cred = hcfg.and_then(|c| c.auth.clone());
        reg.set_credential(if a.is_mirror { cfg_cred } else { lookup(creds, &upstream.registry, &upstream.repository).cloned().or(cfg_cred) });
        let r = Reference { registry: a.host.clone(), repository: a.repository.clone(), ..upstream.clone() };
        match reg.resolve(&r).await {
            Ok(image) => {
                chosen = Some((reg, r, image));
                break;
            }
            Err(e) => last = Some(e.into()),
        }
    }
    let Some((mut reg, r, image)) = chosen else { return Err(last.unwrap_or(Error::Image("no registry to pull from"))) };
    if image.manifest.layers.len() > MAX_LAYERS {
        return Err(Error::Image("too many layers"));
    }
    let cfg_desc = &image.manifest.config;
    let id = ImageId(cfg_desc.digest.as_str().strip_prefix("sha256:").ok_or(kr_net::Error::UnsupportedDigest)?.to_string());
    if store.has_image(&id) {
        store.set_ref(image_ref, &id)?;
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
        if mt.contains("zstd") {
            return Err(Error::Image("zstd-compressed layers are not supported"));
        }
        gz.push(!(mt.ends_with(".tar") && !mt.contains("gzip")));
    }
    for l in &image.manifest.layers {
        ensure_blob(store, &mut reg, &r, l).await?;
    }

    crate::offload::install_image(store, &id, &image.raw, &cfg_json, &image.manifest.layers, &gz, &icfg.diff_ids, limits).await?;
    store.set_ref(image_ref, &id)?;
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

