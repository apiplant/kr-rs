//! Image pull: registry -> verified blobs -> flattened rootfs (ADR-013, ADR-017).
use crate::store::{cpath, Ctx, Error, ImageConfig, ImageId, Result, Store};
use crate::unpack::{unpack_layer_fd, Limits, Stats};
use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;
use kr_net::registry::{Descriptor, Reference, Registry};
use kr_sys::fs::{self, AT_FDCWD};
use kr_sys::Errno;

const MAX_LAYERS: usize = 512;
const MAX_CONFIG: u64 = 4 << 20;

/// Pulls `image_ref` into `store` and returns its id. Returns immediately when the reference is
/// already present. Blobs already in the store are re-verified instead of downloaded again.
pub async fn pull(store: &Store, image_ref: &str) -> Result<ImageId> {
    pull_with(store, image_ref, &Limits::default()).await
}

/// [`pull`] with explicit unpack limits.
pub async fn pull_with(store: &Store, image_ref: &str, limits: &Limits) -> Result<ImageId> {
    if let Some(id) = store.resolve_ref(image_ref) {
        if store.has_image(&id) {
            return Ok(id);
        }
    }
    let r = Reference::parse(image_ref)?;
    let mut reg = Registry::new();
    let image = reg.resolve(&r).await?;
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
    ImageConfig::parse(&cfg_json)?; // reject unusable configs before downloading layers
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

    let dir = store.image_dir(&id)?;
    crate::store::mkdir_p(&dir, 0o755)?;
    crate::store::write_file_atomic(&format!("{dir}/manifest.json"), &image.raw)?;
    crate::store::write_file_atomic(&format!("{dir}/config.json"), &cfg_json)?;

    let dirfd = fs::openat(AT_FDCWD, &cpath(&dir)?, fs::O_PATH | fs::O_DIRECTORY | fs::O_CLOEXEC, 0).ctx("open image dir")?;
    fs::remove_all(dirfd.raw(), b"rootfs.tmp\0").ctx("clear rootfs.tmp")?;
    fs::mkdirat(dirfd.raw(), b"rootfs.tmp\0", 0o755).ctx("mkdir rootfs.tmp")?;
    let built = build_rootfs(store, &image.manifest.layers, &gz, &format!("{dir}/rootfs.tmp"), limits);
    if let Err(e) = built {
        let _ = fs::remove_all(dirfd.raw(), b"rootfs.tmp\0");
        return Err(e);
    }
    match fs::renameat2(dirfd.raw(), b"rootfs.tmp\0", dirfd.raw(), b"rootfs\0", fs::RENAME_NOREPLACE) {
        Ok(()) => {}
        Err(Errno(fs::EEXIST)) | Err(Errno(fs::ENOTEMPTY)) => {
            // a concurrent pull finished first
            let _ = fs::remove_all(dirfd.raw(), b"rootfs.tmp\0");
        }
        Err(e) => {
            let _ = fs::remove_all(dirfd.raw(), b"rootfs.tmp\0");
            return Err(Error::Io("rename rootfs", e));
        }
    }
    store.set_ref(image_ref, &id)?;
    Ok(id)
}

fn build_rootfs(store: &Store, layers: &[Descriptor], gz: &[bool], tmp: &str, limits: &Limits) -> Result<Vec<Stats>> {
    let root = fs::openat(AT_FDCWD, &cpath(tmp)?, fs::O_RDONLY | fs::O_DIRECTORY | fs::O_CLOEXEC, 0).ctx("open rootfs.tmp")?;
    let mut out = Vec::new();
    for (l, &g) in layers.iter().zip(gz) {
        let blob = store.open_blob(&l.digest)?;
        out.push(unpack_layer_fd(root.raw(), blob.raw(), g, limits)?);
    }
    Ok(out)
}

/// Makes sure the blob is in the store, downloading and verifying it if absent or corrupt.
async fn ensure_blob(store: &Store, reg: &mut Registry, r: &Reference, d: &Descriptor) -> Result<()> {
    if !d.digest.is_sha256() {
        return Err(Error::Net(kr_net::Error::UnsupportedDigest));
    }
    if store.has_blob(&d.digest) && store.verify_blob(&d.digest)? {
        return Ok(());
    }
    let mut w = store.blob_writer(&d.digest)?;
    let mut werr: Option<Error> = None;
    let res = reg
        .pull_blob(r, d, &mut |b: &[u8]| {
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
    w.commit()
}

