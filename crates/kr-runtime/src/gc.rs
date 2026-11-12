//! Image garbage collection (#130): which images exist and when each was last used, and removal
//! of one image together with the refs, shared layers and blobs nothing else needs.
//!
//! The caller (the kubelet) decides what is in use and how much to free; this module only
//! knows the store layout. A removal never touches a layer or blob that a remaining image's
//! manifest/layer list names.

use crate::store::{cpath, ImageId, Result, Store};
use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_net::registry::{parse_manifest, Manifest};
use kr_sys::fs::{self, AT_FDCWD};

impl Store {
    /// Records "now" as the last use of the image (the mtime of its directory).
    pub fn mark_used(&self, id: &ImageId) {
        let Ok(dir) = self.image_dir(id) else { return };
        let Ok(p) = cpath(&dir) else { return };
        let now = kr_sys::Timespec { tv_sec: 0, tv_nsec: fs::UTIME_NOW };
        let _ = fs::utimensat(AT_FDCWD, Some(&p), &[now, now], 0);
    }

    /// Records which image a container runs, so garbage collection knows the image is in use for
    /// as long as the container directory exists.
    pub fn set_container_image(&self, cid: &str, id: &ImageId) {
        let _ = crate::store::write_file_atomic_nosync(&format!("{}/containers/{cid}/image", self.root().trim_end_matches('/')), id.0.as_bytes());
    }

    /// Image ids used by the containers that exist; `None` when some container directory has no
    /// record (created by an older release or by `kr run`), meaning the set is unknown.
    pub fn images_in_use(&self) -> Option<BTreeSet<String>> {
        let mut out = BTreeSet::new();
        for c in self.list_dir("containers") {
            let p = cpath(&format!("{}/containers/{c}/image", self.root().trim_end_matches('/'))).ok()?;
            let id = fs::read_file(&p, 128).ok().and_then(|d| String::from_utf8(d).ok())?;
            out.insert(id.trim().to_string());
        }
        Some(out)
    }

    fn list_dir(&self, sub: &str) -> Vec<String> {
        let Ok(p) = cpath(&format!("{}/{sub}", self.root().trim_end_matches('/'))) else { return Vec::new() };
        let Ok(fd) = fs::openat(AT_FDCWD, &p, fs::O_RDONLY | fs::O_DIRECTORY | fs::O_CLOEXEC, 0) else { return Vec::new() };
        fs::read_dir(&fd).filter_map(core::result::Result::ok).filter_map(|e| String::from_utf8(e.name).ok()).collect()
    }

    /// Every installed image with the time (seconds) it was installed or last marked used.
    pub fn images(&self) -> Vec<(ImageId, i64)> {
        self.list_dir("images")
            .into_iter()
            .map(ImageId)
            .filter(ImageId::valid)
            .filter_map(|id| {
                let p = cpath(&self.image_dir(&id).ok()?).ok()?;
                let st = fs::newfstatat(AT_FDCWD, &p, fs::AT_SYMLINK_NOFOLLOW).ok()?;
                Some((id, st.mtime_sec))
            })
            .collect()
    }

    /// The references (as stored in `refs/`) that point at the image.
    pub fn refs_of(&self, id: &ImageId) -> Vec<String> {
        self.list_dir("refs")
            .into_iter()
            .filter(|name| {
                let Ok(p) = cpath(&format!("{}/refs/{name}", self.root().trim_end_matches('/'))) else { return false };
                fs::read_file(&p, 256).ok().is_some_and(|d| core::str::from_utf8(&d).is_ok_and(|s| s.trim() == id.0))
            })
            .collect()
    }

    /// Config and layer digests named by an installed image's manifest (empty when unreadable).
    fn blobs_of(&self, id: &ImageId) -> Option<Vec<String>> {
        let p = cpath(&format!("{}/manifest.json", self.image_dir(id).ok()?)).ok()?;
        let raw = fs::read_file(&p, 4 << 20).ok()?;
        match parse_manifest(&raw, None).ok()? {
            Manifest::Image(m) => Some(core::iter::once(m.config.digest.as_str().to_string()).chain(m.layers.iter().map(|l| l.digest.as_str().to_string())).collect()),
            Manifest::Index(_) => None,
        }
    }

    /// Removes the image: its refs, its directory (flattened rootfs included), the shared layers
    /// and blobs no remaining image uses. Returns the number of layers and blobs removed.
    /// The caller must make sure no container uses the image and no pull is installing.
    pub fn remove_image(&self, id: &ImageId) -> Result<(usize, usize)> {
        let blobs = self.blobs_of(id);
        let layers = self.image_layers(id).unwrap_or_default();
        for r in self.refs_of(id) {
            let _ = fs::unlinkat(AT_FDCWD, &cpath(&format!("{}/refs/{r}", self.root().trim_end_matches('/')))?, 0);
        }
        let images = format!("{}/images", self.root().trim_end_matches('/'));
        let dirfd = fs::openat(AT_FDCWD, &cpath(&images)?, fs::O_RDONLY | fs::O_DIRECTORY | fs::O_CLOEXEC, 0).map_err(|e| crate::store::Error::Io("open images", e))?;
        for left in self.list_dir("images").into_iter().filter(|n| n.starts_with("gc-")) {
            let _ = fs::remove_all(dirfd.raw(), &cpath(&left)?); // a removal that a crash interrupted
        }
        // Rename away first so the image is never half-visible, then delete at leisure.
        let gone = format!("gc-{}\0", id.0);
        let _ = fs::renameat2(dirfd.raw(), &cpath(&id.0)?, dirfd.raw(), gone.as_bytes(), 0);
        let _ = fs::remove_all(dirfd.raw(), gone.as_bytes());
        let (mut keep_layers, mut keep_blobs) = (BTreeSet::new(), BTreeSet::new());
        for (other, _) in self.images() {
            keep_layers.extend(self.image_layers(&other).unwrap_or_default());
            match self.blobs_of(&other) {
                Some(b) => keep_blobs.extend(b),
                None => return Ok((0, 0)), // cannot tell what it needs: keep every blob and layer
            }
        }
        let ldir = self.layers_dir();
        let lfd = fs::openat(AT_FDCWD, &cpath(&ldir)?, fs::O_RDONLY | fs::O_DIRECTORY | fs::O_CLOEXEC, 0).ok();
        let mut nl = 0;
        for k in layers.iter().filter(|k| !keep_layers.contains(*k)) {
            if let Some(fd) = &lfd {
                nl += fs::remove_all(fd.raw(), &cpath(k)?).is_ok() as usize;
            }
        }
        let mut nb = 0;
        for d in blobs.unwrap_or_default().iter().filter(|d| !keep_blobs.contains(*d)) {
            if let Ok(dg) = kr_net::registry::Digest::parse(d) {
                if let Ok(bp) = self.blob_path(&dg) {
                    nb += fs::unlinkat(AT_FDCWD, &cpath(&bp)?, 0).is_ok() as usize;
                }
            }
        }
        Ok((nl, nb))
    }
}
