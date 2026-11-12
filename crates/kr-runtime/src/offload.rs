//! Image work run in offload workers (ADR-052): verifying a stored blob and installing (unpacking)
//! an image's layers. Both read and write only files in the store, so a worker needs just the
//! store root and the digests; the CPU-heavy part (SHA-256 of layers, gunzip, tar extraction)
//! then no longer blocks the event loop of the kubelet.

use crate::store::{Error, Raw, Result, Store};
use crate::unpack::Limits;
use alloc::string::String;
use alloc::vec::Vec;
use kr_net::registry::{Descriptor, Digest};

/// Job kinds (the API server uses 1..9).
pub const KIND_VERIFY_BLOB: u32 = 10;
pub const KIND_INSTALL_IMAGE: u32 = 11;
pub const KIND_FSYNC_FILE: u32 = 12;
pub const KIND_REMOVE_IMAGE: u32 = 13;

#[derive(Default)]
struct Enc(Vec<u8>);

impl Enc {
    fn bytes(&mut self, b: &[u8]) {
        self.0.extend_from_slice(&(b.len() as u32).to_le_bytes());
        self.0.extend_from_slice(b);
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
}

struct Dec<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Dec<'a> {
    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = u32::from_le_bytes(self.b.get(self.p..self.p + 4)?.try_into().ok()?) as usize;
        self.p += 4;
        let s = self.b.get(self.p..self.p.checked_add(n)?)?;
        self.p += n;
        Some(s)
    }
    fn str(&mut self) -> Option<&'a str> {
        core::str::from_utf8(self.bytes()?).ok()
    }
    fn u64(&mut self) -> Option<u64> {
        let v = u64::from_le_bytes(self.b.get(self.p..self.p + 8)?.try_into().ok()?);
        self.p += 8;
        Some(v)
    }
}

/// The handler the workers run for the kinds above.
pub fn handler(kind: u32, req: &[u8]) -> Vec<u8> {
    run(kind, req).unwrap_or_else(|| alloc::vec![1, b'b', b'a', b'd', b' ', b'j', b'o', b'b'])
}

fn run(kind: u32, req: &[u8]) -> Option<Vec<u8>> {
    let mut d = Dec { b: req, p: 0 };
    if kind == KIND_FSYNC_FILE {
        let mut path = d.bytes()?.to_vec();
        path.push(0);
        let fd = kr_sys::fs::openat(kr_sys::fs::AT_FDCWD, &path, kr_sys::fs::O_RDONLY | kr_sys::fs::O_CLOEXEC, 0).ok()?;
        return Some(alloc::vec![kr_sys::fs::fsync(fd.raw()).is_err() as u8]);
    }
    let store = Store::open(Some(d.str()?)).ok()?;
    match kind {
        KIND_VERIFY_BLOB => {
            let digest = Digest::parse(d.str()?).ok()?;
            Some(alloc::vec![match store.verify_blob(&digest) {
                Ok(true) => 0,
                Ok(false) => 1,
                Err(_) => 2,
            }])
        }
        KIND_INSTALL_IMAGE => {
            let id = crate::store::ImageId(d.str()?.into());
            let manifest = d.bytes()?;
            let cfg = d.bytes()?;
            let n = d.u64()? as usize;
            let mut layers = Vec::new();
            for _ in 0..n {
                layers.push(Descriptor { media_type: String::new(), digest: Digest::parse(d.str()?).ok()?, size: 0 });
            }
            let gz: Vec<bool> = d.bytes()?.iter().map(|b| *b != 0).collect();
            let mut diff_ids = Vec::new();
            for _ in 0..d.u64()? {
                diff_ids.push(String::from(d.str()?));
            }
            let limits = Limits { max_bytes: d.u64()?, max_image_bytes: d.u64()?, max_entries: d.u64()?, max_path: d.u64()? as usize };
            Some(match crate::pull::install_image(&store, &id, manifest, cfg, &layers, &gz, &diff_ids, &limits) {
                Ok(()) => alloc::vec![0],
                Err(e) => {
                    let mut out = alloc::vec![1];
                    out.extend_from_slice(alloc::format!("{e:?}").as_bytes());
                    out
                }
            })
        }
        KIND_REMOVE_IMAGE => {
            let id = crate::store::ImageId(d.str()?.into());
            Some(match store.remove_image(&id) {
                Ok((l, b)) => {
                    let mut out = alloc::vec![0];
                    out.extend_from_slice(&(l as u64).to_le_bytes());
                    out.extend_from_slice(&(b as u64).to_le_bytes());
                    out
                }
                Err(e) => {
                    let mut out = alloc::vec![1];
                    out.extend_from_slice(alloc::format!("{e:?}").as_bytes());
                    out
                }
            })
        }
        _ => None,
    }
}

fn error_of(out: &[u8]) -> Error {
    Error::Remote(Raw(String::from_utf8_lossy(&out[1..]).into_owned()))
}

/// [`Store::verify_blob`], in a worker when one is available (hashing a layer takes seconds).
pub async fn verify_blob(store: &Store, d: &Digest) -> Result<bool> {
    if kr_rt::offload::enabled_in(kr_rt::offload::SLOW) {
        let mut e = Enc::default();
        e.bytes(store.root().as_bytes());
        e.bytes(d.as_str().as_bytes());
        if let Some(out) = kr_rt::offload::call_in(kr_rt::offload::SLOW, KIND_VERIFY_BLOB, &e.0).await {
            return match out.first() {
                Some(0) => Ok(true),
                Some(1) => Ok(false),
                _ => store.verify_blob(d), // the worker could not tell: do it here
            };
        }
    }
    store.verify_blob(d)
}

/// [`crate::pull::install_image`], in a worker when one is available (gunzip, SHA-256 and tar
/// extraction of every layer).
#[allow(clippy::too_many_arguments)]
pub async fn install_image(store: &Store, id: &crate::store::ImageId, manifest: &[u8], cfg_json: &[u8], layers: &[Descriptor], gz: &[bool], diff_ids: &[String], limits: &Limits) -> Result<()> {
    if kr_rt::offload::enabled_in(kr_rt::offload::SLOW) {
        let mut e = Enc::default();
        e.bytes(store.root().as_bytes());
        e.bytes(id.0.as_bytes());
        e.bytes(manifest);
        e.bytes(cfg_json);
        e.u64(layers.len() as u64);
        for l in layers {
            e.bytes(l.digest.as_str().as_bytes());
        }
        e.bytes(&gz.iter().map(|g| *g as u8).collect::<Vec<u8>>());
        e.u64(diff_ids.len() as u64);
        for d in diff_ids {
            e.bytes(d.as_bytes());
        }
        for v in [limits.max_bytes, limits.max_image_bytes, limits.max_entries, limits.max_path as u64] {
            e.u64(v);
        }
        if let Some(out) = kr_rt::offload::call_in(kr_rt::offload::SLOW, KIND_INSTALL_IMAGE, &e.0).await {
            return match out.first() {
                Some(0) => Ok(()),
                Some(1) => Err(error_of(&out)),
                _ => crate::pull::install_image(store, id, manifest, cfg_json, layers, gz, diff_ids, limits),
            };
        }
    }
    crate::pull::install_image(store, id, manifest, cfg_json, layers, gz, diff_ids, limits)
}

/// fsyncs a file by path in a worker (flushing hundreds of MB takes seconds), or here when no
/// worker is available.
pub async fn fsync_file(path: &str) -> Result<()> {
    if kr_rt::offload::enabled_in(kr_rt::offload::SLOW) {
        let mut e = Enc::default();
        e.bytes(path.as_bytes());
        if let Some(out) = kr_rt::offload::call_in(kr_rt::offload::SLOW, KIND_FSYNC_FILE, &e.0).await {
            if out.first() == Some(&0) {
                return Ok(());
            }
        }
    }
    let mut p = path.as_bytes().to_vec();
    p.push(0);
    let fd = kr_sys::fs::openat(kr_sys::fs::AT_FDCWD, &p, kr_sys::fs::O_RDONLY | kr_sys::fs::O_CLOEXEC, 0).map_err(|e| Error::Io("open blob for fsync", e))?;
    kr_sys::fs::fsync(fd.raw()).map_err(|e| Error::Io("fsync blob", e))
}

/// [`Store::remove_image`], in a worker when one is available (a rootfs holds tens of thousands
/// of files). Only for a caller whose own uid may delete everything (real root): a rootless
/// kubelet removes files through its id maps and calls the store directly.
pub async fn remove_image(store: &Store, id: &crate::store::ImageId) -> Result<(usize, usize)> {
    if kr_sys::fs::getuid() == 0 && kr_rt::offload::enabled_in(kr_rt::offload::SLOW) {
        let mut e = Enc::default();
        e.bytes(store.root().as_bytes());
        e.bytes(id.0.as_bytes());
        if let Some(out) = kr_rt::offload::call_in(kr_rt::offload::SLOW, KIND_REMOVE_IMAGE, &e.0).await {
            match out.first() {
                Some(0) if out.len() == 17 => {
                    return Ok((u64::from_le_bytes(out[1..9].try_into().unwrap()) as usize, u64::from_le_bytes(out[9..17].try_into().unwrap()) as usize));
                }
                Some(1) => return Err(error_of(&out)),
                _ => {}
            }
        }
    }
    store.remove_image(id)
}
