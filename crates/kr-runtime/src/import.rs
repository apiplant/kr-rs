//! Air-gap image import: `docker save` archives (`manifest.json`) and OCI image layouts
//! (`index.json`) in `.tar` / `.tar.gz` files go into the image store without network
//! (ADR-044). Zstd-compressed archives are refused (kr-archive has no zstd).
use crate::pull::install_image;
use crate::store::{cpath, mkdir_p, Ctx, Error, ImageConfig, ImageId, Result, Store};
use crate::unpack::Limits;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_archive::gzip::GzDecoder;
use kr_archive::tar::{self, Event, Kind, TarReader};
use kr_fmt::json::Value;
use kr_net::registry::{self, Descriptor, Digest, Manifest};
use kr_net::sha256::{hex, Sha256};
use kr_sys::fs::{self, AT_FDCWD};
use kr_sys::{Errno, Fd};

const MAX_ARCHIVE_BYTES: u64 = 64 << 30;
const MAX_JSON: usize = 16 << 20;
const MT_LAYER: &str = "application/vnd.oci.image.layer.v1.tar";
const MT_LAYER_GZ: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

/// Result of importing one file.
#[derive(Debug)]
pub struct Outcome {
    pub file: String,
    pub result: Result<Vec<ImageId>>,
}

fn is_archive_name(n: &str) -> bool {
    n.ends_with(".tar") || n.ends_with(".tar.gz") || n.ends_with(".tgz") || n.ends_with(".tar.zst") || n.ends_with(".tzst")
}

fn list_archives(dir: &str) -> Vec<String> {
    let Ok(c) = cpath(dir) else { return Vec::new() };
    let Ok(fd) = fs::openat(AT_FDCWD, &c, fs::O_RDONLY | fs::O_DIRECTORY | fs::O_CLOEXEC, 0) else { return Vec::new() };
    let mut names: Vec<String> = fs::read_dir(&fd).filter_map(|e| e.ok()).filter_map(|e| String::from_utf8(e.name).ok()).filter(|n| !n.starts_with('.') && is_archive_name(n)).collect();
    names.sort();
    names.into_iter().map(|n| format!("{}/{n}", dir.trim_end_matches('/'))).collect()
}

/// Imports every archive in `dir` (sorted by name); a missing directory imports nothing.
pub fn import_dir(store: &Store, dir: &str) -> Vec<Outcome> {
    list_archives(dir).into_iter().map(|f| Outcome { result: import_file(store, &f), file: f }).collect()
}

fn stat_key(path: &str) -> Option<String> {
    let st = fs::newfstatat(AT_FDCWD, &cpath(path).ok()?, 0).ok()?;
    Some(format!("{path}\t{}\t{}", st.mtime_sec, st.size))
}

/// [`import_dir`] for node start: a file whose path, mtime and size are recorded in
/// `<store>/imported.txt` is skipped, a successful import is recorded.
pub fn import_dir_once(store: &Store, dir: &str) -> Vec<Outcome> {
    let marker = format!("{}/imported.txt", store.root().trim_end_matches('/'));
    let mut done: String = cpath(&marker).ok().and_then(|c| fs::read_file(&c, 8 << 20).ok()).and_then(|b| String::from_utf8(b).ok()).unwrap_or_default();
    let mut out = Vec::new();
    for f in list_archives(dir) {
        let Some(key) = stat_key(&f) else { continue };
        if done.lines().any(|l| l == key) {
            continue;
        }
        let result = import_file(store, &f);
        if result.is_ok() {
            done.push_str(&key);
            done.push('\n');
            let _ = crate::store::write_file_atomic(&marker, done.as_bytes());
        }
        out.push(Outcome { file: f, result });
    }
    out
}

struct Tmp(String);
impl Drop for Tmp {
    fn drop(&mut self) {
        if let Ok(c) = cpath(&self.0) {
            let _ = fs::remove_all(AT_FDCWD, &c);
        }
    }
}

/// Imports one archive and returns the ids of the images it holds.
pub fn import_file(store: &Store, path: &str) -> Result<Vec<ImageId>> {
    let mut nonce = [0u8; 4];
    kr_sys::getrandom(&mut nonce);
    let tmp = Tmp(format!("{}/import.tmp-{}-{:08x}", store.root().trim_end_matches('/'), fs::getpid(), u32::from_le_bytes(nonce)));
    mkdir_p(&tmp.0, 0o700)?;
    extract(path, &tmp.0)?;
    let rd = |rel: &str| -> Result<Vec<u8>> { fs::read_file(&cpath(&format!("{}/{rel}", tmp.0))?, MAX_JSON).map_err(|e| Error::Io("read archive member", e)) };
    let exists = |rel: &str| cpath(&format!("{}/{rel}", tmp.0)).ok().and_then(|c| fs::newfstatat(AT_FDCWD, &c, fs::AT_SYMLINK_NOFOLLOW).ok()).is_some();
    let mut ids = Vec::new();
    if exists("manifest.json") {
        let m = kr_fmt::json::parse(&rd("manifest.json")?).map_err(|_| Error::Json("manifest.json is not valid JSON"))?;
        for item in m.as_array().ok_or(Error::Image("manifest.json is not an array"))? {
            let cfg = item.get("Config").and_then(Value::as_str).ok_or(Error::Image("manifest.json entry without Config"))?;
            let layers: Vec<&str> = item.get("Layers").and_then(Value::as_array).ok_or(Error::Image("manifest.json entry without Layers"))?.iter().filter_map(Value::as_str).collect();
            let tags: Vec<&str> = item.get("RepoTags").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
            let cfg_json = rd(&safe(cfg)?)?;
            let mut descs = Vec::new();
            for l in &layers {
                descs.push(layer_blob(store, &format!("{}/{}", tmp.0, safe(l)?), None)?);
            }
            let id = install(store, &cfg_json, descs, None)?;
            for t in tags {
                tag(store, t, &id)?;
            }
            ids.push(id);
        }
    } else if exists("index.json") {
        let idx = rd("index.json")?;
        oci_index(store, &tmp.0, &idx, None, &mut ids, 0)?;
    } else {
        return Err(Error::Image("not an image archive (no manifest.json or index.json)"));
    }
    if ids.is_empty() {
        return Err(Error::Image("archive holds no images"));
    }
    Ok(ids)
}

/// A relative archive path without `..` or a leading `/`.
fn safe(p: &str) -> Result<String> {
    Ok(tar::sanitize(p).map_err(|_| Error::Unsafe("archive path escapes the archive"))?.into_string())
}

fn blob_file(root: &str, d: &Digest) -> Result<String> {
    let (alg, h) = d.as_str().split_once(':').ok_or(Error::Image("bad digest"))?;
    if alg != "sha256" || h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Net(kr_net::Error::UnsupportedDigest));
    }
    Ok(format!("{root}/blobs/sha256/{h}"))
}

fn oci_index(store: &Store, root: &str, body: &[u8], name: Option<&str>, ids: &mut Vec<ImageId>, depth: u32) -> Result<()> {
    if depth > 4 {
        return Err(Error::Image("OCI index nesting too deep"));
    }
    let v = kr_fmt::json::parse(body).map_err(|_| Error::Json("index.json is not valid JSON"))?;
    for m in v.get("manifests").and_then(Value::as_array).ok_or(Error::Image("index.json without manifests"))? {
        let d = Digest::parse(m.get("digest").and_then(Value::as_str).ok_or(Error::Image("index entry without digest"))?)?;
        let ann = |k: &str| m.get("annotations").and_then(|a| a.get(k)).and_then(Value::as_str);
        // containerd records the full name; the OCI ref.name may be a bare tag
        let nm = ann("io.containerd.image.name").or_else(|| ann("org.opencontainers.image.ref.name")).or(name);
        let raw = fs::read_file(&cpath(&blob_file(root, &d)?)?, MAX_JSON).map_err(|e| Error::Io("read blob", e))?;
        if Digest::sha256_of(&raw) != d {
            return Err(Error::Digest);
        }
        match registry::parse_manifest(&raw, m.get("mediaType").and_then(Value::as_str))? {
            Manifest::Index(entries) => {
                if let Ok(e) = registry::select_platform(&entries, "linux", registry::target_arch()) {
                    let sub = format!("{{\"manifests\":[{{\"digest\":\"{}\",\"mediaType\":\"{}\"}}]}}", e.descriptor.digest, e.descriptor.media_type);
                    oci_index(store, root, sub.as_bytes(), nm, ids, depth + 1)?;
                }
                // an index without our platform is skipped (multi-arch archive)
            }
            Manifest::Image(im) => {
                let cfg_raw = fs::read_file(&cpath(&blob_file(root, &im.config.digest)?)?, MAX_JSON).map_err(|e| Error::Io("read blob", e))?;
                if Digest::sha256_of(&cfg_raw) != im.config.digest {
                    return Err(Error::Digest);
                }
                let mut descs = Vec::new();
                for l in &im.layers {
                    if l.media_type.contains("zstd") {
                        return Err(Error::Image("zstd-compressed layers are not supported"));
                    }
                    descs.push(layer_blob(store, &blob_file(root, &l.digest)?, Some(l.clone()))?);
                }
                let id = install(store, &cfg_raw, descs, Some(&raw))?;
                if let Some(n) = nm {
                    tag(store, n, &id)?;
                }
                ids.push(id);
            }
        }
    }
    Ok(())
}

/// Copies the layer file into the blob store (verifying a known digest) and returns its
/// descriptor; compression is detected from the magic bytes.
fn layer_blob(store: &Store, path: &str, want: Option<Descriptor>) -> Result<Descriptor> {
    let fd = fs::openat(AT_FDCWD, &cpath(path)?, fs::O_RDONLY | fs::O_NOFOLLOW | fs::O_CLOEXEC, 0).map_err(|_| Error::Image("layer file missing from the archive"))?;
    let mut buf = alloc::vec![0u8; 64 << 10];
    let mut h = Sha256::new();
    let (mut size, mut magic) = (0u64, [0u8; 4]);
    loop {
        let n = read(&fd, &mut buf)?;
        if n == 0 {
            break;
        }
        if size < 4 {
            let k = n.min(4 - size as usize);
            magic[size as usize..size as usize + k].copy_from_slice(&buf[..k]);
        }
        size += n as u64;
        h.update(&buf[..n]);
    }
    if magic == [0x28, 0xb5, 0x2f, 0xfd] {
        return Err(Error::Image("zstd-compressed layers are not supported"));
    }
    let digest = Digest::parse(&format!("sha256:{}", hex(&h.finalize())))?;
    if let Some(w) = &want {
        if w.digest != digest {
            return Err(Error::Digest);
        }
    }
    if !store.has_blob(&digest) || !store.verify_blob(&digest)? {
        let fd = fs::openat(AT_FDCWD, &cpath(path)?, fs::O_RDONLY | fs::O_NOFOLLOW | fs::O_CLOEXEC, 0).ctx("reopen layer")?;
        let mut w = store.blob_writer(&digest)?;
        loop {
            let n = read(&fd, &mut buf)?;
            if n == 0 {
                break;
            }
            w.write(&buf[..n])?;
        }
        w.commit()?;
    }
    let gz = magic[..2] == [0x1f, 0x8b];
    Ok(Descriptor { media_type: (if gz { MT_LAYER_GZ } else { MT_LAYER }).to_string(), digest, size })
}

fn read(fd: &Fd, buf: &mut [u8]) -> Result<usize> {
    loop {
        match kr_sys::read(fd.raw(), buf) {
            Err(Errno(kr_sys::EINTR)) => continue,
            r => return r.ctx("read"),
        }
    }
}

/// Stores config + layers (already in the blob store) as an image; the OCI manifest is kept
/// as is, a docker archive gets one synthesised.
fn install(store: &Store, cfg_json: &[u8], layers: Vec<Descriptor>, manifest: Option<&[u8]>) -> Result<ImageId> {
    let cfg_digest = Digest::sha256_of(cfg_json);
    let icfg = ImageConfig::parse(cfg_json)?;
    let id = ImageId(cfg_digest.as_str().strip_prefix("sha256:").ok_or(Error::Image("bad digest"))?.to_string());
    if store.has_image(&id) {
        return Ok(id);
    }
    store.put_blob(&cfg_digest, cfg_json)?;
    let raw = match manifest {
        Some(m) => m.to_vec(),
        None => {
            let ls: Vec<String> = layers.iter().map(|l| format!("{{\"mediaType\":\"{}\",\"digest\":\"{}\",\"size\":{}}}", l.media_type, l.digest, l.size)).collect();
            format!(
                "{{\"schemaVersion\":2,\"mediaType\":\"{}\",\"config\":{{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"{cfg_digest}\",\"size\":{}}},\"layers\":[{}]}}",
                registry::MT_OCI_MANIFEST,
                cfg_json.len(),
                ls.join(",")
            )
            .into_bytes()
        }
    };
    let _ = store.put_blob(&Digest::sha256_of(&raw), &raw);
    let gz: Vec<bool> = layers.iter().map(|l| l.media_type.ends_with("gzip")).collect();
    install_image(store, &id, &raw, cfg_json, &layers, &gz, &icfg.diff_ids, &Limits::default())?;
    Ok(id)
}

/// Registers the tag as written and the forms a pod may use for it: the fully qualified name,
/// and for `:latest` / `docker.io/library/` names the short ones.
fn tag(store: &Store, t: &str, id: &ImageId) -> Result<()> {
    store.set_ref(t, id)?;
    if let Ok(r) = registry::Reference::parse(t) {
        store.set_ref(&r.to_string(), id)?;
        let short = if r.registry == "docker.io" { r.repository.strip_prefix("library/").unwrap_or(&r.repository).to_string() } else { format!("{}/{}", r.registry, r.repository) };
        if let Some(tg) = &r.tag {
            store.set_ref(&format!("{short}:{tg}"), id)?;
            if tg == "latest" {
                store.set_ref(&short, id)?;
            }
        }
    }
    Ok(())
}

/// Streams the (optionally gzip-compressed) tar at `path` into regular files under `dest`.
fn extract(path: &str, dest: &str) -> Result<()> {
    let fd = fs::openat(AT_FDCWD, &cpath(path)?, fs::O_RDONLY | fs::O_CLOEXEC, 0).ctx("open archive")?;
    let mut buf = alloc::vec![0u8; 64 << 10];
    let mut first = true;
    let mut gz: Option<GzDecoder> = None;
    let mut rd = TarReader::new();
    let mut cur: Option<Fd> = None;
    let mut total = 0u64;
    let mut sink = |d: &[u8]| -> Result<()> {
        let r = rd.feed(d, &mut |ev: Event<'_>| -> Result<()> {
            match ev {
                Event::Entry(e) => {
                    cur = None;
                    if e.kind == Kind::File {
                        let rel = safe(&e.path)?;
                        if rel.is_empty() {
                            return Ok(());
                        }
                        let full = format!("{dest}/{rel}");
                        if let Some((parent, _)) = full.rsplit_once('/') {
                            mkdir_p(parent, 0o700)?;
                        }
                        cur = Some(fs::openat(AT_FDCWD, &cpath(&full)?, fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC | fs::O_NOFOLLOW | fs::O_CLOEXEC, 0o600).ctx("create archive member")?);
                    }
                }
                Event::Data(b) => {
                    total += b.len() as u64;
                    if total > MAX_ARCHIVE_BYTES {
                        return Err(Error::Limit("archive too large"));
                    }
                    if let Some(f) = &cur {
                        fs::write_all(f.raw(), b).ctx("write archive member")?;
                    }
                }
                Event::End => cur = None,
            }
            Ok(())
        });
        r.map_err(Error::from)
    };
    loop {
        let n = read(&fd, &mut buf)?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        if first {
            first = false;
            if chunk.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
                return Err(Error::Image("zstd-compressed archives are not supported (use .tar or .tar.gz)"));
            }
            if chunk.starts_with(&[0x1f, 0x8b]) {
                gz = Some(GzDecoder::new());
            }
        }
        match &mut gz {
            Some(g) => g.feed(chunk, &mut sink).map_err(Error::from)?,
            None => sink(chunk)?,
        }
    }
    if let Some(g) = &gz {
        g.finish().map_err(|e| Error::Archive(e))?;
    }
    Ok(())
}
