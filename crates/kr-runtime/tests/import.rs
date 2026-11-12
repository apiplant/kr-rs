mod common;
use common::*;
use kr_net::registry::Digest;
use kr_runtime::import::{import_dir, import_dir_once, import_file};
use kr_runtime::store::Store;
use std::path::PathBuf;

fn tmp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("krrt-import-{}-{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn sha(d: &[u8]) -> String {
    Digest::sha256_of(d).as_str().to_string()
}

/// (layer tar, config json)
fn image() -> (Vec<u8>, Vec<u8>) {
    let mut l = Tar::new();
    l.dir("bin", 0o755);
    l.file("bin/hello", 0o755, b"hi there");
    let layer = l.finish();
    let cfg = format!("{{\"config\":{{\"Cmd\":[\"/bin/hello\"],\"Env\":[\"A=b\"]}},\"rootfs\":{{\"type\":\"layers\",\"diff_ids\":[\"{}\"]}}}}", sha(&layer));
    (layer, cfg.into_bytes())
}

fn docker_archive(tag: &str) -> Vec<u8> {
    let (layer, cfg) = image();
    let mut t = Tar::new();
    t.file("abc.json", 0o644, &cfg);
    t.dir("l1", 0o755);
    t.file("l1/layer.tar", 0o644, &layer);
    let m = format!("[{{\"Config\":\"abc.json\",\"RepoTags\":[\"{tag}\"],\"Layers\":[\"l1/layer.tar\"]}}]");
    t.file("manifest.json", 0o644, m.as_bytes());
    t.finish()
}

#[test]
fn imports_docker_archive_and_gz_without_network() {
    let base = tmp("docker");
    let store = Store::open(Some(base.join("store").to_str().unwrap())).unwrap();
    let ar = docker_archive("example.com/app/hello:v1");
    let f = base.join("hello.tar");
    std::fs::write(&f, &ar).unwrap();
    let ids = import_file(&store, f.to_str().unwrap()).unwrap();
    assert_eq!(ids.len(), 1);
    let (id, cfg, rootfs) = store.image("example.com/app/hello:v1").expect("tag registered");
    assert_eq!(id, ids[0]);
    assert_eq!(cfg.cmd, ["/bin/hello"]);
    let root = String::from_utf8(rootfs[..rootfs.len() - 1].to_vec()).unwrap();
    assert_eq!(std::fs::read(format!("{root}/bin/hello")).unwrap(), b"hi there");

    // gzip variant of a different tag; the directory import finds both files
    let gz = gzip_stored(&docker_archive("busybox:latest"));
    std::fs::create_dir_all(base.join("imgs")).unwrap();
    std::fs::write(base.join("imgs/b.tar.gz"), &gz).unwrap();
    std::fs::write(base.join("imgs/ignored.txt"), b"x").unwrap();
    std::fs::write(base.join("imgs/a.tar"), &ar).unwrap();
    let out = import_dir(&store, base.join("imgs").to_str().unwrap());
    assert_eq!(out.len(), 2);
    assert!(out.iter().all(|o| o.result.is_ok()), "{out:?}");
    assert!(store.resolve_ref("busybox").is_some() && store.resolve_ref("docker.io/library/busybox:latest").is_some());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn import_once_remembers_files() {
    let base = tmp("once");
    let store = Store::open(Some(base.join("store").to_str().unwrap())).unwrap();
    let d = base.join("images");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("a.tar"), docker_archive("x/y:1")).unwrap();
    std::fs::write(d.join("bad.tar"), b"not a tar").unwrap();
    let first = import_dir_once(&store, d.to_str().unwrap());
    assert_eq!(first.len(), 2);
    assert!(first.iter().find(|o| o.file.ends_with("a.tar")).unwrap().result.is_ok());
    assert!(first.iter().find(|o| o.file.ends_with("bad.tar")).unwrap().result.is_err());
    // only the failed file is retried
    let second = import_dir_once(&store, d.to_str().unwrap());
    assert_eq!(second.len(), 1);
    assert!(second[0].file.ends_with("bad.tar"));
    assert!(import_dir(&store, "/nonexistent/dir").is_empty());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn imports_oci_layout() {
    let base = tmp("oci");
    let store = Store::open(Some(base.join("store").to_str().unwrap())).unwrap();
    let (layer, cfg) = image();
    let manifest = format!(
        "{{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"config\":{{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"{}\",\"size\":{}}},\"layers\":[{{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar\",\"digest\":\"{}\",\"size\":{}}}]}}",
        sha(&cfg), cfg.len(), sha(&layer), layer.len()
    );
    let index = format!(
        "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"{}\",\"size\":{},\"annotations\":{{\"io.containerd.image.name\":\"registry.local/oci/app:2\"}}}}]}}",
        sha(manifest.as_bytes()), manifest.len()
    );
    let blob = |d: &[u8]| format!("blobs/sha256/{}", &sha(d)["sha256:".len()..]);
    let mut t = Tar::new();
    t.file("oci-layout", 0o644, b"{\"imageLayoutVersion\":\"1.0.0\"}");
    t.file("index.json", 0o644, index.as_bytes());
    t.dir("blobs", 0o755);
    t.dir("blobs/sha256", 0o755);
    t.file(&blob(manifest.as_bytes()), 0o644, manifest.as_bytes());
    t.file(&blob(&cfg), 0o644, &cfg);
    t.file(&blob(&layer), 0o644, &layer);
    let f = base.join("oci.tar");
    std::fs::write(&f, t.finish()).unwrap();
    let ids = import_file(&store, f.to_str().unwrap()).unwrap();
    assert_eq!(ids.len(), 1);
    assert!(store.image("registry.local/oci/app:2").is_some());
    // a corrupt layer is rejected
    let mut bad = Tar::new();
    bad.file("index.json", 0o644, index.as_bytes());
    bad.file(&blob(manifest.as_bytes()), 0o644, manifest.as_bytes());
    bad.file(&blob(&cfg), 0o644, &cfg);
    bad.file(&blob(&layer), 0o644, b"corrupt");
    std::fs::write(&f, bad.finish()).unwrap();
    let store2 = Store::open(Some(base.join("store2").to_str().unwrap())).unwrap();
    assert!(import_file(&store2, f.to_str().unwrap()).is_err());
    let _ = std::fs::remove_dir_all(&base);
}
