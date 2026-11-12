//! Image removal frees what only that image used and keeps what others share.
use kr_net::registry::Digest;
use kr_runtime::store::*;
use std::path::PathBuf;

fn hex(data: &[u8]) -> String {
    kr_net::sha256::sha256(data).iter().map(|b| format!("{b:02x}")).collect()
}

fn install(s: &Store, root: &PathBuf, cfg: &[u8], layer: &[u8], key: &str, r: &str) -> ImageId {
    let (cd, ld) = (format!("sha256:{}", hex(cfg)), format!("sha256:{}", hex(layer)));
    s.put_blob(&Digest::parse(&cd).unwrap(), cfg).unwrap();
    s.put_blob(&Digest::parse(&ld).unwrap(), layer).unwrap();
    let manifest = format!(r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{cd}","size":{}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{ld}","size":{}}}]}}"#, cfg.len(), layer.len());
    let id = ImageId(hex(cfg));
    let dir = root.join("images").join(&id.0);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("manifest.json"), manifest).unwrap();
    std::fs::write(dir.join("config.json"), cfg).unwrap();
    std::fs::create_dir_all(root.join("layers").join(key)).unwrap();
    std::fs::write(dir.join("layers"), format!("{key}\n")).unwrap();
    s.set_ref(r, &id).unwrap();
    id
}

#[test]
fn removing_an_image_keeps_shared_layers_and_blobs() {
    let root = std::env::temp_dir().join(format!("krrt-gc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let s = Store::open(Some(root.to_str().unwrap())).unwrap();
    let key = "aaaaaaaaaaaaaaaaaaaaaaaa";
    let shared = b"shared layer bytes";
    let a = install(&s, &root, b"{\"a\":1}", shared, key, "example.com/a:1");
    let b = install(&s, &root, b"{\"b\":2}", shared, key, "example.com/b:1");
    let only = install(&s, &root, b"{\"c\":3}", b"private layer", "bbbbbbbbbbbbbbbbbbbbbbbb", "example.com/c:1");
    assert_eq!(s.images().len(), 3);
    s.mark_used(&a);
    let (nl, nb) = s.remove_image(&only).unwrap();
    assert_eq!((nl, nb), (1, 2), "its own layer, config and layer blob");
    assert!(!root.join("layers/bbbbbbbbbbbbbbbbbbbbbbbb").exists());
    assert!(s.resolve_ref("example.com/c:1").is_none());
    let (nl, nb) = s.remove_image(&a).unwrap();
    assert_eq!((nl, nb), (0, 1), "the layer and its blob are still b's; only a's config goes");
    assert!(root.join("layers").join(key).exists());
    assert!(s.resolve_ref("example.com/b:1").is_some());
    assert_eq!(s.images().into_iter().map(|(i, _)| i).collect::<Vec<_>>(), vec![b.clone()]);
    let (nl, nb) = s.remove_image(&b).unwrap();
    assert_eq!((nl, nb), (1, 2));
    assert!(s.images().is_empty());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn find_image_sweep_and_legacy_container_dirs() {
    let root = std::env::temp_dir().join(format!("krrt-gc2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let s = Store::open(Some(root.to_str().unwrap())).unwrap();
    let a = install(&s, &root, b"{\"a\":1}", b"layer a", "aaaaaaaaaaaaaaaaaaaaaaaa", "example.com/a:1");
    assert_eq!(s.find_image("example.com/a:1"), Some(a.clone()));
    assert_eq!(s.find_image(&a.0[..12]), Some(a.clone()));
    assert_eq!(s.find_image(&format!("sha256:{}", a.0)), Some(a.clone()));
    assert_eq!(s.find_image("example.com/nope:1"), None);
    // A blob no manifest names goes (when old enough); the image's own stay.
    let stray = b"stray";
    s.put_blob(&Digest::parse(&format!("sha256:{}", hex(stray))).unwrap(), stray).unwrap();
    assert_eq!(s.sweep_blobs(i64::MAX / 2, 3600), 1);
    assert_eq!(s.sweep_blobs(i64::MAX / 2, 3600), 0);
    // A container directory with a record protects its image.
    let c = s.create_container("c1").unwrap();
    s.set_container_image("c1", &a);
    assert!(s.images_in_use().unwrap().contains(&a.0));
    // Without a record the set is unknown, as the directory is newer than the boot.
    std::fs::remove_file(format!("{}/image", c.root)).unwrap();
    assert!(s.images_in_use().is_none());
    let _ = std::fs::remove_dir_all(&root);
}
