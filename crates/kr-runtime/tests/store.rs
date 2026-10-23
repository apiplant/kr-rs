mod common;
use common::*;
use kr_net::registry::Digest;
use kr_runtime::store::*;
use std::path::PathBuf;

fn tmp_store(name: &str) -> (PathBuf, Store) {
    let p = std::env::temp_dir().join(format!("krrt-store-{}-{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&p);
    let s = Store::open(Some(p.to_str().unwrap())).unwrap();
    (p, s)
}

#[test]
fn root_rules() {
    let env = |pairs: &'static [(&'static str, &'static str)]| {
        move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
    };
    // KR_ROOT wins, even for root
    assert_eq!(root_from(&env(&[("KR_ROOT", "/x/kr"), ("HOME", "/h")]), 1000).unwrap(), "/x/kr");
    assert_eq!(root_from(&env(&[("KR_ROOT", "/x/kr")]), 0).unwrap(), "/x/kr");
    assert_eq!(root_from(&env(&[("HOME", "/h")]), 0).unwrap(), "/var/lib/kr");
    assert_eq!(root_from(&env(&[("XDG_DATA_HOME", "/xdg"), ("HOME", "/h")]), 1000).unwrap(), "/xdg/kr");
    assert_eq!(root_from(&env(&[("HOME", "/h")]), 1000).unwrap(), "/h/.local/share/kr");
    // relative XDG_DATA_HOME is ignored (per the XDG spec); empty KR_ROOT too
    assert_eq!(root_from(&env(&[("XDG_DATA_HOME", "rel"), ("KR_ROOT", ""), ("HOME", "/h")]), 1000).unwrap(), "/h/.local/share/kr");
    assert_eq!(root_from(&env(&[]), 1000), Err(Error::NoRoot));
}

#[test]
fn env_var_reads_the_process_environment() {
    assert!(env_var("PATH").is_some());
    assert!(env_var("KR_SURELY_UNSET_VARIABLE").is_none());
}

#[test]
fn ref_escaping_is_a_single_safe_component() {
    for r in ["docker.io/library/busybox:latest", "../../etc/passwd", ".hidden", "a b\0c", "x@sha256:abc", "%2f"] {
        let e = escape_ref(r);
        assert!(!e.contains('/') && !e.contains('\0') && !e.starts_with('.'), "{e}");
    }
    assert_ne!(escape_ref("a/b"), escape_ref("a%2fb"));
}

#[test]
fn image_config_parsing() {
    let c = ImageConfig::parse(
        br#"{"architecture":"amd64","config":{"Env":["PATH=/bin","A=b"],"Entrypoint":["/ep"],"Cmd":["sh","-c"],"WorkingDir":"/w","User":"1000:1000","Labels":null}}"#,
    )
    .unwrap();
    assert_eq!(c.env, ["PATH=/bin", "A=b"]);
    assert_eq!(c.entrypoint, ["/ep"]);
    assert_eq!(c.cmd, ["sh", "-c"]);
    assert_eq!((c.working_dir.as_str(), c.user.as_str()), ("/w", "1000:1000"));
    let c = ImageConfig::parse(br#"{"config":{"Cmd":null,"Env":null}}"#).unwrap();
    assert_eq!(c, ImageConfig::default());
    assert_eq!(ImageConfig::parse(b"{}").unwrap(), ImageConfig::default());
    assert!(ImageConfig::parse(b"[]").is_err());
    assert!(ImageConfig::parse(b"not json").is_err());
    assert!(ImageConfig::parse(br#"{"config":{"Cmd":"sh"}}"#).is_err());
    assert!(ImageConfig::parse(br#"{"config":{"Env":[1]}}"#).is_err());
}

#[test]
fn blobs_are_atomic_and_verified() {
    let (p, s) = tmp_store("blobs");
    let data = b"hello blob".to_vec();
    let d = Digest::sha256_of(&data);
    assert!(!s.has_blob(&d));

    // wrong content: nothing appears, tmp file is removed
    let mut w = s.blob_writer(&d).unwrap();
    w.write(b"something else").unwrap();
    assert_eq!(w.commit(), Err(Error::Digest));
    assert!(!s.has_blob(&d));
    // dropped uncommitted writer leaves nothing either
    let mut w = s.blob_writer(&d).unwrap();
    w.write(&data[..3]).unwrap();
    assert!(!s.has_blob(&d));
    drop(w);
    let leftovers: Vec<_> = std::fs::read_dir(p.join("blobs/sha256")).unwrap().collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");

    s.put_blob(&d, &data).unwrap();
    assert!(s.has_blob(&d));
    assert!(s.verify_blob(&d).unwrap());
    // committing it again is fine
    s.put_blob(&d, &data).unwrap();

    // corrupt blob: detected, deleted
    let path = s.blob_path(&d).unwrap();
    std::fs::write(&path, b"corrupt!!!").unwrap();
    assert!(!s.verify_blob(&d).unwrap());
    assert!(!s.has_blob(&d));
    assert!(!s.verify_blob(&d).unwrap()); // missing -> false
    let _ = std::fs::remove_dir_all(&p);
}

#[test]
fn refs_images_and_containers() {
    let (p, s) = tmp_store("refs");
    let hexid = "a".repeat(64);
    let id = ImageId(hexid.clone());
    assert!(s.image("busybox").is_none());
    s.set_ref("busybox", &id).unwrap();
    assert_eq!(s.resolve_ref("busybox"), Some(id.clone()));
    assert_eq!(s.resolve_ref("docker.io/library/busybox:latest"), Some(id.clone())); // canonicalised
    assert!(s.resolve_ref("busybox:other").is_none());
    assert!(s.image("busybox").is_none()); // no rootfs yet
    let dir = format!("{}/images/{}", p.display(), hexid);
    std::fs::create_dir_all(format!("{dir}/rootfs")).unwrap();
    std::fs::write(format!("{dir}/config.json"), br#"{"config":{"Cmd":["sh"],"WorkingDir":"/"}}"#).unwrap();
    let (got, cfg, rootfs) = s.image("busybox").unwrap();
    assert_eq!(got, id);
    assert_eq!(cfg.cmd, ["sh"]);
    assert_eq!(rootfs, format!("{dir}/rootfs\0").into_bytes());
    assert!(ImageId("../x".into()).hex().len() < 64 && s.image_dir(&ImageId("../x".into())).is_err());

    // containers
    let c = s.create_container("c1").unwrap();
    for d in [&c.upper, &c.work, &c.merged] {
        assert!(std::path::Path::new(d).is_dir(), "{d}");
    }
    assert!(s.create_container("c1").is_err());
    for bad in ["", ".", "..", "a/b", "../x", "a\0b"] {
        assert!(s.create_container(bad).is_err(), "{bad:?}");
        assert!(s.delete_container(bad).is_err(), "{bad:?}");
    }
    // populate with awkward content, including a read-only directory tree
    std::fs::create_dir_all(format!("{}/ro/sub", c.upper)).unwrap();
    std::fs::write(format!("{}/ro/sub/f", c.upper), b"x").unwrap();
    std::os::unix::fs::symlink("/", format!("{}/ro/link", c.upper)).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(format!("{}/ro/sub", c.upper), std::fs::Permissions::from_mode(0o500)).unwrap();
    std::fs::set_permissions(format!("{}/ro", c.upper), std::fs::Permissions::from_mode(0o500)).unwrap();
    s.delete_container("c1").unwrap();
    assert!(!std::path::Path::new(&c.root).exists());
    assert!(std::path::Path::new("/").exists()); // the symlink to / was not followed
    s.delete_container("c1").unwrap(); // idempotent
    let _ = std::fs::remove_dir_all(&p);
}

#[test]
fn store_open_is_idempotent_and_requires_absolute_root() {
    let (p, _s) = tmp_store("open");
    let again = Store::open(Some(p.to_str().unwrap())).unwrap();
    assert_eq!(again.root(), p.to_str().unwrap());
    assert!(Store::open(Some("relative/path")).is_err());
    for d in ["blobs/sha256", "images", "refs", "containers"] {
        assert!(p.join(d).is_dir());
    }
    let _ = std::fs::remove_dir_all(&p);
    let _ = Sandbox::new(); // keep `common` used
}
