mod common;
use common::*;
use kr_net::registry::Digest;
use kr_net::sha256::{hex, sha256};
use kr_rt::exec::block_on;
use kr_runtime::pull::pull;
use kr_runtime::store::{Error, Store};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

static LOCK: Mutex<()> = Mutex::new(());

fn dg(b: &[u8]) -> String {
    format!("sha256:{}", hex(&sha256(b)))
}

struct Fixture {
    blobs: HashMap<String, Vec<u8>>,
    manifest: Vec<u8>,
    layers: Vec<Vec<u8>>,
    config: Vec<u8>,
}

fn fixture() -> Fixture {
    fixture_with(false)
}

fn fixture_with(bad_diff: bool) -> Fixture {
    let mut l1 = Tar::new();
    l1.dir("bin", 0o755).file("bin/busybox", 0o755, b"ELF").hardlink("bin/sh", "bin/busybox");
    l1.dir("etc", 0o755).file("etc/old", 0o644, b"old").file("etc/keep", 0o644, b"keep");
    let mut l2 = Tar::new();
    l2.file("etc/.wh.old", 0o644, b"").file("etc/new", 0o644, b"new");
    let (t1, t2) = (l1.finish(), l2.finish());
    let layers = vec![gzip_stored(&t1), gzip_stored(&t2)];
    let d2 = if bad_diff { hex(&sha256(b"wrong")) } else { hex(&sha256(&t2)) };
    let config = format!(
        r#"{{"architecture":"amd64","os":"linux","config":{{"Env":["A=1"],"Cmd":["/bin/sh"],"WorkingDir":"/"}},"rootfs":{{"type":"layers","diff_ids":["sha256:{}","sha256:{}"]}}}}"#,
        hex(&sha256(&t1)),
        d2
    )
    .into_bytes();
    let manifest = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{{"mediaType":"application/vnd.docker.container.image.v1+json","digest":"{}","size":{}}},"layers":[{}]}}"#,
        dg(&config),
        config.len(),
        layers
            .iter()
            .map(|l| format!(r#"{{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","digest":"{}","size":{}}}"#, dg(l), l.len()))
            .collect::<Vec<_>>()
            .join(",")
    )
    .into_bytes();
    let mut blobs = HashMap::new();
    blobs.insert(dg(&config), config.clone());
    for l in &layers {
        blobs.insert(dg(l), l.clone());
    }
    Fixture { blobs, manifest, layers, config }
}

struct Server {
    port: u16,
    log: Arc<Mutex<Vec<String>>>,
}

fn serve(f: Arc<Fixture>, corrupt: Option<String>) -> Server {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let log = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let (f, log, corrupt) = (f.clone(), log2.clone(), corrupt.clone());
            std::thread::spawn(move || {
                s.set_read_timeout(Some(Duration::from_secs(10))).ok();
                loop {
                    let mut head = Vec::new();
                    let mut b = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        match s.read(&mut b) {
                            Ok(1) => head.push(b[0]),
                            _ => return,
                        }
                    }
                    let text = String::from_utf8_lossy(&head).into_owned();
                    let path = text.split(' ').nth(1).unwrap_or("").to_string();
                    log.lock().unwrap().push(path.clone());
                    let (status, ct, body): (&str, &str, Vec<u8>) = if path == "/v2/" {
                        ("200 OK", "application/json", b"{}".to_vec())
                    } else if path.starts_with("/v2/test/app/manifests/") {
                        ("200 OK", "application/vnd.docker.distribution.manifest.v2+json", f.manifest.clone())
                    } else if let Some(d) = path.strip_prefix("/v2/test/app/blobs/") {
                        match f.blobs.get(d) {
                            Some(b) => {
                                let mut b = b.clone();
                                if corrupt.as_deref() == Some(d) {
                                    let n = b.len() / 2;
                                    b[n] ^= 0xff;
                                }
                                ("200 OK", "application/octet-stream", b)
                            }
                            None => ("404 Not Found", "text/plain", vec![]),
                        }
                    } else {
                        ("404 Not Found", "text/plain", vec![])
                    };
                    let mut out = format!("HTTP/1.1 {status}\r\nContent-Type: {ct}\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
                    out.extend_from_slice(&body);
                    if s.write_all(&out).is_err() {
                        return;
                    }
                }
            });
        }
    });
    Server { port, log }
}

fn tmp_store(name: &str) -> (std::path::PathBuf, Store) {
    let p = std::env::temp_dir().join(format!("krrt-pull-{}-{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&p);
    let s = Store::open(Some(p.to_str().unwrap())).unwrap();
    (p, s)
}

fn run_pull(s: &Store, r: &str) -> Result<kr_runtime::store::ImageId, Error> {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (s, r) = (s.clone(), r.to_string());
    block_on(async move { pull(&s, &r).await })
}

#[test]
fn pull_from_fake_registry_resume_and_idempotence() {
    let f = Arc::new(fixture());
    let srv = serve(f.clone(), None);
    let (p, store) = tmp_store("ok");
    let r = format!("127.0.0.1:{}/test/app:latest", srv.port);

    let id = run_pull(&store, &r).unwrap();
    assert_eq!(id.digest(), dg(&f.config));
    let rootfs = p.join(format!("images/{}/rootfs", id.hex()));
    assert_eq!(std::fs::read(rootfs.join("bin/busybox")).unwrap(), b"ELF");
    assert_eq!(std::fs::read(rootfs.join("etc/keep")).unwrap(), b"keep");
    assert_eq!(std::fs::read(rootfs.join("etc/new")).unwrap(), b"new");
    assert!(!rootfs.join("etc/old").exists());
    assert!(!p.join(format!("images/{}/rootfs.tmp", id.hex())).exists());
    assert!(p.join(format!("images/{}/manifest.json", id.hex())).is_file());
    assert_eq!(std::fs::read(p.join(format!("images/{}/config.json", id.hex()))).unwrap(), f.config);
    for l in &f.layers {
        let d = Digest::parse(&dg(l)).unwrap();
        assert!(store.verify_blob(&d).unwrap());
    }
    let (got, cfg, path) = store.image(&r).unwrap();
    assert_eq!(got, id);
    assert_eq!((cfg.cmd.as_slice(), cfg.env.as_slice()), (["/bin/sh".to_string()].as_slice(), ["A=1".to_string()].as_slice()));
    assert_eq!(path, format!("{}\0", rootfs.display()).into_bytes());

    // second pull is a no-op: no network traffic at all
    let n = srv.log.lock().unwrap().len();
    assert_eq!(run_pull(&store, &r).unwrap(), id);
    assert_eq!(srv.log.lock().unwrap().len(), n);

    // same config under a different ref: manifest fetched, no blobs, ref added
    let r2 = format!("127.0.0.1:{}/test/app:other", srv.port);
    assert_eq!(run_pull(&store, &r2).unwrap(), id);
    assert!(srv.log.lock().unwrap()[n..].iter().all(|l| l.contains("/manifests/") || l == "/v2/"));
    assert!(store.image(&r2).is_some());
    let _ = std::fs::remove_dir_all(&p);
}

#[test]
fn pull_resumes_from_existing_blobs_and_refetches_corrupt_ones() {
    let f = Arc::new(fixture());
    let srv = serve(f.clone(), None);
    let (p, store) = tmp_store("resume");
    let r = format!("127.0.0.1:{}/test/app:latest", srv.port);
    // layer 0 already present and valid; layer 1 present but corrupt
    store.put_blob(&Digest::parse(&dg(&f.layers[0])).unwrap(), &f.layers[0]).unwrap();
    std::fs::write(store.blob_path(&Digest::parse(&dg(&f.layers[1])).unwrap()).unwrap(), b"junk").unwrap();
    run_pull(&store, &r).unwrap();
    let log = srv.log.lock().unwrap().clone();
    assert!(!log.iter().any(|l| l.ends_with(&dg(&f.layers[0]))), "{log:?}");
    assert!(log.iter().any(|l| l.ends_with(&dg(&f.layers[1]))), "{log:?}");
    let _ = std::fs::remove_dir_all(&p);
}

#[test]
fn pull_rejects_corrupt_blob_and_leaves_no_image() {
    let f = Arc::new(fixture());
    let bad = dg(&f.layers[1]);
    let srv = serve(f.clone(), Some(bad.clone()));
    let (p, store) = tmp_store("corrupt");
    let r = format!("127.0.0.1:{}/test/app:latest", srv.port);
    let e = run_pull(&store, &r).unwrap_err();
    assert_eq!(e, Error::Net(kr_net::Error::DigestMismatch));
    assert!(store.image(&r).is_none());
    assert!(!store.has_blob(&Digest::parse(&bad).unwrap()));
    let leftovers: Vec<_> = std::fs::read_dir(p.join("blobs/sha256")).unwrap().flatten().map(|e| e.file_name()).collect();
    assert!(leftovers.iter().all(|n| !n.to_string_lossy().starts_with('.')), "{leftovers:?}");
    let imgs: Vec<_> = std::fs::read_dir(p.join("images")).unwrap().flatten().collect();
    assert!(imgs.iter().all(|e| !e.path().join("rootfs").exists()), "{imgs:?}");
    let _ = std::fs::remove_dir_all(&p);
}

#[test]
fn pull_rejects_diff_id_mismatch_and_leaves_no_rootfs() {
    let f = Arc::new(fixture_with(true));
    let srv = serve(f.clone(), None);
    let (p, store) = tmp_store("diffid");
    let r = format!("127.0.0.1:{}/test/app:latest", srv.port);
    let e = run_pull(&store, &r).unwrap_err();
    assert!(matches!(e, Error::Image(m) if m.contains("diff_id")), "{e:?}");
    assert!(store.image(&r).is_none());
    let imgs: Vec<_> = std::fs::read_dir(p.join("images")).unwrap().flatten().collect();
    assert!(imgs.iter().all(|e| !e.path().join("rootfs").exists() && !e.path().join("rootfs.tmp").exists()), "{imgs:?}");
    let _ = std::fs::remove_dir_all(&p);
}

// ---------- real registry:2 through docker (ignored) ----------

fn ok(tool: &str, args: &[&str]) -> bool {
    Command::new(tool).args(args).output().is_ok_and(|o| {
        if !o.status.success() {
            eprintln!("{tool} {args:?}: {}", String::from_utf8_lossy(&o.stderr));
        }
        o.status.success()
    })
}

struct Cleanup(&'static str);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", self.0]).output();
    }
}

#[test]
#[ignore = "needs docker + network (skips when unavailable)"]
fn e2e_pull_busybox_from_local_registry() {
    if !Command::new("docker").arg("--version").output().is_ok_and(|o| o.status.success()) {
        eprintln!("no docker; skipping");
        return;
    }
    const NAME: &str = "krrt-test-registry";
    let _ = Command::new("docker").args(["rm", "-f", NAME]).output();
    if !ok("docker", &["run", "-d", "--rm", "-p", "127.0.0.1:5001:5000", "--name", NAME, "registry:2"]) {
        eprintln!("cannot start registry:2; skipping");
        return;
    }
    let _c = Cleanup(NAME);
    let up = (0..100).any(|_| {
        std::thread::sleep(Duration::from_millis(200));
        TcpStream::connect("127.0.0.1:5001").is_ok()
    });
    assert!(up, "registry did not come up");
    if !ok("docker", &["pull", "busybox"]) {
        eprintln!("cannot pull busybox (offline?); skipping");
        return;
    }
    let target = "localhost:5001/busybox:krrt";
    assert!(ok("docker", &["tag", "busybox", target]));
    assert!(ok("docker", &["push", target]));

    let (p, store) = tmp_store("e2e");
    let id = run_pull(&store, target).unwrap();
    let bb = p.join(format!("images/{}/rootfs/bin/busybox", id.hex()));
    let md = std::fs::metadata(&bb).unwrap();
    assert!(md.is_file() && md.permissions().mode() & 0o111 != 0, "{bb:?}");
    let (_, cfg, rootfs) = store.image(target).unwrap();
    assert!(!cfg.cmd.is_empty() || !cfg.entrypoint.is_empty());
    assert!(rootfs.ends_with(b"/rootfs\0"));
    // busybox applets are hardlinks/symlinks to it
    assert!(p.join(format!("images/{}/rootfs/bin/sh", id.hex())).exists());
    eprintln!("pulled busybox: {} config cmd {:?}", id, cfg.cmd);
    let _ = std::fs::remove_dir_all(&p);
}
