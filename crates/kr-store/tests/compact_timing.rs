//! How long a compaction (snapshot write plus four fsyncs) blocks its caller. Run with
//! `cargo test --release -p kr-store --test compact_timing -- --ignored --nocapture`; the directory
//! is `KR_TEST_DIR` (a real disk) or the system temp directory.
use std::time::Instant;

#[test]
#[ignore]
fn rewrite_log_time() {
    let base = std::env::var("KR_TEST_DIR").unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().into_owned());
    let dir = format!("{base}/kr-compact-{}", std::process::id());
    std::fs::create_dir_all(&dir).unwrap();
    let mut s = kr_store::Store::open(&dir).unwrap();
    let body = vec![b'x'; 3000];
    for i in 0..3000 {
        s.create(&format!("/registry/pods/default/p{i}"), body.clone()).unwrap();
    }
    let t = Instant::now();
    s.rewrite_log().unwrap();
    eprintln!("rewrite_log of {} bytes: {:?}", s.image().len(), t.elapsed());
    let t = Instant::now();
    let img = s.image();
    eprintln!("image() alone: {:?} ({} bytes)", t.elapsed(), img.len());
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}
