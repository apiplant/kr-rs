use kr_runtime::offload::{disk_usage, handler, KIND_DISK_USAGE};

#[test]
fn disk_usage_counts_entries_and_allocated_blocks() {
    let d = std::env::temp_dir().join(format!("kr-du-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("a/b")).unwrap();
    std::fs::write(d.join("a/b/f"), vec![1u8; 100_000]).unwrap();
    std::fs::write(d.join("g"), b"x").unwrap();
    std::os::unix::fs::symlink("/", d.join("a/link")).unwrap();
    let root = d.to_str().unwrap();
    let (bytes, inodes, cut) = disk_usage(root, u64::MAX);
    assert!(!cut);
    assert_eq!(inodes, 5); // a, a/b, a/b/f, a/link, g
    assert!(bytes >= 100_000, "{bytes}");
    assert!(disk_usage(root, 2).2, "the bound cuts the walk short");
    assert_eq!(disk_usage("/nonexistent-kr-du", u64::MAX), (0, 0, false));
    // The worker protocol: length-prefixed path in, two u64 out.
    let mut req = (root.len() as u32).to_le_bytes().to_vec();
    req.extend_from_slice(root.as_bytes());
    let out = handler(KIND_DISK_USAGE, &req);
    assert_eq!(out.len(), 16);
    assert_eq!(u64::from_le_bytes(out[8..].try_into().unwrap()), 5);
    std::fs::remove_dir_all(&d).unwrap();
}
