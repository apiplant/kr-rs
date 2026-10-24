mod common;
use common::*;
use kr_runtime::store::Error;
use kr_runtime::unpack::Limits;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

fn read(p: std::path::PathBuf) -> String {
    String::from_utf8(std::fs::read(p).unwrap()).unwrap()
}

#[test]
fn basic_tree_modes_mtime_links() {
    let sb = Sandbox::new();
    let mut t = Tar::new();
    t.dir("", 0o755); // "./"
    t.dir("bin", 0o755);
    t.file("bin/busybox", 0o755, b"#!bin");
    t.hardlink("bin/sh", "bin/busybox");
    t.symlink("bin/ls", "busybox");
    t.symlink("abs", "/bin/busybox");
    t.dir("ro", 0o555);
    t.file("ro/f", 0o444, b"ro");
    t.file("suid", 0o4755, b"x");
    t.node("dev/null", b'3');
    t.node("dev/sda", b'4');
    t.node("fifo", b'6');
    t.file("empty", 0o600, b"");
    let st = sb.unpack(&t).unwrap();
    assert_eq!(st.skipped_devices, 2);
    assert_eq!(st.hardlinks, 1);
    assert_eq!(st.symlinks, 2);
    assert_eq!(st.fifos, 1);
    let r = &sb.root;
    assert_eq!(read(r.join("bin/busybox")), "#!bin");
    assert_eq!(std::fs::metadata(r.join("bin/busybox")).unwrap().permissions().mode() & 0o7777, 0o755);
    assert_eq!(std::fs::metadata(r.join("bin/busybox")).unwrap().mtime(), 1_600_000_000);
    assert_eq!(std::fs::metadata(r.join("bin")).unwrap().mtime(), 1_600_000_000);
    assert_eq!(std::fs::metadata(r.join("bin/sh")).unwrap().ino(), std::fs::metadata(r.join("bin/busybox")).unwrap().ino());
    assert_eq!(std::fs::read_link(r.join("bin/ls")).unwrap().to_str().unwrap(), "busybox");
    assert_eq!(std::fs::read_link(r.join("abs")).unwrap().to_str().unwrap(), "/bin/busybox");
    assert!(!r.join("dev/null").exists());
    assert!(std::fs::metadata(r.join("fifo")).unwrap().file_type().is_fifo());
    assert!(std::fs::metadata(r.join("empty")).unwrap().len() == 0);
    // rootless: setuid stripped; owner keeps rwx on directories
    if kr_sys::fs::getuid() != 0 {
        assert_eq!(std::fs::metadata(r.join("suid")).unwrap().permissions().mode() & 0o7000, 0);
        assert_eq!(std::fs::metadata(r.join("ro")).unwrap().permissions().mode() & 0o700, 0o700);
    }
}

#[test]
fn dotdot_escape_is_rejected() {
    for bad in ["../evil", "a/../../evil", "../../../../etc/passwd"] {
        let sb = Sandbox::new();
        let before = sb.outside_snapshot();
        let mut t = Tar::new();
        t.file(bad, 0o644, b"pwn");
        let e = sb.unpack(&t).unwrap_err();
        assert!(matches!(e, Error::Unsafe(_)), "{bad}: {e:?}");
        assert_eq!(sb.outside_snapshot(), before, "{bad}");
        assert!(std::fs::read_dir(&sb.root).unwrap().next().is_none());
    }
}

#[test]
fn absolute_path_is_rejected() {
    let sb = Sandbox::new();
    let before = sb.outside_snapshot();
    let mut t = Tar::new();
    t.file(&format!("{}/pwned", sb.outside_abs()), 0o644, b"pwn");
    assert!(sb.unpack(&t).is_err());
    assert_eq!(sb.outside_snapshot(), before);
}

#[test]
fn absolute_symlink_then_write_through_it_is_contained() {
    // ln -s <outside> x; x/pwned: the symlink resolves *inside* the root
    let sb = Sandbox::new();
    let before = sb.outside_snapshot();
    let mut t = Tar::new();
    sb.mirror_outside(&mut t);
    t.symlink("x", &sb.outside_abs());
    t.file("x/pwned", 0o644, b"pwn");
    sb.unpack(&t).unwrap();
    assert_eq!(sb.outside_snapshot(), before);
    let inside = sb.root.join(sb.outside_abs().trim_start_matches('/')).join("pwned");
    assert_eq!(read(inside), "pwn");
}

#[test]
fn absolute_symlink_to_missing_dir_is_rejected() {
    // the classic `ln -s /etc x; x/passwd` with no /etc in the image
    let sb = Sandbox::new();
    let before = sb.outside_snapshot();
    let mut t = Tar::new();
    t.symlink("x", "/etc");
    t.file("x/passwd", 0o644, b"pwn");
    assert!(sb.unpack(&t).is_err());
    assert_eq!(sb.outside_snapshot(), before);
    assert!(!sb.root.join("etc").exists());
}

#[test]
fn absolute_symlink_to_etc_writes_inside_root_only() {
    let sb = Sandbox::new();
    let mut t = Tar::new();
    t.dir("etc", 0o755);
    t.symlink("x", "/etc");
    t.file("x/passwd", 0o644, b"pwn");
    sb.unpack(&t).unwrap();
    assert_eq!(read(sb.root.join("etc/passwd")), "pwn");
    assert_ne!(std::fs::read("/etc/passwd").unwrap_or_default(), b"pwn");
}

#[test]
fn dotdot_symlink_chains_are_clamped_to_the_root() {
    let sb = Sandbox::new();
    let before = sb.outside_snapshot();
    let mut t = Tar::new();
    t.symlink("a", "..");
    t.symlink("b", "a/..");
    t.symlink("c", "../../../../../..");
    t.symlink("d", "a/a/b/c/../..");
    t.file("a/evil1", 0o644, b"1");
    t.file("b/evil2", 0o644, b"2");
    t.file("c/evil3", 0o644, b"3");
    t.file("d/evil4", 0o644, b"4");
    t.file("a/a/a/b/c/d/evil5", 0o644, b"5");
    sb.unpack(&t).unwrap();
    assert_eq!(sb.outside_snapshot(), before);
    for (i, n) in ["evil1", "evil2", "evil3", "evil4", "evil5"].iter().enumerate() {
        assert_eq!(read(sb.root.join(n)), (i + 1).to_string());
    }
}

#[test]
fn hardlink_to_outside_is_rejected() {
    let sb = Sandbox::new();
    let before = sb.outside_snapshot();
    let secret_abs = format!("{}/secret", sb.outside_abs());
    let rel = "../outside/secret".to_string();
    let rel_deep = "a/../../outside/secret".to_string();
    let via_symlink = "o/secret".to_string();
    for (i, target) in [secret_abs, rel, rel_deep, via_symlink].iter().enumerate() {
        let mut t = Tar::new();
        if i == 3 {
            t.symlink("o", &sb.outside_abs());
        }
        t.hardlink("link", target);
        let r = sb.unpack(&t);
        assert!(r.is_err(), "{target}: {r:?}");
        assert_eq!(sb.outside_snapshot(), before, "{target}");
        assert_eq!(std::fs::metadata(sb.outside.join("secret")).unwrap().nlink(), 1, "{target}");
        assert!(!sb.root.join("link").exists());
    }
}

#[test]
fn file_replacing_symlink_does_not_follow_it() {
    let sb = Sandbox::new();
    let before = sb.outside_snapshot();
    let mut t = Tar::new();
    t.symlink("s", &format!("{}/secret", sb.outside_abs()));
    t.file("s", 0o644, b"pwn");
    t.symlink("s2", "../outside/secret");
    t.file("s2", 0o644, b"pwn2");
    sb.unpack(&t).unwrap();
    assert_eq!(sb.outside_snapshot(), before);
    assert_eq!(read(sb.outside.join("secret")), "top secret");
    let md = std::fs::symlink_metadata(sb.root.join("s")).unwrap();
    assert!(md.is_file());
    assert_eq!(read(sb.root.join("s")), "pwn");
    assert_eq!(read(sb.root.join("s2")), "pwn2");
}

#[test]
fn file_replacing_symlink_across_layers() {
    let sb = Sandbox::new();
    let before = sb.outside_snapshot();
    let mut l1 = Tar::new();
    l1.symlink("s", &format!("{}/secret", sb.outside_abs()));
    sb.unpack(&l1).unwrap();
    let mut l2 = Tar::new();
    l2.file("s", 0o644, b"pwn");
    sb.unpack(&l2).unwrap();
    assert_eq!(sb.outside_snapshot(), before);
    assert!(std::fs::symlink_metadata(sb.root.join("s")).unwrap().is_file());
}

#[test]
fn dir_symlink_file_replace_each_other() {
    let sb = Sandbox::new();
    let before = sb.outside_snapshot();
    let mut l1 = Tar::new();
    l1.symlink("d", &sb.outside_abs());
    l1.dir("e", 0o755).dir("e/sub", 0o755).file("e/sub/f", 0o644, b"f");
    l1.file("g", 0o644, b"g");
    sb.unpack(&l1).unwrap();
    let mut l2 = Tar::new();
    l2.dir("d", 0o755).file("d/f", 0o644, b"in d"); // dir replaces the symlink
    l2.symlink("e", "g"); // symlink replaces a populated dir
    l2.dir("g", 0o755); // dir replaces a file
    sb.unpack(&l2).unwrap();
    assert_eq!(sb.outside_snapshot(), before);
    assert!(std::fs::symlink_metadata(sb.root.join("d")).unwrap().is_dir());
    assert_eq!(read(sb.root.join("d/f")), "in d");
    assert!(std::fs::symlink_metadata(sb.root.join("e")).unwrap().file_type().is_symlink());
    assert!(std::fs::symlink_metadata(sb.root.join("g")).unwrap().is_dir());
}

#[test]
fn malicious_whiteouts_stay_inside() {
    let sb = Sandbox::new();
    let before = sb.outside_snapshot();
    let mut t = Tar::new();
    t.symlink("x", &sb.outside_abs());
    t.file(".wh...", 0o644, b""); // would be "remove .."
    t.file(".wh..", 0o644, b"");
    t.file("x/.wh.secret", 0o644, b""); // through the symlink -> inside root
    sb.unpack(&t).unwrap();
    assert_eq!(sb.outside_snapshot(), before);
    assert!(sb.root.exists());
}

#[test]
fn whiteouts_and_opaque_dirs_across_two_layers() {
    let sb = Sandbox::new();
    let mut l1 = Tar::new();
    l1.dir("d", 0o755).file("d/a", 0o644, b"a").file("d/b", 0o644, b"b");
    l1.dir("e", 0o755).file("e/x", 0o644, b"x").dir("e/sub", 0o755).file("e/sub/deep", 0o644, b"d");
    l1.file("f", 0o644, b"f");
    l1.dir("tree", 0o755).dir("tree/n", 0o755).file("tree/n/m", 0o644, b"m");
    l1.dir("o2", 0o755).file("o2/old", 0o644, b"old");
    l1.file("rootold", 0o644, b"r");
    sb.unpack(&l1).unwrap();

    let mut l2 = Tar::new();
    l2.file("d/.wh.a", 0o644, b"");
    l2.file("e/y", 0o644, b"y"); // before the opaque marker: must survive it
    l2.file("e/.wh..wh..opq", 0o644, b"");
    l2.file("e/z", 0o644, b"z"); // after: survives too
    l2.dir("e/newdir", 0o755);
    l2.file(".wh.f", 0o644, b"");
    l2.file(".wh.tree", 0o644, b"");
    l2.file(".wh..wh.plnk", 0o644, b"");
    l2.file("o2/new", 0o644, b"new");
    l2.file("o2/.wh..wh..opq", 0o644, b"");
    l2.file(".wh.nonexistent", 0o644, b""); // harmless
    l2.file("missingdir/.wh.x", 0o644, b""); // parent missing: harmless
    let st = sb.unpack(&l2).unwrap();
    assert_eq!(st.skipped_reserved, 1);

    let r = &sb.root;
    assert!(!r.join("d/a").exists());
    assert_eq!(read(r.join("d/b")), "b");
    assert!(!r.join("e/x").exists());
    assert!(!r.join("e/sub").exists());
    assert_eq!(read(r.join("e/y")), "y");
    assert_eq!(read(r.join("e/z")), "z");
    assert!(r.join("e/newdir").is_dir());
    assert!(!r.join("f").exists());
    assert!(!r.join("tree").exists());
    assert!(!r.join("o2/old").exists());
    assert_eq!(read(r.join("o2/new")), "new");
    assert_eq!(read(r.join("rootold")), "r");
    let mut names: Vec<_> = walkdir(r);
    names.sort();
    assert!(names.iter().all(|n| !n.contains(".wh.")), "{names:?}");
}

#[test]
fn root_opaque_marker_clears_lower_layers() {
    let sb = Sandbox::new();
    let mut l1 = Tar::new();
    l1.file("old", 0o644, b"o").dir("dir", 0o755).file("dir/f", 0o644, b"f");
    sb.unpack(&l1).unwrap();
    let mut l2 = Tar::new();
    l2.file(".wh..wh..opq", 0o644, b"").file("new/inner", 0o644, b"n");
    sb.unpack(&l2).unwrap();
    assert!(!sb.root.join("old").exists() && !sb.root.join("dir").exists());
    assert_eq!(read(sb.root.join("new/inner")), "n");
}

#[test]
fn whiteout_removes_unwritable_directories() {
    let sb = Sandbox::new();
    let mut l1 = Tar::new();
    l1.dir("go", 0o555).dir("go/pkg", 0o555).file("go/pkg/f", 0o444, b"f");
    sb.unpack(&l1).unwrap();
    let mut l2 = Tar::new();
    l2.file(".wh.go", 0o644, b"");
    sb.unpack(&l2).unwrap();
    assert!(!sb.root.join("go").exists());
}

fn walkdir(p: &std::path::Path) -> Vec<String> {
    let mut v = vec![];
    for e in std::fs::read_dir(p).unwrap().flatten() {
        v.push(e.file_name().to_string_lossy().into_owned());
        if e.file_type().unwrap().is_dir() {
            v.extend(walkdir(&e.path()));
        }
    }
    v
}

#[test]
fn limit_entries() {
    let sb = Sandbox::new();
    let mut t = Tar::new();
    for i in 0..10 {
        t.file(&format!("f{i}"), 0o644, b"x");
    }
    let lim = Limits { max_entries: 5, ..Limits::default() };
    assert!(matches!(sb.unpack_with(&t, &lim), Err(Error::Limit(_))));
    let ok = Limits { max_entries: 10, ..Limits::default() };
    sb.unpack_with(&t, &ok).unwrap();
}

#[test]
fn limit_uncompressed_bytes_stored() {
    let sb = Sandbox::new();
    let mut t = Tar::new();
    t.file("big", 0o644, &vec![7u8; 2 << 20]);
    let lim = Limits { max_bytes: 1 << 20, ..Limits::default() };
    assert!(matches!(sb.unpack_with(&t, &lim), Err(Error::Limit(_))));
}

#[test]
fn limit_gzip_bomb() {
    let sb = Sandbox::new();
    let mut t = Tar::new();
    t.file("zeros", 0o644, &vec![0u8; 64 << 20]);
    let Some(gz) = gzip_system(&t.finish()) else {
        eprintln!("no gzip binary; skipping");
        return;
    };
    assert!(gz.len() < 1 << 20, "bomb should compress well: {}", gz.len());
    let lim = Limits { max_bytes: 8 << 20, ..Limits::default() };
    let e = sb.unpack_gz(&gz, &lim).unwrap_err();
    assert!(matches!(e, Error::Limit(_)), "{e:?}");
    // under the limit the same layer is fine, and the real-gzip path works end to end
    let st = sb.unpack_gz(&gz, &Limits::default()).unwrap();
    assert_eq!(st.files, 1);
    assert_eq!(std::fs::metadata(sb.root.join("zeros")).unwrap().len(), 64 << 20);
}

#[test]
fn limit_path_length() {
    let sb = Sandbox::new();
    let long = "a/".repeat(2600) + "f"; // > 4096 bytes
    let mut t = Tar::new();
    t.file(&long, 0o644, b"x");
    assert!(matches!(sb.unpack(&t), Err(Error::Limit(_))));
    let mut t = Tar::new();
    t.file("abcdefghijklmnopqrstuvwxyz", 0o644, b"x");
    let lim = Limits { max_path: 20, ..Limits::default() };
    assert!(matches!(sb.unpack_with(&t, &lim), Err(Error::Limit(_))));
}

#[test]
fn deep_but_legal_paths_work() {
    let sb = Sandbox::new();
    let mut t = Tar::new();
    let mut p = String::new();
    for i in 0..100 {
        p.push_str(&format!("d{i}/"));
        t.dir(p.trim_end_matches('/'), 0o755);
    }
    t.file(&format!("{p}leaf"), 0o644, b"leaf");
    sb.unpack(&t).unwrap();
    assert_eq!(read(sb.root.join(format!("{p}leaf"))), "leaf");
    // missing parents are created implicitly
    let mut t = Tar::new();
    t.file("implicit/parents/here", 0o644, b"i");
    sb.unpack(&t).unwrap();
    assert_eq!(read(sb.root.join("implicit/parents/here")), "i");
}

#[test]
fn corrupt_and_truncated_streams_fail() {
    let sb = Sandbox::new();
    let mut t = Tar::new();
    t.file("f", 0o644, &vec![1u8; 5000]);
    let gz = gzip_stored(&t.finish());
    // truncated
    let e = sb.unpack_gz(&gz[..gz.len() - 20], &Limits::default());
    assert!(e.is_err());
    // bad crc
    let mut bad = gz.clone();
    let n = bad.len();
    bad[n - 8] ^= 0xff;
    assert!(sb.unpack_gz(&bad, &Limits::default()).is_err());
    // tar cut in the middle of file data
    let mut cut = t.finish();
    cut.truncate(700);
    assert!(sb.unpack_gz(&gzip_stored(&cut), &Limits::default()).is_err());
    // not gzip at all
    assert!(sb.unpack_gz(b"definitely not gzip", &Limits::default()).is_err());
}

#[test]
fn symlink_cannot_be_used_to_chmod_outside() {
    // a dir entry whose path goes through a symlink to outside must not touch outside modes
    let sb = Sandbox::new();
    let before = sb.outside_snapshot();
    let mode_before = std::fs::metadata(&sb.outside).unwrap().permissions().mode();
    let mut t = Tar::new();
    t.symlink("o", "../outside");
    t.dir("o", 0o700); // replaces the symlink instead of chmod'ing through it
    t.dir("p", 0o755);
    t.symlink("p/q", "../../outside");
    t.dir("p/q/", 0o700);
    let _ = sb.unpack(&t);
    assert_eq!(std::fs::metadata(&sb.outside).unwrap().permissions().mode(), mode_before);
    assert_eq!(sb.outside_snapshot(), before);
}

#[test]
fn stats_carry_the_sha256_of_the_uncompressed_tar() {
    use kr_net::sha256::{hex, sha256};
    let sb = Sandbox::new();
    let mut t = Tar::new();
    t.file("a", 0o644, b"hello");
    let raw = t.finish();
    let st = sb.unpack_gz(&gzip_stored(&raw), &Limits::default()).unwrap();
    assert_eq!(st.diff_id, hex(&sha256(&raw)));
}

#[test]
fn image_wide_byte_cap_is_a_separate_field() {
    let l = Limits::default();
    assert_eq!(l.max_image_bytes, 8 << 30);
}
