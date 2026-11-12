//! Layers unpacked one by one for use as overlayfs lower layers (ADR-056), mounted for real.
//! Needs to run where overlay can be mounted: `tools/test/layers.sh` runs it in `unshare -Urm`.
mod common;
use common::{gzip_stored, Tar};
use kr_runtime::store::cpath;
use kr_runtime::unpack::{unpack_layer_overlay_fd, Limits};
use kr_sys::fs;
use std::process::Command;

fn unpack(dir: &std::path::Path, tar: &Tar) {
    std::fs::create_dir_all(dir).unwrap();
    let gz = gzip_stored(&tar.finish());
    let file = dir.with_extension("tar.gz");
    std::fs::write(&file, &gz).unwrap();
    let root = fs::openat(fs::AT_FDCWD, &cpath(dir.to_str().unwrap()).unwrap(), fs::O_RDONLY | fs::O_DIRECTORY | fs::O_CLOEXEC, 0).unwrap();
    let blob = fs::openat(fs::AT_FDCWD, &cpath(file.to_str().unwrap()).unwrap(), fs::O_RDONLY | fs::O_CLOEXEC, 0).unwrap();
    unpack_layer_overlay_fd(root.raw(), blob.raw(), true, &Limits::default()).unwrap();
}

#[test]
#[ignore]
fn whiteouts_and_opaque_directories_work_as_lower_layers() {
    let base = std::path::PathBuf::from(std::env::var("KR_TEST_DIR").unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().into_owned())).join(format!("krlayers-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let (l1, l2, l3) = (base.join("l1"), base.join("l2"), base.join("l3"));
    let mut t1 = Tar::new();
    t1.dir("a", 0o755).file("a/keep", 0o644, b"base")
        .file("gone", 0o644, b"deleted later")
        .dir("d", 0o755).file("d/old", 0o644, b"old").file("d/old2", 0o644, b"old2")
        .dir("x", 0o755).file("x/y", 0o644, b"y")
        .file("swap", 0o644, b"was a file");
    // Layer 2: deletes `gone`, replaces the contents of `d`, removes `x/y` only, turns `swap` into a directory.
    let mut t2 = Tar::new();
    t2.file(".wh.gone", 0o644, b"").dir("d", 0o755).file("d/.wh..wh..opq", 0o644, b"").file("d/new", 0o644, b"new")
        .dir("x", 0o755).file("x/.wh.y", 0o644, b"").file("x/z", 0o644, b"z")
        .dir("swap", 0o755).file("swap/inner", 0o644, b"inner");
    // Layer 3: brings `gone` back (a whiteout in a lower layer does not outlive it).
    let mut t3 = Tar::new();
    t3.file("gone", 0o644, b"back");
    unpack(&l1, &t1);
    unpack(&l2, &t2);
    unpack(&l3, &t3);
    // The layer directory itself holds only its own content.
    assert!(!l2.join("a").exists(), "layer 2 does not contain layer 1's files");
    let meta = std::fs::symlink_metadata(l2.join("gone")).unwrap();
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    assert!(meta.file_type().is_char_device() && meta.rdev() == 0, "a whiteout is the 0:0 device");
    let (up, work, merged) = (base.join("up"), base.join("work"), base.join("merged"));
    for d in [&up, &work, &merged] {
        std::fs::create_dir_all(d).unwrap();
    }
    let mount = |lower: String| {
        let o = format!("lowerdir={lower},upperdir={},workdir={},userxattr", up.display(), work.display());
        let out = Command::new("mount").args(["-t", "overlay", "overlay", "-o", &o, merged.to_str().unwrap()]).output().unwrap();
        assert!(out.status.success(), "mount: {}", String::from_utf8_lossy(&out.stderr));
    };
    mount(format!("{}:{}", l2.display(), l1.display()));
    let ls = |p: &str| {
        let mut v: Vec<String> = std::fs::read_dir(merged.join(p)).map(|r| r.map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
        v.sort();
        v
    };
    assert_eq!(ls(""), ["a", "d", "swap", "x"], "`gone` is deleted by the whiteout");
    assert_eq!(ls("d"), ["new"], "the opaque directory hides the lower content");
    assert_eq!(ls("x"), ["z"], "a whiteout hides one lower entry only");
    assert_eq!(ls("swap"), ["inner"], "a directory replaces a lower file");
    assert_eq!(std::fs::read(merged.join("a/keep")).unwrap(), b"base");
    let st = Command::new("umount").arg(merged.to_str().unwrap()).status().unwrap();
    assert!(st.success());
    // With the third layer on top the file is back.
    mount(format!("{}:{}:{}", l3.display(), l2.display(), l1.display()));
    assert_eq!(std::fs::read(merged.join("gone")).unwrap(), b"back");
    let _ = Command::new("umount").arg(merged.to_str().unwrap()).status();
    let _ = std::fs::remove_dir_all(&base);
}
