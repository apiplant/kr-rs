mod common;
use common::*;
use kr_archive::tar::*;
use kr_archive::Error;
use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
struct Rec {
    e: Entry,
    data: Vec<u8>,
}

fn read_tar(data: &[u8], mode: usize, seed: u64) -> Result<Vec<Rec>, Error> {
    let mut rng = Rng(seed);
    let mut r = TarReader::new();
    let mut recs: Vec<Rec> = Vec::new();
    for c in chunks(data, mode, &mut rng) {
        r.feed(c, &mut |ev| {
            match ev {
                Event::Entry(e) => recs.push(Rec { e: e.clone(), data: vec![] }),
                Event::Data(d) => recs.last_mut().unwrap().data.extend_from_slice(d),
                Event::End => {}
            }
            Ok::<(), ()>(())
        })
        .map_err(|e| e.erase())?;
    }
    r.finish()?;
    Ok(recs)
}

fn norm(p: &str) -> String {
    sanitize(p).unwrap().into_string()
}

/// Build a fixture tree; returns (root, names of interesting files).
fn make_tree(name: &str) -> std::path::PathBuf {
    let root = scratch(name);
    let t = root.join("tree");
    let mut rng = Rng(31337);
    std::fs::create_dir_all(t.join("etc")).unwrap();
    std::fs::create_dir_all(t.join("usr/bin")).unwrap();
    std::fs::write(t.join("etc/hostname"), b"node-1\n").unwrap();
    std::fs::write(t.join("etc/empty"), b"").unwrap();
    std::fs::write(t.join("usr/bin/big"), mixed(&mut rng, 300_000)).unwrap();
    std::fs::write(t.join("usr/bin/exact512"), rng.bytes(512)).unwrap();
    std::fs::write(t.join("usr/bin/exact1024"), rng.bytes(1024)).unwrap();
    std::fs::set_permissions(t.join("usr/bin/big"), std::fs::Permissions::from_mode(0o4755)).unwrap();
    // Long names (>100, >255 total).
    let long_dir = format!("{}/{}", "d".repeat(90), "e".repeat(90));
    std::fs::create_dir_all(t.join(&long_dir)).unwrap();
    let long_file = format!("{}/{}", long_dir, "f".repeat(120));
    std::fs::write(t.join(&long_file), b"long name contents").unwrap();
    // Name that fits ustar with prefix split (130 chars).
    let mid = format!("{}/{}", "m".repeat(70), "n".repeat(60));
    std::fs::create_dir_all(t.join("mid")).unwrap();
    std::fs::write(t.join("mid").join(mid.replace('/', "_")), b"mid").unwrap();
    // Symlinks (relative, absolute, long target) and hardlink.
    std::os::unix::fs::symlink("../etc/hostname", t.join("usr/bin/link")).unwrap();
    std::os::unix::fs::symlink("/abs/target", t.join("abs")).unwrap();
    let long_target = "t".repeat(180);
    std::os::unix::fs::symlink(&long_target, t.join("longlink")).unwrap();
    std::fs::hard_link(t.join("etc/hostname"), t.join("etc/hostname.hard")).unwrap();
    run("mkfifo", &[t.join("pipe").to_str().unwrap()]);
    // Non-ASCII name.
    std::fs::write(t.join("caf\u{e9}-\u{1f600}.txt"), b"utf8").unwrap();
    // xattrs.
    let xa = cmd_ok("setfattr", &["-n", "user.test", "-v", "hello", t.join("etc/hostname").to_str().unwrap()]);
    if xa {
        cmd_ok("setfattr", &["-n", "user.bin", "-v", "0x00ff10", t.join("etc/empty").to_str().unwrap()]);
    }
    std::fs::File::create(root.join("has_xattr")).map(|_| ()).ok();
    if !xa {
        std::fs::remove_file(root.join("has_xattr")).ok();
    }
    root
}

fn cmd_ok(cmd: &str, args: &[&str]) -> bool {
    std::process::Command::new(cmd).args(args).status().map(|s| s.success()).unwrap_or(false)
}

fn walk(base: &Path, rel: &str, out: &mut BTreeMap<String, std::fs::Metadata>) {
    let dir = if rel.is_empty() { base.to_path_buf() } else { base.join(rel) };
    for ent in std::fs::read_dir(dir).unwrap() {
        let ent = ent.unwrap();
        let r = if rel.is_empty() {
            ent.file_name().into_string().unwrap()
        } else {
            format!("{}/{}", rel, ent.file_name().into_string().unwrap())
        };
        let md = std::fs::symlink_metadata(ent.path()).unwrap();
        let is_dir = md.is_dir();
        out.insert(r.clone(), md);
        if is_dir {
            walk(base, &r, out);
        }
    }
}

fn check_against_fs(root: &Path, recs: &[Rec], gnu_like_xattr: bool) {
    let tree = root.join("tree");
    let mut fs = BTreeMap::new();
    walk(&tree, "", &mut fs);
    let mut seen = BTreeMap::new();
    for r in recs {
        let p = norm(&r.e.path);
        if p.is_empty() {
            assert_eq!(r.e.kind, Kind::Dir);
            continue;
        }
        let md = fs.get(&p).unwrap_or_else(|| panic!("unexpected entry {p}"));
        seen.insert(p.clone(), r);
        assert_eq!(r.e.mode, md.mode() & 0o7777, "mode {p}");
        assert_eq!(r.e.uid, md.uid(), "uid {p}");
        assert_eq!(r.e.gid, md.gid(), "gid {p}");
        assert_eq!(r.e.mtime, md.mtime(), "mtime {p}");
        let ft = md.file_type();
        match r.e.kind {
            Kind::Dir => assert!(ft.is_dir(), "{p}"),
            Kind::Symlink => {
                assert!(ft.is_symlink(), "{p}");
                let t = std::fs::read_link(tree.join(&p)).unwrap();
                assert_eq!(r.e.linkname, t.to_str().unwrap(), "{p}");
            }
            Kind::Fifo => assert!(std::os::unix::fs::FileTypeExt::is_fifo(&ft), "{p}"),
            Kind::File | Kind::Hardlink => {
                if r.e.kind == Kind::Hardlink {
                    assert_eq!(r.data.len(), 0);
                    let target = norm(&r.e.linkname);
                    let tmd = fs.get(&target).expect("hardlink target exists");
                    assert_eq!(tmd.ino(), md.ino(), "hardlink inode {p}");
                } else {
                    let want = std::fs::read(tree.join(&p)).unwrap();
                    assert_eq!(r.e.size, want.len() as u64, "{p}");
                    assert!(r.data == want, "content {p}");
                }
            }
            k => panic!("unexpected kind {k:?} for {p}"),
        }
    }
    for k in fs.keys() {
        assert!(seen.contains_key(k), "missing from tar: {k}");
    }
    // Exactly one of the two names of the hardlinked pair is a Hardlink entry.
    let hl = recs.iter().filter(|r| r.e.kind == Kind::Hardlink).count();
    assert_eq!(hl, 1);
    if gnu_like_xattr && root.join("has_xattr").exists() {
        let h = seen.get("etc/hostname").unwrap();
        // etc/hostname may be stored as the hardlink target (File) or link.
        let _ = h;
        let e = seen.get("etc/empty").unwrap();
        assert!(e.e.xattrs.contains(&("user.bin".to_string(), vec![0x00, 0xff, 0x10])));
        let host_or_hard = ["etc/hostname", "etc/hostname.hard"]
            .iter()
            .any(|n| seen[*n].e.xattrs.contains(&("user.test".to_string(), b"hello".to_vec())));
        assert!(host_or_hard);
    }
}

fn tar_of(root: &Path, fmt: &str, xattrs: bool) -> Vec<u8> {
    let mut args = vec![format!("--format={fmt}"), "--numeric-owner".into()];
    if xattrs {
        args.push("--xattrs".into());
    }
    args.extend(["-C".into(), root.join("tree").to_str().unwrap().into(), "-cf".into(), "-".into(), ".".into()]);
    let out = std::process::Command::new("tar").args(&args).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    out.stdout
}

#[test]
fn pax_fixture_all_chunkings() {
    let root = make_tree("tar_pax");
    let t = tar_of(&root, "pax", true);
    let base = read_tar(&t, 0, 1).unwrap();
    check_against_fs(&root, &base, true);
    for (mode, seed) in [(1usize, 0u64), (7, 1), (511, 2), (513, 3), (100_000, 4)] {
        assert_eq!(read_tar(&t, mode, seed).unwrap(), base, "mode {mode}");
    }
}

#[test]
fn gnu_fixture_longname_longlink() {
    let root = make_tree("tar_gnu");
    let t = tar_of(&root, "gnu", false);
    // GNU tar must have used L and K records for the >100 char names.
    assert!(t.windows(14).any(|w| w == b"././@LongLink\0"));
    let base = read_tar(&t, 0, 1).unwrap();
    check_against_fs(&root, &base, false);
    assert!(base.iter().any(|r| r.e.path.len() > 255));
    assert!(base.iter().any(|r| r.e.kind == Kind::Symlink && r.e.linkname.len() == 180));
    for (mode, seed) in [(1usize, 0u64), (33, 1), (4096, 2)] {
        assert_eq!(read_tar(&t, mode, seed).unwrap(), base, "mode {mode}");
    }
}

#[test]
fn ustar_fixture_prefix_split() {
    let root = scratch("tar_ustar");
    let t = root.join("tree");
    let long = format!("{}/{}", "p".repeat(90), "q".repeat(60));
    std::fs::create_dir_all(t.join("p".repeat(90))).unwrap();
    std::fs::write(t.join(&long), b"prefix split").unwrap();
    std::fs::write(t.join("short"), b"short").unwrap();
    std::os::unix::fs::symlink("short", t.join("sl")).unwrap();
    let data = tar_of(&root, "ustar", false);
    let recs = read_tar(&data, 0, 1).unwrap();
    let f = recs.iter().find(|r| norm(&r.e.path) == long).expect("prefix+name joined");
    assert_eq!(f.data, b"prefix split");
    for mode in [1usize, 5] {
        assert_eq!(read_tar(&data, mode, 9).unwrap(), recs);
    }
    check_names(&recs, &["short", "sl", &"p".repeat(90), &long]);
}

fn check_names(recs: &[Rec], names: &[&str]) {
    for n in names {
        assert!(recs.iter().any(|r| norm(&r.e.path) == *n), "{n}");
    }
}

// ---- hand-built archives ----

fn octal(v: u64, n: usize) -> Vec<u8> {
    let s = format!("{:0width$o}\0", v, width = n - 1);
    s.into_bytes()
}

fn header(name: &str, typeflag: u8, size: u64, linkname: &str) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..108].copy_from_slice(&octal(0o644, 8));
    h[108..116].copy_from_slice(&octal(1000, 8));
    h[116..124].copy_from_slice(&octal(1000, 8));
    h[124..136].copy_from_slice(&octal(size, 12));
    h[136..148].copy_from_slice(&octal(1_700_000_000, 12));
    h[156] = typeflag;
    h[157..157 + linkname.len()].copy_from_slice(linkname.as_bytes());
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    fix_sum(&mut h);
    h
}

fn fix_sum(h: &mut [u8; 512]) {
    h[148..156].fill(b' ');
    let sum: u64 = h.iter().map(|&b| b as u64).sum();
    h[148..155].copy_from_slice(&octal(sum, 7));
    h[155] = b' ';
}

fn member(h: [u8; 512], data: &[u8]) -> Vec<u8> {
    let mut v = h.to_vec();
    v.extend(data);
    v.resize(v.len().div_ceil(512) * 512, 0);
    v
}

fn pax_rec(k: &str, v: &[u8]) -> Vec<u8> {
    let body_len = 1 + k.len() + 1 + v.len() + 1; // ' ' k '=' v '\n'
    let mut digits = 1;
    loop {
        let total = body_len + digits;
        if total.to_string().len() == digits {
            let mut r = format!("{total} {k}=").into_bytes();
            r.extend(v);
            r.push(b'\n');
            return r;
        }
        digits += 1;
    }
}

fn end() -> Vec<u8> {
    vec![0u8; 1024]
}

#[test]
fn pax_overrides() {
    let mut recs = Vec::new();
    recs.extend(pax_rec("path", b"overridden/long/path/file.txt"));
    recs.extend(pax_rec("linkpath", b"some/target"));
    recs.extend(pax_rec("size", b"5"));
    recs.extend(pax_rec("uid", b"4000000000"));
    recs.extend(pax_rec("gid", b"123456"));
    recs.extend(pax_rec("mtime", b"1234567890.987654321"));
    recs.extend(pax_rec("SCHILY.xattr.security.capability", &[1, 0, 0, 2, 0xff, 0]));
    recs.extend(pax_rec("SCHILY.xattr.user.k", b"v"));
    recs.extend(pax_rec("unknown.key", b"ignored"));
    let mut t = member(header("PaxHeaders/x", b'x', recs.len() as u64, ""), &recs);
    // Header size field says 0 but pax says 5 bytes of data.
    t.extend(member(header("short", b'0', 0, ""), b"hello"));
    // A following entry must not inherit the overrides.
    t.extend(member(header("plain", b'0', 3, ""), b"abc"));
    t.extend(end());
    for mode in [0usize, 1, 100] {
        let r = read_tar(&t, mode, 5).unwrap();
        assert_eq!(r.len(), 2);
        let e = &r[0].e;
        assert_eq!(e.path, "overridden/long/path/file.txt");
        assert_eq!(e.linkname, "some/target");
        assert_eq!(e.size, 5);
        assert_eq!(r[0].data, b"hello");
        assert_eq!(e.uid, 4_000_000_000);
        assert_eq!(e.gid, 123_456);
        assert_eq!(e.mtime, 1_234_567_890);
        assert_eq!(e.xattrs.len(), 2);
        assert_eq!(e.xattrs[0], ("security.capability".to_string(), vec![1, 0, 0, 2, 0xff, 0]));
        assert_eq!(r[1].e.path, "plain");
        assert_eq!(r[1].e.uid, 1000);
        assert_eq!(r[1].data, b"abc");
        assert!(r[1].e.xattrs.is_empty());
    }
}

#[test]
fn pax_global_defaults() {
    let g = pax_rec("uid", b"77");
    let mut t = member(header("g", b'g', g.len() as u64, ""), &g);
    t.extend(member(header("a", b'0', 1, ""), b"x"));
    let l = pax_rec("uid", b"88");
    t.extend(member(header("x", b'x', l.len() as u64, ""), &l));
    t.extend(member(header("b", b'0', 1, ""), b"y"));
    t.extend(end());
    let r = read_tar(&t, 3, 1).unwrap();
    assert_eq!((r[0].e.uid, r[1].e.uid), (77, 88));
}

#[test]
fn gnu_long_records() {
    let long = "x".repeat(300);
    let target = "y".repeat(400);
    let mut name = long.clone().into_bytes();
    name.push(0);
    let mut tgt = target.clone().into_bytes();
    tgt.push(0);
    let mut t = member(header("././@LongLink", b'L', name.len() as u64, ""), &name);
    t.extend(member(header("././@LongLink", b'K', tgt.len() as u64, ""), &tgt));
    t.extend(member(header("truncated-name", b'2', 0, "truncated-target"), b""));
    t.extend(end());
    for mode in [0usize, 1, 64] {
        let r = read_tar(&t, mode, 2).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].e.path, long);
        assert_eq!(r[0].e.linkname, target);
        assert_eq!(r[0].e.kind, Kind::Symlink);
    }
}

#[test]
fn base256_fields_and_devices() {
    let mut h = header("big", b'0', 0, "");
    // size = 10 GiB via base-256 (marker 0x80).
    h[124..136].fill(0);
    h[124] = 0x80;
    let sz: u64 = 10 << 30;
    h[128..136].copy_from_slice(&sz.to_be_bytes());
    // uid = 3_000_000_000 base-256.
    h[108..116].fill(0);
    h[108] = 0x80;
    h[112..116].copy_from_slice(&3_000_000_000u32.to_be_bytes());
    // negative mtime (-5): 0xff...fb
    h[136..148].fill(0xff);
    h[147] = 0xfb;
    fix_sum(&mut h);
    let mut r = TarReader::new();
    let mut got = None;
    let mut dsum = 0u64;
    r.feed(&h, &mut |ev| {
        if let Event::Entry(e) = ev {
            got = Some(e.clone());
        }
        Ok::<(), ()>(())
    })
    .unwrap();
    let e = got.unwrap();
    assert_eq!(e.size, sz);
    assert_eq!(e.uid, 3_000_000_000);
    assert_eq!(e.mtime, -5);
    // Streams data without buffering: feed 1 MiB, still mid-entry.
    let zeros = vec![0u8; 1 << 20];
    r.feed(&zeros, &mut |ev| {
        if let Event::Data(d) = ev {
            dsum += d.len() as u64;
        }
        Ok::<(), ()>(())
    })
    .unwrap();
    assert_eq!(dsum, 1 << 20);
    assert_eq!(r.finish(), Err(Error::Truncated));

    // Devices.
    let mut c = header("null", b'3', 0, "");
    c[329..337].copy_from_slice(&octal(1, 8));
    c[337..345].copy_from_slice(&octal(3, 8));
    fix_sum(&mut c);
    let mut b = header("sda", b'4', 0, "");
    b[329..337].copy_from_slice(&octal(8, 8));
    b[337..345].copy_from_slice(&octal(16, 8));
    fix_sum(&mut b);
    let mut t = c.to_vec();
    t.extend(b);
    t.extend(header("dir/", b'5', 0, ""));
    t.extend(header("dir2", b'0', 0, "")); // plain file, no slash
    t.extend(header("slashfile/", b'0', 0, "")); // file typeflag + trailing slash => dir
    t.extend(header("fifo", b'6', 0, ""));
    t.extend(end());
    let r = read_tar(&t, 0, 1).unwrap();
    assert_eq!((r[0].e.kind, r[0].e.devmajor, r[0].e.devminor), (Kind::CharDev, 1, 3));
    assert_eq!((r[1].e.kind, r[1].e.devmajor, r[1].e.devminor), (Kind::BlockDev, 8, 16));
    assert_eq!(r[2].e.kind, Kind::Dir);
    assert_eq!(r[3].e.kind, Kind::File);
    assert_eq!(r[4].e.kind, Kind::Dir);
    assert_eq!(r[5].e.kind, Kind::Fifo);
}

#[test]
fn checksum_and_truncation_and_types() {
    let mut t = member(header("a", b'0', 4, ""), b"data");
    t.extend(member(header("b", b'0', 600, ""), &[7u8; 600]));
    t.extend(end());
    assert_eq!(read_tar(&t, 0, 1).unwrap().len(), 2);
    // Flip a header byte.
    let mut bad = t.clone();
    bad[0] ^= 1;
    for mode in [0usize, 1] {
        assert_eq!(read_tar(&bad, mode, 1), Err(Error::BadChecksum));
    }
    // Garbage in the checksum field.
    let mut bad = t.clone();
    bad[148] = b'z';
    assert_eq!(read_tar(&bad, 0, 1), Err(Error::BadChecksum));
    // Truncation anywhere before the end-of-archive marker is detected.
    let body_end = t.len() - 1024;
    for cut in (1..body_end).step_by(37) {
        // cuts exactly at an entry boundary are legitimately fine.
        if cut == 512 + 512 || cut == body_end {
            continue;
        }
        assert_eq!(read_tar(&t[..cut], 0, 1), Err(Error::Truncated), "cut {cut}");
    }
    // Truncated inside padding of the last entry too.
    assert_eq!(read_tar(&t[..body_end - 10], 1, 1), Err(Error::Truncated));
    // Unknown typeflag and GNU sparse are rejected.
    let h = header("z", b'Z', 0, "");
    assert_eq!(read_tar(&h, 0, 1), Err(Error::UnsupportedType(b'Z')));
    let h = header("s", b'S', 0, "");
    assert_eq!(read_tar(&h, 0, 1), Err(Error::UnsupportedType(b'S')));
    // Oversized pax header.
    let h = header("x", b'x', 100 << 20, "");
    assert_eq!(read_tar(&h, 0, 1), Err(Error::MetaTooLarge));
    // Malformed pax record.
    let bad_rec = b"99 path=x\n";
    let t = member(header("x", b'x', bad_rec.len() as u64, ""), bad_rec);
    assert_eq!(read_tar(&t, 0, 1), Err(Error::BadPax));
    // Data after the end marker is ignored.
    let mut t2 = t.clone();
    t2.clear();
    t2.extend(member(header("a", b'0', 1, ""), b"x"));
    t2.extend(end());
    t2.extend(b"trailing junk that is not a header");
    assert_eq!(read_tar(&t2, 1, 1).unwrap().len(), 1);
}

#[test]
fn sink_error_propagates() {
    let t = member(header("a", b'0', 1, ""), b"x");
    let mut r = TarReader::new();
    assert_eq!(r.feed(&t, &mut |_| Err("no")), Err(Error::Sink("no")));
}

// ---- paths and whiteouts ----

#[test]
fn sanitize_rules() {
    let ok = |s: &str| sanitize(s).unwrap().into_string();
    assert_eq!(ok("./"), "");
    assert_eq!(ok("."), "");
    assert_eq!(ok(""), "");
    assert_eq!(ok("./etc//passwd"), "etc/passwd");
    assert_eq!(ok("a/./b/"), "a/b");
    assert_eq!(ok("a/b/../c"), "a/c");
    assert_eq!(ok("a/.."), "");
    assert_eq!(ok("a//b///c/"), "a/b/c");
    assert_eq!(ok("..a/b..//..c"), "..a/b../..c");
    for bad in ["/etc/passwd", "//x", "../etc", "a/../..", "a/../../b", "./../x", "..", "a/b/../../..", "x\0y"] {
        assert_eq!(sanitize(bad), Err(Error::UnsafePath), "{bad:?}");
    }
    let p = sanitize("./a/b").unwrap();
    assert_eq!(p.components().collect::<Vec<_>>(), ["a", "b"]);
    assert!(sanitize("./").unwrap().is_root());
}

#[test]
fn malicious_tar_path_is_caught_by_sanitize() {
    let t = member(header("../../etc/cron.d/evil", b'0', 1, ""), b"x");
    let recs = read_tar(&t, 0, 1).unwrap();
    assert_eq!(sanitize(&recs[0].e.path), Err(Error::UnsafePath));
    // Also via pax override and GNU long name.
    let p = pax_rec("path", b"/abs/../../x");
    let mut t = member(header("x", b'x', p.len() as u64, ""), &p);
    t.extend(member(header("ok", b'0', 0, ""), b""));
    let recs = read_tar(&t, 0, 1).unwrap();
    assert_eq!(sanitize(&recs[0].e.path), Err(Error::UnsafePath));
}

#[test]
fn whiteouts() {
    assert_eq!(whiteout("a/b/.wh..wh..opq"), Some(Whiteout::Opaque("a/b".into())));
    assert_eq!(whiteout(".wh..wh..opq"), Some(Whiteout::Opaque("".into())));
    assert_eq!(whiteout("a/b/.wh.foo"), Some(Whiteout::Remove("a/b/foo".into())));
    assert_eq!(whiteout(".wh.foo"), Some(Whiteout::Remove("foo".into())));
    assert_eq!(whiteout("a/.wh.dir/"), Some(Whiteout::Remove("a/dir".into())));
    assert_eq!(whiteout("a/.wh..wh.plnk"), None);
    assert!(is_reserved_whiteout("a/.wh..wh.plnk"));
    assert!(!is_reserved_whiteout("a/.wh..wh..opq"));
    assert_eq!(whiteout("a/.wh."), None);
    assert_eq!(whiteout("a/b"), None);
    assert_eq!(whiteout("a/x.wh.y"), None);
    assert_eq!(whiteout("a/.whfoo"), None);
}

// ---- fuzz ----

#[test]
fn mutation_fuzz_never_panics() {
    let root = make_tree("tar_fuzz");
    let pax = tar_of(&root, "pax", true);
    let gnu = tar_of(&root, "gnu", false);
    let mut rng = Rng(0x7a17_f00d);
    let mut errs = 0;
    for iter in 0..1500 {
        let base = if iter % 2 == 0 { &pax } else { &gnu };
        // Only mutate the first 64 KiB (headers) most of the time.
        let mut m = base[..base.len().min(70_000)].to_vec();
        for _ in 0..1 + rng.below(5) {
            let i = rng.below(m.len());
            match rng.below(4) {
                0 => m[i] ^= 1 << rng.below(8),
                1 => m[i] = rng.next() as u8,
                2 => m.truncate(i.max(1)),
                _ => m.insert(i, rng.next() as u8),
            }
        }
        if read_tar(&m, [0usize, 1, 50][rng.below(3)], iter).is_err() {
            errs += 1;
        }
    }
    assert!(errs > 100);
    for _ in 0..2000 {
        let n = rng.below(2000);
        let g = rng.bytes(n);
        let _ = read_tar(&g, 0, 1);
    }
    // Header-shaped random blocks with valid checksums exercise the field parsers.
    for _ in 0..3000 {
        let mut h = [0u8; 512];
        let n = rng.below(512);
        for b in h.iter_mut().take(n) {
            *b = rng.next() as u8;
        }
        h[156] = b"0123456789xgLKS"[rng.below(15)];
        for r in [124usize, 108, 136] {
            if rng.below(2) == 0 {
                for b in &mut h[r..r + 8] {
                    *b = b'0' + rng.below(8) as u8;
                }
            }
        }
        fix_sum(&mut h);
        let mut t = h.to_vec();
        let k = rng.below(1500);
        t.extend(rng.bytes(k));
        let _ = read_tar(&t, 0, 1);
    }
}

#[test]
fn full_pipeline_gzip_tar() {
    use kr_archive::gzip::GzDecoder;
    let root = make_tree("tar_pipe");
    let t = tar_of(&root, "pax", true);
    let gz = gzip(&t, 6);
    let want = read_tar(&t, 0, 1).unwrap();
    for mode in [1usize, 4096] {
        let mut rng = Rng(5);
        let mut gd = GzDecoder::new();
        let mut tr = TarReader::new();
        let mut recs: Vec<Rec> = Vec::new();
        for c in chunks(&gz, mode, &mut rng) {
            gd.feed(c, &mut |tb| {
                tr.feed(tb, &mut |ev| {
                    match ev {
                        Event::Entry(e) => recs.push(Rec { e: e.clone(), data: vec![] }),
                        Event::Data(d) => recs.last_mut().unwrap().data.extend_from_slice(d),
                        Event::End => {}
                    }
                    Ok::<(), ()>(())
                })
            })
            .map_err(|e| format!("{e:?}"))
            .unwrap();
        }
        gd.finish().unwrap();
        tr.finish().unwrap();
        assert_eq!(recs, want);
    }
}
