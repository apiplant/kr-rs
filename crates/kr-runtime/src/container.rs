//! Kernel-level container isolation (ADR-007, ADR-016).
//!
//! `run` forks (clone3) into fresh user, mount, pid, uts, ipc, net and cgroup namespaces. The
//! parent writes the uid/gid maps and releases the child through a pipe; the child mounts the
//! overlay rootfs, pivots into it, mounts /proc, /dev and /sys and finally execs the entrypoint.
//!
//! Escape-safety of the mount phase: the only paths touched before `pivot_root` are store paths
//! that kr controls (the overlay dirs). Everything that lives inside the image (`/proc`, `/dev`,
//! `/sys`, the cwd, the exec path) is resolved only *after* `pivot_root`, so symlinks in the image
//! resolve against the container root and cannot reach the host.
//!
//! Setup failures in the child are reported back over a CLOEXEC pipe as `(step, errno)`; a
//! successful execve closes that pipe, which the parent reads as EOF = started.

use alloc::vec::Vec;
use kr_sys::ns::{self, CloneArgs};
use kr_sys::{Errno, Fd};

use crate::security;

pub struct RunSpec<'a> {
    /// Flattened image rootfs (overlay lowerdir).
    pub rootfs: &'a [u8],
    /// Per-container overlay dirs; must already exist.
    pub upper: &'a [u8],
    pub work: &'a [u8],
    pub merged: &'a [u8],
    /// argv[0] is resolved against PATH from `env` when it contains no '/'.
    pub argv: &'a [Vec<u8>],
    /// `KEY=value` entries.
    pub env: &'a [Vec<u8>],
    /// Working directory inside the container ("" means "/").
    pub cwd: &'a [u8],
    pub hostname: &'a [u8],
}

#[derive(Debug)]
pub struct RunError {
    pub step: &'static str,
    pub errno: Errno,
}

fn err(step: &'static str) -> impl FnOnce(Errno) -> RunError {
    move |errno| RunError { step, errno }
}

/// Setup steps, indexed by the byte the child sends back.
const STEPS: &[&str] = &[
    "wait for parent",
    "make / private",
    "mount overlay",
    "chdir rootfs",
    "mkdir .oldroot",
    "pivot_root",
    "mount /proc",
    "mount /dev",
    "populate /dev",
    "mount /sys",
    "detach old root",
    "sethostname",
    "chdir cwd",
    "no_new_privs",
    "execve",
    "invalid spec",
    "drop capabilities",
    "seccomp",
    "join cgroup",
];

/// NUL-terminated concatenation of `parts`.
fn cstr(parts: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    for p in parts {
        v.extend_from_slice(p);
    }
    v.push(0);
    v
}

/// Runs the container to completion and returns its exit code (128+signal if killed).
pub fn run(spec: &RunSpec) -> Result<i32, RunError> {
    // Overlay options are comma/colon separated, so those bytes (and NUL) must not occur in paths.
    let bad = |p: &[u8]| p.is_empty() || p.iter().any(|&b| b == b',' || b == b':' || b == 0);
    if bad(spec.rootfs) || bad(spec.upper) || bad(spec.work) || bad(spec.merged) || spec.argv.is_empty() {
        return Err(RunError { step: "invalid spec", errno: Errno(22) });
    }

    let (go_r, go_w) = kr_sys::pipe2(kr_sys::O_CLOEXEC).map_err(err("pipe"))?;
    let (rep_r, rep_w) = kr_sys::pipe2(kr_sys::O_CLOEXEC).map_err(err("pipe"))?;
    let (uid, gid) = (ns::getuid(), ns::getgid());

    let mut args = CloneArgs {
        flags: ns::CLONE_NEWUSER
            | ns::CLONE_NEWNS
            | ns::CLONE_NEWPID
            | ns::CLONE_NEWUTS
            | ns::CLONE_NEWIPC
            | ns::CLONE_NEWNET
            | ns::CLONE_NEWCGROUP,
        exit_signal: ns::SIGCHLD as u64,
        ..Default::default()
    };
    // SAFETY: the runtime is single-threaded (ADR-005), so the forked child's memory is coherent.
    let pid = unsafe { ns::clone3(&mut args) }.map_err(err("clone3"))?;

    if pid == 0 {
        drop(go_w);
        drop(rep_r);
        let (step, e) = child(spec, &go_r, rootless(uid));
        let _ = kr_sys::write(rep_w.raw(), &[step, e.0 as u8, (e.0 >> 8) as u8]);
        kr_sys::exit_group(127);
    }

    drop(go_r);
    drop(rep_w);
    if let Err(e) = write_id_maps(pid, uid, gid) {
        let _ = ns::kill(pid, ns::SIGKILL);
        let _ = ns::wait4(pid);
        return Err(e);
    }
    let _ = kr_sys::write(go_w.raw(), b"g");
    drop(go_w);

    let mut rep = [0u8; 3];
    let n = read_full(&rep_r, &mut rep);
    let status = ns::wait4(pid).map_err(err("wait4"))?;
    if n == 3 {
        let step = STEPS.get(rep[0] as usize).copied().unwrap_or("unknown");
        return Err(RunError { step, errno: Errno(rep[1] as i32 | (rep[2] as i32) << 8) });
    }
    Ok(ns::exit_code(status))
}

fn rootless(uid: u32) -> bool {
    uid != 0
}

fn read_full(fd: &Fd, buf: &mut [u8]) -> usize {
    let mut n = 0;
    while n < buf.len() {
        match kr_sys::read(fd.raw(), &mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(Errno(4)) => continue,
            Err(_) => break,
        }
    }
    n
}

/// Maps container root to the invoking user. As real root, maps the full range (identity).
fn write_id_maps(pid: i32, uid: u32, gid: u32) -> Result<(), RunError> {
    let d = fmt_u32(pid as u32);
    let base = |f: &[u8]| cstr(&[b"/proc/", &d, b"/", f]);
    let (uid_map, gid_map) = if rootless(uid) {
        (map_line(uid), map_line(gid))
    } else {
        (b"0 0 4294967295\n".to_vec(), b"0 0 4294967295\n".to_vec())
    };
    if rootless(uid) {
        // An unprivileged writer must deny setgroups before writing gid_map.
        ns::write_file(&base(b"setgroups"), b"deny").map_err(err("write setgroups"))?;
    }
    ns::write_file(&base(b"uid_map"), &uid_map).map_err(err("write uid_map"))?;
    ns::write_file(&base(b"gid_map"), &gid_map).map_err(err("write gid_map"))?;
    Ok(())
}

fn map_line(id: u32) -> Vec<u8> {
    let mut v = b"0 ".to_vec();
    v.extend_from_slice(&fmt_u32(id));
    v.extend_from_slice(b" 1\n");
    v
}

fn fmt_u32(mut n: u32) -> Vec<u8> {
    let mut buf = [0u8; 10];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    buf[i..].to_vec()
}

/// Child side. Only returns on failure, with (step index, errno).
fn child(spec: &RunSpec, go: &Fd, rootless: bool) -> (u8, Errno) {
    macro_rules! step {
        ($i:expr, $e:expr) => {
            if let Err(e) = $e {
                return ($i, e);
            }
        };
    }
    // Die with the parent rather than linger as an orphaned pid-1.
    let _ = ns::prctl(ns::PR_SET_PDEATHSIG, ns::SIGKILL as usize);
    let mut b = [0u8; 1];
    if read_full(go, &mut b) != 1 {
        return (0, Errno(32));
    }

    step!(1, ns::mount(None, b"/\0", None, ns::MS_REC | ns::MS_PRIVATE, None));

    let mut opts = cstr(&[b"lowerdir=", spec.rootfs, b",upperdir=", spec.upper, b",workdir=", spec.work]);
    if rootless {
        opts.pop();
        opts.extend_from_slice(b",userxattr\0");
    }
    let merged = cstr(&[spec.merged]);
    step!(2, ns::mount(Some(b"overlay\0"), &merged, Some(b"overlay\0"), 0, Some(&opts)));

    // pivot_root(".", ".oldroot"): the kernel rejects a put_old that resolves outside new_root,
    // so a malicious `.oldroot` symlink in the image cannot redirect it.
    step!(3, ns::chdir(&merged));
    match ns::mkdir(b".oldroot\0", 0o700) {
        Ok(()) | Err(Errno(17)) => {}
        Err(e) => return (4, e),
    }
    step!(5, ns::pivot_root(b".\0", b".oldroot\0"));
    step!(5, ns::chdir(b"/\0"));

    // From here on every path resolves inside the container root.
    // /proc must be mounted while the host's proc is still visible (userns "fully visible" rule).
    let _ = ns::mkdir(b"/proc\0", 0o555);
    step!(6, ns::mount(Some(b"proc\0"), b"/proc\0", Some(b"proc\0"), ns::MS_NOSUID | ns::MS_NODEV | ns::MS_NOEXEC, None));

    let _ = ns::mkdir(b"/dev\0", 0o755);
    step!(7, ns::mount(Some(b"tmpfs\0"), b"/dev\0", Some(b"tmpfs\0"), ns::MS_NOSUID | ns::MS_NOEXEC, Some(b"mode=755,size=65536k\0")));
    step!(8, populate_dev());

    // sysfs needs an owned netns; read-only. Some kernels/policies refuse it rootless: tolerate.
    let _ = ns::mkdir(b"/sys\0", 0o555);
    if let Err(e) = ns::mount(Some(b"sysfs\0"), b"/sys\0", Some(b"sysfs\0"), ns::MS_RDONLY | ns::MS_NOSUID | ns::MS_NODEV | ns::MS_NOEXEC, None) {
        if e != Errno(1) {
            return (9, e);
        }
    }

    step!(10, ns::umount2(b"/.oldroot\0", ns::MNT_DETACH));
    let _ = ns::rmdir(b"/.oldroot\0");

    if !spec.hostname.is_empty() {
        step!(11, ns::sethostname(spec.hostname));
    }
    let cwd = if spec.cwd.is_empty() { cstr(&[b"/"]) } else { cstr(&[spec.cwd]) };
    step!(12, ns::chdir(&cwd));
    step!(16, security::drop_caps(security::DEFAULT_CAPS));
    step!(13, ns::prctl(ns::PR_SET_NO_NEW_PRIVS, 1));
    // Built before installing: the filter must be the last thing before execve.
    let filter = security::default_filter();
    step!(17, ns::seccomp_set_filter(&filter));

    exec(spec)
}

/// Fresh /dev: device nodes are bind-mounted from the host (mknod is not allowed rootless).
fn populate_dev() -> Result<(), Errno> {
    for name in [&b"null"[..], b"zero", b"full", b"random", b"urandom", b"tty"] {
        let target = cstr(&[b"/dev/", name]);
        let source = cstr(&[b"/.oldroot/dev/", name]);
        drop(ns::open(&target, ns::O_WRONLY | ns::O_CREAT, 0o666)?);
        ns::mount(Some(&source), &target, None, ns::MS_BIND, None)?;
    }
    for dir in [&b"/dev/pts\0"[..], b"/dev/shm\0"] {
        let _ = ns::mkdir(dir, 0o755);
    }
    ns::mount(Some(b"devpts\0"), b"/dev/pts\0", Some(b"devpts\0"), ns::MS_NOSUID | ns::MS_NOEXEC, Some(b"newinstance,ptmxmode=0666,mode=620\0"))?;
    ns::mount(Some(b"shm\0"), b"/dev/shm\0", Some(b"tmpfs\0"), ns::MS_NOSUID | ns::MS_NODEV | ns::MS_NOEXEC, Some(b"mode=1777,size=65536k\0"))?;
    Ok(())
}

fn exec(spec: &RunSpec) -> (u8, Errno) {
    let argv_c: Vec<Vec<u8>> = spec.argv.iter().map(|a| cstr(&[a])).collect();
    let env_c: Vec<Vec<u8>> = spec.env.iter().map(|e| cstr(&[e])).collect();
    let mut argv: Vec<*const u8> = argv_c.iter().map(|a| a.as_ptr()).collect();
    argv.push(core::ptr::null());
    let mut envp: Vec<*const u8> = env_c.iter().map(|e| e.as_ptr()).collect();
    envp.push(core::ptr::null());

    let prog = &spec.argv[0];
    if prog.contains(&b'/') {
        return (14, ns::execve(&argv_c[0], &argv, &envp));
    }
    let path = spec
        .env
        .iter()
        .find_map(|e| e.strip_prefix(b"PATH="))
        .unwrap_or(b"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    let mut last = Errno(2);
    for dir in path.split(|&b| b == b':').filter(|d| !d.is_empty()) {
        let full = cstr(&[dir, b"/", prog]);
        match ns::execve(&full, &argv, &envp) {
            // Not here (ENOENT/ENOTDIR) or not executable (EACCES): keep searching like execvp.
            e @ (Errno(2) | Errno(13) | Errno(20)) => last = e,
            e => return (14, e),
        }
    }
    (14, last)
}
