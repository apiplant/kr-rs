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

use alloc::rc::Rc;
use alloc::vec::Vec;
use kr_sys::ns::{self, CloneArgs};
use kr_sys::{Errno, Fd};

use crate::cgroup::{Cgroup, Limits};
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
    /// Container id; names the cgroup. Required when `limits` is non-empty.
    pub id: &'a [u8],
    pub limits: Limits,
    /// OCI `user`: `uid|name[:gid|group]`; empty means root. Names resolve against the image's
    /// /etc/passwd and /etc/group, read after pivot_root.
    pub user: &'a [u8],
    /// User-namespace id mapping (see `IdMaps::for_current_user`).
    pub maps: &'a IdMaps,
}

/// Outcome of a container run.
#[derive(Debug)]
pub struct Exit {
    /// Shell-style exit code (128+signal when killed).
    pub code: i32,
    /// The kernel OOM-killed a process in the container's cgroup.
    pub oom_killed: bool,
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
    "loopback up",
    "mask /proc",
    "resolve user",
    "set user",
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

/// Runs the container to completion (blocking) and returns its exit code (128+signal if killed).
pub fn run(spec: &RunSpec) -> Result<Exit, RunError> {
    let r = start(spec)?;
    let status = ns::wait4(r.pid).map_err(err("wait4"));
    let oom_killed = r.finish();
    Ok(Exit { code: ns::exit_code(status?), oom_killed })
}

/// A started container. Dropping it without `wait` leaks the process; call `wait`.
pub struct Running {
    pub pid: i32,
    pidfd: Rc<Fd>,
    cgroup: Option<Cgroup>,
}

/// Sends signals to a container's pid 1; usable from another task while `wait` runs.
#[derive(Clone)]
pub struct Signaller(Rc<Fd>);

impl Signaller {
    /// Note pid 1 of a pid namespace ignores signals it installed no handler for (SIGKILL aside).
    pub fn send(&self, sig: i32) -> Result<(), Errno> {
        ns::pidfd_send_signal(&self.0, sig)
    }
}

impl Running {
    pub fn signaller(&self) -> Signaller {
        Signaller(self.pidfd.clone())
    }

    /// Waits for exit without blocking the executor (pidfd becomes readable on exit).
    pub async fn wait(self) -> Result<Exit, RunError> {
        let Running { pid: _, pidfd, cgroup } = self;
        let code = match kr_rt::exec::Async::new(pidfd) {
            Ok(fd) => loop {
                match ns::pidfd_try_wait(fd.get_ref()) {
                    Ok(Some(c)) => break Ok(c),
                    Ok(None) => fd.wait_readable().await,
                    Err(Errno(4)) => {}
                    Err(e) => break Err(RunError { step: "waitid", errno: e }),
                }
            },
            Err(e) => Err(RunError { step: "register pidfd", errno: e }),
        };
        let oom_killed = finish_cgroup(&cgroup);
        Ok(Exit { code: code?, oom_killed })
    }

    fn finish(self) -> bool {
        finish_cgroup(&self.cgroup)
    }
}

/// Removes the container cgroup; returns whether an OOM kill was recorded in it.
fn finish_cgroup(cg: &Option<Cgroup>) -> bool {
    let oom = cg.as_ref().is_some_and(|c| c.oom_kills() > 0);
    if let Some(c) = cg {
        c.remove();
    }
    oom
}

/// Starts the container and returns once its entrypoint has been exec'd (or setup failed).
pub fn start(spec: &RunSpec) -> Result<Running, RunError> {
    // Overlay options are comma/colon separated, so those bytes (and NUL) must not occur in paths.
    let bad = |p: &[u8]| p.is_empty() || p.iter().any(|&b| b == b',' || b == b':' || b == 0);
    if bad(spec.rootfs) || bad(spec.upper) || bad(spec.work) || bad(spec.merged) || spec.argv.is_empty() {
        return Err(RunError { step: "invalid spec", errno: Errno(22) });
    }

    let (go_r, go_w) = kr_sys::pipe2(kr_sys::O_CLOEXEC).map_err(err("pipe"))?;
    let (rep_r, rep_w) = kr_sys::pipe2(kr_sys::O_CLOEXEC).map_err(err("pipe"))?;
    let (uid, gid) = (ns::getuid(), ns::getgid());
    // Before clone: inside the new userns getuid() reports the overflow id until maps exist.
    let full_map = spec.maps.full();

    let cgroup = if spec.limits.is_empty() {
        None
    } else {
        Some(Cgroup::create(spec.id, &spec.limits).map_err(err("create cgroup (is kr in a delegated cgroup? try systemd-run --user --scope -p Delegate=yes)"))?)
    };

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
    let mut pidfd: i32 = -1;
    args.flags |= ns::CLONE_PIDFD;
    args.pidfd = &mut pidfd as *mut i32 as u64;
    if let Some(cg) = &cgroup {
        args.flags |= ns::CLONE_INTO_CGROUP;
        args.cgroup = cg.dir.raw() as u64;
    }
    // SAFETY: the runtime is single-threaded (ADR-005), so the forked child's memory is coherent.
    let pid = match unsafe { ns::clone3(&mut args) } {
        Ok(p) => p,
        Err(e) => {
            if let Some(cg) = &cgroup {
                cg.remove();
            }
            return Err(RunError { step: "clone3", errno: e });
        }
    };

    if pid == 0 {
        drop(go_w);
        drop(rep_r);
        let (step, e) = child(spec, &go_r, rootless(uid), full_map);
        let _ = kr_sys::write(rep_w.raw(), &[step, e.0 as u8, (e.0 >> 8) as u8]);
        kr_sys::exit_group(127);
    }

    drop(go_r);
    drop(rep_w);
    let running = Running { pid, pidfd: Rc::new(Fd(pidfd)), cgroup };
    if let Err(e) = spec.maps.apply(pid, uid, gid) {
        let _ = ns::kill(pid, ns::SIGKILL);
        let _ = ns::wait4(pid);
        running.finish();
        return Err(e);
    }
    let _ = kr_sys::write(go_w.raw(), b"g");
    drop(go_w);

    let mut rep = [0u8; 3];
    if read_full(&rep_r, &mut rep) == 3 {
        let _ = ns::wait4(pid);
        running.finish();
        let step = STEPS.get(rep[0] as usize).copied().unwrap_or("unknown");
        return Err(RunError { step, errno: Errno(rep[1] as i32 | (rep[2] as i32) << 8) });
    }
    Ok(running)
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

/// User-namespace id mapping for containers (KNOWN_ISSUES #43).
///
/// As real root: identity over the whole range. Rootless: container root is the invoking user,
/// and ids 1.. map onto the user's subordinate range from /etc/subuid and /etc/subgid, written
/// through the setuid `newuidmap`/`newgidmap` helpers (the standard rootless mechanism; they are
/// the only host binaries kr uses, and only when such a range exists). Without a range, only
/// root is mapped and images that switch to another user fail at "set user".
#[derive(Clone, Debug, Default)]
pub struct IdMaps {
    /// (start, count) of the subordinate uid/gid range; None = single-id mapping.
    sub_uid: Option<(u32, u32)>,
    sub_gid: Option<(u32, u32)>,
}

const NEWUIDMAP: &[u8] = b"/usr/bin/newuidmap\0";
const NEWGIDMAP: &[u8] = b"/usr/bin/newgidmap\0";

impl IdMaps {
    pub fn for_current_user() -> IdMaps {
        let uid = ns::getuid();
        if !rootless(uid) || ns::open(NEWUIDMAP, ns::O_RDONLY, 0).is_err() || ns::open(NEWGIDMAP, ns::O_RDONLY, 0).is_err() {
            return IdMaps::default();
        }
        let name = passwd_name(uid);
        let id = fmt_u32(uid);
        let find = |file: &[u8]| -> Option<(u32, u32)> {
            let data = read_small(file).ok()?;
            data.split(|&b| b == b'\n').find_map(|l| {
                let mut f = l.split(|&b| b == b':');
                let who = f.next()?;
                if who != &id[..] && Some(who) != name.as_deref() {
                    return None;
                }
                let start = parse_u32(f.next()?)?;
                let count = parse_u32(f.next()?)?;
                (count > 0 && start.checked_add(count).is_some()).then_some((start, count))
            })
        };
        let (u, g) = (find(b"/etc/subuid\0"), find(b"/etc/subgid\0"));
        // Both or neither: a mixed mapping would leave files with unmapped owners.
        if u.is_some() && g.is_some() {
            IdMaps { sub_uid: u, sub_gid: g }
        } else {
            IdMaps::default()
        }
    }

    /// True when ids other than 0 are mapped (real root or a subordinate range).
    pub fn full(&self) -> bool {
        self.sub_uid.is_some() || !rootless(ns::getuid())
    }

    fn apply(&self, pid: i32, uid: u32, gid: u32) -> Result<(), RunError> {
        let d = fmt_u32(pid as u32);
        if !rootless(uid) {
            let base = |f: &[u8]| cstr(&[b"/proc/", &d, b"/", f]);
            ns::write_file(&base(b"uid_map"), b"0 0 4294967295\n").map_err(err("write uid_map"))?;
            return ns::write_file(&base(b"gid_map"), b"0 0 4294967295\n").map_err(err("write gid_map"));
        }
        match (self.sub_uid, self.sub_gid) {
            (Some(su), Some(sg)) => {
                helper(NEWUIDMAP, &d, uid, su).map_err(err("newuidmap"))?;
                helper(NEWGIDMAP, &d, gid, sg).map_err(err("newgidmap"))
            }
            _ => {
                let base = |f: &[u8]| cstr(&[b"/proc/", &d, b"/", f]);
                // An unprivileged writer must deny setgroups before writing gid_map.
                ns::write_file(&base(b"setgroups"), b"deny").map_err(err("write setgroups"))?;
                ns::write_file(&base(b"uid_map"), &single(uid)).map_err(err("write uid_map"))?;
                ns::write_file(&base(b"gid_map"), &single(gid)).map_err(err("write gid_map"))
            }
        }
    }

    /// Runs `f` as root of a fresh user namespace with these maps (no other namespaces), and
    /// returns whether it succeeded. Used to delete container state owned by subordinate ids,
    /// which the invoking user cannot remove directly.
    pub fn run_as_root(&self, f: impl FnOnce() -> bool) -> Result<bool, RunError> {
        let (go_r, go_w) = kr_sys::pipe2(kr_sys::O_CLOEXEC).map_err(err("pipe"))?;
        let mut args = CloneArgs { flags: ns::CLONE_NEWUSER, exit_signal: ns::SIGCHLD as u64, ..Default::default() };
        // SAFETY: single-threaded runtime (ADR-005); the child only runs `f` and exits.
        let pid = unsafe { ns::clone3(&mut args) }.map_err(err("clone3"))?;
        if pid == 0 {
            drop(go_w);
            let mut b = [0u8; 1];
            let ok = read_full(&go_r, &mut b) == 1 && f();
            kr_sys::exit_group(if ok { 0 } else { 1 });
        }
        drop(go_r);
        let r = self.apply(pid, ns::getuid(), ns::getgid());
        if r.is_ok() {
            let _ = kr_sys::write(go_w.raw(), b"g");
        }
        drop(go_w);
        let status = ns::wait4(pid).map_err(err("wait4"))?;
        r.map(|_| status == 0)
    }
}

/// Runs `newuidmap PID 0 ID 1 1 START COUNT` (or newgidmap) and waits for it.
fn helper(prog: &[u8], pid: &[u8], id: u32, (start, count): (u32, u32)) -> Result<(), Errno> {
    let args: [Vec<u8>; 8] = [
        cstr(&[&prog[..prog.len() - 1]]),
        cstr(&[pid]),
        cstr(&[b"0"]),
        cstr(&[&fmt_u32(id)]),
        cstr(&[b"1"]),
        cstr(&[b"1"]),
        cstr(&[&fmt_u32(start)]),
        cstr(&[&fmt_u32(count)]),
    ];
    let mut argv: Vec<*const u8> = args.iter().map(|a| a.as_ptr()).collect();
    argv.push(core::ptr::null());
    let envp = [core::ptr::null()];
    let mut ca = CloneArgs { exit_signal: ns::SIGCHLD as u64, ..Default::default() };
    // SAFETY: single-threaded runtime (ADR-005); the child only execs.
    let pid = unsafe { ns::clone3(&mut ca) }?;
    if pid == 0 {
        ns::execve(prog, &argv, &envp);
        kr_sys::exit_group(127);
    }
    match ns::exit_code(ns::wait4(pid)?) {
        0 => Ok(()),
        _ => Err(Errno(1)),
    }
}

/// Host user name for `uid`, from /etc/passwd (subuid files may key on either).
fn passwd_name(uid: u32) -> Option<Vec<u8>> {
    let data = read_small(b"/etc/passwd\0").ok()?;
    let id = fmt_u32(uid);
    data.split(|&b| b == b'\n').find_map(|l| {
        let mut f = l.split(|&b| b == b':');
        let name = f.next()?;
        f.next()?;
        (f.next()? == &id[..]).then(|| name.to_vec())
    })
}

fn parse_u32(s: &[u8]) -> Option<u32> {
    if s.is_empty() || s.len() > 10 || !s.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.iter().try_fold(0u32, |a, &d| a.checked_mul(10)?.checked_add((d - b'0') as u32))
}

/// Reads a small regular file. O_NONBLOCK so a FIFO planted in an image cannot hang us.
fn read_small(path: &[u8]) -> Result<Vec<u8>, Errno> {
    const O_NONBLOCK: i32 = 0o4000;
    let fd = ns::open(path, ns::O_RDONLY | O_NONBLOCK, 0)?;
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match kr_sys::read(fd.raw(), &mut buf) {
            Ok(0) => return Ok(out),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(Errno(4)) => continue,
            Err(e) => return Err(e),
        }
        if out.len() > 1 << 20 {
            return Err(Errno(27)); // EFBIG
        }
    }
}

fn single(id: u32) -> Vec<u8> {
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
fn child(spec: &RunSpec, go: &Fd, rootless: bool, full_map: bool) -> (u8, Errno) {
    macro_rules! step {
        ($i:expr, $e:expr) => {
            if let Err(e) = $e {
                return ($i, e);
            }
        };
    }
    // The supervisor blocks signals it reads through a signalfd; the mask would survive execve.
    let _ = ns::sigmask_reset();
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
    step!(20, mask_proc());

    // sysfs needs an owned netns; read-only. Some kernels/policies refuse it rootless: tolerate.
    let _ = ns::mkdir(b"/sys\0", 0o555);
    if let Err(e) = ns::mount(Some(b"sysfs\0"), b"/sys\0", Some(b"sysfs\0"), ns::MS_RDONLY | ns::MS_NOSUID | ns::MS_NODEV | ns::MS_NOEXEC, None) {
        if e != Errno(1) {
            return (9, e);
        }
    }

    step!(10, ns::umount2(b"/.oldroot\0", ns::MNT_DETACH));
    let _ = ns::rmdir(b"/.oldroot\0");

    step!(19, ns::link_up(b"lo"));

    if !spec.hostname.is_empty() {
        step!(11, ns::sethostname(spec.hostname));
    }
    let cwd = if spec.cwd.is_empty() { cstr(&[b"/"]) } else { cstr(&[spec.cwd]) };
    step!(12, ns::chdir(&cwd));
    // Resolved inside the container root, so the image's own /etc/passwd is used.
    let ids = match resolve_user(spec.user) {
        Ok(ids) => ids,
        Err(e) => return (21, e),
    };
    step!(16, security::drop_caps(security::DEFAULT_CAPS));
    if let Some((uid, gid, groups)) = ids {
        // setgroups is denied under a single-id mapping; only root exists there anyway.
        if full_map {
            step!(22, ns::setgroups(&groups));
        }
        step!(22, ns::setresgid(gid));
        // Leaving uid 0 clears the permitted/effective capability sets (no keepcaps).
        step!(22, ns::setresuid(uid));
    }
    step!(13, ns::prctl(ns::PR_SET_NO_NEW_PRIVS, 1));
    // Built before installing: the filter must be the last thing before execve.
    let filter = security::default_filter();
    step!(17, ns::seccomp_set_filter(&filter));

    exec(spec)
}

/// Hides kernel interfaces a container has no business reading or writing (Docker's masked and
/// read-only paths). Missing paths are skipped.
fn mask_proc() -> Result<(), Errno> {
    let ok_missing = |r: Result<(), Errno>| match r {
        Err(Errno(2)) => Ok(()),
        r => r,
    };
    for f in [&b"/proc/kcore\0"[..], b"/proc/keys\0", b"/proc/latency_stats\0", b"/proc/timer_list\0", b"/proc/timer_stats\0", b"/proc/sched_debug\0"] {
        ok_missing(ns::mount(Some(b"/dev/null\0"), f, None, ns::MS_BIND, None))?;
    }
    for d in [&b"/proc/acpi\0"[..], b"/proc/asound\0", b"/proc/scsi\0", b"/sys/firmware\0", b"/sys/devices/virtual/powercap\0"] {
        ok_missing(ns::mount(Some(b"tmpfs\0"), d, Some(b"tmpfs\0"), ns::MS_RDONLY | ns::MS_NOSUID | ns::MS_NODEV | ns::MS_NOEXEC, Some(b"size=0\0")))?;
    }
    for p in [&b"/proc/bus\0"[..], b"/proc/fs\0", b"/proc/irq\0", b"/proc/sys\0", b"/proc/sysrq-trigger\0"] {
        match ns::mount(Some(p), p, None, ns::MS_BIND | ns::MS_REC, None) {
            Err(Errno(2)) => continue,
            r => r?,
        }
        // The remount must repeat the flags locked by the userns, or it fails with EPERM.
        let fl = ns::MS_BIND | ns::MS_REMOUNT | ns::MS_RDONLY | ns::MS_NOSUID | ns::MS_NODEV | ns::MS_NOEXEC;
        ns::mount(None, p, None, fl, None)?;
    }
    Ok(())
}

/// Resolves an OCI user string to (uid, gid, supplementary groups); None means stay root.
fn resolve_user(user: &[u8]) -> Result<Option<(u32, u32, Vec<u32>)>, Errno> {
    if user.is_empty() {
        return Ok(None);
    }
    let (u, g) = match user.iter().position(|&b| b == b':') {
        Some(i) => (&user[..i], Some(&user[i + 1..])),
        None => (user, None),
    };
    let passwd = read_small(b"/etc/passwd\0").unwrap_or_default();
    let group = read_small(b"/etc/group\0").unwrap_or_default();
    let fields = |data: &'_ [u8]| -> Vec<Vec<Vec<u8>>> {
        data.split(|&b| b == b'\n').map(|l| l.split(|&b| b == b':').map(|f| f.to_vec()).collect()).collect()
    };
    let (pw, gr) = (fields(&passwd), fields(&group));
    // passwd: name:x:uid:gid:...   numeric ids need no entry.
    let entry = pw.iter().find(|f| f.len() > 3 && (f[0] == u || f[2] == u));
    let uid = match parse_u32(u) {
        Some(n) => n,
        None => parse_u32(&entry.ok_or(Errno(2))?[2]).ok_or(Errno(22))?,
    };
    let primary = entry.and_then(|f| parse_u32(&f[3])).unwrap_or(0);
    let gid = match g {
        None => primary,
        Some(g) => match parse_u32(g) {
            Some(n) => n,
            None => gr.iter().find(|f| f.len() > 2 && f[0] == g).and_then(|f| parse_u32(&f[2])).ok_or(Errno(2))?,
        },
    };
    if uid == 0 && gid == 0 && g.is_none() {
        return Ok(None);
    }
    // group: name:x:gid:member,member
    let mut groups = alloc::vec![gid];
    if let (Some(name), None) = (entry.map(|f| &f[0]), g) {
        for f in gr.iter().filter(|f| f.len() > 3) {
            if f[3].split(|&b| b == b',').any(|m| m == &name[..]) {
                if let Some(id) = parse_u32(&f[2]) {
                    if !groups.contains(&id) {
                        groups.push(id);
                    }
                }
            }
        }
    }
    Ok(Some((uid, gid, groups)))
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
