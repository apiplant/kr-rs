//! cgroup v2 limits through a delegated subtree (ADR-016).
//!
//! kr must run in a cgroup it may write to: `systemd-run --user --scope -p Delegate=yes` in dev,
//! or a unit with `Delegate=yes` in production. Because of the cgroup v2 "no internal processes"
//! rule, kr first moves itself into `<base>/kr-supervisor`, then enables controllers on `<base>`
//! and creates one sibling cgroup per container. The child is born inside it via CLONE_INTO_CGROUP,
//! so it is never briefly unlimited.

use alloc::vec::Vec;
use kr_sys::ns;
use kr_sys::{Errno, Fd};

#[derive(Clone, Copy, Default, Debug)]
pub struct Limits {
    /// memory.max in bytes (swap is disabled for the container when set).
    pub memory_bytes: Option<u64>,
    /// pids.max.
    pub pids: Option<u64>,
    /// CPU in millicores (1000 = one CPU), written as cpu.max quota over a 100 ms period.
    pub cpu_milli: Option<u64>,
    /// CPU request in millicores, written as cpu.weight (relative share under contention).
    pub cpu_request_milli: Option<u64>,
    /// Memory request in bytes: memory.min when `memory_guaranteed`, else memory.low.
    pub memory_request_bytes: Option<u64>,
    /// The pod is QoS Guaranteed, so its request is a hard reservation (memory.min).
    pub memory_guaranteed: bool,
}

impl Limits {
    /// The memory request as a cgroup protection: `memory.min` for Guaranteed pods, `memory.low`
    /// for Burstable ones. BestEffort (no request) gets none.
    pub fn memory_protection(&self) -> Option<(&'static [u8], u64)> {
        let r = self.memory_request_bytes.filter(|r| *r > 0)?;
        Some((if self.memory_guaranteed { b"memory.min" } else { b"memory.low" }, r))
    }

    pub fn is_empty(&self) -> bool {
        self.memory_bytes.is_none() && self.pids.is_none() && self.cpu_milli.is_none() && self.cpu_request_milli.is_none() && self.memory_request_bytes.is_none()
    }
}

const ROOT: &[u8] = b"/sys/fs/cgroup";
const SUPERVISOR: &[u8] = b"kr-supervisor";
const CPU_PERIOD_US: u64 = 100_000;

pub struct Cgroup {
    path: Vec<u8>,
    pub dir: Fd,
}

fn nul(parts: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    for p in parts {
        v.extend_from_slice(p);
    }
    v.push(0);
    v
}

fn read_small(path: &[u8]) -> Result<Vec<u8>, Errno> {
    let fd = ns::open(path, ns::O_RDONLY, 0)?;
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        match kr_sys::read(fd.raw(), &mut buf) {
            Ok(0) => return Ok(out),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(Errno(4)) => continue,
            Err(e) => return Err(e),
        }
        if out.len() > 64 * 1024 {
            return Err(Errno(27)); // EFBIG
        }
    }
}

fn dec(mut n: u64) -> Vec<u8> {
    let mut b = [0u8; 20];
    let mut i = b.len();
    loop {
        i -= 1;
        b[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    b[i..].to_vec()
}

/// Our cgroup v2 path from /proc/self/cgroup (the `0::` line).
fn own_path() -> Result<Vec<u8>, Errno> {
    let data = read_small(b"/proc/self/cgroup\0")?;
    data.split(|&b| b == b'\n')
        .find_map(|l| l.strip_prefix(b"0::"))
        .map(|p| p.to_vec())
        .ok_or(Errno(95)) // EOPNOTSUPP: no unified hierarchy
}

/// Directory under which container cgroups are created (moving kr into the supervisor leaf).
fn base() -> Result<Vec<u8>, Errno> {
    let mut rel = own_path()?;
    let mut sup_tail = b"/".to_vec();
    sup_tail.extend_from_slice(SUPERVISOR);
    let already = rel.ends_with(&sup_tail);
    if already {
        rel.truncate(rel.len() - sup_tail.len());
    }
    let mut base = ROOT.to_vec();
    if rel != b"/" {
        base.extend_from_slice(&rel);
    }
    if !already {
        let sup = nul(&[&base, b"/", SUPERVISOR]);
        match ns::mkdir(&sup, 0o755) {
            Ok(()) | Err(Errno(17)) => {}
            Err(e) => return Err(e),
        }
        // Move every process of the delegated cgroup (kr itself, and any wrapper such as a shell
        // under systemd-run) into the leaf, so `<base>` may enable controllers.
        let target = nul(&[&base, b"/", SUPERVISOR, b"/cgroup.procs"]);
        let procs = read_small(&nul(&[&base, b"/cgroup.procs"]))?;
        for pid in procs.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
            match ns::write_file(&target, pid) {
                Ok(()) | Err(Errno(3)) => {} // ESRCH: exited meanwhile
                Err(e) => return Err(e),
            }
        }
    }
    // Enabling controllers that are already enabled is a no-op.
    ns::write_file(&nul(&[&base, b"/cgroup.subtree_control"]), b"+cpu +memory +pids")?;
    Ok(base)
}

impl Cgroup {
    /// Creates `<base>/<name>` with `limits` applied.
    pub fn create(name: &[u8], limits: &Limits) -> Result<Cgroup, Errno> {
        Cgroup::create_in(b"", name, limits)
    }

    /// Creates `<base>/<parent>/<name>` (`parent` is a pod cgroup made by [`PodCgroup::create`],
    /// or empty for a flat container cgroup).
    pub fn create_in(parent: &[u8], name: &[u8], limits: &Limits) -> Result<Cgroup, Errno> {
        if name.is_empty() || name.iter().any(|&b| b == b'/' || b == 0) || name == b"." || name == b".." || name == SUPERVISOR {
            return Err(Errno(22));
        }
        let base = base()?;
        let mut path = base;
        if !parent.is_empty() {
            path.push(b'/');
            path.extend_from_slice(parent);
        }
        path.push(b'/');
        path.extend_from_slice(name);
        match ns::mkdir(&nul(&[&path]), 0o755) {
            Ok(()) | Err(Errno(17)) => {}
            Err(e) => return Err(e),
        }
        let cg = Cgroup { dir: ns::open(&nul(&[&path]), ns::O_RDONLY | ns::O_DIRECTORY, 0)?, path };
        if let Err(e) = cg.apply(limits) {
            cg.remove();
            return Err(e);
        }
        Ok(cg)
    }

    fn set(&self, file: &[u8], value: &[u8]) -> Result<(), Errno> {
        ns::write_file(&nul(&[&self.path, b"/", file]), value)
    }

    fn apply(&self, l: &Limits) -> Result<(), Errno> {
        if let Some(m) = l.memory_bytes {
            self.set(b"memory.max", &dec(m))?;
            // Without this the limit only bounds RAM, and the container just swaps.
            match self.set(b"memory.swap.max", b"0") {
                Ok(()) | Err(Errno(2)) => {}
                Err(e) => return Err(e),
            }
        }
        if let Some(p) = l.pids {
            self.set(b"pids.max", &dec(p))?;
        }
        if let Some(c) = l.cpu_milli {
            let quota = (c.saturating_mul(CPU_PERIOD_US) / 1000).max(1000);
            let mut v = dec(quota);
            v.push(b' ');
            v.extend_from_slice(&dec(CPU_PERIOD_US));
            self.set(b"cpu.max", &v)?;
        }
        if let Some(r) = l.cpu_request_milli {
            // Upstream: shares = milli * 1024 / 1000 (min 2), weight = 1 + (shares - 2) * 9999 / 262142.
            let shares = (r.saturating_mul(1024) / 1000).clamp(2, 262_144);
            self.set(b"cpu.weight", &dec(1 + (shares - 2) * 9999 / 262_142))?;
        }
        if let Some((file, v)) = l.memory_protection() {
            // Best effort: without the memory controller delegated (rootless) the file is missing
            // or not writable, which only means no reservation.
            match self.set(file, &dec(v)) {
                Ok(()) | Err(Errno(1)) | Err(Errno(2)) | Err(Errno(13)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Number of OOM kills recorded for this cgroup (memory.events `oom_kill`).
    pub fn oom_kills(&self) -> u64 {
        let Ok(ev) = read_small(&nul(&[&self.path, b"/memory.events"])) else { return 0 };
        ev.split(|&b| b == b'\n')
            .find_map(|l| l.strip_prefix(b"oom_kill "))
            .map(|v| v.iter().take_while(|b| b.is_ascii_digit()).fold(0u64, |a, &d| a * 10 + (d - b'0') as u64))
            .unwrap_or(0)
    }

    /// Removes the cgroup. It must be empty, which it is once the container's pid 1 has exited,
    /// since that tears down the whole pid namespace. Retries briefly while the kernel reaps it.
    pub fn remove(&self) {
        rmdir_retry(&self.path);
    }
}

fn rmdir_retry(path: &[u8]) {
    let p = nul(&[path]);
    for _ in 0..100 {
        match ns::rmdir(&p) {
            Err(Errno(16)) => {
                let ts = kr_sys::Timespec { tv_sec: 0, tv_nsec: 1_000_000 };
                let _ = ns::nanosleep(&ts);
            }
            _ => return,
        }
    }
}

/// Sums container limits for the pod cgroup: a limit is set only when every container has one.
pub fn sum_limits(containers: &[Limits]) -> Limits {
    let sum = |f: fn(&Limits) -> Option<u64>| -> Option<u64> {
        if containers.is_empty() {
            return None;
        }
        containers.iter().try_fold(0u64, |a, l| f(l).map(|v| a.saturating_add(v)))
    };
    Limits { memory_bytes: sum(|l| l.memory_bytes), pids: sum(|l| l.pids), cpu_milli: sum(|l| l.cpu_milli), ..Default::default() }
}

/// Path of a pod's cgroup relative to the delegated base, mirroring upstream's kubepods layout:
/// `kr-pods/<uid>` (Guaranteed), `kr-pods/burstable/<uid>`, `kr-pods/besteffort/<uid>`.
pub fn pod_rel_path(qos: &str, uid: &str) -> Vec<u8> {
    let mut v = b"kr-pods/".to_vec();
    match qos {
        "Burstable" => v.extend_from_slice(b"burstable/"),
        "BestEffort" => v.extend_from_slice(b"besteffort/"),
        _ => {}
    }
    v.extend_from_slice(uid.as_bytes());
    v
}

/// A pod's cgroup. It holds no processes itself: the sandbox lives in the `pause` leaf and each
/// container in its own child, so the pod cgroup may enable controllers for them.
pub struct PodCgroup {
    rel: Vec<u8>,
    path: Vec<u8>,
}

impl PodCgroup {
    /// Creates the pod cgroup (and `kr-pods` and QoS parents) with the summed `limits`.
    pub fn create(qos: &str, uid: &str, limits: &Limits) -> Result<PodCgroup, Errno> {
        if uid.is_empty() || uid.bytes().any(|b| b == b'/' || b == 0 || b == b'.') {
            return Err(Errno(22));
        }
        let rel = pod_rel_path(qos, uid);
        let mut path = base()?;
        for comp in rel.split(|&b| b == b'/') {
            path.push(b'/');
            path.extend_from_slice(comp);
            match ns::mkdir(&nul(&[&path]), 0o755) {
                Ok(()) | Err(Errno(17)) => {}
                Err(e) => return Err(e),
            }
            ns::write_file(&nul(&[&path, b"/cgroup.subtree_control"]), b"+cpu +memory +pids")?;
        }
        let pod = PodCgroup { rel, path };
        let cg = Cgroup { path: pod.path.clone(), dir: ns::open(&nul(&[&pod.path]), ns::O_RDONLY | ns::O_DIRECTORY, 0)? };
        if let Err(e) = cg.apply(limits) {
            pod.remove();
            return Err(e);
        }
        Ok(pod)
    }

    /// Path relative to the base; the `parent` argument of [`Cgroup::create_in`].
    pub fn rel(&self) -> &[u8] {
        &self.rel
    }

    /// Moves `pid` (the sandbox) into the pod's `pause` leaf.
    pub fn add_sandbox(&self, pid: i32) -> Result<(), Errno> {
        match ns::mkdir(&nul(&[&self.path, b"/pause"]), 0o755) {
            Ok(()) | Err(Errno(17)) => {}
            Err(e) => return Err(e),
        }
        ns::write_file(&nul(&[&self.path, b"/pause/cgroup.procs"]), &dec(pid as u64))
    }

    /// Current memory usage of the whole pod (memory.current).
    pub fn memory_current(&self) -> Option<u64> {
        let v = read_small(&nul(&[&self.path, b"/memory.current"])).ok()?;
        v.iter().take_while(|b| b.is_ascii_digit()).try_fold(0u64, |a, &d| a.checked_mul(10)?.checked_add((d - b'0') as u64))
    }

    /// Removes the (empty) pod cgroup and its `pause` leaf; the QoS parents stay.
    pub fn remove(&self) {
        let mut leaf = self.path.clone();
        leaf.extend_from_slice(b"/pause");
        rmdir_retry(&leaf);
        rmdir_retry(&self.path);
    }
}

/// Directories of the tree under `root`, children before their parent. `list` returns the
/// child directory paths of a directory.
fn post_order(root: &[u8], list: &dyn Fn(&[u8]) -> Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for child in list(root) {
        out.extend(post_order(&child, list));
    }
    out.push(root.to_vec());
    out
}

fn list_subdirs(path: &[u8]) -> Vec<Vec<u8>> {
    let Ok(fd) = ns::open(&nul(&[path]), ns::O_RDONLY | ns::O_DIRECTORY, 0) else { return Vec::new() };
    kr_sys::fs::read_dir(&fd)
        .filter_map(Result::ok)
        .filter(|e| e.kind == 4) // DT_DIR
        .map(|e| {
            let mut p = path.to_vec();
            p.push(b'/');
            p.extend_from_slice(&e.name);
            p
        })
        .collect()
}

/// Startup cleanup: kills every process left in the `kr-pods` tree by a previous kr run
/// (containers outlive a killed kubelet as orphans) and removes the cgroups. Does nothing when
/// cgroups are unavailable or not delegated.
pub fn kill_stale_pods() {
    let Ok(mut root) = base() else { return };
    root.extend_from_slice(b"/kr-pods");
    if ns::open(&nul(&[&root]), ns::O_RDONLY | ns::O_DIRECTORY, 0).is_err() {
        return;
    }
    let dirs = post_order(&root, &list_subdirs);
    for _ in 0..50 {
        let mut alive = false;
        for d in &dirs {
            // cgroup.kill (Linux 5.14+) kills the whole subtree; older kernels get SIGKILL per pid.
            if ns::write_file(&nul(&[d, b"/cgroup.kill"]), b"1").is_err() {
                if let Ok(procs) = read_small(&nul(&[d, b"/cgroup.procs"])) {
                    for pid in procs.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
                        let n = pid.iter().take_while(|b| b.is_ascii_digit()).fold(0i32, |a, &c| a * 10 + (c - b'0') as i32);
                        let _ = ns::kill(n, ns::SIGKILL);
                    }
                }
            }
            if read_small(&nul(&[d, b"/cgroup.procs"])).is_ok_and(|p| !p.is_empty()) {
                alive = true;
            }
        }
        if !alive {
            break;
        }
        let ts = kr_sys::Timespec { tv_sec: 0, tv_nsec: 20_000_000 };
        let _ = ns::nanosleep(&ts);
    }
    for d in &dirs {
        rmdir_retry(d);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn children_before_parents() {
        let list = |p: &[u8]| -> Vec<Vec<u8>> {
            match p {
                b"/r" => alloc::vec![b"/r/a".to_vec(), b"/r/b".to_vec()],
                b"/r/a" => alloc::vec![b"/r/a/x".to_vec()],
                _ => Vec::new(),
            }
        };
        let order = post_order(b"/r", &list);
        assert_eq!(order, alloc::vec![b"/r/a/x".to_vec(), b"/r/a".to_vec(), b"/r/b".to_vec(), b"/r".to_vec()]);
    }

    #[test]
    fn memory_protection_by_qos() {
        let mut l = Limits::default();
        assert_eq!(l.memory_protection(), None);
        l.memory_request_bytes = Some(0);
        assert_eq!(l.memory_protection(), None);
        l.memory_request_bytes = Some(1 << 20);
        assert_eq!(l.memory_protection(), Some((&b"memory.low"[..], 1 << 20)));
        l.memory_guaranteed = true;
        assert_eq!(l.memory_protection(), Some((&b"memory.min"[..], 1 << 20)));
        assert!(!l.is_empty());
    }

    #[test]
    fn pod_layout() {
        assert_eq!(pod_rel_path("Guaranteed", "u1"), b"kr-pods/u1");
        assert_eq!(pod_rel_path("Burstable", "u1"), b"kr-pods/burstable/u1");
        assert_eq!(pod_rel_path("BestEffort", "u1"), b"kr-pods/besteffort/u1");
    }

    #[test]
    fn summed_limits() {
        let a = Limits { memory_bytes: Some(100), cpu_milli: Some(500), pids: Some(10), ..Default::default() };
        let b = Limits { memory_bytes: Some(50), cpu_milli: None, pids: Some(10), ..Default::default() };
        let s = sum_limits(&[a, b]);
        assert_eq!((s.memory_bytes, s.cpu_milli, s.pids), (Some(150), None, Some(20)));
        assert!(sum_limits(&[]).is_empty());
    }
}
