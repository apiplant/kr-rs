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
}

impl Limits {
    pub fn is_empty(&self) -> bool {
        self.memory_bytes.is_none() && self.pids.is_none() && self.cpu_milli.is_none() && self.cpu_request_milli.is_none()
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
        if name.is_empty() || name.iter().any(|&b| b == b'/' || b == 0) || name == b"." || name == b".." || name == SUPERVISOR {
            return Err(Errno(22));
        }
        let base = base()?;
        let mut path = base;
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
        let p = nul(&[&self.path]);
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
}
