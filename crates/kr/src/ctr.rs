//! `kr ctr ...`: low-level container commands.

use alloc::vec::Vec;
use kr_fmt::quantity::Quantity;
use kr_rt::{eprint, fmt_u64, Args};
use kr_runtime::cgroup::Limits;
use kr_runtime::container::{self, RunSpec};
use kr_sys::ns;

const USAGE: &[u8] = b"usage: kr ctr run-dir [--memory 64Mi] [--cpus 500m] [--pids 64] <rootfs> <state-dir> [--] <cmd> [args...]\n";

pub fn main(mut args: Args) -> i32 {
    match args.next() {
        Some(b"run-dir") => run_dir(args),
        _ => {
            eprint(USAGE);
            2
        }
    }
}

fn join(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut v = a.to_vec();
    v.push(b'/');
    v.extend_from_slice(b);
    v
}

fn nul(p: &[u8]) -> Vec<u8> {
    let mut v = p.to_vec();
    v.push(0);
    v
}

/// Dev command: run a container from a plain directory, without the image store.
fn run_dir(mut args: Args) -> i32 {
    let mut limits = Limits::default();
    let mut positional = Vec::new();
    while positional.len() < 2 {
        let Some(a) = args.next() else { break };
        let flag = match a {
            b"--memory" | b"--cpus" | b"--pids" => a,
            _ => {
                positional.push(a);
                continue;
            }
        };
        let Some(q) = args.next().and_then(|v| core::str::from_utf8(v).ok()).and_then(|v| Quantity::parse(v).ok()) else {
            eprint(b"kr ctr: bad quantity for ");
            eprint(flag);
            eprint(b"\n");
            return 2;
        };
        let as_u64 = |v: Option<i128>| v.filter(|&v| v > 0).and_then(|v| u64::try_from(v).ok());
        match flag {
            b"--memory" => limits.memory_bytes = as_u64(q.value()),
            b"--cpus" => limits.cpu_milli = as_u64(q.milli_value()),
            _ => limits.pids = as_u64(q.value()),
        }
    }
    let (Some(&rootfs), Some(&state)) = (positional.first(), positional.get(1)) else {
        eprint(USAGE);
        return 2;
    };
    let mut argv: Vec<Vec<u8>> = args.map(|a| a.to_vec()).collect();
    if argv.first().map(|a| a.as_slice()) == Some(b"--") {
        argv.remove(0);
    }
    if argv.is_empty() {
        eprint(USAGE);
        return 2;
    }
    let (upper, work, merged) = (join(state, b"upper"), join(state, b"work"), join(state, b"merged"));
    for d in [state, &upper[..], &work[..], &merged[..]] {
        match ns::mkdir(&nul(d), 0o700) {
            Ok(()) | Err(kr_sys::Errno(17)) => {}
            Err(e) => return fail(b"mkdir state", e.0),
        }
    }
    let mut id = b"ctr-".to_vec();
    id.extend_from_slice(fmt_u64(kr_rt::exec::now_ns(), &mut [0u8; 20]));
    let env = [b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_vec(), b"HOME=/root".to_vec()];
    let spec = RunSpec {
        rootfs,
        upper: &upper,
        work: &work,
        merged: &merged,
        argv: &argv,
        env: &env,
        cwd: b"/",
        hostname: b"kr",
        id: &id,
        limits,
    };
    match container::run(&spec) {
        Ok(exit) => {
            if exit.oom_killed {
                eprint(b"kr ctr: container was OOM-killed\n");
            }
            exit.code
        }
        Err(e) => fail(e.step.as_bytes(), e.errno.0),
    }
}

fn fail(step: &[u8], errno: i32) -> i32 {
    eprint(b"kr ctr: ");
    eprint(step);
    eprint(b": errno ");
    eprint(fmt_u64(errno as u64, &mut [0u8; 20]));
    eprint(b"\n");
    125
}
