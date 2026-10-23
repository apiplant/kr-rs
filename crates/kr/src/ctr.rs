//! `kr ctr ...`: low-level container commands.

use alloc::vec::Vec;
use kr_rt::{eprint, fmt_u64, Args};
use kr_runtime::container::{self, RunSpec};
use kr_sys::ns;

const USAGE: &[u8] = b"usage: kr ctr run-dir <rootfs> <state-dir> [--] <cmd> [args...]\n";

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
    let (Some(rootfs), Some(state)) = (args.next(), args.next()) else {
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
    };
    match container::run(&spec) {
        Ok(code) => code,
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
