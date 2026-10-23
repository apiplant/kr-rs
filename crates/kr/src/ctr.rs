//! `kr ctr ...`: low-level container commands.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use kr_fmt::quantity::Quantity;
use kr_rt::{eprint, print, Args};
use kr_runtime::cgroup::Limits;
use kr_runtime::container::{self, IdMaps, Mount, RunSpec};
use kr_runtime::network::{self, NetConfig};
use kr_runtime::store::Store;
use kr_sys::ns;

const USAGE: &[u8] = b"usage:
  kr ctr pull <image>
  kr ctr run [--memory 64Mi] [--cpus 500m] [--pids 64] [--user uid[:gid]] <image> [--] [cmd args...]
  kr ctr run-dir [limits...] <rootfs> <state-dir> [--] <cmd> [args...]
";

const DEFAULT_PATH: &str = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

pub fn main(mut args: Args) -> i32 {
    match args.next() {
        Some(b"pull") => pull(args),
        Some(b"run") => run(args),
        Some(b"run-dir") => run_dir(args),
        Some(b"pod-demo") => pod_demo(args),
        _ => {
            eprint(USAGE);
            2
        }
    }
}

/// Parses leading limit flags and then `n` positional arguments; the rest is the command.
fn parse(args: &mut Args, n: usize) -> Result<(Limits, Option<&'static [u8]>, Vec<&'static [u8]>, Vec<Vec<u8>>), i32> {
    let mut limits = Limits::default();
    let mut user = None;
    let mut positional = Vec::new();
    while positional.len() < n {
        let Some(a) = args.next() else { break };
        if a == b"--user" {
            user = args.next();
            if user.is_none() {
                eprint(USAGE);
                return Err(2);
            }
            continue;
        }
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
            return Err(2);
        };
        let as_u64 = |v: Option<i128>| v.filter(|&v| v > 0).and_then(|v| u64::try_from(v).ok());
        match flag {
            b"--memory" => limits.memory_bytes = as_u64(q.value()),
            b"--cpus" => limits.cpu_milli = as_u64(q.milli_value()),
            _ => limits.pids = as_u64(q.value()),
        }
    }
    if positional.len() < n {
        eprint(USAGE);
        return Err(2);
    }
    let mut cmd: Vec<Vec<u8>> = args.map(|a| a.to_vec()).collect();
    if cmd.first().map(|a| a.as_slice()) == Some(b"--") {
        cmd.remove(0);
    }
    Ok((limits, user, positional, cmd))
}

fn utf8(b: &[u8]) -> Option<String> {
    core::str::from_utf8(b).ok().map(String::from)
}

fn open_store() -> Result<Store, i32> {
    Store::open(None).map_err(|e| fail(&format!("open store: {e:?}")))
}

fn pull(mut args: Args) -> i32 {
    let Some(image) = args.next().and_then(utf8) else {
        eprint(USAGE);
        return 2;
    };
    let store = match open_store() {
        Ok(s) => s,
        Err(c) => return c,
    };
    let r = kr_rt::exec::block_on(async move { kr_runtime::pull::pull(&store, &image).await });
    match r {
        Ok(id) => {
            print(format!("{id}\n").as_bytes());
            0
        }
        Err(e) => fail(&format!("pull: {e:?}")),
    }
}

fn container_id() -> String {
    format!("ctr-{}", kr_rt::exec::now_ns())
}

fn run(mut args: Args) -> i32 {
    let (limits, user, pos, override_cmd) = match parse(&mut args, 1) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let Some(image) = utf8(pos[0]) else { return fail("image reference is not UTF-8") };
    let store = match open_store() {
        Ok(s) => s,
        Err(c) => return c,
    };
    if store.image(&image).is_none() {
        let (s, i) = (store.clone(), image.clone());
        if let Err(e) = kr_rt::exec::block_on(async move { kr_runtime::pull::pull(&s, &i).await }) {
            return fail(&format!("pull: {e:?}"));
        }
    }
    let Some((_, cfg, mut rootfs)) = store.image(&image) else { return fail("image vanished after pull") };
    rootfs.pop(); // store returns it NUL-terminated

    // OCI semantics: entrypoint + (override or image cmd).
    let mut argv: Vec<Vec<u8>> = cfg.entrypoint.iter().map(|s| s.as_bytes().to_vec()).collect();
    if override_cmd.is_empty() {
        argv.extend(cfg.cmd.iter().map(|s| s.as_bytes().to_vec()));
    } else {
        argv.extend(override_cmd);
    }
    if argv.is_empty() {
        return fail("image has no entrypoint or cmd; pass a command");
    }
    let mut env: Vec<Vec<u8>> = cfg.env.iter().map(|s| s.as_bytes().to_vec()).collect();
    if !env.iter().any(|e| e.starts_with(b"PATH=")) {
        env.push(DEFAULT_PATH.as_bytes().to_vec());
    }

    let maps = IdMaps::for_current_user();
    let id = container_id();
    let lease = match bridge_network(&store, &id) {
        Ok(l) => l,
        Err(c) => return c,
    };
    let dirs = match store.create_container(&id) {
        Ok(d) => d,
        Err(e) => return fail(&format!("create container: {e:?}")),
    };
    let spec = RunSpec {
        rootfs: &rootfs,
        upper: dirs.upper.as_bytes(),
        work: dirs.work.as_bytes(),
        merged: dirs.merged.as_bytes(),
        argv: &argv,
        env: &env,
        cwd: cfg.working_dir.as_bytes(),
        hostname: id.as_bytes(),
        id: id.as_bytes(),
        limits,
        user: user.unwrap_or(cfg.user.as_bytes()),
        maps: &maps,
        net: lease.as_ref().map(|l| NetConfig { ip: l.ip, prefix: network::PREFIX, gateway: network::GATEWAY }),
        sandbox: None,
        mounts: &[],
        log_fd: None,
    };
    if let Some(l) = &lease {
        let ip = l.ip;
        eprint(format!("kr ctr: {id} at {}.{}.{}.{}\n", ip[0], ip[1], ip[2], ip[3]).as_bytes());
    }
    let code = supervise(&spec);
    if let Some(l) = lease {
        l.release();
    }
    // Files the container created belong to subordinate ids; delete from inside a userns
    // where they are mapped (and kr is root).
    let ok = match maps.run_as_root(|| store.delete_container(&id).is_ok()) {
        Ok(ok) => ok,
        // Mapping failed (e.g. newuidmap broken): nothing ran under subordinate ids, try directly.
        Err(_) => store.delete_container(&id).is_ok(),
    };
    if !ok {
        eprint(format!("kr ctr: warning: cleanup of {id} failed\n").as_bytes());
    }
    code
}

/// As real root, sets up the bridge (idempotent) and leases an address; rootless: no network.
fn bridge_network(store: &Store, id: &str) -> Result<Option<network::Lease>, i32> {
    if ns::getuid() != 0 {
        return Ok(None);
    }
    network::setup_host().map_err(|e| fail(&format!("network setup: errno {}", e.0)))?;
    let dir = format!("{}/ipam", store.root());
    match ns::mkdir(&nul(dir.as_bytes()), 0o700) {
        Ok(()) | Err(kr_sys::Errno(17)) => {}
        Err(e) => return Err(fail(&format!("mkdir ipam: errno {}", e.0))),
    }
    network::allocate(dir.as_bytes(), id.as_bytes()).map(Some).map_err(|e| fail(&format!("ipam: errno {}", e.0)))
}

/// Starts the container and waits for it, forwarding SIGINT/SIGTERM to its pid 1. A second
/// SIGINT kills it (pid 1 may have no handler, so the first one can be ignored).
fn supervise(spec: &RunSpec) -> i32 {
    let sigs = [ns::SIGINT, ns::SIGTERM];
    // Blocked so they arrive on the signalfd; the container child resets its mask before exec.
    if ns::sigprocmask(true, &sigs).is_err() {
        return fail("sigprocmask");
    }
    let sfd = ns::signalfd(&sigs);
    let running = match container::start(spec) {
        Ok(r) => r,
        Err(e) => return report(Err(e)),
    };
    let sig = running.signaller();
    let res = kr_rt::exec::block_on(async move {
        let fwd = sfd.ok().and_then(|fd| kr_rt::exec::Async::new(fd).ok()).map(|fd| {
            kr_rt::exec::spawn(async move {
                let mut interrupts = 0;
                loop {
                    match ns::signalfd_read(fd.get_ref()) {
                        Ok(s) => {
                            interrupts += (s == ns::SIGINT) as u32;
                            let _ = sig.send(if interrupts >= 2 { ns::SIGKILL } else { s });
                        }
                        Err(_) => fd.wait_readable().await,
                    }
                }
            })
        });
        let r = running.wait().await;
        if let Some(f) = fwd {
            f.abort();
        }
        r
    });
    let _ = ns::sigprocmask(false, &sigs);
    report(res)
}

fn report(r: Result<container::Exit, container::RunError>) -> i32 {
    match r {
        Ok(exit) => {
            if exit.oom_killed {
                eprint(b"kr ctr: container was OOM-killed\n");
            }
            exit.code
        }
        Err(e) if e.step == "set user" && e.errno.0 == 22 => fail(
            "set user: id not mapped. Rootless kr maps only your own uid unless /etc/subuid and \
             /etc/subgid give you a range (e.g. `usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $USER`)",
        ),
        Err(e) => fail(&format!("{}: errno {}", e.step, e.errno.0)),
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
    let (limits, user, pos, argv) = match parse(&mut args, 2) {
        Ok(v) => v,
        Err(c) => return c,
    };
    if argv.is_empty() {
        eprint(USAGE);
        return 2;
    }
    let (rootfs, state) = (pos[0], pos[1]);
    let (upper, work, merged) = (join(state, b"upper"), join(state, b"work"), join(state, b"merged"));
    for d in [state, &upper[..], &work[..], &merged[..]] {
        match ns::mkdir(&nul(d), 0o700) {
            Ok(()) | Err(kr_sys::Errno(17)) => {}
            Err(e) => return fail(&format!("mkdir state: errno {}", e.0)),
        }
    }
    let maps = IdMaps::for_current_user();
    let id = container_id();
    let env = [DEFAULT_PATH.as_bytes().to_vec(), b"HOME=/root".to_vec()];
    let spec = RunSpec {
        rootfs,
        upper: &upper,
        work: &work,
        merged: &merged,
        argv: &argv,
        env: &env,
        cwd: b"/",
        hostname: b"kr",
        id: id.as_bytes(),
        limits,
        user: user.unwrap_or(b""),
        maps: &maps,
        net: None,
        sandbox: None,
        mounts: &[],
        log_fd: None,
    };
    supervise(&spec)
}

fn fail(msg: &str) -> i32 {
    eprint(b"kr ctr: ");
    eprint(msg.as_bytes());
    eprint(b"\n");
    125
}

/// Dev check of pod semantics: two containers in one sandbox share localhost, the hostname and
/// a volume, but not their pid namespaces.
fn pod_demo(mut args: Args) -> i32 {
    let Some(image) = args.next().and_then(utf8) else {
        eprint(b"usage: kr ctr pod-demo <image with busybox httpd/wget>\n");
        return 2;
    };
    let store = match open_store() {
        Ok(s) => s,
        Err(c) => return c,
    };
    if store.image(&image).is_none() {
        let (s, i) = (store.clone(), image.clone());
        if let Err(e) = kr_rt::exec::block_on(async move { kr_runtime::pull::pull(&s, &i).await }) {
            return fail(&format!("pull: {e:?}"));
        }
    }
    let Some((_, _, mut rootfs)) = store.image(&image) else { return fail("image vanished") };
    rootfs.pop();
    let maps = IdMaps::for_current_user();
    let id = container_id();
    let sb = match container::start_sandbox(id.as_bytes(), b"demo-pod", &maps, None) {
        Ok(s) => s,
        Err(e) => return fail(&format!("sandbox: {}: errno {}", e.step, e.errno.0)),
    };
    let vol = format!("{}/containers/{id}-vol", store.root());
    let _ = ns::mkdir(&nul(vol.as_bytes()), 0o755);
    let mounts = [Mount { source: vol.clone().into_bytes(), target: b"/shared".to_vec(), readonly: false }];
    let env = [DEFAULT_PATH.as_bytes().to_vec()];
    let mk = |name: &str, argv: &[&str]| -> (String, Vec<Vec<u8>>) {
        (format!("{id}-{name}"), argv.iter().map(|a| a.as_bytes().to_vec()).collect())
    };
    let (id1, argv1) = mk("server", &["sh", "-c", "echo \"hello from $(hostname), server pid $$\" > /shared/index.html; exec httpd -f -p 127.0.0.1:8080 -h /shared"]);
    let (id2, argv2) = mk("client", &["sh", "-c", "sleep 0.3; wget -qO- http://127.0.0.1:8080/; echo \"client: hostname $(hostname), pid $$, sees $(ls /proc | grep -c '^[0-9]') processes\""]);
    let mut dirs = Vec::new();
    let mut started = Vec::new();
    for (cid, argv) in [(&id1, &argv1), (&id2, &argv2)] {
        let d = match store.create_container(cid) {
            Ok(d) => d,
            Err(e) => return fail(&format!("create container: {e:?}")),
        };
        let spec = RunSpec {
            rootfs: &rootfs,
            upper: d.upper.as_bytes(),
            work: d.work.as_bytes(),
            merged: d.merged.as_bytes(),
            argv,
            env: &env,
            cwd: b"/",
            hostname: b"",
            id: cid.as_bytes(),
            limits: Limits::default(),
            user: b"",
            maps: &maps,
            net: None,
            sandbox: Some(&sb),
            mounts: &mounts,
            log_fd: None,
        };
        match container::start(&spec) {
            Ok(r) => started.push(r),
            Err(e) => return fail(&format!("{cid}: {}: errno {}", e.step, e.errno.0)),
        }
        dirs.push(cid.clone());
    }
    let client = started.pop().unwrap();
    let server = started.pop().unwrap();
    let code = kr_rt::exec::block_on(async move {
        let r = client.wait().await;
        let _ = server.signaller().send(ns::SIGKILL);
        let _ = server.wait().await;
        r
    });
    sb.stop();
    let _ = maps.run_as_root(|| {
        dirs.iter().all(|d| store.delete_container(d).is_ok()) && {
            let (parent, name) = vol.rsplit_once('/').unwrap_or((".", vol.as_str()));
            ns::open(&nul(parent.as_bytes()), ns::O_RDONLY | ns::O_DIRECTORY, 0).is_ok_and(|fd| kr_sys::fs::remove_all(fd.raw(), &nul(name.as_bytes())).is_ok())
        }
    });
    report(code)
}
