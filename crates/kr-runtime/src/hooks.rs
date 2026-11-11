//! OCI runtime hooks (runtime-spec "Lifecycle"), as CDI specs and container runtimes use them.
//!
//! A hook is an executable started with the container state (`{ociVersion,id,status,pid,bundle}`)
//! as JSON on stdin and exactly the environment the hook lists. The bundle directory holds a
//! `config.json` whose `root.path` is the container's root filesystem; hooks such as NVIDIA's
//! `nvidia-cdi-hook` read it to find the rootfs they modify.
//!
//! * `createRuntime`    - runtime namespace, container namespaces exist, nothing mounted yet.
//! * `createContainer`  - the container's mount namespace with the rootfs and all volumes mounted,
//!   before the read-only remount and the exec. The host root is the hook's root and the container's
//!   root filesystem is mounted at `root.path`, as it is for runc.
//! * `startContainer`   - inside the container's root, right before the process is exec'd.
//! * `poststart`        - runtime namespace after the process started; failures are only logged.
//! * `poststop`         - runtime namespace after the container ended, when its directory is deleted
//!   (`Store::delete_container`); saved to `<bundle>/poststop.json` at start so it also runs after a
//!   kubelet restart. Failures are only logged.
//!
//! Hook output goes to `<bundle>/hooks.log`, not to the container's log.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use kr_sys::{ns, Errno, Fd};

/// Hooks time out after this long when they declare no timeout, so a stuck hook cannot hold a
/// container (and the kubelet) forever.
pub const DEFAULT_TIMEOUT_SECS: u32 = 120;

/// One hook entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Hook {
    /// Absolute path in the namespace the hook runs in.
    pub path: Vec<u8>,
    /// argv, `args[0]` included; empty means `[path]`.
    pub args: Vec<Vec<u8>>,
    /// `KEY=value`; the hook gets nothing else.
    pub env: Vec<Vec<u8>>,
    /// Seconds; 0 = default.
    pub timeout: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Hooks {
    pub create_runtime: Vec<Hook>,
    pub create_container: Vec<Hook>,
    pub start_container: Vec<Hook>,
    pub poststart: Vec<Hook>,
    pub poststop: Vec<Hook>,
}

/// No hooks.
pub static NONE: Hooks = Hooks { create_runtime: Vec::new(), create_container: Vec::new(), start_container: Vec::new(), poststart: Vec::new(), poststop: Vec::new() };

impl Hooks {
    pub fn is_empty(&self) -> bool {
        self.create_runtime.is_empty() && self.create_container.is_empty() && self.start_container.is_empty() && self.poststart.is_empty() && self.poststop.is_empty()
    }

    /// Files a hook under its OCI stage name; `prestart` (deprecated) runs as `createRuntime`.
    /// False for an unknown stage or a hook that cannot run.
    pub fn add(&mut self, stage: &str, h: Hook) -> bool {
        if h.path.first() != Some(&b'/') || h.path.contains(&0) || h.args.iter().chain(h.env.iter()).any(|a| a.contains(&0)) {
            return false;
        }
        match stage {
            "createRuntime" | "prestart" => self.create_runtime.push(h),
            "createContainer" => self.create_container.push(h),
            "startContainer" => self.start_container.push(h),
            "poststart" => self.poststart.push(h),
            "poststop" => self.poststop.push(h),
            _ => return false,
        }
        true
    }
}

fn json_str(out: &mut String, s: &[u8]) {
    out.push('"');
    for ch in String::from_utf8_lossy(s).chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn json_list(out: &mut String, items: &[Vec<u8>]) {
    out.push('[');
    for (i, a) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        json_str(out, a);
    }
    out.push(']');
}

/// The bundle directory of a container: the parent of its merged rootfs directory.
pub fn bundle_of(merged: &[u8]) -> Vec<u8> {
    let m = merged.strip_suffix(b"/").unwrap_or(merged);
    match m.iter().rposition(|&b| b == b'/') {
        Some(0) => b"/".to_vec(),
        Some(i) => m[..i].to_vec(),
        None => b".".to_vec(),
    }
}

/// The container state document passed to a hook on stdin.
pub fn state(id: &[u8], status: &str, pid: i32, bundle: &[u8]) -> Vec<u8> {
    let mut s = String::from("{\"ociVersion\":\"1.0.2\",\"id\":");
    json_str(&mut s, id);
    s.push_str(&format!(",\"status\":\"{status}\",\"pid\":{pid},\"bundle\":"));
    json_str(&mut s, bundle);
    s.push_str(",\"annotations\":{}}");
    s.into_bytes()
}

/// Writes `<bundle>/config.json` (root path, process, hostname). It can hold the container's
/// environment, so it is readable by root only.
pub fn write_bundle(bundle: &[u8], merged: &[u8], argv: &[Vec<u8>], env: &[Vec<u8>], cwd: &[u8], hostname: &[u8]) -> Result<(), Errno> {
    let mut s = String::from("{\"ociVersion\":\"1.0.2\",\"root\":{\"path\":");
    json_str(&mut s, merged);
    s.push_str("},\"process\":{\"args\":");
    json_list(&mut s, argv);
    s.push_str(",\"env\":");
    json_list(&mut s, env);
    s.push_str(",\"cwd\":");
    json_str(&mut s, if cwd.is_empty() { b"/" } else { cwd });
    s.push_str("},\"hostname\":");
    json_str(&mut s, hostname);
    s.push_str(",\"annotations\":{},\"linux\":{}}");
    let mut path = bundle.to_vec();
    path.extend_from_slice(b"/config.json\0");
    let fd = ns::open(&path, ns::O_WRONLY | ns::O_CREAT | 0o1000 /* O_TRUNC */, 0o600)?;
    let b = s.as_bytes();
    let mut off = 0;
    while off < b.len() {
        match kr_sys::write(fd.raw(), &b[off..]) {
            Ok(0) => return Err(Errno(5)),
            Ok(n) => off += n,
            Err(Errno(4)) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Saves the `poststop` hooks next to the bundle so whoever deletes the container runs them.
pub fn save_poststop(bundle: &[u8], id: &[u8], hooks: &[Hook]) -> Result<(), Errno> {
    if hooks.is_empty() {
        return Ok(());
    }
    let mut s = String::from("{\"id\":");
    json_str(&mut s, id);
    s.push_str(",\"hooks\":[");
    for (i, h) in hooks.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str("{\"path\":");
        json_str(&mut s, &h.path);
        s.push_str(",\"args\":");
        json_list(&mut s, &h.args);
        s.push_str(",\"env\":");
        json_list(&mut s, &h.env);
        s.push_str(&format!(",\"timeout\":{}}}", h.timeout));
    }
    s.push_str("]}");
    let mut path = bundle.to_vec();
    path.extend_from_slice(b"/poststop.json\0");
    let fd = ns::open(&path, ns::O_WRONLY | ns::O_CREAT | 0o1000, 0o600)?;
    write_all(fd.raw(), s.as_bytes());
    Ok(())
}

/// Runs and forgets the saved `poststop` hooks of the container whose bundle is `bundle`
/// (state `stopped`). Once only: the file goes first. Failures are written to hooks.log.
pub fn run_poststop(bundle: &[u8]) {
    let mut path = bundle.to_vec();
    path.extend_from_slice(b"/poststop.json\0");
    let Ok(b) = kr_sys::fs::read_file(&path, 1 << 20) else { return };
    let _ = kr_sys::fs::unlinkat(ns::AT_FDCWD, &path, 0);
    let Some(v) = core::str::from_utf8(&b).ok().and_then(|t| kr_fmt::json::parse_str(t).ok()) else { return };
    let strs = |h: &kr_fmt::json::Value, k: &str| -> Vec<Vec<u8>> { h.get(k).and_then(|a| a.as_array()).unwrap_or(&[]).iter().filter_map(|x| x.as_str()).map(|x| x.as_bytes().to_vec()).collect() };
    let hooks: Vec<Hook> = v
        .get("hooks")
        .and_then(|a| a.as_array())
        .unwrap_or(&[])
        .iter()
        .map(|h| Hook { path: h.get("path").and_then(|p| p.as_str()).unwrap_or("").as_bytes().to_vec(), args: strs(h, "args"), env: strs(h, "env"), timeout: h.get("timeout").and_then(|t| t.as_u64()).unwrap_or(0) as u32 })
        .filter(|h| h.path.first() == Some(&b'/'))
        .collect();
    let id = v.get("id").and_then(|i| i.as_str()).unwrap_or("").as_bytes().to_vec();
    let log = open_log(bundle);
    let st = state(&id, "stopped", 0, bundle);
    let _ = run_all(&hooks, &st, None, log.as_ref());
}

/// Opens `<bundle>/hooks.log` for appending (close-on-exec).
pub fn open_log(bundle: &[u8]) -> Option<Fd> {
    let mut path = bundle.to_vec();
    path.extend_from_slice(b"/hooks.log\0");
    ns::open(&path, ns::O_WRONLY | ns::O_CREAT | 0o2000 /* O_APPEND */, 0o600).ok()
}

/// The last `max` bytes of `<bundle>/hooks.log`, for error messages.
pub fn log_tail(bundle: &[u8], max: usize) -> String {
    let mut path = bundle.to_vec();
    path.extend_from_slice(b"/hooks.log\0");
    let b = kr_sys::fs::read_file(&path, 1 << 20).unwrap_or_default();
    let b = &b[b.len().saturating_sub(max)..];
    String::from_utf8_lossy(b).trim().into()
}

/// Why a hook did not succeed.
#[derive(Debug, PartialEq, Eq)]
pub enum Fail {
    /// Could not be started (fork/pipe).
    Start(Errno),
    /// Exited with this shell-style status (127 = exec failed).
    Exit(i32),
    TimedOut,
}

impl Fail {
    /// A value for the child-to-parent error report.
    pub fn errno(&self) -> Errno {
        match self {
            Fail::Start(e) => *e,
            Fail::Exit(c) => Errno(*c),
            Fail::TimedOut => Errno(110),
        }
    }
}

fn nul(v: &[u8]) -> Vec<u8> {
    let mut o = v.to_vec();
    o.push(0);
    o
}

fn write_all(fd: i32, mut b: &[u8]) {
    while !b.is_empty() {
        match kr_sys::write(fd, b) {
            Ok(0) => return,
            Ok(n) => b = &b[n..],
            Err(Errno(4)) => {}
            Err(_) => return,
        }
    }
}

/// Runs one hook to completion. With `root`, the hook's root directory is `root` (it must exist in
/// the caller's mount namespace). Output goes to `log` (or is dropped).
pub fn run_one(h: &Hook, state: &[u8], root: Option<&[u8]>, log: Option<&Fd>) -> Result<(), Fail> {
    let (in_r, in_w) = kr_sys::pipe2(kr_sys::O_CLOEXEC).map_err(Fail::Start)?;
    let path = nul(&h.path);
    let argv_c: Vec<Vec<u8>> = if h.args.is_empty() { alloc::vec![nul(&h.path)] } else { h.args.iter().map(|a| nul(a)).collect() };
    let mut argv: Vec<*const u8> = argv_c.iter().map(|a| a.as_ptr()).collect();
    argv.push(core::ptr::null());
    let env_c: Vec<Vec<u8>> = h.env.iter().map(|a| nul(a)).collect();
    let mut envp: Vec<*const u8> = env_c.iter().map(|a| a.as_ptr()).collect();
    envp.push(core::ptr::null());
    let root_c = root.map(nul);
    let null = if log.is_none() { ns::open(b"/dev/null\0", ns::O_WRONLY, 0).ok() } else { None };

    let mut pidfd: i32 = -1;
    let mut args = ns::CloneArgs { flags: ns::CLONE_PIDFD, exit_signal: ns::SIGCHLD as u64, pidfd: &mut pidfd as *mut i32 as u64, ..Default::default() };
    // SAFETY: the runtime is single-threaded (ADR-005); the child only makes syscalls and execs.
    let pid = unsafe { ns::clone3(&mut args) }.map_err(Fail::Start)?;
    if pid == 0 {
        let _ = ns::sigmask_reset();
        let _ = ns::dup_to(in_r.raw(), 0);
        let out = log.map(|l| l.raw()).or(null.as_ref().map(|n| n.raw()));
        if let Some(o) = out {
            let _ = ns::dup_to(o, 1);
            let _ = ns::dup_to(o, 2);
        }
        if let Some(r) = &root_c {
            if ns::chroot(r).is_err() {
                kr_sys::exit_group(126);
            }
        }
        if ns::chdir(b"/\0").is_err() {
            kr_sys::exit_group(126);
        }
        let _ = ns::execve(&path, &argv, &envp);
        kr_sys::exit_group(127);
    }
    let pidfd = Fd(pidfd);
    drop(in_r);
    write_all(in_w.raw(), state);
    drop(in_w);
    let secs = if h.timeout == 0 { DEFAULT_TIMEOUT_SECS } else { h.timeout };
    let deadline_ms = secs.saturating_mul(1000).min(i32::MAX as u32) as i32;
    let mut waited = 0;
    let finished = loop {
        // Polls in slices so an EINTR does not restart the full timeout.
        match ns::poll2(pidfd.raw(), -1, 1000) {
            Ok((true, _, _)) | Ok((_, _, true)) => break true,
            Ok(_) | Err(Errno(4)) => {
                waited += 1000;
                if waited >= deadline_ms {
                    break false;
                }
            }
            Err(_) => break false,
        }
    };
    if !finished {
        let _ = ns::kill(pid, ns::SIGKILL);
        let _ = ns::wait4(pid);
        return Err(Fail::TimedOut);
    }
    let code = ns::exit_code(ns::wait4(pid).unwrap_or(0));
    if code == 0 {
        Ok(())
    } else {
        Err(Fail::Exit(code))
    }
}

/// Runs `hooks` in order; the first failure stops the list. A line describing it goes to `log`.
pub fn run_all(hooks: &[Hook], state: &[u8], root: Option<&[u8]>, log: Option<&Fd>) -> Result<(), Fail> {
    for h in hooks {
        if let Err(f) = run_one(h, state, root, log) {
            if let Some(l) = log {
                let what = match &f {
                    Fail::Start(e) => format!("could not start (errno {})", e.0),
                    Fail::Exit(127) => String::from("could not be executed (exit 127)"),
                    Fail::Exit(c) => format!("exited with status {c}"),
                    Fail::TimedOut => String::from("timed out"),
                };
                write_all(l.raw(), format!("kr: hook {} {what}\n", String::from_utf8_lossy(&h.path)).as_bytes());
            }
            return Err(f);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_is_parent_of_merged() {
        assert_eq!(bundle_of(b"/var/lib/kr/c1/merged"), b"/var/lib/kr/c1");
        assert_eq!(bundle_of(b"/merged"), b"/");
    }

    #[test]
    fn state_is_json() {
        let s = state(b"abc", "creating", 42, b"/b\"x");
        assert_eq!(core::str::from_utf8(&s).unwrap(), r#"{"ociVersion":"1.0.2","id":"abc","status":"creating","pid":42,"bundle":"/b\"x","annotations":{}}"#);
    }

    #[test]
    fn stages_and_validation() {
        let mut h = Hooks::default();
        let ok = |p: &str| Hook { path: p.as_bytes().to_vec(), ..Default::default() };
        assert!(h.add("createContainer", ok("/bin/true")));
        assert!(h.add("prestart", ok("/bin/true")));
        assert!(!h.add("createContainer", ok("relative")));
        assert!(h.add("poststop", ok("/bin/true")));
        assert!(!h.add("nonsense", ok("/bin/true")));
        assert_eq!((h.create_container.len(), h.create_runtime.len()), (1, 1));
    }

    #[test]
    fn runs_with_state_on_stdin_and_exact_env() {
        let dir = format!("/tmp/kr-hooks-test-{}", kr_sys::fs::getpid());
        let _ = ns::mkdir(format!("{dir}\0").as_bytes(), 0o700);
        let rd = |f: &str| String::from_utf8(kr_sys::fs::read_file(format!("{dir}/{f}\0").as_bytes(), 4096).unwrap()).unwrap();
        let hook = Hook {
            path: b"/bin/sh".to_vec(),
            args: alloc::vec![b"sh".to_vec(), b"-c".to_vec(), format!("cat > {dir}/stdin; echo \"$A\" > {dir}/env; env | grep -c \"^\\(PATH\\|HOME\\|USER\\)=\" > {dir}/count; true").into_bytes()],
            env: alloc::vec![b"A=1".to_vec()],
            timeout: 0,
        };
        let st = state(b"c", "created", 7, b"/b");
        assert_eq!(run_one(&hook, &st, None, None), Ok(()));
        assert_eq!(rd("stdin").as_bytes(), st);
        assert_eq!(rd("env"), "1\n");
        assert_eq!(rd("count").trim(), "0", "the hook gets only the env it lists");
        let fail = Hook { path: b"/bin/sh".to_vec(), args: alloc::vec![b"sh".to_vec(), b"-c".to_vec(), b"exit 3".to_vec()], ..Default::default() };
        assert_eq!(run_one(&fail, &st, None, None), Err(Fail::Exit(3)));
        let missing = Hook { path: b"/nonexistent/hook".to_vec(), ..Default::default() };
        assert_eq!(run_one(&missing, &st, None, None), Err(Fail::Exit(127)));
        let slow = Hook { path: b"/bin/sleep".to_vec(), args: alloc::vec![b"sleep".to_vec(), b"30".to_vec()], timeout: 1, ..Default::default() };
        assert_eq!(run_one(&slow, &st, None, None), Err(Fail::TimedOut));
    }
}
