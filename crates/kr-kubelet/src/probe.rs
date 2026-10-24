//! Container probes (liveness, readiness, startup): exec, tcpSocket and httpGet, with the
//! upstream threshold/period/timeout semantics. Network probes run inside the pod's network
//! namespace (so they work without a pod IP, i.e. rootless); exec probes run inside the
//! container with the same privilege drop as its processes.

use alloc::string::String;
use alloc::vec::Vec;
use kr_fmt::json::Value;
use kr_runtime::container::{self, ExecSpec, ExecTarget, IdMaps};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Startup,
    Liveness,
    Readiness,
}

impl Kind {
    pub fn field(self) -> &'static str {
        match self {
            Kind::Startup => "startupProbe",
            Kind::Liveness => "livenessProbe",
            Kind::Readiness => "readinessProbe",
        }
    }
}

/// Per-probe bookkeeping.
pub struct State {
    pub spec: Value,
    pub next_at: u64,
    pub successes: u32,
    pub failures: u32,
    pub in_flight: bool,
}

fn num(p: &Value, f: &str, default: u64) -> u64 {
    p.get(f).and_then(Value::as_u64).unwrap_or(default)
}

impl State {
    pub fn new(spec: Value, started_ms: u64) -> State {
        let delay = num(&spec, "initialDelaySeconds", 0) * 1000;
        State { spec, next_at: started_ms + delay, successes: 0, failures: 0, in_flight: false }
    }
    pub fn period_ms(&self) -> u64 {
        num(&self.spec, "periodSeconds", 10).max(1) * 1000
    }
    pub fn timeout_ms(&self) -> u64 {
        num(&self.spec, "timeoutSeconds", 1).max(1) * 1000
    }
    pub fn success_threshold(&self) -> u32 {
        num(&self.spec, "successThreshold", 1).max(1) as u32
    }
    pub fn failure_threshold(&self) -> u32 {
        num(&self.spec, "failureThreshold", 3).max(1) as u32
    }
    /// Records a result; returns Some(verdict) when a threshold is crossed.
    pub fn record(&mut self, ok: bool, now: u64) -> Option<bool> {
        self.in_flight = false;
        self.next_at = now + self.period_ms();
        if ok {
            self.failures = 0;
            self.successes += 1;
            (self.successes >= self.success_threshold()).then_some(true)
        } else {
            self.successes = 0;
            self.failures += 1;
            (self.failures >= self.failure_threshold()).then_some(false)
        }
    }
}

/// Resolves an int-or-string port against the container's named ports.
fn port(p: &Value, ctr: &Value) -> Option<u16> {
    match p.get("port")? {
        Value::Number(n) => n.as_u64().and_then(|v| u16::try_from(v).ok()),
        Value::String(s) => match s.parse::<u16>() {
            Ok(v) => Some(v),
            Err(_) => ctr.get("ports")?.as_array()?.iter().find(|cp| cp.get("name").and_then(Value::as_str) == Some(s))?.get("containerPort")?.as_u64().and_then(|v| u16::try_from(v).ok()),
        },
        _ => None,
    }
}

/// Blocking TCP connect (and optional HTTP GET) with timeouts; runs in the pod netns child.
/// Returns the process exit code: 0 success, 1 failure.
fn net_check(host: [u8; 4], port: u16, http_path: Option<&str>, timeout_ms: u64) -> i32 {
    let Ok(fd) = kr_sys::socket(kr_sys::AF_INET, kr_sys::SOCK_STREAM | kr_sys::SOCK_CLOEXEC, 0) else { return 1 };
    // struct timeval { tv_sec, tv_usec }: bounds connect (SO_SNDTIMEO) and reads.
    let mut tv = [0u8; 16];
    tv[..8].copy_from_slice(&((timeout_ms / 1000) as i64).to_ne_bytes());
    tv[8..].copy_from_slice(&(((timeout_ms % 1000) * 1000) as i64).to_ne_bytes());
    let _ = kr_sys::setsockopt(fd.raw(), 1, 20, &tv); // SO_RCVTIMEO
    let _ = kr_sys::setsockopt(fd.raw(), 1, 21, &tv); // SO_SNDTIMEO
    if kr_sys::connect(fd.raw(), &kr_sys::SockaddrIn::new(host, port)).is_err() {
        return 1;
    }
    let Some(path) = http_path else { return 0 };
    let req = alloc::format!("GET {path} HTTP/1.1\r\nHost: {}.{}.{}.{}:{port}\r\nUser-Agent: kube-probe/1.37\r\nAccept: */*\r\nConnection: close\r\n\r\n", host[0], host[1], host[2], host[3]);
    if kr_sys::write(fd.raw(), req.as_bytes()).is_err() {
        return 1;
    }
    let mut buf = [0u8; 64];
    let mut got = 0;
    while got < 12 {
        match kr_sys::read(fd.raw(), &mut buf[got..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n,
        }
    }
    // "HTTP/1.x NNN": success for 200..=399.
    let line = &buf[..got];
    if line.len() >= 12 && line.starts_with(b"HTTP/1.") {
        if let Ok(code) = core::str::from_utf8(&line[9..12]).unwrap_or("").parse::<u16>() {
            return if (200..400).contains(&code) { 0 } else { 1 };
        }
    }
    1
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut it = s.split('.');
    for o in out.iter_mut() {
        *o = it.next()?.parse().ok()?;
    }
    it.next().is_none().then_some(out)
}

/// Runs a lifecycle hook handler (`exec`, `httpGet`, `tcpSocket` or `sleep`); true = success.
pub async fn run_handler(spec: &Value, ctr: &Value, ctr_target: &ExecTarget, pod_target: Option<&ExecTarget>, maps: &IdMaps, timeout_ms: u64) -> bool {
    if let Some(s) = spec.get("sleep") {
        let secs = s.get("seconds").and_then(Value::as_u64).unwrap_or(0);
        kr_rt::exec::sleep((secs * 1000).min(timeout_ms)).await;
        return true;
    }
    run(spec, ctr, ctr_target, pod_target, maps, timeout_ms).await
}

/// Runs one probe; true = success. `ctr_target` enters the container (exec probes),
/// `pod_target` the pod network (tcp/http probes).
pub async fn run(spec: &Value, ctr: &Value, ctr_target: &ExecTarget, pod_target: Option<&ExecTarget>, maps: &IdMaps, timeout_ms: u64) -> bool {
    let started = if let Some(e) = spec.get("exec") {
        let argv: Vec<Vec<u8>> = e.get("command").and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(Value::as_str).map(|s| s.as_bytes().to_vec()).collect();
        if argv.is_empty() {
            return false;
        }
        let env = [b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_vec()];
        let user = ctr.pointer(&["securityContext", "runAsUser"]).and_then(Value::as_i64).map(|u| alloc::format!("{u}")).unwrap_or_default();
        container::exec_in(ctr_target, &ExecSpec { argv: &argv, env: &env, cwd: b"/", user: user.as_bytes(), stdin: None, stdout: None, stderr: None, maps, extra_groups: &[] })
    } else {
        let (net, path): (Option<&Value>, Option<String>) = if let Some(h) = spec.get("httpGet") {
            (Some(h), Some(String::from(h.get("path").and_then(Value::as_str).unwrap_or("/"))))
        } else {
            (spec.get("tcpSocket"), None)
        };
        let (Some(net), Some(target)) = (net, pod_target) else { return false };
        // HTTPS probes skip TLS (upstream does not verify the certificate either); a TCP
        // connect plus a plaintext GET would fail, so treat them as TCP probes.
        let https = net.get("scheme").and_then(Value::as_str) == Some("HTTPS");
        let Some(p) = port(net, ctr) else { return false };
        let path = if https { None } else { path };
        // `host` (an IP) defaults to the pod itself.
        let host = net.get("host").and_then(Value::as_str).and_then(parse_ipv4).unwrap_or([127, 0, 0, 1]);
        container::in_pod_net(target, move || net_check(host, p, path.as_deref(), timeout_ms))
    };
    let Ok(running) = started else { return false };
    let (sig, pid) = (running.signaller(), running.pid);
    match kr_rt::exec::timeout(timeout_ms + 500, running.wait()).await {
        Ok(Ok(exit)) => exit.code == 0,
        Ok(Err(_)) => false,
        Err(_) => {
            // Timed out: kill it and reap it here (the dropped wait future no longer will).
            let _ = sig.send(kr_sys::ns::SIGKILL);
            let _ = kr_sys::ns::wait4(pid);
            false
        }
    }
}
