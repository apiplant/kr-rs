//! Container probes (liveness, readiness, startup): exec, tcpSocket, httpGet and grpc, with the
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

/// Reads exactly `buf.len()` bytes; false on EOF, error or timeout.
fn read_full(fd: i32, buf: &mut [u8]) -> bool {
    let mut got = 0;
    while got < buf.len() {
        match kr_sys::read(fd, &mut buf[got..]) {
            Ok(0) | Err(_) => return false,
            Ok(n) => got += n,
        }
    }
    true
}

/// One HTTP/2 frame: 9-byte header, then the payload.
fn h2_frame(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len() as u32;
    let mut f = alloc::vec![(n >> 16) as u8, (n >> 8) as u8, n as u8, ty, flags];
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// HPACK literal header field without indexing (plain strings, under 127 bytes each).
fn hpack_literal(out: &mut Vec<u8>, name_index: u8, name: &str, value: &str) {
    out.push(name_index);
    if name_index == 0 {
        out.push(name.len() as u8);
        out.extend_from_slice(name.as_bytes());
    }
    out.push(value.len() as u8);
    out.extend_from_slice(value.as_bytes());
}

/// gRPC health check (`grpc.health.v1.Health/Check`) over cleartext HTTP/2 with prior knowledge,
/// run in the pod netns. Success is a SERVING response. Returns the process exit code.
fn grpc_check(port: u16, service: &str, timeout_ms: u64) -> i32 {
    let Ok(fd) = kr_sys::socket(kr_sys::AF_INET, kr_sys::SOCK_STREAM | kr_sys::SOCK_CLOEXEC, 0) else { return 1 };
    let mut tv = [0u8; 16];
    tv[..8].copy_from_slice(&((timeout_ms / 1000) as i64).to_ne_bytes());
    tv[8..].copy_from_slice(&(((timeout_ms % 1000) * 1000) as i64).to_ne_bytes());
    let _ = kr_sys::setsockopt(fd.raw(), 1, 20, &tv); // SO_RCVTIMEO
    let _ = kr_sys::setsockopt(fd.raw(), 1, 21, &tv); // SO_SNDTIMEO
    if kr_sys::connect(fd.raw(), &kr_sys::SockaddrIn::new([127, 0, 0, 1], port)).is_err() {
        return 1;
    }
    let mut hdrs = Vec::new();
    hdrs.push(0x83); // :method POST
    hdrs.push(0x86); // :scheme http
    hpack_literal(&mut hdrs, 0x04, "", "/grpc.health.v1.Health/Check");
    hpack_literal(&mut hdrs, 0x01, "", &alloc::format!("127.0.0.1:{port}"));
    hpack_literal(&mut hdrs, 0x00, "content-type", "application/grpc");
    hpack_literal(&mut hdrs, 0x00, "te", "trailers");
    hpack_literal(&mut hdrs, 0x00, "user-agent", "kube-probe/1.37");
    // HealthCheckRequest { string service = 1 } in a gRPC length-prefixed message.
    let mut msg = alloc::vec![0u8; 5];
    if !service.is_empty() {
        msg.push(0x0a);
        let mut n = service.len();
        while n >= 0x80 {
            msg.push((n as u8 & 0x7f) | 0x80);
            n >>= 7;
        }
        msg.push(n as u8);
        msg.extend_from_slice(service.as_bytes());
    }
    let len = (msg.len() - 5) as u32;
    msg[1..5].copy_from_slice(&len.to_be_bytes());
    let mut out = Vec::from(&b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..]);
    out.extend(h2_frame(0x4, 0, 0, &[]));
    out.extend(h2_frame(0x1, 0x4, 1, &hdrs));
    out.extend(h2_frame(0x0, 0x1, 1, &msg));
    if kr_sys::write(fd.raw(), &out).is_err() {
        return 1;
    }
    let mut data = Vec::new();
    for _ in 0..64 {
        let mut h = [0u8; 9];
        if !read_full(fd.raw(), &mut h) {
            return 1;
        }
        let n = (h[0] as usize) << 16 | (h[1] as usize) << 8 | h[2] as usize;
        let stream = u32::from_be_bytes([h[5] & 0x7f, h[6], h[7], h[8]]);
        let mut payload = alloc::vec![0u8; n];
        if n > (1 << 16) || !read_full(fd.raw(), &mut payload) {
            return 1;
        }
        match (h[3], stream) {
            (0x4, 0) if h[4] & 1 == 0 => {
                let _ = kr_sys::write(fd.raw(), &h2_frame(0x4, 1, 0, &[]));
            }
            (0x0, 1) => data.extend_from_slice(&payload),
            (0x3 | 0x7, _) => return 1, // RST_STREAM, GOAWAY
            _ => {}
        }
        if stream == 1 && h[4] & 1 != 0 && matches!(h[3], 0x0 | 0x1) {
            break; // END_STREAM
        }
    }
    // [0][len: 4][HealthCheckResponse { status = 1 }]: SERVING is 1.
    if data.len() >= 7 && data[0] == 0 && data[5] == 0x08 && data[6] == 1 {
        0
    } else {
        1
    }
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
    } else if let Some(g) = spec.get("grpc") {
        let (Some(target), Some(p)) = (pod_target, g.get("port").and_then(Value::as_u64).and_then(|v| u16::try_from(v).ok())) else { return false };
        let service = String::from(g.get("service").and_then(Value::as_str).unwrap_or(""));
        container::in_pod_net(target, move || grpc_check(p, &service, timeout_ms))
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
