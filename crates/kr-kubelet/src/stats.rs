//! Resource usage of the node and its containers (ADR-048): the kubelet resource-metrics endpoint
//! `GET /metrics/resource` (Prometheus text, what metrics-server and the API server's
//! `metrics.k8s.io` ([`kr_apiserver::metrics`]) scrape) and a subset of `GET /stats/summary`.
//!
//! CPU is cumulative (cgroup v2 `cpu.stat` `usage_usec`; node: `/proc/stat` busy time), memory is
//! the working set (`memory.current` minus `inactive_file`; node: `MemTotal - MemAvailable`).
//! Containers are only measured when kr has a delegated cgroup (`Config::cgroups`).

use crate::{CState, Client, Kubelet};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use kr_apiserver::object::{obj, ApiError};
use kr_fmt::json::{self, Value};
use kr_net::http1::server::{Body, Response};

/// One container's usage.
#[derive(Debug, Clone, PartialEq)]
pub struct CtrStat {
    pub ns: String,
    pub pod: String,
    pub container: String,
    pub cpu_secs: f64,
    pub mem: u64,
}

/// A measurement of the node and its containers at `ts_ms`.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Sample {
    pub ts_ms: i64,
    pub node_cpu: Option<f64>,
    pub node_mem: Option<u64>,
    pub ctrs: Vec<CtrStat>,
}

fn num(s: &[u8]) -> Option<u64> {
    let d: Vec<u8> = s.iter().copied().skip_while(|b| *b == b' ').take_while(|b| b.is_ascii_digit()).collect();
    core::str::from_utf8(&d).ok()?.parse().ok()
}

/// Busy CPU seconds from the aggregate `cpu` line of `/proc/stat` (USER_HZ = 100).
pub fn parse_proc_stat(text: &str) -> Option<f64> {
    let l = text.lines().find(|l| l.starts_with("cpu "))?;
    let f: Vec<u64> = l.split_whitespace().skip(1).filter_map(|x| x.parse().ok()).collect();
    // user nice system idle iowait irq softirq steal: everything but idle and iowait.
    let busy = f.first()? + f.get(1)? + f.get(2)? + f.get(5).copied().unwrap_or(0) + f.get(6).copied().unwrap_or(0) + f.get(7).copied().unwrap_or(0);
    Some(busy as f64 / 100.0)
}

/// Bytes in use: `MemTotal - MemAvailable` of `/proc/meminfo`.
pub fn parse_meminfo(text: &str) -> Option<u64> {
    let field = |n: &str| text.lines().find_map(|l| l.strip_prefix(n)?.strip_prefix(':').and_then(|v| num(v.as_bytes())));
    Some(field("MemTotal")?.saturating_sub(field("MemAvailable")?) * 1024)
}

/// `usage_usec` of a cgroup v2 `cpu.stat`.
pub fn parse_cpu_stat(text: &str) -> Option<u64> {
    text.lines().find_map(|l| l.strip_prefix("usage_usec ")?.trim().parse().ok())
}

/// Working set: `memory.current` minus the `inactive_file` line of `memory.stat`.
pub fn working_set(current: u64, stat: &str) -> u64 {
    let inactive = stat.lines().find_map(|l| l.strip_prefix("inactive_file ")?.trim().parse::<u64>().ok()).unwrap_or(0);
    current.saturating_sub(inactive)
}

fn read(path: &[u8]) -> Option<String> {
    String::from_utf8(kr_sys::fs::read_file(path, 1 << 20).ok()?).ok()
}

fn read_at(dir: i32, name: &[u8]) -> Option<String> {
    let fd = kr_sys::fs::openat(dir, name, kr_sys::fs::O_RDONLY | kr_sys::fs::O_CLOEXEC, 0).ok()?;
    let mut v = Vec::new();
    kr_sys::fs::read_to_end(fd.raw(), &mut v, 1 << 20).ok()?;
    String::from_utf8(v).ok()
}

fn label(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

/// The Prometheus text of `/metrics/resource`.
pub fn render(s: &Sample) -> String {
    use core::fmt::Write;
    let mut o = String::new();
    let ts = s.ts_ms;
    if let Some(c) = s.node_cpu {
        let _ = write!(o, "# HELP node_cpu_usage_seconds_total Cumulative cpu time consumed by the node in core-seconds\n# TYPE node_cpu_usage_seconds_total counter\nnode_cpu_usage_seconds_total {c} {ts}\n");
    }
    if let Some(m) = s.node_mem {
        let _ = write!(o, "# HELP node_memory_working_set_bytes Current working set of the node in bytes\n# TYPE node_memory_working_set_bytes gauge\nnode_memory_working_set_bytes {m} {ts}\n");
    }
    o.push_str("# HELP container_cpu_usage_seconds_total Cumulative cpu time consumed by the container in core-seconds\n# TYPE container_cpu_usage_seconds_total counter\n");
    for c in &s.ctrs {
        let _ = writeln!(o, "container_cpu_usage_seconds_total{{container=\"{}\",namespace=\"{}\",pod=\"{}\"}} {} {ts}", label(&c.container), label(&c.ns), label(&c.pod), c.cpu_secs);
    }
    o.push_str("# HELP container_memory_working_set_bytes Current working set of the container in bytes\n# TYPE container_memory_working_set_bytes gauge\n");
    for c in &s.ctrs {
        let _ = writeln!(o, "container_memory_working_set_bytes{{container=\"{}\",namespace=\"{}\",pod=\"{}\"}} {} {ts}", label(&c.container), label(&c.ns), label(&c.pod), c.mem);
    }
    let mut pods: BTreeMap<(&str, &str), (f64, u64)> = BTreeMap::new();
    for c in &s.ctrs {
        let e = pods.entry((&c.ns, &c.pod)).or_default();
        e.0 += c.cpu_secs;
        e.1 += c.mem;
    }
    o.push_str("# HELP pod_cpu_usage_seconds_total Cumulative cpu time consumed by the pod in core-seconds\n# TYPE pod_cpu_usage_seconds_total counter\n");
    for ((ns, pod), (cpu, _)) in &pods {
        let _ = writeln!(o, "pod_cpu_usage_seconds_total{{namespace=\"{}\",pod=\"{}\"}} {cpu} {ts}", label(ns), label(pod));
    }
    o.push_str("# HELP pod_memory_working_set_bytes Current working set of the pod in bytes\n# TYPE pod_memory_working_set_bytes gauge\n");
    for ((ns, pod), (_, mem)) in &pods {
        let _ = writeln!(o, "pod_memory_working_set_bytes{{namespace=\"{}\",pod=\"{}\"}} {mem} {ts}", label(ns), label(pod));
    }
    let err = u8::from(s.node_cpu.is_none() || s.node_mem.is_none());
    let _ = write!(o, "# HELP resource_scrape_error 1 if there was an error while getting container metrics, 0 otherwise\n# TYPE resource_scrape_error gauge\nresource_scrape_error {err}\n");
    o
}

fn usage(cpu_secs: f64, mem: u64, ts: &str) -> Vec<(&'static str, Value)> {
    alloc::vec![("time", Value::from(ts)), ("usageNanoCores", Value::from(0u64)), ("usageCoreNanoSeconds", Value::from((cpu_secs * 1e9) as u64)), ("workingSetBytes", Value::from(mem))]
}

/// A subset of `/stats/summary`: node and per-container cumulative CPU and working set
/// (`usageNanoCores` is 0: it is a rate, which needs two samples; consumers use the counter).
pub fn summary(node: &str, s: &Sample) -> String {
    let ts = kr_apiserver::object::rfc3339(s.ts_ms.div_euclid(1000));
    let mut pods: BTreeMap<(&str, &str), Vec<Value>> = BTreeMap::new();
    for c in &s.ctrs {
        let mut f = alloc::vec![("name", Value::from(c.container.as_str()))];
        f.push(("cpu", obj(alloc::vec![("time", Value::from(ts.as_str())), ("usageCoreNanoSeconds", Value::from((c.cpu_secs * 1e9) as u64))])));
        f.push(("memory", obj(alloc::vec![("time", Value::from(ts.as_str())), ("workingSetBytes", Value::from(c.mem))])));
        pods.entry((&c.ns, &c.pod)).or_default().push(obj(f));
    }
    let pods: Vec<Value> = pods
        .into_iter()
        .map(|((ns, pod), ctrs)| obj(alloc::vec![("podRef", obj(alloc::vec![("name", Value::from(pod)), ("namespace", Value::from(ns))])), ("containers", Value::Array(ctrs))]))
        .collect();
    let u = usage(s.node_cpu.unwrap_or(0.0), s.node_mem.unwrap_or(0), &ts);
    let pick = |keys: &[&str]| obj(u.iter().filter(|(k, _)| keys.contains(k)).map(|(k, v)| (*k, v.clone())).collect());
    json::to_string(&obj(alloc::vec![
        ("node", obj(alloc::vec![("nodeName", Value::from(node)), ("cpu", pick(&["time", "usageNanoCores", "usageCoreNanoSeconds"])), ("memory", pick(&["time", "workingSetBytes"]))])),
        ("pods", Value::Array(pods)),
    ]))
}

fn wall_ms() -> i64 {
    kr_sys::clock_gettime(0).map(|t| t.tv_sec * 1000 + t.tv_nsec / 1_000_000).unwrap_or(0)
}

impl<C: Client + Clone + 'static> Kubelet<C> {
    /// Measures the node and every running container that has a cgroup.
    pub fn sample(&self) -> Sample {
        let mut s = Sample { ts_ms: wall_ms(), node_cpu: read(b"/proc/stat\0").and_then(|t| parse_proc_stat(&t)), node_mem: read(b"/proc/meminfo\0").and_then(|t| parse_meminfo(&t)), ctrs: Vec::new() };
        if !self.cfg.cgroups {
            return s;
        }
        for p in self.pods.borrow().values() {
            let Some(cg) = &p.cg else { continue };
            for c in &p.ctrs {
                let CState::Running { id, .. } = &c.state else { continue };
                let Ok(g) = kr_runtime::cgroup::Cgroup::open_in(cg.rel(), id.as_bytes()) else { continue };
                let Some(usec) = read_at(g.dir.raw(), b"cpu.stat\0").and_then(|t| parse_cpu_stat(&t)) else { continue };
                let cur = read_at(g.dir.raw(), b"memory.current\0").and_then(|t| t.trim().parse().ok()).unwrap_or(0);
                let mem = working_set(cur, &read_at(g.dir.raw(), b"memory.stat\0").unwrap_or_default());
                s.ctrs.push(CtrStat { ns: p.ns.clone(), pod: p.name.clone(), container: c.name.clone(), cpu_secs: usec as f64 / 1e6, mem });
            }
        }
        s
    }
}

/// `what` is `resource` (`/metrics/resource`) or `summary` (`/stats/summary`); see the routes in
/// `remote::serve`, which reach this through `NodeProxy::pod_subresource("metrics", what, ..)`.
pub fn respond<C: Client + Clone + 'static>(k: &Kubelet<C>, what: &str) -> Result<Response, ApiError> {
    match what {
        "resource" => Ok(Response::new(200, render(&k.sample()).into_bytes()).with_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")),
        "summary" => Ok(Response::new(200, summary(&k.cfg.node_name, &k.sample()).into_bytes()).with_header("Content-Type", "application/json")),
        _ => Err(ApiError::not_found("metrics", what)),
    }
}

/// The API server's scraper: this node's kubelet in process, others over mutual TLS.
impl kr_apiserver::metrics::Scraper for crate::remote::Router {
    fn scrape(&self, node: &str, ip: Option<[u8; 16]>) -> Pin<Box<dyn Future<Output = Option<String>>>> {
        use kr_net::http1::Transport;
        if node == self.local_node {
            let r = self.local.as_ref().and_then(|l| l.pod_subresource("metrics", "resource", "", node, None, "", &[]).ok());
            return Box::pin(async move {
                match r?.body {
                    Body::Full(b) => String::from_utf8(b).ok(),
                    _ => None,
                }
            });
        }
        let tls = self.tls.clone();
        Box::pin(async move {
            let ip = ip?;
            let mut t = crate::remote::connect(tls, ip).await?;
            let req = alloc::format!("GET /metrics/resource HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", kr_net::tcp::url_host(ip));
            t.write_all(req.as_bytes()).await.ok()?;
            let (200, _, mut body) = crate::remote::read_head(&mut t).await? else { return None };
            let mut tmp = alloc::vec![0u8; 16384];
            while body.len() < (8 << 20) {
                match t.read(&mut tmp).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => body.extend_from_slice(&tmp[..n]),
                }
            }
            Some(String::from_utf8_lossy(&body).to_string())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_files() {
        let stat = "cpu  100 10 50 800 20 5 5 10 0 0\ncpu0 1 1 1 1 1 1 1 1 0 0\n";
        assert_eq!(parse_proc_stat(stat), Some(1.8));
        assert_eq!(parse_proc_stat("intr 5\n"), None);
        let mi = "MemTotal:       16000000 kB\nMemFree:         100 kB\nMemAvailable:    6000000 kB\n";
        assert_eq!(parse_meminfo(mi), Some(10_000_000 * 1024));
        assert_eq!(parse_meminfo("MemTotal: 5 kB\n"), None);
    }

    #[test]
    fn cgroup_files() {
        assert_eq!(parse_cpu_stat("usage_usec 2500000\nuser_usec 1\n"), Some(2_500_000));
        assert_eq!(parse_cpu_stat("user_usec 1\n"), None);
        assert_eq!(working_set(10_000, "anon 1\ninactive_file 4000\nactive_file 3\n"), 6000);
        assert_eq!(working_set(10_000, "anon 1\n"), 10_000);
        assert_eq!(working_set(100, "inactive_file 4000\n"), 0);
    }

    fn sample() -> Sample {
        Sample {
            ts_ms: 1_700_000_000_000,
            node_cpu: Some(12.5),
            node_mem: Some(2 << 30),
            ctrs: alloc::vec![
                CtrStat { ns: "default".into(), pod: "web".into(), container: "app".into(), cpu_secs: 1.5, mem: 4096 },
                CtrStat { ns: "default".into(), pod: "web".into(), container: "side\"car".into(), cpu_secs: 0.5, mem: 1024 },
            ],
        }
    }

    #[test]
    fn render_roundtrips_through_the_apiserver_parser() {
        let text = render(&sample());
        for m in ["node_cpu_usage_seconds_total", "node_memory_working_set_bytes", "container_cpu_usage_seconds_total", "container_memory_working_set_bytes", "pod_cpu_usage_seconds_total", "pod_memory_working_set_bytes", "resource_scrape_error 0"] {
            assert!(text.contains(m), "{m}");
        }
        assert!(text.contains("pod_cpu_usage_seconds_total{namespace=\"default\",pod=\"web\"} 2 1700000000000"));
        assert!(text.contains("pod_memory_working_set_bytes{namespace=\"default\",pod=\"web\"} 5120 "));
        let p = kr_apiserver::metrics::parse(&text, 0);
        assert_eq!(p.node_cpu, Some((12.5, 1_700_000_000_000)));
        assert_eq!(p.node_mem, Some(2 << 30));
        assert!(!p.error);
        assert_eq!(p.ctrs.len(), 2);
        let q = p.ctrs.iter().find(|c| c.container == "side\"car").unwrap();
        assert_eq!((q.cpu_secs, q.mem, q.pod.as_str()), (0.5, 1024, "web"));
        // No node data: the scrape is reported as failed.
        assert!(kr_apiserver::metrics::parse(&render(&Sample::default()), 0).error);
    }

    #[test]
    fn summary_subset() {
        let v = json::parse(summary("n1", &sample()).as_bytes()).unwrap();
        assert_eq!(v.pointer(&["node", "nodeName"]).and_then(Value::as_str), Some("n1"));
        assert_eq!(v.pointer(&["node", "cpu", "usageCoreNanoSeconds"]).and_then(Value::as_u64), Some(12_500_000_000));
        let pods = v.get("pods").and_then(Value::as_array).unwrap();
        assert_eq!(pods.len(), 1);
        assert_eq!(pods[0].get("containers").and_then(Value::as_array).map(|c| c.len()), Some(2));
    }
}
