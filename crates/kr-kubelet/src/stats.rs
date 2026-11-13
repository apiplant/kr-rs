//! Resource usage of the node and its containers (ADR-048): the kubelet resource-metrics endpoint
//! `GET /metrics/resource` (Prometheus text, what metrics-server and the API server's
//! `metrics.k8s.io` ([`kr_apiserver::metrics`]) scrape) and a subset of `GET /stats/summary`.
//!
//! CPU is cumulative (cgroup v2 `cpu.stat` `usage_usec`; node: `/proc/stat` busy time), memory is
//! the working set (`memory.current` minus `inactive_file`; node: `MemTotal - MemAvailable`).
//! Containers are only measured when kr has a delegated cgroup (`Config::cgroups`).

use crate::{CState, Client, Kubelet};
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use kr_apiserver::object::{obj, ApiError};
use kr_fmt::json::{self, Value};
use kr_net::http1::server::{Body, Response};

/// What cAdvisor reports beyond CPU and working set (`/metrics/cadvisor`).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Cad {
    pub image: String,
    /// Container id (the `name` label) and cgroup path (the `id` label).
    pub cid: String,
    pub path: String,
    pub started_s: i64,
    pub user_secs: f64,
    pub system_secs: f64,
    pub periods: u64,
    pub throttled_periods: u64,
    pub throttled_secs: f64,
    pub usage: u64,
    pub rss: u64,
    pub cache: u64,
    /// Writable layer (overlay upper directory) and the filesystem holding it; `None` until the
    /// first `fs_usage_loop` pass measured it.
    pub fs: Option<Fs>,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Fs {
    pub usage: u64,
    pub inodes_used: u64,
    /// Filesystem size and free space in bytes, inodes in total and free.
    pub limit: u64,
    pub available: u64,
    pub inodes: u64,
    pub inodes_free: u64,
}

/// Counters of one network interface of a pod's sandbox (`/proc/<pid>/net/dev`).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Iface {
    pub name: String,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub rx_errors: u64,
    pub rx_dropped: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errors: u64,
    pub tx_dropped: u64,
}

/// Network of one pod.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct PodNet {
    pub ns: String,
    pub pod: String,
    pub path: String,
    pub ifaces: Vec<Iface>,
}

/// Counts for the kubelet's own `/metrics`.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Internals {
    pub pods: u64,
    pub containers: u64,
    pub started_s: i64,
    pub node: String,
}

/// One container's usage.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct CtrStat {
    pub cad: Cad,
    pub ns: String,
    pub pod: String,
    pub container: String,
    pub cpu_secs: f64,
    pub mem: u64,
}

/// Usage of one PVC volume of a pod (`kubelet_volume_stats_*`).
#[derive(Debug, Clone, PartialEq)]
pub struct VolStat {
    pub ns: String,
    pub pod: String,
    pub volume: String,
    pub claim: String,
    pub capacity: u64,
    pub used: u64,
    pub available: u64,
    pub inodes: u64,
    pub inodes_used: u64,
    pub inodes_free: u64,
}

/// A measurement of the node and its containers at `ts_ms`.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Sample {
    pub ts_ms: i64,
    pub node_cpu: Option<f64>,
    pub node_mem: Option<u64>,
    pub ctrs: Vec<CtrStat>,
    pub nets: Vec<PodNet>,
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

/// The interfaces of `/proc/<pid>/net/dev` other than `lo`.
pub fn parse_net_dev(text: &str) -> Vec<Iface> {
    text.lines()
        .filter_map(|l| {
            let (name, rest) = l.split_once(':')?;
            let name = name.trim();
            if name == "lo" {
                return None;
            }
            let f: Vec<u64> = rest.split_whitespace().filter_map(|x| x.parse().ok()).collect();
            (f.len() >= 12).then(|| Iface { name: name.to_string(), rx_bytes: f[0], rx_packets: f[1], rx_errors: f[2], rx_dropped: f[3], tx_bytes: f[8], tx_packets: f[9], tx_errors: f[10], tx_dropped: f[11] })
        })
        .collect()
}

/// A `key value` line of a cgroup flat-keyed file.
pub fn stat_field(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|l| l.strip_prefix(key)?.strip_prefix(' ')?.trim().parse().ok())
}

/// One probe outcome counter (`prober_probe_total`).
#[derive(Debug, Clone, PartialEq)]
pub struct ProbeCount {
    pub ns: String,
    pub pod: String,
    pub container: String,
    pub kind: &'static str,
    pub ok: bool,
    pub n: u64,
}

/// Prometheus text of `GET /metrics/cadvisor`: the series cAdvisor exports and dashboards use.
pub fn render_cadvisor(s: &Sample) -> String {
    use core::fmt::Write;
    let mut o = String::new();
    let ts = s.ts_ms;
    let lbl = |c: &CtrStat| alloc::format!("container=\"{}\",id=\"{}\",image=\"{}\",name=\"{}\",namespace=\"{}\",pod=\"{}\"", label(&c.container), label(&c.cad.path), label(&c.cad.image), label(&c.cad.cid), label(&c.ns), label(&c.pod));
    let ctr: [(&str, &str, &str, fn(&CtrStat) -> String); 11] = [
        ("container_cpu_usage_seconds_total", "Cumulative cpu time consumed in seconds.", "counter", |c| c.cpu_secs.to_string()),
        ("container_cpu_user_seconds_total", "Cumulative user cpu time consumed in seconds.", "counter", |c| c.cad.user_secs.to_string()),
        ("container_cpu_system_seconds_total", "Cumulative system cpu time consumed in seconds.", "counter", |c| c.cad.system_secs.to_string()),
        ("container_cpu_cfs_periods_total", "Number of elapsed enforcement period intervals.", "counter", |c| c.cad.periods.to_string()),
        ("container_cpu_cfs_throttled_periods_total", "Number of throttled period intervals.", "counter", |c| c.cad.throttled_periods.to_string()),
        ("container_cpu_cfs_throttled_seconds_total", "Total time duration the container has been throttled.", "counter", |c| c.cad.throttled_secs.to_string()),
        ("container_memory_working_set_bytes", "Current working set in bytes.", "gauge", |c| c.mem.to_string()),
        ("container_memory_usage_bytes", "Current memory usage in bytes, including all memory regardless of when it was accessed.", "gauge", |c| c.cad.usage.to_string()),
        ("container_memory_rss", "Size of RSS in bytes.", "gauge", |c| c.cad.rss.to_string()),
        ("container_memory_cache", "Number of bytes of page cache memory.", "gauge", |c| c.cad.cache.to_string()),
        ("container_start_time_seconds", "Start time of the container since unix epoch in seconds.", "gauge", |c| c.cad.started_s.to_string()),
    ];
    for (name, help, ty, f) in &ctr {
        let _ = write!(o, "# HELP {name} {help}\n# TYPE {name} {ty}\n");
        for c in &s.ctrs {
            let _ = writeln!(o, "{name}{{{}}} {} {ts}", lbl(c), f(c));
        }
    }
    let fsm: [(&str, &str, fn(&Fs) -> u64); 5] = [
        ("container_fs_usage_bytes", "Number of bytes that are consumed by the container on this filesystem.", |f| f.usage),
        ("container_fs_limit_bytes", "Number of bytes that can be consumed by the container on this filesystem.", |f| f.limit),
        ("container_fs_inodes_total", "Number of Inodes", |f| f.inodes),
        ("container_fs_inodes_free", "Number of available Inodes", |f| f.inodes_free),
        ("container_fs_inodes_used", "Number of inodes the container writable layer uses", |f| f.inodes_used),
    ];
    for (name, help, f) in fsm {
        let ty = "gauge";
        let _ = write!(o, "# HELP {name} {help}\n# TYPE {name} {ty}\n");
        for c in &s.ctrs {
            if let Some(fs) = &c.cad.fs {
                let _ = writeln!(o, "{name}{{{}}} {} {ts}", lbl(c), f(fs));
            }
        }
    }
    let _ = write!(o, "# HELP container_last_seen Last time a container was seen by the exporter\n# TYPE container_last_seen gauge\n");
    for c in &s.ctrs {
        let _ = writeln!(o, "container_last_seen{{{}}} {} {ts}", lbl(c), ts / 1000);
    }
    let nets: [(&str, &str, fn(&Iface) -> u64); 8] = [
        ("container_network_receive_bytes_total", "Cumulative count of bytes received", |i| i.rx_bytes),
        ("container_network_receive_packets_total", "Cumulative count of packets received", |i| i.rx_packets),
        ("container_network_receive_errors_total", "Cumulative count of errors encountered while receiving", |i| i.rx_errors),
        ("container_network_receive_packets_dropped_total", "Cumulative count of packets dropped while receiving", |i| i.rx_dropped),
        ("container_network_transmit_bytes_total", "Cumulative count of bytes transmitted", |i| i.tx_bytes),
        ("container_network_transmit_packets_total", "Cumulative count of packets transmitted", |i| i.tx_packets),
        ("container_network_transmit_errors_total", "Cumulative count of errors encountered while transmitting", |i| i.tx_errors),
        ("container_network_transmit_packets_dropped_total", "Cumulative count of packets dropped while transmitting", |i| i.tx_dropped),
    ];
    for (name, help, f) in nets {
        let _ = write!(o, "# HELP {name} {help}\n# TYPE {name} counter\n");
        for p in &s.nets {
            for i in &p.ifaces {
                let _ = writeln!(o, "{name}{{id=\"{}\",interface=\"{}\",namespace=\"{}\",pod=\"{}\"}} {} {ts}", label(&p.path), label(&i.name), label(&p.ns), label(&p.pod), f(i));
            }
        }
    }
    let cores = read(b"/proc/cpuinfo\0").map_or(0, |t| t.lines().filter(|l| l.starts_with("processor")).count());
    let _ = write!(o, "# HELP machine_cpu_cores Number of logical CPU cores.\n# TYPE machine_cpu_cores gauge\nmachine_cpu_cores {cores}\n");
    let mem = read(b"/proc/meminfo\0").and_then(|t| t.lines().find_map(|l| num(l.strip_prefix("MemTotal:")?.as_bytes()))).unwrap_or(0) * 1024;
    let _ = write!(o, "# HELP machine_memory_bytes Amount of memory installed on the machine.\n# TYPE machine_memory_bytes gauge\nmachine_memory_bytes {mem}\n");
    o
}

/// Prometheus text of `GET /metrics/probes`.
pub fn render_probes(c: &[ProbeCount]) -> String {
    use core::fmt::Write;
    let mut o = String::from("# HELP prober_probe_total Cumulative number of a liveness, readiness or startup probe for a container by result.\n# TYPE prober_probe_total counter\n");
    for p in c {
        let _ = writeln!(o, "prober_probe_total{{container=\"{}\",namespace=\"{}\",pod=\"{}\",probe_type=\"{}\",result=\"{}\"}} {}", label(&p.container), label(&p.ns), label(&p.pod), p.kind, if p.ok { "successful" } else { "failed" }, p.n);
    }
    o
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

/// The kubelet's own metrics (`GET /metrics`): the usage of every claim mounted by a pod here.
pub fn render_kubelet(vols: &[VolStat], k: &Internals) -> String {
    use core::fmt::Write;
    let mut o = String::new();
    let _ = write!(o, "# HELP kubelet_running_pods Number of pods that have a running pod sandbox\n# TYPE kubelet_running_pods gauge\nkubelet_running_pods {}\n", k.pods);
    let _ = write!(o, "# HELP kubelet_running_containers Number of containers currently running\n# TYPE kubelet_running_containers gauge\nkubelet_running_containers{{container_state=\"running\"}} {}\n", k.containers);
    let _ = write!(o, "# HELP kubelet_node_name The node's name. The count is always 1.\n# TYPE kubelet_node_name gauge\nkubelet_node_name{{node=\"{}\"}} 1\n", label(&k.node));
    let _ = write!(o, "# HELP process_start_time_seconds Start time of the process since unix epoch in seconds.\n# TYPE process_start_time_seconds gauge\nprocess_start_time_seconds {}\n", k.started_s);
    let fields: [(&str, &str, fn(&VolStat) -> u64); 6] = [
        ("kubelet_volume_stats_capacity_bytes", "Capacity in bytes of the volume", |v| v.capacity),
        ("kubelet_volume_stats_used_bytes", "Number of used bytes in the volume", |v| v.used),
        ("kubelet_volume_stats_available_bytes", "Number of available bytes in the volume", |v| v.available),
        ("kubelet_volume_stats_inodes", "Maximum number of inodes in the volume", |v| v.inodes),
        ("kubelet_volume_stats_inodes_used", "Number of used inodes in the volume", |v| v.inodes_used),
        ("kubelet_volume_stats_inodes_free", "Number of free inodes in the volume", |v| v.inodes_free),
    ];
    // One series per claim (a claim shared by several pods on the node is reported once).
    let mut seen: Vec<(&str, &str)> = Vec::new();
    let uniq: Vec<&VolStat> = vols.iter().filter(|v| !seen.contains(&(v.ns.as_str(), v.claim.as_str())) && { seen.push((&v.ns, &v.claim)); true }).collect();
    for (name, help, f) in fields {
        let _ = write!(o, "# HELP {name} {help}\n# TYPE {name} gauge\n");
        for v in &uniq {
            let _ = writeln!(o, "{name}{{namespace=\"{}\",persistentvolumeclaim=\"{}\"}} {}", label(&v.ns), label(&v.claim), f(v));
        }
    }
    o
}

fn usage(cpu_secs: f64, mem: u64, ts: &str) -> Vec<(&'static str, Value)> {
    alloc::vec![("time", Value::from(ts)), ("usageNanoCores", Value::from(0u64)), ("usageCoreNanoSeconds", Value::from((cpu_secs * 1e9) as u64)), ("workingSetBytes", Value::from(mem))]
}

/// A subset of `/stats/summary`: node and per-container cumulative CPU and working set
/// (`usageNanoCores` is 0: it is a rate, which needs two samples; consumers use the counter).
pub fn summary(node: &str, s: &Sample, vols: &[VolStat]) -> String {
    let ts = kr_apiserver::object::rfc3339(s.ts_ms.div_euclid(1000));
    let mut pods: BTreeMap<(&str, &str), Vec<Value>> = BTreeMap::new();
    for c in &s.ctrs {
        let mut f = alloc::vec![("name", Value::from(c.container.as_str()))];
        f.push(("cpu", obj(alloc::vec![("time", Value::from(ts.as_str())), ("usageCoreNanoSeconds", Value::from((c.cpu_secs * 1e9) as u64))])));
        f.push(("memory", obj(alloc::vec![("time", Value::from(ts.as_str())), ("workingSetBytes", Value::from(c.mem))])));
        if let Some(fs) = &c.cad.fs {
            f.push(("rootfs", obj(alloc::vec![("time", Value::from(ts.as_str())), ("availableBytes", Value::from(fs.available)), ("capacityBytes", Value::from(fs.limit)), ("usedBytes", Value::from(fs.usage)), ("inodesFree", Value::from(fs.inodes_free)), ("inodes", Value::from(fs.inodes)), ("inodesUsed", Value::from(fs.inodes_used))])));
        }
        pods.entry((&c.ns, &c.pod)).or_default().push(obj(f));
    }
    // Pods that only have volumes (no cgroup, no container measured) are listed too.
    for v in vols {
        pods.entry((&v.ns, &v.pod)).or_default();
    }
    let pods: Vec<Value> = pods
        .into_iter()
        .map(|((ns, pod), ctrs)| {
            let volume: Vec<Value> = vols
                .iter()
                .filter(|v| v.ns == ns && v.pod == pod)
                .map(|v| {
                    obj(alloc::vec![
                        ("time", Value::from(ts.as_str())),
                        ("name", Value::from(v.volume.as_str())),
                        ("pvcRef", obj(alloc::vec![("name", Value::from(v.claim.as_str())), ("namespace", Value::from(v.ns.as_str()))])),
                        ("availableBytes", Value::from(v.available)),
                        ("capacityBytes", Value::from(v.capacity)),
                        ("usedBytes", Value::from(v.used)),
                        ("inodes", Value::from(v.inodes)),
                        ("inodesFree", Value::from(v.inodes_free)),
                        ("inodesUsed", Value::from(v.inodes_used)),
                    ])
                })
                .collect();
            let mut f = alloc::vec![("podRef", obj(alloc::vec![("name", Value::from(pod)), ("namespace", Value::from(ns))])), ("containers", Value::Array(ctrs))];
            if !volume.is_empty() {
                f.push(("volume", Value::Array(volume)));
            }
            obj(f)
        })
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
    /// Usage of the claims mounted by the pods here: `statfs` of the directory each is mounted
    /// from (its filesystem; a path that is not there, or not a mount of a CSI volume, is left out).
    pub fn volume_stats(&self) -> Vec<VolStat> {
        let mut out = Vec::new();
        for p in self.pods.borrow().values() {
            for (volume, claim, path) in p.pvcs.iter().flatten() {
                // Driver-reported numbers (NodeGetVolumeStats, refreshed by `volume_stats_loop`).
                if let Some(c) = self.vol_cache.borrow().get(path) {
                    out.push(VolStat { ns: p.ns.clone(), pod: p.name.clone(), volume: volume.clone(), claim: claim.clone(), capacity: c.capacity_bytes, used: c.used_bytes, available: c.available_bytes, inodes: c.inodes, inodes_used: c.inodes_used, inodes_free: c.inodes_free });
                    continue;
                }
                let Ok([bs, blocks, bfree, bavail, files, ffree]) = kr_sys::ns::statfs(path.as_bytes()) else { continue };
                out.push(VolStat {
                    ns: p.ns.clone(),
                    pod: p.name.clone(),
                    volume: volume.clone(),
                    claim: claim.clone(),
                    capacity: blocks * bs,
                    used: blocks.saturating_sub(bfree) * bs,
                    available: bavail * bs,
                    inodes: files,
                    inodes_used: files.saturating_sub(ffree),
                    inodes_free: ffree,
                });
            }
        }
        out
    }

    /// Every minute: asks the CSI drivers that offer GET_VOLUME_STATS for their volume numbers
    /// (statfs is the fallback inside [`crate::csi::Csi::volume_stats`] for the rest) and keeps
    /// them for `/metrics` and `/stats/summary`, so scraping never calls a driver. A volume the
    /// driver reports abnormal raises a `VolumeConditionAbnormal` event once (again after it
    /// recovered and failed again), as upstream's kubelet does.
    pub async fn volume_stats_loop(self: &alloc::rc::Rc<Self>) {
        loop {
            kr_rt::exec::sleep(60_000).await;
            let mut cache = BTreeMap::new();
            let mut bad = BTreeSet::new();
            for s in self.csi.volume_stats().await {
                let Some(path) = self.csi.publish_path(&s.pod_uid, &s.pv) else { continue };
                if let Some(msg) = &s.abnormal {
                    bad.insert(path.clone());
                    if !self.vol_abnormal.borrow().contains(&path) {
                        let pod = self.pods.borrow().get(&s.pod_uid).map(|p| (p.ns.clone(), p.name.clone()));
                        if let Some((ns, name)) = pod {
                            let o = |f: Vec<(&str, Value)>| Value::Object(f.into_iter().map(|(k, v)| (String::from(k), v)).collect());
                            let pod = o(alloc::vec![("metadata", o(alloc::vec![("namespace", Value::from(ns.as_str())), ("name", Value::from(name.as_str())), ("uid", Value::from(s.pod_uid.as_str()))]))]);
                            self.emit_event(&pod, "Warning", "VolumeConditionAbnormal", &alloc::format!("Volume {} is abnormal: {msg}", s.pv)).await;
                        }
                    }
                }
                cache.insert(path, s);
            }
            *self.vol_cache.borrow_mut() = cache;
            *self.vol_abnormal.borrow_mut() = bad;
        }
    }

    /// Every 2 minutes: measures the writable layer of each running container (`du` of
    /// `containers/<id>/upper`) for `container_fs_*` and the summary's `rootfs`. The walk runs in
    /// an offload worker (ADR-052) when there is one, one container at a time; without workers it
    /// is bounded and a bigger layer is skipped. The numbers are cached, so scraping is free.
    pub async fn fs_usage_loop(self: &alloc::rc::Rc<Self>) {
        loop {
            kr_rt::exec::sleep(120_000).await;
            let ids: Vec<String> = self.pods.borrow().values().flat_map(|p| p.ctrs.iter()).filter_map(|c| if let CState::Running { id, .. } = &c.state { Some(id.clone()) } else { None }).collect();
            let root = self.store.root().to_string();
            let Ok([bs, blocks, _, bavail, files, ffree]) = kr_sys::ns::statfs(root.as_bytes()) else { continue };
            let mut cache = BTreeMap::new();
            for id in ids {
                if let Some((usage, inodes_used)) = kr_runtime::offload::dir_usage(&alloc::format!("{root}/containers/{id}/upper")).await {
                    cache.insert(id, Fs { usage, inodes_used, limit: blocks * bs, available: bavail * bs, inodes: files, inodes_free: ffree });
                }
            }
            *self.fs_cache.borrow_mut() = cache;
        }
    }

    pub fn internals(&self) -> Internals {
        let pods = self.pods.borrow();
        let containers = pods.values().flat_map(|p| p.ctrs.iter()).filter(|c| matches!(c.state, CState::Running { .. })).count() as u64;
        Internals { pods: pods.values().filter(|p| p.sandbox.is_some()).count() as u64, containers, started_s: self.started_s, node: self.cfg.node_name.clone() }
    }

    /// Probe outcomes since the kubelet started, sorted for stable output.
    pub fn probe_counts(&self) -> Vec<ProbeCount> {
        self.probe_counts.borrow().iter().map(|((ns, pod, container, kind, ok), n)| ProbeCount { ns: ns.clone(), pod: pod.clone(), container: container.clone(), kind, ok: *ok, n: *n }).collect()
    }

    /// Measures the node and every running container that has a cgroup.
    pub fn sample(&self) -> Sample {
        let mut s = Sample { ts_ms: wall_ms(), node_cpu: read(b"/proc/stat\0").and_then(|t| parse_proc_stat(&t)), node_mem: read(b"/proc/meminfo\0").and_then(|t| parse_meminfo(&t)), ctrs: Vec::new(), nets: Vec::new() };
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
                let cpu = read_at(g.dir.raw(), b"cpu.stat\0").unwrap_or_default();
                let ms = read_at(g.dir.raw(), b"memory.stat\0").unwrap_or_default();
                let secs = |k: &str| stat_field(&cpu, k).unwrap_or(0) as f64 / 1e6;
                let CState::Running { started_at, .. } = &c.state else { continue };
                let cad = Cad {
                    image: c.image.clone(),
                    cid: id.clone(),
                    path: alloc::format!("/{}/{}", String::from_utf8_lossy(cg.rel()), id),
                    started_s: *started_at,
                    user_secs: secs("user_usec"),
                    system_secs: secs("system_usec"),
                    periods: stat_field(&cpu, "nr_periods").unwrap_or(0),
                    throttled_periods: stat_field(&cpu, "nr_throttled").unwrap_or(0),
                    throttled_secs: secs("throttled_usec"),
                    usage: cur,
                    rss: stat_field(&ms, "anon").unwrap_or(0),
                    cache: stat_field(&ms, "file").unwrap_or(0),
                    fs: self.fs_cache.borrow().get(id).cloned(),
                };
                s.ctrs.push(CtrStat { ns: p.ns.clone(), pod: p.name.clone(), container: c.name.clone(), cpu_secs: usec as f64 / 1e6, mem, cad });
            }
            if let Some(sb) = &p.sandbox {
                if let Some(t) = read(alloc::format!("/proc/{}/net/dev\0", sb.pid).as_bytes()) {
                    s.nets.push(PodNet { ns: p.ns.clone(), pod: p.name.clone(), path: alloc::format!("/{}", String::from_utf8_lossy(cg.rel())), ifaces: parse_net_dev(&t) });
                }
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
        "summary" => Ok(Response::new(200, summary(&k.cfg.node_name, &k.sample(), &k.volume_stats()).into_bytes()).with_header("Content-Type", "application/json")),
        "cadvisor" => Ok(Response::new(200, render_cadvisor(&k.sample()).into_bytes()).with_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")),
        "probes" => Ok(Response::new(200, render_probes(&k.probe_counts()).into_bytes()).with_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")),
        "kubelet" => Ok(Response::new(200, render_kubelet(&k.volume_stats(), &k.internals()).into_bytes()).with_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")),
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
        let tls = self.tls.borrow().clone();
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
                CtrStat { ns: "default".into(), pod: "web".into(), container: "app".into(), cpu_secs: 1.5, mem: 4096, ..Default::default() },
                CtrStat { ns: "default".into(), pod: "web".into(), container: "side\"car".into(), cpu_secs: 0.5, mem: 1024, ..Default::default() },
            ],
            nets: Vec::new(),
        }
    }

    #[test]
    fn volume_stats_are_rendered_once_per_claim_and_listed_in_the_summary() {
        let v = |pod: &str| VolStat { ns: "d".into(), pod: pod.into(), volume: "data".into(), claim: "db".into(), capacity: 1000, used: 400, available: 600, inodes: 50, inodes_used: 5, inodes_free: 45 };
        let text = render_kubelet(&[v("a"), v("b")], &Internals { pods: 2, containers: 3, started_s: 5, node: "n1".into() });
        assert!(text.contains("kubelet_running_containers{container_state=\"running\"} 3") && text.contains("kubelet_node_name{node=\"n1\"} 1"));
        assert_eq!(text.matches("kubelet_volume_stats_used_bytes{namespace=\"d\",persistentvolumeclaim=\"db\"} 400").count(), 1, "{text}");
        assert!(text.contains("# TYPE kubelet_volume_stats_inodes_free gauge") && text.contains("kubelet_volume_stats_capacity_bytes{namespace=\"d\",persistentvolumeclaim=\"db\"} 1000"));
        let s = json::parse(summary("n1", &sample(), &[v("a")]).as_bytes()).unwrap();
        let vol = s.get("pods").and_then(Value::as_array).and_then(|a| a.iter().find_map(|p| p.get("volume")?.as_array()?.first())).expect("a volume entry");
        assert_eq!(vol.get("usedBytes").and_then(Value::as_u64), Some(400));
        assert_eq!(vol.pointer(&["pvcRef", "name"]).and_then(Value::as_str), Some("db"));
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
        let v = json::parse(summary("n1", &sample(), &[]).as_bytes()).unwrap();
        assert_eq!(v.pointer(&["node", "nodeName"]).and_then(Value::as_str), Some("n1"));
        assert_eq!(v.pointer(&["node", "cpu", "usageCoreNanoSeconds"]).and_then(Value::as_u64), Some(12_500_000_000));
        let pods = v.get("pods").and_then(Value::as_array).unwrap();
        assert_eq!(pods.len(), 1);
        assert_eq!(pods[0].get("containers").and_then(Value::as_array).map(|c| c.len()), Some(2));
    }

    #[test]
    fn cadvisor_series_and_parsers() {
        let net = "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo: 100 2 0 0 0 0 0 0 100 2 0 0 0 0 0 0\n  eth0: 5000 40 1 2 0 0 0 0 7000 50 3 4 0 0 0 0\n";
        let i = parse_net_dev(net);
        assert_eq!(i.len(), 1);
        assert_eq!((i[0].rx_bytes, i[0].rx_dropped, i[0].tx_bytes, i[0].tx_errors), (5000, 2, 7000, 3));
        assert_eq!(stat_field("nr_periods 10\nnr_throttled 4\nthrottled_usec 2500000\n", "nr_throttled"), Some(4));
        assert_eq!(stat_field("anon 7\nanon_thp 9\n", "anon"), Some(7));
        let mut s = sample();
        s.ctrs[0].cad = Cad { fs: Some(Fs { usage: 7000, limit: 100_000, inodes: 50, inodes_free: 40, inodes_used: 3, available: 9 }), image: "nginx:1".into(), cid: "abc".into(), path: "/kubepods/x/abc".into(), throttled_periods: 4, periods: 10, throttled_secs: 2.5, rss: 99, usage: 5000, ..Default::default() };
        s.nets.push(PodNet { ns: "default".into(), pod: "web".into(), path: "/kubepods/x".into(), ifaces: i });
        let t = render_cadvisor(&s);
        assert!(t.contains("container_cpu_cfs_throttled_periods_total{container=\"app\",id=\"/kubepods/x/abc\",image=\"nginx:1\",name=\"abc\",namespace=\"default\",pod=\"web\"} 4 "), "{t}");
        assert!(t.contains("container_fs_usage_bytes{container=\"app\",id=\"/kubepods/x/abc\",image=\"nginx:1\",name=\"abc\",namespace=\"default\",pod=\"web\"} 7000 ") && t.contains("container_fs_limit_bytes{") && t.contains("container_fs_inodes_free{"), "{t}");
        assert_eq!(t.matches("container_fs_usage_bytes{").count(), 1, "only measured containers");
        for m in ["container_cpu_cfs_periods_total", "container_cpu_cfs_throttled_seconds_total", "container_memory_rss", "container_memory_usage_bytes", "container_network_transmit_bytes_total{id=\"/kubepods/x\",interface=\"eth0\",namespace=\"default\",pod=\"web\"} 7000", "container_network_receive_bytes_total"] {
            assert!(t.contains(m), "{m}");
        }
        let p = render_probes(&[ProbeCount { ns: "d".into(), pod: "p".into(), container: "c".into(), kind: "Liveness", ok: false, n: 3 }]);
        assert!(p.contains("prober_probe_total{container=\"c\",namespace=\"d\",pod=\"p\",probe_type=\"Liveness\",result=\"failed\"} 3"));
    }
}
