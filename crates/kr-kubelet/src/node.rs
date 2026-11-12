//! Node registration (capacity from /proc) and the heartbeat: a Lease in kube-node-lease
//! renewed every 10 s, and the Ready condition refreshed every 60 s.

use crate::Config;
use alloc::string::String;
use kr_apiserver::client::Client;
use kr_apiserver::object::rfc3339;
use kr_fmt::json::{self, Value};

fn now() -> i64 {
    kr_sys::clock_gettime(0).map(|t| t.tv_sec).unwrap_or(0)
}

fn read(path: &[u8]) -> String {
    kr_sys::fs::read_file(path, 1 << 20).ok().and_then(|b| String::from_utf8(b).ok()).unwrap_or_default()
}

pub(crate) fn cpus() -> usize {
    read(b"/proc/cpuinfo\0").lines().filter(|l| l.starts_with("processor")).count().max(1)
}

/// Configurable node pod limit (default 110, upstream default). Override with KR_MAX_PODS.
pub(crate) fn max_pods() -> u32 {
    kr_runtime::store::env_var("KR_MAX_PODS").and_then(|v| v.parse().ok()).unwrap_or(110)
}

pub(crate) fn memory_ki() -> u64 {
    read(b"/proc/meminfo\0").lines().find_map(|l| l.strip_prefix("MemTotal:")).and_then(|v| v.split_whitespace().next()?.parse().ok()).unwrap_or(0)
}

/// MemAvailable in KiB (None if unreadable).
pub(crate) fn memory_available_ki() -> Option<u64> {
    read(b"/proc/meminfo\0").lines().find_map(|l| l.strip_prefix("MemAvailable:")).and_then(|v| v.split_whitespace().next()?.parse().ok())
}

fn status(cfg: &Config, dp: &crate::deviceplugin::Plugins) -> String {
    let (mut ext_cap, mut ext_alloc) = (String::new(), String::new());
    for (k, cap, healthy) in dp.node_resources() {
        ext_cap.push_str(&alloc::format!(r#","{k}":"{cap}""#));
        ext_alloc.push_str(&alloc::format!(r#","{k}":"{healthy}""#));
    }
    let t = rfc3339(now());
    let (cpu, mem) = (cpus(), memory_ki());
    let arch = if cfg!(target_arch = "aarch64") { "arm64" } else { "amd64" };
    let (mp, mp_reason) = if crate::evict::under_pressure(memory_available_ki(), cfg.eviction_memory_bytes) { ("True", "KubeletHasInsufficientMemory") } else { ("False", "KubeletHasSufficientMemory") };
    let kernel = read(b"/proc/sys/kernel/osrelease\0");
    let pods = max_pods();
    alloc::format!(
        r#"{{"capacity":{{"cpu":"{cpu}","memory":"{mem}Ki","pods":"{pods}"{ext_cap}}},"allocatable":{{"cpu":"{cpu}","memory":"{mem}Ki","pods":"{pods}"{ext_alloc}}},
"conditions":[{{"type":"Ready","status":"True","reason":"KubeletReady","message":"kr kubelet is posting ready status","lastHeartbeatTime":"{t}","lastTransitionTime":"{t}"}},
{{"type":"MemoryPressure","status":"{mp}","reason":"{mp_reason}","lastHeartbeatTime":"{t}","lastTransitionTime":"{t}"}},
{{"type":"DiskPressure","status":"False","reason":"KubeletHasNoDiskPressure","lastHeartbeatTime":"{t}","lastTransitionTime":"{t}"}},
{{"type":"PIDPressure","status":"False","reason":"KubeletHasSufficientPID","lastHeartbeatTime":"{t}","lastTransitionTime":"{t}"}}],
"addresses":[{{"type":"InternalIP","address":"{ip}"}}{ip6}{ext},{{"type":"Hostname","address":"{name}"}}],
"nodeInfo":{{"kubeletVersion":"v1.37.0-kr","kubeProxyVersion":"v1.37.0-kr","containerRuntimeVersion":"kr://0.0.1","kernelVersion":"{kernel}","osImage":"kr","operatingSystem":"linux","architecture":"{arch}","machineID":"","systemUUID":"","bootID":""}}}}"#,
        name = cfg.node_name,
        ip6 = kr_apiserver::api::host_ip6().filter(|a| *a != cfg.node_ip).map(|a| alloc::format!(r#",{{"type":"InternalIP","address":"{}"}}"#, kr_net::tcp::ipv6_string(a))).unwrap_or_default(),
        ext = cfg.external_ip.map(|a| alloc::format!(r#",{{"type":"ExternalIP","address":"{}"}}"#, kr_net::tcp::fmt_ip16(a))).unwrap_or_default(),
        kernel = kernel.trim(),
        ip = kr_net::tcp::fmt_ip16(cfg.node_ip)
    )
}

/// Creates the Node (or refreshes its status) and its Lease.
pub async fn register<C: Client>(c: &C, cfg: &Config, dp: &crate::deviceplugin::Plugins) {
    let name = &cfg.node_name;
    let arch = if cfg!(target_arch = "aarch64") { "arm64" } else { "amd64" };
    let role = if cfg.control_plane { r#","node-role.kubernetes.io/control-plane":"""# } else { "" };
    let node = alloc::format!(
        r#"{{"apiVersion":"v1","kind":"Node","metadata":{{"name":"{name}","labels":{{"kubernetes.io/hostname":"{name}","kubernetes.io/os":"linux","kubernetes.io/arch":"{arch}"{role}}}}},"spec":{{}}}}"#
    );
    let mut node = json::parse(node.as_bytes()).unwrap();
    // Configured labels and taints go into the new Node itself, so that no pod is scheduled in
    // the window before they exist.
    let (labels, taints, ann) = crate::nodecfg::for_new_node(&cfg.labels, &cfg.taints);
    for (k, v) in &labels {
        node.entry_object("metadata").entry_object("labels").set(k, Value::from(v.as_str()));
    }
    for (k, v) in &ann {
        node.entry_object("metadata").entry_object("annotations").set(k, Value::from(v.as_str()));
    }
    if !taints.is_empty() {
        node.entry_object("spec").set("taints", Value::Array(taints.iter().map(crate::nodecfg::Taint::to_value).collect()));
    }
    if c.create("/api/v1/nodes", &node).await.is_err() {
        // Registered before: apply the configuration only if it changed since.
        let path = alloc::format!("/api/v1/nodes/{name}");
        if let Ok(existing) = c.get(&path).await {
            if let Some(patch) = crate::nodecfg::reconcile(&existing, &cfg.labels, &cfg.taints) {
                let _ = c.patch(&path, "application/merge-patch+json", &patch).await;
            }
        }
    }
    update_status(c, cfg, dp).await;
    renew_lease(c, cfg).await;
}

async fn update_status<C: Client>(c: &C, cfg: &Config, dp: &crate::deviceplugin::Plugins) {
    let patch = alloc::format!(r#"{{"status":{}}}"#, status(cfg, dp));
    if let Ok(p) = json::parse(patch.as_bytes()) {
        let _ = c.patch(&alloc::format!("/api/v1/nodes/{}/status", cfg.node_name), "application/merge-patch+json", &p).await;
    }
}

async fn renew_lease<C: Client>(c: &C, cfg: &Config) {
    let path = alloc::format!("/apis/coordination.k8s.io/v1/namespaces/kube-node-lease/leases/{}", cfg.node_name);
    let t = rfc3339(now()).replace('Z', ".000000Z");
    let spec = alloc::format!(r#"{{"holderIdentity":"{}","leaseDurationSeconds":40,"renewTime":"{t}"}}"#, cfg.node_name);
    let patch = json::parse(alloc::format!(r#"{{"spec":{spec}}}"#).as_bytes()).unwrap_or(Value::Null);
    if c.patch(&path, "application/merge-patch+json", &patch).await.is_err() {
        let lease = alloc::format!(r#"{{"apiVersion":"coordination.k8s.io/v1","kind":"Lease","metadata":{{"name":"{}"}},"spec":{spec}}}"#, cfg.node_name);
        let _ = c.create("/apis/coordination.k8s.io/v1/namespaces/kube-node-lease/leases", &json::parse(lease.as_bytes()).unwrap_or(Value::Null)).await;
    }
}

pub async fn heartbeat_loop<C: Client>(c: &C, cfg: &Config, dp: &crate::deviceplugin::Plugins) {
    let mut ticks = 0u32;
    let mut seen = dp.generation();
    loop {
        kr_rt::exec::sleep(1000).await;
        ticks += 1;
        if ticks % 10 == 0 {
            renew_lease(c, cfg).await;
        }
        // Device counts changed: push the node status now, not at the next 60 s heartbeat.
        let g = dp.generation();
        if ticks % 30 == 0 || g != seen {
            seen = g;
            update_status(c, cfg, dp).await;
        }
    }
}
