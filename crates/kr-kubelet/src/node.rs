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

fn cpus() -> usize {
    read(b"/proc/cpuinfo\0").lines().filter(|l| l.starts_with("processor")).count().max(1)
}

fn memory_ki() -> u64 {
    read(b"/proc/meminfo\0").lines().find_map(|l| l.strip_prefix("MemTotal:")).and_then(|v| v.split_whitespace().next()?.parse().ok()).unwrap_or(0)
}

fn status(cfg: &Config) -> String {
    let t = rfc3339(now());
    let (cpu, mem) = (cpus(), memory_ki());
    let arch = if cfg!(target_arch = "aarch64") { "arm64" } else { "amd64" };
    let kernel = read(b"/proc/sys/kernel/osrelease\0");
    alloc::format!(
        r#"{{"capacity":{{"cpu":"{cpu}","memory":"{mem}Ki","pods":"110"}},"allocatable":{{"cpu":"{cpu}","memory":"{mem}Ki","pods":"110"}},
"conditions":[{{"type":"Ready","status":"True","reason":"KubeletReady","message":"kr kubelet is posting ready status","lastHeartbeatTime":"{t}","lastTransitionTime":"{t}"}},
{{"type":"MemoryPressure","status":"False","reason":"KubeletHasSufficientMemory","lastHeartbeatTime":"{t}","lastTransitionTime":"{t}"}},
{{"type":"DiskPressure","status":"False","reason":"KubeletHasNoDiskPressure","lastHeartbeatTime":"{t}","lastTransitionTime":"{t}"}},
{{"type":"PIDPressure","status":"False","reason":"KubeletHasSufficientPID","lastHeartbeatTime":"{t}","lastTransitionTime":"{t}"}}],
"addresses":[{{"type":"InternalIP","address":"127.0.0.1"}},{{"type":"Hostname","address":"{name}"}}],
"nodeInfo":{{"kubeletVersion":"v1.31.0-kr","kubeProxyVersion":"v1.31.0-kr","containerRuntimeVersion":"kr://0.0.1","kernelVersion":"{kernel}","osImage":"kr","operatingSystem":"linux","architecture":"{arch}","machineID":"","systemUUID":"","bootID":""}}}}"#,
        name = cfg.node_name,
        kernel = kernel.trim()
    )
}

/// Creates the Node (or refreshes its status) and its Lease.
pub async fn register<C: Client>(c: &C, cfg: &Config) {
    let name = &cfg.node_name;
    let arch = if cfg!(target_arch = "aarch64") { "arm64" } else { "amd64" };
    let node = alloc::format!(
        r#"{{"apiVersion":"v1","kind":"Node","metadata":{{"name":"{name}","labels":{{"kubernetes.io/hostname":"{name}","kubernetes.io/os":"linux","kubernetes.io/arch":"{arch}","node-role.kubernetes.io/control-plane":""}}}},"spec":{{}}}}"#
    );
    let _ = c.create("/api/v1/nodes", &json::parse(node.as_bytes()).unwrap()).await;
    update_status(c, cfg).await;
    renew_lease(c, cfg).await;
}

async fn update_status<C: Client>(c: &C, cfg: &Config) {
    let patch = alloc::format!(r#"{{"status":{}}}"#, status(cfg));
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

pub async fn heartbeat_loop<C: Client>(c: &C, cfg: &Config) {
    let mut ticks = 0u32;
    loop {
        kr_rt::exec::sleep(10_000).await;
        renew_lease(c, cfg).await;
        ticks += 1;
        if ticks % 6 == 0 {
            update_status(c, cfg).await;
        }
    }
}
