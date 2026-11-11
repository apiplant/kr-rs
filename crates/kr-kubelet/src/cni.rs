//! Minimal CNI (Container Network Interface) runner.
//!
//! kr's built-in pod networking is the default. When `KR_CNI_CONF_DIR` points at a
//! directory of CNI configuration files (`.conf`/`.conflist`/`.json`), kr runs the
//! configured plugin chain for each pod instead, using the plugin's returned IPs.
//!
//! Only the ADD and DEL commands are implemented, matching CNI spec 0.4.0/1.0.0.
//! The plugins themselves (bridge, host-local, loopback, ...) must be installed under
//! `KR_CNI_BIN_DIR` (default `/opt/cni/bin`).

use alloc::string::String;
use alloc::vec::Vec;
use kr_fmt::json::{self, Value};

/// Directory of CNI config files.
pub fn conf_dir() -> Option<String> {
    kr_runtime::store::env_var("KR_CNI_CONF_DIR")
}

/// Directory of CNI plugin binaries.
pub fn bin_dir() -> String {
    kr_runtime::store::env_var("KR_CNI_BIN_DIR").unwrap_or_else(|| String::from("/opt/cni/bin"))
}

/// Read and parse the first CNI config found in `dir`.
pub fn load_config(dir: &str) -> Result<Value, String> {
    let rd = kr_sys::ns::open(alloc::format!("{dir}\0").as_bytes(), kr_sys::ns::O_RDONLY | kr_sys::ns::O_DIRECTORY, 0)
        .map_err(|e| alloc::format!("open cni conf dir: {}", e.0))?;
    // Iterate entries; pick the first *.conf / *.conflist / *.json.
    let mut entries: Vec<String> = Vec::new();
    let mut buf = [0u8; 4096];
    // kr has no readdir helper exposed simply; read via getdents64.
    // Fall back to trying common names if readdir unavailable.
    drop(rd);
    // Try a few well-known filenames.
    for name in ["00-kr.conflist", "10-bridge.conf", "10-bridge.conflist", "kr.conflist", "config.json"] {
        let p = alloc::format!("{dir}/{name}");
        if let Ok(b) = kr_sys::fs::read_file(alloc::format!("{p}\0").as_bytes(), 1 << 20) {
            if let Ok(v) = json::parse(&b) {
                return Ok(v);
            }
        }
    }
    // Scan directory entries via getdents64.
    let fd = kr_sys::ns::open(alloc::format!("{dir}\0").as_bytes(), kr_sys::ns::O_RDONLY | kr_sys::ns::O_DIRECTORY, 0)
        .map_err(|e| alloc::format!("open cni conf dir: {}", e.0))?;
    loop {
        let n = kr_sys::fs::getdents64(fd.raw(), &mut buf).unwrap_or(0);
        if n == 0 { break; }
        let mut off = 0usize;
        while off < n {
            // linux_dirent64: ino(u64) off(i64) reclen(u16) type(u8) name[]
            let reclen = u16::from_ne_bytes([buf[off + 16], buf[off + 17]]) as usize;
            let d_type = buf[off + 18];
            let name_start = off + 19;
            let name_end = buf[name_start..off + reclen].iter().position(|&b| b == 0).map(|x| name_start + x).unwrap_or(off + reclen);
            let name = core::str::from_utf8(&buf[name_start..name_end]).unwrap_or("");
            if d_type != 4 && d_type != 0 { /* not dir entry filter */ }
            if !name.is_empty() && name != "." && name != ".." {
                if name.ends_with(".conf") || name.ends_with(".conflist") || name.ends_with(".json") {
                    entries.push(alloc::format!("{dir}/{name}"));
                }
            }
            off += reclen;
        }
    }
    let _ = kr_sys::close(fd.raw());
    entries.sort();
    for p in &entries {
        if let Ok(b) = kr_sys::fs::read_file(alloc::format!("{p}\0").as_bytes(), 1 << 20) {
            if let Ok(v) = json::parse(&b) {
                return Ok(v);
            }
        }
    }
    Err(alloc::format!("no cni config found in {dir}"))
}

/// Result of a CNI ADD: the pod IPs (v4/v6).
#[derive(Clone, Debug)]
pub struct CniResult {
    pub ipv4: Option<[u8; 4]>,
    pub ipv6: Option<[u8; 16]>,
}

async fn run_plugin(plugin: &str, _config: &str, envs: &[(&str, &str)], stdin: &[u8]) -> Result<Vec<u8>, String> {
    let bin = alloc::format!("{}/{}", bin_dir(), plugin);
    let env: Vec<(&str, &str)> = envs.to_vec();
    kr_runtime::container::run_command(bin.as_bytes(), &env, stdin).await
}

/// Run the CNI ADD chain. `netns` is the path to the pod's network namespace
/// (e.g. /proc/<pid>/ns/net). Returns the resulting IPs.
/// `args` is `CNI_ARGS` (`K8S_POD_NAMESPACE=..;K8S_POD_NAME=..`), which Calico and Cilium need.
pub async fn cni_add(config: &Value, container_id: &str, netns: &str, ifname: &str, args: &str) -> Result<CniResult, String> {
    // Handle conflist (plugins array) vs single plugin.
    let plugins: Vec<Value> = if let Some(arr) = config.get("plugins").and_then(Value::as_array) {
        arr.to_vec()
    } else {
        alloc::vec![config.clone()]
    };
    // Run each plugin in sequence, feeding the previous result (`prevResult`) to the next.
    let mut prev: Option<Value> = None;
    let mut last_stdout: Vec<u8> = Vec::new();
    for p in &plugins {
        let plugin_type = p.get("type").and_then(Value::as_str).ok_or("plugin missing type")?;
        // Build per-plugin config: merge top-level + plugin.
        let mut cfg = p.clone();
        if let Some(n) = config.get("name") { cfg.set("name", n.clone()); }
        if let Some(cv) = config.get("cniVersion") { cfg.set("cniVersion", cv.clone()); }
        if let Some(r) = &prev {
            cfg.set("prevResult", r.clone());
        }
        let cfg_str = json::to_string(&cfg);
        let cni_path = bin_dir();
        let envs = [
            ("CNI_COMMAND", "ADD"),
            ("CNI_CONTAINERID", container_id),
            ("CNI_NETNS", netns),
            ("CNI_IFNAME", ifname),
            ("CNI_ARGS", args),
            ("CNI_PATH", cni_path.as_str()),
        ];
        let stdout = run_plugin(plugin_type, &cfg_str, &envs, cfg_str.as_bytes()).await?;
        last_stdout = stdout;
        prev = json::parse(&last_stdout).ok();
    }
    // Parse final result.
    let r = json::parse(&last_stdout).map_err(|e| alloc::format!("parse cni result: {e}"))?;
    let mut res = CniResult { ipv4: None, ipv6: None };
    if let Some(ips) = r.get("ips").and_then(Value::as_array) {
        for ip in ips {
            let ver = ip.get("version").and_then(Value::as_str).unwrap_or("4");
            let addr = ip.get("address").and_then(Value::as_str).unwrap_or("");
            let ipstr = addr.split('/').next().unwrap_or("");
            if ver == "4" {
                let mut a = [0u8; 4];
                let mut ok = true;
                let mut parts = ipstr.split('.');
                for o in a.iter_mut() {
                    match parts.next().and_then(|x| x.parse().ok()) {
                        Some(v) => *o = v,
                        None => { ok = false; break; }
                    }
                }
                if ok { res.ipv4 = Some(a); }
            } else if ver == "6" {
                if let Some(a) = kr_net::tcp::parse_ipv6(ipstr) {
                    res.ipv6 = Some(a);
                }
            }
        }
    }
    Ok(res)
}

/// Run CNI DEL.
pub async fn cni_del(config: &Value, container_id: &str, netns: &str, ifname: &str, args: &str) -> Result<(), String> {
    let plugins: Vec<Value> = if let Some(arr) = config.get("plugins").and_then(Value::as_array) {
        arr.to_vec()
    } else {
        alloc::vec![config.clone()]
    };
    // DEL runs in reverse order.
    let mut first_err: Option<String> = None;
    for p in plugins.iter().rev() {
        let plugin_type = p.get("type").and_then(Value::as_str).ok_or("plugin missing type")?;
        let mut cfg = p.clone();
        if let Some(n) = config.get("name") { cfg.set("name", n.clone()); }
        if let Some(cv) = config.get("cniVersion") { cfg.set("cniVersion", cv.clone()); }
        let cfg_str = json::to_string(&cfg);
        let cni_path = bin_dir();
        let envs = [
            ("CNI_COMMAND", "DEL"),
            ("CNI_CONTAINERID", container_id),
            ("CNI_NETNS", netns),
            ("CNI_IFNAME", ifname),
            ("CNI_ARGS", args),
            ("CNI_PATH", cni_path.as_str()),
        ];
        // Best effort: one plugin failing must not leave the rest of the chain's state behind.
        if let Err(e) = run_plugin(plugin_type, &cfg_str, &envs, cfg_str.as_bytes()).await {
            first_err.get_or_insert(e);
        }
    }
    first_err.map_or(Ok(()), Err)
}

/// Whether CNI is configured (KR_CNI_CONF_DIR set and has config).
pub fn is_enabled() -> bool {
    conf_dir().map(|d| load_config(&d).is_ok()).unwrap_or(false)
}