//! Pod spec -> runtime spec: argv (Kubernetes command/args vs image entrypoint/cmd), env
//! (including `valueFrom`), user, cgroup limits and volume mounts.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_apiserver::client::{meta, Client};
use kr_fmt::json::Value;
use kr_fmt::quantity::Quantity;
use kr_runtime::cgroup::Limits;
use kr_runtime::container::Mount;
use kr_runtime::store::ImageConfig;

pub struct Built {

    pub argv: Vec<Vec<u8>>,
    pub env: Vec<Vec<u8>>,
    pub cwd: String,
    pub user: String,
    pub mounts: Vec<Mount>,
    pub limits: Limits,
    /// fsGroup + supplementalGroups.
    pub extra_groups: Vec<u32>,
}

pub fn find_container<'a>(pod: &'a Value, name: &str) -> Option<&'a Value> {
    ["initContainers", "containers", "ephemeralContainers"]
        .iter()
        .flat_map(|k| pod.pointer(&["spec", k]).and_then(Value::as_array).unwrap_or(&[]).iter())
        .find(|c| c.get("name").and_then(Value::as_str) == Some(name))
}

/// spec.hostname, else the pod name, truncated to a valid 63-char label.
pub fn pod_hostname(pod: &Value) -> String {
    let h = pod.pointer(&["spec", "hostname"]).and_then(Value::as_str).filter(|h| !h.is_empty()).unwrap_or(meta(pod, "name"));
    h.chars().take(63).collect::<String>().trim_end_matches(['-', '.']).to_string()
}

/// /etc/resolv.conf for the pod per `dnsPolicy` (ClusterFirst by default).
pub fn write_resolv_conf(pod_dir: &str, pod: &Value) -> Result<(), ()> {
    let ns = meta(pod, "namespace");
    let policy = pod.pointer(&["spec", "dnsPolicy"]).and_then(Value::as_str).unwrap_or("ClusterFirst");
    let host_net = pod.pointer(&["spec", "hostNetwork"]).and_then(Value::as_bool) == Some(true);
    let mut s = match policy {
        "Default" => String::from_utf8(kr_sys::fs::read_file(b"/etc/resolv.conf\0", 64 * 1024).unwrap_or_default()).unwrap_or_default(),
        "ClusterFirstWithHostNet" | "ClusterFirst" if !(host_net && policy == "ClusterFirst") => {
            alloc::format!("search {ns}.svc.cluster.local svc.cluster.local cluster.local\nnameserver 10.96.0.10\noptions ndots:5\n")
        }
        "ClusterFirst" => String::from_utf8(kr_sys::fs::read_file(b"/etc/resolv.conf\0", 64 * 1024).unwrap_or_default()).unwrap_or_default(),
        _ => String::new(), // "None": only dnsConfig below
    };
    if let Some(cfg) = pod.pointer(&["spec", "dnsConfig"]) {
        for n in cfg.get("nameservers").and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(Value::as_str) {
            s.push_str(&alloc::format!("nameserver {n}\n"));
        }
        let search: Vec<&str> = cfg.get("searches").and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(Value::as_str).collect();
        if !search.is_empty() {
            s.push_str(&alloc::format!("search {}\n", search.join(" ")));
        }
        for o in cfg.get("options").and_then(Value::as_array).unwrap_or(&[]) {
            let name = o.get("name").and_then(Value::as_str).unwrap_or("");
            match o.get("value").and_then(Value::as_str) {
                Some(v) => s.push_str(&alloc::format!("options {name}:{v}\n")),
                None => s.push_str(&alloc::format!("options {name}\n")),
            }
        }
    }
    kr_runtime::store::write_file_atomic(&alloc::format!("{pod_dir}/resolv.conf"), s.as_bytes()).map_err(|_| ())
}

/// Docker-link style service environment variables for the pod's namespace.
async fn service_env<C: Client>(c: &C, pod: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    // The kubernetes service is always injected; others only with enableServiceLinks.
    let links = pod.pointer(&["spec", "enableServiceLinks"]).and_then(Value::as_bool) != Some(false);
    let ns = meta(pod, "namespace");
    let mut svcs: Vec<Value> = Vec::new();
    if let Ok(l) = c.get("/api/v1/namespaces/default/services/kubernetes").await {
        svcs.push(l);
    }
    if links {
        if let Ok(l) = c.list(&alloc::format!("/api/v1/namespaces/{ns}/services"), "").await {
            svcs.extend(l.get("items").and_then(Value::as_array).unwrap_or(&[]).iter().filter(|s| !(ns == "default" && meta(s, "name") == "kubernetes")).cloned());
        }
    }
    for s in svcs {
        let Some(ip) = s.pointer(&["spec", "clusterIP"]).and_then(Value::as_str).filter(|i| !i.is_empty() && *i != "None") else { continue };
        let name: String = meta(&s, "name").chars().map(|c| if c == '-' { '_' } else { c.to_ascii_uppercase() }).collect();
        let ports = s.pointer(&["spec", "ports"]).and_then(Value::as_array).unwrap_or(&[]);
        let Some(first) = ports.first() else { continue };
        let port = |p: &Value| p.get("port").and_then(Value::as_u64).unwrap_or(0);
        let proto = |p: &Value| p.get("protocol").and_then(Value::as_str).unwrap_or("TCP").to_string();
        out.push((alloc::format!("{name}_SERVICE_HOST"), ip.to_string()));
        out.push((alloc::format!("{name}_SERVICE_PORT"), port(first).to_string()));
        out.push((alloc::format!("{name}_PORT"), alloc::format!("{}://{ip}:{}", proto(first).to_ascii_lowercase(), port(first))));
        for p in ports {
            let pr = proto(p);
            let base = alloc::format!("{name}_PORT_{}_{}", port(p), pr);
            if let Some(pn) = p.get("name").and_then(Value::as_str).filter(|n| !n.is_empty()) {
                out.push((alloc::format!("{name}_SERVICE_PORT_{}", pn.replace('-', "_").to_ascii_uppercase()), port(p).to_string()));
            }
            out.push((base.clone(), alloc::format!("{}://{ip}:{}", pr.to_ascii_lowercase(), port(p))));
            out.push((alloc::format!("{base}_PROTO"), pr.to_ascii_lowercase()));
            out.push((alloc::format!("{base}_PORT"), port(p).to_string()));
            out.push((alloc::format!("{base}_ADDR"), ip.to_string()));
        }
    }
    out
}

pub fn write_etc_hosts(pod_dir: &str, hostname: &str, ip: Option<[u8; 4]>) -> Result<(), ()> {
    let mut s = String::from("# Kubernetes-managed hosts file (kr).\n127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n");
    if let Some(a) = ip {
        s.push_str(&alloc::format!("{}.{}.{}.{}\t{hostname}\n", a[0], a[1], a[2], a[3]));
    }
    kr_runtime::store::write_file_atomic(&alloc::format!("{pod_dir}/etc-hosts"), s.as_bytes()).map_err(|_| ())
}

fn strs(v: Option<&Value>) -> Option<Vec<String>> {
    v.and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
}

/// Expands `$(VAR)` references against already-defined env (`$$` escapes), as Kubernetes does.
fn expand(s: &str, env: &[(String, String)]) -> String {
    let b = s.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'$' && b.get(i + 1) == Some(&b'$') {
            out.push('$');
            i += 2;
        } else if b[i] == b'$' && b.get(i + 1) == Some(&b'(') {
            if let Some(end) = s[i + 2..].find(')') {
                let name = &s[i + 2..i + 2 + end];
                match env.iter().rev().find(|(k, _)| k == name) {
                    Some((_, v)) => out.push_str(v),
                    None => out.push_str(&s[i..i + 3 + end]),
                }
                i += 3 + end;
                continue;
            }
            out.push('$');
            i += 1;
        } else {
            let ch = s[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

async fn key_ref<C: Client>(c: &C, ns: &str, kind: &str, r: &Value) -> Result<Option<String>, String> {
    let name = r.get("name").and_then(Value::as_str).unwrap_or("");
    let key = r.get("key").and_then(Value::as_str).unwrap_or("");
    let optional = r.get("optional").and_then(Value::as_bool).unwrap_or(false);
    let obj = match c.get(&alloc::format!("/api/v1/namespaces/{ns}/{kind}/{name}")).await {
        Ok(o) => o,
        Err(_) if optional => return Ok(None),
        Err(_) => return Err(alloc::format!("{kind} \"{name}\" not found")),
    };
    let v = obj.get("data").and_then(|d| d.get(key)).and_then(Value::as_str);
    let v = match (kind, v) {
        ("secrets", Some(b64)) => kr_fmt::base64::decode(b64).ok().and_then(|b| String::from_utf8(b).ok()),
        (_, v) => v.map(String::from),
    };
    match v {
        Some(v) => Ok(Some(v)),
        None if optional => Ok(None),
        None => Err(alloc::format!("couldn't find key {key} in {kind} {ns}/{name}")),
    }
}

fn field_ref(pod: &Value, path: &str, ip: Option<[u8; 4]>, node: &str) -> Option<String> {
    Some(match path {
        "metadata.name" | "metadata.namespace" | "metadata.uid" => meta(pod, &path[9..]).to_string(),
        "spec.nodeName" => node.to_string(),
        "spec.serviceAccountName" => pod.pointer(&["spec", "serviceAccountName"]).and_then(Value::as_str).unwrap_or("default").to_string(),
        "status.podIP" => ip.map(|a| alloc::format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])).unwrap_or_default(),
        "status.hostIP" => "127.0.0.1".to_string(),
        p if p.starts_with("metadata.labels['") || p.starts_with("metadata.annotations['") => {
            let (field, rest) = p.split_once("['")?;
            let key = rest.strip_suffix("']")?;
            pod.pointer(&["metadata", &field[9..], key]).and_then(Value::as_str).unwrap_or("").to_string()
        }
        _ => return None,
    })
}

fn quantity(v: Option<&Value>) -> Option<Quantity> {
    v.and_then(Value::as_str).and_then(|s| Quantity::parse(s).ok()).or_else(|| v.and_then(Value::as_i64).map(|n| Quantity::from_i64(n, kr_fmt::quantity::Format::DecimalSI)))
}

/// Writes a configMap/secret volume's files into `dir`.
async fn materialize<C: Client>(c: &C, ns: &str, kind: &str, name: &str, src: &Value, dir: &str, default_mode: u32) -> Result<(), String> {
    let optional = src.get("optional").and_then(Value::as_bool).unwrap_or(false);
    let obj = match c.get(&alloc::format!("/api/v1/namespaces/{ns}/{kind}/{name}")).await {
        Ok(o) => o,
        Err(_) if optional => return Ok(()),
        Err(_) => return Err(alloc::format!("{kind} \"{name}\" not found")),
    };
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    for (field, b64) in [("data", kind == "secrets"), ("binaryData", true), ("stringData", false)] {
        for (k, v) in obj.get(field).and_then(Value::as_object).unwrap_or(&[]) {
            let Some(s) = v.as_str() else { continue };
            let bytes = if b64 { kr_fmt::base64::decode(s).map_err(|_| alloc::format!("{kind} {name}: bad base64 in {k}"))? } else { s.as_bytes().to_vec() };
            files.push((k.clone(), bytes));
        }
    }
    let items = src.get("items").and_then(Value::as_array);
    let selected: Vec<(String, Vec<u8>, u32)> = match items {
        Some(items) => items
            .iter()
            .filter_map(|it| {
                let key = it.get("key")?.as_str()?;
                let path = it.get("path")?.as_str()?;
                files.iter().find(|(k, _)| k == key).map(|(_, v)| (path.to_string(), v.clone(), item_mode(it, default_mode)))
            })
            .collect(),
        None => files.into_iter().map(|(k, v)| (k, v, default_mode)).collect(),
    };
    kr_runtime::store::mkdir_p(dir, 0o755).map_err(|_| String::from("cannot create volume dir"))?;
    for (path, data, mode) in selected {
        write_item(dir, &path, &data, mode)?;
    }
    Ok(())
}

/// A volume's `defaultMode` (0644 when unset).
fn default_mode(src: &Value) -> u32 {
    src.get("defaultMode").and_then(Value::as_u64).map_or(0o644, |m| m as u32 & 0o777)
}

fn item_mode(item: &Value, default: u32) -> u32 {
    item.get("mode").and_then(Value::as_u64).map_or(default, |m| m as u32 & 0o777)
}

fn write_item(dir: &str, path: &str, data: &[u8], mode: u32) -> Result<(), String> {
    // Paths are validated by the API server; still refuse traversal here.
    if path.is_empty() || path.starts_with('/') || path.split('/').any(|c| c == ".." || c.is_empty()) {
        return Err(alloc::format!("invalid volume item path {path}"));
    }
    let full = alloc::format!("{dir}/{path}");
    if let Some((parent, _)) = full.rsplit_once('/') {
        let _ = kr_runtime::store::mkdir_p(parent, 0o755);
    }
    kr_runtime::store::write_file_atomic(&full, data).map_err(|_| alloc::format!("cannot write {path}"))?;
    let fd = kr_sys::ns::open(alloc::format!("{full}\0").as_bytes(), kr_sys::ns::O_RDONLY | kr_sys::fs::O_NOFOLLOW | kr_sys::O_CLOEXEC, 0).map_err(|_| alloc::format!("cannot open {path}"))?;
    kr_sys::fs::fchmod(fd.raw(), mode).map_err(|_| alloc::format!("cannot chmod {path}"))
}

/// downwardAPI items: fieldRef and resourceFieldRef.
fn downward(pod: &Value, d: &Value, dir: &str, default_mode: u32) -> Result<(), String> {
    for it in d.get("items").and_then(Value::as_array).unwrap_or(&[]) {
        let path = it.get("path").and_then(Value::as_str).unwrap_or("");
        let val = if let Some(fp) = it.pointer(&["fieldRef", "fieldPath"]).and_then(Value::as_str) {
            match fp {
                "metadata.labels" | "metadata.annotations" => {
                    let m = pod.pointer(&["metadata", &fp[9..]]).and_then(Value::as_object).unwrap_or(&[]);
                    m.iter().map(|(k, v)| alloc::format!("{k}=\"{}\"\n", v.as_str().unwrap_or(""))).collect::<String>()
                }
                other => field_ref(pod, other, None, "").unwrap_or_default(),
            }
        } else if let Some(rf) = it.get("resourceFieldRef") {
            resource_field_ref(pod, None, rf).ok_or_else(|| alloc::format!("downwardAPI {path}: unsupported resourceFieldRef"))?
        } else {
            continue;
        };
        write_item(dir, path, val.as_bytes(), item_mode(it, default_mode))?;
    }
    Ok(())
}

/// `resourceFieldRef`: a container's request or limit in units of `divisor` (rounded up).
/// Unset limits report node allocatable, as upstream.
fn resource_field_ref(pod: &Value, container: Option<&str>, rf: &Value) -> Option<String> {
    let cname = rf.get("containerName").and_then(Value::as_str).filter(|n| !n.is_empty()).or(container)?;
    let ctr = ["containers", "initContainers"].iter().flat_map(|k| pod.pointer(&["spec", k]).and_then(Value::as_array).unwrap_or(&[]).iter()).find(|c| c.get("name").and_then(Value::as_str) == Some(cname))?;
    let (kind, res) = rf.get("resource").and_then(Value::as_str)?.split_once('.')?;
    let set = quantity(ctr.pointer(&["resources", kind, res]));
    let q = match (set, kind, res) {
        (Some(q), _, _) => q,
        (None, "limits", "cpu") => Quantity::from_i64(crate::node::cpus() as i64, kr_fmt::quantity::Format::DecimalSI),
        (None, "limits", "memory") => Quantity::from_i64(crate::node::memory_ki() as i64 * 1024, kr_fmt::quantity::Format::BinarySI),
        (None, "requests", "cpu" | "memory" | "ephemeral-storage") => return Some(String::from("0")),
        _ => return None,
    };
    let divisor = quantity(rf.get("divisor")).unwrap_or_else(|| Quantity::from_i64(1, kr_fmt::quantity::Format::DecimalSI));
    let (n, d) = if res == "cpu" { (q.milli_value()?, divisor.milli_value()?) } else { (q.value()?, divisor.value()?) };
    if d <= 0 {
        return None;
    }
    Some(alloc::format!("{}", (n + d - 1).div_euclid(d)))
}

/// Writes a configMap/secret/projected/downwardAPI volume's files into `stage`.
async fn stage_volume<C: Client>(c: &C, pod: &Value, vol: &Value, dir: &str, stage: &str) -> Result<(), String> {
    let ns = meta(pod, "namespace");
    if let Some(cm) = vol.get("configMap") {
        materialize(c, ns, "configmaps", cm.get("name").and_then(Value::as_str).unwrap_or(""), cm, stage, default_mode(cm)).await
    } else if let Some(sec) = vol.get("secret") {
        materialize(c, ns, "secrets", sec.get("secretName").and_then(Value::as_str).unwrap_or(""), sec, stage, default_mode(sec)).await
    } else if let Some(pj) = vol.get("projected") {
        let mode = default_mode(pj);
        for src in pj.get("sources").and_then(Value::as_array).unwrap_or(&[]) {
            if let Some(t) = src.get("serviceAccountToken") {
                let path = t.get("path").and_then(Value::as_str).unwrap_or("token");
                // Reuse the current token until 80% of its lifetime.
                let exp = t.get("expirationSeconds").and_then(Value::as_i64).unwrap_or(3600);
                let cur = alloc::format!("{dir}/..data/{path}\0");
                let fresh = kr_sys::fs::newfstatat(kr_sys::fs::AT_FDCWD, cur.as_bytes(), 0).ok().filter(|st| now_secs() - st.mtime_sec < exp * 8 / 10);
                let token = match fresh.and_then(|_| kr_sys::fs::read_file(cur.as_bytes(), 1 << 16).ok()) {
                    Some(t) => t,
                    None => request_token(c, pod, t).await?.into_bytes(),
                };
                write_item(stage, path, &token, mode)?;
            } else if let Some(cm) = src.get("configMap") {
                materialize(c, ns, "configmaps", cm.get("name").and_then(Value::as_str).unwrap_or(""), cm, stage, mode).await?;
            } else if let Some(sec) = src.get("secret") {
                materialize(c, ns, "secrets", sec.get("name").and_then(Value::as_str).unwrap_or(""), sec, stage, mode).await?;
            } else if let Some(d) = src.get("downwardAPI") {
                downward(pod, d, stage, mode)?;
            }
        }
        Ok(())
    } else if let Some(d) = vol.get("downwardAPI") {
        downward(pod, d, stage, default_mode(d))
    } else {
        Ok(())
    }
}

fn now_secs() -> i64 {
    kr_sys::clock_gettime(0).map(|t| t.tv_sec).unwrap_or(0)
}

/// Points `dir/..data` at `stage_name`, links each top-level entry through it, and removes
/// stale entries and old stages.
fn publish(dir: &str, stage_name: &str) -> Result<(), String> {
    use kr_sys::fs::{self, AT_FDCWD};
    let c = |s: &str| alloc::format!("{s}\0").into_bytes();
    let swap_link = |target: &str, link: &str| -> Result<(), String> {
        let tmp = alloc::format!("{dir}/..tmp_link");
        let _ = fs::unlinkat(AT_FDCWD, &c(&tmp), 0);
        fs::symlinkat(&c(target), AT_FDCWD, &c(&tmp)).map_err(|e| alloc::format!("symlink {link}: errno {}", e.0))?;
        fs::renameat2(AT_FDCWD, &c(&tmp), AT_FDCWD, &c(&alloc::format!("{dir}/{link}")), 0).map_err(|e| alloc::format!("rename {link}: errno {}", e.0))
    };
    let names = |path: &str| -> Vec<String> {
        let Ok(fd) = kr_sys::ns::open(&c(path), kr_sys::ns::O_RDONLY | kr_sys::ns::O_DIRECTORY | kr_sys::O_CLOEXEC, 0) else { return Vec::new() };
        fs::read_dir(&fd).filter_map(|e| e.ok()).filter_map(|e| String::from_utf8(e.name).ok()).collect()
    };
    let dfd = kr_sys::ns::open(&c(dir), kr_sys::ns::O_RDONLY | kr_sys::ns::O_DIRECTORY | kr_sys::O_CLOEXEC, 0).map_err(|e| alloc::format!("open {dir}: errno {}", e.0))?;
    swap_link(stage_name, "..data")?;
    let top: Vec<String> = names(&alloc::format!("{dir}/{stage_name}"));
    for n in &top {
        let p = c(&alloc::format!("{dir}/{n}"));
        // A real file or dir from an older layout is replaced by the link.
        if fs::newfstatat(AT_FDCWD, &p, fs::AT_SYMLINK_NOFOLLOW).is_ok_and(|st| !st.is_symlink()) {
            let _ = fs::remove_all(dfd.raw(), &c(n));
        }
        swap_link(&alloc::format!("..data/{n}"), n)?;
    }
    for n in names(dir) {
        let stale = if n.starts_with("..") { n != "..data" && n != stage_name } else { !top.contains(&n) };
        if stale {
            let _ = fs::remove_all(dfd.raw(), &c(&n));
        }
    }
    Ok(())
}

/// Requests a pod-bound ServiceAccount token (TokenRequest API).
async fn request_token<C: Client>(c: &C, pod: &Value, src: &Value) -> Result<String, String> {
    let ns = meta(pod, "namespace");
    let sa = pod.pointer(&["spec", "serviceAccountName"]).and_then(Value::as_str).unwrap_or("default");
    let exp = src.get("expirationSeconds").and_then(Value::as_i64).unwrap_or(3607);
    let aud = src.get("audience").and_then(Value::as_str).map(|a| alloc::format!(r#","audiences":["{a}"]"#)).unwrap_or_default();
    let body = alloc::format!(
        r#"{{"apiVersion":"authentication.k8s.io/v1","kind":"TokenRequest","spec":{{"expirationSeconds":{exp}{aud},"boundObjectRef":{{"kind":"Pod","apiVersion":"v1","name":"{}","uid":"{}"}}}}}}"#,
        meta(pod, "name"),
        meta(pod, "uid")
    );
    let req = kr_fmt::json::parse(body.as_bytes()).map_err(|_| String::from("bad token request"))?;
    let r = c.create(&alloc::format!("/api/v1/namespaces/{ns}/serviceaccounts/{sa}/token"), &req).await.map_err(|e| alloc::format!("token request failed: {}", e.message))?;
    r.pointer(&["status", "token"]).and_then(Value::as_str).map(String::from).ok_or_else(|| String::from("token request returned no token"))
}

/// mkdir -p of `rel` beneath `root`, without following symlinks; returns an O_PATH fd.
fn create_beneath(root: &kr_sys::Fd, rel: &str) -> Option<kr_sys::Fd> {
    let how = kr_sys::fs::OpenHow {
        flags: (kr_sys::fs::O_PATH | kr_sys::ns::O_DIRECTORY | kr_sys::O_CLOEXEC) as u64,
        mode: 0,
        resolve: kr_sys::fs::RESOLVE_NO_SYMLINKS | kr_sys::fs::RESOLVE_BENEATH | kr_sys::fs::RESOLVE_NO_MAGICLINKS,
    };
    let mut cur: Option<kr_sys::Fd> = None;
    for comp in rel.split('/').filter(|c| !c.is_empty() && *c != ".") {
        let dir = cur.as_ref().unwrap_or(root).raw();
        let name = alloc::format!("{comp}\0");
        match kr_sys::fs::mkdirat(dir, name.as_bytes(), 0o755) {
            Ok(()) | Err(kr_sys::Errno(17)) => {}
            Err(_) => return None,
        }
        cur = Some(kr_sys::fs::openat2(dir, name.as_bytes(), &how).ok()?);
    }
    cur
}

/// fsGroup ownership: volumes become group-owned by `gid` with the setgid bit (and group
/// write for emptyDir), like the kubelet's volume ownership management. Runs inside a user
/// namespace with the pod's maps so container ids are mapped (works rootless).
pub fn apply_fs_group(maps: &kr_runtime::container::IdMaps, pod: &Value, pod_dir: &str) {
    let Some(gid) = pod.pointer(&["spec", "securityContext", "fsGroup"]).and_then(Value::as_u64).map(|g| g as u32) else { return };
    let vols: Vec<String> = pod
        .pointer(&["spec", "volumes"])
        .and_then(Value::as_array)
        .unwrap_or(&[])
        .iter()
        .filter(|v| ["emptyDir", "configMap", "secret", "projected", "downwardAPI"].iter().any(|k| v.get(k).is_some()))
        .filter_map(|v| v.get("name").and_then(Value::as_str).map(|n| alloc::format!("{pod_dir}/volumes/{n}")))
        .collect();
    let _ = maps.run_as_root(|| {
        for d in &vols {
            chown_tree(d, gid, 0);
        }
        true
    });
}

/// Recursively sets group `gid` (uid unchanged) and setgid on directories.
fn chown_tree(path: &str, gid: u32, depth: u32) {
    if depth > 16 {
        return;
    }
    let p = alloc::format!("{path}\0");
    let _ = kr_sys::fs::fchownat(kr_sys::ns::AT_FDCWD, p.as_bytes(), u32::MAX, gid, 0x100); // AT_SYMLINK_NOFOLLOW
    let Ok(fd) = kr_sys::ns::open(p.as_bytes(), kr_sys::ns::O_RDONLY | kr_sys::ns::O_DIRECTORY | kr_sys::fs::O_NOFOLLOW, 0) else { return };
    if let Ok(st) = kr_sys::fs::fstat(fd.raw()) {
        let _ = kr_sys::fs::fchmod(fd.raw(), (st.mode & 0o7777) | 0o2070);
    }
    let names: Vec<Vec<u8>> = kr_sys::fs::read_dir(&fd).filter_map(|e| e.ok()).map(|e| e.name).collect();
    for name in names {
        let n = String::from_utf8_lossy(&name).into_owned();
        if n == "." || n == ".." {
            continue;
        }
        let child = alloc::format!("{path}/{n}");
        let c = alloc::format!("{child}\0");
        let is_dir = kr_sys::ns::open(c.as_bytes(), kr_sys::ns::O_RDONLY | kr_sys::ns::O_DIRECTORY | kr_sys::fs::O_NOFOLLOW, 0).is_ok();
        if is_dir {
            chown_tree(&child, gid, depth + 1);
        } else {
            let _ = kr_sys::fs::fchownat(kr_sys::ns::AT_FDCWD, c.as_bytes(), u32::MAX, gid, 0x100);
        }
    }
}

/// Re-materializes configMap/secret/projected/downwardAPI volumes of a running pod (live
/// updates and token rotation). Files are replaced atomically.
pub async fn refresh_volumes<C: Client>(c: &C, pod: &Value, pod_dir: &str) {
    for vol in pod.pointer(&["spec", "volumes"]).and_then(Value::as_array).unwrap_or(&[]) {
        if ["configMap", "secret", "projected", "downwardAPI"].iter().any(|k| vol.get(k).is_some()) {
            let _ = volume_source(c, pod, vol, pod_dir).await;
        }
    }
}

/// Resolves a pod volume to a host directory (creating/materializing it).
async fn volume_source<C: Client>(c: &C, pod: &Value, vol: &Value, pod_dir: &str) -> Result<Option<String>, String> {
    let name = vol.get("name").and_then(Value::as_str).unwrap_or("");
    let dir = alloc::format!("{pod_dir}/volumes/{name}");
    if vol.get("emptyDir").is_some() {
        kr_runtime::store::mkdir_p(&dir, 0o777).map_err(|_| String::from("cannot create emptyDir"))?;
        // World-writable like upstream (mkdir is subject to the umask).
        if let Ok(fd) = kr_sys::ns::open(alloc::format!("{dir}\0").as_bytes(), kr_sys::ns::O_RDONLY | kr_sys::ns::O_DIRECTORY, 0) {
            let _ = kr_sys::fs::fchmod(fd.raw(), 0o777);
        }
        Ok(Some(dir))
    } else if let Some(h) = vol.get("hostPath") {
        let path = h.get("path").and_then(Value::as_str).unwrap_or("");
        if !path.starts_with('/') {
            return Err(alloc::format!("hostPath {path} must be absolute"));
        }
        if matches!(h.get("type").and_then(Value::as_str), Some("DirectoryOrCreate")) {
            let _ = kr_runtime::store::mkdir_p(path, 0o755);
        }
        Ok(Some(path.to_string()))
    } else if ["configMap", "secret", "projected", "downwardAPI"].iter().any(|k| vol.get(k).is_some()) {
        // Atomic writer (as upstream): files go to a fresh `..<ts>` dir, `..data` is swapped to
        // it, and top-level names are symlinks through `..data`. A reader never sees a mix.
        kr_runtime::store::mkdir_p(&dir, 0o755).map_err(|_| String::from("cannot create volume dir"))?;
        let stage_name = alloc::format!("..{}", kr_rt::exec::now_ns());
        let stage = alloc::format!("{dir}/{stage_name}");
        kr_runtime::store::mkdir_p(&stage, 0o755).map_err(|_| String::from("cannot create volume dir"))?;
        let r = stage_volume(c, pod, vol, &dir, &stage).await.and_then(|()| publish(&dir, &stage_name));
        if r.is_err() {
            if let Ok(fd) = kr_sys::ns::open(alloc::format!("{dir}\0").as_bytes(), kr_sys::ns::O_RDONLY | kr_sys::ns::O_DIRECTORY | kr_sys::O_CLOEXEC, 0) {
                let _ = kr_sys::fs::remove_all(fd.raw(), alloc::format!("{stage_name}\0").as_bytes());
            }
        }
        r.map(|()| Some(dir))
    } else {
        // PVCs and other types: not yet (KNOWN_ISSUES); mounted as an empty dir.
        kr_runtime::store::mkdir_p(&dir, 0o755).map_err(|_| String::from("cannot create volume dir"))?;
        Ok(Some(dir))
    }
}

pub async fn build<C: Client>(c: &C, pod: &Value, ctr: &Value, img: &ImageConfig, pod_dir: &str, ip: Option<[u8; 4]>, node: &str) -> Result<Built, String> {
    let ns = meta(pod, "namespace");
    // env: image env, then container env (later wins), with $(VAR) expansion.
    let mut env: Vec<(String, String)> = img.env.iter().filter_map(|e| e.split_once('=').map(|(k, v)| (k.to_string(), v.to_string()))).collect();
    if !env.iter().any(|(k, _)| k == "PATH") {
        env.push(("PATH".into(), "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into()));
    }
    env.push(("HOSTNAME".into(), pod_hostname(pod)));
    env.extend(service_env(c, pod).await);
    for from in ctr.get("envFrom").and_then(Value::as_array).unwrap_or(&[]) {
        let prefix = from.get("prefix").and_then(Value::as_str).unwrap_or("");
        for (kind, field, b64) in [("configmaps", "configMapRef", false), ("secrets", "secretRef", true)] {
            let Some(r) = from.get(field) else { continue };
            let name = r.get("name").and_then(Value::as_str).unwrap_or("");
            match c.get(&alloc::format!("/api/v1/namespaces/{ns}/{kind}/{name}")).await {
                Ok(o) => {
                    for (k, v) in o.get("data").and_then(Value::as_object).unwrap_or(&[]) {
                        let val = v.as_str().unwrap_or("");
                        let val = if b64 { kr_fmt::base64::decode(val).ok().and_then(|b| String::from_utf8(b).ok()).unwrap_or_default() } else { val.to_string() };
                        env.push((alloc::format!("{prefix}{k}"), val));
                    }
                }
                Err(_) if r.get("optional").and_then(Value::as_bool) == Some(true) => {}
                Err(_) => return Err(alloc::format!("{kind} \"{name}\" not found")),
            }
        }
    }
    for e in ctr.get("env").and_then(Value::as_array).unwrap_or(&[]) {
        let name = e.get("name").and_then(Value::as_str).unwrap_or("").to_string();
        let value = if let Some(v) = e.get("value").and_then(Value::as_str) {
            Some(expand(v, &env))
        } else if let Some(vf) = e.get("valueFrom") {
            if let Some(f) = vf.get("fieldRef") {
                field_ref(pod, f.get("fieldPath").and_then(Value::as_str).unwrap_or(""), ip, node)
            } else if let Some(r) = vf.get("configMapKeyRef") {
                key_ref(c, ns, "configmaps", r).await?
            } else if let Some(r) = vf.get("secretKeyRef") {
                key_ref(c, ns, "secrets", r).await?
            } else if let Some(rf) = vf.get("resourceFieldRef") {
                resource_field_ref(pod, ctr.get("name").and_then(Value::as_str), rf)
            } else {
                None
            }
        } else {
            Some(String::new())
        };
        if let Some(v) = value {
            env.push((name, v));
        }
    }
    // Later definitions win, as in a process environment built from a map.
    let mut dedup: Vec<(String, String)> = Vec::new();
    for (k, v) in env {
        dedup.retain(|(x, _)| *x != k);
        dedup.push((k, v));
    }
    let env = dedup;

    // argv: command replaces ENTRYPOINT (and drops CMD); args replaces CMD.
    let command = strs(ctr.get("command"));
    let args = strs(ctr.get("args"));
    let mut argv: Vec<String> = match (&command, &args) {
        (Some(cmd), Some(a)) => cmd.iter().chain(a.iter()).cloned().collect(),
        (Some(cmd), None) => cmd.clone(),
        (None, Some(a)) => img.entrypoint.iter().chain(a.iter()).cloned().collect(),
        (None, None) => img.entrypoint.iter().chain(img.cmd.iter()).cloned().collect(),
    };
    if command.is_some() || args.is_some() {
        argv = argv.iter().map(|a| expand(a, &env)).collect();
    }
    if argv.is_empty() {
        return Err("no command specified".into());
    }

    // user: container securityContext, then pod securityContext, then image USER.
    let sc = |k: &str| ctr.pointer(&["securityContext", k]).or_else(|| pod.pointer(&["spec", "securityContext", k])).and_then(Value::as_i64);
    let user = match (sc("runAsUser"), sc("runAsGroup")) {
        (Some(u), Some(g)) => alloc::format!("{u}:{g}"),
        (Some(u), None) => u.to_string(),
        (None, Some(g)) => alloc::format!("{}:{g}", if img.user.is_empty() { "0" } else { img.user.split(':').next().unwrap_or("0") }),
        (None, None) => img.user.clone(),
    };

    let mut limits = Limits { pids: Some(4096), ..Default::default() };
    if let Some(m) = quantity(ctr.pointer(&["resources", "limits", "memory"])) {
        limits.memory_bytes = m.value().and_then(|v| u64::try_from(v).ok()).filter(|v| *v > 0);
    }
    if let Some(cpu) = quantity(ctr.pointer(&["resources", "limits", "cpu"])) {
        limits.cpu_milli = cpu.milli_value().and_then(|v| u64::try_from(v).ok()).filter(|v| *v > 0);
    }

    if let Some(cpu) = quantity(ctr.pointer(&["resources", "requests", "cpu"])).or_else(|| quantity(ctr.pointer(&["resources", "limits", "cpu"]))) {
        limits.cpu_request_milli = cpu.milli_value().and_then(|v| u64::try_from(v).ok()).filter(|v| *v > 0);
    }
    let vols = pod.pointer(&["spec", "volumes"]).and_then(Value::as_array).unwrap_or(&[]);
    let mut mounts = alloc::vec![
        Mount { source: alloc::format!("{pod_dir}/etc-hosts").into_bytes(), sub_path: None, target: b"/etc/hosts".to_vec(), readonly: false },
        Mount { source: alloc::format!("{pod_dir}/resolv.conf").into_bytes(), sub_path: None, target: b"/etc/resolv.conf".to_vec(), readonly: false },
    ];
    for vm in ctr.get("volumeMounts").and_then(Value::as_array).unwrap_or(&[]) {
        let name = vm.get("name").and_then(Value::as_str).unwrap_or("");
        let target = vm.get("mountPath").and_then(Value::as_str).unwrap_or("");
        let vol = vols.iter().find(|v| v.get("name").and_then(Value::as_str) == Some(name)).ok_or_else(|| alloc::format!("volume {name} not found"))?;
        let Some(src) = volume_source(c, pod, vol, pod_dir).await? else { continue };
        let mut sub_path = None;
        if let Some(sub) = vm.get("subPath").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            if sub.starts_with('/') || sub.split('/').any(|c| c == "..") {
                return Err(alloc::format!("invalid subPath {sub}"));
            }
            // Resolve inside the volume (RESOLVE_IN_ROOT): a symlink the container created in
            // the volume cannot lead outside it. The O_PATH fd is what gets mounted.
            let root = kr_sys::ns::open(alloc::format!("{src}\0").as_bytes(), kr_sys::fs::O_PATH | kr_sys::ns::O_DIRECTORY, 0).map_err(|_| alloc::format!("volume {name} is missing"))?;
            let how = kr_sys::fs::OpenHow { flags: (kr_sys::fs::O_PATH | kr_sys::O_CLOEXEC) as u64, mode: 0, resolve: kr_sys::fs::RESOLVE_IN_ROOT | kr_sys::fs::RESOLVE_NO_MAGICLINKS };
            let fd = match kr_sys::fs::openat2(root.raw(), alloc::format!("{sub}\0").as_bytes(), &how) {
                Ok(fd) => fd,
                // Upstream creates a missing subPath directory. Create it one component at a
                // time, refusing symlinks, so a planted link cannot make us mkdir on the host.
                Err(_) => create_beneath(&root, sub).ok_or_else(|| alloc::format!("cannot resolve subPath {sub}"))?,
            };
            // The early resolution only validates and pre-creates; the container child resolves
            // again inside its own mount namespace (an fd from ours cannot be bind-mounted).
            drop(fd);
            sub_path = Some(sub.as_bytes().to_vec());
        }
        let ro = vm.get("readOnly").and_then(Value::as_bool).unwrap_or(false) || ["configMap", "secret", "projected", "downwardAPI"].iter().any(|k| vol.get(k).is_some());
        mounts.push(Mount { source: src.into_bytes(), sub_path, target: target.as_bytes().to_vec(), readonly: ro });
    }
    let mut extra_groups: Vec<u32> = pod.pointer(&["spec", "securityContext", "supplementalGroups"]).and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(Value::as_u64).map(|g| g as u32).collect();
    if let Some(fg) = pod.pointer(&["spec", "securityContext", "fsGroup"]).and_then(Value::as_u64) {
        extra_groups.push(fg as u32);
    }
    let cwd = ctr.get("workingDir").and_then(Value::as_str).filter(|w| !w.is_empty()).map(String::from).unwrap_or_else(|| img.working_dir.clone());
    Ok(Built {
        argv: argv.into_iter().map(String::into_bytes).collect(),
        env: env.into_iter().map(|(k, v)| alloc::format!("{k}={v}").into_bytes()).collect(),
        cwd,
        user,
        mounts,
        limits,
        extra_groups,
    })
}
