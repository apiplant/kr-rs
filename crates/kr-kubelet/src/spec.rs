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
}

pub fn find_container<'a>(pod: &'a Value, name: &str) -> Option<&'a Value> {
    ["initContainers", "containers"]
        .iter()
        .flat_map(|k| pod.pointer(&["spec", k]).and_then(Value::as_array).unwrap_or(&[]).iter())
        .find(|c| c.get("name").and_then(Value::as_str) == Some(name))
}

/// spec.hostname, else the pod name, truncated to a valid 63-char label.
pub fn pod_hostname(pod: &Value) -> String {
    let h = pod.pointer(&["spec", "hostname"]).and_then(Value::as_str).filter(|h| !h.is_empty()).unwrap_or(meta(pod, "name"));
    h.chars().take(63).collect::<String>().trim_end_matches(['-', '.']).to_string()
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
async fn materialize<C: Client>(c: &C, ns: &str, kind: &str, name: &str, src: &Value, dir: &str) -> Result<(), String> {
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
    let selected: Vec<(String, Vec<u8>)> = match items {
        Some(items) => items
            .iter()
            .filter_map(|it| {
                let key = it.get("key")?.as_str()?;
                let path = it.get("path")?.as_str()?;
                files.iter().find(|(k, _)| k == key).map(|(_, v)| (path.to_string(), v.clone()))
            })
            .collect(),
        None => files,
    };
    kr_runtime::store::mkdir_p(dir, 0o755).map_err(|_| String::from("cannot create volume dir"))?;
    for (path, data) in selected {
        // Keys are validated by the API server; still refuse traversal here.
        if path.is_empty() || path.starts_with('/') || path.split('/').any(|c| c == ".." || c.is_empty()) {
            return Err(alloc::format!("invalid volume item path {path}"));
        }
        let full = alloc::format!("{dir}/{path}");
        if let Some((parent, _)) = full.rsplit_once('/') {
            let _ = kr_runtime::store::mkdir_p(parent, 0o755);
        }
        kr_runtime::store::write_file_atomic(&full, &data).map_err(|_| alloc::format!("cannot write {path}"))?;
    }
    Ok(())
}

fn write_item(dir: &str, path: &str, data: &[u8]) -> Result<(), String> {
    if path.is_empty() || path.starts_with('/') || path.split('/').any(|c| c == ".." || c.is_empty()) {
        return Err(alloc::format!("invalid volume item path {path}"));
    }
    let full = alloc::format!("{dir}/{path}");
    if let Some((parent, _)) = full.rsplit_once('/') {
        let _ = kr_runtime::store::mkdir_p(parent, 0o755);
    }
    kr_runtime::store::write_file_atomic(&full, data).map_err(|_| alloc::format!("cannot write {path}"))
}

/// downwardAPI items (fieldRef only; resourceFieldRef not yet).
fn downward(pod: &Value, d: &Value, dir: &str) -> Result<(), String> {
    for it in d.get("items").and_then(Value::as_array).unwrap_or(&[]) {
        let path = it.get("path").and_then(Value::as_str).unwrap_or("");
        let Some(fp) = it.pointer(&["fieldRef", "fieldPath"]).and_then(Value::as_str) else { continue };
        let val = match fp {
            "metadata.labels" | "metadata.annotations" => {
                let m = pod.pointer(&["metadata", &fp[9..]]).and_then(Value::as_object).unwrap_or(&[]);
                m.iter().map(|(k, v)| alloc::format!("{k}=\"{}\"\n", v.as_str().unwrap_or(""))).collect::<String>()
            }
            other => field_ref(pod, other, None, "").unwrap_or_default(),
        };
        write_item(dir, path, val.as_bytes())?;
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

/// Resolves a pod volume to a host directory (creating/materializing it).
async fn volume_source<C: Client>(c: &C, pod: &Value, vol: &Value, pod_dir: &str) -> Result<Option<String>, String> {
    let name = vol.get("name").and_then(Value::as_str).unwrap_or("");
    let ns = meta(pod, "namespace");
    let dir = alloc::format!("{pod_dir}/volumes/{name}");
    if vol.get("emptyDir").is_some() {
        kr_runtime::store::mkdir_p(&dir, 0o777).map_err(|_| String::from("cannot create emptyDir"))?;
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
    } else if let Some(cm) = vol.get("configMap") {
        materialize(c, ns, "configmaps", cm.get("name").and_then(Value::as_str).unwrap_or(""), cm, &dir).await?;
        Ok(Some(dir))
    } else if let Some(sec) = vol.get("secret") {
        materialize(c, ns, "secrets", sec.get("secretName").and_then(Value::as_str).unwrap_or(""), sec, &dir).await?;
        Ok(Some(dir))
    } else if let Some(pj) = vol.get("projected") {
        let _ = kr_runtime::store::mkdir_p(&dir, 0o755);
        for src in pj.get("sources").and_then(Value::as_array).unwrap_or(&[]) {
            if let Some(t) = src.get("serviceAccountToken") {
                let token = request_token(c, pod, t).await?;
                let path = t.get("path").and_then(Value::as_str).unwrap_or("token");
                write_item(&dir, path, token.as_bytes())?;
            } else if let Some(cm) = src.get("configMap") {
                materialize(c, ns, "configmaps", cm.get("name").and_then(Value::as_str).unwrap_or(""), cm, &dir).await?;
            } else if let Some(sec) = src.get("secret") {
                materialize(c, ns, "secrets", sec.get("name").and_then(Value::as_str).unwrap_or(""), sec, &dir).await?;
            } else if let Some(d) = src.get("downwardAPI") {
                downward(pod, d, &dir)?;
            }
        }
        Ok(Some(dir))
    } else if let Some(d) = vol.get("downwardAPI") {
        let _ = kr_runtime::store::mkdir_p(&dir, 0o755);
        downward(pod, d, &dir)?;
        Ok(Some(dir))
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
            } else {
                None // resourceFieldRef: not yet
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
    let mut mounts = alloc::vec![Mount { source: alloc::format!("{pod_dir}/etc-hosts").into_bytes(), target: b"/etc/hosts".to_vec(), readonly: false }];
    for vm in ctr.get("volumeMounts").and_then(Value::as_array).unwrap_or(&[]) {
        let name = vm.get("name").and_then(Value::as_str).unwrap_or("");
        let target = vm.get("mountPath").and_then(Value::as_str).unwrap_or("");
        let vol = vols.iter().find(|v| v.get("name").and_then(Value::as_str) == Some(name)).ok_or_else(|| alloc::format!("volume {name} not found"))?;
        let Some(mut src) = volume_source(c, pod, vol, pod_dir).await? else { continue };
        if let Some(sub) = vm.get("subPath").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            if sub.starts_with('/') || sub.split('/').any(|c| c == "..") {
                return Err(alloc::format!("invalid subPath {sub}"));
            }
            src = alloc::format!("{src}/{sub}");
        }
        let ro = vm.get("readOnly").and_then(Value::as_bool).unwrap_or(false) || ["configMap", "secret", "projected", "downwardAPI"].iter().any(|k| vol.get(k).is_some());
        mounts.push(Mount { source: src.into_bytes(), target: target.as_bytes().to_vec(), readonly: ro });
    }
    let cwd = ctr.get("workingDir").and_then(Value::as_str).filter(|w| !w.is_empty()).map(String::from).unwrap_or_else(|| img.working_dir.clone());
    Ok(Built {
        argv: argv.into_iter().map(String::into_bytes).collect(),
        env: env.into_iter().map(|(k, v)| alloc::format!("{k}={v}").into_bytes()).collect(),
        cwd,
        user,
        mounts,
        limits,
    })
}
