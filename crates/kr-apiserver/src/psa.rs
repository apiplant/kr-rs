//! Pod Security admission (the upstream PodSecurity plugin): namespace labels
//! `pod-security.kubernetes.io/{enforce,warn,audit}` = `privileged` | `baseline` | `restricted`
//! select the Pod Security Standard a namespace's pods must meet. Unlabelled namespaces are
//! `privileged` (upstream's default configuration); an unparseable level is evaluated as
//! `restricted` (fail closed), and namespaces with one are rejected.
//!
//! Pods are checked on create and on updates that change their spec; `enforce` rejects them,
//! `warn` adds a warning. Workload resources with a pod template only get warnings (and only for
//! `enforce`/`warn` levels), as upstream. The `-version` labels are accepted and ignored (all
//! checks are `latest`); there are no exemptions and no audit log (`audit` is accepted).
//!
//! Messages follow upstream's wording, e.g. `violates PodSecurity "baseline:latest": host
//! namespaces (hostNetwork=true), hostPort (container "c" uses hostPort 80)`.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_fmt::json::Value;

pub const ENFORCE: &str = "pod-security.kubernetes.io/enforce";
pub const WARN: &str = "pod-security.kubernetes.io/warn";
pub const AUDIT: &str = "pod-security.kubernetes.io/audit";

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Level {
    Privileged,
    Baseline,
    Restricted,
}

impl Level {
    fn name(self) -> &'static str {
        match self {
            Level::Privileged => "privileged",
            Level::Baseline => "baseline",
            Level::Restricted => "restricted",
        }
    }
}

fn parse(v: &str) -> Option<Level> {
    match v {
        "privileged" => Some(Level::Privileged),
        "baseline" => Some(Level::Baseline),
        "restricted" => Some(Level::Restricted),
        _ => None,
    }
}

/// The level a namespace label selects: absent is privileged, invalid is restricted.
fn level_of(ns: Option<&Value>, key: &str) -> Level {
    match ns.and_then(|n| n.pointer(&["metadata", "labels", key])).and_then(Value::as_str) {
        None => Level::Privileged,
        Some(v) => parse(v).unwrap_or(Level::Restricted),
    }
}

/// Namespace label validation: the three level labels must name a level.
pub fn validate_namespace(ns: &Value) -> Result<(), String> {
    for key in [ENFORCE, WARN, AUDIT] {
        if let Some(v) = ns.pointer(&["metadata", "labels", key]).and_then(Value::as_str) {
            if parse(v).is_none() {
                return Err(format!("metadata.labels[{key}]: Invalid value: {v:?}: must be one of privileged, baseline, restricted"));
            }
        }
    }
    Ok(())
}

fn s<'a>(v: &'a Value, p: &[&str]) -> &'a str {
    v.pointer(p).and_then(Value::as_str).unwrap_or("")
}

fn truthy(v: &Value, p: &[&str]) -> bool {
    v.pointer(p).and_then(Value::as_bool) == Some(true)
}

/// Every container of the pod spec (regular, init and ephemeral).
fn containers(spec: &Value) -> Vec<&Value> {
    ["initContainers", "containers", "ephemeralContainers"].iter().flat_map(|k| spec.get(k).and_then(Value::as_array).unwrap_or(&[]).iter()).collect()
}

fn quoted(names: &[String]) -> String {
    names.iter().map(|n| format!("{n:?}")).collect::<Vec<_>>().join(", ")
}

/// `container "a"` / `containers "a", "b"`.
fn subject(kind: &str, names: &[String]) -> String {
    if names.len() == 1 { format!("{kind} {}", quoted(names)) } else { format!("{kind}s {}", quoted(names)) }
}

const BASELINE_CAPS: [&str; 13] = ["AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD", "NET_BIND_SERVICE", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT"];
const SAFE_SYSCTLS: [&str; 12] = [
    "kernel.shm_rmid_forced",
    "net.ipv4.ip_local_port_range",
    "net.ipv4.ip_unprivileged_port_start",
    "net.ipv4.tcp_syncookies",
    "net.ipv4.ping_group_range",
    "net.ipv4.ip_local_reserved_ports",
    "net.ipv4.tcp_keepalive_time",
    "net.ipv4.tcp_fin_timeout",
    "net.ipv4.tcp_keepalive_intvl",
    "net.ipv4.tcp_keepalive_probes",
    "net.ipv4.tcp_rmem",
    "net.ipv4.tcp_wmem",
];
const SELINUX_TYPES: [&str; 4] = ["container_t", "container_init_t", "container_kvm_t", "container_engine_t"];
const RESTRICTED_VOLUMES: [&str; 8] = ["configMap", "csi", "downwardAPI", "emptyDir", "ephemeral", "persistentVolumeClaim", "projected", "secret"];

fn caps(c: &Value, which: &str) -> Vec<String> {
    c.pointer(&["securityContext", "capabilities", which]).and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(Value::as_str).map(String::from).collect()
}

/// The checks of `level` that `spec` (a PodSpec, with `meta` the pod's metadata) fails, in
/// upstream's order and wording.
pub fn violations(level: Level, spec: &Value, meta: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if level == Level::Privileged {
        return out;
    }
    let ctrs = containers(spec);
    let name = |c: &Value| s(c, &["name"]).to_string();

    // ---- baseline ----
    let hostns: Vec<&str> = [("hostNetwork", "hostNetwork=true"), ("hostPID", "hostPID=true"), ("hostIPC", "hostIPC=true")].iter().filter(|(k, _)| truthy(spec, &[k])).map(|(_, m)| *m).collect();
    if !hostns.is_empty() {
        out.push(format!("host namespaces ({})", hostns.join(", ")));
    }
    let privileged: Vec<String> = ctrs.iter().filter(|c| truthy(c, &["securityContext", "privileged"])).map(|c| name(c)).collect();
    if !privileged.is_empty() {
        out.push(format!("privileged ({} must not set securityContext.privileged=true)", subject("container", &privileged)));
    }
    if level == Level::Baseline {
        let mut bad: Vec<String> = Vec::new();
        for c in &ctrs {
            for cap in caps(c, "add") {
                if !BASELINE_CAPS.contains(&cap.as_str()) {
                    bad.push(format!("container {:?} must not include {cap:?} in securityContext.capabilities.add", name(c)));
                }
            }
        }
        if !bad.is_empty() {
            out.push(format!("non-default capabilities ({})", bad.join("; ")));
        }
    }
    let vols = spec.get("volumes").and_then(Value::as_array).unwrap_or(&[]);
    let hostpath: Vec<String> = vols.iter().filter(|v| v.get("hostPath").is_some()).map(|v| s(v, &["name"]).to_string()).collect();
    if !hostpath.is_empty() {
        out.push(format!("hostPath volumes ({})", subject("volume", &hostpath)));
    }
    let mut ports: Vec<String> = Vec::new();
    for c in &ctrs {
        let used: Vec<String> = c.get("ports").and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(|p| p.get("hostPort").and_then(Value::as_u64)).filter(|p| *p != 0).map(|p| p.to_string()).collect();
        if !used.is_empty() {
            ports.push(format!("container {:?} uses hostPort{} {}", name(c), if used.len() > 1 { "s" } else { "" }, used.join(", ")));
        }
    }
    if !ports.is_empty() {
        out.push(format!("hostPort ({})", ports.join(", ")));
    }
    let mut apparmor: Vec<String> = Vec::new();
    let aa_ok = |t: &str| matches!(t, "" | "RuntimeDefault" | "Localhost");
    if !aa_ok(s(spec, &["securityContext", "appArmorProfile", "type"])) {
        apparmor.push(format!("pod must not set securityContext.appArmorProfile.type to {:?}", s(spec, &["securityContext", "appArmorProfile", "type"])));
    }
    for c in &ctrs {
        let t = s(c, &["securityContext", "appArmorProfile", "type"]);
        if !aa_ok(t) {
            apparmor.push(format!("container {:?} must not set securityContext.appArmorProfile.type to {t:?}", name(c)));
        }
    }
    for (k, v) in meta.get("annotations").and_then(Value::as_object).unwrap_or(&[]) {
        let v = v.as_str().unwrap_or("");
        if k.starts_with("container.apparmor.security.beta.kubernetes.io/") && !(v == "runtime/default" || v.starts_with("localhost/")) {
            apparmor.push(format!("{k}={v:?}"));
        }
    }
    if !apparmor.is_empty() {
        out.push(format!("forbidden AppArmor profile{} ({})", if apparmor.len() > 1 { "s" } else { "" }, apparmor.join(", ")));
    }
    let mut selinux: Vec<String> = Vec::new();
    let check_se = |who: String, sc: Option<&Value>, out: &mut Vec<String>| {
        let Some(o) = sc.and_then(|x| x.get("seLinuxOptions")) else { return };
        let t = s(o, &["type"]);
        if !t.is_empty() && !SELINUX_TYPES.contains(&t) {
            out.push(format!("{who} set forbidden securityContext.seLinuxOptions: type {t:?}"));
        }
        for f in ["user", "role"] {
            if !s(o, &[f]).is_empty() {
                out.push(format!("{who} set forbidden securityContext.seLinuxOptions: {f} {:?}", s(o, &[f])));
            }
        }
    };
    check_se(String::from("pod"), spec.get("securityContext"), &mut selinux);
    for c in &ctrs {
        check_se(format!("container {:?}", name(c)), c.get("securityContext"), &mut selinux);
    }
    if !selinux.is_empty() {
        out.push(format!("seLinuxOptions ({})", selinux.join("; ")));
    }
    let procmount: Vec<String> = ctrs.iter().filter(|c| !matches!(s(c, &["securityContext", "procMount"]), "" | "Default")).map(|c| name(c)).collect();
    if !procmount.is_empty() {
        out.push(format!("procMount ({} must not set securityContext.procMount to \"Unmasked\")", subject("container", &procmount)));
    }
    let mut unconfined: Vec<String> = Vec::new();
    if s(spec, &["securityContext", "seccompProfile", "type"]) == "Unconfined" {
        unconfined.push(String::from("pod"));
    }
    for c in &ctrs {
        if s(c, &["securityContext", "seccompProfile", "type"]) == "Unconfined" {
            unconfined.push(format!("container {:?}", name(c)));
        }
    }
    if !unconfined.is_empty() {
        out.push(format!("seccompProfile ({} must not set securityContext.seccompProfile.type to \"Unconfined\")", unconfined.join(" and ")));
    }
    let sysctls: Vec<String> = spec.pointer(&["securityContext", "sysctls"]).and_then(Value::as_array).unwrap_or(&[]).iter().map(|x| s(x, &["name"]).to_string()).filter(|n| !SAFE_SYSCTLS.contains(&n.as_str())).collect();
    if !sysctls.is_empty() {
        out.push(format!("forbidden sysctls ({})", sysctls.join(", ")));
    }
    let hostprocess = truthy(spec, &["securityContext", "windowsOptions", "hostProcess"]) || ctrs.iter().any(|c| truthy(c, &["securityContext", "windowsOptions", "hostProcess"]));
    if hostprocess {
        out.push(String::from("hostProcess (pod or containers must not set securityContext.windowsOptions.hostProcess=true)"));
    }
    if level == Level::Baseline {
        return out;
    }

    // ---- restricted ----
    let mut restricted_vols: Vec<String> = Vec::new();
    for v in vols {
        if let Some((ty, _)) = v.as_object().and_then(|o| o.iter().find(|(k, _)| k != "name")) {
            if !RESTRICTED_VOLUMES.contains(&ty.as_str()) {
                restricted_vols.push(format!("volume {:?} uses restricted volume type {ty:?}", s(v, &["name"])));
            }
        }
    }
    if !restricted_vols.is_empty() {
        out.push(format!("restricted volume types ({})", restricted_vols.join(", ")));
    }
    let ape: Vec<String> = ctrs.iter().filter(|c| c.pointer(&["securityContext", "allowPrivilegeEscalation"]).and_then(Value::as_bool) != Some(false)).map(|c| name(c)).collect();
    if !ape.is_empty() {
        out.push(format!("allowPrivilegeEscalation != false ({} must set securityContext.allowPrivilegeEscalation=false)", subject("container", &ape)));
    }
    let mut caps_bad: Vec<String> = Vec::new();
    for c in &ctrs {
        if !caps(c, "drop").iter().any(|d| d == "ALL") {
            caps_bad.push(format!("container {:?} must set securityContext.capabilities.drop=[\"ALL\"]", name(c)));
        }
        for cap in caps(c, "add") {
            if cap != "NET_BIND_SERVICE" {
                caps_bad.push(format!("container {:?} must not include {cap:?} in securityContext.capabilities.add", name(c)));
            }
        }
    }
    if !caps_bad.is_empty() {
        out.push(format!("unrestricted capabilities ({})", caps_bad.join("; ")));
    }
    let pod_nonroot = spec.pointer(&["securityContext", "runAsNonRoot"]).and_then(Value::as_bool);
    let nonroot_bad: Vec<String> = ctrs.iter().filter(|c| match c.pointer(&["securityContext", "runAsNonRoot"]).and_then(Value::as_bool) { Some(v) => !v, None => pod_nonroot != Some(true) }).map(|c| name(c)).collect();
    if pod_nonroot == Some(false) || !nonroot_bad.is_empty() {
        let who = if pod_nonroot == Some(false) { String::from("pod") } else { format!("pod or {}", subject("container", &nonroot_bad)) };
        out.push(format!("runAsNonRoot != true ({who} must set securityContext.runAsNonRoot=true)"));
    }
    let pod_root = spec.pointer(&["securityContext", "runAsUser"]).and_then(Value::as_i64) == Some(0);
    let root_ctrs: Vec<String> = ctrs.iter().filter(|c| c.pointer(&["securityContext", "runAsUser"]).and_then(Value::as_i64) == Some(0)).map(|c| name(c)).collect();
    if pod_root || !root_ctrs.is_empty() {
        let who = if pod_root && root_ctrs.is_empty() { String::from("pod") } else if pod_root { format!("pod and {}", subject("container", &root_ctrs)) } else { subject("container", &root_ctrs) };
        out.push(format!("runAsUser=0 ({who} must not set runAsUser=0)"));
    }
    let sc_ok = |t: &str| matches!(t, "RuntimeDefault" | "Localhost");
    let pod_sc = sc_ok(s(spec, &["securityContext", "seccompProfile", "type"]));
    let sc_missing: Vec<String> = ctrs.iter().filter(|c| {
        let t = s(c, &["securityContext", "seccompProfile", "type"]);
        if t.is_empty() { !pod_sc } else { !sc_ok(t) && t != "Unconfined" }
    }).map(|c| name(c)).collect();
    if !sc_missing.is_empty() {
        out.push(format!("seccompProfile (pod or {} must set securityContext.seccompProfile.type to \"RuntimeDefault\" or \"Localhost\")", subject("container", &sc_missing)));
    }
    out
}

/// Outcome of checking a pod (or pod template) against its namespace's labels.
pub struct Decision {
    /// Rejection message (`enforce` failed), for pods only.
    pub deny: Option<String>,
    pub warnings: Vec<String>,
}

fn label(level: Level) -> String {
    format!("{}:latest", level.name())
}

/// Checks a pod (`template == false`) or a workload's pod template against `ns` (the Namespace
/// object; None for cluster-scoped or unknown namespaces, which are privileged).
pub fn check(ns: Option<&Value>, spec: &Value, meta: &Value, template: bool) -> Decision {
    let (enforce, warn) = (level_of(ns, ENFORCE), level_of(ns, WARN));
    let mut d = Decision { deny: None, warnings: Vec::new() };
    let ev = violations(enforce, spec, meta);
    if !ev.is_empty() {
        if template {
            d.warnings.push(format!("would violate PodSecurity {:?}: {}", label(enforce), ev.join(", ")));
        } else {
            d.deny = Some(format!("violates PodSecurity {:?}: {}", label(enforce), ev.join(", ")));
        }
    }
    // A warn level at or below a failing enforce level adds nothing new.
    if warn > enforce || ev.is_empty() {
        let wv = violations(warn, spec, meta);
        if !wv.is_empty() && !(template && warn == enforce) {
            d.warnings.push(format!("would violate PodSecurity {:?}: {}", label(warn), wv.join(", ")));
        }
    }
    d
}

/// The pod template path of a workload kind (`spec.template`, CronJob's
/// `spec.jobTemplate.spec.template`), for template warnings.
pub fn template_path(group: &str, plural: &str) -> Option<&'static [&'static str]> {
    match (group, plural) {
        ("apps", "deployments" | "replicasets" | "statefulsets" | "daemonsets") | ("batch", "jobs") | ("", "replicationcontrollers") => Some(&["spec", "template"]),
        ("batch", "cronjobs") => Some(&["spec", "jobTemplate", "spec", "template"]),
        ("", "podtemplates") => Some(&["template"]),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_fmt::json;

    fn v(s: &str) -> Value {
        json::parse(s.as_bytes()).unwrap()
    }

    fn ns(labels: &str) -> Value {
        v(&format!(r#"{{"metadata":{{"name":"n","labels":{labels}}}}}"#))
    }

    #[test]
    fn baseline_rejects_host_access() {
        let spec = v(r#"{"hostNetwork":true,"hostPID":true,"volumes":[{"name":"h","hostPath":{"path":"/"}}],"containers":[{"name":"c","securityContext":{"privileged":true,"capabilities":{"add":["NET_ADMIN","CHOWN"]}},"ports":[{"containerPort":80,"hostPort":80}]}]}"#);
        let e = violations(Level::Baseline, &spec, &Value::Null);
        assert_eq!(
            e,
            [
                "host namespaces (hostNetwork=true, hostPID=true)",
                "privileged (container \"c\" must not set securityContext.privileged=true)",
                "non-default capabilities (container \"c\" must not include \"NET_ADMIN\" in securityContext.capabilities.add)",
                "hostPath volumes (volume \"h\")",
                "hostPort (container \"c\" uses hostPort 80)",
            ]
        );
        let d = check(Some(&ns(r#"{"pod-security.kubernetes.io/enforce":"baseline"}"#)), &spec, &Value::Null, false);
        assert!(d.deny.unwrap().starts_with("violates PodSecurity \"baseline:latest\": host namespaces (hostNetwork=true, hostPID=true)"));
    }

    #[test]
    fn restricted_requires_hardening() {
        let plain = v(r#"{"containers":[{"name":"c","image":"i"}]}"#);
        let e = violations(Level::Restricted, &plain, &Value::Null);
        assert_eq!(
            e,
            [
                "allowPrivilegeEscalation != false (container \"c\" must set securityContext.allowPrivilegeEscalation=false)",
                "unrestricted capabilities (container \"c\" must set securityContext.capabilities.drop=[\"ALL\"])",
                "runAsNonRoot != true (pod or container \"c\" must set securityContext.runAsNonRoot=true)",
                "seccompProfile (pod or container \"c\" must set securityContext.seccompProfile.type to \"RuntimeDefault\" or \"Localhost\")",
            ]
        );
        let hardened = v(r#"{"securityContext":{"runAsNonRoot":true,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"c","securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}],"volumes":[{"name":"t","projected":{}}]}"#);
        assert!(violations(Level::Restricted, &hardened, &Value::Null).is_empty());
        assert!(violations(Level::Baseline, &plain, &Value::Null).is_empty());
    }

    #[test]
    fn levels_from_labels() {
        let spec = v(r#"{"hostNetwork":true,"containers":[{"name":"c"}]}"#);
        // Unlabelled: privileged, nothing to say.
        let d = check(Some(&ns("{}")), &spec, &Value::Null, false);
        assert!(d.deny.is_none() && d.warnings.is_empty());
        // Invalid level: restricted (fail closed), and the namespace itself is rejected.
        let bad = ns(r#"{"pod-security.kubernetes.io/enforce":"bogus"}"#);
        assert!(check(Some(&bad), &spec, &Value::Null, false).deny.unwrap().contains("restricted:latest"));
        assert!(validate_namespace(&bad).is_err());
        // Warn only: admitted with a warning; templates never denied.
        let w = ns(r#"{"pod-security.kubernetes.io/warn":"baseline"}"#);
        let d = check(Some(&w), &spec, &Value::Null, false);
        assert!(d.deny.is_none());
        assert_eq!(d.warnings, ["would violate PodSecurity \"baseline:latest\": host namespaces (hostNetwork=true)"]);
        let e = ns(r#"{"pod-security.kubernetes.io/enforce":"baseline"}"#);
        let d = check(Some(&e), &spec, &Value::Null, true);
        assert!(d.deny.is_none() && d.warnings.len() == 1);
    }
}
