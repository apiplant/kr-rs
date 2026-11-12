//! Pod Security admission (the upstream PodSecurity plugin): namespace labels
//! `pod-security.kubernetes.io/{enforce,warn,audit}` = `privileged` | `baseline` | `restricted`
//! select the Pod Security Standard a namespace's pods must meet. Unlabelled namespaces are
//! `privileged` (upstream's default configuration); an unparseable level is evaluated as
//! `restricted` (fail closed), and namespaces with one are rejected.
//!
//! Pods are checked on create and on updates that change their spec; `enforce` rejects them,
//! `warn` adds a warning. Workload resources with a pod template only get warnings (and only for
//! `enforce`/`warn` levels), as upstream. `audit` violations become annotations of the audit
//! event (`audit.rs`). The `<mode>-version` labels (`latest` or `v1.NN`) pin the checks whose
//! rules changed over time (seccomp 1.19, restricted capabilities 1.22, hostProcess 1.23); a
//! `PodSecurityConfiguration` ([`Config`]) gives per-mode defaults and exemptions (ADR-046).
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
const MODES: [&str; 3] = [ENFORCE, WARN, AUDIT];
/// The newest minor version `latest` stands for (the server's own).
const LATEST_MINOR: u32 = 37;

/// A pinned policy version: `None` is `latest`.
pub type Version = Option<u32>;

/// `latest` or `v1.NN`.
pub fn parse_version(v: &str) -> Option<Version> {
    if v == "latest" {
        return Some(None);
    }
    let n = v.strip_prefix("v1.")?;
    if n.is_empty() || n.len() > 3 || !n.bytes().all(|b| b.is_ascii_digit()) || (n.len() > 1 && n.starts_with('0')) {
        return None;
    }
    // Versions newer than the server are `latest`.
    n.parse::<u32>().ok().map(|m| if m >= LATEST_MINOR { None } else { Some(m) })
}

/// The `PodSecurityConfiguration`: default level/version per mode (enforce, warn, audit) and
/// exemptions.
#[derive(Clone, Debug)]
pub struct Config {
    pub defaults: [(Level, Version); 3],
    pub users: Vec<String>,
    pub runtime_classes: Vec<String>,
    pub namespaces: Vec<String>,
}

impl Default for Config {
    fn default() -> Config {
        Config { defaults: [(Level::Privileged, None); 3], users: Vec::new(), runtime_classes: Vec::new(), namespaces: Vec::new() }
    }
}

impl Config {
    /// Parses `PodSecurityConfiguration` YAML, bare or as the `PodSecurity` plugin entry of an
    /// `AdmissionConfiguration`.
    pub fn parse(src: &str) -> Result<Config, String> {
        let doc = kr_fmt::yaml::parse(src).map_err(|e| format!("pod security configuration: {e}"))?;
        let mut doc = &doc;
        if doc.get("kind").and_then(Value::as_str) == Some("AdmissionConfiguration") {
            doc = doc.get("plugins").and_then(Value::as_array).unwrap_or(&[]).iter().find(|p| p.get("name").and_then(Value::as_str) == Some("PodSecurity")).and_then(|p| p.get("configuration")).ok_or("pod security configuration: no PodSecurity plugin in the AdmissionConfiguration")?;
        }
        if doc.get("kind").and_then(Value::as_str) != Some("PodSecurityConfiguration") {
            return Err(String::from("pod security configuration: kind must be PodSecurityConfiguration"));
        }
        let mut c = Config::default();
        for (i, mode) in ["enforce", "warn", "audit"].iter().enumerate() {
            if let Some(l) = doc.pointer(&["defaults", mode]).and_then(Value::as_str) {
                c.defaults[i].0 = parse(l).ok_or_else(|| format!("pod security configuration: defaults.{mode}: Invalid value: {l:?}: must be one of privileged, baseline, restricted"))?;
            }
            if let Some(v) = doc.pointer(&["defaults", &format!("{mode}-version")]).and_then(Value::as_str) {
                c.defaults[i].1 = parse_version(v).ok_or_else(|| format!("pod security configuration: defaults.{mode}-version: Invalid value: {v:?}: must be latest or v1.NN"))?;
            }
        }
        let list = |k: &str| doc.pointer(&["exemptions", k]).and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(Value::as_str).map(String::from).collect::<Vec<_>>();
        c.users = list("usernames");
        c.runtime_classes = list("runtimeClasses");
        c.namespaces = list("namespaces");
        Ok(c)
    }
}

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

/// The level and version a namespace selects for `mode` (index into [`MODES`]): the label, else
/// the configured default. An invalid level is restricted (fail closed), an invalid version latest.
fn level_of(cfg: &Config, ns: Option<&Value>, mode: usize) -> (Level, Version) {
    let label = |k: &str| ns.and_then(|n| n.pointer(&["metadata", "labels", k])).and_then(Value::as_str);
    let level = label(MODES[mode]).map(|v| parse(v).unwrap_or(Level::Restricted)).unwrap_or(cfg.defaults[mode].0);
    let version = label(&format!("{}-version", MODES[mode])).map(|v| parse_version(v).unwrap_or(None)).unwrap_or(cfg.defaults[mode].1);
    (level, version)
}

/// Namespace label validation: the three level labels must name a level.
pub fn validate_namespace(ns: &Value) -> Result<(), String> {
    for key in [ENFORCE, WARN, AUDIT] {
        if let Some(v) = ns.pointer(&["metadata", "labels", key]).and_then(Value::as_str) {
            if parse(v).is_none() {
                return Err(format!("metadata.labels[{key}]: Invalid value: {v:?}: must be one of privileged, baseline, restricted"));
            }
        }
        let vkey = format!("{key}-version");
        if let Some(v) = ns.pointer(&["metadata", "labels", &vkey]).and_then(Value::as_str) {
            if parse_version(v).is_none() {
                return Err(format!("metadata.labels[{vkey}]: Invalid value: {v:?}: must be \"latest\" or \"v1.NN\""));
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
pub const SAFE_SYSCTLS: [&str; 12] = [
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
    violations_at(level, None, spec, meta)
}

/// [`violations`] under the rules of Kubernetes minor version `ver` (`None`: latest).
pub fn violations_at(level: Level, ver: Version, spec: &Value, meta: &Value) -> Vec<String> {
    let since = |m: u32| ver.is_none_or(|v| v >= m);
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
    if since(19) && s(spec, &["securityContext", "seccompProfile", "type"]) == "Unconfined" {
        unconfined.push(String::from("pod"));
    }
    for c in &ctrs {
        if since(19) && s(c, &["securityContext", "seccompProfile", "type"]) == "Unconfined" {
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
    if hostprocess && since(23) {
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
    if since(22) && !caps_bad.is_empty() {
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
    if since(19) && !sc_missing.is_empty() {
        out.push(format!("seccompProfile (pod or {} must set securityContext.seccompProfile.type to \"RuntimeDefault\" or \"Localhost\")", subject("container", &sc_missing)));
    }
    out
}

/// Outcome of checking a pod (or pod template) against its namespace's labels.
pub struct Decision {
    /// Rejection message (`enforce` failed), for pods only.
    pub deny: Option<String>,
    pub warnings: Vec<String>,
    /// Annotations for the audit event (`audit` violations, the enforced policy, exemptions).
    pub audit: Vec<(String, String)>,
}

fn label(level: Level, ver: Version) -> String {
    match ver {
        None => format!("{}:latest", level.name()),
        Some(m) => format!("{}:v1.{m}", level.name()),
    }
}

/// Checks a pod (`template == false`) or a workload's pod template against `ns` (the Namespace
/// object; None for cluster-scoped or unknown namespaces, which get the configured defaults),
/// created by `user` in namespace `ns_name`.
pub fn check(cfg: &Config, user: &str, ns_name: &str, ns: Option<&Value>, spec: &Value, meta: &Value, template: bool) -> Decision {
    let mut d = Decision { deny: None, warnings: Vec::new(), audit: Vec::new() };
    let rc = s(spec, &["runtimeClassName"]);
    let exempt = if cfg.users.iter().any(|u| u == user) {
        Some("user")
    } else if cfg.namespaces.iter().any(|n| n == ns_name) {
        Some("namespace")
    } else if !rc.is_empty() && cfg.runtime_classes.iter().any(|r| r == rc) {
        Some("runtimeClass")
    } else {
        None
    };
    if let Some(e) = exempt {
        d.audit.push((String::from("pod-security.kubernetes.io/exempt"), e.to_string()));
        return d;
    }
    let ((enforce, ev_), (warn, wv_), (audit, av_)) = (level_of(cfg, ns, 0), level_of(cfg, ns, 1), level_of(cfg, ns, 2));
    let ev = violations_at(enforce, ev_, spec, meta);
    if enforce > Level::Privileged {
        d.audit.push((String::from("pod-security.kubernetes.io/enforce-policy"), label(enforce, ev_)));
    }
    if !ev.is_empty() {
        if template {
            d.warnings.push(format!("would violate PodSecurity {:?}: {}", label(enforce, ev_), ev.join(", ")));
        } else {
            d.deny = Some(format!("violates PodSecurity {:?}: {}", label(enforce, ev_), ev.join(", ")));
        }
    }
    // A warn level at or below a failing enforce level adds nothing new.
    if warn > enforce || ev.is_empty() {
        let wv = violations_at(warn, wv_, spec, meta);
        if !wv.is_empty() && !(template && warn == enforce) {
            d.warnings.push(format!("would violate PodSecurity {:?}: {}", label(warn, wv_), wv.join(", ")));
        }
    }
    if audit > Level::Privileged {
        let av = violations_at(audit, av_, spec, meta);
        if !av.is_empty() {
            d.audit.push((String::from("pod-security.kubernetes.io/audit-violations"), format!("would violate PodSecurity {:?}: {}", label(audit, av_), av.join(", "))));
            d.audit.push((String::from("pod-security.kubernetes.io/audit"), label(audit, av_)));
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

    fn chk(ns: Option<&Value>, spec: &Value, template: bool) -> Decision {
        check(&Config::default(), "u", "n", ns, spec, &Value::Null, template)
    }

    #[test]
    fn versions_and_pinning() {
        assert_eq!(parse_version("latest"), Some(None));
        assert_eq!(parse_version("v1.25"), Some(Some(25)));
        assert_eq!(parse_version("v1.99"), Some(None));
        assert_eq!(parse_version("1.25"), None);
        assert_eq!(parse_version("v1.x"), None);
        assert!(validate_namespace(&ns(r#"{"pod-security.kubernetes.io/warn-version":"bogus"}"#)).is_err());
        let plain = v(r#"{"containers":[{"name":"c","securityContext":{"allowPrivilegeEscalation":false,"runAsNonRoot":true}}]}"#);
        // Without drop=ALL (1.22) and seccomp (1.19) the pod passed restricted at older versions.
        assert!(!violations_at(Level::Restricted, None, &plain, &Value::Null).is_empty());
        assert!(violations_at(Level::Restricted, Some(18), &plain, &Value::Null).is_empty());
        assert_eq!(violations_at(Level::Restricted, Some(20), &plain, &Value::Null).len(), 1);
        let n = ns(r#"{"pod-security.kubernetes.io/enforce":"restricted","pod-security.kubernetes.io/enforce-version":"v1.18"}"#);
        assert!(chk(Some(&n), &plain, false).deny.is_none());
        let n = ns(r#"{"pod-security.kubernetes.io/enforce":"restricted","pod-security.kubernetes.io/enforce-version":"v1.20"}"#);
        assert!(chk(Some(&n), &plain, false).deny.unwrap().contains("\"restricted:v1.20\""));
    }

    #[test]
    fn config_defaults_and_exemptions() {
        let src = "apiVersion: apiserver.config.k8s.io/v1\nkind: AdmissionConfiguration\nplugins:\n- name: PodSecurity\n  configuration:\n    apiVersion: pod-security.admission.config.k8s.io/v1\n    kind: PodSecurityConfiguration\n    defaults:\n      enforce: baseline\n      enforce-version: latest\n      audit: restricted\n    exemptions:\n      usernames: [admin]\n      runtimeClasses: [gvisor]\n      namespaces: [kube-system]\n";
        let cfg = Config::parse(src).unwrap();
        assert_eq!(cfg.defaults[0].0, Level::Baseline);
        let spec = v(r#"{"hostNetwork":true,"containers":[{"name":"c"}]}"#);
        // Unlabelled namespace: the default applies.
        let d = check(&cfg, "u", "n", None, &spec, &Value::Null, false);
        assert!(d.deny.is_some());
        assert!(d.audit.iter().any(|(k, v)| k == "pod-security.kubernetes.io/audit" && v == "restricted:latest"));
        assert!(d.audit.iter().any(|(k, v)| k.ends_with("audit-violations") && v.contains("would violate PodSecurity \"restricted:latest\"")));
        // A label overrides the default.
        let n = ns(r#"{"pod-security.kubernetes.io/enforce":"privileged"}"#);
        assert!(check(&cfg, "u", "n", Some(&n), &spec, &Value::Null, false).deny.is_none());
        // Exemptions.
        for (user, nsn, rc, kind) in [("admin", "n", "", "user"), ("u", "kube-system", "", "namespace"), ("u", "n", "gvisor", "runtimeClass")] {
            let mut sp = spec.clone();
            if !rc.is_empty() {
                sp.set("runtimeClassName", Value::String(rc.into()));
            }
            let d = check(&cfg, user, nsn, None, &sp, &Value::Null, false);
            assert!(d.deny.is_none() && d.warnings.is_empty(), "{kind}");
            assert_eq!(d.audit, [(String::from("pod-security.kubernetes.io/exempt"), kind.to_string())]);
        }
        assert!(Config::parse("kind: Other").is_err());
        assert!(Config::parse("kind: PodSecurityConfiguration\ndefaults:\n  enforce: loud\n").is_err());
        assert!(Config::parse("kind: PodSecurityConfiguration\ndefaults:\n  warn-version: v2\n").is_err());
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
        let d = chk(Some(&ns(r#"{"pod-security.kubernetes.io/enforce":"baseline"}"#)), &spec, false);
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
        let d = chk(Some(&ns("{}")), &spec, false);
        assert!(d.deny.is_none() && d.warnings.is_empty());
        // Invalid level: restricted (fail closed), and the namespace itself is rejected.
        let bad = ns(r#"{"pod-security.kubernetes.io/enforce":"bogus"}"#);
        assert!(chk(Some(&bad), &spec, false).deny.unwrap().contains("restricted:latest"));
        assert!(validate_namespace(&bad).is_err());
        // Warn only: admitted with a warning; templates never denied.
        let w = ns(r#"{"pod-security.kubernetes.io/warn":"baseline"}"#);
        let d = chk(Some(&w), &spec, false);
        assert!(d.deny.is_none());
        assert_eq!(d.warnings, ["would violate PodSecurity \"baseline:latest\": host namespaces (hostNetwork=true)"]);
        let e = ns(r#"{"pod-security.kubernetes.io/enforce":"baseline"}"#);
        let d = chk(Some(&e), &spec, true);
        assert!(d.deny.is_none() && d.warnings.len() == 1);
    }
}
