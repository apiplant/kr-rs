//! Optional admission plugins, off unless named in `--enable-admission-plugins` (#362):
//! `AlwaysPullImages`, `PodNodeSelector` and `EventRateLimit`, configured through an
//! `AdmissionConfiguration` (`--admission-control-config-file`) like kube-apiserver.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use kr_fmt::json::Value;

/// Namespace annotation of PodNodeSelector.
pub const NODE_SELECTOR_ANNOTATION: &str = "scheduler.alpha.kubernetes.io/node-selector";

/// Plugins kr always runs (or that have no effect in kr); naming them is accepted.
const BUILTIN: &[&str] = &[
    "NamespaceLifecycle", "LimitRanger", "ServiceAccount", "NodeRestriction", "PodSecurity", "ResourceQuota", "DefaultStorageClass", "Priority", "RuntimeClass",
    "MutatingAdmissionWebhook", "ValidatingAdmissionWebhook", "ValidatingAdmissionPolicy", "MutatingAdmissionPolicy", "DefaultTolerationSeconds", "TaintNodesByCondition",
    "PersistentVolumeClaimResize", "StorageObjectInUseProtection", "CertificateApproval", "CertificateSigning", "CertificateSubjectRestriction", "DefaultIngressClass",
    "ClusterTrustBundleAttest", "NamespaceExists", "NamespaceAutoProvision", "OwnerReferencesPermissionEnforcement", "PodTopologyLabels",
];

#[derive(Default)]
pub struct Plugins {
    pub always_pull: bool,
    pub node_selector: Option<NodeSelector>,
    pub event_rate: Option<EventRateLimit>,
}

#[derive(Default)]
pub struct NodeSelector {
    /// Used for namespaces without the annotation.
    pub cluster_default: String,
    /// Namespace -> allowed labels (the merged selector must be within them).
    pub whitelist: Vec<(String, String)>,
}

/// `k=v,k2=v2` as pairs.
pub fn parse_labels(s: &str) -> Result<Vec<(String, String)>, String> {
    let mut out: Vec<(String, String)> = Vec::new();
    for p in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (k, v) = p.split_once('=').ok_or_else(|| format!("invalid node selector {s:?}"))?;
        let (k, v) = (k.trim().to_string(), v.trim().to_string());
        if k.is_empty() {
            return Err(format!("invalid node selector {s:?}"));
        }
        if let Some(e) = out.iter_mut().find(|(ek, _)| *ek == k) {
            e.1 = v;
        } else {
            out.push((k, v));
        }
    }
    Ok(out)
}

/// Enabled plugins from the names and the `AdmissionConfiguration` text (if any). `read`
/// loads a plugin configuration file named by `path`.
pub fn configure(names: &str, admission_config: Option<&str>, read: &dyn Fn(&str) -> Result<String, String>) -> Result<Plugins, String> {
    let mut cfgs: Vec<(String, Value)> = Vec::new();
    if let Some(t) = admission_config {
        let v = kr_fmt::yaml::parse(t).map_err(|e| format!("admission config: {e:?}"))?;
        if v.get("kind").and_then(Value::as_str).is_some_and(|k| k != "AdmissionConfiguration") {
            return Err("admission config: kind must be AdmissionConfiguration".into());
        }
        for p in v.get("plugins").and_then(Value::as_array).unwrap_or(&[]) {
            let name = p.get("name").and_then(Value::as_str).unwrap_or("").to_string();
            let c = match (p.get("configuration"), p.get("path").and_then(Value::as_str)) {
                (Some(c), _) => c.clone(),
                (None, Some(path)) => kr_fmt::yaml::parse(&read(path)?).map_err(|e| format!("admission config {path}: {e:?}"))?,
                _ => continue,
            };
            cfgs.push((name, c));
        }
    }
    let cfg = |n: &str| cfgs.iter().find(|(k, _)| k == n).map(|(_, v)| v);
    let mut out = Plugins::default();
    for n in names.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        match n {
            "AlwaysPullImages" => out.always_pull = true,
            "PodNodeSelector" => {
                let mut ns = NodeSelector::default();
                if let Some(Value::Object(m)) = cfg(n).and_then(|c| c.get("podNodeSelectorPluginConfig")) {
                    for (k, v) in m {
                        let v = v.as_str().unwrap_or("").to_string();
                        parse_labels(&v).map_err(|e| format!("PodNodeSelector: {e}"))?;
                        if k == "clusterDefaultNodeSelector" {
                            ns.cluster_default = v;
                        } else {
                            ns.whitelist.push((k.clone(), v));
                        }
                    }
                }
                parse_labels(&ns.cluster_default)?;
                out.node_selector = Some(ns);
            }
            "EventRateLimit" => out.event_rate = Some(EventRateLimit::from_config(cfg(n).ok_or("EventRateLimit needs its configuration in the admission control config file")?)?),
            _ if BUILTIN.contains(&n) => {}
            _ => return Err(format!("enable-admission-plugins: unknown or unsupported plugin {n:?}")),
        }
    }
    Ok(out)
}

/// AlwaysPullImages: every container of the pod pulls its image.
pub fn always_pull(pod: &mut Value) {
    let Some(spec) = pod.get_mut("spec") else { return };
    for key in ["initContainers", "containers", "ephemeralContainers"] {
        if let Some(Value::Array(cs)) = spec.get_mut(key) {
            for c in cs.iter_mut() {
                c.set("imagePullPolicy", Value::from("Always"));
            }
        }
    }
}

impl NodeSelector {
    /// Merges the namespace's selector (`ns_annotation`, else the cluster default) into the
    /// pod's `nodeSelector`; errors are the 403 detail.
    pub fn admit(&self, pod: &mut Value, ns: &str, ns_annotation: Option<&str>) -> Result<(), String> {
        let ns_sel = parse_labels(ns_annotation.unwrap_or(&self.cluster_default))?;
        let spec = pod.entry_object("spec");
        let mut sel: Vec<(String, String)> = match spec.get("nodeSelector") {
            Some(Value::Object(m)) => m.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string())).collect(),
            _ => Vec::new(),
        };
        for (k, v) in &ns_sel {
            match sel.iter().find(|(pk, _)| pk == k) {
                Some((_, pv)) if pv != v => return Err("pod node label selector conflicts with its namespace node label selector".into()),
                Some(_) => {}
                None => sel.push((k.clone(), v.clone())),
            }
        }
        if let Some((_, wl)) = self.whitelist.iter().find(|(n, _)| n == ns) {
            let wl = parse_labels(wl)?;
            if !sel.iter().all(|(k, v)| wl.iter().any(|(wk, wv)| wk == k && wv == v)) {
                return Err("pod node label selector labels conflict with its namespace whitelist".into());
            }
        }
        if !sel.is_empty() {
            spec.set("nodeSelector", Value::Object(sel.into_iter().map(|(k, v)| (k, Value::String(v))).collect()));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LimitType {
    Server,
    Namespace,
    User,
    SourceAndObject,
}

impl LimitType {
    fn name(self) -> &'static str {
        match self {
            LimitType::Server => "Server",
            LimitType::Namespace => "Namespace",
            LimitType::User => "User",
            LimitType::SourceAndObject => "SourceAndObject",
        }
    }
}

struct Limit {
    ty: LimitType,
    qps: u64,
    burst: u64,
    cache_size: usize,
    /// key -> (milli-tokens, last refill ms, last use sequence)
    buckets: RefCell<BTreeMap<String, (u64, u64, u64)>>,
}

/// EventRateLimit: token buckets per server, namespace, user or event source and object.
pub struct EventRateLimit {
    limits: Vec<Limit>,
    seq: Cell<u64>,
}

impl EventRateLimit {
    /// From `eventratelimit.admission.k8s.io/v1alpha1` `Configuration`.
    pub fn from_config(c: &Value) -> Result<EventRateLimit, String> {
        let mut limits = Vec::new();
        for l in c.get("limits").and_then(Value::as_array).unwrap_or(&[]) {
            let ty = match l.get("type").and_then(Value::as_str) {
                Some("Server") => LimitType::Server,
                Some("Namespace") => LimitType::Namespace,
                Some("User") => LimitType::User,
                Some("SourceAndObject") => LimitType::SourceAndObject,
                t => return Err(format!("EventRateLimit: unsupported limit type {t:?}")),
            };
            let n = |k: &str| l.get(k).and_then(Value::as_i64).unwrap_or(0);
            let (qps, burst) = (n("qps"), n("burst"));
            if qps <= 0 || burst <= 0 {
                return Err(format!("EventRateLimit: {} limit needs positive qps and burst", ty.name()));
            }
            let cache = match n("cacheSize") {
                0 => 4096,
                c if c > 0 => c as usize,
                _ => return Err("EventRateLimit: cacheSize must be positive".into()),
            };
            if ty == LimitType::Server && l.get("cacheSize").is_some() {
                return Err("EventRateLimit: a Server limit takes no cacheSize".into());
            }
            limits.push(Limit { ty, qps: qps as u64, burst: burst as u64, cache_size: cache, buckets: RefCell::new(BTreeMap::new()) });
        }
        if limits.is_empty() {
            return Err("EventRateLimit: limits: Required value".into());
        }
        Ok(EventRateLimit { limits, seq: Cell::new(0) })
    }

    fn key(ty: LimitType, ns: &str, user: &str, ev: &Value) -> String {
        let s = |p: &[&str]| ev.pointer(p).and_then(Value::as_str).unwrap_or("").to_string();
        match ty {
            LimitType::Server => String::new(),
            LimitType::Namespace => ns.into(),
            LimitType::User => user.into(),
            LimitType::SourceAndObject => {
                // core/v1 Events name `source` and `involvedObject`, events.k8s.io the reporting
                // controller and `regarding`.
                let (src, obj) = if ev.get("involvedObject").is_some() { (["source", "component"], "involvedObject") } else { (["reportingController", ""], "regarding") };
                let host = if obj == "involvedObject" { s(&["source", "host"]) } else { s(&["reportingInstance"]) };
                let o = |k: &str| s(&[obj, k]);
                format!("{}\x00{host}\x00{}\x00{}\x00{}\x00{}\x00{}", s(&src[..if src[1].is_empty() { 1 } else { 2 }]), o("kind"), o("namespace"), o("name"), o("uid"), o("apiVersion"))
            }
        }
    }

    /// Takes one token from every applicable bucket, or none when one is empty; the error is
    /// the 429 detail.
    pub fn admit(&self, ns: &str, user: &str, ev: &Value, now_ms: u64) -> Result<(), String> {
        let keys: Vec<String> = self.limits.iter().map(|l| Self::key(l.ty, ns, user, ev)).collect();
        // Refill, then check every bucket before taking from any.
        for (l, k) in self.limits.iter().zip(&keys) {
            let mut b = l.buckets.borrow_mut();
            let seq = self.seq.get() + 1;
            self.seq.set(seq);
            if !b.contains_key(k) && b.len() >= l.cache_size {
                // Least recently used bucket goes (it is full again by the time it comes back).
                if let Some(old) = b.iter().min_by_key(|(_, (_, _, s))| *s).map(|(k, _)| k.clone()) {
                    b.remove(&old);
                }
            }
            let e = b.entry(k.clone()).or_insert((l.burst * 1000, now_ms, seq));
            let refill = now_ms.saturating_sub(e.1).saturating_mul(l.qps);
            e.0 = (e.0 + refill).min(l.burst * 1000);
            e.1 = now_ms;
            e.2 = seq;
            if e.0 < 1000 {
                return Err(format!("limit reached on type {} for key {}", l.ty.name(), if k.is_empty() { "" } else if l.ty == LimitType::SourceAndObject { "<source and object>" } else { k.as_str() }));
            }
        }
        for (l, k) in self.limits.iter().zip(&keys) {
            if let Some(e) = l.buckets.borrow_mut().get_mut(k) {
                e.0 -= 1000;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Value {
        kr_fmt::json::parse_str(s).unwrap()
    }

    fn no_read(_: &str) -> Result<String, String> {
        Err("no".into())
    }

    #[test]
    fn plugin_names() {
        assert!(configure("NodeRestriction,AlwaysPullImages", None, &no_read).unwrap().always_pull);
        assert!(configure("Bogus", None, &no_read).is_err());
        assert!(configure("EventRateLimit", None, &no_read).is_err(), "needs configuration");
    }

    #[test]
    fn always_pull_sets_every_container() {
        let mut p = v(r#"{"spec":{"containers":[{"name":"a","imagePullPolicy":"Never"}],"initContainers":[{"name":"i"}]}}"#);
        always_pull(&mut p);
        assert_eq!(p.pointer(&["spec", "containers"]).unwrap().as_array().unwrap()[0].get("imagePullPolicy").and_then(Value::as_str), Some("Always"));
        assert_eq!(p.pointer(&["spec", "initContainers"]).unwrap().as_array().unwrap()[0].get("imagePullPolicy").and_then(Value::as_str), Some("Always"));
    }

    #[test]
    fn node_selector_merges_conflicts_and_whitelist() {
        let cfg = "kind: AdmissionConfiguration\nplugins:\n- name: PodNodeSelector\n  configuration:\n    podNodeSelectorPluginConfig:\n      clusterDefaultNodeSelector: zone=a\n      prod: env=prod,zone=a\n";
        let p = configure("PodNodeSelector", Some(cfg), &no_read).unwrap();
        let ns = p.node_selector.unwrap();
        let mut pod = v(r#"{"spec":{"nodeSelector":{"disk":"ssd"}}}"#);
        ns.admit(&mut pod, "dev", None).unwrap();
        assert_eq!(pod.pointer(&["spec", "nodeSelector", "zone"]).and_then(Value::as_str), Some("a"), "cluster default");
        let mut pod = v(r#"{"spec":{"nodeSelector":{"env":"dev"}}}"#);
        assert!(ns.admit(&mut pod, "x", Some("env=prod")).unwrap_err().contains("conflicts"));
        let mut pod = v(r#"{"spec":{}}"#);
        ns.admit(&mut pod, "prod", Some("env=prod")).unwrap();
        let mut pod = v(r#"{"spec":{"nodeSelector":{"disk":"ssd"}}}"#);
        assert!(ns.admit(&mut pod, "prod", Some("env=prod")).unwrap_err().contains("whitelist"));
    }

    #[test]
    fn event_rate_limit_buckets() {
        let c = v(r#"{"limits":[{"type":"Namespace","qps":1,"burst":2,"cacheSize":2},{"type":"User","qps":10,"burst":100}]}"#);
        let l = EventRateLimit::from_config(&c).unwrap();
        let ev = v(r#"{"involvedObject":{"kind":"Pod","name":"p"}}"#);
        assert!(l.admit("a", "u", &ev, 0).is_ok());
        assert!(l.admit("a", "u", &ev, 0).is_ok());
        assert_eq!(l.admit("a", "u", &ev, 10).unwrap_err(), "limit reached on type Namespace for key a");
        assert!(l.admit("b", "u", &ev, 10).is_ok(), "per namespace");
        assert!(l.admit("a", "u", &ev, 1010).is_ok(), "refilled after a second");
        // Cache of 2 namespaces: a third evicts the least recently used, which comes back full.
        assert!(l.admit("c", "u", &ev, 1010).is_ok());
        assert!(l.admit("b", "u", &ev, 1010).is_ok());
        let s = EventRateLimit::from_config(&v(r#"{"limits":[{"type":"SourceAndObject","qps":1,"burst":1}]}"#)).unwrap();
        assert!(s.admit("a", "u", &ev, 0).is_ok());
        assert!(s.admit("a", "u", &ev, 0).is_err());
        assert!(s.admit("a", "u", &v(r#"{"involvedObject":{"kind":"Pod","name":"q"}}"#), 0).is_ok(), "another object");
        assert!(EventRateLimit::from_config(&v(r#"{"limits":[{"type":"Server","qps":0,"burst":1}]}"#)).is_err());
    }
}
