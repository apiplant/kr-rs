//! Pod admission that needs no store access of its own: sysctl name validation, the
//! RuntimeClass plugin (overhead and scheduling merge) and the LimitRanger plugin (container
//! defaults, then min/max/ratio checks). `api.rs` looks up the RuntimeClass and LimitRanges and
//! hands them in; errors are the detail text of a 403 (or, for sysctls, 422) response.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use kr_fmt::json::Value;
use kr_fmt::quantity::Quantity;

fn valid_sysctl_name(n: &str) -> bool {
    let edge = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
    !n.is_empty()
        && n.split('.').all(|seg| {
            let (first, last) = (seg.chars().next(), seg.chars().next_back());
            first.is_some_and(edge) && last.is_some_and(edge) && seg.chars().all(|c| edge(c) || c == '-' || c == '_')
        })
}

/// `spec.securityContext.sysctls[].name` syntax; every bad entry is reported.
pub fn validate_sysctls(spec: &Value) -> Result<(), String> {
    let list = spec.pointer(&["securityContext", "sysctls"]).and_then(Value::as_array).unwrap_or(&[]);
    let errs: Vec<String> = list
        .iter()
        .enumerate()
        .filter_map(|(i, s)| {
            let n = s.get("name").and_then(Value::as_str).unwrap_or("");
            (!valid_sysctl_name(n)).then(|| format!("spec.securityContext.sysctls[{i}].name: Invalid value: {n:?}: sysctl names must consist of lower case alphanumeric characters or '.' (may be '-', '_' in the middle of a segment)"))
        })
        .collect();
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join(", "))
    }
}

/// Bounds of `maxExpirationSeconds` on pod certificates (1 hour .. 91 days).
pub const PCR_MIN_EXPIRATION: i64 = 3600;
pub const PCR_MAX_EXPIRATION: i64 = 7_862_400;

/// `maxExpirationSeconds` of a pod certificate projection or request, if invalid.
pub fn check_max_expiration(path: &str, v: Option<&Value>) -> Result<(), String> {
    let Some(n) = v.and_then(Value::as_i64) else { return Ok(()) };
    if n < PCR_MIN_EXPIRATION {
        return Err(format!("{path}: Invalid value: {n}: if provided, maxExpirationSeconds must be >= {PCR_MIN_EXPIRATION}"));
    }
    if n > PCR_MAX_EXPIRATION {
        return Err(format!("{path}: Invalid value: {n}: if provided, maxExpirationSeconds must be <= {PCR_MAX_EXPIRATION}"));
    }
    Ok(())
}

/// `projected` volume `podCertificate` sources: signer, key type and `maxExpirationSeconds`.
pub fn validate_pod_certificates(spec: &Value) -> Result<(), String> {
    let mut errs = Vec::new();
    for (i, vol) in spec.get("volumes").and_then(Value::as_array).unwrap_or(&[]).iter().enumerate() {
        for (j, src) in vol.pointer(&["projected", "sources"]).and_then(Value::as_array).unwrap_or(&[]).iter().enumerate() {
            let Some(pc) = src.get("podCertificate") else { continue };
            let at = format!("spec.volumes[{i}].projected.sources[{j}].podCertificate");
            if pc.get("signerName").and_then(Value::as_str).is_none_or(str::is_empty) {
                errs.push(format!("{at}.signerName: Required value"));
            }
            if !matches!(pc.get("keyType").and_then(Value::as_str), Some("RSA3072" | "RSA4096" | "ECDSAP256" | "ECDSAP384" | "ECDSAP521" | "ED25519")) {
                errs.push(format!("{at}.keyType: Unsupported value: {:?}", pc.get("keyType").and_then(Value::as_str).unwrap_or("")));
            }
            if let Err(e) = check_max_expiration(&format!("{at}.maxExpirationSeconds"), pc.get("maxExpirationSeconds")) {
                errs.push(e);
            }
            if ["credentialBundlePath", "keyPath", "certificateChainPath"].iter().all(|k| pc.get(k).and_then(Value::as_str).is_none_or(str::is_empty)) {
                errs.push(format!("{at}: Required value: must set at least one of credentialBundlePath, keyPath or certificateChainPath"));
            }
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join(", "))
    }
}

/// RuntimeClass admission: `rc` is the named class (None when it does not exist). Copies
/// `overhead.podFixed` into `spec.overhead` and merges `scheduling.nodeSelector` / `tolerations`.
pub fn runtime_class(spec: &mut Value, name: &str, rc: Option<&Value>) -> Result<(), String> {
    let Some(rc) = rc else { return Err(format!("pod rejected: RuntimeClass {name:?} not found")) };
    let nonempty = |v: &Value| v.as_object().is_some_and(|o| !o.is_empty());
    if let Some(fixed) = rc.pointer(&["overhead", "podFixed"]).filter(|f| nonempty(f)) {
        match spec.get("overhead").filter(|o| nonempty(o)) {
            Some(have) if have != fixed => return Err(String::from("pod rejected: Pod's Overhead doesn't match RuntimeClass's defined Overhead")),
            _ => spec.set("overhead", fixed.clone()),
        }
    }
    if let Some(sel) = rc.pointer(&["scheduling", "nodeSelector"]).and_then(Value::as_object) {
        let ns = spec.entry_object("nodeSelector");
        for (k, v) in sel {
            match ns.get(k) {
                Some(have) if have != v => return Err(format!("pod rejected: conflict: runtime class node selector [{k}={}] does not match the pod node selector", v.as_str().unwrap_or(""))),
                Some(_) => {}
                None => ns.set(k, v.clone()),
            }
        }
    }
    if let Some(tols) = rc.pointer(&["scheduling", "tolerations"]).and_then(Value::as_array) {
        let mut have: Vec<Value> = spec.get("tolerations").and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
        for t in tols {
            if !have.contains(t) {
                have.push(t.clone());
            }
        }
        if !have.is_empty() {
            spec.set("tolerations", Value::Array(have));
        }
    }
    Ok(())
}

fn qty(v: Option<&Value>) -> Option<Quantity> {
    match v? {
        Value::String(s) => Quantity::parse(s).ok(),
        Value::Number(n) => Quantity::parse(n.raw()).ok(),
        _ => None,
    }
}

fn nano(q: &Quantity) -> i128 {
    q.scaled_value(-9).unwrap_or(0)
}

/// LimitRanger for a PersistentVolumeClaim: `PersistentVolumeClaim` limits bound the storage request.
pub fn limit_ranger_pvc(pvc: &Value, ranges: &[Value]) -> Result<(), String> {
    let Some(req) = qty(pvc.pointer(&["spec", "resources", "requests", "storage"])) else { return Ok(()) };
    let mut errs = Vec::new();
    for it in ranges.iter().flat_map(|r| r.pointer(&["spec", "limits"]).and_then(Value::as_array).unwrap_or(&[])).filter(|i| i.get("type").and_then(Value::as_str) == Some("PersistentVolumeClaim")) {
        if let Some(min) = qty(it.pointer(&["min", "storage"])).filter(|m| req < *m) {
            errs.push(format!("minimum storage usage per PersistentVolumeClaim is {}, but request is {}", min.to_canonical_string(), req.to_canonical_string()));
        }
        if let Some(max) = qty(it.pointer(&["max", "storage"])).filter(|m| req > *m) {
            errs.push(format!("maximum storage usage per PersistentVolumeClaim is {}, but request is {}", max.to_canonical_string(), req.to_canonical_string()));
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join(", "))
    }
}

/// LimitRanger for one pod: defaults every container's missing requests and limits from the
/// namespace's `Container` limits, then checks min, max and the limit/request ratio.
pub fn limit_ranger(spec: &mut Value, ranges: &[Value]) -> Result<(), String> {
    let items: Vec<&Value> = ranges.iter().flat_map(|r| r.pointer(&["spec", "limits"]).and_then(Value::as_array).unwrap_or(&[])).filter(|i| i.get("type").and_then(Value::as_str) == Some("Container")).collect();
    let pod_items: Vec<&Value> = ranges.iter().flat_map(|r| r.pointer(&["spec", "limits"]).and_then(Value::as_array).unwrap_or(&[])).filter(|i| i.get("type").and_then(Value::as_str) == Some("Pod")).collect();
    if items.is_empty() && pod_items.is_empty() {
        return Ok(());
    }
    let mut errs = Vec::new();
    for key in ["initContainers", "containers"] {
        let Some(Value::Array(cs)) = spec.get_mut(key) else { continue };
        for c in cs.iter_mut() {
            let res = c.entry_object("resources");
            // A limit alone also sets the request (API defaulting), ahead of any default request.
            let lim: Vec<(String, Value)> = res.get("limits").and_then(Value::as_object).map(|o| o.to_vec()).unwrap_or_default();
            for (k, v) in &lim {
                if res.get("requests").and_then(|r| r.get(k)).is_none() {
                    res.entry_object("requests").set(k, v.clone());
                }
            }
            for it in &items {
                for (field, target) in [("defaultRequest", "requests"), ("default", "limits")] {
                    for (k, v) in it.get(field).and_then(Value::as_object).unwrap_or(&[]) {
                        if res.get(target).and_then(|r| r.get(k)).is_none() {
                            res.entry_object(target).set(k, v.clone());
                        }
                    }
                }
            }
            for it in &items {
                let get = |kind: &str, k: &str| qty(res.get(kind).and_then(|r| r.get(k)));
                for (k, v) in it.get("min").and_then(Value::as_object).unwrap_or(&[]) {
                    let Some(min) = qty(Some(v)) else { continue };
                    for (kind, word) in [("requests", "request"), ("limits", "limit")] {
                        if let Some(x) = get(kind, k).filter(|x| *x < min) {
                            errs.push(format!("minimum {k} usage per Container is {}, but {word} is {}", min.to_canonical_string(), x.to_canonical_string()));
                        }
                    }
                }
                for (k, v) in it.get("max").and_then(Value::as_object).unwrap_or(&[]) {
                    let Some(max) = qty(Some(v)) else { continue };
                    if let Some(x) = get("requests", k).filter(|x| *x > max) {
                        errs.push(format!("maximum {k} usage per Container is {}, but request is {}", max.to_canonical_string(), x.to_canonical_string()));
                    }
                    match get("limits", k) {
                        None => errs.push(format!("maximum {k} usage per Container is {}.  No limit is specified", max.to_canonical_string())),
                        Some(x) if x > max => errs.push(format!("maximum {k} usage per Container is {}, but limit is {}", max.to_canonical_string(), x.to_canonical_string())),
                        _ => {}
                    }
                }
                for (k, v) in it.get("maxLimitRequestRatio").and_then(Value::as_object).unwrap_or(&[]) {
                    let (Some(ratio), Some(l), Some(r)) = (qty(Some(v)), get("limits", k), get("requests", k)) else { continue };
                    if nano(&r) > 0 && nano(&l) > nano(&ratio) * nano(&r) / 1_000_000_000 {
                        errs.push(format!("{k} max limit to request ratio per Container is {}, but provided ratio is {}", ratio.to_canonical_string(), nano(&l) as f64 / nano(&r) as f64));
                    }
                }
            }
        }
    }
    // Pod type: the pod's total (sum of the app containers, or the largest init container when
    // that is bigger) against min, max and the limit/request ratio.
    if !pod_items.is_empty() {
        let total = |kind: &str, k: &str| -> Option<i128> {
            let of = |c: &Value| qty(c.pointer(&["resources", kind, k])).map(|q| nano(&q));
            let apps: Vec<&Value> = spec.get("containers").and_then(Value::as_array).unwrap_or(&[]).iter().collect();
            let sum: i128 = apps.iter().filter_map(|c| of(c)).sum();
            let init = spec.get("initContainers").and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(of).max().unwrap_or(0);
            let t = sum.max(init);
            (apps.iter().any(|c| of(c).is_some()) || init > 0).then_some(t)
        };
        let fmt = |n: i128, f: kr_fmt::quantity::Format| Quantity::new(n, -9, f).to_canonical_string();
        for it in &pod_items {
            for (k, v) in it.get("min").and_then(Value::as_object).unwrap_or(&[]) {
                let Some(mq) = qty(Some(v)) else { continue };
                let (min, f) = (nano(&mq), mq.format());
                for (kind, word) in [("requests", "request"), ("limits", "limit")] {
                    if let Some(x) = total(kind, k).filter(|x| *x < min) {
                        errs.push(format!("minimum {k} usage per Pod is {}, but total {word}s is {}", fmt(min, f), fmt(x, f)));
                    }
                }
            }
            for (k, v) in it.get("max").and_then(Value::as_object).unwrap_or(&[]) {
                let Some(mq) = qty(Some(v)) else { continue };
                let (max, f) = (nano(&mq), mq.format());
                if let Some(x) = total("requests", k).filter(|x| *x > max) {
                    errs.push(format!("maximum {k} usage per Pod is {}, but total requests is {}", fmt(max, f), fmt(x, f)));
                }
                match total("limits", k) {
                    None => errs.push(format!("maximum {k} usage per Pod is {}.  No limit is specified", fmt(max, f))),
                    Some(x) if x > max => errs.push(format!("maximum {k} usage per Pod is {}, but total limits is {}", fmt(max, f), fmt(x, f))),
                    _ => {}
                }
            }
            for (k, v) in it.get("maxLimitRequestRatio").and_then(Value::as_object).unwrap_or(&[]) {
                let (Some(ratio), Some(l), Some(r)) = (qty(Some(v)), total("limits", k), total("requests", k)) else { continue };
                if r > 0 && l > nano(&ratio) * r / 1_000_000_000 {
                    errs.push(format!("{k} max limit to request ratio per Pod is {}, but provided ratio is {}", ratio.to_canonical_string(), l as f64 / r as f64));
                }
            }
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pod_type_limits() {
        let lr = j(r#"{"spec":{"limits":[{"type":"Pod","max":{"cpu":"1"},"min":{"memory":"10Mi"}}]}}"#);
        let mut ok = j(r#"{"containers":[{"name":"a","resources":{"requests":{"cpu":"400m","memory":"8Mi"},"limits":{"cpu":"400m"}}},{"name":"b","resources":{"requests":{"cpu":"400m","memory":"8Mi"},"limits":{"cpu":"400m"}}}]}"#);
        limit_ranger(&mut ok, core::slice::from_ref(&lr)).unwrap();
        let mut bad = j(r#"{"containers":[{"name":"a","resources":{"requests":{"cpu":"700m","memory":"1Mi"},"limits":{"cpu":"700m"}}},{"name":"b","resources":{"requests":{"cpu":"700m","memory":"1Mi"},"limits":{"cpu":"700m"}}}]}"#);
        let e = limit_ranger(&mut bad, core::slice::from_ref(&lr)).unwrap_err();
        assert!(e.contains("maximum cpu usage per Pod is 1, but total requests is 1400m") && e.contains("minimum memory usage per Pod is 10Mi"), "{e}");
    }

    #[test]
    fn pvc_limits() {
        let lr = j(r#"{"spec":{"limits":[{"type":"PersistentVolumeClaim","min":{"storage":"1Gi"},"max":{"storage":"2Gi"}}]}}"#);
        let pvc = |s: &str| j(&format!(r#"{{"spec":{{"resources":{{"requests":{{"storage":"{s}"}}}}}}}}"#));
        limit_ranger_pvc(&pvc("1500Mi"), core::slice::from_ref(&lr)).unwrap();
        assert!(limit_ranger_pvc(&pvc("500Mi"), core::slice::from_ref(&lr)).is_err());
        assert!(limit_ranger_pvc(&pvc("3Gi"), core::slice::from_ref(&lr)).is_err());
    }

    fn j(s: &str) -> Value {
        kr_fmt::json::parse_str(s).unwrap()
    }

    #[test]
    fn sysctl_names() {
        for ok in ["kernel.shmmax", "net.ipv4.ip_local_port_range", "a-b.c_d"] {
            assert!(valid_sysctl_name(ok), "{ok}");
        }
        for bad in ["foo-", "bar..", "", ".a", "A.b", "a.-b"] {
            assert!(!valid_sysctl_name(bad), "{bad}");
        }
        let e = validate_sysctls(&j(r#"{"securityContext":{"sysctls":[{"name":"foo-","value":"1"},{"name":"kernel.shmmax","value":"1"},{"name":"bar..","value":"4"}]}}"#)).unwrap_err();
        assert!(e.contains(r#"Invalid value: "foo-""#) && e.contains(r#"Invalid value: "bar..""#) && !e.contains("shmmax"));
    }

    #[test]
    fn runtime_class_overhead_and_scheduling() {
        let rc = j(r#"{"overhead":{"podFixed":{"cpu":"10m"}},"scheduling":{"nodeSelector":{"a":"b"},"tolerations":[{"key":"k","operator":"Exists"}]}}"#);
        let mut spec = j(r#"{"tolerations":[{"key":"k","operator":"Exists"}]}"#);
        runtime_class(&mut spec, "x", Some(&rc)).unwrap();
        assert_eq!(spec.pointer(&["overhead", "cpu"]).and_then(Value::as_str), Some("10m"));
        assert_eq!(spec.pointer(&["nodeSelector", "a"]).and_then(Value::as_str), Some("b"));
        assert_eq!(spec.get("tolerations").and_then(Value::as_array).map(|a| a.len()), Some(1));
        assert_eq!(runtime_class(&mut spec, "x", None).unwrap_err(), "pod rejected: RuntimeClass \"x\" not found");
        let mut other = j(r#"{"overhead":{"cpu":"1"}}"#);
        assert!(runtime_class(&mut other, "x", Some(&rc)).is_err());
    }

    #[test]
    fn limit_ranger_defaults_and_bounds() {
        let lr = j(r#"{"spec":{"limits":[{"type":"Container","min":{"cpu":"50m"},"max":{"cpu":"500m"},"default":{"cpu":"500m","memory":"500Mi"},"defaultRequest":{"cpu":"100m","memory":"200Mi"}}]}}"#);
        let mut spec = j(r#"{"containers":[{"name":"c"}]}"#);
        limit_ranger(&mut spec, core::slice::from_ref(&lr)).unwrap();
        let r = |s: &Value, a: &str, b: &str| s.pointer(&["containers"]).and_then(Value::as_array).unwrap()[0].pointer(&["resources", a, b]).and_then(Value::as_str).map(String::from);
        assert_eq!(r(&spec, "requests", "memory").as_deref(), Some("200Mi"));
        assert_eq!(r(&spec, "limits", "cpu").as_deref(), Some("500m"));
        // Partial: the limit alone becomes the request, the other default fills in.
        let mut p = j(r#"{"containers":[{"name":"c","resources":{"limits":{"cpu":"300m"},"requests":{"memory":"150Mi"}}}]}"#);
        limit_ranger(&mut p, core::slice::from_ref(&lr)).unwrap();
        assert_eq!(r(&p, "requests", "cpu").as_deref(), Some("300m"));
        assert_eq!(r(&p, "limits", "memory").as_deref(), Some("500Mi"));
        let mut lo = j(r#"{"containers":[{"name":"c","resources":{"requests":{"cpu":"10m"}}}]}"#);
        assert!(limit_ranger(&mut lo, core::slice::from_ref(&lr)).is_err());
        let mut hi = j(r#"{"containers":[{"name":"c","resources":{"requests":{"cpu":"600m"}}}]}"#);
        assert!(limit_ranger(&mut hi, core::slice::from_ref(&lr)).is_err());
    }
}
