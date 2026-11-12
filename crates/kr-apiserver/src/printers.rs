//! Server-side printing for `kubectl get` (meta.k8s.io/v1 Table): per-kind extra columns and
//! the human-readable age format kubectl expects.

use alloc::string::{String, ToString};
use kr_fmt::json::Value;

type Col = (&'static str, fn(&Value) -> String);

fn s(v: &Value, path: &[&str]) -> String {
    match v.pointer(path) {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Number(n)) => n.raw().to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn n(v: &Value, path: &[&str]) -> i64 {
    v.pointer(path).and_then(Value::as_i64).unwrap_or(0)
}

fn pod_ready(v: &Value) -> String {
    let statuses = v.pointer(&["status", "containerStatuses"]).and_then(Value::as_array).unwrap_or(&[]);
    let total = v.pointer(&["spec", "containers"]).and_then(Value::as_array).map_or(0, |c| c.len());
    let ready = statuses.iter().filter(|c| c.get("ready").and_then(Value::as_bool) == Some(true)).count();
    alloc::format!("{ready}/{total}")
}

fn pod_status(v: &Value) -> String {
    if v.pointer(&["metadata", "deletionTimestamp"]).is_some() {
        return "Terminating".into();
    }
    let p = s(v, &["status", "phase"]);
    if p.is_empty() {
        return "Pending".into();
    }
    // Like kubectl: a waiting/terminated container reason beats the phase.
    let init = v.pointer(&["status", "initContainerStatuses"]).and_then(Value::as_array).unwrap_or(&[]);
    let main = v.pointer(&["status", "containerStatuses"]).and_then(Value::as_array).unwrap_or(&[]);
    for c in init.iter().chain(main.iter()) {
        let r = s(c, &["state", "waiting", "reason"]);
        if !r.is_empty() {
            return r;
        }
    }
    if p == "Failed" || p == "Running" {
        for c in main {
            let r = s(c, &["state", "terminated", "reason"]);
            if !r.is_empty() && p != "Running" {
                return r;
            }
        }
    }
    if s(v, &["status", "reason"]) == "NodeLost" || s(v, &["status", "reason"]) == "Evicted" {
        return s(v, &["status", "reason"]);
    }
    p
}

fn pod_restarts(v: &Value) -> String {
    let r: i64 = v.pointer(&["status", "containerStatuses"]).and_then(Value::as_array).unwrap_or(&[]).iter().map(|c| c.get("restartCount").and_then(Value::as_i64).unwrap_or(0)).sum();
    r.to_string()
}

fn ready_of(v: &Value) -> String {
    alloc::format!("{}/{}", n(v, &["status", "readyReplicas"]), v.pointer(&["spec", "replicas"]).and_then(Value::as_i64).unwrap_or(1))
}

fn svc_ports(v: &Value) -> String {
    let ports = v.pointer(&["spec", "ports"]).and_then(Value::as_array).unwrap_or(&[]);
    let out: alloc::vec::Vec<String> = ports.iter().map(|p| {
        let pr = s(p, &["protocol"]);
        let pr = if pr.is_empty() { String::from("TCP") } else { pr };
        let np = s(p, &["nodePort"]);
        if np.is_empty() { alloc::format!("{}/{pr}", s(p, &["port"])) } else { alloc::format!("{}:{np}/{pr}", s(p, &["port"])) }
    }).collect();
    if out.is_empty() { "<none>".into() } else { out.join(",") }
}

/// `kubectl get endpoints` ENDPOINTS column (upstream `formatEndpoints`): at most three
/// `ip:port` entries, then ` + N more...`.
fn endpoints_list(v: &Value) -> String {
    let subsets = v.get("subsets").and_then(Value::as_array).unwrap_or(&[]);
    if subsets.is_empty() {
        return "<none>".into();
    }
    let max = 3;
    let (mut list, mut count): (alloc::vec::Vec<String>, usize) = (alloc::vec::Vec::new(), 0);
    for ss in subsets {
        let addrs = ss.get("addresses").and_then(Value::as_array).unwrap_or(&[]);
        let ports = ss.get("ports").and_then(Value::as_array).unwrap_or(&[]);
        let hp = |ip: String, port: Option<&Value>| match port {
            None => ip,
            Some(p) if ip.contains(':') => alloc::format!("[{ip}]:{}", s(p, &["port"])),
            Some(p) => alloc::format!("{ip}:{}", s(p, &["port"])),
        };
        if ports.is_empty() {
            for a in addrs {
                count += 1;
                if list.len() < max { list.push(hp(s(a, &["ip"]), None)); }
            }
        } else {
            for p in ports {
                for a in addrs {
                    count += 1;
                    if list.len() < max { list.push(hp(s(a, &["ip"]), Some(p))); }
                }
            }
        }
    }
    let mut out = list.join(",");
    if count > max {
        out.push_str(&alloc::format!(" + {} more...", count - max));
    }
    out
}

fn or_none(x: String) -> String {
    if x.is_empty() { "<none>".into() } else { x }
}

fn data_count(v: &Value) -> String {
    let a = v.get("data").and_then(Value::as_object).map_or(0, |o| o.len());
    let b = v.get("binaryData").and_then(Value::as_object).map_or(0, |o| o.len());
    (a + b).to_string()
}

fn cond_true(v: &Value, ty: &str) -> bool {
    v.pointer(&["status", "conditions"]).and_then(Value::as_array).is_some_and(|c| c.iter().any(|x| s(x, &["type"]) == ty && s(x, &["status"]) == "True"))
}

fn node_status(v: &Value) -> String {
    let conds = v.pointer(&["status", "conditions"]).and_then(Value::as_array).unwrap_or(&[]);
    let st = match conds.iter().find(|x| s(x, &["type"]) == "Ready") {
        Some(c) if s(c, &["status"]) == "True" => "Ready",
        _ => "NotReady",
    };
    if v.pointer(&["spec", "unschedulable"]).and_then(Value::as_bool) == Some(true) { alloc::format!("{st},SchedulingDisabled") } else { st.into() }
}

fn node_roles(v: &Value) -> String {
    let l = v.pointer(&["metadata", "labels"]).and_then(Value::as_object).unwrap_or(&[]);
    let roles: alloc::vec::Vec<&str> = l.iter().filter_map(|(k, _)| k.strip_prefix("node-role.kubernetes.io/")).collect();
    or_none(roles.join(","))
}

fn job_status(v: &Value) -> String {
    if cond_true(v, "Failed") { "Failed".into() } else if cond_true(v, "Complete") { "Complete".into() } else if cond_true(v, "Suspended") { "Suspended".into() } else { "Running".into() }
}

fn job_duration(v: &Value) -> String {
    let Some(start) = parse_rfc3339(&s(v, &["status", "startTime"])) else { return String::new() };
    let end = parse_rfc3339(&s(v, &["status", "completionTime"])).unwrap_or(start);
    human_duration(end - start)
}

fn modes(v: &Value, path: &[&str]) -> String {
    let m: alloc::vec::Vec<&str> = v.pointer(path).and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(|x| match x.as_str()? {
        "ReadWriteOnce" => Some("RWO"), "ReadOnlyMany" => Some("ROX"), "ReadWriteMany" => Some("RWX"), "ReadWriteOncePod" => Some("RWOP"), o => Some(o),
    }).collect();
    m.join(",")
}

fn cap(v: &Value, path: &[&str]) -> String {
    s(v, path)
}

/// `kind/name` of an HPA's scale target.
fn hpa_reference(v: &Value) -> String {
    alloc::format!("{}/{}", s(v, &["spec", "scaleTargetRef", "kind"]), s(v, &["spec", "scaleTargetRef", "name"]))
}

/// `current/target` of each metric of an HPA (`kubectl get hpa` TARGETS), e.g. `45%/80%`.
fn hpa_targets(v: &Value) -> String {
    let specs = v.pointer(&["spec", "metrics"]).and_then(Value::as_array).filter(|m| !m.is_empty());
    let Some(specs) = specs else {
        // autoscaling/v1: a CPU percentage.
        let cur = v.pointer(&["status", "currentCPUUtilizationPercentage"]).and_then(Value::as_i64).map(|c| alloc::format!("{c}%")).unwrap_or_else(|| "<unknown>".into());
        let target = v.pointer(&["spec", "targetCPUUtilizationPercentage"]).and_then(Value::as_i64).map(|t| alloc::format!("{t}%")).unwrap_or_else(|| "<unset>".into());
        return alloc::format!("{cur}/{target}");
    };
    let current: &[Value] = v.pointer(&["status", "currentMetrics"]).and_then(Value::as_array).unwrap_or(&[]);
    specs
        .iter()
        .map(|m| {
            let ty = s(m, &["type"]);
            let key = match ty.as_str() {
                "Resource" => "resource",
                "ContainerResource" => "containerResource",
                "Pods" => "pods",
                "Object" => "object",
                _ => "external",
            };
            let name = if matches!(ty.as_str(), "Resource" | "ContainerResource") { s(m, &[key, "name"]) } else { s(m, &[key, "metric", "name"]) };
            let target = match s(m, &[key, "target", "type"]).as_str() {
                "Utilization" => alloc::format!("{}%", s(m, &[key, "target", "averageUtilization"])),
                "AverageValue" => s(m, &[key, "target", "averageValue"]),
                _ => s(m, &[key, "target", "value"]),
            };
            let cur = current.iter().find(|c| s(c, &["type"]) == ty && (if matches!(ty.as_str(), "Resource" | "ContainerResource") { s(c, &[key, "name"]) == name } else { s(c, &[key, "metric", "name"]) == name }));
            let cur = match cur {
                Some(c) if c.pointer(&[key, "current", "averageUtilization"]).is_some() => alloc::format!("{}%", s(c, &[key, "current", "averageUtilization"])),
                Some(c) if c.pointer(&[key, "current", "averageValue"]).is_some() => s(c, &[key, "current", "averageValue"]),
                Some(c) => s(c, &[key, "current", "value"]),
                None => "<unknown>".into(),
            };
            alloc::format!("{cur}/{target}")
        })
        .collect::<alloc::vec::Vec<_>>()
        .join(", ")
}

/// Extra columns between NAME and AGE.
pub fn columns(kind: &str) -> &'static [Col] {
    match kind {
        "HorizontalPodAutoscaler" => &[("Reference", hpa_reference), ("Targets", hpa_targets), ("MinPods", |v| v.pointer(&["spec", "minReplicas"]).and_then(Value::as_i64).unwrap_or(1).to_string()), ("MaxPods", |v| n(v, &["spec", "maxReplicas"]).to_string()), ("Replicas", |v| n(v, &["status", "currentReplicas"]).to_string())],
        "Pod" => &[("Ready", pod_ready), ("Status", pod_status), ("Restarts", pod_restarts)],
        "Deployment" => &[("Ready", ready_of), ("Up-to-date", |v| n(v, &["status", "updatedReplicas"]).to_string()), ("Available", |v| n(v, &["status", "availableReplicas"]).to_string())],
        "ReplicaSet" => &[("Desired", |v| n(v, &["spec", "replicas"]).to_string()), ("Current", |v| n(v, &["status", "replicas"]).to_string()), ("Ready", |v| n(v, &["status", "readyReplicas"]).to_string())],
        "StatefulSet" => &[("Ready", ready_of)],
        "Service" => &[("Type", |v| { let t = s(v, &["spec", "type"]); if t.is_empty() { "ClusterIP".into() } else { t } }), ("Cluster-IP", |v| or_none(s(v, &["spec", "clusterIP"]))), ("Ports", svc_ports)],
        "Endpoints" => &[("Endpoints", endpoints_list)],
        "Namespace" => &[("Status", |v| { let p = s(v, &["status", "phase"]); if p.is_empty() { "Active".into() } else { p } })],
        "ConfigMap" | "Secret" => &[("Data", data_count)],
        "Node" => &[("Status", node_status), ("Roles", node_roles)],
        "Job" => &[
            ("Status", job_status),
            ("Completions", |v| alloc::format!("{}/{}", n(v, &["status", "succeeded"]), v.pointer(&["spec", "completions"]).and_then(Value::as_i64).unwrap_or(1))),
            ("Duration", job_duration),
        ],
        "CronJob" => &[
            ("Schedule", |v| s(v, &["spec", "schedule"])),
            ("Timezone", |v| or_none(s(v, &["spec", "timeZone"]))),
            ("Suspend", |v| (v.pointer(&["spec", "suspend"]).and_then(Value::as_bool) == Some(true)).to_string().replace("true", "True").replace("false", "False")),
            ("Active", |v| v.pointer(&["status", "active"]).and_then(Value::as_array).map_or(0, |a| a.len()).to_string()),
            ("Last Schedule", |v| parse_rfc3339(&s(v, &["status", "lastScheduleTime"])).map_or("<none>".into(), |_| s(v, &["status", "lastScheduleTime"]))),
        ],
        "DaemonSet" => &[
            ("Desired", |v| n(v, &["status", "desiredNumberScheduled"]).to_string()),
            ("Current", |v| n(v, &["status", "currentNumberScheduled"]).to_string()),
            ("Ready", |v| n(v, &["status", "numberReady"]).to_string()),
            ("Up-to-date", |v| n(v, &["status", "updatedNumberScheduled"]).to_string()),
            ("Available", |v| n(v, &["status", "numberAvailable"]).to_string()),
        ],
        "PersistentVolumeClaim" => &[
            ("Status", |v| s(v, &["status", "phase"])),
            ("Volume", |v| s(v, &["spec", "volumeName"])),
            ("Capacity", |v| cap(v, &["status", "capacity", "storage"])),
            ("Access Modes", |v| modes(v, &["status", "accessModes"])),
            ("StorageClass", |v| or_none(s(v, &["spec", "storageClassName"]))),
        ],
        "PersistentVolume" => &[
            ("Capacity", |v| cap(v, &["spec", "capacity", "storage"])),
            ("Access Modes", |v| modes(v, &["spec", "accessModes"])),
            ("Reclaim Policy", |v| s(v, &["spec", "persistentVolumeReclaimPolicy"])),
            ("Status", |v| s(v, &["status", "phase"])),
            ("Claim", |v| { let ns = s(v, &["spec", "claimRef", "namespace"]); if ns.is_empty() { String::new() } else { alloc::format!("{ns}/{}", s(v, &["spec", "claimRef", "name"])) } }),
            ("StorageClass", |v| or_none(s(v, &["spec", "storageClassName"]))),
        ],
        "StorageClass" => &[
            ("Provisioner", |v| s(v, &["provisioner"])),
            ("ReclaimPolicy", |v| { let r = s(v, &["reclaimPolicy"]); if r.is_empty() { "Delete".into() } else { r } }),
            ("VolumeBindingMode", |v| { let r = s(v, &["volumeBindingMode"]); if r.is_empty() { "Immediate".into() } else { r } }),
            ("AllowVolumeExpansion", |v| (v.get("allowVolumeExpansion").and_then(Value::as_bool) == Some(true)).to_string()),
        ],
        _ => &[],
    }
}

fn selector_text(v: &Value) -> String {
    let sel = v.pointer(&["spec", "selector", "matchLabels"]).or_else(|| v.pointer(&["spec", "selector"])).and_then(Value::as_object).unwrap_or(&[]);
    let out: alloc::vec::Vec<String> = sel.iter().filter_map(|(k, x)| Some(alloc::format!("{k}={}", x.as_str()?))).collect();
    or_none(out.join(","))
}

fn tpl_ctrs(v: &Value, key: &str) -> String {
    let cs = v.pointer(&["spec", "template", "spec", "containers"]).and_then(Value::as_array).unwrap_or(&[]);
    cs.iter().map(|c| s(c, &[key])).collect::<alloc::vec::Vec<_>>().join(",")
}

fn node_addr(v: &Value) -> String {
    let a = v.pointer(&["status", "addresses"]).and_then(Value::as_array).unwrap_or(&[]);
    a.iter().find(|x| s(x, &["type"]) == "InternalIP").map(|x| s(x, &["address"])).unwrap_or_else(|| "<none>".into())
}

/// Extra columns after AGE that `kubectl get -o wide` adds (table column priority 1).
pub fn wide_columns(kind: &str) -> &'static [Col] {
    match kind {
        "Pod" => &[
            ("IP", |v| or_none(s(v, &["status", "podIP"]))),
            ("Node", |v| or_none(s(v, &["spec", "nodeName"]))),
            ("Nominated Node", |v| or_none(s(v, &["status", "nominatedNodeName"]))),
            ("Readiness Gates", |v| {
                let g: alloc::vec::Vec<String> = v.pointer(&["spec", "readinessGates"]).and_then(Value::as_array).unwrap_or(&[]).iter().map(|x| s(x, &["conditionType"])).collect();
                or_none(g.join(","))
            }),
        ],
        "Deployment" | "ReplicaSet" | "StatefulSet" | "DaemonSet" | "Job" => &[("Containers", |v| tpl_ctrs(v, "name")), ("Images", |v| tpl_ctrs(v, "image")), ("Selector", selector_text)],
        "Service" => &[("Selector", |v| {
            let sel = v.pointer(&["spec", "selector"]).and_then(Value::as_object).unwrap_or(&[]);
            or_none(sel.iter().filter_map(|(k, x)| Some(alloc::format!("{k}={}", x.as_str()?))).collect::<alloc::vec::Vec<_>>().join(","))
        })],
        "Node" => &[
            ("Internal-IP", node_addr),
            ("OS-Image", |v| s(v, &["status", "nodeInfo", "osImage"])),
            ("Kernel-Version", |v| s(v, &["status", "nodeInfo", "kernelVersion"])),
            ("Container-Runtime", |v| s(v, &["status", "nodeInfo", "containerRuntimeVersion"])),
        ],
        _ => &[],
    }
}

/// Parses "YYYY-MM-DDTHH:MM:SSZ" (fractional seconds and offsets other than Z rejected).
pub fn parse_rfc3339(t: &str) -> Option<i64> {
    let b = t.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[19] != b'Z' {
        return None;
    }
    let num = |r: core::ops::Range<usize>| -> Option<i64> { t.get(r)?.parse().ok() };
    let (y, m, d, hh, mm, ss) = (num(0..4)?, num(5..7)?, num(8..10)?, num(11..13)?, num(14..16)?, num(17..19)?);
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146097 + doe - 719468) * 86400 + hh * 3600 + mm * 60 + ss)
}

/// k8s.io/apimachinery duration.HumanDuration.
pub fn human_duration(secs: i64) -> String {
    let s = secs.max(0);
    let (m, h, d) = (s / 60, s / 3600, s / 86400);
    if s < 120 {
        alloc::format!("{s}s")
    } else if m < 10 {
        if s % 60 == 0 { alloc::format!("{m}m") } else { alloc::format!("{m}m{}s", s % 60) }
    } else if h < 3 {
        alloc::format!("{m}m")
    } else if h < 8 {
        if m % 60 == 0 { alloc::format!("{h}h") } else { alloc::format!("{h}h{}m", m % 60) }
    } else if h < 48 {
        alloc::format!("{h}h")
    } else if h < 192 {
        if h % 24 == 0 { alloc::format!("{d}d") } else { alloc::format!("{d}d{}h", h % 24) }
    } else if d < 730 {
        alloc::format!("{d}d")
    } else {
        alloc::format!("{}y{}d", d / 365, d % 365)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn endpoints_column() {
        let p = |x: &str| kr_fmt::json::parse(x.as_bytes()).unwrap();
        assert_eq!(endpoints_list(&p("{}")), "<none>");
        let v = p(r#"{"subsets":[{"addresses":[{"ip":"10.0.0.1"},{"ip":"10.0.0.2"}],"ports":[{"port":80},{"port":443}]}]}"#);
        assert_eq!(endpoints_list(&v), "10.0.0.1:80,10.0.0.2:80,10.0.0.1:443 + 1 more...");
        assert_eq!(endpoints_list(&p(r#"{"subsets":[{"addresses":[{"ip":"fd00::1"}],"ports":[{"port":80}]}]}"#)), "[fd00::1]:80");
        assert_eq!(endpoints_list(&p(r#"{"subsets":[{"addresses":[{"ip":"1.1.1.1"}]}]}"#)), "1.1.1.1");
    }
    #[test]
    fn durations_and_time() {
        assert_eq!(human_duration(5), "5s");
        assert_eq!(human_duration(185), "3m5s");
        assert_eq!(human_duration(3600 * 5 + 120), "5h2m");
        assert_eq!(human_duration(86400 * 3), "3d");
        assert_eq!(parse_rfc3339(&crate::object::rfc3339(1_800_000_123)), Some(1_800_000_123));
        assert_eq!(parse_rfc3339("2026-10-23T16:00:00.5Z"), None);
    }
}
