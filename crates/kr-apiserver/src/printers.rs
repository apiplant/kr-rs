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
    if p.is_empty() { "Pending".into() } else { p }
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
    let out: alloc::vec::Vec<String> = ports.iter().map(|p| alloc::format!("{}/{}", s(p, &["port"]), { let pr = s(p, &["protocol"]); if pr.is_empty() { "TCP".into() } else { pr } })).collect();
    if out.is_empty() { "<none>".into() } else { out.join(",") }
}

fn or_none(x: String) -> String {
    if x.is_empty() { "<none>".into() } else { x }
}

fn data_count(v: &Value) -> String {
    let a = v.get("data").and_then(Value::as_object).map_or(0, |o| o.len());
    let b = v.get("binaryData").and_then(Value::as_object).map_or(0, |o| o.len());
    (a + b).to_string()
}

/// Extra columns between NAME and AGE.
pub fn columns(kind: &str) -> &'static [Col] {
    match kind {
        "Pod" => &[("Ready", pod_ready), ("Status", pod_status), ("Restarts", pod_restarts)],
        "Deployment" => &[("Ready", ready_of), ("Up-to-date", |v| n(v, &["status", "updatedReplicas"]).to_string()), ("Available", |v| n(v, &["status", "availableReplicas"]).to_string())],
        "ReplicaSet" => &[("Desired", |v| n(v, &["spec", "replicas"]).to_string()), ("Current", |v| n(v, &["status", "replicas"]).to_string()), ("Ready", |v| n(v, &["status", "readyReplicas"]).to_string())],
        "StatefulSet" => &[("Ready", ready_of)],
        "Service" => &[("Type", |v| { let t = s(v, &["spec", "type"]); if t.is_empty() { "ClusterIP".into() } else { t } }), ("Cluster-IP", |v| or_none(s(v, &["spec", "clusterIP"]))), ("Ports", svc_ports)],
        "Namespace" => &[("Status", |v| { let p = s(v, &["status", "phase"]); if p.is_empty() { "Active".into() } else { p } })],
        "ConfigMap" | "Secret" => &[("Data", data_count)],
        "Node" => &[("Status", |v| {
            let ready = v.pointer(&["status", "conditions"]).and_then(Value::as_array).and_then(|c| c.iter().find(|x| x.get("type").and_then(Value::as_str) == Some("Ready"))).and_then(|c| c.get("status")).and_then(Value::as_str) == Some("True");
            if ready { "Ready".into() } else { "NotReady".into() }
        })],
        "Job" => &[("Completions", |v| alloc::format!("{}/{}", n(v, &["status", "succeeded"]), v.pointer(&["spec", "completions"]).and_then(Value::as_i64).unwrap_or(1)))],
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
    fn durations_and_time() {
        assert_eq!(human_duration(5), "5s");
        assert_eq!(human_duration(185), "3m5s");
        assert_eq!(human_duration(3600 * 5 + 120), "5h2m");
        assert_eq!(human_duration(86400 * 3), "3d");
        assert_eq!(parse_rfc3339(&crate::object::rfc3339(1_800_000_123)), Some(1_800_000_123));
        assert_eq!(parse_rfc3339("2026-10-23T16:00:00.5Z"), None);
    }
}
