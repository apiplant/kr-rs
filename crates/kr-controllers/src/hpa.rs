//! The HorizontalPodAutoscaler controller (autoscaling/v2; v1 objects work too).
//!
//! Every [`Config::hpa_ms`] (default 15 s, as upstream) each HPA is evaluated: the replica count of
//! its scale target (read and written through the `/scale` subresource, so Deployments,
//! StatefulSets, ReplicaSets, ReplicationControllers and custom resources with a scale
//! subresource all work) is moved towards what the metrics ask for.
//!
//! Metrics: `Resource` and `ContainerResource` (percent of the requests or an average value, from
//! `metrics.k8s.io`), and `Pods`, `Object` and `External`, read from `custom.metrics.k8s.io` and
//! `external.metrics.k8s.io` as served by a metrics adapter registered as an APIService (kr has
//! none of its own; the aggregator proxies the calls).
//!
//! The algorithm follows kube-controller-manager's replica calculator: tolerance 0.1; pods without
//! metrics are assumed to use 100% when scaling down and 0% when scaling up, pods that are not
//! ready yet 0% when scaling up (and are ignored otherwise), CPU samples of pods still in their
//! initialization period are discarded, and a recalculation that flips the direction cancels the
//! change. `spec.behavior` (stabilization windows, rate policies, `selectPolicy`) is honoured with
//! the upstream defaults. Recommendations and scale events are kept in memory and persisted in
//! `status.krHistory` (a kr extension), so the stabilization windows survive a restart.
//! Events: `SuccessfulRescale` and warnings for failures.

use crate::util::*;
use crate::Config;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_apiserver::client::{Client, Result};
use kr_fmt::json::Value;

const TOLERANCE: f64 = 0.1;
const DEFAULT_UTILIZATION: i64 = 80;
const DEFAULT_DOWN_WINDOW: i64 = 300;
/// History older than this (the longest policy period upstream allows is 1800 s) is dropped.
const KEEP_SECS: i64 = 1900;
/// A pod is within its CPU initialization period for this long after it started.
const CPU_INIT_PERIOD: i64 = 300;
/// A pod that never became ready within this long of starting is "never ready".
const INITIAL_READINESS_DELAY: i64 = 30;

// ---- the replica calculator (pure) ----

/// One pod as the calculator sees it. Units: millicores for CPU, bytes for memory, milli-units
/// for custom metrics. `usage: None` is a pod without a metric ("missing"); a pod with a metric
/// that is not `ready` has its sample ignored.
#[derive(Clone, Debug, PartialEq)]
pub struct PodUsage {
    pub ready: bool,
    pub usage: Option<i64>,
    pub request: i64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Target {
    /// Percent of the requests.
    Utilization(i64),
    /// Per pod, in the metric's unit.
    AverageValue(i64),
}

fn ratio(target: Target, usage: &[(i64, i64)]) -> (f64, i64) {
    // `usage` = (usage, request) per pod.
    match target {
        Target::Utilization(t) => {
            let (u, r): (i64, i64) = usage.iter().fold((0, 0), |a, p| (a.0 + p.0, a.1 + p.1));
            let util = if r == 0 { 0 } else { u * 100 / r };
            (util as f64 / t as f64, util)
        }
        Target::AverageValue(t) => {
            let avg = if usage.is_empty() { 0 } else { usage.iter().map(|p| p.0).sum::<i64>() / usage.len() as i64 };
            (avg as f64 / t as f64, avg)
        }
    }
}

fn ceil(x: f64) -> i64 {
    let t = x as i64;
    if x > t as f64 { t + 1 } else { t }
}

/// The replica count one per-pod metric asks for, and the current utilization (percent) or
/// average value.
pub fn resource_replicas(current: i64, target: Target, pods: &[PodUsage]) -> core::result::Result<(i64, i64), &'static str> {
    let ready: Vec<&PodUsage> = pods.iter().filter(|p| p.ready && p.usage.is_some()).collect();
    let unready: Vec<&PodUsage> = pods.iter().filter(|p| !p.ready && p.usage.is_some()).collect();
    let missing: Vec<&PodUsage> = pods.iter().filter(|p| p.usage.is_none()).collect();
    if ready.is_empty() {
        return Err("did not receive metrics for any ready pods");
    }
    let mut metrics: Vec<(i64, i64)> = ready.iter().map(|p| (p.usage.unwrap_or(0), p.request)).collect();
    let (usage_ratio, current_value) = ratio(target, &metrics);
    let rebalance_unready = !unready.is_empty() && usage_ratio > 1.0;
    if !rebalance_unready && missing.is_empty() {
        if (1.0 - usage_ratio).abs() <= TOLERANCE {
            return Ok((current, current_value));
        }
        return Ok((ceil(usage_ratio * metrics.len() as f64), current_value));
    }
    // Pods without metrics: 100% of their request (or the target value) when the load is falling,
    // 0 when it is rising; pods that are not ready yet count as 0 when scaling up.
    for p in &missing {
        let assumed = if usage_ratio < 1.0 {
            match target {
                Target::Utilization(_) => p.request,
                Target::AverageValue(v) => v,
            }
        } else {
            0
        };
        metrics.push((assumed, p.request));
    }
    if rebalance_unready {
        for p in &unready {
            metrics.push((0, p.request));
        }
    }
    let (new_ratio, _) = ratio(target, &metrics);
    if (1.0 - new_ratio).abs() <= TOLERANCE || (usage_ratio > 1.0 && new_ratio < 1.0) || (usage_ratio < 1.0 && new_ratio > 1.0) {
        return Ok((current, current_value));
    }
    Ok((ceil(new_ratio * metrics.len() as f64), current_value))
}

/// Upstream's `getUsageRatioReplicaCount`: a ratio against the ready pods (an Object or External
/// metric with a `Value` target). From zero replicas it asks for `ceil(ratio)`.
pub fn usage_ratio_replicas(current: i64, usage_ratio: f64, ready_pods: i64) -> i64 {
    if current != 0 {
        if (1.0 - usage_ratio).abs() <= TOLERANCE {
            return current;
        }
        return ceil(usage_ratio * ready_pods as f64);
    }
    ceil(usage_ratio)
}

/// An Object or External metric with an `AverageValue` target: the metric is a total, the target
/// is per pod. Returns the replicas and the current per-pod value.
pub fn per_pod_replicas(status_replicas: i64, value: i64, target_average: i64) -> (i64, i64) {
    let n = status_replicas.max(1);
    let r = value as f64 / (target_average as f64 * n as f64);
    let replicas = if (1.0 - r).abs() > TOLERANCE { ceil(value as f64 / target_average as f64) } else { status_replicas };
    (replicas, ceil(value as f64 / n as f64))
}

/// Upstream's rule for discarding the CPU sample of a pod: during the 5 minutes after it started
/// a sample taken before one metric window had passed since the last readiness change, or of a
/// pod that is not ready, is ignored; later only a pod that never became ready is.
pub fn cpu_unready(pending: bool, ready_cond: Option<(bool, i64)>, start: Option<i64>, metric_ts: i64, window: i64, now: i64) -> bool {
    if pending {
        return true;
    }
    let (Some((ready, transition)), Some(start)) = (ready_cond, start) else { return true };
    if start + CPU_INIT_PERIOD > now {
        !ready || metric_ts < transition + window
    } else {
        !ready && start + INITIAL_READINESS_DELAY > transition
    }
}

// ---- behavior: stabilization and rate limits (pure) ----

#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    /// "Pods" or "Percent".
    pub kind: String,
    pub value: i64,
    pub period: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Rules {
    pub window: i64,
    /// "Max", "Min" or "Disabled".
    pub select: String,
    pub policies: Vec<Policy>,
}

fn rules_of(behavior: Option<&Value>, which: &str, up: bool) -> Rules {
    let r = behavior.and_then(|b| b.get(which));
    let window = r.and_then(|r| r.get("stabilizationWindowSeconds")).and_then(Value::as_i64).unwrap_or(if up { 0 } else { DEFAULT_DOWN_WINDOW });
    let select = r.and_then(|r| r.get("selectPolicy")).and_then(Value::as_str).unwrap_or("Max").to_string();
    let mut policies: Vec<Policy> = r
        .and_then(|r| r.get("policies"))
        .and_then(Value::as_array)
        .map(|a| a.iter().map(|p| Policy { kind: p.get("type").and_then(Value::as_str).unwrap_or("Pods").to_string(), value: p.get("value").and_then(Value::as_i64).unwrap_or(0), period: p.get("periodSeconds").and_then(Value::as_i64).unwrap_or(15) }).collect())
        .unwrap_or_default();
    if policies.is_empty() {
        policies = if up {
            alloc::vec![Policy { kind: "Pods".into(), value: 4, period: 15 }, Policy { kind: "Percent".into(), value: 100, period: 15 }]
        } else {
            alloc::vec![Policy { kind: "Percent".into(), value: 100, period: 15 }]
        };
    }
    Rules { window, select, policies }
}

/// Recommendation history and scale events of one HPA.
#[derive(Default, Debug, PartialEq)]
pub struct History {
    /// (time, recommended replicas before normalisation)
    recs: Vec<(i64, i64)>,
    /// (time, replicas added (>0) or removed (<0))
    events: Vec<(i64, i64)>,
}

impl History {
    fn prune(&mut self, now: i64) {
        self.recs.retain(|r| now - r.0 <= KEEP_SECS);
        self.events.retain(|e| now - e.0 <= KEEP_SECS);
    }

    /// The history a previous run stored in `status.krHistory` (empty if there is none).
    pub fn from_status(hpa: &Value) -> History {
        let Some(h) = hpa.pointer(&["status", "krHistory"]).and_then(Value::as_str).and_then(|s| kr_fmt::json::parse_str(s).ok()) else { return History::default() };
        let pairs = |k: &str| -> Vec<(i64, i64)> { h.get(k).and_then(Value::as_array).map(|a| a.iter().filter_map(|p| Some((p.as_array()?.first()?.as_i64()?, p.as_array()?.get(1)?.as_i64()?))).collect()).unwrap_or_default() };
        History { recs: pairs("recs"), events: pairs("events") }
    }

    /// The compact JSON text stored in `status.krHistory`.
    pub fn to_status(&self) -> String {
        let pairs = |v: &[(i64, i64)]| v.iter().map(|(a, b)| format!("[{a},{b}]")).collect::<Vec<_>>().join(",");
        format!("{{\"recs\":[{}],\"events\":[{}]}}", pairs(&self.recs), pairs(&self.events))
    }
}

/// Upstream's `stabilizeRecommendationWithBehaviors`: no scale-down below the highest
/// recommendation of the down window, no scale-up above the lowest of the up window.
pub fn stabilize(current: i64, desired: i64, recs: &[(i64, i64)], now: i64, up_window: i64, down_window: i64) -> i64 {
    let (mut up, mut down) = (desired, desired);
    for &(t, r) in recs {
        if t > now - up_window {
            up = up.min(r);
        }
        if t > now - down_window {
            down = down.max(r);
        }
    }
    let mut rec = current;
    if rec < up {
        rec = up;
    }
    if rec > down {
        rec = down;
    }
    rec
}

fn change_in(period: i64, events: &[(i64, i64)], now: i64, up: bool) -> i64 {
    events.iter().filter(|e| now - e.0 <= period && (e.1 > 0) == up).map(|e| e.1.abs()).sum()
}

/// How many replicas the rules allow at most (up) or at least (down), given what already changed.
pub fn rate_limit(current: i64, rules: &Rules, events: &[(i64, i64)], now: i64, up: bool) -> i64 {
    if rules.select == "Disabled" {
        return current;
    }
    let mut limit: Option<i64> = None;
    for p in &rules.policies {
        let added = change_in(p.period, events, now, true);
        let removed = change_in(p.period, events, now, false);
        let start = current - added + removed;
        let proposed = if up {
            match p.kind.as_str() {
                "Percent" => ceil(start as f64 * (1.0 + p.value as f64 / 100.0)),
                _ => start + p.value,
            }
        } else {
            match p.kind.as_str() {
                "Percent" => ceil(start as f64 * (1.0 - p.value as f64 / 100.0)),
                _ => start - p.value,
            }
        };
        // "Max" picks the policy that allows the biggest change.
        limit = Some(match (limit, up, rules.select.as_str()) {
            (None, ..) => proposed,
            (Some(l), true, "Min") | (Some(l), false, "Max") => l.min(proposed),
            (Some(l), true, _) | (Some(l), false, _) => l.max(proposed),
        });
    }
    limit.unwrap_or(current)
}

/// Stabilisation, rate limits and `minReplicas`/`maxReplicas` applied to a recommendation.
pub fn normalize(current: i64, desired: i64, min: i64, max: i64, behavior: Option<&Value>, h: &mut History, now: i64) -> i64 {
    let up = rules_of(behavior, "scaleUp", true);
    let down = rules_of(behavior, "scaleDown", false);
    h.recs.push((now, desired));
    let stable = stabilize(current, desired, &h.recs, now, up.window, down.window);
    let mut result = stable;
    if stable > current {
        result = stable.min(rate_limit(current, &up, &h.events, now, true).max(current));
    } else if stable < current {
        result = stable.max(rate_limit(current, &down, &h.events, now, false).min(current));
    }
    result = result.clamp(min, max.max(min));
    h.prune(now);
    result
}

// ---- metric specs ----

/// A metric of `spec.metrics` this controller can evaluate.
#[derive(Debug, PartialEq)]
pub enum Metric {
    Resource { name: String, container: Option<String>, target: Target },
    Pods { name: String, selector: String, average: i64 },
    Object { api_version: String, kind: String, object: String, name: String, selector: String, target: ObjectTarget },
    External { name: String, selector: String, target: ObjectTarget },
}

/// `Value` or `AverageValue` of an Object or External metric, in milli-units.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ObjectTarget {
    Value(i64),
    Average(i64),
}

/// A resource quantity in millicores (cpu) or bytes (memory).
fn qty(name: &str, s: &str) -> Option<i64> {
    let q = kr_fmt::quantity::Quantity::parse(s).ok()?;
    let v = if name == "cpu" { q.milli_value()? } else { q.value()? };
    i64::try_from(v).ok()
}

/// A custom metric quantity in milli-units.
fn milli(s: &str) -> Option<i64> {
    i64::try_from(kr_fmt::quantity::Quantity::parse(s).ok()?.milli_value()?).ok()
}

/// Milli-units as a quantity string (`1500` -> `1500m`, `2000` -> `2`).
fn fmt_milli(m: i64) -> String {
    if m % 1000 == 0 { (m / 1000).to_string() } else { format!("{m}m") }
}

fn object_target(t: &Value) -> Option<ObjectTarget> {
    match t.get("type").and_then(Value::as_str)? {
        "Value" => Some(ObjectTarget::Value(milli(t.get("value").and_then(Value::as_str)?)?)),
        "AverageValue" => Some(ObjectTarget::Average(milli(t.get("averageValue").and_then(Value::as_str)?)?)),
        _ => None,
    }
}

pub fn metric_spec(m: &Value) -> Option<Metric> {
    let ty = m.get("type").and_then(Value::as_str)?;
    let metric_name = |b: &Value| b.pointer(&["metric", "name"]).and_then(Value::as_str).map(String::from);
    let metric_sel = |b: &Value| b.pointer(&["metric", "selector"]).map(selector_string).unwrap_or_default();
    match ty {
        "Resource" | "ContainerResource" => {
            let body = m.get(if ty == "Resource" { "resource" } else { "containerResource" })?;
            let name = body.get("name").and_then(Value::as_str)?.to_string();
            let container = (ty == "ContainerResource").then(|| body.get("container").and_then(Value::as_str).unwrap_or("").to_string());
            let t = body.get("target")?;
            let target = match t.get("type").and_then(Value::as_str)? {
                "Utilization" => Target::Utilization(t.get("averageUtilization").and_then(Value::as_i64)?),
                "AverageValue" => Target::AverageValue(qty(&name, t.get("averageValue").and_then(Value::as_str)?)?),
                _ => return None,
            };
            Some(Metric::Resource { name, container, target })
        }
        "Pods" => {
            let b = m.get("pods")?;
            let t = b.get("target")?;
            if t.get("type").and_then(Value::as_str) != Some("AverageValue") {
                return None;
            }
            Some(Metric::Pods { name: metric_name(b)?, selector: metric_sel(b), average: milli(t.get("averageValue").and_then(Value::as_str)?)? })
        }
        "Object" => {
            let b = m.get("object")?;
            let d = b.get("describedObject")?;
            Some(Metric::Object {
                api_version: d.get("apiVersion").and_then(Value::as_str).unwrap_or("v1").to_string(),
                kind: d.get("kind").and_then(Value::as_str)?.to_string(),
                object: d.get("name").and_then(Value::as_str)?.to_string(),
                name: metric_name(b)?,
                selector: metric_sel(b),
                target: object_target(b.get("target")?)?,
            })
        }
        "External" => {
            let b = m.get("external")?;
            Some(Metric::External { name: metric_name(b)?, selector: metric_sel(b), target: object_target(b.get("target")?)? })
        }
        _ => None,
    }
}

fn plural_of(kind: &str) -> String {
    let k = kind.to_ascii_lowercase();
    if k.ends_with('s') {
        format!("{k}es")
    } else if let Some(stem) = k.strip_suffix('y').filter(|s| !s.ends_with(['a', 'e', 'i', 'o', 'u'])) {
        format!("{stem}ies")
    } else {
        format!("{k}s")
    }
}

fn target_path(r: &Value, ns: &str) -> Option<String> {
    let kind = r.get("kind").and_then(Value::as_str)?;
    let name = r.get("name").and_then(Value::as_str)?;
    let av = r.get("apiVersion").and_then(Value::as_str).unwrap_or("apps/v1");
    let (group, version) = av.rsplit_once('/').unwrap_or(("", av));
    let plural = match kind {
        "Deployment" => "deployments".to_string(),
        "StatefulSet" => "statefulsets".to_string(),
        "ReplicaSet" => "replicasets".to_string(),
        "ReplicationController" => "replicationcontrollers".to_string(),
        k => plural_of(k),
    };
    Some(format!("{}/{name}", api_path(group, version, Some(ns), &plural)))
}

// ---- reading the cluster ----

fn pod_requests(p: &Value, res: &str, container: Option<&str>) -> core::result::Result<i64, String> {
    let mut sum = 0;
    for c in p.pointer(&["spec", "containers"]).and_then(Value::as_array).unwrap_or(&[]) {
        let cname = c.get("name").and_then(Value::as_str).unwrap_or("");
        if container.is_some_and(|w| w != cname) {
            continue;
        }
        match c.pointer(&["resources", "requests", res]).and_then(Value::as_str).and_then(|s| qty(res, s)) {
            Some(v) => sum += v,
            None => return Err(format!("missing request for {res} in container {cname} of Pod {}", name(p))),
        }
    }
    Ok(sum)
}

/// A pod's sample from `metrics.k8s.io`: usage, time of the sample and its window (seconds).
struct Sample {
    usage: i64,
    ts: i64,
    window: i64,
}

async fn pod_metrics<C: Client>(c: &C, ns: &str, selector: &str, res: &str, container: Option<&str>) -> Result<BTreeMap<String, Sample>> {
    let q = if selector.is_empty() { String::new() } else { format!("labelSelector={}", enc(selector)) };
    let list = c.list(&format!("/apis/metrics.k8s.io/v1beta1/namespaces/{ns}/pods"), &q).await?;
    let mut out = BTreeMap::new();
    for it in items(&list) {
        let mut sum = 0;
        let mut any = false;
        for ct in it.get("containers").and_then(Value::as_array).unwrap_or(&[]) {
            if container.is_some_and(|w| ct.get("name").and_then(Value::as_str) != Some(w)) {
                continue;
            }
            if let Some(v) = ct.pointer(&["usage", res]).and_then(Value::as_str).and_then(|s| qty(res, s)) {
                sum += v;
                any = true;
            }
        }
        if any {
            let ts = it.get("timestamp").and_then(Value::as_str).and_then(parse_time).unwrap_or(0);
            let window = it.get("window").and_then(Value::as_str).and_then(|w| kr_fmt::quantity::parse_duration(w).ok()).map_or(0, |ns| ns / 1_000_000_000);
            out.insert(name(&it).to_string(), Sample { usage: sum, ts, window });
        }
    }
    Ok(out)
}

fn value_of(item: &Value) -> Option<i64> {
    milli(item.get("value").and_then(Value::as_str)?)
}

/// `custom.metrics.k8s.io` values of a metric for each pod matching `selector`.
async fn custom_pod_values<C: Client>(c: &C, ns: &str, metric: &str, selector: &str, metric_selector: &str) -> Result<BTreeMap<String, i64>> {
    let mut q = String::new();
    if !selector.is_empty() {
        q = format!("labelSelector={}", enc(selector));
    }
    if !metric_selector.is_empty() {
        q = format!("{q}{}metricLabelSelector={}", if q.is_empty() { "" } else { "&" }, enc(metric_selector));
    }
    let list = c.list(&format!("/apis/custom.metrics.k8s.io/v1beta1/namespaces/{ns}/pods/*/{metric}"), &q).await?;
    Ok(items(&list).iter().filter_map(|i| Some((i.pointer(&["describedObject", "name"]).and_then(Value::as_str)?.to_string(), value_of(i)?))).collect())
}

async fn object_value<C: Client>(c: &C, ns: &str, api_version: &str, kind: &str, object: &str, metric: &str, metric_selector: &str) -> Result<i64> {
    let group = api_version.rsplit_once('/').map_or("", |g| g.0);
    let resource = if group.is_empty() { plural_of(kind) } else { format!("{}.{group}", plural_of(kind)) };
    let q = if metric_selector.is_empty() { String::new() } else { format!("metricLabelSelector={}", enc(metric_selector)) };
    let v = c.get(&format!("/apis/custom.metrics.k8s.io/v1beta1/namespaces/{ns}/{resource}/{object}/{metric}{}", if q.is_empty() { String::new() } else { format!("?{q}") })).await?;
    // The adapter answers with a MetricValueList of one item (some with the item itself).
    let item = items(&v).into_iter().next().unwrap_or(v);
    value_of(&item).ok_or_else(|| kr_apiserver::object::ApiError::new(502, "BadGateway", "the metrics adapter returned no value"))
}

async fn external_values<C: Client>(c: &C, ns: &str, metric: &str, selector: &str) -> Result<Vec<i64>> {
    let q = if selector.is_empty() { String::new() } else { format!("labelSelector={}", enc(selector)) };
    let list = c.list(&format!("/apis/external.metrics.k8s.io/v1beta1/namespaces/{ns}/{metric}"), &q).await?;
    Ok(items(&list).iter().filter_map(value_of).collect())
}

fn condition(ty: &str, status: bool, reason: &str, message: &str, now: i64) -> Value {
    obj(alloc::vec![
        ("type", Value::from(ty)),
        ("status", Value::from(if status { "True" } else { "False" })),
        ("reason", Value::from(reason)),
        ("message", Value::from(message)),
        ("lastTransitionTime", Value::String(kr_apiserver::object::rfc3339(now))),
    ])
}

/// Keeps `lastTransitionTime` of a condition whose status did not change.
fn keep_transition(new: &mut [Value], old: &[Value]) {
    for n in new.iter_mut() {
        if let Some(o) = old.iter().find(|o| o.get("type") == n.get("type") && o.get("status") == n.get("status")) {
            if let Some(t) = o.get("lastTransitionTime") {
                n.set("lastTransitionTime", t.clone());
            }
        }
    }
}

async fn emit_event<C: Client>(c: &C, hpa: &Value, now: i64, ty: &str, reason: &str, msg: &str) {
    let ns = namespace(hpa);
    let t = Value::String(kr_apiserver::object::rfc3339(now));
    let ev = obj(alloc::vec![
        ("apiVersion", Value::from("v1")),
        ("kind", Value::from("Event")),
        ("metadata", obj(alloc::vec![("generateName", Value::String(format!("{}.", name(hpa)))), ("namespace", Value::from(ns))])),
        ("involvedObject", obj(alloc::vec![("apiVersion", Value::from("autoscaling/v2")), ("kind", Value::from("HorizontalPodAutoscaler")), ("namespace", Value::from(ns)), ("name", Value::from(name(hpa))), ("uid", Value::from(uid(hpa)))])),
        ("type", Value::from(ty)),
        ("reason", Value::from(reason)),
        ("message", Value::from(msg)),
        ("source", obj(alloc::vec![("component", Value::from("horizontal-pod-autoscaler"))])),
        ("reportingComponent", Value::from("horizontal-pod-autoscaler")),
        ("firstTimestamp", t.clone()),
        ("lastTimestamp", t),
        ("count", num(1)),
    ]);
    let _ = c.create(&format!("/api/v1/namespaces/{ns}/events"), &ev).await;
}

/// What one metric produced.
struct Computed {
    replicas: i64,
    /// The `currentMetrics` entry.
    status: Value,
    /// "cpu resource utilization (percentage of request)", used in messages.
    label: String,
    /// CPU utilization percent, for autoscaling/v1 status.
    cpu_pct: Option<i64>,
}

struct Failure {
    reason: &'static str,
    message: String,
}

fn fail(reason: &'static str, what: &str, e: &str) -> Failure {
    Failure { reason, message: format!("the HPA was unable to compute the replica count: {what}: {e}") }
}

/// Evaluates one metric against the pods of the target.
async fn compute<C: Client>(c: &C, m: &Metric, ns: &str, selector: &str, current: i64, live: &[Value], now: i64) -> core::result::Result<Computed, Failure> {
    let ready_count = live.iter().filter(|p| str_at(p, &["status", "phase"]) != "Pending" && pod_ready(p)).count() as i64;
    match m {
        Metric::Resource { name: res, container, target } => {
            let label = if matches!(target, Target::Utilization(_)) { format!("{res} resource utilization (percentage of request)") } else { format!("{res} resource") };
            let usage = pod_metrics(c, ns, selector, res, container.as_deref()).await.map_err(|e| fail("FailedGetResourceMetric", &format!("unable to get metrics for resource {res}"), &e.message))?;
            let mut input = Vec::new();
            for p in live {
                let request = match pod_requests(p, res, container.as_deref()) {
                    Ok(r) => r,
                    Err(msg) if matches!(target, Target::Utilization(_)) => return Err(fail("FailedGetResourceMetric", &format!("failed to get {label}"), &msg)),
                    Err(_) => 0,
                };
                let sample = usage.get(name(p));
                let pending = str_at(p, &["status", "phase"]) == "Pending";
                let ready = if res == "cpu" {
                    let cond = p.pointer(&["status", "conditions"]).and_then(Value::as_array).and_then(|a| a.iter().find(|x| str_at(x, &["type"]) == "Ready")).map(|x| (str_at(x, &["status"]) == "True", parse_time(str_at(x, &["lastTransitionTime"])).unwrap_or(0)));
                    let start = p.pointer(&["status", "startTime"]).and_then(Value::as_str).and_then(parse_time);
                    let (ts, window) = sample.map_or((0, 0), |s| (s.ts, s.window));
                    !cpu_unready(pending, cond, start, ts, window, now)
                } else {
                    !pending
                };
                input.push(PodUsage { ready, usage: sample.map(|s| s.usage), request });
            }
            let (replicas, value) = resource_replicas(current, *target, &input).map_err(|e| fail("FailedGetResourceMetric", &format!("failed to get {label}"), e))?;
            let (cur, cpu_pct) = match target {
                Target::Utilization(_) => (obj(alloc::vec![("averageUtilization", num(value))]), (res == "cpu").then_some(value)),
                Target::AverageValue(_) => (obj(alloc::vec![("averageValue", Value::String(if res == "cpu" { format!("{value}m") } else { value.to_string() }))]), None),
            };
            let (ty, key) = if container.is_some() { ("ContainerResource", "containerResource") } else { ("Resource", "resource") };
            let mut body = alloc::vec![("name", Value::from(res.as_str())), ("current", cur)];
            if let Some(cn) = container {
                body.push(("container", Value::from(cn.as_str())));
            }
            Ok(Computed { replicas, status: obj(alloc::vec![("type", Value::from(ty)), (key, obj(body))]), label, cpu_pct })
        }
        Metric::Pods { name: metric, selector: msel, average } => {
            let label = format!("{metric} pods metric");
            let values = custom_pod_values(c, ns, metric, selector, msel).await.map_err(|e| fail("FailedGetPodsMetric", &format!("unable to get metric {metric}"), &e.message))?;
            let input: Vec<PodUsage> = live.iter().map(|p| PodUsage { ready: str_at(p, &["status", "phase"]) != "Pending", usage: values.get(name(p)).copied(), request: 0 }).collect();
            let (replicas, value) = resource_replicas(current, Target::AverageValue(*average), &input).map_err(|e| fail("FailedGetPodsMetric", &format!("failed to get {label}"), e))?;
            let status = obj(alloc::vec![("type", Value::from("Pods")), ("pods", obj(alloc::vec![("metric", obj(alloc::vec![("name", Value::from(metric.as_str()))])), ("current", obj(alloc::vec![("averageValue", Value::String(fmt_milli(value)))]))]))]);
            Ok(Computed { replicas, status, label, cpu_pct: None })
        }
        Metric::Object { api_version, kind, object, name: metric, selector: msel, target } => {
            let label = format!("{metric} object metric");
            let value = object_value(c, ns, api_version, kind, object, metric, msel).await.map_err(|e| fail("FailedGetObjectMetric", &format!("unable to get metric {metric}"), &e.message))?;
            let (replicas, cur) = match target {
                ObjectTarget::Value(t) => (usage_ratio_replicas(current, value as f64 / *t as f64, ready_count), obj(alloc::vec![("value", Value::String(fmt_milli(value)))])),
                ObjectTarget::Average(t) => {
                    let (r, per_pod) = per_pod_replicas(current, value, *t);
                    (r, obj(alloc::vec![("averageValue", Value::String(fmt_milli(per_pod)))]))
                }
            };
            let described = obj(alloc::vec![("apiVersion", Value::from(api_version.as_str())), ("kind", Value::from(kind.as_str())), ("name", Value::from(object.as_str()))]);
            let status = obj(alloc::vec![("type", Value::from("Object")), ("object", obj(alloc::vec![("metric", obj(alloc::vec![("name", Value::from(metric.as_str()))])), ("describedObject", described), ("current", cur)]))]);
            Ok(Computed { replicas, status, label, cpu_pct: None })
        }
        Metric::External { name: metric, selector: msel, target } => {
            let label = format!("{metric} external metric");
            let values = external_values(c, ns, metric, msel).await.map_err(|e| fail("FailedGetExternalMetric", &format!("unable to get external metric {metric}"), &e.message))?;
            if values.is_empty() {
                return Err(fail("FailedGetExternalMetric", &format!("unable to get external metric {metric}"), "no metrics returned from the external metrics API"));
            }
            let total: i64 = values.iter().sum();
            let (replicas, cur) = match target {
                ObjectTarget::Value(t) => (usage_ratio_replicas(current, total as f64 / *t as f64, ready_count), obj(alloc::vec![("value", Value::String(fmt_milli(total)))])),
                ObjectTarget::Average(t) => {
                    let (r, per_pod) = per_pod_replicas(current, total, *t);
                    (r, obj(alloc::vec![("averageValue", Value::String(fmt_milli(per_pod)))]))
                }
            };
            let status = obj(alloc::vec![("type", Value::from("External")), ("external", obj(alloc::vec![("metric", obj(alloc::vec![("name", Value::from(metric.as_str()))])), ("current", cur)]))]);
            Ok(Computed { replicas, status, label, cpu_pct: None })
        }
    }
}

// ---- one HPA ----

async fn reconcile<C: Client>(c: &C, hpa: &Value, now: i64, hist: &mut History) -> Result<()> {
    let ns = namespace(hpa).to_string();
    let hname = name(hpa).to_string();
    let spec = hpa.get("spec").cloned().unwrap_or(Value::Null);
    let old_status = hpa.get("status").cloned().unwrap_or(Value::Null);
    let old_conds: Vec<Value> = old_status.get("conditions").and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
    let old_msg = |ty: &str| old_conds.iter().find(|o| str_at(o, &["type"]) == ty).map(|o| str_at(o, &["message"]).to_string()).unwrap_or_default();
    let generation = hpa.pointer(&["metadata", "generation"]).and_then(Value::as_i64).unwrap_or(0);
    let min = spec.get("minReplicas").and_then(Value::as_i64).unwrap_or(1);
    let max = spec.get("maxReplicas").and_then(Value::as_i64).unwrap_or(1);

    let write = |conds: Vec<Value>, current: i64, desired: i64, metrics: Vec<Value>, cpu_pct: Option<i64>, scaled: bool, hist: &History| {
        let mut conds = conds;
        keep_transition(&mut conds, &old_conds);
        let mut st = alloc::vec![("observedGeneration", num(generation)), ("currentReplicas", num(current)), ("desiredReplicas", num(desired)), ("conditions", Value::Array(conds)), ("krHistory", Value::String(hist.to_status()))];
        if !metrics.is_empty() {
            st.push(("currentMetrics", Value::Array(metrics)));
        }
        if let Some(p) = cpu_pct {
            st.push(("currentCPUUtilizationPercentage", num(p)));
        }
        if scaled {
            st.push(("lastScaleTime", Value::String(kr_apiserver::object::rfc3339(now))));
        }
        obj(alloc::vec![("status", obj(st))])
    };

    // The scale target.
    let Some(tpath) = spec.get("scaleTargetRef").and_then(|r| target_path(r, &ns)) else { return Ok(()) };
    let scale = match c.get(&format!("{tpath}/scale")).await {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("the HPA controller was unable to get the target's current scale: {}", e.message);
            if old_msg("AbleToScale") != msg {
                emit_event(c, hpa, now, "Warning", "FailedGetScale", &msg).await;
            }
            let conds = alloc::vec![condition("AbleToScale", false, "FailedGetScale", &msg, now)];
            write_status(c, &ns, &hname, &write(conds, 0, 0, Vec::new(), None, false, hist)).await;
            return Ok(());
        }
    };
    let current = int_at(&scale, &["spec", "replicas"], 0);
    let selector = str_at(&scale, &["status", "selector"]).to_string();

    let mut conds = alloc::vec![condition("AbleToScale", true, "ReadyForNewScale", "recommended size matches current size", now)];
    let mut desired = current;
    let mut metrics_out: Vec<Value> = Vec::new();
    let mut cpu_pct = None;
    let mut active = true;
    let mut reason = String::new();

    if current == 0 && min != 0 {
        conds.push(condition("ScalingActive", false, "ScalingDisabled", "scaling is disabled since the replica count of the target is zero", now));
        active = false;
    } else if current > max {
        desired = max;
        reason = "Current number of replicas above Spec.MaxReplicas".into();
        conds.push(condition("ScalingActive", true, "ValidMetricFound", "the HPA was able to successfully calculate a replica count", now));
    } else if current < min {
        desired = min;
        reason = "Current number of replicas below Spec.MinReplicas".into();
        conds.push(condition("ScalingActive", true, "ValidMetricFound", "the HPA was able to successfully calculate a replica count", now));
    } else {
        // The declared metrics; v1 objects carry a CPU percentage instead.
        let mut specs: Vec<Value> = spec.get("metrics").and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
        if specs.is_empty() {
            let pct = spec.get("targetCPUUtilizationPercentage").and_then(Value::as_i64).unwrap_or(DEFAULT_UTILIZATION);
            specs.push(obj(alloc::vec![("type", Value::from("Resource")), ("resource", obj(alloc::vec![("name", Value::from("cpu")), ("target", obj(alloc::vec![("type", Value::from("Utilization")), ("averageUtilization", num(pct))]))]))]));
        }
        let pods_list = c.list(&pods(Some(&ns)), &if selector.is_empty() { String::new() } else { format!("labelSelector={}", enc(&selector)) }).await.map(|l| items(&l)).unwrap_or_default();
        let live: Vec<Value> = pods_list.into_iter().filter(|p| !deleting(p) && !pod_terminal(p)).collect();
        let mut best: Option<(i64, String)> = None;
        let mut failure: Option<Failure> = None;
        let mut invalid = 0;
        for m in &specs {
            let Some(metric) = metric_spec(m) else {
                invalid += 1;
                failure.get_or_insert(Failure { reason: "InvalidMetricSourceType", message: format!("the HPA was unable to compute the replica count: unsupported or invalid metric of type {}", m.get("type").and_then(Value::as_str).unwrap_or("")) });
                continue;
            };
            match compute(c, &metric, &ns, &selector, current, &live, now).await {
                Ok(r) => {
                    if best.as_ref().is_none_or(|b| r.replicas > b.0) {
                        best = Some((r.replicas, r.label.clone()));
                    }
                    if cpu_pct.is_none() {
                        cpu_pct = r.cpu_pct;
                    }
                    metrics_out.push(r.status);
                }
                Err(f) => {
                    invalid += 1;
                    failure = Some(f);
                }
            }
        }
        match best {
            Some((mut n, label)) => {
                // With a metric that could not be read, never scale down (upstream's rule).
                if invalid > 0 && n < current {
                    n = current;
                }
                desired = n;
                reason = if n > current { format!("{label} above target") } else { format!("{label} below target") };
                let mut msg = format!("the HPA was able to successfully calculate a replica count from {label}");
                if let Some(f) = &failure {
                    msg = format!("{msg}; another metric failed: {}", f.message);
                }
                conds.push(condition("ScalingActive", true, "ValidMetricFound", &msg, now));
            }
            None => {
                active = false;
                let f = failure.unwrap_or(Failure { reason: "InvalidMetricSourceType", message: "the HPA was unable to compute the replica count: no metric".into() });
                if old_msg("ScalingActive") != f.message {
                    emit_event(c, hpa, now, "Warning", f.reason, &f.message).await;
                }
                conds.push(condition("ScalingActive", false, f.reason, &f.message, now));
            }
        }
    }

    let mut scaled = false;
    let mut final_replicas = current;
    if active {
        final_replicas = normalize(current, desired, min, max, spec.get("behavior"), hist, now);
        let limited = if desired > max && final_replicas == max {
            Some(("TooManyReplicas", "the desired replica count is more than the maximum replica count"))
        } else if desired < min && final_replicas == min {
            Some(("TooFewReplicas", "the desired replica count is less than the minimum replica count"))
        } else {
            None
        };
        conds.push(match limited {
            Some((r, m)) => condition("ScalingLimited", true, r, m, now),
            None => condition("ScalingLimited", false, "DesiredWithinRange", "the desired count is within the acceptable range", now),
        });
        if final_replicas != current {
            let body = obj(alloc::vec![("spec", obj(alloc::vec![("replicas", num(final_replicas))]))]);
            match c.patch(&format!("{tpath}/scale"), "application/merge-patch+json", &body).await {
                Ok(_) => {
                    scaled = true;
                    hist.events.push((now, final_replicas - current));
                    let msg = format!("the HPA controller was able to update the target scale to {final_replicas}");
                    conds[0] = condition("AbleToScale", true, "SucceededRescale", &msg, now);
                    emit_event(c, hpa, now, "Normal", "SuccessfulRescale", &format!("New size: {final_replicas}; reason: {reason}")).await;
                }
                Err(e) => {
                    let msg = format!("the HPA controller was unable to update the target scale: {}", e.message);
                    conds[0] = condition("AbleToScale", false, "FailedUpdateScale", &msg, now);
                    if old_msg("AbleToScale") != msg {
                        emit_event(c, hpa, now, "Warning", "FailedUpdateScale", &msg).await;
                    }
                    final_replicas = current;
                }
            }
        }
    }
    let st = write(conds, current, if active { final_replicas } else { current }, metrics_out, cpu_pct, scaled, hist);
    write_status(c, &ns, &hname, &st).await;
    Ok(())
}

/// Writes the status through the version the object was stored in: v2 first, and v1 when the
/// object was created as autoscaling/v1 (the API refuses a body of another version).
async fn write_status<C: Client>(c: &C, ns: &str, hname: &str, st: &Value) {
    for v in ["v2", "v1"] {
        let path = format!("/apis/autoscaling/{v}/namespaces/{ns}/horizontalpodautoscalers/{hname}/status");
        match c.patch(&path, "application/merge-patch+json", st).await {
            Ok(_) => return,
            Err(e) if e.code == 400 => continue,
            Err(_) => return,
        }
    }
}

pub async fn run<C: Client + Clone + 'static>(c: C, cfg: Config) {
    let mut hist: BTreeMap<String, History> = BTreeMap::new();
    loop {
        kr_rt::exec::sleep(cfg.hpa_ms).await;
        let now = (cfg.now)();
        let Ok(list) = c.list("/apis/autoscaling/v2/horizontalpodautoscalers", "").await else { continue };
        let all = items(&list);
        let keys: Vec<String> = all.iter().map(key_of).collect();
        hist.retain(|k, _| keys.contains(k));
        for h in &all {
            if deleting(h) {
                continue;
            }
            // After a restart the history comes from the object.
            let entry = hist.entry(key_of(h)).or_insert_with(|| History::from_status(h));
            let _ = reconcile(&c, h, now, entry).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pod with a sample.
    fn pod(ready: bool, usage: Option<i64>, request: i64) -> PodUsage {
        PodUsage { ready, usage, request }
    }

    #[test]
    fn utilization_scales_with_the_ratio_and_respects_the_tolerance() {
        let pods = alloc::vec![pod(true, Some(90), 100); 4];
        assert_eq!(resource_replicas(4, Target::Utilization(50), &pods), Ok((8, 90)));
        // Within 10% of the target: unchanged.
        let pods = alloc::vec![pod(true, Some(52), 100); 4];
        assert_eq!(resource_replicas(4, Target::Utilization(50), &pods), Ok((4, 52)));
        // Scale down: 10% against 50%: ceil(0.2 * 4) = 1.
        let pods = alloc::vec![pod(true, Some(10), 100); 4];
        assert_eq!(resource_replicas(4, Target::Utilization(50), &pods).unwrap().0, 1);
        // Average value target (millicores per pod).
        let pods = alloc::vec![pod(true, Some(300), 0); 2];
        assert_eq!(resource_replicas(2, Target::AverageValue(100), &pods).unwrap().0, 6);
        assert!(resource_replicas(2, Target::Utilization(50), &[pod(true, None, 100)]).is_err(), "no metrics at all");
    }

    #[test]
    fn missing_and_unready_pods_are_handled_conservatively() {
        // Rising load: a pod without metrics counts as 0%, a pod whose sample is ignored too.
        // Two pods at 200% would ask for double, but with the other two counted the load is the target.
        let pods = alloc::vec![pod(true, Some(200), 100), pod(true, Some(200), 100), pod(true, None, 100), pod(false, Some(500), 100)];
        assert_eq!(resource_replicas(4, Target::Utilization(100), &pods).unwrap().0, 4);
        // At 300% the four pods are at 150% of the target: 6.
        let pods = alloc::vec![pod(true, Some(300), 100), pod(true, Some(300), 100), pod(true, None, 100), pod(false, Some(500), 100)];
        assert_eq!(resource_replicas(4, Target::Utilization(100), &pods).unwrap().0, 6);
        // Falling load with a pod that has no metrics: it counts as 100%, which can cancel a scale down.
        let pods = alloc::vec![pod(true, Some(40), 100), pod(true, None, 100)];
        assert_eq!(resource_replicas(2, Target::Utilization(50), &pods).unwrap().0, 2, "assumed 100% flips the direction");
        // Unready pods are ignored when the load is falling.
        let pods = alloc::vec![pod(true, Some(10), 100), pod(true, Some(10), 100), pod(false, Some(900), 100)];
        assert_eq!(resource_replicas(3, Target::Utilization(50), &pods).unwrap().0, 1);
    }

    #[test]
    fn object_and_external_metrics() {
        // Value target: ratio of the metric to the target applied to the ready pods.
        assert_eq!(usage_ratio_replicas(4, 2.0, 4), 8);
        assert_eq!(usage_ratio_replicas(4, 1.05, 4), 4, "within the tolerance");
        assert_eq!(usage_ratio_replicas(4, 0.25, 3), 1, "ready pods, not the current count");
        assert_eq!(usage_ratio_replicas(0, 2.4, 0), 3, "from zero it follows the ratio");
        // AverageValue target: a total of 900 against 100 per pod needs 9, unless close enough.
        assert_eq!(per_pod_replicas(3, 900, 100), (9, 300));
        assert_eq!(per_pod_replicas(3, 310, 100), (3, 104), "within the tolerance of 3 pods");
        assert_eq!(per_pod_replicas(0, 250, 100), (3, 250), "from zero");
    }

    #[test]
    fn cpu_samples_of_starting_pods_are_discarded_like_upstream() {
        let now = 10_000;
        // Pending, or no Ready condition: ignored.
        assert!(cpu_unready(true, Some((true, 0)), Some(0), 0, 15, now));
        assert!(cpu_unready(false, None, Some(0), 0, 15, now));
        // Started 100 s ago (inside the 300 s period): a not-ready pod is ignored, a ready one
        // only if the sample predates one window after becoming ready.
        let start = now - 100;
        assert!(cpu_unready(false, Some((false, start + 10)), Some(start), now, 15, now));
        assert!(cpu_unready(false, Some((true, now - 5)), Some(start), now - 10, 15, now), "sample from before ready + window");
        assert!(!cpu_unready(false, Some((true, now - 60)), Some(start), now - 10, 15, now));
        // Started long ago: only a pod that never became ready (transition within 30 s of the start) is ignored.
        let old = now - 3600;
        assert!(!cpu_unready(false, Some((true, now - 5)), Some(old), now - 1, 15, now), "a recent readiness flip no longer matters");
        assert!(cpu_unready(false, Some((false, old + 10)), Some(old), now, 15, now), "never ready");
        assert!(!cpu_unready(false, Some((false, old + 600)), Some(old), now, 15, now), "became unready later: sample kept");
    }

    #[test]
    fn stabilization_holds_scale_downs_for_the_window() {
        let recs = alloc::vec![(940, 10), (1000, 3)];
        assert_eq!(stabilize(10, 3, &recs, 1000, 0, 300), 10, "the high recommendation of the last 300 s wins");
        assert_eq!(stabilize(10, 3, &recs, 1000, 0, 30), 3, "outside a 30 s window it does not");
        assert_eq!(stabilize(5, 9, &[(990, 6), (1000, 9)], 1000, 0, 300), 9);
        assert_eq!(stabilize(5, 9, &[(990, 6), (1000, 9)], 1000, 60, 300), 6);
    }

    #[test]
    fn rate_limits_default_to_plus_four_or_double_and_halve_per_period() {
        let up = rules_of(None, "scaleUp", true);
        let down = rules_of(None, "scaleDown", false);
        assert_eq!(rate_limit(2, &up, &[], 1000, true), 6, "the pods policy (+4) allows more than the percent one (x2): Max picks 6");
        assert_eq!(rate_limit(2, &down, &[], 1000, false), 0, "100% per period may remove everything");
        let min = Rules { select: "Min".into(), ..up };
        assert_eq!(rate_limit(2, &min, &[], 1000, true), 4, "Min picks the policy that allows the smaller change");
    }

    #[test]
    fn normalize_applies_window_limits_and_bounds() {
        let mut h = History::default();
        assert_eq!(normalize(1, 50, 1, 100, None, &mut h, 1000), 5);
        h.events.push((1000, 4));
        assert_eq!(normalize(5, 50, 1, 100, None, &mut h, 1005), 5, "already added 4 within the period: no more");
        assert_eq!(normalize(5, 50, 1, 100, None, &mut h, 1020), 10, "next period: +100% of 5");
        let mut h = History::default();
        assert_eq!(normalize(8, 8, 2, 20, None, &mut h, 2000), 8);
        assert_eq!(normalize(8, 2, 2, 20, None, &mut h, 2010), 8, "the recommendation 8 of 10 s ago holds it");
        assert_eq!(normalize(8, 2, 2, 20, None, &mut h, 2400), 2, "after the window it drops (100% per period allows it)");
        let mut h = History::default();
        assert_eq!(normalize(3, 0, 2, 20, None, &mut h, 3000), 2, "never below minReplicas");
        assert_eq!(normalize(3, 100, 2, 4, None, &mut h, 3001), 4);
        let b = kr_fmt::json::parse_str(r#"{"scaleUp":{"selectPolicy":"Disabled"},"scaleDown":{"stabilizationWindowSeconds":0,"policies":[{"type":"Pods","value":1,"periodSeconds":60}]}}"#).unwrap();
        let mut h = History::default();
        assert_eq!(normalize(5, 9, 1, 10, Some(&b), &mut h, 4000), 5);
        assert_eq!(normalize(5, 1, 1, 10, Some(&b), &mut h, 4001), 4);
    }

    #[test]
    fn history_survives_a_round_trip_through_the_status() {
        let mut h = History::default();
        normalize(8, 8, 2, 20, None, &mut h, 2000);
        h.events.push((1990, -3));
        let hpa = kr_fmt::json::parse_str(&format!(r#"{{"status":{{"krHistory":{}}}}}"#, kr_fmt::json::to_string(&Value::String(h.to_status())))).unwrap();
        let back = History::from_status(&hpa);
        assert_eq!(back, h);
        // So the 300 s window still holds a scale-down after a restart.
        let mut back = back;
        assert_eq!(normalize(8, 2, 2, 20, None, &mut back, 2100), 8);
        assert_eq!(History::from_status(&kr_fmt::json::parse_str("{}").unwrap()), History::default());
        assert_eq!(History::from_status(&kr_fmt::json::parse_str(r#"{"status":{"krHistory":"garbage"}}"#).unwrap()), History::default());
    }

    #[test]
    fn metric_specs_and_targets_are_read() {
        let p = |s: &str| metric_spec(&kr_fmt::json::parse_str(s).unwrap());
        assert_eq!(p(r#"{"type":"Resource","resource":{"name":"cpu","target":{"type":"Utilization","averageUtilization":60}}}"#), Some(Metric::Resource { name: "cpu".into(), container: None, target: Target::Utilization(60) }));
        assert_eq!(
            p(r#"{"type":"ContainerResource","containerResource":{"name":"memory","container":"app","target":{"type":"AverageValue","averageValue":"100Mi"}}}"#),
            Some(Metric::Resource { name: "memory".into(), container: Some("app".into()), target: Target::AverageValue(100 << 20) })
        );
        assert_eq!(
            p(r#"{"type":"Pods","pods":{"metric":{"name":"qps","selector":{"matchLabels":{"a":"b"}}},"target":{"type":"AverageValue","averageValue":"1500m"}}}"#),
            Some(Metric::Pods { name: "qps".into(), selector: "a=b".into(), average: 1500 })
        );
        assert_eq!(p(r#"{"type":"Pods","pods":{"metric":{"name":"qps"},"target":{"type":"Value","value":"1"}}}"#), None, "pods metrics are averages");
        assert_eq!(
            p(r#"{"type":"Object","object":{"metric":{"name":"rps"},"describedObject":{"apiVersion":"networking.k8s.io/v1","kind":"Ingress","name":"main"},"target":{"type":"Value","value":"10k"}}}"#),
            Some(Metric::Object { api_version: "networking.k8s.io/v1".into(), kind: "Ingress".into(), object: "main".into(), name: "rps".into(), selector: String::new(), target: ObjectTarget::Value(10_000_000) })
        );
        assert_eq!(
            p(r#"{"type":"External","external":{"metric":{"name":"queue"},"target":{"type":"AverageValue","averageValue":"30"}}}"#),
            Some(Metric::External { name: "queue".into(), selector: String::new(), target: ObjectTarget::Average(30_000) })
        );
        assert_eq!(p(r#"{"type":"Weird"}"#), None);
        let r = kr_fmt::json::parse_str(r#"{"kind":"Deployment","name":"web","apiVersion":"apps/v1"}"#).unwrap();
        assert_eq!(target_path(&r, "default").as_deref(), Some("/apis/apps/v1/namespaces/default/deployments/web"));
        assert_eq!(plural_of("Ingress"), "ingresses");
        assert_eq!(plural_of("Gateway"), "gateways");
        assert_eq!(plural_of("Policy"), "policies");
        assert_eq!(fmt_milli(2000), "2");
        assert_eq!(fmt_milli(1500), "1500m");
    }
}
