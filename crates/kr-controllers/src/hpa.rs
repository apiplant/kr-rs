//! The HorizontalPodAutoscaler controller (autoscaling/v2; v1 objects work too).
//!
//! Every [`Config::hpa_ms`] (default 15 s, as upstream) each HPA is evaluated: the replica count of
//! its scale target (read and written through the `/scale` subresource, so Deployments,
//! StatefulSets, ReplicaSets, ReplicationControllers and custom resources with a scale
//! subresource all work) is moved towards what the resource metrics ask for.
//!
//! Metrics: `Resource` and `ContainerResource` with `Utilization` (percent of the pods' requests)
//! or `AverageValue` targets, from `metrics.k8s.io` (the kubelet's cAdvisor-less scrape of the
//! API server). `Pods`, `Object` and `External` metrics need a custom metrics adapter, which kr
//! does not have; they are reported in the `ScalingActive` condition and skipped.
//!
//! The algorithm follows kube-controller-manager's replica calculator: tolerance 0.1; pods that
//! are not ready or have no metrics are assumed to use 0% when scaling up and 100% when scaling
//! down, and a recalculation that flips the direction cancels the change. `spec.behavior`
//! (stabilization windows, rate policies, `selectPolicy`) is honoured with the upstream defaults
//! (scale up: max of +4 pods or +100% per 15 s, no window; scale down: 100% per 15 s, 300 s
//! window). History (recommendations, scale events) is kept in memory: after a restart the
//! stabilization windows start empty.

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

// ---- the replica calculator (pure) ----

/// One pod as the calculator sees it. Units: millicores for CPU, bytes for memory.
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

/// The replica count one metric asks for, and the current utilization (percent) or average value.
pub fn resource_replicas(current: i64, target: Target, pods: &[PodUsage]) -> core::result::Result<(i64, i64), &'static str> {
    let ready: Vec<&PodUsage> = pods.iter().filter(|p| p.ready && p.usage.is_some()).collect();
    let unready = pods.iter().filter(|p| !p.ready).count();
    let missing: Vec<&PodUsage> = pods.iter().filter(|p| p.ready && p.usage.is_none()).collect();
    if ready.is_empty() {
        return Err("did not receive metrics for any ready pods");
    }
    let mut metrics: Vec<(i64, i64)> = ready.iter().map(|p| (p.usage.unwrap_or(0), p.request)).collect();
    let (usage_ratio, current_value) = ratio(target, &metrics);
    let rebalance_unready = unready > 0 && usage_ratio > 1.0;
    if !rebalance_unready && missing.is_empty() {
        if (1.0 - usage_ratio).abs() <= TOLERANCE {
            return Ok((current, current_value));
        }
        return Ok((ceil(usage_ratio * metrics.len() as f64), current_value));
    }
    // Pods without metrics: 100% of their request (or the target value) when the load is falling,
    // 0 when it is rising; pods that are not ready yet count as 0 when scaling up.
    if !missing.is_empty() {
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
    }
    if rebalance_unready {
        for p in pods.iter().filter(|p| !p.ready) {
            metrics.push((0, p.request));
        }
    }
    let (new_ratio, _) = ratio(target, &metrics);
    if (1.0 - new_ratio).abs() <= TOLERANCE || (usage_ratio > 1.0 && new_ratio < 1.0) || (usage_ratio < 1.0 && new_ratio > 1.0) {
        return Ok((current, current_value));
    }
    Ok((ceil(new_ratio * metrics.len() as f64), current_value))
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
#[derive(Default)]
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
#[allow(clippy::too_many_arguments)]
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

// ---- reading the cluster ----

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
        k => format!("{}s", k.to_ascii_lowercase()),
    };
    Some(format!("{}/{name}", api_path(group, version, Some(ns), &plural)))
}

/// A resource quantity in millicores (cpu) or bytes (memory).
fn qty(name: &str, s: &str) -> Option<i64> {
    let q = kr_fmt::quantity::Quantity::parse(s).ok()?;
    let v = if name == "cpu" { q.milli_value()? } else { q.value()? };
    i64::try_from(v).ok()
}

/// What one metric spec asks for: `(resource name, optional container, target)`.
fn metric_spec(m: &Value) -> Option<(String, Option<String>, Target)> {
    let ty = m.get("type").and_then(Value::as_str)?;
    let body = match ty {
        "Resource" => m.get("resource")?,
        "ContainerResource" => m.get("containerResource")?,
        _ => return None,
    };
    let name = body.get("name").and_then(Value::as_str)?.to_string();
    let container = (ty == "ContainerResource").then(|| body.get("container").and_then(Value::as_str).unwrap_or("").to_string());
    let t = body.get("target")?;
    let target = match t.get("type").and_then(Value::as_str)? {
        "Utilization" => Target::Utilization(t.get("averageUtilization").and_then(Value::as_i64)?),
        "AverageValue" => Target::AverageValue(qty(&name, t.get("averageValue").and_then(Value::as_str)?)?),
        _ => return None,
    };
    Some((name, container, target))
}

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

/// The metric for each pod: `(pod name, usage)` from `metrics.k8s.io`.
async fn pod_metrics<C: Client>(c: &C, ns: &str, selector: &str, res: &str, container: Option<&str>) -> Result<BTreeMap<String, i64>> {
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
            out.insert(name(&it).to_string(), sum);
        }
    }
    Ok(out)
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
fn keep_transition(new: &mut Vec<Value>, old: &[Value]) {
    for n in new.iter_mut() {
        if let Some(o) = old.iter().find(|o| o.get("type") == n.get("type") && o.get("status") == n.get("status")) {
            if let Some(t) = o.get("lastTransitionTime") {
                n.set("lastTransitionTime", t.clone());
            }
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
    let generation = hpa.pointer(&["metadata", "generation"]).and_then(Value::as_i64).unwrap_or(0);
    let min = spec.get("minReplicas").and_then(Value::as_i64).unwrap_or(1);
    let max = spec.get("maxReplicas").and_then(Value::as_i64).unwrap_or(1);

    let write = |conds: Vec<Value>, current: i64, desired: i64, metrics: Vec<Value>, cpu_pct: Option<i64>, scaled: bool| {
        let mut conds = conds;
        keep_transition(&mut conds, &old_conds);
        let mut st = alloc::vec![("observedGeneration", num(generation)), ("currentReplicas", num(current)), ("desiredReplicas", num(desired)), ("conditions", Value::Array(conds))];
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
            let conds = alloc::vec![condition("AbleToScale", false, "FailedGetScale", &format!("the HPA controller was unable to get the target's current scale: {}", e.message), now)];
            write_status(c, &ns, &hname, &write(conds, 0, 0, Vec::new(), None, false)).await;
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

    if current == 0 && min != 0 {
        conds.push(condition("ScalingActive", false, "ScalingDisabled", "scaling is disabled since the replica count of the target is zero", now));
        active = false;
    } else if current > max {
        desired = max;
        conds.push(condition("ScalingActive", true, "ValidMetricFound", "the HPA was able to successfully calculate a replica count", now));
    } else if current < min {
        desired = min;
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
        let mut best: Option<i64> = None;
        let mut failure: Option<(String, String)> = None;
        let mut skipped: Vec<String> = Vec::new();
        for m in &specs {
            let Some((res, container, target)) = metric_spec(m) else {
                skipped.push(m.get("type").and_then(Value::as_str).unwrap_or("").to_string());
                continue;
            };
            let label = if matches!(target, Target::Utilization(_)) { format!("{res} resource utilization (percentage of request)") } else { format!("{res} resource") };
            let usage = match pod_metrics(c, &ns, &selector, &res, container.as_deref()).await {
                Ok(u) => u,
                Err(e) => {
                    failure = Some(("FailedGetResourceMetric".into(), format!("the HPA was unable to compute the replica count: unable to get metrics for resource {res}: {}", e.message)));
                    continue;
                }
            };
            let mut input = Vec::new();
            let mut bad = None;
            for p in &live {
                let request = match pod_requests(p, &res, container.as_deref()) {
                    Ok(r) => r,
                    Err(msg) => {
                        bad = Some(msg);
                        break;
                    }
                };
                let unready = str_at(p, &["status", "phase"]) != "Running" || (res == "cpu" && !pod_ready(p));
                input.push(PodUsage { ready: !unready, usage: usage.get(name(p)).copied(), request });
            }
            if let Some(msg) = bad {
                if matches!(target, Target::Utilization(_)) {
                    failure = Some(("FailedGetResourceMetric".into(), format!("the HPA was unable to compute the replica count: failed to get {label} utilization: {msg}")));
                    continue;
                }
            }
            match resource_replicas(current, target, &input) {
                Ok((n, value)) => {
                    best = Some(best.map_or(n, |b| b.max(n)));
                    let cur = match target {
                        Target::Utilization(_) => {
                            if res == "cpu" && cpu_pct.is_none() {
                                cpu_pct = Some(value);
                            }
                            obj(alloc::vec![("averageUtilization", num(value))])
                        }
                        Target::AverageValue(_) => obj(alloc::vec![("averageValue", Value::String(if res == "cpu" { format!("{value}m") } else { value.to_string() }))]),
                    };
                    let (ty, key) = if container.is_some() { ("ContainerResource", "containerResource") } else { ("Resource", "resource") };
                    let mut body = alloc::vec![("name", Value::from(res.as_str())), ("current", cur)];
                    if let Some(cn) = &container {
                        body.push(("container", Value::from(cn.as_str())));
                    }
                    metrics_out.push(obj(alloc::vec![("type", Value::from(ty)), (key, obj(body))]));
                }
                Err(msg) => failure = Some(("FailedGetResourceMetric".into(), format!("the HPA was unable to compute the replica count: failed to get {label}: {msg}"))),
            }
        }
        match best {
            Some(n) => {
                desired = n;
                let mut msg = String::from("the HPA was able to successfully calculate a replica count from the resource metrics");
                if !skipped.is_empty() {
                    msg = format!("{msg}; metrics of type {} are not supported (no custom metrics adapter) and were ignored", skipped.join(", "));
                }
                conds.push(condition("ScalingActive", true, "ValidMetricFound", &msg, now));
            }
            None => {
                active = false;
                let (reason, msg) = failure.unwrap_or_else(|| ("InvalidMetricSourceType".into(), format!("the HPA was unable to compute the replica count: no supported metric (unsupported: {})", skipped.join(", "))));
                conds.push(condition("ScalingActive", false, &reason, &msg, now));
            }
        }
    }

    let mut scaled = false;
    let mut final_replicas = current;
    if active && !(current == 0 && min != 0) {
        final_replicas = normalize(current, desired, min, max, spec.get("behavior"), hist, now);
        let limited = if final_replicas == max && desired > max || (final_replicas == max && desired >= max) && desired != current {
            Some(("TooManyReplicas", "the desired replica count is more than the maximum replica count"))
        } else if final_replicas == min && desired < min {
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
                    conds[0] = condition("AbleToScale", true, "SucceededRescale", &format!("the HPA controller was able to update the target scale to {final_replicas}"), now);
                }
                Err(e) => {
                    conds[0] = condition("AbleToScale", false, "FailedUpdateScale", &format!("the HPA controller was unable to update the target scale: {}", e.message), now);
                    final_replicas = current;
                }
            }
        }
    }
    let st = write(conds, current, if active { final_replicas } else { current }, metrics_out, cpu_pct, scaled);
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
            let _ = reconcile(&c, h, now, hist.entry(key_of(h)).or_default()).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pod(ready: bool, usage: Option<i64>, request: i64) -> PodUsage {
        PodUsage { ready, usage, request }
    }

    #[test]
    fn utilization_scales_with_the_ratio_and_respects_the_tolerance() {
        // 3 pods at 200m of 100m requests... 4 pods using 90% of requests, target 50%: ratio 1.8.
        let pods = alloc::vec![pod(true, Some(90), 100); 4];
        assert_eq!(resource_replicas(4, Target::Utilization(50), &pods), Ok((8, 90)));
        // Within 10% of the target: unchanged.
        let pods = alloc::vec![pod(true, Some(52), 100); 4];
        assert_eq!(resource_replicas(4, Target::Utilization(50), &pods), Ok((4, 52)));
        // Scale down: 10% against 50% -> 1 replica of 4... ceil(0.2 * 4) = 1.
        let pods = alloc::vec![pod(true, Some(10), 100); 4];
        assert_eq!(resource_replicas(4, Target::Utilization(50), &pods).unwrap().0, 1);
        // Average value target (millicores per pod).
        let pods = alloc::vec![pod(true, Some(300), 0); 2];
        assert_eq!(resource_replicas(2, Target::AverageValue(100), &pods).unwrap().0, 6);
        assert!(resource_replicas(2, Target::Utilization(50), &[pod(true, None, 100)]).is_err(), "no metrics at all");
    }

    #[test]
    fn missing_and_unready_pods_are_handled_conservatively() {
        // Scaling up with one pod without metrics (counted as 0%) and one not ready (0%): two pods at
        // 200% would ask for double, but with the other two counted the load is exactly the target.
        let pods = alloc::vec![pod(true, Some(200), 100), pod(true, Some(200), 100), pod(true, None, 100), pod(false, None, 100)];
        assert_eq!(resource_replicas(4, Target::Utilization(100), &pods).unwrap().0, 4);
        // At 300% the four pods are at 150% of the target: 6.
        let pods = alloc::vec![pod(true, Some(300), 100), pod(true, Some(300), 100), pod(true, None, 100), pod(false, None, 100)];
        assert_eq!(resource_replicas(4, Target::Utilization(100), &pods).unwrap().0, 6);
        // Falling load with a pod that has no metrics: it counts as 100%, which can cancel a scale down.
        let pods = alloc::vec![pod(true, Some(40), 100), pod(true, None, 100)];
        assert_eq!(resource_replicas(2, Target::Utilization(50), &pods).unwrap().0, 2, "assumed 100% flips the direction");
        // Unready pods are ignored when the load is falling.
        let pods = alloc::vec![pod(true, Some(10), 100), pod(true, Some(10), 100), pod(false, None, 100)];
        assert_eq!(resource_replicas(3, Target::Utilization(50), &pods).unwrap().0, 1);
    }

    #[test]
    fn stabilization_holds_scale_downs_for_the_window() {
        // Recommendations: high load a minute ago (10), now low (3). Current 10.
        let recs = alloc::vec![(940, 10), (1000, 3)];
        assert_eq!(stabilize(10, 3, &recs, 1000, 0, 300), 10, "the high recommendation of the last 300 s wins");
        assert_eq!(stabilize(10, 3, &recs, 1000, 0, 30), 3, "outside a 30 s window it does not");
        // Scale up uses the lowest recommendation of the up window (0 s: just the new one).
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
        // Scale up wanted from 1 to 50: limited to +4 pods (max of +4 and +100%) per period.
        assert_eq!(normalize(1, 50, 1, 100, None, &mut h, 1000), 5);
        h.events.push((1000, 4));
        assert_eq!(normalize(5, 50, 1, 100, None, &mut h, 1005), 5, "already added 4 within the period: no more");
        assert_eq!(normalize(5, 50, 1, 100, None, &mut h, 1020), 10, "next period: +100% of 5");
        // Scale down is held by the 300 s window, then limited by 100% per period.
        let mut h = History::default();
        assert_eq!(normalize(8, 8, 2, 20, None, &mut h, 2000), 8);
        assert_eq!(normalize(8, 2, 2, 20, None, &mut h, 2010), 8, "the recommendation 8 of 10 s ago holds it");
        assert_eq!(normalize(8, 2, 2, 20, None, &mut h, 2400), 2, "after the window it drops (100% per period allows it)");
        // minReplicas / maxReplicas bound everything.
        let mut h = History::default();
        assert_eq!(normalize(3, 0, 2, 20, None, &mut h, 3000), 2, "never below minReplicas");
        assert_eq!(normalize(3, 100, 2, 4, None, &mut h, 3001), 4);
        // Behavior: scale up disabled, scale down by at most 1 pod per 60 s without a window.
        let b = kr_fmt::json::parse_str(r#"{"scaleUp":{"selectPolicy":"Disabled"},"scaleDown":{"stabilizationWindowSeconds":0,"policies":[{"type":"Pods","value":1,"periodSeconds":60}]}}"#).unwrap();
        let mut h = History::default();
        assert_eq!(normalize(5, 9, 1, 10, Some(&b), &mut h, 4000), 5);
        assert_eq!(normalize(5, 1, 1, 10, Some(&b), &mut h, 4001), 4);
    }

    #[test]
    fn metric_specs_and_targets_are_read() {
        let m = kr_fmt::json::parse_str(r#"{"type":"Resource","resource":{"name":"cpu","target":{"type":"Utilization","averageUtilization":60}}}"#).unwrap();
        assert_eq!(metric_spec(&m), Some(("cpu".into(), None, Target::Utilization(60))));
        let m = kr_fmt::json::parse_str(r#"{"type":"ContainerResource","containerResource":{"name":"memory","container":"app","target":{"type":"AverageValue","averageValue":"100Mi"}}}"#).unwrap();
        assert_eq!(metric_spec(&m), Some(("memory".into(), Some("app".into()), Target::AverageValue(100 << 20))));
        let pods_metric = kr_fmt::json::parse_str(r#"{"type":"Pods","pods":{"metric":{"name":"x"},"target":{"type":"AverageValue","averageValue":"1"}}}"#).unwrap();
        assert_eq!(metric_spec(&pods_metric), None);
        let r = kr_fmt::json::parse_str(r#"{"kind":"Deployment","name":"web","apiVersion":"apps/v1"}"#).unwrap();
        assert_eq!(target_path(&r, "default").as_deref(), Some("/apis/apps/v1/namespaces/default/deployments/web"));
    }
}
