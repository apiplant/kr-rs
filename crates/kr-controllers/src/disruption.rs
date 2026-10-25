//! The PodDisruptionBudget controller: keeps `status` (`expectedPods`, `currentHealthy`,
//! `desiredHealthy`, `disruptionsAllowed`, `observedGeneration`) of every budget in step with
//! the pods its selector matches. The API server's `pods/eviction` only reads these numbers
//! (and decrements `disruptionsAllowed` when it evicts), so the controller is what gives a
//! budget back its allowance as replacement pods become Ready.
//!
//! Unlike upstream, `expectedPods` is the number of live matching pods rather than the sum of
//! the owning controllers' scales. Level-triggered like the rest: any event on a pod or a
//! budget marks its namespace `<ns>/*`.

use crate::util::*;
use crate::Config;
use alloc::string::String;
use alloc::vec::Vec;
use kr_apiserver::client::{Client, Result};
use kr_fmt::json::Value;

/// How long a pod stays in `status.disruptedPods` (the eviction was granted but the pod has not
/// gone yet) before the allowance is no longer withheld for it.
const DISRUPTED_TIMEOUT: i64 = 120;

pub async fn run<C: Client + Clone + 'static>(c: C, cfg: Config) {
    let queue = Queue::new();
    let mut g = Guard::default();
    for (group, version, plural) in [("", "v1", "pods"), ("policy", "v1", "poddisruptionbudgets")] {
        let q2 = queue.clone();
        g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), api_path(group, version, None, plural), String::new(), cfg, move |_, o| q2.add(&alloc::format!("{}/*", namespace(o))))));
    }
    let (c2, c3, q3) = (c.clone(), c.clone(), queue.clone());
    drive(
        &cfg,
        &queue,
        move |key| {
            let c = c2.clone();
            async move {
                let (ns, who) = split_key(&key);
                if ns.is_empty() || who != "*" {
                    return Ok(None);
                }
                reconcile(&c, ns, cfg.now).await?;
                Ok(None)
            }
        },
        move || {
            let (c, q) = (c3.clone(), q3.clone());
            async move {
                if let Ok(l) = c.list("/apis/policy/v1/poddisruptionbudgets", "").await {
                    for pdb in items(&l) {
                        q.add(&alloc::format!("{}/*", namespace(&pdb)));
                    }
                }
            }
        },
    )
    .await
}

async fn reconcile<C: Client>(c: &C, ns: &str, now: fn() -> i64) -> Result<()> {
    let path = api_path("policy", "v1", Some(ns), "poddisruptionbudgets");
    let pdbs = items(&c.list(&path, "").await?);
    if pdbs.is_empty() {
        return Ok(());
    }
    let pods = items(&c.list(&pods(Some(ns)), "").await?);
    for pdb in pdbs.iter().filter(|p| !deleting(p)) {
        let pdb_path = alloc::format!("{path}/{}", name(pdb));
        put_status(c, &pdb_path, |cur| want_status(cur, &pods, now())).await?;
    }
    Ok(())
}

/// Resolves an int-or-percent value against `total`, rounding percentages up.
fn resolve(v: &Value, total: i64) -> Option<i64> {
    if let Some(n) = v.as_i64() {
        return Some(n);
    }
    let p = v.as_str()?.strip_suffix('%')?.parse::<i64>().ok()?;
    Some((p * total + 99) / 100)
}

/// The `status` the budget should carry given the namespace's pods.
fn want_status(pdb: &Value, pods: &[Value], now: i64) -> Value {
    let sel = pdb.pointer(&["spec", "selector"]).and_then(parse_selector);
    let matched: Vec<&Value> = match &sel {
        Some((_, s)) => pods.iter().filter(|p| !pod_terminal(p) && s.matches(p)).collect(),
        None => Vec::new(),
    };
    let expected = matched.len() as i64;
    let healthy = matched.iter().filter(|p| !deleting(p) && running_ready(p)).count() as i64;
    let desired = match (pdb.pointer(&["spec", "minAvailable"]), pdb.pointer(&["spec", "maxUnavailable"])) {
        (Some(m), _) => resolve(m, expected).unwrap_or(0),
        (None, Some(m)) => expected - resolve(m, expected).unwrap_or(0),
        (None, None) => 0,
    }
    .clamp(0, expected);
    // Evicted pods that are still around withhold their allowance until they go (or time out).
    let mut disrupted: Vec<(String, Value)> = Vec::new();
    if let Some(m) = pdb.pointer(&["status", "disruptedPods"]).and_then(Value::as_object) {
        for (pod, t) in m {
            let live = matched.iter().any(|p| name(p) == pod && !deleting(p));
            if live && parse_time(t.as_str().unwrap_or("")).is_some_and(|t| now - t < DISRUPTED_TIMEOUT) {
                disrupted.push((pod.clone(), t.clone()));
            }
        }
    }
    let mut st = obj(alloc::vec![
        ("currentHealthy", num(healthy)),
        ("desiredHealthy", num(desired)),
        ("disruptionsAllowed", num((healthy - desired).max(0))),
        ("expectedPods", num(expected)),
        ("observedGeneration", num(int_at(pdb, &["metadata", "generation"], 0))),
    ]);
    if !disrupted.is_empty() {
        st.set("disruptedPods", Value::Object(disrupted));
    }
    st
}
