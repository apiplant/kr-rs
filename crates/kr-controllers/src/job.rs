//! The Job controller: runs pods to completion.
//!
//! Pods are labelled `batch.kubernetes.io/controller-uid`, `batch.kubernetes.io/job-name`
//! (and the legacy `controller-uid`, `job-name`) and controlled by the Job. Counts are derived
//! from the pods that exist: `succeeded` (phase Succeeded), `failed` (phase Failed), `active`
//! (neither, not terminating), `ready`, `terminating`. Finished pods are kept (deleting them
//! lowers the counts); `uncountedTerminatedPods` stays empty.
//!
//! * **Completions.** With `spec.completions` the job is complete at that many successes
//!   (distinct indexes when `completionMode: Indexed`). Without it (work queue) it is complete
//!   when some pod succeeded and none is active. At most
//!   `min(parallelism, completions - succeeded)` pods run; `parallelism` defaults to 1 and 0
//!   pauses the job. Indexed pods get the index in annotation and label
//!   `batch.kubernetes.io/job-completion-index`, env `JOB_COMPLETION_INDEX` (a downward-API
//!   reference to that annotation) in every container, hostname `<job>-<index>`, and the lowest
//!   free indexes are started first. `status.completedIndexes` lists the succeeded ones.
//! * **backoffLimit** (default 6): the job fails with `BackoffLimitExceeded` when the failed
//!   pods (plus container restarts of active pods when `restartPolicy` is OnFailure) exceed it.
//!   Replacement pods are delayed like upstream: `Config::job_backoff_ms` (10 s) times
//!   2^(failures - 1), capped at 6 minutes, counted from the latest pod failure (the newest
//!   container `finishedAt`, else the pod's deletion/creation time).
//! * **activeDeadlineSeconds**: measured from `status.startTime`; exceeding it fails the job with
//!   `DeadlineExceeded`. The check is re-run when the deadline is due.
//! * **suspend**: active pods are deleted, `startTime` cleared, condition `Suspended`; resuming
//!   sets a new `startTime`.
//! * **Conditions**: success adds `SuccessCriteriaMet` then `Complete` and sets `completionTime`;
//!   failure adds `Failed` (the reasons above); remaining active pods are deleted. A pod template
//!   whose `restartPolicy` is not Never/OnFailure fails the job with `InvalidRestartPolicy`
//!   without creating pods (upstream rejects it at admission).
//! * **ttlSecondsAfterFinished**: a finished job is deleted at `finish time + ttl` (its pods go
//!   with it through the garbage collector).
//!
//! `spec.selector` is defaulted by the API server (`controller-uid`). Matching pods without a
//! controller are adopted, controlled pods that stop matching are released.
//!
//! * **podFailurePolicy**: each failed pod is checked against the rules (`onExitCodes`,
//!   `onPodConditions`); `Ignore` leaves it uncounted, `FailJob` fails the job with
//!   `PodFailurePolicy`, `FailIndex` fails that index (needs `backoffLimitPerIndex`).
//! * **backoffLimitPerIndex / maxFailedIndexes**: an Indexed job counts failures per index; an
//!   index with more failures than the limit is failed (`status.failedIndexes`) and not run
//!   again; the job fails with `FailedIndexes` once every index is done, or with
//!   `MaxFailedIndexesExceeded` as soon as there are too many. Without `backoffLimit` the
//!   job-wide limit is off.
//! * **successPolicy**: the job is successful once a rule is met by the succeeded indexes
//!   (`SuccessCriteriaMet` with reason `SuccessPolicy`); `Complete` is added after the
//!   remaining pods are gone.

use crate::util::*;
use crate::Config;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_apiserver::client::{Client, Result};
use kr_fmt::json::Value;

pub const UID_LABEL: &str = "batch.kubernetes.io/controller-uid";
pub const NAME_LABEL: &str = "batch.kubernetes.io/job-name";
pub const INDEX_KEY: &str = "batch.kubernetes.io/job-completion-index";

pub async fn run<C: Client + Clone + 'static>(c: C, cfg: Config) {
    let q = Queue::new();
    let mut g = Guard::default();
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), jobs(None), String::new(), cfg, move |_, o| q2.add(&key_of(o)))));
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), pods(None), String::new(), cfg, move |_, p| {
        match controller_ref(p) {
            Some(r) if str_at(r, &["kind"]) == "Job" => q2.add(&alloc::format!("{}/{}", namespace(p), str_at(r, &["name"]))),
            Some(_) => {}
            // An orphan that carries a job's name label may be adopted by it.
            None => {
                let n = str_at(p, &["metadata", "labels", NAME_LABEL]);
                if !n.is_empty() {
                    q2.add(&alloc::format!("{}/{n}", namespace(p)));
                }
            }
        }
    })));
    let (c2, c3, q3) = (c.clone(), c.clone(), q.clone());
    drive(
        &cfg,
        &q,
        move |key| {
            let c = c2.clone();
            async move {
                let (ns, n) = split_key(&key);
                reconcile(&c, &cfg, ns, n).await
            }
        },
        move || {
            let (c, q) = (c3.clone(), q3.clone());
            async move {
                if let Ok(l) = c.list(&jobs(None), "").await {
                    for j in items(&l) {
                        q.add(&key_of(&j));
                    }
                }
            }
        },
    )
    .await
}

fn finished(j: &Value) -> bool {
    has_condition(j, "Complete") || has_condition(j, "Failed")
}

fn finish_time(j: &Value) -> Option<i64> {
    let conds = j.pointer(&["status", "conditions"])?.as_array()?;
    let c = conds.iter().find(|c| matches!(str_at(c, &["type"]), "Complete" | "Failed") && str_at(c, &["status"]) == "True")?;
    parse_time(str_at(c, &["lastTransitionTime"]))
}

fn pod_index(p: &Value) -> Option<i64> {
    str_at(p, &["metadata", "annotations", INDEX_KEY]).parse().ok().or_else(|| str_at(p, &["metadata", "labels", INDEX_KEY]).parse().ok())
}

fn restarts(p: &Value) -> i64 {
    p.pointer(&["status", "containerStatuses"]).and_then(Value::as_array).map(|a| a.iter().map(|s| int_at(s, &["restartCount"], 0)).sum()).unwrap_or(0)
}

const MAX_BACKOFF_MS: u64 = 360_000;

/// Unix seconds at which the pod failed.
fn failure_time(p: &Value) -> i64 {
    let finished = p.pointer(&["status", "containerStatuses"]).and_then(Value::as_array).into_iter().flatten().filter_map(|s| parse_time(str_at(s, &["state", "terminated", "finishedAt"]))).max();
    finished.or_else(|| parse_time(str_at(p, &["metadata", "creationTimestamp"]))).unwrap_or(0)
}

fn ms_until(secs: i64) -> u64 {
    (secs.max(0) as u64) * 1000 + 50
}

fn build_pod(job: &Value, index: Option<i64>) -> Value {
    let template = job.pointer(&["spec", "template"]).cloned().unwrap_or(Value::Null);
    let (juid, jname) = (uid(job), name(job));
    let idx = index.map(|i| i.to_string());
    let prefix = match &idx {
        Some(i) => alloc::format!("{jname}-{i}-"),
        None => alloc::format!("{jname}-"),
    };
    let mut labels: Vec<(&str, &str)> = alloc::vec![(UID_LABEL, juid), (NAME_LABEL, jname), ("controller-uid", juid), ("job-name", jname)];
    let mut annotations: Vec<(&str, &str)> = Vec::new();
    if let Some(i) = &idx {
        labels.push((INDEX_KEY, i));
        annotations.push((INDEX_KEY, i));
    }
    let mut pod = pod_from_template(job, "batch/v1", "Job", &template, None, &prefix, &labels, &annotations);
    if let Some(i) = &idx {
        let env = obj(alloc::vec![
            ("name", Value::from("JOB_COMPLETION_INDEX")),
            ("valueFrom", obj(alloc::vec![("fieldRef", obj(alloc::vec![("fieldPath", Value::String(alloc::format!("metadata.annotations['{INDEX_KEY}']")))]))])),
        ]);
        let spec = pod.entry_object("spec");
        for field in ["initContainers", "containers"] {
            if let Some(cs) = spec.get_mut(field).and_then(Value::as_array_mut) {
                for ctr in cs {
                    let envs = ctr.entry_array("env");
                    envs.retain(|e| str_at(e, &["name"]) != "JOB_COMPLETION_INDEX");
                    envs.push(env.clone());
                }
            }
        }
        spec.set("hostname", Value::String(alloc::format!("{jname}-{i}")));
    }
    pod
}

trait EntryArray {
    fn entry_array(&mut self, key: &str) -> &mut Vec<Value>;
}
impl EntryArray for Value {
    fn entry_array(&mut self, key: &str) -> &mut Vec<Value> {
        if !matches!(self.get(key), Some(Value::Array(_))) {
            self.set(key, Value::Array(Vec::new()));
        }
        self.get_mut(key).and_then(Value::as_array_mut).expect("just set")
    }
}

/// What the status write should say.
struct Outcome {
    active: i64,
    ready: i64,
    succeeded: i64,
    failed: i64,
    terminating: i64,
    completed_indexes: Option<String>,
    failed_indexes: Option<String>,
    start_time: Option<String>,
    completion_time: Option<String>,
    /// Conditions to add/replace: (type, status, reason, message).
    conds: Vec<(&'static str, bool, String, String)>,
}

/// What the pod failure policy says about one failed pod.
#[derive(Clone, Copy, PartialEq)]
enum Action {
    Count,
    Ignore,
    FailJob,
    FailIndex,
}

/// First matching `podFailurePolicy` rule for a failed pod: the action and the message of a
/// match (`Count` without a message when no rule matches).
fn failure_action(job: &Value, p: &Value) -> (Action, String) {
    let rules = job.pointer(&["spec", "podFailurePolicy", "rules"]).and_then(Value::as_array).unwrap_or(&[]);
    for (i, r) in rules.iter().enumerate() {
        let action = match str_at(r, &["action"]) {
            "Ignore" => Action::Ignore,
            "FailJob" => Action::FailJob,
            "FailIndex" => Action::FailIndex,
            _ => Action::Count,
        };
        let pod = alloc::format!("{}/{}", namespace(p), name(p));
        let note = |what: String| alloc::format!("{what} matching {} rule at index {i}", str_at(r, &["action"]));
        if let Some(req) = r.get("onExitCodes") {
            let want = str_at(req, &["containerName"]);
            let values: Vec<i64> = req.get("values").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_i64).collect()).unwrap_or_default();
            let negate = str_at(req, &["operator"]) == "NotIn";
            for field in ["initContainerStatuses", "containerStatuses"] {
                for s in p.pointer(&["status", field]).and_then(Value::as_array).unwrap_or(&[]) {
                    let Some(code) = s.pointer(&["state", "terminated", "exitCode"]).and_then(Value::as_i64) else { continue };
                    if code == 0 || (!want.is_empty() && str_at(s, &["name"]) != want) {
                        continue;
                    }
                    if values.contains(&code) != negate {
                        return (action, note(alloc::format!("Container {} for pod {pod} failed with exit code {code}", str_at(s, &["name"]))));
                    }
                }
            }
        }
        for pat in r.get("onPodConditions").and_then(Value::as_array).unwrap_or(&[]) {
            let status = if str_at(pat, &["status"]).is_empty() { "True" } else { str_at(pat, &["status"]) };
            let hit = p.pointer(&["status", "conditions"]).and_then(Value::as_array).is_some_and(|cs| cs.iter().any(|c| str_at(c, &["type"]) == str_at(pat, &["type"]) && str_at(c, &["status"]) == status));
            if hit {
                return (action, note(alloc::format!("Pod {pod} has condition {}", str_at(pat, &["type"]))));
            }
        }
    }
    (Action::Count, String::new())
}

/// Parses `0,2-4` into the set of indexes.
fn parse_indexes(s: &str) -> BTreeSet<i64> {
    let mut out = BTreeSet::new();
    for part in s.split(',') {
        match part.split_once('-') {
            Some((a, b)) => {
                if let (Ok(a), Ok(b)) = (a.trim().parse::<i64>(), b.trim().parse::<i64>()) {
                    out.extend(a..=b.min(a + 100_000));
                }
            }
            None => out.extend(part.trim().parse::<i64>().ok()),
        }
    }
    out
}

/// Index of the first `successPolicy` rule met by the succeeded indexes.
fn success_rule(job: &Value, succeeded: &BTreeSet<i64>) -> Option<usize> {
    let rules = job.pointer(&["spec", "successPolicy", "rules"]).and_then(Value::as_array)?;
    rules.iter().position(|r| {
        let count = r.get("succeededCount").and_then(Value::as_i64);
        match r.get("succeededIndexes").and_then(Value::as_str) {
            Some(s) => {
                let set = parse_indexes(s);
                let hit = set.intersection(succeeded).count() as i64;
                // Without a count every listed index must have succeeded.
                hit >= count.unwrap_or(set.len() as i64) && (count.is_some() || !set.is_empty())
            }
            None => count.is_some_and(|n| succeeded.len() as i64 >= n),
        }
    })
}

pub async fn reconcile<C: Client>(c: &C, cfg: &Config, ns: &str, jname: &str) -> Result<Option<u64>> {
    let path = alloc::format!("{}/{jname}", jobs(Some(ns)));
    let Some(job) = get_opt(c, &path).await? else { return Ok(None) };
    if deleting(&job) {
        return Ok(None);
    }
    let now = (cfg.now)();

    if finished(&job) {
        // The pods that were still going when the job finished leave: keep the counts true.
        if int_at(&job, &["status", "active"], 0) + int_at(&job, &["status", "terminating"], 0) > 0 {
            let list = c.list(&pods(Some(ns)), &alloc::format!("labelSelector={}", enc(&alloc::format!("{UID_LABEL}={}", uid(&job))))).await?;
            let live: Vec<Value> = items(&list).into_iter().filter(|p| controlled_by(p, uid(&job)) && !pod_terminal(p)).collect();
            let active = live.iter().filter(|p| !deleting(p)).count() as i64;
            let terminating = live.len() as i64 - active;
            let ready = live.iter().filter(|p| !deleting(p) && pod_ready(p)).count() as i64;
            put_status(c, &path, |o| {
                let mut st = o.get("status").cloned().unwrap_or(Value::Null);
                for (k, v) in [("active", active), ("terminating", terminating), ("ready", ready)] {
                    st.set(k, num(v));
                }
                st
            })
            .await?;
        }
        // Only the TTL is left to do.
        if let (Some(ttl), Some(done)) = (job.pointer(&["spec", "ttlSecondsAfterFinished"]).and_then(Value::as_i64), finish_time(&job)) {
            let due = done + ttl.max(0);
            if now >= due {
                delete_ok(c, &path).await?;
                return Ok(None);
            }
            return Ok(Some(ms_until(due - now)));
        }
        return Ok(None);
    }

    let juid = uid(&job).to_string();
    // The namespace's pods: matching orphans are adopted, controlled pods that no longer match
    // the selector are released.
    let sel = job.pointer(&["spec", "selector"]).and_then(parse_selector).map(|(_, s)| s);
    let list = c.list(&pods(Some(ns)), "").await?;
    let mut mine: Vec<Value> = Vec::new();
    for p in items(&list) {
        let matches = match &sel {
            Some(s) => s.matches(&p),
            None => str_at(&p, &["metadata", "labels", UID_LABEL]) == juid,
        };
        match controller_ref(&p) {
            Some(r) if str_at(r, &["uid"]) == juid => {
                if matches || deleting(&p) {
                    mine.push(p);
                } else {
                    release_owner(c, &pods(Some(ns)), &juid, &p).await?;
                }
            }
            Some(_) => {}
            None if matches && !deleting(&p) => {
                if let Some(p) = adopt(c, &pods(Some(ns)), &job, "batch/v1", "Job", &p).await? {
                    mine.push(p);
                }
            }
            None => {}
        }
    }

    let spec_i = |f: &str| job.pointer(&["spec", f]).and_then(Value::as_i64);
    let completions = spec_i("completions");
    let parallelism = spec_i("parallelism").unwrap_or(1).max(0);
    let indexed = str_at(&job, &["spec", "completionMode"]) == "Indexed" && completions.is_some();
    let limit_per_index = spec_i("backoffLimitPerIndex").filter(|_| indexed);
    let backoff_limit = spec_i("backoffLimit").unwrap_or(if limit_per_index.is_some() { i64::MAX } else { 6 });
    let max_failed_indexes = spec_i("maxFailedIndexes");
    let suspended = job.pointer(&["spec", "suspend"]).and_then(Value::as_bool) == Some(true);
    let restart = str_at(&job, &["spec", "template", "spec", "restartPolicy"]);
    let on_failure = restart == "OnFailure";

    let succeeded_pods: Vec<&Value> = mine.iter().filter(|p| str_at(p, &["status", "phase"]) == "Succeeded").collect();
    let active_pods: Vec<&Value> = mine.iter().filter(|p| !pod_terminal(p) && !deleting(p)).collect();
    let terminating = mine.iter().filter(|p| deleting(p) && !pod_terminal(p)).count() as i64;
    let ready = active_pods.iter().filter(|p| pod_ready(p)).count() as i64;
    let succeeded_idx: BTreeSet<i64> = succeeded_pods.iter().filter_map(|p| pod_index(p)).collect();
    let succeeded = if indexed { succeeded_idx.len() as i64 } else { succeeded_pods.len() as i64 };

    // Failed pods, through the pod failure policy: ignored ones are not counted, FailJob ends
    // the job, FailIndex (and exceeding backoffLimitPerIndex) ends one index.
    let mut failed_pods = 0i64;
    let mut last_failure = 0i64;
    let mut fail_job: Option<String> = None;
    let mut index_failures: BTreeMap<i64, (i64, i64)> = BTreeMap::new();
    let mut failed_idx: BTreeSet<i64> = BTreeSet::new();
    for p in mine.iter().filter(|p| str_at(p, &["status", "phase"]) == "Failed") {
        let (action, msg) = failure_action(&job, p);
        let idx = pod_index(p).filter(|_| indexed);
        match action {
            Action::Ignore => continue,
            Action::FailJob if fail_job.is_none() => fail_job = Some(msg),
            Action::FailIndex => failed_idx.extend(idx.filter(|_| limit_per_index.is_some())),
            _ => {}
        }
        failed_pods += 1;
        let t = failure_time(p);
        last_failure = last_failure.max(t);
        if let Some(i) = idx {
            let e = index_failures.entry(i).or_insert((0, 0));
            e.0 += 1;
            e.1 = e.1.max(t);
        }
    }
    if let Some(limit) = limit_per_index {
        failed_idx.extend(index_failures.iter().filter(|(_, (n, _))| *n > limit).map(|(i, _)| *i));
        failed_idx.retain(|i| !succeeded_idx.contains(i));
    }
    let failed = failed_pods + if on_failure { active_pods.iter().map(|p| restarts(p)).sum::<i64>() } else { 0 };

    let old_start = str_at(&job, &["status", "startTime"]);
    let start = if suspended { None } else if old_start.is_empty() { Some(rfc3339(now)) } else { Some(old_start.to_string()) };

    let mut out = Outcome {
        active: active_pods.len() as i64,
        ready,
        succeeded,
        failed,
        terminating,
        completed_indexes: indexed.then(|| compress_indexes(&succeeded_idx.iter().copied().collect::<Vec<_>>())),
        failed_indexes: limit_per_index.map(|_| compress_indexes(&failed_idx.iter().copied().collect::<Vec<_>>())),
        start_time: start.clone(),
        completion_time: None,
        conds: Vec::new(),
    };
    let mut wait: Option<u64> = None;
    let mut delete_active = false;

    // Success criteria: a successPolicy rule, else the completions.
    let met_cond = job.pointer(&["status", "conditions"]).and_then(Value::as_array).and_then(|a| a.iter().find(|c| str_at(c, &["type"]) == "SuccessCriteriaMet" && str_at(c, &["status"]) == "True"));
    let success: Option<(String, String)> = if let Some(c) = met_cond {
        Some((str_at(c, &["reason"]).to_string(), str_at(c, &["message"]).to_string()))
    } else if let Some(i) = success_rule(&job, &succeeded_idx).filter(|_| indexed) {
        Some(("SuccessPolicy".to_string(), alloc::format!("Matched rules at index {i}")))
    } else {
        let done = match completions {
            Some(n) => succeeded >= n,
            None => succeeded > 0 && active_pods.is_empty(),
        };
        done.then(|| ("CompletionsReached".to_string(), "Reached expected number of succeeded pods".to_string()))
    };
    let deadline = spec_i("activeDeadlineSeconds");
    let started = start.as_deref().and_then(parse_time);
    let n_indexes = completions.unwrap_or(0);
    let all_indexes_done = indexed && limit_per_index.is_some() && succeeded_idx.len() + failed_idx.len() >= n_indexes as usize;

    if !matches!(restart, "Never" | "OnFailure") {
        out.conds.push(("Failed", true, "InvalidRestartPolicy".to_string(), "Job pod template restartPolicy must be Never or OnFailure".to_string()));
    } else if let Some((reason, msg)) = success {
        // Complete follows SuccessCriteriaMet once the remaining pods are gone.
        out.conds.push(("SuccessCriteriaMet", true, reason.clone(), msg.clone()));
        delete_active = true;
        if active_pods.is_empty() && terminating == 0 {
            out.completion_time = Some(rfc3339(now));
            out.conds.push(("Complete", true, reason, msg));
        }
    } else if let Some(msg) = fail_job {
        out.conds.push(("Failed", true, "PodFailurePolicy".to_string(), msg));
        delete_active = true;
    } else if failed > backoff_limit {
        out.conds.push(("Failed", true, "BackoffLimitExceeded".to_string(), "Job has reached the specified backoff limit".to_string()));
        delete_active = true;
    } else if max_failed_indexes.is_some_and(|m| failed_idx.len() as i64 > m) {
        out.conds.push(("Failed", true, "MaxFailedIndexesExceeded".to_string(), "Job has exceeded the specified maximal number of failed indexes".to_string()));
        delete_active = true;
    } else if all_indexes_done && !failed_idx.is_empty() {
        out.conds.push(("Failed", true, "FailedIndexes".to_string(), "Job has failed indexes".to_string()));
        delete_active = true;
    } else if matches!((deadline, started), (Some(d), Some(s)) if now - s >= d) {
        out.conds.push(("Failed", true, "DeadlineExceeded".to_string(), "Job was active longer than specified deadline".to_string()));
        delete_active = true;
    } else if suspended {
        out.conds.push(("Suspended", true, "JobSuspended".to_string(), "Job suspended".to_string()));
        delete_active = true;
    } else {
        if has_condition(&job, "Suspended") {
            out.conds.push(("Suspended", false, "JobResumed".to_string(), "Job resumed".to_string()));
        }
        // Start pods up to the wanted number of active ones.
        let want_active = match completions {
            Some(n) => parallelism.min((n - succeeded - failed_idx.len() as i64).max(0)),
            None if succeeded > 0 => 0,
            None => parallelism,
        };
        let mut missing = want_active - active_pods.len() as i64;
        let now_ms = now.max(0) as u64 * 1000;
        // Back off after failures: wait base * 2^(failures-1) since the last one.
        let delay = |n: i64| cfg.job_backoff_ms.saturating_mul(1u64 << (n - 1).clamp(0, 20)).min(MAX_BACKOFF_MS);
        if missing > 0 && failed_pods > 0 && limit_per_index.is_none() {
            let due = (last_failure.max(0) as u64) * 1000 + delay(failed_pods);
            if now_ms < due {
                wait = Some(due - now_ms + 50);
                missing = 0;
            }
        }
        if missing > 0 {
            if indexed {
                let active_idx: BTreeSet<i64> = active_pods.iter().filter_map(|p| pod_index(p)).collect();
                let mut todo: Vec<i64> = Vec::new();
                for i in (0..n_indexes).filter(|i| !succeeded_idx.contains(i) && !active_idx.contains(i) && !failed_idx.contains(i)) {
                    if todo.len() as i64 >= missing {
                        break;
                    }
                    if limit_per_index.is_some() {
                        if let Some((n, last)) = index_failures.get(&i) {
                            let due = (*last).max(0) as u64 * 1000 + delay(*n);
                            if now_ms < due {
                                let w = due - now_ms + 50;
                                wait = Some(wait.map_or(w, |b| b.min(w)));
                                continue;
                            }
                        }
                    }
                    todo.push(i);
                }
                for i in todo {
                    c.create(&pods(Some(ns)), &build_pod(&job, Some(i))).await?;
                }
            } else {
                for _ in 0..missing.min(500) {
                    c.create(&pods(Some(ns)), &build_pod(&job, None)).await?;
                }
            }
        } else if missing < 0 {
            // Too many (parallelism lowered): remove the newest, not-ready ones first.
            let mut extra: Vec<&&Value> = active_pods.iter().collect();
            extra.sort_by_key(|p| (pod_ready(p), core::cmp::Reverse(str_at(p, &["metadata", "creationTimestamp"]).to_string())));
            for p in extra.into_iter().take((-missing) as usize) {
                delete_ok(c, &alloc::format!("{}/{}", pods(Some(ns)), name(p))).await?;
            }
        }
        if let (Some(d), Some(s)) = (deadline, started) {
            let w = ms_until(s + d - now);
            wait = Some(wait.map_or(w, |b| b.min(w)));
        }
    }

    if delete_active {
        for p in &active_pods {
            delete_ok(c, &alloc::format!("{}/{}", pods(Some(ns)), name(p))).await?;
        }
        out.terminating += out.active;
        out.active = 0;
        out.ready = 0;
    }

    write_status(c, &path, &out, now).await?;
    if out.conds.iter().any(|(t, s, ..)| matches!(*t, "Complete" | "Failed") && *s) {
        // Finished just now: look at the TTL right away.
        return Ok(Some(0));
    }
    Ok(wait)
}

async fn write_status<C: Client>(c: &C, path: &str, out: &Outcome, now: i64) -> Result<()> {
    put_status(c, path, |o| {
        let old = o.get("status").cloned().unwrap_or(Value::Null);
        let old_conds: Vec<Value> = old.get("conditions").and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
        let mut conds = old_conds.clone();
        for (ty, status, reason, msg) in &out.conds {
            let cond = merge_condition(&old_conds, condition(ty, *status, reason, msg, now));
            set_condition(&mut conds, cond);
        }
        let mut st = obj(alloc::vec![
            ("active", num(out.active)),
            ("ready", num(out.ready)),
            ("succeeded", num(out.succeeded)),
            ("failed", num(out.failed)),
            ("terminating", num(out.terminating)),
            ("uncountedTerminatedPods", obj(Vec::new())),
        ]);
        if let Some(t) = &out.start_time {
            st.set("startTime", Value::from(t.as_str()));
        }
        if let Some(t) = out.completion_time.as_deref().or_else(|| old.get("completionTime").and_then(Value::as_str)) {
            st.set("completionTime", Value::from(t));
        }
        for (key, v) in [("completedIndexes", &out.completed_indexes), ("failedIndexes", &out.failed_indexes)] {
            if let Some(i) = v.as_deref().filter(|i| !i.is_empty()) {
                st.set(key, Value::from(i));
            }
        }
        if !conds.is_empty() {
            st.set("conditions", Value::Array(conds));
        }
        st
    })
    .await
}
