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
//! `spec.selector` is not defaulted (that belongs to the API server); pods are found by the
//! `controller-uid` label plus the controller reference.

use crate::util::*;
use crate::Config;
use alloc::collections::BTreeSet;
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
        if let Some(r) = controller_ref(p).filter(|r| str_at(r, &["kind"]) == "Job") {
            q2.add(&alloc::format!("{}/{}", namespace(p), str_at(r, &["name"])));
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
    start_time: Option<String>,
    completion_time: Option<String>,
    /// Conditions to add/replace: (type, status, reason, message).
    conds: Vec<(&'static str, bool, &'static str, String)>,
}

pub async fn reconcile<C: Client>(c: &C, cfg: &Config, ns: &str, jname: &str) -> Result<Option<u64>> {
    let path = alloc::format!("{}/{jname}", jobs(Some(ns)));
    let Some(job) = get_opt(c, &path).await? else { return Ok(None) };
    if deleting(&job) {
        return Ok(None);
    }
    let now = (cfg.now)();

    if finished(&job) {
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
    let list = c.list(&pods(Some(ns)), &alloc::format!("labelSelector={}", enc(&alloc::format!("{UID_LABEL}={juid}")))).await?;
    let mine: Vec<Value> = items(&list).into_iter().filter(|p| controlled_by(p, &juid)).collect();
    let succeeded_pods: Vec<&Value> = mine.iter().filter(|p| str_at(p, &["status", "phase"]) == "Succeeded").collect();
    let failed_pods = mine.iter().filter(|p| str_at(p, &["status", "phase"]) == "Failed").count() as i64;
    let active_pods: Vec<&Value> = mine.iter().filter(|p| !pod_terminal(p) && !deleting(p)).collect();
    let terminating = mine.iter().filter(|p| deleting(p) && !pod_terminal(p)).count() as i64;
    let ready = active_pods.iter().filter(|p| pod_ready(p)).count() as i64;

    let spec_i = |f: &str| job.pointer(&["spec", f]).and_then(Value::as_i64);
    let completions = spec_i("completions");
    let parallelism = spec_i("parallelism").unwrap_or(1).max(0);
    let backoff_limit = spec_i("backoffLimit").unwrap_or(6);
    let indexed = str_at(&job, &["spec", "completionMode"]) == "Indexed" && completions.is_some();
    let suspended = job.pointer(&["spec", "suspend"]).and_then(Value::as_bool) == Some(true);
    let restart = str_at(&job, &["spec", "template", "spec", "restartPolicy"]);
    let on_failure = restart == "OnFailure";

    let succeeded_idx: BTreeSet<i64> = succeeded_pods.iter().filter_map(|p| pod_index(p)).collect();
    let succeeded = if indexed { succeeded_idx.len() as i64 } else { succeeded_pods.len() as i64 };
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
        start_time: start.clone(),
        completion_time: None,
        conds: Vec::new(),
    };
    let mut wait: Option<u64> = None;
    let mut delete_active = false;

    let success = match completions {
        Some(n) => succeeded >= n,
        None => succeeded > 0 && active_pods.is_empty(),
    };
    let deadline = spec_i("activeDeadlineSeconds");
    let started = start.as_deref().and_then(parse_time);

    if !matches!(restart, "Never" | "OnFailure") {
        out.conds.push(("Failed", true, "InvalidRestartPolicy", "Job pod template restartPolicy must be Never or OnFailure".to_string()));
    } else if success {
        out.completion_time = Some(rfc3339(now));
        out.conds.push(("SuccessCriteriaMet", true, "CompletionsReached", "Reached expected number of succeeded pods".to_string()));
        out.conds.push(("Complete", true, "", String::new()));
        delete_active = true;
    } else if failed > backoff_limit {
        out.conds.push(("Failed", true, "BackoffLimitExceeded", "Job has reached the specified backoff limit".to_string()));
        delete_active = true;
    } else if matches!((deadline, started), (Some(d), Some(s)) if now - s >= d) {
        out.conds.push(("Failed", true, "DeadlineExceeded", "Job was active longer than specified deadline".to_string()));
        delete_active = true;
    } else if suspended {
        out.conds.push(("Suspended", true, "JobSuspended", "Job suspended".to_string()));
        delete_active = true;
    } else {
        if has_condition(&job, "Suspended") {
            out.conds.push(("Suspended", false, "JobResumed", "Job resumed".to_string()));
        }
        // Start pods up to the wanted number of active ones.
        let want_active = match completions {
            Some(n) => parallelism.min((n - succeeded).max(0)),
            None if succeeded > 0 => 0,
            None => parallelism,
        };
        let mut missing = want_active - active_pods.len() as i64;
        if missing > 0 && failed_pods > 0 {
            // Back off after failures: wait base * 2^(failures-1) since the last one.
            let last = mine.iter().filter(|p| str_at(p, &["status", "phase"]) == "Failed").map(failure_time).max().unwrap_or(0);
            let delay = cfg.job_backoff_ms.saturating_mul(1u64 << (failed_pods - 1).min(20)).min(MAX_BACKOFF_MS);
            let due = (last.max(0) as u64) * 1000 + delay;
            let now_ms = now.max(0) as u64 * 1000;
            if now_ms < due {
                wait = Some(due - now_ms + 50);
                missing = 0;
            }
        }
        if missing > 0 {
            if indexed {
                let n = completions.unwrap_or(0);
                let active_idx: BTreeSet<i64> = active_pods.iter().filter_map(|p| pod_index(p)).collect();
                let todo: Vec<i64> = (0..n).filter(|i| !succeeded_idx.contains(i) && !active_idx.contains(i)).take(missing as usize).collect();
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
        if let Some(i) = &out.completed_indexes {
            if !i.is_empty() {
                st.set("completedIndexes", Value::from(i.as_str()));
            }
        }
        if !conds.is_empty() {
            st.set("conditions", Value::Array(conds));
        }
        st
    })
    .await
}
