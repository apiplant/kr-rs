//! `kr-controllers`: the Kubernetes control loops of kr, run inside the single binary on the
//! single-threaded executor (`kr_rt::exec`).
//!
//! # Design
//! Independent loops, each an `async fn run(c, cfg)` that never returns:
//!
//! * [`scheduler`]: binds unscheduled pods to nodes (filter, score, `pods/binding`).
//! * [`replicaset`]: keeps `spec.replicas` pods per ReplicaSet, adopting matching orphans.
//! * [`deployment`]: manages ReplicaSets per pod template (Recreate / RollingUpdate), history
//!   and status.
//! * [`statefulset`]: ordered, identity-stable pods with ControllerRevisions and PVCs.
//! * [`daemonset`]: one pod per eligible node, rolling updates.
//! * [`job`]: run-to-completion pods (completions, parallelism, indexed, backoff, TTL).
//! * [`cronjob`]: cron parsing and Job creation with concurrency policies.
//! * [`endpoints`]: Endpoints and EndpointSlices for Services with selectors.
//! * [`namespace`]: finishes the deletion of Terminating namespaces (empties, then finalizes).
//! * [`pvc`]: PVC/PV binding, a local-path provisioner and pvc-protection.
//! * [`gc`]: deletes dependents whose owner no longer exists (background propagation).
//!
//! All of them are *level-triggered*. A watch (list, remember the list's `resourceVersion`,
//! watch from it; on end or ERROR re-list and re-watch with a backoff on failures) only marks
//! keys dirty. A reconciler reads fresh state with `get`/`list` (cheap in-process), makes the
//! smallest set of writes that moves the world towards the spec, and retries on 409. A periodic
//! resync marks everything dirty again, so a missed event only delays convergence.
//!
//! Every object a controller creates carries an `ownerReferences` entry with
//! `controller: true` and `blockOwnerDeletion: true`; the garbage collector relies on it.
//!
//! The controllers talk to the API only through [`kr_apiserver::client::Client`], so they work
//! unchanged against the in-process server or a remote one.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod cronjob;
pub mod daemonset;
pub mod deployment;
pub mod endpoints;
pub mod gc;
pub mod job;
pub mod namespace;
pub mod pvc;
pub mod quota;
pub mod replicaset;
pub mod scheduler;
pub mod statefulset;
pub mod util;

use kr_apiserver::client::Client;
use kr_rt::exec::spawn;

/// Timing knobs. Tests shrink them; the defaults are the production values.
#[derive(Clone, Copy)]
pub struct Config {
    /// Every key is reconciled again at this interval, whatever the watches said.
    pub resync_ms: u64,
    /// Garbage collector sweep interval.
    pub gc_ms: u64,
    /// Delay before retrying after a failed reconcile or a broken watch.
    pub backoff_ms: u64,
    /// Delay before re-checking something that cannot progress yet (unschedulable pod,
    /// Recreate waiting for old pods to go away).
    pub retry_ms: u64,
    /// Base delay (ms) before replacing a failed Job pod; doubles per further failure, capped at
    /// 6 minutes (upstream: 10 s).
    pub job_backoff_ms: u64,
    /// Unix time in seconds, for condition timestamps. The default always returns 0; the
    /// binary passes its real clock.
    pub now: fn() -> i64,
}

fn zero_clock() -> i64 {
    0
}

impl Default for Config {
    fn default() -> Config {
        Config { resync_ms: 30_000, gc_ms: 5_000, backoff_ms: 1_000, retry_ms: 5_000, job_backoff_ms: 10_000, now: zero_clock }
    }
}

/// Spawns every controller with the default [`Config`] and runs until dropped.
pub async fn run_all<C: Client + Clone + 'static>(c: C) {
    run_all_with(c, Config::default()).await
}

/// Like [`run_all`] with explicit timing. Dropping (or aborting) the returned future stops all
/// controllers and their watchers.
pub async fn run_all_with<C: Client + Clone + 'static>(c: C, cfg: Config) {
    let _guard = util::Guard(alloc::vec![
        spawn(scheduler::run(c.clone(), cfg)),
        spawn(replicaset::run(c.clone(), cfg)),
        spawn(replicaset::run_rc(c.clone(), cfg)),
        spawn(deployment::run(c.clone(), cfg)),
        spawn(statefulset::run(c.clone(), cfg)),
        spawn(daemonset::run(c.clone(), cfg)),
        spawn(job::run(c.clone(), cfg)),
        spawn(cronjob::run(c.clone(), cfg)),
        spawn(endpoints::run(c.clone(), cfg)),
        spawn(quota::run(c.clone(), cfg)),
        spawn(namespace::run(c.clone(), cfg)),
        spawn(pvc::run(c.clone(), cfg)),
        spawn(gc::run(c, cfg)),
    ]);
    // A never-woken future would let the executor free this task (and abort the guard).
    loop {
        kr_rt::exec::sleep(3_600_000).await;
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_workloads;
#[cfg(test)]
mod tests_pvc;
