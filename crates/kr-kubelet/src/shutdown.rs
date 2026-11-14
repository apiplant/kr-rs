//! Graceful node shutdown (#363): the configuration and the order in which pods are stopped.
//! The kubelet holds a logind delay inhibitor lock ([`crate::dbus`]); on `PrepareForShutdown(true)`
//! it stops pods group by group (lowest priority first) within each group's grace period, then
//! releases the lock.

use alloc::string::String;
use alloc::vec::Vec;

pub const MESSAGE: &str = "Pod was terminated in response to imminent node shutdown.";
pub const REASON: &str = "Terminated";
pub const REJECTED: &str = "Pod was rejected as the node is shutting down.";

/// `scheduling.SystemCriticalPriority`.
pub const SYSTEM_CRITICAL: i64 = 2_000_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// (lowest pod priority of the group, grace period in seconds), ascending by priority.
    pub groups: Vec<(i64, u64)>,
}

impl Config {
    /// From `shutdown-grace-period` / `-critical-pods`, or the by-priority list (which wins, as
    /// upstream's validation makes them exclusive). Returns warnings too.
    pub fn from(get: &dyn Fn(&str) -> Option<String>) -> (Config, Vec<String>) {
        let mut warn = Vec::new();
        let num = |k: &str| get(k).and_then(|v| v.trim().parse::<u64>().ok()).unwrap_or(0);
        let mut groups: Vec<(i64, u64)> = get("KR_SHUTDOWN_GRACE_PERIOD_BY_POD_PRIORITY")
            .unwrap_or_default()
            .split(',')
            .filter_map(|e| {
                let (p, s) = e.split_once('=')?;
                Some((p.trim().parse().ok()?, s.trim().parse().ok()?))
            })
            .collect();
        if groups.is_empty() {
            let (total, mut critical) = (num("KR_SHUTDOWN_GRACE_PERIOD"), num("KR_SHUTDOWN_GRACE_PERIOD_CRITICAL_PODS"));
            if critical > total {
                warn.push(alloc::format!("shutdown-grace-period-critical-pods ({critical}s) exceeds shutdown-grace-period ({total}s); using {total}s"));
                critical = total;
            }
            if total > 0 {
                groups = alloc::vec![(0, total - critical), (SYSTEM_CRITICAL, critical)];
            }
        } else if get("KR_SHUTDOWN_GRACE_PERIOD").is_some() {
            warn.push(String::from("shutdown-grace-period-by-pod-priority is set: shutdown-grace-period and -critical-pods are ignored"));
        }
        groups.sort();
        groups.dedup_by_key(|g| g.0);
        (Config { groups }, warn)
    }

    pub fn from_env() -> (Config, Vec<String>) {
        Config::from(&|k| kr_runtime::store::env_var(k))
    }

    pub fn enabled(&self) -> bool {
        self.total() > 0
    }

    /// The whole shutdown budget: what logind's InhibitDelayMaxSec must allow.
    pub fn total(&self) -> u64 {
        self.groups.iter().map(|g| g.1).sum()
    }

    /// The group of a pod: the one with the highest priority not above the pod's (the lowest
    /// group for pods below every group).
    pub fn group_of(&self, priority: i64) -> usize {
        self.groups.iter().rposition(|g| g.0 <= priority).unwrap_or(0)
    }

    /// The grace period a pod gets: its own, capped by its group's.
    pub fn grace(&self, group: usize, pod_grace: u64) -> u64 {
        pod_grace.min(self.groups.get(group).map_or(0, |g| g.1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    fn cfg(vars: &[(&str, &str)]) -> (Config, Vec<String>) {
        Config::from(&|k| vars.iter().find(|(v, _)| *v == k).map(|(_, x)| x.to_string()))
    }

    #[test]
    fn critical_and_regular_groups() {
        let (c, w) = cfg(&[("KR_SHUTDOWN_GRACE_PERIOD", "30"), ("KR_SHUTDOWN_GRACE_PERIOD_CRITICAL_PODS", "10")]);
        assert!(w.is_empty() && c.enabled());
        assert_eq!(c.groups, [(0, 20), (SYSTEM_CRITICAL, 10)]);
        assert_eq!(c.total(), 30);
        assert_eq!(c.group_of(-5), 0);
        assert_eq!(c.group_of(1000), 0);
        assert_eq!(c.group_of(SYSTEM_CRITICAL + 1000), 1);
        assert_eq!(c.grace(0, 30), 20);
        assert_eq!(c.grace(1, 5), 5);
        assert!(!cfg(&[]).0.enabled());
        let (c, w) = cfg(&[("KR_SHUTDOWN_GRACE_PERIOD", "10"), ("KR_SHUTDOWN_GRACE_PERIOD_CRITICAL_PODS", "20")]);
        assert_eq!((c.groups, w.len()), (alloc::vec![(0, 0), (SYSTEM_CRITICAL, 10)], 1));
    }

    #[test]
    fn by_priority() {
        let (c, _) = cfg(&[("KR_SHUTDOWN_GRACE_PERIOD_BY_POD_PRIORITY", "100000=10,0=60,2000000000=5")]);
        assert_eq!(c.groups, [(0, 60), (100_000, 10), (SYSTEM_CRITICAL, 5)]);
        assert_eq!(c.group_of(99_999), 0);
        assert_eq!(c.group_of(100_000), 1);
        assert_eq!(c.total(), 75);
    }
}
