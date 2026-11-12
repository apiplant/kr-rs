//! Memory-pressure eviction (upstream hard eviction, simplified): the pure decisions. The
//! kubelet feeds in MemAvailable and per-pod usage and acts on the result.

use alloc::string::String;

/// Upstream's default hard eviction threshold: memory.available < 100Mi.
pub const DEFAULT_MEMORY_AVAILABLE: u64 = 100 << 20;

/// Taint set on the node while under memory pressure.
pub const TAINT_KEY: &str = "node.kubernetes.io/memory-pressure";

/// Threshold in bytes: `KR_EVICTION_MEMORY_AVAILABLE` (a quantity, e.g. `1000Gi`) or the default.
pub fn threshold_from_env() -> u64 {
    kr_runtime::store::env_var("KR_EVICTION_MEMORY_AVAILABLE")
        .and_then(|s| kr_fmt::quantity::Quantity::parse(&s).ok())
        .and_then(|q| q.value())
        .and_then(|v| u64::try_from(v).ok())
        .unwrap_or(DEFAULT_MEMORY_AVAILABLE)
}

/// Seconds a device must stay unhealthy before its pods are failed (`KR_DEVICE_UNHEALTHY_GRACE`,
/// default 30; 0 = immediately). A flapping device (transient XID) then does not kill pods.
pub fn device_grace_ms() -> u64 {
    kr_runtime::store::env_var("KR_DEVICE_UNHEALTHY_GRACE").and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(30).saturating_mul(1000)
}

/// Seconds a pod whose PodDisruptionBudget forbids its eviction may keep an unhealthy device
/// before it is failed anyway (`KR_DEVICE_UNHEALTHY_PDB_WAIT`, default 600).
pub fn device_pdb_wait_ms() -> u64 {
    kr_runtime::store::env_var("KR_DEVICE_UNHEALTHY_PDB_WAIT").and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(600).saturating_mul(1000)
}

/// What to do with a pod on an unhealthy device after asking the eviction API.
#[derive(Debug, PartialEq, Eq)]
pub enum DeviceEviction {
    /// The pod is being deleted (or is gone).
    Evicted,
    /// A PodDisruptionBudget has no room yet: ask again later.
    Wait,
    /// Not possible (no permission, API error) or waited long enough: fail the pod in place.
    Fail,
}

/// `answer`: the HTTP status of the eviction request, None for success. `blocked_since` is when
/// a budget first refused this pod (set here).
pub fn device_eviction(answer: Option<u16>, blocked_since: &mut Option<u64>, now_ms: u64, wait_ms: u64) -> DeviceEviction {
    match answer {
        None => DeviceEviction::Evicted,
        Some(429) => {
            let first = *blocked_since.get_or_insert(now_ms);
            if now_ms.saturating_sub(first) < wait_ms {
                DeviceEviction::Wait
            } else {
                DeviceEviction::Fail
            }
        }
        Some(_) => DeviceEviction::Fail,
    }
}

/// Remembers since when pods have continuously held an unhealthy device.
#[derive(Default)]
pub struct DeviceGrace {
    since: alloc::collections::BTreeMap<alloc::string::String, u64>,
}

impl DeviceGrace {
    /// `bad` are the uids unhealthy right now: returns those unhealthy for at least `grace_ms`
    /// and forgets the ones that recovered.
    pub fn due(&mut self, bad: &[alloc::string::String], now_ms: u64, grace_ms: u64) -> alloc::vec::Vec<alloc::string::String> {
        self.since.retain(|u, _| bad.contains(u));
        bad.iter().filter(|u| now_ms.saturating_sub(*self.since.entry((*u).clone()).or_insert(now_ms)) >= grace_ms).cloned().collect()
    }
}

/// Whether MemAvailable (KiB; None when unreadable) is below the threshold (bytes).
pub fn under_pressure(available_ki: Option<u64>, threshold_bytes: u64) -> bool {
    available_ki.is_some_and(|a| a.saturating_mul(1024) < threshold_bytes)
}

/// Tracks whether the node taint is set. `observe` returns the new state when it changed.
#[derive(Default)]
pub struct PressureState {
    pub active: bool,
}

impl PressureState {
    pub fn observe(&mut self, pressure: bool) -> Option<bool> {
        if pressure == self.active {
            return None;
        }
        self.active = pressure;
        Some(pressure)
    }
}

#[derive(Clone, Debug)]
pub struct Candidate {
    pub uid: String,
    /// "Guaranteed", "Burstable" or "BestEffort".
    pub qos: &'static str,
    pub usage: u64,
    pub request: u64,
    /// system-node-critical / system-cluster-critical (or a static pod): never evicted.
    pub critical: bool,
}

fn rank(qos: &str) -> u8 {
    match qos {
        "BestEffort" => 0,
        "Burstable" => 1,
        _ => 2,
    }
}

/// The pod to evict: BestEffort first, then Burstable and Guaranteed pods that use more than
/// they request; within a class, the largest usage above the request first.
pub fn pick(cands: &[Candidate]) -> Option<&Candidate> {
    cands
        .iter()
        .filter(|c| !c.critical && (c.qos == "BestEffort" || c.usage > c.request))
        .min_by_key(|c| (rank(c.qos), core::cmp::Reverse(c.usage.saturating_sub(c.request))))
}

pub fn message(threshold: u64) -> String {
    alloc::format!("The node was low on resource: memory. Threshold quantity: {threshold}, available is lower.")
}


#[cfg(test)]
mod tests {
    #[test]
    fn device_eviction_waits_for_a_budget_then_fails_in_place() {
        let mut since = None;
        assert_eq!(device_eviction(None, &mut since, 1000, 600_000), DeviceEviction::Evicted);
        assert_eq!(device_eviction(Some(429), &mut since, 1000, 600_000), DeviceEviction::Wait);
        assert_eq!(since, Some(1000));
        assert_eq!(device_eviction(Some(429), &mut since, 599_999, 600_000), DeviceEviction::Wait);
        assert_eq!(device_eviction(Some(429), &mut since, 601_000, 600_000), DeviceEviction::Fail);
        // No permission or any other failure: fail at once.
        assert_eq!(device_eviction(Some(403), &mut None, 0, 600_000), DeviceEviction::Fail);
        // A wait of zero never waits.
        assert_eq!(device_eviction(Some(429), &mut None, 5, 0), DeviceEviction::Fail);
    }

    use super::*;

    fn c(uid: &str, qos: &'static str, usage: u64, request: u64) -> Candidate {
        Candidate { uid: uid.into(), qos, usage, request, critical: false }
    }

    #[test]
    fn threshold() {
        assert!(under_pressure(Some(100 * 1024 - 1), DEFAULT_MEMORY_AVAILABLE));
        assert!(!under_pressure(Some(100 * 1024), DEFAULT_MEMORY_AVAILABLE));
        assert!(!under_pressure(None, DEFAULT_MEMORY_AVAILABLE));
    }

    #[test]
    fn state_machine() {
        let mut s = PressureState::default();
        assert_eq!(s.observe(false), None);
        assert_eq!(s.observe(true), Some(true));
        assert_eq!(s.observe(true), None);
        assert_eq!(s.observe(false), Some(false));
    }

    #[test]
    fn ranking() {
        let v = alloc::vec![c("g", "Guaranteed", 300, 200), c("b-small", "Burstable", 150, 100), c("b-big", "Burstable", 900, 100), c("be", "BestEffort", 10, 0)];
        assert_eq!(pick(&v).unwrap().uid, "be");
        let v = alloc::vec![c("g", "Guaranteed", 300, 200), c("b-small", "Burstable", 150, 100), c("b-big", "Burstable", 900, 100)];
        assert_eq!(pick(&v).unwrap().uid, "b-big");
        // Burstable within its request is spared; Guaranteed within its request too.
        let v = alloc::vec![c("g", "Guaranteed", 100, 200), c("b", "Burstable", 100, 100)];
        assert!(pick(&v).is_none());
        let v = alloc::vec![c("g", "Guaranteed", 300, 200), c("b", "Burstable", 100, 100)];
        assert_eq!(pick(&v).unwrap().uid, "g");
    }

    #[test]
    fn critical_never_evicted() {
        let mut be = c("be", "BestEffort", 10, 0);
        be.critical = true;
        assert!(pick(&[be]).is_none());
    }

    #[test]
    fn device_grace() {
        let mut g = DeviceGrace::default();
        let a = alloc::vec![alloc::string::String::from("a")];
        assert!(g.due(&a, 1000, 30_000).is_empty());
        assert!(g.due(&a, 20_000, 30_000).is_empty());
        assert!(g.due(&[], 25_000, 30_000).is_empty()); // recovered: forgotten
        assert!(g.due(&a, 40_000, 30_000).is_empty()); // clock restarts
        assert_eq!(g.due(&a, 70_000, 30_000), a);
        assert_eq!(DeviceGrace::default().due(&a, 5, 0), a); // grace 0: immediately
    }
}
