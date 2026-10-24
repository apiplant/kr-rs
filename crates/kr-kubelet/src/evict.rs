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
}
