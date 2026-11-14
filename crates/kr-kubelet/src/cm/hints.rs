//! Topology manager: NUMA affinity hints of the hint providers (CPU manager, memory manager,
//! device plugins) merged per container under a policy, as upstream's `policy_*.go`.

use alloc::vec::Vec;

/// A NUMA affinity: `mask` has bit n for NUMA node n.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hint {
    pub mask: u64,
    pub preferred: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    None,
    BestEffort,
    Restricted,
    SingleNuma,
}

impl Policy {
    pub fn parse(s: &str) -> Option<Policy> {
        Some(match s {
            "" | "none" => Policy::None,
            "best-effort" => Policy::BestEffort,
            "restricted" => Policy::Restricted,
            "single-numa-node" => Policy::SingleNuma,
            _ => return None,
        })
    }
}

/// Every non-empty subset of the nodes in `all` (a mask), narrowest first.
pub fn masks(all: u64) -> Vec<u64> {
    let nodes: Vec<u32> = (0..64).filter(|n| all & (1 << n) != 0).collect();
    let mut out: Vec<u64> = (1u64..(1 << nodes.len())).map(|sel| nodes.iter().enumerate().filter(|(i, _)| sel & (1 << i) != 0).fold(0, |m, (_, n)| m | 1 << n)).collect();
    out.sort_by_key(|m| (m.count_ones(), *m));
    out
}

/// The hints of one resource request: every NUMA combination where `fits` (enough free), marked
/// preferred when it is as narrow as the narrowest combination where `could_fit` (enough in
/// total, free or not). Empty when nothing fits: the request cannot be aligned right now.
pub fn generate(all: u64, fits: &dyn Fn(u64) -> bool, could_fit: &dyn Fn(u64) -> bool) -> Vec<Hint> {
    let ms = masks(all);
    let min = ms.iter().filter(|m| could_fit(**m)).map(|m| m.count_ones()).min().unwrap_or(u32::MAX);
    ms.into_iter().filter(|m| fits(*m)).map(|m| Hint { mask: m, preferred: m.count_ones() == min }).collect()
}

/// Merges the providers' hint lists (one list per resource with a NUMA preference; resources
/// without one are simply absent) into the best hint, and whether the policy admits it.
pub fn merge(policy: Policy, all: u64, lists: &[Vec<Hint>]) -> (Hint, bool) {
    // A resource with no possible alignment counts as "any NUMA node, not preferred".
    let mut lists: Vec<Vec<Hint>> = lists.iter().map(|l| if l.is_empty() { alloc::vec![Hint { mask: all, preferred: false }] } else { l.clone() }).collect();
    if policy == Policy::SingleNuma {
        for l in lists.iter_mut() {
            l.retain(|h| h.preferred && h.mask.count_ones() == 1);
            if l.is_empty() {
                l.push(Hint { mask: all, preferred: false });
            }
        }
    }
    let mut best = Hint { mask: all, preferred: false };
    let mut idx = alloc::vec![0usize; lists.len()];
    loop {
        // One permutation: one hint from each list.
        let (mut mask, mut preferred) = (all, true);
        for (l, i) in lists.iter().zip(&idx) {
            mask &= l[*i].mask;
            preferred &= l[*i].preferred;
        }
        if mask != 0 {
            let cand = Hint { mask, preferred };
            let narrower = (cand.mask.count_ones(), cand.mask) < (best.mask.count_ones(), best.mask);
            if (cand.preferred && !best.preferred) || (cand.preferred == best.preferred && narrower) {
                best = cand;
            }
        }
        // Next permutation (odometer); done after the last.
        let mut k = 0;
        while k < lists.len() {
            idx[k] += 1;
            if idx[k] < lists[k].len() {
                break;
            }
            idx[k] = 0;
            k += 1;
        }
        if k == lists.len() {
            break;
        }
    }
    let admit = match policy {
        Policy::None | Policy::BestEffort => true,
        // Under single-numa-node a preferred permutation is single-node (or there were no lists).
        Policy::Restricted | Policy::SingleNuma => best.preferred,
    };
    (best, admit)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: u64 = 0b11;

    fn h(mask: u64, preferred: bool) -> Hint {
        Hint { mask, preferred }
    }

    #[test]
    fn masks_narrowest_first() {
        assert_eq!(masks(0b101), [0b001, 0b100, 0b101]);
        assert_eq!(masks(0b11).len(), 3);
    }

    #[test]
    fn generated_hints() {
        // 4 free CPUs on node 0, 1 on node 1; 4 in total on each. A request for 2.
        let free = |m: u64| (if m & 1 != 0 { 4 } else { 0 }) + (if m & 2 != 0 { 1 } else { 0 });
        let hints = generate(ALL, &|m| free(m) >= 2, &|m| m.count_ones() * 4 >= 2);
        assert_eq!(hints, [h(0b01, true), h(0b11, false)]);
        // A request for 6 needs both nodes: preferred there.
        let hints = generate(ALL, &|m| free(m) >= 5, &|m| m.count_ones() * 4 >= 6);
        assert_eq!(hints, [h(0b11, true)]);
        assert!(generate(ALL, &|_| false, &|_| true).is_empty());
    }

    #[test]
    fn merging_picks_preferred_then_narrowest() {
        let cpu = alloc::vec![h(0b01, true), h(0b10, true), h(0b11, false)];
        let gpu = alloc::vec![h(0b10, true), h(0b11, false)];
        assert_eq!(merge(Policy::BestEffort, ALL, &[cpu.clone(), gpu.clone()]), (h(0b10, true), true));
        // No list at all: any node, preferred.
        assert_eq!(merge(Policy::Restricted, ALL, &[]), (h(ALL, true), true));
        // CPUs only on node 0, the device only on node 1: no preferred alignment.
        let cpu0 = alloc::vec![h(0b01, true), h(0b11, false)];
        let (best, _) = merge(Policy::BestEffort, ALL, &[cpu0.clone(), gpu.clone()]);
        assert_eq!(best, h(0b01, false));
        assert!(merge(Policy::BestEffort, ALL, &[cpu0.clone(), gpu.clone()]).1);
        assert!(!merge(Policy::Restricted, ALL, &[cpu0.clone(), gpu.clone()]).1);
        assert!(!merge(Policy::SingleNuma, ALL, &[cpu0, gpu]).1);
        // A request that needs both nodes is fine for restricted, not for single-numa-node.
        let wide = alloc::vec![h(0b11, true)];
        assert!(merge(Policy::Restricted, ALL, &[wide.clone()]).1);
        let (best, admit) = merge(Policy::SingleNuma, ALL, &[wide]);
        assert_eq!((best, admit), (h(ALL, false), false));
        // Nothing can be aligned (empty list): best effort admits, restricted does not.
        assert_eq!(merge(Policy::BestEffort, ALL, &[Vec::new()]), (h(ALL, false), true));
        assert!(!merge(Policy::Restricted, ALL, &[Vec::new()]).1);
        // single-numa-node with two single-node hints picks the lower node.
        assert_eq!(merge(Policy::SingleNuma, ALL, &[cpu]), (h(0b01, true), true));
    }
}
