//! A set of CPU (or NUMA node) numbers, as written to `cpuset.cpus` / `cpuset.mems` in the
//! kernel's list format (`0-3,8,10-11`). Fixed size (1024 entries) so that it is `Copy` and can
//! sit in [`crate::cgroup::Limits`].

use alloc::string::String;
use alloc::vec::Vec;

pub const MAX: usize = 1024;

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, PartialOrd, Ord)]
pub struct CpuSet([u64; MAX / 64]);

impl CpuSet {
    pub fn from_iter(it: impl IntoIterator<Item = usize>) -> CpuSet {
        let mut s = CpuSet::default();
        for c in it {
            s.insert(c);
        }
        s
    }

    pub fn insert(&mut self, c: usize) {
        if c < MAX {
            self.0[c / 64] |= 1 << (c % 64);
        }
    }

    pub fn remove(&mut self, c: usize) {
        if c < MAX {
            self.0[c / 64] &= !(1 << (c % 64));
        }
    }

    pub fn contains(&self, c: usize) -> bool {
        c < MAX && self.0[c / 64] & (1 << (c % 64)) != 0
    }

    pub fn len(&self) -> usize {
        self.0.iter().map(|w| w.count_ones() as usize).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|w| *w == 0)
    }

    pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        (0..MAX).filter(|c| self.contains(*c))
    }

    fn zip(&self, o: &CpuSet, f: impl Fn(u64, u64) -> u64) -> CpuSet {
        let mut r = CpuSet::default();
        for i in 0..self.0.len() {
            r.0[i] = f(self.0[i], o.0[i]);
        }
        r
    }

    pub fn union(&self, o: &CpuSet) -> CpuSet {
        self.zip(o, |a, b| a | b)
    }

    pub fn intersect(&self, o: &CpuSet) -> CpuSet {
        self.zip(o, |a, b| a & b)
    }

    pub fn minus(&self, o: &CpuSet) -> CpuSet {
        self.zip(o, |a, b| a & !b)
    }

    pub fn is_subset(&self, o: &CpuSet) -> bool {
        self.minus(o).is_empty()
    }

    /// Kernel list format; empty for the empty set.
    pub fn to_list(&self) -> String {
        let mut out = String::new();
        let v: Vec<usize> = self.iter().collect();
        let mut i = 0;
        while i < v.len() {
            let mut j = i;
            while j + 1 < v.len() && v[j + 1] == v[j] + 1 {
                j += 1;
            }
            if !out.is_empty() {
                out.push(',');
            }
            if j > i {
                out.push_str(&alloc::format!("{}-{}", v[i], v[j]));
            } else {
                out.push_str(&alloc::format!("{}", v[i]));
            }
            i = j + 1;
        }
        out
    }

    /// Parses the list format (whitespace around it and an empty list are allowed).
    pub fn parse(s: &str) -> Option<CpuSet> {
        let mut r = CpuSet::default();
        for part in s.trim().split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let (a, b) = match part.split_once('-') {
                Some((a, b)) => (a.trim().parse::<usize>().ok()?, b.trim().parse::<usize>().ok()?),
                None => {
                    let n = part.parse::<usize>().ok()?;
                    (n, n)
                }
            };
            if a > b || b >= MAX {
                return None;
            }
            for c in a..=b {
                r.insert(c);
            }
        }
        Some(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_format_round_trip() {
        let s = CpuSet::parse(" 0-3,8, 10-11\n").unwrap();
        assert_eq!(s.len(), 7);
        assert_eq!(s.to_list(), "0-3,8,10-11");
        assert_eq!(CpuSet::parse("").unwrap().to_list(), "");
        assert!(CpuSet::parse("3-1").is_none());
        assert!(CpuSet::parse("x").is_none());
        assert!(CpuSet::parse("1024").is_none());
        let a = CpuSet::from_iter([1, 2, 3]);
        let b = CpuSet::from_iter([3, 4]);
        assert_eq!(a.union(&b).to_list(), "1-4");
        assert_eq!(a.minus(&b).to_list(), "1-2");
        assert_eq!(a.intersect(&b).to_list(), "3");
        assert!(CpuSet::from_iter([1]).is_subset(&a));
        assert_eq!(CpuSet::from_iter([1023, 64, 63]).to_list(), "63-64,1023");
    }
}
