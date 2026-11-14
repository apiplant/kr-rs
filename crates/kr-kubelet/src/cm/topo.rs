//! CPU topology from sysfs (`/sys/devices/system/{cpu,node}`) and the CPU manager's choice of
//! CPUs: whole sockets first, then whole physical cores, then single threads, packed onto the
//! sockets and cores that are already the most used (upstream `takeByTopology`).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use kr_runtime::cpuset::CpuSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cpu {
    pub id: usize,
    /// Index of the physical core (unique across sockets).
    pub core: usize,
    pub socket: usize,
    pub numa: usize,
}

#[derive(Clone, Debug, Default)]
pub struct Topology {
    /// Online CPUs, by id.
    pub cpus: Vec<Cpu>,
    /// NUMA node id -> MemTotal in bytes.
    pub numa_mem: BTreeMap<usize, u64>,
}

impl Topology {
    /// Reads the topology; `read(rel)` returns the text of `/sys/<rel>` (None if absent).
    /// Without NUMA information every CPU is on node 0 with `fallback_mem` bytes.
    pub fn read_with(read: &dyn Fn(&str) -> Option<String>, fallback_mem: u64) -> Option<Topology> {
        let online = CpuSet::parse(&read("devices/system/cpu/online")?)?;
        let mut numa_of: BTreeMap<usize, usize> = BTreeMap::new();
        let mut numa_mem = BTreeMap::new();
        if let Some(nodes) = read("devices/system/node/online").and_then(|s| CpuSet::parse(&s)) {
            for n in nodes.iter() {
                let Some(list) = read(&alloc::format!("devices/system/node/node{n}/cpulist")).and_then(|s| CpuSet::parse(&s)) else { continue };
                for c in list.iter() {
                    numa_of.insert(c, n);
                }
                // "Node 0 MemTotal:       16326856 kB"
                let mem = read(&alloc::format!("devices/system/node/node{n}/meminfo"))
                    .and_then(|m| m.lines().find_map(|l| l.split_once("MemTotal:").map(|(_, v)| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())).flatten())
                    .unwrap_or(0);
                numa_mem.insert(n, mem * 1024);
            }
        }
        if numa_mem.is_empty() {
            numa_mem.insert(0, fallback_mem);
        }
        let mut cores: BTreeMap<(usize, i64), usize> = BTreeMap::new();
        let mut cpus = Vec::new();
        for id in online.iter() {
            let num = |f: &str| read(&alloc::format!("devices/system/cpu/cpu{id}/topology/{f}")).and_then(|s| s.trim().parse::<i64>().ok());
            let socket = num("physical_package_id").unwrap_or(0).max(0) as usize;
            // Without core_id every CPU is its own core.
            let core_id = num("core_id").unwrap_or(-1 - id as i64);
            let n = cores.len();
            let core = *cores.entry((socket, core_id)).or_insert(n);
            cpus.push(Cpu { id, core, socket, numa: numa_of.get(&id).copied().unwrap_or(0) });
        }
        if cpus.is_empty() {
            return None;
        }
        Some(Topology { cpus, numa_mem })
    }

    /// The real topology of this machine.
    pub fn read() -> Option<Topology> {
        let read = |rel: &str| {
            let p = alloc::format!("/sys/{rel}\0");
            kr_sys::fs::read_file(p.as_bytes(), 1 << 16).ok().and_then(|b| String::from_utf8(b).ok())
        };
        Topology::read_with(&read, crate::node::memory_ki() * 1024)
    }

    pub fn all(&self) -> CpuSet {
        CpuSet::from_iter(self.cpus.iter().map(|c| c.id))
    }

    /// NUMA node ids (sorted).
    pub fn numa_nodes(&self) -> Vec<usize> {
        let mut v: Vec<usize> = self.cpus.iter().map(|c| c.numa).chain(self.numa_mem.keys().copied()).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Bit mask of every NUMA node.
    pub fn numa_mask(&self) -> u64 {
        self.numa_nodes().iter().filter(|n| **n < 64).fold(0, |m, n| m | 1 << n)
    }

    /// CPUs on the NUMA nodes of `mask`.
    pub fn cpus_in(&self, mask: u64) -> CpuSet {
        CpuSet::from_iter(self.cpus.iter().filter(|c| c.numa < 64 && mask & (1 << c.numa) != 0).map(|c| c.id))
    }

    /// NUMA nodes of the CPUs in `set`, as a mask.
    pub fn mask_of(&self, set: &CpuSet) -> u64 {
        self.cpus.iter().filter(|c| set.contains(c.id) && c.numa < 64).fold(0, |m, c| m | 1 << c.numa)
    }

    pub fn threads_per_core(&self) -> usize {
        let mut n: BTreeMap<usize, usize> = BTreeMap::new();
        for c in &self.cpus {
            *n.entry(c.core).or_default() += 1;
        }
        n.values().copied().max().unwrap_or(1)
    }

    fn cpus_where(&self, f: impl Fn(&Cpu) -> bool) -> CpuSet {
        CpuSet::from_iter(self.cpus.iter().filter(|c| f(c)).map(|c| c.id))
    }

    /// `n` CPUs out of `avail`: whole sockets, then whole cores, then threads (only whole cores
    /// with `full_cores`). None if `avail` cannot give them.
    pub fn take(&self, avail: &CpuSet, n: usize, full_cores: bool) -> Option<CpuSet> {
        if avail.len() < n {
            return None;
        }
        let mut out = CpuSet::default();
        let mut avail = *avail;
        let mut sockets: Vec<usize> = self.cpus.iter().map(|c| c.socket).collect();
        sockets.sort_unstable();
        sockets.dedup();
        // 1. Whole free sockets.
        for s in &sockets {
            let all = self.cpus_where(|c| c.socket == *s);
            if n - out.len() >= all.len() && all.is_subset(&avail) {
                out = out.union(&all);
                avail = avail.minus(&all);
            }
        }
        // 2. Whole free cores, from the socket with the fewest free CPUs first (packing).
        let mut cores: Vec<(usize, usize)> = self.cpus.iter().map(|c| (c.socket, c.core)).collect();
        cores.sort_unstable();
        cores.dedup();
        let free_in_socket = |avail: &CpuSet, s: usize| self.cpus_where(|c| c.socket == s).intersect(avail).len();
        let mut free_cores: Vec<(usize, usize, usize)> = cores
            .iter()
            .filter(|(_, core)| self.cpus_where(|c| c.core == *core).is_subset(&avail))
            .map(|(s, core)| (free_in_socket(&avail, *s), *s, *core))
            .collect();
        free_cores.sort_unstable();
        for (_, _, core) in free_cores {
            let all = self.cpus_where(|c| c.core == core);
            if n - out.len() >= all.len() {
                out = out.union(&all);
                avail = avail.minus(&all);
            }
        }
        if out.len() == n {
            return Some(out);
        }
        if full_cores {
            return None;
        }
        // 3. Threads: partly used cores first, then the fullest socket, then the lowest id.
        let mut rest: Vec<(usize, usize, usize, usize)> = self
            .cpus
            .iter()
            .filter(|c| avail.contains(c.id))
            .map(|c| (self.cpus_where(|x| x.core == c.core).intersect(&avail).len(), free_in_socket(&avail, c.socket), c.core, c.id))
            .collect();
        rest.sort_unstable();
        for (_, _, _, id) in rest.into_iter().take(n - out.len()) {
            out.insert(id);
        }
        (out.len() == n).then_some(out)
    }

    /// Whole free cores in `avail` (for the full-pcpus-only error message).
    pub fn free_cores(&self, avail: &CpuSet) -> usize {
        let mut cores: Vec<usize> = self.cpus.iter().map(|c| c.core).collect();
        cores.sort_unstable();
        cores.dedup();
        cores.iter().filter(|core| self.cpus_where(|c| c.core == **core).is_subset(avail)).count()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A sysfs tree: 2 sockets x 2 cores x 2 threads, one NUMA node per socket. CPU i and i+4
    /// are siblings (Intel numbering).
    pub(crate) fn two_socket_smt() -> Topology {
        let mut files: Vec<(String, String)> = alloc::vec![
            ("devices/system/cpu/online".into(), "0-7\n".into()),
            ("devices/system/node/online".into(), "0-1\n".into()),
            ("devices/system/node/node0/cpulist".into(), "0-1,4-5\n".into()),
            ("devices/system/node/node1/cpulist".into(), "2-3,6-7\n".into()),
            ("devices/system/node/node0/meminfo".into(), "Node 0 MemTotal:        8388608 kB\nNode 0 MemFree: 1 kB\n".into()),
            ("devices/system/node/node1/meminfo".into(), "Node 1 MemTotal:        4194304 kB\n".into()),
        ];
        for id in 0..8usize {
            let (socket, core) = ((id % 4) / 2, id % 2);
            files.push((alloc::format!("devices/system/cpu/cpu{id}/topology/physical_package_id"), alloc::format!("{socket}\n")));
            files.push((alloc::format!("devices/system/cpu/cpu{id}/topology/core_id"), alloc::format!("{core}\n")));
        }
        let read = |p: &str| files.iter().find(|(f, _)| f == p).map(|(_, t)| t.clone());
        Topology::read_with(&read, 0).unwrap()
    }

    #[test]
    fn parses_sockets_cores_numa_and_siblings() {
        let t = two_socket_smt();
        assert_eq!(t.cpus.len(), 8);
        assert_eq!(t.threads_per_core(), 2);
        assert_eq!(t.numa_nodes(), [0, 1]);
        assert_eq!(t.numa_mem[&0], 8 << 30);
        assert_eq!(t.numa_mem[&1], 4 << 30);
        let c4 = t.cpus.iter().find(|c| c.id == 4).unwrap();
        let c0 = t.cpus.iter().find(|c| c.id == 0).unwrap();
        assert_eq!((c4.core, c4.socket, c4.numa), (c0.core, 0, 0));
        assert_eq!(t.cpus_in(0b10).to_list(), "2-3,6-7");
        assert_eq!(t.mask_of(&CpuSet::from_iter([1, 6])), 0b11);
    }

    #[test]
    fn without_numa_or_core_ids() {
        let read = |p: &str| (p == "devices/system/cpu/online").then(|| String::from("0-3"));
        let t = Topology::read_with(&read, 1000).unwrap();
        assert_eq!(t.numa_nodes(), [0]);
        assert_eq!(t.numa_mem[&0], 1000);
        assert_eq!(t.threads_per_core(), 1);
        assert!(Topology::read_with(&|_| None, 0).is_none());
    }

    #[test]
    fn allocation_prefers_sockets_then_cores_then_threads() {
        let t = two_socket_smt();
        let all = t.all();
        // A whole socket.
        assert_eq!(t.take(&all, 4, false).unwrap().to_list(), "0-1,4-5");
        // Two threads: one whole core.
        assert_eq!(t.take(&all, 2, false).unwrap().to_list(), "0,4");
        // CPU 0 used (reserved): the single thread goes to its sibling, keeping cores whole.
        let avail = all.minus(&CpuSet::from_iter([0]));
        assert_eq!(t.take(&avail, 1, false).unwrap().to_list(), "4");
        // Two CPUs with CPU 0 gone: a whole free core, on the fuller socket 0.
        assert_eq!(t.take(&avail, 2, false).unwrap().to_list(), "1,5");
        // Six: socket 1 whole (socket 0 is not free), then a whole core of socket 0.
        assert_eq!(t.take(&avail, 6, false).unwrap().to_list(), "1-3,5-7");
        // full-pcpus-only: three threads cannot be whole cores.
        assert!(t.take(&avail, 3, true).is_none());
        assert_eq!(t.take(&avail, 2, true).unwrap().to_list(), "1,5");
        assert!(t.take(&avail, 8, false).is_none());
        assert_eq!(t.free_cores(&avail), 3);
    }
}
