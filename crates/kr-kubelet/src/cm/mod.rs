//! Container resource managers (#363): the CPU manager (`static`: exclusive CPUs for the
//! integer-CPU containers of Guaranteed pods, everyone else on the shared pool), the memory
//! manager (`Static`: NUMA memory pinning through cpuset.mems for Guaranteed pods) and the
//! topology manager (NUMA alignment of CPUs, memory and devices at container scope).
//!
//! Allocations are made at pod admission and kept in checkpoint files in the kubelet directory
//! (`cpu_manager_state`, `memory_manager_state`), so that containers adopted after a kubelet
//! restart keep their CPUs.

pub mod hints;
pub mod topo;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use hints::{Hint, Policy};
use kr_fmt::json::{self, Number, Value};
use kr_runtime::cpuset::CpuSet;
use topo::Topology;

pub const TOPOLOGY_ERROR: &str = "Resources cannot be allocated with Topology locality";

/// Configuration (ADR-060 settings).
#[derive(Clone, Debug, PartialEq)]
pub struct Settings {
    pub cpu_static: bool,
    pub full_pcpus: bool,
    pub reserved: Option<CpuSet>,
    pub mem_static: bool,
    /// NUMA node -> reserved bytes (`reserved-memory`).
    pub reserved_mem: BTreeMap<usize, u64>,
    pub topology: Policy,
}

fn quantity_bytes(q: &str) -> Option<u64> {
    kr_fmt::quantity::Quantity::parse(q.trim()).ok()?.value().and_then(|v| u64::try_from(v).ok())
}

impl Settings {
    /// From `get(var)` (the `KR_*` variables). Values were validated by the config layer;
    /// anything unusable here falls back to the default.
    pub fn from(get: &dyn Fn(&str) -> Option<String>) -> Settings {
        let mut reserved_mem = BTreeMap::new();
        for e in get("KR_RESERVED_MEMORY").unwrap_or_default().split(';') {
            let Some((n, rest)) = e.split_once(':') else { continue };
            let Ok(n) = n.trim().parse::<usize>() else { continue };
            for kv in rest.split(',') {
                if let Some(b) = kv.split_once('=').filter(|(k, _)| k.trim() == "memory").and_then(|(_, q)| quantity_bytes(q)) {
                    *reserved_mem.entry(n).or_insert(0) += b;
                }
            }
        }
        Settings {
            cpu_static: get("KR_CPU_MANAGER_POLICY").as_deref() == Some("static"),
            full_pcpus: get("KR_CPU_MANAGER_POLICY_OPTIONS").is_some_and(|o| o.split(',').any(|kv| kv.trim() == "full-pcpus-only=true")),
            reserved: get("KR_RESERVED_CPUS").and_then(|l| CpuSet::parse(&l)).filter(|s| !s.is_empty()),
            mem_static: get("KR_MEMORY_MANAGER_POLICY").as_deref() == Some("Static"),
            reserved_mem,
            topology: get("KR_TOPOLOGY_MANAGER_POLICY").and_then(|p| Policy::parse(&p)).unwrap_or(Policy::None),
        }
    }

    pub fn from_env() -> Settings {
        Settings::from(&|k| kr_runtime::store::env_var(k))
    }

    /// Any manager does something (otherwise the kubelet skips all of this).
    pub fn active(&self) -> bool {
        self.cpu_static || self.mem_static || self.topology != Policy::None
    }
}

/// What one container asks the managers for.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Need {
    pub name: String,
    /// A (non-restartable) init container: its CPUs may be reused by the pod's later containers.
    pub init: bool,
    /// Exclusive CPUs (0: shared pool).
    pub cpus: usize,
    /// Memory pinned by the memory manager (0: none).
    pub mem: u64,
    /// Device plugin resources and counts.
    pub devices: Vec<(String, usize)>,
}

/// The needs of a pod's containers (init containers first), as upstream decides them: exclusive
/// CPUs for an integer CPU request in a Guaranteed pod, memory pinning for Guaranteed pods.
pub fn needs(pod: &Value, s: &Settings, managed: &dyn Fn(&str) -> bool) -> Vec<Need> {
    let guaranteed = crate::spec::qos_class(pod) == "Guaranteed";
    let q = |v: Option<&Value>| v.and_then(|v| v.as_str().map(String::from).or_else(|| v.as_i64().map(|n| n.to_string()))).and_then(|s| kr_fmt::quantity::Quantity::parse(&s).ok());
    let mut out = Vec::new();
    for (key, init) in [("initContainers", true), ("containers", false)] {
        for c in pod.pointer(&["spec", key]).and_then(Value::as_array).unwrap_or(&[]) {
            let sidecar = init && c.get("restartPolicy").and_then(Value::as_str) == Some("Always");
            let milli = q(c.pointer(&["resources", "requests", "cpu"])).or_else(|| q(c.pointer(&["resources", "limits", "cpu"]))).and_then(|q| q.milli_value()).and_then(|v| u64::try_from(v).ok()).unwrap_or(0);
            let cpus = if s.cpu_static && guaranteed && milli > 0 && milli % 1000 == 0 { (milli / 1000) as usize } else { 0 };
            let mem = if s.mem_static && guaranteed { q(c.pointer(&["resources", "limits", "memory"])).and_then(|q| q.value()).and_then(|v| u64::try_from(v).ok()).unwrap_or(0) } else { 0 };
            let devices = c
                .pointer(&["resources", "limits"])
                .and_then(Value::as_object)
                .unwrap_or(&[])
                .iter()
                .filter(|(k, _)| managed(k))
                .filter_map(|(k, v)| Some((k.clone(), q(Some(v))?.value().and_then(|v| usize::try_from(v).ok())?)))
                .filter(|(_, n)| *n > 0)
                .collect();
            out.push(Need { name: c.get("name").and_then(Value::as_str).unwrap_or("").to_string(), init: init && !sidecar, cpus, mem, devices });
        }
    }
    out
}

/// NUMA nodes of a device plugin resource's healthy devices (-1: unknown), of the free ones, and
/// of those the container already holds.
#[derive(Clone, Debug, Default)]
pub struct DevTopo {
    pub all: Vec<i64>,
    pub free: Vec<i64>,
    pub held: Vec<i64>,
}

type Key = (String, String);

pub struct Manager {
    pub s: Settings,
    pub topo: Topology,
    reserved: CpuSet,
    cpus: BTreeMap<Key, CpuSet>,
    /// Per container: (NUMA node, bytes) for every node of its affinity.
    mem: BTreeMap<Key, Vec<(usize, u64)>>,
    /// Topology manager's choice per container, for the device allocation that follows.
    pub affinity: BTreeMap<Key, u64>,
    /// Kubelet directory of the checkpoint files ("" in tests: nothing is written).
    root: String,
}

fn count_in(nodes: &[i64], mask: u64) -> usize {
    nodes.iter().filter(|n| (0..64).contains(*n) && mask & (1 << **n) != 0).count()
}

impl Manager {
    /// A manager for `topo`; returns warnings to log (defaults taken, checkpoint discarded).
    pub fn new(s: Settings, topo: Topology, root: &str) -> (Manager, Vec<String>) {
        let mut warn = Vec::new();
        let all = topo.all();
        let reserved = match s.reserved {
            Some(r) if r.is_subset(&all) => r,
            Some(r) => {
                warn.push(alloc::format!("reserved-cpus {} includes CPUs that are not online; using {}", r.to_list(), r.intersect(&all).to_list()));
                r.intersect(&all)
            }
            None if s.cpu_static => {
                // Upstream refuses a static policy without a reservation; kr keeps one CPU for
                // the shared pool (the system, the kubelet, Burstable and BestEffort pods).
                let r = topo.take(&all, 1, false).unwrap_or_default();
                warn.push(alloc::format!("cpu-manager-policy static without reserved-cpus: reserving CPU {}", r.to_list()));
                r
            }
            None => CpuSet::default(),
        };
        let mut m = Manager { s, topo, reserved, cpus: BTreeMap::new(), mem: BTreeMap::new(), affinity: BTreeMap::new(), root: root.to_string() };
        if m.s.topology != Policy::None && m.topo.numa_nodes().len() > 8 {
            warn.push(String::from("more than 8 NUMA nodes: the topology manager is off (as upstream)"));
            m.s.topology = Policy::None;
        }
        if !root.is_empty() {
            let read = |f: &str| kr_sys::fs::read_file(alloc::format!("{root}/{f}\0").as_bytes(), 1 << 22).ok().and_then(|b| String::from_utf8(b).ok());
            if let Some(t) = read("cpu_manager_state") {
                if let Err(e) = m.load_cpu(&t) {
                    warn.push(alloc::format!("CPU manager checkpoint discarded: {e}"));
                }
            }
            if let Some(t) = read("memory_manager_state") {
                if let Err(e) = m.load_mem(&t) {
                    warn.push(alloc::format!("memory manager checkpoint discarded: {e}"));
                }
            }
        }
        (m, warn)
    }

    /// CPUs of the shared pool: every online CPU but the exclusive ones (reserved ones included).
    pub fn shared(&self) -> CpuSet {
        self.cpus.values().fold(self.topo.all(), |a, c| a.minus(c))
    }

    /// The container's cpuset.cpus: its exclusive CPUs, else the shared pool (None without the
    /// static policy).
    pub fn cpus_for(&self, uid: &str, ctr: &str) -> Option<CpuSet> {
        if !self.s.cpu_static {
            return None;
        }
        Some(self.cpus.get(&(uid.to_string(), ctr.to_string())).copied().unwrap_or_else(|| self.shared()))
    }

    pub fn exclusive(&self, uid: &str, ctr: &str) -> Option<CpuSet> {
        self.cpus.get(&(uid.to_string(), ctr.to_string())).copied()
    }

    /// The container's cpuset.mems (memory manager), if pinned.
    pub fn mems_for(&self, uid: &str, ctr: &str) -> Option<CpuSet> {
        self.mem.get(&(uid.to_string(), ctr.to_string())).map(|b| CpuSet::from_iter(b.iter().map(|(n, _)| *n)))
    }

    pub fn has_pod(&self, uid: &str) -> bool {
        self.cpus.keys().chain(self.mem.keys()).any(|k| k.0 == uid)
    }

    fn mem_alloc(&self, n: usize) -> u64 {
        self.topo.numa_mem.get(&n).copied().unwrap_or(0).saturating_sub(self.s.reserved_mem.get(&n).copied().unwrap_or(0))
    }

    fn mem_free(&self, n: usize) -> u64 {
        let used: u64 = self.mem.values().flat_map(|b| b.iter()).filter(|(x, _)| *x == n).map(|(_, b)| *b).sum();
        self.mem_alloc(n).saturating_sub(used)
    }

    fn nodes(mask: u64) -> impl Iterator<Item = usize> {
        (0..64usize).filter(move |n| mask & (1 << n) != 0)
    }

    /// CPUs a new exclusive allocation of `uid` may use: not reserved, not exclusive to another
    /// container, except the pod's own init containers (`reusable`; they ran before).
    fn avail(&self, uid: &str, reusable: &BTreeSet<&str>) -> CpuSet {
        let taken = self.cpus.iter().filter(|(k, _)| !(k.0 == uid && reusable.contains(k.1.as_str()))).fold(CpuSet::default(), |a, (_, c)| a.union(c));
        self.topo.all().minus(&self.reserved).minus(&taken)
    }

    fn cpu_hints(&self, uid: &str, n: &Need, reusable: &BTreeSet<&str>) -> Vec<Hint> {
        let all = self.topo.numa_mask();
        if let Some(c) = self.exclusive(uid, &n.name) {
            return alloc::vec![Hint { mask: self.topo.mask_of(&c), preferred: true }];
        }
        let avail = self.avail(uid, reusable);
        hints::generate(all, &|m| self.topo.cpus_in(m).intersect(&avail).len() >= n.cpus, &|m| self.topo.cpus_in(m).len() >= n.cpus)
    }

    fn mem_hints(&self, uid: &str, n: &Need) -> Vec<Hint> {
        let all = self.topo.numa_mask();
        if let Some(b) = self.mem.get(&(uid.to_string(), n.name.clone())) {
            return alloc::vec![Hint { mask: b.iter().fold(0, |m, (x, _)| m | 1 << x), preferred: true }];
        }
        hints::generate(all, &|m| Self::nodes(m).map(|x| self.mem_free(x)).sum::<u64>() >= n.mem, &|m| Self::nodes(m).map(|x| self.mem_alloc(x)).sum::<u64>() >= n.mem)
    }

    fn dev_hints(&self, d: &DevTopo, count: usize) -> Option<Vec<Hint>> {
        // A device without NUMA information: the resource has no preference.
        if d.all.is_empty() || d.all.iter().any(|n| !(0..64).contains(n)) {
            return None;
        }
        if d.held.len() == count {
            return Some(alloc::vec![Hint { mask: d.held.iter().fold(0, |m, n| m | 1 << n), preferred: true }]);
        }
        Some(hints::generate(self.topo.numa_mask(), &|m| count_in(&d.free, m) >= count, &|m| count_in(&d.all, m) >= count))
    }

    /// Admits a pod: merges the hints of each container, allocates its exclusive CPUs and pinned
    /// memory, and records the affinity for its devices. On an error nothing new is kept and the
    /// message is the pod's rejection message.
    pub fn admit(&mut self, uid: &str, needs: &[Need], dev: &dyn Fn(&str, &str) -> Option<DevTopo>) -> Result<(), String> {
        let mut new: Vec<Key> = Vec::new();
        let r = self.admit_inner(uid, needs, dev, &mut new);
        if r.is_err() {
            for k in &new {
                self.cpus.remove(k);
                self.mem.remove(k);
                self.affinity.remove(k);
            }
        }
        if !new.is_empty() && r.is_ok() {
            self.save();
        }
        r
    }

    fn admit_inner(&mut self, uid: &str, needs: &[Need], dev: &dyn Fn(&str, &str) -> Option<DevTopo>, new: &mut Vec<Key>) -> Result<(), String> {
        let inits: Vec<String> = needs.iter().filter(|n| n.init).map(|n| n.name.clone()).collect();
        let all = self.topo.numa_mask();
        for n in needs {
            let key = (uid.to_string(), n.name.clone());
            let reusable: BTreeSet<&str> = inits.iter().map(String::as_str).filter(|i| *i != n.name).collect();
            let affinity = if self.s.topology == Policy::None {
                None
            } else {
                let mut lists = Vec::new();
                if n.cpus > 0 {
                    lists.push(self.cpu_hints(uid, n, &reusable));
                }
                if n.mem > 0 {
                    lists.push(self.mem_hints(uid, n));
                }
                for (res, count) in &n.devices {
                    if let Some(h) = dev(res, &n.name).and_then(|d| self.dev_hints(&d, *count)) {
                        lists.push(h);
                    }
                }
                let (best, ok) = hints::merge(self.s.topology, all, &lists);
                if !ok {
                    return Err(TOPOLOGY_ERROR.into());
                }
                (best.mask != all).then_some(best.mask)
            };
            if n.cpus > 0 && self.exclusive(uid, &n.name).is_none() {
                let tpc = self.topo.threads_per_core();
                if self.s.full_pcpus && n.cpus % tpc != 0 {
                    return Err(alloc::format!("SMT Alignment Error: requested {} cpus not multiple cpus per core = {tpc}", n.cpus));
                }
                let avail = self.avail(uid, &reusable);
                let aligned = affinity.map(|m| avail.intersect(&self.topo.cpus_in(m)));
                let got = aligned.and_then(|a| self.topo.take(&a, n.cpus, self.s.full_pcpus)).or_else(|| self.topo.take(&avail, n.cpus, self.s.full_pcpus));
                let Some(got) = got else {
                    return Err(if self.s.full_pcpus {
                        alloc::format!("SMT Alignment Error: not enough free physical CPUs: available physical CPUs = {}, requested CPUs = {}, CPUs per core = {tpc}", self.topo.free_cores(&avail) * tpc, n.cpus)
                    } else {
                        alloc::format!("Allocate failed due to not enough cpus available to satisfy request: requested={}, available={}, which is unexpected", n.cpus, avail.len())
                    });
                };
                self.cpus.insert(key.clone(), got);
                new.push(key.clone());
            }
            if n.mem > 0 && !self.mem.contains_key(&key) {
                // The topology manager's choice, else the memory manager's own best hint.
                let mask = affinity.or_else(|| self.mem_hints(uid, n).iter().find(|h| h.preferred).or(self.mem_hints(uid, n).first()).map(|h| h.mask));
                let free = |m: u64| Self::nodes(m).map(|x| self.mem_free(x)).sum::<u64>();
                let Some(mask) = mask.filter(|m| free(*m) >= n.mem) else {
                    return Err(alloc::format!("Allocate failed due to [memorymanager] failed to find NUMA nodes with {} bytes of free memory, which is unexpected", n.mem));
                };
                let mut left = n.mem;
                let blocks: Vec<(usize, u64)> = Self::nodes(mask)
                    .map(|x| {
                        let take = left.min(self.mem_free(x));
                        left -= take;
                        (x, take)
                    })
                    .collect();
                self.mem.insert(key.clone(), blocks);
                new.push(key.clone());
            }
            if let Some(m) = affinity {
                self.affinity.insert(key.clone(), m);
                new.push(key);
            }
        }
        Ok(())
    }

    /// Forgets one container (a finished init container); true if something changed.
    pub fn release_ctr(&mut self, uid: &str, ctr: &str) -> bool {
        let k = (uid.to_string(), ctr.to_string());
        let changed = self.cpus.remove(&k).is_some() | self.mem.remove(&k).is_some();
        self.affinity.remove(&k);
        if changed {
            self.save();
        }
        changed
    }

    pub fn release_pod(&mut self, uid: &str) -> bool {
        self.retain(&|u| u != uid)
    }

    /// Keeps only the pods `keep` accepts (stale state after a restart); true if something changed.
    pub fn retain(&mut self, keep: &dyn Fn(&str) -> bool) -> bool {
        let n = self.cpus.len() + self.mem.len();
        self.cpus.retain(|k, _| keep(&k.0));
        self.mem.retain(|k, _| keep(&k.0));
        self.affinity.retain(|k, _| keep(&k.0));
        let changed = n != self.cpus.len() + self.mem.len();
        if changed {
            self.save();
        }
        changed
    }

    fn save(&self) {
        if self.root.is_empty() {
            return;
        }
        if self.s.cpu_static {
            let _ = kr_runtime::store::write_file_atomic(&alloc::format!("{}/cpu_manager_state", self.root), self.encode_cpu().as_bytes());
        }
        if self.s.mem_static {
            let _ = kr_runtime::store::write_file_atomic(&alloc::format!("{}/memory_manager_state", self.root), self.encode_mem().as_bytes());
        }
    }

    fn by_pod<T>(m: &BTreeMap<Key, T>, f: impl Fn(&T) -> Value) -> Value {
        let mut out: Vec<(String, Value)> = Vec::new();
        for ((uid, ctr), v) in m {
            if out.last().is_none_or(|(u, _)| u != uid) {
                out.push((uid.clone(), Value::Object(Vec::new())));
            }
            out.last_mut().unwrap().1.set(ctr, f(v));
        }
        Value::Object(out)
    }

    /// Upstream's `cpu_manager_state` layout (without the checksum, which only upstream reads).
    pub fn encode_cpu(&self) -> String {
        let v = Value::Object(alloc::vec![
            ("policyName".into(), Value::from(if self.s.cpu_static { "static" } else { "none" })),
            ("defaultCpuSet".into(), Value::String(self.shared().to_list())),
            ("entries".into(), Self::by_pod(&self.cpus, |c| Value::String(c.to_list()))),
        ]);
        json::to_string(&v)
    }

    /// Upstream's `memory_manager_state` entries: one block per NUMA node of the affinity.
    pub fn encode_mem(&self) -> String {
        let block = |(n, b): &(usize, u64)| Value::Object(alloc::vec![("numaAffinity".into(), Value::Array(alloc::vec![Value::Number(Number::from_u64(*n as u64))])), ("type".into(), Value::from("memory")), ("size".into(), Value::Number(Number::from_u64(*b)))]);
        let v = Value::Object(alloc::vec![("policyName".into(), Value::from(if self.s.mem_static { "Static" } else { "None" })), ("entries".into(), Self::by_pod(&self.mem, |bs: &Vec<(usize, u64)>| Value::Array(bs.iter().map(block).collect())))]);
        json::to_string(&v)
    }

    fn entries(v: &Value) -> Vec<(Key, &Value)> {
        v.get("entries").and_then(Value::as_object).unwrap_or(&[]).iter().flat_map(|(uid, cs)| cs.as_object().unwrap_or(&[]).iter().map(move |(c, x)| ((uid.clone(), c.clone()), x))).collect()
    }

    pub fn load_cpu(&mut self, text: &str) -> Result<(), String> {
        let v = json::parse(text.as_bytes()).map_err(|_| String::from("not JSON"))?;
        let policy = v.get("policyName").and_then(Value::as_str).unwrap_or("");
        if policy != if self.s.cpu_static { "static" } else { "none" } {
            return Err(alloc::format!("it was written by the {policy:?} policy"));
        }
        let all = self.topo.all().minus(&self.reserved);
        let mut cpus = BTreeMap::new();
        for (k, x) in Self::entries(&v) {
            let set = x.as_str().and_then(CpuSet::parse).filter(|s| s.is_subset(&all)).ok_or_else(|| alloc::format!("the CPUs of {}/{} are not assignable on this node", k.0, k.1))?;
            cpus.insert(k, set);
        }
        self.cpus = cpus;
        Ok(())
    }

    pub fn load_mem(&mut self, text: &str) -> Result<(), String> {
        let v = json::parse(text.as_bytes()).map_err(|_| String::from("not JSON"))?;
        let policy = v.get("policyName").and_then(Value::as_str).unwrap_or("");
        if policy != if self.s.mem_static { "Static" } else { "None" } {
            return Err(alloc::format!("it was written by the {policy:?} policy"));
        }
        let nodes = self.topo.numa_nodes();
        let mut mem = BTreeMap::new();
        for (k, x) in Self::entries(&v) {
            let mut blocks = Vec::new();
            for b in x.as_array().unwrap_or(&[]) {
                let n = b.pointer(&["numaAffinity"]).and_then(|a| a.at(0)).and_then(Value::as_u64).map(|n| n as usize).filter(|n| nodes.contains(n));
                let size = b.get("size").and_then(Value::as_u64);
                match (n, size) {
                    (Some(n), Some(s)) => blocks.push((n, s)),
                    _ => return Err(alloc::format!("a memory block of {}/{} is not valid on this node", k.0, k.1)),
                }
            }
            mem.insert(k, blocks);
        }
        self.mem = mem;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(cpu: bool, mem: bool, topo: Policy) -> Settings {
        Settings { cpu_static: cpu, full_pcpus: false, reserved: Some(CpuSet::from_iter([0, 4])), mem_static: mem, reserved_mem: BTreeMap::new(), topology: topo }
    }

    fn mgr(s: Settings) -> Manager {
        Manager::new(s, topo::tests::two_socket_smt(), "").0
    }

    fn need(name: &str, cpus: usize, mem: u64) -> Need {
        Need { name: name.into(), cpus, mem, ..Default::default() }
    }

    const NO_DEV: &dyn Fn(&str, &str) -> Option<DevTopo> = &|_, _| None;

    #[test]
    fn settings_from_variables() {
        let vars = [("KR_CPU_MANAGER_POLICY", "static"), ("KR_CPU_MANAGER_POLICY_OPTIONS", "full-pcpus-only=true"), ("KR_RESERVED_CPUS", "0,4"), ("KR_MEMORY_MANAGER_POLICY", "Static"), ("KR_RESERVED_MEMORY", "0:memory=1Gi;1:memory=512Mi,hugepages-2Mi=0"), ("KR_TOPOLOGY_MANAGER_POLICY", "restricted")];
        let s = Settings::from(&|k| vars.iter().find(|(v, _)| *v == k).map(|(_, x)| x.to_string()));
        assert!(s.cpu_static && s.full_pcpus && s.mem_static && s.active());
        assert_eq!(s.reserved.unwrap().to_list(), "0,4");
        assert_eq!(s.reserved_mem[&0], 1 << 30);
        assert_eq!(s.reserved_mem[&1], 512 << 20);
        assert_eq!(s.topology, Policy::Restricted);
        assert!(!Settings::from(&|_| None).active());
    }

    #[test]
    fn pod_needs_follow_qos_and_integer_cpus() {
        let s = settings(true, true, Policy::None);
        let pod = json::parse(br#"{"spec":{"initContainers":[{"name":"i","resources":{"limits":{"cpu":"1","memory":"1Gi"}}},{"name":"side","restartPolicy":"Always","resources":{"limits":{"cpu":"500m","memory":"1Gi"}}}],
            "containers":[{"name":"a","resources":{"limits":{"cpu":"2","memory":"2Gi","example.com/gpu":"1"}}}]},"status":{"qosClass":"Guaranteed"}}"#).unwrap();
        let n = needs(&pod, &s, &|r| r == "example.com/gpu");
        assert_eq!(n.len(), 3);
        assert_eq!((n[0].init, n[0].cpus, n[0].mem), (true, 1, 1 << 30));
        assert_eq!((n[1].init, n[1].cpus), (false, 0));
        assert_eq!((n[2].cpus, n[2].mem, n[2].devices.clone()), (2, 2 << 30, alloc::vec![("example.com/gpu".to_string(), 1)]));
        let burst = json::parse(br#"{"spec":{"containers":[{"name":"a","resources":{"requests":{"cpu":"2"}}}]},"status":{"qosClass":"Burstable"}}"#).unwrap();
        assert_eq!(needs(&burst, &s, &|_| false)[0].cpus, 0);
    }

    #[test]
    fn exclusive_cpus_and_shared_pool() {
        let mut m = mgr(settings(true, false, Policy::None));
        assert_eq!(m.cpus_for("p1", "a").unwrap().to_list(), "0-7");
        m.admit("p1", &[need("a", 2, 0)], NO_DEV).unwrap();
        let a = m.exclusive("p1", "a").unwrap();
        assert_eq!(a.len(), 2);
        assert!(!a.contains(0) && !a.contains(4));
        assert_eq!(m.shared(), m.topo.all().minus(&a));
        assert_eq!(m.cpus_for("p2", "x").unwrap(), m.shared());
        // Admitting again is idempotent.
        m.admit("p1", &[need("a", 2, 0)], NO_DEV).unwrap();
        assert_eq!(m.exclusive("p1", "a"), Some(a));
        // Only 4 CPUs are left for exclusive use (8 minus 2 reserved minus 2).
        let e = m.admit("p2", &[need("b", 5, 0)], NO_DEV).unwrap_err();
        assert!(e.contains("not enough cpus"), "{e}");
        assert!(!m.has_pod("p2"));
        assert!(m.release_pod("p1"));
        assert_eq!(m.shared().to_list(), "0-7");
    }

    #[test]
    fn init_container_cpus_are_reused() {
        let mut m = mgr(settings(true, false, Policy::None));
        let init = Need { name: "i".into(), init: true, cpus: 6, ..Default::default() };
        m.admit("p", &[init, need("a", 6, 0)], NO_DEV).unwrap();
        assert_eq!(m.exclusive("p", "i"), m.exclusive("p", "a"));
        assert!(m.release_ctr("p", "i"));
        assert_eq!(m.shared().to_list(), "0,4");
    }

    #[test]
    fn full_pcpus_only() {
        let mut s = settings(true, false, Policy::None);
        s.full_pcpus = true;
        let mut m = mgr(s);
        let e = m.admit("p", &[need("a", 3, 0)], NO_DEV).unwrap_err();
        assert!(e.starts_with("SMT Alignment Error: requested 3 cpus"), "{e}");
        m.admit("p", &[need("a", 2, 0)], NO_DEV).unwrap();
        assert_eq!(m.exclusive("p", "a").unwrap().to_list(), "1,5");
    }

    #[test]
    fn topology_aligns_cpus_with_devices() {
        // The device is on node 1: the CPUs follow it.
        let mut m = mgr(settings(true, false, Policy::SingleNuma));
        let dev = |_: &str, _: &str| Some(DevTopo { all: alloc::vec![1], free: alloc::vec![1], held: Vec::new() });
        let mut n = need("a", 2, 0);
        n.devices = alloc::vec![("gpu".into(), 1)];
        m.admit("p", &[n.clone()], &dev).unwrap();
        assert_eq!(m.exclusive("p", "a").unwrap().to_list(), "2,6");
        assert_eq!(m.affinity[&("p".to_string(), "a".to_string())], 0b10);
        // Five CPUs cannot be on one node with the device: single-numa-node rejects, and
        // nothing of the failed pod is kept.
        let mut big = need("b", 5, 0);
        big.devices = alloc::vec![("gpu".into(), 1)];
        assert_eq!(m.admit("q", &[big.clone()], &dev).unwrap_err(), TOPOLOGY_ERROR);
        assert!(!m.has_pod("q"));
        // best-effort admits it anyway.
        let mut m = mgr(settings(true, false, Policy::BestEffort));
        big.cpus = 4;
        m.admit("q", &[big], &dev).unwrap();
        assert_eq!(m.exclusive("q", "b").unwrap().len(), 4);
    }

    #[test]
    fn memory_pinning_and_checkpoint_round_trip() {
        let mut m = mgr(settings(true, true, Policy::Restricted));
        // 8 GiB on node 0, 4 GiB on node 1.
        m.admit("p", &[need("a", 1, 6 << 30)], NO_DEV).unwrap();
        assert_eq!(m.mems_for("p", "a").unwrap().to_list(), "0");
        assert_eq!(m.topo.mask_of(&m.exclusive("p", "a").unwrap()), 0b01);
        // 2 GiB left on node 0 and 4 on node 1: 6 more need both nodes, which is not preferred
        // (node 0 alone could hold 6 GiB), so restricted rejects it; 3 GiB fit on node 1.
        let e = m.admit("q", &[need("b", 1, 6 << 30)], NO_DEV);
        assert_eq!(e.unwrap_err(), TOPOLOGY_ERROR);
        m.admit("q", &[need("b", 1, 3 << 30)], NO_DEV).unwrap();
        let cpu = m.encode_cpu();
        let mem = m.encode_mem();
        let mut back = mgr(settings(true, true, Policy::Restricted));
        back.load_cpu(&cpu).unwrap();
        back.load_mem(&mem).unwrap();
        assert_eq!(back.encode_cpu(), cpu);
        assert_eq!(back.encode_mem(), mem);
        assert_eq!(back.exclusive("p", "a"), m.exclusive("p", "a"));
        assert_eq!(back.mems_for("q", "b"), m.mems_for("q", "b"));
        assert!(cpu.contains(r#""policyName":"static""#) && cpu.contains("defaultCpuSet"));
        // Another policy's checkpoint or CPUs that are not assignable are refused.
        let mut none = mgr(settings(false, true, Policy::None));
        assert!(none.load_cpu(&cpu).is_err());
        let mut other = mgr(settings(true, true, Policy::None));
        assert!(other.load_cpu(r#"{"policyName":"static","entries":{"p":{"a":"0"}}}"#).is_err());
        assert!(other.load_cpu(r#"{"policyName":"static","entries":{"p":{"a":"99"}}}"#).is_err());
        // Stale pods go.
        assert!(back.retain(&|u| u == "q"));
        assert!(!back.has_pod("p") && back.has_pod("q"));
    }
}
