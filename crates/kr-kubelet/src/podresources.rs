//! The kubelet's `PodResources` gRPC API (v1: `List`, `GetAllocatableResources`, `Get`; v1alpha1
//! `List`) on
//! `<kubelet dir>/pod-resources/kubelet.sock`, for tools that map devices to pods (the DCGM
//! exporter, monitoring agents). Devices come from the device plugin allocations (ADR-038); CPU
//! and memory lists are always empty (kr has no CPU or memory manager).

use crate::deviceplugin::Plugins;
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_fmt::proto::{Reader, Writer};
use kr_net::grpc::{self, Responder, Status};
use kr_rt::exec::{spawn, Async};

const LIST: &str = "/v1.PodResourcesLister/List";
const ALLOCATABLE: &str = "/v1.PodResourcesLister/GetAllocatableResources";
const GET: &str = "/v1.PodResourcesLister/Get";
/// v1alpha1 `List` (still what the DCGM exporter calls): the same messages and field numbers as
/// v1's, which only adds fields (topology, cpu_ids, memory) that a v1alpha1 decoder skips.
const LIST_V1ALPHA1: &str = "/v1alpha1.PodResourcesLister/List";
const NOT_FOUND: u32 = 5;

/// A pod on this node, as far as the API needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PodInfo {
    pub uid: String,
    pub ns: String,
    pub name: String,
    /// Container names (init, app).
    pub ctrs: Vec<String>,
}

/// `ContainerDevices` messages: one per (resource, NUMA node), device ids in order.
fn devices(w: &mut Writer, field: u32, groups: &BTreeMap<(String, i64), Vec<String>>) {
    for ((res, numa), ids) in groups {
        w.message(field, |w| {
            w.string(1, res);
            for i in ids {
                w.string(2, i);
            }
            if *numa >= 0 {
                w.message(3, |w| {
                    w.message(1, |w| {
                        w.int64(1, *numa);
                    });
                });
            }
        });
    }
}

fn pod_message(w: &mut Writer, p: &PodInfo, dp: &Plugins) {
    let held = dp.holdings();
    w.string(1, &p.name).string(2, &p.ns);
    for c in &p.ctrs {
        let mut groups: BTreeMap<(String, i64), Vec<String>> = BTreeMap::new();
        for (_, _, res, ids) in held.iter().filter(|h| h.0 == p.uid && h.1 == *c) {
            for id in ids {
                groups.entry((res.clone(), dp.numa_of(res, id))).or_default().push(id.clone());
            }
        }
        w.message(3, |w| {
            w.string(1, c);
            devices(w, 2, &groups);
        });
    }
}

/// `ListPodResourcesResponse`.
pub fn encode_list(pods: &[PodInfo], dp: &Plugins) -> Vec<u8> {
    let mut w = Writer::new();
    for p in pods {
        w.message(1, |w| pod_message(w, p, dp));
    }
    w.into_bytes()
}

/// `AllocatableResourcesResponse`: the healthy devices.
pub fn encode_allocatable(dp: &Plugins) -> Vec<u8> {
    let mut groups: BTreeMap<(String, i64), Vec<String>> = BTreeMap::new();
    for (res, id, numa) in dp.allocatable_devices() {
        groups.entry((res, numa)).or_default().push(id);
    }
    let mut w = Writer::new();
    devices(&mut w, 1, &groups);
    w.into_bytes()
}

/// `GetPodResourcesResponse` for the pod called (`ns`, `name`); None if it is not on the node.
pub fn encode_get(pods: &[PodInfo], req: &[u8], dp: &Plugins) -> Option<Vec<u8>> {
    let (mut name, mut ns) = (String::new(), String::new());
    let mut r = Reader::new(req);
    while let Ok(Some(f)) = r.next() {
        match f.number {
            1 => name = f.as_str().unwrap_or("").to_string(),
            2 => ns = f.as_str().unwrap_or("").to_string(),
            _ => {}
        }
    }
    let p = pods.iter().find(|p| p.name == name && p.ns == ns)?;
    let mut w = Writer::new();
    w.message(1, |w| pod_message(w, p, dp));
    Some(w.into_bytes())
}

/// Serves the API next to the device plugin directory (`<kubelet dir>/pod-resources`). False if
/// the socket cannot be created. `pods` lists the pods on the node.
pub fn start(dp: &Rc<Plugins>, pods: Rc<dyn Fn() -> Vec<PodInfo>>) -> bool {
    let Some((kubelet_dir, _)) = dp.dir().rsplit_once('/') else { return false };
    let dir = alloc::format!("{kubelet_dir}/pod-resources");
    if kr_runtime::store::mkdir_p(&dir, 0o750).is_err() {
        return false;
    }
    let sock = alloc::format!("{dir}/kubelet.sock");
    let _ = kr_sys::fs::unlinkat(kr_sys::fs::AT_FDCWD, alloc::format!("{sock}\0").as_bytes(), 0);
    let Ok(fd) = kr_sys::ns::unix_listen(sock.as_bytes()) else { return false };
    let Ok(l) = kr_sys::ns::set_nonblocking(fd.raw()).and_then(|_| Async::new(fd)) else { return false };
    let dp = dp.clone();
    spawn(grpc::serve(
        l,
        Rc::new(move |m: String, req: Vec<u8>, r: Responder| {
            let (dp, pods) = (dp.clone(), pods.clone());
            async move {
                let body = match m.as_str() {
                    LIST | LIST_V1ALPHA1 => Some(encode_list(&pods(), &dp)),
                    ALLOCATABLE => Some(encode_allocatable(&dp)),
                    GET => match encode_get(&pods(), &req, &dp) {
                        Some(b) => Some(b),
                        None => return r.finish(Status::new(NOT_FOUND, "pod not found")).await,
                    },
                    _ => None,
                };
                match body {
                    Some(b) => {
                        let _ = r.send(&b).await;
                        r.finish(Status::ok()).await
                    }
                    None => r.finish(Status::new(grpc::UNIMPLEMENTED, "unknown method")).await,
                }
            }
        }),
    ));
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pods() -> Vec<PodInfo> {
        alloc::vec![PodInfo { uid: "u1".into(), ns: "ns".into(), name: "p".into(), ctrs: alloc::vec!["main".into(), "side".into()] }]
    }

    fn parse_container_devices(b: &[u8]) -> (String, Vec<String>, Option<u64>) {
        let (mut res, mut ids, mut numa) = (String::new(), Vec::new(), None);
        let mut r = Reader::new(b);
        while let Ok(Some(f)) = r.next() {
            match f.number {
                1 => res = f.as_str().unwrap().into(),
                2 => ids.push(f.as_str().unwrap().into()),
                3 => {
                    let mut t = Reader::new(f.as_bytes().unwrap());
                    let n = t.next().unwrap().unwrap();
                    let mut nr = Reader::new(n.as_bytes().unwrap());
                    numa = nr.next().unwrap().unwrap().as_varint();
                }
                _ => {}
            }
        }
        (res, ids, numa)
    }

    #[test]
    fn list_get_and_allocatable() {
        let _g = crate::deviceplugin::tests::lock();
        let (dp, _dir) = crate::deviceplugin::tests::plugins_with("x.com/gpu", &[("a", true, 0), ("b", true, 1), ("c", false, 1)], &[("u1", "main", &["b"])]);
        // List: one pod, two containers, only `main` has a device, with its NUMA node.
        let b = encode_list(&pods(), &dp);
        let mut r = Reader::new(&b);
        let pod = r.next().unwrap().unwrap();
        assert_eq!(pod.number, 1);
        let mut pr = Reader::new(pod.as_bytes().unwrap());
        assert_eq!(pr.next().unwrap().unwrap().as_str(), Some("p"));
        assert_eq!(pr.next().unwrap().unwrap().as_str(), Some("ns"));
        let c1 = pr.next().unwrap().unwrap();
        let mut cr = Reader::new(c1.as_bytes().unwrap());
        assert_eq!(cr.next().unwrap().unwrap().as_str(), Some("main"));
        assert_eq!(parse_container_devices(cr.next().unwrap().unwrap().as_bytes().unwrap()), ("x.com/gpu".into(), alloc::vec!["b".into()], Some(1)));
        let c2 = pr.next().unwrap().unwrap();
        let mut cr = Reader::new(c2.as_bytes().unwrap());
        assert_eq!(cr.next().unwrap().unwrap().as_str(), Some("side"));
        assert!(cr.next().unwrap().is_none());
        // Get: found and not found.
        let mut q = Writer::new();
        q.string(1, "p").string(2, "ns");
        assert!(encode_get(&pods(), q.as_bytes(), &dp).is_some());
        let mut q = Writer::new();
        q.string(1, "other").string(2, "ns");
        assert!(encode_get(&pods(), q.as_bytes(), &dp).is_none());
        // Allocatable: healthy devices grouped by NUMA node.
        let b = encode_allocatable(&dp);
        let mut r = Reader::new(&b);
        let mut got = Vec::new();
        while let Some(f) = r.next().unwrap() {
            got.push(parse_container_devices(f.as_bytes().unwrap()));
        }
        assert_eq!(got, alloc::vec![("x.com/gpu".to_string(), alloc::vec!["a".to_string()], Some(0)), ("x.com/gpu".to_string(), alloc::vec!["b".to_string()], Some(1))]);
    }
}
