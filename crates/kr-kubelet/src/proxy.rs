//! Service proxy (kube-proxy replacement, ADR-022): a userspace proxy inside kr.
//!
//! The Service CIDR is made locally deliverable in the node network namespace with a single
//! `local 10.96.0.0/16` route, so every ClusterIP can be bound directly. For each service port
//! kr listens on ClusterIP:port (and on 0.0.0.0:nodePort in the host namespace for NodePort
//! services), accepts, picks a ready endpoint (round-robin, or by client IP with
//! `sessionAffinity: ClientIP`) and splices both directions with half-close. UDP keeps one
//! session per client.
//!
//! Rootless, the node namespace is the pod-network infra namespace: a socket factory process
//! inside it creates the listening and connecting sockets and hands them to kr (SCM_RIGHTS);
//! sockets keep their namespace for life. Backends outside the pod CIDR (the API server) are
//! dialled from the host namespace.

use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use kr_apiserver::client::Client;
use kr_fmt::json::Value;
use kr_rt::exec::{Async, JoinHandle};
use kr_runtime::container::{self, Running, Sandbox};
use kr_sys::{ns, Errno, Fd};

pub const SERVICE_CIDR: ([u8; 4], u8) = ([10, 96, 0, 0], 16);
const POD_CIDR: ([u8; 4], u8) = ([10, 88, 0, 0], 16);

const OP_LISTEN: u8 = 1;
const OP_CONNECT: u8 = 2;
const OP_LOCAL_ROUTE: u8 = 3;
const TCP: u8 = 1;
const UDP: u8 = 2;

fn in_cidr(ip: [u8; 4], (net, len): ([u8; 4], u8)) -> bool {
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    u32::from_be_bytes(ip) & mask == u32::from_be_bytes(net) & mask
}

/// Executes a socket operation in the current network namespace. Returns the new socket
/// (non-blocking, close-on-exec) or None for status-only operations.
fn local_op(op: u8, proto: u8, ip: [u8; 4], port: u16) -> Result<Option<Fd>, Errno> {
    match op {
        OP_LOCAL_ROUTE => {
            let nl = kr_net::netlink::Netlink::route()?;
            let lo = kr_net::netlink::ifindex(b"lo")?;
            match nl.route_add_local(ip, port as u8, lo) {
                Ok(()) | Err(Errno(17)) => Ok(None),
                Err(e) => Err(e),
            }
        }
        OP_LISTEN | OP_CONNECT => {
            let ty = if proto == UDP { 2 } else { kr_sys::SOCK_STREAM };
            let fd = kr_sys::socket(kr_sys::AF_INET, ty | kr_sys::SOCK_NONBLOCK | kr_sys::SOCK_CLOEXEC, 0)?;
            if op == OP_LISTEN {
                kr_sys::setsockopt(fd.raw(), 1, 2, &1i32.to_ne_bytes())?; // SO_REUSEADDR
                kr_sys::bind(fd.raw(), &kr_sys::SockaddrIn::new(ip, port))?;
                if proto == TCP {
                    kr_sys::listen(fd.raw(), 1024)?;
                }
            } else {
                match kr_sys::connect(fd.raw(), &kr_sys::SockaddrIn::new(ip, port)) {
                    Ok(()) | Err(Errno(kr_sys::EINPROGRESS)) => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(Some(fd))
        }
        _ => Err(Errno(22)),
    }
}

/// Where node-namespace sockets come from.
pub enum NodeNet {
    /// kr itself runs in the node network namespace (root mode).
    Host,
    /// A helper inside the rootless pod network creates them.
    Factory { sock: Fd, _helper: Running },
}

impl NodeNet {
    /// Starts the socket factory inside `infra`'s network namespace.
    pub fn factory(infra: &Sandbox) -> Result<NodeNet, Errno> {
        let (ours, theirs) = ns::socketpair()?;
        let theirs_raw = theirs.raw();
        let target = infra.target()?;
        let helper = container::in_pod_net(&target, move || {
            let mut req = [0u8; 8];
            loop {
                match kr_sys::read(theirs_raw, &mut req) {
                    Ok(8) => {}
                    _ => return 0, // kr went away
                }
                let ip = [req[2], req[3], req[4], req[5]];
                let port = u16::from_be_bytes([req[6], req[7]]);
                let r = local_op(req[0], req[1], ip, port);
                let status: i32 = match &r {
                    Ok(_) => 0,
                    Err(e) => e.0,
                };
                let sent = match &r {
                    Ok(Some(fd)) => ns::send_fd(theirs_raw, &status.to_ne_bytes(), fd.raw()),
                    _ => kr_sys::write(theirs_raw, &status.to_ne_bytes()),
                };
                if sent.is_err() {
                    return 1;
                }
            }
        })
        .map_err(|e| e.errno)?;
        drop(theirs);
        Ok(NodeNet::Factory { sock: ours, _helper: helper })
    }

    fn op(&self, op: u8, proto: u8, ip: [u8; 4], port: u16) -> Result<Option<Fd>, Errno> {
        match self {
            NodeNet::Host => local_op(op, proto, ip, port),
            NodeNet::Factory { sock, .. } => {
                let mut req = [op, proto, ip[0], ip[1], ip[2], ip[3], 0, 0];
                req[6..].copy_from_slice(&port.to_be_bytes());
                kr_sys::write(sock.raw(), &req)?;
                let mut st = [0u8; 4];
                let (n, fd) = ns::recv_fd(sock.raw(), &mut st)?;
                if n != 4 {
                    return Err(Errno(5));
                }
                match i32::from_ne_bytes(st) {
                    0 => Ok(fd),
                    e => Err(Errno(e)),
                }
            }
        }
    }

    /// Makes the Service CIDR locally deliverable in the node namespace.
    pub fn setup(&self) -> Result<(), Errno> {
        self.op(OP_LOCAL_ROUTE, 0, SERVICE_CIDR.0, SERVICE_CIDR.1 as u16).map(|_| ())
    }

    /// proto: 1 = TCP, 2 = UDP.
    pub fn listen(&self, proto: u8, ip: [u8; 4], port: u16) -> Result<Fd, Errno> {
        self.op(OP_LISTEN, proto, ip, port)?.ok_or(Errno(5))
    }

    /// Dials a backend; pod-CIDR addresses from the node namespace, others from the host.
    fn dial(&self, proto: u8, ip: [u8; 4], port: u16) -> Result<Fd, Errno> {
        if matches!(self, NodeNet::Factory { .. }) && !in_cidr(ip, POD_CIDR) {
            return local_op(OP_CONNECT, proto, ip, port)?.ok_or(Errno(5));
        }
        self.op(OP_CONNECT, proto, ip, port)?.ok_or(Errno(5))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct Key {
    proto: u8,
    ip: [u8; 4],
    port: u16,
    /// NodePort listeners live in the host namespace.
    host: bool,
}

#[derive(Default)]
struct Backends {
    eps: Vec<([u8; 4], u16)>,
    rr: Cell<usize>,
    affinity: bool,
}

impl Backends {
    fn pick(&self, client: [u8; 4], attempt: usize) -> Option<([u8; 4], u16)> {
        if self.eps.is_empty() {
            return None;
        }
        let i = if self.affinity {
            // Stable per client IP (FNV-1a), shifted by the attempt number on failure.
            let h = client.iter().fold(0x811c_9dc5u32, |h, &b| (h ^ b as u32).wrapping_mul(0x0100_0193)) as usize;
            h + attempt
        } else {
            let i = self.rr.get();
            self.rr.set(i.wrapping_add(1));
            i
        };
        Some(self.eps[i % self.eps.len()])
    }
}

struct Listener {
    backends: Rc<RefCell<Backends>>,
    _task: JoinHandle<()>,
}

pub struct Proxy<C: Client> {
    c: C,
    net: Rc<NodeNet>,
    node: String,
    listeners: RefCell<BTreeMap<Key, Listener>>,
}

/// `(namespace, name)` of an object.
fn by_name(o: &Value) -> (&str, &str) {
    (kr_apiserver::client::meta(o, "namespace"), kr_apiserver::client::meta(o, "name"))
}

fn ip4(s: &str) -> Option<[u8; 4]> {
    kr_apiserver::object::parse_ipv4(s)
}

impl<C: Client + Clone + 'static> Proxy<C> {
    pub fn new(c: C, net: Rc<NodeNet>, node: String) -> Rc<Self> {
        Rc::new(Proxy { c, net, node, listeners: RefCell::new(BTreeMap::new()) })
    }

    pub async fn run(self: Rc<Self>) {
        if let Err(e) = self.net.setup() {
            kr_rt::eprint(alloc::format!("proxy: cannot route the service CIDR (errno {}); services disabled\n", e.0).as_bytes());
            return;
        }
        loop {
            let started = kr_rt::exec::now_ms();
            self.reconcile().await;
            // Listing and diffing every Service costs CPU on the shared executor: with many of
            // them, leave at least three times as long to everything else.
            let took = kr_rt::exec::now_ms().saturating_sub(started);
            kr_rt::exec::sleep(1000.max(took * 3)).await;
        }
    }

    /// Desired listeners from Services + Endpoints, diffed against the running ones.
    async fn reconcile(self: &Rc<Self>) {
        let (Ok(svcs), Ok(eps), Ok(slices)) = (self.c.list("/api/v1/services", "").await, self.c.list("/api/v1/endpoints", "").await, self.c.list("/apis/discovery.k8s.io/v1/endpointslices", "").await) else { return };
        let empty = Vec::new();
        let svcs = svcs.get("items").and_then(Value::as_array).unwrap_or(&empty);
        let eps = eps.get("items").and_then(Value::as_array).unwrap_or(&empty);
        let slices = slices.get("items").and_then(Value::as_array).unwrap_or(&empty);
        let mut desired: BTreeMap<Key, Backends> = BTreeMap::new();
        let ep_of: BTreeMap<(&str, &str), &Value> = eps.iter().map(|e| (by_name(e), e)).collect();
        let mut slices_of: BTreeMap<(&str, &str), Vec<&Value>> = BTreeMap::new();
        for sl in slices {
            if let Some(svc) = sl.pointer(&["metadata", "labels", "kubernetes.io/service-name"]).and_then(Value::as_str) {
                slices_of.entry((kr_apiserver::client::meta(sl, "namespace"), svc)).or_default().push(sl);
            }
        }
        for (n, s) in svcs.iter().enumerate() {
            if n % 100 == 99 {
                kr_rt::exec::yield_now().await;
            }
            if s.pointer(&["metadata", "annotations", "kr.io/builtin"]).is_some() {
                continue; // served by kr itself (cluster DNS)
            }
            let Some(cip) = s.pointer(&["spec", "clusterIP"]).and_then(Value::as_str).and_then(ip4) else { continue };
            let ep = ep_of.get(&by_name(s)).copied();
            let own: &[&Value] = slices_of.get(&by_name(s)).map_or(&[], |v| v.as_slice());
            let affinity = s.pointer(&["spec", "sessionAffinity"]).and_then(Value::as_str) == Some("ClientIP");
            for p in s.pointer(&["spec", "ports"]).and_then(Value::as_array).unwrap_or(&[]) {
                let proto = match p.get("protocol").and_then(Value::as_str) {
                    Some("UDP") => UDP,
                    Some("TCP") | None => TCP,
                    _ => continue, // SCTP not supported
                };
                let Some(port) = p.get("port").and_then(Value::as_u64) else { continue };
                let pname = p.get("name").and_then(Value::as_str).unwrap_or("");
                let mut list = Vec::new();
                // EndpointSlices win: Services without a selector may have only hand-written ones.
                for sl in own {
                    let target = sl.get("ports").and_then(Value::as_array).and_then(|ps| ps.iter().find(|sp| sp.get("name").and_then(Value::as_str).unwrap_or("") == pname)).and_then(|sp| sp.get("port")).and_then(Value::as_u64);
                    let Some(tp) = target else { continue };
                    for e in sl.get("endpoints").and_then(Value::as_array).unwrap_or(&[]) {
                        if e.pointer(&["conditions", "ready"]).and_then(Value::as_bool) == Some(false) {
                            continue;
                        }
                        for a in e.get("addresses").and_then(Value::as_array).unwrap_or(&[]) {
                            if let Some(ip) = a.as_str().and_then(ip4) {
                                list.push((ip, tp as u16));
                            }
                        }
                    }
                }
                for sub in ep.filter(|_| own.is_empty()).and_then(|e| e.get("subsets")).and_then(Value::as_array).unwrap_or(&[]) {
                    let target = sub.get("ports").and_then(Value::as_array).and_then(|ps| ps.iter().find(|ep| ep.get("name").and_then(Value::as_str).unwrap_or("") == pname)).and_then(|ep| ep.get("port")).and_then(Value::as_u64);
                    let Some(tp) = target else { continue };
                    for a in sub.get("addresses").and_then(Value::as_array).unwrap_or(&[]) {
                        if let Some(ip) = a.get("ip").and_then(Value::as_str).and_then(ip4) {
                            list.push((ip, tp as u16));
                        }
                    }
                }
                let mk = |eps: &Vec<([u8; 4], u16)>| Backends { eps: eps.clone(), rr: Cell::new(0), affinity };
                desired.insert(Key { proto, ip: cip, port: port as u16, host: false }, mk(&list));
                if let Some(np) = p.get("nodePort").and_then(Value::as_u64) {
                    desired.insert(Key { proto, ip: [0, 0, 0, 0], port: np as u16, host: true }, mk(&list));
                }
            }
        }
        let q = alloc::format!("fieldSelector=spec.nodeName%3D{}", self.node);
        let Ok(pods) = self.c.list("/api/v1/pods", &q).await else { return };
        host_port_listeners(pods.get("items").and_then(Value::as_array).unwrap_or(&empty), &mut desired);
        let mut cur = self.listeners.borrow_mut();
        cur.retain(|k, _| desired.contains_key(k)); // dropping a Listener aborts its task
        for (k, b) in desired {
            if let Some(l) = cur.get(&k) {
                let mut lb = l.backends.borrow_mut();
                lb.eps = b.eps;
                lb.affinity = b.affinity;
                continue;
            }
            let fd = if k.host { local_op(OP_LISTEN, k.proto, k.ip, k.port).and_then(|f| f.ok_or(Errno(5))) } else { self.net.listen(k.proto, k.ip, k.port) };
            let Ok(fd) = fd else { continue }; // retried next round
            let Ok(sock) = Async::new(fd) else { continue };
            let backends = Rc::new(RefCell::new(b));
            let task = if k.proto == TCP {
                kr_rt::exec::spawn(tcp_loop(sock, backends.clone(), self.net.clone()))
            } else {
                kr_rt::exec::spawn(udp_loop(sock, backends.clone(), self.net.clone()))
            };
            cur.insert(k, Listener { backends, _task: task });
        }
    }
}

/// One listener per running pod container hostPort, backed by podIP:containerPort.
fn host_port_listeners(pods: &[Value], desired: &mut BTreeMap<Key, Backends>) {
    for p in pods {
        if p.pointer(&["status", "phase"]).and_then(Value::as_str) != Some("Running") || p.pointer(&["metadata", "deletionTimestamp"]).is_some()
            // hostNetwork pods already listen on the host themselves.
            || p.pointer(&["spec", "hostNetwork"]).and_then(Value::as_bool) == Some(true)
        {
            continue;
        }
        let Some(pip) = p.pointer(&["status", "podIP"]).and_then(Value::as_str).and_then(ip4) else { continue };
        for c in p.pointer(&["spec", "containers"]).and_then(Value::as_array).unwrap_or(&[]) {
            for pt in c.get("ports").and_then(Value::as_array).unwrap_or(&[]) {
                let (Some(hp), Some(cp)) = (pt.get("hostPort").and_then(Value::as_u64), pt.get("containerPort").and_then(Value::as_u64)) else { continue };
                if hp == 0 {
                    continue;
                }
                let proto = match pt.get("protocol").and_then(Value::as_str) {
                    Some("UDP") => UDP,
                    Some("TCP") | None => TCP,
                    _ => continue,
                };
                let ip = pt.get("hostIP").and_then(Value::as_str).and_then(ip4).unwrap_or([0; 4]);
                desired.insert(Key { proto, ip, port: hp as u16, host: true }, Backends { eps: alloc::vec![(pip, cp as u16)], rr: Cell::new(0), affinity: false });
            }
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self._task.abort();
    }
}

async fn tcp_loop(listener: Async<Fd>, backends: Rc<RefCell<Backends>>, net: Rc<NodeNet>) {
    loop {
        let Ok(client) = listener.accept().await else {
            kr_rt::exec::sleep(100).await;
            continue;
        };
        let (b, n) = (backends.clone(), net.clone());
        kr_rt::exec::spawn(async move {
            // The peer address only matters for ClientIP affinity.
            let peer = client_ip(&client).unwrap_or([0; 4]);
            let count = b.borrow().eps.len().max(1);
            for attempt in 0..count.min(3) {
                let Some((ip, port)) = b.borrow().pick(peer, attempt) else { return };
                let Ok(fd) = n.dial(TCP, ip, port) else { continue };
                let Ok(up) = Async::new(fd) else { continue };
                if kr_rt::exec::timeout(5000, up.wait_writable()).await.is_err() {
                    continue;
                }
                if kr_sys::socket_error(up.get_ref().raw()).map(|e| e != 0).unwrap_or(true) {
                    continue;
                }
                splice(client, up).await;
                return;
            }
        });
    }
}

fn client_ip(s: &Async<Fd>) -> Option<[u8; 4]> {
    ns::peer_ipv4(s.get_ref().raw())
}

/// Copies both ways until both directions are closed; EOF on one side half-closes the other.
async fn splice(a: Async<Fd>, b: Async<Fd>) {
    let (a, b) = (Rc::new(a), Rc::new(b));
    let one = kr_rt::exec::spawn(copy(a.clone(), b.clone()));
    copy(b, a).await;
    let _ = one.await;
}

async fn copy(from: Rc<Async<Fd>>, to: Rc<Async<Fd>>) {
    let mut buf = alloc::vec![0u8; 32 * 1024];
    loop {
        match from.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if kr_net::tcp::write_all_nosignal(&to, &buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = kr_sys::shutdown(to.get_ref().raw(), 1); // SHUT_WR
}

struct UdpSession {
    upstream: Rc<Async<Fd>>,
    _task: JoinHandle<()>,
    last: Cell<u64>,
}

async fn udp_loop(listener: Async<Fd>, backends: Rc<RefCell<Backends>>, net: Rc<NodeNet>) {
    let listener = Rc::new(listener);
    let sessions: Rc<RefCell<BTreeMap<([u8; 4], u16), UdpSession>>> = Rc::new(RefCell::new(BTreeMap::new()));
    let mut buf = alloc::vec![0u8; 65536];
    loop {
        listener.wait_readable().await;
        loop {
            let (n, cip, cport) = match ns::recv_from(listener.get_ref().raw(), &mut buf) {
                Ok(r) => r,
                Err(_) => break, // EAGAIN: wait for the next edge
            };
            let now = kr_rt::exec::now_ms();
            // Expire idle sessions (60 s).
            sessions.borrow_mut().retain(|_, s| now.saturating_sub(s.last.get()) < 60_000);
            let key = (cip, cport);
            if !sessions.borrow().contains_key(&key) {
                let Some((ip, port)) = backends.borrow().pick(cip, 0) else { continue };
                let Ok(fd) = net.dial(UDP, ip, port) else { continue };
                let Ok(up) = Async::new(fd) else { continue };
                let up = Rc::new(up);
                // Replies from the backend go back to this client from the service address.
                let (l, u) = (listener.clone(), up.clone());
                let task = kr_rt::exec::spawn(async move {
                    let mut rb = alloc::vec![0u8; 65536];
                    loop {
                        match kr_rt::exec::timeout(60_000, u.read(&mut rb)).await {
                            Ok(Ok(n)) => {
                                let _ = ns::send_to(l.get_ref().raw(), &rb[..n], cip, cport);
                            }
                            _ => return,
                        }
                    }
                });
                sessions.borrow_mut().insert(key, UdpSession { upstream: up, _task: task, last: Cell::new(now) });
            }
            if let Some(s) = sessions.borrow().get(&key) {
                s.last.set(now);
                let _ = kr_sys::write(s.upstream.get_ref().raw(), &buf[..n]);
            }
        }
    }
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        self._task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn host_ports_desired() {
        let pod = |ip: &str, proto: &str, phase: &str| kr_fmt::json::parse_str(&alloc::format!(r#"{{"status":{{"phase":"{phase}","podIP":"10.1.0.5"}},"spec":{{"containers":[{{"ports":[{{"containerPort":8080,"hostPort":9090,"hostIP":"{ip}","protocol":"{proto}"}},{{"containerPort":1}}]}}]}}}}"#)).unwrap();
        let pods = [pod("", "TCP", "Running"), pod("127.0.0.1", "TCP", "Running"), pod("", "UDP", "Running"), pod("", "TCP", "Pending")];
        let mut d = BTreeMap::new();
        host_port_listeners(&pods, &mut d);
        assert_eq!(d.len(), 3);
        let b = &d[&Key { proto: UDP, ip: [0; 4], port: 9090, host: true }];
        assert_eq!(b.eps, alloc::vec![([10, 1, 0, 5], 8080)]);
        assert!(d.contains_key(&Key { proto: TCP, ip: [127, 0, 0, 1], port: 9090, host: true }));
    }
}
