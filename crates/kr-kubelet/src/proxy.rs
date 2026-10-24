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
    listeners: RefCell<BTreeMap<Key, Listener>>,
}

fn ip4(s: &str) -> Option<[u8; 4]> {
    kr_apiserver::object::parse_ipv4(s)
}

impl<C: Client + Clone + 'static> Proxy<C> {
    pub fn new(c: C, net: Rc<NodeNet>) -> Rc<Self> {
        Rc::new(Proxy { c, net, listeners: RefCell::new(BTreeMap::new()) })
    }

    pub async fn run(self: Rc<Self>) {
        if let Err(e) = self.net.setup() {
            kr_rt::eprint(alloc::format!("proxy: cannot route the service CIDR (errno {}); services disabled\n", e.0).as_bytes());
            return;
        }
        loop {
            self.reconcile().await;
            kr_rt::exec::sleep(1000).await;
        }
    }

    /// Desired listeners from Services + Endpoints, diffed against the running ones.
    async fn reconcile(self: &Rc<Self>) {
        let (Ok(svcs), Ok(eps)) = (self.c.list("/api/v1/services", "").await, self.c.list("/api/v1/endpoints", "").await) else { return };
        let empty = Vec::new();
        let svcs = svcs.get("items").and_then(Value::as_array).unwrap_or(&empty);
        let eps = eps.get("items").and_then(Value::as_array).unwrap_or(&empty);
        let mut desired: BTreeMap<Key, Backends> = BTreeMap::new();
        for s in svcs {
            if s.pointer(&["metadata", "annotations", "kr.io/builtin"]).is_some() {
                continue; // served by kr itself (cluster DNS)
            }
            let Some(cip) = s.pointer(&["spec", "clusterIP"]).and_then(Value::as_str).and_then(ip4) else { continue };
            let (ns_, name) = (kr_apiserver::client::meta(s, "namespace"), kr_apiserver::client::meta(s, "name"));
            let ep = eps.iter().find(|e| kr_apiserver::client::meta(e, "namespace") == ns_ && kr_apiserver::client::meta(e, "name") == name);
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
                for sub in ep.and_then(|e| e.get("subsets")).and_then(Value::as_array).unwrap_or(&[]) {
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
