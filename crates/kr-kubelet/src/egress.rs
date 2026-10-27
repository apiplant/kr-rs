//! Rootless pod egress (ADR-030): the infra namespace routes everything it has no local route
//! for into a TUN device; this driver, running in the node (host) network namespace, feeds those
//! packets to `kr_net::usernat` and relays each flow over ordinary host sockets.

use crate::Notify;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use kr_net::tcp::{self, IpAddr, SocketAddr};
use kr_runtime::network;
use kr_net::usernat::{Event, FlowId, Nat};
use kr_rt::exec::{self, now_ms, sleep, Async};
use kr_sys::{self as sys, Fd};

const MTU: usize = 1400;
/// Host-to-pod bytes buffered per flow before the host socket is no longer read.
const MAX_PENDING: usize = 256 << 10;

/// The host's first IPv4 nameserver (what `EGRESS_DNS` is forwarded to).
fn host_dns() -> [u8; 4] {
    let text = kr_sys::fs::read_file(b"/etc/resolv.conf\0", 16384).unwrap_or_default();
    core::str::from_utf8(&text)
        .unwrap_or("")
        .lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .find_map(|a| tcp::parse_ipv4(a.trim()))
        .unwrap_or([1, 1, 1, 1])
}

fn dst_for(ip: [u8; 4], port: u16) -> [u8; 4] {
    if ip == network::EGRESS_DNS && port == 53 {
        host_dns()
    } else {
        ip
    }
}

struct TcpFlow {
    sock: RefCell<Option<Rc<Async<Fd>>>>,
    to_host: RefCell<VecDeque<Vec<u8>>>,
    shut_wr: Cell<bool>,
    closed: Cell<bool>,
    wake: Notify,
    /// The reader waits here while too much host data is queued for the pod.
    room: Notify,
    blocked: Cell<bool>,
}

struct UdpFlow {
    sock: Async<Fd>,
}

struct Egress {
    tun: Async<Fd>,
    nat: RefCell<Nat>,
    tcp: RefCell<BTreeMap<FlowId, Rc<TcpFlow>>>,
    udp: RefCell<BTreeMap<FlowId, Rc<UdpFlow>>>,
}

/// Serves `tun` (the infra namespace's default route) until the process exits.
pub async fn run(tun: Fd) {
    let Ok(tun) = Async::new(tun) else { return };
    let mut nat = Nat::new(MTU);
    nat.forward_icmp(true);
    let eg = Rc::new(Egress { tun, nat: RefCell::new(nat), tcp: RefCell::new(BTreeMap::new()), udp: RefCell::new(BTreeMap::new()) });
    exec::spawn(tick(eg.clone()));
    let mut buf = [0u8; 65536];
    loop {
        match eg.tun.read(&mut buf).await {
            Ok(n) if n > 0 => {
                eg.nat.borrow_mut().packet_from_pod(&buf[..n], now_ms());
                eg.pump();
                // Acks from the pod make room for readers that paused.
                for f in eg.tcp.borrow().values() {
                    if f.blocked.replace(false) {
                        f.room.notify();
                    }
                }
            }
            Ok(_) => {}
            Err(_) => sleep(100).await,
        }
    }
}

async fn tick(eg: Rc<Egress>) {
    loop {
        sleep(1000).await;
        eg.nat.borrow_mut().tick(now_ms());
        eg.pump();
    }
}

impl Egress {
    /// Writes packets for the pods and acts on engine events.
    fn pump(self: &Rc<Self>) {
        loop {
            let (events, packets) = {
                let mut nat = self.nat.borrow_mut();
                (nat.take_events(), nat.take_packets())
            };
            if events.is_empty() && packets.is_empty() {
                return;
            }
            for p in packets {
                // A full TUN queue drops the packet like a congested link; TCP recovers.
                let _ = sys::write(self.tun.get_ref().raw(), &p);
            }
            for ev in events {
                self.event(ev);
            }
        }
    }

    fn event(self: &Rc<Self>, ev: Event) {
        match ev {
            Event::TcpConnect { flow, dst, port } => {
                let f = Rc::new(TcpFlow { sock: RefCell::new(None), to_host: RefCell::new(VecDeque::new()), shut_wr: Cell::new(false), closed: Cell::new(false), wake: Notify::default(), room: Notify::default(), blocked: Cell::new(false) });
                self.tcp.borrow_mut().insert(flow, f.clone());
                exec::spawn(tcp_flow(self.clone(), flow, SocketAddr { ip: IpAddr::V4(dst_for(dst, port)), port }, f));
            }
            Event::TcpData { flow, data } => {
                if let Some(f) = self.tcp.borrow().get(&flow) {
                    f.to_host.borrow_mut().push_back(data);
                    f.wake.notify();
                }
            }
            Event::TcpShutdownWrite { flow } => {
                if let Some(f) = self.tcp.borrow().get(&flow) {
                    f.shut_wr.set(true);
                    f.wake.notify();
                }
            }
            Event::TcpClose { flow } => {
                if let Some(f) = self.tcp.borrow_mut().remove(&flow) {
                    f.closed.set(true);
                    f.wake.notify();
                }
            }
            Event::UdpSend { flow, dst, port, data } => {
                let existing = self.udp.borrow().get(&flow).cloned();
                let u = match existing {
                    Some(u) => u,
                    None => {
                        let Some(sock) = sys::socket(sys::AF_INET, 2 | sys::SOCK_NONBLOCK | sys::SOCK_CLOEXEC, 0).ok().and_then(|fd| Async::new(fd).ok()) else { return };
                        let u = Rc::new(UdpFlow { sock });
                        self.udp.borrow_mut().insert(flow, u.clone());
                        exec::spawn(udp_reader(self.clone(), flow, u.clone()));
                        u
                    }
                };
                let _ = sys::ns::send_to(u.sock.get_ref().raw(), &data, dst_for(dst, port), port);
            }
            Event::IcmpEcho { pod, dst, id, seq, data } => {
                exec::spawn(ping(self.clone(), pod, dst, id, seq, data));
            }
            Event::UdpClose { flow } => {
                self.udp.borrow_mut().remove(&flow);
            }
        }
    }
}

/// One pod `ping`: an unprivileged ICMP socket (needs `net.ipv4.ping_group_range`; without it the
/// request is dropped) sends the echo and the reply, if any arrives within 3 s, goes back.
async fn ping(eg: Rc<Egress>, pod: [u8; 4], dst: [u8; 4], id: u16, seq: u16, data: Vec<u8>) {
    let Some(sock) = sys::socket(sys::AF_INET, 2 | sys::SOCK_NONBLOCK | sys::SOCK_CLOEXEC, 1).ok().and_then(|fd| Async::new(fd).ok()) else { return };
    // The kernel replaces the identifier; the sequence number and data pass through.
    let mut m = alloc::vec![8u8, 0, 0, 0, 0, 0];
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(&data);
    if sys::ns::send_to(sock.get_ref().raw(), &m, dst, 0).is_err() {
        return;
    }
    let mut buf = alloc::vec![0u8; 65536];
    let deadline = now_ms() + 3000;
    while now_ms() < deadline {
        let _ = exec::timeout(deadline - now_ms(), sock.wait_readable()).await;
        if let Ok((n, _, _)) = sys::ns::recv_from(sock.get_ref().raw(), &mut buf) {
            if n >= 8 && buf[0] == 0 {
                eg.nat.borrow_mut().icmp_reply(pod, dst, id, seq, &buf[8..n]);
                eg.pump();
                return;
            }
        }
    }
}

async fn tcp_flow(eg: Rc<Egress>, id: FlowId, dst: SocketAddr, f: Rc<TcpFlow>) {
    let sock = match tcp::connect_addr(dst, 10_000).await {
        Ok(s) => Rc::new(s),
        Err(_) => {
            eg.tcp.borrow_mut().remove(&id);
            eg.nat.borrow_mut().tcp_refused(id);
            eg.pump();
            return;
        }
    };
    *f.sock.borrow_mut() = Some(sock.clone());
    eg.nat.borrow_mut().tcp_connected(id);
    eg.pump();
    let reader = exec::spawn(tcp_reader(eg.clone(), id, sock.clone(), f.clone()));
    // Writer: pod bytes to the host socket.
    loop {
        loop {
            let chunk = f.to_host.borrow_mut().pop_front();
            let Some(chunk) = chunk else { break };
            if f.closed.get() || sock.write_all(&chunk).await.is_err() {
                f.closed.set(true);
                break;
            }
        }
        if f.closed.get() {
            break;
        }
        if f.shut_wr.get() && f.to_host.borrow().is_empty() {
            let _ = sys::shutdown(sock.get_ref().raw(), sys::SHUT_WR);
            f.shut_wr.set(false);
        }
        f.wake.wait(1000).await;
    }
    reader.abort();
    if eg.tcp.borrow_mut().remove(&id).is_some() {
        // The host side failed first: reset the pod's connection.
        eg.nat.borrow_mut().tcp_host_reset(id);
        eg.pump();
    }
}

async fn tcp_reader(eg: Rc<Egress>, id: FlowId, sock: Rc<Async<Fd>>, f: Rc<TcpFlow>) {
    let mut buf = [0u8; 16384];
    loop {
        if eg.nat.borrow().pending_to_pod(id) > MAX_PENDING {
            f.blocked.set(true);
            f.room.wait(100).await;
            continue;
        }
        match sock.read(&mut buf).await {
            Ok(0) => {
                eg.nat.borrow_mut().tcp_host_eof(id);
                eg.pump();
                return;
            }
            Ok(n) => {
                eg.nat.borrow_mut().tcp_host_data(id, &buf[..n]);
                eg.pump();
            }
            Err(_) => {
                f.closed.set(true);
                f.wake.notify();
                return;
            }
        }
    }
}

async fn udp_reader(eg: Rc<Egress>, id: FlowId, u: Rc<UdpFlow>) {
    let mut buf = alloc::vec![0u8; 65536];
    loop {
        let _ = exec::timeout(5000, u.sock.wait_readable()).await;
        loop {
            match sys::ns::recv_from(u.sock.get_ref().raw(), &mut buf) {
                Ok((n, _, _)) => {
                    eg.nat.borrow_mut().udp_from_host(id, &buf[..n]);
                    eg.pump();
                }
                Err(_) => break,
            }
        }
        if !eg.udp.borrow().contains_key(&id) {
            return;
        }
    }
}
