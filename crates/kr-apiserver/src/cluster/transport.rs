//! Server-to-server Raft transport (ADR-026): mutual TLS on port 6444, frames of
//! `[u32 LE len][kr_raft::codec message]`.
//!
//! Peers authenticate with certificates from the cluster CA whose subject is
//! `CN=system:kr-server:<id>, O=system:kr-servers`; a message is accepted only if its `from`
//! is the id in the sender's certificate. Outbound messages go through one bounded queue and
//! one connection per peer, reconnected with backoff; a full queue drops messages (Raft
//! retransmits), so a slow or dead peer never blocks the node.

use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::future::poll_fn;
use core::task::{Poll, Waker};
use kr_crypto::tls::{ClientConfig, ServerConfig};
use kr_net::http1::Transport;
use kr_net::tls::TlsStream;
use kr_raft::{codec, Message, NodeId};
use kr_rt::exec::{sleep, spawn, timeout, Async, JoinHandle};
use kr_sys::Fd;

pub const PORT: u16 = 6444;
pub const ORG: &str = "system:kr-servers";
/// Largest frame (an InstallSnapshot carries the whole store image).
const MAX_FRAME: usize = 512 << 20;
/// Messages queued per peer before new ones are dropped.
const QUEUE: usize = 4096;

/// `system:kr-server:<id>` for a server certificate.
pub fn cert_cn(id: NodeId) -> String {
    alloc::format!("system:kr-server:{id}")
}

/// The node id in a peer certificate (CN + organization checked).
pub fn peer_id(der: &[u8]) -> Option<NodeId> {
    let c = kr_crypto::x509::Certificate::parse(der).ok()?;
    if !c.organizations().iter().any(|o| *o == ORG.as_bytes()) {
        return None;
    }
    let cn = core::str::from_utf8(c.common_name()?).ok()?;
    cn.strip_prefix("system:kr-server:")?.parse().ok().filter(|id| *id != 0)
}

/// Wakes the Raft driver when something arrives.
#[derive(Default)]
pub struct Notify {
    flag: Cell<bool>,
    waker: RefCell<Option<Waker>>,
}

impl Notify {
    pub fn notify(&self) {
        self.flag.set(true);
        if let Some(w) = self.waker.borrow_mut().take() {
            w.wake();
        }
    }

    /// Resolves on `notify` or after `max_ms`.
    pub async fn wait(&self, max_ms: u64) {
        let wait = poll_fn(|cx| {
            if self.flag.replace(false) {
                Poll::Ready(())
            } else {
                *self.waker.borrow_mut() = Some(cx.waker().clone());
                Poll::Pending
            }
        });
        let _ = timeout(max_ms, wait).await;
    }
}

/// Received messages, drained by the driver.
#[derive(Default)]
pub struct Inbox {
    pub msgs: RefCell<VecDeque<Message>>,
    pub notify: Notify,
    /// Set on shutdown: connection tasks stop delivering and close.
    pub closed: Cell<bool>,
}

async fn read_exact<T: Transport>(s: &mut T, buf: &mut [u8]) -> bool {
    let mut got = 0;
    while got < buf.len() {
        match s.read(&mut buf[got..]).await {
            Ok(0) | Err(_) => return false,
            Ok(n) => got += n,
        }
    }
    true
}

/// Accepts peers on `listener` and feeds their messages into `inbox`.
pub async fn serve(listener: Async<Fd>, tls: Rc<ServerConfig>, me: NodeId, inbox: Rc<Inbox>) {
    loop {
        let Ok(sock) = listener.accept().await else {
            sleep(50).await;
            continue;
        };
        let (tls, inbox) = (tls.clone(), inbox.clone());
        spawn(async move {
            let Ok(Ok(mut s)) = timeout(10_000, TlsStream::accept(sock, tls)).await else { return };
            let Some(from) = s.connection().peer_certificates().first().and_then(|c| peer_id(c)) else { return };
            let mut hdr = [0u8; 4];
            loop {
                if !read_exact(&mut s, &mut hdr).await {
                    return;
                }
                let n = u32::from_le_bytes(hdr) as usize;
                if n > MAX_FRAME {
                    return;
                }
                let mut buf = alloc::vec![0u8; n];
                if !read_exact(&mut s, &mut buf).await {
                    return;
                }
                // Only well-formed messages, addressed to us, from the authenticated sender.
                if inbox.closed.get() {
                    return;
                }
                match codec::decode_message(&buf) {
                    Some(m) if m.from == from && m.to == me => {
                        inbox.msgs.borrow_mut().push_back(m);
                        inbox.notify.notify();
                    }
                    _ => return,
                }
            }
        });
    }
}

/// An outbound link to one peer.
pub struct Peer {
    queue: Rc<RefCell<VecDeque<Vec<u8>>>>,
    wake: Rc<Notify>,
    addr: Rc<RefCell<([u8; 4], u16)>>,
    _task: JoinHandle<()>,
}

impl Peer {
    pub fn new(addr: ([u8; 4], u16), tls: Rc<ClientConfig>) -> Peer {
        let queue: Rc<RefCell<VecDeque<Vec<u8>>>> = Rc::default();
        let wake: Rc<Notify> = Rc::default();
        let addr = Rc::new(RefCell::new(addr));
        let task = spawn(sender(queue.clone(), wake.clone(), addr.clone(), tls));
        Peer { queue, wake, addr, _task: task }
    }

    /// A changed address takes effect at once: the open connection is dropped (one to a dead
    /// address can accept writes for minutes before TCP gives up).
    pub fn set_addr(&self, addr: ([u8; 4], u16)) {
        if *self.addr.borrow() != addr {
            *self.addr.borrow_mut() = addr;
            self.wake.notify();
        }
    }

    pub fn send(&self, m: &Message) {
        let mut q = self.queue.borrow_mut();
        if q.len() >= QUEUE {
            return; // Raft retransmits; never block the node on a slow peer
        }
        let body = codec::encode_message(m);
        let mut f = Vec::with_capacity(4 + body.len());
        f.extend_from_slice(&(body.len() as u32).to_le_bytes());
        f.extend_from_slice(&body);
        q.push_back(f);
        drop(q);
        self.wake.notify();
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self._task.abort();
    }
}

async fn sender(queue: Rc<RefCell<VecDeque<Vec<u8>>>>, wake: Rc<Notify>, addr: Rc<RefCell<([u8; 4], u16)>>, tls: Rc<ClientConfig>) {
    let mut backoff = 100;
    loop {
        let (ip, port) = *addr.borrow();
        let sock = match kr_net::tcp::connect_addr(kr_net::tcp::SocketAddr { ip: kr_net::tcp::IpAddr::V4(ip), port }, 3000).await {
            Ok(s) => s,
            Err(_) => {
                // Messages queued for a dead peer are stale by the time it returns.
                queue.borrow_mut().clear();
                sleep(backoff).await;
                backoff = (backoff * 2).min(2000);
                continue;
            }
        };
        let name = alloc::format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
        let mut s = match timeout(10_000, TlsStream::connect(sock, tls.clone(), &name)).await {
            Ok(Ok(s)) => s,
            _ => {
                queue.borrow_mut().clear();
                sleep(backoff).await;
                backoff = (backoff * 2).min(2000);
                continue;
            }
        };
        backoff = 100;
        loop {
            if *addr.borrow() != (ip, port) {
                break; // moved: reconnect to the new address
            }
            let next = queue.borrow_mut().pop_front();
            match next {
                Some(f) => {
                    if timeout(10_000, s.write_all(&f)).await.map(|r| r.is_ok()) != Ok(true) {
                        break; // reconnect; this frame is lost (Raft retransmits)
                    }
                }
                None => wake.wait(1000).await,
            }
        }
    }
}
