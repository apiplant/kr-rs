//! TLS 1.3 streams over the executor: glue between `kr_crypto::tls` (sans-I/O) and sockets.
//!
//! [`TlsStream`] implements [`Transport`], so the HTTP client works over it unchanged;
//! [`TlsConnector`] picks plain TCP or TLS per URL scheme.

use crate::http1::{Connector, Scheme, Transport, Url};
use crate::dns::SystemResolver;
use crate::tcp::{self, Resolver};
use crate::{Error, Result};
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use kr_crypto::resume::{SessionCache, SessionHooks, TicketHooks, TicketKeys};
use kr_crypto::tls::{ClientConfig, Connection, ServerConfig};
use kr_rt::exec::Async;
use kr_sys::Fd;

fn rng(buf: &mut [u8]) {
    kr_sys::getrandom(buf)
}

fn unix_now() -> i64 {
    kr_sys::clock_gettime(0).map(|t| t.tv_sec as i64).unwrap_or(0) // CLOCK_REALTIME
}

/// A value behind a spin lock: the process-wide resumption state (ADR-051) must be a `static`,
/// and `kr-crypto` keeps no global state. The critical sections are a few microseconds and never
/// call back into this module, so contention (tests with threads) is harmless.
struct Spin<T> {
    lock: AtomicBool,
    v: UnsafeCell<T>,
}

// SAFETY: access to `v` is serialised by `lock`.
unsafe impl<T: Send> Sync for Spin<T> {}

impl<T> Spin<T> {
    const fn new(v: T) -> Spin<T> {
        Spin { lock: AtomicBool::new(false), v: UnsafeCell::new(v) }
    }

    fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        while self.lock.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        // SAFETY: the lock is held, so this is the only reference.
        let r = f(unsafe { &mut *self.v.get() });
        self.lock.store(false, Ordering::Release);
        r
    }
}

/// Ticket keys of this process (servers): a restart invalidates every ticket, which only costs a
/// full handshake.
static TICKET_KEYS: Spin<TicketKeys> = Spin::new(TicketKeys::new());
/// Tickets received from servers (clients).
static SESSIONS: Spin<SessionCache> = Spin::new(SessionCache::new());
static RESUMPTION: AtomicBool = AtomicBool::new(true);

const TICKET_HOOKS: TicketHooks = TicketHooks { seal: |p, now| TICKET_KEYS.with(|k| k.seal(p, now, rng)), open: |t| TICKET_KEYS.with(|k| k.open(t)) };
const SESSION_HOOKS: SessionHooks = SessionHooks { put: |k, s| SESSIONS.with(|c| c.put(k, s)), take: |k, now| SESSIONS.with(|c| c.take(k, now)) };

/// Turns TLS 1.3 session resumption (ADR-051) on or off for connections made afterwards; on by default.
pub fn set_resumption(enabled: bool) {
    RESUMPTION.store(enabled, Ordering::Relaxed);
}

/// A TLS connection over an inner transport.
pub struct TlsStream<T: Transport> {
    inner: T,
    conn: Connection,
    /// Ciphertext not yet written (kept across cancelled writes).
    pending: Vec<u8>,
    rbuf: Vec<u8>,
}

impl<T: Transport> TlsStream<T> {
    /// Client handshake to `server_name` (also checked against the certificate).
    pub async fn connect(inner: T, cfg: Rc<ClientConfig>, server_name: &str) -> Result<Self> {
        let conn = if RESUMPTION.load(Ordering::Relaxed) {
            Connection::client_with_sessions(cfg, server_name.as_bytes(), SESSION_HOOKS, rng, unix_now())
        } else {
            Connection::client(cfg, server_name.as_bytes(), rng, unix_now())
        };
        Self::handshake(inner, conn).await
    }

    /// Client handshake that accepts any server certificate (`Connection::client_insecure`).
    pub async fn connect_insecure(inner: T, cfg: Rc<ClientConfig>, server_name: &str) -> Result<Self> {
        let conn = Connection::client_insecure(cfg, server_name.as_bytes(), rng, unix_now());
        Self::handshake(inner, conn).await
    }

    /// Server handshake on an accepted connection.
    pub async fn accept(inner: T, cfg: Rc<ServerConfig>) -> Result<Self> {
        let conn = if RESUMPTION.load(Ordering::Relaxed) {
            Connection::server_with_tickets(cfg, TICKET_HOOKS, rng, unix_now())
        } else {
            Connection::server(cfg, rng, unix_now())
        };
        Self::handshake(inner, conn).await
    }

    async fn handshake(inner: T, conn: Connection) -> Result<Self> {
        let mut s = TlsStream { inner, conn, pending: Vec::new(), rbuf: alloc::vec![0; 16 * 1024 + 512] };
        while s.conn.is_handshaking() {
            s.flush().await?;
            s.read_more().await?;
        }
        s.flush().await?; // client Finished
        Ok(s)
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// The underlying transport (e.g. to reach the socket for a lingering close).
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    async fn flush(&mut self) -> Result<()> {
        self.pending.extend_from_slice(&self.conn.take_output());
        if !self.pending.is_empty() {
            self.inner.write_all(&self.pending).await?;
            self.pending.clear();
        }
        Ok(())
    }

    /// Reads one chunk from the socket into the TLS engine. EOF before close_notify is an error
    /// (truncation attack) once the handshake is done.
    async fn read_more(&mut self) -> Result<()> {
        let n = self.inner.read(&mut self.rbuf).await?;
        if n == 0 {
            return Err(Error::UnexpectedEof);
        }
        let r = self.conn.feed(&self.rbuf[..n]);
        if r.is_err() {
            let _ = self.flush().await; // deliver our alert
        }
        r.map_err(Error::Tls)
    }

    /// Sends close_notify.
    pub async fn shutdown(&mut self) -> Result<()> {
        self.conn.close();
        self.flush().await
    }
}

impl<T: Transport> Transport for TlsStream<T> {
    fn peer_gone(&self) -> bool {
        self.inner.peer_gone()
    }

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let n = self.conn.read(buf);
            if n > 0 || buf.is_empty() {
                return Ok(n);
            }
            if self.conn.peer_closed() {
                return Ok(0);
            }
            self.read_more().await?;
            self.flush().await?; // KeyUpdate responses
        }
    }

    async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.flush().await?;
        // Encrypting a multi-MB body (a large list, the OpenAPI document) in one call is one long
        // poll of the event loop: seal and send it in slices, giving other tasks a turn whenever
        // this poll has run for a few ms. The slices also bound the encrypted data held in memory.
        for chunk in buf.chunks(64 * 1024) {
            self.conn.write(chunk).map_err(Error::Tls)?;
            if buf.len() > 64 * 1024 {
                self.flush().await?;
                kr_rt::exec::yield_if_long(5).await;
            }
        }
        self.flush().await
    }
}

/// Either side of an `http`/`https` URL.
pub enum MaybeTls {
    Plain(Async<Fd>),
    Tls(TlsStream<Async<Fd>>),
}

impl Transport for MaybeTls {
    fn peer_gone(&self) -> bool {
        match self {
            MaybeTls::Plain(s) => Transport::peer_gone(s),
            MaybeTls::Tls(s) => s.peer_gone(),
        }
    }
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            MaybeTls::Plain(s) => Transport::read(s, buf).await,
            MaybeTls::Tls(s) => s.read(buf).await,
        }
    }
    async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        match self {
            MaybeTls::Plain(s) => Transport::write_all(s, buf).await,
            MaybeTls::Tls(s) => s.write_all(buf).await,
        }
    }
}

/// Connects with TLS for `https` URLs and plain TCP otherwise.
pub struct TlsConnector<R: Resolver = SystemResolver> {
    resolver: R,
    /// Swappable (certificate rotation); new connections pick up the current config.
    cfg: core::cell::RefCell<Rc<ClientConfig>>,
}

impl<R: Resolver> TlsConnector<R> {
    pub fn new(resolver: R, cfg: Rc<ClientConfig>) -> Self {
        TlsConnector { resolver, cfg: core::cell::RefCell::new(cfg) }
    }

    /// Replaces the config for future connections (pooled connections keep theirs).
    pub fn set_config(&self, cfg: Rc<ClientConfig>) {
        *self.cfg.borrow_mut() = cfg;
    }
}

impl TlsConnector {
    /// System resolver (hosts + DNS), trust anchors from the given PEM bundle.
    pub fn with_roots_pem(pem: &str) -> Result<Self> {
        let roots = kr_crypto::x509::pem_decode_all(pem, "CERTIFICATE").map_err(|_| Error::BadRef("bad CA bundle"))?;
        Ok(TlsConnector {
            resolver: SystemResolver::system(),
            cfg: core::cell::RefCell::new(Rc::new(ClientConfig { pinned_ca: None, roots, client_cert: None, alpn: alloc::vec![b"http/1.1".to_vec()], tls12: true })),
        })
    }
}

impl<R: Resolver> Connector for TlsConnector<R> {
    type Conn = MaybeTls;
    async fn connect(&self, url: &Url, timeout_ms: u64) -> Result<MaybeTls> {
        let sock = tcp::connect(&self.resolver, &url.host, url.port, timeout_ms).await?;
        if url.scheme != Scheme::Https {
            return Ok(MaybeTls::Plain(sock));
        }
        let hs = TlsStream::connect(sock, self.cfg.borrow().clone(), &url.host);
        match kr_rt::exec::timeout(timeout_ms, hs).await {
            Ok(r) => r.map(MaybeTls::Tls),
            Err(_) => Err(Error::Timeout),
        }
    }
}
