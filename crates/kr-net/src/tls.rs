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
use kr_crypto::tls::{ClientConfig, Connection, ServerConfig};
use kr_rt::exec::Async;
use kr_sys::Fd;

fn rng(buf: &mut [u8]) {
    kr_sys::getrandom(buf)
}

fn unix_now() -> i64 {
    kr_sys::clock_gettime(0).map(|t| t.tv_sec as i64).unwrap_or(0) // CLOCK_REALTIME
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
        let conn = Connection::client(cfg, server_name.as_bytes(), rng, unix_now());
        Self::handshake(inner, conn).await
    }

    /// Server handshake on an accepted connection.
    pub async fn accept(inner: T, cfg: Rc<ServerConfig>) -> Result<Self> {
        Self::handshake(inner, Connection::server(cfg, rng, unix_now())).await
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
        self.conn.write(buf).map_err(Error::Tls)?;
        self.flush().await
    }
}

/// Either side of an `http`/`https` URL.
pub enum MaybeTls {
    Plain(Async<Fd>),
    Tls(TlsStream<Async<Fd>>),
}

impl Transport for MaybeTls {
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
    cfg: Rc<ClientConfig>,
}

impl<R: Resolver> TlsConnector<R> {
    pub fn new(resolver: R, cfg: Rc<ClientConfig>) -> Self {
        TlsConnector { resolver, cfg }
    }
}

impl TlsConnector {
    /// System resolver (hosts + DNS), trust anchors from the given PEM bundle.
    pub fn with_roots_pem(pem: &str) -> Result<Self> {
        let roots = kr_crypto::x509::pem_decode_all(pem, "CERTIFICATE").map_err(|_| Error::BadRef("bad CA bundle"))?;
        Ok(TlsConnector {
            resolver: SystemResolver::system(),
            cfg: Rc::new(ClientConfig { pinned_ca: None, roots, client_cert: None, alpn: alloc::vec![b"http/1.1".to_vec()] }),
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
        let hs = TlsStream::connect(sock, self.cfg.clone(), &url.host);
        match kr_rt::exec::timeout(timeout_ms, hs).await {
            Ok(r) => r.map(MaybeTls::Tls),
            Err(_) => Err(Error::Timeout),
        }
    }
}
