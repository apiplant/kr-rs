//! HTTP/1.1: strict head parser, chunked coding, URL handling, a keep-alive client and a server.
//!
//! The client is generic over [`Connector`]/[`Transport`], so a TLS connector can be added
//! later (ADR-013, ADR-015) without touching the protocol code.

pub mod body;
pub mod channel;
pub mod client;
pub mod head;
pub mod server;
pub mod upgrade;
pub mod url;
pub mod websocket;

pub use client::{Client, Config, Response};
pub use head::{Framing, Header, Limits};
pub use url::{Scheme, Url};

use crate::tcp::{self, HostsResolver, Resolver};
use crate::{Error, Result};
use kr_rt::exec::Async;
use kr_sys::Fd;

/// A bidirectional byte stream. Implementations must be cancel-safe at `.await` points the way
/// the executor's [`Async`] is: dropping a pending future loses no data.
#[allow(async_fn_in_trait)]
pub trait Transport {
    /// Reads at least one byte, or returns `Ok(0)` at EOF.
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
    async fn write_all(&mut self, buf: &[u8]) -> Result<()>;
}

impl Transport for Async<Fd> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        Async::read(self, buf).await.map_err(Error::Io)
    }
    async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        Async::write_all(self, buf).await.map_err(Error::Io)
    }
}

/// Opens a [`Transport`] to the origin of a URL. A TLS implementation wraps the TCP stream
/// for `https` URLs.
#[allow(async_fn_in_trait)]
pub trait Connector {
    type Conn: Transport;
    async fn connect(&self, url: &Url, timeout_ms: u64) -> Result<Self::Conn>;
}

/// Plain TCP. `https` URLs fail with [`Error::TlsUnsupported`].
pub struct TcpConnector<R: Resolver = HostsResolver> {
    resolver: R,
}

impl<R: Resolver> TcpConnector<R> {
    pub fn new(resolver: R) -> Self {
        TcpConnector { resolver }
    }
}

impl Default for TcpConnector {
    fn default() -> Self {
        TcpConnector { resolver: HostsResolver::system() }
    }
}

impl<R: Resolver> Connector for TcpConnector<R> {
    type Conn = Async<Fd>;
    async fn connect(&self, url: &Url, timeout_ms: u64) -> Result<Async<Fd>> {
        if url.scheme == Scheme::Https {
            return Err(Error::TlsUnsupported);
        }
        tcp::connect(&self.resolver, &url.host, url.port, timeout_ms).await
    }
}
