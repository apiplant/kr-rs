//! `kr-net`: async TCP connect, a strict HTTP/1.1 client and an OCI distribution (registry v2)
//! client (ADR-013, ADR-015).
//!
//! `no_std` + `alloc`, no dependencies outside the workspace. TLS is not available yet: the
//! HTTP client is written against the [`http1::Transport`] / [`http1::Connector`] traits and
//! `https` URLs fail with [`Error::TlsUnsupported`] until `kr-crypto` provides a connector.
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod dns;
pub mod http1;
pub mod netlink;
pub mod nft;
pub mod registry;
pub mod sha256;
pub mod tcp;
pub mod tls;

use kr_sys::Errno;

/// Every failure in this crate. Static strings keep the type `Clone + Eq` and allocation-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A syscall failed.
    Io(Errno),
    /// A connect, request-head or idle-read deadline expired.
    Timeout,
    /// Name resolution failed (hosts file and DNS).
    Resolve,
    /// An `https` URL was requested from a plain-TCP connector (use `tls::TlsConnector`).
    TlsUnsupported,
    /// The TLS handshake or record layer failed.
    Tls(kr_crypto::tls::Error),
    BadUrl(&'static str),
    /// Malformed HTTP syntax.
    Parse(&'static str),
    /// A message that is ambiguous in a way that enables request smuggling.
    Smuggling(&'static str),
    /// A configured size/count limit was exceeded.
    TooLarge(&'static str),
    /// The peer closed the connection before the message was complete.
    UnexpectedEof,
    TooManyRedirects,
    /// A redirect changed the scheme (e.g. http -> https), which is refused.
    RedirectScheme,
    /// The server answered with an unexpected HTTP status.
    Status(u16),
    BadRef(&'static str),
    /// JSON in a manifest or token response could not be used.
    Json(&'static str),
    Manifest(&'static str),
    /// The index has no entry for this machine's linux platform.
    NoPlatform,
    DigestMismatch,
    /// Only `sha256` digests can be verified.
    UnsupportedDigest,
    Auth(&'static str),
    /// A caller-supplied sink refused data.
    Sink,
}

impl From<Errno> for Error {
    fn from(e: Errno) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = core::result::Result<T, Error>;
