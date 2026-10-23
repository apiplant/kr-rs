//! The Kubernetes streaming channel protocol over WebSocket binary messages.
//!
//! `v4.channel.k8s.io` / `v5.channel.k8s.io` (exec, attach): every message is
//! `[channel byte][payload]`. Channels: 0 stdin, 1 stdout, 2 stderr, 3 error (a `metav1.Status`
//! JSON), 4 resize (`{"Width":w,"Height":h}`), and in v5 only 255 close-stream (payload: one
//! byte, the channel to close).
//!
//! `v2.portforward.k8s.io` / `portforward.k8s.io` (port-forward, WebSocket form only): for the
//! i-th requested port, channel `2*i` carries data and `2*i+1` carries errors. The server's
//! first frame on each of those channels is the port number as 2 little-endian bytes
//! ([`PortForward::initial_frames`]). The apiserver does not expect a header from the client;
//! [`PortForward::expect_client_header`] enables dropping a matching one (off by default).

use crate::{Error, Result};
use alloc::string::String;
use alloc::vec::Vec;

pub const STDIN: u8 = 0;
pub const STDOUT: u8 = 1;
pub const STDERR: u8 = 2;
pub const ERROR: u8 = 3;
pub const RESIZE: u8 = 4;
pub const CLOSE: u8 = 255;

pub const V5: &str = "v5.channel.k8s.io";
pub const V4: &str = "v4.channel.k8s.io";
pub const PORTFORWARD_V2: &str = "v2.portforward.k8s.io";
pub const PORTFORWARD_V1: &str = "portforward.k8s.io";

/// Exec/attach subprotocols in server preference order, for [`super::websocket::handshake`].
pub const EXEC_PROTOCOLS: [&str; 2] = [V5, V4];
/// Port-forward subprotocols in server preference order.
pub const PORTFORWARD_PROTOCOLS: [&str; 2] = [PORTFORWARD_V2, PORTFORWARD_V1];

/// A negotiated subprotocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    V4,
    V5,
    PortForwardV2,
    PortForwardV1,
}

impl Protocol {
    pub fn from_token(t: &str) -> Option<Protocol> {
        Some(match t {
            V5 => Protocol::V5,
            V4 => Protocol::V4,
            PORTFORWARD_V2 => Protocol::PortForwardV2,
            PORTFORWARD_V1 => Protocol::PortForwardV1,
            _ => return None,
        })
    }

    pub fn token(self) -> &'static str {
        match self {
            Protocol::V5 => V5,
            Protocol::V4 => V4,
            Protocol::PortForwardV2 => PORTFORWARD_V2,
            Protocol::PortForwardV1 => PORTFORWARD_V1,
        }
    }

    /// True if channel 255 (close-stream) exists.
    pub fn has_close_stream(self) -> bool {
        self == Protocol::V5
    }
}

// ---------- frames ----------

/// `[channel][data]`.
pub fn encode(channel: u8, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + data.len());
    v.push(channel);
    v.extend_from_slice(data);
    v
}

/// Splits a message into channel and payload. An empty message is an error.
pub fn decode(msg: &[u8]) -> Result<(u8, &[u8])> {
    match msg.split_first() {
        Some((c, rest)) => Ok((*c, rest)),
        None => Err(Error::Parse("channel: empty message")),
    }
}

/// Terminal size from a resize message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalSize {
    pub width: u16,
    pub height: u16,
}

/// What a client sent on an exec/attach connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientMsg<'a> {
    Stdin(&'a [u8]),
    Resize(TerminalSize),
    /// v5 only: the client closed this channel (for stdin: EOF to the process).
    CloseStream(u8),
    /// Output/error channels or unknown ones; servers ignore these.
    Other(u8, &'a [u8]),
}

/// Decodes a client message for exec/attach under `proto` (v4 or v5).
pub fn decode_client(proto: Protocol, msg: &[u8]) -> Result<ClientMsg<'_>> {
    let (ch, data) = decode(msg)?;
    Ok(match ch {
        STDIN => ClientMsg::Stdin(data),
        RESIZE => ClientMsg::Resize(parse_resize(data)?),
        CLOSE if proto.has_close_stream() => match data {
            [c] => ClientMsg::CloseStream(*c),
            _ => return Err(Error::Parse("channel: bad close-stream message")),
        },
        c => ClientMsg::Other(c, data),
    })
}

/// Parses `{"Width":w,"Height":h}` (lower-case keys accepted too).
pub fn parse_resize(data: &[u8]) -> Result<TerminalSize> {
    let v = kr_fmt::json::parse(data).map_err(|_| Error::Parse("channel: bad resize json"))?;
    let get = |a: &str, b: &str| -> Result<u16> {
        let n = v.get(a).or_else(|| v.get(b)).and_then(|x| x.as_u64()).ok_or(Error::Parse("channel: bad resize json"))?;
        u16::try_from(n).map_err(|_| Error::Parse("channel: resize out of range"))
    };
    Ok(TerminalSize { width: get("Width", "width")?, height: get("Height", "height")? })
}

pub fn stdout_frame(data: &[u8]) -> Vec<u8> {
    encode(STDOUT, data)
}

pub fn stderr_frame(data: &[u8]) -> Vec<u8> {
    encode(STDERR, data)
}

pub fn error_frame(status_json: &str) -> Vec<u8> {
    encode(ERROR, status_json.as_bytes())
}

/// v5: tells the client we closed `channel`.
pub fn close_frame(channel: u8) -> Vec<u8> {
    encode(CLOSE, &[channel])
}

// ---------- exec status ----------

/// `{"metadata":{},"status":"Success"}`
pub fn status_success() -> String {
    String::from("{\"metadata\":{},\"status\":\"Success\"}")
}

/// Status for a finished command: success for 0, else the `NonZeroExitCode` failure that
/// kubectl turns into its exit status.
pub fn status_exit(code: i32) -> String {
    if code == 0 {
        return status_success();
    }
    let mut s = String::from("{\"metadata\":{},\"status\":\"Failure\",\"message\":");
    kr_fmt::json::write_str(&alloc::format!("command terminated with non-zero exit code: exit status {code}"), &mut s);
    s.push_str(",\"reason\":\"NonZeroExitCode\",\"details\":{\"causes\":[{\"reason\":\"ExitCode\",\"message\":");
    kr_fmt::json::write_str(&alloc::format!("{code}"), &mut s);
    s.push_str("}]}}");
    s
}

/// A generic failure status, e.g. `status_failure("container not found", "InternalError")`.
pub fn status_failure(message: &str, reason: &str) -> String {
    let mut s = String::from("{\"metadata\":{},\"status\":\"Failure\",\"message\":");
    kr_fmt::json::write_str(message, &mut s);
    s.push_str(",\"reason\":");
    kr_fmt::json::write_str(reason, &mut s);
    s.push('}');
    s
}

// ---------- port-forward ----------

/// Parses the `ports` query parameters (`ports=80&ports=8080,9090`): 1..=65535, no duplicates,
/// at least one, at most 64.
pub fn parse_ports(query: &str) -> Result<Vec<u16>> {
    let mut ports: Vec<u16> = Vec::new();
    for kv in query.split('&') {
        let Some(("ports", v)) = kv.split_once('=') else { continue };
        for p in v.split(',') {
            let n: u16 = p.trim().parse().map_err(|_| Error::Parse("portforward: bad port"))?;
            if n == 0 {
                return Err(Error::Parse("portforward: port 0"));
            }
            if ports.contains(&n) {
                return Err(Error::Parse("portforward: duplicate port"));
            }
            if ports.len() == 64 {
                return Err(Error::TooLarge("portforward: too many ports"));
            }
            ports.push(n);
        }
    }
    if ports.is_empty() {
        return Err(Error::Parse("portforward: no ports"));
    }
    Ok(ports)
}

/// Which stream of a forwarded port a channel is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortStream {
    Data,
    Error,
}

/// The channel layout of one port-forward session.
#[derive(Clone, Debug)]
pub struct PortForward {
    pub ports: Vec<u16>,
    /// Per channel: the client's first frame is still expected to be the port header.
    pending_header: Vec<bool>,
}

impl PortForward {
    pub fn new(ports: Vec<u16>) -> PortForward {
        PortForward { pending_header: alloc::vec![false; ports.len() * 2], ports }
    }

    /// From a request query string (see [`parse_ports`]).
    pub fn from_query(query: &str) -> Result<PortForward> {
        parse_ports(query).map(PortForward::new)
    }

    /// Treat a first client frame of exactly the 2-byte LE port on a channel as a header and
    /// drop it, instead of passing it on as data. Off by default.
    pub fn expect_client_header(mut self, on: bool) -> PortForward {
        self.pending_header = alloc::vec![on; self.ports.len() * 2];
        self
    }

    pub fn data_channel(&self, index: usize) -> u8 {
        (index * 2) as u8
    }

    pub fn error_channel(&self, index: usize) -> u8 {
        (index * 2 + 1) as u8
    }

    /// The first frame on every channel, in channel order: `[channel, port_lo, port_hi]`.
    pub fn initial_frames(&self) -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        for (i, p) in self.ports.iter().enumerate() {
            v.push(encode(self.data_channel(i), &p.to_le_bytes()));
            v.push(encode(self.error_channel(i), &p.to_le_bytes()));
        }
        v
    }

    /// Maps a channel to `(port index, stream)`; `None` if out of range.
    pub fn route(&self, channel: u8) -> Option<(usize, PortStream)> {
        let i = (channel / 2) as usize;
        if i >= self.ports.len() {
            return None;
        }
        Some((i, if channel % 2 == 0 { PortStream::Data } else { PortStream::Error }))
    }

    /// Decodes a client message. `Ok(Some((port_index, payload)))` is data for that port;
    /// `Ok(None)` means nothing to forward (header, empty frame or the error channel, which
    /// clients do not write to). An unknown channel is an error.
    pub fn client_data<'a>(&mut self, msg: &'a [u8]) -> Result<Option<(usize, &'a [u8])>> {
        let (ch, data) = decode(msg)?;
        let (i, stream) = self.route(ch).ok_or(Error::Parse("portforward: unknown channel"))?;
        if core::mem::take(&mut self.pending_header[ch as usize]) && data == self.ports[i].to_le_bytes() {
            return Ok(None);
        }
        if stream == PortStream::Error || data.is_empty() {
            return Ok(None);
        }
        Ok(Some((i, data)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn frames_and_clients() {
        assert_eq!(encode(1, b"hi"), [1, b'h', b'i']);
        assert_eq!(decode(&[2, 9]).unwrap(), (2, &[9u8][..]));
        assert!(decode(&[]).is_err());
        assert_eq!(decode_client(Protocol::V4, &[0, b'x']).unwrap(), ClientMsg::Stdin(b"x"));
        assert_eq!(
            decode_client(Protocol::V5, &[&[4u8][..], br#"{"Width":120,"Height":40}"#].concat()).unwrap(),
            ClientMsg::Resize(TerminalSize { width: 120, height: 40 })
        );
        assert_eq!(decode_client(Protocol::V5, &[255, 0]).unwrap(), ClientMsg::CloseStream(0));
        assert_eq!(decode_client(Protocol::V4, &[255, 0]).unwrap(), ClientMsg::Other(255, &[0]));
        assert!(decode_client(Protocol::V5, &[255]).is_err());
        assert!(decode_client(Protocol::V5, &[4, b'{']).is_err());
    }

    #[test]
    fn statuses() {
        assert_eq!(status_success(), r#"{"metadata":{},"status":"Success"}"#);
        assert_eq!(status_exit(0), status_success());
        let s = status_exit(3);
        let v = kr_fmt::json::parse_str(&s).unwrap();
        assert_eq!(v.get("reason").and_then(|x| x.as_str()), Some("NonZeroExitCode"));
        assert_eq!(v.get("status").and_then(|x| x.as_str()), Some("Failure"));
        let c = v.pointer(&["details", "causes"]).and_then(|c| c.at(0)).unwrap();
        assert_eq!(c.get("reason").and_then(|x| x.as_str()), Some("ExitCode"));
        assert_eq!(c.get("message").and_then(|x| x.as_str()), Some("3"));
        let f = status_failure("a \"q\"\n", "InternalError");
        assert_eq!(kr_fmt::json::parse_str(&f).unwrap().get("message").and_then(|x| x.as_str()), Some("a \"q\"\n"));
    }

    #[test]
    fn ports() {
        assert_eq!(parse_ports("ports=80&ports=8080,9090&x=1").unwrap(), vec![80, 8080, 9090]);
        assert!(parse_ports("").is_err());
        assert!(parse_ports("ports=0").is_err());
        assert!(parse_ports("ports=80&ports=80").is_err());
        assert!(parse_ports("ports=70000").is_err());
        let mut pf = PortForward::from_query("ports=80,443").unwrap();
        assert_eq!(pf.initial_frames(), vec![vec![0, 80, 0], vec![1, 80, 0], vec![2, 0xBB, 1], vec![3, 0xBB, 1]]);
        assert_eq!(pf.route(3), Some((1, PortStream::Error)));
        assert_eq!(pf.route(4), None);
        assert_eq!(pf.client_data(&[2, b'x']).unwrap(), Some((1, &b"x"[..])));
        assert_eq!(pf.client_data(&[3, b'x']).unwrap(), None);
        assert!(pf.client_data(&[9, b'x']).is_err());
        let mut pf = pf.expect_client_header(true);
        assert_eq!(pf.client_data(&[0, 80, 0]).unwrap(), None);
        assert_eq!(pf.client_data(&[0, 80, 0]).unwrap(), Some((0, &[80u8, 0][..])));
    }
}
