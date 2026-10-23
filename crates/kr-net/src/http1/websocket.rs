//! WebSocket (RFC 6455), server side: handshake, frame codec and a poll-friendly [`WebSocket`].
//!
//! # Design
//!
//! [`WebSocket`] owns all its state (input buffer, partially assembled message, output queue),
//! so it can be driven either with the `async` methods or from a hand-written polling loop:
//!
//! * [`WebSocket::poll_recv`] / [`WebSocket::recv`]: cancel-safe. A dropped `recv` future loses
//!   nothing; bytes already read stay buffered.
//! * `queue_*` methods append whole frames to the output queue synchronously (never blocking,
//!   never partially). [`WebSocket::poll_flush`] / [`WebSocket::flush`] push the queue out.
//!   `send_*` = `queue_*` + `flush`, so a cancelled `send_*` leaves the message queued and a
//!   later flush delivers it exactly once.
//!
//! Select reads against writes by polling `poll_recv` and `poll_flush` in one `poll_fn`.
//! Control replies (pong, close echo) are queued automatically and flushed by `recv` itself.
//!
//! Flush cancel-safety requires `T::write_all` to be all-or-nothing when cancelled. That holds
//! for the `Box<dyn Conn>` handed to upgrade handlers; a raw socket transport may repeat a
//! partially written prefix if a flush is dropped mid-write, so do not cancel flushes on those.
//!
//! Failures in the peer's framing queue the matching close frame (1002 protocol error, 1007 bad
//! UTF-8, 1009 too big) before `recv` returns the error; `recv` flushes it best-effort.

use super::server::{Body, Request, Response};
use super::upgrade::UpgradeHandler;
use super::Transport;
use crate::{Error, Result};
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::future::{poll_fn, Future};
use core::pin::pin;
use core::task::{Context, Poll};
use kr_sys::Errno;

pub const DEFAULT_MAX_MESSAGE: usize = 16 * 1024 * 1024;

// ---------- SHA-1 (handshake only) ----------

/// SHA-1, used ONLY to compute `Sec-WebSocket-Accept` as RFC 6455 section 4.2.2 mandates.
/// It is not used for any security purpose (the accept key proves the server understood the
/// upgrade request, nothing more) and must not be reused elsewhere: SHA-1 is broken for
/// collision resistance.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let mut msg = Vec::with_capacity(data.len() + 72);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, b) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6u32),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// `Sec-WebSocket-Accept` for a client key (RFC 6455 section 4.2.2).
pub fn accept_key(client_key: &str) -> String {
    let mut buf = String::with_capacity(client_key.len() + 36);
    buf.push_str(client_key);
    buf.push_str("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    kr_fmt::base64::encode(&sha1(buf.as_bytes()))
}

// ---------- handshake ----------

/// A validated upgrade request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handshake {
    /// The subprotocol chosen from the server's preference list (`None` if the client offered
    /// none or none matched; no `Sec-WebSocket-Protocol` header is then sent).
    pub protocol: Option<String>,
    /// True if the client offered at least one subprotocol.
    pub client_offered_protocols: bool,
    accept: String,
}

impl Handshake {
    /// The `101` response for this handshake, handing the connection to `handler`.
    pub fn into_response(self, handler: Box<dyn UpgradeHandler>) -> Response {
        let mut r = Response { status: 101, headers: Vec::new(), body: Body::Upgrade(handler) };
        r.headers.push(("Upgrade".to_string(), "websocket".to_string()));
        r.headers.push(("Sec-WebSocket-Accept".to_string(), self.accept));
        if let Some(p) = self.protocol {
            r.headers.push(("Sec-WebSocket-Protocol".to_string(), p));
        }
        r
    }
}

fn has_token(req: &Request, name: &str, token: &str) -> bool {
    req.headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .any(|(_, v)| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
}

fn reject(status: u16, msg: &str) -> Response {
    Response::new(status, alloc::format!("{msg}\n").into_bytes()).with_header("Content-Type", "text/plain")
}

/// Validates an upgrade request and picks the subprotocol: the first entry of
/// `server_protocols` (server preference order) that the client offered.
///
/// `Err` is a ready-made rejection: 405 for a non-GET method, 426 (with
/// `Sec-WebSocket-Version: 13`) for a wrong version, 400 for anything else malformed.
pub fn handshake(req: &Request, server_protocols: &[&str]) -> core::result::Result<Handshake, Response> {
    if req.method != "GET" {
        return Err(reject(405, "websocket upgrade requires GET").with_header("Allow", "GET"));
    }
    if !has_token(req, "upgrade", "websocket") {
        return Err(reject(400, "missing Upgrade: websocket"));
    }
    if !has_token(req, "connection", "upgrade") {
        return Err(reject(400, "missing Connection: Upgrade"));
    }
    let versions: Vec<&str> = req
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("sec-websocket-version"))
        .flat_map(|(_, v)| v.split(',').map(str::trim))
        .collect();
    if versions.as_slice() != ["13"] {
        return Err(reject(426, "unsupported websocket version").with_header("Sec-WebSocket-Version", "13"));
    }
    let mut keys = req.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("sec-websocket-key"));
    let key = match (keys.next(), keys.next()) {
        (Some((_, k)), None) => k.trim(),
        _ => return Err(reject(400, "missing or repeated Sec-WebSocket-Key")),
    };
    match kr_fmt::base64::decode(key) {
        Ok(raw) if raw.len() == 16 => {}
        _ => return Err(reject(400, "invalid Sec-WebSocket-Key")),
    }
    let offered: Vec<&str> = req
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("sec-websocket-protocol"))
        .flat_map(|(_, v)| v.split(',').map(str::trim))
        .filter(|t| !t.is_empty())
        .collect();
    let protocol = server_protocols.iter().find(|p| offered.contains(p)).map(|p| p.to_string());
    Ok(Handshake { protocol, client_offered_protocols: !offered.is_empty(), accept: accept_key(key) })
}

// ---------- messages and frames ----------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Text(String),
    Binary(Vec<u8>),
    /// The peer's close frame; `code` is 1005 when it carried none. The reply was queued.
    Close { code: u16, reason: String },
}

#[derive(Clone, Copy, Debug)]
pub struct WsConfig {
    /// Largest accepted message (all fragments together) in bytes; larger gets close 1009.
    pub max_message: usize,
}

impl Default for WsConfig {
    fn default() -> Self {
        WsConfig { max_message: DEFAULT_MAX_MESSAGE }
    }
}

const OP_CONT: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BIN: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// Appends one unmasked (server) frame.
pub fn encode_frame(out: &mut Vec<u8>, fin: bool, op: u8, payload: &[u8]) {
    out.push(if fin { 0x80 } else { 0 } | op);
    match payload.len() {
        n if n < 126 => out.push(n as u8),
        n if n <= 0xFFFF => {
            out.push(126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
}

fn valid_close_code(c: u16) -> bool {
    matches!(c, 1000..=1003 | 1007..=1014 | 3000..=4999)
}

fn epipe() -> Error {
    Error::Io(Errno(kr_sys::EPIPE))
}

pub struct WebSocket<T: Transport> {
    io: T,
    cfg: WsConfig,
    /// Raw input; `rpos` is the parse offset.
    rbuf: Vec<u8>,
    rpos: usize,
    /// The data message being assembled and its opcode.
    msg: Vec<u8>,
    msg_op: Option<u8>,
    /// Frames waiting to be written.
    out: Vec<u8>,
    close_sent: bool,
    /// A close frame was received or a protocol failure ended the session; `recv` errors.
    done: bool,
}

impl<T: Transport> WebSocket<T> {
    pub fn new(io: T, cfg: WsConfig) -> Self {
        WebSocket { io, cfg, rbuf: Vec::new(), rpos: 0, msg: Vec::new(), msg_op: None, out: Vec::new(), close_sent: false, done: false }
    }

    pub fn into_inner(self) -> T {
        self.io
    }

    /// True when queued output has not been written yet.
    pub fn has_pending_output(&self) -> bool {
        !self.out.is_empty()
    }

    /// True once a close frame has been queued or sent.
    pub fn is_closing(&self) -> bool {
        self.close_sent
    }

    // ----- sending -----

    fn check_open(&self) -> Result<()> {
        if self.close_sent {
            Err(epipe())
        } else {
            Ok(())
        }
    }

    pub fn queue_binary(&mut self, data: &[u8]) -> Result<()> {
        self.check_open()?;
        encode_frame(&mut self.out, true, OP_BIN, data);
        Ok(())
    }

    pub fn queue_text(&mut self, text: &str) -> Result<()> {
        self.check_open()?;
        encode_frame(&mut self.out, true, OP_TEXT, text.as_bytes());
        Ok(())
    }

    pub fn queue_ping(&mut self, data: &[u8]) -> Result<()> {
        self.check_open()?;
        encode_frame(&mut self.out, true, OP_PING, &data[..data.len().min(125)]);
        Ok(())
    }

    /// Queues a close frame (no-op if one was already queued). The reason is cut to fit.
    pub fn queue_close(&mut self, code: u16, reason: &str) {
        if self.close_sent {
            return;
        }
        self.close_sent = true;
        let mut p = Vec::with_capacity(2 + reason.len());
        p.extend_from_slice(&code.to_be_bytes());
        let mut n = reason.len().min(123);
        while !reason.is_char_boundary(n) {
            n -= 1;
        }
        p.extend_from_slice(&reason.as_bytes()[..n]);
        encode_frame(&mut self.out, true, OP_CLOSE, &p);
    }

    pub async fn send_binary(&mut self, data: &[u8]) -> Result<()> {
        self.queue_binary(data)?;
        self.flush().await
    }

    pub async fn send_text(&mut self, text: &str) -> Result<()> {
        self.queue_text(text)?;
        self.flush().await
    }

    /// Sends a close frame. The handshake completes when `recv` yields the peer's
    /// [`Message::Close`] (or errors); drop the transport afterwards.
    pub async fn close(&mut self, code: u16, reason: &str) -> Result<()> {
        self.queue_close(code, reason);
        self.flush().await
    }

    pub async fn flush(&mut self) -> Result<()> {
        poll_fn(|cx| self.poll_flush(cx)).await
    }

    /// Writes queued frames. `Ready` once the queue is empty.
    pub fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        if self.out.is_empty() {
            return Poll::Ready(Ok(()));
        }
        let r = {
            let mut f = pin!(self.io.write_all(&self.out));
            f.as_mut().poll(cx)
        };
        match r {
            Poll::Ready(Ok(())) => {
                self.out.clear();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                self.out.clear();
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    // ----- receiving -----

    /// Next data message or the peer's close. Pings are answered, pongs ignored. After a close
    /// frame or a protocol failure every call returns `Err`. Cancel-safe.
    pub async fn recv(&mut self) -> Result<Message> {
        let r = poll_fn(|cx| self.poll_recv(cx)).await;
        if !self.out.is_empty() {
            let _ = self.flush().await; // pong / close reply, best effort
        }
        r
    }

    /// Polling form of [`recv`](Self::recv). Also opportunistically pushes queued control
    /// replies; call [`poll_flush`](Self::poll_flush) after it returns `Ready`.
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Message>> {
        loop {
            match self.parse_next() {
                Ok(Some(m)) => return Poll::Ready(Ok(m)),
                Ok(None) => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
            if !self.out.is_empty() {
                let _ = self.poll_flush(cx);
            }
            if self.rpos > 0 {
                self.rbuf.drain(..self.rpos);
                self.rpos = 0;
            }
            let start = self.rbuf.len();
            self.rbuf.resize(start + 8192, 0);
            let r = {
                let mut f = pin!(self.io.read(&mut self.rbuf[start..]));
                f.as_mut().poll(cx)
            };
            match r {
                Poll::Pending => {
                    self.rbuf.truncate(start);
                    return Poll::Pending;
                }
                Poll::Ready(Ok(0)) => {
                    self.rbuf.truncate(start);
                    self.done = true;
                    return Poll::Ready(Err(Error::UnexpectedEof));
                }
                Poll::Ready(Ok(n)) => self.rbuf.truncate(start + n),
                Poll::Ready(Err(e)) => {
                    self.rbuf.truncate(start);
                    self.done = true;
                    return Poll::Ready(Err(e));
                }
            }
        }
    }

    /// Queues a close with `code` and ends the session.
    fn fail(&mut self, code: u16, why: &'static str) -> Error {
        self.queue_close(code, "");
        self.done = true;
        if code == 1009 {
            Error::TooLarge(why)
        } else {
            Error::Parse(why)
        }
    }

    /// Parses buffered input into the next message. `Ok(None)` = need more bytes.
    pub(crate) fn parse_next(&mut self) -> Result<Option<Message>> {
        loop {
            if self.done {
                return Err(Error::UnexpectedEof);
            }
            let b = &self.rbuf[self.rpos..];
            if b.len() < 2 {
                return Ok(None);
            }
            let (fin, rsv, op) = (b[0] & 0x80 != 0, b[0] & 0x70, b[0] & 0x0F);
            let masked = b[1] & 0x80 != 0;
            let (len, hl) = match b[1] & 0x7F {
                126 => {
                    if b.len() < 4 {
                        return Ok(None);
                    }
                    (u16::from_be_bytes([b[2], b[3]]) as u64, 4)
                }
                127 => {
                    if b.len() < 10 {
                        return Ok(None);
                    }
                    let mut a = [0u8; 8];
                    a.copy_from_slice(&b[2..10]);
                    (u64::from_be_bytes(a), 10)
                }
                n => (n as u64, 2),
            };
            // Header-level checks first, so a bad or oversized frame is refused before its
            // payload is buffered.
            if rsv != 0 {
                return Err(self.fail(1002, "websocket: reserved bits set"));
            }
            if !masked {
                return Err(self.fail(1002, "websocket: client frame not masked"));
            }
            let is_control = op & 0x8 != 0;
            if !matches!(op, OP_CONT | OP_TEXT | OP_BIN | OP_CLOSE | OP_PING | OP_PONG) {
                return Err(self.fail(1002, "websocket: unknown opcode"));
            }
            if is_control && (!fin || len > 125) {
                return Err(self.fail(1002, "websocket: bad control frame"));
            }
            if len >= 1 << 63 {
                return Err(self.fail(1002, "websocket: bad length"));
            }
            if !is_control && (self.msg.len() as u64).saturating_add(len) > self.cfg.max_message as u64 {
                return Err(self.fail(1009, "websocket: message too large"));
            }
            let len = len as usize;
            if b.len() < hl + 4 + len {
                return Ok(None);
            }
            let mask = [b[hl], b[hl + 1], b[hl + 2], b[hl + 3]];
            let mut payload: Vec<u8> = b[hl + 4..hl + 4 + len].to_vec();
            for (i, x) in payload.iter_mut().enumerate() {
                *x ^= mask[i & 3];
            }
            self.rpos += hl + 4 + len;
            if self.rpos == self.rbuf.len() {
                self.rbuf.clear();
                self.rpos = 0;
            }
            match op {
                OP_PING => {
                    if !self.close_sent {
                        encode_frame(&mut self.out, true, OP_PONG, &payload);
                    }
                }
                OP_PONG => {}
                OP_CLOSE => return self.on_close(&payload).map(Some),
                _ => {
                    if op == OP_CONT {
                        if self.msg_op.is_none() {
                            return Err(self.fail(1002, "websocket: unexpected continuation"));
                        }
                    } else if self.msg_op.is_some() {
                        return Err(self.fail(1002, "websocket: new message inside fragmented message"));
                    } else {
                        self.msg_op = Some(op);
                    }
                    if self.msg.is_empty() {
                        self.msg = payload;
                    } else {
                        self.msg.append(&mut payload);
                    }
                    if fin {
                        let kind = self.msg_op.take();
                        let data = core::mem::take(&mut self.msg);
                        return if kind == Some(OP_TEXT) {
                            match String::from_utf8(data) {
                                Ok(s) => Ok(Some(Message::Text(s))),
                                Err(_) => Err(self.fail(1007, "websocket: invalid UTF-8 in text message")),
                            }
                        } else {
                            Ok(Some(Message::Binary(data)))
                        };
                    }
                }
            }
        }
    }

    fn on_close(&mut self, p: &[u8]) -> Result<Message> {
        let (code, reason) = match p.len() {
            0 => (None, String::new()),
            1 => return Err(self.fail(1002, "websocket: bad close payload")),
            _ => {
                let code = u16::from_be_bytes([p[0], p[1]]);
                if !valid_close_code(code) {
                    return Err(self.fail(1002, "websocket: bad close code"));
                }
                match core::str::from_utf8(&p[2..]) {
                    Ok(s) => (Some(code), s.to_string()),
                    Err(_) => return Err(self.fail(1007, "websocket: invalid UTF-8 in close reason")),
                }
            }
        };
        if !self.close_sent {
            self.close_sent = true;
            match code {
                Some(c) => encode_frame(&mut self.out, true, OP_CLOSE, &c.to_be_bytes()),
                None => encode_frame(&mut self.out, true, OP_CLOSE, &[]),
            }
        }
        self.done = true;
        Ok(Message::Close { code: code.unwrap_or(1005), reason })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    struct Null;
    impl Transport for Null {
        async fn read(&mut self, _: &mut [u8]) -> Result<usize> {
            Ok(0)
        }
        async fn write_all(&mut self, _: &[u8]) -> Result<()> {
            Ok(())
        }
    }

    fn hx(b: &[u8]) -> String {
        crate::sha256::hex(b)
    }

    #[test]
    fn sha1_vectors() {
        assert_eq!(hx(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hx(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(hx(&sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")), "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
        assert_eq!(hx(&sha1(&vec![b'a'; 1_000_000])), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    }

    #[test]
    fn rfc_accept_key() {
        assert_eq!(accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    fn req(headers: &[(&str, &str)]) -> Request {
        Request {
            method: "GET".into(),
            target: "/x".into(),
            headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            body: Vec::new(),
            peer: Default::default(),
        }
    }

    const GOOD: [(&str, &str); 4] =
        [("Upgrade", "WebSocket"), ("Connection", "keep-alive, Upgrade"), ("Sec-WebSocket-Version", "13"), ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")];

    #[test]
    fn handshake_checks() {
        let h = handshake(&req(&GOOD), &[]).ok().unwrap();
        assert_eq!(h.accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert_eq!(h.protocol, None);
        let mut bad = GOOD.to_vec();
        bad[2].1 = "8";
        assert_eq!(handshake(&req(&bad), &[]).unwrap_err().status, 426);
        let mut bad = GOOD.to_vec();
        bad[3].1 = "c2hvcnQ="; // not 16 bytes
        assert_eq!(handshake(&req(&bad), &[]).unwrap_err().status, 400);
        assert_eq!(handshake(&req(&GOOD[..3]), &[]).unwrap_err().status, 400);
        let mut bad = GOOD.to_vec();
        bad[1].1 = "close";
        assert_eq!(handshake(&req(&bad), &[]).unwrap_err().status, 400);
        let mut r = req(&GOOD);
        r.method = "POST".into();
        assert_eq!(handshake(&r, &[]).unwrap_err().status, 405);
    }

    #[test]
    fn subprotocol_prefers_server_order() {
        let mut h = GOOD.to_vec();
        h.push(("Sec-WebSocket-Protocol", "v4.channel.k8s.io, v3.channel.k8s.io"));
        h.push(("sec-websocket-protocol", "v5.channel.k8s.io"));
        let hs = handshake(&req(&h), &["v5.channel.k8s.io", "v4.channel.k8s.io"]).ok().unwrap();
        assert_eq!(hs.protocol.as_deref(), Some("v5.channel.k8s.io"));
        let hs = handshake(&req(&h), &["nope"]).ok().unwrap();
        assert_eq!((hs.protocol, hs.client_offered_protocols), (None, true));
    }

    fn masked(fin: bool, op: u8, payload: &[u8]) -> Vec<u8> {
        let mask = [0x37, 0xfa, 0x21, 0x3d];
        let mut v = vec![if fin { 0x80 } else { 0 } | op];
        if payload.len() < 126 {
            v.push(0x80 | payload.len() as u8);
        } else {
            v.push(0x80 | 126);
            v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        v.extend_from_slice(&mask);
        v.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i & 3]));
        v
    }

    fn ws(cfg: WsConfig) -> WebSocket<Null> {
        WebSocket::new(Null, cfg)
    }

    #[test]
    fn rfc_masked_hello() {
        // RFC 6455 section 5.7.
        let mut w = ws(WsConfig::default());
        w.rbuf.extend_from_slice(&[0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]);
        assert_eq!(w.parse_next().unwrap(), Some(Message::Text("Hello".into())));
    }

    #[test]
    fn fragments_ping_between_and_partial_input() {
        let mut w = ws(WsConfig::default());
        let mut all = masked(false, OP_TEXT, b"Hel");
        all.extend(masked(true, OP_PING, b"p"));
        all.extend(masked(true, OP_CONT, b"lo"));
        for (i, b) in all.iter().enumerate() {
            w.rbuf.push(*b);
            let r = w.parse_next().unwrap();
            if i + 1 < all.len() {
                assert_eq!(r, None);
            } else {
                assert_eq!(r, Some(Message::Text("Hello".into())));
            }
        }
        // pong "p" queued
        assert_eq!(w.out, [0x8A, 1, b'p']);
    }

    #[test]
    fn protocol_errors_queue_close_codes() {
        let code = |w: &WebSocket<Null>| u16::from_be_bytes([w.out[2], w.out[3]]);
        let mut w = ws(WsConfig::default());
        w.rbuf.extend_from_slice(&[0x81, 0x01, b'x']); // unmasked
        assert!(w.parse_next().is_err());
        assert_eq!(code(&w), 1002);
        let mut w = ws(WsConfig { max_message: 10 });
        w.rbuf.extend(masked(true, OP_BIN, &[0; 11]));
        assert!(matches!(w.parse_next(), Err(Error::TooLarge(_))));
        assert_eq!(code(&w), 1009);
        let mut w = ws(WsConfig { max_message: 10 });
        w.rbuf.extend(masked(false, OP_BIN, &[0; 6]));
        w.rbuf.extend(masked(true, OP_CONT, &[0; 6]));
        assert!(w.parse_next().is_err());
        assert_eq!(code(&w), 1009);
        let mut w = ws(WsConfig::default());
        w.rbuf.extend(masked(true, OP_TEXT, &[0xff, 0xfe]));
        assert!(w.parse_next().is_err());
        assert_eq!(code(&w), 1007);
        let mut w = ws(WsConfig::default());
        w.rbuf.extend(masked(true, OP_CONT, b"x"));
        assert!(w.parse_next().is_err());
        assert_eq!(code(&w), 1002);
        let mut w = ws(WsConfig::default());
        w.rbuf.extend(masked(false, OP_PING, b"x"));
        assert!(w.parse_next().is_err());
        assert_eq!(code(&w), 1002);
        // after failure every call errors
        assert!(w.parse_next().is_err());
    }

    #[test]
    fn close_echo() {
        let mut w = ws(WsConfig::default());
        let mut p = 1001u16.to_be_bytes().to_vec();
        p.extend_from_slice(b"bye");
        w.rbuf.extend(masked(true, OP_CLOSE, &p));
        assert_eq!(w.parse_next().unwrap(), Some(Message::Close { code: 1001, reason: "bye".into() }));
        assert_eq!(w.out, [0x88, 2, 0x03, 0xE9]);
        let mut w = ws(WsConfig::default());
        w.rbuf.extend(masked(true, OP_CLOSE, &1005u16.to_be_bytes()));
        assert!(w.parse_next().is_err()); // 1005 may not appear on the wire
    }

    #[test]
    fn encode_lengths() {
        let mut v = Vec::new();
        encode_frame(&mut v, true, OP_BIN, &[7; 300]);
        assert_eq!(&v[..4], &[0x82, 126, 1, 44]);
        let mut v = Vec::new();
        encode_frame(&mut v, true, OP_BIN, &vec![7; 70_000]);
        assert_eq!(&v[..10], &[0x82, 127, 0, 0, 0, 0, 0, 1, 0x11, 0x70]);
    }
}
