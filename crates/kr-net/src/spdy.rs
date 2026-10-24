//! SPDY/3.1, server side, sans-I/O (the framing `kubectl port-forward` speaks).
//!
//! # Layers
//!
//! * Codec: [`parse_frame`], [`write_data`], [`write_control`] and the zlib header-block
//!   coders [`HeaderEncoder`] / [`HeaderDecoder`]. Header blocks are zlib streams primed with the
//!   SPDY/3 preset dictionary; the compression context is per connection and per direction and
//!   continues across frames, so one coder lives as long as the connection.
//! * [`Session`]: the connection state machine. Feed it the peer's bytes with
//!   [`Session::feed`], drain [`Event`]s with [`Session::poll_event`], send with
//!   [`Session::reply`] / [`Session::data`] / [`Session::reset`], and write whatever
//!   [`Session::take_output`] returns to the peer. It never blocks and never touches a socket,
//!   so it works inside a single-threaded poll loop and over any byte stream (a raw upgraded
//!   TCP connection, or the payloads of binary WebSocket messages, KEP-4006).
//!
//! # Flow control
//!
//! Every stream starts with a 64 KiB window in each direction. Outgoing data queued with
//! [`Session::data`] is cut into frames no larger than the peer's current window and the rest
//! waits for `WINDOW_UPDATE` (or a larger `SETTINGS_INITIAL_WINDOW_SIZE`);
//! [`Session::pending`] reports the queued bytes so callers can stop reading their source.
//! Incoming windows are refilled by [`Session::consume`], which the application calls once it
//! has handled `n` received bytes (that is what makes the peer slow down when we are slow).
//! Some peers ignore windows altogether (moby/spdystream, hence kubectl and the Kubernetes
//! apiserver: they neither wait for our `WINDOW_UPDATE` nor stop at 64 KiB, and grant windows
//! that overflow 2^31-1); against those enforcing stalls or resets every transfer, so
//! [`Session::set_flow_control_enforced`] can turn enforcement off (the caller must then apply
//! its own backpressure, e.g. stop reading the transport while its queues are long).
//! The SPDY/3.1 session-level window (stream 0) is deliberately not enforced or sent: common
//! peers (moby/spdystream) do not implement it and it would only add a way to stall.
//!
//! Output compression uses stored deflate blocks (no actual compression), ended by a sync
//! flush marker, which is valid zlib and costs nothing to compute.

use crate::spdy_dict::DICT;
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;
use kr_archive::inflate::{Inflater, Status};

pub const VERSION: u16 = 3;

pub const FLAG_FIN: u8 = 0x01;
pub const FLAG_UNIDIRECTIONAL: u8 = 0x02;

pub const SYN_STREAM: u16 = 1;
pub const SYN_REPLY: u16 = 2;
pub const RST_STREAM: u16 = 3;
pub const SETTINGS: u16 = 4;
pub const PING: u16 = 6;
pub const GOAWAY: u16 = 7;
pub const HEADERS: u16 = 8;
pub const WINDOW_UPDATE: u16 = 9;

/// `RST_STREAM` / `GOAWAY` status codes.
pub mod status {
    pub const OK: u32 = 0;
    pub const PROTOCOL_ERROR: u32 = 1;
    pub const INVALID_STREAM: u32 = 2;
    pub const REFUSED_STREAM: u32 = 3;
    pub const UNSUPPORTED_VERSION: u32 = 4;
    pub const CANCEL: u32 = 5;
    pub const INTERNAL_ERROR: u32 = 6;
    pub const FLOW_CONTROL_ERROR: u32 = 7;
    pub const STREAM_IN_USE: u32 = 8;
    pub const STREAM_ALREADY_CLOSED: u32 = 9;
    pub const FRAME_TOO_LARGE: u32 = 11;
}

/// `SETTINGS` id of the per-stream initial window.
pub const SETTING_INITIAL_WINDOW_SIZE: u32 = 7;
pub const INITIAL_WINDOW: u32 = 65536;
/// Largest accepted frame payload.
pub const MAX_FRAME: usize = 1 << 20;
/// Largest data frame we send.
const SEND_CHUNK: usize = 16 * 1024;
/// Largest decompressed header block.
const MAX_HEADER_BYTES: usize = 256 * 1024;
const MAX_HEADERS: u32 = 1024;
const MAX_STREAMS: usize = 1024;
const MAX_WINDOW: i64 = 0x7fff_ffff;
const DICT_ID: u32 = 0xe3c6_a7c2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Not SPDY version 3.
    Version,
    /// A frame is larger than [`MAX_FRAME`].
    FrameTooLarge,
    /// Malformed frame or illegal sequence.
    Protocol(&'static str),
    /// A header block is not valid zlib / SPDY name-value data.
    Compression(&'static str),
    /// A window went out of range.
    FlowControl,
    /// The session already failed.
    Failed,
}

pub type Result<T> = core::result::Result<T, Error>;

// ---------- frame codec ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame<'a> {
    Data { stream: u32, flags: u8, data: &'a [u8] },
    Control { version: u16, ty: u16, flags: u8, payload: &'a [u8] },
}

/// Parses one frame from the front of `buf`. `Ok(None)` if more bytes are needed; otherwise the
/// frame and the number of bytes it occupied.
pub fn parse_frame(buf: &[u8]) -> Result<Option<(Frame<'_>, usize)>> {
    if buf.len() < 8 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([0, buf[5], buf[6], buf[7]]) as usize;
    if len > MAX_FRAME {
        return Err(Error::FrameTooLarge);
    }
    if buf.len() < 8 + len {
        return Ok(None);
    }
    let payload = &buf[8..8 + len];
    let flags = buf[4];
    let frame = if buf[0] & 0x80 != 0 {
        Frame::Control { version: u16::from_be_bytes([buf[0] & 0x7f, buf[1]]), ty: u16::from_be_bytes([buf[2], buf[3]]), flags, payload }
    } else {
        Frame::Data { stream: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]), flags, data: payload }
    };
    Ok(Some((frame, 8 + len)))
}

/// Appends a data frame (`data.len()` must fit in 24 bits).
pub fn write_data(out: &mut Vec<u8>, stream: u32, flags: u8, data: &[u8]) {
    out.extend_from_slice(&(stream & 0x7fff_ffff).to_be_bytes());
    out.push(flags);
    out.extend_from_slice(&(data.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(data);
}

/// Appends a control frame of SPDY version 3.
pub fn write_control(out: &mut Vec<u8>, ty: u16, flags: u8, payload: &[u8]) {
    out.extend_from_slice(&(0x8000 | VERSION).to_be_bytes());
    out.extend_from_slice(&ty.to_be_bytes());
    out.push(flags);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(payload);
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

// ---------- header blocks ----------

pub type Headers = Vec<(String, String)>;

/// Compresses header blocks for one connection direction: a single zlib stream (preset
/// dictionary id in the first header) of stored blocks, each block ended by a sync flush.
#[derive(Default)]
pub struct HeaderEncoder {
    started: bool,
}

impl HeaderEncoder {
    pub fn new() -> Self {
        HeaderEncoder { started: false }
    }

    /// The compressed name/value block for `headers`. Blocks must be sent in the order they
    /// were produced.
    pub fn encode(&mut self, headers: &[(&str, &str)]) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend_from_slice(&(headers.len() as u32).to_be_bytes());
        for (k, v) in headers {
            raw.extend_from_slice(&(k.len() as u32).to_be_bytes());
            raw.extend_from_slice(k.as_bytes());
            raw.extend_from_slice(&(v.len() as u32).to_be_bytes());
            raw.extend_from_slice(v.as_bytes());
        }
        let mut out = Vec::with_capacity(raw.len() + 16);
        if !self.started {
            self.started = true;
            out.extend_from_slice(&[0x78, 0xbb]); // deflate, 32K window, FDICT, check bits
            out.extend_from_slice(&DICT_ID.to_be_bytes());
        }
        for chunk in raw.chunks(0xffff) {
            let n = chunk.len() as u16;
            out.push(0); // BFINAL=0, BTYPE=stored
            out.extend_from_slice(&n.to_le_bytes());
            out.extend_from_slice(&(!n).to_le_bytes());
            out.extend_from_slice(chunk);
        }
        out.extend_from_slice(&[0, 0, 0, 0xff, 0xff]); // empty stored block: Z_SYNC_FLUSH
        out
    }
}

/// Decompresses the peer's header blocks: one inflate stream for the whole connection.
pub struct HeaderDecoder {
    inf: Box<Inflater>,
    started: bool,
}

impl Default for HeaderDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl HeaderDecoder {
    pub fn new() -> Self {
        HeaderDecoder { inf: Box::new(Inflater::new()), started: false }
    }

    /// Decompresses and parses one block. Every block of the connection must pass through here
    /// in order, even those whose frames are otherwise ignored; after an error the decoder is
    /// unusable.
    pub fn decode(&mut self, block: &[u8]) -> Result<Headers> {
        let mut body = block;
        if !self.started {
            if body.len() < 2 {
                return Err(Error::Compression("short zlib header"));
            }
            let (cmf, flg) = (body[0], body[1]);
            if cmf & 0x0f != 8 || cmf >> 4 > 7 || (u16::from(cmf) << 8 | u16::from(flg)) % 31 != 0 {
                return Err(Error::Compression("bad zlib header"));
            }
            body = &body[2..];
            if flg & 0x20 != 0 {
                if body.len() < 4 || be32(body) != DICT_ID {
                    return Err(Error::Compression("unknown preset dictionary"));
                }
                body = &body[4..];
                self.inf.set_dictionary(&DICT);
            }
            self.started = true;
        }
        let mut raw: Vec<u8> = Vec::new();
        let r = self.inf.feed::<()>(body, &mut |b| {
            if raw.len() + b.len() > MAX_HEADER_BYTES {
                return Err(());
            }
            raw.extend_from_slice(b);
            Ok(())
        });
        match r {
            Ok(Status::NeedInput) => {}
            Ok(Status::Done { .. }) => return Err(Error::Compression("header stream ended")),
            Err(_) => return Err(Error::Compression("inflate failed")),
        }
        parse_pairs(&raw)
    }
}

fn parse_pairs(raw: &[u8]) -> Result<Headers> {
    const BAD: Error = Error::Compression("malformed name/value block");
    fn take<'a>(raw: &'a [u8], pos: &mut usize) -> Result<&'a [u8]> {
        if raw.len() < *pos + 4 {
            return Err(BAD);
        }
        let n = be32(&raw[*pos..]) as usize;
        *pos += 4;
        if raw.len() - *pos < n {
            return Err(BAD);
        }
        let s = &raw[*pos..*pos + n];
        *pos += n;
        Ok(s)
    }
    if raw.len() < 4 {
        return Err(BAD);
    }
    let count = be32(raw);
    if count > MAX_HEADERS {
        return Err(BAD);
    }
    let mut pos = 4;
    let mut out = Vec::new();
    for _ in 0..count {
        let name = take(raw, &mut pos)?;
        let value = take(raw, &mut pos)?;
        if name.is_empty() {
            return Err(BAD);
        }
        out.push((String::from_utf8_lossy(name).into_owned(), String::from_utf8_lossy(value).into_owned()));
    }
    if pos != raw.len() {
        return Err(BAD);
    }
    Ok(out)
}

// ---------- session ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The peer opened a stream (`SYN_STREAM`). `fin` if it will send no data.
    StreamOpened { id: u32, headers: Headers, fin: bool },
    /// Payload for a stream; `fin` marks the peer's last data (the chunk may be empty).
    Data { id: u32, bytes: Vec<u8>, fin: bool },
    /// The stream was reset by the peer (or by us on a flow-control violation). It is gone.
    Reset { id: u32, status: u32 },
    /// The peer is going away.
    GoAway { last_stream: u32, status: u32 },
}

struct Stream {
    send_win: i64,
    recv_win: i64,
    /// Bytes consumed by the application but not yet announced to the peer.
    unacked: u32,
    out: Vec<u8>,
    out_pos: usize,
    fin_queued: bool,
    fin_sent: bool,
    remote_fin: bool,
}

pub struct Session {
    rbuf: Vec<u8>,
    out: Vec<u8>,
    events: VecDeque<Event>,
    streams: BTreeMap<u32, Stream>,
    dec: HeaderDecoder,
    enc: HeaderEncoder,
    init_send_win: i64,
    enforce_fc: bool,
    last_stream: u32,
    failed: bool,
    peer_goaway: bool,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub fn new() -> Session {
        Session {
            rbuf: Vec::new(),
            out: Vec::new(),
            events: VecDeque::new(),
            streams: BTreeMap::new(),
            dec: HeaderDecoder::new(),
            enc: HeaderEncoder::new(),
            init_send_win: i64::from(INITIAL_WINDOW),
            enforce_fc: true,
            last_stream: 0,
            failed: false,
            peer_goaway: false,
        }
    }

    /// Whether stream windows are enforced in both directions (default: yes): queued data
    /// waits for the peer's window and a peer overrunning ours is reset. Turn off for peers that
    /// ignore windows altogether (moby/spdystream); see the module docs.
    pub fn set_flow_control_enforced(&mut self, on: bool) {
        self.enforce_fc = on;
    }

    /// True after a connection-level error (a GOAWAY was queued) or once the peer said GOAWAY.
    pub fn is_closed(&self) -> bool {
        self.failed || self.peer_goaway
    }

    /// Number of live streams.
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    pub fn has_stream(&self, id: u32) -> bool {
        self.streams.contains_key(&id)
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    pub fn has_output(&self) -> bool {
        !self.out.is_empty()
    }

    /// Everything to send to the peer since the last call.
    pub fn take_output(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.out)
    }

    /// Bytes queued on `id` that flow control has not let out yet.
    pub fn pending(&self, id: u32) -> usize {
        self.streams.get(&id).map_or(0, |s| s.out.len() - s.out_pos)
    }

    /// Feeds bytes received from the peer. Events become available through
    /// [`Session::poll_event`]. An `Err` is fatal: a GOAWAY was queued, nothing more is accepted.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<()> {
        if self.failed {
            return Err(Error::Failed);
        }
        self.rbuf.extend_from_slice(bytes);
        let buf = core::mem::take(&mut self.rbuf);
        let mut pos = 0;
        let r = loop {
            match parse_frame(&buf[pos..]) {
                Ok(Some((f, n))) => {
                    if let Err(e) = self.handle(f) {
                        break Err(e);
                    }
                    pos += n;
                }
                Ok(None) => break Ok(()),
                Err(e) => break Err(e),
            }
        };
        match r {
            Ok(()) => {
                self.rbuf = buf[pos..].to_vec();
                Ok(())
            }
            Err(e) => {
                self.fail(if e == Error::Version { status::UNSUPPORTED_VERSION } else { status::PROTOCOL_ERROR });
                Err(e)
            }
        }
    }

    fn fail(&mut self, st: u32) {
        if !self.failed {
            self.failed = true;
            self.write_goaway(st);
        }
    }

    fn write_goaway(&mut self, st: u32) {
        let mut p = [0u8; 8];
        p[..4].copy_from_slice(&self.last_stream.to_be_bytes());
        p[4..].copy_from_slice(&st.to_be_bytes());
        write_control(&mut self.out, GOAWAY, 0, &p);
    }

    /// Announces that we will accept no new streams.
    pub fn goaway(&mut self, st: u32) {
        self.write_goaway(st);
    }

    fn write_rst(&mut self, id: u32, st: u32) {
        let mut p = [0u8; 8];
        p[..4].copy_from_slice(&id.to_be_bytes());
        p[4..].copy_from_slice(&st.to_be_bytes());
        write_control(&mut self.out, RST_STREAM, 0, &p);
    }

    fn handle(&mut self, f: Frame<'_>) -> Result<()> {
        match f {
            Frame::Data { stream, flags, data } => self.on_data(stream, flags, data),
            Frame::Control { version, ty, flags, payload } => {
                if version != VERSION {
                    return Err(Error::Version);
                }
                self.on_control(ty, flags, payload)
            }
        }
    }

    fn on_data(&mut self, id: u32, flags: u8, data: &[u8]) -> Result<()> {
        let fin = flags & FLAG_FIN != 0;
        let Some(s) = self.streams.get_mut(&id) else {
            self.write_rst(id, status::INVALID_STREAM);
            return Ok(());
        };
        if s.remote_fin {
            self.write_rst(id, status::STREAM_ALREADY_CLOSED);
            self.streams.remove(&id);
            self.events.push_back(Event::Reset { id, status: status::STREAM_ALREADY_CLOSED });
            return Ok(());
        }
        if self.enforce_fc && data.len() as i64 > s.recv_win {
            self.write_rst(id, status::FLOW_CONTROL_ERROR);
            self.streams.remove(&id);
            self.events.push_back(Event::Reset { id, status: status::FLOW_CONTROL_ERROR });
            return Ok(());
        }
        s.recv_win -= data.len() as i64;
        s.remote_fin |= fin;
        if !data.is_empty() || fin {
            self.events.push_back(Event::Data { id, bytes: data.to_vec(), fin });
        }
        self.gc(id);
        Ok(())
    }

    fn on_control(&mut self, ty: u16, flags: u8, p: &[u8]) -> Result<()> {
        match ty {
            SYN_STREAM => {
                if p.len() < 10 {
                    return Err(Error::Protocol("short SYN_STREAM"));
                }
                // Decompress first: the context must advance even if the stream is refused.
                let headers = self.dec.decode(&p[10..])?;
                let id = be32(p) & 0x7fff_ffff;
                if id == 0 || id % 2 == 0 {
                    return Err(Error::Protocol("bad client stream id"));
                }
                if self.streams.contains_key(&id) {
                    self.write_rst(id, status::STREAM_IN_USE);
                    return Ok(());
                }
                if id <= self.last_stream {
                    self.write_rst(id, status::PROTOCOL_ERROR);
                    return Ok(());
                }
                self.last_stream = id;
                if self.streams.len() >= MAX_STREAMS || self.peer_goaway {
                    self.write_rst(id, status::REFUSED_STREAM);
                    return Ok(());
                }
                let fin = flags & FLAG_FIN != 0;
                self.streams.insert(
                    id,
                    Stream {
                        send_win: self.init_send_win,
                        recv_win: i64::from(INITIAL_WINDOW),
                        unacked: 0,
                        out: Vec::new(),
                        out_pos: 0,
                        fin_queued: false,
                        fin_sent: false,
                        remote_fin: fin,
                    },
                );
                self.events.push_back(Event::StreamOpened { id, headers, fin });
            }
            SYN_REPLY | HEADERS => {
                if p.len() < 4 {
                    return Err(Error::Protocol("short header frame"));
                }
                self.dec.decode(&p[4..])?;
            }
            RST_STREAM => {
                if p.len() != 8 {
                    return Err(Error::Protocol("bad RST_STREAM"));
                }
                let id = be32(p) & 0x7fff_ffff;
                if self.streams.remove(&id).is_some() {
                    self.events.push_back(Event::Reset { id, status: be32(&p[4..]) });
                }
            }
            SETTINGS => {
                if p.len() < 4 {
                    return Err(Error::Protocol("short SETTINGS"));
                }
                let n = be32(p) as usize;
                if n > MAX_FRAME / 8 || p.len() != 4 + 8 * n {
                    return Err(Error::Protocol("bad SETTINGS"));
                }
                for e in p[4..].chunks_exact(8) {
                    let (sid, val) = (u32::from_be_bytes([0, e[1], e[2], e[3]]), be32(&e[4..]));
                    if sid == SETTING_INITIAL_WINDOW_SIZE {
                        if i64::from(val) > MAX_WINDOW {
                            return Err(Error::FlowControl);
                        }
                        let delta = i64::from(val) - self.init_send_win;
                        self.init_send_win = i64::from(val);
                        for s in self.streams.values_mut() {
                            s.send_win += delta;
                            if s.send_win > MAX_WINDOW {
                                return Err(Error::FlowControl);
                            }
                        }
                        let ids: Vec<u32> = self.streams.keys().copied().collect();
                        for id in ids {
                            self.flush(id);
                        }
                    }
                }
            }
            PING => {
                if p.len() != 4 {
                    return Err(Error::Protocol("bad PING"));
                }
                // Client pings have odd ids and are echoed; even ids would be answers to ours.
                if be32(p) % 2 == 1 {
                    write_control(&mut self.out, PING, 0, p);
                }
            }
            GOAWAY => {
                if p.len() != 8 {
                    return Err(Error::Protocol("bad GOAWAY"));
                }
                self.peer_goaway = true;
                self.events.push_back(Event::GoAway { last_stream: be32(p) & 0x7fff_ffff, status: be32(&p[4..]) });
            }
            WINDOW_UPDATE => {
                if p.len() != 8 {
                    return Err(Error::Protocol("bad WINDOW_UPDATE"));
                }
                let id = be32(p) & 0x7fff_ffff;
                let delta = i64::from(be32(&p[4..]) & 0x7fff_ffff);
                if id == 0 {
                    return Ok(());
                }
                let Some(s) = self.streams.get_mut(&id) else { return Ok(()) };
                // Without enforcement the window is advisory: peers that grant more than 2^31-1
                // in total (moby/spdystream does) are clamped instead of reset.
                if !self.enforce_fc {
                    s.send_win = (s.send_win + delta).min(MAX_WINDOW);
                    return Ok(());
                }
                if delta == 0 || s.send_win + delta > MAX_WINDOW {
                    let st = if delta == 0 { status::PROTOCOL_ERROR } else { status::FLOW_CONTROL_ERROR };
                    self.write_rst(id, st);
                    self.streams.remove(&id);
                    self.events.push_back(Event::Reset { id, status: st });
                    return Ok(());
                }
                s.send_win += delta;
                self.flush(id);
            }
            _ => {} // CREDENTIAL, NOOP and unknown types are ignored
        }
        Ok(())
    }

    /// Both directions finished: forget the stream.
    fn gc(&mut self, id: u32) {
        if self.streams.get(&id).is_some_and(|s| s.remote_fin && s.fin_sent) {
            self.streams.remove(&id);
        }
    }

    /// Sends as much queued data as the peer's window allows.
    fn flush(&mut self, id: u32) {
        let Some(s) = self.streams.get_mut(&id) else { return };
        loop {
            let queued = s.out.len() - s.out_pos;
            let avail = if self.enforce_fc { s.send_win.max(0) as usize } else { usize::MAX };
            let n = queued.min(avail).min(SEND_CHUNK);
            let fin = s.fin_queued && !s.fin_sent && n == queued;
            if n == 0 && !fin {
                break;
            }
            write_data(&mut self.out, id, if fin { FLAG_FIN } else { 0 }, &s.out[s.out_pos..s.out_pos + n]);
            s.out_pos += n;
            s.send_win -= n as i64;
            s.fin_sent |= fin;
            if fin {
                break;
            }
        }
        if s.out_pos == s.out.len() {
            s.out.clear();
            s.out_pos = 0;
        } else if s.out_pos > 64 * 1024 {
            s.out.drain(..s.out_pos);
            s.out_pos = 0;
        }
        self.gc(id);
    }

    /// Answers a `SYN_STREAM` (`SYN_REPLY`). Ignored if the stream is gone.
    pub fn reply(&mut self, id: u32, headers: &[(&str, &str)]) {
        if !self.streams.contains_key(&id) {
            return;
        }
        let block = self.enc.encode(headers);
        let mut p = Vec::with_capacity(4 + block.len());
        p.extend_from_slice(&id.to_be_bytes());
        p.extend_from_slice(&block);
        write_control(&mut self.out, SYN_REPLY, 0, &p);
    }

    /// Queues `bytes` on a stream (`fin` closes our side after them). Sent as fast as the
    /// peer's window allows. Ignored if the stream is gone or we already sent FIN.
    pub fn data(&mut self, id: u32, bytes: &[u8], fin: bool) {
        let Some(s) = self.streams.get_mut(&id) else { return };
        if s.fin_queued {
            return;
        }
        s.out.extend_from_slice(bytes);
        s.fin_queued = fin;
        self.flush(id);
    }

    /// Aborts a stream with `CANCEL`.
    pub fn reset(&mut self, id: u32) {
        self.reset_with(id, status::CANCEL);
    }

    /// Aborts a stream (sent even if it is unknown, e.g. to refuse one).
    pub fn reset_with(&mut self, id: u32, st: u32) {
        self.streams.remove(&id);
        self.write_rst(id, st);
    }

    /// Tells the session the application has dealt with `n` received bytes of `id`, so the
    /// peer may send that many more. Queues a `WINDOW_UPDATE` once enough accumulated.
    pub fn consume(&mut self, id: u32, n: usize) {
        let Some(s) = self.streams.get_mut(&id) else { return };
        s.unacked = s.unacked.saturating_add(n as u32);
        if s.remote_fin || s.unacked < INITIAL_WINDOW / 2 {
            return;
        }
        let d = core::mem::take(&mut s.unacked);
        s.recv_win += i64::from(d);
        let mut p = [0u8; 8];
        p[..4].copy_from_slice(&id.to_be_bytes());
        p[4..].copy_from_slice(&d.to_be_bytes());
        write_control(&mut self.out, WINDOW_UPDATE, 0, &p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adler32(d: &[u8]) -> u32 {
        let (mut a, mut b) = (1u32, 0u32);
        for x in d {
            a = (a + u32::from(*x)) % 65521;
            b = (b + a) % 65521;
        }
        b << 16 | a
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    // zlib (python `compressobj(9, DEFLATED, 15, 9, 0, zdict)`, Z_SYNC_FLUSH after each block)
    // of the name/value blocks for the error and data streams of one port-forward connection.
    const Z1: &str = "78f9e3c6a7c202253a703a2b294a4dcc851625aca9a0808614cb45e01c6061606100a4398b20d198094ade8c0600000000ffff";
    const Z2: &str = "c2aa19540e2512d60b000000ffff";

    fn syn_stream(id: u32, flags: u8, block: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&id.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 0]); // associated stream
        p.extend_from_slice(&[0, 0]); // priority, slot
        p.extend_from_slice(block);
        let mut out = Vec::new();
        write_control(&mut out, SYN_STREAM, flags, &p);
        out
    }

    fn hdrs(h: &[(&str, &str)]) -> Headers {
        h.iter().map(|(k, v)| ((*k).into(), (*v).into())).collect()
    }

    fn frames(mut b: &[u8]) -> Vec<(u16, u8, Vec<u8>)> {
        // (type or 0xffff+stream for data is awkward: data frames use ty = 0 and payload = id|data)
        let mut v = Vec::new();
        while let Some((f, n)) = parse_frame(b).unwrap() {
            match f {
                Frame::Control { ty, flags, payload, .. } => v.push((ty, flags, payload.to_vec())),
                Frame::Data { stream, flags, data } => {
                    let mut p = stream.to_be_bytes().to_vec();
                    p.extend_from_slice(data);
                    v.push((0, flags, p));
                }
            }
            b = &b[n..];
        }
        assert!(b.is_empty());
        v
    }

    #[test]
    fn dictionary_is_the_spdy3_one() {
        assert_eq!(DICT.len(), 1423);
        assert_eq!(adler32(&DICT), DICT_ID);
    }

    #[test]
    fn frame_codec_round_trip() {
        let mut b = Vec::new();
        write_data(&mut b, 5, FLAG_FIN, b"abc");
        write_control(&mut b, PING, 0, &[0, 0, 0, 1]);
        assert_eq!(&b[..11], &[0, 0, 0, 5, 1, 0, 0, 3, b'a', b'b', b'c']);
        assert_eq!(&b[11..19], &[0x80, 3, 0, 6, 0, 0, 0, 4]);
        let (f, n) = parse_frame(&b).unwrap().unwrap();
        assert_eq!(f, Frame::Data { stream: 5, flags: 1, data: b"abc" });
        let (f, m) = parse_frame(&b[n..]).unwrap().unwrap();
        assert_eq!(f, Frame::Control { version: 3, ty: PING, flags: 0, payload: &[0, 0, 0, 1] });
        assert_eq!(n + m, b.len());
        assert_eq!(parse_frame(&b[..10]).unwrap(), None);
        assert_eq!(parse_frame(&[0, 0, 0, 1, 0, 0x7f, 0xff, 0xff]), Err(Error::FrameTooLarge));
    }

    #[test]
    fn decodes_real_zlib_blocks() {
        let mut d = HeaderDecoder::new();
        let h1 = d.decode(&unhex(Z1)).unwrap();
        assert_eq!(h1, hdrs(&[("streamtype", "error"), ("port", "8080"), ("requestid", "0")]));
        let h2 = d.decode(&unhex(Z2)).unwrap();
        assert_eq!(h2, hdrs(&[("streamtype", "data"), ("port", "8080"), ("requestid", "0")]));
        // Block 2 only makes sense after block 1 (shared context).
        let mut d = HeaderDecoder::new();
        assert!(d.decode(&unhex(Z2)).is_err());
    }

    #[test]
    fn encoder_decoder_round_trip_across_blocks() {
        let mut e = HeaderEncoder::new();
        let mut d = HeaderDecoder::new();
        for i in 0..3 {
            let v = alloc::format!("value-{i}");
            let b = e.encode(&[(":status", "200"), ("x-n", &v)]);
            assert_eq!(d.decode(&b).unwrap(), hdrs(&[(":status", "200"), ("x-n", &v)]));
        }
        // Larger than one stored block.
        let big = "x".repeat(70_000);
        let b = e.encode(&[("big", &big)]);
        assert_eq!(d.decode(&b).unwrap()[0].1.len(), 70_000);
    }

    #[test]
    fn encoder_output_is_valid_zlib() {
        // Verified against python: zlib.decompressobj(zdict=SPDY_DICT).decompress(bytes) ==
        // the raw name/value block, for this and the following block.
        let mut e = HeaderEncoder::new();
        let b = e.encode(&[("a", "b")]);
        assert_eq!(
            b,
            unhex("78bbe3c6a7c2000e00f1ff0000000100000001610000000162000000ffff")
        );
        let b2 = e.encode(&[("a", "b")]);
        assert_eq!(b2, unhex("000e00f1ff0000000100000001610000000162000000ffff"));
    }

    #[test]
    fn session_exchange() {
        let mut s = Session::new();
        let mut wire = syn_stream(1, 0, &unhex(Z1));
        wire.extend(syn_stream(3, 0, &unhex(Z2)));
        // Feed one byte at a time.
        for b in &wire {
            s.feed(&[*b]).unwrap();
        }
        assert_eq!(s.poll_event(), Some(Event::StreamOpened { id: 1, headers: hdrs(&[("streamtype", "error"), ("port", "8080"), ("requestid", "0")]), fin: false }));
        assert_eq!(s.poll_event(), Some(Event::StreamOpened { id: 3, headers: hdrs(&[("streamtype", "data"), ("port", "8080"), ("requestid", "0")]), fin: false }));
        s.reply(1, &[]);
        s.reply(3, &[]);
        let out = s.take_output();
        let fr = frames(&out);
        assert_eq!(fr.len(), 2);
        assert_eq!(fr[0].0, SYN_REPLY);
        assert_eq!(&fr[0].2[..4], &[0, 0, 0, 1]);
        // The client decodes the replies with one decoder.
        let mut cd = HeaderDecoder::new();
        assert!(cd.decode(&fr[0].2[4..]).unwrap().is_empty());
        assert!(cd.decode(&fr[1].2[4..]).unwrap().is_empty());

        // Incoming data and window refills.
        let mut d = Vec::new();
        write_data(&mut d, 3, 0, &[7u8; 40000]);
        s.feed(&d).unwrap();
        assert_eq!(s.poll_event(), Some(Event::Data { id: 3, bytes: alloc::vec![7u8; 40000], fin: false }));
        assert!(!s.has_output());
        s.consume(3, 40000);
        let fr = frames(&s.take_output());
        assert_eq!(fr, [(WINDOW_UPDATE, 0, [&3u32.to_be_bytes()[..], &40000u32.to_be_bytes()[..]].concat())]);
        // A peer that overruns its window is reset.
        let mut d = Vec::new();
        write_data(&mut d, 3, 0, &[1u8; 30000]);
        write_data(&mut d, 3, 0, &[1u8; 30000]);
        s.feed(&d).unwrap();
        assert!(matches!(s.poll_event(), Some(Event::Data { .. })));
        assert!(matches!(s.poll_event(), Some(Event::Data { .. })));
        let mut d = Vec::new();
        write_data(&mut d, 3, 0, &[1u8; 30000]);
        s.feed(&d).unwrap();
        assert_eq!(s.poll_event(), Some(Event::Reset { id: 3, status: status::FLOW_CONTROL_ERROR }));
        assert_eq!(frames(&s.take_output())[0].0, RST_STREAM);

        // Data on an unknown stream.
        let mut d = Vec::new();
        write_data(&mut d, 9, 0, b"x");
        s.feed(&d).unwrap();
        let fr = frames(&s.take_output());
        assert_eq!(fr[0].0, RST_STREAM);
        assert_eq!(&fr[0].2[4..], &status::INVALID_STREAM.to_be_bytes());
    }

    #[test]
    fn send_respects_windows() {
        let mut s = Session::new();
        let mut e = HeaderEncoder::new();
        s.feed(&syn_stream(1, 0, &e.encode(&[("k", "v")]))).unwrap();
        s.poll_event();
        s.data(1, &alloc::vec![9u8; 100_000], true);
        assert_eq!(s.pending(1), 100_000 - 65536);
        let sent: usize = frames(&s.take_output()).iter().map(|f| f.2.len() - 4).sum();
        assert_eq!(sent, 65536);
        // WINDOW_UPDATE releases more.
        let mut w = Vec::new();
        write_control(&mut w, WINDOW_UPDATE, 0, &[&1u32.to_be_bytes()[..], &20000u32.to_be_bytes()[..]].concat());
        s.feed(&w).unwrap();
        let fr = frames(&s.take_output());
        assert_eq!(fr.iter().map(|f| f.2.len() - 4).sum::<usize>(), 20000);
        assert_eq!(s.pending(1), 100_000 - 65536 - 20000);
        // SETTINGS raising the initial window by 100000 releases the rest and the FIN.
        let mut st = Vec::new();
        let mut p = 1u32.to_be_bytes().to_vec();
        p.extend_from_slice(&[0, 0, 0, 7]);
        p.extend_from_slice(&(65536u32 + 100_000).to_be_bytes());
        write_control(&mut st, SETTINGS, 0, &p);
        s.feed(&st).unwrap();
        let fr = frames(&s.take_output());
        assert_eq!(fr.last().unwrap().1, FLAG_FIN);
        assert_eq!(fr.iter().map(|f| f.2.len() - 4).sum::<usize>(), 100_000 - 65536 - 20000);
        assert_eq!(s.pending(1), 0);
        // Our FIN is out; the peer FIN removes the stream.
        assert!(s.has_stream(1));
        let mut d = Vec::new();
        write_data(&mut d, 1, FLAG_FIN, b"");
        s.feed(&d).unwrap();
        assert_eq!(s.poll_event(), Some(Event::Data { id: 1, bytes: Vec::new(), fin: true }));
        assert!(!s.has_stream(1));
    }

    #[test]
    fn ping_goaway_rst_and_errors() {
        let mut s = Session::new();
        let mut e = HeaderEncoder::new();
        s.feed(&syn_stream(1, FLAG_FIN, &e.encode(&[("k", "v")]))).unwrap();
        assert!(matches!(s.poll_event(), Some(Event::StreamOpened { id: 1, fin: true, .. })));
        let mut b = Vec::new();
        write_control(&mut b, PING, 0, &[0, 0, 0, 1]);
        write_control(&mut b, PING, 0, &[0, 0, 0, 2]); // answer to a ping of ours: ignored
        s.feed(&b).unwrap();
        let fr = frames(&s.take_output());
        assert_eq!(fr, [(PING, 0, alloc::vec![0, 0, 0, 1])]);
        // Reusing / going back in stream ids is refused without killing the connection.
        s.feed(&syn_stream(1, 0, &e.encode(&[("k", "v")]))).unwrap();
        assert_eq!(&frames(&s.take_output())[0].2[4..], &status::STREAM_IN_USE.to_be_bytes());
        // Peer reset.
        let mut b = Vec::new();
        write_control(&mut b, RST_STREAM, 0, &[&1u32.to_be_bytes()[..], &5u32.to_be_bytes()[..]].concat());
        write_control(&mut b, GOAWAY, 0, &[0u8; 8]);
        s.feed(&b).unwrap();
        assert_eq!(s.poll_event(), Some(Event::Reset { id: 1, status: 5 }));
        assert_eq!(s.poll_event(), Some(Event::GoAway { last_stream: 0, status: 0 }));
        assert!(s.is_closed());
        // Wrong version, garbage header block: fatal, GOAWAY queued.
        let mut s = Session::new();
        assert_eq!(s.feed(&[0x80, 2, 0, 6, 0, 0, 0, 4, 0, 0, 0, 1]), Err(Error::Version));
        assert_eq!(frames(&s.take_output())[0].0, GOAWAY);
        assert_eq!(s.feed(b"x"), Err(Error::Failed));
        let mut s = Session::new();
        assert!(s.feed(&syn_stream(1, 0, b"not zlib at all")).is_err());
    }

    #[test]
    fn unenforced_flow_control_ignores_windows() {
        let mut s = Session::new();
        s.set_flow_control_enforced(false);
        let mut e = HeaderEncoder::new();
        s.feed(&syn_stream(1, 0, &e.encode(&[("k", "v")]))).unwrap();
        s.poll_event();
        let mut w = Vec::new();
        write_control(&mut w, WINDOW_UPDATE, 0, &[&1u32.to_be_bytes()[..], &0x7fff_ff00u32.to_be_bytes()[..]].concat());
        s.feed(&w).unwrap();
        assert!(s.poll_event().is_none());
        s.data(1, &alloc::vec![1u8; 200_000], false);
        assert_eq!(s.pending(1), 0);
        assert_eq!(frames(&s.take_output()).iter().map(|f| f.2.len() - 4).sum::<usize>(), 200_000);
        // Overrunning our receive window is tolerated too.
        let mut d = Vec::new();
        for _ in 0..4 {
            write_data(&mut d, 1, 0, &[1u8; 30000]);
        }
        s.feed(&d).unwrap();
        for _ in 0..4 {
            assert!(matches!(s.poll_event(), Some(Event::Data { .. })));
        }
    }
}
