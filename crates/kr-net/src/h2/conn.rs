//! One HTTP/2 connection (cleartext, prior knowledge) multiplexing streams over an
//! `Async<Fd>`.
//!
//! A reader task parses frames into shared state; a writer task drains an output buffer that
//! every producer appends whole frames to synchronously, so frames never interleave and HPACK
//! encoding order equals wire order. All state is in one `RefCell` that is never held across an
//! `.await`; waiters re-check their condition whenever any state changes ([`Inner::wait`]).

use super::frame::*;
use super::hpack::{Decoder, Encoder};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::rc::Rc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::future::poll_fn;
use core::task::{Poll, Waker};
use kr_rt::exec::{spawn, Async, JoinHandle};
use kr_sys::Fd;

pub type Hdrs = Vec<(Vec<u8>, Vec<u8>)>;

const INIT_WIN: i64 = 1 << 20;
const MAX_STREAMS: usize = 100;
const MAX_HDR_BLOCK: usize = 64 * 1024;
const MAX_WIN: i64 = 0x7fff_ffff;
const OUT_HIGH: usize = 256 * 1024;
const OUT_MAX: usize = 16 << 20;
const MAX_INBOX: usize = 4096;
const CREDIT_STEP: i64 = 32 * 1024;

enum Item {
    Headers(Hdrs),
    Data(Vec<u8>),
}

struct S {
    send_win: i64,
    recv_win: i64,
    unacked: i64,
    inbox: VecDeque<Item>,
    remote_end: bool,
    local_end: bool,
    reset: Option<u32>,
}

impl S {
    fn new(send_win: i64) -> S {
        S { send_win, recv_win: INIT_WIN, unacked: 0, inbox: VecDeque::new(), remote_end: false, local_end: false, reset: None }
    }
    fn closed(&self) -> bool {
        self.reset.is_some() || (self.remote_end && self.local_end)
    }
    fn queued_data(&self) -> usize {
        self.inbox.iter().map(|i| if let Item::Data(d) = i { d.len() } else { 0 }).sum()
    }
}

struct Cont {
    sid: u32,
    end_stream: bool,
    buf: Vec<u8>,
}

struct St {
    client: bool,
    closed: bool,
    dying: bool,
    out: Vec<u8>,
    wakers: Vec<Waker>,
    streams: BTreeMap<u32, S>,
    next_id: u32,
    last_peer_id: u32,
    incoming: VecDeque<u32>,
    send_win: i64,
    recv_win: i64,
    conn_unacked: i64,
    peer_init_win: i64,
    peer_max_frame: usize,
    peer_max_streams: usize,
    peer_goaway: bool,
    got_settings: bool,
    enc: Encoder,
    dec: Decoder,
    cont: Option<Cont>,
}

type R = Result<(), u32>;

impl St {
    fn dead(&self) -> bool {
        self.closed || self.dying
    }

    fn put(&mut self, ty: u8, flags: u8, sid: u32, payload: &[u8]) {
        if self.closed {
            return;
        }
        put(&mut self.out, ty, flags, sid, payload);
        if self.out.len() > OUT_MAX {
            self.hard_close();
        }
    }

    fn hard_close(&mut self) {
        self.closed = true;
        self.out.clear();
    }

    fn conn_error(&mut self, code: u32) {
        if self.dead() {
            return;
        }
        let mut p = [0u8; 8];
        p[..4].copy_from_slice(&self.last_peer_id.to_be_bytes());
        p[4..].copy_from_slice(&code.to_be_bytes());
        self.put(GOAWAY, 0, 0, &p);
        self.dying = true;
    }

    fn rst(&mut self, sid: u32, code: u32) {
        self.put(RST_STREAM, 0, sid, &code.to_be_bytes());
    }

    /// Marks the stream reset; unread data is dropped (and its window returned) unless the
    /// peer already finished sending, in which case the application may still read it.
    fn kill(&mut self, sid: u32, code: u32) {
        let mut freed = 0;
        if let Some(s) = self.streams.get_mut(&sid) {
            if s.reset.is_none() {
                s.reset = Some(code);
            }
            if !s.remote_end {
                freed = s.queued_data();
                s.inbox.clear();
            }
        }
        self.credit_conn(freed);
    }

    fn credit_conn(&mut self, n: usize) {
        self.conn_unacked += n as i64;
        if self.conn_unacked >= CREDIT_STEP {
            let u = core::mem::take(&mut self.conn_unacked);
            self.recv_win += u;
            self.put(WINDOW_UPDATE, 0, 0, &(u as u32).to_be_bytes());
        }
    }

    fn credit_stream(&mut self, sid: u32, n: usize) {
        let mut upd = 0;
        if let Some(s) = self.streams.get_mut(&sid) {
            if !s.remote_end && s.reset.is_none() {
                s.unacked += n as i64;
                if s.unacked >= CREDIT_STEP {
                    upd = core::mem::take(&mut s.unacked);
                    s.recv_win += upd;
                }
            }
        }
        if upd > 0 {
            self.put(WINDOW_UPDATE, 0, sid, &(upd as u32).to_be_bytes());
        }
    }

    fn send_headers(&mut self, sid: u32, hdrs: &[(&[u8], &[u8])], end: bool) {
        let mut blk = Vec::new();
        self.enc.encode(hdrs, &mut blk);
        let max = self.peer_max_frame;
        let mut off = 0;
        let mut first = true;
        loop {
            let n = (blk.len() - off).min(max);
            let last = off + n == blk.len();
            let (ty, mut fl) = if first { (HEADERS, if end { END_STREAM } else { 0 }) } else { (CONTINUATION, 0) };
            if last {
                fl |= END_HEADERS;
            }
            self.put(ty, fl, sid, &blk[off..off + n]);
            first = false;
            off += n;
            if last {
                break;
            }
        }
    }

    fn open_count(&self) -> usize {
        self.streams.values().filter(|s| !s.closed()).count()
    }

    fn is_ours(&self, sid: u32) -> bool {
        (sid & 1 == 1) == self.client
    }

    fn is_idle(&self, sid: u32) -> bool {
        if self.is_ours(sid) {
            sid >= self.next_id
        } else {
            sid > self.last_peer_id
        }
    }

    fn on_frame(&mut self, h: &Head, p: &[u8]) -> R {
        if let Some(c) = &self.cont {
            if h.ty != CONTINUATION || h.sid != c.sid {
                return Err(PROTOCOL_ERROR);
            }
        }
        match h.ty {
            DATA => self.on_data(h, p),
            HEADERS => {
                if h.sid == 0 {
                    return Err(PROTOCOL_ERROR);
                }
                let mut p = strip_padding(h.flags, p).ok_or(PROTOCOL_ERROR)?;
                if h.flags & PRIORITY_FLAG != 0 {
                    if p.len() < 5 {
                        return Err(FRAME_SIZE_ERROR);
                    }
                    p = &p[5..];
                }
                if p.len() > MAX_HDR_BLOCK {
                    return Err(ENHANCE_YOUR_CALM);
                }
                if h.flags & END_HEADERS != 0 {
                    self.on_block(h.sid, h.flags & END_STREAM != 0, p)
                } else {
                    self.cont = Some(Cont { sid: h.sid, end_stream: h.flags & END_STREAM != 0, buf: p.to_vec() });
                    Ok(())
                }
            }
            CONTINUATION => {
                let c = self.cont.as_mut().ok_or(PROTOCOL_ERROR)?;
                if c.buf.len() + p.len() > MAX_HDR_BLOCK {
                    return Err(ENHANCE_YOUR_CALM);
                }
                c.buf.extend_from_slice(p);
                if h.flags & END_HEADERS != 0 {
                    if let Some(c) = self.cont.take() {
                        return self.on_block(c.sid, c.end_stream, &c.buf);
                    }
                }
                Ok(())
            }
            PRIORITY => {
                if h.sid == 0 {
                    Err(PROTOCOL_ERROR)
                } else if p.len() != 5 {
                    Err(FRAME_SIZE_ERROR)
                } else {
                    Ok(())
                }
            }
            RST_STREAM => {
                if h.sid == 0 {
                    return Err(PROTOCOL_ERROR);
                }
                if p.len() != 4 {
                    return Err(FRAME_SIZE_ERROR);
                }
                if self.is_idle(h.sid) {
                    return Err(PROTOCOL_ERROR);
                }
                self.kill(h.sid, u32::from_be_bytes([p[0], p[1], p[2], p[3]]));
                Ok(())
            }
            SETTINGS => self.on_settings(h, p),
            PUSH_PROMISE => Err(PROTOCOL_ERROR),
            PING => {
                if h.sid != 0 {
                    return Err(PROTOCOL_ERROR);
                }
                if p.len() != 8 {
                    return Err(FRAME_SIZE_ERROR);
                }
                if h.flags & ACK == 0 {
                    self.put(PING, ACK, 0, p);
                }
                Ok(())
            }
            GOAWAY => {
                if h.sid != 0 {
                    return Err(PROTOCOL_ERROR);
                }
                if p.len() < 8 {
                    return Err(FRAME_SIZE_ERROR);
                }
                let last = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff;
                self.peer_goaway = true;
                let ids: Vec<u32> = self.streams.keys().copied().filter(|&i| self.is_ours(i) && i > last).collect();
                for i in ids {
                    self.kill(i, REFUSED_STREAM);
                }
                Ok(())
            }
            WINDOW_UPDATE => {
                if p.len() != 4 {
                    return Err(FRAME_SIZE_ERROR);
                }
                let inc = (u32::from_be_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff) as i64;
                if h.sid == 0 {
                    if inc == 0 {
                        return Err(PROTOCOL_ERROR);
                    }
                    self.send_win += inc;
                    if self.send_win > MAX_WIN {
                        return Err(FLOW_CONTROL_ERROR);
                    }
                    return Ok(());
                }
                if self.is_idle(h.sid) {
                    return Err(PROTOCOL_ERROR);
                }
                let mut bad = if inc == 0 { Some(PROTOCOL_ERROR) } else { None };
                if let Some(s) = self.streams.get_mut(&h.sid) {
                    s.send_win += inc;
                    if s.send_win > MAX_WIN {
                        bad = Some(FLOW_CONTROL_ERROR);
                    }
                }
                if let Some(code) = bad {
                    if self.streams.contains_key(&h.sid) {
                        self.kill(h.sid, code);
                    }
                    self.rst(h.sid, code);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn on_settings(&mut self, h: &Head, p: &[u8]) -> R {
        if h.sid != 0 {
            return Err(PROTOCOL_ERROR);
        }
        if h.flags & ACK != 0 {
            return if p.is_empty() { Ok(()) } else { Err(FRAME_SIZE_ERROR) };
        }
        if p.len() % 6 != 0 {
            return Err(FRAME_SIZE_ERROR);
        }
        self.got_settings = true;
        for e in p.chunks_exact(6) {
            let id = u16::from_be_bytes([e[0], e[1]]);
            let v = u32::from_be_bytes([e[2], e[3], e[4], e[5]]);
            match id {
                SETTINGS_HEADER_TABLE_SIZE => self.enc.set_max_table_size((v as usize).min(4096)),
                SETTINGS_ENABLE_PUSH => {
                    if v > 1 {
                        return Err(PROTOCOL_ERROR);
                    }
                }
                SETTINGS_MAX_CONCURRENT_STREAMS => self.peer_max_streams = v as usize,
                SETTINGS_INITIAL_WINDOW_SIZE => {
                    if v as i64 > MAX_WIN {
                        return Err(FLOW_CONTROL_ERROR);
                    }
                    let delta = v as i64 - self.peer_init_win;
                    self.peer_init_win = v as i64;
                    for s in self.streams.values_mut() {
                        s.send_win += delta;
                        if s.send_win > MAX_WIN {
                            return Err(FLOW_CONTROL_ERROR);
                        }
                    }
                }
                SETTINGS_MAX_FRAME_SIZE => {
                    if !(16384..=0xff_ffff).contains(&v) {
                        return Err(PROTOCOL_ERROR);
                    }
                    self.peer_max_frame = v as usize;
                }
                _ => {}
            }
        }
        self.put(SETTINGS, ACK, 0, &[]);
        Ok(())
    }

    fn on_data(&mut self, h: &Head, p: &[u8]) -> R {
        let sid = h.sid;
        if sid == 0 {
            return Err(PROTOCOL_ERROR);
        }
        let total = p.len() as i64;
        let data = strip_padding(h.flags, p).ok_or(PROTOCOL_ERROR)?;
        self.recv_win -= total;
        if self.recv_win < 0 {
            return Err(FLOW_CONTROL_ERROR);
        }
        if self.is_idle(sid) {
            return Err(PROTOCOL_ERROR);
        }
        let pad = (total as usize) - data.len();
        let Some(s) = self.streams.get_mut(&sid) else {
            self.credit_conn(total as usize);
            return Ok(());
        };
        if s.remote_end || s.reset.is_some() {
            let closed = s.remote_end;
            if closed {
                self.rst(sid, STREAM_CLOSED);
            }
            self.credit_conn(total as usize);
            return Ok(());
        }
        s.recv_win -= total;
        if s.recv_win < 0 || s.inbox.len() > MAX_INBOX {
            let code = if s.recv_win < 0 { FLOW_CONTROL_ERROR } else { ENHANCE_YOUR_CALM };
            self.kill(sid, code);
            self.rst(sid, code);
            self.credit_conn(total as usize);
            return Ok(());
        }
        if !data.is_empty() {
            match s.inbox.back_mut() {
                Some(Item::Data(d)) => d.extend_from_slice(data),
                _ => s.inbox.push_back(Item::Data(data.to_vec())),
            }
        }
        if h.flags & END_STREAM != 0 {
            s.remote_end = true;
        }
        if pad > 0 {
            self.credit_conn(pad);
            self.credit_stream(sid, pad);
        }
        Ok(())
    }

    fn on_block(&mut self, sid: u32, end: bool, blk: &[u8]) -> R {
        let hdrs = self.dec.decode(blk).map_err(|_| COMPRESSION_ERROR)?;
        if let Some(s) = self.streams.get_mut(&sid) {
            if s.reset.is_some() {
                return Ok(());
            }
            if s.remote_end {
                self.rst(sid, STREAM_CLOSED);
                return Ok(());
            }
            if s.inbox.len() > MAX_INBOX {
                self.kill(sid, ENHANCE_YOUR_CALM);
                self.rst(sid, ENHANCE_YOUR_CALM);
                return Ok(());
            }
            s.inbox.push_back(Item::Headers(hdrs));
            if end {
                s.remote_end = true;
            }
            return Ok(());
        }
        if self.is_idle(sid) {
            if self.client || self.is_ours(sid) {
                return Err(PROTOCOL_ERROR); // server push / unopened stream
            }
            self.last_peer_id = sid;
            if self.open_count() >= MAX_STREAMS {
                self.rst(sid, REFUSED_STREAM);
                return Ok(());
            }
            let mut s = S::new(self.peer_init_win);
            s.inbox.push_back(Item::Headers(hdrs));
            s.remote_end = end;
            self.streams.insert(sid, s);
            self.incoming.push_back(sid);
        }
        Ok(()) // headers on a stream we already forgot
    }
}

pub(crate) struct Inner {
    st: RefCell<St>,
    tasks: RefCell<Vec<JoinHandle<()>>>,
}

impl Inner {
    fn with<R>(&self, f: impl FnOnce(&mut St) -> R) -> R {
        let (r, ws) = {
            let mut st = self.st.borrow_mut();
            let r = f(&mut st);
            (r, core::mem::take(&mut st.wakers))
        };
        for w in ws {
            w.wake();
        }
        r
    }

    /// Waits until `f` returns `Some`. `f` must not mutate state when it returns `None`.
    async fn wait<T>(&self, mut f: impl FnMut(&mut St) -> Option<T>) -> T {
        poll_fn(|cx| {
            let (r, ws) = {
                let mut st = self.st.borrow_mut();
                match f(&mut st) {
                    Some(v) => (Poll::Ready(v), core::mem::take(&mut st.wakers)),
                    None => {
                        if !st.wakers.iter().any(|w| w.will_wake(cx.waker())) {
                            st.wakers.push(cx.waker().clone());
                        }
                        (Poll::Pending, Vec::new())
                    }
                }
            };
            for w in ws {
                w.wake();
            }
            r
        })
        .await
    }
}

/// An HTTP/2 connection; dropping it closes the transport.
pub struct Conn {
    inner: Rc<Inner>,
}

impl Conn {
    /// Starts a client connection (sends the preface and SETTINGS).
    pub fn client(io: Async<Fd>) -> Rc<Conn> {
        Self::start(io, true)
    }

    /// Starts a server connection (expects the client preface).
    pub fn server(io: Async<Fd>) -> Rc<Conn> {
        Self::start(io, false)
    }

    fn start(io: Async<Fd>, client: bool) -> Rc<Conn> {
        let mut st = St {
            client,
            closed: false,
            dying: false,
            out: Vec::new(),
            wakers: Vec::new(),
            streams: BTreeMap::new(),
            next_id: 1,
            last_peer_id: 0,
            incoming: VecDeque::new(),
            send_win: 65535,
            recv_win: 65535 + (INIT_WIN - 65535),
            conn_unacked: 0,
            peer_init_win: 65535,
            peer_max_frame: 16384,
            peer_max_streams: usize::MAX,
            peer_goaway: false,
            got_settings: false,
            enc: Encoder::new(),
            dec: Decoder::new(4096),
            cont: None,
        };
        if client {
            st.out.extend_from_slice(PREFACE);
        }
        let mut s = Vec::new();
        for (id, v) in [
            (SETTINGS_MAX_CONCURRENT_STREAMS, MAX_STREAMS as u32),
            (SETTINGS_INITIAL_WINDOW_SIZE, INIT_WIN as u32),
            (SETTINGS_MAX_HEADER_LIST_SIZE, MAX_HDR_BLOCK as u32),
        ] {
            s.extend_from_slice(&id.to_be_bytes());
            s.extend_from_slice(&v.to_be_bytes());
        }
        st.put(SETTINGS, 0, 0, &s);
        st.put(WINDOW_UPDATE, 0, 0, &((INIT_WIN - 65535) as u32).to_be_bytes());
        let inner = Rc::new(Inner { st: RefCell::new(st), tasks: RefCell::new(Vec::new()) });
        let io = Rc::new(io);
        let r = spawn(reader(inner.clone(), io.clone(), client));
        let w = spawn(writer(inner.clone(), io));
        inner.tasks.borrow_mut().extend([r, w]);
        Rc::new(Conn { inner })
    }

    pub fn is_closed(&self) -> bool {
        self.inner.st.borrow().dead()
    }

    /// Next peer-initiated stream (its request HEADERS are already queued); `None` once the
    /// connection is closed.
    pub async fn accept(self: &Rc<Self>) -> Option<Stream> {
        let id = self
            .inner
            .wait(|st| {
                if st.dead() {
                    return Some(None);
                }
                st.incoming.pop_front().map(Some)
            })
            .await?;
        Some(Stream { conn: self.clone(), id })
    }

    /// Opens a stream by sending HEADERS; waits while the peer's concurrency limit is reached.
    pub async fn open(self: &Rc<Self>, hdrs: &[(&[u8], &[u8])], end: bool) -> Result<Stream, ()> {
        let id = self
            .inner
            .wait(|st| {
                if st.dead() || st.peer_goaway || st.next_id > 0x7fff_fffe {
                    return Some(None);
                }
                // Wait for the peer's SETTINGS so MAX_CONCURRENT_STREAMS is known.
                if !st.got_settings || st.open_count() >= st.peer_max_streams {
                    return None;
                }
                let id = st.next_id;
                st.next_id += 2;
                let mut s = S::new(st.peer_init_win);
                s.local_end = end;
                st.streams.insert(id, s);
                st.send_headers(id, hdrs, end);
                Some(Some(id))
            })
            .await
            .ok_or(())?;
        Ok(Stream { conn: self.clone(), id })
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.inner.with(|st| st.hard_close());
        let tasks = core::mem::take(&mut *self.inner.tasks.borrow_mut());
        for t in &tasks {
            t.abort();
        }
    }
}

async fn writer(inner: Rc<Inner>, io: Rc<Async<Fd>>) {
    loop {
        let buf = inner
            .wait(|st| {
                if st.closed {
                    Some(None)
                } else if !st.out.is_empty() {
                    Some(Some(core::mem::take(&mut st.out)))
                } else {
                    None
                }
            })
            .await;
        let Some(buf) = buf else { return };
        if io.write_all(&buf).await.is_err() {
            inner.with(|st| st.hard_close());
            return;
        }
        inner.with(|st| {
            if st.dying && st.out.is_empty() {
                st.closed = true;
            }
        });
    }
}

async fn reader(inner: Rc<Inner>, io: Rc<Async<Fd>>, client: bool) {
    let mut buf = vec![0u8; 64 * 1024];
    let (mut pos, mut have) = (0usize, 0usize);
    let mut need_preface = !client;
    loop {
        loop {
            if need_preface {
                if have - pos < PREFACE.len() {
                    break;
                }
                if &buf[pos..pos + PREFACE.len()] != PREFACE {
                    inner.with(|st| st.hard_close());
                    return;
                }
                pos += PREFACE.len();
                need_preface = false;
            }
            if have - pos < 9 {
                break;
            }
            let h = parse_head(&buf[pos..pos + 9]);
            if h.len > MAX_FRAME {
                inner.with(|st| st.conn_error(FRAME_SIZE_ERROR));
                return;
            }
            if have - pos < 9 + h.len {
                break;
            }
            let payload = &buf[pos + 9..pos + 9 + h.len];
            if let Err(code) = inner.with(|st| st.on_frame(&h, payload)) {
                inner.with(|st| st.conn_error(code));
            }
            pos += 9 + h.len;
            if inner.st.borrow().dead() {
                return;
            }
        }
        if pos > 0 {
            buf.copy_within(pos..have, 0);
            have -= pos;
            pos = 0;
        }
        match io.read(&mut buf[have..]).await {
            Ok(n) if n > 0 => have += n,
            _ => {
                inner.with(|st| st.hard_close());
                return;
            }
        }
    }
}

/// One stream's events as seen by the application.
pub enum Ev {
    Headers(Hdrs),
    Data(Vec<u8>),
    /// The peer finished sending (everything before was delivered).
    End,
    Reset(u32),
    /// The connection died.
    Closed,
}

/// Handle to a stream. Dropping an unfinished stream sends RST_STREAM(CANCEL).
pub struct Stream {
    conn: Rc<Conn>,
    id: u32,
}

impl Stream {
    pub fn id(&self) -> u32 {
        self.id
    }

    pub async fn recv(&self) -> Ev {
        let id = self.id;
        self.conn
            .inner
            .wait(|st| {
                let dead = st.dead();
                let Some(s) = st.streams.get_mut(&id) else { return Some(Ev::Closed) };
                match s.inbox.pop_front() {
                    Some(Item::Headers(h)) => Some(Ev::Headers(h)),
                    Some(Item::Data(d)) => {
                        st.credit_conn(d.len());
                        st.credit_stream(id, d.len());
                        Some(Ev::Data(d))
                    }
                    None => {
                        if s.remote_end {
                            Some(Ev::End)
                        } else if let Some(c) = s.reset {
                            Some(Ev::Reset(c))
                        } else if dead {
                            Some(Ev::Closed)
                        } else {
                            None
                        }
                    }
                }
            })
            .await
    }

    /// Sends a header block (initial headers or trailers).
    pub fn send_headers(&self, hdrs: &[(&[u8], &[u8])], end: bool) -> Result<(), ()> {
        let id = self.id;
        self.conn.inner.with(|st| {
            if st.dead() {
                return Err(());
            }
            match st.streams.get_mut(&id) {
                Some(s) if s.reset.is_none() && !s.local_end => s.local_end = end,
                _ => return Err(()),
            }
            st.send_headers(id, hdrs, end);
            Ok(())
        })
    }

    /// Sends `data` honouring flow control and the peer's frame size; `end` sets END_STREAM on
    /// the last frame. Fails if the stream was reset or the connection died.
    pub async fn send_data(&self, data: &[u8], end: bool) -> Result<(), ()> {
        let id = self.id;
        let mut off = 0;
        if data.is_empty() && !end {
            return Ok(());
        }
        loop {
            let done = self
                .conn
                .inner
                .wait(|st| {
                    if st.dead() {
                        return Some(Err(()));
                    }
                    let sw = match st.streams.get(&id) {
                        Some(s) if s.reset.is_none() && !s.local_end => s.send_win,
                        _ => return Some(Err(())),
                    };
                    let remaining = data.len() - off;
                    let n = if remaining == 0 {
                        0
                    } else {
                        if sw <= 0 || st.send_win <= 0 || st.out.len() > OUT_HIGH {
                            return None;
                        }
                        remaining.min(sw as usize).min(st.send_win as usize).min(st.peer_max_frame)
                    };
                    let last = off + n == data.len();
                    let fl = if last && end { END_STREAM } else { 0 };
                    st.put(DATA, fl, id, &data[off..off + n]);
                    st.send_win -= n as i64;
                    if let Some(s) = st.streams.get_mut(&id) {
                        s.send_win -= n as i64;
                        if last && end {
                            s.local_end = true;
                        }
                    }
                    off += n;
                    Some(Ok(last))
                })
                .await?;
            if done {
                return Ok(());
            }
        }
    }

    pub fn reset(&self, code: u32) {
        let id = self.id;
        self.conn.inner.with(|st| {
            let live = st.streams.get(&id).is_some_and(|s| s.reset.is_none());
            if live {
                st.kill(id, code);
                st.rst(id, code);
            }
        });
    }

    /// True when the stream was reset or the connection is gone.
    pub fn is_dead(&self) -> bool {
        let st = self.conn.inner.st.borrow();
        st.dead() || st.streams.get(&self.id).is_none_or(|s| s.reset.is_some())
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        let id = self.id;
        self.conn.inner.with(|st| {
            if let Some(s) = st.streams.remove(&id) {
                if !s.closed() {
                    st.rst(id, CANCEL);
                }
                st.credit_conn(s.queued_data());
            }
        });
    }
}
