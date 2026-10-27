//! Slirp-style IPv4 userspace NAT engine for rootless pods (pure logic, no I/O).
//!
//! The pod's default route is a TUN device (raw IP packets). A driver feeds those packets to
//! [`Nat::packet_from_pod`], opens real host sockets for the [`Event`]s it gets back and relays
//! bytes through the `tcp_*` / `udp_from_host` calls; packets for the pod come out of
//! [`Nat::take_packets`]. The engine terminates the pod's TCP itself and answers ICMP echo.
//!
//! Choices: window scaling (shift 4 on our side, so 65535 advertises 1 MiB) is offered only
//! when the pod's SYN had it; otherwise (RFC 7323) neither side scales and the pod's window is
//! at most 65535. We always advertise 65535 in the header (data goes straight to the
//! driver). No retransmission timers (TUN is lossless). IP fragments from the pod are
//! reassembled (at most 32 datagrams, 30 s, overlaps discard the datagram) and packets larger
//! than the MTU leave fragmented. TCP options besides MSS and window scale are ignored.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

pub type FlowId = u32;

/// Engine -> driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Pod sent SYN; the driver must connect a host socket.
    TcpConnect { flow: FlowId, dst: [u8; 4], port: u16 },
    /// Bytes from the pod to the host socket (in order, deduplicated).
    TcpData { flow: FlowId, data: Vec<u8> },
    /// Pod sent FIN.
    TcpShutdownWrite { flow: FlowId },
    /// Flow is finished / reset / timed out; drop the host socket.
    TcpClose { flow: FlowId },
    /// Datagram from the pod; send via the per-flow host UDP socket.
    UdpSend { flow: FlowId, dst: [u8; 4], port: u16, data: Vec<u8> },
    /// Idle expiry.
    UdpClose { flow: FlowId },
    /// Pod `ping` (only with [`Nat::forward_icmp`]): send an echo request to `dst` from the host
    /// and answer with [`Nat::icmp_reply`].
    IcmpEcho { pod: [u8; 4], dst: [u8; 4], id: u16, seq: u16, data: Vec<u8> },
}

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

const UDP_IDLE_MS: u64 = 60_000;
const HANDSHAKE_MS: u64 = 30_000;
const CLOSED_MS: u64 = 10_000;
const WND: u16 = 65535;
/// Our window scale (RFC 7323), offered only when the pod's SYN carried the option: the
/// advertised 65535 then means 1 MiB.
const RCV_SHIFT: u8 = 4;

type Key = ([u8; 4], u16, [u8; 4], u16, u8);

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    /// SYN seen, waiting for the host connect result.
    SynWait,
    Open,
    /// Both FINs exchanged and acked; kept briefly to re-ack retransmits.
    Closed,
}

struct Tcb {
    pip: [u8; 4],
    pport: u16,
    dip: [u8; 4],
    dport: u16,
    state: State,
    pod_isn: u32,
    isn: u32,
    rcv_nxt: u32,
    snd_una: u32,
    snd_nxt: u32,
    wnd: u32,
    mss: usize,
    /// The pod offered window scaling: its shift, and ours is `RCV_SHIFT`.
    ws: bool,
    snd_shift: u8,
    /// Host bytes from `snd_una` on: sent-but-unacked first, then unsent.
    buf: VecDeque<u8>,
    eof: bool,
    fin_sent: bool,
    pod_fin: bool,
    /// Creation time (SynWait) or close time (Closed).
    t: u64,
}

struct Udp {
    pip: [u8; 4],
    pport: u16,
    dip: [u8; 4],
    dport: u16,
    last: u64,
}

#[derive(Default)]
struct Out {
    pkts: Vec<Vec<u8>>,
    ip_id: u16,
    /// Link MTU; larger packets leave as fragments (0: unlimited).
    mtu: usize,
}

pub struct Nat {
    mss: usize,
    now: u64,
    next_id: FlowId,
    index: BTreeMap<Key, FlowId>,
    tcp: BTreeMap<FlowId, Tcb>,
    udp: BTreeMap<FlowId, Udp>,
    events: Vec<Event>,
    out: Out,
    forward_icmp: bool,
    frags: BTreeMap<([u8; 4], [u8; 4], u8, u16), Frag>,
}

const MAX_FRAGS: usize = 32;
const FRAG_MS: u64 = 30_000;

struct Frag {
    t: u64,
    parts: BTreeMap<usize, Vec<u8>>,
    total: Option<usize>,
}

// ---- wire helpers ----

fn sum(data: &[u8], mut acc: u32) -> u32 {
    let mut c = data.chunks_exact(2);
    for w in &mut c {
        acc += u16::from_be_bytes([w[0], w[1]]) as u32;
    }
    if let [b] = c.remainder() {
        acc += (*b as u32) << 8;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    acc as u16
}

/// Transport checksum over pseudo header + segment; 0 when the embedded checksum is valid.
fn l4_sum(src: [u8; 4], dst: [u8; 4], proto: u8, seg: &[u8]) -> u16 {
    let mut a = sum(&src, 0);
    a = sum(&dst, a);
    a += proto as u32 + seg.len() as u32;
    !fold(sum(seg, a))
}

fn ip_packet(out: &mut Out, src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8]) {
    out.ip_id = out.ip_id.wrapping_add(1);
    let id = out.ip_id;
    let one = |off: usize, chunk: &[u8], more: bool, df: bool| {
        let mut p = Vec::with_capacity(20 + chunk.len());
        p.extend_from_slice(&[0x45, 0]);
        p.extend_from_slice(&((20 + chunk.len()) as u16).to_be_bytes());
        p.extend_from_slice(&id.to_be_bytes());
        let fo = (off / 8) as u16 | if more { 0x2000 } else { 0 } | if df { 0x4000 } else { 0 };
        p.extend_from_slice(&fo.to_be_bytes());
        p.extend_from_slice(&[64, proto, 0, 0]);
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        let c = !fold(sum(&p, 0));
        p[10..12].copy_from_slice(&c.to_be_bytes());
        p.extend_from_slice(chunk);
        p
    };
    if out.mtu == 0 || 20 + payload.len() <= out.mtu {
        out.pkts.push(one(0, payload, false, true));
        return;
    }
    // Fragment: every piece but the last is a multiple of 8 bytes.
    let step = (out.mtu.saturating_sub(20) / 8 * 8).max(8);
    let mut off = 0;
    while off < payload.len() {
        let end = (off + step).min(payload.len());
        out.pkts.push(one(off, &payload[off..end], end < payload.len(), false));
        off = end;
    }
}

#[allow(clippy::too_many_arguments)]
fn tcp_pkt(
    out: &mut Out,
    src: [u8; 4],
    sp: u16,
    dst: [u8; 4],
    dp: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    opts: &[u8],
    data: &[u8],
) {
    let hl = 20 + opts.len();
    let mut s = Vec::with_capacity(hl + data.len());
    s.extend_from_slice(&sp.to_be_bytes());
    s.extend_from_slice(&dp.to_be_bytes());
    s.extend_from_slice(&seq.to_be_bytes());
    s.extend_from_slice(&ack.to_be_bytes());
    s.push(((hl / 4) as u8) << 4);
    s.push(flags);
    s.extend_from_slice(&WND.to_be_bytes());
    s.extend_from_slice(&[0, 0, 0, 0]);
    s.extend_from_slice(opts);
    s.extend_from_slice(data);
    let c = l4_sum(src, dst, 6, &s);
    s[16..18].copy_from_slice(&c.to_be_bytes());
    ip_packet(out, src, dst, 6, &s);
}

fn udp_pkt(out: &mut Out, src: [u8; 4], sp: u16, dst: [u8; 4], dp: u16, data: &[u8]) {
    let mut s = Vec::with_capacity(8 + data.len());
    s.extend_from_slice(&sp.to_be_bytes());
    s.extend_from_slice(&dp.to_be_bytes());
    s.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    s.extend_from_slice(&[0, 0]);
    s.extend_from_slice(data);
    let c = match l4_sum(src, dst, 17, &s) {
        0 => 0xffff,
        c => c,
    };
    s[6..8].copy_from_slice(&c.to_be_bytes());
    ip_packet(out, src, dst, 17, &s);
}

struct Ip<'a> {
    src: [u8; 4],
    dst: [u8; 4],
    proto: u8,
    payload: &'a [u8],
    id: u16,
    /// Fragment byte offset, and whether more fragments follow.
    off: usize,
    mf: bool,
}

fn parse_ip(p: &[u8]) -> Option<Ip<'_>> {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return None;
    }
    let ihl = (p[0] & 15) as usize * 4;
    let total = u16::from_be_bytes([p[2], p[3]]) as usize;
    if ihl < 20 || total < ihl || total > p.len() {
        return None;
    }
    if fold(sum(&p[..ihl], 0)) != 0xffff {
        return None;
    }
    let fo = u16::from_be_bytes([p[6], p[7]]);
    Some(Ip {
        id: u16::from_be_bytes([p[4], p[5]]),
        off: (fo & 0x1fff) as usize * 8,
        mf: fo & 0x2000 != 0,
        src: [p[12], p[13], p[14], p[15]],
        dst: [p[16], p[17], p[18], p[19]],
        proto: p[9],
        payload: &p[ihl..total],
    })
}

struct Seg<'a> {
    sp: u16,
    dp: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    wnd: u32,
    mss: Option<u16>,
    ws: Option<u8>,
    data: &'a [u8],
}

fn parse_tcp<'a>(ip: &Ip<'a>) -> Option<Seg<'a>> {
    let s = ip.payload;
    if s.len() < 20 {
        return None;
    }
    let hl = (s[12] >> 4) as usize * 4;
    if hl < 20 || hl > s.len() || l4_sum(ip.src, ip.dst, 6, s) != 0 {
        return None;
    }
    let mut mss = None;
    let mut ws = None;
    let mut o = &s[20..hl];
    while let Some(&k) = o.first() {
        match k {
            0 => break,
            1 => o = &o[1..],
            _ => {
                let l = *o.get(1)? as usize;
                if l < 2 || l > o.len() {
                    return None;
                }
                if k == 2 && l == 4 {
                    mss = Some(u16::from_be_bytes([o[2], o[3]]));
                }
                if k == 3 && l == 3 {
                    ws = Some(o[2].min(14));
                }
                o = &o[l..];
            }
        }
    }
    Some(Seg {
        sp: u16::from_be_bytes([s[0], s[1]]),
        dp: u16::from_be_bytes([s[2], s[3]]),
        seq: u32::from_be_bytes([s[4], s[5], s[6], s[7]]),
        ack: u32::from_be_bytes([s[8], s[9], s[10], s[11]]),
        flags: s[13],
        wnd: u16::from_be_bytes([s[14], s[15]]) as u32,
        mss,
        ws,
        data: &s[hl..],
    })
}

impl Tcb {
    fn send(&self, out: &mut Out, seq: u32, flags: u8, opts: &[u8], data: &[u8]) {
        tcp_pkt(out, self.dip, self.dport, self.pip, self.pport, seq, self.rcv_nxt, flags, opts, data);
    }

    fn synack(&self, out: &mut Out, mss: usize) {
        let mut o = alloc::vec![2, 4, (mss >> 8) as u8, mss as u8];
        if self.ws {
            o.extend_from_slice(&[1, 3, 3, RCV_SHIFT]);
        }
        self.send(out, self.isn, SYN | ACK, &o, &[]);
    }

    /// Send as much buffered data (then FIN) as the pod's window allows. True if anything sent.
    fn flush(&mut self, out: &mut Out) -> bool {
        if self.state != State::Open {
            return false;
        }
        let mut any = false;
        loop {
            let infl = self.snd_nxt.wrapping_sub(self.snd_una) as usize;
            let sent = infl.min(self.buf.len());
            let unsent = self.buf.len() - sent;
            let avail = (self.wnd as usize).saturating_sub(infl);
            let n = unsent.min(avail).min(self.mss);
            if n == 0 {
                break;
            }
            let data: Vec<u8> = self.buf.range(sent..sent + n).copied().collect();
            let fl = if n == unsent { ACK | PSH } else { ACK };
            self.send(out, self.snd_nxt, fl, &[], &data);
            self.snd_nxt = self.snd_nxt.wrapping_add(n as u32);
            any = true;
        }
        let infl = self.snd_nxt.wrapping_sub(self.snd_una) as usize;
        if self.eof && !self.fin_sent && self.buf.len() <= infl {
            self.send(out, self.snd_nxt, FIN | ACK, &[], &[]);
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            self.fin_sent = true;
            any = true;
        }
        any
    }

    fn on_ack(&mut self, ack: u32, wnd: u32) {
        let d = ack.wrapping_sub(self.snd_una) as i32;
        if d < 0 || (ack.wrapping_sub(self.snd_nxt) as i32) > 0 {
            return;
        }
        self.snd_una = ack;
        self.wnd = wnd;
        let n = (d as usize).min(self.buf.len());
        self.buf.drain(..n);
    }

    fn fin_acked(&self) -> bool {
        self.fin_sent && self.snd_una == self.snd_nxt
    }
}

impl Nat {
    pub fn new(mtu: usize) -> Nat {
        Nat {
            mss: mtu.saturating_sub(40).max(1),
            now: 0,
            next_id: 1,
            index: BTreeMap::new(),
            tcp: BTreeMap::new(),
            udp: BTreeMap::new(),
            events: Vec::new(),
            out: Out { mtu, ..Out::default() },
            forward_icmp: false,
            frags: BTreeMap::new(),
        }
    }

    pub fn take_events(&mut self) -> Vec<Event> {
        core::mem::take(&mut self.events)
    }

    pub fn take_packets(&mut self) -> Vec<Vec<u8>> {
        core::mem::take(&mut self.out.pkts)
    }

    /// Live flows (TCP including lingering closed ones, and UDP).
    pub fn flow_count(&self) -> usize {
        self.index.len()
    }

    pub fn pending_to_pod(&self, flow: FlowId) -> usize {
        self.tcp.get(&flow).map_or(0, |t| t.buf.len())
    }

    pub fn packet_from_pod(&mut self, pkt: &[u8], now_ms: u64) {
        self.now = now_ms;
        let Some(ip) = parse_ip(pkt) else { return };
        if ip.mf || ip.off > 0 {
            if let Some(whole) = self.reassemble(&ip) {
                let full = Ip { payload: &whole, off: 0, mf: false, ..ip };
                self.deliver(&full);
            }
            return;
        }
        self.deliver(&ip);
    }

    /// Collects a fragment; returns the whole payload once every byte arrived. Overlapping
    /// fragments discard the datagram (RFC 5722 style); at most `MAX_FRAGS` datagrams wait.
    fn reassemble(&mut self, ip: &Ip<'_>) -> Option<Vec<u8>> {
        let key = (ip.src, ip.dst, ip.proto, ip.id);
        if !self.frags.contains_key(&key) && self.frags.len() >= MAX_FRAGS {
            let oldest = *self.frags.iter().min_by_key(|(_, f)| f.t)?.0;
            self.frags.remove(&oldest);
        }
        let now = self.now;
        let f = self.frags.entry(key).or_insert_with(|| Frag { t: now, parts: BTreeMap::new(), total: None });
        let end = ip.off + ip.payload.len();
        if ip.payload.is_empty() || end > 65515 || (ip.mf && ip.payload.len() % 8 != 0) {
            self.frags.remove(&key);
            return None;
        }
        if !ip.mf {
            f.total = Some(end);
        }
        let overlaps = f.parts.range(..end).any(|(&o, d)| o + d.len() > ip.off) && !f.parts.contains_key(&ip.off);
        if overlaps || f.total.is_some_and(|t| end > t) {
            self.frags.remove(&key);
            return None;
        }
        f.parts.insert(ip.off, ip.payload.to_vec());
        let total = f.total?;
        let mut next = 0;
        for (&o, d) in &f.parts {
            if o != next {
                return None;
            }
            next = o + d.len();
        }
        if next != total {
            return None;
        }
        let f = self.frags.remove(&key)?;
        Some(f.parts.into_values().flatten().collect())
    }

    fn deliver(&mut self, ip: &Ip<'_>) {
        let ip = Ip { ..*ip };
        match ip.proto {
            1 => self.icmp_in(&ip),
            6 => {
                if let Some(seg) = parse_tcp(&ip) {
                    self.tcp_in(ip.src, ip.dst, seg);
                }
            }
            17 => self.udp_in(&ip),
            _ => {}
        }
    }

    fn icmp_in(&mut self, ip: &Ip<'_>) {
        let p = ip.payload;
        if p.len() < 8 || p[0] != 8 || p[1] != 0 || fold(sum(p, 0)) != 0xffff {
            return;
        }
        if self.forward_icmp {
            let id = u16::from_be_bytes([p[4], p[5]]);
            let seq = u16::from_be_bytes([p[6], p[7]]);
            self.events.push(Event::IcmpEcho { pod: ip.src, dst: ip.dst, id, seq, data: p[8..].to_vec() });
            return;
        }
        self.icmp_reply(ip.src, ip.dst, u16::from_be_bytes([p[4], p[5]]), u16::from_be_bytes([p[6], p[7]]), &p[8..]);
    }

    /// Sends an echo reply from `from` to the pod `pod`.
    pub fn icmp_reply(&mut self, pod: [u8; 4], from: [u8; 4], id: u16, seq: u16, data: &[u8]) {
        let mut r = alloc::vec![0u8; 8];
        r[4..6].copy_from_slice(&id.to_be_bytes());
        r[6..8].copy_from_slice(&seq.to_be_bytes());
        r.extend_from_slice(data);
        let c = !fold(sum(&r, 0));
        r[2..4].copy_from_slice(&c.to_be_bytes());
        ip_packet(&mut self.out, from, pod, 1, &r);
    }

    /// Forward pod pings to the host as [`Event::IcmpEcho`] instead of answering them locally.
    pub fn forward_icmp(&mut self, on: bool) {
        self.forward_icmp = on;
    }

    fn alloc_id(&mut self) -> FlowId {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        id
    }

    fn udp_in(&mut self, ip: &Ip<'_>) {
        let s = ip.payload;
        if s.len() < 8 {
            return;
        }
        let len = u16::from_be_bytes([s[4], s[5]]) as usize;
        if len < 8 || len > s.len() {
            return;
        }
        let s = &s[..len];
        if (s[6] != 0 || s[7] != 0) && l4_sum(ip.src, ip.dst, 17, s) != 0 {
            return;
        }
        let sp = u16::from_be_bytes([s[0], s[1]]);
        let dp = u16::from_be_bytes([s[2], s[3]]);
        let key = (ip.src, sp, ip.dst, dp, 17);
        let id = match self.index.get(&key) {
            Some(&id) => id,
            None => {
                let id = self.alloc_id();
                self.index.insert(key, id);
                self.udp.insert(id, Udp { pip: ip.src, pport: sp, dip: ip.dst, dport: dp, last: self.now });
                id
            }
        };
        if let Some(u) = self.udp.get_mut(&id) {
            u.last = self.now;
        }
        self.events.push(Event::UdpSend { flow: id, dst: ip.dst, port: dp, data: s[8..].to_vec() });
    }

    pub fn udp_from_host(&mut self, flow: FlowId, data: &[u8]) {
        let now = self.now;
        let Some(u) = self.udp.get_mut(&flow) else { return };
        u.last = now;
        udp_pkt(&mut self.out, u.dip, u.dport, u.pip, u.pport, data);
    }

    fn remove_tcp(&mut self, id: FlowId) {
        if let Some(t) = self.tcp.remove(&id) {
            self.index.remove(&(t.pip, t.pport, t.dip, t.dport, 6));
        }
    }

    fn tcp_in(&mut self, src: [u8; 4], dst: [u8; 4], seg: Seg<'_>) {
        let key = (src, seg.sp, dst, seg.dp, 6);
        let syn = seg.flags & SYN != 0;
        let rst = seg.flags & RST != 0;
        let has_ack = seg.flags & ACK != 0;
        let mut id = self.index.get(&key).copied();
        if let Some(i) = id {
            if syn && !has_ack && !rst {
                let t = &self.tcp[&i];
                if t.state == State::Closed {
                    self.remove_tcp(i);
                    id = None;
                } else {
                    // Retransmitted SYN: answer once connected, ignore before.
                    if t.state == State::Open && seg.seq == t.pod_isn && t.snd_nxt == t.isn.wrapping_add(1) {
                        t.synack(&mut self.out, t.mss.min(self.mss));
                    }
                    return;
                }
            }
        }
        let Some(id) = id else {
            if rst {
                return;
            }
            if syn && !has_ack {
                let id = self.alloc_id();
                let isn = id.wrapping_mul(2654435761).wrapping_add((self.now as u32).wrapping_mul(250));
                let pod_mss = seg.mss.map_or(536, |m| m as usize).max(1);
                self.index.insert(key, id);
                self.tcp.insert(
                    id,
                    Tcb {
                        pip: src,
                        pport: seg.sp,
                        dip: dst,
                        dport: seg.dp,
                        state: State::SynWait,
                        pod_isn: seg.seq,
                        isn,
                        rcv_nxt: seg.seq.wrapping_add(1),
                        snd_una: isn.wrapping_add(1),
                        snd_nxt: isn.wrapping_add(1),
                        wnd: seg.wnd,
                        mss: pod_mss.min(self.mss),
                        ws: seg.ws.is_some(),
                        snd_shift: seg.ws.unwrap_or(0),
                        buf: VecDeque::new(),
                        eof: false,
                        fin_sent: false,
                        pod_fin: false,
                        t: self.now,
                    },
                );
                self.events.push(Event::TcpConnect { flow: id, dst, port: seg.dp });
                return;
            }
            // No such flow: RST (RFC 793).
            let occ = seg.data.len() as u32 + (seg.flags & (SYN | FIN)).count_ones();
            if has_ack {
                tcp_pkt(&mut self.out, dst, seg.dp, src, seg.sp, seg.ack, 0, RST, &[], &[]);
            } else {
                let a = seg.seq.wrapping_add(occ);
                tcp_pkt(&mut self.out, dst, seg.dp, src, seg.sp, 0, a, RST | ACK, &[], &[]);
            }
            return;
        };
        let Some(t) = self.tcp.get_mut(&id) else { return };
        if rst {
            if t.state != State::Closed {
                self.events.push(Event::TcpClose { flow: id });
            }
            self.remove_tcp(id);
            return;
        }
        let occupies = !seg.data.is_empty() || seg.flags & FIN != 0;
        match t.state {
            State::SynWait => return,
            State::Closed => {
                if occupies {
                    t.send(&mut self.out, t.snd_nxt, ACK, &[], &[]);
                }
                return;
            }
            State::Open => {}
        }
        if has_ack {
            t.on_ack(seg.ack, seg.wnd << t.snd_shift);
        }
        // Receive path: accept only in-order bytes, trim already-acked overlap.
        let mut data = seg.data;
        let mut fin = seg.flags & FIN != 0;
        let mut d = seg.seq.wrapping_sub(t.rcv_nxt) as i32;
        if d < 0 {
            let skip = d.unsigned_abs() as usize;
            if skip > data.len() {
                data = &[];
                fin = false;
            } else {
                data = &data[skip..];
            }
            d = 0;
        }
        if d > 0 {
            data = &[];
            fin = false;
        }
        if t.pod_fin {
            data = &[];
            fin = false;
        }
        if !data.is_empty() {
            t.rcv_nxt = t.rcv_nxt.wrapping_add(data.len() as u32);
            self.events.push(Event::TcpData { flow: id, data: data.to_vec() });
        }
        if fin {
            t.pod_fin = true;
            t.rcv_nxt = t.rcv_nxt.wrapping_add(1);
            self.events.push(Event::TcpShutdownWrite { flow: id });
        }
        let sent = t.flush(&mut self.out);
        if occupies && !sent {
            t.send(&mut self.out, t.snd_nxt, ACK, &[], &[]);
        }
        if t.pod_fin && t.fin_acked() {
            t.state = State::Closed;
            t.t = self.now;
            t.buf.clear();
            self.events.push(Event::TcpClose { flow: id });
        }
    }

    pub fn tcp_connected(&mut self, flow: FlowId) {
        let Some(t) = self.tcp.get_mut(&flow) else { return };
        if t.state != State::SynWait {
            return;
        }
        t.state = State::Open;
        t.synack(&mut self.out, self.mss);
        t.flush(&mut self.out);
    }

    pub fn tcp_refused(&mut self, flow: FlowId) {
        let Some(t) = self.tcp.get(&flow) else { return };
        let ack = t.pod_isn.wrapping_add(1);
        tcp_pkt(&mut self.out, t.dip, t.dport, t.pip, t.pport, 0, ack, RST | ACK, &[], &[]);
        self.remove_tcp(flow);
    }

    pub fn tcp_host_reset(&mut self, flow: FlowId) {
        let Some(t) = self.tcp.get(&flow) else { return };
        if t.state != State::Closed {
            t.send(&mut self.out, t.snd_nxt, RST | ACK, &[], &[]);
        }
        self.remove_tcp(flow);
    }

    pub fn tcp_host_data(&mut self, flow: FlowId, data: &[u8]) {
        let Some(t) = self.tcp.get_mut(&flow) else { return };
        if t.eof || t.state == State::Closed || data.is_empty() {
            return;
        }
        t.buf.extend(data);
        t.flush(&mut self.out);
    }

    pub fn tcp_host_eof(&mut self, flow: FlowId) {
        let Some(t) = self.tcp.get_mut(&flow) else { return };
        t.eof = true;
        t.flush(&mut self.out);
    }

    pub fn tick(&mut self, now_ms: u64) {
        self.now = now_ms;
        self.frags.retain(|_, f| now_ms.saturating_sub(f.t) < FRAG_MS);
        let dead: Vec<FlowId> = self
            .udp
            .iter()
            .filter(|(_, u)| now_ms.saturating_sub(u.last) >= UDP_IDLE_MS)
            .map(|(&i, _)| i)
            .collect();
        for id in dead {
            if let Some(u) = self.udp.remove(&id) {
                self.index.remove(&(u.pip, u.pport, u.dip, u.dport, 17));
                self.events.push(Event::UdpClose { flow: id });
            }
        }
        let dead: Vec<FlowId> = self
            .tcp
            .iter()
            .filter(|(_, t)| {
                let age = now_ms.saturating_sub(t.t);
                match t.state {
                    State::SynWait => age >= HANDSHAKE_MS,
                    State::Closed => age >= CLOSED_MS,
                    State::Open => false,
                }
            })
            .map(|(&i, _)| i)
            .collect();
        for id in dead {
            if self.tcp[&id].state == State::SynWait {
                let t = &self.tcp[&id];
                tcp_pkt(&mut self.out, t.dip, t.dport, t.pip, t.pport, 0, t.rcv_nxt, RST | ACK, &[], &[]);
                self.events.push(Event::TcpClose { flow: id });
            }
            self.remove_tcp(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POD: [u8; 4] = [10, 0, 0, 2];
    const DST: [u8; 4] = [93, 184, 216, 34];
    const PP: u16 = 40000;

    fn pod_tcp(seq: u32, ack: u32, flags: u8, wnd: u16, mss: Option<u16>, data: &[u8]) -> Vec<u8> {
        let mut o = Out::default();
        let opts: Vec<u8> = mss.map_or(Vec::new(), |m| alloc::vec![2, 4, (m >> 8) as u8, m as u8]);
        tcp_pkt(&mut o, POD, PP, DST, 80, seq, ack, flags, &opts, data);
        let mut p = o.pkts.pop().unwrap();
        // tcp_pkt always advertises WND; patch the window and refresh the checksum.
        let ihl = 20;
        p[ihl + 14..ihl + 16].copy_from_slice(&wnd.to_be_bytes());
        p[ihl + 16] = 0;
        p[ihl + 17] = 0;
        let c = l4_sum(POD, DST, 6, &p[ihl..]);
        p[ihl + 16..ihl + 18].copy_from_slice(&c.to_be_bytes());
        p
    }

    fn parse(p: &[u8]) -> (Ip<'_>, Seg<'_>) {
        let ip = parse_ip(p).expect("valid ip");
        assert_eq!(ip.proto, 6);
        let seg = parse_tcp(&ip).expect("valid tcp");
        (ip, seg)
    }

    struct Hs {
        nat: Nat,
        id: FlowId,
        isn: u32, // our ISN
        pod_seq: u32,
    }

    fn handshake(wnd: u16) -> Hs {
        let mut nat = Nat::new(1500);
        nat.packet_from_pod(&pod_tcp(1000, 0, SYN, wnd, Some(1460), &[]), 0);
        let ev = nat.take_events();
        assert_eq!(ev.len(), 1);
        let Event::TcpConnect { flow, dst, port } = ev[0].clone() else { panic!() };
        assert_eq!((dst, port), (DST, 80));
        assert!(nat.take_packets().is_empty());
        nat.tcp_connected(flow);
        let pk = nat.take_packets();
        assert_eq!(pk.len(), 1);
        let (ip, s) = parse(&pk[0]);
        assert_eq!((ip.src, ip.dst), (DST, POD));
        assert_eq!(s.flags, SYN | ACK);
        assert_eq!(s.ack, 1001);
        assert_eq!(s.mss, Some(1460));
        let isn = s.seq;
        nat.packet_from_pod(&pod_tcp(1001, isn.wrapping_add(1), ACK, wnd, None, &[]), 1);
        assert!(nat.take_packets().is_empty());
        Hs { nat, id: flow, isn, pod_seq: 1001 }
    }

    fn drain(nat: &mut Nat) -> Vec<(u8, u32, u32, Vec<u8>)> {
        nat.take_packets()
            .iter()
            .map(|p| {
                let (_, s) = parse(p);
                (s.flags, s.seq, s.ack, s.data.to_vec())
            })
            .collect()
    }

    #[test]
    fn full_flow() {
        let mut h = handshake(65535);
        let id = h.id;
        // pod -> host data
        h.nat.packet_from_pod(&pod_tcp(h.pod_seq, h.isn + 1, ACK | PSH, 65535, None, b"hello"), 2);
        assert_eq!(h.nat.take_events(), alloc::vec![Event::TcpData { flow: id, data: b"hello".to_vec() }]);
        let a = drain(&mut h.nat);
        assert_eq!(a.len(), 1);
        assert_eq!((a[0].0, a[0].2), (ACK, h.pod_seq + 5));
        h.pod_seq += 5;
        // host -> pod, bigger than mss
        let big: Vec<u8> = (0..4000u32).map(|i| i as u8).collect();
        h.nat.tcp_host_data(id, &big);
        let segs = drain(&mut h.nat);
        assert_eq!(segs.len(), 3);
        assert_eq!(segs[0].3.len(), 1460);
        assert_eq!(segs[2].3.len(), 4000 - 2 * 1460);
        assert_eq!(segs[0].0, ACK);
        assert_eq!(segs[2].0, ACK | PSH);
        let got: Vec<u8> = segs.iter().flat_map(|s| s.3.clone()).collect();
        assert_eq!(got, big);
        assert_eq!(segs[1].1, h.isn + 1 + 1460);
        assert_eq!(h.nat.pending_to_pod(id), 4000);
        h.nat.packet_from_pod(&pod_tcp(h.pod_seq, h.isn + 1 + 4000, ACK, 65535, None, &[]), 3);
        assert_eq!(h.nat.pending_to_pod(id), 0);
        // pod FIN
        h.nat.packet_from_pod(&pod_tcp(h.pod_seq, h.isn + 1 + 4000, FIN | ACK, 65535, None, &[]), 4);
        assert_eq!(h.nat.take_events(), alloc::vec![Event::TcpShutdownWrite { flow: id }]);
        let a = drain(&mut h.nat);
        assert_eq!((a[0].0, a[0].2), (ACK, h.pod_seq + 1));
        h.pod_seq += 1;
        // duplicate FIN is only re-acked
        h.nat.packet_from_pod(&pod_tcp(h.pod_seq - 1, h.isn + 1 + 4000, FIN | ACK, 65535, None, &[]), 4);
        assert!(h.nat.take_events().is_empty());
        assert_eq!(drain(&mut h.nat).len(), 1);
        // host eof -> FIN, pod acks
        h.nat.tcp_host_eof(id);
        let f = drain(&mut h.nat);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].0, FIN | ACK);
        h.nat.packet_from_pod(&pod_tcp(h.pod_seq, h.isn + 4002, ACK, 65535, None, &[]), 5);
        assert_eq!(h.nat.take_events(), alloc::vec![Event::TcpClose { flow: id }]);
        assert_eq!(h.nat.flow_count(), 1);
        h.nat.tick(5 + CLOSED_MS);
        assert_eq!(h.nat.flow_count(), 0);
    }

    #[test]
    fn fin_from_host_first() {
        let mut h = handshake(65535);
        h.nat.tcp_host_data(h.id, b"x");
        h.nat.tcp_host_eof(h.id);
        let s = drain(&mut h.nat);
        assert_eq!(s.len(), 2);
        assert_eq!(s[1].0, FIN | ACK);
        h.nat.packet_from_pod(&pod_tcp(h.pod_seq, h.isn + 3, ACK, 65535, None, &[]), 2);
        assert!(h.nat.take_events().is_empty());
        h.nat.packet_from_pod(&pod_tcp(h.pod_seq, h.isn + 3, FIN | ACK, 65535, None, &[]), 3);
        let ev = h.nat.take_events();
        assert_eq!(ev.len(), 2);
        assert_eq!(ev[1], Event::TcpClose { flow: h.id });
    }

    #[test]
    fn window_limits() {
        let mut h = handshake(1000);
        let id = h.id;
        let data = alloc::vec![7u8; 3000];
        h.nat.tcp_host_data(id, &data);
        let s = drain(&mut h.nat);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].3.len(), 1000);
        assert_eq!(s[0].0, ACK); // more buffered: no PSH
        // zero window ack: nothing more
        h.nat.packet_from_pod(&pod_tcp(h.pod_seq, h.isn + 1001, ACK, 0, None, &[]), 2);
        assert!(h.nat.take_packets().is_empty());
        assert_eq!(h.nat.pending_to_pod(id), 2000);
        // window opens
        h.nat.packet_from_pod(&pod_tcp(h.pod_seq, h.isn + 1001, ACK, 1200, None, &[]), 3);
        let s = drain(&mut h.nat);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].3.len(), 1200);
        h.nat.packet_from_pod(&pod_tcp(h.pod_seq, h.isn + 2201, ACK, 5000, None, &[]), 4);
        let s = drain(&mut h.nat);
        assert_eq!(s.len(), 1);
        assert_eq!((s[0].3.len(), s[0].0), (800, ACK | PSH));
    }

    #[test]
    fn refused() {
        let mut nat = Nat::new(1500);
        nat.packet_from_pod(&pod_tcp(5, 0, SYN, 1000, None, &[]), 0);
        let Event::TcpConnect { flow, .. } = nat.take_events()[0].clone() else { panic!() };
        nat.tcp_refused(flow);
        let p = nat.take_packets();
        let (_, s) = parse(&p[0]);
        assert_eq!(s.flags, RST | ACK);
        assert_eq!(s.ack, 6);
        assert_eq!(nat.flow_count(), 0);
    }

    #[test]
    fn duplicate_syn() {
        let mut nat = Nat::new(1500);
        let syn = pod_tcp(1000, 0, SYN, 1000, Some(1460), &[]);
        nat.packet_from_pod(&syn, 0);
        let Event::TcpConnect { flow, .. } = nat.take_events()[0].clone() else { panic!() };
        nat.packet_from_pod(&syn, 1);
        assert!(nat.take_events().is_empty());
        assert!(nat.take_packets().is_empty());
        nat.tcp_connected(flow);
        assert_eq!(nat.take_packets().len(), 1);
        nat.packet_from_pod(&syn, 2);
        assert!(nat.take_events().is_empty());
        let p = nat.take_packets();
        assert_eq!(p.len(), 1);
        assert_eq!(parse(&p[0]).1.flags, SYN | ACK);
    }

    #[test]
    fn out_of_order_and_dups() {
        let mut h = handshake(65535);
        let (id, isn, s0) = (h.id, h.isn, h.pod_seq);
        // gap: dropped, re-ack rcv_nxt
        h.nat.packet_from_pod(&pod_tcp(s0 + 3, isn + 1, ACK, 65535, None, b"def"), 2);
        assert!(h.nat.take_events().is_empty());
        let a = drain(&mut h.nat);
        assert_eq!(a[0].2, s0);
        h.nat.packet_from_pod(&pod_tcp(s0, isn + 1, ACK, 65535, None, b"abc"), 3);
        assert_eq!(h.nat.take_events(), alloc::vec![Event::TcpData { flow: id, data: b"abc".to_vec() }]);
        h.nat.take_packets();
        // full duplicate
        h.nat.packet_from_pod(&pod_tcp(s0, isn + 1, ACK, 65535, None, b"abc"), 4);
        assert!(h.nat.take_events().is_empty());
        assert_eq!(drain(&mut h.nat)[0].2, s0 + 3);
        // overlap: only new tail delivered
        h.nat.packet_from_pod(&pod_tcp(s0 + 1, isn + 1, ACK, 65535, None, b"bcde"), 5);
        assert_eq!(h.nat.take_events(), alloc::vec![Event::TcpData { flow: id, data: b"de".to_vec() }]);
        assert_eq!(drain(&mut h.nat)[0].2, s0 + 5);
    }

    #[test]
    fn rst_from_pod() {
        let mut h = handshake(65535);
        h.nat.packet_from_pod(&pod_tcp(h.pod_seq, 0, RST, 0, None, &[]), 2);
        assert_eq!(h.nat.take_events(), alloc::vec![Event::TcpClose { flow: h.id }]);
        assert_eq!(h.nat.flow_count(), 0);
        assert!(h.nat.take_packets().is_empty());
    }

    #[test]
    fn host_reset_and_unknown_flow() {
        let mut h = handshake(65535);
        h.nat.tcp_host_reset(h.id);
        let a = drain(&mut h.nat);
        assert_eq!(a[0].0 & RST, RST);
        assert_eq!(h.nat.flow_count(), 0);
        h.nat.packet_from_pod(&pod_tcp(h.pod_seq, h.isn + 1, ACK, 100, None, b"zz"), 2);
        assert_eq!(drain(&mut h.nat)[0].0 & RST, RST);
    }

    #[test]
    fn handshake_timeout() {
        let mut nat = Nat::new(1500);
        nat.packet_from_pod(&pod_tcp(5, 0, SYN, 1000, None, &[]), 0);
        let Event::TcpConnect { flow, .. } = nat.take_events()[0].clone() else { panic!() };
        nat.tick(29_999);
        assert_eq!(nat.flow_count(), 1);
        nat.tick(30_000);
        assert_eq!(nat.take_events(), alloc::vec![Event::TcpClose { flow }]);
        assert_eq!(nat.flow_count(), 0);
        assert_eq!(nat.take_packets().len(), 1);
    }

    fn pod_udp(data: &[u8]) -> Vec<u8> {
        let mut o = Out::default();
        let mut s = Vec::new();
        s.extend_from_slice(&5000u16.to_be_bytes());
        s.extend_from_slice(&53u16.to_be_bytes());
        s.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
        s.extend_from_slice(&[0, 0]);
        s.extend_from_slice(data);
        let c = l4_sum(POD, DST, 17, &s);
        s[6..8].copy_from_slice(&c.to_be_bytes());
        ip_packet(&mut o, POD, DST, 17, &s);
        o.pkts.pop().unwrap()
    }

    #[test]
    fn udp_roundtrip_and_expiry() {
        let mut nat = Nat::new(1500);
        nat.packet_from_pod(&pod_udp(b"query"), 100);
        let ev = nat.take_events();
        let Event::UdpSend { flow, dst, port, data } = ev[0].clone() else { panic!() };
        assert_eq!((dst, port, data), (DST, 53, b"query".to_vec()));
        nat.packet_from_pod(&pod_udp(b"q2"), 200);
        let Event::UdpSend { flow: f2, .. } = nat.take_events()[0].clone() else { panic!() };
        assert_eq!(flow, f2);
        nat.udp_from_host(flow, b"answer");
        let p = nat.take_packets();
        let ip = parse_ip(&p[0]).unwrap();
        assert_eq!((ip.src, ip.dst, ip.proto), (DST, POD, 17));
        assert_eq!(l4_sum(ip.src, ip.dst, 17, ip.payload), 0);
        assert_eq!(u16::from_be_bytes([ip.payload[0], ip.payload[1]]), 53);
        assert_eq!(u16::from_be_bytes([ip.payload[2], ip.payload[3]]), 5000);
        assert_eq!(&ip.payload[8..], b"answer");
        nat.tick(200 + UDP_IDLE_MS - 1);
        assert!(nat.take_events().is_empty());
        nat.tick(200 + UDP_IDLE_MS);
        assert_eq!(nat.take_events(), alloc::vec![Event::UdpClose { flow }]);
        assert_eq!(nat.flow_count(), 0);
    }

    #[test]
    fn icmp_echo() {
        let mut nat = Nat::new(1500);
        let mut m = alloc::vec![8, 0, 0, 0, 0x12, 0x34, 0, 7, b'a', b'b', b'c'];
        let c = !fold(sum(&m, 0));
        m[2..4].copy_from_slice(&c.to_be_bytes());
        let mut o = Out::default();
        ip_packet(&mut o, POD, DST, 1, &m);
        nat.packet_from_pod(&o.pkts[0], 0);
        assert!(nat.take_events().is_empty());
        let p = nat.take_packets();
        let ip = parse_ip(&p[0]).unwrap();
        assert_eq!((ip.src, ip.dst, ip.proto), (DST, POD, 1));
        assert_eq!(ip.payload[0], 0);
        assert_eq!(&ip.payload[4..], &m[4..]);
        assert_eq!(fold(sum(ip.payload, 0)), 0xffff);
    }

    #[test]
    fn icmp_echo_forwarded() {
        let mut nat = Nat::new(1500);
        nat.forward_icmp(true);
        let mut m = alloc::vec![8, 0, 0, 0, 0x12, 0x34, 0, 7, b'a', b'b'];
        let c = !fold(sum(&m, 0));
        m[2..4].copy_from_slice(&c.to_be_bytes());
        let mut o = Out::default();
        ip_packet(&mut o, POD, DST, 1, &m);
        nat.packet_from_pod(&o.pkts[0], 0);
        assert!(nat.take_packets().is_empty());
        assert_eq!(nat.take_events(), alloc::vec![Event::IcmpEcho { pod: POD, dst: DST, id: 0x1234, seq: 7, data: alloc::vec![b'a', b'b'] }]);
        nat.icmp_reply(POD, DST, 0x1234, 7, b"ab");
        let p = nat.take_packets();
        let ip = parse_ip(&p[0]).unwrap();
        assert_eq!((ip.src, ip.dst, ip.proto), (DST, POD, 1));
        assert_eq!(&ip.payload[4..], &m[4..]);
        assert_eq!(fold(sum(ip.payload, 0)), 0xffff);
    }

    #[test]
    fn fragments_from_pod_are_reassembled() {
        let data: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
        let whole = pod_udp(&data);
        let payload = whole[20..].to_vec();
        let mut o = Out { mtu: 600, ..Out::default() };
        ip_packet(&mut o, POD, DST, 17, &payload);
        assert!(o.pkts.len() > 4);
        let mut nat = Nat::new(1500);
        for f in o.pkts.iter().rev() {
            assert!(nat.take_events().is_empty());
            nat.packet_from_pod(f, 0);
        }
        let ev = nat.take_events();
        assert_eq!(ev.len(), 1);
        let Event::UdpSend { data: got, port, .. } = &ev[0] else { panic!() };
        assert_eq!((got, *port), (&data, 53));
    }

    #[test]
    fn overlapping_fragments_discarded() {
        let payload = pod_udp(&[7u8; 1500])[20..].to_vec();
        let mut o = Out { mtu: 600, ..Out::default() };
        ip_packet(&mut o, POD, DST, 17, &payload);
        let mut nat = Nat::new(1500);
        nat.packet_from_pod(&o.pkts[0], 0);
        // A fragment whose bytes overlap the first one's.
        let mut bad = o.pkts[1].clone();
        bad[6..8].copy_from_slice(&(0x2000u16 | 10).to_be_bytes());
        bad[10] = 0;
        bad[11] = 0;
        let c = !fold(sum(&bad[..20], 0));
        bad[10..12].copy_from_slice(&c.to_be_bytes());
        nat.packet_from_pod(&bad, 0);
        for f in &o.pkts[1..] {
            nat.packet_from_pod(f, 0);
        }
        assert!(nat.take_events().is_empty());
    }

    #[test]
    fn large_udp_reply_is_fragmented() {
        let mut nat = Nat::new(600);
        nat.packet_from_pod(&pod_udp(b"q"), 0);
        let Event::UdpSend { flow, .. } = nat.take_events()[0].clone() else { panic!() };
        let reply: Vec<u8> = (0..4000u32).map(|i| (i * 3) as u8).collect();
        nat.udp_from_host(flow, &reply);
        let pk = nat.take_packets();
        assert!(pk.len() > 6 && pk.iter().all(|p| p.len() <= 600));
        // The pod's side reassembles it back (reuse the reassembler as the receiver).
        let mut rx = Nat::new(1500);
        for p in &pk {
            rx.packet_from_pod(p, 0);
        }
        let ev = rx.take_events();
        let Event::UdpSend { data, .. } = &ev[0] else { panic!() };
        assert_eq!(data, &reply);
    }

    #[test]
    fn stale_fragments_expire() {
        let payload = pod_udp(&[1u8; 1500])[20..].to_vec();
        let mut o = Out { mtu: 600, ..Out::default() };
        ip_packet(&mut o, POD, DST, 17, &payload);
        let mut nat = Nat::new(1500);
        nat.packet_from_pod(&o.pkts[0], 0);
        nat.tick(FRAG_MS);
        for f in &o.pkts[1..] {
            nat.packet_from_pod(f, FRAG_MS);
        }
        assert!(nat.take_events().is_empty());
    }

    #[test]
    fn window_scale_negotiated() {
        let mut nat = Nat::new(1500);
        let mut o = Out::default();
        // MSS 1460, NOP, window scale 7.
        tcp_pkt(&mut o, POD, PP, DST, 80, 1000, 0, SYN, &[2, 4, 5, 0xb4, 1, 3, 3, 7], &[]);
        nat.packet_from_pod(&o.pkts[0], 0);
        let Event::TcpConnect { flow, .. } = nat.take_events()[0].clone() else { panic!() };
        nat.tcp_connected(flow);
        let pk = nat.take_packets();
        let (ip, _) = parse(&pk[0]);
        let opts = &ip.payload[20..(ip.payload[12] >> 4) as usize * 4];
        assert!(opts.windows(4).any(|w| w == [1, 3, 3, RCV_SHIFT]), "{opts:?}");
        let isn = u32::from_be_bytes(ip.payload[4..8].try_into().unwrap());
        // ACK with window 100 << 7 = 12800 bytes.
        let mut o = Out::default();
        tcp_pkt(&mut o, POD, PP, DST, 80, 1001, isn.wrapping_add(1), ACK, &[], &[]);
        let mut a = o.pkts.pop().unwrap();
        a[34..36].copy_from_slice(&100u16.to_be_bytes());
        a[36] = 0;
        a[37] = 0;
        let c = l4_sum(POD, DST, 6, &a[20..]);
        a[36..38].copy_from_slice(&c.to_be_bytes());
        nat.packet_from_pod(&a, 1);
        nat.take_packets();
        nat.tcp_host_data(flow, &[9u8; 40000]);
        let sent: usize = nat.take_packets().iter().map(|p| parse(p).0.payload.len() - 20).sum();
        assert_eq!(sent, 12800 / 1460 * 1460 + if 12800 % 1460 > 0 { 12800 % 1460 } else { 0 });
        assert_eq!(nat.pending_to_pod(flow), 40000);
    }

    #[test]
    fn no_window_scale_unless_offered() {
        let mut nat = Nat::new(1500);
        nat.packet_from_pod(&pod_tcp(1000, 0, SYN, 1000, Some(1460), &[]), 0);
        let Event::TcpConnect { flow, .. } = nat.take_events()[0].clone() else { panic!() };
        nat.tcp_connected(flow);
        let pk = nat.take_packets();
        let (ip, _) = parse(&pk[0]);
        assert_eq!((ip.payload[12] >> 4) as usize * 4, 24);
    }

    #[test]
    fn bad_checksums_dropped() {
        let mut nat = Nat::new(1500);
        let good = pod_tcp(1, 0, SYN, 100, None, &[]);
        let mut bad_ip = good.clone();
        bad_ip[8] ^= 1; // TTL changed, header checksum stale
        nat.packet_from_pod(&bad_ip, 0);
        let mut bad_tcp = good.clone();
        let n = bad_tcp.len();
        bad_tcp[n - 1] ^= 0x55;
        nat.packet_from_pod(&bad_tcp, 0);
        let mut bad_udp = pod_udp(b"x");
        let n = bad_udp.len();
        bad_udp[n - 1] ^= 1;
        nat.packet_from_pod(&bad_udp, 0);
        let mut frag = good.clone();
        frag[6] = 0x20; // MF
        frag[10] = 0;
        frag[11] = 0;
        let c = !fold(sum(&frag[..20], 0));
        frag[10..12].copy_from_slice(&c.to_be_bytes());
        nat.packet_from_pod(&frag, 0);
        assert!(nat.take_events().is_empty());
        assert!(nat.take_packets().is_empty());
        nat.packet_from_pod(&good, 0);
        assert_eq!(nat.take_events().len(), 1);
    }

    #[test]
    fn emitted_checksums_verify() {
        let mut h = handshake(65535);
        h.nat.tcp_host_data(h.id, &alloc::vec![9u8; 3001]);
        h.nat.tcp_host_eof(h.id);
        h.nat.packet_from_pod(&pod_udp(b"odd"), 0);
        let Event::UdpSend { flow, .. } = h.nat.take_events()[0].clone() else { panic!() };
        h.nat.udp_from_host(flow, b"abc");
        let pk = h.nat.take_packets();
        assert!(pk.len() >= 5);
        for p in &pk {
            assert_eq!(fold(sum(&p[..20], 0)), 0xffff);
            assert_eq!(p[0], 0x45);
            assert_eq!(p[8], 64);
            assert_eq!(p[6] & 0x40, 0x40);
            assert_eq!(u16::from_be_bytes([p[2], p[3]]) as usize, p.len());
            assert_eq!(l4_sum([p[12], p[13], p[14], p[15]], [p[16], p[17], p[18], p[19]], p[9], &p[20..]), 0);
        }
    }
}
