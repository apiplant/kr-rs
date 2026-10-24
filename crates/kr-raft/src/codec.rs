//! Binary encoding of Raft messages, entries, hard state and snapshot metadata, used by the
//! server-to-server transport and the on-disk log. Little-endian fixed-width integers; byte
//! strings are length-prefixed. Decoding is bounds-checked and rejects trailing bytes. Node id
//! 0 is reserved (it encodes "no vote").

use crate::{Entry, EntryKind, HardState, Message, MsgBody, NodeId, Snapshot, SnapshotMeta};
use alloc::rc::Rc;
use alloc::vec::Vec;

/// Upper bound on any length field (entries, snapshot data), against hostile peers.
pub const MAX_LEN: u64 = 1 << 30;

struct W<'a>(&'a mut Vec<u8>);

impl W<'_> {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.u64(b.len() as u64);
        self.0.extend_from_slice(b);
    }
}

struct R<'a> {
    b: &'a [u8],
}

impl<'a> R<'a> {
    fn u8(&mut self) -> Option<u8> {
        let (&v, rest) = self.b.split_first()?;
        self.b = rest;
        Some(v)
    }
    fn u64(&mut self) -> Option<u64> {
        if self.b.len() < 8 {
            return None;
        }
        let (h, rest) = self.b.split_at(8);
        self.b = rest;
        Some(u64::from_le_bytes(h.try_into().ok()?))
    }
    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u64()?;
        if n > MAX_LEN || n as usize > self.b.len() {
            return None;
        }
        let (h, rest) = self.b.split_at(n as usize);
        self.b = rest;
        Some(h)
    }
    fn done(&self) -> Option<()> {
        self.b.is_empty().then_some(())
    }
}

pub fn encode_entry(out: &mut Vec<u8>, e: &Entry) {
    let mut w = W(out);
    w.u64(e.term);
    w.u64(e.index);
    match e.kind {
        EntryKind::Normal => w.u8(0),
        EntryKind::Noop => w.u8(1),
        EntryKind::AddVoter(id) => {
            w.u8(2);
            w.u64(id);
        }
        EntryKind::RemoveVoter(id) => {
            w.u8(3);
            w.u64(id);
        }
    }
    w.bytes(&e.data);
}

fn read_entry(r: &mut R) -> Option<Entry> {
    let term = r.u64()?;
    let index = r.u64()?;
    let kind = match r.u8()? {
        0 => EntryKind::Normal,
        1 => EntryKind::Noop,
        2 => EntryKind::AddVoter(r.u64().filter(|id| *id != 0)?),
        3 => EntryKind::RemoveVoter(r.u64().filter(|id| *id != 0)?),
        _ => return None,
    };
    let data = r.bytes()?.to_vec();
    Some(Entry { term, index, kind, data })
}

pub fn decode_entry(b: &[u8]) -> Option<Entry> {
    let mut r = R { b };
    let e = read_entry(&mut r)?;
    r.done()?;
    Some(e)
}

pub fn encode_hard_state(hs: &HardState) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    let mut w = W(&mut out);
    w.u64(hs.term);
    w.u64(hs.vote.unwrap_or(0));
    w.u64(hs.commit);
    out
}

pub fn decode_hard_state(b: &[u8]) -> Option<HardState> {
    let mut r = R { b };
    let term = r.u64()?;
    let vote = r.u64()?;
    let commit = r.u64()?;
    r.done()?;
    Some(HardState { term, vote: (vote != 0).then_some(vote), commit })
}

fn write_meta(w: &mut W, m: &SnapshotMeta) {
    w.u64(m.index);
    w.u64(m.term);
    w.u64(m.voters.len() as u64);
    for v in &m.voters {
        w.u64(*v);
    }
}

fn read_meta(r: &mut R) -> Option<SnapshotMeta> {
    let index = r.u64()?;
    let term = r.u64()?;
    let n = r.u64()?;
    if n > 1024 {
        return None;
    }
    let mut voters = Vec::with_capacity(n as usize);
    for _ in 0..n {
        voters.push(r.u64().filter(|id| *id != 0)?);
    }
    Some(SnapshotMeta { index, term, voters })
}

pub fn encode_snapshot_meta(m: &SnapshotMeta) -> Vec<u8> {
    let mut out = Vec::new();
    write_meta(&mut W(&mut out), m);
    out
}

pub fn decode_snapshot_meta(b: &[u8]) -> Option<SnapshotMeta> {
    let mut r = R { b };
    let m = read_meta(&mut r)?;
    r.done()?;
    Some(m)
}

pub fn encode_message(m: &Message) -> Vec<u8> {
    let mut out = Vec::new();
    let mut w = W(&mut out);
    w.u64(m.from);
    w.u64(m.to);
    w.u64(m.term);
    match &m.body {
        MsgBody::PreVote { last_index, last_term } => {
            w.u8(1);
            w.u64(*last_index);
            w.u64(*last_term);
        }
        MsgBody::PreVoteResp { granted } => {
            w.u8(2);
            w.u8(*granted as u8);
        }
        MsgBody::Vote { last_index, last_term, transfer } => {
            w.u8(3);
            w.u64(*last_index);
            w.u64(*last_term);
            w.u8(*transfer as u8);
        }
        MsgBody::VoteResp { granted } => {
            w.u8(4);
            w.u8(*granted as u8);
        }
        MsgBody::Append { prev_index, prev_term, entries, commit } => {
            w.u8(5);
            w.u64(*prev_index);
            w.u64(*prev_term);
            w.u64(*commit);
            w.u64(entries.len() as u64);
            for e in entries {
                encode_entry(w.0, e);
            }
        }
        MsgBody::AppendResp { success, index } => {
            w.u8(6);
            w.u8(*success as u8);
            w.u64(*index);
        }
        MsgBody::InstallSnapshot { snapshot } => {
            w.u8(7);
            write_meta(&mut w, &snapshot.meta);
            w.bytes(&snapshot.data);
        }
        MsgBody::TimeoutNow => w.u8(8),
    }
    out
}

fn bool8(r: &mut R) -> Option<bool> {
    match r.u8()? {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

pub fn decode_message(b: &[u8]) -> Option<Message> {
    let mut r = R { b };
    let from: NodeId = r.u64().filter(|id| *id != 0)?;
    let to: NodeId = r.u64().filter(|id| *id != 0)?;
    let term = r.u64()?;
    let body = match r.u8()? {
        1 => MsgBody::PreVote { last_index: r.u64()?, last_term: r.u64()? },
        2 => MsgBody::PreVoteResp { granted: bool8(&mut r)? },
        3 => MsgBody::Vote { last_index: r.u64()?, last_term: r.u64()?, transfer: bool8(&mut r)? },
        4 => MsgBody::VoteResp { granted: bool8(&mut r)? },
        5 => {
            let prev_index = r.u64()?;
            let prev_term = r.u64()?;
            let commit = r.u64()?;
            let n = r.u64()?;
            if n > 1 << 16 {
                return None;
            }
            let mut entries = Vec::with_capacity(n as usize);
            for i in 0..n {
                let e = read_entry(&mut r)?;
                // Entries must be the contiguous run after prev_index.
                if e.index != prev_index + 1 + i {
                    return None;
                }
                entries.push(e);
            }
            MsgBody::Append { prev_index, prev_term, entries, commit }
        }
        6 => MsgBody::AppendResp { success: bool8(&mut r)?, index: r.u64()? },
        7 => {
            let meta = read_meta(&mut r)?;
            let data: Rc<[u8]> = Rc::from(r.bytes()?);
            MsgBody::InstallSnapshot { snapshot: Snapshot { meta, data } }
        }
        8 => MsgBody::TimeoutNow,
        _ => return None,
    };
    r.done()?;
    Some(Message { from, to, term, body })
}
