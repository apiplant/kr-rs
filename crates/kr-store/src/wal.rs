//! On-disk record framing shared by the log and the snapshot.
//!
//! ```text
//! record  = [u32 LE payload_len][u32 LE crc32(payload)][payload]
//! payload = op:u8 (1 put, 2 delete) | rev:u64 | create_rev:u64
//!         | key_len:u32 | key | val_len:u32 | val          (all integers little endian)
//! ```
//!
//! For a delete, `rev` is the deletion revision, `create_rev` is the deleted key's creation
//! revision and `val` is empty. In a snapshot, `rev` of a put record is the key's `mod_rev`.
//!
//! The parser distinguishes a *torn* record (the file ends inside it, or its CRC fails and it is the
//! last record in the file: a crash during append) from a *corrupt* one (anything else).
//! Limitation: a bit flip in the length field of a mid-log record that makes it extend past EOF
//! is indistinguishable from a torn tail and is treated as one.
use alloc::vec::Vec;
use kr_archive::crc32::crc32;

pub const OP_PUT: u8 = 1;
pub const OP_DELETE: u8 = 2;
/// Frame header (8) plus fixed payload fields (1 + 8 + 8 + 4 + 4).
pub const RECORD_OVERHEAD: usize = 8 + 25;
pub const MAX_KEY: usize = 4 * 1024;
pub const MAX_VALUE: usize = 3 * 1024 * 1024;
const MAX_PAYLOAD: usize = RECORD_OVERHEAD + MAX_KEY + MAX_VALUE;

pub const SNAP_MAGIC: &[u8; 8] = b"KRSNAP1\0";

pub fn encode(buf: &mut Vec<u8>, op: u8, rev: u64, create_rev: u64, key: &str, val: &[u8]) {
    let plen = 25 + key.len() + val.len();
    buf.reserve(8 + plen);
    buf.extend_from_slice(&(plen as u32).to_le_bytes());
    let crc_at = buf.len();
    buf.extend_from_slice(&[0; 4]);
    let start = buf.len();
    buf.push(op);
    buf.extend_from_slice(&rev.to_le_bytes());
    buf.extend_from_slice(&create_rev.to_le_bytes());
    buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
    buf.extend_from_slice(key.as_bytes());
    buf.extend_from_slice(&(val.len() as u32).to_le_bytes());
    buf.extend_from_slice(val);
    let crc = crc32(&buf[start..]);
    buf[crc_at..crc_at + 4].copy_from_slice(&crc.to_le_bytes());
}

pub struct Record<'a> {
    pub op: u8,
    pub rev: u64,
    pub create_rev: u64,
    pub key: &'a str,
    pub val: &'a [u8],
    /// Offset one past this record.
    pub end: usize,
}

pub enum Parsed<'a> {
    Rec(Record<'a>),
    /// Incomplete or CRC-failing final record: a crash during append.
    Torn,
    Corrupt(&'static str),
}

fn u32_at(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}

fn u64_at(d: &[u8], o: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[o..o + 8]);
    u64::from_le_bytes(b)
}

/// Parses the record starting at `off` (which must be < `data.len()`).
pub fn parse(data: &[u8], off: usize) -> Parsed<'_> {
    if data.len() - off < 8 {
        return Parsed::Torn;
    }
    let plen = u32_at(data, off) as usize;
    let crc = u32_at(data, off + 4);
    let end = match (off + 8).checked_add(plen) {
        Some(e) if e <= data.len() => e,
        _ => return Parsed::Torn,
    };
    let p = &data[off + 8..end];
    if crc32(p) != crc {
        return if end == data.len() { Parsed::Torn } else { Parsed::Corrupt("log record crc mismatch") };
    }
    if plen > MAX_PAYLOAD || plen < 25 {
        return Parsed::Corrupt("record length out of range");
    }
    let op = p[0];
    if op != OP_PUT && op != OP_DELETE {
        return Parsed::Corrupt("unknown record op");
    }
    let rev = u64_at(p, 1);
    let create_rev = u64_at(p, 9);
    let klen = u32_at(p, 17) as usize;
    if klen > MAX_KEY || 21 + klen + 4 > p.len() {
        return Parsed::Corrupt("bad key length");
    }
    let key = match core::str::from_utf8(&p[21..21 + klen]) {
        Ok(k) => k,
        Err(_) => return Parsed::Corrupt("key is not utf-8"),
    };
    let vo = 21 + klen;
    let vlen = u32_at(p, vo) as usize;
    if vo + 4 + vlen != p.len() {
        return Parsed::Corrupt("bad value length");
    }
    Parsed::Rec(Record { op, rev, create_rev, key, val: &p[vo + 4..], end })
}
