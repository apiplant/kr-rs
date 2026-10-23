//! Protobuf wire format: varints, zigzag, tags, a field `Reader` and a `Writer`.
//!
//! Groups (wire types 3/4) are rejected; Kubernetes protobuf never uses them.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// Input ended inside a varint, fixed value or length-delimited payload.
    Truncated,
    /// Varint longer than 10 bytes or overflowing 64 bits.
    VarintOverflow,
    /// Field number 0 or above 2^29-1.
    InvalidFieldNumber,
    /// Wire types 3, 4, 6, 7.
    InvalidWireType,
    /// Length prefix above the configured limit.
    LengthLimit,
    /// String field is not UTF-8.
    InvalidUtf8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub offset: usize,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = match self.kind {
            ErrorKind::Truncated => "truncated input",
            ErrorKind::VarintOverflow => "varint overflow",
            ErrorKind::InvalidFieldNumber => "invalid field number",
            ErrorKind::InvalidWireType => "invalid or unsupported wire type",
            ErrorKind::LengthLimit => "length exceeds limit",
            ErrorKind::InvalidUtf8 => "invalid UTF-8",
        };
        write!(f, "proto: {} at byte {}", m, self.offset)
    }
}

fn err<T>(kind: ErrorKind, offset: usize) -> Result<T, Error> {
    Err(Error { kind, offset })
}

/// Maximum field number.
pub const MAX_FIELD: u32 = (1 << 29) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireType {
    Varint = 0,
    Fixed64 = 1,
    Len = 2,
    Fixed32 = 5,
}

impl WireType {
    pub fn from_u8(v: u8) -> Option<WireType> {
        match v {
            0 => Some(WireType::Varint),
            1 => Some(WireType::Fixed64),
            2 => Some(WireType::Len),
            5 => Some(WireType::Fixed32),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------- varint/zigzag

pub fn encode_varint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Encoded size of a varint.
pub fn varint_len(v: u64) -> usize {
    (64 - (v | 1).leading_zeros() as usize).div_ceil(7)
}

/// Decode a varint; returns (value, bytes consumed). Non-minimal encodings
/// (e.g. `0x80 0x00`) are accepted, like the reference implementations.
pub fn decode_varint(buf: &[u8]) -> Result<(u64, usize), Error> {
    let mut v = 0u64;
    for (i, &b) in buf.iter().enumerate() {
        if i == 9 && b > 1 {
            return err(ErrorKind::VarintOverflow, i);
        }
        v |= u64::from(b & 0x7f) << (7 * i as u32);
        if b & 0x80 == 0 {
            return Ok((v, i + 1));
        }
        if i == 9 {
            return err(ErrorKind::VarintOverflow, i);
        }
    }
    err(ErrorKind::Truncated, buf.len())
}

pub fn zigzag_encode32(v: i32) -> u32 {
    ((v << 1) ^ (v >> 31)) as u32
}
pub fn zigzag_decode32(v: u32) -> i32 {
    ((v >> 1) as i32) ^ -((v & 1) as i32)
}
pub fn zigzag_encode64(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}
pub fn zigzag_decode64(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

// ---------------------------------------------------------------- tags

pub fn make_tag(field: u32, wt: WireType) -> u64 {
    (u64::from(field) << 3) | wt as u64
}

/// Split a tag into field number and wire type.
pub fn split_tag(tag: u64) -> Result<(u32, WireType), ErrorKind> {
    let field = tag >> 3;
    if field == 0 || field > u64::from(MAX_FIELD) {
        return Err(ErrorKind::InvalidFieldNumber);
    }
    match WireType::from_u8((tag & 7) as u8) {
        Some(w) => Ok((field as u32, w)),
        None => Err(ErrorKind::InvalidWireType),
    }
}

/// Decode a packed repeated varint payload.
pub fn packed_varints(mut buf: &[u8]) -> Result<Vec<u64>, Error> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        let (v, n) = decode_varint(buf)?;
        out.push(v);
        buf = &buf[n..];
    }
    Ok(out)
}

// ---------------------------------------------------------------- reader

/// A decoded field value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value<'a> {
    Varint(u64),
    Fixed64(u64),
    Fixed32(u32),
    Bytes(&'a [u8]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field<'a> {
    pub number: u32,
    pub value: Value<'a>,
}

impl<'a> Field<'a> {
    pub fn as_varint(&self) -> Option<u64> {
        if let Value::Varint(v) = self.value { Some(v) } else { None }
    }
    pub fn as_bytes(&self) -> Option<&'a [u8]> {
        if let Value::Bytes(b) = self.value { Some(b) } else { None }
    }
    /// Length-delimited payload as UTF-8.
    pub fn as_str(&self) -> Option<&'a str> {
        self.as_bytes().and_then(|b| core::str::from_utf8(b).ok())
    }
    pub fn as_sint64(&self) -> Option<i64> {
        self.as_varint().map(zigzag_decode64)
    }
    pub fn as_bool(&self) -> Option<bool> {
        self.as_varint().map(|v| v != 0)
    }
}

/// Reader limits.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum accepted length-delimited payload (default 64 MiB).
    pub max_len: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_len: 64 << 20 }
    }
}

/// Iterates the fields of one message.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    limits: Limits,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self::with_limits(buf, Limits::default())
    }
    pub fn with_limits(buf: &'a [u8], limits: Limits) -> Self {
        Reader { buf, pos: 0, limits }
    }
    pub fn offset(&self) -> usize {
        self.pos
    }
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn varint(&mut self) -> Result<u64, Error> {
        match decode_varint(&self.buf[self.pos..]) {
            Ok((v, n)) => {
                self.pos += n;
                Ok(v)
            }
            Err(e) => err(e.kind, self.pos + e.offset),
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.buf.len() - self.pos < n {
            return err(ErrorKind::Truncated, self.buf.len());
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Next field, or `Ok(None)` at the end of the message.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Field<'a>>, Error> {
        if self.is_empty() {
            return Ok(None);
        }
        let at = self.pos;
        let tag = self.varint()?;
        let (number, wt) = match split_tag(tag) {
            Ok(x) => x,
            Err(k) => return err(k, at),
        };
        let value = match wt {
            WireType::Varint => Value::Varint(self.varint()?),
            WireType::Fixed64 => {
                let b = self.take(8)?;
                Value::Fixed64(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
            }
            WireType::Fixed32 => {
                let b = self.take(4)?;
                Value::Fixed32(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            }
            WireType::Len => {
                let at = self.pos;
                let len = self.varint()?;
                if len > self.limits.max_len as u64 {
                    return err(ErrorKind::LengthLimit, at);
                }
                Value::Bytes(self.take(len as usize)?)
            }
        };
        Ok(Some(Field { number, value }))
    }
}

// ---------------------------------------------------------------- writer

/// Builds a message.
#[derive(Default, Debug, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    fn tag(&mut self, field: u32, wt: WireType) {
        debug_assert!((1..=MAX_FIELD).contains(&field));
        encode_varint(make_tag(field, wt), &mut self.buf);
    }

    pub fn varint(&mut self, field: u32, v: u64) -> &mut Self {
        self.tag(field, WireType::Varint);
        encode_varint(v, &mut self.buf);
        self
    }
    /// `int32`/`int64`: negative values take 10 bytes (sign-extended).
    pub fn int64(&mut self, field: u32, v: i64) -> &mut Self {
        self.varint(field, v as u64)
    }
    pub fn sint64(&mut self, field: u32, v: i64) -> &mut Self {
        self.varint(field, zigzag_encode64(v))
    }
    pub fn sint32(&mut self, field: u32, v: i32) -> &mut Self {
        self.varint(field, u64::from(zigzag_encode32(v)))
    }
    pub fn bool(&mut self, field: u32, v: bool) -> &mut Self {
        self.varint(field, u64::from(v))
    }
    pub fn fixed32(&mut self, field: u32, v: u32) -> &mut Self {
        self.tag(field, WireType::Fixed32);
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn fixed64(&mut self, field: u32, v: u64) -> &mut Self {
        self.tag(field, WireType::Fixed64);
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn bytes(&mut self, field: u32, v: &[u8]) -> &mut Self {
        self.tag(field, WireType::Len);
        encode_varint(v.len() as u64, &mut self.buf);
        self.buf.extend_from_slice(v);
        self
    }
    pub fn string(&mut self, field: u32, v: &str) -> &mut Self {
        self.bytes(field, v.as_bytes())
    }
    /// Embedded message built by `f`.
    pub fn message(&mut self, field: u32, f: impl FnOnce(&mut Writer)) -> &mut Self {
        let mut inner = Writer::new();
        f(&mut inner);
        self.bytes(field, &inner.buf)
    }
    /// Packed repeated varints.
    pub fn packed_varints(&mut self, field: u32, vs: &[u64]) -> &mut Self {
        let mut inner = Vec::new();
        for &v in vs {
            encode_varint(v, &mut inner);
        }
        self.bytes(field, &inner)
    }
}

/// Read a string field, mapping UTF-8 failure to an [`Error`].
pub fn utf8_field(f: &Field<'_>, offset: usize) -> Result<String, Error> {
    match f.as_str() {
        Some(s) => Ok(String::from(s)),
        None => err(ErrorKind::InvalidUtf8, offset),
    }
}
