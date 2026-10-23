//! Strict ASN.1 DER reader and a small writer (enough for X.509 and PKCS#8/SEC1 keys).
//!
//! The reader accepts only DER: single-byte tags (no high-tag-number form), definite minimal
//! lengths, at most 4 length bytes, and it never reads past its input. Every accessor checks
//! the expected tag, so malformed input yields `Err(Error)` rather than misinterpretation.

use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error;

pub type Result<T> = core::result::Result<T, Error>;

pub const BOOLEAN: u8 = 0x01;
pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const NULL: u8 = 0x05;
pub const OID: u8 = 0x06;
pub const UTF8_STRING: u8 = 0x0c;
pub const PRINTABLE_STRING: u8 = 0x13;
pub const IA5_STRING: u8 = 0x16;
pub const UTC_TIME: u8 = 0x17;
pub const GENERALIZED_TIME: u8 = 0x18;
pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;

/// Context-specific tag `[n]`, constructed.
pub const fn ctx(n: u8) -> u8 {
    0xa0 | n
}

/// Context-specific tag `[n]`, primitive (IMPLICIT, e.g. SAN dNSName = [2]).
pub const fn ctx_prim(n: u8) -> u8 {
    0x80 | n
}

/// A cursor over DER bytes.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn peek_tag(&self) -> Option<u8> {
        self.data.first().copied()
    }

    /// Reads one TLV: returns (tag, contents, full encoding).
    pub fn any(&mut self) -> Result<(u8, &'a [u8], &'a [u8])> {
        let d = self.data;
        if d.len() < 2 {
            return Err(Error);
        }
        let tag = d[0];
        if tag & 0x1f == 0x1f {
            return Err(Error); // high-tag-number form: never used by X.509
        }
        let (len, hdr) = match d[1] {
            n if n < 0x80 => (n as usize, 2),
            0x80 => return Err(Error), // indefinite length is BER, not DER
            n => {
                let k = (n & 0x7f) as usize;
                if k > 4 || d.len() < 2 + k || d[2] == 0 {
                    return Err(Error); // too long or leading zero (non-minimal)
                }
                let len = d[2..2 + k].iter().fold(0usize, |a, &b| a << 8 | b as usize);
                if len < 0x80 {
                    return Err(Error); // should have used the short form
                }
                (len, 2 + k)
            }
        };
        let end = hdr.checked_add(len).ok_or(Error)?;
        if d.len() < end {
            return Err(Error);
        }
        self.data = &d[end..];
        Ok((tag, &d[hdr..end], &d[..end]))
    }

    /// Reads a TLV with the given tag and returns its contents.
    pub fn read(&mut self, tag: u8) -> Result<&'a [u8]> {
        let (t, c, _) = self.any()?;
        if t != tag {
            return Err(Error);
        }
        Ok(c)
    }

    /// Like `read` but also returns the complete encoding (e.g. the signed TBSCertificate).
    pub fn read_full(&mut self, tag: u8) -> Result<(&'a [u8], &'a [u8])> {
        let (t, c, full) = self.any()?;
        if t != tag {
            return Err(Error);
        }
        Ok((c, full))
    }

    /// Reads an optional element with `tag`, if it is next.
    pub fn optional(&mut self, tag: u8) -> Result<Option<&'a [u8]>> {
        if self.peek_tag() == Some(tag) {
            self.read(tag).map(Some)
        } else {
            Ok(None)
        }
    }

    pub fn sequence(&mut self) -> Result<Reader<'a>> {
        self.read(SEQUENCE).map(Reader::new)
    }

    /// INTEGER contents, validated as minimal; returns the big-endian bytes (sign byte kept).
    pub fn integer(&mut self) -> Result<&'a [u8]> {
        let v = self.read(INTEGER)?;
        if v.is_empty() || (v.len() > 1 && ((v[0] == 0 && v[1] & 0x80 == 0) || (v[0] == 0xff && v[1] & 0x80 != 0))) {
            return Err(Error);
        }
        Ok(v)
    }

    /// A non-negative INTEGER that fits u64.
    pub fn small_uint(&mut self) -> Result<u64> {
        let v = self.integer()?;
        if v[0] & 0x80 != 0 {
            return Err(Error);
        }
        let v = if v[0] == 0 { &v[1..] } else { v };
        if v.len() > 8 {
            return Err(Error);
        }
        Ok(v.iter().fold(0u64, |a, &b| a << 8 | b as u64))
    }

    /// BIT STRING with no unused bits; returns the bytes.
    pub fn bit_string(&mut self) -> Result<&'a [u8]> {
        let v = self.read(BIT_STRING)?;
        if v.first() != Some(&0) {
            return Err(Error);
        }
        Ok(&v[1..])
    }

    pub fn oid(&mut self) -> Result<&'a [u8]> {
        self.read(OID)
    }

    pub fn boolean(&mut self) -> Result<bool> {
        match self.read(BOOLEAN)? {
            [0x00] => Ok(false),
            [0xff] => Ok(true),
            _ => Err(Error), // DER requires exactly 0x00 / 0xff
        }
    }

    /// Errors unless all input was consumed (no trailing data).
    pub fn finish(&self) -> Result<()> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(Error)
        }
    }
}

// ---- writer ----

fn push_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = (usize::BITS / 8 - len.leading_zeros() / 8) as usize;
        out.push(0x80 | bytes as u8);
        for i in (0..bytes).rev() {
            out.push((len >> (8 * i)) as u8);
        }
    }
}

/// Appends a TLV.
pub fn tlv(out: &mut Vec<u8>, tag: u8, contents: &[u8]) {
    out.push(tag);
    push_len(out, contents.len());
    out.extend_from_slice(contents);
}

/// Builds a TLV whose contents are produced by `f`.
pub fn nested(out: &mut Vec<u8>, tag: u8, f: impl FnOnce(&mut Vec<u8>)) {
    let mut inner = Vec::new();
    f(&mut inner);
    tlv(out, tag, &inner);
}

/// INTEGER from unsigned big-endian bytes (leading zeros stripped, sign byte added).
pub fn uint(out: &mut Vec<u8>, be: &[u8]) {
    let mut i = 0;
    while i + 1 < be.len() && be[i] == 0 {
        i += 1;
    }
    let v = &be[i..];
    let mut c = Vec::with_capacity(v.len() + 1);
    if v.is_empty() || v[0] & 0x80 != 0 {
        c.push(0);
    }
    c.extend_from_slice(v);
    tlv(out, INTEGER, &c);
}

pub fn bit_string(out: &mut Vec<u8>, bytes: &[u8]) {
    let mut c = Vec::with_capacity(bytes.len() + 1);
    c.push(0);
    c.extend_from_slice(bytes);
    tlv(out, BIT_STRING, &c);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_der() {
        assert!(Reader::new(&[0x30, 0x80, 0, 0]).any().is_err()); // indefinite
        assert!(Reader::new(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5]).any().is_err()); // long form for short len
        assert!(Reader::new(&[0x04, 0x82, 0x00, 0x80]).any().is_err()); // leading zero
        assert!(Reader::new(&[0x04, 0x05, 1, 2]).any().is_err()); // truncated
        assert!(Reader::new(&[0x1f, 0x01, 0]).any().is_err()); // high tag
        assert!(Reader::new(&[0x02, 0x02, 0x00, 0x01]).integer().is_err()); // non-minimal int
        assert!(Reader::new(&[0x01, 0x01, 0x01]).boolean().is_err());
    }

    #[test]
    fn roundtrip_lengths() {
        for n in [0usize, 1, 127, 128, 255, 256, 70000] {
            let mut out = Vec::new();
            tlv(&mut out, OCTET_STRING, &alloc::vec![7u8; n]);
            let mut r = Reader::new(&out);
            assert_eq!(r.read(OCTET_STRING).unwrap().len(), n);
            r.finish().unwrap();
        }
        let mut out = Vec::new();
        uint(&mut out, &[0, 0, 0x80]);
        assert_eq!(out, [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(Reader::new(&out).small_uint().unwrap(), 128);
    }
}
