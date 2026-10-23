//! RFC 4648 base64 (standard and URL-safe) with strict decoding: no
//! whitespace, exact padding rules, and non-canonical trailing bits rejected.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// Which alphabet to use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alphabet {
    /// `+` and `/`
    Standard,
    /// `-` and `_`
    UrlSafe,
}

/// Padding policy. Decoding is strict in both modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Padding {
    /// Output is padded with `=`; input must be padded.
    Required,
    /// Output is not padded; input must not contain `=`.
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidByte,
    InvalidLength,
    InvalidPadding,
    /// The unused trailing bits of the last symbol are not zero.
    NonCanonical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub offset: usize,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = match self.kind {
            ErrorKind::InvalidByte => "invalid byte",
            ErrorKind::InvalidLength => "invalid length",
            ErrorKind::InvalidPadding => "invalid padding",
            ErrorKind::NonCanonical => "non-canonical trailing bits",
        };
        write!(f, "base64: {} at byte {}", m, self.offset)
    }
}

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn table(a: Alphabet) -> &'static [u8; 64] {
    match a {
        Alphabet::Standard => STD,
        Alphabet::UrlSafe => URL,
    }
}

pub fn encode(data: &[u8]) -> String {
    encode_config(data, Alphabet::Standard, Padding::Required)
}
pub fn encode_url(data: &[u8]) -> String {
    encode_config(data, Alphabet::UrlSafe, Padding::None)
}
pub fn decode(s: &str) -> Result<Vec<u8>, Error> {
    decode_config(s.as_bytes(), Alphabet::Standard, Padding::Required)
}
pub fn decode_url(s: &str) -> Result<Vec<u8>, Error> {
    decode_config(s.as_bytes(), Alphabet::UrlSafe, Padding::None)
}

pub fn encode_config(data: &[u8], alpha: Alphabet, pad: Padding) -> String {
    let t = table(alpha);
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        out.push(t[(n >> 18) as usize & 63] as char);
        out.push(t[(n >> 12) as usize & 63] as char);
        if c.len() > 1 {
            out.push(t[(n >> 6) as usize & 63] as char);
        } else if pad == Padding::Required {
            out.push('=');
        }
        if c.len() > 2 {
            out.push(t[n as usize & 63] as char);
        } else if pad == Padding::Required {
            out.push('=');
        }
    }
    out
}

fn val(alpha: Alphabet, b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' if alpha == Alphabet::Standard => Some(62),
        b'/' if alpha == Alphabet::Standard => Some(63),
        b'-' if alpha == Alphabet::UrlSafe => Some(62),
        b'_' if alpha == Alphabet::UrlSafe => Some(63),
        _ => None,
    }
}

pub fn decode_config(s: &[u8], alpha: Alphabet, pad: Padding) -> Result<Vec<u8>, Error> {
    let err = |kind, offset| Err(Error { kind, offset });
    let mut body = s.len();
    while body > 0 && s[body - 1] == b'=' {
        body -= 1;
    }
    let pads = s.len() - body;
    match pad {
        Padding::Required => {
            if !s.len().is_multiple_of(4) {
                return err(ErrorKind::InvalidLength, s.len());
            }
            let rem = body % 4;
            let ok = matches!((rem, pads), (0, 0) | (2, 2) | (3, 1));
            if !ok {
                // rem == 1 can never be valid; otherwise the padding count is wrong.
                return if rem == 1 {
                    err(ErrorKind::InvalidLength, body)
                } else {
                    err(ErrorKind::InvalidPadding, body)
                };
            }
        }
        Padding::None => {
            if pads > 0 {
                return err(ErrorKind::InvalidPadding, body);
            }
            if body % 4 == 1 {
                return err(ErrorKind::InvalidLength, body);
            }
        }
    }
    let mut out = Vec::with_capacity(body / 4 * 3 + 2);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for (i, &b) in s[..body].iter().enumerate() {
        let Some(v) = val(alpha, b) else {
            return err(ErrorKind::InvalidByte, i);
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if acc != 0 {
        return err(ErrorKind::NonCanonical, body - 1);
    }
    Ok(out)
}
