//! Chunked transfer coding (RFC 9112 7.1): an incremental decoder and an encoder.
//!
//! Strict: framing lines need CRLF, chunk sizes are 1-16 hex digits, extensions are skipped but
//! bounded and must not contain control characters, trailers are validated and discarded.

use crate::{Error, Result};
use alloc::vec::Vec;

const MAX_EXT: usize = 1024;
const MAX_TRAILER_LINE: usize = 8 * 1024;
const MAX_TRAILER_TOTAL: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Size,
    Ext,
    SizeLf,
    Data,
    DataCr,
    DataLf,
    TrailerStart,
    TrailerLine,
    TrailerLf,
    EndLf,
    Done,
}

#[derive(Clone, Debug)]
pub struct ChunkedDecoder {
    state: State,
    size: u64,
    digits: u8,
    remaining: u64,
    ext_len: usize,
    line_len: usize,
    trailer_total: usize,
}

impl Default for ChunkedDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkedDecoder {
    pub const fn new() -> Self {
        ChunkedDecoder { state: State::Size, size: 0, digits: 0, remaining: 0, ext_len: 0, line_len: 0, trailer_total: 0 }
    }

    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    /// Decodes from `input` into `out` (which must be non-empty). Returns
    /// `(bytes_consumed, bytes_produced)`; stops early when `out` is full or the message ends.
    pub fn decode(&mut self, input: &[u8], out: &mut [u8]) -> Result<(usize, usize)> {
        let (mut i, mut o) = (0usize, 0usize);
        while i < input.len() && self.state != State::Done {
            if self.state == State::Data {
                if o == out.len() {
                    break;
                }
                let n = (self.remaining.min(usize::MAX as u64) as usize).min(input.len() - i).min(out.len() - o);
                out[o..o + n].copy_from_slice(&input[i..i + n]);
                i += n;
                o += n;
                self.remaining -= n as u64;
                if self.remaining == 0 {
                    self.state = State::DataCr;
                }
                continue;
            }
            let b = input[i];
            i += 1;
            match self.state {
                State::Size => match b {
                    b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => {
                        self.digits += 1;
                        if self.digits > 16 {
                            return Err(Error::Parse("chunk size too long"));
                        }
                        let d = (b as char).to_digit(16).unwrap_or(0) as u64;
                        self.size = self.size.checked_mul(16).and_then(|s| s.checked_add(d)).ok_or(Error::Parse("chunk size overflow"))?;
                    }
                    b';' if self.digits > 0 => {
                        self.state = State::Ext;
                        self.ext_len = 0;
                    }
                    b'\r' if self.digits > 0 => self.state = State::SizeLf,
                    _ => return Err(Error::Parse("bad chunk size line")),
                },
                State::Ext => match b {
                    b'\r' => self.state = State::SizeLf,
                    0x00..=0x1f | 0x7f => return Err(Error::Parse("control character in chunk extension")),
                    _ => {
                        self.ext_len += 1;
                        if self.ext_len > MAX_EXT {
                            return Err(Error::TooLarge("chunk extension"));
                        }
                    }
                },
                State::SizeLf => {
                    if b != b'\n' {
                        return Err(Error::Parse("bad chunk size line"));
                    }
                    if self.size == 0 {
                        self.state = State::TrailerStart;
                    } else {
                        self.remaining = self.size;
                        self.state = State::Data;
                    }
                }
                State::DataCr => {
                    if b != b'\r' {
                        return Err(Error::Parse("missing CRLF after chunk data"));
                    }
                    self.state = State::DataLf;
                }
                State::DataLf => {
                    if b != b'\n' {
                        return Err(Error::Parse("missing CRLF after chunk data"));
                    }
                    self.size = 0;
                    self.digits = 0;
                    self.state = State::Size;
                }
                State::TrailerStart => match b {
                    b'\r' => self.state = State::EndLf,
                    b' ' | b'\t' => return Err(Error::Parse("obs-fold in trailer")),
                    _ => {
                        self.line_len = 0;
                        self.trailer_byte(b)?;
                        self.state = State::TrailerLine;
                    }
                },
                State::TrailerLine => match b {
                    b'\r' => self.state = State::TrailerLf,
                    _ => self.trailer_byte(b)?,
                },
                State::TrailerLf => {
                    if b != b'\n' {
                        return Err(Error::Parse("bare CR in trailer"));
                    }
                    self.state = State::TrailerStart;
                }
                State::EndLf => {
                    if b != b'\n' {
                        return Err(Error::Parse("bad end of chunked body"));
                    }
                    self.state = State::Done;
                }
                State::Data | State::Done => unreachable!(),
            }
        }
        Ok((i, o))
    }

    fn trailer_byte(&mut self, b: u8) -> Result<()> {
        if (b < 0x20 && b != b'\t') || b == 0x7f {
            return Err(Error::Parse("control character in trailer"));
        }
        self.line_len += 1;
        self.trailer_total += 1;
        if self.line_len > MAX_TRAILER_LINE || self.trailer_total > MAX_TRAILER_TOTAL {
            return Err(Error::TooLarge("trailer"));
        }
        Ok(())
    }
}

/// Appends one chunk (`hex-size CRLF data CRLF`). Empty data is skipped: a zero-size chunk
/// would terminate the body, use [`encode_end`] for that.
pub fn encode_chunk(out: &mut Vec<u8>, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let mut hex = [0u8; 16];
    let mut n = data.len();
    let mut i = hex.len();
    while n > 0 {
        i -= 1;
        hex[i] = b"0123456789abcdef"[n & 15];
        n >>= 4;
    }
    out.extend_from_slice(&hex[i..]);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
}

/// Appends the terminating `0 CRLF CRLF` (no trailers).
pub fn encode_end(out: &mut Vec<u8>) {
    out.extend_from_slice(b"0\r\n\r\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    /// Feeds `input` split into pieces of `step` bytes through a small output buffer.
    fn run(input: &[u8], step: usize, outsz: usize) -> Result<(Vec<u8>, bool, usize)> {
        let mut d = ChunkedDecoder::new();
        let mut body = Vec::new();
        let mut consumed_total = 0;
        let mut pos = 0;
        let mut out = vec![0u8; outsz];
        while pos < input.len() && !d.is_done() {
            let end = (pos + step).min(input.len());
            let mut piece = &input[pos..end];
            loop {
                let (c, p) = d.decode(piece, &mut out)?;
                body.extend_from_slice(&out[..p]);
                consumed_total += c;
                piece = &piece[c..];
                if piece.is_empty() || d.is_done() {
                    break;
                }
            }
            pos = end;
        }
        Ok((body, d.is_done(), consumed_total))
    }

    #[test]
    fn simple_and_split_everywhere() {
        let msg = b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\n\r\n";
        for step in 1..=msg.len() {
            for outsz in [1, 3, 64] {
                let (b, done, used) = run(msg, step, outsz).unwrap();
                assert_eq!(b, b"hello world", "step {step} out {outsz}");
                assert!(done);
                assert_eq!(used, msg.len());
            }
        }
    }

    #[test]
    fn leaves_pipelined_bytes() {
        let msg = b"1\r\na\r\n0\r\n\r\nHTTP/1.1 200";
        let (_, done, used) = run(msg, msg.len(), 16).unwrap();
        assert!(done);
        assert_eq!(&msg[used..], b"HTTP/1.1 200");
    }

    #[test]
    fn hex_case_and_extensions() {
        let (b, done, _) = run(b"A\r\n0123456789\r\n0;a=b;c\r\n\r\n", 100, 64).unwrap();
        assert_eq!(b, b"0123456789");
        assert!(done);
        let (b, _, _) = run(b"a\r\n0123456789\r\n00\r\n\r\n", 100, 64).unwrap();
        assert_eq!(b.len(), 10);
    }

    #[test]
    fn trailers_ignored() {
        let (b, done, used) = run(b"3\r\nabc\r\n0\r\nX-Sum: 1\r\nY: 2\r\n\r\n", 100, 64).unwrap();
        assert_eq!(b, b"abc");
        assert!(done);
        assert_eq!(used, 29);
    }

    #[test]
    fn rejects_malformed() {
        let bad: &[&[u8]] = &[
            b"\r\n",                         // empty size
            b"g\r\n",                        // non-hex
            b" 5\r\nhello\r\n0\r\n\r\n",     // leading space
            b"5 \r\nhello\r\n0\r\n\r\n",     // BWS before CRLF
            b"5 ;x\r\nhello\r\n0\r\n\r\n",   // whitespace before ext
            b"5\nhello\r\n0\r\n\r\n",        // bare LF
            b"5\rhello\r\n",                 // bare CR
            b"5\r\nhello\n0\r\n\r\n",        // data not followed by CRLF
            b"5\r\nhelloXX0\r\n\r\n",        // data longer than declared
            b"5\r\nhello\r0\r\n\r\n",
            b"+5\r\nhello\r\n",              // sign
            b"0x5\r\nhello\r\n",
            b"10000000000000000\r\n",        // 17 digits
            b"FFFFFFFFFFFFFFFFF\r\n",
            b"5;a\x01\r\nhello\r\n",         // control in extension
            b"0\r\n\r",                      // truncated is fine, covered below
        ];
        for (i, m) in bad.iter().enumerate() {
            let r = run(m, m.len(), 64);
            if i == bad.len() - 1 {
                assert!(matches!(r, Ok((_, false, _))));
            } else {
                assert!(r.is_err(), "case {i}: {:?}", core::str::from_utf8(m));
            }
        }
        // trailer problems
        assert!(run(b"0\r\n a: b\r\n\r\n", 100, 8).is_err());
        assert!(run(b"0\r\na: b\n\r\n", 100, 8).is_err());
        assert!(run(b"0\r\na: b\rc\r\n\r\n", 100, 8).is_err());
        assert!(run(b"0\r\n\r\r\n", 100, 8).is_err());
    }

    #[test]
    fn max_u64_sized_chunk_does_not_overflow() {
        // 16 hex digits fit in u64; the decoder just waits for data.
        let (b, done, _) = run(b"FFFFFFFFFFFFFFFF\r\nabc", 100, 8).unwrap();
        assert_eq!(b, b"abc");
        assert!(!done);
    }

    #[test]
    fn size_limits() {
        let mut m = std::vec::Vec::from(&b"5;"[..]);
        m.extend(core::iter::repeat_n(b'x', 2000));
        m.extend_from_slice(b"\r\n");
        assert_eq!(run(&m, m.len(), 8).unwrap_err(), Error::TooLarge("chunk extension"));
        let mut t = std::vec::Vec::from(&b"0\r\nX: "[..]);
        t.extend(core::iter::repeat_n(b'y', 9000));
        assert_eq!(run(&t, t.len(), 8).unwrap_err(), Error::TooLarge("trailer"));
    }

    #[test]
    fn encode_roundtrip() {
        let mut v = Vec::new();
        encode_chunk(&mut v, b"");
        encode_chunk(&mut v, b"hello");
        encode_chunk(&mut v, &[7u8; 300]);
        encode_end(&mut v);
        assert!(v.starts_with(b"5\r\nhello\r\n12c\r\n"));
        assert!(v.ends_with(b"\r\n0\r\n\r\n"));
        let (b, done, used) = run(&v, v.len(), 1024).unwrap();
        assert!(done);
        assert_eq!(used, v.len());
        assert_eq!(b.len(), 305);
    }
}
