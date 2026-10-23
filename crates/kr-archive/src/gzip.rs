//! Streaming RFC 1952 gzip decoder on top of [`Inflater`].
//!
//! Handles FEXTRA/FNAME/FCOMMENT/FHCRC, verifies CRC32 and ISIZE per member,
//! and supports concatenated members. Nothing is buffered beyond the 32 KiB
//! inflate window. Bytes after the last member that are not a gzip magic are
//! rejected ([`Error::TrailingGarbage`]).

use crate::crc32::Crc32;
use crate::inflate::{Inflater, Status};
use crate::Error;

const FHCRC: u8 = 2;
const FEXTRA: u8 = 4;
const FNAME: u8 = 8;
const FCOMMENT: u8 = 16;

#[derive(Clone, Copy, PartialEq, Eq)]
enum St {
    Fixed(u8),
    XLen(u8),
    Extra(u16),
    Name,
    Comment,
    Hcrc(u8),
    Body,
    Trailer(u8),
    /// Between members (or finished).
    End,
    Failed,
}

/// Streaming gzip decoder.
pub struct GzDecoder {
    st: St,
    inf: Inflater,
    crc: Crc32,
    hcrc: Crc32,
    size: u32,
    flags: u8,
    hdr: [u8; 10],
    xlen: [u8; 2],
    trailer: [u8; 8],
    stored_hcrc: [u8; 2],
    members: u32,
}

impl Default for GzDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl GzDecoder {
    pub fn new() -> Self {
        GzDecoder {
            st: St::Fixed(0),
            inf: Inflater::new(),
            crc: Crc32::new(),
            hcrc: Crc32::new(),
            size: 0,
            flags: 0,
            hdr: [0; 10],
            xlen: [0; 2],
            trailer: [0; 8],
            stored_hcrc: [0; 2],
            members: 0,
        }
    }

    /// Number of fully verified members so far.
    pub fn members(&self) -> u32 {
        self.members
    }

    /// Feed compressed bytes of any size; decompressed data goes to `out`.
    pub fn feed<E>(
        &mut self,
        mut input: &[u8],
        out: &mut dyn FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), Error<E>> {
        if self.st == St::Failed {
            return Err(Error::Failed);
        }
        let r = self.feed_inner(&mut input, out);
        if r.is_err() {
            self.st = St::Failed;
        }
        r
    }

    /// Call after the last `feed`. Succeeds only if the input ended exactly at
    /// a member boundary after at least one member.
    pub fn finish(&self) -> Result<(), Error> {
        if self.st == St::Failed {
            return Err(Error::Failed);
        }
        if self.st == St::End && self.members > 0 {
            Ok(())
        } else {
            Err(Error::Truncated)
        }
    }

    fn hbyte(&mut self, b: u8) {
        self.hcrc.update(&[b]);
    }

    /// Advance to the first header section at or after `stage`
    /// (0 extra, 1 name, 2 comment, 3 hcrc, 4 body).
    fn goto_stage(&mut self, stage: u8) {
        let f = self.flags;
        self.st = if stage == 0 && f & FEXTRA != 0 {
            St::XLen(0)
        } else if stage <= 1 && f & FNAME != 0 {
            St::Name
        } else if stage <= 2 && f & FCOMMENT != 0 {
            St::Comment
        } else if stage <= 3 && f & FHCRC != 0 {
            St::Hcrc(0)
        } else {
            self.inf.reset();
            self.crc = Crc32::new();
            self.size = 0;
            St::Body
        };
    }

    fn feed_inner<E>(
        &mut self,
        input: &mut &[u8],
        out: &mut dyn FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), Error<E>> {
        while !input.is_empty() {
            match self.st {
                St::End => {
                    if input[0] != 0x1f {
                        return Err(Error::TrailingGarbage);
                    }
                    self.hcrc = Crc32::new();
                    self.st = St::Fixed(0);
                }
                St::Fixed(n) => {
                    let b = input[0];
                    *input = &input[1..];
                    if n == 0 && b != 0x1f || n == 1 && b != 0x8b {
                        return Err(if self.members > 0 {
                            Error::TrailingGarbage
                        } else {
                            Error::BadMagic
                        });
                    }
                    self.hdr[n as usize] = b;
                    self.hbyte(b);
                    if n == 9 {
                        if self.hdr[2] != 8 {
                            return Err(Error::UnsupportedMethod);
                        }
                        self.flags = self.hdr[3];
                        if self.flags & 0xe0 != 0 {
                            return Err(Error::ReservedFlags);
                        }
                        self.goto_stage(0);
                    } else {
                        self.st = St::Fixed(n + 1);
                    }
                }
                St::XLen(n) => {
                    let b = input[0];
                    *input = &input[1..];
                    self.hbyte(b);
                    self.xlen[n as usize] = b;
                    if n == 1 {
                        let l = u16::from_le_bytes(self.xlen);
                        if l == 0 {
                            self.goto_stage(1);
                        } else {
                            self.st = St::Extra(l);
                        }
                    } else {
                        self.st = St::XLen(1);
                    }
                }
                St::Extra(rem) => {
                    let n = (rem as usize).min(input.len());
                    self.hcrc.update(&input[..n]);
                    *input = &input[n..];
                    if n == rem as usize {
                        self.goto_stage(1);
                    } else {
                        self.st = St::Extra(rem - n as u16);
                    }
                }
                St::Name | St::Comment => {
                    let z = input.iter().position(|&b| b == 0);
                    let n = z.map_or(input.len(), |p| p + 1);
                    self.hcrc.update(&input[..n]);
                    *input = &input[n..];
                    if z.is_some() {
                        self.goto_stage(if self.st == St::Name { 2 } else { 3 });
                    }
                }
                St::Hcrc(n) => {
                    let b = input[0];
                    *input = &input[1..];
                    self.stored_hcrc[n as usize] = b;
                    if n == 1 {
                        let want = (self.hcrc.value() & 0xffff) as u16;
                        if u16::from_le_bytes(self.stored_hcrc) != want {
                            return Err(Error::HeaderCrc);
                        }
                        self.goto_stage(4);
                    } else {
                        self.st = St::Hcrc(1);
                    }
                }
                St::Body => {
                    let crc = &mut self.crc;
                    let size = &mut self.size;
                    let mut cb = |d: &[u8]| {
                        crc.update(d);
                        *size = size.wrapping_add(d.len() as u32);
                        out(d)
                    };
                    match self.inf.feed(input, &mut cb)? {
                        Status::NeedInput => *input = &[],
                        Status::Done { consumed } => {
                            *input = &input[consumed..];
                            self.st = St::Trailer(0);
                        }
                    }
                }
                St::Trailer(n) => {
                    self.trailer[n as usize] = input[0];
                    *input = &input[1..];
                    if n == 7 {
                        let c = u32::from_le_bytes(self.trailer[..4].try_into().unwrap());
                        let s = u32::from_le_bytes(self.trailer[4..].try_into().unwrap());
                        if c != self.crc.value() {
                            return Err(Error::Crc32Mismatch);
                        }
                        if s != self.size {
                            return Err(Error::SizeMismatch);
                        }
                        self.members += 1;
                        self.st = St::End;
                    } else {
                        self.st = St::Trailer(n + 1);
                    }
                }
                St::Failed => return Err(Error::Failed),
            }
        }
        Ok(())
    }
}
