//! Streaming RFC 1951 DEFLATE decoder.
//!
//! Input may be fed in chunks of any size (including one byte). Output is
//! delivered through a callback in slices borrowed from a 32 KiB sliding
//! window, so nothing proportional to the stream size is ever buffered.
//!
//! Huffman decoding uses a 10-bit primary lookup table; codes longer than
//! 10 bits fall back to a canonical (count/offset) decode.
//!
//! Strictness: invalid code-length sets (over-subscribed or incomplete,
//! except the zlib-style single 1-bit code for literal/length and distance
//! trees), missing end-of-block code, bad stored-block lengths, reserved
//! symbols, and distances reaching before the start of output are errors.

use crate::Error;
use alloc::boxed::Box;
use alloc::vec;

const WSIZE: usize = 32768;
const WMASK: usize = WSIZE - 1;
const FAST: u32 = 10;
const FAST_MASK: u64 = (1 << FAST) - 1;

static LBASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
static LEXT: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
static DBASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
static DEXT: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
static CL_ORDER: [u8; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/// Result of a successful [`Inflater::feed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// All input was consumed; more is needed to finish the stream.
    NeedInput,
    /// The final block ended. `consumed` bytes of this call's input belonged
    /// to the deflate stream; the rest (e.g. a gzip trailer) is untouched.
    Done { consumed: usize },
}

enum Dec {
    Sym(u16, u32),
    Need,
    Invalid,
}

struct Huff {
    fast: [u16; 1 << FAST], // sym << 4 | len; 0 = not in fast table
    count: [u16; 16],
    symbols: [u16; 288],
}

impl Huff {
    fn new() -> Box<Huff> {
        Box::new(Huff { fast: [0; 1 << FAST], count: [0; 16], symbols: [0; 288] })
    }

    /// Build from code lengths. `strict`: the code must be complete (used for
    /// the code-length code). Otherwise a lone 1-bit code is also accepted
    /// (and an empty code, which can never decode a symbol).
    #[allow(clippy::needless_range_loop)]
    fn build(&mut self, lens: &[u8], strict: bool) -> Result<(), Error> {
        let mut count = [0u16; 16];
        for &l in lens {
            count[l as usize] += 1;
        }
        count[0] = 0;
        let mut left: i32 = 1;
        for len in 1..16 {
            left <<= 1;
            left -= count[len] as i32;
            if left < 0 {
                return Err(Error::OversubscribedCode);
            }
        }
        let total: u32 = count.iter().map(|&c| c as u32).sum();
        if left > 0 {
            let lone = total == 1 && count[1] == 1;
            if strict || !(lone || total == 0) {
                return Err(Error::IncompleteCode);
            }
        }
        let mut offs = [0u16; 16];
        for len in 1..15 {
            offs[len + 1] = offs[len] + count[len];
        }
        let mut next = [0u32; 16];
        let mut c = 0u32;
        for len in 1..16 {
            c = (c + count[len - 1] as u32) << 1;
            next[len] = c;
        }
        self.fast.fill(0);
        for (sym, &l) in lens.iter().enumerate() {
            if l == 0 {
                continue;
            }
            let l = l as usize;
            self.symbols[offs[l] as usize] = sym as u16;
            offs[l] += 1;
            let code = next[l];
            next[l] += 1;
            if l as u32 <= FAST {
                let rev = ((code as u16).reverse_bits() >> (16 - l)) as usize;
                let entry = ((sym as u16) << 4) | l as u16;
                let mut i = rev;
                while i < (1 << FAST) {
                    self.fast[i] = entry;
                    i += 1 << l;
                }
            }
        }
        self.count = count;
        Ok(())
    }

    #[inline(always)]
    fn decode(&self, bits: u64, nbits: u32) -> Dec {
        let e = self.fast[(bits & FAST_MASK) as usize];
        if e != 0 {
            let l = (e & 15) as u32;
            return if l <= nbits { Dec::Sym(e >> 4, l) } else { Dec::Need };
        }
        self.decode_slow(bits, nbits)
    }

    #[cold]
    fn decode_slow(&self, bits: u64, nbits: u32) -> Dec {
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for len in 1..16u32 {
            if len > nbits {
                return Dec::Need;
            }
            code |= ((bits >> (len - 1)) & 1) as i32;
            let count = self.count[len as usize] as i32;
            if code - count < first {
                return Dec::Sym(self.symbols[(index + (code - first)) as usize], len);
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        Dec::Invalid
    }
}

#[derive(Clone, Copy)]
enum State {
    Header,
    StoredLen,
    Stored(u32),
    DynCounts,
    DynClLens(u8),
    DynLens,
    Block,
    Dist(u16),
    Done,
    Failed,
}

/// Streaming DEFLATE decoder.
pub struct Inflater {
    state: State,
    last: bool,
    bits: u64,
    nbits: u32,
    win: Box<[u8; WSIZE]>,
    pos: usize,
    start: usize,
    full: bool,
    lit: Box<Huff>,
    dist: Box<Huff>,
    hlit: usize,
    hdist: usize,
    hclen: usize,
    lens: [u8; 320],
    nlens: usize,
}

impl Default for Inflater {
    fn default() -> Self {
        Self::new()
    }
}

type Out<'a, E> = &'a mut dyn FnMut(&[u8]) -> Result<(), E>;

impl Inflater {
    pub fn new() -> Self {
        let win: Box<[u8; WSIZE]> = vec![0u8; WSIZE].into_boxed_slice().try_into().unwrap();
        Inflater {
            state: State::Header,
            last: false,
            bits: 0,
            nbits: 0,
            win,
            pos: 0,
            start: 0,
            full: false,
            lit: Huff::new(),
            dist: Huff::new(),
            hlit: 0,
            hdist: 0,
            hclen: 0,
            lens: [0; 320],
            nlens: 0,
        }
    }

    /// Prepare for a new stream (keeps allocations).
    pub fn reset(&mut self) {
        self.state = State::Header;
        self.last = false;
        self.bits = 0;
        self.nbits = 0;
        self.pos = 0;
        self.start = 0;
        self.full = false;
    }

    /// True once the final block has been fully decoded.
    pub fn is_done(&self) -> bool {
        matches!(self.state, State::Done)
    }

    /// Feed compressed bytes; decoded bytes are passed to `out` (possibly in
    /// several calls). On error the decoder is poisoned until `reset`.
    pub fn feed<E>(&mut self, input: &[u8], out: Out<'_, E>) -> Result<Status, Error<E>> {
        if matches!(self.state, State::Failed) {
            return Err(Error::Failed);
        }
        if matches!(self.state, State::Done) {
            return Ok(Status::Done { consumed: 0 });
        }
        let mut i = 0usize;
        let r = self.run(input, &mut i, out);
        let fl = self.flush(out);
        match (r, fl) {
            (Err(e), _) => {
                self.state = State::Failed;
                Err(e)
            }
            (Ok(_), Err(e)) => {
                self.state = State::Failed;
                Err(e)
            }
            (Ok(Some(())), Ok(())) => {
                // Done: align to byte, hand back whole unread bytes.
                let spare = (self.nbits / 8) as usize;
                self.bits = 0;
                self.nbits = 0;
                Ok(Status::Done { consumed: i.saturating_sub(spare) })
            }
            (Ok(None), Ok(())) => Ok(Status::NeedInput),
        }
    }

    #[inline(always)]
    fn refill(&mut self, input: &[u8], i: &mut usize) {
        if *i + 8 <= input.len() {
            let w = u64::from_le_bytes(input[*i..*i + 8].try_into().unwrap());
            let n = (63 - self.nbits) >> 3;
            let nb = self.nbits + n * 8;
            self.bits = (self.bits | (w << self.nbits)) & ((1u64 << nb) - 1);
            *i += n as usize;
            self.nbits = nb;
        } else {
            while self.nbits <= 56 && *i < input.len() {
                self.bits |= (input[*i] as u64) << self.nbits;
                self.nbits += 8;
                *i += 1;
            }
        }
    }

    #[inline(always)]
    fn need(&mut self, n: u32, input: &[u8], i: &mut usize) -> bool {
        if self.nbits < n {
            self.refill(input, i);
        }
        self.nbits >= n
    }

    #[inline(always)]
    fn take(&mut self, n: u32) -> u32 {
        let v = (self.bits & ((1u64 << n) - 1)) as u32;
        self.bits >>= n;
        self.nbits -= n;
        v
    }

    fn flush<E>(&mut self, out: Out<'_, E>) -> Result<(), Error<E>> {
        if self.pos > self.start {
            let r = out(&self.win[self.start..self.pos]);
            self.start = self.pos;
            r.map_err(Error::Sink)?;
        }
        Ok(())
    }

    #[inline(always)]
    fn wrap<E>(&mut self, out: Out<'_, E>) -> Result<(), Error<E>> {
        self.flush(out)?;
        self.pos = 0;
        self.start = 0;
        self.full = true;
        Ok(())
    }

    #[inline(always)]
    fn put<E>(&mut self, b: u8, out: Out<'_, E>) -> Result<(), Error<E>> {
        self.win[self.pos & WMASK] = b;
        self.pos += 1;
        if self.pos == WSIZE {
            self.wrap(out)?;
        }
        Ok(())
    }

    fn put_slice<E>(&mut self, mut d: &[u8], out: Out<'_, E>) -> Result<(), Error<E>> {
        while !d.is_empty() {
            let n = d.len().min(WSIZE - self.pos);
            self.win[self.pos..self.pos + n].copy_from_slice(&d[..n]);
            self.pos += n;
            d = &d[n..];
            if self.pos == WSIZE {
                self.wrap(out)?;
            }
        }
        Ok(())
    }

    fn copy<E>(&mut self, len: usize, dist: usize, out: Out<'_, E>) -> Result<(), Error<E>> {
        let mut rem = len;
        while rem > 0 {
            let dst = self.pos;
            let src = dst.wrapping_sub(dist) & WMASK;
            let n = rem.min(WSIZE - dst).min(WSIZE - src);
            if src + n <= dst || dst + n <= src {
                self.win.copy_within(src..src + n, dst);
            } else if dist == 1 {
                let b = self.win[src];
                self.win[dst..dst + n].fill(b);
            } else {
                for k in 0..n {
                    self.win[dst + k] = self.win[src + k];
                }
            }
            self.pos += n;
            rem -= n;
            if self.pos == WSIZE {
                self.wrap(out)?;
            }
        }
        Ok(())
    }

    /// Decode a distance and perform the copy. `Ok(false)` = need more input.
    fn do_dist<E>(
        &mut self,
        len: usize,
        input: &[u8],
        i: &mut usize,
        out: Out<'_, E>,
    ) -> Result<bool, Error<E>> {
        if self.nbits < 32 {
            self.refill(input, i);
        }
        match self.dist.decode(self.bits, self.nbits) {
            Dec::Sym(s, l) => {
                let s = s as usize;
                if s >= 30 {
                    return Err(Error::InvalidDistanceSymbol);
                }
                let eb = DEXT[s] as u32;
                if self.nbits < l + eb {
                    return Ok(false);
                }
                self.bits >>= l;
                self.nbits -= l;
                let d = DBASE[s] as usize + self.take(eb) as usize;
                let limit = if self.full { WSIZE } else { self.pos };
                if d > limit {
                    return Err(Error::DistanceTooFar);
                }
                self.copy(len, d, out)?;
                Ok(true)
            }
            Dec::Need => Ok(false),
            Dec::Invalid => Err(Error::InvalidCode),
        }
    }

    /// Returns Ok(Some(())) on stream end, Ok(None) when starved.
    fn run<E>(
        &mut self,
        input: &[u8],
        i: &mut usize,
        out: Out<'_, E>,
    ) -> Result<Option<()>, Error<E>> {
        loop {
            match self.state {
                State::Header => {
                    if !self.need(3, input, i) {
                        return Ok(None);
                    }
                    let h = self.take(3);
                    self.last = h & 1 != 0;
                    match h >> 1 {
                        0 => {
                            let drop = self.nbits & 7;
                            self.take(drop);
                            self.state = State::StoredLen;
                        }
                        1 => {
                            let mut l = [8u8; 288];
                            l[144..256].fill(9);
                            l[256..280].fill(7);
                            self.lit.build(&l, false).map_err(Error::erase_into)?;
                            self.dist.build(&[5u8; 32], false).map_err(Error::erase_into)?;
                            self.state = State::Block;
                        }
                        2 => self.state = State::DynCounts,
                        _ => return Err(Error::InvalidBlockType),
                    }
                }
                State::StoredLen => {
                    if !self.need(32, input, i) {
                        return Ok(None);
                    }
                    let v = self.take(32);
                    let len = v & 0xffff;
                    if len != (!(v >> 16)) & 0xffff {
                        return Err(Error::StoredLenMismatch);
                    }
                    self.state = State::Stored(len);
                    if self.nbits == 0 {
                        self.bits = 0;
                    }
                }
                State::Stored(mut rem) => {
                    while rem > 0 && self.nbits >= 8 {
                        let b = self.take(8) as u8;
                        self.put(b, out)?;
                        rem -= 1;
                    }
                    if rem > 0 {
                        let avail = input.len() - *i;
                        let n = (rem as usize).min(avail);
                        self.put_slice(&input[*i..*i + n], out)?;
                        *i += n;
                        rem -= n as u32;
                    }
                    if rem > 0 {
                        self.state = State::Stored(rem);
                        return Ok(None);
                    }
                    self.after_block();
                    if self.is_done() {
                        return Ok(Some(()));
                    }
                }
                State::DynCounts => {
                    if !self.need(14, input, i) {
                        return Ok(None);
                    }
                    let v = self.take(14);
                    self.hlit = (v & 31) as usize + 257;
                    self.hdist = ((v >> 5) & 31) as usize + 1;
                    self.hclen = ((v >> 10) & 15) as usize + 4;
                    if self.hlit > 286 || self.hdist > 30 {
                        return Err(Error::InvalidCodeLengths);
                    }
                    self.lens[..19].fill(0);
                    self.state = State::DynClLens(0);
                }
                State::DynClLens(mut k) => {
                    while (k as usize) < self.hclen {
                        if !self.need(3, input, i) {
                            self.state = State::DynClLens(k);
                            return Ok(None);
                        }
                        let v = self.take(3);
                        self.lens[CL_ORDER[k as usize] as usize] = v as u8;
                        k += 1;
                    }
                    let l = self.lens;
                    self.lit.build(&l[..19], true).map_err(Error::erase_into)?;
                    self.nlens = 0;
                    self.state = State::DynLens;
                }
                State::DynLens => {
                    let total = self.hlit + self.hdist;
                    while self.nlens < total {
                        if self.nbits < 32 {
                            self.refill(input, i);
                        }
                        match self.lit.decode(self.bits, self.nbits) {
                            Dec::Sym(s, l) => {
                                if s < 16 {
                                    self.bits >>= l;
                                    self.nbits -= l;
                                    self.lens[self.nlens] = s as u8;
                                    self.nlens += 1;
                                    continue;
                                }
                                let eb = match s {
                                    16 => 2,
                                    17 => 3,
                                    _ => 7,
                                };
                                if self.nbits < l + eb {
                                    return Ok(None);
                                }
                                self.bits >>= l;
                                self.nbits -= l;
                                let e = self.take(eb) as usize;
                                let (val, rep) = match s {
                                    16 => {
                                        if self.nlens == 0 {
                                            return Err(Error::InvalidCodeLengthRepeat);
                                        }
                                        (self.lens[self.nlens - 1], 3 + e)
                                    }
                                    17 => (0, 3 + e),
                                    _ => (0, 11 + e),
                                };
                                if self.nlens + rep > total {
                                    return Err(Error::InvalidCodeLengthRepeat);
                                }
                                self.lens[self.nlens..self.nlens + rep].fill(val);
                                self.nlens += rep;
                            }
                            Dec::Need => return Ok(None),
                            Dec::Invalid => return Err(Error::InvalidCode),
                        }
                    }
                    if self.lens[256] == 0 {
                        return Err(Error::MissingEndOfBlock);
                    }
                    let l = self.lens;
                    self.lit.build(&l[..self.hlit], false).map_err(Error::erase_into)?;
                    self.dist
                        .build(&l[self.hlit..self.hlit + self.hdist], false)
                        .map_err(Error::erase_into)?;
                    self.state = State::Block;
                }
                State::Block => loop {
                    if self.nbits < 32 {
                        self.refill(input, i);
                    }
                    match self.lit.decode(self.bits, self.nbits) {
                        Dec::Sym(s, l) => {
                            if s < 256 {
                                self.bits >>= l;
                                self.nbits -= l;
                                self.put(s as u8, out)?;
                                continue;
                            }
                            if s == 256 {
                                self.bits >>= l;
                                self.nbits -= l;
                                self.after_block();
                                break;
                            }
                            let li = (s - 257) as usize;
                            if li >= 29 {
                                return Err(Error::InvalidLengthSymbol);
                            }
                            let eb = LEXT[li] as u32;
                            if self.nbits < l + eb {
                                return Ok(None);
                            }
                            self.bits >>= l;
                            self.nbits -= l;
                            let len = LBASE[li] as usize + self.take(eb) as usize;
                            if !self.do_dist(len, input, i, out)? {
                                self.state = State::Dist(len as u16);
                                return Ok(None);
                            }
                        }
                        Dec::Need => return Ok(None),
                        Dec::Invalid => return Err(Error::InvalidCode),
                    }
                },
                State::Dist(len) => {
                    if !self.do_dist(len as usize, input, i, out)? {
                        return Ok(None);
                    }
                    self.state = State::Block;
                }
                State::Done => return Ok(Some(())),
                State::Failed => return Err(Error::Failed),
            }
            if matches!(self.state, State::Done) {
                return Ok(Some(()));
            }
        }
    }

    fn after_block(&mut self) {
        self.state = if self.last { State::Done } else { State::Header };
    }
}

impl Error<()> {
    /// Lift a payload-free error into any `Error<E>` (used by table builders,
    /// which can never produce `Sink`).
    pub(crate) fn erase_into<E>(self) -> Error<E> {
        match self {
            Error::OversubscribedCode => Error::OversubscribedCode,
            Error::IncompleteCode => Error::IncompleteCode,
            _ => Error::InvalidCode,
        }
    }
}
