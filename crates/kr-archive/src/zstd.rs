//! Streaming Zstandard (RFC 8878) decoder.
//!
//! Push-based like [`crate::gzip::GzDecoder`]: callers feed input in chunks of any size and get
//! the decompressed bytes through a callback. The decoder buffers at most one block of compressed
//! input (128 KiB) plus the frame's history window (at most [`MAX_WINDOW`]). Dictionaries are not
//! supported; skippable frames are skipped; the optional content checksum is consumed but not
//! verified (OCI layers are verified by digest and diff id).

use crate::Error;
use alloc::vec::Vec;

/// Largest window accepted (the default limit of the reference decoder).
pub const MAX_WINDOW: u64 = 1 << 27;
const BLOCK_MAX: usize = 128 * 1024;
const MAGIC: u32 = 0xFD2F_B528;

fn bad<E>(why: &'static str) -> Error<E> {
    Error::Zstd(why)
}

// ---- backward bit reader (Huffman literals, sequences, FSE weights) ----

struct Back<'a> {
    d: &'a [u8],
    /// Bits still unread; negative once a read went past the start (the missing bits read as 0).
    left: i64,
}

impl<'a> Back<'a> {
    fn new<E>(d: &'a [u8]) -> Result<Back<'a>, Error<E>> {
        let last = *d.last().ok_or(bad("empty bit stream"))?;
        if last == 0 {
            return Err(bad("bit stream without end mark"));
        }
        let hi = 7 - last.leading_zeros() as i64;
        Ok(Back { d, left: (d.len() as i64 - 1) * 8 + hi })
    }

    /// The `n` (<= 32) bits ending at the read position, without consuming them.
    fn peek(&self, n: u32) -> u64 {
        if n == 0 {
            return 0;
        }
        let start = self.left - n as i64; // may be negative
        let mask = (1u64 << n) - 1;
        let (from, lost) = if start >= 0 { (start as usize, 0) } else { (0, (-start) as u32) };
        // Up to 8 bytes from the byte holding `from`, little endian, zero padded past the end.
        let mut w = [0u8; 8];
        let b = from / 8;
        let avail = self.d.len().saturating_sub(b).min(8);
        w[..avail].copy_from_slice(&self.d[b..b + avail]);
        let v = (u64::from_le_bytes(w) >> (from % 8)) & mask;
        if lost == 0 {
            v
        } else {
            // Bits before the start of the stream read as zero: the kept bits move up.
            ((v & ((1u64 << (n - lost.min(n))) - 1)) << lost.min(63)) & mask
        }
    }

    fn read(&mut self, n: u32) -> u64 {
        let v = self.peek(n);
        self.left -= n as i64;
        v
    }

    fn overflowed(&self) -> bool {
        self.left < 0
    }
}

// ---- forward bit reader (FSE table descriptions) ----

struct Fwd<'a> {
    d: &'a [u8],
    bit: usize,
}

impl Fwd<'_> {
    fn peek(&self, n: u32) -> u32 {
        let mut v = 0u32;
        for i in 0..n as usize {
            let pos = self.bit + i;
            if let Some(b) = self.d.get(pos / 8) {
                v |= (((b >> (pos % 8)) & 1) as u32) << i;
            }
        }
        v
    }
    fn skip(&mut self, n: u32) {
        self.bit += n as usize;
    }
    fn bytes_used(&self) -> usize {
        self.bit.div_ceil(8)
    }
}

// ---- FSE ----

#[derive(Clone, Copy, Default)]
struct Cell {
    sym: u16,
    nb: u8,
    base: u16,
}

#[derive(Clone, Default)]
struct Fse {
    log: u32,
    cells: Vec<Cell>,
}

impl Fse {
    /// Builds the decoding table from normalized counts (-1 = "less than one").
    fn build<E>(counts: &[i16], log: u32) -> Result<Fse, Error<E>> {
        let size = 1usize << log;
        let mut cells = alloc::vec![Cell::default(); size];
        let mut high = size;
        let mut next = alloc::vec![0u16; counts.len()];
        for (s, &c) in counts.iter().enumerate() {
            if c == -1 {
                high -= 1;
                cells[high] = Cell { sym: s as u16, nb: log as u8, base: 0 };
                next[s] = 1;
            } else {
                next[s] = c as u16;
            }
        }
        let step = (size >> 1) + (size >> 3) + 3;
        let mask = size - 1;
        let mut pos = 0usize;
        for (s, &c) in counts.iter().enumerate() {
            for _ in 0..c.max(0) {
                cells[pos].sym = s as u16;
                loop {
                    pos = (pos + step) & mask;
                    if pos < high {
                        break;
                    }
                }
            }
        }
        if pos != 0 {
            return Err(bad("inconsistent FSE table"));
        }
        for c in cells.iter_mut().take(high) {
            let s = c.sym as usize;
            let x = next[s] as u32;
            next[s] += 1;
            let nb = log - (31 - x.leading_zeros());
            c.nb = nb as u8;
            c.base = ((x << nb) as usize - size) as u16;
        }
        Ok(Fse { log, cells })
    }

    /// Reads a table description; returns the table and the bytes it took.
    fn read<E>(d: &[u8], max_sym: usize, max_log: u32) -> Result<(Fse, usize), Error<E>> {
        let mut f = Fwd { d, bit: 0 };
        let log = f.peek(4) + 5;
        f.skip(4);
        if log > max_log {
            return Err(bad("FSE accuracy too large"));
        }
        let mut remaining: i32 = (1 << log) + 1;
        let mut counts: Vec<i16> = Vec::new();
        while remaining > 1 && counts.len() < max_sym {
            let bits = 32 - (remaining as u32).leading_zeros();
            let val = f.peek(bits) as i32;
            let lower_mask = (1i32 << (bits - 1)) - 1;
            let max = (1i32 << bits) - 1 - remaining;
            let value;
            if (val & lower_mask) < max {
                value = val & lower_mask;
                f.skip(bits - 1);
            } else {
                let mut v = val & ((1 << bits) - 1);
                if v > lower_mask {
                    v -= max;
                }
                value = v;
                f.skip(bits);
            }
            let prob = value - 1;
            remaining -= prob.abs();
            counts.push(prob as i16);
            if prob == 0 {
                loop {
                    let rep = f.peek(2);
                    f.skip(2);
                    for _ in 0..rep {
                        if counts.len() >= max_sym {
                            return Err(bad("FSE table has too many symbols"));
                        }
                        counts.push(0);
                    }
                    if rep != 3 {
                        break;
                    }
                }
            }
            if f.bit > d.len() * 8 + 16 {
                return Err(Error::Truncated);
            }
        }
        if remaining != 1 || f.bit > d.len() * 8 {
            return Err(bad("bad FSE table description"));
        }
        let used = f.bytes_used();
        Ok((Fse::build(&counts, log)?, used))
    }

    fn rle<E>(sym: u8) -> Result<Fse, Error<E>> {
        Ok(Fse { log: 0, cells: alloc::vec![Cell { sym: sym as u16, nb: 0, base: 0 }] })
    }
}

// ---- Huffman ----

#[derive(Clone, Default)]
struct Huff {
    bits: u32,
    /// Indexed by the next `bits` bits of the stream: (symbol, length).
    table: Vec<(u8, u8)>,
}

impl Huff {
    fn from_weights<E>(w: &[u8]) -> Result<Huff, Error<E>> {
        if w.is_empty() || w.len() > 255 {
            return Err(bad("bad Huffman weight count"));
        }
        let mut total: u32 = 0;
        for &x in w {
            if x > 11 {
                return Err(bad("Huffman weight too large"));
            }
            if x > 0 {
                total += 1 << (x - 1);
            }
        }
        if total == 0 {
            return Err(bad("empty Huffman tree"));
        }
        let max_bits = 32 - total.leading_zeros(); // smallest power of two above total is 1 << max_bits
        if max_bits > 11 {
            return Err(bad("Huffman tree too deep"));
        }
        let rest = (1u32 << max_bits) - total;
        if !rest.is_power_of_two() {
            return Err(bad("Huffman weights do not complete the tree"));
        }
        let mut weights: Vec<u8> = w.to_vec();
        weights.push((rest.trailing_zeros() + 1) as u8);
        let size = 1usize << max_bits;
        let mut table = alloc::vec![(0u8, 0u8); size];
        let mut pos = 0usize;
        for wt in 1..=max_bits as u8 {
            for (s, &x) in weights.iter().enumerate() {
                if x == wt {
                    let run = 1usize << (wt - 1);
                    if pos + run > size {
                        return Err(bad("Huffman table overflow"));
                    }
                    let nb = (max_bits as u8 + 1) - wt;
                    for t in &mut table[pos..pos + run] {
                        *t = (s as u8, nb);
                    }
                    pos += run;
                }
            }
        }
        if pos != size {
            return Err(bad("Huffman table not full"));
        }
        Ok(Huff { bits: max_bits, table })
    }

    /// Decodes exactly `n` symbols from one stream.
    fn stream<E>(&self, d: &[u8], n: usize, out: &mut Vec<u8>) -> Result<(), Error<E>> {
        let mut b = Back::new(d)?;
        for _ in 0..n {
            let (sym, nb) = self.table[b.peek(self.bits) as usize];
            b.left -= nb as i64;
            if b.overflowed() {
                return Err(bad("Huffman stream too short"));
            }
            out.push(sym);
        }
        if b.left != 0 {
            return Err(bad("Huffman stream has unused bits"));
        }
        Ok(())
    }
}

/// Reads the Huffman tree description at the start of `d`; returns the table and bytes used.
fn read_huff<E>(d: &[u8]) -> Result<(Huff, usize), Error<E>> {
    let hdr = *d.first().ok_or(Error::Truncated)? as usize;
    let mut weights: Vec<u8> = Vec::new();
    let used;
    if hdr >= 128 {
        let n = hdr - 127;
        let nbytes = n.div_ceil(2);
        let body = d.get(1..1 + nbytes).ok_or(Error::Truncated)?;
        for i in 0..n {
            let byte = body[i / 2];
            weights.push(if i % 2 == 0 { byte >> 4 } else { byte & 15 });
        }
        used = 1 + nbytes;
    } else {
        let body = d.get(1..1 + hdr).ok_or(Error::Truncated)?;
        let (fse, hlen) = Fse::read(body, 256, 6)?;
        let mut b = Back::new(&body[hlen..])?;
        let mut s1 = b.read(fse.log) as usize;
        let mut s2 = b.read(fse.log) as usize;
        loop {
            let c = fse.cells[s1];
            weights.push(c.sym as u8);
            if weights.len() > 255 {
                return Err(bad("too many Huffman weights"));
            }
            s1 = c.base as usize + b.read(c.nb as u32) as usize;
            if b.overflowed() {
                weights.push(fse.cells[s2].sym as u8);
                break;
            }
            let c = fse.cells[s2];
            weights.push(c.sym as u8);
            if weights.len() > 255 {
                return Err(bad("too many Huffman weights"));
            }
            s2 = c.base as usize + b.read(c.nb as u32) as usize;
            if b.overflowed() {
                weights.push(fse.cells[s1].sym as u8);
                break;
            }
        }
        used = 1 + hdr;
    }
    Ok((Huff::from_weights(&weights)?, used))
}

// ---- sequence code tables ----

const LL_PREDEF: [i16; 36] = [4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1];
const ML_PREDEF: [i16; 53] = [1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1];
const OF_PREDEF: [i16; 29] = [1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1];

const LL_BASE: [(u32, u32); 36] = [
    (0, 0), (1, 0), (2, 0), (3, 0), (4, 0), (5, 0), (6, 0), (7, 0), (8, 0), (9, 0), (10, 0), (11, 0), (12, 0), (13, 0), (14, 0), (15, 0),
    (16, 1), (18, 1), (20, 1), (22, 1), (24, 2), (28, 2), (32, 3), (40, 3), (48, 4), (64, 6), (128, 7), (256, 8), (512, 9), (1024, 10), (2048, 11), (4096, 12),
    (8192, 13), (16384, 14), (32768, 15), (65536, 16),
];
const ML_BASE: [(u32, u32); 53] = [
    (3, 0), (4, 0), (5, 0), (6, 0), (7, 0), (8, 0), (9, 0), (10, 0), (11, 0), (12, 0), (13, 0), (14, 0), (15, 0), (16, 0), (17, 0), (18, 0),
    (19, 0), (20, 0), (21, 0), (22, 0), (23, 0), (24, 0), (25, 0), (26, 0), (27, 0), (28, 0), (29, 0), (30, 0), (31, 0), (32, 0), (33, 0), (34, 0),
    (35, 1), (37, 1), (39, 1), (41, 1), (43, 2), (47, 2), (51, 3), (59, 3), (67, 4), (83, 4), (99, 5), (131, 7), (259, 8), (515, 9), (1027, 10), (2051, 11),
    (4099, 12), (8195, 13), (16387, 14), (32771, 15), (65539, 16),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum St {
    Header,
    BlockHeader,
    Block { last: bool, kind: u8, size: usize },
    Skip(u64),
    Checksum,
    Failed,
}

/// Streaming Zstandard decoder.
pub struct ZstdDecoder {
    st: St,
    buf: Vec<u8>,
    /// Output so far in this frame, newest last (older data is dropped beyond the window).
    hist: Vec<u8>,
    window: usize,
    checksum: bool,
    frames: u32,
    reps: [u32; 3],
    huff: Option<Huff>,
    ll: Option<Fse>,
    of: Option<Fse>,
    ml: Option<Fse>,
}

impl Default for ZstdDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ZstdDecoder {
    pub fn new() -> Self {
        ZstdDecoder { st: St::Header, buf: Vec::new(), hist: Vec::new(), window: 0, checksum: false, frames: 0, reps: [1, 4, 8], huff: None, ll: None, of: None, ml: None }
    }

    /// Number of complete frames decoded.
    pub fn frames(&self) -> u32 {
        self.frames
    }

    /// Feed compressed bytes of any size; decompressed data goes to `out`.
    pub fn feed<E>(&mut self, input: &[u8], out: &mut dyn FnMut(&[u8]) -> Result<(), E>) -> Result<(), Error<E>> {
        if self.st == St::Failed {
            return Err(Error::Failed);
        }
        self.buf.extend_from_slice(input);
        let r = self.run(out);
        if r.is_err() {
            self.st = St::Failed;
        }
        r
    }

    /// Call after the last `feed`: succeeds only when the input ended between frames after at
    /// least one frame.
    pub fn finish(&self) -> Result<(), Error> {
        if self.st == St::Failed {
            return Err(Error::Failed);
        }
        if self.st == St::Header && self.buf.is_empty() && self.frames > 0 {
            Ok(())
        } else {
            Err(Error::Truncated)
        }
    }

    fn take(&mut self, n: usize) {
        self.buf.drain(..n);
    }

    fn run<E>(&mut self, out: &mut dyn FnMut(&[u8]) -> Result<(), E>) -> Result<(), Error<E>> {
        loop {
            match self.st {
                St::Failed => return Err(Error::Failed),
                St::Header => {
                    if self.buf.len() < 4 {
                        return Ok(());
                    }
                    let magic = u32::from_le_bytes(self.buf[..4].try_into().unwrap());
                    if magic & 0xFFFF_FFF0 == 0x184D_2A50 {
                        if self.buf.len() < 8 {
                            return Ok(());
                        }
                        let n = u32::from_le_bytes(self.buf[4..8].try_into().unwrap()) as u64;
                        self.take(8);
                        self.frames += 1;
                        self.st = St::Skip(n);
                        continue;
                    }
                    if magic != MAGIC {
                        return Err(Error::BadMagic);
                    }
                    let Some(used) = self.frame_header()? else { return Ok(()) };
                    self.take(used);
                    self.st = St::BlockHeader;
                }
                St::Skip(left) => {
                    let n = (self.buf.len() as u64).min(left) as usize;
                    self.take(n);
                    if left as usize == n && left <= self.buf.len() as u64 + n as u64 {
                        self.st = St::Header;
                    } else {
                        self.st = St::Skip(left - n as u64);
                        return Ok(());
                    }
                }
                St::BlockHeader => {
                    if self.buf.len() < 3 {
                        return Ok(());
                    }
                    let h = self.buf[0] as u32 | (self.buf[1] as u32) << 8 | (self.buf[2] as u32) << 16;
                    let (last, kind, size) = (h & 1 == 1, ((h >> 1) & 3) as u8, (h >> 3) as usize);
                    if kind == 3 {
                        return Err(bad("reserved block type"));
                    }
                    if size > BLOCK_MAX || (kind == 2 && size > BLOCK_MAX - 1) {
                        return Err(bad("block too large"));
                    }
                    self.take(3);
                    self.st = St::Block { last, kind, size };
                }
                St::Block { last, kind, size } => {
                    let need = if kind == 1 { 1 } else { size };
                    if self.buf.len() < need {
                        return Ok(());
                    }
                    let start = self.hist.len();
                    match kind {
                        0 => {
                            let b = self.buf[..need].to_vec();
                            self.hist.extend_from_slice(&b);
                        }
                        1 => {
                            let byte = self.buf[0];
                            self.hist.resize(start + size, byte);
                        }
                        _ => {
                            let block = self.buf[..need].to_vec();
                            self.compressed(&block)?;
                        }
                    }
                    self.take(need);
                    out(&self.hist[start..]).map_err(Error::Sink)?;
                    // Keep the window and a little more, drop the rest.
                    if self.hist.len() > self.window * 2 + BLOCK_MAX * 2 {
                        let cut = self.hist.len() - self.window;
                        self.hist.drain(..cut);
                    }
                    if last {
                        self.st = if self.checksum { St::Checksum } else { St::Header };
                        if !self.checksum {
                            self.end_frame();
                        }
                    } else {
                        self.st = St::BlockHeader;
                    }
                }
                St::Checksum => {
                    if self.buf.len() < 4 {
                        return Ok(());
                    }
                    self.take(4);
                    self.end_frame();
                    self.st = St::Header;
                }
            }
        }
    }

    fn end_frame(&mut self) {
        self.frames += 1;
        self.hist.clear();
        self.reps = [1, 4, 8];
        self.huff = None;
        self.ll = None;
        self.of = None;
        self.ml = None;
    }

    /// Parses the frame header at the start of `buf`; `None` when more input is needed.
    fn frame_header<E>(&mut self) -> Result<Option<usize>, Error<E>> {
        let b = &self.buf;
        if b.len() < 5 {
            return Ok(None);
        }
        let d = b[4];
        if d & 0x08 != 0 {
            return Err(bad("reserved frame header bit"));
        }
        let fcs_flag = d >> 6;
        let single = d & 0x20 != 0;
        let checksum = d & 0x04 != 0;
        let dict = match d & 3 {
            0 => 0,
            1 => 1,
            2 => 2,
            _ => 4,
        };
        let fcs_len = match fcs_flag {
            0 => usize::from(single),
            1 => 2,
            2 => 4,
            _ => 8,
        };
        let total = 5 + usize::from(!single) + dict + fcs_len;
        if b.len() < total {
            return Ok(None);
        }
        let mut p = 5;
        let mut window: u64 = 0;
        if !single {
            let w = b[p];
            p += 1;
            let exp = (w >> 3) as u32;
            let base = 1u64 << (10 + exp);
            window = base + (base / 8) * (w & 7) as u64;
        }
        if b[p..p + dict].iter().any(|&x| x != 0) {
            return Err(bad("dictionaries are not supported"));
        }
        p += dict;
        if fcs_len > 0 {
            let mut v: u64 = 0;
            for (i, x) in b[p..p + fcs_len].iter().enumerate() {
                v |= (*x as u64) << (8 * i);
            }
            if fcs_flag == 1 {
                v += 256;
            }
            if single {
                window = v;
            }
        }
        if window > MAX_WINDOW {
            return Err(bad("window too large"));
        }
        self.window = window as usize;
        self.checksum = checksum;
        self.reps = [1, 4, 8];
        Ok(Some(total))
    }

    fn compressed<E>(&mut self, blk: &[u8]) -> Result<(), Error<E>> {
        // ---- literals ----
        let b0 = *blk.first().ok_or(Error::Truncated)?;
        let ltype = b0 & 3;
        let fmt = (b0 >> 2) & 3;
        let mut p;
        let mut lits: Vec<u8> = Vec::new();
        match ltype {
            0 | 1 => {
                let (size, hl) = match fmt {
                    0 | 2 => ((b0 >> 3) as usize, 1),
                    1 => (((b0 >> 4) as usize) | (*blk.get(1).ok_or(Error::Truncated)? as usize) << 4, 2),
                    _ => (((b0 >> 4) as usize) | (*blk.get(1).ok_or(Error::Truncated)? as usize) << 4 | (*blk.get(2).ok_or(Error::Truncated)? as usize) << 12, 3),
                };
                if size > BLOCK_MAX {
                    return Err(bad("literals too large"));
                }
                p = hl;
                if ltype == 0 {
                    lits.extend_from_slice(blk.get(p..p + size).ok_or(Error::Truncated)?);
                    p += size;
                } else {
                    let byte = *blk.get(p).ok_or(Error::Truncated)?;
                    lits.resize(size, byte);
                    p += 1;
                }
            }
            _ => {
                let (hl, n_bits, streams4) = match fmt {
                    0 => (3, 10, false),
                    1 => (3, 10, true),
                    2 => (4, 14, true),
                    _ => (5, 18, true),
                };
                let hb = blk.get(..hl).ok_or(Error::Truncated)?;
                let mut v: u64 = 0;
                for (i, x) in hb.iter().enumerate() {
                    v |= (*x as u64) << (8 * i);
                }
                let mask = (1u64 << n_bits) - 1;
                let regen = ((v >> 4) & mask) as usize;
                let comp = ((v >> (4 + n_bits)) & mask) as usize;
                if regen > BLOCK_MAX {
                    return Err(bad("literals too large"));
                }
                let body = blk.get(hl..hl + comp).ok_or(Error::Truncated)?;
                let mut off = 0;
                if ltype == 2 {
                    let (h, used) = read_huff(body)?;
                    self.huff = Some(h);
                    off = used;
                }
                let huff = self.huff.clone().ok_or(bad("literals reuse a Huffman table that does not exist"))?;
                let data = &body[off..];
                if !streams4 {
                    huff.stream(data, regen, &mut lits)?;
                } else {
                    if data.len() < 6 {
                        return Err(Error::Truncated);
                    }
                    let s1 = u16::from_le_bytes([data[0], data[1]]) as usize;
                    let s2 = u16::from_le_bytes([data[2], data[3]]) as usize;
                    let s3 = u16::from_le_bytes([data[4], data[5]]) as usize;
                    let rest = &data[6..];
                    if s1 + s2 + s3 > rest.len() {
                        return Err(Error::Truncated);
                    }
                    let seg = regen.div_ceil(4);
                    let counts = [seg, seg, seg, regen.saturating_sub(3 * seg)];
                    let parts = [&rest[..s1], &rest[s1..s1 + s2], &rest[s1 + s2..s1 + s2 + s3], &rest[s1 + s2 + s3..]];
                    for (part, n) in parts.iter().zip(counts) {
                        huff.stream(part, n, &mut lits)?;
                    }
                }
                p = hl + comp;
            }
        }
        // ---- sequences ----
        let rest = &blk[p..];
        let mut lp = 0usize; // position in lits
        if rest.is_empty() {
            return Err(Error::Truncated);
        }
        let (nseq, mut q) = match rest[0] {
            0 => (0usize, 1),
            x if x < 128 => (x as usize, 1),
            x if x < 255 => ((((x as usize) - 128) << 8) + *rest.get(1).ok_or(Error::Truncated)? as usize, 2),
            _ => (*rest.get(1).ok_or(Error::Truncated)? as usize + ((*rest.get(2).ok_or(Error::Truncated)? as usize) << 8) + 0x7F00, 3),
        };
        if nseq == 0 {
            self.hist.extend_from_slice(&lits);
            return Ok(());
        }
        let modes = *rest.get(q).ok_or(Error::Truncated)?;
        q += 1;
        if modes & 3 != 0 {
            return Err(bad("reserved sequence mode bits"));
        }
        let table = |mode: u8, prev: &Option<Fse>, predef: &[i16], plog: u32, max_sym: usize, max_log: u32, q: &mut usize| -> Result<Fse, Error<E>> {
            Ok(match mode {
                0 => Fse::build(predef, plog)?,
                1 => {
                    let s = *rest.get(*q).ok_or(Error::Truncated)?;
                    *q += 1;
                    Fse::rle(s)?
                }
                2 => {
                    let (t, used) = Fse::read(rest.get(*q..).ok_or(Error::Truncated)?, max_sym, max_log)?;
                    *q += used;
                    t
                }
                _ => prev.clone().ok_or(bad("sequence table repeat without a previous table"))?,
            })
        };
        let ll = table(modes >> 6, &self.ll, &LL_PREDEF, 6, 36, 9, &mut q)?;
        let of = table((modes >> 4) & 3, &self.of, &OF_PREDEF, 5, 32, 8, &mut q)?;
        let ml = table((modes >> 2) & 3, &self.ml, &ML_PREDEF, 6, 53, 9, &mut q)?;
        self.ll = Some(ll.clone());
        self.of = Some(of.clone());
        self.ml = Some(ml.clone());
        let mut b = Back::new(&rest[q..])?;
        let mut sl = b.read(ll.log) as usize;
        let mut so = b.read(of.log) as usize;
        let mut sm = b.read(ml.log) as usize;
        let mut reps = self.reps;
        let block_start = self.hist.len() - 0;
        for i in 0..nseq {
            let (lc, oc, mc) = (ll.cells[sl].sym as usize, of.cells[so].sym as usize, ml.cells[sm].sym as usize);
            if lc >= 36 || mc >= 53 || oc >= 32 {
                return Err(bad("bad sequence code"));
            }
            let ofv = (1u64 << oc) + b.read(oc as u32);
            let (mb, mx) = ML_BASE[mc];
            let mlen = (mb as u64 + b.read(mx)) as usize;
            let (lb, lx) = LL_BASE[lc];
            let llen = (lb as u64 + b.read(lx)) as usize;
            if i + 1 < nseq {
                let c = ll.cells[sl];
                sl = c.base as usize + b.read(c.nb as u32) as usize;
                let c = ml.cells[sm];
                sm = c.base as usize + b.read(c.nb as u32) as usize;
                let c = of.cells[so];
                so = c.base as usize + b.read(c.nb as u32) as usize;
            }
            if b.overflowed() {
                return Err(bad("sequence stream too short"));
            }
            // Offset: values 1..=3 pick a repeated offset.
            let offset: u32;
            if ofv > 3 {
                offset = (ofv - 3) as u32;
                reps = [offset, reps[0], reps[1]];
            } else {
                let idx = if llen == 0 { ofv as usize } else { ofv as usize - 1 }; // 0..=3
                if idx == 3 {
                    offset = reps[0].checked_sub(1).filter(|o| *o > 0).ok_or(bad("repeat offset of zero"))?;
                    reps = [offset, reps[0], reps[1]];
                } else {
                    offset = reps[idx];
                    if idx == 1 {
                        reps = [reps[1], reps[0], reps[2]];
                    } else if idx == 2 {
                        reps = [reps[2], reps[0], reps[1]];
                    }
                }
            }
            // Literals, then the match.
            let end = lp.checked_add(llen).filter(|e| *e <= lits.len()).ok_or(bad("sequence uses more literals than the block has"))?;
            self.hist.extend_from_slice(&lits[lp..end]);
            lp = end;
            let offset = offset as usize;
            if offset == 0 || offset > self.hist.len() {
                return Err(bad("match offset before the start of the frame"));
            }
            if offset > self.window {
                return Err(bad("match offset beyond the window"));
            }
            if self.hist.len() - block_start + mlen > BLOCK_MAX {
                return Err(bad("block expands past 128 KiB"));
            }
            let from = self.hist.len() - offset;
            for k in 0..mlen {
                let byte = self.hist[from + k];
                self.hist.push(byte);
            }
        }
        if !b.overflowed() && b.left != 0 {
            return Err(bad("sequence stream has unused bits"));
        }
        self.hist.extend_from_slice(&lits[lp..]);
        if self.hist.len() - block_start > BLOCK_MAX {
            return Err(bad("block expands past 128 KiB"));
        }
        self.reps = reps;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::vec;

    fn zstd(data: &[u8], args: &[&str]) -> Option<Vec<u8>> {
        let mut c = Command::new("zstd").args(args).arg("-c").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?;
        let mut stdin = c.stdin.take()?;
        let d = data.to_vec();
        let t = std::thread::spawn(move || {
            let _ = stdin.write_all(&d);
        });
        let out = c.wait_with_output().ok()?;
        t.join().ok()?;
        out.status.success().then_some(out.stdout)
    }

    fn decode(z: &[u8], chunk: usize) -> Result<Vec<u8>, Error<()>> {
        let mut d = ZstdDecoder::new();
        let mut out = Vec::new();
        for c in z.chunks(chunk.max(1)) {
            d.feed(c, &mut |b: &[u8]| -> Result<(), ()> {
                out.extend_from_slice(b);
                Ok(())
            })?;
        }
        d.finish()?;
        Ok(out)
    }

    /// Text-like data with repeats, so matches, literals and all table kinds appear.
    fn sample(n: usize) -> Vec<u8> {
        let words = ["kubernetes", "container", "image", "layer", "overlay", "namespace", "pod", "deployment", "service", "ingress", "0123456789", "\n"];
        let mut s: u64 = 88172645463325252;
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            if s % 11 == 0 {
                v.push((s >> 32) as u8); // some noise
            } else {
                v.extend_from_slice(words[(s >> 8) as usize % words.len()].as_bytes());
                v.push(b' ');
            }
        }
        v.truncate(n);
        v
    }

    #[test]
    fn matches_the_reference_encoder() {
        if zstd(b"x", &["-1"]).is_none() {
            return; // no zstd binary here
        }
        let inputs: Vec<Vec<u8>> = vec![Vec::new(), b"a".to_vec(), vec![0u8; 100_000], sample(500), sample(70_000), sample(1_000_000), (0..300_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect()];
        for (n, data) in inputs.iter().enumerate() {
            for level in ["-1", "-3", "-9", "-19", "--ultra", "-22"] {
                let args: Vec<&str> = if level == "--ultra" { vec!["--ultra", "-20"] } else { vec![level] };
                let Some(z) = zstd(data, &args) else { continue };
                for chunk in [1usize << 20, 4096, 7] {
                    if chunk == 7 && z.len() > 200_000 {
                        continue;
                    }
                    let r = decode(&z, chunk); assert!(r.is_ok() && r.as_ref().unwrap() == data, "input {n} level {level} chunk {chunk}: {:?}", r.err());
                }
            }
        }
    }

    #[test]
    fn long_window_checksum_and_concatenated_frames() {
        if zstd(b"x", &["-1"]).is_none() {
            return;
        }
        let data = sample(3_000_000);
        let z = zstd(&data, &["-5", "--long=27", "--check"]).unwrap();
        assert!(decode(&z, 65536).unwrap() == data);
        let a = zstd(&sample(1000), &["-3"]).unwrap();
        let b = zstd(&sample(2000), &["-19"]).unwrap();
        let mut both = a.clone();
        both.extend_from_slice(&b);
        let mut want = sample(1000);
        want.extend_from_slice(&sample(2000));
        assert!(decode(&both, 100).unwrap() == want);
    }

    /// `cargo test --release -p kr-archive zstd_speed -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn zstd_speed() {
        let data = sample(60_000_000);
        let z = zstd(&data, &["-3"]).unwrap();
        let t = std::time::Instant::now();
        let out = decode(&z, 1 << 16).unwrap();
        let dt = t.elapsed().as_secs_f64();
        assert!(out == data);
        std::println!("{} MB -> {} MB in {dt:.2}s = {:.0} MB/s", z.len() / 1_000_000, data.len() / 1_000_000, data.len() as f64 / 1e6 / dt);
    }

    #[test]
    fn damaged_or_truncated_input_is_an_error_not_a_panic() {
        if zstd(b"x", &["-1"]).is_none() {
            return;
        }
        let data = sample(200_000);
        let z = zstd(&data, &["-3"]).unwrap();
        assert!(decode(&z[..z.len() - 3], 4096).is_err(), "truncated");
        let mut s: u64 = 12345;
        for _ in 0..300 {
            let mut bad = z.clone();
            for _ in 0..3 {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                let i = (s as usize) % bad.len();
                bad[i] ^= 1 << (s >> 40 & 7);
            }
            let _ = decode(&bad, 8192); // must not panic; may even succeed (no checksum verified)
        }
        assert!(decode(b"not zstd", 8).is_err());
        assert!(decode(&[], 8).is_err());
    }
}
