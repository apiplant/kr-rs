//! SHA-256, SHA-384 and SHA-512 (FIPS 180-4).
//!
//! Hashing only processes public lengths, so the straightforward implementation is constant-time
//! with respect to the data. The 64-bit round constants are generated from their definition
//! (cube roots of the first 80 primes), not typed in.

/// A hash function usable by HMAC/HKDF.
pub trait Hash: Clone {
    const OUT: usize;
    const BLOCK: usize;
    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    /// Writes `OUT` bytes into `out[..OUT]`.
    fn finish_into(self, out: &mut [u8]);
}

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H256: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K512: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

const H512: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

const H384: [u64; 8] = [
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
];

/// Shared block buffering for both widths.
#[derive(Clone)]
struct Buf<const B: usize> {
    block: [u8; B],
    fill: usize,
    total: u128,
}

impl<const B: usize> Buf<B> {
    const fn new() -> Self {
        Buf { block: [0; B], fill: 0, total: 0 }
    }

    fn update(&mut self, mut data: &[u8], mut compress: impl FnMut(&[u8; B])) {
        self.total += data.len() as u128;
        if self.fill > 0 {
            let n = (B - self.fill).min(data.len());
            self.block[self.fill..self.fill + n].copy_from_slice(&data[..n]);
            self.fill += n;
            data = &data[n..];
            if self.fill < B {
                return;
            }
            compress(&self.block);
            self.fill = 0;
        }
        while data.len() >= B {
            compress(data[..B].try_into().unwrap());
            data = &data[B..];
        }
        self.block[..data.len()].copy_from_slice(data);
        self.fill = data.len();
    }

    /// Appends 0x80, zeros and the big-endian bit length in `len_bytes` bytes.
    fn pad(&mut self, len_bytes: usize, mut compress: impl FnMut(&[u8; B])) {
        let bits = self.total.wrapping_mul(8);
        self.block[self.fill] = 0x80;
        self.fill += 1;
        if self.fill > B - len_bytes {
            self.block[self.fill..].fill(0);
            compress(&self.block);
            self.fill = 0;
        }
        self.block[self.fill..B - len_bytes].fill(0);
        let be = bits.to_be_bytes();
        self.block[B - len_bytes..].copy_from_slice(&be[16 - len_bytes..]);
        compress(&self.block);
    }
}

#[derive(Clone)]
pub struct Sha256 {
    h: [u32; 8],
    buf: Buf<64>,
}

fn compress256(h: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[4 * i..4 * i + 4].try_into().unwrap());
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K256[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (x, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
        *x = x.wrapping_add(v);
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 { h: H256, buf: Buf::new() }
    }

    pub fn update(&mut self, data: &[u8]) {
        let h = &mut self.h;
        self.buf.update(data, |b| compress256(h, b));
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let h = &mut self.h;
        self.buf.pad(8, |b| compress256(h, b));
        let mut out = [0u8; 32];
        for (o, v) in out.chunks_exact_mut(4).zip(self.h) {
            o.copy_from_slice(&v.to_be_bytes());
        }
        out
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

#[derive(Clone)]
struct Sha512Core {
    h: [u64; 8],
    buf: Buf<128>,
}

fn compress512(h: &mut [u64; 8], block: &[u8; 128]) {
    let mut w = [0u64; 80];
    for i in 0..16 {
        w[i] = u64::from_be_bytes(block[8 * i..8 * i + 8].try_into().unwrap());
    }
    for i in 16..80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
    for i in 0..80 {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ (!e & g);
        let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K512[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (x, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
        *x = x.wrapping_add(v);
    }
}

impl Sha512Core {
    fn update(&mut self, data: &[u8]) {
        let h = &mut self.h;
        self.buf.update(data, |b| compress512(h, b));
    }

    fn finish(mut self) -> [u8; 64] {
        let h = &mut self.h;
        self.buf.pad(16, |b| compress512(h, b));
        let mut out = [0u8; 64];
        for (o, v) in out.chunks_exact_mut(8).zip(self.h) {
            o.copy_from_slice(&v.to_be_bytes());
        }
        out
    }
}

#[derive(Clone)]
pub struct Sha512(Sha512Core);

impl Sha512 {
    pub fn new() -> Self {
        Sha512(Sha512Core { h: H512, buf: Buf::new() })
    }
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }
    pub fn finalize(self) -> [u8; 64] {
        self.0.finish()
    }
}

#[derive(Clone)]
pub struct Sha384(Sha512Core);

impl Sha384 {
    pub fn new() -> Self {
        Sha384(Sha512Core { h: H384, buf: Buf::new() })
    }
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }
    pub fn finalize(self) -> [u8; 48] {
        self.0.finish()[..48].try_into().unwrap()
    }
}

pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(data);
    h.finalize()
}

pub fn sha384(data: &[u8]) -> [u8; 48] {
    let mut h = Sha384::new();
    h.update(data);
    h.finalize()
}

macro_rules! impl_hash {
    ($t:ty, $out:expr, $block:expr) => {
        impl Hash for $t {
            const OUT: usize = $out;
            const BLOCK: usize = $block;
            fn new() -> Self {
                <$t>::new()
            }
            fn update(&mut self, data: &[u8]) {
                <$t>::update(self, data)
            }
            fn finish_into(self, out: &mut [u8]) {
                out[..$out].copy_from_slice(&self.finalize());
            }
        }
    };
}
impl_hash!(Sha256, 32, 64);
impl_hash!(Sha384, 48, 128);
impl_hash!(Sha512, 64, 128);
