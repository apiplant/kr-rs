//! AES-128/256 encryption and AES-GCM (FIPS 197, NIST SP 800-38D), constant-time.
//!
//! No lookup tables: up to 4 blocks are bitsliced into 8 planes (`u64`; bit 16k+j of plane b is
//! bit b of byte j of block k), and the S-box is the Boyar-Peralta boolean circuit. CTR mode
//! encrypts 4 counter blocks per pass. GHASH multiplies with masks instead of branches or tables. This is slower than
//! AES-NI, so TLS prefers ChaCha20-Poly1305 and keeps AES-GCM for interoperability.

use crate::{ct_eq, wipe};

type Planes = [u64; 8];

/// Repeats a 16-bit lane pattern across the four lanes of a plane.
const fn lanes(x: u16) -> u64 {
    (x as u64) * 0x0001_0001_0001_0001
}

fn to_planes(blocks: &[[u8; 16]]) -> Planes {
    let mut p = [0u64; 8];
    for (k, blk) in blocks.iter().enumerate() {
        for (j, &byte) in blk.iter().enumerate() {
            for (bit, plane) in p.iter_mut().enumerate() {
                *plane |= (((byte >> bit) & 1) as u64) << (16 * k + j);
            }
        }
    }
    p
}

fn from_planes(p: &Planes, k: usize) -> [u8; 16] {
    let mut b = [0u8; 16];
    for (j, byte) in b.iter_mut().enumerate() {
        for (bit, plane) in p.iter().enumerate() {
            *byte |= (((plane >> (16 * k + j)) & 1) as u8) << bit;
        }
    }
    b
}

/// SubBytes on all bytes at once with the Boyar-Peralta circuit (113 gates; as in BearSSL's
/// constant-time AES). Verified exhaustively against the definition in `tests::sbox_exhaustive`.
fn sub_bytes(q: &Planes) -> Planes {
    let (x0, x1, x2, x3, x4, x5, x6, x7) = (q[7], q[6], q[5], q[4], q[3], q[2], q[1], q[0]);
    // Top linear transformation.
    let y14 = x3 ^ x5;
    let y13 = x0 ^ x6;
    let y9 = x0 ^ x3;
    let y8 = x0 ^ x5;
    let t0 = x1 ^ x2;
    let y1 = t0 ^ x7;
    let y4 = y1 ^ x3;
    let y12 = y13 ^ y14;
    let y2 = y1 ^ x0;
    let y5 = y1 ^ x6;
    let y3 = y5 ^ y8;
    let t1 = x4 ^ y12;
    let y15 = t1 ^ x5;
    let y20 = t1 ^ x1;
    let y6 = y15 ^ x7;
    let y10 = y15 ^ t0;
    let y11 = y20 ^ y9;
    let y7 = x7 ^ y11;
    let y17 = y10 ^ y11;
    let y19 = y10 ^ y8;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let y18 = x0 ^ y16;
    // Non-linear section.
    let t2 = y12 & y15;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t5 = y4 & x7;
    let t6 = t5 ^ t2;
    let t7 = y13 & y16;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t12 = y9 & y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let t17 = t4 ^ t14;
    let t18 = t6 ^ t16;
    let t19 = t9 ^ t14;
    let t20 = t11 ^ t16;
    let t21 = t17 ^ y20;
    let t22 = t18 ^ y19;
    let t23 = t19 ^ y21;
    let t24 = t20 ^ y18;
    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;
    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41;
    let z0 = t44 & y15;
    let z1 = t37 & y6;
    let z2 = t33 & x7;
    let z3 = t43 & y16;
    let z4 = t40 & y1;
    let z5 = t29 & y7;
    let z6 = t42 & y11;
    let z7 = t45 & y17;
    let z8 = t41 & y10;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z11 = t33 & y4;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z14 = t29 & y2;
    let z15 = t42 & y9;
    let z16 = t45 & y14;
    let z17 = t41 & y8;
    // Bottom linear transformation.
    let t46 = z15 ^ z16;
    let t47 = z10 ^ z11;
    let t48 = z5 ^ z13;
    let t49 = z9 ^ z10;
    let t50 = z2 ^ z12;
    let t51 = z2 ^ z5;
    let t52 = z7 ^ z8;
    let t53 = z0 ^ z3;
    let t54 = z6 ^ z7;
    let t55 = z16 ^ z17;
    let t56 = z12 ^ t48;
    let t57 = t50 ^ t53;
    let t58 = z4 ^ t46;
    let t59 = z3 ^ t54;
    let t60 = t46 ^ t57;
    let t61 = z14 ^ t57;
    let t62 = t52 ^ t58;
    let t63 = t49 ^ t58;
    let t64 = z4 ^ t59;
    let t65 = t61 ^ t62;
    let t66 = z1 ^ t63;
    let s0 = t59 ^ t63;
    let s6 = t56 ^ !t62;
    let s7 = t48 ^ !t60;
    let t67 = t64 ^ t65;
    let s3 = t53 ^ t66;
    let s4 = t51 ^ t66;
    let s5 = t47 ^ t65;
    let s1 = t64 ^ !s3;
    let s2 = t55 ^ !t67;
    [s7, s6, s5, s4, s3, s2, s1, s0]
}

/// Byte j = row (j % 4), column (j / 4), i.e. bit 4c + r of a lane. ShiftRows rotates row r
/// left by r columns: new (r, c) <- old (r, c + r), done per lane with masks.
fn shift_rows(p: &Planes) -> Planes {
    let mut out = [0u64; 8];
    for b in 0..8 {
        let mut v = p[b] & lanes(0x1111);
        for r in 1..4u32 {
            let row = p[b] & lanes(0x1111 << r);
            let lo = lanes(0xffff >> (4 * r));
            let hi = !lo & lanes(0xffff);
            v |= (((row >> (4 * r)) & lo) | ((row << (16 - 4 * r)) & hi)) & lanes(0x1111 << r);
        }
        out[b] = v;
    }
    out
}

/// Within each column (one nibble of a lane), take the byte `k` rows further down.
fn rot_rows(p: u64, k: u32) -> u64 {
    match k {
        1 => ((p >> 1) & lanes(0x7777)) | ((p << 3) & lanes(0x8888)),
        2 => ((p >> 2) & lanes(0x3333)) | ((p << 2) & lanes(0xcccc)),
        _ => ((p >> 3) & lanes(0x1111)) | ((p << 1) & lanes(0xeeee)),
    }
}

fn mix_columns(s: &Planes) -> Planes {
    // out_r = xtime(a_r ^ a_{r+1}) ^ a_{r+1} ^ a_{r+2} ^ a_{r+3}
    let mut t = [0u64; 8];
    let mut rest = [0u64; 8];
    for b in 0..8 {
        let r1 = rot_rows(s[b], 1);
        t[b] = s[b] ^ r1;
        rest[b] = r1 ^ rot_rows(s[b], 2) ^ rot_rows(s[b], 3);
    }
    let xt = [t[7], t[0] ^ t[7], t[1], t[2] ^ t[7], t[3] ^ t[7], t[4], t[5], t[6]];
    let mut out = [0u64; 8];
    for b in 0..8 {
        out[b] = xt[b] ^ rest[b];
    }
    out
}

/// Constant-time S-box of the four bytes of a key-schedule word.
fn sub_word(w: [u8; 4]) -> [u8; 4] {
    let mut b = [0u8; 16];
    b[..4].copy_from_slice(&w);
    let s = from_planes(&sub_bytes(&to_planes(&[b])), 0);
    [s[0], s[1], s[2], s[3]]
}

/// An expanded AES-128 or AES-256 key (round keys stored bitsliced).
pub struct Aes {
    rk: [Planes; 15],
    rounds: usize,
}

impl Aes {
    /// `key` must be 16 or 32 bytes.
    pub fn new(key: &[u8]) -> Aes {
        let nk = key.len() / 4;
        assert!(key.len() == 16 || key.len() == 32, "AES key must be 16 or 32 bytes");
        let rounds = nk + 6;
        let total = 4 * (rounds + 1);
        let mut w = [[0u8; 4]; 60];
        for i in 0..nk {
            w[i].copy_from_slice(&key[4 * i..4 * i + 4]);
        }
        let mut rcon = 1u8;
        for i in nk..total {
            let mut t = w[i - 1];
            if i % nk == 0 {
                t = sub_word([t[1], t[2], t[3], t[0]]);
                t[0] ^= rcon;
                rcon = (rcon << 1) ^ (((rcon >> 7) & 1) * 0x1b);
            } else if nk > 6 && i % nk == 4 {
                t = sub_word(t);
            }
            for k in 0..4 {
                w[i][k] = w[i - nk][k] ^ t[k];
            }
        }
        let mut rk = [[0u64; 8]; 15];
        for r in 0..=rounds {
            let mut b = [0u8; 16];
            for c in 0..4 {
                b[4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c]);
            }
            rk[r] = to_planes(&[b, b, b, b]); // same key in every lane
            wipe(&mut b);
        }
        for x in w.iter_mut() {
            wipe(x);
        }
        Aes { rk, rounds }
    }

    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut out = [[0u8; 16]; 1];
        self.encrypt_blocks(&[*block], &mut out);
        out[0]
    }

    /// Encrypts 1..=4 blocks in one bitsliced pass.
    pub fn encrypt_blocks(&self, blocks: &[[u8; 16]], out: &mut [[u8; 16]]) {
        assert!(!blocks.is_empty() && blocks.len() <= 4 && out.len() >= blocks.len());
        let mut s = to_planes(blocks);
        let xor = |s: &mut Planes, k: &Planes| {
            for b in 0..8 {
                s[b] ^= k[b];
            }
        };
        xor(&mut s, &self.rk[0]);
        for r in 1..self.rounds {
            s = mix_columns(&shift_rows(&sub_bytes(&s)));
            xor(&mut s, &self.rk[r]);
        }
        s = shift_rows(&sub_bytes(&s));
        xor(&mut s, &self.rk[self.rounds]);
        for (k, o) in out.iter_mut().take(blocks.len()).enumerate() {
            *o = from_planes(&s, k);
        }
    }
}

impl Drop for Aes {
    fn drop(&mut self) {
        for p in self.rk.iter_mut() {
            *p = [0u64; 8];
        }
        core::hint::black_box(&self.rk);
    }
}

/// Carry-less 64x64 -> low 64 bits, constant-time: integer multiplies on operands with
/// 3-bit holes between data bits so carries never reach a data position (BearSSL `bmul64`).
fn bmul64(x: u64, y: u64) -> u64 {
    const M0: u64 = 0x1111_1111_1111_1111;
    let (x0, x1, x2, x3) = (x & M0, x & (M0 << 1), x & (M0 << 2), x & (M0 << 3));
    let (y0, y1, y2, y3) = (y & M0, y & (M0 << 1), y & (M0 << 2), y & (M0 << 3));
    let m = |a: u64, b: u64| a.wrapping_mul(b);
    let z0 = m(x0, y0) ^ m(x1, y3) ^ m(x2, y2) ^ m(x3, y1);
    let z1 = m(x0, y1) ^ m(x1, y0) ^ m(x2, y3) ^ m(x3, y2);
    let z2 = m(x0, y2) ^ m(x1, y1) ^ m(x2, y0) ^ m(x3, y3);
    let z3 = m(x0, y3) ^ m(x1, y2) ^ m(x2, y1) ^ m(x3, y0);
    (z0 & M0) | (z1 & (M0 << 1)) | (z2 & (M0 << 2)) | (z3 & (M0 << 3))
}

/// GF(2^128) multiplication in GCM's (bit-reflected) order: Karatsuba over `bmul64`, with the
/// high halves obtained by bit reversal, then reduction (BearSSL `ghash_ctmul64`).
fn gf128_mul(x: u128, h: u128) -> u128 {
    let (y1, y0) = ((x >> 64) as u64, x as u64);
    let (h1, h0) = ((h >> 64) as u64, h as u64);
    let (h0r, h1r) = (h0.reverse_bits(), h1.reverse_bits());
    let (h2, h2r) = (h0 ^ h1, h0r ^ h1r);
    let (y0r, y1r) = (y0.reverse_bits(), y1.reverse_bits());
    let (y2, y2r) = (y0 ^ y1, y0r ^ y1r);
    let z0 = bmul64(y0, h0);
    let z1 = bmul64(y1, h1);
    let mut z2 = bmul64(y2, h2);
    let mut z0h = bmul64(y0r, h0r);
    let mut z1h = bmul64(y1r, h1r);
    let mut z2h = bmul64(y2r, h2r);
    z2 ^= z0 ^ z1;
    z2h ^= z0h ^ z1h;
    z0h = z0h.reverse_bits() >> 1;
    z1h = z1h.reverse_bits() >> 1;
    z2h = z2h.reverse_bits() >> 1;
    let (mut v0, mut v1, mut v2, mut v3) = (z0, z0h ^ z2, z1 ^ z2h, z1h);
    v3 = (v3 << 1) | (v2 >> 63);
    v2 = (v2 << 1) | (v1 >> 63);
    v1 = (v1 << 1) | (v0 >> 63);
    v0 <<= 1;
    v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
    v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
    v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
    v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);
    ((v3 as u128) << 64) | v2 as u128
}

struct Ghash {
    h: u128,
    y: u128,
}

impl Ghash {
    fn absorb(&mut self, data: &[u8]) {
        for chunk in data.chunks(16) {
            let mut b = [0u8; 16];
            b[..chunk.len()].copy_from_slice(chunk);
            self.y = gf128_mul(self.y ^ u128::from_be_bytes(b), self.h);
        }
    }
}

pub const TAG_LEN: usize = 16;

/// AES-GCM with a 96-bit nonce.
pub struct AesGcm {
    aes: Aes,
    h: u128,
}

impl AesGcm {
    pub fn new(key: &[u8]) -> AesGcm {
        let aes = Aes::new(key);
        let h = u128::from_be_bytes(aes.encrypt_block(&[0; 16]));
        AesGcm { aes, h }
    }

    fn ctr(&self, nonce: &[u8; 12], data: &mut [u8]) {
        let mut counter = 2u32;
        for chunk in data.chunks_mut(64) {
            let n = chunk.len().div_ceil(16);
            let mut cbs = [[0u8; 16]; 4];
            for cb in cbs.iter_mut().take(n) {
                cb[..12].copy_from_slice(nonce);
                cb[12..].copy_from_slice(&counter.to_be_bytes());
                counter = counter.wrapping_add(1);
            }
            let mut ks = [[0u8; 16]; 4];
            self.aes.encrypt_blocks(&cbs[..n], &mut ks);
            for (i, d) in chunk.iter_mut().enumerate() {
                *d ^= ks[i / 16][i % 16];
            }
        }
    }

    fn tag(&self, nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> [u8; 16] {
        let mut g = Ghash { h: self.h, y: 0 };
        g.absorb(aad);
        g.absorb(ct);
        let lens = ((aad.len() as u128 * 8) << 64) | (ct.len() as u128 * 8);
        g.y = gf128_mul(g.y ^ lens, g.h);
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
        let ek = u128::from_be_bytes(self.aes.encrypt_block(&j0));
        (g.y ^ ek).to_be_bytes()
    }

    /// Encrypts in place and returns the tag.
    pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
        self.ctr(nonce, data);
        self.tag(nonce, aad, data)
    }

    /// Verifies, then decrypts in place; `data` is untouched on failure.
    pub fn open(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], tag: &[u8]) -> Result<(), ()> {
        if !ct_eq(&self.tag(nonce, aad, data), tag) {
            return Err(());
        }
        self.ctr(nonce, data);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference S-box computed the slow, obvious way (test only).
    fn sbox_ref(x: u8) -> u8 {
        let mul = |mut a: u8, mut b: u8| {
            let mut p = 0u8;
            while b != 0 {
                if b & 1 != 0 {
                    p ^= a;
                }
                a = (a << 1) ^ if a & 0x80 != 0 { 0x1b } else { 0 };
                b >>= 1;
            }
            p
        };
        let inv = if x == 0 { 0 } else { (1..=255u8).find(|&y| mul(x, y) == 1).unwrap() };
        inv ^ inv.rotate_left(1) ^ inv.rotate_left(2) ^ inv.rotate_left(3) ^ inv.rotate_left(4) ^ 0x63
    }

    /// The straightforward bit-serial GF(2^128) multiply (SP 800-38D Algorithm 1).
    fn gf128_ref(x: u128, y: u128) -> u128 {
        let (mut z, mut v) = (0u128, y);
        for i in 0..128 {
            if (x >> (127 - i)) & 1 == 1 {
                z ^= v;
            }
            v = if v & 1 == 1 { (v >> 1) ^ (0xe1u128 << 120) } else { v >> 1 };
        }
        z
    }

    #[test]
    fn gf128_matches_reference() {
        let mut s = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128;
        for _ in 0..2000 {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let (a, b) = (s, s.rotate_left(61) ^ 0x5555);
            assert_eq!(gf128_mul(a, b), gf128_ref(a, b));
        }
        assert_eq!(gf128_mul(0, 12345), 0);
        assert_eq!(gf128_mul(1u128 << 127, 0xabcdef), 0xabcdef); // 1 in GCM bit order
    }

    #[test]
    fn sbox_exhaustive() {
        for base in (0..256).step_by(16) {
            let b: [u8; 16] = core::array::from_fn(|i| (base + i) as u8);
            let s = from_planes(&sub_bytes(&to_planes(&[b])), 0);
            for i in 0..16 {
                assert_eq!(s[i], sbox_ref(b[i]), "sbox({:#x})", b[i]);
            }
        }
    }

    #[test]
    fn planes_roundtrip() {
        let b: [u8; 16] = core::array::from_fn(|i| (i * 37 + 5) as u8);
        let c: [u8; 16] = core::array::from_fn(|i| (i * 11 + 3) as u8);
        let p = to_planes(&[b, c, b, c]);
        assert_eq!(from_planes(&p, 0), b);
        assert_eq!(from_planes(&p, 3), c);
    }
}
