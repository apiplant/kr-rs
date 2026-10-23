//! AES-128/256 encryption and AES-GCM (FIPS 197, NIST SP 800-38D), constant-time.
//!
//! No lookup tables: the 16 state bytes are bitsliced into 8 planes (`u16`, bit j of plane b is
//! bit b of byte j), and the S-box is computed as inversion in GF(2^8) (x^254) followed by the
//! affine map. GHASH multiplies with masks instead of branches or tables. This is slower than
//! AES-NI, so TLS prefers ChaCha20-Poly1305 and keeps AES-GCM for interoperability.

use crate::{ct_eq, wipe};

type Planes = [u16; 8];

fn to_planes(b: &[u8; 16]) -> Planes {
    let mut p = [0u16; 8];
    for (j, &byte) in b.iter().enumerate() {
        for (bit, plane) in p.iter_mut().enumerate() {
            *plane |= (((byte >> bit) & 1) as u16) << j;
        }
    }
    p
}

fn from_planes(p: &Planes) -> [u8; 16] {
    let mut b = [0u8; 16];
    for (j, byte) in b.iter_mut().enumerate() {
        for (bit, plane) in p.iter().enumerate() {
            *byte |= (((plane >> j) & 1) as u8) << bit;
        }
    }
    b
}

/// Bitsliced GF(2^8) multiplication modulo x^8 + x^4 + x^3 + x + 1.
fn gf_mul(a: &Planes, b: &Planes) -> Planes {
    let mut c = [0u16; 15];
    for i in 0..8 {
        for j in 0..8 {
            c[i + j] ^= a[i] & b[j];
        }
    }
    for k in (8..15).rev() {
        let t = c[k];
        c[k - 8] ^= t;
        c[k - 7] ^= t;
        c[k - 5] ^= t;
        c[k - 4] ^= t;
    }
    c[..8].try_into().unwrap()
}

/// SubBytes on all 16 bytes at once: x^254 (inverse, 0 -> 0), then the affine transform.
fn sub_bytes(x: &Planes) -> Planes {
    let x2 = gf_mul(x, x);
    let x3 = gf_mul(&x2, x);
    let x6 = gf_mul(&x3, &x3);
    let x12 = gf_mul(&x6, &x6);
    let x15 = gf_mul(&x12, &x3);
    let mut x240 = x15;
    for _ in 0..4 {
        x240 = gf_mul(&x240, &x240);
    }
    let x252 = gf_mul(&x240, &x12);
    let inv = gf_mul(&x252, &x2);
    let mut out = [0u16; 8];
    for i in 0..8 {
        let c = if (0x63 >> i) & 1 == 1 { 0xffff } else { 0 }; // public constant
        out[i] = inv[i] ^ inv[(i + 7) % 8] ^ inv[(i + 6) % 8] ^ inv[(i + 5) % 8] ^ inv[(i + 4) % 8] ^ c;
    }
    out
}

/// Byte j = row (j % 4), column (j / 4). ShiftRows: new (r, c) <- old (r, c + r).
fn shift_rows(p: &Planes) -> Planes {
    let mut out = [0u16; 8];
    for j in 0..16 {
        let (r, c) = (j % 4, j / 4);
        let src = r + 4 * ((c + r) % 4);
        for b in 0..8 {
            out[b] |= ((p[b] >> src) & 1) << j;
        }
    }
    out
}

/// Within each column (one nibble of a plane), take the byte `k` rows further down.
fn rot_rows(p: u16, k: u32) -> u16 {
    match k {
        1 => ((p >> 1) & 0x7777) | ((p << 3) & 0x8888),
        2 => ((p >> 2) & 0x3333) | ((p << 2) & 0xcccc),
        _ => ((p >> 3) & 0x1111) | ((p << 1) & 0xeeee),
    }
}

fn mix_columns(s: &Planes) -> Planes {
    // out_r = xtime(a_r ^ a_{r+1}) ^ a_{r+1} ^ a_{r+2} ^ a_{r+3}
    let mut t = [0u16; 8];
    let mut rest = [0u16; 8];
    for b in 0..8 {
        let r1 = rot_rows(s[b], 1);
        t[b] = s[b] ^ r1;
        rest[b] = r1 ^ rot_rows(s[b], 2) ^ rot_rows(s[b], 3);
    }
    let xt = [t[7], t[0] ^ t[7], t[1], t[2] ^ t[7], t[3] ^ t[7], t[4], t[5], t[6]];
    let mut out = [0u16; 8];
    for b in 0..8 {
        out[b] = xt[b] ^ rest[b];
    }
    out
}

/// Constant-time S-box of the four bytes of a key-schedule word.
fn sub_word(w: [u8; 4]) -> [u8; 4] {
    let mut b = [0u8; 16];
    b[..4].copy_from_slice(&w);
    let s = from_planes(&sub_bytes(&to_planes(&b)));
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
        let mut rk = [[0u16; 8]; 15];
        for r in 0..=rounds {
            let mut b = [0u8; 16];
            for c in 0..4 {
                b[4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c]);
            }
            rk[r] = to_planes(&b);
            wipe(&mut b);
        }
        for x in w.iter_mut() {
            wipe(x);
        }
        Aes { rk, rounds }
    }

    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut s = to_planes(block);
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
        from_planes(&s)
    }
}

impl Drop for Aes {
    fn drop(&mut self) {
        for p in self.rk.iter_mut() {
            *p = [0; 8];
        }
        core::hint::black_box(&self.rk);
    }
}

/// GF(2^128) multiplication in GCM's bit order, branch- and table-free.
fn gf128_mul(x: u128, y: u128) -> u128 {
    let mut z = 0u128;
    let mut v = y;
    for i in 0..128 {
        let bit = (x >> (127 - i)) & 1;
        z ^= v & 0u128.wrapping_sub(bit);
        let lsb = v & 1;
        v = (v >> 1) ^ (0xe1u128 << 120 & 0u128.wrapping_sub(lsb));
    }
    z
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
        let mut cb = [0u8; 16];
        cb[..12].copy_from_slice(nonce);
        let mut counter = 2u32;
        for chunk in data.chunks_mut(16) {
            cb[12..].copy_from_slice(&counter.to_be_bytes());
            let ks = self.aes.encrypt_block(&cb);
            for (d, k) in chunk.iter_mut().zip(ks.iter()) {
                *d ^= k;
            }
            counter = counter.wrapping_add(1);
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

    #[test]
    fn sbox_exhaustive() {
        for base in (0..256).step_by(16) {
            let b: [u8; 16] = core::array::from_fn(|i| (base + i) as u8);
            let s = from_planes(&sub_bytes(&to_planes(&b)));
            for i in 0..16 {
                assert_eq!(s[i], sbox_ref(b[i]), "sbox({:#x})", b[i]);
            }
        }
    }

    #[test]
    fn planes_roundtrip() {
        let b: [u8; 16] = core::array::from_fn(|i| (i * 37 + 5) as u8);
        assert_eq!(from_planes(&to_planes(&b)), b);
    }
}
