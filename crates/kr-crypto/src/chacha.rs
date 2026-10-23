//! ChaCha20, Poly1305 and the ChaCha20-Poly1305 AEAD (RFC 8439).
//!
//! Constant-time by construction: ChaCha is add/rotate/xor only, and Poly1305 uses 26-bit limbs
//! with branch-free carries and a masked final reduction. Tag comparison uses `ct_eq`.

use crate::{ct_eq, wipe};

fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// One 64-byte keystream block.
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut init = [0u32; 16];
    init[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    for i in 0..8 {
        init[4 + i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
    }
    init[12] = counter;
    for i in 0..3 {
        init[13 + i] = u32::from_le_bytes(nonce[4 * i..4 * i + 4].try_into().unwrap());
    }
    let mut s = init;
    for _ in 0..10 {
        quarter(&mut s, 0, 4, 8, 12);
        quarter(&mut s, 1, 5, 9, 13);
        quarter(&mut s, 2, 6, 10, 14);
        quarter(&mut s, 3, 7, 11, 15);
        quarter(&mut s, 0, 5, 10, 15);
        quarter(&mut s, 1, 6, 11, 12);
        quarter(&mut s, 2, 7, 8, 13);
        quarter(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&s[i].wrapping_add(init[i]).to_le_bytes());
    }
    out
}

/// XORs `data` in place with the keystream starting at block `counter`.
pub fn chacha20_xor(key: &[u8; 32], mut counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    for chunk in data.chunks_mut(64) {
        let mut ks = chacha20_block(key, counter, nonce);
        for (d, k) in chunk.iter_mut().zip(ks.iter()) {
            *d ^= k;
        }
        wipe(&mut ks);
        counter = counter.wrapping_add(1);
    }
}

/// Poly1305 one-time authenticator (26-bit limbs, poly1305-donna style).
pub struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
    buf: [u8; 16],
    fill: usize,
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        let le = |i: usize| u32::from_le_bytes(key[i..i + 4].try_into().unwrap());
        // r is clamped: r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
        let r = [
            le(0) & 0x03ff_ffff,
            (le(3) >> 2) & 0x03ff_ff03,
            (le(6) >> 4) & 0x03ff_c0ff,
            (le(9) >> 6) & 0x03f0_3fff,
            (le(12) >> 8) & 0x000f_ffff,
        ];
        Poly1305 { r, h: [0; 5], pad: [le(16), le(20), le(24), le(28)], buf: [0; 16], fill: 0 }
    }

    /// Absorbs one 16-byte block; `hibit` is 1<<24 for full blocks, 0 for the padded final one.
    fn block(&mut self, m: &[u8; 16], hibit: u32) {
        let le = |i: usize| u32::from_le_bytes(m[i..i + 4].try_into().unwrap());
        let [r0, r1, r2, r3, r4] = self.r;
        let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);
        let mut h = self.h;
        h[0] += le(0) & 0x03ff_ffff;
        h[1] += (le(3) >> 2) & 0x03ff_ffff;
        h[2] += (le(6) >> 4) & 0x03ff_ffff;
        h[3] += (le(9) >> 6) & 0x03ff_ffff;
        h[4] += (le(12) >> 8) | hibit;
        let m = |a: u32, b: u32| a as u64 * b as u64;
        let d0 = m(h[0], r0) + m(h[1], s4) + m(h[2], s3) + m(h[3], s2) + m(h[4], s1);
        let mut d1 = m(h[0], r1) + m(h[1], r0) + m(h[2], s4) + m(h[3], s3) + m(h[4], s2);
        let mut d2 = m(h[0], r2) + m(h[1], r1) + m(h[2], r0) + m(h[3], s4) + m(h[4], s3);
        let mut d3 = m(h[0], r3) + m(h[1], r2) + m(h[2], r1) + m(h[3], r0) + m(h[4], s4);
        let mut d4 = m(h[0], r4) + m(h[1], r3) + m(h[2], r2) + m(h[3], r1) + m(h[4], r0);
        let mut c: u32;
        c = (d0 >> 26) as u32;
        h[0] = d0 as u32 & 0x03ff_ffff;
        d1 += c as u64;
        c = (d1 >> 26) as u32;
        h[1] = d1 as u32 & 0x03ff_ffff;
        d2 += c as u64;
        c = (d2 >> 26) as u32;
        h[2] = d2 as u32 & 0x03ff_ffff;
        d3 += c as u64;
        c = (d3 >> 26) as u32;
        h[3] = d3 as u32 & 0x03ff_ffff;
        d4 += c as u64;
        c = (d4 >> 26) as u32;
        h[4] = d4 as u32 & 0x03ff_ffff;
        h[0] += c * 5;
        c = h[0] >> 26;
        h[0] &= 0x03ff_ffff;
        h[1] += c;
        self.h = h;
    }

    pub fn update(&mut self, mut data: &[u8]) {
        if self.fill > 0 {
            let n = (16 - self.fill).min(data.len());
            self.buf[self.fill..self.fill + n].copy_from_slice(&data[..n]);
            self.fill += n;
            data = &data[n..];
            if self.fill < 16 {
                return;
            }
            let b = self.buf;
            self.block(&b, 1 << 24);
            self.fill = 0;
        }
        while data.len() >= 16 {
            self.block(data[..16].try_into().unwrap(), 1 << 24);
            data = &data[16..];
        }
        self.buf[..data.len()].copy_from_slice(data);
        self.fill = data.len();
    }

    /// Absorbs zero bytes up to the next 16-byte boundary (AEAD padding).
    fn pad16(&mut self) {
        if self.fill > 0 {
            let z = [0u8; 16];
            let n = 16 - self.fill;
            self.update(&z[..n]);
        }
    }

    pub fn finalize(mut self) -> [u8; 16] {
        if self.fill > 0 {
            let mut b = [0u8; 16];
            b[..self.fill].copy_from_slice(&self.buf[..self.fill]);
            b[self.fill] = 1;
            self.block(&b, 0);
        }
        let mut h = self.h;
        // Full carry.
        let mut c = h[1] >> 26;
        h[1] &= 0x03ff_ffff;
        for i in 2..5 {
            h[i] += c;
            c = h[i] >> 26;
            h[i] &= 0x03ff_ffff;
        }
        h[0] += c * 5;
        c = h[0] >> 26;
        h[0] &= 0x03ff_ffff;
        h[1] += c;
        // g = h + 5 - 2^130; select g if it did not borrow (h >= p), constant-time.
        let mut g = [0u32; 5];
        g[0] = h[0].wrapping_add(5);
        c = g[0] >> 26;
        g[0] &= 0x03ff_ffff;
        for i in 1..5 {
            g[i] = h[i].wrapping_add(c);
            c = g[i] >> 26;
            g[i] &= 0x03ff_ffff;
        }
        g[4] = g[4].wrapping_sub(1 << 26);
        let mask = (g[4] >> 31).wrapping_sub(1); // all ones when g4 did not go negative
        for i in 0..5 {
            h[i] = (h[i] & !mask) | (g[i] & mask);
        }
        // h mod 2^128, then + pad.
        let w0 = h[0] | (h[1] << 26);
        let w1 = (h[1] >> 6) | (h[2] << 20);
        let w2 = (h[2] >> 12) | (h[3] << 14);
        let w3 = (h[3] >> 18) | (h[4] << 8);
        let mut out = [0u8; 16];
        let mut f: u64 = 0;
        for (i, w) in [w0, w1, w2, w3].into_iter().enumerate() {
            f = (f >> 32) + w as u64 + self.pad[i] as u64;
            out[4 * i..4 * i + 4].copy_from_slice(&(f as u32).to_le_bytes());
        }
        out
    }
}

pub const TAG_LEN: usize = 16;

fn aead_tag(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut otk_block = chacha20_block(key, 0, nonce);
    let mut p = Poly1305::new(otk_block[..32].try_into().unwrap());
    wipe(&mut otk_block);
    p.update(aad);
    p.pad16();
    p.update(ct);
    p.pad16();
    let mut lens = [0u8; 16];
    lens[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lens[8..].copy_from_slice(&(ct.len() as u64).to_le_bytes());
    p.update(&lens);
    p.finalize()
}

/// Encrypts `data` in place and returns the tag.
pub fn seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
    chacha20_xor(key, 1, nonce, data);
    aead_tag(key, nonce, aad, data)
}

/// Verifies the tag, then decrypts `data` in place. On failure `data` is left untouched.
pub fn open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], data: &mut [u8], tag: &[u8]) -> Result<(), ()> {
    let expect = aead_tag(key, nonce, aad, data);
    if !ct_eq(&expect, tag) {
        return Err(());
    }
    chacha20_xor(key, 1, nonce, data);
    Ok(())
}
