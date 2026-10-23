//! NIST P-256: ECDSA (with RFC 6979 deterministic nonces) and ECDH, on the generic curve code
//! in `ecc` (complete formulas, constant-time ladder).

use crate::bigint::{U256, P256_N as N};
use crate::ecc::{self, Curve};
use crate::hmac::Hmac;
use crate::sha2::Sha256;
use alloc::vec::Vec;

const C: &Curve<4> = &ecc::P256;

fn encode(x: &U256, y: &U256) -> [u8; 65] {
    let mut out = [0u8; 65];
    out[0] = 4;
    out[1..33].copy_from_slice(&x.to_be_bytes());
    out[33..].copy_from_slice(&y.to_be_bytes());
    out
}

/// A private scalar in [1, n-1].
pub struct SecretKey(U256);

impl SecretKey {
    /// Accepts a 32-byte big-endian scalar in [1, n-1].
    pub fn from_bytes(b: &[u8; 32]) -> Option<SecretKey> {
        let d = U256::from_be_bytes(b);
        (!d.is_zero() && d.ct_lt(&N.m)).then_some(SecretKey(d))
    }

    /// Derives a key from 48 uniformly random bytes (reduced mod n-1, plus 1: negligible bias).
    pub fn from_seed(seed: &[u8; 48]) -> SecretKey {
        let mut wide = [0u8; 64];
        for (i, b) in seed.iter().rev().enumerate() {
            wide[i] = *b; // little-endian for reduce_wide_le
        }
        let d = N.reduce_wide_le(&wide);
        crate::wipe(&mut wide);
        // Map 0 to 1 (probability 2^-256): avoid the identity without a branch on d.
        let zero = d.is_zero() as u64;
        SecretKey(U256::select(&d, &U256::ONE, zero))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_be_bytes()
    }

    /// Uncompressed public key (65 bytes).
    pub fn public_key(&self) -> [u8; 65] {
        let (x, y) = C.to_affine(&C.mul(&C.generator(), &self.0)).expect("d in [1, n-1]");
        encode(&x, &y)
    }

    /// ECDH: the x-coordinate of d * peer. Errors on an invalid or identity point.
    pub fn ecdh(&self, peer: &[u8]) -> Result<[u8; 32], ()> {
        let q = C.decode(peer).ok_or(())?;
        let (x, _) = C.to_affine(&C.mul(&q, &self.0)).ok_or(())?;
        Ok(x.to_be_bytes())
    }

    /// ECDSA over SHA-256 of `msg`; returns (r, s) as 32-byte big-endian values.
    pub fn sign(&self, msg: &[u8]) -> ([u8; 32], [u8; 32]) {
        let mut h = Sha256::new();
        h.update(msg);
        self.sign_digest(&h.finalize())
    }

    /// ECDSA over a precomputed SHA-256 digest, nonce from RFC 6979 (HMAC-SHA256).
    pub fn sign_digest(&self, digest: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let e = N.reduce(&U256::from_be_bytes(digest));
        let mut drbg = Rfc6979::new(&self.0.to_be_bytes(), &e.to_be_bytes());
        loop {
            let k = drbg.next();
            if k.is_zero() || !k.ct_lt(&N.m) {
                continue;
            }
            let Some((x, _)) = C.to_affine(&C.mul(&C.generator(), &k)) else { continue };
            let r = N.reduce(&x);
            if r.is_zero() {
                continue;
            }
            // s = k^-1 (e + r d) mod n
            let km = N.to_mont(&k);
            let rd = N.mul(&N.to_mont(&r), &N.to_mont(&self.0));
            let sum = N.add(&N.to_mont(&e), &rd);
            let s = N.from_mont(&N.mul(&N.inv(&km), &sum));
            if s.is_zero() {
                continue;
            }
            return (r.to_be_bytes(), s.to_be_bytes());
        }
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0 = U256::ZERO;
        core::hint::black_box(&self.0);
    }
}

/// HMAC-DRBG nonce generator of RFC 6979 section 3.2 (qlen = hlen = 256).
struct Rfc6979 {
    k: [u8; 32],
    v: [u8; 32],
}

impl Rfc6979 {
    fn new(x: &[u8; 32], h: &[u8; 32]) -> Rfc6979 {
        let mut s = Rfc6979 { k: [0; 32], v: [1; 32] };
        for tag in [0u8, 1] {
            let mut m = Hmac::<Sha256>::new(&s.k);
            m.update(&s.v);
            m.update(&[tag]);
            m.update(x);
            m.update(h);
            m.finish_into(&mut s.k);
            s.v = s.hmac_v();
        }
        s
    }

    fn hmac_v(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut m = Hmac::<Sha256>::new(&self.k);
        m.update(&self.v);
        m.finish_into(&mut out);
        out
    }

    /// Next candidate; after a rejected candidate the state is updated as the RFC requires.
    fn next(&mut self) -> U256 {
        self.v = self.hmac_v();
        let k = U256::from_be_bytes(&self.v);
        let mut m = Hmac::<Sha256>::new(&self.k);
        m.update(&self.v);
        m.update(&[0]);
        m.finish_into(&mut self.k);
        self.v = self.hmac_v();
        k
    }
}

/// Verifies an ECDSA-SHA256 signature `(r, s)` by the uncompressed public key `pk`.
pub fn verify(pk: &[u8], msg: &[u8], r: &[u8; 32], s: &[u8; 32]) -> bool {
    let mut h = Sha256::new();
    h.update(msg);
    verify_digest(pk, &h.finalize(), r, s)
}

pub fn verify_digest(pk: &[u8], digest: &[u8; 32], r: &[u8; 32], s: &[u8; 32]) -> bool {
    C.verify_digest(pk, digest, r, s)
}

// ---- DER encoding of ECDSA signatures (SEQUENCE { INTEGER r, INTEGER s }) ----

fn der_int(v: &[u8; 32], out: &mut Vec<u8>) {
    let mut i = 0;
    while i < 31 && v[i] == 0 {
        i += 1;
    }
    let pad = v[i] & 0x80 != 0;
    out.push(0x02);
    out.push((32 - i + pad as usize) as u8);
    if pad {
        out.push(0);
    }
    out.extend_from_slice(&v[i..]);
}

pub fn sig_to_der(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    let mut body = Vec::with_capacity(72);
    der_int(r, &mut body);
    der_int(s, &mut body);
    let mut out = Vec::with_capacity(body.len() + 2);
    out.push(0x30);
    out.push(body.len() as u8);
    out.extend_from_slice(&body);
    out
}

/// Strict DER decoding (minimal lengths and integers, positive, at most 32 bytes of value).
pub fn sig_from_der(der: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let (r, s) = ecc::sig_from_der(der)?;
    if r.len() > 32 || s.len() > 32 {
        return None;
    }
    let (mut ro, mut so) = ([0u8; 32], [0u8; 32]);
    ro[32 - r.len()..].copy_from_slice(r);
    so[32 - s.len()..].copy_from_slice(s);
    Some((ro, so))
}
