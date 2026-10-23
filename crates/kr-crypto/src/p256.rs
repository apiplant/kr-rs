//! NIST P-256: ECDSA (with RFC 6979 deterministic nonces) and ECDH.
//!
//! Points use projective coordinates with the complete addition formula of Renes, Costello and
//! Batina (2016, Algorithm 4, a = -3), so there are no special cases to branch on. Scalar
//! multiplication is a double-and-add-always ladder with constant-time selection. Field values
//! are in Montgomery form throughout.

use crate::bigint::{U256, P256_N as N, P256_P as P};
use crate::hmac::Hmac;
use crate::sha2::Sha256;
use alloc::vec::Vec;

const B_BE: [u8; 32] = hex32("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
const GX_BE: [u8; 32] = hex32("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
const GY_BE: [u8; 32] = hex32("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");

const fn nib(c: u8) -> u8 {
    if c <= b'9' {
        c - b'0'
    } else {
        c - b'a' + 10
    }
}

const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nib(b[2 * i]) << 4 | nib(b[2 * i + 1]);
        i += 1;
    }
    out
}

#[derive(Clone, Copy, Debug)]
struct Point {
    x: U256,
    y: U256,
    z: U256,
}

fn fe(b: &[u8; 32]) -> U256 {
    P.to_mont(&U256::from_be_bytes(b))
}

impl Point {
    fn identity() -> Point {
        Point { x: U256::ZERO, y: P.one(), z: U256::ZERO }
    }

    fn generator() -> Point {
        Point { x: fe(&GX_BE), y: fe(&GY_BE), z: P.one() }
    }

    /// Complete addition (RCB16 Algorithm 4, a = -3). Also correct for doubling and identity.
    fn add(&self, o: &Point) -> Point {
        let b = fe(&B_BE);
        let (m, a, s) = (|x: &U256, y: &U256| P.mul(x, y), |x: &U256, y: &U256| P.add(x, y), |x: &U256, y: &U256| P.sub(x, y));
        let (x1, y1, z1, x2, y2, z2) = (&self.x, &self.y, &self.z, &o.x, &o.y, &o.z);
        let mut t0 = m(x1, x2);
        let mut t1 = m(y1, y2);
        let mut t2 = m(z1, z2);
        let mut t3 = a(x1, y1);
        let mut t4 = a(x2, y2);
        t3 = m(&t3, &t4);
        t4 = a(&t0, &t1);
        t3 = s(&t3, &t4);
        t4 = a(y1, z1);
        let mut x3 = a(y2, z2);
        t4 = m(&t4, &x3);
        x3 = a(&t1, &t2);
        t4 = s(&t4, &x3);
        x3 = a(x1, z1);
        let mut y3 = a(x2, z2);
        x3 = m(&x3, &y3);
        y3 = a(&t0, &t2);
        y3 = s(&x3, &y3);
        let mut z3 = m(&b, &t2);
        x3 = s(&y3, &z3);
        z3 = a(&x3, &x3);
        x3 = a(&x3, &z3);
        z3 = s(&t1, &x3);
        x3 = a(&t1, &x3);
        y3 = m(&b, &y3);
        t1 = a(&t2, &t2);
        t2 = a(&t1, &t2);
        y3 = s(&y3, &t2);
        y3 = s(&y3, &t0);
        t1 = a(&y3, &y3);
        y3 = a(&t1, &y3);
        t1 = a(&t0, &t0);
        t0 = a(&t1, &t0);
        t0 = s(&t0, &t2);
        t1 = m(&t4, &y3);
        t2 = m(&t0, &y3);
        y3 = m(&x3, &z3);
        y3 = a(&y3, &t2);
        x3 = m(&t3, &x3);
        x3 = s(&x3, &t1);
        z3 = m(&t4, &z3);
        t1 = m(&t3, &t0);
        z3 = a(&z3, &t1);
        Point { x: x3, y: y3, z: z3 }
    }

    fn select(a: &Point, b: &Point, choose: u64) -> Point {
        Point { x: U256::select(&a.x, &b.x, choose), y: U256::select(&a.y, &b.y, choose), z: U256::select(&a.z, &b.z, choose) }
    }

    /// k * self, constant-time in k (k is a plain integer, any 256-bit value).
    fn mul(&self, k: &U256) -> Point {
        let mut r = Point::identity();
        for i in (0..256).rev() {
            r = r.add(&r);
            let t = r.add(self);
            r = Point::select(&r, &t, k.bit(i));
        }
        r
    }

    /// Affine (x, y) in plain form; None for the identity.
    fn to_affine(&self) -> Option<(U256, U256)> {
        if self.z.is_zero() {
            return None;
        }
        let zi = P.inv(&self.z);
        Some((P.from_mont(&P.mul(&self.x, &zi)), P.from_mont(&P.mul(&self.y, &zi))))
    }

    /// Decodes an uncompressed SEC1 point (0x04 || X || Y), checking range and the curve equation.
    fn decode(b: &[u8]) -> Option<Point> {
        if b.len() != 65 || b[0] != 4 {
            return None;
        }
        let x = U256::from_be_bytes(b[1..33].try_into().unwrap());
        let y = U256::from_be_bytes(b[33..].try_into().unwrap());
        if !x.ct_lt(&P.m) || !y.ct_lt(&P.m) {
            return None;
        }
        let (xm, ym) = (P.to_mont(&x), P.to_mont(&y));
        // y^2 == x^3 - 3x + b
        let lhs = P.mul(&ym, &ym);
        let x3 = P.mul(&P.mul(&xm, &xm), &xm);
        let three_x = P.add(&P.add(&xm, &xm), &xm);
        let rhs = P.add(&P.sub(&x3, &three_x), &fe(&B_BE));
        if lhs != rhs {
            return None;
        }
        Some(Point { x: xm, y: ym, z: P.one() })
    }

    fn encode(x: &U256, y: &U256) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[0] = 4;
        out[1..33].copy_from_slice(&x.to_be_bytes());
        out[33..].copy_from_slice(&y.to_be_bytes());
        out
    }
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
        let (x, y) = Point::generator().mul(&self.0).to_affine().expect("d in [1, n-1]");
        Point::encode(&x, &y)
    }

    /// ECDH: the x-coordinate of d * peer. Errors on an invalid or identity point.
    pub fn ecdh(&self, peer: &[u8]) -> Result<[u8; 32], ()> {
        let q = Point::decode(peer).ok_or(())?;
        let (x, _) = q.mul(&self.0).to_affine().ok_or(())?;
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
            let Some((x, _)) = Point::generator().mul(&k).to_affine() else { continue };
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
    let Some(q) = Point::decode(pk) else { return false };
    let (r, s) = (U256::from_be_bytes(r), U256::from_be_bytes(s));
    if r.is_zero() || s.is_zero() || !r.ct_lt(&N.m) || !s.ct_lt(&N.m) {
        return false;
    }
    let e = N.reduce(&U256::from_be_bytes(digest));
    let w = N.inv(&N.to_mont(&s));
    let u1 = N.from_mont(&N.mul(&N.to_mont(&e), &w));
    let u2 = N.from_mont(&N.mul(&N.to_mont(&r), &w));
    let pt = Point::generator().mul(&u1).add(&q.mul(&u2));
    match pt.to_affine() {
        Some((x, _)) => N.reduce(&x) == r,
        None => false,
    }
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
    if der.len() < 8 || der[0] != 0x30 || der[1] as usize != der.len() - 2 || der[1] >= 0x80 {
        return None;
    }
    let mut rest = &der[2..];
    let mut take = || -> Option<[u8; 32]> {
        if rest.len() < 2 || rest[0] != 0x02 {
            return None;
        }
        let len = rest[1] as usize;
        if len == 0 || len > 33 || rest.len() < 2 + len {
            return None;
        }
        let v = &rest[2..2 + len];
        if v[0] & 0x80 != 0 || (len > 1 && v[0] == 0 && v[1] & 0x80 == 0) {
            return None; // negative or non-minimal
        }
        let v = if v[0] == 0 && len > 1 { &v[1..] } else { v };
        if v.len() > 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out[32 - v.len()..].copy_from_slice(v);
        rest = &rest[2 + len..];
        Some(out)
    };
    let r = take()?;
    let s = take()?;
    rest.is_empty().then_some((r, s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_on_curve_and_order() {
        let g = Point::generator();
        let (x, y) = g.to_affine().unwrap();
        assert!(Point::decode(&Point::encode(&x, &y)).is_some());
        // n * G = identity
        assert!(g.mul(&N.m).to_affine().is_none());
    }
}
