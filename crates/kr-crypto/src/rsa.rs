//! RSA signature verification (RFC 8017): PKCS#1 v1.5 and PSS with SHA-256/384/512.
//!
//! Verification only; every input is public, so this code is not constant-time. Moduli of
//! 2048..=8192 bits and odd public exponents up to 2^32 are accepted. PKCS#1 v1.5 is checked
//! by re-encoding the expected block and comparing, never by parsing the decrypted one.

use crate::der::{self, Reader};
use crate::sha2::{Sha256, Sha384, Sha512};
use alloc::vec;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    pub fn len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }

    pub fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        macro_rules! h {
            ($t:ty) => {{
                let mut h = <$t>::new();
                for p in parts {
                    h.update(p);
                }
                h.finalize().to_vec()
            }};
        }
        match self {
            HashAlg::Sha256 => h!(Sha256),
            HashAlg::Sha384 => h!(Sha384),
            HashAlg::Sha512 => h!(Sha512),
        }
    }

    /// DER DigestInfo prefix (RFC 8017 section 9.2, note 1).
    fn digest_info_prefix(self) -> &'static [u8] {
        match self {
            HashAlg::Sha256 => &[0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20],
            HashAlg::Sha384 => &[0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30],
            HashAlg::Sha512 => &[0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    /// Big-endian modulus without leading zeros.
    n: Vec<u8>,
    e: u64,
}

impl PublicKey {
    /// From the DER `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`.
    pub fn from_pkcs1(der_bytes: &[u8]) -> Option<PublicKey> {
        let mut r = Reader::new(der_bytes);
        let mut s = r.sequence().ok()?;
        r.finish().ok()?;
        let n = s.integer().ok()?;
        let e = s.small_uint().ok()?;
        s.finish().ok()?;
        if n[0] & 0x80 != 0 {
            return None; // negative
        }
        let n = if n[0] == 0 { &n[1..] } else { n };
        let bits = n.len() * 8 - n[0].leading_zeros() as usize;
        if !(2048..=8192).contains(&bits) || n[n.len() - 1] & 1 == 0 || e < 3 || e & 1 == 0 || e > u32::MAX as u64 {
            return None;
        }
        Some(PublicKey { n: n.to_vec(), e })
    }

    pub fn to_pkcs1(&self) -> Vec<u8> {
        let mut out = Vec::new();
        der::nested(&mut out, der::SEQUENCE, |s| {
            der::uint(s, &self.n);
            der::uint(s, &self.e.to_be_bytes());
        });
        out
    }

    pub fn modulus_len(&self) -> usize {
        self.n.len()
    }

    /// s^e mod n as a big-endian block of the modulus length; None if s >= n.
    fn public_op(&self, sig: &[u8]) -> Option<Vec<u8>> {
        if sig.len() != self.n.len() {
            return None;
        }
        let n = Nat::from_be(&self.n);
        let s = Nat::from_be(sig);
        if !s.lt(&n) {
            return None;
        }
        let m = Mont::new(&n);
        Some(m.pow(&s, self.e).to_be(self.n.len()))
    }

    /// RSASSA-PKCS1-v1_5 verification of `msg`.
    pub fn verify_pkcs1v15(&self, hash: HashAlg, msg: &[u8], sig: &[u8]) -> bool {
        let Some(em) = self.public_op(sig) else { return false };
        let digest = hash.digest(&[msg]);
        let t_len = hash.digest_info_prefix().len() + digest.len();
        if em.len() < t_len + 11 {
            return false;
        }
        let mut expect = vec![0xffu8; em.len()];
        expect[0] = 0;
        expect[1] = 1;
        let t = em.len() - t_len;
        expect[t - 1] = 0;
        expect[t..t + hash.digest_info_prefix().len()].copy_from_slice(hash.digest_info_prefix());
        expect[em.len() - digest.len()..].copy_from_slice(&digest);
        em == expect
    }

    /// RSASSA-PSS verification with MGF1 using the same hash, and salt length `salt_len`
    /// (TLS 1.3 and most certificates use salt length = hash length).
    pub fn verify_pss(&self, hash: HashAlg, msg: &[u8], sig: &[u8], salt_len: usize) -> bool {
        let Some(em_full) = self.public_op(sig) else { return false };
        let mod_bits = self.n.len() * 8 - self.n[0].leading_zeros() as usize;
        let em_bits = mod_bits - 1;
        let em_len = em_bits.div_ceil(8);
        // EM is the low em_len bytes; any extra leading byte must be zero.
        let (lead, em) = em_full.split_at(em_full.len() - em_len);
        if lead.iter().any(|&b| b != 0) {
            return false;
        }
        let h_len = hash.len();
        if em_len < h_len + salt_len + 2 || em[em_len - 1] != 0xbc {
            return false;
        }
        let (masked_db, rest) = em.split_at(em_len - h_len - 1);
        let h = &rest[..h_len];
        let unused = 8 * em_len - em_bits;
        if unused > 0 && masked_db[0] >> (8 - unused) != 0 {
            return false;
        }
        let mut db = mgf1(hash, h, masked_db.len());
        for (d, m) in db.iter_mut().zip(masked_db) {
            *d ^= m;
        }
        if unused > 0 {
            db[0] &= 0xff >> unused;
        }
        let ps_len = em_len - h_len - salt_len - 2;
        if db[..ps_len].iter().any(|&b| b != 0) || db[ps_len] != 1 {
            return false;
        }
        let salt = &db[db.len() - salt_len..];
        let m_hash = hash.digest(&[msg]);
        let h2 = hash.digest(&[&[0u8; 8], &m_hash, salt]);
        h == &h2[..]
    }
}

fn mgf1(hash: HashAlg, seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 64);
    let mut counter = 0u32;
    while out.len() < len {
        out.extend_from_slice(&hash.digest(&[seed, &counter.to_be_bytes()]));
        counter += 1;
    }
    out.truncate(len);
    out
}

// ---- minimal arbitrary-precision naturals (little-endian u64 limbs) ----

#[derive(Clone, Debug, PartialEq, Eq)]
struct Nat(Vec<u64>);

impl Nat {
    fn from_be(b: &[u8]) -> Nat {
        let mut limbs = vec![0u64; b.len().div_ceil(8)];
        for (i, &byte) in b.iter().rev().enumerate() {
            limbs[i / 8] |= (byte as u64) << (8 * (i % 8));
        }
        Nat(limbs)
    }

    fn to_be(&self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        for i in 0..len {
            let limb = self.0.get(i / 8).copied().unwrap_or(0);
            out[len - 1 - i] = (limb >> (8 * (i % 8))) as u8;
        }
        out
    }

    fn lt(&self, o: &Nat) -> bool {
        let n = self.0.len().max(o.0.len());
        for i in (0..n).rev() {
            let (a, b) = (self.0.get(i).copied().unwrap_or(0), o.0.get(i).copied().unwrap_or(0));
            if a != b {
                return a < b;
            }
        }
        false
    }
}

/// Montgomery arithmetic modulo an odd n with k limbs (R = 2^(64k)).
struct Mont {
    n: Vec<u64>,
    n0: u64,
    r2: Vec<u64>,
}

impl Mont {
    fn new(n: &Nat) -> Mont {
        let mut nl = n.0.clone();
        while nl.len() > 1 && *nl.last().unwrap() == 0 {
            nl.pop();
        }
        // n0 = -n^-1 mod 2^64 by Newton iteration.
        let mut inv = 1u64;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(nl[0].wrapping_mul(inv)));
        }
        let k = nl.len();
        let mut m = Mont { n: nl, n0: inv.wrapping_neg(), r2: Vec::new() };
        // R^2 mod n by doubling 1 a total of 2 * 64k times.
        let mut x = vec![0u64; k];
        x[0] = 1;
        for _ in 0..128 * k {
            m.double_mod(&mut x);
        }
        m.r2 = x;
        m
    }

    fn double_mod(&self, x: &mut [u64]) {
        let mut carry = 0u64;
        for l in x.iter_mut() {
            let next = *l >> 63;
            *l = (*l << 1) | carry;
            carry = next;
        }
        if carry == 1 || !lt_limbs(x, &self.n) {
            sub_limbs(x, &self.n);
        }
    }

    fn mul(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let k = self.n.len();
        let mut t = vec![0u64; k + 2];
        for i in 0..k {
            let mut c = 0u128;
            for j in 0..k {
                let s = t[j] as u128 + a[j] as u128 * b[i] as u128 + c;
                t[j] = s as u64;
                c = s >> 64;
            }
            let s = t[k] as u128 + c;
            t[k] = s as u64;
            t[k + 1] = (s >> 64) as u64;
            let q = t[0].wrapping_mul(self.n0);
            let s = t[0] as u128 + q as u128 * self.n[0] as u128;
            let mut c = s >> 64;
            for j in 1..k {
                let s = t[j] as u128 + q as u128 * self.n[j] as u128 + c;
                t[j - 1] = s as u64;
                c = s >> 64;
            }
            let s = t[k] as u128 + c;
            t[k - 1] = s as u64;
            t[k] = t[k + 1] + (s >> 64) as u64;
        }
        let hi = t[k];
        t.truncate(k);
        if hi != 0 || !lt_limbs(&t, &self.n) {
            sub_limbs(&mut t, &self.n);
        }
        t
    }

    /// base^e mod n for a plain-form base < n.
    fn pow(&self, base: &Nat, e: u64) -> Nat {
        let k = self.n.len();
        let mut b = base.0.clone();
        b.resize(k, 0);
        let bm = self.mul(&b, &self.r2);
        let mut acc = bm.clone();
        let top = 63 - e.leading_zeros();
        for i in (0..top).rev() {
            acc = self.mul(&acc, &acc);
            if (e >> i) & 1 == 1 {
                acc = self.mul(&acc, &bm);
            }
        }
        let mut one = vec![0u64; k];
        one[0] = 1;
        Nat(self.mul(&acc, &one))
    }
}

fn lt_limbs(a: &[u64], b: &[u64]) -> bool {
    for i in (0..a.len()).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

fn sub_limbs(a: &mut [u64], b: &[u64]) {
    let mut borrow = 0u64;
    for i in 0..a.len() {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        a[i] = d2;
        borrow = (b1 | b2) as u64;
    }
}
