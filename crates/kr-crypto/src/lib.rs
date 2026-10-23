//! `kr-crypto`: the cryptography kr needs for TLS 1.3 and cluster PKI (ADR-020).
//!
//! `no_std`, no dependencies, no `unsafe`. Secret-dependent code is written to be constant-time
//! (no secret-dependent branches or table indices); see each module for its specific notes.
//! Everything is tested against RFC vectors and differentially against OpenSSL / pyca.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod chacha;
pub mod field25519;
pub mod hmac;
pub mod sha2;
pub mod x25519;

/// Constant-time equality of equal-length slices (false when lengths differ; lengths are public).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let d = a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y));
    core::hint::black_box(d) == 0
}

/// Best-effort zeroing of key material (black_box keeps the writes from being optimised away).
pub fn wipe(b: &mut [u8]) {
    for x in b.iter_mut() {
        *x = 0;
    }
    core::hint::black_box(b);
}

#[cfg(test)]
pub(crate) fn unhex(s: &str) -> alloc::vec::Vec<u8> {
    let s: alloc::string::String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
