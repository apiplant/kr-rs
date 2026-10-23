//! X25519 Diffie-Hellman (RFC 7748): a Montgomery ladder with constant-time swaps.

use crate::field25519::Fe;

pub const BASEPOINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// Scalar multiplication `k * u`. The scalar is clamped as RFC 7748 requires.
pub fn x25519(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut k = *k;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    let x1 = Fe::from_bytes(u);
    let (mut x2, mut z2, mut x3, mut z3) = (Fe::ONE, Fe::ZERO, x1, Fe::ONE);
    let mut swap = 0u64;
    for t in (0..255).rev() {
        let bit = ((k[t >> 3] >> (t & 7)) & 1) as u64;
        swap ^= bit;
        Fe::cswap(&mut x2, &mut x3, swap);
        Fe::cswap(&mut z2, &mut z3, swap);
        swap = bit;
        let a = x2.add(&z2);
        let aa = a.square();
        let b = x2.sub(&z2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        x3 = da.add(&cb).square();
        z3 = x1.mul(&da.sub(&cb).square());
        x2 = aa.mul(&bb);
        z2 = e.mul(&aa.add(&e.mul_small(121665)));
    }
    Fe::cswap(&mut x2, &mut x3, swap);
    Fe::cswap(&mut z2, &mut z3, swap);
    crate::wipe(&mut k);
    x2.mul(&z2.invert()).to_bytes()
}

/// Public key for a private scalar.
pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    x25519(secret, &BASEPOINT)
}

/// Shared secret; Err for an all-zero result (small-order peer key), which TLS must reject.
pub fn shared(secret: &[u8; 32], peer: &[u8; 32]) -> Result<[u8; 32], ()> {
    let s = x25519(secret, peer);
    if crate::ct_eq(&s, &[0u8; 32]) {
        Err(())
    } else {
        Ok(s)
    }
}
