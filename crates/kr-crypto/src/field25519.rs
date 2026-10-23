//! Arithmetic modulo p = 2^255 - 19 with five 51-bit limbs (shared by X25519 and Ed25519).
//!
//! Every operation is branch-free in the limb values. Elements are kept loosely reduced
//! (limbs < 2^52) between operations; `to_bytes` produces the canonical encoding.

const MASK: u64 = (1 << 51) - 1;

#[derive(Clone, Copy, Debug)]
pub struct Fe(pub [u64; 5]);

impl Fe {
    pub const ZERO: Fe = Fe([0; 5]);
    pub const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    /// Decodes 32 little-endian bytes, ignoring the top bit (RFC 7748).
    pub fn from_bytes(b: &[u8; 32]) -> Fe {
        let le = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        Fe([
            le(0) & MASK,
            (le(6) >> 3) & MASK,
            (le(12) >> 6) & MASK,
            (le(19) >> 1) & MASK,
            (le(24) >> 12) & MASK,
        ])
    }

    /// Canonical little-endian encoding (fully reduced mod p).
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut h = self.carry().0;
        // q = 1 iff h >= p: add 19 and see whether it carries past 2^255.
        let mut q = (h[0] + 19) >> 51;
        q = (h[1] + q) >> 51;
        q = (h[2] + q) >> 51;
        q = (h[3] + q) >> 51;
        q = (h[4] + q) >> 51;
        h[0] += 19 * q;
        for i in 0..4 {
            h[i + 1] += h[i] >> 51;
            h[i] &= MASK;
        }
        h[4] &= MASK;
        let mut out = [0u8; 32];
        let words = [
            h[0] | (h[1] << 51),
            (h[1] >> 13) | (h[2] << 38),
            (h[2] >> 26) | (h[3] << 25),
            (h[3] >> 39) | (h[4] << 12),
        ];
        for (o, w) in out.chunks_exact_mut(8).zip(words) {
            o.copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    fn carry(&self) -> Fe {
        let mut h = self.0;
        let c = h[4] >> 51;
        h[4] &= MASK;
        h[0] += c * 19;
        for i in 0..4 {
            h[i + 1] += h[i] >> 51;
            h[i] &= MASK;
        }
        let c = h[4] >> 51;
        h[4] &= MASK;
        h[0] += c * 19;
        Fe(h)
    }

    pub fn add(&self, o: &Fe) -> Fe {
        let mut r = [0u64; 5];
        for i in 0..5 {
            r[i] = self.0[i] + o.0[i];
        }
        Fe(r).carry()
    }

    /// self - o, computed as self + 4p - o so limbs never underflow.
    pub fn sub(&self, o: &Fe) -> Fe {
        const P4: [u64; 5] = [0x1f_ffff_ffff_ffb4, 0x1f_ffff_ffff_fffc, 0x1f_ffff_ffff_fffc, 0x1f_ffff_ffff_fffc, 0x1f_ffff_ffff_fffc];
        let o = o.carry();
        let mut r = [0u64; 5];
        for i in 0..5 {
            r[i] = self.0[i] + P4[i] - o.0[i];
        }
        Fe(r).carry()
    }

    pub fn neg(&self) -> Fe {
        Fe::ZERO.sub(self)
    }

    pub fn mul(&self, o: &Fe) -> Fe {
        let a = self.carry().0;
        let b = o.carry().0;
        let m = |x: u64, y: u64| x as u128 * y as u128;
        let b19 = [b[0], b[1] * 19, b[2] * 19, b[3] * 19, b[4] * 19];
        let r0 = m(a[0], b[0]) + m(a[1], b19[4]) + m(a[2], b19[3]) + m(a[3], b19[2]) + m(a[4], b19[1]);
        let r1 = m(a[0], b[1]) + m(a[1], b[0]) + m(a[2], b19[4]) + m(a[3], b19[3]) + m(a[4], b19[2]);
        let r2 = m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a[3], b19[4]) + m(a[4], b19[3]);
        let r3 = m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a[4], b19[4]);
        let r4 = m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]);
        reduce_wide([r0, r1, r2, r3, r4])
    }

    pub fn square(&self) -> Fe {
        self.mul(self)
    }

    pub fn mul_small(&self, k: u32) -> Fe {
        let mut r = [0u128; 5];
        let a = self.carry().0;
        for i in 0..5 {
            r[i] = a[i] as u128 * k as u128;
        }
        reduce_wide(r)
    }

    /// Repeated squaring.
    fn pow2k(&self, k: u32) -> Fe {
        let mut x = *self;
        for _ in 0..k {
            x = x.square();
        }
        x
    }

    /// self^(2^250 - 1) and self^11, the shared prefix of inversion and sqrt chains.
    fn pow22501(&self) -> (Fe, Fe) {
        let z2 = self.square();
        let z9 = z2.pow2k(2).mul(self);
        let z11 = z9.mul(&z2);
        let z2_5_0 = z11.square().mul(&z9);
        let z2_10_0 = z2_5_0.pow2k(5).mul(&z2_5_0);
        let z2_20_0 = z2_10_0.pow2k(10).mul(&z2_10_0);
        let z2_40_0 = z2_20_0.pow2k(20).mul(&z2_20_0);
        let z2_50_0 = z2_40_0.pow2k(10).mul(&z2_10_0);
        let z2_100_0 = z2_50_0.pow2k(50).mul(&z2_50_0);
        let z2_200_0 = z2_100_0.pow2k(100).mul(&z2_100_0);
        let z2_250_0 = z2_200_0.pow2k(50).mul(&z2_50_0);
        (z2_250_0, z11)
    }

    /// Multiplicative inverse (self^(p-2)); 0 maps to 0.
    pub fn invert(&self) -> Fe {
        let (t, z11) = self.pow22501();
        t.pow2k(5).mul(&z11)
    }

    /// self^((p-5)/8), used for square roots in Ed25519 decoding.
    pub fn pow_p58(&self) -> Fe {
        let (t, _) = self.pow22501();
        t.pow2k(2).mul(self)
    }

    pub fn is_zero(&self) -> bool {
        crate::ct_eq(&self.to_bytes(), &[0u8; 32])
    }

    /// Low bit of the canonical encoding ("negative" in RFC 8032 terms).
    pub fn is_negative(&self) -> u8 {
        self.to_bytes()[0] & 1
    }

    pub fn ct_eq(&self, o: &Fe) -> bool {
        crate::ct_eq(&self.to_bytes(), &o.to_bytes())
    }

    /// Constant-time conditional swap when `swap` is 1.
    pub fn cswap(a: &mut Fe, b: &mut Fe, swap: u64) {
        let mask = 0u64.wrapping_sub(swap);
        for i in 0..5 {
            let t = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
        }
    }

    /// Constant-time select: `b` when `choose` is 1, else `a`.
    pub fn select(a: &Fe, b: &Fe, choose: u64) -> Fe {
        let mask = 0u64.wrapping_sub(choose);
        let mut r = [0u64; 5];
        for i in 0..5 {
            r[i] = a.0[i] ^ (mask & (a.0[i] ^ b.0[i]));
        }
        Fe(r)
    }
}

fn reduce_wide(r: [u128; 5]) -> Fe {
    let mut r = r;
    for i in 0..4 {
        r[i + 1] += r[i] >> 51;
        r[i] &= MASK as u128;
    }
    let c = r[4] >> 51;
    r[4] &= MASK as u128;
    r[0] += c * 19;
    let c = r[0] >> 51;
    r[0] &= MASK as u128;
    r[1] += c;
    Fe([r[0] as u64, r[1] as u64, r[2] as u64, r[3] as u64, r[4] as u64])
}
