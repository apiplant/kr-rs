//! HMAC (RFC 2104) and HKDF (RFC 5869), generic over the SHA-2 family.

use crate::sha2::Hash;

const MAX_BLOCK: usize = 128;
const MAX_OUT: usize = 64;

#[derive(Clone)]
pub struct Hmac<H: Hash> {
    inner: H,
    outer: H,
}

impl<H: Hash> Hmac<H> {
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; MAX_BLOCK];
        if key.len() > H::BLOCK {
            let mut h = H::new();
            h.update(key);
            h.finish_into(&mut k);
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let (mut ipad, mut opad) = ([0u8; MAX_BLOCK], [0u8; MAX_BLOCK]);
        for i in 0..H::BLOCK {
            ipad[i] = k[i] ^ 0x36;
            opad[i] = k[i] ^ 0x5c;
        }
        let (mut inner, mut outer) = (H::new(), H::new());
        inner.update(&ipad[..H::BLOCK]);
        outer.update(&opad[..H::BLOCK]);
        crate::wipe(&mut k);
        crate::wipe(&mut ipad);
        crate::wipe(&mut opad);
        Hmac { inner, outer }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Writes `H::OUT` bytes into `out[..H::OUT]`.
    pub fn finish_into(self, out: &mut [u8]) {
        let mut ih = [0u8; MAX_OUT];
        self.inner.finish_into(&mut ih);
        let mut o = self.outer;
        o.update(&ih[..H::OUT]);
        o.finish_into(out);
    }
}

/// One-shot HMAC into `out[..H::OUT]`.
pub fn hmac<H: Hash>(key: &[u8], data: &[u8], out: &mut [u8]) {
    let mut m = Hmac::<H>::new(key);
    m.update(data);
    m.finish_into(out);
}

/// HKDF-Extract: PRK = HMAC(salt, ikm). An empty salt means `H::OUT` zero bytes.
pub fn hkdf_extract<H: Hash>(salt: &[u8], ikm: &[u8], prk: &mut [u8]) {
    let zeros = [0u8; MAX_OUT];
    let salt = if salt.is_empty() { &zeros[..H::OUT] } else { salt };
    hmac::<H>(salt, ikm, prk);
}

/// HKDF-Expand into `out` (at most 255 * `H::OUT` bytes). `info` is given in parts so TLS can
/// pass its HkdfLabel without allocating.
pub fn hkdf_expand<H: Hash>(prk: &[u8], info: &[&[u8]], out: &mut [u8]) {
    assert!(out.len() <= 255 * H::OUT, "hkdf output too long");
    let mut t = [0u8; MAX_OUT];
    let mut t_len = 0;
    let mut counter = 1u8;
    for chunk in out.chunks_mut(H::OUT) {
        let mut m = Hmac::<H>::new(prk);
        m.update(&t[..t_len]);
        for part in info {
            m.update(part);
        }
        m.update(&[counter]);
        m.finish_into(&mut t);
        t_len = H::OUT;
        chunk.copy_from_slice(&t[..chunk.len()]);
        counter = counter.wrapping_add(1);
    }
    crate::wipe(&mut t);
}
