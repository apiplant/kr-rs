//! SHA-256 for content digests: re-exported from `kr-crypto` (the interim copy is gone).

use alloc::string::String;
pub use kr_crypto::sha2::{sha256, Sha256};

pub fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 15) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn hx(data: &[u8]) -> std::string::String {
        hex(&sha256(data))
    }

    #[test]
    fn fips_vectors() {
        assert_eq!(hx(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hx(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(
            hx(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hx(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        );
    }

    #[test]
    fn million_a() {
        let mut h = Sha256::new();
        let block = [b'a'; 1000];
        for _ in 0..1000 {
            h.update(&block);
        }
        assert_eq!(hex(&h.finalize()), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }

    #[test]
    fn incremental_matches_oneshot_at_every_split() {
        let data: Vec<u8> = (0..300u32).map(|i| (i * 7 + 3) as u8).collect();
        let want = sha256(&data);
        for split in 0..data.len() {
            let mut h = Sha256::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finalize(), want, "split {split}");
        }
        // padding boundary lengths
        for n in [55usize, 56, 57, 63, 64, 65, 119, 120] {
            let d = std::vec![0x61u8; n];
            let mut h = Sha256::new();
            for b in &d {
                h.update(core::slice::from_ref(b));
            }
            assert_eq!(h.finalize(), sha256(&d), "len {n}");
        }
    }
}
