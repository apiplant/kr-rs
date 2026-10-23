mod common;
use common::{rows, unhex};
use kr_crypto::aes::{Aes, AesGcm};

#[test]
fn fips197_appendix_c() {
    let pt: [u8; 16] = unhex("00112233445566778899aabbccddeeff").try_into().unwrap();
    let k128 = unhex("000102030405060708090a0b0c0d0e0f");
    assert_eq!(Aes::new(&k128).encrypt_block(&pt).to_vec(), unhex("69c4e0d86a7b0430d8cdb78070b4c55a"));
    let k256 = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    assert_eq!(Aes::new(&k256).encrypt_block(&pt).to_vec(), unhex("8ea2b7ca516745bfeafc49904b496089"));
}

#[test]
fn gcm_vs_openssl() {
    let mut n = 0;
    for r in rows(include_str!("vectors/aes_gcm.txt")) {
        let (k, nonce, aad, pt, ct) = (unhex(r[0]), unhex(r[1]), unhex(r[2]), unhex(r[3]), unhex(r[4]));
        let nonce: [u8; 12] = nonce.try_into().unwrap();
        let g = AesGcm::new(&k);
        let mut buf = pt.clone();
        let tag = g.seal(&nonce, &aad, &mut buf);
        assert_eq!([&buf[..], &tag[..]].concat(), ct, "klen {} len {}", k.len(), pt.len());
        assert!(g.open(&nonce, &aad, &mut buf, &tag).is_ok());
        assert_eq!(buf, pt);
        let mut bad = aad.clone();
        bad.push(0);
        let mut c = ct[..pt.len()].to_vec();
        assert!(g.open(&nonce, &bad, &mut c, &tag).is_err());
        n += 1;
    }
    assert_eq!(n, 22);
}
