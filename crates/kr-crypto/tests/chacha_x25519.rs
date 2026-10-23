mod common;
use common::{rows, unhex};
use kr_crypto::chacha;
use kr_crypto::x25519::{public_key, shared, x25519};

fn a32(v: &[u8]) -> [u8; 32] {
    v.try_into().unwrap()
}

#[test]
fn vs_openssl() {
    let (mut na, mut nx) = (0, 0);
    for r in rows(include_str!("vectors/chacha_x25519.txt")) {
        if r[0] == "aead" {
            let (k, nonce, aad, pt, ct) = (unhex(r[1]), unhex(r[2]), unhex(r[3]), unhex(r[4]), unhex(r[5]));
            let (k, nonce) = (a32(&k), nonce.try_into().unwrap());
            let mut buf = pt.clone();
            let tag = chacha::seal(&k, &nonce, &aad, &mut buf);
            assert_eq!([&buf[..], &tag[..]].concat(), ct, "len {}", pt.len());
            assert!(chacha::open(&k, &nonce, &aad, &mut buf, &tag).is_ok());
            assert_eq!(buf, pt);
            // Any flipped bit in ciphertext, tag or aad must fail and leave data untouched.
            if !buf.is_empty() {
                let mut c = ct[..pt.len()].to_vec();
                c[0] ^= 1;
                let before = c.clone();
                assert!(chacha::open(&k, &nonce, &aad, &mut c, &tag).is_err());
                assert_eq!(c, before);
            }
            let mut t2 = tag;
            t2[15] ^= 0x80;
            let mut c = ct[..pt.len()].to_vec();
            assert!(chacha::open(&k, &nonce, &aad, &mut c, &t2).is_err());
            na += 1;
        } else {
            let (a, b, pa, s) = (a32(&unhex(r[1])), a32(&unhex(r[2])), unhex(r[3]), unhex(r[4]));
            assert_eq!(public_key(&a).to_vec(), pa);
            assert_eq!(shared(&b, &a32(&pa)).unwrap().to_vec(), s);
            assert_eq!(shared(&a, &public_key(&b)).unwrap().to_vec(), s);
            nx += 1;
        }
    }
    assert_eq!((na, nx), (11, 20));
}

#[test]
fn rfc8439_aead() {
    let key = a32(&unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"));
    let nonce: [u8; 12] = unhex("070000004041424344454647").try_into().unwrap();
    let aad = unhex("50515253c0c1c2c3c4c5c6c7");
    let mut m = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
    let tag = chacha::seal(&key, &nonce, &aad, &mut m);
    assert_eq!(tag.to_vec(), unhex("1ae10b594f09e26a7e902ecbd0600691"));
    assert_eq!(&m[..8], &unhex("d31a8d34648e60db")[..]);
}

#[test]
fn rfc7748_vectors() {
    let k = a32(&unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"));
    let u = a32(&unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"));
    assert_eq!(x25519(&k, &u).to_vec(), unhex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"));
    // Iterated: 1000 rounds of k, u = x25519(k, u), k.
    let (mut k, mut u) = (kr_crypto::x25519::BASEPOINT, kr_crypto::x25519::BASEPOINT);
    for _ in 0..1000 {
        let r = x25519(&k, &u);
        u = k;
        k = r;
    }
    assert_eq!(k.to_vec(), unhex("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"));
}

#[test]
fn small_order_point_rejected() {
    let zero = [0u8; 32];
    assert!(shared(&[7u8; 32], &zero).is_err());
    let mut one = [0u8; 32];
    one[0] = 1;
    assert!(shared(&[7u8; 32], &one).is_err());
}

#[test]
fn noncanonical_u_is_reduced() {
    // u = p + 9 must behave like u = 9 (RFC 7748: implementations accept non-canonical values).
    let mut p9 = [0xffu8; 32];
    p9[0] = 0xed + 9;
    p9[31] = 0x7f;
    let k = [0x42u8; 32];
    assert_eq!(x25519(&k, &p9), x25519(&k, &kr_crypto::x25519::BASEPOINT));
}
