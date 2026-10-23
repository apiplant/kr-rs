mod common;
use common::{rows, unhex};
use kr_crypto::{ed25519, p256};

#[test]
fn ed25519_vs_openssl() {
    let mut n = 0;
    for r in rows(include_str!("vectors/signatures.txt")).filter(|r| r[0] == "ed25519") {
        let seed: [u8; 32] = unhex(r[1]).try_into().unwrap();
        let (pk, msg, sig) = (unhex(r[2]), unhex(r[3]), unhex(r[4]));
        let k = ed25519::SigningKey::from_seed(&seed);
        assert_eq!(k.public_key().to_vec(), pk);
        let ours = k.sign(&msg);
        assert_eq!(ours.to_vec(), sig, "deterministic signature differs");
        let pk: [u8; 32] = pk.try_into().unwrap();
        assert!(ed25519::verify(&pk, &msg, &ours));
        let mut bad = ours;
        bad[5] ^= 1;
        assert!(!ed25519::verify(&pk, &msg, &bad));
        let mut m2 = msg.clone();
        m2.push(1);
        assert!(!ed25519::verify(&pk, &m2, &ours));
        // S + L (non-canonical) must be rejected even though it is "equivalent".
        let mut s_plus_l = ours;
        let l = unhex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
        let mut carry = 0u16;
        for i in 0..32 {
            let v = s_plus_l[32 + i] as u16 + l[i] as u16 + carry;
            s_plus_l[32 + i] = v as u8;
            carry = v >> 8;
        }
        assert!(!ed25519::verify(&pk, &msg, &s_plus_l));
        n += 1;
    }
    assert_eq!(n, 16);
}

#[test]
fn ed25519_rfc8032_test1() {
    let k = ed25519::SigningKey::from_seed(&unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").try_into().unwrap());
    assert_eq!(k.public_key().to_vec(), unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));
    assert_eq!(
        k.sign(b"").to_vec(),
        unhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    );
}

#[test]
fn p256_vs_openssl() {
    let mut n = 0;
    for r in rows(include_str!("vectors/signatures.txt")).filter(|r| r[0] == "p256") {
        let d: [u8; 32] = unhex(r[1]).try_into().unwrap();
        let (pk, msg, det, rnd, peer, shared) = (unhex(r[2]), unhex(r[3]), unhex(r[4]), unhex(r[5]), unhex(r[6]), unhex(r[7]));
        let k = p256::SecretKey::from_bytes(&d).unwrap();
        assert_eq!(k.public_key().to_vec(), pk);
        let (sr, ss) = k.sign(&msg);
        assert_eq!(p256::sig_to_der(&sr, &ss), det, "RFC 6979 signature differs");
        assert_eq!(p256::sig_from_der(&det), Some((sr, ss)));
        let (rr, rs) = p256::sig_from_der(&rnd).expect("openssl DER");
        assert!(p256::verify(&pk, &msg, &rr, &rs));
        assert!(!p256::verify(&pk, b"other", &rr, &rs));
        let mut bad_s = rs;
        bad_s[31] ^= 1;
        assert!(!p256::verify(&pk, &msg, &rr, &bad_s));
        assert_eq!(k.ecdh(&peer).unwrap().to_vec(), shared);
        n += 1;
    }
    assert_eq!(n, 12);
}

#[test]
fn p256_rejects_bad_points() {
    let k = p256::SecretKey::from_bytes(&[7u8; 32]).unwrap();
    let mut pk = k.public_key();
    assert!(k.ecdh(&pk).is_ok());
    pk[64] ^= 1; // off the curve
    assert!(k.ecdh(&pk).is_err());
    assert!(k.ecdh(&[4u8; 65]).is_err());
    assert!(k.ecdh(&pk[..64]).is_err());
    assert!(p256::SecretKey::from_bytes(&[0u8; 32]).is_none());
    assert!(p256::SecretKey::from_bytes(&[0xffu8; 32]).is_none()); // >= n
}

#[test]
fn der_strictness() {
    assert!(p256::sig_from_der(&unhex("3006020100020101")).is_some());
    assert!(p256::sig_from_der(&unhex("300702020001020101")).is_none()); // non-minimal
    assert!(p256::sig_from_der(&unhex("3006020180020101")).is_none()); // negative
    assert!(p256::sig_from_der(&unhex("300702010002010100")).is_none()); // trailing
}
