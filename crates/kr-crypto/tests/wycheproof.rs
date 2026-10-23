//! Wycheproof suites (C2SP), converted by tools/wycheproof_convert.py. "valid" cases must pass
//! and "invalid" cases must be rejected; "acceptable" cases may go either way unless noted.
mod common;
use common::unhex;
use kr_crypto::aes::AesGcm;
use kr_crypto::sha2::Sha256;
use kr_crypto::{chacha, ed25519, hmac, p256, x25519};

struct Case<'a> {
    id: &'a str,
    result: &'a str,
    f: Vec<&'a str>,
}

fn cases(data: &str) -> Vec<Case<'_>> {
    data.lines()
        .map(|l| {
            let mut it = l.split('|');
            let (id, result) = (it.next().unwrap(), it.next().unwrap());
            Case { id, result, f: it.collect() }
        })
        .collect()
}

#[test]
fn x25519_suite() {
    let all = cases(include_str!("wycheproof/x25519.txt"));
    for c in &all {
        let k: [u8; 32] = unhex(c.f[0]).try_into().unwrap();
        let u: [u8; 32] = unhex(c.f[1]).try_into().unwrap();
        // Raw scalar multiplication must match for valid and acceptable cases alike.
        assert_eq!(x25519::x25519(&k, &u).to_vec(), unhex(c.f[2]), "tc {}", c.id);
        if c.result == "valid" {
            assert!(x25519::shared(&k, &u).is_ok(), "tc {}", c.id);
        }
    }
    assert!(all.len() > 500);
}

#[test]
fn ed25519_suite() {
    for c in cases(include_str!("wycheproof/ed25519.txt")) {
        let pk: [u8; 32] = unhex(c.f[0]).try_into().unwrap();
        let (msg, sig) = (unhex(c.f[1]), unhex(c.f[2]));
        let ok = sig.len() == 64 && ed25519::verify(&pk, &msg, &sig[..].try_into().unwrap());
        assert_eq!(ok, c.result == "valid", "tc {} ({})", c.id, c.result);
    }
}

#[test]
fn ecdsa_p256_suite() {
    for c in cases(include_str!("wycheproof/ecdsa_p256_sha256.txt")) {
        let (pk, msg, sig) = (unhex(c.f[0]), unhex(c.f[1]), unhex(c.f[2]));
        let ok = p256::sig_from_der(&sig).is_some_and(|(r, s)| p256::verify(&pk, &msg, &r, &s));
        match c.result {
            "valid" => assert!(ok, "tc {} should verify", c.id),
            "invalid" => assert!(!ok, "tc {} should be rejected", c.id),
            _ => {}
        }
    }
}

#[test]
fn ecdh_p256_suite() {
    let mut checked = 0;
    for c in cases(include_str!("wycheproof/ecdh_p256.txt")) {
        let (public, d) = (unhex(c.f[0]), unhex(c.f[1]));
        let Some(k) = p256::SecretKey::from_bytes(&d[..].try_into().unwrap()) else { continue };
        let compressed = matches!(public.first(), Some(2 | 3));
        let r = k.ecdh(&public);
        match c.result {
            "valid" if !compressed => {
                assert_eq!(r.expect("valid ecdh").to_vec(), unhex(c.f[2]), "tc {}", c.id);
                checked += 1;
            }
            "invalid" => assert!(r.is_err(), "tc {} should be rejected", c.id),
            _ => {}
        }
    }
    assert!(checked > 50);
}

fn aead_suite(data: &str, seal: impl Fn(&[u8], &[u8; 12], &[u8], &mut [u8]) -> [u8; 16], open: impl Fn(&[u8], &[u8; 12], &[u8], &mut [u8], &[u8]) -> bool) {
    for c in cases(data) {
        let (key, iv, aad, msg, ct, tag) = (unhex(c.f[0]), unhex(c.f[1]), unhex(c.f[2]), unhex(c.f[3]), unhex(c.f[4]), unhex(c.f[5]));
        let iv: [u8; 12] = iv.try_into().unwrap();
        let mut buf = ct.clone();
        let opened = open(&key, &iv, &aad, &mut buf, &tag);
        if c.result == "valid" {
            assert!(opened, "tc {} should open", c.id);
            assert_eq!(buf, msg, "tc {}", c.id);
            let mut p = msg.clone();
            assert_eq!(seal(&key, &iv, &aad, &mut p).to_vec(), tag, "tc {}", c.id);
            assert_eq!(p, ct);
        } else {
            assert!(!opened, "tc {} should be rejected", c.id);
            assert_eq!(buf, ct, "tc {}: ciphertext modified on failure", c.id);
        }
    }
}

#[test]
fn aes_gcm_suite() {
    aead_suite(
        include_str!("wycheproof/aes_gcm.txt"),
        |k, iv, aad, d| AesGcm::new(k).seal(iv, aad, d),
        |k, iv, aad, d, t| AesGcm::new(k).open(iv, aad, d, t).is_ok(),
    );
}

#[test]
fn chacha20_poly1305_suite() {
    aead_suite(
        include_str!("wycheproof/chacha20_poly1305.txt"),
        |k, iv, aad, d| chacha::seal(k.try_into().unwrap(), iv, aad, d),
        |k, iv, aad, d, t| chacha::open(k.try_into().unwrap(), iv, aad, d, t).is_ok(),
    );
}

#[test]
fn hkdf_hmac_sha256_suites() {
    for c in cases(include_str!("wycheproof/hkdf_sha256.txt")) {
        let size: usize = c.f[3].parse().unwrap();
        if size > 255 * 32 {
            assert_eq!(c.result, "invalid", "tc {}", c.id);
            continue; // hkdf_expand rejects this length by contract (assert)
        }
        let mut prk = [0u8; 32];
        hmac::hkdf_extract::<Sha256>(&unhex(c.f[1]), &unhex(c.f[0]), &mut prk);
        let mut okm = vec![0u8; size];
        hmac::hkdf_expand::<Sha256>(&prk, &[&unhex(c.f[2])], &mut okm);
        assert_eq!(okm, unhex(c.f[4]), "tc {}", c.id);
    }
    for c in cases(include_str!("wycheproof/hmac_sha256.txt")) {
        let bits: usize = c.f[3].parse().unwrap();
        let mut tag = [0u8; 32];
        hmac::hmac::<Sha256>(&unhex(c.f[0]), &unhex(c.f[1]), &mut tag);
        let ok = kr_crypto::ct_eq(&tag[..bits / 8], &unhex(c.f[2]));
        assert_eq!(ok, c.result == "valid", "tc {}", c.id);
    }
}

#[test]
fn rsa_pkcs1_and_pss_suites() {
    use kr_crypto::rsa::{HashAlg, PublicKey};
    let mut n = 0;
    for c in cases(include_str!("wycheproof/rsa.txt")) {
        let (kind, sha, salt) = (c.f[0], c.f[1], c.f[2].parse::<usize>().unwrap());
        let h = match sha {
            "SHA-256" => HashAlg::Sha256,
            "SHA-384" => HashAlg::Sha384,
            _ => HashAlg::Sha512,
        };
        let key = PublicKey::from_pkcs1(&unhex(c.f[3])).expect("wycheproof key parses");
        let (msg, sig) = (unhex(c.f[4]), unhex(c.f[5]));
        let ok = if kind == "pkcs1" { key.verify_pkcs1v15(h, &msg, &sig) } else { key.verify_pss(h, &msg, &sig, salt) };
        match c.result {
            "valid" => assert!(ok, "tc {} ({kind} {sha}) should verify", c.id),
            "invalid" => assert!(!ok, "tc {} ({kind} {sha}) should be rejected", c.id),
            _ => {}
        }
        n += 1;
    }
    assert_eq!(n, 1275);
}

#[test]
fn ecdsa_p384_and_p256_sha512_suites() {
    use kr_crypto::ecc;
    use kr_crypto::rsa::HashAlg;
    let mut n = 0;
    for c in cases(include_str!("wycheproof/ecdsa_more.txt")) {
        let h = if c.f[1] == "SHA-384" { HashAlg::Sha384 } else { HashAlg::Sha512 };
        let (pk, msg, sig) = (unhex(c.f[2]), unhex(c.f[3]), unhex(c.f[4]));
        let digest = h.digest(&[&msg]);
        let ok = ecc::sig_from_der(&sig).is_some_and(|(r, s)| match c.f[0] {
            "p384" => ecc::P384.verify_digest(&pk, &digest, r, s),
            _ => ecc::P256.verify_digest(&pk, &digest, r, s),
        });
        match c.result {
            "valid" => assert!(ok, "tc {} ({} {}) should verify", c.id, c.f[0], c.f[1]),
            "invalid" => assert!(!ok, "tc {} ({} {}) should be rejected", c.id, c.f[0], c.f[1]),
            _ => {}
        }
        n += 1;
    }
    assert!(n > 1000);
}
