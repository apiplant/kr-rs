mod common;
use common::{rows, unhex};
use kr_crypto::hmac::{hkdf_expand, hkdf_extract, hmac};
use kr_crypto::sha2::{sha256, sha384, sha512, Hash, Sha256, Sha384, Sha512};

fn digest(alg: &str, m: &[u8]) -> Vec<u8> {
    match alg {
        "sha256" => sha256(m).to_vec(),
        "sha384" => sha384(m).to_vec(),
        "sha512" => sha512(m).to_vec(),
        _ => unreachable!(),
    }
}

#[test]
fn sha2_vs_openssl() {
    let mut n = 0;
    for r in rows(include_str!("vectors/sha2.txt")) {
        let m = unhex(r[1]);
        assert_eq!(digest(r[0], &m), unhex(r[2]), "{} len {}", r[0], m.len());
        n += 1;
    }
    assert_eq!(n, 54);
}

#[test]
fn sha2_streaming_split_points() {
    let m: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
    for split in [0, 1, 63, 64, 65, 127, 128, 129, 999] {
        let mut a = Sha256::new();
        a.update(&m[..split]);
        a.update(&m[split..]);
        assert_eq!(a.finalize(), sha256(&m));
        let mut b = Sha384::new();
        b.update(&m[..split]);
        b.update(&m[split..]);
        assert_eq!(b.finalize(), sha384(&m));
    }
}

#[test]
fn fips_abc() {
    assert_eq!(sha256(b"abc").to_vec(), unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    assert_eq!(
        sha512(b"abc").to_vec(),
        unhex("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
    );
}

fn mac(alg: &str, k: &[u8], m: &[u8]) -> Vec<u8> {
    let mut out = [0u8; 64];
    match alg {
        "sha256" => hmac::<Sha256>(k, m, &mut out),
        "sha384" => hmac::<Sha384>(k, m, &mut out),
        _ => hmac::<Sha512>(k, m, &mut out),
    }
    let n = match alg { "sha256" => Sha256::OUT, "sha384" => Sha384::OUT, _ => Sha512::OUT };
    out[..n].to_vec()
}

fn hkdf(alg: &str, salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut prk = [0u8; 64];
    let mut okm = vec![0u8; len];
    match alg {
        "sha256" => {
            hkdf_extract::<Sha256>(salt, ikm, &mut prk);
            hkdf_expand::<Sha256>(&prk[..32], &[info], &mut okm)
        }
        "sha384" => {
            hkdf_extract::<Sha384>(salt, ikm, &mut prk);
            hkdf_expand::<Sha384>(&prk[..48], &[info], &mut okm)
        }
        _ => {
            hkdf_extract::<Sha512>(salt, ikm, &mut prk);
            hkdf_expand::<Sha512>(&prk, &[info], &mut okm)
        }
    }
    okm
}

#[test]
fn hmac_hkdf_vs_openssl() {
    let mut n = 0;
    for r in rows(include_str!("vectors/hmac_hkdf.txt")) {
        if r[0] == "hmac" {
            assert_eq!(mac(r[1], &unhex(r[2]), &unhex(r[3])), unhex(r[4]), "hmac {} klen {}", r[1], r[2].len() / 2);
        } else {
            let okm = unhex(r[5]);
            assert_eq!(hkdf(r[1], &unhex(r[2]), &unhex(r[3]), &unhex(r[4]), okm.len()), okm);
        }
        n += 1;
    }
    assert_eq!(n, 3 * (11 + 8));
}

#[test]
fn rfc5869_case1() {
    let okm = hkdf(
        "sha256",
        &unhex("000102030405060708090a0b0c"),
        &unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
        &unhex("f0f1f2f3f4f5f6f7f8f9"),
        42,
    );
    assert_eq!(okm, unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
}
