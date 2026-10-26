//! Verifies a corpus of certificates made by Go's crypto/x509 (the way the Kubernetes e2e suite
//! makes them: a self-signed RSA CA and a server leaf per test) with `x509::verify_chain`.
//!
//! The corpus is not in the repository; generate it with a small Go program and run
//! `KR_CERT_CORPUS=/dir cargo test -p kr-crypto --test x509_corpus -- --ignored`.
//! Files: `<i>.ca.pem`, `<i>.leaf.pem`, `<i>.host`.

use kr_crypto::x509::{self, Usage};

#[test]
#[ignore]
fn go_generated_chains_verify() {
    let Ok(dir) = std::env::var("KR_CERT_CORPUS") else { return };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let (mut ok, mut bad) = (0, Vec::new());
    for i in 0.. {
        let (ca, leaf, host) = (format!("{dir}/{i}.ca.pem"), format!("{dir}/{i}.leaf.pem"), format!("{dir}/{i}.host"));
        let Ok(ca) = std::fs::read_to_string(&ca) else { break };
        let leaf = std::fs::read_to_string(&leaf).unwrap();
        let host = std::fs::read_to_string(&host).unwrap();
        let ca = x509::pem_decode_all(&ca, "CERTIFICATE").unwrap().remove(0);
        let leaf = x509::pem_decode_all(&leaf, "CERTIFICATE").unwrap().remove(0);
        match x509::verify_chain(&[&leaf], &[&ca], now, Usage::Server(host.as_bytes())) {
            Ok(()) => ok += 1,
            Err(e) => bad.push((i, e)),
        }
    }
    println!("verified {ok}, failed {}", bad.len());
    assert!(bad.is_empty(), "failures: {:?}", &bad[..bad.len().min(10)]);
}
