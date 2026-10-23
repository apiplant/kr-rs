//! Rough timings: `cargo test --release -p kr-crypto --test bench -- --ignored --nocapture`.
use kr_crypto::{aes::AesGcm, chacha, ed25519, p256, x25519};
use std::time::Instant;

fn time(name: &str, iters: u32, bytes: usize, mut f: impl FnMut()) {
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    let per = t.elapsed() / iters;
    if bytes > 0 {
        println!("{name:24} {:>10.1} MB/s", bytes as f64 / per.as_secs_f64() / 1e6);
    } else {
        println!("{name:24} {:>10.1} us/op", per.as_secs_f64() * 1e6);
    }
}

#[test]
#[ignore]
fn bench() {
    let mut buf = vec![0u8; 16384];
    let key = [7u8; 32];
    time("chacha20-poly1305 16K", 200, buf.len(), || { std::hint::black_box(chacha::seal(&key, &[0; 12], &[], &mut buf)); });
    let g = AesGcm::new(&key[..16]);
    time("aes-128-gcm 16K", 20, buf.len(), || { std::hint::black_box(g.seal(&[0; 12], &[], &mut buf)); });
    time("x25519", 200, 0, || { std::hint::black_box(x25519::public_key(&key)); });
    let ek = ed25519::SigningKey::from_seed(&key);
    time("ed25519 sign", 100, 0, || { std::hint::black_box(ek.sign(b"hello")); });
    let sig = ek.sign(b"hello");
    time("ed25519 verify", 100, 0, || assert!(ed25519::verify(&ek.public_key(), b"hello", &sig)));
    let pk = p256::SecretKey::from_bytes(&key).unwrap();
    time("p256 sign", 50, 0, || { std::hint::black_box(pk.sign(b"hello")); });
    let (r, s) = pk.sign(b"hello");
    let pub_ = pk.public_key();
    time("p256 verify", 50, 0, || assert!(p256::verify(&pub_, b"hello", &r, &s)));
}
