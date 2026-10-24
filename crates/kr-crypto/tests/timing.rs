//! dudect-style constant-time checks (KNOWN_ISSUES #58): for each primitive, time it on two
//! input classes, "fixed" (one secret, repeated) and "random" (fresh secrets), interleaved in
//! random order, and compare the timing distributions with Welch's t-test. |t| > 4.5 means the
//! timing depends on the secret with high confidence; well below means no leak was detected at
//! this sample size (absence of evidence, not proof).
//!
//! Run in release on a quiet machine:
//!   cargo test --release -p kr-crypto --test timing -- --ignored --nocapture --test-threads=1

use kr_crypto::{aes::AesGcm, chacha, ct_eq, ed25519, p256, x25519};

const THRESHOLD: f64 = 4.5;

fn rng_fill(b: &mut [u8]) {
    let f = std::fs::File::open("/dev/urandom").unwrap();
    use std::io::Read;
    (&f).read_exact(b).unwrap();
}

#[inline(always)]
fn ticks() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_mm_lfence();
        let t = core::arch::x86_64::_rdtsc();
        core::arch::x86_64::_mm_lfence();
        t
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        std::time::Instant::now().elapsed().as_nanos() as u64
    }
}

/// Welch's t statistic between two samples.
fn welch(a: &[f64], b: &[f64]) -> f64 {
    let stats = |x: &[f64]| {
        let n = x.len() as f64;
        let m = x.iter().sum::<f64>() / n;
        let v = x.iter().map(|y| (y - m) * (y - m)).sum::<f64>() / (n - 1.0);
        (n, m, v)
    };
    let (na, ma, va) = stats(a);
    let (nb, mb, vb) = stats(b);
    (ma - mb) / (va / na + vb / nb).sqrt()
}

/// Measures `op` on `n` samples, class chosen at random per sample. `prepare(class, i)` builds
/// the input outside the timed region. Returns the worst |t| over the raw data and dudect-style
/// crops (keep samples below the p-th percentile, which removes interrupt/scheduler outliers).
fn dudect<I>(name: &str, n: usize, mut prepare: impl FnMut(bool) -> I, mut op: impl FnMut(&I)) -> f64 {
    let mut classes = vec![0u8; n];
    rng_fill(&mut classes);
    let inputs: Vec<(bool, I)> = classes.iter().map(|c| {
        let fixed = c & 1 == 0;
        (fixed, prepare(fixed))
    }).collect();
    // Warm-up.
    for (_, i) in inputs.iter().take(n / 20 + 1) {
        op(i);
    }
    let mut times = Vec::with_capacity(n);
    for (fixed, i) in &inputs {
        let t0 = ticks();
        op(i);
        let t1 = ticks();
        times.push((*fixed, t1.wrapping_sub(t0) as f64));
    }
    let mut sorted: Vec<f64> = times.iter().map(|t| t.1).collect();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mut worst: f64 = 0.0;
    let mut report = String::new();
    for pct in [100.0, 99.0, 95.0, 90.0, 75.0, 50.0] {
        let cut = sorted[((sorted.len() - 1) as f64 * pct / 100.0) as usize];
        let a: Vec<f64> = times.iter().filter(|t| t.0 && t.1 <= cut).map(|t| t.1).collect();
        let b: Vec<f64> = times.iter().filter(|t| !t.0 && t.1 <= cut).map(|t| t.1).collect();
        if a.len() < 100 || b.len() < 100 {
            continue;
        }
        let t = welch(&a, &b);
        report.push_str(&format!(" p{pct}:{t:+.2}"));
        worst = worst.max(t.abs());
    }
    let median = sorted[sorted.len() / 2];
    eprintln!("{name:<28} n={n:<7} median={median:>9.0} ticks  max|t|={worst:5.2} {}  [{report} ]", if worst > THRESHOLD { "LEAK?" } else { "ok" });
    worst
}

fn key32(fixed: bool, base: &[u8; 32]) -> [u8; 32] {
    if fixed {
        *base
    } else {
        let mut k = [0u8; 32];
        rng_fill(&mut k);
        k
    }
}

#[test]
#[ignore]
fn ct_eq_is_constant_time() {
    // Equal buffers vs. buffers differing in the first byte: a short-circuiting compare leaks.
    let a = [0x5au8; 64];
    let t = dudect("ct_eq(64B)", 200_000, |fixed| {
        let mut b = a;
        if !fixed {
            b[0] ^= 1;
        }
        b
    }, |b| {
        for _ in 0..16 {
            std::hint::black_box(ct_eq(std::hint::black_box(&a), std::hint::black_box(b)));
        }
    });
    assert!(t < THRESHOLD);
}

#[test]
#[ignore]
fn x25519_is_constant_time() {
    let mut base = [0u8; 32];
    rng_fill(&mut base);
    let u = x25519::public_key(&base);
    // Fixed class: a low-weight scalar (all zero bits but the clamped ones) vs random scalars.
    let fixed_scalar = [0u8; 32];
    let t = dudect("x25519 scalar mult", 20_000, |fixed| key32(fixed, &fixed_scalar), |k| {
        std::hint::black_box(x25519::x25519(std::hint::black_box(k), &u));
    });
    assert!(t < THRESHOLD);
}

#[test]
#[ignore]
fn ed25519_sign_is_constant_time() {
    let mut base = [0u8; 32];
    rng_fill(&mut base);
    let msg = [7u8; 64];
    let t = dudect("ed25519 sign", 10_000, |fixed| ed25519::SigningKey::from_seed(&key32(fixed, &base)), |k| {
        std::hint::black_box(k.sign(std::hint::black_box(&msg)));
    });
    assert!(t < THRESHOLD);
}

#[test]
#[ignore]
fn p256_sign_is_constant_time() {
    let mut base = [0u8; 32];
    rng_fill(&mut base);
    base[0] &= 0x7f;
    let digest = [9u8; 32];
    let t = dudect("p256 sign (digest)", 4_000, |fixed| {
        let mut k = key32(fixed, &base);
        k[0] &= 0x7f; // below the group order
        p256::SecretKey::from_bytes(&k).unwrap()
    }, |k| {
        std::hint::black_box(k.sign_digest(std::hint::black_box(&digest)));
    });
    assert!(t < THRESHOLD);
}

#[test]
#[ignore]
fn chacha20_poly1305_is_constant_time() {
    let base = [0u8; 32];
    let nonce = [1u8; 12];
    let t = dudect("chacha20-poly1305 seal(1K)", 50_000, |fixed| key32(fixed, &base), |k| {
        let mut data = [0u8; 1024];
        std::hint::black_box(chacha::seal(std::hint::black_box(k), &nonce, b"aad", &mut data));
    });
    assert!(t < THRESHOLD);
}

#[test]
#[ignore]
fn aes_gcm_is_constant_time() {
    let base = [0u8; 32];
    let nonce = [1u8; 12];
    let t = dudect("aes-128-gcm seal(1K)", 30_000, |fixed| AesGcm::new(&key32(fixed, &base)[..16]), |g| {
        let mut data = [0u8; 1024];
        std::hint::black_box(g.seal(&nonce, b"aad", &mut data));
    });
    assert!(t < THRESHOLD);
}

#[test]
#[ignore]
fn harness_detects_a_leaky_compare() {
    // Control: a short-circuiting compare must be flagged, or the harness proves nothing.
    #[inline(never)]
    fn leaky_eq(a: &[u8], b: &[u8]) -> bool {
        for i in 0..a.len() {
            if std::hint::black_box(a[i]) != b[i] {
                return false;
            }
        }
        true
    }
    let a = [0x5au8; 512];
    let t = dudect("CONTROL leaky compare(512B)", 100_000, |fixed| {
        let mut b = a;
        if !fixed {
            b[0] ^= 1;
        }
        b
    }, |b| {
        std::hint::black_box(leaky_eq(std::hint::black_box(&a), std::hint::black_box(b)));
    });
    assert!(t > THRESHOLD, "the harness failed to detect a known timing leak (|t| = {t:.2})");
}
