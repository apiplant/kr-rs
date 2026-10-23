#!/usr/bin/env python3
"""Generates differential test vectors for kr-crypto from pyca/cryptography (OpenSSL).

Dev tooling only (ADR-020): the shipped code has no dependencies. Output is deterministic
(seeded) and committed under crates/kr-crypto/tests/vectors/, one case per line, fields
separated by '|', binary fields hex-encoded.
Run: python3 -I tools/gen_crypto_vectors.py
"""
import os, random, sys
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "crates", "kr-crypto", "tests", "vectors")
rng = random.Random(0x6b72)
def rb(n): return bytes(rng.getrandbits(8) for _ in range(n))
def w(name, rows):
    with open(os.path.join(OUT, name), "w") as f:
        for r in rows: f.write("|".join(x.hex() if isinstance(x, bytes) else str(x) for x in r) + "\n")

GENERATORS = {}
def gen(f): GENERATORS[f.__name__] = f; return f

HASHES = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}
LENS = [0, 1, 3, 55, 56, 57, 63, 64, 65, 111, 112, 113, 127, 128, 129, 200, 1000, 4097]

@gen
def sha2():
    rows = []
    for name, h in HASHES.items():
        for n in LENS:
            m = rb(n); d = hashes.Hash(h()); d.update(m); rows.append((name, m, d.finalize()))
    w("sha2.txt", rows)

@gen
def hmac_hkdf():
    rows = []
    for name, h in HASHES.items():
        for kl in [0, 1, 16, 32, 63, 64, 65, 127, 128, 129, 300]:
            k, m = rb(kl), rb(rng.randrange(0, 300))
            x = hmac.HMAC(k, h()); x.update(m); rows.append(("hmac", name, k, m, x.finalize()))
        for _ in range(8):
            salt, ikm, info = rb(rng.choice([0, 13, 32, 64])), rb(rng.randrange(1, 80)), rb(rng.randrange(0, 40))
            L = rng.choice([1, 16, 32, 42, 48, 64, 100, 255])
            okm = HKDF(algorithm=h(), length=L, salt=salt or None, info=info).derive(ikm)
            rows.append(("hkdf", name, salt, ikm, info, okm))
    w("hmac_hkdf.txt", rows)

@gen
def chacha_x25519():
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives import serialization as ser
    rows = []
    for n in [0, 1, 15, 16, 17, 63, 64, 65, 255, 256, 1000]:
        k, nonce, aad, pt = rb(32), rb(12), rb(rng.choice([0, 1, 13, 16, 40])), rb(n)
        rows.append(("aead", k, nonce, aad, pt, ChaCha20Poly1305(k).encrypt(nonce, pt, aad)))
    raw = dict(encoding=ser.Encoding.Raw, format=ser.PublicFormat.Raw)
    for _ in range(20):
        a, b = rb(32), rb(32)
        A = X25519PrivateKey.from_private_bytes(a); B = X25519PrivateKey.from_private_bytes(b)
        pa = A.public_key().public_bytes(**raw)
        rows.append(("x25519", a, b, pa, B.exchange(X25519PublicKey.from_public_bytes(pa))))
    w("chacha_x25519.txt", rows)

@gen
def aes_gcm():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    rows = []
    for kl in (16, 32):
        for n in [0, 1, 15, 16, 17, 31, 32, 33, 64, 100, 1000]:
            k, nonce, aad, pt = rb(kl), rb(12), rb(rng.choice([0, 1, 13, 16, 20, 40])), rb(n)
            rows.append((k, nonce, aad, pt, AESGCM(k).encrypt(nonce, pt, aad)))
    w("aes_gcm.txt", rows)

@gen
def signatures():
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.hazmat.primitives import serialization as ser
    rows = []
    raw = dict(encoding=ser.Encoding.Raw, format=ser.PublicFormat.Raw)
    for _ in range(16):
        seed, msg = rb(32), rb(rng.randrange(0, 200))
        k = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        rows.append(("ed25519", seed, k.public_key().public_bytes(**raw), msg, k.sign(msg)))
    unc = dict(encoding=ser.Encoding.X962, format=ser.PublicFormat.UncompressedPoint)
    n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    for _ in range(12):
        d = rng.randrange(1, n); msg = rb(rng.randrange(0, 200))
        k = ec.derive_private_key(d, ec.SECP256R1())
        pub = k.public_key().public_bytes(**unc)
        det = k.sign(msg, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        rnd = k.sign(msg, ec.ECDSA(hashes.SHA256()))
        d2 = rng.randrange(1, n); k2 = ec.derive_private_key(d2, ec.SECP256R1())
        shared = k.exchange(ec.ECDH(), k2.public_key())
        rows.append(("p256", d.to_bytes(32, "big"), pub, msg, det, rnd, k2.public_key().public_bytes(**unc), shared))
    w("signatures.txt", rows)

if __name__ == "__main__":
    for n in (sys.argv[1:] or GENERATORS):
        GENERATORS[n]()
