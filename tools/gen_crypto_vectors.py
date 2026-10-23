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

if __name__ == "__main__":
    for n in (sys.argv[1:] or GENERATORS):
        GENERATORS[n]()
