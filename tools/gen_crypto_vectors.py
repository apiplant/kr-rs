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

@gen
def x509_chains():
    """Chains built by pyca/OpenSSL for kr's verifier. Times are fixed; tests use NOW=1800000000."""
    import datetime as dt, ipaddress
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, ObjectIdentifier
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from cryptography.hazmat.primitives import serialization as ser
    d = os.path.join(OUT, "x509"); os.makedirs(d, exist_ok=True)
    T = lambda s: dt.datetime.fromtimestamp(s, dt.timezone.utc)
    def key(kind="ec"):
        return ec.derive_private_key(rng.randrange(1, 2**255), ec.SECP256R1()) if kind == "ec" else ed25519.Ed25519PrivateKey.from_private_bytes(rb(32))
    def name(cn, o=None):
        attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)] + ([x509.NameAttribute(NameOID.ORGANIZATION_NAME, o)] if o else [])
        return x509.Name(attrs)
    def cert(subj, pub, issuer, ikey, ca=False, pathlen=None, eku=None, sans=(), nb=1700000000, na=1900000000, extra=None, ku=True):
        b = (x509.CertificateBuilder().subject_name(subj).issuer_name(issuer).public_key(pub)
             .serial_number(rng.randrange(1, 2**63)).not_valid_before(T(nb)).not_valid_after(T(na)))
        b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=pathlen), critical=True)
        if ku:
            b = b.add_extension(x509.KeyUsage(digital_signature=not ca, content_commitment=False, key_encipherment=False, data_encipherment=False,
                                              key_agreement=False, key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False), critical=True)
        if eku: b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
        if sans:
            b = b.add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(s)) if s[0].isdigit() or ":" in s else x509.DNSName(s) for s in sans]), critical=False)
        if extra: b = b.add_extension(x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.99999.1"), b"\x05\x00"), critical=extra == "critical")
        algo = None if isinstance(ikey, ed25519.Ed25519PrivateKey) else hashes.SHA256()
        return b.sign(ikey, algo)
    pem = lambda c: c.public_bytes(ser.Encoding.PEM).decode()
    SRV, CLI = [ExtendedKeyUsageOID.SERVER_AUTH], [ExtendedKeyUsageOID.CLIENT_AUTH]
    rk = key(); root = cert(name("kr-test-root"), rk.public_key(), name("kr-test-root"), rk, ca=True, pathlen=1)
    ik = key(); inter = cert(name("kr-test-inter"), ik.public_key(), root.subject, rk, ca=True, pathlen=0)
    ek = key("ed"); edroot = cert(name("kr-ed-root"), ek.public_key(), name("kr-ed-root"), ek, ca=True)
    def leaf(cn="api", **kw): k = key(); return cert(name(cn, kw.pop("o", None)), k.public_key(), inter.subject, ik, **kw)
    cases = {
        "ok_server_via_inter": (leaf(eku=SRV, sans=["api.kr.local", "*.svc.kr.local", "10.0.0.1", "::1"]), "server", "ok"),
        "ok_client": (leaf("alice", o="system:masters", eku=CLI), "client", "ok"),
        "expired": (leaf(eku=SRV, sans=["api.kr.local"], na=1750000000), "server", "Expired"),
        "wrong_eku": (leaf(eku=CLI, sans=["api.kr.local"]), "server", "Usage"),
        "wrong_host": (leaf(eku=SRV, sans=["other.kr.local"]), "server", "HostMismatch"),
        "unknown_critical": (leaf(eku=SRV, sans=["api.kr.local"], extra="critical"), "server", "Parse"),
        "unknown_noncritical": (leaf(eku=SRV, sans=["api.kr.local"], extra="plain"), "server", "ok"),
    }
    # leaf issued by a non-CA leaf
    fake_k = key(); fake = cert(name("fake-ca"), fake_k.public_key(), inter.subject, ik, eku=SRV)
    k = key(); cases["issuer_not_ca"] = (cert(name("x"), k.public_key(), fake.subject, fake_k, eku=SRV, sans=["api.kr.local"]), "server", "NotCa")
    # path length: root pathlen=1 -> inter(pathlen 0) -> inter2 is too deep
    i2k = key(); inter2 = cert(name("kr-test-inter2"), i2k.public_key(), inter.subject, ik, ca=True)
    k = key(); cases["pathlen_exceeded"] = (cert(name("y"), k.public_key(), inter2.subject, i2k, eku=SRV, sans=["api.kr.local"]), "server", "NotCa")
    k = key(); cases["ed25519_root"] = (cert(name("z"), k.public_key(), edroot.subject, ek, eku=SRV, sans=["api.kr.local"]), "server", "ok_ed")
    ok = key(); other = cert(name("kr-test-inter"), ok.public_key(), root.subject, ok, ca=True)  # same name, wrong key
    k = key(); cases["unknown_issuer"] = (cert(name("w"), k.public_key(), other.subject, ok, eku=SRV, sans=["api.kr.local"]), "server", "UnknownIssuer")
    with open(os.path.join(d, "roots.pem"), "w") as f: f.write(pem(root) + pem(edroot))
    with open(os.path.join(d, "inter.pem"), "w") as f: f.write(pem(inter) + pem(fake) + pem(inter2))
    with open(os.path.join(d, "cases.txt"), "w") as f:
        for n, (c, usage, want) in cases.items():
            f.write("|".join((n, usage, want, c.public_bytes(ser.Encoding.DER).hex())) + "\n")

if __name__ == "__main__":
    for n in (sys.argv[1:] or GENERATORS):
        GENERATORS[n]()
