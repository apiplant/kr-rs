#!/usr/bin/env python3
"""Converts Wycheproof JSON suites (C2SP/wycheproof testvectors_v1) into kr-crypto's compact
line format: tcId|result|fields... with result in valid/invalid/acceptable.

Usage: python3 -I tools/wycheproof_convert.py <dir-with-json>
Suites converted (and the parameter subsets kr supports):
  x25519, ed25519, ecdsa P-256/SHA-256 (DER sigs), ecdh P-256 (uncompressed points only),
  AES-GCM (96-bit IV, 128-bit tag, 128/256-bit keys), ChaCha20-Poly1305 (96-bit IV), HKDF/HMAC-SHA256.
"""
import json, os, sys
SRC = sys.argv[1]
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "crates", "kr-crypto", "tests", "wycheproof")
os.makedirs(OUT, exist_ok=True)

def load(name): return json.load(open(os.path.join(SRC, name + "_test.json")))
def write(name, rows):
    with open(os.path.join(OUT, name + ".txt"), "w") as f:
        for r in rows: f.write("|".join(str(x) for x in r) + "\n")

def x25519():
    write("x25519", [(t["tcId"], t["result"], t["private"], t["public"], t["shared"])
                     for g in load("x25519")["testGroups"] for t in g["tests"]])

def ed25519():
    write("ed25519", [(t["tcId"], t["result"], g["publicKey"]["pk"], t["msg"], t["sig"])
                      for g in load("ed25519")["testGroups"] for t in g["tests"]])

def ecdsa():
    write("ecdsa_p256_sha256", [(t["tcId"], t["result"], g["publicKey"]["uncompressed"], t["msg"], t["sig"])
                                for g in load("ecdsa_secp256r1_sha256")["testGroups"] for t in g["tests"]])

def ecdh():
    rows = []
    for g in load("ecdh_secp256r1_ecpoint")["testGroups"]:
        for t in g["tests"]:
            d = int(t["private"], 16) if t["private"] else 0
            if d >= 2**256: continue
            rows.append((t["tcId"], t["result"], t["public"], "%064x" % d, t["shared"]))
    write("ecdh_p256", rows)

def aead(src, name, keysizes):
    rows = []
    for g in load(src)["testGroups"]:
        if g["ivSize"] != 96 or g["tagSize"] != 128 or g["keySize"] not in keysizes: continue
        for t in g["tests"]:
            rows.append((t["tcId"], t["result"], t["key"], t["iv"], t["aad"], t["msg"], t["ct"], t["tag"]))
    write(name, rows)

def mac_kdf():
    write("hkdf_sha256", [(t["tcId"], t["result"], t["ikm"], t["salt"], t["info"], t["size"], t["okm"])
                          for g in load("hkdf_sha256")["testGroups"] for t in g["tests"]])
    write("hmac_sha256", [(t["tcId"], t["result"], t["key"], t["msg"], t["tag"], g["tagSize"])
                          for g in load("hmac_sha256")["testGroups"] for t in g["tests"]])

x25519(); ed25519(); ecdsa(); ecdh(); aead("aes_gcm", "aes_gcm", (128, 256)); aead("chacha20_poly1305", "chacha20_poly1305", (256,)); mac_kdf()
