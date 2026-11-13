//! ServiceAccount tokens: ES256 JWTs (RFC 7519/7515) signed with the cluster's SA key.
//!
//! Issued through the TokenRequest API (`serviceaccounts/<name>/token`), optionally bound to a
//! pod. Verification checks the signature, `exp`/`nbf`, the audience, and that the
//! ServiceAccount (and bound pod) still exist with the same uid, so deleting either revokes
//! the token.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_crypto::p256;
use kr_crypto::sha2::sha256;
use kr_fmt::base64;
use kr_fmt::json::{self, Value};

pub const ISSUER: &str = "https://kubernetes.default.svc.cluster.local";

/// Audiences the API server accepts by default (upstream uses the issuer).
pub const API_AUDIENCES: &[&str] = &[ISSUER, "https://kubernetes.default.svc", "kubernetes"];

pub struct Signer {
    key: p256::SecretKey,
    pub_key: [u8; 65],
    kid: String,
    /// Public keys of earlier signing keys: tokens signed with them still verify (rotation overlap).
    old: Vec<([u8; 65], String)>,
    /// Tokens whose signature already verified: SHA-256 of the token -> (claims, nbf). A P-256
    /// verification costs about 0.5 ms and every request of a pod carries its token, so this is
    /// what keeps in-cluster clients cheap (kube-apiserver caches token authentication too). The
    /// time window is checked on every use, revocation by the caller; a key rotation builds a new
    /// Signer, which starts empty.
    cache: core::cell::RefCell<alloc::collections::BTreeMap<[u8; 32], (Claims, i64)>>,
}

/// Verified tokens kept at most (about 300 bytes each).
const CACHE_MAX: usize = 4096;

/// Verified token contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    pub namespace: String,
    pub sa_name: String,
    pub sa_uid: String,
    pub pod: Option<(String, String)>, // (name, uid)
    pub audiences: Vec<String>,
    pub exp: i64,
    /// Token id (`jti`), the credential id reported by TokenReview.
    pub jti: String,
}

/// JWS uses unpadded base64url, which is exactly kr-fmt's URL-safe codec.
fn b64(data: &[u8]) -> String {
    base64::encode_url(data)
}

fn unb64(s: &str) -> Option<Vec<u8>> {
    base64::decode_url(s).ok()
}

impl Signer {
    pub fn new(key: p256::SecretKey) -> Signer {
        let pub_key = key.public_key();
        // kid: base64url(SHA-256 of the public key), like upstream's key-id derivation.
        let kid = b64(&sha256(&pub_key));
        Signer { key, pub_key, kid, old: Vec::new(), cache: core::cell::RefCell::new(alloc::collections::BTreeMap::new()) }
    }

    /// Accepts tokens signed by `key` as well (an earlier signing key kept for the overlap after a
    /// rotation); it never signs.
    pub fn add_verify_key(&mut self, key: &p256::SecretKey) {
        let pk = key.public_key();
        let kid = b64(&sha256(&pk));
        if kid != self.kid && !self.old.iter().any(|(_, k)| *k == kid) {
            self.old.push((pk, kid));
        }
        self.cache.borrow_mut().clear();
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Issues a token for `system:serviceaccount:<ns>:<name>`.
    pub fn issue(&self, ns: &str, name: &str, sa_uid: &str, pod: Option<(&str, &str)>, audiences: &[String], now: i64, ttl: i64) -> String {
        let header = alloc::format!(r#"{{"alg":"ES256","kid":"{}"}}"#, self.kid);
        let auds: Vec<Value> = audiences.iter().map(|a| Value::String(a.clone())).collect();
        let mut k8s = alloc::vec![
            ("namespace".into(), Value::from(ns)),
            ("serviceaccount".into(), Value::Object(alloc::vec![("name".into(), Value::from(name)), ("uid".into(), Value::from(sa_uid))])),
        ];
        if let Some((pn, pu)) = pod {
            k8s.push(("pod".into(), Value::Object(alloc::vec![("name".into(), Value::from(pn)), ("uid".into(), Value::from(pu))])));
        }
        // jti: a digest of everything that identifies this issuance (distinct tokens differ in
        // audience, subject, bound pod or time).
        let ident = alloc::format!("{ns}/{name}/{sa_uid}/{pod:?}/{audiences:?}/{now}/{ttl}");
        let d = sha256(ident.as_bytes());
        let jti = alloc::format!("{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]);
        let claims = Value::Object(alloc::vec![
            ("aud".into(), Value::Array(auds)),
            ("exp".into(), Value::from((now + ttl) as u64)),
            ("iat".into(), Value::from(now as u64)),
            ("iss".into(), Value::from(ISSUER)),
            ("jti".into(), Value::String(jti)),
            ("kubernetes.io".into(), Value::Object(k8s)),
            ("nbf".into(), Value::from(now as u64)),
            ("sub".into(), Value::String(alloc::format!("system:serviceaccount:{ns}:{name}"))),
        ]);
        let signing_input = alloc::format!("{}.{}", b64(header.as_bytes()), b64(json::to_string(&claims).as_bytes()));
        let (r, s) = self.key.sign(signing_input.as_bytes());
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r);
        sig[32..].copy_from_slice(&s);
        alloc::format!("{signing_input}.{}", b64(&sig))
    }

    /// Verifies signature and time window; returns the claims (existence checks are the
    /// caller's, since they need the store).
    pub fn verify(&self, token: &str, now: i64) -> Option<Claims> {
        let id = sha256(token.as_bytes());
        if let Some((c, nbf)) = self.cache.borrow().get(&id) {
            // 60 s leeway for clock skew, as upstream (and as below).
            return (now <= c.exp + 60 && now + 60 >= *nbf).then(|| c.clone());
        }
        let (c, nbf) = self.verify_uncached(token, now)?;
        let mut cache = self.cache.borrow_mut();
        if cache.len() >= CACHE_MAX {
            cache.retain(|_, (c, _)| now <= c.exp + 60);
            if cache.len() >= CACHE_MAX {
                cache.clear();
            }
        }
        cache.insert(id, (c.clone(), nbf));
        Some(c)
    }

    fn verify_uncached(&self, token: &str, now: i64) -> Option<(Claims, i64)> {
        let mut parts = token.split('.');
        let (h, c, s) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() || token.len() > 16 * 1024 {
            return None;
        }
        let header = json::parse(&unb64(h)?).ok()?;
        if header.get("alg").and_then(Value::as_str) != Some("ES256") {
            return None; // never "none" or anything else
        }
        let sig = unb64(s)?;
        if sig.len() != 64 {
            return None;
        }
        let digest = sha256(alloc::format!("{h}.{c}").as_bytes());
        // The key named by `kid` (the current one, or an earlier one kept for the overlap).
        let kid = header.get("kid").and_then(Value::as_str).unwrap_or("");
        let key = if kid == self.kid || kid.is_empty() { &self.pub_key } else { &self.old.iter().find(|(_, k)| k == kid)?.0 };
        if !p256::verify_digest(key, &digest, sig[..32].try_into().ok()?, sig[32..].try_into().ok()?) {
            return None;
        }
        let claims = json::parse(&unb64(c)?).ok()?;
        if claims.get("iss").and_then(Value::as_str) != Some(ISSUER) {
            return None;
        }
        let exp = claims.get("exp").and_then(Value::as_i64)?;
        let nbf = claims.get("nbf").and_then(Value::as_i64).unwrap_or(0);
        // 60 s leeway for clock skew, as upstream.
        if now > exp + 60 || now + 60 < nbf {
            return None;
        }
        let k8s = claims.get("kubernetes.io")?;
        let audiences = match claims.get("aud")? {
            Value::String(a) => alloc::vec![a.clone()],
            Value::Array(a) => a.iter().filter_map(Value::as_str).map(String::from).collect(),
            _ => return None,
        };
        let pod = k8s.get("pod").map(|p| (p.get("name").and_then(Value::as_str).unwrap_or("").to_string(), p.get("uid").and_then(Value::as_str).unwrap_or("").to_string()));
        Some((Claims {
            namespace: k8s.get("namespace")?.as_str()?.to_string(),
            sa_name: k8s.pointer(&["serviceaccount", "name"])?.as_str()?.to_string(),
            sa_uid: k8s.pointer(&["serviceaccount", "uid"])?.as_str()?.to_string(),
            pod,
            audiences,
            exp,
            jti: claims.get("jti").and_then(Value::as_str).unwrap_or("").to_string(),
        }, nbf))
    }

    /// JWKS document for service-account issuer discovery.
    pub fn jwks(&self) -> String {
        let one = |pk: &[u8; 65], kid: &str| alloc::format!(r#"{{"use":"sig","kty":"EC","kid":"{kid}","crv":"P-256","alg":"ES256","x":"{}","y":"{}"}}"#, b64(&pk[1..33]), b64(&pk[33..]));
        let mut keys = alloc::vec![one(&self.pub_key, &self.kid)];
        keys.extend(self.old.iter().map(|(pk, kid)| one(pk, kid)));
        alloc::format!(r#"{{"keys":[{}]}}"#, keys.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_of_an_earlier_key_verify_while_it_is_kept() {
        let old_key = p256::SecretKey::from_bytes(&[3; 32]).unwrap();
        let aud = alloc::vec![String::from(ISSUER)];
        let old_token = Signer::new(p256::SecretKey::from_bytes(&[3; 32]).unwrap()).issue("d", "sa", "uid-1", None, &aud, 1_000, 3600);
        let mut rotated = Signer::new(p256::SecretKey::from_bytes(&[4; 32]).unwrap());
        assert!(rotated.verify(&old_token, 1_100).is_none(), "an unknown key is refused");
        rotated.add_verify_key(&old_key);
        assert_eq!(rotated.verify(&old_token, 1_100).unwrap().sa_name, "sa");
        let fresh = rotated.issue("d", "sa", "uid-1", None, &aud, 1_000, 3600);
        assert!(rotated.verify(&fresh, 1_100).is_some());
        assert_eq!(rotated.jwks().matches("\"kid\"").count(), 2, "both keys are published");
        let mut forged = old_token.clone();
        forged.replace_range(forged.len() - 4.., "AAAA");
        assert!(rotated.verify(&forged, 1_100).is_none());
    }

    #[test]
    fn issue_verify_and_tamper() {
        let s = Signer::new(p256::SecretKey::from_bytes(&[9; 32]).unwrap());
        let aud = alloc::vec![String::from(ISSUER)];
        let t = s.issue("default", "bot", "uid-1", Some(("p", "puid")), &aud, 1_800_000_000, 3600);
        let c = s.verify(&t, 1_800_000_100).unwrap();
        assert_eq!((c.namespace.as_str(), c.sa_name.as_str(), c.sa_uid.as_str()), ("default", "bot", "uid-1"));
        assert_eq!(c.pod, Some(("p".into(), "puid".into())));
        assert!(s.verify(&t, 1_800_000_000 + 3600 + 61).is_none(), "expired");
        // Flip a character of the payload: signature must fail.
        let mut parts: Vec<String> = t.split('.').map(String::from).collect();
        parts[1] = parts[1].replacen('e', "f", 1);
        assert!(s.verify(&parts.join("."), 1_800_000_100).is_none());
        // alg=none is refused.
        let none = alloc::format!("{}.{}.", b64(br#"{"alg":"none"}"#), t.split('.').nth(1).unwrap());
        assert!(s.verify(&none, 1_800_000_100).is_none());
        // Another key's token is refused.
        let other = Signer::new(p256::SecretKey::from_bytes(&[8; 32]).unwrap());
        assert!(s.verify(&other.issue("default", "bot", "uid-1", None, &aud, 1_800_000_000, 3600), 1_800_000_100).is_none());
    }

    #[test]
    fn cached_tokens_keep_their_time_window_and_the_cache_is_bounded() {
        let s = Signer::new(p256::SecretKey::from_bytes(&[5; 32]).unwrap());
        let aud = alloc::vec![String::from(ISSUER)];
        let t = s.issue("d", "sa", "u", None, &aud, 10_000, 3600);
        assert!(s.verify(&t, 10_100).is_some());
        assert!(s.verify(&t, 10_000 - 61).is_none(), "not yet valid, though cached");
        assert!(s.verify(&t, 10_000 + 3600 + 61).is_none(), "expired, though cached");
        assert!(s.verify(&t, 10_100).is_some());
        for i in 0..(CACHE_MAX + 10) {
            assert!(s.verify(&s.issue("d", "sa", "u", None, &aud, i as i64, 3600), i as i64).is_some());
        }
        assert!(s.cache.borrow().len() <= CACHE_MAX);
    }
}
