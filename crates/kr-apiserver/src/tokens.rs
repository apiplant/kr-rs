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
}

/// Verified token contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    pub namespace: String,
    pub sa_name: String,
    pub sa_uid: String,
    pub pod: Option<(String, String)>, // (name, uid)
    pub audiences: Vec<String>,
    pub exp: i64,
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
        Signer { key, pub_key, kid }
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
        let claims = Value::Object(alloc::vec![
            ("aud".into(), Value::Array(auds)),
            ("exp".into(), Value::from((now + ttl) as u64)),
            ("iat".into(), Value::from(now as u64)),
            ("iss".into(), Value::from(ISSUER)),
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
        if !p256::verify_digest(&self.pub_key, &digest, sig[..32].try_into().ok()?, sig[32..].try_into().ok()?) {
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
        Some(Claims {
            namespace: k8s.get("namespace")?.as_str()?.to_string(),
            sa_name: k8s.pointer(&["serviceaccount", "name"])?.as_str()?.to_string(),
            sa_uid: k8s.pointer(&["serviceaccount", "uid"])?.as_str()?.to_string(),
            pod,
            audiences,
            exp,
        })
    }

    /// JWKS document for service-account issuer discovery.
    pub fn jwks(&self) -> String {
        alloc::format!(
            r#"{{"keys":[{{"use":"sig","kty":"EC","kid":"{}","crv":"P-256","alg":"ES256","x":"{}","y":"{}"}}]}}"#,
            self.kid,
            b64(&self.pub_key[1..33]),
            b64(&self.pub_key[33..])
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
