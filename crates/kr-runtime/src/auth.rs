//! Registry credentials from Kubernetes image pull secrets (`kubernetes.io/dockerconfigjson`
//! and legacy `kubernetes.io/dockercfg`). Credentials are never logged or formatted.
use crate::store::{Error, Result};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_fmt::json::Value;
pub use kr_net::registry::Credential;

/// A credential and the (canonical) registry host it applies to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cred {
    pub registry: String,
    pub cred: Credential,
}

/// Canonical registry host for matching: scheme, path (`/v1/`) and case dropped, docker.io
/// aliases folded (`index.docker.io`, `registry-1.docker.io`, ...).
pub fn registry_key(s: &str) -> String {
    let s = s.trim().to_ascii_lowercase();
    let s = s.strip_prefix("https://").or_else(|| s.strip_prefix("http://")).unwrap_or(&s);
    let host = s.split('/').next().unwrap_or("").to_string();
    match host.as_str() {
        "index.docker.io" | "registry-1.docker.io" | "registry.hub.docker.com" | "docker.io" => "docker.io".to_string(),
        _ => host,
    }
}

/// The credential for `registry` (a [`kr_net::registry::Reference`] registry), if any.
pub fn lookup<'a>(creds: &'a [Cred], registry: &str) -> Option<&'a Credential> {
    let want = registry_key(registry);
    creds.iter().find(|c| c.registry == want).map(|c| &c.cred)
}

fn entry(host: &str, v: &Value) -> Option<Cred> {
    let mut cred = Credential::default();
    if let Some(a) = v.get("auth").and_then(Value::as_str).filter(|a| !a.is_empty()) {
        let raw = kr_fmt::base64::decode(a.trim()).ok()?;
        let raw = String::from_utf8(raw).ok()?;
        let (u, p) = raw.split_once(':')?;
        cred.username = u.to_string();
        cred.password = p.to_string();
    }
    if let Some(u) = v.get("username").and_then(Value::as_str).filter(|u| !u.is_empty()) {
        cred.username = u.to_string();
        cred.password = v.get("password").and_then(Value::as_str).unwrap_or("").to_string();
    }
    cred.identity_token = v.get("identitytoken").and_then(Value::as_str).filter(|t| !t.is_empty()).map(|t| t.to_string());
    if cred.username.is_empty() && cred.identity_token.is_none() {
        return None;
    }
    Some(Cred { registry: registry_key(host), cred })
}

/// Parses a docker config: `{"auths": {registry: {auth | username+password, identitytoken}}}`
/// (`.dockerconfigjson`) or the legacy top-level `{registry: {...}}` (`.dockercfg`).
/// Unusable entries are skipped.
pub fn parse_dockerconfig(json: &[u8]) -> Result<Vec<Cred>> {
    let v = kr_fmt::json::parse(json).map_err(|_| Error::Json("invalid docker config"))?;
    let map = match v.get("auths") {
        Some(a) => a,
        None => &v,
    };
    let obj = map.as_object().ok_or(Error::Json("docker config is not an object"))?;
    Ok(obj.iter().filter_map(|(host, e)| entry(host, e)).collect())
}

/// Credentials from a Secret object (type dockerconfigjson / dockercfg, `data` base64).
pub fn from_secret(secret: &Value) -> Vec<Cred> {
    let ty = secret.get("type").and_then(Value::as_str).unwrap_or("");
    let key = match ty {
        "kubernetes.io/dockerconfigjson" => ".dockerconfigjson",
        "kubernetes.io/dockercfg" => ".dockercfg",
        _ => return Vec::new(),
    };
    let Some(b64) = secret.pointer(&["data", key]).and_then(Value::as_str) else { return Vec::new() };
    let Ok(raw) = kr_fmt::base64::decode(b64.trim()) else { return Vec::new() };
    parse_dockerconfig(&raw).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn registry_matching() {
        for k in ["docker.io", "index.docker.io", "https://index.docker.io/v1/", "registry-1.docker.io", "HTTPS://Registry-1.Docker.io"] {
            assert_eq!(registry_key(k), "docker.io", "{k}");
        }
        assert_eq!(registry_key("https://quay.io/v2/"), "quay.io");
        assert_eq!(registry_key("localhost:5000/v1/"), "localhost:5000");
        assert_eq!(registry_key("reg.example.com"), "reg.example.com");
    }

    #[test]
    fn dockerconfigjson() {
        let auth = kr_fmt::base64::encode(b"alice:p:w");
        let cfg = format!(
            r#"{{"auths":{{"https://index.docker.io/v1/":{{"auth":"{auth}"}},"reg.io":{{"username":"bob","password":"pw"}},"id.io":{{"identitytoken":"rt"}},"junk.io":{{"auth":"!!"}},"empty.io":{{}}}}}}"#
        );
        let creds = parse_dockerconfig(cfg.as_bytes()).unwrap();
        assert_eq!(creds.len(), 3);
        let c = lookup(&creds, "docker.io").unwrap();
        assert_eq!((c.username.as_str(), c.password.as_str()), ("alice", "p:w"));
        let c = lookup(&creds, "reg.io").unwrap();
        assert_eq!((c.username.as_str(), c.password.as_str()), ("bob", "pw"));
        assert_eq!(lookup(&creds, "id.io").unwrap().identity_token.as_deref(), Some("rt"));
        assert!(lookup(&creds, "other.io").is_none());
        assert!(lookup(&creds, "junk.io").is_none());
        // Debug never shows secrets
        assert!(!format!("{creds:?}").contains("alice") && !format!("{creds:?}").contains("pw"));
    }

    #[test]
    fn legacy_dockercfg_and_secret() {
        let auth = kr_fmt::base64::encode(b"u:p");
        let cfg = format!(r#"{{"reg.io":{{"auth":"{auth}","email":"a@b"}}}}"#);
        let creds = parse_dockerconfig(cfg.as_bytes()).unwrap();
        assert_eq!(lookup(&creds, "reg.io").unwrap().username, "u");
        let secret = kr_fmt::json::parse(format!(r#"{{"type":"kubernetes.io/dockercfg","data":{{".dockercfg":"{}"}}}}"#, kr_fmt::base64::encode(cfg.as_bytes())).as_bytes()).unwrap();
        assert_eq!(from_secret(&secret).len(), 1);
        let other = kr_fmt::json::parse(br#"{"type":"Opaque","data":{}}"#).unwrap();
        assert!(from_secret(&other).is_empty());
        assert!(parse_dockerconfig(b"[]").is_err());
    }
}
