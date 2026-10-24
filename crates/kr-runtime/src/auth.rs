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

/// Canonical key for matching: scheme and case dropped, docker.io aliases folded
/// (`index.docker.io`, `registry-1.docker.io`, ...), the legacy `/v1/` suffix dropped. A
/// repository path is kept (`registry.io/org/team`), as is a `*.` wildcard host.
pub fn registry_key(s: &str) -> String {
    let s = s.trim().to_ascii_lowercase();
    let s = s.strip_prefix("https://").or_else(|| s.strip_prefix("http://")).unwrap_or(&s);
    let s = s.trim_end_matches('/');
    let s = s.strip_suffix("/v1").or_else(|| s.strip_suffix("/v2")).unwrap_or(s);
    let (host, path) = s.split_once('/').unwrap_or((s, ""));
    let host = match host {
        "index.docker.io" | "registry-1.docker.io" | "registry.hub.docker.com" | "docker.io" => "docker.io",
        h => h,
    };
    if path.is_empty() { host.to_string() } else { alloc::format!("{host}/{path}") }
}

/// Whether credential key `key` applies to `host` + `repo`, and how specifically (higher wins):
/// exact host beats `*.` wildcard, and a longer repository prefix (on `/` boundaries) beats a
/// shorter one, as the kubelet's credential-provider matching does.
fn match_rank(key: &str, host: &str, repo: &str) -> Option<usize> {
    let (khost, kpath) = key.split_once('/').unwrap_or((key, ""));
    let host_rank = if khost == host {
        2
    } else if let Some(suffix) = khost.strip_prefix("*.") {
        // One label only, like the kubelet: *.example.com matches a.example.com.
        let (label, rest) = host.split_once('.')?;
        if rest != suffix || label.is_empty() {
            return None;
        }
        1
    } else {
        return None;
    };
    if !kpath.is_empty() && !(repo == kpath || repo.starts_with(kpath) && repo.as_bytes().get(kpath.len()) == Some(&b'/')) {
        return None;
    }
    Some(kpath.len() * 4 + host_rank)
}

/// The most specific credential for `registry` + `repository` (from a
/// [`kr_net::registry::Reference`]), if any.
pub fn lookup<'a>(creds: &'a [Cred], registry: &str, repository: &str) -> Option<&'a Credential> {
    let host = registry_key(registry);
    let repo = repository.to_ascii_lowercase();
    creds.iter().filter_map(|c| match_rank(&c.registry, &host, &repo).map(|r| (r, &c.cred))).max_by_key(|(r, _)| *r).map(|(_, c)| c)
}

/// Docker client config for `kr ctr pull`: `$DOCKER_CONFIG/config.json`, else
/// `~/.docker/config.json`. Credential helpers (`credsStore`/`credHelpers`) are not run.
pub fn docker_config(env: &dyn Fn(&str) -> Option<String>) -> Vec<Cred> {
    let path = match (env("DOCKER_CONFIG"), env("HOME")) {
        (Some(d), _) if !d.is_empty() => alloc::format!("{d}/config.json"),
        (_, Some(h)) => alloc::format!("{h}/.docker/config.json"),
        _ => return Vec::new(),
    };
    let Ok(data) = kr_sys::fs::read_file(alloc::format!("{path}\0").as_bytes(), 1 << 20) else { return Vec::new() };
    parse_dockerconfig(&data).unwrap_or_default()
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
        let c = lookup(&creds, "docker.io", "lib/app").unwrap();
        assert_eq!((c.username.as_str(), c.password.as_str()), ("alice", "p:w"));
        let c = lookup(&creds, "reg.io", "lib/app").unwrap();
        assert_eq!((c.username.as_str(), c.password.as_str()), ("bob", "pw"));
        assert_eq!(lookup(&creds, "id.io", "lib/app").unwrap().identity_token.as_deref(), Some("rt"));
        assert!(lookup(&creds, "other.io", "lib/app").is_none());
        assert!(lookup(&creds, "junk.io", "lib/app").is_none());
        // Debug never shows secrets
        assert!(!format!("{creds:?}").contains("alice") && !format!("{creds:?}").contains("pw"));
    }

    #[test]
    fn legacy_dockercfg_and_secret() {
        let auth = kr_fmt::base64::encode(b"u:p");
        let cfg = format!(r#"{{"reg.io":{{"auth":"{auth}","email":"a@b"}}}}"#);
        let creds = parse_dockerconfig(cfg.as_bytes()).unwrap();
        assert_eq!(lookup(&creds, "reg.io", "lib/app").unwrap().username, "u");
        let secret = kr_fmt::json::parse(format!(r#"{{"type":"kubernetes.io/dockercfg","data":{{".dockercfg":"{}"}}}}"#, kr_fmt::base64::encode(cfg.as_bytes())).as_bytes()).unwrap();
        assert_eq!(from_secret(&secret).len(), 1);
        let other = kr_fmt::json::parse(br#"{"type":"Opaque","data":{}}"#).unwrap();
        assert!(from_secret(&other).is_empty());
        assert!(parse_dockerconfig(b"[]").is_err());
    }
}

#[cfg(test)]
mod prefix_tests {
    use super::*;

    fn creds(keys: &[&str]) -> Vec<Cred> {
        keys.iter().map(|k| Cred { registry: registry_key(k), cred: Credential { username: (*k).to_string(), ..Default::default() } }).collect()
    }

    #[test]
    fn most_specific_key_wins() {
        let c = creds(&["reg.io", "reg.io/team", "reg.io/team/app", "*.cdn.io", "https://index.docker.io/v1/"]);
        let user = |h: &str, r: &str| lookup(&c, h, r).map(|x| x.username.clone());
        assert_eq!(user("reg.io", "team/app").as_deref(), Some("reg.io/team/app"));
        assert_eq!(user("reg.io", "team/other").as_deref(), Some("reg.io/team"));
        assert_eq!(user("reg.io", "teamx/app").as_deref(), Some("reg.io")); // prefix on '/' only
        assert_eq!(user("reg.io", "lib").as_deref(), Some("reg.io"));
        assert_eq!(user("eu.cdn.io", "x").as_deref(), Some("*.cdn.io"));
        assert_eq!(user("a.b.cdn.io", "x"), None); // one label only
        assert_eq!(user("cdn.io", "x"), None);
        assert_eq!(user("docker.io", "library/alpine").as_deref(), Some("https://index.docker.io/v1/"));
        assert_eq!(user("other.io", "x"), None);
    }
}
