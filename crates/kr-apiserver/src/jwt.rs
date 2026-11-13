//! JWT authenticators (OIDC, `AuthenticationConfiguration` `jwt[]`, `--oidc-*`).
//!
//! A token is routed to the authenticator whose `issuer.url` equals its (unverified) `iss`.
//! Verification is synchronous and uses only the cached JWKS: signature (RS256/384/512, ES256),
//! `iss`, `aud`, `exp`/`nbf`/`iat` with 60 s skew, the claim validation rules, then the claim
//! mappings. Keys come from `<issuer>/.well-known/openid-configuration` -> `jwks_uri` (or
//! `issuer.discoveryURL`) over HTTPS, fetched by a background task at start and hourly, and
//! again (rate limited to once per 10 s) when a token names a `kid` that is not cached: the
//! transport awaits that refresh before authenticating ([`Jwt::ensure_key`]), the synchronous
//! path (TokenReview) only schedules it and fails closed.

use crate::api::User;
use crate::cel::Program;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use kr_crypto::rsa::{self, HashAlg};
use kr_crypto::sha2::sha256;
use kr_crypto::{der, p256, x509};
use kr_fmt::base64;
use kr_fmt::json::{self, Value};
use kr_net::http1::client::{Client as Http, Config as HttpConfig};
use kr_net::tls::TlsConnector;

/// Clock skew allowed on `exp`, `nbf` and `iat`.
const SKEW: i64 = 60;
/// At most one key refresh per issuer in this interval (unknown `kid`s cannot flood the issuer).
const REFRESH_MIN_MS: u64 = 10_000;
/// Keys are re-read this often even without an unknown `kid`.
const REFRESH_EVERY_MS: u64 = 3_600_000;
const CACHE_MAX: usize = 4096;

enum Map {
    None,
    /// (claim, prefix)
    Claim(String, String),
    Expr(Program),
}

enum Rule {
    /// (claim, required value)
    Claim(String, String),
    /// CEL over `claims` (the message is not reported: clients only see 401).
    Expr(Program),
}

enum Key {
    Rsa(rsa::PublicKey),
    P256([u8; 65]),
}

pub struct Jwt {
    pub issuer: String,
    discovery: String,
    audiences: Vec<String>,
    username: Map,
    groups: Map,
    uid: Map,
    rules: Vec<Rule>,
    user_rules: Vec<Program>,
    keys: RefCell<Vec<(String, Key)>>,
    http: Http<TlsConnector>,
    last_try: Cell<u64>,
    min_refresh_ms: Cell<u64>,
    last_ok: Cell<u64>,
    busy: Cell<bool>,
    want: Cell<bool>,
    /// SHA-256 of a verified token -> (user, nbf, exp).
    cache: RefCell<BTreeMap<[u8; 32], (User, i64, i64)>>,
}

fn unb64(s: &str) -> Option<Vec<u8>> {
    base64::decode_url(s.trim_end_matches('=')).ok()
}

/// (header, claims) of a compact JWS, unverified.
pub fn peek(token: &str) -> Option<(Value, Value)> {
    let mut p = token.split('.');
    let (h, c) = (p.next()?, p.next()?);
    if token.len() > 16 * 1024 {
        return None;
    }
    Some((json::parse(&unb64(h)?).ok()?, json::parse(&unb64(c)?).ok()?))
}

fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(String::from)
}

fn strs(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => alloc::vec![s.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(String::from).collect(),
        _ => Vec::new(),
    }
}

fn mapping(v: Option<&Value>, what: &str, need_prefix: bool) -> Result<Map, String> {
    let Some(v) = v else { return Ok(Map::None) };
    match (s(v, "claim").filter(|c| !c.is_empty()), s(v, "expression").filter(|c| !c.is_empty())) {
        (Some(_), Some(_)) => Err(format!("claimMappings.{what}: claim and expression are mutually exclusive")),
        (Some(c), None) => {
            let prefix = s(v, "prefix");
            if need_prefix && prefix.is_none() {
                return Err(format!("claimMappings.{what}.prefix: Required value (may be \"\")"));
            }
            Ok(Map::Claim(c, prefix.unwrap_or_default()))
        }
        (None, Some(e)) => {
            if s(v, "prefix").is_some_and(|p| !p.is_empty()) {
                return Err(format!("claimMappings.{what}.prefix: may not be set with expression"));
            }
            Ok(Map::Expr(Program::compile(&e, &["claims"]).map_err(|e| format!("claimMappings.{what}.expression: {e}"))?))
        }
        (None, None) => Ok(Map::None),
    }
}

/// The settings of one authenticator before its HTTP client exists.
pub struct Spec {
    pub issuer: String,
    pub discovery: Option<String>,
    pub audiences: Vec<String>,
    /// PEM of the issuer's CA; empty for the caller's default roots.
    pub ca_pem: String,
    username: Map,
    groups: Map,
    uid: Map,
    rules: Vec<Rule>,
    user_rules: Vec<Program>,
}

fn check_url(u: &str, what: &str) -> Result<(), String> {
    if !u.starts_with("https://") || u.contains('#') || u.contains('?') {
        return Err(format!("{what}: must be an https:// URL without query or fragment"));
    }
    Ok(())
}

/// Parses an `AuthenticationConfiguration` (apiserver.config.k8s.io v1alpha1/v1beta1/v1); only
/// `jwt` is used.
pub fn parse_config(text: &str) -> Result<Vec<Spec>, String> {
    let v = kr_fmt::yaml::parse(text).map_err(|e| format!("authentication config: {e:?}"))?;
    if v.get("kind").and_then(Value::as_str).is_some_and(|k| k != "AuthenticationConfiguration") {
        return Err("authentication config: kind must be AuthenticationConfiguration".into());
    }
    let mut out: Vec<Spec> = Vec::new();
    for (i, j) in v.get("jwt").and_then(Value::as_array).unwrap_or(&[]).iter().enumerate() {
        let at = |m: String| format!("authentication config: jwt[{i}].{m}");
        let iss = j.get("issuer").ok_or_else(|| at("issuer: Required value".into()))?;
        let url = s(iss, "url").unwrap_or_default();
        check_url(&url, "issuer.url").map_err(at)?;
        if out.iter().any(|o| o.issuer == url) {
            return Err(at("issuer.url: Duplicate value".into()));
        }
        let discovery = s(iss, "discoveryURL").filter(|d| !d.is_empty());
        if let Some(d) = &discovery {
            check_url(d, "issuer.discoveryURL").map_err(at)?;
        }
        let audiences = strs(iss.get("audiences"));
        if audiences.is_empty() {
            return Err(at("issuer.audiences: Required value".into()));
        }
        match s(iss, "audienceMatchPolicy").as_deref() {
            None | Some("") if audiences.len() == 1 => {}
            Some("MatchAny") => {}
            _ => return Err(at("issuer.audienceMatchPolicy: must be MatchAny when several audiences are given".into())),
        }
        let cm = j.get("claimMappings").ok_or_else(|| at("claimMappings: Required value".into()))?;
        let username = mapping(cm.get("username"), "username", true).map_err(at)?;
        if matches!(username, Map::None) {
            return Err(at("claimMappings.username: Required value".into()));
        }
        let mut rules = Vec::new();
        for r in j.get("claimValidationRules").and_then(Value::as_array).unwrap_or(&[]) {
            match (s(r, "claim").filter(|c| !c.is_empty()), s(r, "expression").filter(|c| !c.is_empty())) {
                (Some(c), None) => rules.push(Rule::Claim(c, s(r, "requiredValue").unwrap_or_default())),
                (None, Some(e)) => rules.push(Rule::Expr(Program::compile(&e, &["claims"]).map_err(|e| at(format!("claimValidationRules: {e}")))?)),
                _ => return Err(at("claimValidationRules: exactly one of claim and expression".into())),
            }
        }
        let mut user_rules = Vec::new();
        for r in j.get("userValidationRules").and_then(Value::as_array).unwrap_or(&[]) {
            user_rules.push(Program::compile(&s(r, "expression").unwrap_or_default(), &["user"]).map_err(|e| at(format!("userValidationRules: {e}")))?);
        }
        out.push(Spec {
            issuer: url,
            discovery,
            audiences,
            ca_pem: s(iss, "certificateAuthority").unwrap_or_default(),
            username,
            groups: mapping(cm.get("groups"), "groups", true).map_err(at)?,
            uid: mapping(cm.get("uid"), "uid", false).map_err(at)?,
            rules,
            user_rules,
        });
    }
    Ok(out)
}

/// One authenticator from the `--oidc-*` settings (kube-apiserver semantics: the username
/// prefix defaults to `<issuer>#` unless the claim is `email`; `-` means none).
#[allow(clippy::too_many_arguments)]
pub fn oidc_spec(issuer: &str, client_id: &str, username_claim: Option<&str>, username_prefix: Option<&str>, groups_claim: Option<&str>, groups_prefix: Option<&str>, required: Option<&str>, ca_pem: String) -> Result<Spec, String> {
    check_url(issuer, "oidc-issuer-url")?;
    if client_id.is_empty() {
        return Err("oidc-client-id: Required value".into());
    }
    let claim = username_claim.filter(|c| !c.is_empty()).unwrap_or("sub");
    let prefix = match username_prefix {
        Some("-") => String::new(),
        Some(p) if !p.is_empty() => p.to_string(),
        _ if claim == "email" => String::new(),
        _ => format!("{issuer}#"),
    };
    let mut rules = Vec::new();
    for kv in required.unwrap_or("").split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').ok_or("oidc-required-claim: expected key=value")?;
        rules.push(Rule::Claim(k.trim().into(), v.trim().into()));
    }
    Ok(Spec {
        issuer: issuer.into(),
        discovery: None,
        audiences: alloc::vec![client_id.into()],
        ca_pem,
        username: Map::Claim(claim.into(), prefix),
        groups: match groups_claim.filter(|c| !c.is_empty()) {
            Some(g) => Map::Claim(g.into(), groups_prefix.unwrap_or("").into()),
            None => Map::None,
        },
        uid: Map::None,
        rules,
        user_rules: Vec::new(),
    })
}

/// A JWK as a key (RSA or P-256); other types are skipped.
fn jwk(k: &Value) -> Option<(String, Key)> {
    if s(k, "use").is_some_and(|u| u != "sig") {
        return None;
    }
    let kid = s(k, "kid").unwrap_or_default();
    match k.get("kty").and_then(Value::as_str)? {
        "RSA" => {
            let (n, e) = (unb64(&s(k, "n")?)?, unb64(&s(k, "e")?)?);
            let mut d = Vec::new();
            der::nested(&mut d, der::SEQUENCE, |o| {
                der::uint(o, &n);
                der::uint(o, &e);
            });
            Some((kid, Key::Rsa(rsa::PublicKey::from_pkcs1(&d)?)))
        }
        "EC" if k.get("crv").and_then(Value::as_str) == Some("P-256") => {
            let (x, y) = (unb64(&s(k, "x")?)?, unb64(&s(k, "y")?)?);
            if x.len() != 32 || y.len() != 32 {
                return None;
            }
            let mut pk = [4u8; 65];
            pk[1..33].copy_from_slice(&x);
            pk[33..].copy_from_slice(&y);
            Some((kid, Key::P256(pk)))
        }
        _ => None,
    }
}

/// Keys of a JWKS document.
fn parse_jwks(body: &[u8]) -> Option<Vec<(String, Key)>> {
    let v = json::parse(body).ok()?;
    Some(v.get("keys")?.as_array()?.iter().filter_map(jwk).collect())
}

fn verify_sig(alg: &str, key: &Key, input: &[u8], sig: &[u8]) -> bool {
    match (alg, key) {
        ("RS256", Key::Rsa(k)) => k.verify_pkcs1v15(HashAlg::Sha256, input, sig),
        ("RS384", Key::Rsa(k)) => k.verify_pkcs1v15(HashAlg::Sha384, input, sig),
        ("RS512", Key::Rsa(k)) => k.verify_pkcs1v15(HashAlg::Sha512, input, sig),
        ("ES256", Key::P256(pk)) if sig.len() == 64 => p256::verify_digest(pk, &sha256(input), sig[..32].try_into().unwrap(), sig[32..].try_into().unwrap()),
        _ => false,
    }
}

/// The claim value as a string (strings only, like upstream).
fn claim_str(claims: &Value, c: &str) -> Option<String> {
    claims.get(c).and_then(Value::as_str).map(String::from)
}

impl Jwt {
    /// `roots`: trust anchors when the spec names no CA (the system bundle).
    pub fn new(spec: Spec, roots: &[Vec<u8>]) -> Result<Rc<Jwt>, String> {
        let roots = if spec.ca_pem.trim().is_empty() { roots.to_vec() } else { x509::pem_decode_all(&spec.ca_pem, "CERTIFICATE").map_err(|_| format!("{}: invalid certificateAuthority", spec.issuer))? };
        let tls = Rc::new(kr_crypto::tls::ClientConfig { pinned_ca: None, roots, client_cert: None, alpn: alloc::vec![b"http/1.1".to_vec()], tls12: true });
        let http = Http::with_connector(
            TlsConnector::new(kr_net::dns::SystemResolver::system(), tls),
            HttpConfig { max_redirects: 0, max_idle: 1, connect_timeout_ms: 5_000, head_timeout_ms: 10_000, read_timeout_ms: 10_000, user_agent: "kr-apiserver".to_string(), ..HttpConfig::default() },
        );
        let discovery = spec.discovery.clone().unwrap_or_else(|| format!("{}/.well-known/openid-configuration", spec.issuer.trim_end_matches('/')));
        Ok(Rc::new(Jwt {
            issuer: spec.issuer,
            discovery,
            audiences: spec.audiences,
            username: spec.username,
            groups: spec.groups,
            uid: spec.uid,
            rules: spec.rules,
            user_rules: spec.user_rules,
            keys: RefCell::new(Vec::new()),
            http,
            last_try: Cell::new(0),
            min_refresh_ms: Cell::new(REFRESH_MIN_MS),
            last_ok: Cell::new(0),
            busy: Cell::new(false),
            want: Cell::new(false),
            cache: RefCell::new(BTreeMap::new()),
        }))
    }

    /// Changes the minimum interval between refreshes (tests).
    pub fn set_min_refresh_ms(&self, ms: u64) {
        self.min_refresh_ms.set(ms);
    }

    /// Number of cached keys.
    pub fn key_count(&self) -> usize {
        self.keys.borrow().len()
    }

    async fn get(&self, url: &str) -> Option<Vec<u8>> {
        let fut = async {
            let mut r = self.http.request("GET", url, &[("Accept", "application/json")], &[]).await.ok()?;
            let body = r.read_to_end(1 << 20).await.ok()?;
            (r.status == 200).then_some(body)
        };
        kr_rt::exec::timeout(15_000, fut).await.ok().flatten()
    }

    async fn fetch(&self) -> Option<Vec<(String, Key)>> {
        let d = json::parse(&self.get(&self.discovery).await?).ok()?;
        // The discovery document must name this issuer (OpenID Connect Discovery 1.0, 4.3).
        if d.get("issuer").and_then(Value::as_str).is_some_and(|i| i != self.issuer) {
            return None;
        }
        let uri = d.get("jwks_uri").and_then(Value::as_str)?.to_string();
        parse_jwks(&self.get(&uri).await?)
    }

    /// Reads the keys again, at most once per [`REFRESH_MIN_MS`] unless `force`; a refresh
    /// already running is awaited instead of starting another.
    pub async fn refresh(&self, force: bool) {
        if self.busy.get() {
            while self.busy.get() {
                kr_rt::exec::sleep(5).await;
            }
            return;
        }
        let now = kr_rt::exec::now_ms();
        if !force && self.last_try.get() != 0 && now.saturating_sub(self.last_try.get()) < self.min_refresh_ms.get() {
            return;
        }
        self.busy.set(true);
        self.last_try.set(now);
        self.want.set(false);
        if let Some(k) = self.fetch().await {
            *self.keys.borrow_mut() = k;
            self.last_ok.set(kr_rt::exec::now_ms());
        } else {
            let _ = kr_sys::write(2, format!("kr: oidc: cannot read the signing keys of {}\n", self.issuer).as_bytes());
        }
        self.busy.set(false);
    }

    /// Background key maintenance: first fetch now (retried), then hourly and on request.
    pub fn start(self: &Rc<Self>) {
        let j = self.clone();
        kr_rt::exec::spawn(async move {
            loop {
                let now = kr_rt::exec::now_ms();
                if j.last_ok.get() == 0 || j.want.get() || now.saturating_sub(j.last_ok.get()) >= REFRESH_EVERY_MS {
                    j.refresh(false).await;
                }
                kr_rt::exec::sleep(1000).await;
            }
        });
    }

    fn has_kid(&self, kid: Option<&str>) -> bool {
        let keys = self.keys.borrow();
        match kid {
            Some(k) => keys.iter().any(|(id, _)| id == k),
            None => !keys.is_empty(),
        }
    }

    /// Before a synchronous verification: refreshes the keys (rate limited) when the token's
    /// `kid` is not cached.
    pub async fn ensure_key(&self, token: &str) {
        let Some((h, _)) = peek(token) else { return };
        if !self.has_kid(h.get("kid").and_then(Value::as_str)) {
            self.refresh(false).await;
        }
    }

    /// Verifies a token whose `iss` is this issuer. `Err` is the reason (not shown to clients).
    pub fn verify(&self, token: &str, now: i64) -> Result<User, &'static str> {
        let id = sha256(token.as_bytes());
        if let Some((u, nbf, exp)) = self.cache.borrow().get(&id) {
            return if now <= exp + SKEW && now + SKEW >= *nbf { Ok(u.clone()) } else { Err("token expired") };
        }
        let (u, nbf, exp) = self.verify_uncached(token, now)?;
        let mut c = self.cache.borrow_mut();
        if c.len() >= CACHE_MAX {
            c.retain(|_, (_, _, e)| now <= *e + SKEW);
            if c.len() >= CACHE_MAX {
                c.clear();
            }
        }
        c.insert(id, (u.clone(), nbf, exp));
        Ok(u)
    }

    fn verify_uncached(&self, token: &str, now: i64) -> Result<(User, i64, i64), &'static str> {
        let bad = "malformed token";
        let mut parts = token.split('.');
        let (h, c, sg) = (parts.next().ok_or(bad)?, parts.next().ok_or(bad)?, parts.next().ok_or(bad)?);
        if parts.next().is_some() {
            return Err(bad);
        }
        let (header, claims) = peek(token).ok_or(bad)?;
        let alg = header.get("alg").and_then(Value::as_str).unwrap_or("");
        let sig = unb64(sg).ok_or(bad)?;
        let kid = header.get("kid").and_then(Value::as_str);
        let input = &token.as_bytes()[..h.len() + 1 + c.len()];
        {
            let keys = self.keys.borrow();
            let known = kid.is_none_or(|k| keys.iter().any(|(id, _)| id == k));
            if !known {
                self.want.set(true);
                return Err("unknown signing key");
            }
            if !keys.iter().filter(|(id, _)| kid.is_none_or(|k| k == id)).any(|(_, key)| verify_sig(alg, key, input, &sig)) {
                return Err("invalid signature");
            }
        }
        if claims.get("iss").and_then(Value::as_str) != Some(self.issuer.as_str()) {
            return Err("issuer mismatch");
        }
        let aud = strs(claims.get("aud"));
        if !aud.iter().any(|a| self.audiences.contains(a)) {
            return Err("audience mismatch");
        }
        let exp = claims.get("exp").and_then(Value::as_i64).ok_or("exp: Required value")?;
        let nbf = claims.get("nbf").and_then(Value::as_i64).unwrap_or(i64::MIN / 2);
        if now > exp + SKEW {
            return Err("token expired");
        }
        if now + SKEW < nbf || claims.get("iat").and_then(Value::as_i64).is_some_and(|iat| iat > now + SKEW) {
            return Err("token not yet valid");
        }
        for r in &self.rules {
            match r {
                Rule::Claim(k, want) => {
                    if claim_str(&claims, k).as_deref() != Some(want.as_str()) {
                        return Err("claim validation failed");
                    }
                }
                Rule::Expr(p) => {
                    if !p.eval_bool(&[("claims", &claims)]).unwrap_or(false) {
                        return Err("claim validation failed");
                    }
                }
            }
        }
        let name = match &self.username {
            Map::Claim(k, prefix) => {
                let v = claim_str(&claims, k).filter(|v| !v.is_empty()).ok_or("username claim missing")?;
                // An unverified email is no identity (upstream).
                if k == "email" && claims.get("email_verified").is_some_and(|e| e.as_bool() != Some(true)) {
                    return Err("email not verified");
                }
                format!("{prefix}{v}")
            }
            Map::Expr(p) => match p.eval(&[("claims", &claims)]) {
                Ok(Value::String(s)) if !s.is_empty() => s,
                _ => return Err("username expression failed"),
            },
            Map::None => return Err("no username mapping"),
        };
        let mut groups = match &self.groups {
            Map::Claim(k, prefix) => strs(claims.get(k)).into_iter().map(|g| format!("{prefix}{g}")).collect(),
            Map::Expr(p) => match p.eval(&[("claims", &claims)]) {
                Ok(v @ (Value::String(_) | Value::Array(_))) => strs(Some(&v)),
                Ok(Value::Null) => Vec::new(),
                _ => return Err("groups expression failed"),
            },
            Map::None => Vec::new(),
        };
        let uid = match &self.uid {
            Map::Claim(k, _) => claim_str(&claims, k).unwrap_or_default(),
            Map::Expr(p) => match p.eval(&[("claims", &claims)]) {
                Ok(Value::String(s)) => s,
                _ => return Err("uid expression failed"),
            },
            Map::None => String::new(),
        };
        // An external identity never claims a system: name or group.
        if name.starts_with("system:") || groups.iter().any(|g| g.starts_with("system:")) {
            return Err("system: identities are reserved");
        }
        if !self.user_rules.is_empty() {
            let user = Value::Object(alloc::vec![
                ("username".into(), Value::String(name.clone())),
                ("uid".into(), Value::String(uid)),
                ("groups".into(), Value::Array(groups.iter().map(|g| Value::String(g.clone())).collect())),
            ]);
            if !self.user_rules.iter().all(|p| p.eval_bool(&[("user", &user)]).unwrap_or(false)) {
                return Err("user validation failed");
            }
        }
        groups.push("system:authenticated".into());
        Ok((User { name, groups }, nbf, exp))
    }
}

/// The authenticator for a token's issuer, if one is configured.
pub fn route<'a>(list: &'a [Rc<Jwt>], token: &str) -> Option<&'a Rc<Jwt>> {
    if list.is_empty() || token.matches('.').count() != 2 {
        return None;
    }
    let (_, claims) = peek(token)?;
    let iss = claims.get("iss").and_then(Value::as_str)?;
    list.iter().find(|j| j.issuer == iss)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(b: &[u8]) -> String {
        base64::encode_url(b)
    }

    fn es256(key: &p256::SecretKey, kid: &str, claims: &str) -> String {
        let input = format!("{}.{}", b64(format!(r#"{{"alg":"ES256","kid":"{kid}"}}"#).as_bytes()), b64(claims.as_bytes()));
        let (r, s) = key.sign(input.as_bytes());
        format!("{input}.{}{}", "", b64(&[r, s].concat()))
    }

    fn jwt_with_key(spec: Spec, key: &p256::SecretKey) -> Rc<Jwt> {
        let j = Jwt::new(spec, &[]).unwrap();
        let pk = key.public_key();
        let doc = format!(r#"{{"keys":[{{"kty":"EC","crv":"P-256","kid":"k1","use":"sig","x":"{}","y":"{}"}}]}}"#, b64(&pk[1..33]), b64(&pk[33..]));
        *j.keys.borrow_mut() = parse_jwks(doc.as_bytes()).unwrap();
        j
    }

    const CFG: &str = "apiVersion: apiserver.config.k8s.io/v1\nkind: AuthenticationConfiguration\njwt:\n- issuer:\n    url: https://idp.example\n    audiences: [kr, other]\n    audienceMatchPolicy: MatchAny\n  claimValidationRules:\n  - claim: hd\n    requiredValue: example.com\n  - expression: 'claims.level > 1'\n    message: level\n  claimMappings:\n    username:\n      claim: email\n      prefix: 'oidc:'\n    groups:\n      expression: 'claims.roles'\n";

    #[test]
    fn structured_config_verifies_and_maps_claims() {
        let key = p256::SecretKey::from_bytes(&[7; 32]).unwrap();
        let spec = parse_config(CFG).unwrap().pop().unwrap();
        let j = jwt_with_key(spec, &key);
        let now = 1_900_000_000;
        let good = format!(r#"{{"iss":"https://idp.example","aud":["other"],"exp":{},"iat":{now},"email":"a@example.com","email_verified":true,"hd":"example.com","level":2,"roles":["dev","ops"]}}"#, now + 600);
        let u = j.verify(&es256(&key, "k1", &good), now).unwrap();
        assert_eq!(u.name, "oidc:a@example.com");
        assert_eq!(u.groups, ["dev", "ops", "system:authenticated"]);
        for (bad, why) in [
            (good.replace("\"other\"", "\"nope\""), "audience"),
            (good.replace("example.com\",\"level", "evil.com\",\"level"), "claim rule"),
            (good.replace("\"level\":2", "\"level\":1"), "expression rule"),
            (good.replace("\"email_verified\":true", "\"email_verified\":false"), "unverified email"),
            (good.replace("https://idp.example", "https://evil"), "issuer"),
            (good.replace(&format!("\"exp\":{}", now + 600), &format!("\"exp\":{}", now - 600)), "expired"),
            (good.replace(&format!("\"iat\":{now}"), &format!("\"iat\":{}", now + 600)), "issued in the future"),
            (good.replace("\"roles\":[\"dev\",\"ops\"]", "\"roles\":[\"system:masters\"]"), "system group"),
        ] {
            assert!(j.verify(&es256(&key, "k1", &bad), now).is_err(), "{why}");
        }
        let other = p256::SecretKey::from_bytes(&[8; 32]).unwrap();
        assert!(j.verify(&es256(&other, "k1", &good), now).is_err(), "wrong key");
        assert_eq!(j.verify(&es256(&key, "k2", &good), now), Err("unknown signing key"));
        assert!(j.want.get(), "an unknown kid schedules a refresh");
        // alg none / HS256 are refused.
        let none = format!("{}.{}.", b64(br#"{"alg":"none","kid":"k1"}"#), b64(good.as_bytes()));
        assert!(j.verify(&none, now).is_err());
    }

    #[test]
    fn oidc_flags_build_one_authenticator() {
        let key = p256::SecretKey::from_bytes(&[9; 32]).unwrap();
        let j = jwt_with_key(oidc_spec("https://idp.example", "kr", None, None, Some("groups"), Some("g:"), Some("tenant=a"), String::new()).unwrap(), &key);
        let now = 1_900_000_000;
        let t = format!(r#"{{"iss":"https://idp.example","aud":"kr","exp":{},"sub":"1234","groups":"admins","tenant":"a"}}"#, now + 60);
        let u = j.verify(&es256(&key, "k1", &t), now).unwrap();
        assert_eq!(u.name, "https://idp.example#1234");
        assert_eq!(u.groups, ["g:admins", "system:authenticated"]);
        assert!(j.verify(&es256(&key, "k1", &t.replace("\"tenant\":\"a\"", "\"tenant\":\"b\"")), now).is_err());
        assert!(oidc_spec("http://idp", "kr", None, None, None, None, None, String::new()).is_err());
    }

    #[test]
    fn config_errors() {
        assert!(parse_config("kind: AuthenticationConfiguration\njwt:\n- issuer: {url: 'https://a', audiences: [x, y]}\n  claimMappings: {username: {claim: sub, prefix: ''}}\n").is_err(), "two audiences need MatchAny");
        assert!(parse_config("kind: AuthenticationConfiguration\njwt:\n- issuer: {url: 'https://a', audiences: [x]}\n  claimMappings: {username: {claim: sub}}\n").is_err(), "claim needs a prefix");
        assert!(parse_config("kind: AuthenticationConfiguration\njwt:\n- issuer: {url: 'https://a', audiences: [x]}\n  claimMappings: {username: {expression: 'claims.sub'}}\n").is_ok());
    }

    #[test]
    fn rsa_jwk_parses() {
        let pem = include_str!("../../kr-crypto/tests/vectors/rsa/k2048.pem");
        let k = rsa::PrivateKey::from_pkcs1(&x509::pem_decode_all(pem, "RSA PRIVATE KEY").unwrap()[0]).unwrap();
        let mut seed = 1u8;
        let mut rng = |b: &mut [u8]| {
            for x in b {
                seed = seed.wrapping_mul(31).wrapping_add(7);
                *x = seed;
            }
        };
        let sig = k.sign_pkcs1v15(HashAlg::Sha256, b"a.b", &mut rng).unwrap();
        // n and e from the PKCS#1 encoding of the public key.
        let pkcs1 = k.public().to_pkcs1();
        let mut r = der::Reader::new(&pkcs1);
        let mut sq = r.sequence().unwrap();
        let n = sq.integer().unwrap();
        let n = if n[0] == 0 { &n[1..] } else { n };
        let doc = format!(r#"{{"keys":[{{"kty":"RSA","kid":"r","n":"{}","e":"AQAB"}}]}}"#, b64(n));
        let keys = parse_jwks(doc.as_bytes()).unwrap();
        assert_eq!(keys.len(), 1);
        assert!(verify_sig("RS256", &keys[0].1, b"a.b", &sig));
        assert!(!verify_sig("RS384", &keys[0].1, b"a.b", &sig));
    }
}
