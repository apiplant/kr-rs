//! External authentication and authorization (#362): JWT/OIDC authenticators ([`crate::jwt`]),
//! webhook token authentication (TokenReview), webhook authorization (SubjectAccessReview) and
//! the authorizer chain (`--authorization-mode`, `AuthorizationConfiguration`).
//!
//! Authentication and authorization in [`crate::api`] are synchronous; the network calls happen
//! in an async step the transport runs before the handler ([`authenticate`], [`prefetch_authz`]):
//! it refreshes JWKS for an unknown `kid`, asks the token webhook (the user is then handed to
//! the handler like a client-certificate identity), and asks authorization webhooks for the
//! request's attributes, filling TTL caches the synchronous decision then reads. A synchronous
//! decision without a cached webhook answer (SubjectAccessReview, impersonation checks, writes
//! by in-process components) applies the webhook's failure policy.

use crate::api::{ApiServer, Req, User};
use crate::cel::Program;
use crate::rbac::Attrs;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use kr_crypto::sha2::sha256;
use kr_fmt::json::{self, Value};
use kr_net::http1::client::{Client as Http, Config as HttpConfig};
use kr_net::tls::TlsConnector;

const CACHE_MAX: usize = 8192;

/// A webhook authorizer's answer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
    NoOpinion,
}

#[derive(Clone)]
pub enum Authorizer {
    Node,
    Rbac,
    Webhook(Rc<AuthzWebhook>),
    AlwaysAllow,
    AlwaysDeny,
}

/// External authenticators, the authorizer chain and the optional admission plugins.
#[derive(Default)]
pub struct Hub {
    pub jwt: RefCell<Vec<Rc<crate::jwt::Jwt>>>,
    pub token_webhook: RefCell<Option<Rc<TokenWebhook>>>,
    /// Empty: Node then RBAC (the default).
    pub authorizers: RefCell<Vec<Authorizer>>,
    pub plugins: RefCell<crate::plugins::Plugins>,
    started: Cell<bool>,
}

impl Hub {
    /// Starts the JWKS maintenance tasks (once; inside the executor).
    pub fn start(&self) {
        if self.started.replace(true) {
            return;
        }
        for j in self.jwt.borrow().iter() {
            j.start();
        }
    }

    pub(crate) fn has_webhook_authz(&self) -> bool {
        self.authorizers.borrow().iter().any(|a| matches!(a, Authorizer::Webhook(_)))
    }

    /// Synchronous JWT verification: `None` when no authenticator owns the token's issuer.
    pub(crate) fn verify_jwt(&self, token: &str, now: i64) -> Option<Result<User, &'static str>> {
        let list = self.jwt.borrow();
        crate::jwt::route(&list, token).map(|j| j.verify(token, now))
    }

    /// The token webhook's cached answer (`Some(None)`: cached rejection).
    pub(crate) fn token_cached(&self, token: &str) -> Option<Option<User>> {
        self.token_webhook.borrow().as_ref()?.cached(token)
    }
}

/// HTTPS client of a webhook configured by a kubeconfig.
pub struct WebhookClient {
    url: String,
    token: Option<String>,
    http: Http<TlsConnector>,
    timeout_ms: u64,
}

impl WebhookClient {
    pub fn new(mut cfg: crate::audit_webhook::Config, timeout_ms: u64) -> WebhookClient {
        let tls = Rc::new(kr_crypto::tls::ClientConfig { pinned_ca: None, roots: core::mem::take(&mut cfg.roots), client_cert: cfg.client.take(), alpn: alloc::vec![b"http/1.1".to_vec()], tls12: true });
        let http = Http::with_connector(
            TlsConnector::new(kr_net::dns::SystemResolver::system(), tls),
            HttpConfig { max_redirects: 0, max_idle: 4, connect_timeout_ms: timeout_ms, head_timeout_ms: timeout_ms, read_timeout_ms: timeout_ms, user_agent: "kr-apiserver".to_string(), ..HttpConfig::default() },
        );
        WebhookClient { url: cfg.url, token: cfg.token, http, timeout_ms }
    }

    /// POSTs `body`; the JSON reply of a 2xx answer.
    async fn post(&self, body: &str) -> Option<Value> {
        let auth = self.token.as_ref().map(|t| format!("Bearer {t}"));
        let mut h = alloc::vec![("Content-Type", "application/json"), ("Accept", "application/json")];
        if let Some(a) = &auth {
            h.push(("Authorization", a.as_str()));
        }
        let fut = async {
            let mut r = self.http.request("POST", &self.url, &h, body.as_bytes()).await.ok()?;
            let b = r.read_to_end(1 << 20).await.ok()?;
            if !(200..300).contains(&r.status) {
                return None;
            }
            json::parse(&b).ok()
        };
        kr_rt::exec::timeout(self.timeout_ms, fut).await.ok().flatten()
    }
}

/// `--authentication-token-webhook-config-file`: TokenReview to a webhook, answers cached.
pub struct TokenWebhook {
    client: WebhookClient,
    version: String,
    ttl_ms: u64,
    cache: RefCell<BTreeMap<[u8; 32], (Option<User>, u64)>>,
}

fn bounded<K: Ord, V>(m: &mut BTreeMap<K, (V, u64)>, now: u64) {
    if m.len() >= CACHE_MAX {
        m.retain(|_, (_, t)| *t > now);
        if m.len() >= CACHE_MAX {
            m.clear();
        }
    }
}

impl TokenWebhook {
    /// `version`: `v1` or `v1beta1` (of authentication.k8s.io).
    pub fn new(client: WebhookClient, version: &str, ttl_secs: u64) -> Result<Rc<TokenWebhook>, String> {
        if !matches!(version, "v1" | "v1beta1") {
            return Err("authentication-token-webhook-version takes v1 or v1beta1".into());
        }
        Ok(Rc::new(TokenWebhook { client, version: version.into(), ttl_ms: ttl_secs * 1000, cache: RefCell::new(BTreeMap::new()) }))
    }

    fn cached(&self, token: &str) -> Option<Option<User>> {
        let now = kr_rt::exec::now_ms();
        self.cache.borrow().get(&sha256(token.as_bytes())).filter(|(_, t)| *t > now).map(|(u, _)| u.clone())
    }

    /// The user the webhook accepts `token` as. Answers (both ways) are cached for the TTL;
    /// transport errors are not.
    pub async fn authenticate(&self, token: &str) -> Option<User> {
        if let Some(u) = self.cached(token) {
            return u;
        }
        let review = Value::Object(alloc::vec![
            ("apiVersion".into(), Value::String(format!("authentication.k8s.io/{}", self.version))),
            ("kind".into(), Value::from("TokenReview")),
            ("spec".into(), Value::Object(alloc::vec![("token".into(), Value::String(token.into()))])),
        ]);
        let resp = self.client.post(&json::to_string(&review)).await?;
        let st = resp.get("status");
        let user = st.filter(|s| s.get("authenticated").and_then(Value::as_bool) == Some(true)).and_then(|s| s.get("user")).and_then(|u| {
            let name = u.get("username").and_then(Value::as_str).filter(|n| !n.is_empty())?.to_string();
            let mut groups: Vec<String> = u.get("groups").and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(Value::as_str).map(String::from).collect();
            if !groups.iter().any(|g| g == "system:authenticated") {
                groups.push("system:authenticated".into());
            }
            Some(User { name, groups })
        });
        let now = kr_rt::exec::now_ms();
        let mut c = self.cache.borrow_mut();
        bounded(&mut c, now);
        c.insert(sha256(token.as_bytes()), (user.clone(), now + self.ttl_ms));
        user
    }
}

/// A webhook authorizer (SubjectAccessReview), with authorized/unauthorized TTL caches.
pub struct AuthzWebhook {
    pub name: String,
    client: WebhookClient,
    version: String,
    authorized_ms: u64,
    unauthorized_ms: u64,
    failure_deny: bool,
    conditions: Vec<Program>,
    cache: RefCell<BTreeMap<String, (Verdict, u64)>>,
}

/// Grace after expiry for a synchronous lookup right after the async step filled the entry.
const GRACE_MS: u64 = 5_000;

fn sar_spec(user: &User, a: &Attrs) -> Value {
    let st = |v: &str| Value::String(v.into());
    let attrs = if a.resource_request {
        let mut f = alloc::vec![("verb".to_string(), st(&a.verb)), ("group".into(), st(&a.api_group)), ("resource".into(), st(&a.resource))];
        for (k, v) in [("namespace", &a.namespace), ("subresource", &a.subresource), ("name", &a.name)] {
            if !v.is_empty() {
                f.push((k.into(), st(v)));
            }
        }
        ("resourceAttributes".to_string(), Value::Object(f))
    } else {
        ("nonResourceAttributes".to_string(), Value::Object(alloc::vec![("path".into(), st(&a.path)), ("verb".into(), st(&a.verb))]))
    };
    Value::Object(alloc::vec![attrs, ("user".into(), st(&user.name)), ("groups".into(), Value::Array(user.groups.iter().map(|g| st(g)).collect()))])
}

impl AuthzWebhook {
    fn key(user: &User, a: &Attrs) -> String {
        format!("{}\x00{}\x00{}\x00{}\x00{}\x00{}\x00{}\x00{}\x00{}\x00{}", user.name, user.groups.join("\x01"), a.verb, a.api_group, a.resource, a.subresource, a.namespace, a.name, a.path, a.resource_request)
    }

    /// The cached answer, if any.
    pub(crate) fn lookup(&self, user: &User, a: &Attrs) -> Option<Verdict> {
        let now = kr_rt::exec::now_ms();
        self.cache.borrow().get(&Self::key(user, a)).filter(|(_, t)| *t + GRACE_MS > now).map(|(v, _)| *v)
    }

    /// What a synchronous decision uses when nothing is cached.
    pub(crate) fn failure(&self) -> Verdict {
        if self.failure_deny {
            Verdict::Deny
        } else {
            Verdict::NoOpinion
        }
    }

    /// Asks the webhook (unless a fresh answer is cached) and caches the answer.
    pub async fn fetch(&self, user: &User, a: &Attrs) -> Verdict {
        let key = Self::key(user, a);
        let now = kr_rt::exec::now_ms();
        if let Some((v, _)) = self.cache.borrow().get(&key).filter(|(_, t)| *t > now) {
            return *v;
        }
        let spec = sar_spec(user, a);
        let (v, ttl) = match self.conditions.iter().map(|c| c.eval_bool(&[("request", &spec)])).try_fold(true, |acc, r| r.map(|b| acc && b)) {
            Ok(false) => (Verdict::NoOpinion, self.authorized_ms),
            Err(_) => (self.failure(), 1_000),
            Ok(true) => {
                let review = Value::Object(alloc::vec![
                    ("apiVersion".into(), Value::String(format!("authorization.k8s.io/{}", self.version))),
                    ("kind".into(), Value::from("SubjectAccessReview")),
                    ("spec".into(), spec),
                ]);
                match self.client.post(&json::to_string(&review)).await {
                    None => (self.failure(), 1_000),
                    Some(r) => {
                        let flag = |k: &str| r.pointer(&["status", k]).and_then(Value::as_bool) == Some(true);
                        if flag("allowed") {
                            (Verdict::Allow, self.authorized_ms)
                        } else if flag("denied") {
                            (Verdict::Deny, self.unauthorized_ms)
                        } else {
                            (Verdict::NoOpinion, self.unauthorized_ms)
                        }
                    }
                }
            }
        };
        let now = kr_rt::exec::now_ms();
        let mut c = self.cache.borrow_mut();
        bounded(&mut c, now);
        c.insert(key, (v, now + ttl.max(1)));
        v
    }
}

/// Settings of one webhook authorizer.
pub struct AuthzWebhookSpec {
    pub name: String,
    /// Path of the kubeconfig.
    pub kubeconfig: String,
    pub version: String,
    pub timeout_ms: u64,
    pub authorized_secs: u64,
    pub unauthorized_secs: u64,
    pub failure_deny: bool,
    pub conditions: Vec<String>,
}

impl AuthzWebhookSpec {
    pub fn build(self, client: WebhookClient) -> Result<Rc<AuthzWebhook>, String> {
        if !matches!(self.version.as_str(), "v1" | "v1beta1") {
            return Err(format!("authorization webhook {}: subjectAccessReviewVersion takes v1 or v1beta1", self.name));
        }
        let conditions = self.conditions.iter().map(|c| Program::compile(c, &["request"]).map_err(|e| format!("authorization webhook {}: matchConditions: {e}", self.name))).collect::<Result<Vec<_>, _>>()?;
        Ok(Rc::new(AuthzWebhook { name: self.name, client, version: self.version, authorized_ms: self.authorized_secs * 1000, unauthorized_ms: self.unauthorized_secs * 1000, failure_deny: self.failure_deny, conditions, cache: RefCell::new(BTreeMap::new()) }))
    }
}

/// One entry of the authorizer chain before its webhook client exists.
pub enum AuthorizerSpec {
    Node,
    Rbac,
    AlwaysAllow,
    AlwaysDeny,
    Webhook(AuthzWebhookSpec),
}

/// `1m`, `30s`, `5m0s`, `2h`, plain seconds.
pub fn parse_duration_secs(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }
    let (mut total, mut num, mut any) = (0u64, String::new(), false);
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        let unit = if c == 'm' && it.peek() == Some(&'s') {
            it.next();
            0
        } else {
            match c {
                'h' => 3600,
                'm' => 60,
                's' => 1,
                _ => return None,
            }
        };
        total += num.parse::<u64>().ok()? * unit;
        num.clear();
        any = true;
    }
    (any && num.is_empty()).then_some(total)
}

/// `--authorization-mode` (`Node,RBAC,Webhook`, also `AlwaysAllow`, `AlwaysDeny`); `webhook`
/// is the webhook authorizer's settings from the `--authorization-webhook-*` flags.
pub fn parse_mode(mode: &str, webhook: Option<AuthzWebhookSpec>) -> Result<Vec<AuthorizerSpec>, String> {
    let mut out = Vec::new();
    let mut webhook = webhook;
    for m in mode.split(',').map(str::trim).filter(|m| !m.is_empty()) {
        out.push(match m {
            "Node" => AuthorizerSpec::Node,
            "RBAC" => AuthorizerSpec::Rbac,
            "AlwaysAllow" => AuthorizerSpec::AlwaysAllow,
            "AlwaysDeny" => AuthorizerSpec::AlwaysDeny,
            "Webhook" => AuthorizerSpec::Webhook(webhook.take().ok_or("authorization-mode Webhook needs authorization-webhook-config-file (once)")?),
            _ => return Err(format!("authorization-mode: unsupported mode {m:?}")),
        });
    }
    if out.is_empty() {
        return Err("authorization-mode: empty".into());
    }
    Ok(out)
}

/// `AuthorizationConfiguration` (apiserver.config.k8s.io v1alpha1/v1beta1/v1).
pub fn parse_authz_config(text: &str) -> Result<Vec<AuthorizerSpec>, String> {
    let v = kr_fmt::yaml::parse(text).map_err(|e| format!("authorization config: {e:?}"))?;
    if v.get("kind").and_then(Value::as_str).is_some_and(|k| k != "AuthorizationConfiguration") {
        return Err("authorization config: kind must be AuthorizationConfiguration".into());
    }
    let mut out = Vec::new();
    let mut names: Vec<String> = Vec::new();
    for (i, a) in v.get("authorizers").and_then(Value::as_array).unwrap_or(&[]).iter().enumerate() {
        let at = |m: &str| format!("authorization config: authorizers[{i}]: {m}");
        let ty = a.get("type").and_then(Value::as_str).unwrap_or("");
        out.push(match ty {
            "Node" => AuthorizerSpec::Node,
            "RBAC" => AuthorizerSpec::Rbac,
            "AlwaysAllow" => AuthorizerSpec::AlwaysAllow,
            "AlwaysDeny" => AuthorizerSpec::AlwaysDeny,
            "Webhook" => {
                let name = a.get("name").and_then(Value::as_str).filter(|n| !n.is_empty()).ok_or_else(|| at("name: Required value"))?.to_string();
                if names.contains(&name) {
                    return Err(at("name: Duplicate value"));
                }
                names.push(name.clone());
                let w = a.get("webhook").ok_or_else(|| at("webhook: Required value"))?;
                let gs = |k: &str| w.get(k).and_then(Value::as_str).map(String::from);
                let dur = |k: &str, d: u64| -> Result<u64, String> {
                    match gs(k) {
                        None => Ok(d),
                        Some(s) => parse_duration_secs(&s).ok_or_else(|| at(&format!("webhook.{k}: invalid duration {s:?}"))),
                    }
                };
                let ci = w.get("connectionInfo").ok_or_else(|| at("webhook.connectionInfo: Required value"))?;
                let kubeconfig = match ci.get("type").and_then(Value::as_str) {
                    Some("KubeConfigFile") => ci.get("kubeConfigFile").and_then(Value::as_str).filter(|p| !p.is_empty()).ok_or_else(|| at("webhook.connectionInfo.kubeConfigFile: Required value"))?.to_string(),
                    _ => return Err(at("webhook.connectionInfo.type: only KubeConfigFile is supported")),
                };
                let failure_deny = match gs("failurePolicy").as_deref() {
                    Some("Deny") => true,
                    Some("NoOpinion") | None => false,
                    Some(p) => return Err(at(&format!("webhook.failurePolicy: unsupported value {p:?}"))),
                };
                let cache_ok = w.get("cacheAuthorizedRequests").and_then(Value::as_bool).unwrap_or(true);
                let cache_no = w.get("cacheUnauthorizedRequests").and_then(Value::as_bool).unwrap_or(true);
                let timeout = dur("timeout", 3)?;
                if !(1..=30).contains(&timeout) {
                    return Err(at("webhook.timeout: must be between 1s and 30s"));
                }
                let conditions = w.get("matchConditions").and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(|c| c.get("expression").and_then(Value::as_str).map(String::from)).collect();
                AuthorizerSpec::Webhook(AuthzWebhookSpec {
                    name,
                    kubeconfig,
                    version: gs("subjectAccessReviewVersion").unwrap_or_else(|| "v1".into()),
                    timeout_ms: timeout * 1000,
                    // Not caching still lets the request that fetched the answer use it.
                    authorized_secs: if cache_ok { dur("authorizedTTL", 300)? } else { 0 },
                    unauthorized_secs: if cache_no { dur("unauthorizedTTL", 30)? } else { 0 },
                    failure_deny,
                    conditions,
                })
            }
            _ => return Err(at(&format!("type: unsupported value {ty:?}"))),
        });
    }
    if out.is_empty() {
        return Err("authorization config: authorizers: Required value".into());
    }
    Ok(out)
}

/// The async authentication step of the transport for a bearer token: refreshes the JWKS of
/// the token's issuer when its `kid` is unknown, and asks the token webhook when no
/// synchronous authenticator accepts the token. `Some` is the webhook's user.
pub async fn authenticate(api: &ApiServer, token: &str) -> Option<User> {
    let j = crate::jwt::route(&api.ext.jwt.borrow(), token).cloned();
    if let Some(j) = j {
        j.ensure_key(token).await;
    }
    let w = api.ext.token_webhook.borrow().clone()?;
    if api.bearer_valid(token) {
        return None;
    }
    w.authenticate(token).await
}

/// The async authorization step: asks the webhook authorizers the chain reaches for this
/// request (answers are cached for the synchronous decision).
pub async fn prefetch_authz(api: &ApiServer, r: &Req<'_>) {
    if !api.ext.has_webhook_authz() {
        return;
    }
    let Ok(user) = api.authenticate(r) else { return };
    let Some((attrs, body_name)) = api.request_attrs(r, &user) else { return };
    for _ in 0..8 {
        let missing: RefCell<Option<Rc<AuthzWebhook>>> = RefCell::new(None);
        api.authorize_with(&user, &attrs, body_name.as_deref(), &|w: &Rc<AuthzWebhook>| match w.lookup(&user, &attrs) {
            Some(v) => v,
            None => {
                *missing.borrow_mut() = Some(w.clone());
                Verdict::Deny
            }
        });
        let Some(w) = missing.into_inner() else { return };
        w.fetch(&user, &attrs).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration_secs("5m0s"), Some(300));
        assert_eq!(parse_duration_secs("30s"), Some(30));
        assert_eq!(parse_duration_secs("2h"), Some(7200));
        assert_eq!(parse_duration_secs("12"), Some(12));
        assert_eq!(parse_duration_secs("500ms"), Some(0));
        assert_eq!(parse_duration_secs("x"), None);
    }

    #[test]
    fn authorization_config_parses() {
        let t = "apiVersion: apiserver.config.k8s.io/v1\nkind: AuthorizationConfiguration\nauthorizers:\n- type: Node\n  name: node\n- type: Webhook\n  name: wh\n  webhook:\n    timeout: 3s\n    authorizedTTL: 1m\n    unauthorizedTTL: 10s\n    subjectAccessReviewVersion: v1\n    matchConditionSubjectAccessReviewVersion: v1\n    failurePolicy: Deny\n    connectionInfo:\n      type: KubeConfigFile\n      kubeConfigFile: /etc/wh.kubeconfig\n    matchConditions:\n    - expression: has(request.resourceAttributes)\n- type: RBAC\n  name: rbac\n";
        let a = parse_authz_config(t).unwrap();
        assert_eq!(a.len(), 3);
        let AuthorizerSpec::Webhook(w) = &a[1] else { panic!() };
        assert_eq!((w.authorized_secs, w.unauthorized_secs, w.failure_deny, w.timeout_ms), (60, 10, true, 3000));
        assert_eq!(w.kubeconfig, "/etc/wh.kubeconfig");
        assert!(parse_authz_config("kind: AuthorizationConfiguration\nauthorizers:\n- type: Bogus\n").is_err());
        assert!(parse_mode("Node,RBAC,Webhook", None).is_err());
        assert_eq!(parse_mode("Node,RBAC", None).unwrap().len(), 2);
    }

    #[test]
    fn sar_spec_shapes() {
        let u = User { name: "jane".into(), groups: alloc::vec!["dev".into()] };
        let a = Attrs { verb: "get".into(), resource: "pods".into(), namespace: "ns".into(), resource_request: true, ..Default::default() };
        let s = json::to_string(&sar_spec(&u, &a));
        assert!(s.contains(r#""resourceAttributes":{"verb":"get","group":"","resource":"pods","namespace":"ns"}"#), "{s}");
        let n = Attrs { verb: "get".into(), path: "/healthz".into(), ..Default::default() };
        assert!(json::to_string(&sar_spec(&u, &n)).contains(r#""nonResourceAttributes":{"path":"/healthz","verb":"get"}"#));
    }
}
