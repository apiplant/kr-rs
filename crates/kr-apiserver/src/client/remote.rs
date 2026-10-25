//! HTTPS implementation of [`Client`] for node agents on other machines.

use super::{Client, Result, Watch};
use crate::object::ApiError;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_crypto::tls::ClientConfig;
use kr_crypto::x509;
use kr_fmt::json::{self, Value};
use kr_net::dns::SystemResolver;
use kr_net::http1::client::{Client as Http, Config as HttpConfig, Response};
use kr_net::http1::Url;
use kr_net::tls::{MaybeTls, TlsConnector};
use kr_net::Error as NetError;
use kr_rt::exec::timeout;

/// Total budget for a unary call (connect, request, full response).
const UNARY_TIMEOUT_MS: u64 = 30_000;
/// A watch is dropped after this long without receiving any bytes.
const WATCH_IDLE_MS: u64 = 300_000;
const WATCH_TIMEOUT_SECONDS: u32 = 300;
const MAX_BODY: usize = 64 * 1024 * 1024;

/// How the client authenticates to the API server.
pub enum RemoteAuth {
    /// TLS client certificate: PEM certificate chain (leaf first) and PEM private key
    /// (PKCS#8 `PRIVATE KEY`, or SEC1 `EC PRIVATE KEY`).
    ClientCert { chain: String, key: String },
    /// `Authorization: Bearer <token>` (e.g. a ServiceAccount token).
    Bearer(String),
}

struct Inner {
    /// API servers (HA: every server works); `cur` is the one in use. A transport error moves
    /// to the next.
    servers: core::cell::RefCell<Vec<String>>,
    cur: core::cell::Cell<usize>,
    roots: Vec<Vec<u8>>,
    bearer: Option<String>,
    unary: Http<TlsConnector>,
    /// Separate client (own pool, never reuses) with the long idle read limit.
    watch: Http<TlsConnector>,
}

/// Talks to a kr/Kubernetes API server over HTTPS. Clones share the connection pool.
#[derive(Clone)]
pub struct Remote {
    inner: Rc<Inner>,
}

/// PEM chain (leaf first) and PKCS#8 or SEC1 key.
fn client_cert(chain: &str, key: &str) -> Result<(Vec<Vec<u8>>, x509::SigningKey)> {
    let chain = x509::pem_decode_all(chain, "CERTIFICATE").map_err(|_| bad("invalid client certificate"))?;
    if chain.is_empty() {
        return Err(bad("client certificate chain is empty"));
    }
    let key = match x509::pem_decode_all(key, "PRIVATE KEY") {
        Ok(v) if !v.is_empty() => x509::private_key_from_pkcs8(&v[0]),
        _ => match x509::pem_decode_all(key, "EC PRIVATE KEY") {
            Ok(v) if !v.is_empty() => x509::private_key_from_sec1(&v[0]),
            _ => return Err(bad("invalid client key")),
        },
    }
    .map_err(|_| bad("invalid client key"))?;
    Ok((chain, key))
}

fn bad(msg: &str) -> ApiError {
    ApiError::new(400, "BadRequest", msg)
}

impl Remote {
    /// `server_url` like `https://10.0.0.1:6443`; `ca_pem` is the cluster CA bundle.
    pub fn new(server_url: &str, auth: RemoteAuth, ca_pem: &str) -> Result<Remote> {
        let base = server_url.trim_end_matches('/');
        Url::parse(base).map_err(|_| bad("invalid server URL"))?;
        let roots = x509::pem_decode_all(ca_pem, "CERTIFICATE").map_err(|_| bad("invalid CA bundle"))?;
        if roots.is_empty() {
            return Err(bad("CA bundle has no certificates"));
        }
        let (client_cert, bearer) = match auth {
            RemoteAuth::Bearer(t) => {
                if t.is_empty() || t.bytes().any(|b| b <= b' ' || b == 0x7f) {
                    return Err(bad("invalid bearer token"));
                }
                (None, Some(t))
            }
            RemoteAuth::ClientCert { chain, key } => (Some(client_cert(&chain, &key)?), None),
        };
        let cfg = Rc::new(ClientConfig { pinned_ca: None, roots: roots.clone(), client_cert, alpn: alloc::vec![b"http/1.1".to_vec()], tls12: false });
        let unary = Http::with_connector(
            TlsConnector::new(SystemResolver::system(), cfg.clone()),
            HttpConfig { max_redirects: 0, user_agent: "kr-node/0.0.1".to_string(), ..HttpConfig::default() },
        );
        let watch = Http::with_connector(
            TlsConnector::new(SystemResolver::system(), cfg),
            HttpConfig { read_timeout_ms: WATCH_IDLE_MS, max_redirects: 0, max_idle: 0, user_agent: "kr-node/0.0.1".to_string(), ..HttpConfig::default() },
        );
        Ok(Remote { inner: Rc::new(Inner { servers: core::cell::RefCell::new(alloc::vec![base.to_string()]), cur: core::cell::Cell::new(0), roots, bearer, unary, watch }) })
    }

    /// Switches to a new client certificate (rotation). New connections use it; pooled and
    /// in-flight ones finish with the old one, which is still valid.
    pub fn set_client_cert(&self, chain: &str, key: &str) -> Result<()> {
        let cc = client_cert(chain, key)?;
        let cfg = Rc::new(ClientConfig { pinned_ca: None, roots: self.inner.roots.clone(), client_cert: Some(cc), alpn: alloc::vec![b"http/1.1".to_vec()], tls12: false });
        self.inner.unary.connector().set_config(cfg.clone());
        self.inner.watch.connector().set_config(cfg);
        Ok(())
    }

    /// Replaces the server list (e.g. from the `kubernetes` endpoints), keeping the server in
    /// use if it is still listed. Invalid URLs are skipped; an empty list changes nothing.
    pub fn set_servers(&self, urls: &[String]) {
        let urls: Vec<String> = urls.iter().map(|u| u.trim_end_matches('/').to_string()).filter(|u| Url::parse(u).is_ok()).collect();
        if urls.is_empty() {
            return;
        }
        let current = self.server();
        let mut list = self.inner.servers.borrow_mut();
        *list = urls;
        let i = list.iter().position(|u| *u == current).unwrap_or(0);
        self.inner.cur.set(i);
    }

    pub fn servers(&self) -> Vec<String> {
        self.inner.servers.borrow().clone()
    }

    /// The server in use.
    pub fn server(&self) -> String {
        let l = self.inner.servers.borrow();
        l[self.inner.cur.get() % l.len()].clone()
    }

    fn rotate(&self) {
        let n = self.inner.servers.borrow().len();
        self.inner.cur.set((self.inner.cur.get() + 1) % n);
    }

    fn url(&self, path: &str, query: &str) -> String {
        let mut u = alloc::format!("{}{}", self.server(), path);
        if !query.is_empty() {
            u.push('?');
            u.push_str(query);
        }
        u
    }

    fn headers<'a>(&'a self, ct: Option<&'a str>, auth: &'a str) -> Vec<(&'a str, &'a str)> {
        let mut h = alloc::vec![("Accept", "application/json")];
        if let Some(ct) = ct {
            h.push(("Content-Type", ct));
        }
        if self.inner.bearer.is_some() {
            h.push(("Authorization", auth));
        }
        h
    }

    /// One call, trying each server once on transport errors (refused, reset, timeout). A
    /// write may then reach the cluster twice; the kubelet's writes are idempotent or
    /// precondition-guarded (resourceVersion, AlreadyExists).
    async fn unary(&self, method: &str, path: &str, query: &str, ct: Option<&str>, body: &[u8]) -> Result<Value> {
        let n = self.inner.servers.borrow().len();
        let mut last = None;
        for _ in 0..n {
            match self.unary_once(method, path, query, ct, body).await {
                Err(e) if e.code == 503 && e.message.starts_with(TRANSPORT) => {
                    self.rotate();
                    last = Some(e);
                }
                r => return r,
            }
        }
        Err(last.unwrap_or_else(|| ApiError::new(503, "ServiceUnavailable", "no API server")))
    }

    async fn unary_once(&self, method: &str, path: &str, query: &str, ct: Option<&str>, body: &[u8]) -> Result<Value> {
        let (path, query) = split_path(path, query);
        let url = self.url(path, &query);
        let auth = self.inner.bearer.as_deref().map(|t| alloc::format!("Bearer {t}")).unwrap_or_default();
        let headers = self.headers(ct, &auth);
        let call = async {
            let mut resp = self.inner.unary.request(method, &url, &headers, body).await.map_err(net_err)?;
            let data = resp.read_to_end(MAX_BODY).await.map_err(net_err)?;
            if (200..300).contains(&resp.status) {
                json::parse(&data).map_err(|_| ApiError::new(502, "BadGateway", "invalid JSON in response"))
            } else {
                Err(status_error(resp.status, &resp.reason, &data))
            }
        };
        match timeout(UNARY_TIMEOUT_MS, call).await {
            Ok(r) => r,
            Err(_) => Err(ApiError::new(503, "ServiceUnavailable", alloc::format!("{TRANSPORT}timeout"))),
        }
    }
}

fn split_path<'a>(path: &'a str, query: &'a str) -> (&'a str, String) {
    match path.split_once('?') {
        Some((p, q)) if query.is_empty() => (p, q.to_string()),
        Some((p, q)) => (p, alloc::format!("{q}&{query}")),
        None => (path, query.to_string()),
    }
}

fn describe(e: NetError) -> &'static str {
    match e {
        NetError::Timeout => "timeout",
        NetError::Resolve => "name resolution failed",
        NetError::UnexpectedEof => "connection closed unexpectedly",
        NetError::Tls(_) => "TLS error",
        NetError::Io(_) => "connection error",
        NetError::TooLarge(_) => "response too large",
        NetError::Parse(_) | NetError::Smuggling(_) => "malformed HTTP response",
        _ => "network error",
    }
}

/// Message prefix of errors where no HTTP response arrived (another server may answer).
const TRANSPORT: &str = "transport error: ";

fn net_err(e: NetError) -> ApiError {
    ApiError::new(503, "ServiceUnavailable", alloc::format!("{TRANSPORT}{}", describe(e)))
}

fn status_error(code: u16, http_reason: &str, body: &[u8]) -> ApiError {
    let v = json::parse(body).ok();
    let sreason = v.as_ref().and_then(|v| v.get("reason")).and_then(Value::as_str).unwrap_or("");
    let reason: &'static str = match sreason {
        "NotFound" => "NotFound",
        "AlreadyExists" => "AlreadyExists",
        "Conflict" => "Conflict",
        "Invalid" => "Invalid",
        "BadRequest" => "BadRequest",
        "Forbidden" => "Forbidden",
        "Unauthorized" => "Unauthorized",
        "Expired" | "Gone" => "Expired",
        "MethodNotAllowed" => "MethodNotAllowed",
        "RequestEntityTooLarge" => "RequestEntityTooLarge",
        "UnsupportedMediaType" => "UnsupportedMediaType",
        "ServiceUnavailable" => "ServiceUnavailable",
        "InternalError" => "InternalError",
        _ => match code {
            400 => "BadRequest",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "NotFound",
            405 => "MethodNotAllowed",
            409 => "Conflict",
            410 => "Expired",
            413 => "RequestEntityTooLarge",
            415 => "UnsupportedMediaType",
            422 => "Invalid",
            503 => "ServiceUnavailable",
            _ => "Error",
        },
    };
    let msg = match v.as_ref().and_then(|v| v.get("message")).and_then(Value::as_str) {
        Some(m) if !m.is_empty() => m.to_string(),
        _ => http_reason.to_string(),
    };
    ApiError::new(code, reason, msg)
}

/// The body of an in-flight watch response. Dropping it closes the connection; it is never
/// pooled mid-stream (and the watch client's pool is disabled anyway).
pub struct RemoteStream {
    resp: Response<MaybeTls>,
}

impl RemoteStream {
    /// Appends the next body bytes to `buf`; false at end of stream or on error.
    pub(super) async fn read_more(&mut self, buf: &mut Vec<u8>) -> bool {
        let mut tmp = [0u8; 8192];
        match self.resp.read_chunk(&mut tmp).await {
            Ok(n) if n > 0 => {
                buf.extend_from_slice(&tmp[..n]);
                true
            }
            _ => false,
        }
    }
}

impl Client for Remote {
    async fn get(&self, path: &str) -> Result<Value> {
        self.unary("GET", path, "", None, b"").await
    }
    async fn list(&self, path: &str, query: &str) -> Result<Value> {
        self.unary("GET", path, query, None, b"").await
    }
    async fn create(&self, path: &str, obj: &Value) -> Result<Value> {
        self.unary("POST", path, "", Some("application/json"), json::to_string(obj).as_bytes()).await
    }
    async fn update(&self, path: &str, obj: &Value) -> Result<Value> {
        self.unary("PUT", path, "", Some("application/json"), json::to_string(obj).as_bytes()).await
    }
    async fn patch(&self, path: &str, content_type: &str, patch: &Value) -> Result<Value> {
        self.unary("PATCH", path, "", Some(content_type), json::to_string(patch).as_bytes()).await
    }
    async fn delete(&self, path: &str) -> Result<Value> {
        self.unary("DELETE", path, "", None, b"").await
    }
    async fn watch(&self, path: &str, query: &str) -> Result<Watch> {
        let (path, mut q) = split_path(path, query);
        if !q.split('&').any(|kv| kv == "watch=1" || kv == "watch=true") {
            if !q.is_empty() {
                q.push('&');
            }
            q.push_str("watch=1");
        }
        if !q.split('&').any(|kv| kv.starts_with("timeoutSeconds=")) {
            q.push_str(&alloc::format!("&timeoutSeconds={WATCH_TIMEOUT_SECONDS}"));
        }
        let url = self.url(path, &q);
        let auth = self.inner.bearer.as_deref().map(|t| alloc::format!("Bearer {t}")).unwrap_or_default();
        let headers = self.headers(None, &auth);
        // Only connecting and the response head are bounded; the body has the idle limit.
        // On failure the next attempt (the caller re-watches) goes to the next server.
        let mut resp = match timeout(UNARY_TIMEOUT_MS, self.inner.watch.request("GET", &url, &headers, b"")).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                self.rotate();
                return Err(net_err(e));
            }
            Err(_) => {
                self.rotate();
                return Err(ApiError::new(503, "ServiceUnavailable", alloc::format!("{TRANSPORT}timeout")));
            }
        };
        if !(200..300).contains(&resp.status) {
            let data = resp.read_to_end(1024 * 1024).await.unwrap_or_default();
            return Err(status_error(resp.status, &resp.reason, &data));
        }
        Ok(Watch::from_remote(RemoteStream { resp }))
    }
}

