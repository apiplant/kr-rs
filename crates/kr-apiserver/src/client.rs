//! The API client used by kr's own components (controllers, scheduler, kubelet).
//!
//! [`Client`] is the interface; [`InProcess`] calls [`ApiServer::handle`] directly as an
//! internal `system:masters` identity (no HTTP, no TLS). [`Remote`] speaks HTTPS to an API
//! server on another machine (node agents). All objects are `kr_fmt::json::Value`.

use crate::api::{ApiServer, Reply, Req, User, WatchStream};
use crate::object::ApiError;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::future::poll_fn;
use kr_fmt::json::{self, Value};

mod remote;
pub use remote::{Remote, RemoteAuth};

pub type Result<T> = core::result::Result<T, ApiError>;

/// A watch event: `ADDED`, `MODIFIED`, `DELETED`, `BOOKMARK` or `ERROR`.
#[derive(Debug, Clone)]
pub struct WatchEvent {
    pub kind: String,
    pub object: Value,
}

/// API access for kr components. Paths are API paths without query
/// (e.g. `/api/v1/namespaces/default/pods`); `query` is a raw query string.
#[allow(async_fn_in_trait)]
pub trait Client {
    async fn get(&self, path: &str) -> Result<Value>;
    async fn list(&self, path: &str, query: &str) -> Result<Value>;
    async fn create(&self, path: &str, obj: &Value) -> Result<Value>;
    async fn update(&self, path: &str, obj: &Value) -> Result<Value>;
    /// `content_type` is one of the patch media types.
    async fn patch(&self, path: &str, content_type: &str, patch: &Value) -> Result<Value>;
    async fn delete(&self, path: &str) -> Result<Value>;
    async fn watch(&self, path: &str, query: &str) -> Result<Watch>;
}

/// A stream of watch events. Ends (`None`) at the server-side timeout or on error; callers
/// re-list/re-watch (see [`Informer`]-style loops in the controllers).
pub struct Watch {
    inner: Source,
    buf: Vec<u8>,
}

enum Source {
    InProcess(WatchStream),
    Remote(remote::RemoteStream),
}

impl Watch {
    pub(crate) fn from_remote(r: remote::RemoteStream) -> Watch {
        Watch { inner: Source::Remote(r), buf: Vec::new() }
    }
}

impl Watch {
    pub async fn next(&mut self) -> Option<WatchEvent> {
        loop {
            if let Some(i) = self.buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=i).collect();
                let Ok(v) = json::parse(&line[..line.len() - 1]) else { continue };
                let kind = v.get("type").and_then(Value::as_str).unwrap_or("").to_string();
                let object = v.get("object").cloned().unwrap_or(Value::Null);
                return Some(WatchEvent { kind, object });
            }
            match &mut self.inner {
                Source::InProcess(w) => {
                    let chunk = poll_fn(|cx| w.poll_chunk(cx)).await?;
                    self.buf.extend_from_slice(&chunk);
                }
                Source::Remote(r) => {
                    if !r.read_more(&mut self.buf).await {
                        return None;
                    }
                }
            }
        }
    }
}

/// Direct calls into the API server on the same executor.
#[derive(Clone)]
pub struct InProcess {
    api: Rc<ApiServer>,
    user: User,
}

impl InProcess {
    pub fn new(api: Rc<ApiServer>, component: &str) -> InProcess {
        InProcess { api, user: User { name: alloc::format!("system:kr:{component}"), groups: alloc::vec![String::from("system:masters")] } }
    }

    fn call(&self, method: &str, path: &str, query: &str, ct: Option<&str>, body: &[u8]) -> Result<Value> {
        // Allow "path?query" for convenience (e.g. delete with gracePeriodSeconds).
        let (path, query) = match path.split_once('?') {
            Some((p, q)) if query.is_empty() => (p, q),
            _ => (path, query),
        };
        let req = Req { method, path, query, content_type: ct, accept: Some("application/json"), body, user: Some(self.user.clone()), bearer: None, headers: &[], authz_verb: None };
        match self.api.handle(&req) {
            Reply::Json(code, s) => {
                let v = json::parse(s.as_bytes()).unwrap_or(Value::Null);
                if code < 300 {
                    Ok(v)
                } else {
                    let reason = match code {
                        404 => "NotFound",
                        409 if s.contains("AlreadyExists") => "AlreadyExists",
                        409 => "Conflict",
                        410 => "Expired",
                        _ => "Error",
                    };
                    let msg = v.get("message").and_then(Value::as_str).unwrap_or("").to_string();
                    Err(ApiError::new(code, reason, msg))
                }
            }
            Reply::Watch(_) | Reply::Http(_) => Err(ApiError::new(500, "InternalError", "unexpected streaming reply")),
        }
    }
}

impl Client for InProcess {
    async fn get(&self, path: &str) -> Result<Value> {
        self.call("GET", path, "", None, b"")
    }
    async fn list(&self, path: &str, query: &str) -> Result<Value> {
        self.call("GET", path, query, None, b"")
    }
    async fn create(&self, path: &str, obj: &Value) -> Result<Value> {
        self.call("POST", path, "", Some("application/json"), json::to_string(obj).as_bytes())
    }
    async fn update(&self, path: &str, obj: &Value) -> Result<Value> {
        self.call("PUT", path, "", Some("application/json"), json::to_string(obj).as_bytes())
    }
    async fn patch(&self, path: &str, content_type: &str, patch: &Value) -> Result<Value> {
        self.call("PATCH", path, "", Some(content_type), json::to_string(patch).as_bytes())
    }
    async fn delete(&self, path: &str) -> Result<Value> {
        self.call("DELETE", path, "", None, b"")
    }
    async fn watch(&self, path: &str, query: &str) -> Result<Watch> {
        let q = if query.is_empty() { String::from("watch=1") } else { alloc::format!("{query}&watch=1") };
        let req = Req { method: "GET", path, query: &q, content_type: None, accept: Some("application/json"), body: b"", user: Some(self.user.clone()), bearer: None, headers: &[], authz_verb: None };
        match self.api.handle(&req) {
            Reply::Watch(w) => Ok(Watch { inner: Source::InProcess(w), buf: Vec::new() }),
            Reply::Json(code, s) => Err(ApiError::new(code, "Error", s)),
            Reply::Http(_) => Err(ApiError::new(500, "InternalError", "unexpected raw reply")),
        }
    }
}

/// `metadata.name` / `metadata.namespace` / ... of an object, or "".
pub fn meta<'a>(o: &'a Value, field: &str) -> &'a str {
    o.pointer(&["metadata", field]).and_then(Value::as_str).unwrap_or("")
}
