//! CRD conversion webhooks (apiextensions.k8s.io/v1 ConversionReview).
//!
//! New objects are stored in the CRD's storage version; objects written before that was done
//! (or before the storage version changed) keep the version they were written in, and a list may
//! mix versions. With `strategy: None` the handlers only retag apiVersion (`ApiServer::route`
//! rewrites a write to the storage version's URL, `ApiServer::convert_reply` retags the reply).
//! With `strategy: Webhook` the webhook calls are network I/O, so the transport runs them around
//! the synchronous handlers. Order of a write: authorization, [`pre`] (PATCH: the stored object
//! in the requested version), admission webhooks (they see the request's version, as upstream),
//! [`write`] (validation in the requested version, conversion to the storage version, execution
//! at the storage version's URL), [`post`] (the reply in the requested version). Watch events
//! are converted by [`watch`]. In-process clients see objects as stored.

use crate::api::{version_path, ApiServer, Reply, Req, WatchStream};
use crate::object::{obj, ApiError};
use alloc::boxed::Box;
use alloc::format;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use kr_fmt::json::{self, Value};
use kr_net::http1::server::{Body, Response, ResponseStream};

/// Upstream gives a conversion webhook 30 seconds.
const TIMEOUT_SECS: u64 = 30;

/// The metadata that must survive a conversion (labels and annotations may change).
fn meta_key(o: &Value) -> Value {
    let mut m = o.get("metadata").cloned().unwrap_or(Value::Null);
    m.remove("labels");
    m.remove("annotations");
    m
}

/// Sends `objs` to the webhook for conversion to `desired` (`group/version`) and checks the answer.
pub(crate) async fn convert(api: &ApiServer, cc: &Value, desired: &str, objs: &[Value]) -> Result<Vec<Value>, String> {
    let uid = api.wh_uid();
    let review = json::to_string(&obj(alloc::vec![
        ("apiVersion", Value::from("apiextensions.k8s.io/v1")),
        ("kind", Value::from("ConversionReview")),
        ("request", obj(alloc::vec![("uid", Value::from(uid.as_str())), ("desiredAPIVersion", Value::from(desired)), ("objects", Value::Array(objs.to_vec()))])),
    ]));
    let resp = crate::webhook::post_review(api, cc, TIMEOUT_SECS, &review).await?;
    check(&resp, &uid, desired, objs)
}

/// Validates a ConversionReview response.
pub(crate) fn check(resp: &Value, uid: &str, desired: &str, objs: &[Value]) -> Result<Vec<Value>, String> {
    let r = resp.get("response").ok_or("webhook response has no \"response\"")?;
    if r.get("uid").and_then(Value::as_str) != Some(uid) {
        return Err("expected response.uid to match request.uid".to_string());
    }
    if r.pointer(&["result", "status"]).and_then(Value::as_str) != Some("Success") {
        let m = r.pointer(&["result", "message"]).and_then(Value::as_str).unwrap_or("");
        return Err(format!("webhook failed to convert the objects: {m}"));
    }
    let out = r.get("convertedObjects").and_then(Value::as_array).ok_or("webhook response has no convertedObjects")?;
    if out.len() != objs.len() {
        return Err(format!("webhook returned {} objects for {}", out.len(), objs.len()));
    }
    for (o, c) in objs.iter().zip(out) {
        if c.get("apiVersion").and_then(Value::as_str) != Some(desired) {
            return Err(format!("webhook returned an object of apiVersion {:?}, want {desired:?}", c.get("apiVersion").and_then(Value::as_str).unwrap_or("")));
        }
        if c.get("kind") != o.get("kind") {
            return Err("webhook changed the kind of an object".to_string());
        }
        // Webhooks re-serialize the metadata with their own key order.
        if !crate::object::same_json(&Some(&meta_key(c)), &Some(&meta_key(o))) {
            return Err("webhook changed the metadata of an object".to_string());
        }
    }
    Ok(out.to_vec())
}

fn failed(from: &str, to: &str, why: &str) -> ApiError {
    ApiError::new(500, "InternalError", format!("conversion webhook for {from} to {to} failed: {why}"))
}

/// Converts every object of `items` that is not in `gv`, in one webhook call per source version.
async fn convert_items(api: &ApiServer, cc: &Value, gv: &str, items: &mut [&mut Value]) -> Result<(), ApiError> {
    let mut froms: Vec<String> = Vec::new();
    for it in items.iter() {
        let f = it.get("apiVersion").and_then(Value::as_str).unwrap_or(gv);
        if f != gv && !froms.iter().any(|x| x == f) {
            froms.push(f.to_string());
        }
    }
    for from in froms {
        let idx: Vec<usize> = (0..items.len()).filter(|i| items[*i].get("apiVersion").and_then(Value::as_str) == Some(from.as_str())).collect();
        let objs: Vec<Value> = idx.iter().map(|i| items[*i].clone()).collect();
        let out = convert(api, cc, gv, &objs).await.map_err(|e| failed(&from, gv, &e))?;
        for (i, c) in idx.into_iter().zip(out) {
            *items[i] = c;
        }
    }
    Ok(())
}

/// Before a PATCH of a webhook-converted custom resource: converts the stored object to the
/// requested version when it was stored as another one, and remembers it for the synchronous
/// handlers ([`ApiServer::cache_converted`]), so the patch applies to (and admission sees) the
/// object in that version. `Some`: the answer, an error.
pub async fn pre(api: &ApiServer, req: &Req<'_>) -> Option<Reply> {
    if req.method != "PATCH" {
        return None;
    }
    let rt = api.wh_route(req.path)?;
    let name = rt.name.clone()?;
    if rt.sub.as_deref().is_some_and(|s| s != "status") {
        return None;
    }
    let cc = api.conversion_webhook(rt.res)?;
    let gv = rt.res.group_version();
    let (kv, mut old) = api.get_value(&rt, &name).ok()?;
    if old.get("apiVersion").and_then(Value::as_str).is_none_or(|v| v == gv) {
        return None;
    }
    let user = api.authenticate(req).ok()?;
    // Only callers allowed to patch the object get a webhook call made on their behalf.
    if let Err(e) = api.authorize_request(req, &user) {
        return Some(Reply::err(e));
    }
    if let Err(e) = convert_items(api, &cc, &gv, &mut [&mut old]).await {
        return Some(Reply::err(e));
    }
    api.cache_converted(&rt, &name, &kv, old);
    None
}

/// `query` with `fieldValidation` replaced by `Ignore`.
fn ignore_validation(query: &str) -> String {
    let mut q: Vec<&str> = query.split('&').filter(|p| !p.is_empty() && !p.starts_with("fieldValidation=")).collect();
    q.push("fieldValidation=Ignore");
    q.join("&")
}

/// A write (POST, PUT, PATCH) to a webhook-converted custom resource in a version other than the
/// storage version: validates it in the requested version (so `fieldValidation` and errors are
/// about the object the client sent), converts the object to the storage version and executes the
/// write at the storage version's URL. The reply is in the storage version (see [`post`]).
///
/// Runs after admission, which sees the object in the requested version (as upstream does).
/// `None`: nothing to convert, execute the request as it is.
pub async fn write(api: &ApiServer, req: &Req<'_>) -> Option<(Reply, Vec<String>)> {
    if !matches!(req.method, "POST" | "PUT" | "PATCH") {
        return None;
    }
    let rt = api.wh_route(req.path)?;
    if rt.sub.as_deref().is_some_and(|s| s != "status") {
        return None;
    }
    let cc = api.conversion_webhook(rt.res)?;
    let sv = api.storage_version(rt.res)?;
    let gv = rt.res.group_version();
    let sgv = format!("{}/{sv}", rt.res.group);
    let user = api.authenticate(req).ok()?;
    // Only callers allowed to write get a webhook call made on their behalf.
    if let Err(e) = api.authorize_request(req, &user) {
        return Some((Reply::err(e), Vec::new()));
    }
    let dry_q = if req.query.is_empty() { "dryRun=All".to_string() } else { format!("{}&dryRun=All", req.query) };
    let dreq = Req { method: req.method, path: req.path, query: &dry_q, content_type: req.content_type, accept: None, body: req.body, user: Some(user.clone()), bearer: req.bearer, headers: req.headers, authz_verb: req.authz_verb };
    let (dreply, mut warns) = api.handle_w(&dreq);
    let Reply::Json(code, dbody) = &dreply else { return Some((dreply, warns)) };
    if *code >= 300 {
        return Some((dreply, warns));
    }
    let dry = req.query.split('&').any(|p| p == "dryRun=All");
    let mut path = version_path(req.path, &sv);
    let mut method = if req.method == "POST" { "POST" } else { "PUT" };
    let mut o = if req.method == "PATCH" {
        // The patched object, in the requested version; the write replaces the stored object
        // it was computed from (a concurrent change conflicts).
        if dry {
            return Some((dreply, warns));
        }
        json::parse(dbody.as_bytes()).ok()?
    } else {
        json::parse(req.body).ok()?
    };
    if o.get("apiVersion").and_then(Value::as_str) != Some(gv.as_str()) {
        return None;
    }
    if req.method == "PATCH" {
        match rt.name.as_deref().map(|n| api.get_value(&rt, n)) {
            Some(Ok((kv, _))) => o.entry_object("metadata").set("resourceVersion", Value::String(kv.mod_rev.to_string())),
            // Server-side apply of an object that does not exist yet.
            _ => {
                method = "POST";
                path.truncate(path.trim_end_matches('/').rfind('/')?);
            }
        }
    }
    if let Err(e) = convert_items(api, &cc, &sgv, &mut [&mut o]).await {
        return Some((Reply::err(e), warns));
    }
    let body = json::to_string(&o).into_bytes();
    // Field validation was done on the object as sent; the converted one is the webhook's.
    let q = ignore_validation(req.query);
    let sreq = Req { method, path: &path, query: &q, content_type: Some("application/json"), accept: None, body: &body, user: Some(user), bearer: req.bearer, headers: req.headers, authz_verb: (req.method == "PATCH").then_some("patch").or(req.authz_verb) };
    let (reply, w) = api.handle_w(&sreq);
    warns.extend(w);
    Some((reply, warns))
}

/// Converts the objects in a successful response of a webhook-converted custom resource to the
/// requested version.
pub async fn post(api: &ApiServer, req: &Req<'_>, reply: Reply) -> Reply {
    let Reply::Json(code, body) = &reply else { return reply };
    if *code >= 300 {
        return reply;
    }
    let Some(rt) = api.wh_route(req.path) else { return reply };
    if rt.sub.as_deref().is_some_and(|s| s != "status") {
        return reply;
    }
    let Some(cc) = api.conversion_webhook(rt.res) else { return reply };
    let gv = rt.res.group_version();
    let Ok(mut v) = json::parse(body.as_bytes()) else { return reply };
    let kind = v.get("kind").and_then(Value::as_str).unwrap_or("").to_string();
    let r = if kind == rt.res.kind {
        convert_items(api, &cc, &gv, &mut [&mut v]).await
    } else if kind == format!("{}List", rt.res.kind) {
        match v.get_mut("items").and_then(Value::as_array_mut) {
            Some(items) => convert_items(api, &cc, &gv, &mut items.iter_mut().collect::<Vec<_>>()).await,
            None => return reply,
        }
    } else {
        return reply;
    };
    let code = *code;
    match r {
        Ok(()) => Reply::Json(code, json::to_string(&v)),
        Err(e) => Reply::err(e),
    }
}

type Pending = Pin<Box<dyn Future<Output = (Vec<u8>, bool)>>>;

/// A watch of a webhook-converted custom resource: delivers each event's object in the requested
/// version. Events are converted a chunk at a time (one webhook call per stored version in it),
/// with at most one conversion in flight; the executor is never blocked. A failed conversion is
/// sent as an ERROR event (Status 500) and ends the stream, as upstream does.
struct ConvWatch {
    api: Rc<ApiServer>,
    cc: Value,
    gv: String,
    inner: WatchStream,
    pending: Option<Pending>,
    done: bool,
}

/// Wraps a watch reply of a webhook-converted custom resource in a [`ConvWatch`].
pub fn watch(api: &Rc<ApiServer>, req: &Req<'_>, reply: Reply) -> Reply {
    let Reply::Watch(inner) = reply else { return reply };
    let Some(rt) = api.wh_route(req.path) else { return Reply::Watch(inner) };
    let Some(cc) = api.conversion_webhook(rt.res) else { return Reply::Watch(inner) };
    let w = ConvWatch { api: api.clone(), cc, gv: rt.res.group_version(), inner, pending: None, done: false };
    Reply::Http(Response { status: 200, headers: alloc::vec![("Content-Type".into(), "application/json".into())], body: Body::Stream(Box::new(w)) })
}

/// Whether the event's object has to be converted to `gv`.
fn needs(ev: &Value, gv: &str) -> bool {
    matches!(ev.get("type").and_then(Value::as_str), Some("ADDED" | "MODIFIED" | "DELETED")) && ev.pointer(&["object", "apiVersion"]).and_then(Value::as_str).is_some_and(|v| v != gv)
}

/// Converts the events in `chunk` (newline-delimited watch events). The flag: the stream ends.
async fn convert_chunk(api: Rc<ApiServer>, cc: Value, gv: String, chunk: Vec<u8>) -> (Vec<u8>, bool) {
    let mut evs: Vec<Value> = chunk.split(|b| *b == b'\n').filter(|l| !l.is_empty()).filter_map(|l| json::parse(l).ok()).collect();
    let mut objs: Vec<&mut Value> = evs.iter_mut().filter(|e| needs(e, &gv)).filter_map(|e| e.get_mut("object")).collect();
    if let Err(e) = convert_items(&api, &cc, &gv, &mut objs).await {
        let Reply::Json(_, status) = Reply::err(e) else { return (Vec::new(), true) };
        let mut out = format!("{{\"type\":\"ERROR\",\"object\":{status}}}").into_bytes();
        out.push(b'\n');
        return (out, true);
    }
    let mut out = Vec::new();
    for e in &evs {
        out.extend_from_slice(json::to_string(e).as_bytes());
        out.push(b'\n');
    }
    (out, false)
}

impl ResponseStream for ConvWatch {
    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<Vec<u8>>> {
        loop {
            if let Some(f) = self.pending.as_mut() {
                let (out, end) = match f.as_mut().poll(cx) {
                    Poll::Ready(r) => r,
                    Poll::Pending => return Poll::Pending,
                };
                self.pending = None;
                self.done = end;
                return Poll::Ready(Some(out));
            }
            if self.done {
                return Poll::Ready(None);
            }
            match self.inner.poll_chunk(cx) {
                Poll::Ready(Some(chunk)) => {
                    let convert = chunk.split(|b| *b == b'\n').filter(|l| !l.is_empty()).any(|l| json::parse(l).is_ok_and(|e| needs(&e, &self.gv)));
                    if !convert {
                        return Poll::Ready(Some(chunk));
                    }
                    self.pending = Some(Box::pin(convert_chunk(self.api.clone(), self.cc.clone(), self.gv.clone(), chunk)));
                }
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_order_is_irrelevant() {
        // Go webhooks re-serialize the metadata with sorted keys.
        let o = json::parse_str(r#"{"apiVersion":"g/v1","kind":"K","metadata":{"name":"a","uid":"u","labels":{"x":"1"}}}"#).unwrap();
        let c = json::parse_str(r#"{"apiVersion":"g/v2","kind":"K","metadata":{"uid":"u","name":"a","labels":{"y":"2"}}}"#).unwrap();
        let resp = json::parse_str(&format!(r#"{{"response":{{"uid":"id","result":{{"status":"Success"}},"convertedObjects":[{}]}}}}"#, json::to_string(&c))).unwrap();
        assert_eq!(check(&resp, "id", "g/v2", &[o.clone()]).err(), None);
        let bad = json::parse_str(&json::to_string(&resp).replace(r#""uid":"u""#, r#""uid":"w""#)).unwrap();
        assert!(check(&bad, "id", "g/v2", &[o]).is_err());
    }
}
