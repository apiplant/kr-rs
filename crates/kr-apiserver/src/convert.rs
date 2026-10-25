//! CRD conversion webhooks (apiextensions.k8s.io/v1 ConversionReview).
//!
//! Objects are stored as written, each with the apiVersion of the version it was written in
//! (a mixed list is the normal state after the storage version changed). With `strategy: None`
//! the handlers only retag apiVersion (`ApiServer::convert_reply`). With `strategy: Webhook`
//! the webhook calls are network I/O, so the transport runs them around the synchronous
//! handlers: [`pre`] converts an object about to be patched into the requested version, and
//! [`post`] converts the objects of a response (single, list) that are not in it. Watch events
//! and in-process clients see objects as stored.

use crate::api::{ApiServer, Reply, Req};
use crate::object::{obj, ApiError};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_fmt::json::{self, Value};

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
        if meta_key(c) != meta_key(o) {
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

/// Before a PATCH of a webhook-converted custom resource: stores the object as the requested
/// version, so the patch applies to (and the result is in) that version. `Some`: the answer.
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
    let (_, mut old) = api.get_value(&rt, &name).ok()?;
    if old.get("apiVersion").and_then(Value::as_str).is_none_or(|v| v == gv) {
        return None;
    }
    let user = api.authenticate(req).ok()?;
    if let Err(e) = convert_items(api, &cc, &gv, &mut [&mut old]).await {
        return Some(Reply::err(e));
    }
    let body = json::to_string(&old).into_bytes();
    let put = Req { method: "PUT", path: req.path, query: "", content_type: Some("application/json"), accept: None, body: &body, user: Some(user), bearer: req.bearer, headers: req.headers, authz_verb: Some("patch") };
    match api.handle(&put) {
        Reply::Json(c, _) if c < 300 => None,
        other => Some(other),
    }
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
