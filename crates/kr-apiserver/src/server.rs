//! HTTP glue: authenticates the TLS client certificate, adapts [`api::Reply`] to kr-net
//! responses (watches become chunked streams), and runs the listener.

use crate::api::{ApiServer, Reply, Req, User, WatchStream};
use crate::cluster::forward;
use kr_fmt::json;
use crate::webhook::Run;
use alloc::boxed::Box;
use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use core::task::{Context, Poll};
use kr_crypto::x509::Certificate;
use kr_net::http1::server::{self, Body, HandlerFuture, Request, Response, ResponseStream, ServerConfig};

/// The client certificate chain was already verified against the cluster CA by the TLS layer;
/// the leaf's CN is the user name and its O values are the groups (Kubernetes convention).
fn user_from_certs(chain: Option<&[alloc::vec::Vec<u8>]>) -> Option<User> {
    let leaf = Certificate::parse(chain?.first()?).ok()?;
    let name = String::from_utf8(leaf.common_name()?.to_vec()).ok()?;
    let mut groups: alloc::vec::Vec<String> = leaf.organizations().iter().filter_map(|o| String::from_utf8(o.to_vec()).ok()).collect();
    groups.push(String::from("system:authenticated"));
    Some(User { name, groups })
}

struct Watch(WatchStream);

impl ResponseStream for Watch {
    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<alloc::vec::Vec<u8>>> {
        self.0.poll_chunk(cx)
    }
}

pub async fn handle(api: &ApiServer, req: Request) -> Response {
    // Another server forwarding a write for one of its clients (ADR-026).
    let peer_cert = req.peer.client_certs.as_deref().and_then(|c| c.first()).map(|c| c.as_slice());
    let forwarded = forward::trusted_identity(peer_cert, req.header(forward::IDENTITY));
    let is_forwarded = forwarded.is_some();
    let user = forwarded.or_else(|| user_from_certs(req.peer.client_certs.as_deref()));
    let r = Req {
        method: &req.method,
        path: req.path(),
        query: req.query(),
        content_type: req.header("content-type"),
        accept: req.header("accept"),
        body: &req.body,
        user,
        headers: &req.headers,
        bearer: req.header("authorization").and_then(|a| a.strip_prefix("Bearer ").or_else(|| a.strip_prefix("bearer "))).map(str::trim),
        authz_verb: None,
    };
    // Raft state of this server, for cluster admins (diagnostics, tools/test/ha.sh).
    if r.method == "GET" && r.path == "/kr/debug/raft" {
        let admin = api.authenticate(&r).is_ok_and(|u| u.groups.iter().any(|g| g == "system:masters"));
        return match api.cluster() {
            _ if !admin => respond(Reply::err(crate::object::ApiError::new(403, "Forbidden", "requires system:masters"))),
            Some(c) => Response::new(200, format!("id={} {}\n", c.id, c.debug_state()).into_bytes()).with_header("Content-Type", "text/plain"),
            None => respond(Reply::err(crate::object::ApiError::new(404, "NotFound", "not an HA server"))),
        };
    }
    if let Some(c) = api.cluster().filter(|_| ApiServer::mutates(&r)) {
        match c.route(5_000).await {
            Ok(None) => {
                if let Some(reply) = c.membership(api, &r).await {
                    return respond(reply);
                }
            }
            // Forward once; a forwarded request reaching a non-leader is refused (no loops).
            Ok(Some(leader)) if !is_forwarded => {
                let user = match api.authenticate(&r) {
                    Ok(u) => u,
                    Err(e) => return respond(Reply::err(e)),
                };
                return match c.forward(api, leader, &user, &req.method, r.path, r.query, &req.headers, &req.body).await {
                    Some(f) => {
                        let mut resp = Response::new(f.status, f.body).with_header("Content-Type", &f.content_type);
                        for w in f.warnings {
                            resp = resp.with_header("Warning", &w);
                        }
                        resp
                    }
                    None => respond(Reply::err(crate::api::not_leader(Some(leader)))),
                };
            }
            Ok(l) | Err(l) => return respond(Reply::err(crate::api::not_leader(l))),
        }
    }
    let before = api.revision();
    let (res, warnings) = crate::webhook::run(api, &r).await;
    let rewritten;
    let reply = match res {
        Err(reply) => reply,
        Ok(Run::Done(reply)) => reply,
        Ok(Run::Pass(w)) => {
            let r = match w {
                None => r,
                Some(w) => {
                    rewritten = w;
                    Req { method: rewritten.method, content_type: Some("application/json"), body: &rewritten.body, authz_verb: (r.method == "PATCH").then_some("patch"), ..r }
                }
            };
            api.handle(&r)
        }
    };
    // A write is acknowledged only once it is on disk (group commit, fsync off the event loop).
    let after = api.revision();
    if after > before && api.commit(after).await.is_err() {
        return respond(Reply::err(crate::object::ApiError::new(500, "InternalError", "storage sync failed")));
    }
    let mut resp = respond_to(reply, req.header("accept"));
    if is_forwarded {
        resp = resp.with_header(forward::REVISION, &format!("{}", api.revision()));
    }
    for w in warnings {
        resp = resp.with_header("Warning", &format!("299 - \"{}\"", w.replace('\\', "\\\\").replace('"', "\\\"").replace(['\n', '\r'], " ")));
    }
    resp
}

/// The client's first acceptable media type is plain protobuf (client-go typed clients send
/// `application/vnd.kubernetes.protobuf, */*`); conversions such as `as=Table` stay JSON.
fn wants_protobuf(accept: Option<&str>) -> bool {
    let Some(first) = accept.and_then(|a| a.split(',').map(str::trim).find(|m| !m.is_empty())) else { return false };
    let mut parts = first.split(';').map(str::trim);
    parts.next() == Some("application/vnd.kubernetes.protobuf") && parts.all(|p| !p.starts_with("as="))
}

/// Like [`respond`], in protobuf when the client prefers it and the kind has a protobuf form.
fn respond_to(reply: Reply, accept: Option<&str>) -> Response {
    if let (true, Reply::Json(code, body)) = (wants_protobuf(accept), &reply) {
        if let Some(b) = json::parse(body.as_bytes()).ok().as_ref().and_then(crate::proto::encode_body) {
            return Response::new(*code, b).with_header("Content-Type", "application/vnd.kubernetes.protobuf");
        }
    }
    respond(reply)
}

fn respond(reply: Reply) -> Response {
    match reply {
        Reply::Json(code, body) => {
            let ct = if body.contains("\"kind\":\"Table\"") && body.starts_with("{\"kind\":\"Table\"") { "application/json;as=Table;v=v1;g=meta.k8s.io" } else { "application/json" };
            Response::new(code, body.into_bytes()).with_header("Content-Type", ct)
        }
        Reply::Http(r) => r,
        Reply::Watch(w) => Response { status: 200, headers: alloc::vec![("Content-Type".into(), "application/json".into())], body: Body::Stream(Box::new(Watch(w))) },
    }
}

/// Serves the API on `addr:port` until the listener fails.
pub async fn run(api: Rc<ApiServer>, addr: [u8; 4], port: u16, tls: Rc<kr_crypto::tls::ServerConfig>) -> kr_net::Result<()> {
    // Writes by in-process components (controllers, the server's kubelet) are not awaited by
    // any HTTP request: flush them every second. Compaction is checked every minute.
    let a = api.clone();
    kr_rt::exec::spawn(async move {
        let mut n = 0u32;
        loop {
            kr_rt::exec::sleep(1000).await;
            let rev = a.revision();
            if rev > a.durable_rev() {
                let _ = a.commit(rev).await;
            }
            n += 1;
            if n % 60 == 0 {
                a.maybe_compact();
            }
        }
    });
    let listener = server::listen(addr, port, 512)?;
    serve(api, listener, tls).await
}

/// Serves the API on an already bound listener (no background flushing; see [`run`]).
pub async fn serve(api: Rc<ApiServer>, listener: kr_rt::exec::Async<kr_sys::Fd>, tls: Rc<kr_crypto::tls::ServerConfig>) -> kr_net::Result<()> {
    let cfg = Rc::new(ServerConfig { tls: Some(tls), idle_timeout_ms: 300_000, ..ServerConfig::default() });
    let handler = move |req: Request| -> HandlerFuture {
        let api = api.clone();
        Box::pin(async move { handle(&api, req).await })
    };
    server::serve(listener, cfg, Rc::new(handler)).await
}
