//! HTTP glue: authenticates the TLS client certificate, adapts [`api::Reply`] to kr-net
//! responses (watches become chunked streams), and runs the listener.

use crate::api::{ApiServer, Reply, Req, User, WatchStream};
use alloc::boxed::Box;
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
    let user = user_from_certs(req.peer.client_certs.as_deref());
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
    let rewritten;
    let r = match crate::webhook::run(api, &r).await {
        Err(reply) => return respond(reply),
        Ok(None) => r,
        Ok(Some(w)) => {
            rewritten = w;
            Req { method: rewritten.method, content_type: Some("application/json"), body: &rewritten.body, authz_verb: (r.method == "PATCH").then_some("patch"), ..r }
        }
    };
    let before = api.revision();
    let reply = api.handle(&r);
    // A write is acknowledged only once it is on disk (group commit, fsync off the event loop).
    let after = api.revision();
    if after > before && api.commit(after).await.is_err() {
        return respond(Reply::err(crate::object::ApiError::new(500, "InternalError", "storage sync failed")));
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
    let cfg = Rc::new(ServerConfig { tls: Some(tls), idle_timeout_ms: 300_000, ..ServerConfig::default() });
    let handler = move |req: Request| -> HandlerFuture {
        let api = api.clone();
        Box::pin(async move { handle(&api, req).await })
    };
    server::serve(listener, cfg, Rc::new(handler)).await
}
