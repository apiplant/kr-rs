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

fn log_line(msg: &str) {
    let _ = kr_sys::write(2, msg.as_bytes());
}

/// Handles a request; one slower than 300 ms is logged (the single-threaded loop is stalled for
/// as long as its synchronous parts run, which is what clients see as timeouts).
pub async fn handle(api: &Rc<ApiServer>, req: Request) -> Response {
    let (t0, method, path) = (kr_rt::exec::now_ms(), req.method.clone(), alloc::string::String::from(req.path()));
    let pf = core::cell::RefCell::new(None);
    let audit = crate::audit::begin(api, &req, user_from_certs(req.peer.client_certs.as_deref()));
    let mut resp = handle_inner(api, req, &pf).await;
    kr_rt::exec::phase("http: audit finish");
    crate::audit::finish(api, audit, &resp);
    kr_rt::exec::phase("http: response built");
    if let Some((flow, level)) = pf.into_inner() {
        resp = resp.with_header("X-Kubernetes-PF-FlowSchema-UID", &flow).with_header("X-Kubernetes-PF-PriorityLevel-UID", &level);
    }
    if resp.status == 429 {
        resp = resp.with_header("Retry-After", "1");
    }
    let took = kr_rt::exec::now_ms().saturating_sub(t0);
    if took >= 300 && !path.contains("/watch") && resp.status != 101 {
        log_line(&alloc::format!("kr: slow request {method} {path} {} {took}ms\n", resp.status));
    }
    resp
}

async fn handle_inner(api: &Rc<ApiServer>, req: Request, pf: &core::cell::RefCell<Option<(alloc::string::String, alloc::string::String)>>) -> Response {
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
    // API priority and fairness (a request forwarded by another server was admitted there).
    let _permit = if is_forwarded {
        None
    } else {
        match crate::apf::admit(api, &r).await {
            Ok((permit, ids)) => {
                *pf.borrow_mut() = ids;
                Some(permit)
            }
            Err(e) => return respond(Reply::err(e)),
        }
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
    // The read-index answer other servers use (peers only: a server certificate).
    if r.method == "GET" && r.path == forward::READ_INDEX {
        let peer_ok = peer_cert.is_some_and(|c| crate::cluster::transport::peer_id(c).is_some());
        return match (peer_ok, api.cluster().and_then(|c| c.read_index_rev())) {
            (true, Some(rev)) => Response::new(200, format!("{rev}").into_bytes()),
            (true, None) => Response::new(503, b"not the leader\n".to_vec()),
            _ => Response::new(403, b"forbidden\n".to_vec()),
        };
    }
    // Reads that must be current (no resourceVersion, not a watch) wait for a read barrier on
    // HA servers, so a client sees every write acknowledged before its read, on any server.
    if let Some(c) = api.cluster().filter(|_| r.method == "GET" && !is_forwarded && (r.path.starts_with("/api") || r.path.starts_with("/apis"))) {
        let q = r.query;
        let has = |k: &str| q.split('&').any(|p| p.split('=').next() == Some(k) && p.split_once('=').is_some_and(|(_, v)| !v.is_empty()));
        let watching = q.split('&').any(|p| matches!(p, "watch=true" | "watch=1" | "watch"));
        if !watching && !has("resourceVersion") && !c.read_barrier(api).await {
            return respond(Reply::err(crate::object::ApiError::new(503, "ServiceUnavailable", "no leader to confirm a consistent read")));
        }
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
    // Aggregated APIs (APIServices backed by a Service) are served by their extension server.
    if let Some(reply) = crate::aggregator::proxy(api, &r).await {
        return respond(reply);
    }
    let before = api.revision();
    if let Some(reply) = crate::convert::pre(api, &r).await {
        return respond(reply);
    }
    // A collection delete selected by a converted version's fields is a list and per-item deletes.
    let (res, mut warnings) = match crate::convert::delete_collection(api, &r).await {
        Some(reply) => (Ok(Run::Done(reply)), alloc::vec::Vec::new()),
        None => crate::webhook::run(api, &r).await,
    };
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
            // Admission saw the request's version; the write is stored as the storage version.
            let (reply, w) = match crate::convert::write(api, &r).await {
                Some(done) => done,
                None => api.handle_w(&r),
            };
            warnings.extend(w);
            let reply = crate::convert::post(api, &r, reply).await;
            crate::convert::watch(api, &r, reply)
        }
    };
    if let Reply::Proxy(t) = reply {
        return crate::podproxy::forward(t).await;
    }
    // A write is acknowledged only once it is on disk (group commit, fsync off the event loop).
    let after = api.revision();
    kr_rt::exec::phase("http: commit");
    if after > before && api.commit(after).await.is_err() {
        return respond(Reply::err(crate::object::ApiError::new(500, "InternalError", "storage sync failed")));
    }
    kr_rt::exec::phase("http: respond");
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
        Reply::Proxy(_) => Response::new(500, b"proxy reply outside the transport".to_vec()),
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
    // Availability of aggregated APIs: probe every Service-backed APIService every few seconds.
    let a2 = api.clone();
    kr_rt::exec::spawn(async move {
        loop {
            crate::aggregator::probe_all(&a2).await;
            let rev = a2.revision();
            if rev > a2.durable_rev() {
                let _ = a2.commit(rev).await;
            }
            kr_rt::exec::sleep(2000).await;
        }
    });
    // Event-loop stalls: a 50 ms sleep that returns much later means something ran too long.
    kr_rt::exec::spawn(async move {
        loop {
            let t0 = kr_rt::exec::now_ms();
            kr_rt::exec::sleep(50).await;
            let lag = kr_rt::exec::now_ms().saturating_sub(t0).saturating_sub(50);
            if lag >= 250 {
                log_line(&alloc::format!("kr: event loop stalled {lag}ms\n"));
            }
        }
    });
    let listener = server::listen(addr, port, 4096)?;
    // Dual stack: pods reach the `kubernetes` Service over IPv6 too (best effort).
    if addr == [0, 0, 0, 0] {
        if let Ok(l6) = server::listen6(port, 4096) {
            let (api, tls) = (api.clone(), tls.clone());
            kr_rt::exec::spawn(async move {
                let _ = serve(api, l6, tls).await;
            });
        }
    }
    serve(api, listener, tls).await
}

/// Serves the API on an already bound listener (no background flushing; see [`run`]).
pub async fn serve(api: Rc<ApiServer>, listener: kr_rt::exec::Async<kr_sys::Fd>, tls: Rc<kr_crypto::tls::ServerConfig>) -> kr_net::Result<()> {
    // Parallel clients keep hundreds of idle connections; one over the cap is closed unanswered
    // (the client sees EOF), so the cap sits well above any realistic client count.
    let cfg = Rc::new(ServerConfig { tls: Some(tls), idle_timeout_ms: 300_000, max_connections: 32_768, ..ServerConfig::default() });
    let handler = move |req: Request| -> HandlerFuture {
        let api = api.clone();
        Box::pin(async move { handle(&api, req).await })
    };
    server::serve(listener, cfg, Rc::new(handler)).await
}
