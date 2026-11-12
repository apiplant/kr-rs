//! `Audit-ID` on every request and `ResponseComplete` for upgraded connections.

use kr_apiserver::api::ApiServer;
use kr_apiserver::audit::{begin, finish, Auditor, Policy};
use kr_net::http1::server::{Body, Request, Response, UpgradedConn};
use std::rc::Rc;
use std::task::{Context, Poll};

fn rng(b: &mut [u8]) {
    kr_sys::getrandom(b)
}

struct Stub;

impl UpgradedConn for Stub {
    fn poll_read(&mut self, _: &mut Context<'_>, _: &mut [u8]) -> Poll<kr_net::Result<usize>> {
        Poll::Ready(Ok(0))
    }
    fn poll_write(&mut self, _: &mut Context<'_>, b: &[u8]) -> Poll<kr_net::Result<usize>> {
        Poll::Ready(Ok(b.len()))
    }
    fn poll_flush(&mut self, _: &mut Context<'_>) -> Poll<kr_net::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(&mut self, _: &mut Context<'_>) -> Poll<kr_net::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn request(path: &str, hdr: &[(&str, &str)]) -> Request {
    Request { method: "POST".into(), target: path.into(), headers: hdr.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect(), body: Vec::new(), peer: Default::default() }
}

#[test]
fn healthz_carries_an_audit_id_even_when_not_audited() {
    let api = Rc::new(ApiServer::new(kr_store::Store::in_memory(), || 1_700_000_000, rng, "127.0.0.1".into()).unwrap());
    let r = kr_rt::exec::block_on({
        let api = api.clone();
        async move { kr_apiserver::server::handle(&api, request("/healthz", &[])).await }
    });
    let id = r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("audit-id")).map(|(_, v)| v.clone()).expect("Audit-ID");
    assert_eq!(id.len(), 36);
    let r = kr_rt::exec::block_on({
        let api = api.clone();
        async move { kr_apiserver::server::handle(&api, request("/healthz", &[("Audit-ID", "mine-1")])).await }
    });
    assert!(r.headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("audit-id") && v == "mine-1"));
}

#[test]
fn upgraded_connection_records_response_complete_when_it_closes() {
    let dir = format!("{}/audit-upgrade-{}", env!("CARGO_TARGET_TMPDIR"), std::process::id());
    let path = format!("{dir}/audit.log");
    let api = Rc::new(ApiServer::new(kr_store::Store::in_memory(), || 1_700_000_000, rng, "127.0.0.1".into()).unwrap());
    let a = Rc::new(Auditor::open(Policy::builtin(), &path, 100, 5));
    api.audit.set_auditor(a.clone());
    let req = request("/api/v1/namespaces/default/pods/p/exec", &[]);
    let p = begin(&api, &req, None);
    assert!(p.is_some());
    let mut resp = Response::new(101, Vec::new()).with_header("Upgrade", "SPDY/3.1");
    resp.body = Body::Upgrade(Box::new(|_c: Box<dyn UpgradedConn>| -> kr_net::http1::server::UpgradeFuture { Box::pin(async {}) }));
    finish(&api, p, &mut resp, Vec::new());
    a.flush();
    let log = std::fs::read_to_string(&path).unwrap();
    assert!(log.contains("\"stage\":\"ResponseStarted\"") && !log.contains("ResponseComplete"), "{log}");
    let Body::Upgrade(h) = std::mem::replace(&mut resp.body, Body::Full(Vec::new())) else { panic!("still an upgrade") };
    kr_rt::exec::block_on(h.upgrade(Box::new(Stub)));
    a.flush();
    let log = std::fs::read_to_string(&path).unwrap();
    assert!(log.contains("\"stage\":\"ResponseComplete\"") && log.contains("\"code\":101"), "{log}");
}
