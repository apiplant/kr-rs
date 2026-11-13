//! How many requests per second one core of the API server handles, in process (no TLS, no sockets):
//! `cargo test --release -p kr-apiserver --test throughput -- --ignored --nocapture`.
use kr_apiserver::api::{ApiServer, Reply, Req, User};
use std::time::Instant;

fn rng(b: &mut [u8]) {
    kr_sys::getrandom(b)
}

fn call(api: &ApiServer, method: &str, path: &str, ct: &str, body: &str) -> u16 {
    let user = Some(User { name: "admin".into(), groups: vec!["system:masters".into()] });
    let req = Req { method, path, query: "", content_type: Some(ct), accept: None, body: body.as_bytes(), user, bearer: None, headers: &[], authz_verb: None };
    match api.handle(&req) {
        Reply::Json(c, _) => c,
        _ => 0,
    }
}

fn rate(name: &str, n: usize, mut f: impl FnMut(usize)) {
    let t = Instant::now();
    for i in 0..n {
        f(i);
    }
    let e = t.elapsed();
    eprintln!("{name:<34} {:>9.0} req/s ({:.1} us each)", n as f64 / e.as_secs_f64(), e.as_secs_f64() * 1e6 / n as f64);
}

#[test]
#[ignore]
fn one_core() {
    let api = ApiServer::new(kr_store::Store::in_memory(), || 1_700_000_000, rng, "127.0.0.1".into()).unwrap();
    let key = kr_crypto::p256::SecretKey::from_bytes(&[7; 32]).unwrap();
    api.set_service_accounts(kr_apiserver::tokens::Signer::new(key), "CA".into()).unwrap();
    let c = "application/json";
    rate("create pod", 2000, |i| {
        let pod = format!(r#"{{"metadata":{{"name":"p{i}","namespace":"default","labels":{{"app":"a{}"}}}},"spec":{{"containers":[{{"name":"c","image":"x"}}]}}}}"#, i % 50);
        assert_eq!(call(&api, "POST", "/api/v1/namespaces/default/pods", c, &pod), 201);
    });
    rate("get pod", 20000, |i| {
        assert_eq!(call(&api, "GET", &format!("/api/v1/namespaces/default/pods/p{}", i % 2000), c, ""), 200);
    });
    rate("patch pod status (merge)", 5000, |i| {
        let p = format!(r#"{{"status":{{"phase":"Running","podIP":"10.0.{}.{}"}}}}"#, (i / 250) % 250, i % 250);
        assert_eq!(call(&api, "PATCH", &format!("/api/v1/namespaces/default/pods/p{}/status", i % 2000), "application/merge-patch+json", &p), 200);
    });
    rate("list 2000 pods (full)", 50, |_| {
        assert_eq!(call(&api, "GET", "/api/v1/namespaces/default/pods", c, ""), 200);
    });
    rate("list pods, labelSelector (40 hits)", 200, |i| {
        let user = Some(User { name: "admin".into(), groups: vec!["system:masters".into()] });
        let q = format!("labelSelector=app%3Da{}", i % 50);
        let req = Req { method: "GET", path: "/api/v1/namespaces/default/pods", query: &q, content_type: Some(c), accept: None, body: b"", user, bearer: None, headers: &[], authz_verb: None };
        assert!(matches!(api.handle(&req), Reply::Json(200, _)));
    });
    rate("delete pod", 1000, |i| {
        assert_eq!(call(&api, "DELETE", &format!("/api/v1/namespaces/default/pods/p{i}"), c, ""), 200);
    });
}

/// The kubelet's query: every node lists `pods?fieldSelector=spec.nodeName=<node>` about once a
/// second, so with N nodes and P pods the API server does N lists over P pods each second.
#[test]
#[ignore]
fn node_pod_lists() {
    let api = ApiServer::new(kr_store::Store::in_memory(), || 1_700_000_000, rng, "127.0.0.1".into()).unwrap();
    let key = kr_crypto::p256::SecretKey::from_bytes(&[7; 32]).unwrap();
    api.set_service_accounts(kr_apiserver::tokens::Signer::new(key), "CA".into()).unwrap();
    let c = "application/json";
    let (pods, nodes) = (5000, 100);
    for i in 0..pods {
        let pod = format!(r#"{{"metadata":{{"name":"p{i}","namespace":"ns{}","labels":{{"app":"a{}"}}}},"spec":{{"nodeName":"n{}","containers":[{{"name":"c","image":"x"}}]}}}}"#, i % 20, i % 50, i % nodes);
        if i < 20 {
            let ns = format!(r#"{{"metadata":{{"name":"ns{i}"}}}}"#);
            call(&api, "POST", "/api/v1/namespaces", c, &ns);
        }
        assert_eq!(call(&api, "POST", &format!("/api/v1/namespaces/ns{}/pods", i % 20), c, &pod), 201);
    }
    let user = || Some(User { name: "admin".into(), groups: vec!["system:masters".into()] });
    rate("list pods, fieldSelector nodeName (50)", 500, |i| {
        let q = format!("fieldSelector=spec.nodeName%3Dn{}", i % nodes);
        let req = Req { method: "GET", path: "/api/v1/pods", query: &q, content_type: Some(c), accept: None, body: b"", user: user(), bearer: None, headers: &[], authz_verb: None };
        match api.handle(&req) {
            Reply::Json(200, b) => assert_eq!(b.matches("\"nodeName\":").count(), pods / nodes, "{q}"),
            _ => panic!("list failed"),
        }
    });
    rate("list pods, labelSelector (100 hits)", 200, |i| {
        let q = format!("labelSelector=app%3Da{}", i % 50);
        let req = Req { method: "GET", path: "/api/v1/pods", query: &q, content_type: Some(c), accept: None, body: b"", user: user(), bearer: None, headers: &[], authz_verb: None };
        assert!(matches!(api.handle(&req), Reply::Json(200, _)));
    });
}

/// Requests authenticated with a ServiceAccount token (every pod's API client).
#[test]
#[ignore]
fn sa_token_requests() {
    let api = ApiServer::new(kr_store::Store::in_memory(), || 1_700_000_000, rng, "127.0.0.1".into()).unwrap();
    let key = kr_crypto::p256::SecretKey::from_bytes(&[7; 32]).unwrap();
    api.set_service_accounts(kr_apiserver::tokens::Signer::new(key), "CA".into()).unwrap();
    let c = "application/json";
    call(&api, "POST", "/api/v1/namespaces/default/pods", c, r#"{"metadata":{"name":"p"},"spec":{"containers":[{"name":"c","image":"x"}]}}"#);
    let admin = || Some(User { name: "admin".into(), groups: vec!["system:masters".into()] });
    let req = Req { method: "POST", path: "/api/v1/namespaces/default/serviceaccounts/default/token", query: "", content_type: Some(c), accept: None, body: br#"{"spec":{"audiences":["https://kubernetes.default.svc"]}}"#, user: admin(), bearer: None, headers: &[], authz_verb: None };
    let tok = match api.handle(&req) {
        Reply::Json(201, b) => kr_fmt::json::parse_str(&b).unwrap().pointer(&["status", "token"]).and_then(|t| t.as_str()).unwrap().to_string(),
        _ => panic!("token"),
    };
    rate("get pod with a ServiceAccount token", 2000, |_| {
        let req = Req { method: "GET", path: "/api/v1/namespaces/default/pods/p", query: "", content_type: Some(c), accept: None, body: b"", user: None, bearer: Some(&tok), headers: &[], authz_verb: None };
        // The default ServiceAccount has no RBAC for pods: authenticated, then 403 (authentication is the cost here).
        assert!(matches!(api.handle(&req), Reply::Json(403, _) | Reply::Json(200, _)));
    });
}
