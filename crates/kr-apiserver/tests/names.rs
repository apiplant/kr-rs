//! metadata.name rules of kinds whose names are not DNS subdomains.

use kr_apiserver::api::{ApiServer, Reply, Req, User};
use kr_fmt::json::{self, Value};

fn now() -> i64 {
    1_700_000_000
}

fn rng(b: &mut [u8]) {
    kr_sys::getrandom(b)
}

fn server() -> ApiServer {
    ApiServer::new(kr_store::Store::in_memory(), now, rng, "127.0.0.1".into()).unwrap()
}

fn call(api: &ApiServer, method: &str, path: &str, ct: &str, body: &str) -> (u16, Value) {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let hdrs = [("User-Agent".to_string(), "kubectl/v1.30.0 (linux/amd64)".to_string())];
    let req = Req {
        method,
        path,
        query,
        content_type: Some(ct),
        accept: None,
        body: body.as_bytes(),
        user: Some(User { name: "admin".into(), groups: vec!["system:masters".into()] }),
        bearer: None,
        headers: &hdrs,
        authz_verb: None,
    };
    match api.handle(&req) {
        Reply::Json(c, b) => (c, json::parse(b.as_bytes()).unwrap_or(Value::Null)),
        _ => panic!("unexpected reply"),
    }
}


#[test]
fn path_segment_names() {
    let api = server();
    let ctb = r#"{"apiVersion":"certificates.k8s.io/v1","kind":"ClusterTrustBundle","metadata":{"name":"test.test:signer-one:0"},"spec":{"signerName":"test.test/signer-one","trustBundle":""}}"#;
    let (c, v) = call(&api, "POST", "/apis/certificates.k8s.io/v1/clustertrustbundles", "application/json", ctb);
    assert_eq!(c, 201, "{v:?}");
    for ip in ["192.168.2.5", "2001:db8::5"] {
        let body = format!(r#"{{"metadata":{{"name":"{ip}"}},"spec":{{"parentRef":{{"group":"","resource":"services","name":"s","namespace":"default"}}}}}}"#);
        let (c, v) = call(&api, "POST", "/apis/networking.k8s.io/v1/ipaddresses", "application/json", &body);
        assert_eq!(c, 201, "{ip}: {v:?}");
    }
    // Still rejected: "/" and ".." are never valid path segments.
    let (c, _) = call(&api, "POST", "/apis/networking.k8s.io/v1/ipaddresses", "application/json", r#"{"metadata":{"name":".."}}"#);
    assert_eq!(c, 422);
}
