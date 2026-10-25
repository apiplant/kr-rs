//! Pod `metadata.generation` through `ApiServer::handle` (no transport).

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
fn pod_generation() {
    let api = server();
    let pods = "/api/v1/namespaces/default/pods";
    let body = r#"{"metadata":{"name":"p","generation":100},"spec":{"containers":[{"name":"c","image":"i"}]}}"#;
    let (c, p) = call(&api, "POST", pods, "application/json", body);
    assert_eq!(c, 201);
    assert_eq!(p.pointer(&["metadata", "generation"]).and_then(Value::as_i64), Some(1));
    // An unchanged object written back (with a client-chosen generation) is not a spec change.
    let same = json::to_string(&p).replace(r#""generation":1"#, r#""generation":5"#);
    let (c, p) = call(&api, "PUT", &format!("{pods}/p"), "application/json", &same);
    assert_eq!(c, 200);
    assert_eq!(p.pointer(&["metadata", "generation"]).and_then(Value::as_i64), Some(1));
    let changed = same.replace(r#""image":"i""#, r#""image":"j""#);
    let (_, p) = call(&api, "PUT", &format!("{pods}/p"), "application/json", &changed);
    assert_eq!(p.pointer(&["metadata", "generation"]).and_then(Value::as_i64), Some(2));
    // A graceful delete of a bound pod bumps the generation.
    let bind = r#"{"apiVersion":"v1","kind":"Binding","metadata":{"name":"p"},"target":{"name":"n1"}}"#;
    assert_eq!(call(&api, "POST", &format!("{pods}/p/binding"), "application/json", bind).0, 201);
    let (c, _) = call(&api, "DELETE", &format!("{pods}/p?gracePeriodSeconds=60"), "", "");
    assert_eq!(c, 200);
    let (_, p) = call(&api, "GET", &format!("{pods}/p"), "", "");
    assert_eq!(p.pointer(&["metadata", "generation"]).and_then(Value::as_i64), Some(3));
}
