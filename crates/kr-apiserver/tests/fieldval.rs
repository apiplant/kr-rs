//! `fieldValidation` through `ApiServer::handle`.

use kr_apiserver::api::{ApiServer, Reply, Req, User};
use kr_fmt::json::{self, Value};

fn rng(b: &mut [u8]) {
    kr_sys::getrandom(b)
}

fn server() -> ApiServer {
    ApiServer::new(kr_store::Store::in_memory(), || 1_700_000_000, rng, "127.0.0.1".into()).unwrap()
}

fn call(api: &ApiServer, method: &str, path: &str, ct: &str, body: &str) -> (u16, Value, Vec<String>) {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let req = Req {
        method,
        path,
        query,
        content_type: Some(ct),
        accept: None,
        body: body.as_bytes(),
        user: Some(User { name: "admin".into(), groups: vec!["system:masters".into()] }),
        bearer: None,
        headers: &[],
        authz_verb: None,
    };
    match api.handle(&req) {
        Reply::Json(c, b) => (c, json::parse(b.as_bytes()).unwrap_or(Value::Null), vec![]),
        Reply::Http(r) => {
            let w = r.headers.iter().filter(|(k, _)| k == "Warning").map(|(_, v)| v.clone()).collect();
            let kr_net::http1::server::Body::Full(body) = r.body else { panic!("streamed") };
            (r.status, json::parse(&body).unwrap_or(Value::Null), w)
        }
        _ => panic!("unexpected reply"),
    }
}

const POD: &str = r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p","labelz":{"a":"b"}},"spec":{"containers":[{"name":"c","image":"i","imagee":"x"}]}}"#;
const PODS: &str = "/api/v1/namespaces/default/pods";

fn post(api: &ApiServer, q: &str, body: &str) -> (u16, Value, Vec<String>) {
    call(api, "POST", &format!("{PODS}{q}"), "application/json", body)
}

#[test]
fn strict_rejects() {
    let api = server();
    let (c, v, _) = post(&api, "?fieldValidation=Strict", POD);
    assert_eq!(c, 400);
    assert_eq!(v.get("message").and_then(Value::as_str), Some(r#"strict decoding error: unknown field "metadata.labelz", unknown field "spec.containers[0].imagee""#));
    assert_eq!(call(&api, "GET", &format!("{PODS}/p"), "", "").0, 404);
}

#[test]
fn warn_is_default() {
    for q in ["", "?fieldValidation=Warn"] {
        let api = server();
        let (c, _, w) = post(&api, q, POD);
        assert_eq!(c, 201);
        assert_eq!(w, [r#"299 - "unknown field \"metadata.labelz\"""#, r#"299 - "unknown field \"spec.containers[0].imagee\"""#]);
    }
}

#[test]
fn ignore_is_silent() {
    let api = server();
    let (c, _, w) = post(&api, "?fieldValidation=Ignore", POD);
    assert_eq!(c, 201);
    assert!(w.is_empty());
}

#[test]
fn dry_run_and_put_and_patch() {
    let api = server();
    let (c, _, w) = post(&api, "?fieldValidation=Warn&dryRun=All", POD);
    assert_eq!((c, w.len()), (201, 2));
    let good = r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p"},"spec":{"containers":[{"name":"c","image":"i"}]}}"#;
    assert_eq!(post(&api, "?fieldValidation=Strict", good).0, 201);
    let p = format!("{PODS}/p");
    let (c, _, _) = call(&api, "PATCH", &format!("{p}?fieldValidation=Strict"), "application/merge-patch+json", r#"{"spec":{"bogus":1}}"#);
    assert_eq!(c, 400);
    let (c, _, w) = call(&api, "PATCH", &format!("{p}?fieldValidation=Warn"), "application/merge-patch+json", r#"{"spec":{"bogus":1}}"#);
    assert_eq!((c, w), (200, vec![r#"299 - "unknown field \"spec.bogus\"""#.to_string()]));
    let (c, v, _) = call(&api, "PUT", &format!("{p}?fieldValidation=Strict"), "application/json", good);
    assert_eq!(c, 200, "{}", json::to_string(&v));
}

#[test]
fn duplicates() {
    let dup = r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p","name":"q"},"spec":{"containers":[{"name":"c","image":"i"}]}}"#;
    let api = server();
    let (c, v, _) = post(&api, "?fieldValidation=Strict", dup);
    assert_eq!(c, 400);
    assert_eq!(v.get("message").and_then(Value::as_str), Some(r#"strict decoding error: duplicate field "metadata.name""#));
    let (c, _, w) = post(&api, "?fieldValidation=Warn", dup);
    assert_eq!((c, w), (201, vec![r#"299 - "duplicate field \"metadata.name\"""#.to_string()]));
    assert_eq!(post(&api, "?fieldValidation=Ignore", &dup.replace("\"q\"", "\"r\"")).0, 201);
}

#[test]
fn custom_resources() {
    let api = server();
    let crd = r#"{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"widgets.example.com"},
"spec":{"group":"example.com","scope":"Namespaced","names":{"plural":"widgets","kind":"Widget"},
"versions":[{"name":"v1","served":true,"storage":true,"schema":{"openAPIV3Schema":{"type":"object","properties":{
"spec":{"type":"object","properties":{"size":{"type":"integer"},"free":{"type":"object","x-kubernetes-preserve-unknown-fields":true}}}}}}}]}}"#;
    assert_eq!(call(&api, "POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", "application/json", crd).0, 201);
    let w = r#"{"apiVersion":"example.com/v1","kind":"Widget","metadata":{"name":"w"},"spec":{"size":1,"extra":2,"free":{"any":1}}}"#;
    let path = "/apis/example.com/v1/namespaces/default/widgets";
    let (c, v, _) = call(&api, "POST", &format!("{path}?fieldValidation=Strict"), "application/json", w);
    assert_eq!(c, 400);
    assert_eq!(v.get("message").and_then(Value::as_str), Some(r#"strict decoding error: unknown field "spec.extra""#));
    let (c, _, ws) = call(&api, "POST", &format!("{path}?fieldValidation=Warn"), "application/json", w);
    assert_eq!((c, ws), (201, vec![r#"299 - "unknown field \"spec.extra\"""#.to_string()]));
    let ok = w.replace("\"w\"", "\"x\"").replace("\"extra\":2,", "");
    assert_eq!(call(&api, "POST", &format!("{path}?fieldValidation=Strict"), "application/json", &ok).0, 201);
}
