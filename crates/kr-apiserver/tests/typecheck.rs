//! JSON type checking of built-in kinds through `ApiServer::handle` (no transport).

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

const PODS: &str = "/api/v1/namespaces/default/pods";
const JSON: &str = "application/json";

fn msg(v: &Value) -> String {
    v.get("message").and_then(Value::as_str).unwrap_or("").to_string()
}

#[test]
fn wrong_types_are_rejected_on_create() {
    let api = server();
    let (c, v) = call(&api, "POST", &format!("{PODS}?fieldValidation=Ignore"), JSON, r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"a"},"spec":{"containers":"x"}}"#);
    assert_eq!(c, 400, "{v:?}");
    let m = msg(&v);
    assert!(m.contains(r#"Pod in version "v1" cannot be handled as a Pod: json: cannot unmarshal string into Go struct field Pod.spec.containers"#), "{m}");
    let (c, _) = call(&api, "POST", PODS, JSON, r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"a","labels":{"k":1}},"spec":{"containers":[{"name":"c","image":"i"}]}}"#);
    assert_eq!(c, 400);
    let (c, v) = call(&api, "POST", PODS, JSON, r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"a"},"spec":{"containers":[{"name":"c","image":"i","ports":[{"containerPort":4294967296}]}]}}"#);
    assert_eq!(c, 400, "{v:?}");
    let (c, v) = call(&api, "POST", PODS, JSON, r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"a"},"spec":{"nodeSelector":null,"containers":[{"name":"c","image":"i","resources":{"limits":{"cpu":1}}}]}}"#);
    assert_eq!(c, 201, "{v:?}");
}

#[test]
fn patch_producing_wrong_type_is_rejected() {
    let api = server();
    let (c, v) = call(&api, "POST", PODS, JSON, r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"a"},"spec":{"containers":[{"name":"c","image":"i"}]}}"#);
    assert_eq!(c, 201, "{v:?}");
    let (c, v) = call(&api, "PATCH", &format!("{PODS}/a"), "application/merge-patch+json", r#"{"metadata":{"labels":"x"}}"#);
    assert_eq!(c, 400, "{v:?}");
    assert!(msg(&v).contains("cannot be handled as a Pod"), "{v:?}");
}

#[test]
fn new_pv_status_is_reset_to_pending() {
    let api = server();
    let (c, v) = call(&api, "POST", "/api/v1/persistentvolumes", JSON, r#"{"apiVersion":"v1","kind":"PersistentVolume","metadata":{"name":"pv"},"spec":{"capacity":{"storage":"1Gi"},"accessModes":["ReadWriteOnce"],"hostPath":{"path":"/x"}},"status":{"phase":"Available"}}"#);
    assert_eq!(c, 201, "{v:?}");
    assert_eq!(v.pointer(&["status", "phase"]).and_then(Value::as_str), Some("Pending"));
}
