//! Review APIs (TokenReview, SubjectAccessReview) and the extra built-in kinds through
//! `ApiServer::handle` (no transport).

use kr_apiserver::api::{ApiServer, Reply, Req, User};
use kr_fmt::json::{self, Value};

fn now() -> i64 {
    1_700_000_000
}

fn rng(b: &mut [u8]) {
    kr_sys::getrandom(b)
}

fn server() -> ApiServer {
    let api = ApiServer::new(kr_store::Store::in_memory(), now, rng, "127.0.0.1".into()).unwrap();
    let key = kr_crypto::p256::SecretKey::from_bytes(&[7; 32]).unwrap();
    api.set_service_accounts(kr_apiserver::tokens::Signer::new(key), "CA".into()).unwrap();
    api
}

fn call_as(api: &ApiServer, user: Option<User>, method: &str, path: &str, body: &str) -> (u16, Value) {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let req = Req { method, path, query, content_type: Some("application/json"), accept: None, body: body.as_bytes(), user, bearer: None, headers: &[], authz_verb: None };
    match api.handle(&req) {
        Reply::Json(c, b) => (c, json::parse(b.as_bytes()).unwrap_or(Value::Null)),
        _ => panic!("unexpected reply"),
    }
}

fn admin() -> Option<User> {
    Some(User { name: "admin".into(), groups: vec!["system:masters".into()] })
}

fn call(api: &ApiServer, method: &str, path: &str, body: &str) -> (u16, Value) {
    call_as(api, admin(), method, path, body)
}

#[test]
fn token_review_validates() {
    let api = server();
    assert_eq!(call(&api, "POST", "/api/v1/namespaces/default/serviceaccounts", r#"{"metadata":{"name":"bot"}}"#).0, 201);
    let (c, t) = call(&api, "POST", "/api/v1/namespaces/default/serviceaccounts/bot/token", r#"{"spec":{}}"#);
    assert_eq!(c, 201);
    let token = t.pointer(&["status", "token"]).and_then(Value::as_str).unwrap().to_string();
    let review = |tok: &str| call(&api, "POST", "/apis/authentication.k8s.io/v1/tokenreviews", &format!(r#"{{"spec":{{"token":"{tok}"}}}}"#));
    let (c, r) = review(&token);
    assert_eq!(c, 201);
    assert_eq!(r.pointer(&["status", "authenticated"]).and_then(Value::as_bool), Some(true));
    assert_eq!(r.pointer(&["status", "user", "username"]).and_then(Value::as_str), Some("system:serviceaccount:default:bot"));
    let jti = r.pointer(&["status", "user", "extra", "authentication.kubernetes.io/credential-id"]).and_then(Value::as_array).unwrap();
    assert!(jti[0].as_str().unwrap().starts_with("JTI="));
    // Tampered and foreign-audience tokens are rejected.
    let mut bad = token.clone();
    bad.push('x');
    assert_eq!(review(&bad).1.pointer(&["status", "authenticated"]).and_then(Value::as_bool), Some(false));
    let (_, r) = call(&api, "POST", "/apis/authentication.k8s.io/v1/tokenreviews", &format!(r#"{{"spec":{{"token":"{token}","audiences":["other"]}}}}"#));
    assert_eq!(r.pointer(&["status", "authenticated"]).and_then(Value::as_bool), Some(false));
    // Deleting the ServiceAccount revokes the token.
    assert_eq!(call(&api, "DELETE", "/api/v1/namespaces/default/serviceaccounts/bot", "").0, 200);
    assert_eq!(review(&token).1.pointer(&["status", "authenticated"]).and_then(Value::as_bool), Some(false));
    // Reviewing needs permission.
    let nobody = Some(User { name: "nobody".into(), groups: vec!["system:authenticated".into()] });
    assert_eq!(call_as(&api, nobody, "POST", "/apis/authentication.k8s.io/v1/tokenreviews", r#"{"spec":{"token":"x"}}"#).0, 403);
}

#[test]
fn subject_access_reviews() {
    let api = server();
    let sar = r#"{"spec":{"user":"nobody","resourceAttributes":{"verb":"list","resource":"configmaps","namespace":"default","version":"v1"}}}"#;
    let (c, r) = call(&api, "POST", "/apis/authorization.k8s.io/v1/subjectaccessreviews", sar);
    assert_eq!((c, r.pointer(&["status", "allowed"]).and_then(Value::as_bool)), (201, Some(false)));
    let admin_sar = r#"{"spec":{"user":"x","groups":["system:masters"],"resourceAttributes":{"verb":"list","resource":"configmaps"}}}"#;
    assert_eq!(call(&api, "POST", "/apis/authorization.k8s.io/v1/subjectaccessreviews", admin_sar).1.pointer(&["status", "allowed"]).and_then(Value::as_bool), Some(true));
    let (c, r) = call(&api, "POST", "/apis/authorization.k8s.io/v1/namespaces/default/localsubjectaccessreviews", admin_sar);
    assert_eq!((c, r.pointer(&["status", "allowed"]).and_then(Value::as_bool)), (201, Some(true)));
    assert_eq!(call(&api, "POST", "/apis/authorization.k8s.io/v1/subjectaccessreviews", r#"{"spec":{}}"#).0, 422);
}

#[test]
fn extra_kinds_crud() {
    let api = server();
    for (path, name, body) in [
        ("/apis/events.k8s.io/v1/namespaces/default/events", "e1", r#"{"metadata":{"name":"e1"},"eventTime":"2024-01-01T00:00:00.000000Z","reportingController":"c","reportingInstance":"i","action":"a","reason":"r","regarding":{"kind":"Pod","name":"p"},"type":"Normal"}"#),
        ("/apis/apiregistration.k8s.io/v1/apiservices", "v1.foo.example.com", r#"{"metadata":{"name":"v1.foo.example.com"},"spec":{"group":"foo.example.com","version":"v1","groupPriorityMinimum":100,"versionPriority":1}}"#),
        ("/apis/storagemigration.k8s.io/v1/storageversionmigrations", "m1", r#"{"metadata":{"name":"m1"},"spec":{"resource":{"group":"","resource":"secrets"}}}"#),
        ("/apis/resource.k8s.io/v1/devicetaintrules", "t1", r#"{"metadata":{"name":"t1"},"spec":{"taint":{"key":"k","effect":"NoSchedule"}}}"#),
        ("/apis/certificates.k8s.io/v1/namespaces/default/podcertificaterequests", "r1", r#"{"metadata":{"name":"r1"},"spec":{}}"#),
    ] {
        assert_eq!(call(&api, "POST", path, body).0, 201, "{path}");
        assert_eq!(call(&api, "GET", &format!("{path}/{name}"), "").0, 200, "{path}");
    }
    let (_, g) = call(&api, "GET", "/apis/apiregistration.k8s.io/v1", "");
    assert!(json::to_string(&g).contains("apiservices"));
}
