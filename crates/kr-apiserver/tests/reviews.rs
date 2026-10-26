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

#[test]
fn immutable_and_status_metadata() {
    let api = server();
    let cms = "/api/v1/namespaces/default/configmaps";
    assert_eq!(call(&api, "POST", cms, r#"{"metadata":{"name":"c"},"data":{"a":"1"},"immutable":true}"#).0, 201);
    assert_eq!(call(&api, "PUT", &format!("{cms}/c"), r#"{"metadata":{"name":"c"},"data":{"a":"2"},"immutable":true}"#).0, 422);
    assert_eq!(call(&api, "PUT", &format!("{cms}/c"), r#"{"metadata":{"name":"c"},"data":{"a":"1"}}"#).0, 422);
    assert_eq!(call(&api, "POST", "/api/v1/namespaces/default/secrets", r#"{"metadata":{"name":"s"},"data":{"":"dg=="}}"#).0, 422);
    let pc = "/apis/scheduling.k8s.io/v1/priorityclasses";
    assert_eq!(call(&api, "POST", pc, r#"{"metadata":{"name":"p"},"value":10}"#).0, 201);
    assert_eq!(call(&api, "PUT", &format!("{pc}/p"), r#"{"metadata":{"name":"p"},"value":11}"#).0, 422);
    // Annotations travel through /status.
    assert_eq!(call(&api, "POST", "/api/v1/namespaces", r#"{"metadata":{"name":"nsx"}}"#).0, 201);
    let (c, o) = call(&api, "PUT", "/api/v1/namespaces/nsx/status", r#"{"metadata":{"name":"nsx","annotations":{"k":"v"}},"status":{"phase":"Active"}}"#);
    assert_eq!(c, 200);
    assert_eq!(o.pointer(&["metadata", "annotations", "k"]).and_then(Value::as_str), Some("v"));
}

#[test]
fn root_ca_republished_and_chunking() {
    let api = server();
    assert_eq!(call(&api, "POST", "/api/v1/namespaces", r#"{"metadata":{"name":"nsy"}}"#).0, 201);
    let cm = "/api/v1/namespaces/nsy/configmaps/kube-root-ca.crt";
    assert_eq!(call(&api, "DELETE", cm, "").0, 200);
    assert_eq!(call(&api, "GET", cm, "").0, 200);
    assert_eq!(call(&api, "PUT", cm, r#"{"metadata":{"name":"kube-root-ca.crt"},"data":{"ca.crt":""}}"#).0, 200);
    let (_, o) = call(&api, "GET", cm, "");
    assert_eq!(o.pointer(&["data", "ca.crt"]).and_then(Value::as_str), Some("CA"));
    // Paging keeps the first page's resourceVersion and reports what remains.
    for i in 0..5 {
        assert_eq!(call(&api, "POST", "/api/v1/namespaces/nsy/configmaps", &format!(r#"{{"metadata":{{"name":"c{i}"}}}}"#)).0, 201);
    }
    let (_, p1) = call(&api, "GET", "/api/v1/namespaces/nsy/configmaps?limit=2", "");
    let rv = p1.pointer(&["metadata", "resourceVersion"]).and_then(Value::as_str).unwrap().to_string();
    assert_eq!(p1.pointer(&["metadata", "remainingItemCount"]).and_then(Value::as_u64), Some(4));
    assert_eq!(call(&api, "POST", "/api/v1/namespaces/nsy/configmaps", r#"{"metadata":{"name":"zz"}}"#).0, 201);
    let tok = p1.pointer(&["metadata", "continue"]).and_then(Value::as_str).unwrap().to_string();
    let (_, p2) = call(&api, "GET", &format!("/api/v1/namespaces/nsy/configmaps?limit=2&continue={tok}"), "");
    assert_eq!(p2.pointer(&["metadata", "resourceVersion"]).and_then(Value::as_str), Some(rv.as_str()));
}

#[test]
fn review_has_no_table() {
    let api = server();
    let req = Req { method: "POST", path: "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", query: "", content_type: Some("application/json"), accept: Some("application/json;as=Table;v=v1;g=meta.k8s.io"), body: br#"{"spec":{"nonResourceAttributes":{"path":"/","verb":"get"}}}"#, user: admin(), bearer: None, headers: &[], authz_verb: None };
    match api.handle(&req) {
        Reply::Json(c, _) => assert_eq!(c, 406),
        _ => panic!(),
    }
}

/// The review APIs disclose authorization decisions and token validity: callers need RBAC
/// permission, like upstream (`create` on the review resource).
#[test]
fn reviews_need_permission() {
    let api = server();
    let nobody = || Some(User { name: "nobody".into(), groups: vec!["system:authenticated".into()] });
    let sar = r#"{"spec":{"user":"x","resourceAttributes":{"verb":"list","resource":"secrets"}}}"#;
    assert_eq!(call_as(&api, nobody(), "POST", "/apis/authorization.k8s.io/v1/subjectaccessreviews", sar).0, 403);
    assert_eq!(call_as(&api, nobody(), "POST", "/apis/authorization.k8s.io/v1/namespaces/default/localsubjectaccessreviews", sar).0, 403);
    assert_eq!(call_as(&api, None, "POST", "/apis/authentication.k8s.io/v1/tokenreviews", r#"{"spec":{"token":"x"}}"#).0 / 100, 4);
}

#[test]
fn reviews_are_discoverable_create_only() {
    let api = server();
    for (path, plural) in [("/apis/authentication.k8s.io/v1", "tokenreviews"), ("/apis/authentication.k8s.io/v1", "selfsubjectreviews"), ("/apis/authorization.k8s.io/v1", "subjectaccessreviews")] {
        let (c, d) = call(&api, "GET", path, "");
        assert_eq!(c, 200, "{path}");
        let res = d.get("resources").and_then(Value::as_array).unwrap();
        let r = res.iter().find(|r| r.get("name").and_then(Value::as_str) == Some(plural)).unwrap_or_else(|| panic!("{plural} not advertised"));
        assert_eq!(r.get("verbs").and_then(Value::as_array).map(|v| v.len()), Some(1));
    }
    assert!(json::to_string(&call(&api, "GET", "/apis", "").1).contains("authentication.k8s.io"));
}

#[test]
fn impersonation_and_self_subject_review() {
    let api = server();
    let headers = [("Impersonate-User".to_string(), "system:serviceaccount:default:e2e".to_string())];
    let as_imp = |user: Option<User>, hdrs: &[(String, String)], method: &str, path: &str, body: &str| {
        let req = Req { method, path, query: "", content_type: Some("application/json"), accept: None, body: body.as_bytes(), user, bearer: None, headers: hdrs, authz_verb: None };
        match api.handle(&req) {
            Reply::Json(c, b) => (c, json::parse(b.as_bytes()).unwrap_or(Value::Null)),
            _ => panic!("unexpected reply"),
        }
    };
    let who = "/apis/authentication.k8s.io/v1/selfsubjectreviews";
    let (c, r) = as_imp(admin(), &headers, "POST", who, "{}");
    assert_eq!(c, 201);
    assert_eq!(r.pointer(&["status", "userInfo", "username"]).and_then(Value::as_str), Some("system:serviceaccount:default:e2e"));
    // The impersonated identity is authorized as itself: it cannot list configmaps.
    assert_eq!(as_imp(admin(), &headers, "GET", "/api/v1/namespaces/default/configmaps", "").0, 403);
    // A caller without the impersonate verb is refused.
    let nobody = Some(User { name: "nobody".into(), groups: vec!["system:authenticated".into()] });
    assert_eq!(as_imp(nobody, &headers, "POST", who, "{}").0, 403);
}

#[test]
fn self_subject_rules_review() {
    let api = server();
    let review = |u: Option<User>| call_as(&api, u, "POST", "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", r#"{"spec":{"namespace":"default"}}"#);
    let (c, r) = review(admin());
    assert_eq!(c, 201);
    assert!(json::to_string(&r).contains(r#""resources":["*"]"#));
    // A user bound to the view role by a RoleBinding gets its rules, only in that namespace.
    assert_eq!(call(&api, "POST", "/apis/rbac.authorization.k8s.io/v1/namespaces/default/rolebindings", r#"{"metadata":{"name":"b"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"view"},"subjects":[{"kind":"User","name":"bob"}]}"#).0, 201);
    let bob = Some(User { name: "bob".into(), groups: vec!["system:authenticated".into()] });
    let (_, r) = review(bob.clone());
    let rules = r.pointer(&["status", "resourceRules"]).and_then(Value::as_array).unwrap();
    assert!(rules.iter().any(|x| json::to_string(x).contains("configmaps")));
    let (_, other) = call_as(&api, bob, "POST", "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", r#"{"spec":{"namespace":"kube-system"}}"#);
    assert!(!json::to_string(&other).contains("configmaps"));
}
