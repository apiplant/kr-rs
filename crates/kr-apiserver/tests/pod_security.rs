//! Pod Security admission: namespace levels, pod denials, template warnings, label validation.

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

fn call(api: &ApiServer, method: &str, path: &str, body: &str) -> (u16, Value, Vec<String>) {
    let hdrs = [("User-Agent".to_string(), "kubectl/v1.37.0 (linux/amd64)".to_string())];
    let req = Req { method, path, query: "", content_type: Some("application/json"), accept: None, body: body.as_bytes(), user: Some(User { name: "admin".into(), groups: vec!["system:masters".into()] }), bearer: None, headers: &hdrs, authz_verb: None };
    match api.handle_w(&req) {
        (Reply::Json(c, b), w) => (c, json::parse(b.as_bytes()).unwrap_or(Value::Null), w),
        _ => panic!("unexpected reply"),
    }
}

const HOSTNET: &str = r#"{"metadata":{"name":"h"},"spec":{"hostNetwork":true,"containers":[{"name":"c","image":"i"}]}}"#;

#[test]
fn namespace_levels_are_enforced() {
    let api = server();
    let mk = |name: &str, labels: &str| format!(r#"{{"metadata":{{"name":"{name}","labels":{labels}}}}}"#);
    assert_eq!(call(&api, "POST", "/api/v1/namespaces", &mk("base", r#"{"pod-security.kubernetes.io/enforce":"baseline"}"#)).0, 201);
    assert_eq!(call(&api, "POST", "/api/v1/namespaces", &mk("open", "{}")).0, 201);
    assert_eq!(call(&api, "POST", "/api/v1/namespaces", &mk("warned", r#"{"pod-security.kubernetes.io/warn":"restricted"}"#)).0, 201);
    let (c, v, _) = call(&api, "POST", "/api/v1/namespaces", &mk("bad", r#"{"pod-security.kubernetes.io/enforce":"strict"}"#));
    assert_eq!(c, 422, "{v:?}");

    let (c, v, _) = call(&api, "POST", "/api/v1/namespaces/base/pods", HOSTNET);
    assert_eq!(c, 403);
    assert_eq!(v.get("message").and_then(Value::as_str), Some("pods \"h\" is forbidden: violates PodSecurity \"baseline:latest\": host namespaces (hostNetwork=true)"));
    assert_eq!(call(&api, "POST", "/api/v1/namespaces/open/pods", HOSTNET).0, 201, "unlabelled namespaces are privileged");
    let (c, _, w) = call(&api, "POST", "/api/v1/namespaces/warned/pods", HOSTNET);
    assert_eq!(c, 201);
    assert!(w.iter().any(|w| w.starts_with("would violate PodSecurity \"restricted:latest\": host namespaces (hostNetwork=true)")), "{w:?}");

    // Workloads only warn; their pods are what gets rejected.
    let dep = r#"{"metadata":{"name":"d"},"spec":{"selector":{"matchLabels":{"a":"b"}},"template":{"metadata":{"labels":{"a":"b"}},"spec":{"hostNetwork":true,"containers":[{"name":"c","image":"i"}]}}}}"#;
    let (c, _, w) = call(&api, "POST", "/apis/apps/v1/namespaces/base/deployments", dep);
    assert_eq!(c, 201);
    assert!(w.iter().any(|w| w.contains("baseline:latest") && w.contains("hostNetwork=true")), "{w:?}");

    // Relabelling a namespace to an invalid level is rejected too.
    let (_, mut ns, _) = call(&api, "GET", "/api/v1/namespaces/open", "");
    ns.entry_object("metadata").entry_object("labels").set("pod-security.kubernetes.io/warn", Value::from("nope"));
    let upd = json::to_string(&ns);
    let (c, v, _) = call(&api, "PUT", "/api/v1/namespaces/open", &upd);
    assert_eq!(c, 422, "{v:?} {upd}");
}
