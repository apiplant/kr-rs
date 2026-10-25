//! Pod admission (sysctls, RuntimeClass, LimitRange) through `ApiServer::handle` (no transport).

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
fn pod_admission_plugins() {
    let api = server();
    let ns = "/api/v1/namespaces/default";
    let pods = format!("{ns}/pods");
    let c = r#""containers":[{"name":"c","image":"i"}]"#;
    // Sysctls: invalid names are 422, naming only the bad ones.
    let body = format!(r#"{{"metadata":{{"name":"s"}},"spec":{{"securityContext":{{"sysctls":[{{"name":"foo-","value":"1"}},{{"name":"kernel.shmmax","value":"1"}}]}},{c}}}}}"#);
    let (code, st) = call(&api, "POST", &pods, "application/json", &body);
    let msg = st.get("message").and_then(Value::as_str).unwrap();
    assert!(code == 422 && msg.contains(r#"Invalid value: "foo-""#) && !msg.contains("shmmax"), "{code} {msg}");
    // RuntimeClass: missing is 403, existing copies its overhead.
    let rcp = format!(r#"{{"metadata":{{"name":"p"}},"spec":{{"runtimeClassName":"rc",{c}}}}}"#);
    let (code, st) = call(&api, "POST", &pods, "application/json", &rcp);
    assert_eq!(code, 403);
    assert!(st.get("message").and_then(Value::as_str).unwrap().contains(r#"pod rejected: RuntimeClass "rc" not found"#));
    let rc = r#"{"metadata":{"name":"rc"},"handler":"h","overhead":{"podFixed":{"cpu":"10m"}}}"#;
    assert_eq!(call(&api, "POST", "/apis/node.k8s.io/v1/runtimeclasses", "application/json", rc).0, 201);
    let (code, p) = call(&api, "POST", &pods, "application/json", &rcp);
    assert_eq!(code, 201);
    assert_eq!(p.pointer(&["spec", "overhead", "cpu"]).and_then(Value::as_str), Some("10m"));
    // LimitRange: defaults applied, bounds enforced.
    let lr = r#"{"metadata":{"name":"lr"},"spec":{"limits":[{"type":"Container","max":{"cpu":"500m"},"default":{"cpu":"400m","memory":"500Mi"},"defaultRequest":{"memory":"200Mi"}}]}}"#;
    assert_eq!(call(&api, "POST", &format!("{ns}/limitranges"), "application/json", lr).0, 201);
    let (code, p) = call(&api, "POST", &pods, "application/json", &format!(r#"{{"metadata":{{"name":"d"}},"spec":{{{c}}}}}"#));
    assert_eq!(code, 201);
    let res = p.pointer(&["spec", "containers"]).and_then(Value::as_array).unwrap()[0].get("resources").unwrap();
    assert_eq!(res.pointer(&["requests", "memory"]).and_then(Value::as_str), Some("200Mi"));
    assert_eq!(res.pointer(&["limits", "memory"]).and_then(Value::as_str), Some("500Mi"));
    let big = r#"{"metadata":{"name":"b"},"spec":{"containers":[{"name":"c","image":"i","resources":{"limits":{"cpu":"600m"}}}]}}"#;
    assert_eq!(call(&api, "POST", &pods, "application/json", big).0, 403);
}

/// Critical priority classes outrank every workload: outside kube-system they need a quota that
/// explicitly covers them (upstream's default limitedResources).
#[test]
fn critical_priority_is_limited() {
    let api = server();
    // Created by the bootstrap policy in a real server (not enabled in this harness).
    let pc = r#"{"apiVersion":"scheduling.k8s.io/v1","kind":"PriorityClass","metadata":{"name":"system-node-critical"},"value":2000001000}"#;
    assert_eq!(call(&api, "POST", "/apis/scheduling.k8s.io/v1/priorityclasses", "application/json", pc).0, 201);
    let pod = |ns: &str| format!(r#"{{"metadata":{{"name":"p","namespace":"{ns}"}},"spec":{{"priorityClassName":"system-node-critical","containers":[{{"name":"c","image":"i"}}]}}}}"#);
    let (c, v) = call(&api, "POST", "/api/v1/namespaces/default/pods", "application/json", &pod("default"));
    assert_eq!(c, 403, "{v:?}");
    assert!(v.get("message").and_then(Value::as_str).unwrap().contains("insufficient quota"), "{v:?}");
    let (c, v) = call(&api, "POST", "/api/v1/namespaces/kube-system/pods", "application/json", &pod("kube-system"));
    assert_eq!(c, 201, "{v:?}");
    let q = r#"{"metadata":{"name":"crit"},"spec":{"hard":{"pods":"10"},"scopeSelector":{"matchExpressions":[{"scopeName":"PriorityClass","operator":"In","values":["system-node-critical"]}]}}}"#;
    assert_eq!(call(&api, "POST", "/api/v1/namespaces/default/resourcequotas", "application/json", q).0, 201);
    let (c, v) = call(&api, "POST", "/api/v1/namespaces/default/pods", "application/json", &pod("default"));
    assert_eq!(c, 201, "{v:?}");
    assert_eq!(v.pointer(&["spec", "priority"]).and_then(Value::as_i64), Some(2_000_001_000));
}
