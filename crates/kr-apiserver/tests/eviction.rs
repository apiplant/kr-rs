//! `pods/eviction` against PodDisruptionBudgets through `ApiServer::handle` (no transport).

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
fn eviction_respects_budgets() {
    let api = server();
    let pods = "/api/v1/namespaces/default/pods";
    let pdbs = "/apis/policy/v1/namespaces/default/poddisruptionbudgets";
    let mk = |n: &str, l: &str| format!(r#"{{"metadata":{{"name":"{n}","labels":{{"app":"{l}"}}}},"spec":{{"containers":[{{"name":"c","image":"i"}}]}}}}"#);
    for (n, l) in [("p1", "a"), ("p2", "a"), ("free", "b"), ("multi", "m")] {
        assert_eq!(call(&api, "POST", pods, "application/json", &mk(n, l)).0, 201);
    }
    let ev = |n: &str| format!(r#"{{"apiVersion":"policy/v1","kind":"Eviction","metadata":{{"name":"{n}"}}}}"#);
    let post = |n: &str, body: &str| call(&api, "POST", &format!("{pods}/{n}/eviction"), "application/json", body);
    // Name mismatch and unknown pod.
    assert_eq!(post("p1", &ev("other")).0, 400);
    assert_eq!(post("nope", &ev("nope")).0, 404);
    // No budget: deleted, 201 Status.
    let (c, s) = post("free", &ev("free"));
    assert_eq!((c, s.get("status").and_then(Value::as_str)), (201, Some("Success")));
    assert_eq!(call(&api, "GET", &format!("{pods}/free"), "", "").0, 404);
    // One budget with no allowance yet: 429 with a cause.
    let pdb = r#"{"metadata":{"name":"pdb"},"spec":{"minAvailable":1,"selector":{"matchLabels":{"app":"a"}}}}"#;
    assert_eq!(call(&api, "POST", pdbs, "application/json", pdb).0, 201);
    let (c, s) = post("p1", &ev("p1"));
    assert_eq!(c, 429);
    assert_eq!(s.get("reason").and_then(Value::as_str), Some("TooManyRequests"));
    assert_eq!(s.pointer(&["details", "causes"]).and_then(Value::as_array).unwrap()[0].get("reason").and_then(Value::as_str), Some("DisruptionBudget"));
    // The controller's numbers: one eviction allowed, then none.
    let st = r#"{"status":{"observedGeneration":1,"disruptionsAllowed":1,"currentHealthy":2,"desiredHealthy":1,"expectedPods":2}}"#;
    assert_eq!(call(&api, "PATCH", &format!("{pdbs}/pdb/status"), "application/merge-patch+json", st).0, 200);
    assert_eq!(post("p1", &ev("p1")).0, 201);
    let (_, b) = call(&api, "GET", &format!("{pdbs}/pdb"), "", "");
    assert_eq!(b.pointer(&["status", "disruptionsAllowed"]).and_then(Value::as_i64), Some(0));
    assert!(b.pointer(&["status", "disruptedPods", "p1"]).is_some());
    assert_eq!(post("p2", &ev("p2")).0, 429);
    // Two budgets on one pod.
    let m = r#"{"metadata":{"name":"m1"},"spec":{"minAvailable":0,"selector":{"matchLabels":{"app":"m"}}}}"#;
    call(&api, "POST", pdbs, "application/json", m);
    call(&api, "POST", pdbs, "application/json", &m.replace("m1", "m2"));
    assert_eq!(post("multi", &ev("multi")).0, 500);
}
