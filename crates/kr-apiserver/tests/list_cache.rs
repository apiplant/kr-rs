//! Lists use cached parsed objects and byte pre-filters (#210): results must follow every change.
use kr_apiserver::api::{ApiServer, Reply, Req, User};
use kr_fmt::json::{self, Value};

fn rng(b: &mut [u8]) {
    kr_sys::getrandom(b)
}

fn call(api: &ApiServer, method: &str, path: &str, query: &str, ct: &str, accept: Option<&str>, body: &str) -> (u16, Value) {
    let user = Some(User { name: "admin".into(), groups: vec!["system:masters".into()] });
    let req = Req { method, path, query, content_type: Some(ct), accept, body: body.as_bytes(), user, bearer: None, headers: &[], authz_verb: None };
    match api.handle(&req) {
        Reply::Json(c, b) => (c, json::parse(b.as_bytes()).unwrap_or(Value::Null)),
        _ => panic!("unexpected reply"),
    }
}

fn names(v: &Value) -> Vec<String> {
    v.get("items").and_then(Value::as_array).unwrap().iter().map(|i| i.pointer(&["metadata", "name"]).and_then(Value::as_str).unwrap().to_string()).collect()
}

#[test]
fn selectors_tables_and_discovery_follow_changes() {
    let api = ApiServer::new(kr_store::Store::in_memory(), || 1_700_000_000, rng, "127.0.0.1".into()).unwrap();
    let j = "application/json";
    let list = |q: &str| names(&call(&api, "GET", "/api/v1/namespaces/default/pods", q, j, None, "").1);
    for (n, app, node) in [("a1", "a", "n1"), ("a2", "a", "n2"), ("b1", "b", "n1")] {
        let pod = format!(r#"{{"metadata":{{"name":"{n}","labels":{{"app":"{app}"}}}},"spec":{{"nodeName":"{node}","containers":[{{"name":"c","image":"x"}}]}}}}"#);
        assert_eq!(call(&api, "POST", "/api/v1/namespaces/default/pods", "", j, None, &pod).0, 201);
    }
    assert_eq!(list("labelSelector=app%3Da"), ["a1", "a2"]);
    assert_eq!(list("fieldSelector=spec.nodeName%3Dn1"), ["a1", "b1"]);
    assert_eq!(list("labelSelector=app%20in%20(a,b)&fieldSelector=spec.nodeName%3Dn2"), ["a2"]);
    assert_eq!(list("labelSelector=app%3Dzzz"), Vec::<String>::new());
    // A label change is visible at once (the cached parse is keyed by revision).
    assert_eq!(call(&api, "PATCH", "/api/v1/namespaces/default/pods/a1", "", "application/merge-patch+json", None, r#"{"metadata":{"labels":{"app":"b"}}}"#).0, 200);
    assert_eq!(list("labelSelector=app%3Da"), ["a2"]);
    assert_eq!(list("labelSelector=app%3Db"), ["a1", "b1"]);
    assert_eq!(call(&api, "DELETE", "/api/v1/namespaces/default/pods/a2", "", j, None, "").0, 200);
    // Table rows name every item, and a renamed-by-recreate object is not served from the old parse.
    let (_, t) = call(&api, "GET", "/api/v1/namespaces/default/pods", "", j, Some("application/json;as=Table;g=meta.k8s.io;v=v1"), "");
    let rows = t.get("rows").and_then(Value::as_array).unwrap();
    assert!(rows.iter().any(|r| r.pointer(&["cells"]).and_then(Value::as_array).and_then(|c| c.first()).and_then(Value::as_str) == Some("b1")));
    assert_eq!(t.get("kind").and_then(Value::as_str), Some("Table"));
    assert!(t.get("columnDefinitions").and_then(Value::as_array).is_some());
    assert!(rows[0].pointer(&["object", "metadata", "name"]).is_some());
    // Discovery follows a new CRD.
    let (_, before) = call(&api, "GET", "/apis", "", j, None, "");
    let crd = r#"{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"foos.cache.example.com"},"spec":{"group":"cache.example.com","scope":"Namespaced","names":{"plural":"foos","singular":"foo","kind":"Foo"},"versions":[{"name":"v1","served":true,"storage":true,"schema":{"openAPIV3Schema":{"type":"object","x-kubernetes-preserve-unknown-fields":true}}}]}}"#;
    assert_eq!(call(&api, "POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", "", j, None, crd).0, 201);
    let (_, after) = call(&api, "GET", "/apis", "", j, None, "");
    assert!(!json::to_string(&before).contains("cache.example.com"));
    assert!(json::to_string(&after).contains("cache.example.com"), "cached /apis must be refreshed by the CRD");
}
