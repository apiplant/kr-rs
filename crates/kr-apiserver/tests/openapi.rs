//! OpenAPI v2 definitions and v3 component schemas of custom resources.

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


const CRD: &str = r#"{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"foos.test.example.com"},
 "spec":{"group":"test.example.com","scope":"Namespaced","names":{"plural":"foos","singular":"foo","kind":"Foo","listKind":"FooList"},
 "versions":[{"name":"v1","served":true,"storage":true,"schema":{"openAPIV3Schema":{"description":"Foo CRD","type":"object","properties":{"spec":{"type":"object","description":"Spec"}}}}},
             {"name":"v2","served":false,"storage":false,"schema":{"openAPIV3Schema":{"type":"object"}}}]}}"#;

#[test]
fn crd_schemas_are_published() {
    let api = server();
    assert_eq!(call(&api, "POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", "application/json", CRD).0, 201);
    let (c, v2) = call(&api, "GET", "/openapi/v2", "", "");
    assert_eq!(c, 200);
    let defs = v2.get("definitions").unwrap();
    let d = defs.get("com.example.test.v1.Foo").expect("served version is published under its REST-friendly name");
    assert!(defs.get("com.example.test.v2.Foo").is_none(), "unserved versions are not published");
    assert_eq!(d.get("description").and_then(Value::as_str), Some("Foo CRD"));
    let props = d.get("properties").unwrap();
    assert_eq!(props.pointer(&["spec", "description"]).and_then(Value::as_str), Some("Spec"));
    assert_eq!(props.pointer(&["metadata", "$ref"]).and_then(Value::as_str), Some("#/definitions/io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta"));
    assert!(props.pointer(&["apiVersion", "description"]).and_then(Value::as_str).is_some_and(|s| s.starts_with("APIVersion defines")));
    assert_eq!(d.pointer(&["x-kubernetes-group-version-kind"]).and_then(Value::as_array).map(|a| a.len()), Some(1));
    assert!(defs.get("io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta").is_some());

    let (c, v3) = call(&api, "GET", "/openapi/v3/apis/test.example.com/v1", "", "");
    assert_eq!(c, 200);
    let s = v3.pointer(&["components", "schemas"]).unwrap();
    let r = s.pointer(&["com.example.test.v1.Foo", "properties", "metadata", "allOf"]).and_then(Value::as_array).and_then(|a| a[0].get("$ref")).and_then(Value::as_str);
    assert_eq!(r, Some("#/components/schemas/io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta"));
    let om = s.get("io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta").unwrap();
    assert!(json::to_string(om).contains("#/components/schemas/io.k8s.apimachinery.pkg.apis.meta.v1.Time"), "meta refs are rebased for v3");

    // Gone with the CRD.
    let crd = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/foos.test.example.com";
    assert_eq!(call(&api, "DELETE", crd, "", "").0, 200);
    // No CRD controller runs here to drop the cleanup finalizer.
    assert_eq!(call(&api, "PATCH", crd, "application/merge-patch+json", r#"{"metadata":{"finalizers":null}}"#).0, 200);
    let (_, v2) = call(&api, "GET", "/openapi/v2", "", "");
    assert!(v2.pointer(&["definitions", "com.example.test.v1.Foo"]).is_none());
}

#[test]
fn unserving_a_version_removes_its_definition() {
    let api = server();
    let crd = |v6_served: bool| format!(r#"{{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{{"name":"multis.test.example.com"}},
     "spec":{{"group":"test.example.com","scope":"Namespaced","names":{{"plural":"multis","singular":"multi","kind":"Multi","listKind":"MultiList"}},
     "versions":[{{"name":"v6alpha1","served":{v6_served},"storage":false,"schema":{{"openAPIV3Schema":{{"type":"object"}}}}}},{{"name":"v5","served":true,"storage":true,"schema":{{"openAPIV3Schema":{{"type":"object"}}}}}}]}}}}"#);
    assert_eq!(call(&api, "POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", "application/json", &crd(true)).0, 201);
    let (_, v2) = call(&api, "GET", "/openapi/v2", "", "");
    assert!(v2.pointer(&["definitions", "com.example.test.v6alpha1.Multi"]).is_some());
    let (_, cur) = call(&api, "GET", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/multis.test.example.com", "", "");
    let mut upd = kr_fmt::json::parse(crd(false).as_bytes()).unwrap();
    upd.entry_object("metadata").set("resourceVersion", cur.pointer(&["metadata", "resourceVersion"]).cloned().unwrap());
    assert_eq!(call(&api, "PUT", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/multis.test.example.com", "application/json", &json::to_string(&upd)).0, 200);
    let (_, v2) = call(&api, "GET", "/openapi/v2", "", "");
    assert!(v2.pointer(&["definitions", "com.example.test.v6alpha1.Multi"]).is_none());
    assert!(v2.pointer(&["definitions", "com.example.test.v5.Multi"]).is_some());
    for p in ["/apis", "/apis/test.example.com", "/apis/test.example.com/v5", "/openapi/v3", "/openapi/v3/apis/test.example.com/v5"] {
        assert_eq!(call(&api, "GET", p, "", "").0, 200, "{p}");
    }
}
