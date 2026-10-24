//! CustomResourceDefinitions through `ApiServer::handle` (no transport).

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
        Reply::Json(c, b) => (c, json::parse(b.as_bytes()).unwrap_or(Value::Null)),
        _ => panic!("unexpected reply"),
    }
}

fn j(api: &ApiServer, method: &str, path: &str, body: &str) -> (u16, Value) {
    call(api, method, path, "application/json", body)
}

const CRD: &str = r#"{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"widgets.example.com"},
"spec":{"group":"example.com","scope":"Namespaced","names":{"plural":"widgets","kind":"Widget","shortNames":["wd"]},
"versions":[{"name":"v1","served":true,"storage":true,"subresources":{"status":{}},"schema":{"openAPIV3Schema":{"type":"object","properties":{
"spec":{"type":"object","required":["size"],"properties":{"size":{"type":"integer"},"color":{"type":"string","enum":["red","blue"]},"tags":{"type":"array","items":{"type":"string"}},"free":{"type":"object","x-kubernetes-preserve-unknown-fields":true}}},
"status":{"type":"object","properties":{"ready":{"type":"boolean"}}}}}}},
{"name":"v2","served":true,"storage":false,"schema":{"openAPIV3Schema":{"type":"object","x-kubernetes-preserve-unknown-fields":true}}}]}}"#;

const W: &str = "/apis/example.com/v1/namespaces/default/widgets";

fn widget(name: &str, spec: &str) -> String {
    format!(r#"{{"apiVersion":"example.com/v1","kind":"Widget","metadata":{{"name":"{name}"}},"spec":{spec}}}"#)
}

fn crd_installed() -> ApiServer {
    let api = server();
    let (c, _) = j(&api, "POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", CRD);
    assert_eq!(c, 201);
    api
}

#[test]
fn crd_is_established_and_validated() {
    let api = server();
    let (c, v) = j(&api, "POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", CRD);
    assert_eq!(c, 201, "{v:?}");
    assert_eq!(v.pointer(&["status", "acceptedNames", "listKind"]).unwrap().as_str(), Some("WidgetList"));
    assert_eq!(v.pointer(&["status", "acceptedNames", "singular"]).unwrap().as_str(), Some("widget"));
    assert_eq!(v.pointer(&["status", "storedVersions"]).unwrap().as_array().unwrap().len(), 1);
    let conds = v.pointer(&["status", "conditions"]).unwrap().as_array().unwrap();
    for t in ["NamesAccepted", "Established"] {
        let c = conds.iter().find(|c| c.get("type").unwrap().as_str() == Some(t)).unwrap();
        assert_eq!(c.get("status").unwrap().as_str(), Some("True"));
        assert!(c.get("lastTransitionTime").is_some());
    }
    let (c, _) = j(&api, "POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", CRD);
    assert_eq!(c, 409);
    let bad = CRD.replace("widgets.example.com", "wrong.example.com");
    assert_eq!(j(&api, "POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", &bad).0, 422);
    let nodot = CRD.replace("widgets.example.com", "widgets.local").replace("\"group\":\"example.com\"", "\"group\":\"local\"");
    assert_eq!(j(&api, "POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", &nodot).0, 422);
    let two = CRD.replace("\"storage\":false", "\"storage\":true");
    assert_eq!(j(&api, "POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", &two).0, 422);
    assert_eq!(j(&api, "GET", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/widgets.example.com", "").0, 200);
}

#[test]
fn protobuf_crd_gets_415() {
    let api = server();
    let mut body = b"k8s\0".to_vec();
    // runtime.Unknown { typeMeta { apiVersion, kind } }
    let (av, k) = (b"apiextensions.k8s.io/v1".as_slice(), b"CustomResourceDefinition".as_slice());
    let mut tm = vec![0x0a, av.len() as u8];
    tm.extend_from_slice(av);
    tm.extend_from_slice(&[0x12, k.len() as u8]);
    tm.extend_from_slice(k);
    body.extend_from_slice(&[0x0a, tm.len() as u8]);
    body.extend_from_slice(&tm);
    body.extend_from_slice(&[0x12, 0]);
    let (c, _) = call(&api, "POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", "application/vnd.kubernetes.protobuf", std::str::from_utf8(&body).unwrap());
    assert_eq!(c, 415);
}

#[test]
fn custom_object_crud_and_status() {
    let api = crd_installed();
    let (c, v) = j(&api, "POST", W, &widget("a", r#"{"size":3,"color":"red"}"#));
    assert_eq!(c, 201, "{v:?}");
    assert_eq!(v.pointer(&["metadata", "generation"]).unwrap().as_u64(), Some(1));
    assert_eq!(j(&api, "POST", W, &widget("a", r#"{"size":3}"#)).0, 409);
    assert_eq!(j(&api, "GET", &format!("{W}/a"), "").1.pointer(&["spec", "size"]).unwrap().as_u64(), Some(3));
    let (_, l) = j(&api, "GET", W, "");
    assert_eq!(l.get("kind").unwrap().as_str(), Some("WidgetList"));
    assert_eq!(l.get("items").unwrap().as_array().unwrap().len(), 1);
    assert_eq!(j(&api, "GET", "/apis/example.com/v1/widgets", "").1.get("items").unwrap().as_array().unwrap().len(), 1);

    // Main endpoint ignores status; the status endpoint only changes status.
    let upd = r#"{"apiVersion":"example.com/v1","kind":"Widget","metadata":{"name":"a"},"spec":{"size":4},"status":{"ready":true}}"#;
    let (c, v) = j(&api, "PUT", &format!("{W}/a"), upd);
    assert_eq!(c, 200, "{v:?}");
    assert!(v.get("status").is_none());
    assert_eq!(v.pointer(&["metadata", "generation"]).unwrap().as_u64(), Some(2));
    let (c, v) = j(&api, "PUT", &format!("{W}/a/status"), &upd.replace("\"size\":4", "\"size\":99"));
    assert_eq!(c, 200, "{v:?}");
    assert_eq!(v.pointer(&["status", "ready"]).unwrap().as_bool(), Some(true));
    assert_eq!(v.pointer(&["spec", "size"]).unwrap().as_u64(), Some(4));
    assert_eq!(v.pointer(&["metadata", "generation"]).unwrap().as_u64(), Some(2));

    // Patches: merge and JSON patch work; strategic merge is refused.
    let (c, v) = call(&api, "PATCH", &format!("{W}/a"), "application/merge-patch+json", r#"{"spec":{"color":"blue"}}"#);
    assert_eq!((c, v.pointer(&["spec", "color"]).unwrap().as_str()), (200, Some("blue")));
    let (c, _) = call(&api, "PATCH", &format!("{W}/a"), "application/json-patch+json", r#"[{"op":"replace","path":"/spec/size","value":5}]"#);
    assert_eq!(c, 200);
    assert_eq!(call(&api, "PATCH", &format!("{W}/a"), "application/strategic-merge-patch+json", r#"{"spec":{"size":6}}"#).0, 415);

    // Another served version reads the same object, with its own apiVersion.
    let (c, v) = j(&api, "GET", "/apis/example.com/v2/namespaces/default/widgets/a", "");
    assert_eq!((c, v.get("apiVersion").unwrap().as_str()), (200, Some("example.com/v2")));
    let (_, l) = j(&api, "GET", "/apis/example.com/v2/widgets", "");
    assert_eq!(l.pointer(&["items"]).unwrap().as_array().unwrap()[0].get("apiVersion").unwrap().as_str(), Some("example.com/v2"));
    // Wrong apiVersion for the URL is refused.
    assert_eq!(j(&api, "POST", W, &widget("b", "{}").replace("example.com/v1", "example.com/v9")).0, 400);

    assert_eq!(j(&api, "DELETE", &format!("{W}/a"), "").0, 200);
    assert_eq!(j(&api, "GET", &format!("{W}/a"), "").0, 404);
}

#[test]
fn schema_validates_and_prunes() {
    let api = crd_installed();
    let (c, v) = j(&api, "POST", W, &widget("p", r#"{"size":1,"bogus":"x","free":{"keep":{"a":1}}}"#));
    assert_eq!(c, 201, "{v:?}");
    assert!(v.pointer(&["spec", "bogus"]).is_none());
    assert!(v.pointer(&["spec", "free", "keep", "a"]).is_some());
    let mut obj = widget("q", r#"{"size":1}"#);
    obj = obj.replace("\"spec\"", "\"extra\":1,\"spec\"");
    assert!(j(&api, "POST", W, &obj).1.get("extra").is_none());
    for spec in [r#"{}"#, r#"{"size":"big"}"#, r#"{"size":1,"color":"green"}"#, r#"{"size":1,"tags":[1]}"#] {
        let (c, v) = j(&api, "POST", W, &widget("bad", spec));
        assert_eq!(c, 422, "{spec}: {v:?}");
    }
}

#[test]
fn discovery_lists_custom_resources_and_delete_removes_them() {
    let api = crd_installed();
    j(&api, "POST", W, &widget("a", r#"{"size":1}"#));
    let (_, g) = j(&api, "GET", "/apis", "");
    let group = g.get("groups").unwrap().as_array().unwrap().iter().find(|x| x.get("name").unwrap().as_str() == Some("example.com")).unwrap().clone();
    let vs: Vec<_> = group.get("versions").unwrap().as_array().unwrap().iter().map(|v| v.get("version").unwrap().as_str().unwrap().to_string()).collect();
    assert_eq!(vs, ["v2", "v1"]);
    assert_eq!(group.pointer(&["preferredVersion", "version"]).unwrap().as_str(), Some("v2"));
    assert_eq!(j(&api, "GET", "/apis/example.com", "").1.get("kind").unwrap().as_str(), Some("APIGroup"));
    let (_, rl) = j(&api, "GET", "/apis/example.com/v1", "");
    let names: Vec<_> = rl.get("resources").unwrap().as_array().unwrap().iter().map(|r| r.get("name").unwrap().as_str().unwrap().to_string()).collect();
    assert_eq!(names, ["widgets", "widgets/status"]);
    let (_, idx) = j(&api, "GET", "/openapi/v3", "");
    assert!(idx.pointer(&["paths", "apis/example.com/v1"]).is_some());
    let (c, doc) = j(&api, "GET", "/openapi/v3/apis/example.com/v1", "");
    assert_eq!(c, 200);
    assert!(doc.pointer(&["paths", "/apis/example.com/v1/namespaces/{namespace}/widgets"]).is_some());

    assert_eq!(j(&api, "DELETE", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/widgets.example.com", "").0, 200);
    assert_eq!(j(&api, "GET", W, "").0, 404);
    assert_eq!(j(&api, "GET", "/apis/example.com/v1", "").0, 404);
    assert_eq!(j(&api, "GET", "/apis/example.com", "").0, 404);
    assert!(j(&api, "GET", "/openapi/v3", "").1.pointer(&["paths", "apis/example.com/v1"]).is_none());
    // Re-creating the CRD finds no leftover objects.
    assert_eq!(j(&api, "POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", CRD).0, 201);
    assert_eq!(j(&api, "GET", W, "").1.get("items").unwrap().as_array().unwrap().len(), 0);
}

#[test]
fn crds_are_loaded_from_the_store_at_startup() {
    let dir = std::env::temp_dir().join(format!("kr-crd-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = dir.to_str().unwrap();
    {
        let api = ApiServer::new(kr_store::Store::open(d).unwrap(), now, rng, "127.0.0.1".into()).unwrap();
        assert_eq!(j(&api, "POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", CRD).0, 201);
        assert_eq!(j(&api, "POST", W, &widget("a", r#"{"size":1}"#)).0, 201);
    }
    let api = ApiServer::new(kr_store::Store::open(d).unwrap(), now, rng, "127.0.0.1".into()).unwrap();
    assert_eq!(j(&api, "GET", &format!("{W}/a"), "").0, 200);
    assert!(j(&api, "GET", "/apis/example.com/v1", "").1.get("resources").is_some());
    let _ = std::fs::remove_dir_all(&dir);
}
