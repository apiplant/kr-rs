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
        Reply::Http(r) => match r.body {
            kr_net::http1::server::Body::Full(b) => (r.status, json::parse(&b).unwrap_or(Value::Null)),
            _ => panic!("unexpected reply"),
        },
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
/// Protobuf CRD bodies are decoded (proto tables include apiextensions): an empty one is
/// rejected by validation, not as an unsupported media type.
fn protobuf_crd_is_decoded() {
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
    let (c, b) = call(&api, "POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", "application/vnd.kubernetes.protobuf", std::str::from_utf8(&body).unwrap());
    assert!(c == 400 || c == 422, "{c} {b}");
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

const CRDS: &str = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions";
const G: &str = "/apis/example.com/v1/namespaces/default/gizmos";

/// A single-version `gizmos` CRD whose root schema is `schema` (a JSON object literal).
fn gizmo_crd(schema: &str) -> String {
    format!(
        r#"{{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{{"name":"gizmos.example.com"}},
"spec":{{"group":"example.com","scope":"Namespaced","names":{{"plural":"gizmos","kind":"Gizmo"}},
"versions":[{{"name":"v1","served":true,"storage":true,"schema":{{"openAPIV3Schema":{schema}}}}}]}}}}"#
    )
}

fn gizmo_api(spec_props: &str, spec_extra: &str) -> ApiServer {
    let api = server();
    let schema = format!(r#"{{"type":"object","properties":{{"spec":{{"type":"object"{spec_extra},"properties":{spec_props}}}}}}}"#);
    let (c, v) = j(&api, "POST", CRDS, &gizmo_crd(&schema));
    assert_eq!(c, 201, "{v:?}");
    api
}

fn gizmo(name: &str, spec: &str) -> String {
    format!(r#"{{"apiVersion":"example.com/v1","kind":"Gizmo","metadata":{{"name":"{name}"}},"spec":{spec}}}"#)
}

fn msg(v: &Value) -> String {
    v.get("message").and_then(Value::as_str).unwrap_or("").to_string()
}

#[test]
fn non_structural_crds_are_rejected() {
    let cases = [
        (r#"{"type":"object","properties":{"a":{"description":"no type"}}}"#, "properties[a].type: Required value: must not be empty for specified object fields"),
        (r#"{"properties":{}}"#, "must not be empty at the root"),
        (r#"{"type":"object","properties":{"a":{"type":"string"}},"additionalProperties":{"type":"string"}}"#, "additionalProperties and properties are mutual exclusive"),
        (r#"{"type":"object","properties":{"a":{"type":"array"}}}"#, "items: Required value"),
        (r#"{"type":"object","properties":{"a":{"type":"array","items":{"description":"x"}}}}"#, "items.type: Required value: must not be empty for specified array items"),
        (r#"{"type":"object","properties":{"a":{"type":"string","anyOf":[{"type":"string"}]}}}"#, "anyOf[0].type: Forbidden"),
        (r#"{"type":"object","properties":{"a":{"type":"string","pattern":"("}}}"#, "pattern: Invalid value"),
        (r#"{"type":"object","properties":{"a":{"type":"string","x-kubernetes-validations":[{"rule":"self.nope("}]}}}"#, "compilation failed"),
        (r#"{"type":"object","properties":{"a":{"type":"string","x-kubernetes-validations":[{"rule":"unknownFn(self)"}]}}}"#, "compilation failed"),
        (r#"{"type":"object","properties":{"a":{"type":"string","x-kubernetes-validations":[{"message":"m"}]}}}"#, "rule: Required value"),
    ];
    for (schema, want) in cases {
        let (c, v) = j(&server(), "POST", CRDS, &gizmo_crd(schema));
        assert_eq!(c, 422, "{schema}");
        assert!(msg(&v).contains(want), "{schema}: {}", msg(&v));
    }
    // Structural forms are accepted: int-or-string, preserve-unknown-fields without type.
    let ok = r#"{"type":"object","properties":{"a":{"x-kubernetes-int-or-string":true,"anyOf":[{"type":"integer"},{"type":"string"}]},"b":{"x-kubernetes-preserve-unknown-fields":true}}}"#;
    assert_eq!(j(&server(), "POST", CRDS, &gizmo_crd(ok)).0, 201);
    // Updates are checked too.
    let api = server();
    assert_eq!(j(&api, "POST", CRDS, &gizmo_crd(ok)).0, 201);
    let bad = gizmo_crd(r#"{"type":"object","properties":{"a":{}}}"#);
    assert_eq!(j(&api, "PUT", &format!("{CRDS}/gizmos.example.com"), &bad).0, 422);
}

#[test]
fn schema_keywords_are_enforced() {
    // allOf/oneOf/not inside a typed node are structural as long as they carry no type.
    let props = r#"{
"name":{"type":"string","pattern":"^[a-z][a-z0-9-]*$","maxLength":10},
"when":{"type":"string","format":"date"},
"at":{"type":"string","format":"date-time"},
"id":{"type":"string","format":"uuid"},
"ip":{"type":"string","format":"ipv4"},
"ip6":{"type":"string","format":"ipv6"},
"host":{"type":"string","format":"hostname"},
"blob":{"type":"string","format":"byte"},
"link":{"type":"string","format":"uri"},
"i32":{"type":"integer","format":"int32"},
"n":{"type":"number","minimum":0,"exclusiveMinimum":true,"maximum":10,"multipleOf":2},
"list":{"type":"array","items":{"type":"string"},"uniqueItems":true,"minItems":1,"maxItems":3},
"set":{"type":"array","items":{"type":"string"},"x-kubernetes-list-type":"set"},
"map":{"type":"array","items":{"type":"object","properties":{"k":{"type":"string"},"v":{"type":"string"}}},"x-kubernetes-list-type":"map","x-kubernetes-list-map-keys":["k"]},
"obj":{"type":"object","additionalProperties":{"type":"string"},"minProperties":1,"maxProperties":2},
"choice":{"type":"integer","allOf":[{"minimum":1}],"oneOf":[{"maximum":5},{"minimum":10}],"not":{"enum":[3]}}
}"#;
    let api = gizmo_api(props, "");
    let good = r#"{"name":"abc-1","when":"2024-02-29","at":"2024-05-01T10:20:30Z","id":"123e4567-e89b-12d3-a456-426614174000","ip":"10.0.0.1","ip6":"::1","host":"a.example.com","blob":"aGk=","link":"https://x.io/p","i32":5,"n":4,"list":["a","b"],"set":["a","b"],"map":[{"k":"a"},{"k":"b"}],"obj":{"x":"y"},"choice":2}"#;
    let (c, v) = j(&api, "POST", G, &gizmo("g", good));
    assert_eq!(c, 201, "{v:?}");
    let bads = [
        (r#"{"name":"Abc"}"#, "should match"),
        (r#"{"name":"abcdefghijklmnop"}"#, "Too long"),
        (r#"{"when":"2023-02-29"}"#, "must be of type date"),
        (r#"{"at":"2024-05-01 10:20"}"#, "date-time"),
        (r#"{"id":"nope"}"#, "uuid"),
        (r#"{"ip":"300.1.1.1"}"#, "ipv4"),
        (r#"{"ip6":"1.2.3.4"}"#, "ipv6"),
        (r#"{"host":"-a.com"}"#, "hostname"),
        (r#"{"blob":"abc"}"#, "byte"),
        (r#"{"link":"not a uri"}"#, "uri"),
        (r#"{"i32":3000000000}"#, "int32"),
        (r#"{"n":0}"#, "greater than 0"),
        (r#"{"n":12}"#, "less than or equal to 10"),
        (r#"{"n":3}"#, "multiple of 2"),
        (r#"{"list":["a","a"]}"#, "Duplicate value"),
        (r#"{"list":[]}"#, "at least 1"),
        (r#"{"list":["a","b","c","d"]}"#, "Too many"),
        (r#"{"set":["a","a"]}"#, "Duplicate value"),
        (r#"{"map":[{"k":"a","v":"1"},{"k":"a","v":"2"}]}"#, "Duplicate value"),
        (r#"{"obj":{}}"#, "at least 1 properties"),
        (r#"{"obj":{"a":"1","b":"2","c":"3"}}"#, "at most 2 properties"),
        (r#"{"choice":0}"#, "greater than or equal to 1"),
        (r#"{"choice":7}"#, "oneOf"),
        (r#"{"choice":3}"#, "(not)"),
    ];
    for (spec, want) in bads {
        let (c, v) = j(&api, "POST", G, &gizmo("h", spec));
        assert_eq!(c, 422, "{spec}: {v:?}");
        assert!(msg(&v).contains(want), "{spec}: {}", msg(&v));
    }
}

#[test]
fn cel_rules_run_with_self_and_old_self() {
    let props = r#"{"lo":{"type":"integer"},"hi":{"type":"integer"},
"replicas":{"type":"integer","x-kubernetes-validations":[{"rule":"self >= oldSelf","message":"replicas may not decrease"}]},
"name":{"type":"string","x-kubernetes-validations":[{"rule":"self.matches('^[a-z]+$') && size(self) < 6","messageExpression":"'bad name ' + self"}]},
"tags":{"type":"array","items":{"type":"string"},"x-kubernetes-validations":[{"rule":"self.all(t, t.startsWith('t-'))"}]}}"#;
    let api = gizmo_api(props, r#","x-kubernetes-validations":[{"rule":"self.lo <= self.hi","message":"lo must not exceed hi"},{"rule":"!has(self.name) || self.name != 'root'"}]"#);
    let (c, v) = j(&api, "POST", G, &gizmo("g", r#"{"lo":1,"hi":2,"replicas":3,"name":"abc","tags":["t-1"]}"#));
    assert_eq!(c, 201, "{v:?}");
    for (spec, want) in [
        (r#"{"lo":3,"hi":2}"#, "lo must not exceed hi"),
        (r#"{"lo":1,"hi":2,"name":"root"}"#, "failed rule"),
        (r#"{"lo":1,"hi":2,"name":"ABC"}"#, "bad name ABC"),
        (r#"{"lo":1,"hi":2,"tags":["x"]}"#, "failed rule: self.all"),
    ] {
        let (c, v) = j(&api, "POST", G, &gizmo("h", spec));
        assert_eq!(c, 422, "{spec}: {v:?}");
        assert!(msg(&v).contains(want), "{spec}: {}", msg(&v));
    }
    // Transition rule: only on update, against the stored value.
    let up = |r: u32| gizmo("g", &format!(r#"{{"lo":1,"hi":2,"replicas":{r},"name":"abc","tags":["t-1"]}}"#));
    assert_eq!(j(&api, "PUT", &format!("{G}/g"), &up(5)).0, 200);
    let (c, v) = j(&api, "PUT", &format!("{G}/g"), &up(2));
    assert_eq!(c, 422);
    assert!(msg(&v).contains("replicas may not decrease"), "{}", msg(&v));
    assert_eq!(j(&api, "PUT", &format!("{G}/g"), &up(5)).0, 200);
}

#[test]
fn watch_events_carry_the_requested_version() {
    use std::task::{Context, Poll, Waker};
    let api = crd_installed();
    assert_eq!(j(&api, "POST", W, &widget("w", r#"{"size":1}"#)).0, 201);
    let lines = |p: &str, q: &str| -> String {
        let req = Req { method: "GET", path: p, query: q, content_type: None, accept: None, body: b"", user: Some(User { name: "admin".into(), groups: vec!["system:masters".into()] }), bearer: None, headers: &[], authz_verb: None };
        let Reply::Watch(mut w) = api.handle(&req) else { panic!("expected a watch") };
        let mut cx = Context::from_waker(Waker::noop());
        let mut out = String::new();
        while let Poll::Ready(Some(c)) = w.poll_chunk(&mut cx) {
            out.push_str(&String::from_utf8(c).unwrap());
        }
        out
    };
    let q = "watch=true&resourceVersion=0";
    let v2 = lines("/apis/example.com/v2/namespaces/default/widgets", q);
    assert!(v2.contains(r#""object":{"apiVersion":"example.com/v2""#), "{v2}");
    let v1 = lines("/apis/example.com/v1/namespaces/default/widgets", q);
    assert!(v1.contains(r#""apiVersion":"example.com/v1""#), "{v1}");
}
