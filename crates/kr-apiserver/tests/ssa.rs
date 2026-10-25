//! Server-side apply and managedFields through `ApiServer::handle` (no transport).

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

const APPLY: &str = "application/apply-patch+yaml";
const DEP: &str = "/apis/apps/v1/namespaces/default/deployments";

fn dep(replicas: i64, extra: &str) -> String {
    format!(
        r#"{{"apiVersion":"apps/v1","kind":"Deployment","metadata":{{"name":"d","labels":{{"app":"d"{extra}}}}},"spec":{{"replicas":{replicas},"selector":{{"matchLabels":{{"app":"d"}}}},"template":{{"metadata":{{"labels":{{"app":"d"}}}},"spec":{{"containers":[{{"name":"c","image":"nginx"}}]}}}}}}}}"#
    )
}

fn mf<'a>(o: &'a Value, manager: &str, op: &str) -> &'a Value {
    o.pointer(&["metadata", "managedFields"])
        .and_then(Value::as_array)
        .and_then(|a| a.iter().find(|e| e.get("manager").and_then(Value::as_str) == Some(manager) && e.get("operation").and_then(Value::as_str) == Some(op)))
        .unwrap_or_else(|| panic!("no {manager}/{op} in {}", json::to_string(o)))
}

#[test]
fn apply_creates_and_tracks_fields() {
    let api = server();
    let (c, o) = call(&api, "PATCH", &format!("{DEP}/d?fieldManager=m1"), APPLY, &dep(1, ""));
    assert_eq!(c, 201, "{}", json::to_string(&o));
    let e = mf(&o, "m1", "Apply");
    assert_eq!(e.get("fieldsType").and_then(Value::as_str), Some("FieldsV1"));
    assert_eq!(e.get("apiVersion").and_then(Value::as_str), Some("apps/v1"));
    let f = e.get("fieldsV1").unwrap();
    assert!(f.pointer(&["f:spec", "f:replicas"]).is_some());
    assert!(f.pointer(&["f:spec", "f:template", "f:spec", "f:containers", "k:{\"name\":\"c\"}", "f:image"]).is_some(), "{}", json::to_string(f));
    // Fields that came from defaults are not owned by the apply.
    assert!(f.pointer(&["f:spec", "f:strategy"]).is_none());
}

#[test]
fn apply_requires_manager() {
    let api = server();
    assert_eq!(call(&api, "PATCH", &format!("{DEP}/d"), APPLY, &dep(1, "")).0, 400);
}

#[test]
fn reapply_removes_dropped_field() {
    let api = server();
    call(&api, "PATCH", &format!("{DEP}/d?fieldManager=m1"), APPLY, &dep(1, r#","extra":"1""#));
    let (c, o) = call(&api, "PATCH", &format!("{DEP}/d?fieldManager=m1"), APPLY, &dep(1, ""));
    assert_eq!(c, 200);
    assert!(o.pointer(&["metadata", "labels", "extra"]).is_none());
    assert!(o.pointer(&["metadata", "labels", "app"]).is_some());
}

#[test]
fn managers_conflict_and_force() {
    let api = server();
    call(&api, "PATCH", &format!("{DEP}/d?fieldManager=m1"), APPLY, &dep(1, ""));
    let (c, o) = call(&api, "PATCH", &format!("{DEP}/d?fieldManager=m2"), APPLY, &dep(3, ""));
    assert_eq!(c, 409);
    assert_eq!(o.get("message").and_then(Value::as_str), Some("Apply failed with 1 conflict: conflict with \"m1\" using apps/v1: .spec.replicas"));
    let (c, o) = call(&api, "PATCH", &format!("{DEP}/d?fieldManager=m2&force=true"), APPLY, &dep(3, ""));
    assert_eq!(c, 200, "{}", json::to_string(&o));
    assert_eq!(o.pointer(&["spec", "replicas"]).and_then(Value::as_i64), Some(3));
    assert!(mf(&o, "m2", "Apply").get("fieldsV1").unwrap().pointer(&["f:spec", "f:replicas"]).is_some());
    assert!(mf(&o, "m1", "Apply").get("fieldsV1").unwrap().pointer(&["f:spec", "f:replicas"]).is_none());
}

#[test]
fn update_by_other_manager_then_apply() {
    let api = server();
    call(&api, "PATCH", &format!("{DEP}/d?fieldManager=m1"), APPLY, &dep(1, ""));
    let (c, o) = call(&api, "PATCH", &format!("{DEP}/d?fieldManager=scaler"), "application/merge-patch+json", r#"{"spec":{"replicas":5}}"#);
    assert_eq!(c, 200);
    assert!(mf(&o, "scaler", "Update").get("fieldsV1").unwrap().pointer(&["f:spec", "f:replicas"]).is_some());
    let (c, o) = call(&api, "PATCH", &format!("{DEP}/d?fieldManager=m1"), APPLY, &dep(2, ""));
    assert_eq!(c, 409, "{}", json::to_string(&o));
    assert!(o.get("message").and_then(Value::as_str).unwrap().contains("conflict with \"scaler\" using apps/v1: .spec.replicas"));
    // Same value: no conflict, both own it.
    let (c, _) = call(&api, "PATCH", &format!("{DEP}/d?fieldManager=m1"), APPLY, &dep(5, ""));
    assert_eq!(c, 200);
}

#[test]
fn update_uses_user_agent_and_merges() {
    let api = server();
    let (_, o) = call(&api, "POST", DEP, "application/json", &dep(1, ""));
    let e = mf(&o, "kubectl", "Update");
    assert!(e.get("fieldsV1").unwrap().pointer(&["f:spec", "f:replicas"]).is_some());
    let mut n = o.clone();
    n.entry_object("spec").set("replicas", Value::from(2i64));
    let (c, o) = call(&api, "PUT", &format!("{DEP}/d"), "application/json", &json::to_string(&n));
    assert_eq!(c, 200);
    assert_eq!(o.pointer(&["metadata", "managedFields"]).unwrap().as_array().unwrap().len(), 1);
}

#[test]
fn managed_fields_reset_and_validation() {
    let api = server();
    call(&api, "POST", DEP, "application/json", &dep(1, ""));
    let (c, _) = call(&api, "PATCH", &format!("{DEP}/d"), "application/merge-patch+json", r#"{"metadata":{"managedFields":[{"manager":"x","operation":"Bogus"}]}}"#);
    assert_eq!(c, 422);
    let (c, o) = call(&api, "PATCH", &format!("{DEP}/d?fieldManager=resetter"), "application/merge-patch+json", r#"{"metadata":{"managedFields":[{}]}}"#);
    assert_eq!(c, 200);
    let a = o.pointer(&["metadata", "managedFields"]).unwrap().as_array().unwrap();
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].get("manager").and_then(Value::as_str), Some("resetter"));
    // A client-supplied (valid) list is ignored.
    let (_, o) = call(&api, "PATCH", &format!("{DEP}/d?fieldManager=resetter"), "application/merge-patch+json", r#"{"metadata":{"managedFields":[{"manager":"x","operation":"Update","fieldsV1":{}}]}}"#);
    assert_eq!(o.pointer(&["metadata", "managedFields"]).unwrap().as_array().unwrap().len(), 1);
}

#[test]
fn status_writes_record_subresource() {
    let api = server();
    call(&api, "POST", DEP, "application/json", &dep(1, ""));
    let (c, o) = call(&api, "PATCH", &format!("{DEP}/d/status?fieldManager=ctl"), "application/merge-patch+json", r#"{"status":{"replicas":1}}"#);
    assert_eq!(c, 200, "{}", json::to_string(&o));
    let e = mf(&o, "ctl", "Update");
    assert_eq!(e.get("subresource").and_then(Value::as_str), Some("status"));
    assert!(e.get("fieldsV1").unwrap().pointer(&["f:status", "f:replicas"]).is_some());
}

static CLOCK: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(1_700_000_000);

fn tick() -> i64 {
    CLOCK.fetch_add(10, std::sync::atomic::Ordering::SeqCst) + 10
}

fn rv(o: &Value) -> String {
    o.pointer(&["metadata", "resourceVersion"]).and_then(Value::as_str).unwrap().to_string()
}

fn times(o: &Value) -> Vec<String> {
    o.pointer(&["metadata", "managedFields"]).and_then(Value::as_array).unwrap().iter().map(|e| e.get("time").and_then(Value::as_str).unwrap().to_string()).collect()
}

#[test]
fn noop_writes_keep_resource_version_and_time() {
    let api = ApiServer::new(kr_store::Store::in_memory(), tick, rng, "127.0.0.1".into()).unwrap();
    let cm = "/api/v1/namespaces/default/configmaps";
    let (_, o) = call(&api, "POST", cm, "application/json", r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"c"},"data":{"a":"1"}}"#);
    let (rv0, t0) = (rv(&o), times(&o));
    // Identical PUT (with the current resourceVersion, as clients send it).
    let body = json::to_string(&o);
    let (c, u) = call(&api, "PUT", &format!("{cm}/c"), "application/json", &body);
    assert_eq!(c, 200, "{}", json::to_string(&u));
    assert_eq!((rv(&u), times(&u)), (rv0.clone(), t0.clone()));
    // Merge patch to the same value.
    let (_, p) = call(&api, "PATCH", &format!("{cm}/c"), "application/merge-patch+json", r#"{"data":{"a":"1"}}"#);
    assert_eq!((rv(&p), times(&p)), (rv0.clone(), t0.clone()));
    // Re-applying the same intent is a no-op too.
    let ap = r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"a"},"data":{"x":"1"}}"#;
    let (_, a1) = call(&api, "PATCH", &format!("{cm}/a?fieldManager=m"), APPLY, ap);
    let (_, a2) = call(&api, "PATCH", &format!("{cm}/a?fieldManager=m"), APPLY, ap);
    assert_eq!((rv(&a2), times(&a2)), (rv(&a1), times(&a1)));
    // No store revision was consumed: the next write gets the next number.
    let (_, n) = call(&api, "PATCH", &format!("{cm}/c"), "application/merge-patch+json", r#"{"data":{"a":"2"}}"#);
    assert_eq!(rv(&n).parse::<u64>().unwrap(), rv(&a1).parse::<u64>().unwrap() + 1);
    assert_ne!(times(&n), t0);
}

#[test]
fn atomic_map_is_owned_and_replaced_whole() {
    let api = server();
    let crd = r#"{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"gizmos.example.com"},
"spec":{"group":"example.com","scope":"Namespaced","names":{"plural":"gizmos","kind":"Gizmo"},
"versions":[{"name":"v1","served":true,"storage":true,"schema":{"openAPIV3Schema":{"type":"object","properties":{"spec":{"type":"object","properties":{"sel":{"type":"object","x-kubernetes-map-type":"atomic","properties":{"a":{"type":"string"},"b":{"type":"string"}}}}}}}}}]}}"#;
    let (c, v) = call(&api, "POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", "application/json", crd);
    assert_eq!(c, 201, "{}", json::to_string(&v));
    let g = "/apis/example.com/v1/namespaces/default/gizmos";
    let body = |s: &str| format!(r#"{{"apiVersion":"example.com/v1","kind":"Gizmo","metadata":{{"name":"g"}},"spec":{{"sel":{s}}}}}"#);
    let (c, o) = call(&api, "PATCH", &format!("{g}/g?fieldManager=m"), APPLY, &body(r#"{"a":"1","b":"2"}"#));
    assert_eq!(c, 201, "{}", json::to_string(&o));
    let f = mf(&o, "m", "Apply").get("fieldsV1").unwrap();
    assert_eq!(json::to_string(f.pointer(&["f:spec", "f:sel"]).unwrap()), "{}");
    let (c, o) = call(&api, "PATCH", &format!("{g}/g?fieldManager=m"), APPLY, &body(r#"{"b":"3"}"#));
    assert_eq!(c, 200, "{}", json::to_string(&o));
    assert_eq!(json::to_string(o.pointer(&["spec", "sel"]).unwrap()), r#"{"b":"3"}"#);
}
