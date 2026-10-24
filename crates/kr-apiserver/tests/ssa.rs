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
