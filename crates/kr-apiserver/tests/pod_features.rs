//! Pod admission details through `ApiServer::handle`: QoS class at creation, projected pod
//! certificates, the `resize` subresource and the graceful-deletion lifecycle.

use kr_apiserver::api::{ApiServer, Reply, Req, User};
use kr_fmt::json::{self, Value};

fn server() -> ApiServer {
    ApiServer::new(kr_store::Store::in_memory(), || 1_700_000_000, |b| kr_sys::getrandom(b), "127.0.0.1".into()).unwrap()
}

fn call(api: &ApiServer, method: &str, path: &str, ct: &str, body: &str) -> (u16, Value) {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let req = Req { method, path, query, content_type: Some(ct), accept: None, body: body.as_bytes(), user: Some(User { name: "admin".into(), groups: vec!["system:masters".into()] }), bearer: None, headers: &[], authz_verb: None };
    match api.handle(&req) {
        Reply::Json(c, b) => (c, json::parse(b.as_bytes()).unwrap_or(Value::Null)),
        _ => panic!("unexpected reply"),
    }
}

fn pod(name: &str, resources: &str, volumes: &str) -> String {
    format!(r#"{{"metadata":{{"name":"{name}"}},"spec":{{"containers":[{{"name":"c","image":"i","resources":{resources}}}]{volumes}}}}}"#)
}

#[test]
fn qos_class_is_set_on_creation() {
    let api = server();
    let (c, p) = call(&api, "POST", "/api/v1/namespaces/default/pods", "application/json", &pod("g", r#"{"limits":{"cpu":"100m","memory":"100Mi"},"requests":{"cpu":"100m","memory":"100Mi"}}"#, ""));
    assert_eq!(c, 201);
    assert_eq!(p.pointer(&["status", "qosClass"]).and_then(Value::as_str), Some("Guaranteed"));
    let (_, p) = call(&api, "POST", "/api/v1/namespaces/default/pods", "application/json", &pod("b", "{}", ""));
    assert_eq!(p.pointer(&["status", "qosClass"]).and_then(Value::as_str), Some("BestEffort"));
    let (_, p) = call(&api, "POST", "/api/v1/namespaces/default/pods", "application/json", &pod("u", r#"{"requests":{"cpu":"1"}}"#, ""));
    assert_eq!(p.pointer(&["status", "qosClass"]).and_then(Value::as_str), Some("Burstable"));
}

#[test]
fn pod_certificate_expiration_bounds() {
    let api = server();
    let vols = |secs: &str| format!(r#","volumes":[{{"name":"v","projected":{{"sources":[{{"podCertificate":{{"signerName":"example.com/s","keyType":"ECDSAP256","credentialBundlePath":"b.pem"{secs}}}}}]}}}}]"#);
    let create = |name: &str, secs: &str| call(&api, "POST", "/api/v1/namespaces/default/pods", "application/json", &pod(name, "{}", &vols(secs))).0;
    assert_eq!(create("ok", ""), 201);
    assert_eq!(create("one-hour", r#","maxExpirationSeconds":3600"#), 201);
    assert_eq!(create("short", r#","maxExpirationSeconds":3599"#), 422);
    assert_eq!(create("long", r#","maxExpirationSeconds":7862401"#), 422);
    // The request kind has the same bounds and defaults to 24 hours.
    let req = |secs: &str| format!(r#"{{"metadata":{{"name":"r{}"}},"spec":{{"signerName":"example.com/s","podName":"p","podUID":"u","serviceAccountName":"d","serviceAccountUID":"u","nodeName":"n","nodeUID":"u","stubPKCS10Request":"AA=="{secs}}}}}"#, secs.len());
    let (c, r) = call(&api, "POST", "/apis/certificates.k8s.io/v1/namespaces/default/podcertificaterequests", "application/json", &req(""));
    assert_eq!(c, 201);
    assert_eq!(r.pointer(&["spec", "maxExpirationSeconds"]).and_then(Value::as_i64), Some(86400));
    assert_eq!(call(&api, "POST", "/apis/certificates.k8s.io/v1/namespaces/default/podcertificaterequests", "application/json", &req(r#","maxExpirationSeconds":60"#)).0, 422);
}

#[test]
fn resize_only_changes_resources() {
    let api = server();
    call(&api, "POST", "/api/v1/namespaces/default/pods", "application/json", &pod("p", r#"{"requests":{"cpu":"100m"},"limits":{"cpu":"200m"}}"#, ""));
    let (_, cur) = call(&api, "GET", "/api/v1/namespaces/default/pods/p", "", "");
    let mut new = cur.clone();
    new.entry_object("spec").get_mut("containers").and_then(Value::as_array_mut).unwrap()[0].set("resources", json::parse(br#"{"requests":{"cpu":"150m"},"limits":{"cpu":"300m"}}"#).unwrap());
    new.entry_object("spec").set("restartPolicy", Value::from("Never"));
    new.entry_object("spec").get_mut("containers").and_then(Value::as_array_mut).unwrap()[0].set("image", Value::from("other"));
    let (c, out) = call(&api, "PUT", "/api/v1/namespaces/default/pods/p/resize", "application/json", &json::to_string(&new));
    assert_eq!(c, 200);
    assert_eq!(out.pointer(&["spec", "containers"]).and_then(Value::as_array).unwrap()[0].pointer(&["resources", "limits", "cpu"]).and_then(Value::as_str), Some("300m"));
    // Everything but the resources is kept.
    assert_eq!(out.pointer(&["spec", "containers"]).and_then(Value::as_array).unwrap()[0].get("image").and_then(Value::as_str), Some("i"));
    assert_eq!(out.pointer(&["spec", "restartPolicy"]).and_then(Value::as_str), Some("Always"));
    assert_eq!(out.pointer(&["metadata", "generation"]).and_then(Value::as_i64), Some(2));
}

#[test]
fn graceful_delete_survives_status_updates() {
    let api = server();
    let (_, p) = call(&api, "POST", "/api/v1/namespaces/default/pods", "application/json", &pod("g", "{}", ""));
    // Bind it so deletion is graceful.
    let mut bound = p.clone();
    bound.entry_object("spec").set("nodeName", Value::from("n1"));
    call(&api, "PUT", "/api/v1/namespaces/default/pods/g", "application/json", &json::to_string(&bound));
    let (c, d) = call(&api, "DELETE", "/api/v1/namespaces/default/pods/g?gracePeriodSeconds=60", "", "");
    assert_eq!(c, 200);
    assert_eq!(d.pointer(&["metadata", "generation"]).and_then(Value::as_i64), Some(3));
    // A kubelet status write must not complete the deletion while the grace period is running.
    let (_, mut cur) = call(&api, "GET", "/api/v1/namespaces/default/pods/g", "", "");
    cur.entry_object("status").set("phase", Value::from("Failed"));
    assert_eq!(call(&api, "PUT", "/api/v1/namespaces/default/pods/g/status", "application/json", &json::to_string(&cur)).0, 200);
    assert_eq!(call(&api, "GET", "/api/v1/namespaces/default/pods/g", "", "").0, 200);
    // Deleting with grace 0 (the kubelet, once the containers are gone) removes it.
    assert_eq!(call(&api, "DELETE", "/api/v1/namespaces/default/pods/g?gracePeriodSeconds=0", "", "").0, 200);
    assert_eq!(call(&api, "GET", "/api/v1/namespaces/default/pods/g", "", "").0, 404);
}

#[test]
fn events_are_one_object_in_two_views() {
    let api = server();
    let body = r#"{"metadata":{"name":"ev"},"eventTime":"2026-01-01T00:00:00.000000Z","reportingController":"test-controller","reportingInstance":"i","regarding":{"kind":"Pod","name":"p","namespace":"default"},"note":"hello","reason":"R","type":"Normal","action":"A"}"#;
    assert_eq!(call(&api, "POST", "/apis/events.k8s.io/v1/namespaces/default/events", "application/json", body).0, 201);
    let (c, l) = call(&api, "GET", "/api/v1/namespaces/default/events?fieldSelector=source%3Dtest-controller", "", "");
    assert_eq!(c, 200);
    let items = l.get("items").and_then(Value::as_array).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!((items[0].get("apiVersion").and_then(Value::as_str), items[0].get("message").and_then(Value::as_str), items[0].pointer(&["involvedObject", "name"]).and_then(Value::as_str)), (Some("v1"), Some("hello"), Some("p")));
    let (_, l) = call(&api, "GET", "/apis/events.k8s.io/v1/namespaces/default/events", "", "");
    assert_eq!(l.get("items").and_then(Value::as_array).unwrap()[0].get("apiVersion").and_then(Value::as_str), Some("events.k8s.io/v1"));
}
