//! `kubectl get hpa` columns.
use kr_apiserver::api::{ApiServer, Reply, Req, User};
use kr_fmt::json::{self, Value};

fn rng(b: &mut [u8]) {
    kr_sys::getrandom(b)
}

fn call(api: &ApiServer, method: &str, path: &str, accept: Option<&str>, body: &str) -> (u16, Value) {
    let user = Some(User { name: "admin".into(), groups: vec!["system:masters".into()] });
    let req = Req { method, path, query: "", content_type: Some("application/json"), accept, body: body.as_bytes(), user, bearer: None, headers: &[], authz_verb: None };
    match api.handle(&req) {
        Reply::Json(c, b) => (c, json::parse(b.as_bytes()).unwrap_or(Value::Null)),
        _ => panic!("unexpected reply"),
    }
}

fn cells(api: &ApiServer, name: &str) -> Vec<String> {
    let (_, t) = call(api, "GET", "/apis/autoscaling/v2/namespaces/default/horizontalpodautoscalers", Some("application/json;as=Table;g=meta.k8s.io;v=v1"), "");
    let rows = t.get("rows").and_then(Value::as_array).unwrap();
    let row = rows.iter().find(|r| r.pointer(&["cells"]).and_then(Value::as_array).and_then(|c| c.first()).and_then(Value::as_str) == Some(name)).unwrap();
    row.get("cells").and_then(Value::as_array).unwrap().iter().map(|c| c.as_str().unwrap_or("").to_string()).collect()
}

#[test]
fn hpa_columns_show_reference_targets_and_replicas() {
    let api = ApiServer::new(kr_store::Store::in_memory(), || 1_700_000_000, rng, "127.0.0.1".into()).unwrap();
    let hpa = r#"{"metadata":{"name":"web"},"spec":{"scaleTargetRef":{"apiVersion":"apps/v1","kind":"Deployment","name":"web"},"minReplicas":2,"maxReplicas":8,"metrics":[{"type":"Resource","resource":{"name":"cpu","target":{"type":"Utilization","averageUtilization":80}}},{"type":"Resource","resource":{"name":"memory","target":{"type":"AverageValue","averageValue":"200Mi"}}}]}}"#;
    assert_eq!(call(&api, "POST", "/apis/autoscaling/v2/namespaces/default/horizontalpodautoscalers", None, hpa).0, 201);
    let c = cells(&api, "web");
    assert_eq!(&c[..5], ["web", "Deployment/web", "<unknown>/80%, <unknown>/200Mi", "2", "8"]);
    let st = r#"{"status":{"currentReplicas":3,"currentMetrics":[{"type":"Resource","resource":{"name":"cpu","current":{"averageUtilization":45}}},{"type":"Resource","resource":{"name":"memory","current":{"averageValue":"150Mi"}}}]}}"#;
    let (code, _) = {
        let user = Some(User { name: "admin".into(), groups: vec!["system:masters".into()] });
        let req = Req { method: "PATCH", path: "/apis/autoscaling/v2/namespaces/default/horizontalpodautoscalers/web/status", query: "", content_type: Some("application/merge-patch+json"), accept: None, body: st.as_bytes(), user, bearer: None, headers: &[], authz_verb: None };
        match api.handle(&req) {
            Reply::Json(c, b) => (c, b),
            _ => panic!(),
        }
    };
    assert_eq!(code, 200);
    let c = cells(&api, "web");
    assert_eq!(&c[..6], ["web", "Deployment/web", "45%/80%, 150Mi/200Mi", "2", "8", "3"]);
    // autoscaling/v1 objects print their CPU percentage.
    let v1 = r#"{"apiVersion":"autoscaling/v1","kind":"HorizontalPodAutoscaler","metadata":{"name":"old"},"spec":{"scaleTargetRef":{"apiVersion":"apps/v1","kind":"Deployment","name":"web"},"maxReplicas":4,"targetCPUUtilizationPercentage":60}}"#;
    assert_eq!(call(&api, "POST", "/apis/autoscaling/v1/namespaces/default/horizontalpodautoscalers", None, v1).0, 201);
    let c = cells(&api, "old");
    assert_eq!(&c[..5], ["old", "Deployment/web", "<unknown>/60%", "1", "4"]);
}
