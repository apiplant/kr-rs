//! `metrics.k8s.io/v1beta1` through `ApiServer::handle`: types, label selectors, discovery.

use kr_apiserver::api::{ApiServer, Reply, Req, User};
use kr_apiserver::metrics::{CtrSample, Scrape};
use kr_fmt::json::{self, Value};

const NOW: i64 = 1_700_000_000;

fn now() -> i64 {
    NOW
}

fn rng(b: &mut [u8]) {
    kr_sys::getrandom(b)
}

fn call(api: &ApiServer, method: &str, path: &str, body: &str) -> (u16, Value) {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let user = Some(User { name: "admin".into(), groups: vec!["system:masters".into()] });
    let req = Req { method, path, query, content_type: Some("application/json"), accept: None, body: body.as_bytes(), user, bearer: None, headers: &[], authz_verb: None };
    match api.handle(&req) {
        Reply::Json(c, b) => (c, json::parse(b.as_bytes()).unwrap_or(Value::Null)),
        _ => panic!("unexpected reply"),
    }
}

fn scrape(cpu: f64, ts: i64, pods: &[(&str, &str)]) -> Scrape {
    Scrape {
        node_cpu: Some((cpu * 2.0, ts)),
        node_mem: Some(512 << 20),
        ctrs: pods.iter().map(|(ns, p)| CtrSample { ns: ns.to_string(), pod: p.to_string(), container: "app".into(), cpu_secs: cpu, mem: 8 << 20, ts_ms: ts }).collect(),
        error: false,
    }
}

#[test]
fn serves_node_and_pod_metrics() {
    let api = ApiServer::new(kr_store::Store::in_memory(), now, rng, "127.0.0.1".into()).unwrap();
    assert_eq!(call(&api, "POST", "/api/v1/nodes", r#"{"metadata":{"name":"n1","labels":{"zone":"a"}}}"#).0, 201);
    for (n, l) in [("web", "web"), ("db", "db")] {
        let body = format!(r#"{{"metadata":{{"name":"{n}","labels":{{"app":"{l}"}}}},"spec":{{"containers":[{{"name":"app","image":"x"}}]}}}}"#);
        assert_eq!(call(&api, "POST", "/api/v1/namespaces/default/pods", &body).0, 201);
    }
    let ms = NOW * 1000;
    // One scrape: no rate yet, so nothing is served.
    api.metrics.apply("n1", &scrape(1.0, ms - 15_000, &[("default", "web"), ("default", "db"), ("default", "gone")]));
    let (c, l) = call(&api, "GET", "/apis/metrics.k8s.io/v1beta1/nodes", "");
    assert_eq!((c, l.get("kind").and_then(Value::as_str), l.get("items").and_then(Value::as_array).map(|a| a.len())), (200, Some("NodeMetricsList"), Some(0)));
    api.metrics.apply("n1", &scrape(2.5, ms, &[("default", "web"), ("default", "db"), ("default", "gone")]));

    let (c, l) = call(&api, "GET", "/apis/metrics.k8s.io/v1beta1/nodes", "");
    assert_eq!(c, 200);
    let it = &l.get("items").and_then(Value::as_array).unwrap()[0];
    assert_eq!(it.get("kind").and_then(Value::as_str), Some("NodeMetrics"));
    assert_eq!(it.get("apiVersion").and_then(Value::as_str), Some("metrics.k8s.io/v1beta1"));
    assert_eq!(it.pointer(&["usage", "cpu"]).and_then(Value::as_str), Some("200000000n"));
    assert_eq!(it.pointer(&["usage", "memory"]).and_then(Value::as_str), Some("524288Ki"));
    assert_eq!(it.get("window").and_then(Value::as_str), Some("15s"));
    assert_eq!(it.pointer(&["metadata", "labels", "zone"]).and_then(Value::as_str), Some("a"));
    assert_eq!(call(&api, "GET", "/apis/metrics.k8s.io/v1beta1/nodes/n1", "").0, 200);
    assert_eq!(call(&api, "GET", "/apis/metrics.k8s.io/v1beta1/nodes/nope", "").0, 404);
    assert_eq!(call(&api, "GET", "/apis/metrics.k8s.io/v1beta1/nodes?labelSelector=zone%3Db", "").1.get("items").and_then(Value::as_array).map(|a| a.len()), Some(0));

    // The "gone" pod has no API object: skipped.
    let (_, l) = call(&api, "GET", "/apis/metrics.k8s.io/v1beta1/pods", "");
    assert_eq!(l.get("kind").and_then(Value::as_str), Some("PodMetricsList"));
    assert_eq!(l.get("items").and_then(Value::as_array).map(|a| a.len()), Some(2));
    let (_, l) = call(&api, "GET", "/apis/metrics.k8s.io/v1beta1/namespaces/default/pods?labelSelector=app%3Dweb", "");
    let items = l.get("items").and_then(Value::as_array).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].pointer(&["metadata", "name"]).and_then(Value::as_str), Some("web"));
    assert_eq!(items[0].pointer(&["containers"]).and_then(Value::as_array).unwrap()[0].pointer(&["usage", "cpu"]).and_then(Value::as_str), Some("100000000n"));
    assert_eq!(call(&api, "GET", "/apis/metrics.k8s.io/v1beta1/namespaces/default/pods/db", "").0, 200);
    assert_eq!(call(&api, "GET", "/apis/metrics.k8s.io/v1beta1/namespaces/default/pods/zzz", "").0, 404);
    assert_eq!(call(&api, "GET", "/apis/metrics.k8s.io/v1beta1/namespaces/other/pods", "").1.get("items").and_then(Value::as_array).map(|a| a.len()), Some(0));
    assert_eq!(call(&api, "DELETE", "/apis/metrics.k8s.io/v1beta1/nodes/n1", "").0, 405);

    // Discovery.
    let (c, g) = call(&api, "GET", "/apis/metrics.k8s.io", "");
    assert_eq!(c, 200);
    assert_eq!(g.pointer(&["preferredVersion", "groupVersion"]).and_then(Value::as_str), Some("metrics.k8s.io/v1beta1"));
    let (_, r) = call(&api, "GET", "/apis/metrics.k8s.io/v1beta1", "");
    let names: Vec<&str> = r.get("resources").and_then(Value::as_array).unwrap().iter().filter_map(|x| x.get("name").and_then(Value::as_str)).collect();
    assert!(names.contains(&"nodes") && names.contains(&"pods"));
}
