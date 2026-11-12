//! Big lists rendered in offload workers (ADR-052) equal the inline rendering, and the audit body
//! encoder matches the inline one. The workers are forks of this test process.
use kr_apiserver::api::{ApiServer, Reply, Req, User};
use kr_fmt::json::{self, Value};
use kr_rt::exec;

fn rng(b: &mut [u8]) {
    kr_sys::getrandom(b)
}

fn req<'a>(method: &'a str, path: &'a str, query: &'a str, accept: Option<&'a str>, body: &'a str) -> Req<'a> {
    let user = Some(User { name: "admin".into(), groups: vec!["system:masters".into()] });
    Req { method, path, query, content_type: Some("application/json"), accept, body: body.as_bytes(), user, bearer: None, headers: &[], authz_verb: None }
}

fn text(r: Reply) -> (u16, String) {
    match r {
        Reply::Json(c, b) => (c, b),
        _ => panic!("unexpected reply"),
    }
}

/// The reply of a GET with deferral on, awaited like the transport does; and whether a job was used.
fn deferred(api: &ApiServer, path: &str, query: &str, accept: Option<&str>) -> (String, bool) {
    api.set_defer_lists(true);
    let (reply, _) = api.handle_w(&req("GET", path, query, accept, ""));
    api.set_defer_lists(false);
    match api.take_list_job() {
        Some(job) => (text(exec::block_on(job.run())).1, true),
        None => (text(reply).1, false),
    }
}

fn inline(api: &ApiServer, path: &str, query: &str, accept: Option<&str>) -> String {
    text(api.handle_w(&req("GET", path, query, accept, "")).0).1
}

fn big_lists_match_their_inline_rendering() {
    kr_rt::offload::init(kr_apiserver::offload::handler, 2);
    let api = ApiServer::new(kr_store::Store::in_memory(), || 1_700_000_000, rng, "127.0.0.1".into()).unwrap();
    // ~1500 pods with some bulk: well over the 256 KB offload threshold.
    for i in 0..1500 {
        let pod = format!(r#"{{"metadata":{{"name":"p{i:04}","namespace":"default","labels":{{"app":"a{}"}},"annotations":{{"note":"{}"}}}},"spec":{{"nodeName":"n{}","containers":[{{"name":"c","image":"registry.example.com/x:{i}"}}]}}}}"#, i % 9, "x".repeat(200), i % 4);
        assert_eq!(text(api.handle_w(&req("POST", "/api/v1/namespaces/default/pods", "", None, &pod)).0).0, 201);
    }
    let table = Some("application/json;as=Table;g=meta.k8s.io;v=v1");
    let partial = Some("application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1");

    let (t_job, used) = deferred(&api, "/api/v1/pods", "", table);
    assert!(used, "a 1500-pod Table list goes to a worker");
    assert_eq!(t_job, inline(&api, "/api/v1/pods", "", table), "Table rows are identical");
    let t: Value = json::parse(t_job.as_bytes()).unwrap();
    assert_eq!(t.get("rows").and_then(Value::as_array).map(|r| r.len()), Some(1500));

    let (p_job, used) = deferred(&api, "/api/v1/pods", "", partial);
    assert!(used);
    assert_eq!(p_job, inline(&api, "/api/v1/pods", "", partial));

    // A small result stays inline.
    let (small, used) = deferred(&api, "/api/v1/namespaces/default/pods/p0001", "", None);
    assert!(!used && small.contains("p0001"));
    let (few, used) = deferred(&api, "/api/v1/pods", "labelSelector=app%3Da3&limit=5", table);
    assert!(!used && few.contains("\"Table\""));

    // Without workers (or when they fail) the same job runs inline: same bytes.
    let (again, _) = deferred(&api, "/api/v1/pods", "", table);
    assert_eq!(again, t_job);
}

fn custom_resources_with_defaults_are_defaulted_in_workers() {
    kr_rt::offload::init(kr_apiserver::offload::handler, 1);
    let api = ApiServer::new(kr_store::Store::in_memory(), || 1_700_000_000, rng, "127.0.0.1".into()).unwrap();
    let crd = r#"{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"widgets.off.example.com"},"spec":{"group":"off.example.com","scope":"Namespaced","names":{"plural":"widgets","singular":"widget","kind":"Widget"},"versions":[{"name":"v1","served":true,"storage":true,"schema":{"openAPIV3Schema":{"type":"object","properties":{"spec":{"type":"object","properties":{"size":{"type":"integer","default":3},"note":{"type":"string"}}}}}}}]}}"#;
    assert_eq!(text(api.handle_w(&req("POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", "", None, crd)).0).0, 201);
    for i in 0..600 {
        let w = format!(r#"{{"apiVersion":"off.example.com/v1","kind":"Widget","metadata":{{"name":"w{i:04}","namespace":"default","annotations":{{"pad":"{}"}}}},"spec":{{"note":"n{i}"}}}}"#, "y".repeat(600));
        assert_eq!(text(api.handle_w(&req("POST", "/apis/off.example.com/v1/namespaces/default/widgets", "", None, &w)).0).0, 201);
    }
    let (job, used) = deferred(&api, "/apis/off.example.com/v1/widgets", "", None);
    assert!(used, "big list of a CRD with defaults goes to a worker");
    assert_eq!(job, inline(&api, "/apis/off.example.com/v1/widgets", "", None));
}

fn audit_body_encoder_matches_the_inline_one() {
    kr_rt::offload::init(kr_apiserver::offload::handler, 1);
    let body = br#"{"kind":"ConfigMap","metadata":{"name":"a","managedFields":[{"manager":"x"}]},"data":{"k":"v"}}"#;
    let mut e = kr_apiserver::offload::Enc::default();
    e.bytes(b"application/json").u8(1).u8(0).bytes(body);
    let payload = e.0.clone();
    let via_worker = exec::block_on(async move { kr_rt::offload::call(kr_apiserver::offload::KIND_AUDIT_BODY, &payload).await.unwrap() });
    let direct = kr_apiserver::offload::handler(kr_apiserver::offload::KIND_AUDIT_BODY, &e.0);
    assert_eq!(via_worker, direct);
    let v: Value = json::parse(&direct).unwrap();
    assert_eq!(v.pointer(&["metadata", "name"]).and_then(Value::as_str), Some("a"));
    assert!(v.pointer(&["metadata", "managedFields"]).is_none(), "managedFields omitted");
    // Secrets are never recorded.
    let secret = br#"{"kind":"Secret","data":{"p":"cw=="}}"#;
    let mut e = kr_apiserver::offload::Enc::default();
    e.bytes(b"application/json").u8(0).u8(0).bytes(secret);
    assert!(kr_apiserver::offload::handler(kr_apiserver::offload::KIND_AUDIT_BODY, &e.0).is_empty());
    // A Table response is not recorded either.
    let tbl = br#"{"kind":"Table","rows":[]}"#;
    let mut e = kr_apiserver::offload::Enc::default();
    e.bytes(b"application/json").u8(0).u8(1).bytes(tbl);
    assert!(kr_apiserver::offload::handler(kr_apiserver::offload::KIND_AUDIT_BODY, &e.0).is_empty());
}

// The executor and the worker pool are process-wide singletons: one test, run in order.
#[test]
fn offloaded_renderings_are_identical_to_inline_ones() {
    big_lists_match_their_inline_rendering();
    custom_resources_with_defaults_are_defaulted_in_workers();
    audit_body_encoder_matches_the_inline_one();
}
