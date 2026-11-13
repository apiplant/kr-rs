//! A PUT that leaves out defaulted fields is a no-op: it must not move the generation or the
//! resourceVersion (a Calico operator fought the server over this in a loop of ~20 writes/s).

use kr_apiserver::api::{ApiServer, Reply, Req, User};
use kr_fmt::json::{self, Value};

fn rng(b: &mut [u8]) {
    kr_sys::getrandom(b)
}

fn call(api: &ApiServer, method: &str, path: &str, body: &str) -> (u16, Value) {
    let user = Some(User { name: "admin".into(), groups: vec!["system:masters".into()] });
    let req = Req { method, path, query: "", content_type: Some("application/json"), accept: None, body: body.as_bytes(), user, bearer: None, headers: &[], authz_verb: None };
    match api.handle(&req) {
        Reply::Json(c, b) => (c, json::parse(b.as_bytes()).unwrap_or(Value::Null)),
        _ => panic!("unexpected reply"),
    }
}

#[test]
fn leaving_out_defaulted_fields_changes_nothing() {
    let api = ApiServer::new(kr_store::Store::in_memory(), || 1_700_000_000, rng, "127.0.0.1".into()).unwrap();
    let key = kr_crypto::p256::SecretKey::from_bytes(&[7; 32]).unwrap();
    api.set_service_accounts(kr_apiserver::tokens::Signer::new(key), "CA".into()).unwrap();
    let path = "/apis/apps/v1/namespaces/default/deployments";
    let body = r#"{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"web"},"spec":{"replicas":1,"selector":{"matchLabels":{"a":"b"}},"template":{"metadata":{"labels":{"a":"b"}},"spec":{"containers":[{"name":"c","image":"x"}]}}}}"#;
    assert_eq!(call(&api, "POST", path, body).0, 201);
    let one = |o: &Value, p: &[&str]| o.pointer(p).cloned().unwrap();
    let cur = call(&api, "GET", &format!("{path}/web"), "").1;
    let (gen0, rv0) = (one(&cur, &["metadata", "generation"]), one(&cur, &["metadata", "resourceVersion"]));
    for drop in [&["spec", "strategy"][..], &["spec", "revisionHistoryLimit"], &["spec", "progressDeadlineSeconds"], &["spec", "template", "spec", "dnsPolicy"], &["spec", "template", "spec", "terminationGracePeriodSeconds"]] {
        let mut stripped = cur.clone();
        let (last, parents) = drop.split_last().unwrap();
        let mut node = &mut stripped;
        for p in parents {
            node = node.get_mut(p).unwrap();
        }
        node.remove(last);
        let r = call(&api, "PUT", &format!("{path}/web"), &json::to_string(&stripped));
        assert_eq!(r.0, 200, "{drop:?}");
        let now = call(&api, "GET", &format!("{path}/web"), "").1;
        assert_eq!((one(&now, &["metadata", "generation"]), one(&now, &["metadata", "resourceVersion"])), (gen0.clone(), rv0.clone()), "dropping {drop:?} moved the object");
    }
    // A real change still counts.
    let mut changed = cur.clone();
    changed.get_mut("spec").unwrap().set("replicas", Value::from(2i64));
    assert_eq!(call(&api, "PUT", &format!("{path}/web"), &json::to_string(&changed)).0, 200);
    let now = call(&api, "GET", &format!("{path}/web"), "").1;
    assert_eq!(one(&now, &["metadata", "generation"]).as_i64(), Some(gen0.as_i64().unwrap() + 1));
}
