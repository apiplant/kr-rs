//! First versus later pod status merge patches through `ApiServer::handle` (cold-work check).
use kr_apiserver::api::{ApiServer, Reply, Req, User};
use std::time::Instant;

fn rng(b: &mut [u8]) {
    kr_sys::getrandom(b)
}

fn call(api: &ApiServer, method: &str, path: &str, ct: &str, body: &str) -> u16 {
    let user = Some(User { name: "system:node:n1".into(), groups: vec!["system:masters".into()] });
    let req = Req { method, path, query: "", content_type: Some(ct), accept: None, body: body.as_bytes(), user, bearer: None, headers: &[], authz_verb: None };
    match api.handle(&req) {
        Reply::Json(c, _) => c,
        _ => 0,
    }
}

#[test]
#[ignore]
fn first_status_patch_vs_later() {
    let api = ApiServer::new(kr_store::Store::in_memory(), || 1_700_000_000, rng, "127.0.0.1".into()).unwrap();
    for i in 0..5 {
        let pod = format!(r#"{{"metadata":{{"name":"p{i}","namespace":"default"}},"spec":{{"containers":[{{"name":"c","image":"x"}}]}}}}"#);
        assert_eq!(call(&api, "POST", "/api/v1/namespaces/default/pods", "application/json", &pod), 201);
    }
    for i in 0..5 {
        let patch = format!(r#"{{"status":{{"phase":"Running","podIP":"10.0.0.{i}","conditions":[{{"type":"Ready","status":"True"}}],"containerStatuses":[{{"name":"c","ready":true,"restartCount":0,"image":"x","imageID":"","state":{{"running":{{"startedAt":"2026-11-12T00:00:00Z"}}}}}}]}}}}"#);
        let t = Instant::now();
        let c = call(&api, "PATCH", &format!("/api/v1/namespaces/default/pods/p{i}/status"), "application/merge-patch+json", &patch);
        eprintln!("status patch {i}: {c} in {:?}", t.elapsed());
    }
}
