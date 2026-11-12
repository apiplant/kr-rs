//! Default ClusterRoles gain the rules of a newer release at start-up (upstream's RBAC auto-reconcile).

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

fn rules(api: &ApiServer, name: &str) -> String {
    json::to_string(call(api, "GET", &format!("/apis/rbac.authorization.k8s.io/v1/clusterroles/{name}"), "").1.get("rules").unwrap())
}

#[test]
fn stale_default_role_gets_new_rules_but_frozen_and_custom_ones_do_not() {
    let api = ApiServer::new(kr_store::Store::in_memory(), || 1_700_000_000, rng, "127.0.0.1".into()).unwrap();
    let key = kr_crypto::p256::SecretKey::from_bytes(&[7; 32]).unwrap();
    api.set_service_accounts(kr_apiserver::tokens::Signer::new(key), "CA".into()).unwrap();
    assert!(rules(&api, "view").contains("metrics.k8s.io"));
    let put = |name: &str, extra: &str, rules: &str| {
        let (_, mut cur) = call(&api, "GET", &format!("/apis/rbac.authorization.k8s.io/v1/clusterroles/{name}"), "");
        let rv = cur.pointer(&["metadata", "resourceVersion"]).and_then(Value::as_str).unwrap().to_string();
        let body = format!(r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{{"name":"{name}","resourceVersion":"{rv}",{extra}}},"rules":{rules}}}"#);
        let _ = &mut cur;
        assert_eq!(call(&api, "PUT", &format!("/apis/rbac.authorization.k8s.io/v1/clusterroles/{name}"), &body).0, 200);
    };
    let old = r#"[{"apiGroups":[""],"resources":["pods"],"verbs":["get"]}]"#;
    put("view", r#""labels":{"kubernetes.io/bootstrapping":"rbac-defaults"}"#, old);
    put("edit", r#""labels":{"kubernetes.io/bootstrapping":"rbac-defaults"},"annotations":{"rbac.authorization.kubernetes.io/autoupdate":"false"}"#, old);
    put("system:discovery", r#""labels":{"team":"mine"}"#, old);
    api.bootstrap_all();
    let v = rules(&api, "view");
    assert!(v.contains("metrics.k8s.io") && v.contains(r#""resources":["pods"],"verbs":["get"]"#), "{v}");
    assert!(!rules(&api, "edit").contains("metrics.k8s.io"));
    assert_eq!(rules(&api, "system:discovery"), old);
}

#[test]
fn default_bindings_gain_missing_subjects_unless_frozen() {
    let api = ApiServer::new(kr_store::Store::in_memory(), || 1_700_000_000, rng, "127.0.0.1".into()).unwrap();
    let key = kr_crypto::p256::SecretKey::from_bytes(&[7; 32]).unwrap();
    api.set_service_accounts(kr_apiserver::tokens::Signer::new(key), "CA".into()).unwrap();
    let path = |n: &str| format!("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/{n}");
    let subjects = |n: &str| json::to_string(call(&api, "GET", &path(n), "").1.get("subjects").unwrap());
    let put = |name: &str, extra: &str| {
        let (_, cur) = call(&api, "GET", &path(name), "");
        let rv = cur.pointer(&["metadata", "resourceVersion"]).and_then(Value::as_str).unwrap().to_string();
        let role = json::to_string(cur.get("roleRef").unwrap());
        let body = format!(r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{{"name":"{name}","resourceVersion":"{rv}",{extra}}},"roleRef":{role},"subjects":[{{"kind":"User","name":"extra","apiGroup":"rbac.authorization.k8s.io"}}]}}"#);
        assert_eq!(call(&api, "PUT", &path(name), &body).0, 200);
    };
    let label = r#""labels":{"kubernetes.io/bootstrapping":"rbac-defaults"}"#;
    let full = subjects("system:basic-user");
    put("system:basic-user", label);
    put("system:discovery", &format!(r#"{label},"annotations":{{"rbac.authorization.kubernetes.io/autoupdate":"false"}}"#));
    api.bootstrap_all();
    let s = subjects("system:basic-user");
    assert!(s.contains("\"extra\"") && s.contains("system:authenticated"), "kept the extra subject and regained the default: {s}");
    assert!(full.contains("system:authenticated"));
    let frozen = subjects("system:discovery");
    assert!(!frozen.contains("system:authenticated"), "{frozen}");
}

#[test]
fn metrics_endpoint_serves_the_loop_counters_to_admins_only() {
    let api = ApiServer::new(kr_store::Store::in_memory(), || 1_700_000_000, rng, "127.0.0.1".into()).unwrap();
    let key = kr_crypto::p256::SecretKey::from_bytes(&[7; 32]).unwrap();
    api.set_service_accounts(kr_apiserver::tokens::Signer::new(key), "CA".into()).unwrap();
    let get = |user: User| {
        let req = Req { method: "GET", path: "/metrics", query: "", content_type: None, accept: None, body: b"", user: Some(user), bearer: None, headers: &[], authz_verb: None };
        api.handle(&req)
    };
    match get(User { name: "admin".into(), groups: vec!["system:masters".into()] }) {
        Reply::Http(r) => {
            let body = String::from_utf8(match r.body { kr_net::http1::server::Body::Full(b) => b, _ => panic!("body") }).unwrap();
            assert!(body.contains("kr_event_loop_stalls_total ") && body.contains("kr_offload_jobs_total{class=\"slow\"}"), "{body}");
        }
        _ => panic!("expected a raw reply"),
    }
    assert!(matches!(get(User { name: "nobody".into(), groups: vec!["system:authenticated".into()] }), Reply::Json(403, _)));
    assert!(rules(&api, "system:monitoring").contains("/metrics"));
}

#[test]
fn suggested_flow_control_objects_follow_the_release_unless_frozen_or_user_owned() {
    let api = ApiServer::new(kr_store::Store::in_memory(), || 1_700_000_000, rng, "127.0.0.1".into()).unwrap();
    let key = kr_crypto::p256::SecretKey::from_bytes(&[7; 32]).unwrap();
    api.set_service_accounts(kr_apiserver::tokens::Signer::new(key), "CA".into()).unwrap();
    let path = |n: &str| format!("/apis/flowcontrol.apiserver.k8s.io/v1/flowschemas/{n}");
    let prec = |n: &str| call(&api, "GET", &path(n), "").1.pointer(&["spec", "matchingPrecedence"]).and_then(Value::as_i64).unwrap();
    let set = |n: &str, ann: &str| {
        let (_, cur) = call(&api, "GET", &path(n), "");
        let rv = cur.pointer(&["metadata", "resourceVersion"]).and_then(Value::as_str).unwrap().to_string();
        let mut spec = cur.get("spec").unwrap().clone();
        spec.set("matchingPrecedence", Value::from(7777i64));
        let body = format!(r#"{{"apiVersion":"flowcontrol.apiserver.k8s.io/v1","kind":"FlowSchema","metadata":{{"name":"{n}","resourceVersion":"{rv}",{ann}}},"spec":{}}}"#, json::to_string(&spec));
        assert_eq!(call(&api, "PUT", &path(n), &body).0, 200);
    };
    let (ca, cb, cc) = (prec("catch-all"), prec("global-default"), prec("service-accounts"));
    set("catch-all", r#""annotations":{"apf.kubernetes.io/autoupdate-spec":"true"}"#);
    set("global-default", r#""annotations":{"apf.kubernetes.io/autoupdate-spec":"false"}"#);
    set("service-accounts", r#""labels":{"mine":"yes"}"#);
    api.bootstrap_all();
    assert_eq!(prec("catch-all"), ca, "autoupdate-spec true: reset to the release");
    assert_eq!(prec("global-default"), 7777, "autoupdate-spec false: left alone");
    assert_eq!(prec("service-accounts"), 7777, "no annotation: the user's object");
    let _ = (cb, cc);
}

#[test]
fn managed_bootstrap_objects_are_adopted_then_follow_the_release_unless_frozen() {
    let api = ApiServer::new(kr_store::Store::in_memory(), || 1_700_000_000, rng, "127.0.0.1".into()).unwrap();
    let key = kr_crypto::p256::SecretKey::from_bytes(&[7; 32]).unwrap();
    api.set_service_accounts(kr_apiserver::tokens::Signer::new(key), "CA".into()).unwrap();
    let path = |n: &str| format!("/apis/scheduling.k8s.io/v1/priorityclasses/{n}");
    let get = |n: &str| call(&api, "GET", &path(n), "").1;
    let desc = |n: &str| get(n).get("description").and_then(Value::as_str).unwrap().to_string();
    let put = |n: &str, ann: &str, d: &str| {
        let cur = get(n);
        let rv = cur.pointer(&["metadata", "resourceVersion"]).and_then(Value::as_str).unwrap().to_string();
        let v = cur.get("value").and_then(Value::as_i64).unwrap();
        let pp = cur.get("preemptionPolicy").and_then(Value::as_str).map(|p| format!(r#""preemptionPolicy":"{p}","#)).unwrap_or_default();
        let body = format!(r#"{{"apiVersion":"scheduling.k8s.io/v1","kind":"PriorityClass","metadata":{{"name":"{n}","resourceVersion":"{rv}"{ann}}},"value":{v},{pp}"description":"{d}"}}"#);
        let r = call(&api, "PUT", &path(n), &body);
        assert_eq!(r.0, 200, "{}", json::to_string(&r.1));
    };
    let original = desc("system-node-critical");
    // From an earlier release: no annotation. It is adopted, not overwritten.
    put("system-node-critical", "", "edited");
    put("system-cluster-critical", r#","annotations":{"kr.io/autoupdate":"false"}"#, "mine");
    api.bootstrap_all();
    assert_eq!(desc("system-node-critical"), "edited");
    assert_eq!(get("system-node-critical").pointer(&["metadata", "annotations", "kr.io/autoupdate"]).and_then(Value::as_str), Some("true"));
    // Now managed: the next start restores the release's text.
    api.bootstrap_all();
    assert_eq!(desc("system-node-critical"), original);
    assert_eq!(desc("system-cluster-critical"), "mine");
    for r in [("storage.k8s.io", "storageclasses", "local-path"), ("networking.k8s.io", "servicecidrs", "kubernetes")] {
        let o = call(&api, "GET", &format!("/apis/{}/v1/{}/{}", r.0, r.1, r.2), "").1;
        assert_eq!(o.pointer(&["metadata", "annotations", "kr.io/autoupdate"]).and_then(Value::as_str), Some("true"), "{}", r.1);
    }
}
