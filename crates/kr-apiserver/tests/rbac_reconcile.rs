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
