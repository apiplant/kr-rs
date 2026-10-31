//! Address families of the pod network (`KR_POD_FAMILIES`): node pod CIDRs and Service families.

use kr_apiserver::api::{ApiServer, Reply, Req, User};
use kr_fmt::json::{self, Value};
use kr_net::tcp::Families;

fn rng(b: &mut [u8]) {
    kr_sys::getrandom(b)
}

fn server(f: Families) -> ApiServer {
    let api = ApiServer::new(kr_store::Store::in_memory(), || 1_700_000_000, rng, "127.0.0.1".into()).unwrap();
    api.set_pod_families(f);
    api
}

fn call(api: &ApiServer, method: &str, path: &str, body: &str) -> (u16, Value) {
    let req = Req { method, path, query: "", content_type: Some("application/json"), accept: None, body: body.as_bytes(), user: Some(User { name: "admin".into(), groups: vec!["system:masters".into()] }), bearer: None, headers: &[], authz_verb: None };
    match api.handle(&req) {
        Reply::Json(c, b) => (c, json::parse(b.as_bytes()).unwrap_or(Value::Null)),
        _ => panic!("unexpected reply"),
    }
}

fn node(api: &ApiServer, name: &str) -> Value {
    let (c, v) = call(api, "POST", "/api/v1/nodes", &format!(r#"{{"metadata":{{"name":"{name}"}}}}"#));
    assert_eq!(c, 201, "{v:?}");
    v
}

fn cidrs(n: &Value) -> Vec<String> {
    n.pointer(&["spec", "podCIDRs"]).and_then(Value::as_array).unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect()
}

fn svc(api: &ApiServer, name: &str, extra: &str) -> (u16, Value) {
    call(api, "POST", "/api/v1/namespaces/default/services", &format!(r#"{{"metadata":{{"name":"{name}"}},"spec":{{"ports":[{{"port":80}}]{extra}}}}}"#))
}

#[test]
fn nodes_get_cidrs_for_the_configured_families() {
    for (f, want) in [(Families::DUAL, vec!["10.88.0.0/24", "fd00:88:0::/64"]), (Families::V4, vec!["10.88.0.0/24"]), (Families::V6, vec!["fd00:88:0::/64"])] {
        let api = server(f);
        let a = node(&api, "a");
        assert_eq!(cidrs(&a), want, "{f:?}");
        assert_eq!(a.pointer(&["spec", "podCIDR"]).and_then(Value::as_str), Some(want[0]));
        // The second node gets the next number, in whichever family.
        let b = node(&api, "b");
        let n: Vec<String> = want.iter().map(|c| c.replace("10.88.0.0", "10.88.1.0").replace("fd00:88:0::", "fd00:88:0:1::")).collect();
        assert_eq!(cidrs(&b), n, "{f:?}");
    }
}

#[test]
fn services_follow_the_cluster_families() {
    let v6 = server(Families::V6);
    let (c, s) = svc(&v6, "a", "");
    assert_eq!(c, 201, "{s:?}");
    assert_eq!(s.pointer(&["spec", "ipFamilies"]).map(json::to_string).as_deref(), Some(r#"["IPv6"]"#));
    assert!(s.pointer(&["spec", "clusterIP"]).and_then(Value::as_str).unwrap().starts_with("fd00:96::"));
    let (c, _) = svc(&v6, "b", r#","ipFamilies":["IPv4"]"#);
    assert_eq!(c, 422); // not configured
    let (c, _) = svc(&v6, "c", r#","ipFamilyPolicy":"RequireDualStack""#);
    assert_eq!(c, 422);
    let (c, s) = svc(&v6, "d", r#","ipFamilyPolicy":"PreferDualStack""#);
    assert_eq!(c, 201); // downgraded to single stack
    assert_eq!(s.pointer(&["spec", "clusterIPs"]).and_then(Value::as_array).map(|a| a.len()), Some(1));

    let v4 = server(Families::V4);
    let (c, s) = svc(&v4, "a", r#","ipFamilyPolicy":"PreferDualStack""#);
    assert_eq!(c, 201, "{s:?}");
    assert_eq!(s.pointer(&["spec", "ipFamilies"]).map(json::to_string).as_deref(), Some(r#"["IPv4"]"#));
    let (c, _) = svc(&v4, "b", r#","ipFamilies":["IPv6"]"#);
    assert_eq!(c, 422);

    let dual = server(Families::DUAL);
    let (c, s) = svc(&dual, "a", r#","ipFamilyPolicy":"PreferDualStack""#);
    assert_eq!(c, 201);
    assert_eq!(s.pointer(&["spec", "ipFamilies"]).map(json::to_string).as_deref(), Some(r#"["IPv4","IPv6"]"#));
}

#[test]
fn builtin_services_follow_the_cluster_families() {
    for (f, kube, dns) in [(Families::V6, "fd00:96::1", "fd00:96::a"), (Families::V4, "10.96.0.1", "10.96.0.10")] {
        let api = server(f);
        api.ensure_builtin_services(kr_sys::map4([10, 0, 0, 5]), 6443).unwrap();
        let (_, k) = call(&api, "GET", "/api/v1/namespaces/default/services/kubernetes", "");
        assert_eq!(k.pointer(&["spec", "clusterIP"]).and_then(Value::as_str), Some(kube), "{f:?}");
        let (_, d) = call(&api, "GET", "/api/v1/namespaces/kube-system/services/kube-dns", "");
        assert_eq!(d.pointer(&["spec", "clusterIP"]).and_then(Value::as_str), Some(dns), "{f:?}");
        assert_eq!(d.pointer(&["spec", "clusterIPs"]).and_then(Value::as_array).map(|a| a.len()), Some(1));
    }
}

#[test]
fn nodes_follow_a_changed_setting_and_keep_their_number() {
    let api = server(Families::DUAL);
    node(&api, "a");
    let b = node(&api, "b");
    assert_eq!(cidrs(&b), ["10.88.1.0/24", "fd00:88:0:1::/64"]);
    // The next start runs with IPv6 only: both nodes move, keeping their numbers.
    api.set_pod_families(Families::V6);
    api.ensure_builtin_services(kr_sys::map4([10, 0, 0, 5]), 6443).unwrap();
    let (_, a) = call(&api, "GET", "/api/v1/nodes/a", "");
    let (_, b) = call(&api, "GET", "/api/v1/nodes/b", "");
    assert_eq!(cidrs(&a), ["fd00:88:0::/64"]);
    assert_eq!(cidrs(&b), ["fd00:88:0:1::/64"]);
    assert_eq!(b.pointer(&["spec", "podCIDR"]).and_then(Value::as_str), Some("fd00:88:0:1::/64"));
    // And back to dual stack.
    api.set_pod_families(Families::DUAL);
    api.ensure_builtin_services(kr_sys::map4([10, 0, 0, 5]), 6443).unwrap();
    let (_, b) = call(&api, "GET", "/api/v1/nodes/b", "");
    assert_eq!(cidrs(&b), ["10.88.1.0/24", "fd00:88:0:1::/64"]);
}
