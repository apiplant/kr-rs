//! ValidatingAdmissionPolicy / MutatingAdmissionPolicy through the admission pass
//! (`webhook::run`, then the request itself), modelled on the upstream e2e tests.

use kr_apiserver::api::{ApiServer, Reply, Req, User};
use kr_apiserver::webhook::{self, Run};
use kr_fmt::json::{self, Value};

fn now() -> i64 {
    1_700_000_000
}

fn rng(b: &mut [u8]) {
    kr_sys::getrandom(b)
}

/// Leaked: `block_on` needs `'static` futures (tests only).
fn server() -> &'static ApiServer {
    Box::leak(Box::new(ApiServer::new(kr_store::Store::in_memory(), now, rng, "127.0.0.1".into()).unwrap()))
}

fn leak(s: &str) -> &'static str {
    Box::leak(s.to_string().into_boxed_str())
}

/// (status, body, warnings) of a request run through admission like the HTTP server does.
fn call(api: &'static ApiServer, method: &str, path: &str, body: &str) -> (u16, Value, Vec<String>) {
    let hdrs: &'static [(String, String)] = Box::leak(Box::new([("User-Agent".to_string(), "e2e.test".to_string())]));
    let (method, path, body) = (leak(method), leak(path), leak(body));
    let user = Some(User { name: "admin".into(), groups: vec!["system:masters".into()] });
    let u2 = user.clone();
    // The executor is process-global and single-threaded; tests run on parallel threads.
    static EXEC: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _g = EXEC.lock().unwrap_or_else(|e| e.into_inner());
    let (r, warns) = kr_rt::exec::block_on(async move {
        let req = Req { method, path, query: "", content_type: Some("application/json"), accept: None, body: body.as_bytes(), user: u2, bearer: None, headers: hdrs, authz_verb: None };
        webhook::run(api, &req).await
    });
    let req = Req { method, path, query: "", content_type: Some("application/json"), accept: None, body: body.as_bytes(), user: user.clone(), bearer: None, headers: hdrs, authz_verb: None };
    let reply = match r {
        Err(reply) => reply,
        Ok(Run::Done(reply)) => reply,
        Ok(Run::Pass(None)) => api.handle(&req),
        Ok(Run::Pass(Some(rw))) => {
            let r2 = Req { method: rw.method, path, query: "", content_type: Some("application/json"), accept: None, body: &rw.body, user, bearer: None, headers: hdrs, authz_verb: None };
            api.handle(&r2)
        }
    };
    match reply {
        Reply::Json(c, b) => (c, json::parse(b.as_bytes()).unwrap_or(Value::Null), warns),
        _ => panic!("unexpected reply"),
    }
}

const AR: &str = "/apis/admissionregistration.k8s.io/v1";

fn setup(api: &'static ApiServer) {
    for (ns, label) in [("t1", true), ("other", false)] {
        let labels = if label { r#","labels":{"t1":"true"}"# } else { "" };
        assert_eq!(call(api, "POST", "/api/v1/namespaces", &format!(r#"{{"metadata":{{"name":"{ns}"{labels}}}}}"#)).0, 201);
    }
}

fn rules() -> &'static str {
    r#""matchConstraints":{"namespaceSelector":{"matchLabels":{"t1":"true"}},"resourceRules":[{"operations":["CREATE","UPDATE"],"apiGroups":["apps"],"apiVersions":["v1"],"resources":["deployments"]}]}"#
}

fn binding(kind: &str, name: &str, policy: &str, actions: &str) -> String {
    let actions = if actions.is_empty() { String::new() } else { format!(r#","validationActions":[{actions}]"#) };
    format!(r#"{{"apiVersion":"admissionregistration.k8s.io/v1","kind":"{kind}","metadata":{{"name":"{name}"}},"spec":{{"policyName":"{policy}","matchResources":{{"namespaceSelector":{{"matchLabels":{{"t1":"true"}}}}}}{actions}}}}}"#)
}

fn deployment(name: &str, replicas: u32) -> String {
    format!(r#"{{"apiVersion":"apps/v1","kind":"Deployment","metadata":{{"name":"{name}","labels":{{"app":"nginx"}}}},"spec":{{"replicas":{replicas},"selector":{{"matchLabels":{{"app":"nginx"}}}},"template":{{"metadata":{{"labels":{{"app":"nginx"}}}},"spec":{{"containers":[{{"name":"nginx","image":"nginx:latest"}}]}}}}}}}}"#)
}

fn replicaset(name: &str, replicas: u32) -> String {
    deployment(name, replicas).replace("\"Deployment\"", "\"ReplicaSet\"")
}

#[test]
fn validating_policy_denies_and_allows() {
    let api = server();
    setup(api);
    let policy = format!(
        r#"{{"metadata":{{"name":"p"}},"spec":{{{},"validations":[{{"expression":"object.spec.replicas > 1","messageExpression":"'wants replicas > 1, got ' + string(object.spec.replicas)"}},{{"expression":"namespaceObject.metadata.name == 't1'","message":"Internal error! Other namespace should not be allowed."}}]}}}}"#,
        rules()
    );
    assert_eq!(call(api, "POST", &format!("{AR}/validatingadmissionpolicies"), &policy).0, 201);
    assert_eq!(call(api, "POST", &format!("{AR}/validatingadmissionpolicybindings"), &binding("ValidatingAdmissionPolicyBinding", "b", "p", r#""Deny""#)).0, 201);

    let (c, v, _) = call(api, "POST", "/apis/apps/v1/namespaces/t1/deployments", &deployment("marker", 1));
    assert_eq!(c, 422, "{v:?}");
    assert_eq!(v.get("reason").and_then(Value::as_str), Some("Invalid"));
    assert_eq!(v.get("message").and_then(Value::as_str), Some("ValidatingAdmissionPolicy 'p' with binding 'b' denied request: wants replicas > 1, got 1"));
    assert_eq!(call(api, "POST", "/apis/apps/v1/namespaces/t1/deployments", &deployment("replicated", 2)).0, 201);
    assert_eq!(call(api, "POST", "/apis/apps/v1/namespaces/t1/replicasets", &replicaset("rs", 1)).0, 201, "other kinds are not matched");
    assert_eq!(call(api, "POST", "/apis/apps/v1/namespaces/other/deployments", &deployment("marker", 1)).0, 201, "unlabelled namespaces are not selected");
    // Updates are matched too.
    let (c, _, _) = call(api, "PUT", "/apis/apps/v1/namespaces/t1/deployments/replicated", &deployment("replicated", 1));
    assert_eq!(c, 422);
}

#[test]
fn variables_and_warn_action() {
    let api = server();
    setup(api);
    let policy = format!(
        r#"{{"metadata":{{"name":"p"}},"spec":{{{},"variables":[{{"name":"replicas","expression":"object.spec.replicas"}},{{"name":"oddReplicas","expression":"variables.replicas % 2 == 1"}}],"validations":[{{"expression":"variables.replicas > 1"}},{{"expression":"variables.oddReplicas"}}]}}}}"#,
        rules()
    );
    assert_eq!(call(api, "POST", &format!("{AR}/validatingadmissionpolicies"), &policy).0, 201);
    assert_eq!(call(api, "POST", &format!("{AR}/validatingadmissionpolicybindings"), &binding("ValidatingAdmissionPolicyBinding", "b", "p", r#""Deny""#)).0, 201);
    let (c, v, _) = call(api, "POST", "/apis/apps/v1/namespaces/t1/deployments", &deployment("one", 1));
    assert_eq!(c, 422);
    assert!(v.get("message").and_then(Value::as_str).unwrap().ends_with("failed expression: variables.replicas > 1"));
    assert_eq!(call(api, "POST", "/apis/apps/v1/namespaces/t1/deployments", &deployment("two", 2)).0, 422, "even count");
    assert_eq!(call(api, "POST", "/apis/apps/v1/namespaces/t1/deployments", &deployment("three", 3)).0, 201);

    // Warn only: admitted, with a warning.
    assert_eq!(call(api, "PUT", &format!("{AR}/validatingadmissionpolicybindings/b"), &binding("ValidatingAdmissionPolicyBinding", "b", "p", r#""Warn""#)).0, 200);
    let (c, _, warns) = call(api, "POST", "/apis/apps/v1/namespaces/t1/deployments", &deployment("four", 4));
    assert_eq!(c, 201);
    assert_eq!(warns, ["Validation failed for ValidatingAdmissionPolicy 'p' with binding 'b': failed expression: variables.oddReplicas"]);
}

#[test]
fn type_checking_status() {
    let api = server();
    let mk = |name: &str, v: &str| format!(r#"{{"metadata":{{"name":"{name}"}},"spec":{{{},"validations":[{v}]}}}}"#, rules());
    let (c, ok, _) = call(api, "POST", &format!("{AR}/validatingadmissionpolicies"), &mk("ok", r#"{"expression":"object.spec.replicas > 1"}"#));
    assert_eq!(c, 201);
    assert_eq!(ok.pointer(&["status", "typeChecking", "expressionWarnings"]).and_then(Value::as_array).map(|a| a.len()), Some(0));
    let (_, bad, _) = call(api, "POST", &format!("{AR}/validatingadmissionpolicies"), &mk("bad", r#"{"expression":"object.spec.replicas > '1'","messageExpression":"'wants replicas > 1, got ' + object.spec.replicas"}"#));
    let w = bad.pointer(&["status", "typeChecking", "expressionWarnings"]).and_then(Value::as_array).unwrap();
    assert_eq!(w.len(), 2, "{w:?}");
    assert_eq!(w[0].get("fieldRef").and_then(Value::as_str), Some("spec.validations[0].expression"));
    assert!(w[0].get("warning").and_then(Value::as_str).unwrap().contains("found no matching overload for '_>_' applied to '(int, string)'"));
    assert_eq!(w[1].get("fieldRef").and_then(Value::as_str), Some("spec.validations[0].messageExpression"));
    assert!(w[1].get("warning").and_then(Value::as_str).unwrap().contains("found no matching overload for '_+_' applied to '(string, int)'"));
    // A GET returns it too (the e2e test polls).
    let (_, got, _) = call(api, "GET", &format!("{AR}/validatingadmissionpolicies/bad"), "");
    assert_eq!(got.pointer(&["status", "typeChecking", "expressionWarnings"]).and_then(Value::as_array).map(|a| a.len()), Some(2));
}

#[test]
fn type_checking_custom_resources() {
    let api = server();
    let crd = r#"{"metadata":{"name":"crontabs.stable.example.com"},"spec":{"group":"stable.example.com","scope":"Namespaced","names":{"plural":"crontabs","singular":"crontab","kind":"CronTab","shortNames":["ct"]},
      "versions":[{"name":"v1","served":true,"storage":true,"schema":{"openAPIV3Schema":{"type":"object","properties":{"spec":{"type":"object","properties":{"cronSpec":{"type":"string"},"image":{"type":"string"},"replicas":{"type":"integer"}}}}}}}]}}"#;
    assert_eq!(call(api, "POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", crd).0, 201);
    let mk = |name: &str, v: &str| format!(r#"{{"metadata":{{"name":"{name}"}},"spec":{{"matchConstraints":{{"resourceRules":[{{"operations":["CREATE","UPDATE"],"apiGroups":["stable.example.com"],"apiVersions":["v1"],"resources":["crontabs"]}}]}},"validations":[{v}]}}}}"#);
    let (_, ok, _) = call(api, "POST", &format!("{AR}/validatingadmissionpolicies"), &mk("ok", r#"{"expression":"object.spec.replicas > 1"}"#));
    assert_eq!(ok.pointer(&["status", "typeChecking", "expressionWarnings"]).and_then(Value::as_array).map(|a| a.len()), Some(0));
    let (_, bad, _) = call(api, "POST", &format!("{AR}/validatingadmissionpolicies"), &mk("bad", r#"{"expression":"object.spec.replicas > '1'","messageExpression":"'wants replicas > 1, got ' + object.spec.replicas"}"#));
    let w = bad.pointer(&["status", "typeChecking", "expressionWarnings"]).and_then(Value::as_array).unwrap();
    assert_eq!(w.len(), 2, "{w:?}");
    assert!(w[0].get("warning").and_then(Value::as_str).unwrap().contains("stable.example.com/v1, Kind=CronTab"));
}

#[test]
fn mutating_policies() {
    let api = server();
    setup(api);
    let mk = |name: &str, m: &str| format!(r#"{{"metadata":{{"name":"{name}"}},"spec":{{"reinvocationPolicy":"Never",{},"mutations":[{m}]}}}}"#, rules());
    let annotate = r#"{"patchType":"ApplyConfiguration","applyConfiguration":{"expression":"Object{\n metadata: Object.metadata{\n annotations: {\n \"mutated-by\": \"admission-policy\"\n }\n }\n }"}}"#;
    assert_eq!(call(api, "POST", &format!("{AR}/mutatingadmissionpolicies"), &mk("annotate", annotate)).0, 201);
    assert_eq!(call(api, "POST", &format!("{AR}/mutatingadmissionpolicybindings"), &binding("MutatingAdmissionPolicyBinding", "annotate", "annotate", "")).0, 201);
    let scale = r#"{"patchType":"ApplyConfiguration","applyConfiguration":{"expression":"Object{spec: Object.spec{replicas: 1337}}"}}"#;
    assert_eq!(call(api, "POST", &format!("{AR}/mutatingadmissionpolicies"), &mk("scale", scale)).0, 201);
    assert_eq!(call(api, "POST", &format!("{AR}/mutatingadmissionpolicybindings"), &binding("MutatingAdmissionPolicyBinding", "scale", "scale", "")).0, 201);
    let jp = r#"{"patchType":"JSONPatch","jsonPatch":{"expression":"[JSONPatch{op: \"add\", path: \"/metadata/labels/patched\", value: \"yes\"}]"}}"#;
    assert_eq!(call(api, "POST", &format!("{AR}/mutatingadmissionpolicies"), &mk("jp", jp)).0, 201);
    assert_eq!(call(api, "POST", &format!("{AR}/mutatingadmissionpolicybindings"), &binding("MutatingAdmissionPolicyBinding", "jp", "jp", "")).0, 201);

    let (c, d, _) = call(api, "POST", "/apis/apps/v1/namespaces/t1/deployments", &deployment("marker", 1));
    assert_eq!(c, 201, "{d:?}");
    assert_eq!(d.pointer(&["metadata", "annotations", "mutated-by"]).and_then(Value::as_str), Some("admission-policy"));
    assert_eq!(d.pointer(&["spec", "replicas"]).and_then(Value::as_u64), Some(1337));
    assert_eq!(d.pointer(&["metadata", "labels", "patched"]).and_then(Value::as_str), Some("yes"));
    assert_eq!(d.pointer(&["metadata", "labels", "app"]).and_then(Value::as_str), Some("nginx"), "apply merges");
    let (_, d, _) = call(api, "POST", "/apis/apps/v1/namespaces/other/deployments", &deployment("marker", 1));
    assert_eq!(d.pointer(&["spec", "replicas"]).and_then(Value::as_u64), Some(1), "unselected namespace");
}
