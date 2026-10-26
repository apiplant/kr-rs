//! Dynamic admission webhooks: the API server over TLS on loopback calling an in-process HTTPS
//! webhook server, all in one executor.

use kr_apiserver::api::ApiServer;
use kr_apiserver::client::{Client, Remote, RemoteAuth};
use kr_crypto::tls::{ClientAuth, ServerConfig as TlsConfig};
use kr_crypto::x509::{self, CertParams, Name, SigningKey};
use kr_fmt::json::{self, Value};
use kr_net::http1::server::{listen, local_addr, serve, HandlerFuture, Request, Response, ServerConfig};
use kr_rt::exec::{block_on, sleep, spawn};
use kr_net::http1::client::{Client as Http, Config as HttpConfig};
use kr_net::tls::TlsConnector;
use std::rc::Rc;
use std::sync::Mutex;

static LOCK: Mutex<()> = Mutex::new(());

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

fn rng(b: &mut [u8]) {
    kr_sys::getrandom(b)
}

fn key(seed: u8) -> SigningKey {
    SigningKey::Ed25519(kr_crypto::ed25519::SigningKey::from_seed(&[seed; 32]))
}

fn cert(name: &Name, serial: u8, k: &SigningKey, ca: bool, server: bool, issuer: (&Name, &SigningKey)) -> Vec<u8> {
    let p = CertParams {
        serial: [serial; 16],
        subject: name.clone(),
        not_before: 1_000_000_000,
        not_after: 4_000_000_000,
        is_ca: ca,
        server,
        client: !server && !ca,
        dns_names: vec![],
        ip_addrs: if server { vec![vec![127, 0, 0, 1]] } else { vec![] },
        public_key: k.public(),
    };
    x509::issue(&p, issuer.0, issuer.1)
}

fn n(cn: &str, o: &[&str]) -> Name {
    Name { common_name: cn.into(), organizations: o.iter().map(|s| s.to_string()).collect() }
}

fn v(s: &str) -> Value {
    json::parse(s.as_bytes()).unwrap()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

thread_local! {
    /// (path, dryRun) of every request the webhook server saw, in order.
    static SEEN: std::cell::RefCell<Vec<(String, bool)>> = const { std::cell::RefCell::new(Vec::new()) };
}

thread_local! {
    /// The last AdmissionRequest per path.
    static LAST: std::cell::RefCell<Vec<(String, Value)>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn last(path: &str) -> Value {
    LAST.with(|s| s.borrow().iter().rev().find(|(p, _)| p == path).map(|(_, r)| r.clone()).unwrap())
}

fn seen(path: &str) -> Vec<bool> {
    SEEN.with(|s| s.borrow().iter().filter(|(p, _)| p == path).map(|(_, d)| *d).collect())
}

/// An HTTPS admission webhook on loopback; behaviour by path.
fn start_webhook(ca_name: &Name, ca_key: &SigningKey) -> u16 {
    let k = key(9);
    let c = cert(&n("webhook", &[]), 9, &k, false, true, (ca_name, ca_key));
    let tls = Rc::new(TlsConfig { cert_chain: vec![c], key: k, client_auth: ClientAuth::None, alpn: vec![b"http/1.1".to_vec()] });
    let l = listen([127, 0, 0, 1], 0, 16).unwrap();
    let port = local_addr(&l).unwrap().1;
    let cfg = Rc::new(ServerConfig { tls: Some(tls), ..ServerConfig::default() });
    let handler = |req: Request| -> HandlerFuture {
        Box::pin(async move {
            let rv = v(std::str::from_utf8(&req.body).unwrap());
            let r = rv.get("request").unwrap();
            let uid = r.get("uid").and_then(Value::as_str).unwrap().to_string();
            let path = req.path().to_string();
            SEEN.with(|s| s.borrow_mut().push((path.clone(), r.get("dryRun").and_then(Value::as_bool).unwrap_or(false))));
            LAST.with(|s| s.borrow_mut().push((path.clone(), r.clone())));
            let body = match path.as_str() {
                "/deny-keep" if r.get("name").and_then(Value::as_str) == Some("keep") => format!(r#"{{"response":{{"uid":"{uid}","allowed":false,"status":{{"message":"keep it"}}}}}}"#),
                "/deny-exec" => format!(r#"{{"response":{{"uid":"{uid}","allowed":false,"status":{{"message":"no exec"}}}}}}"#),
                "/warn" => format!(r#"{{"response":{{"uid":"{uid}","allowed":true,"warnings":["careful","say \"hi\""]}}}}"#),
                "/deny" => format!(r#"{{"response":{{"uid":"{uid}","allowed":false,"status":{{"message":"no way"}}}}}}"#),
                "/mutate" => {
                    let p = kr_fmt::base64::encode(br#"[{"op":"add","path":"/data/mutated","value":"yes"}]"#);
                    format!(r#"{{"response":{{"uid":"{uid}","allowed":true,"patchType":"JSONPatch","patch":"{p}"}}}}"#)
                }
                "/slow" => {
                    sleep(2500).await;
                    format!(r#"{{"response":{{"uid":"{uid}","allowed":true}}}}"#)
                }
                _ => format!(r#"{{"response":{{"uid":"{uid}","allowed":true}}}}"#),
            };
            Response::new(200, body.into_bytes()).with_header("Content-Type", "application/json")
        })
    };
    spawn(async move {
        let _ = serve(l, cfg, Rc::new(handler)).await;
    });
    port
}

struct Env {
    url: String,
    ca_pem: String,
    wh_port: u16,
    chain_pem: String,
    key_pem: String,
    /// A non-admin user ("patcher"), for RBAC checks.
    patcher: (String, String),
}

async fn setup() -> Env {
    let ca_name = n("kr-ca", &[]);
    let ca_key = key(1);
    let ca = cert(&ca_name, 1, &ca_key, true, false, (&ca_name, &ca_key));
    let srv_key = key(2);
    let srv = cert(&n("apiserver", &[]), 2, &srv_key, false, true, (&ca_name, &ca_key));
    let cli_key = key(3);
    let cli = cert(&n("admin", &["system:masters"]), 3, &cli_key, false, false, (&ca_name, &ca_key));
    let wh_port = start_webhook(&ca_name, &ca_key);
    let p_key = key(4);
    let p_cert = cert(&n("patcher", &[]), 4, &p_key, false, false, (&ca_name, &ca_key));

    let api = Rc::new(ApiServer::new(kr_store::Store::in_memory(), now, rng, "127.0.0.1".into()).unwrap());
    let tls = Rc::new(TlsConfig { cert_chain: vec![srv], key: srv_key, client_auth: ClientAuth::Optional(vec![ca.clone()]), alpn: vec![b"http/1.1".to_vec()] });
    let port = free_port();
    spawn(kr_apiserver::server::run(api, [127, 0, 0, 1], port, tls));
    sleep(20).await; // let the listeners bind
    Env {
        url: format!("https://127.0.0.1:{port}"),
        ca_pem: x509::pem_encode("CERTIFICATE", &ca),
        wh_port,
        chain_pem: x509::pem_encode("CERTIFICATE", &cli),
        key_pem: x509::pem_encode("PRIVATE KEY", &x509::private_key_to_pkcs8(&cli_key)),
        patcher: (x509::pem_encode("CERTIFICATE", &p_cert), x509::pem_encode("PRIVATE KEY", &x509::private_key_to_pkcs8(&p_key))),
    }
}

const CM: &str = "/api/v1/namespaces/default/configmaps";
const VWC: &str = "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations";
const MWC: &str = "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations";

fn cm(name: &str) -> Value {
    v(&format!(r#"{{"apiVersion":"v1","kind":"ConfigMap","metadata":{{"name":"{name}"}},"data":{{"k":"1"}}}}"#))
}

/// A webhook entry for configmaps; `extra` is appended inside the object (starts with a comma).
fn wh(e: &Env, path: &str, extra: &str) -> String {
    let ca = kr_fmt::base64::encode(e.ca_pem.as_bytes());
    format!(
        r#"{{"name":"w.example.com","clientConfig":{{"url":"https://127.0.0.1:{}{path}","caBundle":"{ca}"}},"rules":[{{"operations":["CREATE","UPDATE","DELETE"],"apiGroups":[""],"apiVersions":["v1"],"resources":["configmaps"]}}],"sideEffects":"None","admissionReviewVersions":["v1"]{extra}}}"#,
        e.wh_port
    )
}

async fn install(c: &Remote, base: &str, name: &str, webhooks: &[String]) {
    let kind = if base == VWC { "ValidatingWebhookConfiguration" } else { "MutatingWebhookConfiguration" };
    let o = v(&format!(r#"{{"apiVersion":"admissionregistration.k8s.io/v1","kind":"{kind}","metadata":{{"name":"{name}"}},"webhooks":[{}]}}"#, webhooks.join(",")));
    c.create(base, &o).await.unwrap();
}

async fn uninstall(c: &Remote, base: &str, name: &str) {
    c.delete(&format!("{base}/{name}")).await.unwrap();
}

#[test]
fn webhooks() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Unoptimized async state machines are large; give the executor thread room.
    std::thread::Builder::new().stack_size(64 << 20).spawn(run).unwrap().join().unwrap();
}

fn run() {
    block_on(async {
        let e = setup().await;
        let c = Remote::new(&e.url, RemoteAuth::ClientCert { chain: e.chain_pem.clone(), key: e.key_pem.clone() }, &e.ca_pem).unwrap();
        let data = |o: &Value, k: &str| o.pointer(&["data", k]).and_then(Value::as_str).map(String::from);

        // deny
        install(&c, VWC, "deny", &[wh(&e, "/deny", "")]).await;
        let err = c.create(CM, &cm("a")).await.unwrap_err();
        assert_eq!(err.code, 403, "{err:?}");
        assert_eq!(err.message, "admission webhook \"w.example.com\" denied the request: no way");
        assert_eq!(c.get(&format!("{CM}/a")).await.unwrap_err().code, 404);
        // admissionregistration objects are exempt, even from a catch-all webhook
        let all = wh(&e, "/deny", "").replace(r#""apiGroups":[""]"#, r#""apiGroups":["*"]"#).replace(r#""resources":["configmaps"]"#, r#""resources":["*"]"#);
        install(&c, VWC, "catchall", &[all]).await;
        uninstall(&c, VWC, "catchall").await;
        uninstall(&c, VWC, "deny").await;
        c.create(CM, &cm("a")).await.unwrap();

        // mutate: create, update and patch
        install(&c, MWC, "mut", &[wh(&e, "/mutate", "")]).await;
        let o = c.create(CM, &cm("b")).await.unwrap();
        assert_eq!(data(&o, "mutated").as_deref(), Some("yes"));
        let got = c.get(&format!("{CM}/b")).await.unwrap();
        assert_eq!(data(&got, "mutated").as_deref(), Some("yes"));
        let mut upd = got.clone();
        upd.entry_object("data").set("k", Value::from("2"));
        upd.entry_object("data").remove("mutated");
        let o = c.update(&format!("{CM}/b"), &upd).await.unwrap();
        assert_eq!((data(&o, "k").as_deref(), data(&o, "mutated").as_deref()), (Some("2"), Some("yes")));
        let o = c.patch(&format!("{CM}/a"), "application/merge-patch+json", &v(r#"{"data":{"p":"1"}}"#)).await.unwrap();
        assert_eq!((data(&o, "p").as_deref(), data(&o, "mutated").as_deref()), (Some("1"), Some("yes")));
        // A mutated PATCH is replayed as PUT but authorized as "patch": a patch-only user passes.
        c.create("/apis/rbac.authorization.k8s.io/v1/namespaces/default/roles", &v(r#"{"metadata":{"name":"patch-cm"},"rules":[{"apiGroups":[""],"resources":["configmaps"],"verbs":["get","patch"]}]}"#)).await.unwrap();
        c.create("/apis/rbac.authorization.k8s.io/v1/namespaces/default/rolebindings", &v(r#"{"metadata":{"name":"patch-cm"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"patch-cm"},"subjects":[{"kind":"User","apiGroup":"rbac.authorization.k8s.io","name":"patcher"}]}"#)).await.unwrap();
        let pc = Remote::new(&e.url, RemoteAuth::ClientCert { chain: e.patcher.0.clone(), key: e.patcher.1.clone() }, &e.ca_pem).unwrap();
        let o = pc.patch(&format!("{CM}/a"), "application/merge-patch+json", &v(r#"{"data":{"q":"1"}}"#)).await.unwrap();
        assert_eq!((data(&o, "q").as_deref(), data(&o, "mutated").as_deref()), (Some("1"), Some("yes")));
        let mut u = o.clone();
        u.entry_object("data").set("r", Value::from("1"));
        assert_eq!(pc.update(&format!("{CM}/a"), &u).await.unwrap_err().code, 403);
        // validating webhooks also see create/delete after mutation
        install(&c, VWC, "deny", &[wh(&e, "/deny", "")]).await;
        assert_eq!(c.create(CM, &cm("c")).await.unwrap_err().code, 403);
        assert_eq!(c.delete(&format!("{CM}/b")).await.unwrap_err().code, 403);
        uninstall(&c, VWC, "deny").await;
        uninstall(&c, MWC, "mut").await;

        // failurePolicy with the webhook down
        let dead = free_port();
        let down = wh(&e, "/deny", "").replace(&e.wh_port.to_string(), &dead.to_string());
        install(&c, VWC, "down", &[down.clone()]).await;
        let err = c.create(CM, &cm("d")).await.unwrap_err();
        assert_eq!(err.code, 500);
        assert!(err.message.contains("failed calling webhook \"w.example.com\""), "{}", err.message);
        uninstall(&c, VWC, "down").await;
        install(&c, VWC, "down", &[down.replace("\"admissionReviewVersions\"", "\"failurePolicy\":\"Ignore\",\"admissionReviewVersions\"")]).await;
        c.create(CM, &cm("d")).await.unwrap();
        uninstall(&c, VWC, "down").await;

        // timeout
        let slow = |extra: &str| wh(&e, "/slow", &format!(r#","timeoutSeconds":1{extra}"#));
        install(&c, VWC, "slow", &[slow("")]).await;
        let err = c.create(CM, &cm("e")).await.unwrap_err();
        assert!(err.message.contains("deadline exceeded"), "{}", err.message);
        uninstall(&c, VWC, "slow").await;
        install(&c, VWC, "slow", &[slow(r#","failurePolicy":"Ignore""#)]).await;
        c.create(CM, &cm("e")).await.unwrap();
        uninstall(&c, VWC, "slow").await;

        // objectSelector and namespaceSelector
        let sel = wh(&e, "/deny", r#","objectSelector":{"matchLabels":{"deny":"yes"}},"namespaceSelector":{"matchExpressions":[{"key":"env","operator":"In","values":["prod"]}]}"#);
        install(&c, VWC, "sel", &[sel]).await;
        c.create("/api/v1/namespaces", &v(r#"{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"prod","labels":{"env":"prod"}}}"#)).await.unwrap();
        let labelled = |n: &str| v(&format!(r#"{{"apiVersion":"v1","kind":"ConfigMap","metadata":{{"name":"{n}","labels":{{"deny":"yes"}}}}}}"#));
        c.create(CM, &labelled("l1")).await.unwrap(); // default namespace has no env=prod label
        c.create("/api/v1/namespaces/prod/configmaps", &cm("l2")).await.unwrap(); // object not labelled
        assert_eq!(c.create("/api/v1/namespaces/prod/configmaps", &labelled("l3")).await.unwrap_err().code, 403);
        uninstall(&c, VWC, "sel").await;

        // matchConditions
        let mc = wh(&e, "/deny", r#","matchConditions":[{"name":"skip","expression":"!(object.metadata.name.startsWith('skip'))"}]"#);
        install(&c, VWC, "mc", &[mc]).await;
        c.create(CM, &cm("skip-me")).await.unwrap();
        assert_eq!(c.create(CM, &cm("other")).await.unwrap_err().code, 403);
        uninstall(&c, VWC, "mc").await;

        // dryRun and sideEffects
        let before = seen("/allow").len();
        install(&c, VWC, "se", &[wh(&e, "/allow", "").replace("\"None\"", "\"Unknown\"")]).await;
        c.create(CM, &cm("s1")).await.unwrap();
        let err = c.create(&format!("{CM}?dryRun=All"), &cm("s2")).await.unwrap_err();
        assert_eq!(err.code, 400);
        assert!(err.message.contains("does not support dry run"), "{}", err.message);
        uninstall(&c, VWC, "se").await;
        install(&c, VWC, "se", &[wh(&e, "/allow", "").replace("\"None\"", "\"NoneOnDryRun\"")]).await;
        c.create(&format!("{CM}?dryRun=All"), &cm("s3")).await.unwrap();
        assert_eq!(c.get(&format!("{CM}/s3")).await.unwrap_err().code, 404);
        assert_eq!(seen("/allow")[before..], [false, true]);
        uninstall(&c, VWC, "se").await;

        // matchPolicy: Equivalent (default) ignores the rule's version; Exact does not
        let v9 = wh(&e, "/deny", "").replace(r#""apiVersions":["v1"]"#, r#""apiVersions":["v9"]"#);
        install(&c, VWC, "eq", &[v9.clone()]).await;
        assert_eq!(c.create(CM, &cm("m1")).await.unwrap_err().code, 403);
        uninstall(&c, VWC, "eq").await;
        install(&c, VWC, "eq", &[v9.replace("\"admissionReviewVersions\"", "\"matchPolicy\":\"Exact\",\"admissionReviewVersions\"")]).await;
        c.create(CM, &cm("m1")).await.unwrap();
        uninstall(&c, VWC, "eq").await;

        // reinvocationPolicy: IfNeeded runs again after a later webhook changed the object
        let before = seen("/ra").len();
        install(&c, MWC, "1-a", &[wh(&e, "/ra", "")]).await;
        install(&c, MWC, "2-b", &[wh(&e, "/mutate", "")]).await;
        c.create(CM, &cm("r1")).await.unwrap();
        assert_eq!(seen("/ra").len() - before, 1);
        uninstall(&c, MWC, "1-a").await;
        install(&c, MWC, "1-a", &[wh(&e, "/ra", r#","reinvocationPolicy":"IfNeeded""#)]).await;
        c.create(CM, &cm("r2")).await.unwrap();
        assert_eq!(seen("/ra").len() - before, 3);
        uninstall(&c, MWC, "1-a").await;
        uninstall(&c, MWC, "2-b").await;

        // DELETE collection: one admission per item; a denied item stays, the rest go
        for n in ["dc1", "dc2", "keep"] {
            let mut o = cm(n);
            o.entry_object("metadata").set("labels", v(r#"{"g":"1"}"#));
            c.create(CM, &o).await.unwrap();
        }
        let before = seen("/deny-keep").len();
        install(&c, VWC, "dc", &[wh(&e, "/deny-keep", "")]).await;
        let err = c.delete(&format!("{CM}?labelSelector=g%3D1")).await.unwrap_err();
        assert_eq!(err.code, 403, "{err:?}");
        assert!(err.message.contains("keep it"), "{}", err.message);
        assert_eq!(seen("/deny-keep").len() - before, 3);
        assert_eq!(c.get(&format!("{CM}/dc1")).await.unwrap_err().code, 404);
        assert_eq!(c.get(&format!("{CM}/dc2")).await.unwrap_err().code, 404);
        c.get(&format!("{CM}/keep")).await.unwrap();
        uninstall(&c, VWC, "dc").await;
        let l = c.delete(&format!("{CM}?labelSelector=g%3D1")).await.unwrap();
        assert_eq!(l.get("items").and_then(Value::as_array).map(|a| a.len()), Some(1));

        // response warnings become Warning headers
        install(&c, VWC, "warn", &[wh(&e, "/warn", "")]).await;
        let (code, warnings) = raw(&e, "POST", CM, &cm("w1")).await;
        assert_eq!(code, 201);
        assert_eq!(warnings, ["299 - \"careful\"", "299 - \"say \\\"hi\\\"\""]);
        uninstall(&c, VWC, "warn").await;

        // subresources: CONNECT with options, scale, token
        let sub = |path: &str, ops: &str, group: &str, res: &str| {
            wh(&e, path, "").replace(r#""operations":["CREATE","UPDATE","DELETE"]"#, &format!(r#""operations":[{ops}]"#)).replace(r#""apiGroups":[""]"#, &format!(r#""apiGroups":["{group}"]"#)).replace(r#""resources":["configmaps"]"#, &format!(r#""resources":["{res}"]"#))
        };
        install(&c, VWC, "exec", &[sub("/deny-exec", r#""CONNECT""#, "", "pods/exec")]).await;
        let err = c.create("/api/v1/namespaces/default/pods/nopod/exec?command=ls&command=-l&container=main&stdout=true", &v("{}")).await.unwrap_err();
        assert_eq!(err.code, 403, "{err:?}");
        assert!(err.message.contains("no exec"), "{}", err.message);
        let r = last("/deny-exec");
        let s = |p: &[&str]| r.pointer(p).and_then(Value::as_str).map(String::from);
        assert_eq!((s(&["operation"]).as_deref(), s(&["subResource"]).as_deref(), s(&["kind", "kind"]).as_deref(), s(&["name"]).as_deref()), (Some("CONNECT"), Some("exec"), Some("PodExecOptions"), Some("nopod")));
        // The connect options are the object (agnhost's attach webhook reads them there) and the options.
        assert_eq!(r.get("object"), r.get("options"));
        let o = r.get("options").unwrap();
        assert_eq!((o.get("kind").and_then(Value::as_str), o.get("container").and_then(Value::as_str), o.get("stdout").and_then(Value::as_bool), o.get("tty").and_then(Value::as_bool)), (Some("PodExecOptions"), Some("main"), Some(true), Some(false)));
        assert_eq!(json::to_string(o.get("command").unwrap()), r#"["ls","-l"]"#);
        // Authorization comes first: a user without pods/exec gets RBAC's 403 and the webhook
        // never sees the request.
        let calls = seen("/deny-exec").len();
        let pc = Remote::new(&e.url, RemoteAuth::ClientCert { chain: e.patcher.0.clone(), key: e.patcher.1.clone() }, &e.ca_pem).unwrap();
        let err = pc.create("/api/v1/namespaces/default/pods/nopod/exec?command=ls&container=main&stdout=true", &v("{}")).await.unwrap_err();
        assert_eq!(err.code, 403, "{err:?}");
        assert!(!err.message.contains("no exec"), "the webhook answered instead of RBAC: {}", err.message);
        assert_eq!(seen("/deny-exec").len(), calls, "an unauthorized request reached the webhook");
        uninstall(&c, VWC, "exec").await;

        let dep = v(r#"{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"d"},"spec":{"replicas":1,"selector":{"matchLabels":{"a":"b"}},"template":{"metadata":{"labels":{"a":"b"}},"spec":{"containers":[{"name":"c","image":"i"}]}}}}"#);
        c.create("/apis/apps/v1/namespaces/default/deployments", &dep).await.unwrap();
        install(&c, VWC, "scale", &[sub("/deny", r#""UPDATE""#, "apps", "deployments/scale")]).await;
        let sc = v(r#"{"apiVersion":"autoscaling/v1","kind":"Scale","metadata":{"name":"d"},"spec":{"replicas":3}}"#);
        let err = c.update("/apis/apps/v1/namespaces/default/deployments/d/scale", &sc).await.unwrap_err();
        assert_eq!(err.code, 403, "{err:?}");
        let r = last("/deny");
        assert_eq!((r.pointer(&["kind", "kind"]).and_then(Value::as_str), r.pointer(&["object", "spec", "replicas"]).and_then(Value::as_i64), r.pointer(&["oldObject", "spec", "replicas"]).and_then(Value::as_i64)), (Some("Scale"), Some(3), Some(1)));
        uninstall(&c, VWC, "scale").await;
        let got = c.get("/apis/apps/v1/namespaces/default/deployments/d").await.unwrap();
        assert_eq!(got.pointer(&["spec", "replicas"]).and_then(Value::as_i64), Some(1));

        c.create("/api/v1/namespaces/default/serviceaccounts", &v(r#"{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"sa1"}}"#)).await.unwrap();
        install(&c, VWC, "token", &[sub("/deny", r#""CREATE""#, "", "serviceaccounts/token")]).await;
        let err = c.create("/api/v1/namespaces/default/serviceaccounts/sa1/token", &v(r#"{"spec":{"audiences":["x"]}}"#)).await.unwrap_err();
        assert_eq!(err.code, 403, "{err:?}");
        let r = last("/deny");
        assert_eq!((r.pointer(&["kind", "kind"]).and_then(Value::as_str), r.pointer(&["kind", "group"]).and_then(Value::as_str), r.pointer(&["subResource"]).and_then(Value::as_str)), (Some("TokenRequest"), Some("authentication.k8s.io"), Some("token")));
        uninstall(&c, VWC, "token").await;
    });
}

/// One request with the admin client certificate: the status and the `Warning` headers.
async fn raw(e: &Env, method: &str, path: &str, body: &Value) -> (u16, Vec<String>) {
    let chain = x509::pem_decode_all(&e.chain_pem, "CERTIFICATE").unwrap();
    let k = x509::private_key_from_pkcs8(&x509::pem_decode_all(&e.key_pem, "PRIVATE KEY").unwrap()[0]).unwrap();
    let roots = x509::pem_decode_all(&e.ca_pem, "CERTIFICATE").unwrap();
    let cfg = Rc::new(kr_crypto::tls::ClientConfig { pinned_ca: None, roots, client_cert: Some((chain, k)), alpn: vec![b"http/1.1".to_vec()], tls12: false });
    let http = Http::with_connector(TlsConnector::new(kr_net::dns::SystemResolver::system(), cfg), HttpConfig::default());
    let mut resp = http.request(method, &format!("{}{path}", e.url), &[("Content-Type", "application/json")], json::to_string(body).as_bytes()).await.unwrap();
    let _ = resp.read_to_end(1 << 20).await;
    (resp.status, resp.headers().iter().filter(|(n, _)| n.eq_ignore_ascii_case("warning")).map(|(_, v)| v.clone()).collect())
}
