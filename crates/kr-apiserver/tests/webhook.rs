//! Dynamic admission webhooks: the API server over TLS on loopback calling an in-process HTTPS
//! webhook server, all in one executor.

use kr_apiserver::api::ApiServer;
use kr_apiserver::client::{Client, Remote, RemoteAuth};
use kr_crypto::tls::{ClientAuth, ServerConfig as TlsConfig};
use kr_crypto::x509::{self, CertParams, Name, SigningKey};
use kr_fmt::json::{self, Value};
use kr_net::http1::server::{listen, local_addr, serve, HandlerFuture, Request, Response, ServerConfig};
use kr_rt::exec::{block_on, sleep, spawn};
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
            let body = match path.as_str() {
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
    });
}
