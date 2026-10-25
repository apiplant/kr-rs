//! CRD conversion: strategy None and a Webhook (HTTPS on loopback), with a mixed-version store.

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
            let desired = r.get("desiredAPIVersion").and_then(Value::as_str).unwrap().to_string();
            let mut out = Vec::new();
            for o in r.get("objects").and_then(Value::as_array).unwrap() {
                let mut o = o.clone();
                if req.path() == "/bad-meta" {
                    o.entry_object("metadata").set("name", Value::from("renamed"));
                }
                // v1 has hostPort "h:p"; v2 has host and port.
                if desired.ends_with("/v2") {
                    if let Some(hp) = o.get("hostPort").and_then(Value::as_str).map(String::from) {
                        let (h, p) = hp.split_once(':').unwrap();
                        o.remove("hostPort");
                        o.set("host", Value::from(h));
                        o.set("port", Value::from(p));
                    }
                } else if let (Some(h), Some(p)) = (o.get("host").and_then(Value::as_str).map(String::from), o.get("port").and_then(Value::as_str).map(String::from)) {
                    o.remove("host");
                    o.remove("port");
                    o.set("hostPort", Value::from(format!("{h}:{p}").as_str()));
                }
                o.set("apiVersion", Value::from(desired.as_str()));
                out.push(o);
            }
            let mut resp = v(&format!(r#"{{"response":{{"uid":"{uid}","result":{{"status":"Success"}}}}}}"#));
            resp.entry_object("response").set("convertedObjects", Value::Array(out));
            let body = json::to_string(&resp);
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


const CRDS: &str = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions";
const CRS: &str = "/apis/conv.example.com";

fn crd(e: &Env, strategy: &str, path: &str, storage: &str) -> Value {
    let conv = if strategy == "Webhook" {
        let ca = kr_fmt::base64::encode(e.ca_pem.as_bytes());
        format!(r#"{{"strategy":"Webhook","webhook":{{"conversionReviewVersions":["v1"],"clientConfig":{{"url":"https://127.0.0.1:{}{path}","caBundle":"{ca}"}}}}}}"#, e.wh_port)
    } else {
        r#"{"strategy":"None"}"#.to_string()
    };
    let ver = |n: &str| format!(r#"{{"name":"{n}","served":true,"storage":{},"schema":{{"openAPIV3Schema":{{"type":"object","x-kubernetes-preserve-unknown-fields":true}}}}}}"#, n == storage);
    v(&format!(
        r#"{{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{{"name":"{p}s.conv.example.com"}},"spec":{{"group":"conv.example.com","scope":"Namespaced","names":{{"plural":"{p}s","singular":"{p}","kind":"{k}","listKind":"{k}List"}},"conversion":{conv},"versions":[{},{}]}}}}"#,
        ver("v1"), ver("v2"), p = if strategy == "Webhook" { if path == "/bad-meta" { "bad" } else { "hook" } } else { "none" }, k = if strategy == "Webhook" { if path == "/bad-meta" { "Bad" } else { "Hook" } } else { "None" }
    ))
}

#[test]
fn conversion() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::thread::Builder::new().stack_size(64 << 20).spawn(run).unwrap().join().unwrap();
}

fn run() {
    block_on(async {
        let e = setup().await;
        let c = Remote::new(&e.url, RemoteAuth::ClientCert { chain: e.chain_pem.clone(), key: e.key_pem.clone() }, &e.ca_pem).unwrap();
        let s = |o: &Value, k: &str| o.get(k).and_then(Value::as_str).map(String::from);
        let cr = |gv: &str, kind: &str, name: &str, extra: &str| v(&format!(r#"{{"apiVersion":"conv.example.com/{gv}","kind":"{kind}","metadata":{{"name":"{name}"}},{extra}}}"#));

        // strategy None: only apiVersion changes, patching through the other version works
        c.create(CRDS, &crd(&e, "None", "", "v1")).await.unwrap();
        sleep(100).await;
        let base = format!("{CRS}/v1/namespaces/default/nones");
        c.create(&base, &cr("v1", "None", "a", r#""data":{"x":"1"}"#)).await.unwrap();
        let got = c.get(&format!("{CRS}/v2/namespaces/default/nones/a")).await.unwrap();
        assert_eq!(s(&got, "apiVersion").as_deref(), Some("conv.example.com/v2"));
        let p = c.patch(&format!("{CRS}/v2/namespaces/default/nones/a"), "application/json-patch+json", &v(r#"[{"op":"add","path":"/dummy","value":"test"}]"#)).await.unwrap();
        assert_eq!((s(&p, "apiVersion").as_deref(), s(&p, "dummy").as_deref()), (Some("conv.example.com/v2"), Some("test")));

        // strategy Webhook
        c.create(CRDS, &crd(&e, "Webhook", "/convert", "v1")).await.unwrap();
        sleep(100).await;
        let v1 = format!("{CRS}/v1/namespaces/default/hooks");
        let v2 = format!("{CRS}/v2/namespaces/default/hooks");
        c.create(&v1, &cr("v1", "Hook", "one", r#""hostPort":"localhost:8080""#)).await.unwrap();
        let got = c.get(&format!("{v2}/one")).await.unwrap();
        assert_eq!(s(&got, "apiVersion").as_deref(), Some("conv.example.com/v2"));
        assert_eq!((s(&got, "host").as_deref(), s(&got, "port").as_deref(), got.get("hostPort")), (Some("localhost"), Some("8080"), None));
        // a write through v2 (stored as v2) and a mixed list in both versions
        c.create(&v2, &cr("v2", "Hook", "two", r#""host":"h","port":"9""#)).await.unwrap();
        for (base, want) in [(&v1, "conv.example.com/v1"), (&v2, "conv.example.com/v2")] {
            let l = c.get(base).await.unwrap();
            let items = l.get("items").and_then(Value::as_array).unwrap();
            assert_eq!(items.len(), 2);
            assert!(items.iter().all(|i| s(i, "apiVersion").as_deref() == Some(want)), "{l:?}");
            assert!(items.iter().all(|i| (want.ends_with("v1")) == i.get("hostPort").is_some()));
        }
        // patching "one" (stored v1) through v2
        let p = c.patch(&format!("{v2}/one"), "application/merge-patch+json", &v(r#"{"dummy":"test"}"#)).await.unwrap();
        assert_eq!((s(&p, "apiVersion").as_deref(), s(&p, "host").as_deref(), s(&p, "dummy").as_deref()), (Some("conv.example.com/v2"), Some("localhost"), Some("test")));
        // a webhook that changes metadata is refused
        c.create(CRDS, &crd(&e, "Webhook", "/bad-meta", "v1")).await.unwrap();
        sleep(100).await;
        let bad1 = format!("{CRS}/v1/namespaces/default/bads");
        c.create(&bad1, &cr("v1", "Bad", "b", r#""hostPort":"x:1""#)).await.unwrap();
        let err = c.get(&format!("{CRS}/v2/namespaces/default/bads/b")).await.unwrap_err();
        assert_eq!(err.code, 500, "{err:?}");
        assert!(err.message.contains("changed the metadata"), "{}", err.message);
    });
}
