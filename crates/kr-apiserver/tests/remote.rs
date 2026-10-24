//! `Remote` against a real kr API server over TLS on loopback, in one executor.

use kr_apiserver::api::ApiServer;
use kr_apiserver::client::{Client, Remote, RemoteAuth};
use kr_apiserver::tokens::Signer;
use kr_crypto::tls::{ClientAuth, ServerConfig};
use kr_crypto::x509::{self, CertParams, Name, SigningKey};
use kr_fmt::json::{self, Value};
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

struct Env {
    url: String,
    ca_pem: String,
    chain_pem: String,
    key_pem: String,
    api: Rc<ApiServer>,
}

async fn setup() -> Env {
    let ca_name = n("kr-ca", &[]);
    let ca_key = key(1);
    let ca = cert(&ca_name, 1, &ca_key, true, false, (&ca_name, &ca_key));
    let srv_key = key(2);
    let srv = cert(&n("apiserver", &[]), 2, &srv_key, false, true, (&ca_name, &ca_key));
    let cli_key = key(3);
    let cli = cert(&n("system:node:n1", &["system:masters"]), 3, &cli_key, false, false, (&ca_name, &ca_key));

    let api = Rc::new(ApiServer::new(kr_store::Store::in_memory(), now, rng, "127.0.0.1".into()).unwrap());
    let tls = Rc::new(ServerConfig { cert_chain: vec![srv], key: srv_key, client_auth: ClientAuth::Optional(vec![ca.clone()]), alpn: vec![b"http/1.1".to_vec()] });
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    spawn(kr_apiserver::server::run(api.clone(), [127, 0, 0, 1], port, tls));
    sleep(20).await; // let the listener bind
    Env {
        url: format!("https://127.0.0.1:{port}"),
        ca_pem: x509::pem_encode("CERTIFICATE", &ca),
        chain_pem: x509::pem_encode("CERTIFICATE", &cli),
        key_pem: x509::pem_encode("PRIVATE KEY", &x509::private_key_to_pkcs8(&cli_key)),
        api,
    }
}

fn cert_client(e: &Env) -> Remote {
    Remote::new(&e.url, RemoteAuth::ClientCert { chain: e.chain_pem.clone(), key: e.key_pem.clone() }, &e.ca_pem).unwrap()
}

const CM: &str = "/api/v1/namespaces/default/configmaps";

#[test]
fn crud_patch_and_errors() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    block_on(async {
        let e = setup().await;
        let c = cert_client(&e);
        let created = c.create(CM, &v(r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"a"},"data":{"k":"1"}}"#)).await.unwrap();
        assert_eq!(created.pointer(&["metadata", "name"]).and_then(Value::as_str), Some("a"));

        let got = c.get(&format!("{CM}/a")).await.unwrap();
        assert_eq!(got.pointer(&["data", "k"]).and_then(Value::as_str), Some("1"));

        let list = c.list(CM, "").await.unwrap();
        assert_eq!(list.get("items").and_then(Value::as_array).map(|a| a.len()), Some(1));
        let list = c.list(CM, "labelSelector=nope%3Dx").await.unwrap();
        assert_eq!(list.get("items").and_then(Value::as_array).map(|a| a.len()), Some(0));

        // update (PUT) using the fetched resourceVersion
        let mut upd = got.clone();
        upd.entry_object("data").set("k", Value::from("2"));
        let upd = c.update(&format!("{CM}/a"), &upd).await.unwrap();
        assert_eq!(upd.pointer(&["data", "k"]).and_then(Value::as_str), Some("2"));

        // stale update -> 409 Conflict
        let err = c.update(&format!("{CM}/a"), &got).await.unwrap_err();
        assert_eq!((err.code, err.reason), (409, "Conflict"));

        // all three patch types
        let r = c.patch(&format!("{CM}/a"), "application/merge-patch+json", &v(r#"{"data":{"m":"merge"}}"#)).await.unwrap();
        assert_eq!(r.pointer(&["data", "m"]).and_then(Value::as_str), Some("merge"));
        let r = c.patch(&format!("{CM}/a"), "application/json-patch+json", &v(r#"[{"op":"add","path":"/data/j","value":"json"}]"#)).await.unwrap();
        assert_eq!(r.pointer(&["data", "j"]).and_then(Value::as_str), Some("json"));
        let r = c
            .patch(&format!("{CM}/a"), "application/strategic-merge-patch+json", &v(r#"{"data":{"s":"strategic"}}"#))
            .await
            .unwrap();
        assert_eq!(r.pointer(&["data", "s"]).and_then(Value::as_str), Some("strategic"));
        assert_eq!(r.pointer(&["data", "m"]).and_then(Value::as_str), Some("merge"));

        // errors
        let err = c.get(&format!("{CM}/missing")).await.unwrap_err();
        assert_eq!((err.code, err.reason), (404, "NotFound"));
        assert!(!err.message.is_empty());
        let err = c.create(CM, &v(r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"a"}}"#)).await.unwrap_err();
        assert_eq!((err.code, err.reason), (409, "AlreadyExists"));

        // delete (also with a ?query in the path)
        c.delete(&format!("{CM}/a?gracePeriodSeconds=0")).await.unwrap();
        assert_eq!(c.get(&format!("{CM}/a")).await.unwrap_err().code, 404);

        // connection reuse across many calls
        for i in 0..10 {
            c.list(CM, "").await.unwrap_or_else(|e| panic!("call {i}: {}", e.message));
        }
    });
}

#[test]
fn watch_receives_concurrent_writes() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    block_on(async {
        let e = setup().await;
        let c = cert_client(&e);
        let mut w = c.watch(CM, "").await.unwrap();
        let writer = {
            let c = c.clone();
            spawn(async move {
                sleep(50).await;
                c.create(CM, &v(r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"w"},"data":{"k":"1"}}"#)).await.unwrap();
                sleep(20).await;
                c.patch(&format!("{CM}/w"), "application/merge-patch+json", &v(r#"{"data":{"k":"2"}}"#)).await.unwrap();
                sleep(20).await;
                c.delete(&format!("{CM}/w")).await.unwrap();
            })
        };
        let mut kinds = Vec::new();
        while kinds.len() < 3 {
            let ev = w.next().await.expect("watch ended early");
            assert_eq!(ev.object.pointer(&["metadata", "name"]).and_then(Value::as_str), Some("w"));
            kinds.push(ev.kind);
        }
        assert_eq!(kinds, ["ADDED", "MODIFIED", "DELETED"]);
        writer.await.unwrap();
        // The unary pool is unaffected by the open watch.
        c.list(CM, "").await.unwrap();
    });
}

#[test]
fn watch_replays_from_resource_version_and_ends_at_timeout() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    block_on(async {
        let e = setup().await;
        let c = cert_client(&e);
        c.create(CM, &v(r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"x"}}"#)).await.unwrap();
        // Caller-set timeoutSeconds is respected: the server ends the stream after ~1 s.
        let mut w = c.watch(CM, "resourceVersion=0&timeoutSeconds=1").await.unwrap();
        let ev = w.next().await.unwrap();
        assert_eq!(ev.kind, "ADDED");
        assert!(w.next().await.is_none());
    });
}

#[test]
fn bearer_service_account_is_rbac_checked() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    block_on(async {
        let e = setup().await;
        let signer = Signer::new(kr_crypto::p256::SecretKey::from_bytes(&[9; 32]).unwrap());
        e.api.set_service_accounts(signer, e.ca_pem.clone()).unwrap();
        let admin = cert_client(&e);
        admin.create("/api/v1/namespaces/default/serviceaccounts", &v(r#"{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"sa1"}}"#)).await.unwrap();
        let tr = admin
            .create("/api/v1/namespaces/default/serviceaccounts/sa1/token", &v(r#"{"apiVersion":"authentication.k8s.io/v1","kind":"TokenRequest","spec":{"expirationSeconds":3600}}"#))
            .await
            .unwrap();
        let token = tr.pointer(&["status", "token"]).and_then(Value::as_str).unwrap().to_string();

        let sa = Remote::new(&e.url, RemoteAuth::Bearer(token), &e.ca_pem).unwrap();
        let err = sa.list("/api/v1/namespaces/default/secrets", "").await.unwrap_err();
        assert_eq!((err.code, err.reason), (403, "Forbidden"));
        let err = sa.watch("/api/v1/namespaces/default/secrets", "").await.err().unwrap();
        assert_eq!(err.code, 403);

        // A garbage token is rejected as unauthenticated.
        let bad = Remote::new(&e.url, RemoteAuth::Bearer("nope".into()), &e.ca_pem).unwrap();
        assert_eq!(bad.list(CM, "").await.unwrap_err().code, 401);
    });
}

#[test]
fn transport_errors_are_503() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    block_on(async {
        let e = setup().await;
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let c = Remote::new(&format!("https://127.0.0.1:{port}"), RemoteAuth::ClientCert { chain: e.chain_pem.clone(), key: e.key_pem.clone() }, &e.ca_pem).unwrap();
        assert_eq!(c.get("/api/v1/namespaces").await.unwrap_err().code, 503);
        assert!(Remote::new("https://x", RemoteAuth::Bearer("t".into()), "garbage").is_err());
    });
}

#[test]
fn pods_ephemeralcontainers_subresource() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    block_on(async {
        let e = setup().await;
        let c = cert_client(&e);
        let pods = "/api/v1/namespaces/default/pods";
        c.create(pods, &v(r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p"},"spec":{"containers":[{"name":"app","image":"busybox"}]}}"#)).await.unwrap();
        let sub = format!("{pods}/p/ephemeralcontainers");
        let mp = "application/merge-patch+json";
        let eph = |n: &str, img: &str| format!(r#"{{"name":"{n}","image":"{img}"}}"#);

        // add one; unrelated spec/metadata changes in the same patch are ignored
        let body = format!(r#"{{"metadata":{{"labels":{{"x":"y"}}}},"spec":{{"activeDeadlineSeconds":5,"ephemeralContainers":[{}]}}}}"#, eph("dbg", "busybox"));
        let r = c.patch(&sub, mp, &v(&body)).await.unwrap();
        assert_eq!(r.pointer(&["spec", "ephemeralContainers"]).and_then(Value::as_array).map(|a| a.len()), Some(1));
        assert!(r.pointer(&["spec", "activeDeadlineSeconds"]).is_none());
        assert!(r.pointer(&["metadata", "labels"]).is_none());

        // adding a second keeps the first
        let body = format!(r#"{{"spec":{{"ephemeralContainers":[{},{}]}}}}"#, eph("dbg", "busybox"), eph("dbg2", "busybox"));
        let r = c.patch(&sub, mp, &v(&body)).await.unwrap();
        assert_eq!(r.pointer(&["spec", "ephemeralContainers"]).and_then(Value::as_array).map(|a| a.len()), Some(2));

        // modify existing -> 422
        let body = format!(r#"{{"spec":{{"ephemeralContainers":[{},{}]}}}}"#, eph("dbg", "other"), eph("dbg2", "busybox"));
        assert_eq!(c.patch(&sub, mp, &v(&body)).await.unwrap_err().code, 422);
        // remove existing -> 422
        let body = format!(r#"{{"spec":{{"ephemeralContainers":[{}]}}}}"#, eph("dbg", "busybox"));
        assert_eq!(c.patch(&sub, mp, &v(&body)).await.unwrap_err().code, 422);
        // name clash with a regular container -> 422
        let body = format!(r#"{{"spec":{{"ephemeralContainers":[{},{},{}]}}}}"#, eph("dbg", "busybox"), eph("dbg2", "busybox"), eph("app", "busybox"));
        assert_eq!(c.patch(&sub, mp, &v(&body)).await.unwrap_err().code, 422);

        // PUT through the subresource: only ephemeralContainers is taken from the body
        let mut cur = c.get(&format!("{pods}/p")).await.unwrap();
        cur.entry_object("spec").set("activeDeadlineSeconds", Value::Number(kr_fmt::json::Number::from_u64(9)));
        let r = c.update(&sub, &cur).await.unwrap();
        assert!(r.pointer(&["spec", "activeDeadlineSeconds"]).is_none());
        assert_eq!(r.pointer(&["spec", "ephemeralContainers"]).and_then(Value::as_array).map(|a| a.len()), Some(2));
    });
}
