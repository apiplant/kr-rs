//! OIDC (JWT) and webhook token authentication, webhook authorization and the optional
//! admission plugins (#362): the API server over TLS on loopback, an in-process HTTPS OIDC
//! issuer (discovery + JWKS) and an HTTPS TokenReview/SubjectAccessReview webhook.

use kr_apiserver::api::{ApiServer, Reply, Req, User};
use kr_apiserver::extauth::{self, Authorizer, AuthorizerSpec, TokenWebhook, WebhookClient};
use kr_crypto::tls::{ClientAuth, ServerConfig as TlsConfig};
use kr_crypto::x509::{self, CertParams, Name, SigningKey};
use kr_fmt::json::{self, Value};
use kr_net::http1::client::{Client as Http, Config as HttpConfig};
use kr_net::http1::server::{listen, local_addr, serve, HandlerFuture, Request, Response, ServerConfig};
use kr_net::tls::TlsConnector;
use kr_rt::exec::{block_on, sleep, spawn};
use std::cell::{Cell, RefCell};
use std::rc::Rc;

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

fn rng(b: &mut [u8]) {
    kr_sys::getrandom(b)
}

fn key(seed: u8) -> SigningKey {
    SigningKey::Ed25519(kr_crypto::ed25519::SigningKey::from_seed(&[seed; 32]))
}

fn n(cn: &str, o: &[&str]) -> Name {
    Name { common_name: cn.into(), organizations: o.iter().map(|s| s.to_string()).collect() }
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

fn b64(b: &[u8]) -> String {
    kr_fmt::base64::encode_url(b)
}

thread_local! {
    static JWKS: RefCell<String> = const { RefCell::new(String::new()) };
    static JWKS_FETCHES: Cell<u32> = const { Cell::new(0) };
    static TOKEN_REVIEWS: Cell<u32> = const { Cell::new(0) };
    static SARS: RefCell<Vec<Value>> = const { RefCell::new(Vec::new()) };
}

/// An HTTPS server on loopback answering by path.
fn https(ca: (&Name, &SigningKey), seed: u8, handler: fn(Request) -> HandlerFuture) -> u16 {
    let k = key(seed);
    let c = cert(&n("srv", &[]), seed, &k, false, true, ca);
    let tls = Rc::new(TlsConfig { cert_chain: vec![c], key: k, client_auth: ClientAuth::None, alpn: vec![b"http/1.1".to_vec()] });
    let l = listen([127, 0, 0, 1], 0, 16).unwrap();
    let port = local_addr(&l).unwrap().1;
    let cfg = Rc::new(ServerConfig { tls: Some(tls), ..ServerConfig::default() });
    spawn(async move {
        let _ = serve(l, cfg, Rc::new(handler)).await;
    });
    port
}

fn issuer_handler(req: Request) -> HandlerFuture {
    Box::pin(async move {
        let host = req.header("host").unwrap_or("").to_string();
        match req.path() {
            "/.well-known/openid-configuration" => Response::new(200, format!(r#"{{"issuer":"https://{host}","jwks_uri":"https://{host}/keys"}}"#).into_bytes()),
            "/keys" => {
                JWKS_FETCHES.with(|c| c.set(c.get() + 1));
                Response::new(200, JWKS.with(|j| j.borrow().clone()).into_bytes())
            }
            _ => Response::new(404, Vec::new()),
        }
    })
}

/// `/authn`: "opaque-good" is `hook-user`. `/authz`: `oidc:jane` and `hook-user` may list
/// configmaps; secrets are explicitly denied; anything else has no opinion.
fn webhook_handler(req: Request) -> HandlerFuture {
    Box::pin(async move {
        let v = json::parse(&req.body).unwrap();
        let body = match req.path() {
            "/authn" => {
                TOKEN_REVIEWS.with(|c| c.set(c.get() + 1));
                if v.pointer(&["spec", "token"]).and_then(Value::as_str) == Some("opaque-good") {
                    r#"{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","status":{"authenticated":true,"user":{"username":"hook-user","groups":["hookers"]}}}"#.to_string()
                } else {
                    r#"{"status":{"authenticated":false}}"#.to_string()
                }
            }
            _ => {
                SARS.with(|s| s.borrow_mut().push(v.clone()));
                let user = v.pointer(&["spec", "user"]).and_then(Value::as_str).unwrap_or("");
                let res = v.pointer(&["spec", "resourceAttributes", "resource"]).and_then(Value::as_str).unwrap_or("");
                let (allowed, denied) = match res {
                    "configmaps" if user == "oidc:jane" || user == "hook-user" => (true, false),
                    "secrets" => (false, true),
                    _ => (false, false),
                };
                format!(r#"{{"status":{{"allowed":{allowed},"denied":{denied}}}}}"#)
            }
        };
        Response::new(200, body.into_bytes()).with_header("Content-Type", "application/json")
    })
}

fn es256(k: &kr_crypto::p256::SecretKey, kid: &str, claims: &str) -> String {
    let input = format!("{}.{}", b64(format!(r#"{{"alg":"ES256","typ":"JWT","kid":"{kid}"}}"#).as_bytes()), b64(claims.as_bytes()));
    let (r, s) = k.sign(input.as_bytes());
    format!("{input}.{}", b64(&[r, s].concat()))
}

fn jwk(k: &kr_crypto::p256::SecretKey, kid: &str) -> String {
    let pk = k.public_key();
    format!(r#"{{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","kid":"{kid}","x":"{}","y":"{}"}}"#, b64(&pk[1..33]), b64(&pk[33..]))
}

async fn get(url: &str, ca_pem: &str, bearer: &str) -> u16 {
    let roots = x509::pem_decode_all(ca_pem, "CERTIFICATE").unwrap();
    let cfg = Rc::new(kr_crypto::tls::ClientConfig { pinned_ca: None, roots, client_cert: None, alpn: vec![b"http/1.1".to_vec()], tls12: false });
    let http = Http::with_connector(TlsConnector::new(kr_net::dns::SystemResolver::system(), cfg), HttpConfig::default());
    let auth = format!("Bearer {bearer}");
    let mut r = http.request("GET", url, &[("Authorization", &auth)], b"").await.unwrap();
    let _ = r.read_to_end(1 << 20).await;
    r.status
}

#[test]
fn oidc_and_webhooks() {
    std::thread::Builder::new().stack_size(64 << 20).spawn(run).unwrap().join().unwrap();
}

fn run() {
    block_on(async {
        let ca_name = n("test-ca", &[]);
        let ca_key = key(1);
        let ca = cert(&ca_name, 1, &ca_key, true, false, (&ca_name, &ca_key));
        let ca_pem = x509::pem_encode("CERTIFICATE", &ca);
        let k1 = kr_crypto::p256::SecretKey::from_bytes(&[11; 32]).unwrap();
        let k2 = kr_crypto::p256::SecretKey::from_bytes(&[12; 32]).unwrap();
        JWKS.with(|j| *j.borrow_mut() = format!(r#"{{"keys":[{}]}}"#, jwk(&k1, "k1")));
        let iss_port = https((&ca_name, &ca_key), 5, issuer_handler);
        let wh_port = https((&ca_name, &ca_key), 6, webhook_handler);
        let issuer = format!("https://127.0.0.1:{iss_port}");

        let api = Rc::new(ApiServer::new(kr_store::Store::in_memory(), now, rng, "127.0.0.1".into()).unwrap());
        // OIDC from the simple settings.
        let spec = kr_apiserver::jwt::oidc_spec(&issuer, "kr", Some("email"), Some("oidc:"), Some("groups"), None, None, ca_pem.clone()).unwrap();
        let j = kr_apiserver::jwt::Jwt::new(spec, &[]).unwrap();
        j.set_min_refresh_ms(0);
        api.ext.jwt.borrow_mut().push(j.clone());
        // Webhooks.
        let kc = |path: &str| format!("clusters:\n- name: w\n  cluster:\n    server: https://127.0.0.1:{wh_port}{path}\n    certificate-authority-data: {}\nusers:\n- name: u\n  user:\n    token: t\n", kr_fmt::base64::encode(ca_pem.as_bytes()));
        let cfg = kr_apiserver::audit_webhook::Config::from_kubeconfig(&kc("/authn"), &|_| Err("no".into())).unwrap();
        *api.ext.token_webhook.borrow_mut() = Some(TokenWebhook::new(WebhookClient::new(cfg, 5000), "v1", 120).unwrap());
        let authz = format!("kind: AuthorizationConfiguration\nauthorizers:\n- type: Node\n  name: node\n- type: RBAC\n  name: rbac\n- type: Webhook\n  name: hook\n  webhook:\n    timeout: 5s\n    authorizedTTL: 5m\n    unauthorizedTTL: 30s\n    failurePolicy: NoOpinion\n    subjectAccessReviewVersion: v1\n    connectionInfo:\n      type: KubeConfigFile\n      kubeConfigFile: /x\n");
        let mut chain = Vec::new();
        for s in extauth::parse_authz_config(&authz).unwrap() {
            chain.push(match s {
                AuthorizerSpec::Node => Authorizer::Node,
                AuthorizerSpec::Rbac => Authorizer::Rbac,
                AuthorizerSpec::Webhook(w) => {
                    let cfg = kr_apiserver::audit_webhook::Config::from_kubeconfig(&kc("/authz"), &|_| Err("no".into())).unwrap();
                    let t = w.timeout_ms;
                    Authorizer::Webhook(w.build(WebhookClient::new(cfg, t)).unwrap())
                }
                _ => unreachable!(),
            });
        }
        *api.ext.authorizers.borrow_mut() = chain;

        let srv_key = key(2);
        let srv = cert(&n("apiserver", &[]), 2, &srv_key, false, true, (&ca_name, &ca_key));
        let tls = Rc::new(TlsConfig { cert_chain: vec![srv], key: srv_key, client_auth: ClientAuth::Optional(vec![ca.clone()]), alpn: vec![b"http/1.1".to_vec()] });
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        spawn(kr_apiserver::server::run(api.clone(), [127, 0, 0, 1], port, tls));
        for _ in 0..200 {
            if j.key_count() > 0 {
                break;
            }
            sleep(10).await;
        }
        assert_eq!(j.key_count(), 1, "keys are fetched at start through discovery");
        let base = format!("https://127.0.0.1:{port}");
        let cms = format!("{base}/api/v1/namespaces/default/configmaps");
        let secrets = format!("{base}/api/v1/namespaces/default/secrets");
        let t = now();
        let claims = |exp: i64| format!(r#"{{"iss":"{issuer}","aud":"kr","sub":"1","email":"jane","email_verified":true,"groups":["dev"],"iat":{t},"exp":{exp}}}"#);

        // OIDC user, authorized by the webhook.
        let tok = es256(&k1, "k1", &claims(t + 600));
        assert_eq!(get(&cms, &ca_pem, &tok).await, 200);
        let sars = SARS.with(|s| s.borrow().len());
        assert_eq!(sars, 1);
        let sar = SARS.with(|s| s.borrow()[0].clone());
        assert_eq!(sar.pointer(&["spec", "user"]).and_then(Value::as_str), Some("oidc:jane"));
        assert_eq!(sar.pointer(&["spec", "resourceAttributes", "verb"]).and_then(Value::as_str), Some("list"));
        assert_eq!(get(&cms, &ca_pem, &tok).await, 200);
        assert_eq!(SARS.with(|s| s.borrow().len()), 1, "the allow is cached");
        assert_eq!(get(&secrets, &ca_pem, &tok).await, 403, "explicit deny");
        // Expired, wrong audience and forged tokens.
        assert_eq!(get(&cms, &ca_pem, &es256(&k1, "k1", &claims(t - 600))).await, 401);
        assert_eq!(get(&cms, &ca_pem, &es256(&k1, "k1", &claims(t + 600).replace("\"aud\":\"kr\"", "\"aud\":\"x\""))).await, 401);
        assert_eq!(get(&cms, &ca_pem, &es256(&k2, "k1", &claims(t + 600))).await, 401);

        // Key rotation: a token with an unknown kid makes the server read the keys again.
        let fetches = JWKS_FETCHES.with(|c| c.get());
        let tok2 = es256(&k2, "k2", &claims(t + 600));
        assert_eq!(get(&cms, &ca_pem, &tok2).await, 401, "unknown key while the issuer does not publish it");
        assert!(JWKS_FETCHES.with(|c| c.get()) > fetches);
        JWKS.with(|j| *j.borrow_mut() = format!(r#"{{"keys":[{},{}]}}"#, jwk(&k1, "k1"), jwk(&k2, "k2")));
        assert_eq!(get(&cms, &ca_pem, &tok2).await, 200, "the new key is fetched on demand");
        j.set_min_refresh_ms(3_600_000);
        let f = JWKS_FETCHES.with(|c| c.get());
        assert_eq!(get(&cms, &ca_pem, &es256(&k2, "k3", &claims(t + 600))).await, 401);
        assert_eq!(JWKS_FETCHES.with(|c| c.get()), f, "refreshes are rate limited");

        // Webhook token authentication, cached (rejected JWTs above were offered to it too).
        let reviews = TOKEN_REVIEWS.with(|c| c.get());
        assert_eq!(get(&cms, &ca_pem, "opaque-good").await, 200);
        assert_eq!(get(&cms, &ca_pem, "opaque-good").await, 200);
        assert_eq!(TOKEN_REVIEWS.with(|c| c.get()), reviews + 1, "the TokenReview answer is cached");
        assert_eq!(get(&cms, &ca_pem, "opaque-bad").await, 401);
        // Webhook user without a webhook opinion and no RBAC: forbidden.
        assert_eq!(get(&format!("{base}/api/v1/namespaces/default/pods"), &ca_pem, "opaque-good").await, 403);
        let last = SARS.with(|s| s.borrow().last().cloned().unwrap());
        assert_eq!(last.pointer(&["spec", "groups"]).and_then(Value::as_array).map(|g| g.len()), Some(2), "hookers + system:authenticated");
    });
}

fn call(api: &ApiServer, method: &str, path: &str, body: &str) -> (u16, Value) {
    let req = Req { method, path, query: "", content_type: Some("application/json"), accept: None, body: body.as_bytes(), user: Some(User { name: "admin".into(), groups: vec!["system:masters".into()] }), bearer: None, headers: &[], authz_verb: None };
    match api.handle(&req) {
        Reply::Json(c, b) => (c, json::parse(b.as_bytes()).unwrap_or(Value::Null)),
        _ => panic!("unexpected reply"),
    }
}

#[test]
fn admission_plugins() {
    let api = ApiServer::new(kr_store::Store::in_memory(), now, rng, "127.0.0.1".into()).unwrap();
    let cfg = "apiVersion: apiserver.config.k8s.io/v1\nkind: AdmissionConfiguration\nplugins:\n- name: PodNodeSelector\n  configuration:\n    podNodeSelectorPluginConfig:\n      clusterDefaultNodeSelector: tier=general\n- name: EventRateLimit\n  configuration:\n    apiVersion: eventratelimit.admission.k8s.io/v1alpha1\n    kind: Configuration\n    limits:\n    - type: Namespace\n      qps: 1\n      burst: 2\n";
    *api.ext.plugins.borrow_mut() = kr_apiserver::plugins::configure("AlwaysPullImages,PodNodeSelector,EventRateLimit", Some(cfg), &|_| Err("no".into())).unwrap();
    let ns = r#"{"metadata":{"name":"team","annotations":{"scheduler.alpha.kubernetes.io/node-selector":"env=prod"}}}"#;
    assert_eq!(call(&api, "POST", "/api/v1/namespaces", ns).0, 201);
    for nsn in ["team", "default"] {
        if call(&api, "GET", &format!("/api/v1/namespaces/{nsn}/serviceaccounts/default"), "").0 == 404 {
            assert_eq!(call(&api, "POST", &format!("/api/v1/namespaces/{nsn}/serviceaccounts"), r#"{"metadata":{"name":"default"}}"#).0, 201);
        }
    }
    let pod = |name: &str, sel: &str| format!(r#"{{"metadata":{{"name":"{name}"}},"spec":{{"nodeSelector":{{{sel}}},"containers":[{{"name":"c","image":"i","imagePullPolicy":"IfNotPresent"}}]}}}}"#);
    let (code, p) = call(&api, "POST", "/api/v1/namespaces/team/pods", &pod("a", r#""disk":"ssd""#));
    assert_eq!(code, 201, "{p:?}");
    assert_eq!(p.pointer(&["spec", "nodeSelector", "env"]).and_then(Value::as_str), Some("prod"));
    assert_eq!(p.pointer(&["spec", "nodeSelector", "disk"]).and_then(Value::as_str), Some("ssd"));
    assert_eq!(p.pointer(&["spec", "containers"]).unwrap().as_array().unwrap()[0].get("imagePullPolicy").and_then(Value::as_str), Some("Always"));
    let (code, p) = call(&api, "POST", "/api/v1/namespaces/team/pods", &pod("b", r#""env":"dev""#));
    assert_eq!(code, 403, "{p:?}");
    let (code, p) = call(&api, "POST", "/api/v1/namespaces/default/pods", &pod("c", ""));
    assert_eq!(code, 201, "{p:?}");
    assert_eq!(p.pointer(&["spec", "nodeSelector", "tier"]).and_then(Value::as_str), Some("general"), "cluster default");
    // EventRateLimit: a burst of 2 per namespace.
    let ev = |name: &str| format!(r#"{{"metadata":{{"name":"{name}"}},"involvedObject":{{"kind":"Pod","name":"a","namespace":"team"}},"reason":"R","message":"m"}}"#);
    assert_eq!(call(&api, "POST", "/api/v1/namespaces/team/events", &ev("e1")).0, 201);
    assert_eq!(call(&api, "POST", "/api/v1/namespaces/team/events", &ev("e2")).0, 201);
    let (code, st) = call(&api, "POST", "/api/v1/namespaces/team/events", &ev("e3"));
    assert_eq!(code, 429, "{st:?}");
    assert!(st.get("message").and_then(Value::as_str).unwrap().contains("limit reached on type Namespace for key team"));
    assert_eq!(call(&api, "POST", "/api/v1/namespaces/default/events", &ev("e4")).0, 201, "another namespace");
}
