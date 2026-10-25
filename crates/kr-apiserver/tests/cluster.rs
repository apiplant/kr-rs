//! Three API servers replicating their store with Raft over loopback TLS, in one process:
//! election, replicated writes with identical resourceVersions, follower write refusal,
//! watches on followers, and failover after the leader dies.

use kr_apiserver::api::{ApiServer, Reply, Req, User};
use kr_apiserver::client::{Client, InProcess};
use kr_apiserver::cluster::{transport, Cluster, ServerAddr};
use kr_crypto::tls::{ClientAuth, ClientConfig, ServerConfig};
use kr_crypto::x509::{self, CertParams, Name, SigningKey};
use kr_fmt::json::{self, Value};
use kr_net::http1::server::{listen, local_addr};
use kr_rt::exec::{block_on, sleep, spawn, JoinHandle};
use std::rc::Rc;

fn key(seed: u8) -> SigningKey {
    SigningKey::P256(kr_crypto::p256::SecretKey::from_bytes(&[seed; 32]).unwrap())
}

fn issue(subject: &Name, serial: u8, k: &SigningKey, ca: bool, issuer: (&Name, &SigningKey)) -> Vec<u8> {
    let p = CertParams {
        serial: [serial; 16],
        subject: subject.clone(),
        not_before: 1_000_000_000,
        not_after: 4_000_000_000,
        is_ca: ca,
        server: !ca,
        client: !ca,
        dns_names: vec![],
        ip_addrs: if ca { vec![] } else { vec![vec![127, 0, 0, 1]] },
        public_key: k.public(),
    };
    x509::issue(&p, issuer.0, issuer.1)
}

fn now() -> i64 {
    2_000_000_000
}

fn rng(b: &mut [u8]) {
    use std::io::Read;
    std::fs::File::open("/dev/urandom").unwrap().read_exact(b).unwrap();
}

struct Srv {
    id: u64,
    api: Rc<ApiServer>,
    cluster: Rc<Cluster>,
    tasks: Vec<JoinHandle<()>>,
}

fn req<'a>(method: &'a str, path: &'a str, body: &'a [u8]) -> Req<'a> {
    Req {
        method,
        path,
        query: "",
        content_type: Some("application/json"),
        accept: None,
        body,
        user: Some(User { name: "admin".into(), groups: vec!["system:masters".into()] }),
        bearer: None,
        headers: &[],
        authz_verb: None,
    }
}

fn status(r: &Reply) -> (u16, Value) {
    match r {
        Reply::Json(c, b) => (*c, json::parse(b.as_bytes()).unwrap_or(Value::Null)),
        _ => (0, Value::Null),
    }
}

/// A write through `api`, acknowledged only after it commits.
async fn write(s: &Srv, method: &str, path: &str, body: &str) -> (u16, Value) {
    let before = s.api.revision();
    let r = s.api.handle(&req(method, path, body.as_bytes()));
    let (code, v) = status(&r);
    if code < 300 && s.api.revision() > before {
        let rev = s.api.revision();
        if s.api.commit(rev).await.is_err() {
            return (500, Value::Null);
        }
    }
    (code, v)
}

fn get(s: &Srv, path: &str) -> (u16, Value) {
    status(&s.api.handle(&req("GET", path, b"")))
}

fn rv(v: &Value) -> String {
    v.pointer(&["metadata", "resourceVersion"]).and_then(Value::as_str).unwrap_or("").into()
}

#[test]
fn three_servers_replicate_and_fail_over() {
    block_on(async {
        let ca_name = Name { common_name: "kr-ca".into(), organizations: vec![] };
        let ca_key = key(1);
        let ca = issue(&ca_name, 1, &ca_key, true, (&ca_name, &ca_key));
        let base = std::env::temp_dir().join(format!("kr-cluster-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let ids = [1u64, 2, 3];
        let mut listeners = Vec::new();
        let mut api_listeners = Vec::new();
        for _ in ids {
            let l = listen([127, 0, 0, 1], 0, 16).unwrap();
            let port = local_addr(&l).unwrap().1;
            listeners.push((l, port));
            let a = listen([127, 0, 0, 1], 0, 16).unwrap();
            let port = local_addr(&a).unwrap().1;
            api_listeners.push(Some((a, port)));
        }
        let ports: Vec<u16> = listeners.iter().map(|x| x.1).collect();
        let api_ports: Vec<u16> = api_listeners.iter().map(|x| x.as_ref().unwrap().1).collect();
        let mut srvs = Vec::new();
        for (i, (l, _)) in listeners.into_iter().enumerate() {
            let id = ids[i];
            let k = key(10 + id as u8);
            let subject = Name { common_name: transport::cert_cn(id), organizations: vec![transport::ORG.into()] };
            let c = issue(&subject, 10 + id as u8, &k, false, (&ca_name, &ca_key));
            let srv_tls = Rc::new(ServerConfig { cert_chain: vec![c.clone()], key: k, client_auth: ClientAuth::Required(vec![ca.clone()]), alpn: vec![] });
            let cli_tls = Rc::new(ClientConfig { roots: vec![ca.clone()], pinned_ca: None, client_cert: Some((vec![c], key(10 + id as u8))), alpn: vec![], tls12: false });
            let api = Rc::new(ApiServer::new(kr_store::Store::replicated(), now, rng, "127.0.0.1".into()).unwrap());
            let dir = base.join(format!("n{id}"));
            let cluster = Cluster::open(&api, id, dir.to_str().unwrap(), ids.to_vec(), cli_tls, id * 7919).unwrap();
            for (j, other) in ids.iter().enumerate() {
                if *other != id {
                    cluster.add_seed(*other, ServerAddr { ip: [127, 0, 0, 1], raft_port: ports[j], api_port: api_ports[j] });
                }
            }
            api.set_cluster(cluster.clone());
            let api_tls = Rc::new(ServerConfig { cert_chain: srv_tls.cert_chain.clone(), key: key(10 + id as u8), client_auth: ClientAuth::Optional(vec![ca.clone()]), alpn: vec![b"http/1.1".to_vec()] });
            let t1 = spawn(transport::serve(l, srv_tls, id, cluster.inbox.clone()));
            let t2 = spawn(cluster.clone().run(api.clone()));
            let (al, _) = api_listeners[i].take().unwrap();
            let a2 = api.clone();
            let t3 = spawn(async move {
                let _ = kr_apiserver::server::serve(a2, al, api_tls).await;
            });
            srvs.push(Srv { id, api, cluster, tasks: vec![t1, t2, t3] });
        }
        let leader = |srvs: &[Srv]| srvs.iter().position(|s| s.cluster.is_leader());
        let mut l = None;
        for _ in 0..100 {
            sleep(100).await;
            l = leader(&srvs);
            if l.is_some() {
                break;
            }
        }
        let li = l.expect("a leader is elected");

        // A write on the leader commits and replicates with the same resourceVersion.
        let (code, cm) = write(&srvs[li], "POST", "/api/v1/namespaces/default/configmaps", r#"{"metadata":{"name":"a"},"data":{"k":"v"}}"#).await;
        assert_eq!(code, 201, "{cm:?}");
        let want_rv = rv(&cm);
        for _ in 0..50 {
            if srvs.iter().all(|s| get(s, "/api/v1/namespaces/default/configmaps/a").0 == 200) {
                break;
            }
            sleep(50).await;
        }
        for s in &srvs {
            let (c, v) = get(s, "/api/v1/namespaces/default/configmaps/a");
            assert_eq!(c, 200, "server {} lacks the write", s.id);
            assert_eq!(rv(&v), want_rv, "server {} has a different resourceVersion", s.id);
        }

        // A follower refuses writes (they are forwarded to the leader by the HTTP layer).
        let fi = (li + 1) % 3;
        let (code, v) = write(&srvs[fi], "POST", "/api/v1/namespaces/default/configmaps", r#"{"metadata":{"name":"b"}}"#).await;
        assert_eq!(code, 503, "{v:?}");
        assert!(get(&srvs[fi], "/api/v1/namespaces/default/configmaps/b").0 == 404);

        // An in-process client on the follower (its kubelet) forwards the write to the leader
        // over HTTPS with its server certificate, and then reads its own write locally.
        let ip = InProcess::new(srvs[fi].api.clone(), "kubelet");
        let obj = json::parse(br#"{"metadata":{"name":"fwd"},"data":{"x":"1"}}"#).unwrap();
        let created = ip.create("/api/v1/namespaces/default/configmaps", &obj).await.expect("forwarded create");
        let fwd_rv = rv(&created);
        let (c, v) = get(&srvs[fi], "/api/v1/namespaces/default/configmaps/fwd");
        assert_eq!(c, 200, "follower reads its forwarded write");
        assert_eq!(rv(&v), fwd_rv);
        assert_eq!(get(&srvs[li], "/api/v1/namespaces/default/configmaps/fwd").0, 200);
        // The forwarded identity is the original user's: an unprivileged identity is refused
        // by the leader's RBAC, not waved through as the follower server.
        let nobody = InProcess::with_user(srvs[fi].api.clone(), User { name: "nobody".into(), groups: vec!["system:authenticated".into()] });
        let e = nobody.create("/api/v1/namespaces/default/configmaps", &obj).await.unwrap_err();
        assert_eq!(e.code, 403, "{e:?}");

        // The leader dies: the other two elect a new leader and keep accepting writes.
        let dead = srvs[li].id;
        for t in &srvs[li].tasks {
            t.abort();
        }
        srvs[li].cluster.inbox.closed.set(true);
        let mut nl = None;
        for _ in 0..100 {
            sleep(100).await;
            nl = srvs.iter().position(|s| s.id != dead && s.cluster.is_leader());
            if nl.is_some() {
                break;
            }
        }
        let ni = nl.expect("a new leader is elected after the old one died");
        let (code, _) = write(&srvs[ni], "POST", "/api/v1/namespaces/default/configmaps", r#"{"metadata":{"name":"c"}}"#).await;
        assert_eq!(code, 201);
        sleep(500).await;
        let other = srvs.iter().position(|s| s.id != dead && s.id != srvs[ni].id).unwrap();
        assert_eq!(get(&srvs[other], "/api/v1/namespaces/default/configmaps/c").0, 200);
        assert_eq!(srvs[other].api.revision(), srvs[ni].api.revision());

        // The dead server restarts from its own disk (same port), recovers its log and catches
        // up on the write it missed.
        let (l, _port) = loop {
            if let Ok(l) = listen([127, 0, 0, 1], ports[li], 16) {
                break (l, ports[li]);
            }
            sleep(50).await;
        };
        let k = key(10 + dead as u8);
        let subject = Name { common_name: transport::cert_cn(dead), organizations: vec![transport::ORG.into()] };
        let c = issue(&subject, 10 + dead as u8, &k, false, (&ca_name, &ca_key));
        let srv_tls = Rc::new(ServerConfig { cert_chain: vec![c.clone()], key: k, client_auth: ClientAuth::Required(vec![ca.clone()]), alpn: vec![] });
        let cli_tls = Rc::new(ClientConfig { roots: vec![ca.clone()], pinned_ca: None, client_cert: Some((vec![c], key(10 + dead as u8))), alpn: vec![], tls12: false });
        let api = Rc::new(ApiServer::new(kr_store::Store::replicated(), now, rng, "127.0.0.1".into()).unwrap());
        let cluster = Cluster::open(&api, dead, base.join(format!("n{dead}")).to_str().unwrap(), Vec::new(), cli_tls, 99).unwrap();
        for (j, o) in ids.iter().enumerate() {
            if *o != dead {
                cluster.add_seed(*o, ServerAddr { ip: [127, 0, 0, 1], raft_port: ports[j], api_port: 0 });
            }
        }
        api.set_cluster(cluster.clone());
        let t1 = spawn(transport::serve(l, srv_tls, dead, cluster.inbox.clone()));
        let t2 = spawn(cluster.clone().run(api.clone()));
        let back = Srv { id: dead, api, cluster, tasks: vec![t1, t2] };
        for _ in 0..100 {
            if get(&back, "/api/v1/namespaces/default/configmaps/c").0 == 200 {
                break;
            }
            sleep(50).await;
        }
        assert_eq!(get(&back, "/api/v1/namespaces/default/configmaps/a").0, 200, "recovered from its own log");
        assert_eq!(get(&back, "/api/v1/namespaces/default/configmaps/c").0, 200, "caught up on the missed write");
        assert_eq!(back.api.revision(), srvs[ni].api.revision());
        assert!(!back.cluster.is_leader() || back.cluster.term() > srvs[ni].cluster.term());
        // No divergence: byte-identical stores (UIDs, timestamps, revisions) on every live server.
        assert_eq!(back.api.store_digest(), srvs[ni].api.store_digest());
        assert_eq!(srvs[other].api.store_digest(), srvs[ni].api.store_digest());
        let _ = std::fs::remove_dir_all(&base);
    });
}
