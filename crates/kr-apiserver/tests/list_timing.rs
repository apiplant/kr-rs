//! List and discovery costs on a large collection.
//! `cargo test --release -p kr-apiserver --test list_timing -- --ignored --nocapture`
use kr_apiserver::api::{ApiServer, Reply, Req, User};
use std::time::Instant;

fn rng(b: &mut [u8]) {
    kr_sys::getrandom(b)
}

fn call(api: &ApiServer, method: &str, path: &str, query: &str, accept: Option<&str>, body: &str) -> (u16, usize) {
    let user = Some(User { name: "admin".into(), groups: vec!["system:masters".into()] });
    let req = Req { method, path, query, content_type: Some("application/json"), accept, body: body.as_bytes(), user, bearer: None, headers: &[], authz_verb: None };
    match api.handle(&req) {
        Reply::Json(c, b) => (c, b.len()),
        Reply::Http(r) => (r.status, 0),
        _ => (0, 0),
    }
}

fn time(label: &str, n: u32, mut f: impl FnMut()) {
    let t = Instant::now();
    for _ in 0..n {
        f();
    }
    println!("{label:44} {:>9.0} us", t.elapsed().as_secs_f64() * 1e6 / n as f64);
}

#[test]
#[ignore]
fn list_costs() {
    let api = ApiServer::new(kr_store::Store::in_memory(), || 1_700_000_000, rng, "127.0.0.1".into()).unwrap();
    for ns in 0..10 {
        call(&api, "POST", "/api/v1/namespaces", "", None, &format!(r#"{{"metadata":{{"name":"ns{ns}"}}}}"#));
    }
    for i in 0..3000 {
        let ns = i % 10;
        let pod = format!(r#"{{"metadata":{{"name":"p{i}","namespace":"ns{ns}","labels":{{"app":"app{}","tier":"t{}"}}}},"spec":{{"nodeName":"node{}","containers":[{{"name":"c","image":"registry.example.com/team/app:1.2.3","resources":{{"requests":{{"cpu":"100m"}}}}}}]}}}}"#, i % 50, i % 3, i % 20);
        assert_eq!(call(&api, "POST", &format!("/api/v1/namespaces/ns{ns}/pods"), "", None, &pod).0, 201);
    }
    let table = Some("application/json;as=Table;g=meta.k8s.io;v=v1");
    let (c, size) = call(&api, "GET", "/api/v1/pods", "", None, "");
    println!("all pods: {c}, {} KB", size / 1024);
    time("list all pods (plain)", 20, || assert_eq!(call(&api, "GET", "/api/v1/pods", "", None, "").0, 200));
    time("list all pods (Table, kubectl get -A)", 10, || assert_eq!(call(&api, "GET", "/api/v1/pods", "", table, "").0, 200));
    time("labelSelector=app=app7 (60 matches)", 20, || assert_eq!(call(&api, "GET", "/api/v1/pods", "labelSelector=app%3Dapp7", None, "").0, 200));
    time("labelSelector=tier in (t1,t2)", 20, || assert_eq!(call(&api, "GET", "/api/v1/pods", "labelSelector=tier%20in%20(t1,t2)", None, "").0, 200));
    time("fieldSelector=spec.nodeName=node3 (kubelet)", 20, || assert_eq!(call(&api, "GET", "/api/v1/pods", "fieldSelector=spec.nodeName%3Dnode3", None, "").0, 200));
    time("limit=500 first page (+remainingItemCount)", 50, || assert_eq!(call(&api, "GET", "/api/v1/pods", "limit=500", None, "").0, 200));
    time("GET /api/v1 (discovery)", 200, || assert_eq!(call(&api, "GET", "/api/v1", "", None, "").0, 200));
    time("GET /apis (discovery)", 200, || assert_eq!(call(&api, "GET", "/apis", "", None, "").0, 200));
    time("GET /apis (aggregated discovery)", 200, || { call(&api, "GET", "/apis", "", Some("application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList"), ""); });
}

/// How long the event loop is blocked while a 3000-pod Table list is rendered: inline against in a worker.
#[test]
#[ignore]
fn loop_stall_inline_vs_offloaded() {
    use kr_rt::exec;
    use std::cell::Cell;
    use std::rc::Rc;
    kr_rt::offload::init(kr_apiserver::offload::handler, 2);
    let api = ApiServer::new(kr_store::Store::in_memory(), || 1_700_000_000, rng, "127.0.0.1".into()).unwrap();
    for i in 0..3000 {
        let pod = format!(r#"{{"metadata":{{"name":"p{i}","namespace":"default","labels":{{"app":"app{}"}}}},"spec":{{"nodeName":"node{}","containers":[{{"name":"c","image":"registry.example.com/team/app:1.2.3"}}]}}}}"#, i % 50, i % 20);
        assert_eq!(call(&api, "POST", "/api/v1/namespaces/default/pods", "", None, &pod).0, 201);
    }
    let table = Some("application/json;as=Table;g=meta.k8s.io;v=v1");
    let user = Some(User { name: "admin".into(), groups: vec!["system:masters".into()] });
    let api = Rc::new(api);
    for defer in [false, true] {
        let worst = Rc::new(Cell::new(0u128));
        let w2 = worst.clone();
        let a2 = api.clone();
        let user2 = user.clone();
        exec::block_on(async move {
            // A 1 ms ticker: the largest gap between ticks is the longest the loop was blocked.
            let stop = Rc::new(Cell::new(false));
            let s2 = stop.clone();
            let ticker = exec::spawn(async move {
                let mut last = std::time::Instant::now();
                while !s2.get() {
                    exec::sleep(1).await;
                    let now = std::time::Instant::now();
                    w2.set(w2.get().max((now - last).as_micros()));
                    last = now;
                }
            });
            exec::sleep(20).await;
            for _ in 0..5 {
                let req = Req { method: "GET", path: "/api/v1/pods", query: "", content_type: None, accept: table, body: b"", user: user2.clone(), bearer: None, headers: &[], authz_verb: None };
                a2.set_defer_lists(defer);
                let (reply, _) = a2.handle_w(&req);
                a2.set_defer_lists(false);
                let reply = match a2.take_list_job() {
                    Some(job) => job.run().await,
                    None => reply,
                };
                assert!(matches!(reply, Reply::Json(200, ref b) if b.len() > 1000));
                exec::sleep(5).await;
            }
            stop.set(true);
            ticker.await.ok();
        });
        println!("Table list of 3000 pods, {:9}: longest gap of the event loop {:>6} us", if defer { "offloaded" } else { "inline" }, worst.get());
    }
}
