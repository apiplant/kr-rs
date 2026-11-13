//! The forked store compaction (ADR-065), alone in its binary: the child of a fork in a
//! multithreaded test harness could otherwise meet an allocator lock held by another test.
use kr_apiserver::api::{ApiServer, Reply, Req, User};
use kr_fmt::json::{self, Value};

fn now() -> i64 {
    1_700_000_000
}

fn rng(b: &mut [u8]) {
    kr_sys::getrandom(b)
}

fn call(api: &ApiServer, method: &str, path: &str, ct: &str, body: &str) -> (u16, Value) {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let req = Req {
        method,
        path,
        query,
        content_type: Some(ct),
        accept: None,
        body: body.as_bytes(),
        user: Some(User { name: "admin".into(), groups: vec!["system:masters".into()] }),
        bearer: None,
        headers: &[],
        authz_verb: None,
    };
    match api.handle(&req) {
        Reply::Json(c, b) => (c, json::parse(b.as_bytes()).unwrap_or(Value::Null)),
        Reply::Http(r) => match r.body {
            kr_net::http1::server::Body::Full(b) => (r.status, json::parse(&b).unwrap_or(Value::Null)),
            _ => panic!("unexpected reply"),
        },
        _ => panic!("unexpected reply"),
    }
}

fn j(api: &ApiServer, method: &str, path: &str, body: &str) -> (u16, Value) {
    call(api, method, path, "application/json", body)
}


/// The forked compaction (ADR-065): the child writes the snapshot, writes made while it runs
/// stay in the log, and a restart sees everything.
#[test]
fn forked_compaction_keeps_concurrent_writes() {
    let dir = std::env::temp_dir().join(format!("kr-compact-fork-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = dir.to_str().unwrap();
    const CM: &str = "/api/v1/namespaces/default/configmaps";
    let cm = |n: &str, v: &str| format!(r#"{{"metadata":{{"name":"{n}"}},"data":{{"v":"{v}"}}}}"#);
    {
        let mut st = kr_store::Store::open(d).unwrap();
        st.set_compact_min(1);
        let api = std::rc::Rc::new(ApiServer::new(st, now, rng, "127.0.0.1".into()).unwrap());
        assert_eq!(j(&api, "POST", CM, &cm("a", "1")).0, 201);
        for i in 0..50 {
            assert_eq!(j(&api, "PUT", &format!("{CM}/a"), &cm("a", &i.to_string())).0, 200);
        }
        let (a1, a2, during) = (api.clone(), api.clone(), cm("during", "x"));
        kr_rt::exec::block_on(async move {
            let compaction = async move { a1.maybe_compact().await };
            let writes = async move {
                assert_eq!(j(&a2, "POST", CM, &during).0, 201);
            };
            futures_join(compaction, writes).await;
        });
        assert!(std::fs::metadata(format!("{d}/snapshot")).is_ok());
        assert_eq!(j(&api, "POST", CM, &cm("after", "y")).0, 201);
        let a3 = api.clone();
        kr_rt::exec::block_on(async move { a3.commit(a3.revision()).await }).unwrap();
        assert!(std::fs::metadata(format!("{d}/log")).unwrap().len() < 4096, "log prefix dropped");
    }
    let api = ApiServer::new(kr_store::Store::open(d).unwrap(), now, rng, "127.0.0.1".into()).unwrap();
    for (n, v) in [("a", "49"), ("during", "x"), ("after", "y")] {
        let (c, o) = j(&api, "GET", &format!("{CM}/{n}"), "");
        assert_eq!((c, o.pointer(&["data", "v"]).and_then(Value::as_str)), (200, Some(v)), "{n}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

async fn futures_join<A: core::future::Future<Output = ()>, B: core::future::Future<Output = ()>>(a: A, b: B) {
    let (a, b) = (core::pin::pin!(a), core::pin::pin!(b));
    let (mut a, mut b) = (Some(a), Some(b));
    core::future::poll_fn(|cx| {
        if a.as_mut().is_some_and(|f| f.as_mut().poll(cx).is_ready()) {
            a = None;
        }
        if b.as_mut().is_some_and(|f| f.as_mut().poll(cx).is_ready()) {
            b = None;
        }
        if a.is_none() && b.is_none() { core::task::Poll::Ready(()) } else { core::task::Poll::Pending }
    })
    .await
}
