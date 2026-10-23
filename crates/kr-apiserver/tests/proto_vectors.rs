//! Golden vectors: objects encoded by the real Kubernetes protobuf serializer (and `encoding/json`)
//! via `tools/gen_k8s_proto_vectors.sh`. The decoded protobuf must equal the JSON form.

use kr_apiserver::proto::decode_body;
use kr_fmt::json::{self, Value};

/// Recursively drops `null`s (Go emits `creationTimestamp: null` and `containers: null` for zero
/// values that protobuf simply leaves out) and sorts object keys so comparison ignores order.
fn normalize(v: Value) -> Value {
    match v {
        Value::Array(a) => Value::Array(a.into_iter().map(normalize).collect()),
        Value::Object(o) => {
            let mut o: Vec<_> = o.into_iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k, normalize(v))).collect();
            o.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(o)
        }
        v => v,
    }
}

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim().as_bytes();
    s.chunks(2).map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap()).collect()
}

fn check(name: &str, hex: &str, js: &str) {
    let body = unhex(hex);
    let got = decode_body(&body).unwrap_or_else(|e| panic!("{name}: {e}"));
    let want = json::parse(js.as_bytes()).unwrap();
    let (got, want) = (normalize(got), normalize(want));
    assert!(got == want, "{name}:\n got  {}\n want {}", json::to_string(&got), json::to_string(&want));
}

macro_rules! vectors {
    ($($name:ident),* $(,)?) => {
        $(#[test]
        fn $name() {
            check(
                stringify!($name),
                include_str!(concat!("vectors/", stringify!($name), ".pb.hex")),
                include_str!(concat!("vectors/", stringify!($name), ".json")),
            );
        })*
    };
}

vectors!(
    configmap, secret, namespace, serviceaccount, deployment, service, job, pod, deleteoptions, lease,
    role, rolebinding, ingress, pdb, pvc,
);

/// Every strict prefix of a real body must fail cleanly (or decode), never panic.
#[test]
fn truncations_do_not_panic() {
    let body = unhex(include_str!("vectors/deployment.pb.hex"));
    for n in 0..body.len() {
        let _ = decode_body(&body[..n]);
    }
}

/// Flipping any single byte must not panic either.
#[test]
fn corruption_does_not_panic() {
    let body = unhex(include_str!("vectors/pod.pb.hex"));
    for i in 0..body.len() {
        for x in [0x00u8, 0xff, 0x80, 0x07] {
            let mut b = body.clone();
            b[i] ^= x;
            let _ = decode_body(&b);
        }
    }
}

/// A protobuf `create` through the REST handler stores the same object a JSON create would.
#[test]
fn create_configmap_over_protobuf() {
    use kr_apiserver::api::{ApiServer, Reply, Req, User};
    let json_of = |r: Reply| match r {
        Reply::Json(c, b) => (c, b),
        Reply::Watch(_) => panic!("unexpected watch"),
    };
    let server = ApiServer::new(kr_store::Store::in_memory(), || 1_700_000_000, |b| b.fill(7), "127.0.0.1:6443".into()).unwrap();
    let body = unhex(include_str!("vectors/configmap.pb.hex"));
    let req = |method, path, ct, body| Req { method, path, query: "", content_type: ct, accept: None, body, user: Some(User { name: "admin".into(), groups: vec!["system:masters".into()] }) };
    let (code, text) = json_of(server.handle(&req("POST", "/api/v1/namespaces/default/configmaps", Some("application/vnd.kubernetes.protobuf"), &body)));
    assert_eq!(code, 201, "{text}");
    let (_, text) = json_of(server.handle(&req("GET", "/api/v1/namespaces/default/configmaps/x", None, b"")));
    let v = json::parse(text.as_bytes()).unwrap();
    assert_eq!(v.pointer(&["data", "a"]).and_then(Value::as_str), Some("b"));
    assert_eq!(v.pointer(&["binaryData", "bin"]).and_then(Value::as_str), Some("AAEC//4="));
    // Malformed protobuf is a 400, CBOR stays a 415.
    let (code, _) = json_of(server.handle(&req("POST", "/api/v1/namespaces/default/configmaps", Some("application/vnd.kubernetes.protobuf"), b"k8s\0\x0a")));
    assert_eq!(code, 400);
    let (code, _) = json_of(server.handle(&req("POST", "/api/v1/namespaces/default/configmaps", Some("application/cbor"), b"\xa0")));
    assert_eq!(code, 415);
}
