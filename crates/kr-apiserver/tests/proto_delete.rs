//! Protobuf `DeleteOptions` (client-go's default DELETE body) regression tests.
//!
//! Bytes exactly as client-go sends them: `runtime.Unknown` (k8s magic prefix, TypeMeta nested
//! in field 1, raw object in field 2). The first framing is the one that used to be mis-decoded
//! ("protobuf: invalid wire type") and cost ~60 e2e conformance failures in round 3.

use kr_apiserver::proto::decode_body_as;
use kr_fmt::json::Value;
use kr_fmt::proto::Writer;

/// Hand-built `runtime.Unknown{TypeMeta: meta.k8s.io/v1/DeleteOptions, raw: {gracePeriodSeconds:0}}`.
const UNKNOWN_DELETE_ZERO: &[u8] = &[
    0x6b, 0x38, 0x73, 0x00, // "k8s\0"
    0x0a, 0x1f, // field 1 (TypeMeta), len 31
    0x0a, 0x0e, b'm', b'e', b't', b'a', b'.', b'k', b'8', b's', b'.', b'i', b'o', b'/', b'v', b'1',
    0x12, 0x0d, b'D', b'e', b'l', b'e', b't', b'e', b'O', b'p', b't', b'i', b'o', b'n', b's',
    0x12, 0x02, 0x08, 0x00, // field 2 (raw): DeleteOptions{gracePeriodSeconds: 0}
];

/// The same, but with an empty TypeMeta so the request's `fallback` kind applies.
fn unknown_typeless(raw: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.message(1, |_| {})
        .bytes(2, raw);
    let mut out = b"k8s\0".to_vec();
    out.extend_from_slice(w.as_bytes());
    out
}

#[test]
fn typed_delete_options() {
    let v = decode_body_as(UNKNOWN_DELETE_ZERO, Some(("v1", "DeleteOptions"))).expect("typed DeleteOptions decodes");
    assert_eq!(v.get("gracePeriodSeconds"), Some(&Value::Number(kr_fmt::json::Number::from_i64(0))), "zero grace period is kept (force delete)");
}

#[test]
fn typeless_delete_options() {
    let mut w = Writer::new();
    w.int64(1, 30);
    let body = unknown_typeless(w.as_bytes());
    let v = decode_body_as(&body, Some(("v1", "DeleteOptions"))).expect("typeless DeleteOptions decodes via fallback");
    assert_eq!(v.get("gracePeriodSeconds"), Some(&Value::Number(kr_fmt::json::Number::from_i64(30))));
}

#[test]
fn wrong_wire_type_is_rejected() {
    // Same envelope, but gracePeriodSeconds length-delimited (wire type 2) instead of varint.
    let mut body = UNKNOWN_DELETE_ZERO.to_vec();
    let n = body.len();
    body[n - 2] = 0x0a; // field 1, length-delimited
    body[n - 1] = 0x00;
    assert!(decode_body_as(&body, Some(("v1", "DeleteOptions"))).is_err());
}
/// client-go stamps DeleteOptions with the deleted resource's group version (`apps/v1`,
/// `apiextensions.k8s.io/v1`, ...); conformance round 4 lost ~25 deletes to this.
#[test]
fn group_stamped_delete_options() {
    for av in ["apps/v1", "apiextensions.k8s.io/v1", "storage.k8s.io/v1", "node.k8s.io/v1"] {
        let mut w = Writer::new();
        w.message(1, |t| { t.string(1, av).string(2, "DeleteOptions"); })
            .bytes(2, &[0x08, 0x05]);
        let mut body = b"k8s\0".to_vec();
        body.extend_from_slice(w.as_bytes());
        let v = decode_body_as(&body, None).unwrap_or_else(|e| panic!("{av}: {e}"));
        assert_eq!(v.get("gracePeriodSeconds"), Some(&Value::Number(kr_fmt::json::Number::from_i64(5))), "{av}");
    }
}
