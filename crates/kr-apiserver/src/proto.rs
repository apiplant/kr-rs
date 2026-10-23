//! Kubernetes protobuf request bodies (`application/vnd.kubernetes.protobuf`) decoded into the
//! JSON [`Value`] the same object would have as JSON, so the rest of the server only ever sees JSON.
//!
//! The body is the magic `k8s\0` followed by a `runtime.Unknown` envelope whose `raw` field holds
//! the typed message. Field layouts come from the generated [`crate::proto_schema`] tables; the
//! types with a hand-written JSON form (`Time`, `Duration`, `IntOrString`, `Quantity`, ...) are
//! handled here. Parsing is strict (bounds, varint length, wire types, depth) and unknown fields
//! are skipped.

use crate::proto_schema as s;
use alloc::string::String;
use alloc::vec::Vec;
use kr_fmt::json::{self, Number, Value};
use kr_fmt::proto::{self as wire, Reader};

type R<T> = Result<T, &'static str>;
type Object = Vec<(String, Value)>;

/// Leading bytes of every Kubernetes protobuf body.
const MAGIC: &[u8] = b"k8s\0";
/// Maximum message nesting accepted.
const MAX_DEPTH: usize = 64;

fn wire_err(e: wire::Error) -> &'static str {
    match e.kind {
        wire::ErrorKind::Truncated => "protobuf: truncated message",
        wire::ErrorKind::VarintOverflow => "protobuf: varint too long",
        wire::ErrorKind::InvalidFieldNumber => "protobuf: invalid field number",
        wire::ErrorKind::InvalidWireType => "protobuf: invalid wire type",
        wire::ErrorKind::LengthLimit => "protobuf: length too large",
        wire::ErrorKind::InvalidUtf8 => "protobuf: invalid UTF-8",
    }
}

/// Decodes a `k8s\0`-prefixed protobuf body into the equivalent JSON object, with `apiVersion`
/// and `kind` taken from the envelope's `TypeMeta`.
pub fn decode_body(body: &[u8]) -> R<Value> {
    let rest = body.strip_prefix(MAGIC).ok_or("protobuf: missing k8s magic prefix")?;
    let (mut api_version, mut kind, mut raw) = ("", "", None);
    let mut r = Reader::new(rest);
    while let Some(f) = r.next().map_err(wire_err)? {
        match (f.number, f.value) {
            (1, wire::Value::Bytes(tm)) => {
                let mut t = Reader::new(tm);
                while let Some(g) = t.next().map_err(wire_err)? {
                    match (g.number, g.value) {
                        (1, wire::Value::Bytes(_)) => api_version = g.as_str().ok_or("protobuf: invalid UTF-8")?,
                        (2, wire::Value::Bytes(_)) => kind = g.as_str().ok_or("protobuf: invalid UTF-8")?,
                        (1 | 2, _) => return Err("protobuf: wrong wire type in TypeMeta"),
                        _ => {}
                    }
                }
            }
            (2, wire::Value::Bytes(b)) => raw = Some(b),
            (3, wire::Value::Bytes(b)) => {
                if !b.is_empty() {
                    return Err("protobuf: unsupported content encoding");
                }
            }
            (1..=4, wire::Value::Bytes(_)) => {}
            (1..=4, _) => return Err("protobuf: wrong wire type in Unknown"),
            _ => {}
        }
    }
    let raw = raw.ok_or("protobuf: missing raw object")?;
    let idx = s::KINDS.iter().find(|k| k.0 == api_version && k.1 == kind).map(|k| k.2).ok_or("protobuf: unsupported kind")?;
    let mut v = message(raw, idx, 0)?;
    if let Value::Object(o) = &mut v {
        o.retain(|e| e.0 != "kind" && e.0 != "apiVersion");
        o.insert(0, (String::from("kind"), Value::from(kind)));
        o.insert(0, (String::from("apiVersion"), Value::from(api_version)));
    }
    Ok(v)
}

/// Sets `key`, replacing an existing entry (proto "last one wins").
fn set(o: &mut Object, key: &str, v: Value) {
    match o.iter_mut().find(|e| e.0 == key) {
        Some(e) => e.1 = v,
        None => o.push((String::from(key), v)),
    }
}

/// The value stored under `key`, created by `make` when absent.
fn slot<'a>(o: &'a mut Object, key: &str, make: fn() -> Value) -> &'a mut Value {
    let i = match o.iter().position(|e| e.0 == key) {
        Some(i) => i,
        None => {
            o.push((String::from(key), make()));
            o.len() - 1
        }
    };
    &mut o[i].1
}

fn field_name(f: &s::Field) -> &'static str {
    &s::NAMES[f.name_off as usize..f.name_off as usize + f.name_len as usize]
}

fn fields_of(idx: u16) -> &'static [s::Field] {
    &s::FIELDS[s::MSG_START[idx as usize] as usize..s::MSG_START[idx as usize + 1] as usize]
}

/// Decodes one message of type `idx`. Zero `Time`s and empty raw JSON come back as `Null`.
fn message(buf: &[u8], idx: u16, depth: usize) -> R<Value> {
    if depth > MAX_DEPTH {
        return Err("protobuf: messages nested too deeply");
    }
    match idx {
        s::M_TIME => return time(buf, false),
        s::M_MICRO_TIME => return time(buf, true),
        s::M_DURATION => return duration(buf),
        s::M_INT_OR_STRING => return int_or_string(buf),
        s::M_QUANTITY => return quantity(buf),
        s::M_RAW_EXTENSION | s::M_FIELDS_V1 => return raw_json(buf),
        _ => {}
    }
    let fields = fields_of(idx);
    let mut out = Object::new();
    let mut r = Reader::new(buf);
    while let Some(f) = r.next().map_err(wire_err)? {
        let Some(fd) = u16::try_from(f.number).ok().and_then(|n| fields.binary_search_by_key(&n, |x| x.num).ok()).map(|i| &fields[i]) else {
            continue; // unknown field
        };
        let kind = fd.kind & s::K_MASK;
        let repeated = fd.kind & s::F_REPEATED != 0;
        let name = field_name(fd);
        if kind == s::K_MAP {
            let Some(&(kk, _, vk, va)) = s::MAPS.get(fd.arg as usize) else {
                return Err("protobuf: bad schema");
            };
            let wire::Value::Bytes(entry) = f.value else {
                return Err("protobuf: map entry must be length-delimited");
            };
            let (k, v) = map_entry(entry, kk, vk, va, depth)?;
            let Value::Object(m) = slot(&mut out, name, || Value::Object(Object::new())) else { unreachable!() };
            set(m, &k, v);
            continue;
        }
        let mut vals = Vec::new();
        value(kind, fd.arg, &f.value, repeated, depth, &mut vals)?;
        if repeated {
            let Value::Array(a) = slot(&mut out, name, || Value::Array(Vec::new())) else { unreachable!() };
            a.extend(vals);
            continue;
        }
        let Some(v) = vals.pop() else { continue };
        if matches!(v, Value::Null) || (kind != s::K_MESSAGE && fd.kind & s::F_KEEP_ZERO == 0 && is_zero(&v)) {
            continue;
        }
        if fd.kind & s::F_INLINE != 0 {
            if let Value::Object(o) = v {
                for (k, x) in o {
                    set(&mut out, &k, x);
                }
            }
        } else {
            set(&mut out, name, v);
        }
    }
    Ok(Value::Object(out))
}

fn is_zero(v: &Value) -> bool {
    match v {
        Value::String(s) => s.is_empty(),
        Value::Bool(b) => !*b,
        Value::Number(n) => n.as_f64() == 0.0,
        _ => false,
    }
}

/// Decodes a map entry (`key = 1`, `value = 2`); a missing half takes its default.
fn map_entry(buf: &[u8], key_kind: u8, val_kind: u8, val_arg: u16, depth: usize) -> R<(String, Value)> {
    if key_kind != s::K_STRING {
        return Err("protobuf: only string map keys are supported");
    }
    let (mut key, mut val) = (String::new(), None);
    let mut r = Reader::new(buf);
    while let Some(f) = r.next().map_err(wire_err)? {
        let mut vals = Vec::new();
        match f.number {
            1 => {
                value(s::K_STRING, 0, &f.value, false, depth, &mut vals)?;
                if let Some(Value::String(k)) = vals.pop() {
                    key = k;
                }
            }
            2 => {
                value(val_kind, val_arg, &f.value, false, depth, &mut vals)?;
                val = vals.pop();
            }
            _ => {}
        }
    }
    let val = match val {
        Some(v) => v,
        None if val_kind == s::K_MESSAGE => message(&[], val_arg, depth + 1)?,
        None => zero(val_kind),
    };
    Ok((key, val))
}

fn zero(kind: u8) -> Value {
    match kind {
        s::K_STRING | s::K_BYTES => Value::String(String::new()),
        s::K_BOOL => Value::Bool(false),
        _ => Value::Number(Number::from_i64(0)),
    }
}

/// Decodes one wire value of schema `kind` into `out` (several for packed repeated scalars).
fn value(kind: u8, arg: u16, w: &wire::Value<'_>, repeated: bool, depth: usize, out: &mut Vec<Value>) -> R<()> {
    use wire::Value as W;
    let num = |n: Number| Value::Number(n);
    match (kind, w) {
        (s::K_STRING, W::Bytes(b)) => out.push(Value::String(String::from(core::str::from_utf8(b).map_err(|_| "protobuf: invalid UTF-8")?))),
        (s::K_BYTES, W::Bytes(b)) => out.push(Value::String(kr_fmt::base64::encode(b))),
        (s::K_MESSAGE, W::Bytes(b)) => out.push(message(b, arg, depth + 1)?),
        (s::K_BOOL, W::Varint(v)) => out.push(Value::Bool(*v != 0)),
        (s::K_INT32, W::Varint(v)) => out.push(num(Number::from_i64(i64::from(*v as i32)))),
        (s::K_INT64, W::Varint(v)) => out.push(num(Number::from_i64(*v as i64))),
        (s::K_UINT32, W::Varint(v)) => out.push(num(Number::from_u64(u64::from(*v as u32)))),
        (s::K_UINT64, W::Varint(v)) => out.push(num(Number::from_u64(*v))),
        (s::K_DOUBLE, W::Fixed64(v)) => out.push(num(Number::from_f64(f64::from_bits(*v)).ok_or("protobuf: non-finite number")?)),
        (s::K_FLOAT, W::Fixed32(v)) => out.push(num(Number::from_f64(f64::from(f32::from_bits(*v))).ok_or("protobuf: non-finite number")?)),
        (s::K_BOOL | s::K_INT32 | s::K_INT64 | s::K_UINT32 | s::K_UINT64, W::Bytes(b)) if repeated => {
            // Packed repeated scalars.
            for v in wire::packed_varints(b).map_err(wire_err)? {
                value(kind, arg, &W::Varint(v), false, depth, out)?;
            }
        }
        _ => return Err("protobuf: wire type does not match field type"),
    }
    Ok(())
}

// ---------------------------------------------------------------- special types

/// Feeds every field of a small helper message to `f` as `(number, value)`.
fn simple<'a>(buf: &'a [u8], mut f: impl FnMut(u32, wire::Value<'a>) -> R<()>) -> R<()> {
    let mut r = Reader::new(buf);
    while let Some(x) = r.next().map_err(wire_err)? {
        f(x.number, x.value)?;
    }
    Ok(())
}

/// `meta/v1.Time` / `MicroTime`: RFC 3339 in UTC; `Null` for the zero time.
fn time(buf: &[u8], micro: bool) -> R<Value> {
    let (mut secs, mut nanos) = (0i64, 0i32);
    simple(buf, |n, v| {
        match (n, v) {
            (1, wire::Value::Varint(x)) => secs = x as i64,
            (2, wire::Value::Varint(x)) => nanos = x as i32,
            (1 | 2, _) => return Err("protobuf: wrong wire type in Time"),
            _ => {}
        }
        Ok(())
    })?;
    if secs == 0 && nanos == 0 {
        return Ok(Value::Null);
    }
    if !(0..1_000_000_000).contains(&nanos) {
        return Err("protobuf: invalid time nanos");
    }
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    if !(0..=9999).contains(&y) {
        return Err("protobuf: time out of range");
    }
    let (hh, mm, ss) = (tod / 3600, tod % 3600 / 60, tod % 60);
    Ok(Value::String(if micro {
        alloc::format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{:06}Z", nanos / 1000)
    } else {
        alloc::format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
    }))
}

/// Proleptic Gregorian date for a day count since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// `meta/v1.Duration`: a Go duration string.
fn duration(buf: &[u8]) -> R<Value> {
    let mut ns = 0i64;
    simple(buf, |n, v| match (n, v) {
        (1, wire::Value::Varint(x)) => {
            ns = x as i64;
            Ok(())
        }
        (1, _) => Err("protobuf: wrong wire type in Duration"),
        _ => Ok(()),
    })?;
    Ok(Value::String(kr_fmt::quantity::format_duration(ns)))
}

/// `util/intstr.IntOrString`: a number or a string.
fn int_or_string(buf: &[u8]) -> R<Value> {
    let (mut ty, mut int, mut st) = (0u64, 0i32, String::new());
    simple(buf, |n, v| {
        match (n, v) {
            (1, wire::Value::Varint(x)) => ty = x,
            (2, wire::Value::Varint(x)) => int = x as i32,
            (3, wire::Value::Bytes(b)) => st = String::from(core::str::from_utf8(b).map_err(|_| "protobuf: invalid UTF-8")?),
            (1..=3, _) => return Err("protobuf: wrong wire type in IntOrString"),
            _ => {}
        }
        Ok(())
    })?;
    match ty {
        0 => Ok(Value::Number(Number::from_i64(i64::from(int)))),
        1 => Ok(Value::String(st)),
        _ => Err("protobuf: invalid IntOrString type"),
    }
}

/// `api/resource.Quantity`: its canonical string.
fn quantity(buf: &[u8]) -> R<Value> {
    let mut q = String::new();
    simple(buf, |n, v| match (n, v) {
        (1, wire::Value::Bytes(b)) => {
            q = String::from(core::str::from_utf8(b).map_err(|_| "protobuf: invalid UTF-8")?);
            Ok(())
        }
        (1, _) => Err("protobuf: wrong wire type in Quantity"),
        _ => Ok(()),
    })?;
    Ok(Value::String(q))
}

/// `runtime.RawExtension` / `meta/v1.FieldsV1`: the embedded JSON document.
fn raw_json(buf: &[u8]) -> R<Value> {
    let mut raw: &[u8] = &[];
    simple(buf, |n, v| match (n, v) {
        (1, wire::Value::Bytes(b)) => {
            raw = b;
            Ok(())
        }
        (1, _) => Err("protobuf: wrong wire type in raw JSON"),
        _ => Ok(()),
    })?;
    if raw.is_empty() {
        return Ok(Value::Null);
    }
    json::parse(raw).map_err(|_| "protobuf: invalid embedded JSON")
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_fmt::proto::Writer;

    fn envelope(api_version: &str, kind: &str, raw: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        w.message(1, |t| {
            t.string(1, api_version);
            t.string(2, kind);
        });
        w.bytes(2, raw);
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(w.as_bytes());
        out
    }

    #[test]
    fn minimal_namespace() {
        let mut meta = Writer::new();
        meta.string(1, "demo");
        let mut ns = Writer::new();
        ns.bytes(1, meta.as_bytes());
        let v = decode_body(&envelope("v1", "Namespace", ns.as_bytes())).unwrap();
        assert_eq!(v, json::parse(br#"{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"demo"}}"#).unwrap());
    }

    #[test]
    fn rejects_bad_input() {
        assert!(decode_body(b"").is_err());
        assert!(decode_body(b"k8s\x01").is_err());
        assert!(decode_body(b"k8s\0").is_err()); // no raw
        assert!(decode_body(&envelope("v1", "Nope", b"")).is_err());
        assert!(decode_body(&envelope("apps/v1", "Namespace", b"")).is_err());
        let ok = envelope("v1", "Namespace", &[0x0a, 0x00]);
        assert!(decode_body(&ok).is_ok());
        // Every truncation of a valid body is an error or a different valid prefix, never a panic.
        for n in 0..ok.len() {
            let _ = decode_body(&ok[..n]);
        }
        // Wrong wire type for metadata (varint instead of bytes), and an 11-byte varint.
        assert!(decode_body(&envelope("v1", "Namespace", &[0x08, 0x01])).is_err());
        assert!(decode_body(&envelope("v1", "Namespace", &[0x08, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01])).is_err());
        // Length prefix beyond the buffer.
        assert!(decode_body(&envelope("v1", "Namespace", &[0x0a, 0x7f, 0x00])).is_err());
        // Content encoding is not supported.
        let mut w = Writer::new();
        w.message(1, |t| {
            t.string(1, "v1");
            t.string(2, "Namespace");
        });
        w.bytes(2, b"");
        w.string(3, "gzip");
        let mut b = MAGIC.to_vec();
        b.extend_from_slice(w.as_bytes());
        assert!(decode_body(&b).is_err());
    }

    #[test]
    fn skips_unknown_fields() {
        let mut ns = Writer::new();
        ns.varint(99, 7);
        ns.string(98, "x");
        ns.fixed64(97, 1);
        ns.fixed32(96, 1);
        let v = decode_body(&envelope("v1", "Namespace", ns.as_bytes())).unwrap();
        assert_eq!(v, json::parse(br#"{"apiVersion":"v1","kind":"Namespace"}"#).unwrap());
    }

    #[test]
    fn depth_limit() {
        // No served kind nests anywhere near the limit, so exercise the guard directly.
        assert!(message(&[], 0, MAX_DEPTH + 1).is_err());
    }

    #[test]
    fn time_formats() {
        let mut w = Writer::new();
        w.int64(1, 1_715_951_045).varint(2, 999);
        assert_eq!(time(w.as_bytes(), false).unwrap(), Value::from("2024-05-17T13:04:05Z"));
        let mut w = Writer::new();
        w.int64(1, 1_715_951_045).varint(2, 123_456_000);
        assert_eq!(time(w.as_bytes(), true).unwrap(), Value::from("2024-05-17T13:04:05.123456Z"));
        let mut w = Writer::new();
        w.int64(1, -1);
        assert_eq!(time(w.as_bytes(), false).unwrap(), Value::from("1969-12-31T23:59:59Z"));
        let mut w = Writer::new();
        w.int64(1, 951_782_400); // 2000-02-29
        assert_eq!(time(w.as_bytes(), false).unwrap(), Value::from("2000-02-29T00:00:00Z"));
        assert_eq!(time(&[], false).unwrap(), Value::Null);
    }

    #[test]
    fn special_types() {
        let mut w = Writer::new();
        w.int64(1, 90 * 60 * 1_000_000_000);
        assert_eq!(duration(w.as_bytes()).unwrap(), Value::from("1h30m0s"));
        let mut w = Writer::new();
        w.varint(1, 1).string(3, "http");
        assert_eq!(int_or_string(w.as_bytes()).unwrap(), Value::from("http"));
        let mut w = Writer::new();
        w.varint(2, 8080);
        assert_eq!(int_or_string(w.as_bytes()).unwrap(), Value::Number(Number::from_i64(8080)));
        let mut w = Writer::new();
        w.bytes(1, br#"{"a":[1,2]}"#);
        assert_eq!(raw_json(w.as_bytes()).unwrap(), json::parse(br#"{"a":[1,2]}"#).unwrap());
        let mut w = Writer::new();
        w.bytes(1, b"{");
        assert!(raw_json(w.as_bytes()).is_err());
    }
}
