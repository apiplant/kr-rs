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
    decode_body_as(body, None)
}

/// Like [`decode_body`]; `fallback` (apiVersion, kind) applies when the envelope's TypeMeta
/// is empty (client-go sends DeleteOptions that way).
pub fn decode_body_as(body: &[u8], fallback: Option<(&'static str, &'static str)>) -> R<Value> {
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
    if let (true, Some((av, k))) = (kind.is_empty(), fallback) {
        (api_version, kind) = (av, k);
    }
    let idx = s::KINDS.iter().find(|k| (k.0 == api_version || (api_version == "meta.k8s.io/v1" && k.0 == "v1" && kind == "DeleteOptions")) && k.1 == kind).map(|k| k.2).ok_or("protobuf: unsupported kind")?;
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
        s::M_RAW_EXTENSION | s::M_FIELDS_V1 | s::M_EXT_JSON => return raw_json(buf),
        s::M_SCHEMA_OR_ARRAY | s::M_SCHEMA_OR_BOOL | s::M_SCHEMA_OR_STRINGS => return schema_union(buf, idx, depth),
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

/// The CRD schema unions, whose JSON form is one of their alternatives:
/// `JSONSchemaPropsOrArray` {1 schema, 2 jSONSchemas} → schema object or array of schemas;
/// `JSONSchemaPropsOrBool` {1 allows, 2 schema} → schema object or bool;
/// `JSONSchemaPropsOrStringArray` {1 schema, 2 property} → schema object or array of strings.
fn schema_union(buf: &[u8], idx: u16, depth: usize) -> R<Value> {
    let schema_num = if idx == s::M_SCHEMA_OR_BOOL { 2 } else { 1 };
    let schema_idx = fields_of(idx).iter().find(|f| f.num == schema_num).map(|f| f.arg).ok_or("protobuf: bad schema")?;
    let (mut schema, mut list, mut allows) = (None, Vec::new(), false);
    simple(buf, |n, v| {
        match (idx, n, v) {
            (_, n, wire::Value::Bytes(b)) if n == schema_num as u32 => schema = Some(message(b, schema_idx, depth + 1)?),
            (s::M_SCHEMA_OR_ARRAY, 2, wire::Value::Bytes(b)) => list.push(message(b, schema_idx, depth + 1)?),
            (s::M_SCHEMA_OR_STRINGS, 2, wire::Value::Bytes(b)) => list.push(Value::from(core::str::from_utf8(b).map_err(|_| "protobuf: invalid UTF-8")?)),
            (s::M_SCHEMA_OR_BOOL, 1, wire::Value::Varint(x)) => allows = x != 0,
            (_, 1 | 2, _) => return Err("protobuf: wrong wire type in schema union"),
            _ => {}
        }
        Ok(())
    })?;
    Ok(match (schema, idx) {
        (Some(v), _) => v,
        (None, s::M_SCHEMA_OR_BOOL) => Value::Bool(allows),
        (None, _) => Value::Array(list),
    })
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

// ---------------------------------------------------------------- encoding (responses)

/// Encodes a JSON object of a kind in [`s::KINDS`] as a `k8s\0` protobuf body (the inverse of
/// [`decode_body`]); `None` if the kind has no protobuf form (custom resources, Tables) or a
/// value does not fit its field, in which case the caller answers in JSON. Fields the tables
/// do not know are dropped, as a typed Go client would.
pub fn encode_body(v: &Value) -> Option<Vec<u8>> {
    let api_version = v.get("apiVersion")?.as_str()?;
    let kind = v.get("kind")?.as_str()?;
    let idx = s::KINDS.iter().find(|k| k.0 == api_version && k.1 == kind)?.2;
    let mut raw = Writer::new();
    encode_message(&mut raw, v, idx, 0)?;
    let mut w = Writer::new();
    w.message(1, |t| {
        t.string(1, api_version);
        t.string(2, kind);
    });
    w.bytes(2, raw.as_bytes());
    w.string(3, "");
    w.string(4, "");
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(w.as_bytes());
    Some(out)
}

use kr_fmt::proto::Writer;

/// Writes the fields of message `idx` found in the JSON object `v`.
fn encode_message(w: &mut Writer, v: &Value, idx: u16, depth: usize) -> Option<()> {
    if depth > MAX_DEPTH {
        return None;
    }
    let Value::Object(_) = v else { return None };
    for fd in fields_of(idx) {
        let num = u32::from(fd.num);
        let kind = fd.kind & s::K_MASK;
        if fd.kind & s::F_INLINE != 0 {
            // The embedded message's fields live in this object.
            let mut sub = Writer::new();
            encode_message(&mut sub, v, fd.arg, depth + 1)?;
            if !sub.as_bytes().is_empty() {
                w.bytes(num, sub.as_bytes());
            }
            continue;
        }
        let Some(x) = v.get(field_name(fd)) else { continue };
        if matches!(x, Value::Null) {
            continue;
        }
        if kind == s::K_MAP {
            let &(_, _, vk, va) = s::MAPS.get(fd.arg as usize)?;
            let Value::Object(m) = x else { return None };
            for (k, val) in m {
                let mut e = Writer::new();
                e.string(1, k);
                if !matches!(val, Value::Null) {
                    encode_value(&mut e, 2, vk, va, val, depth)?;
                }
                w.bytes(num, e.as_bytes());
            }
            continue;
        }
        if fd.kind & s::F_REPEATED != 0 {
            let Value::Array(items) = x else { return None };
            for it in items {
                encode_value(w, num, kind, fd.arg, it, depth)?;
            }
            continue;
        }
        encode_value(w, num, kind, fd.arg, x, depth)?;
    }
    Some(())
}

fn encode_value(w: &mut Writer, num: u32, kind: u8, arg: u16, v: &Value, depth: usize) -> Option<()> {
    match kind {
        s::K_STRING => {
            w.string(num, v.as_str()?);
        }
        s::K_BYTES => {
            w.bytes(num, &kr_fmt::base64::decode(v.as_str()?).ok()?);
        }
        s::K_BOOL => {
            w.bool(num, v.as_bool()?);
        }
        s::K_INT32 => {
            let i = i32::try_from(v.as_i64()?).ok()?;
            w.int64(num, i64::from(i));
        }
        s::K_INT64 => {
            w.int64(num, v.as_i64()?);
        }
        s::K_UINT32 | s::K_UINT64 => {
            w.varint(num, v.as_u64()?);
        }
        s::K_DOUBLE => {
            w.fixed64(num, v.as_number()?.as_f64().to_bits());
        }
        s::K_FLOAT => {
            w.fixed32(num, (v.as_number()?.as_f64() as f32).to_bits());
        }
        s::K_MESSAGE => {
            let mut sub = Writer::new();
            encode_special(&mut sub, v, arg, depth + 1)?;
            w.bytes(num, sub.as_bytes());
        }
        _ => return None,
    }
    Some(())
}

/// A message value: the hand-written JSON forms, else a plain object.
fn encode_special(w: &mut Writer, v: &Value, idx: u16, depth: usize) -> Option<()> {
    match idx {
        s::M_TIME | s::M_MICRO_TIME => {
            let (secs, nanos) = parse_time(v.as_str()?)?;
            if secs != 0 {
                w.int64(1, secs);
            }
            if nanos != 0 {
                w.int64(2, i64::from(nanos));
            }
        }
        s::M_DURATION => {
            w.int64(1, kr_fmt::quantity::parse_duration(v.as_str()?).ok()?);
        }
        s::M_INT_OR_STRING => match v {
            Value::String(st) => {
                w.varint(1, 1).string(3, st);
            }
            _ => {
                let i = i32::try_from(v.as_i64()?).ok()?;
                w.varint(1, 0).int64(2, i64::from(i));
            }
        },
        s::M_QUANTITY => match v {
            Value::String(q) => {
                w.string(1, q);
            }
            Value::Number(n) => {
                w.string(1, &json::to_string(&Value::Number(n.clone())));
            }
            _ => return None,
        },
        s::M_RAW_EXTENSION | s::M_FIELDS_V1 | s::M_EXT_JSON => {
            w.bytes(1, json::to_string(v).as_bytes());
        }
        s::M_SCHEMA_OR_ARRAY | s::M_SCHEMA_OR_BOOL | s::M_SCHEMA_OR_STRINGS => {
            let schema_num = if idx == s::M_SCHEMA_OR_BOOL { 2 } else { 1 };
            let schema_idx = fields_of(idx).iter().find(|f| f.num == schema_num)?.arg;
            match v {
                Value::Bool(b) if idx == s::M_SCHEMA_OR_BOOL => {
                    w.bool(1, *b);
                }
                Value::Object(_) => {
                    if idx == s::M_SCHEMA_OR_BOOL {
                        w.bool(1, true);
                    }
                    let mut sub = Writer::new();
                    encode_message(&mut sub, v, schema_idx, depth + 1)?;
                    w.bytes(u32::from(schema_num), sub.as_bytes());
                }
                Value::Array(items) if idx != s::M_SCHEMA_OR_BOOL => {
                    for it in items {
                        if idx == s::M_SCHEMA_OR_STRINGS {
                            w.string(2, it.as_str()?);
                        } else {
                            let mut sub = Writer::new();
                            encode_message(&mut sub, it, schema_idx, depth + 1)?;
                            w.bytes(2, sub.as_bytes());
                        }
                    }
                }
                _ => return None,
            }
        }
        _ => encode_message(w, v, idx, depth)?,
    }
    Some(())
}

/// `YYYY-MM-DDTHH:MM:SS[.fraction]Z` to (seconds, nanos).
fn parse_time(t: &str) -> Option<(i64, i32)> {
    let (head, nanos) = match t.split_once('.') {
        Some((h, frac)) => {
            let digits = frac.strip_suffix('Z')?;
            if digits.is_empty() || digits.len() > 9 || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let n: i32 = digits.parse().ok()?;
            (alloc::format!("{h}Z"), n * 10i32.pow(9 - digits.len() as u32))
        }
        None => (String::from(t), 0),
    };
    Some((crate::printers::parse_rfc3339(&head)?, nanos))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn custom_resource_definition() {
        // properties.n: integer with default 3; items: array of strings; additionalProperties
        // false; x-kubernetes-preserve-unknown-fields on the root.
        let mut json_raw = Writer::new();
        json_raw.bytes(1, b"3");
        let mut n = Writer::new();
        n.string(5, "integer");
        n.bytes(8, json_raw.as_bytes());
        let mut item = Writer::new();
        item.string(5, "string");
        let mut items = Writer::new();
        items.bytes(1, item.as_bytes());
        let mut list = Writer::new();
        list.string(5, "array");
        list.bytes(24, items.as_bytes());
        let mut no_extra = Writer::new();
        no_extra.varint(1, 0);
        let mut root = Writer::new();
        root.string(5, "object");
        for (k, v) in [("n", &n), ("list", &list)] {
            root.message(29, |e| {
                e.string(1, k);
                e.bytes(2, v.as_bytes());
            });
        }
        root.bytes(30, no_extra.as_bytes());
        root.varint(38, 1);
        let mut validation = Writer::new();
        validation.bytes(1, root.as_bytes());
        let mut version = Writer::new();
        version.string(1, "v1").varint(2, 1).varint(3, 1);
        version.bytes(4, validation.as_bytes());
        let mut names = Writer::new();
        names.string(1, "widgets").string(4, "Widget");
        let mut spec = Writer::new();
        spec.string(1, "example.com");
        spec.bytes(3, names.as_bytes());
        spec.string(4, "Namespaced");
        spec.bytes(7, version.as_bytes());
        let mut meta = Writer::new();
        meta.string(1, "widgets.example.com");
        let mut crd = Writer::new();
        crd.bytes(1, meta.as_bytes());
        crd.bytes(2, spec.as_bytes());
        let v = decode_body(&envelope("apiextensions.k8s.io/v1", "CustomResourceDefinition", crd.as_bytes())).unwrap();
        let want = br#"{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"widgets.example.com"},
            "spec":{"group":"example.com","names":{"plural":"widgets","kind":"Widget"},"scope":"Namespaced","versions":[{"name":"v1","served":true,"storage":true,
            "schema":{"openAPIV3Schema":{"type":"object","properties":{"n":{"type":"integer","default":3},"list":{"type":"array","items":{"type":"string"}}},
            "additionalProperties":false,"x-kubernetes-preserve-unknown-fields":true}}}]}}"#;
        let got = v.pointer(&["spec", "versions"]).cloned();
        let want = json::parse(want).unwrap();
        assert_eq!(got, want.pointer(&["spec", "versions"]).cloned());
        assert_eq!(v.pointer(&["spec", "names"]), want.pointer(&["spec", "names"]));
        // The union alternatives: a schema wins over the bool, string arrays stay strings.
        let mut ob = Writer::new();
        ob.varint(1, 1);
        assert_eq!(schema_union(ob.as_bytes(), s::M_SCHEMA_OR_BOOL, 0).unwrap(), Value::Bool(true));
        let mut sa = Writer::new();
        sa.string(2, "a").string(2, "b");
        assert_eq!(schema_union(sa.as_bytes(), s::M_SCHEMA_OR_STRINGS, 0).unwrap(), json::parse(br#"["a","b"]"#).unwrap());
    }

    #[test]
    fn binding_and_eviction_bodies() {
        let mut meta = Writer::new();
        meta.string(1, "p");
        let mut target = Writer::new();
        target.string(3, "node-1").string(1, "Node");
        let mut b = Writer::new();
        b.bytes(1, meta.as_bytes());
        b.bytes(2, target.as_bytes());
        let v = decode_body(&envelope("v1", "Binding", b.as_bytes())).unwrap();
        assert_eq!(v.pointer(&["target", "name"]).and_then(Value::as_str), Some("node-1"));
        let mut e = Writer::new();
        e.bytes(1, meta.as_bytes());
        let v = decode_body(&envelope("policy/v1", "Eviction", e.as_bytes())).unwrap();
        assert_eq!(v.pointer(&["metadata", "name"]).and_then(Value::as_str), Some("p"));
    }

    fn sorted(v: &Value) -> Value {
        match v {
            Value::Object(o) => {
                let mut o: Vec<(String, Value)> = o.iter().map(|(k, x)| (k.clone(), sorted(x))).collect();
                o.sort_by(|a, b| a.0.cmp(&b.0));
                Value::Object(o)
            }
            Value::Array(a) => Value::Array(a.iter().map(sorted).collect()),
            x => x.clone(),
        }
    }

    fn roundtrip(src: &[u8]) {
        let v = json::parse(src).unwrap();
        let b = encode_body(&v).expect("encodes");
        assert_eq!(sorted(&decode_body(&b).unwrap()), sorted(&v), "{}", core::str::from_utf8(src).unwrap());
    }

    #[test]
    fn responses_roundtrip() {
        roundtrip(br#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p","namespace":"d","uid":"u-1","resourceVersion":"42","creationTimestamp":"2024-05-17T13:04:05Z","labels":{"app":"web"},"ownerReferences":[{"apiVersion":"apps/v1","kind":"ReplicaSet","name":"rs","uid":"u-2","controller":true}],
            "managedFields":[{"manager":"kubectl","operation":"Update","apiVersion":"v1","time":"2024-05-17T13:04:05Z","fieldsType":"FieldsV1","fieldsV1":{"f:spec":{}}}]},
            "spec":{"containers":[{"name":"c","image":"busybox","command":["sleep","3600"],"ports":[{"containerPort":80,"protocol":"TCP"}],
            "resources":{"limits":{"memory":"64Mi","cpu":"500m"}},"livenessProbe":{"httpGet":{"path":"/","port":"http"},"periodSeconds":10},"readinessProbe":{"tcpSocket":{"port":8080}}}],
            "terminationGracePeriodSeconds":30,"nodeName":"n1","securityContext":{}},
            "status":{"phase":"Running","podIP":"10.42.0.5","startTime":"2024-05-17T13:04:06Z","conditions":[{"type":"Ready","status":"True","lastTransitionTime":"2024-05-17T13:04:07Z"}],
            "containerStatuses":[{"name":"c","ready":true,"restartCount":0,"image":"busybox","imageID":"sha256:x","state":{"running":{"startedAt":"2024-05-17T13:04:07Z"}}}]}}"#);
        roundtrip(br#"{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7","continue":"abc"},"items":[{"metadata":{"name":"a"}},{"metadata":{"name":"b"}}]}"#);
        roundtrip(br#"{"apiVersion":"v1","kind":"Status","metadata":{},"status":"Failure","message":"pods x not found","reason":"NotFound","details":{"name":"x","kind":"pods"},"code":404}"#);
        roundtrip(br#"{"apiVersion":"coordination.k8s.io/v1","kind":"Lease","metadata":{"name":"n"},"spec":{"holderIdentity":"n","leaseDurationSeconds":40,"renewTime":"2024-05-17T13:04:05.123456Z"}}"#);
        roundtrip(br#"{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"w.example.com"},"spec":{"group":"example.com","names":{"plural":"w","kind":"W"},"scope":"Namespaced",
            "versions":[{"name":"v1","served":true,"storage":true,"schema":{"openAPIV3Schema":{"type":"object","properties":{"n":{"type":"integer","default":3},"l":{"type":"array","items":{"type":"string"}},"m":{"type":"object","additionalProperties":{"type":"string"}}},"additionalProperties":false,"required":["n"],"x-kubernetes-preserve-unknown-fields":true}}}]}}"#);
        // No protobuf form: custom resources and Tables stay JSON.
        assert!(encode_body(&json::parse(br#"{"apiVersion":"example.com/v1","kind":"W"}"#).unwrap()).is_none());
        assert!(encode_body(&json::parse(br#"{"apiVersion":"meta.k8s.io/v1","kind":"Table"}"#).unwrap()).is_none());
        // A value that does not fit its field refuses (the caller falls back to JSON).
        assert!(encode_body(&json::parse(br#"{"apiVersion":"v1","kind":"Pod","spec":{"containers":"x"}}"#).unwrap()).is_none());
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
