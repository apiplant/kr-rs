//! Work the API server hands to the offload workers (ADR-052): rendering big list responses and
//! encoding big audit bodies. A job is bytes in, bytes out ([`handler`] runs in a worker process
//! and sees nothing else); the same function runs inline when no worker is available, so the
//! result never depends on where it ran.

use crate::api::Reply;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use kr_fmt::json::{self, Value};

/// Table rows of a list: `(TableCtx, items)` -> the `rows` array body.
pub const KIND_TABLE_ROWS: u32 = 1;
/// Items of a list that need re-encoding: defaults applied (CRDs) or reduced to metadata.
pub const KIND_ITEMS: u32 = 2;
/// One request or response body of an audit event.
pub const KIND_AUDIT_BODY: u32 = 3;

/// Lists smaller than this (bytes of stored JSON) are rendered on the event loop: shipping them
/// to a worker costs more than it saves.
pub const MIN_BYTES: usize = 256 * 1024;

// ---- framing ----

#[derive(Default)]
pub struct Enc(pub Vec<u8>);

impl Enc {
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(&(b.len() as u32).to_le_bytes());
        self.0.extend_from_slice(b);
        self
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    pub fn i64(&mut self, v: i64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
}

pub struct Dec<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Dec<'a> {
    pub fn new(b: &'a [u8]) -> Dec<'a> {
        Dec { b, p: 0 }
    }
    pub fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = u32::from_le_bytes(self.b.get(self.p..self.p + 4)?.try_into().ok()?) as usize;
        self.p += 4;
        let s = self.b.get(self.p..self.p.checked_add(n)?)?;
        self.p += n;
        Some(s)
    }
    pub fn str(&mut self) -> Option<&'a str> {
        core::str::from_utf8(self.bytes()?).ok()
    }
    pub fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.p)?;
        self.p += 1;
        Some(v)
    }
    pub fn i64(&mut self) -> Option<i64> {
        let v = i64::from_le_bytes(self.b.get(self.p..self.p + 8)?.try_into().ok()?);
        self.p += 8;
        Some(v)
    }
}

// ---- deferred replies ----

/// A response whose rendering was handed to a worker. Created while the (synchronous) request
/// handler runs, awaited by the transport.
pub struct ListJob {
    pub kind: u32,
    pub payload: Vec<u8>,
    /// Turns the worker's output into the reply.
    pub finish: Box<dyn FnOnce(Vec<u8>) -> Reply>,
}

impl ListJob {
    /// Runs the job in a worker, or inline when none can take it.
    pub async fn run(self) -> Reply {
        let out = match kr_rt::offload::call(self.kind, &self.payload).await {
            Some(o) => o,
            None => handler(self.kind, &self.payload),
        };
        (self.finish)(out)
    }
}

// ---- Table rows ----

/// What a Table row needs besides the object.
pub struct TableCtx {
    pub kind: String,
    /// Built-in kinds use the printers of `printers.rs`; custom resources the CRD's columns.
    pub builtin: bool,
    pub cust_main: Vec<String>,
    pub cust_wide: Vec<String>,
    pub own_age: bool,
    pub now: i64,
}

impl TableCtx {
    pub fn encode(&self, e: &mut Enc) {
        e.bytes(self.kind.as_bytes()).u8(self.builtin as u8).u8(self.own_age as u8).i64(self.now);
        for list in [&self.cust_main, &self.cust_wide] {
            e.u8(list.len() as u8);
            for p in list {
                e.bytes(p.as_bytes());
            }
        }
    }

    fn decode(d: &mut Dec) -> Option<TableCtx> {
        let kind = d.str()?.into();
        let builtin = d.u8()? != 0;
        let own_age = d.u8()? != 0;
        let now = d.i64()?;
        let mut lists = [Vec::new(), Vec::new()];
        for l in &mut lists {
            for _ in 0..d.u8()? {
                l.push(d.str()?.into());
            }
        }
        let [cust_main, cust_wide] = lists;
        Some(TableCtx { kind, builtin, cust_main, cust_wide, own_age, now })
    }
}

/// Appends the Table row of object `o` (a JSON object `{"cells":[...],"object":{...}}`).
pub fn write_row(rows: &mut String, o: &Value, ctx: &TableCtx) {
    static EMPTY: Value = Value::Null;
    let meta = o.get("metadata").unwrap_or(&EMPTY);
    let name = meta.get("name").and_then(Value::as_str).unwrap_or("");
    if !rows.is_empty() {
        rows.push(',');
    }
    rows.push_str("{\"cells\":[");
    json::write_str(name, rows);
    let cell = |c: &str, rows: &mut String| {
        rows.push(',');
        json::write_str(c, rows);
    };
    let (extra, wide) = if ctx.builtin { (crate::printers::columns(&ctx.kind), crate::printers::wide_columns(&ctx.kind)) } else { (&[][..], &[][..]) };
    for (_, f) in extra {
        cell(&f(o), rows);
    }
    for p in &ctx.cust_main {
        cell(&crate::crd::json_path(o, p), rows);
    }
    if !ctx.own_age {
        let created = meta.get("creationTimestamp").and_then(Value::as_str).and_then(crate::printers::parse_rfc3339);
        cell(&created.map(|c| crate::printers::human_duration(ctx.now - c)).unwrap_or_else(|| "<unknown>".into()), rows);
    }
    for (_, f) in wide {
        cell(&f(o), rows);
    }
    for p in &ctx.cust_wide {
        cell(&crate::crd::json_path(o, p), rows);
    }
    rows.push_str("],\"object\":{\"kind\":\"PartialObjectMetadata\",\"apiVersion\":\"meta.k8s.io/v1\",\"metadata\":");
    if meta.as_object().is_some() {
        rows.push_str(&json::to_string(meta));
    } else {
        rows.push_str("{}");
    }
    rows.push_str("}}");
}

// ---- the worker side ----

/// The handler the workers run (`kr_rt::offload::init`).
pub fn handler(kind: u32, req: &[u8]) -> Vec<u8> {
    run(kind, req).unwrap_or_default()
}

fn run(kind: u32, req: &[u8]) -> Option<Vec<u8>> {
    let mut d = Dec::new(req);
    match kind {
        KIND_TABLE_ROWS => {
            let ctx = TableCtx::decode(&mut d)?;
            let n = u32::from_le_bytes(d.bytes()?.try_into().ok()?);
            let mut rows = String::with_capacity(n as usize * 600);
            for _ in 0..n {
                let o = json::parse(d.bytes()?).ok()?;
                write_row(&mut rows, &o, &ctx);
            }
            Some(rows.into_bytes())
        }
        KIND_ITEMS => {
            let mode = d.u8()?;
            let schema = if mode == 0 { Some(json::parse(d.bytes()?).ok()?) } else { None };
            let n = u32::from_le_bytes(d.bytes()?.try_into().ok()?);
            let mut out = String::new();
            for i in 0..n {
                let mut v = json::parse(d.bytes()?).unwrap_or(Value::Null);
                if i > 0 {
                    out.push(',');
                }
                match &schema {
                    Some(s) => {
                        crate::crd::prune(s, &mut v, true);
                        out.push_str(&json::to_string(&v));
                    }
                    None => {
                        let meta = v.get("metadata").cloned().unwrap_or(Value::Object(Vec::new()));
                        let po = crate::object::obj(alloc::vec![("kind", Value::from("PartialObjectMetadata")), ("apiVersion", Value::from("meta.k8s.io/v1")), ("metadata", meta)]);
                        out.push_str(&json::to_string(&po));
                    }
                }
            }
            Some(out.into_bytes())
        }
        KIND_AUDIT_BODY => {
            let ctype = d.str()?;
            let omit_managed = d.u8()? != 0;
            let response = d.u8()? != 0;
            Some(crate::audit::render_body(ctype, d.bytes()?, omit_managed, response).map(String::into_bytes).unwrap_or_default())
        }
        _ => None,
    }
}

/// Packs the items of a list for a job: a count and each item's stored JSON.
pub fn pack_items(e: &mut Enc, items: &[kr_store::Kv]) {
    e.bytes(&(items.len() as u32).to_le_bytes());
    for kv in items {
        e.bytes(&kv.value);
    }
}
