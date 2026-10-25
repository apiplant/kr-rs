//! The EndpointSlice mirroring controller: Endpoints written by hand for a Service without a
//! selector are published as EndpointSlices too.
//!
//! * An Endpoints object is mirrored when its Service exists and has no selector and it does not
//!   carry `endpointslice.kubernetes.io/skip-mirror: "true"`. Otherwise (and when the Endpoints
//!   is gone) its mirrored slices are deleted.
//! * Mirrored slices `<endpoints>-<hash>` carry the Endpoints' labels plus `kubernetes.io/service-name`
//!   and `endpointslice.kubernetes.io/managed-by: endpointslicemirroring-controller.k8s.io`, and
//!   an owner reference to the Endpoints. Subsets with the same ports (and address family) share
//!   slices of 100 endpoints at most; `addresses` are ready endpoints, `notReadyAddresses` are
//!   `ready: false`; an IP listed twice for one port set is published once.

use crate::endpoints::{MANAGED_BY, SERVICE_LABEL};
use crate::util::*;
use crate::Config;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_apiserver::client::{Client, Result};
use kr_fmt::json::{self, Value};

pub const MANAGER: &str = "endpointslicemirroring-controller.k8s.io";
const SKIP_LABEL: &str = "endpointslice.kubernetes.io/skip-mirror";
const MAX_PER_SLICE: usize = 100;

pub async fn run<C: Client + Clone + 'static>(c: C, cfg: Config) {
    let q = Queue::new();
    let mut g = Guard::default();
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), endpoints(None), String::new(), cfg, move |_, o| q2.add(&key_of(o)))));
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), services(None), String::new(), cfg, move |_, o| q2.add(&key_of(o)))));
    let (c2, c3, q3) = (c.clone(), c.clone(), q.clone());
    drive(
        &cfg,
        &q,
        move |key| {
            let c = c2.clone();
            async move {
                let (ns, n) = split_key(&key);
                reconcile(&c, ns, n).await?;
                Ok(None)
            }
        },
        move || {
            let (c, q) = (c3.clone(), q3.clone());
            async move {
                if let Ok(l) = c.list(&endpoints(None), "").await {
                    for e in items(&l) {
                        q.add(&key_of(&e));
                    }
                }
                // Mirrored slices whose Endpoints vanished while nobody watched.
                if let Ok(l) = c.list(&endpointslices(None), &alloc::format!("labelSelector={}", enc(&alloc::format!("{MANAGED_BY}={MANAGER}")))).await {
                    for s in items(&l) {
                        q.add(&alloc::format!("{}/{}", namespace(&s), str_at(&s, &["metadata", "labels", SERVICE_LABEL])));
                    }
                }
            }
        },
    )
    .await
}

fn is_ipv6(ip: &str) -> bool {
    ip.contains(':')
}

fn port_key(p: &Value) -> Value {
    let mut v = Value::Object(Vec::new());
    v.set("name", Value::from(str_at(p, &["name"])));
    v.set("port", num(int_at(p, &["port"], 0)));
    v.set("protocol", Value::from(match str_at(p, &["protocol"]) {
        "" => "TCP",
        s => s,
    }));
    if let Some(a) = p.get("appProtocol").and_then(Value::as_str) {
        v.set("appProtocol", Value::from(a));
    }
    v
}

fn endpoint(a: &Value, ready: bool) -> Value {
    let mut e = obj(alloc::vec![("addresses", Value::Array(alloc::vec![Value::from(str_at(a, &["ip"]))]))]);
    e.set("conditions", obj(alloc::vec![("ready", Value::Bool(ready)), ("serving", Value::Bool(ready)), ("terminating", Value::Bool(false))]));
    for (from, to) in [("hostname", "hostname"), ("nodeName", "nodeName")] {
        if let Some(s) = a.get(from).and_then(Value::as_str).filter(|s| !s.is_empty()) {
            e.set(to, Value::from(s));
        }
    }
    if let Some(t) = a.get("targetRef") {
        e.set("targetRef", t.clone());
    }
    e
}

/// The slices that mirror `ep`: `(name, addressType, ports, endpoints)`.
fn desired(ep: &Value) -> Vec<(String, &'static str, Vec<Value>, Vec<Value>)> {
    // (address type, ports) -> endpoints, in subset order.
    let mut groups: BTreeMap<String, (&'static str, Vec<Value>, Vec<Value>)> = BTreeMap::new();
    for sub in ep.get("subsets").and_then(Value::as_array).unwrap_or(&[]) {
        let ports: Vec<Value> = sub.get("ports").and_then(Value::as_array).unwrap_or(&[]).iter().map(port_key).collect();
        for (field, ready) in [("addresses", true), ("notReadyAddresses", false)] {
            for a in sub.get(field).and_then(Value::as_array).unwrap_or(&[]) {
                let ip = str_at(a, &["ip"]);
                if ip.is_empty() {
                    continue;
                }
                let family = if is_ipv6(ip) { "IPv6" } else { "IPv4" };
                let key = json::to_string(&Value::Array(core::iter::once(Value::from(family)).chain(ports.iter().cloned()).collect()));
                let g = groups.entry(key).or_insert_with(|| (family, ports.clone(), Vec::new()));
                if !g.2.iter().any(|e| e.pointer(&["addresses"]).and_then(Value::as_array).and_then(|a| a.first()).and_then(Value::as_str) == Some(ip)) {
                    g.2.push(endpoint(a, ready));
                }
            }
        }
    }
    let mut out = Vec::new();
    for (key, (family, ports, eps)) in groups {
        for (i, chunk) in eps.chunks(MAX_PER_SLICE).enumerate() {
            let h = fnv1a32(alloc::format!("{}/{}|{key}|{i}", namespace(ep), name(ep)).as_bytes());
            out.push((alloc::format!("{}-{}", name(ep), safe_encode(&h.to_string())), family, ports.clone(), chunk.to_vec()));
        }
    }
    out
}

pub async fn reconcile<C: Client>(c: &C, ns: &str, n: &str) -> Result<()> {
    let sel = alloc::format!("labelSelector={}", enc(&alloc::format!("{SERVICE_LABEL}={n},{MANAGED_BY}={MANAGER}")));
    let existing = items(&c.list(&endpointslices(Some(ns)), &sel).await?);
    let ep = get_opt(c, &alloc::format!("{}/{n}", endpoints(Some(ns)))).await?.filter(|e| !deleting(e) && str_at(e, &["metadata", "labels", SKIP_LABEL]) != "true");
    let selectorless = match get_opt(c, &alloc::format!("{}/{n}", services(Some(ns)))).await? {
        Some(s) => !deleting(&s) && s.pointer(&["spec", "selector"]).and_then(Value::as_object).is_none_or(|o| o.is_empty()),
        None => false,
    };
    let wanted = match &ep {
        Some(ep) if selectorless => desired(ep),
        _ => Vec::new(),
    };
    for s in &existing {
        if !wanted.iter().any(|w| w.0 == name(s)) {
            delete_ok(c, &alloc::format!("{}/{}", endpointslices(Some(ns)), name(s))).await?;
        }
    }
    let Some(ep) = ep.filter(|_| selectorless) else { return Ok(()) };
    let mut labels = ep.pointer(&["metadata", "labels"]).cloned().unwrap_or(Value::Object(Vec::new()));
    for k in [SERVICE_LABEL, MANAGED_BY, SKIP_LABEL] {
        labels.remove(k);
    }
    labels.set(SERVICE_LABEL, Value::from(n));
    labels.set(MANAGED_BY, Value::from(MANAGER));
    for (sname, family, ports, eps) in wanted {
        let (ports, eps) = (Value::Array(ports), Value::Array(eps));
        let path = alloc::format!("{}/{sname}", endpointslices(Some(ns)));
        retry_conflict(|| async {
            match get_opt(c, &path).await? {
                None => {
                    let s = obj(alloc::vec![
                        ("apiVersion", Value::from("discovery.k8s.io/v1")),
                        ("kind", Value::from("EndpointSlice")),
                        (
                            "metadata",
                            obj(alloc::vec![
                                ("name", Value::from(sname.as_str())),
                                ("namespace", Value::from(ns)),
                                ("labels", labels.clone()),
                                ("ownerReferences", Value::Array(alloc::vec![owner_ref(&ep, "v1", "Endpoints")])),
                            ])
                        ),
                        ("addressType", Value::from(family)),
                        ("endpoints", eps.clone()),
                        ("ports", ports.clone()),
                    ]);
                    c.create(&endpointslices(Some(ns)), &s).await.map(|_| ())
                }
                Some(mut s) => {
                    let same = canonical(s.get("endpoints").unwrap_or(&Value::Null)) == canonical(&eps)
                        && canonical(s.get("ports").unwrap_or(&Value::Null)) == canonical(&ports)
                        && canonical(s.pointer(&["metadata", "labels"]).unwrap_or(&Value::Null)) == canonical(&labels);
                    if same {
                        return Ok(());
                    }
                    s.set("endpoints", eps.clone());
                    s.set("ports", ports.clone());
                    s.entry_object("metadata").set("labels", labels.clone());
                    c.update(&path, &s).await.map(|_| ())
                }
            }
        })
        .await?;
    }
    Ok(())
}
