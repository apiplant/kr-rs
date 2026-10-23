//! The Endpoints and EndpointSlice controller: for every Service with a selector it publishes
//! where the traffic goes.
//!
//! Services without a selector are left alone (their Endpoints are managed by hand). Pods that
//! match the selector, have a `status.podIP` and are not Succeeded/Failed are endpoints:
//!
//! * **Endpoints** (same name as the Service): pods that are Ready are `addresses`, the others
//!   `notReadyAddresses` (both `addresses` when `publishNotReadyAddresses`); terminating pods
//!   are left out. Addresses carry `nodeName`, `targetRef` and, for pods whose `subdomain` is the
//!   Service's name, `hostname`. Pods are grouped by their resolved port list into subsets, like
//!   upstream's repacking; addresses are sorted by IP. Labels are the Service's.
//! * **EndpointSlices** `<svc>-<hash>` (label `kubernetes.io/service-name`, managed-by label,
//!   owner reference to the Service, addressType IPv4): one endpoint per pod with conditions
//!   `ready` (Ready and not terminating, or `publishNotReadyAddresses`), `serving` (Ready) and
//!   `terminating`. Pods are grouped by resolved ports (one slice each, 100 endpoints at most per
//!   slice); with no pods a placeholder slice keeps the ports that need no pod to resolve.
//!   Slices of the Service that are no longer wanted are deleted. IPv6 pod IPs are not published.
//! * **Ports.** Each Service port resolves per pod: no `targetPort` means `port`, a number is
//!   used as is and a name is looked up in the pod's container ports (same protocol). A port that
//!   does not resolve for a pod is left out for that pod.
//!
//! Watches Services and Pods; a Pod event re-evaluates every Service of its namespace
//! (key `<ns>/*`). When a Service is gone its Endpoints and slices are deleted.

use crate::util::*;
use crate::Config;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_apiserver::client::{Client, Result};
use kr_fmt::json::{self, Value};

pub const SERVICE_LABEL: &str = "kubernetes.io/service-name";
pub const MANAGED_BY: &str = "endpointslice.kubernetes.io/managed-by";
pub const MANAGER: &str = "endpointslice-controller.k8s.io";
const MAX_PER_SLICE: usize = 100;

pub async fn run<C: Client + Clone + 'static>(c: C, cfg: Config) {
    let q = Queue::new();
    let mut g = Guard::default();
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), services(None), String::new(), cfg, move |_, o| q2.add(&key_of(o)))));
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), pods(None), String::new(), cfg, move |_, p| q2.add(&alloc::format!("{}/*", namespace(p))))));
    let (c2, q2) = (c.clone(), q.clone());
    let (c3, q3) = (c.clone(), q.clone());
    drive(
        &cfg,
        &q,
        move |key| {
            let (c, q) = (c2.clone(), q2.clone());
            async move {
                let (ns, n) = split_key(&key);
                if n == "*" {
                    for s in items(&c.list(&services(Some(ns)), "").await?) {
                        q.add(&key_of(&s));
                    }
                    return Ok(None);
                }
                reconcile(&c, ns, n).await?;
                Ok(None)
            }
        },
        move || {
            let (c, q) = (c3.clone(), q3.clone());
            async move {
                if let Ok(l) = c.list(&services(None), "").await {
                    for s in items(&l) {
                        q.add(&key_of(&s));
                    }
                }
            }
        },
    )
    .await
}

/// One resolved Service port: `(name, port, protocol)`.
type Port = (String, i64, String);

fn protocol(p: &Value) -> &str {
    match str_at(p, &["protocol"]) {
        "" => "TCP",
        s => s,
    }
}

fn port_value(p: &Port) -> Value {
    let mut v = Value::Object(Vec::new());
    if !p.0.is_empty() {
        v.set("name", Value::from(p.0.as_str()));
    }
    v.set("port", num(p.1));
    v.set("protocol", Value::from(p.2.as_str()));
    v
}

/// Resolves one Service port for a pod (`None` when the named port does not exist).
fn resolve_port(sp: &Value, pod: Option<&Value>) -> Option<Port> {
    let proto = protocol(sp).to_string();
    let n = match sp.get("targetPort") {
        None | Some(Value::Null) => int_at(sp, &["port"], 0),
        Some(Value::Number(n)) => match n.as_i64().unwrap_or(0) {
            0 => int_at(sp, &["port"], 0),
            n => n,
        },
        Some(Value::String(s)) => {
            let cs = pod?.pointer(&["spec", "containers"]).and_then(Value::as_array)?;
            cs.iter().flat_map(|c| c.get("ports").and_then(Value::as_array).unwrap_or(&[]).iter()).find(|p| str_at(p, &["name"]) == s && protocol(p) == proto).and_then(|p| p.get("containerPort")?.as_i64())?
        }
        _ => return None,
    };
    Some((str_at(sp, &["name"]).to_string(), n, proto))
}

struct Member {
    ip: String,
    node: String,
    pod_name: String,
    pod_uid: String,
    hostname: Option<String>,
    ready: bool,
    terminating: bool,
}

fn target_ref(m: &Member, ns: &str) -> Value {
    obj(alloc::vec![("kind", Value::from("Pod")), ("namespace", Value::from(ns)), ("name", Value::from(m.pod_name.as_str())), ("uid", Value::from(m.pod_uid.as_str()))])
}

fn address(m: &Member, ns: &str) -> Value {
    let mut a = obj(alloc::vec![("ip", Value::from(m.ip.as_str()))]);
    if let Some(h) = &m.hostname {
        a.set("hostname", Value::from(h.as_str()));
    }
    if !m.node.is_empty() {
        a.set("nodeName", Value::from(m.node.as_str()));
    }
    a.set("targetRef", target_ref(m, ns));
    a
}

fn selector_of(svc: &Value) -> Option<String> {
    let sel = svc.pointer(&["spec", "selector"]).and_then(Value::as_object)?;
    let parts: Vec<String> = sel.iter().map(|(k, v)| alloc::format!("{k}={}", v.as_str().unwrap_or(""))).collect();
    (!parts.is_empty()).then(|| parts.join(","))
}

pub async fn reconcile<C: Client>(c: &C, ns: &str, sname: &str) -> Result<()> {
    let Some(svc) = get_opt(c, &alloc::format!("{}/{sname}", services(Some(ns)))).await? else {
        delete_ok(c, &alloc::format!("{}/{sname}", endpoints(Some(ns)))).await?;
        for s in items(&c.list(&endpointslices(Some(ns)), &alloc::format!("labelSelector={}", enc(&alloc::format!("{SERVICE_LABEL}={sname},{MANAGED_BY}={MANAGER}")))).await?) {
            delete_ok(c, &alloc::format!("{}/{}", endpointslices(Some(ns)), name(&s))).await?;
        }
        return Ok(());
    };
    if deleting(&svc) {
        return Ok(());
    }
    let Some(sel) = selector_of(&svc) else { return Ok(()) };
    let publish_unready = svc.pointer(&["spec", "publishNotReadyAddresses"]).and_then(Value::as_bool) == Some(true);
    let headless = str_at(&svc, &["spec", "clusterIP"]) == "None";
    let sports: Vec<Value> = svc.pointer(&["spec", "ports"]).and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();

    let mut pods_l = items(&c.list(&pods(Some(ns)), &alloc::format!("labelSelector={}", enc(&sel))).await?);
    pods_l.sort_by(|a, b| name(a).cmp(name(b)));
    // port list -> members
    let mut groups: BTreeMap<String, (Vec<Port>, Vec<Member>)> = BTreeMap::new();
    for p in &pods_l {
        let ip = str_at(p, &["status", "podIP"]);
        if ip.is_empty() || pod_terminal(p) {
            continue;
        }
        let ports: Vec<Port> = if sports.is_empty() { Vec::new() } else { sports.iter().filter_map(|sp| resolve_port(sp, Some(p))).collect() };
        if ports.is_empty() && !sports.is_empty() {
            continue; // none of the Service's ports exists on this pod
        }
        let key = json::to_string(&Value::Array(ports.iter().map(port_value).collect()));
        let hostname = (!str_at(p, &["spec", "hostname"]).is_empty() && str_at(p, &["spec", "subdomain"]) == sname).then(|| str_at(p, &["spec", "hostname"]).to_string());
        let m = Member {
            ip: ip.to_string(),
            node: str_at(p, &["spec", "nodeName"]).to_string(),
            pod_name: name(p).to_string(),
            pod_uid: uid(p).to_string(),
            hostname,
            ready: pod_ready(p) && str_at(p, &["status", "phase"]) != "Pending",
            terminating: deleting(p),
        };
        groups.entry(key).or_insert_with(|| (ports, Vec::new())).1.push(m);
    }
    for (_, ms) in groups.values_mut() {
        ms.sort_by(|a, b| (a.ip.as_str(), a.pod_name.as_str()).cmp(&(b.ip.as_str(), b.pod_name.as_str())));
    }

    write_endpoints(c, &svc, &groups, publish_unready, headless).await?;
    write_slices(c, &svc, &groups, &sports, publish_unready).await
}

async fn write_endpoints<C: Client>(c: &C, svc: &Value, groups: &BTreeMap<String, (Vec<Port>, Vec<Member>)>, publish_unready: bool, headless: bool) -> Result<()> {
    let ns = namespace(svc);
    let mut subsets: Vec<Value> = Vec::new();
    for (ports, ms) in groups.values() {
        let (mut ready, mut unready) = (Vec::new(), Vec::new());
        for m in ms.iter().filter(|m| !m.terminating) {
            if m.ready || publish_unready {
                ready.push(address(m, ns));
            } else {
                unready.push(address(m, ns));
            }
        }
        if ready.is_empty() && unready.is_empty() {
            continue;
        }
        let mut s = Value::Object(Vec::new());
        if !ready.is_empty() {
            s.set("addresses", Value::Array(ready));
        }
        if !unready.is_empty() {
            s.set("notReadyAddresses", Value::Array(unready));
        }
        if !ports.is_empty() {
            s.set("ports", Value::Array(ports.iter().map(port_value).collect()));
        }
        subsets.push(s);
    }
    let mut labels = svc.pointer(&["metadata", "labels"]).cloned().unwrap_or(Value::Object(Vec::new()));
    if headless {
        labels.set("service.kubernetes.io/headless", Value::from(""));
    }
    let want_subsets = Value::Array(subsets);
    let path = alloc::format!("{}/{}", endpoints(Some(ns)), name(svc));
    retry_conflict(|| async {
        match get_opt(c, &path).await? {
            None => {
                let ep = obj(alloc::vec![
                    ("apiVersion", Value::from("v1")),
                    ("kind", Value::from("Endpoints")),
                    ("metadata", obj(alloc::vec![("name", Value::from(name(svc))), ("namespace", Value::from(ns)), ("labels", labels.clone())])),
                    ("subsets", want_subsets.clone()),
                ]);
                match c.create(&endpoints(Some(ns)), &ep).await {
                    Ok(_) => Ok(()),
                    Err(e) if e.code == 409 => Err(e), // retried: it exists now
                    Err(e) => Err(e),
                }
            }
            Some(mut ep) => {
                let have = ep.get("subsets").cloned().unwrap_or(Value::Array(Vec::new()));
                let have_labels = ep.pointer(&["metadata", "labels"]).cloned().unwrap_or(Value::Object(Vec::new()));
                if canonical(&have) == canonical(&want_subsets) && canonical(&have_labels) == canonical(&labels) {
                    return Ok(());
                }
                ep.set("subsets", want_subsets.clone());
                ep.entry_object("metadata").set("labels", labels.clone());
                c.update(&path, &ep).await.map(|_| ())
            }
        }
    })
    .await
}

fn slice_name(svc: &Value, key: &str, chunk: usize) -> String {
    let h = fnv1a32(alloc::format!("{}/{}|{key}|{chunk}", namespace(svc), name(svc)).as_bytes());
    alloc::format!("{}-{}", name(svc), safe_encode(&h.to_string()))
}

async fn write_slices<C: Client>(c: &C, svc: &Value, groups: &BTreeMap<String, (Vec<Port>, Vec<Member>)>, sports: &[Value], publish_unready: bool) -> Result<()> {
    let ns = namespace(svc);
    // (name, ports, endpoints)
    let mut wanted: Vec<(String, Vec<Value>, Vec<Value>)> = Vec::new();
    for (key, (ports, ms)) in groups {
        let ms: Vec<&Member> = ms.iter().filter(|m| !m.ip.contains(':')).collect();
        if ms.is_empty() {
            continue;
        }
        for (i, chunk) in ms.chunks(MAX_PER_SLICE).enumerate() {
            let eps = chunk
                .iter()
                .map(|m| {
                    let mut e = obj(alloc::vec![("addresses", Value::Array(alloc::vec![Value::from(m.ip.as_str())]))]);
                    let conds = obj(alloc::vec![
                        ("ready", Value::Bool((m.ready && !m.terminating) || publish_unready)),
                        ("serving", Value::Bool(m.ready || publish_unready)),
                        ("terminating", Value::Bool(m.terminating)),
                    ]);
                    e.set("conditions", conds);
                    if let Some(h) = &m.hostname {
                        e.set("hostname", Value::from(h.as_str()));
                    }
                    if !m.node.is_empty() {
                        e.set("nodeName", Value::from(m.node.as_str()));
                    }
                    e.set("targetRef", target_ref(m, ns));
                    e
                })
                .collect();
            wanted.push((slice_name(svc, key, i), ports.iter().map(port_value).collect(), eps));
        }
    }
    if wanted.is_empty() {
        let ports: Vec<Port> = sports.iter().filter_map(|sp| resolve_port(sp, None)).collect();
        let key = json::to_string(&Value::Array(ports.iter().map(port_value).collect()));
        wanted.push((slice_name(svc, &key, 0), ports.iter().map(port_value).collect(), Vec::new()));
    }

    let existing = items(&c.list(&endpointslices(Some(ns)), &alloc::format!("labelSelector={}", enc(&alloc::format!("{SERVICE_LABEL}={}", name(svc))))).await?);
    for e in &existing {
        if controlled_by(e, uid(svc)) && !wanted.iter().any(|w| w.0 == name(e)) {
            delete_ok(c, &alloc::format!("{}/{}", endpointslices(Some(ns)), name(e))).await?;
        }
    }
    for (sname, ports, eps) in wanted {
        let labels = obj(alloc::vec![(SERVICE_LABEL, Value::from(name(svc))), (MANAGED_BY, Value::from(MANAGER))]);
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
                                ("ownerReferences", Value::Array(alloc::vec![owner_ref(svc, "v1", "Service")])),
                            ])
                        ),
                        ("addressType", Value::from("IPv4")),
                        ("endpoints", eps.clone()),
                        ("ports", ports.clone()),
                    ]);
                    c.create(&endpointslices(Some(ns)), &s).await.map(|_| ())
                }
                Some(mut s) => {
                    let same = canonical(s.get("endpoints").unwrap_or(&Value::Null)) == canonical(&eps)
                        && canonical(s.get("ports").unwrap_or(&Value::Null)) == canonical(&ports)
                        && s.get("addressType").and_then(Value::as_str) == Some("IPv4")
                        && canonical(s.pointer(&["metadata", "labels"]).unwrap_or(&Value::Null)) == canonical(&labels);
                    if same {
                        return Ok(());
                    }
                    s.set("endpoints", eps.clone());
                    s.set("ports", ports.clone());
                    s.set("addressType", Value::from("IPv4"));
                    s.entry_object("metadata").set("labels", labels.clone());
                    c.update(&path, &s).await.map(|_| ())
                }
            }
        })
        .await?;
    }
    Ok(())
}
