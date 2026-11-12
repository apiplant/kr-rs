//! `metrics.k8s.io/v1beta1` (ADR-048): `NodeMetrics` and `PodMetrics` for `kubectl top` and the
//! HPA's resource metrics, served in-process (what k3s gets from metrics-server).
//!
//! [`run`] scrapes every node's kubelet `/metrics/resource` (Prometheus text) every 15 s through a
//! [`Scraper`] and keeps the latest sample per node and per pod. CPU usage is the rate between two
//! scrapes of the cumulative `*_cpu_usage_seconds_total`, so a value appears after the second
//! scrape; memory is the working set. Entries not refreshed for [`STALE_MS`] disappear.

use crate::api::{ApiServer, Query, Reply};
use crate::object::{obj, ApiError, Selector};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;
use core::future::Future;
use core::pin::Pin;
use kr_fmt::json::{self, Value};

pub const GROUP: &str = "metrics.k8s.io";
const REFRESH_MS: u64 = 15_000;
const STALE_MS: i64 = 120_000;
const SCRAPE_TIMEOUT_MS: u64 = 10_000;

/// Fetches `GET /metrics/resource` of a node's kubelet (implemented over the `Router`).
pub trait Scraper {
    fn scrape(&self, node: &str, ip: Option<[u8; 16]>) -> Pin<Box<dyn Future<Output = Option<String>>>>;
}

/// One container's cumulative CPU (seconds) and working-set memory (bytes).
#[derive(Debug, Clone, PartialEq)]
pub struct CtrSample {
    pub ns: String,
    pub pod: String,
    pub container: String,
    pub cpu_secs: f64,
    pub mem: u64,
    pub ts_ms: i64,
}

/// A parsed `/metrics/resource` exposition.
#[derive(Debug, Default, PartialEq)]
pub struct Scrape {
    /// (cumulative CPU seconds, timestamp ms).
    pub node_cpu: Option<(f64, i64)>,
    pub node_mem: Option<u64>,
    pub ctrs: Vec<CtrSample>,
    /// `resource_scrape_error` was 1.
    pub error: bool,
}

/// `name{a="b",...} value [timestamp_ms]` -> (name, labels, value, timestamp).
fn parse_line(line: &str) -> Option<(&str, Vec<(String, String)>, f64, Option<i64>)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (name, mut rest) = match line.find(['{', ' ']) {
        Some(i) => (&line[..i], &line[i..]),
        None => return None,
    };
    let mut labels = Vec::new();
    if let Some(r) = rest.strip_prefix('{') {
        let mut s = r;
        loop {
            s = s.trim_start_matches([' ', ',']);
            if let Some(after) = s.strip_prefix('}') {
                rest = after;
                break;
            }
            let eq = s.find("=\"")?;
            let key = s[..eq].trim().to_string();
            let mut val = String::new();
            let mut chars = s[eq + 2..].char_indices();
            let end = loop {
                let (i, c) = chars.next()?;
                match c {
                    '"' => break eq + 2 + i + 1,
                    '\\' => match chars.next()?.1 {
                        'n' => val.push('\n'),
                        o => val.push(o),
                    },
                    o => val.push(o),
                }
            };
            labels.push((key, val));
            s = &s[end..];
        }
    }
    let mut it = rest.split_whitespace();
    let value: f64 = it.next()?.parse().ok()?;
    let ts = it.next().and_then(|t| t.parse().ok());
    Some((name, labels, value, ts))
}

/// Parses the kubelet's resource metrics; unknown series are ignored.
pub fn parse(text: &str, now_ms: i64) -> Scrape {
    let mut out = Scrape::default();
    let mut cpu: BTreeMap<(String, String, String), (f64, i64)> = BTreeMap::new();
    let mut mem: BTreeMap<(String, String, String), u64> = BTreeMap::new();
    for line in text.lines() {
        let Some((name, labels, v, ts)) = parse_line(line) else { continue };
        let ts = ts.unwrap_or(now_ms);
        let lab = |k: &str| labels.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap_or_default();
        let key = || (lab("namespace"), lab("pod"), lab("container"));
        match name {
            "node_cpu_usage_seconds_total" => out.node_cpu = Some((v, ts)),
            "node_memory_working_set_bytes" => out.node_mem = Some(v as u64),
            "container_cpu_usage_seconds_total" => {
                cpu.insert(key(), (v, ts));
            }
            "container_memory_working_set_bytes" => {
                mem.insert(key(), v as u64);
            }
            "resource_scrape_error" => out.error = v != 0.0,
            _ => {}
        }
    }
    for ((ns, pod, container), (cpu_secs, ts_ms)) in cpu {
        let m = mem.get(&(ns.clone(), pod.clone(), container.clone())).copied().unwrap_or(0);
        out.ctrs.push(CtrSample { ns, pod, container, cpu_secs, mem: m, ts_ms });
    }
    out
}

/// Nanocores used between two samples of a cumulative CPU counter; None when time did not advance
/// or the counter went backwards (a restarted container).
pub fn rate(prev: (f64, i64), cur: (f64, i64)) -> Option<u64> {
    let dt_ms = cur.1 - prev.1;
    let dc = cur.0 - prev.0;
    if dt_ms <= 0 || dc < 0.0 {
        return None;
    }
    Some((dc / (dt_ms as f64 / 1000.0) * 1e9) as u64)
}

struct CtrEntry {
    name: String,
    cur: (f64, i64),
    nano: Option<u64>,
    mem: u64,
}

struct PodEntry {
    node: String,
    ctrs: Vec<CtrEntry>,
    ts_ms: i64,
    window_ms: i64,
}

struct NodeEntry {
    cur: (f64, i64),
    nano: Option<u64>,
    mem: u64,
    window_ms: i64,
}

#[derive(Default)]
struct State {
    nodes: BTreeMap<String, NodeEntry>,
    pods: BTreeMap<(String, String), PodEntry>,
}

/// The latest samples (a field of the API server).
#[derive(Default)]
pub struct Cache(RefCell<State>);

impl Cache {
    /// Folds a node's scrape into the cache, computing rates against the previous scrape.
    pub fn apply(&self, node: &str, s: &Scrape) {
        let mut st = self.0.borrow_mut();
        if let (Some(cpu), Some(mem)) = (s.node_cpu, s.node_mem) {
            let prev = st.nodes.get(node).map(|e| e.cur);
            st.nodes.insert(node.to_string(), NodeEntry { cur: cpu, nano: prev.and_then(|p| rate(p, cpu)), mem, window_ms: prev.map_or(0, |p| cpu.1 - p.1) });
        }
        // Previous counters of this node's containers; the node's pods are rebuilt from the scrape.
        let mut prev: BTreeMap<(String, String, String), (f64, i64)> = BTreeMap::new();
        st.pods.retain(|(ns, pod), p| {
            if p.node != node {
                return true;
            }
            prev.extend(p.ctrs.iter().map(|c| ((ns.clone(), pod.clone(), c.name.clone()), c.cur)));
            false
        });
        for c in &s.ctrs {
            let e = st.pods.entry((c.ns.clone(), c.pod.clone())).or_insert_with(|| PodEntry { node: node.to_string(), ctrs: Vec::new(), ts_ms: c.ts_ms, window_ms: 0 });
            let before = prev.get(&(c.ns.clone(), c.pod.clone(), c.container.clone())).copied();
            let cur = (c.cpu_secs, c.ts_ms);
            e.ts_ms = c.ts_ms;
            e.window_ms = e.window_ms.max(before.map_or(0, |p| c.ts_ms - p.1));
            e.ctrs.push(CtrEntry { name: c.container.clone(), cur, nano: before.and_then(|p| rate(p, cur)), mem: c.mem });
        }
    }

    /// Drops nodes that no longer exist.
    pub fn retain_nodes(&self, names: &[String]) {
        let mut st = self.0.borrow_mut();
        st.nodes.retain(|n, _| names.contains(n));
        st.pods.retain(|_, p| names.contains(&p.node));
    }
}

fn quantity_mem(bytes: u64) -> String {
    alloc::format!("{}Ki", bytes / 1024)
}

fn window(ms: i64) -> String {
    alloc::format!("{}s", (ms.max(1000) + 500) / 1000)
}

fn usage(nano: u64, mem: u64) -> Value {
    obj(alloc::vec![("cpu", Value::String(alloc::format!("{nano}n"))), ("memory", Value::String(quantity_mem(mem)))])
}

fn meta(name: &str, ns: Option<&str>, ts: &str, labels: Option<&Value>) -> Value {
    let mut m = alloc::vec![("name", Value::from(name))];
    if let Some(ns) = ns {
        m.push(("namespace", Value::from(ns)));
    }
    m.push(("creationTimestamp", Value::from(ts)));
    if let Some(l) = labels.filter(|l| !l.is_null()) {
        m.push(("labels", l.clone()));
    }
    obj(m)
}

const API_VERSION: &str = "metrics.k8s.io/v1beta1";

fn stored(api: &ApiServer, plural: &str, ns: Option<&str>, name: &str) -> Option<Value> {
    let key = crate::resources::find("", "v1", plural)?.key(ns, name);
    json::parse(&api.store.borrow().get(&key)?.value).ok()
}

fn node_item(api: &ApiServer, name: &str, e: &NodeEntry) -> Option<Value> {
    let nano = e.nano?;
    let obj_ = stored(api, "nodes", None, name)?;
    let ts = crate::object::rfc3339(e.cur.1.div_euclid(1000));
    Some(obj(alloc::vec![
        ("kind", Value::from("NodeMetrics")),
        ("apiVersion", Value::from(API_VERSION)),
        ("metadata", meta(name, None, &ts, obj_.pointer(&["metadata", "labels"]))),
        ("timestamp", Value::String(ts)),
        ("window", Value::String(window(e.window_ms))),
        ("usage", usage(nano, e.mem)),
    ]))
}

fn pod_item(api: &ApiServer, ns: &str, name: &str, p: &PodEntry) -> Option<Value> {
    let ctrs: Vec<Value> = p.ctrs.iter().filter_map(|c| Some(obj(alloc::vec![("name", Value::from(c.name.as_str())), ("usage", usage(c.nano?, c.mem))]))).collect();
    if ctrs.is_empty() {
        return None;
    }
    let obj_ = stored(api, "pods", Some(ns), name)?;
    let ts = crate::object::rfc3339(p.ts_ms.div_euclid(1000));
    Some(obj(alloc::vec![
        ("kind", Value::from("PodMetrics")),
        ("apiVersion", Value::from(API_VERSION)),
        ("metadata", meta(name, Some(ns), &ts, obj_.pointer(&["metadata", "labels"]))),
        ("timestamp", Value::String(ts)),
        ("window", Value::String(window(p.window_ms))),
        ("containers", Value::Array(ctrs)),
    ]))
}

fn list(kind: &str, items: Vec<Value>) -> Reply {
    Reply::Json(200, json::to_string(&obj(alloc::vec![("kind", Value::String(alloc::format!("{kind}List"))), ("apiVersion", Value::from(API_VERSION)), ("metadata", obj(Vec::new())), ("items", Value::Array(items))])))
}

/// Serves `/apis/metrics.k8s.io/v1beta1/<rest>` (already authorized).
pub(crate) fn serve(api: &ApiServer, method: &str, q: &Query, rest: &[&str]) -> Result<Reply, ApiError> {
    if method != "GET" {
        return Err(ApiError::new(405, "MethodNotAllowed", "the metrics API is read-only"));
    }
    let sel = match q.get("labelSelector") {
        Some(s) if !s.is_empty() => Selector::parse(s)?,
        _ => Selector::default(),
    };
    let fresh = |ts_ms: i64| api.now() * 1000 - ts_ms <= STALE_MS;
    let st = api.metrics.0.borrow();
    match rest {
        ["nodes"] => {
            let items = st.nodes.iter().filter(|(_, e)| fresh(e.cur.1)).filter_map(|(n, e)| node_item(api, n, e)).filter(|v| sel.matches(v)).collect();
            Ok(list("NodeMetrics", items))
        }
        ["nodes", n] => st.nodes.get(*n).filter(|e| fresh(e.cur.1)).and_then(|e| node_item(api, n, e)).map(|v| Reply::Json(200, json::to_string(&v))).ok_or_else(|| ApiError::not_found("nodemetrics.metrics.k8s.io", n)),
        ["pods"] | ["namespaces", _, "pods"] => {
            let only = if let ["namespaces", ns, _] = rest { Some(*ns) } else { None };
            let items = st.pods.iter().filter(|((ns, _), p)| only.is_none_or(|o| o == ns) && fresh(p.ts_ms)).filter_map(|((ns, n), p)| pod_item(api, ns, n, p)).filter(|v| sel.matches(v)).collect();
            Ok(list("PodMetrics", items))
        }
        ["namespaces", ns, "pods", n] => st
            .pods
            .get(&(ns.to_string(), n.to_string()))
            .filter(|p| fresh(p.ts_ms))
            .and_then(|p| pod_item(api, ns, n, p))
            .map(|v| Reply::Json(200, json::to_string(&v)))
            .ok_or_else(|| ApiError::not_found("podmetrics.metrics.k8s.io", n)),
        _ => Err(ApiError::not_found("path", &rest.join("/"))),
    }
}

/// One refresh: scrapes every Node's kubelet and updates the cache. A failed scrape keeps the
/// old sample (it goes stale and disappears after [`STALE_MS`]).
pub async fn refresh(api: &ApiServer, s: &dyn Scraper) {
    let mut names = Vec::new();
    for n in api.wh_list("", "v1", "nodes") {
        let Some(name) = n.pointer(&["metadata", "name"]).and_then(Value::as_str).map(String::from) else { continue };
        let ip = n.pointer(&["status", "addresses"]).and_then(Value::as_array).and_then(|a| a.iter().filter(|a| a.get("type").and_then(Value::as_str) == Some("InternalIP")).find_map(|a| a.get("address")?.as_str().and_then(kr_net::tcp::parse_ip16)));
        if let Ok(Some(text)) = kr_rt::exec::timeout(SCRAPE_TIMEOUT_MS, s.scrape(&name, ip)).await {
            let scrape = parse(&text, api.now() * 1000);
            if !scrape.error {
                api.metrics.apply(&name, &scrape);
            }
        }
        names.push(name);
    }
    api.metrics.retain_nodes(&names);
}

/// The refresh task: first scrape shortly after start, then every 15 s.
pub async fn run(api: Rc<ApiServer>, s: Rc<dyn Scraper>) {
    kr_rt::exec::sleep(3000).await;
    loop {
        refresh(&api, &*s).await;
        kr_rt::exec::sleep(REFRESH_MS).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = "# HELP node_cpu_usage_seconds_total Cumulative cpu time consumed by the node in core-seconds\n\
# TYPE node_cpu_usage_seconds_total counter\n\
node_cpu_usage_seconds_total 120.5 1700000000000\n\
node_memory_working_set_bytes 1073741824 1700000000000\n\
container_cpu_usage_seconds_total{container=\"app\",namespace=\"default\",pod=\"web-1\"} 2.25 1700000000000\n\
container_memory_working_set_bytes{container=\"app\",namespace=\"default\",pod=\"web-1\"} 5242880 1700000000000\n\
pod_cpu_usage_seconds_total{namespace=\"default\",pod=\"web-1\"} 2.25 1700000000000\n\
resource_scrape_error 0\n";

    #[test]
    fn parses_exposition() {
        let s = parse(TEXT, 5);
        assert_eq!(s.node_cpu, Some((120.5, 1_700_000_000_000)));
        assert_eq!(s.node_mem, Some(1 << 30));
        assert!(!s.error);
        assert_eq!(s.ctrs.len(), 1);
        assert_eq!((s.ctrs[0].ns.as_str(), s.ctrs[0].pod.as_str(), s.ctrs[0].container.as_str()), ("default", "web-1", "app"));
        assert_eq!(s.ctrs[0].mem, 5_242_880);
        assert!(parse("resource_scrape_error 1\n", 0).error);
        assert_eq!(parse("node_cpu_usage_seconds_total 1\n", 77).node_cpu, Some((1.0, 77)));
    }

    #[test]
    fn label_escapes() {
        let (n, l, v, ts) = parse_line("m{a=\"x\\\"y\\\\z\",b=\"\"} 3e2 9").unwrap();
        assert_eq!((n, v, ts), ("m", 300.0, Some(9)));
        assert_eq!(l, alloc::vec![("a".to_string(), "x\"y\\z".to_string()), ("b".to_string(), String::new())]);
        assert!(parse_line("# comment").is_none());
        assert!(parse_line("broken{a=\"x} 1").is_none());
    }

    #[test]
    fn cpu_rate() {
        assert_eq!(rate((10.0, 1000), (11.5, 16_000)), Some(100_000_000));
        assert_eq!(rate((10.0, 1000), (10.0, 16_000)), Some(0));
        assert_eq!(rate((10.0, 1000), (9.0, 16_000)), None);
        assert_eq!(rate((10.0, 1000), (11.0, 1000)), None);
    }

    #[test]
    fn cache_computes_rates_across_scrapes() {
        let c = Cache::default();
        let mk = |cpu: f64, ts: i64| Scrape {
            node_cpu: Some((cpu * 4.0, ts)),
            node_mem: Some(1 << 20),
            ctrs: alloc::vec![CtrSample { ns: "d".into(), pod: "p".into(), container: "c".into(), cpu_secs: cpu, mem: 4096, ts_ms: ts }],
            error: false,
        };
        c.apply("n1", &mk(1.0, 0));
        assert_eq!(c.0.borrow().nodes["n1"].nano, None);
        c.apply("n1", &mk(2.5, 15_000));
        let st = c.0.borrow();
        assert_eq!(st.nodes["n1"].nano, Some(400_000_000));
        assert_eq!(st.nodes["n1"].window_ms, 15_000);
        let p = &st.pods[&("d".to_string(), "p".to_string())];
        assert_eq!(p.ctrs[0].nano, Some(100_000_000));
        assert_eq!(p.window_ms, 15_000);
        drop(st);
        // The pod goes away: its entry is dropped with the next scrape.
        c.apply("n1", &Scrape { node_cpu: Some((20.0, 30_000)), node_mem: Some(1), ..Default::default() });
        assert!(c.0.borrow().pods.is_empty());
        c.retain_nodes(&[]);
        assert!(c.0.borrow().nodes.is_empty());
    }

    #[test]
    fn units() {
        assert_eq!(quantity_mem(5 * 1024 * 1024 + 1), "5120Ki");
        assert_eq!(window(15_020), "15s");
        assert_eq!(window(0), "1s");
        let u = usage(1500, 2048);
        assert_eq!(json::to_string(&u), "{\"cpu\":\"1500n\",\"memory\":\"2Ki\"}");
    }
}
