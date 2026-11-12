//! Audit webhook backend (`--audit-webhook-config-file`, ADR-065): events are POSTed as an
//! `audit.k8s.io/v1` `EventList`. `batch` mode queues events in a bounded buffer that a task
//! sends in batches (never on the request path; a full buffer drops events and counts them);
//! `blocking` and `blocking-strict` hold the response until its events were accepted, strict
//! turning a failure into a 500.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};
use kr_crypto::tls::ClientConfig;
use kr_crypto::x509;
use kr_fmt::json::Value;
use kr_net::http1::client::{Client as Http, Config as HttpConfig};
use kr_net::tls::TlsConnector;

static DROPPED: AtomicU64 = AtomicU64::new(0);
static SENT: AtomicU64 = AtomicU64::new(0);
static FAILED: AtomicU64 = AtomicU64::new(0);

/// Prometheus text for `/metrics`.
pub fn metrics() -> String {
    format!(
        "# HELP kr_audit_webhook_dropped_events_total Audit events dropped because the webhook buffer was full or delivery failed.\n# TYPE kr_audit_webhook_dropped_events_total counter\nkr_audit_webhook_dropped_events_total {}\n\
         # HELP kr_audit_webhook_sent_events_total Audit events accepted by the webhook.\n# TYPE kr_audit_webhook_sent_events_total counter\nkr_audit_webhook_sent_events_total {}\n\
         # HELP kr_audit_webhook_failed_requests_total Failed webhook POSTs.\n# TYPE kr_audit_webhook_failed_requests_total counter\nkr_audit_webhook_failed_requests_total {}\n",
        DROPPED.load(Relaxed),
        SENT.load(Relaxed),
        FAILED.load(Relaxed)
    )
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Batch,
    Blocking,
    BlockingStrict,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "batch" => Some(Mode::Batch),
            "blocking" => Some(Mode::Blocking),
            "blocking-strict" => Some(Mode::BlockingStrict),
            _ => None,
        }
    }
}

pub struct Config {
    pub url: String,
    pub roots: Vec<Vec<u8>>,
    pub client: Option<(Vec<Vec<u8>>, x509::SigningKey)>,
    pub token: Option<String>,
    pub mode: Mode,
    pub max_size: usize,
    pub max_wait_ms: u64,
    pub buffer: usize,
    pub backoff_ms: u64,
}

impl Config {
    /// Reads a kubeconfig (the current context, else the first one). `read` loads files that the
    /// kubeconfig refers to.
    pub fn from_kubeconfig(text: &str, read: &dyn Fn(&str) -> Result<Vec<u8>, String>) -> Result<Config, String> {
        let v = kr_fmt::yaml::parse(text).map_err(|e| format!("audit webhook kubeconfig: {e:?}"))?;
        let list = |k: &str| v.get(k).and_then(Value::as_array).unwrap_or(&[]).to_vec();
        let named = |items: &[Value], name: &str, key: &str| -> Option<Value> { items.iter().find(|i| i.get("name").and_then(Value::as_str) == Some(name)).and_then(|i| i.get(key)).cloned() };
        let (ctxs, clusters, users) = (list("contexts"), list("clusters"), list("users"));
        let cur = v.get("current-context").and_then(Value::as_str).unwrap_or("");
        let ctx = named(&ctxs, cur, "context").or_else(|| ctxs.first().and_then(|c| c.get("context")).cloned());
        let s = |o: &Option<Value>, k: &str| o.as_ref().and_then(|o| o.get(k)).and_then(Value::as_str).map(String::from);
        let cluster = match s(&ctx, "cluster") {
            Some(n) => named(&clusters, &n, "cluster"),
            None => clusters.first().and_then(|c| c.get("cluster")).cloned(),
        };
        let user = match s(&ctx, "user") {
            Some(n) => named(&users, &n, "user"),
            None => users.first().and_then(|c| c.get("user")).cloned(),
        };
        let url = s(&cluster, "server").ok_or("audit webhook kubeconfig: no cluster server")?;
        if cluster.as_ref().and_then(|c| c.get("insecure-skip-tls-verify")).and_then(Value::as_bool) == Some(true) {
            return Err("audit webhook kubeconfig: insecure-skip-tls-verify is not supported; provide certificate-authority".into());
        }
        // `<key>-data` (base64) wins over `<key>` (a path), as in client-go.
        let data = |o: &Option<Value>, k: &str| -> Result<Option<Vec<u8>>, String> {
            if let Some(d) = s(o, &format!("{k}-data")) {
                return kr_fmt::base64::decode(&d).map(Some).map_err(|_| format!("audit webhook kubeconfig: bad {k}-data"));
            }
            match s(o, k) {
                Some(p) => read(&p).map(Some),
                None => Ok(None),
            }
        };
        let pem = |b: Vec<u8>| String::from_utf8(b).map_err(|_| String::from("audit webhook kubeconfig: PEM is not UTF-8"));
        let roots = match data(&cluster, "certificate-authority")? {
            Some(b) => x509::pem_decode_all(&pem(b)?, "CERTIFICATE").map_err(|_| "audit webhook kubeconfig: invalid certificate-authority")?,
            None => Vec::new(),
        };
        let client = match (data(&user, "client-certificate")?, data(&user, "client-key")?) {
            (Some(c), Some(k)) => {
                let chain = x509::pem_decode_all(&pem(c)?, "CERTIFICATE").map_err(|_| "audit webhook kubeconfig: invalid client-certificate")?;
                let k = pem(k)?;
                let key = match x509::pem_decode_all(&k, "PRIVATE KEY") {
                    Ok(v) if !v.is_empty() => x509::private_key_from_pkcs8(&v[0]),
                    _ => match x509::pem_decode_all(&k, "EC PRIVATE KEY") {
                        Ok(v) if !v.is_empty() => x509::private_key_from_sec1(&v[0]),
                        _ => return Err("audit webhook kubeconfig: invalid client-key".into()),
                    },
                }
                .map_err(|_| "audit webhook kubeconfig: invalid client-key")?;
                Some((chain, key))
            }
            _ => None,
        };
        let token = match s(&user, "token") {
            Some(t) => Some(t),
            None => s(&user, "tokenFile").map(|p| read(&p).map(|b| String::from_utf8_lossy(&b).trim().to_string())).transpose()?,
        };
        Ok(Config { url, roots, client, token, mode: Mode::Batch, max_size: 400, max_wait_ms: 30_000, buffer: 10_000, backoff_ms: 10_000 })
    }
}

pub struct Webhook {
    cfg: Config,
    q: RefCell<VecDeque<String>>,
    inflight: Cell<bool>,
    http: Http<TlsConnector>,
}

/// `{"kind":"EventList",...}` around already serialised events.
pub fn event_list(evs: &[String]) -> String {
    let mut o = String::from(r#"{"kind":"EventList","apiVersion":"audit.k8s.io/v1","metadata":{},"items":["#);
    for (i, e) in evs.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        o.push_str(e);
    }
    o.push_str("]}");
    o
}

impl Webhook {
    pub fn new(mut cfg: Config) -> Rc<Webhook> {
        let tls = Rc::new(ClientConfig { pinned_ca: None, roots: cfg.roots.clone(), client_cert: cfg.client.take(), alpn: alloc::vec![b"http/1.1".to_vec()], tls12: false });
        let http = Http::with_connector(
            TlsConnector::new(kr_net::dns::SystemResolver::system(), tls),
            HttpConfig { max_redirects: 0, max_idle: 1, connect_timeout_ms: 10_000, head_timeout_ms: 30_000, read_timeout_ms: 30_000, user_agent: "kr-apiserver".to_string(), ..HttpConfig::default() },
        );
        Rc::new(Webhook { cfg, q: RefCell::new(VecDeque::new()), inflight: Cell::new(false), http })
    }

    pub fn mode(&self) -> Mode {
        self.cfg.mode
    }

    /// Queues an event; dropped (and counted) when the buffer is full.
    pub fn push(&self, ev: &str) {
        let mut q = self.q.borrow_mut();
        if q.len() >= self.cfg.buffer.max(1) {
            DROPPED.fetch_add(1, Relaxed);
            return;
        }
        q.push_back(ev.to_string());
    }

    pub fn queued(&self) -> usize {
        self.q.borrow().len()
    }

    async fn post(&self, body: &str) -> bool {
        let auth = self.cfg.token.as_ref().map(|t| format!("Bearer {t}"));
        let mut h = alloc::vec![("Content-Type", "application/json")];
        if let Some(a) = &auth {
            h.push(("Authorization", a.as_str()));
        }
        let fut = async {
            let mut r = self.http.request("POST", &self.cfg.url, &h, body.as_bytes()).await.ok()?;
            let ok = (200..300).contains(&r.status);
            let _ = r.read_to_end(1 << 20).await;
            Some(ok)
        };
        kr_rt::exec::timeout(60_000, fut).await.ok().flatten().unwrap_or(false)
    }

    /// Sends `evs`, retrying with exponential backoff (`--audit-webhook-initial-backoff`, doubled,
    /// at most `attempts` tries); the events are dropped (counted) when all fail.
    async fn deliver(&self, evs: Vec<String>, attempts: u32) -> bool {
        let body = event_list(&evs);
        let mut wait = self.cfg.backoff_ms;
        for n in 0..attempts {
            if self.post(&body).await {
                SENT.fetch_add(evs.len() as u64, Relaxed);
                return true;
            }
            FAILED.fetch_add(1, Relaxed);
            if n + 1 < attempts {
                kr_rt::exec::sleep(wait).await;
                wait = (wait * 2).min(5 * 60_000);
            }
        }
        DROPPED.fetch_add(evs.len() as u64, Relaxed);
        false
    }

    /// Batch mode: sends when `max_size` events are queued or `max_wait` has passed.
    pub fn spawn_batcher(self: &Rc<Self>) {
        let w = self.clone();
        kr_rt::exec::spawn(async move {
            let mut last = kr_rt::exec::now_ms();
            loop {
                kr_rt::exec::sleep(250).await;
                let n = w.queued();
                let due = kr_rt::exec::now_ms().saturating_sub(last) >= w.cfg.max_wait_ms;
                if n >= w.cfg.max_size || (n > 0 && due) {
                    let take = n.min(w.cfg.max_size.max(1));
                    let evs: Vec<String> = w.q.borrow_mut().drain(..take).collect();
                    w.deliver(evs, 5).await;
                    last = kr_rt::exec::now_ms();
                } else if n == 0 && due {
                    last = kr_rt::exec::now_ms();
                }
            }
        });
    }

    /// Blocking modes: returns once everything queued so far was sent; `false` if delivery failed.
    pub async fn sync(&self) -> bool {
        loop {
            if self.inflight.get() {
                kr_rt::exec::sleep(2).await;
                continue;
            }
            if self.q.borrow().is_empty() {
                return true;
            }
            self.inflight.set(true);
            let evs: Vec<String> = self.q.borrow_mut().drain(..).collect();
            let ok = self.deliver(evs, 2).await;
            self.inflight.set(false);
            return ok;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KC: &str = "apiVersion: v1\nkind: Config\nclusters:\n- name: a\n  cluster:\n    server: https://audit.example:8443/events\ncontexts:\n- name: c\n  context:\n    cluster: a\n    user: u\ncurrent-context: c\nusers:\n- name: u\n  user:\n    token: tok\n";

    fn no_files(_: &str) -> Result<Vec<u8>, String> {
        Err("no".into())
    }

    #[test]
    fn kubeconfig_is_read() {
        let c = Config::from_kubeconfig(KC, &no_files).unwrap();
        assert_eq!(c.url, "https://audit.example:8443/events");
        assert_eq!(c.token.as_deref(), Some("tok"));
        assert!(Config::from_kubeconfig("clusters: []\n", &no_files).is_err());
        let insecure = KC.replace("server: https://audit.example:8443/events", "server: https://x\n    insecure-skip-tls-verify: true");
        assert!(Config::from_kubeconfig(&insecure, &no_files).is_err());
    }

    #[test]
    fn modes_parse() {
        assert_eq!(Mode::parse("batch"), Some(Mode::Batch));
        assert_eq!(Mode::parse("blocking-strict"), Some(Mode::BlockingStrict));
        assert_eq!(Mode::parse("x"), None);
    }

    #[test]
    fn event_list_wraps_items() {
        let l = event_list(&[String::from("{\"a\":1}"), String::from("{\"b\":2}")]);
        let v = kr_fmt::json::parse_str(&l).unwrap();
        assert_eq!(v.get("kind").and_then(Value::as_str), Some("EventList"));
        assert_eq!(v.get("items").and_then(Value::as_array).unwrap().len(), 2);
    }

    #[test]
    fn full_buffer_drops_and_counts() {
        let mut c = Config::from_kubeconfig(KC, &no_files).unwrap();
        c.buffer = 2;
        let w = Webhook::new(c);
        let before = DROPPED.load(Relaxed);
        for _ in 0..5 {
            w.push("{}");
        }
        assert_eq!(w.queued(), 2);
        assert!(DROPPED.load(Relaxed) >= before + 3);
        assert!(metrics().contains("kr_audit_webhook_dropped_events_total "));
    }
}
