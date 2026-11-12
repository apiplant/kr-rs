//! `kr server`: the control plane. On first start it creates the cluster PKI and an admin
//! kubeconfig; then it serves the Kubernetes API over TLS (client-certificate auth).
//!
//! Layout under the data dir (`--data`, else `$KR_ROOT/server`, else `/var/lib/kr/server` as
//! root or `$HOME/.local/share/kr/server`):
//!   pki/ca.pem ca.key apiserver.pem apiserver.key admin.pem admin.key
//!   db/                 kr-store files
//!   admin.kubeconfig    cluster-admin credentials (mode 0600)

use crate::pki;
use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use kr_crypto::tls::{ClientAuth, ServerConfig};
use kr_crypto::x509::{self, CertParams, Name};
use kr_rt::{eprint, print, Args};
use kr_sys::{fs, ns, Errno};

fn fail(msg: &str) -> i32 {
    eprint(b"kr server: ");
    eprint(msg.as_bytes());
    eprint(b"\n");
    1
}

pub fn data_dir() -> String {
    let env = kr_runtime::store::env_var;
    if let Some(r) = env("KR_ROOT").filter(|v| !v.is_empty()) {
        return format!("{r}/server");
    }
    if ns::getuid() == 0 {
        return "/var/lib/kr/server".into();
    }
    format!("{}/.local/share/kr/server", env("HOME").unwrap_or_else(|| "/tmp".into()))
}

pub fn mkdir_p(dir: &str) -> Result<(), String> {
    let mut cur = String::new();
    for part in dir.split('/').filter(|p| !p.is_empty()) {
        cur.push('/');
        cur.push_str(part);
        let mut c = cur.clone().into_bytes();
        c.push(0);
        match ns::mkdir(&c, 0o700) {
            Ok(()) | Err(Errno(17)) => {}
            Err(e) => return Err(format!("mkdir {cur}: errno {}", e.0)),
        }
    }
    Ok(())
}

pub fn hostname() -> String {
    fs::read_file(b"/proc/sys/kernel/hostname\0", 256).ok().and_then(|b| String::from_utf8(b).ok()).map(|s| s.trim().into()).unwrap_or_default()
}

fn exists(p: &[u8]) -> bool {
    ns::open(p, ns::O_RDONLY, 0).is_ok()
}

fn issue(dir: &str, file: &str, ca: &(Name, x509::SigningKey, Vec<u8>), subject: Name, server: bool, client: bool, dns: Vec<String>, ips: Vec<Vec<u8>>) -> Result<(), String> {
    let key = pki::new_key();
    let t = pki::now();
    let p = CertParams { serial: pki::serial(), subject, not_before: t - 300, not_after: t + 365 * 86400, is_ca: false, server, client, dns_names: dns, ip_addrs: ips, public_key: key.public() };
    let cert = x509::issue(&p, &ca.0, &ca.1);
    pki::write_new(&pki::path(dir, &format!("{file}.key")), x509::pem_encode("PRIVATE KEY", &x509::private_key_to_pkcs8(&key)).as_bytes(), 0o600)?;
    pki::write_new(&pki::path(dir, &format!("{file}.pem")), x509::pem_encode("CERTIFICATE", &cert).as_bytes(), 0o644)
}

/// Drops `<file>.pem/.key` if the certificate does not cover `ip` (this machine's address
/// changed), so that it is issued again with the new address.
/// The node's primary address: IPv4 if the host has a route out, else IPv6 (`KR_PREFER_IPV6=1`
/// picks IPv6 even on a dual-stack host: how the IPv6 underlay is tested).
pub(crate) fn primary_addr() -> [u8; 16] {
    kr_sys::ns::route_source_any(kr_runtime::store::env_var("KR_PREFER_IPV6").is_some_and(|v| !v.is_empty() && v != "0"))
}

fn drop_if_ip_changed(pki_dir: &str, file: &str, ip: [u8; 16], adv_check: bool) {
    let Ok(b) = fs::read_file(&pki::path(pki_dir, &format!("{file}.pem")), 1 << 20) else { return };
    let Some(der) = core::str::from_utf8(&b).ok().and_then(|p| x509::pem_decode_all(p, "CERTIFICATE").ok()).and_then(|mut v| (!v.is_empty()).then(|| v.remove(0))) else { return };
    let host = kr_net::tcp::fmt_ip16(ip);
    // Certificates are valid for a year: reissue one that expires within 30 days at start-up.
    let now = kr_sys::clock_gettime(0).map(|t| t.tv_sec).unwrap_or(0);
    if x509::Certificate::parse(&der).is_ok_and(|c| c.not_after - now < 30 * 86400) {
        eprint(format!("kr server: {file}.pem expires soon; issuing a new one\n").as_bytes());
        for ext in ["pem", "key"] {
            let _ = fs::unlinkat(fs::AT_FDCWD, &pki::path(pki_dir, &format!("{file}.{ext}")), 0);
        }
        return;
    }
    if adv_check && x509::Certificate::parse(&der).is_ok_and(|c| !c.matches_host(host.as_bytes())) {
        eprint(format!("kr server: {file}.pem does not cover {host}; issuing a new one\n").as_bytes());
        for ext in ["pem", "key"] {
            let _ = fs::unlinkat(fs::AT_FDCWD, &pki::path(pki_dir, &format!("{file}.{ext}")), 0);
        }
    }
}

/// Creates the CA, the apiserver serving cert and the admin client cert if missing.
pub(crate) fn bootstrap(data: &str, port: u16, ha: bool) -> Result<(), String> {
    let pki_dir = format!("{data}/pki");
    mkdir_p(&pki_dir)?;
    let adv = primary_addr();
    let routable = adv != kr_sys::map4([127, 0, 0, 1]);
    for file in ["apiserver", "server", "kubelet-client"] {
        drop_if_ip_changed(&pki_dir, file, adv, routable && file != "kubelet-client");
    }
    if !exists(&pki::path(&pki_dir, "ca.pem")) {
        pki::create_ca(&pki_dir, "kr-cluster-ca".into(), 3650)?;
    }
    let ca = pki::load_ca(&pki_dir)?;
    if !exists(&pki::path(&pki_dir, "apiserver.pem")) {
        let host = hostname();
        let mut dns: Vec<String> = ["localhost", "kubernetes", "kubernetes.default", "kubernetes.default.svc", "kubernetes.default.svc.cluster.local"].iter().map(|s| String::from(*s)).collect();
        let domain = kr_kubelet::cluster_domain();
        if domain != "cluster.local" {
            dns.push(alloc::format!("kubernetes.default.svc.{domain}"));
        }
        if !host.is_empty() && kr_apiserver::object::is_dns_subdomain(&host) {
            dns.push(host);
        }
        let name = Name { common_name: "kube-apiserver".into(), organizations: Vec::new() };
        let mut ips = alloc::vec![alloc::vec![127, 0, 0, 1], alloc::vec![10, 96, 0, 1]];
        let adv = primary_addr();
        if adv != kr_sys::map4([127, 0, 0, 1]) {
            ips.push(kr_net::tcp::ip_bytes16(adv));
        }
        // IPv6: loopback, the kubernetes Service's IPv6 ClusterIP and the host's global address.
        ips.push(kr_net::tcp::parse_ipv6("::1").unwrap().to_vec());
        ips.push(kr_net::tcp::parse_ipv6("fd00:96::1").unwrap().to_vec());
        if let Some(h6) = kr_apiserver::api::host_ip6() {
            ips.push(h6.to_vec());
        }
        issue(&pki_dir, "apiserver", &ca, name, true, false, dns, ips)?;
    }
    if !exists(&pki::path(&pki_dir, "kubelet-client.pem")) {
        // Used by the API server to reach node agents' kubelets (logs/exec/port-forward).
        let name = Name { common_name: "kube-apiserver-kubelet-client".into(), organizations: alloc::vec!["system:masters".into()] };
        issue(&pki_dir, "kubelet-client", &ca, name, false, true, Vec::new(), Vec::new())?;
    }
    if !exists(&pki::path(data, "node-token")) {
        // K10<sha256 of the CA certificate>::<id>.<secret> (k3s-style join token).
        let mut rnd = [0u8; 22];
        kr_sys::getrandom(&mut rnd);
        const ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let t: String = rnd.iter().map(|b| ALPHA[*b as usize % ALPHA.len()] as char).collect();
        let hash: String = kr_crypto::sha2::sha256(&ca.2).iter().map(|b| alloc::format!("{b:02x}")).collect();
        let token = format!("K10{hash}::{}.{}\n", &t[..6], &t[6..]);
        pki::write_new(&pki::path(data, "node-token"), token.as_bytes(), 0o600)?;
    }
    if ha && !exists(&pki::path(data, "server-token")) {
        // Admits new *servers* (they receive the CA and signing keys): never the node token.
        let mut rnd = [0u8; 32];
        kr_sys::getrandom(&mut rnd);
        const ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let t: String = rnd.iter().map(|b| ALPHA[*b as usize % ALPHA.len()] as char).collect();
        let hash: String = kr_crypto::sha2::sha256(&ca.2).iter().map(|b| alloc::format!("{b:02x}")).collect();
        pki::write_new(&pki::path(data, "server-token"), format!("K10{hash}::server:{t}\n").as_bytes(), 0o600)?;
    }
    if !exists(&pki::path(&pki_dir, "sa.key")) {
        let key = pki::new_key();
        pki::write_new(&pki::path(&pki_dir, "sa.key"), x509::pem_encode("PRIVATE KEY", &x509::private_key_to_pkcs8(&key)).as_bytes(), 0o600)?;
    }
    if !exists(&pki::path(&pki_dir, "admin.pem")) {
        let name = Name { common_name: "kubernetes-admin".into(), organizations: alloc::vec!["system:masters".into()] };
        issue(&pki_dir, "admin", &ca, name, false, true, Vec::new(), Vec::new())?;
        let read = |f: &str| fs::read_file(&pki::path(&pki_dir, f), 1 << 20).map_err(|e| format!("read {f}: errno {}", e.0));
        let b64 = |v: Vec<u8>| kr_fmt::base64::encode(&v);
        let kubeconfig = format!(
            "apiVersion: v1\nkind: Config\nclusters:\n- name: kr\n  cluster:\n    server: https://127.0.0.1:{port}\n    certificate-authority-data: {}\nusers:\n- name: kr-admin\n  user:\n    client-certificate-data: {}\n    client-key-data: {}\ncontexts:\n- name: kr\n  context:\n    cluster: kr\n    user: kr-admin\ncurrent-context: kr\n",
            b64(read("ca.pem")?),
            b64(read("admin.pem")?),
            b64(read("admin.key")?)
        );
        pki::write_new(&pki::path(data, "admin.kubeconfig"), kubeconfig.as_bytes(), 0o600)?;
    }
    Ok(())
}

pub fn load_pem(dir: &str, file: &str, label: &str) -> Result<Vec<Vec<u8>>, String> {
    let b = fs::read_file(&pki::path(dir, file), 1 << 20).map_err(|e| format!("read {file}: errno {}", e.0))?;
    x509::pem_decode_all(core::str::from_utf8(&b).map_err(|_| "not UTF-8")?, label).map_err(|_| format!("{file}: bad PEM"))
}

fn rng(b: &mut [u8]) {
    kr_sys::getrandom(b)
}

/// HA mode (ADR-026): this server's Raft id (`server-id`, created once) and its
/// `system:kr-server:<id>` certificate (`pki/server.pem`), used for the Raft transport and for
/// forwarding writes to the leader.
pub(crate) fn server_identity(data: &str, advertise: [u8; 16]) -> Result<u64, String> {
    let id_path = pki::path(data, "server-id");
    let id = match fs::read_file(&id_path, 64).ok().and_then(|b| String::from_utf8(b).ok()).and_then(|s| s.trim().parse::<u64>().ok()) {
        Some(id) => id,
        None => {
            let mut b = [0u8; 8];
            kr_sys::getrandom(&mut b);
            // Ids are small positive numbers in logs and certificate names.
            let id = (u64::from_le_bytes(b) % 1_000_000_000).max(1);
            pki::write_new(&id_path, format!("{id}\n").as_bytes(), 0o600)?;
            id
        }
    };
    let pki_dir = format!("{data}/pki");
    if !exists(&pki::path(&pki_dir, "server.pem")) {
        let ca = pki::load_ca(&pki_dir)?;
        let name = Name { common_name: kr_apiserver::cluster::transport::cert_cn(id), organizations: alloc::vec![kr_apiserver::cluster::transport::ORG.into()] };
        issue(&pki_dir, "server", &ca, name, true, true, Vec::new(), alloc::vec![alloc::vec![127, 0, 0, 1], kr_net::tcp::ip_bytes16(advertise)])?;
    }
    Ok(id)
}

/// Converts a single-server datastore to HA: its image becomes the Raft snapshot at index 1
/// with this server as the only voter (servers that join later receive it as InstallSnapshot).
/// The old directory is renamed to `db.imported` afterwards, so a crash in between just
/// imports again.
fn import_single_server(data: &str, raft_dir: &str, id: u64) -> Result<(), String> {
    let image = kr_store::Store::open(&format!("{data}/db")).map_err(|_| String::from("cannot open the single-server datastore"))?.image();
    let (mut st, _) = kr_raft::storage::Storage::open(raft_dir).map_err(|e| format!("raft storage: {e:?}"))?;
    let snap = kr_raft::Snapshot { meta: kr_raft::SnapshotMeta { index: 1, term: 1, voters: alloc::vec![id], learners: Vec::new() }, data: Rc::from(image) };
    st.save_snapshot(&snap).map_err(|e| format!("raft snapshot: {e:?}"))?;
    st.set_hard_state(kr_raft::HardState { term: 1, vote: None, commit: 1 }).map_err(|e| format!("raft hard state: {e:?}"))?;
    let (from, to) = (format!("{data}/db\0"), format!("{data}/db.imported\0"));
    fs::renameat2(fs::AT_FDCWD, from.as_bytes(), fs::AT_FDCWD, to.as_bytes(), 0).map_err(|e| format!("rename db: errno {}", e.0))
}

/// Files a joining server receives (relative to the data dir) and their modes.
const JOIN_FILES: [(&str, u32); 5] = [("pki/ca.pem", 0o644), ("pki/ca.key", 0o600), ("pki/sa.key", 0o600), ("node-token", 0o600), ("server-token", 0o600)];

/// What this server hands to joining servers (`/kr/join-server`).
fn join_secrets(data: &str) -> Result<kr_apiserver::cluster::join::JoinSecrets, String> {
    let mut files = Vec::new();
    for (f, _) in JOIN_FILES {
        let b = fs::read_file(&pki::path(data, f), 1 << 20).map_err(|e| format!("read {f}: errno {}", e.0))?;
        files.push((String::from(f), String::from_utf8(b).map_err(|_| format!("{f} is not UTF-8"))?));
    }
    // Optional: the secrets-encryption key must be the same on every server (ADR-047).
    if let Ok(b) = fs::read_file(&pki::path(data, kr_apiserver::encrypt::FILE), 1 << 20) {
        files.push((String::from(kr_apiserver::encrypt::FILE), String::from_utf8(b).map_err(|_| "encryption config is not UTF-8")?));
    }
    let tok = &files[4].1;
    let token_secret = tok.trim().split_once("::server:").map(|(_, s)| String::from(s)).ok_or("bad server-token")?;
    Ok(kr_apiserver::cluster::join::JoinSecrets { token_secret, files })
}

/// First start of a server joining an existing cluster: fetch the CA pinned to the server
/// token's hash, then the cluster's key material; returns the current servers.
async fn join_cluster(server: &str, token: &str, data: &str) -> Result<Vec<(u64, kr_apiserver::cluster::ServerAddr)>, String> {
    let (hash, secret) = token.trim().strip_prefix("K10").and_then(|t| t.split_once("::server:")).ok_or("a server token looks like K10<hash>::server:<secret> (see server-token on an existing server)")?;
    let pin = crate::agent::unhex32(hash).ok_or("bad CA hash in token")?;
    let ca = crate::agent::fetch_ca(server, pin).await?;
    let cfg = Rc::new(kr_crypto::tls::ClientConfig { roots: alloc::vec![ca], pinned_ca: None, client_cert: None, alpn: alloc::vec![b"http/1.1".to_vec()], tls12: false });
    let client = kr_net::http1::Client::with_connector(kr_net::tls::TlsConnector::new(kr_net::dns::SystemResolver::system(), cfg), kr_net::http1::Config { max_redirects: 0, ..kr_net::http1::Config::default() });
    let mut body = String::from(r#"{"token":"#);
    kr_fmt::json::write_str(secret, &mut body);
    body.push('}');
    let mut r = client.request("POST", &format!("{server}/kr/join-server"), &[("Content-Type", "application/json")], body.as_bytes()).await.map_err(|_| String::from("cannot reach the server"))?;
    let status = r.status;
    let resp = r.read_to_end(4 << 20).await.map_err(|_| String::from("reading the join response failed"))?;
    if status != 200 {
        return Err(format!("join refused ({status}): {}", String::from_utf8_lossy(&resp)));
    }
    let v = kr_fmt::json::parse(&resp).map_err(|_| String::from("bad join response"))?;
    let files = v.get("files").ok_or("join response lacks files")?;
    mkdir_p(&format!("{data}/pki"))?;
    for (f, mode) in JOIN_FILES {
        let c = files.get(f).and_then(kr_fmt::json::Value::as_str).ok_or(format!("join response lacks {f}"))?;
        pki::write_new(&pki::path(data, f), c.as_bytes(), mode)?;
    }
    if let Some(c) = files.get(kr_apiserver::encrypt::FILE).and_then(kr_fmt::json::Value::as_str) {
        pki::write_new(&pki::path(data, kr_apiserver::encrypt::FILE), c.as_bytes(), 0o600)?;
    }
    let servers = v.get("servers").and_then(kr_fmt::json::Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
    Ok(servers
        .iter()
        .filter_map(|s| {
            let ip = kr_net::tcp::parse_ip16(s.get("ip")?.as_str()?)?;
            Some((s.get("id")?.as_u64()?, kr_apiserver::cluster::ServerAddr { ip, raft_port: s.get("raftPort")?.as_u64()? as u16, api_port: s.get("apiPort")?.as_u64()? as u16 }))
        })
        .collect())
}

/// Asks the cluster (through `server`) to make this server a voter, until it is one.
async fn become_voter(c: Rc<kr_apiserver::cluster::Cluster>, server: String, pki_dir: String, me: kr_apiserver::cluster::ServerAddr) {
    let read = |f: &str| fs::read_file(&pki::path(&pki_dir, f), 1 << 20).ok().and_then(|b| String::from_utf8(b).ok()).unwrap_or_default();
    let remote = match kr_apiserver::client::Remote::new(&server, kr_apiserver::client::RemoteAuth::ClientCert { chain: read("server.pem"), key: read("server.key") }, &read("ca.pem")) {
        Ok(r) => r,
        Err(e) => {
            eprint(format!("kr server: cannot join as a voter: {}\n", e.message).as_bytes());
            return;
        }
    };
    let body = me.to_json();
    let body = kr_fmt::json::parse(body.as_bytes()).unwrap();
    use kr_apiserver::client::Client;
    while !c.voters().contains(&c.id) {
        match remote.create("/kr/add-server", &body).await {
            Ok(_) => print(format!("kr server: joined as voter {}\n", c.id).as_bytes()),
            Err(e) => {
                eprint(format!("kr server: joining as a voter: {} {}; retrying\n", e.code, e.message).as_bytes());
                kr_rt::exec::sleep(2000).await;
            }
        }
        kr_rt::exec::sleep(500).await;
    }
}

/// TLS configurations for the Raft listener and for outbound server-to-server connections.
fn server_tls(pki_dir: &str) -> Result<(Rc<ServerConfig>, Rc<kr_crypto::tls::ClientConfig>), String> {
    let chain = load_pem(pki_dir, "server.pem", "CERTIFICATE")?;
    let key = || -> Result<x509::SigningKey, String> { x509::private_key_from_pkcs8(&load_pem(pki_dir, "server.key", "PRIVATE KEY")?.pop().ok_or("server.key empty")?).map_err(|_| "server.key unsupported".into()) };
    let ca = load_pem(pki_dir, "ca.pem", "CERTIFICATE")?;
    let srv = Rc::new(ServerConfig { cert_chain: chain.clone(), key: key()?, client_auth: ClientAuth::Required(ca.clone()), alpn: Vec::new() });
    let cli = Rc::new(kr_crypto::tls::ClientConfig { roots: ca, pinned_ca: None, client_cert: Some((chain, key()?)), alpn: alloc::vec![b"http/1.1".to_vec()], tls12: false });
    Ok((srv, cli))
}

/// Reads the audit policy and Pod Security configuration and installs them; returns the audit
/// writer (its flush timer starts inside the executor). `--audit-log-path off` disables auditing.
fn audit_setup(data: &str, policy: Option<&str>, path: Option<&str>, max_mb: u64, backups: usize, psa: Option<&str>, api: &kr_apiserver::api::ApiServer) -> Result<Option<Rc<kr_apiserver::audit::Auditor>>, String> {
    let read = |p: &str| -> Result<String, String> { String::from_utf8(fs::read_file(&[p.as_bytes(), &[0]].concat(), 1 << 20).map_err(|_| format!("cannot read {p}"))?).map_err(|_| format!("{p} is not UTF-8")) };
    if let Some(p) = psa {
        *api.audit.psa.borrow_mut() = kr_apiserver::psa::Config::parse(&read(p)?)?;
    }
    if max_mb == u64::MAX || backups == usize::MAX {
        return Err(String::from("bad --audit-log-maxsize / --audit-log-maxbackup"));
    }
    let path = path.map(String::from).unwrap_or_else(|| format!("{data}/audit/audit.log"));
    if path == "off" {
        return Ok(None);
    }
    let policy = match policy {
        Some(p) => kr_apiserver::audit::Policy::parse(&read(p)?)?,
        None => kr_apiserver::audit::Policy::builtin(),
    };
    let a = Rc::new(kr_apiserver::audit::Auditor::open(policy, &path, max_mb, backups));
    api.audit.set_auditor(a.clone());
    Ok(Some(a))
}

/// The secret the TLS ticket keys are derived from: HKDF over the service-account key with a
/// purpose label, so the key itself is never used as a ticket key.
fn ticket_secret(sa_key: &[u8; 32]) -> [u8; 32] {
    let mut prk = [0u8; 32];
    kr_crypto::hmac::hkdf_extract::<kr_crypto::sha2::Sha256>(b"kr tls ticket secret v1", sa_key, &mut prk);
    prk
}

pub fn main(mut args: Args) -> i32 {
    if kr_runtime::store::env_var("KR_TLS_RESUMPTION").as_deref() == Some("off") {
        kr_net::tls::set_resumption(false);
    }
    // Event-loop watchdog and Raft timing (#213).
    if let Some(ms) = kr_runtime::store::env_var("KR_STALL_WARN_MS").and_then(|v| v.parse().ok()) {
        kr_rt::exec::set_stall_warn_ms(ms);
    }
    // Workers for CPU-bound jobs (big lists, audit bodies, image unpacking; ADR-052). They are
    // forks, so start them before the process grows.
    crate::offload::start(true);
    if let Some(ms) = kr_runtime::store::env_var("KR_RAFT_ELECTION_MS").and_then(|v| v.parse().ok()) {
        kr_apiserver::cluster::set_election_timeout_ms(ms);
    }
    let (mut port, mut data, mut cluster_init) = (6443u16, None, false);
    let (mut snap_every, mut snap_keep) = (None::<u64>, 5usize);
    let mut enc_on = true;
    let (mut audit_policy, mut audit_path, mut audit_max, mut audit_backup, mut psa_config) = (None::<String>, None::<String>, 100u64, 5usize, None::<String>);
    let (mut join_url, mut token, mut token_file): (Option<String>, Option<String>, Option<String>) = (None, None, None);
    while let Some(a) = args.next() {
        // `--flag=value` and `--flag value` are both accepted.
        let (a, inline) = match a.iter().position(|&c| c == b'=') {
            Some(i) if a.starts_with(b"--") => (&a[..i], Some(&a[i + 1..])),
            _ => (a, None),
        };
        let v = inline.or_else(|| args.next()).and_then(|v| core::str::from_utf8(v).ok());
        match (a, v) {
            (b"--port", Some(p)) => match p.parse() {
                Ok(p) => port = p,
                Err(_) => return fail("bad --port"),
            },
            (b"--data", Some(d)) => data = Some(String::from(d)),
            (b"--cluster-init", v) => {
                cluster_init = true;
                if let Some(v) = v {
                    return fail(&format!("unexpected argument {v}"));
                }
            }
            (b"--server", Some(v)) => join_url = Some(String::from(v.trim_end_matches('/'))),
            (b"--token", Some(v)) => {
                eprint(b"kr server: warning: --token exposes the server token to local users via the process list; use --token-file or KR_TOKEN\n");
                token = Some(String::from(v))
            }
            (b"--token-file", Some(v)) => token_file = Some(String::from(v)),
            (b"--snapshot-interval", Some(v)) => match crate::snapshot::parse_duration(v) {
                Some(s) => snap_every = Some(s),
                None => return fail("bad --snapshot-interval (seconds, or 30s, 15m, 6h, 1d)"),
            },
            (b"--secrets-encryption", Some(v)) => match v {
                "on" => enc_on = true,
                "off" => enc_on = false,
                _ => return fail("--secrets-encryption takes on or off"),
            },
            (b"--snapshot-keep", Some(v)) => match v.parse::<usize>() {
                Ok(n) if n > 0 => snap_keep = n,
                _ => return fail("bad --snapshot-keep"),
            },
            (b"--audit-policy-file", Some(v)) => audit_policy = Some(String::from(v)),
            (b"--audit-log-path", Some(v)) => audit_path = Some(String::from(v)),
            (b"--audit-log-maxsize", Some(v)) => audit_max = v.parse().unwrap_or(u64::MAX),
            (b"--audit-log-maxbackup", Some(v)) => audit_backup = v.parse().unwrap_or(usize::MAX),
            (b"--pod-security-config", Some(v)) => psa_config = Some(String::from(v)),
            _ => return fail("usage: kr server [--port 6443] [--data DIR] [--cluster-init | --server https://HOST:6443 [--token-file FILE | --token TOKEN]] [--snapshot-interval 6h [--snapshot-keep 5]] [--secrets-encryption on|off] [--audit-policy-file FILE] [--audit-log-path FILE|-|off] [--audit-log-maxsize MB] [--audit-log-maxbackup N] [--pod-security-config FILE]"),
        }
    }
    let data = data.unwrap_or_else(data_dir);
    if cluster_init && join_url.is_some() {
        return fail("--cluster-init starts a new cluster; --server joins an existing one");
    }
    let pki_dir = format!("{data}/pki");
    let raft_dir = format!("{data}/raft");
    let raft_fresh = !exists(&pki::path(&raft_dir, "hardstate")) && !exists(&pki::path(&raft_dir, "log"));
    // A server joining a cluster: everything but its own certificates comes from the cluster.
    let mut join_seeds = Vec::new();
    if let Some(url) = join_url.as_ref().filter(|_| !exists(&pki::path(&pki_dir, "ca.pem"))) {
        let token = match (token, token_file) {
            (Some(t), _) => t,
            (None, Some(f)) => match crate::agent::read_token_file(&f) {
                Ok(t) => t,
                Err(e) => return fail(&e),
            },
            (None, None) => match kr_runtime::store::env_var("KR_TOKEN").filter(|t| !t.trim().is_empty()) {
                Some(t) => t,
                None => return fail("joining needs the server token (--token-file FILE or KR_TOKEN)"),
            },
        };
        if let Err(e) = mkdir_p(&data) {
            return fail(&e);
        }
        let (u, d) = (url.clone(), data.clone());
        match kr_rt::exec::block_on(async move { join_cluster(&u, &token, &d).await }) {
            Ok(s) => join_seeds = s,
            Err(e) => return fail(&e),
        }
    }
    // HA once initialised (the Raft directory exists), or when starting or joining a cluster.
    let ha = cluster_init || join_url.is_some() || !raft_fresh;
    if let Err(e) = mkdir_p(&data).and_then(|_| bootstrap(&data, port, ha)) {
        return fail(&e);
    }
    // The address pods, agents and other servers use to reach this API server.
    let advertise = primary_addr();
    // An existing single-server datastore: imported on --cluster-init, never thrown away by a join.
    let import_db = ha && raft_fresh && exists(&pki::path(&format!("{data}/db"), "log"));
    if import_db && join_url.is_some() {
        return fail("this server already has a single-server datastore; it can found a cluster (--cluster-init) but not join one");
    }
    let setup = || -> Result<(Rc<ServerConfig>, kr_store::Store), String> {
        // The CA travels in the chain so joining agents can pin it by hash.
        let mut chain = load_pem(&pki_dir, "apiserver.pem", "CERTIFICATE")?;
        chain.extend(load_pem(&pki_dir, "ca.pem", "CERTIFICATE")?);
        let key_der = load_pem(&pki_dir, "apiserver.key", "PRIVATE KEY")?.pop().ok_or("apiserver.key empty")?;
        let key = x509::private_key_from_pkcs8(&key_der).map_err(|_| "apiserver.key unsupported")?;
        let ca = load_pem(&pki_dir, "ca.pem", "CERTIFICATE")?;
        let tls = Rc::new(ServerConfig { cert_chain: chain, key, client_auth: ClientAuth::Optional(ca), alpn: alloc::vec![b"http/1.1".to_vec()] });
        // A joining server gets the cluster's encryption config in the join flow, never its own.
        let codec = crate::secrets_encrypt::load(&data, enc_on, join_url.is_none())?;
        let store = if ha {
            let mut s = kr_store::Store::replicated();
            if let Some(c) = codec {
                s.set_codec(c);
            }
            s
        } else {
            kr_store::Store::open_with(&format!("{data}/db"), codec).map_err(|_| String::from("cannot open the datastore (wrong or missing secrets-encryption key?)"))?
        };
        Ok((tls, store))
    };
    let (tls, store) = match setup() {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    let api = match kr_apiserver::api::ApiServer::new(store, pki::now, rng, format!("127.0.0.1:{port}")) {
        Ok(a) => Rc::new(a),
        Err(e) => return fail(&e.message),
    };
    // Audit log (ADR-046) and Pod Security configuration.
    let auditor = match audit_setup(&data, audit_policy.as_deref(), audit_path.as_deref(), audit_max, audit_backup, psa_config.as_deref(), &api) {
        Ok(a) => a,
        Err(e) => return fail(&e),
    };
    // KR_POD_FAMILIES=4 | 6 | 4,6 (default): which address families pods and Services have. Set the
    // same on every server of an HA cluster; nodes follow from the podCIDRs they are given.
    match kr_runtime::store::env_var("KR_POD_FAMILIES").filter(|v| !v.is_empty()) {
        Some(v) => match kr_net::tcp::Families::parse(&v) {
            Some(f) => api.set_pod_families(f),
            None => return fail("KR_POD_FAMILIES must be 4, 6 or 4,6"),
        },
        None => {}
    }
    // HA: the Raft driver must be attached before any bootstrap write (only a ready leader
    // writes; everything else arrives through the log).
    let mut ha_tasks = None;
    if ha {
        let r = (|| -> Result<_, String> {
            let id = server_identity(&data, advertise)?;
            let (srv_tls, cli_tls) = server_tls(&pki_dir)?;
            mkdir_p(&raft_dir)?;
            // Founding a cluster: just us. Joining: nobody yet (the leader adds us).
            let voters = if raft_fresh && join_url.is_none() { alloc::vec![id] } else { Vec::new() };
            let mut seed = [0u8; 8];
            kr_sys::getrandom(&mut seed);
            if import_db {
                import_single_server(&data, &raft_dir, id)?;
                print(b"kr server: imported the single-server datastore as the initial Raft snapshot\n");
            }
            let c = kr_apiserver::cluster::Cluster::open(&api, id, &raft_dir, voters, cli_tls, u64::from_le_bytes(seed))?;
            c.set_self_addr(kr_apiserver::cluster::ServerAddr { ip: advertise, raft_port: kr_apiserver::cluster::transport::PORT, api_port: port });
            c.set_join_secrets(join_secrets(&data)?);
            for (sid, a) in join_seeds.drain(..) {
                if sid != id {
                    c.add_seed(sid, a);
                }
            }
            api.set_cluster(c.clone());
            let l = kr_net::http1::server::listen([0, 0, 0, 0], kr_apiserver::cluster::transport::PORT, 64).map_err(|_| format!("cannot listen on :{}", kr_apiserver::cluster::transport::PORT))?;
            Ok((c, l, srv_tls, id))
        })();
        match r {
            Ok((c, l, srv_tls, id)) => {
                print(format!("kr server: HA server {id}, raft on :{}\n", kr_apiserver::cluster::transport::PORT).as_bytes());
                ha_tasks = Some((c, l, srv_tls, id));
            }
            Err(e) => return fail(&e),
        }
    }
    let sa_setup = || -> Result<(), String> {
        let der = load_pem(&pki_dir, "sa.key", "PRIVATE KEY")?.pop().ok_or("sa.key empty")?;
        let x509::SigningKey::P256(key) = x509::private_key_from_pkcs8(&der).map_err(|_| "sa.key unsupported")? else {
            return Err("sa.key must be a P-256 key".into());
        };
        // TLS tickets: keys derived from the service-account key, which every server of a cluster
        // holds (ADR-051): a restart or another server still opens the tickets.
        kr_net::tls::set_ticket_secret(ticket_secret(&key.to_bytes()));
        let ca_pem = fs::read_file(&pki::path(&pki_dir, "ca.pem"), 1 << 20).ok().and_then(|b| String::from_utf8(b).ok()).ok_or("cannot read ca.pem")?;
        api.set_service_accounts(kr_apiserver::tokens::Signer::new(key), ca_pem).map_err(|e| e.message)
    };
    if let Err(e) = sa_setup() {
        return fail(&e);
    }
    // Node joining: CA for issuing node certificates, and the bootstrap token Secret.
    let join_setup = || -> Result<(), String> {
        let (name, key, der) = pki::load_ca(&pki_dir)?;
        api.set_ca(name, key, der);
        // Test knob: short node certificate lifetimes exercise rotation.
        if let Some(s) = kr_runtime::store::env_var("KR_NODE_CERT_SECONDS").and_then(|v| v.parse().ok()) {
            api.set_node_cert_lifetime(s);
        }
        let tok = fs::read_file(&pki::path(&data, "node-token"), 4096).ok().and_then(|b| String::from_utf8(b).ok()).ok_or("cannot read node-token")?;
        let (_, idsec) = tok.trim().split_once("::").ok_or("bad node-token")?;
        let (id, secret) = idsec.split_once('.').ok_or("bad node-token")?;
        api.ensure_bootstrap_token(id, secret).map_err(|e| e.message)
    };
    if let Err(e) = join_setup() {
        return fail(&e);
    }
    if let Err(e) = api.ensure_builtin_services(advertise, port) {
        return fail(&e.message);
    }
    print(format!("kr server: listening on https://0.0.0.0:{port}\nkr server: export KUBECONFIG={data}/admin.kubeconfig\n").as_bytes());
    let kubelet = match start_kubelet(&api) {
        Ok(k) => Some(k),
        Err(e) => {
            eprint(format!("kr server: kubelet disabled: {e}\n").as_bytes());
            None
        }
    };
    let controllers = kr_apiserver::client::InProcess::new(api.clone(), "controller-manager");
    let local_node = node_name();
    // TLS identity for reaching agents' kubelets.
    let kubelet_client = match (|| -> Result<Rc<kr_crypto::tls::ClientConfig>, String> {
        let chain = load_pem(&pki_dir, "kubelet-client.pem", "CERTIFICATE")?;
        let key = x509::private_key_from_pkcs8(&load_pem(&pki_dir, "kubelet-client.key", "PRIVATE KEY")?.pop().ok_or("empty key")?).map_err(|_| "bad kubelet-client key")?;
        let roots = load_pem(&pki_dir, "ca.pem", "CERTIFICATE")?;
        Ok(Rc::new(kr_crypto::tls::ClientConfig { roots, pinned_ca: None, client_cert: Some((chain, key)), alpn: alloc::vec![b"http/1.1".to_vec()], tls12: false }))
    })() {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    let api_for_proxy = api.clone();
    let snapshot_data = data.clone();
    let manifest_client = kr_apiserver::client::InProcess::new(api.clone(), "manifests");
    let manifest_dir = crate::manifests::dir(&data);
    match kr_rt::exec::block_on(async move {
        if let Some(a) = auditor {
            kr_apiserver::audit::spawn_flusher(a);
        }
        let cfg = kr_controllers::Config { now: pki::now, evict: kr_controllers::nodelifecycle::Limits::from_lookup(kr_runtime::store::env_var), ..kr_controllers::Config::default() };
        // The CSR approver/signer issues with the cluster CA (absent: it does not run).
        let csr_ca = pki::load_ca(&pki_dir).ok().map(|(name, key, _)| Rc::new(kr_controllers::csr::CaSigner { name, key, rng }));
        match ha_tasks {
            Some((c, l, srv_tls, id)) => {
                if let Ok(l6) = kr_net::http1::server::listen6(kr_apiserver::cluster::transport::PORT, 64) {
                    kr_rt::exec::spawn(kr_apiserver::cluster::transport::serve(l6, srv_tls.clone(), id, c.inbox.clone()));
                }
                kr_rt::exec::spawn(kr_apiserver::cluster::transport::serve(l, srv_tls, id, c.inbox.clone()));
                kr_rt::exec::spawn_priority(c.clone().run(api.clone()));
                kr_rt::exec::spawn(c.clone().keep_registered(api.clone()));
                if let Some(url) = join_url {
                    let me = kr_apiserver::cluster::ServerAddr { ip: advertise, raft_port: kr_apiserver::cluster::transport::PORT, api_port: port };
                    kr_rt::exec::spawn(become_voter(c.clone(), url, pki_dir.clone(), me));
                }
                // Exactly one copy of the controllers and the scheduler: on the leader.
                kr_rt::exec::spawn(c.clone().while_leader(move || kr_controllers::run_all_with_ca(controllers.clone(), cfg, csr_ca.clone())));
                kr_rt::exec::spawn(c.while_leader(move || crate::manifests::run(manifest_client.clone(), manifest_dir.clone())));
            }
            None => {
                kr_rt::exec::spawn(kr_controllers::run_all_with_ca(controllers, cfg, csr_ca));
                kr_rt::exec::spawn(crate::manifests::run(manifest_client, manifest_dir));
            }
        }
        if let Some(every) = snap_every {
            kr_rt::exec::spawn(crate::snapshot::schedule(snapshot_data, every, snap_keep));
        }
        let local: Option<Rc<dyn kr_apiserver::api::NodeProxy>> = kubelet.as_ref().map(|k| Rc::new(kr_kubelet::stream::Proxy(k.clone())) as Rc<dyn kr_apiserver::api::NodeProxy>);
        let local_dial: Option<Rc<dyn kr_apiserver::podproxy::PodDialer>> = kubelet.as_ref().map(|k| Rc::new(kr_kubelet::stream::Proxy(k.clone())) as Rc<dyn kr_apiserver::podproxy::PodDialer>);
        let router = Rc::new(kr_kubelet::remote::Router { local_node: local_node.clone(), local, tls: kubelet_client.clone(), local_dial });
        api_for_proxy.set_pod_dialer(router.clone());
        kr_rt::exec::spawn(kr_apiserver::metrics::run(api_for_proxy.clone(), router.clone()));
        api_for_proxy.set_node_proxy(router);
        if let Some(k) = kubelet {
            kr_rt::exec::spawn(k.run());
        }
        kr_apiserver::server::run(api, [0, 0, 0, 0], port, tls).await
    }) {
        Ok(()) => 0,
        Err(e) => fail(&format!("listener failed: {e:?} (is port {port} already in use?)")),
    }
}

/// This machine's node name: the lowercased hostname, or "kr-node".
pub fn node_name() -> String {
    let name = hostname().to_ascii_lowercase();
    if name.is_empty() || !kr_apiserver::object::is_dns_subdomain(&name) {
        "kr-node".into()
    } else {
        name
    }
}

pub fn cgroups_available() -> bool {
    let probe = kr_runtime::cgroup::Limits { pids: Some(1024), ..Default::default() };
    match kr_runtime::cgroup::Cgroup::create(b"kr-probe", &probe) {
        Ok(cg) => {
            cg.remove();
            true
        }
        Err(e) => {
            eprint(format!("kr: no delegated cgroup (errno {}); container resource limits are not enforced\n", e.0).as_bytes());
            false
        }
    }
}

/// The node agent embedded in the server (single-node mode).
fn start_kubelet(api: &Rc<kr_apiserver::api::ApiServer>) -> Result<Rc<kr_kubelet::Kubelet<kr_apiserver::client::InProcess>>, String> {
    let store = kr_runtime::store::Store::open(None).map_err(|_| String::from("cannot open the image store"))?;
    crate::ctr_import::import_startup(&store);
    let name = node_name();
    let cgroups = cgroups_available();
    let node_ip = primary_addr();
    let cfg = kr_kubelet::Config { node_name: name, root: String::from(store.root()), network: ns::getuid() == 0, cgroups, node_ip, vxlan: kr_runtime::store::env_var("KR_NET_BACKEND").as_deref() != Some("host-gw"), eviction_memory_bytes: kr_kubelet::evict::threshold_from_env(), control_plane: true };
    let client = kr_apiserver::client::InProcess::new(api.clone(), "kubelet");
    Ok(kr_kubelet::Kubelet::new(client, cfg, store))
}
