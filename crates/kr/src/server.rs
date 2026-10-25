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

/// Creates the CA, the apiserver serving cert and the admin client cert if missing.
fn bootstrap(data: &str, port: u16, ha: bool) -> Result<(), String> {
    let pki_dir = format!("{data}/pki");
    mkdir_p(&pki_dir)?;
    if !exists(&pki::path(&pki_dir, "ca.pem")) {
        pki::create_ca(&pki_dir, "kr-cluster-ca".into(), 3650)?;
    }
    let ca = pki::load_ca(&pki_dir)?;
    if !exists(&pki::path(&pki_dir, "apiserver.pem")) {
        let host = hostname();
        let mut dns: Vec<String> = ["localhost", "kubernetes", "kubernetes.default", "kubernetes.default.svc", "kubernetes.default.svc.cluster.local"].iter().map(|s| String::from(*s)).collect();
        if !host.is_empty() && kr_apiserver::object::is_dns_subdomain(&host) {
            dns.push(host);
        }
        let name = Name { common_name: "kube-apiserver".into(), organizations: Vec::new() };
        let mut ips = alloc::vec![alloc::vec![127, 0, 0, 1], alloc::vec![10, 96, 0, 1]];
        if let Ok(adv) = kr_sys::ns::route_source([1, 1, 1, 1]) {
            ips.push(adv.to_vec());
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
fn server_identity(data: &str, advertise: [u8; 4]) -> Result<u64, String> {
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
        issue(&pki_dir, "server", &ca, name, true, true, Vec::new(), alloc::vec![alloc::vec![127, 0, 0, 1], advertise.to_vec()])?;
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
    let snap = kr_raft::Snapshot { meta: kr_raft::SnapshotMeta { index: 1, term: 1, voters: alloc::vec![id] }, data: Rc::from(image) };
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
    let servers = v.get("servers").and_then(kr_fmt::json::Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
    Ok(servers
        .iter()
        .filter_map(|s| {
            let ip = kr_apiserver::object::parse_ipv4(s.get("ip")?.as_str()?)?;
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
    let ip = me.ip;
    let body = format!(r#"{{"ip":"{}.{}.{}.{}","raftPort":{},"apiPort":{}}}"#, ip[0], ip[1], ip[2], ip[3], me.raft_port, me.api_port);
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

pub fn main(mut args: Args) -> i32 {
    let (mut port, mut data, mut cluster_init) = (6443u16, None, false);
    let (mut join_url, mut token, mut token_file): (Option<String>, Option<String>, Option<String>) = (None, None, None);
    while let Some(a) = args.next() {
        let v = args.next().and_then(|v| core::str::from_utf8(v).ok());
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
            _ => return fail("usage: kr server [--port 6443] [--data DIR] [--cluster-init | --server https://HOST:6443 [--token-file FILE | --token TOKEN]]"),
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
    let advertise = kr_sys::ns::route_source([1, 1, 1, 1]).unwrap_or([127, 0, 0, 1]);
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
        let store = if ha {
            kr_store::Store::replicated()
        } else {
            kr_store::Store::open(&format!("{data}/db")).map_err(|_| String::from("cannot open the datastore"))?
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
    match kr_rt::exec::block_on(async move {
        let cfg = kr_controllers::Config { now: pki::now, ..kr_controllers::Config::default() };
        match ha_tasks {
            Some((c, l, srv_tls, id)) => {
                kr_rt::exec::spawn(kr_apiserver::cluster::transport::serve(l, srv_tls, id, c.inbox.clone()));
                kr_rt::exec::spawn(c.clone().run(api.clone()));
                if let Some(url) = join_url {
                    let me = kr_apiserver::cluster::ServerAddr { ip: advertise, raft_port: kr_apiserver::cluster::transport::PORT, api_port: port };
                    kr_rt::exec::spawn(become_voter(c.clone(), url, pki_dir.clone(), me));
                }
                // Exactly one copy of the controllers and the scheduler: on the leader.
                kr_rt::exec::spawn(c.while_leader(move || kr_controllers::run_all_with(controllers.clone(), cfg)));
            }
            None => {
                kr_rt::exec::spawn(kr_controllers::run_all_with(controllers, cfg));
            }
        }
        let local: Option<Rc<dyn kr_apiserver::api::NodeProxy>> = kubelet.as_ref().map(|k| Rc::new(kr_kubelet::stream::Proxy(k.clone())) as Rc<dyn kr_apiserver::api::NodeProxy>);
        api_for_proxy.set_node_proxy(Rc::new(kr_kubelet::remote::Router { local_node: local_node.clone(), local, tls: kubelet_client.clone() }));
        if let Some(k) = kubelet {
            kr_rt::exec::spawn(k.run());
        }
        kr_apiserver::server::run(api, [0, 0, 0, 0], port, tls).await
    }) {
        Ok(()) => 0,
        Err(_) => fail("listener failed"),
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
        Err(_) => {
            eprint(b"kr: no delegated cgroup; container resource limits are not enforced\n");
            false
        }
    }
}

/// The node agent embedded in the server (single-node mode).
fn start_kubelet(api: &Rc<kr_apiserver::api::ApiServer>) -> Result<Rc<kr_kubelet::Kubelet<kr_apiserver::client::InProcess>>, String> {
    let store = kr_runtime::store::Store::open(None).map_err(|_| String::from("cannot open the image store"))?;
    let name = node_name();
    let cgroups = cgroups_available();
    let node_ip = kr_sys::ns::route_source([1, 1, 1, 1]).unwrap_or([127, 0, 0, 1]);
    let cfg = kr_kubelet::Config { node_name: name, root: String::from(store.root()), network: ns::getuid() == 0, cgroups, node_ip, vxlan: kr_runtime::store::env_var("KR_NET_BACKEND").as_deref() != Some("host-gw"), eviction_memory_bytes: kr_kubelet::evict::threshold_from_env() };
    let client = kr_apiserver::client::InProcess::new(api.clone(), "kubelet");
    Ok(kr_kubelet::Kubelet::new(client, cfg, store))
}
