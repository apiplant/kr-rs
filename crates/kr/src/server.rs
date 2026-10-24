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

fn data_dir() -> String {
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
fn bootstrap(data: &str, port: u16) -> Result<(), String> {
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

pub fn main(mut args: Args) -> i32 {
    let (mut port, mut data) = (6443u16, None);
    while let Some(a) = args.next() {
        let v = args.next().and_then(|v| core::str::from_utf8(v).ok());
        match (a, v) {
            (b"--port", Some(p)) => match p.parse() {
                Ok(p) => port = p,
                Err(_) => return fail("bad --port"),
            },
            (b"--data", Some(d)) => data = Some(String::from(d)),
            _ => return fail("usage: kr server [--port 6443] [--data DIR]"),
        }
    }
    let data = data.unwrap_or_else(data_dir);
    if let Err(e) = mkdir_p(&data).and_then(|_| bootstrap(&data, port)) {
        return fail(&e);
    }
    let pki_dir = format!("{data}/pki");
    let setup = || -> Result<(Rc<ServerConfig>, kr_store::Store), String> {
        // The CA travels in the chain so joining agents can pin it by hash.
        let mut chain = load_pem(&pki_dir, "apiserver.pem", "CERTIFICATE")?;
        chain.extend(load_pem(&pki_dir, "ca.pem", "CERTIFICATE")?);
        let key_der = load_pem(&pki_dir, "apiserver.key", "PRIVATE KEY")?.pop().ok_or("apiserver.key empty")?;
        let key = x509::private_key_from_pkcs8(&key_der).map_err(|_| "apiserver.key unsupported")?;
        let ca = load_pem(&pki_dir, "ca.pem", "CERTIFICATE")?;
        let tls = Rc::new(ServerConfig { cert_chain: chain, key, client_auth: ClientAuth::Optional(ca), alpn: alloc::vec![b"http/1.1".to_vec()] });
        let store = kr_store::Store::open(&format!("{data}/db")).map_err(|_| String::from("cannot open the datastore"))?;
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
        let tok = fs::read_file(&pki::path(&data, "node-token"), 4096).ok().and_then(|b| String::from_utf8(b).ok()).ok_or("cannot read node-token")?;
        let (_, idsec) = tok.trim().split_once("::").ok_or("bad node-token")?;
        let (id, secret) = idsec.split_once('.').ok_or("bad node-token")?;
        api.ensure_bootstrap_token(id, secret).map_err(|e| e.message)
    };
    if let Err(e) = join_setup() {
        return fail(&e);
    }
    // The address pods and agents use to reach this API server.
    let advertise = kr_sys::ns::route_source([1, 1, 1, 1]).unwrap_or([127, 0, 0, 1]);
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
        Ok(Rc::new(kr_crypto::tls::ClientConfig { roots, pinned_ca: None, client_cert: Some((chain, key)), alpn: alloc::vec![b"http/1.1".to_vec()] }))
    })() {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    let api_for_proxy = api.clone();
    match kr_rt::exec::block_on(async move {
        let cfg = kr_controllers::Config { now: pki::now, ..kr_controllers::Config::default() };
        kr_rt::exec::spawn(kr_controllers::run_all_with(controllers, cfg));
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
    let cfg = kr_kubelet::Config { node_name: name, root: String::from(store.root()), network: ns::getuid() == 0, cgroups, node_ip };
    let client = kr_apiserver::client::InProcess::new(api.clone(), "kubelet");
    Ok(kr_kubelet::Kubelet::new(client, cfg, store))
}
