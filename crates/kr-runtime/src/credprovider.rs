//! Kubelet image credential provider plugins (`--image-credential-provider-config`,
//! `kubelet.config.k8s.io/v1` `CredentialProviderConfig`, and a bin dir; #364).
//!
//! For an image whose name matches a provider's `matchImages` globs, the plugin `<bin dir>/<name>`
//! is run with its `args` and `env`, gets a `CredentialProviderRequest` on stdin and answers with a
//! `CredentialProviderResponse`. The best matching `auth` entry becomes a registry credential for
//! the pull, in addition to pull secrets and `registries.yaml` (which win on equal specificity).
//! Results are cached per `cacheKeyType` (Image, Registry, Global) until `cacheDuration` ends.
//! The plugin runs asynchronously with a timeout and is killed when it exceeds it.
//!
//! Settings: `KR_CREDENTIAL_PROVIDER_CONFIG` (file) and `KR_CREDENTIAL_PROVIDER_BIN_DIR`
//! (`--image-credential-provider-config`, `--image-credential-provider-bin-dir`).

use crate::auth::{registry_key, Cred, Credential};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;
use kr_fmt::json::Value;
use kr_sys::{ns, Fd};

/// A plugin that outlives this is killed.
const EXEC_TIMEOUT_MS: u64 = 60_000;
const MAX_OUT: usize = 1 << 20;
/// Cache duration of a provider without `defaultCacheDuration` and a response without `cacheDuration`.
const DEFAULT_CACHE_SECS: u64 = 300;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Provider {
    pub name: String,
    pub match_images: Vec<String>,
    pub default_cache_secs: Option<u64>,
    pub api_version: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

/// Go duration (`1h30m`, `90s`, `500ms`) in whole seconds (rounded down); `0` is allowed.
pub fn parse_duration(s: &str) -> Option<u64> {
    let s = s.trim();
    if s == "0" {
        return Some(0);
    }
    let b = s.as_bytes();
    let (mut i, mut ms, mut any) = (0, 0f64, false);
    while i < b.len() {
        let st = i;
        while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
            i += 1;
        }
        let n: f64 = s[st..i].parse().ok()?;
        let us = i;
        while i < b.len() && !(b[i].is_ascii_digit() || b[i] == b'.') {
            i += 1;
        }
        ms += n * match &s[us..i] {
            "ms" => 1.0,
            "s" => 1e3,
            "m" => 6e4,
            "h" => 3.6e6,
            _ => return None,
        };
        any = true;
    }
    any.then_some((ms / 1000.0) as u64)
}

/// Parses a `CredentialProviderConfig` (YAML or JSON).
pub fn parse_config(text: &str) -> Result<Vec<Provider>, String> {
    let root = kr_fmt::yaml::parse(text).map_err(|_| String::from("not valid YAML/JSON"))?;
    if root.get("kind").and_then(|v| v.as_str()) != Some("CredentialProviderConfig") {
        return Err("kind must be CredentialProviderConfig".to_string());
    }
    let strs = |v: Option<&Value>| -> Vec<String> { v.and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default() };
    let mut out = Vec::new();
    for p in root.get("providers").and_then(|v| v.as_array()).unwrap_or(&[]) {
        let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if name.is_empty() || name.contains('/') || name == "." || name == ".." {
            return Err(format!("invalid provider name {name:?}"));
        }
        let match_images = strs(p.get("matchImages"));
        if match_images.is_empty() {
            return Err(format!("provider {name}: matchImages is required"));
        }
        let api_version = p.get("apiVersion").and_then(|v| v.as_str()).unwrap_or("");
        if !api_version.starts_with("credentialprovider.kubelet.k8s.io/") {
            return Err(format!("provider {name}: unsupported apiVersion {api_version:?}"));
        }
        let default_cache_secs = match p.get("defaultCacheDuration").and_then(|v| v.as_str()) {
            Some(d) => Some(parse_duration(d).ok_or_else(|| format!("provider {name}: bad defaultCacheDuration"))?),
            None => None,
        };
        let env = p
            .get("env")
            .and_then(|v| v.as_array())
            .unwrap_or(&[])
            .iter()
            .filter_map(|e| Some((e.get("name")?.as_str()?.to_string(), e.get("value").and_then(|v| v.as_str()).unwrap_or("").to_string())))
            .collect();
        out.push(Provider { name: name.to_string(), match_images, default_cache_secs, api_version: api_version.to_string(), args: strs(p.get("args")), env });
    }
    Ok(out)
}

/// `*` and `?` within one string (callers split on separators first).
fn glob(p: &[u8], s: &[u8]) -> bool {
    match p.split_first() {
        None => s.is_empty(),
        Some((b'*', rest)) => (0..=s.len()).any(|i| glob(rest, &s[i..])),
        Some((b'?', rest)) => !s.is_empty() && glob(rest, &s[1..]),
        Some((c, rest)) => s.first() == Some(c) && glob(rest, &s[1..]),
    }
}

fn split_url(s: &str) -> (&str, &str, &str) {
    let s = s.strip_prefix("https://").or_else(|| s.strip_prefix("http://")).unwrap_or(s);
    let (hp, path) = s.split_once('/').unwrap_or((s, ""));
    match hp.rsplit_once(':') {
        Some((h, p)) if !p.contains(']') => (h, p, path),
        _ => (hp, "", path),
    }
}

/// Upstream kubelet's `URLsMatch`: same number of domain labels each matching its pattern label,
/// matching ports, and the pattern's path segments a prefix of the image's.
pub fn image_matches(pattern: &str, image: &str) -> bool {
    let (ph, pp, ppath) = split_url(pattern);
    let (ih, ip, ipath) = split_url(image);
    let (pl, il): (Vec<&str>, Vec<&str>) = (ph.split('.').collect(), ih.split('.').collect());
    if pl.len() != il.len() || !pl.iter().zip(&il).all(|(p, i)| glob(p.as_bytes(), i.as_bytes())) {
        return false;
    }
    if !glob(pp.as_bytes(), ip.as_bytes()) {
        return false;
    }
    if ppath.is_empty() {
        return true;
    }
    let pparts: Vec<&str> = ppath.trim_end_matches('/').split('/').collect();
    let iparts: Vec<&str> = ipath.split('/').collect();
    iparts.len() >= pparts.len() && pparts.iter().zip(&iparts).all(|(p, i)| glob(p.as_bytes(), i.as_bytes()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheKeyType {
    Image,
    Registry,
    Global,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub key_type: CacheKeyType,
    pub cache_secs: Option<u64>,
    /// (pattern, username, password).
    pub auth: Vec<(String, String, String)>,
}

pub fn parse_response(b: &[u8]) -> Result<Response, String> {
    let v = kr_fmt::json::parse(b).map_err(|_| String::from("response is not JSON"))?;
    if v.get("kind").and_then(|k| k.as_str()) != Some("CredentialProviderResponse") {
        return Err("response kind must be CredentialProviderResponse".to_string());
    }
    let key_type = match v.get("cacheKeyType").and_then(|k| k.as_str()) {
        Some("Image") => CacheKeyType::Image,
        Some("Registry") => CacheKeyType::Registry,
        Some("Global") => CacheKeyType::Global,
        _ => return Err("bad cacheKeyType".to_string()),
    };
    let cache_secs = match v.get("cacheDuration").and_then(|d| d.as_str()) {
        Some(d) => Some(parse_duration(d).ok_or("bad cacheDuration")?),
        None => None,
    };
    let mut auth = Vec::new();
    for (k, e) in v.get("auth").and_then(|a| a.as_object()).unwrap_or(&[]) {
        let u = e.get("username").and_then(|x| x.as_str()).unwrap_or("");
        let p = e.get("password").and_then(|x| x.as_str()).unwrap_or("");
        auth.push((k.clone(), u.to_string(), p.to_string()));
    }
    Ok(Response { key_type, cache_secs, auth })
}

pub fn request_json(api_version: &str, image: &str) -> String {
    let mut s = format!("{{\"apiVersion\":\"{api_version}\",\"kind\":\"CredentialProviderRequest\",\"image\":");
    kr_fmt::json::write_str(image, &mut s);
    s.push('}');
    s
}

/// The credential for `image` (`registry/repository`): the longest matching `auth` key.
pub fn pick(auth: &[(String, String, String)], image: &str) -> Option<(String, String)> {
    auth.iter().filter(|(k, _, _)| image_matches(k, image)).max_by_key(|(k, _, _)| k.len()).map(|(_, u, p)| (u.clone(), p.clone()))
}

struct Entry {
    key: String,
    expires_ms: u64,
    auth: Vec<(String, String, String)>,
}

struct Cache(RefCell<Vec<Entry>>);
// SAFETY: the runtime is single-threaded (ADR-005).
unsafe impl Sync for Cache {}
static CACHE: Cache = Cache(RefCell::new(Vec::new()));

fn mono_ms() -> u64 {
    kr_sys::clock_gettime(1).map(|t| t.tv_sec as u64 * 1000 + t.tv_nsec as u64 / 1_000_000).unwrap_or(0)
}

fn cache_key(p: &Provider, t: CacheKeyType, image: &str, registry: &str) -> String {
    match t {
        CacheKeyType::Image => format!("{}\0i\0{image}", p.name),
        CacheKeyType::Registry => format!("{}\0r\0{registry}", p.name),
        CacheKeyType::Global => format!("{}\0g", p.name),
    }
}

fn cached(p: &Provider, image: &str, registry: &str) -> Option<Vec<(String, String, String)>> {
    let now = mono_ms();
    let mut c = CACHE.0.borrow_mut();
    c.retain(|e| e.expires_ms > now);
    [CacheKeyType::Image, CacheKeyType::Registry, CacheKeyType::Global].iter().find_map(|t| {
        let k = cache_key(p, *t, image, registry);
        c.iter().find(|e| e.key == k).map(|e| e.auth.clone())
    })
}

fn nul(v: &str) -> Vec<u8> {
    let mut o = v.as_bytes().to_vec();
    o.push(0);
    o
}

/// Runs `path` with `input` on stdin; its stdout. None on any failure or timeout.
async fn exec(path: &str, args: &[String], env: &[(String, String)], input: &[u8], timeout_ms: u64) -> Option<Vec<u8>> {
    let mut env_s: Vec<String> = env.iter().map(|(k, v)| format!("{k}={v}")).collect();
    if let Some(p) = crate::store::env_var("PATH") {
        env_s.push(format!("PATH={p}"));
    }
    if path.contains('\0') || args.iter().any(|a| a.contains('\0')) || env_s.iter().any(|a| a.contains('\0')) {
        return None;
    }
    let (in_r, in_w) = kr_sys::pipe2(kr_sys::O_CLOEXEC).ok()?;
    let (out_r, out_w) = kr_sys::pipe2(kr_sys::O_CLOEXEC).ok()?;
    let null = ns::open(b"/dev/null\0", ns::O_WRONLY, 0).ok()?;
    let cpath = nul(path);
    let argv_c: Vec<Vec<u8>> = core::iter::once(cpath.clone()).chain(args.iter().map(|a| nul(a))).collect();
    let mut argv: Vec<*const u8> = argv_c.iter().map(|a| a.as_ptr()).collect();
    argv.push(core::ptr::null());
    let env_c: Vec<Vec<u8>> = env_s.iter().map(|e| nul(e)).collect();
    let mut envp: Vec<*const u8> = env_c.iter().map(|a| a.as_ptr()).collect();
    envp.push(core::ptr::null());
    let mut pidfd: i32 = -1;
    let mut ca = ns::CloneArgs { flags: ns::CLONE_PIDFD, exit_signal: ns::SIGCHLD as u64, pidfd: &mut pidfd as *mut i32 as u64, ..Default::default() };
    // SAFETY: the runtime is single-threaded (ADR-005); the child only makes syscalls and execs.
    let pid = unsafe { ns::clone3(&mut ca) }.ok()?;
    if pid == 0 {
        let _ = ns::sigmask_reset();
        let _ = ns::dup_to(in_r.raw(), 0);
        let _ = ns::dup_to(out_w.raw(), 1);
        let _ = ns::dup_to(null.raw(), 2);
        let _ = ns::execve(&cpath, &argv, &envp);
        kr_sys::exit_group(127);
    }
    let pidfd = Fd(pidfd);
    drop(in_r);
    drop(out_w);
    let r = kr_rt::exec::timeout(timeout_ms, async {
        ns::set_nonblocking(in_w.raw()).ok()?;
        ns::set_nonblocking(out_r.raw()).ok()?;
        let w = kr_rt::exec::Async::new(in_w).ok()?;
        let r = kr_rt::exec::Async::new(out_r).ok()?;
        // An error (EPIPE: a plugin that ignores stdin) surfaces through its exit status.
        let _ = w.write_all(input).await;
        drop(w);
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    if out.len() > MAX_OUT {
                        return None;
                    }
                }
                Err(_) => return None,
            }
        }
        Some(out)
    })
    .await;
    let out = match r {
        Ok(Some(o)) => o,
        _ => {
            let _ = ns::kill(pid, ns::SIGKILL);
            let _ = ns::wait4(pid);
            return None;
        }
    };
    // stdout closed: the plugin is exiting; reap it, killing a straggler after a grace period.
    let mut waited = 0;
    loop {
        if matches!(ns::pidfd_try_wait(&pidfd), Ok(Some(_))) {
            break;
        }
        if waited >= 5000 {
            let _ = ns::kill(pid, ns::SIGKILL);
            break;
        }
        waited += 10;
        kr_rt::exec::sleep(10).await;
    }
    let code = ns::exit_code(ns::wait4(pid).unwrap_or(0));
    (code == 0).then_some(out)
}

/// Credentials from the configured providers for an image, as pull credentials. Empty when no
/// provider is configured or none matches; provider failures are logged and skipped.
pub async fn credentials_for(image_ref: &str, registry: &str, repository: &str) -> Vec<Cred> {
    let Some(cfg) = crate::store::env_var("KR_CREDENTIAL_PROVIDER_CONFIG").filter(|c| !c.is_empty()) else { return Vec::new() };
    let Some(dir) = crate::store::env_var("KR_CREDENTIAL_PROVIDER_BIN_DIR").filter(|c| !c.is_empty()) else { return Vec::new() };
    let log = |m: String| {
        let _ = kr_sys::write(2, format!("kr: image credential provider: {m}\n").as_bytes());
    };
    let providers = match kr_sys::fs::read_file(&nul(&cfg), 1 << 20).map_err(|_| String::from("cannot read config")).and_then(|b| parse_config(&String::from_utf8_lossy(&b))) {
        Ok(p) => p,
        Err(e) => {
            log(format!("{cfg}: {e}"));
            return Vec::new();
        }
    };
    let image = format!("{registry}/{repository}");
    let mut out = Vec::new();
    for p in providers.iter().filter(|p| p.match_images.iter().any(|m| image_matches(m, &image))) {
        let auth = match cached(p, &image, registry) {
            Some(a) => a,
            None => {
                let req = request_json(&p.api_version, image_ref);
                let path = format!("{}/{}", dir.trim_end_matches('/'), p.name);
                let Some(raw) = exec(&path, &p.args, &p.env, req.as_bytes(), EXEC_TIMEOUT_MS).await else {
                    log(format!("{} failed for {image}", p.name));
                    continue;
                };
                let resp = match parse_response(&raw) {
                    Ok(r) => r,
                    Err(e) => {
                        log(format!("{}: {e}", p.name));
                        continue;
                    }
                };
                let secs = resp.cache_secs.or(p.default_cache_secs).unwrap_or(DEFAULT_CACHE_SECS);
                if secs > 0 {
                    CACHE.0.borrow_mut().push(Entry { key: cache_key(p, resp.key_type, &image, registry), expires_ms: mono_ms() + secs * 1000, auth: resp.auth.clone() });
                }
                resp.auth
            }
        };
        if let Some((username, password)) = pick(&auth, &image) {
            out.push(Cred { registry: registry_key(registry), cred: Credential { username, password, identity_token: None, token: None } });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(image_matches("*.dkr.ecr.*.amazonaws.com", "123.dkr.ecr.us-east-1.amazonaws.com/app"));
        assert!(!image_matches("*.amazonaws.com", "a.b.amazonaws.com/x"));
        assert!(image_matches("registry.io:5000", "registry.io:5000/x/y"));
        assert!(!image_matches("registry.io:5000", "registry.io/x"));
        assert!(image_matches("registry.io/team", "registry.io/team/app"));
        assert!(!image_matches("registry.io/team", "registry.io/other/app"));
        assert!(image_matches("registry.io/te*", "registry.io/team/app"));
        assert!(!image_matches("registry.io", "other.io/x"));
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("1h30m"), Some(5400));
        assert_eq!(parse_duration("90s"), Some(90));
        assert_eq!(parse_duration("0"), Some(0));
        assert_eq!(parse_duration("5x"), None);
    }

    #[test]
    fn config_and_response() {
        let y = "apiVersion: kubelet.config.k8s.io/v1\nkind: CredentialProviderConfig\nproviders:\n- name: p\n  matchImages: [\"*.io\"]\n  defaultCacheDuration: 10m\n  apiVersion: credentialprovider.kubelet.k8s.io/v1\n  args: [get-credentials]\n  env:\n  - name: A\n    value: b\n";
        let p = parse_config(y).unwrap();
        assert_eq!((p[0].default_cache_secs, p[0].args.clone(), p[0].env.clone()), (Some(600), alloc::vec!["get-credentials".to_string()], alloc::vec![("A".to_string(), "b".to_string())]));
        assert!(parse_config("kind: Other").is_err());
        let r = parse_response(br#"{"kind":"CredentialProviderResponse","apiVersion":"x","cacheKeyType":"Registry","cacheDuration":"1m","auth":{"a.io":{"username":"u","password":"p"},"a.io/team":{"username":"u2","password":"p2"}}}"#).unwrap();
        assert_eq!(r.key_type, CacheKeyType::Registry);
        assert_eq!(pick(&r.auth, "a.io/team/x"), Some(("u2".to_string(), "p2".to_string())));
        assert_eq!(pick(&r.auth, "a.io/other"), Some(("u".to_string(), "p".to_string())));
        assert_eq!(pick(&r.auth, "b.io/x"), None);
    }

    #[test]
    fn exec_plugin_and_cache() {
        let dir = format!("/tmp/kr-credprov-{}", kr_sys::fs::getpid());
        let _ = ns::mkdir(format!("{dir}\0").as_bytes(), 0o700);
        let counter = format!("{dir}/count");
        let script = format!(
            "#!/bin/sh\ncat >/dev/null\necho x >> {counter}\nprintf '%s' '{{\"kind\":\"CredentialProviderResponse\",\"apiVersion\":\"credentialprovider.kubelet.k8s.io/v1\",\"cacheKeyType\":\"Registry\",\"cacheDuration\":\"1h\",\"auth\":{{\"*.test.io\":{{\"username\":\"u\",\"password\":\"'$1'\"}}}}}}'\n"
        );
        let write = |p: &str, c: &str, mode: u32| {
            let fd = ns::open(format!("{p}\0").as_bytes(), ns::O_WRONLY | ns::O_CREAT | kr_sys::fs::O_TRUNC, mode).unwrap();
            let _ = kr_sys::write(fd.raw(), c.as_bytes());
        };
        write(&format!("{dir}/prov"), &script, 0o700);
        write(&format!("{dir}/cfg.yaml"), "kind: CredentialProviderConfig\nproviders:\n- name: prov\n  matchImages: [\"*.test.io\"]\n  apiVersion: credentialprovider.kubelet.k8s.io/v1\n  args: [sekret]\n", 0o600);
        crate::store::set_override("KR_CREDENTIAL_PROVIDER_CONFIG", &format!("{dir}/cfg.yaml"));
        crate::store::set_override("KR_CREDENTIAL_PROVIDER_BIN_DIR", &dir);
        let got = kr_rt::exec::block_on(async {
            let a = credentials_for("r.test.io/a/b:1", "r.test.io", "a/b").await;
            let b = credentials_for("r.test.io/c:1", "r.test.io", "c").await;
            let c = credentials_for("other.io/c:1", "other.io", "c").await;
            (a, b, c)
        });
        assert_eq!(got.0.len(), 1);
        assert_eq!(got.0[0].cred.password, "sekret");
        assert_eq!(got.1.len(), 1);
        assert!(got.2.is_empty());
        let n = kr_sys::fs::read_file(format!("{counter}\0").as_bytes(), 100).unwrap();
        assert_eq!(n, b"x\n"); // the second call came from the Registry-keyed cache
    }
}
