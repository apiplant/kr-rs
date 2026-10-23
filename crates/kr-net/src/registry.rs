//! OCI distribution (registry v2) client: image references, manifests, blobs, bearer auth.
//!
//! Loopback hosts default to plain `http` (local dev registries), everything else uses `https`
//! through whatever [`Connector`] the client has (`tls::TlsConnector` in kr).

use crate::http1::url::Url;
use crate::http1::{Client, Connector, Response, TcpConnector, Transport};
use crate::sha256::{hex, Sha256};
use crate::tcp::IpAddr;
use crate::{Error, Result};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_fmt::json::{self, Value};

pub const MT_OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub const MT_OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const MT_DOCKER_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
pub const MT_DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
const ACCEPT: &str = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, \
application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json";

const MAX_MANIFEST: usize = 4 * 1024 * 1024;
const MAX_CONFIG: usize = 4 * 1024 * 1024;
const MAX_TOKEN_BODY: usize = 64 * 1024;

/// Architecture string for the running binary's platform (`linux/<arch>`).
pub const fn target_arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "amd64"
    }
}

// ---------- digest ----------

/// `algorithm:hex`, validated. Only `sha256` can be computed by this crate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Digest(String);

impl Digest {
    pub fn parse(s: &str) -> Result<Digest> {
        let (alg, h) = s.split_once(':').ok_or(Error::BadRef("digest needs algorithm:hex"))?;
        let alg_ok = !alg.is_empty()
            && alg.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"+._-".contains(&b));
        let hex_ok = h.len() >= 32 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !alg_ok || !hex_ok {
            return Err(Error::BadRef("malformed digest"));
        }
        if alg == "sha256" && h.len() != 64 {
            return Err(Error::BadRef("sha256 digest must be 64 hex characters"));
        }
        Ok(Digest(s.to_string()))
    }

    pub fn sha256_of(data: &[u8]) -> Digest {
        Digest(format!("sha256:{}", hex(&crate::sha256::sha256(data))))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_sha256(&self) -> bool {
        self.0.starts_with("sha256:")
    }
}

impl core::fmt::Display for Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------- references ----------

/// A parsed image reference with docker's defaulting rules applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reference {
    /// `host[:port]`, normalised (`docker.io` for the default / `index.docker.io`).
    pub registry: String,
    /// Repository path, with `library/` added for single-component `docker.io` names.
    pub repository: String,
    pub tag: Option<String>,
    pub digest: Option<Digest>,
}

fn valid_repo_component(c: &str) -> bool {
    // alnum+ ( ('.' | '_' | '__' | '-'+) alnum+ )*, lowercase only
    let b = c.as_bytes();
    let alnum = |x: u8| x.is_ascii_lowercase() || x.is_ascii_digit();
    let mut i = 0;
    if b.is_empty() || !alnum(b[0]) {
        return false;
    }
    while i < b.len() {
        while i < b.len() && alnum(b[i]) {
            i += 1;
        }
        if i == b.len() {
            return true;
        }
        let s = i;
        match b[i] {
            b'.' => i += 1,
            b'_' => {
                i += 1;
                if i < b.len() && b[i] == b'_' {
                    i += 1;
                }
            }
            b'-' => {
                while i < b.len() && b[i] == b'-' {
                    i += 1;
                }
            }
            _ => return false,
        }
        if s == i || i == b.len() || !alnum(b[i]) {
            return false;
        }
    }
    true
}

fn valid_tag(t: &str) -> bool {
    let b = t.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && (b[0].is_ascii_alphanumeric() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

impl Reference {
    pub fn parse(s: &str) -> Result<Reference> {
        if s.is_empty() || s.bytes().any(|b| b <= 0x20 || b >= 0x7f) {
            return Err(Error::BadRef("empty or contains whitespace/control characters"));
        }
        let (name, digest) = match s.split_once('@') {
            Some((n, d)) => (n, Some(Digest::parse(d)?)),
            None => (s, None),
        };
        let slash = name.rfind('/');
        let (name, tag) = match name.rfind(':') {
            Some(c) if slash.is_none_or(|sl| c > sl) => {
                let t = &name[c + 1..];
                if !valid_tag(t) {
                    return Err(Error::BadRef("invalid tag"));
                }
                (&name[..c], Some(t.to_string()))
            }
            _ => (name, None),
        };
        if name.is_empty() {
            return Err(Error::BadRef("empty repository"));
        }
        let (mut registry, mut repo) = match name.split_once('/') {
            Some((first, rest))
                if first.contains('.') || first.contains(':') || first == "localhost" || first.to_ascii_lowercase() != first =>
            {
                (first.to_string(), rest.to_string())
            }
            _ => ("docker.io".to_string(), name.to_string()),
        };
        if registry == "index.docker.io" {
            registry = "docker.io".to_string();
        }
        if registry == "docker.io" && !repo.contains('/') {
            repo = format!("library/{repo}");
        }
        if repo.is_empty() || repo.len() > 255 || !repo.split('/').all(valid_repo_component) {
            return Err(Error::BadRef("invalid repository name"));
        }
        let host_url = Url::parse(&format!("http://{registry}/")).map_err(|_| Error::BadRef("invalid registry host"))?;
        if host_url.path != "/" {
            return Err(Error::BadRef("invalid registry host"));
        }
        let tag = if tag.is_none() && digest.is_none() { Some("latest".to_string()) } else { tag };
        Ok(Reference { registry, repository: repo, tag, digest })
    }

    /// The manifest reference to request: the digest when pinned, otherwise the tag.
    pub fn manifest_ref(&self) -> &str {
        match (&self.digest, &self.tag) {
            (Some(d), _) => d.as_str(),
            (None, Some(t)) => t,
            (None, None) => "latest",
        }
    }

    /// Host (and port) to connect to; `docker.io` lives at `registry-1.docker.io`.
    pub fn endpoint(&self) -> &str {
        if self.registry == "docker.io" {
            "registry-1.docker.io"
        } else {
            &self.registry
        }
    }
}

impl core::fmt::Display for Reference {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}/{}", self.registry, self.repository)?;
        if let Some(t) = &self.tag {
            write!(f, ":{t}")?;
        }
        if let Some(d) = &self.digest {
            write!(f, "@{d}")?;
        }
        Ok(())
    }
}

// ---------- manifests ----------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub media_type: String,
    pub digest: Digest,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Platform {
    pub os: String,
    pub architecture: String,
    pub variant: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexEntry {
    pub descriptor: Descriptor,
    pub platform: Option<Platform>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageManifest {
    pub media_type: String,
    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Manifest {
    Image(ImageManifest),
    Index(Vec<IndexEntry>),
}

fn descriptor(v: &Value) -> Result<Descriptor> {
    let mt = v.get("mediaType").and_then(Value::as_str).ok_or(Error::Manifest("descriptor without mediaType"))?;
    let d = v.get("digest").and_then(Value::as_str).ok_or(Error::Manifest("descriptor without digest"))?;
    let size = v.get("size").and_then(Value::as_u64).ok_or(Error::Manifest("descriptor without size"))?;
    Ok(Descriptor { media_type: mt.to_string(), digest: Digest::parse(d)?, size })
}

/// Parses an image manifest or index. `content_type` is the HTTP header, used when the JSON has
/// no `mediaType`.
pub fn parse_manifest(body: &[u8], content_type: Option<&str>) -> Result<Manifest> {
    let v = json::parse(body).map_err(|_| Error::Json("manifest is not valid JSON"))?;
    if v.as_object().is_none() {
        return Err(Error::Manifest("manifest is not an object"));
    }
    if v.get("schemaVersion").and_then(Value::as_u64) != Some(2) {
        return Err(Error::Manifest("unsupported schemaVersion (schema1 is not supported)"));
    }
    let ct = content_type.map(|c| c.split(';').next().unwrap_or("").trim());
    let mt = v.get("mediaType").and_then(Value::as_str).or(ct).unwrap_or("");
    let index_like = mt == MT_OCI_INDEX || mt == MT_DOCKER_LIST;
    let image_like = mt == MT_OCI_MANIFEST || mt == MT_DOCKER_MANIFEST;
    let is_index = if index_like {
        true
    } else if image_like {
        false
    } else if v.get("manifests").is_some() {
        true
    } else if v.get("layers").is_some() {
        false
    } else {
        return Err(Error::Manifest("unrecognised manifest type"));
    };
    if is_index {
        let arr = v.get("manifests").and_then(Value::as_array).ok_or(Error::Manifest("index without manifests"))?;
        let mut out = Vec::new();
        for m in arr {
            let platform = m.get("platform").filter(|p| p.as_object().is_some()).map(|p| {
                let g = |k| p.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                Platform { os: g("os"), architecture: g("architecture"), variant: g("variant") }
            });
            out.push(IndexEntry { descriptor: descriptor(m)?, platform });
        }
        Ok(Manifest::Index(out))
    } else {
        let config = descriptor(v.get("config").ok_or(Error::Manifest("manifest without config"))?)?;
        let layers = v.get("layers").and_then(Value::as_array).ok_or(Error::Manifest("manifest without layers"))?;
        let layers = layers.iter().map(descriptor).collect::<Result<Vec<_>>>()?;
        let media_type = if mt.is_empty() { MT_OCI_MANIFEST.to_string() } else { mt.to_string() };
        Ok(Manifest::Image(ImageManifest { media_type, config, layers }))
    }
}

/// Picks the `linux/<arch>` entry of an index (arm64 accepts an empty or `v8` variant).
pub fn select_platform<'a>(entries: &'a [IndexEntry], os: &str, arch: &str) -> Result<&'a IndexEntry> {
    entries
        .iter()
        .find(|e| {
            e.platform.as_ref().is_some_and(|p| {
                p.os == os && p.architecture == arch && (arch != "arm64" || p.variant.is_empty() || p.variant == "v8")
            })
        })
        .ok_or(Error::NoPlatform)
}

// ---------- auth ----------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub scheme: String,
    pub params: Vec<(String, String)>,
}

impl Challenge {
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// Parses a single `WWW-Authenticate` challenge: `Scheme k=v, k="quoted \" value", ...`.
pub fn parse_challenge(h: &str) -> Result<Challenge> {
    let h = h.trim();
    let (scheme, rest) = h.split_once(' ').unwrap_or((h, ""));
    if !crate::http1::head::is_token(scheme) {
        return Err(Error::Auth("malformed challenge"));
    }
    let mut params = Vec::new();
    let b = rest.as_bytes();
    let mut i = 0;
    loop {
        while i < b.len() && matches!(b[i], b' ' | b'\t' | b',') {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let ks = i;
        while i < b.len() && b[i] != b'=' && b[i] != b',' {
            i += 1;
        }
        if i >= b.len() || b[i] != b'=' {
            return Err(Error::Auth("malformed challenge parameter"));
        }
        let key = rest[ks..i].trim();
        if !crate::http1::head::is_token(key) {
            return Err(Error::Auth("malformed challenge parameter"));
        }
        i += 1;
        let mut val = Vec::new();
        if i < b.len() && b[i] == b'"' {
            i += 1;
            loop {
                match b.get(i) {
                    None => return Err(Error::Auth("unterminated quoted string")),
                    Some(b'"') => {
                        i += 1;
                        break;
                    }
                    Some(b'\\') => {
                        val.push(*b.get(i + 1).ok_or(Error::Auth("unterminated quoted string"))?);
                        i += 2;
                    }
                    Some(c) => {
                        val.push(*c);
                        i += 1;
                    }
                }
            }
        } else {
            let vs = i;
            while i < b.len() && b[i] != b',' {
                i += 1;
            }
            val.extend_from_slice(rest[vs..i].trim().as_bytes());
        }
        let val = String::from_utf8(val).map_err(|_| Error::Auth("challenge not UTF-8"))?;
        params.push((key.to_string(), val));
    }
    Ok(Challenge { scheme: scheme.to_string(), params })
}

fn pct_encode(s: &str, out: &mut String) {
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(b"0123456789ABCDEF"[(b >> 4) as usize] as char);
            out.push(b"0123456789ABCDEF"[(b & 15) as usize] as char);
        }
    }
}

// ---------- sink ----------

/// Receives blob bytes as they are verified-in-flight. After an `Err(DigestMismatch)` from
/// [`Registry::pull_blob`] the sink has already seen the data and the caller must discard it.
pub trait Sink {
    fn write(&mut self, data: &[u8]) -> Result<()>;
}

impl Sink for Vec<u8> {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        self.extend_from_slice(data);
        Ok(())
    }
}

impl<F: FnMut(&[u8]) -> Result<()>> Sink for F {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        self(data)
    }
}

// ---------- client ----------

/// A resolved single-platform image.
#[derive(Clone, Debug)]
pub struct Image {
    /// Digest of the platform manifest.
    pub digest: Digest,
    pub manifest: ImageManifest,
    pub raw: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct RawManifest {
    pub digest: Digest,
    pub media_type: String,
    pub body: Vec<u8>,
}

pub struct Registry<C: Connector = TcpConnector> {
    http: Client<C>,
    /// Bearer tokens keyed by `registry/repository`.
    tokens: Vec<(String, String)>,
    plain_http: Vec<String>,
    tls_loopback: bool,
    os: String,
    arch: String,
}

impl Registry<TcpConnector> {
    pub fn new() -> Self {
        Self::with_client(Client::new())
    }
}

impl Default for Registry<TcpConnector> {
    fn default() -> Self {
        Self::new()
    }
}

fn is_loopback_host(hostport: &str) -> bool {
    let host = if let Some(r) = hostport.strip_prefix('[') {
        r.split(']').next().unwrap_or("")
    } else {
        hostport.rsplit_once(':').map_or(hostport, |(h, _)| h)
    };
    host.eq_ignore_ascii_case("localhost") || IpAddr::parse(host).is_some_and(|ip| ip.is_loopback())
}

impl<C: Connector> Registry<C> {
    pub fn with_client(http: Client<C>) -> Self {
        Registry { http, tokens: Vec::new(), plain_http: Vec::new(), tls_loopback: false, os: "linux".to_string(), arch: target_arch().to_string() }
    }

    /// Uses https for loopback registries too (e.g. a local registry with its own CA).
    pub fn tls_for_loopback(&mut self) {
        self.tls_loopback = true;
    }

    /// Allows plain HTTP for a non-loopback registry (`host[:port]`), like docker's insecure list.
    pub fn allow_plain_http(&mut self, registry: &str) {
        self.plain_http.push(registry.to_string());
    }

    /// Overrides the platform used to select from an index (default: linux/<target_arch>).
    pub fn set_platform(&mut self, os: &str, arch: &str) {
        self.os = os.to_string();
        self.arch = arch.to_string();
    }

    fn base(&self, r: &Reference) -> String {
        let plain = (is_loopback_host(&r.registry) && !self.tls_loopback) || self.plain_http.contains(&r.registry);
        format!("{}://{}", if plain { "http" } else { "https" }, r.endpoint())
    }

    async fn fetch_token(&mut self, r: &Reference, challenge: Option<String>) -> Result<String> {
        let ch = parse_challenge(&challenge.ok_or(Error::Auth("401 without WWW-Authenticate"))?)?;
        if !ch.scheme.eq_ignore_ascii_case("bearer") {
            return Err(Error::Auth("only Bearer authentication is supported"));
        }
        let realm = ch.param("realm").ok_or(Error::Auth("challenge without realm"))?;
        let mut url = realm.to_string();
        url.push(if realm.contains('?') { '&' } else { '?' });
        let mut first = true;
        if let Some(svc) = ch.param("service") {
            url.push_str("service=");
            pct_encode(svc, &mut url);
            first = false;
        }
        if !first {
            url.push('&');
        }
        url.push_str("scope=");
        match ch.param("scope") {
            Some(sc) => pct_encode(sc, &mut url),
            None => pct_encode(&format!("repository:{}:pull", r.repository), &mut url),
        }
        // Anonymous: no credentials are ever sent.
        let mut resp = self.http.get(&url, &[("Accept", "application/json")]).await?;
        if resp.status != 200 {
            return Err(Error::Auth("token endpoint refused anonymous access"));
        }
        let body = resp.read_to_end(MAX_TOKEN_BODY).await?;
        let v = json::parse(&body).map_err(|_| Error::Json("token response is not valid JSON"))?;
        let tok = v
            .get("token")
            .and_then(Value::as_str)
            .or_else(|| v.get("access_token").and_then(Value::as_str))
            .ok_or(Error::Json("token response without token"))?;
        if tok.is_empty() || !crate::http1::head::valid_field_value(tok.as_bytes()) {
            return Err(Error::Auth("unusable token"));
        }
        Ok(tok.to_string())
    }

    async fn get(&mut self, r: &Reference, path: &str, accept: Option<&str>) -> Result<Response<C::Conn>> {
        let url = format!("{}{}", self.base(r), path);
        let key = format!("{}/{}", r.registry, r.repository);
        for attempt in 0..2 {
            let bearer = self.tokens.iter().find(|(k, _)| *k == key).map(|(_, t)| format!("Bearer {t}"));
            let mut hdrs: Vec<(&str, &str)> = Vec::new();
            if let Some(a) = accept {
                hdrs.push(("Accept", a));
            }
            if let Some(b) = &bearer {
                hdrs.push(("Authorization", b));
            }
            let resp = self.http.get(&url, &hdrs).await?;
            match resp.status {
                200 => return Ok(resp),
                401 if attempt == 0 => {
                    let challenge = resp.header("www-authenticate").map(|s| s.to_string());
                    drop(resp);
                    let tok = self.fetch_token(r, challenge).await?;
                    self.tokens.retain(|(k, _)| *k != key);
                    self.tokens.push((key.clone(), tok));
                }
                401 => return Err(Error::Auth("token rejected")),
                s => return Err(Error::Status(s)),
            }
        }
        Err(Error::Auth("authentication failed"))
    }

    /// Checks `/v2/` (API version check); `Ok` if the registry speaks the v2 API.
    pub async fn ping(&mut self, r: &Reference) -> Result<()> {
        let url = format!("{}/v2/", self.base(r));
        let resp = self.http.get(&url, &[]).await?;
        match resp.status {
            200 | 401 => Ok(()),
            s => Err(Error::Status(s)),
        }
    }

    /// Fetches the manifest at `reference` (tag or digest), verifying its sha256.
    pub async fn fetch_manifest_raw(&mut self, r: &Reference, reference: &str) -> Result<RawManifest> {
        let path = format!("/v2/{}/manifests/{}", r.repository, reference);
        let mut resp = self.get(r, &path, Some(ACCEPT)).await?;
        let ct = resp.header("content-type").map(|s| s.to_string());
        let claimed = resp.header("docker-content-digest").map(|s| s.to_string());
        let body = resp.read_to_end(MAX_MANIFEST).await?;
        let digest = Digest::sha256_of(&body);
        if reference.starts_with("sha256:") && digest.as_str() != reference {
            return Err(Error::DigestMismatch);
        }
        if reference.contains(':') && !reference.starts_with("sha256:") {
            return Err(Error::UnsupportedDigest);
        }
        if let Some(c) = claimed.filter(|c| c.starts_with("sha256:")) {
            if c != digest.as_str() {
                return Err(Error::DigestMismatch);
            }
        }
        let media_type = match parse_manifest(&body, ct.as_deref())? {
            Manifest::Image(m) => m.media_type,
            Manifest::Index(_) => ct.map(|c| c.split(';').next().unwrap_or("").trim().to_string()).unwrap_or_else(|| MT_OCI_INDEX.to_string()),
        };
        Ok(RawManifest { digest, media_type, body })
    }

    /// Resolves a reference to a single-platform image manifest, descending through indexes.
    pub async fn resolve(&mut self, r: &Reference) -> Result<Image> {
        let mut reference = r.manifest_ref().to_string();
        for _ in 0..3 {
            let raw = self.fetch_manifest_raw(r, &reference).await?;
            match parse_manifest(&raw.body, Some(&raw.media_type))? {
                Manifest::Image(manifest) => return Ok(Image { digest: raw.digest, manifest, raw: raw.body }),
                Manifest::Index(entries) => {
                    let e = select_platform(&entries, &self.os, &self.arch)?;
                    reference = e.descriptor.digest.to_string();
                }
            }
        }
        Err(Error::Manifest("index nesting too deep"))
    }

    /// Streams a blob to `sink`, verifying size and sha256 on the way. Returns the byte count.
    pub async fn pull_blob<S: Sink>(&mut self, r: &Reference, desc: &Descriptor, sink: &mut S) -> Result<u64> {
        if !desc.digest.is_sha256() {
            return Err(Error::UnsupportedDigest);
        }
        let path = format!("/v2/{}/blobs/{}", r.repository, desc.digest);
        let mut resp = self.get(r, &path, None).await?;
        if resp.content_length().is_some_and(|n| n != desc.size) {
            return Err(Error::DigestMismatch);
        }
        let mut h = Sha256::new();
        let mut total: u64 = 0;
        let mut buf = alloc::vec![0u8; 32 * 1024];
        loop {
            let n = resp.read_chunk(&mut buf).await?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > desc.size {
                return Err(Error::DigestMismatch);
            }
            h.update(&buf[..n]);
            sink.write(&buf[..n])?;
        }
        let got = format!("sha256:{}", hex(&h.finalize()));
        if total != desc.size || got != desc.digest.as_str() {
            return Err(Error::DigestMismatch);
        }
        Ok(total)
    }

    /// Fetches and verifies the image config blob.
    pub async fn fetch_config(&mut self, r: &Reference, image: &Image) -> Result<Vec<u8>> {
        if image.manifest.config.size > MAX_CONFIG as u64 {
            return Err(Error::TooLarge("config"));
        }
        let mut v = Vec::new();
        self.pull_blob(r, &image.manifest.config, &mut v).await?;
        Ok(v)
    }
}

// Silence "unused" for the Transport bound used only through the Connector associated type.
#[allow(dead_code)]
fn _assert_transport<T: Transport>() {}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Reference {
        Reference::parse(s).unwrap()
    }
    const D: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn ref_vectors() {
        let r = p("docker.io/library/nginx:1.27");
        assert_eq!((r.registry.as_str(), r.repository.as_str(), r.tag.as_deref()), ("docker.io", "library/nginx", Some("1.27")));
        assert_eq!(r.endpoint(), "registry-1.docker.io");
        let r = p("nginx");
        assert_eq!((r.registry.as_str(), r.repository.as_str(), r.tag.as_deref()), ("docker.io", "library/nginx", Some("latest")));
        assert_eq!(p("nginx:alpine").tag.as_deref(), Some("alpine"));
        assert_eq!(p("busybox").to_string(), "docker.io/library/busybox:latest");
        let r = p("user/app");
        assert_eq!((r.registry.as_str(), r.repository.as_str()), ("docker.io", "user/app"));
        assert_eq!(p("index.docker.io/user/app").registry, "docker.io");
        let r = p(&format!("localhost:5000/foo@{D}"));
        assert_eq!((r.registry.as_str(), r.repository.as_str(), r.tag.clone()), ("localhost:5000", "foo", None));
        assert_eq!(r.digest.as_ref().unwrap().as_str(), D);
        assert_eq!(r.manifest_ref(), D);
        assert_eq!(r.endpoint(), "localhost:5000");
        let r = p("localhost/foo");
        assert_eq!((r.registry.as_str(), r.repository.as_str()), ("localhost", "foo"));
        let r = p("registry.k8s.io/pause:3.9");
        assert_eq!((r.registry.as_str(), r.repository.as_str(), r.tag.as_deref()), ("registry.k8s.io", "pause", Some("3.9")));
        assert_eq!(p("gcr.io/a/b/c:v1").repository, "a/b/c");
        let r = p("127.0.0.1:5000/a/b");
        assert_eq!(r.registry, "127.0.0.1:5000");
        let r = p(&format!("ghcr.io/o/r:t@{D}"));
        assert_eq!((r.tag.as_deref(), r.manifest_ref()), (Some("t"), D));
        assert_eq!(p("[::1]:5000/x").registry, "[::1]:5000");
        // host without dot/colon is a repository namespace
        assert_eq!(p("myorg/app").registry, "docker.io");
        // uppercase first component means registry (docker rule)
        assert_eq!(p("MyReg/app").registry, "MyReg");
        assert_eq!(p("a.b/c_d/e-f/g__h/i.j").repository, "c_d/e-f/g__h/i.j");
        // tag with port-like prefix
        let r = p("localhost:5000/foo:bar");
        assert_eq!((r.registry.as_str(), r.tag.as_deref()), ("localhost:5000", Some("bar")));
        assert_eq!(p("localhost:5000/foo").tag.as_deref(), Some("latest"));
    }

    #[test]
    fn ref_rejects() {
        for bad in [
            "", " nginx", "nginx ", "NGINX", "foo//bar", "foo/", "/foo", "foo:", "foo:-x", "foo:a b", "foo@sha256:abc",
            "foo@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg", "foo@md5", "-foo", "foo-", "foo..bar", "foo._bar",
            "foo___bar", "a/B/c", "localhost:5000/", "bad_host:x/y", "host.io:port/y", "docker.io/", "a/b:tag@",
        ] {
            assert!(Reference::parse(bad).is_err(), "{bad:?} should fail");
        }
        let long = "a".repeat(129);
        assert!(Reference::parse(&format!("x:{long}")).is_err());
        assert!(Reference::parse(&format!("x:{}", "a".repeat(128))).is_ok());
    }

    #[test]
    fn challenge() {
        let c = parse_challenge(r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull""#).unwrap();
        assert_eq!(c.scheme, "Bearer");
        assert_eq!(c.param("realm"), Some("https://auth.docker.io/token"));
        assert_eq!(c.param("SERVICE"), Some("registry.docker.io"));
        assert_eq!(c.param("scope"), Some("repository:library/nginx:pull"));
        let c = parse_challenge(r#"Bearer realm="http://x/t", error=invalid_token , error_description="a \"quoted, bit\"""#).unwrap();
        assert_eq!(c.param("error"), Some("invalid_token"));
        assert_eq!(c.param("error_description"), Some(r#"a "quoted, bit""#));
        assert_eq!(parse_challenge("Basic realm=\"x\"").unwrap().scheme, "Basic");
        assert_eq!(parse_challenge("Bearer").unwrap().params.len(), 0);
        assert!(parse_challenge(r#"Bearer realm="x"#).is_err());
        assert!(parse_challenge("Bearer realm").is_err());
        assert!(parse_challenge("Bearer =x").is_err());
        assert!(parse_challenge("").is_err());
    }

    #[test]
    fn manifests() {
        let img = format!(
            r#"{{"schemaVersion":2,"mediaType":"{MT_OCI_MANIFEST}","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{D}","size":10}},
            "layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{D}","size":20}}]}}"#
        );
        let Manifest::Image(m) = parse_manifest(img.as_bytes(), None).unwrap() else { panic!() };
        assert_eq!((m.config.size, m.layers.len(), m.layers[0].size), (10, 1, 20));
        // docker v2 detected from the content type when mediaType is absent
        let nomt = img.replace(&format!(r#""mediaType":"{MT_OCI_MANIFEST}","#), "");
        let Manifest::Image(m) = parse_manifest(nomt.as_bytes(), Some("application/vnd.docker.distribution.manifest.v2+json; charset=utf-8")).unwrap() else { panic!() };
        assert_eq!(m.media_type, MT_DOCKER_MANIFEST);

        let idx = format!(
            r#"{{"schemaVersion":2,"mediaType":"{MT_OCI_INDEX}","manifests":[
            {{"mediaType":"{MT_OCI_MANIFEST}","digest":"{D}","size":1,"platform":{{"architecture":"unknown","os":"unknown"}}}},
            {{"mediaType":"{MT_OCI_MANIFEST}","digest":"{D}","size":2,"platform":{{"architecture":"arm64","os":"linux","variant":"v8"}}}},
            {{"mediaType":"{MT_OCI_MANIFEST}","digest":"{D}","size":3,"platform":{{"architecture":"amd64","os":"linux"}}}},
            {{"mediaType":"{MT_OCI_MANIFEST}","digest":"{D}","size":4}}]}}"#
        );
        let Manifest::Index(e) = parse_manifest(idx.as_bytes(), None).unwrap() else { panic!() };
        assert_eq!(e.len(), 4);
        assert_eq!(select_platform(&e, "linux", "amd64").unwrap().descriptor.size, 3);
        assert_eq!(select_platform(&e, "linux", "arm64").unwrap().descriptor.size, 2);
        assert_eq!(select_platform(&e, "linux", "riscv64"), Err(Error::NoPlatform));
        assert_eq!(select_platform(&e, "windows", "amd64"), Err(Error::NoPlatform));
        let v7 = idx.replace(r#""variant":"v8""#, r#""variant":"v7""#);
        let Manifest::Index(e) = parse_manifest(v7.as_bytes(), None).unwrap() else { panic!() };
        assert_eq!(select_platform(&e, "linux", "arm64"), Err(Error::NoPlatform));

        for bad in [
            "{", "[]", r#"{"schemaVersion":1}"#, r#"{"schemaVersion":2}"#, r#"{"schemaVersion":2,"layers":[]}"#,
            r#"{"schemaVersion":2,"manifests":[{"digest":"x"}]}"#,
            &format!(r#"{{"schemaVersion":2,"mediaType":"{MT_OCI_INDEX}"}}"#),
            &format!(r#"{{"schemaVersion":2,"config":{{"mediaType":"a","digest":"{D}","size":-1}},"layers":[]}}"#),
        ] {
            assert!(parse_manifest(bad.as_bytes(), None).is_err(), "{bad}");
        }
    }

    #[test]
    fn loopback() {
        for h in ["localhost", "localhost:5000", "127.0.0.1:5000", "[::1]:5000", "127.1.2.3"] {
            assert!(is_loopback_host(h), "{h}");
        }
        for h in ["docker.io", "10.0.0.1:5000", "ghcr.io", "[2001:db8::1]:5000"] {
            assert!(!is_loopback_host(h), "{h}");
        }
    }

    #[test]
    fn encode() {
        let mut s = String::new();
        pct_encode("repository:library/nginx:pull", &mut s);
        assert_eq!(s, "repository%3Alibrary%2Fnginx%3Apull");
    }
}
