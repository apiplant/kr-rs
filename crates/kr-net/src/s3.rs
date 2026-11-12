//! A small S3 client for snapshot upload, listing, download and pruning (ADR-061).
//!
//! AWS Signature Version 4 over `kr-crypto` (HMAC-SHA256), path-style addressing for custom
//! endpoints (MinIO, Ceph, R2...) and virtual-hosted style for `*.amazonaws.com`. Bodies are
//! sent from memory with their SHA-256 in `x-amz-content-sha256` (works over plain HTTP too);
//! bodies above [`MULTIPART_THRESHOLD`] go as a multipart upload in [`PART_SIZE`] parts, so no
//! single request is larger than a part and objects beyond 5 GiB work.

use crate::http1::{Client, Config, Connector, Url};

use crate::sha256::{hex, sha256};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_crypto::hmac::hmac;
use kr_crypto::sha2::Sha256;

pub const MULTIPART_THRESHOLD: usize = 64 << 20;
pub const PART_SIZE: usize = 32 << 20;
/// Largest object `get` returns (a snapshot is read into memory, like `kr snapshot restore`).
pub const GET_LIMIT: usize = 1 << 31;

#[derive(Clone, Debug, Default)]
pub struct Creds {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
}

// ---- SigV4 ----

fn hmac256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hmac::<Sha256>(key, data, &mut out);
    out
}

/// The signing key for `date` (YYYYMMDD), `region` and `service`.
pub fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> [u8; 32] {
    let k = hmac256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k = hmac256(&k, region.as_bytes());
    let k = hmac256(&k, service.as_bytes());
    hmac256(&k, b"aws4_request")
}

/// Percent-encoding of SigV4: everything except `A-Za-z0-9-_.~` (and `/` when `keep_slash`).
pub fn uri_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') || (keep_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The `Authorization` header value. `headers` are all the headers to sign (names are
/// lowercased and sorted here, including `host`); `canonical_query` is already encoded and
/// sorted; `canonical_uri` is the encoded path.
#[allow(clippy::too_many_arguments)]
pub fn authorization(method: &str, canonical_uri: &str, canonical_query: &str, headers: &[(&str, &str)], payload_hash: &str, region: &str, service: &str, creds: &Creds, amz_date: &str) -> String {
    let mut hs: Vec<(String, String)> = headers.iter().map(|(n, v)| (n.to_ascii_lowercase(), v.split_whitespace().collect::<Vec<_>>().join(" "))).collect();
    hs.sort();
    let mut canonical_headers = String::new();
    for (n, v) in &hs {
        canonical_headers.push_str(&format!("{n}:{v}\n"));
    }
    let signed = hs.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(";");
    let creq = format!("{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed}\n{payload_hash}");
    let date = &amz_date[..8];
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let sts = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", hex(&sha256(creq.as_bytes())));
    let sig = hex(&hmac256(&signing_key(&creds.secret_key, date, region, service), sts.as_bytes()));
    format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={sig}", creds.access_key)
}

/// `YYYYMMDDTHHMMSSZ` for a Unix time.
pub fn amz_date(t: i64) -> String {
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    // civil from days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z", secs / 3600, secs % 3600 / 60, secs % 60)
}

// ---- configuration ----

#[derive(Clone, Debug, Default)]
pub struct S3Config {
    /// `host[:port]` or `http(s)://host[:port]`; empty means AWS (`s3.<region>.amazonaws.com`).
    pub endpoint: String,
    pub bucket: String,
    /// Prefix of the keys (no leading or trailing slash).
    pub folder: String,
    pub region: String,
    pub creds: Creds,
    /// Plain HTTP when the endpoint carries no scheme.
    pub insecure: bool,
}

impl S3Config {
    /// (scheme, authority, path-style) of the endpoint.
    fn target(&self) -> Result<(&'static str, String, bool), String> {
        let (scheme, host) = if let Some(h) = self.endpoint.strip_prefix("https://") {
            ("https", h)
        } else if let Some(h) = self.endpoint.strip_prefix("http://") {
            ("http", h)
        } else {
            (if self.insecure { "http" } else { "https" }, self.endpoint.as_str())
        };
        let host = host.trim_end_matches('/');
        if host.contains('/') {
            return Err(format!("S3 endpoint {:?} must not have a path", self.endpoint));
        }
        if host.is_empty() {
            return Ok((scheme, format!("{}.s3.{}.amazonaws.com", self.bucket, self.region), false));
        }
        let hostname = host.rsplit_once(':').filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit())).map_or(host, |(h, _)| h);
        let aws = hostname.ends_with(".amazonaws.com") || hostname == "s3.amazonaws.com";
        if aws {
            Ok((scheme, format!("{}.{host}", self.bucket), false))
        } else {
            Ok((scheme, host.to_string(), true))
        }
    }

    fn key(&self, name: &str) -> String {
        if self.folder.is_empty() {
            name.to_string()
        } else {
            format!("{}/{name}", self.folder)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    /// Key without the folder prefix.
    pub name: String,
    pub size: u64,
    /// ISO 8601 as the server returned it.
    pub last_modified: String,
}

pub struct S3<C: Connector> {
    client: Client<C>,
    cfg: S3Config,
    now: fn() -> i64,
}

type R<T> = Result<T, String>;

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

/// Text of the first `<tag>..</tag>` in `s` and the remainder after it.
fn xml_tag<'a>(s: &'a str, tag: &str) -> Option<(&'a str, &'a str)> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let a = s.find(&open)? + open.len();
    let b = a + s[a..].find(&close)?;
    Some((&s[a..b], &s[b + close.len()..]))
}

/// The objects of a ListObjectsV2 page, whether it is truncated, and the continuation token.
pub fn parse_list(xml: &str) -> (Vec<(String, u64, String)>, bool, Option<String>) {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some((c, after)) = xml_tag(rest, "Contents") {
        if let Some((k, _)) = xml_tag(c, "Key") {
            let size = xml_tag(c, "Size").and_then(|(s, _)| s.trim().parse().ok()).unwrap_or(0);
            let lm = xml_tag(c, "LastModified").map(|(s, _)| s.to_string()).unwrap_or_default();
            out.push((xml_unescape(k), size, lm));
        }
        rest = after;
    }
    let truncated = xml_tag(xml, "IsTruncated").is_some_and(|(t, _)| t.trim() == "true");
    let token = xml_tag(xml, "NextContinuationToken").map(|(t, _)| xml_unescape(t));
    (out, truncated, token)
}

/// The error text of an S3 error document, if it is one.
fn s3_error(body: &[u8]) -> Option<String> {
    let s = core::str::from_utf8(body).ok()?;
    if !s.contains("<Error>") {
        return None;
    }
    let code = xml_tag(s, "Code").map(|(c, _)| c).unwrap_or("?");
    let msg = xml_tag(s, "Message").map(|(m, _)| xml_unescape(m)).unwrap_or_default();
    Some(format!("{code}: {msg}"))
}

/// Names (oldest first) to delete so that only the newest `keep` remain; the names sort by
/// time (`kr-snapshot-<zero padded unix time>.tar`).
pub fn expired(mut names: Vec<String>, keep: usize) -> Vec<String> {
    names.sort();
    let n = names.len().saturating_sub(keep);
    names.truncate(n);
    names
}

impl<C: Connector> S3<C> {
    pub fn new(connector: C, cfg: S3Config, now: fn() -> i64) -> S3<C> {
        let hcfg = Config { head_timeout_ms: 600_000, read_timeout_ms: 120_000, user_agent: "kr-s3/1".to_string(), max_redirects: 0, ..Config::default() };
        S3 { client: Client::with_connector(connector, hcfg), cfg, now }
    }

    pub fn config(&self) -> &S3Config {
        &self.cfg
    }

    /// One signed request; returns the status, response headers and body (at most `limit` bytes).
    async fn call(&self, method: &str, key: &str, query: &mut Vec<(String, String)>, body: &[u8], limit: usize) -> R<(u16, Vec<(String, String)>, Vec<u8>)> {
        let (scheme, authority, path_style) = self.cfg.target()?;
        let path = if path_style { format!("/{}/{}", self.cfg.bucket, key) } else { format!("/{key}") };
        let canonical_uri = uri_encode(&path, true);
        query.sort();
        let canonical_query = query.iter().map(|(k, v)| format!("{}={}", uri_encode(k, false), uri_encode(v, false))).collect::<Vec<_>>().join("&");
        let url_str = format!("{scheme}://{authority}{canonical_uri}{}{canonical_query}", if canonical_query.is_empty() { "" } else { "?" });
        let host = Url::parse(&url_str).map_err(|e| format!("S3 endpoint: {e:?}"))?.host_header();
        let date = amz_date((self.now)());
        let payload = hex(&sha256(body));
        let mut signed: Vec<(&str, &str)> = alloc::vec![("host", &host), ("x-amz-content-sha256", &payload), ("x-amz-date", &date)];
        if let Some(t) = &self.cfg.creds.session_token {
            signed.push(("x-amz-security-token", t));
        }
        let auth = authorization(method, &canonical_uri, &canonical_query, &signed, &payload, &self.cfg.region, "s3", &self.cfg.creds, &date);
        let mut headers: Vec<(&str, &str)> = signed.iter().filter(|(n, _)| *n != "host").copied().collect();
        headers.push(("authorization", &auth));
        let mut resp = self.client.request(method, &url_str, &headers, body).await.map_err(|e| format!("S3 {method} request failed: {e:?}"))?;
        let status = resp.status;
        let hdrs = resp.headers().to_vec();
        let ok = (200..300).contains(&status);
        let data = resp.read_to_end(if ok { limit } else { 64 << 10 }).await.map_err(|e| format!("S3 {method} response failed: {e:?}"))?;
        if !ok {
            let detail = s3_error(&data).unwrap_or_else(|| String::from_utf8_lossy(&data[..data.len().min(200)]).into_owned());
            return Err(format!("S3 {method} {path}: HTTP {status} {detail}"));
        }
        Ok((status, hdrs, data))
    }

    /// Uploads `data` as `<folder>/<name>`.
    pub async fn put(&self, name: &str, data: &[u8]) -> R<()> {
        let key = self.cfg.key(name);
        if data.len() <= MULTIPART_THRESHOLD {
            self.call("PUT", &key, &mut Vec::new(), data, 0).await?;
            return Ok(());
        }
        let (_, _, body) = self.call("POST", &key, &mut alloc::vec![("uploads".to_string(), String::new())], &[], 1 << 20).await?;
        let body = String::from_utf8_lossy(&body).into_owned();
        let upload_id = xml_tag(&body, "UploadId").map(|(u, _)| xml_unescape(u)).ok_or("S3: no UploadId in the response")?;
        let r = self.upload_parts(&key, &upload_id, data).await;
        if r.is_err() {
            let _ = self.call("DELETE", &key, &mut alloc::vec![("uploadId".to_string(), upload_id)], &[], 1 << 20).await;
        }
        r
    }

    async fn upload_parts(&self, key: &str, upload_id: &str, data: &[u8]) -> R<()> {
        let mut etags = Vec::new();
        for (i, part) in data.chunks(PART_SIZE).enumerate() {
            let n = i + 1;
            let q = &mut alloc::vec![("partNumber".to_string(), n.to_string()), ("uploadId".to_string(), upload_id.to_string())];
            let (_, h, _) = self.call("PUT", key, q, part, 0).await?;
            let etag = h.iter().find(|(k, _)| k.eq_ignore_ascii_case("etag")).map(|(_, v)| v.clone()).ok_or("S3: part upload without ETag")?;
            etags.push((n, etag));
        }
        let mut xml = String::from("<CompleteMultipartUpload>");
        for (n, e) in &etags {
            xml.push_str(&format!("<Part><PartNumber>{n}</PartNumber><ETag>{}</ETag></Part>", e.replace('"', "&quot;")));
        }
        xml.push_str("</CompleteMultipartUpload>");
        let q = &mut alloc::vec![("uploadId".to_string(), upload_id.to_string())];
        let (_, _, body) = self.call("POST", key, q, xml.as_bytes(), 1 << 20).await?;
        // Complete can answer 200 with an error document.
        match s3_error(&body) {
            Some(e) => Err(format!("S3 CompleteMultipartUpload: {e}")),
            None => Ok(()),
        }
    }

    pub async fn get(&self, name: &str) -> R<Vec<u8>> {
        Ok(self.call("GET", &self.cfg.key(name), &mut Vec::new(), &[], GET_LIMIT).await?.2)
    }

    pub async fn delete(&self, name: &str) -> R<()> {
        self.call("DELETE", &self.cfg.key(name), &mut Vec::new(), &[], 0).await?;
        Ok(())
    }

    /// Objects directly under the folder whose name starts with `prefix`, sorted by name.
    pub async fn list(&self, prefix: &str) -> R<Vec<Object>> {
        let full = if self.cfg.folder.is_empty() { prefix.to_string() } else { format!("{}/{prefix}", self.cfg.folder) };
        let strip = if self.cfg.folder.is_empty() { 0 } else { self.cfg.folder.len() + 1 };
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        for _ in 0..10_000 {
            let mut q = alloc::vec![("list-type".to_string(), "2".to_string()), ("prefix".to_string(), full.clone())];
            if let Some(t) = &token {
                q.push(("continuation-token".to_string(), t.clone()));
            }
            let (_, _, body) = self.call("GET", "", &mut q, &[], 16 << 20).await?;
            let (items, truncated, next) = parse_list(&String::from_utf8_lossy(&body));
            for (k, size, lm) in items {
                if let Some(name) = k.get(strip..) {
                    if !name.contains('/') && !name.is_empty() {
                        out.push(Object { name: name.to_string(), size, last_modified: lm });
                    }
                }
            }
            match (truncated, next) {
                (true, Some(t)) => token = Some(t),
                _ => break,
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Deletes all but the newest `keep` objects named `<prefix>*<suffix>`; returns the names removed.
    pub async fn prune(&self, prefix: &str, suffix: &str, keep: usize) -> R<Vec<String>> {
        let names: Vec<String> = self.list(prefix).await?.into_iter().map(|o| o.name).filter(|n| n.ends_with(suffix)).collect();
        let old = expired(names, keep);
        for n in &old {
            self.delete(n).await?;
        }
        Ok(old)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AKID: &str = "AKIDEXAMPLE";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn s3_docs_creds() -> Creds {
        Creds { access_key: "AKIAIOSFODNN7EXAMPLE".into(), secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(), session_token: None }
    }

    #[test]
    fn signing_key_vector_from_the_aws_docs() {
        // "Examples of how to derive a signing key" (IAM, 20150830).
        let k = signing_key("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830", "us-east-1", "iam");
        assert_eq!(hex(&k), "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9");
    }

    #[test]
    fn aws_sigv4_test_suite_get_vanilla() {
        let creds = Creds { access_key: AKID.into(), secret_key: SECRET.into(), session_token: None };
        let a = authorization("GET", "/", "", &[("host", "example.amazonaws.com"), ("x-amz-date", "20150830T123600Z")], EMPTY, "us-east-1", "service", &creds, "20150830T123600Z");
        assert_eq!(a, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
    }

    // The four examples of "Signature Calculations for the Authorization Header" (S3 docs).
    #[test]
    fn s3_docs_get_object_with_range() {
        let a = authorization(
            "GET",
            "/test.txt",
            "",
            &[("host", "examplebucket.s3.amazonaws.com"), ("range", "bytes=0-9"), ("x-amz-content-sha256", EMPTY), ("x-amz-date", "20130524T000000Z")],
            EMPTY,
            "us-east-1",
            "s3",
            &s3_docs_creds(),
            "20130524T000000Z",
        );
        assert!(a.ends_with("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"), "{a}");
    }

    #[test]
    fn s3_docs_put_object() {
        let body = b"Welcome to Amazon S3.";
        let hash = hex(&sha256(body));
        assert_eq!(hash, "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072");
        let a = authorization(
            "PUT",
            &uri_encode("/test$file.text", true),
            "",
            &[
                ("date", "Fri, 24 May 2013 00:00:00 GMT"),
                ("host", "examplebucket.s3.amazonaws.com"),
                ("x-amz-date", "20130524T000000Z"),
                ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
                ("x-amz-content-sha256", &hash),
            ],
            &hash,
            "us-east-1",
            "s3",
            &s3_docs_creds(),
            "20130524T000000Z",
        );
        assert!(a.ends_with("SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"), "{a}");
    }

    #[test]
    fn s3_docs_get_bucket_lifecycle_and_list_objects() {
        let hs = [("host", "examplebucket.s3.amazonaws.com"), ("x-amz-content-sha256", EMPTY), ("x-amz-date", "20130524T000000Z")];
        let a = authorization("GET", "/", "lifecycle=", &hs, EMPTY, "us-east-1", "s3", &s3_docs_creds(), "20130524T000000Z");
        assert!(a.ends_with("Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"), "{a}");
        let a = authorization("GET", "/", "max-keys=2&prefix=J", &hs, EMPTY, "us-east-1", "s3", &s3_docs_creds(), "20130524T000000Z");
        assert!(a.ends_with("Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"), "{a}");
    }

    #[test]
    fn encoding_and_dates() {
        assert_eq!(uri_encode("/a b/c$d~e-f_g.h", true), "/a%20b/c%24d~e-f_g.h");
        assert_eq!(uri_encode("a/b+c=d", false), "a%2Fb%2Bc%3Dd");
        assert_eq!(amz_date(0), "19700101T000000Z");
        assert_eq!(amz_date(1_369_353_600), "20130524T000000Z");
        assert_eq!(amz_date(1_456_704_000 + 86399), "20160229T235959Z");
        assert_eq!(amz_date(4_102_444_800), "21000101T000000Z");
    }

    #[test]
    fn endpoints() {
        let c = |endpoint: &str, insecure: bool| S3Config { endpoint: endpoint.into(), bucket: "b".into(), region: "eu-west-1".into(), insecure, ..Default::default() };
        assert_eq!(c("", false).target().unwrap(), ("https", "b.s3.eu-west-1.amazonaws.com".to_string(), false));
        assert_eq!(c("s3.amazonaws.com", false).target().unwrap(), ("https", "b.s3.amazonaws.com".to_string(), false));
        assert_eq!(c("minio.local:9000", true).target().unwrap(), ("http", "minio.local:9000".to_string(), true));
        assert_eq!(c("http://10.0.0.1:9000/", false).target().unwrap(), ("http", "10.0.0.1:9000".to_string(), true));
        assert_eq!(c("https://s3.example.com", true).target().unwrap(), ("https", "s3.example.com".to_string(), true));
        assert!(c("host/path", false).target().is_err());
    }

    #[test]
    fn list_parsing_and_retention() {
        let xml = "<ListBucketResult><IsTruncated>true</IsTruncated><Contents><Key>f/kr-snapshot-000000000002.tar</Key><LastModified>2026-01-02T00:00:00.000Z</LastModified><Size>12</Size></Contents><Contents><Key>f/a&amp;b</Key><Size>3</Size></Contents><NextContinuationToken>tok&amp;1</NextContinuationToken></ListBucketResult>";
        let (items, trunc, tok) = parse_list(xml);
        assert_eq!(items, alloc::vec![("f/kr-snapshot-000000000002.tar".to_string(), 12, "2026-01-02T00:00:00.000Z".to_string()), ("f/a&b".to_string(), 3, String::new())]);
        assert!(trunc);
        assert_eq!(tok.as_deref(), Some("tok&1"));
        let n = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(expired(n(&["c", "a", "d", "b"]), 2), n(&["a", "b"]));
        assert!(expired(n(&["a"]), 5).is_empty());
        assert_eq!(s3_error(b"<Error><Code>NoSuchKey</Code><Message>gone &amp; lost</Message></Error>").unwrap(), "NoSuchKey: gone & lost");
        assert!(s3_error(b"<CompleteMultipartUploadResult/>").is_none());
    }
}
