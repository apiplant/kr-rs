//! The S3 client against an in-process fake server that checks every SigV4 signature, serves
//! path-style requests, paginates listings and implements multipart uploads.

use kr_net::registry::RegConnector;
use kr_net::s3::{authorization, Creds, S3Config, S3, MULTIPART_THRESHOLD, PART_SIZE};
use kr_net::sha256::{hex, sha256};
use kr_rt::exec::block_on;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

static LOCK: Mutex<()> = Mutex::new(());

const ACCESS: &str = "AKIATESTKEY";
const SECRET: &str = "test/secret+key";

#[derive(Default)]
struct State {
    objects: BTreeMap<String, Vec<u8>>,
    uploads: BTreeMap<String, BTreeMap<usize, Vec<u8>>>,
    log: Vec<String>,
    bad_signatures: usize,
}

fn read_request(s: &mut TcpStream) -> Option<(String, String, Vec<(String, String)>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).ok()? == 0 {
            return None;
        }
        buf.push(b[0]);
    }
    let head = String::from_utf8(buf).ok()?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, target) = (first.next()?.to_string(), first.next()?.to_string());
    let headers: Vec<(String, String)> = lines.filter_map(|l| l.split_once(": ")).map(|(a, b)| (a.to_ascii_lowercase(), b.to_string())).collect();
    let len: usize = headers.iter().find(|(n, _)| n == "content-length").and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).ok()?;
    Some((method, target, headers, body))
}

fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

fn respond(s: &mut TcpStream, status: &str, headers: &[(&str, String)], body: &str) {
    let mut r = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n", body.len());
    for (n, v) in headers {
        r.push_str(&format!("{n}: {v}\r\n"));
    }
    r.push_str("\r\n");
    r.push_str(body);
    let _ = s.write_all(r.as_bytes());
}

fn serve(listener: TcpListener, state: Arc<Mutex<State>>) {
    for conn in listener.incoming() {
        let Ok(mut s) = conn else { return };
        let state = state.clone();
        std::thread::spawn(move || {
            while let Some((method, target, headers, body)) = read_request(&mut s) {
                let h = |n: &str| headers.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone()).unwrap_or_default();
                let (path, query) = target.split_once('?').unwrap_or((&target, ""));
                // Verify the signature exactly as an S3 server would.
                let auth = h("authorization");
                let signed_names: Vec<&str> = auth.split("SignedHeaders=").nth(1).and_then(|r| r.split(',').next()).unwrap_or("").split(';').collect();
                let signed: Vec<(&str, String)> = signed_names.iter().map(|n| (*n, h(n))).collect();
                let signed_ref: Vec<(&str, &str)> = signed.iter().map(|(n, v)| (*n, v.as_str())).collect();
                let creds = Creds { access_key: ACCESS.into(), secret_key: SECRET.into(), session_token: None };
                let want = authorization(&method, path, query, &signed_ref, &h("x-amz-content-sha256"), "us-east-1", "s3", &creds, &h("x-amz-date"));
                let mut st = state.lock().unwrap();
                if want != auth || h("x-amz-content-sha256") != hex(&sha256(&body)) {
                    st.bad_signatures += 1;
                    respond(&mut s, "403 Forbidden", &[], "<Error><Code>SignatureDoesNotMatch</Code><Message>bad</Message></Error>");
                    continue;
                }
                st.log.push(format!("{method} {target}"));
                let key = decode(path.strip_prefix("/bucket/").unwrap_or(""));
                let q: BTreeMap<&str, &str> = query.split('&').filter(|p| !p.is_empty()).map(|p| p.split_once('=').unwrap_or((p, ""))).collect();
                match (method.as_str(), q.contains_key("uploads"), q.get("uploadId"), q.get("partNumber")) {
                    ("POST", true, _, _) => {
                        st.uploads.insert("U1".into(), BTreeMap::new());
                        respond(&mut s, "200 OK", &[], "<InitiateMultipartUploadResult><UploadId>U1</UploadId></InitiateMultipartUploadResult>");
                    }
                    ("PUT", _, Some(_), Some(n)) => {
                        let n: usize = n.parse().unwrap();
                        let etag = format!("\"etag{n}\"");
                        st.uploads.get_mut("U1").unwrap().insert(n, body);
                        respond(&mut s, "200 OK", &[("ETag", etag)], "");
                    }
                    ("POST", _, Some(_), _) => {
                        let xml = String::from_utf8(body).unwrap();
                        let parts = st.uploads.remove("U1").unwrap();
                        assert_eq!(xml.matches("<Part>").count(), parts.len());
                        assert!(xml.contains("<ETag>&quot;etag1&quot;</ETag>"), "{xml}");
                        let all: Vec<u8> = parts.into_values().flatten().collect();
                        st.objects.insert(key, all);
                        respond(&mut s, "200 OK", &[], "<CompleteMultipartUploadResult/>");
                    }
                    ("DELETE", _, Some(_), _) => {
                        st.uploads.clear();
                        respond(&mut s, "204 No Content", &[], "");
                    }
                    ("PUT", ..) => {
                        st.objects.insert(key, body);
                        respond(&mut s, "200 OK", &[], "");
                    }
                    ("GET", _, _, _) if q.get("list-type") == Some(&"2") => {
                        let prefix = decode(q["prefix"]);
                        let mut keys: Vec<&String> = st.objects.keys().filter(|k| k.starts_with(&prefix)).collect();
                        keys.sort();
                        // two keys per page
                        let start = q.get("continuation-token").map_or(0, |t| t.parse::<usize>().unwrap());
                        let page = &keys[start.min(keys.len())..(start + 2).min(keys.len())];
                        let mut xml = String::from("<ListBucketResult>");
                        let more = start + 2 < keys.len();
                        xml.push_str(&format!("<IsTruncated>{more}</IsTruncated>"));
                        if more {
                            xml.push_str(&format!("<NextContinuationToken>{}</NextContinuationToken>", start + 2));
                        }
                        for k in page {
                            xml.push_str(&format!("<Contents><Key>{k}</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified><Size>{}</Size></Contents>", st.objects[*k].len()));
                        }
                        xml.push_str("</ListBucketResult>");
                        respond(&mut s, "200 OK", &[], &xml);
                    }
                    ("GET", ..) => match st.objects.get(&key) {
                        Some(b) => {
                            let b = String::from_utf8_lossy(b).into_owned();
                            respond(&mut s, "200 OK", &[], &b);
                        }
                        None => respond(&mut s, "404 Not Found", &[], "<Error><Code>NoSuchKey</Code><Message>nope</Message></Error>"),
                    },
                    ("DELETE", ..) => {
                        st.objects.remove(&key);
                        respond(&mut s, "204 No Content", &[], "");
                    }
                    _ => respond(&mut s, "400 Bad Request", &[], ""),
                }
            }
        });
    }
}

fn setup() -> (Arc<Mutex<State>>, S3<RegConnector>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let state = Arc::new(Mutex::new(State::default()));
    let st = state.clone();
    std::thread::spawn(move || serve(l, st));
    let cfg = S3Config {
        endpoint: format!("127.0.0.1:{port}"),
        bucket: "bucket".into(),
        folder: "snaps/node a".into(),
        region: "us-east-1".into(),
        creds: Creds { access_key: ACCESS.into(), secret_key: SECRET.into(), session_token: None },
        insecure: true,
    };
    let c = RegConnector::new("", None, false).unwrap();
    (state, S3::new(c, cfg, || 1_700_000_000))
}

#[test]
fn put_list_get_prune() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (state, s3) = setup();
    block_on(async move {
        for t in 1..=5u32 {
            s3.put(&format!("kr-snapshot-{t:012}.tar"), format!("snapshot {t}").as_bytes()).await.unwrap();
        }
        s3.put("other.txt", b"x").await.unwrap();
        // an object in a "subfolder" must not be listed
        let l = s3.list("kr-snapshot-").await.unwrap();
        assert_eq!(l.len(), 5, "{l:?}");
        assert_eq!(l[0].name, "kr-snapshot-000000000001.tar");
        assert_eq!(l[4].size, "snapshot 5".len() as u64);
        assert_eq!(s3.get("kr-snapshot-000000000003.tar").await.unwrap(), b"snapshot 3");
        let gone = s3.prune("kr-snapshot-", ".tar", 2).await.unwrap();
        assert_eq!(gone, vec!["kr-snapshot-000000000001.tar", "kr-snapshot-000000000002.tar", "kr-snapshot-000000000003.tar"]);
        let left: Vec<String> = s3.list("kr-snapshot-").await.unwrap().into_iter().map(|o| o.name).collect();
        assert_eq!(left, vec!["kr-snapshot-000000000004.tar", "kr-snapshot-000000000005.tar"]);
        assert!(s3.get("kr-snapshot-000000000001.tar").await.unwrap_err().contains("NoSuchKey"));
        // the folder (with a space) was signed and stored percent-encoded
        assert!(state.lock().unwrap().objects.keys().all(|k| k.starts_with("snaps/node a/")), "{:?}", state.lock().unwrap().objects.keys().collect::<Vec<_>>());
        assert_eq!(state.lock().unwrap().bad_signatures, 0);
    });
}

#[test]
fn bad_credentials_are_reported() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (state, mut s3) = setup();
    let mut cfg = s3.config().clone();
    cfg.creds.secret_key = "wrong".into();
    s3 = S3::new(RegConnector::new("", None, false).unwrap(), cfg, || 1_700_000_000);
    block_on(async move {
        let e = s3.put("x", b"y").await.unwrap_err();
        assert!(e.contains("403") && e.contains("SignatureDoesNotMatch"), "{e}");
    });
    assert_eq!(state.lock().unwrap().bad_signatures, 1);
}

#[test]
fn big_objects_go_multipart() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (state, s3) = setup();
    let data: Vec<u8> = (0..MULTIPART_THRESHOLD + 1000).map(|i| (i % 251) as u8).collect();
    let expect = data.clone();
    block_on(async move {
        s3.put("big.tar", &data).await.unwrap();
    });
    let st = state.lock().unwrap();
    let stored = st.objects.values().next().expect("object stored");
    assert!(*stored == expect, "multipart reassembly differs");
    assert_eq!(st.bad_signatures, 0);
    let parts = (MULTIPART_THRESHOLD + 1000).div_ceil(PART_SIZE);
    assert_eq!(st.log.iter().filter(|l| l.contains("partNumber=")).count(), parts);
    assert!(st.log.iter().any(|l| l.starts_with("POST /bucket/snaps/node%20a/big.tar?uploads=")), "{:?}", st.log);
}

/// Against a real S3-compatible server (MinIO) when `KR_S3_TEST_ENDPOINT` (host:port, plain HTTP),
/// `KR_S3_TEST_BUCKET` (must exist), `KR_S3_ACCESS_KEY` and `KR_S3_SECRET_KEY` are set: a
/// multipart upload of 70 MiB, listing, download, prune and delete.
#[test]
fn real_server_multipart_roundtrip() {
    let (Ok(endpoint), Ok(bucket), Ok(access_key), Ok(secret_key)) = (std::env::var("KR_S3_TEST_ENDPOINT"), std::env::var("KR_S3_TEST_BUCKET"), std::env::var("KR_S3_ACCESS_KEY"), std::env::var("KR_S3_SECRET_KEY")) else {
        return;
    };
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let cfg = S3Config { endpoint, bucket, folder: "multipart-test".into(), region: "us-east-1".into(), creds: Creds { access_key, secret_key, session_token: None }, insecure: true };
    let s3 = S3::new(RegConnector::new("", None, false).unwrap(), cfg, || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64);
    let data: Vec<u8> = (0..(70usize << 20)).map(|i| (i.wrapping_mul(2654435761) >> 7) as u8).collect();
    block_on(async move {
        s3.put("kr-snapshot-000000000001.tar", &data).await.unwrap();
        s3.put("kr-snapshot-000000000002.tar", b"small").await.unwrap();
        let l = s3.list("kr-snapshot-").await.unwrap();
        assert_eq!(l.iter().map(|o| (o.name.as_str(), o.size)).collect::<Vec<_>>(), vec![("kr-snapshot-000000000001.tar", data.len() as u64), ("kr-snapshot-000000000002.tar", 5)]);
        assert!(s3.get("kr-snapshot-000000000001.tar").await.unwrap() == data, "downloaded object differs");
        assert_eq!(s3.prune("kr-snapshot-", ".tar", 1).await.unwrap(), vec!["kr-snapshot-000000000001.tar"]);
        s3.delete("kr-snapshot-000000000002.tar").await.unwrap();
        assert!(s3.list("kr-snapshot-").await.unwrap().is_empty());
    });
}
