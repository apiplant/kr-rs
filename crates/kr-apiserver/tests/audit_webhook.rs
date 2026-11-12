//! Audit webhook backend against a loopback receiver (a std thread speaking minimal HTTP/1.1).

use kr_apiserver::audit_webhook::{Config, Mode, Webhook};
use kr_rt::exec::{block_on, sleep};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::sync::Mutex;

static LOCK: Mutex<()> = Mutex::new(());

/// Answers each request with the next status in `codes` (the last repeats); sends the bodies out.
fn receiver(codes: Vec<u16>) -> (u16, mpsc::Receiver<(String, String)>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut n = 0;
        for s in l.incoming() {
            let mut s = s.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let (head, body) = loop {
                let k = s.read(&mut chunk).unwrap_or(0);
                if k == 0 {
                    break (String::new(), Vec::new());
                }
                buf.extend_from_slice(&chunk[..k]);
                if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..p]).to_string();
                    let want: usize = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap())).unwrap_or(0);
                    while buf.len() < p + 4 + want {
                        let k = s.read(&mut chunk).unwrap_or(0);
                        if k == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..k]);
                    }
                    break (head, buf[p + 4..].to_vec());
                }
            };
            if head.is_empty() {
                continue;
            }
            let code = codes[n.min(codes.len() - 1)];
            n += 1;
            let _ = s.write_all(format!("HTTP/1.1 {code} X\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}").as_bytes());
            let _ = tx.send((head, String::from_utf8_lossy(&body).to_string()));
        }
    });
    (port, rx)
}

fn config(port: u16, mode: Mode) -> Config {
    let kc = format!("clusters:\n- name: a\n  cluster:\n    server: http://127.0.0.1:{port}/audit\nusers:\n- name: u\n  user:\n    token: sekret\n");
    let mut c = Config::from_kubeconfig(&kc, &|_| Err("no".into())).unwrap();
    c.mode = mode;
    c.backoff_ms = 20;
    c
}

#[test]
fn batch_sends_an_event_list_when_full_without_blocking_the_caller() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (port, rx) = receiver(vec![200]);
    let mut c = config(port, Mode::Batch);
    c.max_size = 2;
    c.max_wait_ms = 60_000;
    block_on(async move {
        let w = Webhook::new(c);
        w.spawn_batcher();
        w.push(r#"{"auditID":"1"}"#);
        w.push(r#"{"auditID":"2"}"#);
        w.push(r#"{"auditID":"3"}"#);
        for _ in 0..200 {
            if w.queued() <= 1 {
                break;
            }
            sleep(10).await;
        }
        assert_eq!(w.queued(), 1, "the third event waits for the next batch");
    });
    let (head, body) = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
    assert!(head.starts_with("POST /audit "), "{head}");
    assert!(head.to_ascii_lowercase().contains("authorization: bearer sekret"), "{head}");
    let v = kr_fmt::json::parse_str(&body).unwrap();
    assert_eq!(v.get("kind").and_then(|k| k.as_str()), Some("EventList"));
    assert_eq!(v.get("items").and_then(|i| i.as_array()).unwrap().len(), 2);
}

#[test]
fn blocking_retries_then_succeeds_and_strict_reports_failure() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (port, rx) = receiver(vec![500, 200]);
    let c = config(port, Mode::Blocking);
    let ok = block_on(async move {
        let w = Webhook::new(c);
        w.push("{}");
        w.sync().await
    });
    assert!(ok);
    assert_eq!(rx.try_iter().count() + 0, 2, "one failed try and one retry");

    let (port, _rx) = receiver(vec![503]);
    let c = config(port, Mode::BlockingStrict);
    let ok = block_on(async move {
        let w = Webhook::new(c);
        w.push("{}");
        w.sync().await
    });
    assert!(!ok);
    assert!(kr_apiserver::audit_webhook::metrics().contains("kr_audit_webhook_dropped_events_total"));
}
