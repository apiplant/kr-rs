//! Multi-node plumbing for pod subresources:
//! - [`Router`]: the API server's [`NodeProxy`]. Pods on the server's own node go to the
//!   in-process kubelet; others are forwarded to that node's kubelet over mutual TLS
//!   (`https://<InternalIP>:10250/pods/<ns>/<pod>/<sub>?<query>`), authenticated with the
//!   `kube-apiserver-kubelet-client` certificate. WebSocket upgrades are completed with the
//!   client here (the accept key depends only on the client's key) and replayed to the node
//!   with the same key and subprotocol, after which raw frames are pumped both ways.
//! - [`serve`]: the agent-side kubelet HTTPS server answering those requests.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;
use core::future::{poll_fn, Future};
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use kr_apiserver::api::NodeProxy;
use kr_apiserver::object::ApiError;
use kr_crypto::tls::ClientConfig;
use kr_net::http1::server::{self, Body, Request, Response, ResponseStream};
use kr_net::http1::upgrade::Conn;
use kr_net::http1::{websocket, Transport};
use kr_net::tls::TlsStream;

pub const KUBELET_PORT: u16 = 10250;
const UPGRADE_PROTOCOLS: [&str; 5] = ["v5.channel.k8s.io", "v4.channel.k8s.io", "SPDY/3.1+portforward.k8s.io", "v2.portforward.k8s.io", "portforward.k8s.io"];

pub struct Router {
    pub local_node: String,
    pub local: Option<Rc<dyn NodeProxy>>,
    /// roots = cluster CA, client_cert = kube-apiserver-kubelet-client.
    pub tls: Rc<ClientConfig>,
}

fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

async fn connect(tls: Rc<ClientConfig>, ip: [u8; 4]) -> Option<TlsStream<kr_rt::exec::Async<kr_sys::Fd>>> {
    let sock = kr_net::tcp::connect_addr(kr_net::tcp::SocketAddr { ip: kr_net::tcp::IpAddr::V4(ip), port: KUBELET_PORT }, 5000).await.ok()?;
    let name = alloc::format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    kr_rt::exec::timeout(5000, TlsStream::connect(sock, tls, &name)).await.ok()?.ok()
}

/// Reads an HTTP response head; returns (status, chunked framing?, bytes after the head).
async fn read_head<T: Transport>(t: &mut T) -> Option<(u16, bool, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let status = core::str::from_utf8(buf.get(9..12)?).ok()?.parse().ok()?;
            let head = String::from_utf8_lossy(&buf[..i]).to_ascii_lowercase();
            let chunked = head.lines().any(|l| l.starts_with("transfer-encoding:") && l.contains("chunked"));
            return Some((status, chunked, buf[i + 4..].to_vec()));
        }
        if buf.len() > 16 * 1024 {
            return None;
        }
        let n = t.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// A body fed by a background task (keeps `ResponseStream` poll-based).
#[derive(Default)]
struct Pipe {
    chunks: VecDeque<Vec<u8>>,
    done: bool,
    waker: Option<Waker>,
}

struct PipeStream(Rc<RefCell<Pipe>>);

impl ResponseStream for PipeStream {
    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<Vec<u8>>> {
        let mut p = self.0.borrow_mut();
        if let Some(c) = p.chunks.pop_front() {
            return Poll::Ready(Some(c));
        }
        if p.done {
            return Poll::Ready(None);
        }
        p.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

fn push(p: &Rc<RefCell<Pipe>>, chunk: Option<Vec<u8>>) {
    let mut g = p.borrow_mut();
    match chunk {
        Some(c) => g.chunks.push_back(c),
        None => g.done = true,
    }
    if let Some(w) = g.waker.take() {
        w.wake();
    }
}

impl NodeProxy for Router {
    fn pod_subresource(&self, sub: &str, ns: &str, pod: &str, node: &str, node_ip: Option<[u8; 4]>, query: &str, headers: &[(String, String)]) -> Result<Response, ApiError> {
        if node == self.local_node {
            let l = self.local.as_ref().ok_or_else(|| ApiError::new(503, "ServiceUnavailable", "no local kubelet"))?;
            return l.pod_subresource(sub, ns, pod, node, node_ip, query, headers);
        }
        let ip = node_ip.ok_or_else(|| ApiError::new(503, "ServiceUnavailable", alloc::format!("node {node} has no InternalIP")))?;
        let target = if query.is_empty() { alloc::format!("/pods/{ns}/{pod}/{sub}") } else { alloc::format!("/pods/{ns}/{pod}/{sub}?{query}") };
        let tls = self.tls.clone();
        let upgrade = header(headers, "upgrade").is_some_and(|u| u.eq_ignore_ascii_case("websocket"));
        if !upgrade {
            // Plain (logs, logs -f): stream the node's response body through.
            let pipe = Rc::new(RefCell::new(Pipe::default()));
            let p = pipe.clone();
            kr_rt::exec::spawn(async move {
                let Some(mut t) = connect(tls, ip).await else {
                    push(&p, Some(b"error: cannot reach the node's kubelet\n".to_vec()));
                    return push(&p, None);
                };
                let req = alloc::format!("GET {target} HTTP/1.1\r\nHost: {}.{}.{}.{}\r\nConnection: close\r\n\r\n", ip[0], ip[1], ip[2], ip[3]);
                if t.write_all(req.as_bytes()).await.is_err() {
                    return push(&p, None);
                }
                // Simplified client: the kubelet answers with Connection: close bodies.
                let Some((_, is_chunked, rest)) = read_head(&mut t).await else { return push(&p, None) };
                let mut body = rest;
                let mut chunked = ChunkDecoder { plain: !is_chunked, ..ChunkDecoder::default() };
                let mut tmp = alloc::vec![0u8; 16384];
                loop {
                    let out = chunked.feed(&body);
                    if !out.is_empty() {
                        push(&p, Some(out));
                    }
                    if chunked.done {
                        break;
                    }
                    match t.read(&mut tmp).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => body = tmp[..n].to_vec(),
                    }
                }
                push(&p, None);
            });
            return Ok(Response { status: 200, headers: alloc::vec![("Content-Type".into(), "text/plain".into())], body: Body::Stream(Box::new(PipeStream(pipe))) });
        }
        let req = Request { method: "GET".into(), target: target.clone(), headers: headers.to_vec(), body: Vec::new(), peer: Default::default() };
        let hs = websocket::handshake(&req, &UPGRADE_PROTOCOLS).map_err(|_| ApiError::bad_request("invalid WebSocket upgrade"))?;
        let proto = hs.protocol.clone().ok_or_else(|| ApiError::bad_request("no supported streaming protocol"))?;
        let key = header(headers, "sec-websocket-key").unwrap_or("").to_string();
        let handler = move |conn: Box<dyn Conn>| -> Pin<Box<dyn Future<Output = ()>>> {
            Box::pin(async move {
                let Some(mut t) = connect(tls, ip).await else { return };
                let req = alloc::format!(
                    "GET {target} HTTP/1.1\r\nHost: {}.{}.{}.{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Protocol: {proto}\r\n\r\n",
                    ip[0], ip[1], ip[2], ip[3]
                );
                if t.write_all(req.as_bytes()).await.is_err() {
                    return;
                }
                let Some((101, _, rest)) = read_head(&mut t).await else { return };
                pump(conn, t, rest).await;
            })
        };
        Ok(hs.into_response(Box::new(handler)))
    }
}

/// Copies bytes both ways between the client connection and the node connection.
///
/// Each round races a client read against a node read and handles whichever finishes; the
/// losing read is dropped. That is safe because both reads are cancel-safe: `Conn::poll_read`
/// consumes nothing when pending, and `TlsStream::read` keeps undelivered plaintext and unsent
/// ciphertext inside the stream.
async fn pump(mut client: Box<dyn Conn>, mut node: TlsStream<kr_rt::exec::Async<kr_sys::Fd>>, initial: Vec<u8>) {
    enum Ev {
        Client(usize),
        Node(usize),
        End,
    }
    let mut cbuf = alloc::vec![0u8; 32 * 1024];
    let mut nbuf = alloc::vec![0u8; 32 * 1024];
    let mut to_client = initial;
    loop {
        if !to_client.is_empty() {
            let data = core::mem::take(&mut to_client);
            let ok = poll_fn(|cx| client.poll_write(cx, &data)).await.is_ok();
            if !ok || poll_fn(|cx| client.poll_flush(cx)).await.is_err() {
                return;
            }
        }
        let ev = {
            let nread = node.read(&mut nbuf);
            let mut nread = core::pin::pin!(nread);
            poll_fn(|cx| {
                if let Poll::Ready(r) = client.poll_read(cx, &mut cbuf) {
                    return Poll::Ready(match r {
                        Ok(k) if k > 0 => Ev::Client(k),
                        _ => Ev::End,
                    });
                }
                match nread.as_mut().poll(cx) {
                    Poll::Ready(Ok(k)) if k > 0 => Poll::Ready(Ev::Node(k)),
                    Poll::Ready(_) => Poll::Ready(Ev::End),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await
        };
        match ev {
            Ev::Client(k) => {
                if node.write_all(&cbuf[..k]).await.is_err() {
                    return;
                }
            }
            Ev::Node(k) => to_client = nbuf[..k].to_vec(),
            Ev::End => {
                let _ = poll_fn(|cx| client.poll_close(cx)).await;
                return;
            }
        }
    }
}

/// Minimal chunked-transfer decoder for the node's streaming log responses; `plain` bodies
/// (Content-Length / close-delimited) pass straight through.
#[derive(Default)]
struct ChunkDecoder {
    buf: Vec<u8>,
    remaining: usize,
    done: bool,
    plain: bool,
}

impl ChunkDecoder {
    fn feed(&mut self, data: &[u8]) -> Vec<u8> {
        if self.plain {
            return data.to_vec();
        }
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        loop {
            if self.remaining > 0 {
                let n = self.remaining.min(self.buf.len());
                out.extend_from_slice(&self.buf[..n]);
                self.buf.drain(..n);
                self.remaining -= n;
                if self.remaining > 0 {
                    return out;
                }
                // skip CRLF after the chunk
                if self.buf.len() < 2 {
                    self.remaining = 0;
                    return out;
                }
                self.buf.drain(..2);
            }
            let Some(i) = self.buf.windows(2).position(|w| w == b"\r\n") else { return out };
            let line = core::str::from_utf8(&self.buf[..i]).unwrap_or("").split(';').next().unwrap_or("").trim().to_string();
            let Ok(size) = usize::from_str_radix(&line, 16) else {
                self.done = true; // malformed chunk size: stop
                return out;
            };
            self.buf.drain(..i + 2);
            if size == 0 {
                self.done = true;
                return out;
            }
            self.remaining = size;
        }
    }
}

/// The agent's kubelet HTTPS endpoint (port 10250). Only the API server's kubelet-client
/// identity is accepted (client certificate from the cluster CA with that CN).
pub async fn serve(proxy: Rc<dyn NodeProxy>, node: String, tls: Rc<kr_crypto::tls::ServerConfig>) -> kr_net::Result<()> {
    let listener = server::listen([0, 0, 0, 0], KUBELET_PORT, 128)?;
    let cfg = Rc::new(server::ServerConfig { tls: Some(tls), idle_timeout_ms: 300_000, ..server::ServerConfig::default() });
    let handler = move |req: Request| -> server::HandlerFuture {
        let resp = (|| {
            let cn = req
                .peer
                .client_certs
                .as_ref()
                .and_then(|c| c.first())
                .and_then(|der| kr_crypto::x509::Certificate::parse(der).ok().and_then(|c| c.common_name().map(|n| n.to_vec())));
            if cn.as_deref() != Some(b"kube-apiserver-kubelet-client".as_slice()) {
                return Response::new(403, b"forbidden\n".to_vec());
            }
            let path = req.path().to_string();
            let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
            match parts.as_slice() {
                ["pods", ns, pod, sub] => match proxy.pod_subresource(sub, ns, pod, &node, None, req.query(), &req.headers) {
                    Ok(r) => r,
                    Err(e) => Response::new(e.code, e.to_status_json().into_bytes()).with_header("Content-Type", "application/json"),
                },
                ["healthz"] => Response::new(200, b"ok".to_vec()),
                _ => Response::new(404, b"not found\n".to_vec()),
            }
        })();
        Box::pin(async move { resp })
    };
    server::serve(listener, cfg, Rc::new(handler)).await
}
