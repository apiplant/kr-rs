//! Streaming pod subresources served by the node: `log`, `exec`, `attach`, `portforward`.
//!
//! - log: the container's log file (`tailLines`, `limitBytes`; `follow` streams new data
//!   until the container stops).
//! - exec: WebSocket (`v5.channel.k8s.io`/`v4`) with stdin/stdout/stderr over pipes to a
//!   process started inside the container (`container::exec_in`); the exit code is reported
//!   as a Status on channel 3. TTYs are not supported yet: `-t` runs without a terminal.
//! - attach: follows the container's output (stdin is not attachable: container stdio goes
//!   to the log file).
//! - portforward: SPDY/3.1 (what kubectl speaks), either tunneled in WebSocket binary messages
//!   (`SPDY/3.1+portforward.k8s.io`, kubectl >= 1.31) or after a plain `Upgrade: SPDY/3.1`, plus
//!   the WebSocket channel protocol (`v2.portforward.k8s.io`). Each forwarded connection is a
//!   relay process inside the pod's network namespace, joined to kr by a socketpair, so it works
//!   without a pod IP (rootless).

use crate::{Client, Kubelet};
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::future::{poll_fn, Future};
use core::pin::Pin;
use core::task::{Context, Poll};
use kr_apiserver::api::NodeProxy;
use kr_apiserver::object::ApiError;
use kr_net::http1::channel::{self, ClientMsg, PortForward, Protocol};
use kr_net::http1::server::{Body, PeerInfo, Request, Response, ResponseStream};
use kr_net::http1::upgrade::Conn;
use kr_net::http1::websocket::{self, Message, WebSocket, WsConfig};
use kr_net::spdy::{self, Event as SpdyEvent, Session};
use kr_rt::exec::{Async, Sleep};
use kr_runtime::container::{self, ExecSpec, ExecTarget};
use kr_sys::{ns, Fd};

/// The kubelet as the API server's node proxy.
pub struct Proxy<C: Client + Clone + 'static>(pub Rc<Kubelet<C>>);

struct Query<'a>(Vec<(&'a str, String)>);

impl<'a> Query<'a> {
    fn parse(q: &'a str) -> Query<'a> {
        let dec = |s: &str| -> String {
            let b = s.as_bytes();
            let mut out = Vec::new();
            let mut i = 0;
            while i < b.len() {
                if b[i] == b'%' && i + 2 < b.len() {
                    if let Ok(v) = u8::from_str_radix(core::str::from_utf8(&b[i + 1..i + 3]).unwrap_or(""), 16) {
                        out.push(v);
                        i += 3;
                        continue;
                    }
                }
                out.push(if b[i] == b'+' { b' ' } else { b[i] });
                i += 1;
            }
            String::from_utf8_lossy(&out).into_owned()
        };
        Query(q.split('&').filter(|p| !p.is_empty()).map(|p| p.split_once('=').map(|(k, v)| (k, dec(v))).unwrap_or((p, String::new()))).collect())
    }
    fn get(&self, k: &str) -> Option<&str> {
        self.0.iter().rev().find(|(x, _)| *x == k).map(|(_, v)| v.as_str())
    }
    fn all(&self, k: &str) -> Vec<String> {
        self.0.iter().filter(|(x, _)| *x == k).map(|(_, v)| v.clone()).collect()
    }
    fn flag(&self, k: &str) -> bool {
        matches!(self.get(k), Some("true" | "1"))
    }
}

/// What a request needs from the pod's runtime state.
struct PodView {
    dir: String,
    container: String,
    ctr_target: Option<ExecTarget>,
    pod_target: Option<ExecTarget>,
}

impl<C: Client + Clone + 'static> Proxy<C> {
    fn view(&self, ns: &str, pod: &str, container: Option<&str>) -> Result<PodView, ApiError> {
        let pods = self.0.pods.borrow();
        let p = pods.values().find(|p| p.ns == ns && p.name == pod).ok_or_else(|| ApiError::new(404, "NotFound", alloc::format!("pod {pod} is not running on this node")))?;
        let c = match container {
            Some(n) => p.ctrs.iter().find(|c| c.name == n).ok_or_else(|| ApiError::bad_request(alloc::format!("container {n} is not valid for pod {pod}")))?,
            None => p.ctrs.iter().find(|c| !c.init).ok_or_else(|| ApiError::bad_request("pod has no containers"))?,
        };
        Ok(PodView { dir: p.dir.clone(), container: c.name.clone(), ctr_target: c.target.clone(), pod_target: p.sandbox.as_ref().and_then(|s| s.target().ok()) })
    }

    fn container_running(&self, ns: &str, pod: &str, container: &str) -> bool {
        self.0.pods.borrow().values().any(|p| p.ns == ns && p.name == pod && p.ctrs.iter().any(|c| c.name == container && c.signaller.is_some()))
    }
}

fn ws_request(target: &str, headers: &[(String, String)]) -> Request {
    Request { method: "GET".into(), target: target.into(), headers: headers.to_vec(), body: Vec::new(), peer: PeerInfo::default() }
}

impl<C: Client + Clone + 'static> NodeProxy for Proxy<C> {
    fn pod_subresource(&self, sub: &str, ns: &str, pod: &str, _node: &str, _node_ip: Option<[u8; 4]>, query: &str, headers: &[(String, String)]) -> Result<Response, ApiError> {
        let q = Query::parse(query);
        let v = self.view(ns, pod, q.get("container"))?;
        match sub {
            "log" => self.logs(ns, pod, &v, &q),
            "exec" => {
                let target = v.ctr_target.clone().ok_or_else(|| ApiError::bad_request(alloc::format!("container {} is not running", v.container)))?;
                let argv: Vec<Vec<u8>> = q.all("command").into_iter().map(String::into_bytes).collect();
                if argv.is_empty() {
                    return Err(ApiError::bad_request("you must specify at least 1 command"));
                }
                let (stdin, stdout, stderr) = (q.flag("stdin"), q.get("stdout").is_none_or(|s| s != "false"), q.flag("stderr") || (!q.flag("tty") && q.get("stderr").is_none()));
                let maps = self.0.maps.clone();
                let hdr = |n: &str| headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(n)).flat_map(|(_, v)| v.split(',')).map(str::trim).collect::<Vec<_>>();
                if !hdr("upgrade").iter().any(|t| t.eq_ignore_ascii_case("websocket")) && hdr("upgrade").iter().any(|t| t.eq_ignore_ascii_case("SPDY/3.1")) {
                    // client-go remotecommand over SPDY (sonobuoy, older kubectl): v4 only.
                    if !hdr("x-stream-protocol-version").contains(&"v4.channel.k8s.io") {
                        return Err(ApiError::bad_request("SPDY exec requires X-Stream-Protocol-Version v4.channel.k8s.io"));
                    }
                    // client-go sends every enabled stream explicitly; absent means false.
                    let tty = q.flag("tty");
                    let want = (q.flag("stdin"), q.flag("stdout"), q.flag("stderr") && !tty, tty);
                    let handler = move |conn: Box<dyn Conn>| -> Pin<Box<dyn Future<Output = ()>>> { Box::pin(spdy_exec(PfIo::Raw { conn, wbuf: Vec::new() }, target, argv, maps, want)) };
                    return Ok(Response {
                        status: 101,
                        headers: alloc::vec![("Upgrade".into(), "SPDY/3.1".into()), ("X-Stream-Protocol-Version".into(), "v4.channel.k8s.io".into())],
                        body: Body::Upgrade(Box::new(handler)),
                    });
                }
                let hs = websocket::handshake(&ws_request("/exec", headers), &channel::EXEC_PROTOCOLS).map_err(|_| ApiError::bad_request("exec requires a WebSocket or SPDY/3.1 upgrade"))?;
                let proto = hs.protocol.as_deref().and_then(Protocol::from_token).ok_or_else(|| ApiError::bad_request("no supported streaming protocol"))?;
                let handler = move |conn: Box<dyn Conn>| -> Pin<Box<dyn Future<Output = ()>>> { Box::pin(exec_session(conn, proto, target, argv, maps, stdin, stdout, stderr)) };
                Ok(hs.into_response(Box::new(handler)))
            }
            "attach" => {
                let hs = websocket::handshake(&ws_request("/attach", headers), &channel::EXEC_PROTOCOLS).map_err(|_| ApiError::bad_request("attach requires a WebSocket upgrade"))?;
                let proto = hs.protocol.as_deref().and_then(Protocol::from_token).ok_or_else(|| ApiError::bad_request("no supported streaming protocol"))?;
                let path = alloc::format!("{}/{}.log", v.dir, v.container);
                let me = self.0.clone();
                let (ns, pod, ctr) = (ns.to_string(), pod.to_string(), v.container.clone());
                let handler = move |conn: Box<dyn Conn>| -> Pin<Box<dyn Future<Output = ()>>> {
                    Box::pin(attach_session(conn, proto, path, move || Proxy(me.clone()).container_running(&ns, &pod, &ctr)))
                };
                Ok(hs.into_response(Box::new(handler)))
            }
            "portforward" => {
                let target = v.pod_target.clone().ok_or_else(|| ApiError::bad_request("pod sandbox is not running"))?;
                let hdr = |n: &str| headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(n)).flat_map(|(_, v)| v.split(',')).map(str::trim).collect::<Vec<_>>();
                let ws = hdr("upgrade").iter().any(|t| t.eq_ignore_ascii_case("websocket"));
                if !ws && hdr("upgrade").iter().any(|t| t.eq_ignore_ascii_case("SPDY/3.1")) {
                    // Direct SPDY upgrade (kubectl before 1.31, or with websockets disabled).
                    let handler = move |conn: Box<dyn Conn>| -> Pin<Box<dyn Future<Output = ()>>> { Box::pin(spdy_portforward(PfIo::Raw { conn, wbuf: Vec::new() }, target)) };
                    return Ok(Response {
                        status: 101,
                        headers: alloc::vec![("Upgrade".into(), "SPDY/3.1".into()), ("X-Stream-Protocol-Version".into(), channel::PORTFORWARD_V1.into())],
                        body: Body::Upgrade(Box::new(handler)),
                    });
                }
                let protos = [channel::PORTFORWARD_SPDY_TUNNEL, channel::PORTFORWARD_V2, channel::PORTFORWARD_V1];
                let hs = websocket::handshake(&ws_request("/portforward", headers), &protos).map_err(|_| ApiError::bad_request("portforward requires a WebSocket or SPDY/3.1 upgrade"))?;
                if hs.protocol.as_deref() == Some(channel::PORTFORWARD_SPDY_TUNNEL) {
                    let handler = move |conn: Box<dyn Conn>| -> Pin<Box<dyn Future<Output = ()>>> {
                        Box::pin(spdy_portforward(PfIo::Ws(Box::new(WebSocket::new(conn, WsConfig::default()))), target))
                    };
                    return Ok(hs.into_response(Box::new(handler)));
                }
                let pf = PortForward::from_query(query).map_err(|_| ApiError::bad_request("invalid ports"))?;
                let handler = move |conn: Box<dyn Conn>| -> Pin<Box<dyn Future<Output = ()>>> { Box::pin(portforward_session(conn, pf, target)) };
                Ok(hs.into_response(Box::new(handler)))
            }
            _ => Err(ApiError::not_found("subresource", sub)),
        }
    }
}

impl<C: Client + Clone + 'static> Proxy<C> {
    fn logs(&self, ns: &str, pod: &str, v: &PodView, q: &Query) -> Result<Response, ApiError> {
        let path = alloc::format!("{}/{}.log\0", v.dir, v.container);
        let data = kr_sys::fs::read_file(path.as_bytes(), 64 << 20).unwrap_or_default();
        let mut start = 0;
        if let Some(n) = q.get("tailLines").and_then(|t| t.parse::<usize>().ok()) {
            // Last n lines (a trailing newline does not start a new line).
            let body = if data.ends_with(b"\n") { &data[..data.len() - 1] } else { &data[..] };
            let mut lines = 0;
            start = body.len();
            while start > 0 && lines < n {
                start -= 1;
                if body[start] == b'\n' {
                    lines += 1;
                    if lines == n {
                        start += 1;
                        break;
                    }
                }
            }
            if lines < n {
                start = 0;
            }
        }
        let mut out = data[start..].to_vec();
        if let Some(l) = q.get("limitBytes").and_then(|l| l.parse::<usize>().ok()) {
            out.truncate(l);
        }
        if !q.flag("follow") {
            return Ok(Response::new(200, out).with_header("Content-Type", "text/plain"));
        }
        let fd = ns::open(path.as_bytes(), ns::O_RDONLY, 0).map_err(|_| ApiError::not_found("log", &v.container))?;
        let me = self.0.clone();
        let (ns, pod, ctr) = (ns.to_string(), pod.to_string(), v.container.clone());
        let stream = Follow { fd, pos: data.len() as u64, first: Some(out), timer: None, running: Box::new(move || Proxy(me.clone()).container_running(&ns, &pod, &ctr)) };
        Ok(Response { status: 200, headers: alloc::vec![("Content-Type".into(), "text/plain".into())], body: Body::Stream(Box::new(stream)) })
    }
}

/// `logs -f`: polls the file for growth every 250 ms; ends once the container stopped and
/// everything was sent.
struct Follow {
    fd: Fd,
    pos: u64,
    first: Option<Vec<u8>>,
    timer: Option<Pin<Box<Sleep>>>,
    running: Box<dyn Fn() -> bool>,
}

impl Follow {
    fn read_new(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 16384];
        loop {
            match kr_sys::read(self.fd.raw(), &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    self.pos += n as u64;
                    if out.len() > 256 * 1024 {
                        break;
                    }
                }
            }
        }
        out
    }
}

impl ResponseStream for Follow {
    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<Vec<u8>>> {
        if let Some(f) = self.first.take() {
            // The initial content was read separately; skip to the end of what it covered.
            let mut skip = alloc::vec![0u8; self.pos as usize];
            let mut got = 0;
            while got < skip.len() {
                match kr_sys::read(self.fd.raw(), &mut skip[got..]) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got += n,
                }
            }
            if !f.is_empty() {
                return Poll::Ready(Some(f));
            }
        }
        loop {
            let t = self.timer.get_or_insert_with(|| Box::pin(kr_rt::exec::sleep(250)));
            if t.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.timer = None;
            let alive = (self.running)();
            let data = self.read_new();
            if !data.is_empty() {
                return Poll::Ready(Some(data));
            }
            if !alive {
                return Poll::Ready(None);
            }
        }
    }
}

/// Reads one chunk from a non-blocking pipe end; an empty result means EOF or error.
async fn read_chunk(fd: Rc<Async<Fd>>) -> Vec<u8> {
    let mut b = alloc::vec![0u8; 32 * 1024];
    match fd.read(&mut b).await {
        Ok(n) => {
            b.truncate(n);
            b
        }
        Err(_) => Vec::new(),
    }
}

type ChunkFut = Pin<Box<dyn Future<Output = Vec<u8>>>>;

fn pipe_pair() -> Option<(Fd, Rc<Async<Fd>>)> {
    // (child end, kr end): only kr's end is non-blocking.
    let (r, w) = kr_sys::pipe2(kr_sys::O_CLOEXEC).ok()?;
    ns::set_nonblocking(r.raw()).ok()?;
    Some((w, Rc::new(Async::new(r).ok()?)))
}

enum Ev {
    Ws(Result<Message, kr_net::Error>),
    Out(u8, Vec<u8>),
    Exit(i32),
}

#[allow(clippy::too_many_arguments)]
async fn exec_session(conn: Box<dyn Conn>, proto: Protocol, target: ExecTarget, argv: Vec<Vec<u8>>, maps: kr_runtime::container::IdMaps, want_stdin: bool, want_stdout: bool, want_stderr: bool) {
    let mut ws = WebSocket::new(conn, WsConfig::default());
    let fail = |msg: &str| channel::error_frame(&channel::status_failure(msg, "InternalError"));
    // stdin: blocking pipe; kr keeps the write end.
    let stdin_pipe = if want_stdin { kr_sys::pipe2(kr_sys::O_CLOEXEC).ok() } else { None };
    let (out_child, out_kr) = match want_stdout.then(pipe_pair).flatten() {
        Some((c, k)) => (Some(c), Some(k)),
        None => (None, None),
    };
    let (err_child, err_kr) = match want_stderr.then(pipe_pair).flatten() {
        Some((c, k)) => (Some(c), Some(k)),
        None => (None, None),
    };
    let env = [b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_vec(), b"TERM=xterm".to_vec()];
    let spec = ExecSpec {
        argv: &argv,
        env: &env,
        cwd: b"",
        user: b"",
        stdin: stdin_pipe.as_ref().map(|(r, _)| r.raw()),
        stdout: out_child.as_ref().map(|f| f.raw()),
        stderr: err_child.as_ref().map(|f| f.raw()),
        maps: &maps,
        extra_groups: &[],
    };
    let running = match container::exec_in(&target, &spec) {
        Ok(r) => r,
        Err(e) => {
            let _ = ws.send_binary(&fail(&alloc::format!("exec failed: {}: errno {}", e.step, e.errno.0))).await;
            let _ = ws.close(1000, "").await;
            return;
        }
    };
    // Close the child ends in kr so EOF arrives when the process exits.
    drop(out_child);
    drop(err_child);
    let mut stdin_w = stdin_pipe.map(|(r, w)| {
        drop(r);
        w
    });
    let sig = running.signaller();
    let mut exit_fut: Option<Pin<Box<dyn Future<Output = i32>>>> = Some(Box::pin(async move { running.wait().await.map(|e| e.code).unwrap_or(1) }));
    let mut out_fut: Option<ChunkFut> = out_kr.clone().map(|f| Box::pin(read_chunk(f)) as ChunkFut);
    let mut err_fut: Option<ChunkFut> = err_kr.clone().map(|f| Box::pin(read_chunk(f)) as ChunkFut);
    let mut exit: Option<i32> = None;
    loop {
        if exit.is_some() && out_fut.is_none() && err_fut.is_none() {
            let code = exit.unwrap();
            let status = if code == 0 { channel::status_success() } else { channel::status_exit(code) };
            let _ = ws.send_binary(&channel::error_frame(&status)).await;
            let _ = ws.close(1000, "").await;
            return;
        }
        let ev = poll_fn(|cx| {
            if let Poll::Ready(r) = ws.poll_recv(cx) {
                return Poll::Ready(Ev::Ws(r));
            }
            for (ch, f) in [(channel::STDOUT, &mut out_fut), (channel::STDERR, &mut err_fut)] {
                if let Some(fut) = f.as_mut() {
                    if let Poll::Ready(d) = fut.as_mut().poll(cx) {
                        *f = None;
                        return Poll::Ready(Ev::Out(ch, d));
                    }
                }
            }
            if let Some(fut) = exit_fut.as_mut() {
                if let Poll::Ready(c) = fut.as_mut().poll(cx) {
                    exit_fut = None;
                    return Poll::Ready(Ev::Exit(c));
                }
            }
            let _ = ws.poll_flush(cx);
            Poll::Pending
        })
        .await;
        match ev {
            Ev::Ws(Ok(Message::Binary(m))) => match channel::decode_client(proto, &m) {
                Ok(ClientMsg::Stdin(d)) => {
                    if let Some(w) = &stdin_w {
                        let mut off = 0;
                        while off < d.len() {
                            match kr_sys::write(w.raw(), &d[off..]) {
                                Ok(n) => off += n,
                                Err(_) => break,
                            }
                        }
                    }
                }
                Ok(ClientMsg::CloseStream(channel::STDIN)) => stdin_w = None,
                _ => {}
            },
            Ev::Ws(Ok(Message::Text(_))) => {}
            Ev::Ws(_) => {
                // Client went away: stop the process.
                let _ = sig.send(ns::SIGKILL);
                return;
            }
            Ev::Out(ch, data) => {
                if !data.is_empty() {
                    let _ = ws.queue_binary(&channel::encode(ch, &data));
                    let src = if ch == channel::STDOUT { out_kr.clone() } else { err_kr.clone() };
                    let next = src.map(|f| Box::pin(read_chunk(f)) as ChunkFut);
                    if ch == channel::STDOUT {
                        out_fut = next;
                    } else {
                        err_fut = next;
                    }
                }
            }
            Ev::Exit(c) => exit = Some(c),
        }
    }
}

async fn attach_session(conn: Box<dyn Conn>, proto: Protocol, path: String, running: impl Fn() -> bool + 'static) {
    let _ = proto;
    let mut ws = WebSocket::new(conn, WsConfig::default());
    let Ok(fd) = ns::open(alloc::format!("{path}\0").as_bytes(), ns::O_RDONLY, 0) else {
        let _ = ws.close(1011, "no log").await;
        return;
    };
    // Start at the end: attach shows new output only.
    let mut buf = [0u8; 16384];
    while matches!(kr_sys::read(fd.raw(), &mut buf), Ok(n) if n > 0) {}
    let mut f = Follow { fd, pos: 0, first: None, timer: None, running: Box::new(running) };
    loop {
        let next = poll_fn(|cx| {
            if let Poll::Ready(Ok(Message::Close { .. }) | Err(_)) = ws.poll_recv(cx) {
                return Poll::Ready(None);
            }
            let _ = ws.poll_flush(cx);
            f.poll_next(cx).map(Some)
        })
        .await;
        match next {
            Some(Some(d)) => {
                let _ = ws.queue_binary(&channel::stdout_frame(&d));
            }
            _ => {
                let _ = ws.send_binary(&channel::error_frame(&channel::status_success())).await;
                let _ = ws.close(1000, "").await;
                return;
            }
        }
    }
}

/// One forwarded connection: a relay process in the pod netns, bridged over a socketpair.
/// Dropping it kills the relay.
struct Relay {
    fd: Rc<Async<Fd>>,
    sig: container::Signaller,
    /// The relay's exit code: 1 = no socket, 2 = connect failed (it never reads then).
    exit: Option<kr_rt::exec::JoinHandle<i32>>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.sig.send(ns::SIGKILL);
    }
}

/// Starts the relay. EOF from kr half-closes the pod side (the reply direction keeps flowing);
/// the relay ends when the pod side closes.
fn open_relay(target: &ExecTarget, port: u16) -> Option<Relay> {
    let (ours, theirs) = ns::socketpair().ok()?;
    let theirs_raw = theirs.raw();
    let r = container::in_pod_net(target, move || {
        let Ok(sock) = kr_sys::socket(kr_sys::AF_INET, kr_sys::SOCK_STREAM | kr_sys::SOCK_CLOEXEC, 0) else { return 1 };
        if kr_sys::connect(sock.raw(), &kr_sys::SockaddrIn::new([127, 0, 0, 1], port)).is_err() {
            return 2;
        }
        // Copy both ways until the pod side closes.
        let mut buf = [0u8; 32 * 1024];
        let mut theirs_open = true;
        loop {
            let Ok((a, b, hup)) = ns::poll2(sock.raw(), if theirs_open { theirs_raw } else { -1 }, -1) else { return 3 };
            for (from, to, ready) in [(sock.raw(), theirs_raw, a), (theirs_raw, sock.raw(), b)] {
                if !ready {
                    continue;
                }
                match kr_sys::read(from, &mut buf) {
                    Ok(0) | Err(_) if from == theirs_raw => {
                        let _ = kr_sys::shutdown(sock.raw(), kr_sys::SHUT_WR);
                        theirs_open = false;
                    }
                    Ok(0) | Err(_) => return 0,
                    Ok(n) => {
                        let mut off = 0;
                        while off < n {
                            match kr_sys::write(to, &buf[off..n]) {
                                Ok(w) => off += w,
                                Err(_) => return 0,
                            }
                        }
                    }
                }
            }
            if hup && !a && !b {
                return 0;
            }
        }
    });
    let running = r.ok()?;
    drop(theirs);
    let sig = running.signaller();
    // Reap the relay whenever it ends.
    let exit = kr_rt::exec::spawn(async move { running.wait().await.map(|e| e.code).unwrap_or(1) });
    ns::set_nonblocking(ours.raw()).ok()?;
    Some(Relay { fd: Rc::new(Async::new(ours).ok()?), sig, exit: Some(exit) })
}

async fn portforward_session(conn: Box<dyn Conn>, mut pf: PortForward, target: ExecTarget) {
    let mut ws = WebSocket::new(conn, WsConfig::default());
    for f in pf.initial_frames() {
        let _ = ws.queue_binary(&f);
    }
    let _ = ws.flush().await;
    let ports: Vec<u16> = pf.ports.clone();
    let mut relays: Vec<Option<Relay>> = (0..ports.len()).map(|_| None).collect();
    let mut reads: Vec<Option<ChunkFut>> = (0..ports.len()).map(|_| None).collect();
    loop {
        let ev = poll_fn(|cx| {
            if let Poll::Ready(r) = ws.poll_recv(cx) {
                return Poll::Ready(Err(r));
            }
            for (i, f) in reads.iter_mut().enumerate() {
                if let Some(fut) = f.as_mut() {
                    if let Poll::Ready(d) = fut.as_mut().poll(cx) {
                        *f = None;
                        return Poll::Ready(Ok((i, d)));
                    }
                }
            }
            let _ = ws.poll_flush(cx);
            Poll::Pending
        })
        .await;
        match ev {
            Err(Ok(Message::Binary(m))) => {
                let Ok(Some((i, data))) = pf.client_data(&m) else { continue };
                if i >= ports.len() {
                    continue;
                }
                if relays[i].is_none() {
                    match open_relay(&target, ports[i]) {
                        Some(r) => {
                            reads[i] = Some(Box::pin(read_chunk(r.fd.clone())));
                            relays[i] = Some(r);
                        }
                        None => {
                            let msg = alloc::format!("error forwarding port {} to pod: connection failed", ports[i]);
                            let _ = ws.queue_binary(&channel::encode(pf.error_channel(i), msg.as_bytes()));
                            continue;
                        }
                    }
                }
                if let Some(r) = &relays[i] {
                    let _ = kr_net::tcp::write_all_nosignal(&r.fd, data).await;
                }
            }
            Err(Ok(_)) => {}
            Err(Err(_)) => return,
            Ok((i, d)) => {
                if d.is_empty() {
                    relays[i] = None; // connection closed; a new client stream reopens it
                } else {
                    let _ = ws.queue_binary(&channel::encode(pf.data_channel(i), &d));
                    reads[i] = relays[i].as_ref().map(|r| Box::pin(read_chunk(r.fd.clone())) as ChunkFut);
                }
            }
        }
    }
}

// ---------- SPDY/3.1 port-forward ----------

/// The byte stream under a SPDY session: WebSocket binary messages (KEP-4006 tunneling) or the
/// raw upgraded connection.
enum PfIo {
    Ws(Box<WebSocket<Box<dyn Conn>>>),
    Raw { conn: Box<dyn Conn>, wbuf: Vec<u8> },
}

impl PfIo {
    /// The next chunk of SPDY bytes; `None` once the peer is gone.
    fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<Option<Vec<u8>>> {
        match self {
            PfIo::Ws(ws) => loop {
                match ws.poll_recv(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(Message::Binary(b))) => return Poll::Ready(Some(b)),
                    Poll::Ready(Ok(Message::Text(_))) => {}
                    Poll::Ready(_) => return Poll::Ready(None),
                }
            },
            PfIo::Raw { conn, .. } => {
                let mut b = alloc::vec![0u8; 16 * 1024];
                match conn.poll_read(cx, &mut b) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Ok(n)) if n > 0 => {
                        b.truncate(n);
                        Poll::Ready(Some(b))
                    }
                    Poll::Ready(_) => Poll::Ready(None),
                }
            }
        }
    }

    /// Output is queued that the transport has not taken yet.
    fn backlogged(&self) -> bool {
        match self {
            PfIo::Ws(ws) => ws.has_pending_output(),
            PfIo::Raw { wbuf, .. } => !wbuf.is_empty(),
        }
    }

    fn queue(&mut self, bytes: &[u8]) {
        match self {
            PfIo::Ws(ws) => {
                let _ = ws.queue_binary(bytes);
            }
            PfIo::Raw { wbuf, .. } => wbuf.extend_from_slice(bytes),
        }
    }

    /// Ready once queued output reached the transport (or it failed).
    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        match self {
            PfIo::Ws(ws) => ws.poll_flush(cx).map(|_| ()),
            PfIo::Raw { conn, wbuf } => {
                if !wbuf.is_empty() {
                    match conn.poll_write(cx, wbuf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(_) => wbuf.clear(),
                    }
                }
                conn.poll_flush(cx).map(|_| ())
            }
        }
    }

    async fn finish(mut self) {
        let _ = poll_fn(|cx| self.poll_flush(cx)).await;
        match self {
            PfIo::Ws(mut ws) => {
                let _ = ws.close(1000, "").await;
            }
            PfIo::Raw { mut conn, .. } => {
                let _ = poll_fn(|cx| conn.poll_close(cx)).await;
            }
        }
    }
}

type WriteFut = Pin<Box<dyn Future<Output = (usize, bool)>>>;

/// One SPDY data stream and its relay.
struct Fwd {
    relay: Relay,
    /// Request id shared with the paired error stream.
    req: String,
    port: u16,
    read: Option<ChunkFut>,
    write: Option<WriteFut>,
    /// Client data waiting for the relay.
    wq: VecDeque<Vec<u8>>,
    /// The client finished sending and its half is closed towards the relay.
    client_fin: bool,
    shut: bool,
    /// The relay finished (EOF or failure); FINs went out.
    eof: bool,
    got_bytes: bool,
}

#[derive(Default)]
struct Pair {
    err: Option<u32>,
    data: Option<u32>,
}

enum PfEv {
    Io(Option<Vec<u8>>),
    Read(u32, Vec<u8>),
    Wrote(u32, usize, bool),
    /// Output drained: reads held back by a backlog may start again.
    Kick,
}

fn header_of<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

/// Server side of `kubectl port-forward`: for every connection the client opens an error
/// stream and a data stream (`streamtype`, `port`, `requestid` headers); the data stream is
/// bridged to a relay in the pod's netns, connect errors go to the error stream as text.
async fn spdy_portforward(mut io: PfIo, target: ExecTarget) {
    let mut sess = Session::new();
    // kubectl (moby/spdystream) ignores SPDY windows in both directions, so they cannot pace
    // anything: output backlog gates relay reads, queued relay writes gate reading the client.
    sess.set_flow_control_enforced(false);
    let mut pairs: BTreeMap<String, Pair> = BTreeMap::new();
    let mut fwds: BTreeMap<u32, Fwd> = BTreeMap::new();
    loop {
        // Sync pump: start reads/writes, half-close finished clients, drop dead streams.
        if sess.has_output() {
            io.queue(&sess.take_output());
        }
        let gated = io.backlogged();
        let queued_in: usize = fwds.values().map(|f| f.wq.iter().map(Vec::len).sum::<usize>()).sum();
        let read_io = queued_in < 1024 * 1024;
        fwds.retain(|id, _| sess.has_stream(*id));
        pairs.retain(|_, p| p.err.is_some_and(|e| sess.has_stream(e)) || p.data.is_some_and(|d| sess.has_stream(d)));
        for (id, f) in fwds.iter_mut() {
            if f.write.is_none() {
                if let Some(chunk) = f.wq.pop_front() {
                    let fd = f.relay.fd.clone();
                    f.write = Some(Box::pin(async move { (chunk.len(), kr_net::tcp::write_all_nosignal(&fd, &chunk).await.is_ok()) }));
                } else if f.client_fin && !f.shut {
                    f.shut = true;
                    let _ = kr_sys::shutdown(f.relay.fd.get_ref().raw(), kr_sys::SHUT_WR);
                }
            }
            if f.read.is_none() && !f.eof && !gated && sess.pending(*id) < 128 * 1024 {
                f.read = Some(Box::pin(read_chunk(f.relay.fd.clone())));
            }
        }
        if sess.is_closed() && fwds.is_empty() {
            break;
        }
        let ev = poll_fn(|cx| {
            if read_io {
                if let Poll::Ready(r) = io.poll_read(cx) {
                    return Poll::Ready(PfEv::Io(r));
                }
            }
            for (id, f) in fwds.iter_mut() {
                if let Some(w) = f.write.as_mut() {
                    if let Poll::Ready((n, ok)) = w.as_mut().poll(cx) {
                        f.write = None;
                        return Poll::Ready(PfEv::Wrote(*id, n, ok));
                    }
                }
                if let Some(r) = f.read.as_mut() {
                    if let Poll::Ready(d) = r.as_mut().poll(cx) {
                        f.read = None;
                        return Poll::Ready(PfEv::Read(*id, d));
                    }
                }
            }
            if io.poll_flush(cx).is_ready() && gated {
                return Poll::Ready(PfEv::Kick);
            }
            Poll::Pending
        })
        .await;
        match ev {
            PfEv::Kick => {}
            PfEv::Io(None) => break,
            PfEv::Io(Some(bytes)) => {
                if sess.feed(&bytes).is_err() {
                    io.queue(&sess.take_output());
                    break;
                }
                while let Some(e) = sess.poll_event() {
                    match e {
                        SpdyEvent::StreamOpened { id, headers, .. } => spdy_open(&mut sess, &mut pairs, &mut fwds, &target, id, &headers),
                        SpdyEvent::Data { id, bytes, fin } => match fwds.get_mut(&id) {
                            Some(f) => {
                                if !bytes.is_empty() {
                                    f.wq.push_back(bytes);
                                }
                                f.client_fin |= fin;
                            }
                            None => sess.consume(id, bytes.len()), // error stream: nothing to say
                        },
                        SpdyEvent::Reset { .. } => {} // pruned at the top of the loop
                        SpdyEvent::GoAway { .. } => {
                            io.queue(&sess.take_output());
                            io.finish().await;
                            return;
                        }
                    }
                }
            }
            PfEv::Wrote(id, n, ok) => {
                sess.consume(id, n);
                if !ok {
                    // The relay is gone; its read side reports EOF.
                    if let Some(f) = fwds.get_mut(&id) {
                        f.wq.clear();
                        f.client_fin = true;
                    }
                }
            }
            PfEv::Read(id, chunk) => {
                let Some(f) = fwds.get_mut(&id) else { continue };
                if !chunk.is_empty() {
                    f.got_bytes = true;
                    sess.data(id, &chunk, false);
                    continue;
                }
                f.eof = true;
                let (req, port, got) = (f.req.clone(), f.port, f.got_bytes);
                // A relay that never connected exits with 1 or 2: report it on the error stream.
                let mut failure = None;
                if !got {
                    if let Some(h) = f.relay.exit.take() {
                        if let Ok(Ok(code @ (1 | 2))) = kr_rt::exec::timeout(1000, h).await {
                            failure = Some(code);
                        }
                    }
                }
                let err = pairs.get(&req).and_then(|p| p.err);
                if let (Some(_), Some(e)) = (failure, err) {
                    let msg = alloc::format!("error forwarding port {port} to pod: connection refused or unreachable");
                    sess.data(e, msg.as_bytes(), true);
                } else if let Some(e) = err {
                    sess.data(e, b"", true);
                }
                sess.data(id, b"", true);
            }
        }
    }
    if sess.has_output() {
        io.queue(&sess.take_output());
    }
    io.finish().await;
}

/// Handles a `SYN_STREAM`: pairs error and data streams by `requestid`, starts the relay once
/// the data stream arrives.
fn spdy_open(sess: &mut Session, pairs: &mut BTreeMap<String, Pair>, fwds: &mut BTreeMap<u32, Fwd>, target: &ExecTarget, id: u32, headers: &[(String, String)]) {
    let port = header_of(headers, "port").and_then(|p| p.trim().parse::<u16>().ok()).filter(|p| *p != 0);
    let is_err = match header_of(headers, "streamtype") {
        Some("error") => true,
        Some("data") => false,
        _ => {
            sess.reset_with(id, spdy::status::PROTOCOL_ERROR);
            return;
        }
    };
    let Some(port) = port else {
        sess.reset_with(id, spdy::status::PROTOCOL_ERROR);
        return;
    };
    // Without a request id, clients open (error, data) back to back: ids 1,3 / 5,7 / ...
    let req = header_of(headers, "requestid").map(|r| r.trim().to_string()).unwrap_or_else(|| alloc::format!("auto{}", id.saturating_sub(1) / 4));
    sess.reply(id, &[]);
    let pair = pairs.entry(req.clone()).or_default();
    if is_err {
        pair.err = Some(id);
        return;
    }
    pair.data = Some(id);
    match open_relay(target, port) {
        Some(relay) => {
            fwds.insert(id, Fwd { relay, req, port, read: None, write: None, wq: VecDeque::new(), client_fin: false, shut: false, eof: false, got_bytes: false });
        }
        None => {
            if let Some(e) = pair.err {
                let msg = alloc::format!("error forwarding port {port} to pod: cannot start relay");
                sess.data(e, msg.as_bytes(), true);
            }
            sess.data(id, b"", true);
        }
    }
}

// ---------- SPDY/3.1 exec ----------

enum SxEv {
    Io(Option<Vec<u8>>),
    Out(u32, Vec<u8>),
    Exit(i32),
    Kick,
}

/// Server side of client-go's SPDY exec (`remotecommand` v4): the client opens `error`,
/// `stdin`, `stdout`, `stderr` and `resize` streams (`streamtype` header); the process starts
/// once all requested streams are open, its exit Status goes to the error stream as JSON.
async fn spdy_exec(mut io: PfIo, target: ExecTarget, argv: Vec<Vec<u8>>, maps: kr_runtime::container::IdMaps, want: (bool, bool, bool, bool)) {
    let (want_stdin, want_stdout, want_stderr, tty) = want;
    let mut sess = Session::new();
    sess.set_flow_control_enforced(false);
    let expected = 1 + want_stdin as usize + want_stdout as usize + want_stderr as usize;
    let (mut err_s, mut in_s, mut out_s, mut errout_s) = (None::<u32>, None::<u32>, None::<u32>, None::<u32>);
    let mut got = 0usize;
    // Phase 1: collect streams (bounded wait).
    let deadline = kr_rt::exec::now_ms() + 30_000;
    while got < expected {
        if sess.has_output() {
            io.queue(&sess.take_output());
        }
        let left = deadline.saturating_sub(kr_rt::exec::now_ms());
        if left == 0 {
            io.finish().await;
            return;
        }
        let r = kr_rt::exec::timeout(left, poll_fn(|cx| {
            let _ = io.poll_flush(cx);
            io.poll_read(cx)
        }))
        .await;
        let Ok(Some(bytes)) = r else {
            io.finish().await;
            return;
        };
        if sess.feed(&bytes).is_err() {
            io.queue(&sess.take_output());
            io.finish().await;
            return;
        }
        while let Some(e) = sess.poll_event() {
            if let SpdyEvent::StreamOpened { id, headers, .. } = e {
                sess.reply(id, &[]);
                let slot = match header_of(&headers, "streamtype") {
                    Some("error") => &mut err_s,
                    Some("stdin") => &mut in_s,
                    Some("stdout") => &mut out_s,
                    Some("stderr") => &mut errout_s,
                    Some("resize") => continue,
                    _ => {
                        sess.reset_with(id, spdy::status::PROTOCOL_ERROR);
                        continue;
                    }
                };
                if slot.is_none() {
                    *slot = Some(id);
                    got += 1;
                }
            }
        }
    }
    let _ = tty;
    let err_id = err_s.unwrap_or(0);
    let stdin_pipe = if in_s.is_some() { kr_sys::pipe2(kr_sys::O_CLOEXEC).ok() } else { None };
    let (out_child, out_kr) = match out_s.and_then(|_| pipe_pair()) {
        Some((c, k)) => (Some(c), Some(k)),
        None => (None, None),
    };
    let (err_child, err_kr) = match errout_s.and_then(|_| pipe_pair()) {
        Some((c, k)) => (Some(c), Some(k)),
        None => (None, None),
    };
    let env = [b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_vec(), b"TERM=xterm".to_vec()];
    let spec = ExecSpec {
        argv: &argv,
        env: &env,
        cwd: b"",
        user: b"",
        stdin: stdin_pipe.as_ref().map(|(r, _)| r.raw()),
        stdout: out_child.as_ref().map(|f| f.raw()),
        stderr: err_child.as_ref().map(|f| f.raw()),
        maps: &maps,
        extra_groups: &[],
    };
    let running = match container::exec_in(&target, &spec) {
        Ok(r) => r,
        Err(e) => {
            let st = channel::status_failure(&alloc::format!("exec failed: {}: errno {}", e.step, e.errno.0), "InternalError");
            sess.data(err_id, st.as_bytes(), true);
            io.queue(&sess.take_output());
            io.finish().await;
            return;
        }
    };
    drop(out_child);
    drop(err_child);
    let mut stdin_w = stdin_pipe.map(|(r, w)| {
        drop(r);
        w
    });
    let sig = running.signaller();
    let mut exit_fut: Option<Pin<Box<dyn Future<Output = i32>>>> = Some(Box::pin(async move { running.wait().await.map(|e| e.code).unwrap_or(1) }));
    let mut reads: Vec<(u32, Rc<Async<Fd>>, Option<ChunkFut>)> = Vec::new();
    if let (Some(id), Some(f)) = (out_s, out_kr) {
        reads.push((id, f.clone(), Some(Box::pin(read_chunk(f)))));
    }
    if let (Some(id), Some(f)) = (errout_s, err_kr) {
        reads.push((id, f.clone(), Some(Box::pin(read_chunk(f)))));
    }
    let mut exit: Option<i32> = None;
    loop {
        if sess.has_output() {
            io.queue(&sess.take_output());
        }
        if let Some(code) = exit.filter(|_| reads.iter().all(|r| r.2.is_none())) {
            let st = if code == 0 { channel::status_success() } else { channel::status_exit(code) };
            sess.data(err_id, st.as_bytes(), true);
            io.queue(&sess.take_output());
            io.finish().await;
            return;
        }
        let gated = io.backlogged();
        let ev = poll_fn(|cx| {
            if let Poll::Ready(r) = io.poll_read(cx) {
                return Poll::Ready(SxEv::Io(r));
            }
            if !gated {
                for (id, _, f) in reads.iter_mut() {
                    if let Some(fut) = f.as_mut() {
                        if let Poll::Ready(d) = fut.as_mut().poll(cx) {
                            *f = None;
                            return Poll::Ready(SxEv::Out(*id, d));
                        }
                    }
                }
            }
            if let Some(fut) = exit_fut.as_mut() {
                if let Poll::Ready(c) = fut.as_mut().poll(cx) {
                    exit_fut = None;
                    return Poll::Ready(SxEv::Exit(c));
                }
            }
            if io.poll_flush(cx).is_ready() && gated {
                return Poll::Ready(SxEv::Kick);
            }
            Poll::Pending
        })
        .await;
        match ev {
            SxEv::Kick => {}
            SxEv::Io(None) => {
                let _ = sig.send(ns::SIGKILL);
                return;
            }
            SxEv::Io(Some(bytes)) => {
                if sess.feed(&bytes).is_err() {
                    let _ = sig.send(ns::SIGKILL);
                    return;
                }
                while let Some(e) = sess.poll_event() {
                    match e {
                        SpdyEvent::Data { id, bytes, fin } => {
                            sess.consume(id, bytes.len());
                            if Some(id) == in_s {
                                if let Some(w) = &stdin_w {
                                    let mut off = 0;
                                    while off < bytes.len() {
                                        match kr_sys::write(w.raw(), &bytes[off..]) {
                                            Ok(n) => off += n,
                                            Err(_) => break,
                                        }
                                    }
                                }
                                if fin {
                                    stdin_w = None;
                                }
                            }
                        }
                        SpdyEvent::StreamOpened { id, .. } => sess.reply(id, &[]),
                        SpdyEvent::Reset { id, .. } if Some(id) == in_s => stdin_w = None,
                        SpdyEvent::Reset { .. } => {}
                        SpdyEvent::GoAway { .. } => {
                            let _ = sig.send(ns::SIGKILL);
                            return;
                        }
                    }
                }
            }
            SxEv::Out(id, d) => {
                let r = reads.iter_mut().find(|r| r.0 == id).unwrap();
                if d.is_empty() {
                    sess.data(id, b"", true);
                } else {
                    sess.data(id, &d, false);
                    r.2 = Some(Box::pin(read_chunk(r.1.clone())));
                }
            }
            SxEv::Exit(c) => exit = Some(c),
        }
    }
}
