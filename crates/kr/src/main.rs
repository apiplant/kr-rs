#![no_std]
#![no_main]

extern crate alloc;

use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::Cell;
use kr_rt::exec::{self, spawn, sleep, timeout, Async};
use kr_rt::{eprint, fmt_u64, print, Args};
use kr_sys::{self as sys, Fd};

const MAX_REQ: usize = 16 * 1024;
const IO_DEADLINE_MS: u64 = 10_000;
const LINGER_MS: u64 = 1_000;

#[no_mangle]
fn kr_main(mut args: Args) -> i32 {
    let _argv0 = args.next();
    match args.next() {
        Some(b"version") => {
            print(b"kr 0.0.1\n");
            0
        }
        Some(b"echo") => {
            let port = match args.next() {
                None => 8080,
                Some(p) => match parse_port(p) {
                    Some(p) => p,
                    None => {
                        eprint(b"kr echo: invalid port\n");
                        return 2;
                    }
                },
            };
            match exec::block_on(echo(port)) {
                Ok(()) => 0,
                Err(e) => {
                    let mut b = [0u8; 20];
                    eprint(b"kr echo: errno ");
                    eprint(fmt_u64(e.0 as u64, &mut b));
                    eprint(b"\n");
                    1
                }
            }
        }
        Some(b"sleep-test") => {
            exec::block_on(sleep_test());
            0
        }
        _ => {
            eprint(b"usage: kr <version | echo [port] | sleep-test>\n");
            2
        }
    }
}

fn parse_port(s: &[u8]) -> Option<u16> {
    if s.is_empty() {
        return None;
    }
    let mut n: u32 = 0;
    for &c in s {
        if !c.is_ascii_digit() {
            return None;
        }
        n = n * 10 + (c - b'0') as u32;
        if n > 65535 {
            return None;
        }
    }
    Some(n as u16)
}

async fn sleep_test() {
    const MS: u64 = 100;
    let start = exec::now_ms();
    let done = Rc::new(Cell::new(0u32));
    let mut hs = Vec::new();
    for _ in 0..3 {
        let done = done.clone();
        hs.push(spawn(async move {
            let t0 = exec::now_ns();
            sleep(MS).await;
            done.set(done.get() + 1);
            exec::now_ns() - t0
        }));
    }
    let mut min_ns = u64::MAX;
    for h in hs {
        let el = h.await.expect("sleep task aborted");
        assert!(el >= MS * 1_000_000, "sleep fired early");
        min_ns = min_ns.min(el);
    }
    let mut b = [0u8; 20];
    print(b"elapsed_ms=");
    print(fmt_u64(exec::now_ms() - start, &mut b));
    print(b" done=");
    print(fmt_u64(done.get() as u64, &mut b));
    print(b" min_ns=");
    print(fmt_u64(min_ns, &mut b));
    print(b"\n");

    // Many short sleeps: none may complete early (ms truncation used to allow up to 1 ms).
    for ms in [1u64, 1, 1, 2, 3, 5] {
        for _ in 0..20 {
            let t0 = exec::now_ns();
            sleep(ms).await;
            assert!(exec::now_ns() - t0 >= ms * 1_000_000, "short sleep fired early");
        }
    }
    print(b"sleep_ok\n");

    // Abort of a task blocked on a never-ready read must free it (breaks the Rc cycle).
    let (rd, _wr) = sys::pipe2(sys::O_NONBLOCK | sys::O_CLOEXEC).expect("pipe2");
    let rd = Async::new(rd).expect("register pipe");
    let base = exec::live_tasks();
    let h = spawn(async move {
        let mut one = [0u8; 1];
        let _ = rd.read(&mut one).await;
    });
    sleep(1).await; // let it run and park on the read
    assert_eq!(exec::live_tasks(), base + 1, "task not live");
    assert!(!h.is_finished());
    h.abort();
    sleep(1).await; // one loop tick
    assert!(h.await == Err(exec::Aborted), "handle did not report abort");
    assert_eq!(exec::live_tasks(), base, "task leaked after abort");
    print(b"live_tasks_ok\n");
}

fn find_end(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

enum Req {
    Complete(Vec<u8>),
    TooLarge,
    Closed,
}

async fn read_request(c: &Async<Fd>) -> Result<Req, sys::Errno> {
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = c.read(&mut tmp).await?;
        if n == 0 {
            return Ok(Req::Closed);
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(end) = find_end(&buf) {
            buf.truncate(end);
            return Ok(Req::Complete(buf));
        }
        if buf.len() > MAX_REQ {
            return Ok(Req::TooLarge);
        }
    }
}

async fn handle(c: Async<Fd>) {
    // One overall deadline for the whole request read (slowloris defence).
    let req = match timeout(IO_DEADLINE_MS, read_request(&c)).await {
        Ok(Ok(r)) => r,
        _ => return, // timed out or I/O error: just close
    };
    let out: Vec<u8> = match req {
        Req::Closed => return,
        Req::TooLarge => b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        Req::Complete(body) => {
            let mut nb = [0u8; 20];
            let len = fmt_u64(body.len() as u64, &mut nb);
            let mut out: Vec<u8> = Vec::with_capacity(body.len() + 96);
            out.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: ");
            out.extend_from_slice(len);
            out.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
            out.extend_from_slice(&body);
            out
        }
    };
    if timeout(IO_DEADLINE_MS, c.write_all(&out)).await.is_ok_and(|r| r.is_ok()) {
        linger_close(&c).await;
    }
}

/// Lingering close: signal EOF with `shutdown(SHUT_WR)` and discard whatever the peer still
/// sends for up to 1 s, so closing with unread data does not turn into a TCP RST that could
/// destroy the response before the client reads it. The caller's drop then closes the fd.
async fn linger_close(c: &Async<Fd>) {
    if sys::shutdown(c.get_ref().raw(), sys::SHUT_WR).is_err() {
        return;
    }
    let _ = timeout(LINGER_MS, async {
        let mut tmp = [0u8; 4096];
        loop {
            match c.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await;
}

async fn echo(port: u16) -> Result<(), sys::Errno> {
    let lfd = sys::socket(sys::AF_INET, sys::SOCK_STREAM | sys::SOCK_NONBLOCK | sys::SOCK_CLOEXEC, 0)?;
    sys::setsockopt(lfd.raw(), sys::SOL_SOCKET, sys::SO_REUSEADDR, &1i32.to_ne_bytes())?;
    sys::bind(lfd.raw(), &sys::SockaddrIn::new([0, 0, 0, 0], port))?;
    sys::listen(lfd.raw(), 128)?;
    let listener = Async::new(lfd)?;
    loop {
        match listener.accept().await {
            Ok(c) => {
                spawn(handle(c));
            }
            // Transient (EMFILE, ECONNABORTED, ...): back off briefly instead of spinning.
            Err(_) => sleep(10).await,
        }
    }
}
