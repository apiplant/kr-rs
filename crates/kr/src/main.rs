#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use kr_rt::{eprint, fmt_u64, print, Args};
use kr_sys::{self as sys, EpollEvent, Fd};

const MAX_REQ: usize = 16 * 1024;

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
            match echo(port) {
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
        _ => {
            eprint(b"usage: kr <version | echo [port]>\n");
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

struct Conn {
    fd: Fd,
    buf: Vec<u8>,
}

fn find_end(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn echo(port: u16) -> Result<(), sys::Errno> {
    let lfd = sys::socket(sys::AF_INET, sys::SOCK_STREAM | sys::SOCK_NONBLOCK | sys::SOCK_CLOEXEC, 0)?;
    sys::setsockopt(lfd.raw(), sys::SOL_SOCKET, sys::SO_REUSEADDR, &1i32.to_ne_bytes())?;
    sys::bind(lfd.raw(), &sys::SockaddrIn::new([0, 0, 0, 0], port))?;
    sys::listen(lfd.raw(), 128)?;
    let ep = sys::epoll_create1(sys::EPOLL_CLOEXEC)?;
    let mut ev = EpollEvent { events: sys::EPOLLIN, data: lfd.raw() as u64 };
    sys::epoll_ctl(ep.raw(), sys::EPOLL_CTL_ADD, lfd.raw(), Some(&mut ev))?;

    // Slab keyed by fd.
    let mut conns: Vec<Option<Conn>> = Vec::new();
    let mut events = [EpollEvent::zeroed(); 64];
    let mut tmp = [0u8; 4096];

    loop {
        let n = match sys::epoll_wait(ep.raw(), &mut events, -1) {
            Ok(n) => n,
            Err(sys::Errno(sys::EINTR)) => continue,
            Err(e) => return Err(e),
        };
        for e in &events[..n] {
            let key = e.data as i32;
            if key == lfd.raw() {
                loop {
                    match sys::accept4(lfd.raw(), sys::SOCK_NONBLOCK | sys::SOCK_CLOEXEC) {
                        Ok(cfd) => {
                            let raw = cfd.raw();
                            let mut cev = EpollEvent { events: sys::EPOLLIN, data: raw as u64 };
                            if sys::epoll_ctl(ep.raw(), sys::EPOLL_CTL_ADD, raw, Some(&mut cev)).is_err() {
                                continue; // cfd dropped -> closed
                            }
                            let idx = raw as usize;
                            if conns.len() <= idx {
                                conns.resize_with(idx + 1, || None);
                            }
                            conns[idx] = Some(Conn { fd: cfd, buf: Vec::new() });
                        }
                        Err(sys::Errno(sys::EAGAIN)) => break,
                        Err(sys::Errno(sys::EINTR)) => continue,
                        Err(_) => break,
                    }
                }
                continue;
            }
            let idx = key as usize;
            let Some(Some(conn)) = conns.get_mut(idx) else { continue };
            let mut done: Option<&'static [u8]> = None; // Some(prefix) => respond & close
            let mut respond_echo = false;
            let mut drop_only = false;
            loop {
                match sys::read(conn.fd.raw(), &mut tmp) {
                    Ok(0) => {
                        drop_only = true;
                        break;
                    }
                    Ok(m) => {
                        conn.buf.extend_from_slice(&tmp[..m]);
                        if let Some(end) = find_end(&conn.buf) {
                            conn.buf.truncate(end);
                            respond_echo = true;
                            break;
                        }
                        if conn.buf.len() > MAX_REQ {
                            done = Some(b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                            break;
                        }
                    }
                    Err(sys::Errno(sys::EAGAIN)) => break,
                    Err(sys::Errno(sys::EINTR)) => continue,
                    Err(_) => {
                        drop_only = true;
                        break;
                    }
                }
            }
            if respond_echo {
                let mut nb = [0u8; 20];
                let len = fmt_u64(conn.buf.len() as u64, &mut nb);
                let mut out: Vec<u8> = Vec::with_capacity(conn.buf.len() + 96);
                out.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: ");
                out.extend_from_slice(len);
                out.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
                out.extend_from_slice(&conn.buf);
                // Best-effort blocking-free write; responses are small relative to socket buffers.
                send_all(conn.fd.raw(), &out);
            } else if let Some(r) = done {
                send_all(conn.fd.raw(), r);
            }
            if respond_echo || done.is_some() || drop_only {
                let _ = sys::epoll_ctl(ep.raw(), sys::EPOLL_CTL_DEL, conn.fd.raw(), None);
                conns[idx] = None; // drops Fd -> close
            }
        }
    }
}

fn send_all(fd: i32, mut b: &[u8]) {
    while !b.is_empty() {
        match sys::write(fd, b) {
            Ok(n) if n > 0 => b = &b[n..],
            Err(sys::Errno(sys::EINTR)) => {}
            _ => return, // EAGAIN or error: give up (documented limitation of phase 0)
        }
    }
}
