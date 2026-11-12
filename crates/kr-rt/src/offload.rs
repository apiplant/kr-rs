//! Offloading CPU-bound work from the event loop to worker processes (ADR-052).
//!
//! The runtime is single-threaded and its allocator is not shared, so the helpers are processes,
//! like the fsync helper of ADR-024: [`init`] forks a few workers early, each connected by a
//! socketpair. A worker runs one registered handler function, which maps `(kind, request bytes)`
//! to response bytes; it sees only the bytes it is sent, never the parent's live state. The
//! caller awaits [`call`] on the event loop, whose socket I/O is asynchronous, so the loop keeps
//! running while a worker parses, renders or encodes.
//!
//! [`call`] returns `None` when no worker can take the job (none configured, all busy with a long
//! queue, the worker died); the caller then runs the same handler inline, so a job is always done.
//! A call that is cancelled mid-flight kills its worker (the response would otherwise be mixed
//! up with the next job); the pool starts a fresh one on demand.
//!
//! Frames: request `kind: u32 LE | len: u32 LE | payload`, response `len: u32 LE | payload`.

use crate::exec::Async;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell, UnsafeCell};
use core::future::poll_fn;
use core::task::{Poll, Waker};
use kr_sys::{ns, Fd};

/// Runs in the worker: `(job kind, request) -> response`.
pub type Handler = fn(u32, &[u8]) -> Vec<u8>;

/// Largest frame accepted either way.
const MAX_FRAME: usize = 1 << 30;
/// Callers waiting for a free worker beyond this run their job inline instead.
const MAX_WAITERS: usize = 16;

struct Worker {
    sock: Async<Fd>,
    pid: i32,
    busy: Cell<bool>,
    dead: Cell<bool>,
}

struct Pool {
    handler: Handler,
    want: usize,
    workers: Vec<Rc<Worker>>,
    waiters: Vec<Waker>,
}

struct Global<T>(UnsafeCell<T>);
// SAFETY: the executor is single-threaded (see `exec`); the pool is only touched from it.
unsafe impl<T> Sync for Global<T> {}

static POOL: Global<RefCell<Option<Pool>>> = Global(UnsafeCell::new(RefCell::new(None)));

fn pool() -> &'static RefCell<Option<Pool>> {
    // SAFETY: single-threaded; shared reference to a RefCell.
    unsafe { &*POOL.0.get() }
}

/// Starts `workers` worker processes that run `handler`. Call once, early (before the process has
/// grown or opened its listeners: workers are forks and start with a copy of the caller's
/// memory). `workers == 0` disables offloading.
pub fn init(handler: Handler, workers: usize) {
    let mut ws = Vec::new();
    for _ in 0..workers {
        if let Some(w) = spawn(handler) {
            ws.push(Rc::new(w));
        }
    }
    *pool().borrow_mut() = Some(Pool { handler, want: workers, workers: ws, waiters: Vec::new() });
}

/// Whether workers are configured (a call may still fall back to the caller).
pub fn enabled() -> bool {
    pool().borrow().as_ref().is_some_and(|p| p.want > 0)
}

/// Runs `handler(kind, req)` in a worker. `None`: do it yourself with the same handler.
pub async fn call(kind: u32, req: &[u8]) -> Option<Vec<u8>> {
    if req.len() > MAX_FRAME {
        return None;
    }
    let w = acquire().await?;
    let mut guard = Busy { w: w.clone(), done: false };
    let mut hdr = [0u8; 8];
    hdr[..4].copy_from_slice(&kind.to_le_bytes());
    hdr[4..].copy_from_slice(&(req.len() as u32).to_le_bytes());
    if w.sock.write_all(&hdr).await.is_err() || w.sock.write_all(req).await.is_err() {
        w.dead.set(true);
        return None;
    }
    let mut rh = [0u8; 4];
    if !read_exact(&w.sock, &mut rh).await {
        w.dead.set(true);
        return None;
    }
    let n = u32::from_le_bytes(rh) as usize;
    if n > MAX_FRAME {
        w.dead.set(true);
        return None;
    }
    let mut out = alloc::vec![0u8; n];
    if !read_exact(&w.sock, &mut out).await {
        w.dead.set(true);
        return None;
    }
    guard.done = true;
    Some(out)
}

/// Releases the worker when the call ends; a call dropped before its answer was read kills it.
struct Busy {
    w: Rc<Worker>,
    done: bool,
}

impl Drop for Busy {
    fn drop(&mut self) {
        if !self.done {
            self.w.dead.set(true);
        }
        if self.w.dead.get() {
            let _ = ns::kill(self.w.pid, ns::SIGKILL);
            let _ = ns::wait4(self.w.pid);
        }
        self.w.busy.set(false);
        let waiters: Vec<Waker> = match pool().borrow_mut().as_mut() {
            Some(p) => core::mem::take(&mut p.waiters),
            None => Vec::new(),
        };
        for w in waiters {
            w.wake();
        }
    }
}

async fn acquire() -> Option<Rc<Worker>> {
    let mut waiting = false;
    poll_fn(|cx| {
        let mut guard = pool().borrow_mut();
        let Some(p) = guard.as_mut() else { return Poll::Ready(None) };
        // Replace dead workers lazily.
        for i in 0..p.workers.len() {
            if p.workers[i].dead.get() && !p.workers[i].busy.get() {
                match spawn(p.handler) {
                    Some(w) => p.workers[i] = Rc::new(w),
                    None => {
                        p.workers.remove(i);
                        break;
                    }
                }
            }
        }
        if let Some(w) = p.workers.iter().find(|w| !w.busy.get() && !w.dead.get()) {
            w.busy.set(true);
            return Poll::Ready(Some(w.clone()));
        }
        if p.workers.is_empty() || (!waiting && p.waiters.len() >= MAX_WAITERS) {
            return Poll::Ready(None);
        }
        waiting = true;
        p.waiters.push(cx.waker().clone());
        Poll::Pending
    })
    .await
}

async fn read_exact(sock: &Async<Fd>, buf: &mut [u8]) -> bool {
    let mut n = 0;
    while n < buf.len() {
        match sock.read(&mut buf[n..]).await {
            Ok(0) | Err(_) => return false,
            Ok(k) => n += k,
        }
    }
    true
}

fn spawn(handler: Handler) -> Option<Worker> {
    let (parent_end, child_end) = ns::socketpair().ok()?;
    let parent = kr_sys::fs::getpid();
    let mut args = ns::CloneArgs { exit_signal: ns::SIGCHLD as u64, ..Default::default() };
    // SAFETY: fork-style clone (no CLONE_VM): the child continues on a private copy of the
    // process and never returns to the caller's code.
    match unsafe { ns::clone3(&mut args) } {
        Ok(0) => child(parent, parent_end, child_end, handler),
        Ok(pid) => {
            drop(child_end);
            ns::set_nonblocking(parent_end.raw()).ok()?;
            Some(Worker { sock: Async::new(parent_end).ok()?, pid, busy: Cell::new(false), dead: Cell::new(false) })
        }
        Err(_) => None,
    }
}

fn child(parent: u32, parent_end: Fd, child_end: Fd, handler: Handler) -> ! {
    let _ = ns::prctl(ns::PR_SET_PDEATHSIG, ns::SIGKILL as usize);
    if kr_sys::fs::getppid() != parent {
        kr_sys::exit_group(0);
    }
    let fd = child_end.raw();
    drop(parent_end);
    // Nothing of the parent's sockets, listeners or files may stay open in a worker.
    let mut next = 0i64;
    for keep in [0, 1, 2, fd] {
        if (keep as i64) > next {
            ns::close_range(next as u32, (keep - 1) as u32);
        }
        next = next.max(keep as i64 + 1);
    }
    ns::close_range(next as u32, u32::MAX);
    loop {
        let mut hdr = [0u8; 8];
        if !blocking_read(fd, &mut hdr) {
            kr_sys::exit_group(0);
        }
        let kind = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let len = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
        if len > MAX_FRAME {
            kr_sys::exit_group(1);
        }
        let mut req = alloc::vec![0u8; len];
        if !blocking_read(fd, &mut req) {
            kr_sys::exit_group(0);
        }
        let out = handler(kind, &req);
        drop(req);
        if !blocking_write(fd, &(out.len() as u32).to_le_bytes()) || !blocking_write(fd, &out) {
            kr_sys::exit_group(0);
        }
    }
}

fn blocking_read(fd: i32, buf: &mut [u8]) -> bool {
    let mut n = 0;
    while n < buf.len() {
        match kr_sys::read(fd, &mut buf[n..]) {
            Ok(0) => return false,
            Ok(k) => n += k,
            Err(kr_sys::Errno(4)) => continue,
            Err(_) => return false,
        }
    }
    true
}

fn blocking_write(fd: i32, buf: &[u8]) -> bool {
    let mut n = 0;
    while n < buf.len() {
        match kr_sys::write(fd, &buf[n..]) {
            Ok(k) => n += k,
            Err(kr_sys::Errno(4)) => continue,
            Err(_) => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec;

    fn handler(kind: u32, req: &[u8]) -> Vec<u8> {
        match kind {
            0 => req.iter().rev().copied().collect(),
            1 => req.iter().map(|b| b.wrapping_add(1)).collect(),
            2 => {
                // A slow job (the caller may cancel it).
                let t = exec::now_ms();
                while exec::now_ms() < t + 300 {}
                alloc::vec![7]
            }
            _ => kr_sys::exit_group(3), // the worker dies
        }
    }

    // One test: the pool is a process-wide singleton and workers are forks.
    #[test]
    fn workers_run_jobs_concurrently_and_recover() {
        init(handler, 2);
        assert!(enabled());
        exec::block_on(async {
            assert_eq!(call(0, b"abc").await.as_deref(), Some(&b"cba"[..]));
            // A payload far larger than a socket buffer, both ways.
            let big: Vec<u8> = (0..6_000_000u32).map(|i| i as u8).collect();
            let out = call(1, &big).await.unwrap();
            assert_eq!(out.len(), big.len());
            assert!(out.iter().zip(&big).all(|(o, b)| *o == b.wrapping_add(1)));
            // Several jobs at once, more than workers: all answered, in their own order.
            let hs: Vec<_> = (0..6u8).map(|i| exec::spawn(async move { call(1, &[i, i, i]).await })).collect();
            for (i, h) in hs.into_iter().enumerate() {
                assert_eq!(h.await.unwrap().as_deref(), Some(&[i as u8 + 1; 3][..]));
            }
            // The event loop keeps running while a worker is busy.
            let ticks = Rc::new(Cell::new(0u32));
            let t2 = ticks.clone();
            let ticker = exec::spawn(async move {
                for _ in 0..50 {
                    exec::sleep(5).await;
                    t2.set(t2.get() + 1);
                }
            });
            assert_eq!(call(2, b"").await.as_deref(), Some(&[7u8][..]));
            assert!(ticks.get() >= 20, "loop starved during the job: {}", ticks.get());
            ticker.await.ok();
            // A cancelled call must not poison the next one.
            assert!(exec::timeout(50, call(2, b"")).await.is_err());
            assert_eq!(call(0, b"xyz").await.as_deref(), Some(&b"zyx"[..]));
            // A worker that dies yields None (the caller runs the job itself) and is replaced.
            assert_eq!(call(9, b"").await, None);
            assert_eq!(call(0, b"ok").await.as_deref(), Some(&b"ko"[..]));
            assert_eq!(call(0, b"again").await.as_deref(), Some(&b"niaga"[..]));
        });
    }
}
