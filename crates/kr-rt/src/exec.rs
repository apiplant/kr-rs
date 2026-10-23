//! Single-threaded async executor: Rc-based tasks, edge-triggered epoll reactor and a
//! hierarchical timing wheel (ADR-005).
//!
//! # Single-thread invariant
//! Everything here lives in one `static` ([`Global`]) that is `Sync` only by assertion. The
//! process must never run executor code (spawn, block_on, polling, waking) from more than one
//! thread. [`core::task::Waker`] is `Send + Sync` by type, but ours wrap non-atomic `Rc<Task>`
//! pointers, so a waker MUST NOT leave the executor thread. This is acceptable because the whole
//! runtime is single-threaded (see the allocator).
//!
//! Re-entrancy rule: no `RefCell` borrow of executor state is held across a call that can drop
//! or wake a `Waker`/`Rc<Task>` (dropping the last reference to a task drops its future, which
//! may drop an [`Async`] and touch the reactor again).

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell, UnsafeCell};
use core::future::{poll_fn, Future};
use core::mem::ManuallyDrop;
use core::pin::{pin, Pin};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use kr_sys::{self as sys, Errno, EpollEvent, Fd};

// ---------- global state ----------

struct Global<T>(UnsafeCell<T>);
// SAFETY: see the module docs; the executor is only ever used from a single thread.
unsafe impl<T> Sync for Global<T> {}

struct Exec {
    queue: RefCell<VecDeque<Rc<Task>>>,
    io: RefCell<Reactor>,
    wheel: RefCell<Wheel>,
}

static EXEC: Global<Exec> = Global(UnsafeCell::new(Exec {
    queue: RefCell::new(VecDeque::new()),
    io: RefCell::new(Reactor { epfd: -1, slab: Vec::new(), free: Vec::new() }),
    wheel: RefCell::new(Wheel {
        inited: false,
        elapsed: 0,
        count: 0,
        slots: [const { [const { Vec::new() }; SLOTS] }; LEVELS],
    }),
}));

fn ex() -> &'static Exec {
    // SAFETY: shared reference only; mutation goes through the RefCells. Single-threaded.
    unsafe { &*EXEC.0.get() }
}

// ---------- tasks and wakers ----------

struct Task {
    fut: RefCell<Option<Pin<Box<dyn Future<Output = ()>>>>>,
    queued: Cell<bool>,
}

fn schedule(t: Rc<Task>) {
    if !t.queued.replace(true) {
        ex().queue.borrow_mut().push_back(t);
    }
}

static VTABLE: RawWakerVTable = RawWakerVTable::new(w_clone, w_wake, w_wake_by_ref, w_drop);

unsafe fn w_clone(p: *const ()) -> RawWaker {
    // SAFETY: p came from Rc::into_raw::<Task>; bumping the count keeps it alive for the clone.
    unsafe { Rc::increment_strong_count(p as *const Task) };
    RawWaker::new(p, &VTABLE)
}
unsafe fn w_wake(p: *const ()) {
    // SAFETY: consumes the strong count owned by this waker.
    schedule(unsafe { Rc::from_raw(p as *const Task) });
}
unsafe fn w_wake_by_ref(p: *const ()) {
    // SAFETY: borrow the count without consuming it, then clone for the queue.
    let t = ManuallyDrop::new(unsafe { Rc::from_raw(p as *const Task) });
    schedule(Rc::clone(&t));
}
unsafe fn w_drop(p: *const ()) {
    // SAFETY: releases the strong count owned by this waker.
    drop(unsafe { Rc::from_raw(p as *const Task) });
}

fn waker_for(t: &Rc<Task>) -> Waker {
    let raw = RawWaker::new(Rc::into_raw(Rc::clone(t)) as *const (), &VTABLE);
    // SAFETY: the vtable upholds the RawWaker contract for Rc<Task> (single-threaded only).
    unsafe { Waker::from_raw(raw) }
}

// ---------- spawn / join ----------

struct JoinState<T> {
    result: RefCell<Option<T>>,
    waker: RefCell<Option<Waker>>,
}

/// Handle to a spawned task. Dropping it detaches the task.
pub struct JoinHandle<T> {
    st: Rc<JoinState<T>>,
}

impl<T> Future for JoinHandle<T> {
    type Output = T;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        if let Some(v) = self.st.result.borrow_mut().take() {
            return Poll::Ready(v);
        }
        let old = self.st.waker.borrow_mut().replace(cx.waker().clone());
        drop(old);
        Poll::Pending
    }
}

pub fn spawn<F>(fut: F) -> JoinHandle<F::Output>
where
    F: Future + 'static,
    F::Output: 'static,
{
    let st = Rc::new(JoinState { result: RefCell::new(None), waker: RefCell::new(None) });
    let st2 = st.clone();
    let wrapped = async move {
        let v = fut.await;
        *st2.result.borrow_mut() = Some(v);
        let w = st2.waker.borrow_mut().take();
        if let Some(w) = w {
            w.wake();
        }
    };
    let t = Rc::new(Task { fut: RefCell::new(Some(Box::pin(wrapped))), queued: Cell::new(false) });
    schedule(t);
    JoinHandle { st }
}

/// Runs the event loop until `fut` completes and returns its output.
pub fn block_on<F>(fut: F) -> F::Output
where
    F: Future + 'static,
    F::Output: 'static,
{
    let h = spawn(fut);
    loop {
        run_queue();
        if let Some(v) = h.st.result.borrow_mut().take() {
            return v;
        }
        let queue_empty = ex().queue.borrow().is_empty();
        let timeout = if !queue_empty {
            0
        } else {
            let now = now_ms();
            let next = ex().wheel.borrow().next_event();
            match next {
                Some(t) => t.saturating_sub(now).min(i32::MAX as u64) as i32,
                None => {
                    let io = ex().io.borrow();
                    if io.slab.len() == io.free.len() {
                        panic!("block_on: deadlock (no tasks, timers or fds)");
                    }
                    -1
                }
            }
        };
        poll_io(timeout);
        run_timers();
    }
}

/// Polls every task queued at the start of the round (new wakeups wait for the next round, so
/// a self-waking task cannot starve I/O and timers).
fn run_queue() {
    let n = ex().queue.borrow().len();
    for _ in 0..n {
        let Some(task) = ex().queue.borrow_mut().pop_front() else { break };
        task.queued.set(false);
        let waker = waker_for(&task);
        let mut cx = Context::from_waker(&waker);
        let mut slot = task.fut.borrow_mut();
        if let Some(f) = slot.as_mut() {
            if f.as_mut().poll(&mut cx).is_ready() {
                *slot = None;
            }
        }
    }
}

// ---------- time ----------

/// Monotonic milliseconds (arbitrary epoch).
pub fn now_ms() -> u64 {
    match sys::clock_gettime(sys::CLOCK_MONOTONIC) {
        Ok(ts) => ts.tv_sec as u64 * 1000 + ts.tv_nsec as u64 / 1_000_000,
        Err(_) => 0,
    }
}

const LEVELS: usize = 4;
const SLOTS: usize = 64;
const BITS: u32 = 6;
/// Largest delta (ms) the wheel represents: 64^4 = 16_777_216 ms (~4.66 h).
const SPAN: u64 = 1 << (BITS * LEVELS as u32);

struct TimerState {
    waker: RefCell<Option<Waker>>,
}

struct Entry {
    deadline: u64,
    state: Rc<TimerState>,
}

struct Wheel {
    inited: bool,
    /// Last tick that has been fully processed.
    elapsed: u64,
    count: usize,
    slots: [[Vec<Entry>; SLOTS]; LEVELS],
}

impl Wheel {
    fn place(&mut self, e: Entry, d: u64) {
        let mut d = d;
        let delta = d - self.elapsed;
        let lvl = if delta < 1 << BITS {
            0
        } else if delta < 1 << (2 * BITS) {
            1
        } else if delta < 1 << (3 * BITS) {
            2
        } else {
            3
        };
        if delta >= SPAN {
            d = self.elapsed + SPAN - 1; // clamped; re-armed when it fires early
        }
        self.slots[lvl][((d >> (BITS * lvl as u32)) & 63) as usize].push(e);
    }

    fn insert_new(&mut self, e: Entry, now: u64) {
        if !self.inited {
            self.inited = true;
            self.elapsed = now;
        }
        self.count += 1;
        let d = e.deadline.max(self.elapsed + 1);
        self.place(e, d);
    }

    /// Conservative (never late) tick of the next slot that needs attention.
    fn next_event(&self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        let mut best = u64::MAX;
        for l in 0..LEVELS {
            let sh = BITS * l as u32;
            let cur = self.elapsed >> sh;
            for i in 1..=SLOTS as u64 {
                let blk = cur + i;
                if !self.slots[l][(blk & 63) as usize].is_empty() {
                    best = best.min(blk << sh);
                    break;
                }
            }
        }
        Some(best)
    }

    fn advance(&mut self, now: u64, fired: &mut Vec<Rc<TimerState>>) {
        if !self.inited {
            return;
        }
        while self.elapsed < now {
            if self.count == 0 {
                self.elapsed = now;
                return;
            }
            self.elapsed += 1;
            let t = self.elapsed;
            for l in 1..LEVELS {
                let sh = BITS * l as u32;
                if t & ((1 << sh) - 1) != 0 {
                    break;
                }
                let v = core::mem::take(&mut self.slots[l][((t >> sh) & 63) as usize]);
                for e in v {
                    let d = e.deadline.max(t);
                    self.place(e, d);
                }
            }
            let v = core::mem::take(&mut self.slots[0][(t & 63) as usize]);
            for e in v {
                if e.deadline <= t {
                    self.count -= 1;
                    fired.push(e.state);
                } else {
                    let d = e.deadline;
                    self.place(e, d);
                }
            }
        }
    }
}

fn run_timers() {
    let mut fired = Vec::new();
    ex().wheel.borrow_mut().advance(now_ms(), &mut fired);
    for st in fired {
        let w = st.waker.borrow_mut().take();
        if let Some(w) = w {
            w.wake();
        }
    }
}

pub struct Sleep {
    deadline: u64,
    state: Option<Rc<TimerState>>,
}

/// Completes after `ms` milliseconds (may fire up to 1 ms early due to ms truncation).
pub fn sleep(ms: u64) -> Sleep {
    Sleep { deadline: now_ms().saturating_add(ms), state: None }
}

impl Future for Sleep {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let now = now_ms();
        if now >= self.deadline {
            return Poll::Ready(());
        }
        match &self.state {
            Some(st) => {
                let mut w = st.waker.borrow_mut();
                if !w.as_ref().is_some_and(|w| w.will_wake(cx.waker())) {
                    let old = w.replace(cx.waker().clone());
                    drop(w);
                    drop(old);
                }
            }
            None => {
                let st = Rc::new(TimerState { waker: RefCell::new(Some(cx.waker().clone())) });
                self.state = Some(st.clone());
                ex().wheel.borrow_mut().insert_new(Entry { deadline: self.deadline, state: st }, now);
            }
        }
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if let Some(st) = &self.state {
            // Release the task reference early; the wheel entry is skipped when it fires.
            let old = st.waker.borrow_mut().take();
            drop(old);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimedOut;

/// Polls `fut`; resolves to `Err(TimedOut)` if it is not done within `ms`. The future is
/// polled first, so ready work wins over an expired deadline.
pub async fn timeout<F: Future>(ms: u64, fut: F) -> Result<F::Output, TimedOut> {
    let mut fut = pin!(fut);
    let mut sl = pin!(sleep(ms));
    poll_fn(|cx| {
        if let Poll::Ready(v) = fut.as_mut().poll(cx) {
            return Poll::Ready(Ok(v));
        }
        if sl.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(TimedOut));
        }
        Poll::Pending
    })
    .await
}

// ---------- reactor ----------

struct IoSlot {
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    readable: bool,
    writable: bool,
}

struct Reactor {
    epfd: i32,
    slab: Vec<Option<IoSlot>>,
    free: Vec<usize>,
}

fn ensure_epfd() -> Result<i32, Errno> {
    let mut io = ex().io.borrow_mut();
    if io.epfd < 0 {
        io.epfd = sys::epoll_create1(sys::EPOLL_CLOEXEC)?.into_raw();
    }
    Ok(io.epfd)
}

fn register(fd: i32) -> Result<usize, Errno> {
    let ep = ensure_epfd()?;
    let mut io = ex().io.borrow_mut();
    // Optimistically ready: the first operation just tries and learns EAGAIN.
    let slot = IoSlot { read_waker: None, write_waker: None, readable: true, writable: true };
    let idx = match io.free.pop() {
        Some(i) => {
            io.slab[i] = Some(slot);
            i
        }
        None => {
            io.slab.push(Some(slot));
            io.slab.len() - 1
        }
    };
    let mut ev = EpollEvent {
        events: sys::EPOLLIN | sys::EPOLLOUT | sys::EPOLLRDHUP | sys::EPOLLET,
        data: idx as u64,
    };
    if let Err(e) = sys::epoll_ctl(ep, sys::EPOLL_CTL_ADD, fd, Some(&mut ev)) {
        io.slab[idx] = None;
        io.free.push(idx);
        return Err(e);
    }
    Ok(idx)
}

fn poll_io(timeout_ms: i32) {
    let Ok(ep) = ensure_epfd() else { return };
    let mut evs = [EpollEvent::zeroed(); 64];
    let n = sys::epoll_wait(ep, &mut evs, timeout_ms).unwrap_or(0); // EINTR => just loop
    for e in &evs[..n] {
        let (bits, idx) = (e.events, e.data as usize);
        let rd = bits & (sys::EPOLLIN | sys::EPOLLRDHUP | sys::EPOLLHUP | sys::EPOLLERR) != 0;
        let wr = bits & (sys::EPOLLOUT | sys::EPOLLHUP | sys::EPOLLERR) != 0;
        let (rw, ww) = {
            let mut io = ex().io.borrow_mut();
            // A stale event for a freed/reused slot only causes a harmless spurious flag.
            let Some(Some(s)) = io.slab.get_mut(idx) else { continue };
            let mut rw = None;
            let mut ww = None;
            if rd {
                s.readable = true;
                rw = s.read_waker.take();
            }
            if wr {
                s.writable = true;
                ww = s.write_waker.take();
            }
            (rw, ww)
        };
        if let Some(w) = rw {
            w.wake();
        }
        if let Some(w) = ww {
            w.wake();
        }
    }
}

fn poll_ready(slot: usize, write: bool, cx: &mut Context<'_>) -> Poll<()> {
    let mut io = ex().io.borrow_mut();
    let Some(Some(s)) = io.slab.get_mut(slot) else { return Poll::Ready(()) };
    let (flag, w) = if write { (s.writable, &mut s.write_waker) } else { (s.readable, &mut s.read_waker) };
    if flag {
        return Poll::Ready(());
    }
    if w.as_ref().is_some_and(|w| w.will_wake(cx.waker())) {
        return Poll::Pending;
    }
    let old = w.replace(cx.waker().clone());
    drop(io);
    drop(old);
    Poll::Pending
}

fn clear_ready(slot: usize, write: bool) {
    if let Some(Some(s)) = ex().io.borrow_mut().slab.get_mut(slot) {
        if write {
            s.writable = false;
        } else {
            s.readable = false;
        }
    }
}

/// A non-blocking fd registered with the reactor (edge-triggered). Dropping deregisters it,
/// frees its slot and closes the fd.
pub struct Async<T: AsRawFd = Fd> {
    inner: T,
    slot: usize,
}

pub trait AsRawFd {
    fn as_raw_fd(&self) -> i32;
}
impl AsRawFd for Fd {
    fn as_raw_fd(&self) -> i32 {
        self.raw()
    }
}

impl<T: AsRawFd> Async<T> {
    /// `inner` must already be in non-blocking mode.
    pub fn new(inner: T) -> Result<Self, Errno> {
        let slot = register(inner.as_raw_fd())?;
        Ok(Async { inner, slot })
    }

    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    async fn ready(&self, write: bool) {
        poll_fn(|cx| poll_ready(self.slot, write, cx)).await
    }

    pub async fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        loop {
            self.ready(false).await;
            match sys::read(self.inner.as_raw_fd(), buf) {
                Err(Errno(sys::EAGAIN)) => clear_ready(self.slot, false),
                Err(Errno(sys::EINTR)) => {}
                r => return r,
            }
        }
    }

    pub async fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
        loop {
            self.ready(true).await;
            match sys::write(self.inner.as_raw_fd(), buf) {
                Err(Errno(sys::EAGAIN)) => clear_ready(self.slot, true),
                Err(Errno(sys::EINTR)) => {}
                r => return r,
            }
        }
    }

    pub async fn write_all(&self, mut buf: &[u8]) -> Result<(), Errno> {
        while !buf.is_empty() {
            match self.write(buf).await? {
                0 => return Err(Errno(sys::EPIPE)),
                n => buf = &buf[n..],
            }
        }
        Ok(())
    }
}

impl Async<Fd> {
    /// Accepts one connection from a listening socket; the result is registered and non-blocking.
    pub async fn accept(&self) -> Result<Async<Fd>, Errno> {
        loop {
            self.ready(false).await;
            match sys::accept4(self.inner.raw(), sys::SOCK_NONBLOCK | sys::SOCK_CLOEXEC) {
                Ok(fd) => return Async::new(fd),
                Err(Errno(sys::EAGAIN)) => clear_ready(self.slot, false),
                Err(Errno(sys::EINTR)) => {}
                Err(e) => return Err(e),
            }
        }
    }
}

impl<T: AsRawFd> Drop for Async<T> {
    fn drop(&mut self) {
        let ep = ex().io.borrow().epfd;
        let _ = sys::epoll_ctl(ep, sys::EPOLL_CTL_DEL, self.inner.as_raw_fd(), None);
        let old = {
            let mut io = ex().io.borrow_mut();
            let old = io.slab.get_mut(self.slot).and_then(|s| s.take());
            io.free.push(self.slot);
            old
        };
        drop(old); // wakers dropped outside the borrow; the fd closes when `inner` drops
    }
}
