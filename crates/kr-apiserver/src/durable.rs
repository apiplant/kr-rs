//! Group commit with fsync off the event loop.
//!
//! The API server writes log records to the page cache synchronously (`Store::write_out`) and
//! acknowledges a write only after the log is fsynced. The fsync runs in a helper process that
//! shares kr's file table (`CLONE_FILES`): kr sends it the log fd number over a pipe, it fsyncs
//! and answers with one byte. The event loop never blocks on the disk, and every write that
//! arrives during one fsync rides on the next (one fsync per batch, not per request).
//!
//! If the helper cannot be started (or dies), commits fall back to a blocking fsync.

use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::future::poll_fn;
use core::task::{Poll, Waker};
use kr_rt::exec::Async;
use kr_sys::ns;
use kr_sys::Fd;

struct Helper {
    req: Fd,
    resp: Async<Fd>,
}

pub struct Committer {
    helper: RefCell<Option<Rc<Helper>>>,
    /// Spawn the helper on first use (false: inline fsync only).
    want_helper: Cell<bool>,
    /// Highest revision known to be on disk.
    durable: Cell<u64>,
    busy: Cell<bool>,
    waiters: RefCell<Vec<Waker>>,
}

fn spawn_helper() -> Option<Helper> {
    let (req, resp) = ns::spawn_fsync_helper().ok()?;
    Some(Helper { req, resp: Async::new(resp).ok()? })
}

impl Committer {
    pub fn new() -> Committer {
        Committer { helper: RefCell::new(None), want_helper: Cell::new(true), durable: Cell::new(0), busy: Cell::new(false), waiters: RefCell::new(Vec::new()) }
    }

    /// A committer that always fsyncs inline (no helper process).
    pub fn blocking() -> Committer {
        let c = Committer::new();
        c.want_helper.set(false);
        c
    }

    pub fn durable_rev(&self) -> u64 {
        self.durable.get()
    }

    /// Resolves once everything up to `rev` is on disk. `written` is the revision currently in
    /// the log (after `Store::write_out`); `fd` the log fd (None: nothing to sync).
    pub async fn wait(&self, rev: u64, fd: Option<i32>, written: impl Fn() -> u64) -> Result<(), ()> {
        let Some(fd) = fd else {
            self.durable.set(self.durable.get().max(rev));
            return Ok(());
        };
        loop {
            if self.durable.get() >= rev {
                return Ok(());
            }
            if self.busy.get() {
                // Someone else's fsync is in flight; ours rides on the next one.
                let mut first = true;
                poll_fn(|cx| {
                    if first {
                        first = false;
                        self.waiters.borrow_mut().push(cx.waker().clone());
                        Poll::Pending
                    } else {
                        Poll::Ready(())
                    }
                })
                .await;
                continue;
            }
            self.busy.set(true);
            let target = written();
            let ok = self.fsync(fd).await;
            self.busy.set(false);
            if ok {
                self.durable.set(self.durable.get().max(target));
            }
            for w in self.waiters.borrow_mut().drain(..) {
                w.wake();
            }
            if !ok {
                return Err(());
            }
        }
    }

    async fn fsync(&self, fd: i32) -> bool {
        if self.want_helper.get() && self.helper.borrow().is_none() {
            *self.helper.borrow_mut() = spawn_helper().map(Rc::new);
            self.want_helper.set(self.helper.borrow().is_some());
        }
        let helper = self.helper.borrow().clone();
        if let Some(h) = helper {
            if kr_sys::write(h.req.raw(), &fd.to_le_bytes()) == Ok(4) {
                let mut b = [0u8; 1];
                if let Ok(1) = h.resp.read(&mut b).await {
                    return b[0] == 0;
                }
            }
            // The helper is gone: fall back to inline fsyncs from now on.
            *self.helper.borrow_mut() = None;
            self.want_helper.set(false);
        }
        kr_sys::fs::fsync(fd).is_ok()
    }
}

impl Default for Committer {
    fn default() -> Self {
        Committer::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    // The executor is process-global: tests that drive it must not run concurrently.
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn tmpfile(name: &str) -> std::fs::File {
        let p = std::env::temp_dir().join(alloc::format!("kr-durable-{name}-{}", std::process::id()));
        std::fs::OpenOptions::new().create(true).write(true).truncate(true).open(p).unwrap()
    }

    fn wait(c: &Rc<Committer>, rev: u64, fd: Option<i32>, written: u64) -> Result<(), ()> {
        let c = c.clone();
        kr_rt::exec::block_on(async move { c.wait(rev, fd, move || written).await })
    }

    #[test]
    fn helper_commits_and_batches_waiters() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let f = tmpfile("helper");
        let fd = f.as_raw_fd();
        let c = Rc::new(Committer::new());
        let c2 = c.clone();
        let results = kr_rt::exec::block_on(async move {
            // Three writers waiting at once: one fsync in flight, the rest ride on the next.
            let mut hs = Vec::new();
            for rev in [3u64, 4, 5] {
                let c = c2.clone();
                hs.push(kr_rt::exec::spawn(async move { c.wait(rev, Some(fd), || 5).await }));
            }
            let mut out = Vec::new();
            for h in hs {
                out.push(h.await.unwrap());
            }
            out
        });
        assert_eq!(results, alloc::vec![Ok(()), Ok(()), Ok(())]);
        assert_eq!(c.durable_rev(), 5);
        assert!(c.helper.borrow().is_some(), "the helper process should be in use");
        drop(f);
    }

    #[test]
    fn in_memory_and_blocking_modes() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let c = Rc::new(Committer::blocking());
        assert_eq!(wait(&c, 7, None, 7), Ok(()));
        assert_eq!(c.durable_rev(), 7);
        let f = tmpfile("blocking");
        assert_eq!(wait(&c, 9, Some(f.as_raw_fd()), 9), Ok(()));
        assert_eq!(c.durable_rev(), 9);
        assert!(c.helper.borrow().is_none());
        // A bad fd fails the commit instead of claiming durability.
        assert_eq!(wait(&c, 10, Some(-1), 10), Err(()));
        assert_eq!(c.durable_rev(), 9);
    }
}
