//! Watch delivery.
//!
//! The store keeps `Weak<RefCell<WatchState>>` per watcher; the [`Watcher`] owns the only strong
//! reference, so dropping it unregisters it (the store prunes dead entries on the next mutation).
//! Each state has a bounded queue: when more than [`QUEUE_LIMIT`] events are pending the watcher
//! is closed *and its queue discarded*, so `next()` returns `None` at once and the client must
//! re-list. A slow consumer therefore cannot grow memory without bound.
//! Only `core::task::Waker` is used; there is no executor dependency.
use crate::Event;
use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::string::String;
use core::cell::RefCell;
use core::future::poll_fn;
use core::task::{Poll, Waker};

/// Maximum number of undelivered events per watcher.
pub const QUEUE_LIMIT: usize = 10_000;

pub(crate) struct WatchState {
    pub prefix: String,
    pub queue: VecDeque<Event>,
    pub waker: Option<Waker>,
    pub closed: bool,
    pub overflowed: bool,
}

/// Receiving end of a watch. Dropping it unregisters the watch.
pub struct Watcher {
    pub(crate) state: Rc<RefCell<WatchState>>,
}

impl Watcher {
    /// Next event, waiting if none is queued. `None` once the store was dropped (after the queue
    /// drained) or the watcher overflowed.
    pub async fn next(&mut self) -> Option<Event> {
        poll_fn(|cx| self.poll_next(cx)).await
    }

    /// Poll form of `next` (for hand-written futures/streams): registers `cx`'s waker when no
    /// event is queued.
    pub fn poll_next(&mut self, cx: &mut core::task::Context<'_>) -> Poll<Option<Event>> {
        let mut s = self.state.borrow_mut();
        if let Some(e) = s.queue.pop_front() {
            return Poll::Ready(Some(e));
        }
        if s.closed {
            return Poll::Ready(None);
        }
        s.waker = Some(cx.waker().clone());
        Poll::Pending
    }

    pub fn try_next(&mut self) -> Option<Event> {
        self.state.borrow_mut().queue.pop_front()
    }

    /// True if the watcher was closed because its queue overflowed.
    pub fn overflowed(&self) -> bool {
        self.state.borrow().overflowed
    }
}
