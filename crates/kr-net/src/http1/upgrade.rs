//! Connection upgrades (`101 Switching Protocols`): the type-erased connection handed to a
//! handler after the server has written the `101` response.
//!
//! The server owns the real socket (plain or TLS) and runs a *pump* next to the handler task:
//! the pump moves bytes between the transport and two bounded buffers, the handler sees a
//! [`Conn`] whose operations are all non-blocking `poll_*` functions on those buffers. That keeps
//! the handler independent of the concrete transport and makes every operation cancel-safe:
//! a `poll_write` either buffers the whole slice or buffers nothing, and dropping a pending read
//! loses no data. No HTTP idle/read/write deadlines apply after the upgrade; the handler owns
//! the connection lifetime (a stalled peer is bounded by the write buffer, not by a timer).

use super::Transport;
use crate::{Error, Result};
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::future::{poll_fn, Future};
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use kr_sys::Errno;

/// Bytes buffered from the peer before the pump stops reading (backpressure).
pub(crate) const RX_CAP: usize = 256 * 1024;
/// Bytes queued for the peer before `poll_write` returns `Pending`.
pub(crate) const TX_CAP: usize = 1024 * 1024;

/// A type-erased, poll-based, bidirectional connection.
///
/// All functions register the waker of `cx` when they return `Pending`.
pub trait Conn {
    /// Reads at least one byte, or `Ok(0)` at EOF (peer closed or connection failed after
    /// the buffered bytes were drained).
    fn poll_read(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize>>;
    /// Queues `buf` for sending. All-or-nothing: `Ready(Ok(buf.len()))` or `Pending` (queue
    /// full). Bytes are on the wire only after [`Conn::poll_flush`] completes.
    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>>;
    /// Ready once everything queued has been written to the transport.
    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>>;
    /// Flushes, then shuts the connection down. Ready once the transport is closed.
    fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>>;
}

/// `Box<dyn Conn>` is a [`Transport`]. `write_all` is cancel-safe because `poll_write` is
/// all-or-nothing; it completes when the bytes are queued (use [`Conn::poll_flush`] to wait for
/// the wire).
impl<C: Conn + ?Sized> Transport for Box<C> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        poll_fn(|cx| (**self).poll_read(cx, buf)).await
    }
    async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        poll_fn(|cx| (**self).poll_write(cx, buf)).await.map(|_| ())
    }
}

pub type UpgradeFuture = Pin<Box<dyn Future<Output = ()>>>;

/// Takes over a connection after the `101` response. The connection is closed (after flushing)
/// when the returned future completes and the [`Conn`] is dropped.
pub trait UpgradeHandler {
    fn upgrade(self: Box<Self>, conn: Box<dyn Conn>) -> UpgradeFuture;
}

impl<F> UpgradeHandler for F
where
    F: FnOnce(Box<dyn Conn>) -> UpgradeFuture,
{
    fn upgrade(self: Box<Self>, conn: Box<dyn Conn>) -> UpgradeFuture {
        (*self)(conn)
    }
}

/// State shared between the pump (server side) and the [`ConnIo`] handle (handler side).
#[derive(Default)]
pub(crate) struct Shared {
    rx: Vec<u8>,
    rx_pos: usize,
    pub(crate) rx_eof: bool,
    rx_err: Option<Error>,
    pub(crate) tx: Vec<u8>,
    tx_err: Option<Error>,
    /// The pump is writing a batch it took out of `tx`.
    pub(crate) writing: bool,
    /// The handler asked to close (or dropped its handle).
    pub(crate) close_req: bool,
    /// The pump has finished; nothing more will be read or written.
    pub(crate) closed: bool,
    rd_waker: Option<Waker>,
    wr_waker: Option<Waker>,
    fl_waker: Option<Waker>,
    pub(crate) pump_waker: Option<Waker>,
}

fn wake(w: &mut Option<Waker>) {
    if let Some(w) = w.take() {
        w.wake();
    }
}

impl Shared {
    pub(crate) fn new(initial: Vec<u8>) -> Rc<RefCell<Shared>> {
        Rc::new(RefCell::new(Shared { rx: initial, ..Shared::default() }))
    }

    pub(crate) fn rx_len(&self) -> usize {
        self.rx.len() - self.rx_pos
    }

    pub(crate) fn rx_failed(&self) -> bool {
        self.rx_err.is_some()
    }

    pub(crate) fn push_rx(&mut self, data: &[u8]) {
        if self.rx_pos == self.rx.len() {
            self.rx.clear();
            self.rx_pos = 0;
        }
        self.rx.extend_from_slice(data);
        wake(&mut self.rd_waker);
    }

    pub(crate) fn set_eof(&mut self) {
        self.rx_eof = true;
        wake(&mut self.rd_waker);
    }

    pub(crate) fn set_rx_err(&mut self, e: Error) {
        self.rx_err = Some(e);
        wake(&mut self.rd_waker);
    }

    pub(crate) fn tx_done(&mut self) {
        self.writing = false;
        wake(&mut self.wr_waker);
        wake(&mut self.fl_waker);
    }

    pub(crate) fn fail_tx(&mut self, e: Error) {
        self.tx_err = Some(e);
        self.writing = false;
        self.tx.clear();
        wake(&mut self.wr_waker);
        wake(&mut self.fl_waker);
    }

    pub(crate) fn request_close(&mut self) {
        self.close_req = true;
        wake(&mut self.pump_waker);
    }

    /// Pump exit: wakes every waiter.
    pub(crate) fn finish(&mut self) {
        self.closed = true;
        self.writing = false;
        self.rx_eof = true;
        wake(&mut self.rd_waker);
        wake(&mut self.wr_waker);
        wake(&mut self.fl_waker);
    }
}

/// The handler-side handle: a [`Conn`] over [`Shared`].
pub(crate) struct ConnIo {
    pub(crate) sh: Rc<RefCell<Shared>>,
}

impl Drop for ConnIo {
    fn drop(&mut self) {
        self.sh.borrow_mut().request_close();
    }
}

fn epipe() -> Error {
    Error::Io(Errno(kr_sys::EPIPE))
}

impl Conn for ConnIo {
    fn poll_read(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize>> {
        let mut s = self.sh.borrow_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let avail = s.rx_len();
        if avail > 0 {
            let n = avail.min(buf.len());
            let p = s.rx_pos;
            buf[..n].copy_from_slice(&s.rx[p..p + n]);
            s.rx_pos += n;
            wake(&mut s.pump_waker); // room for more
            return Poll::Ready(Ok(n));
        }
        if let Some(e) = s.rx_err {
            return Poll::Ready(Err(e));
        }
        if s.rx_eof || s.closed {
            return Poll::Ready(Ok(0));
        }
        s.rd_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        let mut s = self.sh.borrow_mut();
        if let Some(e) = s.tx_err {
            return Poll::Ready(Err(e));
        }
        if s.closed || s.close_req {
            return Poll::Ready(Err(epipe()));
        }
        if s.tx.len() >= TX_CAP {
            s.wr_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        s.tx.extend_from_slice(buf);
        wake(&mut s.pump_waker);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let mut s = self.sh.borrow_mut();
        if let Some(e) = s.tx_err {
            return Poll::Ready(Err(e));
        }
        if s.tx.is_empty() && !s.writing {
            return Poll::Ready(Ok(()));
        }
        if s.closed {
            return Poll::Ready(Err(epipe()));
        }
        s.fl_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let mut s = self.sh.borrow_mut();
        s.request_close();
        if s.closed {
            return Poll::Ready(match s.tx_err {
                Some(e) => Err(e),
                None => Ok(()),
            });
        }
        s.fl_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}
