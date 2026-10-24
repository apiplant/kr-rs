//! `kr-store`: an embedded MVCC key-value store replacing etcd for the API server.
//!
//! # Model
//!
//! Single-threaded (`Rc`/`RefCell`, not `Send`), owned by the API server's event loop. Keys are
//! UTF-8 strings, values opaque bytes shared as `Rc<[u8]>`. One global revision counter starts at
//! 0 and increases by exactly 1 per successful mutation. Each live key records the revision that
//! created it and the one that last modified it.
//!
//! # Durability contract
//!
//! Mutations are applied in memory and appended to an in-memory buffer. **Nothing is durable until
//! [`Store::sync`] returns `Ok`; callers MUST `sync()` before acknowledging a write to a client.**
//! One `sync()` covers any number of buffered writes (group commit). [`Store::set_auto_sync`]
//! syncs after every mutation instead. If an auto-sync fails the mutation has still been applied in
//! memory and is reported as `Err(Io)`; the caller should treat the store as failed.
//!
//! # Files (in the store directory)
//!
//! * `log`: append-only records, see [`wal`] framing: `[u32 len][u32 crc32][payload]`.
//! * `snapshot`: `b"KRSNAP1\0"`, `rev: u64 LE`, then put records in the same framing.
//! * `snapshot.tmp`: transient, ignored and removed on open.
//!
//! # Recovery invariants
//!
//! * Open loads the snapshot, then replays the log. Log records with `rev <= snapshot rev` are
//!   skipped, which makes a crash between the snapshot rename and the log truncation harmless.
//! * Remaining records must be contiguous (`rev == current + 1`) else `Corrupt`.
//! * A torn final record is truncated away; a CRC failure anywhere else is `Corrupt`.
//! * Compaction writes `snapshot.tmp`, fsyncs it, renames over `snapshot`, fsyncs the directory,
//!   then truncates the log and fsyncs it.
//!
//! # History and watches
//!
//! A bounded ring of recent events (default 10,000) backs `watch(after_rev)` replay. Events with
//! `rev <= hist_floor` are gone; replaying from before the floor is `Compacted`. History is not
//! persisted: after `open` the floor is the current revision.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod wal;
pub mod watch;

pub use watch::Watcher;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::rc::{Rc, Weak};
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::ops::Bound;
use kr_sys::fs::{self, AT_FDCWD};
use kr_sys::{Errno, Fd};
use wal::{Parsed, MAX_KEY, MAX_VALUE, OP_DELETE, OP_PUT, RECORD_OVERHEAD};
use watch::{WatchState, QUEUE_LIMIT};

const O_APPEND: i32 = 0o2000;
const READ_LIMIT: usize = usize::MAX >> 1;
/// Logs smaller than this are never rewritten (a rewrite costs a snapshot write and fsyncs).
const COMPACT_MIN_LOG: u64 = 8 << 20;

/// Default number of events retained for watch replay.
pub const DEFAULT_HISTORY: usize = 10_000;

#[derive(Clone, Debug)]
pub struct Kv {
    pub key: Rc<str>,
    pub value: Rc<[u8]>,
    pub create_rev: u64,
    pub mod_rev: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    Put,
    Delete,
}

#[derive(Clone, Debug)]
pub struct Event {
    pub kind: EventKind,
    /// For `Delete`: the deleted kv (old value) with `mod_rev` set to the deletion revision.
    pub kv: Kv,
    pub prev: Option<Kv>,
    pub rev: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Exists,
    NotFound,
    /// `expect_mod_rev` did not match; `current_rev` is the key's current `mod_rev`.
    Conflict { current_rev: u64 },
    /// Requested history is gone; `oldest` is the first revision still replayable.
    Compacted { oldest: u64 },
    Io(Errno),
    Corrupt(&'static str),
    TooLarge,
}

impl From<Errno> for Error {
    fn from(e: Errno) -> Error {
        Error::Io(e)
    }
}

struct Persist {
    dir: Fd,
    log: Fd,
    /// Encoded records not yet written.
    buf: Vec<u8>,
    /// Bytes of `log` known written (excludes `buf`).
    log_len: u64,
}

pub struct Store {
    map: BTreeMap<Rc<str>, Kv>,
    rev: u64,
    history: VecDeque<Event>,
    hist_cap: usize,
    /// Events with `rev <= hist_floor` have been dropped.
    hist_floor: u64,
    watchers: Vec<Weak<RefCell<WatchState>>>,
    persist: Option<Persist>,
    auto_sync: bool,
    compact_min: u64,
    /// Replicated mode (ADR-026): records of local mutations, taken by the Raft driver.
    repl: Option<Vec<u8>>,
    /// Watch events above this revision are held until it advances (committed revision).
    visible: u64,
    held: VecDeque<Event>,
    /// Approximate size of a snapshot of the live data.
    live_bytes: u64,
}

fn path(name: &str) -> Vec<u8> {
    let mut v = Vec::from(name.as_bytes());
    v.push(0);
    v
}

fn mkdir_p(dir: &str) -> Result<(), Error> {
    let mut end = 0;
    loop {
        end = match dir[end..].find('/') {
            Some(i) if end + i == 0 => 1,
            Some(i) => end + i + 1,
            None => dir.len(),
        };
        let part = &dir[..end];
        if !part.is_empty() && part != "/" {
            match fs::mkdirat(AT_FDCWD, &path(part), 0o755) {
                Ok(()) => {}
                Err(Errno(fs::EEXIST)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        if end >= dir.len() {
            return Ok(());
        }
    }
}

impl Store {
    fn empty() -> Store {
        Store {
            map: BTreeMap::new(),
            rev: 0,
            history: VecDeque::new(),
            hist_cap: DEFAULT_HISTORY,
            hist_floor: 0,
            watchers: Vec::new(),
            persist: None,
            auto_sync: false,
            compact_min: COMPACT_MIN_LOG,
            repl: None,
            visible: u64::MAX,
            held: VecDeque::new(),
            live_bytes: 0,
        }
    }

    /// A store with no persistence (tests, ephemeral use). `sync` is a no-op.
    pub fn in_memory() -> Store {
        Store::empty()
    }

    /// In-memory store whose durability is Raft's (ADR-026): local mutations are captured as
    /// records ([`Store::take_records`]) to be proposed, records committed elsewhere are applied
    /// with [`Store::apply_records`], and watch events are released only up to the committed
    /// revision ([`Store::set_visible`]).
    pub fn replicated() -> Store {
        let mut s = Store::empty();
        s.repl = Some(Vec::new());
        s.visible = 0;
        s
    }

    /// Records of local mutations since the last call (the payload of a Raft proposal).
    pub fn take_records(&mut self) -> Vec<u8> {
        self.repl.as_mut().map(core::mem::take).unwrap_or_default()
    }

    /// Applies records (from a committed Raft entry, or recovery). Revisions already applied are
    /// skipped, so the leader re-applying its own committed entries is a no-op; a gap is
    /// `Corrupt`. Emits watch events like local mutations. Returns the new revision.
    pub fn apply_records(&mut self, data: &[u8]) -> Result<u64, Error> {
        let mut off = 0;
        while off < data.len() {
            match wal::parse(data, off) {
                Parsed::Rec(rec) => {
                    off = rec.end;
                    if rec.rev <= self.rev {
                        continue;
                    }
                    if rec.rev != self.rev + 1 {
                        return Err(Error::Corrupt("replicated revision gap"));
                    }
                    let key: Rc<str> = Rc::from(rec.key);
                    let prev = self.map.get(rec.key).cloned();
                    if rec.op == OP_PUT {
                        self.apply_event(EventKind::Put, key, Rc::from(rec.val), rec.create_rev, prev);
                    } else {
                        let Some(prev) = prev else { return Err(Error::Corrupt("replicated delete of a missing key")) };
                        let value = prev.value.clone();
                        self.apply_event(EventKind::Delete, key, value, rec.create_rev, Some(prev));
                    }
                }
                Parsed::Torn => return Err(Error::Corrupt("truncated replicated records")),
                Parsed::Corrupt(m) => return Err(Error::Corrupt(m)),
            }
        }
        Ok(self.rev)
    }

    /// Releases watch events up to `rev` (the committed revision).
    pub fn set_visible(&mut self, rev: u64) {
        if rev <= self.visible && self.visible != u64::MAX {
            return;
        }
        self.visible = rev;
        while self.held.front().is_some_and(|e| e.rev <= rev) {
            let ev = self.held.pop_front().unwrap();
            self.notify(&ev);
        }
    }

    pub fn visible(&self) -> u64 {
        self.visible
    }

    /// A snapshot image of the live data (`KRSNAP` format, see the module docs).
    pub fn image(&self) -> Vec<u8> {
        let mut snap = Vec::with_capacity(16 + self.live_bytes as usize);
        snap.extend_from_slice(wal::SNAP_MAGIC);
        snap.extend_from_slice(&self.rev.to_le_bytes());
        for kv in self.map.values() {
            wal::encode(&mut snap, OP_PUT, kv.mod_rev, kv.create_rev, &kv.key, &kv.value);
        }
        snap
    }

    /// Replaces all data with `image` (a Raft snapshot, or a rollback rebuild). Watchers are
    /// closed (clients re-list), history restarts at the image's revision, and nothing local
    /// is left to propose.
    pub fn restore(&mut self, image: &[u8]) -> Result<(), Error> {
        let mut fresh = Store::empty();
        fresh.load_snapshot(image)?;
        self.map = core::mem::take(&mut fresh.map);
        self.live_bytes = fresh.live_bytes;
        self.rev = fresh.rev;
        self.history.clear();
        self.held.clear();
        self.hist_floor = self.rev;
        if self.visible != u64::MAX {
            self.visible = self.rev;
        }
        if let Some(r) = &mut self.repl {
            r.clear();
        }
        for w in self.watchers.drain(..) {
            if let Some(rc) = w.upgrade() {
                let mut st = rc.borrow_mut();
                st.queue.clear();
                st.closed = true;
                st.overflowed = true;
                if let Some(wk) = st.waker.take() {
                    wk.wake();
                }
            }
        }
        Ok(())
    }

    /// Opens (creating if missing) the store in `dir`, loading the snapshot and replaying the log.
    pub fn open(dir: &str) -> Result<Store, Error> {
        mkdir_p(dir)?;
        let dirfd = fs::openat(AT_FDCWD, &path(dir), fs::O_RDONLY | fs::O_DIRECTORY | fs::O_CLOEXEC, 0)?;
        let mut st = Store::empty();
        // A leftover temp file is an unfinished compaction; the old snapshot+log are intact.
        let _ = fs::unlinkat(dirfd.raw(), &path("snapshot.tmp"), 0);

        match fs::openat(dirfd.raw(), &path("snapshot"), fs::O_RDONLY | fs::O_CLOEXEC, 0) {
            Ok(fd) => {
                let mut data = Vec::new();
                fs::read_to_end(fd.raw(), &mut data, READ_LIMIT)?;
                st.load_snapshot(&data)?;
            }
            Err(Errno(fs::ENOENT)) => {}
            Err(e) => return Err(e.into()),
        }

        let existed = match fs::openat(dirfd.raw(), &path("log"), fs::O_RDONLY | fs::O_CLOEXEC, 0) {
            Ok(_) => true,
            Err(Errno(fs::ENOENT)) => false,
            Err(e) => return Err(e.into()),
        };
        let log = fs::openat(dirfd.raw(), &path("log"), fs::O_RDWR | fs::O_CREAT | O_APPEND | fs::O_CLOEXEC, 0o644)?;
        let mut data = Vec::new();
        fs::read_to_end(log.raw(), &mut data, READ_LIMIT)?;
        let good = st.replay_log(&data)?;
        if good < data.len() {
            // Torn tail: a crash during append. Drop it so new records follow valid ones.
            fs::ftruncate(log.raw(), good as u64)?;
            fs::fsync(log.raw())?;
        }
        if !existed {
            fs::fsync(dirfd.raw())?;
        }
        st.hist_floor = st.rev;
        st.persist = Some(Persist { dir: dirfd, log, buf: Vec::new(), log_len: good as u64 });
        Ok(st)
    }

    fn load_snapshot(&mut self, data: &[u8]) -> Result<(), Error> {
        if data.len() < 16 || &data[..8] != wal::SNAP_MAGIC {
            return Err(Error::Corrupt("bad snapshot header"));
        }
        let mut r = [0u8; 8];
        r.copy_from_slice(&data[8..16]);
        let rev = u64::from_le_bytes(r);
        let mut off = 16;
        while off < data.len() {
            match wal::parse(data, off) {
                Parsed::Rec(rec) => {
                    if rec.op != OP_PUT || rec.rev > rev {
                        return Err(Error::Corrupt("bad snapshot record"));
                    }
                    self.raw_put(rec.key, rec.val, rec.create_rev, rec.rev);
                    off = rec.end;
                }
                Parsed::Torn => return Err(Error::Corrupt("truncated snapshot")),
                Parsed::Corrupt(m) => return Err(Error::Corrupt(m)),
            }
        }
        self.rev = rev;
        Ok(())
    }

    /// Applies log records; returns the length of the valid prefix.
    fn replay_log(&mut self, data: &[u8]) -> Result<usize, Error> {
        let mut off = 0;
        while off < data.len() {
            match wal::parse(data, off) {
                Parsed::Rec(rec) => {
                    off = rec.end;
                    if rec.rev <= self.rev {
                        continue; // already covered by the snapshot
                    }
                    if rec.rev != self.rev + 1 {
                        return Err(Error::Corrupt("log revision gap"));
                    }
                    if rec.op == OP_PUT {
                        self.raw_put(rec.key, rec.val, rec.create_rev, rec.rev);
                    } else {
                        self.raw_delete(rec.key);
                    }
                    self.rev = rec.rev;
                }
                Parsed::Torn => break,
                Parsed::Corrupt(m) => return Err(Error::Corrupt(m)),
            }
        }
        Ok(off)
    }

    fn kv_size(key: &str, val: &[u8]) -> u64 {
        (RECORD_OVERHEAD + key.len() + val.len()) as u64
    }

    fn raw_put(&mut self, key: &str, val: &[u8], create_rev: u64, mod_rev: u64) {
        let k: Rc<str> = Rc::from(key);
        let kv = Kv { key: k.clone(), value: Rc::from(val), create_rev, mod_rev };
        self.live_bytes += Self::kv_size(key, val);
        if let Some(old) = self.map.insert(k, kv) {
            self.live_bytes -= Self::kv_size(&old.key, &old.value);
        }
    }

    fn raw_delete(&mut self, key: &str) {
        if let Some(old) = self.map.remove(key) {
            self.live_bytes -= Self::kv_size(&old.key, &old.value);
        }
    }

    pub fn revision(&self) -> u64 {
        self.rev
    }

    /// When true every mutation is followed by `sync()`.
    /// Logs smaller than `bytes` are never rewritten by [`Store::compact`] (default 8 MiB).
    pub fn set_compact_min(&mut self, bytes: u64) {
        self.compact_min = bytes;
    }

    pub fn set_auto_sync(&mut self, on: bool) {
        self.auto_sync = on;
    }

    /// Changes how many events are retained for watch replay (default [`DEFAULT_HISTORY`]).
    pub fn set_history_limit(&mut self, n: usize) {
        self.hist_cap = n;
        self.trim_history();
    }

    /// Number of live (not dropped) watchers.
    pub fn watcher_count(&mut self) -> usize {
        self.watchers.retain(|w| w.strong_count() > 0);
        self.watchers.len()
    }

    pub fn get(&self, key: &str) -> Option<Kv> {
        self.map.get(key).cloned()
    }

    fn range_from<'a>(&'a self, prefix: &'a str, start_after: Option<&'a str>) -> impl Iterator<Item = &'a Kv> + 'a {
        let lo = match start_after {
            Some(s) if s >= prefix => Bound::Excluded(s),
            _ => Bound::Included(prefix),
        };
        self.map.range::<str, _>((lo, Bound::Unbounded)).map(|(_, v)| v).take_while(move |kv| kv.key.starts_with(prefix))
    }

    /// Keys with `prefix`, sorted, strictly after `start_after`, at most `limit` (0 = unlimited).
    /// Returns `(items, has_more)`.
    pub fn list(&self, prefix: &str, start_after: Option<&str>, limit: usize) -> (Vec<Kv>, bool) {
        let mut it = self.range_from(prefix, start_after);
        let mut out = Vec::new();
        while limit == 0 || out.len() < limit {
            match it.next() {
                Some(kv) => out.push(kv.clone()),
                None => return (out, false),
            }
        }
        (out, it.next().is_some())
    }

    pub fn count(&self, prefix: &str) -> usize {
        self.range_from(prefix, None).count()
    }

    fn check(key: &str, value: &[u8]) -> Result<(), Error> {
        if key.len() > MAX_KEY || value.len() > MAX_VALUE {
            return Err(Error::TooLarge);
        }
        Ok(())
    }

    pub fn create(&mut self, key: &str, value: Vec<u8>) -> Result<Kv, Error> {
        Self::check(key, &value)?;
        if self.map.contains_key(key) {
            return Err(Error::Exists);
        }
        let rev = self.rev + 1;
        self.commit(EventKind::Put, Rc::from(key), Rc::from(value), rev, None)
    }

    pub fn update(&mut self, key: &str, value: Vec<u8>, expect_mod_rev: Option<u64>) -> Result<Kv, Error> {
        Self::check(key, &value)?;
        let prev = self.map.get(key).cloned().ok_or(Error::NotFound)?;
        if let Some(e) = expect_mod_rev {
            if e != prev.mod_rev {
                return Err(Error::Conflict { current_rev: prev.mod_rev });
            }
        }
        let create_rev = prev.create_rev;
        self.commit(EventKind::Put, prev.key.clone(), Rc::from(value), create_rev, Some(prev))
    }

    /// Deletes `key`, returning the previous kv.
    pub fn delete(&mut self, key: &str, expect_mod_rev: Option<u64>) -> Result<Kv, Error> {
        let prev = self.map.get(key).cloned().ok_or(Error::NotFound)?;
        if let Some(e) = expect_mod_rev {
            if e != prev.mod_rev {
                return Err(Error::Conflict { current_rev: prev.mod_rev });
            }
        }
        let create_rev = prev.create_rev;
        let value = prev.value.clone();
        let k = prev.key.clone();
        self.commit(EventKind::Delete, k, value, create_rev, Some(prev.clone()))?;
        Ok(prev)
    }

    /// Applies one mutation at revision `self.rev + 1`. `create_rev` is only meaningful for puts
    /// of existing keys and deletes; for a new key pass the new revision.
    fn commit(
        &mut self,
        kind: EventKind,
        key: Rc<str>,
        value: Rc<[u8]>,
        create_rev: u64,
        prev: Option<Kv>,
    ) -> Result<Kv, Error> {
        let rev = self.rev + 1;
        for buf in [self.persist.as_mut().map(|p| &mut p.buf), self.repl.as_mut()].into_iter().flatten() {
            match kind {
                EventKind::Put => wal::encode(buf, OP_PUT, rev, create_rev, &key, &value),
                EventKind::Delete => wal::encode(buf, OP_DELETE, rev, create_rev, &key, &[]),
            }
        }
        let kv = self.apply_event(kind, key, value, create_rev, prev);
        if self.auto_sync {
            self.sync()?;
        }
        Ok(kv)
    }

    /// The in-memory effect of one mutation at `self.rev + 1`, plus its watch event.
    fn apply_event(&mut self, kind: EventKind, key: Rc<str>, value: Rc<[u8]>, create_rev: u64, prev: Option<Kv>) -> Kv {
        let rev = self.rev + 1;
        let kv = Kv { key: key.clone(), value: value.clone(), create_rev, mod_rev: rev };
        match kind {
            EventKind::Put => {
                self.live_bytes += Self::kv_size(&key, &value);
                if let Some(old) = self.map.insert(key, kv.clone()) {
                    self.live_bytes -= Self::kv_size(&old.key, &old.value);
                }
            }
            EventKind::Delete => self.raw_delete(&key),
        }
        self.rev = rev;
        let ev = Event { kind, kv: kv.clone(), prev, rev };
        if rev > self.visible {
            self.held.push_back(ev.clone());
        } else {
            self.notify(&ev);
        }
        self.history.push_back(ev);
        self.trim_history();
        kv
    }

    fn trim_history(&mut self) {
        while self.history.len() > self.hist_cap {
            if let Some(e) = self.history.pop_front() {
                self.hist_floor = e.rev;
            }
        }
    }

    fn notify(&mut self, ev: &Event) {
        let mut wake = Vec::new();
        self.watchers.retain(|w| {
            let Some(rc) = w.upgrade() else { return false };
            let mut s = rc.borrow_mut();
            if s.closed {
                return false;
            }
            if ev.kv.key.starts_with(s.prefix.as_str()) {
                s.queue.push_back(ev.clone());
                if s.queue.len() > QUEUE_LIMIT {
                    s.queue.clear();
                    s.closed = true;
                    s.overflowed = true;
                }
                if let Some(wk) = s.waker.take() {
                    wake.push(wk);
                }
                if s.closed {
                    return false;
                }
            }
            true
        });
        for w in wake {
            w.wake();
        }
    }

    /// Events with `rev > after_rev` on keys under `prefix`: replayed from history, then live.
    pub fn watch(&mut self, prefix: &str, after_rev: u64) -> Result<Watcher, Error> {
        if after_rev < self.hist_floor {
            return Err(Error::Compacted { oldest: self.hist_floor + 1 });
        }
        let mut queue = VecDeque::new();
        // Only visible (committed) events; held ones are delivered to every watcher on release.
        for e in self.history.iter().filter(|e| e.rev > after_rev && e.rev <= self.visible && e.kv.key.starts_with(prefix)) {
            queue.push_back(e.clone());
        }
        let state = Rc::new(RefCell::new(WatchState {
            prefix: String::from(prefix),
            queue,
            waker: None,
            closed: false,
            overflowed: false,
        }));
        self.watchers.retain(|w| w.strong_count() > 0);
        self.watchers.push(Rc::downgrade(&state));
        Ok(Watcher { state })
    }

    /// Writes buffered records and fsyncs the log. Call before acknowledging writes.
    pub fn sync(&mut self) -> Result<(), Error> {
        let had = self.persist.as_ref().is_some_and(|p| !p.buf.is_empty());
        self.write_out()?;
        if let (true, Some(p)) = (had, &self.persist) {
            fs::fsync(p.log.raw())?;
        }
        Ok(())
    }

    /// Writes buffered records to the log without fsync (page cache only); a caller that
    /// acknowledges writes must make [`Store::log_fd`] durable first (e.g. fsync elsewhere,
    /// off the event loop). Returns the revision now in the log.
    pub fn write_out(&mut self) -> Result<u64, Error> {
        let Some(p) = &mut self.persist else { return Ok(self.rev) };
        if !p.buf.is_empty() {
            if let Err(e) = fs::write_all(p.log.raw(), &p.buf) {
                // Remove any partial write so a retry does not duplicate bytes.
                let _ = fs::ftruncate(p.log.raw(), p.log_len);
                return Err(e.into());
            }
            p.log_len += p.buf.len() as u64;
            p.buf.clear();
        }
        Ok(self.rev)
    }

    /// The log file descriptor (None for an in-memory store). Stable across compactions.
    pub fn log_fd(&self) -> Option<i32> {
        self.persist.as_ref().map(|p| p.log.raw())
    }

    /// Whether the log has grown enough that [`Store::compact`] would rewrite it.
    pub fn log_oversized(&self) -> bool {
        self.persist.as_ref().is_some_and(|p| {
            let size = p.log_len + p.buf.len() as u64;
            size > self.compact_min && size > 4 * self.live_bytes
        })
    }

    /// Drops history with `rev <= rev` (watch replay limit), then rewrites the log into a snapshot
    /// if the log is much larger than the live data.
    pub fn compact(&mut self, rev: u64) -> Result<(), Error> {
        let rev = rev.min(self.rev);
        while self.history.front().is_some_and(|e| e.rev <= rev) {
            self.history.pop_front();
        }
        self.hist_floor = self.hist_floor.max(rev);
        if let Some(p) = &self.persist {
            let size = p.log_len + p.buf.len() as u64;
            if size > self.compact_min && size > 4 * self.live_bytes {
                self.rewrite_log()?;
            }
        }
        Ok(())
    }

    /// Unconditionally writes a snapshot of the live data and empties the log.
    pub fn rewrite_log(&mut self) -> Result<(), Error> {
        if self.persist.is_none() {
            return Ok(());
        }
        self.sync()?;
        let snap = self.image();
        let Some(p) = &mut self.persist else { return Ok(()) };
        let d = p.dir.raw();
        {
            let tmp = fs::openat(d, &path("snapshot.tmp"), fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC | fs::O_CLOEXEC, 0o644)?;
            fs::write_all(tmp.raw(), &snap)?;
            fs::fsync(tmp.raw())?;
        }
        fs::renameat2(d, &path("snapshot.tmp"), d, &path("snapshot"), 0)?;
        fs::fsync(d)?;
        fs::ftruncate(p.log.raw(), 0)?;
        fs::fsync(p.log.raw())?;
        p.log_len = 0;
        Ok(())
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        let mut wake = Vec::new();
        for w in &self.watchers {
            if let Some(rc) = w.upgrade() {
                let mut s = rc.borrow_mut();
                s.closed = true;
                if let Some(wk) = s.waker.take() {
                    wake.push(wk);
                }
            }
        }
        for w in wake {
            w.wake();
        }
    }
}

#[cfg(test)]
mod tests;
