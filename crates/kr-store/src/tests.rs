use super::*;
use std::cell::RefCell as StdRefCell;
use std::format;
use std::rc::Rc as StdRc;
use std::string::ToString;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::vec;

static N: AtomicUsize = AtomicUsize::new(0);

fn tmpdir(name: &str) -> std::string::String {
    let p = std::env::temp_dir().join(format!("kr-store-{}-{}-{}", std::process::id(), name, N.fetch_add(1, Ordering::SeqCst)));
    let _ = std::fs::remove_dir_all(&p);
    p.to_str().unwrap().to_string()
}

fn v(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

#[test]
fn crud_and_revisions() {
    let mut s = Store::in_memory();
    assert_eq!(s.revision(), 0);
    assert!(s.get("/a").is_none());
    let a = s.create("/a", v("1")).unwrap();
    assert_eq!((a.create_rev, a.mod_rev), (1, 1));
    assert_eq!(s.create("/a", v("x")).err(), Some(Error::Exists));
    assert_eq!(s.revision(), 1, "failed create must not bump revision");
    let b = s.create("/b", v("2")).unwrap();
    assert_eq!((b.create_rev, b.mod_rev), (2, 2));
    let a2 = s.update("/a", v("11"), None).unwrap();
    assert_eq!((a2.create_rev, a2.mod_rev), (1, 3));
    assert_eq!(&*s.get("/a").unwrap().value, b"11");
    assert_eq!(s.update("/zz", v("x"), None).err(), Some(Error::NotFound));
    assert_eq!(s.update("/a", v("x"), Some(1)).err(), Some(Error::Conflict { current_rev: 3 }));
    assert_eq!(s.revision(), 3);
    let a3 = s.update("/a", v("111"), Some(3)).unwrap();
    assert_eq!(a3.mod_rev, 4);
    assert_eq!(s.delete("/a", Some(3)).err(), Some(Error::Conflict { current_rev: 4 }));
    let prev = s.delete("/a", Some(4)).unwrap();
    assert_eq!((&*prev.value, prev.mod_rev, prev.create_rev), (&b"111"[..], 4, 1));
    assert_eq!(s.revision(), 5);
    assert_eq!(s.delete("/a", None).err(), Some(Error::NotFound));
    assert_eq!(s.revision(), 5);
    // recreate gets a fresh create_rev
    let a4 = s.create("/a", v("again")).unwrap();
    assert_eq!((a4.create_rev, a4.mod_rev), (6, 6));
}

#[test]
fn limits() {
    let mut s = Store::in_memory();
    let big_key = "k".repeat(MAX_KEY + 1);
    assert_eq!(s.create(&big_key, v("x")).err(), Some(Error::TooLarge));
    assert_eq!(s.create("/k", vec![0; MAX_VALUE + 1]).err(), Some(Error::TooLarge));
    assert_eq!(s.revision(), 0);
    s.create(&"k".repeat(MAX_KEY), vec![0; MAX_VALUE]).unwrap();
    assert_eq!(s.update("/k", vec![0; MAX_VALUE + 1], None).err(), Some(Error::TooLarge));
    assert_eq!(s.revision(), 1);
}

fn keys(items: &[Kv]) -> Vec<std::string::String> {
    items.iter().map(|k| k.key.to_string()).collect()
}

#[test]
fn list_prefix_and_pagination() {
    let mut s = Store::in_memory();
    for k in ["/a/1", "/a/2", "/a/3", "/a/4", "/b/1", "/ab/1", "/c"] {
        s.create(k, v(k)).unwrap();
    }
    let (all, more) = s.list("/a/", None, 0);
    assert_eq!(keys(&all), ["/a/1", "/a/2", "/a/3", "/a/4"]);
    assert!(!more);
    assert_eq!(s.count("/a/"), 4);
    assert_eq!(s.count("/a"), 5);
    assert_eq!(s.count(""), 7);
    assert_eq!(s.count("/zzz"), 0);

    let (p1, more) = s.list("/a/", None, 2);
    assert_eq!(keys(&p1), ["/a/1", "/a/2"]);
    assert!(more);
    let (p2, more) = s.list("/a/", Some("/a/2"), 2);
    assert_eq!(keys(&p2), ["/a/3", "/a/4"]);
    assert!(!more, "exactly limit remaining means no more");
    let (p3, more) = s.list("/a/", Some("/a/4"), 2);
    assert!(p3.is_empty() && !more);
    // start_after need not exist, and may lie before the prefix
    let (p, _) = s.list("/a/", Some("/a/25"), 0);
    assert_eq!(keys(&p), ["/a/3", "/a/4"]);
    let (p, _) = s.list("/a/", Some("/"), 1);
    assert_eq!(keys(&p), ["/a/1"]);
    // start_after beyond the prefix range
    let (p, more) = s.list("/a/", Some("/b"), 0);
    assert!(p.is_empty() && !more);
    // deleted keys vanish
    s.delete("/a/2", None).unwrap();
    assert_eq!(s.count("/a/"), 3);
    // full pagination walk
    let mut after: Option<std::string::String> = None;
    let mut seen = Vec::new();
    loop {
        let (items, more) = s.list("", after.as_deref(), 3);
        seen.extend(keys(&items));
        if !more {
            break;
        }
        after = Some(items.last().unwrap().key.to_string());
    }
    assert_eq!(seen.len(), 6);
    let mut sorted = seen.clone();
    sorted.sort();
    assert_eq!(seen, sorted);
}

#[test]
fn watch_live_and_prefix_filter() {
    let mut s = Store::in_memory();
    let mut w = s.watch("/a/", 0).unwrap();
    let mut all = s.watch("", 0).unwrap();
    assert!(w.try_next().is_none());
    s.create("/a/1", v("x")).unwrap();
    s.create("/b/1", v("y")).unwrap();
    s.update("/a/1", v("z"), None).unwrap();
    s.delete("/a/1", None).unwrap();
    let e = w.try_next().unwrap();
    assert_eq!((e.kind, e.rev, e.prev.is_none()), (EventKind::Put, 1, true));
    let e = w.try_next().unwrap();
    assert_eq!((e.kind, e.rev), (EventKind::Put, 3));
    assert_eq!(&*e.prev.unwrap().value, b"x");
    let e = w.try_next().unwrap();
    assert_eq!((e.kind, e.rev, e.kv.mod_rev, e.kv.create_rev), (EventKind::Delete, 4, 4, 1));
    assert_eq!(&*e.kv.value, b"z");
    assert_eq!(&*e.prev.unwrap().value, b"z");
    assert!(w.try_next().is_none());
    let mut n = 0;
    while all.try_next().is_some() {
        n += 1;
    }
    assert_eq!(n, 4);
}

#[test]
fn watch_replay_and_compacted() {
    let mut s = Store::in_memory();
    for i in 0..10 {
        s.create(&format!("/k/{i}"), v("x")).unwrap();
    }
    let mut w = s.watch("/k/", 7).unwrap();
    let revs: Vec<u64> = core::iter::from_fn(|| w.try_next()).map(|e| e.rev).collect();
    assert_eq!(revs, [8, 9, 10]);
    // after_rev == current: nothing replayed, then live
    let mut w = s.watch("/k/", 10).unwrap();
    assert!(w.try_next().is_none());
    s.create("/k/new", v("x")).unwrap();
    assert_eq!(w.try_next().unwrap().rev, 11);
    // full replay from 0
    let mut w = s.watch("", 0).unwrap();
    assert_eq!(core::iter::from_fn(|| w.try_next()).count(), 11);

    s.compact(5).unwrap();
    assert_eq!(s.watch("", 3).err(), Some(Error::Compacted { oldest: 6 }));
    assert!(s.watch("", 5).is_ok());
    let mut w = s.watch("", 5).unwrap();
    assert_eq!(w.try_next().unwrap().rev, 6);
    // compacting beyond current clamps
    s.compact(1000).unwrap();
    assert_eq!(s.watch("", 10).err(), Some(Error::Compacted { oldest: 12 }));
    assert!(s.watch("", 11).is_ok());
}

#[test]
fn history_limit_bounds_replay() {
    let mut s = Store::in_memory();
    s.set_history_limit(3);
    for i in 0..10 {
        s.create(&format!("/k/{i}"), v("x")).unwrap();
    }
    assert_eq!(s.watch("", 6).err(), Some(Error::Compacted { oldest: 8 }));
    let mut w = s.watch("", 7).unwrap();
    let revs: Vec<u64> = core::iter::from_fn(|| w.try_next()).map(|e| e.rev).collect();
    assert_eq!(revs, [8, 9, 10]);
}

#[test]
fn watch_overflow_closes() {
    let mut s = Store::in_memory();
    let mut slow = s.watch("", 0).unwrap();
    let mut fast = s.watch("", 0).unwrap();
    for i in 0..(watch::QUEUE_LIMIT + 1) {
        s.create(&format!("/k/{i}"), v("x")).unwrap();
        if i % 100 == 0 {
            while fast.try_next().is_some() {}
        }
    }
    assert!(slow.overflowed());
    assert!(slow.try_next().is_none(), "queue discarded on overflow");
    assert!(!fast.overflowed());
    // overflowed watcher is unregistered; the fast one remains
    assert_eq!(s.watcher_count(), 1);
    s.create("/after", v("x")).unwrap();
    assert!(fast.try_next().is_some());
}

#[test]
fn watcher_drop_unregisters() {
    let mut s = Store::in_memory();
    let w1 = s.watch("", 0).unwrap();
    let w2 = s.watch("/a", 0).unwrap();
    assert_eq!(s.watcher_count(), 2);
    drop(w1);
    assert_eq!(s.watcher_count(), 1);
    drop(w2);
    s.create("/a", v("x")).unwrap();
    assert_eq!(s.watcher_count(), 0);
}

struct CountWake(AtomicUsize);
impl std::task::Wake for CountWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn async_next_manual_poll_and_wake() {
    use core::future::Future;
    use core::task::{Context, Poll, Waker};
    let mut s = Store::in_memory();
    let mut w = s.watch("/a", 0).unwrap();
    let cw = Arc::new(CountWake(AtomicUsize::new(0)));
    let waker = Waker::from(cw.clone());
    let mut cx = Context::from_waker(&waker);
    {
        let mut fut = std::pin::pin!(w.next());
        assert!(fut.as_mut().poll(&mut cx).is_pending());
        s.create("/b", v("x")).unwrap();
        assert_eq!(cw.0.load(Ordering::SeqCst), 0, "non-matching event must not wake");
        s.create("/a", v("x")).unwrap();
        assert_eq!(cw.0.load(Ordering::SeqCst), 1);
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(Some(e)) => assert_eq!(e.rev, 2),
            _ => panic!("expected event"),
        }
    }
    // store dropped: pending next resolves to None and is woken
    let mut fut = std::pin::pin!(w.next());
    assert!(fut.as_mut().poll(&mut cx).is_pending());
    drop(s);
    assert_eq!(cw.0.load(Ordering::SeqCst), 2);
    assert!(matches!(fut.as_mut().poll(&mut cx), Poll::Ready(None)));
}

#[test]
fn async_next_with_executor() {
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll};
    struct Yield(bool);
    impl Future for Yield {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.0 {
                return Poll::Ready(());
            }
            self.0 = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
    let store = StdRc::new(StdRefCell::new(Store::in_memory()));
    let got = StdRc::new(StdRefCell::new(Vec::new()));
    let (st, g) = (store.clone(), got.clone());
    kr_rt::exec::block_on(async move {
        let mut w = st.borrow_mut().watch("/p/", 0).unwrap();
        let st2 = st.clone();
        let producer = kr_rt::exec::spawn(async move {
            for i in 0..3 {
                Yield(false).await;
                st2.borrow_mut().create(&format!("/p/{i}"), v("x")).unwrap();
            }
        });
        for _ in 0..3 {
            let e = w.next().await.unwrap();
            g.borrow_mut().push(e.rev);
        }
        let _ = producer.await;
    });
    assert_eq!(*got.borrow(), [1, 2, 3]);
}

// ---- persistence ----

fn log_path(d: &str) -> std::string::String {
    format!("{d}/log")
}

#[test]
fn reopen_preserves_data() {
    let d = tmpdir("reopen");
    {
        let mut s = Store::open(&d).unwrap();
        assert_eq!(s.revision(), 0);
        s.create("/a", v("1")).unwrap();
        s.create("/b", v("2")).unwrap();
        s.update("/a", v("11"), None).unwrap();
        s.delete("/b", None).unwrap();
        s.create("/c", v("3")).unwrap();
        s.sync().unwrap();
    }
    let mut s = Store::open(&d).unwrap();
    assert_eq!(s.revision(), 5);
    let a = s.get("/a").unwrap();
    assert_eq!((&*a.value, a.create_rev, a.mod_rev), (&b"11"[..], 1, 3));
    assert!(s.get("/b").is_none());
    assert_eq!(s.get("/c").unwrap().mod_rev, 5);
    // history is not persisted
    assert_eq!(s.watch("", 0).err(), Some(Error::Compacted { oldest: 6 }));
    s.create("/d", v("4")).unwrap();
    s.sync().unwrap();
    drop(s);
    let s = Store::open(&d).unwrap();
    assert_eq!((s.revision(), s.count("")), (6, 3));
}

#[test]
fn unsynced_writes_are_not_durable_and_auto_sync_is() {
    let d = tmpdir("nosync");
    {
        let mut s = Store::open(&d).unwrap();
        s.create("/a", v("1")).unwrap();
        s.sync().unwrap();
        s.create("/b", v("2")).unwrap(); // never synced
    }
    assert_eq!(Store::open(&d).unwrap().revision(), 1);
    let d = tmpdir("autosync");
    {
        let mut s = Store::open(&d).unwrap();
        s.set_auto_sync(true);
        s.create("/a", v("1")).unwrap();
        s.create("/b", v("2")).unwrap();
    }
    assert_eq!(Store::open(&d).unwrap().revision(), 2);
}

#[test]
fn creates_nested_dir() {
    let d = format!("{}/x/y/z", tmpdir("nested"));
    let mut s = Store::open(&d).unwrap();
    s.set_auto_sync(true);
    s.create("/a", v("1")).unwrap();
    drop(s);
    assert_eq!(Store::open(&d).unwrap().revision(), 1);
}

#[test]
fn torn_tail_at_every_offset() {
    let d = tmpdir("torn");
    let mut sizes = Vec::new();
    {
        let mut s = Store::open(&d).unwrap();
        s.set_auto_sync(true);
        for i in 0..4 {
            s.create(&format!("/k/{i}"), vec![i as u8; 20 + i]).unwrap();
            sizes.push(std::fs::metadata(log_path(&d)).unwrap().len() as usize);
        }
    }
    let full = std::fs::read(log_path(&d)).unwrap();
    let last_start = sizes[2];
    assert_eq!(full.len(), sizes[3]);
    for cut in last_start..full.len() {
        let dd = tmpdir("torn-case");
        std::fs::create_dir_all(&dd).unwrap();
        std::fs::write(log_path(&dd), &full[..cut]).unwrap();
        let mut s = Store::open(&dd).unwrap_or_else(|_| panic!("open failed at cut {cut}"));
        assert_eq!(s.revision(), 3, "cut {cut}");
        assert_eq!(s.count(""), 3);
        assert!(s.get("/k/3").is_none());
        assert_eq!(&*s.get("/k/2").unwrap().value, &[2u8; 22][..]);
        // torn bytes were removed so a new append is clean
        assert_eq!(std::fs::metadata(log_path(&dd)).unwrap().len() as usize, last_start, "cut {cut}");
        s.create("/k/new", v("n")).unwrap();
        s.sync().unwrap();
        drop(s);
        let s = Store::open(&dd).unwrap();
        assert_eq!((s.revision(), s.count("")), (4, 4));
    }
    // CRC failure in the final record (full length) is also a torn tail
    let mut bad = full.clone();
    let n = bad.len();
    bad[n - 1] ^= 0xff;
    let dd = tmpdir("torn-crc");
    std::fs::create_dir_all(&dd).unwrap();
    std::fs::write(log_path(&dd), &bad).unwrap();
    assert_eq!(Store::open(&dd).unwrap().revision(), 3);
    // garbage shorter than a header
    let mut g = full.clone();
    g.extend_from_slice(&[1, 2, 3]);
    std::fs::write(log_path(&dd), &g).unwrap();
    assert_eq!(Store::open(&dd).unwrap().revision(), 4);
}

#[test]
fn flipped_byte_mid_log_is_corrupt() {
    let d = tmpdir("corrupt");
    let first_end;
    {
        let mut s = Store::open(&d).unwrap();
        s.set_auto_sync(true);
        s.create("/a", v("aaaaaaaa")).unwrap();
        first_end = std::fs::metadata(log_path(&d)).unwrap().len() as usize;
        s.create("/b", v("bbbbbbbb")).unwrap();
        s.create("/c", v("cccccccc")).unwrap();
    }
    let full = std::fs::read(log_path(&d)).unwrap();
    // flip each payload byte of the first and second record
    for idx in (8..first_end).chain(first_end + 8..first_end * 2) {
        let mut bad = full.clone();
        bad[idx] ^= 0x01;
        std::fs::write(log_path(&d), &bad).unwrap();
        match Store::open(&d).err() {
            Some(Error::Corrupt(_)) => {}
            other => panic!("byte {idx}: expected Corrupt, got {other:?}"),
        }
    }
    // flipping a CRC byte of a middle record too
    let mut bad = full.clone();
    bad[first_end + 4] ^= 0x80;
    std::fs::write(log_path(&d), &bad).unwrap();
    assert!(matches!(Store::open(&d).err(), Some(Error::Corrupt(_))));
}

#[test]
fn snapshot_round_trip_and_log_reset() {
    let d = tmpdir("snap");
    {
        let mut s = Store::open(&d).unwrap();
        s.set_auto_sync(true);
        s.create("/a", v("1")).unwrap();
        s.create("/b", v("2")).unwrap();
        s.update("/a", v("11"), None).unwrap();
        s.delete("/b", None).unwrap();
        s.create("/c", v("3")).unwrap();
        s.rewrite_log().unwrap();
        assert_eq!(std::fs::metadata(log_path(&d)).unwrap().len(), 0);
        assert!(std::fs::metadata(format!("{d}/snapshot")).is_ok());
        assert!(std::fs::metadata(format!("{d}/snapshot.tmp")).is_err());
        s.create("/d", v("4")).unwrap(); // post-snapshot log record
    }
    let s = Store::open(&d).unwrap();
    assert_eq!(s.revision(), 6);
    assert_eq!(s.count(""), 3);
    let a = s.get("/a").unwrap();
    assert_eq!((&*a.value, a.create_rev, a.mod_rev), (&b"11"[..], 1, 3));
    assert_eq!(s.get("/c").unwrap().mod_rev, 5);
    assert_eq!(s.get("/d").unwrap().mod_rev, 6);
    assert_eq!(std::fs::read(format!("{d}/snapshot")).unwrap()[..8], *b"KRSNAP1\0");
}

#[test]
fn crash_between_snapshot_rename_and_log_truncate() {
    let d = tmpdir("crash");
    let old_log;
    {
        let mut s = Store::open(&d).unwrap();
        s.set_auto_sync(true);
        s.create("/a", v("1")).unwrap();
        s.update("/a", v("2"), None).unwrap();
        s.create("/b", v("3")).unwrap();
        s.delete("/b", None).unwrap();
        old_log = std::fs::read(log_path(&d)).unwrap();
        s.rewrite_log().unwrap();
    }
    // Simulate the crash: snapshot in place, log not yet truncated.
    std::fs::write(log_path(&d), &old_log).unwrap();
    let mut s = Store::open(&d).unwrap();
    assert_eq!(s.revision(), 4);
    assert_eq!(s.count(""), 1);
    assert_eq!(&*s.get("/a").unwrap().value, b"2");
    assert_eq!(s.get("/a").unwrap().create_rev, 1);
    // new writes continue seamlessly after the stale prefix
    s.set_auto_sync(true);
    s.create("/c", v("4")).unwrap();
    drop(s);
    let s = Store::open(&d).unwrap();
    assert_eq!((s.revision(), s.count("")), (5, 2));
    // stale snapshot.tmp from a crash before rename is ignored and removed
    std::fs::write(format!("{d}/snapshot.tmp"), b"garbage").unwrap();
    drop(s);
    let s = Store::open(&d).unwrap();
    assert_eq!(s.revision(), 5);
    assert!(std::fs::metadata(format!("{d}/snapshot.tmp")).is_err());
}

#[test]
fn compact_rewrites_large_log() {
    let d = tmpdir("compact");
    let mut s = Store::open(&d).unwrap();
    s.set_compact_min(64 * 1024);
    assert!(!s.log_oversized());
    for _ in 0..40 {
        s.update_or_create("/big", vec![7u8; 4096]);
    }
    s.sync().unwrap();
    let before = std::fs::metadata(log_path(&d)).unwrap().len();
    assert!(before > 64 * 1024);
    assert!(s.log_oversized());
    s.compact(s.revision()).unwrap();
    assert!(!s.log_oversized());
    assert_eq!(std::fs::metadata(log_path(&d)).unwrap().len(), 0);
    drop(s);
    let s = Store::open(&d).unwrap();
    assert_eq!(s.revision(), 40);
    assert_eq!(s.get("/big").unwrap().create_rev, 1);
    // small log: compact must not rewrite
    let d = tmpdir("compact-small");
    let mut s = Store::open(&d).unwrap();
    s.create("/a", v("1")).unwrap();
    s.sync().unwrap();
    s.compact(1).unwrap();
    assert!(std::fs::metadata(log_path(&d)).unwrap().len() > 0);
}

#[test]
fn corrupt_snapshot_and_gap_detected() {
    let d = tmpdir("badsnap");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(format!("{d}/snapshot"), b"nope").unwrap();
    assert!(matches!(Store::open(&d).err(), Some(Error::Corrupt(_))));

    // log with a revision gap
    let d = tmpdir("gap");
    {
        let mut s = Store::open(&d).unwrap();
        s.set_auto_sync(true);
        s.create("/a", v("1")).unwrap();
        s.create("/b", v("2")).unwrap();
        s.create("/c", v("3")).unwrap();
    }
    let full = std::fs::read(log_path(&d)).unwrap();
    let rec = full.len() / 3; // equal-sized records
    let mut gapped = full[..rec].to_vec();
    gapped.extend_from_slice(&full[2 * rec..]);
    std::fs::write(log_path(&d), &gapped).unwrap();
    assert_eq!(Store::open(&d).err(), Some(Error::Corrupt("log revision gap")));
}

impl Store {
    fn update_or_create(&mut self, k: &str, val: Vec<u8>) {
        if self.get(k).is_some() {
            self.update(k, val, None).unwrap();
        } else {
            self.create(k, val).unwrap();
        }
    }
}

#[test]
fn write_out_persists_without_fsync_and_reopens() {
    let d = tmpdir("writeout");
    let mut s = Store::open(&d).unwrap();
    s.create("/a", b"1".to_vec()).unwrap();
    let rev = s.write_out().unwrap();
    assert_eq!(rev, s.revision());
    assert!(s.log_fd().is_some());
    assert!(std::fs::metadata(log_path(&d)).unwrap().len() > 0);
    drop(s);
    let s = Store::open(&d).unwrap();
    assert_eq!(&*s.get("/a").unwrap().value, b"1");
    assert!(Store::in_memory().log_fd().is_none());
}

#[test]
fn replicated_leader_and_follower_converge() {
    let mut leader = Store::replicated();
    let mut follower = Store::replicated();
    leader.create("/a", b"1".to_vec()).unwrap();
    leader.create("/b", b"2".to_vec()).unwrap();
    let kv = leader.get("/a").unwrap();
    leader.update("/a", b"3".to_vec(), Some(kv.mod_rev)).unwrap();
    leader.delete("/b", None).unwrap();
    // A precondition failure produces no record.
    assert!(leader.update("/a", b"x".to_vec(), Some(1)).is_err());
    let recs = leader.take_records();
    assert!(leader.take_records().is_empty());
    assert_eq!(follower.apply_records(&recs).unwrap(), 4);
    assert_eq!(follower.revision(), leader.revision());
    assert_eq!(&*follower.get("/a").unwrap().value, b"3");
    assert_eq!(follower.get("/a").unwrap().create_rev, leader.get("/a").unwrap().create_rev);
    assert!(follower.get("/b").is_none());
    // The leader re-applying its own committed records is a no-op; applying records is not
    // re-captured (a follower that becomes leader must not re-propose them).
    assert_eq!(leader.apply_records(&recs).unwrap(), 4);
    assert!(follower.take_records().is_empty());
    // Records overlapping what a store already has: the known prefix is skipped.
    let mut src = Store::replicated();
    for i in 0..3 {
        src.create(&alloc::format!("/k{i}"), b"v".to_vec()).unwrap();
    }
    let all = src.take_records();
    let mut partial = Store::replicated();
    partial.create("/k0", b"v".to_vec()).unwrap();
    let first_len = partial.take_records().len();
    assert_eq!(partial.apply_records(&all).unwrap(), 3);
    // A gap (rev 2 onto an empty store) is refused.
    let mut empty = Store::replicated();
    assert!(matches!(empty.apply_records(&all[first_len..]), Err(Error::Corrupt(_))));
}

#[test]
fn watch_events_wait_for_commit() {
    let mut s = Store::replicated();
    let mut w = s.watch("/", 0).unwrap();
    s.create("/a", b"1".to_vec()).unwrap();
    s.create("/b", b"1".to_vec()).unwrap();
    assert!(w.try_next().is_none(), "uncommitted write must not be visible to watchers");
    // A watcher created while events are held must not see them early either, nor twice.
    let mut late = s.watch("/", 0).unwrap();
    assert!(late.try_next().is_none());
    s.set_visible(1);
    assert_eq!(w.try_next().unwrap().rev, 1);
    assert!(w.try_next().is_none());
    s.set_visible(2);
    assert_eq!(w.try_next().unwrap().rev, 2);
    assert_eq!(late.try_next().unwrap().rev, 1);
    assert_eq!(late.try_next().unwrap().rev, 2);
    assert!(late.try_next().is_none());
    // Non-replicated stores are not gated.
    let mut plain = Store::in_memory();
    let mut pw = plain.watch("/", 0).unwrap();
    plain.create("/a", b"1".to_vec()).unwrap();
    assert!(pw.try_next().is_some());
}

#[test]
fn image_restore_roundtrip_closes_watchers() {
    let mut a = Store::replicated();
    for i in 0..5 {
        a.create(&alloc::format!("/k{i}"), alloc::vec![i as u8]).unwrap();
    }
    a.delete("/k2", None).unwrap();
    let img = a.image();
    let mut b = Store::replicated();
    b.create("/junk", b"x".to_vec()).unwrap();
    let mut w = b.watch("/", 0).unwrap();
    b.restore(&img).unwrap();
    assert_eq!(b.revision(), 6);
    assert_eq!(b.list("/", None, 0).0.len(), 4);
    assert!(b.get("/junk").is_none());
    assert!(w.try_next().is_none() && w.overflowed(), "watchers must re-list after a restore");
    assert!(b.take_records().is_empty());
    assert!(matches!(b.watch("/", 3), Err(Error::Compacted { .. })));
}
