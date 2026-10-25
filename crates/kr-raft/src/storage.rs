//! On-disk Raft state (ADR-026), in a directory:
//!
//! * `log`: append-only entries, each `[u32 LE len][u32 LE crc32(payload)][payload]` with the
//!   payload from [`crate::codec::encode_entry`]. An in-memory offset index makes truncation
//!   (conflicting entries from an old leader) a single `ftruncate`. Appends are written without
//!   fsync: [`Storage::log_fd`] is fsynced by the caller (off the event loop, ADR-024) before
//!   anything that depends on the entries is sent.
//! * `hardstate`: term, vote, commit, replaced atomically (tmp + fsync + rename + dir fsync) only
//!   when the term or vote changes. A stale commit index after a crash is safe (it is learned
//!   again from the leader), so commit-only changes are not written.
//! * `snapshot`: `[u32 meta_len][meta][u32 crc32(meta ++ data)][data]`, replaced atomically; the
//!   log is then rewritten to hold only entries after the snapshot.
//!
//! Recovery: a torn final log record is cut off; a CRC failure anywhere else, or entries that are
//! not contiguous, is `Corrupt`.

use crate::codec;
use crate::{Entry, HardState, Snapshot};
use alloc::rc::Rc;
use alloc::vec::Vec;
use kr_archive::crc32::crc32;
use kr_sys::fs::{self, AT_FDCWD};
use kr_sys::{Errno, Fd};

const O_APPEND: i32 = 0o2000;
const MAX_RECORD: usize = 64 << 20;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Io(Errno),
    Corrupt(&'static str),
}

impl From<Errno> for Error {
    fn from(e: Errno) -> Error {
        Error::Io(e)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// What was on disk at open.
#[derive(Debug, Default)]
pub struct Loaded {
    pub hard_state: HardState,
    pub snapshot: Option<Snapshot>,
    pub entries: Vec<Entry>,
}

pub struct Storage {
    dir: Fd,
    log: Fd,
    /// (index, byte offset of its record) for every entry in `log`.
    offsets: Vec<(u64, u64)>,
    log_len: u64,
    hs: HardState,
}

fn cname(s: &str) -> Vec<u8> {
    let mut v = Vec::from(s.as_bytes());
    v.push(0);
    v
}

fn mkdir_p(dir: &str) -> Result<()> {
    let mut end = 0;
    loop {
        end = match dir[end..].find('/') {
            Some(0) if end == 0 => 1,
            Some(i) => end + i + 1,
            None => dir.len(),
        };
        let part = dir[..end].trim_end_matches('/');
        if !part.is_empty() {
            match fs::mkdirat(AT_FDCWD, &cname(part), 0o700) {
                Ok(()) | Err(Errno(fs::EEXIST)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        if end >= dir.len() {
            return Ok(());
        }
    }
}

fn frame(out: &mut Vec<u8>, payload: &[u8]) {
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&crc32(payload).to_le_bytes());
    out.extend_from_slice(payload);
}

fn read_all(dir: &Fd, name: &str) -> Result<Option<Vec<u8>>> {
    let fd = match fs::openat(dir.raw(), &cname(name), fs::O_RDONLY | fs::O_CLOEXEC, 0) {
        Ok(fd) => fd,
        Err(Errno(2)) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    fs::read_to_end(fd.raw(), &mut out, 1 << 31)?;
    Ok(Some(out))
}

/// Replaces `name` atomically and durably.
fn write_atomic(dir: &Fd, name: &str, data: &[u8]) -> Result<()> {
    let tmp = alloc::format!("{name}.tmp");
    {
        let fd = fs::openat(dir.raw(), &cname(&tmp), fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC | fs::O_CLOEXEC, 0o600)?;
        fs::write_all(fd.raw(), data)?;
        fs::fsync(fd.raw())?;
    }
    fs::renameat2(dir.raw(), &cname(&tmp), dir.raw(), &cname(name), 0)?;
    fs::fsync(dir.raw())?;
    Ok(())
}

fn decode_snapshot(b: &[u8]) -> Result<Snapshot> {
    let bad = Error::Corrupt("snapshot");
    if b.len() < 8 {
        return Err(bad);
    }
    let ml = u32::from_le_bytes(b[..4].try_into().unwrap()) as usize;
    if b.len() < 4 + ml + 4 {
        return Err(bad);
    }
    let meta_b = &b[4..4 + ml];
    let crc = u32::from_le_bytes(b[4 + ml..8 + ml].try_into().unwrap());
    let data = &b[8 + ml..];
    let mut chk = Vec::with_capacity(meta_b.len() + data.len());
    chk.extend_from_slice(meta_b);
    chk.extend_from_slice(data);
    if crc32(&chk) != crc {
        return Err(bad);
    }
    let meta = codec::decode_snapshot_meta(meta_b).ok_or(Error::Corrupt("snapshot meta"))?;
    Ok(Snapshot { meta, data: Rc::from(data) })
}

pub fn encode_snapshot(s: &Snapshot) -> Vec<u8> {
    let meta = codec::encode_snapshot_meta(&s.meta);
    let mut chk = Vec::with_capacity(meta.len() + s.data.len());
    chk.extend_from_slice(&meta);
    chk.extend_from_slice(&s.data);
    let mut out = Vec::with_capacity(8 + chk.len());
    out.extend_from_slice(&(meta.len() as u32).to_le_bytes());
    out.extend_from_slice(&meta);
    out.extend_from_slice(&crc32(&chk).to_le_bytes());
    out.extend_from_slice(&s.data);
    out
}

impl Storage {
    /// Opens (creating) the state in `dir` and returns what was persisted.
    pub fn open(dir: &str) -> Result<(Storage, Loaded)> {
        mkdir_p(dir)?;
        let dfd = fs::openat(AT_FDCWD, &cname(dir), fs::O_RDONLY | fs::O_DIRECTORY | fs::O_CLOEXEC, 0)?;
        for t in ["hardstate.tmp", "snapshot.tmp", "peers.tmp", "log.tmp.w", "log.tmp.w.tmp"] {
            let _ = fs::unlinkat(dfd.raw(), &cname(t), 0);
        }
        let hs = match read_all(&dfd, "hardstate")? {
            Some(b) => codec::decode_hard_state(&b).ok_or(Error::Corrupt("hardstate"))?,
            None => HardState::default(),
        };
        let snapshot = match read_all(&dfd, "snapshot")? {
            Some(b) => Some(decode_snapshot(&b)?),
            None => None,
        };
        let snap_index = snapshot.as_ref().map_or(0, |s| s.meta.index);
        let raw = read_all(&dfd, "log")?.unwrap_or_default();
        let (mut entries, mut offsets, mut pos) = (Vec::new(), Vec::new(), 0usize);
        while pos < raw.len() {
            let rest = &raw[pos..];
            if rest.len() < 8 {
                break; // torn header at the tail
            }
            let len = u32::from_le_bytes(rest[..4].try_into().unwrap()) as usize;
            let crc = u32::from_le_bytes(rest[4..8].try_into().unwrap());
            if len > MAX_RECORD {
                return Err(Error::Corrupt("log record length"));
            }
            if rest.len() < 8 + len {
                break; // torn payload at the tail
            }
            let payload = &rest[8..8 + len];
            if crc32(payload) != crc {
                // A bad CRC on the last record is a torn write; anywhere else is corruption.
                if pos + 8 + len == raw.len() {
                    break;
                }
                return Err(Error::Corrupt("log record crc"));
            }
            let e = codec::decode_entry(payload).ok_or(Error::Corrupt("log entry"))?;
            if let Some(prev) = entries.last().map(|x: &Entry| x.index) {
                if e.index != prev + 1 {
                    return Err(Error::Corrupt("log not contiguous"));
                }
            }
            offsets.push((e.index, pos as u64));
            entries.push(e);
            pos += 8 + len;
        }
        let log = fs::openat(dfd.raw(), &cname("log"), fs::O_RDWR | fs::O_CREAT | O_APPEND | fs::O_CLOEXEC, 0o600)?;
        if pos < raw.len() {
            fs::ftruncate(log.raw(), pos as u64)?;
            fs::fsync(log.raw())?;
        }
        // Entries covered by the snapshot (a crash between snapshot and log rewrite) are dropped.
        let keep_from = entries.iter().position(|e| e.index > snap_index).unwrap_or(entries.len());
        let entries: Vec<Entry> = entries.split_off(keep_from);
        let offsets = offsets.split_off(keep_from);
        if let (Some(first), true) = (entries.first(), snap_index > 0) {
            if first.index != snap_index + 1 {
                return Err(Error::Corrupt("gap between snapshot and log"));
            }
        }
        let st = Storage { dir: dfd, log, offsets, log_len: pos as u64, hs };
        Ok((st, Loaded { hard_state: hs, snapshot, entries }))
    }

    pub fn log_fd(&self) -> i32 {
        self.log.raw()
    }

    /// Removes entries with index >= `from` (conflict resolution). Durable once the log is
    /// fsynced.
    pub fn truncate(&mut self, from: u64) -> Result<()> {
        let Some(i) = self.offsets.iter().position(|(idx, _)| *idx >= from) else { return Ok(()) };
        let at = self.offsets[i].1;
        fs::ftruncate(self.log.raw(), at)?;
        self.offsets.truncate(i);
        self.log_len = at;
        Ok(())
    }

    /// Appends entries (written, not yet fsynced). They must continue the log.
    pub fn append(&mut self, entries: &[Entry]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        if let Some(&(last, _)) = self.offsets.last() {
            if entries[0].index != last + 1 {
                // Overwriting a suffix: callers truncate first; be strict.
                if entries[0].index <= last {
                    self.truncate(entries[0].index)?;
                } else {
                    return Err(Error::Corrupt("append leaves a gap"));
                }
            }
        }
        let mut buf = Vec::new();
        let mut payload = Vec::new();
        for e in entries {
            payload.clear();
            codec::encode_entry(&mut payload, e);
            self.offsets.push((e.index, self.log_len + buf.len() as u64));
            frame(&mut buf, &payload);
        }
        if let Err(e) = fs::write_all(self.log.raw(), &buf) {
            // Undo a partial write so the file matches the index.
            let _ = fs::ftruncate(self.log.raw(), self.log_len);
            let keep = self.offsets.len() - entries.len();
            self.offsets.truncate(keep);
            return Err(e.into());
        }
        self.log_len += buf.len() as u64;
        Ok(())
    }

    /// Persists the hard state if its term or vote changed (blocking: elections only).
    pub fn set_hard_state(&mut self, hs: HardState) -> Result<()> {
        if hs.term == self.hs.term && hs.vote == self.hs.vote {
            self.hs.commit = self.hs.commit.max(hs.commit);
            return Ok(());
        }
        write_atomic(&self.dir, "hardstate", &codec::encode_hard_state(&hs))?;
        self.hs = hs;
        Ok(())
    }

    /// Saves a snapshot durably and drops log entries it covers (log rewritten atomically).
    /// The driver's own small state next to the log (atomic replace): e.g. peer addresses,
    /// which must be known before the log is applied.
    pub fn save_extra(&mut self, name: &'static str, data: &[u8]) -> Result<()> {
        write_atomic(&self.dir, name, data)
    }

    pub fn load_extra(&self, name: &'static str) -> Result<Option<Vec<u8>>> {
        read_all(&self.dir, name)
    }

    pub fn save_snapshot(&mut self, s: &Snapshot) -> Result<()> {
        write_atomic(&self.dir, "snapshot", &encode_snapshot(s))?;
        self.compact_log(s.meta.index)
    }

    /// Rewrites the log to hold only entries with index > `after`.
    fn compact_log(&mut self, after: u64) -> Result<()> {
        let keep = self.offsets.iter().position(|(idx, _)| *idx > after);
        let Some(i) = keep else {
            // Nothing to keep: empty the log.
            fs::ftruncate(self.log.raw(), 0)?;
            fs::fsync(self.log.raw())?;
            self.offsets.clear();
            self.log_len = 0;
            return Ok(());
        };
        if i == 0 {
            return Ok(());
        }
        let start = self.offsets[i].1;
        let mut tail = Vec::new();
        {
            let fd = fs::openat(self.dir.raw(), &cname("log"), fs::O_RDONLY | fs::O_CLOEXEC, 0)?;
            let mut all = Vec::new();
            fs::read_to_end(fd.raw(), &mut all, 1 << 31)?;
            tail.extend_from_slice(&all[start as usize..self.log_len as usize]);
        }
        write_atomic(&self.dir, "log.tmp.w", &tail)?;
        fs::renameat2(self.dir.raw(), &cname("log.tmp.w"), self.dir.raw(), &cname("log"), 0)?;
        fs::fsync(self.dir.raw())?;
        self.log = fs::openat(self.dir.raw(), &cname("log"), fs::O_RDWR | O_APPEND | fs::O_CLOEXEC, 0)?;
        self.offsets = self.offsets[i..].iter().map(|(idx, off)| (*idx, off - start)).collect();
        self.log_len -= start;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EntryKind, SnapshotMeta};

    fn dir(tag: &str) -> alloc::string::String {
        let d = std::env::temp_dir().join(alloc::format!("kr-raft-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d.to_str().unwrap().into()
    }

    fn e(term: u64, index: u64) -> Entry {
        Entry { term, index, kind: EntryKind::Normal, data: alloc::vec![index as u8; (index % 7) as usize] }
    }

    #[test]
    fn append_truncate_reopen() {
        let d = dir("basic");
        let (mut s, l) = Storage::open(&d).unwrap();
        assert!(l.entries.is_empty() && l.snapshot.is_none());
        s.append(&(1..=10).map(|i| e(1, i)).collect::<Vec<_>>()).unwrap();
        s.truncate(7).unwrap();
        s.append(&[e(2, 7), e(2, 8)]).unwrap();
        s.set_hard_state(HardState { term: 2, vote: Some(3), commit: 5 }).unwrap();
        drop(s);
        let (_, l) = Storage::open(&d).unwrap();
        assert_eq!(l.entries.len(), 8);
        assert_eq!(l.entries[6], e(2, 7));
        assert_eq!(l.hard_state, HardState { term: 2, vote: Some(3), commit: 5 });
    }

    #[test]
    fn torn_tail_is_cut_but_mid_log_corruption_is_an_error() {
        let d = dir("torn");
        let (mut s, _) = Storage::open(&d).unwrap();
        s.append(&(1..=5).map(|i| e(1, i)).collect::<Vec<_>>()).unwrap();
        drop(s);
        let p = std::path::Path::new(&d).join("log");
        let full = std::fs::read(&p).unwrap();
        // Every possible torn length of the last record recovers entries 1..=4.
        let last_start = full.len() - (8 + (5 % 7) + 8 + 8 + 1 + 8);
        for cut in last_start + 1..full.len() {
            std::fs::write(&p, &full[..cut]).unwrap();
            let (_, l) = Storage::open(&d).unwrap();
            assert_eq!(l.entries.len(), 4, "cut at {cut}");
        }
        // A flipped byte in the first record (not the tail) is corruption.
        let mut bad = full.clone();
        bad[10] ^= 0xff;
        std::fs::write(&p, &bad).unwrap();
        assert!(matches!(Storage::open(&d), Err(Error::Corrupt(_))));
    }

    #[test]
    fn snapshot_compacts_log_and_survives_reopen() {
        let d = dir("snap");
        let (mut s, _) = Storage::open(&d).unwrap();
        s.append(&(1..=20).map(|i| e(1, i)).collect::<Vec<_>>()).unwrap();
        let snap = Snapshot { meta: SnapshotMeta { index: 12, term: 1, voters: alloc::vec![1, 2, 3] }, data: Rc::from(&b"state@12"[..]) };
        s.save_snapshot(&snap).unwrap();
        // Appends keep working on the rewritten log.
        s.append(&[e(2, 21)]).unwrap();
        drop(s);
        let (_, l) = Storage::open(&d).unwrap();
        assert_eq!(l.snapshot.as_ref().unwrap(), &snap);
        assert_eq!(l.entries.first().unwrap().index, 13);
        assert_eq!(l.entries.last().unwrap(), &e(2, 21));
        // A snapshot covering everything empties the log.
        let (mut s, _) = Storage::open(&d).unwrap();
        let all = Snapshot { meta: SnapshotMeta { index: 21, term: 2, voters: alloc::vec![1] }, data: Rc::from(&b"s"[..]) };
        s.save_snapshot(&all).unwrap();
        drop(s);
        let (_, l) = Storage::open(&d).unwrap();
        assert!(l.entries.is_empty());
        assert_eq!(l.snapshot.unwrap().meta.index, 21);
    }

    #[test]
    fn crash_between_snapshot_and_log_rewrite_is_harmless() {
        let d = dir("crashsnap");
        let (mut s, _) = Storage::open(&d).unwrap();
        s.append(&(1..=10).map(|i| e(1, i)).collect::<Vec<_>>()).unwrap();
        // Snapshot file written, log not yet rewritten (simulated by writing the file only).
        let snap = Snapshot { meta: SnapshotMeta { index: 6, term: 1, voters: alloc::vec![1] }, data: Rc::from(&b"x"[..]) };
        write_atomic(&s.dir, "snapshot", &encode_snapshot(&snap)).unwrap();
        drop(s);
        let (_, l) = Storage::open(&d).unwrap();
        assert_eq!(l.entries.first().unwrap().index, 7, "entries covered by the snapshot are dropped");
        // A corrupted snapshot is detected.
        let p = std::path::Path::new(&d).join("snapshot");
        let mut b = std::fs::read(&p).unwrap();
        let n = b.len();
        b[n - 1] ^= 1;
        std::fs::write(&p, &b).unwrap();
        assert!(matches!(Storage::open(&d), Err(Error::Corrupt(_))));
    }
}
