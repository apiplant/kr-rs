//! `kr-raft`: the Raft consensus algorithm (Ongaro & Ousterhout) as a sans-I/O state machine
//! (ADR-026).
//!
//! The caller owns time, storage and the network:
//! * [`Raft::tick`] advances the logical clock (one tick ≈ 100 ms in kr);
//! * [`Raft::step`] delivers a message from a peer;
//! * [`Raft::propose`] / [`Raft::propose_conf`] append to the log (leader only);
//! * [`Raft::ready`] returns everything that must happen next, in order: persist the hard state,
//!   truncate and append entries, persist a received snapshot, **then** send the messages and
//!   apply the committed entries; finally call [`Raft::advance`]. Nothing is sent before it is
//!   durable, and the leader counts its own entries towards a majority only after `advance`.
//!
//! Implemented: leader election with randomized timeouts, pre-vote (§9.6) and check-quorum with
//! leader stickiness (a partitioned or stale leader steps down; a rejoining node cannot depose a
//! healthy leader); log replication with probe/pipelined progress and conflict hints; the commit
//! rule restricted to current-term entries (§5.4.2) with a no-op on election; snapshots and
//! InstallSnapshot for lagging followers; single-server membership changes (§4.1: one at a time,
//! effective on append, recomputed on truncation); leadership transfer (TimeoutNow).
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod codec;
pub mod storage;

use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::vec::Vec;

pub type NodeId = u64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryKind {
    /// Opaque state-machine payload.
    Normal,
    /// Appended by every new leader to commit entries of earlier terms (§5.4.2).
    Noop,
    AddVoter(NodeId),
    RemoveVoter(NodeId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub term: u64,
    pub index: u64,
    pub kind: EntryKind,
    pub data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HardState {
    pub term: u64,
    pub vote: Option<NodeId>,
    pub commit: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SnapshotMeta {
    pub index: u64,
    pub term: u64,
    /// Voters as of `index`.
    pub voters: Vec<NodeId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub meta: SnapshotMeta,
    /// State-machine image at `meta.index` (opaque to Raft).
    pub data: Rc<[u8]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MsgBody {
    /// Pre-vote (§9.6): "would you vote for me in term `msg.term`?" Changes nobody's term.
    PreVote { last_index: u64, last_term: u64 },
    PreVoteResp { granted: bool },
    /// `transfer`: sent after TimeoutNow; overrides leader stickiness.
    Vote { last_index: u64, last_term: u64, transfer: bool },
    VoteResp { granted: bool },
    Append { prev_index: u64, prev_term: u64, entries: Vec<Entry>, commit: u64 },
    /// On success `index` is the last index the follower now matches. On failure, `index` is a
    /// hint: the first index of the conflicting term (or the follower's last index + 1 when its
    /// log is shorter), so the leader skips back a whole term per round trip.
    AppendResp { success: bool, index: u64 },
    InstallSnapshot { snapshot: Snapshot },
    /// Leadership transfer: start an election now.
    TimeoutNow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub from: NodeId,
    pub to: NodeId,
    pub term: u64,
    pub body: MsgBody,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Follower,
    PreCandidate,
    Candidate,
    Leader,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProposeError {
    /// Not the leader; the current leader, if known.
    NotLeader(Option<NodeId>),
    /// A membership change is still uncommitted, or a leadership transfer is in progress.
    Busy,
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub id: NodeId,
    /// Base election timeout in ticks; the actual timeout is uniform in [base, 2 * base).
    pub election_ticks: u32,
    pub heartbeat_ticks: u32,
    /// Max entries per Append message.
    pub max_batch: usize,
    /// Max Append messages in flight to a replicating follower.
    pub max_inflight: usize,
}

impl Config {
    pub fn new(id: NodeId) -> Config {
        Config { id, election_ticks: 10, heartbeat_ticks: 1, max_batch: 64, max_inflight: 16 }
    }
}

/// What the caller must do next (see the crate docs for the order).
#[derive(Debug, Default)]
pub struct Ready {
    pub hard_state: Option<HardState>,
    /// Remove stable entries with index >= this before appending `entries`.
    pub truncate_from: Option<u64>,
    pub entries: Vec<Entry>,
    /// Received from the leader: persist it, replace the state machine with it.
    pub snapshot: Option<Snapshot>,
    pub committed: Vec<Entry>,
    pub messages: Vec<Message>,
}

impl Ready {
    pub fn is_empty(&self) -> bool {
        self.hard_state.is_none() && self.truncate_from.is_none() && self.entries.is_empty() && self.snapshot.is_none() && self.committed.is_empty() && self.messages.is_empty()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProgressState {
    /// One Append in flight until it is answered (finding the match point).
    Probe,
    /// Pipelined up to `max_inflight`.
    Replicate,
    /// A snapshot was sent; waiting for it to be installed.
    Snapshot,
}

#[derive(Clone, Debug)]
struct Progress {
    matched: u64,
    next: u64,
    state: ProgressState,
    /// Last index of each in-flight Append (Replicate) or 1 entry (Probe/Snapshot).
    inflight: Vec<u64>,
    /// Heard from in the current check-quorum window.
    active: bool,
    /// Heartbeats since the snapshot was sent (resent after an election timeout).
    snap_wait: u32,
}

pub struct Raft {
    cfg: Config,
    rng: u64,
    pub term: u64,
    vote: Option<NodeId>,
    role: Role,
    leader: Option<NodeId>,
    // log: snapshot boundary + entries after it
    snap: Option<Snapshot>,
    snap_index: u64,
    snap_term: u64,
    snap_voters: Vec<NodeId>,
    log: Vec<Entry>,
    /// Index of the last entry known persisted by the caller (advance()).
    stable: u64,
    pub commit: u64,
    applied: u64,
    voters: Vec<NodeId>,
    /// Index of the latest config change entry (in the log, possibly uncommitted).
    pending_conf: u64,
    // timers
    elapsed: u32,
    timeout: u32,
    heartbeat_elapsed: u32,
    // candidate
    votes: BTreeMap<NodeId, bool>,
    // leader
    progress: BTreeMap<NodeId, Progress>,
    transfer_to: Option<NodeId>,
    // outputs
    msgs: Vec<Message>,
    hs_dirty: bool,
    truncate_from: Option<u64>,
    unstable_from: u64,
    recv_snapshot: Option<Snapshot>,
}

impl Raft {
    /// A node starting from persisted state. A brand-new cluster member starts with
    /// `hs = HardState::default()`, the voters it will join with (or just itself for a new
    /// cluster) in `snap_meta.voters`, and no entries.
    pub fn new(cfg: Config, seed: u64, hs: HardState, snapshot: Option<Snapshot>, voters: Vec<NodeId>, entries: Vec<Entry>) -> Raft {
        let fresh = snapshot.is_none() && entries.is_empty() && hs == HardState::default();
        let (snap_index, snap_term, snap_voters) = match &snapshot {
            Some(s) => (s.meta.index, s.meta.term, s.meta.voters.clone()),
            None if fresh => (0, 0, Vec::new()),
            None => (0, 0, voters.clone()),
        };
        // A brand-new member of a new cluster writes the initial membership as term-0 config
        // entries (identical on every founding member), so nodes that join later learn it by
        // replication. A node joining an existing cluster passes no voters: it learns them.
        let mut entries = entries;
        let mut boot_commit = 0;
        if fresh && !voters.is_empty() {
            let mut v = voters;
            v.sort_unstable();
            for (i, id) in v.iter().enumerate() {
                entries.push(Entry { term: 0, index: i as u64 + 1, kind: EntryKind::AddVoter(*id), data: Vec::new() });
            }
            boot_commit = v.len() as u64;
        }
        let last = entries.last().map_or(snap_index, |e| e.index);
        let stable = if boot_commit > 0 { 0 } else { last };
        let mut r = Raft {
            cfg,
            rng: seed | 1,
            term: hs.term,
            vote: hs.vote,
            role: Role::Follower,
            leader: None,
            snap: snapshot,
            snap_index,
            snap_term,
            snap_voters,
            log: entries,
            stable,
            commit: hs.commit.max(snap_index).max(boot_commit),
            applied: snap_index,
            voters: Vec::new(),
            pending_conf: 0,
            elapsed: 0,
            timeout: 0,
            heartbeat_elapsed: 0,
            votes: BTreeMap::new(),
            progress: BTreeMap::new(),
            transfer_to: None,
            msgs: Vec::new(),
            hs_dirty: boot_commit > 0,
            truncate_from: None,
            unstable_from: if boot_commit > 0 { 1 } else { last + 1 },
            recv_snapshot: None,
        };
        r.recompute_voters();
        r.reset_timeout();
        r
    }

    // ---- accessors ----

    pub fn id(&self) -> NodeId {
        self.cfg.id
    }
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn leader(&self) -> Option<NodeId> {
        self.leader
    }
    pub fn voters(&self) -> &[NodeId] {
        &self.voters
    }
    pub fn last_index(&self) -> u64 {
        self.log.last().map_or(self.snap_index, |e| e.index)
    }
    pub fn applied(&self) -> u64 {
        self.applied
    }
    pub fn hard_state(&self) -> HardState {
        HardState { term: self.term, vote: self.vote, commit: self.commit }
    }
    pub fn snapshot_index(&self) -> u64 {
        self.snap_index
    }

    fn last_term(&self) -> u64 {
        self.log.last().map_or(self.snap_term, |e| e.term)
    }

    /// Term of `index`, if known (the snapshot boundary counts).
    fn term_at(&self, index: u64) -> Option<u64> {
        if index == self.snap_index {
            return Some(self.snap_term);
        }
        if index < self.snap_index {
            return None;
        }
        self.log.get((index - self.snap_index - 1) as usize).map(|e| e.term)
    }

    fn entry(&self, index: u64) -> Option<&Entry> {
        if index <= self.snap_index {
            return None;
        }
        self.log.get((index - self.snap_index - 1) as usize)
    }

    fn quorum(&self) -> usize {
        self.voters.len() / 2 + 1
    }

    fn is_voter(&self, id: NodeId) -> bool {
        self.voters.contains(&id)
    }

    // ---- randomness / timers ----

    fn rand(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn reset_timeout(&mut self) {
        self.elapsed = 0;
        let base = self.cfg.election_ticks.max(2);
        self.timeout = base + (self.rand() % base as u64) as u32;
    }

    // ---- membership ----

    /// Voters = snapshot voters + every config entry in the log (committed or not), §4.1.
    fn recompute_voters(&mut self) {
        let mut v = self.snap_voters.clone();
        let mut pending = 0;
        for e in &self.log {
            match e.kind {
                EntryKind::AddVoter(id) => {
                    if !v.contains(&id) {
                        v.push(id);
                    }
                    pending = e.index;
                }
                EntryKind::RemoveVoter(id) => {
                    v.retain(|x| *x != id);
                    pending = e.index;
                }
                _ => {}
            }
        }
        v.sort_unstable();
        self.voters = v;
        self.pending_conf = pending;
        if self.role == Role::Leader {
            let ids: Vec<NodeId> = self.voters.clone();
            let next = self.last_index() + 1;
            for id in ids {
                if id != self.cfg.id {
                    self.progress.entry(id).or_insert(Progress { matched: 0, next, state: ProgressState::Probe, inflight: Vec::new(), active: true, snap_wait: 0 });
                }
            }
            let voters = self.voters.clone();
            self.progress.retain(|id, _| voters.contains(id));
        }
    }

    // ---- state transitions ----

    fn become_follower(&mut self, term: u64, leader: Option<NodeId>) {
        if term > self.term {
            self.term = term;
            self.vote = None;
            self.hs_dirty = true;
        }
        self.role = Role::Follower;
        self.leader = leader;
        self.progress.clear();
        self.votes.clear();
        self.transfer_to = None;
        self.reset_timeout();
    }

    fn become_pre_candidate(&mut self) {
        self.role = Role::PreCandidate;
        self.leader = None;
        self.votes.clear();
        self.reset_timeout();
        self.votes.insert(self.cfg.id, true);
        if self.won() {
            return self.become_candidate(false);
        }
        let (li, lt) = (self.last_index(), self.last_term());
        for id in self.voters.clone() {
            if id != self.cfg.id {
                self.send(id, self.term + 1, MsgBody::PreVote { last_index: li, last_term: lt });
            }
        }
    }

    fn become_candidate(&mut self, transfer: bool) {
        self.role = Role::Candidate;
        self.term += 1;
        self.vote = Some(self.cfg.id);
        self.hs_dirty = true;
        self.leader = None;
        self.votes.clear();
        self.reset_timeout();
        self.votes.insert(self.cfg.id, true);
        if self.won() {
            return self.become_leader();
        }
        let (li, lt) = (self.last_index(), self.last_term());
        for id in self.voters.clone() {
            if id != self.cfg.id {
                self.send(id, self.term, MsgBody::Vote { last_index: li, last_term: lt, transfer });
            }
        }
    }

    fn won(&self) -> bool {
        self.voters.iter().filter(|id| self.votes.get(id) == Some(&true)).count() >= self.quorum()
    }

    fn lost(&self) -> bool {
        self.voters.iter().filter(|id| self.votes.get(id) == Some(&false)).count() > self.voters.len() - self.quorum()
    }

    fn become_leader(&mut self) {
        self.role = Role::Leader;
        self.leader = Some(self.cfg.id);
        self.heartbeat_elapsed = 0;
        self.elapsed = 0;
        self.progress.clear();
        self.recompute_voters();
        // §5.4.2: commit an entry of our own term so earlier entries can commit.
        let idx = self.last_index() + 1;
        self.append_local(Entry { term: self.term, index: idx, kind: EntryKind::Noop, data: Vec::new() });
        self.broadcast_append();
    }

    // ---- driving ----

    /// One logical clock tick.
    pub fn tick(&mut self) {
        self.elapsed += 1;
        match self.role {
            Role::Leader => {
                self.heartbeat_elapsed += 1;
                if self.heartbeat_elapsed >= self.cfg.heartbeat_ticks {
                    self.heartbeat_elapsed = 0;
                    self.recover_lost();
                    self.broadcast_append();
                }
                // Check quorum once per election timeout: step down if a majority went quiet.
                if self.elapsed >= self.cfg.election_ticks {
                    self.elapsed = 0;
                    let me = self.cfg.id;
                    let active = self.voters.iter().filter(|id| **id == me || self.progress.get(id).is_some_and(|p| p.active)).count();
                    for p in self.progress.values_mut() {
                        p.active = false;
                    }
                    if active < self.quorum() {
                        let t = self.term;
                        self.become_follower(t, None);
                        return;
                    }
                    // A transfer that did not complete within a timeout is abandoned.
                    self.transfer_to = None;
                }
            }
            _ => {
                if self.elapsed >= self.timeout && self.is_voter(self.cfg.id) {
                    self.become_pre_candidate();
                }
            }
        }
    }

    /// Appends a state-machine command; returns its index. Leader only.
    pub fn propose(&mut self, data: Vec<u8>) -> Result<u64, ProposeError> {
        self.propose_kind(EntryKind::Normal, data)
    }

    /// Adds or removes one voter (single-server change). Leader only; one at a time.
    pub fn propose_conf(&mut self, kind: EntryKind) -> Result<u64, ProposeError> {
        if self.pending_conf > self.commit {
            return Err(ProposeError::Busy);
        }
        // A leader must have committed an entry of its term before changing membership.
        if self.term_at(self.commit) != Some(self.term) {
            return Err(ProposeError::Busy);
        }
        match kind {
            EntryKind::AddVoter(_) | EntryKind::RemoveVoter(_) => self.propose_kind(kind, Vec::new()),
            _ => Err(ProposeError::Busy),
        }
    }

    fn propose_kind(&mut self, kind: EntryKind, data: Vec<u8>) -> Result<u64, ProposeError> {
        if self.role != Role::Leader {
            return Err(ProposeError::NotLeader(self.leader));
        }
        if self.transfer_to.is_some() {
            return Err(ProposeError::Busy);
        }
        let idx = self.last_index() + 1;
        self.append_local(Entry { term: self.term, index: idx, kind, data });
        self.broadcast_append();
        Ok(idx)
    }

    /// Hands leadership to `to` once it is caught up (TimeoutNow).
    pub fn transfer_leadership(&mut self, to: NodeId) {
        if self.role != Role::Leader || to == self.cfg.id || !self.is_voter(to) {
            return;
        }
        self.transfer_to = Some(to);
        self.elapsed = 0;
        if self.progress.get(&to).is_some_and(|p| p.matched == self.last_index()) {
            self.send(to, self.term, MsgBody::TimeoutNow);
        } else {
            self.send_append(to);
        }
    }

    fn append_local(&mut self, e: Entry) {
        let is_conf = matches!(e.kind, EntryKind::AddVoter(_) | EntryKind::RemoveVoter(_));
        self.log.push(e);
        if is_conf {
            self.recompute_voters();
        }
    }

    // ---- messages ----

    fn send(&mut self, to: NodeId, term: u64, body: MsgBody) {
        self.msgs.push(Message { from: self.cfg.id, to, term, body });
    }

    /// Delivers a message from a peer.
    pub fn step(&mut self, m: Message) {
        // Term handling (§5.1), with pre-vote and leader stickiness (§4.2.3 / §9.6).
        match &m.body {
            MsgBody::PreVote { .. } => {
                // Never changes our term. Refuse while we hear from a live leader.
                let granted = m.term > self.term && !self.leader_alive() && self.log_ok(&m.body);
                self.send(m.from, if granted { m.term } else { self.term }, MsgBody::PreVoteResp { granted });
                return;
            }
            MsgBody::Vote { transfer, .. } if m.term > self.term && !transfer && self.leader_alive() => {
                // Stickiness: ignore (do not even bump our term) while a leader is alive.
                return;
            }
            MsgBody::PreVoteResp { granted: true } => {}
            _ if m.term > self.term => {
                let leader = matches!(m.body, MsgBody::Append { .. } | MsgBody::InstallSnapshot { .. }).then_some(m.from);
                self.become_follower(m.term, leader);
            }
            _ if m.term < self.term => {
                // Stale sender: tell it our term so it steps down (Append/Snapshot), else drop.
                if matches!(m.body, MsgBody::Append { .. } | MsgBody::InstallSnapshot { .. }) {
                    self.send(m.from, self.term, MsgBody::AppendResp { success: false, index: 0 });
                }
                return;
            }
            _ => {}
        }
        match m.body {
            MsgBody::PreVoteResp { granted } => {
                if self.role != Role::PreCandidate || m.term != self.term + 1 && granted {
                    return;
                }
                self.votes.insert(m.from, granted);
                if self.won() {
                    self.become_candidate(false);
                } else if self.lost() {
                    let t = self.term;
                    self.become_follower(t, None);
                }
            }
            MsgBody::Vote { .. } => {
                let can = self.vote.is_none() || self.vote == Some(m.from);
                let granted = can && self.log_ok(&m.body);
                if granted {
                    self.vote = Some(m.from);
                    self.hs_dirty = true;
                    self.elapsed = 0;
                }
                self.send(m.from, self.term, MsgBody::VoteResp { granted });
            }
            MsgBody::VoteResp { granted } => {
                if self.role != Role::Candidate {
                    return;
                }
                self.votes.insert(m.from, granted);
                if self.won() {
                    self.become_leader();
                } else if self.lost() {
                    let t = self.term;
                    self.become_follower(t, None);
                }
            }
            MsgBody::Append { prev_index, prev_term, entries, commit } => {
                if self.role != Role::Follower {
                    let t = self.term;
                    self.become_follower(t, Some(m.from));
                }
                self.leader = Some(m.from);
                self.elapsed = 0;
                self.handle_append(m.from, prev_index, prev_term, entries, commit);
            }
            MsgBody::AppendResp { success, index } => self.handle_append_resp(m.from, success, index),
            MsgBody::InstallSnapshot { snapshot } => {
                if self.role != Role::Follower {
                    let t = self.term;
                    self.become_follower(t, Some(m.from));
                }
                self.leader = Some(m.from);
                self.elapsed = 0;
                self.handle_snapshot(m.from, snapshot);
            }
            MsgBody::TimeoutNow => {
                if self.role == Role::Follower && self.is_voter(self.cfg.id) {
                    self.become_candidate(true);
                }
            }
            MsgBody::PreVote { .. } => {} // answered above
        }
    }

    /// A leader we heard from within the minimum election timeout (stickiness).
    fn leader_alive(&self) -> bool {
        self.leader.is_some() && self.elapsed < self.cfg.election_ticks
    }

    /// §5.4.1: the candidate's log is at least as up to date as ours.
    fn log_ok(&self, body: &MsgBody) -> bool {
        let (li, lt) = match body {
            MsgBody::PreVote { last_index, last_term } | MsgBody::Vote { last_index, last_term, .. } => (*last_index, *last_term),
            _ => return false,
        };
        lt > self.last_term() || (lt == self.last_term() && li >= self.last_index())
    }

    fn handle_append(&mut self, from: NodeId, prev_index: u64, prev_term: u64, entries: Vec<Entry>, commit: u64) {
        if prev_index < self.snap_index {
            // Already covered by our snapshot: report what we match.
            let idx = self.snap_index.max(self.commit);
            self.send(from, self.term, MsgBody::AppendResp { success: true, index: idx });
            return;
        }
        match self.term_at(prev_index) {
            Some(t) if t == prev_term => {}
            Some(t) => {
                // Conflict: hint the first index of the conflicting term.
                let mut i = prev_index;
                while i > self.snap_index + 1 && self.term_at(i - 1) == Some(t) {
                    i -= 1;
                }
                self.send(from, self.term, MsgBody::AppendResp { success: false, index: i });
                return;
            }
            None => {
                let hint = self.last_index() + 1;
                self.send(from, self.term, MsgBody::AppendResp { success: false, index: hint });
                return;
            }
        }
        // The match point we can vouch for: prev + what the leader sent. Anything after it in our
        // log is unverified (possibly stale) and must neither count as matched nor commit.
        let last_new = prev_index + entries.len() as u64;
        let mut conf_changed = false;
        for e in entries {
            match self.term_at(e.index) {
                Some(t) if t == e.term => continue, // already have it (duplicate/reordered)
                Some(_) => {
                    // Conflict: drop it and everything after (never committed entries).
                    debug_assert!(e.index > self.commit, "conflict below commit index");
                    let keep = (e.index - self.snap_index - 1) as usize;
                    conf_changed |= self.log[keep..].iter().any(|x| matches!(x.kind, EntryKind::AddVoter(_) | EntryKind::RemoveVoter(_)));
                    self.log.truncate(keep);
                    self.truncate_from = Some(self.truncate_from.map_or(e.index, |t| t.min(e.index)));
                    self.stable = self.stable.min(e.index - 1);
                    self.unstable_from = self.unstable_from.min(e.index);
                }
                None => {}
            }
            conf_changed |= matches!(e.kind, EntryKind::AddVoter(_) | EntryKind::RemoveVoter(_));
            self.unstable_from = self.unstable_from.min(e.index);
            self.log.push(e);
        }
        if conf_changed {
            self.recompute_voters();
        }
        // Commit up to what the leader committed, but only within what we verified matches.
        let new_commit = commit.min(last_new);
        if new_commit > self.commit {
            self.commit = new_commit;
            self.hs_dirty = true;
        }
        self.send(from, self.term, MsgBody::AppendResp { success: true, index: last_new });
    }

    fn handle_snapshot(&mut self, from: NodeId, s: Snapshot) {
        let idx = s.meta.index;
        if idx <= self.commit {
            self.send(from, self.term, MsgBody::AppendResp { success: true, index: self.commit });
            return;
        }
        // Keep the log after the snapshot if it matches it; else drop everything.
        if self.term_at(idx) == Some(s.meta.term) {
            let drop = (idx - self.snap_index) as usize;
            self.log.drain(..drop.min(self.log.len()));
            self.stable = self.stable.max(idx);
        } else {
            self.log.clear();
            self.truncate_from = Some(0);
            self.stable = idx;
        }
        self.snap_index = idx;
        self.snap_term = s.meta.term;
        self.snap_voters = s.meta.voters.clone();
        self.commit = idx;
        self.applied = idx;
        self.unstable_from = self.unstable_from.max(idx + 1);
        self.hs_dirty = true;
        self.recompute_voters();
        self.snap = Some(s.clone());
        self.recv_snapshot = Some(s);
        self.send(from, self.term, MsgBody::AppendResp { success: true, index: idx });
    }

    fn handle_append_resp(&mut self, from: NodeId, success: bool, index: u64) {
        if self.role != Role::Leader {
            return;
        }
        let last = self.last_index();
        let Some(p) = self.progress.get_mut(&from) else { return };
        p.active = true;
        if success {
            if index > p.matched {
                p.matched = index;
            }
            p.next = p.next.max(index + 1);
            p.inflight.retain(|i| *i > index);
            match p.state {
                ProgressState::Probe | ProgressState::Snapshot => {
                    p.state = ProgressState::Replicate;
                    p.inflight.clear();
                }
                ProgressState::Replicate => {}
            }
            self.maybe_commit();
            if self.transfer_to == Some(from) && self.progress.get(&from).is_some_and(|p| p.matched == last) {
                self.send(from, self.term, MsgBody::TimeoutNow);
            }
            if self.progress.get(&from).is_some_and(|p| p.next <= last) {
                self.send_append(from);
            }
        } else {
            // Rejected: back off to the hint (never below what is known matched).
            if index == 0 {
                return; // a "stale term" reply; the term logic already ran
            }
            p.next = index.max(p.matched + 1).min(last + 1);
            p.state = ProgressState::Probe;
            p.inflight.clear();
            self.send_append(from);
        }
    }

    /// Messages can be lost: on every heartbeat, a probe is resent, a full pipeline that got no
    /// answer falls back to probing from the last known match, and a snapshot is resent after
    /// an election timeout.
    fn recover_lost(&mut self) {
        let et = self.cfg.election_ticks;
        let max = self.cfg.max_inflight;
        for p in self.progress.values_mut() {
            match p.state {
                ProgressState::Probe => p.inflight.clear(),
                ProgressState::Replicate if p.inflight.len() >= max => {
                    p.state = ProgressState::Probe;
                    p.next = p.matched + 1;
                    p.inflight.clear();
                }
                ProgressState::Replicate => {}
                ProgressState::Snapshot => {
                    p.snap_wait += 1;
                    if p.snap_wait >= et {
                        p.snap_wait = 0;
                        p.state = ProgressState::Probe;
                        p.next = p.matched + 1;
                        p.inflight.clear();
                    }
                }
            }
        }
    }

    fn maybe_commit(&mut self) {
        // The quorum-th highest match index (leader counts its stable entries).
        let mut m: Vec<u64> = self.voters.iter().map(|id| if *id == self.cfg.id { self.stable } else { self.progress.get(id).map_or(0, |p| p.matched) }).collect();
        if m.is_empty() {
            return;
        }
        m.sort_unstable_by(|a, b| b.cmp(a));
        let candidate = m[self.quorum() - 1];
        // §5.4.2: only entries of the current term commit by counting replicas.
        if candidate > self.commit && self.term_at(candidate) == Some(self.term) {
            self.commit = candidate;
            self.hs_dirty = true;
            self.broadcast_append_commit();
        }
        // A leader removed by a now-committed config steps down.
        if self.role == Role::Leader && !self.is_voter(self.cfg.id) && self.pending_conf <= self.commit {
            let t = self.term;
            self.become_follower(t, None);
        }
    }

    /// After the commit index moves, tell followers (cheap: piggyback on the next Append).
    fn broadcast_append_commit(&mut self) {
        for id in self.voters.clone() {
            if id != self.cfg.id {
                let p = self.progress.get(&id).cloned();
                if let Some(p) = p {
                    if p.state == ProgressState::Replicate && p.inflight.len() < self.cfg.max_inflight {
                        self.send_append(id);
                    }
                }
            }
        }
    }

    fn broadcast_append(&mut self) {
        for id in self.voters.clone() {
            if id != self.cfg.id {
                self.send_append(id);
            }
        }
    }

    /// Sends the next batch (or a heartbeat, or a snapshot) to `to`.
    fn send_append(&mut self, to: NodeId) {
        let last = self.last_index();
        let Some(p) = self.progress.get(&to).cloned() else { return };
        let full = match p.state {
            ProgressState::Probe | ProgressState::Snapshot => !p.inflight.is_empty(),
            ProgressState::Replicate => p.inflight.len() >= self.cfg.max_inflight,
        };
        if full {
            // Heartbeat only (keeps the follower's timer and commit index fresh).
            if p.state != ProgressState::Snapshot {
                let prev = p.matched;
                if let Some(pt) = self.term_at(prev) {
                    let c = self.commit.min(prev);
                    self.send(to, self.term, MsgBody::Append { prev_index: prev, prev_term: pt, entries: Vec::new(), commit: c });
                }
            }
            return;
        }
        let prev = p.next - 1;
        let Some(prev_term) = self.term_at(prev) else {
            // The follower needs entries we compacted: send the snapshot.
            if let Some(s) = self.snap.clone() {
                let pr = self.progress.get_mut(&to).unwrap();
                pr.state = ProgressState::Snapshot;
                pr.snap_wait = 0;
                pr.inflight = alloc::vec![s.meta.index];
                pr.next = s.meta.index + 1;
                self.send(to, self.term, MsgBody::InstallSnapshot { snapshot: s });
            }
            return;
        };
        let mut entries = Vec::new();
        let mut i = p.next;
        while i <= last && entries.len() < self.cfg.max_batch {
            entries.push(self.entry(i).unwrap().clone());
            i += 1;
        }
        let sent_last = prev + entries.len() as u64;
        let commit = self.commit;
        let pr = self.progress.get_mut(&to).unwrap();
        if !entries.is_empty() {
            pr.inflight.push(sent_last);
            if pr.state == ProgressState::Replicate {
                pr.next = sent_last + 1;
            }
        }
        self.send(to, self.term, MsgBody::Append { prev_index: prev, prev_term, entries, commit });
    }

    // ---- ready / advance ----

    pub fn has_ready(&self) -> bool {
        self.hs_dirty || self.truncate_from.is_some() || self.unstable_from <= self.last_index() || !self.msgs.is_empty() || self.recv_snapshot.is_some() || self.applied < self.commit.min(self.last_index())
    }

    /// Everything to do next. Call [`Raft::advance`] with the same `Ready` once it is done.
    pub fn ready(&mut self) -> Ready {
        let entries: Vec<Entry> = if self.unstable_from <= self.last_index() {
            let from = self.unstable_from.max(self.snap_index + 1);
            (from..=self.last_index()).filter_map(|i| self.entry(i).cloned()).collect()
        } else {
            Vec::new()
        };
        let upto = self.commit.min(self.last_index());
        let committed: Vec<Entry> = ((self.applied + 1).max(self.snap_index + 1)..=upto).filter_map(|i| self.entry(i).cloned()).collect();
        Ready {
            hard_state: self.hs_dirty.then(|| self.hard_state()),
            truncate_from: self.truncate_from,
            entries,
            snapshot: self.recv_snapshot.clone(),
            committed,
            messages: core::mem::take(&mut self.msgs),
        }
    }

    /// The caller persisted and applied `rd`.
    pub fn advance(&mut self, rd: Ready) {
        if rd.hard_state.is_some() {
            self.hs_dirty = false;
        }
        if rd.truncate_from.is_some() {
            self.truncate_from = None;
        }
        if let Some(last) = rd.entries.last() {
            // Still in our log with the same term (not truncated meanwhile)?
            if self.term_at(last.index) == Some(last.term) {
                self.stable = self.stable.max(last.index);
                self.unstable_from = self.unstable_from.max(last.index + 1);
            }
        }
        if let Some(s) = rd.snapshot {
            if self.recv_snapshot.as_ref().is_some_and(|r| r.meta.index == s.meta.index) {
                self.recv_snapshot = None;
            }
            self.stable = self.stable.max(s.meta.index);
        }
        if let Some(last) = rd.committed.last() {
            self.applied = self.applied.max(last.index);
        }
        if self.role == Role::Leader {
            self.maybe_commit();
        }
    }

    /// The state machine was snapshotted at `index` (≤ applied): drop the log before it.
    pub fn compact(&mut self, index: u64, data: Rc<[u8]>) {
        if index <= self.snap_index || index > self.applied {
            return;
        }
        let term = self.term_at(index).unwrap();
        // Voters as of `index`: snapshot voters + config entries up to index.
        let mut v = self.snap_voters.clone();
        for e in self.log.iter().take_while(|e| e.index <= index) {
            match e.kind {
                EntryKind::AddVoter(id) if !v.contains(&id) => v.push(id),
                EntryKind::RemoveVoter(id) => v.retain(|x| *x != id),
                _ => {}
            }
        }
        v.sort_unstable();
        let drop = (index - self.snap_index) as usize;
        self.log.drain(..drop);
        self.snap_index = index;
        self.snap_term = term;
        self.snap_voters = v.clone();
        self.snap = Some(Snapshot { meta: SnapshotMeta { index, term, voters: v }, data });
    }
}

#[cfg(test)]
mod tests;
