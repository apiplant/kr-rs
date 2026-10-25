//! Unit tests and a randomized cluster simulation that checks Raft's safety properties under
//! message loss, duplication, reordering, partitions, crashes and snapshots.

use super::*;
use alloc::collections::BTreeMap;
use alloc::vec;
use std::collections::{HashMap, HashSet};

/// Deterministic test RNG (splitmix64).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.next() % 100 < pct
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// What a node has on "disk", and its state machine.
#[derive(Clone, Default)]
struct Disk {
    hs: HardState,
    snapshot: Option<Snapshot>,
    entries: Vec<Entry>,
}

struct Node {
    raft: Raft,
    disk: Disk,
    /// State machine: the applied Normal payloads in order (snapshot data = their concatenation).
    sm: Vec<u8>,
    sm_index: u64,
    alive: bool,
    voters0: Vec<NodeId>,
}

struct Sim {
    rng: Rng,
    nodes: BTreeMap<NodeId, Node>,
    /// (deliver_at, message)
    net: Vec<(u64, Message)>,
    now: u64,
    drop_pct: u64,
    dup_pct: u64,
    max_delay: u64,
    /// Nodes in different groups cannot talk.
    group: HashMap<NodeId, u8>,
    // invariants
    leaders: HashMap<u64, NodeId>,
    applied: HashMap<u64, (u64, Vec<u8>)>,
    proposed: u64,
    stats: Stats,
}

#[derive(Default, Debug)]
struct Stats {
    elections: u64,
    crashes: u64,
    partitions: u64,
    snapshots_installed: u64,
}

fn cfg(id: NodeId) -> Config {
    Config { id, election_ticks: 10, heartbeat_ticks: 2, max_batch: 8, max_inflight: 4 }
}

impl Sim {
    fn new(seed: u64, n: u64) -> Sim {
        let voters: Vec<NodeId> = (1..=n).collect();
        let mut nodes = BTreeMap::new();
        for id in 1..=n {
            let raft = Raft::new(cfg(id), seed ^ (id * 7919), HardState::default(), None, voters.clone(), Vec::new());
            nodes.insert(id, Node { raft, disk: Disk::default(), sm: Vec::new(), sm_index: 0, alive: true, voters0: voters.clone() });
        }
        Sim { rng: Rng(seed), nodes, net: Vec::new(), now: 0, drop_pct: 0, dup_pct: 0, max_delay: 1, group: HashMap::new(), leaders: HashMap::new(), applied: HashMap::new(), proposed: 0, stats: Stats::default() }
    }

    fn connected(&self, a: NodeId, b: NodeId) -> bool {
        self.group.get(&a).copied().unwrap_or(0) == self.group.get(&b).copied().unwrap_or(0)
    }

    /// Processes a node's Ready like the real driver: persist, send, apply, advance.
    fn drain(&mut self, id: NodeId) {
        loop {
            let node = self.nodes.get_mut(&id).unwrap();
            if !node.alive || !node.raft.has_ready() {
                return;
            }
            let rd = node.raft.ready();
            if let Some(hs) = rd.hard_state {
                node.disk.hs = hs;
            }
            if let Some(from) = rd.truncate_from {
                node.disk.entries.retain(|e| e.index < from);
            }
            if let Some(s) = &rd.snapshot {
                self.stats.snapshots_installed += 1;
                node.disk.snapshot = Some(s.clone());
                node.disk.entries.retain(|e| e.index > s.meta.index);
                node.sm = s.data.to_vec();
                node.sm_index = s.meta.index;
            }
            for e in &rd.entries {
                node.disk.entries.retain(|x| x.index < e.index);
                node.disk.entries.push(e.clone());
            }
            let mut out = Vec::new();
            for m in &rd.messages {
                out.push(m.clone());
            }
            for e in &rd.committed {
                if e.index <= node.sm_index {
                    continue;
                }
                assert_eq!(e.index, node.sm_index + 1, "node {id} applied out of order");
                node.sm_index = e.index;
                if e.kind == EntryKind::Normal {
                    node.sm.extend_from_slice(&e.data);
                }
                // State machine safety: the same index never holds two different entries.
                let rec = (e.term, e.data.clone());
                if let Some(prev) = self.applied.get(&e.index) {
                    assert_eq!(prev, &rec, "two different entries committed at index {}", e.index);
                } else {
                    self.applied.insert(e.index, rec);
                }
            }
            let node = self.nodes.get_mut(&id).unwrap();
            node.raft.advance(rd);
            // Election safety: one leader per term.
            if node.raft.role() == Role::Leader {
                let t = node.raft.term;
                if let Some(l) = self.leaders.get(&t) {
                    assert_eq!(*l, id, "two leaders in term {t}");
                } else {
                    self.leaders.insert(t, id);
                    self.stats.elections += 1;
                    // Leader completeness: every entry committed anywhere is in the new leader's
                    // log (or covered by its snapshot) with the same term.
                    let r = &node.raft;
                    for (idx, (term, _)) in &self.applied {
                        if *idx > r.snapshot_index() {
                            assert_eq!(r.term_at(*idx), Some(*term), "leader {id} (term {t}) lacks committed entry {idx}");
                        }
                    }
                }
            }
            for m in out {
                self.post(m);
            }
        }
    }

    fn post(&mut self, m: Message) {
        if self.rng.chance(self.drop_pct) {
            return;
        }
        let at = self.now + 1 + self.rng.below(self.max_delay);
        if self.rng.chance(self.dup_pct) {
            let at2 = self.now + 1 + self.rng.below(self.max_delay);
            self.net.push((at2, m.clone()));
        }
        self.net.push((at, m));
    }

    fn step_time(&mut self) {
        self.now += 1;
        let ids: Vec<NodeId> = self.nodes.keys().copied().collect();
        for id in &ids {
            if self.nodes[id].alive {
                self.nodes.get_mut(id).unwrap().raft.tick();
                self.drain(*id);
            }
        }
        // Deliver due messages in random order.
        let mut due: Vec<Message> = Vec::new();
        let now = self.now;
        self.net.retain(|(at, m)| {
            if *at <= now {
                due.push(m.clone());
                false
            } else {
                true
            }
        });
        for i in (1..due.len()).rev() {
            let j = self.rng.below(i as u64 + 1) as usize;
            due.swap(i, j);
        }
        for m in due {
            let (from, to) = (m.from, m.to);
            if !self.connected(from, to) || !self.nodes.get(&to).is_some_and(|n| n.alive) {
                continue;
            }
            self.nodes.get_mut(&to).unwrap().raft.step(m);
            self.drain(to);
        }
    }

    fn leader(&self) -> Option<NodeId> {
        // The leader with the highest term among live nodes.
        self.nodes.iter().filter(|(_, n)| n.alive && n.raft.role() == Role::Leader).max_by_key(|(_, n)| n.raft.term).map(|(id, _)| *id)
    }

    fn propose(&mut self) {
        if let Some(l) = self.leader() {
            self.proposed += 1;
            let data = self.proposed.to_le_bytes().to_vec();
            if self.nodes.get_mut(&l).unwrap().raft.propose(data).is_ok() {
                self.drain(l);
            }
        }
    }

    fn crash(&mut self, id: NodeId) {
        self.stats.crashes += 1;
        self.nodes.get_mut(&id).unwrap().alive = false;
    }

    /// Restart from the persisted state only (unpersisted entries and votes are lost).
    fn restart(&mut self, id: NodeId, seed: u64) {
        let n = self.nodes.get_mut(&id).unwrap();
        let d = n.disk.clone();
        n.raft = Raft::new(cfg(id), seed, d.hs, d.snapshot.clone(), n.voters0.clone(), d.entries.clone());
        n.sm = d.snapshot.as_ref().map(|s| s.data.to_vec()).unwrap_or_default();
        n.sm_index = d.snapshot.as_ref().map_or(0, |s| s.meta.index);
        n.alive = true;
    }

    fn snapshot(&mut self, id: NodeId) {
        let n = self.nodes.get_mut(&id).unwrap();
        if !n.alive || n.sm_index <= n.raft.snapshot_index() {
            return;
        }
        let data: Rc<[u8]> = Rc::from(&n.sm[..]);
        n.raft.compact(n.sm_index, data);
        let meta_index = n.raft.snapshot_index();
        // Persist the snapshot like the real driver: snapshot file + log truncation.
        n.disk.snapshot = n.raft.snap.clone();
        n.disk.entries.retain(|e| e.index > meta_index);
    }

    fn converged(&self) -> bool {
        let live: Vec<&Node> = self.nodes.values().filter(|n| n.alive).collect();
        let first = &live[0];
        live.iter().all(|n| n.sm_index == first.sm_index && n.sm == first.sm)
    }
}

fn run_chaos(seed: u64, n: u64, rounds: u64) -> Stats {
    let mut s = Sim::new(seed, n);
    s.drop_pct = 10;
    s.dup_pct = 5;
    s.max_delay = 4;
    for r in 0..rounds {
        s.step_time();
        if s.rng.chance(30) {
            s.propose();
        }
        let ids: Vec<NodeId> = s.nodes.keys().copied().collect();
        let pick = ids[s.rng.below(ids.len() as u64) as usize];
        match s.rng.below(1000) {
            0..=4 => {
                // crash a minority at most
                let down = s.nodes.values().filter(|x| !x.alive).count() as u64;
                if s.nodes[&pick].alive && down < (n - 1) / 2 {
                    s.crash(pick);
                }
            }
            5..=14 => {
                if !s.nodes[&pick].alive {
                    s.restart(pick, seed ^ r);
                }
            }
            15..=19 => {
                // partition: random two groups
                s.group.clear();
                s.stats.partitions += 1;
                for id in &ids {
                    if s.rng.chance(40) {
                        s.group.insert(*id, 1);
                    }
                }
            }
            20..=39 => s.group.clear(),
            40..=49 => s.snapshot(pick),
            _ => {}
        }
    }
    // Heal: everyone up, no faults; the cluster must converge and keep committing.
    s.group.clear();
    s.drop_pct = 0;
    s.dup_pct = 0;
    s.max_delay = 2;
    let ids: Vec<NodeId> = s.nodes.keys().copied().collect();
    for id in ids {
        if !s.nodes[&id].alive {
            s.restart(id, seed ^ 0xdead);
        }
    }
    for _ in 0..300 {
        s.step_time();
    }
    let before = s.applied.len();
    for _ in 0..20 {
        s.propose();
        s.step_time();
    }
    for _ in 0..200 {
        s.step_time();
    }
    assert!(s.leader().is_some(), "seed {seed}: no leader after healing");
    assert!(s.applied.len() > before, "seed {seed}: nothing committed after healing");
    assert!(s.converged(), "seed {seed}: state machines diverge after healing");
    s.stats
}

#[test]
fn chaos_3_nodes() {
    let mut total = Stats::default();
    for seed in 1..=40 {
        let st = run_chaos(seed, 3, 3000);
        total.elections += st.elections;
        total.crashes += st.crashes;
        total.partitions += st.partitions;
        total.snapshots_installed += st.snapshots_installed;
    }
    // The faults really happened (the run is not vacuous).
    assert!(total.elections > 200 && total.crashes > 20 && total.partitions > 50 && total.snapshots_installed > 5, "{total:?}");
}

/// Long soak: `cargo test --release -p kr-raft -- --ignored soak`.
#[test]
#[ignore]
fn soak() {
    for seed in 1000..2000 {
        run_chaos(seed, if seed % 2 == 0 { 3 } else { 5 }, 5000);
    }
}

#[test]
fn chaos_5_nodes() {
    for seed in 100..=120 {
        run_chaos(seed, 5, 3000);
    }
}

#[test]
fn single_node_commits_after_persist() {
    let mut r = Raft::new(cfg(1), 7, HardState::default(), None, vec![1], Vec::new());
    for _ in 0..40 {
        r.tick();
    }
    assert_eq!(r.role(), Role::Leader);
    let rd = r.ready();
    r.advance(rd);
    let idx = r.propose(b"x".to_vec()).unwrap();
    // Not committed until the entry is persisted (advance).
    assert!(r.commit < idx);
    let rd = r.ready();
    assert!(rd.entries.iter().any(|e| e.index == idx));
    r.advance(rd);
    assert_eq!(r.commit, idx);
    let rd = r.ready();
    assert!(rd.committed.iter().any(|e| e.index == idx && e.data == b"x"));
    r.advance(rd);
}

#[test]
fn elects_one_leader_and_replicates() {
    let mut s = Sim::new(42, 3);
    for _ in 0..100 {
        s.step_time();
    }
    let l = s.leader().expect("leader");
    for _ in 0..10 {
        s.propose();
    }
    for _ in 0..50 {
        s.step_time();
    }
    assert!(s.converged());
    assert!(s.nodes.values().all(|n| n.sm.len() == 80), "10 entries x 8 bytes everywhere");
    assert_eq!(s.leader(), Some(l), "no needless re-election");
}

#[test]
fn partitioned_leader_steps_down_and_rejoins_without_disruption() {
    let mut s = Sim::new(9, 3);
    for _ in 0..100 {
        s.step_time();
    }
    let old = s.leader().unwrap();
    let old_term = s.nodes[&old].raft.term;
    s.group.insert(old, 1);
    for _ in 0..100 {
        s.step_time();
    }
    // Check-quorum: the isolated leader stepped down; the majority elected a new one.
    assert_ne!(s.nodes[&old].raft.role(), Role::Leader);
    let new = s.leader().unwrap();
    assert_ne!(new, old);
    s.propose();
    // Pre-vote: the isolated node never bumped its term while alone...
    assert_eq!(s.nodes[&old].raft.term, old_term);
    s.group.clear();
    for _ in 0..100 {
        s.step_time();
    }
    // ...so rejoining does not depose the healthy leader.
    assert_eq!(s.leader(), Some(new));
    assert!(s.converged());
}

#[test]
fn lagging_follower_catches_up_from_snapshot() {
    let mut s = Sim::new(5, 3);
    for _ in 0..100 {
        s.step_time();
    }
    let l = s.leader().unwrap();
    let lag = *s.nodes.keys().find(|id| **id != l).unwrap();
    s.crash(lag);
    for _ in 0..30 {
        s.propose();
        s.step_time();
    }
    for _ in 0..20 {
        s.step_time();
    }
    // Compact the leader's log past what the lagging node has.
    s.snapshot(l);
    assert!(s.nodes[&l].raft.snapshot_index() > 10);
    s.restart(lag, 77);
    for _ in 0..100 {
        s.step_time();
    }
    assert!(s.converged(), "snapshot install brings the follower up to date");
    assert!(s.nodes[&lag].disk.snapshot.is_some());
}

#[test]
fn membership_add_and_remove() {
    let mut s = Sim::new(11, 3);
    for _ in 0..100 {
        s.step_time();
    }
    // A new node joins knowing nothing (no voters): it must not campaign on its own.
    let raft = Raft::new(cfg(4), 4, HardState::default(), None, Vec::new(), Vec::new());
    s.nodes.insert(4, Node { raft, disk: Disk::default(), sm: Vec::new(), sm_index: 0, alive: true, voters0: Vec::new() });
    for _ in 0..50 {
        s.step_time();
    }
    assert_ne!(s.nodes[&4].raft.role(), Role::Leader);
    let l = s.leader().unwrap();
    // One change at a time: a second change is refused until the first commits.
    s.nodes.get_mut(&l).unwrap().raft.propose_conf(EntryKind::AddVoter(4)).unwrap();
    assert_eq!(s.nodes.get_mut(&l).unwrap().raft.propose_conf(EntryKind::RemoveVoter(1)), Err(ProposeError::Busy));
    s.drain(l);
    for _ in 0..100 {
        s.step_time();
    }
    assert_eq!(s.nodes[&4].raft.voters(), &[1, 2, 3, 4]);
    s.propose();
    for _ in 0..50 {
        s.step_time();
    }
    assert!(s.converged());
    // Remove the leader itself: it steps down once the removal commits, the rest carry on.
    let l = s.leader().unwrap();
    s.nodes.get_mut(&l).unwrap().raft.propose_conf(EntryKind::RemoveVoter(l)).unwrap();
    s.drain(l);
    for _ in 0..200 {
        s.step_time();
    }
    let nl = s.leader().unwrap();
    assert_ne!(nl, l);
    assert!(!s.nodes[&nl].raft.voters().contains(&l));
    s.crash(l);
    s.propose();
    for _ in 0..50 {
        s.step_time();
    }
    let live_ok = s.nodes.iter().filter(|(id, n)| **id != l && n.alive).all(|(_, n)| n.sm_index == s.nodes[&nl].sm_index);
    assert!(live_ok);
}

#[test]
fn learner_catches_up_without_counting_for_quorum() {
    // One voter; a learner that is down must not stall commits (as a voter it would: 2 of 2).
    let mut s = Sim::new(17, 1);
    for _ in 0..50 {
        s.step_time();
    }
    let raft = Raft::new(cfg(2), 2, HardState::default(), None, Vec::new(), Vec::new());
    s.nodes.insert(2, Node { raft, disk: Disk::default(), sm: Vec::new(), sm_index: 0, alive: true, voters0: Vec::new() });
    let l = s.leader().unwrap();
    s.nodes.get_mut(&l).unwrap().raft.propose_conf(EntryKind::AddLearner(2)).unwrap();
    s.drain(l);
    for _ in 0..50 {
        s.step_time();
    }
    assert_eq!(s.nodes[&l].raft.learners(), &[2]);
    assert_eq!(s.nodes[&2].raft.learners(), &[2], "the learner learns its own membership");
    s.crash(2);
    let before = s.nodes[&l].sm_index;
    s.propose();
    for _ in 0..50 {
        s.step_time();
    }
    assert!(s.nodes[&l].sm_index > before, "a dead learner stalled the commit");
    // Back up: it catches up, never campaigns, and only then is promoted.
    s.restart(2, 99);
    for _ in 0..200 {
        s.step_time();
    }
    assert_ne!(s.nodes[&2].raft.role(), Role::Leader);
    assert_eq!(s.leader(), Some(l));
    assert_eq!(s.nodes[&l].raft.matched(2), Some(s.nodes[&l].raft.last_index()));
    assert_eq!(s.nodes[&2].sm_index, s.nodes[&l].sm_index);
    s.nodes.get_mut(&l).unwrap().raft.propose_conf(EntryKind::AddVoter(2)).unwrap();
    s.drain(l);
    for _ in 0..100 {
        s.step_time();
    }
    assert_eq!(s.nodes[&2].raft.voters(), &[1, 2]);
    assert!(s.nodes[&2].raft.learners().is_empty());
    // Learners survive compaction (snapshot metadata).
    let li = s.nodes[&l].raft.applied();
    s.nodes.get_mut(&l).unwrap().raft.compact(li, Rc::from(&b"img"[..]));
    assert_eq!(s.nodes[&l].raft.snapshot().unwrap().meta.voters, vec![1, 2]);
}

#[test]
fn leadership_transfer() {
    let mut s = Sim::new(13, 3);
    for _ in 0..100 {
        s.step_time();
    }
    let l = s.leader().unwrap();
    let target = *s.nodes.keys().find(|id| **id != l).unwrap();
    s.nodes.get_mut(&l).unwrap().raft.transfer_leadership(target);
    s.drain(l);
    for _ in 0..30 {
        s.step_time();
    }
    assert_eq!(s.leader(), Some(target));
}

#[test]
fn codec_roundtrips_and_rejects_garbage() {
    let snap = Snapshot { meta: SnapshotMeta { index: 9, term: 3, voters: vec![1, 2, 3], learners: vec![] }, data: Rc::from(&b"state"[..]) };
    let entries = vec![
        Entry { term: 2, index: 5, kind: EntryKind::Normal, data: b"a".to_vec() },
        Entry { term: 2, index: 6, kind: EntryKind::AddVoter(4), data: Vec::new() },
    ];
    let msgs = [
        MsgBody::PreVote { last_index: 1, last_term: 2 },
        MsgBody::PreVoteResp { granted: true },
        MsgBody::Vote { last_index: 1, last_term: 2, transfer: true },
        MsgBody::VoteResp { granted: false },
        MsgBody::Append { prev_index: 4, prev_term: 2, entries, commit: 3 },
        MsgBody::AppendResp { success: false, index: 7 },
        MsgBody::InstallSnapshot { snapshot: snap },
        MsgBody::TimeoutNow,
    ];
    for body in msgs {
        let m = Message { from: 1, to: 2, term: 5, body };
        let b = codec::encode_message(&m);
        assert_eq!(codec::decode_message(&b), Some(m.clone()));
        // Truncations and trailing bytes are rejected, never panic.
        for cut in 0..b.len() {
            assert!(codec::decode_message(&b[..cut]).is_none());
        }
        let mut extra = b.clone();
        extra.push(0);
        assert!(codec::decode_message(&extra).is_none());
    }
    // Non-contiguous entries in an Append are rejected.
    let bad = Message { from: 1, to: 2, term: 1, body: MsgBody::Append { prev_index: 4, prev_term: 1, entries: vec![Entry { term: 1, index: 9, kind: EntryKind::Normal, data: Vec::new() }], commit: 0 } };
    assert!(codec::decode_message(&codec::encode_message(&bad)).is_none());
    let hs = HardState { term: 3, vote: Some(2), commit: 7 };
    assert_eq!(codec::decode_hard_state(&codec::encode_hard_state(&hs)), Some(hs));
    let _ = HashSet::<u8>::new();
}

/// Raft paper Figure 8 / §5.4.2: a leader never commits an entry of an earlier term by counting
/// replicas; it commits only once an entry of its own term is on a majority (which then commits
/// the earlier ones too).
#[test]
fn old_term_entries_commit_only_with_a_current_term_entry() {
    // Node 1's log: two entries from term 1 (bootstrap config aside), now leader in a later term.
    let old: Vec<Entry> = (4..=5).map(|i| Entry { term: 1, index: i, kind: EntryKind::Normal, data: alloc::vec![i as u8] }).collect();
    let mut entries: Vec<Entry> = (1..=3).map(|i| Entry { term: 0, index: i, kind: EntryKind::AddVoter(i), data: Vec::new() }).collect();
    entries.extend(old);
    let hs = HardState { term: 2, vote: None, commit: 3 };
    let mut r = Raft::new(cfg(1), 5, hs, None, Vec::new(), entries);
    r.become_candidate(false);
    r.step(Message { from: 2, to: 1, term: r.term, body: MsgBody::VoteResp { granted: true } });
    assert_eq!(r.role(), Role::Leader);
    let noop = r.last_index();
    assert_eq!(r.term_at(noop), Some(r.term));
    let rd = r.ready();
    r.advance(rd); // the leader's own entries are now stable
    // Follower 2 has the old-term entries (index 5) but not the new no-op: index 5 is now on a
    // majority (nodes 1 and 2), yet it must NOT commit.
    let t = r.term;
    r.step(Message { from: 2, to: 1, term: t, body: MsgBody::AppendResp { success: true, index: 5 } });
    assert_eq!(r.commit, 3, "an old-term entry committed by counting replicas (Figure 8)");
    // Once the current-term no-op is on the majority, everything up to it commits.
    r.step(Message { from: 2, to: 1, term: t, body: MsgBody::AppendResp { success: true, index: noop } });
    assert_eq!(r.commit, noop);
}
