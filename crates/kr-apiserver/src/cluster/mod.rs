//! HA: the kr-store log replicated across servers with Raft (ADR-026).
//!
//! [`Cluster`] is the Raft driver for one server. It owns the Raft state machine, its on-disk
//! [`Storage`], and the outbound [`transport::Peer`] links; the API server's store is in
//! replicated mode ([`kr_store::Store::replicated`]). Each `Ready` is processed in order:
//! persist (hard state, truncation, entries, fsync off the event loop, received snapshot) →
//! send messages → apply committed entries (store records, membership) → `advance`.
//!
//! Writes on the leader are applied to the store speculatively by the request handler; their
//! records are proposed ([`Cluster::propose`]) and the response waits for the commit
//! ([`Cluster::wait_committed`]). Watch events are released only up to the committed revision.
//! A leader that steps down with uncommitted writes rebuilds its store from the snapshot plus
//! the committed log; writes that did replicate are applied again when they commit.

pub mod forward;
pub mod join;
pub mod transport;

use crate::api::ApiServer;
use crate::durable::Committer;
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::future::poll_fn;
use core::task::{Poll, Waker};
use kr_crypto::tls::ClientConfig;
use kr_raft::storage::Storage;
use kr_raft::{Config, Entry, EntryKind, NodeId, ProposeError, Raft, Ready, Role, Snapshot};
use kr_store::Store;
use transport::{Inbox, Peer};

/// One tick = 100 ms: heartbeat every 200 ms, election timeout 1–2 s.
pub const TICK_MS: u64 = 100;
/// Take a snapshot once this many entries were applied since the last one.
const SNAPSHOT_EVERY: u64 = 10_000;
/// Store key prefix of server addresses (replicated with everything else).
pub const SERVERS_PREFIX: &str = "/kr/servers/";

#[derive(Debug, PartialEq, Eq)]
pub enum WriteError {
    /// Not the leader (the leader's id, if known); the request should be forwarded.
    NotLeader(Option<NodeId>),
    /// Leadership changed before the entry committed: outcome unknown, the client may retry.
    Lost,
    /// The local log could not be written.
    Storage,
}

/// The address of a server, as stored under [`SERVERS_PREFIX`]`<id>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerAddr {
    pub ip: [u8; 4],
    pub raft_port: u16,
    pub api_port: u16,
}

impl ServerAddr {
    pub fn to_json(&self) -> String {
        let ip = self.ip;
        alloc::format!(r#"{{"ip":"{}.{}.{}.{}","raftPort":{},"apiPort":{}}}"#, ip[0], ip[1], ip[2], ip[3], self.raft_port, self.api_port)
    }

    pub fn from_json(b: &[u8]) -> Option<ServerAddr> {
        let v = kr_fmt::json::parse(b).ok()?;
        let ip = crate::object::parse_ipv4(v.get("ip")?.as_str()?)?;
        Some(ServerAddr { ip, raft_port: v.get("raftPort")?.as_u64()? as u16, api_port: v.get("apiPort")?.as_u64()? as u16 })
    }
}

pub struct Cluster {
    pub id: NodeId,
    raft: RefCell<Raft>,
    storage: RefCell<Storage>,
    peers: RefCell<BTreeMap<NodeId, Peer>>,
    /// Addresses known before they are replicated (founding members, the leader we joined).
    seeds: RefCell<BTreeMap<NodeId, ServerAddr>>,
    tls: Rc<ClientConfig>,
    pub inbox: Rc<Inbox>,
    fsync: Committer,
    /// Last committed (applied) Raft index and store revision.
    committed_index: Cell<u64>,
    committed_rev: Cell<u64>,
    /// Term of the entry each waiting proposal got (to detect it being overwritten).
    waiting: RefCell<BTreeMap<u64, u64>>,
    waiters: RefCell<Vec<Waker>>,
    /// Proposals that failed because leadership changed (another entry may commit at the same
    /// index later; its writer must still see a failure). Pruned far behind the commit index.
    lost: RefCell<alloc::collections::BTreeSet<u64>>,
    was_leader: Cell<bool>,
    was_ready: Cell<bool>,
    /// Bumped on every leadership change (leader-only components restart on it).
    pub epoch: Cell<u64>,
    /// HTTP client for forwarding writes to the leader (created on first use).
    /// This server's own address, registered under [`SERVERS_PREFIX`] when it leads.
    self_addr: RefCell<Option<ServerAddr>>,
    /// Peer addresses as last saved to `peers` (a restarted server must reach the others
    /// before its store, where the addresses are replicated, is caught up).
    saved_peers: RefCell<String>,
    join_secrets: RefCell<Option<join::JoinSecrets>>,
    forwarder: RefCell<Option<Rc<kr_net::http1::client::Client<kr_net::tls::TlsConnector>>>>,
}

impl Cluster {
    /// Opens the node's Raft state in `dir`. `voters` is the initial membership for a brand
    /// new cluster (just `[id]` for the first server), empty for a server joining one.
    pub fn open(api: &ApiServer, id: NodeId, dir: &str, voters: Vec<NodeId>, tls: Rc<ClientConfig>, seed: u64) -> Result<Rc<Cluster>, String> {
        let (storage, loaded) = Storage::open(dir).map_err(|e| alloc::format!("raft storage: {e:?}"))?;
        if let Some(s) = &loaded.snapshot {
            api.store.borrow_mut().restore(&s.data).map_err(|e| alloc::format!("raft snapshot: {e:?}"))?;
        }
        let raft = Raft::new(Config::new(id), seed, loaded.hard_state, loaded.snapshot.clone(), voters, loaded.entries);
        let c = Cluster {
            id,
            committed_index: Cell::new(raft.snapshot_index()),
            committed_rev: Cell::new(api.store.borrow().revision()),
            raft: RefCell::new(raft),
            storage: RefCell::new(storage),
            peers: RefCell::new(BTreeMap::new()),
            seeds: RefCell::new(BTreeMap::new()),
            tls,
            inbox: Rc::default(),
            fsync: Committer::new(),
            waiting: RefCell::new(BTreeMap::new()),
            waiters: RefCell::new(Vec::new()),
            lost: RefCell::new(alloc::collections::BTreeSet::new()),
            was_leader: Cell::new(false),
            was_ready: Cell::new(false),
            epoch: Cell::new(0),
            self_addr: RefCell::new(None),
            saved_peers: RefCell::new(String::new()),
            join_secrets: RefCell::new(None),
            forwarder: RefCell::new(None),
        };
        api.store.borrow_mut().set_visible(c.committed_rev.get());
        if let Ok(Some(b)) = c.storage.borrow().load_extra("peers") {
            *c.saved_peers.borrow_mut() = String::from_utf8_lossy(&b).into_owned();
            if let Ok(kr_fmt::json::Value::Object(m)) = kr_fmt::json::parse(&b) {
                for (id, a) in m {
                    if let (Ok(id), Some(a)) = (id.parse::<NodeId>(), ServerAddr::from_json(kr_fmt::json::to_string(&a).as_bytes())) {
                        c.seeds.borrow_mut().insert(id, a);
                    }
                }
            }
        }
        Ok(Rc::new(c))
    }

    pub fn is_leader(&self) -> bool {
        self.raft.borrow().role() == Role::Leader
    }

    /// Leader that has applied an entry of its own term, hence everything committed before its
    /// election: only then may it change the store (a write before that would take revisions
    /// that committed entries already own).
    pub fn ready(&self) -> bool {
        let r = self.raft.borrow();
        r.role() == Role::Leader && r.applied_term() == Some(r.term)
    }

    pub fn leader(&self) -> Option<NodeId> {
        self.raft.borrow().leader()
    }

    pub fn voters(&self) -> Vec<NodeId> {
        self.raft.borrow().voters().to_vec()
    }

    pub fn learners(&self) -> Vec<NodeId> {
        self.raft.borrow().learners().to_vec()
    }

    /// Leader: `id` has every entry up to the commit index.
    pub fn caught_up(&self, id: NodeId) -> bool {
        let r = self.raft.borrow();
        r.matched(id).is_some_and(|m| m >= r.commit)
    }

    pub fn term(&self) -> u64 {
        self.raft.borrow().term
    }

    /// Proposes store records (leader only); returns the entry index.
    pub fn propose(&self, records: Vec<u8>) -> Result<u64, WriteError> {
        let r = self.raft.borrow_mut().propose(records);
        self.map_propose(r)
    }

    /// Adds or removes a voter (leader only, one change at a time).
    pub fn propose_conf(&self, kind: EntryKind) -> Result<u64, WriteError> {
        let r = self.raft.borrow_mut().propose_conf(kind);
        self.map_propose(r)
    }

    fn map_propose(&self, r: Result<u64, ProposeError>) -> Result<u64, WriteError> {
        match r {
            Ok(idx) => {
                let term = self.raft.borrow().term;
                self.waiting.borrow_mut().insert(idx, term);
                self.inbox.notify.notify();
                Ok(idx)
            }
            Err(ProposeError::NotLeader(l)) => Err(WriteError::NotLeader(l)),
            Err(ProposeError::Busy) => Err(WriteError::Lost),
        }
    }

    /// Resolves once entry `index` is committed and applied, or fails if it was lost.
    pub async fn wait_committed(&self, index: u64) -> Result<(), WriteError> {
        poll_fn(|cx| {
            if !self.waiting.borrow().contains_key(&index) {
                // Done (or failed): failed ones are recorded as committed_index < index.
                return Poll::Ready(if self.committed_index.get() >= index && !self.lost_index(index) { Ok(()) } else { Err(WriteError::Lost) });
            }
            self.waiters.borrow_mut().push(cx.waker().clone());
            Poll::Pending
        })
        .await
    }

    pub fn committed_rev(&self) -> u64 {
        self.committed_rev.get()
    }

    /// Resolves once the committed store revision reaches `rev`; fails if leadership changed
    /// meanwhile (the write may or may not survive: the client should retry).
    pub async fn wait_rev(&self, rev: u64) -> Result<(), WriteError> {
        let epoch = self.epoch.get();
        poll_fn(|cx| {
            if self.committed_rev.get() >= rev {
                return Poll::Ready(Ok(()));
            }
            if self.epoch.get() != epoch || !self.is_leader() {
                return Poll::Ready(Err(WriteError::Lost));
            }
            self.waiters.borrow_mut().push(cx.waker().clone());
            Poll::Pending
        })
        .await
    }

    /// Resolves once this server has applied store revision `rev` (any role).
    pub async fn wait_applied(&self, rev: u64) {
        poll_fn(|cx| {
            if self.committed_rev.get() >= rev {
                return Poll::Ready(());
            }
            self.waiters.borrow_mut().push(cx.waker().clone());
            Poll::Pending
        })
        .await
    }

    /// Where a write should go: `Ok(None)` = handle it here (ready leader), `Ok(Some(id))` =
    /// forward to leader `id`. Waits up to `max_ms` through an election; `Err` = no leader.
    pub async fn route(&self, max_ms: u64) -> Result<Option<NodeId>, Option<NodeId>> {
        let deadline = kr_rt::exec::now_ms() + max_ms;
        loop {
            if self.ready() {
                return Ok(None);
            }
            match self.leader() {
                Some(l) if l != self.id => return Ok(Some(l)),
                l => {
                    if kr_rt::exec::now_ms() >= deadline {
                        return Err(l);
                    }
                }
            }
            kr_rt::exec::sleep(50).await;
        }
    }

    /// A server's address: the replicated `/kr/servers/<id>` entry, else the seed.
    pub fn addr_of(&self, api: &ApiServer, id: NodeId) -> Option<ServerAddr> {
        let stored = api.store.borrow().get(&alloc::format!("{SERVERS_PREFIX}{id}")).and_then(|kv| ServerAddr::from_json(&kv.value));
        stored.or_else(|| self.seeds.borrow().get(&id).cloned())
    }

    fn lost_index(&self, index: u64) -> bool {
        self.lost.borrow().contains(&index)
    }

    fn wake_waiters(&self) {
        for w in self.waiters.borrow_mut().drain(..) {
            w.wake();
        }
    }

    /// An address to use until the replicated `/kr/servers/<id>` entry says otherwise.
    pub fn add_seed(&self, id: NodeId, addr: ServerAddr) {
        self.seeds.borrow_mut().insert(id, addr);
        self.inbox.notify.notify();
    }

    pub fn set_self_addr(&self, addr: ServerAddr) {
        *self.self_addr.borrow_mut() = Some(addr);
    }

    /// Addresses of all servers known to the replicated store.
    pub fn servers(&self, api: &ApiServer) -> Vec<(NodeId, ServerAddr)> {
        let (kvs, _) = api.store.borrow().list(SERVERS_PREFIX, None, 1000);
        kvs.iter().filter_map(|kv| Some((kv.key.strip_prefix(SERVERS_PREFIX)?.parse().ok()?, ServerAddr::from_json(&kv.value)?))).collect()
    }

    /// Ready leader: make sure the store has this server's current address.
    fn register_self(&self, api: &ApiServer) {
        let Some(me) = self.self_addr.borrow().clone() else { return };
        let key = alloc::format!("{SERVERS_PREFIX}{}", self.id);
        let mut store = api.store.borrow_mut();
        match store.get(&key) {
            Some(kv) if ServerAddr::from_json(&kv.value).as_ref() == Some(&me) => {}
            Some(_) => {
                let _ = store.update(&key, me.to_json().into_bytes(), None);
            }
            None => {
                let _ = store.create(&key, me.to_json().into_bytes());
            }
        }
    }

    /// Keeps `/kr/servers/<id>` equal to this server's current address (e.g. after its IP
    /// changed): the leader writes its own; a member follower asks the leader through
    /// `/kr/add-server`, which only updates the address of an existing voter.
    pub async fn keep_registered(self: Rc<Self>, api: Rc<ApiServer>) {
        loop {
            kr_rt::exec::sleep(15_000).await;
            let Some(me) = self.self_addr.borrow().clone() else { continue };
            let stored = api.store.borrow().get(&alloc::format!("{SERVERS_PREFIX}{}", self.id)).and_then(|kv| ServerAddr::from_json(&kv.value));
            if stored.as_ref() == Some(&me) || !self.voters().contains(&self.id) {
                continue; // up to date, or not a member (the join flow registers it)
            }
            if self.ready() {
                self.register_self(&api);
                continue;
            }
            // Our own certificate is the identity; any server works (a follower forwards it
            // once). Other servers may still be sending to our old address, so the leader may
            // be unknown here: try it first, then everyone else.
            let mut targets: Vec<NodeId> = self.leader().into_iter().collect();
            targets.extend(self.voters().into_iter().filter(|v| *v != self.id && Some(*v) != self.leader()));
            let ip = me.ip;
            let body = alloc::format!(r#"{{"ip":"{}.{}.{}.{}","raftPort":{},"apiPort":{}}}"#, ip[0], ip[1], ip[2], ip[3], me.raft_port, me.api_port);
            for t in targets {
                if self.post_as_self(&api, t, "/kr/add-server", body.as_bytes()).await == Some(200) {
                    kr_rt::eprint(b"kr server: re-registered this server's address\n");
                    break;
                }
            }
        }
    }

    /// Updates the outbound links from the current voters and their stored addresses.
    fn sync_peers(&self, api: &ApiServer) {
        let mut voters = self.voters();
        voters.extend(self.learners());
        if !voters.contains(&self.id) || self.learners().contains(&self.id) {
            // Joining: answer the servers we were told about until we learn the membership.
            voters.extend(self.seeds.borrow().keys().filter(|id| !voters.contains(id)).copied().collect::<Vec<_>>());
        }
        let store = api.store.borrow();
        let mut peers = self.peers.borrow_mut();
        peers.retain(|id, _| voters.contains(id));
        let mut known = String::from("{");
        for id in voters {
            if id == self.id {
                continue;
            }
            let stored = store.get(&alloc::format!("{SERVERS_PREFIX}{id}")).and_then(|kv| ServerAddr::from_json(&kv.value));
            let Some(a) = stored.or_else(|| self.seeds.borrow().get(&id).cloned()) else { continue };
            if known.len() > 1 {
                known.push(',');
            }
            known.push_str(&alloc::format!("\"{id}\":{}", a.to_json()));
            match peers.get(&id) {
                Some(p) => p.set_addr((a.ip, a.raft_port)),
                None => {
                    peers.insert(id, Peer::new((a.ip, a.raft_port), self.tls.clone()));
                }
            }
        }
        known.push('}');
        if *self.saved_peers.borrow() != known {
            // Best effort: without it a restart still works whenever a quorum is up.
            if self.storage.borrow_mut().save_extra("peers", known.as_bytes()).is_ok() {
                *self.saved_peers.borrow_mut() = known;
            }
        }
    }

    /// The driver: run forever on the API server's event loop.
    pub async fn run(self: Rc<Self>, api: Rc<ApiServer>) {
        let mut next_tick = kr_rt::exec::now_ms() + TICK_MS;
        self.sync_peers(&api);
        loop {
            let now = kr_rt::exec::now_ms();
            if now >= next_tick {
                self.raft.borrow_mut().tick();
                next_tick = now + TICK_MS;
            }
            loop {
                let m = self.inbox.msgs.borrow_mut().pop_front();
                let Some(m) = m else { break };
                self.raft.borrow_mut().step(m);
            }
            // Writes by in-process components (controllers) are proposed in batches.
            if self.is_leader() {
                let recs = api.store.borrow_mut().take_records();
                if !recs.is_empty() {
                    let _ = self.propose(recs);
                }
            }
            while self.raft.borrow().has_ready() {
                let rd = self.raft.borrow_mut().ready();
                if !self.handle_ready(&api, rd).await {
                    // Storage failure: a server that cannot persist must not keep voting.
                    kr_rt::eprint(b"kr server: raft storage failure, exiting\n");
                    kr_sys::exit_group(1);
                }
            }
            self.leadership_changes(&api);
            if self.peers.borrow().len() + 1 < self.voters().len() + self.learners().len() || !self.voters().contains(&self.id) {
                self.sync_peers(&api); // still missing links (addresses not known yet)
            }
            let wait = next_tick.saturating_sub(kr_rt::exec::now_ms()).max(1);
            self.inbox.notify.wait(wait).await;
        }
    }

    async fn handle_ready(&self, api: &ApiServer, rd: Ready) -> bool {
        {
            let mut st = self.storage.borrow_mut();
            if let Some(hs) = rd.hard_state {
                if st.set_hard_state(hs).is_err() {
                    return false;
                }
            }
            if let Some(from) = rd.truncate_from {
                if st.truncate(from).is_err() {
                    return false;
                }
            }
            if st.append(&rd.entries).is_err() {
                return false;
            }
        }
        if !rd.entries.is_empty() || rd.truncate_from.is_some() {
            let fd = self.storage.borrow().log_fd();
            if !self.fsync.fsync_fd(fd).await {
                return false;
            }
        }
        if let Some(s) = &rd.snapshot {
            if self.storage.borrow_mut().save_snapshot(s).is_err() {
                return false;
            }
            if api.store.borrow_mut().restore(&s.data).is_err() {
                return false;
            }
            api.reload_crds();
            self.committed_index.set(s.meta.index);
            self.committed_rev.set(api.store.borrow().revision());
        }
        for m in &rd.messages {
            if let Some(p) = self.peers.borrow().get(&m.to) {
                p.send(m);
            }
        }
        let mut membership = false;
        for e in &rd.committed {
            self.apply(api, e);
            membership |= e.kind.is_conf();
        }
        let had_committed = !rd.committed.is_empty();
        self.raft.borrow_mut().advance(rd);
        if had_committed {
            let ci = self.committed_index.get();
            self.waiting.borrow_mut().retain(|idx, _| *idx > ci);
            self.lost.borrow_mut().retain(|idx| *idx + 100_000 > ci);
            self.wake_waiters();
            self.maybe_snapshot(api);
        }
        if membership || had_committed {
            // Server addresses arrive as ordinary committed writes.
            self.sync_peers(api);
        }
        true
    }

    fn apply(&self, api: &ApiServer, e: &Entry) {
        if e.kind == EntryKind::Normal && !e.data.is_empty() {
            let crds = Store::records_touch(&e.data, &ApiServer::crd_prefix());
            self.apply_store(api, e);
            if crds {
                api.reload_crds();
            }
        }
        self.committed_index.set(e.index);
    }

    fn apply_store(&self, api: &ApiServer, e: &Entry) {
        {
            let mut store = api.store.borrow_mut();
            if store.apply_records(&e.data).is_err() {
                // Divergence from the replicated log is unrecoverable for this replica.
                kr_rt::eprint(b"kr server: replicated records do not apply, exiting\n");
                kr_sys::exit_group(1);
            }
            if let Some(rev) = Store::records_last_rev(&e.data) {
                self.committed_rev.set(rev);
                store.set_visible(rev);
            }
        }
    }

    /// Snapshot at a quiescent moment (the leader's store holds no uncommitted writes).
    fn maybe_snapshot(&self, api: &ApiServer) {
        let (applied, snap) = {
            let r = self.raft.borrow();
            (r.applied(), r.snapshot_index())
        };
        if applied < snap + SNAPSHOT_EVERY {
            return;
        }
        let store = api.store.borrow();
        if store.revision() != self.committed_rev.get() {
            return;
        }
        let data: Rc<[u8]> = Rc::from(store.image());
        drop(store);
        self.raft.borrow_mut().compact(applied, data);
        let s = self.raft.borrow().snapshot().cloned();
        if let Some(s) = s {
            let _ = self.storage.borrow_mut().save_snapshot(&s);
        }
    }

    /// On becoming a ready leader: bootstrap. On losing leadership: fail waiting writes and
    /// drop uncommitted speculative state.
    fn leadership_changes(&self, api: &ApiServer) {
        let ready = self.ready();
        if ready && !self.was_ready.get() {
            self.was_ready.set(true);
            self.register_self(api);
            api.bootstrap_all();
            self.inbox.notify.notify(); // propose the bootstrap records
        }
        if !ready {
            self.was_ready.set(false);
        }
        let leader = self.is_leader();
        if leader == self.was_leader.get() {
            return;
        }
        self.was_leader.set(leader);
        self.epoch.set(self.epoch.get() + 1);
        if leader {
            return;
        }
        let pending: Vec<u64> = self.waiting.borrow().keys().copied().collect();
        self.lost.borrow_mut().extend(pending);
        self.waiting.borrow_mut().clear();
        self.wake_waiters();
        if api.store.borrow().revision() > self.committed_rev.get() {
            self.rebuild(api);
        }
    }

    /// Store = snapshot + committed entries (drops speculative writes of a deposed leader).
    pub(crate) fn rebuild(&self, api: &ApiServer) {
        let (base, entries) = {
            let r = self.raft.borrow();
            let base: Vec<u8> = r.snapshot().map(|s| s.data.to_vec()).unwrap_or_else(|| Store::replicated().image());
            let entries: Vec<Entry> = r.entries(r.snapshot_index() + 1, self.committed_index.get());
            (base, entries)
        };
        let mut store = api.store.borrow_mut();
        if store.restore(&base).is_err() {
            kr_sys::exit_group(1);
        }
        for e in entries.iter().filter(|e| e.kind == EntryKind::Normal) {
            if store.apply_records(&e.data).is_err() {
                kr_sys::exit_group(1);
            }
        }
        let rev = store.revision();
        store.set_visible(rev);
        self.committed_rev.set(rev);
        let _ = store.take_records();
        drop(store);
        api.reload_crds();
    }

    /// Runs `start()` while this server is the ready leader and aborts it when leadership is
    /// lost (controllers and the scheduler: exactly one copy runs in the cluster).
    pub async fn while_leader<F: core::future::Future<Output = ()> + 'static>(self: Rc<Self>, start: impl Fn() -> F) {
        loop {
            while !self.ready() {
                kr_rt::exec::sleep(200).await;
            }
            let epoch = self.epoch.get();
            let task = kr_rt::exec::spawn(start());
            while self.epoch.get() == epoch && self.is_leader() {
                kr_rt::exec::sleep(200).await;
            }
            task.abort();
        }
    }

    /// Hands leadership to another voter (graceful shutdown or removal).
    pub fn transfer_leadership(&self, to: NodeId) {
        self.raft.borrow_mut().transfer_leadership(to);
        self.inbox.notify.notify();
    }

    /// (term, role, leader, commit, last index, applied, voters) for diagnostics.
    pub fn debug_state(&self) -> String {
        let r = self.raft.borrow();
        alloc::format!("term={} role={:?} leader={:?} commit={} last={} applied={} voters={:?} peers={:?}", r.term, r.role(), r.leader(), r.commit, r.last_index(), r.applied(), r.voters(), self.peers.borrow().keys().collect::<Vec<_>>())
    }

    pub fn snapshot_for_tests(&self) -> Option<Snapshot> {
        self.raft.borrow().snapshot().cloned()
    }
}
