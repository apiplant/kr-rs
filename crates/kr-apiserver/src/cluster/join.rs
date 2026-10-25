//! Server membership endpoints (ADR-026). All are POSTs, so a follower forwards them and they
//! run on the ready leader.
//!
//! - `POST /kr/join-server {"token"}`: a new server presents the *server* token (never an
//!   agent token: the answer holds the CA and service-account signing keys) and receives the
//!   cluster's key material. Nothing changes yet.
//! - `POST /kr/add-server {"ip","raftPort","apiPort"}`: the new server, now listening with its
//!   own `system:kr-server:<id>` certificate, asks to become a voter. Its id comes from the
//!   authenticated identity, never from the body.
//! - `POST /kr/remove-server {"id"}`: cluster admins (`system:masters`) remove a voter.

use super::{transport, Cluster, ServerAddr, WriteError, SERVERS_PREFIX};
use crate::api::{ApiServer, Reply, Req, User};
use crate::object::ApiError;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_fmt::json::{self, Value};
use kr_raft::{EntryKind, NodeId};

/// What a joining server receives: the secret it must present, and (file, contents) pairs it
/// writes under its data dir (`pki/ca.pem`, `pki/ca.key`, `pki/sa.key`, `node-token`,
/// `server-token`).
pub struct JoinSecrets {
    pub token_secret: String,
    pub files: Vec<(String, String)>,
}

/// How long `/kr/add-server` waits for a learner to catch up before asking it to retry.
const CATCH_UP_MS: u64 = 20_000;

pub const PATHS: [&str; 3] = ["/kr/join-server", "/kr/add-server", "/kr/remove-server"];

fn ok(v: Value) -> Reply {
    Reply::Json(200, json::to_string(&v))
}

fn obj(fields: Vec<(&str, Value)>) -> Value {
    Value::Object(fields.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn write_err(e: WriteError) -> ApiError {
    match e {
        WriteError::NotLeader(l) => crate::api::not_leader(l),
        WriteError::Lost => ApiError::new(503, "ServiceUnavailable", "leadership changed; retry"),
        WriteError::Storage => ApiError::new(500, "InternalError", "storage failure"),
    }
}

/// The server id of an authenticated server identity.
fn server_id(u: &User) -> Option<NodeId> {
    if !u.groups.iter().any(|g| g == transport::ORG) {
        return None;
    }
    u.name.strip_prefix("system:kr-server:")?.parse().ok().filter(|id| *id != 0)
}

impl Cluster {
    pub fn set_join_secrets(&self, s: JoinSecrets) {
        *self.join_secrets.borrow_mut() = Some(s);
    }

    /// Handles a membership request on the ready leader; `None` if `req` is not one.
    pub async fn membership(&self, api: &ApiServer, req: &Req<'_>) -> Option<Reply> {
        if req.method != "POST" || !PATHS.contains(&req.path) {
            return None;
        }
        Some(match self.membership_inner(api, req).await {
            Ok(r) => r,
            Err(e) => Reply::err(e),
        })
    }

    async fn membership_inner(&self, api: &ApiServer, req: &Req<'_>) -> Result<Reply, ApiError> {
        let body = json::parse(req.body).map_err(|_| ApiError::bad_request("request body must be JSON"))?;
        match req.path {
            "/kr/join-server" => {
                let token = body.get("token").and_then(Value::as_str).unwrap_or("");
                let secrets = self.join_secrets.borrow();
                let s = secrets.as_ref().ok_or_else(|| ApiError::new(503, "ServiceUnavailable", "this server cannot admit servers"))?;
                if s.token_secret.is_empty() || !kr_crypto::ct_eq(token.as_bytes(), s.token_secret.as_bytes()) {
                    return Err(ApiError::new(401, "Unauthorized", "invalid server token"));
                }
                let files = Value::Object(s.files.iter().map(|(k, v)| (k.clone(), Value::from(v.as_str()))).collect());
                // Where the current servers are, so the newcomer can answer the leader before
                // it knows the membership (it is not a voter until it does).
                let servers = Value::Array(
                    self.servers(api)
                        .into_iter()
                        .map(|(id, a)| obj(alloc::vec![("id", Value::from(id as i64)), ("ip", Value::from(alloc::format!("{}.{}.{}.{}", a.ip[0], a.ip[1], a.ip[2], a.ip[3]).as_str())), ("raftPort", Value::from(a.raft_port as i64)), ("apiPort", Value::from(a.api_port as i64))]))
                        .collect(),
                );
                Ok(ok(obj(alloc::vec![("files", files), ("servers", servers)])))
            }
            "/kr/add-server" => {
                let user = api.authenticate(req)?;
                let id = server_id(&user).ok_or_else(|| ApiError::new(403, "Forbidden", "only server certificates may join as servers"))?;
                let ip = body.get("ip").and_then(Value::as_str).and_then(crate::object::parse_ipv4).ok_or_else(|| ApiError::bad_request("ip is required"))?;
                let port = |f: &str| body.get(f).and_then(Value::as_u64).filter(|p| (1..=65535).contains(p)).map(|p| p as u16).ok_or_else(|| ApiError::bad_request(alloc::format!("{f} is required")));
                let addr = ServerAddr { ip, raft_port: port("raftPort")?, api_port: port("apiPort")? };
                // The address first (so the leader can reach the new voter), then membership.
                self.put_addr(api, id, Some(&addr)).await?;
                if !self.voters().contains(&id) {
                    // A learner first: it receives the log without counting for quorum, so a
                    // newcomer that dies while catching up cannot stall the cluster.
                    if !self.learners().contains(&id) {
                        self.conf(EntryKind::AddLearner(id)).await?;
                    }
                    let deadline = kr_rt::exec::now_ms() + CATCH_UP_MS;
                    while !self.caught_up(id) {
                        if kr_rt::exec::now_ms() >= deadline || !self.ready() {
                            return Err(ApiError::new(503, "ServiceUnavailable", "the new server is still catching up; retry"));
                        }
                        kr_rt::exec::sleep(200).await;
                    }
                    self.conf(EntryKind::AddVoter(id)).await?;
                }
                self.refresh_endpoints(api).await?;
                Ok(ok(self.voters_json()))
            }
            "/kr/remove-server" => {
                let user = api.authenticate(req)?;
                if !user.groups.iter().any(|g| g == "system:masters") {
                    return Err(ApiError::new(403, "Forbidden", "removing a server requires system:masters"));
                }
                let id = body.get("id").and_then(Value::as_u64).ok_or_else(|| ApiError::bad_request("id is required"))?;
                let voters = self.voters();
                if voters.contains(&id) {
                    if voters.len() == 1 {
                        return Err(ApiError::new(409, "Conflict", "cannot remove the last server"));
                    }
                    if id == self.id {
                        // The leader cannot remove itself: hand over, the client retries.
                        if let Some(to) = voters.iter().copied().find(|v| *v != id) {
                            self.transfer_leadership(to);
                        }
                        return Err(ApiError::new(503, "ServiceUnavailable", "transferring leadership away from the server being removed; retry"));
                    }
                    self.conf(EntryKind::RemoveVoter(id)).await?;
                } else if self.learners().contains(&id) {
                    self.conf(EntryKind::RemoveVoter(id)).await?;
                }
                self.put_addr(api, id, None).await?;
                self.refresh_endpoints(api).await?;
                Ok(ok(self.voters_json()))
            }
            _ => Err(ApiError::new(404, "NotFound", "not found")),
        }
    }

    /// Proposes a membership change and waits for it to commit.
    async fn conf(&self, kind: EntryKind) -> Result<(), ApiError> {
        let idx = self.propose_conf(kind).map_err(|e| match e {
            WriteError::Lost => ApiError::new(503, "ServiceUnavailable", "another membership change is in progress; retry"),
            e => write_err(e),
        })?;
        self.wait_committed(idx).await.map_err(write_err)
    }

    fn voters_json(&self) -> Value {
        obj(alloc::vec![("voters", Value::Array(self.voters().into_iter().map(|v| Value::from(v as i64)).collect()))])
    }

    /// Sets (or with `None` deletes) `/kr/servers/<id>` and waits for it to commit.
    async fn put_addr(&self, api: &ApiServer, id: NodeId, addr: Option<&ServerAddr>) -> Result<(), ApiError> {
        let key = alloc::format!("{SERVERS_PREFIX}{id}");
        {
            let mut store = api.store.borrow_mut();
            let cur = store.get(&key).and_then(|kv| ServerAddr::from_json(&kv.value));
            let r = match (addr, cur) {
                (Some(a), Some(c)) if *a == c => Ok(()),
                (Some(a), Some(_)) => store.update(&key, a.to_json().into_bytes(), None).map(|_| ()),
                (Some(a), None) => store.create(&key, a.to_json().into_bytes()).map(|_| ()),
                (None, Some(_)) => store.delete(&key, None).map(|_| ()),
                (None, None) => Ok(()),
            };
            r.map_err(|_| ApiError::new(500, "InternalError", "store write failed"))?;
        }
        api.commit(api.revision()).await.map_err(|_| ApiError::new(503, "ServiceUnavailable", "write did not commit; retry"))
    }

    async fn refresh_endpoints(&self, api: &ApiServer) -> Result<(), ApiError> {
        api.refresh_endpoints();
        api.commit(api.revision()).await.map_err(|_| ApiError::new(503, "ServiceUnavailable", "write did not commit; retry"))
    }
}
