//! Writes reaching a follower are proxied to the leader's API port (ADR-026).
//!
//! The follower authenticates the request itself and sends the resulting identity in
//! [`IDENTITY`], over TLS with its own server certificate; the leader honours that header only
//! when the TLS client certificate is a `system:kr-servers` one ([`trusted_identity`]). The
//! leader answers with the store revision after the write ([`REVISION`]), and the follower
//! waits until it has applied that revision before replying, so a client that writes and then
//! reads through the same server sees its own write.

use super::{transport, Cluster};
use crate::api::User;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_fmt::json::{self, Value};
use kr_net::dns::SystemResolver;
use kr_net::http1::client::{Client as Http, Config as HttpConfig};
use kr_net::tls::TlsConnector;

/// `base64(JSON {"name","groups"})` of the user a forwarded request is made for.
pub const IDENTITY: &str = "Kr-Forwarded-Identity";
/// Store revision on the leader once the forwarded write committed.
pub const REVISION: &str = "Kr-Revision";
const MAX_BODY: usize = 64 << 20;
/// How long a follower waits to apply the leader's revision before replying anyway.
const CATCH_UP_MS: u64 = 5_000;

/// Headers that are not passed on: hop-by-hop, framing, credentials (the identity replaces
/// them) and our own.
fn skip(name: &str) -> bool {
    ["host", "connection", "keep-alive", "transfer-encoding", "content-length", "authorization", "upgrade", "te", "trailer", "proxy-authorization", IDENTITY, REVISION].iter().any(|h| h.eq_ignore_ascii_case(name))
}

pub fn encode_identity(u: &User) -> String {
    let groups = Value::Array(u.groups.iter().map(|g| Value::from(g.as_str())).collect());
    let v = Value::Object(alloc::vec![("name".to_string(), Value::from(u.name.as_str())), ("groups".to_string(), groups)]);
    kr_fmt::base64::encode(json::to_string(&v).as_bytes())
}

fn decode_identity(h: &str) -> Option<User> {
    let v = json::parse(&kr_fmt::base64::decode(h).ok()?).ok()?;
    let name = v.get("name")?.as_str()?.to_string();
    let groups = v.get("groups")?.as_array()?.iter().map(|g| g.as_str().map(String::from)).collect::<Option<Vec<_>>>()?;
    (!name.is_empty()).then_some(User { name, groups })
}

/// The forwarded identity of a request, if it came from another server: the TLS layer already
/// verified `peer_cert` against the cluster CA, and only server certificates may vouch.
pub fn trusted_identity(peer_cert: Option<&[u8]>, header: Option<&str>) -> Option<User> {
    transport::peer_id(peer_cert?)?;
    decode_identity(header?)
}

pub struct Forwarded {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
    pub warnings: Vec<String>,
}

impl Cluster {
    fn http(&self) -> Rc<Http<TlsConnector>> {
        self.forwarder
            .borrow_mut()
            .get_or_insert_with(|| Rc::new(Http::with_connector(TlsConnector::new(SystemResolver::system(), self.tls.clone()), HttpConfig { max_redirects: 0, user_agent: "kr-server".to_string(), ..HttpConfig::default() })))
            .clone()
    }

    /// POSTs `body` to server `to` as this server itself (no forwarded identity); the status.
    pub async fn post_as_self(&self, api: &crate::api::ApiServer, to: kr_raft::NodeId, path: &str, body: &[u8]) -> Option<u16> {
        let a = self.addr_of(api, to)?;
        let url = alloc::format!("https://{}.{}.{}.{}:{}{}", a.ip[0], a.ip[1], a.ip[2], a.ip[3], a.api_port, path);
        let http = self.http();
        let mut resp = kr_rt::exec::timeout(10_000, http.request("POST", &url, &[("Content-Type", "application/json")], body)).await.ok()?.ok()?;
        let _ = resp.read_to_end(1 << 20).await;
        Some(resp.status)
    }

    /// Sends the request to `leader` as `user`; `None` if the leader is unreachable.
    #[allow(clippy::too_many_arguments)]
    pub async fn forward(&self, api: &crate::api::ApiServer, leader: kr_raft::NodeId, user: &User, method: &str, path: &str, query: &str, headers: &[(String, String)], body: &[u8]) -> Option<Forwarded> {
        let addr = self.addr_of(api, leader)?;
        let ip = addr.ip;
        let mut url = alloc::format!("https://{}.{}.{}.{}:{}{}", ip[0], ip[1], ip[2], ip[3], addr.api_port, path);
        if !query.is_empty() {
            url.push('?');
            url.push_str(query);
        }
        let ident = encode_identity(user);
        let mut h: Vec<(&str, &str)> = headers.iter().filter(|(k, _)| !skip(k)).map(|(k, v)| (k.as_str(), v.as_str())).collect();
        h.push((IDENTITY, &ident));
        let http = self.http();
        let mut resp = http.request(method, &url, &h, body).await.ok()?;
        let status = resp.status;
        let content_type = resp.header("content-type").unwrap_or("application/json").to_string();
        let warnings = resp.headers().iter().filter(|(k, _)| k.eq_ignore_ascii_case("warning")).map(|(_, v)| v.clone()).collect();
        let rev: Option<u64> = resp.header(REVISION).and_then(|r| r.parse().ok());
        let body = resp.read_to_end(MAX_BODY).await.ok()?;
        if let Some(rev) = rev {
            let _ = kr_rt::exec::timeout(CATCH_UP_MS, self.wait_applied(rev)).await;
        }
        Some(Forwarded { status, content_type, body, warnings })
    }
}
