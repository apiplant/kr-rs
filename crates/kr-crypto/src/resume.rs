//! State for TLS 1.3 session resumption (ADR-051): the server's ticket keys and the client's
//! ticket cache, as plain data. `kr-crypto` keeps no global state and uses no `unsafe`, so the
//! process-wide instances live in `kr-net` and reach a [`crate::tls::Connection`] through the
//! function pointers of [`TicketHooks`] and [`SessionHooks`].

use crate::tls::Rng;
use crate::{chacha, wipe};
use alloc::vec::Vec;

/// How long a ticket is valid, in seconds (also the ticket key rotation period).
pub const TICKET_LIFETIME: u32 = 3600;
/// A chain of resumed sessions ends this long after the first full handshake.
pub const HARD_LIMIT_SECS: i64 = 24 * 3600;
/// Tickets kept by a client (one per server name and configuration).
const CACHE_CAP: usize = 64;
const KEY_ID: usize = 8;

struct Key {
    id: [u8; KEY_ID],
    key: [u8; 32],
    created: i64,
}

impl Drop for Key {
    fn drop(&mut self) {
        wipe(&mut self.key);
    }
}

/// The server's ticket encryption keys: the current one and the previous one (tickets sealed
/// under it are still accepted until the next rotation).
pub struct TicketKeys {
    cur: Option<Key>,
    prev: Option<Key>,
}

impl Default for TicketKeys {
    fn default() -> Self {
        Self::new()
    }
}

impl TicketKeys {
    pub const fn new() -> TicketKeys {
        TicketKeys { cur: None, prev: None }
    }

    /// Seals `plaintext` into a ticket: `key_id | nonce | ciphertext | tag`.
    pub fn seal(&mut self, plaintext: &[u8], now: i64, rng: Rng) -> Vec<u8> {
        if self.cur.as_ref().is_none_or(|k| now - k.created >= TICKET_LIFETIME as i64 || now < k.created) {
            let mut k = Key { id: [0; KEY_ID], key: [0; 32], created: now };
            rng(&mut k.id);
            rng(&mut k.key);
            self.prev = self.cur.replace(k);
        }
        let cur = self.cur.as_ref().expect("just set");
        let mut nonce = [0u8; 12];
        rng(&mut nonce);
        let mut out = Vec::with_capacity(KEY_ID + 12 + plaintext.len() + 16);
        out.extend_from_slice(&cur.id);
        out.extend_from_slice(&nonce);
        let start = out.len();
        out.extend_from_slice(plaintext);
        let tag = chacha::seal(&cur.key, &nonce, &cur.id, &mut out[start..]);
        out.extend_from_slice(&tag);
        out
    }

    /// The plaintext of a ticket sealed by this process under a current or previous key.
    pub fn open(&self, ticket: &[u8]) -> Option<Vec<u8>> {
        if ticket.len() < KEY_ID + 12 + 16 {
            return None;
        }
        let (id, rest) = ticket.split_at(KEY_ID);
        let key = [self.cur.as_ref(), self.prev.as_ref()].into_iter().flatten().find(|k| k.id == id)?;
        let (nonce, rest) = rest.split_at(12);
        let (ct, tag) = rest.split_at(rest.len() - 16);
        let mut data = ct.to_vec();
        chacha::open(&key.key, nonce.try_into().ok()?, &key.id, &mut data, tag).ok()?;
        Some(data)
    }
}

/// What a client keeps of a resumable session.
pub struct Session {
    /// The opaque ticket to present.
    pub ticket: Vec<u8>,
    /// The PSK derived from the resumption master secret.
    pub psk: [u8; 32],
    pub suite: u16,
    pub age_add: u32,
    /// When the ticket arrived (Unix seconds) and how long the server said it is good for.
    pub received_at: i64,
    pub lifetime: u32,
    /// The server's certificates from the full handshake (reported again after resumption).
    pub server_chain: Vec<Vec<u8>>,
    pub alpn: Option<Vec<u8>>,
}

impl Drop for Session {
    fn drop(&mut self) {
        wipe(&mut self.psk);
    }
}

/// Tickets by session key (server name and a fingerprint of the client configuration).
pub struct SessionCache {
    entries: Vec<(Vec<u8>, Session)>,
}

impl Default for SessionCache {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionCache {
    pub const fn new() -> SessionCache {
        SessionCache { entries: Vec::new() }
    }

    /// Stores a ticket, replacing the one under the same key.
    pub fn put(&mut self, key: &[u8], s: Session) {
        self.entries.retain(|(k, _)| k != key);
        if self.entries.len() >= CACHE_CAP {
            self.entries.remove(0);
        }
        self.entries.push((key.to_vec(), s));
    }

    /// Removes and returns the ticket under `key` if it has not expired (a ticket is offered once).
    pub fn take(&mut self, key: &[u8], now: i64) -> Option<Session> {
        let i = self.entries.iter().position(|(k, _)| k == key)?;
        let (_, s) = self.entries.remove(i);
        (now >= s.received_at && now < s.received_at + s.lifetime as i64).then_some(s)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// How a server connection seals and opens tickets (function pointers into the owner's keys).
#[derive(Clone, Copy)]
pub struct TicketHooks {
    /// `(plaintext, now)` -> ticket.
    pub seal: fn(&[u8], i64) -> Vec<u8>,
    /// ticket -> plaintext, if it is ours and authentic.
    pub open: fn(&[u8]) -> Option<Vec<u8>>,
}

/// How a client connection stores and retrieves tickets.
#[derive(Clone, Copy)]
pub struct SessionHooks {
    pub put: fn(&[u8], Session),
    pub take: fn(&[u8], i64) -> Option<Session>,
}

/// The contents of a ticket (what the server remembers about the session).
pub(crate) struct TicketData {
    pub valid_until: i64,
    /// The end of the whole chain of resumed sessions (hard limit, certificate expiry).
    pub limit: i64,
    pub suite: u16,
    pub psk: [u8; 32],
    pub binding: [u8; 32],
    pub alpn: Option<Vec<u8>>,
    /// The authenticated client certificate chain (empty without client certificates).
    pub chain: Vec<Vec<u8>>,
}

const VERSION: u8 = 1;

impl TicketData {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(128 + self.chain.iter().map(|c| c.len() + 3).sum::<usize>());
        o.push(VERSION);
        o.extend_from_slice(&self.valid_until.to_be_bytes());
        o.extend_from_slice(&self.limit.to_be_bytes());
        o.extend_from_slice(&self.suite.to_be_bytes());
        o.extend_from_slice(&self.psk);
        o.extend_from_slice(&self.binding);
        match &self.alpn {
            Some(a) => {
                o.push(a.len() as u8);
                o.extend_from_slice(a);
            }
            None => o.push(0),
        }
        o.extend_from_slice(&(self.chain.len() as u16).to_be_bytes());
        for c in &self.chain {
            o.extend_from_slice(&(c.len() as u32).to_be_bytes()[1..]);
            o.extend_from_slice(c);
        }
        o
    }

    pub fn decode(b: &[u8]) -> Option<TicketData> {
        let mut p = 0usize;
        let mut take = |n: usize| -> Option<&[u8]> {
            let s = b.get(p..p.checked_add(n)?)?;
            p += n;
            Some(s)
        };
        if take(1)? != [VERSION] {
            return None;
        }
        let valid_until = i64::from_be_bytes(take(8)?.try_into().ok()?);
        let limit = i64::from_be_bytes(take(8)?.try_into().ok()?);
        let suite = u16::from_be_bytes(take(2)?.try_into().ok()?);
        let psk: [u8; 32] = take(32)?.try_into().ok()?;
        let binding: [u8; 32] = take(32)?.try_into().ok()?;
        let al = take(1)?[0] as usize;
        let alpn = if al == 0 { None } else { Some(take(al)?.to_vec()) };
        let n = u16::from_be_bytes(take(2)?.try_into().ok()?) as usize;
        let mut chain = Vec::new();
        for _ in 0..n {
            let l = take(3)?;
            let len = (l[0] as usize) << 16 | (l[1] as usize) << 8 | l[2] as usize;
            chain.push(take(len)?.to_vec());
        }
        (p == b.len()).then_some(TicketData { valid_until, limit, suite, psk, binding, alpn, chain })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng(b: &mut [u8]) {
        use core::sync::atomic::{AtomicU64, Ordering};
        static S: AtomicU64 = AtomicU64::new(0x9e3779b97f4a7c15);
        for x in b {
            let mut v = S.load(Ordering::Relaxed);
            v ^= v << 13;
            v ^= v >> 7;
            v ^= v << 17;
            S.store(v, Ordering::Relaxed);
            *x = v as u8;
        }
    }

    #[test]
    fn tickets_seal_open_and_rotate() {
        let mut k = TicketKeys::new();
        let t1 = k.seal(b"first", 1000, rng);
        assert_eq!(k.open(&t1).as_deref(), Some(&b"first"[..]));
        // Same key within the period; a rotation keeps the previous key for one more period.
        let t2 = k.seal(b"second", 1000 + TICKET_LIFETIME as i64, rng);
        assert_ne!(t1[..8], t2[..8]);
        assert!(k.open(&t1).is_some() && k.open(&t2).is_some());
        let _t3 = k.seal(b"third", 1000 + 2 * TICKET_LIFETIME as i64, rng);
        assert!(k.open(&t1).is_none(), "two rotations later the first key is gone");
        // Tampering anywhere fails.
        let mut bad = t2.clone();
        for i in 0..bad.len() {
            bad[i] ^= 1;
            assert!(k.open(&bad).is_none(), "byte {i}");
            bad[i] ^= 1;
        }
        assert!(k.open(&t2[..t2.len() - 1]).is_none());
        assert!(TicketKeys::new().open(&t2).is_none());
    }

    #[test]
    fn ticket_data_roundtrip() {
        let d = TicketData { valid_until: 5, limit: 9, suite: 0x1303, psk: [7; 32], binding: [8; 32], alpn: Some(b"h2".to_vec()), chain: alloc::vec![alloc::vec![1, 2, 3], alloc::vec![4; 700]] };
        let e = d.encode();
        let b = TicketData::decode(&e).unwrap();
        assert_eq!((b.valid_until, b.limit, b.suite, b.psk, b.binding, b.alpn, b.chain), (5, 9, 0x1303, [7; 32], [8; 32], Some(b"h2".to_vec()), d.chain));
        assert!(TicketData::decode(&e[..e.len() - 1]).is_none());
        let mut extra = e.clone();
        extra.push(0);
        assert!(TicketData::decode(&extra).is_none());
    }

    #[test]
    fn cache_takes_once_and_expires() {
        let s = |t: i64| Session { ticket: alloc::vec![1], psk: [1; 32], suite: 0x1303, age_add: 0, received_at: t, lifetime: 100, server_chain: Vec::new(), alpn: None };
        let mut c = SessionCache::new();
        c.put(b"a", s(1000));
        assert!(c.take(b"a", 1099).is_some());
        assert!(c.take(b"a", 1099).is_none(), "used once");
        c.put(b"a", s(1000));
        assert!(c.take(b"a", 1100).is_none(), "expired");
        for i in 0..100u8 {
            c.put(&[i], s(0));
        }
        assert_eq!(c.len(), CACHE_CAP);
    }
}
