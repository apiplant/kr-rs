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
    /// Shared mode: every key is derived from this secret and the hour (`created` = the epoch),
    /// so servers holding the same secret open each other's tickets and a restart loses none.
    secret: Option<[u8; 32]>,
    derived: Vec<Key>,
}

impl Default for TicketKeys {
    fn default() -> Self {
        Self::new()
    }
}

impl TicketKeys {
    pub const fn new() -> TicketKeys {
        TicketKeys { cur: None, prev: None, secret: None, derived: Vec::new() }
    }

    /// Switches to keys derived from `secret` (the same on every server of a cluster): the key for
    /// hour `h` is `HKDF(secret, "kr tls ticket key v1" || h)`. A ticket opens in the hour it was
    /// sealed, the one before and the one after (clock skew between servers).
    pub fn set_secret(&mut self, secret: [u8; 32]) {
        self.secret = Some(secret);
        self.derived.clear();
        self.cur = None;
        self.prev = None;
    }

    fn epoch(now: i64) -> i64 {
        now.div_euclid(TICKET_LIFETIME as i64)
    }

    /// The derived key of `epoch`, cached.
    fn derive(&mut self, epoch: i64) -> Option<&Key> {
        let secret = self.secret?;
        if !self.derived.iter().any(|k| k.created == epoch) {
            let mut prk = [0u8; 32];
            crate::hmac::hkdf_extract::<crate::sha2::Sha256>(b"kr tls ticket", &secret, &mut prk);
            let mut out = [0u8; 40];
            crate::hmac::hkdf_expand::<crate::sha2::Sha256>(&prk, &[b"kr tls ticket key v1", &epoch.to_be_bytes()], &mut out);
            wipe(&mut prk);
            let mut k = Key { id: [0; KEY_ID], key: [0; 32], created: epoch };
            k.key.copy_from_slice(&out[..32]);
            k.id.copy_from_slice(&out[32..]);
            wipe(&mut out);
            if self.derived.len() >= 4 {
                self.derived.remove(0);
            }
            self.derived.push(k);
        }
        self.derived.iter().find(|k| k.created == epoch)
    }

    /// Seals `plaintext` into a ticket: `key_id | nonce | ciphertext | tag`.
    pub fn seal(&mut self, plaintext: &[u8], now: i64, rng: Rng) -> Vec<u8> {
        if self.secret.is_some() {
            let (id, key) = self.derive(Self::epoch(now)).map(|k| (k.id, k.key)).expect("secret set");
            return Self::seal_with(&id, &key, plaintext, rng);
        }
        if self.cur.as_ref().is_none_or(|k| now - k.created >= TICKET_LIFETIME as i64 || now < k.created) {
            let mut k = Key { id: [0; KEY_ID], key: [0; 32], created: now };
            rng(&mut k.id);
            rng(&mut k.key);
            self.prev = self.cur.replace(k);
        }
        let cur = self.cur.as_ref().expect("just set");
        Self::seal_with(&cur.id, &cur.key, plaintext, rng)
    }

    fn seal_with(id: &[u8; KEY_ID], key: &[u8; 32], plaintext: &[u8], rng: Rng) -> Vec<u8> {
        let mut nonce = [0u8; 12];
        rng(&mut nonce);
        let mut out = Vec::with_capacity(KEY_ID + 12 + plaintext.len() + 16);
        out.extend_from_slice(id);
        out.extend_from_slice(&nonce);
        let start = out.len();
        out.extend_from_slice(plaintext);
        let tag = chacha::seal(key, &nonce, id, &mut out[start..]);
        out.extend_from_slice(&tag);
        out
    }

    /// The plaintext of a ticket sealed under a key this process (or, in shared mode, any server
    /// with the same secret) can derive or still holds. `now` selects the shared-mode hours.
    pub fn open(&mut self, ticket: &[u8], now: i64) -> Option<Vec<u8>> {
        if ticket.len() < KEY_ID + 12 + 16 {
            return None;
        }
        let (id, rest) = ticket.split_at(KEY_ID);
        let key: (Vec<u8>, [u8; 32]) = if self.secret.is_some() {
            let e = Self::epoch(now);
            let mut found = None;
            for epoch in [e, e - 1, e + 1] {
                if let Some(k) = self.derive(epoch) {
                    if k.id == id {
                        found = Some((k.id.to_vec(), k.key));
                        break;
                    }
                }
            }
            found?
        } else {
            let k = [self.cur.as_ref(), self.prev.as_ref()].into_iter().flatten().find(|k| k.id == id)?;
            (k.id.to_vec(), k.key)
        };
        let (nonce, rest) = rest.split_at(12);
        let (ct, tag) = rest.split_at(rest.len() - 16);
        let mut data = ct.to_vec();
        chacha::open(&key.1, nonce.try_into().ok()?, &key.0, &mut data, tag).ok()?;
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
    /// `(ticket, now)` -> plaintext, if it is ours and authentic.
    pub open: fn(&[u8], i64) -> Option<Vec<u8>>,
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
        assert_eq!(k.open(&t1, 1000).as_deref(), Some(&b"first"[..]));
        // Same key within the period; a rotation keeps the previous key for one more period.
        let t2 = k.seal(b"second", 1000 + TICKET_LIFETIME as i64, rng);
        assert_ne!(t1[..8], t2[..8]);
        assert!(k.open(&t1, 5000).is_some() && k.open(&t2, 5000).is_some());
        let _t3 = k.seal(b"third", 1000 + 2 * TICKET_LIFETIME as i64, rng);
        assert!(k.open(&t1, 9000).is_none(), "two rotations later the first key is gone");
        // Tampering anywhere fails.
        let mut bad = t2.clone();
        for i in 0..bad.len() {
            bad[i] ^= 1;
            assert!(k.open(&bad, 5000).is_none(), "byte {i}");
            bad[i] ^= 1;
        }
        assert!(k.open(&t2[..t2.len() - 1], 5000).is_none());
        assert!(TicketKeys::new().open(&t2, 5000).is_none());
    }

    #[test]
    fn shared_secret_keys_open_across_instances_and_restarts() {
        let h = TICKET_LIFETIME as i64;
        let (mut a, mut b) = (TicketKeys::new(), TicketKeys::new());
        a.set_secret([7; 32]);
        b.set_secret([7; 32]);
        let t = a.seal(b"shared", 10 * h + 5, rng);
        // Another server with the same secret opens it (this hour, the next, the one after that
        // is outside the skew window), a fresh instance too (a restart), a different secret never.
        assert_eq!(b.open(&t, 10 * h + 100).as_deref(), Some(&b"shared"[..]));
        assert!(b.open(&t, 11 * h + 1).is_some());
        assert!(TicketKeys::new().open(&t, 10 * h).is_none(), "random-key mode cannot");
        let mut restarted = TicketKeys::new();
        restarted.set_secret([7; 32]);
        assert!(restarted.open(&t, 10 * h + 50).is_some());
        assert!(restarted.open(&t, 12 * h + 1).is_none(), "two hours later it is out of the window");
        let mut other = TicketKeys::new();
        other.set_secret([8; 32]);
        assert!(other.open(&t, 10 * h).is_none());
        // Hours use different keys.
        let t2 = a.seal(b"later", 11 * h + 5, rng);
        assert_ne!(t[..8], t2[..8]);
        assert!(restarted.open(&t2, 11 * h + 5).is_some());
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
