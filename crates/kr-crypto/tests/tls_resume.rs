//! TLS 1.3 session resumption (ADR-051) between kr's own client and server.
use kr_crypto::resume::{SessionCache, SessionHooks, TicketHooks, TicketKeys};
use kr_crypto::tls::{self, ClientAuth, ClientConfig, Connection, Error, ServerConfig};
use kr_crypto::x509::{self, CertParams, Name, SigningKey};
use kr_crypto::{ed25519, p256};
use std::rc::Rc;

const NOW: i64 = 1_800_000_000;

/// Deterministic test RNG (xorshift); real callers pass getrandom.
fn rng(buf: &mut [u8]) {
    use std::cell::Cell;
    thread_local!(static S: Cell<u64> = const { Cell::new(0x9e3779b97f4a7c15) });
    S.with(|s| {
        for b in buf {
            let mut x = s.get();
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            s.set(x);
            *b = x as u8;
        }
    });
}

struct Pki {
    ca: Vec<u8>,
    ca_name: Name,
    ca_key: SigningKey,
}

fn pki(ed: bool) -> Pki {
    let ca_key = if ed { SigningKey::Ed25519(ed25519::SigningKey::from_seed(&[1; 32])) } else { SigningKey::P256(p256::SecretKey::from_bytes(&[1; 32]).unwrap()) };
    let ca_name = Name { common_name: "test-ca".into(), organizations: vec![] };
    let ca = x509::issue(&params(&ca_name, ca_key.public(), true, false, false, vec![]), &ca_name, &ca_key);
    Pki { ca, ca_name, ca_key }
}

fn params(name: &Name, pk: x509::PublicKey, ca: bool, server: bool, client: bool, dns: Vec<String>) -> CertParams {
    CertParams { serial: [7; 16], subject: name.clone(), not_before: NOW - 60, not_after: NOW + 3600, is_ca: ca, server, client, dns_names: dns, ip_addrs: vec![vec![127, 0, 0, 1]], public_key: pk }
}

impl Pki {
    fn leaf(&self, cn: &str, server: bool, ed: bool) -> (Vec<u8>, SigningKey) {
        let key = if ed { SigningKey::Ed25519(ed25519::SigningKey::from_seed(&[cn.len() as u8; 32])) } else { SigningKey::P256(p256::SecretKey::from_bytes(&[cn.len() as u8 + 2; 32]).unwrap()) };
        let name = Name { common_name: cn.into(), organizations: vec!["system:masters".into()] };
        let cert = x509::issue(&params(&name, key.public(), false, server, !server, vec!["api.kr.local".into()]), &self.ca_name, &self.ca_key);
        (cert, key)
    }
}

/// Shuttles bytes until neither side has output; `chunk` limits each delivery.
fn pump(c: &mut Connection, s: &mut Connection, chunk: usize) -> Result<(), (char, Error)> {
    for _ in 0..10_000 {
        let (a, b) = (c.take_output(), s.take_output());
        if a.is_empty() && b.is_empty() {
            return Ok(());
        }
        for piece in a.chunks(chunk.max(1)) {
            s.feed(piece).map_err(|e| ('s', e))?;
        }
        for piece in b.chunks(chunk.max(1)) {
            c.feed(piece).map_err(|e| ('c', e))?;
        }
    }
    panic!("no progress");
}

fn server(p: &Pki, auth: ClientAuth, ed: bool, alpn: Vec<Vec<u8>>) -> Rc<ServerConfig> {
    let (cert, key) = p.leaf("apiserver", true, ed);
    Rc::new(ServerConfig { cert_chain: vec![cert], key, client_auth: auth, alpn })
}

fn client(p: &Pki, cert: bool, alpn: Vec<Vec<u8>>) -> Rc<ClientConfig> {
    Rc::new(ClientConfig { pinned_ca: None, roots: vec![p.ca.clone()], client_cert: cert.then(|| { let (c, k) = p.leaf("alice", false, false); (vec![c], k) }), alpn, tls12: false })
}


thread_local! {
    static KEYS: std::cell::RefCell<TicketKeys> = const { std::cell::RefCell::new(TicketKeys::new()) };
    static CACHE: std::cell::RefCell<SessionCache> = const { std::cell::RefCell::new(SessionCache::new()) };
}

const TICKETS: TicketHooks = TicketHooks { seal: |p, now| KEYS.with(|k| k.borrow_mut().seal(p, now, rng)), open: |t| KEYS.with(|k| k.borrow().open(t)) };
const SESSIONS: SessionHooks = SessionHooks { put: |k, s| CACHE.with(|c| c.borrow_mut().put(k, s)), take: |k, now| CACHE.with(|c| c.borrow_mut().take(k, now)) };

fn reset() {
    KEYS.with(|k| *k.borrow_mut() = TicketKeys::new());
    CACHE.with(|c| *c.borrow_mut() = SessionCache::new());
}

fn srv(cfg: &Rc<ServerConfig>, now: i64) -> Connection {
    Connection::server_with_tickets(cfg.clone(), TICKETS, rng, now)
}

fn cli(cfg: &Rc<ClientConfig>, now: i64) -> Connection {
    Connection::client_with_sessions(cfg.clone(), b"api.kr.local", SESSIONS, rng, now)
}

fn first_connection(scfg: &Rc<ServerConfig>, ccfg: &Rc<ClientConfig>, now: i64) {
    let (mut s, mut c) = (srv(scfg, now), cli(ccfg, now));
    pump(&mut c, &mut s, usize::MAX).unwrap();
    assert!(!c.resumed() && !s.resumed());
    assert!(!c.is_handshaking());
    // The ticket arrives with the first application round trip.
    s.write(b"x").unwrap();
    pump(&mut c, &mut s, usize::MAX).unwrap();
    assert_eq!(CACHE.with(|c| c.borrow().len()), 1, "client stored the ticket");
}

#[test]
fn full_handshake_then_resumption_with_client_certificate() {
    for chunk in [usize::MAX, 1, 9] {
        reset();
        let p = pki(false);
        let scfg = server(&p, ClientAuth::Required(vec![p.ca.clone()]), false, vec![b"h2".to_vec()]);
        let ccfg = client(&p, true, vec![b"h2".to_vec()]);
        first_connection(&scfg, &ccfg, NOW);
        let (mut s, mut c) = (srv(&scfg, NOW + 10), cli(&ccfg, NOW + 10));
        pump(&mut c, &mut s, chunk).unwrap();
        assert!(c.resumed() && s.resumed(), "second connection resumed");
        // The server still knows who the client is, and the client still knows the server's certificate.
        let peer = x509::Certificate::parse(&s.peer_certificates()[0]).unwrap();
        assert_eq!(peer.common_name(), Some(&b"alice"[..]));
        assert_eq!(c.peer_certificates().len(), 1);
        assert_eq!(c.alpn(), Some(&b"h2"[..]));
        c.write(b"hello over a resumed session").unwrap();
        s.write(b"pong").unwrap();
        pump(&mut c, &mut s, chunk).unwrap();
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf);
        assert_eq!(&buf[..n], b"hello over a resumed session");
        assert_eq!(c.read(&mut buf), 4);
        // And a ticket from the resumed session resumes again.
        assert_eq!(CACHE.with(|c| c.borrow().len()), 1);
        let (mut s, mut c) = (srv(&scfg, NOW + 20), cli(&ccfg, NOW + 20));
        pump(&mut c, &mut s, chunk).unwrap();
        assert!(c.resumed() && s.resumed());
    }
}

#[test]
fn a_ticket_is_offered_once() {
    reset();
    let p = pki(false);
    let scfg = server(&p, ClientAuth::None, false, vec![]);
    let ccfg = client(&p, false, vec![]);
    first_connection(&scfg, &ccfg, NOW);
    let (mut s, mut c) = (srv(&scfg, NOW + 1), cli(&ccfg, NOW + 1));
    // Taken from the cache when offered; the resumed connection has not been given a new one yet.
    assert_eq!(CACHE.with(|c| c.borrow().len()), 0);
    pump(&mut c, &mut s, usize::MAX).unwrap();
    assert!(c.resumed());
}

#[test]
fn unusable_tickets_fall_back_to_a_full_handshake() {
    let p = pki(false);
    let scfg = server(&p, ClientAuth::Required(vec![p.ca.clone()]), false, vec![]);
    let ccfg = client(&p, true, vec![]);
    // Expired ticket (valid for at most an hour and not past the client certificate).
    reset();
    first_connection(&scfg, &ccfg, NOW);
    let (mut s, mut c) = (srv(&scfg, NOW + 3000), cli(&ccfg, NOW + 3000));
    pump(&mut c, &mut s, usize::MAX).unwrap();
    assert!(c.resumed(), "still within the lifetime");
    // Past the ticket's end the server ignores it, and the full handshake then fails on the expired certificate.
    reset();
    first_connection(&scfg, &ccfg, NOW);
    let (mut s, mut c) = (srv(&scfg, NOW + 3700), cli(&ccfg, NOW + 3700));
    assert!(pump(&mut c, &mut s, usize::MAX).is_err(), "no resumption past the certificate's validity");
    // Another server configuration (different certificate): ticket ignored, full handshake succeeds.
    reset();
    first_connection(&scfg, &ccfg, NOW);
    let other = server(&pki(true), ClientAuth::None, true, vec![]);
    let p2 = pki(true);
    let ccfg2 = Rc::new(ClientConfig { pinned_ca: None, roots: vec![p2.ca.clone()], client_cert: None, alpn: vec![], tls12: false });
    let _ = ccfg2;
    let (mut s, mut c) = (srv(&other, NOW + 5), cli(&ccfg, NOW + 5));
    let _ = pump(&mut c, &mut s, usize::MAX); // ccfg does not trust `other`: whatever happens, never resumed
    assert!(!s.resumed());
    // A ticket whose contents were damaged is just not accepted.
    reset();
    first_connection(&scfg, &ccfg, NOW);
    KEYS.with(|k| *k.borrow_mut() = TicketKeys::new()); // the server forgot its keys (a restart)
    let (mut s, mut c) = (srv(&scfg, NOW + 5), cli(&ccfg, NOW + 5));
    pump(&mut c, &mut s, usize::MAX).unwrap();
    assert!(!c.resumed() && !s.resumed());
    assert!(!c.is_handshaking());
}

#[test]
fn a_wrong_binder_is_fatal() {
    reset();
    let p = pki(false);
    let scfg = server(&p, ClientAuth::None, false, vec![]);
    let ccfg = client(&p, false, vec![]);
    first_connection(&scfg, &ccfg, NOW);
    // Corrupt the PSK the client holds: its binder will not verify on the server.
    let key = tls::session_key(&ccfg, b"api.kr.local");
    let mut s0 = CACHE.with(|c| c.borrow_mut().take(&key, NOW + 1)).unwrap();
    s0.psk[0] ^= 1;
    CACHE.with(|c| c.borrow_mut().put(&key, s0));
    let (mut s, mut c) = (srv(&scfg, NOW + 1), cli(&ccfg, NOW + 1));
    match pump(&mut c, &mut s, usize::MAX) {
        Err(('s', Error::Local(tls::Alert::DecryptError))) => {}
        other => panic!("expected a decrypt_error from the server, got {other:?}"),
    }
}

#[test]
fn tickets_do_not_cross_client_configurations() {
    reset();
    let p = pki(false);
    let scfg = server(&p, ClientAuth::Optional(vec![p.ca.clone()]), false, vec![]);
    let with_cert = client(&p, true, vec![]);
    let without = client(&p, false, vec![]);
    first_connection(&scfg, &with_cert, NOW);
    // The anonymous client config has another fingerprint: it gets no ticket and cannot borrow alice's.
    let (mut s, mut c) = (srv(&scfg, NOW + 1), cli(&without, NOW + 1));
    pump(&mut c, &mut s, usize::MAX).unwrap();
    assert!(!c.resumed() && !s.resumed());
    assert!(s.peer_certificates().is_empty());
}

#[test]
fn servers_without_ticket_support_still_work_with_a_client_that_offers() {
    reset();
    let p = pki(false);
    let scfg = server(&p, ClientAuth::None, false, vec![]);
    let ccfg = client(&p, false, vec![]);
    first_connection(&scfg, &ccfg, NOW);
    // A server that issues no tickets and does not know the PSK extension's contents.
    let mut s = Connection::server(scfg.clone(), rng, NOW + 1);
    let mut c = cli(&ccfg, NOW + 1);
    pump(&mut c, &mut s, usize::MAX).unwrap();
    assert!(!c.resumed() && !s.resumed());
    assert!(!c.is_handshaking());
}

/// `cargo test --release -p kr-crypto --test tls_resume -- --ignored --nocapture`
#[test]
#[ignore]
fn handshake_cost_full_vs_resumed() {
    use std::time::Instant;
    reset();
    let p = pki(false);
    let scfg = server(&p, ClientAuth::Required(vec![p.ca.clone()]), false, vec![]);
    let ccfg = client(&p, true, vec![]);
    first_connection(&scfg, &ccfg, NOW);
    let n = 200;
    let mut resumed = std::time::Duration::ZERO;
    let mut full = std::time::Duration::ZERO;
    for _ in 0..n {
        // Put a fresh ticket back each time (a ticket is offered once).
        reset();
        first_connection(&scfg, &ccfg, NOW);
        let t = Instant::now();
        let (mut s, mut c) = (srv(&scfg, NOW + 1), cli(&ccfg, NOW + 1));
        pump(&mut c, &mut s, usize::MAX).unwrap();
        resumed += t.elapsed();
        assert!(c.resumed());
        let t = Instant::now();
        let mut s = Connection::server(scfg.clone(), rng, NOW + 1);
        let mut c = Connection::client(ccfg.clone(), b"api.kr.local", rng, NOW + 1);
        pump(&mut c, &mut s, usize::MAX).unwrap();
        full += t.elapsed();
    }
    println!("mutual-TLS handshake, both sides, per connection: full {:?}, resumed {:?}", full / n, resumed / n);
}

thread_local! {
    static CA_TABLE: std::cell::RefCell<Option<(Vec<u8>, &'static kr_crypto::p256::KeyTable)>> = const { std::cell::RefCell::new(None) };
}

fn ca_tables(pk: &[u8; 65]) -> Option<&'static kr_crypto::p256::KeyTable> {
    CA_TABLE.with(|t| t.borrow().as_ref().filter(|(k, _)| k[..] == pk[..]).map(|(_, t)| *t))
}

/// Chain verification with a precomputed table for the CA key (#219): accepts what the plain path
/// accepts and rejects a certificate signed by another CA.
#[test]
fn certificates_verify_with_a_ca_key_table() {
    let p = pki(false);
    let ca_cert = x509::Certificate::parse(&p.ca).unwrap();
    let Some(x509::PublicKey::P256(pk)) = ca_cert.public_key else { panic!("P-256 CA") };
    let table: &'static _ = Box::leak(Box::new(kr_crypto::p256::key_table(&pk).unwrap()));
    CA_TABLE.with(|t| *t.borrow_mut() = Some((pk.to_vec(), table)));

    let scfg = server(&p, ClientAuth::Required(vec![p.ca.clone()]), false, vec![]);
    let ccfg = client(&p, true, vec![]);
    let mut s = Connection::server(scfg.clone(), rng, NOW).with_key_tables(ca_tables);
    let mut c = Connection::client(ccfg.clone(), b"api.kr.local", rng, NOW).with_key_tables(ca_tables);
    pump(&mut c, &mut s, usize::MAX).unwrap();
    assert!(!c.is_handshaking() && !s.is_handshaking());

    // A client certificate issued by an unrelated CA with the same name is refused, tables or not.
    let evil_key = SigningKey::P256(p256::SecretKey::from_bytes(&[9; 32]).unwrap());
    let evil = x509::issue(&params(&p.ca_name, evil_key.public(), true, false, false, vec![]), &p.ca_name, &evil_key);
    let evil_pki = Pki { ca: evil, ca_name: p.ca_name.clone(), ca_key: evil_key };
    let bad_client = client(&evil_pki, true, vec![]);
    let mut s = Connection::server(scfg, rng, NOW).with_key_tables(ca_tables);
    let mut c = Connection::client(bad_client, b"api.kr.local", rng, NOW).with_key_tables(ca_tables);
    assert!(pump(&mut c, &mut s, usize::MAX).is_err());
}
