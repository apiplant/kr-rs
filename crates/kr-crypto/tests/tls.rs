//! In-memory TLS 1.3 handshakes between kr's own client and server.
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

#[test]
fn handshake_and_data_all_configs() {
    for ed in [false, true] {
        for chunk in [usize::MAX, 1, 7] {
            let p = pki(ed);
            let mut s = Connection::server(server(&p, ClientAuth::Required(vec![p.ca.clone()]), ed, vec![b"h2".to_vec(), b"http/1.1".to_vec()]), rng, NOW);
            let mut c = Connection::client(client(&p, true, vec![b"http/1.1".to_vec()]), b"api.kr.local", rng, NOW);
            pump(&mut c, &mut s, chunk).unwrap();
            assert!(!c.is_handshaking() && !s.is_handshaking());
            assert_eq!(c.alpn(), Some(&b"http/1.1"[..]));
            assert_eq!(s.alpn(), Some(&b"http/1.1"[..]));
            assert_eq!(c.cipher_suite(), tls::TLS_CHACHA20_POLY1305_SHA256);
            let peer = x509::Certificate::parse(&s.peer_certificates()[0]).unwrap();
            assert_eq!(peer.common_name(), Some(&b"alice"[..]));
            // data both ways, including more than one record
            let big: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
            c.write(&big).unwrap();
            s.write(b"pong").unwrap();
            pump(&mut c, &mut s, chunk).unwrap();
            let mut buf = vec![0u8; 50_000];
            let n = s.read(&mut buf);
            assert_eq!(&buf[..n], &big[..]);
            assert_eq!(c.read(&mut buf), 4);
            // key update in both directions, then more data
            c.key_update().unwrap();
            c.write(b"after update").unwrap();
            pump(&mut c, &mut s, chunk).unwrap();
            let n = s.read(&mut buf);
            assert_eq!(&buf[..n], b"after update");
            s.write(b"server after").unwrap();
            pump(&mut c, &mut s, chunk).unwrap();
            let n = c.read(&mut buf);
            assert_eq!(&buf[..n], b"server after");
            // clean close
            c.close();
            pump(&mut c, &mut s, chunk).unwrap();
            assert!(s.peer_closed());
        }
    }
}

#[test]
fn aes_suite_when_client_prefers_it() {
    // Our client offers ChaCha first; the server picks by its own preference, so force AES by
    // feeding a server that only sees AES offered: emulate with a raw ClientHello edit.
    let p = pki(false);
    let mut s = Connection::server(server(&p, ClientAuth::None, false, vec![]), rng, NOW);
    let mut c = Connection::client(client(&p, false, vec![]), b"api.kr.local", rng, NOW);
    let mut ch = c.take_output();
    // cipher_suites follow: 5 (record) + 4 (hs hdr) + 2 + 32 + 1 + 32 (session id)
    let off = 5 + 4 + 2 + 32 + 1 + 32;
    assert_eq!(&ch[off..off + 6], &[0, 4, 0x13, 0x03, 0x13, 0x01]);
    ch[off + 3] = 0x01; // offer AES twice
    // The edited ClientHello is now in the server transcript but not the client's: the
    // handshake must fail at Finished, proving transcript binding covers the suite list.
    s.feed(&ch).unwrap();
    assert_eq!(s.cipher_suite(), tls::TLS_AES_128_GCM_SHA256);
    let out = s.take_output();
    assert!(c.feed(&out).is_err());
}

#[test]
fn rejections() {
    let p = pki(false);
    let other = pki(true);
    // Unknown CA.
    let mut s = Connection::server(server(&other, ClientAuth::None, true, vec![]), rng, NOW);
    let mut c = Connection::client(client(&p, false, vec![]), b"api.kr.local", rng, NOW);
    assert_eq!(pump(&mut c, &mut s, usize::MAX), Err(('c', Error::Local(tls::Alert::UnknownCa))));
    // Wrong host.
    let mut s = Connection::server(server(&p, ClientAuth::None, false, vec![]), rng, NOW);
    let mut c = Connection::client(client(&p, false, vec![]), b"evil.example", rng, NOW);
    assert_eq!(pump(&mut c, &mut s, usize::MAX), Err(('c', Error::Local(tls::Alert::CertHostMismatch))));
    // Expired (client clock far in the future).
    let mut s = Connection::server(server(&p, ClientAuth::None, false, vec![]), rng, NOW);
    let mut c = Connection::client(client(&p, false, vec![]), b"api.kr.local", rng, NOW + 86400 * 365);
    assert_eq!(pump(&mut c, &mut s, usize::MAX), Err(('c', Error::Local(tls::Alert::CertificateExpired))));
    // Client certificate required but absent: server alerts after the client's flight.
    let mut s = Connection::server(server(&p, ClientAuth::Required(vec![p.ca.clone()]), false, vec![]), rng, NOW);
    let mut c = Connection::client(client(&p, false, vec![]), b"api.kr.local", rng, NOW);
    assert_eq!(pump(&mut c, &mut s, usize::MAX), Err(('s', Error::Local(tls::Alert::CertificateRequired))));
    // Optional client auth without a certificate is fine.
    let mut s = Connection::server(server(&p, ClientAuth::Optional(vec![p.ca.clone()]), false, vec![]), rng, NOW);
    let mut c = Connection::client(client(&p, false, vec![]), b"api.kr.local", rng, NOW);
    pump(&mut c, &mut s, usize::MAX).unwrap();
    assert!(s.peer_certificates().is_empty() && !s.is_handshaking());
    // A client cert from another CA is rejected by the server.
    let mut s = Connection::server(server(&p, ClientAuth::Required(vec![other.ca.clone()]), false, vec![]), rng, NOW);
    let mut c = Connection::client(client(&p, true, vec![]), b"api.kr.local", rng, NOW);
    assert_eq!(pump(&mut c, &mut s, usize::MAX), Err(('s', Error::Local(tls::Alert::UnknownCa))));
    // ALPN mismatch.
    let mut s = Connection::server(server(&p, ClientAuth::None, false, vec![b"h2".to_vec()]), rng, NOW);
    let mut c = Connection::client(client(&p, false, vec![b"http/1.1".to_vec()]), b"api.kr.local", rng, NOW);
    assert_eq!(pump(&mut c, &mut s, usize::MAX), Err(('s', Error::Local(tls::Alert::NoApplicationProtocol))));
}

#[test]
fn tampered_records_are_fatal() {
    let p = pki(false);
    let mut s = Connection::server(server(&p, ClientAuth::None, false, vec![]), rng, NOW);
    let mut c = Connection::client(client(&p, false, vec![]), b"api.kr.local", rng, NOW);
    pump(&mut c, &mut s, usize::MAX).unwrap();
    c.write(b"secret").unwrap();
    let mut rec = c.take_output();
    let last = rec.len() - 1;
    rec[last] ^= 1;
    assert_eq!(s.feed(&rec), Err(Error::Local(tls::Alert::BadRecordMac)));
    assert!(s.is_closed());
    // The alert we queued is a well-formed encrypted record.
    assert!(s.take_output().len() > 5);
    // Writing before the handshake completes is refused.
    let mut c2 = Connection::client(client(&p, false, vec![]), b"api.kr.local", rng, NOW);
    assert_eq!(c2.write(b"x"), Err(Error::NotReady));
    // Garbage instead of a ServerHello.
    assert!(c2.feed(&[22, 3, 3, 0, 4, 2, 0, 0, 0]).is_err());
}

#[test]
fn client_alert_after_server_hello_is_encrypted() {
    // The client rejects the server certificate; the server must decode that alert (not fail
    // with bad_record_mac), i.e. the client used its handshake keys.
    let p = pki(false);
    let other = pki(true);
    let mut s = Connection::server(server(&other, ClientAuth::None, true, vec![]), rng, NOW);
    let mut c = Connection::client(client(&p, false, vec![]), b"api.kr.local", rng, NOW);
    s.feed(&c.take_output()).unwrap();
    assert_eq!(c.feed(&s.take_output()), Err(Error::Local(tls::Alert::UnknownCa)));
    assert_eq!(s.feed(&c.take_output()), Err(Error::Peer(tls::Alert::UnknownCa as u8)));
}
