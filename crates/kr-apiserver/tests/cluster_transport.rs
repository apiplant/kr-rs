//! Raft transport over real loopback TLS: delivery between server certificates, rejection of
//! spoofed senders and of certificates outside system:kr-servers.

use kr_apiserver::cluster::transport::{self, Inbox, Peer};
use kr_crypto::tls::{ClientAuth, ClientConfig, ServerConfig};
use kr_crypto::x509::{self, CertParams, Name, SigningKey};
use kr_net::http1::server::{listen, local_addr};
use kr_raft::{Message, MsgBody};
use kr_rt::exec::{block_on, sleep, spawn};
use std::rc::Rc;

fn key(seed: u8) -> SigningKey {
    SigningKey::P256(kr_crypto::p256::SecretKey::from_bytes(&[seed; 32]).unwrap())
}

fn name(cn: &str, o: &[&str]) -> Name {
    Name { common_name: cn.into(), organizations: o.iter().map(|s| s.to_string()).collect() }
}

fn issue(subject: &Name, serial: u8, k: &SigningKey, ca: bool, issuer: (&Name, &SigningKey)) -> Vec<u8> {
    let p = CertParams {
        serial: [serial; 16],
        subject: subject.clone(),
        not_before: 1_000_000_000,
        not_after: 4_000_000_000,
        is_ca: ca,
        server: !ca,
        client: !ca,
        dns_names: vec![],
        ip_addrs: if ca { vec![] } else { vec![vec![127, 0, 0, 1]] },
        public_key: k.public(),
    };
    x509::issue(&p, issuer.0, issuer.1)
}

fn now() -> i64 {
    2_000_000_000
}

struct Who {
    srv: Rc<ServerConfig>,
    cli: Rc<ClientConfig>,
}

fn identity(ca: &(Name, SigningKey, Vec<u8>), cn: &str, org: &str, seed: u8) -> Who {
    let k = key(seed);
    let c = issue(&name(cn, &[org]), seed, &k, false, (&ca.0, &ca.1));
    let k2 = key(seed);
    let srv = Rc::new(ServerConfig { cert_chain: vec![c.clone()], key: k, client_auth: ClientAuth::Required(vec![ca.2.clone()]), alpn: vec![] });
    let cli = Rc::new(ClientConfig { roots: vec![ca.2.clone()], pinned_ca: None, client_cert: Some((vec![c], k2)), alpn: vec![], tls12: false });
    Who { srv, cli }
}

fn msg(from: u64, to: u64, term: u64) -> Message {
    Message { from, to, term, body: MsgBody::AppendResp { success: true, index: term } }
}

#[test]
fn transport_delivers_and_authenticates() {
    let _ = now;
    block_on(async {
        let ca_name = name("kr-ca", &[]);
        let ca_key = key(1);
        let ca_der = issue(&ca_name, 1, &ca_key, true, (&ca_name, &ca_key));
        let ca = (ca_name, ca_key, ca_der);
        let s1 = identity(&ca, &transport::cert_cn(1), transport::ORG, 11);
        let s2 = identity(&ca, &transport::cert_cn(2), transport::ORG, 12);
        // Same CA, but an agent identity: must not be able to talk Raft.
        let agent = identity(&ca, &transport::cert_cn(1), "system:nodes", 13);

        let l = listen([127, 0, 0, 1], 0, 16).unwrap();
        let port = local_addr(&l).unwrap().1;
        let inbox: Rc<Inbox> = Rc::default();
        spawn(transport::serve(l, s2.srv.clone(), 2, inbox.clone()));

        // 1 -> 2: delivered.
        let p = Peer::new(([127, 0, 0, 1], port), s1.cli.clone());
        p.send(&msg(1, 2, 7));
        for _ in 0..200 {
            if !inbox.msgs.borrow().is_empty() {
                break;
            }
            sleep(10).await;
        }
        assert_eq!(inbox.msgs.borrow_mut().pop_front(), Some(msg(1, 2, 7)));

        // A spoofed sender id (claims to be 3) is dropped and the connection closed.
        p.send(&msg(3, 2, 8));
        p.send(&msg(1, 2, 9));
        sleep(300).await;
        assert!(inbox.msgs.borrow().iter().all(|m| m.from == 1 && m.term != 8), "spoofed message accepted");

        // A certificate outside system:kr-servers delivers nothing.
        let bad = Peer::new(([127, 0, 0, 1], port), agent.cli.clone());
        bad.send(&msg(1, 2, 10));
        sleep(300).await;
        assert!(inbox.msgs.borrow().iter().all(|m| m.term != 10), "non-server certificate accepted");

        // The good link recovers after its connection was closed by the spoof. A write into a
        // just-closed socket can still "succeed", so (like Raft heartbeats) keep resending.
        for _ in 0..100 {
            if inbox.msgs.borrow().iter().any(|m| m.term == 11) {
                break;
            }
            p.send(&msg(1, 2, 11));
            sleep(50).await;
        }
        assert!(inbox.msgs.borrow().iter().any(|m| m.term == 11), "link did not reconnect");
    });
}
