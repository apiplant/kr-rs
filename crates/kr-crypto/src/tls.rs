//! TLS 1.3 (RFC 8446), client and server, as a sans-I/O state machine.
//!
//! Feed received bytes with [`Connection::feed`], send what [`Connection::take_output`] returns,
//! read decrypted application data with [`Connection::read`] and write it with
//! [`Connection::write`]. Socket glue lives in `kr-net`.
//!
//! Supported: TLS_CHACHA20_POLY1305_SHA256 (preferred) and TLS_AES_128_GCM_SHA256; X25519 and
//! secp256r1 key exchange; ecdsa_secp256r1_sha256 and ed25519 signatures; mutual TLS; ALPN;
//! KeyUpdate; middlebox-compatibility ChangeCipherSpec. Not supported: TLS 1.2, PSK/resumption,
//! 0-RTT, HelloRetryRequest as a server (a client must offer a usable key share), RSA certs.

use crate::aes::AesGcm;
use crate::hmac::{hkdf_expand, hkdf_extract, Hmac};
use crate::sha2::Sha256;
use crate::x509::{self, PublicKey, SigAlg, SigningKey, Usage, VerifyError};
use crate::{chacha, ct_eq, p256, x25519};
use alloc::rc::Rc;
use alloc::vec::Vec;

// ---- protocol constants ----

const CT_CCS: u8 = 20;
const CT_ALERT: u8 = 21;
const CT_HANDSHAKE: u8 = 22;
const CT_APPDATA: u8 = 23;

const HT_CLIENT_HELLO: u8 = 1;
const HT_SERVER_HELLO: u8 = 2;
const HT_NEW_SESSION_TICKET: u8 = 4;
const HT_ENCRYPTED_EXTENSIONS: u8 = 8;
const HT_CERTIFICATE: u8 = 11;
const HT_CERTIFICATE_REQUEST: u8 = 13;
const HT_CERTIFICATE_VERIFY: u8 = 15;
const HT_FINISHED: u8 = 20;
const HT_KEY_UPDATE: u8 = 24;

const EXT_SERVER_NAME: u16 = 0;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_ALPN: u16 = 16;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_KEY_SHARE: u16 = 51;

const TLS13: u16 = 0x0304;
pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
const GROUP_X25519: u16 = 0x001d;
const GROUP_P256: u16 = 0x0017;
const SIG_ECDSA_P256_SHA256: u16 = 0x0403;
const SIG_ED25519: u16 = 0x0807;
const SIG_ECDSA_P384_SHA384: u16 = 0x0503;
const SIG_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
const SIG_RSA_PSS_RSAE_SHA384: u16 = 0x0805;
const SIG_RSA_PSS_RSAE_SHA512: u16 = 0x0806;
/// PKCS#1 v1.5 schemes are offered only for certificate signatures (never CertificateVerify).
const SIG_RSA_PKCS1_SHA256: u16 = 0x0401;
const SIG_RSA_PKCS1_SHA384: u16 = 0x0501;
const SIG_RSA_PKCS1_SHA512: u16 = 0x0601;

/// SHA-256("HelloRetryRequest"): the ServerHello.random of a HelloRetryRequest.
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09,
    0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

const MAX_PLAINTEXT: usize = 1 << 14;
const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 256;
/// Largest handshake message we accept (certificate chains are the big ones).
const MAX_HANDSHAKE: usize = 64 * 1024;

/// TLS alert descriptions used here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Alert {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    RecordOverflow = 22,
    HandshakeFailure = 40,
    BadCertificate = 42,
    CertificateExpired = 45,
    IllegalParameter = 47,
    UnknownCa = 48,
    DecodeError = 50,
    DecryptError = 51,
    ProtocolVersion = 70,
    InternalError = 80,
    MissingExtension = 109,
    CertificateRequired = 116,
    NoApplicationProtocol = 120,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// We detected a problem and sent this fatal alert.
    Local(Alert),
    /// The peer sent this fatal alert.
    Peer(u8),
    /// The connection is closed (close_notify sent or received).
    Closed,
    /// Application data written before the handshake finished.
    NotReady,
}

type Result<T> = core::result::Result<T, Error>;

fn fail<T>(a: Alert) -> Result<T> {
    Err(Error::Local(a))
}

// ---- wire codec ----

struct Rd<'a> {
    b: &'a [u8],
}

impl<'a> Rd<'a> {
    fn new(b: &'a [u8]) -> Self {
        Rd { b }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.b.len() < n {
            return fail(Alert::DecodeError);
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Ok(h)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Result<usize> {
        let b = self.take(3)?;
        Ok((b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize)
    }
    fn vec8(&mut self) -> Result<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    fn vec16(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    fn vec24(&mut self) -> Result<&'a [u8]> {
        let n = self.u24()?;
        self.take(n)
    }
    fn done(&self) -> Result<()> {
        if self.b.is_empty() {
            Ok(())
        } else {
            fail(Alert::DecodeError)
        }
    }
}

fn put_u16(o: &mut Vec<u8>, v: u16) {
    o.extend_from_slice(&v.to_be_bytes());
}

/// Appends a length-prefixed block whose body is written by `f` (`width` = 1, 2 or 3 bytes).
fn put_vec(o: &mut Vec<u8>, width: usize, f: impl FnOnce(&mut Vec<u8>)) {
    let start = o.len();
    o.extend_from_slice(&[0, 0, 0][..width]);
    f(o);
    let len = o.len() - start - width;
    let be = (len as u32).to_be_bytes();
    o[start..start + width].copy_from_slice(&be[4 - width..]);
}

fn put_ext(o: &mut Vec<u8>, ty: u16, f: impl FnOnce(&mut Vec<u8>)) {
    put_u16(o, ty);
    put_vec(o, 2, f);
}

/// Handshake message framing: type, u24 length, body.
fn handshake_msg(ty: u8, f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut m = alloc::vec![ty];
    put_vec(&mut m, 3, f);
    m
}

/// Parses an extensions block into (type, body) pairs, rejecting duplicates.
fn extensions(block: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut r = Rd::new(block);
    let mut out: Vec<(u16, &[u8])> = Vec::new();
    while !r.b.is_empty() {
        let ty = r.u16()?;
        let body = r.vec16()?;
        if out.iter().any(|(t, _)| *t == ty) {
            return fail(Alert::IllegalParameter);
        }
        out.push((ty, body));
    }
    Ok(out)
}

fn find_ext<'a>(exts: &[(u16, &'a [u8])], ty: u16) -> Option<&'a [u8]> {
    exts.iter().find(|(t, _)| *t == ty).map(|(_, b)| *b)
}

// ---- key schedule (SHA-256 only: both supported suites use it) ----

type Secret = [u8; 32];

fn expand_label(secret: &[u8], label: &[u8], ctx: &[u8], out: &mut [u8]) {
    let len = (out.len() as u16).to_be_bytes();
    let llen = [(6 + label.len()) as u8];
    let clen = [ctx.len() as u8];
    hkdf_expand::<Sha256>(secret, &[&len, &llen, b"tls13 ", label, &clen, ctx], out);
}

fn derive_secret(secret: &[u8], label: &[u8], transcript_hash: &[u8; 32]) -> Secret {
    let mut out = [0u8; 32];
    expand_label(secret, label, transcript_hash, &mut out);
    out
}

fn extract(salt: &[u8], ikm: &[u8]) -> Secret {
    let mut out = [0u8; 32];
    hkdf_extract::<Sha256>(salt, ikm, &mut out);
    out
}

fn empty_hash() -> [u8; 32] {
    crate::sha2::sha256(b"")
}

fn finished_mac(base: &Secret, transcript_hash: &[u8; 32]) -> [u8; 32] {
    let mut key = [0u8; 32];
    expand_label(base, b"finished", b"", &mut key);
    let mut out = [0u8; 32];
    let mut m = Hmac::<Sha256>::new(&key);
    m.update(transcript_hash);
    m.finish_into(&mut out);
    crate::wipe(&mut key);
    out
}

// ---- record protection ----

enum Aead {
    ChaCha([u8; 32]),
    Aes(AesGcm),
}

struct RecordKeys {
    aead: Aead,
    iv: [u8; 12],
    seq: u64,
    secret: Secret,
    suite: u16,
}

impl RecordKeys {
    fn new(suite: u16, secret: Secret) -> RecordKeys {
        let mut iv = [0u8; 12];
        expand_label(&secret, b"iv", b"", &mut iv);
        let aead = if suite == TLS_CHACHA20_POLY1305_SHA256 {
            let mut k = [0u8; 32];
            expand_label(&secret, b"key", b"", &mut k);
            Aead::ChaCha(k)
        } else {
            let mut k = [0u8; 16];
            expand_label(&secret, b"key", b"", &mut k);
            let a = Aead::Aes(AesGcm::new(&k));
            crate::wipe(&mut k);
            a
        };
        RecordKeys { aead, iv, seq: 0, secret, suite }
    }

    /// Keys for the next generation (KeyUpdate).
    fn updated(&self) -> RecordKeys {
        let mut next = [0u8; 32];
        expand_label(&self.secret, b"traffic upd", b"", &mut next);
        RecordKeys::new(self.suite, next)
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = self.iv;
        for (i, b) in self.seq.to_be_bytes().iter().enumerate() {
            n[4 + i] ^= b;
        }
        n
    }

    /// Encrypts one record (`content` + inner type) and appends it to `out`.
    fn seal(&mut self, ty: u8, content: &[u8], out: &mut Vec<u8>) {
        let mut body = Vec::with_capacity(content.len() + 1 + 16);
        body.extend_from_slice(content);
        body.push(ty);
        let len = body.len() + 16;
        let hdr = [CT_APPDATA, 0x03, 0x03, (len >> 8) as u8, len as u8];
        let nonce = self.nonce();
        let tag = match &self.aead {
            Aead::ChaCha(k) => chacha::seal(k, &nonce, &hdr, &mut body),
            Aead::Aes(g) => g.seal(&nonce, &hdr, &mut body),
        };
        self.seq += 1;
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&body);
        out.extend_from_slice(&tag);
    }

    /// Decrypts a record body in place; returns (inner type, content length).
    fn open(&mut self, hdr: &[u8; 5], body: &mut [u8]) -> Result<(u8, usize)> {
        if body.len() < 17 {
            return fail(Alert::BadRecordMac);
        }
        let (ct, tag) = body.split_at_mut(body.len() - 16);
        let nonce = self.nonce();
        let ok = match &self.aead {
            Aead::ChaCha(k) => chacha::open(k, &nonce, hdr, ct, tag),
            Aead::Aes(g) => g.open(&nonce, hdr, ct, tag),
        };
        if ok.is_err() {
            return fail(Alert::BadRecordMac);
        }
        self.seq += 1;
        // Strip zero padding; the last non-zero byte is the real content type.
        let mut n = ct.len();
        while n > 0 && ct[n - 1] == 0 {
            n -= 1;
        }
        if n == 0 {
            return fail(Alert::UnexpectedMessage);
        }
        if n - 1 > MAX_PLAINTEXT {
            return fail(Alert::RecordOverflow);
        }
        Ok((ct[n - 1], n - 1))
    }
}

impl Drop for RecordKeys {
    fn drop(&mut self) {
        crate::wipe(&mut self.secret);
        if let Aead::ChaCha(k) = &mut self.aead {
            crate::wipe(k);
        }
    }
}

// ---- configuration ----

pub enum ClientAuth {
    None,
    /// Request a client certificate; verify it against these roots if one is sent.
    Optional(Vec<Vec<u8>>),
    /// Require a client certificate chaining to these roots.
    Required(Vec<Vec<u8>>),
}

pub struct ServerConfig {
    /// Leaf first, DER.
    pub cert_chain: Vec<Vec<u8>>,
    pub key: SigningKey,
    pub client_auth: ClientAuth,
    /// Protocols in server preference order; empty disables ALPN.
    pub alpn: Vec<Vec<u8>>,
}

pub struct ClientConfig {
    /// Trust anchors (DER).
    pub roots: Vec<Vec<u8>>,
    /// Certificate chain and key presented if the server asks.
    pub client_cert: Option<(Vec<Vec<u8>>, SigningKey)>,
    pub alpn: Vec<Vec<u8>>,
}

/// Randomness source (getrandom in kr). Must fill the buffer with CSPRNG output.
pub type Rng = fn(&mut [u8]);

// ---- connection ----

enum KeyShare {
    X25519([u8; 32]),
    P256(p256::SecretKey),
}

impl KeyShare {
    fn public(&self) -> Vec<u8> {
        match self {
            KeyShare::X25519(s) => x25519::public_key(s).to_vec(),
            KeyShare::P256(k) => k.public_key().to_vec(),
        }
    }
    fn shared(&self, peer: &[u8]) -> Result<Vec<u8>> {
        match self {
            KeyShare::X25519(s) => {
                let p: [u8; 32] = peer.try_into().or(fail(Alert::IllegalParameter))?;
                x25519::shared(s, &p).map(|v| v.to_vec()).or(fail(Alert::IllegalParameter))
            }
            KeyShare::P256(k) => k.ecdh(peer).map(|v| v.to_vec()).or(fail(Alert::IllegalParameter)),
        }
    }
}

impl Drop for KeyShare {
    fn drop(&mut self) {
        if let KeyShare::X25519(s) = self {
            crate::wipe(s);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    // server
    SrvWaitClientHello,
    SrvWaitCert,
    SrvWaitCertVerify,
    SrvWaitFinished,
    // client
    CliWaitServerHello,
    CliWaitEncryptedExtensions,
    CliWaitCertOrRequest,
    CliWaitCert,
    CliWaitCertVerify,
    CliWaitFinished,
    // both
    Established,
    Closed,
}

enum Role {
    Server(Rc<ServerConfig>),
    Client { cfg: Rc<ClientConfig>, server_name: Vec<u8>, share: Option<KeyShare>, offered_p256: bool },
}

pub struct Connection {
    role: Role,
    state: State,
    rng: Rng,
    now: i64,
    transcript: Sha256,
    suite: u16,
    hs_secret: Secret,
    master: Secret,
    /// Handshake traffic secrets, kept to compute Finished.
    c_hs: Secret,
    s_hs: Secret,
    read_keys: Option<RecordKeys>,
    write_keys: Option<RecordKeys>,
    /// Application secrets, installed after the handshake (one side lags the other).
    pending_read: Option<RecordKeys>,
    incoming: Vec<u8>,
    hs_buf: Vec<u8>,
    out: Vec<u8>,
    plain: Vec<u8>,
    plain_pos: usize,
    alpn: Option<Vec<u8>>,
    peer_certs: Vec<Vec<u8>>,
    peer_key: Option<PublicKey>,
    cert_requested: bool,
    session_id: Vec<u8>,
    ccs_allowed: bool,
    peer_closed: bool,
    /// Bumped whenever the read keys change.
    read_epoch: u32,
}

impl Connection {
    fn base(role: Role, state: State, rng: Rng, now: i64) -> Connection {
        Connection {
            role,
            state,
            rng,
            now,
            transcript: Sha256::new(),
            suite: 0,
            hs_secret: [0; 32],
            master: [0; 32],
            c_hs: [0; 32],
            s_hs: [0; 32],
            read_keys: None,
            write_keys: None,
            pending_read: None,
            incoming: Vec::new(),
            hs_buf: Vec::new(),
            out: Vec::new(),
            plain: Vec::new(),
            plain_pos: 0,
            alpn: None,
            peer_certs: Vec::new(),
            peer_key: None,
            cert_requested: false,
            session_id: Vec::new(),
            ccs_allowed: true,
            peer_closed: false,
            read_epoch: 0,
        }
    }

    /// A server connection; `now` (Unix seconds) is used to validate client certificates.
    pub fn server(cfg: Rc<ServerConfig>, rng: Rng, now: i64) -> Connection {
        Connection::base(Role::Server(cfg), State::SrvWaitClientHello, rng, now)
    }

    /// A client connection to `server_name` (DNS name or IP literal, used for SNI and checks).
    pub fn client(cfg: Rc<ClientConfig>, server_name: &[u8], rng: Rng, now: i64) -> Connection {
        let mut c = Connection::base(
            Role::Client { cfg, server_name: server_name.to_vec(), share: None, offered_p256: false },
            State::CliWaitServerHello,
            rng,
            now,
        );
        c.send_client_hello(false);
        c
    }

    pub fn is_handshaking(&self) -> bool {
        !matches!(self.state, State::Established | State::Closed)
    }

    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    /// The negotiated ALPN protocol, if any.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    /// The peer's verified certificate chain (leaf first); empty if none was presented.
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.peer_certs
    }

    pub fn cipher_suite(&self) -> u16 {
        self.suite
    }

    /// Bytes to send to the peer (drains the buffer).
    pub fn take_output(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.out)
    }

    pub fn has_output(&self) -> bool {
        !self.out.is_empty()
    }

    /// Reads decrypted application data. Ok(0) means the peer closed cleanly (or no data yet;
    /// check `peer_closed`).
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let avail = &self.plain[self.plain_pos..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        self.plain_pos += n;
        if self.plain_pos == self.plain.len() {
            self.plain.clear();
            self.plain_pos = 0;
        }
        n
    }

    pub fn plaintext_available(&self) -> usize {
        self.plain.len() - self.plain_pos
    }

    pub fn peer_closed(&self) -> bool {
        self.peer_closed
    }

    /// Encrypts application data into the output buffer.
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        match self.state {
            State::Established => {}
            State::Closed => return Err(Error::Closed),
            _ => return Err(Error::NotReady),
        }
        let keys = self.write_keys.as_mut().ok_or(Error::NotReady)?;
        for chunk in data.chunks(MAX_PLAINTEXT) {
            keys.seal(CT_APPDATA, chunk, &mut self.out);
        }
        Ok(())
    }

    /// Sends close_notify; further writes fail.
    pub fn close(&mut self) {
        if self.state != State::Closed {
            self.send_alert(Alert::CloseNotify);
            self.state = State::Closed;
        }
    }

    /// Initiates a KeyUpdate of our sending keys (asking the peer to update too).
    pub fn key_update(&mut self) -> Result<()> {
        if self.state != State::Established {
            return Err(Error::NotReady);
        }
        let msg = handshake_msg(HT_KEY_UPDATE, |m| m.push(1));
        self.send_handshake_record(&msg);
        let next = self.write_keys.as_ref().unwrap().updated();
        self.write_keys = Some(next);
        Ok(())
    }

    /// Processes received bytes. On a fatal error the alert is queued in the output (send it)
    /// and the connection is closed.
    pub fn feed(&mut self, data: &[u8]) -> Result<()> {
        if self.state == State::Closed {
            return Err(Error::Closed);
        }
        self.incoming.extend_from_slice(data);
        match self.process_records() {
            Ok(()) => Ok(()),
            Err(Error::Local(a)) => {
                self.send_alert(a);
                self.state = State::Closed;
                Err(Error::Local(a))
            }
            Err(e) => {
                self.state = State::Closed;
                Err(e)
            }
        }
    }

    fn send_alert(&mut self, a: Alert) {
        let level = if a == Alert::CloseNotify { 1 } else { 2 };
        let body = [level, a as u8];
        match self.write_keys.as_mut() {
            Some(k) => k.seal(CT_ALERT, &body, &mut self.out),
            None => {
                self.out.extend_from_slice(&[CT_ALERT, 3, 3, 0, 2]);
                self.out.extend_from_slice(&body);
            }
        }
    }

    fn process_records(&mut self) -> Result<()> {
        let mut pos = 0;
        let result = loop {
            if self.state == State::Closed {
                break Ok(());
            }
            let rest = &self.incoming[pos..];
            if rest.len() < 5 {
                break Ok(());
            }
            let hdr: [u8; 5] = rest[..5].try_into().unwrap();
            let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
            if len > MAX_CIPHERTEXT {
                break fail(Alert::RecordOverflow);
            }
            if hdr[1] != 3 {
                break fail(Alert::ProtocolVersion);
            }
            if rest.len() < 5 + len {
                break Ok(());
            }
            let mut body = rest[5..5 + len].to_vec();
            pos += 5 + len;
            if let Err(e) = self.record(&hdr, &mut body) {
                break Err(e);
            }
        };
        self.incoming.drain(..pos);
        result
    }

    fn record(&mut self, hdr: &[u8; 5], body: &mut [u8]) -> Result<()> {
        let ty = hdr[0];
        if ty == CT_CCS {
            // Middlebox compatibility: a single 0x01 is ignored during the handshake only.
            if self.ccs_allowed && self.is_handshaking() && body == [1] {
                return Ok(());
            }
            return fail(Alert::UnexpectedMessage);
        }
        let (inner, content): (u8, &[u8]) = match self.read_keys.as_mut() {
            None => {
                if body.len() > MAX_PLAINTEXT {
                    return fail(Alert::RecordOverflow);
                }
                if ty != CT_HANDSHAKE && ty != CT_ALERT {
                    return fail(Alert::UnexpectedMessage);
                }
                (ty, body)
            }
            Some(k) => {
                if ty != CT_APPDATA {
                    // Plaintext alerts are possible if the peer failed before deriving keys.
                    if ty == CT_ALERT && body.len() == 2 {
                        return self.alert(body);
                    }
                    return fail(Alert::UnexpectedMessage);
                }
                let (t, n) = k.open(hdr, body)?;
                (t, &body[..n])
            }
        };
        match inner {
            CT_HANDSHAKE => {
                if content.is_empty() {
                    return fail(Alert::UnexpectedMessage);
                }
                self.hs_buf.extend_from_slice(content);
                self.handshake_messages()
            }
            CT_ALERT => self.alert(content),
            CT_APPDATA => {
                if self.state != State::Established || !self.hs_buf.is_empty() {
                    return fail(Alert::UnexpectedMessage);
                }
                self.plain.extend_from_slice(content);
                Ok(())
            }
            _ => fail(Alert::UnexpectedMessage),
        }
    }

    fn alert(&mut self, body: &[u8]) -> Result<()> {
        if body.len() != 2 {
            return fail(Alert::DecodeError);
        }
        if body[1] == Alert::CloseNotify as u8 {
            self.peer_closed = true;
            if self.state != State::Established {
                self.state = State::Closed;
                return Err(Error::Closed);
            }
            return Ok(());
        }
        // TLS 1.3: every other alert is fatal.
        self.state = State::Closed;
        Err(Error::Peer(body[1]))
    }

    fn handshake_messages(&mut self) -> Result<()> {
        loop {
            if self.hs_buf.len() < 4 {
                return Ok(());
            }
            let len = (self.hs_buf[1] as usize) << 16 | (self.hs_buf[2] as usize) << 8 | self.hs_buf[3] as usize;
            if len > MAX_HANDSHAKE {
                return fail(Alert::DecodeError);
            }
            if self.hs_buf.len() < 4 + len {
                return Ok(());
            }
            let msg: Vec<u8> = self.hs_buf.drain(..4 + len).collect();
            let epoch = self.read_epoch;
            self.handshake(&msg)?;
            // A key change must align with a record boundary (RFC 8446 5.1).
            if self.read_epoch != epoch && !self.hs_buf.is_empty() {
                return fail(Alert::UnexpectedMessage);
            }
        }
    }

    fn handshake(&mut self, msg: &[u8]) -> Result<()> {
        let (ty, body) = (msg[0], &msg[4..]);
        match (self.state, ty) {
            (State::SrvWaitClientHello, HT_CLIENT_HELLO) => self.srv_client_hello(msg, body),
            (State::SrvWaitCert, HT_CERTIFICATE) => self.peer_certificate(msg, body),
            (State::SrvWaitCertVerify, HT_CERTIFICATE_VERIFY) => self.peer_cert_verify(msg, body),
            (State::SrvWaitFinished, HT_FINISHED) => self.srv_finished(msg, body),
            (State::CliWaitServerHello, HT_SERVER_HELLO) => self.cli_server_hello(msg, body),
            (State::CliWaitEncryptedExtensions, HT_ENCRYPTED_EXTENSIONS) => self.cli_encrypted_extensions(msg, body),
            (State::CliWaitCertOrRequest, HT_CERTIFICATE_REQUEST) => self.cli_cert_request(msg, body),
            (State::CliWaitCertOrRequest | State::CliWaitCert, HT_CERTIFICATE) => self.peer_certificate(msg, body),
            (State::CliWaitCertVerify, HT_CERTIFICATE_VERIFY) => self.peer_cert_verify(msg, body),
            (State::CliWaitFinished, HT_FINISHED) => self.cli_finished(msg, body),
            (State::Established, HT_KEY_UPDATE) => self.peer_key_update(body),
            (State::Established, HT_NEW_SESSION_TICKET) if matches!(self.role, Role::Client { .. }) => Ok(()), // no resumption
            _ => fail(Alert::UnexpectedMessage),
        }
    }

    fn peer_key_update(&mut self, body: &[u8]) -> Result<()> {
        let req = match body {
            [0] => false,
            [1] => true,
            _ => return fail(Alert::DecodeError),
        };
        let next = self.read_keys.as_ref().unwrap().updated();
        self.set_read(Some(next));
        if req {
            let msg = handshake_msg(HT_KEY_UPDATE, |m| m.push(0));
            self.send_handshake_record(&msg);
            let next = self.write_keys.as_ref().unwrap().updated();
            self.write_keys = Some(next);
        }
        Ok(())
    }

    fn set_read(&mut self, k: Option<RecordKeys>) {
        self.read_keys = k;
        self.read_epoch += 1;
    }

    fn transcript_hash(&self) -> [u8; 32] {
        self.transcript.clone().finalize()
    }

    /// Sends a handshake message in its own record (encrypted once keys exist).
    fn send_handshake_record(&mut self, msg: &[u8]) {
        match self.write_keys.as_mut() {
            Some(k) => {
                for chunk in msg.chunks(MAX_PLAINTEXT) {
                    k.seal(CT_HANDSHAKE, chunk, &mut self.out);
                }
            }
            None => {
                for chunk in msg.chunks(MAX_PLAINTEXT) {
                    self.out.extend_from_slice(&[CT_HANDSHAKE, 3, 3]);
                    let n = chunk.len();
                    self.out.extend_from_slice(&[(n >> 8) as u8, n as u8]);
                    self.out.extend_from_slice(chunk);
                }
            }
        }
    }

    fn send_hs(&mut self, msg: Vec<u8>) {
        self.transcript.update(&msg);
        self.send_handshake_record(&msg);
    }

    fn random32(&self) -> [u8; 32] {
        let mut r = [0u8; 32];
        (self.rng)(&mut r);
        r
    }

    fn derive_handshake(&mut self, shared: &[u8]) {
        let early = extract(&[], &[0u8; 32]);
        let derived = derive_secret(&early, b"derived", &empty_hash());
        self.hs_secret = extract(&derived, shared);
        let th = self.transcript_hash();
        self.c_hs = derive_secret(&self.hs_secret, b"c hs traffic", &th);
        self.s_hs = derive_secret(&self.hs_secret, b"s hs traffic", &th);
        let derived = derive_secret(&self.hs_secret, b"derived", &empty_hash());
        self.master = extract(&derived, &[0u8; 32]);
    }

    fn app_secrets(&self) -> (Secret, Secret) {
        let th = self.transcript_hash();
        (derive_secret(&self.master, b"c ap traffic", &th), derive_secret(&self.master, b"s ap traffic", &th))
    }

    // ---- server ----

    fn srv_client_hello(&mut self, msg: &[u8], body: &[u8]) -> Result<()> {
        let Role::Server(cfg) = &self.role else { unreachable!() };
        let cfg = cfg.clone();
        let mut r = Rd::new(body);
        let _legacy_version = r.u16()?;
        r.take(32)?; // random
        let session_id = r.vec8()?;
        if session_id.len() > 32 {
            return fail(Alert::IllegalParameter);
        }
        let suites = r.vec16()?;
        let compression = r.vec8()?;
        let exts = extensions(r.vec16()?)?;
        r.done()?;
        if compression != [0] {
            return fail(Alert::IllegalParameter);
        }
        // Version: TLS 1.3 only, via supported_versions.
        let versions = find_ext(&exts, EXT_SUPPORTED_VERSIONS).ok_or(Error::Local(Alert::ProtocolVersion))?;
        let mut vr = Rd::new(versions);
        let list = vr.vec8()?;
        vr.done()?;
        if !list.chunks(2).any(|v| v == TLS13.to_be_bytes()) {
            return fail(Alert::ProtocolVersion);
        }
        // Cipher suite: our preference order.
        let offered = |s: u16| suites.chunks(2).any(|c| c == s.to_be_bytes());
        self.suite = [TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256].into_iter().find(|&s| offered(s)).ok_or(Error::Local(Alert::HandshakeFailure))?;
        // Signature algorithm for our key must be offered.
        let sig_algs = find_ext(&exts, EXT_SIGNATURE_ALGORITHMS).ok_or(Error::Local(Alert::MissingExtension))?;
        let mut sr = Rd::new(sig_algs);
        let sigs = sr.vec16()?;
        sr.done()?;
        let our_sig = sig_scheme(&cfg.key);
        if !sigs.chunks(2).any(|c| c == our_sig.to_be_bytes()) {
            return fail(Alert::HandshakeFailure);
        }
        // Key share: first usable share in the client's order.
        let ks = find_ext(&exts, EXT_KEY_SHARE).ok_or(Error::Local(Alert::MissingExtension))?;
        find_ext(&exts, EXT_SUPPORTED_GROUPS).ok_or(Error::Local(Alert::MissingExtension))?;
        let mut kr = Rd::new(ks);
        let mut shares = Rd::new(kr.vec16()?);
        kr.done()?;
        let mut chosen = None;
        while !shares.b.is_empty() {
            let group = shares.u16()?;
            let key = shares.vec16()?;
            if chosen.is_none() && (group == GROUP_X25519 || group == GROUP_P256) {
                chosen = Some((group, key));
            }
        }
        let (group, peer_key) = chosen.ok_or(Error::Local(Alert::HandshakeFailure))?; // no HRR support
        // ALPN.
        if let (Some(a), false) = (find_ext(&exts, EXT_ALPN), cfg.alpn.is_empty()) {
            let mut ar = Rd::new(a);
            let mut list = Rd::new(ar.vec16()?);
            ar.done()?;
            let mut theirs = Vec::new();
            while !list.b.is_empty() {
                theirs.push(list.vec8()?);
            }
            let pick = cfg.alpn.iter().find(|p| theirs.contains(&&p[..])).ok_or(Error::Local(Alert::NoApplicationProtocol))?;
            self.alpn = Some(pick.clone());
        }

        self.session_id = session_id.to_vec();
        self.transcript.update(msg);
        let share = if group == GROUP_X25519 { KeyShare::X25519(self.random32()) } else { KeyShare::P256(p256_key(self.rng)) };
        let shared = share.shared(peer_key)?;
        let random = self.random32();
        let sh = handshake_msg(HT_SERVER_HELLO, |m| {
            put_u16(m, 0x0303);
            m.extend_from_slice(&random);
            put_vec(m, 1, |v| v.extend_from_slice(&self.session_id));
            put_u16(m, self.suite);
            m.push(0);
            put_vec(m, 2, |e| {
                put_ext(e, EXT_SUPPORTED_VERSIONS, |v| put_u16(v, TLS13));
                put_ext(e, EXT_KEY_SHARE, |v| {
                    put_u16(v, group);
                    put_vec(v, 2, |k| k.extend_from_slice(&share.public()));
                });
            });
        });
        self.send_hs(sh);
        if !self.session_id.is_empty() {
            self.out.extend_from_slice(&[CT_CCS, 3, 3, 0, 1, 1]);
        }
        self.derive_handshake(&shared);
        self.write_keys = Some(RecordKeys::new(self.suite, self.s_hs));
        self.set_read(Some(RecordKeys::new(self.suite, self.c_hs)));

        let ee = handshake_msg(HT_ENCRYPTED_EXTENSIONS, |m| {
            put_vec(m, 2, |e| {
                if let Some(p) = &self.alpn {
                    put_ext(e, EXT_ALPN, |v| put_vec(v, 2, |l| put_vec(l, 1, |x| x.extend_from_slice(p))));
                }
            })
        });
        self.send_hs(ee);
        if !matches!(cfg.client_auth, ClientAuth::None) {
            let cr = handshake_msg(HT_CERTIFICATE_REQUEST, |m| {
                m.push(0); // empty context
                put_vec(m, 2, |e| put_ext(e, EXT_SIGNATURE_ALGORITHMS, |v| put_vec(v, 2, |l| {
                    put_u16(l, SIG_ECDSA_P256_SHA256);
                    put_u16(l, SIG_ED25519);
                })));
            });
            self.send_hs(cr);
            self.cert_requested = true;
        }
        self.send_certificate(&cfg.cert_chain);
        self.send_cert_verify(&cfg.key, b"TLS 1.3, server CertificateVerify");
        let fin = finished_mac(&self.s_hs, &self.transcript_hash());
        self.send_hs(handshake_msg(HT_FINISHED, |m| m.extend_from_slice(&fin)));
        // Server application keys are derived over CH..server Finished.
        let (c_ap, s_ap) = self.app_secrets();
        self.write_keys = Some(RecordKeys::new(self.suite, s_ap));
        self.pending_read = Some(RecordKeys::new(self.suite, c_ap));
        self.state = if self.cert_requested { State::SrvWaitCert } else { State::SrvWaitFinished };
        Ok(())
    }

    fn send_certificate(&mut self, chain: &[Vec<u8>]) {
        let m = handshake_msg(HT_CERTIFICATE, |m| {
            m.push(0); // context
            put_vec(m, 3, |l| {
                for c in chain {
                    put_vec(l, 3, |x| x.extend_from_slice(c));
                    put_u16(l, 0); // no per-certificate extensions
                }
            });
        });
        self.send_hs(m);
    }

    fn send_cert_verify(&mut self, key: &SigningKey, context: &[u8]) {
        let content = verify_content(context, &self.transcript_hash());
        let sig = key.sign(&content);
        let m = handshake_msg(HT_CERTIFICATE_VERIFY, |m| {
            put_u16(m, sig_scheme(key));
            put_vec(m, 2, |s| s.extend_from_slice(&sig));
        });
        self.send_hs(m);
    }

    /// Certificate from the peer (server's on the client; client's on the server).
    fn peer_certificate(&mut self, msg: &[u8], body: &[u8]) -> Result<()> {
        let mut r = Rd::new(body);
        if !r.vec8()?.is_empty() {
            return fail(Alert::IllegalParameter); // we never send a non-empty request context
        }
        let mut list = Rd::new(r.vec24()?);
        r.done()?;
        let mut chain = Vec::new();
        while !list.b.is_empty() {
            let cert = list.vec24()?;
            if cert.is_empty() {
                return fail(Alert::DecodeError);
            }
            list.vec16()?; // extensions: ignored
            chain.push(cert.to_vec());
        }
        self.transcript.update(msg);
        let is_server = matches!(self.role, Role::Server(_));
        if chain.is_empty() {
            if !is_server {
                return fail(Alert::DecodeError);
            }
            let Role::Server(cfg) = &self.role else { unreachable!() };
            if matches!(cfg.client_auth, ClientAuth::Required(_)) {
                return fail(Alert::CertificateRequired);
            }
            self.state = State::SrvWaitFinished;
            return Ok(());
        }
        let refs: Vec<&[u8]> = chain.iter().map(|c| &c[..]).collect();
        let result = match &self.role {
            Role::Server(cfg) => {
                let roots = match &cfg.client_auth {
                    ClientAuth::Optional(r) | ClientAuth::Required(r) => r,
                    ClientAuth::None => return fail(Alert::UnexpectedMessage),
                };
                let roots: Vec<&[u8]> = roots.iter().map(|c| &c[..]).collect();
                x509::verify_chain(&refs, &roots, self.now, Usage::Client)
            }
            Role::Client { cfg, server_name, .. } => {
                let roots: Vec<&[u8]> = cfg.roots.iter().map(|c| &c[..]).collect();
                x509::verify_chain(&refs, &roots, self.now, Usage::Server(server_name))
            }
        };
        if let Err(e) = result {
            return fail(match e {
                VerifyError::Expired => Alert::CertificateExpired,
                VerifyError::UnknownIssuer | VerifyError::NotCa => Alert::UnknownCa,
                _ => Alert::BadCertificate,
            });
        }
        let leaf = x509::Certificate::parse(&chain[0]).or(fail(Alert::BadCertificate))?;
        self.peer_key = leaf.public_key.clone();
        self.peer_certs = chain;
        self.state = if is_server { State::SrvWaitCertVerify } else { State::CliWaitCertVerify };
        Ok(())
    }

    fn peer_cert_verify(&mut self, msg: &[u8], body: &[u8]) -> Result<()> {
        let mut r = Rd::new(body);
        let scheme = r.u16()?;
        let sig = r.vec16()?;
        r.done()?;
        let is_server = matches!(self.role, Role::Server(_));
        let context: &[u8] = if is_server { b"TLS 1.3, client CertificateVerify" } else { b"TLS 1.3, server CertificateVerify" };
        let content = verify_content(context, &self.transcript_hash());
        let alg = match scheme {
            // TLS 1.3 binds the curve to the scheme.
            SIG_ECDSA_P256_SHA256 if matches!(self.peer_key, Some(PublicKey::P256(_))) => SigAlg::Ecdsa(crate::rsa::HashAlg::Sha256),
            SIG_ECDSA_P384_SHA384 if matches!(self.peer_key, Some(PublicKey::P384(_))) => SigAlg::Ecdsa(crate::rsa::HashAlg::Sha384),
            SIG_ED25519 => SigAlg::Ed25519,
            SIG_RSA_PSS_RSAE_SHA256 => SigAlg::RsaPss(crate::rsa::HashAlg::Sha256, 32),
            SIG_RSA_PSS_RSAE_SHA384 => SigAlg::RsaPss(crate::rsa::HashAlg::Sha384, 48),
            SIG_RSA_PSS_RSAE_SHA512 => SigAlg::RsaPss(crate::rsa::HashAlg::Sha512, 64),
            _ => return fail(Alert::IllegalParameter),
        };
        let key = self.peer_key.as_ref().ok_or(Error::Local(Alert::BadCertificate))?;
        if !key.verify(alg, &content, sig) {
            return fail(Alert::DecryptError);
        }
        self.transcript.update(msg);
        self.state = if is_server { State::SrvWaitFinished } else { State::CliWaitFinished };
        Ok(())
    }

    fn srv_finished(&mut self, msg: &[u8], body: &[u8]) -> Result<()> {
        let expect = finished_mac(&self.c_hs, &self.transcript_hash());
        if !ct_eq(&expect, body) {
            return fail(Alert::DecryptError);
        }
        self.transcript.update(msg);
        let k = self.pending_read.take();
        self.set_read(k);
        self.ccs_allowed = false;
        self.state = State::Established;
        Ok(())
    }

    // ---- client ----

    fn send_client_hello(&mut self, p256_only: bool) {
        let Role::Client { cfg, server_name, share, offered_p256 } = &mut self.role else { unreachable!() };
        let new_share = if p256_only { KeyShare::P256(p256_key(self.rng)) } else {
            let mut s = [0u8; 32];
            (self.rng)(&mut s);
            KeyShare::X25519(s)
        };
        *offered_p256 = p256_only;
        let pubkey = new_share.public();
        *share = Some(new_share);
        let (cfg, sni) = (cfg.clone(), server_name.clone());
        if self.session_id.is_empty() {
            let mut sid = [0u8; 32];
            (self.rng)(&mut sid);
            self.session_id = sid.to_vec();
        }
        let random = self.random32();
        let ch = handshake_msg(HT_CLIENT_HELLO, |m| {
            put_u16(m, 0x0303);
            m.extend_from_slice(&random);
            put_vec(m, 1, |v| v.extend_from_slice(&self.session_id));
            put_vec(m, 2, |v| {
                put_u16(v, TLS_CHACHA20_POLY1305_SHA256);
                put_u16(v, TLS_AES_128_GCM_SHA256);
            });
            put_vec(m, 1, |v| v.push(0));
            put_vec(m, 2, |e| {
                if x509::parse_ip(&sni).is_none() && !sni.is_empty() {
                    put_ext(e, EXT_SERVER_NAME, |v| put_vec(v, 2, |l| {
                        l.push(0); // host_name
                        put_vec(l, 2, |h| h.extend_from_slice(&sni));
                    }));
                }
                put_ext(e, EXT_SUPPORTED_VERSIONS, |v| put_vec(v, 1, |l| put_u16(l, TLS13)));
                put_ext(e, EXT_SUPPORTED_GROUPS, |v| put_vec(v, 2, |l| {
                    put_u16(l, GROUP_X25519);
                    put_u16(l, GROUP_P256);
                }));
                put_ext(e, EXT_SIGNATURE_ALGORITHMS, |v| put_vec(v, 2, |l| {
                    for s in [SIG_ECDSA_P256_SHA256, SIG_ECDSA_P384_SHA384, SIG_ED25519, SIG_RSA_PSS_RSAE_SHA256, SIG_RSA_PSS_RSAE_SHA384, SIG_RSA_PSS_RSAE_SHA512, SIG_RSA_PKCS1_SHA256, SIG_RSA_PKCS1_SHA384, SIG_RSA_PKCS1_SHA512] {
                        put_u16(l, s);
                    }
                }));
                put_ext(e, EXT_KEY_SHARE, |v| put_vec(v, 2, |l| {
                    put_u16(l, if p256_only { GROUP_P256 } else { GROUP_X25519 });
                    put_vec(l, 2, |k| k.extend_from_slice(&pubkey));
                }));
                if !cfg.alpn.is_empty() {
                    put_ext(e, EXT_ALPN, |v| put_vec(v, 2, |l| {
                        for p in &cfg.alpn {
                            put_vec(l, 1, |x| x.extend_from_slice(p));
                        }
                    }));
                }
            });
        });
        self.send_hs(ch);
    }

    fn cli_server_hello(&mut self, msg: &[u8], body: &[u8]) -> Result<()> {
        let mut r = Rd::new(body);
        if r.u16()? != 0x0303 {
            return fail(Alert::ProtocolVersion);
        }
        let random = r.take(32)?;
        let sid = r.vec8()?;
        let suite = r.u16()?;
        let compression = r.u8()?;
        let exts = extensions(r.vec16()?)?;
        r.done()?;
        if sid != &self.session_id[..] || compression != 0 {
            return fail(Alert::IllegalParameter);
        }
        if suite != TLS_CHACHA20_POLY1305_SHA256 && suite != TLS_AES_128_GCM_SHA256 {
            return fail(Alert::IllegalParameter);
        }
        let v = find_ext(&exts, EXT_SUPPORTED_VERSIONS).ok_or(Error::Local(Alert::ProtocolVersion))?;
        if v != TLS13.to_be_bytes() {
            return fail(Alert::ProtocolVersion);
        }
        let ks = find_ext(&exts, EXT_KEY_SHARE).ok_or(Error::Local(Alert::MissingExtension))?;
        if random == HRR_RANDOM {
            // HelloRetryRequest: only "use P-256 instead" is supported, once.
            let Role::Client { offered_p256, .. } = &self.role else { unreachable!() };
            if *offered_p256 || ks != GROUP_P256.to_be_bytes() || find_ext(&exts, 44).is_some() {
                return fail(Alert::IllegalParameter); // cookie (44) unsupported
            }
            // Transcript restarts with message_hash(CH1).
            let ch1 = self.transcript_hash();
            self.transcript = Sha256::new();
            self.transcript.update(&[254, 0, 0, 32]);
            self.transcript.update(&ch1);
            self.transcript.update(msg);
            self.send_client_hello(true);
            return Ok(());
        }
        let mut kr = Rd::new(ks);
        let group = kr.u16()?;
        let key = kr.vec16()?;
        kr.done()?;
        let Role::Client { share, .. } = &self.role else { unreachable!() };
        let share = share.as_ref().unwrap();
        let ok_group = matches!((share, group), (KeyShare::X25519(_), GROUP_X25519) | (KeyShare::P256(_), GROUP_P256));
        if !ok_group {
            return fail(Alert::IllegalParameter);
        }
        let shared = share.shared(key)?;
        self.suite = suite;
        self.transcript.update(msg);
        self.derive_handshake(&shared);
        self.set_read(Some(RecordKeys::new(self.suite, self.s_hs)));
        // From here on our records (including alerts) use the client handshake keys; the
        // compatibility CCS goes out first, in plaintext.
        self.out.extend_from_slice(&[CT_CCS, 3, 3, 0, 1, 1]);
        self.write_keys = Some(RecordKeys::new(self.suite, self.c_hs));
        self.state = State::CliWaitEncryptedExtensions;
        Ok(())
    }

    fn cli_encrypted_extensions(&mut self, msg: &[u8], body: &[u8]) -> Result<()> {
        let mut r = Rd::new(body);
        let exts = extensions(r.vec16()?)?;
        r.done()?;
        if let Some(a) = find_ext(&exts, EXT_ALPN) {
            let mut ar = Rd::new(a);
            let mut list = Rd::new(ar.vec16()?);
            ar.done()?;
            let p = list.vec8()?;
            list.done()?;
            let Role::Client { cfg, .. } = &self.role else { unreachable!() };
            if !cfg.alpn.iter().any(|x| x == p) {
                return fail(Alert::IllegalParameter);
            }
            self.alpn = Some(p.to_vec());
        }
        self.transcript.update(msg);
        self.state = State::CliWaitCertOrRequest;
        Ok(())
    }

    fn cli_cert_request(&mut self, msg: &[u8], body: &[u8]) -> Result<()> {
        let mut r = Rd::new(body);
        let ctx = r.vec8()?;
        extensions(r.vec16()?)?;
        r.done()?;
        if !ctx.is_empty() {
            return fail(Alert::IllegalParameter);
        }
        self.transcript.update(msg);
        self.cert_requested = true;
        self.state = State::CliWaitCert;
        Ok(())
    }

    fn cli_finished(&mut self, msg: &[u8], body: &[u8]) -> Result<()> {
        let expect = finished_mac(&self.s_hs, &self.transcript_hash());
        if !ct_eq(&expect, body) {
            return fail(Alert::DecryptError);
        }
        self.transcript.update(msg);
        let (c_ap, s_ap) = self.app_secrets();
        if self.cert_requested {
            let Role::Client { cfg, .. } = &self.role else { unreachable!() };
            let cfg = cfg.clone();
            match &cfg.client_cert {
                Some((chain, key)) => {
                    self.send_certificate(chain);
                    self.send_cert_verify(key, b"TLS 1.3, client CertificateVerify");
                }
                None => self.send_certificate(&[]),
            }
        }
        let fin = finished_mac(&self.c_hs, &self.transcript_hash());
        self.send_hs(handshake_msg(HT_FINISHED, |m| m.extend_from_slice(&fin)));
        self.write_keys = Some(RecordKeys::new(self.suite, c_ap));
        self.set_read(Some(RecordKeys::new(self.suite, s_ap)));
        self.ccs_allowed = false;
        self.state = State::Established;
        Ok(())
    }
}

fn sig_scheme(k: &SigningKey) -> u16 {
    match k {
        SigningKey::P256(_) => SIG_ECDSA_P256_SHA256,
        SigningKey::Ed25519(_) => SIG_ED25519,
    }
}

/// 64 spaces, the context string, a zero byte, then the transcript hash (RFC 8446 4.4.3).
fn verify_content(context: &[u8], th: &[u8; 32]) -> Vec<u8> {
    let mut v = alloc::vec![0x20u8; 64];
    v.extend_from_slice(context);
    v.push(0);
    v.extend_from_slice(th);
    v
}

fn p256_key(rng: Rng) -> p256::SecretKey {
    let mut seed = [0u8; 48];
    rng(&mut seed);
    let k = p256::SecretKey::from_seed(&seed);
    crate::wipe(&mut seed);
    k
}
