//! Encryption of selected resources at rest (ADR-047), like kube-apiserver's
//! `EncryptionConfiguration`. Values of the configured resources are encrypted with AES-256-GCM
//! when they leave memory for the log, snapshots and Raft records ([`kr_store::Codec`]) and
//! decrypted when loaded. In memory, and in watch events and API responses, they stay plain
//! (as in kube-apiserver's watch cache), so reads cost nothing.
//!
//! Stored value: `k8s:enc:aesgcm:v1:<keyname>:` + nonce (12) + ciphertext + tag (16). The store
//! key is the AEAD associated data, so a ciphertext cannot be moved to another object. Nonces are
//! random 96-bit: keep under 2^32 writes per key (rotate by name well before; a busy cluster does
//! that in years, not days). The first key encrypts; every key listed can decrypt. A value without
//! the prefix is read as plaintext (identity fallback, upgrade in place and `disable`).
//! A value that cannot be decrypted fails the load or apply with an error, never garbage.
use alloc::string::String;
use alloc::vec::Vec;
use kr_crypto::aes::AesGcm;
use kr_fmt::json::{self, Value};
use kr_store::Codec;

pub const FILE: &str = "encryption-config.json";
const PREFIX: &str = "k8s:enc:aesgcm:v1:";
const MAGIC: &str = "k8s:enc:";

#[derive(Clone, Debug, PartialEq)]
pub struct KeyEntry {
    pub name: String,
    pub secret: [u8; 32],
}

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    /// `plural` or `plural.group` (core resources have no group), like upstream.
    pub resources: Vec<String>,
    /// The first key encrypts (unless `identity_first`); all of them decrypt.
    pub keys: Vec<KeyEntry>,
    /// Write plaintext (decryption still works): the state while disabling.
    pub identity_first: bool,
}

fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 63 && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl Config {
    /// A fresh configuration for Secrets with one random key named `key<unix time>`.
    pub fn generate(rng: fn(&mut [u8]), now: i64) -> Config {
        Config { resources: alloc::vec![String::from("secrets")], keys: alloc::vec![new_key(rng, now, &[])], identity_first: false }
    }

    /// Adds a new first key; the old ones stay for reading.
    pub fn rotate(&mut self, rng: fn(&mut [u8]), now: i64) -> String {
        let k = new_key(rng, now, &self.keys);
        let name = k.name.clone();
        self.keys.insert(0, k);
        self.identity_first = false;
        name
    }

    pub fn parse(text: &[u8]) -> Result<Config, String> {
        let v = json::parse(text).map_err(|_| String::from("not valid JSON"))?;
        let resources: Vec<String> = v.get("resources").and_then(Value::as_array).ok_or("missing resources")?.iter().filter_map(|r| r.as_str().map(String::from)).collect();
        if resources.is_empty() || resources.iter().any(|r| r.is_empty() || r.contains('/')) {
            return Err("resources must be a non-empty list of plural[.group] names".into());
        }
        let mut keys = Vec::new();
        for k in v.get("keys").and_then(Value::as_array).ok_or("missing keys")? {
            let name = k.get("name").and_then(Value::as_str).ok_or("key without name")?;
            if !valid_name(name) || keys.iter().any(|e: &KeyEntry| e.name == name) {
                return Err(alloc::format!("bad or duplicate key name {name:?}"));
            }
            let raw = kr_fmt::base64::decode(k.get("secret").and_then(Value::as_str).ok_or("key without secret")?).map_err(|_| "key secret is not base64")?;
            let secret: [u8; 32] = raw.try_into().map_err(|_| "key secret must be 32 bytes (AES-256)")?;
            keys.push(KeyEntry { name: String::from(name), secret });
        }
        if keys.is_empty() {
            return Err("at least one key is required".into());
        }
        let identity_first = v.get("identityFirst").and_then(Value::as_bool).unwrap_or(false);
        Ok(Config { resources, keys, identity_first })
    }

    pub fn to_json(&self) -> String {
        let keys = self
            .keys
            .iter()
            .map(|k| Value::Object(alloc::vec![(String::from("name"), Value::String(k.name.clone())), (String::from("secret"), Value::String(kr_fmt::base64::encode(&k.secret)))]))
            .collect();
        let mut s = json::to_string(&Value::Object(alloc::vec![
            (String::from("resources"), Value::Array(self.resources.iter().map(|r| Value::String(r.clone())).collect())),
            (String::from("keys"), Value::Array(keys)),
            (String::from("identityFirst"), Value::Bool(self.identity_first)),
        ]));
        s.push('\n');
        s
    }

    /// Store key prefixes of the configured resources (`/registry/<group|core>/<plural>/`).
    pub fn prefixes(&self) -> Vec<String> {
        self.resources
            .iter()
            .map(|r| {
                let (plural, group) = r.split_once('.').unwrap_or((r, "core"));
                alloc::format!("/registry/{group}/{plural}/")
            })
            .collect()
    }
}

fn new_key(rng: fn(&mut [u8]), now: i64, existing: &[KeyEntry]) -> KeyEntry {
    let mut secret = [0u8; 32];
    rng(&mut secret);
    let mut name = alloc::format!("key{now}");
    let mut n = 1;
    while existing.iter().any(|k| k.name == name) {
        n += 1;
        name = alloc::format!("key{now}-{n}");
    }
    KeyEntry { name, secret }
}

/// The [`Codec`] for a [`Config`].
pub struct Encryptor {
    prefixes: Vec<String>,
    keys: Vec<(String, AesGcm)>,
    identity_first: bool,
    rng: fn(&mut [u8]),
}

impl Encryptor {
    pub fn new(cfg: &Config, rng: fn(&mut [u8])) -> Encryptor {
        Encryptor { prefixes: cfg.prefixes(), keys: cfg.keys.iter().map(|k| (k.name.clone(), AesGcm::new(&k.secret))).collect(), identity_first: cfg.identity_first, rng }
    }

    fn covers(&self, key: &str) -> bool {
        self.prefixes.iter().any(|p| key.starts_with(p.as_str()))
    }
}

impl Codec for Encryptor {
    fn encode(&self, key: &str, value: &[u8]) -> Option<Vec<u8>> {
        if self.identity_first || !self.covers(key) {
            return None;
        }
        let (name, gcm) = &self.keys[0];
        let mut nonce = [0u8; 12];
        (self.rng)(&mut nonce);
        let mut out = Vec::with_capacity(PREFIX.len() + name.len() + 1 + 12 + value.len() + 16);
        out.extend_from_slice(PREFIX.as_bytes());
        out.extend_from_slice(name.as_bytes());
        out.push(b':');
        out.extend_from_slice(&nonce);
        let start = out.len();
        out.extend_from_slice(value);
        let tag = gcm.seal(&nonce, key.as_bytes(), &mut out[start..]);
        out.extend_from_slice(&tag);
        Some(out)
    }

    fn decode(&self, key: &str, value: &[u8]) -> Result<Option<Vec<u8>>, ()> {
        if !value.starts_with(MAGIC.as_bytes()) {
            return Ok(None); // identity (plaintext)
        }
        let rest = value.strip_prefix(PREFIX.as_bytes()).ok_or(())?;
        let colon = rest.iter().position(|b| *b == b':').ok_or(())?;
        let name = core::str::from_utf8(&rest[..colon]).map_err(|_| ())?;
        let body = &rest[colon + 1..];
        if body.len() < 12 + 16 {
            return Err(());
        }
        let gcm = &self.keys.iter().find(|(n, _)| n == name).ok_or(())?.1;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&body[..12]);
        let (ct, tag) = body[12..].split_at(body.len() - 12 - 16);
        let mut data = ct.to_vec();
        gcm.open(&nonce, key.as_bytes(), &mut data, tag)?;
        Ok(Some(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::rc::Rc;
    use std::sync::atomic::{AtomicU64, Ordering};

    static CTR: AtomicU64 = AtomicU64::new(1);
    fn rng(b: &mut [u8]) {
        // deterministic but distinct (tests only)
        for x in b.iter_mut() {
            let c = CTR.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::SeqCst);
            *x = (c >> 29) as u8 ^ (c >> 7) as u8;
        }
    }
    const SK: &str = "/registry/core/secrets/default/s";

    fn tmp(n: &str) -> std::string::String {
        let p = std::env::temp_dir().join(std::format!("kr-enc-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p.to_str().unwrap().into()
    }

    #[test]
    fn round_trip_and_selective() {
        let cfg = Config::generate(rng, 1);
        let e = Encryptor::new(&cfg, rng);
        let c = e.encode(SK, b"{\"data\":{\"p\":\"aHVudGVyMg==\"}}").unwrap();
        assert!(c.starts_with(b"k8s:enc:aesgcm:v1:key1:"));
        assert!(!c.windows(8).any(|w| w == b"aHVudGVy"));
        assert_eq!(e.decode(SK, &c).unwrap().unwrap(), b"{\"data\":{\"p\":\"aHVudGVyMg==\"}}");
        assert!(e.encode("/registry/core/configmaps/default/c", b"x").is_none());
        assert_eq!(Config::parse(cfg.to_json().as_bytes()).unwrap(), cfg);
    }

    #[test]
    fn a_resource_removed_from_the_list_still_reads_back() {
        let mut cfg = Config::generate(rng, 1);
        cfg.resources.push("configmaps".into());
        let cm = "/registry/core/configmaps/default/c";
        let stored = Encryptor::new(&cfg, rng).encode(cm, b"{\"data\":{}}").unwrap();
        // Later the list names only secrets: new writes stay plaintext, the old ciphertext decrypts.
        cfg.resources.retain(|r| r != "configmaps");
        let later = Encryptor::new(&cfg, rng);
        assert!(later.encode(cm, b"x").is_none());
        assert_eq!(later.decode(cm, &stored).unwrap().unwrap(), b"{\"data\":{}}");
    }

    #[test]
    fn wrong_key_tamper_and_moved_fail_closed() {
        let e = Encryptor::new(&Config::generate(rng, 1), rng);
        let other = Encryptor::new(&Config::generate(rng, 1), rng); // same name, other secret
        let c = e.encode(SK, b"secret").unwrap();
        assert!(other.decode(SK, &c).is_err());
        let mut t = c.clone();
        let n = t.len();
        t[n - 20] ^= 1;
        assert!(e.decode(SK, &t).is_err());
        let mut t = c.clone();
        t[n - 1] ^= 1;
        assert!(e.decode(SK, &t).is_err());
        assert!(e.decode("/registry/core/secrets/default/other", &c).is_err(), "bound to its key");
        assert!(e.decode(SK, &c[..30]).is_err());
        assert!(e.decode(SK, b"k8s:enc:aesgcm:v1:nokey:0123456789012345678901234567890123456789").is_err());
        assert_eq!(e.decode(SK, b"{\"plain\":1}").unwrap(), None, "plaintext fallback");
    }

    #[test]
    fn rotation_order_and_disable() {
        let mut cfg = Config::generate(rng, 1);
        let old = Encryptor::new(&cfg, rng);
        let c_old = old.encode(SK, b"v").unwrap();
        assert_eq!(cfg.rotate(rng, 2), "key2");
        let e = Encryptor::new(&cfg, rng);
        let c_new = e.encode(SK, b"v").unwrap();
        assert!(c_new.starts_with(b"k8s:enc:aesgcm:v1:key2:"));
        assert_eq!(e.decode(SK, &c_old).unwrap().unwrap(), b"v", "old key still reads");
        assert!(old.decode(SK, &c_new).is_err(), "removed key set cannot read");
        cfg.identity_first = true;
        let d = Encryptor::new(&cfg, rng);
        assert!(d.encode(SK, b"v").is_none());
        assert_eq!(d.decode(SK, &c_new).unwrap().unwrap(), b"v");
    }

    #[test]
    fn store_log_snapshot_and_reopen() {
        let dir = tmp("store");
        let cfg = Config::generate(rng, 1);
        let codec: Rc<dyn Codec> = Rc::new(Encryptor::new(&cfg, rng));
        let mut s = kr_store::Store::open_with(&dir, Some(codec.clone())).unwrap();
        s.create(SK, b"TOPSECRET-VALUE".to_vec()).unwrap();
        s.create("/registry/core/configmaps/default/c", b"PLAINCM".to_vec()).unwrap();
        s.sync().unwrap();
        assert_eq!(&*s.get(SK).unwrap().value, b"TOPSECRET-VALUE");
        let log = std::fs::read(std::format!("{dir}/log")).unwrap();
        assert!(!log.windows(9).any(|w| w == b"TOPSECRET") && log.windows(7).any(|w| w == b"PLAINCM"));
        assert!(!s.image().windows(9).any(|w| w == b"TOPSECRET"));
        s.rewrite_log().unwrap();
        drop(s);
        let snap = std::fs::read(std::format!("{dir}/snapshot")).unwrap();
        assert!(!snap.windows(9).any(|w| w == b"TOPSECRET"));
        let s = kr_store::Store::open_with(&dir, Some(codec)).unwrap();
        assert_eq!(&*s.get(SK).unwrap().value, b"TOPSECRET-VALUE");
        // wrong key: opening fails, never garbage
        let bad: Rc<dyn Codec> = Rc::new(Encryptor::new(&Config::generate(rng, 1), rng));
        drop(s);
        assert!(kr_store::Store::open_with(&dir, Some(bad)).is_err());
        // plaintext store read with encryption on (upgrade in place), then new writes encrypted
        let dir2 = tmp("up");
        let mut p = kr_store::Store::open(&dir2).unwrap();
        p.create(SK, b"OLDPLAIN".to_vec()).unwrap();
        p.sync().unwrap();
        drop(p);
        let c2: Rc<dyn Codec> = Rc::new(Encryptor::new(&cfg, rng));
        let mut s = kr_store::Store::open_with(&dir2, Some(c2)).unwrap();
        assert_eq!(&*s.get(SK).unwrap().value, b"OLDPLAIN");
        s.update(SK, b"NEWVAL-ENC".to_vec(), None).unwrap();
        s.sync().unwrap();
        let log = std::fs::read(std::format!("{dir2}/log")).unwrap();
        assert!(!log.windows(6).any(|w| w == b"NEWVAL"));
    }

    #[test]
    fn replicated_records_round_trip() {
        let codec: Rc<dyn Codec> = Rc::new(Encryptor::new(&Config::generate(rng, 1), rng));
        let mut a = kr_store::Store::replicated();
        a.set_codec(codec.clone());
        a.create(SK, b"RAFTSECRET".to_vec()).unwrap();
        let rec = a.take_records();
        assert!(!rec.windows(10).any(|w| w == b"RAFTSECRET"));
        let mut b = kr_store::Store::replicated();
        b.set_codec(codec);
        b.apply_records(&rec).unwrap();
        assert_eq!(&*b.get(SK).unwrap().value, b"RAFTSECRET");
        let mut c = kr_store::Store::replicated();
        c.set_codec(Rc::new(Encryptor::new(&Config::generate(rng, 1), rng)));
        assert!(c.apply_records(&rec).is_err());
    }

    #[test]
    fn performance_sanity() {
        let e = Encryptor::new(&Config::generate(rng, 1), rng);
        let v = std::vec![b'x'; 2048];
        let t = std::time::Instant::now();
        for _ in 0..2000 {
            let c = e.encode(SK, &v).unwrap();
            assert_eq!(e.decode(SK, &c).unwrap().unwrap().len(), 2048);
        }
        // Non-secret keys cost one prefix check.
        let t2 = std::time::Instant::now();
        for _ in 0..200_000 {
            assert!(e.encode("/registry/core/pods/default/p", &v).is_none());
        }
        std::eprintln!("2000 x 2KiB enc+dec: {:?}; 200k passthrough: {:?}", t.elapsed(), t2.elapsed());
        assert!(t2.elapsed().as_secs() < 2);
    }
}
