//! Replicated key material (ADR-058, KNOWN_ISSUES #189): the cluster CA files, the
//! service-account keys and the secrets-encryption config travel through the Raft log as one
//! sealed record, like k3s keeps its bootstrap data in the datastore.
//!
//! The record lives at [`KEY`] in the replicated store. Its payload (a list of data-dir
//! relative files) is sealed with AES-256-GCM under a key derived from the server token's
//! secret, so the Raft log, its snapshots and `kr snapshot` store images never hold the CA key
//! or the encryption keys in the clear. Every server runs an applier (in the `kr` binary) that
//! writes the files and reloads what can reload, then acknowledges the generation under
//! [`ACK_PREFIX`]`<id>`. The leader refuses to change the key that Secrets are written with
//! until every voter acknowledged that it can read it ([`check_write_key`]).

use crate::encrypt::Config;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_crypto::aes::AesGcm;
use kr_fmt::json::{self, Value};
use kr_raft::NodeId;

pub const KEY: &str = "/kr/keysync";
pub const ACK_PREFIX: &str = "/kr/keysync-ack/";

/// Files the record may carry (relative to the data dir) and their modes.
pub const FILES: [(&str, u32); 7] = [
    ("pki/ca.pem", 0o644),
    ("pki/ca.key", 0o600),
    ("pki/sa.key", 0o600),
    ("pki/sa-old.pem", 0o600),
    ("node-token", 0o600),
    ("server-token", 0o600),
    (crate::encrypt::FILE, 0o600),
];

pub fn mode_of(file: &str) -> Option<u32> {
    FILES.iter().find(|(f, _)| *f == file).map(|(_, m)| *m)
}

#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    pub gen: u64,
    pub files: Vec<(String, String)>,
}

impl Record {
    pub fn file(&self, name: &str) -> Option<&str> {
        self.files.iter().find(|(f, _)| f == name).map(|(_, c)| c.as_str())
    }
}

fn cipher(secret: &str) -> AesGcm {
    let mut prk = [0u8; 32];
    kr_crypto::hmac::hkdf_extract::<kr_crypto::sha2::Sha256>(b"kr keysync v1", secret.as_bytes(), &mut prk);
    let mut key = [0u8; 32];
    kr_crypto::hmac::hkdf_expand::<kr_crypto::sha2::Sha256>(&prk, &[b"aes-256-gcm"], &mut key);
    let c = AesGcm::new(&key);
    kr_crypto::wipe(&mut key);
    c
}

fn aad(gen: u64) -> String {
    alloc::format!("kr-keysync-v1:{gen}")
}

/// The stored envelope: `{"v":1,"gen":N,"nonce":b64,"ct":b64}` (ciphertext followed by the tag).
pub fn seal(secret: &str, rec: &Record, nonce: [u8; 12]) -> String {
    let files = Value::Object(rec.files.iter().map(|(k, v)| (k.clone(), Value::from(v.as_str()))).collect());
    let mut data = json::to_string(&files).into_bytes();
    let tag = cipher(secret).seal(&nonce, aad(rec.gen).as_bytes(), &mut data);
    data.extend_from_slice(&tag);
    json::to_string(&Value::Object(alloc::vec![
        ("v".to_string(), Value::from(1i64)),
        ("gen".to_string(), Value::from(rec.gen as i64)),
        ("nonce".to_string(), Value::from(kr_fmt::base64::encode(&nonce).as_str())),
        ("ct".to_string(), Value::from(kr_fmt::base64::encode(&data).as_str())),
    ]))
}

/// The generation of a stored envelope without decrypting it.
pub fn gen_of(envelope: &[u8]) -> Option<u64> {
    json::parse(envelope).ok()?.get("gen")?.as_u64()
}

pub fn open(secret: &str, envelope: &[u8]) -> Result<Record, String> {
    let v = json::parse(envelope).map_err(|_| String::from("key-sync record is not JSON"))?;
    let gen = v.get("gen").and_then(Value::as_u64).ok_or("key-sync record without gen")?;
    let nonce: [u8; 12] = kr_fmt::base64::decode(v.get("nonce").and_then(Value::as_str).ok_or("no nonce")?).map_err(|_| "bad nonce")?.try_into().map_err(|_| "bad nonce")?;
    let mut ct = kr_fmt::base64::decode(v.get("ct").and_then(Value::as_str).ok_or("no ct")?).map_err(|_| "bad ct")?;
    if ct.len() < 16 {
        return Err("key-sync record is truncated".into());
    }
    let tag = ct.split_off(ct.len() - 16);
    cipher(secret).open(&nonce, aad(gen).as_bytes(), &mut ct, &tag).map_err(|_| String::from("key-sync record does not open: a different server token?"))?;
    let files = json::parse(&ct).map_err(|_| String::from("key-sync payload is not JSON"))?;
    let Value::Object(fields) = files else { return Err("key-sync payload is not an object".into()) };
    let mut out = Vec::new();
    for (k, v) in fields {
        out.push((k, v.as_str().ok_or("key-sync file is not a string")?.to_string()));
    }
    Ok(Record { gen, files: out })
}

/// The files of the next generation: the previous ones with `upd` laid over them.
pub fn merge(prev: Option<&Record>, upd: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut files = prev.map(|r| r.files.clone()).unwrap_or_default();
    for (k, v) in upd {
        match files.iter_mut().find(|(f, _)| *f == k) {
            Some(e) => e.1 = v,
            None => files.push((k, v)),
        }
    }
    files
}

/// Checks the files of an update before they are replicated.
pub fn validate(files: &[(String, String)]) -> Result<(), String> {
    for (f, c) in files {
        if mode_of(f).is_none() {
            return Err(alloc::format!("{f} is not a replicated file"));
        }
        if c.is_empty() || c.len() > (1 << 20) {
            return Err(alloc::format!("{f} is empty or too large"));
        }
        if f == crate::encrypt::FILE {
            Config::parse(c.as_bytes()).map_err(|e| alloc::format!("{f}: {e}"))?;
        }
        if f.ends_with(".pem") && !c.contains("-----BEGIN ") {
            return Err(alloc::format!("{f} is not PEM"));
        }
    }
    Ok(())
}

/// What a server reports after applying a generation.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Ack {
    pub gen: u64,
    /// Names of the encryption keys this server can read with.
    pub keys: Vec<String>,
    /// The key it writes with (empty: plaintext or no encryption).
    pub writes: String,
    /// Short digests of ca.pem and sa.key, to compare servers.
    pub ca: String,
    pub sa: String,
}

impl Ack {
    pub fn to_json(&self) -> String {
        json::to_string(&Value::Object(alloc::vec![
            ("gen".to_string(), Value::from(self.gen as i64)),
            ("keys".to_string(), Value::Array(self.keys.iter().map(|k| Value::from(k.as_str())).collect())),
            ("writes".to_string(), Value::from(self.writes.as_str())),
            ("ca".to_string(), Value::from(self.ca.as_str())),
            ("sa".to_string(), Value::from(self.sa.as_str())),
        ]))
    }

    pub fn from_json(b: &[u8]) -> Option<Ack> {
        let v = json::parse(b).ok()?;
        let s = |f: &str| v.get(f).and_then(Value::as_str).unwrap_or("").to_string();
        Some(Ack {
            gen: v.get("gen")?.as_u64()?,
            keys: v.get("keys")?.as_array()?.iter().filter_map(|k| k.as_str().map(String::from)).collect(),
            writes: s("writes"),
            ca: s("ca"),
            sa: s("sa"),
        })
    }
}

/// The ordering rule for secrets encryption: a new write key may be published only when every
/// voter has acknowledged a configuration that contains it (so every server can read what the
/// first server to switch will write). No previous configuration: this is the baseline.
pub fn check_write_key(prev: Option<&Config>, next: &Config, voters: &[NodeId], acks: &[(NodeId, Ack)]) -> Result<(), String> {
    let Some(prev) = prev else { return Ok(()) };
    let writes = |c: &Config| if c.identity_first { None } else { c.keys.first().map(|k| k.name.clone()) };
    let Some(w) = writes(next) else { return Ok(()) };
    if writes(prev).as_deref() == Some(w.as_str()) {
        return Ok(());
    }
    let mut missing = Vec::new();
    for v in voters {
        if !acks.iter().any(|(id, a)| id == v && a.keys.iter().any(|k| *k == w)) {
            missing.push(v.to_string());
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(alloc::format!("key {w} cannot become the write key yet: server(s) {} have not acknowledged it as a read key (publish it as a reader first and wait)", missing.join(", ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(gen: u64) -> Record {
        Record { gen, files: alloc::vec![("pki/ca.key".into(), "SECRET\n".into()), ("encryption-config.json".into(), "{}".into())] }
    }

    fn cfg(names: &[&str], identity: bool) -> Config {
        Config { resources: alloc::vec!["secrets".into()], keys: names.iter().map(|n| crate::encrypt::KeyEntry { name: (*n).into(), secret: [1; 32] }).collect(), identity_first: identity }
    }

    #[test]
    fn seal_open_round_trip_and_nothing_in_the_clear() {
        let env = seal("tok", &rec(3), [7; 12]);
        assert!(!env.contains("SECRET") && !env.contains("pki/ca.key"));
        assert_eq!(gen_of(env.as_bytes()), Some(3));
        assert_eq!(open("tok", env.as_bytes()).unwrap(), rec(3));
    }

    #[test]
    fn wrong_token_tampering_and_replayed_generation_fail() {
        let env = seal("tok", &rec(3), [7; 12]);
        assert!(open("other", env.as_bytes()).is_err());
        // A record moved to another generation does not open (the generation is authenticated).
        let moved = env.replace("\"gen\":3", "\"gen\":4");
        assert!(open("tok", moved.as_bytes()).is_err());
        let mut v = json::parse(env.as_bytes()).unwrap();
        let ct = v.get("ct").and_then(Value::as_str).unwrap().to_string();
        let mut raw = kr_fmt::base64::decode(&ct).unwrap();
        raw[0] ^= 1;
        v.set("ct", Value::from(kr_fmt::base64::encode(&raw).as_str()));
        assert!(open("tok", json::to_string(&v).as_bytes()).is_err());
    }

    #[test]
    fn merge_overlays_and_keeps_the_rest() {
        let m = merge(Some(&rec(1)), alloc::vec![("pki/ca.key".into(), "NEW".into()), ("pki/sa.key".into(), "SA".into())]);
        assert_eq!(m.len(), 3);
        assert_eq!(m.iter().find(|(f, _)| f == "pki/ca.key").unwrap().1, "NEW");
        assert_eq!(merge(None, alloc::vec![("node-token".into(), "t".into())]).len(), 1);
    }

    #[test]
    fn validate_rejects_unknown_files_and_bad_config() {
        assert!(validate(&[("../etc/passwd".into(), "x".into())]).is_err());
        assert!(validate(&[("encryption-config.json".into(), "nope".into())]).is_err());
        assert!(validate(&[("pki/ca.pem".into(), "not pem".into())]).is_err());
        assert!(validate(&[("node-token".into(), "K10abc::x.y".into())]).is_ok());
    }

    #[test]
    fn a_new_write_key_needs_every_voter_to_read_it() {
        let ack = |keys: &[&str]| Ack { gen: 1, keys: keys.iter().map(|k| k.to_string()).collect(), ..Ack::default() };
        let prev = cfg(&["a", "b"], false);
        let next = cfg(&["c", "a", "b"], false);
        let voters = [1, 2, 3];
        // Server 3 has not read key c yet.
        let acks = alloc::vec![(1, ack(&["a", "b", "c"])), (2, ack(&["a", "b", "c"])), (3, ack(&["a", "b"]))];
        assert!(check_write_key(Some(&prev), &next, &voters, &acks).unwrap_err().contains("3"));
        // No ack at all counts as not read.
        assert!(check_write_key(Some(&prev), &next, &voters, &acks[..2]).is_err());
        let all = alloc::vec![(1, ack(&["a", "b", "c"])), (2, ack(&["a", "b", "c"])), (3, ack(&["c", "a"]))];
        assert!(check_write_key(Some(&prev), &next, &voters, &all).is_ok());
        // Adding a reader (the write key stays), plaintext, and the baseline are always fine.
        assert!(check_write_key(Some(&prev), &cfg(&["a", "b", "c"], false), &voters, &[]).is_ok());
        assert!(check_write_key(Some(&prev), &cfg(&["c", "a"], true), &voters, &[]).is_ok());
        assert!(check_write_key(None, &next, &voters, &[]).is_ok());
    }

    #[test]
    fn ack_round_trip() {
        let a = Ack { gen: 5, keys: alloc::vec!["k1".into(), "k2".into()], writes: "k1".into(), ca: "ab12".into(), sa: "cd34".into() };
        assert_eq!(Ack::from_json(a.to_json().as_bytes()), Some(a));
    }
}
