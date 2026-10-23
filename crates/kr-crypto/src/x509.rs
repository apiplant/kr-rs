//! X.509 certificates (RFC 5280 subset): parsing, chain verification and issuance.
//!
//! Supported keys and signatures: ECDSA P-256 with SHA-256, and Ed25519. Other algorithms parse
//! but never verify. Parsing is strict DER; unknown *critical* extensions make a certificate
//! unusable, as RFC 5280 requires. Hostname checks use SANs only (no CN fallback, like Go).

use crate::der::{self, Reader};
use crate::{ed25519, p256};
use alloc::string::String;
use alloc::vec::Vec;

pub use crate::der::Error;
type Result<T> = core::result::Result<T, Error>;

// DER-encoded OID contents.
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]; // 1.2.840.10045.2.1
const OID_PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]; // 1.2.840.10045.3.1.7
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]; // 1.2.840.10045.4.3.2
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70]; // 1.3.101.112
const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_O: &[u8] = &[0x55, 0x04, 0x0a];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const OID_EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];
const OID_SKI: &[u8] = &[0x55, 0x1d, 0x0e];
const OID_AKI: &[u8] = &[0x55, 0x1d, 0x23];
const OID_EKU_SERVER: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const OID_EKU_CLIENT: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
const OID_EKU_ANY: &[u8] = &[0x55, 0x1d, 0x25, 0x00];

pub const KU_DIGITAL_SIGNATURE: u16 = 1 << 0;
pub const KU_KEY_ENCIPHERMENT: u16 = 1 << 2;
pub const KU_KEY_CERT_SIGN: u16 = 1 << 5;
pub const KU_CRL_SIGN: u16 = 1 << 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicKey {
    P256([u8; 65]),
    Ed25519([u8; 32]),
}

impl PublicKey {
    /// Verifies `sig` over `msg` using the algorithm matching this key type.
    /// ECDSA signatures are DER-encoded; Ed25519 signatures are raw 64 bytes.
    pub fn verify(&self, alg: SigAlg, msg: &[u8], sig: &[u8]) -> bool {
        match (self, alg) {
            (PublicKey::P256(pk), SigAlg::EcdsaSha256) => p256::sig_from_der(sig).is_some_and(|(r, s)| p256::verify(pk, msg, &r, &s)),
            (PublicKey::Ed25519(pk), SigAlg::Ed25519) => sig.len() == 64 && ed25519::verify(pk, msg, sig.try_into().unwrap()),
            _ => false,
        }
    }

    /// DER SubjectPublicKeyInfo.
    pub fn spki(&self) -> Vec<u8> {
        let mut out = Vec::new();
        der::nested(&mut out, der::SEQUENCE, |o| {
            match self {
                PublicKey::P256(pk) => {
                    der::nested(o, der::SEQUENCE, |a| {
                        der::tlv(a, der::OID, OID_EC_PUBLIC_KEY);
                        der::tlv(a, der::OID, OID_PRIME256V1);
                    });
                    der::bit_string(o, pk);
                }
                PublicKey::Ed25519(pk) => {
                    der::nested(o, der::SEQUENCE, |a| der::tlv(a, der::OID, OID_ED25519));
                    der::bit_string(o, pk);
                }
            }
        });
        out
    }

    pub fn from_spki(spki: &[u8]) -> Result<Option<PublicKey>> {
        let mut r = Reader::new(spki);
        let mut s = r.sequence()?;
        r.finish()?;
        let mut alg = s.sequence()?;
        let oid = alg.oid()?;
        let key = s.bit_string()?;
        s.finish()?;
        Ok(match oid {
            OID_EC_PUBLIC_KEY => {
                if alg.oid()? != OID_PRIME256V1 || key.len() != 65 || key[0] != 4 {
                    return Ok(None);
                }
                Some(PublicKey::P256(key.try_into().unwrap()))
            }
            OID_ED25519 => {
                alg.finish()?; // parameters MUST be absent
                Some(PublicKey::Ed25519(key.try_into().map_err(|_| Error)?))
            }
            _ => None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigAlg {
    EcdsaSha256,
    Ed25519,
    Unsupported,
}

fn parse_sig_alg(r: &mut Reader) -> Result<SigAlg> {
    let mut a = r.sequence()?;
    let oid = a.oid()?;
    let alg = match oid {
        OID_ECDSA_SHA256 => SigAlg::EcdsaSha256,
        OID_ED25519 => SigAlg::Ed25519,
        _ => return Ok(SigAlg::Unsupported), // may carry parameters; not inspected
    };
    a.finish()?; // both supported algorithms have absent parameters
    Ok(alg)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Eku {
    pub server: bool,
    pub client: bool,
    pub any: bool,
    /// The extension was present (absence means "any purpose").
    pub present: bool,
}

#[derive(Debug, Clone)]
pub struct Certificate<'a> {
    pub raw: &'a [u8],
    pub tbs: &'a [u8],
    pub sig_alg: SigAlg,
    pub signature: &'a [u8],
    pub serial: &'a [u8],
    /// DER of the issuer and subject Names (compared byte-wise for chaining).
    pub issuer: &'a [u8],
    pub subject: &'a [u8],
    pub not_before: i64,
    pub not_after: i64,
    pub public_key: Option<PublicKey>,
    pub is_ca: bool,
    pub path_len: Option<u64>,
    pub key_usage: Option<u16>,
    pub eku: Eku,
    pub dns_names: Vec<&'a [u8]>,
    pub ip_addrs: Vec<&'a [u8]>,
}

impl<'a> Certificate<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Certificate<'a>> {
        let mut outer = Reader::new(raw);
        let (body, full) = outer.read_full(der::SEQUENCE)?;
        outer.finish()?;
        let mut c = Reader::new(body);
        let (tbs_body, tbs) = c.read_full(der::SEQUENCE)?;
        let sig_alg = parse_sig_alg(&mut c)?;
        let signature = c.bit_string()?;
        c.finish()?;

        let mut t = Reader::new(tbs_body);
        let version = match t.optional(der::ctx(0))? {
            Some(v) => {
                let mut vr = Reader::new(v);
                let n = vr.small_uint()?;
                vr.finish()?;
                n
            }
            None => 0,
        };
        if version != 2 {
            return Err(Error); // only v3 certificates
        }
        let serial = t.integer()?;
        let inner_alg = parse_sig_alg(&mut t)?;
        if inner_alg != sig_alg {
            return Err(Error);
        }
        let (_, issuer) = t.read_full(der::SEQUENCE)?;
        let mut validity = t.sequence()?;
        let not_before = parse_time(&mut validity)?;
        let not_after = parse_time(&mut validity)?;
        validity.finish()?;
        let (_, subject) = t.read_full(der::SEQUENCE)?;
        let (_, spki) = t.read_full(der::SEQUENCE)?;
        let public_key = PublicKey::from_spki(spki)?;
        // issuerUniqueID [1], subjectUniqueID [2]: skip if present.
        t.optional(der::ctx_prim(1))?;
        t.optional(der::ctx_prim(2))?;
        let mut cert = Certificate {
            raw: full,
            tbs,
            sig_alg,
            signature,
            serial,
            issuer,
            subject,
            not_before,
            not_after,
            public_key,
            is_ca: false,
            path_len: None,
            key_usage: None,
            eku: Eku::default(),
            dns_names: Vec::new(),
            ip_addrs: Vec::new(),
        };
        if let Some(exts) = t.optional(der::ctx(3))? {
            let mut er = Reader::new(exts);
            let mut list = er.sequence()?;
            er.finish()?;
            let mut seen: Vec<&[u8]> = Vec::new();
            while !list.is_empty() {
                let mut e = list.sequence()?;
                let oid = e.oid()?;
                if seen.contains(&oid) {
                    return Err(Error); // duplicate extension
                }
                seen.push(oid);
                let critical = if e.peek_tag() == Some(der::BOOLEAN) { e.boolean()? } else { false };
                let value = e.read(der::OCTET_STRING)?;
                e.finish()?;
                cert.extension(oid, critical, value)?;
            }
        }
        t.finish()?;
        Ok(cert)
    }

    fn extension(&mut self, oid: &[u8], critical: bool, value: &'a [u8]) -> Result<()> {
        let mut r = Reader::new(value);
        match oid {
            OID_BASIC_CONSTRAINTS => {
                let mut s = r.sequence()?;
                if s.peek_tag() == Some(der::BOOLEAN) {
                    self.is_ca = s.boolean()?;
                }
                if s.peek_tag() == Some(der::INTEGER) {
                    self.path_len = Some(s.small_uint()?);
                }
                s.finish()?;
            }
            OID_KEY_USAGE => {
                let v = r.read(der::BIT_STRING)?;
                if v.is_empty() || v.len() > 3 || v[0] > 7 {
                    return Err(Error);
                }
                // Bit 0 is the MSB of the first byte.
                let mut bits = 0u16;
                for (i, &b) in v[1..].iter().enumerate() {
                    for j in 0..8 {
                        if b & (0x80 >> j) != 0 {
                            bits |= 1 << (8 * i + j);
                        }
                    }
                }
                self.key_usage = Some(bits);
            }
            OID_EXT_KEY_USAGE => {
                let mut s = r.sequence()?;
                self.eku.present = true;
                while !s.is_empty() {
                    match s.oid()? {
                        OID_EKU_SERVER => self.eku.server = true,
                        OID_EKU_CLIENT => self.eku.client = true,
                        OID_EKU_ANY => self.eku.any = true,
                        _ => {}
                    }
                }
            }
            OID_SAN => {
                let mut s = r.sequence()?;
                while !s.is_empty() {
                    let (tag, v, _) = s.any()?;
                    match tag {
                        t if t == der::ctx_prim(2) => self.dns_names.push(v),
                        t if t == der::ctx_prim(7) => {
                            if v.len() != 4 && v.len() != 16 {
                                return Err(Error);
                            }
                            self.ip_addrs.push(v)
                        }
                        _ => {}
                    }
                }
            }
            OID_SKI | OID_AKI => return Ok(()), // informational only
            _ if critical => return Err(Error), // unknown critical extension
            _ => return Ok(()),
        }
        r.finish()
    }

    /// Values of a given attribute in the subject (e.g. CN, O), as raw string bytes.
    fn subject_attrs(&self, want: &[u8]) -> Vec<&'a [u8]> {
        let mut out = Vec::new();
        let Ok(mut name) = Reader::new(self.subject).sequence() else { return out };
        while let Ok(rdn) = name.read(der::SET) {
            let mut rdn = Reader::new(rdn);
            while let Ok(mut atv) = rdn.sequence() {
                if let (Ok(oid), Ok((tag, v, _))) = (atv.oid(), atv.any()) {
                    if oid == want && matches!(tag, der::UTF8_STRING | der::PRINTABLE_STRING | der::IA5_STRING) {
                        out.push(v);
                    }
                }
            }
        }
        out
    }

    pub fn common_name(&self) -> Option<&'a [u8]> {
        self.subject_attrs(OID_CN).first().copied()
    }

    pub fn organizations(&self) -> Vec<&'a [u8]> {
        self.subject_attrs(OID_O)
    }

    /// True when `issuer`'s key signed this certificate.
    pub fn signed_by(&self, issuer: &PublicKey) -> bool {
        issuer.verify(self.sig_alg, self.tbs, self.signature)
    }

    /// RFC 6125-style host match against DNS SANs (one leftmost `*` label) or IP SANs.
    pub fn matches_host(&self, host: &[u8]) -> bool {
        if let Some(ip) = parse_ip(host) {
            return self.ip_addrs.iter().any(|a| *a == &ip[..]);
        }
        let host = trim_dot(host);
        self.dns_names.iter().any(|pat| {
            let pat = trim_dot(pat);
            if let Some(rest) = pat.strip_prefix(b"*.") {
                match host.iter().position(|&b| b == b'.') {
                    Some(i) => i > 0 && eq_ignore_case(&host[i + 1..], rest) && rest.contains(&b'.'),
                    None => false,
                }
            } else {
                eq_ignore_case(pat, host)
            }
        })
    }
}

fn trim_dot(s: &[u8]) -> &[u8] {
    s.strip_suffix(b".").unwrap_or(s)
}

fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// Dotted IPv4 or a literal IPv6 (full or `::`-compressed) into 4/16 bytes.
pub fn parse_ip(s: &[u8]) -> Option<Vec<u8>> {
    if s.contains(&b':') {
        let s = core::str::from_utf8(s).ok()?.trim_start_matches('[').trim_end_matches(']');
        let (head, tail) = match s.find("::") {
            Some(i) => (&s[..i], Some(&s[i + 2..])),
            None => (s, None),
        };
        let parse = |p: &str| -> Option<Vec<u16>> {
            if p.is_empty() {
                return Some(Vec::new());
            }
            p.split(':').map(|g| if g.len() <= 4 { u16::from_str_radix(g, 16).ok() } else { None }).collect()
        };
        let (h, t) = (parse(head)?, tail.map(parse).unwrap_or(Some(Vec::new()))?);
        let groups = match tail {
            None if h.len() == 8 => h,
            Some(_) if h.len() + t.len() < 8 => {
                let mut g = h;
                g.resize(8 - t.len(), 0);
                g.extend(t);
                g
            }
            _ => return None,
        };
        return Some(groups.iter().flat_map(|g| g.to_be_bytes()).collect());
    }
    let mut out = Vec::with_capacity(4);
    for part in s.split(|&b| b == b'.') {
        if part.is_empty() || part.len() > 3 || !part.iter().all(u8::is_ascii_digit) || (part.len() > 1 && part[0] == b'0') {
            return None;
        }
        let v = part.iter().fold(0u32, |a, &d| a * 10 + (d - b'0') as u32);
        out.push(u8::try_from(v).ok()?);
    }
    (out.len() == 4).then_some(out)
}

// ---- time ----

/// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + (m <= 2) as i64, m, d)
}

fn digits(b: &[u8]) -> Result<i64> {
    if b.is_empty() || !b.iter().all(u8::is_ascii_digit) {
        return Err(Error);
    }
    Ok(b.iter().fold(0i64, |a, &d| a * 10 + (d - b'0') as i64))
}

/// UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ) to Unix seconds.
fn parse_time(r: &mut Reader) -> Result<i64> {
    let (tag, v, _) = r.any()?;
    let (year, rest) = match (tag, v.len()) {
        (der::UTC_TIME, 13) => {
            let yy = digits(&v[..2])?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &v[2..])
        }
        (der::GENERALIZED_TIME, 15) => (digits(&v[..4])?, &v[4..]),
        _ => return Err(Error),
    };
    if rest[10] != b'Z' {
        return Err(Error);
    }
    let (mo, d, h, mi, s) = (digits(&rest[0..2])?, digits(&rest[2..4])?, digits(&rest[4..6])?, digits(&rest[6..8])?, digits(&rest[8..10])?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 59 {
        return Err(Error);
    }
    Ok(days_from_civil(year, mo, d) * 86400 + h * 3600 + mi * 60 + s)
}

fn write_time(out: &mut Vec<u8>, t: i64) {
    let (y, m, d) = civil_from_days(t.div_euclid(86400));
    let secs = t.rem_euclid(86400);
    let mut s = String::new();
    let two = |s: &mut String, v: i64| {
        s.push((b'0' + (v / 10 % 10) as u8) as char);
        s.push((b'0' + (v % 10) as u8) as char);
    };
    let tag = if (1950..2050).contains(&y) {
        two(&mut s, y % 100);
        der::UTC_TIME
    } else {
        two(&mut s, y / 100);
        two(&mut s, y % 100);
        der::GENERALIZED_TIME
    };
    for v in [m, d, secs / 3600, secs / 60 % 60, secs % 60] {
        two(&mut s, v);
    }
    s.push('Z');
    der::tlv(out, tag, s.as_bytes());
}

// ---- verification ----

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Usage<'h> {
    /// A server certificate presented for `host` (DNS name or IP literal).
    Server(&'h [u8]),
    Client,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    Parse,
    Expired,
    UnknownIssuer,
    BadSignature,
    NotCa,
    Usage,
    HostMismatch,
    UnsupportedKey,
}

/// Verifies `chain[0]` (leaf) up to one of `roots` (DER), using `chain[1..]` as intermediates.
/// Roots are trust anchors: their own signature and validity are checked only for expiry.
pub fn verify_chain(chain: &[&[u8]], roots: &[&[u8]], now: i64, usage: Usage) -> core::result::Result<(), VerifyError> {
    const MAX_DEPTH: usize = 5;
    let leaf_der = chain.first().ok_or(VerifyError::Parse)?;
    let leaf = Certificate::parse(leaf_der).map_err(|_| VerifyError::Parse)?;
    let pool: Vec<Certificate> = chain[1..].iter().filter_map(|c| Certificate::parse(c).ok()).collect();
    let anchors: Vec<Certificate> = roots.iter().filter_map(|c| Certificate::parse(c).ok()).collect();

    let in_time = |c: &Certificate| c.not_before <= now && now <= c.not_after;
    if !in_time(&leaf) {
        return Err(VerifyError::Expired);
    }
    match usage {
        Usage::Server(host) => {
            if leaf.eku.present && !(leaf.eku.server || leaf.eku.any) {
                return Err(VerifyError::Usage);
            }
            if !leaf.matches_host(host) {
                return Err(VerifyError::HostMismatch);
            }
        }
        Usage::Client => {
            if leaf.eku.present && !(leaf.eku.client || leaf.eku.any) {
                return Err(VerifyError::Usage);
            }
        }
    }
    if leaf.key_usage.is_some_and(|ku| ku & KU_DIGITAL_SIGNATURE == 0) {
        return Err(VerifyError::Usage);
    }
    leaf.public_key.ok_or(VerifyError::UnsupportedKey)?;

    let mut cur = leaf;
    for depth in 0..MAX_DEPTH {
        // Is `cur` signed by a trust anchor?
        for a in &anchors {
            if a.subject == cur.issuer && a.public_key.is_some_and(|k| cur.signed_by(&k)) {
                if !in_time(a) {
                    return Err(VerifyError::Expired);
                }
                check_ca(a, depth)?;
                return Ok(());
            }
        }
        // Otherwise step to an intermediate.
        let next = pool
            .iter()
            .find(|c| c.subject == cur.issuer && c.public_key.is_some_and(|k| cur.signed_by(&k)))
            .ok_or(VerifyError::UnknownIssuer)?;
        if !in_time(next) {
            return Err(VerifyError::Expired);
        }
        check_ca(next, depth)?;
        cur = next.clone();
    }
    Err(VerifyError::UnknownIssuer)
}

/// `depth` = number of intermediates below this CA in the path.
fn check_ca(ca: &Certificate, depth: usize) -> core::result::Result<(), VerifyError> {
    if !ca.is_ca || ca.key_usage.is_some_and(|ku| ku & KU_KEY_CERT_SIGN == 0) {
        return Err(VerifyError::NotCa);
    }
    if ca.path_len.is_some_and(|p| (depth as u64) > p) {
        return Err(VerifyError::NotCa);
    }
    Ok(())
}

// ---- issuance ----

/// A signing key for issuing certificates (and for TLS CertificateVerify).
pub enum SigningKey {
    P256(p256::SecretKey),
    Ed25519(ed25519::SigningKey),
}

impl SigningKey {
    pub fn public(&self) -> PublicKey {
        match self {
            SigningKey::P256(k) => PublicKey::P256(k.public_key()),
            SigningKey::Ed25519(k) => PublicKey::Ed25519(k.public_key()),
        }
    }

    pub fn sig_alg(&self) -> SigAlg {
        match self {
            SigningKey::P256(_) => SigAlg::EcdsaSha256,
            SigningKey::Ed25519(_) => SigAlg::Ed25519,
        }
    }

    /// Signature in X.509/TLS wire form (DER for ECDSA, raw for Ed25519).
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            SigningKey::P256(k) => {
                let (r, s) = k.sign(msg);
                p256::sig_to_der(&r, &s)
            }
            SigningKey::Ed25519(k) => k.sign(msg).to_vec(),
        }
    }
}

/// Key identifier: SHA-256 of the subjectPublicKey bits, truncated to 160 bits (RFC 7093).
fn key_id(k: &PublicKey) -> [u8; 20] {
    let bits: &[u8] = match k {
        PublicKey::P256(b) => b,
        PublicKey::Ed25519(b) => b,
    };
    crate::sha2::sha256(bits)[..20].try_into().unwrap()
}

fn write_sig_alg(out: &mut Vec<u8>, alg: SigAlg) {
    der::nested(out, der::SEQUENCE, |a| {
        der::tlv(a, der::OID, if alg == SigAlg::Ed25519 { OID_ED25519 } else { OID_ECDSA_SHA256 });
    });
}

/// A distinguished name: CN plus zero or more O values (Kubernetes uses O for groups).
#[derive(Clone, Debug, Default)]
pub struct Name {
    pub common_name: String,
    pub organizations: Vec<String>,
}

impl Name {
    pub fn to_der(&self) -> Vec<u8> {
        let mut out = Vec::new();
        der::nested(&mut out, der::SEQUENCE, |n| {
            for o in &self.organizations {
                der::nested(n, der::SET, |s| {
                    der::nested(s, der::SEQUENCE, |a| {
                        der::tlv(a, der::OID, OID_O);
                        der::tlv(a, der::UTF8_STRING, o.as_bytes());
                    })
                });
            }
            der::nested(n, der::SET, |s| {
                der::nested(s, der::SEQUENCE, |a| {
                    der::tlv(a, der::OID, OID_CN);
                    der::tlv(a, der::UTF8_STRING, self.common_name.as_bytes());
                })
            });
        });
        out
    }
}

/// Parameters for a new certificate.
pub struct CertParams {
    /// 1..=20 bytes; use random bytes (the top bit is cleared to keep it positive).
    pub serial: [u8; 16],
    pub subject: Name,
    pub not_before: i64,
    pub not_after: i64,
    pub is_ca: bool,
    pub server: bool,
    pub client: bool,
    pub dns_names: Vec<String>,
    pub ip_addrs: Vec<Vec<u8>>,
    pub public_key: PublicKey,
}

/// Issues a certificate signed by `issuer_key`. For a self-signed CA, pass its own Name.
pub fn issue(p: &CertParams, issuer: &Name, issuer_key: &SigningKey) -> Vec<u8> {
    let alg = issuer_key.sig_alg();
    let mut tbs = Vec::new();
    der::nested(&mut tbs, der::SEQUENCE, |t| {
        der::nested(t, der::ctx(0), |v| der::uint(v, &[2]));
        let mut serial = p.serial;
        serial[0] &= 0x7f;
        serial[0] |= 0x40; // fixed length, positive, never zero
        der::uint(t, &serial);
        write_sig_alg(t, alg);
        t.extend_from_slice(&issuer.to_der());
        der::nested(t, der::SEQUENCE, |v| {
            write_time(v, p.not_before);
            write_time(v, p.not_after);
        });
        t.extend_from_slice(&p.subject.to_der());
        t.extend_from_slice(&p.public_key.spki());
        der::nested(t, der::ctx(3), |e| {
            der::nested(e, der::SEQUENCE, |list| {
                let ext = |list: &mut Vec<u8>, oid: &[u8], critical: bool, value: Vec<u8>| {
                    der::nested(list, der::SEQUENCE, |x| {
                        der::tlv(x, der::OID, oid);
                        if critical {
                            der::tlv(x, der::BOOLEAN, &[0xff]);
                        }
                        der::tlv(x, der::OCTET_STRING, &value);
                    });
                };
                // keyUsage: CA -> keyCertSign|cRLSign (bits 5,6); leaf -> digitalSignature (bit 0)
                let ku = if p.is_ca { [0x01, 0x06] } else { [0x07, 0x80] }; // [unused bits, bits]
                let mut v = Vec::new();
                der::tlv(&mut v, der::BIT_STRING, &ku);
                ext(list, OID_KEY_USAGE, true, v);
                let mut v = Vec::new();
                der::nested(&mut v, der::SEQUENCE, |b| {
                    if p.is_ca {
                        der::tlv(b, der::BOOLEAN, &[0xff]);
                    }
                });
                ext(list, OID_BASIC_CONSTRAINTS, true, v);
                if p.server || p.client {
                    let mut v = Vec::new();
                    der::nested(&mut v, der::SEQUENCE, |s| {
                        if p.server {
                            der::tlv(s, der::OID, OID_EKU_SERVER);
                        }
                        if p.client {
                            der::tlv(s, der::OID, OID_EKU_CLIENT);
                        }
                    });
                    ext(list, OID_EXT_KEY_USAGE, false, v);
                }
                // Key identifiers (RFC 7093 method 1: leftmost 160 bits of SHA-256 of the key).
                let mut v = Vec::new();
                der::tlv(&mut v, der::OCTET_STRING, &key_id(&p.public_key));
                ext(list, OID_SKI, false, v);
                let mut v = Vec::new();
                der::nested(&mut v, der::SEQUENCE, |a| der::tlv(a, der::ctx_prim(0), &key_id(&issuer_key.public())));
                ext(list, OID_AKI, false, v);
                if !p.dns_names.is_empty() || !p.ip_addrs.is_empty() {
                    let mut v = Vec::new();
                    der::nested(&mut v, der::SEQUENCE, |s| {
                        for d in &p.dns_names {
                            der::tlv(s, der::ctx_prim(2), d.as_bytes());
                        }
                        for ip in &p.ip_addrs {
                            der::tlv(s, der::ctx_prim(7), ip);
                        }
                    });
                    ext(list, OID_SAN, false, v);
                }
            });
        });
    });
    let sig = issuer_key.sign(&tbs);
    let mut cert = Vec::new();
    der::nested(&mut cert, der::SEQUENCE, |c| {
        c.extend_from_slice(&tbs);
        write_sig_alg(c, alg);
        der::bit_string(c, &sig);
    });
    cert
}

// ---- PEM ----

/// Encodes DER as PEM with the given label ("CERTIFICATE", "PRIVATE KEY", ...).
pub fn pem_encode(label: &str, der: &[u8]) -> String {
    let b64 = kr_fmt::base64::encode(der);
    let mut s = String::with_capacity(b64.len() + b64.len() / 64 + 64);
    s.push_str("-----BEGIN ");
    s.push_str(label);
    s.push_str("-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        s.push_str(core::str::from_utf8(chunk).unwrap());
        s.push('\n');
    }
    s.push_str("-----END ");
    s.push_str(label);
    s.push_str("-----\n");
    s
}

/// All PEM blocks with `label`, decoded (others are skipped; malformed ones are errors).
pub fn pem_decode_all(text: &str, label: &str) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut rest = text;
    let begin = alloc::format!("-----BEGIN {label}-----");
    let end = alloc::format!("-----END {label}-----");
    while let Some(i) = rest.find(&begin) {
        let after = &rest[i + begin.len()..];
        let j = after.find(&end).ok_or(Error)?;
        let body: String = after[..j].chars().filter(|c| !c.is_ascii_whitespace()).collect();
        out.push(kr_fmt::base64::decode(&body).map_err(|_| Error)?);
        rest = &after[j + end.len()..];
    }
    Ok(out)
}

// ---- private keys (PKCS#8 for both types; also SEC1 "EC PRIVATE KEY" on input) ----

/// PKCS#8 PrivateKeyInfo DER.
pub fn private_key_to_pkcs8(k: &SigningKey) -> Vec<u8> {
    let mut out = Vec::new();
    der::nested(&mut out, der::SEQUENCE, |s| {
        der::uint(s, &[0]);
        match k {
            SigningKey::P256(sk) => {
                der::nested(s, der::SEQUENCE, |a| {
                    der::tlv(a, der::OID, OID_EC_PUBLIC_KEY);
                    der::tlv(a, der::OID, OID_PRIME256V1);
                });
                let mut ec = Vec::new();
                der::nested(&mut ec, der::SEQUENCE, |e| {
                    der::uint(e, &[1]);
                    der::tlv(e, der::OCTET_STRING, &sk.to_bytes());
                    der::nested(e, der::ctx(1), |p| der::bit_string(p, &sk.public_key()));
                });
                der::tlv(s, der::OCTET_STRING, &ec);
            }
            SigningKey::Ed25519(sk) => {
                der::nested(s, der::SEQUENCE, |a| der::tlv(a, der::OID, OID_ED25519));
                let mut inner = Vec::new();
                der::tlv(&mut inner, der::OCTET_STRING, sk.seed());
                der::tlv(s, der::OCTET_STRING, &inner);
            }
        }
    });
    out
}

fn sec1_scalar(der_bytes: &[u8]) -> Result<[u8; 32]> {
    let mut r = Reader::new(der_bytes);
    let mut s = r.sequence()?;
    if s.small_uint()? != 1 {
        return Err(Error);
    }
    let d = s.read(der::OCTET_STRING)?;
    d.try_into().map_err(|_| Error)
}

pub fn private_key_from_pkcs8(der_bytes: &[u8]) -> Result<SigningKey> {
    let mut r = Reader::new(der_bytes);
    let mut s = r.sequence()?;
    r.finish()?;
    if s.small_uint()? != 0 {
        return Err(Error);
    }
    let mut alg = s.sequence()?;
    let oid = alg.oid()?;
    let key = s.read(der::OCTET_STRING)?;
    match oid {
        OID_EC_PUBLIC_KEY => {
            if alg.oid()? != OID_PRIME256V1 {
                return Err(Error);
            }
            p256::SecretKey::from_bytes(&sec1_scalar(key)?).map(SigningKey::P256).ok_or(Error)
        }
        OID_ED25519 => {
            let mut k = Reader::new(key);
            let seed: [u8; 32] = k.read(der::OCTET_STRING)?.try_into().map_err(|_| Error)?;
            Ok(SigningKey::Ed25519(ed25519::SigningKey::from_seed(&seed)))
        }
        _ => Err(Error),
    }
}

/// SEC1 `EC PRIVATE KEY` (as written by `openssl ecparam -genkey`), P-256 only.
pub fn private_key_from_sec1(der_bytes: &[u8]) -> Result<SigningKey> {
    p256::SecretKey::from_bytes(&sec1_scalar(der_bytes)?).map(SigningKey::P256).ok_or(Error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_roundtrip() {
        for t in [0i64, 951782400, 2524608000, 4102444799, -86400] {
            let (y, m, d) = civil_from_days(t.div_euclid(86400));
            assert_eq!(days_from_civil(y, m, d) * 86400 + t.rem_euclid(86400), t);
        }
        assert_eq!(days_from_civil(2000, 3, 1), 11017);
    }

    #[test]
    fn ip_parsing() {
        assert_eq!(parse_ip(b"10.0.0.1"), Some(alloc::vec![10, 0, 0, 1]));
        assert_eq!(parse_ip(b"10.0.0.01"), None);
        assert_eq!(parse_ip(b"256.0.0.1"), None);
        assert_eq!(parse_ip(b"::1").unwrap()[15], 1);
        assert_eq!(parse_ip(b"fe80::1:2").unwrap()[..2], [0xfe, 0x80]);
        assert_eq!(parse_ip(b"1:2:3:4:5:6:7:8:9"), None);
        assert_eq!(parse_ip(b"kubernetes.default"), None);
    }
}
