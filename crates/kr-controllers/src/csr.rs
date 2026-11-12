//! CertificateSigningRequest approver and signer.
//!
//! # Approval
//! Only two kinds of request are approved automatically, and only when the requestor *is the
//! node itself* (`username: system:node:<n>` in group `system:nodes`):
//!
//! * `kubernetes.io/kube-apiserver-client-kubelet`: CN equals the username, `O=system:nodes`, no
//!   SANs, usages within {digital signature, key encipherment, client auth} including client auth.
//! * `kubernetes.io/kubelet-serving`: CN equals the username, `O=system:nodes`, only DNS and IP
//!   SANs (at least one), every one of them an address or name of the Node object `<n>`, usages
//!   within {digital signature, key encipherment, server auth} including server auth.
//!
//! Everything else stays Pending for a human (`kubectl certificate approve`, the `approval`
//! subresource).
//!
//! # Signing
//! Approved requests (by this controller or by a human) of the four built-in signers
//! (`kube-apiserver-client`, `kube-apiserver-client-kubelet`, `kubelet-serving`, `legacy-unknown`)
//! are signed with the cluster CA ([`CaSigner`], supplied by the caller) and get
//! `status.certificate` (base64 of the PEM chain). An unapproved, denied or failed request is never
//! signed. A request that cannot be signed (bad PKCS#10, bad signature, unsupported key, usages or
//! subject that the signer does not allow) gets a `Failed` condition. The two kubelet signers
//! also enforce their subject rules for human-approved requests. Certificates last
//! `expirationSeconds` (default and maximum: one year).
//!
//! Only P-256 and Ed25519 request keys are supported (what kr-crypto verifies).

use crate::util::*;
use crate::Config;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_apiserver::client::{Client, Result};
use kr_crypto::der::{self, Reader};
use kr_crypto::rsa::HashAlg;
use kr_crypto::x509::{self, CertParams, Name, PublicKey, SigAlg, SigningKey};
use kr_fmt::json::Value;

const KUBELET_SERVING: &str = "kubernetes.io/kubelet-serving";
const KUBELET_CLIENT: &str = "kubernetes.io/kube-apiserver-client-kubelet";
const API_CLIENT: &str = "kubernetes.io/kube-apiserver-client";
const LEGACY: &str = "kubernetes.io/legacy-unknown";
const NODE_PREFIX: &str = "system:node:";
const NODES_GROUP: &str = "system:nodes";
const MAX_LIFETIME: i64 = 365 * 86400;
const BASE: &str = "/apis/certificates.k8s.io/v1/certificatesigningrequests";

/// The cluster CA the signer issues with.
pub struct CaSigner {
    pub name: Name,
    pub key: SigningKey,
    /// Fills the certificate serial numbers.
    pub rng: fn(&mut [u8]),
}

pub async fn run<C: Client + Clone + 'static>(c: C, cfg: Config, ca: Rc<CaSigner>) {
    let q = Queue::new();
    let mut g = Guard::default();
    let q2 = q.clone();
    g.0.push(kr_rt::exec::spawn(watch_loop(c.clone(), BASE.to_string(), String::new(), cfg, move |_, o| q2.add(&key_of(o)))));
    let (c2, c3, q3) = (c.clone(), c.clone(), q.clone());
    drive(
        &cfg,
        &q,
        move |key| {
            let (c, ca) = (c2.clone(), ca.clone());
            async move { reconcile(&c, &ca, &key, (cfg.now)()).await.map(|r| r.then_some(cfg.retry_ms)) }
        },
        move || {
            let (c, q) = (c3.clone(), q3.clone());
            async move {
                if let Ok(l) = c.list(BASE, "").await {
                    let now = (cfg.now)();
                    for r in items(&l) {
                        if expired(&r, now) {
                            let _ = c.delete(&alloc::format!("{BASE}/{}", str_at(&r, &["metadata", "name"]))).await;
                        } else if str_at(&r, &["status", "certificate"]).is_empty() {
                            q.add(&key_of(&r));
                        }
                    }
                }
            }
        },
    )
    .await
}

// ---- garbage collection ----

const HOUR: i64 = 3600;

/// Upstream's CSR cleaner: a request is deleted one hour after it was issued, denied or failed
/// (or approved without ever being issued), and 24 hours after it was created if nobody decided
/// it.
pub fn expired(csr: &Value, now: i64) -> bool {
    let created = parse_time(str_at(csr, &["metadata", "creationTimestamp"])).unwrap_or(now);
    let cond_time = |ty: &str| {
        csr.pointer(&["status", "conditions"]).and_then(Value::as_array).unwrap_or(&[]).iter().filter(|c| str_at(c, &["type"]) == ty && str_at(c, &["status"]) != "False").filter_map(|c| parse_time(str_at(c, &["lastUpdateTime"])).or_else(|| parse_time(str_at(c, &["lastTransitionTime"])))).max()
    };
    let past = |t: i64, secs: i64| now - t >= secs;
    if !str_at(csr, &["status", "certificate"]).is_empty() {
        return past(created, HOUR);
    }
    if let Some(t) = cond_time("Denied").or_else(|| cond_time("Failed")) {
        return past(t, HOUR);
    }
    if let Some(t) = cond_time("Approved") {
        return past(t, HOUR); // approved, never issued
    }
    past(created, 24 * HOUR)
}

// ---- PKCS#10 ----

/// What the signer needs from a certification request.
#[derive(Debug)]
pub struct Request {
    pub cn: String,
    pub orgs: Vec<String>,
    pub key: PublicKey,
    pub dns: Vec<String>,
    pub ips: Vec<Vec<u8>>,
    /// A SAN other than DNS or IP (email, URI, ...): never issued.
    pub other_san: bool,
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// Parses a DER PKCS#10 request and verifies its self-signature.
pub fn parse_request(raw: &[u8]) -> core::result::Result<Request, &'static str> {
    const BAD: &str = "malformed certification request";
    const EXT_REQ: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e];
    const CN: &[u8] = &[0x55, 0x04, 0x03];
    const ORG: &[u8] = &[0x55, 0x04, 0x0a];
    const SAN: &[u8] = &[0x55, 0x1d, 0x11];
    let mut top = Reader::new(raw);
    let mut seq = top.sequence().map_err(|_| BAD)?;
    top.finish().map_err(|_| BAD)?;
    let (_, info_body, info_full) = seq.any().map_err(|_| BAD)?;
    let mut alg = seq.sequence().map_err(|_| BAD)?;
    let alg_oid = alg.oid().map_err(|_| BAD)?;
    let sig = seq.bit_string().map_err(|_| BAD)?;
    seq.finish().map_err(|_| BAD)?;
    let mut info = Reader::new(info_body);
    if info.small_uint().map_err(|_| BAD)? != 0 {
        return Err(BAD);
    }
    let mut subject = info.sequence().map_err(|_| BAD)?;
    let (_, _, spki) = info.any().map_err(|_| BAD)?;
    let attrs = info.optional(der::ctx(0)).map_err(|_| BAD)?;
    info.finish().map_err(|_| BAD)?;
    let key = PublicKey::from_spki(spki).map_err(|_| BAD)?.ok_or("unsupported public key")?;
    let sig_alg = match (&key, alg_oid) {
        (PublicKey::P256(_), [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]) => SigAlg::Ecdsa(HashAlg::Sha256),
        (PublicKey::Ed25519(_), [0x2b, 0x65, 0x70]) => SigAlg::Ed25519,
        _ => return Err("unsupported key or signature algorithm"),
    };
    if !key.verify(sig_alg, info_full, sig) {
        return Err("invalid request signature");
    }
    let mut req = Request { cn: String::new(), orgs: Vec::new(), key, dns: Vec::new(), ips: Vec::new(), other_san: false };
    let mut have_cn = false;
    while !subject.is_empty() {
        let mut rdn = Reader::new(subject.read(der::SET).map_err(|_| BAD)?);
        while !rdn.is_empty() {
            let mut atv = rdn.sequence().map_err(|_| BAD)?;
            let oid = atv.oid().map_err(|_| BAD)?;
            let (_, val, _) = atv.any().map_err(|_| BAD)?;
            match oid {
                CN if !have_cn => {
                    req.cn = lossy(val);
                    have_cn = true;
                }
                ORG => req.orgs.push(lossy(val)),
                _ => {}
            }
        }
    }
    let mut attrs = Reader::new(attrs.unwrap_or(&[]));
    while !attrs.is_empty() {
        let mut a = attrs.sequence().map_err(|_| BAD)?;
        let oid = a.oid().map_err(|_| BAD)?;
        let vals = a.read(der::SET).map_err(|_| BAD)?;
        if oid != EXT_REQ {
            continue;
        }
        let mut exts = Reader::new(vals).sequence().map_err(|_| BAD)?;
        while !exts.is_empty() {
            let mut e = exts.sequence().map_err(|_| BAD)?;
            let eoid = e.oid().map_err(|_| BAD)?;
            e.optional(der::BOOLEAN).map_err(|_| BAD)?;
            let val = e.read(der::OCTET_STRING).map_err(|_| BAD)?;
            if eoid != SAN {
                continue;
            }
            let mut names = Reader::new(val).sequence().map_err(|_| BAD)?;
            while !names.is_empty() {
                match names.any().map_err(|_| BAD)? {
                    (0x82, d, _) => req.dns.push(lossy(d)),
                    (0x87, ip, _) if ip.len() == 4 || ip.len() == 16 => req.ips.push(ip.to_vec()),
                    _ => req.other_san = true,
                }
            }
        }
    }
    Ok(req)
}

fn ip_string(ip: &[u8]) -> String {
    if ip.len() == 4 {
        alloc::format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
    } else {
        let mut s = String::new();
        for (i, p) in ip.chunks(2).enumerate() {
            if i > 0 {
                s.push(':');
            }
            s.push_str(&alloc::format!("{:x}", u16::from_be_bytes([p[0], p[1]])));
        }
        s
    }
}

// ---- policy ----

fn strings(v: Option<&Value>) -> Vec<&str> {
    v.and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(Value::as_str).collect()
}

fn condition_status(csr: &Value, ty: &str) -> bool {
    csr.pointer(&["status", "conditions"]).and_then(Value::as_array).unwrap_or(&[]).iter().any(|c| str_at(c, &["type"]) == ty && str_at(c, &["status"]) != "False")
}

/// The node name when the requestor is a node itself.
fn requesting_node(csr: &Value) -> Option<&str> {
    let user = str_at(csr, &["spec", "username"]);
    let n = user.strip_prefix(NODE_PREFIX).filter(|n| !n.is_empty())?;
    strings(csr.pointer(&["spec", "groups"])).contains(&NODES_GROUP).then_some(n)
}

/// Whether the usages are a subset of `allowed` and contain `need`.
fn usages_ok(csr: &Value, allowed: &[&str], need: &str) -> bool {
    let u = strings(csr.pointer(&["spec", "usages"]));
    u.contains(&need) && u.iter().all(|x| allowed.contains(x))
}

/// Subject rules of the two kubelet signers (shared by approval and signing).
fn kubelet_subject_ok(csr: &Value, req: &Request) -> bool {
    let signer = str_at(csr, &["spec", "signerName"]);
    let base = req.cn.starts_with(NODE_PREFIX) && req.cn.len() > NODE_PREFIX.len() && req.orgs.len() == 1 && req.orgs[0] == NODES_GROUP && !req.other_san;
    base && match signer {
        KUBELET_CLIENT => req.dns.is_empty() && req.ips.is_empty(),
        _ => !(req.dns.is_empty() && req.ips.is_empty()),
    }
}

/// Whether the usages are allowed for the signer.
fn signer_usages_ok(csr: &Value) -> bool {
    match str_at(csr, &["spec", "signerName"]) {
        KUBELET_CLIENT => usages_ok(csr, &["digital signature", "key encipherment", "client auth"], "client auth"),
        KUBELET_SERVING => usages_ok(csr, &["digital signature", "key encipherment", "server auth"], "server auth"),
        API_CLIENT => usages_ok(csr, &["digital signature", "key encipherment", "client auth"], "client auth"),
        _ => true,
    }
}

/// `Some(true)`: approve. `Some(false)`: leave for a human. `None`: cannot decide yet.
async fn auto_approve<C: Client>(c: &C, csr: &Value, req: &Request) -> Result<Option<bool>> {
    let signer = str_at(csr, &["spec", "signerName"]);
    if !matches!(signer, KUBELET_SERVING | KUBELET_CLIENT) {
        return Ok(Some(false));
    }
    let Some(node) = requesting_node(csr) else { return Ok(Some(false)) };
    let user = str_at(csr, &["spec", "username"]);
    if req.cn != user || !kubelet_subject_ok(csr, req) || !signer_usages_ok(csr) {
        return Ok(Some(false));
    }
    if signer == KUBELET_CLIENT {
        return Ok(Some(true));
    }
    let Some(n) = get_opt(c, &alloc::format!("/api/v1/nodes/{node}")).await? else { return Ok(None) };
    let addrs = n.pointer(&["status", "addresses"]).and_then(Value::as_array).unwrap_or(&[]);
    let has = |types: &[&str], v: &str| addrs.iter().any(|a| types.contains(&str_at(a, &["type"])) && str_at(a, &["address"]) == v);
    let dns_ok = req.dns.iter().all(|d| d == node || has(&["Hostname", "InternalDNS", "ExternalDNS"], d));
    let ips_ok = req.ips.iter().all(|ip| has(&["InternalIP", "ExternalIP"], &ip_string(ip)));
    Ok(Some(dns_ok && ips_ok))
}

fn condition_json(ty: &str, reason: &str, message: &str, now: i64) -> Value {
    let t = rfc3339(now);
    obj(alloc::vec![
        ("type", Value::from(ty)),
        ("status", Value::from("True")),
        ("reason", Value::from(reason)),
        ("message", Value::from(message)),
        ("lastUpdateTime", Value::from(t.as_str())),
        ("lastTransitionTime", Value::from(t.as_str())),
    ])
}

async fn add_condition<C: Client>(c: &C, name: &str, sub: &str, cond: Value) -> Result<Value> {
    let path = alloc::format!("{BASE}/{name}");
    retry_conflict(|| async {
        let mut o = c.get(&path).await?;
        let mut st = o.get("status").cloned().unwrap_or_else(|| obj(Vec::new()));
        let mut conds: Vec<Value> = st.get("conditions").and_then(Value::as_array).map(|a| a.to_vec()).unwrap_or_default();
        if conds.iter().any(|x| str_at(x, &["type"]) == str_at(&cond, &["type"])) {
            return Ok(o);
        }
        conds.push(cond.clone());
        st.set("conditions", Value::Array(conds));
        o.set("status", st);
        c.update(&alloc::format!("{path}/{sub}"), &o).await
    })
    .await
}

fn issue(csr: &Value, req: &Request, ca: &CaSigner, now: i64) -> Vec<u8> {
    let usages = strings(csr.pointer(&["spec", "usages"]));
    let signer = str_at(csr, &["spec", "signerName"]);
    let (server, client) = match signer {
        KUBELET_SERVING => (true, false),
        KUBELET_CLIENT | API_CLIENT => (false, true),
        _ => (usages.is_empty() || usages.contains(&"server auth"), usages.is_empty() || usages.contains(&"client auth")),
    };
    let life = int_at(csr, &["spec", "expirationSeconds"], MAX_LIFETIME).clamp(600, MAX_LIFETIME);
    let mut serial = [0u8; 16];
    (ca.rng)(&mut serial);
    let p = CertParams {
        serial,
        subject: Name { common_name: req.cn.clone(), organizations: req.orgs.clone() },
        not_before: now - 300,
        not_after: now + life,
        is_ca: false,
        server,
        client,
        dns_names: req.dns.clone(),
        ip_addrs: req.ips.clone(),
        public_key: req.key.clone(),
    };
    x509::issue(&p, &ca.name, &ca.key)
}

/// Approves (when allowed) and signs one request. `Ok(true)` asks for a later retry.
pub async fn reconcile<C: Client>(c: &C, ca: &CaSigner, name: &str, now: i64) -> Result<bool> {
    let Some(mut csr) = get_opt(c, &alloc::format!("{BASE}/{name}")).await? else { return Ok(false) };
    let signer = str_at(&csr, &["spec", "signerName"]).to_string();
    let signer = signer.as_str();
    if !matches!(signer, KUBELET_SERVING | KUBELET_CLIENT | API_CLIENT | LEGACY)
        || !str_at(&csr, &["status", "certificate"]).is_empty()
        || condition_status(&csr, "Denied")
        || condition_status(&csr, "Failed")
        || deleting(&csr)
    {
        return Ok(false);
    }
    if now <= 0 {
        return Ok(true);
    }
    let parsed = kr_fmt::base64::decode(str_at(&csr, &["spec", "request"]))
        .map_err(|_| "request is not base64")
        .and_then(|b| String::from_utf8(b).map_err(|_| "request is not PEM"))
        .and_then(|t| x509::pem_decode_all(&t, "CERTIFICATE REQUEST").map_err(|_| "request is not PEM"))
        .and_then(|mut v| if v.is_empty() { Err("request has no CERTIFICATE REQUEST block") } else { Ok(v.remove(0)) })
        .and_then(|der| parse_request(&der));
    let approved = condition_status(&csr, "Approved");
    let fail = |msg: &str| add_condition(c, name, "status", condition_json("Failed", "SignerFailed", msg, now));
    let req = match parsed {
        Ok(r) => r,
        Err(e) => {
            // A request nobody approved is left alone: it may be denied or deleted.
            if approved {
                fail(e).await?;
            }
            return Ok(false);
        }
    };
    if !approved {
        match auto_approve(c, &csr, &req).await? {
            Some(true) => {
                csr = add_condition(c, name, "approval", condition_json("Approved", "AutoApproved", "Auto approving the node's own kubelet certificate request", now)).await?;
            }
            Some(false) => return Ok(false),
            None => return Ok(true),
        }
    }
    if !signer_usages_ok(&csr) || (matches!(signer, KUBELET_SERVING | KUBELET_CLIENT) && !kubelet_subject_ok(&csr, &req)) {
        fail("the request's subject, SANs or usages are not allowed for this signer").await?;
        return Ok(false);
    }
    if req.other_san {
        fail("only DNS and IP SANs are supported").await?;
        return Ok(false);
    }
    let pem = x509::pem_encode("CERTIFICATE", &issue(&csr, &req, ca, now));
    let cert = kr_fmt::base64::encode(pem.as_bytes());
    retry_conflict(|| async {
        let mut o = c.get(&alloc::format!("{BASE}/{name}")).await?;
        let mut st = o.get("status").cloned().unwrap_or_else(|| obj(Vec::new()));
        st.set("certificate", Value::from(cert.as_str()));
        o.set("status", st);
        c.update(&alloc::format!("{BASE}/{name}/status"), &o).await
    })
    .await?;
    Ok(false)
}

#[cfg(test)]
mod tests {
    #[test]
    fn old_requests_are_collected_like_upstream() {
        let csr = |created: &str, status: &str| kr_fmt::json::parse(alloc::format!(r#"{{"metadata":{{"name":"x","creationTimestamp":"{created}"}},"status":{status}}}"#).as_bytes()).unwrap();
        let t0 = kr_apiserver::printers::parse_rfc3339("2026-11-12T00:00:00Z").unwrap();
        let at = |h: i64| t0 + h * 3600;
        let cond = |ty: &str, when: &str| alloc::format!(r#"{{"conditions":[{{"type":"{ty}","status":"True","lastUpdateTime":"{when}"}}]}}"#);
        // Issued: gone an hour after creation, not before.
        let issued = csr("2026-11-12T00:00:00Z", r#"{"certificate":"x"}"#);
        assert!(!expired(&issued, at(0) + 3599) && expired(&issued, at(1)));
        // Denied and failed count from the decision.
        let denied = csr("2026-11-12T00:00:00Z", &cond("Denied", "2026-11-12T05:00:00Z"));
        assert!(!expired(&denied, at(5)) && expired(&denied, at(6)));
        assert!(expired(&csr("2026-11-12T00:00:00Z", &cond("Failed", "2026-11-12T00:00:00Z")), at(1)));
        // Approved but never issued: one hour after the approval.
        assert!(expired(&csr("2026-11-12T00:00:00Z", &cond("Approved", "2026-11-12T00:00:00Z")), at(1)));
        // Undecided: 24 hours.
        let pending = csr("2026-11-12T00:00:00Z", "{}");
        assert!(!expired(&pending, at(23)) && expired(&pending, at(24)));
    }

    use super::*;
    use crate::tests::*;
    use kr_apiserver::client::InProcess;

    fn ca() -> CaSigner {
        CaSigner { name: Name { common_name: "test-ca".into(), organizations: Vec::new() }, key: SigningKey::P256(kr_crypto::p256::SecretKey::from_seed(&[9u8; 48])), rng }
    }

    /// A signed PKCS#10 request with the given subject and SANs.
    fn csr_pem(cn: &str, orgs: &[&str], dns: &[&str], ips: &[[u8; 4]], key: &SigningKey) -> String {
        let mut info = Vec::new();
        der::nested(&mut info, der::SEQUENCE, |i| {
            der::uint(i, &[0]);
            i.extend_from_slice(&Name { common_name: cn.into(), organizations: orgs.iter().map(|o| o.to_string()).collect() }.to_der());
            i.extend_from_slice(&key.public().spki());
            der::nested(i, der::ctx(0), |a| {
                if dns.is_empty() && ips.is_empty() {
                    return;
                }
                der::nested(a, der::SEQUENCE, |attr| {
                    der::tlv(attr, der::OID, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e]);
                    der::nested(attr, der::SET, |set| {
                        der::nested(set, der::SEQUENCE, |exts| {
                            der::nested(exts, der::SEQUENCE, |e| {
                                der::tlv(e, der::OID, &[0x55, 0x1d, 0x11]);
                                let mut names = Vec::new();
                                der::nested(&mut names, der::SEQUENCE, |n| {
                                    for d in dns {
                                        der::tlv(n, 0x82, d.as_bytes());
                                    }
                                    for ip in ips {
                                        der::tlv(n, 0x87, ip);
                                    }
                                });
                                der::tlv(e, der::OCTET_STRING, &names);
                            });
                        });
                    });
                });
            });
        });
        let sig = key.sign(&info);
        let mut out = Vec::new();
        der::nested(&mut out, der::SEQUENCE, |o| {
            o.extend_from_slice(&info);
            der::nested(o, der::SEQUENCE, |a| der::tlv(a, der::OID, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]));
            der::bit_string(o, &sig);
        });
        x509::pem_encode("CERTIFICATE REQUEST", &out)
    }

    fn new_key(n: u8) -> SigningKey {
        SigningKey::P256(kr_crypto::p256::SecretKey::from_seed(&[n; 48]))
    }

    fn csr_obj(name: &str, signer: &str, user: &str, groups: &str, usages: &str, pem: &str) -> Value {
        v(&alloc::format!(
            r#"{{"metadata":{{"name":"{name}"}},"spec":{{"request":"{}","signerName":"{signer}","username":"{user}","groups":{groups},"usages":{usages}}}}}"#,
            kr_fmt::base64::encode(pem.as_bytes())
        ))
    }

    const CLIENT: &str = r#"["digital signature","key encipherment","client auth"]"#;
    const SERVER: &str = r#"["digital signature","key encipherment","server auth"]"#;
    const NODES: &str = r#"["system:nodes","system:authenticated"]"#;

    #[test]
    fn parses_subject_and_sans() {
        let k = new_key(1);
        let r = parse_request(&x509::pem_decode_all(&csr_pem("system:node:n1", &["system:nodes"], &["n1", "n1.lan"], &[[10, 0, 0, 5]], &k), "CERTIFICATE REQUEST").unwrap()[0]).unwrap();
        assert_eq!((r.cn.as_str(), r.orgs.as_slice()), ("system:node:n1", &["system:nodes".to_string()][..]));
        assert_eq!(r.dns, ["n1", "n1.lan"]);
        assert_eq!(r.ips, [alloc::vec![10, 0, 0, 5]]);
        assert!(!r.other_san);
        // A flipped signature byte is rejected.
        let mut der_csr = x509::pem_decode_all(&csr_pem("x", &[], &[], &[], &k), "CERTIFICATE REQUEST").unwrap().remove(0);
        let last = der_csr.len() - 1;
        der_csr[last] ^= 1;
        assert!(parse_request(&der_csr).is_err());
        assert!(parse_request(b"junk").is_err());
    }

    fn run_case<F, Fut>(f: F)
    where
        F: FnOnce(InProcess) -> Fut + 'static,
        Fut: core::future::Future<Output = ()> + 'static,
    {
        let _l = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let api = Rc::new(kr_apiserver::api::ApiServer::new(kr_store::Store::in_memory(), || T0, rng, "127.0.0.1:6443".to_string()).unwrap());
        let c = InProcess::new(api, "test");
        kr_rt::exec::block_on(f(c));
    }

    async fn add_node(c: &InProcess, n: &str, ip: &str) {
        c.create("/api/v1/nodes", &v(&alloc::format!(r#"{{"metadata":{{"name":"{n}"}}}}"#))).await.unwrap();
        let st = v(&alloc::format!(r#"{{"addresses":[{{"type":"InternalIP","address":"{ip}"}},{{"type":"Hostname","address":"{n}"}}]}}"#));
        put_status(c, &alloc::format!("/api/v1/nodes/{n}"), |_| st.clone()).await.unwrap();
    }

    fn cert_of(csr: &Value) -> Vec<u8> {
        let pem = String::from_utf8(kr_fmt::base64::decode(str_at(csr, &["status", "certificate"])).unwrap()).unwrap();
        x509::pem_decode_all(&pem, "CERTIFICATE").unwrap().remove(0)
    }

    #[test]
    fn node_requests_are_approved_and_signed() {
        run_case(|c| async move {
            let ca = ca();
            add_node(&c, "n1", "10.0.0.5").await;
            let k = new_key(2);
            let client = csr_obj("c1", KUBELET_CLIENT, "system:node:n1", NODES, CLIENT, &csr_pem("system:node:n1", &["system:nodes"], &[], &[], &k));
            let serving = csr_obj("s1", KUBELET_SERVING, "system:node:n1", NODES, SERVER, &csr_pem("system:node:n1", &["system:nodes"], &["n1"], &[[10, 0, 0, 5]], &k));
            c.create(BASE, &client).await.unwrap();
            c.create(BASE, &serving).await.unwrap();
            for n in ["c1", "s1"] {
                assert!(!reconcile(&c, &ca, n, T0).await.unwrap());
                let o = c.get(&alloc::format!("{BASE}/{n}")).await.unwrap();
                assert!(condition_status(&o, "Approved"), "{n} approved");
                let der_cert = cert_of(&o);
                let cert = x509::Certificate::parse(&der_cert).unwrap();
                assert_eq!(cert.common_name(), Some(&b"system:node:n1"[..]));
                assert!(cert.signed_by(&ca.key.public()));
                assert_eq!(cert.eku.client, n == "c1");
                assert_eq!(cert.eku.server, n == "s1");
                assert_eq!(cert.not_after, T0 + MAX_LIFETIME);
            }
            let o = c.get(&alloc::format!("{BASE}/s1")).await.unwrap();
            let der_cert = cert_of(&o);
            let cert = x509::Certificate::parse(&der_cert).unwrap();
            assert_eq!(cert.dns_names, [&b"n1"[..]]);
            assert_eq!(cert.ip_addrs, [&[10u8, 0, 0, 5][..]]);
        });
    }

    #[test]
    fn foreign_and_mismatching_requests_stay_pending() {
        run_case(|c| async move {
            let ca = ca();
            add_node(&c, "n1", "10.0.0.5").await;
            let k = new_key(3);
            let ok_csr = csr_pem("system:node:n1", &["system:nodes"], &[], &[], &k);
            let cases = [
                // Requestor is another node / a user / not in system:nodes.
                ("other", csr_obj("other", KUBELET_CLIENT, "system:node:n2", NODES, CLIENT, &ok_csr)),
                ("user", csr_obj("user", KUBELET_CLIENT, "alice", r#"["system:masters"]"#, CLIENT, &ok_csr)),
                ("nogroup", csr_obj("nogroup", KUBELET_CLIENT, "system:node:n1", r#"["x"]"#, CLIENT, &ok_csr)),
                // CN differs from the requestor; wrong organization; SAN on a client request.
                ("cn", csr_obj("cn", KUBELET_CLIENT, "system:node:n1", NODES, CLIENT, &csr_pem("system:node:n2", &["system:nodes"], &[], &[], &k))),
                ("org", csr_obj("org", KUBELET_CLIENT, "system:node:n1", NODES, CLIENT, &csr_pem("system:node:n1", &["system:masters"], &[], &[], &k))),
                ("san", csr_obj("san", KUBELET_CLIENT, "system:node:n1", NODES, CLIENT, &csr_pem("system:node:n1", &["system:nodes"], &["evil"], &[], &k))),
                // Serving: SAN not an address of the node; wrong usages.
                ("dns", csr_obj("dns", KUBELET_SERVING, "system:node:n1", NODES, SERVER, &csr_pem("system:node:n1", &["system:nodes"], &["kubernetes.default"], &[], &k))),
                ("ip", csr_obj("ip", KUBELET_SERVING, "system:node:n1", NODES, SERVER, &csr_pem("system:node:n1", &["system:nodes"], &["n1"], &[[1, 2, 3, 4]], &k))),
                ("usage", csr_obj("usage", KUBELET_SERVING, "system:node:n1", NODES, CLIENT, &csr_pem("system:node:n1", &["system:nodes"], &["n1"], &[], &k))),
                // Other signers are never approved by the controller.
                ("api", csr_obj("api", API_CLIENT, "system:node:n1", NODES, CLIENT, &ok_csr)),
                ("legacy", csr_obj("legacy", LEGACY, "system:node:n1", NODES, CLIENT, &ok_csr)),
            ];
            for (n, o) in &cases {
                c.create(BASE, o).await.unwrap();
                reconcile(&c, &ca, n, T0).await.unwrap();
                let got = c.get(&alloc::format!("{BASE}/{n}")).await.unwrap();
                assert!(!condition_status(&got, "Approved"), "{n} must not be approved");
                assert!(str_at(&got, &["status", "certificate"]).is_empty(), "{n} must not be signed");
            }
        });
    }

    #[test]
    fn human_approval_is_required_for_other_signers() {
        run_case(|c| async move {
            let ca = ca();
            let k = new_key(4);
            let pem = csr_pem("alice", &["devs"], &[], &[], &k);
            c.create(BASE, &csr_obj("alice", API_CLIENT, "alice", r#"["devs"]"#, CLIENT, &pem)).await.unwrap();
            c.create(BASE, &csr_obj("old", LEGACY, "alice", r#"["devs"]"#, CLIENT, &pem)).await.unwrap();
            for n in ["alice", "old"] {
                reconcile(&c, &ca, n, T0).await.unwrap();
                assert!(str_at(&c.get(&alloc::format!("{BASE}/{n}")).await.unwrap(), &["status", "certificate"]).is_empty());
                // The human approves through the approval subresource.
                add_condition(&c, n, "approval", condition_json("Approved", "ByHand", "ok", T0)).await.unwrap();
                reconcile(&c, &ca, n, T0).await.unwrap();
                let o = c.get(&alloc::format!("{BASE}/{n}")).await.unwrap();
                let der_cert = cert_of(&o);
                let cert = x509::Certificate::parse(&der_cert).unwrap();
                assert_eq!(cert.common_name(), Some(&b"alice"[..]));
                assert_eq!(cert.organizations(), [&b"devs"[..]]);
                assert!(cert.signed_by(&ca.key.public()));
            }
            // Denied requests are never signed.
            c.create(BASE, &csr_obj("bad", API_CLIENT, "alice", r#"["devs"]"#, CLIENT, &pem)).await.unwrap();
            add_condition(&c, "bad", "approval", condition_json("Denied", "No", "no", T0)).await.unwrap();
            reconcile(&c, &ca, "bad", T0).await.unwrap();
            assert!(str_at(&c.get(&alloc::format!("{BASE}/bad")).await.unwrap(), &["status", "certificate"]).is_empty());
        });
    }

    #[test]
    fn approved_but_invalid_requests_fail() {
        run_case(|c| async move {
            let ca = ca();
            let k = new_key(5);
            // Human-approved kubelet-serving request for a non-node subject.
            let bad = csr_obj("evil", KUBELET_SERVING, "alice", r#"["devs"]"#, SERVER, &csr_pem("admin", &["system:masters"], &["x"], &[], &k));
            c.create(BASE, &bad).await.unwrap();
            add_condition(&c, "evil", "approval", condition_json("Approved", "ByHand", "ok", T0)).await.unwrap();
            reconcile(&c, &ca, "evil", T0).await.unwrap();
            let o = c.get(&alloc::format!("{BASE}/evil")).await.unwrap();
            assert!(condition_status(&o, "Failed"));
            assert!(str_at(&o, &["status", "certificate"]).is_empty());
            // Garbage request, approved.
            let junk = csr_obj("junk", API_CLIENT, "alice", r#"["devs"]"#, CLIENT, "not pem");
            c.create(BASE, &junk).await.unwrap();
            add_condition(&c, "junk", "approval", condition_json("Approved", "ByHand", "ok", T0)).await.unwrap();
            reconcile(&c, &ca, "junk", T0).await.unwrap();
            assert!(condition_status(&c.get(&alloc::format!("{BASE}/junk")).await.unwrap(), "Failed"));
        });
    }
}
