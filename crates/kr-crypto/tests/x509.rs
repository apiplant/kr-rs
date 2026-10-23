mod common;
use common::unhex;
use kr_crypto::x509::{self, CertParams, Certificate, Name, SigningKey, Usage, VerifyError};
use kr_crypto::{ed25519, p256};

const NOW: i64 = 1_800_000_000;

fn pems(file: &str) -> Vec<Vec<u8>> {
    x509::pem_decode_all(file, "CERTIFICATE").unwrap()
}

#[test]
fn chains_built_by_openssl() {
    let roots = pems(include_str!("vectors/x509/roots.pem"));
    let inter = pems(include_str!("vectors/x509/inter.pem"));
    let roots: Vec<&[u8]> = roots.iter().map(|v| &v[..]).collect();
    for line in include_str!("vectors/x509/cases.txt").lines() {
        let f: Vec<&str> = line.split('|').collect();
        let leaf = unhex(f[3]);
        let mut chain: Vec<&[u8]> = vec![&leaf];
        chain.extend(inter.iter().map(|v| &v[..]));
        let usage = if f[1] == "client" { Usage::Client } else { Usage::Server(b"api.kr.local") };
        let got = x509::verify_chain(&chain, &roots, NOW, usage);
        let want = match f[2] {
            "ok" | "ok_ed" => Ok(()),
            "Expired" => Err(VerifyError::Expired),
            "Usage" => Err(VerifyError::Usage),
            "HostMismatch" => Err(VerifyError::HostMismatch),
            "Parse" => Err(VerifyError::Parse),
            "NotCa" => Err(VerifyError::NotCa),
            "UnknownIssuer" => Err(VerifyError::UnknownIssuer),
            w => panic!("unknown expectation {w}"),
        };
        assert_eq!(got, want, "case {}", f[0]);
        if f[0] == "ok_server_via_inter" {
            let c = Certificate::parse(&leaf).unwrap();
            for (h, ok) in [(&b"x.svc.kr.local"[..], true), (b"a.b.svc.kr.local", false), (b"svc.kr.local", false), (b"10.0.0.1", true), (b"::1", true), (b"10.0.0.2", false), (b"API.KR.LOCAL.", true)] {
                assert_eq!(c.matches_host(h), ok, "host {}", String::from_utf8_lossy(h));
            }
            // without the intermediate the chain is incomplete
            assert_eq!(x509::verify_chain(&[&leaf], &roots, NOW, usage), Err(VerifyError::UnknownIssuer));
            // not yet valid / expired windows
            assert_eq!(x509::verify_chain(&chain, &roots, 1_600_000_000, usage), Err(VerifyError::Expired));
        }
        if f[0] == "ok_client" {
            let c = Certificate::parse(&leaf).unwrap();
            assert_eq!(c.common_name(), Some(&b"alice"[..]));
            assert_eq!(c.organizations(), vec![&b"system:masters"[..]]);
        }
    }
}

fn ca(key: &SigningKey, cn: &str) -> (Name, Vec<u8>) {
    let name = Name { common_name: cn.into(), organizations: vec![] };
    let p = CertParams {
        serial: [9; 16],
        subject: name.clone(),
        not_before: NOW - 3600,
        not_after: NOW + 86400 * 3650,
        is_ca: true,
        server: false,
        client: false,
        dns_names: vec![],
        ip_addrs: vec![],
        public_key: key.public(),
    };
    let der = x509::issue(&p, &name, key);
    (name, der)
}

#[test]
fn issued_certificates_verify_here() {
    for ca_key in [SigningKey::P256(p256::SecretKey::from_bytes(&[3; 32]).unwrap()), SigningKey::Ed25519(ed25519::SigningKey::from_seed(&[4; 32]))] {
        let (ca_name, ca_der) = ca(&ca_key, "kr-ca");
        let leaf_key = SigningKey::P256(p256::SecretKey::from_bytes(&[5; 32]).unwrap());
        let p = CertParams {
            serial: [1; 16],
            subject: Name { common_name: "kube-apiserver".into(), organizations: vec!["kr".into()] },
            not_before: NOW - 60,
            not_after: NOW + 86400,
            is_ca: false,
            server: true,
            client: false,
            dns_names: vec!["kubernetes.default.svc".into(), "localhost".into()],
            ip_addrs: vec![vec![127, 0, 0, 1]],
            public_key: leaf_key.public(),
        };
        let leaf = x509::issue(&p, &ca_name, &ca_key);
        assert_eq!(x509::verify_chain(&[&leaf], &[&ca_der], NOW, Usage::Server(b"127.0.0.1")), Ok(()));
        assert_eq!(x509::verify_chain(&[&leaf], &[&ca_der], NOW, Usage::Server(b"localhost")), Ok(()));
        assert_eq!(x509::verify_chain(&[&leaf], &[&ca_der], NOW, Usage::Client), Err(VerifyError::Usage));
        let mut tampered = leaf.clone();
        let i = tampered.windows(9).position(|w| w == b"localhost").unwrap();
        tampered[i] = b'L';
        assert_eq!(x509::verify_chain(&[&tampered], &[&ca_der], NOW, Usage::Server(b"Localhost")), Err(VerifyError::UnknownIssuer));
        // key round trip through PKCS#8
        let k2 = x509::private_key_from_pkcs8(&x509::private_key_to_pkcs8(&leaf_key)).unwrap();
        assert_eq!(k2.public(), leaf_key.public());
    }
}

/// Our certificates must satisfy OpenSSL too (skipped when the `openssl` binary is missing).
#[test]
fn issued_certificates_verify_in_openssl() {
    let Ok(_) = std::process::Command::new("openssl").arg("version").output() else { return };
    let dir = std::env::temp_dir().join(format!("kr-x509-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    for (i, ca_key) in [SigningKey::P256(p256::SecretKey::from_bytes(&[6; 32]).unwrap()), SigningKey::Ed25519(ed25519::SigningKey::from_seed(&[7; 32]))].into_iter().enumerate() {
        let name = Name { common_name: "kr-ca".into(), organizations: vec![] };
        let mut p = CertParams {
            serial: [2; 16],
            subject: name.clone(),
            not_before: now - 3600,
            not_after: now + 86400,
            is_ca: true,
            server: false,
            client: false,
            dns_names: vec![],
            ip_addrs: vec![],
            public_key: ca_key.public(),
        };
        let ca_der = x509::issue(&p, &name, &ca_key);
        let leaf_key = SigningKey::P256(p256::SecretKey::from_bytes(&[8; 32]).unwrap());
        p.subject = Name { common_name: "node-1".into(), organizations: vec!["system:nodes".into()] };
        p.is_ca = false;
        p.server = true;
        p.client = true;
        p.dns_names = vec!["node-1.kr.local".into()];
        p.ip_addrs = vec![vec![10, 88, 0, 1]];
        p.public_key = leaf_key.public();
        let leaf = x509::issue(&p, &name, &ca_key);
        let (ca_path, leaf_path, key_path) = (dir.join(format!("ca{i}.pem")), dir.join(format!("leaf{i}.pem")), dir.join(format!("key{i}.pem")));
        std::fs::write(&ca_path, x509::pem_encode("CERTIFICATE", &ca_der)).unwrap();
        std::fs::write(&leaf_path, x509::pem_encode("CERTIFICATE", &leaf)).unwrap();
        std::fs::write(&key_path, x509::pem_encode("PRIVATE KEY", &x509::private_key_to_pkcs8(&leaf_key))).unwrap();
        for extra in [&["-verify_hostname", "node-1.kr.local", "-purpose", "sslserver"][..], &["-verify_ip", "10.88.0.1", "-purpose", "sslclient"]] {
            let out = std::process::Command::new("openssl")
                .args(["verify", "-x509_strict", "-CAfile"])
                .arg(&ca_path)
                .args(extra)
                .arg(&leaf_path)
                .output()
                .unwrap();
            assert!(out.status.success(), "openssl verify ({i}): {}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        }
        // OpenSSL agrees the private key matches the certificate.
        let pk_cert = std::process::Command::new("openssl").args(["x509", "-noout", "-pubkey", "-in"]).arg(&leaf_path).output().unwrap().stdout;
        let pk_key = std::process::Command::new("openssl").args(["pkey", "-pubout", "-in"]).arg(&key_path).output().unwrap().stdout;
        assert_eq!(pk_cert, pk_key);
    }
}
