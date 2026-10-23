//! `kr pki ...`: cluster CA and certificate issuance (ECDSA P-256).
//!
//! Files: `<dir>/ca.pem` + `<dir>/ca.key`, and `<dir>/<name>.pem` + `<dir>/<name>.key`. Keys are
//! PKCS#8 PEM written with mode 0600 and never overwritten.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use kr_crypto::x509::{self, CertParams, Name, SigningKey};
use kr_crypto::p256;
use kr_rt::{eprint, print, Args};
use kr_sys::{fs, ns, Errno};

const USAGE: &[u8] = b"usage:
  kr pki ca <dir> [--cn name] [--days 3650]
  kr pki issue <dir> <name> [--cn cn] [--org o]... [--dns name]... [--ip addr]... [--server] [--client] [--days 365]
";

pub fn main(mut args: Args) -> i32 {
    let r = match args.next() {
        Some(b"ca") => ca(args),
        Some(b"issue") => issue(args),
        _ => Err(String::from("unknown subcommand")),
    };
    match r {
        Ok(()) => 0,
        Err(e) => {
            eprint(b"kr pki: ");
            eprint(e.as_bytes());
            eprint(b"\n");
            eprint(USAGE);
            2
        }
    }
}

fn utf8(b: &[u8]) -> Result<String, String> {
    core::str::from_utf8(b).map(String::from).map_err(|_| String::from("argument is not UTF-8"))
}

fn now() -> i64 {
    kr_sys::clock_gettime(0).map(|t| t.tv_sec).unwrap_or(0)
}

fn path(dir: &str, file: &str) -> Vec<u8> {
    let mut p = format!("{dir}/{file}").into_bytes();
    p.push(0);
    p
}

/// Creates a file that must not exist yet (O_EXCL) with `mode`.
fn write_new(p: &[u8], data: &[u8], mode: u32) -> Result<(), String> {
    const O_EXCL: i32 = 0o200;
    let fd = ns::open(p, ns::O_WRONLY | ns::O_CREAT | O_EXCL, mode).map_err(|e| match e {
        Errno(17) => format!("{} already exists", core::str::from_utf8(&p[..p.len() - 1]).unwrap_or("?")),
        e => format!("create file: errno {}", e.0),
    })?;
    let mut off = 0;
    while off < data.len() {
        off += kr_sys::write(fd.raw(), &data[off..]).map_err(|e| format!("write: errno {}", e.0))?;
    }
    Ok(())
}

fn new_key() -> SigningKey {
    let mut seed = [0u8; 48];
    kr_sys::getrandom(&mut seed);
    let k = SigningKey::P256(p256::SecretKey::from_seed(&seed));
    kr_crypto::wipe(&mut seed);
    k
}

fn serial() -> [u8; 16] {
    let mut s = [0u8; 16];
    kr_sys::getrandom(&mut s);
    s
}

fn days(v: &[u8]) -> Result<i64, String> {
    let s = utf8(v)?;
    s.parse::<i64>().ok().filter(|d| (1..=36500).contains(d)).ok_or(format!("bad --days {s}"))
}

fn ca(mut args: Args) -> Result<(), String> {
    let dir = utf8(args.next().ok_or("missing <dir>")?)?;
    let (mut cn, mut d) = (String::from("kr-ca"), 3650);
    while let Some(a) = args.next() {
        let v = args.next().ok_or("flag needs a value")?;
        match a {
            b"--cn" => cn = utf8(v)?,
            b"--days" => d = days(v)?,
            _ => return Err(format!("unknown flag {}", utf8(a)?)),
        }
    }
    match ns::mkdir(&path(&dir, ""), 0o700) {
        Ok(()) | Err(Errno(17)) => {}
        Err(e) => return Err(format!("mkdir: errno {}", e.0)),
    }
    let key = new_key();
    let name = Name { common_name: cn, organizations: Vec::new() };
    let t = now();
    let p = CertParams {
        serial: serial(),
        subject: name.clone(),
        not_before: t - 300,
        not_after: t + d * 86400,
        is_ca: true,
        server: false,
        client: false,
        dns_names: Vec::new(),
        ip_addrs: Vec::new(),
        public_key: key.public(),
    };
    let cert = x509::issue(&p, &name, &key);
    write_new(&path(&dir, "ca.key"), x509::pem_encode("PRIVATE KEY", &x509::private_key_to_pkcs8(&key)).as_bytes(), 0o600)?;
    write_new(&path(&dir, "ca.pem"), x509::pem_encode("CERTIFICATE", &cert).as_bytes(), 0o644)?;
    print(format!("{dir}/ca.pem\n").as_bytes());
    Ok(())
}

fn load_ca(dir: &str) -> Result<(Name, SigningKey, Vec<u8>), String> {
    let read = |f: &str| fs::read_file(&path(dir, f), 1 << 20).map_err(|e| format!("read {dir}/{f}: errno {}", e.0));
    let pem = read("ca.pem")?;
    let cert = x509::pem_decode_all(core::str::from_utf8(&pem).map_err(|_| "ca.pem not UTF-8")?, "CERTIFICATE")
        .ok()
        .and_then(|mut v| (!v.is_empty()).then(|| v.remove(0)))
        .ok_or("ca.pem has no certificate")?;
    let key_pem = read("ca.key")?;
    let key_der = x509::pem_decode_all(core::str::from_utf8(&key_pem).map_err(|_| "ca.key not UTF-8")?, "PRIVATE KEY")
        .ok()
        .and_then(|mut v| (!v.is_empty()).then(|| v.remove(0)))
        .ok_or("ca.key has no PRIVATE KEY")?;
    let key = x509::private_key_from_pkcs8(&key_der).map_err(|_| "ca.key is not a supported key")?;
    let parsed = x509::Certificate::parse(&cert).map_err(|_| "ca.pem does not parse")?;
    if parsed.public_key != Some(key.public()) {
        return Err("ca.key does not match ca.pem".into());
    }
    let cn = parsed.common_name().map(|c| String::from_utf8_lossy(c).into_owned()).unwrap_or_default();
    let orgs = parsed.organizations().iter().map(|o| String::from_utf8_lossy(o).into_owned()).collect();
    Ok((Name { common_name: cn, organizations: orgs }, key, cert))
}

fn issue(mut args: Args) -> Result<(), String> {
    let dir = utf8(args.next().ok_or("missing <dir>")?)?;
    let name = utf8(args.next().ok_or("missing <name>")?)?;
    if name.is_empty() || name == "ca" || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.') || name.starts_with('.') {
        return Err(format!("invalid name {name}"));
    }
    let (ca_name, ca_key, _) = load_ca(&dir)?;
    let key = new_key();
    let t = now();
    let mut p = CertParams {
        serial: serial(),
        subject: Name { common_name: name.clone(), organizations: Vec::new() },
        not_before: t - 300,
        not_after: t + 365 * 86400,
        is_ca: false,
        server: false,
        client: false,
        dns_names: Vec::new(),
        ip_addrs: Vec::new(),
        public_key: key.public(),
    };
    while let Some(a) = args.next() {
        match a {
            b"--server" => p.server = true,
            b"--client" => p.client = true,
            _ => {
                let v = args.next().ok_or("flag needs a value")?;
                match a {
                    b"--cn" => p.subject.common_name = utf8(v)?,
                    b"--org" => p.subject.organizations.push(utf8(v)?),
                    b"--dns" => p.dns_names.push(utf8(v)?),
                    b"--ip" => p.ip_addrs.push(x509::parse_ip(v).ok_or("bad --ip")?),
                    b"--days" => p.not_after = t + days(v)? * 86400,
                    _ => return Err(format!("unknown flag {}", utf8(a)?)),
                }
            }
        }
    }
    if !p.server && !p.client {
        return Err("pass --server and/or --client".into());
    }
    let cert = x509::issue(&p, &ca_name, &ca_key);
    write_new(&path(&dir, &format!("{name}.key")), x509::pem_encode("PRIVATE KEY", &x509::private_key_to_pkcs8(&key)).as_bytes(), 0o600)?;
    write_new(&path(&dir, &format!("{name}.pem")), x509::pem_encode("CERTIFICATE", &cert).as_bytes(), 0o644)?;
    print(format!("{dir}/{name}.pem\n").as_bytes());
    Ok(())
}
