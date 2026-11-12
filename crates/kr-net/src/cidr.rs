//! The cluster's IPv4 pod and Service networks. Both are a /16 (`A.B.0.0/16`): each node gets a
//! /24 of the pod network (`A.B.N.0/24`) and Services take addresses of the Service network
//! (`A.B.0.1` is `kubernetes`, `A.B.0.10` the DNS). Defaults `10.88.0.0/16` and `10.96.0.0/16`;
//! `KR_POD_CIDR` / `KR_SERVICE_CIDR` change them (k3s: `--cluster-cidr`, `--service-cidr`), the same
//! on the server and on every agent. Set once at start-up by [`init`].

use alloc::string::String;
use core::sync::atomic::{AtomicU32, Ordering};

const DEFAULT_POD: [u8; 2] = [10, 88];
const DEFAULT_SERVICE: [u8; 2] = [10, 96];

// Stored as 0x10000 | (a << 8) | b so that 0 means "default".
static POD: AtomicU32 = AtomicU32::new(0);
static SERVICE: AtomicU32 = AtomicU32::new(0);

fn get(v: &AtomicU32, default: [u8; 2]) -> [u8; 2] {
    match v.load(Ordering::Relaxed) {
        0 => default,
        x => [(x >> 8) as u8, x as u8],
    }
}

/// The first two octets of the pod network.
pub fn pod_prefix() -> [u8; 2] {
    get(&POD, DEFAULT_POD)
}

/// The first two octets of the Service network.
pub fn service_prefix() -> [u8; 2] {
    get(&SERVICE, DEFAULT_SERVICE)
}

/// The pod network as `(address, prefix length)`.
pub fn pod_cidr() -> ([u8; 4], u8) {
    let p = pod_prefix();
    ([p[0], p[1], 0, 0], 16)
}

/// The Service network as `(address, prefix length)`.
pub fn service_cidr() -> ([u8; 4], u8) {
    let p = service_prefix();
    ([p[0], p[1], 0, 0], 16)
}

/// A Service address `A.B.hi.lo` of the Service network.
pub fn service_ip(hi: u8, lo: u8) -> [u8; 4] {
    let p = service_prefix();
    [p[0], p[1], hi, lo]
}

/// `A.B.0.0/16` -> `[A, B]`.
pub fn parse16(s: &str) -> Result<[u8; 2], String> {
    let bad = || alloc::format!("{s:?} is not an IPv4 network of the form A.B.0.0/16");
    let (ip, len) = s.trim().split_once('/').ok_or_else(bad)?;
    if len != "16" {
        return Err(bad());
    }
    let mut o = [0u8; 4];
    let mut parts = ip.split('.');
    for x in o.iter_mut() {
        *x = parts.next().and_then(|p| p.parse().ok()).ok_or_else(bad)?;
    }
    if parts.next().is_some() || o[2] != 0 || o[3] != 0 || o[0] == 0 || o[0] == 127 || o[0] >= 224 {
        return Err(bad());
    }
    Ok([o[0], o[1]])
}

/// Applies `KR_POD_CIDR` / `KR_SERVICE_CIDR` (None = default). Both must differ.
pub fn init(pod: Option<&str>, service: Option<&str>) -> Result<(), String> {
    let p = pod.map(|s| parse16(s).map_err(|e| alloc::format!("KR_POD_CIDR: {e}"))).transpose()?.unwrap_or(DEFAULT_POD);
    let s = service.map(|s| parse16(s).map_err(|e| alloc::format!("KR_SERVICE_CIDR: {e}"))).transpose()?.unwrap_or(DEFAULT_SERVICE);
    if p == s {
        return Err(String::from("KR_POD_CIDR and KR_SERVICE_CIDR must be different networks"));
    }
    POD.store(0x10000 | (p[0] as u32) << 8 | p[1] as u32, Ordering::Relaxed);
    SERVICE.store(0x10000 | (s[0] as u32) << 8 | s[1] as u32, Ordering::Relaxed);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sixteens_only() {
        assert_eq!(parse16("10.42.0.0/16"), Ok([10, 42]));
        assert!(parse16("10.42.0.0/24").is_err());
        assert!(parse16("10.42.1.0/16").is_err());
        assert!(parse16("10.42.0/16").is_err());
        assert!(parse16("127.1.0.0/16").is_err());
        assert!(parse16("10.42.0.0").is_err());
    }

    #[test]
    fn init_defaults_and_conflicts() {
        assert!(init(Some("10.1.0.0/16"), Some("10.1.0.0/16")).is_err());
        assert!(init(Some("bad"), None).unwrap_err().starts_with("KR_POD_CIDR"));
        assert!(init(Some("10.42.0.0/16"), Some("10.43.0.0/16")).is_ok());
        assert_eq!((pod_cidr(), service_ip(0, 10)), (([10, 42, 0, 0], 16), [10, 43, 0, 10]));
        assert!(init(None, None).is_ok());
        assert_eq!(pod_prefix(), [10, 88]);
    }
}
