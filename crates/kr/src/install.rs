//! Install-time configuration shared by `kr server` and `kr agent` (ADR-060): the configuration
//! file merged in front of the command line, and the node settings (`--tls-san`, `--node-name`,
//! `--node-label`, `--node-taint`, `--node-ip`, `--node-external-ip`, `--disable`) that flags and
//! file publish as `KR_*` variables. A flag or file key overrides the environment variable.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use kr_apiserver::components::Disabled;
use kr_kubelet::nodecfg::{self, Taint};
use kr_rt::Args;

pub use kr_runtime::config::Install;

/// The effective arguments: configuration file(s), then the command line.
pub struct Argv {
    v: Vec<&'static [u8]>,
    i: usize,
}

impl Argv {
    pub fn load(args: Args) -> Result<Argv, String> {
        let cli: Vec<String> = args.map(|a| String::from_utf8_lossy(a).into_owned()).collect();
        let v = kr_runtime::config::load(cli)?;
        // Kept for the life of the process, like the real argv.
        Ok(Argv { v: v.into_iter().map(|s| &*Box::leak(s.into_bytes().into_boxed_slice())).collect(), i: 0 })
    }
}

impl Iterator for Argv {
    type Item = &'static [u8];
    fn next(&mut self) -> Option<&'static [u8]> {
        let a = self.v.get(self.i).copied();
        self.i += 1;
        a
    }
}

fn var(name: &str) -> Option<String> {
    kr_runtime::store::env_var(name).filter(|v| !v.is_empty())
}

/// Validates what was configured (flags and environment alike), so a typo stops the start
/// instead of being ignored.
pub fn publish(inst: &Install) -> Result<(), String> {
    inst.publish();
    disabled()?;
    node_settings()?;
    if let Some(n) = var("KR_NODE_NAME") {
        if !kr_apiserver::object::is_dns_subdomain(&n.to_ascii_lowercase()) {
            return Err(alloc::format!("--node-name {n:?} is not a valid node name"));
        }
    }
    for v in ["KR_NODE_IP", "KR_NODE_EXTERNAL_IP"] {
        if let Some(s) = var(v) {
            node_ip_value(&s).ok_or_else(|| alloc::format!("{v}: {s:?} is not an IP address"))?;
        }
    }
    for san in tls_sans() {
        if san.contains(char::is_whitespace) {
            return Err(alloc::format!("--tls-san {san:?} is not a host name or address"));
        }
    }
    let d = disabled()?;
    if !d.names().is_empty() {
        kr_rt::print(alloc::format!("kr: disabled components: {}\n", d.names().join(", ")).as_bytes());
    }
    // Network policy is enforced by the kubelet, which reads this long-standing switch.
    if d.network_policy {
        kr_runtime::store::set_override("KR_NETWORK_POLICY", "off");
    }
    Ok(())
}

pub fn disabled() -> Result<Disabled, String> {
    Disabled::parse(&kr_runtime::store::env_var("KR_DISABLE").unwrap_or_default())
}

/// The first address of `--node-ip` (a dual-stack `v4,v6` pair is accepted; the first is primary).
fn node_ip_value(s: &str) -> Option<[u8; 16]> {
    kr_net::tcp::parse_ip16(s.split(',').next()?.trim())
}

pub fn node_ip() -> Option<[u8; 16]> {
    var("KR_NODE_IP").and_then(|s| node_ip_value(&s))
}

pub fn external_ip() -> Option<[u8; 16]> {
    var("KR_NODE_EXTERNAL_IP").and_then(|s| node_ip_value(&s))
}

pub fn tls_sans() -> Vec<String> {
    var("KR_TLS_SAN").map(|s| s.split(',').map(|x| String::from(x.trim())).filter(|x| !x.is_empty()).collect()).unwrap_or_default()
}

pub fn node_settings() -> Result<(Vec<(String, String)>, Vec<Taint>), String> {
    Ok((nodecfg::parse_labels(&var("KR_NODE_LABELS").unwrap_or_default())?, nodecfg::parse_taints(&var("KR_NODE_TAINTS").unwrap_or_default())?))
}
