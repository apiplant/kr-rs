//! Optional built-in components that `--disable <name>` (config key `disable`, `KR_DISABLE`) turns
//! off, with k3s's names (ADR-060).

use alloc::string::String;
use alloc::vec::Vec;

/// A set of disabled components. `Default` disables nothing.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Disabled {
    /// LoadBalancer status controller (k3s: servicelb).
    pub servicelb: bool,
    /// metrics.k8s.io scraper (k3s: metrics-server).
    pub metrics_server: bool,
    /// Cluster DNS (k3s: coredns).
    pub coredns: bool,
    /// The `local-path` provisioner and default StorageClass (k3s: local-storage).
    pub local_storage: bool,
    /// NetworkPolicy enforcement (k3s: `--disable-network-policy`).
    pub network_policy: bool,
    /// The HelmChart controller (k3s: `--disable-helm-controller`).
    pub helm_controller: bool,
}

/// k3s components kr does not ship; accepted so a k3s config works unchanged.
const NOOP: &[&str] = &["traefik", "runtime-class", "ccm", "cloud-controller", "snapshot-controller"];

impl Disabled {
    /// Parses a comma separated list of component names (repeatable flags are joined by the caller).
    pub fn parse(list: &str) -> Result<Disabled, String> {
        let mut d = Disabled::default();
        for n in list.split([',', '\n']).map(str::trim).filter(|n| !n.is_empty()) {
            match n {
                "servicelb" => d.servicelb = true,
                "metrics-server" | "metrics" => d.metrics_server = true,
                "coredns" | "dns" => d.coredns = true,
                "local-storage" | "local-path" => d.local_storage = true,
                "network-policy" => d.network_policy = true,
                "helm-controller" | "helm" => d.helm_controller = true,
                n if NOOP.contains(&n) => {}
                n => return Err(alloc::format!("unknown component {n:?} for --disable (servicelb, metrics-server, coredns, local-storage, network-policy, helm-controller)")),
            }
        }
        Ok(d)
    }

    /// Names, for logging.
    pub fn names(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        for (on, n) in [(self.servicelb, "servicelb"), (self.metrics_server, "metrics-server"), (self.coredns, "coredns"), (self.local_storage, "local-storage"), (self.network_policy, "network-policy"), (self.helm_controller, "helm-controller")] {
            if on {
                v.push(n);
            }
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_names_and_aliases() {
        let d = Disabled::parse("servicelb, metrics ,local-path\ntraefik").unwrap();
        assert!(d.servicelb && d.metrics_server && d.local_storage);
        assert!(!d.coredns && !d.network_policy && !d.helm_controller);
        assert_eq!(d.names(), ["servicelb", "metrics-server", "local-storage"]);
        assert_eq!(Disabled::parse("").unwrap(), Disabled::default());
        assert!(Disabled::parse("dns,helm").unwrap().coredns);
        assert!(Disabled::parse("nonsense").is_err());
    }
}
