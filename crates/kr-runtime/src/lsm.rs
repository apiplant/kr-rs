//! Linux security modules for containers (#131): AppArmor profiles and SELinux labels.
//!
//! Resolution is pure (host facts are passed in) so it can be tested; the probes read the host
//! once per container start. The result, an [`Lsm`], is applied by the container setup: the
//! profile or label is written to `/proc/self/attr/...` just before `execve`, and the SELinux
//! mount label becomes a `context=` option of the rootfs, `/dev` and `/dev/shm` mounts.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// What to apply to one container (and its `exec` processes). All `None` = nothing.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct Lsm {
    /// AppArmor profile name for the next exec; `Some("unconfined")` is the explicit opt-out.
    pub apparmor: Option<String>,
    /// SELinux process label (`user:role:type:level`).
    pub selinux_process: Option<String>,
    /// SELinux label of the container's mounts (the `context=` option).
    pub selinux_mount: Option<String>,
}

pub const NONE: Lsm = Lsm { apparmor: None, selinux_process: None, selinux_mount: None };

/// The AppArmor profile that stands for `RuntimeDefault`: containerd's, else Docker's. kr cannot
/// compile and load a profile itself (there is no policy compiler in a single static binary), so
/// the host must provide one of them; otherwise `RuntimeDefault` runs unconfined.
pub const DEFAULT_PROFILES: [&str; 2] = ["cri-containerd.apparmor.d", "docker-default"];

pub fn apparmor_enabled() -> bool {
    kr_sys::fs::read_file(b"/sys/module/apparmor/parameters/enabled\0", 16).is_ok_and(|d| d.first() == Some(&b'Y'))
}

/// Names of the loaded profiles (`/sys/kernel/security/apparmor/profiles`, `name (mode)` lines).
pub fn loaded_profiles() -> Vec<String> {
    let d = kr_sys::fs::read_file(b"/sys/kernel/security/apparmor/profiles\0", 8 << 20).unwrap_or_default();
    parse_profiles(&String::from_utf8_lossy(&d))
}

pub fn parse_profiles(text: &str) -> Vec<String> {
    text.lines().filter_map(|l| l.rsplit_once(" (").map(|(n, _)| n.to_string())).collect()
}

/// The profile for an `appArmorProfile` (`kind` is `RuntimeDefault`, `Localhost` or `Unconfined`).
/// `enabled` and `loaded` describe the host. As upstream: with AppArmor off, `RuntimeDefault` and
/// `Unconfined` run unconfined and `Localhost` is an error.
pub fn resolve_apparmor(kind: &str, localhost: Option<&str>, enabled: bool, loaded: &[String]) -> Result<Option<String>, String> {
    match kind {
        "Unconfined" => Ok(None),
        "RuntimeDefault" => Ok(if enabled { DEFAULT_PROFILES.iter().find(|p| loaded.iter().any(|l| l == *p)).map(|p| p.to_string()) } else { None }),
        "Localhost" => {
            let name = localhost.filter(|n| !n.is_empty()).ok_or("appArmorProfile type Localhost needs localhostProfile")?;
            if name.bytes().any(|b| b < 0x20 || b == b' ' || b == b'\n') {
                return Err(format!("AppArmor profile {name:?} is not a valid name"));
            }
            if !enabled {
                return Err(format!("AppArmor profile {name:?} cannot be applied: AppArmor is not enabled on the host"));
            }
            if !loaded.iter().any(|l| l == name) {
                return Err(format!("AppArmor profile {name:?} is not loaded on the node"));
            }
            Ok(Some(name.to_string()))
        }
        other => Err(format!("appArmorProfile type {other:?} is not valid")),
    }
}

/// Parses the deprecated annotation value: `runtime/default`, `localhost/<name>`, `unconfined`.
/// Returns `(type, localhostProfile)`.
pub fn parse_apparmor_annotation(v: &str) -> Result<(&'static str, Option<&str>), String> {
    match v {
        "runtime/default" => Ok(("RuntimeDefault", None)),
        "unconfined" => Ok(("Unconfined", None)),
        _ => match v.strip_prefix("localhost/") {
            Some(n) => Ok(("Localhost", Some(n))),
            None => Err(format!("invalid AppArmor annotation value {v:?}")),
        },
    }
}

/// The text written to the `attr/exec` file: both `/proc/self/attr/apparmor/exec` and the legacy
/// `/proc/self/attr/exec` take `exec <profile>`; an unconfined container is not written at all.
pub fn apparmor_exec_command(profile: &str) -> String {
    format!("exec {profile}")
}

pub fn selinux_enabled() -> bool {
    kr_sys::fs::read_file(b"/sys/fs/selinux/enforce\0", 4).is_ok()
}

/// The fields of `seLinuxOptions`.
#[derive(Default, Clone, Copy)]
pub struct SeOptions<'a> {
    pub user: &'a str,
    pub role: &'a str,
    pub type_: &'a str,
    pub level: &'a str,
}

fn valid_part(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b',' | b':'))
}

/// The process label for `seLinuxOptions`. Fields that are not given come from `default`
/// (containerd's `process` label of `lxc_contexts`, `system_u:system_r:container_t:s0`); a level
/// that is given nowhere, or that is only the sensitivity, gets the categories `mcs`
/// (`c<a>,c<b>`, chosen by the caller per container). Returns the process and the mount label.
pub fn selinux_labels(o: &SeOptions, default: Option<&str>, file_type: &str, mcs: &str) -> Result<(String, String), String> {
    for p in [o.user, o.role, o.type_, o.level] {
        if !valid_part(p) {
            return Err(format!("invalid seLinuxOptions field {p:?}"));
        }
    }
    let d: Vec<&str> = default.map(|d| d.splitn(4, ':').collect()).unwrap_or_default();
    let pick = |given: &str, i: usize| -> Option<String> {
        if !given.is_empty() {
            Some(given.to_string())
        } else {
            d.get(i).filter(|s| !s.is_empty()).map(|s| s.to_string())
        }
    };
    let (user, role, ty) = (pick(o.user, 0), pick(o.role, 1), pick(o.type_, 2));
    let (Some(user), Some(role), Some(ty)) = (user, role, ty) else {
        return Err("seLinuxOptions are incomplete and the host has no default container label".to_string());
    };
    let mut level = pick(o.level, 3).unwrap_or_else(|| "s0".to_string());
    if !level.contains(':') {
        level = format!("{level}:{mcs}");
    }
    Ok((format!("{user}:{role}:{ty}:{level}"), format!("{user}:object_r:{file_type}:{level}")))
}

/// `process` and `file` labels from `/etc/selinux/contexts/lxc_contexts` (`key = "value"`).
pub fn default_labels() -> (Option<String>, String) {
    let d = kr_sys::fs::read_file(b"/etc/selinux/contexts/lxc_contexts\0", 1 << 16).unwrap_or_default();
    parse_lxc_contexts(&String::from_utf8_lossy(&d))
}

/// Returns the process label and the file *type* (`container_file_t` when unspecified).
pub fn parse_lxc_contexts(text: &str) -> (Option<String>, String) {
    let (mut process, mut file) = (None, String::from("container_file_t"));
    for l in text.lines() {
        let Some((k, v)) = l.split_once('=') else { continue };
        let v = v.trim().trim_matches('"');
        match k.trim() {
            "process" => process = Some(v.to_string()),
            "file" => file = v.split(':').nth(2).unwrap_or("container_file_t").to_string(),
            _ => {}
        }
    }
    (process, file)
}

/// Random MCS categories `c<a>,c<b>` with `a < b < 1024`.
pub fn random_mcs() -> String {
    let mut b = [0u8; 4];
    kr_sys::getrandom(&mut b);
    mcs_from(u16::from_le_bytes([b[0], b[1]]), u16::from_le_bytes([b[2], b[3]]))
}

pub fn mcs_from(x: u16, y: u16) -> String {
    let (a, mut c) = (x % 1024, y % 1024);
    if c == a {
        c = (a + 1) % 1024;
    }
    format!("c{},c{}", a.min(c), a.max(c))
}

/// Writes the label or profile selection for the next `execve` of this process. AppArmor uses
/// `attr/apparmor/exec` (falling back to the legacy `attr/exec` on kernels without the
/// per-module directory); SELinux writes the label alone to `attr/exec`.
pub fn apply_exec(l: &Lsm) -> Result<(), kr_sys::Errno> {
    if let Some(p) = &l.apparmor {
        let cmd = apparmor_exec_command(p);
        if kr_sys::ns::write_file(b"/proc/self/attr/apparmor/exec\0", cmd.as_bytes()).is_err() {
            kr_sys::ns::write_file(b"/proc/self/attr/exec\0", cmd.as_bytes())?;
        }
    }
    if let Some(p) = &l.selinux_process {
        kr_sys::ns::write_file(b"/proc/self/attr/exec\0", p.as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loaded(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_the_profiles_file() {
        let t = "docker-default (enforce)\n/usr/bin/man (complain)\nlsb_release (enforce)\n";
        assert_eq!(parse_profiles(t), ["docker-default", "/usr/bin/man", "lsb_release"]);
    }

    #[test]
    fn apparmor_resolution_follows_upstream() {
        let l = loaded(&["docker-default", "mine"]);
        assert_eq!(resolve_apparmor("Unconfined", None, true, &l), Ok(None));
        assert_eq!(resolve_apparmor("RuntimeDefault", None, true, &l), Ok(Some("docker-default".into())));
        assert_eq!(resolve_apparmor("RuntimeDefault", None, true, &loaded(&["cri-containerd.apparmor.d", "docker-default"])), Ok(Some("cri-containerd.apparmor.d".into())));
        assert_eq!(resolve_apparmor("RuntimeDefault", None, true, &[]), Ok(None), "no default profile on the host");
        assert_eq!(resolve_apparmor("RuntimeDefault", None, false, &l), Ok(None), "AppArmor off: silently unconfined");
        assert_eq!(resolve_apparmor("Localhost", Some("mine"), true, &l), Ok(Some("mine".into())));
        assert!(resolve_apparmor("Localhost", Some("other"), true, &l).unwrap_err().contains("not loaded"));
        assert!(resolve_apparmor("Localhost", Some("mine"), false, &l).unwrap_err().contains("not enabled"));
        assert!(resolve_apparmor("Localhost", None, true, &l).is_err());
        assert!(resolve_apparmor("Localhost", Some("a b"), true, &l).is_err());
        assert!(resolve_apparmor("Bogus", None, true, &l).is_err());
    }

    #[test]
    fn annotation_values() {
        assert_eq!(parse_apparmor_annotation("runtime/default"), Ok(("RuntimeDefault", None)));
        assert_eq!(parse_apparmor_annotation("unconfined"), Ok(("Unconfined", None)));
        assert_eq!(parse_apparmor_annotation("localhost/mine"), Ok(("Localhost", Some("mine"))));
        assert!(parse_apparmor_annotation("mine").is_err());
        assert_eq!(apparmor_exec_command("mine"), "exec mine");
    }

    #[test]
    fn selinux_labels_fill_from_the_default() {
        let d = Some("system_u:system_r:container_t:s0");
        let o = SeOptions { level: "s0:c1,c2", ..Default::default() };
        assert_eq!(selinux_labels(&o, d, "container_file_t", "c7,c9").unwrap(), ("system_u:system_r:container_t:s0:c1,c2".into(), "system_u:object_r:container_file_t:s0:c1,c2".into()));
        let o = SeOptions { type_: "spc_t", ..Default::default() };
        assert_eq!(selinux_labels(&o, d, "container_file_t", "c7,c9").unwrap().0, "system_u:system_r:spc_t:s0:c7,c9");
        let o = SeOptions { user: "u", role: "r", type_: "t", level: "s0" };
        assert_eq!(selinux_labels(&o, None, "container_file_t", "c1,c2").unwrap().0, "u:r:t:s0:c1,c2");
        assert!(selinux_labels(&SeOptions { type_: "t", ..Default::default() }, None, "f", "c1,c2").is_err());
        assert!(selinux_labels(&SeOptions { type_: "t\",x", ..Default::default() }, d, "f", "c1,c2").is_err());
    }

    #[test]
    fn lxc_contexts_and_mcs() {
        let t = "process = \"system_u:system_r:container_t:s0\"\nfile = \"system_u:object_r:container_file_t:s0\"\nother = \"x\"\n";
        assert_eq!(parse_lxc_contexts(t), (Some("system_u:system_r:container_t:s0".into()), "container_file_t".into()));
        assert_eq!(parse_lxc_contexts(""), (None, "container_file_t".into()));
        assert_eq!(mcs_from(5, 3), "c3,c5");
        assert_eq!(mcs_from(5, 5 + 1024), "c5,c6");
        assert_eq!(mcs_from(1023, 1023), "c0,c1023");
    }
}
