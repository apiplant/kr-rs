//! The configuration file of `kr server` and `kr agent` (ADR-060).
//!
//! `/etc/kr/config.yaml` (or `--config FILE` / `KR_CONFIG`) is a YAML mapping whose keys are the
//! command-line flags without the leading dashes, as in k3s:
//!
//! ```yaml
//! tls-san: [kube.example.com, 203.0.113.7]
//! node-label: ["zone=a"]
//! disable: servicelb
//! cluster-init: true
//! ```
//!
//! Files in `<config>.d/*.yaml` (`config.yaml.d/` by default) are merged over it in lexical
//! order: a key replaces the earlier value, `key+` appends to it. The result becomes flags that
//! come *before* the real command line, so scalar flags given on the command line win and
//! repeatable ones (`tls-san`, `node-label`, `node-taint`, `disable`) accumulate.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_fmt::json::Value;

pub const DEFAULT_PATH: &str = "/etc/kr/config.yaml";

/// Flags that take no value: `true` emits the bare flag, `false` nothing.
const BOOL_FLAGS: &[&str] = &["cluster-init"];

/// Removes `--config FILE` / `--config=FILE` from `argv`; returns the path (explicit: the file
/// must exist) from it, else `KR_CONFIG`, else the default.
pub fn take_config_flag(argv: &mut Vec<String>, env: Option<String>) -> Result<(String, bool), String> {
    let mut path = None;
    let mut i = 0;
    while i < argv.len() {
        if argv[i] == "--config" {
            if i + 1 >= argv.len() {
                return Err("--config needs a file".into());
            }
            path = Some(argv.remove(i + 1));
            argv.remove(i);
        } else if let Some(v) = argv[i].strip_prefix("--config=") {
            path = Some(v.to_string());
            argv.remove(i);
        } else {
            i += 1;
        }
    }
    Ok(match path.or(env.filter(|e| !e.is_empty())) {
        Some(p) => (p, true),
        None => (DEFAULT_PATH.to_string(), false),
    })
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.raw().to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Merges parsed documents (later over earlier) into an ordered key list.
pub fn merge(docs: Vec<(String, Value)>) -> Result<Vec<(String, Value)>, String> {
    let mut out: Vec<(String, Value)> = Vec::new();
    for (origin, doc) in docs {
        let Some(map) = (match &doc {
            Value::Null => Some(&[][..]),
            d => d.as_object(),
        }) else {
            return Err(alloc::format!("{origin}: the configuration must be a YAML mapping"));
        };
        for (k, v) in map {
            let k = k.trim_start_matches('-');
            let (key, append) = match k.strip_suffix('+') {
                Some(b) => (b, true),
                None => (k, false),
            };
            if key.is_empty() {
                return Err(alloc::format!("{origin}: empty key"));
            }
            let pos = out.iter().position(|(ek, _)| ek == key);
            match (pos, append) {
                (Some(i), true) => {
                    let mut items = match &out[i].1 {
                        Value::Array(a) => a.clone(),
                        Value::Null => Vec::new(),
                        s => alloc::vec![s.clone()],
                    };
                    match v {
                        Value::Array(a) => items.extend(a.iter().cloned()),
                        Value::Null => {}
                        s => items.push(s.clone()),
                    }
                    out[i].1 = Value::Array(items);
                }
                (Some(i), false) => out[i].1 = v.clone(),
                (None, _) => out.push((key.to_string(), v.clone())),
            }
        }
    }
    Ok(out)
}

/// Flags (`--key`, `value` pairs, one flag per list element) for a merged configuration.
pub fn to_args(merged: &[(String, Value)]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for (k, v) in merged {
        if k == "config" {
            continue;
        }
        let flag = alloc::format!("--{k}");
        match v {
            Value::Null => {}
            Value::Bool(b) if BOOL_FLAGS.contains(&k.as_str()) => {
                if *b {
                    out.push(flag);
                }
            }
            Value::Array(items) => {
                for it in items {
                    let s = scalar(it).ok_or_else(|| alloc::format!("configuration key {k}: list items must be scalars"))?;
                    out.push(flag.clone());
                    out.push(s);
                }
            }
            v => {
                let s = scalar(v).ok_or_else(|| alloc::format!("configuration key {k}: a scalar or a list is expected"))?;
                out.push(flag);
                out.push(s);
            }
        }
    }
    Ok(out)
}

/// Builds the effective argument list: configuration flags, then `cli`. `read(path)` returns a
/// file's text (`None` if absent), `list(dir)` the names in a directory.
pub fn expand(
    mut cli: Vec<String>,
    env_config: Option<String>,
    read: &dyn Fn(&str) -> Option<String>,
    list: &dyn Fn(&str) -> Vec<String>,
) -> Result<Vec<String>, String> {
    let (path, explicit) = take_config_flag(&mut cli, env_config)?;
    let mut docs = Vec::new();
    match read(&path) {
        Some(t) => docs.push((path.clone(), kr_fmt::yaml::parse(&t).map_err(|e| alloc::format!("{path}: {e}"))?)),
        None if explicit => return Err(alloc::format!("cannot read configuration file {path}")),
        None => {}
    }
    let dir = alloc::format!("{path}.d");
    let mut names: Vec<String> = list(&dir).into_iter().filter(|n| !n.starts_with('.') && (n.ends_with(".yaml") || n.ends_with(".yml"))).collect();
    names.sort();
    for n in names {
        let p = alloc::format!("{dir}/{n}");
        if let Some(t) = read(&p) {
            docs.push((p.clone(), kr_fmt::yaml::parse(&t).map_err(|e| alloc::format!("{p}: {e}"))?));
        }
    }
    let mut args = to_args(&merge(docs)?)?;
    args.extend(cli);
    Ok(args)
}

/// [`expand`] on the real file system, with `KR_CONFIG` from the environment.
pub fn load(cli: Vec<String>) -> Result<Vec<String>, String> {
    let read = |p: &str| {
        let mut c = p.as_bytes().to_vec();
        c.push(0);
        kr_sys::fs::read_file(&c, 1 << 20).ok().and_then(|b| String::from_utf8(b).ok())
    };
    let list = |d: &str| {
        let mut c = d.as_bytes().to_vec();
        c.push(0);
        let Ok(fd) = kr_sys::fs::openat(kr_sys::fs::AT_FDCWD, &c, kr_sys::fs::O_RDONLY | kr_sys::fs::O_DIRECTORY | kr_sys::fs::O_CLOEXEC, 0) else { return Vec::new() };
        kr_sys::fs::read_dir(&fd).filter_map(|e| e.ok()).filter(|e| e.kind != kr_sys::fs::DT_DIR).filter_map(|e| String::from_utf8(e.name).ok()).collect()
    };
    expand(cli, crate::store::env_var("KR_CONFIG"), &read, &list)
}

/// Handles the repeatable node/install flags shared by `server` and `agent`: collects the values
/// and, once done, publishes them as `KR_*` overrides so that flags win over the environment.
#[derive(Default)]
pub struct Install {
    pub tls_san: Vec<String>,
    pub node_name: Option<String>,
    pub node_label: Vec<String>,
    pub node_taint: Vec<String>,
    pub node_ip: Option<String>,
    pub node_external_ip: Option<String>,
    pub disable: Vec<String>,
}

impl Install {
    /// Takes `flag value` if it is one of ours.
    pub fn take(&mut self, flag: &[u8], value: &str) -> bool {
        match flag {
            b"--tls-san" => self.tls_san.extend(value.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty())),
            b"--node-name" => self.node_name = Some(value.to_string()),
            b"--node-label" => self.node_label.push(value.to_string()),
            b"--node-taint" => self.node_taint.push(value.to_string()),
            b"--node-ip" | b"-i" => self.node_ip = Some(value.to_string()),
            b"--node-external-ip" => self.node_external_ip = Some(value.to_string()),
            b"--disable" => self.disable.push(value.to_string()),
            _ => return false,
        }
        true
    }

    /// Environment variable and value for each setting that was given.
    pub fn vars(&self) -> Vec<(&'static str, String)> {
        let mut v = Vec::new();
        let mut put = |k: &'static str, val: Option<String>| {
            if let Some(val) = val {
                v.push((k, val));
            }
        };
        put("KR_TLS_SAN", (!self.tls_san.is_empty()).then(|| self.tls_san.join(",")));
        put("KR_NODE_NAME", self.node_name.clone());
        put("KR_NODE_LABELS", (!self.node_label.is_empty()).then(|| self.node_label.join(",")));
        put("KR_NODE_TAINTS", (!self.node_taint.is_empty()).then(|| self.node_taint.join(",")));
        put("KR_NODE_IP", self.node_ip.clone());
        put("KR_NODE_EXTERNAL_IP", self.node_external_ip.clone());
        put("KR_DISABLE", (!self.disable.is_empty()).then(|| self.disable.join(",")));
        v
    }

    pub fn publish(&self) {
        for (k, val) in self.vars() {
            crate::store::set_override(k, &val);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn run(cli: &[&str], files: &[(&str, &str)], env: Option<&str>) -> Result<Vec<String>, String> {
        let files: Vec<(String, String)> = files.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
        let read = |p: &str| files.iter().find(|(f, _)| f == p).map(|(_, t)| t.clone());
        let list = |d: &str| files.iter().filter_map(|(f, _)| f.strip_prefix(d)?.strip_prefix('/').map(String::from)).collect::<Vec<_>>();
        expand(s(cli), env.map(String::from), &read, &list)
    }

    #[test]
    fn keys_become_flags_before_the_command_line() {
        let cfg = "port: 7443\ncluster-init: true\ntls-san:\n  - a.example.com\n  - 10.0.0.1\nnode-label: zone=a\ndisable: [servicelb, metrics-server]\n# comment\nsnapshot-keep: 3\nunused: null\n";
        let a = run(&["--port", "9000"], &[(DEFAULT_PATH, cfg)], None).unwrap();
        assert_eq!(
            a,
            s(&["--port", "7443", "--cluster-init", "--tls-san", "a.example.com", "--tls-san", "10.0.0.1", "--node-label", "zone=a", "--disable", "servicelb", "--disable", "metrics-server", "--snapshot-keep", "3", "--port", "9000"])
        );
    }

    #[test]
    fn false_bool_and_leading_dashes() {
        let a = run(&[], &[(DEFAULT_PATH, "cluster-init: false\n\"--data\": /x\n")], None).unwrap();
        assert_eq!(a, s(&["--data", "/x"]));
    }

    #[test]
    fn drop_ins_merge_in_lexical_order() {
        let base = "tls-san: [a]\nport: 1\nnode-name: base\n";
        let d1 = "port: 2\ntls-san+: [b]\n";
        let d2 = "port: 3\nnode-name: late\ntls-san+: c\n";
        let d0 = "node-name: first\n";
        let files = [(DEFAULT_PATH, base), ("/etc/kr/config.yaml.d/20-b.yaml", d2), ("/etc/kr/config.yaml.d/10-a.yaml", d1), ("/etc/kr/config.yaml.d/00.yml", d0), ("/etc/kr/config.yaml.d/ignored.txt", "port: 99")];
        let a = run(&[], &files, None).unwrap();
        assert_eq!(a, s(&["--tls-san", "a", "--tls-san", "b", "--tls-san", "c", "--port", "3", "--node-name", "late"]));
    }

    #[test]
    fn plain_key_replaces_a_list() {
        let a = run(&[], &[(DEFAULT_PATH, "tls-san: [a, b]\n"), ("/etc/kr/config.yaml.d/x.yaml", "tls-san: [z]\n")], None).unwrap();
        assert_eq!(a, s(&["--tls-san", "z"]));
    }

    #[test]
    fn config_flag_env_and_missing_files() {
        // The default file may be absent; an explicit one may not.
        assert_eq!(run(&["--port", "1"], &[], None).unwrap(), s(&["--port", "1"]));
        assert!(run(&["--config", "/nope.yaml"], &[], None).is_err());
        assert!(run(&[], &[], Some("/nope.yaml")).is_err());
        let files = [("/my.yaml", "node-name: n1\n"), ("/my.yaml.d/a.yaml", "node-name: n2\n")];
        assert_eq!(run(&["--config=/my.yaml"], &files, None).unwrap(), s(&["--node-name", "n2"]));
        assert_eq!(run(&["--config", "/my.yaml", "--node-name", "cli"], &files, None).unwrap(), s(&["--node-name", "n2", "--node-name", "cli"]));
        assert_eq!(run(&[], &files, Some("/my.yaml")).unwrap(), s(&["--node-name", "n2"]));
        assert!(run(&["--config"], &[], None).is_err());
    }

    #[test]
    fn rejects_bad_documents() {
        assert!(run(&[], &[(DEFAULT_PATH, "- a\n- b\n")], None).is_err());
        assert!(run(&[], &[(DEFAULT_PATH, "x: {a: b}\n")], None).is_err());
        assert!(run(&[], &[(DEFAULT_PATH, "x: [[1]]\n")], None).is_err());
        assert!(run(&[], &[(DEFAULT_PATH, "a: [unterminated\n")], None).is_err());
        assert_eq!(run(&[], &[(DEFAULT_PATH, "")], None).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn install_flags_to_vars() {
        let mut i = Install::default();
        assert!(i.take(b"--tls-san", "a.example.com, 10.0.0.1"));
        assert!(i.take(b"--tls-san", "b"));
        assert!(i.take(b"--node-label", "a=b"));
        assert!(i.take(b"--node-label", "c=d"));
        assert!(i.take(b"--node-taint", "k=v:NoSchedule"));
        assert!(i.take(b"--disable", "servicelb"));
        assert!(i.take(b"--disable", "metrics-server"));
        assert!(i.take(b"--node-name", "n"));
        assert!(!i.take(b"--port", "1"));
        let v = i.vars();
        assert!(v.contains(&("KR_TLS_SAN", "a.example.com,10.0.0.1,b".into())));
        assert!(v.contains(&("KR_NODE_LABELS", "a=b,c=d".into())));
        assert!(v.contains(&("KR_NODE_TAINTS", "k=v:NoSchedule".into())));
        assert!(v.contains(&("KR_DISABLE", "servicelb,metrics-server".into())));
        assert!(v.contains(&("KR_NODE_NAME", "n".into())));
        assert_eq!(v.len(), 5);
    }
}
