//! Manifest auto-deploy (ADR-043): at start and every 20 s `kr server` applies every `*.yaml`,
//! `*.yml` and `*.json` file of `<data dir>/manifests` with server-side apply through the
//! in-process client (field manager `kr-manifests`, conflicts forced). Objects get the annotation
//! `kr.io/manifest-file: <file name>`. Removing a file or an object from a file deletes nothing.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_apiserver::client::{Client, InProcess};
use kr_fmt::json::Value;
use kr_rt::{eprint, print};
use kr_sys::fs;

pub const ANNOTATION: &str = "kr.io/manifest-file";
const PERIOD_MS: u64 = 20_000;
const MAX_FILE: usize = 4 << 20;

pub fn dir(data: &str) -> String {
    format!("{data}/manifests")
}

/// File names to apply, sorted (so Namespaces and CRDs named `00-*` go first).
pub fn list(dir: &str) -> Vec<String> {
    let mut c = Vec::from(dir.as_bytes());
    c.push(0);
    let Ok(fd) = fs::openat(fs::AT_FDCWD, &c, fs::O_RDONLY | fs::O_DIRECTORY | fs::O_CLOEXEC, 0) else { return Vec::new() };
    let mut v: Vec<String> = fs::read_dir(&fd).filter_map(|e| e.ok()).filter(|e| e.kind != fs::DT_DIR).filter_map(|e| String::from_utf8(e.name).ok()).filter(|n| wanted(n)).collect();
    v.sort();
    v
}

pub fn wanted(name: &str) -> bool {
    !name.starts_with('.') && (name.ends_with(".yaml") || name.ends_with(".yml") || name.ends_with(".json"))
}

/// The objects of a file: every YAML document, with `kind: List` expanded.
pub fn objects(text: &str) -> Result<Vec<Value>, String> {
    let docs = kr_fmt::yaml::parse_all(text).map_err(|e| format!("parse error: {e:?}"))?;
    let mut out = Vec::new();
    for d in docs {
        if d.is_null() {
            continue;
        }
        let items = d.get("kind").and_then(Value::as_str).filter(|k| k.ends_with("List")).and(d.get("items")).and_then(Value::as_array).map(|a| a.to_vec());
        match items {
            Some(items) => out.extend(items),
            None => out.push(d),
        }
    }
    Ok(out)
}

/// Sets `metadata.annotations[kr.io/manifest-file]`.
pub fn annotate(o: &mut Value, file: &str) {
    if o.get("metadata").is_none_or(|m| m.as_object().is_none()) {
        o.set("metadata", Value::Object(Vec::new()));
    }
    let md = o.get_mut("metadata").unwrap();
    if md.get("annotations").is_none_or(|m| m.as_object().is_none()) {
        md.set("annotations", Value::Object(Vec::new()));
    }
    md.get_mut("annotations").unwrap().set(ANNOTATION, Value::from(file));
}

/// `/api/v1` or `/apis/<group>/<version>`.
pub fn group_version_path(api_version: &str) -> String {
    if api_version.contains('/') { format!("/apis/{api_version}") } else { format!("/api/{api_version}") }
}

async fn apply_object(c: &InProcess, disco: &mut BTreeMap<String, Value>, mut o: Value, file: &str) -> Result<String, String> {
    let api_version = o.get("apiVersion").and_then(Value::as_str).ok_or("object without apiVersion")?.to_string();
    let kind = o.get("kind").and_then(Value::as_str).ok_or("object without kind")?.to_string();
    let name = o.pointer(&["metadata", "name"]).and_then(Value::as_str).ok_or("object without metadata.name")?.to_string();
    let gv = group_version_path(&api_version);
    if !disco.contains_key(&gv) {
        let l = c.get(&gv).await.map_err(|e| format!("discovery of {api_version}: {}", e.message))?;
        disco.insert(gv.clone(), l);
    }
    let res = disco[&gv].get("resources").and_then(Value::as_array).and_then(|r| r.iter().find(|r| r.get("kind").and_then(Value::as_str) == Some(&kind) && r.get("name").and_then(Value::as_str).is_some_and(|n| !n.contains('/')))).ok_or_else(|| format!("no resource of kind {kind} in {api_version} (yet)"))?;
    let plural = res.get("name").and_then(Value::as_str).unwrap_or("").to_string();
    let namespaced = matches!(res.get("namespaced"), Some(Value::Bool(true)));
    annotate(&mut o, file);
    let path = if namespaced {
        let ns = o.pointer(&["metadata", "namespace"]).and_then(Value::as_str).filter(|n| !n.is_empty()).unwrap_or("default").to_string();
        format!("{gv}/namespaces/{ns}/{plural}/{name}")
    } else {
        format!("{gv}/{plural}/{name}")
    };
    c.patch(&format!("{path}?fieldManager=kr-manifests&force=true"), "application/apply-patch+yaml", &o).await.map_err(|e| format!("{}: {}", e.code, e.message))?;
    Ok(format!("{kind}/{name}"))
}

/// One pass over the directory. `last` remembers each file's content and outcome, so the log
/// only speaks when something changed.
pub async fn pass(c: &InProcess, dir: &str, last: &mut BTreeMap<String, (Vec<u8>, String)>) {
    let mut disco = BTreeMap::new();
    for f in list(dir) {
        let mut p = Vec::from(format!("{dir}/{f}").as_bytes());
        p.push(0);
        let text = match fs::read_file(&p, MAX_FILE) {
            Ok(t) => t,
            Err(e) => {
                note(last, &f, Vec::new(), format!("cannot read: errno {}", e.0), true);
                continue;
            }
        };
        let (mut applied, mut errs) = (Vec::new(), Vec::new());
        match core::str::from_utf8(&text).map_err(|_| String::from("not UTF-8")).and_then(objects) {
            Ok(objs) => {
                for o in objs {
                    match apply_object(c, &mut disco, o, &f).await {
                        Ok(n) => applied.push(n),
                        Err(e) => errs.push(e),
                    }
                }
            }
            Err(e) => errs.push(e),
        }
        let state = if errs.is_empty() { format!("applied {}", applied.join(", ")) } else { format!("{} (applied {})", errs.join("; "), applied.len()) };
        note(last, &f, text, state, !errs.is_empty());
    }
}

fn note(last: &mut BTreeMap<String, (Vec<u8>, String)>, f: &str, text: Vec<u8>, state: String, failed: bool) {
    if last.get(f).is_some_and(|(_, s)| *s == state) {
        return;
    }
    let line = format!("kr server: manifests: {f}: {state}\n");
    if failed { eprint(line.as_bytes()) } else { print(line.as_bytes()) }
    last.insert(String::from(f), (text, state));
}

/// Runs for the life of the server.
pub async fn run(c: InProcess, dir: String) {
    let mut last = BTreeMap::new();
    loop {
        pass(&c, &dir, &mut last).await;
        kr_rt::exec::sleep(PERIOD_MS).await;
    }
}
