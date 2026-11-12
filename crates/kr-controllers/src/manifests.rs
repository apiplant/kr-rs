//! Manifest auto-deploy (ADR-043, ADR-061): at start and every 20 s `kr server` applies every
//! `*.yaml`, `*.yml` and `*.json` file of `<data dir>/manifests` with server-side apply through the
//! in-process client (field manager `kr-manifests`, conflicts forced). Objects get the annotation
//! `kr.io/manifest-file: <file name>`.
//!
//! Like the k3s addon controller, the objects of a file are deleted when the file goes away, and
//! an object that disappears from a file is deleted too. What each file created is remembered in
//! the ConfigMap `kube-system/kr-manifests` (key `state.json`), so this also works across
//! restarts. An object is deleted only while it still carries the annotation of that file (one
//! moved to another file, or taken over by hand, stays), never after a pass with errors for that
//! file, and never when the directory cannot be read.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kr_apiserver::client::Client;
use kr_fmt::json::Value;
use kr_rt::{eprint, print};

pub const ANNOTATION: &str = "kr.io/manifest-file";
pub const STATE_PATH: &str = "/api/v1/namespaces/kube-system/configmaps/kr-manifests";
const PERIOD_MS: u64 = 20_000;
const MAX_FILE: usize = 4 << 20;

/// File name -> paths of the objects it created.
pub type State = BTreeMap<String, Vec<String>>;

pub fn dir(data: &str) -> String {
    format!("{data}/manifests")
}

/// The wanted file names, sorted (so Namespaces and CRDs named `00-*` go first); `None` when the
/// directory cannot be opened.
pub fn list_opt(dir: &str) -> Option<Vec<String>> {
    use kr_sys::fs;
    let mut c = Vec::from(dir.as_bytes());
    c.push(0);
    let fd = fs::openat(fs::AT_FDCWD, &c, fs::O_RDONLY | fs::O_DIRECTORY | fs::O_CLOEXEC, 0).ok()?;
    let mut v: Vec<String> = fs::read_dir(&fd).filter_map(|e| e.ok()).filter(|e| e.kind != fs::DT_DIR).filter_map(|e| String::from_utf8(e.name).ok()).filter(|n| wanted(n)).collect();
    v.sort();
    Some(v)
}

pub fn list(dir: &str) -> Vec<String> {
    list_opt(dir).unwrap_or_default()
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

/// Applies one object; returns `(Kind/name, path)`.
async fn apply_object<C: Client>(c: &C, disco: &mut BTreeMap<String, Value>, mut o: Value, file: &str) -> Result<(String, String), String> {
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
    Ok((format!("{kind}/{name}"), path))
}

pub fn state_to_json(s: &State) -> String {
    let mut files = Value::Object(Vec::new());
    for (f, paths) in s {
        files.set(f, Value::Array(paths.iter().map(|p| Value::from(p.as_str())).collect()));
    }
    let mut root = Value::Object(Vec::new());
    root.set("files", files);
    kr_fmt::json::to_string(&root)
}

pub fn state_from_json(text: &str) -> State {
    let mut out = State::new();
    if let Some(files) = kr_fmt::json::parse_str(text).ok().and_then(|v| v.get("files").and_then(Value::as_object).map(|o| o.to_vec())) {
        for (f, paths) in files {
            out.insert(f, paths.as_array().unwrap_or(&[]).iter().filter_map(|p| p.as_str().map(String::from)).collect());
        }
    }
    out
}

async fn load_state<C: Client>(c: &C) -> State {
    match c.get(STATE_PATH).await {
        Ok(cm) => cm.pointer(&["data", "state.json"]).and_then(Value::as_str).map(state_from_json).unwrap_or_default(),
        Err(_) => State::new(),
    }
}

async fn save_state<C: Client>(c: &C, s: &State) {
    let mut cm = Value::Object(Vec::new());
    cm.set("apiVersion", Value::from("v1"));
    cm.set("kind", Value::from("ConfigMap"));
    let mut md = Value::Object(Vec::new());
    md.set("name", Value::from("kr-manifests"));
    md.set("namespace", Value::from("kube-system"));
    cm.set("metadata", md);
    let mut data = Value::Object(Vec::new());
    data.set("state.json", Value::from(state_to_json(s)));
    cm.set("data", data);
    if let Err(e) = c.patch(&format!("{STATE_PATH}?fieldManager=kr-manifests&force=true"), "application/apply-patch+yaml", &cm).await {
        eprint(format!("kr server: manifests: cannot save the state: {}\n", e.message).as_bytes());
    }
}

/// What to delete: the recorded objects of files that are gone, and of present files the object
/// of which they no longer contain (only for files whose pass had no errors).
pub fn stale(old: &State, new: &State, present: &BTreeSet<String>, clean: &BTreeSet<String>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (f, paths) in old {
        let keep: &[String] = if present.contains(f) {
            if !clean.contains(f) {
                continue;
            }
            new.get(f).map(|v| v.as_slice()).unwrap_or(&[])
        } else {
            &[]
        };
        for p in paths.iter().filter(|p| !keep.contains(p)) {
            out.push((f.clone(), p.clone()));
        }
    }
    out
}

/// One pass over the directory. `last` remembers each file's content and outcome, so the log
/// only speaks when something changed; `state` is what the files created so far.
pub async fn pass<C: Client>(c: &C, dir: &str, last: &mut BTreeMap<String, (Vec<u8>, String)>, state: &mut State) {
    let Some(files) = list_opt(dir) else { return };
    let mut disco = BTreeMap::new();
    let (mut new, mut clean, mut present) = (State::new(), BTreeSet::new(), BTreeSet::new());
    for f in files {
        present.insert(f.clone());
        let mut p = Vec::from(format!("{dir}/{f}").as_bytes());
        p.push(0);
        let text = match kr_sys::fs::read_file(&p, MAX_FILE) {
            Ok(t) => t,
            Err(e) => {
                note(last, &f, Vec::new(), format!("cannot read: errno {}", e.0), true);
                continue;
            }
        };
        let (mut applied, mut paths, mut errs) = (Vec::new(), Vec::new(), Vec::new());
        match core::str::from_utf8(&text).map_err(|_| String::from("not UTF-8")).and_then(objects) {
            Ok(objs) => {
                for o in objs {
                    match apply_object(c, &mut disco, o, &f).await {
                        Ok((n, path)) => {
                            applied.push(n);
                            paths.push(path);
                        }
                        Err(e) => errs.push(e),
                    }
                }
            }
            Err(e) => errs.push(e),
        }
        let state_text = if errs.is_empty() { format!("applied {}", applied.join(", ")) } else { format!("{} (applied {})", errs.join("; "), applied.len()) };
        note(last, &f, text, state_text, !errs.is_empty());
        if errs.is_empty() {
            clean.insert(f.clone());
        } else if let Some(old) = state.get(&f) {
            // Keep what the file created before: a later clean pass may still delete it.
            for p in old {
                if !paths.contains(p) {
                    paths.push(p.clone());
                }
            }
        }
        new.insert(f, paths);
    }
    for (f, path) in stale(state, &new, &present, &clean) {
        match c.get(&path).await {
            Ok(o) if o.pointer(&["metadata", "annotations", ANNOTATION]).and_then(Value::as_str) == Some(f.as_str()) => match c.delete(&path).await {
                Ok(_) => print(format!("kr server: manifests: {f} no longer has {path}: deleted\n").as_bytes()),
                Err(e) if e.code == 404 => {}
                Err(e) => {
                    eprint(format!("kr server: manifests: deleting {path}: {}\n", e.message).as_bytes());
                    // Try again in the next pass.
                    new.entry(f.clone()).or_default().push(path.clone());
                }
            },
            Ok(_) | Err(_) => {}
        }
    }
    if new != *state {
        save_state(c, &new).await;
        *state = new;
    }
    last.retain(|f, _| present.contains(f));
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
pub async fn run<C: Client>(c: C, dir: String) {
    let mut last = BTreeMap::new();
    let mut state = load_state(&c).await;
    loop {
        pass(&c, &dir, &mut last, &mut state).await;
        kr_rt::exec::sleep(PERIOD_MS).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(items: &[(&str, &[&str])]) -> State {
        items.iter().map(|(f, p)| (f.to_string(), p.iter().map(|x| x.to_string()).collect())).collect()
    }
    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn state_round_trip() {
        let s = st(&[("a.yaml", &["/api/v1/namespaces/x"]), ("b.yaml", &[])]);
        assert_eq!(state_from_json(&state_to_json(&s)), s);
        assert!(state_from_json("garbage").is_empty());
    }

    #[test]
    fn stale_objects() {
        let old = st(&[("gone.yaml", &["/p1", "/p2"]), ("edited.yaml", &["/p3", "/p4"]), ("broken.yaml", &["/p5"])]);
        let new = st(&[("edited.yaml", &["/p3"]), ("broken.yaml", &[])]);
        let del = stale(&old, &new, &set(&["edited.yaml", "broken.yaml"]), &set(&["edited.yaml"]));
        assert_eq!(del, [("edited.yaml".to_string(), "/p4".to_string()), ("gone.yaml".to_string(), "/p1".to_string()), ("gone.yaml".to_string(), "/p2".to_string())]);
    }

    const CM: &str = "/api/v1/namespaces/default/configmaps";

    fn cm(name: &str) -> String {
        format!("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {name}\ndata:\n  k: v\n")
    }

    async fn exists<C: Client>(c: &C, n: &str) -> bool {
        c.get(&format!("{CM}/{n}")).await.is_ok()
    }

    #[test]
    fn deleting_a_file_or_an_object_deletes_what_it_created() {
        use crate::tests::scenario;
        let dir = alloc::format!("{}/../../target/test-manifests-{}", env!("CARGO_MANIFEST_DIR"), std::process::id());
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let d = dir.clone();
        scenario(move |c| async move {
            std::fs::write(format!("{d}/a.yaml"), format!("{}---\n{}", cm("a1"), cm("a2"))).unwrap();
            std::fs::write(format!("{d}/b.yaml"), cm("b1")).unwrap();
            let (mut last, mut state) = (BTreeMap::new(), State::new());
            pass(&c, &d, &mut last, &mut state).await;
            assert!(exists(&c, "a1").await && exists(&c, "a2").await && exists(&c, "b1").await);
            let a1 = c.get(&format!("{CM}/a1")).await.unwrap();
            assert_eq!(a1.pointer(&["metadata", "annotations", ANNOTATION]).and_then(Value::as_str), Some("a.yaml"));
            assert_eq!(state.len(), 2);
            // The state survives a restart.
            let mut state = load_state(&c).await;
            assert_eq!(state.get("a.yaml").map(|v| v.len()), Some(2));

            // An object dropped from its file goes; the rest stays.
            std::fs::write(format!("{d}/a.yaml"), cm("a1")).unwrap();
            pass(&c, &d, &mut last, &mut state).await;
            assert!(exists(&c, "a1").await && !exists(&c, "a2").await && exists(&c, "b1").await);

            // A file with an error deletes nothing.
            std::fs::write(format!("{d}/a.yaml"), "kind: [unterminated\n").unwrap();
            pass(&c, &d, &mut last, &mut state).await;
            assert!(exists(&c, "a1").await);

            // An object taken over by another owner is not deleted with its file.
            std::fs::write(format!("{d}/a.yaml"), cm("a1")).unwrap();
            pass(&c, &d, &mut last, &mut state).await;
            c.patch(&format!("{CM}/b1"), "application/merge-patch+json", &crate::tests::v(r#"{"metadata":{"annotations":{"kr.io/manifest-file":"other.yaml"}}}"#)).await.unwrap();
            // A directory that cannot be read deletes nothing.
            pass(&c, "/nonexistent-kr-dir", &mut last, &mut state).await;
            assert!(exists(&c, "a1").await);
            std::fs::remove_file(format!("{d}/b.yaml")).unwrap();
            std::fs::remove_file(format!("{d}/a.yaml")).unwrap();
            pass(&c, &d, &mut last, &mut state).await;
            assert!(!exists(&c, "a1").await);
            assert!(exists(&c, "b1").await, "taken over by another owner");
            assert!(state.is_empty(), "{state:?}");
        });
        let _ = std::fs::remove_dir_all(&dir);
    }
}
