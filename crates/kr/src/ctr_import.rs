//! `kr ctr import <file>...`: loads image archives (docker save / OCI layout, `.tar`,
//! `.tar.gz`) into the local image store without network (ADR-044).
use alloc::string::String;
use alloc::format;
use kr_rt::{eprint, print, Args};
use kr_runtime::store::Store;

pub fn run(mut args: Args) -> i32 {
    let store = match Store::open(None) {
        Ok(s) => s,
        Err(e) => {
            eprint(format!("kr ctr: open store: {e:?}\n").as_bytes());
            return 1;
        }
    };
    let mut n = 0;
    let mut rc = 0;
    while let Some(a) = args.next() {
        let Ok(path) = core::str::from_utf8(a) else {
            eprint(b"kr ctr import: file name is not UTF-8\n");
            return 2;
        };
        n += 1;
        match kr_runtime::import::import_file(&store, path) {
            Ok(ids) => ids.iter().for_each(|id| print(format!("{path}: {id}\n").as_bytes())),
            Err(e) => {
                eprint(format!("kr ctr import: {path}: {e:?}\n").as_bytes());
                rc = 1;
            }
        }
    }
    if n == 0 {
        eprint(b"usage: kr ctr import <file.tar[.gz]>...\n");
        return 2;
    }
    rc
}

/// Node start: imports `<store root>/agent/images` once per file (ADR-044), and `extra` too (an
/// agent started with `--data DIR` looks in `DIR/images` as well).
pub fn import_startup(store: &Store, extra: Option<&str>) {
    let main = format!("{}/agent/images", store.root().trim_end_matches('/'));
    let mut dirs = alloc::vec![main.clone()];
    if let Some(e) = extra.filter(|e| *e != main) {
        dirs.push(String::from(e));
    }
    for dir in dirs {
        for o in kr_runtime::import::import_dir_once(store, &dir) {
            match o.result {
                Ok(ids) => print(format!("kr: imported {} ({} image(s))\n", o.file, ids.len()).as_bytes()),
                Err(e) => eprint(format!("kr: import {}: {e:?}\n", o.file).as_bytes()),
            }
        }
    }
}
