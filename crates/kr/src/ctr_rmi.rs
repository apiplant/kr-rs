//! `kr ctr rmi <image|id>...` and `kr ctr rmi --prune` (#130): manual image removal, with the
//! in-use check of the image garbage collector (a container directory records its image).
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use kr_rt::{eprint, print, Args};
use kr_runtime::store::{ImageId, Store};

pub fn run(mut args: Args) -> i32 {
    let (mut prune, mut names) = (false, Vec::new());
    while let Some(a) = args.next() {
        match core::str::from_utf8(a) {
            Ok("--prune" | "-a") => prune = true,
            Ok(n) if !n.starts_with('-') => names.push(String::from(n)),
            _ => return usage(),
        }
    }
    if prune == !names.is_empty() {
        return usage();
    }
    let store = match Store::open(None) {
        Ok(s) => s,
        Err(e) => {
            eprint(format!("kr ctr rmi: open store: {e:?}\n").as_bytes());
            return 1;
        }
    };
    let Some(in_use) = store.images_in_use() else {
        eprint(b"kr ctr rmi: a container of an older release or `kr run` exists whose image is unknown; refusing to remove images\n");
        return 1;
    };
    let mut rc = 0;
    let targets: Vec<(String, ImageId)> = if prune {
        store.images().into_iter().filter(|(id, _)| !in_use.contains(&id.0)).map(|(id, _)| (id.0.clone(), id)).collect()
    } else {
        let mut t = Vec::new();
        for n in &names {
            match store.find_image(n) {
                Some(id) if in_use.contains(&id.0) => {
                    eprint(format!("kr ctr rmi: {n}: image is in use by a container\n").as_bytes());
                    rc = 1;
                }
                Some(id) => t.push((n.clone(), id)),
                None => {
                    eprint(format!("kr ctr rmi: {n}: no such image\n").as_bytes());
                    rc = 1;
                }
            }
        }
        t
    };
    for (n, id) in targets {
        match store.remove_image(&id) {
            Ok((l, b)) => print(format!("removed {n} ({l} layers, {b} blobs)\n").as_bytes()),
            Err(e) => {
                eprint(format!("kr ctr rmi: {n}: {e:?}\n").as_bytes());
                rc = 1;
            }
        }
    }
    if prune {
        // Blobs that no manifest names (images installed before the layered store, aborted
        // pulls); the hour keeps a concurrent pull's fresh blobs.
        let n = store.sweep_blobs((kr_rt::exec::now_ns() / 1_000_000_000) as i64, 3600);
        print(format!("removed {n} unreferenced blobs\n").as_bytes());
    }
    rc
}

fn usage() -> i32 {
    eprint(b"usage: kr ctr rmi <image|id>...\n       kr ctr rmi --prune\n");
    2
}
