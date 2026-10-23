#![allow(dead_code)]
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n + 8);
        while v.len() < n {
            v.extend_from_slice(&self.next().to_le_bytes());
        }
        v.truncate(n);
        v
    }
}

const WORDS: &[&str] = &[
    "kubernetes", "container", "image", "layer", "the", "of", "and", "pod", "node", "cluster",
    "registry", "manifest", "digest", "overlay", "namespace", "cgroup", "runtime", "kubelet",
    "scheduler", "controller", "service", "ingress", "volume", "secret", "config", "deployment",
];

pub fn text(rng: &mut Rng, n: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(n + 32);
    while v.len() < n {
        v.extend_from_slice(WORDS[rng.below(WORDS.len())].as_bytes());
        v.push(if rng.below(12) == 0 { b'\n' } else { b' ' });
    }
    v.truncate(n);
    v
}

/// Mixed payload: random and text segments, plus runs.
pub fn mixed(rng: &mut Rng, n: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(n);
    while v.len() < n {
        let seg = 1 + rng.below(70_000);
        match rng.below(4) {
            0 => v.extend(rng.bytes(seg)),
            1 | 2 => v.extend(text(rng, seg)),
            _ => {
                let b = rng.next() as u8;
                v.extend(std::iter::repeat_n(b, seg));
            }
        }
    }
    v.truncate(n);
    v
}

pub fn scratch(name: &str) -> PathBuf {
    let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

pub fn pipe(cmd: &str, args: &[&str], input: &[u8]) -> Vec<u8> {
    let mut c = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = c.stdin.take().unwrap();
    let data = input.to_vec();
    let t = std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });
    let out = c.wait_with_output().unwrap();
    t.join().unwrap();
    assert!(out.status.success(), "{cmd} failed");
    out.stdout
}

pub fn gzip(data: &[u8], level: u8) -> Vec<u8> {
    pipe("gzip", &[&format!("-{level}"), "-c"], data)
}

pub fn run(cmd: &str, args: &[&str]) {
    let st = Command::new(cmd).args(args).status().unwrap();
    assert!(st.success(), "{cmd} {args:?} failed");
}

/// Split `data` into chunks according to `mode`: 0 = whole, 1 = one byte,
/// n>1 = random sizes in 1..=n.
pub fn chunks<'a>(data: &'a [u8], mode: usize, rng: &mut Rng) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let n = match mode {
            0 => data.len(),
            1 => 1,
            m => 1 + rng.below(m),
        };
        let e = (i + n).min(data.len());
        out.push(&data[i..e]);
        i = e;
    }
    out
}
