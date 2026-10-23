// Shared helpers for vector-driven tests (included with `mod common;`).
#![allow(dead_code)]

pub fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// Rows of a vector file: fields split on '|'.
pub fn rows(data: &str) -> impl Iterator<Item = Vec<&str>> {
    data.lines().filter(|l| !l.is_empty()).map(|l| l.split('|').collect())
}
