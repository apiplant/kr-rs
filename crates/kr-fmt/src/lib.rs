//! `kr-fmt`: wire and text formats for `kr` (JSON, a YAML subset, protobuf wire
//! format, base64, Kubernetes quantities and Go durations).
//!
//! `no_std` + `alloc`, no unsafe code, no dependencies.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod base64;
pub mod json;
pub mod proto;
pub mod quantity;
pub mod yaml;

#[cfg(test)]
mod tests;
