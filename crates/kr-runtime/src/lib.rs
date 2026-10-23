//! Container runtime: image store + layer unpack (store, unpack, pull) and
//! kernel-level isolation (container). See ADR-007, ADR-016, ADR-017.
#![no_std]
extern crate alloc;

pub mod container;
pub mod pull;
pub mod security;
pub mod store;
pub mod unpack;
