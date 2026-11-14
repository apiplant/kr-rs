//! Container runtime: image store + layer unpack (store, unpack, pull) and
//! kernel-level isolation (container). See ADR-007, ADR-016, ADR-017.
#![no_std]
extern crate alloc;

pub mod auth;
pub mod cgroup;
pub mod config;
pub mod cpuset;
pub mod container;
pub mod devfilter;
pub mod gc;
pub mod hooks;
pub mod lsm;
pub mod import;
pub mod offload;
pub mod network;
pub mod pull;
pub mod registries;
pub mod security;
pub mod seccomp;
pub mod syscalls;
pub mod store;
pub mod unpack;
