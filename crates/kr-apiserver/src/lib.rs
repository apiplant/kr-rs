//! `kr-apiserver`: a Kubernetes API server over `kr-store` (ADR-021).
//!
//! Objects are generic JSON validated for the fields the server itself relies on (apiVersion,
//! kind, metadata); typed schemas for every kind are out of scope for now.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod api;
pub mod client;
pub mod cluster;
pub mod cel;
pub mod crd;
pub mod defaults;
pub mod discovery;
pub mod durable;
pub mod fieldval;
pub mod node_authz;
pub mod object;
pub mod openapi;
pub mod patch;
pub mod ssa;
pub mod printers;
pub mod rbac;
pub mod proto;
pub mod proto_schema;
pub mod quota;
pub mod regex;
pub mod resources;
pub mod server;
pub mod tokens;
pub(crate) mod policy;
pub mod webhook;
