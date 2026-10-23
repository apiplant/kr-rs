//! `kr-apiserver`: a Kubernetes API server over `kr-store` (ADR-021).
//!
//! Objects are generic JSON validated for the fields the server itself relies on (apiVersion,
//! kind, metadata); typed schemas for every kind are out of scope for now.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod discovery;
pub mod object;
pub mod patch;
pub mod resources;
