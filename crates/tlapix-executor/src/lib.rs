//! Tlapix Executor - BPF map-based autonomous action execution and ACME renewal.

pub mod acme;
pub mod expiry;
pub mod failure_handler;
pub mod integrity;
pub mod map_writer;

pub const CRATE_NAME: &str = "tlapix-executor";
