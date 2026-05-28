//! Tlapix Collector - Userspace collector service for processing eBPF ring buffer events.

pub mod buffer;
pub mod dedup;
pub mod event_processor;
pub mod ring_buffer;

pub const CRATE_NAME: &str = "tlapix-collector";
