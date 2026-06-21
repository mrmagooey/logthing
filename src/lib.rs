// Library target exposing internal modules for integration tests.
// The binary target (main.rs) re-declares these modules directly.

pub mod config;
pub mod forwarding;
pub mod ipfix;
pub mod models;
pub mod syslog;
