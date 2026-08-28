// Library target — single authoritative module home for all crate modules.
// The binary target (main.rs) uses `logthing::` instead of re-declaring modules.

// result_large_err misfires on idiomatic axum `Result<T, Response>` handlers
// (clippy 1.98 counts the >=128-byte Response as an oversized Err variant);
// these are cold admin endpoints, boxing would be noise for no benefit.
#[allow(clippy::result_large_err)]
pub mod admin;
pub mod config;
pub mod forwarding;
pub mod ingest;
pub mod ipfix;
pub mod middleware;
pub mod models;
pub mod parser;
pub mod profiling;
pub mod protocol;
pub mod server;
pub mod sflow;
pub mod shutdown;
pub mod stats;
pub mod suricata;
pub mod syslog;
pub mod zeek;
