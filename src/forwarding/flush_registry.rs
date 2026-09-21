//! Registry of every running writer's live flush interval.
//!
//! Each buffered Parquet writer (syslog, ipfix, sflow, zeek, suricata, wef,
//! hec — S3 and/or local variants) registers its `LiveInterval` handle here
//! once at startup, keyed by `"<source>.<target>"` (e.g. `"wef.s3"`,
//! `"hec.local"`). `flush_interval_secs` is otherwise restart-only —
//! `security.allowed_ips`, `hec.token` and the S3 flush intervals are all
//! loaded once from config at startup and require a process restart to
//! change.

use crate::forwarding::buffered_writer::LiveInterval;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Registry of every running writer's live flush interval, keyed by
/// "<source>.<target>" (e.g. "wef.s3", "hec.local"). Each writer registers
/// itself once at startup.
#[derive(Clone, Default)]
pub struct FlushIntervalRegistry(Arc<Mutex<HashMap<String, LiveInterval>>>);

impl FlushIntervalRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, key: impl Into<String>, handle: LiveInterval) {
        self.0.lock().unwrap().insert(key.into(), handle);
    }
}
