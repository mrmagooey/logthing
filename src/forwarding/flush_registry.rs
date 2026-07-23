//! Registry of every running writer's live flush interval.
//!
//! Each buffered Parquet writer (syslog, ipfix, sflow, zeek, suricata, wef,
//! hec — S3 and/or local variants) registers its `LiveInterval` handle here
//! once at startup, keyed by `"<source>.<target>"` (e.g. `"wef.s3"`,
//! `"hec.local"`). The admin config API consults this registry whenever a
//! full config replaces the running one, so `flush_interval_secs` changes
//! reach already-running writers without a process restart.

use crate::forwarding::buffered_writer::LiveInterval;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Registry of every running writer's live flush interval, keyed by
/// "<source>.<target>" (e.g. "wef.s3", "hec.local"). Each writer registers
/// itself once at startup; the admin config API consults this registry
/// whenever a full config replaces the running one, so flush_interval_secs
/// changes reach already-running writers without a process restart.
#[derive(Clone, Default)]
pub struct FlushIntervalRegistry(Arc<Mutex<HashMap<String, LiveInterval>>>);

impl FlushIntervalRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, key: impl Into<String>, handle: LiveInterval) {
        self.0.lock().unwrap().insert(key.into(), handle);
    }

    /// No-op if `key` has no registered writer (source not configured, or
    /// not yet started) — there's nothing running to update.
    pub fn set_secs(&self, key: &str, secs: u64) {
        if let Some(handle) = self.0.lock().unwrap().get(key) {
            handle.set_secs(secs);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn register_then_set_secs_updates_the_registered_handle() {
        let registry = FlushIntervalRegistry::new();
        let handle = LiveInterval::new(Duration::from_secs(900));
        registry.register("syslog.s3", handle.clone());

        registry.set_secs("syslog.s3", 42);

        assert_eq!(handle.get(), Duration::from_secs(42));
    }

    #[test]
    fn set_secs_on_unregistered_key_is_a_noop_and_does_not_panic() {
        let registry = FlushIntervalRegistry::new();
        // No panic expected — key was never registered.
        registry.set_secs("nonexistent.key", 42);
    }
}
