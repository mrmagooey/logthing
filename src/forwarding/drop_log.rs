//! Throttling for per-dropped-record log lines.
//!
//! Nineteen call sites log once per dropped record when a writer's bounded
//! channel is full or closed. Measured at 50,000 syslog datagrams/sec that
//! costs ~15µs per received datagram and ~21% of ingest throughput — not
//! because the logging burns much CPU in aggregate, but because it runs on
//! the single-task UDP receive path, so time spent formatting and locking
//! stdout is time not spent draining the socket.
//!
//! `parquet_s3_dropped{source,target}` remains the authoritative per-drop
//! record; these logs become a human-facing summary.
//!
//! See `docs/superpowers/specs/2026-07-25-drop-log-throttle-design.md`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tokio::sync::mpsc::error::TrySendError;

/// Minimum spacing between emitted lines for one `(site, kind)` pair.
/// Matches the pre-existing `drop_oldest_to_cap` throttle in
/// `buffered_writer.rs`, so the codebase has one throttle cadence.
pub const DROP_LOG_INTERVAL_NANOS: u64 = 30 * 1_000_000_000;

/// Sentinel for "nothing has been logged yet", chosen so a test clock
/// starting at 0 cannot be mistaken for a real prior log timestamp.
const NEVER_LOGGED: u64 = u64::MAX;

/// Why a record was dropped. Kept separate per site so that a writer-died
/// `Closed` is never suppressed because a transient `Full` fired recently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropKind {
    /// The bounded channel was full — transient backpressure.
    Full = 0,
    /// The receiving writer task is gone — permanent.
    Closed = 1,
}

impl<R> From<&TrySendError<R>> for DropKind {
    fn from(err: &TrySendError<R>) -> Self {
        match err {
            TrySendError::Full(_) => DropKind::Full,
            TrySendError::Closed(_) => DropKind::Closed,
        }
    }
}

/// Which logical call site is reporting.
///
/// This is deliberately finer-grained than the owning `ParquetWriterHandle`:
/// OTLP and HEC/NDJSON share the *same* `ParquetWriterHandle<GenericSink>`
/// instances, so keying only by handle would let an OTLP drop burst mute
/// HEC's first-occurrence line for a full interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropSite {
    Wef = 0,
    Hec = 1,
    Otlp = 2,
    Sflow = 3,
    Zeek = 4,
    Suricata = 5,
    Ipfix = 6,
    Syslog = 7,
    StructuredSyslog = 8,
}

/// Number of `DropSite` variants; the slot array is `DROP_SITE_COUNT * 2`.
pub const DROP_SITE_COUNT: usize = 9;

/// One throttle: a monotonic drop count plus the time of the last emitted line.
///
/// `total` is **never reset**. That removes any read-modify-write on the count,
/// so a lost race or a missed window cannot corrupt or lose it — the next
/// emitted line simply reports a larger, still-correct total.
#[derive(Debug)]
pub struct DropLogThrottle {
    total: AtomicU64,
    last_log_nanos: AtomicU64,
}

impl Default for DropLogThrottle {
    fn default() -> Self {
        Self::new()
    }
}

impl DropLogThrottle {
    /// A fresh throttle that has never logged.
    pub const fn new() -> Self {
        Self {
            total: AtomicU64::new(0),
            last_log_nanos: AtomicU64::new(NEVER_LOGGED),
        }
    }

    /// Record one drop and decide whether to emit a line.
    ///
    /// Returns `Some(running_total)` when this caller won the emission slot,
    /// `None` otherwise. `now_nanos` is injected so the policy is testable
    /// without sleeping.
    pub fn check_at(&self, now_nanos: u64) -> Option<u64> {
        self.total.fetch_add(1, Ordering::Relaxed);

        let last = self.last_log_nanos.load(Ordering::Relaxed);
        let due = last == NEVER_LOGGED || now_nanos.saturating_sub(last) >= DROP_LOG_INTERVAL_NANOS;
        if !due {
            return None;
        }

        // Exactly one caller may claim the slot; losers stay silent. Their
        // drops are still counted, and surface in whoever wins next.
        match self.last_log_nanos.compare_exchange(
            last,
            now_nanos,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => Some(self.total.load(Ordering::Relaxed)),
            Err(_) => None,
        }
    }

    /// Total drops recorded since process start. Never reset.
    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }
}

/// One `DropLogThrottle` per `(DropSite, DropKind)` pair, in a fixed array —
/// no map, no allocation, lock-free.
#[derive(Debug)]
pub struct DropLogThrottles {
    slots: [DropLogThrottle; DROP_SITE_COUNT * 2],
}

impl Default for DropLogThrottles {
    fn default() -> Self {
        Self::new()
    }
}

impl DropLogThrottles {
    /// Build a fresh set with every slot un-logged.
    pub fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| DropLogThrottle::new()),
        }
    }

    /// `check_at` with an injected clock, for tests.
    pub fn check_at(&self, site: DropSite, kind: DropKind, now_nanos: u64) -> Option<u64> {
        self.slots[site as usize * 2 + kind as usize].check_at(now_nanos)
    }

    /// Record one drop for `(site, kind)` and decide whether to emit a line.
    pub fn check(&self, site: DropSite, kind: DropKind) -> Option<u64> {
        self.check_at(site, kind, process_nanos())
    }
}

/// Monotonic nanoseconds since first use. Monotonic (not wall-clock) so a
/// clock step cannot suppress logging for 30 seconds or unthrottle it.
fn process_nanos() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;

    #[test]
    fn first_call_always_logs_regardless_of_clock_value() {
        // Clock starting at 0 must not be mistaken for "logged at time 0".
        let t = DropLogThrottle::new();
        assert_eq!(t.check_at(0), Some(1));
    }

    #[test]
    fn suppresses_within_the_interval() {
        let t = DropLogThrottle::new();
        assert_eq!(t.check_at(0), Some(1));
        assert_eq!(t.check_at(1), None);
        assert_eq!(t.check_at(29 * S), None);
    }

    #[test]
    fn emits_again_after_the_interval() {
        let t = DropLogThrottle::new();
        assert_eq!(t.check_at(0), Some(1));
        for _ in 0..10 {
            assert_eq!(t.check_at(S), None);
        }
        // 12th call, past the window: reports the running total including itself.
        assert_eq!(t.check_at(30 * S), Some(12));
    }

    #[test]
    fn total_is_never_reset() {
        let t = DropLogThrottle::new();
        t.check_at(0);
        for _ in 0..99 {
            t.check_at(S);
        }
        assert_eq!(t.total(), 100);
        assert_eq!(t.check_at(30 * S), Some(101));
        assert_eq!(t.total(), 101);
    }

    #[test]
    fn counts_every_call_under_concurrency() {
        use std::sync::Arc;
        let t = Arc::new(DropLogThrottle::new());
        let mut hs = Vec::new();
        for _ in 0..8 {
            let t = t.clone();
            hs.push(std::thread::spawn(move || {
                for i in 0..1000u64 {
                    t.check_at(i);
                }
            }));
        }
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(t.total(), 8000, "no increments may be lost");
    }

    #[test]
    fn full_and_closed_are_independent() {
        let ts = DropLogThrottles::new();
        assert_eq!(ts.check_at(DropSite::Wef, DropKind::Full, 0), Some(1));
        // A Closed drop must log immediately even though Full just logged.
        assert_eq!(ts.check_at(DropSite::Wef, DropKind::Closed, 0), Some(1));
    }

    #[test]
    fn sites_are_independent() {
        let ts = DropLogThrottles::new();
        assert_eq!(ts.check_at(DropSite::Otlp, DropKind::Full, 0), Some(1));
        // OTLP and HEC share one ParquetWriterHandle; they must not mute each other.
        assert_eq!(ts.check_at(DropSite::Hec, DropKind::Full, 0), Some(1));
    }

    #[test]
    fn every_site_kind_pair_maps_to_a_distinct_slot() {
        let ts = DropLogThrottles::new();
        let sites = [
            DropSite::Wef,
            DropSite::Hec,
            DropSite::Otlp,
            DropSite::Sflow,
            DropSite::Zeek,
            DropSite::Suricata,
            DropSite::Ipfix,
            DropSite::Syslog,
            DropSite::StructuredSyslog,
        ];
        assert_eq!(sites.len(), DROP_SITE_COUNT);
        for s in sites {
            for k in [DropKind::Full, DropKind::Closed] {
                // Each pair is untouched, so each must log on its own first call.
                assert_eq!(ts.check_at(s, k, 0), Some(1));
            }
        }
    }

    #[test]
    fn drop_kind_derives_from_try_send_error() {
        use tokio::sync::mpsc::error::TrySendError;
        let full: TrySendError<u8> = TrySendError::Full(1);
        let closed: TrySendError<u8> = TrySendError::Closed(1);
        assert_eq!(DropKind::from(&full), DropKind::Full);
        assert_eq!(DropKind::from(&closed), DropKind::Closed);
    }
}
