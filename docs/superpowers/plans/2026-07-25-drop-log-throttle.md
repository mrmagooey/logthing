# Per-Drop Log Throttle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop 19 `tracing::warn!`/`error!` call sites from firing once per dropped record, recovering ~15µs per received datagram (−15%) and ~21% of ingest throughput, without losing first-occurrence visibility or per-source context.

**Architecture:** A lock-free `DropLogThrottle` (two `AtomicU64`, never-reset cumulative total) lives in a new `src/forwarding/drop_log.rs`. `ParquetWriterHandle` gains an `Arc<DropLogThrottles>` — `Arc` because the handle is `Clone` and is cloned per request — holding one throttle per `(DropSite, DropKind)` pair in a fixed array. All 19 call sites already funnel through `ParquetWriterHandle::try_send`, so they simply ask `handle.drop_log_due(site, kind)` whether to emit, keeping their existing message text and exporter context verbatim.

**Tech Stack:** Rust 2024, tokio, `tracing` / `tracing-subscriber` (already dependencies), `std::sync::atomic`. No new external dependencies.

**Full design rationale:** `docs/superpowers/specs/2026-07-25-drop-log-throttle-design.md` — read it before starting. Its decisions (four rounds of independent review) are not re-litigated here.

## Global Constraints

- Branch: `perf/drop-log-throttle` (exists, off `master` `9fb0c94`; spec committed at `91e05c9`). **Never commit to `master`.**
- **Always** `export CC=/usr/bin/gcc CXX=/usr/bin/g++` before any cargo command — this machine has a `zig-cc` shim on `PATH` that breaks C dependency builds.
- Style (`AGENTS.md`): Rust 2024, 100-char max lines, 4-space indent, trailing newline, imports std → external → internal, `///` docs on public items, `#[derive(Debug)]` on structs/enums.
- `cargo fmt` and `cargo clippy --all-targets -- -D warnings` must be clean before every commit. The branch starts clean, so any warning is yours.
- **No new external crate dependencies.**
- **Existing log message text and levels must be preserved verbatim.** Only a `dropped_total` structured field is added. Changing wording or level is an unrequested behaviour change.
- **Nothing may add allocation or locking to the per-drop path.** One `fetch_add` plus one atomic load is the budget.
- `parquet_s3_dropped{source,target}` must keep incrementing for every drop — it stays the authoritative record. Do not touch it.
- Do not remove the redundant `hec_events_dropped` counter — explicitly out of scope.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/forwarding/drop_log.rs` (create) | `DropKind`, `DropSite`, `DropLogThrottle`, `DropLogThrottles` + unit tests |
| `src/forwarding/mod.rs` (modify) | register `pub mod drop_log;` |
| `src/forwarding/buffered_writer.rs` (modify) | `drop_log: Arc<DropLogThrottles>` field on `ParquetWriterHandle`, built in `start_with_stats`; `drop_log_due()` |
| `src/forwarding/{sflow,syslog,suricata,zeek,ipfix}_s3.rs` (modify) | 5 call sites |
| `src/syslog/listener.rs` (modify) | 2 call sites |
| `src/server/mod.rs` (modify) | 8 call sites (WEF ×4, OTLP ×4) |
| `src/ingest/handlers.rs` (modify) | 4 call sites (HEC ×4) |
| `tests/drop_log_integration.rs` (create) | tracing-capture burst test + clone-sharing test |
| `docs/performance/2026-07-25-drop-log-throttle-results.md` (create) | E2E measurement |

---

## Task 1: The throttle type

**Files:**
- Create: `src/forwarding/drop_log.rs`
- Modify: `src/forwarding/mod.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `DropKind {Full, Closed}` with `impl<R> From<&TrySendError<R>> for DropKind`; `DropSite {Wef, Hec, Otlp, Sflow, Zeek, Suricata, Ipfix, Syslog, StructuredSyslog}`; `DROP_SITE_COUNT: usize`; `DropLogThrottle::new()` (const) / `check_at(u64) -> Option<u64>` / `total() -> u64`; `DropLogThrottles::new()` / `check_at(DropSite, DropKind, u64) -> Option<u64>` / `check(DropSite, DropKind) -> Option<u64>`; `DROP_LOG_INTERVAL_NANOS: u64`.

- [ ] **Step 1: Write the failing tests**

Create `src/forwarding/drop_log.rs` containing ONLY this test module for now:

```rust
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
```

Add to `src/forwarding/mod.rs`, keeping the `pub mod` list alphabetical (it currently begins `pub mod buffered_writer;`, then `pub mod flush_registry;` — insert between them):

```rust
pub mod drop_log;
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
cargo test --lib forwarding::drop_log 2>&1 | tail -20
```

Expected: FAIL to compile — `cannot find type DropLogThrottle in this scope`, and similarly for `DropLogThrottles`, `DropSite`, `DropKind`, `DROP_SITE_COUNT`.

- [ ] **Step 3: Write the implementation**

Prepend to `src/forwarding/drop_log.rs`, above the test module:

```rust
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
        let due =
            last == NEVER_LOGGED || now_nanos.saturating_sub(last) >= DROP_LOG_INTERVAL_NANOS;
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
cargo test --lib forwarding::drop_log 2>&1 | tail -15
cargo fmt && cargo clippy --all-targets -- -D warnings
```

Expected: 9 tests pass; fmt and clippy clean.

- [ ] **Step 5: Commit**

```bash
git add src/forwarding/drop_log.rs src/forwarding/mod.rs
git commit -m "feat(forwarding): add lock-free per-drop log throttle (unwired)"
```

---

## Task 2: Wire the throttle into `ParquetWriterHandle`

**Files:**
- Modify: `src/forwarding/buffered_writer.rs` (struct at `:1118-1130`, constructor in `start_with_stats`, new method)

**Interfaces:**
- Consumes: `DropLogThrottles`, `DropSite`, `DropKind` from Task 1.
- Produces: `ParquetWriterHandle::drop_log_due(&self, site: DropSite, kind: DropKind) -> Option<u64>`.

- [ ] **Step 1: Write the failing test**

Append to the existing `#[cfg(test)] mod tests` block at the end of `src/forwarding/buffered_writer.rs`:

```rust
    #[tokio::test]
    async fn drop_log_throttle_is_shared_across_handle_clones() {
        use crate::forwarding::drop_log::{DropKind, DropSite};

        let s3 = unreachable_s3().await;
        let (handle, _join) = ParquetWriterHandle::<TestSink>::start(
            TestSink,
            s3,
            test_config(),
            test_policy(),
        );

        // ParquetWriterHandle is #[derive(Clone)] and AppState/IngestState
        // clone it per request. If throttle state were per-clone rather than
        // Arc-shared, every request would get a fresh throttle and the log
        // storm would silently return.
        let clone = handle.clone();
        assert_eq!(
            handle.drop_log_due(DropSite::Wef, DropKind::Full),
            Some(1),
            "first drop on the original handle must log"
        );
        assert_eq!(
            clone.drop_log_due(DropSite::Wef, DropKind::Full),
            None,
            "a clone must share the throttle, not reset it"
        );
    }
```

**Note on helpers:** `unreachable_s3()`, `test_config()`, `test_policy()`, and `TestSink` already exist in that test module and are used by neighbouring tests — reuse them exactly as those tests do. If `ParquetWriterHandle::<TestSink>::start` has a different name or arity in this file, match the existing call in the test named `handle_start_spawns_background_task_and_try_send_works`.

- [ ] **Step 2: Run test to verify it fails**

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
cargo test --lib drop_log_throttle_is_shared_across_handle_clones 2>&1 | tail -15
```

Expected: FAIL to compile — `no method named drop_log_due found for struct ParquetWriterHandle`.

- [ ] **Step 3: Write the implementation**

In `src/forwarding/buffered_writer.rs`, add to the `use` block at the top of the file:

```rust
use crate::forwarding::drop_log::{DropKind, DropLogThrottles, DropSite};
```

Add a field to `ParquetWriterHandle` (the struct at `:1118`), after `flush_interval`:

```rust
    /// Per-(site, kind) log throttles. `Arc` because this struct is `Clone`
    /// and both `AppState` and `IngestState` clone it per request — per-clone
    /// throttle state would reset constantly and restore the log storm.
    drop_log: std::sync::Arc<DropLogThrottles>,
```

In `start_with_stats`, where the returned `Self { .. }` is constructed (it currently sets `tx`, `source`, `target`, `flush_interval`), add:

```rust
                drop_log: std::sync::Arc::new(DropLogThrottles::new()),
```

Add the accessor to `impl<S: ParquetSink> ParquetWriterHandle<S>`, next to `try_send`:

```rust
    /// Record one dropped record for `(site, kind)` and report whether a log
    /// line is due.
    ///
    /// `parquet_s3_dropped{source,target}` — incremented by `try_send` — stays
    /// the authoritative count. This only rate-limits the human-facing line.
    ///
    /// `site` is passed by the caller rather than derived from this handle
    /// because OTLP and HEC/NDJSON share the same `ParquetWriterHandle`
    /// instances; keying by handle alone would let one mute the other.
    pub fn drop_log_due(&self, site: DropSite, kind: DropKind) -> Option<u64> {
        self.drop_log.check(site, kind)
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
cargo test --lib drop_log_throttle_is_shared_across_handle_clones 2>&1 | tail -10
cargo test --lib 2>&1 | grep -E "^test result"
cargo fmt && cargo clippy --all-targets -- -D warnings
```

Expected: the new test passes, the full lib suite still passes, fmt and clippy clean.

- [ ] **Step 5: Commit**

```bash
git add src/forwarding/buffered_writer.rs
git commit -m "feat(forwarding): give ParquetWriterHandle an Arc-shared drop-log throttle"
```

---

## Task 3: Convert the 7 forwarding and syslog call sites

**Files:**
- Modify: `src/forwarding/sflow_s3.rs:246-248`, `src/forwarding/syslog_s3.rs:160-165`, `src/forwarding/suricata_s3.rs:110-116`, `src/forwarding/zeek_s3.rs:160-166`, `src/forwarding/ipfix_s3.rs:245-253`, `src/syslog/listener.rs:105-110` and `:136-140`

**Interfaces:**
- Consumes: `drop_log_due(DropSite, DropKind) -> Option<u64>` from Task 2; `DropKind: From<&TrySendError<R>>` from Task 1.
- Produces: nothing consumed by later tasks.

**Rule for every edit in this task:** keep the message string and log level **byte-identical**; add only the `dropped_total` field and the surrounding `if let`.

- [ ] **Step 1: Convert `sflow_s3.rs`**

Replace:
```rust
            if let Err(_dropped) = self.try_send(record) {
                tracing::warn!("sFlow S3 channel full; dropped record from {}", source);
            }
```
with:
```rust
            if let Err(e) = self.try_send(record)
                && let Some(dropped_total) =
                    self.drop_log_due(DropSite::Sflow, DropKind::from(&e))
            {
                tracing::warn!(
                    dropped_total,
                    "sFlow S3 channel full; dropped record from {}",
                    source
                );
            }
```
and add to that file's imports:
```rust
use crate::forwarding::drop_log::{DropKind, DropSite};
```

- [ ] **Step 2: Convert `syslog_s3.rs`**

Replace the `Err(_dropped) => { tracing::warn!("Syslog S3 channel full; dropped message"); }` arm with:
```rust
            Err(e) => {
                if let Some(dropped_total) =
                    self.drop_log_due(DropSite::Syslog, DropKind::from(&e))
                {
                    tracing::warn!(dropped_total, "Syslog S3 channel full; dropped message");
                }
            }
```
plus the same `use` line, with `DropSite::Syslog`.

- [ ] **Step 3: Convert `suricata_s3.rs`, `zeek_s3.rs`, `ipfix_s3.rs`**

Same shape. Preserve each existing message verbatim, including the pre-existing comments about `parquet_s3_dropped` already being incremented. Use `DropSite::Suricata`, `DropSite::Zeek`, `DropSite::Ipfix` respectively. For `ipfix_s3.rs` the message is multi-line:
```rust
            Err(e) => {
                // parquet_s3_dropped{source="ipfix"} is already incremented by try_send;
                // just warn here.
                if let Some(dropped_total) =
                    self.drop_log_due(DropSite::Ipfix, DropKind::from(&e))
                {
                    tracing::warn!(
                        dropped_total,
                        "IPFIX S3 channel full; dropped {} flows from {}",
                        count,
                        source
                    );
                }
            }
```

- [ ] **Step 4: Convert the two `syslog/listener.rs` sites**

Both use `DropSite::StructuredSyslog`. The first (`:105-110`):
```rust
                match handle.try_send(rec) {
                    Ok(()) => {}
                    Err(e) => {
                        if let Some(dropped_total) =
                            handle.drop_log_due(DropSite::StructuredSyslog, DropKind::from(&e))
                        {
                            tracing::warn!(
                                dropped_total,
                                "structured_syslog S3 channel full; dropped record"
                            );
                        }
                    }
                }
```
The second (`:136-140`) has message `"structured_syslog channel full; dropped"` — same shape, called on `h` rather than `handle`. Add the `use` line to that file.

- [ ] **Step 5: Verify**

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
cargo test --lib 2>&1 | grep -E "^test result"
cargo fmt && cargo clippy --all-targets -- -D warnings
grep -c "drop_log_due" src/forwarding/sflow_s3.rs src/forwarding/syslog_s3.rs \
    src/forwarding/suricata_s3.rs src/forwarding/zeek_s3.rs src/forwarding/ipfix_s3.rs \
    src/syslog/listener.rs
```
Expected: lib suite passes; fmt/clippy clean; the `grep -c` shows `1` for each of the five `_s3.rs` files and `2` for `listener.rs` (7 total).

- [ ] **Step 6: Commit**

```bash
git add src/forwarding/sflow_s3.rs src/forwarding/syslog_s3.rs src/forwarding/suricata_s3.rs \
    src/forwarding/zeek_s3.rs src/forwarding/ipfix_s3.rs src/syslog/listener.rs
git commit -m "perf(forwarding): throttle the 7 forwarding and syslog drop logs"
```

---

## Task 4: Convert the 12 HTTP-path call sites

**Files:**
- Modify: `src/server/mod.rs:727-747` (WEF ×4) and `:2735-2757` (OTLP ×4)
- Modify: `src/ingest/handlers.rs:84-108` (HEC ×4)

**Interfaces:**
- Consumes: `drop_log_due(DropSite, DropKind)` from Task 2.
- Produces: nothing consumed by later tasks.

**Critical:** OTLP sites use `DropSite::Otlp` and HEC sites use `DropSite::Hec` even though both operate on the **same** `ParquetWriterHandle<GenericSink>` instances. That distinction is the entire reason `site` is a parameter — do not collapse them.

- [ ] **Step 1: Convert the four WEF sites in `server/mod.rs`**

Replace the first block (`:727-737`) with:
```rust
        && let Err(e) = sender.try_send(event.clone())
    {
        let kind = crate::forwarding::drop_log::DropKind::from(&e);
        if let Some(dropped_total) =
            sender.drop_log_due(crate::forwarding::drop_log::DropSite::Wef, kind)
        {
            match kind {
                crate::forwarding::drop_log::DropKind::Full => {
                    warn!(dropped_total, "WEF Parquet S3 channel full, dropping event");
                }
                crate::forwarding::drop_log::DropKind::Closed => {
                    error!(dropped_total, "WEF Parquet S3 channel closed");
                }
            }
        }
    }
```
Apply the same shape to the WEF local block (`:739-749`), keeping its messages `"WEF Parquet local channel full, dropping event"` and `"WEF Parquet local channel closed"` verbatim.

Prefer adding `use crate::forwarding::drop_log::{DropKind, DropSite};` to the file's import block and dropping the long paths — match whatever the surrounding file already does for `crate::forwarding` imports.

- [ ] **Step 2: Convert the four OTLP sites in `server/mod.rs`**

Same shape at `:2735-2757`, using `DropSite::Otlp`, keeping messages `"OTLP generic_s3 channel full, dropping record"`, `"OTLP generic_s3 channel closed"`, `"OTLP generic_local channel full, dropping record"`, `"OTLP generic_local channel closed"` verbatim.

- [ ] **Step 3: Convert the four HEC sites in `ingest/handlers.rs`**

```rust
    if let Some(ref handler) = ingest.generic_s3
        && let Err(e) = handler.try_send(record.clone())
    {
        metrics::counter!("hec_events_dropped").increment(1);
        let kind = DropKind::from(&e);
        if let Some(dropped_total) = handler.drop_log_due(DropSite::Hec, kind) {
            match kind {
                DropKind::Full => {
                    tracing::warn!(dropped_total, "HEC S3 channel full; dropped {context}");
                }
                DropKind::Closed => {
                    tracing::error!(dropped_total, "HEC S3 channel closed; dropped {context}");
                }
            }
        }
    }
```
and the matching `generic_local` block with `"HEC local channel full; dropped {context}"` / `"HEC local channel closed; dropped {context}"`.

**Leave `metrics::counter!("hec_events_dropped").increment(1)` exactly where it is** — it must still fire on every drop.

- [ ] **Step 4: Verify**

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
cargo test 2>&1 | grep -E "^test result"
cargo fmt && cargo clippy --all-targets -- -D warnings
grep -c "drop_log_due" src/server/mod.rs src/ingest/handlers.rs
```
Expected: all tests pass; fmt/clippy clean; `grep -c` shows `4` for `server/mod.rs` and `2` for `ingest/handlers.rs` (one per `if let` block, 6 blocks covering 12 log sites).

- [ ] **Step 5: Confirm all 19 sites are converted**

```bash
grep -rn --include='*.rs' -iE "channel (full|closed)" src/ | grep -vE "drop_oldest|//" | wc -l
grep -rn --include='*.rs' "drop_log_due" src/ | wc -l
```
Expected: the second count is 13 (7 from Task 3 + 6 blocks here). Every message-string site must sit inside a `drop_log_due` guard — verify by reading, not just counting.

- [ ] **Step 6: Commit**

```bash
git add src/server/mod.rs src/ingest/handlers.rs
git commit -m "perf(server,ingest): throttle the 12 WEF, OTLP and HEC drop logs"
```

---

## Task 5: Integration test — a burst emits one line

**Files:**
- Create: `tests/drop_log_integration.rs`

**Interfaces:**
- Consumes: `DropLogThrottles`, `DropSite`, `DropKind`, `DROP_LOG_INTERVAL_NANOS` from Task 1.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Write the test**

```rust
//! Integration coverage for per-drop log throttling.
//!
//! The unit tests in `drop_log.rs` pin the policy; this pins the property the
//! change exists for: a burst of drops must produce ONE log line, not one per
//! drop, while still reporting an accurate running total.

use std::sync::{Arc, Mutex};

use logthing::forwarding::drop_log::{
    DROP_LOG_INTERVAL_NANOS, DropKind, DropLogThrottles, DropSite,
};
use tracing::subscriber;
use tracing_subscriber::layer::SubscriberExt;

/// Collects formatted event messages so we can count emitted lines.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<String>>>);

impl<S> tracing_subscriber::Layer<S> for Capture
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        struct V(String);
        impl tracing::field::Visit for V {
            fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                self.0.push_str(&format!("{}={:?} ", f.name(), v));
            }
        }
        let mut v = V(String::new());
        event.record(&mut v);
        self.0.lock().unwrap().push(v.0);
    }
}

#[test]
fn burst_of_drops_emits_one_line_with_a_correct_total() {
    let cap = Capture::default();
    let sub = tracing_subscriber::registry().with(cap.clone());
    let _g = subscriber::set_default(sub);

    let throttles = DropLogThrottles::new();
    // 10,000 drops inside one interval, exactly as an overload burst produces.
    for _ in 0..10_000 {
        if let Some(dropped_total) = throttles.check_at(DropSite::Syslog, DropKind::Full, 0) {
            tracing::warn!(dropped_total, "Syslog S3 channel full; dropped message");
        }
    }

    let lines = cap.0.lock().unwrap();
    assert_eq!(
        lines.len(),
        1,
        "10,000 drops must emit exactly one line, got {}",
        lines.len()
    );
    assert!(
        lines[0].contains("dropped_total=1"),
        "first line reports the total at emission time, got: {}",
        lines[0]
    );
}

#[test]
fn a_second_line_after_the_interval_reports_the_accumulated_total() {
    let cap = Capture::default();
    let sub = tracing_subscriber::registry().with(cap.clone());
    let _g = subscriber::set_default(sub);

    let throttles = DropLogThrottles::new();
    for _ in 0..5_000 {
        if let Some(dropped_total) = throttles.check_at(DropSite::Syslog, DropKind::Full, 0) {
            tracing::warn!(dropped_total, "Syslog S3 channel full; dropped message");
        }
    }
    // One more drop, past the window.
    if let Some(dropped_total) =
        throttles.check_at(DropSite::Syslog, DropKind::Full, DROP_LOG_INTERVAL_NANOS)
    {
        tracing::warn!(dropped_total, "Syslog S3 channel full; dropped message");
    }

    let lines = cap.0.lock().unwrap();
    assert_eq!(lines.len(), 2, "expected one line per interval");
    assert!(
        lines[1].contains("dropped_total=5001"),
        "the second line must report every drop since start, got: {}",
        lines[1]
    );
}
```

- [ ] **Step 2: Run and verify**

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
cargo test --test drop_log_integration 2>&1 | tail -12
cargo fmt && cargo clippy --all-targets -- -D warnings
```
Expected: 2 tests pass; fmt/clippy clean.

If `tracing_subscriber::Layer` needs the `registry` feature and it is not enabled, check `Cargo.toml`'s `tracing-subscriber` features — it currently has `["env-filter", "json"]`. `registry` is a default feature of `tracing-subscriber`, so this should work as-is; if it does not, add `registry` to the existing feature list rather than adding a new dependency.

- [ ] **Step 3: Commit**

```bash
git add tests/drop_log_integration.rs Cargo.toml
git commit -m "test(forwarding): pin that a drop burst emits one throttled line"
```

---

## Task 6: End-to-end measurement and write-up

The point of the change is the throughput recovery. This task proves it.

**Files:**
- Create: `docs/performance/2026-07-25-drop-log-throttle-results.md`

**Interfaces:**
- Consumes: the converted call sites from Tasks 3-4.
- Produces: the finding.

- [ ] **Step 1: Build both binaries**

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
cargo build --profile profiling --features pprof
cargo build -p loadgen --release
```

- [ ] **Step 2: Measure at `info` — the condition the fix targets**

Use the same harness shape as the pre-fix measurement: swap `logthing.admin.toml` aside (it is git-tracked and overrides `logthing.toml`), copy `tools/loadgen/ci/logthing-baseline.toml` over `logthing.toml`, append `[logging] level = "info"`, run `loadgen syslog-udp --target-rate 50000 --duration-secs 30`, and restore both config files via an `EXIT` trap. **Verify `git status --short -- logthing.toml logthing.admin.toml` is empty afterwards.**

Capture, for each run: total process CPU-seconds (sum of `utime + stime` across `/proc/<pid>/task/*/stat`), the `syslog_messages_received` delta, and the emitted log line count.

Run it **twice** — single samples are what produced the bad numbers this repo has already had to correct.

- [ ] **Step 3: Compare against the pre-fix baseline**

Pre-fix, measured on this machine at 50k, `info`, two runs:

| | CPU-sec | received | µs/received datagram | log lines |
|---|---|---|---|---|
| run 1 | 85.97 | 852,799 | 100.8 | 1,176,360 |
| run 2 | 84.17 | 839,702 | 100.2 | — |

And with logging suppressed entirely (`error`), the ceiling the fix should approach:

| | CPU-sec | received | µs/received datagram |
|---|---|---|---|
| run 1 | 88.04 | 1,054,868 | 83.5 |
| run 2 | 86.23 | 991,117 | 87.0 |

Compute µs/received-datagram for the post-fix `info` runs and state where they land between 100.5 (pre-fix) and 85.2 (logging off).

- [ ] **Step 4: Re-check the pprof segfault**

Run `scripts/profile-syslog-udp.sh` with `LOG_LEVEL=info` **five times**, recording how many runs crash. Pre-fix this segfaulted reproducibly (exit 139).

**Report the crash rate honestly.** The design states the crash is *reduced, not eliminated* — ~190,000× fewer emissions makes a `SIGPROF`/stdout-lock collision unlikely, not impossible. Do not claim it is fixed on the strength of five clean runs; report "0/5 crashed" and say what that does and does not establish.

- [ ] **Step 5: Write the document**

Create `docs/performance/2026-07-25-drop-log-throttle-results.md` following `docs/performance/methodology-template.md`, in the candid register of `docs/performance/2026-07-24-syslog-udp-baseline-results.md`. It must contain: commit SHA, exact commands, the before/after table with both runs per condition, the log-line count collapse, the pprof crash-rate result with its caveat, and a Limitations section.

If the measured improvement is smaller than the ~15µs predicted, **say so plainly and give the number** — an honest smaller win is worth more than a forced match to the prediction.

- [ ] **Step 6: Commit**

```bash
git add docs/performance/2026-07-25-drop-log-throttle-results.md
git commit -m "docs(perf): measure the drop-log throttle's throughput recovery"
```

---

## Completion criteria

- [ ] `cargo test` passes; `cargo test --features pprof` passes.
- [ ] `cargo clippy --all-targets -- -D warnings` clean, with and without `--features pprof`.
- [ ] All 19 message-string sites sit inside a `drop_log_due` guard — verified by reading, not counting.
- [ ] Every original message string and log level is byte-identical to `master`; only `dropped_total` was added. Check with `git diff master -- src/ | grep -E '^[-+].*channel (full|closed)'`.
- [ ] `parquet_s3_dropped` and `hec_events_dropped` still increment on every drop.
- [ ] `git status` clean; `logthing.toml` and `logthing.admin.toml` byte-identical to committed state.
- [ ] Nothing committed to `master`. The branch is left for the user to review and merge.
