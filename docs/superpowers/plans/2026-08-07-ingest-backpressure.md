# Ingest Backpressure + 100 MiB Channel Budget Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the residual Zeek channel-full record drops by applying TCP backpressure on the two stream-transport ingest sources and sizing every source's bounded channel to a ~100 MiB memory budget instead of a fixed 256 records.

**Architecture:** `ParquetWriterHandle` gains a bounded-wait send (`send_timeout`, 5 s default, stored as an overridable field) alongside the existing non-blocking `try_send`. Only the Zeek and Suricata handlers adopt it — they are the only sources receiving on a dedicated per-connection task over a pure stream transport, so blocking closes exactly one TCP window and affects nothing else. Separately, a `CHANNEL_BUDGET_BYTES = 100 MiB` constant divided by a *measured* per-record heap footprint replaces each hardcoded `channel_capacity` default.

**Tech Stack:** Rust 2024 edition, tokio (`full` features, so `mpsc::Sender::send_timeout` is available), `futures 0.3` (already a dependency), `metrics` + `metrics-util` `DebuggingRecorder` for assertions, `arrow`/`parquet`.

**Spec:** `docs/superpowers/specs/2026-08-07-ingest-backpressure-design.md`

## Global Constraints

- **Branch:** all work lands on `feat/ingest-backpressure` (base `a972aba`). Never commit to `master`.
- **Build env:** a real gcc is required for both C deps and the linker. Export before any cargo command:
  `export CC=/usr/bin/gcc CXX=/usr/bin/g++ CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc`
  Dropping the linker var silently links LLVM libunwind and breaks unwinding.
- **Test levels:** per repo `CLAUDE.md`, changed behaviour needs unit **and** integration **and** e2e coverage. Do not report a task complete until its tests pass.
- **Default workspace member:** plain `cargo build`/`test`/`clippy` must keep building only the `logthing` package. Do not add workspace members.
- **Budget constant:** `CHANNEL_BUDGET_BYTES` is exactly `100 * 1024 * 1024` (100 MiB).
- **Send timeout default:** exactly `Duration::from_secs(5)`.
- **Lint:** `cargo clippy` must pass clean; this repo treats warnings as review blockers.
- **Existing behaviour that must not regress:** `parquet_s3_dropped{source,target}` remains the authoritative drop counter, incremented at the send site; drop log lines remain throttled through `DropLogThrottles`.

---

## File Structure

| File | Responsibility | Action |
|---|---|---|
| `src/forwarding/channel_budget.rs` | The 100 MiB constant, per-record heap-footprint measurement, and `capacity_for()` | **create** |
| `src/forwarding/mod.rs` | Register the new module | modify |
| `src/config/mod.rs` | Seven `default_*_channel_capacity()` fns derive from the budget | modify |
| `src/forwarding/drop_log.rs` | `From<&SendTimeoutError<R>> for DropKind` | modify |
| `src/forwarding/buffered_writer.rs` | `send_timeout` field, `SEND_TIMEOUT_DEFAULT`, `with_send_timeout()`, `send_or_drop()`; shutdown row logging | modify |
| `src/forwarding/zeek_s3.rs` | Zeek handler blocks; `MultiZeekHandler` fans out concurrently | modify |
| `src/forwarding/suricata_s3.rs` | Suricata handler blocks; `MultiSuricataHandler` fans out concurrently | modify |
| `logthing.toml` | Update `channel_capacity` comments to the new defaults | modify |
| `tests/ingest_backpressure_integration.rs` | Integration: block-then-succeed, wedged-writer drop, fan-out isolation, shutdown-within-deadline | **create** |
| `tests/zeek_backpressure_e2e.rs` | E2E: real TCP client vs slow sink, zero drops, socket writes block | **create** |

---

## Task 1: Channel budget module and record footprint measurement

**Files:**
- Create: `src/forwarding/channel_budget.rs`
- Modify: `src/forwarding/mod.rs`

**Interfaces:**
- Consumes: nothing (first task).
- Produces:
  - `pub const CHANNEL_BUDGET_BYTES: usize`
  - `pub const fn capacity_for(bytes_per_record: usize) -> usize`
  - `pub fn json_heap_bytes(v: &serde_json::Value) -> usize`
  - Per-source byte constants: `ZEEK_RECORD_BYTES`, `SURICATA_RECORD_BYTES`, `GENERIC_RECORD_BYTES`, `SYSLOG_MESSAGE_BYTES`, `SFLOW_RECORD_BYTES`, `IPFIX_DATAGRAM_BYTES`, `WEF_EVENT_BYTES` (all `usize`)

- [ ] **Step 1: Write the failing test**

Create `src/forwarding/channel_budget.rs` with the tests module only (the impl comes in step 3), so the file starts as a failing compile:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_for_divides_the_budget() {
        assert_eq!(capacity_for(1024), 100 * 1024);
        assert_eq!(capacity_for(CHANNEL_BUDGET_BYTES), 1);
    }

    #[test]
    fn capacity_for_never_returns_zero() {
        // A record larger than the whole budget must still allow one in flight,
        // otherwise `mpsc::channel(0)` panics.
        assert_eq!(capacity_for(CHANNEL_BUDGET_BYTES * 2), 1);
        assert_eq!(capacity_for(0), 1);
    }

    #[test]
    fn json_heap_bytes_counts_nested_strings() {
        let v = serde_json::json!({"a": "0123456789", "b": {"c": "abc"}});
        // Two string values (10 + 3) plus key capacities (1 + 1 + 1); the exact
        // total depends on allocator slack, so assert a sane lower bound only.
        assert!(json_heap_bytes(&v) >= 16, "got {}", json_heap_bytes(&v));
    }

    #[test]
    fn json_heap_bytes_is_zero_for_scalars() {
        assert_eq!(json_heap_bytes(&serde_json::json!(42)), 0);
        assert_eq!(json_heap_bytes(&serde_json::json!(null)), 0);
        assert_eq!(json_heap_bytes(&serde_json::json!(true)), 0);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib forwarding::channel_budget`
Expected: FAIL — `cannot find value CHANNEL_BUDGET_BYTES`, `cannot find function capacity_for`, `cannot find function json_heap_bytes`, and `module channel_budget not found` until it is registered.

- [ ] **Step 3: Write the implementation**

Prepend to `src/forwarding/channel_budget.rs`:

```rust
//! Per-source bounded-channel sizing from a fixed memory budget.
//!
//! `channel_capacity` is expressed in **records**, but the operational
//! constraint is **bytes**: a Zeek record and an IPFIX datagram's worth of
//! flows differ by an order of magnitude, so one shared record count would
//! mean 100 MiB for one source and gigabytes for another. Each source's
//! default is therefore `CHANNEL_BUDGET_BYTES / <measured bytes per record>`.
//!
//! The per-record figures below are **measured**, not guessed — see the tests
//! at the bottom of this file, which rebuild a representative record for each
//! type and fail if the constant has drifted by more than 2x. A memory ceiling
//! computed from an unverified divisor is fiction, and adding a field to a
//! record type would otherwise silently inflate the real ceiling.
//!
//! See `docs/superpowers/specs/2026-08-07-ingest-backpressure-design.md` §4.

/// Memory budget for one source's bounded channel, in bytes.
///
/// This is a **ceiling, not a reservation**: tokio's bounded mpsc allocates
/// its buffer lazily in blocks, so an idle or healthy channel costs nearly
/// nothing. Only Zeek and Suricata apply backpressure, so only those two are
/// designed to dwell near capacity under sustained load.
pub const CHANNEL_BUDGET_BYTES: usize = 100 * 1024 * 1024;

/// Records that fit in the budget, given a per-record byte figure.
///
/// Always returns at least 1: `tokio::sync::mpsc::channel(0)` panics, and a
/// record larger than the entire budget must still be deliverable.
pub const fn capacity_for(bytes_per_record: usize) -> usize {
    if bytes_per_record == 0 {
        return 1;
    }
    let n = CHANNEL_BUDGET_BYTES / bytes_per_record;
    if n == 0 { 1 } else { n }
}

/// Heap bytes owned by a `serde_json::Value`, following nesting.
///
/// Approximate by design (per-entry map overhead is not modelled exactly) —
/// the 2x drift tolerance in the tests is the accuracy contract.
pub fn json_heap_bytes(v: &serde_json::Value) -> usize {
    use serde_json::Value;
    match v {
        Value::Null | Value::Bool(_) | Value::Number(_) => 0,
        Value::String(s) => s.capacity(),
        Value::Array(a) => {
            a.capacity() * std::mem::size_of::<Value>()
                + a.iter().map(json_heap_bytes).sum::<usize>()
        }
        Value::Object(m) => m
            .iter()
            .map(|(k, val)| k.capacity() + std::mem::size_of::<Value>() + json_heap_bytes(val))
            .sum(),
    }
}
```

Register the module in `src/forwarding/mod.rs` by adding this line alongside the existing `pub mod` declarations:

```rust
pub mod channel_budget;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib forwarding::channel_budget`
Expected: PASS, 4 tests.

- [ ] **Step 5: Add the measured per-source constants and their drift tests**

Append to the impl section of `src/forwarding/channel_budget.rs`:

```rust
/// Measured heap footprint of one `ZeekRecord` carrying a representative
/// `conn` log line. See `measured_zeek_record_bytes_matches_constant`.
pub const ZEEK_RECORD_BYTES: usize = 2048;

/// Measured heap footprint of one `SuricataRecord` carrying a representative
/// `alert` event. Same shape as `ZeekRecord` (String + Value + DateTime).
pub const SURICATA_RECORD_BYTES: usize = 2048;

/// Measured heap footprint of one `GenericRecord` (HEC/NDJSON, OTLP).
pub const GENERIC_RECORD_BYTES: usize = 2048;

/// Measured heap footprint of one `SyslogMessage`.
pub const SYSLOG_MESSAGE_BYTES: usize = 512;

/// Measured heap footprint of one `SflowRecord` — a flat, fixed-size struct
/// with no owned heap, so this is `size_of` plus slack.
pub const SFLOW_RECORD_BYTES: usize = 256;

/// Measured footprint of one IPFIX channel message, which is a `Vec<FlowRecord>`
/// holding **all flows from one UDP datagram**.
///
/// **Average-case, not a ceiling.** Flows-per-datagram is variable; this uses a
/// representative count from the repo's IPFIX test fixtures. Datagrams denser
/// than that average will push this source past `CHANNEL_BUDGET_BYTES`. Known
/// and accepted limitation — see the spec §4.3.
pub const IPFIX_DATAGRAM_BYTES: usize = 4096;

/// Measured footprint of one `Arc<WindowsEvent>` — the **pointee**, not the
/// 8-byte pointer in the channel slot. Each queued `Arc` is a distinct event;
/// the `Arc` is a transfer mechanism, not sharing. WEF fan-out to `.s3` and
/// `.local` clones the same `Arc` into both channels, so counting it once per
/// channel overcounts, which is the safe direction. Dominated by `raw_xml`.
pub const WEF_EVENT_BYTES: usize = 8192;
```

Replace the constants above with whatever the drift tests below actually measure, rounded **up** to a clean power-of-two-ish number (rounding up shrinks the record count, which is the memory-safe direction). Then append these tests to the `tests` module:

```rust
    /// Assert `measured` is within 2x of the documented `constant`, in either
    /// direction. Tolerance rather than equality because allocator slack and
    /// fixture choice both move the number, but a 2x drift means the 100 MiB
    /// budget is no longer 100 MiB and the constant must be revisited.
    fn assert_within_2x(measured: usize, constant: usize, name: &str) {
        assert!(
            measured * 2 >= constant && constant * 2 >= measured,
            "{name}: measured {measured} bytes but constant says {constant}; \
             update the constant (round up) and re-derive the capacity"
        );
    }

    #[test]
    fn measured_zeek_record_bytes_matches_constant() {
        use crate::zeek::ZeekRecord;
        let fields = serde_json::json!({
            "_path": "conn", "ts": 1717171717.123456, "uid": "CHhAvVGS1DHFjwGM9",
            "id.orig_h": "192.168.7.102", "id.orig_p": 33764,
            "id.resp_h": "93.184.216.34", "id.resp_p": 443,
            "proto": "tcp", "service": "ssl", "duration": 0.253,
            "orig_bytes": 1420, "resp_bytes": 5320, "conn_state": "SF",
            "local_orig": true, "local_resp": false, "missed_bytes": 0,
            "history": "ShADadFf", "orig_pkts": 12, "orig_ip_bytes": 1948,
            "resp_pkts": 14, "resp_ip_bytes": 5892
        });
        let record = ZeekRecord {
            log_path: "conn".to_string(),
            fields,
            received_at: chrono::Utc::now(),
        };
        let measured = std::mem::size_of::<ZeekRecord>()
            + record.log_path.capacity()
            + json_heap_bytes(&record.fields);
        assert_within_2x(measured, ZEEK_RECORD_BYTES, "ZeekRecord");
    }

    #[test]
    fn measured_wef_event_bytes_counts_the_pointee_not_the_pointer() {
        use crate::models::WindowsEvent;
        let event = WindowsEvent {
            id: uuid::Uuid::new_v4(),
            received_at: chrono::Utc::now(),
            source_host: "dc01.corp.example".to_string(),
            subscription_id: Some("sub-1".to_string()),
            raw_xml: "<Event>".to_string() + &"<Data>x</Data>".repeat(400) + "</Event>",
            parsed: None,
        };
        let measured = std::mem::size_of::<WindowsEvent>()
            + event.source_host.capacity()
            + event.subscription_id.as_ref().map_or(0, |s| s.capacity())
            + event.raw_xml.capacity();
        // Guard the methodology itself: an Arc slot is 8 bytes, so measuring the
        // pointer instead of the pointee would yield a capacity in the millions.
        assert!(
            measured > std::mem::size_of::<std::sync::Arc<WindowsEvent>>() * 100,
            "must measure the pointee, not the Arc pointer"
        );
        assert_within_2x(measured, WEF_EVENT_BYTES, "WindowsEvent");
    }

    #[test]
    fn every_derived_capacity_is_nonzero_and_within_budget() {
        for (name, bytes) in [
            ("zeek", ZEEK_RECORD_BYTES),
            ("suricata", SURICATA_RECORD_BYTES),
            ("generic", GENERIC_RECORD_BYTES),
            ("syslog", SYSLOG_MESSAGE_BYTES),
            ("sflow", SFLOW_RECORD_BYTES),
            ("ipfix", IPFIX_DATAGRAM_BYTES),
            ("wef", WEF_EVENT_BYTES),
        ] {
            let cap = capacity_for(bytes);
            assert!(cap >= 1, "{name} capacity must be >= 1");
            assert!(
                cap * bytes <= CHANNEL_BUDGET_BYTES,
                "{name}: {cap} records x {bytes} bytes exceeds the budget"
            );
        }
    }
```

Add matching `measured_*_bytes_matches_constant` tests for `SuricataRecord`, `GenericRecord`, `SyslogMessage`, `SflowRecord`, and the IPFIX `Vec<FlowRecord>` following the same shape: build a representative value, sum `size_of` plus owned heap, call `assert_within_2x`. For IPFIX, build the `Vec` with the flows-per-datagram count used by the existing fixtures in `src/forwarding/ipfix_s3.rs` tests and document that count in a comment.

- [ ] **Step 6: Run the tests, adjust constants to what you measured**

Run: `cargo test --lib forwarding::channel_budget -- --nocapture`
Expected: PASS. If a `assert_within_2x` fails, the failure message names the measured value — set the constant to that value rounded up, and re-run. Do **not** widen the tolerance to make a test pass.

- [ ] **Step 7: Commit**

```bash
git add src/forwarding/channel_budget.rs src/forwarding/mod.rs
git commit -m "feat(channel): add 100MiB channel budget and measured record footprints"
```

---

## Task 2: Derive every source's channel_capacity default from the budget

**Files:**
- Modify: `src/config/mod.rs` (fns at lines 304, 406, 468, 548, 745, 806, 911)
- Modify: `logthing.toml` (the `channel_capacity` comment lines, e.g. line 61 and 82)

**Interfaces:**
- Consumes: `capacity_for`, `CHANNEL_BUDGET_BYTES`, and the seven `*_BYTES` constants from Task 1.
- Produces: no new symbols; the seven existing `default_*_channel_capacity()` fns change their returned values.

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `src/config/mod.rs`:

```rust
#[test]
fn channel_capacity_defaults_derive_from_the_budget() {
    use crate::forwarding::channel_budget::*;
    assert_eq!(default_zeek_channel_capacity(), capacity_for(ZEEK_RECORD_BYTES));
    assert_eq!(default_suricata_channel_capacity(), capacity_for(SURICATA_RECORD_BYTES));
    assert_eq!(default_hec_channel_capacity(), capacity_for(GENERIC_RECORD_BYTES));
    assert_eq!(default_syslog_s3_channel_capacity(), capacity_for(SYSLOG_MESSAGE_BYTES));
    assert_eq!(default_sflow_channel_capacity(), capacity_for(SFLOW_RECORD_BYTES));
    assert_eq!(default_ipfix_channel_capacity(), capacity_for(IPFIX_DATAGRAM_BYTES));
    assert_eq!(default_wef_channel_capacity(), capacity_for(WEF_EVENT_BYTES));
}

#[test]
fn channel_capacity_defaults_are_far_above_the_old_256() {
    // The incident this change addresses: 256 records is ~60-250ms of burst
    // headroom at realistic sensor rates.
    assert!(default_zeek_channel_capacity() > 10_000);
    assert!(default_suricata_channel_capacity() > 10_000);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib config::tests::channel_capacity`
Expected: FAIL — `default_zeek_channel_capacity()` still returns 256.

- [ ] **Step 3: Write the implementation**

Rewrite each of the seven default fns in `src/config/mod.rs`. Zeek shown; apply the identical pattern to the other six:

```rust
/// Bounded channel depth, derived from the shared 100 MiB per-source budget
/// (`channel_budget::CHANNEL_BUDGET_BYTES`) and the measured per-record
/// footprint. Was a hardcoded 256 — roughly 60-250 ms of burst headroom,
/// which is what caused the production channel-full drops.
fn default_zeek_channel_capacity() -> usize {
    crate::forwarding::channel_budget::capacity_for(
        crate::forwarding::channel_budget::ZEEK_RECORD_BYTES,
    )
}
```

Mapping: zeek → `ZEEK_RECORD_BYTES`; suricata → `SURICATA_RECORD_BYTES`; hec → `GENERIC_RECORD_BYTES`; syslog_s3 → `SYSLOG_MESSAGE_BYTES`; sflow → `SFLOW_RECORD_BYTES`; ipfix → `IPFIX_DATAGRAM_BYTES`; wef → `WEF_EVENT_BYTES`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib config::tests::channel_capacity`
Expected: PASS, 2 tests.

- [ ] **Step 5: Update the config file comments**

In `logthing.toml`, every line reading `# channel_capacity      = 256                     # channel depth (default 256)` must state the new derived default for that source, e.g.:

```toml
# channel_capacity      = 51200                   # channel depth (default: 100 MiB budget / ~2 KiB per record)
```

Use the value the corresponding `default_*_channel_capacity()` now returns. Check every source block in the file — `zeek`, `suricata`, `hec`, `syslog`, `sflow`, `ipfix`, `wef` — and any `*.local` blocks that document the same key.

- [ ] **Step 6: Run the full config and forwarding test suites**

Run: `cargo test --lib config:: && cargo test --lib forwarding::`
Expected: PASS. Several existing tests construct configs with explicit `channel_capacity` values and are unaffected; if any test asserted the literal `256` default, update it to assert the derived value.

- [ ] **Step 7: Commit**

```bash
git add src/config/mod.rs logthing.toml
git commit -m "feat(config): size every channel_capacity default from the 100MiB budget"
```

---

## Task 3: Bounded-wait send on ParquetWriterHandle

**Files:**
- Modify: `src/forwarding/drop_log.rs` (after the existing `impl<R> From<&TrySendError<R>> for DropKind`, line 47-54)
- Modify: `src/forwarding/buffered_writer.rs` (struct at 1120-1139, `start_with_stats` return at 1254-1263, methods after `try_send` at 1290)

**Interfaces:**
- Consumes: nothing from Tasks 1-2.
- Produces:
  - `pub const SEND_TIMEOUT_DEFAULT: Duration` in `buffered_writer`
  - `ParquetWriterHandle::with_send_timeout(self, timeout: Duration) -> Self`
  - `ParquetWriterHandle::send_or_drop(&self, record: S::Record) -> Result<(), tokio::sync::mpsc::error::SendTimeoutError<S::Record>>` (async)
  - `impl<R> From<&SendTimeoutError<R>> for DropKind`

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `src/forwarding/drop_log.rs`:

```rust
#[test]
fn drop_kind_derives_from_send_timeout_error() {
    use tokio::sync::mpsc::error::SendTimeoutError;
    let timeout: SendTimeoutError<u8> = SendTimeoutError::Timeout(1);
    let closed: SendTimeoutError<u8> = SendTimeoutError::Closed(1);
    // A timeout means the channel stayed full for the whole wait — same
    // operator-facing meaning as Full, and it must not be muted by a Closed.
    assert_eq!(DropKind::from(&timeout), DropKind::Full);
    assert_eq!(DropKind::from(&closed), DropKind::Closed);
}
```

Add to the `tests` module in `src/forwarding/buffered_writer.rs`:

```rust
#[tokio::test]
async fn send_or_drop_delivers_when_capacity_is_available() {
    let (handle, _task) = ParquetWriterHandle::start(
        MockSink,
        Arc::new(MockUploadSink),
        BufferedWriterConfig {
            connection: unused_s3_connection_placeholder(),
            prefix: "t".to_string(),
            max_buffer_rows: 10,
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 4,
            max_partitions: 0,
        },
        FlushPolicy::default(),
    );
    assert!(handle.send_or_drop("hello".to_string()).await.is_ok());
}

#[tokio::test]
async fn send_or_drop_times_out_and_reports_full_when_the_writer_never_drains() {
    // Capacity 1 and a writer that is never polled: the first send fills the
    // channel, the second must wait the full timeout and then report Timeout.
    let (tx, _rx) = tokio::sync::mpsc::channel::<String>(1);
    tx.send("first".to_string()).await.unwrap();
    let start = std::time::Instant::now();
    let err = tx
        .send_timeout("second".to_string(), Duration::from_millis(50))
        .await
        .expect_err("must time out against a full, undrained channel");
    assert!(matches!(err, tokio::sync::mpsc::error::SendTimeoutError::Timeout(_)));
    assert!(start.elapsed() >= Duration::from_millis(50));
}

#[test]
fn send_timeout_default_is_five_seconds() {
    assert_eq!(SEND_TIMEOUT_DEFAULT, Duration::from_secs(5));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib forwarding::drop_log && cargo test --lib forwarding::buffered_writer`
Expected: FAIL — `SEND_TIMEOUT_DEFAULT` not found, `send_or_drop` not found, and no `From<&SendTimeoutError<R>>` impl.

- [ ] **Step 3: Write the implementation**

In `src/forwarding/drop_log.rs`, after the existing `TrySendError` impl:

```rust
impl<R> From<&tokio::sync::mpsc::error::SendTimeoutError<R>> for DropKind {
    fn from(err: &tokio::sync::mpsc::error::SendTimeoutError<R>) -> Self {
        use tokio::sync::mpsc::error::SendTimeoutError;
        match err {
            // The channel stayed full for the entire bounded wait. Operationally
            // identical to Full: transient backpressure that outlasted patience.
            SendTimeoutError::Timeout(_) => DropKind::Full,
            SendTimeoutError::Closed(_) => DropKind::Closed,
        }
    }
}
```

In `src/forwarding/buffered_writer.rs`, add the constant near the other tunables (beside `MAX_CONCURRENT_FLUSHES_PER_WRITER`, line 375):

```rust
/// How long a backpressure-aware sender waits for channel capacity before
/// giving up and dropping the record.
///
/// Far longer than any plausible writer hiccup (a `spawn_blocking` zstd encode,
/// a metrics scrape), far shorter than sensor and TCP timeouts. Deliberately
/// not a config key — no evidence anyone needs to tune it, and promoting a
/// const to a config field later is trivial.
///
/// ponytail: const + per-handle override; promote to `BufferedWriterConfig` if
/// an operator ever needs it per-source.
pub const SEND_TIMEOUT_DEFAULT: Duration = Duration::from_secs(5);
```

Add the field to `ParquetWriterHandle` (after `flush_interval`, line 1130):

```rust
    /// Bounded wait applied by `send_or_drop`. A field rather than a bare
    /// constant so tests can shorten it — otherwise every test that must
    /// observe the drop-after-timeout path would stall for 5 real seconds.
    send_timeout: Duration,
```

Set it in `start_with_stats`'s returned `Self` (line 1254-1263):

```rust
            Self {
                tx,
                source,
                target,
                flush_interval: handle_flush_interval,
                drop_log: Arc::new(DropLogThrottles::new()),
                send_timeout: SEND_TIMEOUT_DEFAULT,
            },
```

Add both methods after `try_send` (line 1290):

```rust
    /// Override the bounded-wait timeout used by `send_or_drop`. Test seam.
    #[must_use]
    pub fn with_send_timeout(mut self, timeout: Duration) -> Self {
        self.send_timeout = timeout;
        self
    }

    /// Send one record, waiting up to `send_timeout` for channel capacity.
    ///
    /// This is the backpressure-aware counterpart to `try_send`, for sources
    /// whose transport can absorb the wait: awaiting here stops the caller's
    /// per-connection task from reading its socket, which closes the TCP
    /// window and pushes the queue back to the sender. Only use it from a task
    /// that owns a single connection — never from a task shared across
    /// connections or transports (see the spec's §3.1 note on syslog).
    ///
    /// On timeout or a closed channel the record is dropped and
    /// `parquet_s3_dropped{source,target}` is incremented, exactly as
    /// `try_send` does, so the existing safety valve and metrics are unchanged.
    #[must_use = "callers should log or handle the error to avoid silent record loss"]
    pub async fn send_or_drop(
        &self,
        record: S::Record,
    ) -> Result<(), tokio::sync::mpsc::error::SendTimeoutError<S::Record>> {
        match self.tx.send_timeout(record, self.send_timeout).await {
            Ok(()) => Ok(()),
            Err(e) => {
                metrics::counter!("parquet_s3_dropped", "source" => self.source, "target" => self.target)
                    .increment(1);
                Err(e)
            }
        }
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib forwarding::drop_log && cargo test --lib forwarding::buffered_writer`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/forwarding/drop_log.rs src/forwarding/buffered_writer.rs
git commit -m "feat(writer): add bounded-wait send_or_drop alongside try_send"
```

---

## Task 4: Zeek and Suricata handlers apply backpressure

**Files:**
- Modify: `src/forwarding/zeek_s3.rs:160-174` (the `ZeekHandler` impl)
- Modify: `src/forwarding/suricata_s3.rs:110-126` (the `SuricataHandler` impl)
- Modify: `src/forwarding/zeek_s3.rs:653-723` (`handler_overflow_increments_dropped_counter`)
- Modify: the equivalent capacity-1 overflow test in `src/forwarding/suricata_s3.rs` (config at line 426)

**Interfaces:**
- Consumes: `send_or_drop`, `with_send_timeout`, `SEND_TIMEOUT_DEFAULT` from Task 3; `DropKind::from(&SendTimeoutError<_>)` from Task 3.
- Produces: no new symbols — behaviour change only.

- [ ] **Step 1: Update the existing overflow tests to the new behaviour**

`handler_overflow_increments_dropped_counter` currently relies on `try_send` returning instantly against a capacity-1 channel. Under blocking sends it would stall 50 x 5 s. Shorten the timeout at construction so the test still exercises the drop path fast. In `src/forwarding/zeek_s3.rs`, change the handler construction (line 682-687) to:

```rust
        let (handler, _writer_handle) = zeek_start(
            &cfg,
            sink,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );
        // The writer is wired to an unreachable sink, so the channel stays
        // full; a 20ms bounded wait keeps this test fast while still taking
        // the real timeout-then-drop path.
        let handler = handler.with_send_timeout(std::time::Duration::from_millis(20));
```

Apply the identical change to the Suricata overflow test whose config is at `src/forwarding/suricata_s3.rs:426`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib forwarding::zeek_s3 && cargo test --lib forwarding::suricata_s3`
Expected: FAIL to compile — `with_send_timeout` returns `Self` but `zeek_start` returns a tuple; make sure you rebind only the handler, not the tuple. Once compiling, the tests pass but still exercise `try_send` — that is expected until step 3.

- [ ] **Step 3: Switch both handlers to the bounded-wait send**

`src/forwarding/zeek_s3.rs`, replacing the body of `handle_record` at line 160-174:

```rust
    async fn handle_record(&self, record: ZeekRecord, source: std::net::SocketAddr) {
        // Bounded wait, not try_send: Zeek arrives over TCP on a dedicated
        // per-connection task, so blocking here stops reading this one socket,
        // closes the TCP window, and pushes the queue back to the sensor —
        // which has its own disk-backed spool. A drop now means the writer was
        // unavailable for a full SEND_TIMEOUT_DEFAULT, not merely that a burst
        // arrived.
        match self.send_or_drop(record).await {
            Ok(()) => {}
            Err(e) => {
                // parquet_s3_dropped{source="zeek"} is already incremented by send_or_drop.
                if let Some(dropped_total) = self.drop_log_due(DropSite::Zeek, DropKind::from(&e)) {
                    tracing::warn!(
                        dropped_total,
                        "Zeek S3 channel full for {:?}; dropped 1 record from {}",
                        SEND_TIMEOUT_DEFAULT,
                        source
                    );
                }
            }
        }
    }
```

Import `SEND_TIMEOUT_DEFAULT` at the top of the file alongside the existing `buffered_writer` imports. Apply the structurally identical change to `src/forwarding/suricata_s3.rs:110-126`, keeping its `DropSite::Suricata` and its "Suricata S3 channel full..." wording.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib forwarding::zeek_s3 && cargo test --lib forwarding::suricata_s3`
Expected: PASS. The overflow tests still see `parquet_s3_dropped >= 1` because the sink is unreachable and the 20 ms wait expires.

- [ ] **Step 5: Write the integration tests**

Create `tests/ingest_backpressure_integration.rs`:

```rust
//! Integration coverage for bounded-wait ingest sends (spec §3).

use logthing::forwarding::zeek_s3::zeek_local_start;
use std::sync::Arc;
use std::time::Duration;

mod helpers;

/// A send that cannot fit immediately must WAIT for the writer to drain and
/// then succeed — not drop. This is the whole point of the change.
#[tokio::test]
async fn full_channel_blocks_then_succeeds_once_the_writer_drains() {
    // Build a Zeek local writer with a deliberately tiny channel so the very
    // first burst exceeds it, and a real (fast) local-disk sink so the writer
    // genuinely drains.
    // Send more records than the channel can hold, then assert that EVERY
    // record was accepted (zero parquet_s3_dropped) and that the elapsed time
    // is below the send timeout — proving it waited rather than dropped.
    todo!("see step 5 guidance below")
}
```

Replace the `todo!` bodies with real tests following the construction pattern already used by `tests/zeek_local_integration.rs` (a `tempfile::TempDir`, `ZeekLocalConfig`, `zeek_local_start`, `LocalDiskSink`). Write these four tests:

1. `full_channel_blocks_then_succeeds_once_the_writer_drains` — channel capacity 4, 200 records, real local sink. Assert `parquet_s3_dropped{source="zeek"}` is **0** and all 200 rows reach Parquet. This fails on the pre-change code, which drops.
2. `wedged_writer_drops_after_the_timeout` — capacity 1, handler built with `.with_send_timeout(Duration::from_millis(50))`, writer wired to an unreachable sink. Send 20 records; assert `parquet_s3_dropped >= 1` and total elapsed is under 5 s (proving the *short* timeout was honoured, not the default).
3. `fan_out_does_not_serialise_a_healthy_destination_behind_a_stalled_one` — a `MultiZeekHandler` holding one deliberately slow handler (sleeps 200 ms per record) and one counting handler; send 5 records and assert the elapsed time is closer to `5 * 200ms` than to `5 * 400ms`, and that the counting handler saw all 5. (This test is written here but only *passes* after Task 5.)
4. `budget_full_channel_completes_shutdown_within_the_deadline` — fill a channel sized by `capacity_for(ZEEK_RECORD_BYTES)` to at least 20,000 records against a fast local sink, drop the handler, and assert the writer task joins within the same 10 s that `main.rs` allows. **If this test cannot pass, lower `CHANNEL_BUDGET_BYTES` until it does and record the new value in the spec** — the delivered budget is whatever this test permits.

- [ ] **Step 6: Run the integration tests**

Run: `cargo test --test ingest_backpressure_integration`
Expected: tests 1, 2, 4 PASS; test 3 FAILS until Task 5. That is the intended TDD state — do not skip or ignore test 3.

- [ ] **Step 7: Commit**

```bash
git add src/forwarding/zeek_s3.rs src/forwarding/suricata_s3.rs tests/ingest_backpressure_integration.rs
git commit -m "feat(ingest): apply TCP backpressure on Zeek and Suricata sends"
```

---

## Task 5: Concurrent multi-destination fan-out

**Files:**
- Modify: `src/forwarding/zeek_s3.rs:187-194` (`MultiZeekHandler`)
- Modify: `src/forwarding/suricata_s3.rs:141-148` (`MultiSuricataHandler`)

**Interfaces:**
- Consumes: the blocking handlers from Task 4; test 3 from Task 4's integration file.
- Produces: no new symbols.

- [ ] **Step 1: Confirm the failing test**

Run: `cargo test --test ingest_backpressure_integration fan_out_does_not_serialise`
Expected: FAIL — sequential fan-out makes elapsed time the *sum* of both destinations.

- [ ] **Step 2: Make the fan-out concurrent**

`src/forwarding/zeek_s3.rs`:

```rust
#[async_trait::async_trait]
impl crate::zeek::listener::ZeekHandler for MultiZeekHandler {
    async fn handle_record(&self, record: ZeekRecord, source: std::net::SocketAddr) {
        // Concurrent, not sequential: sends now block for up to
        // SEND_TIMEOUT_DEFAULT, and awaiting destinations in series would let a
        // stalled S3 target add that latency to an otherwise-healthy local one.
        // Each destination owns an independent channel and writer with no
        // shared mutable state, so concurrent polling is safe and total latency
        // becomes max() instead of sum().
        futures::future::join_all(
            self.0
                .iter()
                .map(|handler| handler.handle_record(record.clone(), source)),
        )
        .await;
    }
}
```

Apply the structurally identical change to `MultiSuricataHandler` in `src/forwarding/suricata_s3.rs:141-148`.

- [ ] **Step 3: Run the tests to verify they pass**

Run: `cargo test --test ingest_backpressure_integration && cargo test --lib forwarding::zeek_s3 && cargo test --lib forwarding::suricata_s3`
Expected: PASS — including the pre-existing `multi_zeek_handler` test asserting the healthy handler receives every record even when the struggling one drops (`src/forwarding/zeek_s3.rs` around line 900), which must still hold.

- [ ] **Step 4: Commit**

```bash
git add src/forwarding/zeek_s3.rs src/forwarding/suricata_s3.rs
git commit -m "fix(ingest): fan out to multiple destinations concurrently"
```

---

## Task 6: Report how much data is at risk at shutdown

**Files:**
- Modify: `src/forwarding/buffered_writer.rs:1212-1222` (the channel-closed arm of the writer loop)

**Interfaces:**
- Consumes: nothing new.
- Produces: `PartitionedParquetWriter::total_buffered_rows(&self) -> usize` (crate-visible).

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `src/forwarding/buffered_writer.rs`:

```rust
#[tokio::test]
async fn total_buffered_rows_sums_every_partition() {
    let mut writer = PartitionedParquetWriter::new(
        MockSink,
        Arc::new(MockUploadSink),
        BufferedWriterConfig {
            connection: unused_s3_connection_placeholder(),
            prefix: "t".to_string(),
            max_buffer_rows: usize::MAX,
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 16,
            max_partitions: 0,
        },
        FlushPolicy {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
            interval: LiveInterval::new(Duration::from_secs(3600)),
        },
    );
    assert_eq!(writer.total_buffered_rows(), 0);
    writer.push("a".to_string()).await.unwrap();
    writer.push("b".to_string()).await.unwrap();
    assert_eq!(writer.total_buffered_rows(), 2);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib forwarding::buffered_writer::tests::total_buffered_rows`
Expected: FAIL — no method `total_buffered_rows`.

- [ ] **Step 3: Write the implementation**

Add the method to `impl<S: ParquetSink> PartitionedParquetWriter<S>`, next to `update_buffer_gauges` (line 797):

```rust
    /// Rows currently buffered across every partition, including any live
    /// amortized builder. Used to report how much data is at stake when the
    /// shutdown path begins its final flush.
    pub(crate) fn total_buffered_rows(&self) -> usize {
        self.buffers.values().map(|b| b.row_count).sum()
    }
```

Then extend the channel-closed arm of the writer loop (line 1212-1222) so the operator learns the volume rather than inferring it from a cumulative counter:

```rust
                            None => {
                                // Channel closed — drain any in-flight background
                                // flushes first (so a late failure's data gets
                                // merged back for the final flush below to
                                // pick up), THEN flush whatever remains.
                                writer.drain_pending_flushes().await;
                                let at_risk = writer.total_buffered_rows();
                                tracing::info!(
                                    source,
                                    target,
                                    buffered_rows = at_risk,
                                    "parquet_s3 writer shutting down; flushing buffered rows"
                                );
                                if let Err(e) = writer.flush_all().await {
                                    tracing::warn!(
                                        source,
                                        target,
                                        buffered_rows = at_risk,
                                        "parquet_s3 flush_all on shutdown: {e}"
                                    );
                                }
                                break;
                            }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib forwarding::buffered_writer`
Expected: PASS.

- [ ] **Step 5: Confirm the shutdown-deadline regression test still holds**

Run: `cargo test --test ingest_backpressure_integration budget_full_channel_completes_shutdown`
Expected: PASS within the 10 s deadline. If it does not, lower `CHANNEL_BUDGET_BYTES` in `src/forwarding/channel_budget.rs` until it does, re-run Task 1 and Task 2's tests, and update §5 of the spec with the delivered value.

- [ ] **Step 6: Commit**

```bash
git add src/forwarding/buffered_writer.rs
git commit -m "feat(writer): log buffered row count at shutdown"
```

---

## Task 7: End-to-end proof that backpressure reaches the wire

**Files:**
- Create: `tests/zeek_backpressure_e2e.rs`

**Interfaces:**
- Consumes: everything from Tasks 1-6.
- Produces: no source symbols.

- [ ] **Step 1: Write the failing test**

Create `tests/zeek_backpressure_e2e.rs`. Model the harness on `examples/flush_decoupling_benchmark.rs`, which already wires a real `ZeekListener` on an ephemeral port against a custom `UploadSink`:

```rust
//! E2E: a Zeek sensor outrunning the writer must be back-pressured over TCP,
//! not silently dropped (spec §6).

use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// An UploadSink that sleeps, simulating a slow Garage endpoint.
struct SlowSink {
    delay: Duration,
}

#[async_trait::async_trait]
impl logthing::forwarding::buffered_writer::UploadSink for SlowSink {
    async fn upload(&self, _key: &str, _body: Vec<u8>) -> anyhow::Result<()> {
        tokio::time::sleep(self.delay).await;
        Ok(())
    }
    fn target_label(&self) -> &'static str {
        "e2e"
    }
    fn location_hint(&self) -> String {
        "slow-sink".to_string()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zeek_tcp_client_is_backpressured_rather_than_dropped() {
    // 1. Install a real PrometheusBuilder recorder (not DebuggingRecorder —
    //    it has a documented cross-thread visibility gap on a multi-threaded
    //    runtime, see BENCHMARK_RESULTS.md §1).
    // 2. Start a real ZeekListener on 127.0.0.1:0 wired to a
    //    ParquetWriterHandle<ZeekSink> backed by SlowSink { delay: 150ms }.
    // 3. Connect a real TcpStream and write NDJSON conn lines as fast as the
    //    socket accepts them, for a fixed duration.
    // 4. Assert parquet_s3_dropped{source="zeek"} == 0.
    // 5. Assert at least one write() call took materially longer than the
    //    others — the socket's send buffer filled because the server stopped
    //    reading. That is backpressure reaching the wire.
    todo!("implement per the numbered steps above")
}
```

Replace the `todo!` with the real implementation following those five numbered steps. For step 5, record per-write elapsed times in a `Vec<Duration>` and assert `max > 10 * median` — a socket that never blocks shows a flat distribution.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test zeek_backpressure_e2e`
Expected: FAIL initially on the `todo!`, then PASS once implemented. To confirm the test is meaningful, temporarily revert `zeek_s3.rs`'s `send_or_drop` back to `try_send` and check the test fails on the zero-drops assertion; then restore it.

- [ ] **Step 3: Run the whole suite and clippy**

Run: `cargo test && cargo clippy --all-targets`
Expected: PASS, no warnings.

- [ ] **Step 4: Commit**

```bash
git add tests/zeek_backpressure_e2e.rs
git commit -m "test(e2e): prove Zeek TCP backpressure reaches the wire"
```

---

## Self-Review

**Spec coverage:**

| Spec section | Task |
|---|---|
| §3.1 which sources (Zeek + Suricata only) | 4 |
| §3.2 `send_timeout` mechanism, unchanged drop path | 3, 4 |
| §3.3 5 s default as an overridable field | 3 |
| §3.4 concurrent fan-out | 5 |
| §4.1 record units, budget constant | 1 |
| §4.2 per-source derivation, seven default fns | 1, 2 |
| §4.3 measurement methodology incl. Arc pointee and Vec average-case | 1 |
| §4.4 aggregate memory documented | 1 (module doc) |
| §5 shutdown: keep 10 s, regression test, report volume | 4 (test 4), 6 |
| §6 unit / integration / e2e | 1-3 / 4-6 / 7 |
| §7 out of scope | not implemented, by design |

**Type consistency:** `send_or_drop` returns `Result<(), SendTimeoutError<S::Record>>` in Task 3 and is consumed that way in Task 4; `DropKind::from(&e)` is used against `&SendTimeoutError<_>` in Task 4 and the impl is added in Task 3. `capacity_for` and the seven `*_BYTES` constants are defined in Task 1 and consumed in Task 2 under those exact names. `with_send_timeout` takes `self` by value and returns `Self`, so Task 4 rebinds the handler rather than the tuple — called out explicitly in Task 4 step 2.

**Known deliberate ordering:** Task 4 writes an integration test that fails until Task 5 lands. Flagged in Task 4 step 6 so the implementer does not "fix" it by weakening the assertion.
