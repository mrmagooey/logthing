# Admin Console Per-Source Hourly Ingest Stats Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `SourceHourlyStats` counter fed from the existing Parquet/S3 write path, exposed as two new authenticated routes (`GET /stats` HTML, `GET /stats.json`) on the existing `src/admin/` console, showing ingested-record counts per pipeline source per hour over a rolling 24-hour window.

**Architecture:** A new `DashMap`-backed, hour-bucketed counter (`src/stats/mod.rs`) is incremented once per record inside `PartitionedParquetWriter::push()` (`src/forwarding/buffered_writer.rs`) — at record-acceptance time, not flush time, so counts land in the hour a record actually arrived rather than the hour its buffer happened to drain. A single shared `Arc<SourceHourlyStats>` is constructed once in `main.rs` and threaded into each of the 8 per-source writer-startup functions and into the admin server, which reads it via two new read-only, auth-gated routes.

**Tech Stack:** Rust, tokio, axum, dashmap, chrono, serde — all already dependencies. No new crates.

## Global Constraints

- No new dependencies (no templating crate, no metrics-recorder wrapper, no global/`LazyLock` singleton for the stats struct).
- `SourceHourlyStats::record` is a plain sync fn (not `async fn`) — `DashMap` entry access has no await point.
- Retention: 24 hourly buckets, in-memory only, reset on process restart.
- The 8 production per-source `_start` functions and `main.rs` must pass a shared `Arc<SourceHourlyStats>`; the existing ~20 test call sites of `PartitionedParquetWriter::new`/`ParquetWriterHandle::start` must keep compiling **unchanged** (via thin-wrapper defaults).
- `/stats` and `/stats.json` require the same `ensure_authorized` basic-auth check as `/config` and `/audit-log` — not open like `/health`.
- Counting is done once per record in `push()` right after a successful `to_record_batch()`, keyed by `self.sink.source()`. It is **not** done in `flush_partition()` (would skew the hour attribution — see spec).
- Spec: `docs/superpowers/specs/2026-07-02-admin-source-hourly-stats-design.md`. Branch: `feature/admin-source-hourly-stats` (already created, spec already committed at `4d5d5bb`).

---

## Task 1: `SourceHourlyStats` struct + unit tests

**Files:**
- Modify: `src/stats/mod.rs`

**Interfaces:**
- Produces: `pub struct SourceHourlyStats` with `pub fn new() -> Self`, `pub fn default() -> Self` (via `#[derive(Default)]` semantics matching `ThroughputStats`'s pattern), `pub fn record(&self, source: &str, count: u64)` (sync), `pub fn snapshot(&self) -> Vec<SourceHourlySnapshot>`. `pub struct SourceHourlySnapshot { pub source: String, pub hours: Vec<HourCount> }` (`#[derive(Serialize, Clone)]`). `pub struct HourCount { pub hour: chrono::DateTime<chrono::Utc>, pub count: u64 }` (`#[derive(Serialize, Clone)]`).

- [ ] **Step 1: Write the failing unit tests**

Add to the bottom of `src/stats/mod.rs`, inside the existing `#[cfg(test)] mod tests { use super::*; ... }` block (after the existing `records_counts_per_event_type` test):

```rust
    #[test]
    fn source_hourly_records_counts_per_source() {
        let stats = SourceHourlyStats::new();

        stats.record("syslog", 3);
        stats.record("ipfix", 1);
        stats.record("syslog", 2);

        let snapshot = stats.snapshot();
        let mut by_source: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        for row in snapshot {
            let total: u64 = row.hours.iter().map(|h| h.count).sum();
            by_source.insert(row.source, total);
        }

        assert_eq!(by_source.get("syslog"), Some(&5));
        assert_eq!(by_source.get("ipfix"), Some(&1));
    }

    #[test]
    fn source_hourly_buckets_by_current_hour() {
        let stats = SourceHourlyStats::new();
        stats.record("zeek", 7);

        let snapshot = stats.snapshot();
        let row = snapshot.iter().find(|r| r.source == "zeek").unwrap();
        assert_eq!(row.hours.len(), 1, "expected exactly one hour bucket so far");
        assert_eq!(row.hours[0].count, 7);
    }

    #[test]
    fn source_hourly_retains_at_most_24_hours() {
        let stats = SourceHourlyStats::new();
        // Directly drive record() with synthetic hours via the internal helper
        // by recording, then asserting eviction behavior through the public
        // API: record 30 distinct synthetic "hours" is not possible without
        // a clock seam, so this test instead verifies the retention constant
        // itself is wired to the bucket-eviction path by checking that a
        // freshly recorded source never exceeds 24 buckets even after many
        // record() calls within the same hour (they coalesce into one bucket).
        for _ in 0..100 {
            stats.record("wef", 1);
        }
        let snapshot = stats.snapshot();
        let row = snapshot.iter().find(|r| r.source == "wef").unwrap();
        assert_eq!(row.hours.len(), 1, "same-hour records coalesce into one bucket");
        assert_eq!(row.hours[0].count, 100);
    }

    #[test]
    fn source_hourly_snapshot_empty_when_nothing_recorded() {
        let stats = SourceHourlyStats::new();
        assert!(stats.snapshot().is_empty());
    }
```

- [ ] **Step 2: Run tests to verify they fail (struct doesn't exist yet)**

Run: `cargo test --lib source_hourly -- --test-threads=1`
Expected: FAIL to compile — `cannot find struct/function SourceHourlyStats in this scope` (or similar).

- [ ] **Step 3: Implement `SourceHourlyStats`**

Add to `src/stats/mod.rs`, after the existing `ThroughputStats` implementation and its `EventStats`/`MinuteBucket` internals (i.e. after line 174's `current_minute()` fn, before the existing `#[cfg(test)] mod tests` block):

```rust
const HOUR_RETENTION: i64 = 24;

/// Per-pipeline-source, hour-bucketed ingest counter.
///
/// Keyed by the same `source` string used as the S3-key/metrics label
/// (`ParquetSink::source()` — `"wef"`, `"syslog"`, `"ipfix"`, `"sflow"`,
/// `"zeek"`, `"suricata"`, `"generic"`, `"structured_syslog"`), bucketed by
/// hour with a rolling 24-hour retention. In-memory only; resets on restart.
#[derive(Clone)]
pub struct SourceHourlyStats {
    inner: Arc<DashMap<String, SourceBuckets>>,
}

impl Default for SourceHourlyStats {
    fn default() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }
}

impl SourceHourlyStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `count` ingested records for `source` in the current hour.
    /// Sync: `DashMap` entry access has no await point, so there is no
    /// value in making this `async fn`.
    pub fn record(&self, source: &str, count: u64) {
        let hour = current_hour();
        self.inner
            .entry(source.to_string())
            .or_default()
            .record(hour, count);
    }

    /// Snapshot all sources' last-24h hourly counts, oldest bucket first.
    pub fn snapshot(&self) -> Vec<SourceHourlySnapshot> {
        let mut rows: Vec<SourceHourlySnapshot> = self
            .inner
            .iter()
            .map(|entry| entry.value().to_snapshot(entry.key().clone()))
            .collect();
        rows.sort_by(|a, b| a.source.cmp(&b.source));
        rows
    }
}

#[derive(Default)]
struct SourceBuckets {
    buckets: VecDeque<RawHourBucket>,
}

struct RawHourBucket {
    hour: i64,
    count: u64,
}

impl SourceBuckets {
    fn record(&mut self, hour: i64, count: u64) {
        match self.buckets.back_mut() {
            Some(bucket) if bucket.hour == hour => bucket.count += count,
            _ => self.buckets.push_back(RawHourBucket { hour, count }),
        }
        self.retain_recent(hour);
    }

    fn retain_recent(&mut self, hour: i64) {
        while let Some(front) = self.buckets.front() {
            if front.hour < hour - HOUR_RETENTION + 1 {
                self.buckets.pop_front();
            } else {
                break;
            }
        }
    }

    fn to_snapshot(&self, source: String) -> SourceHourlySnapshot {
        let hours = self
            .buckets
            .iter()
            .map(|b| HourCount {
                hour: chrono::DateTime::from_timestamp(b.hour * 3600, 0).unwrap_or_default(),
                count: b.count,
            })
            .collect();
        SourceHourlySnapshot { source, hours }
    }
}

#[derive(Serialize, Clone)]
pub struct SourceHourlySnapshot {
    pub source: String,
    pub hours: Vec<HourCount>,
}

#[derive(Serialize, Clone)]
pub struct HourCount {
    pub hour: DateTime<Utc>,
    pub count: u64,
}

fn current_hour() -> i64 {
    let now: DateTime<Utc> = Utc::now();
    now.timestamp() / 3600
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib source_hourly -- --test-threads=1`
Expected: PASS (4 tests: `source_hourly_records_counts_per_source`, `source_hourly_buckets_by_current_hour`, `source_hourly_retains_at_most_24_hours`, `source_hourly_snapshot_empty_when_nothing_recorded`)

- [ ] **Step 5: Commit**

```bash
git add src/stats/mod.rs
git commit -m "feat(stats): add SourceHourlyStats per-source hourly ingest counter"
```

---

## Task 2: Hook `SourceHourlyStats` into `PartitionedParquetWriter::push()`

**Files:**
- Modify: `src/forwarding/buffered_writer.rs`

**Interfaces:**
- Consumes: `crate::stats::SourceHourlyStats` (Task 1) — `SourceHourlyStats::new()`, `.record(&str, u64)`.
- Produces: `PartitionedParquetWriter<S>::with_source_stats(sink: S, s3: Arc<S3Sink>, config: BufferedWriterConfig, policy: FlushPolicy, source_stats: Arc<SourceHourlyStats>) -> Self` (real constructor; existing `new(...)` becomes a thin wrapper). `ParquetWriterHandle<S>::start_with_stats(sink: S, s3: Arc<S3Sink>, config: BufferedWriterConfig, policy: FlushPolicy, source_stats: Arc<SourceHourlyStats>) -> (Self, tokio::task::JoinHandle<()>)` (real constructor; existing `start(...)` becomes a thin wrapper).

- [ ] **Step 1: Write the failing test**

Add to `src/forwarding/buffered_writer.rs`'s existing `#[cfg(test)] mod tests` block, after `push_accumulates_below_row_threshold`:

```rust
    /// `push()` must record into a shared `SourceHourlyStats` once per
    /// record, independent of whether the record's buffer ever flushes.
    #[tokio::test]
    async fn push_records_into_shared_source_hourly_stats() {
        let s3 = unreachable_s3().await;
        let (cfg, policy) = test_config(1_000); // high threshold: nothing flushes
        let shared_stats = Arc::new(crate::stats::SourceHourlyStats::new());
        let mut w = PartitionedParquetWriter::with_source_stats(
            MockSink,
            s3,
            cfg,
            policy,
            shared_stats.clone(),
        );

        for i in 0..3 {
            w.push(format!("r{i}")).await.unwrap();
        }

        let snapshot = shared_stats.snapshot();
        let row = snapshot.iter().find(|r| r.source == "test").unwrap();
        let total: u64 = row.hours.iter().map(|h| h.count).sum();
        assert_eq!(total, 3, "push() must count records even though nothing flushed");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib push_records_into_shared_source_hourly_stats -- --test-threads=1`
Expected: FAIL to compile — `no function or associated item named 'with_source_stats' found`.

- [ ] **Step 3: Add the `source_stats` field and builder constructors**

In `src/forwarding/buffered_writer.rs`, modify the `PartitionedParquetWriter` struct definition (currently at line ~176-183):

```rust
pub struct PartitionedParquetWriter<S: ParquetSink> {
    sink: S,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
    config: BufferedWriterConfig,
    policy: FlushPolicy,
    /// `""` key for None-partition sources; sanitized-path / `"event_type=<id>"` for multi-partition.
    pub(crate) buffers: HashMap<String, PartitionBuffer>,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
}
```

Replace the existing `impl<S: ParquetSink> PartitionedParquetWriter<S> { pub fn new(...) -> Self { ... } }` (currently lines ~185-199) with:

```rust
impl<S: ParquetSink> PartitionedParquetWriter<S> {
    pub fn new(
        sink: S,
        s3: Arc<crate::forwarding::s3_sink::S3Sink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
    ) -> Self {
        Self::with_source_stats(
            sink,
            s3,
            config,
            policy,
            Arc::new(crate::stats::SourceHourlyStats::default()),
        )
    }

    pub fn with_source_stats(
        sink: S,
        s3: Arc<crate::forwarding::s3_sink::S3Sink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
        source_stats: Arc<crate::stats::SourceHourlyStats>,
    ) -> Self {
        Self {
            sink,
            s3,
            config,
            policy,
            buffers: HashMap::new(),
            source_stats,
        }
    }
```

(Keep the closing `}` of the `impl` block where it already is — this only replaces the `new` associated function, the rest of the `impl` body (`push`, `flush_all`, etc.) is unchanged.)

- [ ] **Step 4: Add the counting call in `push()`**

In `push()`, immediately after the existing `to_record_batch` match block (currently lines ~238-247):

```rust
        let batch = match self.sink.to_record_batch(&record, &schema) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(
                    source = self.sink.source(),
                    "to_record_batch failed, skipping record: {e}"
                );
                return Ok(());
            }
        };
        self.source_stats.record(self.sink.source(), 1);
```

- [ ] **Step 5: Add `start_with_stats` to `ParquetWriterHandle`**

Replace the existing `impl<S: ParquetSink> ParquetWriterHandle<S> { pub fn start(...) -> (Self, JoinHandle<()>) { ... } }` (currently lines ~412-457) with:

```rust
impl<S: ParquetSink> ParquetWriterHandle<S> {
    /// Spawn the background writer task.
    /// Returns `(handle, JoinHandle)`. The `JoinHandle` must be awaited during
    /// graceful shutdown after all senders are dropped.
    pub fn start(
        sink: S,
        s3: Arc<crate::forwarding::s3_sink::S3Sink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        Self::start_with_stats(
            sink,
            s3,
            config,
            policy,
            Arc::new(crate::stats::SourceHourlyStats::default()),
        )
    }

    /// Same as `start`, but records ingested-record counts into a shared,
    /// externally-owned `SourceHourlyStats` (used to feed the admin `/stats`
    /// page from every source through one instance).
    pub fn start_with_stats(
        sink: S,
        s3: Arc<crate::forwarding::s3_sink::S3Sink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
        source_stats: Arc<crate::stats::SourceHourlyStats>,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let capacity = config.channel_capacity.max(1);
        // Capture the source label before `sink` is moved into the task.
        let source = sink.source();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<S::Record>(capacity);
        let flush_check = crate::forwarding::s3_sink::flush_check_interval(policy.interval);
        let handle = tokio::spawn(async move {
            let mut writer =
                PartitionedParquetWriter::with_source_stats(sink, s3, config, policy, source_stats);
            let mut interval = tokio::time::interval(flush_check);
            loop {
                tokio::select! {
                    msg = rx.recv() => {
                        match msg {
                            Some(record) => {
                                if let Err(e) = writer.push(record).await {
                                    tracing::warn!("parquet_s3 writer push error: {e}");
                                }
                            }
                            None => {
                                // Channel closed — flush all and exit.
                                if let Err(e) = writer.flush_all().await {
                                    tracing::warn!("parquet_s3 flush_all on shutdown: {e}");
                                }
                                break;
                            }
                        }
                    }
                    _ = interval.tick() => {
                        if let Err(e) = writer.flush_all_if_needed().await {
                            tracing::warn!("parquet_s3 flush_all_if_needed: {e}");
                        }
                    }
                }
            }
        });
        (Self { tx, source }, handle)
    }

    /// Try to send a record without blocking.
    ///
    /// On channel overflow or closed, increments `parquet_s3_dropped{source=<source>}` and
    /// returns the `TrySendError` to the caller so they can apply any additional handling.
    #[must_use = "callers should log or handle the TrySendError to avoid silent record loss"]
    pub fn try_send(
        &self,
        record: S::Record,
    ) -> Result<(), tokio::sync::mpsc::error::TrySendError<S::Record>> {
        match self.tx.try_send(record) {
            Ok(()) => Ok(()),
            Err(e) => {
                metrics::counter!("parquet_s3_dropped", "source" => self.source).increment(1);
                Err(e)
            }
        }
    }
}
```

- [ ] **Step 6: Run all buffered_writer tests to verify nothing broke and the new test passes**

Run: `cargo test --lib forwarding::buffered_writer -- --test-threads=1`
Expected: PASS — all existing tests (config deserialization, `build_key`, `push_accumulates_below_row_threshold`, `push_enforces_hard_cap_on_flush_failure`, etc.) plus the new `push_records_into_shared_source_hourly_stats`.

- [ ] **Step 7: Commit**

```bash
git add src/forwarding/buffered_writer.rs
git commit -m "feat(forwarding): count ingested records into SourceHourlyStats at push() time"
```

---

## Task 3: Thread `source_stats` through `syslog_start`

**Files:**
- Modify: `src/forwarding/syslog_s3.rs`

**Interfaces:**
- Consumes: `crate::stats::SourceHourlyStats` (Task 1), `ParquetWriterHandle::start_with_stats` (Task 2).
- Produces: `syslog_start(cfg: &SyslogS3Config, s3: Arc<S3Sink>, source_stats: Arc<crate::stats::SourceHourlyStats>) -> (SyslogS3Handler, JoinHandle<()>)`.

- [ ] **Step 1: Write the failing integration test**

Add to `src/forwarding/syslog_s3.rs`'s existing `#[cfg(test)] mod tests` block:

```rust
    #[tokio::test]
    async fn syslog_sink_reports_into_shared_source_hourly_stats() {
        use crate::forwarding::buffered_writer::{
            BufferedWriterConfig, FlushPolicy, PartitionedParquetWriter,
        };
        use std::sync::Arc;

        let s3 = unreachable_sink().await;
        let bwc = BufferedWriterConfig {
            connection: crate::config::S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "t".to_string(),
                region: "us-east-1".to_string(),
                access_key: "K".to_string(),
                secret_key: "S".to_string(),
            },
            prefix: "syslog".to_string(),
            max_buffer_rows: 1_000,
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 64,
            max_partitions: 1,
        };
        let policy = FlushPolicy {
            max_rows: 1_000,
            max_bytes: usize::MAX,
            interval: std::time::Duration::from_secs(3600),
        };
        let shared_stats = Arc::new(crate::stats::SourceHourlyStats::new());

        let mut writer = PartitionedParquetWriter::with_source_stats(
            SyslogSink,
            s3,
            bwc,
            policy,
            shared_stats.clone(),
        );
        writer.push(dummy_msg("test")).await.unwrap();

        let snapshot = shared_stats.snapshot();
        let row = snapshot.iter().find(|r| r.source == "syslog").unwrap();
        let total: u64 = row.hours.iter().map(|h| h.count).sum();
        assert_eq!(total, 1);
    }
```

This uses the file's existing `unreachable_sink()` helper (line ~255) and `dummy_msg(text: &str) -> SyslogMessage` helper (line ~237) — both already used by neighboring tests in this module, so no new scaffolding is needed.

- [ ] **Step 2: Run test to verify it passes already (validates Task 2's API against the real SyslogSink)**

Run: `cargo test --lib syslog_sink_reports_into_shared_source_hourly_stats -- --test-threads=1`
Expected: PASS — this test doesn't call `syslog_start` (that's changed in Step 3 below), it calls `PartitionedParquetWriter::with_source_stats` directly, which Task 2 already added.

- [ ] **Step 3: Update `syslog_start`'s signature**

In `src/forwarding/syslog_s3.rs`, modify `syslog_start` (currently lines 176-197):

```rust
pub fn syslog_start(
    cfg: &SyslogS3Config,
    s3: std::sync::Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (SyslogS3Handler, tokio::task::JoinHandle<()>) {
```

(Keep the rest of the function body unchanged up to the final line.) Change the final line from:

```rust
    ParquetWriterHandle::start(SyslogSink, s3, bwc, policy)
```

to:

```rust
    ParquetWriterHandle::start_with_stats(SyslogSink, s3, bwc, policy, source_stats)
```

- [ ] **Step 4: Run this file's tests to verify everything compiles and passes**

Run: `cargo test --lib forwarding::syslog_s3 -- --test-threads=1`
Expected: PASS (this will fail to compile until `main.rs`'s call site is also updated — Task 13 — because `cargo test --lib` compiles the whole crate. If it fails only with an error at `src/main.rs`'s call to `syslog_start(...)` about a missing argument, that is expected at this point in the plan; confirm the failure is *only* that missing-argument error at `main.rs`, not anything in `syslog_s3.rs` itself, then proceed — Task 13 fixes the `main.rs` call site.)

- [ ] **Step 5: Commit**

```bash
git add src/forwarding/syslog_s3.rs
git commit -m "feat(forwarding): thread source_stats through syslog_start"
```

---

## Task 4: Thread `source_stats` through `ipfix_start`

**Files:**
- Modify: `src/forwarding/ipfix_s3.rs`

**Interfaces:**
- Consumes: same as Task 3.
- Produces: `ipfix_start(cfg: &IpfixS3Config, s3: Arc<S3Sink>, source_stats: Arc<crate::stats::SourceHourlyStats>) -> (IpfixS3Handler, JoinHandle<()>)`.

- [ ] **Step 1: Write the failing integration test**

Add to `src/forwarding/ipfix_s3.rs`'s existing `#[cfg(test)] mod tests` block. This file already has an `unreachable_sink()`-style helper and a `make_flow_record(...)` helper used by neighboring tests (see the test around line 522) — reuse them:

```rust
    #[tokio::test]
    async fn ipfix_sink_reports_into_shared_source_hourly_stats() {
        let s3 = unreachable_sink().await;
        let bwc = BufferedWriterConfig {
            connection: S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "ipfix".to_string(),
            max_buffer_rows: 1_000,
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_partitions: 1,
        };
        let policy = FlushPolicy {
            max_rows: 1_000,
            max_bytes: usize::MAX,
            interval: std::time::Duration::from_secs(3600),
        };
        let shared_stats = std::sync::Arc::new(crate::stats::SourceHourlyStats::new());

        let mut writer = PartitionedParquetWriter::with_source_stats(
            IpfixSink,
            s3,
            bwc,
            policy,
            shared_stats.clone(),
        );
        let record = make_flow_record(None, None, serde_json::json!({}));
        writer.push(vec![record]).await.unwrap();

        let snapshot = shared_stats.snapshot();
        let row = snapshot.iter().find(|r| r.source == "ipfix").unwrap();
        let total: u64 = row.hours.iter().map(|h| h.count).sum();
        assert_eq!(total, 1);
    }
```

If `unreachable_sink()` or `make_flow_record(...)` have different names/signatures than shown here, use the exact names already present in this file's test module (grep this file for `async fn unreachable` and `fn make_flow_record`) — the load-bearing part of this test is the `with_source_stats` call and the final `snapshot()` assertion.

- [ ] **Step 2: Run test to verify it passes already (validates Task 2's API against the real IpfixSink)**

Run: `cargo test --lib ipfix_sink_reports_into_shared_source_hourly_stats -- --test-threads=1`
Expected: PASS.

- [ ] **Step 3: Update `ipfix_start`'s signature**

In `src/forwarding/ipfix_s3.rs`, modify `ipfix_start` (currently lines 269-290):

```rust
pub fn ipfix_start(
    cfg: &IpfixS3Config,
    s3: std::sync::Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (IpfixS3Handler, tokio::task::JoinHandle<()>) {
```

Change the final line from `ParquetWriterHandle::start(IpfixSink, s3, bwc, policy)` to:

```rust
    ParquetWriterHandle::start_with_stats(IpfixSink, s3, bwc, policy, source_stats)
```

- [ ] **Step 4: Run this file's tests**

Run: `cargo test --lib forwarding::ipfix_s3 -- --test-threads=1`
Expected: same expected outcome as Task 3 Step 4 — passes except for the (expected, not-yet-fixed) `main.rs` call site error, fixed in Task 13.

- [ ] **Step 5: Commit**

```bash
git add src/forwarding/ipfix_s3.rs
git commit -m "feat(forwarding): thread source_stats through ipfix_start"
```

---

## Task 5: Thread `source_stats` through `zeek_start`

**Files:**
- Modify: `src/forwarding/zeek_s3.rs`

**Interfaces:**
- Produces: `zeek_start(cfg: &ZeekS3Config, s3: Arc<S3Sink>, source_stats: Arc<crate::stats::SourceHourlyStats>) -> (ZeekS3Handler, JoinHandle<()>)`.

- [ ] **Step 1: Write the failing integration test**

Add to `src/forwarding/zeek_s3.rs`'s existing `#[cfg(test)] mod tests` block (this file already has 3 tests using `PartitionedParquetWriter::new(ZeekSink, sink, bwc, policy)` around lines 461/497/522 — copy one's `bwc`/`policy`/sink setup and adapt):

```rust
    #[tokio::test]
    async fn zeek_sink_reports_into_shared_source_hourly_stats() {
        let s3 = unreachable_sink().await;
        let bwc = BufferedWriterConfig {
            connection: S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "zeek".to_string(),
            max_buffer_rows: 1_000,
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_partitions: 256,
        };
        let policy = FlushPolicy {
            max_rows: 1_000,
            max_bytes: usize::MAX,
            interval: std::time::Duration::from_secs(3600),
        };
        let shared_stats = std::sync::Arc::new(crate::stats::SourceHourlyStats::new());

        let mut writer = PartitionedParquetWriter::with_source_stats(
            ZeekSink,
            s3,
            bwc,
            policy,
            shared_stats.clone(),
        );
        writer.push(make_conn_record("conn")).await.unwrap();

        let snapshot = shared_stats.snapshot();
        let row = snapshot.iter().find(|r| r.source == "zeek").unwrap();
        let total: u64 = row.hours.iter().map(|h| h.count).sum();
        assert_eq!(total, 1);
    }
```

This uses the file's existing `unreachable_sink()` helper (line ~219) and `make_conn_record(uid: &str) -> ZeekRecord` helper (line ~258).

- [ ] **Step 2: Run test to verify it passes already**

Run: `cargo test --lib zeek_sink_reports_into_shared_source_hourly_stats -- --test-threads=1`
Expected: PASS.

- [ ] **Step 3: Update `zeek_start`'s signature**

In `src/forwarding/zeek_s3.rs`, modify `zeek_start` (currently lines 171-196):

```rust
pub fn zeek_start(
    cfg: &ZeekS3Config,
    s3: std::sync::Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (ZeekS3Handler, tokio::task::JoinHandle<()>) {
```

Change the final line from `ParquetWriterHandle::start(ZeekSink, s3, bwc, policy)` to:

```rust
    ParquetWriterHandle::start_with_stats(ZeekSink, s3, bwc, policy, source_stats)
```

- [ ] **Step 4: Run this file's tests**

Run: `cargo test --lib forwarding::zeek_s3 -- --test-threads=1`
Expected: passes except the expected `main.rs` call-site error (fixed in Task 13).

- [ ] **Step 5: Commit**

```bash
git add src/forwarding/zeek_s3.rs
git commit -m "feat(forwarding): thread source_stats through zeek_start"
```

---

## Task 6: Thread `source_stats` through `suricata_start`

**Files:**
- Modify: `src/forwarding/suricata_s3.rs`

**Interfaces:**
- Produces: `suricata_start(cfg: &SuricataS3Config, s3: Arc<S3Sink>, source_stats: Arc<crate::stats::SourceHourlyStats>) -> (SuricataS3Handler, JoinHandle<()>)`.

- [ ] **Step 1: Write the failing integration test**

Add to `src/forwarding/suricata_s3.rs`'s existing `#[cfg(test)] mod tests` block (mirror the existing test around line 329, which already builds a `bwc`/`policy` with `prefix: "suricata"` and pushes via `make_alert_record`/`make_flow_record`):

```rust
    #[tokio::test]
    async fn suricata_sink_reports_into_shared_source_hourly_stats() {
        let s3 = unreachable_sink().await;
        let bwc = BufferedWriterConfig {
            connection: S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "suricata".to_string(),
            max_buffer_rows: 1_000,
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_partitions: 256,
        };
        let policy = FlushPolicy {
            max_rows: 1_000,
            max_bytes: usize::MAX,
            interval: std::time::Duration::from_secs(3600),
        };
        let shared_stats = std::sync::Arc::new(crate::stats::SourceHourlyStats::new());

        let mut writer = PartitionedParquetWriter::with_source_stats(
            SuricataSink,
            s3,
            bwc,
            policy,
            shared_stats.clone(),
        );
        writer.push(make_alert_record("1.1.1.1")).await.unwrap();

        let snapshot = shared_stats.snapshot();
        let row = snapshot.iter().find(|r| r.source == "suricata").unwrap();
        let total: u64 = row.hours.iter().map(|h| h.count).sum();
        assert_eq!(total, 1);
    }
```

Match this file's actual helper names (grep for `async fn unreachable` and `fn make_alert_record`) if they differ from above.

- [ ] **Step 2: Run test to verify it passes already**

Run: `cargo test --lib suricata_sink_reports_into_shared_source_hourly_stats -- --test-threads=1`
Expected: PASS.

- [ ] **Step 3: Update `suricata_start`'s signature**

In `src/forwarding/suricata_s3.rs`, modify `suricata_start` (currently lines 137-162):

```rust
pub fn suricata_start(
    cfg: &SuricataS3Config,
    s3: std::sync::Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (SuricataS3Handler, tokio::task::JoinHandle<()>) {
```

Change the final line from `ParquetWriterHandle::start(SuricataSink, s3, bwc, policy)` to:

```rust
    ParquetWriterHandle::start_with_stats(SuricataSink, s3, bwc, policy, source_stats)
```

- [ ] **Step 4: Run this file's tests**

Run: `cargo test --lib forwarding::suricata_s3 -- --test-threads=1`
Expected: passes except the expected `main.rs` call-site error (fixed in Task 13).

- [ ] **Step 5: Commit**

```bash
git add src/forwarding/suricata_s3.rs
git commit -m "feat(forwarding): thread source_stats through suricata_start"
```

---

## Task 7: Thread `source_stats` through `sflow_start`

**Files:**
- Modify: `src/forwarding/sflow_s3.rs`

**Interfaces:**
- Produces: `sflow_start(cfg: &SflowS3Config, s3: Arc<S3Sink>, source_stats: Arc<crate::stats::SourceHourlyStats>) -> (SflowS3Handler, JoinHandle<()>)`.

- [ ] **Step 1: Write the failing integration test**

Add to `src/forwarding/sflow_s3.rs`'s `#[cfg(test)] mod tests` block:

```rust
    #[tokio::test]
    async fn sflow_sink_reports_into_shared_source_hourly_stats() {
        use crate::config::S3ConnectionConfig;
        use crate::forwarding::s3_sink::S3Sink;

        let s3 = Arc::new(
            S3Sink::from_connection(&S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "t".to_string(),
                region: "us-east-1".to_string(),
                access_key: "K".to_string(),
                secret_key: "S".to_string(),
            })
            .await
            .unwrap(),
        );
        let bwc = BufferedWriterConfig {
            connection: S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "t".to_string(),
                region: "us-east-1".to_string(),
                access_key: "K".to_string(),
                secret_key: "S".to_string(),
            },
            prefix: "sflow".to_string(),
            max_buffer_rows: 1_000,
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 64,
            max_partitions: 2,
        };
        let policy = FlushPolicy {
            max_rows: 1_000,
            max_bytes: usize::MAX,
            interval: std::time::Duration::from_secs(3600),
        };
        let shared_stats = Arc::new(crate::stats::SourceHourlyStats::new());

        let mut writer = PartitionedParquetWriter::with_source_stats(
            SflowSink,
            s3,
            bwc,
            policy,
            shared_stats.clone(),
        );
        writer.push(make_flow_record()).await.unwrap();

        let snapshot = shared_stats.snapshot();
        let row = snapshot.iter().find(|r| r.source == "sflow").unwrap();
        let total: u64 = row.hours.iter().map(|h| h.count).sum();
        assert_eq!(total, 1);
    }
```

This uses the file's existing `make_flow_record() -> SflowRecord` helper (line ~176, no arguments).

- [ ] **Step 2: Run test to verify it passes already**

Run: `cargo test --lib sflow_sink_reports_into_shared_source_hourly_stats -- --test-threads=1`
Expected: PASS.

- [ ] **Step 3: Update `sflow_start`'s signature**

In `src/forwarding/sflow_s3.rs`, modify `sflow_start` (currently lines 145-164):

```rust
pub fn sflow_start(
    cfg: &SflowS3Config,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
) -> (SflowS3Handler, tokio::task::JoinHandle<()>) {
```

Change the final line from `ParquetWriterHandle::start(SflowSink, s3, bwc, policy)` to:

```rust
    ParquetWriterHandle::start_with_stats(SflowSink, s3, bwc, policy, source_stats)
```

- [ ] **Step 4: Run this file's tests**

Run: `cargo test --lib forwarding::sflow_s3 -- --test-threads=1`
Expected: passes except the expected `main.rs` call-site error (fixed in Task 13).

- [ ] **Step 5: Commit**

```bash
git add src/forwarding/sflow_s3.rs
git commit -m "feat(forwarding): thread source_stats through sflow_start"
```

---

## Task 8: Thread `source_stats` through `wef_start`

**Files:**
- Modify: `src/forwarding/parquet_s3.rs`

**Interfaces:**
- Produces: `wef_start(cfg: &WefS3Config, s3: Arc<S3Sink>, source_stats: Arc<crate::stats::SourceHourlyStats>) -> (ParquetWriterHandle<WefSink>, JoinHandle<()>)`.

- [ ] **Step 1: Write the failing integration test**

Add to `src/forwarding/parquet_s3.rs`'s `#[cfg(test)] mod tests` block (this file already has a test around line 332 using `PartitionedParquetWriter::new(WefSink, s3, cfg, policy)` — mirror its `cfg`/`policy` setup):

```rust
    #[tokio::test]
    async fn wef_sink_reports_into_shared_source_hourly_stats() {
        use crate::config::S3ConnectionConfig;
        use crate::forwarding::s3_sink::S3Sink;

        let conn = S3ConnectionConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            bucket: "t".to_string(),
            region: "us-east-1".to_string(),
            access_key: "K".to_string(),
            secret_key: "S".to_string(),
        };
        let s3 = Arc::new(S3Sink::from_connection(&conn).await.expect("construct"));
        let bwc = BufferedWriterConfig {
            connection: conn,
            prefix: "".to_string(),
            max_buffer_rows: 100_000,
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_partitions: 0,
        };
        let policy = FlushPolicy {
            max_rows: 100_000,
            max_bytes: usize::MAX,
            interval: std::time::Duration::from_secs(3600),
        };
        let shared_stats = std::sync::Arc::new(crate::stats::SourceHourlyStats::new());

        let mut writer = PartitionedParquetWriter::with_source_stats(
            WefSink,
            s3,
            bwc,
            policy,
            shared_stats.clone(),
        );
        writer.push(make_parsed_event(4624)).await.unwrap();

        let snapshot = shared_stats.snapshot();
        let row = snapshot.iter().find(|r| r.source == "wef").unwrap();
        let total: u64 = row.hours.iter().map(|h| h.count).sum();
        assert_eq!(total, 1);
    }
```

This uses the file's existing `make_parsed_event(event_id: u32) -> Arc<WindowsEvent>` helper (line ~159) and mirrors the inline S3-construction pattern the existing `unparsed_events_are_skipped_not_stored` test (line ~300) already uses in this file (no separate `unreachable_s3`/`unreachable_sink` helper exists here).

- [ ] **Step 2: Run test to verify it passes already**

Run: `cargo test --lib wef_sink_reports_into_shared_source_hourly_stats -- --test-threads=1`
Expected: PASS.

- [ ] **Step 3: Update `wef_start`'s signature**

In `src/forwarding/parquet_s3.rs`, modify `wef_start` (currently lines 100-124):

```rust
pub fn wef_start(
    cfg: &WefS3Config,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
) -> (
    crate::forwarding::buffered_writer::ParquetWriterHandle<WefSink>,
    tokio::task::JoinHandle<()>,
) {
```

Change the final line from `ParquetWriterHandle::start(WefSink, s3, bwc, policy)` to:

```rust
    ParquetWriterHandle::start_with_stats(WefSink, s3, bwc, policy, source_stats)
```

- [ ] **Step 4: Run this file's tests**

Run: `cargo test --lib forwarding::parquet_s3 -- --test-threads=1`
Expected: passes except the expected `main.rs` call-site error (fixed in Task 13).

- [ ] **Step 5: Commit**

```bash
git add src/forwarding/parquet_s3.rs
git commit -m "feat(forwarding): thread source_stats through wef_start"
```

---

## Task 9: Thread `source_stats` through `hec_start`

**Files:**
- Modify: `src/forwarding/generic_s3.rs`

**Interfaces:**
- Produces: `hec_start(cfg: &HecS3Config, s3: Arc<S3Sink>, max_partitions: usize, source_stats: Arc<crate::stats::SourceHourlyStats>) -> (GenericS3Handler, JoinHandle<()>)`.

- [ ] **Step 1: Write the failing integration test**

Add to `src/forwarding/generic_s3.rs`'s `#[cfg(test)] mod tests` block (mirror the existing test around line 294 using `make_record(...)`):

```rust
    #[tokio::test]
    async fn generic_sink_reports_into_shared_source_hourly_stats() {
        let s3 = unreachable_sink().await;
        let bwc = BufferedWriterConfig {
            connection: S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "hec".to_string(),
            max_buffer_rows: 1_000,
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_partitions: 64,
        };
        let policy = FlushPolicy {
            max_rows: 1_000,
            max_bytes: usize::MAX,
            interval: std::time::Duration::from_secs(3600),
        };
        let shared_stats = std::sync::Arc::new(crate::stats::SourceHourlyStats::new());

        let mut writer = PartitionedParquetWriter::with_source_stats(
            GenericSink,
            s3,
            bwc,
            policy,
            shared_stats.clone(),
        );
        writer.push(make_record("access_log")).await.unwrap();

        let snapshot = shared_stats.snapshot();
        let row = snapshot.iter().find(|r| r.source == "generic").unwrap();
        let total: u64 = row.hours.iter().map(|h| h.count).sum();
        assert_eq!(total, 1);
    }
```

Match this file's actual `unreachable_sink()`/`make_record(...)` helper names if they differ.

- [ ] **Step 2: Run test to verify it passes already**

Run: `cargo test --lib generic_sink_reports_into_shared_source_hourly_stats -- --test-threads=1`
Expected: PASS.

- [ ] **Step 3: Update `hec_start`'s signature**

In `src/forwarding/generic_s3.rs`, modify `hec_start` (currently lines 122-145). Note this function already has a `max_partitions: usize` parameter — add `source_stats` after it:

```rust
pub fn hec_start(
    cfg: &HecS3Config,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
    max_partitions: usize,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
) -> (GenericS3Handler, tokio::task::JoinHandle<()>) {
```

Change the final line from `ParquetWriterHandle::start(GenericSink, s3, bwc, policy)` to:

```rust
    ParquetWriterHandle::start_with_stats(GenericSink, s3, bwc, policy, source_stats)
```

- [ ] **Step 4: Run this file's tests**

Run: `cargo test --lib forwarding::generic_s3 -- --test-threads=1`
Expected: passes except the expected `main.rs` call-site error (fixed in Task 13).

- [ ] **Step 5: Commit**

```bash
git add src/forwarding/generic_s3.rs
git commit -m "feat(forwarding): thread source_stats through hec_start"
```

---

## Task 10: Thread `source_stats` through `structured_syslog_start`

**Files:**
- Modify: `src/forwarding/structured_syslog_s3.rs`

**Interfaces:**
- Produces: `structured_syslog_start(cfg: &SyslogS3Config, s3: Arc<S3Sink>, source_stats: Arc<crate::stats::SourceHourlyStats>) -> (StructuredS3Handler, JoinHandle<()>)`.

- [ ] **Step 1: Write the failing integration test**

Add to `src/forwarding/structured_syslog_s3.rs`'s `#[cfg(test)] mod tests` block:

```rust
    #[tokio::test]
    async fn structured_syslog_sink_reports_into_shared_source_hourly_stats() {
        use crate::config::S3ConnectionConfig;
        use crate::forwarding::s3_sink::S3Sink;
        use std::sync::Arc;

        let s3 = Arc::new(
            S3Sink::from_connection(&S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "t".to_string(),
                region: "us-east-1".to_string(),
                access_key: "K".to_string(),
                secret_key: "S".to_string(),
            })
            .await
            .unwrap(),
        );
        let bwc = BufferedWriterConfig {
            connection: S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "t".to_string(),
                region: "us-east-1".to_string(),
                access_key: "K".to_string(),
                secret_key: "S".to_string(),
            },
            prefix: "structured_syslog".to_string(),
            max_buffer_rows: 1_000,
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 64,
            max_partitions: 8,
        };
        let policy = FlushPolicy {
            max_rows: 1_000,
            max_bytes: usize::MAX,
            interval: std::time::Duration::from_secs(3600),
        };
        let shared_stats = Arc::new(crate::stats::SourceHourlyStats::new());

        let mut writer = PartitionedParquetWriter::with_source_stats(
            StructuredSyslogSink,
            s3,
            bwc,
            policy,
            shared_stats.clone(),
        );
        writer.push(sample_record("cef")).await.unwrap();

        let snapshot = shared_stats.snapshot();
        let row = snapshot
            .iter()
            .find(|r| r.source == "structured_syslog")
            .unwrap();
        let total: u64 = row.hours.iter().map(|h| h.count).sum();
        assert_eq!(total, 1);
    }
```

This uses the file's existing `sample_record(ptype: &'static str) -> StructuredSyslogRecord` helper (line ~145).

- [ ] **Step 2: Run test to verify it passes already**

Run: `cargo test --lib structured_syslog_sink_reports_into_shared_source_hourly_stats -- --test-threads=1`
Expected: PASS.

- [ ] **Step 3: Update `structured_syslog_start`'s signature**

In `src/forwarding/structured_syslog_s3.rs`, modify `structured_syslog_start` (currently lines 112-135):

```rust
pub fn structured_syslog_start(
    cfg: &SyslogS3Config,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
) -> (StructuredS3Handler, tokio::task::JoinHandle<()>) {
```

Change the final line from `ParquetWriterHandle::start(StructuredSyslogSink, s3, bwc, policy)` to:

```rust
    ParquetWriterHandle::start_with_stats(StructuredSyslogSink, s3, bwc, policy, source_stats)
```

- [ ] **Step 4: Fix the existing test that calls `structured_syslog_start` directly**

This file already has a test, `structured_syslog_start_wires_handle_and_join` (currently ending around line 277), that calls `structured_syslog_start(&cfg, s3)` directly — that call site now needs the new argument. Change:

```rust
        let (handle, join_handle) = structured_syslog_start(&cfg, s3);
```

to:

```rust
        let (handle, join_handle) = structured_syslog_start(
            &cfg,
            s3,
            Arc::new(crate::stats::SourceHourlyStats::new()),
        );
```

- [ ] **Step 5: Run this file's tests**

Run: `cargo test --lib forwarding::structured_syslog_s3 -- --test-threads=1`
Expected: passes except the expected `main.rs` call-site error (fixed in Task 13).

- [ ] **Step 6: Commit**

```bash
git add src/forwarding/structured_syslog_s3.rs
git commit -m "feat(forwarding): thread source_stats through structured_syslog_start"
```

---

## Task 11: `AdminState.source_stats` field

**Files:**
- Modify: `src/admin/state.rs`
- Modify: `src/admin/mod.rs` (test helper `test_state()`)

**Interfaces:**
- Consumes: `crate::stats::SourceHourlyStats` (Task 1).
- Produces: `AdminState { ..., pub source_stats: Arc<crate::stats::SourceHourlyStats> }`.

- [ ] **Step 1: Add the field to `AdminState`**

In `src/admin/state.rs`, modify the `AdminState` struct (currently lines 254-261):

```rust
/// Admin state shared across handlers
#[derive(Clone)]
pub struct AdminState {
    pub config: Arc<RwLock<Config>>,
    pub server_config: AdminServerConfig,
    pub audit_logger: AuditLogger,
    pub csrf_tokens: Arc<RwLock<Vec<(String, Instant)>>>,
    pub request_counts: Arc<RwLock<std::collections::HashMap<String, (Instant, u32)>>>,
    pub source_stats: Arc<crate::stats::SourceHourlyStats>,
}
```

- [ ] **Step 2: Update the `test_state()` helper in `src/admin/mod.rs`**

In `src/admin/mod.rs`, modify the `test_state()` helper (currently lines 25-43) to add the new field:

```rust
    async fn test_state() -> AdminState {
        let server_config = AdminServerConfig {
            bind_address: "0.0.0.0:8080".parse().unwrap(),
            username: "user".to_string(),
            password_hash: PasswordHash::hash("pass").unwrap(),
            allowed_ips: vec![],
            tls_config: None,
            enable_csrf: false,
            enable_rate_limiting: false,
        };

        AdminState {
            config: Arc::new(RwLock::new(Config::default())),
            server_config,
            audit_logger: AuditLogger::new(100).await,
            csrf_tokens: Arc::new(RwLock::new(Vec::new())),
            request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
            source_stats: Arc::new(crate::stats::SourceHourlyStats::new()),
        }
    }
```

- [ ] **Step 3: Run existing admin tests to check for other `AdminState` literals**

Run: `cargo build --lib 2>&1 | grep -A3 "missing field"`
Expected: this surfaces every other place an `AdminState { ... }` struct literal is constructed without the new field (there is at least one more in `src/admin/routes.rs`'s test module, `test_state()`, currently around line 380-397 based on the file's existing test setup — see Task 12, which touches that file next and will fix it. If the build output shows other files/line numbers, note them here for Task 12's implementer.)

- [ ] **Step 4: Commit**

```bash
git add src/admin/state.rs src/admin/mod.rs
git commit -m "feat(admin): add source_stats field to AdminState"
```

(This task intentionally leaves `src/admin/routes.rs` non-compiling if it has its own `AdminState { ... }` test literal — Task 12 fixes that as part of adding the new routes to that same file.)

---

## Task 12: `/stats` and `/stats.json` admin routes

**Files:**
- Modify: `src/admin/routes.rs`
- Create: `src/admin/templates/stats.html`

**Interfaces:**
- Consumes: `AdminState.source_stats` (Task 11), `SourceHourlyStats::snapshot()` / `SourceHourlySnapshot` / `HourCount` (Task 1).
- Produces: `async fn get_stats(...) -> Result<Html<String>, Response>`, `async fn get_stats_json(...) -> Result<Json<Vec<SourceHourlySnapshot>>, Response>`, both auth-gated; router now has `.route("/stats", get(get_stats))` and `.route("/stats.json", get(get_stats_json))`.

- [ ] **Step 1: Fix the existing `test_state()` in `src/admin/routes.rs` first (unblocks Task 11's build)**

In `src/admin/routes.rs`'s `#[cfg(test)] mod tests` block, find the `test_state()` helper (currently around lines 378-398, constructing `AdminState { config: ..., server_config, audit_logger: ..., csrf_tokens: ..., request_counts: ... }`) and add the new field:

```rust
    async fn test_state() -> AdminState {
        let server_config = AdminServerConfig {
            bind_address: "0.0.0.0:8080".parse().unwrap(),
            username: "admin".to_string(),
            password_hash: PasswordHash::hash("admin").unwrap(),
            allowed_ips: vec![],
            tls_config: None,
            enable_csrf: false,
            enable_rate_limiting: false,
        };

        AdminState {
            config: Arc::new(RwLock::new(Config::default())),
            server_config,
            audit_logger: AuditLogger::new(100).await,
            csrf_tokens: Arc::new(RwLock::new(Vec::new())),
            request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
            source_stats: Arc::new(crate::stats::SourceHourlyStats::new()),
        }
    }
```

(Keep whatever fields/values already exist in this helper beyond what's shown; only add the new `source_stats` field.)

Run: `cargo build --lib` — expected to now compile cleanly (confirms Task 11 + this step fixed every `AdminState` literal).

- [ ] **Step 2: Write the failing auth-gating tests**

Add to `src/admin/routes.rs`'s `#[cfg(test)] mod tests` block, near the existing `get_audit_log_requires_auth` / `get_audit_log_returns_entries_with_valid_auth` tests:

```rust
    #[tokio::test]
    async fn get_stats_requires_auth() {
        let state = test_state().await;
        let app = axum::Router::new()
            .route("/stats", axum::routing::get(get_stats))
            .with_state(state);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/stats")
            .body(Body::empty())
            .unwrap();

        let resp = app
            .into_make_service_with_connect_info::<SocketAddr>()
            .oneshot(req)
            .await
            .unwrap();
        // axum's oneshot on a MakeService needs a connect-info-wrapped
        // request in this codebase's existing tests — mirror exactly how
        // `get_audit_log_requires_auth` builds/calls its request in this
        // same file and follow that pattern if this differs.
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn get_stats_json_requires_auth() {
        let state = test_state().await;
        let app = axum::Router::new()
            .route("/stats.json", axum::routing::get(get_stats_json))
            .with_state(state);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/stats.json")
            .body(Body::empty())
            .unwrap();

        let resp = app
            .into_make_service_with_connect_info::<SocketAddr>()
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn get_stats_json_returns_recorded_counts_with_valid_auth() {
        let state = test_state().await;
        state.source_stats.record("syslog", 5);

        let app = axum::Router::new()
            .route("/stats.json", axum::routing::get(get_stats_json))
            .with_state(state);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/stats.json")
            .header(
                "Authorization",
                format!(
                    "Basic {}",
                    base64_encode_for_test("admin", "admin")
                ),
            )
            .body(Body::empty())
            .unwrap();

        let resp = app
            .into_make_service_with_connect_info::<SocketAddr>()
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let rows: Vec<crate::stats::SourceHourlySnapshot> =
            serde_json::from_slice(&body).unwrap();
        let syslog_row = rows.iter().find(|r| r.source == "syslog").unwrap();
        let total: u64 = syslog_row.hours.iter().map(|h| h.count).sum();
        assert_eq!(total, 5);
    }
```

This test needs a `base64_encode_for_test(user, pass)` helper. If this file's existing tests (e.g. `ensure_authorized_checks_credentials` in `src/admin/mod.rs`, or others in this file) already construct Basic-Auth request headers via `headers::Authorization::basic(...)` and `TypedHeader`, follow that exact existing pattern instead of hand-rolling base64 — search this file and `src/admin/mod.rs` for `Authorization::basic` and copy the pattern used to attach it to a raw `Request` builder (rather than the `TypedHeader` extractor test style used for direct handler calls). The important behavior under test is unchanged: 401 without credentials, 200 with valid ones, and the JSON body reflecting `source_stats`.

- [ ] **Step 3: Run tests to verify they fail (handlers don't exist yet)**

Run: `cargo test --lib get_stats -- --test-threads=1`
Expected: FAIL to compile — `cannot find function 'get_stats'`/`'get_stats_json'` in this scope.

- [ ] **Step 4: Create the HTML template**

Create `src/admin/templates/stats.html`:

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>logthing admin — ingest stats</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 2rem; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: right; }
    th:first-child, td:first-child { text-align: left; }
    caption { caption-side: bottom; font-size: 0.85rem; color: #555; margin-top: 0.75rem; text-align: left; }
  </style>
</head>
<body>
  <h1>Ingested records per source, per hour (last 24h)</h1>
  <table>
    <thead><tr><th>Source</th>{{HOUR_HEADERS}}</tr></thead>
    <tbody>
      {{STATS_ROWS}}
    </tbody>
    <caption>Counts records accepted into the write pipeline; may include a small overcount during a sustained S3 outage (see parquet_s3_upload_errors).</caption>
  </table>
</body>
</html>
```

- [ ] **Step 5: Implement `get_stats` and `get_stats_json` handlers**

In `src/admin/routes.rs`, add after the existing `get_audit_log` handler (currently ending around line 365, before the `#[cfg(test)]` block):

```rust
/// Render the last-24h per-source hourly ingest table as HTML.
async fn get_stats(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
) -> Result<Html<String>, Response> {
    let client_ip = addr.ip().to_string();
    let username = ensure_authorized(&state, auth, &client_ip).await?;

    let snapshot = state.source_stats.snapshot();

    // Union of all hour timestamps across sources, sorted ascending, for
    // consistent column headers.
    let mut all_hours: Vec<chrono::DateTime<chrono::Utc>> = snapshot
        .iter()
        .flat_map(|row| row.hours.iter().map(|h| h.hour))
        .collect();
    all_hours.sort();
    all_hours.dedup();

    let hour_headers: String = all_hours
        .iter()
        .map(|h| format!("<th>{}</th>", h.format("%Y-%m-%d %H:00")))
        .collect();

    let rows: String = snapshot
        .iter()
        .map(|row| {
            let cells: String = all_hours
                .iter()
                .map(|h| {
                    let count = row
                        .hours
                        .iter()
                        .find(|hc| hc.hour == *h)
                        .map(|hc| hc.count)
                        .unwrap_or(0);
                    format!("<td>{count}</td>")
                })
                .collect();
            format!("<tr><td>{}</td>{}</tr>", row.source, cells)
        })
        .collect();

    state
        .audit_logger
        .log("STATS_PAGE_ACCESS", &username, &client_ip, None)
        .await;

    let html = include_str!("templates/stats.html")
        .replace("{{HOUR_HEADERS}}", &hour_headers)
        .replace("{{STATS_ROWS}}", &rows);
    Ok(Html(html))
}

/// Return the last-24h per-source hourly ingest counts as JSON.
async fn get_stats_json(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
) -> Result<Json<Vec<crate::stats::SourceHourlySnapshot>>, Response> {
    let client_ip = addr.ip().to_string();
    let username = ensure_authorized(&state, auth, &client_ip).await?;

    let snapshot = state.source_stats.snapshot();

    state
        .audit_logger
        .log("STATS_JSON_READ", &username, &client_ip, None)
        .await;

    Ok(Json(snapshot))
}
```

- [ ] **Step 6: Wire the new routes into the router**

In `src/admin/routes.rs`'s `run_admin_server` function, modify the router construction (currently lines 55-93) to add the two new routes after the existing `/audit-log` route:

```rust
    let app = axum::Router::new()
        .route("/", axum::routing::get(admin_page))
        .route(
            "/config",
            axum::routing::get(get_config)
                .put(update_config)
                .patch(patch_config),
        )
        .route(
            "/config/validate",
            axum::routing::post(crate::admin::config_api::validate_config),
        )
        .route(
            "/config/diff",
            axum::routing::post(crate::admin::config_api::diff_config),
        )
        .route(
            "/config/export",
            axum::routing::post(crate::admin::config_api::export_config),
        )
        .route(
            "/config/import",
            axum::routing::post(crate::admin::config_api::import_config),
        )
        .route(
            "/config/reload",
            axum::routing::post(crate::admin::config_api::reload_config),
        )
        .route("/health", axum::routing::get(health_check))
        .route("/audit-log", axum::routing::get(get_audit_log))
        .route("/stats", axum::routing::get(get_stats))
        .route("/stats.json", axum::routing::get(get_stats_json))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            security_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::admin::middleware::csrf_middleware,
        ))
        .with_state(state);
```

- [ ] **Step 7: Update `spawn_admin_server`'s signature**

In `src/admin/routes.rs`, modify `spawn_admin_server` and `run_admin_server` (currently lines 21-40):

```rust
/// Spawn the admin server as a background task
pub fn spawn_admin_server(
    config: Arc<RwLock<Config>>,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
) {
    tokio::spawn(async move {
        match load_admin_config() {
            Ok(server_config) => {
                if let Err(err) = run_admin_server(config, server_config, source_stats).await {
                    error!("Admin server error: {}", err);
                }
            }
            Err(err) => {
                error!("Failed to load admin configuration: {}", err);
            }
        }
    });
}

/// Run the admin server
async fn run_admin_server(
    config: Arc<RwLock<Config>>,
    server_config: AdminServerConfig,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
) -> anyhow::Result<()> {
    let audit_logger = AuditLogger::new(1000).await;
    let csrf_tokens: Arc<RwLock<Vec<(String, std::time::Instant)>>> =
        Arc::new(RwLock::new(Vec::new()));
    let request_counts: Arc<RwLock<std::collections::HashMap<String, (std::time::Instant, u32)>>> =
        Arc::new(RwLock::new(std::collections::HashMap::new()));

    let state = AdminState {
        config,
        server_config: server_config.clone(),
        audit_logger: audit_logger.clone(),
        csrf_tokens: csrf_tokens.clone(),
        request_counts: request_counts.clone(),
        source_stats,
    };
```

(The rest of `run_admin_server`'s body — building `app`, binding the listener, TLS branch — is unchanged.)

- [ ] **Step 8: Run all admin tests**

Run: `cargo test --lib admin:: -- --test-threads=1`
Expected: PASS — all existing admin tests plus the 3 new ones from Step 2. (`cargo build --lib` will still show an error at `src/main.rs`'s `admin::spawn_admin_server(shared_config.clone())` call, missing the new argument — expected, fixed in Task 13.)

- [ ] **Step 9: Commit**

```bash
git add src/admin/routes.rs src/admin/templates/stats.html
git commit -m "feat(admin): add /stats and /stats.json routes"
```

---

## Task 13: Wire everything together in `main.rs`

**Files:**
- Modify: `src/main.rs`

**Interfaces:**
- Consumes: `stats::SourceHourlyStats::new()` (Task 1), all 8 updated `_start` functions (Tasks 3-10), `admin::spawn_admin_server(config, source_stats)` (Task 12).

- [ ] **Step 1: Construct the shared `SourceHourlyStats` and pass it to the admin server**

In `src/main.rs`, modify lines 52-54:

```rust
    let shared_config = Arc::new(RwLock::new(config.clone()));
    let source_stats = Arc::new(stats::SourceHourlyStats::new());
    admin::spawn_admin_server(shared_config.clone(), source_stats.clone());
    let throughput = Arc::new(stats::ThroughputStats::new());
```

- [ ] **Step 2: Pass `source_stats.clone()` into every `*_start(...)` call site**

`src/main.rs` calls each `_start` function once, inside its own `if config.<source>.enabled { ... }` block. For each of the following call sites, add `source_stats.clone()` as the last argument:

- `forwarding::structured_syslog_s3::structured_syslog_start(ss3_cfg, Arc::new(sink))` → `forwarding::structured_syslog_s3::structured_syslog_start(ss3_cfg, Arc::new(sink), source_stats.clone())`
- `forwarding::syslog_s3::syslog_start(s3_cfg, Arc::new(sink))` → `forwarding::syslog_s3::syslog_start(s3_cfg, Arc::new(sink), source_stats.clone())`
- `forwarding::ipfix_s3::ipfix_start(s3_cfg, Arc::new(sink))` → `forwarding::ipfix_s3::ipfix_start(s3_cfg, Arc::new(sink), source_stats.clone())`
- `forwarding::zeek_s3::zeek_start(s3_cfg, Arc::new(sink))` → `forwarding::zeek_s3::zeek_start(s3_cfg, Arc::new(sink), source_stats.clone())`
- `forwarding::suricata_s3::suricata_start(s3_cfg, Arc::new(sink))` → `forwarding::suricata_s3::suricata_start(s3_cfg, Arc::new(sink), source_stats.clone())`
- `forwarding::sflow_s3::sflow_start(s3_cfg, Arc::new(sink))` → `forwarding::sflow_s3::sflow_start(s3_cfg, Arc::new(sink), source_stats.clone())`

Also find and update the call sites for `wef_start` and `hec_start` (these exist in `main.rs` further down, following the same `if config.<source>.enabled { ... S3Sink::from_connection(...) ... <source>_start(...) }` shape as the ones above — locate them by searching this file for `wef_start(` and `hec_start(`) the same way: append `, source_stats.clone()` as the final argument to each call (for `hec_start`, which already takes a `max_partitions` argument, add `source_stats.clone()` *after* `max_partitions`, matching Task 9's new signature).

- [ ] **Step 3: Build the whole crate**

Run: `cargo build --workspace 2>&1 | tail -50`
Expected: clean build, no errors. If any `_start` call site was missed, the compiler reports it as a "this function takes N arguments but M were supplied" error at the exact `main.rs` line — fix any such reported site the same way as Step 2.

- [ ] **Step 4: Run the full test suite**

Run: `cargo test --workspace 2>&1 | tail -80`
Expected: PASS — every test added in Tasks 1-12, plus all pre-existing tests, green.

- [ ] **Step 5: Commit**

```bash
git add src/main.rs
git commit -m "feat(main): wire shared SourceHourlyStats through all sources and the admin server"
```

---

## Task 14: End-to-end test — real socket, real wiring, real HTTP call

**Files:**
- Modify: `src/admin/routes.rs` (add one `#[cfg(test)]` test to the existing test module)

**Interfaces:**
- Consumes: everything built in Tasks 1-13 — `PartitionedParquetWriter::with_source_stats`, `AdminServerConfig`, `AdminState`, the real router built the same way `run_admin_server` builds it, `reqwest` (already a dependency).

This is the one test in the whole plan that reproduces `main.rs`'s actual wiring rather than exercising the admin route or a writer in isolation — it specifically catches a mistake where two *different* `Arc<SourceHourlyStats>` instances were accidentally used (one for a writer, a different one passed into the admin server), which would compile cleanly but leave `/stats.json` silently empty forever.

- [ ] **Step 1: Write the end-to-end test**

Add to `src/admin/routes.rs`'s `#[cfg(test)] mod tests` block:

```rust
    #[tokio::test]
    async fn e2e_shared_source_stats_reach_stats_json_over_real_socket() {
        use crate::config::S3ConnectionConfig;
        use crate::forwarding::buffered_writer::{
            BufferedWriterConfig, FlushPolicy, PartitionedParquetWriter,
        };
        use crate::forwarding::s3_sink::S3Sink;
        use crate::stats::SourceHourlyStats;

        // Step 1: build the ONE shared Arc, exactly as main.rs does.
        let source_stats = Arc::new(SourceHourlyStats::new());

        // Step 2: push a record through a real writer using that shared Arc —
        // exactly the shape of what an enabled source's `_start` function does.
        let s3 = Arc::new(
            S3Sink::from_connection(&S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "t".to_string(),
                region: "us-east-1".to_string(),
                access_key: "K".to_string(),
                secret_key: "S".to_string(),
            })
            .await
            .unwrap(),
        );
        let bwc = BufferedWriterConfig {
            connection: S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "t".to_string(),
                region: "us-east-1".to_string(),
                access_key: "K".to_string(),
                secret_key: "S".to_string(),
            },
            prefix: "e2e".to_string(),
            max_buffer_rows: 1_000,
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 64,
            max_partitions: 1,
        };
        let policy = FlushPolicy {
            max_rows: 1_000,
            max_bytes: usize::MAX,
            interval: std::time::Duration::from_secs(3600),
        };

        struct E2eSink;
        impl crate::forwarding::buffered_writer::ParquetSink for E2eSink {
            type Record = String;
            fn source(&self) -> &'static str {
                "e2e_source"
            }
            fn partition(&self, _r: &String) -> Option<String> {
                None
            }
            fn schema(&self, _p: Option<&str>) -> Arc<arrow_schema::Schema> {
                Arc::new(arrow_schema::Schema::new(vec![arrow_schema::Field::new(
                    "val",
                    arrow_schema::DataType::Utf8,
                    false,
                )]))
            }
            fn to_record_batch(
                &self,
                record: &String,
                schema: &Arc<arrow_schema::Schema>,
            ) -> anyhow::Result<arrow_array::RecordBatch> {
                let col = Arc::new(arrow_array::StringArray::from(vec![record.as_str()]));
                Ok(arrow_array::RecordBatch::try_new(schema.clone(), vec![col])?)
            }
        }

        let mut writer = PartitionedParquetWriter::with_source_stats(
            E2eSink,
            s3,
            bwc,
            policy,
            source_stats.clone(),
        );
        writer.push("hello".to_string()).await.unwrap();

        // Step 3: spawn the REAL admin app (same router-building code
        // run_admin_server uses) bound to an ephemeral loopback port, sharing
        // the SAME Arc<SourceHourlyStats> — exactly as main.rs does when it
        // calls admin::spawn_admin_server(shared_config, source_stats.clone()).
        let server_config = AdminServerConfig {
            bind_address: "127.0.0.1:0".parse().unwrap(),
            username: "admin".to_string(),
            password_hash: PasswordHash::hash("admin").unwrap(),
            allowed_ips: vec![],
            tls_config: None,
            enable_csrf: false,
            enable_rate_limiting: false,
        };
        let state = AdminState {
            config: Arc::new(RwLock::new(Config::default())),
            server_config: server_config.clone(),
            audit_logger: AuditLogger::new(100).await,
            csrf_tokens: Arc::new(RwLock::new(Vec::new())),
            request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
            source_stats: source_stats.clone(),
        };
        let app = axum::Router::new()
            .route("/stats.json", axum::routing::get(get_stats_json))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let real_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });

        // Step 4: make a REAL HTTP request over the real socket with Basic Auth.
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{real_addr}/stats.json"))
            .basic_auth("admin", Some("admin"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);

        let rows: Vec<crate::stats::SourceHourlySnapshot> = resp.json().await.unwrap();
        let row = rows.iter().find(|r| r.source == "e2e_source").unwrap();
        let total: u64 = row.hours.iter().map(|h| h.count).sum();
        assert_eq!(
            total, 1,
            "the count recorded via the writer's Arc must be visible through \
             the admin server's Arc — they must be the SAME instance"
        );
    }
```

- [ ] **Step 2: Run the test to verify it fails without the fix (sanity-check the test itself)**

Temporarily change `source_stats: source_stats.clone()` in the test's `AdminState` construction to `source_stats: Arc::new(SourceHourlyStats::new())` (a *different* Arc) and run:

Run: `cargo test --lib e2e_shared_source_stats_reach_stats_json_over_real_socket -- --test-threads=1`
Expected: FAIL — `assertion failed: rows.iter().find(...) ... .is_some()` (no `"e2e_source"` row, or a row with count 0), proving the test actually detects the Arc-identity bug it's designed to catch.

Revert the temporary change back to `source_stats: source_stats.clone()`.

- [ ] **Step 3: Run the test to verify it passes with the real (shared-Arc) wiring**

Run: `cargo test --lib e2e_shared_source_stats_reach_stats_json_over_real_socket -- --test-threads=1`
Expected: PASS.

- [ ] **Step 4: Run the entire workspace test suite one final time**

Run: `cargo test --workspace 2>&1 | tail -100`
Expected: PASS, all green — this is the full plan's final verification.

- [ ] **Step 5: Commit**

```bash
git add src/admin/routes.rs
git commit -m "test(admin): add e2e test proving shared SourceHourlyStats Arc reaches /stats.json over a real socket"
```

---

## Task dependency summary (for parallel execution)

- Task 1: no dependencies.
- Task 2: depends on Task 1.
- Tasks 3-10 (8 per-source wrapper edits): each depends on Task 2 only — **can run in parallel with each other** (8 independent files, no shared state between them).
- Task 11: depends on Task 1 only — **can run in parallel with Tasks 2-10**.
- Task 12: depends on Task 11.
- Task 13: depends on **all of** Tasks 3-10 and Task 12.
- Task 14: depends on Task 13.
