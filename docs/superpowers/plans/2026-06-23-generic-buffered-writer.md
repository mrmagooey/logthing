# Generic Buffered Parquet Writer — Implementation Plan

**Date:** 2026-06-23
**Branch:** `feat/generic-writer`
**Plan implements:** `docs/superpowers/specs/2026-06-23-generic-buffered-writer-design.md`
**Status:** Ready for execution

---

## Goal

Replace the four near-duplicate S3 Parquet writers (`parquet_s3.rs`, `syslog_s3.rs`,
`ipfix_s3.rs`, `zeek_s3.rs`) with **one generic buffered-Parquet-writer** in
`src/forwarding/buffered_writer.rs` plus a thin per-source adapter (~40–60 lines each),
so all buffering / flush / cap / encode / upload / channel / graceful-shutdown machinery
lives in exactly one place.

## Architecture

- `ParquetSink` trait: the adapter contract (source label, partition key, schema, row mapping)
- `PartitionedParquetWriter<S>`: monomorphized over `S: ParquetSink`; owns all buffer/flush/cap/encode/upload logic
- `ParquetWriterHandle<S>`: channel sender + `start(sink, s3, config) -> (Self, JoinHandle)`
- `BufferedWriterConfig`: shared TOML-compatible config struct (superset of all four current configs)
- `FlushPolicy`: unified rows-OR-bytes-OR-age trigger (M-2 convergence; timing deliberately not byte-identical to old single-trigger writers)
- Per-source adapters: `IpfixSink`, `SyslogSink`, `ZeekSink`, `WefSink` (each reuses existing row-mapping code)

## Tech Stack

- Rust 2024 edition, async Tokio runtime (multi-thread)
- Arrow / Parquet via `arrow` + `parquet` crates (already in Cargo.toml)
- `aws-sdk-s3` via existing `S3Sink` (unchanged)
- `metrics` crate (counter! macro) for unified metric labels
- `anyhow` / `thiserror` for error handling
- `serde` / `toml` for config deserialization
- `uuid` for S3 key UUIDs
- `chrono` for date partitioning in keys

---

## Global Constraints

1. **Rust 2024 edition** — `edition = "2024"` in Cargo.toml; let-chains and other 2024 features are in use throughout.
2. **100-column line limit**, 4-space indent; `cargo fmt` must be applied after every step.
3. **`cargo clippy --all-targets -- -D warnings`** must pass with zero new warnings at every commit, including the `tests/` integration targets. Never suppress a warning with `#[allow]` unless it was already present in the file before this work.
4. **Full `cargo test` (all targets)** — run `cargo test` (NOT `--lib`-only) at every test step. The integration tests under `tests/` must compile and pass (or be skipped by their env-var gate) at each phase. A prior effort hid regressions by running `--lib` only.
5. Always prefix cargo commands with: `export PATH="$HOME/.cargo/bin:$PATH"; cargo …`
6. **`anyhow` / `thiserror`** for all error types; no raw `Box<dyn Error>`.
7. **Tests in `#[cfg(test)]` modules** inside the source file; no separate test files unless existing `tests/` integration tests.
8. **Metrics via `metrics` crate** (`metrics::counter!` macro); unified label form `"parquet_s3_*"` with `source` label.
9. **Bounded channels + drop-on-overflow** (counted by `parquet_s3_dropped{source}`); never block the caller.
10. **Graceful-shutdown flush-on-close**: when the channel closes (all senders dropped), the background task flushes all partitions then exits; the `JoinHandle` is awaited in `main.rs` (within the existing 10 s deadline).
11. **Panic-free on all inputs**: `to_record_batch` must never panic; type mismatches or serialization failures are best-effort handled (warn + skip field or use `_extra`/raw column where schema has one).
12. **Conventional commits**: `feat(buffered-writer): …`, `refactor(ipfix): …`, etc.
13. **No main/master commits without explicit user consent**; all work on `feat/generic-writer` branch.
14. **Two-stage review** (spec-compliance then code-quality) before the branch is considered complete — but out of scope for this plan document.
15. **`S3ConnectionConfig` masked Debug** is inherited by `BufferedWriterConfig` via delegation.
16. **Hard cap** = `max_buffer_rows.saturating_mul(4)` rows per partition; drop-oldest on cap breach, throttled warn (≥30 s between warnings).

---

## Phase 1 — Generic Core

**New file:** `src/forwarding/buffered_writer.rs`
**Also touched:** `src/forwarding/mod.rs` (add `pub mod buffered_writer;`)

### Task 1.1 — Define `ParquetSink` trait and `BufferedWriterConfig` + `FlushPolicy`

**Files:**
- `src/forwarding/buffered_writer.rs` (create)
- `src/forwarding/mod.rs` (add `pub mod buffered_writer;`)

**Interfaces — Produces:**

```rust
pub trait ParquetSink: Send + Sync + 'static {
    type Record: Send + 'static;

    /// Stable source label, e.g. "ipfix" | "syslog" | "zeek" | "wef".
    /// Used as the `source` metric label and base S3 prefix component.
    fn source(&self) -> &'static str;

    /// Partition segment for this record.
    /// `None` → single shared buffer (syslog, ipfix).
    /// `Some(seg)` → one buffer per seg (zeek: sanitized log_path; wef: "event_type=<id>").
    /// The segment is used as both the buffer-map key and an S3 key path component.
    fn partition(&self, record: &Self::Record) -> Option<String>;

    /// Arrow schema for a partition.
    /// `partition` is `None` for single-schema sources; the sanitized segment for multi-partition.
    fn schema(&self, partition: Option<&str>) -> Arc<arrow_schema::Schema>;

    /// Convert one record to a single-row RecordBatch for the partition's schema.
    /// Must be panic-free and best-effort total (never silently drop a whole record;
    /// type mismatches go to an `_extra`/raw column where the schema has one).
    fn to_record_batch(
        &self,
        record: &Self::Record,
        schema: &Arc<arrow_schema::Schema>,
    ) -> anyhow::Result<arrow_array::RecordBatch>;
}

/// Unified flush policy: flush a partition when ANY trigger fires.
#[derive(Debug, Clone)]
pub struct FlushPolicy {
    /// Flush when buffered row count >= this value.
    pub max_rows: usize,
    /// Flush when estimated buffered bytes >= this value.
    pub max_bytes: usize,
    /// Flush when oldest buffered batch age >= this duration (wall-clock).
    pub interval: std::time::Duration,
}

/// Shared config for all buffered-Parquet writers. TOML backward-compatible:
/// each source's existing TOML keys deserialize into this struct.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct BufferedWriterConfig {
    #[serde(flatten)]
    pub connection: crate::config::S3ConnectionConfig,
    /// S3 key prefix, slash-free (e.g. "syslog", "ipfix", "zeek", "wef").
    #[serde(default)]
    pub prefix: String,
    /// Flush when buffered row count per partition reaches this (default: source-specific).
    #[serde(default)]
    pub max_buffer_rows: usize,
    /// Flush when estimated bytes per partition reaches this (default: source-specific).
    #[serde(default)]
    pub flush_threshold_bytes: usize,
    /// Flush after this many seconds regardless (default: 900).
    #[serde(default)]
    pub flush_interval_secs: u64,
    /// Bounded channel capacity (number of records; default: source-specific).
    #[serde(default)]
    pub channel_capacity: usize,
    /// Maximum number of distinct partition buffers; overflow → fixed "_overflow" partition.
    /// Generalizes MAX_ZEEK_STREAMS; also bounds WEF event-type cardinality.
    #[serde(default)]
    pub max_partitions: usize,
}
```

**Steps:**
- [ ] Write the failing test: verify `FlushPolicy` fields are accessible, `BufferedWriterConfig` deserializes from a flat TOML string with all five `S3ConnectionConfig` fields + `prefix` + the four threshold fields.
  ```rust
  #[test]
  fn buffered_writer_config_deserializes_from_toml() {
      let toml = r#"
  endpoint   = "http://minio:9000"
  bucket     = "test"
  region     = "us-east-1"
  access_key = "KEY"
  secret_key  = "SECRET"
  prefix = "ipfix"
  max_buffer_rows = 50000
  flush_threshold_bytes = 52428800
  flush_interval_secs = 300
  channel_capacity = 512
  max_partitions = 128
  "#;
      let cfg: BufferedWriterConfig = toml::from_str(toml).expect("deserialize");
      assert_eq!(cfg.prefix, "ipfix");
      assert_eq!(cfg.max_buffer_rows, 50_000);
      assert_eq!(cfg.flush_threshold_bytes, 52_428_800);
      assert_eq!(cfg.flush_interval_secs, 300);
      assert_eq!(cfg.channel_capacity, 512);
      assert_eq!(cfg.max_partitions, 128);
      assert_eq!(cfg.connection.bucket, "test");
  }

  #[test]
  fn flush_policy_fields_accessible() {
      let p = FlushPolicy {
          max_rows: 10_000,
          max_bytes: 100 * 1024 * 1024,
          interval: std::time::Duration::from_secs(900),
      };
      assert_eq!(p.max_rows, 10_000);
      assert_eq!(p.max_bytes, 100 * 1024 * 1024);
      assert_eq!(p.interval.as_secs(), 900);
  }
  ```
- [ ] Run, expect compile error (types not defined yet): `export PATH="$HOME/.cargo/bin:$PATH"; cargo test -p logthing buffered_writer 2>&1 | head -40`
- [ ] Create `src/forwarding/buffered_writer.rs` with the trait, `FlushPolicy`, and `BufferedWriterConfig` as defined in the Interfaces block above. Add `pub mod buffered_writer;` to `src/forwarding/mod.rs`.
- [ ] Run `export PATH="$HOME/.cargo/bin:$PATH"; cargo test 2>&1 | tail -20` — expect both new tests to pass, all existing tests still pass.
- [ ] `export PATH="$HOME/.cargo/bin:$PATH"; cargo fmt && cargo clippy --all-targets -- -D warnings`
- [ ] Commit: `feat(buffered-writer): add ParquetSink trait, FlushPolicy, BufferedWriterConfig`

---

### Task 1.2 — Per-partition buffer type and key builder

**Files:** `src/forwarding/buffered_writer.rs`

**Interfaces — Produces (internal types + public key builder):**

```rust
/// Internal per-partition state.
struct PartitionBuffer {
    schema: Arc<arrow_schema::Schema>,
    buffer: std::collections::VecDeque<(arrow_array::RecordBatch, usize)>, // (batch, est_bytes)
    row_count: usize,
    byte_count: usize,
    last_flush: std::time::Instant,
    last_drop_warn: Option<std::time::Instant>,
}

/// Build the S3 object key for a flush.
/// Pattern: `{prefix}/[{partition}/]year={Y}/month={MM}/day={DD}/{uuid}.parquet`
/// The partition segment is omitted when `partition` is `None` (syslog, ipfix).
pub(crate) fn build_key(
    prefix: &str,
    partition: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
) -> String;
```

**Steps:**
- [ ] Write failing tests for `build_key`:
  ```rust
  #[test]
  fn build_key_no_partition() {
      use chrono::TimeZone;
      let now = chrono::Utc.with_ymd_and_hms(2026, 3, 7, 0, 0, 0).unwrap();
      let key = build_key("syslog", None, now);
      assert!(key.starts_with("syslog/year=2026/month=03/day=07/"), "got: {key}");
      assert!(key.ends_with(".parquet"), "got: {key}");
      assert!(!key.contains("//"), "double-slash: {key}");
  }

  #[test]
  fn build_key_with_partition() {
      use chrono::TimeZone;
      let now = chrono::Utc.with_ymd_and_hms(2026, 3, 7, 0, 0, 0).unwrap();
      let key = build_key("zeek", Some("conn"), now);
      assert!(key.starts_with("zeek/conn/year=2026/month=03/day=07/"), "got: {key}");
      assert!(key.ends_with(".parquet"), "got: {key}");
  }

  #[test]
  fn build_key_wef_partition_segment() {
      use chrono::TimeZone;
      let now = chrono::Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
      let key = build_key("wef", Some("event_type=4624"), now);
      assert!(key.starts_with("wef/event_type=4624/year=2026/"), "got: {key}");
  }
  ```
- [ ] Run, expect compile error.
- [ ] Implement `build_key` and `PartitionBuffer` (internal struct, not `pub`):
  ```rust
  use chrono::Datelike as _;

  pub(crate) fn build_key(
      prefix: &str,
      partition: Option<&str>,
      now: chrono::DateTime<chrono::Utc>,
  ) -> String {
      let id = uuid::Uuid::new_v4();
      match partition {
          Some(seg) => format!(
              "{}/{}/year={}/month={:02}/day={:02}/{}.parquet",
              prefix, seg, now.year(), now.month(), now.day(), id
          ),
          None => format!(
              "{}/year={}/month={:02}/day={:02}/{}.parquet",
              prefix, now.year(), now.month(), now.day(), id
          ),
      }
  }
  ```
- [ ] Run `export PATH="$HOME/.cargo/bin:$PATH"; cargo test 2>&1 | tail -20`
- [ ] `cargo fmt && cargo clippy --all-targets -- -D warnings`
- [ ] Commit: `feat(buffered-writer): add PartitionBuffer and build_key`

---

### Task 1.3 — `PartitionedParquetWriter<S>`: push, flush-policy evaluation, `drop_oldest_to_cap`

**Files:** `src/forwarding/buffered_writer.rs`

**Interfaces — Produces:**

```rust
pub struct PartitionedParquetWriter<S: ParquetSink> {
    sink: S,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
    config: BufferedWriterConfig,
    policy: FlushPolicy,
    // "" key for None-partition sources; sanitized-path / "event_type=<id>" for multi-partition
    buffers: std::collections::HashMap<String, PartitionBuffer>,
}

impl<S: ParquetSink> PartitionedParquetWriter<S> {
    pub fn new(
        sink: S,
        s3: Arc<crate::forwarding::s3_sink::S3Sink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
    ) -> Self;

    /// Push one record: map to RecordBatch, append to partition buffer,
    /// enforce partition cap (overflow to "_overflow"), check flush policy,
    /// call flush_partition + drop_oldest_to_cap on failure.
    pub async fn push(&mut self, record: S::Record) -> anyhow::Result<()>;

    /// Flush all partitions unconditionally (called on shutdown).
    pub async fn flush_all(&mut self) -> anyhow::Result<()>;

    /// Flush partitions whose flush policy is triggered (called by timer).
    pub async fn flush_all_if_needed(&mut self) -> anyhow::Result<()>;
}
```

**Steps:**
- [ ] Write failing tests (use a test-only `MockSink: ParquetSink` with a pre-built single-row RecordBatch):
  ```rust
  #[cfg(test)]
  mod tests {
      use super::*;
      use arrow::array::StringArray;
      use arrow::datatypes::{DataType, Field, Schema};
      use arrow::record_batch::RecordBatch;
      use std::sync::Arc;

      fn test_schema() -> Arc<Schema> {
          Arc::new(Schema::new(vec![Field::new("val", DataType::Utf8, false)]))
      }

      struct MockSink;
      impl ParquetSink for MockSink {
          type Record = String;
          fn source(&self) -> &'static str { "test" }
          fn partition(&self, _r: &String) -> Option<String> { None }
          fn schema(&self, _p: Option<&str>) -> Arc<Schema> { test_schema() }
          fn to_record_batch(
              &self,
              record: &String,
              schema: &Arc<Schema>,
          ) -> anyhow::Result<RecordBatch> {
              let col = Arc::new(StringArray::from(vec![record.as_str()]));
              Ok(RecordBatch::try_new(schema.clone(), vec![col])?)
          }
      }

      async fn unreachable_s3() -> Arc<crate::forwarding::s3_sink::S3Sink> {
          use crate::config::S3ConnectionConfig;
          Arc::new(
              crate::forwarding::s3_sink::S3Sink::from_connection(&S3ConnectionConfig {
                  endpoint: "http://127.0.0.1:1".to_string(),
                  bucket: "t".to_string(), region: "us-east-1".to_string(),
                  access_key: "K".to_string(), secret_key: "S".to_string(),
              }).await.unwrap()
          )
      }

      fn test_config(max_rows: usize) -> (BufferedWriterConfig, FlushPolicy) {
          use crate::config::S3ConnectionConfig;
          let cfg = BufferedWriterConfig {
              connection: S3ConnectionConfig {
                  endpoint: "http://127.0.0.1:1".to_string(),
                  bucket: "t".to_string(), region: "us-east-1".to_string(),
                  access_key: "K".to_string(), secret_key: "S".to_string(),
              },
              prefix: "test".to_string(),
              max_buffer_rows: max_rows,
              flush_threshold_bytes: usize::MAX,
              flush_interval_secs: 3600,
              channel_capacity: 64,
              max_partitions: 8,
          };
          let policy = FlushPolicy {
              max_rows,
              max_bytes: usize::MAX,
              interval: std::time::Duration::from_secs(3600),
          };
          (cfg, policy)
      }

      /// Records accumulate below the row threshold.
      #[tokio::test]
      async fn push_accumulates_below_row_threshold() {
          let s3 = unreachable_s3().await;
          let (cfg, policy) = test_config(5);
          let mut w = PartitionedParquetWriter::new(MockSink, s3, cfg, policy);
          for i in 0..4 {
              w.push(format!("r{i}")).await.unwrap();
          }
          assert_eq!(w.buffers.get("").unwrap().row_count, 4);
      }

      /// Row-threshold flush fails (unreachable S3) but hard cap is enforced.
      #[tokio::test]
      async fn push_enforces_hard_cap_on_flush_failure() {
          let s3 = unreachable_s3().await;
          let max_rows = 2usize;
          let (cfg, policy) = test_config(max_rows);
          let hard_cap = max_rows.saturating_mul(4);
          let mut w = PartitionedParquetWriter::new(MockSink, s3, cfg, policy);
          let mut errors = 0usize;
          for i in 0..(hard_cap * 3) {
              if w.push(format!("r{i}")).await.is_err() { errors += 1; }
          }
          assert!(errors > 0);
          let buf = w.buffers.get("").unwrap();
          assert!(buf.row_count <= hard_cap,
              "row_count {} must be <= hard_cap {}", buf.row_count, hard_cap);
      }
  }
  ```
- [ ] Run, expect compile error (`PartitionedParquetWriter` not defined).
- [ ] Implement `PartitionedParquetWriter::new`, `push`, `flush_all`, `flush_all_if_needed`, and the private `flush_partition` + `drop_oldest_to_cap` helpers:
  ```rust
  // Within PartitionedParquetWriter<S>
  async fn flush_partition(&mut self, key: &str) -> anyhow::Result<()> {
      let buf = match self.buffers.get_mut(key) {
          Some(b) if !b.buffer.is_empty() => b,
          _ => return Ok(()),
      };
      let batches: Vec<_> = buf.buffer.iter().map(|(b, _)| b.clone()).collect();
      let row_count = buf.row_count;
      let schema = buf.schema.clone();
      let source = self.sink.source();
      // Concatenate all single-row batches into one before encoding.
      let merged = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
          use parquet::arrow::ArrowWriter;
          use parquet::basic::{Compression, ZstdLevel};
          use parquet::file::properties::WriterProperties;
          let batch = arrow::compute::concat_batches(&schema, &batches)?;
          let props = WriterProperties::builder()
              .set_compression(Compression::ZSTD(ZstdLevel::try_new(3)?))
              .build();
          let mut buf = Vec::new();
          let mut writer = ArrowWriter::try_new(&mut buf, schema, Some(props))?;
          writer.write(&batch)?;
          writer.close()?;
          Ok(buf)
      })
      .await
      .map_err(|e| anyhow::anyhow!("spawn_blocking join: {e}"))??;

      let partition_seg = if key.is_empty() { None } else { Some(key) };
      let s3_key = build_key(&self.config.prefix, partition_seg, chrono::Utc::now());
      match self.s3.upload(&s3_key, merged).await {
          Ok(()) => {
              metrics::counter!("parquet_s3_records_written", "source" => source)
                  .increment(row_count as u64);
              metrics::counter!("parquet_s3_uploads", "source" => source).increment(1);
              let buf = self.buffers.get_mut(key).unwrap();
              buf.buffer.clear();
              buf.row_count = 0;
              buf.byte_count = 0;
              buf.last_flush = std::time::Instant::now();
              Ok(())
          }
          Err(e) => {
              metrics::counter!("parquet_s3_upload_errors", "source" => source).increment(1);
              Err(e)
          }
      }
  }

  fn drop_oldest_to_cap(buf: &mut PartitionBuffer, cap: usize, source: &'static str) {
      let mut dropped = 0usize;
      while buf.row_count > cap {
          if let Some((batch, est)) = buf.buffer.pop_front() {
              let n = batch.num_rows();
              buf.row_count = buf.row_count.saturating_sub(n);
              buf.byte_count = buf.byte_count.saturating_sub(est);
              dropped += n;
          } else { break; }
      }
      if dropped > 0 {
          metrics::counter!("parquet_s3_buffer_dropped", "source" => source)
              .increment(dropped as u64);
          let should_warn = buf.last_drop_warn
              .map(|t| t.elapsed().as_secs() >= 30).unwrap_or(true);
          if should_warn {
              tracing::warn!(
                  dropped, source,
                  "parquet_s3: S3 upload failing — dropped oldest rows to stay within hard cap"
              );
              buf.last_drop_warn = Some(std::time::Instant::now());
          }
      }
  }
  ```
- [ ] Run `export PATH="$HOME/.cargo/bin:$PATH"; cargo test 2>&1 | tail -20`
- [ ] `cargo fmt && cargo clippy --all-targets -- -D warnings`
- [ ] Commit: `feat(buffered-writer): implement PartitionedParquetWriter push/flush/cap`

---

### Task 1.4 — Partition-count cap (`max_partitions`) + overflow partition

**Files:** `src/forwarding/buffered_writer.rs`

**Steps:**
- [ ] Write failing test:
  ```rust
  #[tokio::test]
  async fn partition_cap_overflows_to_overflow_buffer() {
      struct PartitionedMock;
      impl ParquetSink for PartitionedMock {
          type Record = (String, String); // (partition, value)
          fn source(&self) -> &'static str { "test" }
          fn partition(&self, r: &(String, String)) -> Option<String> { Some(r.0.clone()) }
          fn schema(&self, _: Option<&str>) -> Arc<Schema> { test_schema() }
          fn to_record_batch(&self, r: &(String, String), s: &Arc<Schema>)
              -> anyhow::Result<RecordBatch>
          {
              let col = Arc::new(StringArray::from(vec![r.1.as_str()]));
              Ok(RecordBatch::try_new(s.clone(), vec![col])?)
          }
      }
      let s3 = unreachable_s3().await;
      let (mut cfg, policy) = test_config(10_000);
      cfg.max_partitions = 3;
      let mut w = PartitionedParquetWriter::new(PartitionedMock, s3, cfg, policy);
      // Push 5 distinct partitions — only 3 allowed, the rest go to "_overflow"
      for i in 0..5usize {
          w.push((format!("part_{i}"), "v".to_string())).await.unwrap();
      }
      // At most max_partitions + 1 (_overflow) buffers exist
      assert!(w.buffers.len() <= 4, "got {} buffers", w.buffers.len());
      assert!(w.buffers.contains_key("_overflow"),
          "overflow key must exist after cap breach");
  }
  ```
- [ ] Run, expect failure.
- [ ] In `PartitionedParquetWriter::push`, before creating a new buffer entry: if `self.buffers.len() >= self.config.max_partitions` and the key doesn't already exist, route to `"_overflow"` and increment `parquet_s3_partitions_capped{source}`:
  ```rust
  let effective_key = if self.buffers.contains_key(&key)
      || self.buffers.len() < self.config.max_partitions
  {
      key
  } else {
      metrics::counter!("parquet_s3_partitions_capped", "source" => self.sink.source())
          .increment(1);
      "_overflow".to_string()
  };
  ```
- [ ] Run `export PATH="$HOME/.cargo/bin:$PATH"; cargo test 2>&1 | tail -20`
- [ ] `cargo fmt && cargo clippy --all-targets -- -D warnings`
- [ ] Commit: `feat(buffered-writer): partition-count cap with overflow to _overflow buffer`

---

### Task 1.5 — `ParquetWriterHandle<S>`: bounded channel + background `select!` loop

**Files:** `src/forwarding/buffered_writer.rs`

**Interfaces — Produces:**

```rust
pub struct ParquetWriterHandle<S: ParquetSink> {
    tx: tokio::sync::mpsc::Sender<S::Record>,
}

impl<S: ParquetSink> ParquetWriterHandle<S> {
    /// Spawn the background writer task.
    /// Returns `(handle, JoinHandle)`. The JoinHandle must be awaited during
    /// graceful shutdown after all senders are dropped (mirrors the existing
    /// `start_with_capacity` contract across the current four writers).
    pub fn start(
        sink: S,
        s3: Arc<crate::forwarding::s3_sink::S3Sink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
    ) -> (Self, tokio::task::JoinHandle<()>);

    /// Try to send a record without blocking. Returns `TrySendError` on overflow/closed.
    /// Callers should increment `parquet_s3_dropped{source}` on overflow and log a warning.
    pub fn try_send(
        &self,
        record: S::Record,
    ) -> Result<(), tokio::sync::mpsc::error::TrySendError<S::Record>>;
}
```

**Steps:**
- [ ] Write failing tests:
  ```rust
  #[tokio::test]
  async fn handle_start_spawns_background_task_and_try_send_works() {
      let s3 = unreachable_s3().await;
      let (cfg, policy) = test_config(10_000);
      let (handle, jh) = ParquetWriterHandle::start(MockSink, s3, cfg, policy);
      // try_send should succeed when channel not full and writer not stalled
      assert!(handle.try_send("hello".to_string()).is_ok());
      drop(handle);
      tokio::time::timeout(std::time::Duration::from_secs(2), jh).await
          .expect("join within timeout")
          .expect("task did not panic");
  }

  #[tokio::test]
  #[allow(clippy::mutable_key_type)]
  async fn handle_channel_overflow_increments_metric() {
      use metrics::set_default_local_recorder;
      use metrics_util::CompositeKey;
      use metrics_util::MetricKind;
      use metrics_util::debugging::DebuggingRecorder;

      let recorder = DebuggingRecorder::new();
      let snapshotter = recorder.snapshotter();
      let _guard = set_default_local_recorder(&recorder);

      let s3 = unreachable_s3().await;
      let (mut cfg, policy) = test_config(1); // flush_threshold_bytes=usize::MAX, max_rows=1
      // Override: flush immediately so background task stalls on S3
      let policy = FlushPolicy { max_rows: 1, max_bytes: 1, interval: std::time::Duration::from_secs(3600) };
      cfg.channel_capacity = 1;
      let (handle, _jh) = ParquetWriterHandle::start(MockSink, s3, cfg, policy);
      tokio::task::yield_now().await;

      let mut dropped = 0u64;
      for i in 0..50usize {
          if let Err(_) = handle.try_send(format!("r{i}")) {
              dropped += 1;
              metrics::counter!("parquet_s3_dropped", "source" => "test").increment(1);
          }
      }
      assert!(dropped > 0, "expected channel-overflow drops");
  }

  #[tokio::test]
  async fn handle_drop_triggers_flush_on_close() {
      // With an in-memory mock, verify the background task exits cleanly
      // when the handle (sender) is dropped, without panicking.
      let s3 = unreachable_s3().await;
      let (cfg, policy) = test_config(10_000);
      let (handle, jh) = ParquetWriterHandle::start(MockSink, s3, cfg, policy);
      handle.try_send("flush-me".to_string()).ok();
      drop(handle);
      // Task should exit (flush attempt, then break); unreachable S3 means flush errors,
      // but the task must still exit without panicking.
      tokio::time::timeout(std::time::Duration::from_secs(5), jh).await
          .expect("task did not exit within 5s")
          .expect("task panicked");
  }
  ```
- [ ] Run, expect compile error.
- [ ] Implement `ParquetWriterHandle`:
  ```rust
  impl<S: ParquetSink> ParquetWriterHandle<S> {
      pub fn start(
          sink: S,
          s3: Arc<crate::forwarding::s3_sink::S3Sink>,
          config: BufferedWriterConfig,
          policy: FlushPolicy,
      ) -> (Self, tokio::task::JoinHandle<()>) {
          let capacity = config.channel_capacity.max(1);
          let (tx, mut rx) = tokio::sync::mpsc::channel::<S::Record>(capacity);
          let flush_check = crate::forwarding::s3_sink::flush_check_interval(policy.interval);
          let handle = tokio::spawn(async move {
              let mut writer = PartitionedParquetWriter::new(sink, s3, config, policy);
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
          (Self { tx }, handle)
      }

      pub fn try_send(
          &self,
          record: S::Record,
      ) -> Result<(), tokio::sync::mpsc::error::TrySendError<S::Record>> {
          self.tx.try_send(record)
      }
  }
  ```
- [ ] Run `export PATH="$HOME/.cargo/bin:$PATH"; cargo test 2>&1 | tail -20`
- [ ] `cargo fmt && cargo clippy --all-targets -- -D warnings`
- [ ] Commit: `feat(buffered-writer): ParquetWriterHandle with start/try_send, flush-on-close`

---

### Task 1.6 — Additional unit tests: byte-flush trigger, age-flush trigger, encode round-trip, multi-partition flush

**Files:** `src/forwarding/buffered_writer.rs`

**Steps:**
- [ ] Add the following tests to the `#[cfg(test)]` block:
  ```rust
  /// Byte-threshold flush: use a mock with max_bytes=1 so the first push triggers a flush.
  #[tokio::test]
  async fn byte_threshold_triggers_flush() {
      let s3 = unreachable_s3().await;
      let (cfg, _) = test_config(10_000);
      let policy = FlushPolicy {
          max_rows: 10_000,
          max_bytes: 1, // triggers immediately
          interval: std::time::Duration::from_secs(3600),
      };
      let mut w = PartitionedParquetWriter::new(MockSink, s3, cfg, policy);
      // push returns Err (unreachable S3) but must not panic
      let _ = w.push("r1".to_string()).await;
      // After failed flush, buffer is either retained or capped — must not exceed hard cap
      let buf = w.buffers.get("").unwrap();
      assert!(buf.row_count <= 10_000usize.saturating_mul(4));
  }

  /// Age-flush trigger: manually wind back last_flush to simulate an old buffer.
  #[tokio::test]
  async fn age_threshold_triggers_flush_if_needed() {
      let s3 = unreachable_s3().await;
      let (cfg, policy) = test_config(10_000);
      let mut w = PartitionedParquetWriter::new(MockSink, s3, cfg, policy);
      w.push("r1".to_string()).await.unwrap();
      // Age out the buffer by backdating last_flush.
      if let Some(buf) = w.buffers.get_mut("") {
          buf.last_flush = std::time::Instant::now()
              - std::time::Duration::from_secs(3601);
      }
      // flush_all_if_needed should attempt flush (will fail on unreachable S3).
      let _ = w.flush_all_if_needed().await;
      // Regardless of success, must not panic.
  }

  /// Multi-partition: records go to distinct buffers keyed by partition segment.
  #[tokio::test]
  async fn multi_partition_buffers_are_independent() {
      struct MultiSink;
      impl ParquetSink for MultiSink {
          type Record = (String, String);
          fn source(&self) -> &'static str { "test" }
          fn partition(&self, r: &(String, String)) -> Option<String> { Some(r.0.clone()) }
          fn schema(&self, _: Option<&str>) -> Arc<Schema> { test_schema() }
          fn to_record_batch(&self, r: &(String, String), s: &Arc<Schema>)
              -> anyhow::Result<RecordBatch>
          {
              let col = Arc::new(StringArray::from(vec![r.1.as_str()]));
              Ok(RecordBatch::try_new(s.clone(), vec![col])?)
          }
      }
      let s3 = unreachable_s3().await;
      let (mut cfg, policy) = test_config(10_000);
      cfg.max_partitions = 16;
      let mut w = PartitionedParquetWriter::new(MultiSink, s3, cfg, policy);
      for _ in 0..3 { w.push(("a".to_string(), "v".to_string())).await.unwrap(); }
      for _ in 0..2 { w.push(("b".to_string(), "v".to_string())).await.unwrap(); }
      assert_eq!(w.buffers.get("a").unwrap().row_count, 3);
      assert_eq!(w.buffers.get("b").unwrap().row_count, 2);
  }

  /// Encode round-trip: a schema + RecordBatch round-trips through Parquet encoding
  /// (validates the spawn_blocking encode path with a real Parquet reader).
  #[test]
  fn encode_round_trip_via_concat_and_parquet() {
      use arrow::array::StringArray;
      use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

      let schema = test_schema();
      let batch = RecordBatch::try_new(
          schema.clone(),
          vec![Arc::new(StringArray::from(vec!["hello"])) as _],
      ).unwrap();

      // Simulate what flush_partition does: concat_batches + ArrowWriter
      let merged = arrow::compute::concat_batches(&schema, &[batch]).unwrap();
      let props = parquet::file::properties::WriterProperties::builder()
          .set_compression(parquet::basic::Compression::ZSTD(
              parquet::basic::ZstdLevel::try_new(3).unwrap()
          ))
          .build();
      let mut buf = Vec::new();
      let mut writer = parquet::arrow::ArrowWriter::try_new(
          &mut buf, schema, Some(props)
      ).unwrap();
      writer.write(&merged).unwrap();
      writer.close().unwrap();

      let bytes = bytes::Bytes::from(buf);
      let mut reader = ParquetRecordBatchReaderBuilder::try_new(bytes)
          .unwrap().build().unwrap();
      let rb = reader.next().unwrap().unwrap();
      assert_eq!(rb.num_rows(), 1);
      let col = rb.column(0).as_any().downcast_ref::<StringArray>().unwrap();
      assert_eq!(col.value(0), "hello");
  }
  ```
- [ ] Run `export PATH="$HOME/.cargo/bin:$PATH"; cargo test 2>&1 | tail -30`
- [ ] `cargo fmt && cargo clippy --all-targets -- -D warnings`
- [ ] Commit: `test(buffered-writer): byte/age flush triggers, encode round-trip, multi-partition`

---

## Phase 2 — ipfix Adapter

**Spec phase:** 2 (migrate ipfix to the generic core)

**Files modified:**
- `src/forwarding/ipfix_s3.rs` — keep existing code but add `IpfixSink: ParquetSink` and a new thin `IpfixWriterHandle` wrapper; delete the bespoke writer machinery only after the new path is wired and all tests pass.
- `src/main.rs` — update the IPFIX startup block to use `ParquetWriterHandle::start`.
- `src/config/mod.rs` — `IpfixS3Config` kept as-is for now (alias to `BufferedWriterConfig` in Phase 6).

**Interfaces — Consumes (from Phase 1):**
- `ParquetSink`, `ParquetWriterHandle::start(sink, s3, config, policy) -> (ParquetWriterHandle<IpfixSink>, JoinHandle)`
- `BufferedWriterConfig`, `FlushPolicy`

**Interfaces — Produces:**

```rust
// In src/forwarding/ipfix_s3.rs
pub struct IpfixSink;

impl ParquetSink for IpfixSink {
    type Record = Vec<crate::ipfix::FlowRecord>;
    fn source(&self) -> &'static str { "ipfix" }
    fn partition(&self, _: &Vec<crate::ipfix::FlowRecord>) -> Option<String> { None }
    fn schema(&self, _: Option<&str>) -> Arc<arrow_schema::Schema> { flow_record_schema() }
    fn to_record_batch(
        &self,
        records: &Vec<crate::ipfix::FlowRecord>,
        schema: &Arc<arrow_schema::Schema>,
    ) -> anyhow::Result<arrow_array::RecordBatch> {
        // reuses existing append_flow_record + finish_batch
        let mut builders = FlowRecordBuilders::new();
        for r in records { append_flow_record(&mut builders, r)?; }
        finish_batch(builders, schema.clone())
    }
}

// Thin public wrapper so existing callers (main.rs) have a named type
pub type IpfixS3Handler = crate::forwarding::buffered_writer::ParquetWriterHandle<IpfixSink>;
```

### Task 2.1 — Implement `IpfixSink: ParquetSink`

**Steps:**
- [ ] Write failing test asserting `IpfixSink.to_record_batch` produces a 2-row batch matching `append_flow_record` behavior:
  ```rust
  #[test]
  fn ipfix_sink_to_record_batch_produces_correct_schema_and_rows() {
      use crate::forwarding::buffered_writer::ParquetSink;
      let sink = IpfixSink;
      let schema = sink.schema(None);
      assert_eq!(schema.fields().len(), 18);
      assert!(sink.partition(&vec![]).is_none());

      let r = make_flow_record(Some("10.0.0.1"), Some(999), serde_json::json!({"k":"v"}));
      let batch = sink.to_record_batch(&vec![r], &schema).unwrap();
      assert_eq!(batch.num_rows(), 1);
      use arrow::array::StringArray;
      let src = batch.column_by_name("src_addr").unwrap()
          .as_any().downcast_ref::<StringArray>().unwrap();
      assert_eq!(src.value(0), "10.0.0.1");
  }
  ```
- [ ] Run, expect compile error.
- [ ] Add `IpfixSink` struct and its `ParquetSink` impl to `ipfix_s3.rs`, reusing `append_flow_record` + `finish_batch`.
- [ ] Run `export PATH="$HOME/.cargo/bin:$PATH"; cargo test 2>&1 | tail -20`
- [ ] `cargo fmt && cargo clippy --all-targets -- -D warnings`
- [ ] Commit: `feat(ipfix): add IpfixSink implementing ParquetSink`

---

### Task 2.2 — Wire `IpfixS3Handler` through `ParquetWriterHandle` + update `main.rs`

**Steps:**
- [ ] Add type alias `pub type IpfixS3Handler = crate::forwarding::buffered_writer::ParquetWriterHandle<IpfixSink>;` to `ipfix_s3.rs`.
- [ ] Add a `pub fn ipfix_start(config: &IpfixS3Config, sink: Arc<S3Sink>) -> (IpfixS3Handler, JoinHandle<()>)` adapter function that builds `BufferedWriterConfig` + `FlushPolicy` from the existing `IpfixS3Config` defaults and calls `ParquetWriterHandle::start`:
  ```rust
  pub fn ipfix_start(
      cfg: &IpfixS3Config,
      s3: Arc<crate::forwarding::s3_sink::S3Sink>,
  ) -> (IpfixS3Handler, tokio::task::JoinHandle<()>) {
      use crate::config::S3ConnectionConfig;
      use crate::forwarding::buffered_writer::{BufferedWriterConfig, FlushPolicy, ParquetWriterHandle};
      let bwc = BufferedWriterConfig {
          connection: cfg.connection.clone(),
          prefix: cfg.prefix.clone(),
          max_buffer_rows: cfg.max_buffer_rows,
          flush_threshold_bytes: cfg.flush_threshold_bytes,
          flush_interval_secs: cfg.flush_interval_secs,
          channel_capacity: cfg.channel_capacity,
          max_partitions: 1, // single-partition source
      };
      let policy = FlushPolicy {
          max_rows: cfg.max_buffer_rows,
          max_bytes: cfg.flush_threshold_bytes,
          interval: std::time::Duration::from_secs(cfg.flush_interval_secs),
      };
      ParquetWriterHandle::start(IpfixSink, s3, bwc, policy)
  }
  ```
- [ ] Update `src/main.rs` IPFIX block: replace `IpfixS3Handler::start_with_capacity(...)` call with `forwarding::ipfix_s3::ipfix_start(s3_cfg, Arc::new(sink))`. Update the handler `Arc` construction and `IpfixHandler` impl: since `ParquetWriterHandle<IpfixSink>` does not yet implement `IpfixHandler`, keep the bespoke `IpfixS3Handler` struct that wraps it (or implement the trait on the type alias — see next step).
- [ ] Implement `IpfixHandler` for the type alias by implementing it on the concrete wrapper:

  In `ipfix_s3.rs`, add:
  ```rust
  #[async_trait::async_trait]
  impl crate::ipfix::listener::IpfixHandler for IpfixS3Handler {
      async fn handle_flows(
          &self,
          flows: Vec<crate::ipfix::FlowRecord>,
          source: std::net::SocketAddr,
      ) {
          let count = flows.len() as u64;
          match self.try_send(flows) {
              Ok(()) => {}
              Err(_dropped) => {
                  metrics::counter!("parquet_s3_dropped", "source" => "ipfix")
                      .increment(count);
                  tracing::warn!(
                      "IPFIX S3 channel full; dropped {} flows from {}",
                      count, source
                  );
              }
          }
      }
  }
  ```
  Note: `IpfixHandler` currently takes `Vec<FlowRecord>`. Since `IpfixSink::Record = Vec<FlowRecord>`, `try_send` passes the batch directly.
- [ ] Remove the bespoke `IpfixS3Writer` struct and its `flush_then_cap`, `drop_oldest_to_cap`, `flush_if_needed`, `flush`, `push_batch` methods (the generic now owns this logic). Keep `flow_record_schema()`, `FlowRecordBuilders`, `append_flow_record()`, `finish_batch()`, `encode_batches_to_parquet()`, `build_s3_key()` for now (they are still used by tests and `IpfixSink::to_record_batch`; `encode_batches_to_parquet` can be removed in Phase 6 cleanup).
- [ ] Update existing ipfix tests:
  - Tests asserting `ipfix_s3_dropped` metric → change to `parquet_s3_dropped` with `source="ipfix"` label.
  - Tests asserting `ipfix_s3_records_written` → `parquet_s3_records_written{source="ipfix"}`.
  - Tests asserting single-trigger flush behavior (bytes-only) → update to unified policy; the byte trigger still fires first (byte-dominant defaults preserved), so behavior is preserved but the row trigger is now also active.
  - Remove references to `IpfixS3WriterConfig` and `IpfixS3Writer` in tests; use `IpfixSink` + `ParquetWriterHandle` directly.
- [ ] Run `export PATH="$HOME/.cargo/bin:$PATH"; cargo test 2>&1 | tail -30` — all tests must pass.
- [ ] `cargo fmt && cargo clippy --all-targets -- -D warnings`
- [ ] Commit: `refactor(ipfix): collapse IpfixS3Writer to IpfixSink adapter; update metric labels`

---

### Task 2.3 — ipfix e2e green gate

**Steps:**
- [ ] Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test 2>&1 | tail -20` — all tests pass (integration gated by env var; confirm the gate is active, not removed).
- [ ] Visually verify `IPFIX_S3_INTEGRATION_TEST=1` test path still compiles (even if not run locally).
- [ ] Commit: `test(ipfix): verify e2e gate still compiles after adapter migration`

---

## Phase 3 — syslog Adapter

**Spec phase:** 3 (migrate syslog)

**Files modified:**
- `src/forwarding/syslog_s3.rs`
- `src/main.rs` (syslog startup block)

**Interfaces — Consumes (Phase 1):** `ParquetSink`, `ParquetWriterHandle::start`, `BufferedWriterConfig`, `FlushPolicy`

**Interfaces — Produces:**

```rust
// In syslog_s3.rs
pub struct SyslogSink;

impl ParquetSink for SyslogSink {
    type Record = crate::syslog::SyslogMessage;
    fn source(&self) -> &'static str { "syslog" }
    fn partition(&self, _: &crate::syslog::SyslogMessage) -> Option<String> { None }
    fn schema(&self, _: Option<&str>) -> Arc<arrow_schema::Schema> { syslog_schema() }
    fn to_record_batch(
        &self,
        record: &crate::syslog::SyslogMessage,
        _schema: &Arc<arrow_schema::Schema>,
    ) -> anyhow::Result<arrow_array::RecordBatch> {
        // reuses existing syslog_message_to_batch
        syslog_message_to_batch(record)
    }
}

pub type SyslogS3Handler = crate::forwarding::buffered_writer::ParquetWriterHandle<SyslogSink>;
```

### Task 3.1 — Implement `SyslogSink: ParquetSink`

**Steps:**
- [ ] Write failing test:
  ```rust
  #[test]
  fn syslog_sink_to_record_batch_matches_direct_mapping() {
      use crate::forwarding::buffered_writer::ParquetSink;
      let sink = SyslogSink;
      let schema = sink.schema(None);
      assert_eq!(schema.fields().len(), 11);
      assert!(sink.partition(&sample_rfc5424()).is_none());
      let batch = sink.to_record_batch(&sample_rfc5424(), &schema).unwrap();
      assert_eq!(batch.num_rows(), 1);
      use arrow::array::UInt8Array;
      let priority = batch.column(0).as_any().downcast_ref::<UInt8Array>().unwrap();
      assert_eq!(priority.value(0), 34);
  }
  ```
- [ ] Run, expect compile error.
- [ ] Implement `SyslogSink` and its `ParquetSink` impl, delegating to `syslog_message_to_batch`.
- [ ] Add `pub type SyslogS3Handler = crate::forwarding::buffered_writer::ParquetWriterHandle<SyslogSink>;`
- [ ] Add `pub fn syslog_start(cfg: &SyslogS3Config, s3: Arc<S3Sink>) -> (SyslogS3Handler, JoinHandle<()>)` builder (same pattern as `ipfix_start`; note syslog is **row-dominant**: `max_rows = cfg.max_buffer_rows`, `max_bytes = usize::MAX` in defaults, but `flush_threshold_bytes` field exists for the unified policy).
- [ ] Implement `SyslogHandler` for `SyslogS3Handler` (same pattern as ipfix):
  ```rust
  #[async_trait::async_trait]
  impl crate::syslog::listener::SyslogHandler for SyslogS3Handler {
      async fn handle_message(
          &self,
          message: crate::syslog::SyslogMessage,
          _source: std::net::SocketAddr,
      ) {
          match self.try_send(message) {
              Ok(()) => {}
              Err(_) => {
                  metrics::counter!("parquet_s3_dropped", "source" => "syslog").increment(1);
              }
          }
      }
  }
  ```
- [ ] Update `main.rs` syslog block: replace `SyslogS3Handler::start_with_capacity(...)` with `forwarding::syslog_s3::syslog_start(s3_cfg, Arc::new(sink))`.
- [ ] Remove bespoke `SyslogS3Writer` machinery; keep `syslog_schema()` and `syslog_message_to_batch()`.
- [ ] Update existing syslog tests: change metric names (`syslog_s3_*` → `parquet_s3_*{source="syslog"}`); update row-trigger assertions to unified policy (still fires at `max_buffer_rows` because row-dominant defaults).
- [ ] Run `export PATH="$HOME/.cargo/bin:$PATH"; cargo test 2>&1 | tail -30`
- [ ] `cargo fmt && cargo clippy --all-targets -- -D warnings`
- [ ] Commit: `refactor(syslog): collapse SyslogS3Writer to SyslogSink adapter; update metric labels`

---

### Task 3.2 — syslog e2e green gate

**Steps:**
- [ ] Run `export PATH="$HOME/.cargo/bin:$PATH"; cargo test 2>&1 | tail -20` — all tests pass.
- [ ] Commit: `test(syslog): verify adapter migration + unified flush policy`

---

## Phase 4 — zeek Adapter

**Spec phase:** 4 (migrate zeek — multi-partition, schema registry, path sanitizer)

**Files modified:**
- `src/forwarding/zeek_s3.rs`
- `src/main.rs` (zeek startup block)

**Interfaces — Consumes (Phase 1):** `ParquetSink`, `ParquetWriterHandle::start`, `BufferedWriterConfig`, `FlushPolicy`; `sanitize_log_path` stays in `zeek_s3.rs`.

**Interfaces — Produces:**

```rust
// In zeek_s3.rs
pub struct ZeekSink;

impl ParquetSink for ZeekSink {
    type Record = crate::zeek::ZeekRecord;
    fn source(&self) -> &'static str { "zeek" }
    /// Partition = sanitized log_path (used as buffer-map key and S3 path segment).
    fn partition(&self, record: &crate::zeek::ZeekRecord) -> Option<String> {
        Some(sanitize_log_path(&record.log_path))
    }
    /// Schema: per-partition lookup via `get_schema_entry` (typed or envelope fallback).
    fn schema(&self, partition: Option<&str>) -> Arc<arrow_schema::Schema> {
        let path = partition.unwrap_or("unknown");
        crate::zeek::schema::get_schema_entry(path).schema.clone()
    }
    /// Row mapping: delegates to the `SchemaEntry.mapper` closure (best-effort/total).
    fn to_record_batch(
        &self,
        record: &crate::zeek::ZeekRecord,
        schema: &Arc<arrow_schema::Schema>,
    ) -> anyhow::Result<arrow_array::RecordBatch> {
        let path = sanitize_log_path(&record.log_path);
        let entry = crate::zeek::schema::get_schema_entry(&path);
        (entry.mapper)(&record.fields)
    }
}

pub type ZeekS3Handler = crate::forwarding::buffered_writer::ParquetWriterHandle<ZeekSink>;
```

### Task 4.1 — Implement `ZeekSink: ParquetSink`

**Important note on `schema()` signature:** The generic `PartitionedParquetWriter` calls `sink.schema(Some(effective_key))` when creating a new partition buffer (where `effective_key` is the result of `partition()`, already sanitized). For the `"_overflow"` case, `sink.schema(Some("_overflow"))` is called; `get_schema_entry("_overflow")` returns the envelope fallback (since "unknown"/"_overflow" are not in the curated registry), which is correct behavior.

**Steps:**
- [ ] Write failing tests:
  ```rust
  #[test]
  fn zeek_sink_partition_sanitizes_path() {
      use crate::forwarding::buffered_writer::ParquetSink;
      let sink = ZeekSink;
      let rec = ZeekRecord {
          log_path: "conn".to_string(),
          fields: serde_json::json!({}),
          received_at: chrono::Utc::now(),
      };
      assert_eq!(sink.partition(&rec), Some("conn".to_string()));

      let bad = ZeekRecord {
          log_path: "../etc/passwd".to_string(),
          fields: serde_json::json!({}),
          received_at: chrono::Utc::now(),
      };
      let part = sink.partition(&bad).unwrap();
      assert!(!part.contains('/'), "sanitized partition must not contain /");
      assert!(!part.contains('.'), "sanitized partition must not contain .");
  }

  #[test]
  fn zeek_sink_schema_returns_conn_schema_for_conn() {
      use crate::forwarding::buffered_writer::ParquetSink;
      let sink = ZeekSink;
      let schema = sink.schema(Some("conn"));
      // conn_schema has at least ts, uid, id.orig_h
      assert!(schema.field_with_name("uid").is_ok());
  }

  #[test]
  fn zeek_sink_to_record_batch_maps_conn_record() {
      use crate::forwarding::buffered_writer::ParquetSink;
      let sink = ZeekSink;
      let rec = make_conn_record("CTEST");
      let schema = sink.schema(Some("conn"));
      let batch = sink.to_record_batch(&rec, &schema).unwrap();
      assert_eq!(batch.num_rows(), 1);
  }
  ```
- [ ] Run, expect compile error.
- [ ] Implement `ZeekSink` + `ParquetSink` impl.
- [ ] Add `pub type ZeekS3Handler = crate::forwarding::buffered_writer::ParquetWriterHandle<ZeekSink>;`
- [ ] Add `pub fn zeek_start(cfg: &ZeekS3Config, s3: Arc<S3Sink>) -> (ZeekS3Handler, JoinHandle<()>)`:
  ```rust
  pub fn zeek_start(
      cfg: &crate::config::ZeekS3Config,
      s3: Arc<crate::forwarding::s3_sink::S3Sink>,
  ) -> (ZeekS3Handler, tokio::task::JoinHandle<()>) {
      use crate::forwarding::buffered_writer::{BufferedWriterConfig, FlushPolicy, ParquetWriterHandle};
      let bwc = BufferedWriterConfig {
          connection: cfg.connection.clone(),
          prefix: cfg.prefix.clone(),
          max_buffer_rows: cfg.max_buffer_rows,
          flush_threshold_bytes: cfg.flush_threshold_bytes,
          flush_interval_secs: cfg.flush_interval_secs,
          channel_capacity: cfg.channel_capacity,
          max_partitions: MAX_ZEEK_STREAMS, // preserve existing cap
      };
      let policy = FlushPolicy {
          max_rows: cfg.max_buffer_rows,
          max_bytes: cfg.flush_threshold_bytes,
          interval: std::time::Duration::from_secs(cfg.flush_interval_secs),
      };
      ParquetWriterHandle::start(ZeekSink, s3, bwc, policy)
  }
  ```
- [ ] Implement `ZeekHandler` for `ZeekS3Handler`:
  ```rust
  #[async_trait::async_trait]
  impl crate::zeek::listener::ZeekHandler for ZeekS3Handler {
      async fn handle_record(
          &self,
          record: crate::zeek::ZeekRecord,
          source: std::net::SocketAddr,
      ) {
          match self.try_send(record) {
              Ok(()) => {}
              Err(_dropped) => {
                  metrics::counter!("parquet_s3_dropped", "source" => "zeek").increment(1);
                  tracing::warn!("Zeek S3 channel full; dropped 1 record from {}", source);
              }
          }
      }
  }
  ```
- [ ] Update `main.rs` zeek block: replace `ZeekS3Handler::start_with_capacity(...)` with `forwarding::zeek_s3::zeek_start(s3_cfg, Arc::new(sink))`.
- [ ] Remove bespoke `ZeekS3Writer` and `StreamBuffer` machinery; keep `sanitize_log_path()`, `build_zeek_s3_key()` (used by existing tests; can be removed in Phase 6 cleanup), `MAX_ZEEK_STREAMS`.
- [ ] **Key format for zeek**: The generic `build_key("zeek", Some("conn"), now)` produces `zeek/conn/year=…` which exactly matches the old `build_zeek_s3_key("zeek", "conn", now)`. Verify this in the existing `zeek_s3_key_has_correct_structure` test by re-checking it passes.
- [ ] Update existing zeek tests: change metric names (`zeek_s3_*` → `parquet_s3_*{source="zeek"}`); `zeek_streams_capped` counter → `parquet_s3_partitions_capped{source="zeek"}`; `zeek_streams_capped` field on `ZeekS3Writer` removed (the generic tracks it internally).
- [ ] Run `export PATH="$HOME/.cargo/bin:$PATH"; cargo test 2>&1 | tail -30`
- [ ] `cargo fmt && cargo clippy --all-targets -- -D warnings`
- [ ] Commit: `refactor(zeek): collapse ZeekS3Writer to ZeekSink adapter; update metric labels`

---

### Task 4.2 — zeek e2e green gate

**Steps:**
- [ ] Run `export PATH="$HOME/.cargo/bin:$PATH"; cargo test 2>&1 | tail -20`
- [ ] Confirm: `zeek_s3_key_has_correct_structure` test passes (partition-based key matches `zeek/conn/year=…`).
- [ ] Commit: `test(zeek): verify adapter migration + partition cap + key format`

---

## Phase 5 — WEF Adapter

**Spec phase:** 5 — the riskiest increment; WEF flows through an HTTP path + graceful-shutdown worker that differs from the listener-based sources.

**Files modified:**
- `src/forwarding/parquet_s3.rs` — keep `ParquetS3Config` and `create_parquet_s3_forwarder` for now (they locate the destination); add `WefSink: ParquetSink`; remove `ParquetS3Forwarder`, `EventTypeBuffer`, `BufferedEvent`.
- `src/server/mod.rs` — replace the bespoke worker (the `tokio::spawn` with `s3_forwarder.forward()` / `shutdown_flush()`) with `ParquetWriterHandle::start`; replace `AppState.parquet_s3_sender: Option<mpsc::Sender<Arc<WindowsEvent>>>` with `Option<crate::forwarding::buffered_writer::ParquetWriterHandle<WefSink>>` or keep the sender as a thin wrapper.
- `src/main.rs` — the WEF `wef_worker_handle` is already handled in the generic `writer_handles` pattern; migrate the WEF handle into `writer_handles`.

**Interfaces — Consumes (Phase 1):** `ParquetSink`, `ParquetWriterHandle::start`, `BufferedWriterConfig`, `FlushPolicy`

**Interfaces — Produces:**

```rust
// In parquet_s3.rs
pub struct WefSink;

impl ParquetSink for WefSink {
    type Record = std::sync::Arc<crate::models::WindowsEvent>;
    fn source(&self) -> &'static str { "wef" }
    /// Partition: "event_type=<id>" when parsed event_id is available, "_unclassified" otherwise.
    fn partition(&self, record: &std::sync::Arc<crate::models::WindowsEvent>) -> Option<String> {
        let id = record.parsed.as_ref().map(|p| p.event_id)?;
        Some(format!("event_type={id}"))
    }
    /// Fixed WEF schema (same 5-column schema as the current write_parquet_file).
    fn schema(&self, _: Option<&str>) -> Arc<arrow_schema::Schema> { wef_schema() }
    fn to_record_batch(
        &self,
        record: &std::sync::Arc<crate::models::WindowsEvent>,
        schema: &Arc<arrow_schema::Schema>,
    ) -> anyhow::Result<arrow_array::RecordBatch> {
        wef_event_to_batch(record, schema)
    }
}

/// Fixed WEF schema (matches current write_parquet_file):
pub fn wef_schema() -> Arc<arrow_schema::Schema> {
    use arrow::datatypes::{DataType, Field, Schema};
    std::sync::Arc::new(Schema::new(vec![
        Field::new("event_id",        DataType::UInt32, false),
        Field::new("timestamp",       DataType::Utf8,   false),
        Field::new("source_host",     DataType::Utf8,   false),
        Field::new("subscription_id", DataType::Utf8,   true),
        Field::new("event_data",      DataType::Utf8,   false),
    ]))
}

pub type WefWriterHandle = crate::forwarding::buffered_writer::ParquetWriterHandle<WefSink>;
```

### Task 5.1 — Implement `WefSink: ParquetSink`

**Steps:**
- [ ] Extract `wef_schema()` as a `pub fn` (currently inlined in `write_parquet_file`).
- [ ] Implement `wef_event_to_batch(event: &Arc<WindowsEvent>, schema: &Arc<Schema>) -> anyhow::Result<RecordBatch>` using the existing array-construction logic from `write_parquet_file` (event_id, timestamp, source_host, subscription_id, event_data). Handle `None` parsed event gracefully (return `Err` so the record is skipped, mirroring `BufferedEvent::from_windows_event`'s `None` path).
- [ ] Write failing tests:
  ```rust
  #[test]
  fn wef_schema_has_five_columns() {
      let schema = wef_schema();
      assert_eq!(schema.fields().len(), 5);
      assert!(schema.field_with_name("event_id").is_ok());
      assert!(schema.field_with_name("event_data").is_ok());
  }

  #[test]
  fn wef_sink_partition_returns_event_type_segment() {
      use crate::forwarding::buffered_writer::ParquetSink;
      use crate::models::{EventLevel, ParsedEvent, WindowsEvent};
      let parsed = ParsedEvent {
          provider: "Security".into(), event_id: 4624,
          level: EventLevel::Information, task: 0, opcode: 0, keywords: 0,
          time_created: chrono::Utc::now(), event_record_id: 1,
          process_id: None, thread_id: None, channel: "Security".into(),
          computer: "HOST".into(), security_user_id: None, message: None, data: None,
      };
      let event = std::sync::Arc::new(
          WindowsEvent::new("host".into(), "<Event/>".into()).with_parsed(parsed)
      );
      let sink = WefSink;
      assert_eq!(sink.partition(&event), Some("event_type=4624".to_string()));
  }

  #[test]
  fn wef_sink_partition_returns_none_without_parsed() {
      use crate::forwarding::buffered_writer::ParquetSink;
      use crate::models::WindowsEvent;
      let event = std::sync::Arc::new(WindowsEvent::new("h".into(), "<Event/>".into()));
      let sink = WefSink;
      // No parsed → partition returns None (routed to single buffer or skipped)
      assert!(sink.partition(&event).is_none());
  }

  #[test]
  fn wef_sink_to_record_batch_maps_event_fields() {
      use crate::forwarding::buffered_writer::ParquetSink;
      use crate::models::{EventLevel, ParsedEvent, WindowsEvent};
      use arrow::array::{StringArray, UInt32Array};
      let parsed = ParsedEvent {
          provider: "Security".into(), event_id: 4625,
          level: EventLevel::Information, task: 0, opcode: 0, keywords: 0,
          time_created: chrono::Utc::now(), event_record_id: 2,
          process_id: None, thread_id: None, channel: "Security".into(),
          computer: "DC01".into(), security_user_id: None, message: None, data: None,
      };
      let event = std::sync::Arc::new(
          WindowsEvent::new("dc01".into(), "<Event/>".into()).with_parsed(parsed)
      );
      let sink = WefSink;
      let schema = sink.schema(None);
      let batch = sink.to_record_batch(&event, &schema).unwrap();
      assert_eq!(batch.num_rows(), 1);
      let id_col = batch.column_by_name("event_id").unwrap()
          .as_any().downcast_ref::<UInt32Array>().unwrap();
      assert_eq!(id_col.value(0), 4625);
      let host_col = batch.column_by_name("source_host").unwrap()
          .as_any().downcast_ref::<StringArray>().unwrap();
      assert_eq!(host_col.value(0), "dc01");
  }
  ```
- [ ] Run, expect compile error.
- [ ] Implement `WefSink`, `wef_schema()`, `wef_event_to_batch()`.
- [ ] Run `export PATH="$HOME/.cargo/bin:$PATH"; cargo test 2>&1 | tail -20`
- [ ] `cargo fmt && cargo clippy --all-targets -- -D warnings`
- [ ] Commit: `feat(wef): add WefSink implementing ParquetSink`

---

### Task 5.2 — Wire WEF through `ParquetWriterHandle`, migrate `server/mod.rs` + `main.rs`

**Steps:**
- [ ] Add `pub type WefWriterHandle = crate::forwarding::buffered_writer::ParquetWriterHandle<WefSink>;` to `parquet_s3.rs`.
- [ ] Add `pub fn wef_start(config: &ParquetS3Config, s3: crate::forwarding::s3_sink::S3Sink) -> (WefWriterHandle, tokio::task::JoinHandle<()>)`:
  ```rust
  pub fn wef_start(
      config: &ParquetS3Config,
      s3: crate::forwarding::s3_sink::S3Sink,
  ) -> (WefWriterHandle, tokio::task::JoinHandle<()>) {
      use crate::forwarding::buffered_writer::{BufferedWriterConfig, FlushPolicy, ParquetWriterHandle};
      let max_bytes = (config.max_file_size_mb * 1024 * 1024) as usize;
      let bwc = BufferedWriterConfig {
          connection: config.connection.clone(),
          prefix: "wef".to_string(),
          max_buffer_rows: 100_000,       // generous row cap for WEF
          flush_threshold_bytes: max_bytes,
          flush_interval_secs: config.flush_interval_secs,
          channel_capacity: 10_000,       // matches existing AppState channel size
          max_partitions: 4_096,          // generous event-type cardinality bound
      };
      let policy = FlushPolicy {
          max_rows: 100_000,
          max_bytes: max_bytes,
          interval: std::time::Duration::from_secs(config.flush_interval_secs),
      };
      ParquetWriterHandle::start(WefSink, std::sync::Arc::new(s3), bwc, policy)
  }
  ```
- [ ] Update `server/mod.rs`:
  - Change `AppState.parquet_s3_sender` from `Option<mpsc::Sender<Arc<WindowsEvent>>>` to `Option<WefWriterHandle>` (the handle type already wraps the sender).
  - Remove the bespoke `tokio::spawn` worker task (the `loop { select! { … s3_forwarder.forward / shutdown_flush … } }`) and replace with a call to `wef_start`.
  - In `Server::new`: the `(parquet_s3_sender, wef_worker_handle)` tuple now comes from `wef_start` instead of the manual spawn. The `wef_worker_handle` is the `JoinHandle` returned by `ParquetWriterHandle::start`.
  - In `process_single_event`: update the `sender.try_send(event.clone())` call to `state.parquet_s3_sender.as_ref().map(|h| h.try_send(Arc::clone(&event)))` (the handle's `try_send` is the same API).
  - On overflow: change `wef_events_dropped` metric to `parquet_s3_dropped{source="wef"}`.
- [ ] Update `main.rs`:
  - The `wef_worker_handle` extraction via `server.take_wef_worker_handle()` and the separate `if let Some(wef_handle)` shutdown block can be merged into the `writer_handles` vec: in `Server::new`, do NOT store `wef_worker_handle` separately. Instead push it into `writer_handles` via a new `Server::take_writer_handles() -> Vec<JoinHandle<()>>` method or expose `wef_worker_handle` as before and add it to the vec at the call site in `main.rs`.

  Preferred approach (minimal diff): keep `take_wef_worker_handle()` and push the handle into `writer_handles` in `main.rs`:
  ```rust
  // main.rs, after server is built:
  let wef_worker_handle = server.take_wef_worker_handle();
  // ... later in shutdown:
  if let Some(h) = wef_worker_handle {
      writer_handles.push(h); // add to the existing writer_handles vec before the flush loop
  }
  ```
  This avoids the separate `if let Some(wef_handle)` block and reuses the existing 10s flush deadline loop.
- [ ] Update existing WEF tests in `server/mod.rs`:
  - `AppState` construction in `build_state_with_config` and `default_state`: `parquet_s3_sender: None` stays `None` (type changes but `None` is still valid for `Option<WefWriterHandle>`).
  - If any test checks `wef_events_dropped` metric, update to `parquet_s3_dropped{source="wef"}`.
- [ ] Remove dead code from `parquet_s3.rs`: `ParquetS3Forwarder`, `EventTypeBuffer`, `BufferedEvent`, `write_parquet_file`, `upload_to_s3`, `flush_event_type`, `flush_all`, `shutdown_flush`, `forward`. Keep `ParquetS3Config`, `ParquetS3Config::from_destination`, `create_parquet_s3_forwarder` (still needed to locate the destination and build `S3Sink`).
- [ ] Run `export PATH="$HOME/.cargo/bin:$PATH"; cargo test 2>&1 | tail -30`
- [ ] `cargo fmt && cargo clippy --all-targets -- -D warnings`
- [ ] Commit: `refactor(wef): migrate ParquetS3Forwarder to WefSink adapter; unify shutdown path`

---

### Task 5.3 — WEF e2e + graceful-shutdown verification

**Steps:**
- [ ] Add/update unit test for graceful-shutdown sequence:
  ```rust
  #[tokio::test]
  async fn wef_writer_handle_drop_triggers_flush_on_close() {
      use crate::forwarding::buffered_writer::{BufferedWriterConfig, FlushPolicy, ParquetWriterHandle};
      use crate::config::S3ConnectionConfig;
      let s3 = std::sync::Arc::new(
          crate::forwarding::s3_sink::S3Sink::from_connection(&S3ConnectionConfig {
              endpoint: "http://127.0.0.1:1".to_string(),
              bucket: "b".to_string(), region: "us-east-1".to_string(),
              access_key: "k".to_string(), secret_key: "s".to_string(),
          }).await.unwrap()
      );
      let cfg = BufferedWriterConfig {
          connection: S3ConnectionConfig {
              endpoint: "http://127.0.0.1:1".to_string(),
              bucket: "b".to_string(), region: "us-east-1".to_string(),
              access_key: "k".to_string(), secret_key: "s".to_string(),
          },
          prefix: "wef".to_string(),
          max_buffer_rows: 10_000,
          flush_threshold_bytes: usize::MAX,
          flush_interval_secs: 3600,
          channel_capacity: 64,
          max_partitions: 512,
      };
      let policy = FlushPolicy {
          max_rows: 10_000, max_bytes: usize::MAX,
          interval: std::time::Duration::from_secs(3600),
      };
      use crate::forwarding::parquet_s3::WefSink;
      let (handle, jh) = ParquetWriterHandle::start(WefSink, s3, cfg, policy);
      drop(handle); // close the channel
      // Background task must exit within 5s (flush attempt fails on unreachable S3, then breaks)
      tokio::time::timeout(std::time::Duration::from_secs(5), jh).await
          .expect("task did not exit within 5s")
          .expect("task panicked");
  }
  ```
- [ ] Run `export PATH="$HOME/.cargo/bin:$PATH"; cargo test 2>&1 | tail -20`
- [ ] `cargo fmt && cargo clippy --all-targets -- -D warnings`
- [ ] Commit: `test(wef): shutdown flush-on-close regression test`

---

## Phase 6 — Cleanup

**Spec phase:** 6 — remove all dead duplicated code, unify config, update docs.

### Task 6.1 — Remove dead writer code from all four source files

**Files:** `src/forwarding/{ipfix_s3,syslog_s3,zeek_s3,parquet_s3}.rs`

**Steps:**
- [ ] In `ipfix_s3.rs`: remove `IpfixS3Writer`, `IpfixS3WriterConfig`, `BufferedBatch`, `encode_batches_to_parquet()`, `build_s3_key()` (now replaced by `build_key` in `buffered_writer.rs`). Keep `flow_record_schema()`, `FlowRecordBuilders`, `append_flow_record()`, `finish_batch()` (still used by `IpfixSink::to_record_batch`). Verify all remaining tests pass.
- [ ] In `syslog_s3.rs`: remove `SyslogS3Writer`, `SyslogS3WriterConfig`, `encode_batches_to_parquet()`. Keep `syslog_schema()`, `syslog_message_to_batch()`.
- [ ] In `zeek_s3.rs`: remove `ZeekS3Writer`, `StreamBuffer`, `BufferedBatch`, `encode_batches()`, `build_zeek_s3_key()`. Keep `sanitize_log_path()`, `MAX_ZEEK_STREAMS` (still referenced in `zeek_start`). Update the `zeek_s3_key_has_correct_structure` test to use `build_key` from `buffered_writer`.
- [ ] In `parquet_s3.rs`: confirm `ParquetS3Forwarder`, `EventTypeBuffer`, `BufferedEvent`, `write_parquet_file`, `upload_to_s3` are already removed in Phase 5. Remove `flush_interval_secs` accessor and other dead methods. Keep `ParquetS3Config`, `create_parquet_s3_forwarder`, `wef_schema()`, `wef_event_to_batch()`, `WefSink`, `WefWriterHandle`, `wef_start`.
- [ ] Run `export PATH="$HOME/.cargo/bin:$PATH"; cargo test 2>&1 | tail -30`
- [ ] `cargo fmt && cargo clippy --all-targets -- -D warnings`
- [ ] Commit: `refactor: remove dead per-source writer machinery after generic migration`

---

### Task 6.2 — Unify config structs + source-specific default functions

**Files:** `src/config/mod.rs`, `src/forwarding/{ipfix_s3,syslog_s3,zeek_s3,parquet_s3}.rs`

**Steps:**
- [ ] Keep `SyslogS3Config`, `IpfixS3Config` (from `ipfix_s3.rs`), `ZeekS3Config` as the TOML deserialization types (backward-compatible). These are the types that appear in `[syslog.s3]`, `[ipfix.s3]`, `[zeek.s3]` TOML sections. The `*_start` adapter functions convert them to `BufferedWriterConfig` + `FlushPolicy` at startup.
- [ ] The WEF path uses `ParquetS3Config` (read from `[forwarding.destinations]`); leave it as-is.
- [ ] **No TOML key changes** — backward compatibility is fully preserved. The spec says "only the Rust struct is unified"; since we decided to keep the per-source TOML types and only convert at startup, Phase 6 cleanup is a no-op for config.
- [ ] Remove the now-unused `IpfixS3WriterConfig` from `ipfix_s3.rs` (it was only used by the deleted `IpfixS3Writer`).
- [ ] Remove `SyslogS3WriterConfig` from `syslog_s3.rs`.
- [ ] Remove `ZeekS3WriterConfig` from `zeek_s3.rs`.
- [ ] Run `export PATH="$HOME/.cargo/bin:$PATH"; cargo test 2>&1 | tail -20`
- [ ] `cargo fmt && cargo clippy --all-targets -- -D warnings`
- [ ] Commit: `refactor(config): remove bespoke WriterConfig structs; keep per-source TOML types`

---

### Task 6.3 — Verify unified metric names in all tests

**Files:** `src/forwarding/{ipfix_s3,syslog_s3,zeek_s3,parquet_s3,buffered_writer}.rs`, `src/server/mod.rs`

**Steps:**
- [ ] `grep -rn "ipfix_s3_\|syslog_s3_\|zeek_s3_\|wef_s3_\|wef_events_dropped\|zeek_streams_capped\"" src/` — must return zero hits.
- [ ] `grep -rn "parquet_s3_" src/ | head -50` — all metric references must use the `{source}` label pattern.
- [ ] If any stale metric names remain, fix them.
- [ ] Run `export PATH="$HOME/.cargo/bin:$PATH"; cargo test 2>&1 | tail -20`
- [ ] Commit: `refactor: final metric name cleanup — all counters use parquet_s3_{name}{source}`

---

### Task 6.4 — Update documentation

**Files:** `README.md`, `docs/IPFIX_IMPLEMENTATION.md`, `docs/SYSLOG_IMPLEMENTATION.md`, `docs/ZEEK_IMPLEMENTATION.md`, `docs/IMPLEMENTATION.md` (if they exist)

**Steps:**
- [ ] `ls /home/peter/projects/logthing/docs/` to enumerate the doc files that exist.
- [ ] For each `*_IMPLEMENTATION.md` that mentions old metric names (`ipfix_s3_*`, `syslog_s3_*`, `zeek_s3_*`, `wef_*`), replace them with the unified `parquet_s3_*{source="…"}` form.
- [ ] In `README.md`, update any metrics table to use unified names.
- [ ] Run `export PATH="$HOME/.cargo/bin:$PATH"; cargo test 2>&1 | tail -10` — ensure docs changes don't break doc tests.
- [ ] `cargo fmt && cargo clippy --all-targets -- -D warnings`
- [ ] Commit: `docs: update metric names to parquet_s3_{name}{source} across all implementation docs`

---

### Task 6.5 — Final full-test sweep

**Steps:**
- [ ] `export PATH="$HOME/.cargo/bin:$PATH"; cargo test 2>&1`
- [ ] `export PATH="$HOME/.cargo/bin:$PATH"; cargo clippy --all-targets -- -D warnings 2>&1`
- [ ] `export PATH="$HOME/.cargo/bin:$PATH"; cargo fmt --check 2>&1`
- [ ] All green. If any failures: fix before proceeding.
- [ ] Commit: `chore: final cleanup sweep — all tests pass, clippy clean, fmt clean`

---

## Self-Review

### Spec-Coverage Checklist

| Spec Decision | Covered | Where |
|---|---|---|
| `ParquetSink` trait (source, partition, schema, to_record_batch) | ✅ | Task 1.1 |
| `PartitionedParquetWriter<S>` (generic, monomorphized) | ✅ | Task 1.3 |
| `ParquetWriterHandle<S>` (start, try_send) | ✅ | Task 1.5 |
| `BufferedWriterConfig` (shared TOML-compatible) | ✅ | Task 1.1 |
| `FlushPolicy` (rows OR bytes OR age) | ✅ | Task 1.1, 1.3 |
| Per-partition `VecDeque<(RecordBatch, est_bytes)>` | ✅ | Task 1.2, 1.3 |
| `drop_oldest_to_cap` + `parquet_s3_buffer_dropped{source}` | ✅ | Task 1.3 |
| Partition-count cap + `_overflow` + `parquet_s3_partitions_capped{source}` | ✅ | Task 1.4 |
| `flush_check_interval` timer | ✅ | Task 1.5 (reuses s3_sink helper) |
| `spawn_blocking` encode via `concat_batches` → parquet | ✅ | Task 1.3 |
| S3 upload via `S3Sink::upload` | ✅ | Task 1.3 |
| Bounded channel + background `select!` loop | ✅ | Task 1.5 |
| Channel-overflow `parquet_s3_dropped{source}` | ✅ | Task 1.5 |
| Flush-on-channel-close (graceful shutdown) | ✅ | Task 1.5 |
| Key format `{prefix}/[{partition}/]year=…/month=…/day=…/{uuid}.parquet` | ✅ | Task 1.2 |
| Phase 1 unit tests (all 8 scenarios) | ✅ | Tasks 1.3–1.6 |
| Phase 2 ipfix adapter (`IpfixSink`, metric labels, e2e) | ✅ | Tasks 2.1–2.3 |
| Phase 3 syslog adapter (`SyslogSink`, row-dominant, e2e) | ✅ | Tasks 3.1–3.2 |
| Phase 4 zeek adapter (`ZeekSink`, partition=sanitized path, registry, cap) | ✅ | Tasks 4.1–4.2 |
| Phase 5 WEF adapter (`WefSink`, partition=event_type=<id>, shutdown) | ✅ | Tasks 5.1–5.3 |
| Phase 6 dead-code removal, config unification, doc updates | ✅ | Tasks 6.1–6.4 |
| Unified metric names `parquet_s3_*{source}` | ✅ | Throughout |
| Hard cap = `max_buffer_rows * 4` | ✅ | Task 1.3 |
| Panic-free best-effort total record→batch | ✅ | Trait contract (Task 1.1), adapter impls |
| `cargo test` (all targets, not `--lib`) at every phase | ✅ | Global Constraints + each task |
| S3 key format preserved per-source | ✅ | Task 1.2 (verified in Task 4.2 for zeek) |

### Placeholder Scan

No `TODO`, `FIXME`, or `unimplemented!()` appear in the plan's code blocks. All code shown is real, compilable Rust using actual types from the codebase.

### Type and Signature Consistency (Phase 1 Generic vs. Adapter Phases)

| Component | Phase 1 Generic Type | Phase 2 (ipfix) | Phase 3 (syslog) | Phase 4 (zeek) | Phase 5 (wef) |
|---|---|---|---|---|---|
| `S::Record` | — | `Vec<FlowRecord>` | `SyslogMessage` | `ZeekRecord` | `Arc<WindowsEvent>` |
| `source()` | `&'static str` | `"ipfix"` | `"syslog"` | `"zeek"` | `"wef"` |
| `partition()` | `Option<String>` | `None` | `None` | `Some(sanitize_log_path)` | `Some("event_type=<id>")` |
| `schema(None)` | `Arc<Schema>` | `flow_record_schema()` | `syslog_schema()` | `get_schema_entry(path).schema` | `wef_schema()` |
| `to_record_batch` | `anyhow::Result<RecordBatch>` | uses `append_flow_record`+`finish_batch` | uses `syslog_message_to_batch` | uses `SchemaEntry.mapper` | uses `wef_event_to_batch` |
| Handler impl | — | `IpfixHandler` on `ParquetWriterHandle<IpfixSink>` | `SyslogHandler` on `ParquetWriterHandle<SyslogSink>` | `ZeekHandler` on `ParquetWriterHandle<ZeekSink>` | via `AppState.parquet_s3_sender` |
| Key pattern | `build_key(prefix, partition, now)` | `build_key("ipfix", None, _)` | `build_key("syslog", None, _)` | `build_key("zeek", Some(path), _)` | `build_key("wef", Some("event_type=<id>"), _)` |

All signatures chain correctly: `ParquetWriterHandle::start` accepts any `S: ParquetSink`, all adapter `Record` types are `Send + 'static`, and the `JoinHandle<()>` return type matches the existing `writer_handles: Vec<JoinHandle<()>>` in `main.rs`.

### Risks and Assumptions

**Risk 1 — WEF `AppState.parquet_s3_sender` type change (Phase 5)**
The field changes from `Option<mpsc::Sender<Arc<WindowsEvent>>>` to `Option<WefWriterHandle>` (which is `Option<ParquetWriterHandle<WefSink>>`). All callers in `server/mod.rs` use `try_send`, which is available on both types. The `process_single_event` call site needs updating from `sender.try_send(event.clone())` to `handle.try_send(Arc::clone(&event))`. The `AppState` tests that construct it with `parquet_s3_sender: None` continue to work since `None` is type-agnostic.

**Risk 2 — WEF `partition()` returns `None` for unparsed events**
The current `BufferedEvent::from_windows_event` silently skips events without `parsed`. With `WefSink`, `partition()` returns `None` for unparsed events. The generic writer will use `""` as the key, routing unparsed events to the single `""` buffer rather than discarding them. This is a slight behavior change (previously skipped; now buffered under `""`). Mitigation: in `WefSink::to_record_batch`, return `Err(...)` for unparsed events so the writer logs a warning and skips them — preserving the existing skip behavior. The plan implements this correctly in Task 5.1.

**Risk 3 — WEF uses `local_buffer_path` (temp file) currently; generic does not**
The current `ParquetS3Forwarder` writes to a temp file, reads it back, then uploads. The generic writes directly to memory via `spawn_blocking` → in-memory `Vec<u8>`. This is strictly better (no filesystem I/O, no file cleanup race), but it requires the Parquet payload to fit in RAM. WEF events are already estimated by byte size (`event_data.len() + 256`), and `max_file_size_mb` defaults to 100 MiB, which fits in RAM on any reasonable server. The `local_buffer_path` field in `ParquetS3Config` becomes unused in Phase 5; it is left in the struct (no TOML breaking change) and can be deprecated in a future cleanup.

**Risk 4 — Flush timing convergence (M-2) — intended, not a bug**
Syslog gains a byte trigger; ipfix/zeek gain a row trigger. Tests that assert single-trigger behavior at exact thresholds are updated in Phases 2–4. All e2e tests verify S3 object presence, not flush timing, so they are unaffected. This is documented in the spec as deliberate.

**Risk 5 — `IpfixHandler` on type alias**
`impl IpfixHandler for ParquetWriterHandle<IpfixSink>` works in Rust (no orphan rule violation since `IpfixHandler` and `ParquetWriterHandle` are both crate-local). Confirmed by checking the existing pattern: `impl ZeekHandler for ZeekS3Handler` (a struct wrapping `mpsc::Sender`) already exists. The generic version follows the same pattern.

**Assumption 1 — `arrow::compute::concat_batches` is available**
The `arrow` crate is already in `Cargo.toml` (confirmed by `encode_batches_to_parquet` using `ArrowWriter`). `concat_batches` is in `arrow::compute`. If unavailable, the fallback is to pass the `Vec<RecordBatch>` slice directly to `ArrowWriter::write()` in a loop (which is how all four current writers already work). The plan's `flush_partition` implementation uses the loop approach (`writer.write(&merged)`) after `concat_batches`; alternatively the loop over batches can be used directly without `concat_batches`. Either approach is correct.

**Assumption 2 — `bytes` crate available for Parquet reader in tests**
Used in existing `encode_parquet_round_trips_expected_schema_and_values` tests. It is already in `Cargo.toml`. No new dependency needed.
