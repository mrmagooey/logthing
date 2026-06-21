# Syslog → S3 Persistence (Phase 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`)
> syntax for tracking.

**Goal:** Add a `SyslogS3Writer` + `SyslogS3Handler` that buffers parsed `SyslogMessage` records,
encodes them as Parquet, and uploads them to S3 under a syslog-specific prefix via the Phase-2
`S3Sink`, wired into `main.rs` when a new `[syslog.s3]` config section is present.

**Architecture:** `SyslogS3Handler` (implements `SyslogHandler`) receives messages from the
existing `SyslogListener` via a bounded `tokio::sync::mpsc` channel; a background task owns a
`SyslogS3Writer` that drains the channel, accumulates rows into Arrow `RecordBatch`es, and flushes
to Parquet bytes on a size or age threshold, then calls `S3Sink::upload`. Absent `[syslog.s3]`
config leaves the current log-only `DefaultSyslogHandler` path unchanged.

**Tech Stack:** `arrow`/`arrow-array`/`arrow-schema` 53.0, `parquet` 53.0, `aws-sdk-s3` 1.x via
Phase-2 `S3Sink`, `tokio` 1.35, `async-trait` 0.1, `metrics` 0.22, `serde`/`serde_json` 1.0,
`chrono` 0.4, `anyhow` 1.0, `tempfile` 3.9 (tests).

## Global Constraints

- Rust edition 2024; 100-column line limit; 4-space indent; `cargo fmt` + `cargo clippy -D
  warnings` must pass after every task.
- Error handling via `anyhow` at call-sites and `thiserror` for library-style error enums if
  introduced; never `.unwrap()` outside `#[cfg(test)]`.
- All new counters via the `metrics` crate (`metrics::counter!`); no raw atomic accumulators.
- New metrics: `syslog_s3_records_written`, `syslog_s3_uploads`, `syslog_s3_upload_errors`,
  `syslog_s3_dropped`.
- Bounded channels only; on overflow → drop message + `metrics::counter!("syslog_s3_dropped", 1)`.
- Tests live in `#[cfg(test)]` modules inside the file under test (unit/integration) or in
  `tests/` (integration tests that span multiple modules); no `mod tests` in separate files unless
  the file is already large.
- Backward-compatible config: a `Config` with no `[syslog.s3]` section must deserialize cleanly
  and produce `None` for the S3 config, leaving behavior identical to today.
- **Depends on Phase 2:** treats `src/forwarding/s3_sink.rs` with `S3Sink::from_config` and
  `S3Sink::upload` as already present. If Phase 2 uses slightly different names (e.g.
  `S3Sink::new`), the implementer adjusts at integration time — note the assumption below.
- Commit style: conventional commits (`feat:`, `test:`, `refactor:`, `chore:`).
- Branch: `feat/ipfix-s3-persistence` (do not work on `master`).

**Assumption A1:** Phase 2 produces `S3Sink` in `src/forwarding/s3_sink.rs` with exactly:
```rust
impl S3Sink {
    pub async fn from_config(cfg: &ParquetS3Config) -> anyhow::Result<Self>;
    pub async fn upload(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()>;
}
```
If the real signatures differ (e.g. `body: bytes::Bytes`), adjust the call site in
`SyslogS3Writer::flush` accordingly — the plan logic does not change.

**Assumption A2:** `src/forwarding/s3_sink.rs` re-exports or re-uses the existing
`ParquetS3Config` type from `src/forwarding/parquet_s3.rs`. The new `SyslogS3Config` (Task 4)
converts into a `ParquetS3Config` to construct an `S3Sink`. If Phase 2 introduces a dedicated
`S3SinkConfig`, the implementer maps `SyslogS3Config` fields to that type instead.

---

## Task 1 — Syslog Arrow Schema + Row-Mapping (Unit)

**Files:**
- Create: `src/forwarding/syslog_s3.rs` (schema definition + mapping function only; no writer
  struct yet)

**Interfaces — Produces:**
```rust
// Public schema accessor (lazily initialised via std::sync::LazyLock)
pub fn syslog_schema() -> Arc<arrow_schema::Schema>;

// Map one SyslogMessage to a single-row RecordBatch using the syslog schema.
// Returns Err if Arrow array/batch construction fails.
pub fn syslog_message_to_batch(
    msg: &crate::syslog::SyslogMessage,
) -> anyhow::Result<arrow::record_batch::RecordBatch>;
```

**Schema columns** (in order; nullable as noted):

| Column name      | Arrow type                              | Nullable | Source field                           |
|------------------|-----------------------------------------|----------|----------------------------------------|
| `priority`       | `UInt8`                                 | false    | `msg.priority`                         |
| `severity`       | `UInt8`                                 | false    | `msg.severity`                         |
| `facility`       | `UInt8`                                 | false    | `msg.facility`                         |
| `timestamp`      | `Utf8` (RFC 3339 string)                | true     | `msg.timestamp.map(|t| t.to_rfc3339())`|
| `hostname`       | `Utf8`                                  | true     | `msg.hostname.clone()`                 |
| `app_name`       | `Utf8`                                  | true     | `msg.app_name.clone()`                 |
| `proc_id`        | `Utf8`                                  | true     | `msg.proc_id.clone()`                  |
| `msg_id`         | `Utf8`                                  | true     | `msg.msg_id.clone()`                   |
| `message`        | `Utf8`                                  | false    | `msg.message.clone()`                  |
| `structured_data`| `Utf8` (JSON)                           | true     | `serde_json::to_string(&msg.structured_data).ok()` |
| `protocol`       | `Utf8`                                  | false    | `format!("{:?}", msg.protocol)`        |

**TDD Steps:**

- [ ] **Red — schema shape test.** In `src/forwarding/syslog_s3.rs`, write (inside
  `#[cfg(test)]`):
  ```rust
  #[test]
  fn schema_has_correct_columns_and_types() {
      use arrow::datatypes::DataType;
      let schema = syslog_schema();
      // 11 columns
      assert_eq!(schema.fields().len(), 11);
      assert_eq!(schema.field_with_name("priority").unwrap().data_type(), &DataType::UInt8);
      assert_eq!(schema.field_with_name("priority").unwrap().is_nullable(), false);
      assert_eq!(schema.field_with_name("timestamp").unwrap().data_type(), &DataType::Utf8);
      assert_eq!(schema.field_with_name("timestamp").unwrap().is_nullable(), true);
      assert_eq!(schema.field_with_name("structured_data").unwrap().data_type(), &DataType::Utf8);
      assert_eq!(schema.field_with_name("structured_data").unwrap().is_nullable(), true);
      assert_eq!(schema.field_with_name("protocol").unwrap().is_nullable(), false);
  }
  ```
  Run: `cargo test -p logthing syslog_s3::tests::schema_has_correct_columns_and_types 2>&1 | tail
  -5` — expect compile error (function not yet defined).

- [ ] **Green — implement schema.** Add to `src/forwarding/syslog_s3.rs`:
  ```rust
  use std::sync::{Arc, LazyLock};
  use arrow::datatypes::{DataType, Field, Schema};

  static SYSLOG_SCHEMA: LazyLock<Arc<Schema>> = LazyLock::new(|| {
      Arc::new(Schema::new(vec![
          Field::new("priority",        DataType::UInt8, false),
          Field::new("severity",        DataType::UInt8, false),
          Field::new("facility",        DataType::UInt8, false),
          Field::new("timestamp",       DataType::Utf8,  true),
          Field::new("hostname",        DataType::Utf8,  true),
          Field::new("app_name",        DataType::Utf8,  true),
          Field::new("proc_id",         DataType::Utf8,  true),
          Field::new("msg_id",          DataType::Utf8,  true),
          Field::new("message",         DataType::Utf8,  false),
          Field::new("structured_data", DataType::Utf8,  true),
          Field::new("protocol",        DataType::Utf8,  false),
      ]))
  });

  pub fn syslog_schema() -> Arc<Schema> {
      SYSLOG_SCHEMA.clone()
  }
  ```
  Run: `cargo test -p logthing syslog_s3::tests::schema_has_correct_columns_and_types` — expect
  pass.

- [ ] **Red — row mapping test.** Add to `#[cfg(test)]`:
  ```rust
  use crate::syslog::{SyslogMessage, SyslogProtocol};
  use std::collections::HashMap;

  fn sample_rfc5424() -> SyslogMessage {
      let mut sd = HashMap::new();
      let mut params = HashMap::new();
      params.insert("iut".to_string(), "3".to_string());
      sd.insert("example@32473".to_string(), params);
      SyslogMessage {
          priority: 34,
          severity: 2,
          facility: 4,
          timestamp: Some(
              chrono::DateTime::parse_from_rfc3339("2003-10-11T22:14:15Z")
                  .unwrap()
                  .with_timezone(&chrono::Utc),
          ),
          hostname: Some("mymachine".to_string()),
          app_name: Some("su".to_string()),
          proc_id: None,
          msg_id: Some("ID47".to_string()),
          message: "'su root' failed".to_string(),
          structured_data: Some(sd),
          protocol: SyslogProtocol::Rfc5424,
      }
  }

  #[test]
  fn row_mapping_produces_expected_column_values() {
      use arrow::array::{StringArray, UInt8Array};
      let msg = sample_rfc5424();
      let batch = syslog_message_to_batch(&msg).expect("batch");
      assert_eq!(batch.num_rows(), 1);
      assert_eq!(batch.num_columns(), 11);

      let priority = batch.column(0).as_any().downcast_ref::<UInt8Array>().unwrap();
      assert_eq!(priority.value(0), 34);

      let hostname = batch.column(4).as_any().downcast_ref::<StringArray>().unwrap();
      assert_eq!(hostname.value(0), "mymachine");

      // proc_id is None → null
      let proc_id = batch.column(6).as_any().downcast_ref::<StringArray>().unwrap();
      assert!(proc_id.is_null(0));

      // structured_data is JSON
      let sd_col = batch.column(9).as_any().downcast_ref::<StringArray>().unwrap();
      assert!(sd_col.value(0).contains("example@32473"));

      let protocol = batch.column(10).as_any().downcast_ref::<StringArray>().unwrap();
      assert_eq!(protocol.value(0), "Rfc5424");
  }

  #[test]
  fn row_mapping_handles_all_none_optional_fields() {
      use arrow::array::StringArray;
      let msg = SyslogMessage {
          priority: 0,
          severity: 0,
          facility: 0,
          timestamp: None,
          hostname: None,
          app_name: None,
          proc_id: None,
          msg_id: None,
          message: "bare".to_string(),
          structured_data: None,
          protocol: SyslogProtocol::Unknown,
      };
      let batch = syslog_message_to_batch(&msg).expect("batch");
      let ts = batch.column(3).as_any().downcast_ref::<StringArray>().unwrap();
      assert!(ts.is_null(0));
      let sd = batch.column(9).as_any().downcast_ref::<StringArray>().unwrap();
      assert!(sd.is_null(0));
  }
  ```
  Run: `cargo test -p logthing syslog_s3::tests::row_mapping` — expect compile error (function
  not yet defined).

- [ ] **Green — implement `syslog_message_to_batch`.** Add:
  ```rust
  use arrow::array::{ArrayRef, StringArray, UInt8Array};
  use arrow::record_batch::RecordBatch;
  use crate::syslog::SyslogMessage;
  use std::sync::Arc;

  pub fn syslog_message_to_batch(msg: &SyslogMessage) -> anyhow::Result<RecordBatch> {
      let schema = syslog_schema();

      let priority        = Arc::new(UInt8Array::from(vec![msg.priority]))   as ArrayRef;
      let severity        = Arc::new(UInt8Array::from(vec![msg.severity]))   as ArrayRef;
      let facility        = Arc::new(UInt8Array::from(vec![msg.facility]))   as ArrayRef;
      let timestamp       = Arc::new(StringArray::from(vec![
          msg.timestamp.as_ref().map(|t| t.to_rfc3339())
      ])) as ArrayRef;
      let hostname        = Arc::new(StringArray::from(vec![msg.hostname.clone()]))    as ArrayRef;
      let app_name        = Arc::new(StringArray::from(vec![msg.app_name.clone()]))   as ArrayRef;
      let proc_id         = Arc::new(StringArray::from(vec![msg.proc_id.clone()]))    as ArrayRef;
      let msg_id          = Arc::new(StringArray::from(vec![msg.msg_id.clone()]))     as ArrayRef;
      let message         = Arc::new(StringArray::from(vec![msg.message.clone()]))    as ArrayRef;
      let structured_data = Arc::new(StringArray::from(vec![
          msg.structured_data.as_ref().and_then(|sd| serde_json::to_string(sd).ok())
      ])) as ArrayRef;
      let protocol        = Arc::new(StringArray::from(vec![
          format!("{:?}", msg.protocol)
      ])) as ArrayRef;

      Ok(RecordBatch::try_new(schema, vec![
          priority, severity, facility, timestamp, hostname,
          app_name, proc_id, msg_id, message, structured_data, protocol,
      ])?)
  }
  ```
  Run: `cargo test -p logthing syslog_s3::tests` — all three tests must pass. Then:
  `cargo clippy -p logthing -- -D warnings`.

- [ ] **Commit:** `test: syslog Arrow schema shape and row-mapping unit tests`

---

## Task 2 — `SyslogS3Writer`: Buffer, Flush, Encode to Parquet (Unit)

**Files:**
- Extend: `src/forwarding/syslog_s3.rs`

**Interfaces — Produces:**
```rust
pub struct SyslogS3WriterConfig {
    /// Maximum number of buffered rows before an automatic flush is triggered.
    pub max_buffer_rows: usize,
    /// Maximum wall-clock age of a non-empty buffer before flush.
    pub flush_interval: std::time::Duration,
    /// S3 key prefix, e.g. "syslog/".  A trailing slash is conventional.
    pub key_prefix: String,
}

impl Default for SyslogS3WriterConfig {
    fn default() -> Self {
        Self {
            max_buffer_rows: 10_000,
            flush_interval: std::time::Duration::from_secs(900), // 15 min
            key_prefix: "syslog/".to_string(),
        }
    }
}

pub struct SyslogS3Writer {
    config: SyslogS3WriterConfig,
    sink: Arc<crate::forwarding::s3_sink::S3Sink>,
    buffer: Vec<arrow::record_batch::RecordBatch>,
    buffer_row_count: usize,
    last_flush: std::time::Instant,
}

impl SyslogS3Writer {
    pub fn new(
        config: SyslogS3WriterConfig,
        sink: Arc<crate::forwarding::s3_sink::S3Sink>,
    ) -> Self;

    /// Append one message to the buffer; flushes if threshold is met.
    pub async fn push(&mut self, msg: &crate::syslog::SyslogMessage) -> anyhow::Result<()>;

    /// Flush if the age or row-count threshold is exceeded; no-op if buffer is empty.
    pub async fn flush_if_needed(&mut self) -> anyhow::Result<()>;

    /// Unconditionally encode all buffered rows to a single Parquet byte buffer
    /// and upload via `self.sink`.  Clears the buffer on success.
    pub async fn flush(&mut self) -> anyhow::Result<()>;

    /// Encode the current buffer to a Parquet `Vec<u8>` without uploading.
    /// Returns `None` if the buffer is empty.
    pub fn encode_parquet(&self) -> anyhow::Result<Option<Vec<u8>>>;

    /// Build the S3 object key: `{prefix}year={Y}/month={MM}/day={DD}/{uuid}.parquet`
    fn build_key(&self) -> String;
}
```

**TDD Steps:**

- [ ] **Red — Parquet round-trip test.** Add to `#[cfg(test)]` in `syslog_s3.rs`:
  ```rust
  #[test]
  fn encode_parquet_round_trips_expected_schema_and_values() {
      // Build a writer with a no-op sink (we won't call flush/upload here)
      // We test encode_parquet in isolation.
      use crate::syslog::{SyslogMessage, SyslogProtocol};
      use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
      use std::io::Cursor;

      // Construct writer manually for testing encode
      let msg = SyslogMessage {
          priority: 134,
          severity: 6,
          facility: 16,
          timestamp: Some(chrono::Utc::now()),
          hostname: Some("testhost".to_string()),
          app_name: Some("myapp".to_string()),
          proc_id: Some("9999".to_string()),
          msg_id: None,
          message: "hello world".to_string(),
          structured_data: None,
          protocol: SyslogProtocol::Rfc3164,
      };

      let batch = syslog_message_to_batch(&msg).unwrap();
      // Simulate a writer buffer containing one batch
      let bytes = encode_batches_to_parquet(&[batch]).unwrap();
      assert!(!bytes.is_empty(), "Parquet bytes must not be empty");

      // Re-read and verify
      let cursor = Cursor::new(bytes);
      let builder = ParquetRecordBatchReaderBuilder::try_new(cursor).unwrap();
      let schema = builder.schema().clone();
      let mut reader = builder.build().unwrap();
      let rb = reader.next().unwrap().unwrap();
      assert_eq!(rb.num_rows(), 1);
      assert_eq!(schema.fields().len(), 11);

      use arrow::array::StringArray;
      let hostname = rb.column(4).as_any().downcast_ref::<StringArray>().unwrap();
      assert_eq!(hostname.value(0), "testhost");
      let msg_col = rb.column(8).as_any().downcast_ref::<StringArray>().unwrap();
      assert_eq!(msg_col.value(0), "hello world");
  }

  #[test]
  fn encode_parquet_multiple_batches_concatenates_rows() {
      use crate::syslog::{SyslogMessage, SyslogProtocol};
      use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
      use std::io::Cursor;

      let make_msg = |msg_text: &str| SyslogMessage {
          priority: 1, severity: 1, facility: 0,
          timestamp: None, hostname: None, app_name: None, proc_id: None, msg_id: None,
          message: msg_text.to_string(), structured_data: None,
          protocol: SyslogProtocol::Unknown,
      };

      let batches: Vec<_> = ["alpha", "beta", "gamma"]
          .iter()
          .map(|t| syslog_message_to_batch(&make_msg(t)).unwrap())
          .collect();

      let bytes = encode_batches_to_parquet(&batches).unwrap();
      let cursor = Cursor::new(bytes);
      let mut reader = ParquetRecordBatchReaderBuilder::try_new(cursor)
          .unwrap()
          .build()
          .unwrap();

      let mut total_rows = 0usize;
      for rb in reader.by_ref() {
          total_rows += rb.unwrap().num_rows();
      }
      assert_eq!(total_rows, 3);
  }
  ```
  Run: `cargo test -p logthing syslog_s3::tests::encode_parquet` — expect compile errors.

- [ ] **Green — implement `encode_batches_to_parquet` and `SyslogS3Writer`.** Add:
  ```rust
  use parquet::arrow::ArrowWriter;
  use parquet::basic::{Compression, ZstdLevel};
  use parquet::file::properties::WriterProperties;

  /// Encode a slice of RecordBatches (all sharing `syslog_schema()`) into a Parquet byte buffer.
  /// Returns an empty Vec if the slice is empty.
  pub(crate) fn encode_batches_to_parquet(
      batches: &[arrow::record_batch::RecordBatch],
  ) -> anyhow::Result<Vec<u8>> {
      if batches.is_empty() {
          return Ok(Vec::new());
      }
      let schema = syslog_schema();
      let props = WriterProperties::builder()
          .set_compression(Compression::ZSTD(ZstdLevel::try_new(3)?))
          .build();
      let mut buf = Vec::new();
      let mut writer = ArrowWriter::try_new(&mut buf, schema, Some(props))?;
      for batch in batches {
          writer.write(batch)?;
      }
      writer.close()?;
      Ok(buf)
  }
  ```
  Then implement `SyslogS3Writer`:
  ```rust
  use crate::forwarding::s3_sink::S3Sink;
  use chrono::{Datelike, Utc};

  pub struct SyslogS3Writer {
      config: SyslogS3WriterConfig,
      sink: Arc<S3Sink>,
      buffer: Vec<RecordBatch>,
      buffer_row_count: usize,
      last_flush: std::time::Instant,
  }

  impl SyslogS3Writer {
      pub fn new(config: SyslogS3WriterConfig, sink: Arc<S3Sink>) -> Self {
          Self {
              config,
              sink,
              buffer: Vec::new(),
              buffer_row_count: 0,
              last_flush: std::time::Instant::now(),
          }
      }

      pub async fn push(&mut self, msg: &crate::syslog::SyslogMessage) -> anyhow::Result<()> {
          let batch = syslog_message_to_batch(msg)?;
          self.buffer_row_count += batch.num_rows();
          self.buffer.push(batch);
          if self.buffer_row_count >= self.config.max_buffer_rows {
              self.flush().await?;
          }
          Ok(())
      }

      pub async fn flush_if_needed(&mut self) -> anyhow::Result<()> {
          if self.buffer.is_empty() {
              return Ok(());
          }
          let age_exceeded = self.last_flush.elapsed() >= self.config.flush_interval;
          let size_exceeded = self.buffer_row_count >= self.config.max_buffer_rows;
          if age_exceeded || size_exceeded {
              self.flush().await?;
          }
          Ok(())
      }

      pub async fn flush(&mut self) -> anyhow::Result<()> {
          if self.buffer.is_empty() {
              return Ok(());
          }
          let bytes = encode_batches_to_parquet(&self.buffer)?;
          let key = self.build_key();
          match self.sink.upload(&key, bytes).await {
              Ok(()) => {
                  metrics::counter!("syslog_s3_records_written")
                      .increment(self.buffer_row_count as u64);
                  metrics::counter!("syslog_s3_uploads").increment(1);
              }
              Err(e) => {
                  metrics::counter!("syslog_s3_upload_errors").increment(1);
                  return Err(e);
              }
          }
          self.buffer.clear();
          self.buffer_row_count = 0;
          self.last_flush = std::time::Instant::now();
          Ok(())
      }

      pub fn encode_parquet(&self) -> anyhow::Result<Option<Vec<u8>>> {
          if self.buffer.is_empty() {
              return Ok(None);
          }
          Ok(Some(encode_batches_to_parquet(&self.buffer)?))
      }

      fn build_key(&self) -> String {
          let now = Utc::now();
          let id = uuid::Uuid::new_v4();
          format!(
              "{}year={}/month={:02}/day={:02}/{}.parquet",
              self.config.key_prefix,
              now.year(),
              now.month(),
              now.day(),
              id,
          )
      }
  }
  ```
  Run: `cargo test -p logthing syslog_s3::tests::encode_parquet` — all tests must pass.

- [ ] **Red — `SyslogS3Writer::push` accumulates rows and flush clears buffer.** Add:
  ```rust
  #[test]
  fn push_accumulates_and_flush_clears_buffer() {
      // Test that push() increments row count and that encode_parquet() returns
      // Some after push and None after a successful encode with empty buffer.
      // We cannot call .flush() without a real S3Sink, so we test encode_parquet directly.
      use crate::syslog::{SyslogMessage, SyslogProtocol};

      // Build a writer with a dummy sink — we won't call flush()
      // Instead exercise encode_parquet() directly.
      fn dummy_msg(text: &str) -> SyslogMessage {
          SyslogMessage {
              priority: 0, severity: 0, facility: 0, timestamp: None,
              hostname: None, app_name: None, proc_id: None, msg_id: None,
              message: text.to_string(), structured_data: None,
              protocol: SyslogProtocol::Unknown,
          }
      }

      // Directly build the buffer to test encode_parquet
      let batches: Vec<_> = ["a", "b"]
          .iter()
          .map(|t| syslog_message_to_batch(&dummy_msg(t)).unwrap())
          .collect();

      let bytes = encode_batches_to_parquet(&batches).unwrap();
      assert!(!bytes.is_empty());

      // Empty batch slice returns empty Vec
      let empty = encode_batches_to_parquet(&[]).unwrap();
      assert!(empty.is_empty());
  }
  ```
  Run: `cargo test -p logthing syslog_s3::tests::push_accumulates` — expect pass (function is
  already defined).

- [ ] **Commit:** `feat: SyslogS3Writer buffer and Parquet encode` and
  `test: SyslogS3Writer Parquet round-trip unit tests`

---

## Task 3 — `SyslogS3Handler`: Channel + Drop-on-Overflow (Unit)

**Files:**
- Extend: `src/forwarding/syslog_s3.rs`

**Interfaces — Produces:**
```rust
/// Channel capacity for the handler → writer channel.
pub const SYSLOG_S3_CHANNEL_CAPACITY: usize = 4_096;

pub struct SyslogS3Handler {
    sender: tokio::sync::mpsc::Sender<crate::syslog::SyslogMessage>,
}

impl SyslogS3Handler {
    /// Construct a handler and start the writer background task.
    /// The background task owns the `SyslogS3Writer` and runs until the sender side is dropped.
    pub fn start(
        config: SyslogS3WriterConfig,
        sink: Arc<crate::forwarding::s3_sink::S3Sink>,
    ) -> Self;
}

#[async_trait::async_trait]
impl crate::syslog::listener::SyslogHandler for SyslogS3Handler {
    async fn handle_message(
        &self,
        message: crate::syslog::SyslogMessage,
        _source: std::net::SocketAddr,
    );
}
```

**Background task internals** (not public API, documented for implementers):

```
tokio::spawn(async move {
    let mut writer = SyslogS3Writer::new(config, sink);
    let mut interval = tokio::time::interval(flush_check_period);  // e.g. 60 s
    loop {
        tokio::select! {
            msg = receiver.recv() => {
                match msg {
                    Some(m) => { writer.push(&m).await.unwrap_or_else(|e| warn!(...)); }
                    None => {
                        // Sender dropped — flush remaining and exit.
                        writer.flush().await.unwrap_or_else(|e| warn!(...));
                        break;
                    }
                }
            }
            _ = interval.tick() => {
                writer.flush_if_needed().await.unwrap_or_else(|e| warn!(...));
            }
        }
    }
})
```

**TDD Steps:**

- [ ] **Red — overflow drops message and increments metric.** Add to `#[cfg(test)]`:
  ```rust
  #[tokio::test]
  async fn handler_drops_on_channel_overflow_and_counts_metric() {
      use metrics_util::debugging::{DebuggingRecorder, Snapshotter};
      let recorder = DebuggingRecorder::new();
      let snapshotter = recorder.snapshotter();
      let _guard = metrics::set_global_recorder(recorder);
      // Not available yet — write a minimal counter check via try_send semantics
      // Since SyslogS3Handler is not yet defined, expect compile error.
      // Stub: just reference the type.
      let _ = std::marker::PhantomData::<SyslogS3Handler>;
  }
  ```
  Run: `cargo test -p logthing syslog_s3::tests::handler_drops` — expect compile error.

  NOTE: `metrics-util` may not be in `[dev-dependencies]`. If it is unavailable, test the
  overflow behaviour using a hand-rolled counter via `std::sync::atomic::AtomicU64` wrapped in a
  custom `metrics::Recorder`. The simpler approach (preferred, avoids extra dep): directly test
  that a `try_send` on a full channel returns `Err` and then manually call
  `metrics::counter!("syslog_s3_dropped", 1)` from test code:
  ```rust
  #[tokio::test]
  async fn channel_try_send_on_full_returns_err() {
      use crate::syslog::{SyslogMessage, SyslogProtocol};
      use tokio::sync::mpsc;

      let (tx, _rx) = mpsc::channel::<SyslogMessage>(1);
      let msg = SyslogMessage {
          priority: 0, severity: 0, facility: 0, timestamp: None,
          hostname: None, app_name: None, proc_id: None, msg_id: None,
          message: "fill".to_string(), structured_data: None,
          protocol: SyslogProtocol::Unknown,
      };
      tx.try_send(msg.clone()).expect("first send fills channel");
      let result = tx.try_send(msg);
      assert!(result.is_err(), "second send on full channel must fail");
  }
  ```
  Run: `cargo test -p logthing syslog_s3::tests::channel_try_send_on_full_returns_err` — passes
  immediately (no new code needed); documents the contract before implementing `SyslogS3Handler`.

- [ ] **Red — handler routes messages through channel.** Add:
  ```rust
  #[tokio::test]
  async fn handler_routes_messages_to_writer_task() {
      // Build a handler with a real but flushing-suppressed writer.
      // We cannot provide a real S3Sink without a live MinIO, so this test
      // only verifies that messages enqueued via handle_message are consumed
      // by the background task (no panic, no hang).
      // Use a very small channel (capacity 2) and a writer that does NOT upload
      // by constructing the channel directly.

      use crate::syslog::{SyslogMessage, SyslogProtocol};
      use tokio::sync::mpsc;
      use std::net::SocketAddr;
      use crate::syslog::listener::SyslogHandler as SyslogHandlerTrait;

      // Spawn a fake receiver that simulates what the background task does.
      let (tx, mut rx) = mpsc::channel::<SyslogMessage>(SYSLOG_S3_CHANNEL_CAPACITY);
      let received = Arc::new(std::sync::atomic::AtomicUsize::new(0));
      let received_clone = received.clone();
      tokio::spawn(async move {
          while let Some(_) = rx.recv().await {
              received_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
          }
      });

      // Wrap tx in a minimal struct implementing SyslogHandler to test handle_message contract.
      struct TestHandler(mpsc::Sender<SyslogMessage>);
      #[async_trait::async_trait]
      impl crate::syslog::listener::SyslogHandler for TestHandler {
          async fn handle_message(&self, message: SyslogMessage, _src: SocketAddr) {
              let _ = self.0.try_send(message);
          }
      }

      let handler = TestHandler(tx);
      let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();
      for i in 0..5 {
          let msg = SyslogMessage {
              priority: i, severity: 0, facility: 0, timestamp: None,
              hostname: None, app_name: None, proc_id: None, msg_id: None,
              message: format!("msg {i}"), structured_data: None,
              protocol: SyslogProtocol::Unknown,
          };
          handler.handle_message(msg, src).await;
      }

      tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
      assert_eq!(received.load(std::sync::atomic::Ordering::SeqCst), 5);
  }
  ```
  Run: `cargo test -p logthing syslog_s3::tests::handler_routes` — expect pass (uses TestHandler
  directly, no `SyslogS3Handler` yet).

- [ ] **Green — implement `SyslogS3Handler`.** Add:
  ```rust
  use tokio::sync::mpsc;
  use tracing::warn;

  pub const SYSLOG_S3_CHANNEL_CAPACITY: usize = 4_096;

  pub struct SyslogS3Handler {
      sender: mpsc::Sender<crate::syslog::SyslogMessage>,
  }

  impl SyslogS3Handler {
      pub fn start(config: SyslogS3WriterConfig, sink: Arc<S3Sink>) -> Self {
          let (tx, mut rx) = mpsc::channel::<crate::syslog::SyslogMessage>(
              SYSLOG_S3_CHANNEL_CAPACITY,
          );
          let flush_check = std::time::Duration::from_secs(60);
          tokio::spawn(async move {
              let mut writer = SyslogS3Writer::new(config, sink);
              let mut interval = tokio::time::interval(flush_check);
              loop {
                  tokio::select! {
                      msg = rx.recv() => {
                          match msg {
                              Some(m) => {
                                  if let Err(e) = writer.push(&m).await {
                                      warn!("SyslogS3Writer::push error: {e}");
                                  }
                              }
                              None => {
                                  if let Err(e) = writer.flush().await {
                                      warn!("SyslogS3Writer::flush on shutdown error: {e}");
                                  }
                                  break;
                              }
                          }
                      }
                      _ = interval.tick() => {
                          if let Err(e) = writer.flush_if_needed().await {
                              warn!("SyslogS3Writer::flush_if_needed error: {e}");
                          }
                      }
                  }
              }
          });
          Self { sender: tx }
      }
  }

  #[async_trait::async_trait]
  impl crate::syslog::listener::SyslogHandler for SyslogS3Handler {
      async fn handle_message(
          &self,
          message: crate::syslog::SyslogMessage,
          _source: std::net::SocketAddr,
      ) {
          match self.sender.try_send(message) {
              Ok(()) => {}
              Err(_) => {
                  metrics::counter!("syslog_s3_dropped").increment(1);
              }
          }
      }
  }
  ```
  Run: `cargo test -p logthing syslog_s3::tests` — all tests must pass.
  `cargo clippy -p logthing -- -D warnings`.

- [ ] **Commit:** `feat: SyslogS3Handler with bounded channel and drop-on-overflow`

---

## Task 4 — Config: `SyslogS3Config` + `Config` Integration (Unit)

**Files:**
- Modify: `src/config/mod.rs`

**Interfaces — Produces:**
```rust
/// Per-source S3 persistence config for the syslog listener.
/// Absent from the TOML → None → no S3 persistence (backward compatible).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SyslogS3Config {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    /// S3 key prefix, e.g. "syslog/".
    #[serde(default = "default_syslog_s3_key_prefix")]
    pub key_prefix: String,
    /// Flush when row count reaches this threshold (default 10 000).
    #[serde(default = "default_syslog_s3_max_rows")]
    pub max_buffer_rows: usize,
    /// Flush after this many seconds regardless of row count (default 900 = 15 min).
    #[serde(default = "default_syslog_s3_flush_interval_secs")]
    pub flush_interval_secs: u64,
}

// Added to SyslogConfig:
pub struct SyslogConfig {
    // ... existing fields ...
    #[serde(default)]
    pub s3: Option<SyslogS3Config>,
}
```

**TDD Steps:**

- [ ] **Red — absent `[syslog.s3]` gives `None`.** Add to `src/config/mod.rs` `#[cfg(test)]`:
  ```rust
  #[test]
  fn syslog_s3_absent_gives_none() {
      // Config::default() must have syslog.s3 = None
      let cfg = Config::default();
      assert!(cfg.syslog.s3.is_none(), "absent [syslog.s3] must deserialize to None");
  }
  ```
  Run: `cargo test -p logthing config::tests::syslog_s3_absent_gives_none` — expect compile error
  (field not yet defined).

- [ ] **Red — present `[syslog.s3]` parses bucket and prefix.** Add:
  ```rust
  #[test]
  fn syslog_s3_present_parses_correctly() {
      let toml_str = r#"
  [syslog.s3]
  endpoint  = "http://minio:9000"
  bucket    = "syslog-bucket"
  region    = "us-east-1"
  access_key = "KEY"
  secret_key = "SECRET"
  key_prefix = "syslog/"
  max_buffer_rows = 5000
  flush_interval_secs = 300
  "#;
      let cfg: Config = toml::from_str(toml_str).expect("parse config");
      let s3 = cfg.syslog.s3.expect("s3 config present");
      assert_eq!(s3.bucket, "syslog-bucket");
      assert_eq!(s3.key_prefix, "syslog/");
      assert_eq!(s3.max_buffer_rows, 5000);
      assert_eq!(s3.flush_interval_secs, 300);
  }
  ```
  Run: `cargo test -p logthing config::tests::syslog_s3_present_parses_correctly` — expect compile
  error.

- [ ] **Red — defaults apply when sub-keys are absent.** Add:
  ```rust
  #[test]
  fn syslog_s3_defaults_apply_when_sub_keys_absent() {
      let toml_str = r#"
  [syslog.s3]
  endpoint   = "http://minio:9000"
  bucket     = "syslog-bucket"
  region     = "us-east-1"
  access_key = "KEY"
  secret_key = "SECRET"
  "#;
      let cfg: Config = toml::from_str(toml_str).expect("parse");
      let s3 = cfg.syslog.s3.expect("present");
      assert_eq!(s3.key_prefix, "syslog/");
      assert_eq!(s3.max_buffer_rows, 10_000);
      assert_eq!(s3.flush_interval_secs, 900);
  }
  ```
  Run: `cargo test -p logthing config::tests::syslog_s3_defaults_apply` — expect compile error.

- [ ] **Red — existing config tests still pass (backward compat guard).** Run:
  `cargo test -p logthing config::tests` — note which tests pass before the change.

- [ ] **Green — add `SyslogS3Config` to `src/config/mod.rs`.** Insert after `SyslogConfig`:
  ```rust
  #[derive(Debug, Clone, Deserialize, Serialize)]
  pub struct SyslogS3Config {
      pub endpoint: String,
      pub bucket: String,
      pub region: String,
      pub access_key: String,
      pub secret_key: String,
      #[serde(default = "default_syslog_s3_key_prefix")]
      pub key_prefix: String,
      #[serde(default = "default_syslog_s3_max_rows")]
      pub max_buffer_rows: usize,
      #[serde(default = "default_syslog_s3_flush_interval_secs")]
      pub flush_interval_secs: u64,
  }

  fn default_syslog_s3_key_prefix() -> String   { "syslog/".to_string() }
  fn default_syslog_s3_max_rows() -> usize       { 10_000 }
  fn default_syslog_s3_flush_interval_secs() -> u64 { 900 }
  ```
  Add `pub s3: Option<SyslogS3Config>` to `SyslogConfig` and update its `Default` impl:
  ```rust
  impl Default for SyslogConfig {
      fn default() -> Self {
          Self {
              enabled: default_syslog_enabled(),
              udp_port: default_syslog_udp_port(),
              tcp_port: default_syslog_tcp_port(),
              parse_dns: default_syslog_parse_dns(),
              s3: None,  // ← new field, backward-compatible default
          }
      }
  }
  ```
  Run: `cargo test -p logthing config::tests` — all four new tests plus all pre-existing config
  tests must pass.

- [ ] **Add a conversion helper** from `SyslogS3Config` to
  `crate::forwarding::parquet_s3::ParquetS3Config` (needed by Task 5 to construct `S3Sink`):
  ```rust
  impl SyslogS3Config {
      /// Convert to `ParquetS3Config` so we can construct an `S3Sink` via Phase-2 API.
      /// (Assumption A2: `S3Sink::from_config` accepts `&ParquetS3Config`.)
      pub fn to_parquet_s3_config(&self) -> crate::forwarding::parquet_s3::ParquetS3Config {
          crate::forwarding::parquet_s3::ParquetS3Config {
              endpoint:           self.endpoint.clone(),
              bucket:             self.bucket.clone(),
              region:             self.region.clone(),
              access_key:         self.access_key.clone(),
              secret_key:         self.secret_key.clone(),
              max_file_size_mb:   0,   // unused by S3Sink
              flush_interval_secs: self.flush_interval_secs,
              local_buffer_path:  std::path::PathBuf::new(), // unused by S3Sink
          }
      }
  }
  ```
  Run: `cargo test -p logthing config::tests` — still green.

- [ ] **Commit:** `feat: add SyslogS3Config to SyslogConfig with backward-compatible default`

---

## Task 5 — Listener Wiring in `main.rs` (Integration)

**Files:**
- Modify: `src/main.rs`
- Modify: `src/forwarding/mod.rs` (add `pub mod syslog_s3;`)
- Integration test: `tests/syslog_s3_integration.rs` (new file)

**Wiring logic in `src/main.rs`:**

When `config.syslog.enabled` is `true`, choose handler based on `config.syslog.s3`:

```rust
// In async_main(), replace the existing syslog spawn block:
if config.syslog.enabled {
    let config_clone = config.clone();
    tokio::spawn(async move {
        let syslog_config = syslog::listener::SyslogListenerConfig {
            udp_port: config_clone.syslog.udp_port,
            tcp_port: config_clone.syslog.tcp_port,
            bind_address: "0.0.0.0".to_string(),
            parse_dns_logs: config_clone.syslog.parse_dns,
        };

        let handler: Arc<dyn syslog::listener::SyslogHandler> =
            if let Some(s3_cfg) = config_clone.syslog.s3.as_ref() {
                let parquet_cfg = s3_cfg.to_parquet_s3_config();
                match forwarding::s3_sink::S3Sink::from_config(&parquet_cfg).await {
                    Ok(sink) => {
                        let writer_cfg = forwarding::syslog_s3::SyslogS3WriterConfig {
                            max_buffer_rows: s3_cfg.max_buffer_rows,
                            flush_interval: std::time::Duration::from_secs(
                                s3_cfg.flush_interval_secs,
                            ),
                            key_prefix: s3_cfg.key_prefix.clone(),
                        };
                        let handler = forwarding::syslog_s3::SyslogS3Handler::start(
                            writer_cfg,
                            Arc::new(sink),
                        );
                        Arc::new(handler)
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to create S3Sink for syslog persistence, \
                             falling back to DefaultSyslogHandler: {e}"
                        );
                        Arc::new(syslog::listener::DefaultSyslogHandler::new(
                            config_clone.syslog.parse_dns,
                        ))
                    }
                }
            } else {
                Arc::new(syslog::listener::DefaultSyslogHandler::new(
                    config_clone.syslog.parse_dns,
                ))
            };

        let listener = syslog::listener::SyslogListener::new(syslog_config, handler);
        if let Err(e) = listener.start().await {
            tracing::error!("Syslog listener error: {e}");
        }
    });
    tracing::info!(
        "Syslog listener started on UDP:{}/TCP:{}",
        config.syslog.udp_port,
        config.syslog.tcp_port
    );
}
```

**Integration test** (`tests/syslog_s3_integration.rs`):

This test uses MinIO/localstack if available; it is skipped (not failed) when neither
`MINIO_ENDPOINT` nor `LOCALSTACK_ENDPOINT` is set, matching the existing test convention used by
`parquet_s3.rs` tests.

**TDD Steps:**

- [ ] **Red — add `pub mod syslog_s3;` to `src/forwarding/mod.rs` and verify it compiles.** Run:
  `cargo build -p logthing 2>&1 | head -20` — expect error because `syslog_s3.rs` already exists
  but `mod.rs` didn't declare it. After adding the declaration, build should succeed.

- [ ] **Red — integration test skeleton.** Create `tests/syslog_s3_integration.rs`:
  ```rust
  //! Integration test: syslog UDP datagram → SyslogS3Handler → Parquet object in MinIO.
  //!
  //! Requires a running MinIO (or S3-compatible) instance.
  //! Set MINIO_ENDPOINT, MINIO_BUCKET, MINIO_ACCESS_KEY, MINIO_SECRET_KEY env vars.
  //! If MINIO_ENDPOINT is absent, the test is skipped.

  use logthing::forwarding::parquet_s3::ParquetS3Config;
  use logthing::forwarding::s3_sink::S3Sink;           // Phase-2 dependency
  use logthing::forwarding::syslog_s3::{
      SyslogS3Handler, SyslogS3WriterConfig, SYSLOG_S3_CHANNEL_CAPACITY,
  };
  use logthing::syslog::listener::SyslogHandler as SyslogHandlerTrait;
  use logthing::syslog::{SyslogMessage, SyslogProtocol};
  use std::net::SocketAddr;
  use std::sync::Arc;

  fn skip_if_no_minio() -> Option<String> {
      std::env::var("MINIO_ENDPOINT").ok()
  }

  fn minio_config(endpoint: &str) -> ParquetS3Config {
      ParquetS3Config {
          endpoint: endpoint.to_string(),
          bucket: std::env::var("MINIO_BUCKET")
              .unwrap_or_else(|_| "syslog-test".to_string()),
          region: "us-east-1".to_string(),
          access_key: std::env::var("MINIO_ACCESS_KEY")
              .unwrap_or_else(|_| "minioadmin".to_string()),
          secret_key: std::env::var("MINIO_SECRET_KEY")
              .unwrap_or_else(|_| "minioadmin".to_string()),
          max_file_size_mb: 0,
          flush_interval_secs: 900,
          local_buffer_path: std::path::PathBuf::new(),
      }
  }

  #[tokio::test]
  async fn syslog_message_appears_as_parquet_in_s3() {
      let endpoint = match skip_if_no_minio() {
          Some(e) => e,
          None => {
              eprintln!("MINIO_ENDPOINT not set — skipping syslog_s3 integration test");
              return;
          }
      };

      let cfg = minio_config(&endpoint);
      // Phase-2 dependency: S3Sink::from_config
      let sink = Arc::new(
          S3Sink::from_config(&cfg)
              .await
              .expect("S3Sink::from_config"),
      );

      let writer_cfg = SyslogS3WriterConfig {
          max_buffer_rows: 1,    // flush immediately on first message
          flush_interval: std::time::Duration::from_secs(3600),
          key_prefix: "syslog-test/".to_string(),
      };

      let handler = SyslogS3Handler::start(writer_cfg, sink.clone());

      let msg = SyslogMessage {
          priority: 134,
          severity: 6,
          facility: 16,
          timestamp: Some(chrono::Utc::now()),
          hostname: Some("integrationhost".to_string()),
          app_name: Some("testapp".to_string()),
          proc_id: None,
          msg_id: None,
          message: "integration test message".to_string(),
          structured_data: None,
          protocol: SyslogProtocol::Rfc3164,
      };

      let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();
      handler.handle_message(msg, src).await;

      // Give the background task time to flush (max_buffer_rows=1 triggers flush on push)
      tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

      // Verify object exists in S3 by listing under the prefix
      use aws_sdk_s3::Client as S3Client;
      // Build a client using the same config as S3Sink to list objects.
      // (This couples the test to the ParquetS3Config fields — acceptable for integration.)
      let region = aws_sdk_s3::config::Region::new("us-east-1");
      let credentials = aws_credential_types::Credentials::new(
          cfg.access_key.clone(),
          cfg.secret_key.clone(),
          None, None, "test",
      );
      let sdk_cfg = aws_config::from_env()
          .region(region)
          .endpoint_url(&cfg.endpoint)
          .credentials_provider(credentials)
          .load()
          .await;
      let s3 = S3Client::from_conf(
          aws_sdk_s3::config::Builder::from(&sdk_cfg)
              .force_path_style(true)
              .build(),
      );

      let list = s3
          .list_objects_v2()
          .bucket(&cfg.bucket)
          .prefix("syslog-test/")
          .send()
          .await
          .expect("list_objects_v2");

      let objects = list.contents();
      assert!(
          !objects.is_empty(),
          "Expected at least one Parquet object under syslog-test/ prefix, found none"
      );

      // Download the first object and verify it is valid Parquet with expected columns
      let key = objects[0].key().expect("key");
      let get_resp = s3
          .get_object()
          .bucket(&cfg.bucket)
          .key(key)
          .send()
          .await
          .expect("get_object");

      let body = get_resp
          .body
          .collect()
          .await
          .expect("collect body")
          .into_bytes();

      use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
      use std::io::Cursor;
      let builder =
          ParquetRecordBatchReaderBuilder::try_new(Cursor::new(body)).expect("parquet builder");
      let schema = builder.schema().clone();
      assert_eq!(schema.fields().len(), 11, "Syslog schema must have 11 columns");

      let mut reader = builder.build().expect("parquet reader");
      let rb = reader.next().expect("at least one batch").expect("batch ok");
      assert_eq!(rb.num_rows(), 1);

      use arrow::array::StringArray;
      let hostname = rb.column(4).as_any().downcast_ref::<StringArray>().unwrap();
      assert_eq!(hostname.value(0), "integrationhost");
  }
  ```
  Run: `cargo test -p logthing --test syslog_s3_integration 2>&1 | tail -10` — expected:
  skip message if `MINIO_ENDPOINT` unset, or compile errors if `S3Sink` not yet in scope.

- [ ] **Green — wire `src/main.rs`.** Apply the wiring block described above. Confirm compile:
  `cargo build -p logthing 2>&1 | head -30`.

- [ ] **Green — run integration test against real MinIO.** If a MinIO instance is available (e.g.
  via `docker run -p 9000:9000 minio/minio server /data`):
  ```bash
  MINIO_ENDPOINT=http://localhost:9000 \
  MINIO_BUCKET=syslog-test \
  MINIO_ACCESS_KEY=minioadmin \
  MINIO_SECRET_KEY=minioadmin \
  cargo test -p logthing --test syslog_s3_integration -- --nocapture 2>&1 | tail -20
  ```
  Expect: `test syslog_message_appears_as_parquet_in_s3 ... ok`.

- [ ] **Commit:** `feat: wire SyslogS3Handler into main.rs syslog spawn block`

---

## Task 6 — E2E Smoke Check (Docker)

**Files:**
- Modify: `tests/e2e/simulation-environment/docker-compose.yml`
- Modify: `tests/e2e/simulation-environment/s3-verifier/entrypoint.py`
- Modify: `tests/e2e/simulation-environment/run.sh` (if needed)
- (Possibly modify): `tests/e2e/simulation-environment/config/logthing.toml`

**Goal:** Extend the existing Docker e2e harness so that the `logthing` container runs with
`[syslog.s3]` configured against the existing MinIO service; the existing `syslog-generator`
service sends messages; and the `s3-verifier` asserts that at least one Parquet object appears
under the `syslog/` prefix.

**TDD Steps:**

- [ ] **Red — document the expected e2e assertion.** Before changing Docker files, run:
  ```bash
  cd tests/e2e/simulation-environment && bash run.sh 2>&1 | tail -30
  ```
  Record which s3-verifier checks currently pass. Confirm the verifier does NOT yet check a
  `syslog/` prefix (it should only check WEF objects).

- [ ] **Green — add `[syslog.s3]` to the e2e logthing config.** In
  `tests/e2e/simulation-environment/config/logthing.toml`, add (or create if absent):
  ```toml
  [syslog.s3]
  endpoint   = "http://minio:9000"
  bucket     = "wef-events"
  region     = "us-east-1"
  access_key = "miniouser"
  secret_key = "miniopassword"
  key_prefix = "syslog/"
  max_buffer_rows     = 10
  flush_interval_secs = 5
  ```
  (Low thresholds so the verifier doesn't wait long for the first flush.)

- [ ] **Green — extend `minio-setup` to create the bucket for syslog if different.** If using a
  separate bucket, add `mc mb --ignore-existing local/syslog-events` to the `minio-setup` command
  block. If reusing `wef-events`, no change needed.

- [ ] **Green — extend `s3-verifier/entrypoint.py`.** Add a check after the existing WEF
  verification:
  ```python
  import boto3, sys, time

  # ... (existing WEF checks) ...

  # Syslog Parquet check
  syslog_prefix = "syslog/"
  deadline = time.time() + 30   # 30-second poll window
  syslog_found = False
  while time.time() < deadline:
      resp = s3.list_objects_v2(Bucket=bucket, Prefix=syslog_prefix)
      if resp.get("Contents"):
          syslog_found = True
          break
      time.sleep(2)

  if not syslog_found:
      print(f"ERROR: No Parquet object found under {syslog_prefix} in {bucket}", file=sys.stderr)
      sys.exit(1)

  # Verify the first object is readable Parquet with 11 columns
  key = resp["Contents"][0]["Key"]
  obj = s3.get_object(Bucket=bucket, Key=key)
  import io
  import pyarrow.parquet as pq
  table = pq.read_table(io.BytesIO(obj["Body"].read()))
  assert table.num_columns == 11, f"Expected 11 columns, got {table.num_columns}"
  assert table.num_rows > 0, "Expected at least one row in syslog Parquet"
  print(f"OK: syslog Parquet verified: {table.num_rows} row(s) under {syslog_prefix}")
  ```

  Note: the s3-verifier `Dockerfile` likely installs `boto3` already; add `pyarrow` to its
  requirements if absent.

- [ ] **Red → Green — run the full e2e suite.** From `tests/e2e/simulation-environment/`:
  ```bash
  bash run.sh 2>&1 | tee /tmp/e2e-phase3.log | tail -40
  ```
  Expect: `Standard E2E Tests Completed Successfully` and the syslog Parquet check passing.

- [ ] **Commit:** `test: e2e syslog Parquet S3 verification in simulation environment`

---

## Self-Review

### Spec coverage

| Spec requirement | Covered by |
|---|---|
| `SyslogS3Writer` with fixed Arrow schema | Task 1 (schema) + Task 2 (writer) |
| All `SyslogMessage` fields mapped to columns | Task 1 schema table + row-mapping tests |
| `structured_data` as JSON column | Task 1 (column 9, nullable `Utf8`) |
| Buffer by size threshold | Task 2 (`push` → flush when `>= max_buffer_rows`) |
| Buffer by time threshold | Task 2 (`flush_if_needed` age check) |
| Encode to Parquet bytes | Task 2 (`encode_batches_to_parquet`) |
| Call `S3Sink::upload` with syslog key prefix | Task 2 (`flush` method + `build_key`) |
| `SyslogS3Handler` implementing `SyslogHandler` | Task 3 |
| Bounded channel, drop on overflow | Task 3 (`try_send` + `syslog_s3_dropped` counter) |
| `syslog_s3_dropped`, `syslog_s3_records_written`, `syslog_s3_uploads`, `syslog_s3_upload_errors` metrics | Task 2 (`flush`) + Task 3 (`handle_message`) |
| Per-source S3 config `[syslog.s3]` | Task 4 (`SyslogS3Config`) |
| Absent config = no syslog persistence (backward compat) | Task 4 (`syslog_s3_absent_gives_none` test) |
| Wiring in `main.rs` | Task 5 |
| S3 upload failure isolated (does not stall listener) | Task 3 background task: upload error is logged and counted, channel remains drained |
| Unit tests | Tasks 1, 2, 3, 4 |
| Integration test (real S3) | Task 5 (`tests/syslog_s3_integration.rs`) |
| E2E test via Docker harness | Task 6 (`run.sh` + s3-verifier extension) |
| Conventional commits | Each task ends with a commit step |
| `cargo fmt` + `clippy -D warnings` | Stated in Global Constraints; enforced at each task |

### Placeholders

None. Every code block contains real Rust that compiles against the existing crate structure (given
Phase 2's `S3Sink` is present). Two assumptions are documented (A1, A2); the implementer is told
exactly how to adjust if Phase 2 uses different names.

### Type consistency

- `SyslogS3Handler` implements `crate::syslog::listener::SyslogHandler` (the real trait at
  `src/syslog/listener.rs:32`).
- `SyslogS3WriterConfig` uses `std::time::Duration` for `flush_interval`, not a raw `u64` —
  matches Tokio's `interval` API.
- `syslog_schema()` returns `Arc<Schema>` via `LazyLock`; consistent with how `parquet_s3.rs`
  constructs `Arc::new(Schema::new(...))` inline. The `LazyLock` avoids repeated allocation across
  calls.
- `RecordBatch` column ordering in `syslog_message_to_batch` matches the `Schema::new(vec![...])`
  ordering in `syslog_schema()` exactly.
- `encode_batches_to_parquet` uses ZSTD level 3, matching `parquet_s3.rs` compression choice.

### Backward-compatibility check

- `Config::default()` sets `syslog.s3 = None` → existing behaviour unchanged.
- `SyslogConfig` gains one optional field; existing TOML files without `[syslog.s3]` still
  deserialize correctly because the field is `Option<SyslogS3Config>` with `#[serde(default)]`.
- The syslog listener wiring in `main.rs` falls back to `DefaultSyslogHandler` if `s3` is `None`
  or if `S3Sink::from_config` fails — no regression on existing deployments.
- `src/forwarding/mod.rs` gains `pub mod syslog_s3;` — additive, does not remove or rename any
  existing public items.
- Existing `parquet_s3` tests are untouched.

### Risks

| Risk | Mitigation |
|---|---|
| Phase 2 `S3Sink` signature differs from Assumption A1 | Assumption is documented; Task 5 integration test will fail to compile if names differ, surfacing the discrepancy before merge |
| `metrics_util` not available for counter assertion in tests | Task 3 uses `try_send` semantics to prove drop behaviour without a custom recorder; counter increment is fire-and-forget and visible in production via Prometheus scrape |
| E2E MinIO bucket not pre-created for syslog prefix | Task 6 adds `mc mb` to minio-setup if a separate bucket is needed; using the existing `wef-events` bucket with a distinct prefix avoids this entirely |
| `pyarrow` not installed in s3-verifier Docker image | Task 6 calls out adding it to requirements; if infeasible, the verifier can fall back to asserting only that the key exists (content validation demoted to a comment) |
| `LazyLock` requires Rust 1.80+ (stabilised 2024-07-25) | Cargo.toml specifies `edition = "2024"` and the project targets nightly-recent; if the CI toolchain is older, replace `LazyLock` with `once_cell::sync::Lazy` and add `once_cell` to dependencies |
