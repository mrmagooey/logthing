//! Generic buffered Parquet writer.
//!
//! Provides:
//! - `ParquetSink` trait — the per-source adapter contract.
//! - `FlushPolicy` — unified rows-OR-bytes-OR-age flush trigger.
//! - `BufferedWriterConfig` — shared TOML-compatible config struct.
//! - `PartitionBuffer` + `build_key` — per-partition state and S3 key builder.
//! - `PartitionedParquetWriter<S>` — generic writer owning all buffer/flush/cap/encode/upload logic.
//! - `ParquetWriterHandle<S>` — bounded channel + background task + graceful-shutdown flush.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;

// ---------------------------------------------------------------------------
// ParquetSink trait
// ---------------------------------------------------------------------------

/// The per-source adapter contract.  Implement this for each log source;
/// the generic `PartitionedParquetWriter` and `ParquetWriterHandle` handle all
/// buffering, flush, cap, encode, and upload machinery.
pub trait ParquetSink: Send + Sync + 'static {
    type Record: Send + 'static;

    /// Stable source label, e.g. `"ipfix"` | `"syslog"` | `"zeek"` | `"wef"`.
    /// Used as the `source` metric label and base S3 prefix component.
    fn source(&self) -> &'static str;

    /// Partition segment for this record.
    /// `None` → single shared buffer (syslog, ipfix).
    /// `Some(seg)` → one buffer per seg (zeek: sanitized log_path; wef: `"event_type=<id>"`).
    /// The segment is used as both the buffer-map key and an S3 key path component.
    fn partition(&self, record: &Self::Record) -> Option<String>;

    /// Arrow schema for a partition.
    /// `partition` is `None` for single-schema sources; the sanitized segment for multi-partition.
    fn schema(&self, partition: Option<&str>) -> Arc<arrow_schema::Schema>;

    /// Convert one record to a single-row `RecordBatch` for the partition's schema.
    /// Must be panic-free and best-effort total.
    fn to_record_batch(
        &self,
        record: &Self::Record,
        schema: &Arc<arrow_schema::Schema>,
    ) -> anyhow::Result<arrow_array::RecordBatch>;
}

// ---------------------------------------------------------------------------
// FlushPolicy
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// BufferedWriterConfig
// ---------------------------------------------------------------------------

fn default_max_buffer_rows() -> usize {
    100_000
}

fn default_flush_threshold_bytes() -> usize {
    // 128 MiB — a reasonable Parquet file size before flushing.
    128 * 1024 * 1024
}

fn default_flush_interval_secs() -> u64 {
    // 15 minutes.
    900
}

fn default_channel_capacity() -> usize {
    // Large enough to absorb bursts without dropping at the channel layer.
    8_192
}

/// Shared config for all buffered-Parquet writers. TOML backward-compatible:
/// each source's existing TOML keys deserialize into this struct.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct BufferedWriterConfig {
    #[serde(flatten)]
    pub connection: crate::config::S3ConnectionConfig,
    /// S3 key prefix, slash-free (e.g. `"syslog"`, `"ipfix"`, `"zeek"`, `"wef"`).
    #[serde(default)]
    pub prefix: String,
    /// Flush when buffered row count per partition reaches this.
    /// Absent TOML key → 100_000 rows.
    #[serde(default = "default_max_buffer_rows")]
    pub max_buffer_rows: usize,
    /// Flush when estimated bytes per partition reaches this.
    /// Absent TOML key → 128 MiB.
    #[serde(default = "default_flush_threshold_bytes")]
    pub flush_threshold_bytes: usize,
    /// Flush after this many seconds regardless.
    /// Absent TOML key → 900 s (15 min).
    #[serde(default = "default_flush_interval_secs")]
    pub flush_interval_secs: u64,
    /// Bounded channel capacity (number of records).
    /// Absent TOML key → 8 192 records.
    #[serde(default = "default_channel_capacity")]
    pub channel_capacity: usize,
    /// Maximum number of distinct partition buffers; overflow → fixed `"_overflow"` partition.
    /// 0 means "unlimited" — this is intentional and safe; no hard cap on partitions.
    #[serde(default)]
    pub max_partitions: usize,
}

// ---------------------------------------------------------------------------
// PartitionBuffer — internal per-partition state
// ---------------------------------------------------------------------------

pub(crate) struct PartitionBuffer {
    pub(crate) schema: Arc<arrow_schema::Schema>,
    pub(crate) buffer: VecDeque<(arrow_array::RecordBatch, usize)>, // (batch, est_bytes)
    pub(crate) row_count: usize,
    pub(crate) byte_count: usize,
    pub(crate) last_flush: Instant,
    pub(crate) last_drop_warn: Option<Instant>,
}

impl PartitionBuffer {
    fn new(schema: Arc<arrow_schema::Schema>) -> Self {
        Self {
            schema,
            buffer: VecDeque::new(),
            row_count: 0,
            byte_count: 0,
            last_flush: Instant::now(),
            last_drop_warn: None,
        }
    }
}

// ---------------------------------------------------------------------------
// S3 key builder
// ---------------------------------------------------------------------------

/// Build the S3 object key for a flush.
/// Pattern: `{prefix}/[{partition}/]year={Y}/month={MM}/day={DD}/{uuid}.parquet`
/// The partition segment is omitted when `partition` is `None` (syslog, ipfix).
pub(crate) fn build_key(
    prefix: &str,
    partition: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    use chrono::Datelike as _;
    let id = uuid::Uuid::new_v4();
    match partition {
        Some(seg) => format!(
            "{}/{}/year={}/month={:02}/day={:02}/{}.parquet",
            prefix,
            seg,
            now.year(),
            now.month(),
            now.day(),
            id
        ),
        None => format!(
            "{}/year={}/month={:02}/day={:02}/{}.parquet",
            prefix,
            now.year(),
            now.month(),
            now.day(),
            id
        ),
    }
}

// ---------------------------------------------------------------------------
// PartitionedParquetWriter<S>
// ---------------------------------------------------------------------------

pub struct PartitionedParquetWriter<S: ParquetSink> {
    sink: S,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
    config: BufferedWriterConfig,
    policy: FlushPolicy,
    /// `""` key for None-partition sources; sanitized-path / `"event_type=<id>"` for multi-partition.
    pub(crate) buffers: HashMap<String, PartitionBuffer>,
}

impl<S: ParquetSink> PartitionedParquetWriter<S> {
    pub fn new(
        sink: S,
        s3: Arc<crate::forwarding::s3_sink::S3Sink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
    ) -> Self {
        Self {
            sink,
            s3,
            config,
            policy,
            buffers: HashMap::new(),
        }
    }

    /// Push one record: map to RecordBatch, append to partition buffer,
    /// enforce partition cap (overflow to `"_overflow"`), check flush policy,
    /// call `flush_partition` + `drop_oldest_to_cap` on failure.
    pub async fn push(&mut self, record: S::Record) -> anyhow::Result<()> {
        let raw_key = self.sink.partition(&record).unwrap_or_default();

        // Partition-count cap: if we've hit max_partitions and this is a new key, overflow.
        let effective_key = if self.buffers.contains_key(&raw_key)
            || self.config.max_partitions == 0
            || self.buffers.len() < self.config.max_partitions
        {
            raw_key
        } else {
            metrics::counter!("parquet_s3_partitions_capped", "source" => self.sink.source())
                .increment(1);
            "_overflow".to_string()
        };

        // Lazily create the buffer for this partition.
        let schema = if !self.buffers.contains_key(&effective_key) {
            let seg = if effective_key.is_empty() {
                None
            } else {
                Some(effective_key.as_str())
            };
            Some(self.sink.schema(seg))
        } else {
            None
        };
        if let Some(s) = schema {
            self.buffers
                .insert(effective_key.clone(), PartitionBuffer::new(s));
        }

        // Convert record → RecordBatch.
        let buf = self.buffers.get(&effective_key).unwrap();
        let schema = buf.schema.clone();
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

        let est_bytes = batch.get_array_memory_size();
        let n_rows = batch.num_rows();

        let buf = self.buffers.get_mut(&effective_key).unwrap();
        buf.buffer.push_back((batch, est_bytes));
        buf.row_count += n_rows;
        buf.byte_count += est_bytes;

        // Check flush policy.
        let should_flush = buf.row_count >= self.policy.max_rows
            || buf.byte_count >= self.policy.max_bytes
            || buf.last_flush.elapsed() >= self.policy.interval;

        if should_flush {
            let cap = self.config.max_buffer_rows.saturating_mul(4);
            let source = self.sink.source();
            if let Err(e) = self.flush_partition(&effective_key).await {
                // Flush failed — enforce hard cap.
                // Defense-in-depth: cap == 0 means "no hard cap"; skip drop so a zero can never
                // drain the entire buffer on S3 failure.
                if cap > 0
                    && let Some(b) = self.buffers.get_mut(&effective_key)
                {
                    Self::drop_oldest_to_cap(b, cap, source);
                }
                return Err(e);
            }
        }
        Ok(())
    }

    /// Flush all partitions unconditionally (called on shutdown).
    pub async fn flush_all(&mut self) -> anyhow::Result<()> {
        let keys: Vec<String> = self.buffers.keys().cloned().collect();
        let mut last_err: Option<anyhow::Error> = None;
        for key in keys {
            if let Err(e) = self.flush_partition(&key).await {
                last_err = Some(e);
            }
        }
        match last_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Flush partitions whose flush policy is triggered (called by timer).
    pub async fn flush_all_if_needed(&mut self) -> anyhow::Result<()> {
        let keys: Vec<String> = self.buffers.keys().cloned().collect();
        let mut last_err: Option<anyhow::Error> = None;
        for key in keys {
            let should_flush = {
                let buf = self.buffers.get(&key).unwrap();
                if buf.buffer.is_empty() {
                    false
                } else {
                    buf.row_count >= self.policy.max_rows
                        || buf.byte_count >= self.policy.max_bytes
                        || buf.last_flush.elapsed() >= self.policy.interval
                }
            };
            if should_flush && let Err(e) = self.flush_partition(&key).await {
                last_err = Some(e);
            }
        }
        match last_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

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
                buf.last_flush = Instant::now();
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
            } else {
                break;
            }
        }
        if dropped > 0 {
            metrics::counter!("parquet_s3_buffer_dropped", "source" => source)
                .increment(dropped as u64);
            let should_warn = buf
                .last_drop_warn
                .map(|t| t.elapsed().as_secs() >= 30)
                .unwrap_or(true);
            if should_warn {
                tracing::warn!(
                    dropped,
                    source,
                    "parquet_s3: S3 upload failing — dropped oldest rows to stay within hard cap"
                );
                buf.last_drop_warn = Some(Instant::now());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ParquetWriterHandle<S>
// ---------------------------------------------------------------------------

pub struct ParquetWriterHandle<S: ParquetSink> {
    tx: tokio::sync::mpsc::Sender<S::Record>,
    /// Source label captured at `start()` time; used for the drop metric.
    source: &'static str,
}

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
        let capacity = config.channel_capacity.max(1);
        // Capture the source label before `sink` is moved into the task.
        let source = sink.source();
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

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::StringArray;
    use arrow::datatypes::{DataType, Field, Schema};
    use arrow::record_batch::RecordBatch;

    // -----------------------------------------------------------------------
    // Task 1.1 — config deserialization tests
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Task 1.2 — build_key tests
    // -----------------------------------------------------------------------

    #[test]
    fn build_key_no_partition() {
        use chrono::TimeZone;
        let now = chrono::Utc.with_ymd_and_hms(2026, 3, 7, 0, 0, 0).unwrap();
        let key = build_key("syslog", None, now);
        assert!(
            key.starts_with("syslog/year=2026/month=03/day=07/"),
            "got: {key}"
        );
        assert!(key.ends_with(".parquet"), "got: {key}");
        assert!(!key.contains("//"), "double-slash: {key}");
    }

    #[test]
    fn build_key_with_partition() {
        use chrono::TimeZone;
        let now = chrono::Utc.with_ymd_and_hms(2026, 3, 7, 0, 0, 0).unwrap();
        let key = build_key("zeek", Some("conn"), now);
        assert!(
            key.starts_with("zeek/conn/year=2026/month=03/day=07/"),
            "got: {key}"
        );
        assert!(key.ends_with(".parquet"), "got: {key}");
    }

    #[test]
    fn build_key_wef_partition_segment() {
        use chrono::TimeZone;
        let now = chrono::Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        let key = build_key("wef", Some("event_type=4624"), now);
        assert!(
            key.starts_with("wef/event_type=4624/year=2026/"),
            "got: {key}"
        );
    }

    // -----------------------------------------------------------------------
    // Shared test helpers for Tasks 1.3–1.6
    // -----------------------------------------------------------------------

    fn test_schema() -> Arc<Schema> {
        Arc::new(Schema::new(vec![Field::new("val", DataType::Utf8, false)]))
    }

    struct MockSink;
    impl ParquetSink for MockSink {
        type Record = String;
        fn source(&self) -> &'static str {
            "test"
        }
        fn partition(&self, _r: &String) -> Option<String> {
            None
        }
        fn schema(&self, _p: Option<&str>) -> Arc<Schema> {
            test_schema()
        }
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
                bucket: "t".to_string(),
                region: "us-east-1".to_string(),
                access_key: "K".to_string(),
                secret_key: "S".to_string(),
            })
            .await
            .unwrap(),
        )
    }

    fn test_config(max_rows: usize) -> (BufferedWriterConfig, FlushPolicy) {
        use crate::config::S3ConnectionConfig;
        let cfg = BufferedWriterConfig {
            connection: S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "t".to_string(),
                region: "us-east-1".to_string(),
                access_key: "K".to_string(),
                secret_key: "S".to_string(),
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

    // -----------------------------------------------------------------------
    // Task 1.3 — PartitionedParquetWriter push / flush / cap tests
    // -----------------------------------------------------------------------

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
            if w.push(format!("r{i}")).await.is_err() {
                errors += 1;
            }
        }
        assert!(errors > 0);
        let buf = w.buffers.get("").unwrap();
        assert!(
            buf.row_count <= hard_cap,
            "row_count {} must be <= hard_cap {}",
            buf.row_count,
            hard_cap
        );
    }

    // -----------------------------------------------------------------------
    // Task 1.4 — partition-count cap tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn partition_cap_overflows_to_overflow_buffer() {
        struct PartitionedMock;
        impl ParquetSink for PartitionedMock {
            type Record = (String, String); // (partition, value)
            fn source(&self) -> &'static str {
                "test"
            }
            fn partition(&self, r: &(String, String)) -> Option<String> {
                Some(r.0.clone())
            }
            fn schema(&self, _: Option<&str>) -> Arc<Schema> {
                test_schema()
            }
            fn to_record_batch(
                &self,
                r: &(String, String),
                s: &Arc<Schema>,
            ) -> anyhow::Result<RecordBatch> {
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
            w.push((format!("part_{i}"), "v".to_string()))
                .await
                .unwrap();
        }
        // At most max_partitions + 1 (_overflow) buffers exist
        assert!(w.buffers.len() <= 4, "got {} buffers", w.buffers.len());
        assert!(
            w.buffers.contains_key("_overflow"),
            "overflow key must exist after cap breach"
        );
    }

    // -----------------------------------------------------------------------
    // Task 1.5 — ParquetWriterHandle tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn handle_start_spawns_background_task_and_try_send_works() {
        let s3 = unreachable_s3().await;
        let (cfg, policy) = test_config(10_000);
        let (handle, jh) = ParquetWriterHandle::start(MockSink, s3, cfg, policy);
        // try_send should succeed when channel not full and writer not stalled
        assert!(handle.try_send("hello".to_string()).is_ok());
        drop(handle);
        // 5 s — generous enough that a connection-refused S3 attempt always completes.
        tokio::time::timeout(std::time::Duration::from_secs(5), jh)
            .await
            .expect("join within timeout")
            .expect("task did not panic");
    }

    /// I3: channel-overflow metric is now incremented by the PRODUCTION `try_send` path,
    /// not by the test itself.  We use a `DebuggingRecorder` and assert the counter was
    /// bumped by the production code — without any manual `metrics::counter!` call in
    /// the test body.
    ///
    /// Strategy: create a handle with channel capacity = 1 and send many records back-to-back
    /// without yielding.  The channel holds at most one record; subsequent `try_send` calls
    /// fire while the first record is still queued, returning `Err(Full)` and causing the
    /// production code to increment the counter.
    #[tokio::test]
    #[allow(clippy::mutable_key_type)] // false positive: CompositeKey AtomicBool is never used for hashing
    async fn handle_channel_overflow_increments_metric_via_production_code() {
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let s3 = unreachable_s3().await;
        let (mut cfg, _) = test_config(10_000);
        // Channel of capacity 1: the first try_send fills it; subsequent ones overflow.
        cfg.channel_capacity = 1;
        let policy = FlushPolicy {
            max_rows: 10_000,
            max_bytes: usize::MAX,
            interval: std::time::Duration::from_secs(3600),
        };
        let (handle, _jh) = ParquetWriterHandle::start(MockSink, s3, cfg, policy);

        // Fill the channel then overflow it — without yielding so the background task
        // cannot drain the channel between sends.  Production try_send increments the metric.
        let mut overflow_count = 0usize;
        for i in 0..50usize {
            if handle.try_send(format!("r{i}")).is_err() {
                overflow_count += 1;
            }
        }
        assert!(
            overflow_count > 0,
            "expected at least one channel-overflow drop"
        );

        // Verify the production code emitted parquet_s3_dropped.
        // The metric is labeled ("source" => "test"), so we must include labels in the lookup.
        let snapshot = snapshotter.snapshot();
        let map = snapshot.into_hashmap();
        let labeled_key = CompositeKey::new(
            MetricKind::Counter,
            metrics::Key::from_parts(
                "parquet_s3_dropped",
                vec![metrics::Label::new("source", "test")],
            ),
        );
        let dropped = map
            .get(&labeled_key)
            .map(|(_, _, v)| {
                if let DebugValue::Counter(c) = v {
                    *c
                } else {
                    0
                }
            })
            .unwrap_or(0);
        assert!(
            dropped >= 1,
            "parquet_s3_dropped{{source=\"test\"}} should have been incremented by production try_send, got {dropped}"
        );
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
        tokio::time::timeout(std::time::Duration::from_secs(5), jh)
            .await
            .expect("task did not exit within 5s")
            .expect("task panicked");
    }

    // -----------------------------------------------------------------------
    // Task 1.6 — Additional tests: byte/age flush triggers, encode round-trip,
    //            multi-partition
    // -----------------------------------------------------------------------

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
            buf.last_flush = Instant::now() - std::time::Duration::from_secs(3601);
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
            fn source(&self) -> &'static str {
                "test"
            }
            fn partition(&self, r: &(String, String)) -> Option<String> {
                Some(r.0.clone())
            }
            fn schema(&self, _: Option<&str>) -> Arc<Schema> {
                test_schema()
            }
            fn to_record_batch(
                &self,
                r: &(String, String),
                s: &Arc<Schema>,
            ) -> anyhow::Result<RecordBatch> {
                let col = Arc::new(StringArray::from(vec![r.1.as_str()]));
                Ok(RecordBatch::try_new(s.clone(), vec![col])?)
            }
        }
        let s3 = unreachable_s3().await;
        let (mut cfg, policy) = test_config(10_000);
        cfg.max_partitions = 16;
        let mut w = PartitionedParquetWriter::new(MultiSink, s3, cfg, policy);
        for _ in 0..3 {
            w.push(("a".to_string(), "v".to_string())).await.unwrap();
        }
        for _ in 0..2 {
            w.push(("b".to_string(), "v".to_string())).await.unwrap();
        }
        assert_eq!(w.buffers.get("a").unwrap().row_count, 3);
        assert_eq!(w.buffers.get("b").unwrap().row_count, 2);
    }

    // -----------------------------------------------------------------------
    // I1 extra tests — default config and cap-0 guard
    // -----------------------------------------------------------------------

    /// A `BufferedWriterConfig` deserialized from a minimal TOML (no numeric fields) must
    /// have a non-zero `max_buffer_rows` thanks to the serde default function.
    #[test]
    fn config_defaults_have_nonzero_max_buffer_rows() {
        let toml = r#"
endpoint   = "http://minio:9000"
bucket     = "test"
region     = "us-east-1"
access_key = "KEY"
secret_key  = "SECRET"
"#;
        let cfg: BufferedWriterConfig = toml::from_str(toml).expect("deserialize");
        assert!(
            cfg.max_buffer_rows > 0,
            "max_buffer_rows must be non-zero by default, got {}",
            cfg.max_buffer_rows
        );
        assert!(
            cfg.flush_threshold_bytes > 0,
            "flush_threshold_bytes must be non-zero by default"
        );
        assert!(
            cfg.flush_interval_secs > 0,
            "flush_interval_secs must be non-zero by default"
        );
        assert!(
            cfg.channel_capacity > 0,
            "channel_capacity must be non-zero by default"
        );
    }

    /// With a non-zero `max_buffer_rows`, pushing many records against an unreachable S3
    /// keeps `row_count <= cap` (cap = max_buffer_rows * 4).
    #[tokio::test]
    async fn hard_cap_enforced_with_nonzero_max_buffer_rows() {
        let s3 = unreachable_s3().await;
        let max_rows = 10usize;
        let (cfg, policy) = test_config(max_rows);
        let hard_cap = max_rows.saturating_mul(4);
        let mut w = PartitionedParquetWriter::new(MockSink, s3, cfg, policy);
        for i in 0..(hard_cap * 5) {
            let _ = w.push(format!("r{i}")).await;
        }
        let buf = w.buffers.get("").unwrap();
        assert!(
            buf.row_count <= hard_cap,
            "row_count {} exceeds hard_cap {}",
            buf.row_count,
            hard_cap
        );
    }

    // -----------------------------------------------------------------------
    // m2 — drop_oldest_to_cap byte-counter consistency
    // -----------------------------------------------------------------------

    /// After `drop_oldest_to_cap`, `byte_count` must exactly equal the sum of
    /// `est_bytes` for the remaining elements in the buffer.
    #[test]
    fn drop_oldest_to_cap_byte_count_stays_consistent() {
        let schema = test_schema();
        let mut buf = PartitionBuffer::new(schema.clone());

        // Push 10 entries with distinct est_bytes values so we can verify bookkeeping.
        for i in 1usize..=10 {
            let col = Arc::new(arrow::array::StringArray::from(vec!["x"]));
            let batch = RecordBatch::try_new(schema.clone(), vec![col]).unwrap();
            let est = i * 100; // 100, 200, …, 1000
            buf.buffer.push_back((batch, est));
            buf.row_count += 1;
            buf.byte_count += est;
        }

        // Drop down to cap = 5 rows.
        PartitionedParquetWriter::<MockSink>::drop_oldest_to_cap(&mut buf, 5, "test");

        // Verify row_count.
        assert!(buf.row_count <= 5, "row_count={}", buf.row_count);

        // Verify byte_count equals sum of remaining est_bytes.
        let expected_bytes: usize = buf.buffer.iter().map(|(_, est)| est).sum();
        assert_eq!(
            buf.byte_count, expected_bytes,
            "byte_count {} != sum of remaining est_bytes {}",
            buf.byte_count, expected_bytes
        );
    }

    // -----------------------------------------------------------------------
    // m4 — _overflow partition gets a valid schema and accepts records
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn overflow_partition_gets_valid_schema_and_accepts_records() {
        struct PartitionedMockM4;
        impl ParquetSink for PartitionedMockM4 {
            type Record = (String, String);
            fn source(&self) -> &'static str {
                "test"
            }
            fn partition(&self, r: &(String, String)) -> Option<String> {
                Some(r.0.clone())
            }
            fn schema(&self, _p: Option<&str>) -> Arc<Schema> {
                test_schema()
            }
            fn to_record_batch(
                &self,
                r: &(String, String),
                s: &Arc<Schema>,
            ) -> anyhow::Result<RecordBatch> {
                let col = Arc::new(arrow::array::StringArray::from(vec![r.1.as_str()]));
                Ok(RecordBatch::try_new(s.clone(), vec![col])?)
            }
        }

        let s3 = unreachable_s3().await;
        let (mut cfg, policy) = test_config(10_000);
        cfg.max_partitions = 2;
        let mut w = PartitionedParquetWriter::new(PartitionedMockM4, s3, cfg, policy);

        // Push 4 distinct partitions; the 3rd and 4th should overflow to `_overflow`.
        for i in 0..4usize {
            w.push((format!("part_{i}"), "v".to_string()))
                .await
                .unwrap();
        }

        assert!(
            w.buffers.contains_key("_overflow"),
            "_overflow buffer must exist after partition cap exceeded"
        );
        // The _overflow buffer must have rows (records were actually written to it).
        let ov = w.buffers.get("_overflow").unwrap();
        assert!(ov.row_count > 0, "_overflow buffer must contain records");
        // The schema must be valid (non-empty field list from sink.schema(Some("_overflow"))).
        assert!(
            !ov.schema.fields().is_empty(),
            "_overflow buffer must have a non-empty schema"
        );
    }

    // -----------------------------------------------------------------------
    // m1 — byte-flush and age-flush tests assert state change occurred
    // -----------------------------------------------------------------------

    /// Byte-threshold flush: after a flush attempt the result is Err (unreachable S3),
    /// confirming the flush path was actually entered (not silently skipped).
    #[tokio::test]
    async fn byte_threshold_flush_changes_buffer_state() {
        let s3 = unreachable_s3().await;
        let (cfg, _) = test_config(10_000);
        let policy = FlushPolicy {
            max_rows: 10_000,
            max_bytes: 1, // triggers on the very first push
            interval: std::time::Duration::from_secs(3600),
        };
        let mut w = PartitionedParquetWriter::new(MockSink, s3, cfg, policy);

        // Push one record; this should trigger a flush attempt (which fails on unreachable S3).
        let result = w.push("r1".to_string()).await;
        // The flush should have been attempted (returned Err due to unreachable S3).
        assert!(
            result.is_err(),
            "flush attempt on unreachable S3 should return Err"
        );
        // After failed flush the hard cap kicks in; row_count must be <= cap.
        let buf = w.buffers.get("").unwrap();
        let hard_cap = 10_000usize * 4;
        assert!(
            buf.row_count <= hard_cap,
            "row_count {} must not exceed hard_cap {}",
            buf.row_count,
            hard_cap
        );
    }

    /// Age-flush trigger: after backdating last_flush and calling flush_all_if_needed,
    /// the flush path was entered — evidenced by Err (unreachable S3 guarantees attempt made).
    #[tokio::test]
    async fn age_threshold_flush_if_needed_enters_flush_path() {
        let s3 = unreachable_s3().await;
        let (cfg, policy) = test_config(10_000);
        let mut w = PartitionedParquetWriter::new(MockSink, s3, cfg, policy);
        w.push("r1".to_string()).await.unwrap();

        // Backdate last_flush so the age trigger fires.
        let backdated = Instant::now() - std::time::Duration::from_secs(3601);
        if let Some(buf) = w.buffers.get_mut("") {
            buf.last_flush = backdated;
        }

        // flush_all_if_needed will attempt flush (will fail, unreachable S3).
        let flush_result = w.flush_all_if_needed().await;

        // The flush path was entered: unreachable S3 guarantees the attempt was made.
        assert!(
            flush_result.is_err(),
            "flush_all_if_needed should have attempted a flush and returned Err on unreachable S3"
        );
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
        )
        .unwrap();

        // Simulate what flush_partition does: concat_batches + ArrowWriter
        let merged = arrow::compute::concat_batches(&schema, &[batch]).unwrap();
        let props = parquet::file::properties::WriterProperties::builder()
            .set_compression(parquet::basic::Compression::ZSTD(
                parquet::basic::ZstdLevel::try_new(3).unwrap(),
            ))
            .build();
        let mut buf = Vec::new();
        let mut writer =
            parquet::arrow::ArrowWriter::try_new(&mut buf, schema, Some(props)).unwrap();
        writer.write(&merged).unwrap();
        writer.close().unwrap();

        let bytes = bytes::Bytes::from(buf);
        let mut reader = ParquetRecordBatchReaderBuilder::try_new(bytes)
            .unwrap()
            .build()
            .unwrap();
        let rb = reader.next().unwrap().unwrap();
        assert_eq!(rb.num_rows(), 1);
        let col = rb.column(0).as_any().downcast_ref::<StringArray>().unwrap();
        assert_eq!(col.value(0), "hello");
    }
}
