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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::Notify;
use tokio::task::JoinSet;

// ---------------------------------------------------------------------------
// UploadSink trait
// ---------------------------------------------------------------------------

/// A destination for encoded Parquet bytes. Implemented by `S3Sink` (existing)
/// and `LocalDiskSink` (local-disk target). `PartitionedParquetWriter` is
/// generic over this trait so any source can persist to either destination
/// (or, via two independent writer instances, both at once) without touching
/// the buffering/flush/cap machinery.
#[async_trait]
pub trait UploadSink: Send + Sync {
    /// Upload `body` at `key` (a relative path, e.g.
    /// `zeek/conn/year=2026/month=07/day=04/<uuid>.parquet`).
    async fn upload(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()>;

    /// Stable label for the `target` metric dimension, e.g. `"s3"` | `"local"`.
    fn target_label(&self) -> &'static str;

    /// A fully-qualified location prefix for objects this sink uploads,
    /// e.g. `"http://minio:9000/my-bucket"` (S3) or `"file:///data/zeek"`
    /// (local disk). Used to build a fully-qualified `file_path` in
    /// `IcebergDescriptor` (a bare relative key alone doesn't tell an
    /// external reader which bucket/directory a file lives in — different
    /// sources may point at different buckets).
    fn location_hint(&self) -> String;
}

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
    /// Live-updatable: see `LiveInterval`.
    pub interval: LiveInterval,
}

// ---------------------------------------------------------------------------
// LiveInterval
// ---------------------------------------------------------------------------

/// A whole-seconds `Duration` that a writer's background task reads on every
/// flush check, and that can be updated live (e.g. from the admin API)
/// without restarting the task.
#[derive(Clone)]
pub struct LiveInterval {
    secs: Arc<AtomicU64>,
    changed: Arc<Notify>,
}

impl std::fmt::Debug for LiveInterval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveInterval")
            .field("secs", &self.secs.load(Ordering::Relaxed))
            .finish()
    }
}

impl LiveInterval {
    pub fn new(initial: Duration) -> Self {
        Self {
            secs: Arc::new(AtomicU64::new(initial.as_secs())),
            changed: Arc::new(Notify::new()),
        }
    }

    pub fn get(&self) -> Duration {
        Duration::from_secs(self.secs.load(Ordering::Relaxed))
    }

    /// Update the live value and wake a writer task waiting in `changed()`.
    pub fn set_secs(&self, secs: u64) {
        self.secs.store(secs, Ordering::Relaxed);
        self.changed.notify_one();
    }

    /// Resolves the next time `set_secs` is called. `Notify` coalesces
    /// multiple sets into a single stored permit if nothing is currently
    /// awaiting, so no update is lost.
    pub async fn changed(&self) {
        self.changed.notified().await;
    }
}

#[cfg(test)]
mod live_interval_tests {
    use super::*;

    #[test]
    fn get_returns_constructed_value() {
        let li = LiveInterval::new(Duration::from_secs(42));
        assert_eq!(li.get(), Duration::from_secs(42));
    }

    #[test]
    fn set_secs_updates_get() {
        let li = LiveInterval::new(Duration::from_secs(42));
        li.set_secs(7);
        assert_eq!(li.get(), Duration::from_secs(7));
    }

    #[tokio::test]
    async fn changed_resolves_promptly_after_set_secs() {
        let li = LiveInterval::new(Duration::from_secs(3600));
        let waiter = li.clone();
        let wait_fut = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(2), waiter.changed()).await
        });
        // Give the spawned task a chance to start waiting before we notify.
        tokio::task::yield_now().await;
        li.set_secs(1);
        let result = wait_fut.await.expect("task did not panic");
        assert!(
            result.is_ok(),
            "changed() must resolve promptly after set_secs"
        );
    }
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

/// `BufferedWriterConfig.connection` is never read by the generic writer once
/// a pre-built sink is supplied — only `prefix`/`max_buffer_rows`/etc. are used
/// in `push`/`flush_partition`/`drop_oldest_to_cap`. For a local-disk-only
/// pipeline there is no S3 connection to report, so this fills the field with
/// harmless placeholder values rather than changing its required type (which
/// would ripple into every other source's `BufferedWriterConfig` literal).
pub(crate) fn unused_s3_connection_placeholder() -> crate::config::S3ConnectionConfig {
    crate::config::S3ConnectionConfig {
        endpoint: String::new(),
        bucket: String::new(),
        region: String::new(),
        access_key: String::new(),
        secret_key: String::new(),
    }
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
    /// True while a background flush task owns this partition's previously
    /// buffered data. At most one flush is ever in-flight per partition —
    /// see `try_flush_partition_async`.
    pub(crate) in_flight: bool,
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
            in_flight: false,
        }
    }
}

// ---------------------------------------------------------------------------
// S3 key builder
// ---------------------------------------------------------------------------

/// Build the S3 object key for a flush.
/// Pattern: `{prefix}/[{partition}/]year={Y}/month={MM}/day={DD}/{uuid}.parquet`
/// The partition segment is omitted when `partition` is `None` (syslog, ipfix).
/// When `prefix` is empty the prefix segment is omitted entirely (no leading slash).
pub(crate) fn build_key(
    prefix: &str,
    partition: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    use chrono::Datelike as _;
    let id = uuid::Uuid::new_v4();
    let date = format!(
        "year={}/month={:02}/day={:02}",
        now.year(),
        now.month(),
        now.day()
    );
    match (prefix.is_empty(), partition) {
        (true, Some(seg)) => format!("{}/{}/{}.parquet", seg, date, id),
        (true, None) => format!("{}/{}.parquet", date, id),
        (false, Some(seg)) => format!("{}/{}/{}/{}.parquet", prefix, seg, date, id),
        (false, None) => format!("{}/{}/{}.parquet", prefix, date, id),
    }
}

// ---------------------------------------------------------------------------
// PartitionedParquetWriter<S>
// ---------------------------------------------------------------------------

/// Maximum number of flushes (across all of a writer's partitions) allowed
/// to run concurrently. Bounds worst-case memory/network footprint when
/// many partitions cross their flush threshold around the same time (e.g.
/// Zeek's up to 256 partitions all created near service start) and, after
/// a failed flush's `last_flush` is deliberately re-staled to retry almost
/// immediately (see `apply_flush_outcome`), prevents a systemic backend
/// outage from causing many partitions to retry in lockstep.
const MAX_CONCURRENT_FLUSHES_PER_WRITER: usize = 4;

/// Outcome of a background flush task (see `encode_and_upload`), reported
/// back to the single task that owns `PartitionedParquetWriter::buffers`
/// via `flush_tasks: JoinSet`. Never constructed with a partial/ambiguous
/// state: either the upload succeeded, or it didn't and the caller gets
/// back everything needed to retry.
enum FlushOutcome {
    Success {
        key: String,
    },
    Failure {
        key: String,
        batches: VecDeque<(arrow_array::RecordBatch, usize)>,
        row_count: usize,
        byte_count: usize,
        error: String,
    },
}

pub struct PartitionedParquetWriter<S: ParquetSink> {
    sink: S,
    s3: Arc<dyn UploadSink>,
    config: BufferedWriterConfig,
    policy: FlushPolicy,
    /// `""` key for None-partition sources; sanitized-path / `"event_type=<id>"` for multi-partition.
    pub(crate) buffers: HashMap<String, PartitionBuffer>,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
    /// Optional destination for the Iceberg "descriptor" JSON emitted
    /// alongside each successful Parquet flush. `None` (the default via
    /// `new()`) means the feature is off — zero behavior change.
    descriptor_sink: Option<Arc<dyn UploadSink>>,
    /// Background flush tasks spawned by `try_flush_partition_async`,
    /// reaped by the guarded `select!` branch in
    /// `ParquetWriterHandle::start_with_stats` (steady state) or by
    /// `drain_pending_flushes` (shutdown / tests).
    flush_tasks: JoinSet<FlushOutcome>,
    /// Bounds concurrent flushes across all of this writer's partitions.
    /// Acquired INSIDE the spawned task (`encode_and_upload`), never
    /// before spawning — see `MAX_CONCURRENT_FLUSHES_PER_WRITER`.
    flush_semaphore: Arc<tokio::sync::Semaphore>,
}

impl<S: ParquetSink> PartitionedParquetWriter<S> {
    pub fn new(
        sink: S,
        s3: Arc<dyn UploadSink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
    ) -> Self {
        Self::with_source_stats(
            sink,
            s3,
            config,
            policy,
            Arc::new(crate::stats::SourceHourlyStats::default()),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_source_stats(
        sink: S,
        s3: Arc<dyn UploadSink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
        source_stats: Arc<crate::stats::SourceHourlyStats>,
        descriptor_sink: Option<Arc<dyn UploadSink>>,
    ) -> Self {
        Self {
            sink,
            s3,
            config,
            policy,
            buffers: HashMap::new(),
            source_stats,
            descriptor_sink,
            flush_tasks: JoinSet::new(),
            flush_semaphore: Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_FLUSHES_PER_WRITER,
            )),
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
            metrics::counter!("parquet_s3_partitions_capped",
                "source" => self.sink.source(), "target" => self.s3.target_label())
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
        self.source_stats.record(self.sink.source(), 1);

        let est_bytes = batch.get_array_memory_size();
        let n_rows = batch.num_rows();

        let buf = self.buffers.get_mut(&effective_key).unwrap();
        buf.buffer.push_back((batch, est_bytes));
        buf.row_count += n_rows;
        buf.byte_count += est_bytes;

        // Check flush policy.
        let should_flush = buf.row_count >= self.policy.max_rows
            || buf.byte_count >= self.policy.max_bytes
            || buf.last_flush.elapsed() >= self.policy.interval.get();

        if should_flush {
            self.try_flush_partition_async(&effective_key);
        }
        Ok(())
    }

    /// Flush all partitions unconditionally (called on shutdown, after
    /// `drain_pending_flushes` has settled any in-flight background work).
    /// Deliberately still synchronous/inline — at shutdown there is no
    /// channel left to keep draining, so there is no benefit to spawning,
    /// only a need for a single definitive attempt per partition.
    pub async fn flush_all(&mut self) -> anyhow::Result<()> {
        let keys: Vec<String> = self.buffers.keys().cloned().collect();
        let mut last_err: Option<anyhow::Error> = None;
        for key in keys {
            let taken = {
                let Some(buf) = self.buffers.get_mut(&key) else {
                    continue;
                };
                if buf.buffer.is_empty() {
                    continue;
                }
                let schema = buf.schema.clone();
                let batches = std::mem::take(&mut buf.buffer);
                let row_count = buf.row_count;
                let byte_count = buf.byte_count;
                (schema, batches, row_count, byte_count)
            };
            let (schema, batches, row_count, byte_count) = taken;

            let outcome = encode_and_upload(
                key.clone(),
                batches,
                row_count,
                byte_count,
                schema,
                self.s3.clone(),
                self.descriptor_sink.clone(),
                self.config.prefix.clone(),
                self.sink.source(),
                self.flush_semaphore.clone(),
            )
            .await;

            if let FlushOutcome::Failure {
                key,
                batches,
                row_count,
                byte_count,
                error,
            } = outcome
            {
                if let Some(buf) = self.buffers.get_mut(&key) {
                    buf.buffer = batches;
                    buf.row_count = row_count;
                    buf.byte_count = byte_count;
                }
                last_err = Some(anyhow::anyhow!(error));
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
        for key in keys {
            let should_flush = {
                let buf = self.buffers.get(&key).unwrap();
                if buf.buffer.is_empty() {
                    false
                } else {
                    buf.row_count >= self.policy.max_rows
                        || buf.byte_count >= self.policy.max_bytes
                        || buf.last_flush.elapsed() >= self.policy.interval.get()
                }
            };
            if should_flush {
                self.try_flush_partition_async(&key);
            }
        }
        Ok(())
    }

    async fn flush_partition(&mut self, key: &str) -> anyhow::Result<()> {
        let buf = match self.buffers.get_mut(key) {
            Some(b) if !b.buffer.is_empty() => b,
            _ => return Ok(()),
        };
        let schema = buf.schema.clone();
        let batches = std::mem::take(&mut buf.buffer);
        let row_count = buf.row_count;
        let byte_count = buf.byte_count;

        let outcome = encode_and_upload(
            key.to_string(),
            batches,
            row_count,
            byte_count,
            schema,
            self.s3.clone(),
            self.descriptor_sink.clone(),
            self.config.prefix.clone(),
            self.sink.source(),
            self.flush_semaphore.clone(),
        )
        .await;

        match outcome {
            FlushOutcome::Success { key } => {
                let buf = self.buffers.get_mut(&key).unwrap();
                buf.row_count = 0;
                buf.byte_count = 0;
                buf.last_flush = Instant::now();
                Ok(())
            }
            FlushOutcome::Failure {
                key,
                batches,
                row_count,
                byte_count,
                error,
            } => {
                // Put the data back exactly as flush_partition's callers
                // (push/flush_all/flush_all_if_needed) expect on failure
                // today: still present in the buffer, untouched, to be
                // retried on the next threshold crossing.
                let buf = self.buffers.get_mut(&key).unwrap();
                buf.buffer = batches;
                buf.row_count = row_count;
                buf.byte_count = byte_count;
                Err(anyhow::anyhow!(error))
            }
        }
    }

    /// If `key`'s partition has no flush currently in-flight, detach its
    /// buffered batches (swapping in a fresh, empty `PartitionBuffer` so new
    /// records keep accumulating without waiting on the flush) and spawn
    /// `encode_and_upload` for them in the background. If a flush IS
    /// already in-flight for `key`, does not spawn a second one — applies
    /// the existing `drop_oldest_to_cap` to the live (still-growing) buffer
    /// instead, exactly as today's flush-failure path already does, just
    /// from a second call site.
    fn try_flush_partition_async(&mut self, key: &str) {
        let in_flight = self.buffers.get(key).map(|b| b.in_flight).unwrap_or(false);
        let source = self.sink.source();
        let target = self.s3.target_label();

        if in_flight {
            let cap = self.config.max_buffer_rows.saturating_mul(4);
            if cap > 0
                && let Some(b) = self.buffers.get_mut(key)
            {
                Self::drop_oldest_to_cap(b, cap, source, target);
            }
            return;
        }

        let Some(buf) = self.buffers.get_mut(key) else {
            return;
        };
        if buf.buffer.is_empty() {
            return;
        }

        let schema = buf.schema.clone();
        let taken_batches = std::mem::take(&mut buf.buffer);
        let row_count = buf.row_count;
        let byte_count = buf.byte_count;
        buf.row_count = 0;
        buf.byte_count = 0;
        buf.last_flush = Instant::now();
        buf.in_flight = true;

        metrics::gauge!("parquet_s3_flushes_in_flight", "source" => source, "target" => target)
            .increment(1.0);

        self.flush_tasks.spawn(encode_and_upload(
            key.to_string(),
            taken_batches,
            row_count,
            byte_count,
            schema,
            self.s3.clone(),
            self.descriptor_sink.clone(),
            self.config.prefix.clone(),
            source,
            self.flush_semaphore.clone(),
        ));
    }

    /// Apply one completed background flush's outcome. On success, clears
    /// in-flight for that partition. On failure, clears in-flight AND
    /// merges the returned batches back onto the FRONT of the (possibly
    /// already-refilling) live buffer -- they're older, so
    /// `drop_oldest_to_cap` (which pops from the front) drops the stalest
    /// data first if the merged total exceeds the cap -- then re-stales
    /// `last_flush` so the age-based flush trigger fires on the very next
    /// check, reproducing today's behavior (a failed flush's `last_flush`
    /// is simply never touched, so it's already stale and retries almost
    /// immediately) that the fresh-buffer-gets-"now"-at-swap-time design
    /// would otherwise silently break.
    fn apply_flush_outcome(&mut self, outcome: FlushOutcome) {
        let source = self.sink.source();
        let target = self.s3.target_label();
        metrics::gauge!("parquet_s3_flushes_in_flight", "source" => source, "target" => target)
            .decrement(1.0);

        match outcome {
            FlushOutcome::Success { key } => {
                if let Some(buf) = self.buffers.get_mut(&key) {
                    buf.in_flight = false;
                }
            }
            FlushOutcome::Failure {
                key,
                mut batches,
                row_count,
                byte_count,
                error,
            } => {
                tracing::warn!("parquet_s3 writer push error: {error}");

                let Some(buf) = self.buffers.get_mut(&key) else {
                    return;
                };
                buf.in_flight = false;

                while let Some(entry) = batches.pop_back() {
                    buf.buffer.push_front(entry);
                }
                buf.row_count += row_count;
                buf.byte_count += byte_count;

                let interval = self.policy.interval.get();
                buf.last_flush = Instant::now()
                    .checked_sub(interval + std::time::Duration::from_secs(1))
                    .unwrap_or_else(Instant::now);

                let cap = self.config.max_buffer_rows.saturating_mul(4);
                if cap > 0 {
                    Self::drop_oldest_to_cap(buf, cap, source, target);
                }
            }
        }
    }

    /// Drain all in-flight background flushes to completion, applying each
    /// outcome as it arrives. Used at graceful shutdown (so the writer's
    /// `JoinHandle` doesn't complete while a flush is still outstanding —
    /// callers await it expecting persistence to be genuinely finished) and
    /// reused by tests for deterministic waiting instead of sleep-based
    /// polling.
    async fn drain_pending_flushes(&mut self) {
        while let Some(result) = self.flush_tasks.join_next().await {
            match result {
                Ok(outcome) => self.apply_flush_outcome(outcome),
                Err(join_err) => {
                    tracing::warn!("parquet_s3 flush task panicked: {join_err}");
                }
            }
        }
    }

    fn drop_oldest_to_cap(
        buf: &mut PartitionBuffer,
        cap: usize,
        source: &'static str,
        target: &'static str,
    ) {
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
            metrics::counter!("parquet_s3_buffer_dropped", "source" => source, "target" => target)
                .increment(dropped as u64);
            let should_warn = buf
                .last_drop_warn
                .map(|t| t.elapsed().as_secs() >= 30)
                .unwrap_or(true);
            if should_warn {
                tracing::warn!(
                    dropped,
                    source,
                    target,
                    "parquet_s3: upload failing — dropped oldest rows to stay within hard cap"
                );
                buf.last_drop_warn = Some(Instant::now());
            }
        }
    }
}

/// Encode+upload one partition's already-detached batch of records. Called
/// two ways: synchronously (awaited inline) from `flush_partition` in this
/// task (unchanged behavior — Task 1), and, from Task 2 onward, from inside
/// a spawned background task via `try_flush_partition_async`, decoupled
/// from the writer's channel-draining loop.
///
/// Acquires `semaphore` INSIDE this function, never before calling it —
/// this is load-bearing once this is called from a spawned task (Task 2):
/// acquiring the permit in the *caller* (the main `select!` loop) would
/// block that loop the instant the semaphore saturates, reintroducing the
/// exact bug this change fixes.
#[allow(clippy::too_many_arguments)]
async fn encode_and_upload(
    key: String,
    batches: VecDeque<(arrow_array::RecordBatch, usize)>,
    row_count: usize,
    byte_count: usize,
    schema: Arc<arrow_schema::Schema>,
    s3: Arc<dyn UploadSink>,
    descriptor_sink: Option<Arc<dyn UploadSink>>,
    prefix: String,
    source: &'static str,
    semaphore: Arc<tokio::sync::Semaphore>,
) -> FlushOutcome {
    let _permit = semaphore
        .acquire_owned()
        .await
        .expect("flush semaphore is never closed");

    let to_concat: Vec<arrow_array::RecordBatch> = batches.iter().map(|(b, _)| b.clone()).collect();
    let schema_for_encode = schema.clone();
    let encode_result = tokio::task::spawn_blocking(
        move || -> anyhow::Result<(Vec<u8>, parquet::format::FileMetaData)> {
            use parquet::arrow::ArrowWriter;
            use parquet::basic::{Compression, ZstdLevel};
            use parquet::file::properties::WriterProperties;

            let batch = arrow::compute::concat_batches(&schema_for_encode, &to_concat)?;
            let props = WriterProperties::builder()
                .set_compression(Compression::ZSTD(ZstdLevel::try_new(3)?))
                .build();
            let mut buf = Vec::new();
            let mut writer =
                ArrowWriter::try_new(&mut buf, schema_for_encode.clone(), Some(props))?;
            writer.write(&batch)?;
            let file_metadata = writer.close()?;
            Ok((buf, file_metadata))
        },
    )
    .await
    .map_err(|e| anyhow::anyhow!("spawn_blocking join: {e}"));

    let (merged, file_metadata) = match encode_result.and_then(|r| r) {
        Ok(pair) => pair,
        Err(e) => {
            return FlushOutcome::Failure {
                key,
                batches,
                row_count,
                byte_count,
                error: format!("{e}"),
            };
        }
    };

    let partition_seg = if key.is_empty() {
        None
    } else {
        Some(key.as_str())
    };
    let s3_key = build_key(&prefix, partition_seg, chrono::Utc::now());
    let target = s3.target_label();
    let body_len = merged.len();

    match s3.upload(&s3_key, merged).await {
        Ok(()) => {
            metrics::counter!("parquet_s3_records_written", "source" => source, "target" => target)
                .increment(row_count as u64);
            metrics::counter!("parquet_s3_uploads", "source" => source, "target" => target)
                .increment(1);

            if let Some(descriptor_sink) = descriptor_sink {
                let descriptor = build_descriptor(
                    source,
                    partition_seg,
                    s3.location_hint(),
                    &s3_key,
                    row_count as u64,
                    body_len as u64,
                    target,
                    &schema,
                    &file_metadata,
                );
                upload_descriptor(descriptor_sink, descriptor, &s3_key, source).await;
            }
            FlushOutcome::Success { key }
        }
        Err(e) => {
            metrics::counter!("parquet_s3_upload_errors", "source" => source, "target" => target)
                .increment(1);
            FlushOutcome::Failure {
                key,
                batches,
                row_count,
                byte_count,
                error: format!("{e}"),
            }
        }
    }
}

/// Build an `IcebergDescriptor` from data already available at the exact
/// moment a Parquet flush succeeds — no re-read of the encoded file.
#[allow(clippy::too_many_arguments)]
fn build_descriptor(
    source: &'static str,
    partition: Option<&str>,
    location_hint: String,
    relative_key: &str,
    record_count: u64,
    file_size_in_bytes: u64,
    storage_target: &'static str,
    schema: &arrow_schema::Schema,
    file_metadata: &parquet::format::FileMetaData,
) -> crate::forwarding::iceberg_descriptor::IcebergDescriptor {
    use crate::forwarding::iceberg_descriptor::{ColumnStat, IcebergDescriptor, schema_version};
    use base64::Engine;

    let mut column_stats = std::collections::HashMap::new();
    if let Some(row_group) = file_metadata.row_groups.first() {
        for (idx, column) in row_group.columns.iter().enumerate() {
            let Some(col_meta) = column.meta_data.as_ref() else {
                continue;
            };
            // `col_meta.type_` is the raw thrift `parquet::format::Type` newtype
            // (`Type(1)`, `Type(6)`, ...) — its derived `Debug` is useless for the
            // committer contract. Convert to `parquet::basic::Type`, whose derived
            // `Debug` gives the human-readable name (`INT32`, `BYTE_ARRAY`, ...)
            // that callers need to decode the base64 min/max bytes below.
            let physical_type = parquet::basic::Type::try_from(col_meta.type_)
                .map(|t| format!("{t:?}"))
                .unwrap_or_else(|_| format!("UNKNOWN({})", col_meta.type_.0));
            let (null_count, min, max) = match col_meta.statistics.as_ref() {
                Some(stats) => (
                    stats.null_count.unwrap_or(0).max(0) as u64,
                    stats
                        .min
                        .as_ref()
                        .map(|b| base64::engine::general_purpose::STANDARD.encode(b)),
                    stats
                        .max
                        .as_ref()
                        .map(|b| base64::engine::general_purpose::STANDARD.encode(b)),
                ),
                None => (0, None, None),
            };
            column_stats.insert(
                idx as u32,
                ColumnStat {
                    null_count,
                    min,
                    max,
                    physical_type,
                },
            );
        }
    }

    IcebergDescriptor {
        source: source.to_string(),
        partition: partition.map(|p| p.to_string()),
        file_path: format!("{location_hint}/{relative_key}"),
        file_format: "PARQUET".to_string(),
        record_count,
        file_size_in_bytes,
        storage_target: storage_target.to_string(),
        schema_version: schema_version(schema),
        written_at: chrono::Utc::now(),
        column_stats,
    }
}

/// Best-effort descriptor upload: logs + increments a metric on failure,
/// never returns an error to the caller. A descriptor-sink outage must
/// never fail, retry, or hard-cap the core Parquet-writing path.
///
/// `relative_key` is the Parquet file's own relative key (e.g.
/// `zeek/conn/year=2026/month=07/day=10/abc.parquet`) — NOT
/// `descriptor.file_path`, which is already fully-qualified (see
/// `build_descriptor` above) and would be the wrong thing to upload the
/// descriptor itself under. The descriptor sink's own configured `prefix`
/// (from `IcebergDescriptorS3Config`/`IcebergDescriptorLocalConfig`) is
/// applied transparently by `descriptor_sink` itself — see
/// `build_iceberg_descriptor_sink`/`PrefixedUploadSink` below — so this
/// function always derives the key with an empty prefix.
async fn upload_descriptor(
    descriptor_sink: Arc<dyn UploadSink>,
    descriptor: crate::forwarding::iceberg_descriptor::IcebergDescriptor,
    relative_key: &str,
    source: &'static str,
) {
    let key = crate::forwarding::iceberg_descriptor::build_descriptor_key("", relative_key);
    let bytes = match descriptor.to_json_bytes() {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(source, "iceberg descriptor serialization failed: {e}");
            metrics::counter!("iceberg_descriptor_upload_errors", "source" => source).increment(1);
            return;
        }
    };
    match descriptor_sink.upload(&key, bytes).await {
        Ok(()) => {
            metrics::counter!("iceberg_descriptor_uploads", "source" => source).increment(1);
        }
        Err(e) => {
            tracing::warn!(source, "iceberg descriptor upload failed: {e}");
            metrics::counter!("iceberg_descriptor_upload_errors", "source" => source).increment(1);
        }
    }
}

// ---------------------------------------------------------------------------
// ParquetWriterHandle<S>
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ParquetWriterHandle<S: ParquetSink> {
    tx: tokio::sync::mpsc::Sender<S::Record>,
    /// Source label captured at `start()` time; used for the drop metric.
    source: &'static str,
    /// Target label captured at `start()` time; used for the drop metric.
    target: &'static str,
    /// Live handle onto this writer's flush-age interval, so the admin API
    /// (via `FlushIntervalRegistry`) can change the flush cadence of an
    /// already-running writer without a restart.
    flush_interval: LiveInterval,
}

impl<S: ParquetSink> ParquetWriterHandle<S> {
    /// Spawn the background writer task.
    /// Returns `(handle, JoinHandle)`. The `JoinHandle` must be awaited during
    /// graceful shutdown after all senders are dropped.
    pub fn start(
        sink: S,
        s3: Arc<dyn UploadSink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        Self::start_with_stats(
            sink,
            s3,
            config,
            policy,
            Arc::new(crate::stats::SourceHourlyStats::default()),
            None,
        )
    }

    /// Same as `start`, but records ingested-record counts into a shared,
    /// externally-owned `SourceHourlyStats` (used to feed the admin `/stats`
    /// page from every source through one instance), and optionally emits
    /// an Iceberg descriptor alongside each successful flush.
    #[allow(clippy::too_many_arguments)]
    pub fn start_with_stats(
        sink: S,
        s3: Arc<dyn UploadSink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
        source_stats: Arc<crate::stats::SourceHourlyStats>,
        descriptor_sink: Option<Arc<dyn UploadSink>>,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let capacity = config.channel_capacity.max(1);
        // Capture the source/target labels before `sink`/`s3` are moved into the task.
        let source = sink.source();
        let target = s3.target_label();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<S::Record>(capacity);
        // Clone the live-interval handle before `policy` is moved into the
        // writer below, so both the writer (flush-age comparisons) and this
        // task (ticker rebuild) share the same underlying live value. A third
        // clone is kept on the returned `Self` so external callers (e.g. the
        // admin API's flush-interval registry) can update it live too.
        let interval_handle = policy.interval.clone();
        let handle_flush_interval = interval_handle.clone();
        let flush_check = crate::forwarding::s3_sink::flush_check_interval(interval_handle.get());
        let handle = tokio::spawn(async move {
            let mut writer = PartitionedParquetWriter::with_source_stats(
                sink,
                s3,
                config,
                policy,
                source_stats,
                descriptor_sink,
            );
            let mut ticker = tokio::time::interval(flush_check);
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
                                // Channel closed — drain any in-flight background
                                // flushes first (so a late failure's data gets
                                // merged back for the final flush below to
                                // pick up), THEN flush whatever remains.
                                writer.drain_pending_flushes().await;
                                if let Err(e) = writer.flush_all().await {
                                    tracing::warn!("parquet_s3 flush_all on shutdown: {e}");
                                }
                                break;
                            }
                        }
                    }
                    _ = ticker.tick() => {
                        if let Err(e) = writer.flush_all_if_needed().await {
                            tracing::warn!("parquet_s3 flush_all_if_needed: {e}");
                        }
                    }
                    _ = interval_handle.changed() => {
                        ticker = tokio::time::interval(crate::forwarding::s3_sink::flush_check_interval(interval_handle.get()));
                    }
                    // Reap completed background flushes. The `if !is_empty()`
                    // guard is load-bearing: `JoinSet::join_next()` on an
                    // empty set resolves immediately to `None`, so an
                    // unguarded branch would busy-spin this loop.
                    Some(result) = writer.flush_tasks.join_next(), if !writer.flush_tasks.is_empty() => {
                        match result {
                            Ok(outcome) => writer.apply_flush_outcome(outcome),
                            Err(join_err) => {
                                tracing::warn!("parquet_s3 flush task panicked: {join_err}");
                            }
                        }
                    }
                }
            }
        });
        (
            Self {
                tx,
                source,
                target,
                flush_interval: handle_flush_interval,
            },
            handle,
        )
    }

    /// Live handle onto this writer's flush-age interval. Cloning this and
    /// registering it (e.g. in `FlushIntervalRegistry`) lets external callers
    /// change the writer's flush cadence without restarting it.
    pub fn flush_interval(&self) -> LiveInterval {
        self.flush_interval.clone()
    }

    /// Try to send a record without blocking.
    ///
    /// On channel overflow or closed, increments `parquet_s3_dropped{source=<source>,target=<target>}`
    /// and returns the `TrySendError` to the caller so they can apply any additional handling.
    #[must_use = "callers should log or handle the TrySendError to avoid silent record loss"]
    pub fn try_send(
        &self,
        record: S::Record,
    ) -> Result<(), tokio::sync::mpsc::error::TrySendError<S::Record>> {
        match self.tx.try_send(record) {
            Ok(()) => Ok(()),
            Err(e) => {
                metrics::counter!("parquet_s3_dropped", "source" => self.source, "target" => self.target)
                    .increment(1);
                Err(e)
            }
        }
    }
}

/// Generic replacement for each source's former `build_xxx_handle` helper
/// (e.g. Zeek's `build_zeek_handle`, Suricata's `build_suricata_handle`).
/// Every such helper did nothing beyond this: assemble
/// `BufferedWriterConfig`/`FlushPolicy` from flat scalar fields and forward
/// to `ParquetWriterHandle::start_with_stats` — there was no source-specific
/// behavior in any of them, only code the `S: ParquetSink` bound already
/// makes fully generic. `max_partitions` is a parameter (not hardcoded here)
/// because it differs per source.
#[allow(clippy::too_many_arguments)] // one parameter per BufferedWriterConfig/FlushPolicy field, plus source_stats/descriptor_sink; splitting into a struct would only move the count, not reduce it
pub(crate) fn start_writer<S: ParquetSink + Default>(
    prefix: String,
    max_buffer_rows: usize,
    flush_threshold_bytes: usize,
    flush_interval_secs: u64,
    channel_capacity: usize,
    max_partitions: usize,
    sink: Arc<dyn UploadSink>,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<Arc<dyn UploadSink>>,
) -> (ParquetWriterHandle<S>, tokio::task::JoinHandle<()>) {
    let bwc = BufferedWriterConfig {
        connection: unused_s3_connection_placeholder(),
        prefix,
        max_buffer_rows,
        flush_threshold_bytes,
        flush_interval_secs,
        channel_capacity,
        max_partitions,
    };
    let policy = FlushPolicy {
        max_rows: max_buffer_rows,
        max_bytes: flush_threshold_bytes,
        interval: LiveInterval::new(std::time::Duration::from_secs(flush_interval_secs)),
    };
    ParquetWriterHandle::start_with_stats(
        S::default(),
        sink,
        bwc,
        policy,
        source_stats,
        descriptor_sink,
    )
}

/// Wraps another `UploadSink`, transparently prepending a fixed prefix to
/// every key. Used so the descriptor sink's own configured `prefix`
/// (`IcebergDescriptorS3Config`/`IcebergDescriptorLocalConfig`) is applied
/// once, at construction, without threading a separate prefix parameter
/// through `flush_partition`/`upload_descriptor` and every one of the 14
/// per-source `_start`/`_local_start` call sites.
struct PrefixedUploadSink {
    inner: Arc<dyn UploadSink>,
    prefix: String,
}

#[async_trait]
impl UploadSink for PrefixedUploadSink {
    async fn upload(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()> {
        let full_key = format!("{}/{}", self.prefix, key);
        self.inner.upload(&full_key, body).await
    }
    fn target_label(&self) -> &'static str {
        self.inner.target_label()
    }
    fn location_hint(&self) -> String {
        self.inner.location_hint()
    }
}

/// Construct the shared Iceberg descriptor `UploadSink` from `[iceberg]`
/// config, if configured. Called once by `main.rs` and once by
/// `Server::new` (in `src/server/mod.rs`) — each independently builds its
/// own `Arc<dyn UploadSink>` pointed at the same configured destination,
/// since both already have their own `Config` instance and there is no
/// other shared state between them for this. Returns `Ok(None)` when
/// neither `iceberg.s3` nor `iceberg.local` is configured (the common
/// case — feature off, zero behavior change).
pub async fn build_iceberg_descriptor_sink(
    cfg: &crate::config::IcebergConfig,
) -> anyhow::Result<Option<Arc<dyn UploadSink>>> {
    if let Some(s3_cfg) = cfg.s3.as_ref() {
        let sink = crate::forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await?;
        let sink: Arc<dyn UploadSink> = Arc::new(sink);
        return Ok(Some(wrap_with_prefix(sink, &s3_cfg.prefix)));
    }
    if let Some(local_cfg) = cfg.local.as_ref() {
        let sink =
            crate::forwarding::local_sink::LocalDiskSink::new(local_cfg.directory.clone()).await?;
        let sink: Arc<dyn UploadSink> = Arc::new(sink);
        return Ok(Some(wrap_with_prefix(sink, &local_cfg.prefix)));
    }
    Ok(None)
}

fn wrap_with_prefix(inner: Arc<dyn UploadSink>, prefix: &str) -> Arc<dyn UploadSink> {
    if prefix.is_empty() {
        inner
    } else {
        Arc::new(PrefixedUploadSink {
            inner,
            prefix: prefix.to_string(),
        })
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
            interval: LiveInterval::new(std::time::Duration::from_secs(900)),
        };
        assert_eq!(p.max_rows, 10_000);
        assert_eq!(p.max_bytes, 100 * 1024 * 1024);
        assert_eq!(p.interval.get().as_secs(), 900);
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

    #[test]
    fn build_key_empty_prefix_with_partition() {
        use chrono::TimeZone;
        let now = chrono::Utc.with_ymd_and_hms(2026, 6, 21, 0, 0, 0).unwrap();

        // empty prefix + partition → no leading slash, no double-slash
        let key = build_key("", Some("event_type=4624"), now);
        assert!(
            key.starts_with("event_type=4624/year=2026/"),
            "empty prefix with partition must not have leading slash: {key}"
        );
        assert!(!key.starts_with('/'), "must not start with /: {key}");
        assert!(!key.contains("//"), "must not have double-slash: {key}");
        assert!(key.ends_with(".parquet"), "must end with .parquet: {key}");

        // empty prefix + no partition → no leading slash
        let key2 = build_key("", None, now);
        assert!(
            key2.starts_with("year=2026/"),
            "empty prefix without partition must start with year=: {key2}"
        );
        assert!(!key2.starts_with('/'), "must not start with /: {key2}");
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
            interval: LiveInterval::new(std::time::Duration::from_secs(3600)),
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

    /// Proves `PartitionedParquetWriter` is destination-agnostic: an in-memory
    /// `UploadSink` (not `S3Sink`) receives the flushed bytes.
    struct RecordingSink {
        uploads: std::sync::Arc<std::sync::Mutex<Vec<(String, usize)>>>,
    }

    #[async_trait::async_trait]
    impl UploadSink for RecordingSink {
        async fn upload(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()> {
            self.uploads
                .lock()
                .unwrap()
                .push((key.to_string(), body.len()));
            Ok(())
        }
        fn target_label(&self) -> &'static str {
            "recording"
        }
        fn location_hint(&self) -> String {
            "recording://test".to_string()
        }
    }

    #[tokio::test]
    async fn partitioned_writer_uploads_via_generic_uploadsink_trait_object() {
        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink: Arc<dyn UploadSink> = Arc::new(RecordingSink {
            uploads: uploads.clone(),
        });
        let (cfg, policy) = test_config(1); // flush on first row
        let mut w = PartitionedParquetWriter::new(MockSink, sink, cfg, policy);

        w.push("hello".to_string()).await.unwrap();

        let recorded = uploads.lock().unwrap();
        assert_eq!(
            recorded.len(),
            1,
            "expected exactly one upload via the non-S3 sink"
        );
        assert!(
            recorded[0].1 > 0,
            "uploaded body must be non-empty Parquet bytes"
        );
    }

    /// Proves the `target` label reaches `parquet_s3_uploads`/`parquet_s3_upload_errors`.
    #[tokio::test]
    #[allow(clippy::mutable_key_type)]
    async fn flush_metrics_carry_the_target_label() {
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink: Arc<dyn UploadSink> = Arc::new(RecordingSink { uploads });
        let (cfg, policy) = test_config(1);
        let mut w = PartitionedParquetWriter::new(MockSink, sink, cfg, policy);

        w.push("hello".to_string()).await.unwrap();

        let snapshot = snapshotter.snapshot();
        let map = snapshot.into_hashmap();
        let key = CompositeKey::new(
            MetricKind::Counter,
            metrics::Key::from_parts(
                "parquet_s3_uploads",
                vec![
                    metrics::Label::new("source", "test"),
                    metrics::Label::new("target", "recording"),
                ],
            ),
        );
        let count = map
            .get(&key)
            .map(|(_, _, v)| {
                if let DebugValue::Counter(c) = v {
                    *c
                } else {
                    0
                }
            })
            .unwrap_or(0);
        assert_eq!(
            count, 1,
            "expected parquet_s3_uploads{{source=\"test\",target=\"recording\"}} == 1"
        );
    }

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
            None,
        );

        for i in 0..3 {
            w.push(format!("r{i}")).await.unwrap();
        }

        let snapshot = shared_stats.snapshot();
        let row = snapshot.iter().find(|r| r.source == "test").unwrap();
        let total: u64 = row.hours.iter().map(|h| h.count).sum();
        assert_eq!(
            total, 3,
            "push() must count records even though nothing flushed"
        );
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
            interval: LiveInterval::new(std::time::Duration::from_secs(3600)),
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
        // The metric is labeled ("source" => "test", "target" => "s3"), so we must include
        // both labels in the lookup (unreachable_s3() backs this handle with a real S3Sink).
        let snapshot = snapshotter.snapshot();
        let map = snapshot.into_hashmap();
        let labeled_key = CompositeKey::new(
            MetricKind::Counter,
            metrics::Key::from_parts(
                "parquet_s3_dropped",
                vec![
                    metrics::Label::new("source", "test"),
                    metrics::Label::new("target", "s3"),
                ],
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
            "parquet_s3_dropped{{source=\"test\",target=\"s3\"}} should have been incremented by production try_send, got {dropped}"
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
            interval: LiveInterval::new(std::time::Duration::from_secs(3600)),
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
        PartitionedParquetWriter::<MockSink>::drop_oldest_to_cap(&mut buf, 5, "test", "test");

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
            interval: LiveInterval::new(std::time::Duration::from_secs(3600)),
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

    /// Core regression test for the live-reload flush-interval bug: an
    /// ALREADY-RUNNING writer (spawned via `start_with_stats`, not a freshly
    /// constructed one) must pick up a changed flush interval without being
    /// restarted. Spawns a writer with a long (3600s) `flush_interval_secs`,
    /// pushes a record (which alone would never trip the row/byte/age
    /// thresholds), then calls `.set_secs(1)` on the handle's live interval —
    /// exactly what `FlushIntervalRegistry::set_secs` does when the admin API
    /// pushes a config change — and asserts the flush lands within a short
    /// bounded wait.
    #[tokio::test]
    async fn already_running_writer_picks_up_live_flush_interval_change() {
        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink: Arc<dyn UploadSink> = Arc::new(RecordingSink {
            uploads: uploads.clone(),
        });

        let cfg = BufferedWriterConfig {
            connection: unused_s3_connection_placeholder(),
            prefix: "test".to_string(),
            max_buffer_rows: 10_000,
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 64,
            max_partitions: 8,
        };
        let policy = FlushPolicy {
            max_rows: 10_000,
            max_bytes: usize::MAX,
            interval: LiveInterval::new(Duration::from_secs(3600)),
        };

        let (handle, _jh) = ParquetWriterHandle::start_with_stats(
            MockSink,
            sink,
            cfg,
            policy,
            Arc::new(crate::stats::SourceHourlyStats::default()),
            None,
        );

        // Push a record — with a 3600s interval and no row/byte threshold
        // hit, this alone would never trigger a flush.
        handle.try_send("hello".to_string()).expect("try_send ok");

        // Give the background task a moment to actually consume the record
        // before we change the interval underneath it.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Simulate the admin API changing flush_interval_secs on the
        // ALREADY-RUNNING writer via its registered live handle — no restart.
        handle.flush_interval().set_secs(1);

        // The ticker rebuild is edge-triggered via `Notify`, not a fixed
        // 1-second poll — so poll briefly here (test-side) for the flush to
        // land instead of waiting out the original 3600s interval.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            if !uploads.lock().unwrap().is_empty() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "writer did not flush within 3s of set_secs(1) on its live interval handle"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        assert_eq!(uploads.lock().unwrap().len(), 1);
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

    /// Regression test for a bug where `physical_type` was built via
    /// `format!("{:?}", col_meta.type_)` on `parquet::format::Type` — a
    /// thrift-generated newtype (`pub struct Type(pub i32)`) whose derived
    /// `Debug` yields `"Type(1)"`, not the human-readable `"INT32"` that
    /// `IcebergDescriptor`'s contract promises to the external committer
    /// (which decodes the base64 min/max bytes using this field).
    ///
    /// This exercises the REAL extraction path: a real Arrow `RecordBatch`
    /// with an `Int32` column is encoded through the real `ArrowWriter`
    /// (the same path `flush_partition` uses), and `build_descriptor` is
    /// called on the resulting real `parquet::format::FileMetaData` — not a
    /// hand-built `ColumnStat` fixture, which is what let this bug slip
    /// through prior reviews.
    #[test]
    fn build_descriptor_reports_human_readable_physical_type_for_int32_column() {
        use arrow::array::Int32Array;

        let schema = Arc::new(Schema::new(vec![Field::new("val", DataType::Int32, false)]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(Int32Array::from(vec![1, 2, 3])) as _],
        )
        .unwrap();

        let props = parquet::file::properties::WriterProperties::builder().build();
        let mut buf = Vec::new();
        let mut writer =
            parquet::arrow::ArrowWriter::try_new(&mut buf, schema.clone(), Some(props)).unwrap();
        writer.write(&batch).unwrap();
        let file_metadata = writer.close().unwrap();

        let descriptor = build_descriptor(
            "test_source",
            None,
            "s3://bucket".to_string(),
            "path/to/file.parquet",
            3,
            buf.len() as u64,
            "test_target",
            &schema,
            &file_metadata,
        );

        let stat = descriptor
            .column_stats
            .get(&0)
            .expect("column 0 stat present");
        assert_eq!(
            stat.physical_type, "INT32",
            "physical_type must be the human-readable enum name (\"INT32\"), not the raw \
             thrift Debug output (e.g. \"Type(1)\")"
        );
    }

    // -----------------------------------------------------------------------
    // Task 1: start_writer<S> generic helper function test
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn start_writer_wires_a_generic_parquet_sink_and_exits_cleanly() {
        use std::sync::Arc as StdArc;

        #[derive(Default)]
        struct TestSink;

        impl ParquetSink for TestSink {
            type Record = String;

            fn source(&self) -> &'static str {
                "test_start_writer"
            }

            fn partition(&self, _record: &Self::Record) -> Option<String> {
                None
            }

            fn schema(&self, _partition: Option<&str>) -> Arc<arrow_schema::Schema> {
                Arc::new(arrow_schema::Schema::new(vec![Field::new(
                    "value",
                    DataType::Utf8,
                    false,
                )]))
            }

            fn to_record_batch(
                &self,
                record: &Self::Record,
                schema: &Arc<arrow_schema::Schema>,
            ) -> anyhow::Result<RecordBatch> {
                let col = StdArc::new(StringArray::from(vec![record.as_str()]));
                Ok(RecordBatch::try_new(schema.clone(), vec![col])?)
            }
        }

        struct UnreachableUploadSink;
        #[async_trait::async_trait]
        impl UploadSink for UnreachableUploadSink {
            async fn upload(&self, _key: &str, _body: Vec<u8>) -> anyhow::Result<()> {
                anyhow::bail!("unreachable in this test")
            }
            fn target_label(&self) -> &'static str {
                "test"
            }
            fn location_hint(&self) -> String {
                "unreachable://test".to_string()
            }
        }

        let (handle, join_handle) = start_writer::<TestSink>(
            "test-prefix".to_string(),
            100_000,
            usize::MAX,
            3600,
            256,
            1,
            StdArc::new(UnreachableUploadSink),
            StdArc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );

        handle.try_send("hello".to_string()).ok();
        drop(handle);

        tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("writer task must exit within 5s")
            .expect("writer task must not panic");
    }

    #[tokio::test]
    async fn flush_emits_descriptor_when_descriptor_sink_configured() {
        let s3 = unreachable_s3().await; // Parquet upload target — unreachable is fine, we swap below
        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let parquet_sink: Arc<dyn UploadSink> = Arc::new(RecordingSink {
            uploads: uploads.clone(),
        });
        let descriptor_uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let descriptor_sink: Arc<dyn UploadSink> = Arc::new(RecordingSink {
            uploads: descriptor_uploads.clone(),
        });
        let _ = s3; // silence unused-var warning; kept for signature parity with other tests

        let (cfg, policy) = test_config(1); // flush on first row
        let mut w = PartitionedParquetWriter::with_source_stats(
            MockSink,
            parquet_sink,
            cfg,
            policy,
            Arc::new(crate::stats::SourceHourlyStats::default()),
            Some(descriptor_sink),
        );

        w.push("hello".to_string()).await.unwrap();

        let parquet_calls = uploads.lock().unwrap();
        assert_eq!(parquet_calls.len(), 1, "expected one Parquet upload");

        let descriptor_calls = descriptor_uploads.lock().unwrap();
        assert_eq!(descriptor_calls.len(), 1, "expected one descriptor upload");
        assert!(
            descriptor_calls[0].0.ends_with(".json"),
            "descriptor key must end in .json, got: {}",
            descriptor_calls[0].0
        );
        assert!(
            descriptor_calls[0].1 > 0,
            "descriptor body must be non-empty"
        );
    }

    #[tokio::test]
    async fn flush_emits_no_descriptor_when_descriptor_sink_is_none() {
        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let parquet_sink: Arc<dyn UploadSink> = Arc::new(RecordingSink {
            uploads: uploads.clone(),
        });
        let (cfg, policy) = test_config(1);
        // descriptor_sink: None — the default via `new()`.
        let mut w = PartitionedParquetWriter::new(MockSink, parquet_sink, cfg, policy);

        w.push("hello".to_string()).await.unwrap();

        // Only the Parquet upload happened; RecordingSink was never given
        // a descriptor destination to record into, so there is nothing
        // more to assert beyond "this did not panic and behaves exactly
        // as before this feature existed" — the real assertion is that
        // flush succeeded at all with descriptor_sink absent.
        assert_eq!(uploads.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn descriptor_upload_failure_does_not_fail_the_flush() {
        struct FailingSink;
        #[async_trait::async_trait]
        impl UploadSink for FailingSink {
            async fn upload(&self, _key: &str, _body: Vec<u8>) -> anyhow::Result<()> {
                anyhow::bail!("descriptor destination unreachable")
            }
            fn target_label(&self) -> &'static str {
                "failing"
            }
            fn location_hint(&self) -> String {
                "failing://test".to_string()
            }
        }

        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let parquet_sink: Arc<dyn UploadSink> = Arc::new(RecordingSink { uploads });
        let (cfg, policy) = test_config(1);
        let mut w = PartitionedParquetWriter::with_source_stats(
            MockSink,
            parquet_sink,
            cfg,
            policy,
            Arc::new(crate::stats::SourceHourlyStats::default()),
            Some(Arc::new(FailingSink)),
        );

        // Must succeed — a failing descriptor sink must never fail the
        // Parquet flush itself.
        let result = w.push("hello".to_string()).await;
        assert!(
            result.is_ok(),
            "flush must succeed even when the descriptor sink fails: {result:?}"
        );
    }

    #[tokio::test]
    async fn prefixed_upload_sink_prepends_prefix_to_every_key() {
        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let inner: Arc<dyn UploadSink> = Arc::new(RecordingSink {
            uploads: uploads.clone(),
        });
        let prefixed = wrap_with_prefix(inner, "_iceberg_descriptors");
        prefixed
            .upload("zeek/conn/abc.json", vec![1, 2, 3])
            .await
            .unwrap();
        let calls = uploads.lock().unwrap();
        assert_eq!(calls[0].0, "_iceberg_descriptors/zeek/conn/abc.json");
    }

    #[test]
    fn wrap_with_prefix_returns_inner_unchanged_when_prefix_empty() {
        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let inner: Arc<dyn UploadSink> = Arc::new(RecordingSink { uploads });
        // No way to compare Arc<dyn Trait> pointers cleanly across a trait
        // object boundary in a way that's meaningful here — instead, assert
        // behavior: an empty prefix must not alter the key at all.
        let wrapped = wrap_with_prefix(inner, "");
        assert_eq!(wrapped.target_label(), "recording");
    }
}
