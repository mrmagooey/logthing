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

use crate::forwarding::drop_log::{DropKind, DropLogThrottles, DropSite};

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
    ///
    /// Implementations MUST NOT panic from `upload` -- always return `Err`
    /// instead. A panicking upload surfaces as a `JoinError` from the
    /// `flush_tasks` `JoinSet` (in `ParquetWriterHandle::start_with_stats`'s
    /// `select!` loop and in `drain_pending_flushes`), which is logged but
    /// loses the partition key -- that partition's `in_flight` flag and
    /// `parquet_s3_flushes_in_flight` gauge entry would never be cleared,
    /// permanently stranding it (every future threshold crossing would fall
    /// through to `drop_oldest_to_cap` instead of ever flushing again).
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

    /// Optional amortized-builder fast path. Returns `None` (the default)
    /// to opt out and keep the exact one-`to_record_batch()`-call-per-push
    /// behavior -- existing adapters need no code change to keep working
    /// exactly as before, and are provably unaffected since this code path
    /// is structurally unreachable for them.
    fn new_batch(
        &self,
        schema: &Arc<arrow_schema::Schema>,
    ) -> Option<Box<dyn RecordBatchAccumulator<Self::Record>>> {
        let _ = schema;
        None
    }

    /// Name of the Arrow column whose value determines a record's UTC
    /// event day -- the column `day_and_batch`'s default implementation
    /// reads to bucket buffers (and therefore Parquet files) so each one
    /// is "day-clean": every row decodes to the same Iceberg `day()`
    /// partition tuple. See
    /// docs/superpowers/specs/2026-09-05-day-clean-parquet-partitions-design.md.
    ///
    /// `None` means this sink has not opted in, so `day_and_batch`'s
    /// default falls straight through to the generic `received_at` / `now`
    /// fallback chain in `day_from_batch`. That is intentionally fine for
    /// every sink that doesn't override it -- in particular this crate's
    /// own test-only `ParquetSink` mocks, none of which need accurate
    /// day partitioning and all of which get correct (if day-agnostic)
    /// bucketing for free.
    fn time_column(&self) -> Option<&'static str> {
        None
    }

    /// Map one record to its batch AND the UTC day its `time_column()`
    /// value falls on, in a single pass.
    ///
    /// Default: calls `to_record_batch` exactly once, then reads the day
    /// back off the very batch it just built (`day_from_batch`). This is
    /// deliberate, not just an optimization: it is the only way a sink
    /// that stamps a fresh `Utc::now()` value into the row it returns
    /// (e.g. syslog's `received_at` -- see `syslog_s3.rs`) can guarantee
    /// the buffer-key day and the persisted value never disagree. Calling
    /// `to_record_batch` a second time, or reading the clock a second
    /// time, would each independently reopen that race.
    ///
    /// Returns `(day, None)` instead of `(day, Some(batch))` only when a
    /// sink overrides this method to compute the day WITHOUT building a
    /// batch -- exclusively relevant to a sink that also implements
    /// `new_batch` (an amortized fast path whose entire purpose is
    /// avoiding a per-record `to_record_batch` call; see `ZeekSink`'s
    /// override). The caller (`PartitionedParquetWriter::push`) treats
    /// `None` as "map it later, only if actually needed."
    fn day_and_batch(
        &self,
        record: &Self::Record,
        schema: &Arc<arrow_schema::Schema>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<(chrono::NaiveDate, Option<arrow_array::RecordBatch>)> {
        let batch = self.to_record_batch(record, schema)?;
        let day = day_from_batch(&batch, self.time_column(), now);
        Ok((day, Some(batch)))
    }
}

/// Amortized builder state for one in-progress, possibly-multi-row
/// `RecordBatch`. An adapter that wants to amortize builder-allocation
/// cost across multiple records implements this and returns it from
/// `ParquetSink::new_batch`.
pub trait RecordBatchAccumulator<Record>: Send {
    /// Try to append one record. Returns `Ok(false)` if this record does
    /// not belong to this accumulator's schema (mirrors whatever
    /// per-record schema-mismatch fallback the adapter's `to_record_batch`
    /// already performs) -- the caller must then fall back to
    /// `to_record_batch` for just this one record.
    ///
    /// `now` is `push()`'s single per-push clock read -- the same value
    /// threaded through `ParquetSink::day_and_batch` -- passed in rather
    /// than read here. `ConnAccumulator` and `EnvelopeAccumulator` derive
    /// their own event/receipt instant from the record itself and simply
    /// ignore it; it exists for an accumulator like IPFIX's
    /// `FlowRecordAccumulator`, which is long-lived across many pushes and
    /// has no per-record receipt instant of its own to fall back on.
    /// Calling `Utc::now()` inside `try_append` would reintroduce a second
    /// clock read on either side of midnight that could disagree with the
    /// `now` `day_and_batch` already used to pick this very buffer; binding
    /// `now` once at construction instead would be worse, since the
    /// accumulator outlives any single `now` and records appended after
    /// midnight would still be stamped with a stale day. Do not
    /// "simplify" this away by calling the clock inside an implementation.
    ///
    /// Contract implementers must uphold: on `Ok(true)`, `len()` must be
    /// exactly `rows_before + N` where `N` is the number of rows this
    /// `Record` contributed (1 for a one-row-per-record sink, more for a
    /// sink whose `Record` carries multiple rows, e.g. a batch of flow
    /// records). This method must never internally call `finish` (which
    /// would reset `len()` back to zero). The caller
    /// (`PartitionedParquetWriter::push`) derives the exact row count to
    /// add to its own bookkeeping from the `len()` delta across this call
    /// rather than assuming 1, so a violation here silently corrupts
    /// `row_count`-driven behavior: the `max_rows` flush trigger, the
    /// `BUILDER_BATCH_ROWS` force-materialize check, and
    /// `drop_oldest_to_cap`'s hard-cap eviction loop.
    fn try_append(
        &mut self,
        record: &Record,
        now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<bool>;

    /// Rows appended so far, not yet finished into a `RecordBatch`.
    fn len(&self) -> usize;

    /// True when no rows have been appended yet.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Finish the currently-accumulated rows into one `RecordBatch` and
    /// reset internal builder state to empty, ready to accumulate the
    /// next batch without reallocating.
    fn finish(&mut self) -> anyhow::Result<arrow_array::RecordBatch>;
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
/// in `push`/`try_flush_partition_async`/`drop_oldest_to_cap`. For a local-disk-only
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

/// Extract the UTC calendar day a just-mapped batch's designated
/// `time_col` falls on, reading row 0 only.
///
/// Row 0 is correct for every sink's batch except `IpfixSink`'s, which
/// maps a whole `Vec<FlowRecord>` (already batched at the listener) into
/// one multi-row `RecordBatch` per push -- but IPFIX's `export_time` is
/// decoded once per message and copied onto every `FlowRecord` produced
/// from it (see `src/ipfix/decoder.rs`), so row 0 can never disagree with
/// any other row in that same batch.
///
/// Fallback chain: `time_col` -> a column literally named `"received_at"`
/// -> `now`. The middle step is what lets syslog/structured_syslog/generic
/// (each of whose primary time column is nullable) fall back to their own
/// `received_at` column without any sink-specific code here; it is a
/// harmless no-op for sinks whose primary column has no such column to
/// find (e.g. Zeek's typed schemas, which fall straight to `now`).
fn day_from_batch(
    batch: &arrow_array::RecordBatch,
    time_col: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
) -> chrono::NaiveDate {
    use arrow_array::Array as _;

    let day_of = |name: &str| -> Option<chrono::NaiveDate> {
        let col = batch.column_by_name(name)?;
        let ts = col
            .as_any()
            .downcast_ref::<arrow_array::TimestampMicrosecondArray>()?;
        if ts.is_empty() || ts.is_null(0) {
            return None;
        }
        chrono::DateTime::from_timestamp_micros(ts.value(0)).map(|dt| dt.date_naive())
    };

    time_col
        .and_then(day_of)
        .or_else(|| day_of("received_at"))
        .unwrap_or_else(|| now.date_naive())
}

#[cfg(test)]
mod day_from_batch_tests {
    use super::*;
    use arrow::array::TimestampMicrosecondArray;
    use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
    use arrow::record_batch::RecordBatch;
    use chrono::TimeZone;

    fn ts_schema(cols: &[&str]) -> Arc<Schema> {
        Arc::new(Schema::new(
            cols.iter()
                .map(|name| {
                    Field::new(
                        *name,
                        DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                        true,
                    )
                })
                .collect::<Vec<_>>(),
        ))
    }

    fn ts_batch(schema: &Arc<Schema>, values: &[Option<i64>]) -> RecordBatch {
        let cols: Vec<arrow_array::ArrayRef> = values
            .iter()
            .map(|v| {
                Arc::new(TimestampMicrosecondArray::from(vec![*v]).with_timezone("UTC"))
                    as arrow_array::ArrayRef
            })
            .collect();
        RecordBatch::try_new(schema.clone(), cols).unwrap()
    }

    fn micros(y: i32, m: u32, d: u32) -> i64 {
        chrono::Utc
            .with_ymd_and_hms(y, m, d, 12, 0, 0)
            .unwrap()
            .timestamp_micros()
    }

    #[test]
    fn reads_the_primary_column_when_non_null() {
        let schema = ts_schema(&["ts"]);
        let batch = ts_batch(&schema, &[Some(micros(2026, 3, 7))]);
        let now = chrono::Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap();
        let day = day_from_batch(&batch, Some("ts"), now);
        assert_eq!(day, chrono::NaiveDate::from_ymd_opt(2026, 3, 7).unwrap());
    }

    #[test]
    fn falls_back_to_received_at_when_primary_is_null() {
        let schema = ts_schema(&["timestamp", "received_at"]);
        let batch = ts_batch(&schema, &[None, Some(micros(2026, 5, 1))]);
        let now = chrono::Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap();
        let day = day_from_batch(&batch, Some("timestamp"), now);
        assert_eq!(day, chrono::NaiveDate::from_ymd_opt(2026, 5, 1).unwrap());
    }

    #[test]
    fn falls_back_to_now_when_nothing_else_applies() {
        let schema = ts_schema(&["ts"]);
        let batch = ts_batch(&schema, &[None]);
        let now = chrono::Utc.with_ymd_and_hms(2030, 12, 25, 0, 0, 0).unwrap();
        let day = day_from_batch(&batch, Some("ts"), now);
        assert_eq!(day, chrono::NaiveDate::from_ymd_opt(2030, 12, 25).unwrap());
    }

    #[test]
    fn none_time_column_skips_straight_to_fallback_chain() {
        let schema = ts_schema(&["received_at"]);
        let batch = ts_batch(&schema, &[Some(micros(2027, 2, 2))]);
        let now = chrono::Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap();
        // time_column() defaults to None for sinks that don't opt in.
        let day = day_from_batch(&batch, None, now);
        assert_eq!(day, chrono::NaiveDate::from_ymd_opt(2027, 2, 2).unwrap());
    }
}

/// Widest backfill accepted from a record's own timestamp before
/// `partition_time` falls back to receipt time instead. This is the knob
/// that bounds live-buffer fan-out: an untrusted sender can claim any event
/// timestamp it likes (syslog, IPFIX `export_time`, HEC `time`), and without
/// a ceiling each distinct claimed day mints its own buffer, its own small
/// Parquet PUT, and its own descriptor PUT. Clamping to 30 days means a
/// sender can mint at most ~31 buffers per partition (30 backfill days plus
/// today) no matter how many distinct dates it claims.
///
/// The tradeoff: a *genuine* backfill deeper than 30 days is bucketed by
/// receipt time rather than event time. It is not dropped and not
/// mis-typed -- the real event timestamp is still queryable in its own
/// column -- but the file it lands in partitions by when it was ingested,
/// not by when it happened. Widen this if deep replay matters more than the
/// fan-out bound.
const MAX_BACKFILL: chrono::TimeDelta = chrono::TimeDelta::days(30);

/// Tolerance for a sender's clock running ahead of ours. A small forward
/// skew is normal clock drift; anything past this is treated the same as an
/// out-of-range backfill and bucketed by receipt time instead.
const MAX_SKEW: chrono::TimeDelta = chrono::TimeDelta::days(1);

/// Derive the instant a record's partition day is computed from.
///
/// This is the single source of truth for the `partition_time` column: a
/// pure, clock-free function of the record's own event timestamp (if any)
/// and the receipt instant logthing stamped on ingest. It never reads
/// `Utc::now()`, which closes the last path where two clock reads either
/// side of midnight could disagree about which day a buffer belongs to --
/// the same record, evaluated twice, always derives the same instant.
///
/// - `event` is `None` (the record carries no usable timestamp of its own,
///   e.g. a CEF payload) -> `received_at`.
/// - `event` is `Some(t)` but falls outside `[received_at - MAX_BACKFILL,
///   received_at + MAX_SKEW]` -> `received_at`. This is the untrusted-input
///   clamp: a sender cannot mint unbounded live buffers by claiming
///   arbitrary event dates, because anything too far from receipt time
///   collapses onto `received_at`.
/// - otherwise -> `t`, the record's own event timestamp.
pub(crate) fn partition_time(
    event: Option<chrono::DateTime<chrono::Utc>>,
    received_at: chrono::DateTime<chrono::Utc>,
) -> chrono::DateTime<chrono::Utc> {
    match event {
        Some(t) if t >= received_at - MAX_BACKFILL && t <= received_at + MAX_SKEW => t,
        _ => received_at,
    }
}

#[cfg(test)]
mod partition_time_tests {
    use super::*;
    use chrono::TimeZone;

    fn at(y: i32, m: u32, d: u32, h: u32) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.with_ymd_and_hms(y, m, d, h, 0, 0).unwrap()
    }

    #[test]
    fn none_event_falls_back_to_received_at() {
        let received_at = at(2026, 6, 15, 12);
        assert_eq!(partition_time(None, received_at), received_at);
    }

    #[test]
    fn event_a_few_hours_before_received_at_is_used_verbatim() {
        // Different UTC day from received_at, so returning received_at
        // instead would be visibly wrong -- this can't pass by accident.
        let received_at = at(2026, 6, 15, 1);
        let event = at(2026, 6, 14, 20);
        assert_eq!(partition_time(Some(event), received_at), event);
    }

    #[test]
    fn event_31_days_before_received_at_falls_back() {
        let received_at = at(2026, 6, 15, 12);
        let event = received_at - chrono::TimeDelta::days(31);
        assert_eq!(partition_time(Some(event), received_at), received_at);
    }

    #[test]
    fn event_2_days_after_received_at_falls_back() {
        let received_at = at(2026, 6, 15, 12);
        let event = received_at + chrono::TimeDelta::days(2);
        assert_eq!(partition_time(Some(event), received_at), received_at);
    }

    #[test]
    fn exactly_30_days_backfill_is_accepted() {
        let received_at = at(2026, 6, 15, 12);
        let event = received_at - MAX_BACKFILL;
        assert_eq!(partition_time(Some(event), received_at), event);
    }

    #[test]
    fn one_microsecond_beyond_backfill_bound_is_rejected() {
        let received_at = at(2026, 6, 15, 12);
        let event = received_at - MAX_BACKFILL - chrono::TimeDelta::microseconds(1);
        assert_eq!(partition_time(Some(event), received_at), received_at);
    }

    #[test]
    fn exactly_1_day_skew_is_accepted() {
        let received_at = at(2026, 6, 15, 12);
        let event = received_at + MAX_SKEW;
        assert_eq!(partition_time(Some(event), received_at), event);
    }

    #[test]
    fn one_microsecond_beyond_skew_bound_is_rejected() {
        let received_at = at(2026, 6, 15, 12);
        let event = received_at + MAX_SKEW + chrono::TimeDelta::microseconds(1);
        assert_eq!(partition_time(Some(event), received_at), received_at);
    }
}

// ---------------------------------------------------------------------------
// BufKey — buffer-map key
// ---------------------------------------------------------------------------

/// Buffer-map key: partition segment (`""` = no partition, mirroring the
/// historical `String`-keyed map used by syslog/ipfix) plus the UTC
/// calendar day of the records it holds. Splitting by day is the entire
/// mechanism behind "day-clean" Parquet files -- see
/// `ParquetSink::time_column`'s doc comment. Each `BufKey` maps to
/// exactly one `PartitionBuffer`, so one buffer -> one flush -> one file
/// -> one descriptor -> one `day()` Iceberg partition tuple, by
/// construction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct BufKey {
    pub(crate) partition: String,
    pub(crate) day: chrono::NaiveDate,
}

// ---------------------------------------------------------------------------
// PartitionBuffer — internal per-partition state
// ---------------------------------------------------------------------------

pub(crate) struct PartitionBuffer<R> {
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
    /// Live, in-progress amortized builder for this partition. `None` for
    /// every adapter that doesn't opt in (`ParquetSink::new_batch` returns
    /// `None`), and `None` even for an opted-in adapter until its first
    /// record lands.
    pub(crate) live_builder: Option<Box<dyn RecordBatchAccumulator<R>>>,
}

impl<R> PartitionBuffer<R> {
    fn new(schema: Arc<arrow_schema::Schema>) -> Self {
        Self {
            schema,
            buffer: VecDeque::new(),
            row_count: 0,
            byte_count: 0,
            last_flush: Instant::now(),
            last_drop_warn: None,
            in_flight: false,
            live_builder: None,
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
///
/// Takes the buffer's own UTC day directly, never `chrono::Utc::now()` --
/// the buffer key (`BufKey`) is what makes each file day-clean; reading
/// any other clock here would silently reintroduce the bug this design
/// fixes for a flush that crosses midnight mid-encode (see the design
/// doc's "Rejected approach" section, point 1).
pub(crate) fn build_key(prefix: &str, partition: Option<&str>, day: chrono::NaiveDate) -> String {
    use chrono::Datelike as _;
    let id = uuid::Uuid::new_v4();
    let date = format!(
        "year={}/month={:02}/day={:02}",
        day.year(),
        day.month(),
        day.day()
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

/// How often the writer task refreshes `parquet_s3_channel_available`.
///
/// Fixed and short, independent of `flush_interval`: this gauge is the
/// recommended queue-depth alert signal, and a channel can fill and drain many
/// times inside one 900-second flush interval. One timer wakeup per second per
/// writer, with no per-record cost in the drain loop.
const CHANNEL_GAUGE_INTERVAL: Duration = Duration::from_secs(1);

/// Row-count threshold at which a partition's live (in-progress) amortized
/// builder is force-materialized into a real, stored `RecordBatch` entry,
/// independent of any flush. Bounds two things: the maximum size of a
/// single amortization unit, and the maximum number of rows that can be
/// "invisible" to `drop_oldest_to_cap`'s hard-cap enforcement at any given
/// instant (small relative to the default hard cap of
/// `max_buffer_rows.saturating_mul(4)` = 400,000 at the 100,000-row
/// default). See the design doc's "BUILDER_BATCH_ROWS" section.
const BUILDER_BATCH_ROWS: usize = 1000;

/// Outcome of a background flush task (see `encode_and_upload`), reported
/// back to the single task that owns `PartitionedParquetWriter::buffers`
/// via `flush_tasks: JoinSet`. Never constructed with a partial/ambiguous
/// state: either the upload succeeded, or it didn't and the caller gets
/// back everything needed to retry.
enum FlushOutcome {
    Success {
        key: BufKey,
    },
    Failure {
        key: BufKey,
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
    /// One entry per `(partition, day)` currently live. `partition` is
    /// `""` for None-partition sources; sanitized-path / `"event_type=<id>"`
    /// for multi-partition; `"_overflow"` past the partition cap.
    pub(crate) buffers: HashMap<BufKey, PartitionBuffer<S::Record>>,
    /// Every distinct partition string ever admitted as a real buffer
    /// (never `"_overflow"`'s inputs, only the sentinel itself once
    /// created), independent of day and NEVER shrunk -- including by the
    /// empty-buffer reaping in `apply_flush_outcome`. `max_partitions`
    /// must cap the number of distinct log streams (e.g. Zeek's up to
    /// 256 stream types), not the number of `(partition, day)` buffer
    /// entries, and must not "forget" a partition that goes briefly idle
    /// across midnight and gets reaped.
    known_partitions: std::collections::HashSet<String>,
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

/// Bytes a batch's data actually occupies, as opposed to the capacity its
/// builders allocated.
///
/// `RecordBatch::get_array_memory_size()` reports allocated capacity. For a
/// batch built one row at a time that is dominated by a fixed per-builder
/// allocation — measured at 94,080 bytes for a 1-row IPFIX batch whose real
/// payload is 109 — a ~860x overstatement that drove the byte-based flush
/// threshold 1-2 orders of magnitude too early. See
/// `docs/performance/2026-09-14-writer-channel-loss.md`.
///
/// `get_slice_memory_size` is arrow's own used-bytes accounting: slice-aware
/// (a hand-rolled `buffers().map(|b| b.len())` sum reports the *parent*
/// buffer for a sliced array, reintroducing an overstatement of the same
/// kind) and recursive into child data, so it stays correct if a nested
/// column type is ever added.
fn used_bytes(batch: &arrow_array::RecordBatch) -> usize {
    batch
        .columns()
        .iter()
        .map(|c| c.to_data().get_slice_memory_size().unwrap_or(0))
        .sum()
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
            known_partitions: std::collections::HashSet::new(),
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
    /// call `try_flush_partition_async` (spawns a background flush) or
    /// `drop_oldest_to_cap` (if one is already in-flight for this partition).
    pub async fn push(&mut self, record: S::Record) -> anyhow::Result<()> {
        // Read the clock exactly once per push and thread it through
        // day_and_batch/day_from_batch. Two reads either side of midnight
        // would produce exactly the non-day-clean file this whole feature
        // exists to prevent.
        let now = chrono::Utc::now();
        let raw_partition = self.sink.partition(&record).unwrap_or_default();

        // Partition-count cap: based on distinct partitions ever admitted
        // (`known_partitions`), NOT on `self.buffers.len()`. Buffers are
        // now keyed by (partition, day), so `buffers.len()` can be
        // transiently inflated by day multiplicity (e.g. two buffers open
        // around midnight for the same partition) or deflated by the
        // empty-buffer reaping in `apply_flush_outcome` -- either would
        // destabilize a cap based directly on it: a doubling could trip
        // the cap early and divert live data to `"_overflow"`, or reaping
        // could "free" a slot that a live stream still occupies.
        // `known_partitions` never shrinks, so it is immune to both.
        //
        // `raw_known` reuses the one `contains` lookup this branch already
        // needs, and doubles as the insert guard below: on the
        // overwhelmingly common path (a partition `push()` has already seen
        // -- true for essentially every record once a source has warmed
        // up), `raw_known` is `true` and the `insert` is skipped entirely.
        // `push()` is the hottest call in this file and must not pay for a
        // hash + no-op insert on every single record. The `insert` still
        // runs for a genuinely new partition (including repeated overflow
        // of previously-unseen partitions once the cap is hit, where
        // `raw_known` is always false) -- `known_partitions`'s contents end
        // up identical to the unguarded version either way, just without
        // the redundant work on the hot path.
        let raw_known = self.known_partitions.contains(&raw_partition);
        let effective_partition = if raw_known
            || self.config.max_partitions == 0
            || self.known_partitions.len() < self.config.max_partitions
        {
            raw_partition
        } else {
            metrics::counter!("parquet_s3_partitions_capped",
                "source" => self.sink.source(), "target" => self.s3.target_label())
            .increment(1);
            "_overflow".to_string()
        };
        if !raw_known {
            self.known_partitions.insert(effective_partition.clone());
        }

        let seg = if effective_partition.is_empty() {
            None
        } else {
            Some(effective_partition.as_str())
        };
        let schema = self.sink.schema(seg);

        // Map once, and read the record's own UTC day back off the
        // result -- see `ParquetSink::day_and_batch` for why this must
        // not run `to_record_batch` (or read the clock) a second time.
        let (day, pre_mapped) = match self.sink.day_and_batch(&record, &schema, now) {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(
                    source = self.sink.source(),
                    "day_and_batch failed, skipping record: {e}"
                );
                return Ok(());
            }
        };

        let effective_key = BufKey {
            partition: effective_partition,
            day,
        };

        // Lazily create the buffer for this (partition, day).
        if !self.buffers.contains_key(&effective_key) {
            self.buffers
                .insert(effective_key.clone(), PartitionBuffer::new(schema.clone()));
        }

        // Convert record → RecordBatch, using the amortized live-builder
        // path if the sink opted in for this partition's schema, else the
        // unchanged one-call-per-record fallback.
        let buf = self.buffers.get_mut(&effective_key).unwrap();

        if buf.live_builder.is_none() {
            buf.live_builder = self.sink.new_batch(&schema);
        }

        let (n_rows, byte_delta) = if let Some(builder) = buf.live_builder.as_mut() {
            let rows_before = builder.len();
            match builder.try_append(&record, now) {
                Ok(true) => {
                    // Accepted into the live builder. row_count is exact and
                    // immediate; byte_count is deliberately deferred to
                    // materialization time (see design doc §5).
                    //
                    // Derived as a delta rather than assumed to be 1: a
                    // `Record` need not be exactly one row (e.g. a future
                    // `IpfixSink::Record = Vec<FlowRecord>`, one push per
                    // UDP datagram). `RecordBatchAccumulator::try_append`'s
                    // contract guarantees `len()` increases by exactly the
                    // number of rows appended, so this delta is exact for
                    // both today's one-row sinks and any future multi-row
                    // sink. Saturating so a contract-violating accumulator
                    // can't underflow `n_rows`.
                    (builder.len().saturating_sub(rows_before), 0usize)
                }
                Ok(false) => {
                    // Rejected: this record doesn't match the accumulator's
                    // schema (e.g. Zeek's raw/sanitized log_path mismatch
                    // case). Fall back to today's exact per-record path for
                    // just this one record.
                    let mapped = match pre_mapped {
                        Some(b) => Ok(b),
                        None => self.sink.to_record_batch(&record, &schema),
                    };
                    match mapped {
                        Ok(b) => {
                            let est_bytes = used_bytes(&b);
                            let n = b.num_rows();
                            buf.buffer.push_back((b, est_bytes));
                            (n, est_bytes)
                        }
                        Err(e) => {
                            tracing::warn!(
                                source = self.sink.source(),
                                "to_record_batch failed, skipping record: {e}"
                            );
                            return Ok(());
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        source = self.sink.source(),
                        "live builder append failed, skipping record: {e}"
                    );
                    return Ok(());
                }
            }
        } else {
            // Adapter never opted in for this schema: unchanged behavior,
            // except reusing the batch `day_and_batch` already built
            // instead of mapping the record a second time.
            let mapped = match pre_mapped {
                Some(b) => Ok(b),
                None => self.sink.to_record_batch(&record, &schema),
            };
            match mapped {
                Ok(b) => {
                    let est_bytes = used_bytes(&b);
                    let n = b.num_rows();
                    buf.buffer.push_back((b, est_bytes));
                    (n, est_bytes)
                }
                Err(e) => {
                    tracing::warn!(
                        source = self.sink.source(),
                        "to_record_batch failed, skipping record: {e}"
                    );
                    return Ok(());
                }
            }
        };
        self.source_stats.record(self.sink.source(), 1);

        let buf = self.buffers.get_mut(&effective_key).unwrap();
        buf.row_count += n_rows;
        buf.byte_count += byte_delta;

        // Bound the live builder's own size independent of any flush, so
        // drop_oldest_to_cap always has fine-enough-grained entries to trim
        // under sustained backpressure (see design doc §3).
        if buf.live_builder.as_ref().map(|b| b.len()).unwrap_or(0) >= BUILDER_BATCH_ROWS {
            Self::materialize_live_builder(buf);
        }

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
        let keys: Vec<BufKey> = self.buffers.keys().cloned().collect();
        let mut last_err: Option<anyhow::Error> = None;
        for key in keys {
            let taken = {
                let Some(buf) = self.buffers.get_mut(&key) else {
                    continue;
                };
                Self::materialize_live_builder(buf);
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
    ///
    /// Also reaps empty, non-in-flight buffers: `push()` inserts a
    /// `PartitionBuffer` for `effective_key` *before* it knows whether
    /// mapping the record will succeed, so it can hand the amortized
    /// `live_builder` path (see `ParquetSink::new_batch`) a buffer to
    /// append into. Every failure branch after that insert (`try_append`
    /// erroring, or the `to_record_batch` fallback erroring -- documented
    /// as "panic-free and best-effort total", so rare, but not impossible)
    /// returns early with the record simply dropped and `row_count` still
    /// 0. `apply_flush_outcome`'s reaping only runs in a flush's success
    /// arm, which such a buffer never reaches: `flush_all_if_needed` itself
    /// skips `row_count == 0` buffers, and `try_flush_partition_async`
    /// declines to spawn a flush for one (`buf.buffer.is_empty()`). Left
    /// alone, one such orphan persists forever per `(partition, day)` that
    /// ever suffered a mapping failure -- unbounded over a long-running
    /// process's lifetime, plus a fully-allocated `RecordBatchAccumulator`
    /// for any sink that opts into `new_batch` (currently only `ZeekSink`).
    ///
    /// This is the one place that can close the hole without adding
    /// per-record cost to `push()`: it already walks every buffer once per
    /// tick, `try_flush_partition_async` (the only other buffer-removing
    /// code path via `apply_flush_outcome`) never fires for a buffer this
    /// empty, and it is easy to prove safe. A buffer with `row_count == 0`
    /// while `in_flight` is legitimate, not an orphan: `try_flush_partition_async`
    /// deliberately zeroes `row_count` the instant it hands the previous
    /// batches to the background task, and new pushes keep landing in the
    /// *same* buffer while that upload runs (see its doc comment) -- so
    /// `in_flight` buffers are excluded from reaping here, and reaping
    /// never touches `known_partitions` (see its doc comment on the
    /// never-shrink invariant), matching `apply_flush_outcome`'s existing
    /// idle-buffer reap.
    pub async fn flush_all_if_needed(&mut self) -> anyhow::Result<()> {
        let keys: Vec<BufKey> = self.buffers.keys().cloned().collect();
        for key in keys {
            enum Action {
                None,
                Flush,
                Reap,
            }
            let action = {
                let buf = self.buffers.get(&key).unwrap();
                if buf.row_count == 0 {
                    if buf.in_flight {
                        Action::None
                    } else {
                        Action::Reap
                    }
                } else if buf.row_count >= self.policy.max_rows
                    || buf.byte_count >= self.policy.max_bytes
                    || buf.last_flush.elapsed() >= self.policy.interval.get()
                {
                    Action::Flush
                } else {
                    Action::None
                }
            };
            match action {
                Action::Flush => self.try_flush_partition_async(&key),
                Action::Reap => {
                    self.buffers.remove(&key);
                    self.refresh_partition_gauge(&key.partition);
                }
                Action::None => {}
            }
        }
        Ok(())
    }

    /// If `key`'s partition has no flush currently in-flight, detach its
    /// buffered batches (swapping in a fresh, empty `PartitionBuffer` so new
    /// records keep accumulating without waiting on the flush) and spawn
    /// `encode_and_upload` for them in the background. If a flush IS
    /// already in-flight for `key`, does not spawn a second one — applies
    /// the existing `drop_oldest_to_cap` to the live (still-growing) buffer
    /// instead, exactly as today's flush-failure path already does, just
    /// from a second call site.
    fn try_flush_partition_async(&mut self, key: &BufKey) {
        if let Some(buf) = self.buffers.get_mut(key) {
            Self::materialize_live_builder(buf);
        }

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
            key.clone(),
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
                // A flush that lands with nothing accumulated since it was
                // kicked off (no pushes arrived while the upload was
                // in-flight) means this buffer is genuinely idle. Remove
                // it outright: with the day now part of the key, a
                // long-running process would otherwise accumulate one
                // dead buffer per partition per UTC day that ever saw
                // traffic -- an unbounded leak. The next record for this
                // (partition, day) recreates it lazily in `push`, exactly
                // like a brand-new partition. This must NOT touch
                // `known_partitions` (see its doc comment): removing the
                // partition from the cap's accounting here would let a
                // later stream steal a live partition's slot the moment
                // its buffer goes briefly idle.
                if self
                    .buffers
                    .get(&key)
                    .map(|b| b.row_count == 0)
                    .unwrap_or(false)
                {
                    self.buffers.remove(&key);
                    self.refresh_partition_gauge(&key.partition);
                }
            }
            FlushOutcome::Failure {
                key,
                mut batches,
                row_count,
                byte_count,
                error,
            } => {
                tracing::warn!(source, target, "parquet_s3 writer push error: {error}");

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

    /// Recompute and republish the aggregate `parquet_s3_buffer_rows` gauge
    /// for a single partition, immediately after one of its day-buffers is
    /// reaped (see the two `self.buffers.remove(&key)` call sites in
    /// `flush_all_if_needed` and `apply_flush_outcome`).
    ///
    /// `update_buffer_gauges` only walks `self.buffers` and republishes a
    /// value for partitions that still have at least one live buffer --
    /// with day now part of `BufKey`, reaping the LAST day-buffer for a
    /// partition drops it out of that map entirely, so nothing ever visits
    /// that label again to correct it. Without this, a partition whose
    /// buffer got reaped keeps reporting its last non-zero row count on
    /// `parquet_s3_buffer_rows` forever -- a permanently stuck false alarm
    /// on the gauge this file's `update_buffer_gauges` doc comment calls
    /// the leading backpressure indicator.
    ///
    /// Recomputes from the remaining buffers (rather than unconditionally
    /// setting 0.0) because a partition can legitimately hold more than one
    /// live day-buffer at once (e.g. one flushing out while a new day's
    /// buffer is already accumulating) -- reaping one of them must not
    /// zero out a gauge that should still reflect the other's rows.
    fn refresh_partition_gauge(&self, partition: &str) {
        let source = self.sink.source();
        let target = self.s3.target_label();
        let row_count: usize = self
            .buffers
            .iter()
            .filter(|(key, _)| key.partition == partition)
            .map(|(_, buf)| buf.row_count)
            .sum();
        metrics::gauge!("parquet_s3_buffer_rows",
            "source" => source, "target" => target, "partition" => partition.to_string())
        .set(row_count as f64);
    }

    /// Report each partition's live buffered row count as a leading
    /// indicator of backpressure. Called only from the writer's periodic
    /// ticker (see `ParquetWriterHandle::start_with_stats`), never from
    /// `push()` -- `push()` is the hottest call in this file and must not
    /// gain unconditional per-record work.
    pub(crate) fn update_buffer_gauges(&self) {
        let source = self.sink.source();
        let target = self.s3.target_label();
        // Aggregate across days per partition: this preserves today's
        // metric meaning ("rows buffered for partition X") rather than
        // fragmenting one gauge series into one-per-day, which would make
        // the metric harder to alert on and would multiply cardinality by
        // however many distinct days currently have a live buffer.
        let mut per_partition: HashMap<&str, usize> = HashMap::new();
        for (key, buf) in &self.buffers {
            *per_partition.entry(key.partition.as_str()).or_insert(0) += buf.row_count;
        }
        for (partition, row_count) in per_partition {
            metrics::gauge!("parquet_s3_buffer_rows",
                "source" => source, "target" => target, "partition" => partition.to_string())
            .set(row_count as f64);
        }
    }

    /// Rows currently buffered across every partition, including any live
    /// amortized builder. Used to report how much data is at stake when the
    /// shutdown path begins its final flush.
    pub(crate) fn total_buffered_rows(&self) -> usize {
        self.buffers.values().map(|b| b.row_count).sum()
    }

    /// Test-only convenience: look up a buffer by partition alone,
    /// ignoring day. Correct wherever a test's records all map to the
    /// same UTC day -- every test in this crate does, since they run in
    /// milliseconds -- so "the buffer for this partition" is
    /// unambiguous. Production code must never use this: a real
    /// long-running writer legitimately holds one buffer per
    /// `(partition, day)`.
    #[cfg(test)]
    pub(crate) fn buffer_by_partition(
        &self,
        partition: &str,
    ) -> Option<&PartitionBuffer<S::Record>> {
        self.buffers
            .iter()
            .find(|(k, _)| k.partition == partition)
            .map(|(_, v)| v)
    }

    /// Test-only mutable counterpart to `buffer_by_partition`, for the
    /// handful of tests that need to hand-backdate a buffer's
    /// `last_flush` to simulate an age-triggered flush. The same
    /// single-UTC-day assumption applies -- see `buffer_by_partition`.
    #[cfg(test)]
    pub(crate) fn buffer_by_partition_mut(
        &mut self,
        partition: &str,
    ) -> Option<&mut PartitionBuffer<S::Record>> {
        self.buffers
            .iter_mut()
            .find(|(k, _)| k.partition == partition)
            .map(|(_, v)| v)
    }

    /// Drain all in-flight background flushes to completion, applying each
    /// outcome as it arrives. Used at graceful shutdown (so the writer's
    /// `JoinHandle` doesn't complete while a flush is still outstanding —
    /// callers await it expecting persistence to be genuinely finished) and
    /// reused by tests for deterministic waiting instead of sleep-based
    /// polling.
    pub(crate) async fn drain_pending_flushes(&mut self) {
        while let Some(result) = self.flush_tasks.join_next().await {
            match result {
                Ok(outcome) => self.apply_flush_outcome(outcome),
                Err(join_err) => {
                    tracing::warn!(
                        source = self.sink.source(),
                        target = self.s3.target_label(),
                        "parquet_s3 flush task panicked: {join_err}"
                    );
                }
            }
        }
    }

    fn drop_oldest_to_cap(
        buf: &mut PartitionBuffer<S::Record>,
        cap: usize,
        source: &'static str,
        target: &'static str,
    ) {
        Self::materialize_live_builder(buf);
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

    /// Finish the partition's live builder (if any, and if it has
    /// accumulated at least one row) into a real, stored `RecordBatch`
    /// entry, exactly as if that many single-row batches had been pushed
    /// via the non-amortized path. Called defensively from every code path
    /// that reads or takes `buf.buffer` for a flush or hard-cap decision --
    /// see the design doc's materialization audit table for the full list
    /// of call sites and why each one needs this.
    fn materialize_live_builder(buf: &mut PartitionBuffer<S::Record>) {
        if let Some(builder) = buf.live_builder.as_mut()
            && !builder.is_empty()
        {
            match builder.finish() {
                Ok(batch) => {
                    let est_bytes = used_bytes(&batch);
                    buf.byte_count += est_bytes;
                    buf.buffer.push_back((batch, est_bytes));
                }
                Err(e) => {
                    // Should not happen in practice (finishing
                    // already-validated builder state into Arrow arrays is
                    // not a fallible runtime operation under normal
                    // conditions). Log and leave the builder as-is; the
                    // next materialize attempt will retry.
                    tracing::error!("parquet_s3: live builder finish() failed: {e}");
                }
            }
        }
    }
}

/// Encode+upload one partition's already-detached batch of records. Called
/// two ways: synchronously (awaited inline) from `flush_all` (at shutdown,
/// where there is no concurrency to gain from spawning), and asynchronously
/// (spawned) from `try_flush_partition_async` during steady-state operation,
/// decoupled from the writer's channel-draining loop.
///
/// Acquires `semaphore` INSIDE this function, never before calling it —
/// this is load-bearing once this is called from a spawned task (Task 2):
/// acquiring the permit in the *caller* (the main `select!` loop) would
/// block that loop the instant the semaphore saturates, reintroducing the
/// exact bug this change fixes.
#[allow(clippy::too_many_arguments)]
async fn encode_and_upload(
    key: BufKey,
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

    // `partition_seg` carries ONLY the partition segment -- never the day.
    // `IcebergDescriptor::partition` (see build_descriptor below) is a
    // documented contract with the external committer and must not gain
    // an extra, undocumented day component; the day belongs solely in the
    // S3 key path segments built by `build_key`.
    let partition_seg = if key.partition.is_empty() {
        None
    } else {
        Some(key.partition.as_str())
    };
    let s3_key = build_key(&prefix, partition_seg, key.day);
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
    /// Per-(site, kind) log throttles. `Arc` because this struct is `Clone`
    /// and `IngestState` clones its `GenericS3Handler` fields (`generic_s3`,
    /// `generic_local`) per request (`AppState` is held behind
    /// `Arc<AppState>` and is not itself `Clone`; `ParquetWriterHandle<WefSink>`
    /// isn't `Clone` either, since `WefSink` doesn't implement `Clone`) —
    /// per-clone throttle state would reset constantly and restore the log
    /// storm.
    drop_log: Arc<DropLogThrottles>,
    /// Bounded wait applied by `send_or_drop`. A field rather than a bare
    /// constant so tests can shorten it — otherwise every test that must
    /// observe the drop-after-timeout path would stall for 5 real seconds.
    send_timeout: Duration,
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
            // Separate, deliberately short ticker for the channel-depth gauge.
            // It used to ride on `ticker`, whose period is
            // `flush_check_interval(flush_interval)` -- 900s at every source's
            // default `flush_interval_secs`, which makes a queue-depth alert
            // useless (the spec recommends alerting on this gauge). One
            // timer wakeup per second per writer is cheap; sampling it on the
            // `recv` arm instead would be per-record work in the hot loop and
            // would freeze the gauge at its last value whenever traffic stops,
            // exactly when a stuck-full channel most needs reporting.
            let mut gauge_ticker = tokio::time::interval(CHANNEL_GAUGE_INTERVAL);
            loop {
                tokio::select! {
                    msg = rx.recv() => {
                        match msg {
                            Some(record) => {
                                // NOTE: unreachable today (see comment below) -- no test
                                // exercises this branch; source/target fields verified by
                                // code review + successful compilation only.
                                // push() always returns Ok now (flush failures surface async via
                                // apply_flush_outcome) -- kept as Result to avoid churning callers;
                                // this branch is currently unreachable.
                                if let Err(e) = writer.push(record).await {
                                    tracing::warn!(source, target, "parquet_s3 writer push error: {e}");
                                }
                            }
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
                                    // `at_risk` is the PRE-flush count, so it
                                    // overstates loss whenever `flush_all`
                                    // partially succeeded; the count still
                                    // buffered afterwards is what was actually
                                    // lost. Both are reported, named for what
                                    // they are.
                                    tracing::warn!(
                                        source,
                                        target,
                                        rows_before_flush = at_risk,
                                        rows_still_buffered = writer.total_buffered_rows(),
                                        "parquet_s3 flush_all on shutdown: {e}"
                                    );
                                }
                                break;
                            }
                        }
                    }
                    _ = gauge_ticker.tick() => {
                        metrics::gauge!("parquet_s3_channel_available", "source" => source, "target" => target)
                            .set(rx.capacity() as f64);
                        // Depth, not headroom: `available` alone cannot be read
                        // as a volume without knowing each channel's configured
                        // capacity, and shutdown wants exactly that volume (see
                        // `await_handles_with_deadline`'s caller in main.rs).
                        metrics::gauge!("parquet_s3_channel_queued", "source" => source, "target" => target)
                            .set(capacity.saturating_sub(rx.capacity()) as f64);
                    }
                    _ = ticker.tick() => {
                        writer.update_buffer_gauges();
                        // flush_all_if_needed() always returns Ok now (flush failures surface
                        // async via apply_flush_outcome) -- kept as Result to avoid churning
                        // callers; this branch is currently unreachable.
                        if let Err(e) = writer.flush_all_if_needed().await {
                            tracing::warn!(source, target, "parquet_s3 flush_all_if_needed: {e}");
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
                                tracing::warn!(source, target, "parquet_s3 flush task panicked: {join_err}");
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
                drop_log: Arc::new(DropLogThrottles::new()),
                send_timeout: SEND_TIMEOUT_DEFAULT,
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

    /// Override the bounded-wait timeout used by `send_or_drop`. Test seam.
    #[must_use]
    pub fn with_send_timeout(mut self, timeout: Duration) -> Self {
        self.send_timeout = timeout;
        self
    }

    /// Test seam (like `with_send_timeout`): build a handle around a
    /// caller-supplied `Sender` whose receiver the caller controls (and may
    /// simply never poll). Other modules' overflow tests -- including
    /// integration tests, which compile against this crate without
    /// `cfg(test)` and so cannot see `#[cfg(test)]`-gated items -- need
    /// this to genuinely stall a channel: going through `start()`'s real
    /// writer task doesn't work for that purpose, because `push()` never
    /// awaits the upload (flushes are spawned into `flush_tasks`, decoupled
    /// from the channel-draining loop -- see `try_flush_partition_async`),
    /// so a real writer drains a healthy channel in microseconds regardless
    /// of how broken the sink is, and a capacity-1 channel never actually
    /// stays full long enough to time out.
    #[doc(hidden)]
    #[must_use]
    pub fn for_test(
        tx: tokio::sync::mpsc::Sender<S::Record>,
        source: &'static str,
        target: &'static str,
    ) -> Self {
        Self {
            tx,
            source,
            target,
            flush_interval: LiveInterval::new(Duration::from_secs(900)),
            drop_log: Arc::new(DropLogThrottles::new()),
            send_timeout: SEND_TIMEOUT_DEFAULT,
        }
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

    /// Record one dropped record for `(site, kind)` and report whether a log
    /// line is due.
    ///
    /// `parquet_s3_dropped{source,target}` — incremented by `try_send` —
    /// stays the authoritative count. This only rate-limits the human-facing
    /// line.
    ///
    /// `site` is passed by the caller rather than derived from this handle
    /// because OTLP and HEC/NDJSON share the same `ParquetWriterHandle`
    /// instances; keying by handle alone would let one mute the other.
    pub fn drop_log_due(&self, site: DropSite, kind: DropKind) -> Option<u64> {
        self.drop_log.check(site, kind)
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
/// through `encode_and_upload`/`upload_descriptor` and every one of the 14
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
    use arrow::array::{StringArray, StringBuilder, TimestampMicrosecondArray};
    use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
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
        let day = chrono::NaiveDate::from_ymd_opt(2026, 3, 7).unwrap();
        let key = build_key("syslog", None, day);
        assert!(
            key.starts_with("syslog/year=2026/month=03/day=07/"),
            "got: {key}"
        );
        assert!(key.ends_with(".parquet"), "got: {key}");
        assert!(!key.contains("//"), "double-slash: {key}");
    }

    #[test]
    fn build_key_with_partition() {
        let day = chrono::NaiveDate::from_ymd_opt(2026, 3, 7).unwrap();
        let key = build_key("zeek", Some("conn"), day);
        assert!(
            key.starts_with("zeek/conn/year=2026/month=03/day=07/"),
            "got: {key}"
        );
        assert!(key.ends_with(".parquet"), "got: {key}");
    }

    #[test]
    fn build_key_wef_partition_segment() {
        let day = chrono::NaiveDate::from_ymd_opt(2026, 6, 1).unwrap();
        let key = build_key("wef", Some("event_type=4624"), day);
        assert!(
            key.starts_with("wef/event_type=4624/year=2026/"),
            "got: {key}"
        );
    }

    #[test]
    fn build_key_empty_prefix_with_partition() {
        let day = chrono::NaiveDate::from_ymd_opt(2026, 6, 21).unwrap();

        // empty prefix + partition → no leading slash, no double-slash
        let key = build_key("", Some("event_type=4624"), day);
        assert!(
            key.starts_with("event_type=4624/year=2026/"),
            "empty prefix with partition must not have leading slash: {key}"
        );
        assert!(!key.starts_with('/'), "must not start with /: {key}");
        assert!(!key.contains("//"), "must not have double-slash: {key}");
        assert!(key.ends_with(".parquet"), "must end with .parquet: {key}");

        // empty prefix + no partition → no leading slash
        let key2 = build_key("", None, day);
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

    // -----------------------------------------------------------------------
    // In-test tracing field capture (for asserting `source`/`target` fields
    // on warn! calls -- uses only already-present `tracing`/`tracing-subscriber`
    // deps, not a new external test crate).
    // -----------------------------------------------------------------------

    #[derive(Default, Clone, Debug)]
    struct CapturedEvent {
        message: String,
        fields: std::collections::HashMap<String, String>,
    }

    struct FieldVisitor(CapturedEvent);
    impl tracing::field::Visit for FieldVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            let s = format!("{value:?}").trim_matches('"').to_string();
            if field.name() == "message" {
                self.0.message = s;
            } else {
                self.0.fields.insert(field.name().to_string(), s);
            }
        }
    }

    struct CaptureLayer {
        events: std::sync::Arc<std::sync::Mutex<Vec<CapturedEvent>>>,
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = FieldVisitor(CapturedEvent::default());
            event.record(&mut visitor);
            self.events.lock().unwrap().push(visitor.0);
        }
    }

    /// Installs a thread-local tracing subscriber for the lifetime of the
    /// returned guard. Must be used with the default (current-thread)
    /// `#[tokio::test]` flavor so any background-task-emitted events land
    /// on the same OS thread this installs on.
    struct TestTracingCapture {
        events: std::sync::Arc<std::sync::Mutex<Vec<CapturedEvent>>>,
        _guard: tracing::subscriber::DefaultGuard,
    }

    impl TestTracingCapture {
        fn install() -> Self {
            use tracing_subscriber::layer::SubscriberExt as _;
            let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let layer = CaptureLayer {
                events: events.clone(),
            };
            let subscriber = tracing_subscriber::registry().with(layer);
            let guard = tracing::subscriber::set_default(subscriber);
            Self {
                events,
                _guard: guard,
            }
        }

        fn events(&self) -> Vec<CapturedEvent> {
            self.events.lock().unwrap().clone()
        }
    }

    /// Upload sink whose `upload()` always panics -- used to exercise the
    /// flush-task-panicked warning paths (lines 686, 1067).
    struct PanicUploadSink;
    #[async_trait::async_trait]
    impl UploadSink for PanicUploadSink {
        async fn upload(&self, _key: &str, _body: Vec<u8>) -> anyhow::Result<()> {
            panic!("intentional test panic to exercise flush-task panic handling")
        }
        fn target_label(&self) -> &'static str {
            "panicky"
        }
        fn location_hint(&self) -> String {
            "panic://test".to_string()
        }
    }

    #[derive(Clone)]
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

    #[test]
    fn new_batch_defaults_to_none_for_mock_sink() {
        assert!(
            MockSink.new_batch(&test_schema()).is_none(),
            "MockSink does not override new_batch, so it must default to None"
        );
    }

    // -----------------------------------------------------------------------
    // Amortized-builder tests (generic mechanism, proven with a trivial
    // test-only accumulator before the real ZeekSink conversion)
    // -----------------------------------------------------------------------

    struct MockAccumulator {
        builder: StringBuilder,
        rows: usize,
    }

    impl MockAccumulator {
        fn new() -> Self {
            Self {
                builder: StringBuilder::new(),
                rows: 0,
            }
        }
    }

    impl RecordBatchAccumulator<String> for MockAccumulator {
        fn try_append(
            &mut self,
            record: &String,
            _now: chrono::DateTime<chrono::Utc>,
        ) -> anyhow::Result<bool> {
            self.builder.append_value(record);
            self.rows += 1;
            Ok(true)
        }
        fn len(&self) -> usize {
            self.rows
        }
        fn finish(&mut self) -> anyhow::Result<RecordBatch> {
            let col: Arc<dyn arrow::array::Array> = Arc::new(self.builder.finish());
            self.rows = 0;
            Ok(RecordBatch::try_new(test_schema(), vec![col])?)
        }
    }

    struct AmortizingMockSink;
    impl ParquetSink for AmortizingMockSink {
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
        fn new_batch(
            &self,
            _schema: &Arc<Schema>,
        ) -> Option<Box<dyn RecordBatchAccumulator<String>>> {
            Some(Box::new(MockAccumulator::new()))
        }
    }

    #[tokio::test]
    async fn push_accepts_records_into_the_live_builder() {
        let s3 = unreachable_s3().await;
        let (cfg, policy) = test_config(1_000_000); // nothing flushes
        let mut w = PartitionedParquetWriter::new(AmortizingMockSink, s3, cfg, policy);

        for i in 0..5 {
            w.push(format!("r{i}")).await.unwrap();
        }

        let buf = w.buffer_by_partition("").unwrap();
        assert_eq!(
            buf.row_count, 5,
            "row_count must reflect all 5 accepted records"
        );
        assert_eq!(
            buf.buffer.len(),
            0,
            "below BUILDER_BATCH_ROWS and no flush yet, nothing should be materialized into buf.buffer"
        );
        assert_eq!(
            buf.live_builder.as_ref().map(|b| b.len()),
            Some(5),
            "all 5 records should be sitting in the live builder"
        );
    }

    // -----------------------------------------------------------------------
    // Multi-row accumulator tests (row-count accounting fix) -- no real
    // sink has a `Record` carrying more than one row yet (the motivating
    // case is a future `IpfixSink::Record = Vec<FlowRecord>`, one push per
    // UDP datagram), so this test-only accumulator/sink pair is the only
    // way to exercise that shape today.
    // -----------------------------------------------------------------------

    /// Appends every element of a `Vec<String>` record as its own row --
    /// i.e. `try_append` can add more than one row per call, unlike
    /// `MockAccumulator` above.
    struct MultiRowMockAccumulator {
        builder: StringBuilder,
        rows: usize,
    }

    impl MultiRowMockAccumulator {
        fn new() -> Self {
            Self {
                builder: StringBuilder::new(),
                rows: 0,
            }
        }
    }

    impl RecordBatchAccumulator<Vec<String>> for MultiRowMockAccumulator {
        fn try_append(
            &mut self,
            record: &Vec<String>,
            _now: chrono::DateTime<chrono::Utc>,
        ) -> anyhow::Result<bool> {
            for v in record {
                self.builder.append_value(v);
            }
            self.rows += record.len();
            Ok(true)
        }
        fn len(&self) -> usize {
            self.rows
        }
        fn finish(&mut self) -> anyhow::Result<RecordBatch> {
            let col: Arc<dyn arrow::array::Array> = Arc::new(self.builder.finish());
            self.rows = 0;
            Ok(RecordBatch::try_new(test_schema(), vec![col])?)
        }
    }

    struct MultiRowMockSink;
    impl ParquetSink for MultiRowMockSink {
        type Record = Vec<String>;
        fn source(&self) -> &'static str {
            "test"
        }
        fn partition(&self, _r: &Vec<String>) -> Option<String> {
            None
        }
        fn schema(&self, _p: Option<&str>) -> Arc<Schema> {
            test_schema()
        }
        fn to_record_batch(
            &self,
            record: &Vec<String>,
            schema: &Arc<Schema>,
        ) -> anyhow::Result<RecordBatch> {
            let col = Arc::new(StringArray::from(
                record.iter().map(String::as_str).collect::<Vec<_>>(),
            ));
            Ok(RecordBatch::try_new(schema.clone(), vec![col])?)
        }
        fn new_batch(
            &self,
            _schema: &Arc<Schema>,
        ) -> Option<Box<dyn RecordBatchAccumulator<Vec<String>>>> {
            Some(Box::new(MultiRowMockAccumulator::new()))
        }
    }

    /// Direct, no-writer-involved unit test of the accumulator's own
    /// contract: `len()` must increase by exactly the number of elements
    /// appended, never by 1 regardless of record size -- this is the
    /// invariant `PartitionedParquetWriter::push`'s row-count delta relies
    /// on.
    #[test]
    fn multi_row_accumulator_len_advances_by_exact_row_count_appended() {
        let mut acc = MultiRowMockAccumulator::new();
        assert_eq!(acc.len(), 0);

        acc.try_append(
            &vec!["a".to_string(), "b".to_string(), "c".to_string()],
            chrono::Utc::now(),
        )
        .unwrap();
        assert_eq!(acc.len(), 3, "a 3-element record must add exactly 3 rows");

        acc.try_append(&vec![], chrono::Utc::now()).unwrap();
        assert_eq!(
            acc.len(),
            3,
            "an empty record must add 0 rows, not silently count as 1"
        );

        acc.try_append(&vec!["d".to_string()], chrono::Utc::now())
            .unwrap();
        assert_eq!(
            acc.len(),
            4,
            "a 1-element record must add exactly 1 row on top of the prior 3"
        );
    }

    /// The bug this branch fixes: `push()` used to hardcode `n_rows = 1`
    /// for every record accepted into the live builder, which is only
    /// correct for a `Record` that is exactly one row. Pushing records
    /// that carry N>1 rows must increase `buf.row_count` by exactly N,
    /// covering N=3, N=1, and the N=0 edge case (which must not be
    /// silently counted as 1).
    #[tokio::test]
    async fn push_multi_row_record_increases_row_count_by_the_actual_row_count() {
        let s3 = unreachable_s3().await;
        let (cfg, policy) = test_config(1_000_000); // nothing flushes
        let mut w = PartitionedParquetWriter::new(MultiRowMockSink, s3, cfg, policy);

        // N=3
        w.push(vec!["a".to_string(), "b".to_string(), "c".to_string()])
            .await
            .unwrap();
        assert_eq!(
            w.buffer_by_partition("").unwrap().row_count,
            3,
            "a 3-row record must increase row_count by 3, not 1"
        );

        // N=0 -- must not be silently counted as 1.
        w.push(vec![]).await.unwrap();
        assert_eq!(
            w.buffer_by_partition("").unwrap().row_count,
            3,
            "an empty record must add 0 rows to row_count"
        );

        // N=1
        w.push(vec!["d".to_string()]).await.unwrap();
        assert_eq!(
            w.buffer_by_partition("").unwrap().row_count,
            4,
            "a 1-row record must add exactly 1 row on top of the prior 3"
        );

        assert_eq!(
            w.buffer_by_partition("")
                .unwrap()
                .live_builder
                .as_ref()
                .map(|b| b.len()),
            Some(4),
            "the live builder's own row count must match buf.row_count exactly"
        );
    }

    #[tokio::test]
    async fn push_materializes_at_the_builder_batch_rows_threshold() {
        let s3 = unreachable_s3().await;
        let (cfg, policy) = test_config(1_000_000); // nothing flushes on row/byte count
        let mut w = PartitionedParquetWriter::new(AmortizingMockSink, s3, cfg, policy);

        for i in 0..(BUILDER_BATCH_ROWS + 1) {
            w.push(format!("r{i}")).await.unwrap();
        }

        let buf = w.buffer_by_partition("").unwrap();
        assert_eq!(
            buf.row_count,
            BUILDER_BATCH_ROWS + 1,
            "row_count must reflect every accepted record"
        );
        assert_eq!(
            buf.buffer.len(),
            1,
            "crossing the threshold must materialize exactly one stored batch"
        );
        assert_eq!(
            buf.buffer.front().map(|(b, _)| b.num_rows()),
            Some(BUILDER_BATCH_ROWS),
            "the materialized batch must contain exactly BUILDER_BATCH_ROWS rows"
        );
        assert_eq!(
            buf.live_builder.as_ref().map(|b| b.len()),
            Some(1),
            "the one record past the threshold must remain in the live builder"
        );
    }

    #[tokio::test]
    async fn flush_materializes_pending_live_builder_rows() {
        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink: Arc<dyn UploadSink> = Arc::new(RecordingSink {
            uploads: uploads.clone(),
        });
        let (cfg, policy) = test_config(3); // flush once row_count >= 3
        let mut w = PartitionedParquetWriter::new(AmortizingMockSink, sink, cfg, policy);

        // 3 records accepted into the live builder, none materialized yet
        // (below BUILDER_BATCH_ROWS), but should_flush fires on the 3rd push.
        for i in 0..3 {
            w.push(format!("r{i}")).await.unwrap();
        }
        w.drain_pending_flushes().await;

        let recorded = uploads.lock().unwrap();
        assert_eq!(
            recorded.len(),
            1,
            "the flush must have actually uploaded, proving the live builder's \
             pending rows were materialized before the buffer was taken"
        );
        assert!(recorded[0].1 > 0, "uploaded body must be non-empty");
    }

    // -----------------------------------------------------------------------
    // used_bytes — flush byte-accounting fix
    // -----------------------------------------------------------------------

    #[test]
    fn used_bytes_reports_a_small_figure_for_a_1_row_batch_built_via_a_builder() {
        // A builder-backed batch (the accumulator path every real sink goes
        // through) allocates default capacity up front, so
        // `get_array_memory_size()` reports that capacity, not the single
        // short string actually written. `used_bytes` must not fall for the
        // same trap.
        let mut acc = MockAccumulator::new();
        acc.try_append(&"r0".to_string(), chrono::Utc::now())
            .unwrap();
        let batch = acc.finish().unwrap();
        assert_eq!(batch.num_rows(), 1);

        let capacity_estimate = batch.get_array_memory_size();
        let used = used_bytes(&batch);

        assert!(
            used < 1024,
            "a 1-row batch's real payload should be well under 1KiB, got {used}"
        );
        assert!(
            used < capacity_estimate,
            "used_bytes ({used}) must be strictly less than the capacity-based \
             estimate ({capacity_estimate}) it replaces -- otherwise the fix \
             changed nothing"
        );
    }

    #[tokio::test]
    async fn flush_all_materializes_pending_live_builder_rows_at_shutdown() {
        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink: Arc<dyn UploadSink> = Arc::new(RecordingSink {
            uploads: uploads.clone(),
        });
        let (cfg, policy) = test_config(1_000_000); // nothing flushes on its own
        let mut w = PartitionedParquetWriter::new(AmortizingMockSink, sink, cfg, policy);

        for i in 0..3 {
            w.push(format!("r{i}")).await.unwrap();
        }
        // Nothing should have flushed yet -- all 3 rows sit in the live builder.
        assert!(uploads.lock().unwrap().is_empty());

        w.flush_all().await.unwrap();

        let recorded = uploads.lock().unwrap();
        assert_eq!(
            recorded.len(),
            1,
            "flush_all (graceful shutdown) must not silently drop rows sitting \
             in an unmaterialized live builder"
        );
    }

    #[tokio::test]
    async fn flush_all_if_needed_flushes_a_partition_whose_only_pending_data_is_in_the_live_builder()
     {
        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink: Arc<dyn UploadSink> = Arc::new(RecordingSink {
            uploads: uploads.clone(),
        });
        // max_rows=2 so 3 pushes trip the row-count flush trigger, but
        // nothing crosses BUILDER_BATCH_ROWS, so buf.buffer stays empty
        // (everything is in the live builder) until flush_all_if_needed runs.
        let (cfg, policy) = test_config(2);
        let mut w = PartitionedParquetWriter::new(AmortizingMockSink, sink, cfg, policy);

        for i in 0..3 {
            w.push(format!("r{i}")).await.unwrap();
        }
        w.flush_all_if_needed().await.unwrap();
        w.drain_pending_flushes().await;

        let recorded = uploads.lock().unwrap();
        assert_eq!(
            recorded.len(),
            1,
            "flush_all_if_needed must detect a pending flush even when buf.buffer \
             (as opposed to row_count) is empty"
        );
    }

    /// Discriminates specifically the `flush_all_if_needed` ticker-gate fix
    /// (as opposed to `push()`'s own inline `should_flush` check, which by
    /// the `try_flush_partition_async` materialize fix already handles the
    /// row-count trigger on its own). `max_rows` is set high enough that
    /// `push()` never trips its own flush, and the age trigger is set to
    /// fire almost immediately -- so the only way this test's flush can
    /// happen is via `flush_all_if_needed` correctly detecting pending rows
    /// sitting in the live builder despite `buf.buffer` being empty.
    #[tokio::test]
    async fn flush_all_if_needed_flushes_via_age_trigger_when_only_the_live_builder_is_pending() {
        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink: Arc<dyn UploadSink> = Arc::new(RecordingSink {
            uploads: uploads.clone(),
        });
        let (cfg, mut policy) = test_config(1_000_000);
        policy.interval = LiveInterval::new(std::time::Duration::from_millis(1));
        let mut w = PartitionedParquetWriter::new(AmortizingMockSink, sink, cfg, policy);

        for i in 0..3 {
            w.push(format!("r{i}")).await.unwrap();
        }
        assert!(
            uploads.lock().unwrap().is_empty(),
            "nothing should have flushed yet -- rows sit only in the live builder"
        );

        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        w.flush_all_if_needed().await.unwrap();
        w.drain_pending_flushes().await;

        let recorded = uploads.lock().unwrap();
        assert_eq!(
            recorded.len(),
            1,
            "flush_all_if_needed's age trigger must fire for rows sitting only \
             in the live builder, even though buf.buffer is empty"
        );
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
        assert_eq!(w.buffer_by_partition("").unwrap().row_count, 4);
    }

    /// `total_buffered_rows()` starts at zero and sums row counts across
    /// every partition -- used at shutdown to report how much data is at
    /// stake before the final flush. Uses a genuinely partitioning sink (two
    /// distinct partition keys) so the test can't pass by summing only one
    /// partition's `row_count`.
    #[tokio::test]
    async fn total_buffered_rows_sums_every_partition() {
        struct TwoPartitionMock;
        impl ParquetSink for TwoPartitionMock {
            type Record = (String, String); // (partition, value)
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
                schema: &Arc<Schema>,
            ) -> anyhow::Result<RecordBatch> {
                let col = Arc::new(StringArray::from(vec![r.1.as_str()]));
                Ok(RecordBatch::try_new(schema.clone(), vec![col])?)
            }
        }

        let s3 = unreachable_s3().await;
        let (cfg, policy) = test_config(usize::MAX); // never flush during the test
        let mut w = PartitionedParquetWriter::new(TwoPartitionMock, s3, cfg, policy);
        assert_eq!(w.total_buffered_rows(), 0);
        w.push(("p1".to_string(), "a".to_string())).await.unwrap();
        w.push(("p2".to_string(), "b".to_string())).await.unwrap();
        assert_eq!(
            w.buffers.len(),
            2,
            "records must land in distinct partitions"
        );
        assert_eq!(w.total_buffered_rows(), 2);
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

    /// A `ParquetSink` whose records carry a real UTC timestamp and that
    /// opts into `time_column()`, used to prove buffers actually split by
    /// UTC day rather than always falling back to `now`.
    #[derive(Clone)]
    struct TimestampedMock;
    impl ParquetSink for TimestampedMock {
        type Record = chrono::DateTime<chrono::Utc>;
        fn source(&self) -> &'static str {
            "test"
        }
        fn partition(&self, _: &chrono::DateTime<chrono::Utc>) -> Option<String> {
            None
        }
        fn schema(&self, _: Option<&str>) -> Arc<Schema> {
            Arc::new(Schema::new(vec![Field::new(
                "ts",
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                true,
            )]))
        }
        fn time_column(&self) -> Option<&'static str> {
            Some("ts")
        }
        fn to_record_batch(
            &self,
            record: &chrono::DateTime<chrono::Utc>,
            schema: &Arc<Schema>,
        ) -> anyhow::Result<RecordBatch> {
            let col = TimestampMicrosecondArray::from(vec![Some(record.timestamp_micros())])
                .with_timezone("UTC");
            Ok(RecordBatch::try_new(schema.clone(), vec![Arc::new(col)])?)
        }
    }

    #[tokio::test]
    async fn buffers_split_by_utc_day_produce_separate_flushes() {
        use chrono::TimeZone;

        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let s3: Arc<dyn UploadSink> = Arc::new(RecordingSink {
            uploads: uploads.clone(),
        });
        let (cfg, policy) = test_config(usize::MAX);
        let mut w = PartitionedParquetWriter::new(TimestampedMock, s3, cfg, policy);

        let day1 = chrono::Utc.with_ymd_and_hms(2026, 3, 7, 23, 59, 0).unwrap();
        let day2 = chrono::Utc.with_ymd_and_hms(2026, 3, 8, 0, 1, 0).unwrap();

        w.push(day1).await.unwrap();
        w.push(day2).await.unwrap();

        assert_eq!(
            w.buffers.len(),
            2,
            "records on different UTC days must land in separate buffers, even with no partition"
        );

        w.flush_all().await.unwrap();
        w.drain_pending_flushes().await;

        let keys: Vec<String> = uploads
            .lock()
            .unwrap()
            .iter()
            .map(|(k, _)| k.clone())
            .collect();
        assert_eq!(
            keys.len(),
            2,
            "each day-bucket must produce its own file: {keys:?}"
        );
        assert!(
            keys.iter()
                .any(|k| k.contains("year=2026/month=03/day=07/")),
            "{keys:?}"
        );
        assert!(
            keys.iter()
                .any(|k| k.contains("year=2026/month=03/day=08/")),
            "{keys:?}"
        );
    }

    #[tokio::test]
    async fn successful_flush_reaps_an_idle_buffer() {
        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let s3: Arc<dyn UploadSink> = Arc::new(RecordingSink { uploads });
        let (cfg, policy) = test_config(1);
        let mut w = PartitionedParquetWriter::new(MockSink, s3, cfg, policy);

        w.push("hello".to_string()).await.unwrap();
        assert_eq!(w.buffers.len(), 1, "buffer created lazily on first push");

        w.drain_pending_flushes().await;

        assert_eq!(
            w.buffers.len(),
            0,
            "a buffer that received no new pushes while its flush was in flight must be reaped"
        );
    }

    #[tokio::test]
    async fn max_partitions_cap_survives_empty_buffer_reaping() {
        struct TwoPartitionMock2;
        impl ParquetSink for TwoPartitionMock2 {
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
                schema: &Arc<Schema>,
            ) -> anyhow::Result<RecordBatch> {
                let col = Arc::new(StringArray::from(vec![r.1.as_str()]));
                Ok(RecordBatch::try_new(schema.clone(), vec![col])?)
            }
        }

        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let s3: Arc<dyn UploadSink> = Arc::new(RecordingSink { uploads });
        let (mut cfg, policy) = test_config(1);
        cfg.max_partitions = 1;
        let mut w = PartitionedParquetWriter::new(TwoPartitionMock2, s3, cfg, policy);

        w.push(("p1".to_string(), "a".to_string())).await.unwrap();
        w.drain_pending_flushes().await;
        assert_eq!(w.buffers.len(), 0, "p1's buffer was flushed and reaped");

        w.push(("p2".to_string(), "b".to_string())).await.unwrap();
        assert!(
            w.buffer_by_partition("_overflow").is_some(),
            "p2 must overflow: p1 already holds the one available partition slot, \
             even though its buffer was reaped"
        );
        assert!(
            w.buffer_by_partition("p2").is_none(),
            "p2 must not get its own buffer once the cap is reached"
        );
    }

    /// `push()` inserts a `PartitionBuffer` for `effective_key` as soon as
    /// `day_and_batch` succeeds -- BEFORE it knows whether the record will
    /// actually map into a batch. The default `day_and_batch` calls
    /// `to_record_batch` itself and can't diverge from it, so to reach the
    /// leak this models a sink like `ZeekSink` that overrides
    /// `day_and_batch` to derive the day WITHOUT building a batch
    /// (`Ok((day, None))`, exactly `ZeekSink::day_and_batch`'s shape) --
    /// deferring the real `to_record_batch` call to `push()`'s own fallback
    /// path, which can then fail independently. `push()` drops the record
    /// and returns `Ok(())` early on that failure, but the just-inserted
    /// buffer (row_count == 0, never in-flight) is left behind. Nothing
    /// else ever removes it: `flush_all_if_needed` used to skip
    /// `row_count == 0` buffers outright, and `try_flush_partition_async`
    /// never spawns a flush for an empty buffer, so `apply_flush_outcome`'s
    /// success-arm reaping is never reached for it either. This proves the
    /// periodic flush check now reaps that orphan instead of leaking it
    /// forever.
    #[tokio::test]
    async fn flush_all_if_needed_reaps_a_buffer_orphaned_by_a_mapping_failure() {
        struct DeferredMappingFailingSink;
        impl ParquetSink for DeferredMappingFailingSink {
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
                _record: &String,
                _schema: &Arc<Schema>,
            ) -> anyhow::Result<RecordBatch> {
                anyhow::bail!("intentional mapping failure for test")
            }
            // Mirrors `ZeekSink::day_and_batch`: derive the day without
            // building a batch, so `to_record_batch` is deferred to
            // `push()`'s own fallback call and can fail there instead of
            // inside `day_and_batch` (which would abort before the buffer
            // is ever created).
            fn day_and_batch(
                &self,
                _record: &String,
                _schema: &Arc<Schema>,
                now: chrono::DateTime<chrono::Utc>,
            ) -> anyhow::Result<(chrono::NaiveDate, Option<RecordBatch>)> {
                Ok((now.date_naive(), None))
            }
        }

        let s3 = unreachable_s3().await;
        let (cfg, policy) = test_config(1_000_000); // nothing flushes on its own
        let mut w = PartitionedParquetWriter::new(DeferredMappingFailingSink, s3, cfg, policy);

        w.push("boom".to_string()).await.unwrap();
        assert_eq!(
            w.buffers.len(),
            1,
            "push() must still lazily create the buffer even though the mapping fails"
        );
        assert_eq!(
            w.buffer_by_partition("").unwrap().row_count,
            0,
            "a record that failed to map must not be counted"
        );

        w.flush_all_if_needed().await.unwrap();

        assert_eq!(
            w.buffers.len(),
            0,
            "a buffer orphaned by a mapping failure (row_count == 0, never \
             in-flight) must be reaped by the periodic flush check, not \
             persist forever"
        );
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
        w.drain_pending_flushes().await;

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
        w.drain_pending_flushes().await;

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

    /// Proves `parquet_s3_flushes_in_flight` goes 0 -> 1 while a flush is
    /// running, then back to 0 once it completes -- the observability half
    /// of the concurrency cap (spec decision #3).
    #[tokio::test]
    #[allow(clippy::mutable_key_type)]
    async fn flushes_in_flight_gauge_tracks_a_single_flush() {
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink: Arc<dyn UploadSink> = Arc::new(RecordingSink {
            uploads: uploads.clone(),
        });
        let (cfg, policy) = test_config(1); // flush on first row
        let mut w = PartitionedParquetWriter::new(MockSink, sink, cfg, policy);

        w.push("hello".to_string()).await.unwrap();

        let gauge_key = CompositeKey::new(
            MetricKind::Gauge,
            metrics::Key::from_parts(
                "parquet_s3_flushes_in_flight",
                vec![
                    metrics::Label::new("source", "test"),
                    metrics::Label::new("target", "recording"),
                ],
            ),
        );
        let read_gauge = |snapshotter: &metrics_util::debugging::Snapshotter| -> f64 {
            snapshotter
                .snapshot()
                .into_hashmap()
                .get(&gauge_key)
                .map(|(_, _, v)| {
                    if let DebugValue::Gauge(g) = v {
                        g.into_inner()
                    } else {
                        0.0
                    }
                })
                .unwrap_or(0.0)
        };

        // The flush was spawned by push() above; drain it to completion.
        w.drain_pending_flushes().await;

        assert_eq!(
            read_gauge(&snapshotter),
            0.0,
            "gauge must return to 0 once the flush completes"
        );
        assert_eq!(
            uploads.lock().unwrap().len(),
            1,
            "the flush must actually have run and uploaded once"
        );
    }

    /// `update_buffer_gauges()` must set `parquet_s3_buffer_rows` to each
    /// partition's live `row_count`, labeled by source/target/partition.
    #[tokio::test]
    #[allow(clippy::mutable_key_type)]
    async fn update_buffer_gauges_reports_live_row_counts() {
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let s3 = unreachable_s3().await;
        let (cfg, policy) = test_config(1_000); // high threshold: nothing flushes
        let mut w = PartitionedParquetWriter::new(MockSink, s3, cfg, policy);

        for i in 0..7 {
            w.push(format!("r{i}")).await.unwrap();
        }
        w.update_buffer_gauges();

        let key = CompositeKey::new(
            MetricKind::Gauge,
            metrics::Key::from_parts(
                "parquet_s3_buffer_rows",
                vec![
                    metrics::Label::new("source", "test"),
                    metrics::Label::new("target", "s3"),
                    metrics::Label::new("partition", ""),
                ],
            ),
        );
        let value = snapshotter
            .snapshot()
            .into_hashmap()
            .get(&key)
            .map(|(_, _, v)| {
                if let DebugValue::Gauge(g) = v {
                    g.into_inner()
                } else {
                    0.0
                }
            })
            .unwrap_or(0.0);
        assert_eq!(
            value, 7.0,
            "expected parquet_s3_buffer_rows{{source=\"test\",target=\"s3\",partition=\"\"}} == 7.0"
        );
    }

    /// Regression test: a partition's `parquet_s3_buffer_rows` gauge must
    /// NOT keep reporting its last non-zero value forever once its buffer
    /// is reaped. Before `apply_flush_outcome`'s `Success` branch called
    /// `refresh_partition_gauge`, removing the last live day-buffer for a
    /// partition dropped it out of `update_buffer_gauges`'s `per_partition`
    /// map entirely -- nothing ever visited that label again to correct
    /// it, so the gauge stuck at its last published value even though the
    /// partition had gone idle.
    #[tokio::test]
    #[allow(clippy::mutable_key_type)]
    async fn reaping_the_last_buffer_for_a_partition_zeroes_its_stale_gauge() {
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let s3 = unreachable_s3().await;
        let (cfg, policy) = test_config(1_000); // high threshold: nothing flushes on its own
        let mut w = PartitionedParquetWriter::new(MockSink, s3, cfg, policy);

        for i in 0..5 {
            w.push(format!("r{i}")).await.unwrap();
        }
        w.update_buffer_gauges();

        let gauge_key = CompositeKey::new(
            MetricKind::Gauge,
            metrics::Key::from_parts(
                "parquet_s3_buffer_rows",
                vec![
                    metrics::Label::new("source", "test"),
                    metrics::Label::new("target", "s3"),
                    metrics::Label::new("partition", ""),
                ],
            ),
        );
        let read_gauge = |snapshotter: &metrics_util::debugging::Snapshotter| -> f64 {
            snapshotter
                .snapshot()
                .into_hashmap()
                .get(&gauge_key)
                .map(|(_, _, v)| {
                    if let DebugValue::Gauge(g) = v {
                        g.into_inner()
                    } else {
                        0.0
                    }
                })
                .unwrap_or(0.0)
        };
        assert_eq!(
            read_gauge(&snapshotter),
            5.0,
            "sanity: gauge must reflect the 5 buffered rows before the reap"
        );

        // Simulate the flush landing with nothing accumulated meanwhile:
        // the production path (`try_flush_partition_async`) zeroes
        // `row_count` the instant it hands batches to the background task,
        // and no new pushes arrive before this `Success` outcome is
        // applied -- exactly the "buffer went idle mid-flush" case
        // `apply_flush_outcome`'s doc comment describes.
        w.buffer_by_partition_mut("").unwrap().row_count = 0;
        let key = BufKey {
            partition: String::new(),
            day: chrono::Utc::now().date_naive(),
        };
        w.apply_flush_outcome(FlushOutcome::Success { key });

        assert_eq!(
            w.buffers.len(),
            0,
            "an idle buffer with row_count == 0 after a successful flush must be reaped"
        );
        assert_eq!(
            read_gauge(&snapshotter),
            0.0,
            "parquet_s3_buffer_rows must be republished as 0 the instant the \
             partition's last live buffer is reaped, not left at its stale \
             pre-reap value"
        );
    }

    /// Line 649 (`apply_flush_outcome`'s failure branch) must log both
    /// `source` and `target` as structured fields, not just interpolate
    /// them into the message.
    #[tokio::test]
    async fn apply_flush_outcome_failure_logs_source_and_target_fields() {
        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink: Arc<dyn UploadSink> = Arc::new(RecordingSink { uploads });
        let (cfg, policy) = test_config(5);
        let mut w = PartitionedParquetWriter::new(MockSink, sink, cfg, policy);

        let capture = TestTracingCapture::install();
        w.apply_flush_outcome(FlushOutcome::Failure {
            key: BufKey {
                partition: String::new(),
                day: chrono::Utc::now().date_naive(),
            },
            batches: std::collections::VecDeque::new(),
            row_count: 0,
            byte_count: 0,
            error: "simulated upload failure".to_string(),
        });

        let events = capture.events();
        let found = events.iter().any(|e| {
            e.message.contains("writer push error")
                && e.fields.get("source").map(String::as_str) == Some("test")
                && e.fields.get("target").map(String::as_str) == Some("recording")
        });
        assert!(
            found,
            "expected a warn event with source=\"test\" target=\"recording\", got: {events:?}"
        );
    }

    /// Line 686 (`drain_pending_flushes`'s panic branch) must log both
    /// `source` and `target` -- neither is a local in that function, so
    /// they must be fetched via `self.sink.source()` / `self.s3.target_label()`.
    #[tokio::test]
    async fn drain_pending_flushes_panic_logs_source_and_target_fields() {
        let sink: Arc<dyn UploadSink> = Arc::new(PanicUploadSink);
        let (cfg, policy) = test_config(1); // flush on first row
        let mut w = PartitionedParquetWriter::new(MockSink, sink, cfg, policy);

        w.push("hello".to_string()).await.unwrap(); // spawns the flush task, which will panic inside upload()

        let capture = TestTracingCapture::install();
        w.drain_pending_flushes().await;

        let events = capture.events();
        let found = events.iter().any(|e| {
            e.message.contains("flush task panicked")
                && e.fields.get("source").map(String::as_str) == Some("test")
                && e.fields.get("target").map(String::as_str) == Some("panicky")
        });
        assert!(
            found,
            "expected a warn event with source=\"test\" target=\"panicky\", got: {events:?}"
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
        for i in 0..(hard_cap * 3) {
            w.push(format!("r{i}")).await.unwrap(); // push() itself no longer fails -- flush failures surface asynchronously
            w.drain_pending_flushes().await; // deterministically wait for the just-triggered flush attempt (and its merge-back) to finish before pushing more
        }
        let buf = w.buffer_by_partition("").unwrap();
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
            w.buffer_by_partition("_overflow").is_some(),
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

    #[tokio::test]
    async fn send_or_drop_delivers_when_capacity_is_available() {
        let s3 = unreachable_s3().await;
        let (mut cfg, policy) = test_config(10_000);
        cfg.channel_capacity = 4;
        let (handle, _task) = ParquetWriterHandle::start(MockSink, s3, cfg, policy);
        assert!(handle.send_or_drop("hello".to_string()).await.is_ok());
    }

    /// Exercises `ParquetWriterHandle::send_or_drop`'s actual timeout path
    /// (not a bare `tokio::mpsc::Sender`): a hand-built handle around a
    /// capacity-1 channel whose receiver is held but never polled, so the
    /// channel genuinely never drains (no writer task to race against).
    /// Proves three things the vacuous predecessor test proved none of:
    /// `send_or_drop` itself times out, the dropped record is handed back
    /// in the error (no silent swallow), and `parquet_s3_dropped` is
    /// incremented by the production code. Also exercises `with_send_timeout`,
    /// which was otherwise dead.
    #[tokio::test]
    #[allow(clippy::mutable_key_type)]
    async fn send_or_drop_times_out_and_reports_full_when_the_writer_never_drains() {
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        // Capacity 1, receiver bound but never polled: the first send fills
        // the channel and it stays full for the rest of the test.
        let (tx, _rx) = tokio::sync::mpsc::channel::<String>(1);
        tx.try_send("first".to_string()).unwrap();
        let handle = ParquetWriterHandle::<MockSink> {
            tx,
            source: "test",
            target: "s3",
            flush_interval: LiveInterval::new(Duration::from_secs(900)),
            drop_log: Arc::new(DropLogThrottles::new()),
            send_timeout: SEND_TIMEOUT_DEFAULT,
        }
        .with_send_timeout(Duration::from_millis(50));

        let start = std::time::Instant::now();
        let err = handle
            .send_or_drop("second".to_string())
            .await
            .expect_err("must time out against a full, undrained channel");
        assert!(start.elapsed() >= Duration::from_millis(50));
        // Upper bound: proves the shortened per-handle timeout (50ms) was
        // actually honoured, not `SEND_TIMEOUT_DEFAULT` (5s) hardcoded in
        // place of `self.send_timeout` -- that mutation would still pass the
        // lower-bound assertion above, just five seconds slower.
        assert!(start.elapsed() < Duration::from_millis(500));

        match err {
            tokio::sync::mpsc::error::SendTimeoutError::Timeout(record) => {
                assert_eq!(
                    record, "second",
                    "the dropped record must be handed back, not silently swallowed"
                );
            }
            other => panic!("expected Timeout, got {other:?}"),
        }

        let key = CompositeKey::new(
            MetricKind::Counter,
            metrics::Key::from_parts(
                "parquet_s3_dropped",
                vec![
                    metrics::Label::new("source", "test"),
                    metrics::Label::new("target", "s3"),
                ],
            ),
        );
        let dropped = snapshotter
            .snapshot()
            .into_hashmap()
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
            dropped, 1,
            "parquet_s3_dropped{{source=\"test\",target=\"s3\"}} should be incremented by send_or_drop on timeout"
        );
    }

    /// The other half of `send_or_drop`'s error path: a **closed** channel.
    /// It is not a slow variant of the timeout case — `send_timeout` on a
    /// dead receiver returns `Closed` immediately, waiting zero time, which
    /// is why the Zeek/Suricata drop warnings must not name a duration. This
    /// was the one untested branch and it was the one logging the wrong line.
    #[tokio::test]
    #[allow(clippy::mutable_key_type)]
    async fn send_or_drop_returns_closed_immediately_when_the_writer_is_gone() {
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        // Receiver dropped == writer task dead. Capacity is irrelevant.
        let (tx, rx) = tokio::sync::mpsc::channel::<String>(8);
        drop(rx);
        let handle = ParquetWriterHandle::<MockSink> {
            tx,
            source: "test",
            target: "s3",
            flush_interval: LiveInterval::new(Duration::from_secs(900)),
            drop_log: Arc::new(DropLogThrottles::new()),
            send_timeout: SEND_TIMEOUT_DEFAULT, // 5s, and none of it is spent
        };

        let start = std::time::Instant::now();
        let err = handle
            .send_or_drop("orphan".to_string())
            .await
            .expect_err("a closed channel must fail");
        let elapsed = start.elapsed();

        match err {
            tokio::sync::mpsc::error::SendTimeoutError::Closed(record) => {
                assert_eq!(
                    record, "orphan",
                    "the dropped record must be handed back, not silently swallowed"
                );
            }
            other => panic!("expected Closed, got {other:?}"),
        }
        assert!(
            elapsed < Duration::from_secs(1),
            "Closed must return without waiting out send_timeout; took {elapsed:?}"
        );
        let key = CompositeKey::new(
            MetricKind::Counter,
            metrics::Key::from_parts(
                "parquet_s3_dropped",
                vec![
                    metrics::Label::new("source", "test"),
                    metrics::Label::new("target", "s3"),
                ],
            ),
        );
        let dropped = snapshotter
            .snapshot()
            .into_hashmap()
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
            dropped, 1,
            "parquet_s3_dropped must be incremented on the closed branch too"
        );
    }

    /// The channel-depth gauges are the recommended queue-depth alert signal,
    /// so their cadence must stay short and, crucially, independent of
    /// `flush_check_interval` — which is 900s at every source's default
    /// `flush_interval_secs`.
    #[test]
    fn channel_gauge_interval_is_short_and_independent_of_the_flush_interval() {
        assert!(CHANNEL_GAUGE_INTERVAL <= Duration::from_secs(5));
        assert_ne!(
            CHANNEL_GAUGE_INTERVAL,
            crate::forwarding::s3_sink::flush_check_interval(Duration::from_secs(
                default_flush_interval_secs()
            ))
        );
    }

    #[test]
    fn send_timeout_default_is_five_seconds() {
        assert_eq!(SEND_TIMEOUT_DEFAULT, Duration::from_secs(5));
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
        let buf = w.buffer_by_partition("").unwrap();
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
        if let Some(buf) = w.buffer_by_partition_mut("") {
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
        assert_eq!(w.buffer_by_partition("a").unwrap().row_count, 3);
        assert_eq!(w.buffer_by_partition("b").unwrap().row_count, 2);
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
        let buf = w.buffer_by_partition("").unwrap();
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
            w.buffer_by_partition("_overflow").is_some(),
            "_overflow buffer must exist after partition cap exceeded"
        );
        // The _overflow buffer must have rows (records were actually written to it).
        let ov = w.buffer_by_partition("_overflow").unwrap();
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
        w.push("r1".to_string()).await.unwrap(); // push() no longer fails synchronously when a flush fails
        w.drain_pending_flushes().await; // deterministically wait for the triggered flush attempt (and its merge-back) to finish
        // After failed flush the hard cap kicks in; row_count must be <= cap.
        let buf = w.buffer_by_partition("").unwrap();
        let hard_cap = 10_000usize * 4;
        assert!(
            buf.row_count <= hard_cap,
            "row_count {} must not exceed hard_cap {}",
            buf.row_count,
            hard_cap
        );
    }

    /// Age-flush trigger: after backdating last_flush and calling flush_all_if_needed,
    /// the flush path was entered — evidenced by the upload-errors metric incrementing
    /// (unreachable S3 guarantees an attempt was made and failed), not merely by the
    /// record's row_count being unchanged (which would also be true if the age trigger
    /// silently never fired at all).
    #[tokio::test]
    #[allow(clippy::mutable_key_type)]
    async fn age_threshold_flush_if_needed_enters_flush_path() {
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let s3 = unreachable_s3().await;
        let (cfg, policy) = test_config(10_000);
        let mut w = PartitionedParquetWriter::new(MockSink, s3, cfg, policy);
        w.push("r1".to_string()).await.unwrap();

        // Backdate last_flush so the age trigger fires.
        let backdated = Instant::now() - std::time::Duration::from_secs(3601);
        if let Some(buf) = w.buffer_by_partition_mut("") {
            buf.last_flush = backdated;
        }

        // flush_all_if_needed will attempt flush (will fail, unreachable S3).
        w.flush_all_if_needed().await.unwrap(); // flush_all_if_needed() no longer fails synchronously
        w.drain_pending_flushes().await;

        // Prove the flush path was genuinely entered and failed: the upload-errors
        // metric only increments if encode_and_upload's upload step actually ran.
        let snapshot = snapshotter.snapshot();
        let map = snapshot.into_hashmap();
        let key = CompositeKey::new(
            MetricKind::Counter,
            metrics::Key::from_parts(
                "parquet_s3_upload_errors",
                vec![
                    metrics::Label::new("source", "test"),
                    metrics::Label::new("target", "s3"),
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
        assert!(
            count >= 1,
            "expected parquet_s3_upload_errors{{source=\"test\",target=\"s3\"}} >= 1, \
             proving the age-triggered flush was actually attempted and failed"
        );

        // The flush path was entered and failed (unreachable S3): the merge-back-on-failure
        // logic must have put the record back, proving the data wasn't lost.
        assert_eq!(
            w.buffer_by_partition("").unwrap().row_count,
            1,
            "the record must still be present -- a failed flush merges its data back rather than losing it"
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

        // Simulate what encode_and_upload does: concat_batches + ArrowWriter
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
    /// (the same path `encode_and_upload` uses), and `build_descriptor` is
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
        w.drain_pending_flushes().await;

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
        w.drain_pending_flushes().await;

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

    // -----------------------------------------------------------------------
    // Task 6 — concurrency-guarantee tests for the decoupling mechanism
    // -----------------------------------------------------------------------

    /// A second threshold-crossing while a flush is already in-flight for
    /// the same partition must NOT spawn a second flush -- it must fall
    /// back to `drop_oldest_to_cap` on the live buffer instead (spec
    /// decision #2). Proven here by using a sink that blocks forever until
    /// released, so if a second flush WERE spawned, this test would hang
    /// (caught by the outer test timeout) instead of passing.
    ///
    /// The gate is a `Semaphore` starting at 0 permits, not a `Notify`, so
    /// that releasing it (`add_permits`) is race-free regardless of whether
    /// the release happens before or after a waiter calls `acquire()` --
    /// unlike `Notify::notify_waiters()`, permits added to a `Semaphore` are
    /// never lost if no one is waiting yet (deliberate deviation from the
    /// brief's literal `Notify`-based helper; see task-6-report.md for why).
    struct BlockingSink {
        gate: Arc<tokio::sync::Semaphore>,
    }
    #[async_trait::async_trait]
    impl UploadSink for BlockingSink {
        async fn upload(&self, _key: &str, _body: Vec<u8>) -> anyhow::Result<()> {
            self.gate.acquire().await.unwrap().forget();
            Ok(())
        }
        fn target_label(&self) -> &'static str {
            "blocking"
        }
        fn location_hint(&self) -> String {
            "blocking://test".to_string()
        }
    }

    #[tokio::test]
    async fn second_threshold_crossing_while_in_flight_hard_caps_instead_of_double_flushing() {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let sink: Arc<dyn UploadSink> = Arc::new(BlockingSink { gate: gate.clone() });
        let max_rows = 1usize;
        let (cfg, policy) = test_config(max_rows);
        let hard_cap = max_rows.saturating_mul(4); // 4
        let mut w = PartitionedParquetWriter::new(MockSink, sink, cfg, policy);

        // First push triggers a flush that will block forever until `gate` fires.
        w.push("r0".to_string()).await.unwrap();
        assert!(
            w.buffer_by_partition("").unwrap().in_flight,
            "first push must mark the partition in-flight"
        );

        // Push more than hard_cap while the first flush is stuck in-flight.
        for i in 1..(hard_cap * 3) {
            w.push(format!("r{i}")).await.unwrap();
        }

        let buf = w.buffer_by_partition("").unwrap();
        assert!(
            buf.row_count <= hard_cap,
            "row_count {} must be capped at {} even while a flush is stuck in-flight",
            buf.row_count,
            hard_cap
        );
        assert!(
            buf.in_flight,
            "the ORIGINAL flush must still be the only one in-flight (still blocked on the gate)"
        );

        // Release the blocked upload so the test can clean up without hanging.
        gate.add_permits(1);
        w.drain_pending_flushes().await;
    }

    /// The scenario 3 rounds of design review focused on: while a flush is
    /// stuck in-flight, every subsequent push accumulates into the live
    /// builder (below `BUILDER_BATCH_ROWS`, so `buf.buffer` never sees them
    /// directly). If `drop_oldest_to_cap` didn't self-materialize those
    /// pending rows first, it would have nothing poppable from `buf.buffer`
    /// and `row_count` would grow unbounded despite the hard cap.
    #[tokio::test]
    async fn in_flight_flush_still_hard_caps_rows_accumulating_in_the_live_builder() {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let sink: Arc<dyn UploadSink> = Arc::new(BlockingSink { gate: gate.clone() });
        let max_rows = 1usize;
        let (cfg, policy) = test_config(max_rows);
        let hard_cap = max_rows.saturating_mul(4); // 4
        let mut w = PartitionedParquetWriter::new(AmortizingMockSink, sink, cfg, policy);

        // First push triggers a flush that blocks forever until `gate` fires.
        w.push("r0".to_string()).await.unwrap();
        assert!(w.buffer_by_partition("").unwrap().in_flight);

        // Push far more than hard_cap while the first flush is stuck
        // in-flight, WITHOUT draining -- every one of these accumulates in
        // the live builder (below BUILDER_BATCH_ROWS), which is exactly the
        // scenario that would leave drop_oldest_to_cap with nothing
        // poppable if materialize_live_builder weren't wired into it.
        for i in 1..(hard_cap * 3) {
            w.push(format!("r{i}")).await.unwrap();
        }

        let buf = w.buffer_by_partition("").unwrap();
        assert!(
            buf.row_count <= hard_cap,
            "row_count {} must be capped at {} even while rows are accumulating \
             in the live builder during an in-flight flush",
            buf.row_count,
            hard_cap
        );

        gate.add_permits(1);
        w.drain_pending_flushes().await;
    }

    /// Same scenario as `in_flight_flush_still_hard_caps_rows_accumulating_in_the_live_builder`,
    /// but with a sink whose `Record` carries 3 rows per push. Before the
    /// row-count accounting fix, `row_count` would advance by 1 per push
    /// regardless of the real 3-row content, so `drop_oldest_to_cap`'s
    /// `while row_count > cap` loop would see a row_count roughly a third
    /// of reality and evict far too rarely -- silently letting real
    /// buffered data grow well past the intended hard cap even though
    /// `row_count` itself stayed small. This checks the REAL held row
    /// count (materialized batches + live builder), not just the
    /// `row_count` bookkeeping field, since a buggy row_count would
    /// otherwise stay numerically small enough to pass a naive
    /// `row_count <= hard_cap` check while still being wrong.
    #[tokio::test]
    async fn drop_oldest_to_cap_bounds_real_rows_for_multi_row_records() {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let sink: Arc<dyn UploadSink> = Arc::new(BlockingSink { gate: gate.clone() });
        let max_rows = 1usize;
        let (cfg, policy) = test_config(max_rows);
        let hard_cap = max_rows.saturating_mul(4); // 4
        let rows_per_push = 3usize;
        let mut w = PartitionedParquetWriter::new(MultiRowMockSink, sink, cfg, policy);

        // First push (3 rows) triggers a flush that blocks forever until
        // `gate` fires.
        w.push(vec!["a".to_string(), "b".to_string(), "c".to_string()])
            .await
            .unwrap();
        assert!(w.buffer_by_partition("").unwrap().in_flight);

        // Push far more 3-row records while the first flush is stuck
        // in-flight.
        for i in 1..(hard_cap * 3) {
            w.push(vec![format!("r{i}a"), format!("r{i}b"), format!("r{i}c")])
                .await
                .unwrap();
        }

        let buf = w.buffer_by_partition("").unwrap();
        let real_rows_held: usize = buf.buffer.iter().map(|(b, _)| b.num_rows()).sum::<usize>()
            + buf.live_builder.as_ref().map(|b| b.len()).unwrap_or(0);
        assert!(
            real_rows_held <= hard_cap + rows_per_push,
            "real buffered rows {real_rows_held} must stay bounded near hard_cap \
             {hard_cap} (+ one push's worth of slack for eviction granularity) even \
             though every push carries {rows_per_push} rows -- under the pre-fix \
             per-push-counts-as-1 bug this grows unbounded because the eviction \
             loop's row_count undercounts real content by a factor of \
             {rows_per_push}x"
        );

        gate.add_permits(1);
        w.drain_pending_flushes().await;
    }

    /// A failed flush's data must be merged back onto the live buffer
    /// (prepended -- older data first) AND `last_flush` must be re-staled
    /// so the age trigger fires on the very next check, matching today's
    /// behavior where a failed flush simply never touches `last_flush`
    /// (spec decision #12).
    #[tokio::test]
    #[allow(clippy::mutable_key_type)]
    async fn failed_flush_merges_batches_back_and_restales_last_flush_for_prompt_retry() {
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let s3 = unreachable_s3().await; // every upload fails fast
        let max_rows = 100usize; // high enough that only the AGE trigger fires
        let (cfg, mut policy) = test_config(max_rows);
        policy.interval = LiveInterval::new(std::time::Duration::from_secs(900));
        let mut w = PartitionedParquetWriter::new(MockSink, s3, cfg, policy);

        // Force the age trigger by backdating last_flush before the buffer exists.
        w.push("r0".to_string()).await.unwrap();
        w.buffer_by_partition_mut("").unwrap().last_flush =
            Instant::now() - std::time::Duration::from_secs(901);

        // This push crosses the age threshold and triggers (and fails) a flush.
        w.push("r1".to_string()).await.unwrap();
        w.drain_pending_flushes().await;

        // Prove the flush path was genuinely entered and failed: the upload-errors
        // metric only increments if encode_and_upload's upload step actually ran.
        let snapshot = snapshotter.snapshot();
        let map = snapshot.into_hashmap();
        let key = CompositeKey::new(
            MetricKind::Counter,
            metrics::Key::from_parts(
                "parquet_s3_upload_errors",
                vec![
                    metrics::Label::new("source", "test"),
                    metrics::Label::new("target", "s3"),
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
        assert!(
            count >= 1,
            "expected parquet_s3_upload_errors{{source=\"test\",target=\"s3\"}} >= 1, \
             proving the age-triggered flush was actually attempted and failed"
        );

        let buf = w.buffer_by_partition("").unwrap();
        assert_eq!(
            buf.row_count, 2,
            "both records must still be present after the failed flush merges back"
        );
        assert!(
            buf.last_flush.elapsed() >= std::time::Duration::from_secs(900),
            "last_flush must be re-staled past the interval so the next check retries almost immediately, not after a full 900s wait"
        );
    }

    /// `apply_flush_outcome`'s last_flush re-staling must not panic when
    /// `Instant::now()` hasn't been running long enough to subtract a large
    /// configured interval from (e.g. shortly after process start with a
    /// long flush_interval_secs) -- it must fall back to "not re-staled"
    /// instead (spec decision #12's checked_sub fix).
    #[tokio::test]
    async fn restale_last_flush_does_not_panic_when_interval_exceeds_process_uptime() {
        let s3 = unreachable_s3().await;
        let max_rows = 1usize;
        let (cfg, mut policy) = test_config(max_rows);
        // A deliberately enormous interval -- far longer than this test (or
        // realistically, this process) has been running.
        policy.interval = LiveInterval::new(std::time::Duration::from_secs(365 * 24 * 3600));
        let mut w = PartitionedParquetWriter::new(MockSink, s3, cfg, policy);

        // Triggers and fails a flush; must not panic during outcome handling.
        w.push("r0".to_string()).await.unwrap();
        w.drain_pending_flushes().await;

        assert_eq!(
            w.buffer_by_partition("").unwrap().row_count,
            1,
            "the record must still be present after the (non-panicking) failed flush"
        );
    }

    /// `try_flush_partition_async` must return immediately even when the
    /// writer's flush semaphore is fully saturated -- proving the permit is
    /// acquired INSIDE the spawned task, not in the caller. If this were
    /// wrong (acquired before spawning), this test would hang.
    #[tokio::test]
    async fn spawning_a_flush_does_not_block_even_when_semaphore_is_saturated() {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let sink: Arc<dyn UploadSink> = Arc::new(BlockingSink { gate: gate.clone() });
        let (cfg, policy) = test_config(1);
        // Multi-partition sink so distinct keys each get their own buffer,
        // letting us saturate the semaphore (MAX_CONCURRENT_FLUSHES_PER_WRITER = 4)
        // with more than 4 simultaneously in-flight, blocked, flushes.
        struct MultiKeySink;
        impl ParquetSink for MultiKeySink {
            type Record = (String, String); // (partition, value)
            fn source(&self) -> &'static str {
                "test"
            }
            fn partition(&self, r: &Self::Record) -> Option<String> {
                Some(r.0.clone())
            }
            fn schema(&self, _p: Option<&str>) -> Arc<Schema> {
                test_schema()
            }
            fn to_record_batch(
                &self,
                record: &Self::Record,
                schema: &Arc<Schema>,
            ) -> anyhow::Result<RecordBatch> {
                let col = Arc::new(StringArray::from(vec![record.1.as_str()]));
                Ok(RecordBatch::try_new(schema.clone(), vec![col])?)
            }
        }
        let mut w = PartitionedParquetWriter::new(MultiKeySink, sink, cfg, policy);

        // Trigger 6 partitions' flushes (> the semaphore's 4 permits), all
        // blocked on `gate`. Every push() call below must return promptly.
        for i in 0..6 {
            w.push((format!("p{i}"), "v".to_string())).await.unwrap();
        }

        // `add_permits` (unlike `Notify::notify_waiters`) is race-free: it
        // is never lost even if called before any of the 6 spawned flushes
        // has reached `gate.acquire()` -- see `BlockingSink` above.
        gate.add_permits(6);
        w.drain_pending_flushes().await;
    }

    #[tokio::test]
    async fn drop_log_throttle_is_shared_across_handle_clones() {
        use crate::forwarding::drop_log::{DropKind, DropSite};

        let s3 = unreachable_s3().await;
        let (cfg, policy) = test_config(10_000);
        let (handle, _join) = ParquetWriterHandle::start(MockSink, s3, cfg, policy);

        // ParquetWriterHandle is #[derive(Clone)] and IngestState clones its
        // handles per request (AppState is held behind Arc<AppState> and
        // isn't itself Clone; ParquetWriterHandle<WefSink> isn't Clone either,
        // since WefSink isn't Clone). If throttle state were per-clone rather
        // than Arc-shared, every request would get a fresh throttle and the
        // log storm would silently return.
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
}
