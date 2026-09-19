//! Zeek → S3 Parquet persistence.
//!
//! Provides:
//! - `ZeekSink` — `ParquetSink` adapter for the generic writer (multi-partition)
//! - `ZeekS3Handler` — type alias for `ParquetWriterHandle<ZeekSink>`
//! - `zeek_start()` — convenience constructor wiring `ZeekS3Config` → `ParquetWriterHandle`
//!
//! The generic `PartitionedParquetWriter` handles all buffering, flush, cap, encode, and
//! upload machinery.  `ZeekSink` is the thin adapter that provides:
//! - `partition()` → `sanitize_log_path(record.log_path)` (per-stream buffer key)
//! - `schema(partition)` → typed registry schema or envelope fallback
//! - `to_record_batch()` → registry row mapper for the record's actual log_path
//!
//! S3 key layout:  `zeek/<sanitized_log_path>/year={Y}/month={MM}/day={DD}/{uuid}.parquet`
//! Partition cap:  `max_partitions` (replaces `MAX_ZEEK_STREAMS`); excess → `"_overflow"` buffer.
//! Metrics:        `parquet_s3_*{source="zeek"}` (generic labels).
//!
//! `sanitize_log_path()` (the safe path segment for S3 keys) lives in
//! `buffered_writer` — it is shared with Suricata and HEC, which also embed
//! wire-supplied strings in S3 keys.

use crate::config::ZeekS3Config;
use crate::forwarding::buffered_writer::{ParquetSink, sanitize_log_path};
use crate::forwarding::drop_log::{DropKind, DropSite};
use crate::zeek::ZeekRecord;
use crate::zeek::schema::{envelope_schema, get_schema_entry};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// ZeekSink — ParquetSink adapter
// ---------------------------------------------------------------------------

/// `ParquetSink` adapter for Zeek NDJSON records.
///
/// This is the multi-partition case: each distinct `log_path` (after sanitization)
/// gets its own buffer keyed by the sanitized path.  Excess partitions overflow to
/// the `"_overflow"` buffer (generic machinery; configured via `max_partitions`).
#[derive(Default)]
pub struct ZeekSink;

impl ParquetSink for ZeekSink {
    type Record = ZeekRecord;

    fn source(&self) -> &'static str {
        "zeek"
    }

    /// Partition segment = `sanitize_log_path(record.log_path)`.
    /// This is used as both the buffer-map key and the S3 path component,
    /// producing keys of the form `zeek/<log_path>/year=…/…parquet`.
    fn partition(&self, record: &ZeekRecord) -> Option<String> {
        Some(sanitize_log_path(&record.log_path))
    }

    /// Schema for `partition`:
    /// - For a typed log path (`conn`, `dns`, `http`, `ssl`, `files`, `notice`):
    ///   returns the typed schema from the registry.
    /// - For `None`, `"_overflow"`, or any unknown path: returns the envelope fallback schema.
    ///
    /// `partition` is the **sanitized** path segment (the buffer-map key), not the raw log_path.
    fn schema(&self, partition: Option<&str>) -> Arc<arrow_schema::Schema> {
        match partition {
            // No partition (should not happen for ZeekSink, but be safe).
            None => envelope_schema(),
            // Overflow bucket — always use the envelope fallback.
            Some("_overflow") => envelope_schema(),
            // Known or unknown named partition: look up the registry.
            // get_schema_entry falls back to envelope_schema for unknown paths.
            Some(seg) => get_schema_entry(seg).schema.clone(),
        }
    }

    /// Event time column for day bucketing. `ts` (Zeek's own event time --
    /// connection start, DNS query time, etc.) is nullable in all 7 Zeek
    /// schemas, and 6 of those 7 have no other non-null receipt column of
    /// their own -- so a `ts`-mixed log path could otherwise split one
    /// Parquet file's rows across two `day(ts)` Iceberg partition values.
    /// `partition_time` is the non-null, per-row-materialised column every
    /// schema carries specifically to close that gap: `ts` when present and
    /// within the shared backfill/skew window, `received_at` otherwise (see
    /// `zeek_partition_time`).
    fn time_column(&self) -> Option<&'static str> {
        Some("partition_time")
    }

    /// Convert one `ZeekRecord` to a single-row `RecordBatch`.
    ///
    /// Uses `get_schema_entry(&record.log_path)` to select the row mapper for the
    /// **actual** (unsanitized) log path, applying the typed or envelope mapper.
    /// Type mismatches go to `_extra` (typed schemas) or `payload` (envelope); never panics.
    fn to_record_batch(
        &self,
        record: &ZeekRecord,
        schema: &Arc<arrow_schema::Schema>,
    ) -> anyhow::Result<arrow_array::RecordBatch> {
        // Use the actual (unsanitized) log_path to select the mapper so that the
        // registry look-up matches the same path that produced the schema in schema().
        // For the _overflow partition the schema is envelope; get_schema_entry for an
        // unknown path also returns an envelope mapper — so the types are always consistent.
        let entry = get_schema_entry(&record.log_path);

        // Sanity check: if the entry schema matches the partition schema we were given,
        // use the entry's mapper directly; otherwise fall back to re-running with the
        // schema we actually hold (avoids RecordBatch schema mismatch panics).
        if entry.schema == *schema {
            (entry.mapper)(&record.fields, record.received_at).map_err(|e| {
                anyhow::anyhow!("ZeekSink mapper error for '{}': {e}", record.log_path)
            })
        } else {
            // The partition was overflowed to "_overflow" (or the sanitized path doesn't match
            // the raw path).  Use the envelope mapper for the schema we were given.
            let overflow_entry = get_schema_entry("_overflow_nonexistent_");
            // get_schema_entry for unknown path always returns envelope — use that mapper.
            (overflow_entry.mapper)(&record.fields, record.received_at).map_err(|e| {
                anyhow::anyhow!(
                    "ZeekSink overflow mapper error for '{}': {e}",
                    record.log_path
                )
            })
        }
    }

    fn new_batch(
        &self,
        schema: &Arc<arrow_schema::Schema>,
    ) -> Option<Box<dyn crate::forwarding::buffered_writer::RecordBatchAccumulator<ZeekRecord>>>
    {
        use crate::zeek::schema as zs;
        // Every Zeek schema has an accumulator. Dispatch on the schema Arc the
        // writer hands us -- NOT on the record's log_path, which may be a raw
        // spelling that only `get_schema_entry` resolves. Each accumulator
        // re-checks the record's own resolved schema in `try_append` and
        // returns Ok(false) on a mismatch (e.g. raw "Conn" vs sanitized
        // "conn"), so a stray record falls back to to_record_batch rather
        // than being appended into the wrong builder set.
        if Arc::ptr_eq(schema, &zs::conn_schema()) {
            Some(Box::new(zs::ConnAccumulator::new()))
        } else if Arc::ptr_eq(schema, &zs::dns_schema()) {
            Some(Box::new(zs::DnsAccumulator::new()))
        } else if Arc::ptr_eq(schema, &zs::http_schema()) {
            Some(Box::new(zs::HttpAccumulator::new()))
        } else if Arc::ptr_eq(schema, &zs::ssl_schema()) {
            Some(Box::new(zs::SslAccumulator::new()))
        } else if Arc::ptr_eq(schema, &zs::files_schema()) {
            Some(Box::new(zs::FilesAccumulator::new()))
        } else if Arc::ptr_eq(schema, &zs::notice_schema()) {
            Some(Box::new(zs::NoticeAccumulator::new()))
        } else if Arc::ptr_eq(schema, &zs::envelope_schema()) {
            Some(Box::new(zs::EnvelopeAccumulator::new()))
        } else {
            None
        }
    }

    /// Overrides the default `day_and_batch`: derives the day from
    /// `zeek_partition_time(&record.fields, record.received_at)` directly
    /// instead of building a batch first. Applies uniformly to every Zeek
    /// log path, not just `conn` -- cheaper than the default for all 7
    /// schemas, and the only correct option for `conn` specifically, whose
    /// amortized `ConnAccumulator` must never pay for a `to_record_batch`
    /// call it doesn't need (see the design doc's amortized-builder-path
    /// note).
    ///
    /// Returning `(day, None)` -- not `(day, Some(batch))` -- is load
    /// bearing: `push()` calls this before it knows whether a record goes
    /// to the amortized live builder, so building a batch here just to
    /// learn the day would make every Zeek record pay for a throwaway
    /// `RecordBatch`, defeating the entire point of `ConnAccumulator`.
    ///
    /// `zeek_partition_time` is a pure function of `(fields, received_at)`
    /// -- no `Utc::now()` read anywhere in it -- so calling it here and
    /// again from a row mapper for the very same record always agrees on
    /// the same instant; the `now` parameter this trait method receives is
    /// unused precisely because of that.
    fn day_and_batch(
        &self,
        record: &ZeekRecord,
        _schema: &Arc<arrow_schema::Schema>,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<(chrono::NaiveDate, Option<arrow_array::RecordBatch>)> {
        let day = crate::zeek::schema::zeek_partition_time(&record.fields, record.received_at)
            .date_naive();
        Ok((day, None))
    }
}

// ---------------------------------------------------------------------------
// ZeekS3Handler — type alias + ZeekHandler impl
// ---------------------------------------------------------------------------

/// `ZeekS3Handler` is a thin alias for the generic `ParquetWriterHandle<ZeekSink>`.
pub type ZeekS3Handler = crate::forwarding::buffered_writer::ParquetWriterHandle<ZeekSink>;

#[async_trait::async_trait]
impl crate::zeek::listener::ZeekHandler
    for crate::forwarding::buffered_writer::ParquetWriterHandle<ZeekSink>
{
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
                // No duration in the message: `SendTimeoutError::Closed`
                // returns immediately (writer task dead, nothing waited), so
                // naming the timeout would be a lie on exactly the branch that
                // matters most. `DropKind` already distinguishes the two in the
                // throttle key.
                if let Some(dropped_total) = self.drop_log_due(DropSite::Zeek, DropKind::from(&e)) {
                    tracing::warn!(
                        dropped_total,
                        "Zeek S3 channel unavailable; dropped 1 record from {}",
                        source
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MultiZeekHandler — fan-out to multiple destinations
// ---------------------------------------------------------------------------

/// Fans out each record to every configured handler. Used only when both
/// `.s3` and `.local` persistence resolve to a live handler for the same
/// run, so each destination keeps its own independent buffer, flush policy,
/// backpressure, and hard cap (no shared state between destinations).
pub struct MultiZeekHandler(pub Vec<std::sync::Arc<dyn crate::zeek::listener::ZeekHandler>>);

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

// ---------------------------------------------------------------------------
// zeek_start / zeek_local_start — convenience constructors
// ---------------------------------------------------------------------------

/// Replaces the old `MAX_ZEEK_STREAMS` constant.
const DEFAULT_MAX_ZEEK_PARTITIONS: usize = 256;

/// Construct a `ZeekS3Handler` (i.e. `ParquetWriterHandle<ZeekSink>`) from a
/// `ZeekS3Config` and a pre-built `S3Sink`.
///
/// `max_partitions` is set to 256 (the old `MAX_ZEEK_STREAMS` value) unless the
/// config provides a higher or lower value (the config struct does not expose this
/// field, so we hard-code the default here — matching the old behavior).
///
/// Returns `(handler, writer_task_handle)`. The caller should retain the `JoinHandle`
/// and await it during graceful shutdown, after all `Arc<dyn ZeekHandler>` references
/// have been dropped so the channel closes and the final flush fires.
pub fn zeek_start(
    cfg: &ZeekS3Config,
    s3: std::sync::Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<std::sync::Arc<dyn crate::forwarding::buffered_writer::UploadSink>>,
) -> (ZeekS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<ZeekSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        DEFAULT_MAX_ZEEK_PARTITIONS,
        s3,
        source_stats,
        descriptor_sink,
    )
}

/// Construct a `ZeekS3Handler` from a `ZeekLocalConfig` and a pre-built
/// `LocalDiskSink`. Structurally identical to `zeek_start`, writing to local
/// disk instead of S3 — same `ZeekSink` adapter, same buffering/flush/cap
/// machinery, same S3-key-shaped relative path layout on disk.
pub fn zeek_local_start(
    cfg: &crate::config::ZeekLocalConfig,
    sink: std::sync::Arc<crate::forwarding::local_sink::LocalDiskSink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<std::sync::Arc<dyn crate::forwarding::buffered_writer::UploadSink>>,
) -> (ZeekS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<ZeekSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        DEFAULT_MAX_ZEEK_PARTITIONS,
        sink,
        source_stats,
        descriptor_sink,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::S3ConnectionConfig;
    use crate::forwarding::buffered_writer::{
        BufferedWriterConfig, FlushPolicy, ParquetSink, PartitionedParquetWriter,
    };
    use crate::forwarding::s3_sink::S3Sink;
    use crate::zeek::ZeekRecord;
    use chrono::Utc;
    use std::sync::Arc;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    async fn unreachable_sink() -> Arc<S3Sink> {
        let conn = S3ConnectionConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            bucket: "test-bucket".to_string(),
            region: "us-east-1".to_string(),
            access_key: "AKIATEST".to_string(),
            secret_key: "SECRETTEST".to_string(),
        };
        Arc::new(S3Sink::from_connection(&conn).await.expect("constructs"))
    }

    fn make_zeek_cfg(
        max_rows: usize,
        flush_bytes: usize,
        max_partitions: usize,
    ) -> (BufferedWriterConfig, FlushPolicy) {
        let bwc = BufferedWriterConfig {
            connection: S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "zeek".to_string(),
            max_buffer_rows: max_rows,
            flush_threshold_bytes: flush_bytes,
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_partitions,
        };
        let policy = FlushPolicy {
            max_rows,
            max_bytes: flush_bytes,
            interval: crate::forwarding::buffered_writer::LiveInterval::new(
                std::time::Duration::from_secs(3600),
            ),
        };
        (bwc, policy)
    }

    fn make_conn_record(uid: &str) -> ZeekRecord {
        ZeekRecord {
            log_path: "conn".to_string(),
            fields: serde_json::json!({
                "_path": "conn",
                "ts": 1700000000.0,
                "uid": uid,
                "id.orig_h": "10.0.0.1",
                "id.orig_p": 12345,
                "id.resp_h": "10.0.0.2",
                "id.resp_p": 80,
                "proto": "tcp",
                "conn_state": "SF",
                "orig_bytes": 512,
                "resp_bytes": 4096,
            }),
            received_at: Utc::now(),
        }
    }

    fn make_dns_record(uid: &str) -> ZeekRecord {
        ZeekRecord {
            log_path: "dns".to_string(),
            fields: serde_json::json!({
                "_path": "dns",
                "ts": 1700000100.0,
                "uid": uid,
                "id.orig_h": "192.168.1.100",
                "id.orig_p": 12345,
                "id.resp_h": "8.8.8.8",
                "id.resp_p": 53,
                "query": "example.com",
                "qtype_name": "A",
                "rcode_name": "NOERROR",
            }),
            received_at: Utc::now(),
        }
    }

    fn make_unknown_record() -> ZeekRecord {
        ZeekRecord {
            log_path: "weird".to_string(),
            fields: serde_json::json!({
                "_path": "weird",
                "ts": 1700000200.0,
                "uid": "CUnk1",
                "raw_data": "some weird log"
            }),
            received_at: Utc::now(),
        }
    }

    // -----------------------------------------------------------------------
    // ZeekSink unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn zeek_sink_source_returns_zeek() {
        assert_eq!(ZeekSink.source(), "zeek");
    }

    #[test]
    fn zeek_sink_day_and_batch_uses_partition_time_and_never_builds_a_batch() {
        use chrono::TimeZone;

        let schema = crate::zeek::schema::conn_schema();
        // received_at is a distinctly different day from ts (6 days later,
        // still inside the 30-day backfill window), so a test that
        // accidentally asserted the received_at fallback day instead of the
        // real ts-derived day would fail loudly rather than passing by
        // coincidence.
        let received_at = chrono::Utc.with_ymd_and_hms(2023, 11, 20, 8, 0, 0).unwrap();
        let record = ZeekRecord {
            log_path: "conn".to_string(),
            fields: serde_json::json!({"_path": "conn", "ts": 1700000000.0, "uid": "C1"}),
            received_at,
        };
        // `now` is passed but must be ignored entirely: day_and_batch derives
        // the day from `zeek_partition_time(fields, received_at)`, which
        // never reads the clock. A far-future `now` that the implementation
        // wrongly used would produce 2099-01-01, not 2023-11-14.
        let now = chrono::Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap();

        let (day, batch) = ZeekSink.day_and_batch(&record, &schema, now).unwrap();
        assert_eq!(day, chrono::NaiveDate::from_ymd_opt(2023, 11, 14).unwrap());
        assert!(
            batch.is_none(),
            "the amortized path must not pre-build a batch just to learn the day"
        );
    }

    #[test]
    fn zeek_sink_partition_sanitizes_log_path() {
        let record = make_conn_record("C1");
        assert_eq!(ZeekSink.partition(&record), Some("conn".to_string()));

        let weird = ZeekRecord {
            log_path: "../etc/passwd".to_string(),
            fields: serde_json::json!({}),
            received_at: Utc::now(),
        };
        let part = ZeekSink.partition(&weird).unwrap();
        assert!(!part.contains('/'));
        assert!(!part.contains('.'));
    }

    #[test]
    fn zeek_sink_schema_typed_for_known_paths() {
        use crate::zeek::schema::{conn_schema, dns_schema};

        // Typed paths return typed schemas.
        assert_eq!(ZeekSink.schema(Some("conn")), conn_schema());
        assert_eq!(ZeekSink.schema(Some("dns")), dns_schema());

        // _overflow → envelope schema
        let overflow_schema = ZeekSink.schema(Some("_overflow"));
        assert!(
            overflow_schema.field_with_name("payload").is_ok(),
            "_overflow schema must be envelope (has 'payload' column)"
        );

        // None → envelope schema
        let none_schema = ZeekSink.schema(None);
        assert!(
            none_schema.field_with_name("payload").is_ok(),
            "None partition schema must be envelope"
        );

        // Unknown path → envelope schema (fallback)
        let unknown_schema = ZeekSink.schema(Some("notaknownpath"));
        assert!(
            unknown_schema.field_with_name("payload").is_ok(),
            "unknown path schema must be envelope fallback"
        );
    }

    #[test]
    fn zeek_sink_to_record_batch_conn() {
        let record = make_conn_record("C1");
        let schema = ZeekSink.schema(Some("conn"));
        let batch = ZeekSink.to_record_batch(&record, &schema).unwrap();
        assert_eq!(batch.num_rows(), 1);
        // conn schema has 'uid' column
        use arrow::array::StringArray;
        let uid = batch
            .column_by_name("uid")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(uid.value(0), "C1");
    }

    #[test]
    fn zeek_sink_to_record_batch_unknown_path_uses_envelope() {
        let record = make_unknown_record();
        // Unknown paths get envelope schema from schema()
        let schema = ZeekSink.schema(Some("weird"));
        let batch = ZeekSink.to_record_batch(&record, &schema).unwrap();
        assert_eq!(batch.num_rows(), 1);
        // Envelope schema has 'payload' column
        let col = batch.column_by_name("payload");
        assert!(col.is_some(), "envelope schema must have 'payload' column");
    }

    #[test]
    fn zeek_sink_to_record_batch_overflow_partition() {
        // When the partition is "_overflow", we use envelope schema.
        // The record may have any log_path — we test with a conn record.
        let record = make_conn_record("Overflow1");
        let schema = ZeekSink.schema(Some("_overflow"));
        // schema is envelope; to_record_batch must succeed (not panic).
        let result = ZeekSink.to_record_batch(&record, &schema);
        assert!(
            result.is_ok(),
            "to_record_batch must succeed for _overflow partition: {:?}",
            result.err()
        );
        let batch = result.unwrap();
        assert_eq!(batch.num_rows(), 1);
    }

    // -----------------------------------------------------------------------
    // S3 key layout verification
    // -----------------------------------------------------------------------

    #[test]
    fn build_key_produces_zeek_log_path_layout() {
        use crate::forwarding::buffered_writer::build_key;

        let day = chrono::NaiveDate::from_ymd_opt(2026, 3, 7).unwrap();

        // zeek/<log_path>/year=…/month=…/day=…/<uuid>.parquet
        let key = build_key("zeek", Some("conn"), day);
        assert!(
            key.starts_with("zeek/conn/year=2026/month=03/day=07/"),
            "key: {key}"
        );
        assert!(key.ends_with(".parquet"), "key: {key}");

        let key = build_key("zeek", Some("dns"), day);
        assert!(key.starts_with("zeek/dns/year="), "key: {key}");

        let key = build_key("zeek", Some("_overflow"), day);
        assert!(key.starts_with("zeek/_overflow/year="), "key: {key}");
    }

    #[test]
    fn zeek_sink_time_column_partition_time_exists_in_all_schemas() {
        let sink = ZeekSink;
        let col = sink
            .time_column()
            .expect("zeek_sink must opt in to day partitioning");
        // Pin the exact column name, not just that SOME name resolves.
        assert_eq!(col, "partition_time");
        // Check that partition_time exists in all 6 typed schemas plus the envelope fallback.
        for partition in &[
            Some("conn"),
            Some("dns"),
            Some("http"),
            Some("ssl"),
            Some("files"),
            Some("notice"),
            None, // envelope fallback for unknown paths
        ] {
            let schema = sink.schema(*partition);
            assert!(
                schema.field_with_name(col).is_ok(),
                "time_column() returned {:?}, which is not a field in schema for partition {:?}",
                col,
                partition
            );
        }
    }

    // -----------------------------------------------------------------------
    // PartitionedParquetWriter accumulation tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn writer_accumulates_per_partition_buffers() {
        let sink = unreachable_sink().await;
        let (bwc, policy) = make_zeek_cfg(100_000, usize::MAX, 256);
        let mut writer = PartitionedParquetWriter::new(ZeekSink, sink, bwc, policy);

        writer.push(make_conn_record("C1")).await.ok();
        writer.push(make_conn_record("C2")).await.ok();
        writer.push(make_dns_record("D1")).await.ok();
        writer.push(make_unknown_record()).await.ok();

        // conn → "conn" partition, dns → "dns" partition, weird → "weird" partition
        assert_eq!(
            writer
                .buffer_by_partition("conn")
                .map(|b| b.row_count)
                .unwrap_or(0),
            2,
            "conn buffer should have 2 rows"
        );
        assert_eq!(
            writer
                .buffer_by_partition("dns")
                .map(|b| b.row_count)
                .unwrap_or(0),
            1,
            "dns buffer should have 1 row"
        );
        assert_eq!(
            writer
                .buffer_by_partition("weird")
                .map(|b| b.row_count)
                .unwrap_or(0),
            1,
            "weird buffer should have 1 row"
        );
    }

    #[tokio::test]
    async fn writer_bounded_under_s3_outage() {
        let sink = unreachable_sink().await;
        let max_rows = 2usize;
        let hard_cap = max_rows.saturating_mul(4);
        let (bwc, policy) = make_zeek_cfg(max_rows, 1, 256); // flush on every push

        let mut writer = PartitionedParquetWriter::new(ZeekSink, sink, bwc, policy);
        let total = hard_cap * 3;
        for i in 0..total {
            let rec = make_conn_record(&format!("C{i}"));
            writer.push(rec).await.unwrap();
            writer.drain_pending_flushes().await;
        }
        assert!(
            writer
                .buffer_by_partition("conn")
                .map(|b| b.row_count)
                .unwrap_or(0)
                <= hard_cap,
            "conn buffer must stay at or below hard cap ({hard_cap})"
        );
    }

    // -----------------------------------------------------------------------
    // Partition cap test — overflow to "_overflow"
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn writer_partition_cap_overflows_to_overflow_buffer() {
        let sink = unreachable_sink().await;
        let cap = 3usize;
        let (bwc, policy) = make_zeek_cfg(100_000, usize::MAX, cap);
        let mut writer = PartitionedParquetWriter::new(ZeekSink, sink, bwc, policy);

        // Push records with cap+5 distinct log_paths.
        for i in 0..(cap + 5) {
            let rec = ZeekRecord {
                log_path: format!("stream_{i}"),
                fields: serde_json::json!({
                    "_path": format!("stream_{i}"),
                    "ts": 1700000000.0,
                    "uid": format!("C{i}"),
                }),
                received_at: Utc::now(),
            };
            writer.push(rec).await.ok();
        }

        // Map size must be <= cap + 1 (the +1 is the "_overflow" buffer)
        assert!(
            writer.buffers.len() <= cap + 1,
            "buffers map must be bounded; got {} (cap={})",
            writer.buffers.len(),
            cap
        );
        // The "_overflow" buffer must exist.
        assert!(
            writer.buffer_by_partition("_overflow").is_some(),
            "_overflow buffer must exist after cap exceeded"
        );
        // The "_overflow" buffer must have rows and a valid (non-empty) schema.
        let ov = writer.buffer_by_partition("_overflow").unwrap();
        assert!(ov.row_count > 0, "_overflow must contain records");
        assert!(
            !ov.schema.fields().is_empty(),
            "_overflow must have a valid schema"
        );
    }

    // -----------------------------------------------------------------------
    // Rotation-boundary regression: a rotated `_path` (as the listener now
    // normalizes it) must land in the typed conn schema/partition, not the
    // envelope fallback.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn rotated_log_path_accumulates_into_conn_buffer_via_writer() {
        // End-to-end through PartitionedParquetWriter: a record whose log_path
        // has already been normalized (as the listener does) must accumulate
        // into the "conn" buffer using the typed ConnAccumulator, not overflow
        // into a distinct per-rotation buffer or the envelope fallback.
        let sink = unreachable_sink().await;
        let (bwc, policy) = make_zeek_cfg(100_000, usize::MAX, 256);
        let mut writer = PartitionedParquetWriter::new(ZeekSink, sink, bwc, policy);

        let raw_path = "/logs/conn.2026-08-14-16-08-44.log.gz";
        let normalized = crate::zeek::normalize_log_path(raw_path).to_string();
        assert_eq!(normalized, "conn");

        let record = ZeekRecord {
            log_path: normalized,
            fields: serde_json::json!({
                "_path": raw_path,
                "ts": 1700000000.0,
                "uid": "CRot2",
                "id.orig_h": "10.0.0.1",
                "id.orig_p": 12345,
                "id.resp_h": "10.0.0.2",
                "id.resp_p": 80,
                "proto": "tcp",
                "conn_state": "SF",
                "orig_bytes": 512,
                "resp_bytes": 4096,
            }),
            received_at: Utc::now(),
        };
        writer.push(record).await.unwrap();

        // Lands in the single stable "conn" buffer — no rotation-suffixed sibling.
        assert_eq!(
            writer
                .buffer_by_partition("conn")
                .map(|b| b.row_count)
                .unwrap_or(0),
            1,
            "rotated record must accumulate into the stable 'conn' buffer"
        );
        assert_eq!(
            writer.buffers.len(),
            1,
            "no additional per-rotation buffer should have been created"
        );
        // Accepted into the typed live builder (ConnAccumulator), not pushed as a
        // pre-built envelope fallback batch.
        let buf = writer.buffer_by_partition("conn").unwrap();
        assert_eq!(
            buf.live_builder.as_ref().map(|b| b.len()).unwrap_or(0),
            1,
            "rotated record must be accepted into the conn live builder (typed path)"
        );
    }

    #[tokio::test]
    async fn mismatched_raw_log_path_falls_back_to_envelope_not_conn_accumulator() {
        let sink = unreachable_sink().await;
        let (bwc, policy) = make_zeek_cfg(100_000, usize::MAX, 256);
        let mut writer = PartitionedParquetWriter::new(ZeekSink, sink, bwc, policy);

        // Raw log_path "Conn" (mixed case) sanitizes to partition "conn"
        // (ZeekSink::new_batch will offer a ConnAccumulator for that
        // partition's schema), but the raw-path registry lookup inside
        // ConnAccumulator::try_append is case-sensitive and misses -- this
        // record must be rejected and fall back to the envelope mapper,
        // exactly as to_record_batch's pre-existing fallback already does.
        let rec = ZeekRecord {
            log_path: "Conn".to_string(),
            fields: serde_json::json!({"_path": "Conn", "ts": 1700000000.0, "uid": "C1"}),
            received_at: Utc::now(),
        };
        writer.push(rec).await.unwrap();

        let buf = writer.buffer_by_partition("conn").unwrap();
        assert_eq!(
            buf.row_count, 1,
            "the record must still be counted, just via the fallback path"
        );
        assert!(
            buf.live_builder.as_ref().map(|b| b.len()).unwrap_or(0) == 0,
            "the mismatched record must NOT have been accepted into the conn live builder"
        );
        assert_eq!(
            buf.buffer.len(),
            1,
            "the rejected record's fallback batch must be pushed directly onto buf.buffer"
        );
    }

    // -----------------------------------------------------------------------
    // Handler overflow drops and increments parquet_s3_dropped{source="zeek"}
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[allow(clippy::mutable_key_type)]
    async fn handler_overflow_increments_dropped_counter() {
        use crate::forwarding::buffered_writer::ParquetWriterHandle;
        use crate::zeek::listener::ZeekHandler;
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::DebuggingRecorder;
        use std::net::SocketAddr;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        // Capacity 1, receiver held but never polled: the channel genuinely
        // stays full for the life of the test (no writer task draining it).
        // Going through a real `zeek_start` writer task doesn't work here:
        // since `push()` never awaits the actual upload (flushes are
        // spawned and decoupled from the channel-draining loop), a real
        // writer drains a healthy channel in microseconds regardless of how
        // broken the sink is, so a capacity-1 channel never actually stays
        // full long enough for `send_or_drop` to time out.
        let (tx, _rx) = tokio::sync::mpsc::channel::<ZeekRecord>(1);
        tx.try_send(make_conn_record("Cfirst")).unwrap();
        let handler = ParquetWriterHandle::<ZeekSink>::for_test(tx, "zeek", "s3")
            .with_send_timeout(std::time::Duration::from_millis(20));

        let src: SocketAddr = "127.0.0.1:47760".parse().unwrap();
        for i in 0..50usize {
            let rec = make_conn_record(&format!("C{i}"));
            handler.handle_record(rec, src).await;
        }

        let snapshot = snapshotter.snapshot();
        let map = snapshot.into_hashmap();
        let key = CompositeKey::new(
            MetricKind::Counter,
            metrics::Key::from_parts(
                "parquet_s3_dropped",
                vec![
                    metrics::Label::new("source", "zeek"),
                    metrics::Label::new("target", "s3"),
                ],
            ),
        );
        let dropped = map
            .get(&key)
            .map(|(_, _, v)| {
                if let metrics_util::debugging::DebugValue::Counter(c) = v {
                    *c
                } else {
                    0
                }
            })
            .unwrap_or(0);
        assert!(
            dropped >= 1,
            "expected parquet_s3_dropped{{source=\"zeek\"}} >= 1; got {dropped}"
        );
    }

    // -----------------------------------------------------------------------
    // zeek_start wires handler and join handle
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn zeek_start_wires_handler_and_join_handle() {
        use crate::zeek::listener::ZeekHandler;
        use std::net::SocketAddr;

        let sink = unreachable_sink().await;
        let cfg = ZeekS3Config {
            connection: S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "zeek".to_string(),
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_buffer_rows: 100_000,
        };
        let (handler, join_handle) = zeek_start(
            &cfg,
            sink,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );

        let src: SocketAddr = "127.0.0.1:47760".parse().unwrap();
        handler.handle_record(make_conn_record("C1"), src).await;

        // Drop the handler to close the channel and trigger shutdown flush.
        drop(handler);

        // Join the background task within 5s.
        tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("writer task must exit within 5s")
            .expect("writer task must not panic");
    }

    // -----------------------------------------------------------------------
    // zeek_local_start wires handler and join handle
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn zeek_local_start_wires_handler_and_join_handle() {
        use crate::config::ZeekLocalConfig;
        use crate::forwarding::local_sink::LocalDiskSink;
        use crate::zeek::listener::ZeekHandler;
        use std::net::SocketAddr;

        let dir = tempfile::tempdir().unwrap();
        let sink = Arc::new(
            LocalDiskSink::new(dir.path().to_path_buf())
                .await
                .expect("LocalDiskSink::new"),
        );
        let cfg = ZeekLocalConfig {
            directory: dir.path().to_path_buf(),
            prefix: "zeek".to_string(),
            flush_threshold_bytes: 1, // flush on first push
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_buffer_rows: 100_000,
        };
        let (handler, join_handle) = zeek_local_start(
            &cfg,
            sink,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );

        let src: SocketAddr = "127.0.0.1:47760".parse().unwrap();
        handler.handle_record(make_conn_record("Local1"), src).await;

        // Give the background flush a moment, then drop to trigger shutdown flush.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        drop(handler);
        tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("writer task must exit within 5s")
            .expect("writer task must not panic");

        // A real Parquet file must exist under zeek/conn/ on disk.
        let conn_dir = dir.path().join("zeek/conn");
        let found = std::fs::read_dir(&conn_dir)
            .expect("zeek/conn directory must exist")
            .count();
        assert!(
            found >= 1,
            "expected at least one Parquet file under {conn_dir:?}"
        );
    }

    // -----------------------------------------------------------------------
    // MultiZeekHandler tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn multi_zeek_handler_fans_out_to_every_inner_handler() {
        use crate::zeek::listener::ZeekHandler;
        use std::net::SocketAddr;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingHandler(Arc<AtomicUsize>);
        #[async_trait::async_trait]
        impl ZeekHandler for CountingHandler {
            async fn handle_record(&self, _record: ZeekRecord, _source: SocketAddr) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let count_a = Arc::new(AtomicUsize::new(0));
        let count_b = Arc::new(AtomicUsize::new(0));
        let multi = MultiZeekHandler(vec![
            Arc::new(CountingHandler(count_a.clone())),
            Arc::new(CountingHandler(count_b.clone())),
        ]);

        let src: SocketAddr = "127.0.0.1:47760".parse().unwrap();
        multi.handle_record(make_conn_record("Fan1"), src).await;

        assert_eq!(
            count_a.load(Ordering::SeqCst),
            1,
            "handler A must receive the record"
        );
        assert_eq!(
            count_b.load(Ordering::SeqCst),
            1,
            "handler B must receive the record"
        );
    }

    #[tokio::test]
    #[allow(clippy::mutable_key_type)]
    async fn multi_zeek_handler_survives_one_inner_handler_dropping() {
        use crate::forwarding::buffered_writer::ParquetWriterHandle;
        use crate::zeek::listener::ZeekHandler;
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::DebuggingRecorder;
        use std::net::SocketAddr;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        // Capacity 1, receiver held but never polled: the struggling
        // handler's channel genuinely stays full, so `send_or_drop` (with a
        // short timeout) reliably times out and drops on every send. A real
        // `zeek_start` writer task can't produce this: `push()` never awaits
        // the actual upload, so a real writer drains a healthy channel in
        // microseconds regardless of how broken the sink is, and would just
        // as well succeed for every record. Fan-out is now concurrent (via
        // join_all), so the struggling handler's 20ms wait-then-drop runs
        // alongside the healthy handler's send on every iteration — this
        // proves a healthy destination still receives every record even
        // while a sibling destination drops, under concurrent fan-out.
        let (tx, _rx) = tokio::sync::mpsc::channel::<ZeekRecord>(1);
        tx.try_send(make_conn_record("Cfirst")).unwrap();
        let struggling_handler = ParquetWriterHandle::<ZeekSink>::for_test(tx, "zeek", "s3")
            .with_send_timeout(std::time::Duration::from_millis(20));

        use std::sync::atomic::{AtomicUsize, Ordering};
        struct CountingHandler(Arc<AtomicUsize>);
        #[async_trait::async_trait]
        impl ZeekHandler for CountingHandler {
            async fn handle_record(&self, _record: ZeekRecord, _source: SocketAddr) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let healthy_count = Arc::new(AtomicUsize::new(0));
        let multi = MultiZeekHandler(vec![
            Arc::new(struggling_handler),
            Arc::new(CountingHandler(healthy_count.clone())),
        ]);

        let src: SocketAddr = "127.0.0.1:47760".parse().unwrap();
        for i in 0..20 {
            multi
                .handle_record(make_conn_record(&format!("C{i}")), src)
                .await;
        }

        assert_eq!(
            healthy_count.load(Ordering::SeqCst),
            20,
            "the healthy handler must receive every record even if the struggling one drops some"
        );

        let snapshot = snapshotter.snapshot();
        let map = snapshot.into_hashmap();
        let key = CompositeKey::new(
            MetricKind::Counter,
            metrics::Key::from_parts(
                "parquet_s3_dropped",
                vec![
                    metrics::Label::new("source", "zeek"),
                    metrics::Label::new("target", "s3"),
                ],
            ),
        );
        let dropped = map
            .get(&key)
            .map(|(_, _, v)| {
                if let metrics_util::debugging::DebugValue::Counter(c) = v {
                    *c
                } else {
                    0
                }
            })
            .unwrap_or(0);
        assert!(
            dropped >= 1,
            "the struggling handler must actually have dropped at least one record \
             for this test to prove handler isolation (dropped={dropped})"
        );
    }

    // -----------------------------------------------------------------------
    // Integration test (gated on env var)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn integration_records_produce_parquet_in_s3() {
        if std::env::var("ZEEK_S3_INTEGRATION_TEST").is_err() {
            eprintln!("skipping; set ZEEK_S3_INTEGRATION_TEST=1 to run against local MinIO");
            return;
        }
        use crate::zeek::listener::ZeekHandler;

        let bucket = std::env::var("ZEEK_S3_BUCKET").unwrap_or_else(|_| "zeek-test".to_string());
        let conn = S3ConnectionConfig {
            endpoint: "http://localhost:9000".to_string(),
            bucket: bucket.clone(),
            region: "us-east-1".to_string(),
            access_key: "minioadmin".to_string(),
            secret_key: "minioadmin".to_string(),
        };
        let sink = Arc::new(
            S3Sink::from_connection(&conn)
                .await
                .expect("S3Sink construct"),
        );
        let cfg = ZeekS3Config {
            connection: conn.clone(),
            prefix: "zeek".to_string(),
            flush_threshold_bytes: 1,
            flush_interval_secs: 1,
            channel_capacity: 256,
            max_buffer_rows: 100_000,
        };
        let (handler, _writer_handle) = zeek_start(
            &cfg,
            sink,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );
        let src: std::net::SocketAddr = "127.0.0.1:47760".parse().unwrap();

        for i in 0..5usize {
            handler
                .handle_record(make_conn_record(&format!("CInteg{i}")), src)
                .await;
        }
        for i in 0..3usize {
            handler
                .handle_record(make_dns_record(&format!("DInteg{i}")), src)
                .await;
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        use aws_config::meta::region::RegionProviderChain;
        use aws_credential_types::{Credentials, provider::SharedCredentialsProvider};
        use aws_sdk_s3::Client as S3Client;
        use aws_sdk_s3::config::Builder as S3ConfigBuilder;

        let region = RegionProviderChain::first_try(aws_sdk_s3::config::Region::new(
            "us-east-1".to_string(),
        ));
        let sdk_cfg = aws_config::from_env()
            .region(region)
            .endpoint_url("http://localhost:9000")
            .load()
            .await;
        let creds = SharedCredentialsProvider::new(Credentials::new(
            "minioadmin",
            "minioadmin",
            None,
            None,
            "test",
        ));
        let s3_cfg = S3ConfigBuilder::from(&sdk_cfg)
            .credentials_provider(creds)
            .force_path_style(true)
            .build();
        let client = S3Client::from_conf(s3_cfg);

        for prefix in &["zeek/conn/", "zeek/dns/"] {
            let resp = client
                .list_objects_v2()
                .bucket(&bucket)
                .prefix(*prefix)
                .send()
                .await
                .expect("list_objects_v2");
            assert!(
                !resp.contents().is_empty(),
                "expected >= 1 Parquet object under {prefix}"
            );
        }
    }

    #[tokio::test]
    async fn zeek_sink_reports_into_shared_source_hourly_stats() {
        use crate::forwarding::buffered_writer::{
            BufferedWriterConfig, FlushPolicy, PartitionedParquetWriter,
        };
        let s3 = unreachable_sink().await;
        let bwc = BufferedWriterConfig {
            connection: crate::config::S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "t".to_string(),
                region: "us-east-1".to_string(),
                access_key: "K".to_string(),
                secret_key: "S".to_string(),
            },
            prefix: "zeek".to_string(),
            max_buffer_rows: 1_000,
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 64,
            max_partitions: 256,
        };
        let policy = FlushPolicy {
            max_rows: 1_000,
            max_bytes: usize::MAX,
            interval: crate::forwarding::buffered_writer::LiveInterval::new(
                std::time::Duration::from_secs(3600),
            ),
        };
        let shared_stats = std::sync::Arc::new(crate::stats::SourceHourlyStats::new());

        let mut writer = PartitionedParquetWriter::with_source_stats(
            ZeekSink,
            s3,
            bwc,
            policy,
            shared_stats.clone(),
            None,
        );
        writer.push(make_conn_record("conn")).await.unwrap();

        let snapshot = shared_stats.snapshot();
        let row = snapshot.iter().find(|r| r.source == "zeek").unwrap();
        let total: u64 = row.hours.iter().map(|h| h.count).sum();
        assert_eq!(total, 1);
    }
}
