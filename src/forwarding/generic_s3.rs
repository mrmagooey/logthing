//! Generic JSON / HEC → S3 Parquet persistence.
//!
//! `GenericSink` is a `ParquetSink` that partitions `GenericRecord`s by
//! `sourcetype`.  All partitions share a single fixed schema (6 columns):
//! `sourcetype`, `host` (nullable), `time` (nullable timestamp), `received_at`,
//! `fields` (JSON string), and `partition_time` (non-null; derived from `time`,
//! clamped and falling back to `received_at` -- see `ParquetSink::time_column`).
//! The `_overflow` partition uses the same schema.
//!
//! S3 key layout: `hec/<sourcetype>/year={Y}/month={MM}/day={DD}/{uuid}.parquet`

use crate::config::HecS3Config;
use crate::forwarding::buffered_writer::ParquetSink;
use crate::ingest::GenericRecord;
use arrow_array::{RecordBatch, StringArray, TimestampMicrosecondArray};
use arrow_schema::{DataType, Field, Schema, TimeUnit};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// GenericSink — ParquetSink adapter
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
pub struct GenericSink;

/// Build the fixed 6-column schema used for all HEC partitions.
fn generic_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("sourcetype", DataType::Utf8, false),
        Field::new("host", DataType::Utf8, true),
        Field::new(
            "time",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            true,
        ),
        Field::new(
            "received_at",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            false,
        ),
        Field::new("fields", DataType::Utf8, false),
        Field::new(
            "partition_time",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            false,
        ),
    ]))
}

impl ParquetSink for GenericSink {
    type Record = GenericRecord;

    fn source(&self) -> &'static str {
        "hec"
    }

    /// Partition key = `sourcetype`.  Invalid characters are preserved as-is
    /// because sourcetypes are operator-controlled (admin-set token required).
    fn partition(&self, record: &GenericRecord) -> Option<String> {
        Some(record.sourcetype.clone())
    }

    /// All partitions — including `_overflow` and `None` — use the same fixed
    /// 5-column schema.  There is no per-sourcetype typed schema.
    fn schema(&self, _partition: Option<&str>) -> Arc<Schema> {
        generic_schema()
    }

    /// Event time column for day bucketing. `partition_time` is non-null by
    /// construction (derived from the application-supplied, nullable `time`,
    /// clamped and falling back to `received_at`), so a buffer keyed on its
    /// day is day-clean for every row even when events with and without a
    /// `time` field land in the same sourcetype partition.
    fn time_column(&self) -> Option<&'static str> {
        Some("partition_time")
    }

    fn to_record_batch(
        &self,
        record: &GenericRecord,
        schema: &Arc<Schema>,
    ) -> anyhow::Result<RecordBatch> {
        // col 0: sourcetype (Utf8, non-null)
        let sourcetype = StringArray::from(vec![record.sourcetype.as_str()]);

        // col 1: host (Utf8, nullable)
        let host: StringArray = StringArray::from(vec![record.host.as_deref()]);

        // col 2: time (Timestamp(Microsecond, UTC), nullable)
        // IMPORTANT: must call .with_timezone("UTC") so the array's DataType
        // matches the schema field's Timestamp(Microsecond, Some("UTC")).
        let time_col = match &record.time {
            Some(dt) => TimestampMicrosecondArray::from(vec![Some(dt.timestamp_micros())]),
            None => TimestampMicrosecondArray::from(vec![None::<i64>]),
        }
        .with_timezone("UTC");

        // col 3: received_at (Timestamp(Microsecond, UTC), non-null)
        let received_col =
            TimestampMicrosecondArray::from(vec![Some(record.received_at.timestamp_micros())])
                .with_timezone("UTC");

        // col 4: fields (Utf8, non-null) — JSON-serialized
        let fields_json =
            serde_json::to_string(&record.fields).unwrap_or_else(|_| "{}".to_string());
        let fields_col = StringArray::from(vec![fields_json.as_str()]);

        // col 5: partition_time (Timestamp(Microsecond, UTC), non-null) —
        // derived from the nullable `time` (HEC's application-supplied event
        // time), clamped against and falling back to `received_at`. See
        // `crate::forwarding::buffered_writer::partition_time`.
        let partition_time_value =
            crate::forwarding::buffered_writer::partition_time(record.time, record.received_at);
        let partition_time_col =
            TimestampMicrosecondArray::from(vec![Some(partition_time_value.timestamp_micros())])
                .with_timezone("UTC");

        RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(sourcetype),
                Arc::new(host),
                Arc::new(time_col),
                Arc::new(received_col),
                Arc::new(fields_col),
                Arc::new(partition_time_col),
            ],
        )
        .map_err(|e| anyhow::anyhow!("GenericSink RecordBatch error: {e}"))
    }
}

// ---------------------------------------------------------------------------
// GenericS3Handler type alias + hec_start convenience constructor
// ---------------------------------------------------------------------------

/// `GenericS3Handler` is a thin alias for `ParquetWriterHandle<GenericSink>`.
pub type GenericS3Handler = crate::forwarding::buffered_writer::ParquetWriterHandle<GenericSink>;

/// Construct a `GenericS3Handler` from a `HecS3Config`, a pre-built `S3Sink`,
/// and the maximum distinct sourcetype partition count.
///
/// Returns `(handler, writer_join_handle)`.  The caller retains the `JoinHandle`
/// and awaits it during graceful shutdown after all `GenericS3Handler` clones
/// have been dropped (closing the channel and triggering the final flush).
pub fn hec_start(
    cfg: &HecS3Config,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
    max_partitions: usize,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<Arc<dyn crate::forwarding::buffered_writer::UploadSink>>,
) -> (GenericS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<GenericSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        max_partitions,
        s3,
        source_stats,
        descriptor_sink,
    )
}

/// Construct a `GenericS3Handler` from a `GenericLocalConfig` and a pre-built
/// `LocalDiskSink`. Structurally identical to `hec_start`, writing to local
/// disk instead of S3 — same `GenericSink` adapter, same buffering/flush/cap
/// machinery, same S3-key-shaped relative path layout on disk.
pub fn hec_local_start(
    cfg: &crate::config::GenericLocalConfig,
    sink: Arc<crate::forwarding::local_sink::LocalDiskSink>,
    max_partitions: usize,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<Arc<dyn crate::forwarding::buffered_writer::UploadSink>>,
) -> (GenericS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<GenericSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        max_partitions,
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
    use crate::ingest::GenericRecord;
    use chrono::Utc;
    use serde_json::json;
    use std::sync::Arc;

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

    fn make_record(sourcetype: &str) -> GenericRecord {
        GenericRecord {
            sourcetype: sourcetype.to_string(),
            host: Some("host1".to_string()),
            time: Some(Utc::now()),
            fields: json!({"action": "login", "user": "alice"}),
            received_at: Utc::now(),
        }
    }

    #[test]
    fn generic_sink_source_returns_hec() {
        assert_eq!(GenericSink.source(), "hec");
    }

    #[test]
    fn generic_sink_partition_uses_sourcetype() {
        let rec = make_record("access_log");
        assert_eq!(GenericSink.partition(&rec), Some("access_log".to_string()));
    }

    #[test]
    fn generic_sink_schema_has_six_columns() {
        let schema = GenericSink.schema(Some("access_log"));
        assert_eq!(schema.fields().len(), 6);
        for col in &[
            "sourcetype",
            "host",
            "time",
            "received_at",
            "fields",
            "partition_time",
        ] {
            assert!(
                schema.field_with_name(col).is_ok(),
                "schema must have column '{col}'"
            );
        }
    }

    #[test]
    fn schema_partition_time_is_non_null_microsecond_timestamp() {
        use arrow::datatypes::{DataType, TimeUnit};
        let schema = generic_schema();
        let f = schema
            .field_with_name("partition_time")
            .expect("partition_time column");
        assert_eq!(
            f.data_type(),
            &DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
        );
        assert!(!f.is_nullable(), "partition_time must be non-nullable");
    }

    #[test]
    fn generic_sink_schema_overflow_same_as_named() {
        // All partitions use the same fixed schema — no per-partition variation.
        assert_eq!(
            GenericSink.schema(Some("_overflow")),
            GenericSink.schema(Some("anything"))
        );
        assert_eq!(GenericSink.schema(None), GenericSink.schema(Some("x")));
    }

    #[test]
    fn generic_sink_to_record_batch_produces_one_row() {
        let rec = make_record("access_log");
        let schema = GenericSink.schema(Some("access_log"));
        let batch = GenericSink.to_record_batch(&rec, &schema).unwrap();
        assert_eq!(batch.num_rows(), 1);

        use arrow::array::StringArray;
        let st = batch
            .column_by_name("sourcetype")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(st.value(0), "access_log");

        let fields_col = batch
            .column_by_name("fields")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(fields_col.value(0)).expect("fields must be valid JSON");
        assert_eq!(parsed["user"], "alice");
    }

    #[test]
    fn generic_sink_null_host_produces_null_in_batch() {
        use arrow::array::{Array, StringArray, TimestampMicrosecondArray};
        let mut rec = make_record("mytype");
        rec.host = None;
        rec.time = None;
        let schema = GenericSink.schema(Some("mytype"));
        let batch = GenericSink.to_record_batch(&rec, &schema).unwrap();
        let host_col = batch
            .column_by_name("host")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert!(host_col.is_null(0), "null host must produce Arrow null");

        let time_col = batch
            .column_by_name("time")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert!(time_col.is_null(0), "null time must produce Arrow null");
    }

    #[test]
    fn schema_time_and_received_at_are_microsecond_timestamps() {
        use arrow::datatypes::{DataType, TimeUnit};
        let schema = generic_schema();
        let expected = DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()));
        assert_eq!(
            schema.field_with_name("time").unwrap().data_type(),
            &expected
        );
        assert!(schema.field_with_name("time").unwrap().is_nullable());
        assert_eq!(
            schema.field_with_name("received_at").unwrap().data_type(),
            &expected
        );
        assert!(!schema.field_with_name("received_at").unwrap().is_nullable());
    }

    #[test]
    fn time_and_received_at_are_written_as_microseconds() {
        use arrow::array::TimestampMicrosecondArray;
        use chrono::TimeZone;
        // 123_456 microseconds past the second — unmistakable from a
        // millisecond-truncated value (which would read 1_700_000_000_123).
        let dt = chrono::Utc
            .timestamp_opt(1_700_000_000, 123_456_000)
            .unwrap();
        let mut rec = make_record("access_log");
        rec.time = Some(dt);
        rec.received_at = dt;
        let schema = GenericSink.schema(Some("access_log"));
        let batch = GenericSink.to_record_batch(&rec, &schema).unwrap();

        let time_col = batch
            .column_by_name("time")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(time_col.value(0), 1_700_000_000_123_456);

        let received_col = batch
            .column_by_name("received_at")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(received_col.value(0), 1_700_000_000_123_456);
    }

    #[test]
    fn generic_sink_time_column_partition_time_exists_in_schema() {
        let sink = GenericSink;
        let col = sink
            .time_column()
            .expect("generic_sink must opt in to day partitioning");
        // Pin the exact column name, not just that SOME name resolves --
        // e.g. `Some("received_at")` would also resolve against this
        // schema but would reinstate the pre-`partition_time` straddling
        // bug for HEC.
        assert_eq!(col, "partition_time");
        let schema = sink.schema(None);
        assert!(
            schema.field_with_name(col).is_ok(),
            "time_column() returned {:?}, which is not a field in the schema",
            col
        );
    }

    #[test]
    fn partition_time_equals_time_on_distinctly_different_day() {
        use arrow::array::TimestampMicrosecondArray;
        use chrono::TimeZone;
        let mut rec = make_record("access_log");
        rec.received_at = chrono::Utc.with_ymd_and_hms(2024, 6, 2, 8, 0, 0).unwrap();
        let event = chrono::Utc.with_ymd_and_hms(2024, 6, 1, 3, 0, 0).unwrap();
        rec.time = Some(event);

        let schema = GenericSink.schema(Some("access_log"));
        let batch = GenericSink.to_record_batch(&rec, &schema).unwrap();
        let col = batch
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(col.value(0), event.timestamp_micros());
    }

    #[test]
    fn partition_time_falls_back_to_received_at_when_time_is_null() {
        use arrow::array::TimestampMicrosecondArray;
        use chrono::TimeZone;
        let mut rec = make_record("access_log");
        rec.time = None;
        rec.received_at = chrono::Utc.with_ymd_and_hms(2024, 6, 2, 8, 0, 0).unwrap();

        let schema = GenericSink.schema(Some("access_log"));
        let batch = GenericSink.to_record_batch(&rec, &schema).unwrap();
        let col = batch
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(col.value(0), rec.received_at.timestamp_micros());
    }

    #[test]
    fn partition_time_falls_back_to_received_at_when_time_outside_clamp() {
        use arrow::array::TimestampMicrosecondArray;
        use chrono::TimeZone;
        let mut rec = make_record("access_log");
        rec.received_at = chrono::Utc.with_ymd_and_hms(2024, 6, 2, 8, 0, 0).unwrap();
        // 60 days before receipt -- well past the 30-day backfill clamp.
        rec.time = Some(rec.received_at - chrono::TimeDelta::days(60));

        let schema = GenericSink.schema(Some("access_log"));
        let batch = GenericSink.to_record_batch(&rec, &schema).unwrap();
        let col = batch
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(col.value(0), rec.received_at.timestamp_micros());
    }

    #[test]
    fn partition_time_mixed_null_and_valid_time_same_receipt_day_agree_regression() {
        // The regression case for this addendum: a null-`time` HEC event and
        // a valid-`time` HEC event received the same real day must derive
        // the buffer day from the SAME non-null column, never from
        // coalesce(time, received_at) (which is not itself a column).
        use arrow::array::TimestampMicrosecondArray;
        use chrono::TimeZone;
        let receipt_day_a = chrono::Utc.with_ymd_and_hms(2024, 6, 2, 8, 0, 0).unwrap();
        let receipt_day_b = chrono::Utc.with_ymd_and_hms(2024, 6, 2, 20, 0, 0).unwrap();

        let mut rec_a = make_record("access_log");
        rec_a.time = None;
        rec_a.received_at = receipt_day_a;

        let mut rec_b = make_record("access_log");
        rec_b.time = Some(receipt_day_b - chrono::TimeDelta::hours(1));
        rec_b.received_at = receipt_day_b;

        let schema = GenericSink.schema(Some("access_log"));
        let batch_a = GenericSink.to_record_batch(&rec_a, &schema).unwrap();
        let batch_b = GenericSink.to_record_batch(&rec_b, &schema).unwrap();

        let day_of = |batch: &RecordBatch| {
            let col = batch
                .column_by_name("partition_time")
                .unwrap()
                .as_any()
                .downcast_ref::<TimestampMicrosecondArray>()
                .unwrap();
            chrono::DateTime::from_timestamp_micros(col.value(0))
                .unwrap()
                .date_naive()
        };

        assert_eq!(
            day_of(&batch_a),
            day_of(&batch_b),
            "a null-time row and a valid-time row received the same day must \
             land in the same partition_time day"
        );
    }

    #[tokio::test]
    async fn writer_partitions_by_sourcetype() {
        let sink = unreachable_sink().await;
        let bwc = BufferedWriterConfig {
            connection: S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "hec".to_string(),
            max_buffer_rows: 100_000,
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_partitions: 64,
        };
        let policy = FlushPolicy {
            max_rows: 100_000,
            max_bytes: usize::MAX,
            interval: crate::forwarding::buffered_writer::LiveInterval::new(
                std::time::Duration::from_secs(3600),
            ),
        };
        let mut writer = PartitionedParquetWriter::new(GenericSink, sink, bwc, policy);

        writer.push(make_record("access_log")).await.ok();
        writer.push(make_record("access_log")).await.ok();
        writer.push(make_record("audit_log")).await.ok();

        assert_eq!(
            writer
                .buffer_by_partition("access_log")
                .map(|b| b.row_count)
                .unwrap_or(0),
            2
        );
        assert_eq!(
            writer
                .buffer_by_partition("audit_log")
                .map(|b| b.row_count)
                .unwrap_or(0),
            1
        );
    }

    #[tokio::test]
    async fn writer_overflows_to_overflow_partition_at_cap() {
        let sink = unreachable_sink().await;
        let cap = 2usize;
        let bwc = BufferedWriterConfig {
            connection: S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "hec".to_string(),
            max_buffer_rows: 100_000,
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_partitions: cap,
        };
        let policy = FlushPolicy {
            max_rows: 100_000,
            max_bytes: usize::MAX,
            interval: crate::forwarding::buffered_writer::LiveInterval::new(
                std::time::Duration::from_secs(3600),
            ),
        };
        let mut writer = PartitionedParquetWriter::new(GenericSink, sink, bwc, policy);

        // Push cap + 3 distinct sourcetypes.
        for i in 0..(cap + 3) {
            writer.push(make_record(&format!("type_{i}"))).await.ok();
        }

        assert!(
            writer.buffers.len() <= cap + 1,
            "buffers map must be bounded (cap={cap} + 1 overflow)"
        );
        assert!(
            writer.buffer_by_partition("_overflow").is_some(),
            "_overflow partition must exist after cap exceeded"
        );
    }

    #[tokio::test]
    async fn hec_start_wires_handler_and_join_handle() {
        use crate::config::HecS3Config;

        let conn = S3ConnectionConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            bucket: "test-bucket".to_string(),
            region: "us-east-1".to_string(),
            access_key: "AKIATEST".to_string(),
            secret_key: "SECRETTEST".to_string(),
        };
        let s3 = Arc::new(S3Sink::from_connection(&conn).await.expect("S3Sink"));
        let cfg = HecS3Config {
            connection: conn,
            prefix: "hec".to_string(),
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_buffer_rows: 100_000,
        };
        let (handler, join_handle) = hec_start(
            &cfg,
            s3,
            64,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );
        handler
            .try_send(make_record("access_log"))
            .expect("send ok");
        drop(handler);
        tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("writer exits within 5s")
            .expect("writer does not panic");
    }

    #[tokio::test]
    async fn hec_local_start_wires_handler_and_join_handle() {
        use crate::config::GenericLocalConfig;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let sink = Arc::new(
            crate::forwarding::local_sink::LocalDiskSink::new(dir.path().to_path_buf())
                .await
                .expect("constructs"),
        );
        let cfg = GenericLocalConfig {
            directory: dir.path().to_path_buf(),
            prefix: "hec".to_string(),
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_buffer_rows: 100_000,
        };

        let (handler, join_handle) = hec_local_start(
            &cfg,
            sink,
            64,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );
        handler
            .try_send(make_record("access_log"))
            .expect("send ok");
        drop(handler);
        tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("writer exits within 5s")
            .expect("writer does not panic");
    }

    #[tokio::test]
    async fn generic_sink_reports_into_shared_source_hourly_stats() {
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
            prefix: "hec".to_string(),
            max_buffer_rows: 1_000,
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 64,
            max_partitions: 64,
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
            GenericSink,
            s3,
            bwc,
            policy,
            shared_stats.clone(),
            None,
        );
        writer.push(make_record("access_log")).await.unwrap();

        let snapshot = shared_stats.snapshot();
        let row = snapshot.iter().find(|r| r.source == "hec").unwrap();
        let total: u64 = row.hours.iter().map(|h| h.count).sum();
        assert_eq!(total, 1);
    }
}
