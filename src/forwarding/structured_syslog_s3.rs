//! StructuredSyslog → S3 Parquet persistence (partitioned by payload_type).
//!
//! Schema: 10 columns — syslog envelope, payload_type, parsed (JSON string),
//! and partition_time (non-null; derived from timestamp, clamped and
//! falling back to received_at -- see `ParquetSink::time_column`).
//! Partition key: payload_type string ("cef", "leef", "auditd", "dhcp",
//!                "radius", "web_access", "dns").
//! The sink reuses SyslogS3Config (identical connection/flush parameters).

use crate::config::SyslogS3Config;
use crate::forwarding::buffered_writer::ParquetSink;
use crate::syslog::payload::StructuredSyslogRecord;
use arrow::array::{ArrayRef, StringArray, TimestampMicrosecondArray, UInt8Array};
use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use arrow::record_batch::RecordBatch;
use std::sync::{Arc, LazyLock};

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

static STRUCTURED_SYSLOG_SCHEMA: LazyLock<Arc<Schema>> = LazyLock::new(|| {
    Arc::new(Schema::new(vec![
        Field::new("priority", DataType::UInt8, false),
        Field::new("severity", DataType::UInt8, false),
        Field::new("facility", DataType::UInt8, false),
        Field::new(
            "timestamp",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            true,
        ),
        Field::new("hostname", DataType::Utf8, true),
        Field::new("app_name", DataType::Utf8, true),
        Field::new(
            "received_at",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            false,
        ),
        Field::new("payload_type", DataType::Utf8, false),
        Field::new("parsed", DataType::Utf8, false),
        Field::new(
            "partition_time",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            false,
        ),
    ]))
});

pub fn structured_syslog_schema() -> Arc<Schema> {
    STRUCTURED_SYSLOG_SCHEMA.clone()
}

// ---------------------------------------------------------------------------
// Row mapping
// ---------------------------------------------------------------------------

pub fn structured_syslog_record_to_batch(
    rec: &StructuredSyslogRecord,
) -> anyhow::Result<RecordBatch> {
    let schema = structured_syslog_schema();
    let priority = Arc::new(UInt8Array::from(vec![rec.priority])) as ArrayRef;
    let severity = Arc::new(UInt8Array::from(vec![rec.severity])) as ArrayRef;
    let facility = Arc::new(UInt8Array::from(vec![rec.facility])) as ArrayRef;
    let tz: Arc<str> = Arc::from("UTC");
    let timestamp = Arc::new(
        TimestampMicrosecondArray::from(vec![rec.timestamp.map(|t| t.timestamp_micros())])
            .with_timezone(tz.clone()),
    ) as ArrayRef;
    let hostname = Arc::new(StringArray::from(vec![rec.hostname.clone()])) as ArrayRef;
    let app_name = Arc::new(StringArray::from(vec![rec.app_name.clone()])) as ArrayRef;
    let received_at = Arc::new(
        TimestampMicrosecondArray::from(vec![rec.received_at.timestamp_micros()])
            .with_timezone(tz.clone()),
    ) as ArrayRef;
    let payload_type = Arc::new(StringArray::from(vec![rec.payload_type])) as ArrayRef;
    let parsed = Arc::new(StringArray::from(vec![
        serde_json::to_string(&rec.parsed).unwrap_or_else(|_| "null".to_string()),
    ])) as ArrayRef;
    // `timestamp` is the syslog header's event time (nullable -- absent for
    // e.g. some CEF/LEEF payloads); `partition_time` derives the buffer's
    // day-clean column from it, clamped against and falling back to the
    // non-null `received_at`. See `crate::forwarding::buffered_writer::partition_time`.
    let partition_time_value =
        crate::forwarding::buffered_writer::partition_time(rec.timestamp, rec.received_at);
    let partition_time = Arc::new(
        TimestampMicrosecondArray::from(vec![partition_time_value.timestamp_micros()])
            .with_timezone(tz),
    ) as ArrayRef;

    Ok(RecordBatch::try_new(
        schema,
        vec![
            priority,
            severity,
            facility,
            timestamp,
            hostname,
            app_name,
            received_at,
            payload_type,
            parsed,
            partition_time,
        ],
    )?)
}

// ---------------------------------------------------------------------------
// StructuredSyslogSink — ParquetSink adapter
// ---------------------------------------------------------------------------

pub struct StructuredSyslogSink;

impl ParquetSink for StructuredSyslogSink {
    type Record = StructuredSyslogRecord;

    fn source(&self) -> &'static str {
        "structured_syslog"
    }

    fn partition(&self, record: &StructuredSyslogRecord) -> Option<String> {
        Some(record.payload_type.to_string())
    }

    fn schema(&self, _partition: Option<&str>) -> Arc<arrow_schema::Schema> {
        structured_syslog_schema()
    }

    /// Event time column for day bucketing. `partition_time` is non-null by
    /// construction (derived from the nullable `timestamp`, clamped and
    /// falling back to `received_at`), so a buffer keyed on its day is
    /// day-clean for every row even when parsed and unparsed-timestamp
    /// payloads land in the same partition. See `structured_syslog_record_to_batch`.
    fn time_column(&self) -> Option<&'static str> {
        Some("partition_time")
    }

    fn to_record_batch(
        &self,
        record: &StructuredSyslogRecord,
        _schema: &Arc<arrow_schema::Schema>,
    ) -> anyhow::Result<arrow_array::RecordBatch> {
        structured_syslog_record_to_batch(record)
    }
}

// ---------------------------------------------------------------------------
// Type alias + start function
// ---------------------------------------------------------------------------

pub type StructuredS3Handler =
    crate::forwarding::buffered_writer::ParquetWriterHandle<StructuredSyslogSink>;

/// Construct a `StructuredS3Handler` from `SyslogS3Config` (reusing the same
/// config shape; the `prefix` is used as the S3 key base path).
///
/// Returns `(handler, writer_task_handle)`.
pub fn structured_syslog_start(
    cfg: &SyslogS3Config,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<Arc<dyn crate::forwarding::buffered_writer::UploadSink>>,
) -> (StructuredS3Handler, tokio::task::JoinHandle<()>) {
    use crate::forwarding::buffered_writer::{
        BufferedWriterConfig, FlushPolicy, LiveInterval, ParquetWriterHandle,
    };

    let bwc = BufferedWriterConfig {
        connection: cfg.connection.clone(),
        prefix: cfg.prefix.clone(),
        max_buffer_rows: cfg.max_buffer_rows,
        flush_threshold_bytes: usize::MAX,
        flush_interval_secs: cfg.flush_interval_secs,
        channel_capacity: cfg.channel_capacity,
        // 7 known payload types + 1 overflow = 8 partitions max.
        max_partitions: 8,
    };
    let policy = FlushPolicy {
        max_rows: cfg.max_buffer_rows,
        max_bytes: usize::MAX,
        interval: LiveInterval::new(std::time::Duration::from_secs(cfg.flush_interval_secs)),
    };
    ParquetWriterHandle::start_with_stats(
        StructuredSyslogSink,
        s3,
        bwc,
        policy,
        source_stats,
        descriptor_sink,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forwarding::buffered_writer::ParquetSink;
    use crate::syslog::payload::StructuredSyslogRecord;
    use arrow::array::{StringArray, UInt8Array};

    fn sample_record(ptype: &'static str) -> StructuredSyslogRecord {
        StructuredSyslogRecord {
            priority: 134,
            severity: 6,
            facility: 16,
            timestamp: Some(
                chrono::DateTime::parse_from_rfc3339("2024-01-15T10:30:45Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            hostname: Some("fw01".into()),
            app_name: Some("ArcSight".into()),
            received_at: chrono::Utc::now(),
            payload_type: ptype,
            parsed: serde_json::json!({"src": "10.0.0.1", "dst": "10.0.0.2"}),
        }
    }

    #[test]
    fn schema_has_ten_columns() {
        let schema = structured_syslog_schema();
        assert_eq!(
            schema.fields().len(),
            10,
            "expected 10 fields, got {}",
            schema.fields().len()
        );
    }

    #[test]
    fn schema_partition_time_is_non_null_microsecond_timestamp() {
        use arrow::datatypes::{DataType, TimeUnit};
        let schema = structured_syslog_schema();
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
    fn schema_payload_type_is_non_nullable_utf8() {
        use arrow::datatypes::DataType;
        let schema = structured_syslog_schema();
        let f = schema.field_with_name("payload_type").unwrap();
        assert_eq!(f.data_type(), &DataType::Utf8);
        assert!(!f.is_nullable());
    }

    #[test]
    fn schema_parsed_is_non_nullable_utf8() {
        use arrow::datatypes::DataType;
        let schema = structured_syslog_schema();
        let f = schema.field_with_name("parsed").unwrap();
        assert_eq!(f.data_type(), &DataType::Utf8);
        assert!(!f.is_nullable());
    }

    #[test]
    fn schema_timestamp_and_received_at_are_microsecond_timestamps() {
        use arrow::datatypes::{DataType, TimeUnit};
        let schema = structured_syslog_schema();
        let expected = DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()));

        let f = schema.field_with_name("timestamp").unwrap();
        assert_eq!(f.data_type(), &expected);
        assert!(f.is_nullable());

        let f = schema.field_with_name("received_at").unwrap();
        assert_eq!(f.data_type(), &expected);
        assert!(!f.is_nullable()); // received_at is always set
    }

    #[test]
    fn absent_timestamp_is_null() {
        use arrow::array::{Array, TimestampMicrosecondArray};
        let mut rec = sample_record("cef");
        rec.timestamp = None;
        let batch = structured_syslog_record_to_batch(&rec).unwrap();
        let col = batch
            .column_by_name("timestamp")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert!(col.is_null(0));
    }

    #[test]
    fn timestamp_and_received_at_are_written_as_microseconds() {
        use arrow::array::TimestampMicrosecondArray;
        use chrono::TimeZone;
        let mut rec = sample_record("cef");
        rec.timestamp = Some(chrono::Utc.timestamp_opt(1_700_000_000, 0).unwrap());
        rec.received_at = chrono::Utc.timestamp_opt(1_700_000_001, 0).unwrap();
        let batch = structured_syslog_record_to_batch(&rec).unwrap();

        let ts = batch
            .column_by_name("timestamp")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(ts.value(0), 1_700_000_000_000_000);

        let received = batch
            .column_by_name("received_at")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(received.value(0), 1_700_000_001_000_000);
    }

    #[test]
    fn sink_partition_returns_payload_type() {
        let sink = StructuredSyslogSink;
        let rec = sample_record("cef");
        assert_eq!(sink.partition(&rec), Some("cef".to_string()));
    }

    #[test]
    fn sink_source_is_structured_syslog() {
        assert_eq!(StructuredSyslogSink.source(), "structured_syslog");
    }

    #[test]
    fn to_record_batch_produces_correct_values() {
        let sink = StructuredSyslogSink;
        let rec = sample_record("leef");
        let schema = sink.schema(Some("leef"));
        let batch = sink.to_record_batch(&rec, &schema).expect("batch");

        assert_eq!(batch.num_rows(), 1);

        let priority = batch
            .column(0)
            .as_any()
            .downcast_ref::<UInt8Array>()
            .unwrap();
        assert_eq!(priority.value(0), 134);

        let ptype_col = batch.column_by_name("payload_type").unwrap();
        let ptype = ptype_col.as_any().downcast_ref::<StringArray>().unwrap();
        assert_eq!(ptype.value(0), "leef");

        let parsed_col = batch.column_by_name("parsed").unwrap();
        let parsed = parsed_col.as_any().downcast_ref::<StringArray>().unwrap();
        let v: serde_json::Value = serde_json::from_str(parsed.value(0)).unwrap();
        assert_eq!(v["src"], "10.0.0.1");
    }

    #[test]
    fn to_record_batch_hostname_nullable() {
        use arrow::array::Array;
        let sink = StructuredSyslogSink;
        let mut rec = sample_record("cef");
        rec.hostname = None;
        let schema = sink.schema(Some("cef"));
        let batch = sink.to_record_batch(&rec, &schema).unwrap();
        let hostname = batch.column_by_name("hostname").unwrap();
        let arr = hostname.as_any().downcast_ref::<StringArray>().unwrap();
        assert!(arr.is_null(0));
    }

    #[test]
    fn structured_syslog_sink_time_column_partition_time_exists_in_schema() {
        let sink = StructuredSyslogSink;
        let col = sink
            .time_column()
            .expect("structured_syslog_sink must opt in to day partitioning");
        // Pin the exact column name, not just that SOME name resolves.
        assert_eq!(col, "partition_time");
        let schema = sink.schema(None);
        assert!(
            schema.field_with_name(col).is_ok(),
            "time_column() returned {:?}, which is not a field in the schema",
            col
        );
    }

    #[test]
    fn partition_time_equals_timestamp_on_distinctly_different_day() {
        use arrow::array::TimestampMicrosecondArray;
        let mut rec = sample_record("cef");
        // Event a full day before receipt -- an unmistakably different UTC
        // calendar day, so a bug that fell back to received_at could not
        // pass by accident.
        rec.received_at = chrono::DateTime::parse_from_rfc3339("2024-06-02T08:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let event = chrono::DateTime::parse_from_rfc3339("2024-06-01T03:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        rec.timestamp = Some(event);

        let batch = structured_syslog_record_to_batch(&rec).unwrap();
        let col = batch
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(col.value(0), event.timestamp_micros());
    }

    #[test]
    fn partition_time_falls_back_to_received_at_when_timestamp_is_null() {
        use arrow::array::TimestampMicrosecondArray;
        let mut rec = sample_record("cef");
        rec.timestamp = None;
        rec.received_at = chrono::DateTime::parse_from_rfc3339("2024-06-02T08:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let batch = structured_syslog_record_to_batch(&rec).unwrap();
        let col = batch
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(col.value(0), rec.received_at.timestamp_micros());
    }

    #[test]
    fn partition_time_falls_back_to_received_at_when_timestamp_outside_clamp() {
        use arrow::array::TimestampMicrosecondArray;
        let mut rec = sample_record("cef");
        rec.received_at = chrono::DateTime::parse_from_rfc3339("2024-06-02T08:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        // 60 days before receipt -- well past the 30-day backfill clamp.
        rec.timestamp = Some(rec.received_at - chrono::TimeDelta::days(60));

        let batch = structured_syslog_record_to_batch(&rec).unwrap();
        let col = batch
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(col.value(0), rec.received_at.timestamp_micros());
    }

    #[test]
    fn partition_time_mixed_null_and_valid_timestamp_same_receipt_day_agree_regression() {
        // The regression case for this addendum: a null-timestamp row and a
        // valid-timestamp row received on the same real day must derive the
        // buffer day from the SAME non-null column, never from
        // coalesce(timestamp, received_at) (which is not itself a column).
        use arrow::array::TimestampMicrosecondArray;
        let receipt_day_a = chrono::DateTime::parse_from_rfc3339("2024-06-02T08:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let receipt_day_b = chrono::DateTime::parse_from_rfc3339("2024-06-02T20:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let mut rec_a = sample_record("cef");
        rec_a.timestamp = None;
        rec_a.received_at = receipt_day_a;

        let mut rec_b = sample_record("leef");
        rec_b.timestamp = Some(receipt_day_b - chrono::TimeDelta::hours(1));
        rec_b.received_at = receipt_day_b;

        let batch_a = structured_syslog_record_to_batch(&rec_a).unwrap();
        let batch_b = structured_syslog_record_to_batch(&rec_b).unwrap();

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
            "a null-timestamp row and a valid-timestamp row received the same \
             day must land in the same partition_time day"
        );
    }

    #[tokio::test]
    async fn structured_syslog_start_wires_handle_and_join() {
        // Purpose: verify that structured_syslog_start returns a usable handle
        // and a JoinHandle, and that dropping the handle (closing the channel)
        // with an empty buffer causes the writer task to exit cleanly — no S3
        // round-trip is needed to test this wiring.
        //
        // Previously the test sent one record (with max_buffer_rows=1) which
        // immediately triggered a PutObject against the dead endpoint
        // http://127.0.0.1:1, racing the AWS SDK retry/connect budget against a
        // hardcoded 5 s timeout → flaky under concurrent test load.
        //
        // Fix: do not send any records.  flush_all() on channel-close iterates
        // only over non-empty partition buffers; with an empty buffer map it
        // returns instantly, so the task exits without any S3 call.
        use crate::config::{S3ConnectionConfig, SyslogS3Config};
        use crate::forwarding::s3_sink::S3Sink;

        let conn = S3ConnectionConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            bucket: "test".to_string(),
            region: "us-east-1".to_string(),
            access_key: "KEY".to_string(),
            secret_key: "SECRET".to_string(),
        };
        let s3 = Arc::new(S3Sink::from_connection(&conn).await.expect("constructs"));
        let cfg = SyslogS3Config {
            connection: conn,
            prefix: "structured-syslog-test".to_string(),
            // Large enough that a stray record never triggers an auto-flush.
            max_buffer_rows: 1_000,
            flush_interval_secs: 3600,
            channel_capacity: 16,
        };
        let (handle, join_handle) = structured_syslog_start(
            &cfg,
            s3,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );
        // Drop the handle immediately — empty buffer → flush_all is a no-op →
        // writer task exits without any S3 call.
        drop(handle);
        // 2 s is generous; the task should join in well under 100 ms.
        tokio::time::timeout(std::time::Duration::from_secs(2), join_handle)
            .await
            .expect("writer task exits within 2s")
            .expect("no panic");
    }

    #[tokio::test]
    async fn structured_syslog_sink_reports_into_shared_source_hourly_stats() {
        use crate::forwarding::buffered_writer::{
            BufferedWriterConfig, FlushPolicy, PartitionedParquetWriter,
        };
        let s3 = std::sync::Arc::new(
            crate::forwarding::s3_sink::S3Sink::from_connection(
                &crate::config::S3ConnectionConfig {
                    endpoint: "http://127.0.0.1:1".to_string(),
                    bucket: "t".to_string(),
                    region: "us-east-1".to_string(),
                    access_key: "K".to_string(),
                    secret_key: "S".to_string(),
                },
            )
            .await
            .unwrap(),
        );
        let bwc = BufferedWriterConfig {
            connection: crate::config::S3ConnectionConfig {
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
            interval: crate::forwarding::buffered_writer::LiveInterval::new(
                std::time::Duration::from_secs(3600),
            ),
        };
        let shared_stats = std::sync::Arc::new(crate::stats::SourceHourlyStats::new());

        let mut writer = PartitionedParquetWriter::with_source_stats(
            StructuredSyslogSink,
            s3,
            bwc,
            policy,
            shared_stats.clone(),
            None,
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
}
