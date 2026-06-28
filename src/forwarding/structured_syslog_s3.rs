//! StructuredSyslog → S3 Parquet persistence (partitioned by payload_type).
//!
//! Schema: 9 columns — syslog envelope + payload_type + parsed (JSON string).
//! Partition key: payload_type string ("cef", "leef", "auditd", "dhcp",
//!                "radius", "web_access", "dns").
//! The sink reuses SyslogS3Config (identical connection/flush parameters).

use crate::config::SyslogS3Config;
use crate::forwarding::buffered_writer::ParquetSink;
use crate::syslog::payload::StructuredSyslogRecord;
use arrow::array::{ArrayRef, StringArray, UInt8Array};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use std::sync::{Arc, LazyLock};

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

static STRUCTURED_SYSLOG_SCHEMA: LazyLock<Arc<Schema>> = LazyLock::new(|| {
    Arc::new(Schema::new(vec![
        Field::new("priority",     DataType::UInt8, false),
        Field::new("severity",     DataType::UInt8, false),
        Field::new("facility",     DataType::UInt8, false),
        Field::new("timestamp",    DataType::Utf8,  true),
        Field::new("hostname",     DataType::Utf8,  true),
        Field::new("app_name",     DataType::Utf8,  true),
        Field::new("received_at",  DataType::Utf8,  false),
        Field::new("payload_type", DataType::Utf8,  false),
        Field::new("parsed",       DataType::Utf8,  false),
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
    let priority    = Arc::new(UInt8Array::from(vec![rec.priority]))    as ArrayRef;
    let severity    = Arc::new(UInt8Array::from(vec![rec.severity]))    as ArrayRef;
    let facility    = Arc::new(UInt8Array::from(vec![rec.facility]))    as ArrayRef;
    let timestamp   = Arc::new(StringArray::from(vec![
        rec.timestamp.as_ref().map(|t| t.to_rfc3339()),
    ])) as ArrayRef;
    let hostname    = Arc::new(StringArray::from(vec![rec.hostname.clone()]))   as ArrayRef;
    let app_name    = Arc::new(StringArray::from(vec![rec.app_name.clone()]))   as ArrayRef;
    let received_at = Arc::new(StringArray::from(vec![
        Some(rec.received_at.to_rfc3339()),
    ])) as ArrayRef;
    let payload_type = Arc::new(StringArray::from(vec![rec.payload_type])) as ArrayRef;
    let parsed = Arc::new(StringArray::from(vec![
        serde_json::to_string(&rec.parsed).unwrap_or_else(|_| "null".to_string()),
    ])) as ArrayRef;

    Ok(RecordBatch::try_new(
        schema,
        vec![
            priority, severity, facility, timestamp, hostname,
            app_name, received_at, payload_type, parsed,
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
) -> (StructuredS3Handler, tokio::task::JoinHandle<()>) {
    use crate::forwarding::buffered_writer::{
        BufferedWriterConfig, FlushPolicy, ParquetWriterHandle,
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
        interval: std::time::Duration::from_secs(cfg.flush_interval_secs),
    };
    ParquetWriterHandle::start(StructuredSyslogSink, s3, bwc, policy)
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
    fn schema_has_nine_columns() {
        let schema = structured_syslog_schema();
        assert_eq!(schema.fields().len(), 9,
            "expected 9 fields, got {}", schema.fields().len());
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

        let priority = batch.column(0).as_any().downcast_ref::<UInt8Array>().unwrap();
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
        let (handle, join_handle) = structured_syslog_start(&cfg, s3);
        // Drop the handle immediately — empty buffer → flush_all is a no-op →
        // writer task exits without any S3 call.
        drop(handle);
        // 2 s is generous; the task should join in well under 100 ms.
        tokio::time::timeout(std::time::Duration::from_secs(2), join_handle)
            .await
            .expect("writer task exits within 2s")
            .expect("no panic");
    }
}
