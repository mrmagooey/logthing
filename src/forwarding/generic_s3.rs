//! Generic JSON / HEC → S3 Parquet persistence.
//!
//! `GenericSink` is a `ParquetSink` that partitions `GenericRecord`s by
//! `sourcetype`.  All partitions share a single fixed schema (5 columns):
//! `sourcetype`, `host` (nullable), `time` (nullable timestamp), `received_at`,
//! and `fields` (JSON string).  The `_overflow` partition uses the same schema.
//!
//! S3 key layout: `hec/<sourcetype>/year={Y}/month={MM}/day={DD}/{uuid}.parquet`

use crate::config::HecS3Config;
use crate::forwarding::buffered_writer::ParquetSink;
use crate::ingest::GenericRecord;
use arrow_array::{RecordBatch, StringArray, TimestampMillisecondArray};
use arrow_schema::{DataType, Field, Schema, TimeUnit};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// GenericSink — ParquetSink adapter
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct GenericSink;

/// Build the fixed 5-column schema used for all HEC partitions.
fn generic_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("sourcetype", DataType::Utf8, false),
        Field::new("host", DataType::Utf8, true),
        Field::new(
            "time",
            DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into())),
            true,
        ),
        Field::new(
            "received_at",
            DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into())),
            false,
        ),
        Field::new("fields", DataType::Utf8, false),
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

    fn to_record_batch(
        &self,
        record: &GenericRecord,
        schema: &Arc<Schema>,
    ) -> anyhow::Result<RecordBatch> {
        // col 0: sourcetype (Utf8, non-null)
        let sourcetype = StringArray::from(vec![record.sourcetype.as_str()]);

        // col 1: host (Utf8, nullable)
        let host: StringArray = StringArray::from(vec![record.host.as_deref()]);

        // col 2: time (Timestamp(Millisecond, UTC), nullable)
        // IMPORTANT: must call .with_timezone("UTC") so the array's DataType
        // matches the schema field's Timestamp(Millisecond, Some("UTC")).
        let time_col = match &record.time {
            Some(dt) => {
                TimestampMillisecondArray::from(vec![Some(dt.timestamp_millis())])
            }
            None => TimestampMillisecondArray::from(vec![None::<i64>]),
        }
        .with_timezone("UTC");

        // col 3: received_at (Timestamp(Millisecond, UTC), non-null)
        let received_col =
            TimestampMillisecondArray::from(vec![Some(record.received_at.timestamp_millis())])
                .with_timezone("UTC");

        // col 4: fields (Utf8, non-null) — JSON-serialized
        let fields_json = serde_json::to_string(&record.fields)
            .unwrap_or_else(|_| "{}".to_string());
        let fields_col = StringArray::from(vec![fields_json.as_str()]);

        RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(sourcetype),
                Arc::new(host),
                Arc::new(time_col),
                Arc::new(received_col),
                Arc::new(fields_col),
            ],
        )
        .map_err(|e| anyhow::anyhow!("GenericSink RecordBatch error: {e}"))
    }
}

// ---------------------------------------------------------------------------
// GenericS3Handler type alias + hec_start convenience constructor
// ---------------------------------------------------------------------------

/// `GenericS3Handler` is a thin alias for `ParquetWriterHandle<GenericSink>`.
pub type GenericS3Handler =
    crate::forwarding::buffered_writer::ParquetWriterHandle<GenericSink>;

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
) -> (GenericS3Handler, tokio::task::JoinHandle<()>) {
    use crate::forwarding::buffered_writer::{
        BufferedWriterConfig, FlushPolicy, ParquetWriterHandle,
    };

    let bwc = BufferedWriterConfig {
        connection: cfg.connection.clone(),
        prefix: cfg.prefix.clone(),
        max_buffer_rows: cfg.max_buffer_rows,
        flush_threshold_bytes: cfg.flush_threshold_bytes,
        flush_interval_secs: cfg.flush_interval_secs,
        channel_capacity: cfg.channel_capacity,
        max_partitions,
    };
    let policy = FlushPolicy {
        max_rows: cfg.max_buffer_rows,
        max_bytes: cfg.flush_threshold_bytes,
        interval: std::time::Duration::from_secs(cfg.flush_interval_secs),
    };
    ParquetWriterHandle::start(GenericSink, s3, bwc, policy)
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
    fn generic_sink_schema_has_five_columns() {
        let schema = GenericSink.schema(Some("access_log"));
        assert_eq!(schema.fields().len(), 5);
        for col in &["sourcetype", "host", "time", "received_at", "fields"] {
            assert!(
                schema.field_with_name(col).is_ok(),
                "schema must have column '{col}'"
            );
        }
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
        use arrow::array::{Array, StringArray, TimestampMillisecondArray};
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
            .downcast_ref::<TimestampMillisecondArray>()
            .unwrap();
        assert!(time_col.is_null(0), "null time must produce Arrow null");
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
            interval: std::time::Duration::from_secs(3600),
        };
        let mut writer = PartitionedParquetWriter::new(GenericSink, sink, bwc, policy);

        writer.push(make_record("access_log")).await.ok();
        writer.push(make_record("access_log")).await.ok();
        writer.push(make_record("audit_log")).await.ok();

        assert_eq!(
            writer.buffers.get("access_log").map(|b| b.row_count).unwrap_or(0),
            2
        );
        assert_eq!(
            writer.buffers.get("audit_log").map(|b| b.row_count).unwrap_or(0),
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
            interval: std::time::Duration::from_secs(3600),
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
            writer.buffers.contains_key("_overflow"),
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
        let (handler, join_handle) = hec_start(&cfg, s3, 64);
        handler.try_send(make_record("access_log")).expect("send ok");
        drop(handler);
        tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("writer exits within 5s")
            .expect("writer does not panic");
    }
}
