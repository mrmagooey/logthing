//! Syslog → S3 Parquet persistence.
//!
//! Provides:
//! - `syslog_schema()` — fixed Arrow schema for `SyslogMessage`
//! - `syslog_message_to_batch()` — convert one message to a single-row RecordBatch
//! - `SyslogSink` — `ParquetSink` adapter for the generic writer
//! - `SyslogS3Handler` — type alias for `ParquetWriterHandle<SyslogSink>`
//! - `syslog_start()` — convenience constructor wiring `SyslogS3Config` → `ParquetWriterHandle`

#[cfg(test)]
use crate::config::SyslogLocalConfig;
use crate::config::SyslogS3Config;
use crate::forwarding::buffered_writer::ParquetSink;
use crate::forwarding::drop_log::{DropKind, DropSite};
use crate::syslog::SyslogMessage;
use arrow::array::{ArrayRef, StringArray, TimestampMicrosecondArray, UInt8Array};
use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use arrow::record_batch::RecordBatch;
use std::sync::{Arc, LazyLock};

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

static SYSLOG_SCHEMA: LazyLock<Arc<Schema>> = LazyLock::new(|| {
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
        Field::new("proc_id", DataType::Utf8, true),
        Field::new("msg_id", DataType::Utf8, true),
        Field::new("message", DataType::Utf8, false),
        Field::new("structured_data", DataType::Utf8, true),
        Field::new("protocol", DataType::Utf8, false),
    ]))
});

/// Return the fixed Arrow schema for `SyslogMessage` rows.
pub fn syslog_schema() -> Arc<Schema> {
    SYSLOG_SCHEMA.clone()
}

// ---------------------------------------------------------------------------
// Row mapping
// ---------------------------------------------------------------------------

/// Map one `SyslogMessage` to a single-row `RecordBatch`.
pub fn syslog_message_to_batch(msg: &SyslogMessage) -> anyhow::Result<RecordBatch> {
    let schema = syslog_schema();

    let priority = Arc::new(UInt8Array::from(vec![msg.priority])) as ArrayRef;
    let severity = Arc::new(UInt8Array::from(vec![msg.severity])) as ArrayRef;
    let facility = Arc::new(UInt8Array::from(vec![msg.facility])) as ArrayRef;
    let tz: Arc<str> = Arc::from("UTC");
    let timestamp = Arc::new(
        TimestampMicrosecondArray::from(vec![msg.timestamp.map(|t| t.timestamp_micros())])
            .with_timezone(tz),
    ) as ArrayRef;
    let hostname = Arc::new(StringArray::from(vec![msg.hostname.clone()])) as ArrayRef;
    let app_name = Arc::new(StringArray::from(vec![msg.app_name.clone()])) as ArrayRef;
    let proc_id = Arc::new(StringArray::from(vec![msg.proc_id.clone()])) as ArrayRef;
    let msg_id = Arc::new(StringArray::from(vec![msg.msg_id.clone()])) as ArrayRef;
    let message = Arc::new(StringArray::from(vec![msg.message.clone()])) as ArrayRef;
    let structured_data = Arc::new(StringArray::from(vec![
        msg.structured_data
            .as_ref()
            .and_then(|sd| serde_json::to_string(sd).ok()),
    ])) as ArrayRef;
    let protocol = Arc::new(StringArray::from(vec![format!("{:?}", msg.protocol)])) as ArrayRef;

    Ok(RecordBatch::try_new(
        schema,
        vec![
            priority,
            severity,
            facility,
            timestamp,
            hostname,
            app_name,
            proc_id,
            msg_id,
            message,
            structured_data,
            protocol,
        ],
    )?)
}

// ---------------------------------------------------------------------------
// Parquet encoding (kept as private helper for tests)
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) fn encode_batches_to_parquet(batches: &[RecordBatch]) -> anyhow::Result<Vec<u8>> {
    use parquet::arrow::ArrowWriter;
    use parquet::basic::{Compression, ZstdLevel};
    use parquet::file::properties::WriterProperties;

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

// ---------------------------------------------------------------------------
// SyslogSink — ParquetSink adapter
// ---------------------------------------------------------------------------

/// `ParquetSink` adapter for syslog messages.
/// The `Record` type is `SyslogMessage` — one row per message.
#[derive(Default)]
pub struct SyslogSink;

impl ParquetSink for SyslogSink {
    type Record = SyslogMessage;

    fn source(&self) -> &'static str {
        "syslog"
    }

    fn partition(&self, _: &SyslogMessage) -> Option<String> {
        None
    }

    fn schema(&self, _: Option<&str>) -> Arc<arrow_schema::Schema> {
        syslog_schema()
    }

    fn to_record_batch(
        &self,
        record: &SyslogMessage,
        _schema: &Arc<arrow_schema::Schema>,
    ) -> anyhow::Result<arrow_array::RecordBatch> {
        syslog_message_to_batch(record)
    }
}

// ---------------------------------------------------------------------------
// SyslogS3Handler — type alias + SyslogHandler impl
// ---------------------------------------------------------------------------

/// `SyslogS3Handler` is a thin alias for the generic `ParquetWriterHandle<SyslogSink>`.
pub type SyslogS3Handler = crate::forwarding::buffered_writer::ParquetWriterHandle<SyslogSink>;

#[async_trait::async_trait]
impl crate::syslog::listener::SyslogHandler
    for crate::forwarding::buffered_writer::ParquetWriterHandle<SyslogSink>
{
    async fn handle_message(&self, message: SyslogMessage, _source: std::net::SocketAddr) {
        match self.try_send(message) {
            Ok(()) => {}
            Err(e) => {
                if let Some(dropped_total) = self.drop_log_due(DropSite::Syslog, DropKind::from(&e))
                {
                    tracing::warn!(dropped_total, "Syslog S3 channel full; dropped message");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// syslog_start — convenience constructor
// ---------------------------------------------------------------------------

/// Construct a `SyslogS3Handler` (i.e. `ParquetWriterHandle<SyslogSink>`) from a
/// `SyslogS3Config` and a pre-built `S3Sink`.
///
/// Returns `(handler, writer_task_handle)`. The caller should retain the `JoinHandle`
/// and await it during graceful shutdown, after all `Arc<dyn SyslogHandler>` references
/// have been dropped so the channel closes and the final flush fires.
pub fn syslog_start(
    cfg: &SyslogS3Config,
    s3: std::sync::Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<std::sync::Arc<dyn crate::forwarding::buffered_writer::UploadSink>>,
) -> (SyslogS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<SyslogSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        usize::MAX, // syslog uses row-count + age triggers only
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        1,
        s3,
        source_stats,
        descriptor_sink,
    )
}

/// Construct a `SyslogS3Handler` from a `SyslogLocalConfig` and a pre-built
/// `LocalDiskSink`. Structurally identical to `syslog_start`, writing to
/// local disk instead of S3 — same `SyslogSink` adapter, same
/// buffering/flush/cap machinery, same S3-key-shaped relative path layout
/// on disk.
pub fn syslog_local_start(
    cfg: &crate::config::SyslogLocalConfig,
    sink: std::sync::Arc<crate::forwarding::local_sink::LocalDiskSink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<std::sync::Arc<dyn crate::forwarding::buffered_writer::UploadSink>>,
) -> (SyslogS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<SyslogSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        usize::MAX, // syslog uses row-count + age triggers only
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        1,
        sink,
        source_stats,
        descriptor_sink,
    )
}

/// Fans out each message to every configured handler. Used only when at
/// least one of `.s3` / `.local` persistence resolves to a live handler for
/// this run — `main.rs` always wraps the resulting `MultiSyslogHandler` (or
/// the sole handler, if that's the only element) as the `inner` of a
/// `PayloadDispatchingHandler`, never in place of it. Each destination keeps
/// its own independent buffer, flush policy, backpressure, and hard cap (no
/// shared state between destinations).
pub struct MultiSyslogHandler(pub Vec<std::sync::Arc<dyn crate::syslog::listener::SyslogHandler>>);

#[async_trait::async_trait]
impl crate::syslog::listener::SyslogHandler for MultiSyslogHandler {
    async fn handle_message(&self, message: SyslogMessage, source: std::net::SocketAddr) {
        for handler in &self.0 {
            handler.handle_message(message.clone(), source).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syslog::{SyslogMessage, SyslogProtocol};
    use arrow::array::Array as ArrowArray; // needed for .is_null()
    use std::collections::HashMap;

    // -- helpers --

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

    fn dummy_msg(text: &str) -> SyslogMessage {
        SyslogMessage {
            priority: 0,
            severity: 0,
            facility: 0,
            timestamp: None,
            hostname: None,
            app_name: None,
            proc_id: None,
            msg_id: None,
            message: text.to_string(),
            structured_data: None,
            protocol: SyslogProtocol::Unknown,
        }
    }

    // -- helper: unreachable S3Sink --

    async fn unreachable_sink() -> Arc<crate::forwarding::s3_sink::S3Sink> {
        use crate::config::S3ConnectionConfig;
        let conn = S3ConnectionConfig {
            endpoint: "http://127.0.0.1:1".to_string(), // port 1 is always refused
            bucket: "test-bucket".to_string(),
            region: "us-east-1".to_string(),
            access_key: "AKIATEST".to_string(),
            secret_key: "SECRETTEST".to_string(),
        };
        Arc::new(
            crate::forwarding::s3_sink::S3Sink::from_connection(&conn)
                .await
                .expect("constructs"),
        )
    }

    // -- Task 1: schema shape --

    #[test]
    fn schema_has_correct_columns_and_types() {
        use arrow::datatypes::{DataType, TimeUnit};
        let schema = syslog_schema();
        assert_eq!(schema.fields().len(), 11);
        assert_eq!(
            schema.field_with_name("priority").unwrap().data_type(),
            &DataType::UInt8
        );
        assert!(!schema.field_with_name("priority").unwrap().is_nullable());
        assert_eq!(
            schema.field_with_name("timestamp").unwrap().data_type(),
            &DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
        );
        assert!(schema.field_with_name("timestamp").unwrap().is_nullable());
        assert_eq!(
            schema
                .field_with_name("structured_data")
                .unwrap()
                .data_type(),
            &DataType::Utf8
        );
        assert!(
            schema
                .field_with_name("structured_data")
                .unwrap()
                .is_nullable()
        );
        assert!(!schema.field_with_name("protocol").unwrap().is_nullable());
    }

    #[test]
    fn timestamp_is_written_as_microseconds() {
        use chrono::TimeZone;
        let mut msg = sample_rfc5424();
        msg.timestamp = Some(chrono::Utc.timestamp_opt(1_700_000_000, 0).unwrap());
        let batch = syslog_message_to_batch(&msg).unwrap();
        let col = batch
            .column_by_name("timestamp")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .expect("timestamp should be TimestampMicrosecondArray");
        assert_eq!(col.value(0), 1_700_000_000_000_000);
    }

    #[test]
    fn absent_timestamp_is_null() {
        let mut msg = sample_rfc5424();
        msg.timestamp = None;
        let batch = syslog_message_to_batch(&msg).unwrap();
        let col = batch
            .column_by_name("timestamp")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert!(col.is_null(0));
    }

    // -- Task 1: row mapping --

    #[test]
    fn row_mapping_produces_expected_column_values() {
        use arrow::array::{StringArray, UInt8Array};
        let msg = sample_rfc5424();
        let batch = syslog_message_to_batch(&msg).expect("batch");
        assert_eq!(batch.num_rows(), 1);
        assert_eq!(batch.num_columns(), 11);

        let priority = batch
            .column(0)
            .as_any()
            .downcast_ref::<UInt8Array>()
            .unwrap();
        assert_eq!(priority.value(0), 34);

        let hostname = batch
            .column(4)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(hostname.value(0), "mymachine");

        // proc_id is None → null
        let proc_id = batch
            .column(6)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert!(proc_id.is_null(0));

        // structured_data is JSON
        let sd_col = batch
            .column(9)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert!(sd_col.value(0).contains("example@32473"));

        let protocol = batch
            .column(10)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
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
        let ts = batch
            .column(3)
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert!(ts.is_null(0));
        let sd = batch
            .column(9)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert!(sd.is_null(0));
    }

    // -- Task 2: Parquet round-trip --

    #[test]
    fn encode_parquet_round_trips_expected_schema_and_values() {
        use bytes::Bytes;
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

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
        let raw = encode_batches_to_parquet(&[batch]).unwrap();
        assert!(!raw.is_empty(), "Parquet bytes must not be empty");

        // ParquetRecordBatchReaderBuilder requires bytes::Bytes (implements ChunkReader)
        let buf = Bytes::from(raw);
        let builder = ParquetRecordBatchReaderBuilder::try_new(buf).unwrap();
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
        use bytes::Bytes;
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

        let batches: Vec<_> = ["alpha", "beta", "gamma"]
            .iter()
            .map(|t| syslog_message_to_batch(&dummy_msg(t)).unwrap())
            .collect();

        let raw = encode_batches_to_parquet(&batches).unwrap();
        let buf = Bytes::from(raw);
        let mut reader = ParquetRecordBatchReaderBuilder::try_new(buf)
            .unwrap()
            .build()
            .unwrap();

        let mut total_rows = 0usize;
        for rb in reader.by_ref() {
            total_rows += rb.unwrap().num_rows();
        }
        assert_eq!(total_rows, 3);
    }

    // -- SyslogSink adapter tests --

    #[test]
    fn syslog_sink_source_returns_syslog() {
        assert_eq!(SyslogSink.source(), "syslog");
    }

    #[test]
    fn syslog_sink_partition_returns_none() {
        let msg = dummy_msg("test");
        assert!(SyslogSink.partition(&msg).is_none());
    }

    #[test]
    fn syslog_sink_to_record_batch_produces_correct_schema_and_rows() {
        use crate::forwarding::buffered_writer::ParquetSink;
        use arrow::array::StringArray;

        let sink = SyslogSink;
        let schema = sink.schema(None);
        assert_eq!(schema.fields().len(), 11);

        let msg = sample_rfc5424();
        let batch = sink.to_record_batch(&msg, &schema).unwrap();
        assert_eq!(batch.num_rows(), 1);

        let hostname = batch
            .column(4)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(hostname.value(0), "mymachine");
    }

    #[tokio::test]
    async fn syslog_start_wires_handler_and_join_handle() {
        use crate::config::S3ConnectionConfig;
        use crate::syslog::listener::SyslogHandler as SyslogHandlerTrait;
        use std::net::SocketAddr;

        let sink = unreachable_sink().await;
        let cfg = SyslogS3Config {
            connection: S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "syslog".to_string(),
            max_buffer_rows: 10_000,
            flush_interval_secs: 3600,
            channel_capacity: 4096,
        };

        let (handler, join_handle) = syslog_start(
            &cfg,
            sink,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );

        // try_send one message through the handler
        let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();
        handler.handle_message(dummy_msg("hello"), src).await;

        // Drop the handler to close the channel and trigger shutdown flush
        drop(handler);

        // Join the background task within 5s
        tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("writer task must exit within 5s")
            .expect("writer task must not panic");
    }

    #[tokio::test]
    async fn syslog_local_start_wires_handler_and_join_handle() {
        use crate::syslog::listener::SyslogHandler as SyslogHandlerTrait;
        use std::net::SocketAddr;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let sink = Arc::new(
            crate::forwarding::local_sink::LocalDiskSink::new(dir.path().to_path_buf())
                .await
                .expect("constructs"),
        );
        let cfg = SyslogLocalConfig {
            directory: dir.path().to_path_buf(),
            prefix: "syslog".to_string(),
            max_buffer_rows: 10_000,
            flush_interval_secs: 3600,
            channel_capacity: 4096,
        };

        let (handler, join_handle) = syslog_local_start(
            &cfg,
            sink,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );

        let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();
        handler.handle_message(dummy_msg("hello"), src).await;

        drop(handler);

        tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("writer task must exit within 5s")
            .expect("writer task must not panic");
    }

    #[tokio::test]
    async fn multi_syslog_handler_fans_out_to_every_inner_handler() {
        use crate::syslog::listener::SyslogHandler as SyslogHandlerTrait;
        use std::net::SocketAddr;
        use std::sync::Mutex;

        struct CountingHandler {
            count: Mutex<usize>,
        }

        #[async_trait::async_trait]
        impl SyslogHandlerTrait for CountingHandler {
            async fn handle_message(&self, _message: SyslogMessage, _source: SocketAddr) {
                *self.count.lock().unwrap() += 1;
            }
        }

        let h1 = Arc::new(CountingHandler {
            count: Mutex::new(0),
        });
        let h2 = Arc::new(CountingHandler {
            count: Mutex::new(0),
        });
        let multi = MultiSyslogHandler(vec![h1.clone(), h2.clone()]);

        let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();
        multi.handle_message(dummy_msg("test"), src).await;

        assert_eq!(*h1.count.lock().unwrap(), 1);
        assert_eq!(*h2.count.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn multi_syslog_handler_survives_one_inner_handler_dropping() {
        use crate::syslog::listener::SyslogHandler as SyslogHandlerTrait;
        use std::net::SocketAddr;

        let sink = unreachable_sink().await;
        let cfg = SyslogS3Config {
            connection: crate::config::S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "syslog".to_string(),
            max_buffer_rows: 10_000,
            flush_interval_secs: 3600,
            channel_capacity: 4096,
        };
        let (handler, join_handle) = syslog_start(
            &cfg,
            sink,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );
        let live: Arc<dyn SyslogHandlerTrait> = Arc::new(handler);

        let multi = MultiSyslogHandler(vec![live.clone()]);
        let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();
        multi.handle_message(dummy_msg("still works"), src).await;

        drop(live);
        drop(multi);
        tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("writer task must exit within 5s")
            .expect("writer task must not panic");
    }

    #[tokio::test]
    async fn syslog_sink_reports_into_shared_source_hourly_stats() {
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
            prefix: "syslog".to_string(),
            max_buffer_rows: 1_000,
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 64,
            max_partitions: 1,
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
            SyslogSink,
            s3,
            bwc,
            policy,
            shared_stats.clone(),
            None,
        );
        writer.push(dummy_msg("test")).await.unwrap();

        let snapshot = shared_stats.snapshot();
        let row = snapshot.iter().find(|r| r.source == "syslog").unwrap();
        let total: u64 = row.hours.iter().map(|h| h.count).sum();
        assert_eq!(total, 1);
    }
}
