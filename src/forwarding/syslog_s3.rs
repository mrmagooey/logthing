//! Syslog → S3 Parquet persistence.
//!
//! Provides:
//! - `syslog_schema()` — fixed Arrow schema for `SyslogMessage`
//! - `syslog_message_to_batch()` — convert one message to a single-row RecordBatch
//! - `encode_batches_to_parquet()` — encode a slice of RecordBatches to Parquet bytes
//! - `SyslogS3Writer` — buffers RecordBatches and flushes to S3 on size/age thresholds
//! - `SyslogS3Handler` — implements `SyslogHandler`, wraps a bounded channel + background writer

use crate::forwarding::s3_sink::S3Sink;
use crate::syslog::SyslogMessage;
use arrow::array::{ArrayRef, StringArray, UInt8Array};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use chrono::{Datelike, Utc};
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;
use std::sync::{Arc, LazyLock};
use tokio::sync::mpsc;
use tracing::warn;

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

static SYSLOG_SCHEMA: LazyLock<Arc<Schema>> = LazyLock::new(|| {
    Arc::new(Schema::new(vec![
        Field::new("priority", DataType::UInt8, false),
        Field::new("severity", DataType::UInt8, false),
        Field::new("facility", DataType::UInt8, false),
        Field::new("timestamp", DataType::Utf8, true),
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
    let timestamp = Arc::new(StringArray::from(vec![
        msg.timestamp.as_ref().map(|t| t.to_rfc3339()),
    ])) as ArrayRef;
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
// Parquet encoding
// ---------------------------------------------------------------------------

/// Encode a slice of `RecordBatch`es (all sharing `syslog_schema()`) into a Parquet byte buffer.
/// Returns an empty `Vec` if `batches` is empty.
pub(crate) fn encode_batches_to_parquet(batches: &[RecordBatch]) -> anyhow::Result<Vec<u8>> {
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
// SyslogS3Writer
// ---------------------------------------------------------------------------

/// Writer configuration.
pub struct SyslogS3WriterConfig {
    /// Maximum number of buffered rows before an automatic flush is triggered.
    pub max_buffer_rows: usize,
    /// Maximum wall-clock age of a non-empty buffer before flush.
    pub flush_interval: std::time::Duration,
    /// S3 key prefix, e.g. `"syslog/"`.  A trailing slash is conventional.
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

/// Buffers `SyslogMessage` rows as Arrow `RecordBatch`es and flushes to S3 as Parquet.
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

    /// Append one message to the buffer; flushes immediately if the row-count threshold is met.
    pub async fn push(&mut self, msg: &SyslogMessage) -> anyhow::Result<()> {
        let batch = syslog_message_to_batch(msg)?;
        self.buffer_row_count += batch.num_rows();
        self.buffer.push(batch);
        if self.buffer_row_count >= self.config.max_buffer_rows {
            self.flush().await?;
        }
        Ok(())
    }

    /// Flush if the age or row-count threshold is exceeded; no-op if the buffer is empty.
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

    /// Unconditionally encode all buffered rows to Parquet and upload via `self.sink`.
    /// Clears the buffer on success.
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

    /// Encode the current buffer to Parquet without uploading.
    /// Returns `None` if the buffer is empty.
    #[allow(dead_code)]
    pub fn encode_parquet(&self) -> anyhow::Result<Option<Vec<u8>>> {
        if self.buffer.is_empty() {
            return Ok(None);
        }
        Ok(Some(encode_batches_to_parquet(&self.buffer)?))
    }

    /// Build the S3 object key: `{prefix}year={Y}/month={MM}/day={DD}/{uuid}.parquet`
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

// ---------------------------------------------------------------------------
// SyslogS3Handler
// ---------------------------------------------------------------------------

/// Channel capacity for the handler → writer channel.
pub const SYSLOG_S3_CHANNEL_CAPACITY: usize = 4_096;

/// `SyslogHandler` implementation that forwards messages through a bounded channel to a background
/// writer task.  Messages dropped on overflow increment `syslog_s3_dropped`.
pub struct SyslogS3Handler {
    sender: mpsc::Sender<SyslogMessage>,
}

impl SyslogS3Handler {
    /// Construct a handler and start the writer background task.
    pub fn start(config: SyslogS3WriterConfig, sink: Arc<S3Sink>) -> Self {
        let (tx, mut rx) = mpsc::channel::<SyslogMessage>(SYSLOG_S3_CHANNEL_CAPACITY);
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
                                // Sender dropped — flush remaining and exit.
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
    async fn handle_message(&self, message: SyslogMessage, _source: std::net::SocketAddr) {
        match self.sender.try_send(message) {
            Ok(()) => {}
            Err(_) => {
                metrics::counter!("syslog_s3_dropped").increment(1);
            }
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

    // -- Task 1: schema shape --

    #[test]
    fn schema_has_correct_columns_and_types() {
        use arrow::datatypes::DataType;
        let schema = syslog_schema();
        assert_eq!(schema.fields().len(), 11);
        assert_eq!(
            schema.field_with_name("priority").unwrap().data_type(),
            &DataType::UInt8
        );
        assert!(!schema.field_with_name("priority").unwrap().is_nullable());
        assert_eq!(
            schema.field_with_name("timestamp").unwrap().data_type(),
            &DataType::Utf8
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
            .downcast_ref::<StringArray>()
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

    #[test]
    fn push_accumulates_and_flush_clears_buffer() {
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

    // -- Task 3: channel semantics --

    #[tokio::test]
    async fn channel_try_send_on_full_returns_err() {
        use tokio::sync::mpsc;

        let (tx, _rx) = mpsc::channel::<SyslogMessage>(1);
        let msg = dummy_msg("fill");
        tx.try_send(msg.clone()).expect("first send fills channel");
        let result = tx.try_send(msg);
        assert!(result.is_err(), "second send on full channel must fail");
    }

    #[tokio::test]
    async fn handler_routes_messages_to_writer_task() {
        use crate::syslog::listener::SyslogHandler as SyslogHandlerTrait;
        use std::net::SocketAddr;
        use tokio::sync::mpsc;

        let (tx, mut rx) = mpsc::channel::<SyslogMessage>(SYSLOG_S3_CHANNEL_CAPACITY);
        let received = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let received_clone = received.clone();
        tokio::spawn(async move {
            while rx.recv().await.is_some() {
                received_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });

        struct TestHandler(mpsc::Sender<SyslogMessage>);
        #[async_trait::async_trait]
        impl crate::syslog::listener::SyslogHandler for TestHandler {
            async fn handle_message(&self, message: SyslogMessage, _src: SocketAddr) {
                let _ = self.0.try_send(message);
            }
        }

        let handler = TestHandler(tx);
        let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();
        for i in 0u8..5 {
            let msg = SyslogMessage {
                priority: i,
                severity: 0,
                facility: 0,
                timestamp: None,
                hostname: None,
                app_name: None,
                proc_id: None,
                msg_id: None,
                message: format!("msg {i}"),
                structured_data: None,
                protocol: SyslogProtocol::Unknown,
            };
            handler.handle_message(msg, src).await;
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        assert_eq!(received.load(std::sync::atomic::Ordering::SeqCst), 5);
    }
}
