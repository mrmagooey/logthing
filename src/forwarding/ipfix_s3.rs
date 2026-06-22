//! IPFIX → S3 Parquet persistence.
//!
//! Provides:
//! - `flow_record_schema()` — fixed Arrow schema for `FlowRecord`
//! - `FlowRecordBuilders` — column builders for batching rows
//! - `append_flow_record()` / `finish_batch()` — row mapping
//! - `IpfixS3Writer` — buffers RecordBatches and flushes to S3 on size/age thresholds
//! - `IpfixS3Handler` — implements `IpfixHandler`, wraps a bounded channel + background writer
//!
//! The buffer has a hard cap of `max_buffer_rows * 4` to protect against unbounded memory
//! growth under persistent S3 outages. See `flush_then_cap()` for details.

use crate::forwarding::s3_sink::S3Sink;
use crate::ipfix::FlowRecord;
use arrow::array::{
    ArrayRef, StringBuilder, UInt8Builder, UInt16Builder, UInt32Builder, UInt64Builder,
};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use chrono::{Datelike, Utc};
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;
use std::collections::VecDeque;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::warn;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Per-source S3 persistence config for the IPFIX listener.
/// Absent from TOML → `None` → no S3 persistence (backward compatible).
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct IpfixS3Config {
    /// Shared S3 connection fields (endpoint, bucket, region, access_key, secret_key).
    /// Flattened so the TOML block stays flat: `[ipfix.s3]\nendpoint = …`
    #[serde(flatten)]
    pub connection: crate::config::S3ConnectionConfig,
    /// S3 key prefix for IPFIX objects, slash-free (default: `"ipfix"`); builder inserts `/`.
    #[serde(default = "default_ipfix_s3_prefix")]
    pub prefix: String,
    /// Max buffer size in bytes before an eager flush (default: 100 MiB)
    #[serde(default = "default_ipfix_flush_bytes")]
    pub flush_threshold_bytes: usize,
    /// Max age of buffered records in seconds before a time-triggered flush (default: 900)
    #[serde(default = "default_ipfix_flush_secs")]
    pub flush_interval_secs: u64,
    /// Bounded channel capacity (number of batches; default: 256)
    #[serde(default = "default_ipfix_channel_capacity")]
    pub channel_capacity: usize,
    /// Maximum number of buffered rows before hard cap kicks in (default: 100 000)
    #[serde(default = "default_ipfix_max_buffer_rows")]
    pub max_buffer_rows: usize,
}

fn default_ipfix_s3_prefix() -> String {
    "ipfix".to_string()
}
fn default_ipfix_flush_bytes() -> usize {
    100 * 1024 * 1024 // 100 MiB
}
fn default_ipfix_flush_secs() -> u64 {
    900
}
fn default_ipfix_channel_capacity() -> usize {
    256
}
fn default_ipfix_max_buffer_rows() -> usize {
    100_000
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

static FLOW_RECORD_SCHEMA: LazyLock<Arc<Schema>> = LazyLock::new(|| {
    Arc::new(Schema::new(vec![
        Field::new("observation_domain_id", DataType::UInt32, false),
        Field::new("template_id", DataType::UInt16, false),
        Field::new("protocol_version", DataType::UInt8, false),
        Field::new("exporter", DataType::Utf8, false),
        Field::new("export_time", DataType::Utf8, false),
        Field::new("src_addr", DataType::Utf8, true),
        Field::new("dst_addr", DataType::Utf8, true),
        Field::new("src_port", DataType::UInt16, true),
        Field::new("dst_port", DataType::UInt16, true),
        Field::new("ip_protocol", DataType::UInt8, true),
        Field::new("octet_delta_count", DataType::UInt64, true),
        Field::new("packet_delta_count", DataType::UInt64, true),
        Field::new("flow_start", DataType::Utf8, true),
        Field::new("flow_end", DataType::Utf8, true),
        Field::new("tcp_flags", DataType::UInt8, true),
        Field::new("input_interface", DataType::UInt32, true),
        Field::new("output_interface", DataType::UInt32, true),
        // extra: JSON object of non-curated fields; always present (non-null)
        Field::new("extra", DataType::Utf8, false),
    ]))
});

/// Return the fixed Arrow schema for `FlowRecord` rows.
pub fn flow_record_schema() -> Arc<Schema> {
    FLOW_RECORD_SCHEMA.clone()
}

// ---------------------------------------------------------------------------
// Row mapping — builders
// ---------------------------------------------------------------------------

/// Mutable column builders for one Parquet row group.
pub struct FlowRecordBuilders {
    observation_domain_id: UInt32Builder,
    template_id: UInt16Builder,
    protocol_version: UInt8Builder,
    exporter: StringBuilder,
    export_time: StringBuilder,
    src_addr: StringBuilder,
    dst_addr: StringBuilder,
    src_port: UInt16Builder,
    dst_port: UInt16Builder,
    ip_protocol: UInt8Builder,
    octet_delta_count: UInt64Builder,
    packet_delta_count: UInt64Builder,
    flow_start: StringBuilder,
    flow_end: StringBuilder,
    tcp_flags: UInt8Builder,
    input_interface: UInt32Builder,
    output_interface: UInt32Builder,
    extra: StringBuilder,
    row_count: usize,
}

impl FlowRecordBuilders {
    pub fn new() -> Self {
        Self {
            observation_domain_id: UInt32Builder::new(),
            template_id: UInt16Builder::new(),
            protocol_version: UInt8Builder::new(),
            exporter: StringBuilder::new(),
            export_time: StringBuilder::new(),
            src_addr: StringBuilder::new(),
            dst_addr: StringBuilder::new(),
            src_port: UInt16Builder::new(),
            dst_port: UInt16Builder::new(),
            ip_protocol: UInt8Builder::new(),
            octet_delta_count: UInt64Builder::new(),
            packet_delta_count: UInt64Builder::new(),
            flow_start: StringBuilder::new(),
            flow_end: StringBuilder::new(),
            tcp_flags: UInt8Builder::new(),
            input_interface: UInt32Builder::new(),
            output_interface: UInt32Builder::new(),
            extra: StringBuilder::new(),
            row_count: 0,
        }
    }

    #[allow(dead_code)] // Part of the public builder API; used in tests
    pub fn len(&self) -> usize {
        self.row_count
    }

    #[allow(dead_code)] // Part of the public builder API
    pub fn is_empty(&self) -> bool {
        self.row_count == 0
    }
}

impl Default for FlowRecordBuilders {
    fn default() -> Self {
        Self::new()
    }
}

/// Append one `FlowRecord` to the provided mutable column builders.
pub fn append_flow_record(
    builders: &mut FlowRecordBuilders,
    record: &FlowRecord,
) -> anyhow::Result<()> {
    builders
        .observation_domain_id
        .append_value(record.observation_domain_id);
    builders.template_id.append_value(record.template_id);
    builders
        .protocol_version
        .append_value(record.protocol_version);
    builders.exporter.append_value(record.exporter.to_string());
    builders
        .export_time
        .append_value(record.export_time.to_rfc3339());

    builders
        .src_addr
        .append_option(record.src_addr.as_ref().map(|a| a.to_string()));
    builders
        .dst_addr
        .append_option(record.dst_addr.as_ref().map(|a| a.to_string()));
    builders.src_port.append_option(record.src_port);
    builders.dst_port.append_option(record.dst_port);
    builders.ip_protocol.append_option(record.ip_protocol);
    builders
        .octet_delta_count
        .append_option(record.octet_delta_count);
    builders
        .packet_delta_count
        .append_option(record.packet_delta_count);
    builders
        .flow_start
        .append_option(record.flow_start.as_ref().map(|t| t.to_rfc3339()));
    builders
        .flow_end
        .append_option(record.flow_end.as_ref().map(|t| t.to_rfc3339()));
    builders.tcp_flags.append_option(record.tcp_flags);
    builders
        .input_interface
        .append_option(record.input_interface);
    builders
        .output_interface
        .append_option(record.output_interface);

    let extra_str = serde_json::to_string(&record.extra).unwrap_or_else(|_| "{}".to_string());
    builders.extra.append_value(extra_str);

    builders.row_count += 1;
    Ok(())
}

/// Consume builders and produce a `RecordBatch`.
pub fn finish_batch(
    mut builders: FlowRecordBuilders,
    schema: Arc<Schema>,
) -> anyhow::Result<RecordBatch> {
    let columns: Vec<ArrayRef> = vec![
        Arc::new(builders.observation_domain_id.finish()) as ArrayRef,
        Arc::new(builders.template_id.finish()) as ArrayRef,
        Arc::new(builders.protocol_version.finish()) as ArrayRef,
        Arc::new(builders.exporter.finish()) as ArrayRef,
        Arc::new(builders.export_time.finish()) as ArrayRef,
        Arc::new(builders.src_addr.finish()) as ArrayRef,
        Arc::new(builders.dst_addr.finish()) as ArrayRef,
        Arc::new(builders.src_port.finish()) as ArrayRef,
        Arc::new(builders.dst_port.finish()) as ArrayRef,
        Arc::new(builders.ip_protocol.finish()) as ArrayRef,
        Arc::new(builders.octet_delta_count.finish()) as ArrayRef,
        Arc::new(builders.packet_delta_count.finish()) as ArrayRef,
        Arc::new(builders.flow_start.finish()) as ArrayRef,
        Arc::new(builders.flow_end.finish()) as ArrayRef,
        Arc::new(builders.tcp_flags.finish()) as ArrayRef,
        Arc::new(builders.input_interface.finish()) as ArrayRef,
        Arc::new(builders.output_interface.finish()) as ArrayRef,
        Arc::new(builders.extra.finish()) as ArrayRef,
    ];
    Ok(RecordBatch::try_new(schema, columns)?)
}

// ---------------------------------------------------------------------------
// Pure key-building helper (extracted for testability)
// ---------------------------------------------------------------------------

/// Build the S3 object key: `{prefix}/year={Y}/month={MM}/day={DD}/{uuid}.parquet`
pub(crate) fn build_s3_key(prefix: &str, now: chrono::DateTime<Utc>) -> String {
    let id = uuid::Uuid::new_v4();
    format!(
        "{}/year={}/month={:02}/day={:02}/{}.parquet",
        prefix,
        now.year(),
        now.month(),
        now.day(),
        id,
    )
}

// ---------------------------------------------------------------------------
// Parquet encoding
// ---------------------------------------------------------------------------

/// Encode a slice of `RecordBatch`es (sharing `flow_record_schema()`) into Parquet bytes.
/// Returns an empty `Vec` if `batches` is empty.
pub(crate) fn encode_batches_to_parquet(batches: &[RecordBatch]) -> anyhow::Result<Vec<u8>> {
    if batches.is_empty() {
        return Ok(Vec::new());
    }
    let schema = flow_record_schema();
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
// IpfixS3Writer
// ---------------------------------------------------------------------------

/// Writer configuration (derived from `IpfixS3Config`).
pub struct IpfixS3WriterConfig {
    /// Flush when the estimated buffer size (bytes) exceeds this threshold.
    pub flush_threshold_bytes: usize,
    /// Flush after this wall-clock interval regardless of buffer size.
    pub flush_interval: Duration,
    /// S3 key prefix, e.g. `"ipfix"`.
    pub key_prefix: String,
    /// Maximum number of buffered rows before hard cap kicks in (4× = hard cap).
    pub max_buffer_rows: usize,
}

impl IpfixS3WriterConfig {
    /// Hard cap on total buffered rows: 4× the flush threshold.
    pub fn hard_cap_rows(&self) -> usize {
        self.max_buffer_rows.saturating_mul(4)
    }
}

impl Default for IpfixS3WriterConfig {
    fn default() -> Self {
        Self {
            flush_threshold_bytes: default_ipfix_flush_bytes(),
            flush_interval: Duration::from_secs(default_ipfix_flush_secs()),
            key_prefix: default_ipfix_s3_prefix(),
            max_buffer_rows: default_ipfix_max_buffer_rows(),
        }
    }
}

/// A single buffered batch: the Arrow batch paired with its estimated byte size.
struct BufferedBatch {
    batch: RecordBatch,
    est_bytes: usize,
}

/// Buffers `FlowRecord` rows as Arrow `RecordBatch`es and flushes to S3 as Parquet.
///
/// Memory safety: the buffer has a hard cap of `max_buffer_rows * 4`. When a flush fails and
/// the buffer exceeds this cap, the oldest batch(es) are dropped to keep memory bounded.
pub struct IpfixS3Writer {
    config: IpfixS3WriterConfig,
    sink: Arc<S3Sink>,
    /// Single deque whose elements carry both the batch and its byte estimate.
    /// This eliminates the former two-deque design that risked length desync.
    buffer: VecDeque<BufferedBatch>,
    buffer_row_count: usize,
    buffered_bytes: usize,
    last_flush: Instant,
    /// Timestamp of the last drop-warning log line, used to throttle noisy output.
    last_drop_warn: Option<Instant>,
}

impl IpfixS3Writer {
    pub fn new(config: IpfixS3WriterConfig, sink: Arc<S3Sink>) -> Self {
        Self {
            config,
            sink,
            buffer: VecDeque::new(),
            buffer_row_count: 0,
            buffered_bytes: 0,
            last_flush: Instant::now(),
            last_drop_warn: None,
        }
    }

    /// Number of rows currently in the write buffer (for tests / inspection).
    #[allow(dead_code)]
    pub(crate) fn buffered_rows(&self) -> usize {
        self.buffer_row_count
    }

    /// Append a batch of `FlowRecord`s to the buffer; flushes if the byte threshold is met.
    pub async fn push_batch(&mut self, records: &[FlowRecord]) -> anyhow::Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let mut builders = FlowRecordBuilders::new();
        for r in records {
            append_flow_record(&mut builders, r)?;
        }
        let batch = finish_batch(builders, flow_record_schema())?;
        let estimated = records
            .iter()
            .map(|r| {
                128 + serde_json::to_string(&r.extra)
                    .map(|s| s.len())
                    .unwrap_or(2)
            })
            .sum::<usize>();
        self.buffer_row_count += batch.num_rows();
        self.buffered_bytes += estimated;
        self.buffer.push_back(BufferedBatch {
            batch,
            est_bytes: estimated,
        });

        if self.buffered_bytes >= self.config.flush_threshold_bytes {
            self.flush_then_cap().await?;
        }
        Ok(())
    }

    /// Attempt a flush; if it fails and the buffer exceeds the hard cap, drop oldest batches.
    async fn flush_then_cap(&mut self) -> anyhow::Result<()> {
        if let Err(e) = self.flush().await {
            let cap = self.config.hard_cap_rows();
            if self.buffer_row_count > cap {
                self.drop_oldest_to_cap(cap);
            }
            return Err(e);
        }
        Ok(())
    }

    /// Drop batches from the front until `buffer_row_count <= cap`.
    fn drop_oldest_to_cap(&mut self, cap: usize) {
        let mut dropped_rows: usize = 0;
        while self.buffer_row_count > cap {
            if self.buffer.is_empty() {
                break;
            }
            let oldest = self
                .buffer
                .pop_front()
                .expect("buffer non-empty per loop guard");
            let n = oldest.batch.num_rows();
            self.buffer_row_count = self.buffer_row_count.saturating_sub(n);
            self.buffered_bytes = self.buffered_bytes.saturating_sub(oldest.est_bytes);
            dropped_rows += n;
        }
        if dropped_rows > 0 {
            metrics::counter!("ipfix_s3_buffer_dropped").increment(dropped_rows as u64);
            let should_warn = self
                .last_drop_warn
                .map(|t| t.elapsed().as_secs() >= 30)
                .unwrap_or(true);
            if should_warn {
                warn!(
                    dropped_rows,
                    buffer_row_count = self.buffer_row_count,
                    "IpfixS3Writer: S3 upload failing — dropped oldest rows to stay within hard cap"
                );
                self.last_drop_warn = Some(Instant::now());
            }
        }
    }

    /// Flush if the age or byte threshold is exceeded; no-op if the buffer is empty.
    pub async fn flush_if_needed(&mut self) -> anyhow::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let age_exceeded = self.last_flush.elapsed() >= self.config.flush_interval;
        let size_exceeded = self.buffered_bytes >= self.config.flush_threshold_bytes;
        if age_exceeded || size_exceeded {
            self.flush_then_cap().await?;
        }
        Ok(())
    }

    /// Unconditionally encode all buffered rows to Parquet and upload via `self.sink`.
    /// Clears the buffer on success.
    pub async fn flush(&mut self) -> anyhow::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let batches: Vec<RecordBatch> = self.buffer.iter().map(|b| b.batch.clone()).collect();
        let row_count = self.buffer_row_count;
        let bytes = encode_batches_to_parquet(&batches)?;
        let key = build_s3_key(&self.config.key_prefix, Utc::now());
        match self.sink.upload(&key, bytes).await {
            Ok(()) => {
                metrics::counter!("ipfix_s3_records_written").increment(row_count as u64);
                metrics::counter!("ipfix_s3_uploads").increment(1);
            }
            Err(e) => {
                metrics::counter!("ipfix_s3_upload_errors").increment(1);
                return Err(e);
            }
        }
        self.buffer.clear();
        self.buffer_row_count = 0;
        self.buffered_bytes = 0;
        self.last_flush = Instant::now();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// IpfixS3Handler — channel + background writer
// ---------------------------------------------------------------------------

/// Channel capacity for the handler → writer channel (production default).
/// Used by `start()` as a convenience wrapper and available for callers that
/// want the default without hardcoding the literal.
#[allow(dead_code)]
pub const IPFIX_S3_CHANNEL_CAPACITY: usize = 256;

/// `IpfixHandler` implementation that forwards flow batches through a bounded channel to a
/// background `IpfixS3Writer` task. Batches dropped on overflow increment `ipfix_s3_dropped`.
pub struct IpfixS3Handler {
    sender: mpsc::Sender<Vec<FlowRecord>>,
}

impl IpfixS3Handler {
    /// Construct a handler and start the writer background task with the default channel capacity.
    ///
    /// Returns `(handler, writer_task_handle)`. The caller should retain the `JoinHandle` and
    /// await it (with a timeout) during graceful shutdown, after all `Arc<IpfixS3Handler>`
    /// references have been dropped so the channel closes and the final flush fires.
    #[allow(dead_code)]
    pub fn start(
        config: IpfixS3WriterConfig,
        sink: Arc<S3Sink>,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        Self::start_with_capacity(config, sink, IPFIX_S3_CHANNEL_CAPACITY)
    }

    /// Construct a handler and start the writer background task with a custom channel `capacity`.
    ///
    /// Returns `(handler, writer_task_handle)`. The caller should hold the `JoinHandle` and await
    /// it (with a timeout) during shutdown, after dropping all `Arc<dyn IpfixHandler>` references
    /// so that the channel closes and the writer flushes its buffer.
    pub fn start_with_capacity(
        config: IpfixS3WriterConfig,
        sink: Arc<S3Sink>,
        capacity: usize,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let (tx, mut rx) = mpsc::channel::<Vec<FlowRecord>>(capacity);
        let flush_check = crate::forwarding::s3_sink::flush_check_interval(config.flush_interval);
        let handle = tokio::spawn(async move {
            let mut writer = IpfixS3Writer::new(config, sink);
            let mut interval = tokio::time::interval(flush_check);
            loop {
                tokio::select! {
                    msg = rx.recv() => {
                        match msg {
                            Some(flows) => {
                                if let Err(e) = writer.push_batch(&flows).await {
                                    warn!("IpfixS3Writer::push_batch error: {e}");
                                }
                            }
                            None => {
                                // Sender dropped — flush remaining and exit.
                                if let Err(e) = writer.flush().await {
                                    warn!("IpfixS3Writer::flush on shutdown error: {e}");
                                }
                                break;
                            }
                        }
                    }
                    _ = interval.tick() => {
                        if let Err(e) = writer.flush_if_needed().await {
                            warn!("IpfixS3Writer::flush_if_needed error: {e}");
                        }
                    }
                }
            }
        });
        (Self { sender: tx }, handle)
    }
}

#[async_trait::async_trait]
impl crate::ipfix::listener::IpfixHandler for IpfixS3Handler {
    async fn handle_flows(&self, flows: Vec<FlowRecord>, source: std::net::SocketAddr) {
        let count = flows.len() as u64;
        match self.sender.try_send(flows) {
            Ok(()) => {}
            Err(_dropped) => {
                metrics::counter!("ipfix_s3_dropped").increment(count);
                warn!(
                    "IPFIX S3 channel full; dropped {} flows from {}",
                    count, source
                );
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
    use crate::ipfix::FlowRecord;
    use arrow::array::{Array as ArrowArray, StringArray, UInt64Array};
    use chrono::TimeZone;
    use std::net::IpAddr;

    // -- helpers --

    fn make_flow_record(
        src: Option<&str>,
        octet_count: Option<u64>,
        extra: serde_json::Value,
    ) -> FlowRecord {
        FlowRecord {
            observation_domain_id: 1,
            template_id: 256,
            protocol_version: 10,
            exporter: "10.0.0.1".parse().unwrap(),
            export_time: chrono::Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap(),
            src_addr: src.map(|s| s.parse::<IpAddr>().unwrap()),
            dst_addr: Some("192.168.1.1".parse().unwrap()),
            src_port: Some(1234),
            dst_port: Some(80),
            ip_protocol: Some(6),
            octet_delta_count: octet_count,
            packet_delta_count: Some(10),
            flow_start: None,
            flow_end: None,
            tcp_flags: Some(0x02),
            input_interface: Some(1),
            output_interface: Some(2),
            extra,
        }
    }

    async fn unreachable_sink() -> Arc<S3Sink> {
        use crate::forwarding::parquet_s3::ParquetS3Config;
        let cfg = ParquetS3Config {
            endpoint: "http://127.0.0.1:1".to_string(), // port 1 is always refused
            bucket: "test-bucket".to_string(),
            region: "us-east-1".to_string(),
            access_key: "AKIATEST".to_string(),
            secret_key: "SECRETTEST".to_string(),
            max_file_size_mb: 10,
            flush_interval_secs: 60,
            local_buffer_path: std::env::temp_dir().join("ipfix-s3-test"),
        };
        Arc::new(S3Sink::from_config(&cfg).await.expect("constructs"))
    }

    // -- Task 1: schema shape --

    #[test]
    fn schema_has_correct_fields_and_types() {
        use arrow::datatypes::DataType;
        let schema = flow_record_schema();
        assert_eq!(schema.fields().len(), 18, "expected 18 columns");

        let cases: &[(&str, DataType, bool)] = &[
            ("observation_domain_id", DataType::UInt32, false),
            ("template_id", DataType::UInt16, false),
            ("protocol_version", DataType::UInt8, false),
            ("exporter", DataType::Utf8, false),
            ("export_time", DataType::Utf8, false),
            ("src_addr", DataType::Utf8, true),
            ("dst_addr", DataType::Utf8, true),
            ("src_port", DataType::UInt16, true),
            ("dst_port", DataType::UInt16, true),
            ("ip_protocol", DataType::UInt8, true),
            ("octet_delta_count", DataType::UInt64, true),
            ("packet_delta_count", DataType::UInt64, true),
            ("flow_start", DataType::Utf8, true),
            ("flow_end", DataType::Utf8, true),
            ("tcp_flags", DataType::UInt8, true),
            ("input_interface", DataType::UInt32, true),
            ("output_interface", DataType::UInt32, true),
            ("extra", DataType::Utf8, false),
        ];

        for (name, expected_type, expected_nullable) in cases {
            let field = schema
                .field_with_name(name)
                .unwrap_or_else(|_| panic!("field '{}' missing from schema", name));
            assert_eq!(
                field.data_type(),
                expected_type,
                "field '{}' has wrong type",
                name
            );
            assert_eq!(
                field.is_nullable(),
                *expected_nullable,
                "field '{}' has wrong nullability",
                name
            );
        }
    }

    // -- Task 1: row mapping --

    #[test]
    fn append_and_finish_produces_correct_columns() {
        let r0 = make_flow_record(
            Some("10.0.0.1"),
            Some(1234),
            serde_json::json!({"ie200": "0xdeadbeef"}),
        );
        let r1 = make_flow_record(None, None, serde_json::json!({}));

        let mut builders = FlowRecordBuilders::new();
        append_flow_record(&mut builders, &r0).unwrap();
        append_flow_record(&mut builders, &r1).unwrap();
        assert_eq!(builders.len(), 2);

        let batch = finish_batch(builders, flow_record_schema()).unwrap();
        assert_eq!(batch.num_rows(), 2);

        let src_addr_col = batch
            .column_by_name("src_addr")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(src_addr_col.value(0), "10.0.0.1");
        assert!(src_addr_col.is_null(1), "row 1 src_addr should be null");

        let octet_col = batch
            .column_by_name("octet_delta_count")
            .unwrap()
            .as_any()
            .downcast_ref::<UInt64Array>()
            .unwrap();
        assert_eq!(octet_col.value(0), 1234u64);
        assert!(
            octet_col.is_null(1),
            "row 1 octet_delta_count should be null"
        );

        let extra_col = batch
            .column_by_name("extra")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert!(
            extra_col.value(0).contains("ie200"),
            "extra column at row 0 must contain ie200"
        );
    }

    #[test]
    fn extra_json_round_trips() {
        let original = serde_json::json!({"ie300": "0xabcd", "nested": {"k": 1}});
        let r = make_flow_record(Some("10.1.2.3"), Some(42), original.clone());
        let mut builders = FlowRecordBuilders::new();
        append_flow_record(&mut builders, &r).unwrap();
        let batch = finish_batch(builders, flow_record_schema()).unwrap();

        let extra_col = batch
            .column_by_name("extra")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(extra_col.value(0)).expect("must parse as JSON");
        assert_eq!(parsed, original);
    }

    // -- Task 2: Parquet round-trip --

    #[test]
    fn encode_parquet_round_trips_expected_schema_and_values() {
        use bytes::Bytes;
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

        let r = make_flow_record(
            Some("172.16.0.1"),
            Some(9999),
            serde_json::json!({"ie1": "val"}),
        );
        let mut builders = FlowRecordBuilders::new();
        append_flow_record(&mut builders, &r).unwrap();
        let batch = finish_batch(builders, flow_record_schema()).unwrap();

        let raw = encode_batches_to_parquet(&[batch]).unwrap();
        assert!(!raw.is_empty(), "Parquet bytes must not be empty");

        let buf = Bytes::from(raw);
        let builder = ParquetRecordBatchReaderBuilder::try_new(buf).unwrap();
        let schema = builder.schema().clone();
        let mut reader = builder.build().unwrap();
        let rb = reader.next().unwrap().unwrap();

        assert_eq!(rb.num_rows(), 1);
        assert_eq!(schema.fields().len(), 18);

        let exporter_col = rb
            .column_by_name("exporter")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(exporter_col.value(0), "10.0.0.1");

        let octet_col = rb
            .column_by_name("octet_delta_count")
            .unwrap()
            .as_any()
            .downcast_ref::<UInt64Array>()
            .unwrap();
        assert_eq!(octet_col.value(0), 9999u64);
    }

    // -- Task 2: s3_key structure --

    #[test]
    fn s3_key_has_correct_structure() {
        let now = chrono::Utc.with_ymd_and_hms(2026, 3, 7, 0, 0, 0).unwrap();
        let key = build_s3_key("ipfix", now);
        assert!(
            key.starts_with("ipfix/year="),
            "key must start with 'ipfix/year='; got: {key}"
        );
        assert!(key.contains("/month="), "key must contain /month=");
        assert!(key.contains("/day="), "key must contain /day=");
        assert!(key.ends_with(".parquet"), "key must end with .parquet");
        assert!(
            key.contains("2026"),
            "key must contain year 2026; got: {key}"
        );
        assert!(key.contains("03"), "key must contain month 03");
        assert!(key.contains("07"), "key must contain day 07");
    }

    // -- Task 2: writer push accumulation and bounded buffer under S3 outage --

    #[tokio::test]
    async fn writer_push_accumulates_and_bounded_under_outage() {
        let sink = unreachable_sink().await;
        let max_rows = 2usize;
        let config = IpfixS3WriterConfig {
            flush_threshold_bytes: 1, // flush immediately
            flush_interval: Duration::from_secs(3600),
            key_prefix: "ipfix".to_string(),
            max_buffer_rows: max_rows,
        };
        let hard_cap = config.hard_cap_rows();
        let mut writer = IpfixS3Writer::new(config, sink);

        let total_pushes = hard_cap * 3;
        let mut flush_errors = 0usize;
        for _ in 0..total_pushes {
            let record = make_flow_record(None, None, serde_json::json!({}));
            let result = writer.push_batch(&[record]).await;
            if result.is_err() {
                flush_errors += 1;
            }
        }

        assert!(flush_errors > 0, "expected at least some flush errors");
        assert!(
            writer.buffered_rows() <= hard_cap,
            "buffer must stay at or below hard cap ({hard_cap}), got {}",
            writer.buffered_rows()
        );
    }

    // -- A1: single-deque byte consistency --

    /// Verify that after the hard cap kicks in, `buffered_bytes` equals the sum of
    /// `est_bytes` for the remaining elements in the single buffer deque.
    #[tokio::test]
    async fn buffer_byte_accounting_is_consistent_after_cap() {
        let sink = unreachable_sink().await;
        let max_rows = 2usize;
        let config = IpfixS3WriterConfig {
            flush_threshold_bytes: 1, // flush immediately on every push
            flush_interval: Duration::from_secs(3600),
            key_prefix: "ipfix".to_string(),
            max_buffer_rows: max_rows,
        };
        let hard_cap = config.hard_cap_rows();
        let mut writer = IpfixS3Writer::new(config, sink);

        // Push enough records to exceed the cap several times.
        for _ in 0..(hard_cap * 3) {
            let record = make_flow_record(None, None, serde_json::json!({}));
            let _ = writer.push_batch(&[record]).await;
        }

        // After many failed flushes the cap must have been applied. Now verify
        // that buffered_bytes == sum of each element's est_bytes in the deque.
        let sum_from_deque: usize = writer.buffer.iter().map(|b| b.est_bytes).sum();
        assert_eq!(
            writer.buffered_bytes, sum_from_deque,
            "buffered_bytes scalar must equal the sum of est_bytes in the buffer deque"
        );

        // Also verify the row count scalar is consistent.
        let rows_from_deque: usize = writer.buffer.iter().map(|b| b.batch.num_rows()).sum();
        assert_eq!(writer.buffer_row_count, rows_from_deque);

        // And the hard cap was enforced.
        assert!(writer.buffered_rows() <= hard_cap);
    }

    // -- Task 3: IpfixS3Handler overflow test (real handler, real metrics) --

    #[tokio::test]
    async fn handler_overflow_increments_dropped_counter() {
        use crate::ipfix::listener::IpfixHandler;
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::DebuggingRecorder;
        use std::net::SocketAddr;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let sink = unreachable_sink().await;
        // Channel capacity of 1: immediately saturates once background task stalls on S3.
        let config = IpfixS3WriterConfig {
            flush_threshold_bytes: 1, // flush on every push so background task stalls on S3
            flush_interval: Duration::from_secs(3600),
            key_prefix: "ipfix".to_string(),
            max_buffer_rows: 1,
        };
        let (handler, _writer_handle) = IpfixS3Handler::start_with_capacity(config, sink, 1);

        // Yield so the background task starts and blocks inside the S3 upload.
        tokio::task::yield_now().await;

        let src: SocketAddr = "127.0.0.1:4739".parse().unwrap();

        // Send 50 batches — far more than capacity (1) + in-flight (1).
        for i in 0..50usize {
            let record = make_flow_record(None, None, serde_json::json!({"i": i}));
            handler.handle_flows(vec![record], src).await;
        }

        tokio::task::yield_now().await;

        let snapshot = snapshotter.snapshot();
        let map = snapshot.into_hashmap();
        let key = CompositeKey::new(
            MetricKind::Counter,
            metrics::Key::from_name("ipfix_s3_dropped"),
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
            "expected ipfix_s3_dropped >= 1 after saturating the channel; got {dropped}. \
             The real IpfixS3Handler::handle_flows must increment the counter on overflow."
        );
    }

    // -- F1: channel_capacity is honored by start_with_capacity --

    /// Prove that `start_with_capacity` wires the capacity parameter by showing that
    /// a tiny capacity (1) causes drops for a burst of sends, while a large capacity
    /// (10_000) does not for the same modest send count.
    #[tokio::test]
    async fn channel_capacity_parameter_is_wired() {
        use crate::ipfix::listener::IpfixHandler;
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::DebuggingRecorder;
        use std::net::SocketAddr;

        let src: SocketAddr = "127.0.0.1:4739".parse().unwrap();

        // --- small capacity (1): expect drops ---
        {
            let recorder = DebuggingRecorder::new();
            let snapshotter = recorder.snapshotter();
            let _guard = set_default_local_recorder(&recorder);

            let sink = unreachable_sink().await;
            let config = IpfixS3WriterConfig {
                flush_threshold_bytes: 1, // flush on every push so background task stalls on S3
                flush_interval: Duration::from_secs(3600),
                key_prefix: "ipfix".to_string(),
                max_buffer_rows: 1,
            };
            let (handler, _writer_handle) = IpfixS3Handler::start_with_capacity(config, sink, 1);
            tokio::task::yield_now().await;

            // Send 30 batches — far more than capacity (1) + the one in-flight with S3.
            for i in 0..30usize {
                let record = make_flow_record(None, None, serde_json::json!({"i": i}));
                handler.handle_flows(vec![record], src).await;
            }
            tokio::task::yield_now().await;

            let snapshot = snapshotter.snapshot();
            let map = snapshot.into_hashmap();
            let key = CompositeKey::new(
                MetricKind::Counter,
                metrics::Key::from_name("ipfix_s3_dropped"),
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
                "capacity=1 should cause drops; got ipfix_s3_dropped={dropped}"
            );
        }

        // --- large capacity (10_000): expect no drops for a modest send count (30) ---
        {
            let recorder = DebuggingRecorder::new();
            let snapshotter = recorder.snapshotter();
            let _guard = set_default_local_recorder(&recorder);

            let sink = unreachable_sink().await;
            let config = IpfixS3WriterConfig {
                flush_threshold_bytes: usize::MAX, // prevent flush so channel never stalls
                flush_interval: Duration::from_secs(3600),
                key_prefix: "ipfix".to_string(),
                max_buffer_rows: 100_000,
            };
            let (handler, _writer_handle) =
                IpfixS3Handler::start_with_capacity(config, sink, 10_000);
            tokio::task::yield_now().await;

            for i in 0..30usize {
                let record = make_flow_record(None, None, serde_json::json!({"i": i}));
                handler.handle_flows(vec![record], src).await;
            }
            tokio::task::yield_now().await;

            let snapshot = snapshotter.snapshot();
            let map = snapshot.into_hashmap();
            let key = CompositeKey::new(
                MetricKind::Counter,
                metrics::Key::from_name("ipfix_s3_dropped"),
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
                dropped == 0,
                "capacity=10_000 should not cause drops for 30 sends; got ipfix_s3_dropped={dropped}"
            );
        }
    }

    // -- Task 6 Integration test (gated on IPFIX_S3_INTEGRATION_TEST env var) --

    #[tokio::test]
    async fn integration_flows_produce_parquet_in_s3() {
        if std::env::var("IPFIX_S3_INTEGRATION_TEST").is_err() {
            eprintln!("skipping; set IPFIX_S3_INTEGRATION_TEST=1 to run against local MinIO");
            return;
        }

        use crate::ipfix::listener::IpfixHandler;

        let bucket = std::env::var("IPFIX_S3_BUCKET").unwrap_or_else(|_| "ipfix-test".to_string());
        let s3_cfg = IpfixS3Config {
            connection: crate::config::S3ConnectionConfig {
                endpoint: "http://localhost:9000".to_string(),
                bucket: bucket.clone(),
                region: "us-east-1".to_string(),
                access_key: "minioadmin".to_string(),
                secret_key: "minioadmin".to_string(),
            },
            prefix: "ipfix".to_string(),
            flush_threshold_bytes: 1, // force immediate flush
            flush_interval_secs: 1,
            channel_capacity: 256,
            max_buffer_rows: 100_000,
        };

        let sink = Arc::new(
            S3Sink::from_connection(&s3_cfg.connection)
                .await
                .expect("S3Sink construct"),
        );
        let writer_config = IpfixS3WriterConfig {
            flush_threshold_bytes: s3_cfg.flush_threshold_bytes,
            flush_interval: Duration::from_secs(s3_cfg.flush_interval_secs),
            key_prefix: s3_cfg.prefix.clone(),
            max_buffer_rows: s3_cfg.max_buffer_rows,
        };
        let (handler, _writer_handle) = IpfixS3Handler::start(writer_config, sink);
        let src: std::net::SocketAddr = "127.0.0.1:4739".parse().unwrap();

        let flows: Vec<FlowRecord> = (0..10)
            .map(|i| make_flow_record(Some("10.1.2.3"), Some(i * 100), serde_json::json!({})))
            .collect();
        handler.handle_flows(flows, src).await;

        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        // Use aws-sdk-s3 to verify objects exist
        use aws_config::meta::region::RegionProviderChain;
        use aws_credential_types::{Credentials, provider::SharedCredentialsProvider};
        use aws_sdk_s3::Client as S3Client;
        use aws_sdk_s3::config::Builder as S3ConfigBuilder;

        let region_provider = RegionProviderChain::first_try(aws_sdk_s3::config::Region::new(
            "us-east-1".to_string(),
        ));
        let sdk_config = aws_config::from_env()
            .region(region_provider)
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
        let s3_config = S3ConfigBuilder::from(&sdk_config)
            .credentials_provider(creds)
            .force_path_style(true)
            .build();
        let client = S3Client::from_conf(s3_config);

        let resp = client
            .list_objects_v2()
            .bucket(&bucket)
            .prefix("ipfix/")
            .send()
            .await
            .expect("list_objects_v2");

        let contents = resp.contents();
        assert!(
            !contents.is_empty(),
            "expected at least 1 Parquet object under ipfix/; found none"
        );

        // Download and validate
        let key = contents[0].key().expect("object key");
        println!("Found Parquet object at {key}");
        let obj = client
            .get_object()
            .bucket(&bucket)
            .key(key)
            .send()
            .await
            .expect("get_object");
        let body = obj.body.collect().await.expect("body").into_bytes();
        assert!(!body.is_empty(), "Parquet object must be non-empty");

        let buf = bytes::Bytes::from(body.to_vec());
        let mut reader =
            parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(buf)
                .unwrap()
                .build()
                .unwrap();
        let rb = reader.next().unwrap().unwrap();
        assert_eq!(rb.num_rows(), 10);
        assert!(
            rb.schema().field_with_name("src_addr").is_ok(),
            "schema must have src_addr column"
        );
    }
}
