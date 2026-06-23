//! IPFIX → S3 Parquet persistence.
//!
//! Provides:
//! - `flow_record_schema()` — fixed Arrow schema for `FlowRecord`
//! - `FlowRecordBuilders` — column builders for batching rows
//! - `append_flow_record()` / `finish_batch()` — row mapping
//! - `IpfixSink` — `ParquetSink` adapter for the generic writer
//! - `IpfixS3Handler` — type alias for `ParquetWriterHandle<IpfixSink>`
//! - `ipfix_start()` — convenience constructor wiring `IpfixS3Config` → `ParquetWriterHandle`

use crate::config::IpfixS3Config;
use crate::forwarding::buffered_writer::ParquetSink;
use crate::ipfix::FlowRecord;
use arrow::array::{
    ArrayRef, StringBuilder, UInt8Builder, UInt16Builder, UInt32Builder, UInt64Builder,
};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use std::sync::{Arc, LazyLock};

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
// IpfixSink — ParquetSink adapter
// ---------------------------------------------------------------------------

/// `ParquetSink` adapter for IPFIX flow records.
/// The `Record` type is `Vec<FlowRecord>` to match the existing
/// `IpfixHandler::handle_flows` batch API.
pub struct IpfixSink;

impl ParquetSink for IpfixSink {
    type Record = Vec<FlowRecord>;

    fn source(&self) -> &'static str {
        "ipfix"
    }

    fn partition(&self, _: &Vec<FlowRecord>) -> Option<String> {
        None
    }

    fn schema(&self, _: Option<&str>) -> Arc<arrow_schema::Schema> {
        flow_record_schema()
    }

    fn to_record_batch(
        &self,
        records: &Vec<FlowRecord>,
        schema: &Arc<arrow_schema::Schema>,
    ) -> anyhow::Result<arrow_array::RecordBatch> {
        let mut builders = FlowRecordBuilders::new();
        for r in records {
            append_flow_record(&mut builders, r)?;
        }
        finish_batch(builders, schema.clone())
    }
}

// ---------------------------------------------------------------------------
// IpfixS3Handler — type alias + IpfixHandler impl
// ---------------------------------------------------------------------------

/// `IpfixS3Handler` is a thin alias for the generic `ParquetWriterHandle<IpfixSink>`.
pub type IpfixS3Handler = crate::forwarding::buffered_writer::ParquetWriterHandle<IpfixSink>;

#[async_trait::async_trait]
impl crate::ipfix::listener::IpfixHandler
    for crate::forwarding::buffered_writer::ParquetWriterHandle<IpfixSink>
{
    async fn handle_flows(&self, flows: Vec<FlowRecord>, source: std::net::SocketAddr) {
        let count = flows.len() as u64;
        match self.try_send(flows) {
            Ok(()) => {}
            Err(_dropped) => {
                // parquet_s3_dropped{source="ipfix"} is already incremented by try_send;
                // just warn here.
                tracing::warn!(
                    "IPFIX S3 channel full; dropped {} flows from {}",
                    count,
                    source
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ipfix_start — convenience constructor
// ---------------------------------------------------------------------------

/// Construct an `IpfixS3Handler` (i.e. `ParquetWriterHandle<IpfixSink>`) from an
/// `IpfixS3Config` and a pre-built `S3Sink`.
///
/// Returns `(handler, writer_task_handle)`. The caller should retain the `JoinHandle`
/// and await it during graceful shutdown, after all `Arc<dyn IpfixHandler>` references
/// have been dropped so the channel closes and the final flush fires.
pub fn ipfix_start(
    cfg: &IpfixS3Config,
    s3: std::sync::Arc<crate::forwarding::s3_sink::S3Sink>,
) -> (IpfixS3Handler, tokio::task::JoinHandle<()>) {
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
        max_partitions: 1,
    };
    let policy = FlushPolicy {
        max_rows: cfg.max_buffer_rows,
        max_bytes: cfg.flush_threshold_bytes,
        interval: std::time::Duration::from_secs(cfg.flush_interval_secs),
    };
    ParquetWriterHandle::start(IpfixSink, s3, bwc, policy)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forwarding::s3_sink::S3Sink;
    use crate::ipfix::FlowRecord;
    use arrow::array::{Array, StringArray, UInt64Array};
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
        use crate::config::S3ConnectionConfig;
        let conn = S3ConnectionConfig {
            endpoint: "http://127.0.0.1:1".to_string(), // port 1 is always refused
            bucket: "test-bucket".to_string(),
            region: "us-east-1".to_string(),
            access_key: "AKIATEST".to_string(),
            secret_key: "SECRETTEST".to_string(),
        };
        Arc::new(S3Sink::from_connection(&conn).await.expect("constructs"))
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

    // -- IpfixSink unit tests (Task 2.1) --

    #[test]
    fn ipfix_sink_to_record_batch_produces_correct_schema_and_rows() {
        use crate::forwarding::buffered_writer::ParquetSink;
        let sink = IpfixSink;
        let schema = sink.schema(None);
        assert_eq!(schema.fields().len(), 18);
        assert!(sink.partition(&vec![]).is_none());

        let r = make_flow_record(Some("10.0.0.1"), Some(999), serde_json::json!({"k":"v"}));
        let batch = sink.to_record_batch(&vec![r], &schema).unwrap();
        assert_eq!(batch.num_rows(), 1);
        use arrow::array::StringArray;
        let src = batch
            .column_by_name("src_addr")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(src.value(0), "10.0.0.1");
    }

    // -- Task 2: writer push accumulation and bounded buffer under S3 outage --

    #[tokio::test]
    async fn writer_push_accumulates_and_bounded_under_outage() {
        use crate::config::S3ConnectionConfig;
        use crate::forwarding::buffered_writer::{
            BufferedWriterConfig, FlushPolicy, PartitionedParquetWriter,
        };

        let sink_s3 = unreachable_sink().await;
        let max_rows = 2usize;
        let hard_cap = max_rows.saturating_mul(4);

        let bwc = BufferedWriterConfig {
            connection: S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "ipfix".to_string(),
            max_buffer_rows: max_rows,
            flush_threshold_bytes: 1, // flush immediately
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_partitions: 1,
        };
        let policy = FlushPolicy {
            max_rows,
            max_bytes: 1,
            interval: std::time::Duration::from_secs(3600),
        };

        let mut writer = PartitionedParquetWriter::new(IpfixSink, sink_s3, bwc, policy);

        let total_pushes = hard_cap * 3;
        let mut flush_errors = 0usize;
        for _ in 0..total_pushes {
            let record = make_flow_record(None, None, serde_json::json!({}));
            let result = writer.push(vec![record]).await;
            if result.is_err() {
                flush_errors += 1;
            }
        }

        assert!(flush_errors > 0, "expected at least some flush errors");
        let buf = writer.buffers.get("").unwrap();
        assert!(
            buf.row_count <= hard_cap,
            "buffer must stay at or below hard cap ({hard_cap}), got {}",
            buf.row_count
        );
    }

    // -- Task 3: IpfixS3Handler overflow test (real handler, real metrics) --

    #[tokio::test]
    #[allow(clippy::mutable_key_type)] // clippy false positive: CompositeKey interior mutability (AtomicBool) is never used for hashing
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
        let cfg = IpfixS3Config {
            connection: crate::config::S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "ipfix".to_string(),
            flush_threshold_bytes: 1, // flush on every push so background task stalls on S3
            flush_interval_secs: 3600,
            channel_capacity: 1,
            max_buffer_rows: 1,
        };
        let (handler, _writer_handle) = ipfix_start(&cfg, sink);

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
            metrics::Key::from_parts(
                "parquet_s3_dropped",
                vec![metrics::Label::new("source", "ipfix")],
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
            "expected parquet_s3_dropped{{source=\"ipfix\"}} >= 1 after saturating the channel; got {dropped}. \
             The IpfixS3Handler::handle_flows must increment the counter on overflow."
        );
    }

    // -- F1: channel_capacity is honored by ipfix_start --

    /// Prove that `ipfix_start` wires the capacity parameter by showing that
    /// a tiny capacity (1) causes drops for a burst of sends, while a large capacity
    /// (10_000) does not for the same modest send count.
    #[tokio::test]
    #[allow(clippy::mutable_key_type)] // clippy false positive: CompositeKey interior mutability (AtomicBool) is never used for hashing
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
            let cfg = IpfixS3Config {
                connection: crate::config::S3ConnectionConfig {
                    endpoint: "http://127.0.0.1:1".to_string(),
                    bucket: "test-bucket".to_string(),
                    region: "us-east-1".to_string(),
                    access_key: "AKIATEST".to_string(),
                    secret_key: "SECRETTEST".to_string(),
                },
                prefix: "ipfix".to_string(),
                flush_threshold_bytes: 1, // flush on every push so background task stalls on S3
                flush_interval_secs: 3600,
                channel_capacity: 1,
                max_buffer_rows: 1,
            };
            let (handler, _writer_handle) = ipfix_start(&cfg, sink);
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
                metrics::Key::from_parts(
                    "parquet_s3_dropped",
                    vec![metrics::Label::new("source", "ipfix")],
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
                "capacity=1 should cause drops; got parquet_s3_dropped{{source=\"ipfix\"}}={dropped}"
            );
        }

        // --- large capacity (10_000): expect no drops for a modest send count (30) ---
        {
            let recorder = DebuggingRecorder::new();
            let snapshotter = recorder.snapshotter();
            let _guard = set_default_local_recorder(&recorder);

            let sink = unreachable_sink().await;
            let cfg = IpfixS3Config {
                connection: crate::config::S3ConnectionConfig {
                    endpoint: "http://127.0.0.1:1".to_string(),
                    bucket: "test-bucket".to_string(),
                    region: "us-east-1".to_string(),
                    access_key: "AKIATEST".to_string(),
                    secret_key: "SECRETTEST".to_string(),
                },
                prefix: "ipfix".to_string(),
                flush_threshold_bytes: usize::MAX, // prevent flush so channel never stalls
                flush_interval_secs: 3600,
                channel_capacity: 10_000,
                max_buffer_rows: 100_000,
            };
            let (handler, _writer_handle) = ipfix_start(&cfg, sink);
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
                metrics::Key::from_parts(
                    "parquet_s3_dropped",
                    vec![metrics::Label::new("source", "ipfix")],
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
                dropped == 0,
                "capacity=10_000 should not cause drops for 30 sends; got parquet_s3_dropped{{source=\"ipfix\"}}={dropped}"
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
        let (handler, _writer_handle) = ipfix_start(&s3_cfg, sink);
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
