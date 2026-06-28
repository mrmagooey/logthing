//! sFlow v5 → S3 Parquet persistence.

use crate::config::SflowS3Config;
use crate::forwarding::buffered_writer::ParquetSink;
use crate::sflow::{SampleType, SflowRecord};
use arrow::array::{
    ArrayRef, StringBuilder, UInt8Builder, UInt16Builder, UInt32Builder, UInt64Builder,
};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use std::sync::{Arc, LazyLock};

// ── Schemas ──────────────────────────────────────────────────────────────────

static FLOW_SCHEMA: LazyLock<Arc<Schema>> = LazyLock::new(|| {
    Arc::new(Schema::new(vec![
        Field::new("sample_type",    DataType::Utf8,   false),
        Field::new("exporter",       DataType::Utf8,   false),
        Field::new("received_at",    DataType::Utf8,   false),
        Field::new("src_addr",       DataType::Utf8,   true),
        Field::new("dst_addr",       DataType::Utf8,   true),
        Field::new("src_port",       DataType::UInt16, true),
        Field::new("dst_port",       DataType::UInt16, true),
        Field::new("ip_protocol",    DataType::UInt8,  true),
        Field::new("sampling_rate",  DataType::UInt32, true),
        Field::new("input_ifindex",  DataType::UInt32, true),
        Field::new("output_ifindex", DataType::UInt32, true),
        Field::new("extra",          DataType::Utf8,   false),
    ]))
});

static COUNTER_SCHEMA: LazyLock<Arc<Schema>> = LazyLock::new(|| {
    Arc::new(Schema::new(vec![
        Field::new("sample_type",       DataType::Utf8,   false),
        Field::new("exporter",          DataType::Utf8,   false),
        Field::new("received_at",       DataType::Utf8,   false),
        Field::new("if_index",          DataType::UInt32, true),
        Field::new("if_type",           DataType::UInt32, true),
        Field::new("if_speed",          DataType::UInt64, true),
        Field::new("if_direction",      DataType::UInt32, true),
        Field::new("if_in_octets",      DataType::UInt64, true),
        Field::new("if_out_octets",     DataType::UInt64, true),
        Field::new("if_in_ucast_pkts",  DataType::UInt64, true),
        Field::new("if_out_ucast_pkts", DataType::UInt64, true),
        Field::new("if_in_errors",      DataType::UInt32, true),
        Field::new("if_out_errors",     DataType::UInt32, true),
        Field::new("extra",             DataType::Utf8,   false),
    ]))
});

// ── SflowSink ────────────────────────────────────────────────────────────────

pub struct SflowSink;

impl ParquetSink for SflowSink {
    type Record = SflowRecord;

    fn source(&self) -> &'static str { "sflow" }

    fn partition(&self, record: &SflowRecord) -> Option<String> {
        Some(match record.sample_type {
            SampleType::Flow    => "flow".to_string(),
            SampleType::Counter => "counter".to_string(),
        })
    }

    fn schema(&self, partition: Option<&str>) -> Arc<arrow_schema::Schema> {
        match partition {
            Some("counter") => COUNTER_SCHEMA.clone(),
            _               => FLOW_SCHEMA.clone(),   // "flow" or None
        }
    }

    fn to_record_batch(
        &self,
        record: &SflowRecord,
        schema: &Arc<arrow_schema::Schema>,
    ) -> anyhow::Result<arrow_array::RecordBatch> {
        match record.sample_type {
            SampleType::Flow    => flow_to_record_batch(record, schema),
            SampleType::Counter => counter_to_record_batch(record, schema),
        }
    }
}

fn flow_to_record_batch(r: &SflowRecord, schema: &Arc<Schema>) -> anyhow::Result<RecordBatch> {
    let extra_str = serde_json::to_string(&r.extra).unwrap_or_else(|_| "[]".to_string());
    let columns: Vec<ArrayRef> = vec![
        Arc::new({ let mut b = StringBuilder::new(); b.append_value(match r.sample_type { SampleType::Flow => "flow", SampleType::Counter => "counter" }); b.finish() }),
        Arc::new({ let mut b = StringBuilder::new(); b.append_value(r.exporter.to_string()); b.finish() }),
        Arc::new({ let mut b = StringBuilder::new(); b.append_value(r.received_at.to_rfc3339()); b.finish() }),
        Arc::new({ let mut b = StringBuilder::new(); b.append_option(r.src_addr.as_ref().map(|a| a.to_string())); b.finish() }),
        Arc::new({ let mut b = StringBuilder::new(); b.append_option(r.dst_addr.as_ref().map(|a| a.to_string())); b.finish() }),
        Arc::new({ let mut b = UInt16Builder::new(); b.append_option(r.src_port); b.finish() }),
        Arc::new({ let mut b = UInt16Builder::new(); b.append_option(r.dst_port); b.finish() }),
        Arc::new({ let mut b = UInt8Builder::new();  b.append_option(r.ip_protocol); b.finish() }),
        Arc::new({ let mut b = UInt32Builder::new(); b.append_option(r.sampling_rate); b.finish() }),
        Arc::new({ let mut b = UInt32Builder::new(); b.append_option(r.input_ifindex); b.finish() }),
        Arc::new({ let mut b = UInt32Builder::new(); b.append_option(r.output_ifindex); b.finish() }),
        Arc::new({ let mut b = StringBuilder::new(); b.append_value(&extra_str); b.finish() }),
    ];
    Ok(RecordBatch::try_new(schema.clone(), columns)?)
}

fn counter_to_record_batch(r: &SflowRecord, schema: &Arc<Schema>) -> anyhow::Result<RecordBatch> {
    let extra_str = serde_json::to_string(&r.extra).unwrap_or_else(|_| "[]".to_string());
    let columns: Vec<ArrayRef> = vec![
        Arc::new({ let mut b = StringBuilder::new(); b.append_value("counter"); b.finish() }),
        Arc::new({ let mut b = StringBuilder::new(); b.append_value(r.exporter.to_string()); b.finish() }),
        Arc::new({ let mut b = StringBuilder::new(); b.append_value(r.received_at.to_rfc3339()); b.finish() }),
        Arc::new({ let mut b = UInt32Builder::new(); b.append_option(r.if_index); b.finish() }),
        Arc::new({ let mut b = UInt32Builder::new(); b.append_option(r.if_type); b.finish() }),
        Arc::new({ let mut b = UInt64Builder::new(); b.append_option(r.if_speed); b.finish() }),
        Arc::new({ let mut b = UInt32Builder::new(); b.append_option(r.if_direction); b.finish() }),
        Arc::new({ let mut b = UInt64Builder::new(); b.append_option(r.if_in_octets); b.finish() }),
        Arc::new({ let mut b = UInt64Builder::new(); b.append_option(r.if_out_octets); b.finish() }),
        Arc::new({ let mut b = UInt64Builder::new(); b.append_option(r.if_in_ucast_pkts); b.finish() }),
        Arc::new({ let mut b = UInt64Builder::new(); b.append_option(r.if_out_ucast_pkts); b.finish() }),
        Arc::new({ let mut b = UInt32Builder::new(); b.append_option(r.if_in_errors); b.finish() }),
        Arc::new({ let mut b = UInt32Builder::new(); b.append_option(r.if_out_errors); b.finish() }),
        Arc::new({ let mut b = StringBuilder::new(); b.append_value(&extra_str); b.finish() }),
    ];
    Ok(RecordBatch::try_new(schema.clone(), columns)?)
}

// ── SflowS3Handler — type alias + SflowHandler impl ─────────────────────────

pub type SflowS3Handler = crate::forwarding::buffered_writer::ParquetWriterHandle<SflowSink>;

#[async_trait::async_trait]
impl crate::sflow::listener::SflowHandler
    for crate::forwarding::buffered_writer::ParquetWriterHandle<SflowSink>
{
    async fn handle_samples(&self, samples: Vec<SflowRecord>, source: std::net::SocketAddr) {
        for record in samples {
            if let Err(_dropped) = self.try_send(record) {
                tracing::warn!("sFlow S3 channel full; dropped record from {}", source);
            }
        }
    }
}

// ── sflow_start — convenience constructor ────────────────────────────────────

pub fn sflow_start(
    cfg: &SflowS3Config,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
) -> (SflowS3Handler, tokio::task::JoinHandle<()>) {
    use crate::forwarding::buffered_writer::{BufferedWriterConfig, FlushPolicy, ParquetWriterHandle};
    let bwc = BufferedWriterConfig {
        connection: cfg.connection.clone(),
        prefix: cfg.prefix.clone(),
        max_buffer_rows: cfg.max_buffer_rows,
        flush_threshold_bytes: cfg.flush_threshold_bytes,
        flush_interval_secs: cfg.flush_interval_secs,
        channel_capacity: cfg.channel_capacity,
        max_partitions: 2, // "flow" and "counter"
    };
    let policy = FlushPolicy {
        max_rows: cfg.max_buffer_rows,
        max_bytes: cfg.flush_threshold_bytes,
        interval: std::time::Duration::from_secs(cfg.flush_interval_secs),
    };
    ParquetWriterHandle::start(SflowSink, s3, bwc, policy)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forwarding::buffered_writer::ParquetSink;
    use crate::sflow::{SampleType, SflowRecord};
    use arrow::array::{StringArray, UInt32Array, UInt64Array};

    fn make_flow_record() -> SflowRecord {
        SflowRecord {
            sample_type: SampleType::Flow,
            exporter: "10.0.0.1".parse().unwrap(),
            received_at: chrono::Utc::now(),
            src_addr: Some("192.168.1.1".parse().unwrap()),
            dst_addr: Some("10.0.0.2".parse().unwrap()),
            src_port: Some(1234),
            dst_port: Some(443),
            ip_protocol: Some(6),
            sampling_rate: Some(512),
            input_ifindex: Some(1),
            output_ifindex: Some(2),
            if_index: None, if_type: None, if_speed: None, if_direction: None,
            if_in_octets: None, if_out_octets: None,
            if_in_ucast_pkts: None, if_out_ucast_pkts: None,
            if_in_errors: None, if_out_errors: None,
            extra: serde_json::json!([]),
        }
    }

    fn make_counter_record() -> SflowRecord {
        SflowRecord {
            sample_type: SampleType::Counter,
            exporter: "10.0.0.1".parse().unwrap(),
            received_at: chrono::Utc::now(),
            src_addr: None, dst_addr: None, src_port: None, dst_port: None, ip_protocol: None,
            sampling_rate: None, input_ifindex: None, output_ifindex: None,
            if_index: Some(1), if_type: Some(6),
            if_speed: Some(1_000_000_000),
            if_direction: Some(1),
            if_in_octets: Some(1_000_000),
            if_out_octets: Some(500_000),
            if_in_ucast_pkts: Some(1000),
            if_out_ucast_pkts: Some(500),
            if_in_errors: Some(2),
            if_out_errors: Some(1),
            extra: serde_json::json!([]),
        }
    }

    #[test]
    fn sink_partition_returns_flow_for_flow_records() {
        let sink = SflowSink;
        let r = make_flow_record();
        assert_eq!(sink.partition(&r), Some("flow".to_string()));
    }

    #[test]
    fn sink_partition_returns_counter_for_counter_records() {
        let sink = SflowSink;
        let r = make_counter_record();
        assert_eq!(sink.partition(&r), Some("counter".to_string()));
    }

    #[test]
    fn flow_schema_has_required_columns() {
        let sink = SflowSink;
        let schema = sink.schema(Some("flow"));
        for col in &["sample_type", "exporter", "received_at", "src_addr", "dst_addr",
                      "src_port", "dst_port", "ip_protocol", "sampling_rate",
                      "input_ifindex", "output_ifindex", "extra"] {
            assert!(
                schema.field_with_name(col).is_ok(),
                "flow schema missing column '{col}'"
            );
        }
    }

    #[test]
    fn counter_schema_has_required_columns() {
        let sink = SflowSink;
        let schema = sink.schema(Some("counter"));
        for col in &["sample_type", "exporter", "received_at",
                      "if_index", "if_type", "if_speed", "if_direction",
                      "if_in_octets", "if_out_octets",
                      "if_in_ucast_pkts", "if_out_ucast_pkts",
                      "if_in_errors", "if_out_errors", "extra"] {
            assert!(
                schema.field_with_name(col).is_ok(),
                "counter schema missing column '{col}'"
            );
        }
    }

    #[test]
    fn to_record_batch_flow_produces_correct_values() {
        let sink = SflowSink;
        let r = make_flow_record();
        let schema = sink.schema(Some("flow"));
        let batch = sink.to_record_batch(&r, &schema).unwrap();
        assert_eq!(batch.num_rows(), 1);

        let src = batch.column_by_name("src_addr").unwrap()
            .as_any().downcast_ref::<StringArray>().unwrap();
        assert_eq!(src.value(0), "192.168.1.1");

        let sr = batch.column_by_name("sampling_rate").unwrap()
            .as_any().downcast_ref::<UInt32Array>().unwrap();
        assert_eq!(sr.value(0), 512);
    }

    #[test]
    fn to_record_batch_counter_produces_correct_values() {
        let sink = SflowSink;
        let r = make_counter_record();
        let schema = sink.schema(Some("counter"));
        let batch = sink.to_record_batch(&r, &schema).unwrap();
        assert_eq!(batch.num_rows(), 1);

        let if_speed = batch.column_by_name("if_speed").unwrap()
            .as_any().downcast_ref::<UInt64Array>().unwrap();
        assert_eq!(if_speed.value(0), 1_000_000_000u64);

        let if_in_oct = batch.column_by_name("if_in_octets").unwrap()
            .as_any().downcast_ref::<UInt64Array>().unwrap();
        assert_eq!(if_in_oct.value(0), 1_000_000u64);
    }
}
