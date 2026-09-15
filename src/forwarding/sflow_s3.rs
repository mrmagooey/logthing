//! sFlow v5 → S3 Parquet persistence.

use crate::config::SflowS3Config;
use crate::forwarding::buffered_writer::ParquetSink;
use crate::forwarding::drop_log::{DropKind, DropSite};
use crate::sflow::{SampleType, SflowRecord};
use arrow::array::{
    ArrayRef, StringBuilder, TimestampMicrosecondBuilder, UInt8Builder, UInt16Builder,
    UInt32Builder, UInt64Builder,
};
use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use arrow::record_batch::RecordBatch;
use std::sync::{Arc, LazyLock};

// ── Schemas ──────────────────────────────────────────────────────────────────

static FLOW_SCHEMA: LazyLock<Arc<Schema>> = LazyLock::new(|| {
    Arc::new(Schema::new(vec![
        Field::new("sample_type", DataType::Utf8, false),
        Field::new("exporter", DataType::Utf8, false),
        Field::new(
            "received_at",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            false,
        ),
        Field::new("src_addr", DataType::Utf8, true),
        Field::new("dst_addr", DataType::Utf8, true),
        Field::new("src_port", DataType::UInt16, true),
        Field::new("dst_port", DataType::UInt16, true),
        Field::new("ip_protocol", DataType::UInt8, true),
        Field::new("sampling_rate", DataType::UInt32, true),
        Field::new("input_ifindex", DataType::UInt32, true),
        Field::new("output_ifindex", DataType::UInt32, true),
        Field::new("extra", DataType::Utf8, false),
        Field::new(
            "partition_time",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            false,
        ),
    ]))
});

static COUNTER_SCHEMA: LazyLock<Arc<Schema>> = LazyLock::new(|| {
    Arc::new(Schema::new(vec![
        Field::new("sample_type", DataType::Utf8, false),
        Field::new("exporter", DataType::Utf8, false),
        Field::new(
            "received_at",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            false,
        ),
        Field::new("if_index", DataType::UInt32, true),
        Field::new("if_type", DataType::UInt32, true),
        Field::new("if_speed", DataType::UInt64, true),
        Field::new("if_direction", DataType::UInt32, true),
        Field::new("if_in_octets", DataType::UInt64, true),
        Field::new("if_out_octets", DataType::UInt64, true),
        Field::new("if_in_ucast_pkts", DataType::UInt64, true),
        Field::new("if_out_ucast_pkts", DataType::UInt64, true),
        Field::new("if_in_errors", DataType::UInt32, true),
        Field::new("if_out_errors", DataType::UInt32, true),
        Field::new("extra", DataType::Utf8, false),
        Field::new(
            "partition_time",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            false,
        ),
    ]))
});

// ── SflowSink ────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct SflowSink;

impl ParquetSink for SflowSink {
    type Record = SflowRecord;

    fn source(&self) -> &'static str {
        "sflow"
    }

    fn partition(&self, record: &SflowRecord) -> Option<String> {
        Some(match record.sample_type {
            SampleType::Flow => "flow".to_string(),
            SampleType::Counter => "counter".to_string(),
        })
    }

    fn schema(&self, partition: Option<&str>) -> Arc<arrow_schema::Schema> {
        match partition {
            Some("counter") => COUNTER_SCHEMA.clone(),
            _ => FLOW_SCHEMA.clone(), // "flow" or None
        }
    }

    /// Time column for day bucketing. sFlow samples carry a sample timestamp
    /// but it is offset-based, not absolute; `partition_time` is derived from
    /// the non-null `received_at` (collector receipt time) for reliable
    /// partitioning across clock skews.
    fn time_column(&self) -> Option<&'static str> {
        Some("partition_time")
    }

    fn to_record_batch(
        &self,
        record: &SflowRecord,
        schema: &Arc<arrow_schema::Schema>,
    ) -> anyhow::Result<arrow_array::RecordBatch> {
        match record.sample_type {
            SampleType::Flow => flow_to_record_batch(record, schema),
            SampleType::Counter => counter_to_record_batch(record, schema),
        }
    }

    /// Amortized-builder fast path. Unlike IPFIX/Suricata's single schema,
    /// sFlow has two -- gate on `Arc::ptr_eq` against each of `FLOW_SCHEMA`
    /// and `COUNTER_SCHEMA` (mirroring `ZeekSink::new_batch`'s per-schema
    /// gating) so a partition buffer only ever gets the accumulator that
    /// matches the exact schema `push()` resolved for it.
    fn new_batch(
        &self,
        schema: &Arc<arrow_schema::Schema>,
    ) -> Option<Box<dyn crate::forwarding::buffered_writer::RecordBatchAccumulator<SflowRecord>>>
    {
        if Arc::ptr_eq(schema, &FLOW_SCHEMA) {
            Some(Box::new(FlowSampleAccumulator::new()))
        } else if Arc::ptr_eq(schema, &COUNTER_SCHEMA) {
            Some(Box::new(CounterSampleAccumulator::new()))
        } else {
            None
        }
    }

    /// Overrides the default `day_and_batch`: derives the day directly from
    /// `record.received_at` without building a batch. Load-bearing for the
    /// same reason as `IpfixSink`'s / `ZeekSink`'s overrides -- `push()`
    /// calls this before it knows whether the record goes to the amortized
    /// live builder, so building a batch here just to learn the day would
    /// make every push pay for a throwaway `RecordBatch`, defeating the
    /// entire point of `FlowSampleAccumulator`/`CounterSampleAccumulator`.
    ///
    /// Must match today's (default `day_and_batch` + `day_from_batch`)
    /// behaviour exactly: `day_from_batch` reads `partition_time` row 0 of
    /// the materialized batch, and both mappers set `partition_time` to
    /// exactly `partition_time(Some(record.received_at), record.received_at)`
    /// -- replicating that same call here picks the identical day without
    /// needing the batch at all.
    ///
    /// Unlike `IpfixSink` (which has no per-record receipt instant and must
    /// use `push()`'s single `now`), `SflowRecord` already carries its own
    /// stamped `received_at` (like `SuricataRecord`), so `now` is unused
    /// here -- using it instead would disagree with what the accumulator
    /// itself derives the day from.
    fn day_and_batch(
        &self,
        record: &SflowRecord,
        _schema: &Arc<arrow_schema::Schema>,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<(chrono::NaiveDate, Option<arrow_array::RecordBatch>)> {
        let day = crate::forwarding::buffered_writer::partition_time(
            Some(record.received_at),
            record.received_at,
        )
        .date_naive();
        Ok((day, None))
    }
}

// ---------------------------------------------------------------------------
// FlowSampleAccumulator / CounterSampleAccumulator — amortized-builder fast path
// ---------------------------------------------------------------------------

/// Amortized builder set for flow-sample rows (`FLOW_SCHEMA`). Holds the
/// same 13 Arrow builders `flow_to_record_batch` used to create fresh on
/// every call, as persistent fields, reused across many records via
/// `finish(&mut self)` instead of reallocated per record. Mirrors
/// `suricata::schema::EnvelopeAccumulator`.
pub(crate) struct FlowSampleAccumulator {
    b_sample_type: StringBuilder,
    b_exporter: StringBuilder,
    b_received_at: TimestampMicrosecondBuilder,
    b_src_addr: StringBuilder,
    b_dst_addr: StringBuilder,
    b_src_port: UInt16Builder,
    b_dst_port: UInt16Builder,
    b_ip_protocol: UInt8Builder,
    b_sampling_rate: UInt32Builder,
    b_input_ifindex: UInt32Builder,
    b_output_ifindex: UInt32Builder,
    b_extra: StringBuilder,
    b_partition_time: TimestampMicrosecondBuilder,
    rows: usize,
}

impl FlowSampleAccumulator {
    pub(crate) fn new() -> Self {
        Self {
            b_sample_type: StringBuilder::new(),
            b_exporter: StringBuilder::new(),
            b_received_at: TimestampMicrosecondBuilder::new().with_data_type(DataType::Timestamp(
                TimeUnit::Microsecond,
                Some("UTC".into()),
            )),
            b_src_addr: StringBuilder::new(),
            b_dst_addr: StringBuilder::new(),
            b_src_port: UInt16Builder::new(),
            b_dst_port: UInt16Builder::new(),
            b_ip_protocol: UInt8Builder::new(),
            b_sampling_rate: UInt32Builder::new(),
            b_input_ifindex: UInt32Builder::new(),
            b_output_ifindex: UInt32Builder::new(),
            b_extra: StringBuilder::new(),
            b_partition_time: TimestampMicrosecondBuilder::new().with_data_type(
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            ),
            rows: 0,
        }
    }

    /// Append one flow-sample `SflowRecord` into the persistent builders.
    /// Shared by both the amortized path (`RecordBatchAccumulator::try_append`)
    /// and `flow_to_record_batch`'s single-record wrapper below -- identical
    /// extraction logic either way, so there is exactly one place that knows
    /// how a flow-sample `SflowRecord` becomes a row.
    fn append_flow_value(&mut self, r: &SflowRecord) {
        let extra_str = serde_json::to_string(&r.extra).unwrap_or_else(|_| "[]".to_string());
        // sFlow has no absolute event timestamp (sample timestamps are
        // offset-based), so `received_at` is both the event and the receipt
        // instant. Routed through the shared helper (rather than assigned
        // directly) so every sink derives `partition_time` via one code path.
        let partition_time =
            crate::forwarding::buffered_writer::partition_time(Some(r.received_at), r.received_at);

        self.b_sample_type.append_value("flow");
        self.b_exporter.append_value(r.exporter.to_string());
        self.b_received_at
            .append_value(r.received_at.timestamp_micros());
        self.b_src_addr
            .append_option(r.src_addr.as_ref().map(|a| a.to_string()));
        self.b_dst_addr
            .append_option(r.dst_addr.as_ref().map(|a| a.to_string()));
        self.b_src_port.append_option(r.src_port);
        self.b_dst_port.append_option(r.dst_port);
        self.b_ip_protocol.append_option(r.ip_protocol);
        self.b_sampling_rate.append_option(r.sampling_rate);
        self.b_input_ifindex.append_option(r.input_ifindex);
        self.b_output_ifindex.append_option(r.output_ifindex);
        self.b_extra.append_value(&extra_str);
        self.b_partition_time
            .append_value(partition_time.timestamp_micros());
        self.rows += 1;
    }

    fn finish_batch(&mut self) -> anyhow::Result<RecordBatch> {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(self.b_sample_type.finish()),
            Arc::new(self.b_exporter.finish()),
            Arc::new(self.b_received_at.finish()),
            Arc::new(self.b_src_addr.finish()),
            Arc::new(self.b_dst_addr.finish()),
            Arc::new(self.b_src_port.finish()),
            Arc::new(self.b_dst_port.finish()),
            Arc::new(self.b_ip_protocol.finish()),
            Arc::new(self.b_sampling_rate.finish()),
            Arc::new(self.b_input_ifindex.finish()),
            Arc::new(self.b_output_ifindex.finish()),
            Arc::new(self.b_extra.finish()),
            Arc::new(self.b_partition_time.finish()),
        ];
        self.rows = 0;
        Ok(RecordBatch::try_new(FLOW_SCHEMA.clone(), columns)?)
    }
}

impl crate::forwarding::buffered_writer::RecordBatchAccumulator<SflowRecord>
    for FlowSampleAccumulator
{
    /// sFlow has two schemas selected by `record.sample_type` (unlike
    /// Suricata/IPFIX's single schema), so a counter-sample record handed to
    /// a flow accumulator is a real mismatch, not a defensive-only case:
    /// return `Ok(false)` so `push()` falls back to `to_record_batch` (which
    /// dispatches on `record.sample_type` itself and always lands the record
    /// in its own correct partition/schema).
    fn try_append(
        &mut self,
        record: &SflowRecord,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<bool> {
        if record.sample_type != SampleType::Flow {
            return Ok(false);
        }
        self.append_flow_value(record);
        Ok(true)
    }

    fn len(&self) -> usize {
        self.rows
    }

    fn finish(&mut self) -> anyhow::Result<RecordBatch> {
        self.finish_batch()
    }
}

/// Amortized builder set for counter-sample rows (`COUNTER_SCHEMA`). Same
/// shape as `FlowSampleAccumulator`, mirroring its own fixed schema.
pub(crate) struct CounterSampleAccumulator {
    b_sample_type: StringBuilder,
    b_exporter: StringBuilder,
    b_received_at: TimestampMicrosecondBuilder,
    b_if_index: UInt32Builder,
    b_if_type: UInt32Builder,
    b_if_speed: UInt64Builder,
    b_if_direction: UInt32Builder,
    b_if_in_octets: UInt64Builder,
    b_if_out_octets: UInt64Builder,
    b_if_in_ucast_pkts: UInt64Builder,
    b_if_out_ucast_pkts: UInt64Builder,
    b_if_in_errors: UInt32Builder,
    b_if_out_errors: UInt32Builder,
    b_extra: StringBuilder,
    b_partition_time: TimestampMicrosecondBuilder,
    rows: usize,
}

impl CounterSampleAccumulator {
    pub(crate) fn new() -> Self {
        Self {
            b_sample_type: StringBuilder::new(),
            b_exporter: StringBuilder::new(),
            b_received_at: TimestampMicrosecondBuilder::new().with_data_type(DataType::Timestamp(
                TimeUnit::Microsecond,
                Some("UTC".into()),
            )),
            b_if_index: UInt32Builder::new(),
            b_if_type: UInt32Builder::new(),
            b_if_speed: UInt64Builder::new(),
            b_if_direction: UInt32Builder::new(),
            b_if_in_octets: UInt64Builder::new(),
            b_if_out_octets: UInt64Builder::new(),
            b_if_in_ucast_pkts: UInt64Builder::new(),
            b_if_out_ucast_pkts: UInt64Builder::new(),
            b_if_in_errors: UInt32Builder::new(),
            b_if_out_errors: UInt32Builder::new(),
            b_extra: StringBuilder::new(),
            b_partition_time: TimestampMicrosecondBuilder::new().with_data_type(
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            ),
            rows: 0,
        }
    }

    /// Append one counter-sample `SflowRecord` into the persistent builders.
    /// Shared by both the amortized path and `counter_to_record_batch`'s
    /// single-record wrapper below -- see `FlowSampleAccumulator::append_flow_value`.
    fn append_counter_value(&mut self, r: &SflowRecord) {
        let extra_str = serde_json::to_string(&r.extra).unwrap_or_else(|_| "[]".to_string());
        // See append_flow_value: counter samples likewise have no absolute
        // event timestamp, so `received_at` stands in for both helper arguments.
        let partition_time =
            crate::forwarding::buffered_writer::partition_time(Some(r.received_at), r.received_at);

        self.b_sample_type.append_value("counter");
        self.b_exporter.append_value(r.exporter.to_string());
        self.b_received_at
            .append_value(r.received_at.timestamp_micros());
        self.b_if_index.append_option(r.if_index);
        self.b_if_type.append_option(r.if_type);
        self.b_if_speed.append_option(r.if_speed);
        self.b_if_direction.append_option(r.if_direction);
        self.b_if_in_octets.append_option(r.if_in_octets);
        self.b_if_out_octets.append_option(r.if_out_octets);
        self.b_if_in_ucast_pkts.append_option(r.if_in_ucast_pkts);
        self.b_if_out_ucast_pkts.append_option(r.if_out_ucast_pkts);
        self.b_if_in_errors.append_option(r.if_in_errors);
        self.b_if_out_errors.append_option(r.if_out_errors);
        self.b_extra.append_value(&extra_str);
        self.b_partition_time
            .append_value(partition_time.timestamp_micros());
        self.rows += 1;
    }

    fn finish_batch(&mut self) -> anyhow::Result<RecordBatch> {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(self.b_sample_type.finish()),
            Arc::new(self.b_exporter.finish()),
            Arc::new(self.b_received_at.finish()),
            Arc::new(self.b_if_index.finish()),
            Arc::new(self.b_if_type.finish()),
            Arc::new(self.b_if_speed.finish()),
            Arc::new(self.b_if_direction.finish()),
            Arc::new(self.b_if_in_octets.finish()),
            Arc::new(self.b_if_out_octets.finish()),
            Arc::new(self.b_if_in_ucast_pkts.finish()),
            Arc::new(self.b_if_out_ucast_pkts.finish()),
            Arc::new(self.b_if_in_errors.finish()),
            Arc::new(self.b_if_out_errors.finish()),
            Arc::new(self.b_extra.finish()),
            Arc::new(self.b_partition_time.finish()),
        ];
        self.rows = 0;
        Ok(RecordBatch::try_new(COUNTER_SCHEMA.clone(), columns)?)
    }
}

impl crate::forwarding::buffered_writer::RecordBatchAccumulator<SflowRecord>
    for CounterSampleAccumulator
{
    /// See `FlowSampleAccumulator::try_append`: the mirror-image mismatch --
    /// a flow-sample record handed to the counter accumulator falls back to
    /// `to_record_batch` for just that one record.
    fn try_append(
        &mut self,
        record: &SflowRecord,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<bool> {
        if record.sample_type != SampleType::Counter {
            return Ok(false);
        }
        self.append_counter_value(record);
        Ok(true)
    }

    fn len(&self) -> usize {
        self.rows
    }

    fn finish(&mut self) -> anyhow::Result<RecordBatch> {
        self.finish_batch()
    }
}

fn flow_to_record_batch(r: &SflowRecord, _schema: &Arc<Schema>) -> anyhow::Result<RecordBatch> {
    let mut acc = FlowSampleAccumulator::new();
    acc.append_flow_value(r);
    acc.finish_batch()
}

fn counter_to_record_batch(r: &SflowRecord, _schema: &Arc<Schema>) -> anyhow::Result<RecordBatch> {
    let mut acc = CounterSampleAccumulator::new();
    acc.append_counter_value(r);
    acc.finish_batch()
}

// ── SflowS3Handler — type alias + SflowHandler impl ─────────────────────────

pub type SflowS3Handler = crate::forwarding::buffered_writer::ParquetWriterHandle<SflowSink>;

#[async_trait::async_trait]
impl crate::sflow::listener::SflowHandler
    for crate::forwarding::buffered_writer::ParquetWriterHandle<SflowSink>
{
    async fn handle_samples(&self, samples: Vec<SflowRecord>, source: std::net::SocketAddr) {
        for record in samples {
            if let Err(e) = self.try_send(record)
                && let Some(dropped_total) = self.drop_log_due(DropSite::Sflow, DropKind::from(&e))
            {
                tracing::warn!(
                    dropped_total,
                    "sFlow S3 channel full; dropped record from {}",
                    source
                );
            }
        }
    }
}

// ── MultiSflowHandler — fan-out to multiple destinations ────────────────────

/// Fans out each sample batch to every configured handler. Used only when
/// both `.s3` and `.local` persistence resolve to a live handler for the
/// same run, so each destination keeps its own independent buffer, flush
/// policy, backpressure, and hard cap (no shared state between destinations).
pub struct MultiSflowHandler(pub Vec<std::sync::Arc<dyn crate::sflow::listener::SflowHandler>>);

#[async_trait::async_trait]
impl crate::sflow::listener::SflowHandler for MultiSflowHandler {
    async fn handle_samples(&self, samples: Vec<SflowRecord>, source: std::net::SocketAddr) {
        for handler in &self.0 {
            handler.handle_samples(samples.clone(), source).await;
        }
    }
}

// ── sflow_start / sflow_local_start — convenience constructors ──────────────

/// sFlow has exactly two fixed partitions: `"flow"` and `"counter"`.
const SFLOW_MAX_PARTITIONS: usize = 2;

pub fn sflow_start(
    cfg: &SflowS3Config,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<std::sync::Arc<dyn crate::forwarding::buffered_writer::UploadSink>>,
) -> (SflowS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<SflowSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        SFLOW_MAX_PARTITIONS,
        s3,
        source_stats,
        descriptor_sink,
    )
}

/// Construct an `SflowS3Handler` from an `SflowLocalConfig` and a pre-built
/// `LocalDiskSink`. Structurally identical to `sflow_start`, writing to
/// local disk instead of S3 — same `SflowSink` adapter, same
/// buffering/flush/cap machinery, same S3-key-shaped relative path layout
/// on disk.
pub fn sflow_local_start(
    cfg: &crate::config::SflowLocalConfig,
    sink: std::sync::Arc<crate::forwarding::local_sink::LocalDiskSink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<std::sync::Arc<dyn crate::forwarding::buffered_writer::UploadSink>>,
) -> (SflowS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<SflowSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        SFLOW_MAX_PARTITIONS,
        sink,
        source_stats,
        descriptor_sink,
    )
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
            if_index: None,
            if_type: None,
            if_speed: None,
            if_direction: None,
            if_in_octets: None,
            if_out_octets: None,
            if_in_ucast_pkts: None,
            if_out_ucast_pkts: None,
            if_in_errors: None,
            if_out_errors: None,
            extra: serde_json::json!([]),
        }
    }

    fn make_counter_record() -> SflowRecord {
        SflowRecord {
            sample_type: SampleType::Counter,
            exporter: "10.0.0.1".parse().unwrap(),
            received_at: chrono::Utc::now(),
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            ip_protocol: None,
            sampling_rate: None,
            input_ifindex: None,
            output_ifindex: None,
            if_index: Some(1),
            if_type: Some(6),
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
        for col in &[
            "sample_type",
            "exporter",
            "received_at",
            "src_addr",
            "dst_addr",
            "src_port",
            "dst_port",
            "ip_protocol",
            "sampling_rate",
            "input_ifindex",
            "output_ifindex",
            "extra",
        ] {
            assert!(
                schema.field_with_name(col).is_ok(),
                "flow schema missing column '{col}'"
            );
        }
        let f = schema.field_with_name("received_at").unwrap();
        assert_eq!(
            f.data_type(),
            &DataType::Timestamp(arrow::datatypes::TimeUnit::Microsecond, Some("UTC".into()))
        );
        assert!(!f.is_nullable());
    }

    #[test]
    fn counter_schema_has_required_columns() {
        let sink = SflowSink;
        let schema = sink.schema(Some("counter"));
        for col in &[
            "sample_type",
            "exporter",
            "received_at",
            "if_index",
            "if_type",
            "if_speed",
            "if_direction",
            "if_in_octets",
            "if_out_octets",
            "if_in_ucast_pkts",
            "if_out_ucast_pkts",
            "if_in_errors",
            "if_out_errors",
            "extra",
        ] {
            assert!(
                schema.field_with_name(col).is_ok(),
                "counter schema missing column '{col}'"
            );
        }
        let f = schema.field_with_name("received_at").unwrap();
        assert_eq!(
            f.data_type(),
            &DataType::Timestamp(arrow::datatypes::TimeUnit::Microsecond, Some("UTC".into()))
        );
        assert!(!f.is_nullable());
    }

    #[test]
    fn to_record_batch_flow_produces_correct_values() {
        let sink = SflowSink;
        let r = make_flow_record();
        let schema = sink.schema(Some("flow"));
        let batch = sink.to_record_batch(&r, &schema).unwrap();
        assert_eq!(batch.num_rows(), 1);

        let src = batch
            .column_by_name("src_addr")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(src.value(0), "192.168.1.1");

        let sr = batch
            .column_by_name("sampling_rate")
            .unwrap()
            .as_any()
            .downcast_ref::<UInt32Array>()
            .unwrap();
        assert_eq!(sr.value(0), 512);

        let received_at = batch
            .column_by_name("received_at")
            .unwrap()
            .as_any()
            .downcast_ref::<arrow::array::TimestampMicrosecondArray>()
            .expect("received_at column should be TimestampMicrosecondArray");
        assert_eq!(received_at.value(0), r.received_at.timestamp_micros());
    }

    #[test]
    fn to_record_batch_counter_produces_correct_values() {
        let sink = SflowSink;
        let r = make_counter_record();
        let schema = sink.schema(Some("counter"));
        let batch = sink.to_record_batch(&r, &schema).unwrap();
        assert_eq!(batch.num_rows(), 1);

        let if_speed = batch
            .column_by_name("if_speed")
            .unwrap()
            .as_any()
            .downcast_ref::<UInt64Array>()
            .unwrap();
        assert_eq!(if_speed.value(0), 1_000_000_000u64);

        let if_in_oct = batch
            .column_by_name("if_in_octets")
            .unwrap()
            .as_any()
            .downcast_ref::<UInt64Array>()
            .unwrap();
        assert_eq!(if_in_oct.value(0), 1_000_000u64);

        let received_at = batch
            .column_by_name("received_at")
            .unwrap()
            .as_any()
            .downcast_ref::<arrow::array::TimestampMicrosecondArray>()
            .expect("received_at column should be TimestampMicrosecondArray");
        assert_eq!(received_at.value(0), r.received_at.timestamp_micros());
    }

    #[test]
    fn flow_schema_has_non_null_microsecond_partition_time() {
        let sink = SflowSink;
        let schema = sink.schema(Some("flow"));
        let f = schema
            .field_with_name("partition_time")
            .expect("flow schema missing partition_time");
        assert_eq!(
            f.data_type(),
            &DataType::Timestamp(arrow::datatypes::TimeUnit::Microsecond, Some("UTC".into()))
        );
        assert!(!f.is_nullable(), "partition_time must be non-nullable");
    }

    #[test]
    fn counter_schema_has_non_null_microsecond_partition_time() {
        let sink = SflowSink;
        let schema = sink.schema(Some("counter"));
        let f = schema
            .field_with_name("partition_time")
            .expect("counter schema missing partition_time");
        assert_eq!(
            f.data_type(),
            &DataType::Timestamp(arrow::datatypes::TimeUnit::Microsecond, Some("UTC".into()))
        );
        assert!(!f.is_nullable(), "partition_time must be non-nullable");
    }

    #[test]
    fn to_record_batch_flow_partition_time_equals_received_at() {
        // A distinctive, non-"now" instant: a broken mapper that fell back to
        // Utc::now() or the epoch would visibly fail this.
        let mut r = make_flow_record();
        r.received_at = chrono::DateTime::parse_from_rfc3339("2024-03-11T08:15:30.654321Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let sink = SflowSink;
        let schema = sink.schema(Some("flow"));
        let batch = sink.to_record_batch(&r, &schema).unwrap();

        let partition_time = batch
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<arrow::array::TimestampMicrosecondArray>()
            .expect("partition_time column should be TimestampMicrosecondArray");
        assert_eq!(partition_time.value(0), r.received_at.timestamp_micros());
    }

    #[test]
    fn to_record_batch_counter_partition_time_equals_received_at() {
        let mut r = make_counter_record();
        r.received_at = chrono::DateTime::parse_from_rfc3339("2024-03-11T08:15:30.654321Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let sink = SflowSink;
        let schema = sink.schema(Some("counter"));
        let batch = sink.to_record_batch(&r, &schema).unwrap();

        let partition_time = batch
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<arrow::array::TimestampMicrosecondArray>()
            .expect("partition_time column should be TimestampMicrosecondArray");
        assert_eq!(partition_time.value(0), r.received_at.timestamp_micros());
    }

    #[test]
    fn sflow_sink_time_column_received_at_exists_in_both_schemas() {
        let sink = SflowSink;
        let col = sink
            .time_column()
            .expect("sflow_sink must opt in to day partitioning");
        // Pin the exact column name, not just that SOME name resolves.
        assert_eq!(col, "partition_time");
        // Check both flow and counter schemas
        for partition in &[Some("flow"), Some("counter")] {
            let schema = sink.schema(*partition);
            assert!(
                schema.field_with_name(col).is_ok(),
                "time_column() returned {:?}, which is not a field in schema for partition {:?}",
                col,
                partition
            );
        }
    }

    // -- FlowSampleAccumulator / CounterSampleAccumulator unit tests --

    fn make_flow_records(n: usize) -> Vec<SflowRecord> {
        (0..n)
            .map(|i| {
                let mut r = make_flow_record();
                r.src_port = Some(1000 + i as u16);
                r
            })
            .collect()
    }

    fn make_counter_records(n: usize) -> Vec<SflowRecord> {
        (0..n)
            .map(|i| {
                let mut r = make_counter_record();
                r.if_index = Some(i as u32);
                r
            })
            .collect()
    }

    #[test]
    fn flow_accumulator_matches_to_record_batch_output_row_for_row() {
        use crate::forwarding::buffered_writer::RecordBatchAccumulator;

        let records = make_flow_records(3);
        let schema = FLOW_SCHEMA.clone();

        // Baseline: today's exact per-record path, N single-row batches concatenated.
        let single_row_batches: Vec<RecordBatch> = records
            .iter()
            .map(|r| flow_to_record_batch(r, &schema).unwrap())
            .collect();
        let expected = arrow::compute::concat_batches(&schema, &single_row_batches).unwrap();

        // Amortized path: one accumulator, N appends, one finish.
        let mut acc = FlowSampleAccumulator::new();
        for r in &records {
            assert!(acc.try_append(r, chrono::Utc::now()).unwrap());
        }
        let actual = acc.finish().unwrap();

        assert_eq!(actual.num_rows(), expected.num_rows());
        assert_eq!(actual.schema(), expected.schema());
        for col_idx in 0..expected.num_columns() {
            assert_eq!(
                format!("{:?}", actual.column(col_idx)),
                format!("{:?}", expected.column(col_idx)),
                "column {col_idx} differs between amortized and per-record paths"
            );
        }
    }

    #[test]
    fn counter_accumulator_matches_to_record_batch_output_row_for_row() {
        use crate::forwarding::buffered_writer::RecordBatchAccumulator;

        let records = make_counter_records(3);
        let schema = COUNTER_SCHEMA.clone();

        let single_row_batches: Vec<RecordBatch> = records
            .iter()
            .map(|r| counter_to_record_batch(r, &schema).unwrap())
            .collect();
        let expected = arrow::compute::concat_batches(&schema, &single_row_batches).unwrap();

        let mut acc = CounterSampleAccumulator::new();
        for r in &records {
            assert!(acc.try_append(r, chrono::Utc::now()).unwrap());
        }
        let actual = acc.finish().unwrap();

        assert_eq!(actual.num_rows(), expected.num_rows());
        assert_eq!(actual.schema(), expected.schema());
        for col_idx in 0..expected.num_columns() {
            assert_eq!(
                format!("{:?}", actual.column(col_idx)),
                format!("{:?}", expected.column(col_idx)),
                "column {col_idx} differs between amortized and per-record paths"
            );
        }
    }

    #[test]
    fn flow_accumulator_len_and_is_empty() {
        use crate::forwarding::buffered_writer::RecordBatchAccumulator;

        let mut acc = FlowSampleAccumulator::new();
        assert_eq!(acc.len(), 0);
        assert!(acc.is_empty());

        acc.try_append(&make_flow_record(), chrono::Utc::now())
            .unwrap();
        assert_eq!(acc.len(), 1);
        assert!(!acc.is_empty());

        acc.try_append(&make_flow_record(), chrono::Utc::now())
            .unwrap();
        assert_eq!(acc.len(), 2);

        acc.finish().unwrap();
        assert_eq!(acc.len(), 0, "finish must reset the row count");
        assert!(acc.is_empty());
    }

    #[test]
    fn counter_accumulator_len_and_is_empty() {
        use crate::forwarding::buffered_writer::RecordBatchAccumulator;

        let mut acc = CounterSampleAccumulator::new();
        assert_eq!(acc.len(), 0);
        assert!(acc.is_empty());

        acc.try_append(&make_counter_record(), chrono::Utc::now())
            .unwrap();
        assert_eq!(acc.len(), 1);
        assert!(!acc.is_empty());

        acc.finish().unwrap();
        assert_eq!(acc.len(), 0, "finish must reset the row count");
        assert!(acc.is_empty());
    }

    #[test]
    fn flow_accumulator_finish_twice_produces_independent_batches() {
        use crate::forwarding::buffered_writer::RecordBatchAccumulator;

        let mut acc = FlowSampleAccumulator::new();

        let mut rec_a = make_flow_record();
        rec_a.src_port = Some(1111);
        acc.try_append(&rec_a, chrono::Utc::now()).unwrap();
        let batch_a = acc.finish().unwrap();
        assert_eq!(
            batch_a.num_rows(),
            1,
            "first finish must contain exactly the rows appended before it"
        );

        let mut rec_b = make_flow_record();
        rec_b.src_port = Some(2222);
        let mut rec_c = make_flow_record();
        rec_c.src_port = Some(3333);
        acc.try_append(&rec_b, chrono::Utc::now()).unwrap();
        acc.try_append(&rec_c, chrono::Utc::now()).unwrap();
        let batch_b = acc.finish().unwrap();

        assert_eq!(
            batch_b.num_rows(),
            2,
            "second finish must contain exactly the rows appended since the first finish -- \
             a builder that retained prior rows would produce 3 here, silently duplicating data"
        );
        let src_ports = batch_b
            .column_by_name("src_port")
            .unwrap()
            .as_any()
            .downcast_ref::<arrow::array::UInt16Array>()
            .unwrap();
        assert_eq!(src_ports.value(0), 2222);
        assert_eq!(src_ports.value(1), 3333);
    }

    #[test]
    fn counter_accumulator_finish_twice_produces_independent_batches() {
        use crate::forwarding::buffered_writer::RecordBatchAccumulator;

        let mut acc = CounterSampleAccumulator::new();

        let mut rec_a = make_counter_record();
        rec_a.if_index = Some(11);
        acc.try_append(&rec_a, chrono::Utc::now()).unwrap();
        let batch_a = acc.finish().unwrap();
        assert_eq!(batch_a.num_rows(), 1);

        let mut rec_b = make_counter_record();
        rec_b.if_index = Some(22);
        let mut rec_c = make_counter_record();
        rec_c.if_index = Some(33);
        acc.try_append(&rec_b, chrono::Utc::now()).unwrap();
        acc.try_append(&rec_c, chrono::Utc::now()).unwrap();
        let batch_b = acc.finish().unwrap();

        assert_eq!(batch_b.num_rows(), 2);
        let if_indexes = batch_b
            .column_by_name("if_index")
            .unwrap()
            .as_any()
            .downcast_ref::<UInt32Array>()
            .unwrap();
        assert_eq!(if_indexes.value(0), 22);
        assert_eq!(if_indexes.value(1), 33);
    }

    /// The cross-schema rejection case that makes sFlow's fallback path
    /// REAL (unlike Suricata/IPFIX's always-`Ok(true)` single-schema
    /// accumulators): a flow-sample accumulator handed a counter-sample
    /// record must reject it, unmodified, so `push()` falls back to
    /// `to_record_batch` for just that one record.
    #[test]
    fn flow_accumulator_rejects_counter_sample_record() {
        use crate::forwarding::buffered_writer::RecordBatchAccumulator;

        let mut acc = FlowSampleAccumulator::new();
        let rejected = acc
            .try_append(&make_counter_record(), chrono::Utc::now())
            .unwrap();
        assert!(
            !rejected,
            "a counter-sample record must not be accepted by the flow accumulator"
        );
        assert_eq!(
            acc.len(),
            0,
            "a rejected record must not have been appended"
        );
    }

    /// Mirror image of the above: a counter-sample accumulator handed a
    /// flow-sample record must likewise reject it.
    #[test]
    fn counter_accumulator_rejects_flow_sample_record() {
        use crate::forwarding::buffered_writer::RecordBatchAccumulator;

        let mut acc = CounterSampleAccumulator::new();
        let rejected = acc
            .try_append(&make_flow_record(), chrono::Utc::now())
            .unwrap();
        assert!(
            !rejected,
            "a flow-sample record must not be accepted by the counter accumulator"
        );
        assert_eq!(
            acc.len(),
            0,
            "a rejected record must not have been appended"
        );
    }

    #[test]
    fn sflow_sink_new_batch_activates_for_both_real_schemas_and_rejects_unrelated() {
        let sink = SflowSink;
        assert!(
            sink.new_batch(&FLOW_SCHEMA).is_some(),
            "new_batch must activate for the real FLOW_SCHEMA"
        );
        assert!(
            sink.new_batch(&COUNTER_SCHEMA).is_some(),
            "new_batch must activate for the real COUNTER_SCHEMA"
        );

        let other_schema: Arc<Schema> = Arc::new(Schema::new(vec![Field::new(
            "unrelated",
            DataType::Utf8,
            false,
        )]));
        assert!(
            sink.new_batch(&other_schema).is_none(),
            "new_batch must not activate for a schema that isn't FLOW_SCHEMA or COUNTER_SCHEMA"
        );
    }

    // -- SflowSink::day_and_batch unit tests --

    #[test]
    fn day_and_batch_matches_default_day_from_batch_mechanism_for_flow() {
        let sink = SflowSink;
        let schema = FLOW_SCHEMA.clone();
        let mut r = make_flow_record();
        r.received_at = chrono::DateTime::parse_from_rfc3339("2026-05-06T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let now = chrono::Utc::now(); // deliberately far from r.received_at; must be ignored

        let (day, pre_mapped) = sink.day_and_batch(&r, &schema, now).unwrap();
        assert!(
            pre_mapped.is_none(),
            "day_and_batch must not build a batch just to compute the day"
        );
        assert_eq!(day, chrono::NaiveDate::from_ymd_opt(2026, 5, 6).unwrap());

        // Cross-check against the default mechanism: build the batch and
        // read the day back off it via the same column the trait's default
        // day_and_batch/day_from_batch would use.
        let batch = flow_to_record_batch(&r, &schema).unwrap();
        let col = batch
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<arrow::array::TimestampMicrosecondArray>()
            .unwrap();
        let default_day = chrono::DateTime::from_timestamp_micros(col.value(0))
            .unwrap()
            .date_naive();
        assert_eq!(day, default_day);
    }

    #[test]
    fn day_and_batch_matches_default_day_from_batch_mechanism_for_counter() {
        let sink = SflowSink;
        let schema = COUNTER_SCHEMA.clone();
        let mut r = make_counter_record();
        r.received_at = chrono::DateTime::parse_from_rfc3339("2026-01-02T23:59:59Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let now = chrono::Utc::now();

        let (day, pre_mapped) = sink.day_and_batch(&r, &schema, now).unwrap();
        assert!(pre_mapped.is_none());
        assert_eq!(day, chrono::NaiveDate::from_ymd_opt(2026, 1, 2).unwrap());

        let batch = counter_to_record_batch(&r, &schema).unwrap();
        let col = batch
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<arrow::array::TimestampMicrosecondArray>()
            .unwrap();
        let default_day = chrono::DateTime::from_timestamp_micros(col.value(0))
            .unwrap()
            .date_naive();
        assert_eq!(day, default_day);
    }

    #[tokio::test]
    async fn sflow_sink_reports_into_shared_source_hourly_stats() {
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
            prefix: "sflow".to_string(),
            max_buffer_rows: 1_000,
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 64,
            max_partitions: 2,
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
            SflowSink,
            s3,
            bwc,
            policy,
            shared_stats.clone(),
            None,
        );
        writer.push(make_flow_record()).await.unwrap();

        let snapshot = shared_stats.snapshot();
        let row = snapshot.iter().find(|r| r.source == "sflow").unwrap();
        let total: u64 = row.hours.iter().map(|h| h.count).sum();
        assert_eq!(total, 1);
    }

    // -- sflow_local_start wires handler and join handle --

    #[tokio::test]
    async fn sflow_local_start_wires_handler_and_join_handle() {
        use crate::config::SflowLocalConfig;
        use crate::forwarding::local_sink::LocalDiskSink;
        use crate::sflow::listener::SflowHandler;
        use std::net::SocketAddr;

        let dir = tempfile::tempdir().unwrap();
        let sink = Arc::new(
            LocalDiskSink::new(dir.path().to_path_buf())
                .await
                .expect("LocalDiskSink::new"),
        );
        let cfg = SflowLocalConfig {
            directory: dir.path().to_path_buf(),
            prefix: "sflow".to_string(),
            flush_threshold_bytes: 1, // flush on first push
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_buffer_rows: 100_000,
        };
        let (handler, join_handle) = sflow_local_start(
            &cfg,
            sink,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );

        let src: SocketAddr = "127.0.0.1:6343".parse().unwrap();
        handler
            .handle_samples(vec![make_flow_record(), make_counter_record()], src)
            .await;

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        drop(handler);
        tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("writer task must exit within 5s")
            .expect("writer task must not panic");

        for partition in ["flow", "counter"] {
            let dir_path = dir.path().join("sflow").join(partition);
            let mut found = false;
            for entry in walk_all_files(&dir_path) {
                if entry.extension().is_some_and(|e| e == "parquet") {
                    found = true;
                    break;
                }
            }
            assert!(
                found,
                "expected at least one Parquet file under {dir_path:?}"
            );
        }
    }

    /// Recursive walk — sFlow's key layout nests under year=/month=/day=/, so
    /// a flat `read_dir` on the prefix directory alone won't find the file.
    fn walk_all_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries {
                let entry = entry.unwrap();
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    out.push(path);
                }
            }
        }
        out
    }

    // -- MultiSflowHandler tests --

    #[tokio::test]
    async fn multi_sflow_handler_fans_out_to_every_inner_handler() {
        use crate::sflow::listener::SflowHandler;
        use std::net::SocketAddr;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingHandler(Arc<AtomicUsize>);
        #[async_trait::async_trait]
        impl SflowHandler for CountingHandler {
            async fn handle_samples(&self, _samples: Vec<SflowRecord>, _source: SocketAddr) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let count_a = Arc::new(AtomicUsize::new(0));
        let count_b = Arc::new(AtomicUsize::new(0));
        let multi = MultiSflowHandler(vec![
            Arc::new(CountingHandler(count_a.clone())),
            Arc::new(CountingHandler(count_b.clone())),
        ]);

        let src: SocketAddr = "127.0.0.1:6343".parse().unwrap();
        multi.handle_samples(vec![make_flow_record()], src).await;

        assert_eq!(
            count_a.load(Ordering::SeqCst),
            1,
            "handler A must receive the batch"
        );
        assert_eq!(
            count_b.load(Ordering::SeqCst),
            1,
            "handler B must receive the batch"
        );
    }

    #[tokio::test]
    #[allow(clippy::mutable_key_type)]
    async fn multi_sflow_handler_survives_one_inner_handler_dropping() {
        use crate::config::S3ConnectionConfig;
        use crate::sflow::listener::SflowHandler;
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::DebuggingRecorder;
        use std::net::SocketAddr;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let s3 = Arc::new(
            crate::forwarding::s3_sink::S3Sink::from_connection(&S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            })
            .await
            .unwrap(),
        );
        let cfg = SflowS3Config {
            connection: S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "sflow".to_string(),
            flush_threshold_bytes: 1,
            flush_interval_secs: 3600,
            channel_capacity: 1,
            max_buffer_rows: 1,
        };
        let (struggling_handler, _jh) = sflow_start(
            &cfg,
            s3,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );

        use std::sync::atomic::{AtomicUsize, Ordering};
        struct CountingHandler(Arc<AtomicUsize>);
        #[async_trait::async_trait]
        impl SflowHandler for CountingHandler {
            async fn handle_samples(&self, _samples: Vec<SflowRecord>, _source: SocketAddr) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let healthy_count = Arc::new(AtomicUsize::new(0));
        let multi = MultiSflowHandler(vec![
            Arc::new(struggling_handler),
            Arc::new(CountingHandler(healthy_count.clone())),
        ]);

        let src: SocketAddr = "127.0.0.1:6343".parse().unwrap();
        for _ in 0..20 {
            multi.handle_samples(vec![make_flow_record()], src).await;
        }

        assert_eq!(
            healthy_count.load(Ordering::SeqCst),
            20,
            "the healthy handler must receive every batch even if the struggling one drops some"
        );

        let snapshot = snapshotter.snapshot();
        let map = snapshot.into_hashmap();
        let key = CompositeKey::new(
            MetricKind::Counter,
            metrics::Key::from_parts(
                "parquet_s3_dropped",
                vec![
                    metrics::Label::new("source", "sflow"),
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
            "the struggling handler must actually have dropped at least one batch \
             for this test to prove handler isolation (dropped={dropped})"
        );
    }
}
