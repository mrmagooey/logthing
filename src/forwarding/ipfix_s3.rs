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
use crate::forwarding::buffered_writer::{ParquetSink, RecordBatchAccumulator};
use crate::forwarding::drop_log::{DropKind, DropSite};
use crate::ipfix::FlowRecord;
use arrow::array::{
    ArrayRef, StringBuilder, TimestampMicrosecondBuilder, UInt8Builder, UInt16Builder,
    UInt32Builder, UInt64Builder,
};
use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use arrow::record_batch::RecordBatch;
use chrono::{DateTime, Utc};
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
        Field::new(
            "export_time",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            false,
        ),
        Field::new("src_addr", DataType::Utf8, true),
        Field::new("dst_addr", DataType::Utf8, true),
        Field::new("src_port", DataType::UInt16, true),
        Field::new("dst_port", DataType::UInt16, true),
        Field::new("ip_protocol", DataType::UInt8, true),
        Field::new("octet_delta_count", DataType::UInt64, true),
        Field::new("packet_delta_count", DataType::UInt64, true),
        Field::new(
            "flow_start",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            true,
        ),
        Field::new(
            "flow_end",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            true,
        ),
        Field::new("tcp_flags", DataType::UInt8, true),
        Field::new("input_interface", DataType::UInt32, true),
        Field::new("output_interface", DataType::UInt32, true),
        // extra: JSON object of non-curated fields; always present (non-null)
        Field::new("extra", DataType::Utf8, false),
        Field::new(
            "partition_time",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            false,
        ),
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
    export_time: TimestampMicrosecondBuilder,
    src_addr: StringBuilder,
    dst_addr: StringBuilder,
    src_port: UInt16Builder,
    dst_port: UInt16Builder,
    ip_protocol: UInt8Builder,
    octet_delta_count: UInt64Builder,
    packet_delta_count: UInt64Builder,
    flow_start: TimestampMicrosecondBuilder,
    flow_end: TimestampMicrosecondBuilder,
    tcp_flags: UInt8Builder,
    input_interface: UInt32Builder,
    output_interface: UInt32Builder,
    extra: StringBuilder,
    partition_time: TimestampMicrosecondBuilder,
    row_count: usize,
}

impl FlowRecordBuilders {
    pub fn new() -> Self {
        Self {
            observation_domain_id: UInt32Builder::new(),
            template_id: UInt16Builder::new(),
            protocol_version: UInt8Builder::new(),
            exporter: StringBuilder::new(),
            export_time: TimestampMicrosecondBuilder::new().with_data_type(DataType::Timestamp(
                TimeUnit::Microsecond,
                Some("UTC".into()),
            )),
            src_addr: StringBuilder::new(),
            dst_addr: StringBuilder::new(),
            src_port: UInt16Builder::new(),
            dst_port: UInt16Builder::new(),
            ip_protocol: UInt8Builder::new(),
            octet_delta_count: UInt64Builder::new(),
            packet_delta_count: UInt64Builder::new(),
            flow_start: TimestampMicrosecondBuilder::new().with_data_type(DataType::Timestamp(
                TimeUnit::Microsecond,
                Some("UTC".into()),
            )),
            flow_end: TimestampMicrosecondBuilder::new().with_data_type(DataType::Timestamp(
                TimeUnit::Microsecond,
                Some("UTC".into()),
            )),
            tcp_flags: UInt8Builder::new(),
            input_interface: UInt32Builder::new(),
            output_interface: UInt32Builder::new(),
            extra: StringBuilder::new(),
            partition_time: TimestampMicrosecondBuilder::new().with_data_type(DataType::Timestamp(
                TimeUnit::Microsecond,
                Some("UTC".into()),
            )),
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
///
/// `received_at` is the receipt instant `partition_time` is clamped
/// against -- see the doc comment on `IpfixSink::to_record_batch` for why
/// it is a caller-supplied parameter here rather than `record.export_time`
/// itself.
pub fn append_flow_record(
    builders: &mut FlowRecordBuilders,
    record: &FlowRecord,
    received_at: DateTime<Utc>,
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
        .append_value(record.export_time.timestamp_micros());

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
        .append_option(record.flow_start.map(|t| t.timestamp_micros()));
    builders
        .flow_end
        .append_option(record.flow_end.map(|t| t.timestamp_micros()));
    builders.tcp_flags.append_option(record.tcp_flags);
    builders
        .input_interface
        .append_option(record.input_interface);
    builders
        .output_interface
        .append_option(record.output_interface);

    let extra_str = serde_json::to_string(&record.extra).unwrap_or_else(|_| "{}".to_string());
    builders.extra.append_value(extra_str);

    // `record.export_time` is the untrusted event instant (read verbatim
    // off the wire, see `decoder.rs`); `received_at` is the one clock
    // read `to_record_batch` bound for this whole batch. Passing them as
    // two DISTINCT values here (rather than `export_time` for both, which
    // made the clamp in `partition_time` tautologically true for every
    // input) is what makes the untrusted-day-fan-out clamp actually bind.
    let partition_time =
        crate::forwarding::buffered_writer::partition_time(Some(record.export_time), received_at);
    builders
        .partition_time
        .append_value(partition_time.timestamp_micros());

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
        Arc::new(builders.partition_time.finish()) as ArrayRef,
    ];
    Ok(RecordBatch::try_new(schema, columns)?)
}

// ---------------------------------------------------------------------------
// FlowRecordAccumulator — amortized-builder fast path
// ---------------------------------------------------------------------------

/// Amortized builder state for IPFIX flow records. Holds one persistent
/// `FlowRecordBuilders` set, reused across many pushes via `finish(&mut
/// self)` instead of reallocated per push. Mirrors `zeek::schema::ConnAccumulator`
/// / `suricata::schema::EnvelopeAccumulator`, but its `Record` is
/// `Vec<FlowRecord>` (one push per UDP datagram, already batched at the
/// listener) rather than one row per record -- `try_append` therefore loops
/// over the `Vec` and increments the row counter once per flow, not once per
/// call.
pub(crate) struct FlowRecordAccumulator {
    builders: FlowRecordBuilders,
}

impl FlowRecordAccumulator {
    pub(crate) fn new() -> Self {
        Self {
            builders: FlowRecordBuilders::new(),
        }
    }
}

impl crate::forwarding::buffered_writer::RecordBatchAccumulator<Vec<FlowRecord>>
    for FlowRecordAccumulator
{
    /// IPFIX has exactly one schema (`flow_record_schema()`), unlike Zeek's
    /// per-log-path registry, so there is no per-record mismatch case to
    /// fall back from: every flow in every `Vec<FlowRecord>` belongs to this
    /// accumulator. `now` is the one clock read `push()` bound for this
    /// whole call (see `IpfixSink::to_record_batch`'s doc comment for why it
    /// must not be read again here) and is threaded straight into
    /// `append_flow_record` as `received_at` for every flow in the batch.
    fn try_append(&mut self, record: &Vec<FlowRecord>, now: DateTime<Utc>) -> anyhow::Result<bool> {
        for flow in record {
            append_flow_record(&mut self.builders, flow, now)?;
        }
        Ok(true)
    }

    fn len(&self) -> usize {
        self.builders.row_count
    }

    fn finish(&mut self) -> anyhow::Result<RecordBatch> {
        // finish_batch consumes FlowRecordBuilders by value, so swap in a
        // fresh, empty set -- this is what makes finish() reusable rather
        // than one-shot: a builder that instead kept accumulating into the
        // same finished set would silently duplicate rows on the next call.
        let builders = std::mem::take(&mut self.builders);
        finish_batch(builders, flow_record_schema())
    }
}

// ---------------------------------------------------------------------------
// IpfixSink — ParquetSink adapter
// ---------------------------------------------------------------------------

/// `ParquetSink` adapter for IPFIX flow records.
/// The `Record` type is `Vec<FlowRecord>` to match the existing
/// `IpfixHandler::handle_flows` batch API.
#[derive(Default)]
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

    /// Event time column for day bucketing. `partition_time` is derived from
    /// IPFIX `export_time`, the absolute flow export time from the exporter
    /// (non-null), representing when the flow ended and was exported, which
    /// is more accurate for partitioning.
    fn time_column(&self) -> Option<&'static str> {
        Some("partition_time")
    }

    /// `FlowRecord` carries no logthing-stamped receipt instant -- unlike
    /// every other sink in this file tree, IPFIX has nothing trustworthy to
    /// use as `received_at` except `export_time` itself, and `export_time`
    /// is read verbatim off unauthenticated, source-spoofable UDP (see
    /// `decoder.rs`). Passing it as BOTH the event and the receipt instant
    /// to `partition_time` would make its untrusted-day-fan-out clamp
    /// `t >= t - MAX_BACKFILL && t <= t + MAX_SKEW` trivially true for
    /// every input -- a spoofed `export_time` sweeping the u32 wire range
    /// could then mint one live day-buffer per distinct claimed date
    /// (~49,710 of them), each eventually its own single-row Parquet PUT.
    ///
    /// So a batch of `FlowRecord`s must be mapped against exactly ONE bound
    /// `Utc::now()`, threaded through `append_flow_record` as `received_at`
    /// for every flow in the batch -- unlike the other eight sinks' mappers,
    /// which are pure and clock-free. This is safe for the same reason
    /// syslog's single `Utc::now()` read is (see `syslog_message_to_batch`):
    /// the one bound value is written into the `partition_time` column of
    /// the SAME batch whose buffer-key day is derived from that same value
    /// (see `day_and_batch` below), so the buffer key and the persisted
    /// column can never disagree, even though the value itself is a
    /// wall-clock read. Do NOT "fix" this back to `export_time` for both
    /// arguments -- that reinstates the inert clamp above.
    ///
    /// In the production `push()` path this method is never actually
    /// called: `new_batch` below always matches (IPFIX has one schema), so
    /// every record goes through `FlowRecordAccumulator`, fed the single
    /// `now` `push()` already read and passed via `day_and_batch`. This
    /// implementation exists as the direct-call path (`ParquetSink`'s own
    /// tests, and any caller that invokes `to_record_batch` outside the
    /// writer) and binds its own `Utc::now()` for that path only, via the
    /// same accumulator so the row-mapping logic exists in exactly one
    /// place.
    fn to_record_batch(
        &self,
        records: &Vec<FlowRecord>,
        _schema: &Arc<arrow_schema::Schema>,
    ) -> anyhow::Result<arrow_array::RecordBatch> {
        let mut acc = FlowRecordAccumulator::new();
        acc.try_append(records, chrono::Utc::now())?;
        acc.finish()
    }

    /// Amortized-builder fast path: IPFIX has exactly one schema
    /// (`flow_record_schema()`), so this always matches -- gated on
    /// `Arc::ptr_eq` rather than unconditionally returning `Some` purely
    /// defensively, mirroring `ZeekSink::new_batch` / `SuricataSink::new_batch`.
    fn new_batch(
        &self,
        schema: &Arc<arrow_schema::Schema>,
    ) -> Option<Box<dyn crate::forwarding::buffered_writer::RecordBatchAccumulator<Vec<FlowRecord>>>>
    {
        if Arc::ptr_eq(schema, &flow_record_schema()) {
            Some(Box::new(FlowRecordAccumulator::new()))
        } else {
            None
        }
    }

    /// Overrides the default `day_and_batch`: derives the day directly from
    /// the FIRST flow in the `Vec`, without building a batch. Load-bearing
    /// for the same reason as `ZeekSink`'s / `SuricataSink`'s overrides --
    /// `push()` calls this before it knows whether the record goes to the
    /// amortized live builder, so building a batch here just to learn the
    /// day would make every push pay for a throwaway `RecordBatch` (the
    /// full 19-builder `FlowRecordBuilders` set), defeating the entire point
    /// of `FlowRecordAccumulator`.
    ///
    /// Must match today's (default `day_and_batch` + `day_from_batch`)
    /// behaviour exactly: `day_from_batch` reads `ts.value(0)` -- row 0 only
    /// -- of the materialized batch's `partition_time` column. Row 0 always
    /// corresponds to `records[0]` (`append_flow_record` appends in order),
    /// so replicating `partition_time(Some(records[0].export_time), now)`
    /// here picks the identical day without needing the batch at all. A
    /// datagram with multiple flows spanning midnight keys on its first
    /// flow today and must continue to -- do not average, sort, or use the
    /// last flow instead.
    ///
    /// `now` here IS the same single per-push clock read `to_record_batch`
    /// binds independently in its own fallback path -- unlike Zeek/Suricata,
    /// IPFIX has no per-record receipt instant to fall back to, so this
    /// method actually uses its `now` argument instead of ignoring it.
    fn day_and_batch(
        &self,
        records: &Vec<FlowRecord>,
        _schema: &Arc<arrow_schema::Schema>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<(chrono::NaiveDate, Option<arrow_array::RecordBatch>)> {
        let day = match records.first() {
            Some(first) => {
                crate::forwarding::buffered_writer::partition_time(Some(first.export_time), now)
                    .date_naive()
            }
            None => now.date_naive(),
        };
        Ok((day, None))
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
            Err(e) => {
                // parquet_s3_dropped{source="ipfix"} is already incremented by try_send;
                // just warn here.
                if let Some(dropped_total) = self.drop_log_due(DropSite::Ipfix, DropKind::from(&e))
                {
                    tracing::warn!(
                        dropped_total,
                        "IPFIX S3 channel full; dropped {} flows from {}",
                        count,
                        source
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MultiIpfixHandler — fan-out to multiple destinations
// ---------------------------------------------------------------------------

/// Fans out each flow batch to every configured handler. Used only when both
/// `.s3` and `.local` persistence resolve to a live handler for the same
/// run, so each destination keeps its own independent buffer, flush policy,
/// backpressure, and hard cap (no shared state between destinations).
pub struct MultiIpfixHandler(pub Vec<std::sync::Arc<dyn crate::ipfix::listener::IpfixHandler>>);

#[async_trait::async_trait]
impl crate::ipfix::listener::IpfixHandler for MultiIpfixHandler {
    async fn handle_flows(&self, flows: Vec<FlowRecord>, source: std::net::SocketAddr) {
        for handler in &self.0 {
            handler.handle_flows(flows.clone(), source).await;
        }
    }
}

// ---------------------------------------------------------------------------
// ipfix_start / ipfix_local_start — convenience constructors
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
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<std::sync::Arc<dyn crate::forwarding::buffered_writer::UploadSink>>,
) -> (IpfixS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<IpfixSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        1, // IPFIX is single-partition
        s3,
        source_stats,
        descriptor_sink,
    )
}

/// Construct an `IpfixS3Handler` from an `IpfixLocalConfig` and a pre-built
/// `LocalDiskSink`. Structurally identical to `ipfix_start`, writing to local
/// disk instead of S3 — same `IpfixSink` adapter, same buffering/flush/cap
/// machinery, same S3-key-shaped relative path layout on disk.
pub fn ipfix_local_start(
    cfg: &crate::config::IpfixLocalConfig,
    sink: std::sync::Arc<crate::forwarding::local_sink::LocalDiskSink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<std::sync::Arc<dyn crate::forwarding::buffered_writer::UploadSink>>,
) -> (IpfixS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<IpfixSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        1, // IPFIX is single-partition
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
        assert_eq!(schema.fields().len(), 19, "expected 19 columns");

        use arrow::datatypes::TimeUnit;
        let ts_type = DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()));
        let cases: &[(&str, DataType, bool)] = &[
            ("observation_domain_id", DataType::UInt32, false),
            ("template_id", DataType::UInt16, false),
            ("protocol_version", DataType::UInt8, false),
            ("exporter", DataType::Utf8, false),
            ("export_time", ts_type.clone(), false),
            ("src_addr", DataType::Utf8, true),
            ("dst_addr", DataType::Utf8, true),
            ("src_port", DataType::UInt16, true),
            ("dst_port", DataType::UInt16, true),
            ("ip_protocol", DataType::UInt8, true),
            ("octet_delta_count", DataType::UInt64, true),
            ("packet_delta_count", DataType::UInt64, true),
            ("flow_start", ts_type.clone(), true),
            ("flow_end", ts_type.clone(), true),
            ("tcp_flags", DataType::UInt8, true),
            ("input_interface", DataType::UInt32, true),
            ("output_interface", DataType::UInt32, true),
            ("extra", DataType::Utf8, false),
            ("partition_time", ts_type.clone(), false),
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
        append_flow_record(&mut builders, &r0, r0.export_time).unwrap();
        append_flow_record(&mut builders, &r1, r1.export_time).unwrap();

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
    fn export_time_flow_start_flow_end_produce_exact_microseconds_and_nulls() {
        use arrow::array::TimestampMicrosecondArray;

        let mut r0 = make_flow_record(Some("10.0.0.1"), Some(1), serde_json::json!({}));
        r0.flow_start = Some(
            chrono::Utc
                .with_ymd_and_hms(2026, 1, 15, 11, 59, 0)
                .unwrap(),
        );
        r0.flow_end = Some(
            chrono::Utc
                .with_ymd_and_hms(2026, 1, 15, 12, 0, 30)
                .unwrap(),
        );
        let r1 = make_flow_record(None, None, serde_json::json!({})); // flow_start/flow_end: None

        let mut builders = FlowRecordBuilders::new();
        append_flow_record(&mut builders, &r0, r0.export_time).unwrap();
        append_flow_record(&mut builders, &r1, r1.export_time).unwrap();
        let batch = finish_batch(builders, flow_record_schema()).unwrap();

        let export_time_col = batch
            .column_by_name("export_time")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .expect("export_time column should be TimestampMicrosecondArray");
        assert_eq!(export_time_col.value(0), r0.export_time.timestamp_micros());

        let flow_start_col = batch
            .column_by_name("flow_start")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .expect("flow_start column should be TimestampMicrosecondArray");
        assert_eq!(
            flow_start_col.value(0),
            r0.flow_start.unwrap().timestamp_micros()
        );
        assert!(
            flow_start_col.is_null(1),
            "row 1 flow_start (None) must be a real NULL, not an epoch value"
        );

        let flow_end_col = batch
            .column_by_name("flow_end")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .expect("flow_end column should be TimestampMicrosecondArray");
        assert_eq!(
            flow_end_col.value(0),
            r0.flow_end.unwrap().timestamp_micros()
        );
        assert!(
            flow_end_col.is_null(1),
            "row 1 flow_end (None) must be a real NULL, not an epoch value"
        );
    }

    #[test]
    fn extra_json_round_trips() {
        let original = serde_json::json!({"ie300": "0xabcd", "nested": {"k": 1}});
        let r = make_flow_record(Some("10.1.2.3"), Some(42), original.clone());
        let mut builders = FlowRecordBuilders::new();
        append_flow_record(&mut builders, &r, r.export_time).unwrap();
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

    #[test]
    fn schema_partition_time_is_non_null_microsecond_timestamp() {
        use arrow::datatypes::TimeUnit;
        let schema = flow_record_schema();
        let f = schema
            .field_with_name("partition_time")
            .expect("partition_time column missing");
        assert_eq!(
            f.data_type(),
            &DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
        );
        assert!(!f.is_nullable(), "partition_time must be non-nullable");
    }

    #[test]
    fn partition_time_equals_export_time_when_within_clamp_of_received_at() {
        use arrow::array::TimestampMicrosecondArray;

        // A fixed, arbitrary receipt instant, deliberately NOT derived from
        // either record's export_time -- so this test cannot degenerate
        // into the tautological "event == received_at" check the old
        // version of this test performed (every `append_flow_record` call
        // used to pass `record.export_time` for both arguments).
        let received_at = chrono::Utc.with_ymd_and_hms(2026, 4, 10, 0, 0, 0).unwrap();

        // Two records with distinct, distinctive export_time values inside
        // `[received_at - MAX_BACKFILL, received_at + MAX_SKEW]`, so a
        // mapper that fell back to a shared/constant/epoch/received_at
        // value would visibly fail this.
        let mut r0 = make_flow_record(Some("10.0.0.1"), Some(1), serde_json::json!({}));
        r0.export_time = chrono::Utc.with_ymd_and_hms(2026, 4, 2, 9, 17, 5).unwrap(); // 8 days back
        let mut r1 = make_flow_record(None, None, serde_json::json!({}));
        r1.export_time = chrono::Utc.with_ymd_and_hms(2026, 4, 10, 18, 0, 0).unwrap(); // hours forward

        let mut builders = FlowRecordBuilders::new();
        append_flow_record(&mut builders, &r0, received_at).unwrap();
        append_flow_record(&mut builders, &r1, received_at).unwrap();
        let batch = finish_batch(builders, flow_record_schema()).unwrap();

        let partition_time_col = batch
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .expect("partition_time column should be TimestampMicrosecondArray");
        assert_eq!(
            partition_time_col.value(0),
            r0.export_time.timestamp_micros()
        );
        assert_eq!(
            partition_time_col.value(1),
            r1.export_time.timestamp_micros()
        );
    }

    #[test]
    fn ipfix_sink_buckets_spoofed_far_future_and_far_past_export_time_by_receipt_day() {
        // Regression test for the finding that IPFIX's `partition_time`
        // clamp used to be inert: `to_record_batch` passed
        // `record.export_time` as BOTH the event and the `received_at`
        // argument to `partition_time`, making the untrusted-day-fan-out
        // guard `t >= t - MAX_BACKFILL && t <= t + MAX_SKEW` trivially true
        // for every input. `export_time` is read verbatim off
        // unauthenticated, source-spoofable UDP, so an exporter sweeping it
        // across the u32 wire range could mint one live day-buffer per
        // claimed date. `to_record_batch` now binds a real `Utc::now()` as
        // `received_at`, so a spoofed export_time decades in the future OR
        // decades in the past must each bucket by the real receipt day
        // instead.
        use arrow::array::TimestampMicrosecondArray;

        let far_future = chrono::Utc.with_ymd_and_hms(2090, 3, 1, 0, 0, 0).unwrap();
        let far_past = chrono::Utc.with_ymd_and_hms(1975, 6, 1, 0, 0, 0).unwrap();

        let mut r_future = make_flow_record(Some("10.0.0.1"), Some(1), serde_json::json!({}));
        r_future.export_time = far_future;
        let mut r_past = make_flow_record(None, None, serde_json::json!({}));
        r_past.export_time = far_past;

        let sink = IpfixSink;
        let schema = sink.schema(None);
        let before = chrono::Utc::now();
        let batch = sink
            .to_record_batch(&vec![r_future, r_past], &schema)
            .unwrap();
        let after = chrono::Utc::now();

        let partition_time_col = batch
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .expect("partition_time column should be TimestampMicrosecondArray");

        for (i, spoofed) in [far_future, far_past].into_iter().enumerate() {
            let value =
                chrono::DateTime::<chrono::Utc>::from_timestamp_micros(partition_time_col.value(i))
                    .expect("valid micros");
            assert!(
                value >= before - chrono::TimeDelta::seconds(1)
                    && value <= after + chrono::TimeDelta::seconds(1),
                "row {i} partition_time must bucket by the real receipt time, \
                 not the spoofed export_time; got {value}, expected within \
                 [{before}, {after}]"
            );
            assert_ne!(
                value.date_naive(),
                spoofed.date_naive(),
                "row {i} partition_time must not land on the spoofed export_time's day"
            );
        }
    }

    // -- IpfixSink unit tests (Task 2.1) --

    #[test]
    fn ipfix_sink_to_record_batch_produces_correct_schema_and_rows() {
        use crate::forwarding::buffered_writer::ParquetSink;
        let sink = IpfixSink;
        let schema = sink.schema(None);
        assert_eq!(schema.fields().len(), 19);
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

    #[test]
    fn ipfix_sink_time_column_export_time_exists_in_schema() {
        let sink = IpfixSink;
        let col = sink
            .time_column()
            .expect("ipfix_sink must opt in to day partitioning");
        // Pin the exact column name, not just that SOME name resolves.
        assert_eq!(col, "partition_time");
        let schema = sink.schema(None);
        assert!(
            schema.field_with_name(col).is_ok(),
            "time_column() returned {:?}, which is not a field in the schema",
            col
        );
    }

    // -- FlowRecordAccumulator unit tests --

    #[test]
    fn flow_record_accumulator_appends_exact_row_count_for_ten_flows() {
        let records: Vec<FlowRecord> = (0..10)
            .map(|i| make_flow_record(Some("10.0.0.1"), Some(i as u64), serde_json::json!({})))
            .collect();

        let mut acc = FlowRecordAccumulator::new();
        assert_eq!(acc.len(), 0);
        assert!(acc.try_append(&records, Utc::now()).unwrap());
        assert_eq!(acc.len(), 10, "10 flows in one push must add exactly 10 rows");

        let batch = acc.finish().unwrap();
        assert_eq!(batch.num_rows(), 10);
        assert_eq!(acc.len(), 0, "finish must reset the row count");
    }

    #[test]
    fn flow_record_accumulator_single_flow_and_empty_vec() {
        let mut acc = FlowRecordAccumulator::new();

        // N=0: an empty datagram must add 0 rows, not silently count as 1.
        assert!(acc.try_append(&vec![], Utc::now()).unwrap());
        assert_eq!(acc.len(), 0, "an empty Vec<FlowRecord> must add 0 rows");

        // N=1.
        let r = make_flow_record(Some("10.0.0.1"), Some(1), serde_json::json!({}));
        assert!(acc.try_append(&vec![r], Utc::now()).unwrap());
        assert_eq!(acc.len(), 1, "a single-flow push must add exactly 1 row");
    }

    #[test]
    fn flow_record_accumulator_finish_twice_produces_independent_batches() {
        let mut acc = FlowRecordAccumulator::new();

        let r_a = make_flow_record(Some("10.0.0.1"), Some(1), serde_json::json!({}));
        acc.try_append(&vec![r_a], Utc::now()).unwrap();
        let batch_a = acc.finish().unwrap();
        assert_eq!(
            batch_a.num_rows(),
            1,
            "first finish must contain exactly the rows appended before it"
        );

        let r_b = make_flow_record(Some("10.0.0.2"), Some(2), serde_json::json!({}));
        let r_c = make_flow_record(Some("10.0.0.3"), Some(3), serde_json::json!({}));
        acc.try_append(&vec![r_b, r_c], Utc::now()).unwrap();
        let batch_b = acc.finish().unwrap();
        assert_eq!(
            batch_b.num_rows(),
            2,
            "second finish must contain exactly the rows appended since the first finish -- \
             a builder that retained prior rows would produce 3 here, silently duplicating data"
        );
    }

    #[test]
    fn flow_record_accumulator_matches_append_flow_record_output_row_for_row() {
        // Baseline: today's exact per-record path, N single-record calls
        // into the same builders, concatenated -- i.e. exactly what
        // `to_record_batch` used to do inline before routing through the
        // accumulator.
        let now = Utc.with_ymd_and_hms(2026, 4, 2, 8, 0, 0).unwrap();
        let mut r0 = make_flow_record(
            Some("10.0.0.1"),
            Some(1234),
            serde_json::json!({"ie200": "0xdeadbeef", "nested": {"k": 1}}),
        );
        r0.flow_start = Some(Utc.with_ymd_and_hms(2026, 4, 2, 7, 59, 0).unwrap());
        r0.flow_end = Some(Utc.with_ymd_and_hms(2026, 4, 2, 8, 0, 30).unwrap());
        let r1 = make_flow_record(None, None, serde_json::json!({})); // nullable fields all absent
        let records = vec![r0, r1];

        let mut expected_builders = FlowRecordBuilders::new();
        for r in &records {
            append_flow_record(&mut expected_builders, r, now).unwrap();
        }
        let expected = finish_batch(expected_builders, flow_record_schema()).unwrap();

        // Accumulator path: one accumulator, one multi-flow append, one finish.
        let mut acc = FlowRecordAccumulator::new();
        acc.try_append(&records, now).unwrap();
        let actual = acc.finish().unwrap();

        assert_eq!(actual.num_rows(), expected.num_rows());
        assert_eq!(actual.schema(), expected.schema());
        for col_idx in 0..expected.num_columns() {
            assert_eq!(
                format!("{:?}", actual.column(col_idx)),
                format!("{:?}", expected.column(col_idx)),
                "column {col_idx} differs between the accumulator and per-record paths"
            );
        }
    }

    #[test]
    fn ipfix_sink_new_batch_gates_on_schema_ptr_eq() {
        let sink = IpfixSink;
        assert!(
            sink.new_batch(&flow_record_schema()).is_some(),
            "new_batch must activate for the real flow_record_schema()"
        );

        let other_schema = Arc::new(Schema::new(Vec::<Field>::new()));
        assert!(
            sink.new_batch(&other_schema).is_none(),
            "new_batch must not activate for a schema that isn't flow_record_schema()"
        );
    }

    // -- IpfixSink::day_and_batch unit tests --

    #[test]
    fn day_and_batch_matches_default_day_from_batch_mechanism() {
        // The default `ParquetSink::day_and_batch` would build a batch and
        // read `ts.value(0)` off its `partition_time` column (row 0 only).
        // `IpfixSink::day_and_batch` must derive the identical day without
        // building that batch. Prove parity by building the row-0 reference
        // batch directly via the accumulator (same mechanism, same `now`)
        // and comparing days.
        let now = Utc.with_ymd_and_hms(2026, 6, 15, 3, 0, 0).unwrap();
        let mut r0 = make_flow_record(Some("10.0.0.1"), Some(1), serde_json::json!({}));
        r0.export_time = Utc.with_ymd_and_hms(2026, 6, 14, 23, 0, 0).unwrap(); // previous day, within clamp
        let r1 = make_flow_record(None, None, serde_json::json!({}));
        let records = vec![r0, r1];

        let mut acc = FlowRecordAccumulator::new();
        acc.try_append(&records, now).unwrap();
        let batch = acc.finish().unwrap();
        let partition_time_col = batch
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<arrow::array::TimestampMicrosecondArray>()
            .unwrap();
        let expected_day =
            DateTime::from_timestamp_micros(partition_time_col.value(0))
                .unwrap()
                .date_naive();

        let sink = IpfixSink;
        let schema = sink.schema(None);
        let (day, pre_mapped) = sink.day_and_batch(&records, &schema, now).unwrap();
        assert!(
            pre_mapped.is_none(),
            "day_and_batch must not build a batch just to compute the day"
        );
        assert_eq!(day, expected_day);
    }

    #[test]
    fn day_and_batch_empty_vec_uses_now() {
        let now = Utc.with_ymd_and_hms(2030, 12, 25, 0, 0, 0).unwrap();
        let sink = IpfixSink;
        let schema = sink.schema(None);
        let (day, pre_mapped) = sink.day_and_batch(&vec![], &schema, now).unwrap();
        assert!(pre_mapped.is_none());
        assert_eq!(day, now.date_naive());
    }

    /// Day-key regression test guarding the security invariant: a
    /// multi-flow datagram whose FIRST flow has a spoofed `export_time` --
    /// once far in the future, once far in the past -- must bucket by the
    /// day `partition_time`'s clamp produces (the real receipt day), never
    /// by the spoofed claimed date. If `day_and_batch` ever read its own
    /// clock instead of the `now` threaded in from `push()`, or if
    /// `try_append` ever stamped a different `now` into the persisted
    /// column than `day_and_batch` used to pick the buffer, this test would
    /// only fail once in a blue moon (both reads are "now" microseconds
    /// apart) -- the case that reliably catches a broken clamp is the
    /// spoofed-date assertions below, not a hypothetical clock race.
    #[test]
    fn day_and_batch_rejects_spoofed_first_flow_export_time_far_future_and_far_past() {
        let now = Utc.with_ymd_and_hms(2026, 6, 15, 12, 0, 0).unwrap();
        let far_future = Utc.with_ymd_and_hms(2090, 3, 1, 0, 0, 0).unwrap();
        let far_past = Utc.with_ymd_and_hms(1975, 6, 1, 0, 0, 0).unwrap();

        for spoofed in [far_future, far_past] {
            let mut r0 = make_flow_record(Some("10.0.0.1"), Some(1), serde_json::json!({}));
            r0.export_time = spoofed;
            let r1 = make_flow_record(None, None, serde_json::json!({}));
            let records = vec![r0, r1];

            let sink = IpfixSink;
            let schema = sink.schema(None);
            let (day, _) = sink.day_and_batch(&records, &schema, now).unwrap();

            assert_eq!(
                day,
                now.date_naive(),
                "a spoofed first-flow export_time must bucket by the receipt day, not the claimed date"
            );
            assert_ne!(
                day,
                spoofed.date_naive(),
                "the buffer-key day must never equal the spoofed export_time's day"
            );
        }
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
            interval: crate::forwarding::buffered_writer::LiveInterval::new(
                std::time::Duration::from_secs(3600),
            ),
        };

        let mut writer = PartitionedParquetWriter::new(IpfixSink, sink_s3, bwc, policy);

        let total_pushes = hard_cap * 3;
        for _ in 0..total_pushes {
            let record = make_flow_record(None, None, serde_json::json!({}));
            writer.push(vec![record]).await.unwrap();
            writer.drain_pending_flushes().await;
        }

        let buf = writer.buffer_by_partition("").unwrap();
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
        let (handler, _writer_handle) = ipfix_start(
            &cfg,
            sink,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );

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
                vec![
                    metrics::Label::new("source", "ipfix"),
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
            let (handler, _writer_handle) = ipfix_start(
                &cfg,
                sink,
                std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
                None,
            );
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
                    vec![
                        metrics::Label::new("source", "ipfix"),
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
            let (handler, _writer_handle) = ipfix_start(
                &cfg,
                sink,
                std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
                None,
            );
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
                    vec![
                        metrics::Label::new("source", "ipfix"),
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
        let (handler, _writer_handle) = ipfix_start(
            &s3_cfg,
            sink,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );
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

    #[tokio::test]
    async fn ipfix_sink_reports_into_shared_source_hourly_stats() {
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
            prefix: "ipfix".to_string(),
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
            IpfixSink,
            s3,
            bwc,
            policy,
            shared_stats.clone(),
            None,
        );
        writer
            .push(vec![make_flow_record(None, None, serde_json::json!({}))])
            .await
            .unwrap();

        let snapshot = shared_stats.snapshot();
        let row = snapshot.iter().find(|r| r.source == "ipfix").unwrap();
        let total: u64 = row.hours.iter().map(|h| h.count).sum();
        assert_eq!(total, 1);
    }

    // -- ipfix_local_start wires handler and join handle --

    #[tokio::test]
    async fn ipfix_local_start_wires_handler_and_join_handle() {
        use crate::config::IpfixLocalConfig;
        use crate::forwarding::local_sink::LocalDiskSink;
        use crate::ipfix::listener::IpfixHandler;
        use std::net::SocketAddr;

        let dir = tempfile::tempdir().unwrap();
        let sink = Arc::new(
            LocalDiskSink::new(dir.path().to_path_buf())
                .await
                .expect("LocalDiskSink::new"),
        );
        let cfg = IpfixLocalConfig {
            directory: dir.path().to_path_buf(),
            prefix: "ipfix".to_string(),
            flush_threshold_bytes: 1, // flush on first push
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_buffer_rows: 100_000,
        };
        let (handler, join_handle) = ipfix_local_start(
            &cfg,
            sink,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );

        let src: SocketAddr = "127.0.0.1:4739".parse().unwrap();
        handler
            .handle_flows(
                vec![make_flow_record(
                    Some("10.0.0.1"),
                    Some(42),
                    serde_json::json!({}),
                )],
                src,
            )
            .await;

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        drop(handler);
        tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("writer task must exit within 5s")
            .expect("writer task must not panic");

        let ipfix_dir = dir.path().join("ipfix");
        let mut found = false;
        for entry in walkdir_flat(&ipfix_dir) {
            if entry.extension().is_some_and(|e| e == "parquet") {
                found = true;
                break;
            }
        }
        assert!(
            found,
            "expected at least one Parquet file under {ipfix_dir:?}"
        );
    }

    /// Minimal recursive walk — IPFIX's key layout nests under year=/month=/day=/,
    /// so a flat `read_dir` on the prefix directory won't find the file directly.
    fn walkdir_flat(root: &std::path::Path) -> Vec<std::path::PathBuf> {
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

    /// Day-key regression test guarding the security invariant, driven
    /// through the REAL writer path (`ipfix_local_start` -> `push()` ->
    /// on-disk Parquet), not just a direct `day_and_batch` call. The S3/local
    /// key layout embeds the buffer's day key as `year=Y/month=M/day=D` (see
    /// `build_key`); this test extracts that day from the on-disk path and
    /// compares it against the day of the `partition_time` value actually
    /// written into row 0 of the file's own contents. A regression that
    /// reintroduces the second clock read (`day_and_batch` computing its own
    /// `Utc::now()` instead of using the one `push()` passed in) would make
    /// the two disagree once in a while near midnight; a regression that
    /// reinstates the inert clamp (passing `export_time` as both arguments
    /// to `partition_time`) would instead make the spoofed date show up
    /// directly in the directory path -- both are asserted against below.
    #[tokio::test]
    async fn day_key_regression_spoofed_export_time_lands_on_receipt_day_not_claimed_date() {
        use crate::config::IpfixLocalConfig;
        use crate::forwarding::local_sink::LocalDiskSink;
        use crate::ipfix::listener::IpfixHandler;
        use arrow::array::TimestampMicrosecondArray;

        let dir = tempfile::tempdir().expect("tempdir");
        let sink = Arc::new(
            LocalDiskSink::new(dir.path().to_path_buf())
                .await
                .expect("LocalDiskSink::new"),
        );
        let cfg = IpfixLocalConfig {
            directory: dir.path().to_path_buf(),
            prefix: "ipfix".to_string(),
            max_buffer_rows: 100,
            flush_threshold_bytes: usize::MAX, // only the shutdown flush fires
            flush_interval_secs: 3600,
            channel_capacity: 64,
        };
        let (handler, writer_task) = ipfix_local_start(
            &cfg,
            sink,
            Arc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );

        let far_future = Utc.with_ymd_and_hms(2090, 3, 1, 0, 0, 0).unwrap();
        let far_past = Utc.with_ymd_and_hms(1975, 6, 1, 0, 0, 0).unwrap();

        // First flow in the datagram carries the spoofed export_time --
        // day_and_batch keys the whole push on row 0.
        let mut r_future = make_flow_record(Some("10.0.0.1"), Some(1), serde_json::json!({}));
        r_future.export_time = far_future;
        let mut r_past = make_flow_record(None, None, serde_json::json!({}));
        r_past.export_time = far_past;

        let before = Utc::now();
        let src: std::net::SocketAddr = "127.0.0.1:4739".parse().unwrap();
        handler.handle_flows(vec![r_future], src).await;
        handler.handle_flows(vec![r_past], src).await;
        let after = Utc::now();

        drop(handler);
        tokio::time::timeout(std::time::Duration::from_secs(5), writer_task)
            .await
            .expect("writer task must exit within 5s")
            .expect("writer task must not panic");

        let ipfix_dir = dir.path().join("ipfix");
        let parquet_files: Vec<_> = walkdir_flat(&ipfix_dir)
            .into_iter()
            .filter(|p| p.extension().is_some_and(|e| e == "parquet"))
            .collect();
        assert_eq!(
            parquet_files.len(),
            1,
            "both spoofed dates must collapse onto the SAME receipt-day buffer, \
             not mint one file per claimed date; found {parquet_files:?}"
        );

        let path_str = parquet_files[0].to_string_lossy().to_string();
        let key_day = day_from_key_path(&path_str)
            .unwrap_or_else(|| panic!("could not parse year=/month=/day= from {path_str}"));

        let bytes = std::fs::read(&parquet_files[0]).expect("read parquet file");
        let builder =
            parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(
                bytes::Bytes::from(bytes),
            )
            .expect("parquet builder");
        let mut reader = builder.build().expect("parquet reader");
        let rb = reader.next().expect("at least one batch").expect("batch ok");
        let partition_time_col = rb
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        let row0_day = DateTime::from_timestamp_micros(partition_time_col.value(0))
            .unwrap()
            .date_naive();

        assert_eq!(
            key_day, row0_day,
            "the buffer-key day (from the on-disk path) must equal the day of the \
             partition_time value actually written into row 0"
        );
        assert_ne!(key_day, far_future.date_naive());
        assert_ne!(key_day, far_past.date_naive());
        assert!(
            key_day >= before.date_naive() && key_day <= after.date_naive(),
            "the buffer-key day must be the real receipt day ({before}..{after}), got {key_day}"
        );
    }

    /// Parse the `year=YYYY/month=MM/day=DD` segments out of an on-disk (or
    /// S3) key path built by `build_key`.
    fn day_from_key_path(path: &str) -> Option<chrono::NaiveDate> {
        let mut year = None;
        let mut month = None;
        let mut day = None;
        for seg in path.split(['/', '\\']) {
            if let Some(v) = seg.strip_prefix("year=") {
                year = v.parse::<i32>().ok();
            } else if let Some(v) = seg.strip_prefix("month=") {
                month = v.parse::<u32>().ok();
            } else if let Some(v) = seg.strip_prefix("day=") {
                day = v.parse::<u32>().ok();
            }
        }
        chrono::NaiveDate::from_ymd_opt(year?, month?, day?)
    }

    // -- MultiIpfixHandler tests --

    #[tokio::test]
    async fn multi_ipfix_handler_fans_out_to_every_inner_handler() {
        use crate::ipfix::listener::IpfixHandler;
        use std::net::SocketAddr;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingHandler(Arc<AtomicUsize>);
        #[async_trait::async_trait]
        impl IpfixHandler for CountingHandler {
            async fn handle_flows(&self, _flows: Vec<FlowRecord>, _source: SocketAddr) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let count_a = Arc::new(AtomicUsize::new(0));
        let count_b = Arc::new(AtomicUsize::new(0));
        let multi = MultiIpfixHandler(vec![
            Arc::new(CountingHandler(count_a.clone())),
            Arc::new(CountingHandler(count_b.clone())),
        ]);

        let src: SocketAddr = "127.0.0.1:4739".parse().unwrap();
        multi
            .handle_flows(
                vec![make_flow_record(
                    Some("10.0.0.1"),
                    Some(1),
                    serde_json::json!({}),
                )],
                src,
            )
            .await;

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
    async fn multi_ipfix_handler_survives_one_inner_handler_dropping() {
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
        let cfg = IpfixS3Config {
            connection: crate::config::S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "ipfix".to_string(),
            flush_threshold_bytes: 1,
            flush_interval_secs: 3600,
            channel_capacity: 1,
            max_buffer_rows: 1,
        };
        let (struggling_handler, _jh) = ipfix_start(
            &cfg,
            sink,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );

        use std::sync::atomic::{AtomicUsize, Ordering};
        struct CountingHandler(Arc<AtomicUsize>);
        #[async_trait::async_trait]
        impl IpfixHandler for CountingHandler {
            async fn handle_flows(&self, _flows: Vec<FlowRecord>, _source: SocketAddr) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let healthy_count = Arc::new(AtomicUsize::new(0));
        let multi = MultiIpfixHandler(vec![
            Arc::new(struggling_handler),
            Arc::new(CountingHandler(healthy_count.clone())),
        ]);

        let src: SocketAddr = "127.0.0.1:4739".parse().unwrap();
        for i in 0..20 {
            multi
                .handle_flows(
                    vec![make_flow_record(None, None, serde_json::json!({"i": i}))],
                    src,
                )
                .await;
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
                    metrics::Label::new("source", "ipfix"),
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
