//! OTLP log persistence: `OtlpRecord` -> typed Parquet.
//!
//! One source label (`otlp`), one fixed 21-column schema (see `otlp_schema`), one Iceberg table
//! (`otlp`, see `committer/commit.py`). The Parquet path segment is the sanitized
//! `service.name` (or `unknown`), capped at `otlp.max_service_partitions` with overflow to
//! `_overflow`, so every file holds one service and Trino can prune files via per-file
//! min/max stats on `service_name`. The `service_name` COLUMN always holds the raw value.
//!
//! HEC's config structs cannot be reused as-is because their defaults are HEC-specific
//! (`prefix = "hec"`, channel capacity derived from `GENERIC_RECORD_BYTES`), so OTLP gets
//! mirror structs (`OtlpS3Config`, `OtlpLocalConfig`) that reuse HEC's flush/row default
//! functions. `resource_attributes` keeps ALL resource attributes (promoted keys included)
//! so the column is lossless. The writer appends records through `OtlpAccumulator`
//! (`ParquetSink::new_batch`), which reuses one set of Arrow builders across many rows;
//! building a 21-column one-row batch per record capped a single writer near 13k rec/s.
//! `to_record_batch` is a thin one-row wrapper over the same accumulator.
//!
//! S3 key layout: `otlp/<service>/year={Y}/month={MM}/day={DD}/{uuid}.parquet`
//!
//! Column types are FROZEN: the committer evolves tables additively only, so a type change
//! would quarantine every new file. Add columns by APPENDING nullable ones.

use crate::config::{OtlpLocalConfig, OtlpS3Config};
use crate::forwarding::buffered_writer::{
    ParquetSink, ParquetWriterHandle, RecordBatchAccumulator, UploadSink, partition_time,
    sanitize_log_path, start_writer,
};
use crate::ingest::EventUuid;
use arrow_array::builder::{
    Int32Builder, StringBuilder, TimestampMicrosecondBuilder, UInt32Builder,
};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema, TimeUnit};
use chrono::{DateTime, NaiveDate, Utc};
use std::sync::{Arc, LazyLock};

/// Partition segment used when a record carries no usable `service.name`.
pub const UNKNOWN_SERVICE_PARTITION: &str = "unknown";

/// One OTLP log record in its persisted shape. See `otlp_schema` for column semantics.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OtlpRecord {
    /// UUIDv7 row identity; `None` until `assign_event_uuids` runs (handlers always assign).
    pub event_uuid: Option<String>,
    /// `time_unix_nano` (0 -> `None`).
    pub time: Option<DateTime<Utc>>,
    /// `observed_time_unix_nano` (0 -> `None`).
    pub observed_time: Option<DateTime<Utc>>,
    /// Wall-clock receipt time.
    pub received_at: DateTime<Utc>,
    /// OTLP `severity_number` (0/unspecified -> `None`).
    pub severity_number: Option<i32>,
    /// OTLP `severity_text` (empty -> `None`).
    pub severity_text: Option<String>,
    /// String bodies verbatim; any other AnyValue as JSON text.
    pub body: Option<String>,
    /// Resource `service.name` (string-typed, non-empty), RAW.
    pub service_name: Option<String>,
    /// Resource `service.namespace`.
    pub service_namespace: Option<String>,
    /// Resource `service.instance.id`.
    pub service_instance_id: Option<String>,
    /// Resource `host.name`.
    pub host_name: Option<String>,
    /// TCP peer IP of the exporter.
    pub peer_addr: Option<String>,
    /// Lowercase hex trace id (empty -> `None`).
    pub trace_id: Option<String>,
    /// Lowercase hex span id (empty -> `None`).
    pub span_id: Option<String>,
    /// W3C trace flags (0 -> `None`).
    pub flags: Option<u32>,
    /// OTLP `event_name` (empty -> `None`).
    pub event_name: Option<String>,
    /// Instrumentation scope name (empty -> `None`).
    pub scope_name: Option<String>,
    /// Instrumentation scope version (empty -> `None`).
    pub scope_version: Option<String>,
    /// ALL resource attributes as a JSON object (lossless; promoted keys are repeated here).
    pub resource_attributes: serde_json::Value,
    /// Log attributes merged over scope attributes, as a JSON object.
    pub attributes: serde_json::Value,
}

impl EventUuid for OtlpRecord {
    fn set_event_uuid(&mut self, uuid: String) {
        self.event_uuid = Some(uuid);
    }
}

fn ts_type() -> DataType {
    DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
}

/// The frozen 21-column OTLP schema. `LazyLock`-cached so `Arc::ptr_eq` comparisons are
/// meaningful (same reasoning as `generic_s3::generic_schema`).
pub fn otlp_schema() -> Arc<Schema> {
    static S: LazyLock<Arc<Schema>> = LazyLock::new(|| {
        let utf8 = |n: &str, nullable: bool| Field::new(n, DataType::Utf8, nullable);
        Arc::new(Schema::new(vec![
            utf8("event_uuid", false),
            Field::new("time", ts_type(), true),
            Field::new("observed_time", ts_type(), true),
            Field::new("received_at", ts_type(), false),
            Field::new("severity_number", DataType::Int32, true),
            utf8("severity_text", true),
            utf8("body", true),
            utf8("service_name", true),
            utf8("service_namespace", true),
            utf8("service_instance_id", true),
            utf8("host_name", true),
            utf8("peer_addr", true),
            utf8("trace_id", true),
            utf8("span_id", true),
            Field::new("flags", DataType::UInt32, true),
            utf8("event_name", true),
            utf8("scope_name", true),
            utf8("scope_version", true),
            utf8("resource_attributes", false),
            utf8("attributes", false),
            Field::new("partition_time", ts_type(), false),
        ]))
    });
    S.clone()
}

/// `ParquetSink` adapter for `OtlpRecord`.
#[derive(Clone, Default, Debug)]
pub struct OtlpSink;

fn json_text(v: &serde_json::Value) -> String {
    if v.is_null() {
        return "{}".to_string();
    }
    serde_json::to_string(v).unwrap_or_else(|_| "{}".to_string())
}

impl ParquetSink for OtlpSink {
    type Record = OtlpRecord;

    fn source(&self) -> &'static str {
        "otlp"
    }

    /// Sanitized `service_name`, or `unknown` when absent/empty. `service.name` is wire-supplied
    /// so it is sanitized exactly like HEC `sourcetype` (lowercase, `[a-z0-9_]`, <= 64 chars).
    fn partition(&self, record: &OtlpRecord) -> Option<String> {
        Some(match record.service_name.as_deref() {
            Some(s) if !s.is_empty() => sanitize_log_path(s),
            _ => UNKNOWN_SERVICE_PARTITION.to_string(),
        })
    }

    fn schema(&self, _partition: Option<&str>) -> Arc<Schema> {
        otlp_schema()
    }

    /// `partition_time` is non-null by construction (event time clamped, else `received_at`).
    fn time_column(&self) -> Option<&'static str> {
        Some("partition_time")
    }

    /// One-row fallback path. Unreachable from the OTLP writer (`new_batch` is always `Some`
    /// for `otlp_schema()` and `try_append` always returns `Ok(true)`); it is slower than the
    /// accumulator by design (fresh builders per call). Used by tests and as the trait's
    /// required fallback.
    ///
    /// One-row wrapper over `OtlpAccumulator`: the column-append code exists in exactly one
    /// place (`OtlpAccumulator::append_record_value`), shared with the amortized path.
    fn to_record_batch(
        &self,
        r: &OtlpRecord,
        _schema: &Arc<Schema>,
    ) -> anyhow::Result<RecordBatch> {
        let mut acc = OtlpAccumulator::new();
        acc.append_record_value(r);
        acc.finish_batch()
    }

    /// Amortized-builder fast path, gated on `Arc::ptr_eq` with the one OTLP schema.
    fn new_batch(
        &self,
        schema: &Arc<Schema>,
    ) -> Option<Box<dyn RecordBatchAccumulator<OtlpRecord>>> {
        if Arc::ptr_eq(schema, &otlp_schema()) {
            Some(Box::new(OtlpAccumulator::new()))
        } else {
            None
        }
    }

    /// Derives the day from `partition_time(time, received_at)` without building a batch.
    /// Load-bearing: `push()` calls this before it knows the record goes to the accumulator,
    /// so building a batch here would reintroduce the per-record cost. `partition_time` is
    /// always non-null in `to_record_batch`, so this is exactly what `day_from_batch` reads.
    fn day_and_batch(
        &self,
        record: &OtlpRecord,
        _schema: &Arc<Schema>,
        _now: DateTime<Utc>,
    ) -> anyhow::Result<(NaiveDate, Option<RecordBatch>)> {
        Ok((
            partition_time(record.time, record.received_at).date_naive(),
            None,
        ))
    }
}

/// Persistent Arrow builders for the 21-column OTLP schema, reused across many rows.
pub(crate) struct OtlpAccumulator {
    event_uuid: StringBuilder,
    time: TimestampMicrosecondBuilder,
    observed_time: TimestampMicrosecondBuilder,
    received_at: TimestampMicrosecondBuilder,
    severity_number: Int32Builder,
    severity_text: StringBuilder,
    body: StringBuilder,
    service_name: StringBuilder,
    service_namespace: StringBuilder,
    service_instance_id: StringBuilder,
    host_name: StringBuilder,
    peer_addr: StringBuilder,
    trace_id: StringBuilder,
    span_id: StringBuilder,
    flags: UInt32Builder,
    event_name: StringBuilder,
    scope_name: StringBuilder,
    scope_version: StringBuilder,
    resource_attributes: StringBuilder,
    attributes: StringBuilder,
    partition_time: TimestampMicrosecondBuilder,
    rows: usize,
}

impl OtlpAccumulator {
    fn new() -> Self {
        let ts = || TimestampMicrosecondBuilder::new().with_data_type(ts_type());
        Self {
            event_uuid: StringBuilder::new(),
            time: ts(),
            observed_time: ts(),
            received_at: ts(),
            severity_number: Int32Builder::new(),
            severity_text: StringBuilder::new(),
            body: StringBuilder::new(),
            service_name: StringBuilder::new(),
            service_namespace: StringBuilder::new(),
            service_instance_id: StringBuilder::new(),
            host_name: StringBuilder::new(),
            peer_addr: StringBuilder::new(),
            trace_id: StringBuilder::new(),
            span_id: StringBuilder::new(),
            flags: UInt32Builder::new(),
            event_name: StringBuilder::new(),
            scope_name: StringBuilder::new(),
            scope_version: StringBuilder::new(),
            resource_attributes: StringBuilder::new(),
            attributes: StringBuilder::new(),
            partition_time: ts(),
            rows: 0,
        }
    }

    /// Append one record to every column. Infallible: no partial row is possible.
    fn append_record_value(&mut self, r: &OtlpRecord) {
        match r.event_uuid.as_deref() {
            Some(u) => self.event_uuid.append_value(u),
            None => self
                .event_uuid
                .append_value(crate::ingest::new_event_uuid()),
        }
        self.time
            .append_option(r.time.map(|d| d.timestamp_micros()));
        self.observed_time
            .append_option(r.observed_time.map(|d| d.timestamp_micros()));
        self.received_at
            .append_value(r.received_at.timestamp_micros());
        self.severity_number.append_option(r.severity_number);
        self.severity_text.append_option(r.severity_text.as_deref());
        self.body.append_option(r.body.as_deref());
        self.service_name.append_option(r.service_name.as_deref());
        self.service_namespace
            .append_option(r.service_namespace.as_deref());
        self.service_instance_id
            .append_option(r.service_instance_id.as_deref());
        self.host_name.append_option(r.host_name.as_deref());
        self.peer_addr.append_option(r.peer_addr.as_deref());
        self.trace_id.append_option(r.trace_id.as_deref());
        self.span_id.append_option(r.span_id.as_deref());
        self.flags.append_option(r.flags);
        self.event_name.append_option(r.event_name.as_deref());
        self.scope_name.append_option(r.scope_name.as_deref());
        self.scope_version.append_option(r.scope_version.as_deref());
        self.resource_attributes
            .append_value(json_text(&r.resource_attributes));
        self.attributes.append_value(json_text(&r.attributes));
        self.partition_time
            .append_value(partition_time(r.time, r.received_at).timestamp_micros());
        self.rows += 1;
    }

    /// Drain every builder into one batch and reset. The builders are drained before
    /// `RecordBatch::try_new`, so an error would lose the rows; it cannot occur here because
    /// the schema is fixed and the 21 columns are built in schema order with matching types
    /// and equal lengths. Returns `Result` only to match `RecordBatchAccumulator::finish`
    /// (same shape as `GenericAccumulator::finish_batch`).
    fn finish_batch(&mut self) -> anyhow::Result<RecordBatch> {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(self.event_uuid.finish()),
            Arc::new(self.time.finish()),
            Arc::new(self.observed_time.finish()),
            Arc::new(self.received_at.finish()),
            Arc::new(self.severity_number.finish()),
            Arc::new(self.severity_text.finish()),
            Arc::new(self.body.finish()),
            Arc::new(self.service_name.finish()),
            Arc::new(self.service_namespace.finish()),
            Arc::new(self.service_instance_id.finish()),
            Arc::new(self.host_name.finish()),
            Arc::new(self.peer_addr.finish()),
            Arc::new(self.trace_id.finish()),
            Arc::new(self.span_id.finish()),
            Arc::new(self.flags.finish()),
            Arc::new(self.event_name.finish()),
            Arc::new(self.scope_name.finish()),
            Arc::new(self.scope_version.finish()),
            Arc::new(self.resource_attributes.finish()),
            Arc::new(self.attributes.finish()),
            Arc::new(self.partition_time.finish()),
        ];
        self.rows = 0;
        Ok(RecordBatch::try_new(otlp_schema(), columns)?)
    }
}

impl RecordBatchAccumulator<OtlpRecord> for OtlpAccumulator {
    fn try_append(&mut self, record: &OtlpRecord, _now: DateTime<Utc>) -> anyhow::Result<bool> {
        // One fixed schema, so there is no mismatch case to fall back from.
        self.append_record_value(record);
        Ok(true)
    }

    fn len(&self) -> usize {
        self.rows
    }

    fn finish(&mut self) -> anyhow::Result<RecordBatch> {
        self.finish_batch()
    }
}

/// `ParquetWriterHandle<OtlpSink>`; what `IngestState` holds per OTLP target.
pub type OtlpHandler = ParquetWriterHandle<OtlpSink>;

/// Start the OTLP S3 writer. The caller awaits the `JoinHandle` at graceful shutdown after
/// dropping every `OtlpHandler` clone.
pub fn otlp_start(
    cfg: &OtlpS3Config,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
    max_partitions: usize,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<Arc<dyn UploadSink>>,
) -> (OtlpHandler, tokio::task::JoinHandle<()>) {
    start_writer::<OtlpSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        max_partitions,
        s3,
        source_stats,
        descriptor_sink,
    )
}

/// Local-disk twin of `otlp_start`.
pub fn otlp_local_start(
    cfg: &OtlpLocalConfig,
    sink: Arc<crate::forwarding::local_sink::LocalDiskSink>,
    max_partitions: usize,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<Arc<dyn UploadSink>>,
) -> (OtlpHandler, tokio::task::JoinHandle<()>) {
    start_writer::<OtlpSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        max_partitions,
        sink,
        source_stats,
        descriptor_sink,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::{Array, Int32Array, StringArray, TimestampMicrosecondArray, UInt32Array};
    use chrono::TimeZone;
    use serde_json::json;

    fn sample() -> OtlpRecord {
        OtlpRecord {
            event_uuid: Some("0199c4e0-7d2a-7b3c-9a10-4f2b6d8e1c35".to_string()),
            time: Some(Utc.with_ymd_and_hms(2026, 10, 6, 12, 0, 0).unwrap()),
            observed_time: None,
            received_at: Utc.with_ymd_and_hms(2026, 10, 6, 12, 0, 1).unwrap(),
            severity_number: Some(9),
            severity_text: Some("INFO".to_string()),
            body: Some("hello".to_string()),
            service_name: Some("Checkout Svc".to_string()),
            service_namespace: Some("shop".to_string()),
            service_instance_id: Some("i-1".to_string()),
            host_name: Some("web01".to_string()),
            peer_addr: Some("10.0.0.7".to_string()),
            trace_id: Some("0af7651916cd43dd8448eb211c80319c".to_string()),
            span_id: Some("b7ad6b7169203331".to_string()),
            flags: Some(1),
            event_name: None,
            scope_name: Some("lib".to_string()),
            scope_version: Some("1.2".to_string()),
            resource_attributes: json!({"service.name": "Checkout Svc", "k8s.pod": "p1"}),
            attributes: json!({"http.route": "/x"}),
        }
    }

    fn bare() -> OtlpRecord {
        OtlpRecord {
            event_uuid: None,
            time: None,
            observed_time: None,
            received_at: Utc.with_ymd_and_hms(2026, 10, 6, 12, 0, 1).unwrap(),
            severity_number: None,
            severity_text: None,
            body: None,
            service_name: None,
            service_namespace: None,
            service_instance_id: None,
            host_name: None,
            peer_addr: None,
            trace_id: None,
            span_id: None,
            flags: None,
            event_name: None,
            scope_name: None,
            scope_version: None,
            resource_attributes: json!({}),
            attributes: json!({}),
        }
    }

    /// Frozen copy of the pre-accumulator one-row-per-record implementation. Independent of
    /// production code so the equivalence tests pin byte-identical output.
    fn reference_batch(r: &OtlpRecord) -> RecordBatch {
        let ts = |v: Option<DateTime<Utc>>| -> ArrayRef {
            Arc::new(
                TimestampMicrosecondArray::from(vec![v.map(|d| d.timestamp_micros())])
                    .with_timezone("UTC"),
            )
        };
        let utf8 = |v: Option<&str>| -> ArrayRef { Arc::new(StringArray::from(vec![v])) };
        let fallback_uuid;
        let event_uuid = match r.event_uuid.as_deref() {
            Some(u) => u,
            None => {
                fallback_uuid = crate::ingest::new_event_uuid();
                &fallback_uuid
            }
        };
        let resource_attributes = json_text(&r.resource_attributes);
        let attributes = json_text(&r.attributes);
        let columns: Vec<ArrayRef> = vec![
            utf8(Some(event_uuid)),
            ts(r.time),
            ts(r.observed_time),
            ts(Some(r.received_at)),
            Arc::new(Int32Array::from(vec![r.severity_number])),
            utf8(r.severity_text.as_deref()),
            utf8(r.body.as_deref()),
            utf8(r.service_name.as_deref()),
            utf8(r.service_namespace.as_deref()),
            utf8(r.service_instance_id.as_deref()),
            utf8(r.host_name.as_deref()),
            utf8(r.peer_addr.as_deref()),
            utf8(r.trace_id.as_deref()),
            utf8(r.span_id.as_deref()),
            Arc::new(UInt32Array::from(vec![r.flags])),
            utf8(r.event_name.as_deref()),
            utf8(r.scope_name.as_deref()),
            utf8(r.scope_version.as_deref()),
            utf8(Some(&resource_attributes)),
            utf8(Some(&attributes)),
            ts(Some(partition_time(r.time, r.received_at))),
        ];
        RecordBatch::try_new(otlp_schema(), columns).unwrap()
    }

    #[test]
    fn otlp_schema_is_frozen_names_types_and_nullability() {
        use arrow_schema::{DataType as D, TimeUnit};
        let ts = D::Timestamp(TimeUnit::Microsecond, Some("UTC".into()));
        let expected: Vec<(&str, D, bool)> = vec![
            ("event_uuid", D::Utf8, false),
            ("time", ts.clone(), true),
            ("observed_time", ts.clone(), true),
            ("received_at", ts.clone(), false),
            ("severity_number", D::Int32, true),
            ("severity_text", D::Utf8, true),
            ("body", D::Utf8, true),
            ("service_name", D::Utf8, true),
            ("service_namespace", D::Utf8, true),
            ("service_instance_id", D::Utf8, true),
            ("host_name", D::Utf8, true),
            ("peer_addr", D::Utf8, true),
            ("trace_id", D::Utf8, true),
            ("span_id", D::Utf8, true),
            ("flags", D::UInt32, true),
            ("event_name", D::Utf8, true),
            ("scope_name", D::Utf8, true),
            ("scope_version", D::Utf8, true),
            ("resource_attributes", D::Utf8, false),
            ("attributes", D::Utf8, false),
            ("partition_time", ts, false),
        ];
        let schema = otlp_schema();
        let actual: Vec<(&str, D, bool)> = schema
            .fields()
            .iter()
            .map(|f| (f.name().as_str(), f.data_type().clone(), f.is_nullable()))
            .collect();
        assert_eq!(actual, expected);
        assert!(
            Arc::ptr_eq(&otlp_schema(), &otlp_schema()),
            "schema must be cached"
        );
    }

    #[test]
    fn otlp_sink_source_and_time_column() {
        assert_eq!(OtlpSink.source(), "otlp");
        assert_eq!(OtlpSink.time_column(), Some("partition_time"));
    }

    #[test]
    fn partition_is_sanitized_service_name_with_unknown_fallback() {
        assert_eq!(
            OtlpSink.partition(&sample()).as_deref(),
            Some("checkout_svc")
        );
        assert_eq!(OtlpSink.partition(&bare()).as_deref(), Some("unknown"));
        let mut empty = bare();
        empty.service_name = Some(String::new());
        assert_eq!(OtlpSink.partition(&empty).as_deref(), Some("unknown"));
        let mut hostile = bare();
        hostile.service_name = Some("../../etc/passwd".to_string());
        let p = OtlpSink.partition(&hostile).unwrap();
        assert!(!p.contains('/') && !p.contains('.'), "path-safe: {p}");
    }

    #[test]
    fn to_record_batch_keeps_raw_service_name_and_typed_values() {
        let schema = otlp_schema();
        let b = OtlpSink.to_record_batch(&sample(), &schema).unwrap();
        assert_eq!(b.num_rows(), 1);
        let s = |n: &str| {
            b.column_by_name(n)
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap()
                .clone()
        };
        assert_eq!(
            s("service_name").value(0),
            "Checkout Svc",
            "raw, unsanitized"
        );
        assert_eq!(
            s("event_uuid").value(0),
            "0199c4e0-7d2a-7b3c-9a10-4f2b6d8e1c35"
        );
        assert_eq!(s("trace_id").value(0), "0af7651916cd43dd8448eb211c80319c");
        assert!(s("event_name").is_null(0));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(s("resource_attributes").value(0)).unwrap(),
            json!({"service.name": "Checkout Svc", "k8s.pod": "p1"}),
            "resource_attributes keeps ALL resource attrs including promoted keys"
        );
        let sev = b
            .column_by_name("severity_number")
            .unwrap()
            .as_any()
            .downcast_ref::<Int32Array>()
            .unwrap();
        assert_eq!(sev.value(0), 9);
        let flags = b
            .column_by_name("flags")
            .unwrap()
            .as_any()
            .downcast_ref::<UInt32Array>()
            .unwrap();
        assert_eq!(flags.value(0), 1);
        let t = b
            .column_by_name("time")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(t.value(0), sample().time.unwrap().timestamp_micros());
        let pt = b
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(pt.value(0), sample().time.unwrap().timestamp_micros());
    }

    #[test]
    fn bare_record_writes_nulls_empty_json_and_generates_an_event_uuid() {
        let schema = otlp_schema();
        let b = OtlpSink.to_record_batch(&bare(), &schema).unwrap();
        for n in [
            "time",
            "observed_time",
            "severity_number",
            "severity_text",
            "body",
            "service_name",
            "service_namespace",
            "service_instance_id",
            "host_name",
            "peer_addr",
            "trace_id",
            "span_id",
            "flags",
            "event_name",
            "scope_name",
            "scope_version",
        ] {
            assert!(b.column_by_name(n).unwrap().is_null(0), "{n} must be null");
        }
        let s = |n: &str| {
            b.column_by_name(n)
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap()
                .clone()
        };
        assert_eq!(s("resource_attributes").value(0), "{}");
        assert_eq!(s("attributes").value(0), "{}");
        // Defensive: handlers assign ids, but a sink-level caller still gets a valid row.
        let id = s("event_uuid").value(0).to_string();
        assert_eq!(uuid::Uuid::parse_str(&id).unwrap().get_version_num(), 7);
        let pt = b
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(
            pt.value(0),
            bare().received_at.timestamp_micros(),
            "falls back to received_at"
        );
    }

    #[test]
    fn partition_time_outside_clamp_falls_back_to_received_at() {
        let mut r = sample();
        r.time = Some(r.received_at - chrono::TimeDelta::days(60));
        let b = OtlpSink.to_record_batch(&r, &otlp_schema()).unwrap();
        let pt = b
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(pt.value(0), r.received_at.timestamp_micros());
    }

    #[test]
    fn event_uuid_trait_sets_the_field() {
        let mut r = bare();
        crate::ingest::assign_event_uuids(std::slice::from_mut(&mut r));
        assert!(r.event_uuid.is_some());
    }

    fn full_record(i: usize) -> OtlpRecord {
        let sev = [1, 5, 9, 13, 17, 21, 24][i % 7];
        OtlpRecord {
            event_uuid: Some(format!("0199c4e0-7d2a-7b3c-9a10-{i:012}")),
            time: Some(
                Utc.timestamp_micros(1_790_000_000_000_000 + i as i64 * 997)
                    .unwrap(),
            ),
            observed_time: Some(Utc.timestamp_micros(1_790_000_000_000_500).unwrap()),
            received_at: Utc.with_ymd_and_hms(2026, 10, 6, 12, 0, 1).unwrap(),
            severity_number: Some(sev),
            severity_text: Some(["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"][i % 6].into()),
            body: Some(format!("body \u{e9}\u{4e2d}\u{1f600} \"q\" {i}")),
            service_name: Some(format!("Svc {}", i % 3)),
            service_namespace: Some("ns".into()),
            service_instance_id: Some(format!("inst-{i}")),
            host_name: Some("h\u{fc}st".into()),
            peer_addr: Some("::1".into()),
            trace_id: Some("0af7651916cd43dd8448eb211c80319c".into()),
            span_id: Some("b7ad6b7169203331".into()),
            flags: Some(u32::MAX),
            event_name: Some("ev".into()),
            scope_name: Some("lib".into()),
            scope_version: Some("1.0".into()),
            resource_attributes: json!({"service.name": format!("Svc {}", i % 3), "n": i}),
            attributes: json!({"k": ["a", 1, null], "u": "\u{1f600}"}),
        }
    }

    fn representative_records() -> Vec<OtlpRecord> {
        let mut v: Vec<OtlpRecord> = (0..40).map(full_record).collect();
        v.push(sample());
        let mut b = bare();
        b.event_uuid = Some("fixed-uuid".into());
        v.push(b);
        // Edge timestamps: epoch, far future, pre-epoch, outside the partition clamp.
        for micros in [0_i64, -1, 4_102_444_800_000_000, 1] {
            let mut r = full_record(1);
            r.time = Some(Utc.timestamp_micros(micros).unwrap());
            r.observed_time = Some(Utc.timestamp_micros(micros).unwrap());
            v.push(r);
        }
        let mut null_attrs = full_record(2);
        null_attrs.resource_attributes = serde_json::Value::Null;
        null_attrs.attributes = serde_json::Value::Null;
        v.push(null_attrs);
        let mut empty_strs = full_record(3);
        empty_strs.body = Some(String::new());
        empty_strs.service_name = Some(String::new());
        v.push(empty_strs);
        v
    }

    #[test]
    fn new_batch_activates_for_real_schema_and_not_for_an_unrelated_one() {
        assert!(OtlpSink.new_batch(&otlp_schema()).is_some());
        let unrelated = Arc::new(Schema::new(vec![Field::new("x", DataType::Utf8, false)]));
        assert!(OtlpSink.new_batch(&unrelated).is_none());
        // Equal-by-value but a distinct Arc must not activate (Arc::ptr_eq contract).
        let copy = Arc::new(Schema::new(otlp_schema().fields().clone()));
        assert!(OtlpSink.new_batch(&copy).is_none());
    }

    #[test]
    fn accumulator_finish_equals_concat_of_per_record_batches() {
        let records = representative_records();
        let mut acc = OtlpSink.new_batch(&otlp_schema()).unwrap();
        let now = Utc::now();
        for r in &records {
            assert!(acc.try_append(r, now).unwrap());
        }
        assert_eq!(acc.len(), records.len());
        let got = acc.finish().unwrap();
        assert_eq!(acc.len(), 0, "finish resets");
        let singles: Vec<RecordBatch> = records.iter().map(reference_batch).collect();
        let want = arrow::compute::concat_batches(&otlp_schema(), &singles).unwrap();
        assert_eq!(got.schema(), want.schema());
        assert_eq!(got.num_rows(), want.num_rows());
        for (i, f) in want.schema().fields().iter().enumerate() {
            assert_eq!(
                got.column(i).as_ref(),
                want.column(i).as_ref(),
                "column {}",
                f.name()
            );
        }
        // The production per-record path must agree with the reference too.
        for r in &records {
            let a = OtlpSink.to_record_batch(r, &otlp_schema()).unwrap();
            assert_eq!(a, reference_batch(r));
        }
    }

    #[test]
    fn accumulator_is_reusable_after_finish() {
        let mut acc = OtlpSink.new_batch(&otlp_schema()).unwrap();
        let now = Utc::now();
        for round in 0..2 {
            for i in 0..5 {
                assert!(acc.try_append(&full_record(i), now).unwrap());
            }
            let b = acc.finish().unwrap();
            assert_eq!(b.num_rows(), 5, "round {round}");
            assert_eq!(
                b,
                arrow::compute::concat_batches(
                    &otlp_schema(),
                    &(0..5)
                        .map(|i| reference_batch(&full_record(i)))
                        .collect::<Vec<_>>(),
                )
                .unwrap()
            );
        }
    }

    #[test]
    fn accumulator_missing_event_uuid_gets_a_generated_v7_uuid() {
        let mut acc = OtlpSink.new_batch(&otlp_schema()).unwrap();
        assert!(acc.try_append(&bare(), Utc::now()).unwrap());
        let b = acc.finish().unwrap();
        let id = b
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap()
            .value(0);
        assert_eq!(uuid::Uuid::parse_str(id).unwrap().get_version_num(), 7);
    }

    /// No `OtlpRecord` can make `try_append` fail or half-append: every column is built from
    /// infallible builder appends (JSON text falls back to `{}`), and the schema is fixed so
    /// there is no mismatch case. Assert the observable consequence: always `Ok(true)` and
    /// `len()` grows by exactly one, even for the most hostile values.
    #[test]
    fn try_append_never_fails_and_adds_exactly_one_row() {
        let mut acc = OtlpSink.new_batch(&otlp_schema()).unwrap();
        let mut hostile = full_record(0);
        hostile.body = Some("\0\n\u{feff}".repeat(10_000));
        hostile.attributes = json!({"deep": {"a": {"b": {"c": [1, 2, {"d": null}]}}}});
        for (n, r) in [bare(), hostile, full_record(1)].iter().enumerate() {
            assert!(acc.try_append(r, Utc::now()).unwrap());
            assert_eq!(acc.len(), n + 1);
        }
        assert_eq!(acc.finish().unwrap().num_rows(), 3);
    }

    #[test]
    fn day_and_batch_never_builds_a_batch_and_matches_partition_day() {
        let schema = otlp_schema();
        let now = Utc::now();
        for r in representative_records() {
            let (day, batch) = OtlpSink.day_and_batch(&r, &schema, now).unwrap();
            assert!(batch.is_none(), "must not build a throwaway batch");
            let single = reference_batch(&r);
            let micros = single
                .column_by_name("partition_time")
                .unwrap()
                .as_any()
                .downcast_ref::<TimestampMicrosecondArray>()
                .unwrap()
                .value(0);
            let old_day = Utc.timestamp_micros(micros).unwrap().date_naive();
            assert_eq!(day, old_day);
        }
    }
}
