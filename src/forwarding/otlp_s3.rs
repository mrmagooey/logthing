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
//! so the column is lossless. The sink uses the default per-record `to_record_batch` path
//! (no amortized accumulator).
//!
//! S3 key layout: `otlp/<service>/year={Y}/month={MM}/day={DD}/{uuid}.parquet`
//!
//! Column types are FROZEN: the committer evolves tables additively only, so a type change
//! would quarantine every new file. Add columns by APPENDING nullable ones.

use crate::config::{OtlpLocalConfig, OtlpS3Config};
use crate::forwarding::buffered_writer::{
    ParquetSink, ParquetWriterHandle, UploadSink, partition_time, sanitize_log_path, start_writer,
};
use crate::ingest::EventUuid;
use arrow_array::{
    ArrayRef, Int32Array, RecordBatch, StringArray, TimestampMicrosecondArray, UInt32Array,
};
use arrow_schema::{DataType, Field, Schema, TimeUnit};
use chrono::{DateTime, Utc};
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

    fn to_record_batch(
        &self,
        r: &OtlpRecord,
        _schema: &Arc<Schema>,
    ) -> anyhow::Result<RecordBatch> {
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
        Ok(RecordBatch::try_new(otlp_schema(), columns)?)
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
}
