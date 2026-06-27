//! Suricata → S3 Parquet persistence.
//!
//! Provides:
//! - `sanitize_event_type()` — safe path segment for S3 keys
//! - `SuricataSink` — `ParquetSink` adapter for the generic writer (single envelope schema)
//! - `SuricataS3Handler` — type alias for `ParquetWriterHandle<SuricataSink>`
//! - `suricata_start()` — convenience constructor wiring `SuricataS3Config` → `ParquetWriterHandle`
//!
//! Unlike Zeek (which has per-stream typed schemas), Suricata uses a single envelope schema
//! for all event types.  The generic `PartitionedParquetWriter` handles all buffering, flush,
//! cap, encode, and upload machinery.  `SuricataSink` is the thin adapter that provides:
//! - `partition()` → `sanitize_event_type(record.event_type)` (per-event-type buffer key)
//! - `schema(partition)` → always returns `envelope_schema()` (no typed registry)
//! - `to_record_batch()` → calls `map_envelope(record)` directly
//!
//! S3 key layout:  `suricata/<sanitized_event_type>/year={Y}/month={MM}/day={DD}/{uuid}.parquet`
//! Partition cap:  `DEFAULT_MAX_SURICATA_PARTITIONS = 256`; excess → `"_overflow"` buffer.
//! Metrics:        `parquet_s3_*{source="suricata"}` (generic labels).

use crate::config::SuricataS3Config;
use crate::forwarding::buffered_writer::ParquetSink;
use crate::suricata::SuricataRecord;
use crate::suricata::schema::{envelope_schema, map_envelope};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// sanitize_event_type — public helper reused by tests + generic partition()
// ---------------------------------------------------------------------------

/// Sanitise an attacker-supplied `event_type` value so it is safe to embed in an S3 key.
/// - Lowercases the input
/// - Keeps `[a-z0-9_]`, replaces anything else with `_`
/// - Truncates to 64 chars
/// - Empty result → `"unknown"`
pub(crate) fn sanitize_event_type(raw: &str) -> String {
    let s: String = raw
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    if s.is_empty() {
        "unknown".to_string()
    } else {
        s
    }
}

// ---------------------------------------------------------------------------
// SuricataSink — ParquetSink adapter
// ---------------------------------------------------------------------------

/// `ParquetSink` adapter for Suricata EVE JSON records.
///
/// Uses a single envelope schema for all event types — no per-event-type typed registry.
/// Each distinct `event_type` (after sanitization) gets its own buffer keyed by the
/// sanitized event type.  Excess partitions overflow to the `"_overflow"` buffer.
pub struct SuricataSink;

impl ParquetSink for SuricataSink {
    type Record = SuricataRecord;

    fn source(&self) -> &'static str {
        "suricata"
    }

    /// Partition segment = `sanitize_event_type(record.event_type)`.
    /// This is used as both the buffer-map key and the S3 path component,
    /// producing keys of the form `suricata/<event_type>/year=…/…parquet`.
    fn partition(&self, record: &SuricataRecord) -> Option<String> {
        Some(sanitize_event_type(&record.event_type))
    }

    /// Schema for `partition`: always returns `envelope_schema()`.
    /// Suricata uses a single envelope schema for all event types.
    fn schema(&self, _partition: Option<&str>) -> Arc<arrow_schema::Schema> {
        envelope_schema()
    }

    /// Convert one `SuricataRecord` to a single-row `RecordBatch`.
    /// Uses `map_envelope` which always produces a row matching `envelope_schema()`.
    fn to_record_batch(
        &self,
        record: &SuricataRecord,
        _schema: &Arc<arrow_schema::Schema>,
    ) -> anyhow::Result<arrow_array::RecordBatch> {
        map_envelope(record)
    }
}

// ---------------------------------------------------------------------------
// SuricataS3Handler — type alias + SuricataHandler impl
// ---------------------------------------------------------------------------

/// `SuricataS3Handler` is a thin alias for the generic `ParquetWriterHandle<SuricataSink>`.
pub type SuricataS3Handler =
    crate::forwarding::buffered_writer::ParquetWriterHandle<SuricataSink>;

#[async_trait::async_trait]
impl crate::suricata::listener::SuricataHandler
    for crate::forwarding::buffered_writer::ParquetWriterHandle<SuricataSink>
{
    async fn handle_record(
        &self,
        record: SuricataRecord,
        source: std::net::SocketAddr,
    ) {
        match self.try_send(record) {
            Ok(()) => {}
            Err(_dropped) => {
                // parquet_s3_dropped{source="suricata"} is already incremented by try_send.
                tracing::warn!(
                    "Suricata S3 channel full; dropped 1 record from {}",
                    source
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// suricata_start — convenience constructor
// ---------------------------------------------------------------------------

/// Construct a `SuricataS3Handler` (i.e. `ParquetWriterHandle<SuricataSink>`) from a
/// `SuricataS3Config` and a pre-built `S3Sink`.
///
/// Returns `(handler, writer_task_handle)`. The caller should retain the `JoinHandle`
/// and await it during graceful shutdown, after all `Arc<dyn SuricataHandler>` references
/// have been dropped so the channel closes and the final flush fires.
pub fn suricata_start(
    cfg: &SuricataS3Config,
    s3: std::sync::Arc<crate::forwarding::s3_sink::S3Sink>,
) -> (SuricataS3Handler, tokio::task::JoinHandle<()>) {
    use crate::forwarding::buffered_writer::{
        BufferedWriterConfig, FlushPolicy, ParquetWriterHandle,
    };

    /// Replaces the old per-source streams constant.
    const DEFAULT_MAX_SURICATA_PARTITIONS: usize = 256;

    let bwc = BufferedWriterConfig {
        connection: cfg.connection.clone(),
        prefix: cfg.prefix.clone(),
        max_buffer_rows: cfg.max_buffer_rows,
        flush_threshold_bytes: cfg.flush_threshold_bytes,
        flush_interval_secs: cfg.flush_interval_secs,
        channel_capacity: cfg.channel_capacity,
        max_partitions: DEFAULT_MAX_SURICATA_PARTITIONS,
    };
    let policy = FlushPolicy {
        max_rows: cfg.max_buffer_rows,
        max_bytes: cfg.flush_threshold_bytes,
        interval: std::time::Duration::from_secs(cfg.flush_interval_secs),
    };
    ParquetWriterHandle::start(SuricataSink, s3, bwc, policy)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::S3ConnectionConfig;
    use crate::forwarding::buffered_writer::{
        BufferedWriterConfig, FlushPolicy, PartitionedParquetWriter,
    };
    use crate::forwarding::s3_sink::S3Sink;
    use crate::suricata::SuricataRecord;
    use chrono::Utc;
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

    fn make_alert_record(src_ip: &str) -> SuricataRecord {
        SuricataRecord {
            event_type: "alert".to_string(),
            fields: serde_json::json!({
                "event_type": "alert",
                "src_ip": src_ip,
                "dest_ip": "1.2.3.4",
                "alert": {"signature": "ET TEST"}
            }),
            received_at: Utc::now(),
        }
    }

    fn make_flow_record() -> SuricataRecord {
        SuricataRecord {
            event_type: "flow".to_string(),
            fields: serde_json::json!({
                "event_type": "flow",
                "src_ip": "10.0.0.1",
                "dest_ip": "8.8.8.8",
                "flow": {"bytes_toserver": 512, "bytes_toclient": 4096}
            }),
            received_at: Utc::now(),
        }
    }

    // -- sanitize_event_type --

    #[test]
    fn event_type_sanitizer_handles_traversal_and_length() {
        assert_eq!(sanitize_event_type("alert"), "alert");
        assert_eq!(sanitize_event_type("../etc"), "___etc");
        let out = sanitize_event_type("../../etc/passwd");
        assert!(!out.contains('/'));
        assert!(!out.contains('.'));
        assert_eq!(sanitize_event_type(""), "unknown");
        let long_input = "a".repeat(100);
        assert_eq!(sanitize_event_type(&long_input).len(), 64);
    }

    // -- SuricataSink unit --

    #[test]
    fn suricata_sink_source_returns_suricata() {
        assert_eq!(SuricataSink.source(), "suricata");
    }

    #[test]
    fn suricata_sink_partition_sanitizes_event_type() {
        let rec = make_alert_record("10.0.0.1");
        assert_eq!(SuricataSink.partition(&rec), Some("alert".to_string()));

        let bad = SuricataRecord {
            event_type: "../bad".to_string(),
            fields: serde_json::json!({}),
            received_at: Utc::now(),
        };
        let part = SuricataSink.partition(&bad).unwrap();
        assert!(!part.contains('/'));
        assert!(!part.contains('.'));
    }

    #[test]
    fn suricata_sink_schema_always_returns_envelope() {
        use crate::suricata::schema::envelope_schema;

        // All partitions — named, overflow, or None — return the same envelope schema
        assert_eq!(SuricataSink.schema(Some("alert")), envelope_schema());
        assert_eq!(SuricataSink.schema(Some("_overflow")), envelope_schema());
        assert_eq!(SuricataSink.schema(None), envelope_schema());
        assert_eq!(SuricataSink.schema(Some("unknown_anything")), envelope_schema());
    }

    #[test]
    fn suricata_sink_to_record_batch_produces_one_row() {
        let rec = make_alert_record("192.168.1.1");
        let schema = SuricataSink.schema(Some("alert"));
        let batch = SuricataSink.to_record_batch(&rec, &schema).unwrap();
        assert_eq!(batch.num_rows(), 1);
        use arrow::array::StringArray;
        let et = batch
            .column_by_name("event_type")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(et.value(0), "alert");
        let src = batch
            .column_by_name("src_ip")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(src.value(0), "192.168.1.1");
    }

    // -- S3 key layout --

    #[test]
    fn build_key_produces_suricata_event_type_layout() {
        use crate::forwarding::buffered_writer::build_key;
        use chrono::TimeZone;

        let now = chrono::Utc.with_ymd_and_hms(2026, 3, 7, 0, 0, 0).unwrap();
        let key = build_key("suricata", Some("alert"), now);
        assert!(
            key.starts_with("suricata/alert/year=2026/month=03/day=07/"),
            "key: {key}"
        );
        assert!(key.ends_with(".parquet"), "key: {key}");
    }

    // -- PartitionedParquetWriter accumulation --

    #[tokio::test]
    async fn writer_accumulates_per_event_type_buffers() {
        let sink = unreachable_sink().await;
        let bwc = BufferedWriterConfig {
            connection: S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "suricata".to_string(),
            max_buffer_rows: 100_000,
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_partitions: 256,
        };
        let policy = FlushPolicy {
            max_rows: 100_000,
            max_bytes: usize::MAX,
            interval: std::time::Duration::from_secs(3600),
        };
        let mut writer = PartitionedParquetWriter::new(SuricataSink, sink, bwc, policy);

        writer.push(make_alert_record("1.1.1.1")).await.ok();
        writer.push(make_alert_record("2.2.2.2")).await.ok();
        writer.push(make_flow_record()).await.ok();

        assert_eq!(
            writer.buffers.get("alert").map(|b| b.row_count).unwrap_or(0),
            2,
            "alert buffer should have 2 rows"
        );
        assert_eq!(
            writer.buffers.get("flow").map(|b| b.row_count).unwrap_or(0),
            1,
            "flow buffer should have 1 row"
        );
    }

    // -- Handler overflow drops --

    #[tokio::test]
    #[allow(clippy::mutable_key_type)]
    async fn handler_overflow_increments_dropped_counter() {
        use crate::config::SuricataS3Config;
        use crate::suricata::listener::SuricataHandler;
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::DebuggingRecorder;
        use std::net::SocketAddr;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let sink = unreachable_sink().await;
        let cfg = SuricataS3Config {
            connection: S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "suricata".to_string(),
            flush_threshold_bytes: 1,
            flush_interval_secs: 3600,
            channel_capacity: 1,
            max_buffer_rows: 1,
        };
        let (handler, _writer_handle) = suricata_start(&cfg, sink);
        tokio::task::yield_now().await;

        let src: SocketAddr = "127.0.0.1:47761".parse().unwrap();
        for i in 0..50usize {
            handler.handle_record(make_alert_record(&format!("{i}.0.0.1")), src).await;
        }
        tokio::task::yield_now().await;

        let snapshot = snapshotter.snapshot();
        let map = snapshot.into_hashmap();
        let key = CompositeKey::new(
            MetricKind::Counter,
            metrics::Key::from_parts(
                "parquet_s3_dropped",
                vec![metrics::Label::new("source", "suricata")],
            ),
        );
        let dropped = map
            .get(&key)
            .map(|(_, _, v)| {
                if let metrics_util::debugging::DebugValue::Counter(c) = v { *c } else { 0 }
            })
            .unwrap_or(0);
        assert!(
            dropped >= 1,
            "expected parquet_s3_dropped{{source=\"suricata\"}} >= 1; got {dropped}"
        );
    }

    // -- suricata_start wires handler and join handle --

    #[tokio::test]
    async fn suricata_start_wires_handler_and_join_handle() {
        use crate::config::SuricataS3Config;
        use crate::suricata::listener::SuricataHandler;
        use std::net::SocketAddr;

        let sink = unreachable_sink().await;
        let cfg = SuricataS3Config {
            connection: S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "suricata".to_string(),
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_buffer_rows: 100_000,
        };
        let (handler, join_handle) = suricata_start(&cfg, sink);
        let src: SocketAddr = "127.0.0.1:47761".parse().unwrap();
        handler.handle_record(make_alert_record("10.0.0.1"), src).await;
        drop(handler);

        tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("writer task must exit within 5s")
            .expect("writer task must not panic");
    }
}
