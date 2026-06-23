//! Zeek → S3 Parquet persistence.
//!
//! Provides:
//! - `sanitize_log_path()` — safe path segment for S3 keys
//! - `ZeekSink` — `ParquetSink` adapter for the generic writer (multi-partition)
//! - `ZeekS3Handler` — type alias for `ParquetWriterHandle<ZeekSink>`
//! - `zeek_start()` — convenience constructor wiring `ZeekS3Config` → `ParquetWriterHandle`
//!
//! The generic `PartitionedParquetWriter` handles all buffering, flush, cap, encode, and
//! upload machinery.  `ZeekSink` is the thin adapter that provides:
//! - `partition()` → `sanitize_log_path(record.log_path)` (per-stream buffer key)
//! - `schema(partition)` → typed registry schema or envelope fallback
//! - `to_record_batch()` → registry row mapper for the record's actual log_path
//!
//! S3 key layout:  `zeek/<sanitized_log_path>/year={Y}/month={MM}/day={DD}/{uuid}.parquet`
//! Partition cap:  `max_partitions` (replaces `MAX_ZEEK_STREAMS`); excess → `"_overflow"` buffer.
//! Metrics:        `parquet_s3_*{source="zeek"}` (generic labels).

use crate::config::ZeekS3Config;
use crate::forwarding::buffered_writer::ParquetSink;
use crate::zeek::ZeekRecord;
use crate::zeek::schema::{envelope_schema, get_schema_entry};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// sanitize_log_path — public helper reused by tests + generic partition()
// ---------------------------------------------------------------------------

/// Sanitise an attacker-supplied `_path` value so it is safe to embed in an S3 key.
/// - Lowercases the input
/// - Keeps `[a-z0-9_]`, replaces anything else with `_`
/// - Truncates to 64 chars
/// - Empty result → `"unknown"`
pub(crate) fn sanitize_log_path(raw: &str) -> String {
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
// ZeekSink — ParquetSink adapter
// ---------------------------------------------------------------------------

/// `ParquetSink` adapter for Zeek NDJSON records.
///
/// This is the multi-partition case: each distinct `log_path` (after sanitization)
/// gets its own buffer keyed by the sanitized path.  Excess partitions overflow to
/// the `"_overflow"` buffer (generic machinery; configured via `max_partitions`).
pub struct ZeekSink;

impl ParquetSink for ZeekSink {
    type Record = ZeekRecord;

    fn source(&self) -> &'static str {
        "zeek"
    }

    /// Partition segment = `sanitize_log_path(record.log_path)`.
    /// This is used as both the buffer-map key and the S3 path component,
    /// producing keys of the form `zeek/<log_path>/year=…/…parquet`.
    fn partition(&self, record: &ZeekRecord) -> Option<String> {
        Some(sanitize_log_path(&record.log_path))
    }

    /// Schema for `partition`:
    /// - For a typed log path (`conn`, `dns`, `http`, `ssl`, `files`, `notice`):
    ///   returns the typed schema from the registry.
    /// - For `None`, `"_overflow"`, or any unknown path: returns the envelope fallback schema.
    ///
    /// `partition` is the **sanitized** path segment (the buffer-map key), not the raw log_path.
    fn schema(&self, partition: Option<&str>) -> Arc<arrow_schema::Schema> {
        match partition {
            // No partition (should not happen for ZeekSink, but be safe).
            None => envelope_schema(),
            // Overflow bucket — always use the envelope fallback.
            Some("_overflow") => envelope_schema(),
            // Known or unknown named partition: look up the registry.
            // get_schema_entry falls back to envelope_schema for unknown paths.
            Some(seg) => get_schema_entry(seg).schema.clone(),
        }
    }

    /// Convert one `ZeekRecord` to a single-row `RecordBatch`.
    ///
    /// Uses `get_schema_entry(&record.log_path)` to select the row mapper for the
    /// **actual** (unsanitized) log path, applying the typed or envelope mapper.
    /// Type mismatches go to `_extra` (typed schemas) or `payload` (envelope); never panics.
    fn to_record_batch(
        &self,
        record: &ZeekRecord,
        schema: &Arc<arrow_schema::Schema>,
    ) -> anyhow::Result<arrow_array::RecordBatch> {
        // Use the actual (unsanitized) log_path to select the mapper so that the
        // registry look-up matches the same path that produced the schema in schema().
        // For the _overflow partition the schema is envelope; get_schema_entry for an
        // unknown path also returns an envelope mapper — so the types are always consistent.
        let entry = get_schema_entry(&record.log_path);

        // Sanity check: if the entry schema matches the partition schema we were given,
        // use the entry's mapper directly; otherwise fall back to re-running with the
        // schema we actually hold (avoids RecordBatch schema mismatch panics).
        if entry.schema == *schema {
            (entry.mapper)(&record.fields).map_err(|e| {
                anyhow::anyhow!("ZeekSink mapper error for '{}': {e}", record.log_path)
            })
        } else {
            // The partition was overflowed to "_overflow" (or the sanitized path doesn't match
            // the raw path).  Use the envelope mapper for the schema we were given.
            let overflow_entry = get_schema_entry("_overflow_nonexistent_");
            // get_schema_entry for unknown path always returns envelope — use that mapper.
            (overflow_entry.mapper)(&record.fields).map_err(|e| {
                anyhow::anyhow!(
                    "ZeekSink overflow mapper error for '{}': {e}",
                    record.log_path
                )
            })
        }
    }
}

// ---------------------------------------------------------------------------
// ZeekS3Handler — type alias + ZeekHandler impl
// ---------------------------------------------------------------------------

/// `ZeekS3Handler` is a thin alias for the generic `ParquetWriterHandle<ZeekSink>`.
pub type ZeekS3Handler = crate::forwarding::buffered_writer::ParquetWriterHandle<ZeekSink>;

#[async_trait::async_trait]
impl crate::zeek::listener::ZeekHandler
    for crate::forwarding::buffered_writer::ParquetWriterHandle<ZeekSink>
{
    async fn handle_record(&self, record: ZeekRecord, source: std::net::SocketAddr) {
        match self.try_send(record) {
            Ok(()) => {}
            Err(_dropped) => {
                // parquet_s3_dropped{source="zeek"} is already incremented by try_send.
                tracing::warn!("Zeek S3 channel full; dropped 1 record from {}", source);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// zeek_start — convenience constructor
// ---------------------------------------------------------------------------

/// Construct a `ZeekS3Handler` (i.e. `ParquetWriterHandle<ZeekSink>`) from a
/// `ZeekS3Config` and a pre-built `S3Sink`.
///
/// `max_partitions` is set to 256 (the old `MAX_ZEEK_STREAMS` value) unless the
/// config provides a higher or lower value (the config struct does not expose this
/// field, so we hard-code the default here — matching the old behavior).
///
/// Returns `(handler, writer_task_handle)`. The caller should retain the `JoinHandle`
/// and await it during graceful shutdown, after all `Arc<dyn ZeekHandler>` references
/// have been dropped so the channel closes and the final flush fires.
pub fn zeek_start(
    cfg: &ZeekS3Config,
    s3: std::sync::Arc<crate::forwarding::s3_sink::S3Sink>,
) -> (ZeekS3Handler, tokio::task::JoinHandle<()>) {
    use crate::forwarding::buffered_writer::{
        BufferedWriterConfig, FlushPolicy, ParquetWriterHandle,
    };

    /// Replaces the old `MAX_ZEEK_STREAMS` constant.
    const DEFAULT_MAX_ZEEK_PARTITIONS: usize = 256;

    let bwc = BufferedWriterConfig {
        connection: cfg.connection.clone(),
        prefix: cfg.prefix.clone(),
        max_buffer_rows: cfg.max_buffer_rows,
        flush_threshold_bytes: cfg.flush_threshold_bytes,
        flush_interval_secs: cfg.flush_interval_secs,
        channel_capacity: cfg.channel_capacity,
        max_partitions: DEFAULT_MAX_ZEEK_PARTITIONS,
    };
    let policy = FlushPolicy {
        max_rows: cfg.max_buffer_rows,
        max_bytes: cfg.flush_threshold_bytes,
        interval: std::time::Duration::from_secs(cfg.flush_interval_secs),
    };
    ParquetWriterHandle::start(ZeekSink, s3, bwc, policy)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::S3ConnectionConfig;
    use crate::forwarding::buffered_writer::{
        BufferedWriterConfig, FlushPolicy, ParquetSink, PartitionedParquetWriter,
    };
    use crate::forwarding::s3_sink::S3Sink;
    use crate::zeek::ZeekRecord;
    use chrono::Utc;
    use std::sync::Arc;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

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

    fn make_zeek_cfg(
        max_rows: usize,
        flush_bytes: usize,
        max_partitions: usize,
    ) -> (BufferedWriterConfig, FlushPolicy) {
        let bwc = BufferedWriterConfig {
            connection: S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "zeek".to_string(),
            max_buffer_rows: max_rows,
            flush_threshold_bytes: flush_bytes,
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_partitions,
        };
        let policy = FlushPolicy {
            max_rows,
            max_bytes: flush_bytes,
            interval: std::time::Duration::from_secs(3600),
        };
        (bwc, policy)
    }

    fn make_conn_record(uid: &str) -> ZeekRecord {
        ZeekRecord {
            log_path: "conn".to_string(),
            fields: serde_json::json!({
                "_path": "conn",
                "ts": 1700000000.0,
                "uid": uid,
                "id.orig_h": "10.0.0.1",
                "id.orig_p": 12345,
                "id.resp_h": "10.0.0.2",
                "id.resp_p": 80,
                "proto": "tcp",
                "conn_state": "SF",
                "orig_bytes": 512,
                "resp_bytes": 4096,
            }),
            received_at: Utc::now(),
        }
    }

    fn make_dns_record(uid: &str) -> ZeekRecord {
        ZeekRecord {
            log_path: "dns".to_string(),
            fields: serde_json::json!({
                "_path": "dns",
                "ts": 1700000100.0,
                "uid": uid,
                "id.orig_h": "192.168.1.100",
                "id.orig_p": 12345,
                "id.resp_h": "8.8.8.8",
                "id.resp_p": 53,
                "query": "example.com",
                "qtype_name": "A",
                "rcode_name": "NOERROR",
            }),
            received_at: Utc::now(),
        }
    }

    fn make_unknown_record() -> ZeekRecord {
        ZeekRecord {
            log_path: "weird".to_string(),
            fields: serde_json::json!({
                "_path": "weird",
                "ts": 1700000200.0,
                "uid": "CUnk1",
                "raw_data": "some weird log"
            }),
            received_at: Utc::now(),
        }
    }

    // -----------------------------------------------------------------------
    // sanitize_log_path tests
    // -----------------------------------------------------------------------

    #[test]
    fn log_path_sanitizer_handles_traversal() {
        assert_eq!(sanitize_log_path("../weird path"), "___weird_path");
        assert_eq!(sanitize_log_path("conn"), "conn");
        assert_eq!(sanitize_log_path("../foo"), "___foo");
        let out = sanitize_log_path("../../etc/passwd");
        assert!(!out.contains('/'), "sanitized path must not contain /");
        assert!(!out.contains('.'), "sanitized path must not contain .");
        assert_eq!(sanitize_log_path(""), "unknown");
        let long_input = "a".repeat(100);
        assert_eq!(sanitize_log_path(&long_input).len(), 64);
    }

    // -----------------------------------------------------------------------
    // ZeekSink unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn zeek_sink_source_returns_zeek() {
        assert_eq!(ZeekSink.source(), "zeek");
    }

    #[test]
    fn zeek_sink_partition_sanitizes_log_path() {
        let record = make_conn_record("C1");
        assert_eq!(ZeekSink.partition(&record), Some("conn".to_string()));

        let weird = ZeekRecord {
            log_path: "../etc/passwd".to_string(),
            fields: serde_json::json!({}),
            received_at: Utc::now(),
        };
        let part = ZeekSink.partition(&weird).unwrap();
        assert!(!part.contains('/'));
        assert!(!part.contains('.'));
    }

    #[test]
    fn zeek_sink_schema_typed_for_known_paths() {
        use crate::zeek::schema::{conn_schema, dns_schema};

        // Typed paths return typed schemas.
        assert_eq!(ZeekSink.schema(Some("conn")), conn_schema());
        assert_eq!(ZeekSink.schema(Some("dns")), dns_schema());

        // _overflow → envelope schema
        let overflow_schema = ZeekSink.schema(Some("_overflow"));
        assert!(
            overflow_schema.field_with_name("payload").is_ok(),
            "_overflow schema must be envelope (has 'payload' column)"
        );

        // None → envelope schema
        let none_schema = ZeekSink.schema(None);
        assert!(
            none_schema.field_with_name("payload").is_ok(),
            "None partition schema must be envelope"
        );

        // Unknown path → envelope schema (fallback)
        let unknown_schema = ZeekSink.schema(Some("notaknownpath"));
        assert!(
            unknown_schema.field_with_name("payload").is_ok(),
            "unknown path schema must be envelope fallback"
        );
    }

    #[test]
    fn zeek_sink_to_record_batch_conn() {
        let record = make_conn_record("C1");
        let schema = ZeekSink.schema(Some("conn"));
        let batch = ZeekSink.to_record_batch(&record, &schema).unwrap();
        assert_eq!(batch.num_rows(), 1);
        // conn schema has 'uid' column
        use arrow::array::StringArray;
        let uid = batch
            .column_by_name("uid")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(uid.value(0), "C1");
    }

    #[test]
    fn zeek_sink_to_record_batch_unknown_path_uses_envelope() {
        let record = make_unknown_record();
        // Unknown paths get envelope schema from schema()
        let schema = ZeekSink.schema(Some("weird"));
        let batch = ZeekSink.to_record_batch(&record, &schema).unwrap();
        assert_eq!(batch.num_rows(), 1);
        // Envelope schema has 'payload' column
        let col = batch.column_by_name("payload");
        assert!(col.is_some(), "envelope schema must have 'payload' column");
    }

    #[test]
    fn zeek_sink_to_record_batch_overflow_partition() {
        // When the partition is "_overflow", we use envelope schema.
        // The record may have any log_path — we test with a conn record.
        let record = make_conn_record("Overflow1");
        let schema = ZeekSink.schema(Some("_overflow"));
        // schema is envelope; to_record_batch must succeed (not panic).
        let result = ZeekSink.to_record_batch(&record, &schema);
        assert!(
            result.is_ok(),
            "to_record_batch must succeed for _overflow partition: {:?}",
            result.err()
        );
        let batch = result.unwrap();
        assert_eq!(batch.num_rows(), 1);
    }

    // -----------------------------------------------------------------------
    // S3 key layout verification
    // -----------------------------------------------------------------------

    #[test]
    fn build_key_produces_zeek_log_path_layout() {
        use crate::forwarding::buffered_writer::build_key;
        use chrono::TimeZone;

        let now = chrono::Utc.with_ymd_and_hms(2026, 3, 7, 0, 0, 0).unwrap();

        // zeek/<log_path>/year=…/month=…/day=…/<uuid>.parquet
        let key = build_key("zeek", Some("conn"), now);
        assert!(
            key.starts_with("zeek/conn/year=2026/month=03/day=07/"),
            "key: {key}"
        );
        assert!(key.ends_with(".parquet"), "key: {key}");

        let key = build_key("zeek", Some("dns"), now);
        assert!(key.starts_with("zeek/dns/year="), "key: {key}");

        let key = build_key("zeek", Some("_overflow"), now);
        assert!(key.starts_with("zeek/_overflow/year="), "key: {key}");
    }

    // -----------------------------------------------------------------------
    // PartitionedParquetWriter accumulation tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn writer_accumulates_per_partition_buffers() {
        let sink = unreachable_sink().await;
        let (bwc, policy) = make_zeek_cfg(100_000, usize::MAX, 256);
        let mut writer = PartitionedParquetWriter::new(ZeekSink, sink, bwc, policy);

        writer.push(make_conn_record("C1")).await.ok();
        writer.push(make_conn_record("C2")).await.ok();
        writer.push(make_dns_record("D1")).await.ok();
        writer.push(make_unknown_record()).await.ok();

        // conn → "conn" partition, dns → "dns" partition, weird → "weird" partition
        assert_eq!(
            writer.buffers.get("conn").map(|b| b.row_count).unwrap_or(0),
            2,
            "conn buffer should have 2 rows"
        );
        assert_eq!(
            writer.buffers.get("dns").map(|b| b.row_count).unwrap_or(0),
            1,
            "dns buffer should have 1 row"
        );
        assert_eq!(
            writer
                .buffers
                .get("weird")
                .map(|b| b.row_count)
                .unwrap_or(0),
            1,
            "weird buffer should have 1 row"
        );
    }

    #[tokio::test]
    async fn writer_bounded_under_s3_outage() {
        let sink = unreachable_sink().await;
        let max_rows = 2usize;
        let hard_cap = max_rows.saturating_mul(4);
        let (bwc, policy) = make_zeek_cfg(max_rows, 1, 256); // flush on every push

        let mut writer = PartitionedParquetWriter::new(ZeekSink, sink, bwc, policy);
        let total = hard_cap * 3;
        let mut errors = 0usize;
        for i in 0..total {
            let rec = make_conn_record(&format!("C{i}"));
            if writer.push(rec).await.is_err() {
                errors += 1;
            }
        }
        assert!(errors > 0, "expected flush errors under S3 outage");
        assert!(
            writer.buffers.get("conn").map(|b| b.row_count).unwrap_or(0) <= hard_cap,
            "conn buffer must stay at or below hard cap ({hard_cap})"
        );
    }

    // -----------------------------------------------------------------------
    // Partition cap test — overflow to "_overflow"
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn writer_partition_cap_overflows_to_overflow_buffer() {
        let sink = unreachable_sink().await;
        let cap = 3usize;
        let (bwc, policy) = make_zeek_cfg(100_000, usize::MAX, cap);
        let mut writer = PartitionedParquetWriter::new(ZeekSink, sink, bwc, policy);

        // Push records with cap+5 distinct log_paths.
        for i in 0..(cap + 5) {
            let rec = ZeekRecord {
                log_path: format!("stream_{i}"),
                fields: serde_json::json!({
                    "_path": format!("stream_{i}"),
                    "ts": 1700000000.0,
                    "uid": format!("C{i}"),
                }),
                received_at: Utc::now(),
            };
            writer.push(rec).await.ok();
        }

        // Map size must be <= cap + 1 (the +1 is the "_overflow" buffer)
        assert!(
            writer.buffers.len() <= cap + 1,
            "buffers map must be bounded; got {} (cap={})",
            writer.buffers.len(),
            cap
        );
        // The "_overflow" buffer must exist.
        assert!(
            writer.buffers.contains_key("_overflow"),
            "_overflow buffer must exist after cap exceeded"
        );
        // The "_overflow" buffer must have rows and a valid (non-empty) schema.
        let ov = writer.buffers.get("_overflow").unwrap();
        assert!(ov.row_count > 0, "_overflow must contain records");
        assert!(
            !ov.schema.fields().is_empty(),
            "_overflow must have a valid schema"
        );
    }

    // -----------------------------------------------------------------------
    // Handler overflow drops and increments parquet_s3_dropped{source="zeek"}
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[allow(clippy::mutable_key_type)]
    async fn handler_overflow_increments_dropped_counter() {
        use crate::zeek::listener::ZeekHandler;
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::DebuggingRecorder;
        use std::net::SocketAddr;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let sink = unreachable_sink().await;
        let cfg = ZeekS3Config {
            connection: S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "zeek".to_string(),
            flush_threshold_bytes: 1,
            flush_interval_secs: 3600,
            channel_capacity: 1,
            max_buffer_rows: 1,
        };
        let (handler, _writer_handle) = zeek_start(&cfg, sink);
        tokio::task::yield_now().await;

        let src: SocketAddr = "127.0.0.1:47760".parse().unwrap();
        for i in 0..50usize {
            let rec = make_conn_record(&format!("C{i}"));
            handler.handle_record(rec, src).await;
        }
        tokio::task::yield_now().await;

        let snapshot = snapshotter.snapshot();
        let map = snapshot.into_hashmap();
        let key = CompositeKey::new(
            MetricKind::Counter,
            metrics::Key::from_parts(
                "parquet_s3_dropped",
                vec![metrics::Label::new("source", "zeek")],
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
            "expected parquet_s3_dropped{{source=\"zeek\"}} >= 1; got {dropped}"
        );
    }

    // -----------------------------------------------------------------------
    // zeek_start wires handler and join handle
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn zeek_start_wires_handler_and_join_handle() {
        use crate::zeek::listener::ZeekHandler;
        use std::net::SocketAddr;

        let sink = unreachable_sink().await;
        let cfg = ZeekS3Config {
            connection: S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "zeek".to_string(),
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_buffer_rows: 100_000,
        };
        let (handler, join_handle) = zeek_start(&cfg, sink);

        let src: SocketAddr = "127.0.0.1:47760".parse().unwrap();
        handler.handle_record(make_conn_record("C1"), src).await;

        // Drop the handler to close the channel and trigger shutdown flush.
        drop(handler);

        // Join the background task within 5s.
        tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("writer task must exit within 5s")
            .expect("writer task must not panic");
    }

    // -----------------------------------------------------------------------
    // Integration test (gated on env var)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn integration_records_produce_parquet_in_s3() {
        if std::env::var("ZEEK_S3_INTEGRATION_TEST").is_err() {
            eprintln!("skipping; set ZEEK_S3_INTEGRATION_TEST=1 to run against local MinIO");
            return;
        }
        use crate::zeek::listener::ZeekHandler;

        let bucket = std::env::var("ZEEK_S3_BUCKET").unwrap_or_else(|_| "zeek-test".to_string());
        let conn = S3ConnectionConfig {
            endpoint: "http://localhost:9000".to_string(),
            bucket: bucket.clone(),
            region: "us-east-1".to_string(),
            access_key: "minioadmin".to_string(),
            secret_key: "minioadmin".to_string(),
        };
        let sink = Arc::new(
            S3Sink::from_connection(&conn)
                .await
                .expect("S3Sink construct"),
        );
        let cfg = ZeekS3Config {
            connection: conn.clone(),
            prefix: "zeek".to_string(),
            flush_threshold_bytes: 1,
            flush_interval_secs: 1,
            channel_capacity: 256,
            max_buffer_rows: 100_000,
        };
        let (handler, _writer_handle) = zeek_start(&cfg, sink);
        let src: std::net::SocketAddr = "127.0.0.1:47760".parse().unwrap();

        for i in 0..5usize {
            handler
                .handle_record(make_conn_record(&format!("CInteg{i}")), src)
                .await;
        }
        for i in 0..3usize {
            handler
                .handle_record(make_dns_record(&format!("DInteg{i}")), src)
                .await;
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        use aws_config::meta::region::RegionProviderChain;
        use aws_credential_types::{Credentials, provider::SharedCredentialsProvider};
        use aws_sdk_s3::Client as S3Client;
        use aws_sdk_s3::config::Builder as S3ConfigBuilder;

        let region = RegionProviderChain::first_try(aws_sdk_s3::config::Region::new(
            "us-east-1".to_string(),
        ));
        let sdk_cfg = aws_config::from_env()
            .region(region)
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
        let s3_cfg = S3ConfigBuilder::from(&sdk_cfg)
            .credentials_provider(creds)
            .force_path_style(true)
            .build();
        let client = S3Client::from_conf(s3_cfg);

        for prefix in &["zeek/conn/", "zeek/dns/"] {
            let resp = client
                .list_objects_v2()
                .bucket(&bucket)
                .prefix(*prefix)
                .send()
                .await
                .expect("list_objects_v2");
            assert!(
                !resp.contents().is_empty(),
                "expected >= 1 Parquet object under {prefix}"
            );
        }
    }
}
