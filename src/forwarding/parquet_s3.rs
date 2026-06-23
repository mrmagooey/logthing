//! WEF (Windows Event Forwarding) → S3 Parquet persistence.
//!
//! Provides:
//! - `WefSink` — `ParquetSink` adapter for WEF events
//! - `wef_start()` — convenience constructor wiring `WefS3Config` → `ParquetWriterHandle`
//!
//! S3 KEY LAYOUT: `event_type=<id>/year=Y/month=MM/day=DD/<uuid>.parquet`
//! (empty prefix, preserving the legacy layout — behavior-preserving choice (a)).

use crate::config::WefS3Config;
use crate::forwarding::buffered_writer::ParquetSink;
use crate::models::WindowsEvent;
use arrow::array::{ArrayRef, StringArray, UInt32Array};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// WefSink — ParquetSink adapter
// ---------------------------------------------------------------------------

/// `ParquetSink` adapter for Windows Event Forwarding records.
///
/// - `Record` = `Arc<WindowsEvent>` (matches the channel item type).
/// - `partition()` = `Some("event_type=<event_id>")` from the parsed EventID.
///   If the event has no parsed data, returns `Some("event_type=0")` as a safe
///   sentinel — but `to_record_batch` will return `Err` to skip unparsed events.
/// - `schema()` = fixed 5-column WEF schema (unchanged from legacy writer).
/// - `to_record_batch()` = returns `Err` for events with no parsed data (generic
///   writer logs + skips, matching legacy "silently skipped" behavior).
///
/// **S3 KEY LAYOUT (choice a — behavior-preserving):**
/// `event_type=<id>/year=Y/month=MM/day=DD/<uuid>.parquet`
/// Achieved by using an empty prefix (`""`), so `build_key("", Some("event_type=4624"), now)`
/// → `event_type=4624/year=…`. No leading slash (verified in generic unit test).
pub struct WefSink;

impl ParquetSink for WefSink {
    type Record = Arc<WindowsEvent>;

    fn source(&self) -> &'static str {
        "wef"
    }

    fn partition(&self, record: &Arc<WindowsEvent>) -> Option<String> {
        // Use parsed EventID for partition; if none, use sentinel "event_type=0".
        // to_record_batch will return Err for unparsed events so they are skipped.
        let event_id = record.parsed.as_ref().map(|p| p.event_id).unwrap_or(0);
        Some(format!("event_type={}", event_id))
    }

    fn schema(&self, _partition: Option<&str>) -> Arc<arrow_schema::Schema> {
        Arc::new(Schema::new(vec![
            Field::new("event_id", DataType::UInt32, false),
            Field::new("timestamp", DataType::Utf8, false),
            Field::new("source_host", DataType::Utf8, false),
            Field::new("subscription_id", DataType::Utf8, true),
            Field::new("event_data", DataType::Utf8, false),
        ]))
    }

    fn to_record_batch(
        &self,
        record: &Arc<WindowsEvent>,
        schema: &Arc<arrow_schema::Schema>,
    ) -> anyhow::Result<arrow_array::RecordBatch> {
        // Unparsed events are silently skipped (matches legacy behavior).
        // Return Err here; the generic writer logs a warn and continues.
        let parsed = record
            .parsed
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("WEF event has no parsed data; skipping"))?;

        let event_data = serde_json::to_string(record.as_ref())
            .map_err(|e| anyhow::anyhow!("WEF event JSON serialization failed: {e}"))?;

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(UInt32Array::from(vec![parsed.event_id])) as ArrayRef,
                Arc::new(StringArray::from(vec![record.received_at.to_rfc3339()])) as ArrayRef,
                Arc::new(StringArray::from(vec![record.source_host.as_str()])) as ArrayRef,
                Arc::new(StringArray::from(vec![record.subscription_id.as_deref()])) as ArrayRef,
                Arc::new(StringArray::from(vec![event_data.as_str()])) as ArrayRef,
            ],
        )?;
        Ok(batch)
    }
}

// ---------------------------------------------------------------------------
// wef_start — convenience constructor
// ---------------------------------------------------------------------------

/// Construct a `ParquetWriterHandle<WefSink>` from a `WefS3Config` and a pre-built `S3Sink`.
///
/// Returns `(handle, writer_task_handle)`. The caller must retain the `JoinHandle` and
/// await it during graceful shutdown. When `AppState` drops its `ParquetWriterHandle<WefSink>`,
/// the channel closes, the background task flushes, and the `JoinHandle` completes.
pub fn wef_start(
    cfg: &WefS3Config,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
) -> (
    crate::forwarding::buffered_writer::ParquetWriterHandle<WefSink>,
    tokio::task::JoinHandle<()>,
) {
    use crate::forwarding::buffered_writer::{
        BufferedWriterConfig, FlushPolicy, ParquetWriterHandle,
    };
    let bwc = BufferedWriterConfig {
        connection: cfg.connection.clone(),
        prefix: cfg.prefix.clone(), // "" for behavior-preserving empty-prefix layout
        max_buffer_rows: cfg.max_buffer_rows,
        flush_threshold_bytes: cfg.flush_threshold_bytes,
        flush_interval_secs: cfg.flush_interval_secs,
        channel_capacity: cfg.channel_capacity,
        max_partitions: 0, // unlimited — EventIDs are bounded in practice
    };
    let policy = FlushPolicy {
        max_rows: cfg.max_buffer_rows,
        max_bytes: cfg.flush_threshold_bytes,
        interval: std::time::Duration::from_secs(cfg.flush_interval_secs),
    };
    ParquetWriterHandle::start(WefSink, s3, bwc, policy)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WefS3Config;
    use crate::forwarding::buffered_writer::ParquetSink;
    use crate::models::{EventLevel, ParsedEvent, WindowsEvent};
    use chrono::Utc;

    fn sample_parsed_event(event_id: u32) -> ParsedEvent {
        ParsedEvent {
            provider: "Security".into(),
            event_id,
            level: EventLevel::Information,
            task: 0,
            opcode: 0,
            keywords: 0,
            time_created: Utc::now(),
            event_record_id: 1,
            process_id: None,
            thread_id: None,
            channel: "Security".into(),
            computer: "HOST".into(),
            security_user_id: None,
            message: None,
            data: None,
        }
    }

    fn make_parsed_event(event_id: u32) -> Arc<WindowsEvent> {
        Arc::new(
            WindowsEvent::new("host".into(), "<Event/>".into())
                .with_parsed(sample_parsed_event(event_id)),
        )
    }

    fn make_unparsed_event() -> Arc<WindowsEvent> {
        Arc::new(WindowsEvent::new("host".into(), "<Event/>".into()))
    }

    // WefSink unit tests

    #[test]
    fn wef_sink_source_returns_wef() {
        assert_eq!(WefSink.source(), "wef");
    }

    #[test]
    fn wef_sink_schema_has_five_columns() {
        let schema = WefSink.schema(None);
        assert_eq!(schema.fields().len(), 5);
        assert!(schema.field_with_name("event_id").is_ok());
        assert!(schema.field_with_name("timestamp").is_ok());
        assert!(schema.field_with_name("source_host").is_ok());
        assert!(schema.field_with_name("subscription_id").is_ok());
        assert!(schema.field_with_name("event_data").is_ok());
    }

    #[test]
    fn wef_sink_partition_uses_event_id() {
        let event = make_parsed_event(4624);
        assert_eq!(
            WefSink.partition(&event),
            Some("event_type=4624".to_string())
        );
    }

    #[test]
    fn wef_sink_partition_unparsed_uses_sentinel() {
        let event = make_unparsed_event();
        // Sentinel "event_type=0" — to_record_batch will Err and skip it
        assert_eq!(WefSink.partition(&event), Some("event_type=0".to_string()));
    }

    #[test]
    fn wef_sink_to_record_batch_parsed_event() {
        let event = make_parsed_event(4624);
        let schema = WefSink.schema(Some("event_type=4624"));
        let batch = WefSink.to_record_batch(&event, &schema).expect("ok");
        assert_eq!(batch.num_rows(), 1);

        use arrow::array::{StringArray, UInt32Array};
        let id_col = batch
            .column_by_name("event_id")
            .unwrap()
            .as_any()
            .downcast_ref::<UInt32Array>()
            .unwrap();
        assert_eq!(id_col.value(0), 4624);

        let host_col = batch
            .column_by_name("source_host")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(host_col.value(0), "host");
    }

    #[test]
    fn wef_sink_to_record_batch_unparsed_returns_err() {
        let event = make_unparsed_event();
        let schema = WefSink.schema(None);
        let result = WefSink.to_record_batch(&event, &schema);
        assert!(
            result.is_err(),
            "unparsed event must return Err (will be skipped by generic writer)"
        );
    }

    #[test]
    fn wef_sink_schema_unchanged_for_any_partition() {
        // Schema must be identical regardless of partition segment
        let s1 = WefSink.schema(None);
        let s2 = WefSink.schema(Some("event_type=4624"));
        let s3 = WefSink.schema(Some("event_type=4625"));
        assert_eq!(s1, s2);
        assert_eq!(s2, s3);
    }

    #[test]
    fn s3_key_layout_empty_prefix_produces_correct_path() {
        use crate::forwarding::buffered_writer::build_key;
        use chrono::TimeZone;
        let now = chrono::Utc.with_ymd_and_hms(2026, 6, 21, 0, 0, 0).unwrap();
        let key = build_key("", Some("event_type=4624"), now);
        assert!(
            key.starts_with("event_type=4624/year=2026/month=06/day=21/"),
            "WEF S3 key must match legacy layout: {key}"
        );
        assert!(!key.starts_with('/'), "must not start with /");
        assert!(!key.contains("//"), "must not have double-slash");
        assert!(key.ends_with(".parquet"));
    }

    #[tokio::test]
    async fn wef_start_spawns_and_exits_cleanly() {
        use crate::config::S3ConnectionConfig;
        use crate::forwarding::s3_sink::S3Sink;

        let conn = S3ConnectionConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            bucket: "test-bucket".to_string(),
            region: "us-east-1".to_string(),
            access_key: "K".to_string(),
            secret_key: "S".to_string(),
        };
        let s3 = Arc::new(S3Sink::from_connection(&conn).await.expect("construct"));
        let cfg = WefS3Config {
            connection: conn,
            prefix: "".to_string(),
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_buffer_rows: 100_000,
        };
        let (handle, jh) = wef_start(&cfg, s3);

        // Send a parsed event — should be accepted
        let event = make_parsed_event(4624);
        assert!(handle.try_send(event).is_ok());

        // Drop handle → closes channel → writer flushes + exits
        drop(handle);
        tokio::time::timeout(std::time::Duration::from_secs(5), jh)
            .await
            .expect("writer must exit within 5s")
            .expect("writer must not panic");
    }

    #[tokio::test]
    async fn unparsed_events_are_skipped_not_stored() {
        // Verify that the generic writer's to_record_batch error path is triggered
        // for unparsed events (they are logged+skipped, not stored).
        use crate::config::S3ConnectionConfig;
        use crate::forwarding::buffered_writer::{
            BufferedWriterConfig, FlushPolicy, PartitionedParquetWriter,
        };
        use crate::forwarding::s3_sink::S3Sink;

        let conn = S3ConnectionConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            bucket: "t".to_string(),
            region: "us-east-1".to_string(),
            access_key: "K".to_string(),
            secret_key: "S".to_string(),
        };
        let s3 = Arc::new(S3Sink::from_connection(&conn).await.expect("construct"));
        let cfg = BufferedWriterConfig {
            connection: conn,
            prefix: "".to_string(),
            max_buffer_rows: 100_000,
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_partitions: 0,
        };
        let policy = FlushPolicy {
            max_rows: 100_000,
            max_bytes: usize::MAX,
            interval: std::time::Duration::from_secs(3600),
        };
        let mut writer = PartitionedParquetWriter::new(WefSink, s3, cfg, policy);

        // Push unparsed event — to_record_batch returns Err → push returns Ok (skipped)
        let unparsed = make_unparsed_event();
        let result = writer.push(unparsed).await;
        assert!(
            result.is_ok(),
            "unparsed event must not propagate error: {result:?}"
        );

        // The buffer for event_type=0 should exist but be EMPTY (record skipped)
        // Actually: the buffer might not exist at all if the skip happens before insertion.
        // Check: row_count is 0 for any partition, or the partition doesn't exist.
        let total_rows: usize = writer.buffers.values().map(|b| b.row_count).sum();
        assert_eq!(
            total_rows, 0,
            "unparsed events must not add rows to any buffer"
        );
    }
}
