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
use arrow::array::{ArrayRef, StringBuilder, TimestampMicrosecondBuilder, UInt32Builder};
use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use arrow::record_batch::RecordBatch;
use std::sync::{Arc, LazyLock};

/// Fixed WEF schema. `LazyLock`, not a fresh `Arc::new(Schema::new(...))` per
/// call: `push()` calls `schema()` once per record, and before this each call
/// allocated a new `Schema` (6 `Field`s plus the `Vec`/`Arc` wrappers) —
/// ~8 heap allocations per Windows event that every other sink in this file
/// tree avoids by caching its schema statically.
static WEF_SCHEMA: LazyLock<Arc<Schema>> = LazyLock::new(|| {
    Arc::new(Schema::new(vec![
        Field::new("event_id", DataType::UInt32, false),
        Field::new(
            "timestamp",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            false,
        ),
        Field::new("source_host", DataType::Utf8, false),
        Field::new("subscription_id", DataType::Utf8, true),
        Field::new("event_data", DataType::Utf8, false),
        Field::new(
            "partition_time",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            false,
        ),
    ]))
});

// ---------------------------------------------------------------------------
// WefSink — ParquetSink adapter
// ---------------------------------------------------------------------------

/// `ParquetSink` adapter for Windows Event Forwarding records.
///
/// - `Record` = `Arc<WindowsEvent>` (matches the channel item type).
/// - `partition()` = `Some("event_type=<event_id>")` from the parsed EventID.
///   If the event has no parsed data, returns `Some("event_type=0")` as a safe
///   sentinel — but `to_record_batch` will return `Err` to skip unparsed events.
/// - `schema()` = fixed 6-column WEF schema (5 legacy columns plus
///   `partition_time`).
/// - `to_record_batch()` = returns `Err` for events with no parsed data (generic
///   writer logs + skips, matching legacy "silently skipped" behavior).
///
/// **S3 KEY LAYOUT (choice a — behavior-preserving):**
/// `event_type=<id>/year=Y/month=MM/day=DD/<uuid>.parquet`
/// Achieved by using an empty prefix (`""`), so `build_key("", Some("event_type=4624"), day)`
/// → `event_type=4624/year=…`. No leading slash (verified in generic unit test).
#[derive(Default)]
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
        WEF_SCHEMA.clone()
    }

    /// Time column for day bucketing. Despite its name, the `timestamp`
    /// column is written from `record.received_at` (server receipt time),
    /// NOT the event's own `time_created` from the Windows Event Log --
    /// see `to_record_batch` below. `partition_time` is derived from that
    /// same `received_at` value, so WEF files partition by when logthing
    /// received an event, not when Windows recorded it.
    fn time_column(&self) -> Option<&'static str> {
        Some("partition_time")
    }

    fn to_record_batch(
        &self,
        record: &Arc<WindowsEvent>,
        _schema: &Arc<arrow_schema::Schema>,
    ) -> anyhow::Result<arrow_array::RecordBatch> {
        let mut acc = WefAccumulator::new();
        acc.append_event(record)?;
        acc.finish_batch()
    }

    /// Opt into the amortized builder path. Gated on the schema Arc even
    /// though this sink has one schema, mirroring the other sinks.
    fn new_batch(
        &self,
        schema: &Arc<arrow_schema::Schema>,
    ) -> Option<
        Box<dyn crate::forwarding::buffered_writer::RecordBatchAccumulator<Arc<WindowsEvent>>>,
    > {
        if Arc::ptr_eq(schema, &WEF_SCHEMA) {
            Some(Box::new(WefAccumulator::new()))
        } else {
            None
        }
    }

    /// Overrides the default `day_and_batch`, which would call
    /// `to_record_batch` and read the day off the built batch -- allocating
    /// the full builder set on every push before `new_batch`'s accumulator is
    /// consulted, making the amortized path a no-op.
    ///
    /// `partition_time` is written as `partition_time(Some(received_at),
    /// received_at)`, so this reproduces the default's row-0 read exactly.
    /// Unparsed events (which `to_record_batch` rejects) still get a day here;
    /// they are dropped later by the per-record fallback, exactly as before.
    fn day_and_batch(
        &self,
        record: &Arc<WindowsEvent>,
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

/// Amortized builder set for the WEF schema. Holds the six columns
/// `to_record_batch` used to build fresh per record as persistent builders.
///
/// The row mapping lives here exactly once; `WefSink::to_record_batch` is a
/// `new -> append -> finish` wrapper over it, so the amortized path and the
/// single-record fallback cannot drift apart.
pub(crate) struct WefAccumulator {
    b_event_id: UInt32Builder,
    b_timestamp: TimestampMicrosecondBuilder,
    b_source_host: StringBuilder,
    b_subscription_id: StringBuilder,
    b_event_data: StringBuilder,
    b_partition_time: TimestampMicrosecondBuilder,
    rows: usize,
}

impl WefAccumulator {
    pub(crate) fn new() -> Self {
        let ts = || {
            TimestampMicrosecondBuilder::new().with_data_type(DataType::Timestamp(
                TimeUnit::Microsecond,
                Some("UTC".into()),
            ))
        };
        Self {
            b_event_id: UInt32Builder::new(),
            b_timestamp: ts(),
            b_source_host: StringBuilder::new(),
            b_subscription_id: StringBuilder::new(),
            b_event_data: StringBuilder::new(),
            b_partition_time: ts(),
            rows: 0,
        }
    }

    /// Append one event. Returns `Err` for an unparsed event or a
    /// serialization failure, matching the original mapper's contract --
    /// the generic writer logs a warn and skips.
    fn append_event(&mut self, record: &Arc<WindowsEvent>) -> anyhow::Result<()> {
        // Unparsed events are silently skipped (matches legacy behavior).
        let parsed = record
            .parsed
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("WEF event has no parsed data; skipping"))?;
        let event_data = serde_json::to_string(record.as_ref())
            .map_err(|e| anyhow::anyhow!("WEF event JSON serialization failed: {e}"))?;

        // `timestamp` is already `record.received_at` (server receipt time),
        // not an event-carried timestamp, so it is both the event and the
        // receipt instant here. Routed through the shared helper (rather
        // than assigned directly) so every sink derives `partition_time` via
        // one code path.
        let partition_time = crate::forwarding::buffered_writer::partition_time(
            Some(record.received_at),
            record.received_at,
        );

        self.b_event_id.append_value(parsed.event_id);
        self.b_timestamp
            .append_value(record.received_at.timestamp_micros());
        self.b_source_host.append_value(&record.source_host);
        self.b_subscription_id
            .append_option(record.subscription_id.as_deref());
        self.b_event_data.append_value(&event_data);
        self.b_partition_time
            .append_value(partition_time.timestamp_micros());
        self.rows += 1;
        Ok(())
    }

    fn finish_batch(&mut self) -> anyhow::Result<RecordBatch> {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(self.b_event_id.finish()),
            Arc::new(self.b_timestamp.finish()),
            Arc::new(self.b_source_host.finish()),
            Arc::new(self.b_subscription_id.finish()),
            Arc::new(self.b_event_data.finish()),
            Arc::new(self.b_partition_time.finish()),
        ];
        self.rows = 0;
        Ok(RecordBatch::try_new(WEF_SCHEMA.clone(), columns)?)
    }
}

impl crate::forwarding::buffered_writer::RecordBatchAccumulator<Arc<WindowsEvent>>
    for WefAccumulator
{
    /// Returns `Ok(false)` for an event this accumulator cannot take, so
    /// `push()` falls back to `to_record_batch` for that one record --
    /// which returns `Err`, and the writer logs a warn and skips it. That
    /// reproduces the pre-accumulator behaviour for unparsed events exactly,
    /// rather than inventing a second skip path here.
    ///
    /// `_now` is unused: `WindowsEvent` carries its own `received_at`.
    fn try_append(
        &mut self,
        record: &Arc<WindowsEvent>,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<bool> {
        if record.parsed.is_none() {
            return Ok(false);
        }
        self.append_event(record)?;
        Ok(true)
    }

    fn len(&self) -> usize {
        self.rows
    }

    fn finish(&mut self) -> anyhow::Result<RecordBatch> {
        self.finish_batch()
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
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<Arc<dyn crate::forwarding::buffered_writer::UploadSink>>,
) -> (
    crate::forwarding::buffered_writer::ParquetWriterHandle<WefSink>,
    tokio::task::JoinHandle<()>,
) {
    crate::forwarding::buffered_writer::start_writer::<WefSink>(
        cfg.prefix.clone(), // "" for behavior-preserving empty-prefix layout
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        0, // unlimited partitions — EventIDs are bounded in practice
        s3,
        source_stats,
        descriptor_sink,
    )
}

/// Construct a `ParquetWriterHandle<WefSink>` from a `WefLocalConfig` and a
/// pre-built `LocalDiskSink`. Structurally identical to `wef_start`, writing
/// to local disk instead of S3 — same `WefSink` adapter, same
/// buffering/flush/cap machinery, same S3-key-shaped relative path layout
/// on disk.
pub fn wef_local_start(
    cfg: &crate::config::WefLocalConfig,
    sink: Arc<crate::forwarding::local_sink::LocalDiskSink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<Arc<dyn crate::forwarding::buffered_writer::UploadSink>>,
) -> (
    crate::forwarding::buffered_writer::ParquetWriterHandle<WefSink>,
    tokio::task::JoinHandle<()>,
) {
    crate::forwarding::buffered_writer::start_writer::<WefSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        0,
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
    use crate::config::WefS3Config;
    use crate::forwarding::buffered_writer::ParquetSink;
    use crate::models::{EventLevel, ParsedEvent, WindowsEvent};
    use arrow::array::TimestampMicrosecondArray;
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

    // -- RecordBatchAccumulator (amortized builder path) --

    /// The amortized path must produce byte-identical columns to the
    /// single-record path, including the nullable `subscription_id`.
    #[test]
    fn wef_accumulator_matches_single_record_batches_column_for_column() {
        use crate::forwarding::buffered_writer::RecordBatchAccumulator;
        let events = [
            make_parsed_event(4624),
            make_parsed_event(4625),
            make_parsed_event(4688),
        ];
        let schema = WefSink.schema(None);

        let mut acc = WefAccumulator::new();
        assert!(acc.is_empty());
        for (i, e) in events.iter().enumerate() {
            assert!(acc.try_append(e, Utc::now()).unwrap());
            assert_eq!(acc.len(), i + 1);
        }
        let batched = acc.finish().unwrap();
        assert_eq!(batched.num_rows(), events.len());

        for (i, e) in events.iter().enumerate() {
            let single = WefSink.to_record_batch(e, &schema).unwrap();
            for col in 0..single.num_columns() {
                assert_eq!(
                    single.column(col).to_data(),
                    batched.column(col).slice(i, 1).to_data(),
                    "row {i} column {} differs between amortized and single-record paths",
                    schema.field(col).name()
                );
            }
        }
    }

    /// An unparsed event must be REJECTED by try_append (Ok(false)) so push()
    /// falls back to to_record_batch, which errors and makes the writer log
    /// and skip it -- the pre-accumulator behaviour. Appending it instead
    /// would either panic or write a bogus row.
    #[test]
    fn wef_accumulator_rejects_unparsed_event_and_appends_nothing() {
        use crate::forwarding::buffered_writer::RecordBatchAccumulator;
        let mut acc = WefAccumulator::new();
        assert!(
            !acc.try_append(&make_unparsed_event(), Utc::now()).unwrap(),
            "unparsed event must return Ok(false) so the per-record fallback skips it"
        );
        assert_eq!(acc.len(), 0, "a rejected event must not add a row");
        assert!(acc.is_empty());

        // And the fallback it defers to still errors, as before.
        let schema = WefSink.schema(None);
        assert!(
            WefSink
                .to_record_batch(&make_unparsed_event(), &schema)
                .is_err(),
            "to_record_batch must still reject unparsed events"
        );
    }

    /// A builder retaining prior rows would silently duplicate data into the
    /// next flush.
    #[test]
    fn wef_accumulator_finish_twice_produces_independent_batches() {
        use crate::forwarding::buffered_writer::RecordBatchAccumulator;
        let mut acc = WefAccumulator::new();
        acc.try_append(&make_parsed_event(1), Utc::now()).unwrap();
        acc.try_append(&make_parsed_event(2), Utc::now()).unwrap();
        let first = acc.finish().unwrap();
        assert_eq!(first.num_rows(), 2);
        assert_eq!(acc.len(), 0);

        acc.try_append(&make_parsed_event(3), Utc::now()).unwrap();
        let second = acc.finish().unwrap();
        assert_eq!(second.num_rows(), 1);
        let ids = second
            .column_by_name("event_id")
            .unwrap()
            .as_any()
            .downcast_ref::<arrow::array::UInt32Array>()
            .unwrap();
        assert_eq!(ids.value(0), 3);
    }

    /// Guards the silent no-op: new_batch returning None would leave push()
    /// allocating a fresh builder set per record, with every other test still
    /// passing.
    #[test]
    fn wef_new_batch_activates_for_the_real_schema_and_not_an_unrelated_one() {
        let schema = WefSink.schema(None);
        assert!(Arc::ptr_eq(&schema, &WEF_SCHEMA));
        assert!(
            WefSink.new_batch(&schema).is_some(),
            "new_batch must return Some -- if None, the accumulator never activates"
        );
        let other: Arc<Schema> = Arc::new(Schema::new(vec![Field::new(
            "unrelated",
            DataType::Utf8,
            false,
        )]));
        assert!(WefSink.new_batch(&other).is_none());
    }

    /// day_and_batch must give the day the default would have read off row 0,
    /// and must NOT build a batch -- building one reinstates the per-push
    /// allocation the override exists to remove.
    #[test]
    fn wef_day_and_batch_matches_default_mechanism_without_building_a_batch() {
        let e = make_parsed_event(4624);
        let schema = WefSink.schema(None);
        let (day, batch) = WefSink.day_and_batch(&e, &schema, Utc::now()).unwrap();
        assert!(batch.is_none(), "must not build a batch");

        let built = WefSink.to_record_batch(&e, &schema).unwrap();
        let pt = built
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<arrow::array::TimestampMicrosecondArray>()
            .unwrap();
        let expected = chrono::DateTime::from_timestamp_micros(pt.value(0))
            .unwrap()
            .date_naive();
        assert_eq!(day, expected);
    }

    // WefSink unit tests

    #[test]
    fn wef_sink_source_returns_wef() {
        assert_eq!(WefSink.source(), "wef");
    }

    #[test]
    fn wef_sink_schema_has_six_columns() {
        let schema = WefSink.schema(None);
        assert_eq!(schema.fields().len(), 6);
        assert!(schema.field_with_name("event_id").is_ok());
        assert!(schema.field_with_name("timestamp").is_ok());
        assert!(schema.field_with_name("source_host").is_ok());
        assert!(schema.field_with_name("subscription_id").is_ok());
        assert!(schema.field_with_name("event_data").is_ok());
        assert!(schema.field_with_name("partition_time").is_ok());
    }

    #[test]
    fn schema_partition_time_is_non_null_microsecond_timestamp() {
        use arrow::datatypes::{DataType, TimeUnit};
        let schema = WefSink.schema(None);
        let f = schema.field_with_name("partition_time").unwrap();
        assert_eq!(
            f.data_type(),
            &DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
        );
        assert!(!f.is_nullable(), "partition_time must be non-nullable");
    }

    #[test]
    fn schema_timestamp_is_microsecond_timestamp() {
        use arrow::datatypes::{DataType, TimeUnit};
        let schema = WefSink.schema(None);
        let f = schema.field_with_name("timestamp").unwrap();
        assert_eq!(
            f.data_type(),
            &DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
        );
        assert!(!f.is_nullable());
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

        let ts_col = batch
            .column_by_name("timestamp")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .expect("timestamp column should be TimestampMicrosecondArray");
        assert_eq!(ts_col.value(0), event.received_at.timestamp_micros());
    }

    #[test]
    fn wef_sink_to_record_batch_partition_time_equals_received_at() {
        // A distinctive, non-"now" instant: a broken mapper that fell back
        // to Utc::now() or the epoch would visibly fail this.
        let mut event = WindowsEvent::new("host".into(), "<Event/>".into())
            .with_parsed(sample_parsed_event(4624));
        event.received_at = chrono::DateTime::parse_from_rfc3339("2024-07-19T02:41:09.987654Z")
            .unwrap()
            .with_timezone(&Utc);
        let event = Arc::new(event);
        let schema = WefSink.schema(Some("event_type=4624"));
        let batch = WefSink.to_record_batch(&event, &schema).expect("ok");

        let partition_time_col = batch
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .expect("partition_time column should be TimestampMicrosecondArray");
        assert_eq!(
            partition_time_col.value(0),
            event.received_at.timestamp_micros()
        );
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
        let day = chrono::NaiveDate::from_ymd_opt(2026, 6, 21).unwrap();
        let key = build_key("", Some("event_type=4624"), day);
        assert!(
            key.starts_with("event_type=4624/year=2026/month=06/day=21/"),
            "WEF S3 key must match legacy layout: {key}"
        );
        assert!(!key.starts_with('/'), "must not start with /");
        assert!(!key.contains("//"), "must not have double-slash");
        assert!(key.ends_with(".parquet"));
    }

    #[test]
    fn wef_sink_time_column_timestamp_exists_in_schema() {
        let sink = WefSink;
        let col = sink
            .time_column()
            .expect("wef_sink must opt in to day partitioning");
        // Pin the exact column name, not just that SOME name resolves.
        assert_eq!(col, "partition_time");
        // Use a valid partition format (event_type=4624)
        let schema = sink.schema(Some("event_type=4624"));
        assert!(
            schema.field_with_name(col).is_ok(),
            "time_column() returned {:?}, which is not a field in the schema",
            col
        );
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
        let (handle, jh) = wef_start(
            &cfg,
            s3,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );

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
    async fn wef_local_start_spawns_and_exits_cleanly() {
        use crate::config::WefLocalConfig;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let sink = Arc::new(
            crate::forwarding::local_sink::LocalDiskSink::new(dir.path().to_path_buf())
                .await
                .expect("constructs"),
        );
        let cfg = WefLocalConfig {
            directory: dir.path().to_path_buf(),
            prefix: "".to_string(),
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 256,
            max_buffer_rows: 100_000,
        };

        let (handle, jh) = wef_local_start(
            &cfg,
            sink,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );

        let event = make_parsed_event(4624);
        assert!(handle.try_send(event).is_ok());

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
            interval: crate::forwarding::buffered_writer::LiveInterval::new(
                std::time::Duration::from_secs(3600),
            ),
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

    #[tokio::test]
    async fn wef_sink_reports_into_shared_source_hourly_stats() {
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
            prefix: "".to_string(),
            max_buffer_rows: 1_000,
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 64,
            max_partitions: 0,
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
            WefSink,
            s3,
            bwc,
            policy,
            shared_stats.clone(),
            None,
        );
        writer.push(make_parsed_event(4624)).await.unwrap();

        let snapshot = shared_stats.snapshot();
        let row = snapshot.iter().find(|r| r.source == "wef").unwrap();
        let total: u64 = row.hours.iter().map(|h| h.count).sum();
        assert_eq!(total, 1);
    }
}
