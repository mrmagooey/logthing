//! Syslog → S3 Parquet persistence.
//!
//! Provides:
//! - `syslog_schema()` — fixed Arrow schema for `SyslogMessage`
//! - `syslog_message_to_batch()` — convert one message to a single-row RecordBatch
//! - `SyslogSink` — `ParquetSink` adapter for the generic writer
//! - `SyslogS3Handler` — type alias for `ParquetWriterHandle<SyslogSink>`
//! - `syslog_start()` — convenience constructor wiring `SyslogS3Config` → `ParquetWriterHandle`

#[cfg(test)]
use crate::config::SyslogLocalConfig;
use crate::config::SyslogS3Config;
use crate::forwarding::buffered_writer::ParquetSink;
use crate::forwarding::drop_log::{DropKind, DropSite};
use crate::syslog::SyslogMessage;
use arrow::array::{ArrayRef, StringBuilder, TimestampMicrosecondBuilder, UInt8Builder};
#[cfg(test)]
use arrow::array::{StringArray, TimestampMicrosecondArray};
use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use arrow::record_batch::RecordBatch;
use std::sync::{Arc, LazyLock};

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

static SYSLOG_SCHEMA: LazyLock<Arc<Schema>> = LazyLock::new(|| {
    Arc::new(Schema::new(vec![
        Field::new("priority", DataType::UInt8, false),
        Field::new("severity", DataType::UInt8, false),
        Field::new("facility", DataType::UInt8, false),
        Field::new(
            "timestamp",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            true,
        ),
        Field::new("hostname", DataType::Utf8, true),
        Field::new("app_name", DataType::Utf8, true),
        Field::new("proc_id", DataType::Utf8, true),
        Field::new("msg_id", DataType::Utf8, true),
        Field::new("message", DataType::Utf8, false),
        Field::new("structured_data", DataType::Utf8, true),
        Field::new("protocol", DataType::Utf8, false),
        Field::new(
            "received_at",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            false,
        ),
        Field::new(
            "partition_time",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            false,
        ),
    ]))
});

/// Return the fixed Arrow schema for `SyslogMessage` rows.
pub fn syslog_schema() -> Arc<Schema> {
    SYSLOG_SCHEMA.clone()
}

// ---------------------------------------------------------------------------
// Row mapping
// ---------------------------------------------------------------------------

/// Amortized builder set for `syslog_schema()`. Holds the same 13 Arrow
/// builders `syslog_message_to_batch` used to create fresh on every call, as
/// persistent fields, so they can be reused across many records via
/// `finish(&mut self)` instead of reallocated per record. Mirrors
/// `suricata::schema::EnvelopeAccumulator`.
pub(crate) struct SyslogAccumulator {
    b_priority: UInt8Builder,
    b_severity: UInt8Builder,
    b_facility: UInt8Builder,
    b_timestamp: TimestampMicrosecondBuilder,
    b_hostname: StringBuilder,
    b_app_name: StringBuilder,
    b_proc_id: StringBuilder,
    b_msg_id: StringBuilder,
    b_message: StringBuilder,
    b_structured_data: StringBuilder,
    b_protocol: StringBuilder,
    b_received_at: TimestampMicrosecondBuilder,
    b_partition_time: TimestampMicrosecondBuilder,
    rows: usize,
}

impl SyslogAccumulator {
    pub(crate) fn new() -> Self {
        let ts_type = DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()));
        Self {
            b_priority: UInt8Builder::new(),
            b_severity: UInt8Builder::new(),
            b_facility: UInt8Builder::new(),
            b_timestamp: TimestampMicrosecondBuilder::new().with_data_type(ts_type.clone()),
            b_hostname: StringBuilder::new(),
            b_app_name: StringBuilder::new(),
            b_proc_id: StringBuilder::new(),
            b_msg_id: StringBuilder::new(),
            b_message: StringBuilder::new(),
            b_structured_data: StringBuilder::new(),
            b_protocol: StringBuilder::new(),
            b_received_at: TimestampMicrosecondBuilder::new().with_data_type(ts_type.clone()),
            b_partition_time: TimestampMicrosecondBuilder::new().with_data_type(ts_type),
            rows: 0,
        }
    }

    /// Append one `SyslogMessage` into the persistent builders. Shared by
    /// both the amortized path (`RecordBatchAccumulator::try_append`) and
    /// `syslog_message_to_batch`'s single-record wrapper below -- identical
    /// extraction logic either way, so there is exactly one place that knows
    /// how a `SyslogMessage` becomes a row.
    ///
    /// `now` is bound ONCE by the caller and reused for BOTH `received_at`
    /// and the derivation of `partition_time`. Two separate `Utc::now()`
    /// calls either side of midnight would put different days in the two
    /// columns -- `partition_time` is what the buffer's day key and the
    /// eventual Iceberg partition are derived from, so if it disagreed with
    /// `received_at` (the fallback `day_from_batch` would otherwise read) a
    /// flush could still land in a file declared for a different day than
    /// the value actually stamped into `received_at`. This is why `now` is a
    /// parameter here rather than a fresh `chrono::Utc::now()` call -- see
    /// the `RecordBatchAccumulator::try_append` trait doc comment for why
    /// the live-builder path must not read the clock itself.
    fn append_syslog_value(&mut self, msg: &SyslogMessage, now: chrono::DateTime<chrono::Utc>) {
        self.b_priority.append_value(msg.priority);
        self.b_severity.append_value(msg.severity);
        self.b_facility.append_value(msg.facility);
        self.b_timestamp
            .append_option(msg.timestamp.map(|t| t.timestamp_micros()));
        self.b_hostname.append_option(msg.hostname.as_deref());
        self.b_app_name.append_option(msg.app_name.as_deref());
        self.b_proc_id.append_option(msg.proc_id.as_deref());
        self.b_msg_id.append_option(msg.msg_id.as_deref());
        self.b_message.append_value(&msg.message);
        let structured_data = msg
            .structured_data
            .as_ref()
            .and_then(|sd| serde_json::to_string(sd).ok());
        self.b_structured_data
            .append_option(structured_data.as_deref());
        self.b_protocol.append_value(format!("{:?}", msg.protocol));
        self.b_received_at.append_value(now.timestamp_micros());
        let partition_time_value =
            crate::forwarding::buffered_writer::partition_time(msg.timestamp, now);
        self.b_partition_time
            .append_value(partition_time_value.timestamp_micros());
        self.rows += 1;
    }

    fn finish_batch(&mut self) -> anyhow::Result<RecordBatch> {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(self.b_priority.finish()),
            Arc::new(self.b_severity.finish()),
            Arc::new(self.b_facility.finish()),
            Arc::new(self.b_timestamp.finish()),
            Arc::new(self.b_hostname.finish()),
            Arc::new(self.b_app_name.finish()),
            Arc::new(self.b_proc_id.finish()),
            Arc::new(self.b_msg_id.finish()),
            Arc::new(self.b_message.finish()),
            Arc::new(self.b_structured_data.finish()),
            Arc::new(self.b_protocol.finish()),
            Arc::new(self.b_received_at.finish()),
            Arc::new(self.b_partition_time.finish()),
        ];
        self.rows = 0;
        Ok(RecordBatch::try_new(syslog_schema(), columns)?)
    }
}

impl crate::forwarding::buffered_writer::RecordBatchAccumulator<SyslogMessage>
    for SyslogAccumulator
{
    fn try_append(
        &mut self,
        record: &SyslogMessage,
        // `push()`'s single per-push clock read, used as the receipt instant
        // for both `received_at` and `partition_time` -- see
        // `append_syslog_value`'s doc comment. `SyslogMessage` carries no
        // logthing-stamped receipt instant of its own (unlike
        // `SuricataRecord::received_at`), so unlike `EnvelopeAccumulator`
        // this accumulator actually uses the `now` argument instead of
        // ignoring it.
        now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<bool> {
        // Syslog has exactly one schema, unlike Zeek's per-log-path
        // registry, so there is no mismatch case to fall back from: every
        // SyslogMessage belongs to this accumulator.
        self.append_syslog_value(record, now);
        Ok(true)
    }

    fn len(&self) -> usize {
        self.rows
    }

    fn finish(&mut self) -> anyhow::Result<RecordBatch> {
        self.finish_batch()
    }
}

/// Map one `SyslogMessage` to a single-row `RecordBatch`.
///
/// Stamps `received_at` with `Utc::now()` here -- the row-mapping
/// boundary, called exactly once per push -- mirroring
/// `StructuredSyslogRecord::from`'s identical stamp. This is deliberately
/// NOT a field on `SyslogMessage` itself: that struct is
/// `Serialize`/`Deserialize` (a new field would change JSON forwarding
/// output) and is consumed by `aggregate/fields.rs` and `channel_budget.rs`.
/// See `SyslogAccumulator::append_syslog_value` for why that single stamp
/// must be reused for both `received_at` and `partition_time`.
pub fn syslog_message_to_batch(msg: &SyslogMessage) -> anyhow::Result<RecordBatch> {
    let mut acc = SyslogAccumulator::new();
    acc.append_syslog_value(msg, chrono::Utc::now());
    acc.finish_batch()
}

// ---------------------------------------------------------------------------
// Parquet encoding (kept as private helper for tests)
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) fn encode_batches_to_parquet(batches: &[RecordBatch]) -> anyhow::Result<Vec<u8>> {
    use parquet::arrow::ArrowWriter;
    use parquet::basic::{Compression, ZstdLevel};
    use parquet::file::properties::WriterProperties;

    if batches.is_empty() {
        return Ok(Vec::new());
    }
    let schema = syslog_schema();
    let props = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(3)?))
        .build();
    let mut buf = Vec::new();
    let mut writer = ArrowWriter::try_new(&mut buf, schema, Some(props))?;
    for batch in batches {
        writer.write(batch)?;
    }
    writer.close()?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// SyslogSink — ParquetSink adapter
// ---------------------------------------------------------------------------

/// `ParquetSink` adapter for syslog messages.
/// The `Record` type is `SyslogMessage` — one row per message.
#[derive(Default)]
pub struct SyslogSink;

impl ParquetSink for SyslogSink {
    type Record = SyslogMessage;

    fn source(&self) -> &'static str {
        "syslog"
    }

    fn partition(&self, _: &SyslogMessage) -> Option<String> {
        None
    }

    fn schema(&self, _: Option<&str>) -> Arc<arrow_schema::Schema> {
        syslog_schema()
    }

    /// Event time column for day bucketing. `partition_time` (see
    /// `syslog_message_to_batch`) is non-null by construction, so a buffer
    /// keyed on its day is genuinely day-clean for every row -- including a
    /// mix of RFC 5424 messages (nullable `timestamp` parsed) and CEF/LEEF
    /// payloads (`timestamp: None`), which is the ordinary case for SIEM
    /// traffic on this listener.
    fn time_column(&self) -> Option<&'static str> {
        Some("partition_time")
    }

    fn to_record_batch(
        &self,
        record: &SyslogMessage,
        _schema: &Arc<arrow_schema::Schema>,
    ) -> anyhow::Result<arrow_array::RecordBatch> {
        syslog_message_to_batch(record)
    }

    /// Amortized-builder fast path: syslog has exactly one schema, so this
    /// always matches -- gated on `Arc::ptr_eq` rather than unconditionally
    /// returning `Some` purely defensively, mirroring
    /// `SuricataSink`/`IpfixSink::new_batch`.
    fn new_batch(
        &self,
        schema: &Arc<arrow_schema::Schema>,
    ) -> Option<Box<dyn crate::forwarding::buffered_writer::RecordBatchAccumulator<SyslogMessage>>>
    {
        if Arc::ptr_eq(schema, &syslog_schema()) {
            Some(Box::new(SyslogAccumulator::new()))
        } else {
            None
        }
    }

    /// Overrides the default `day_and_batch`: derives the day directly from
    /// `partition_time(record.timestamp, now)` instead of building a batch
    /// first. Load-bearing for the same reason as `SuricataSink`'s /
    /// `IpfixSink`'s overrides -- `push()` calls this before it knows
    /// whether the record goes to the amortized `SyslogAccumulator`, so
    /// building a batch here just to learn the day would make every record
    /// pay for a throwaway `RecordBatch`, defeating the entire point of the
    /// accumulator.
    ///
    /// Must reproduce the default's day exactly: the default's
    /// `day_from_batch` reads `partition_time.value(0)` -- always non-null
    /// by construction -- which `SyslogAccumulator` derives from
    /// `partition_time(msg.timestamp, now)` using this SAME `now`: the
    /// single per-push clock read `push()` threads through both
    /// `day_and_batch` and `try_append`, so the two can never disagree.
    fn day_and_batch(
        &self,
        record: &SyslogMessage,
        _schema: &Arc<arrow_schema::Schema>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<(chrono::NaiveDate, Option<arrow_array::RecordBatch>)> {
        let day =
            crate::forwarding::buffered_writer::partition_time(record.timestamp, now).date_naive();
        Ok((day, None))
    }
}

// ---------------------------------------------------------------------------
// SyslogS3Handler — type alias + SyslogHandler impl
// ---------------------------------------------------------------------------

/// `SyslogS3Handler` is a thin alias for the generic `ParquetWriterHandle<SyslogSink>`.
pub type SyslogS3Handler = crate::forwarding::buffered_writer::ParquetWriterHandle<SyslogSink>;

#[async_trait::async_trait]
impl crate::syslog::listener::SyslogHandler
    for crate::forwarding::buffered_writer::ParquetWriterHandle<SyslogSink>
{
    async fn handle_message(&self, message: SyslogMessage, _source: std::net::SocketAddr) {
        match self.try_send(message) {
            Ok(()) => {}
            Err(e) => {
                if let Some(dropped_total) = self.drop_log_due(DropSite::Syslog, DropKind::from(&e))
                {
                    tracing::warn!(dropped_total, "Syslog S3 channel full; dropped message");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// syslog_start — convenience constructor
// ---------------------------------------------------------------------------

/// Construct a `SyslogS3Handler` (i.e. `ParquetWriterHandle<SyslogSink>`) from a
/// `SyslogS3Config` and a pre-built `S3Sink`.
///
/// Returns `(handler, writer_task_handle)`. The caller should retain the `JoinHandle`
/// and await it during graceful shutdown, after all `Arc<dyn SyslogHandler>` references
/// have been dropped so the channel closes and the final flush fires.
pub fn syslog_start(
    cfg: &SyslogS3Config,
    s3: std::sync::Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<std::sync::Arc<dyn crate::forwarding::buffered_writer::UploadSink>>,
) -> (SyslogS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<SyslogSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        usize::MAX, // syslog uses row-count + age triggers only
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        1,
        s3,
        source_stats,
        descriptor_sink,
    )
}

/// Construct a `SyslogS3Handler` from a `SyslogLocalConfig` and a pre-built
/// `LocalDiskSink`. Structurally identical to `syslog_start`, writing to
/// local disk instead of S3 — same `SyslogSink` adapter, same
/// buffering/flush/cap machinery, same S3-key-shaped relative path layout
/// on disk.
pub fn syslog_local_start(
    cfg: &crate::config::SyslogLocalConfig,
    sink: std::sync::Arc<crate::forwarding::local_sink::LocalDiskSink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<std::sync::Arc<dyn crate::forwarding::buffered_writer::UploadSink>>,
) -> (SyslogS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<SyslogSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        usize::MAX, // syslog uses row-count + age triggers only
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        1,
        sink,
        source_stats,
        descriptor_sink,
    )
}

/// Fans out each message to every configured handler. Used only when at
/// least one of `.s3` / `.local` persistence resolves to a live handler for
/// this run — `main.rs` always wraps the resulting `MultiSyslogHandler` (or
/// the sole handler, if that's the only element) as the `inner` of a
/// `PayloadDispatchingHandler`, never in place of it. Each destination keeps
/// its own independent buffer, flush policy, backpressure, and hard cap (no
/// shared state between destinations).
pub struct MultiSyslogHandler(pub Vec<std::sync::Arc<dyn crate::syslog::listener::SyslogHandler>>);

#[async_trait::async_trait]
impl crate::syslog::listener::SyslogHandler for MultiSyslogHandler {
    async fn handle_message(&self, message: SyslogMessage, source: std::net::SocketAddr) {
        for handler in &self.0 {
            handler.handle_message(message.clone(), source).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syslog::{SyslogMessage, SyslogProtocol};
    use arrow::array::Array as ArrowArray; // needed for .is_null()
    use std::collections::HashMap;

    // -- helpers --

    fn sample_rfc5424() -> SyslogMessage {
        let mut sd = HashMap::new();
        let mut params = HashMap::new();
        params.insert("iut".to_string(), "3".to_string());
        sd.insert("example@32473".to_string(), params);
        SyslogMessage {
            priority: 34,
            severity: 2,
            facility: 4,
            timestamp: Some(
                chrono::DateTime::parse_from_rfc3339("2003-10-11T22:14:15Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            hostname: Some("mymachine".to_string()),
            app_name: Some("su".to_string()),
            proc_id: None,
            msg_id: Some("ID47".to_string()),
            message: "'su root' failed".to_string(),
            structured_data: Some(sd),
            protocol: SyslogProtocol::Rfc5424,
        }
    }

    fn dummy_msg(text: &str) -> SyslogMessage {
        SyslogMessage {
            priority: 0,
            severity: 0,
            facility: 0,
            timestamp: None,
            hostname: None,
            app_name: None,
            proc_id: None,
            msg_id: None,
            message: text.to_string(),
            structured_data: None,
            protocol: SyslogProtocol::Unknown,
        }
    }

    // -- helper: unreachable S3Sink --

    async fn unreachable_sink() -> Arc<crate::forwarding::s3_sink::S3Sink> {
        use crate::config::S3ConnectionConfig;
        let conn = S3ConnectionConfig {
            endpoint: "http://127.0.0.1:1".to_string(), // port 1 is always refused
            bucket: "test-bucket".to_string(),
            region: "us-east-1".to_string(),
            access_key: "AKIATEST".to_string(),
            secret_key: "SECRETTEST".to_string(),
        };
        Arc::new(
            crate::forwarding::s3_sink::S3Sink::from_connection(&conn)
                .await
                .expect("constructs"),
        )
    }

    // -- Task 1: schema shape --

    #[test]
    fn schema_has_correct_columns_and_types() {
        use arrow::datatypes::{DataType, TimeUnit};
        let schema = syslog_schema();
        assert_eq!(schema.fields().len(), 13);
        assert_eq!(
            schema.field_with_name("priority").unwrap().data_type(),
            &DataType::UInt8
        );
        assert!(!schema.field_with_name("priority").unwrap().is_nullable());
        assert_eq!(
            schema.field_with_name("timestamp").unwrap().data_type(),
            &DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
        );
        assert!(schema.field_with_name("timestamp").unwrap().is_nullable());
        assert_eq!(
            schema
                .field_with_name("structured_data")
                .unwrap()
                .data_type(),
            &DataType::Utf8
        );
        assert!(
            schema
                .field_with_name("structured_data")
                .unwrap()
                .is_nullable()
        );
        assert_eq!(
            schema.field_with_name("received_at").unwrap().data_type(),
            &DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
        );
        assert!(
            !schema.field_with_name("received_at").unwrap().is_nullable(),
            "received_at must always be set -- it is the fallback day source \
             when timestamp fails to parse"
        );
        assert!(!schema.field_with_name("protocol").unwrap().is_nullable());
        assert_eq!(
            schema
                .field_with_name("partition_time")
                .unwrap()
                .data_type(),
            &DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
        );
        assert!(
            !schema
                .field_with_name("partition_time")
                .unwrap()
                .is_nullable(),
            "partition_time must always be set -- it is the single non-null \
             column the buffer day and the Iceberg partition are derived from"
        );
    }

    #[test]
    fn syslog_message_to_batch_stamps_received_at_non_null() {
        let msg = dummy_msg("no timestamp in this message");
        let batch = syslog_message_to_batch(&msg).unwrap();
        let col = batch
            .column_by_name("received_at")
            .unwrap()
            .as_any()
            .downcast_ref::<arrow::array::TimestampMicrosecondArray>()
            .unwrap();
        assert!(
            !col.is_null(0),
            "received_at must be stamped even when timestamp is None"
        );
    }

    #[test]
    fn syslog_message_to_batch_null_timestamp_day_column_is_todays_utc_date() {
        // Narrower than the trait-level test below: just checks the raw
        // `received_at` column value the mapper wrote, independent of
        // whether anything downstream actually reads it for day bucketing.
        let msg = dummy_msg("no timestamp in this message");
        let batch = syslog_message_to_batch(&msg).unwrap();

        let ts_col = batch
            .column_by_name("timestamp")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert!(ts_col.is_null(0), "precondition: timestamp must be null");

        let received_at_col = batch
            .column_by_name("received_at")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        let day = chrono::DateTime::from_timestamp_micros(received_at_col.value(0))
            .unwrap()
            .date_naive();
        assert_eq!(
            day,
            chrono::Utc::now().date_naive(),
            "received_at must resolve to today's UTC day when timestamp is null"
        );
    }

    #[test]
    fn syslog_message_to_batch_valid_timestamp_day_column_matches_timestamp() {
        // Narrower than the trait-level test below: just checks the raw
        // `timestamp` column value the mapper wrote, independent of whether
        // `time_column()`/`day_and_batch` actually reads it.
        let mut msg = sample_rfc5424();
        msg.timestamp = Some(
            chrono::DateTime::parse_from_rfc3339("2003-10-11T22:14:15Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        );
        let batch = syslog_message_to_batch(&msg).unwrap();

        let ts_col = batch
            .column_by_name("timestamp")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert!(!ts_col.is_null(0));
        let ts_day = chrono::DateTime::from_timestamp_micros(ts_col.value(0))
            .unwrap()
            .date_naive();
        assert_eq!(
            ts_day,
            chrono::NaiveDate::from_ymd_opt(2003, 10, 11).unwrap()
        );
        assert_ne!(
            ts_day,
            chrono::Utc::now().date_naive(),
            "test is only meaningful if timestamp's day differs from received_at's day"
        );
    }

    #[test]
    fn syslog_message_to_batch_partition_time_equals_timestamp_on_different_day() {
        // Different UTC day from receipt time so a bug that silently fell
        // back to received_at could not pass by accident.
        let mut msg = sample_rfc5424();
        let event = chrono::Utc::now() - chrono::TimeDelta::hours(30);
        msg.timestamp = Some(event);
        let batch = syslog_message_to_batch(&msg).unwrap();

        let partition_time_col = batch
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(partition_time_col.value(0), event.timestamp_micros());

        let received_at_col = batch
            .column_by_name("received_at")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_ne!(
            partition_time_col.value(0),
            received_at_col.value(0),
            "test is only meaningful if partition_time actually differs from received_at"
        );
    }

    #[test]
    fn syslog_message_to_batch_partition_time_equals_received_at_when_timestamp_null() {
        // The single-stamp requirement this addendum exists to guarantee:
        // when `timestamp` fails to parse (e.g. a CEF/LEEF payload),
        // `received_at` and `partition_time` must be the EXACT same value,
        // not two independent `Utc::now()` reads that could straddle
        // midnight and disagree about which day the row belongs to.
        let msg = dummy_msg("no timestamp in this message");
        let batch = syslog_message_to_batch(&msg).unwrap();

        let received_at_col = batch
            .column_by_name("received_at")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        let partition_time_col = batch
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(
            received_at_col.value(0),
            partition_time_col.value(0),
            "received_at and partition_time must be stamped from the same \
             Utc::now() call when timestamp is null"
        );
    }

    #[test]
    fn syslog_message_to_batch_partition_time_falls_back_when_timestamp_outside_clamp() {
        let mut msg = sample_rfc5424();
        // 60 days back is well past the 30-day backfill clamp.
        msg.timestamp = Some(chrono::Utc::now() - chrono::TimeDelta::days(60));
        let before = chrono::Utc::now();
        let batch = syslog_message_to_batch(&msg).unwrap();
        let after = chrono::Utc::now();

        let partition_time_col = batch
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        let value = partition_time_col.value(0);
        assert!(
            value >= before.timestamp_micros() && value <= after.timestamp_micros(),
            "partition_time must fall back to received_at (receipt time) once \
             the event timestamp is outside the clamp window"
        );
    }

    // -- Trait-level fallback-chain wiring: these are the tests that
    // actually guard the feature. They go through `SyslogSink::day_and_batch`
    // (the real call path `PartitionedParquetWriter::push` uses), not just
    // the raw column values `syslog_message_to_batch` wrote.
    //
    // Since the accumulator conversion, `day_and_batch`'s `now` argument IS
    // the receipt instant (see `SyslogAccumulator::append_syslog_value`'s
    // doc comment) -- `push()` reads the clock exactly once and threads that
    // same value through both `day_and_batch` and `try_append`, so
    // `SyslogMessage` (which carries no receipt instant of its own) uses it
    // directly instead of a second, independent `Utc::now()` read. So unlike
    // before this conversion, these tests pick a realistic FIXED `now` and
    // compute event timestamps relative to it (mirroring
    // `IpfixSink::day_and_batch`'s tests) rather than passing a wall-clock-
    // divorced sentinel `now` -- `now` is no longer a value the fallback
    // chain should ignore, it is the fallback value itself.

    #[test]
    fn day_and_batch_uses_timestamp_column_when_present() {
        use chrono::TimeZone;
        let sink = SyslogSink;
        let schema = sink.schema(None);
        let now = chrono::Utc.with_ymd_and_hms(2026, 6, 15, 3, 0, 0).unwrap();
        let mut msg = sample_rfc5424();
        // 30 hours back is inside the partition_time clamp window (30-day
        // backfill) but guaranteed to land on a different UTC calendar day
        // than `now`.
        let event = now - chrono::TimeDelta::hours(30);
        msg.timestamp = Some(event);

        let (day, pre_mapped) = sink.day_and_batch(&msg, &schema, now).unwrap();

        assert!(
            pre_mapped.is_none(),
            "day_and_batch must not build a batch just to compute the day"
        );
        assert_eq!(day, event.date_naive());
        assert_ne!(
            day,
            now.date_naive(),
            "test is only meaningful if the event's day differs from receipt's day"
        );
    }

    #[test]
    fn day_and_batch_timestamp_outside_clamp_falls_back_to_received_at() {
        use chrono::TimeZone;
        let sink = SyslogSink;
        let schema = sink.schema(None);
        let now = chrono::Utc.with_ymd_and_hms(2026, 6, 15, 3, 0, 0).unwrap();
        let mut msg = sample_rfc5424();
        msg.timestamp = Some(now - chrono::TimeDelta::days(60));

        let (day, _pre_mapped) = sink.day_and_batch(&msg, &schema, now).unwrap();

        assert_eq!(
            day,
            now.date_naive(),
            "an event timestamp outside the clamp window must bucket by receipt day"
        );
    }

    #[test]
    fn day_and_batch_mixed_null_and_valid_timestamp_same_receipt_day_agree_regression() {
        // The regression case for this addendum: previously the buffer day
        // came from coalesce(timestamp, received_at), a quantity with no
        // matching column. A null-timestamp row (e.g. CEF/LEEF) and a
        // valid-timestamp row received on the same real day could reach the
        // SAME buffer day via DIFFERENT source columns, producing a file
        // whose declared day did not match a single non-null Iceberg
        // partition column. With partition_time, both rows must derive the
        // buffer day from the very same column.
        use chrono::TimeZone;
        let sink = SyslogSink;
        let schema = sink.schema(None);
        let now = chrono::Utc.with_ymd_and_hms(2026, 6, 15, 3, 0, 0).unwrap();

        // Record A: no parseable header timestamp -- falls back to received_at.
        let msg_a = dummy_msg("cef-like, no header timestamp");
        let (day_a, _) = sink.day_and_batch(&msg_a, &schema, now).unwrap();

        // Record B: a valid timestamp a couple of seconds before `now` --
        // inside the clamp window and on the same calendar day as record A's
        // receipt time.
        let mut msg_b = sample_rfc5424();
        msg_b.timestamp = Some(now - chrono::TimeDelta::seconds(2));
        let (day_b, _) = sink.day_and_batch(&msg_b, &schema, now).unwrap();

        assert_eq!(day_a, now.date_naive());
        assert_eq!(
            day_a, day_b,
            "a null-timestamp row and a valid-timestamp row received on the \
             same day must land in the same partition_time day"
        );
    }

    #[test]
    fn day_and_batch_falls_back_to_received_at_when_timestamp_is_null() {
        use chrono::TimeZone;
        let sink = SyslogSink;
        let schema = sink.schema(None);
        let now = chrono::Utc.with_ymd_and_hms(2026, 6, 15, 3, 0, 0).unwrap();
        let msg = dummy_msg("no timestamp in this message");

        let (day, _pre_mapped) = sink.day_and_batch(&msg, &schema, now).unwrap();

        assert_eq!(
            day,
            now.date_naive(),
            "day must come from the received_at (now) stamp when timestamp is null"
        );
    }

    #[test]
    fn syslog_sink_time_column_partition_time_exists_in_schema() {
        let sink = SyslogSink;
        let col = sink
            .time_column()
            .expect("syslog_sink must opt in to day partitioning");
        // Pin the exact column name, not just that SOME name resolves.
        assert_eq!(col, "partition_time");
        let schema = sink.schema(None);
        assert!(
            schema.field_with_name(col).is_ok(),
            "time_column() returned {:?}, which is not a field in the schema",
            col
        );
    }

    #[test]
    fn timestamp_is_written_as_microseconds() {
        use chrono::TimeZone;
        let mut msg = sample_rfc5424();
        msg.timestamp = Some(chrono::Utc.timestamp_opt(1_700_000_000, 0).unwrap());
        let batch = syslog_message_to_batch(&msg).unwrap();
        let col = batch
            .column_by_name("timestamp")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .expect("timestamp should be TimestampMicrosecondArray");
        assert_eq!(col.value(0), 1_700_000_000_000_000);
    }

    #[test]
    fn absent_timestamp_is_null() {
        let mut msg = sample_rfc5424();
        msg.timestamp = None;
        let batch = syslog_message_to_batch(&msg).unwrap();
        let col = batch
            .column_by_name("timestamp")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert!(col.is_null(0));
    }

    // -- Task 1: row mapping --

    #[test]
    fn row_mapping_produces_expected_column_values() {
        use arrow::array::{StringArray, UInt8Array};
        let msg = sample_rfc5424();
        let batch = syslog_message_to_batch(&msg).expect("batch");
        assert_eq!(batch.num_rows(), 1);
        assert_eq!(batch.num_columns(), 13);

        let priority = batch
            .column(0)
            .as_any()
            .downcast_ref::<UInt8Array>()
            .unwrap();
        assert_eq!(priority.value(0), 34);

        let hostname = batch
            .column(4)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(hostname.value(0), "mymachine");

        // proc_id is None → null
        let proc_id = batch
            .column(6)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert!(proc_id.is_null(0));

        // structured_data is JSON
        let sd_col = batch
            .column(9)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert!(sd_col.value(0).contains("example@32473"));

        let protocol = batch
            .column(10)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(protocol.value(0), "Rfc5424");
    }

    #[test]
    fn row_mapping_handles_all_none_optional_fields() {
        use arrow::array::StringArray;
        let msg = SyslogMessage {
            priority: 0,
            severity: 0,
            facility: 0,
            timestamp: None,
            hostname: None,
            app_name: None,
            proc_id: None,
            msg_id: None,
            message: "bare".to_string(),
            structured_data: None,
            protocol: SyslogProtocol::Unknown,
        };
        let batch = syslog_message_to_batch(&msg).expect("batch");
        let ts = batch
            .column(3)
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert!(ts.is_null(0));
        let sd = batch
            .column(9)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert!(sd.is_null(0));
    }

    // -- Task 2: Parquet round-trip --

    #[test]
    fn encode_parquet_round_trips_expected_schema_and_values() {
        use bytes::Bytes;
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

        let msg = SyslogMessage {
            priority: 134,
            severity: 6,
            facility: 16,
            timestamp: Some(chrono::Utc::now()),
            hostname: Some("testhost".to_string()),
            app_name: Some("myapp".to_string()),
            proc_id: Some("9999".to_string()),
            msg_id: None,
            message: "hello world".to_string(),
            structured_data: None,
            protocol: SyslogProtocol::Rfc3164,
        };

        let batch = syslog_message_to_batch(&msg).unwrap();
        let raw = encode_batches_to_parquet(&[batch]).unwrap();
        assert!(!raw.is_empty(), "Parquet bytes must not be empty");

        // ParquetRecordBatchReaderBuilder requires bytes::Bytes (implements ChunkReader)
        let buf = Bytes::from(raw);
        let builder = ParquetRecordBatchReaderBuilder::try_new(buf).unwrap();
        let schema = builder.schema().clone();
        let mut reader = builder.build().unwrap();
        let rb = reader.next().unwrap().unwrap();
        assert_eq!(rb.num_rows(), 1);
        assert_eq!(schema.fields().len(), 13);

        use arrow::array::StringArray;
        let hostname = rb.column(4).as_any().downcast_ref::<StringArray>().unwrap();
        assert_eq!(hostname.value(0), "testhost");
        let msg_col = rb.column(8).as_any().downcast_ref::<StringArray>().unwrap();
        assert_eq!(msg_col.value(0), "hello world");
    }

    #[test]
    fn encode_parquet_multiple_batches_concatenates_rows() {
        use bytes::Bytes;
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

        let batches: Vec<_> = ["alpha", "beta", "gamma"]
            .iter()
            .map(|t| syslog_message_to_batch(&dummy_msg(t)).unwrap())
            .collect();

        let raw = encode_batches_to_parquet(&batches).unwrap();
        let buf = Bytes::from(raw);
        let mut reader = ParquetRecordBatchReaderBuilder::try_new(buf)
            .unwrap()
            .build()
            .unwrap();

        let mut total_rows = 0usize;
        for rb in reader.by_ref() {
            total_rows += rb.unwrap().num_rows();
        }
        assert_eq!(total_rows, 3);
    }

    // -- SyslogSink adapter tests --

    #[test]
    fn syslog_sink_source_returns_syslog() {
        assert_eq!(SyslogSink.source(), "syslog");
    }

    #[test]
    fn syslog_sink_partition_returns_none() {
        let msg = dummy_msg("test");
        assert!(SyslogSink.partition(&msg).is_none());
    }

    #[test]
    fn syslog_sink_to_record_batch_produces_correct_schema_and_rows() {
        use crate::forwarding::buffered_writer::ParquetSink;
        use arrow::array::StringArray;

        let sink = SyslogSink;
        let schema = sink.schema(None);
        assert_eq!(schema.fields().len(), 13);

        let msg = sample_rfc5424();
        let batch = sink.to_record_batch(&msg, &schema).unwrap();
        assert_eq!(batch.num_rows(), 1);

        let hostname = batch
            .column(4)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(hostname.value(0), "mymachine");
    }

    // -- SyslogAccumulator tests --

    #[test]
    fn syslog_accumulator_matches_single_row_batches_concatenated() {
        use crate::forwarding::buffered_writer::RecordBatchAccumulator;
        use chrono::TimeZone;

        // Fixed `now`, shared by baseline and accumulator paths: the public
        // `syslog_message_to_batch` reads its own clock internally and
        // cannot be pinned, so the baseline here is built directly through
        // the same private accumulator helper `syslog_message_to_batch`
        // itself calls -- exactly what "one to_record_batch call per
        // record, concatenated" meant before this conversion.
        let now = chrono::Utc.with_ymd_and_hms(2026, 4, 2, 8, 0, 0).unwrap();
        let records = vec![
            sample_rfc5424(),
            // Missing timestamp/hostname/app_name -> null columns, exercised
            // through the accumulator.
            dummy_msg("no timestamp in this message"),
            {
                let mut m = sample_rfc5424();
                m.hostname = None;
                m.app_name = None;
                m.structured_data = None;
                m
            },
        ];

        let single_row_batches: Vec<RecordBatch> = records
            .iter()
            .map(|r| {
                let mut acc = SyslogAccumulator::new();
                acc.try_append(r, now).unwrap();
                acc.finish().unwrap()
            })
            .collect();
        let expected =
            arrow::compute::concat_batches(&syslog_schema(), &single_row_batches).unwrap();

        // Amortized path: one accumulator, N appends, one finish.
        let mut acc = SyslogAccumulator::new();
        for r in &records {
            assert!(acc.try_append(r, now).unwrap());
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
    fn syslog_accumulator_len_and_is_empty() {
        use crate::forwarding::buffered_writer::RecordBatchAccumulator;

        let mut acc = SyslogAccumulator::new();
        assert_eq!(acc.len(), 0);
        assert!(acc.is_empty());

        let now = chrono::Utc::now();
        acc.try_append(&dummy_msg("a"), now).unwrap();
        assert_eq!(acc.len(), 1);
        assert!(!acc.is_empty());

        acc.try_append(&dummy_msg("b"), now).unwrap();
        assert_eq!(acc.len(), 2);

        acc.finish().unwrap();
        assert_eq!(acc.len(), 0, "finish must reset the row count");
        assert!(acc.is_empty());
    }

    #[test]
    fn syslog_accumulator_finish_twice_produces_independent_batches() {
        use crate::forwarding::buffered_writer::RecordBatchAccumulator;

        let mut acc = SyslogAccumulator::new();
        let now = chrono::Utc::now();

        acc.try_append(&dummy_msg("first"), now).unwrap();
        let batch_a = acc.finish().unwrap();
        assert_eq!(
            batch_a.num_rows(),
            1,
            "first finish must contain exactly the rows appended before it"
        );

        acc.try_append(&dummy_msg("second"), now).unwrap();
        acc.try_append(&dummy_msg("third"), now).unwrap();
        let batch_b = acc.finish().unwrap();

        assert_eq!(
            batch_b.num_rows(),
            2,
            "second finish must contain exactly the rows appended since the first finish -- \
             a builder that retained prior rows would produce 3 here, silently duplicating data"
        );
        let messages = batch_b
            .column_by_name("message")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(messages.value(0), "second");
        assert_eq!(messages.value(1), "third");
    }

    /// Runtime-activation check: `new_batch` must actually return `Some` for
    /// the real syslog schema `push()` passes it, and `None` for a distinct
    /// schema Arc -- proving the amortized-builder fast path is really wired
    /// up, not silently falling back to a fresh `to_record_batch` per push
    /// (which would make the accumulator a no-op).
    #[test]
    fn syslog_sink_new_batch_activates_for_the_real_syslog_schema() {
        let schema = SyslogSink.schema(None);
        assert!(
            Arc::ptr_eq(&schema, &syslog_schema()),
            "sanity: SyslogSink::schema must return the same Arc as syslog_schema()"
        );
        let acc = SyslogSink.new_batch(&schema);
        assert!(
            acc.is_some(),
            "new_batch must return Some(SyslogAccumulator) for syslog_schema() -- \
             if this is None, push() falls back to a fresh builder per record and the \
             accumulator never activates"
        );

        let other_schema: Arc<arrow_schema::Schema> =
            Arc::new(arrow_schema::Schema::new(vec![arrow_schema::Field::new(
                "unrelated",
                arrow_schema::DataType::Utf8,
                true,
            )]));
        assert!(
            SyslogSink.new_batch(&other_schema).is_none(),
            "new_batch must return None for a schema that isn't syslog_schema()'s Arc"
        );
    }

    /// `day_and_batch` must not build a batch just to compute the day --
    /// that would allocate the full 13-builder set on every push and defeat
    /// the entire point of `SyslogAccumulator`. Also proves parity with the
    /// default `day_from_batch` mechanism: build the row-0 reference batch
    /// directly via the accumulator (same mechanism, same `now`) and compare
    /// days.
    #[test]
    fn day_and_batch_matches_default_day_from_batch_mechanism_and_skips_batch_build() {
        use crate::forwarding::buffered_writer::RecordBatchAccumulator;
        use chrono::TimeZone;

        let now = chrono::Utc.with_ymd_and_hms(2026, 6, 15, 3, 0, 0).unwrap();
        let mut msg = sample_rfc5424();
        msg.timestamp = Some(chrono::Utc.with_ymd_and_hms(2026, 6, 14, 23, 0, 0).unwrap()); // previous day, within clamp

        let mut acc = SyslogAccumulator::new();
        acc.try_append(&msg, now).unwrap();
        let batch = acc.finish().unwrap();
        let partition_time_col = batch
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        let expected_day = chrono::DateTime::from_timestamp_micros(partition_time_col.value(0))
            .unwrap()
            .date_naive();

        let sink = SyslogSink;
        let schema = sink.schema(None);
        let (day, pre_mapped) = sink.day_and_batch(&msg, &schema, now).unwrap();
        assert!(
            pre_mapped.is_none(),
            "day_and_batch must not build a batch just to compute the day"
        );
        assert_eq!(day, expected_day);
    }

    #[tokio::test]
    async fn syslog_start_wires_handler_and_join_handle() {
        use crate::config::S3ConnectionConfig;
        use crate::syslog::listener::SyslogHandler as SyslogHandlerTrait;
        use std::net::SocketAddr;

        let sink = unreachable_sink().await;
        let cfg = SyslogS3Config {
            connection: S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "syslog".to_string(),
            max_buffer_rows: 10_000,
            flush_interval_secs: 3600,
            channel_capacity: 4096,
        };

        let (handler, join_handle) = syslog_start(
            &cfg,
            sink,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );

        // try_send one message through the handler
        let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();
        handler.handle_message(dummy_msg("hello"), src).await;

        // Drop the handler to close the channel and trigger shutdown flush
        drop(handler);

        // Join the background task within 5s
        tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("writer task must exit within 5s")
            .expect("writer task must not panic");
    }

    #[tokio::test]
    async fn syslog_local_start_wires_handler_and_join_handle() {
        use crate::syslog::listener::SyslogHandler as SyslogHandlerTrait;
        use std::net::SocketAddr;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let sink = Arc::new(
            crate::forwarding::local_sink::LocalDiskSink::new(dir.path().to_path_buf())
                .await
                .expect("constructs"),
        );
        let cfg = SyslogLocalConfig {
            directory: dir.path().to_path_buf(),
            prefix: "syslog".to_string(),
            max_buffer_rows: 10_000,
            flush_interval_secs: 3600,
            channel_capacity: 4096,
        };

        let (handler, join_handle) = syslog_local_start(
            &cfg,
            sink,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );

        let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();
        handler.handle_message(dummy_msg("hello"), src).await;

        drop(handler);

        tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("writer task must exit within 5s")
            .expect("writer task must not panic");
    }

    #[tokio::test]
    async fn multi_syslog_handler_fans_out_to_every_inner_handler() {
        use crate::syslog::listener::SyslogHandler as SyslogHandlerTrait;
        use std::net::SocketAddr;
        use std::sync::Mutex;

        struct CountingHandler {
            count: Mutex<usize>,
        }

        #[async_trait::async_trait]
        impl SyslogHandlerTrait for CountingHandler {
            async fn handle_message(&self, _message: SyslogMessage, _source: SocketAddr) {
                *self.count.lock().unwrap() += 1;
            }
        }

        let h1 = Arc::new(CountingHandler {
            count: Mutex::new(0),
        });
        let h2 = Arc::new(CountingHandler {
            count: Mutex::new(0),
        });
        let multi = MultiSyslogHandler(vec![h1.clone(), h2.clone()]);

        let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();
        multi.handle_message(dummy_msg("test"), src).await;

        assert_eq!(*h1.count.lock().unwrap(), 1);
        assert_eq!(*h2.count.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn multi_syslog_handler_survives_one_inner_handler_dropping() {
        use crate::syslog::listener::SyslogHandler as SyslogHandlerTrait;
        use std::net::SocketAddr;

        let sink = unreachable_sink().await;
        let cfg = SyslogS3Config {
            connection: crate::config::S3ConnectionConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIATEST".to_string(),
                secret_key: "SECRETTEST".to_string(),
            },
            prefix: "syslog".to_string(),
            max_buffer_rows: 10_000,
            flush_interval_secs: 3600,
            channel_capacity: 4096,
        };
        let (handler, join_handle) = syslog_start(
            &cfg,
            sink,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );
        let live: Arc<dyn SyslogHandlerTrait> = Arc::new(handler);

        let multi = MultiSyslogHandler(vec![live.clone()]);
        let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();
        multi.handle_message(dummy_msg("still works"), src).await;

        drop(live);
        drop(multi);
        tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("writer task must exit within 5s")
            .expect("writer task must not panic");
    }

    #[tokio::test]
    async fn syslog_sink_reports_into_shared_source_hourly_stats() {
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
            prefix: "syslog".to_string(),
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
            SyslogSink,
            s3,
            bwc,
            policy,
            shared_stats.clone(),
            None,
        );
        writer.push(dummy_msg("test")).await.unwrap();

        let snapshot = shared_stats.snapshot();
        let row = snapshot.iter().find(|r| r.source == "syslog").unwrap();
        let total: u64 = row.hours.iter().map(|h| h.count).sum();
        assert_eq!(total, 1);
    }
}
