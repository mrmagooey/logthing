//! StructuredSyslog → S3 Parquet persistence (partitioned by payload_type).
//!
//! Schema: 10 columns — syslog envelope, payload_type, parsed (JSON string),
//! and partition_time (non-null; derived from timestamp, clamped and
//! falling back to received_at -- see `ParquetSink::time_column`).
//! Partition key: payload_type string ("cef", "leef", "auditd", "dhcp",
//!                "radius", "web_access", "dns").
//! The sink reuses SyslogS3Config (identical connection/flush parameters).

use crate::config::SyslogS3Config;
use crate::forwarding::buffered_writer::ParquetSink;
use crate::syslog::payload::StructuredSyslogRecord;
use arrow::array::{ArrayRef, StringBuilder, TimestampMicrosecondBuilder, UInt8Builder};
use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use arrow::record_batch::RecordBatch;
use std::sync::{Arc, LazyLock};

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

static STRUCTURED_SYSLOG_SCHEMA: LazyLock<Arc<Schema>> = LazyLock::new(|| {
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
        Field::new(
            "received_at",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            false,
        ),
        Field::new("payload_type", DataType::Utf8, false),
        Field::new("parsed", DataType::Utf8, false),
        Field::new(
            "partition_time",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            false,
        ),
    ]))
});

pub fn structured_syslog_schema() -> Arc<Schema> {
    STRUCTURED_SYSLOG_SCHEMA.clone()
}

// ---------------------------------------------------------------------------
// Row mapping
// ---------------------------------------------------------------------------

/// Amortized builder set for the structured-syslog schema. Holds the same 10
/// Arrow columns `structured_syslog_record_to_batch` used to build fresh on
/// every call, as persistent builders reused across many records.
///
/// The extraction logic lives here exactly once: `structured_syslog_record_to_batch`
/// below is a thin `new -> append -> finish` wrapper over it, so the amortized
/// path and the single-record fallback can never drift apart. (Contrast
/// `zeek::schema::ConnAccumulator`, which duplicates `map_conn` and needs a
/// parity test to stay in sync.)
pub(crate) struct StructuredSyslogAccumulator {
    b_priority: UInt8Builder,
    b_severity: UInt8Builder,
    b_facility: UInt8Builder,
    b_timestamp: TimestampMicrosecondBuilder,
    b_hostname: StringBuilder,
    b_app_name: StringBuilder,
    b_received_at: TimestampMicrosecondBuilder,
    b_payload_type: StringBuilder,
    b_parsed: StringBuilder,
    b_partition_time: TimestampMicrosecondBuilder,
    rows: usize,
}

impl StructuredSyslogAccumulator {
    pub(crate) fn new() -> Self {
        let ts = || {
            TimestampMicrosecondBuilder::new().with_data_type(DataType::Timestamp(
                TimeUnit::Microsecond,
                Some("UTC".into()),
            ))
        };
        Self {
            b_priority: UInt8Builder::new(),
            b_severity: UInt8Builder::new(),
            b_facility: UInt8Builder::new(),
            b_timestamp: ts(),
            b_hostname: StringBuilder::new(),
            b_app_name: StringBuilder::new(),
            b_received_at: ts(),
            b_payload_type: StringBuilder::new(),
            b_parsed: StringBuilder::new(),
            b_partition_time: ts(),
            rows: 0,
        }
    }

    /// Append one record. Mirrors the original mapper's field handling
    /// exactly, including `timestamp`'s nullability and `partition_time`'s
    /// derivation from the nullable `timestamp` clamped against the non-null
    /// `received_at`.
    fn append_record(&mut self, rec: &StructuredSyslogRecord) {
        self.b_priority.append_value(rec.priority);
        self.b_severity.append_value(rec.severity);
        self.b_facility.append_value(rec.facility);
        self.b_timestamp
            .append_option(rec.timestamp.map(|t| t.timestamp_micros()));
        self.b_hostname.append_option(rec.hostname.as_deref());
        self.b_app_name.append_option(rec.app_name.as_deref());
        self.b_received_at
            .append_value(rec.received_at.timestamp_micros());
        self.b_payload_type.append_value(rec.payload_type);
        self.b_parsed.append_value(
            serde_json::to_string(&rec.parsed).unwrap_or_else(|_| "null".to_string()),
        );
        // `timestamp` is the syslog header's event time (nullable -- absent for
        // e.g. some CEF/LEEF payloads); `partition_time` derives the buffer's
        // day-clean column from it, clamped against and falling back to the
        // non-null `received_at`. See `crate::forwarding::buffered_writer::partition_time`.
        let partition_time_value =
            crate::forwarding::buffered_writer::partition_time(rec.timestamp, rec.received_at);
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
            Arc::new(self.b_received_at.finish()),
            Arc::new(self.b_payload_type.finish()),
            Arc::new(self.b_parsed.finish()),
            Arc::new(self.b_partition_time.finish()),
        ];
        self.rows = 0;
        Ok(RecordBatch::try_new(structured_syslog_schema(), columns)?)
    }
}

impl crate::forwarding::buffered_writer::RecordBatchAccumulator<StructuredSyslogRecord>
    for StructuredSyslogAccumulator
{
    /// `_now` is unused: `StructuredSyslogRecord` carries its own non-null
    /// `received_at`, so the receipt instant never comes from the clock here.
    /// (IPFIX threads `now` through because `FlowRecord` has no trustworthy
    /// receipt instant of its own.)
    fn try_append(
        &mut self,
        record: &StructuredSyslogRecord,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<bool> {
        self.append_record(record);
        Ok(true)
    }

    fn len(&self) -> usize {
        self.rows
    }

    fn finish(&mut self) -> anyhow::Result<RecordBatch> {
        self.finish_batch()
    }
}

/// Map one `StructuredSyslogRecord` to a single-row `RecordBatch`.
///
/// Thin wrapper over `StructuredSyslogAccumulator` so the column mapping has
/// exactly one implementation shared with the amortized path.
pub fn structured_syslog_record_to_batch(
    rec: &StructuredSyslogRecord,
) -> anyhow::Result<RecordBatch> {
    let mut acc = StructuredSyslogAccumulator::new();
    acc.append_record(rec);
    acc.finish_batch()
}

// ---------------------------------------------------------------------------
// StructuredSyslogSink — ParquetSink adapter
// ---------------------------------------------------------------------------

pub struct StructuredSyslogSink;

impl ParquetSink for StructuredSyslogSink {
    type Record = StructuredSyslogRecord;

    fn source(&self) -> &'static str {
        "structured_syslog"
    }

    fn partition(&self, record: &StructuredSyslogRecord) -> Option<String> {
        Some(record.payload_type.to_string())
    }

    fn schema(&self, _partition: Option<&str>) -> Arc<arrow_schema::Schema> {
        structured_syslog_schema()
    }

    /// Event time column for day bucketing. `partition_time` is non-null by
    /// construction (derived from the nullable `timestamp`, clamped and
    /// falling back to `received_at`), so a buffer keyed on its day is
    /// day-clean for every row even when parsed and unparsed-timestamp
    /// payloads land in the same partition. See `structured_syslog_record_to_batch`.
    fn time_column(&self) -> Option<&'static str> {
        Some("partition_time")
    }

    fn to_record_batch(
        &self,
        record: &StructuredSyslogRecord,
        _schema: &Arc<arrow_schema::Schema>,
    ) -> anyhow::Result<arrow_array::RecordBatch> {
        structured_syslog_record_to_batch(record)
    }

    /// Opt into the amortized builder path. Gated on the schema Arc even
    /// though this sink has only one schema, mirroring `ZeekSink`/`SflowSink`
    /// so a future second schema cannot silently accumulate into the wrong
    /// builder set.
    fn new_batch(
        &self,
        schema: &Arc<arrow_schema::Schema>,
    ) -> Option<
        Box<dyn crate::forwarding::buffered_writer::RecordBatchAccumulator<StructuredSyslogRecord>>,
    > {
        if Arc::ptr_eq(schema, &structured_syslog_schema()) {
            Some(Box::new(StructuredSyslogAccumulator::new()))
        } else {
            None
        }
    }

    /// Overrides the default `day_and_batch`, which would call
    /// `to_record_batch` and read the day back off the built batch --
    /// allocating the full builder set on every push, before `new_batch`'s
    /// accumulator is ever consulted, making the amortized path a no-op.
    ///
    /// Derives the identical day directly: the default reads `ts.value(0)`
    /// from the `partition_time` column (row 0 only), and that column is
    /// written as `partition_time(rec.timestamp, rec.received_at)`, so this
    /// reproduces it exactly without building anything.
    fn day_and_batch(
        &self,
        record: &StructuredSyslogRecord,
        _schema: &Arc<arrow_schema::Schema>,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<(chrono::NaiveDate, Option<arrow_array::RecordBatch>)> {
        let day = crate::forwarding::buffered_writer::partition_time(
            record.timestamp,
            record.received_at,
        )
        .date_naive();
        Ok((day, None))
    }
}

// ---------------------------------------------------------------------------
// Type alias + start function
// ---------------------------------------------------------------------------

pub type StructuredS3Handler =
    crate::forwarding::buffered_writer::ParquetWriterHandle<StructuredSyslogSink>;

/// Construct a `StructuredS3Handler` from `SyslogS3Config` (reusing the same
/// config shape; the `prefix` is used as the S3 key base path).
///
/// Returns `(handler, writer_task_handle)`.
pub fn structured_syslog_start(
    cfg: &SyslogS3Config,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<Arc<dyn crate::forwarding::buffered_writer::UploadSink>>,
) -> (StructuredS3Handler, tokio::task::JoinHandle<()>) {
    use crate::forwarding::buffered_writer::{
        BufferedWriterConfig, FlushPolicy, LiveInterval, ParquetWriterHandle,
    };

    let bwc = BufferedWriterConfig {
        connection: cfg.connection.clone(),
        prefix: cfg.prefix.clone(),
        max_buffer_rows: cfg.max_buffer_rows,
        flush_threshold_bytes: usize::MAX,
        flush_interval_secs: cfg.flush_interval_secs,
        channel_capacity: cfg.channel_capacity,
        // 7 known payload types + 1 overflow = 8 partitions max.
        max_partitions: 8,
    };
    let policy = FlushPolicy {
        max_rows: cfg.max_buffer_rows,
        max_bytes: usize::MAX,
        interval: LiveInterval::new(std::time::Duration::from_secs(cfg.flush_interval_secs)),
    };
    ParquetWriterHandle::start_with_stats(
        StructuredSyslogSink,
        s3,
        bwc,
        policy,
        source_stats,
        descriptor_sink,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forwarding::buffered_writer::ParquetSink;
    use crate::syslog::payload::StructuredSyslogRecord;
    use arrow::array::{StringArray, UInt8Array};

    // -- RecordBatchAccumulator (amortized builder path) --

    /// The amortized path must produce byte-identical columns to the
    /// single-record path. This is the test that would catch the accumulator
    /// and the fallback mapper drifting apart -- except they cannot drift,
    /// because `structured_syslog_record_to_batch` IS the accumulator. This
    /// pins that invariant so a future refactor that re-duplicates the
    /// mapping gets caught.
    #[test]
    fn accumulator_matches_single_record_batches_column_for_column() {
        use crate::forwarding::buffered_writer::RecordBatchAccumulator;
        let recs = [
            sample_record("cef"),
            {
                // timestamp absent -- exercises the nullable column and the
                // partition_time fallback to received_at.
                let mut r = sample_record("leef");
                r.timestamp = None;
                r
            },
            {
                let mut r = sample_record("auditd");
                r.hostname = None;
                r.app_name = None;
                r
            },
        ];

        let mut acc = StructuredSyslogAccumulator::new();
        assert!(acc.is_empty());
        for (i, r) in recs.iter().enumerate() {
            assert!(acc.try_append(r, chrono::Utc::now()).unwrap());
            assert_eq!(acc.len(), i + 1);
        }
        let batched = acc.finish().unwrap();
        assert_eq!(batched.num_rows(), recs.len());

        for (i, r) in recs.iter().enumerate() {
            let single = structured_syslog_record_to_batch(r).unwrap();
            for col in 0..single.num_columns() {
                let a = single.column(col).to_data();
                let b = batched.column(col).slice(i, 1).to_data();
                assert_eq!(
                    a,
                    b,
                    "row {i} column {} ({}) differs between the amortized and \
                     single-record paths",
                    col,
                    structured_syslog_schema().field(col).name()
                );
            }
        }
    }

    /// A builder that kept prior rows would silently duplicate data into the
    /// next flush. `finish` must reset to empty and stay reusable.
    #[test]
    fn accumulator_finish_twice_produces_independent_batches() {
        use crate::forwarding::buffered_writer::RecordBatchAccumulator;
        let mut acc = StructuredSyslogAccumulator::new();
        acc.try_append(&sample_record("cef"), chrono::Utc::now())
            .unwrap();
        acc.try_append(&sample_record("cef"), chrono::Utc::now())
            .unwrap();
        let first = acc.finish().unwrap();
        assert_eq!(first.num_rows(), 2);
        assert_eq!(acc.len(), 0, "finish must reset the row count");
        assert!(acc.is_empty());

        acc.try_append(&sample_record("dhcp"), chrono::Utc::now())
            .unwrap();
        let second = acc.finish().unwrap();
        assert_eq!(
            second.num_rows(),
            1,
            "second batch must hold only the rows appended after the first finish"
        );
        let ptype = second
            .column_by_name("payload_type")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(ptype.value(0), "dhcp");
    }

    /// Guards the silent no-op: a conversion that compiles and passes every
    /// other test while `new_batch` never returns `Some`, so `push()` keeps
    /// allocating a fresh builder set per record and the amortized path is
    /// dead code. This has actually happened on another branch in this repo.
    #[test]
    fn new_batch_activates_for_the_real_schema_and_not_an_unrelated_one() {
        let schema = StructuredSyslogSink.schema(Some("cef"));
        assert!(Arc::ptr_eq(&schema, &structured_syslog_schema()));
        assert!(
            StructuredSyslogSink.new_batch(&schema).is_some(),
            "new_batch must return Some for the real schema -- if None, the \
             accumulator never activates and the conversion is a no-op"
        );
        let other: Arc<Schema> = Arc::new(Schema::new(vec![Field::new(
            "unrelated",
            DataType::Utf8,
            false,
        )]));
        assert!(StructuredSyslogSink.new_batch(&other).is_none());
    }

    /// `day_and_batch` must return the same day the default implementation
    /// would have read off row 0 of the built batch, and must NOT build one.
    #[test]
    fn day_and_batch_matches_the_default_mechanism_without_building_a_batch() {
        let rec = sample_record("cef");
        let schema = StructuredSyslogSink.schema(Some("cef"));
        let (day, batch) = StructuredSyslogSink
            .day_and_batch(&rec, &schema, chrono::Utc::now())
            .unwrap();
        assert!(
            batch.is_none(),
            "must not build a batch -- doing so reinstates the per-push \
             allocation this override exists to avoid"
        );

        let built = structured_syslog_record_to_batch(&rec).unwrap();
        let pt = built
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<arrow::array::TimestampMicrosecondArray>()
            .unwrap();
        let expected = chrono::DateTime::from_timestamp_micros(pt.value(0))
            .unwrap()
            .date_naive();
        assert_eq!(
            day, expected,
            "buffer-key day must equal row 0 partition_time"
        );
    }

    fn sample_record(ptype: &'static str) -> StructuredSyslogRecord {
        StructuredSyslogRecord {
            priority: 134,
            severity: 6,
            facility: 16,
            timestamp: Some(
                chrono::DateTime::parse_from_rfc3339("2024-01-15T10:30:45Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            hostname: Some("fw01".into()),
            app_name: Some("ArcSight".into()),
            received_at: chrono::Utc::now(),
            payload_type: ptype,
            parsed: serde_json::json!({"src": "10.0.0.1", "dst": "10.0.0.2"}),
        }
    }

    #[test]
    fn schema_has_ten_columns() {
        let schema = structured_syslog_schema();
        assert_eq!(
            schema.fields().len(),
            10,
            "expected 10 fields, got {}",
            schema.fields().len()
        );
    }

    #[test]
    fn schema_partition_time_is_non_null_microsecond_timestamp() {
        use arrow::datatypes::{DataType, TimeUnit};
        let schema = structured_syslog_schema();
        let f = schema
            .field_with_name("partition_time")
            .expect("partition_time column");
        assert_eq!(
            f.data_type(),
            &DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
        );
        assert!(!f.is_nullable(), "partition_time must be non-nullable");
    }

    #[test]
    fn schema_payload_type_is_non_nullable_utf8() {
        use arrow::datatypes::DataType;
        let schema = structured_syslog_schema();
        let f = schema.field_with_name("payload_type").unwrap();
        assert_eq!(f.data_type(), &DataType::Utf8);
        assert!(!f.is_nullable());
    }

    #[test]
    fn schema_parsed_is_non_nullable_utf8() {
        use arrow::datatypes::DataType;
        let schema = structured_syslog_schema();
        let f = schema.field_with_name("parsed").unwrap();
        assert_eq!(f.data_type(), &DataType::Utf8);
        assert!(!f.is_nullable());
    }

    #[test]
    fn schema_timestamp_and_received_at_are_microsecond_timestamps() {
        use arrow::datatypes::{DataType, TimeUnit};
        let schema = structured_syslog_schema();
        let expected = DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()));

        let f = schema.field_with_name("timestamp").unwrap();
        assert_eq!(f.data_type(), &expected);
        assert!(f.is_nullable());

        let f = schema.field_with_name("received_at").unwrap();
        assert_eq!(f.data_type(), &expected);
        assert!(!f.is_nullable()); // received_at is always set
    }

    #[test]
    fn absent_timestamp_is_null() {
        use arrow::array::{Array, TimestampMicrosecondArray};
        let mut rec = sample_record("cef");
        rec.timestamp = None;
        let batch = structured_syslog_record_to_batch(&rec).unwrap();
        let col = batch
            .column_by_name("timestamp")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert!(col.is_null(0));
    }

    #[test]
    fn timestamp_and_received_at_are_written_as_microseconds() {
        use arrow::array::TimestampMicrosecondArray;
        use chrono::TimeZone;
        let mut rec = sample_record("cef");
        rec.timestamp = Some(chrono::Utc.timestamp_opt(1_700_000_000, 0).unwrap());
        rec.received_at = chrono::Utc.timestamp_opt(1_700_000_001, 0).unwrap();
        let batch = structured_syslog_record_to_batch(&rec).unwrap();

        let ts = batch
            .column_by_name("timestamp")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(ts.value(0), 1_700_000_000_000_000);

        let received = batch
            .column_by_name("received_at")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(received.value(0), 1_700_000_001_000_000);
    }

    #[test]
    fn sink_partition_returns_payload_type() {
        let sink = StructuredSyslogSink;
        let rec = sample_record("cef");
        assert_eq!(sink.partition(&rec), Some("cef".to_string()));
    }

    #[test]
    fn sink_source_is_structured_syslog() {
        assert_eq!(StructuredSyslogSink.source(), "structured_syslog");
    }

    #[test]
    fn to_record_batch_produces_correct_values() {
        let sink = StructuredSyslogSink;
        let rec = sample_record("leef");
        let schema = sink.schema(Some("leef"));
        let batch = sink.to_record_batch(&rec, &schema).expect("batch");

        assert_eq!(batch.num_rows(), 1);

        let priority = batch
            .column(0)
            .as_any()
            .downcast_ref::<UInt8Array>()
            .unwrap();
        assert_eq!(priority.value(0), 134);

        let ptype_col = batch.column_by_name("payload_type").unwrap();
        let ptype = ptype_col.as_any().downcast_ref::<StringArray>().unwrap();
        assert_eq!(ptype.value(0), "leef");

        let parsed_col = batch.column_by_name("parsed").unwrap();
        let parsed = parsed_col.as_any().downcast_ref::<StringArray>().unwrap();
        let v: serde_json::Value = serde_json::from_str(parsed.value(0)).unwrap();
        assert_eq!(v["src"], "10.0.0.1");
    }

    #[test]
    fn to_record_batch_hostname_nullable() {
        use arrow::array::Array;
        let sink = StructuredSyslogSink;
        let mut rec = sample_record("cef");
        rec.hostname = None;
        let schema = sink.schema(Some("cef"));
        let batch = sink.to_record_batch(&rec, &schema).unwrap();
        let hostname = batch.column_by_name("hostname").unwrap();
        let arr = hostname.as_any().downcast_ref::<StringArray>().unwrap();
        assert!(arr.is_null(0));
    }

    #[test]
    fn structured_syslog_sink_time_column_partition_time_exists_in_schema() {
        let sink = StructuredSyslogSink;
        let col = sink
            .time_column()
            .expect("structured_syslog_sink must opt in to day partitioning");
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
    fn partition_time_equals_timestamp_on_distinctly_different_day() {
        use arrow::array::TimestampMicrosecondArray;
        let mut rec = sample_record("cef");
        // Event a full day before receipt -- an unmistakably different UTC
        // calendar day, so a bug that fell back to received_at could not
        // pass by accident.
        rec.received_at = chrono::DateTime::parse_from_rfc3339("2024-06-02T08:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let event = chrono::DateTime::parse_from_rfc3339("2024-06-01T03:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        rec.timestamp = Some(event);

        let batch = structured_syslog_record_to_batch(&rec).unwrap();
        let col = batch
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(col.value(0), event.timestamp_micros());
    }

    #[test]
    fn partition_time_falls_back_to_received_at_when_timestamp_is_null() {
        use arrow::array::TimestampMicrosecondArray;
        let mut rec = sample_record("cef");
        rec.timestamp = None;
        rec.received_at = chrono::DateTime::parse_from_rfc3339("2024-06-02T08:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let batch = structured_syslog_record_to_batch(&rec).unwrap();
        let col = batch
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(col.value(0), rec.received_at.timestamp_micros());
    }

    #[test]
    fn partition_time_falls_back_to_received_at_when_timestamp_outside_clamp() {
        use arrow::array::TimestampMicrosecondArray;
        let mut rec = sample_record("cef");
        rec.received_at = chrono::DateTime::parse_from_rfc3339("2024-06-02T08:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        // 60 days before receipt -- well past the 30-day backfill clamp.
        rec.timestamp = Some(rec.received_at - chrono::TimeDelta::days(60));

        let batch = structured_syslog_record_to_batch(&rec).unwrap();
        let col = batch
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(col.value(0), rec.received_at.timestamp_micros());
    }

    #[test]
    fn partition_time_mixed_null_and_valid_timestamp_same_receipt_day_agree_regression() {
        // The regression case for this addendum: a null-timestamp row and a
        // valid-timestamp row received on the same real day must derive the
        // buffer day from the SAME non-null column, never from
        // coalesce(timestamp, received_at) (which is not itself a column).
        use arrow::array::TimestampMicrosecondArray;
        let receipt_day_a = chrono::DateTime::parse_from_rfc3339("2024-06-02T08:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let receipt_day_b = chrono::DateTime::parse_from_rfc3339("2024-06-02T20:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let mut rec_a = sample_record("cef");
        rec_a.timestamp = None;
        rec_a.received_at = receipt_day_a;

        let mut rec_b = sample_record("leef");
        rec_b.timestamp = Some(receipt_day_b - chrono::TimeDelta::hours(1));
        rec_b.received_at = receipt_day_b;

        let batch_a = structured_syslog_record_to_batch(&rec_a).unwrap();
        let batch_b = structured_syslog_record_to_batch(&rec_b).unwrap();

        let day_of = |batch: &RecordBatch| {
            let col = batch
                .column_by_name("partition_time")
                .unwrap()
                .as_any()
                .downcast_ref::<TimestampMicrosecondArray>()
                .unwrap();
            chrono::DateTime::from_timestamp_micros(col.value(0))
                .unwrap()
                .date_naive()
        };

        assert_eq!(
            day_of(&batch_a),
            day_of(&batch_b),
            "a null-timestamp row and a valid-timestamp row received the same \
             day must land in the same partition_time day"
        );
    }

    #[tokio::test]
    async fn structured_syslog_start_wires_handle_and_join() {
        // Purpose: verify that structured_syslog_start returns a usable handle
        // and a JoinHandle, and that dropping the handle (closing the channel)
        // with an empty buffer causes the writer task to exit cleanly — no S3
        // round-trip is needed to test this wiring.
        //
        // Previously the test sent one record (with max_buffer_rows=1) which
        // immediately triggered a PutObject against the dead endpoint
        // http://127.0.0.1:1, racing the AWS SDK retry/connect budget against a
        // hardcoded 5 s timeout → flaky under concurrent test load.
        //
        // Fix: do not send any records.  flush_all() on channel-close iterates
        // only over non-empty partition buffers; with an empty buffer map it
        // returns instantly, so the task exits without any S3 call.
        use crate::config::{S3ConnectionConfig, SyslogS3Config};
        use crate::forwarding::s3_sink::S3Sink;

        let conn = S3ConnectionConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            bucket: "test".to_string(),
            region: "us-east-1".to_string(),
            access_key: "KEY".to_string(),
            secret_key: "SECRET".to_string(),
        };
        let s3 = Arc::new(S3Sink::from_connection(&conn).await.expect("constructs"));
        let cfg = SyslogS3Config {
            connection: conn,
            prefix: "structured-syslog-test".to_string(),
            // Large enough that a stray record never triggers an auto-flush.
            max_buffer_rows: 1_000,
            flush_interval_secs: 3600,
            channel_capacity: 16,
        };
        let (handle, join_handle) = structured_syslog_start(
            &cfg,
            s3,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );
        // Drop the handle immediately — empty buffer → flush_all is a no-op →
        // writer task exits without any S3 call.
        drop(handle);
        // 2 s is generous; the task should join in well under 100 ms.
        tokio::time::timeout(std::time::Duration::from_secs(2), join_handle)
            .await
            .expect("writer task exits within 2s")
            .expect("no panic");
    }

    #[tokio::test]
    async fn structured_syslog_sink_reports_into_shared_source_hourly_stats() {
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
            prefix: "structured_syslog".to_string(),
            max_buffer_rows: 1_000,
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 64,
            max_partitions: 8,
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
            StructuredSyslogSink,
            s3,
            bwc,
            policy,
            shared_stats.clone(),
            None,
        );
        writer.push(sample_record("cef")).await.unwrap();

        let snapshot = shared_stats.snapshot();
        let row = snapshot
            .iter()
            .find(|r| r.source == "structured_syslog")
            .unwrap();
        let total: u64 = row.hours.iter().map(|h| h.count).sum();
        assert_eq!(total, 1);
    }
}
