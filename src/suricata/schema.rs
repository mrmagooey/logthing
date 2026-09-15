//! Suricata EVE JSON schema — single envelope schema for all event types.
//!
//! Unlike Zeek (which has a per-stream typed registry), Suricata v1 uses one
//! envelope schema for every event_type.  This keeps the implementation simple
//! and avoids the need to maintain a growing registry as Suricata event types evolve.

use crate::suricata::SuricataRecord;
use arrow::array::{ArrayRef, StringBuilder, TimestampMicrosecondBuilder};
use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use arrow::record_batch::RecordBatch;
use std::sync::{Arc, LazyLock};

/// Envelope schema for all Suricata EVE JSON records.
///
/// Columns:
/// - `event_type`  — Utf8, non-null  (from SuricataRecord.event_type)
/// - `received_at` — Timestamp(µs, UTC), non-null  (wall-clock ingest time)
/// - `src_ip`      — Utf8, nullable  (opportunistic fast path; null when absent)
/// - `payload`     — Utf8, non-null  (full JSON object as string)
/// - `partition_time` — Timestamp(µs, UTC), non-null  (the instant the buffer's
///   day was derived from; see `map_envelope`)
pub fn envelope_schema() -> Arc<Schema> {
    static S: LazyLock<Arc<Schema>> = LazyLock::new(|| {
        Arc::new(Schema::new(vec![
            Field::new("event_type", DataType::Utf8, false),
            Field::new(
                "received_at",
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                false,
            ),
            Field::new("src_ip", DataType::Utf8, true),
            Field::new("payload", DataType::Utf8, false),
            Field::new(
                "partition_time",
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                false,
            ),
        ]))
    });
    S.clone()
}

/// Amortized builder set for the envelope schema. Holds the same 5 Arrow
/// builders `map_envelope` used to create fresh on every call, as persistent
/// fields, so they can be reused across many records via `finish(&mut self)`
/// instead of reallocated per record. Mirrors `zeek::schema::ConnAccumulator`.
pub(crate) struct EnvelopeAccumulator {
    b_event_type: StringBuilder,
    b_received_at: TimestampMicrosecondBuilder,
    b_src_ip: StringBuilder,
    b_payload: StringBuilder,
    b_partition_time: TimestampMicrosecondBuilder,
    rows: usize,
}

impl EnvelopeAccumulator {
    pub(crate) fn new() -> Self {
        Self {
            b_event_type: StringBuilder::new(),
            b_received_at: TimestampMicrosecondBuilder::new().with_data_type(DataType::Timestamp(
                TimeUnit::Microsecond,
                Some("UTC".into()),
            )),
            b_src_ip: StringBuilder::new(),
            b_payload: StringBuilder::new(),
            b_partition_time: TimestampMicrosecondBuilder::new().with_data_type(
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            ),
            rows: 0,
        }
    }

    /// Append one `SuricataRecord` into the persistent builders. Shared by
    /// both the amortized path (`RecordBatchAccumulator::try_append`) and
    /// `map_envelope`'s single-record wrapper below -- identical extraction
    /// logic either way, so there is exactly one place that knows how a
    /// `SuricataRecord` becomes an envelope row.
    fn append_envelope_value(&mut self, record: &SuricataRecord) {
        let src_ip = record
            .fields
            .get("src_ip")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let received_at = record.received_at.timestamp_micros();
        let payload = record.fields.to_string();
        // Suricata has no event-carried timestamp, so `received_at` is both the
        // event and the receipt instant. Routed through the shared helper (rather
        // than assigned directly) so every sink derives `partition_time` via one
        // code path.
        let partition_time = crate::forwarding::buffered_writer::partition_time(
            Some(record.received_at),
            record.received_at,
        );

        self.b_event_type.append_value(&record.event_type);
        self.b_received_at.append_value(received_at);
        self.b_src_ip.append_option(src_ip.as_deref());
        self.b_payload.append_value(&payload);
        self.b_partition_time
            .append_value(partition_time.timestamp_micros());
        self.rows += 1;
    }

    fn finish_batch(&mut self) -> anyhow::Result<RecordBatch> {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(self.b_event_type.finish()),
            Arc::new(self.b_received_at.finish()),
            Arc::new(self.b_src_ip.finish()),
            Arc::new(self.b_payload.finish()),
            Arc::new(self.b_partition_time.finish()),
        ];
        self.rows = 0;
        Ok(RecordBatch::try_new(envelope_schema(), columns)?)
    }
}

impl crate::forwarding::buffered_writer::RecordBatchAccumulator<SuricataRecord>
    for EnvelopeAccumulator
{
    fn try_append(
        &mut self,
        record: &SuricataRecord,
        // Suricata's own `received_at` (stamped on the record at ingest) is
        // both the event and receipt instant `append_envelope_value` already
        // derives `partition_time` from -- the shared per-push clock read has
        // nothing to add here. See the trait doc comment for why the
        // parameter exists at all.
        _now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<bool> {
        // Suricata has exactly one schema (the envelope), unlike Zeek's
        // per-log-path registry, so there is no mismatch case to fall back
        // from: every SuricataRecord belongs to this accumulator.
        self.append_envelope_value(record);
        Ok(true)
    }

    fn len(&self) -> usize {
        self.rows
    }

    fn finish(&mut self) -> anyhow::Result<RecordBatch> {
        self.finish_batch()
    }
}

/// Map one `SuricataRecord` to a single-row `RecordBatch` using the envelope schema.
pub fn map_envelope(record: &SuricataRecord) -> anyhow::Result<RecordBatch> {
    let mut acc = EnvelopeAccumulator::new();
    acc.append_envelope_value(record);
    acc.finish_batch()
}

/// Suricata's EVE `event_type` values, as a closed set. The wire value is
/// unbounded in length and charset, so it must never reach a Prometheus label
/// raw — see `zeek::schema::metric_log_path` for the same problem solved
/// against a registry.
///
/// Hand-maintained, and that is a real difference from zeek's version, which
/// self-updates when a schema is added. Adding a new EVE type here is a
/// deliberate act; until it is added it reports as "other".
const EVE_EVENT_TYPES: &[&str] = &[
    "alert", "anomaly", "drop", "dns", "http", "tls", "ssh", "smtp", "ftp", "smb", "dhcp", "krb5",
    "flow", "netflow", "fileinfo", "stats",
];

/// Bound an `event_type` value to the closed set above, for use as a metric
/// label. `event_type` comes straight off the wire and is unbounded in both
/// length and charset, so labelling a Prometheus counter with it raw lets any
/// client that can reach the listener mint a permanent series per record.
pub fn metric_event_type(event_type: &str) -> &'static str {
    EVE_EVENT_TYPES
        .iter()
        .find(|known| **known == event_type)
        .copied()
        .unwrap_or("other")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suricata::SuricataRecord;
    use arrow::array::StringArray;
    use arrow::datatypes::DataType;
    use chrono::Utc;

    /// `event_type` is attacker-controlled, so the metric label must be
    /// drawn from the fixed allowlist, never from the wire value.
    #[test]
    fn metric_event_type_bounds_the_label_to_the_known_set() {
        for known in EVE_EVENT_TYPES {
            assert_eq!(
                metric_event_type(known),
                *known,
                "modelled event types keep their own series"
            );
        }
        for hostile in [
            "unknown",
            "made_up_type",
            &"A".repeat(16_384),
            "alert\u{0}injected",
            "",
        ] {
            assert_eq!(
                metric_event_type(hostile),
                "other",
                "an unmodelled event_type must collapse to a single series, not mint a new one"
            );
        }
    }

    fn make_alert_record() -> SuricataRecord {
        SuricataRecord {
            event_type: "alert".to_string(),
            fields: serde_json::json!({
                "event_type": "alert",
                "src_ip": "192.168.1.100",
                "dest_ip": "1.2.3.4",
                "alert": {"signature": "ET SCAN", "category": "Scan"}
            }),
            received_at: Utc::now(),
        }
    }

    #[test]
    fn envelope_schema_has_required_columns() {
        let s = envelope_schema();
        s.field_with_name("event_type").expect("event_type column");
        s.field_with_name("received_at")
            .expect("received_at column");
        s.field_with_name("src_ip").expect("src_ip column");
        s.field_with_name("payload").expect("payload column");

        let f = s.field_with_name("payload").unwrap();
        assert_eq!(*f.data_type(), DataType::Utf8);
        assert!(!f.is_nullable(), "payload must not be nullable");

        let f = s.field_with_name("event_type").unwrap();
        assert!(!f.is_nullable(), "event_type must not be nullable");

        let f = s.field_with_name("src_ip").unwrap();
        assert!(
            f.is_nullable(),
            "src_ip is opportunistic — must be nullable"
        );
    }

    #[test]
    fn schema_received_at_is_microsecond_timestamp() {
        use arrow::datatypes::{DataType, TimeUnit};
        let s = envelope_schema();
        let f = s.field_with_name("received_at").unwrap();
        assert_eq!(
            f.data_type(),
            &DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
        );
        assert!(!f.is_nullable());
    }

    #[test]
    fn map_envelope_extracts_event_type_and_payload() {
        let rec = make_alert_record();
        let batch = map_envelope(&rec).unwrap();
        assert_eq!(batch.num_rows(), 1);

        let event_type_col = batch
            .column_by_name("event_type")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(event_type_col.value(0), "alert");

        let payload_col = batch
            .column_by_name("payload")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(payload_col.value(0)).unwrap();
        assert_eq!(parsed["src_ip"], "192.168.1.100");
    }

    #[test]
    fn map_envelope_received_at_is_exact_microseconds() {
        use arrow::array::TimestampMicrosecondArray;
        let mut rec = make_alert_record();
        rec.received_at = chrono::DateTime::parse_from_rfc3339("2024-01-15T10:30:00.123456Z")
            .unwrap()
            .with_timezone(&Utc);
        let batch = map_envelope(&rec).unwrap();
        let col = batch
            .column_by_name("received_at")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .expect("received_at column should be TimestampMicrosecondArray");
        assert_eq!(col.value(0), rec.received_at.timestamp_micros());
    }

    #[test]
    fn schema_has_non_null_microsecond_partition_time() {
        let s = envelope_schema();
        let f = s
            .field_with_name("partition_time")
            .expect("partition_time column");
        assert_eq!(
            f.data_type(),
            &DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
        );
        assert!(!f.is_nullable(), "partition_time must be non-nullable");
    }

    #[test]
    fn map_envelope_partition_time_equals_received_at() {
        use arrow::array::TimestampMicrosecondArray;
        // A distinctive, far-from-"now" instant: a broken mapper that fell
        // back to Utc::now() or to the epoch would visibly fail this.
        let mut rec = make_alert_record();
        rec.received_at = chrono::DateTime::parse_from_rfc3339("2024-01-15T10:30:00.123456Z")
            .unwrap()
            .with_timezone(&Utc);
        let batch = map_envelope(&rec).unwrap();
        let col = batch
            .column_by_name("partition_time")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .expect("partition_time column should be TimestampMicrosecondArray");
        assert_eq!(col.value(0), rec.received_at.timestamp_micros());
    }

    #[test]
    fn map_envelope_unknown_event_type_stored_correctly() {
        let rec = SuricataRecord {
            event_type: "unknown".to_string(),
            fields: serde_json::json!({"dest_port": 443}),
            received_at: Utc::now(),
        };
        let batch = map_envelope(&rec).unwrap();
        let event_type_col = batch
            .column_by_name("event_type")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(event_type_col.value(0), "unknown");
    }

    #[test]
    fn map_envelope_absent_src_ip_is_null() {
        let rec = SuricataRecord {
            event_type: "stats".to_string(),
            fields: serde_json::json!({"uptime": 3600}),
            received_at: Utc::now(),
        };
        let batch = map_envelope(&rec).unwrap();
        use arrow::array::Array;
        let src_ip = batch
            .column_by_name("src_ip")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert!(src_ip.is_null(0), "absent src_ip must be null");
    }

    #[test]
    fn map_envelope_parquet_round_trip() {
        use bytes::Bytes;
        use parquet::arrow::ArrowWriter;
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

        let rec = make_alert_record();
        let batch = map_envelope(&rec).unwrap();
        let schema = envelope_schema();

        let mut buf = Vec::new();
        let mut writer = ArrowWriter::try_new(&mut buf, schema, None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
        assert!(!buf.is_empty());

        let bytes = Bytes::from(buf);
        let mut reader = ParquetRecordBatchReaderBuilder::try_new(bytes)
            .unwrap()
            .build()
            .unwrap();
        let rb = reader.next().unwrap().unwrap();
        assert_eq!(rb.num_rows(), 1);
        let event_type_col = rb
            .column_by_name("event_type")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(event_type_col.value(0), "alert");
    }

    // --- EnvelopeAccumulator tests ---

    fn make_accumulator_test_records() -> Vec<SuricataRecord> {
        vec![
            make_alert_record(),
            // Missing src_ip -> null column, exercised through the accumulator.
            SuricataRecord {
                event_type: "stats".to_string(),
                fields: serde_json::json!({"uptime": 42}),
                received_at: Utc::now(),
            },
            // Non-ASCII, "odd" event_type -- must round-trip byte for byte,
            // not just for the common ASCII case.
            SuricataRecord {
                event_type: "évèpredator🔥".to_string(),
                fields: serde_json::json!({"src_ip": "10.1.2.3", "note": "unicode event_type"}),
                received_at: Utc::now(),
            },
        ]
    }

    #[test]
    fn envelope_accumulator_matches_map_envelope_output_row_for_row() {
        use crate::forwarding::buffered_writer::RecordBatchAccumulator;

        let records = make_accumulator_test_records();

        // Baseline: today's exact per-record path, N single-row batches concatenated.
        let single_row_batches: Vec<RecordBatch> =
            records.iter().map(|r| map_envelope(r).unwrap()).collect();
        let expected =
            arrow::compute::concat_batches(&envelope_schema(), &single_row_batches).unwrap();

        // Amortized path: one accumulator, N appends, one finish.
        let mut acc = EnvelopeAccumulator::new();
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
    fn envelope_accumulator_len_and_is_empty() {
        use crate::forwarding::buffered_writer::RecordBatchAccumulator;

        let mut acc = EnvelopeAccumulator::new();
        assert_eq!(acc.len(), 0);
        assert!(acc.is_empty());

        acc.try_append(&make_alert_record(), chrono::Utc::now())
            .unwrap();
        assert_eq!(acc.len(), 1);
        assert!(!acc.is_empty());

        acc.try_append(&make_alert_record(), chrono::Utc::now())
            .unwrap();
        assert_eq!(acc.len(), 2);

        acc.finish().unwrap();
        assert_eq!(acc.len(), 0, "finish must reset the row count");
        assert!(acc.is_empty());
    }

    #[test]
    fn envelope_accumulator_finish_twice_produces_independent_batches() {
        use crate::forwarding::buffered_writer::RecordBatchAccumulator;

        let mut acc = EnvelopeAccumulator::new();

        let rec_a = SuricataRecord {
            event_type: "alert".to_string(),
            fields: serde_json::json!({"src_ip": "1.1.1.1"}),
            received_at: Utc::now(),
        };
        acc.try_append(&rec_a, chrono::Utc::now()).unwrap();
        let batch_a = acc.finish().unwrap();
        assert_eq!(
            batch_a.num_rows(),
            1,
            "first finish must contain exactly the rows appended before it"
        );

        let rec_b = SuricataRecord {
            event_type: "flow".to_string(),
            fields: serde_json::json!({"src_ip": "2.2.2.2"}),
            received_at: Utc::now(),
        };
        let rec_c = SuricataRecord {
            event_type: "dns".to_string(),
            fields: serde_json::json!({"src_ip": "3.3.3.3"}),
            received_at: Utc::now(),
        };
        acc.try_append(&rec_b, chrono::Utc::now()).unwrap();
        acc.try_append(&rec_c, chrono::Utc::now()).unwrap();
        let batch_b = acc.finish().unwrap();

        assert_eq!(
            batch_b.num_rows(),
            2,
            "second finish must contain exactly the rows appended since the first finish -- \
             a builder that retained prior rows would produce 3 here, silently duplicating data"
        );
        let event_types = batch_b
            .column_by_name("event_type")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(event_types.value(0), "flow");
        assert_eq!(event_types.value(1), "dns");
    }
}
