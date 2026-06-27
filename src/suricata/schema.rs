//! Suricata EVE JSON schema — single envelope schema for all event types.
//!
//! Unlike Zeek (which has a per-stream typed registry), Suricata v1 uses one
//! envelope schema for every event_type.  This keeps the implementation simple
//! and avoids the need to maintain a growing registry as Suricata event types evolve.

use crate::suricata::SuricataRecord;
use arrow::array::{ArrayRef, StringBuilder};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use std::sync::{Arc, LazyLock};

/// Envelope schema for all Suricata EVE JSON records.
///
/// Columns:
/// - `event_type`  — Utf8, non-null  (from SuricataRecord.event_type)
/// - `received_at` — Utf8, non-null  (RFC-3339 wall-clock ingest time)
/// - `src_ip`      — Utf8, nullable  (opportunistic fast path; null when absent)
/// - `payload`     — Utf8, non-null  (full JSON object as string)
pub fn envelope_schema() -> Arc<Schema> {
    static S: LazyLock<Arc<Schema>> = LazyLock::new(|| {
        Arc::new(Schema::new(vec![
            Field::new("event_type", DataType::Utf8, false),
            Field::new("received_at", DataType::Utf8, false),
            Field::new("src_ip", DataType::Utf8, true),
            Field::new("payload", DataType::Utf8, false),
        ]))
    });
    S.clone()
}

/// Map one `SuricataRecord` to a single-row `RecordBatch` using the envelope schema.
pub fn map_envelope(record: &SuricataRecord) -> anyhow::Result<RecordBatch> {
    let schema = envelope_schema();

    let src_ip = record
        .fields
        .get("src_ip")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let received_at = record.received_at.to_rfc3339();
    let payload = record.fields.to_string();

    let mut b_event_type = StringBuilder::new();
    let mut b_received_at = StringBuilder::new();
    let mut b_src_ip = StringBuilder::new();
    let mut b_payload = StringBuilder::new();

    b_event_type.append_value(&record.event_type);
    b_received_at.append_value(&received_at);
    b_src_ip.append_option(src_ip.as_deref());
    b_payload.append_value(&payload);

    let columns: Vec<ArrayRef> = vec![
        Arc::new(b_event_type.finish()),
        Arc::new(b_received_at.finish()),
        Arc::new(b_src_ip.finish()),
        Arc::new(b_payload.finish()),
    ];
    Ok(RecordBatch::try_new(schema, columns)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::StringArray;
    use arrow::datatypes::DataType;
    use chrono::Utc;
    use crate::suricata::SuricataRecord;

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
        s.field_with_name("received_at").expect("received_at column");
        s.field_with_name("src_ip").expect("src_ip column");
        s.field_with_name("payload").expect("payload column");

        let f = s.field_with_name("payload").unwrap();
        assert_eq!(*f.data_type(), DataType::Utf8);
        assert!(!f.is_nullable(), "payload must not be nullable");

        let f = s.field_with_name("event_type").unwrap();
        assert!(!f.is_nullable(), "event_type must not be nullable");

        let f = s.field_with_name("src_ip").unwrap();
        assert!(f.is_nullable(), "src_ip is opportunistic — must be nullable");
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
}
