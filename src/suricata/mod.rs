//! Suricata EVE JSON ingestion — record type and module root.

use chrono::{DateTime, Utc};

/// A single decoded Suricata EVE JSON record.
#[derive(Debug, Clone)]
pub struct SuricataRecord {
    /// Event type, from the JSON `event_type` field; `"unknown"` if absent or non-string.
    pub event_type: String,
    /// Full JSON object as received — used by the schema mapper and the default handler.
    pub fields: serde_json::Value,
    /// Wall-clock time this record was received by the listener.
    pub received_at: DateTime<Utc>,
}

pub mod listener;
pub mod schema;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suricata_record_stores_event_type_and_fields() {
        let rec = SuricataRecord {
            event_type: "alert".to_string(),
            fields: serde_json::json!({"event_type": "alert", "src_ip": "10.0.0.1"}),
            received_at: chrono::Utc::now(),
        };
        assert_eq!(rec.event_type, "alert");
        assert_eq!(rec.fields["src_ip"], "10.0.0.1");
    }

    #[test]
    fn suricata_record_unknown_event_type() {
        let rec = SuricataRecord {
            event_type: "unknown".to_string(),
            fields: serde_json::json!({}),
            received_at: chrono::Utc::now(),
        };
        assert_eq!(rec.event_type, "unknown");
    }
}
