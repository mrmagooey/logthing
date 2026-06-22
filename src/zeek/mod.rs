//! Zeek NDJSON ingestion — record type and module root.

use chrono::{DateTime, Utc};

/// A single decoded Zeek log record.
#[derive(Debug, Clone)]
pub struct ZeekRecord {
    /// Stream type, from the JSON `_path` field; `"unknown"` if absent or non-string.
    pub log_path: String,
    /// Full JSON object as received — used by the schema mapper and the default handler.
    pub fields: serde_json::Value,
    /// Wall-clock time this record was received by the listener.
    pub received_at: DateTime<Utc>,
}

pub mod listener;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeek_record_stores_log_path_and_fields() {
        let rec = ZeekRecord {
            log_path: "conn".to_string(),
            fields: serde_json::json!({"_path": "conn", "uid": "Ctest123"}),
            received_at: Utc::now(),
        };
        assert_eq!(rec.log_path, "conn");
        assert_eq!(rec.fields["uid"], "Ctest123");
    }

    #[test]
    fn zeek_record_unknown_log_path() {
        let rec = ZeekRecord {
            log_path: "unknown".to_string(),
            fields: serde_json::json!({}),
            received_at: Utc::now(),
        };
        assert_eq!(rec.log_path, "unknown");
    }
}
