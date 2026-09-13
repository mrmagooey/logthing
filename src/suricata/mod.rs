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

/// A parsed EVE JSON line plus whether its `event_type` was usable.
pub struct ParsedSuricataLine {
    pub record: SuricataRecord,
    /// `event_type` was absent or non-string. Distinct from a record whose
    /// `event_type` is literally `"unknown"`, which is a present value.
    pub event_type_was_missing: bool,
}

/// Parse one EVE JSON line. The `serde_json::Error` is returned rather than
/// swallowed so the caller can keep it in its log line — the caller owns the
/// `suricata_parse_errors` metric and the warning, since only it knows the
/// peer address.
///
/// Unlike Zeek's `_path`, `event_type` is used verbatim: Suricata does not
/// rotate it into the value the way a log shipper rotates a filename.
pub fn parse_line(
    line: &str,
    received_at: DateTime<Utc>,
) -> Result<ParsedSuricataLine, serde_json::Error> {
    let value: serde_json::Value = serde_json::from_str(line)?;
    let (event_type, event_type_was_missing) =
        match value.get("event_type").and_then(|v| v.as_str()) {
            Some(t) => (t.to_string(), false),
            None => ("unknown".to_string(), true),
        };
    Ok(ParsedSuricataLine {
        record: SuricataRecord {
            event_type,
            fields: value,
            received_at,
        },
        event_type_was_missing,
    })
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

    #[test]
    fn parse_line_extracts_event_type_and_fields() {
        let at = chrono::Utc::now();
        let p = parse_line(r#"{"event_type":"alert","src_ip":"10.0.0.1"}"#, at)
            .expect("valid EVE JSON must parse");
        assert_eq!(p.record.event_type, "alert");
        assert_eq!(p.record.fields["src_ip"], "10.0.0.1");
        assert_eq!(p.record.received_at, at);
        assert!(!p.event_type_was_missing);
    }

    #[test]
    fn parse_line_flags_missing_or_non_string_event_type() {
        let at = chrono::Utc::now();
        for line in [r#"{"src_ip":"10.0.0.1"}"#, r#"{"event_type":7}"#] {
            let p = parse_line(line, at).expect("valid JSON, just no usable event_type");
            assert_eq!(p.record.event_type, "unknown", "line: {line}");
            assert!(p.event_type_was_missing, "line: {line}");
        }
    }

    #[test]
    fn parse_line_does_not_flag_a_literal_unknown_event_type_as_missing() {
        let p = parse_line(r#"{"event_type":"unknown"}"#, chrono::Utc::now())
            .expect("valid EVE JSON must parse");
        assert!(!p.event_type_was_missing);
    }

    #[test]
    fn parse_line_returns_the_serde_error_on_malformed_json() {
        assert!(parse_line("{not json", chrono::Utc::now()).is_err());
    }
}
