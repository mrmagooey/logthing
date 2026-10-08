//! Parse helpers for the three HEC / NDJSON ingest formats.

use crate::ingest::GenericRecord;
use chrono::{DateTime, TimeZone, Utc};

// ---------------------------------------------------------------------------
// HEC event envelope (`/services/collector/event`)
// ---------------------------------------------------------------------------

/// Parse one or more newline-delimited HEC event envelopes.
///
/// Each line must be a JSON object with at minimum an `"event"` key.
/// Optional keys: `"time"` (Unix epoch float), `"host"`, `"sourcetype"`, `"source"`, `"index"`
/// and `"fields"`.
/// Blank / whitespace-only lines are skipped.
///
/// Returns an error if any non-blank line fails to parse as JSON or is
/// missing the required `"event"` key.
pub fn parse_hec_event_body(
    body: &[u8],
    default_sourcetype: &str,
) -> anyhow::Result<Vec<GenericRecord>> {
    let text = std::str::from_utf8(body)?;
    let now = Utc::now();
    let mut records = Vec::new();

    for line in text.split('\n') {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let obj: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| anyhow::Error::new(e).context("HEC envelope JSON parse error"))?;

        let event = obj
            .get("event")
            .ok_or_else(|| anyhow::anyhow!("HEC envelope missing required 'event' key"))?
            .clone();

        let sourcetype = obj
            .get("sourcetype")
            .and_then(|v| v.as_str())
            .unwrap_or(default_sourcetype)
            .to_string();

        let host = obj
            .get("host")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let time = obj
            .get("time")
            .and_then(|v| v.as_f64())
            .map(epoch_float_to_datetime);

        let source = obj
            .get("source")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let index = obj
            .get("index")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let indexed_fields = obj.get("fields").filter(|v| v.is_object()).cloned();

        records.push(GenericRecord {
            sourcetype,
            host,
            time,
            fields: event,
            received_at: now,
            event_uuid: None,
            source,
            index,
            indexed_fields,
        });
    }

    Ok(records)
}

// ---------------------------------------------------------------------------
// HEC raw body (`/services/collector/raw`)
// ---------------------------------------------------------------------------

/// Wrap a raw (non-JSON) body as a single `GenericRecord`.
///
/// The body is stored verbatim as a UTF-8 string in `fields["raw"]`.
/// Invalid UTF-8 sequences are replaced with the Unicode replacement character.
pub fn parse_hec_raw_body(body: &[u8], sourcetype: &str) -> anyhow::Result<GenericRecord> {
    let raw = String::from_utf8_lossy(body).into_owned();
    Ok(GenericRecord {
        sourcetype: sourcetype.to_string(),
        host: None,
        time: None,
        fields: serde_json::json!({ "raw": raw }),
        received_at: Utc::now(),
        ..Default::default()
    })
}

// ---------------------------------------------------------------------------
// NDJSON body (`/ingest`)
// ---------------------------------------------------------------------------

/// Parse a newline-delimited JSON body.  Each non-blank line must be a
/// JSON object; it is stored verbatim as `fields`.  Returns an error on
/// the first malformed line.
pub fn parse_ndjson_body(
    body: &[u8],
    default_sourcetype: &str,
) -> anyhow::Result<Vec<GenericRecord>> {
    let text = std::str::from_utf8(body)?;
    let now = Utc::now();
    let mut records = Vec::new();

    for line in text.split('\n') {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let fields: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| anyhow::Error::new(e).context("NDJSON parse error"))?;

        records.push(GenericRecord {
            sourcetype: default_sourcetype.to_string(),
            host: None,
            time: None,
            fields,
            received_at: now,
            ..Default::default()
        });
    }

    Ok(records)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a Unix epoch float (seconds, possibly fractional) to `DateTime<Utc>`.
///
/// Out-of-range or non-finite values fall back to `Utc::now()` rather than
/// panicking.  The saturating f64→i64/u32 casts (stable since Rust 1.45) mean
/// no cast can panic; `timestamp_opt` handles the out-of-range case.
fn epoch_float_to_datetime(epoch_secs: f64) -> DateTime<Utc> {
    let secs = epoch_secs.trunc() as i64;
    let nanos = ((epoch_secs.fract()).abs() * 1_000_000_000.0).round() as u32;
    Utc.timestamp_opt(secs, nanos)
        .single()
        .unwrap_or_else(Utc::now)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse_hec_event_body ----

    #[test]
    fn hec_event_single_envelope() {
        let body = br#"{"event":{"action":"login","user":"alice"},"sourcetype":"audit","host":"srv1","time":1700000000.5}"#;
        let records = parse_hec_event_body(body, "default_type").unwrap();
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.sourcetype, "audit");
        assert_eq!(r.host.as_deref(), Some("srv1"));
        assert!(r.time.is_some());
        // fields["action"] is "login", fields["user"] is "alice"
        assert_eq!(r.fields["action"], "login");
        assert_eq!(r.fields["user"], "alice");
        // time parsed to ~1700000000 epoch
        let ts = r.time.unwrap().timestamp();
        assert!((ts - 1700000000).abs() <= 1);
    }

    #[test]
    fn hec_event_multiple_newline_delimited() {
        let body = b"{\"event\":{\"a\":1},\"sourcetype\":\"t1\"}\n{\"event\":{\"b\":2},\"sourcetype\":\"t2\"}\n";
        let records = parse_hec_event_body(body, "fallback").unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].sourcetype, "t1");
        assert_eq!(records[1].sourcetype, "t2");
    }

    #[test]
    fn hec_event_uses_default_sourcetype_when_absent() {
        let body = br#"{"event":{"x":1}}"#;
        let records = parse_hec_event_body(body, "my_default").unwrap();
        assert_eq!(records[0].sourcetype, "my_default");
    }

    #[test]
    fn hec_event_no_time_gives_none() {
        let body = br#"{"event":{"x":1},"sourcetype":"t"}"#;
        let records = parse_hec_event_body(body, "t").unwrap();
        assert!(records[0].time.is_none());
    }

    #[test]
    fn hec_event_missing_event_key_is_error() {
        let body = br#"{"sourcetype":"t","host":"h"}"#;
        assert!(parse_hec_event_body(body, "t").is_err());
    }

    #[test]
    fn hec_event_skips_blank_lines() {
        let body = b"{\"event\":{\"k\":1},\"sourcetype\":\"t\"}\n\n{\"event\":{\"k\":2},\"sourcetype\":\"t\"}\n";
        let records = parse_hec_event_body(body, "t").unwrap();
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn hec_event_invalid_json_is_error() {
        let body = b"not json\n";
        assert!(parse_hec_event_body(body, "t").is_err());
    }

    #[test]
    fn hec_event_invalid_utf8_is_error() {
        let body = b"\xff\xfe{\"event\":{}}";
        assert!(parse_hec_event_body(body, "t").is_err());
    }

    #[test]
    fn hec_event_time_as_integer() {
        let body = br#"{"event":{"x":1},"sourcetype":"t","time":1609459200}"#;
        let records = parse_hec_event_body(body, "t").unwrap();
        let ts = records[0].time.unwrap().timestamp();
        assert_eq!(ts, 1609459200);
    }

    #[test]
    fn hec_event_time_non_numeric_string_gives_none() {
        // "time" present but as a string — as_f64() returns None → time is None
        let body = br#"{"event":{"x":1},"sourcetype":"t","time":"garbage"}"#;
        let records = parse_hec_event_body(body, "t").unwrap();
        assert!(records[0].time.is_none());
    }

    // ---- parse_hec_raw_body ----

    #[test]
    fn hec_raw_wraps_body_as_single_record() {
        let body = b"raw log line here";
        let rec = parse_hec_raw_body(body, "raw_type").unwrap();
        assert_eq!(rec.sourcetype, "raw_type");
        assert_eq!(rec.fields["raw"], "raw log line here");
        assert!(rec.time.is_none());
        assert!(rec.host.is_none());
    }

    #[test]
    fn hec_raw_empty_body_is_accepted() {
        let rec = parse_hec_raw_body(b"", "raw_type").unwrap();
        assert_eq!(rec.fields["raw"], "");
    }

    #[test]
    fn hec_raw_invalid_utf8_uses_replacement_char() {
        // Invalid UTF-8 → lossy conversion, no panic
        let body = b"hello \xff world";
        let rec = parse_hec_raw_body(body, "t").unwrap();
        let raw = rec.fields["raw"].as_str().unwrap();
        assert!(raw.contains('\u{FFFD}'));
    }

    // ---- parse_ndjson_body ----

    #[test]
    fn ndjson_parses_multiple_lines() {
        let body = b"{\"host\":\"h1\",\"msg\":\"a\"}\n{\"host\":\"h2\",\"msg\":\"b\"}\n";
        let records = parse_ndjson_body(body, "ndjson_src").unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].sourcetype, "ndjson_src");
        assert_eq!(records[0].fields["host"], "h1");
    }

    #[test]
    fn ndjson_skips_blank_lines() {
        let body = b"{\"k\":1}\n\n{\"k\":2}\n";
        let records = parse_ndjson_body(body, "t").unwrap();
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn ndjson_invalid_json_line_is_error() {
        let body = b"not json\n";
        assert!(parse_ndjson_body(body, "t").is_err());
    }

    #[test]
    fn ndjson_empty_body_gives_empty_vec() {
        let records = parse_ndjson_body(b"", "t").unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn ndjson_invalid_utf8_is_error() {
        let body = b"\xff\xfe{\"k\":1}";
        assert!(parse_ndjson_body(body, "t").is_err());
    }

    #[test]
    fn ndjson_uses_default_sourcetype() {
        let body = b"{\"k\":1}\n";
        let records = parse_ndjson_body(body, "my_src").unwrap();
        assert_eq!(records[0].sourcetype, "my_src");
    }

    #[test]
    fn hec_event_envelope_keeps_source_index_and_indexed_fields() {
        let body = br#"{"event":"x","source":"/var/log/app.log","index":"main","fields":{"env":"prod","n":3}}"#;
        let records = parse_hec_event_body(body, "t").unwrap();
        let r = &records[0];
        assert_eq!(r.source.as_deref(), Some("/var/log/app.log"));
        assert_eq!(r.index.as_deref(), Some("main"));
        assert_eq!(
            r.indexed_fields,
            Some(serde_json::json!({"env": "prod", "n": 3}))
        );
        assert!(r.event_uuid.is_none(), "parse must not assign ids");
    }

    #[test]
    fn hec_event_envelope_ignores_non_object_fields_and_non_string_source() {
        let body = br#"{"event":"x","source":5,"index":null,"fields":["a"]}"#;
        let records = parse_hec_event_body(body, "t").unwrap();
        let r = &records[0];
        assert!(r.source.is_none() && r.index.is_none() && r.indexed_fields.is_none());
    }

    #[test]
    fn raw_and_ndjson_records_carry_no_envelope_columns() {
        let raw = parse_hec_raw_body(b"hello", "t").unwrap();
        assert!(raw.source.is_none() && raw.index.is_none() && raw.indexed_fields.is_none());
        let nd = parse_ndjson_body(b"{\"a\":1}\n", "t").unwrap();
        assert!(nd[0].source.is_none() && nd[0].index.is_none());
    }
}
