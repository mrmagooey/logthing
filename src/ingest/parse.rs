//! Parse helpers for the three HEC / NDJSON ingest formats.

use crate::ingest::GenericRecord;
use chrono::{DateTime, TimeZone, Utc};

// ---------------------------------------------------------------------------
// HEC event envelope (`/services/collector/event`)
// ---------------------------------------------------------------------------

/// Parse one or more newline-delimited HEC event envelopes.
///
/// Each line must be a JSON object with at minimum an `"event"` key.
/// Optional keys: `"time"` (epoch seconds, or milliseconds when >= 1e11; number or numeric
/// string), `"host"`, `"sourcetype"`, `"source"`, `"index"`
/// and `"fields"`.
/// Blank / whitespace-only lines are skipped.
///
/// Returns an error if any non-blank line fails to parse as JSON or is
/// missing the required `"event"` key.
pub fn parse_hec_event_body(
    body: &[u8],
    default_sourcetype: &str,
) -> anyhow::Result<Vec<GenericRecord>> {
    let body = body.strip_prefix(UTF8_BOM).unwrap_or(body);
    let text = std::str::from_utf8(body)?;
    let now = Utc::now();
    let mut records = presized_records(text);

    for line in text.split('\n') {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut obj: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| anyhow::Error::new(e).context("HEC envelope JSON parse error"))?;

        let event = obj
            .get_mut("event")
            .ok_or_else(|| anyhow::anyhow!("HEC envelope missing required 'event' key"))?
            .take();

        let sourcetype = obj
            .get("sourcetype")
            .and_then(|v| v.as_str())
            .unwrap_or(default_sourcetype)
            .to_string();

        let host = obj
            .get("host")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let time = obj.get("time").and_then(envelope_time);

        let source = obj
            .get("source")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let index = obj
            .get("index")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let indexed_fields = obj
            .get_mut("fields")
            .filter(|v| v.is_object())
            .map(serde_json::Value::take);

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
    let body = body.strip_prefix(UTF8_BOM).unwrap_or(body);
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

/// Upper bound on the records reserved up front from a body's newline count. A body of bare
/// newlines (up to the HEC body limit) must not be able to drive a large allocation.
const MAX_PRESIZE_RECORDS: usize = 1024;

/// Allocate the result Vec for a newline-delimited body: `min(newline_count + 1, 1024)` slots.
///
/// Trade-off: the cap bounds the reservation to ~1024 * `size_of::<GenericRecord>()` per request
/// (itself bounded overall by the request concurrency limit). Counting only non-blank lines was
/// rejected because it needs a slower pre-pass.
fn presized_records(text: &str) -> Vec<GenericRecord> {
    let lines = text.bytes().filter(|&b| b == b'\n').count() + 1;
    Vec::with_capacity(lines.min(MAX_PRESIZE_RECORDS))
}

/// UTF-8 byte-order mark some Windows forwarders prepend to a request body.
const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

/// Magnitude at or above which an envelope `time` is epoch milliseconds, not seconds
/// (1e11 s is year 5138; 1e11 ms is 1973).
const EPOCH_MILLIS_THRESHOLD: f64 = 1e11;

/// Read an envelope `time` (JSON number or numeric string) as a timestamp.
///
/// Magnitudes >= [`EPOCH_MILLIS_THRESHOLD`] are epoch milliseconds, smaller ones seconds.
/// Integers are converted exactly; only fractional values go through `f64`.
/// Returns `None` for anything unparsable, non-finite or outside the representable range.
fn envelope_time(v: &serde_json::Value) -> Option<DateTime<Utc>> {
    let (int, float) = match v {
        serde_json::Value::Number(n) => (n.as_i64(), n.as_f64()),
        serde_json::Value::String(s) => {
            let s = s.trim();
            (s.parse::<i64>().ok(), s.parse::<f64>().ok())
        }
        _ => return None,
    };
    if let Some(i) = int {
        return if (i as f64).abs() >= EPOCH_MILLIS_THRESHOLD {
            Utc.timestamp_millis_opt(i).single()
        } else {
            Utc.timestamp_opt(i, 0).single()
        };
    }
    let raw = float.filter(|f| f.is_finite())?;
    epoch_float_to_datetime(if raw.abs() >= EPOCH_MILLIS_THRESHOLD {
        raw / 1000.0
    } else {
        raw
    })
}

/// Convert a Unix epoch float (seconds, possibly fractional) to `DateTime<Utc>`.
///
/// The sub-second part is always non-negative (`-1.5` is 1969-12-31T23:59:58.5Z).
/// Returns `None` when the value is outside the representable range.
fn epoch_float_to_datetime(epoch_secs: f64) -> Option<DateTime<Utc>> {
    let whole = epoch_secs.floor();
    let nanos = (((epoch_secs - whole) * 1_000_000_000.0).round() as u32).min(999_999_999);
    Utc.timestamp_opt(whole as i64, nanos).single()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse_hec_event_body ----

    // ---- HEC time parsing / BOM ----

    fn time_of(json_time: &str) -> Option<DateTime<Utc>> {
        let body = format!(r#"{{"event":{{"x":1}},"time":{json_time}}}"#);
        parse_hec_event_body(body.as_bytes(), "t").unwrap()[0].time
    }

    /// f64 seconds near 1.7e9 carry ~0.2us of error; allow 1us.
    fn assert_near_nanos(t: DateTime<Utc>, want: u32) {
        let got = t.timestamp_subsec_nanos();
        assert!(got.abs_diff(want) < 1_000, "subsec {got} not near {want}");
    }

    #[test]
    fn test_time_string_parses_like_number() {
        let t = time_of(r#""1700000000.123""#).unwrap();
        assert_eq!(t.timestamp(), 1_700_000_000);
        assert_near_nanos(t, 123_000_000);
        assert_eq!(t, time_of("1700000000.123").unwrap());
    }

    #[test]
    fn test_time_millis_at_or_above_1e11_is_epoch_millis() {
        let t = time_of("1700000000123").unwrap();
        assert_eq!(t.timestamp_micros(), 1_700_000_000_123_000);
        assert_eq!(t.date_naive().to_string(), "2023-11-14");
        let t = time_of(r#""1700000000123""#).unwrap();
        assert_eq!(t.timestamp_micros(), 1_700_000_000_123_000);
        let t = time_of("1.7e12").unwrap();
        assert_eq!(t.timestamp_micros(), 1_700_000_000_000_000);
        assert_eq!(time_of("99999999999").unwrap().timestamp(), 99_999_999_999);
        assert_eq!(time_of("100000000000").unwrap().timestamp(), 100_000_000);
    }

    #[test]
    fn test_time_integer_seconds_are_exact() {
        assert_eq!(
            time_of("1700000000").unwrap().timestamp_micros(),
            1_700_000_000_000_000
        );
        assert_eq!(
            time_of(" 1700000000 ").unwrap().timestamp_micros(),
            1_700_000_000_000_000
        );
        assert_eq!(
            time_of(r#"" 1700000000 ""#).unwrap().timestamp_micros(),
            1_700_000_000_000_000
        );
    }

    #[test]
    fn test_time_plus_sign_and_negative_millis() {
        let t = time_of(r#""+1.5""#).unwrap();
        assert_eq!(t.timestamp_micros(), 1_500_000);
        let t = time_of("-1.7e12").unwrap();
        assert_eq!(t.timestamp_micros(), -1_700_000_000_000_000);
        assert_eq!(
            time_of("-1700000000123").unwrap().timestamp_micros(),
            -1_700_000_000_123_000
        );
    }

    #[test]
    fn test_time_out_of_range_is_none() {
        assert!(time_of("1e300").is_none());
        assert!(time_of("-1e300").is_none());
        assert!(time_of(r#""1e300""#).is_none());
        assert!(time_of("9223372036854775807").is_none());
        assert!(time_of("18446744073709551615").is_none());
    }

    #[test]
    fn test_ndjson_leading_bom_is_stripped() {
        let mut body = vec![0xEF, 0xBB, 0xBF];
        body.extend_from_slice(b"{\"a\":1}\n{\"a\":2}\n");
        let records = parse_ndjson_body(&body, "t").unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].fields["a"], 1);
    }

    #[test]
    fn test_time_negative_fraction_has_nonnegative_subsecond() {
        let t = time_of("-1.5").unwrap();
        assert_eq!(t.timestamp(), -2);
        assert_eq!(t.timestamp_subsec_nanos(), 500_000_000);
    }

    #[test]
    fn test_time_unparsable_string_is_none() {
        assert!(time_of(r#""yesterday""#).is_none());
        assert!(time_of(r#""""#).is_none());
        assert!(time_of("true").is_none());
        assert!(time_of(r#""NaN""#).is_none());
        assert!(time_of(r#""inf""#).is_none());
    }

    #[test]
    fn test_hec_event_leading_bom_is_stripped() {
        let mut body = vec![0xEF, 0xBB, 0xBF];
        body.extend_from_slice(b"{\"event\":{\"a\":1}}\n{\"event\":{\"a\":2}}\n");
        let records = parse_hec_event_body(&body, "t").unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].fields["a"], 2);
    }

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

    // ---- fix 1: take() instead of clone, capped pre-size ----

    fn hec_lines(n: usize) -> String {
        (0..n)
            .map(|i| format!(r#"{{"event":{{"i":{i}}},"sourcetype":"t"}}"#))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn hec_event_full_envelope_parses_to_exact_record() {
        let body = br#"{"event":{"action":"login","user":{"name":"alice","groups":["a","b"]},"n":null},"sourcetype":"audit","host":"srv1","time":1700000000,"source":"/var/log/app.log","index":"main","fields":{"env":"prod","nested":{"k":[1,2]}}}"#;
        let records = parse_hec_event_body(body, "dflt").unwrap();
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.sourcetype, "audit");
        assert_eq!(r.host.as_deref(), Some("srv1"));
        assert_eq!(r.time, Utc.timestamp_opt(1_700_000_000, 0).single());
        assert_eq!(
            r.fields,
            serde_json::json!({
                "action": "login",
                "user": {"name": "alice", "groups": ["a", "b"]},
                "n": null
            })
        );
        assert_eq!(r.source.as_deref(), Some("/var/log/app.log"));
        assert_eq!(r.index.as_deref(), Some("main"));
        assert_eq!(
            r.indexed_fields,
            Some(serde_json::json!({"env": "prod", "nested": {"k": [1, 2]}}))
        );
        assert!(r.event_uuid.is_none());
    }

    #[test]
    fn hec_event_non_object_fields_yield_none() {
        for fields in [r#"["a"]"#, "5", r#""s""#, "null", "true"] {
            let body = format!(r#"{{"event":{{"x":1}},"fields":{fields}}}"#);
            let records = parse_hec_event_body(body.as_bytes(), "t").unwrap();
            assert!(records[0].indexed_fields.is_none(), "fields={fields}");
            assert_eq!(records[0].fields, serde_json::json!({"x": 1}));
        }
    }

    #[test]
    fn hec_event_empty_object_fields_is_some_empty_object() {
        let records = parse_hec_event_body(br#"{"event":1,"fields":{}}"#, "t").unwrap();
        assert_eq!(records[0].indexed_fields, Some(serde_json::json!({})));
    }

    #[test]
    fn hec_event_missing_event_error_text_unchanged() {
        let err = parse_hec_event_body(br#"{"sourcetype":"t"}"#, "t").unwrap_err();
        assert_eq!(err.to_string(), "HEC envelope missing required 'event' key");
    }

    #[test]
    fn hec_event_non_object_envelope_is_missing_event() {
        for line in ["[1]", "5", r#""s""#, "true"] {
            let err = parse_hec_event_body(line.as_bytes(), "t").unwrap_err();
            assert_eq!(
                err.to_string(),
                "HEC envelope missing required 'event' key",
                "line={line}"
            );
        }
    }

    #[test]
    fn hec_event_invalid_json_error_text_unchanged() {
        let err = parse_hec_event_body(b"not json", "t").unwrap_err();
        assert_eq!(err.to_string(), "HEC envelope JSON parse error");
    }

    #[test]
    fn hec_event_null_event_is_preserved() {
        let records = parse_hec_event_body(br#"{"event":null}"#, "t").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].fields, serde_json::Value::Null);
    }

    #[test]
    fn hec_event_duplicate_event_key_last_wins() {
        let records = parse_hec_event_body(br#"{"event":{"a":1},"event":{"b":2}}"#, "t").unwrap();
        assert_eq!(records[0].fields, serde_json::json!({"b": 2}));
    }

    #[test]
    fn hec_event_error_on_later_line_discards_earlier_records() {
        let body = b"{\"event\":1}\n{\"sourcetype\":\"t\"}\n";
        let err = parse_hec_event_body(body, "t").unwrap_err();
        assert_eq!(err.to_string(), "HEC envelope missing required 'event' key");
    }

    #[test]
    fn hec_event_presize_matches_normal_body() {
        let body = hec_lines(100);
        let records = parse_hec_event_body(body.as_bytes(), "t").unwrap();
        assert_eq!(records.len(), 100);
        assert!(
            records.capacity() >= 100 && records.capacity() < 128,
            "capacity {} should be pre-sized to ~100 (an unsized Vec grows to 128)",
            records.capacity()
        );
    }

    #[test]
    fn hec_event_presize_is_capped_for_newline_flood() {
        let mut body = "\n".repeat(100_000);
        body.push_str(r#"{"event":{"x":1}}"#);
        let records = parse_hec_event_body(body.as_bytes(), "t").unwrap();
        assert_eq!(records.len(), 1);
        assert!(
            records.capacity() <= MAX_PRESIZE_RECORDS,
            "capacity {} must not follow the newline count",
            records.capacity()
        );
    }
}
