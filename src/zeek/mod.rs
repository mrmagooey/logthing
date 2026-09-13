//! Zeek NDJSON ingestion — record type and module root.

use chrono::{DateTime, Utc};

/// A single decoded Zeek log record.
#[derive(Debug, Clone)]
pub struct ZeekRecord {
    /// Stream type, from the JSON `_path` field; `"unknown"` if absent or non-string.
    /// Already run through [`normalize_log_path`] by the listener — construct it the
    /// same way in any new ingest path, or rotated `_path` values fragment downstream.
    pub log_path: String,
    /// Full JSON object as received — used by the schema mapper and the default handler.
    pub fields: serde_json::Value,
    /// Wall-clock time this record was received by the listener.
    pub received_at: DateTime<Utc>,
}

pub mod listener;
pub mod schema;

/// Zeek stream names never contain '.'; log rotation makes shippers emit the
/// archive filename instead (`conn.2026-08-14-16-08-44`, sometimes a full path
/// ending `.log.gz`). Keep the basename up to the first '.'.
pub fn normalize_log_path(raw: &str) -> &str {
    let base = raw.rsplit('/').next().unwrap_or(raw);
    match base.split_once('.') {
        Some((stem, _)) if !stem.is_empty() => stem,
        _ => base,
    }
}

/// A parsed NDJSON line plus whether its `_path` was usable.
pub struct ParsedZeekLine {
    pub record: ZeekRecord,
    /// `_path` was absent or non-string, so [`ZeekRecord::log_path`] is the
    /// `"unknown"` fallback rather than a real stream name. Distinct from a
    /// record whose `_path` is literally the string `"unknown"`, which is a
    /// present path — the listener's `zeek_missing_path` counter depends on
    /// that distinction.
    pub path_was_missing: bool,
}

/// Parse one NDJSON line. The `serde_json::Error` is returned rather than
/// swallowed so the caller can keep it in its log line — the caller owns the
/// `zeek_parse_errors` metric and the warning, since only it knows the peer
/// address.
///
/// `received_at` is passed in rather than read from the clock here so callers
/// (and benches) are deterministic.
pub fn parse_line(
    line: &str,
    received_at: DateTime<Utc>,
) -> Result<ParsedZeekLine, serde_json::Error> {
    let value: serde_json::Value = serde_json::from_str(line)?;
    let (log_path, path_was_missing) = match value.get("_path").and_then(|v| v.as_str()) {
        Some(p) => (normalize_log_path(p).to_string(), false),
        None => ("unknown".to_string(), true),
    };
    Ok(ParsedZeekLine {
        record: ZeekRecord {
            log_path,
            fields: value,
            received_at,
        },
        path_was_missing,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn parse_line_extracts_normalized_path_and_fields() {
        let at = chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let p = parse_line(r#"{"_path":"conn.2026-08-14-16-08-44","uid":"Cabc"}"#, at)
            .expect("valid NDJSON must parse");
        assert_eq!(
            p.record.log_path, "conn",
            "rotation suffix must be normalized off"
        );
        assert_eq!(p.record.fields["uid"], "Cabc");
        assert_eq!(
            p.record.received_at, at,
            "received_at must be the caller's, not Utc::now()"
        );
        assert!(!p.path_was_missing);
    }

    #[test]
    fn parse_line_flags_missing_or_non_string_path_and_falls_back_to_unknown() {
        let at = chrono::Utc::now();
        for line in [r#"{"uid":"Cabc"}"#, r#"{"_path":42,"uid":"Cabc"}"#] {
            let p = parse_line(line, at).expect("valid JSON, just no usable _path");
            assert_eq!(p.record.log_path, "unknown", "line: {line}");
            assert!(p.path_was_missing, "line: {line}");
        }
    }

    /// The regression the `path_was_missing` flag exists to prevent: a literal
    /// `_path` of "unknown" is a present path, and must NOT be counted as a miss.
    #[test]
    fn parse_line_does_not_flag_a_literal_unknown_path_as_missing() {
        let p = parse_line(r#"{"_path":"unknown","uid":"Cabc"}"#, chrono::Utc::now())
            .expect("valid NDJSON must parse");
        assert_eq!(p.record.log_path, "unknown");
        assert!(
            !p.path_was_missing,
            "a present _path of \"unknown\" is not a missing _path"
        );
    }

    #[test]
    fn parse_line_returns_the_serde_error_on_malformed_json() {
        assert!(parse_line("{not json", chrono::Utc::now()).is_err());
    }

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

    // -- normalize_log_path --

    #[test]
    fn normalize_log_path_stable_name_unchanged() {
        assert_eq!(normalize_log_path("conn"), "conn");
    }

    #[test]
    fn normalize_log_path_strips_rotation_suffix() {
        assert_eq!(normalize_log_path("conn.2026-08-14-16-08-44"), "conn");
    }

    #[test]
    fn normalize_log_path_strips_full_rotated_archive_path() {
        assert_eq!(
            normalize_log_path("/logs/conn.2026-08-14-16-08-44.log.gz"),
            "conn"
        );
    }

    #[test]
    fn normalize_log_path_preserves_underscore_names() {
        assert_eq!(normalize_log_path("ssl"), "ssl");
        assert_eq!(normalize_log_path("dce_rpc"), "dce_rpc");
    }

    #[test]
    fn normalize_log_path_empty_stem_falls_through() {
        // Leading '.' produces an empty stem before the first '.' — fall through
        // to the whole basename rather than returning "". sanitize_log_path
        // handles this downstream.
        assert_eq!(normalize_log_path(".hidden"), ".hidden");
    }

    #[test]
    fn normalize_log_path_empty_input() {
        assert_eq!(normalize_log_path(""), "");
    }

    #[test]
    fn normalize_log_path_trailing_slash_yields_empty() {
        // Degrades to the same bucket as a missing _path: sanitize_log_path
        // maps "" → "unknown" downstream.
        assert_eq!(normalize_log_path("conn/"), "");
    }
}
