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
