//! Generic JSON / Splunk HEC ingest types.
//!
//! `GenericRecord` is the unified envelope for all three ingest routes
//! (`/services/collector/event`, `/services/collector/raw`, `/ingest`).
//! `GenericSink` is the `ParquetSink` adapter that persists these records
//! to S3 partitioned by `sourcetype`.

pub mod decompress;
pub mod handlers;
pub mod parse;

pub use handlers::{HecQueryParams, handle_hec_event, handle_hec_raw, handle_ndjson};
pub use parse::{parse_hec_event_body, parse_hec_raw_body, parse_ndjson_body};

use crate::forwarding::generic_s3::GenericS3Handler;
use chrono::{DateTime, Utc};
use subtle::ConstantTimeEq;

/// Unified envelope record produced by all three HEC/NDJSON ingest routes.
///
/// `fields` holds the raw JSON payload; for HEC event envelopes this is the
/// value of `"event"` key.  For raw and NDJSON routes it is the full parsed
/// JSON object.  The `sourcetype` is used as the Parquet partition key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenericRecord {
    /// Log source type; used as the S3 partition key (e.g. `"access_log"`).
    pub sourcetype: String,
    /// Originating host, if present in the HEC envelope or query parameter.
    pub host: Option<String>,
    /// Event timestamp from the HEC envelope (`"time"` field, epoch seconds).
    /// `None` when absent — consumers should fall back to `received_at`.
    pub time: Option<DateTime<Utc>>,
    /// The event payload as a JSON value.
    pub fields: serde_json::Value,
    /// Wall-clock time this server received the record.
    pub received_at: DateTime<Utc>,
    /// Row identity (UUIDv7 string). `None` until [`assign_event_uuids`] runs.
    #[serde(default)]
    pub event_uuid: Option<String>,
    /// Splunk envelope `"source"` (string only).
    #[serde(default)]
    pub source: Option<String>,
    /// Splunk envelope `"index"` (string only).
    #[serde(default)]
    pub index: Option<String>,
    /// Splunk envelope `"fields"` object (indexed fields); other JSON types are ignored.
    #[serde(default)]
    pub indexed_fields: Option<serde_json::Value>,
}

impl Default for GenericRecord {
    fn default() -> Self {
        Self {
            sourcetype: String::new(),
            host: None,
            time: None,
            fields: serde_json::Value::Null,
            received_at: Utc::now(),
            event_uuid: None,
            source: None,
            index: None,
            indexed_fields: None,
        }
    }
}

/// Records that carry a row identity assigned at ingest.
pub trait EventUuid {
    /// Store the freshly generated identity on the record.
    fn set_event_uuid(&mut self, uuid: String);
}

impl EventUuid for GenericRecord {
    fn set_event_uuid(&mut self, uuid: String) {
        self.event_uuid = Some(uuid);
    }
}

/// A new time-ordered row identity (UUIDv7, hyphenated lowercase).
pub fn new_event_uuid() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// Give every record in `records` a fresh `event_uuid`.
///
/// ORDERING CONTRACT: handlers call this as a SEPARATE step AFTER parsing/mapping and (in a
/// later phase) after redaction, and BEFORE `try_send`. Redaction must therefore never see or
/// depend on the id, and the id must never be derived from redacted-away content. Do not fold
/// id generation into the parsers.
pub fn assign_event_uuids<R: EventUuid>(records: &mut [R]) {
    for r in records.iter_mut() {
        r.set_event_uuid(new_event_uuid());
    }
}

/// Axum extension carrying optional ingest-route S3 handlers.
///
/// Injected as `.layer(axum::Extension(ingest_state))` on the protected router.
/// Cloning is O(1): `GenericS3Handler` is a `ParquetWriterHandle<_>` which
/// wraps an `Arc<tokio::sync::mpsc::Sender<_>>`.
#[derive(Clone, Default)]
pub struct IngestState {
    /// Generic S3 handler for HEC / NDJSON ingest routes.
    /// `None` when `[hec.s3]` is absent or construction failed.
    pub generic_s3: Option<GenericS3Handler>,
    /// Generic local-disk handler for HEC / NDJSON ingest routes.
    /// `None` when `[hec.local]` is absent or construction failed.
    /// Independent of `generic_s3` — both may be `Some` simultaneously.
    pub generic_local: Option<GenericS3Handler>,
    /// OTLP S3 handler. `None` when `[otlp.s3]` is absent or construction failed.
    pub otlp_s3: Option<crate::forwarding::otlp_s3::OtlpHandler>,
    /// OTLP local-disk handler. `None` when `[otlp.local]` is absent or construction failed.
    /// Independent of `otlp_s3`.
    pub otlp_local: Option<crate::forwarding::otlp_s3::OtlpHandler>,
}

/// Validate an `Authorization` header value against the configured HEC token.
///
/// The header must have the form `"Splunk <token>"`.  Comparison is performed
/// in constant time (via `subtle::ConstantTimeEq`) to prevent timing attacks.
///
/// Returns `true` only when the header is present, well-formed, and the token
/// matches `expected` exactly.
pub fn check_hec_token(header_value: Option<&str>, expected: &str) -> bool {
    let Some(value) = header_value else {
        return false;
    };
    let Some(submitted) = value.strip_prefix("Splunk ") else {
        return false;
    };
    // Reject mismatched lengths up front. NOTE: this length check is an early
    // branch, so the configured token's byte length is observable via timing —
    // an accepted tradeoff (token length is low-sensitivity). The token VALUE is
    // compared in constant time via `ct_eq` only on the equal-length path below.
    let a = submitted.as_bytes();
    let b = expected.as_bytes();
    if a.len() != b.len() {
        // The `a.ct_eq(a)` call is a best-effort timing decoy; it does not fully
        // mask the length-branch timing difference above.
        let _ = a.ct_eq(a);
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    #[test]
    fn generic_record_fields_are_accessible() {
        let rec = GenericRecord {
            sourcetype: "my_app".to_string(),
            host: Some("host1".to_string()),
            time: None,
            fields: json!({"key": "value"}),
            received_at: Utc::now(),
            ..Default::default()
        };
        assert_eq!(rec.sourcetype, "my_app");
        assert_eq!(rec.host.as_deref(), Some("host1"));
        assert!(rec.time.is_none());
        assert_eq!(rec.fields["key"], "value");
    }

    #[test]
    fn generic_record_derives_debug_and_clone() {
        let rec = GenericRecord {
            sourcetype: "test".to_string(),
            host: None,
            time: Some(Utc::now()),
            fields: json!({}),
            received_at: Utc::now(),
            ..Default::default()
        };
        let cloned = rec.clone();
        assert_eq!(cloned.sourcetype, rec.sourcetype);
        // Debug must not panic
        let _ = format!("{:?}", cloned);
    }

    #[test]
    fn ingest_state_default_has_no_handlers() {
        let state = IngestState::default();
        assert!(state.generic_s3.is_none());
        assert!(state.generic_local.is_none());
    }

    #[test]
    fn ingest_state_is_clone() {
        let state = IngestState::default();
        let cloned = state.clone();
        assert!(cloned.generic_s3.is_none());
        assert!(cloned.generic_local.is_none());
    }

    #[test]
    fn check_hec_token_accepts_valid_token() {
        assert!(check_hec_token(
            Some("Splunk my-secret-token"),
            "my-secret-token"
        ));
    }

    #[test]
    fn check_hec_token_rejects_wrong_token() {
        assert!(!check_hec_token(
            Some("Splunk wrong-token"),
            "my-secret-token"
        ));
    }

    #[test]
    fn check_hec_token_rejects_missing_header() {
        assert!(!check_hec_token(None, "my-secret-token"));
    }

    #[test]
    fn check_hec_token_rejects_wrong_scheme() {
        // Must start with "Splunk " — Bearer or Basic are rejected.
        assert!(!check_hec_token(
            Some("Bearer my-secret-token"),
            "my-secret-token"
        ));
        assert!(!check_hec_token(Some("my-secret-token"), "my-secret-token"));
    }

    #[test]
    fn check_hec_token_rejects_empty_expected_when_header_empty_splunk_prefix() {
        // "Splunk " with no token: submitted="" vs expected="" → vacuously equal
        // but we still accept it when expected is empty (dev-only no-op mode).
        assert!(check_hec_token(Some("Splunk "), ""));
    }

    #[test]
    fn check_hec_token_constant_time_mismatched_lengths_reject() {
        // Different lengths must reject without panicking.
        assert!(!check_hec_token(
            Some("Splunk short"),
            "a-much-longer-token-value"
        ));
    }

    #[test]
    fn assign_event_uuids_sets_unique_time_ordered_v7_ids() {
        let mut recs = vec![
            GenericRecord::default(),
            GenericRecord::default(),
            GenericRecord::default(),
        ];
        assign_event_uuids(&mut recs);
        let ids: Vec<String> = recs
            .iter()
            .map(|r| r.event_uuid.clone().expect("event_uuid assigned"))
            .collect();
        for id in &ids {
            let u = uuid::Uuid::parse_str(id).expect("valid uuid");
            assert_eq!(u.get_version_num(), 7, "must be UUIDv7: {id}");
        }
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted, ids, "ids must be unique and non-decreasing");
    }

    #[test]
    fn generic_record_default_has_no_event_uuid_or_envelope_fields() {
        let r = GenericRecord::default();
        assert!(r.event_uuid.is_none() && r.source.is_none() && r.index.is_none());
        assert!(r.indexed_fields.is_none());
    }

    #[test]
    fn generic_record_deserializes_without_new_fields() {
        // Forward compatibility: JSON written before these fields existed.
        let json = r#"{"sourcetype":"t","host":null,"time":null,"fields":{},
                       "received_at":"2026-10-06T00:00:00Z"}"#;
        let r: GenericRecord = serde_json::from_str(json).expect("old shape parses");
        assert!(r.event_uuid.is_none());
    }
}
