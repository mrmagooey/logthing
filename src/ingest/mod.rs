//! Generic JSON / Splunk HEC ingest types.
//!
//! `GenericRecord` is the unified envelope for all three ingest routes
//! (`/services/collector/event`, `/services/collector/raw`, `/ingest`).
//! `GenericSink` (Task 4.3) is the `ParquetSink` adapter that persists
//! these records to S3 partitioned by `sourcetype`.

use chrono::{DateTime, Utc};
use crate::forwarding::generic_s3::GenericS3Handler;

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
}

/// Axum extension carrying optional ingest-route S3 handlers.
///
/// Injected as `.layer(axum::Extension(ingest_state))` on the protected router.
/// Cloning is O(1): `GenericS3Handler` is a `ParquetWriterHandle<_>` which
/// wraps an `Arc<tokio::sync::mpsc::Sender<_>>`.
///
/// # Extension point
/// Unit 5 will add `pub otlp_s3: Option<OtlpS3Handler>` here.
#[derive(Clone, Default)]
pub struct IngestState {
    /// Generic S3 handler for HEC / NDJSON ingest routes.
    /// `None` when `[hec]` s3 config is absent or construction failed.
    pub generic_s3: Option<GenericS3Handler>,
    // Unit 5: pub otlp_s3: Option<OtlpS3Handler>,
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
    }

    #[test]
    fn ingest_state_is_clone() {
        let state = IngestState { generic_s3: None };
        let cloned = state.clone();
        assert!(cloned.generic_s3.is_none());
    }
}
