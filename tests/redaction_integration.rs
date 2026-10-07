//! Integration: redacted HEC records land in Parquet with no trace of the originals.

mod common;

use logthing::config::{GenericLocalConfig, RedactionConfig};
use logthing::forwarding::generic_s3::hec_local_start;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::ingest::{GenericRecord, assign_event_uuids};
use logthing::redaction::{Redactor, RedactorKind};
use std::sync::Arc;
use std::time::Duration;

const KEY: &str = "0123456789abcdef";

#[tokio::test]
async fn test_redacted_fields_never_reach_parquet_files() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = GenericLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "hec".to_string(),
        flush_threshold_bytes: usize::MAX,
        flush_interval_secs: 3600,
        channel_capacity: 64,
        max_buffer_rows: 100_000,
    };
    let sink = Arc::new(
        LocalDiskSink::new(cfg.directory.clone())
            .await
            .expect("LocalDiskSink constructs"),
    );
    let (handler, writer) = hec_local_start(
        &cfg,
        sink,
        64,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );
    let redactor = Redactor::compile_with_env(
        &RedactionConfig {
            drop_fields: vec!["password".into()],
            hash_fields: vec!["email".into()],
            hash_key_env: Some("K".into()),
            mask_patterns: vec![r"\d{3}-\d{2}-\d{4}".into()],
        },
        RedactorKind::Hec,
        &|n| (n == "K").then(|| KEY.to_string()),
    )
    .unwrap();

    let mut rec = GenericRecord {
        sourcetype: "app".into(),
        fields: serde_json::json!({
            "password": "hunter2", "email": "alice@example.com",
            "note": "ssn 123-45-6789", "ok": "visible"
        }),
        received_at: chrono::Utc::now(),
        ..Default::default()
    };
    // Same sequence the handlers run: redact, then identity, then enqueue.
    redactor.redact_generic(&mut rec);
    assign_event_uuids(std::slice::from_mut(&mut rec));
    handler.try_send(rec).expect("send");
    drop(handler);
    tokio::time::timeout(Duration::from_secs(15), writer)
        .await
        .expect("writer shuts down")
        .unwrap();

    let batches = common::wait_for_rows(dir.path(), 1, Duration::from_secs(15)).await;
    // Zstd can hide plaintext, so this byte scan is only a weak guard; the decoded column
    // assertions below are the real ones.
    let bytes: Vec<u8> = common::parquet_files(dir.path())
        .iter()
        .flat_map(|p| std::fs::read(p).unwrap())
        .collect();
    let hay = String::from_utf8_lossy(&bytes);
    for secret in ["hunter2", "alice@example.com", "123-45-6789"] {
        assert!(
            !hay.contains(secret),
            "{secret} leaked into the parquet bytes"
        );
    }
    let fields: serde_json::Value =
        serde_json::from_str(common::str_col(&batches[0], "fields").value(0)).unwrap();
    assert!(fields.get("password").is_none(), "{fields}");
    assert_eq!(fields["note"], "ssn [REDACTED]");
    assert_eq!(fields["ok"], "visible");
    assert_eq!(
        fields["email"],
        "f3d6ddc7dbf9be2eb667360a5a9a43434c54e345f522bbb433afeba094d74aa2"
    );
    assert!(
        !common::str_col(&batches[0], "event_uuid")
            .value(0)
            .is_empty()
    );
}
