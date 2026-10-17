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

#[tokio::test]
async fn test_envelope_numeric_and_case_redaction_reach_parquet() {
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
            hash_fields: vec![],
            hash_key_env: None,
            mask_patterns: vec![r"\S+@\S+".into(), r"\d{13,16}".into()],
        },
        RedactorKind::Hec,
        &|_| None,
    )
    .unwrap();

    let mut rec = GenericRecord {
        sourcetype: "app".into(),
        host: Some("alice@corp.com".into()),
        fields: serde_json::json!({"card": 4111111111111111u64, "Password": "x", "n": 7}),
        received_at: chrono::Utc::now(),
        ..Default::default()
    };
    redactor.redact_generic(&mut rec);
    assign_event_uuids(std::slice::from_mut(&mut rec));
    handler.try_send(rec).expect("send");
    drop(handler);
    tokio::time::timeout(Duration::from_secs(15), writer)
        .await
        .expect("writer shuts down")
        .unwrap();

    let batches = common::wait_for_rows(dir.path(), 1, Duration::from_secs(15)).await;
    assert_eq!(common::str_col(&batches[0], "host").value(0), "[REDACTED]");
    let fields: serde_json::Value =
        serde_json::from_str(common::str_col(&batches[0], "fields").value(0)).unwrap();
    assert_eq!(fields, serde_json::json!({"card": "[REDACTED]", "n": 7}));
}

#[cfg(feature = "otlp")]
#[tokio::test]
async fn test_otlp_free_text_numeric_and_case_redaction_reach_parquet() {
    use logthing::config::OtlpLocalConfig;
    use logthing::forwarding::otlp_s3::{OtlpRecord, otlp_local_start};

    let dir = tempfile::tempdir().unwrap();
    let cfg = OtlpLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "otlp".to_string(),
        flush_threshold_bytes: usize::MAX,
        flush_interval_secs: 3600,
        channel_capacity: 64,
        max_buffer_rows: 100_000,
    };
    let sink = Arc::new(LocalDiskSink::new(cfg.directory.clone()).await.unwrap());
    let (handler, writer) = otlp_local_start(
        &cfg,
        sink,
        64,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );
    let redactor = Redactor::compile_with_env(
        &RedactionConfig {
            drop_fields: vec!["password".into()],
            hash_fields: vec!["token".into()],
            hash_key_env: Some("K".into()),
            mask_patterns: vec!["secret".into(), r"\d{13,16}".into(), r"10\.9\.8\.7".into()],
        },
        RedactorKind::Otlp,
        &|n| (n == "K").then(|| KEY.to_string()),
    )
    .unwrap();

    let mut rec = OtlpRecord {
        event_uuid: None,
        time: None,
        observed_time: None,
        received_at: chrono::Utc::now(),
        severity_number: Some(9),
        severity_text: Some("secret-sev".into()),
        body: Some(r#"{"card":4111111111111111,"n":7}"#.into()),
        service_name: Some("checkout".into()),
        service_namespace: None,
        service_instance_id: None,
        host_name: Some("secret-host".into()),
        peer_addr: Some("10.9.8.7".into()),
        trace_id: None,
        span_id: None,
        flags: None,
        event_name: Some("secret.event".into()),
        scope_name: Some("secret.lib".into()),
        scope_version: None,
        resource_attributes: serde_json::json!({}),
        attributes: serde_json::json!({"Password": "hunter2", "TOKEN": "tok-1"}),
    };
    redactor.redact_otlp(&mut rec);
    rec.event_uuid = Some(logthing::ingest::new_event_uuid());
    handler.try_send(rec).expect("send");
    drop(handler);
    tokio::time::timeout(Duration::from_secs(15), writer)
        .await
        .expect("writer shuts down")
        .unwrap();

    let batches = common::wait_for_rows(dir.path(), 1, Duration::from_secs(15)).await;
    let b = &batches[0];
    assert_eq!(common::str_col(b, "host_name").value(0), "[REDACTED]-host");
    assert_eq!(
        common::str_col(b, "event_name").value(0),
        "[REDACTED].event"
    );
    assert_eq!(
        common::str_col(b, "severity_text").value(0),
        "[REDACTED]-sev"
    );
    assert_eq!(common::str_col(b, "scope_name").value(0), "[REDACTED].lib");
    assert_eq!(common::str_col(b, "peer_addr").value(0), "10.9.8.7");
    let body: serde_json::Value =
        serde_json::from_str(common::str_col(b, "body").value(0)).unwrap();
    assert_eq!(body, serde_json::json!({"card": "[REDACTED]", "n": 7}));
    let attrs: serde_json::Value =
        serde_json::from_str(common::str_col(b, "attributes").value(0)).unwrap();
    assert!(attrs.get("Password").is_none(), "{attrs}");
    assert_eq!(attrs["TOKEN"].as_str().map(str::len), Some(64), "{attrs}");
}
