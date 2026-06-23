//! Integration test: WindowsEvent → ParquetWriterHandle<WefSink> → Parquet object in MinIO.
//!
//! Requires a running MinIO (or S3-compatible) instance.
//! Set MINIO_ENDPOINT, MINIO_BUCKET, MINIO_ACCESS_KEY, MINIO_SECRET_KEY env vars.
//! If MINIO_ENDPOINT is absent, the test is skipped.
//!
//! WEF S3 key layout (no source prefix): `event_type=<id>/year=Y/month=MM/day=DD/<uuid>.parquet`

use logthing::config::{S3ConnectionConfig, WefS3Config};
use logthing::forwarding::parquet_s3::wef_start;
use logthing::forwarding::s3_sink::S3Sink;
use logthing::models::{EventLevel, ParsedEvent, WindowsEvent};
use std::sync::Arc;

fn skip_if_no_minio() -> Option<String> {
    std::env::var("MINIO_ENDPOINT").ok()
}

fn minio_wef_config(endpoint: &str) -> WefS3Config {
    WefS3Config {
        connection: S3ConnectionConfig {
            endpoint: endpoint.to_string(),
            bucket: std::env::var("MINIO_BUCKET").unwrap_or_else(|_| "wef-events".to_string()),
            region: "us-east-1".to_string(),
            access_key: std::env::var("MINIO_ACCESS_KEY")
                .unwrap_or_else(|_| "minioadmin".to_string()),
            secret_key: std::env::var("MINIO_SECRET_KEY")
                .unwrap_or_else(|_| "minioadmin".to_string()),
        },
        prefix: "".to_string(), // empty prefix — preserves legacy event_type=<id>/ root layout
        max_buffer_rows: 1,     // flush immediately on first event
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 4096,
    }
}

fn make_windows_event(event_id: u32) -> Arc<WindowsEvent> {
    let parsed = ParsedEvent {
        provider: "Microsoft-Windows-Security-Auditing".into(),
        event_id,
        level: EventLevel::Information,
        task: 12544,
        opcode: 0,
        keywords: 0x8020000000000000,
        time_created: chrono::Utc::now(),
        event_record_id: 42,
        process_id: Some(700),
        thread_id: Some(1234),
        channel: "Security".into(),
        computer: "workstation01".into(),
        security_user_id: Some("S-1-5-18".into()),
        message: Some("An account was successfully logged on.".into()),
        data: Some(serde_json::json!({
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": "SYSTEM",
            "LogonType": "5",
        })),
    };
    Arc::new(
        WindowsEvent::new(
            "workstation01".into(),
            "<Event><System><EventID>4624</EventID></System></Event>".into(),
        )
        .with_parsed(parsed),
    )
}

#[tokio::test]
async fn wef_event_appears_as_parquet_in_s3() {
    let endpoint = match skip_if_no_minio() {
        Some(e) => e,
        None => {
            eprintln!("MINIO_ENDPOINT not set — skipping wef_s3 integration test");
            return;
        }
    };

    let cfg = minio_wef_config(&endpoint);
    let sink = Arc::new(
        S3Sink::from_connection(&cfg.connection)
            .await
            .expect("S3Sink::from_connection"),
    );

    // wef_start returns (handle, writer_join_handle).
    // The handle type is ParquetWriterHandle<WefSink> which exposes try_send().
    let (handle, _writer_task) = wef_start(&cfg, sink.clone());

    let event = make_windows_event(4624);
    handle.try_send(event).expect("try_send must succeed");

    // Give the background task time to flush (max_buffer_rows=1 and flush_threshold_bytes=1
    // both trigger flush on first event)
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // Build an S3 client for verification
    use aws_sdk_s3::Client as S3Client;
    let region = aws_sdk_s3::config::Region::new("us-east-1");
    let credentials = aws_credential_types::Credentials::new(
        cfg.connection.access_key.clone(),
        cfg.connection.secret_key.clone(),
        None,
        None,
        "test",
    );
    let sdk_cfg = aws_config::from_env()
        .region(region)
        .endpoint_url(&cfg.connection.endpoint)
        .credentials_provider(credentials)
        .load()
        .await;
    let s3 = S3Client::from_conf(
        aws_sdk_s3::config::Builder::from(&sdk_cfg)
            .force_path_style(true)
            .build(),
    );

    // WEF key layout: event_type=4624/year=.../month=.../day=.../<uuid>.parquet
    // The prefix is empty so objects live directly under event_type=4624/ in the bucket root.
    let list = s3
        .list_objects_v2()
        .bucket(&cfg.connection.bucket)
        .prefix("event_type=4624/")
        .send()
        .await
        .expect("list_objects_v2");

    let objects = list.contents();
    assert!(
        !objects.is_empty(),
        "Expected at least one Parquet object under event_type=4624/ prefix, found none"
    );

    // Download the first object and verify it is valid Parquet with the expected 5 WEF columns
    let key = objects[0].key().expect("key");
    let get_resp = s3
        .get_object()
        .bucket(&cfg.connection.bucket)
        .key(key)
        .send()
        .await
        .expect("get_object");

    let body_bytes = get_resp
        .body
        .collect()
        .await
        .expect("collect body")
        .into_bytes();

    use bytes::Bytes;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    let buf = Bytes::from(body_bytes.to_vec());
    let builder = ParquetRecordBatchReaderBuilder::try_new(buf).expect("parquet builder");
    let schema = builder.schema().clone();

    // Verify exactly 5 WEF columns
    let expected_columns = &[
        "event_id",
        "timestamp",
        "source_host",
        "subscription_id",
        "event_data",
    ];
    assert_eq!(schema.fields().len(), 5, "WEF schema must have 5 columns");
    for col in expected_columns {
        assert!(
            schema.field_with_name(col).is_ok(),
            "Expected column '{}' in WEF Parquet schema",
            col
        );
    }

    let mut reader = builder.build().expect("parquet reader");
    let rb = reader
        .next()
        .expect("at least one batch")
        .expect("batch ok");
    assert_eq!(rb.num_rows(), 1, "Expected exactly 1 row in WEF Parquet");

    use arrow::array::{StringArray, UInt32Array};
    let event_id_col = rb
        .column_by_name("event_id")
        .expect("event_id column")
        .as_any()
        .downcast_ref::<UInt32Array>()
        .unwrap();
    assert_eq!(event_id_col.value(0), 4624);

    let source_host_col = rb
        .column_by_name("source_host")
        .expect("source_host column")
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(source_host_col.value(0), "workstation01");
}
