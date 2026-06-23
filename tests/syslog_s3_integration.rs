//! Integration test: syslog UDP datagram → SyslogS3Handler → Parquet object in MinIO.
//!
//! Requires a running MinIO (or S3-compatible) instance.
//! Set MINIO_ENDPOINT, MINIO_BUCKET, MINIO_ACCESS_KEY, MINIO_SECRET_KEY env vars.
//! If MINIO_ENDPOINT is absent, the test is skipped.

use logthing::config::{S3ConnectionConfig, SyslogS3Config};
use logthing::forwarding::s3_sink::S3Sink;
use logthing::forwarding::syslog_s3::{SyslogS3Handler, syslog_start};
use logthing::syslog::listener::SyslogHandler as SyslogHandlerTrait;
use logthing::syslog::{SyslogMessage, SyslogProtocol};
use std::net::SocketAddr;
use std::sync::Arc;

fn skip_if_no_minio() -> Option<String> {
    std::env::var("MINIO_ENDPOINT").ok()
}

fn minio_syslog_config(endpoint: &str) -> SyslogS3Config {
    SyslogS3Config {
        connection: S3ConnectionConfig {
            endpoint: endpoint.to_string(),
            bucket: std::env::var("MINIO_BUCKET").unwrap_or_else(|_| "syslog-test".to_string()),
            region: "us-east-1".to_string(),
            access_key: std::env::var("MINIO_ACCESS_KEY")
                .unwrap_or_else(|_| "minioadmin".to_string()),
            secret_key: std::env::var("MINIO_SECRET_KEY")
                .unwrap_or_else(|_| "minioadmin".to_string()),
        },
        prefix: "syslog-test".to_string(),
        max_buffer_rows: 1, // flush immediately on first message
        flush_interval_secs: 3600,
        channel_capacity: 4096,
    }
}

#[tokio::test]
async fn syslog_message_appears_as_parquet_in_s3() {
    let endpoint = match skip_if_no_minio() {
        Some(e) => e,
        None => {
            eprintln!("MINIO_ENDPOINT not set — skipping syslog_s3 integration test");
            return;
        }
    };

    let cfg = minio_syslog_config(&endpoint);
    let sink = Arc::new(
        S3Sink::from_connection(&cfg.connection)
            .await
            .expect("S3Sink::from_connection"),
    );

    // `syslog_start` returns (handler, writer_join_handle) for graceful-shutdown support;
    // the test only needs the handler and lets the writer task run in the background.
    let (handler, _writer_task) = syslog_start(&cfg, sink.clone());

    let msg = SyslogMessage {
        priority: 134,
        severity: 6,
        facility: 16,
        timestamp: Some(chrono::Utc::now()),
        hostname: Some("integrationhost".to_string()),
        app_name: Some("testapp".to_string()),
        proc_id: None,
        msg_id: None,
        message: "integration test message".to_string(),
        structured_data: None,
        protocol: SyslogProtocol::Rfc3164,
    };

    let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();
    handler.handle_message(msg, src).await;

    // Give the background task time to flush (max_buffer_rows=1 triggers flush on push)
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // Verify object exists in S3 by listing under the prefix
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

    let list = s3
        .list_objects_v2()
        .bucket(&cfg.connection.bucket)
        .prefix("syslog-test/")
        .send()
        .await
        .expect("list_objects_v2");

    let objects = list.contents();
    assert!(
        !objects.is_empty(),
        "Expected at least one Parquet object under syslog-test/ prefix, found none"
    );

    // Download the first object and verify it is valid Parquet with expected columns
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
    assert_eq!(
        schema.fields().len(),
        11,
        "Syslog schema must have 11 columns"
    );

    let mut reader = builder.build().expect("parquet reader");
    let rb = reader
        .next()
        .expect("at least one batch")
        .expect("batch ok");
    assert_eq!(rb.num_rows(), 1);

    use arrow::array::StringArray;
    let hostname = rb.column(4).as_any().downcast_ref::<StringArray>().unwrap();
    assert_eq!(hostname.value(0), "integrationhost");
}

// Verify the handler type alias is usable
#[test]
fn syslog_s3_handler_type_alias_is_accessible() {
    // This test just verifies the type alias compiles — it requires no runtime.
    let _: fn() -> Option<SyslogS3Handler> = || None;
}
