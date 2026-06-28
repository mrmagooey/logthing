//! Integration test: GenericRecord → GenericS3Handler → Parquet objects in MinIO.
//!
//! Requires a running MinIO (or S3-compatible) instance.
//! Set MINIO_ENDPOINT env var (and optionally MINIO_BUCKET, MINIO_ACCESS_KEY,
//! MINIO_SECRET_KEY) to enable.  If MINIO_ENDPOINT is absent, the test skips.
//!
//! Exercises: two distinct sourcetypes land in separate S3 prefixes with the
//! 5-column HEC schema (sourcetype, host, time, received_at, fields).

use logthing::config::{HecS3Config, S3ConnectionConfig};
use logthing::forwarding::generic_s3::hec_start;
use logthing::forwarding::s3_sink::S3Sink;
use logthing::ingest::GenericRecord;
use std::sync::Arc;

fn skip_if_no_minio() -> Option<String> {
    std::env::var("MINIO_ENDPOINT").ok()
}

fn minio_hec_config(endpoint: &str) -> HecS3Config {
    HecS3Config {
        connection: S3ConnectionConfig {
            endpoint: endpoint.to_string(),
            bucket: std::env::var("MINIO_BUCKET").unwrap_or_else(|_| "hec-logs".to_string()),
            region: "us-east-1".to_string(),
            access_key: std::env::var("MINIO_ACCESS_KEY")
                .unwrap_or_else(|_| "minioadmin".to_string()),
            secret_key: std::env::var("MINIO_SECRET_KEY")
                .unwrap_or_else(|_| "minioadmin".to_string()),
        },
        prefix: "hec".to_string(),
        max_buffer_rows: 1,       // flush immediately
        flush_threshold_bytes: 1, // flush immediately
        flush_interval_secs: 3600,
        channel_capacity: 4096,
    }
}

fn make_record(sourcetype: &str, user: &str) -> GenericRecord {
    GenericRecord {
        sourcetype: sourcetype.to_string(),
        host: Some("integration-host".to_string()),
        time: Some(chrono::Utc::now()),
        fields: serde_json::json!({"user": user, "action": "login"}),
        received_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn hec_records_appear_as_parquet_in_s3() {
    let endpoint = match skip_if_no_minio() {
        Some(e) => e,
        None => {
            eprintln!("MINIO_ENDPOINT not set — skipping hec_s3 integration test");
            return;
        }
    };

    let cfg = minio_hec_config(&endpoint);
    let sink = Arc::new(
        S3Sink::from_connection(&cfg.connection)
            .await
            .expect("S3Sink::from_connection"),
    );

    let (handler, _writer_task) = hec_start(&cfg, sink, 64);
    handler.try_send(make_record("access_log", "alice")).expect("send");
    handler.try_send(make_record("access_log", "bob")).expect("send");
    handler.try_send(make_record("audit_log", "charlie")).expect("send");

    // Wait for background flush (max_buffer_rows=1 triggers immediately).
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // Build S3 verification client.
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

    // Verify both sourcetype partitions: access_log and audit_log.
    for prefix in &["hec/access_log/", "hec/audit_log/"] {
        let list = s3
            .list_objects_v2()
            .bucket(&cfg.connection.bucket)
            .prefix(*prefix)
            .send()
            .await
            .unwrap_or_else(|e| panic!("list_objects_v2 for {prefix}: {e}"));

        let objects = list.contents();
        assert!(
            !objects.is_empty(),
            "Expected >= 1 Parquet object under {prefix}, found none"
        );

        // Fetch and validate the first object.
        let key = objects[0].key().expect("key");
        let get_resp = s3
            .get_object()
            .bucket(&cfg.connection.bucket)
            .key(key)
            .send()
            .await
            .unwrap_or_else(|e| panic!("get_object {key}: {e}"));

        let body_bytes = get_resp
            .body
            .collect()
            .await
            .expect("collect body")
            .into_bytes();

        use bytes::Bytes;
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let buf = Bytes::from(body_bytes.to_vec());
        let builder =
            ParquetRecordBatchReaderBuilder::try_new(buf).expect("parquet builder");
        let schema = builder.schema().clone();

        // Must have the 5 HEC columns.
        for col in &["sourcetype", "host", "time", "received_at", "fields"] {
            assert!(
                schema.field_with_name(col).is_ok(),
                "Schema under {prefix} must have column '{col}'"
            );
        }
        assert_eq!(schema.fields().len(), 5, "HEC schema must have exactly 5 columns");

        let mut reader = builder.build().expect("parquet reader");
        let rb = reader.next().expect("at least one batch").expect("batch ok");
        assert!(rb.num_rows() >= 1, "Parquet under {prefix} must have >= 1 row");

        use arrow::array::StringArray;
        let st = rb
            .column_by_name("sourcetype")
            .expect("sourcetype col")
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        // Partition prefix matches sourcetype value.
        let expected_st = prefix.trim_start_matches("hec/").trim_end_matches('/');
        assert_eq!(
            st.value(0),
            expected_st,
            "sourcetype column must match partition"
        );
    }
}
