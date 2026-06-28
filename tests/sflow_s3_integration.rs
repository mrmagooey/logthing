// tests/sflow_s3_integration.rs
//! Integration test: SflowRecord → SflowS3Handler → Parquet object in MinIO.
//!
//! Requires a running MinIO (or S3-compatible) instance.
//! Set MINIO_ENDPOINT, MINIO_BUCKET, MINIO_ACCESS_KEY, MINIO_SECRET_KEY env vars.
//! If MINIO_ENDPOINT is absent the test is skipped.

use logthing::config::{S3ConnectionConfig, SflowS3Config};
use logthing::forwarding::s3_sink::S3Sink;
use logthing::forwarding::sflow_s3::sflow_start;
use logthing::sflow::listener::SflowHandler;
use logthing::sflow::{SampleType, SflowRecord};
use std::sync::Arc;

fn skip_if_no_minio() -> Option<String> {
    std::env::var("MINIO_ENDPOINT").ok()
}

fn minio_sflow_config(endpoint: &str) -> SflowS3Config {
    SflowS3Config {
        connection: S3ConnectionConfig {
            endpoint: endpoint.to_string(),
            bucket: std::env::var("MINIO_BUCKET").unwrap_or_else(|_| "sflow-samples".to_string()),
            region: "us-east-1".to_string(),
            access_key: std::env::var("MINIO_ACCESS_KEY")
                .unwrap_or_else(|_| "minioadmin".to_string()),
            secret_key: std::env::var("MINIO_SECRET_KEY")
                .unwrap_or_else(|_| "minioadmin".to_string()),
        },
        prefix: "sflow".to_string(),
        max_buffer_rows: 1,           // flush on first record
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 4096,
    }
}

fn make_flow_record() -> SflowRecord {
    SflowRecord {
        sample_type: SampleType::Flow,
        exporter: "10.0.0.1".parse().unwrap(),
        received_at: chrono::Utc::now(),
        src_addr: Some("192.168.1.10".parse().unwrap()),
        dst_addr: Some("10.0.0.2".parse().unwrap()),
        src_port: Some(8080),
        dst_port: Some(80),
        ip_protocol: Some(6),
        sampling_rate: Some(512),
        input_ifindex: Some(1),
        output_ifindex: Some(2),
        if_index: None, if_type: None, if_speed: None, if_direction: None,
        if_in_octets: None, if_out_octets: None,
        if_in_ucast_pkts: None, if_out_ucast_pkts: None,
        if_in_errors: None, if_out_errors: None,
        extra: serde_json::json!([]),
    }
}

fn make_counter_record() -> SflowRecord {
    SflowRecord {
        sample_type: SampleType::Counter,
        exporter: "10.0.0.1".parse().unwrap(),
        received_at: chrono::Utc::now(),
        // flow-only fields absent for counter records
        src_addr: None, dst_addr: None, src_port: None, dst_port: None,
        ip_protocol: None, sampling_rate: None,
        input_ifindex: None, output_ifindex: None,
        // counter fields populated
        if_index: Some(7),
        if_type: Some(6),
        if_speed: Some(1_000_000_000),
        if_direction: Some(1),
        if_in_octets: Some(123_456),
        if_out_octets: Some(654_321),
        if_in_ucast_pkts: Some(1000),
        if_out_ucast_pkts: Some(500),
        if_in_errors: Some(2),
        if_out_errors: Some(1),
        extra: serde_json::json!([]),
    }
}

#[tokio::test]
async fn sflow_flow_record_appears_as_parquet_in_s3() {
    let endpoint = match skip_if_no_minio() {
        Some(e) => e,
        None => {
            eprintln!("MINIO_ENDPOINT not set — skipping sflow_s3 integration test");
            return;
        }
    };

    let cfg = minio_sflow_config(&endpoint);
    let sink = Arc::new(
        S3Sink::from_connection(&cfg.connection)
            .await
            .expect("S3Sink::from_connection"),
    );
    let (handler, _writer_task) = sflow_start(&cfg, sink.clone());
    let src: std::net::SocketAddr = "127.0.0.1:6343".parse().unwrap();

    handler
        .handle_samples(vec![make_flow_record(), make_counter_record()], src)
        .await;
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // Verify via aws-sdk-s3
    use aws_sdk_s3::Client as S3Client;
    let region = aws_sdk_s3::config::Region::new("us-east-1");
    let credentials = aws_credential_types::Credentials::new(
        cfg.connection.access_key.clone(),
        cfg.connection.secret_key.clone(),
        None, None, "test",
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
        .prefix("sflow/flow/")   // partitioned by sample_type
        .send()
        .await
        .expect("list_objects_v2");

    assert!(
        !list.contents().is_empty(),
        "expected at least one Parquet object under sflow/flow/; found none"
    );

    let key = list.contents()[0].key().expect("key");
    let get_resp = s3
        .get_object()
        .bucket(&cfg.connection.bucket)
        .key(key)
        .send()
        .await
        .expect("get_object");
    let body_bytes = get_resp.body.collect().await.expect("body").into_bytes();

    use bytes::Bytes;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    let buf = Bytes::from(body_bytes.to_vec());
    let builder = ParquetRecordBatchReaderBuilder::try_new(buf).expect("parquet builder");
    let schema = builder.schema().clone();

    assert!(schema.field_with_name("src_addr").is_ok(), "schema must have src_addr");
    assert!(schema.field_with_name("sampling_rate").is_ok(), "schema must have sampling_rate");

    let mut reader = builder.build().expect("reader");
    let rb = reader.next().expect("batch").expect("ok");
    assert_eq!(rb.num_rows(), 1, "expected exactly 1 row");

    use arrow::array::StringArray;
    let src_col = rb.column_by_name("src_addr").unwrap()
        .as_any().downcast_ref::<StringArray>().unwrap();
    assert_eq!(src_col.value(0), "192.168.1.10");

    // ── counter partition (COUNTER_SCHEMA, 14 fields) ──────────────────────────
    let counter_list = s3
        .list_objects_v2()
        .bucket(&cfg.connection.bucket)
        .prefix("sflow/counter/")   // partitioned by sample_type
        .send()
        .await
        .expect("list_objects_v2 for counter");

    assert!(
        !counter_list.contents().is_empty(),
        "expected at least one Parquet object under sflow/counter/; found none"
    );

    let counter_key = counter_list.contents()[0].key().expect("counter key");
    let counter_resp = s3
        .get_object()
        .bucket(&cfg.connection.bucket)
        .key(counter_key)
        .send()
        .await
        .expect("get_object for counter");
    let counter_bytes = counter_resp.body.collect().await.expect("counter body").into_bytes();

    let counter_buf = Bytes::from(counter_bytes.to_vec());
    let counter_builder =
        ParquetRecordBatchReaderBuilder::try_new(counter_buf).expect("counter parquet builder");
    let counter_schema = counter_builder.schema().clone();

    assert!(
        counter_schema.field_with_name("if_index").is_ok(),
        "counter schema must have if_index"
    );
    assert!(
        counter_schema.field_with_name("if_in_octets").is_ok(),
        "counter schema must have if_in_octets"
    );
    assert!(
        counter_schema.field_with_name("if_out_octets").is_ok(),
        "counter schema must have if_out_octets"
    );

    let mut counter_reader = counter_builder.build().expect("counter reader");
    let counter_rb = counter_reader.next().expect("counter batch").expect("counter ok");
    assert_eq!(counter_rb.num_rows(), 1, "expected exactly 1 counter row");

    use arrow::array::{UInt32Array, UInt64Array};
    let if_index_col = counter_rb.column_by_name("if_index").unwrap()
        .as_any().downcast_ref::<UInt32Array>().unwrap();
    assert_eq!(if_index_col.value(0), 7);

    let if_in_octets_col = counter_rb.column_by_name("if_in_octets").unwrap()
        .as_any().downcast_ref::<UInt64Array>().unwrap();
    assert_eq!(if_in_octets_col.value(0), 123_456u64);

    let if_out_octets_col = counter_rb.column_by_name("if_out_octets").unwrap()
        .as_any().downcast_ref::<UInt64Array>().unwrap();
    assert_eq!(if_out_octets_col.value(0), 654_321u64);
}
