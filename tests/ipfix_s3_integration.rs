//! Integration test: IPFIX FlowRecord → IpfixS3Handler → Parquet object in MinIO.
//!
//! Requires a running MinIO (or S3-compatible) instance.
//! Set MINIO_ENDPOINT, MINIO_BUCKET, MINIO_ACCESS_KEY, MINIO_SECRET_KEY env vars.
//! If MINIO_ENDPOINT is absent, the test is skipped.

use logthing::config::{IpfixS3Config, S3ConnectionConfig};
use logthing::forwarding::ipfix_s3::ipfix_start;
use logthing::forwarding::s3_sink::S3Sink;
use logthing::ipfix::FlowRecord;
use logthing::ipfix::listener::IpfixHandler;
use std::net::IpAddr;
use std::sync::Arc;

fn skip_if_no_minio() -> Option<String> {
    std::env::var("MINIO_ENDPOINT").ok()
}

fn minio_ipfix_config(endpoint: &str) -> IpfixS3Config {
    IpfixS3Config {
        connection: S3ConnectionConfig {
            endpoint: endpoint.to_string(),
            bucket: std::env::var("MINIO_BUCKET").unwrap_or_else(|_| "ipfix-flows".to_string()),
            region: "us-east-1".to_string(),
            access_key: std::env::var("MINIO_ACCESS_KEY")
                .unwrap_or_else(|_| "minioadmin".to_string()),
            secret_key: std::env::var("MINIO_SECRET_KEY")
                .unwrap_or_else(|_| "minioadmin".to_string()),
        },
        prefix: "ipfix".to_string(),
        max_buffer_rows: 1, // flush immediately on first batch
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 4096,
    }
}

fn make_flow_record() -> FlowRecord {
    FlowRecord {
        observation_domain_id: 1,
        template_id: 256,
        protocol_version: 10,
        exporter: "10.0.0.1".parse::<IpAddr>().unwrap(),
        export_time: chrono::Utc::now(),
        src_addr: Some("192.168.1.100".parse().unwrap()),
        dst_addr: Some("10.0.0.1".parse().unwrap()),
        src_port: Some(12345),
        dst_port: Some(443),
        ip_protocol: Some(6),
        octet_delta_count: Some(4096),
        packet_delta_count: Some(32),
        flow_start: None,
        flow_end: None,
        tcp_flags: Some(0x18),
        input_interface: Some(1),
        output_interface: Some(2),
        extra: serde_json::json!({"ie200": "0xdeadbeef"}),
    }
}

#[tokio::test]
async fn ipfix_flow_record_appears_as_parquet_in_s3() {
    let endpoint = match skip_if_no_minio() {
        Some(e) => e,
        None => {
            eprintln!("MINIO_ENDPOINT not set — skipping ipfix_s3 integration test");
            return;
        }
    };

    let cfg = minio_ipfix_config(&endpoint);
    let sink = Arc::new(
        S3Sink::from_connection(&cfg.connection)
            .await
            .expect("S3Sink::from_connection"),
    );

    // ipfix_start returns (handler, writer_join_handle)
    let (handler, _writer_task) = ipfix_start(&cfg, sink.clone());

    let flow = make_flow_record();
    let src: std::net::SocketAddr = "127.0.0.1:4739".parse().unwrap();
    handler.handle_flows(vec![flow], src).await;

    // Give the background task time to flush (max_buffer_rows=1 and flush_threshold_bytes=1
    // both trigger flush on first push)
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
        .prefix("ipfix/")
        .send()
        .await
        .expect("list_objects_v2");

    let objects = list.contents();
    assert!(
        !objects.is_empty(),
        "Expected at least one Parquet object under ipfix/ prefix, found none"
    );

    // Download the first object and verify it is valid Parquet with the expected 18 columns
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

    // Verify all 18 FlowRecord columns are present
    let expected_columns = &[
        "observation_domain_id",
        "template_id",
        "protocol_version",
        "exporter",
        "export_time",
        "src_addr",
        "dst_addr",
        "src_port",
        "dst_port",
        "ip_protocol",
        "octet_delta_count",
        "packet_delta_count",
        "flow_start",
        "flow_end",
        "tcp_flags",
        "input_interface",
        "output_interface",
        "extra",
    ];
    assert_eq!(
        schema.fields().len(),
        18,
        "IPFIX schema must have 18 columns"
    );
    for col in expected_columns {
        assert!(
            schema.field_with_name(col).is_ok(),
            "Expected column '{}' in IPFIX Parquet schema",
            col
        );
    }

    let mut reader = builder.build().expect("parquet reader");
    let rb = reader
        .next()
        .expect("at least one batch")
        .expect("batch ok");
    assert_eq!(rb.num_rows(), 1, "Expected exactly 1 row in Parquet file");

    use arrow::array::StringArray;
    let src_addr = rb
        .column_by_name("src_addr")
        .expect("src_addr column")
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(src_addr.value(0), "192.168.1.100");
}
