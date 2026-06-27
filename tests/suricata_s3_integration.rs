//! Integration test: SuricataRecord → SuricataS3Handler → Parquet objects in MinIO.
//!
//! Set MINIO_ENDPOINT (e.g. http://localhost:9000). Skipped if absent.
//! Also reads MINIO_BUCKET (default "suricata-logs"), MINIO_ACCESS_KEY,
//! MINIO_SECRET_KEY (both default "minioadmin").

use logthing::config::{S3ConnectionConfig, SuricataS3Config};
use logthing::forwarding::s3_sink::S3Sink;
use logthing::forwarding::suricata_s3::suricata_start;
use logthing::suricata::SuricataRecord;
use logthing::suricata::listener::SuricataHandler;
use std::sync::Arc;

fn skip_if_no_minio() -> Option<String> {
    std::env::var("MINIO_ENDPOINT").ok()
}

fn minio_suricata_config(endpoint: &str) -> SuricataS3Config {
    SuricataS3Config {
        connection: S3ConnectionConfig {
            endpoint: endpoint.to_string(),
            bucket: std::env::var("MINIO_BUCKET")
                .unwrap_or_else(|_| "suricata-logs".to_string()),
            region: "us-east-1".to_string(),
            access_key: std::env::var("MINIO_ACCESS_KEY")
                .unwrap_or_else(|_| "minioadmin".to_string()),
            secret_key: std::env::var("MINIO_SECRET_KEY")
                .unwrap_or_else(|_| "minioadmin".to_string()),
        },
        prefix: "suricata".to_string(),
        max_buffer_rows: 1,         // flush immediately on first record
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 4096,
    }
}

fn make_alert_record() -> SuricataRecord {
    SuricataRecord {
        event_type: "alert".to_string(),
        fields: serde_json::json!({
            "event_type": "alert",
            "src_ip": "10.0.0.1",
            "dest_ip": "1.2.3.4",
            "dest_port": 443,
            "alert": {
                "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
                "category": "Network Scan",
                "severity": 3
            },
            "timestamp": "2024-01-15T10:30:00.000000+0000"
        }),
        received_at: chrono::Utc::now(),
    }
}

fn make_flow_record() -> SuricataRecord {
    SuricataRecord {
        event_type: "flow".to_string(),
        fields: serde_json::json!({
            "event_type": "flow",
            "src_ip": "192.168.1.5",
            "dest_ip": "8.8.8.8",
            "dest_port": 53,
            "proto": "UDP",
            "flow": {
                "pkts_toserver": 1,
                "pkts_toclient": 1,
                "bytes_toserver": 60,
                "bytes_toclient": 120
            },
            "timestamp": "2024-01-15T10:31:00.000000+0000"
        }),
        received_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn suricata_records_appear_as_parquet_in_s3() {
    let endpoint = match skip_if_no_minio() {
        Some(e) => e,
        None => {
            eprintln!("MINIO_ENDPOINT not set — skipping suricata_s3 integration test");
            return;
        }
    };

    let cfg = minio_suricata_config(&endpoint);
    let sink = Arc::new(
        S3Sink::from_connection(&cfg.connection)
            .await
            .expect("S3Sink::from_connection"),
    );

    let (handler, _writer_task) = suricata_start(&cfg, sink.clone());
    let src: std::net::SocketAddr = "127.0.0.1:47761".parse().unwrap();
    handler.handle_record(make_alert_record(), src).await;
    handler.handle_record(make_flow_record(), src).await;

    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // Build S3 client for verification
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

    // Verify alert record under suricata/alert/
    {
        let list = s3
            .list_objects_v2()
            .bucket(&cfg.connection.bucket)
            .prefix("suricata/alert/")
            .send()
            .await
            .expect("list_objects_v2 for alert");

        let objects = list.contents();
        assert!(
            !objects.is_empty(),
            "Expected at least one Parquet object under suricata/alert/, found none"
        );

        let key = objects[0].key().expect("key");
        let get_resp = s3
            .get_object()
            .bucket(&cfg.connection.bucket)
            .key(key)
            .send()
            .await
            .expect("get_object for alert");

        let body_bytes = get_resp.body.collect().await.expect("collect body").into_bytes();

        use bytes::Bytes;
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let buf = Bytes::from(body_bytes.to_vec());
        let builder =
            ParquetRecordBatchReaderBuilder::try_new(buf).expect("parquet builder for alert");
        let schema = builder.schema().clone();

        // Envelope schema: event_type, received_at, src_ip, payload
        for col in &["event_type", "received_at", "src_ip", "payload"] {
            assert!(
                schema.field_with_name(col).is_ok(),
                "Expected column '{}' in suricata alert Parquet schema",
                col
            );
        }

        let mut reader = builder.build().expect("parquet reader for alert");
        let rb = reader
            .next()
            .expect("at least one batch for alert")
            .expect("batch ok");
        assert_eq!(rb.num_rows(), 1, "Expected exactly 1 row in alert Parquet");

        use arrow::array::StringArray;
        let et = rb
            .column_by_name("event_type")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(et.value(0), "alert");

        let src_ip = rb
            .column_by_name("src_ip")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(src_ip.value(0), "10.0.0.1");
    }

    // Verify flow record under suricata/flow/
    {
        let list = s3
            .list_objects_v2()
            .bucket(&cfg.connection.bucket)
            .prefix("suricata/flow/")
            .send()
            .await
            .expect("list_objects_v2 for flow");

        let objects = list.contents();
        assert!(
            !objects.is_empty(),
            "Expected at least one Parquet object under suricata/flow/, found none"
        );

        let key = objects[0].key().expect("key");
        let get_resp = s3
            .get_object()
            .bucket(&cfg.connection.bucket)
            .key(key)
            .send()
            .await
            .expect("get_object for flow");

        let body_bytes = get_resp.body.collect().await.expect("collect body").into_bytes();

        use bytes::Bytes;
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let buf = Bytes::from(body_bytes.to_vec());
        let mut reader = ParquetRecordBatchReaderBuilder::try_new(buf)
            .unwrap()
            .build()
            .unwrap();
        let rb = reader.next().unwrap().unwrap();
        assert_eq!(rb.num_rows(), 1, "Expected exactly 1 row in flow Parquet");

        use arrow::array::StringArray;
        let et = rb
            .column_by_name("event_type")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(et.value(0), "flow");
    }
}
