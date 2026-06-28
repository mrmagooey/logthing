// tests/syslog_structured_s3_integration.rs
//! Integration test: CEF syslog line → DefaultSyslogHandler (parse_payloads=true)
//! → StructuredS3Handler → Parquet object in MinIO.
//!
//! Gated on MINIO_ENDPOINT.  Skip gracefully if the env var is absent.

use logthing::config::{S3ConnectionConfig, SyslogS3Config};
use logthing::forwarding::s3_sink::S3Sink;
use logthing::forwarding::structured_syslog_s3::structured_syslog_start;
use logthing::syslog::SyslogMessage;
use logthing::syslog::listener::{DefaultSyslogHandler, SyslogHandler as SyslogHandlerTrait};
use std::net::SocketAddr;
use std::sync::Arc;

fn skip_if_no_minio() -> Option<String> {
    std::env::var("MINIO_ENDPOINT").ok()
}

fn minio_cfg(endpoint: &str, prefix: &str) -> SyslogS3Config {
    SyslogS3Config {
        connection: S3ConnectionConfig {
            endpoint: endpoint.to_string(),
            bucket: std::env::var("MINIO_BUCKET")
                .unwrap_or_else(|_| "syslog-structured-test".to_string()),
            region: "us-east-1".to_string(),
            access_key: std::env::var("MINIO_ACCESS_KEY")
                .unwrap_or_else(|_| "minioadmin".to_string()),
            secret_key: std::env::var("MINIO_SECRET_KEY")
                .unwrap_or_else(|_| "minioadmin".to_string()),
        },
        prefix: prefix.to_string(),
        max_buffer_rows: 1, // flush on first record
        flush_interval_secs: 3600,
        channel_capacity: 16,
    }
}

#[tokio::test]
async fn cef_record_appears_as_parquet_under_cef_partition() {
    let endpoint = match skip_if_no_minio() {
        Some(e) => e,
        None => {
            eprintln!("MINIO_ENDPOINT not set — skipping structured_syslog integration test");
            return;
        }
    };

    let prefix = "structured-syslog-int-test";
    let cfg = minio_cfg(&endpoint, prefix);
    let s3 = Arc::new(
        S3Sink::from_connection(&cfg.connection)
            .await
            .expect("S3Sink::from_connection"),
    );

    let (structured_handle, writer_task) = structured_syslog_start(&cfg, s3.clone());
    let structured_handle = Arc::new(structured_handle);

    let handler = DefaultSyslogHandler::new(
        false,
        true,
        Some(structured_handle.clone()),
    );

    // A realistic CEF syslog message.
    let raw = "<134>Jan 15 10:30:45 fw01 arcsight: CEF:0|Vendor|FW|1.0|SIG001|\
               Firewall Accept|6|src=10.0.0.1 dst=8.8.8.8 spt=12345 dpt=443";
    let syslog_msg = SyslogMessage::parse(raw).expect("parse syslog");

    let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();
    handler.handle_message(syslog_msg, src).await;

    // Drop the handle so the channel closes and the writer flushes.
    drop(structured_handle);

    // Wait for the writer task to complete.
    tokio::time::timeout(std::time::Duration::from_secs(30), writer_task)
        .await
        .expect("writer completed within 30s")
        .expect("writer did not panic");

    // List objects under the prefix; expect at least one under the cef/ partition.
    let objects = s3
        .list_objects(&format!("{}/cef/", prefix))
        .await
        .expect("list_objects");

    assert!(
        !objects.is_empty(),
        "expected at least one Parquet object under {}/cef/; found none",
        prefix
    );

    // Download and read the first Parquet file; verify key columns.
    let key = &objects[0];
    let data = s3.get_object(key).await.expect("get_object");
    let bytes = bytes::Bytes::from(data);
    let builder =
        parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(bytes)
            .expect("parquet reader");
    let mut reader = builder.build().expect("build reader");
    let batch = reader.next().expect("at least one batch").expect("batch ok");

    assert_eq!(batch.num_rows(), 1);

    // Verify payload_type column.
    use arrow::array::StringArray;
    let ptype = batch
        .column_by_name("payload_type")
        .expect("payload_type column")
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(ptype.value(0), "cef");

    // Verify parsed column contains CEF fields.
    let parsed_col = batch
        .column_by_name("parsed")
        .expect("parsed column")
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(parsed_col.value(0)).expect("valid JSON");
    assert_eq!(
        parsed["device_vendor"].as_str().unwrap_or(""),
        "Vendor",
        "device_vendor field must survive the round-trip"
    );
}

/// Verify that multiple payload types land in separate S3 partitions.
#[tokio::test]
async fn multiple_payload_types_land_in_separate_partitions() {
    let endpoint = match skip_if_no_minio() {
        Some(e) => e,
        None => return,
    };

    let prefix = "structured-syslog-multi-test";
    let cfg = minio_cfg(&endpoint, prefix);
    let s3 = Arc::new(
        S3Sink::from_connection(&cfg.connection)
            .await
            .expect("S3Sink::from_connection"),
    );

    let (structured_handle, writer_task) = structured_syslog_start(&cfg, s3.clone());
    let structured_handle = Arc::new(structured_handle);

    let handler = DefaultSyslogHandler::new(false, true, Some(structured_handle.clone()));
    let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();

    // CEF message
    let cef_raw = "<134>Jan 15 10:30:45 fw01 arc: CEF:0|V|P|1.0|S|N|5|src=1.2.3.4";
    handler
        .handle_message(SyslogMessage::parse(cef_raw).unwrap(), src)
        .await;

    // DHCP message
    let dhcp_raw = "<30>Jan 15 10:31:00 dhcp-server dhcpd: DHCPACK on 10.0.0.5 to aa:bb:cc:dd:ee:ff (myhost) via eth0";
    handler
        .handle_message(SyslogMessage::parse(dhcp_raw).unwrap(), src)
        .await;

    drop(structured_handle);
    tokio::time::timeout(std::time::Duration::from_secs(30), writer_task)
        .await
        .expect("writer done")
        .expect("no panic");

    let cef_objs = s3.list_objects(&format!("{}/cef/", prefix)).await.expect("list cef");
    let dhcp_objs = s3.list_objects(&format!("{}/dhcp/", prefix)).await.expect("list dhcp");

    assert!(!cef_objs.is_empty(),  "CEF partition must have at least one object");
    assert!(!dhcp_objs.is_empty(), "DHCP partition must have at least one object");
}
