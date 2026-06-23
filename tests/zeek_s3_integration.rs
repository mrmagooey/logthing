//! Integration test: ZeekRecord → ZeekS3Handler → Parquet objects in MinIO.
//!
//! Requires a running MinIO (or S3-compatible) instance.
//! Set MINIO_ENDPOINT, MINIO_BUCKET, MINIO_ACCESS_KEY, MINIO_SECRET_KEY env vars.
//! If MINIO_ENDPOINT is absent, the test is skipped.
//!
//! Two record types are exercised:
//! - A typed `conn` record → appears under `zeek/conn/` with the conn schema columns incl `_extra`
//! - An unmodeled `weird` record → appears under `zeek/weird/` with the envelope columns

use logthing::config::{S3ConnectionConfig, ZeekS3Config};
use logthing::forwarding::s3_sink::S3Sink;
use logthing::forwarding::zeek_s3::zeek_start;
use logthing::zeek::ZeekRecord;
use logthing::zeek::listener::ZeekHandler;
use std::sync::Arc;

fn skip_if_no_minio() -> Option<String> {
    std::env::var("MINIO_ENDPOINT").ok()
}

fn minio_zeek_config(endpoint: &str) -> ZeekS3Config {
    ZeekS3Config {
        connection: S3ConnectionConfig {
            endpoint: endpoint.to_string(),
            bucket: std::env::var("MINIO_BUCKET").unwrap_or_else(|_| "zeek-logs".to_string()),
            region: "us-east-1".to_string(),
            access_key: std::env::var("MINIO_ACCESS_KEY")
                .unwrap_or_else(|_| "minioadmin".to_string()),
            secret_key: std::env::var("MINIO_SECRET_KEY")
                .unwrap_or_else(|_| "minioadmin".to_string()),
        },
        prefix: "zeek".to_string(),
        max_buffer_rows: 1, // flush immediately on first record
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 4096,
    }
}

fn make_conn_record() -> ZeekRecord {
    ZeekRecord {
        log_path: "conn".to_string(),
        fields: serde_json::json!({
            "_path": "conn",
            "ts": 1700000000.0,
            "uid": "CInteg001",
            "id.orig_h": "10.0.0.1",
            "id.orig_p": 12345,
            "id.resp_h": "10.0.0.2",
            "id.resp_p": 443,
            "proto": "tcp",
            "conn_state": "SF",
            "orig_bytes": 1024,
            "resp_bytes": 8192,
        }),
        received_at: chrono::Utc::now(),
    }
}

fn make_weird_record() -> ZeekRecord {
    ZeekRecord {
        log_path: "weird".to_string(),
        fields: serde_json::json!({
            "_path": "weird",
            "ts": 1700000200.0,
            "uid": "CWeird001",
            "id.orig_h": "10.0.0.3",
            "id.orig_p": 54321,
            "id.resp_h": "10.0.0.4",
            "id.resp_p": 80,
            "raw_data": "something unusual happened",
        }),
        received_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn zeek_records_appear_as_parquet_in_s3() {
    let endpoint = match skip_if_no_minio() {
        Some(e) => e,
        None => {
            eprintln!("MINIO_ENDPOINT not set — skipping zeek_s3 integration test");
            return;
        }
    };

    let cfg = minio_zeek_config(&endpoint);
    let sink = Arc::new(
        S3Sink::from_connection(&cfg.connection)
            .await
            .expect("S3Sink::from_connection"),
    );

    // zeek_start returns (handler, writer_join_handle)
    let (handler, _writer_task) = zeek_start(&cfg, sink.clone());

    let src: std::net::SocketAddr = "127.0.0.1:47760".parse().unwrap();
    handler.handle_record(make_conn_record(), src).await;
    handler.handle_record(make_weird_record(), src).await;

    // Give the background task time to flush (max_buffer_rows=1 and flush_threshold_bytes=1
    // both trigger flush on first push per partition)
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

    // --- Verify the typed `conn` record under zeek/conn/ ---
    {
        let list = s3
            .list_objects_v2()
            .bucket(&cfg.connection.bucket)
            .prefix("zeek/conn/")
            .send()
            .await
            .expect("list_objects_v2 for conn");

        let objects = list.contents();
        assert!(
            !objects.is_empty(),
            "Expected at least one Parquet object under zeek/conn/ prefix, found none"
        );

        let key = objects[0].key().expect("key");
        let get_resp = s3
            .get_object()
            .bucket(&cfg.connection.bucket)
            .key(key)
            .send()
            .await
            .expect("get_object for conn");

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
            ParquetRecordBatchReaderBuilder::try_new(buf).expect("parquet builder for conn");
        let schema = builder.schema().clone();

        // conn schema: ts, uid, id_orig_h, id_orig_p, id_resp_h, id_resp_p, proto,
        //              service, duration, orig_bytes, resp_bytes, conn_state, history,
        //              orig_pkts, resp_pkts, _extra  (16 columns)
        let conn_expected_cols = &[
            "ts",
            "uid",
            "id_orig_h",
            "id_orig_p",
            "id_resp_h",
            "id_resp_p",
            "proto",
            "orig_bytes",
            "resp_bytes",
            "conn_state",
            "_extra",
        ];
        for col in conn_expected_cols {
            assert!(
                schema.field_with_name(col).is_ok(),
                "Expected column '{}' in conn Parquet schema",
                col
            );
        }

        let mut reader = builder.build().expect("parquet reader for conn");
        let rb = reader
            .next()
            .expect("at least one batch for conn")
            .expect("batch ok for conn");
        assert_eq!(rb.num_rows(), 1, "Expected exactly 1 row in conn Parquet");

        use arrow::array::StringArray;
        let uid = rb
            .column_by_name("uid")
            .expect("uid column in conn")
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(uid.value(0), "CInteg001");
    }

    // --- Verify the unmodeled `weird` record under zeek/weird/ ---
    {
        let list = s3
            .list_objects_v2()
            .bucket(&cfg.connection.bucket)
            .prefix("zeek/weird/")
            .send()
            .await
            .expect("list_objects_v2 for weird");

        let objects = list.contents();
        assert!(
            !objects.is_empty(),
            "Expected at least one Parquet object under zeek/weird/ prefix, found none"
        );

        let key = objects[0].key().expect("key");
        let get_resp = s3
            .get_object()
            .bucket(&cfg.connection.bucket)
            .key(key)
            .send()
            .await
            .expect("get_object for weird");

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
            ParquetRecordBatchReaderBuilder::try_new(buf).expect("parquet builder for weird");
        let schema = builder.schema().clone();

        // envelope schema: ts, uid, id_orig_h, id_orig_p, id_resp_h, id_resp_p,
        //                  log_path, ingest_time, payload  (9 columns)
        let envelope_expected_cols = &[
            "ts",
            "uid",
            "id_orig_h",
            "id_orig_p",
            "id_resp_h",
            "id_resp_p",
            "log_path",
            "ingest_time",
            "payload",
        ];
        assert_eq!(
            schema.fields().len(),
            9,
            "Envelope (weird) schema must have 9 columns"
        );
        for col in envelope_expected_cols {
            assert!(
                schema.field_with_name(col).is_ok(),
                "Expected column '{}' in envelope (weird) Parquet schema",
                col
            );
        }

        let mut reader = builder.build().expect("parquet reader for weird");
        let rb = reader
            .next()
            .expect("at least one batch for weird")
            .expect("batch ok for weird");
        assert_eq!(rb.num_rows(), 1, "Expected exactly 1 row in weird Parquet");

        use arrow::array::StringArray;
        let log_path = rb
            .column_by_name("log_path")
            .expect("log_path column in weird")
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(log_path.value(0), "weird");
    }
}
