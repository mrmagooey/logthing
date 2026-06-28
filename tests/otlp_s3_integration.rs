//! Integration test: OTLP ExportLogsServiceRequest → GenericS3Handler → Parquet in MinIO.
//!
//! Requires a running MinIO (or S3-compatible) instance.
//! Set MINIO_ENDPOINT, MINIO_BUCKET, MINIO_ACCESS_KEY, MINIO_SECRET_KEY env vars.
//! If MINIO_ENDPOINT is absent the test is skipped automatically.
//!
//! Run with:
//!   cargo test --features otlp --test otlp_s3_integration

#[cfg(feature = "otlp")]
mod tests {
    use logthing::config::{HecS3Config, S3ConnectionConfig};
    use logthing::forwarding::generic_s3::hec_start;
    use logthing::forwarding::s3_sink::S3Sink;
    use logthing::ingest::GenericRecord;
    use logthing::server::otlp::map_otlp_request;
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value::Value as AnyVal};
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    use opentelemetry_proto::tonic::resource::v1::Resource;
    use std::sync::Arc;

    fn skip_if_no_minio() -> Option<String> {
        std::env::var("MINIO_ENDPOINT").ok()
    }

    fn minio_hec_config(endpoint: &str) -> HecS3Config {
        HecS3Config {
            connection: S3ConnectionConfig {
                endpoint: endpoint.to_string(),
                bucket: std::env::var("MINIO_BUCKET")
                    .unwrap_or_else(|_| "otlp-test".to_string()),
                region: "us-east-1".to_string(),
                access_key: std::env::var("MINIO_ACCESS_KEY")
                    .unwrap_or_else(|_| "minioadmin".to_string()),
                secret_key: std::env::var("MINIO_SECRET_KEY")
                    .unwrap_or_else(|_| "minioadmin".to_string()),
            },
            prefix: "otlp-integration".to_string(),
            max_buffer_rows: 1,         // flush immediately on first record
            flush_threshold_bytes: 1,   // flush immediately on first byte
            flush_interval_secs: 3600,
            channel_capacity: 256,
        }
    }

    fn make_otlp_request() -> ExportLogsServiceRequest {
        ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(Resource {
                    attributes: vec![KeyValue {
                        key: "service.name".to_string(),
                        value: Some(AnyValue {
                            value: Some(AnyVal::StringValue("integration-svc".to_string())),
                        }),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
                scope_logs: vec![ScopeLogs {
                    scope: None,
                    log_records: vec![LogRecord {
                        time_unix_nano: 1_700_000_000_000_000_000,
                        severity_text: "WARN".to_string(),
                        body: Some(AnyValue {
                            value: Some(AnyVal::StringValue(
                                "integration test log".to_string(),
                            )),
                        }),
                        attributes: vec![KeyValue {
                            key: "test.run".to_string(),
                            value: Some(AnyValue {
                                value: Some(AnyVal::BoolValue(true)),
                            }),
                            ..Default::default()
                        }],
                        ..Default::default()
                    }],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        }
    }

    #[tokio::test]
    async fn otlp_records_land_as_parquet_in_s3_under_otlp_partition() {
        let endpoint = match skip_if_no_minio() {
            Some(e) => e,
            None => {
                eprintln!("MINIO_ENDPOINT not set — skipping otlp_s3 integration test");
                return;
            }
        };

        let cfg = minio_hec_config(&endpoint);
        let sink = Arc::new(
            S3Sink::from_connection(&cfg.connection)
                .await
                .expect("S3Sink::from_connection"),
        );

        // Start the generic HEC handler targeting the S3 sink.
        let (handler, _writer_task) = hec_start(&cfg, sink.clone(), 64);

        // Map the OTLP request to GenericRecords.
        let req = make_otlp_request();
        let records: Vec<GenericRecord> = map_otlp_request(req, "127.0.0.1".to_string());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].sourcetype, "otlp");

        // Send via the handler (flushes immediately because max_buffer_rows=1).
        handler
            .try_send(records.into_iter().next().unwrap())
            .expect("channel must accept the record");

        // Allow background flush to complete.
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

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

        // Verify the object was written under the `otlp` partition.
        // S3 key layout: {prefix}/otlp/year={Y}/month={MM}/day={DD}/{uuid}.parquet
        let prefix = format!("{}/otlp/", cfg.prefix);
        let list_result = s3
            .list_objects_v2()
            .bucket(&cfg.connection.bucket)
            .prefix(&prefix)
            .send()
            .await
            .expect("list_objects_v2 must succeed");

        let objects = list_result.contents();
        assert!(
            !objects.is_empty(),
            "expected at least one Parquet object under prefix {prefix}; got none. \
             Check that the flush completed and the S3 bucket is correct."
        );

        let key = objects[0].key().expect("object must have a key");
        assert!(
            key.ends_with(".parquet"),
            "written object must have .parquet extension; got {key}"
        );

        // Fetch and validate the Parquet object.
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
            .expect("sourcetype col must exist")
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(
            st.value(0),
            "otlp",
            "sourcetype column must equal 'otlp' for OTLP-ingested records"
        );
    }
}

#[cfg(not(feature = "otlp"))]
#[test]
fn otlp_s3_integration_skipped_without_feature() {
    // Compile-time guard: the integration test body is empty without the feature.
}
