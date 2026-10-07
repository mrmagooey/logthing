//! Integration test: OTLP ExportLogsServiceRequest → OtlpHandler → Parquet in MinIO.
//!
//! Requires a running MinIO (or S3-compatible) instance.
//! Set MINIO_ENDPOINT, MINIO_BUCKET, MINIO_ACCESS_KEY, MINIO_SECRET_KEY env vars.
//! If MINIO_ENDPOINT is absent the test is skipped automatically.
//!
//! Run with:
//!   cargo test --features otlp --test otlp_s3_integration

#[cfg(feature = "otlp")]
mod tests {
    use logthing::config::{OtlpS3Config, S3ConnectionConfig};
    use logthing::forwarding::otlp_s3::{OtlpRecord, otlp_start};
    use logthing::forwarding::s3_sink::S3Sink;
    use logthing::server::otlp::map_otlp_request;
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value::Value as AnyVal};
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    use opentelemetry_proto::tonic::resource::v1::Resource;
    use std::sync::Arc;

    fn skip_if_no_minio() -> Option<String> {
        std::env::var("MINIO_ENDPOINT").ok()
    }

    fn minio_otlp_config(endpoint: &str) -> OtlpS3Config {
        OtlpS3Config {
            connection: S3ConnectionConfig {
                endpoint: endpoint.to_string(),
                bucket: std::env::var("MINIO_BUCKET").unwrap_or_else(|_| "otlp-test".to_string()),
                region: "us-east-1".to_string(),
                access_key: std::env::var("MINIO_ACCESS_KEY")
                    .unwrap_or_else(|_| "minioadmin".to_string()),
                secret_key: std::env::var("MINIO_SECRET_KEY")
                    .unwrap_or_else(|_| "minioadmin".to_string()),
            },
            prefix: "otlp-integration".to_string(),
            max_buffer_rows: 1,       // flush immediately on first record
            flush_threshold_bytes: 1, // flush immediately on first byte
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
                            value: Some(AnyVal::StringValue("integration test log".to_string())),
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

        let cfg = minio_otlp_config(&endpoint);
        let sink = Arc::new(
            S3Sink::from_connection(&cfg.connection)
                .await
                .expect("S3Sink::from_connection"),
        );

        // Start the OTLP handler targeting the S3 sink.
        let (handler, _writer_task) = otlp_start(
            &cfg,
            sink.clone(),
            64,
            std::sync::Arc::new(logthing::stats::SourceHourlyStats::new()),
            None,
        );

        // Map the OTLP request, assign ids like the production handler does.
        let req = make_otlp_request();
        let mut records: Vec<OtlpRecord> = map_otlp_request(req, "127.0.0.1".to_string());
        assert_eq!(records.len(), 1);
        logthing::ingest::assign_event_uuids(&mut records);

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

        // Verify the object was written under the sanitized service partition
        // (`integration-svc` sanitizes to `integration_svc`).
        let prefix = format!("{}/integration_svc/", cfg.prefix);
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
            key.starts_with(&prefix) && key.ends_with(".parquet"),
            "object key must be under {prefix} and end in .parquet; got {key}"
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
        let builder = ParquetRecordBatchReaderBuilder::try_new(buf).expect("parquet builder");
        let schema = builder.schema().clone();

        let names: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();
        assert_eq!(
            names,
            vec![
                "event_uuid",
                "time",
                "observed_time",
                "received_at",
                "severity_number",
                "severity_text",
                "body",
                "service_name",
                "service_namespace",
                "service_instance_id",
                "host_name",
                "peer_addr",
                "trace_id",
                "span_id",
                "flags",
                "event_name",
                "scope_name",
                "scope_version",
                "resource_attributes",
                "attributes",
                "partition_time",
            ],
            "schema must be the 21 frozen OTLP columns in order"
        );

        let mut reader = builder.build().expect("parquet reader");
        let rb = reader
            .next()
            .expect("at least one batch")
            .expect("batch ok");
        assert!(
            rb.num_rows() >= 1,
            "Parquet under {prefix} must have >= 1 row"
        );

        use arrow::array::StringArray;
        let col = |name: &str| {
            rb.column_by_name(name)
                .unwrap_or_else(|| panic!("{name} col must exist"))
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap_or_else(|| panic!("{name} must be Utf8"))
                .clone()
        };
        assert_eq!(col("service_name").value(0), "integration-svc");
        assert_eq!(col("severity_text").value(0), "WARN");
        assert_eq!(col("body").value(0), "integration test log");
        assert!(
            col("attributes").value(0).contains("\"test.run\":true"),
            "attributes JSON must carry test.run=true"
        );
    }
}

#[cfg(not(feature = "otlp"))]
#[test]
fn otlp_s3_integration_skipped_without_feature() {
    // Compile-time guard: the integration test body is empty without the feature.
}
