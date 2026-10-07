//! End-to-end test: real HTTP POST of OTLP protobuf/JSON → handle_otlp_logs → asserted responses.
//!
//! Spins up a real Axum router on an ephemeral port (already bound before
//! tokio::spawn so there is no race on the port number).  Real reqwest POSTs
//! are fired at that port and the HTTP status + body are inspected.
//!
//! No external services required (no MinIO).  The HTTP-behaviour tests use an empty
//! `IngestState` (records are accepted and not persisted); the typed-column tests wire a real
//! local-disk OTLP sink and read the written Parquet back.
//!
//! Run with:
//!   cargo test --features otlp --test otlp_e2e

// ── Router construction note ────────────────────────────────────────────────
//
// `handle_otlp_logs` uses two Axum extractors that must both be satisfied:
//
//   State(app_state): State<Arc<AppState>>
//       → supplied via `.with_state(arc_app_state)`
//
//   Extension(ingest): Extension<IngestState>
//       → supplied via `.layer(Extension(ingest_state))`
//
// The handler also extracts `ConnectInfo<SocketAddr>`, which requires
// `into_make_service_with_connect_info::<SocketAddr>()` at serve time so
// that Axum injects the peer address from the accepted TCP connection.
//
// AppState is constructed directly (all fields are `pub`) using the same
// pattern as the in-module `build_state_with_config` helper in
// src/server/mod.rs's `otlp_handler_tests`.  No test-only constructor needed.

#[cfg(feature = "otlp")]
#[path = "common/mod.rs"]
mod common;

#[cfg(feature = "otlp")]
mod otlp_e2e {
    use super::common;
    use axum::{Extension, Router, routing::post};
    use logthing::config::{Config, OtlpConfig};
    use logthing::ingest::IngestState;
    use logthing::protocol::WefParser;
    use logthing::server::{AppState, handle_otlp_logs};
    use logthing::stats::ThroughputStats;
    use opentelemetry_proto::tonic::collector::logs::v1::{
        ExportLogsServiceRequest, ExportLogsServiceResponse,
    };
    use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value::Value as AnyVal};
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    use prost::Message as ProstMessage;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::sync::RwLock;
    use tokio::time::{Duration, sleep};

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn make_request() -> ExportLogsServiceRequest {
        ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: None,
                scope_logs: vec![ScopeLogs {
                    scope: None,
                    log_records: vec![LogRecord {
                        time_unix_nano: 1_700_000_000_000_000_000,
                        severity_text: "DEBUG".to_string(),
                        body: Some(AnyValue {
                            value: Some(AnyVal::StringValue("e2e check".to_string())),
                        }),
                        ..Default::default()
                    }],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        }
    }

    /// Build an `Arc<AppState>` with `config.otlp` set to the given bearer_token.
    ///
    /// Mirrors the `build_state_with_config` helper inside `otlp_handler_tests`
    /// in src/server/mod.rs.  All AppState fields are `pub` so no test-only
    /// constructor is required.
    async fn build_app_state(bearer_token: Option<String>) -> Arc<AppState> {
        let config = Config {
            otlp: OtlpConfig {
                enabled: true,
                bearer_token,
                ..Default::default()
            },
            ..Default::default()
        };
        Arc::new(AppState {
            config: Arc::new(RwLock::new(config)),
            throughput: Arc::new(ThroughputStats::new()),
            wef_cardinality_watchers: Vec::new(),
            parser: WefParser::new(),
            event_parser: None,
            parquet_s3_sender: None,
            parquet_local_sender: None,
        })
    }

    /// Bind to an ephemeral port, spin up the OTLP router, and return the
    /// base URL + join handle.  The listener is bound *before* spawn so the
    /// port is immediately known and no race exists.
    async fn start_test_server(
        bearer_token: Option<String>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let app_state = build_app_state(bearer_token).await;
        let ingest_state = IngestState::default();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{}", addr);

        let app = Router::new()
            .route("/v1/logs", post(handle_otlp_logs))
            .layer(Extension(ingest_state))
            .with_state(app_state)
            .into_make_service_with_connect_info::<SocketAddr>();

        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Brief readiness pause — the port is already bound so this is very short.
        sleep(Duration::from_millis(10)).await;

        (base_url, handle)
    }

    // ── Test A: protobuf POST → 200 + valid ExportLogsServiceResponse ─────────

    #[tokio::test]
    async fn e2e_proto_post_returns_200_with_response() {
        let (base, _server) = start_test_server(None).await;
        let req_bytes = make_request().encode_to_vec();

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{base}/v1/logs"))
            .header("Content-Type", "application/x-protobuf")
            .body(req_bytes)
            .send()
            .await
            .expect("HTTP request must succeed");

        assert_eq!(resp.status(), 200, "expected 200 OK");
        let body = resp.bytes().await.unwrap();
        // Must decode as a valid ExportLogsServiceResponse (can be empty/default).
        ExportLogsServiceResponse::decode(body.as_ref())
            .expect("response must decode as ExportLogsServiceResponse");
    }

    // ── Test B: JSON POST → 200 ───────────────────────────────────────────────

    #[tokio::test]
    async fn e2e_json_post_returns_200() {
        let (base, _server) = start_test_server(None).await;
        let json_bytes = serde_json::to_vec(&make_request())
            .expect("ExportLogsServiceRequest must be serde-serializable (with-serde feature)");

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{base}/v1/logs"))
            .header("Content-Type", "application/json")
            .body(json_bytes)
            .send()
            .await
            .expect("HTTP request must succeed");

        assert_eq!(resp.status(), 200);
    }

    // ── Test C: correct bearer → 200 ─────────────────────────────────────────

    #[tokio::test]
    async fn e2e_correct_bearer_accepted() {
        let (base, _server) = start_test_server(Some("correct-token".to_string())).await;
        let req_bytes = make_request().encode_to_vec();

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{base}/v1/logs"))
            .header("Content-Type", "application/x-protobuf")
            .header("Authorization", "Bearer correct-token")
            .body(req_bytes)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
    }

    // ── Test D: wrong bearer → 401 ────────────────────────────────────────────
    //
    // Non-empty configured bearer token ensures auth is actually enforced.
    // (Empty token is dev-skip mode → 200; only non-empty triggers the check.)

    #[tokio::test]
    async fn e2e_wrong_bearer_returns_401() {
        let (base, _server) = start_test_server(Some("correct-token".to_string())).await;
        let req_bytes = make_request().encode_to_vec();

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{base}/v1/logs"))
            .header("Content-Type", "application/x-protobuf")
            .header("Authorization", "Bearer bad-token")
            .body(req_bytes)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 401, "wrong bearer must yield 401");
    }

    // ── Test E: absent bearer when required → 401 ────────────────────────────

    #[tokio::test]
    async fn e2e_missing_bearer_returns_401() {
        let (base, _server) = start_test_server(Some("required-token".to_string())).await;
        let req_bytes = make_request().encode_to_vec();

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{base}/v1/logs"))
            .header("Content-Type", "application/x-protobuf")
            .body(req_bytes)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 401, "absent bearer must yield 401");
    }

    // ── Test F: malformed protobuf body → 400 ────────────────────────────────

    #[tokio::test]
    async fn e2e_malformed_proto_returns_400() {
        let (base, _server) = start_test_server(None).await;

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{base}/v1/logs"))
            .header("Content-Type", "application/x-protobuf")
            .body(b"\xff\xfe\xfd garbage not valid protobuf".to_vec())
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 400, "malformed protobuf body must yield 400");
    }

    async fn spawn_otlp_server_with_local_sink(
        dir: &std::path::Path,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use logthing::config::OtlpLocalConfig;
        use logthing::forwarding::local_sink::LocalDiskSink;
        use logthing::forwarding::otlp_s3::otlp_local_start;

        let sink = Arc::new(LocalDiskSink::new(dir.to_path_buf()).await.unwrap());
        let cfg = OtlpLocalConfig {
            directory: dir.to_path_buf(),
            prefix: "otlp".to_string(),
            flush_threshold_bytes: 1,
            flush_interval_secs: 1,
            channel_capacity: 256,
            max_buffer_rows: 100_000,
        };
        let (handler, _join) = otlp_local_start(
            &cfg,
            sink,
            64,
            Arc::new(logthing::stats::SourceHourlyStats::new()),
            None,
        );
        let config = Config {
            otlp: OtlpConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let app_state = Arc::new(AppState {
            config: Arc::new(RwLock::new(config)),
            throughput: Arc::new(ThroughputStats::new()),
            wef_cardinality_watchers: Vec::new(),
            parser: WefParser::new(),
            event_parser: None,
            parquet_s3_sender: None,
            parquet_local_sender: None,
        });
        let router = Router::new()
            .route("/v1/logs", post(handle_otlp_logs))
            .layer(Extension(IngestState {
                otlp_local: Some(handler),
                ..Default::default()
            }))
            .with_state(app_state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        (base, handle)
    }

    async fn post_proto(base: &str, req: &ExportLogsServiceRequest) -> u16 {
        reqwest::Client::new()
            .post(format!("{base}/v1/logs"))
            .header("content-type", "application/x-protobuf")
            .body(req.encode_to_vec())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    }

    fn with_service_name(value: Option<AnyVal>) -> ExportLogsServiceRequest {
        let mut req = make_request();
        req.resource_logs[0].resource = Some(opentelemetry_proto::tonic::resource::v1::Resource {
            attributes: vec![opentelemetry_proto::tonic::common::v1::KeyValue {
                key: "service.name".to_string(),
                value: value.map(|v| AnyValue { value: Some(v) }),
                ..Default::default()
            }],
            ..Default::default()
        });
        req
    }

    #[tokio::test]
    async fn e2e_otlp_records_land_as_typed_parquet_in_local_sink() {
        let tmp = tempfile::tempdir().unwrap();
        let (base, _server) = spawn_otlp_server_with_local_sink(tmp.path()).await;
        let mut req = with_service_name(Some(AnyVal::StringValue("Typed Svc".into())));
        {
            let lr = &mut req.resource_logs[0].scope_logs[0].log_records[0];
            lr.severity_number = 13;
            lr.severity_text = "WARN".to_string();
            lr.trace_id = vec![0x11; 16];
            lr.span_id = vec![0x22; 8];
        }
        assert_eq!(post_proto(&base, &req).await, 200);

        let batches = common::wait_for_rows(tmp.path(), 1, Duration::from_secs(15)).await;
        let b = &batches[0];
        assert_eq!(common::str_col(b, "service_name").value(0), "Typed Svc");
        assert_eq!(common::str_col(b, "severity_text").value(0), "WARN");
        assert_eq!(common::str_col(b, "trace_id").value(0), "11".repeat(16));
        assert_eq!(common::str_col(b, "span_id").value(0), "22".repeat(8));
        assert_eq!(common::str_col(b, "peer_addr").value(0), "127.0.0.1");
        let sev = b
            .column_by_name("severity_number")
            .unwrap()
            .as_any()
            .downcast_ref::<arrow::array::Int32Array>()
            .unwrap();
        assert_eq!(sev.value(0), 13);
        let id = common::str_col(b, "event_uuid").value(0);
        assert_eq!(uuid::Uuid::parse_str(id).unwrap().get_version_num(), 7);
        assert!(
            common::parquet_files(tmp.path())
                .iter()
                .any(|p| p.to_string_lossy().contains("/otlp/typed_svc/")),
            "partition segment is the sanitized service name"
        );
    }

    /// No resource / no `service.name` / empty or non-string `service.name`: every request is
    /// accepted (200), lands under the `unknown` partition, and the written `service_name`
    /// column is NULL.
    #[tokio::test]
    async fn e2e_otlp_missing_or_invalid_service_name_lands_in_unknown_with_null() {
        use arrow::array::Array;
        let tmp = tempfile::tempdir().unwrap();
        let (base, _server) = spawn_otlp_server_with_local_sink(tmp.path()).await;

        let mut no_attr = make_request();
        no_attr.resource_logs[0].resource =
            Some(opentelemetry_proto::tonic::resource::v1::Resource::default());
        let mut no_value = with_service_name(None);
        no_value.resource_logs[0].scope_logs[0].log_records[0].severity_text = "NOVALUE".into();
        let variants = vec![
            make_request(),                                              // no resource at all
            no_attr,  // resource without attributes
            no_value, // service.name key with no value
            with_service_name(Some(AnyVal::StringValue(String::new()))), // empty
            with_service_name(Some(AnyVal::IntValue(42))), // non-string
        ];
        let n = variants.len();
        for v in &variants {
            assert_eq!(post_proto(&base, v).await, 200);
        }

        let batches = common::wait_for_rows(tmp.path(), n, Duration::from_secs(15)).await;
        let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
        assert_eq!(rows, n, "no record dropped");
        let nulls: usize = batches
            .iter()
            .map(|b| common::str_col(b, "service_name").null_count())
            .sum();
        assert_eq!(nulls, n, "service_name is NULL for every row");
        let files = common::parquet_files(tmp.path());
        assert!(!files.is_empty());
        assert!(
            files
                .iter()
                .all(|p| p.to_string_lossy().contains("/otlp/unknown/")),
            "all rows are in the `unknown` partition: {files:?}"
        );
    }

    #[tokio::test]
    async fn e2e_otlp_invalid_utf8_protobuf_returns_400() {
        let (base, _server) = start_test_server(None).await;
        // LogRecord.severity_text (field 3) = invalid UTF-8, wrapped to the request root.
        let lr = [0x1a, 0x02, 0xFF, 0xFE];
        let mut sl = vec![0x12, lr.len() as u8];
        sl.extend_from_slice(&lr);
        let mut rl = vec![0x12, sl.len() as u8];
        rl.extend_from_slice(&sl);
        let mut body = vec![0x0a, rl.len() as u8];
        body.extend_from_slice(&rl);
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/logs"))
            .header("content-type", "application/x-protobuf")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
    }
}

#[cfg(not(feature = "otlp"))]
#[test]
fn otlp_e2e_skipped_without_feature() {}
