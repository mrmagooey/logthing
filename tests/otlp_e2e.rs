//! End-to-end test: real HTTP POST of OTLP protobuf/JSON → handle_otlp_logs → asserted responses.
//!
//! Spins up a real Axum router on an ephemeral port (already bound before
//! tokio::spawn so there is no race on the port number).  Real reqwest POSTs
//! are fired at that port and the HTTP status + body are inspected.
//!
//! No external services required (no MinIO).  `IngestState.generic_s3 = None`
//! means records are accepted and silently dropped — the test validates HTTP
//! behaviour only.
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
mod otlp_e2e {
    use axum::{Extension, Router, routing::post};
    use logthing::config::{Config, OtlpConfig};
    use logthing::forwarding::Forwarder;
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
            },
            ..Default::default()
        };
        let forwarder = Forwarder::new(config.forwarding.destinations.clone())
            .initialize()
            .await;
        Arc::new(AppState {
            config: Arc::new(RwLock::new(config)),
            throughput: Arc::new(ThroughputStats::new()),
            forwarder,
            parser: WefParser::new(),
            event_parser: None,
            parquet_s3_sender: None,
        })
    }

    /// Bind to an ephemeral port, spin up the OTLP router, and return the
    /// base URL + join handle.  The listener is bound *before* spawn so the
    /// port is immediately known and no race exists.
    async fn start_test_server(bearer_token: Option<String>) -> (String, tokio::task::JoinHandle<()>) {
        let app_state = build_app_state(bearer_token).await;
        let ingest_state = IngestState { generic_s3: None };

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
}

#[cfg(not(feature = "otlp"))]
#[test]
fn otlp_e2e_skipped_without_feature() {}
