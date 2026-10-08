//! End-to-end tests for the HEC / NDJSON ingest routes.
//!
//! Spins up the full Axum router (with IngestState + token extension,
//! body-limit layer) on an ephemeral port and fires real HTTP requests via
//! reqwest.  No S3 handler is wired (`generic_s3 = None`), so records are
//! accepted and discarded — the test validates HTTP behaviour only.
//!
//! No external dependency required.  These tests MUST run and pass without
//! MinIO or any other service.

mod common;

use axum::{Extension, Router, extract::DefaultBodyLimit, routing::post};
use logthing::config::Config;
use logthing::ingest::{
    IngestState,
    handlers::{handle_hec_event, handle_hec_raw, handle_ndjson},
};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::time::{Duration, sleep};

/// Mirror of server::MAX_BODY_SIZE (pub(crate) there, so we use the literal).
const BODY_LIMIT: usize = 64 * 1024 * 1024;

/// Spin up the router on an ephemeral port.
///
/// Returns `(base_url, join_handle)`.  The caller should hold the join-handle
/// alive for the duration of the test; dropping it aborts the server task.
async fn spawn_hec_server(token: &str) -> (String, tokio::task::JoinHandle<()>) {
    let mut cfg = Config::default();
    cfg.hec.token = token.to_string();
    let shared_config = Arc::new(RwLock::new(cfg));
    let ingest_state = IngestState::default();

    let router: Router = Router::new()
        .route("/services/collector/event", post(handle_hec_event))
        .route("/services/collector/raw", post(handle_hec_raw))
        .route("/ingest", post(handle_ndjson))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(Extension(shared_config))
        .layer(Extension(ingest_state));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);

    let handle = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    // Brief readiness pause — the port is already bound so this is very short.
    sleep(Duration::from_millis(10)).await;

    (base_url, handle)
}

// ---------------------------------------------------------------------------
// 1. Valid token → 200 + {"text":"Success","code":0}
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_hec_event_valid_token_returns_200_with_success_body() {
    let (base, _server) = spawn_hec_server("e2e-token").await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/services/collector/event"))
        .header("Authorization", "Splunk e2e-token")
        .json(&serde_json::json!({
            "event": {"msg": "hello from e2e", "level": "info"},
            "sourcetype": "e2e_test",
            "host": "test-host"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["text"], "Success");
    assert_eq!(body["code"], 0);
}

// ---------------------------------------------------------------------------
// 2. Bad token → 401 (non-empty configured token ensures auth is enforced)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_hec_event_bad_token_returns_401() {
    let (base, _server) = spawn_hec_server("correct-token").await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/services/collector/event"))
        .header("Authorization", "Splunk bad-token")
        .body(r#"{"event":{"k":1},"sourcetype":"t"}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], 2);
}

// ---------------------------------------------------------------------------
// 3. Missing Authorization header → 401
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_hec_event_missing_token_returns_401() {
    let (base, _server) = spawn_hec_server("tok").await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/services/collector/event"))
        // No Authorization header
        .body(r#"{"event":{"k":1},"sourcetype":"t"}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// 4. Invalid JSON body → 400 + code 6
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_hec_event_invalid_json_returns_400() {
    let (base, _server) = spawn_hec_server("tok").await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/services/collector/event"))
        .header("Authorization", "Splunk tok")
        .body("this is not json")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], 6);
}

// ---------------------------------------------------------------------------
// 5. Valid JSON but missing the "event" key → 400
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_hec_event_missing_event_key_returns_400() {
    let (base, _server) = spawn_hec_server("tok").await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/services/collector/event"))
        .header("Authorization", "Splunk tok")
        .json(&serde_json::json!({"sourcetype": "t", "host": "h"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// 6. Raw endpoint → 200
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_hec_raw_valid_returns_200() {
    let (base, _server) = spawn_hec_server("tok").await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/services/collector/raw?sourcetype=raw_src"))
        .header("Authorization", "Splunk tok")
        .body("2026-06-27T00:00:00Z host app[123]: something happened")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["text"], "Success");
}

// ---------------------------------------------------------------------------
// 7. NDJSON endpoint with two records → 200
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_ndjson_valid_two_lines_returns_200() {
    let (base, _server) = spawn_hec_server("tok").await;
    let client = reqwest::Client::new();

    let ndjson =
        "{\"host\":\"srv1\",\"event\":\"started\"}\n{\"host\":\"srv2\",\"event\":\"stopped\"}\n";
    let resp = client
        .post(format!("{base}/ingest?sourcetype=app_events"))
        .header("Authorization", "Splunk tok")
        .body(ndjson)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

// ---------------------------------------------------------------------------
// 8. Body exceeds 64 MiB limit → 413
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_hec_event_over_body_limit_returns_413() {
    let (base, _server) = spawn_hec_server("tok").await;
    let client = reqwest::Client::new();

    // Allocate just over the limit; this is ~64 MB — acceptable for a test.
    let huge_body = "x".repeat(BODY_LIMIT + 1);
    let resp = client
        .post(format!("{base}/services/collector/event"))
        .header("Authorization", "Splunk tok")
        .body(huge_body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
}

// ---------------------------------------------------------------------------
// 9. Multiple newline-delimited HEC event objects → 200
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_hec_event_multiple_newline_delimited_returns_200() {
    let (base, _server) = spawn_hec_server("tok").await;
    let client = reqwest::Client::new();

    let body = concat!(
        "{\"event\":{\"a\":1},\"sourcetype\":\"t1\"}\n",
        "{\"event\":{\"b\":2},\"sourcetype\":\"t2\"}\n",
        "{\"event\":{\"c\":3},\"sourcetype\":\"t3\"}\n",
    );
    let resp = client
        .post(format!("{base}/services/collector/event"))
        .header("Authorization", "Splunk tok")
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

/// Like `spawn_hec_server` but wired to a real local-disk sink under `dir`.
async fn spawn_hec_server_with_local_sink(
    dir: &std::path::Path,
) -> (String, tokio::task::JoinHandle<()>) {
    use logthing::config::GenericLocalConfig;
    use logthing::forwarding::generic_s3::hec_local_start;
    use logthing::forwarding::local_sink::LocalDiskSink;

    let sink = Arc::new(LocalDiskSink::new(dir.to_path_buf()).await.unwrap());
    let cfg = GenericLocalConfig {
        directory: dir.to_path_buf(),
        prefix: "hec".to_string(),
        flush_threshold_bytes: 1, // flush on first byte
        flush_interval_secs: 1,
        channel_capacity: 256,
        max_buffer_rows: 100_000,
    };
    let (handler, _join) = hec_local_start(
        &cfg,
        sink,
        64,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );
    let ingest_state = IngestState {
        generic_local: Some(handler),
        ..Default::default()
    };
    let shared_config = Arc::new(RwLock::new(Config::default()));
    let router: Router = Router::new()
        .route("/services/collector/event", post(handle_hec_event))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(Extension(shared_config))
        .layer(Extension(ingest_state));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (base, handle)
}

#[tokio::test]
async fn e2e_hec_event_persists_event_uuid_and_envelope_columns() {
    let tmp = tempfile::tempdir().unwrap();
    let (base, _server) = spawn_hec_server_with_local_sink(tmp.path()).await;
    let resp = reqwest::Client::new()
        .post(format!("{base}/services/collector/event"))
        .json(&serde_json::json!({
            "event": {"msg": "e2e"}, "sourcetype": "e2e_t", "source": "unit",
            "index": "main", "fields": {"env": "test"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let batches = common::wait_for_rows(tmp.path(), 1, Duration::from_secs(15)).await;
    let b = &batches[0];
    let id = common::str_col(b, "event_uuid").value(0);
    assert_eq!(uuid::Uuid::parse_str(id).unwrap().get_version_num(), 7);
    assert_eq!(common::str_col(b, "source").value(0), "unit");
    assert_eq!(common::str_col(b, "index").value(0), "main");
    assert_eq!(
        common::str_col(b, "indexed_fields").value(0),
        r#"{"env":"test"}"#
    );
    assert_eq!(common::str_col(b, "sourcetype").value(0), "e2e_t");
}
