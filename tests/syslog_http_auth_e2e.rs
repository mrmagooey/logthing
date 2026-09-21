//! End-to-end test: real HTTP POST to `handle_syslog_http`, exercising the
//! opt-in `syslog.http_token` bearer auth over a real TCP listener.
//!
//! Mirrors the pattern in `tests/otlp_e2e.rs`: `AppState` is constructed
//! directly (all fields are `pub`) and a minimal router wraps the real,
//! exported `handle_syslog_http` handler. No external services required.

use axum::{Router, routing::post};
use logthing::config::Config;
use logthing::protocol::WefParser;
use logthing::server::{AppState, handle_syslog_http};
use logthing::stats::ThroughputStats;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::time::{Duration, sleep};

const SYSLOG_MSG: &str = "<134>Jan 15 10:30:45 dns-server named[1234]: hello from e2e";

/// Build an `Arc<AppState>` with `config.syslog.http_token` set to `token`.
async fn build_app_state(token: &str) -> Arc<AppState> {
    let mut config = Config::default();
    config.syslog.http_token = token.to_string();
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

/// Bind to an ephemeral port, spin up the `/syslog` route alone, and return
/// the base URL + join handle. The listener is bound *before* spawn so the
/// port is immediately known and no race exists.
async fn start_test_server(token: &str) -> (String, tokio::task::JoinHandle<()>) {
    let app_state = build_app_state(token).await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);

    let app = Router::new()
        .route("/syslog", post(handle_syslog_http))
        .with_state(app_state)
        .into_make_service_with_connect_info::<SocketAddr>();

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Brief readiness pause — the port is already bound so this is very short.
    sleep(Duration::from_millis(10)).await;

    (base_url, handle)
}

// ── Back-compat: empty configured token + no header → 200 ─────────────────

#[tokio::test]
async fn e2e_empty_token_and_no_header_returns_200() {
    let (base, _server) = start_test_server("").await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/syslog"))
        .body(SYSLOG_MSG)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "empty token must preserve no-auth behavior"
    );
}

// ── Token configured, no header → 401 ──────────────────────────────────────

#[tokio::test]
async fn e2e_missing_header_returns_401_when_token_configured() {
    let (base, _server) = start_test_server("e2e-secret").await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/syslog"))
        .body(SYSLOG_MSG)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

// ── Token configured, wrong token → 401 ────────────────────────────────────

#[tokio::test]
async fn e2e_wrong_token_returns_401() {
    let (base, _server) = start_test_server("e2e-secret").await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/syslog"))
        .header("Authorization", "Bearer wrong-token")
        .body(SYSLOG_MSG)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

// ── Token configured, malformed header (no "Bearer " prefix) → 401 ────────

#[tokio::test]
async fn e2e_malformed_header_returns_401() {
    let (base, _server) = start_test_server("e2e-secret").await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/syslog"))
        .header("Authorization", "e2e-secret")
        .body(SYSLOG_MSG)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

// ── Token configured, correct bearer → 200 ─────────────────────────────────

#[tokio::test]
async fn e2e_correct_token_returns_200() {
    let (base, _server) = start_test_server("e2e-secret").await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/syslog"))
        .header("Authorization", "Bearer e2e-secret")
        .body(SYSLOG_MSG)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
}
