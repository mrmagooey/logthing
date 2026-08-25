//! Integration coverage for wiring `[security].max_connections` and
//! `[security].connection_timeout_secs` into the real router built by
//! `Server::create_router` (`src/server/mod.rs`).
//!
//! These tests exercise the REAL `create_router` path — a real `Config`, a
//! real `Server::new`, and the real production routes — rather than a
//! hand-rolled router, so a regression in how the two config values are
//! threaded into the `GlobalConcurrencyLimitLayer` / `TimeoutLayer`
//! construction would be caught here. (`create_router` is `pub` precisely
//! so this file can call it.)
//!
//! Mirrors the `build_server`/`with_connect_info` helpers used by the
//! `create_router`-driven tests inside `src/server/mod.rs`'s own
//! `#[cfg(test)]` module (search for `hec_routes_mounted_when_enabled`).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use logthing::config::Config;
use logthing::forwarding::flush_registry::FlushIntervalRegistry;
use logthing::middleware::IpWhitelist;
use logthing::server::Server;
use logthing::stats::{SourceHourlyStats, ThroughputStats};
use tokio::sync::RwLock;
use tokio::time::{Duration, timeout};
use tower::ServiceExt;

/// Build a full `Server` from a config (mirrors the private helper of the
/// same name inside `src/server/mod.rs`'s test module).
async fn build_server(config: Config) -> Server {
    let shared = Arc::new(RwLock::new(config.clone()));
    let throughput = Arc::new(ThroughputStats::new());
    Server::new(
        config,
        shared,
        throughput,
        Arc::new(SourceHourlyStats::new()),
        FlushIntervalRegistry::new(),
    )
    .await
    .expect("Server::new must succeed")
}

/// Inject a `ConnectInfo` extension so the ip_whitelist middleware resolves
/// during a `oneshot` call (it extracts `ConnectInfo<SocketAddr>`).
fn with_connect_info(mut req: Request<Body>) -> Request<Body> {
    let addr: SocketAddr = "127.0.0.1:40000".parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(addr));
    req
}

fn get(uri: &str) -> Request<Body> {
    with_connect_info(
        Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap(),
    )
}

/// `connection_timeout_secs = 0` must reach the real `TimeoutLayer`: a
/// request to a real, fast production route (`/health`) still comes back
/// `408 Request Timeout`. This is deterministic, not a race — verified
/// against the vendored `tower-http-0.5.2` source
/// (`src/timeout/service.rs`): `Timeout`'s `ResponseFuture::poll` checks
/// `sleep.poll(cx)` *before* polling the inner service future — but a
/// real-clock zero-duration `tokio::time::sleep` is not guaranteed to
/// report `Ready` on literally its very first poll (it may need to
/// register with the timer driver first), and `/health`'s handler chain
/// resolves fast enough that this genuinely races on a live clock. Pausing
/// tokio's clock (`start_paused = true`) makes the deadline comparison
/// deterministic instead of a wall-clock race.
#[tokio::test(start_paused = true)]
async fn configured_zero_timeout_reaches_the_layer_via_real_create_router() {
    let mut config = Config::default();
    config.security.connection_timeout_secs = 0;
    let server = build_server(config).await;
    let router = server
        .create_router(IpWhitelist::empty())
        .expect("router builds");

    let resp = router.oneshot(get("/health")).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::REQUEST_TIMEOUT,
        "connection_timeout_secs=0 must reach the real TimeoutLayer and time out /health"
    );
}

/// With the default (non-zero) timeout, the same route still succeeds —
/// proving the layer's presence doesn't regress ordinary traffic.
#[tokio::test]
async fn default_timeout_does_not_break_normal_requests() {
    let server = build_server(Config::default()).await;
    let router = server
        .create_router(IpWhitelist::empty())
        .expect("router builds");

    let resp = router.oneshot(get("/health")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// `max_connections = 0` must reach the real `GlobalConcurrencyLimitLayer`:
/// its semaphore starts with zero permits, so `poll_ready` never resolves
/// and a request against a real production route never completes. Wrapped
/// in a short `tokio::time::timeout` so the test itself stays fast; the
/// assertion is that it deterministically does NOT resolve (a semaphore
/// with 0 permits never grants `poll_acquire`), not a race.
#[tokio::test]
async fn configured_zero_max_connections_reaches_the_layer_via_real_create_router() {
    let mut config = Config::default();
    config.security.max_connections = 0;
    let server = build_server(config).await;
    let router = server
        .create_router(IpWhitelist::empty())
        .expect("router builds");

    let result = timeout(Duration::from_millis(200), router.oneshot(get("/health"))).await;
    assert!(
        result.is_err(),
        "max_connections=0 must reach the real GlobalConcurrencyLimitLayer and block /health \
         forever (a semaphore with zero permits never grants poll_ready)"
    );
}

/// The concurrency layer is applied to the MERGED router (after
/// `public_router.merge(protected_router)`), so it must also gate a
/// protected route, not just a public one.
#[tokio::test]
async fn zero_max_connections_also_blocks_a_protected_route() {
    let mut config = Config::default();
    config.security.max_connections = 0;
    let server = build_server(config).await;
    let router = server
        .create_router(IpWhitelist::empty())
        .expect("router builds");

    let result = timeout(
        Duration::from_millis(200),
        router.oneshot(get("/syslog/examples")),
    )
    .await;
    assert!(
        result.is_err(),
        "max_connections=0 must also block a protected route — the layer covers the merged router"
    );
}

/// With the default (non-zero) `max_connections`, ordinary traffic on a
/// protected route is unaffected.
#[tokio::test]
async fn default_max_connections_does_not_break_normal_requests() {
    let server = build_server(Config::default()).await;
    let router = server
        .create_router(IpWhitelist::empty())
        .expect("router builds");

    let resp = router.oneshot(get("/syslog/examples")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
