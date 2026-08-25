//! End-to-end tests for the security layers `Server::create_router` applies
//! in `src/server/mod.rs`: `tower::limit::GlobalConcurrencyLimitLayer` for
//! `[security].max_connections` and `tower_http::timeout::TimeoutLayer` for
//! `[security].connection_timeout_secs`.
//!
//! `create_router`'s production routes are all fast (no artificial delay),
//! so proving these layers' HTTP-visible behaviour under real traffic needs
//! a handler whose delay is caller-controlled. Following the established
//! pattern in `tests/hec_e2e.rs` (re-create the real production layer
//! stack, with the real layer types, around a purpose-built handler,
//! driven over a real TCP listener via reqwest) rather than routing
//! through the fixed set of production endpoints.
//!
//! No external dependency required.

use axum::{Router, extract::Query, routing::get};
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::time::{Duration, sleep};
use tower::limit::GlobalConcurrencyLimitLayer;
use tower_http::timeout::TimeoutLayer;

#[derive(Deserialize)]
struct SleepParams {
    ms: u64,
}

async fn sleep_handler(Query(params): Query<SleepParams>) -> &'static str {
    sleep(Duration::from_millis(params.ms)).await;
    "done"
}

/// Spin up a router carrying the SAME two layer types, applied the same
/// way (`.layer(concurrency).layer(timeout)` on the fully-built router),
/// that `Server::create_router` applies — with a handler whose delay is
/// controlled via `?ms=` instead of the fixed production handlers.
///
/// Two routes (`/sleep-a`, `/sleep-b`) are registered deliberately, not
/// one. Axum applies a `tower::Layer` independently to each *route* it
/// wraps (see `axum-0.7.9/src/routing/path_router.rs::layer`, which maps
/// `layer.clone()` over every registered route) — so a router with a
/// single route can't distinguish `GlobalConcurrencyLimitLayer` from the
/// plain per-invocation `tower::limit::ConcurrencyLimitLayer`: with only
/// one route, `Layer::layer()` only runs once regardless, and both types
/// would produce identical behaviour. With two routes, `.layer()` runs
/// twice: `GlobalConcurrencyLimitLayer::layer()` hands out the SAME shared
/// `Arc<Semaphore>` both times (cloning this layer never creates a new
/// semaphore — see its doc comment), while `ConcurrencyLimitLayer::layer()`
/// would construct a FRESH `Arc::new(Semaphore::new(max))` on each of the
/// two calls, giving each route its own independent limit. That divergence
/// is exactly what the concurrency test below is built to catch.
async fn spawn_server(
    max_connections: usize,
    timeout_secs: u64,
) -> (String, tokio::task::JoinHandle<()>) {
    let router: Router = Router::new()
        .route("/sleep-a", get(sleep_handler))
        .route("/sleep-b", get(sleep_handler))
        .layer(GlobalConcurrencyLimitLayer::new(max_connections))
        .layer(TimeoutLayer::new(Duration::from_secs(timeout_secs)));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");

    let handle = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    // Brief readiness pause — the port is already bound so this is very short.
    sleep(Duration::from_millis(10)).await;

    (base_url, handle)
}

// ---------------------------------------------------------------------------
// 1. A handler that sleeps past connection_timeout_secs -> 408.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_slow_handler_past_timeout_returns_408() {
    let (base, _server) = spawn_server(/* max_connections */ 100, /* timeout_secs */ 1).await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{base}/sleep-a?ms=3000"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::REQUEST_TIMEOUT);
}

// ---------------------------------------------------------------------------
// 2. A fast handler well under the timeout still succeeds — the layer
//    doesn't regress ordinary traffic.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_fast_handler_under_timeout_returns_200() {
    let (base, _server) = spawn_server(100, 5).await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{base}/sleep-a?ms=10"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

// ---------------------------------------------------------------------------
// 3. Concurrency is bounded SERVER-WIDE, across routes — not per route.
//
// `max_connections = 1`, two concurrent requests against two DIFFERENT
// routes (`/sleep-a`, `/sleep-b`), each sleeping ~300ms. If the semaphore
// is genuinely shared/global, the second request must wait for the first
// to release its permit, so the two sleeps run back-to-back and the
// wall-clock total is close to 2x300ms.
//
// If `tower::limit::ConcurrencyLimitLayer` were used instead of
// `GlobalConcurrencyLimitLayer`, each route would get its OWN independent
// semaphore of size 1 (see the comment on `spawn_server` above), so
// `/sleep-a` and `/sleep-b` would each individually stay under their own
// limit of 1 and run fully concurrently — wall-clock total close to
// 1x300ms. The timing assertion below would then fail, which is the
// point: this test is designed to fail under the wrong layer type.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_concurrency_limit_is_global_across_routes_not_per_route() {
    let (base, _server) = spawn_server(/* max_connections */ 1, /* timeout_secs */ 30).await;

    // Two independent clients, each with their own connection pool.
    let client_a = reqwest::Client::new();
    let client_b = reqwest::Client::new();

    let sleep_ms = 300u64;
    let url_a = format!("{base}/sleep-a?ms={sleep_ms}");
    let url_b = format!("{base}/sleep-b?ms={sleep_ms}");

    let start = std::time::Instant::now();
    let (resp_a, resp_b) = tokio::join!(client_a.get(&url_a).send(), client_b.get(&url_b).send());
    let elapsed = start.elapsed();

    assert_eq!(resp_a.unwrap().status(), reqwest::StatusCode::OK);
    assert_eq!(resp_b.unwrap().status(), reqwest::StatusCode::OK);

    assert!(
        elapsed >= Duration::from_millis(sleep_ms * 3 / 2),
        "expected requests against two different routes to serialize under a global \
         concurrency limit of 1, elapsed={elapsed:?} (would be ~{sleep_ms}ms instead of \
         ~{}ms if the limit were per-route instead of global)",
        sleep_ms * 2
    );
}

// ---------------------------------------------------------------------------
// 4. Negative control: with enough headroom, the same two requests DO run
//    concurrently — the limit is genuinely a cap, not blanket serialization.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_higher_max_connections_allows_concurrent_requests() {
    let (base, _server) = spawn_server(/* max_connections */ 10, /* timeout_secs */ 30).await;

    let client_a = reqwest::Client::new();
    let client_b = reqwest::Client::new();

    let sleep_ms = 300u64;
    let url_a = format!("{base}/sleep-a?ms={sleep_ms}");
    let url_b = format!("{base}/sleep-b?ms={sleep_ms}");

    let start = std::time::Instant::now();
    let (resp_a, resp_b) = tokio::join!(client_a.get(&url_a).send(), client_b.get(&url_b).send());
    let elapsed = start.elapsed();

    assert_eq!(resp_a.unwrap().status(), reqwest::StatusCode::OK);
    assert_eq!(resp_b.unwrap().status(), reqwest::StatusCode::OK);

    assert!(
        elapsed < Duration::from_millis(sleep_ms * 3 / 2),
        "expected the two requests to run concurrently with max_connections=10, \
         elapsed={elapsed:?}"
    );
}
