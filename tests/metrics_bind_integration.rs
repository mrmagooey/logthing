//! Integration test: F7 — the metrics listener must follow `bind_address`
//! instead of hardcoding `0.0.0.0`, and must be gated by the same
//! `security.allowed_ips` whitelist the main router uses.
//!
//! Before this fix, `start_metrics_server` bound `0.0.0.0` unconditionally
//! and applied no IP-whitelist middleware at all — an operator who narrowed
//! `bind_address` to a private interface still exposed `/metrics` on every
//! interface, unauthenticated.
//!
//! Asserting non-reachability on a non-loopback local address would depend
//! on the test machine actually having a second, non-loopback interface,
//! which does not hold in every CI/sandbox environment (see
//! `tests/ipfix_env_var_bind_integration.rs` for the precedent this test
//! follows: proving a *real* OS-level bind via a same-address rebind
//! attempt, rather than via reachability from an address that may not
//! exist locally). The exact bind-address *resolution* (inherit vs.
//! explicit override) is covered deterministically, with no networking at
//! all, by `resolve_metrics_host_inherits_bind_address_when_unset` /
//! `resolve_metrics_host_uses_explicit_override_when_set` in
//! `src/server/mod.rs`'s unit tests.
//!
//! This test instead proves the two things only a real end-to-end run can
//! prove: (1) the metrics listener is live and reachable on the loopback
//! address inherited from `bind_address` (a real OS-level bind — proven by
//! a same-address rebind attempt failing with `AddrInUse`), and (2) a
//! source outside `security.allowed_ips` is rejected with 403 by the
//! whitelist middleware now wired onto the metrics router.
//!
//! This MUST be the only `#[tokio::test]` in this binary: `Server::run`
//! installs the Prometheus recorder via `metrics::set_global_recorder`,
//! which panics if called twice in one process. Cargo runs each
//! integration test *file* as its own process, so keeping this file to a
//! single test keeps that call singular (same constraint documented in
//! `tests/ipfix_socket_drop_metric_e2e.rs`).

use logthing::config::{Config, MetricsConfig, SecurityConfig, TlsConfig};
use logthing::forwarding::flush_registry::FlushIntervalRegistry;
use logthing::server::Server;
use logthing::stats::{SourceHourlyStats, ThroughputStats};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

async fn reserve_tcp_port() -> u16 {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    probe.local_addr().unwrap().port()
}

#[tokio::test]
async fn metrics_listener_inherits_bind_address_and_is_whitelist_gated() {
    let http_port = reserve_tcp_port().await;
    let metrics_port = reserve_tcp_port().await;

    // `bind_address` is narrowed to loopback and `metrics.bind_address` is
    // left unset (the default) — the exact scenario the finding describes.
    // `allowed_ips` excludes loopback, so a request from 127.0.0.1 proves
    // the whitelist middleware is actually wired onto the metrics router
    // (a 403 can only happen if the request first reached a live listener).
    let config = Config {
        bind_address: format!("127.0.0.1:{http_port}").parse().unwrap(),
        tls: TlsConfig {
            enabled: false,
            ..TlsConfig::default()
        },
        metrics: MetricsConfig {
            enabled: true,
            port: metrics_port,
            ..MetricsConfig::default()
        },
        security: SecurityConfig {
            allowed_ips: vec!["10.0.0.0/8".to_string()],
            ..SecurityConfig::default()
        },
        ..Config::default()
    };

    let shared_config = Arc::new(RwLock::new(config.clone()));
    let server = Server::new(
        config,
        shared_config,
        Arc::new(ThroughputStats::new()),
        Arc::new(SourceHourlyStats::new()),
        FlushIntervalRegistry::new(),
    )
    .await
    .expect("Server::new must succeed with no S3/local targets configured");

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_task = tokio::spawn(async move {
        server
            .run(shutdown_rx)
            .await
            .expect("server run must not error");
    });

    // Give the metrics listener time to bind.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // --- Proof 1: a real OS-level bind occurred on 127.0.0.1:<metrics_port>,
    // the address inherited from `bind_address` (not left over from a
    // hardcoded 0.0.0.0). A second bind attempt on the exact same address
    // must fail with AddrInUse — the same live-bind proof idiom used by
    // `tests/ipfix_env_var_bind_integration.rs`.
    let second_bind = tokio::net::TcpListener::bind(("127.0.0.1", metrics_port)).await;
    assert!(
        second_bind.is_err(),
        "expected AddrInUse binding 127.0.0.1:{metrics_port} a second time while the metrics \
         listener holds it; the metrics listener did not bind the inherited bind_address"
    );

    // --- Proof 2: the whitelist middleware gates the metrics router. A
    // request from 127.0.0.1, which is outside `allowed_ips`, must be
    // rejected with 403 — not connection-refused (which would instead mean
    // the listener never came up) and not 200 (which would mean the
    // whitelist middleware was never applied).
    let metrics_url = format!("http://127.0.0.1:{metrics_port}/metrics");
    let response = reqwest::get(&metrics_url)
        .await
        .expect("metrics listener must be reachable on the inherited bind_address");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::FORBIDDEN,
        "metrics router must apply the same IP whitelist as the main router"
    );

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
}
