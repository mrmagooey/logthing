//! Integration test: F7 fix-round-1 regression — an IPv6 `bind_address`
//! must not break server startup.
//!
//! The original F7 fix built the metrics/TLS bind address by formatting
//! `bind_address.ip()` into a string and re-parsing it as a `SocketAddr`
//! (`format!("{ip}:{port}").parse::<SocketAddr>()`). `Ipv6Addr::to_string()`
//! never emits bracket notation, and `SocketAddr`'s parser requires
//! brackets for IPv6 (`"[::1]:9090"`, not `"::1:9090"`), so that string
//! round-trip silently failed to parse for every IPv6 `bind_address`. Since
//! `metrics.enabled` defaults to true and the `?` in `run()` propagates the
//! parse error before the main HTTP listener ever starts serving, an IPv6
//! `bind_address` took down the *entire* server, not just metrics — a
//! regression against the pre-F7 code (which always bound the IPv4 literal
//! `"0.0.0.0"` and so never hit this).
//!
//! The fix (`resolve_metrics_ip` / `tls_bind_addr` in `src/server/mod.rs`)
//! builds the `SocketAddr` directly from the parsed `IpAddr` — see that
//! module's unit tests for the deterministic, non-networked proof of the
//! resolution logic itself. This test is the live, real-socket
//! demonstration: a real `Server::run()` with `bind_address = "[::1]:<port>"`
//! must actually come up and serve `/metrics` over IPv6 loopback.
//!
//! This MUST be the only `#[tokio::test]` in this binary — see
//! `tests/metrics_bind_integration.rs` for why (the Prometheus global
//! recorder can only be installed once per process).

use logthing::config::{Config, MetricsConfig, TlsConfig};
use logthing::forwarding::flush_registry::FlushIntervalRegistry;
use logthing::middleware::IpWhitelist;
use logthing::server::Server;
use logthing::stats::{SourceHourlyStats, ThroughputStats};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

async fn reserve_tcp_port_v6() -> u16 {
    let probe = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    probe.local_addr().unwrap().port()
}

#[tokio::test]
async fn ipv6_bind_address_starts_server_and_serves_metrics_over_ipv6() {
    let http_port = reserve_tcp_port_v6().await;
    let metrics_port = reserve_tcp_port_v6().await;

    // bind_address is IPv6, metrics.bind_address is unset (the default,
    // inherit path) — exactly the combination that previously made
    // `Server::run` return an error before the HTTP listener ever bound.
    let config = Config {
        bind_address: format!("[::1]:{http_port}").parse().unwrap(),
        tls: TlsConfig {
            enabled: false,
            ..TlsConfig::default()
        },
        metrics: MetricsConfig {
            enabled: true,
            port: metrics_port,
            ..MetricsConfig::default()
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
        IpWhitelist::empty(),
    )
    .await
    .expect("Server::new must succeed with no S3/local targets configured");

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_task = tokio::spawn(async move { server.run(shutdown_rx).await });

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Before the fix, `server.run()` above would already have returned
    // `Err` (an unparseable-SocketAddr error) and the task would be
    // finished by now instead of still serving.
    assert!(
        !server_task.is_finished(),
        "server task exited early — an IPv6 bind_address made Server::run fail, \
         the exact regression this test guards against"
    );

    let metrics_url = format!("http://[::1]:{metrics_port}/metrics");
    let response = reqwest::get(&metrics_url)
        .await
        .expect("metrics listener must be reachable over IPv6 loopback");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "metrics endpoint must serve 200 with the default (empty) allowed_ips"
    );

    let _ = shutdown_tx.send(true);
    let result = tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server task must finish within 5s of shutdown signal")
        .expect("server task must not panic");
    assert!(result.is_ok(), "server.run() must not error: {result:?}");
}
