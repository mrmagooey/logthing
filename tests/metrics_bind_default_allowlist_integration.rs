//! Integration test: F7 fix-round-1 finding 2 — the documented default
//! (`security.allowed_ips` empty, meaning allow-all) must still serve
//! `/metrics`.
//!
//! `tests/metrics_bind_integration.rs` proves the whitelist *rejects* a
//! source outside `allowed_ips`, using a deliberately restrictive list.
//! That alone does not prove the far more common, default-empty case still
//! works — `IpWhitelist::is_allowed` returning `true` unconditionally for
//! an empty whitelist (`src/middleware/mod.rs`) is exercised by that type's
//! own unit tests, but nothing previously asserted it end-to-end for the
//! metrics router specifically, which is new wiring as of the F7 fix. A
//! bug that accidentally required a non-empty `allowed_ips` to reach
//! `/metrics` at all would silently break scraping for every default
//! deployment, which is the one property this fix must not get wrong.
//!
//! This MUST be the only `#[tokio::test]` in this binary — see
//! `tests/metrics_bind_integration.rs` for why (the Prometheus global
//! recorder can only be installed once per process).

use logthing::config::{Config, MetricsConfig, TlsConfig};
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
async fn default_empty_allowed_ips_still_serves_metrics() {
    let http_port = reserve_tcp_port().await;
    let metrics_port = reserve_tcp_port().await;

    // `security` is left at `Config::default()`, i.e. `allowed_ips` is the
    // documented default: empty, meaning allow-all.
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
        ..Config::default()
    };
    assert!(
        config.security.allowed_ips.is_empty(),
        "test premise: allowed_ips must be the empty (allow-all) default"
    );

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

    tokio::time::sleep(Duration::from_millis(300)).await;

    let metrics_url = format!("http://127.0.0.1:{metrics_port}/metrics");
    let response = reqwest::get(&metrics_url)
        .await
        .expect("metrics listener must be reachable");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "the default (empty) allowed_ips must not block metrics scraping"
    );

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
}
