//! Integration test: F7 follow-up — `security.allowed_ips`, when non-empty,
//! must gate `/metrics` in *both* directions: a source in the list gets
//! 200, a source outside it gets 403.
//!
//! `metrics_bind_integration.rs` already proves the 403 direction using an
//! `allowed_ips` range (`10.0.0.0/8`) that excludes loopback entirely, so a
//! request from the test's own loopback source is always rejected. That
//! test cannot also prove the 200 direction, because it never sends from an
//! address that's actually in the list. `metrics_bind_default_allowlist_
//! integration.rs` proves `/metrics` stays reachable when `allowed_ips` is
//! the empty (allow-all) default — but an empty list isn't "an allowlisted
//! source", it's an absent whitelist.
//!
//! What's missing is the case operators actually hit: a *non-empty*
//! `allowed_ips` that intentionally includes the Prometheus scraper's
//! address. Forgetting to include it is exactly the trap called out in the
//! README's `[security]` and `## Metrics` sections — since the F7 fix
//! attached the same `IpWhitelist` layer used for wire-ingest sources onto
//! the metrics router, `allowed_ips` now gates both. This test spawns one
//! server with a two-entry `allowed_ips` (one entry is the scraper's
//! address, one is not) and asserts both outcomes against it: a client
//! bound to the listed address gets 200, a client bound to the unlisted
//! one gets 403 — not a timeout, not connection-refused, an actual 403.
//!
//! Two distinct loopback addresses (127.0.0.1 and 127.0.0.2) stand in for
//! "the scraper" and "some other source": Linux treats all of 127.0.0.0/8
//! as local to `lo`, so binding a `reqwest::Client` to either via
//! `ClientBuilder::local_address` needs no extra interface setup (same
//! idiom used by `tests/listener_ip_whitelist_e2e.rs`).
//!
//! This MUST be the only `#[tokio::test]` in this binary — see
//! `tests/metrics_bind_integration.rs` for why (the Prometheus global
//! recorder can only be installed once per process).

use logthing::config::{Config, MetricsConfig, SecurityConfig, TlsConfig};
use logthing::forwarding::flush_registry::FlushIntervalRegistry;
use logthing::middleware::IpWhitelist;
use logthing::server::Server;
use logthing::stats::{SourceHourlyStats, ThroughputStats};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

async fn reserve_tcp_port() -> u16 {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    probe.local_addr().unwrap().port()
}

fn client_bound_to(addr: Ipv4Addr) -> reqwest::Client {
    reqwest::Client::builder()
        .local_address(IpAddr::V4(addr))
        .build()
        .expect("build client bound to a loopback address")
}

#[tokio::test]
async fn allowed_ips_gates_metrics_in_both_directions() {
    let http_port = reserve_tcp_port().await;
    let metrics_port = reserve_tcp_port().await;

    // 127.0.0.2 stands in for the operator's Prometheus scraper: it's in
    // `allowed_ips`. 127.0.0.1 stands in for any other source: it's not.
    let scraper_addr = Ipv4Addr::new(127, 0, 0, 2);
    let other_addr = Ipv4Addr::new(127, 0, 0, 1);

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
            allowed_ips: vec![format!("{scraper_addr}/32")],
            ..SecurityConfig::default()
        },
        ..Config::default()
    };

    let shared_config = Arc::new(RwLock::new(config.clone()));
    let ip_whitelist = IpWhitelist::new(config.security.allowed_ips.clone()).unwrap();
    let server = Server::new(
        config,
        shared_config,
        Arc::new(ThroughputStats::new()),
        Arc::new(SourceHourlyStats::new()),
        FlushIntervalRegistry::new(),
        ip_whitelist,
        Vec::new(),
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

    let metrics_url = format!("http://127.0.0.1:{metrics_port}/metrics");

    // --- Direction 1: the allowlisted scraper address gets 200. ---
    let allowed_response = client_bound_to(scraper_addr)
        .get(&metrics_url)
        .send()
        .await
        .expect("metrics listener must be reachable from the allowlisted source");
    assert_eq!(
        allowed_response.status(),
        reqwest::StatusCode::OK,
        "a source in allowed_ips must be able to scrape /metrics"
    );

    // --- Direction 2: a source not in the list gets 403, not a timeout and
    // not connection-refused — the security property this whole follow-up
    // exists to pin down. ---
    let blocked_response = client_bound_to(other_addr)
        .get(&metrics_url)
        .send()
        .await
        .expect("metrics listener must be reachable (and then reject) the unlisted source");
    assert_eq!(
        blocked_response.status(),
        reqwest::StatusCode::FORBIDDEN,
        "a source outside allowed_ips must be rejected with 403, not silently allowed through"
    );

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
}
