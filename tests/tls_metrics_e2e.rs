//! Regression test for the "Bug 2" metrics-recorder installation bug: with
//! TLS enabled, `run_tls` built its own router and served it directly,
//! WITHOUT ever spawning `start_metrics_server` -- the single call site (pre
//! -fix) that installed the global Prometheus recorder. Since
//! `default_tls_enabled()` returns `true`, any config that omits `[tls]`
//! (i.e. nearly any deployment that doesn't explicitly disable it) ran with
//! a process where every `metrics::counter!`/`gauge!` call resolved to a
//! no-op handle forever, and `/metrics` never started at all.
//!
//! This test drives the real TLS listener end to end: a real `Server`
//! configured with `tls.enabled = true` using the checked-in test
//! certificates (`tests/e2e/simulation-environment/certs/`, already used by
//! the Docker-based TLS simulation under that directory and valid until
//! 2027). It first proves the main listener really does speak TLS -- an
//! HTTPS GET to `/health` with a client that verifies the server
//! certificate against the checked-in CA, not `danger_accept_invalid_certs`
//! -- then scrapes `/metrics` (plain HTTP even under TLS, matching the
//! non-TLS path -- see the comment at the `run_tls` call site in
//! `src/server/mod.rs`). Before the fix, the `/metrics` step fails: nothing
//! is listening on `metrics.port` at all, because `run_tls`'s TLS branch
//! never spawned `start_metrics_server`.
//!
//! This MUST be the only `#[tokio::test]` in this binary -- the Prometheus
//! recorder is a process-global, install-once call (see
//! `install_metrics_recorder`'s doc comment in `src/server/mod.rs`).

use logthing::config::{Config, MetricsConfig, TlsConfig};
use logthing::forwarding::flush_registry::FlushIntervalRegistry;
use logthing::middleware::IpWhitelist;
use logthing::server::Server;
use logthing::stats::{SourceHourlyStats, ThroughputStats};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

async fn reserve_port() -> u16 {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    probe.local_addr().unwrap().port()
}

fn certs_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/e2e/simulation-environment/certs")
}

#[tokio::test]
async fn metrics_endpoint_reachable_over_real_tls() {
    // This binary links both rustls crypto-provider backends transitively
    // (hyper-rustls, pulled in by the AWS SDK deps, enables "ring"; axum-server
    // /tokio-rustls enable "aws-lc-rs") -- with both present, rustls refuses
    // to auto-select one and `rustls::ServerConfig::builder()` (inside
    // `build_tls_config`) panics instead of guessing. Nothing in this crate
    // installs a default provider anywhere today, production included; this
    // is test-harness plumbing standing in for that gap, not a change to
    // production TLS behaviour. Picking aws-lc-rs here matches the feature
    // rustls itself defaults to.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let https_port = reserve_port().await;
    let metrics_port = reserve_port().await;

    let config = Config {
        bind_address: format!("127.0.0.1:{https_port}").parse().unwrap(),
        tls: TlsConfig {
            enabled: true,
            port: https_port,
            cert_file: Some(certs_dir().join("server.crt")),
            key_file: Some(certs_dir().join("server.key")),
            ca_file: None,
            require_client_cert: false,
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
        config.clone(),
        shared_config,
        Arc::new(ThroughputStats::new()),
        Arc::new(SourceHourlyStats::new()),
        FlushIntervalRegistry::new(),
        IpWhitelist::empty(),
        Vec::new(),
    )
    .await
    .expect("Server::new must succeed with no S3/local targets configured");

    let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::watch::channel(false);
    let server_task = tokio::spawn(async move {
        server
            .run_tls(server_shutdown_rx)
            .await
            .expect("server run_tls must not error");
    });

    // --- Wait for `run_tls`'s TLS branch to reach the install-and-spawn
    // point added by the fix. `METRICS_HANDLE` only ever becomes populated
    // via `install_metrics_recorder`, so this is a direct probe of the
    // exact code path Bug 2 skipped. ---
    let install_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while logthing::server::METRICS_HANDLE.get().is_none() {
        assert!(
            tokio::time::Instant::now() < install_deadline,
            "METRICS_HANDLE was never populated by run_tls's TLS branch within 10s -- \
             Bug 2 (TLS deployments never install the recorder) is back"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Seed a known value on a real, described production metric now that
    // the real global recorder is confirmed installed -- proves the
    // scraped body reflects the live recorder, not a stale/no-op one.
    metrics::counter!("aggregate_records_consumed", "rule" => "tls_probe").increment(7);

    // --- Build a client that verifies the server cert against the
    // checked-in CA (not `danger_accept_invalid_certs`) -- a genuine TLS
    // handshake, not a skipped one. Used against the MAIN listener
    // (`https_port`), which really does speak TLS. ---
    let ca_pem = std::fs::read(certs_dir().join("ca.crt")).expect("read checked-in CA cert");
    let ca_cert = reqwest::Certificate::from_pem(&ca_pem).expect("parse checked-in CA cert");
    let tls_client = reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .build()
        .expect("build reqwest client with checked-in CA trust root");

    let health_url = format!("https://127.0.0.1:{https_port}/health");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match tls_client.get(&health_url).send().await {
            Ok(resp) if resp.status().is_success() => break,
            other => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "https://.../health never became reachable within 10s under a real TLS \
                     handshake (verified against the checked-in CA). Last result: {other:?}"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }

    // --- The metrics endpoint itself is plain HTTP even under TLS (same
    // design as the non-TLS path -- see the comment at the `run_tls` call
    // site in `src/server/mod.rs`); a plain client scrapes it directly. The
    // real TLS handshake above already proved `run_tls`'s TLS branch is
    // live; this proves the SAME branch also reaches the install/spawn code
    // this fix added. ---
    let metrics_url = format!("http://127.0.0.1:{metrics_port}/metrics");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let body = loop {
        match reqwest::get(&metrics_url).await {
            Ok(resp) if resp.status().is_success() => {
                break resp.text().await.expect("read /metrics response body");
            }
            other => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "http://.../metrics never became reachable within 10s from a TLS-enabled \
                     Server -- this is the exact endpoint Bug 2 never started. Last result: \
                     {other:?}"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    };

    assert!(
        body.contains("aggregate_records_consumed{rule=\"tls_probe\"} 7"),
        "expected the seeded counter value on the real /metrics endpoint, got:\n{body}"
    );
    assert!(
        body.contains("# HELP aggregate_records_consumed"),
        "describe_all must have registered HELP text against the same recorder the metrics \
         endpoint renders from, got:\n{body}"
    );

    server_shutdown_tx
        .send(true)
        .expect("server shutdown signal must send");
    tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server task must join after shutdown")
        .expect("server task must not panic");
}
