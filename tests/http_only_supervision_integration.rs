//! Integration test: the real `Server` + H-3 listener-supervision arm,
//! wired together exactly as `main.rs`'s top-level `tokio::select!` wires
//! them, when there are zero wire-protocol listeners (an HTTP-only
//! deployment — e.g. HEC only, no syslog/IPFIX/Zeek/Suricata/sFlow).
//!
//! Before the fix, `logthing::shutdown::supervise_listener_handles` (then
//! inlined in `main.rs`) built a `FuturesUnordered` from an empty
//! `listener_handles` vec. `FuturesUnordered::next()` on an empty set
//! resolves immediately with `None`, so that `select!` arm won on the very
//! first poll and the process fell straight through into the graceful
//! shutdown sequence — seconds after a perfectly valid startup. This test
//! reproduces the exact two-armed race (`Server::run` vs. the supervision
//! future) and asserts the combined future stays pending with no listener
//! handles, then resolves cleanly once the real shutdown signal fires.

use logthing::config::{Config, MetricsConfig, TlsConfig};
use logthing::forwarding::flush_registry::FlushIntervalRegistry;
use logthing::middleware::IpWhitelist;
use logthing::server::Server;
use logthing::shutdown::supervise_listener_handles;
use logthing::stats::{SourceHourlyStats, ThroughputStats};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[tokio::test]
async fn http_only_deployment_stays_up_then_shuts_down_cleanly() {
    let port = {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        probe.local_addr().unwrap().port()
    };

    let config = Config {
        bind_address: format!("127.0.0.1:{port}").parse().unwrap(),
        tls: TlsConfig {
            enabled: false,
            ..TlsConfig::default()
        },
        // Avoid binding a second, unneeded port.
        metrics: MetricsConfig {
            enabled: false,
            ..MetricsConfig::default()
        },
        ..Config::default()
    };

    let shared_config = Arc::new(RwLock::new(config.clone()));
    let throughput = Arc::new(ThroughputStats::new());
    let server = Server::new(
        config,
        shared_config,
        throughput,
        Arc::new(SourceHourlyStats::new()),
        FlushIntervalRegistry::new(),
        IpWhitelist::empty(),
    )
    .await
    .expect("Server::new must succeed with no S3/local targets configured");

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Run the same select! shape as main.rs's top-level select (minus the OS
    // signal arm, which is exercised separately by
    // tests/sigterm_graceful_shutdown_e2e.rs) as its own task, so it makes
    // progress concurrently with the HTTP requests below rather than only
    // while directly polled inline.
    let server_task = tokio::spawn(async move {
        // Exactly the `listener_handles` state of an HTTP-only deployment: no
        // syslog/IPFIX/Zeek/Suricata/sFlow listener was ever spawned.
        let mut listener_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

        tokio::select! {
            result = server.run(shutdown_rx.clone()) => {
                result.expect("server run must not error");
            }
            _ = supervise_listener_handles(&mut listener_handles) => {
                panic!(
                    "H-3 supervision arm resolved with zero listener handles — \
                     the empty-FuturesUnordered bug regressed"
                );
            }
        }
    });

    // Assertion 1: with no listener handles, the task must still be running
    // well past the old bug's near-instant exit.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !server_task.is_finished(),
        "server + supervision task exited on its own within 500ms with no \
         listener handles configured — the empty-handle-set bug regressed"
    );

    // Confirm the server is actually serving, not merely not-yet-polled.
    let base_url = format!("http://127.0.0.1:{port}");
    let resp = reqwest::get(format!("{base_url}/health"))
        .await
        .expect("GET /health must succeed while the server is up");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Assertion 2: the real shutdown signal (the watch channel main.rs sends
    // `true` on) still resolves the task cleanly.
    shutdown_tx.send(true).expect("shutdown signal must send");
    tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server task must join after shutdown")
        .expect("server task must not panic");
}
