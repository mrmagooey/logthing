//! End-to-end test: real IPFIX UDP listener → real production `/metrics`
//! HTTP endpoint, for the socket-drop / rx-queue-depth metrics.
//!
//! Before this task, `ipfix_datagrams_received` counted what arrived but
//! nothing counted what the kernel discarded before it ever reached this
//! process — every prior loss figure was reconstructed by hand-diffing the
//! process-wide `/proc/net/snmp`. `SocketDropStats` (`src/net.rs`) instead
//! reads the listener's own `/proc/net/udp` line once a second and reports
//! `ipfix_socket_drops` (counter) and `ipfix_socket_rx_queue_bytes` (gauge).
//!
//! This test proves both series reach the real `/metrics` exposition through
//! the real listener wiring (`IpfixListener::start_with_shutdown`), the same
//! entry point `main.rs` uses. It does not attempt to force a real kernel
//! drop (that would be flaky through an actively-draining listener loop —
//! see the dedicated integration test in `src/net.rs` for that, which floods
//! an *unread* raw socket instead); it only asserts presence and correct
//! per-protocol naming, mirroring `tests/zeek_received_metric_e2e.rs`.
//!
//! Ipfix stands in for sflow/syslog_udp here — the wiring is byte-for-byte
//! identical `SocketDropStats::new` + 1s ticker in a `select!` arm across
//! all three listeners, so one live listener proves the shared `src/net.rs`
//! mechanism actually reaches `/metrics` without duplicating the same proof
//! three times.
//!
//! This MUST be the only `#[tokio::test]` in this binary: `Server::run`
//! installs the Prometheus recorder via `metrics::set_global_recorder`,
//! which panics if called twice in one process. Cargo runs each integration
//! test *file* as its own process, so keeping this file to a single test
//! keeps that call singular.

use logthing::config::{Config, MetricsConfig, TlsConfig};
use logthing::forwarding::flush_registry::FlushIntervalRegistry;
use logthing::ipfix::listener::{DefaultIpfixHandler, IpfixListener, IpfixListenerConfig};
use logthing::middleware::IpWhitelist;
use logthing::server::Server;
use logthing::stats::{SourceHourlyStats, ThroughputStats};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

/// Reserve an ephemeral port: bind a probe socket to 127.0.0.1:0, read the
/// assigned port, then drop the probe so the real component can bind it.
/// Same TOCTOU-avoidance idiom as `tests/zeek_received_metric_e2e.rs`.
async fn reserve_udp_port() -> u16 {
    let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    probe.local_addr().unwrap().port()
}

async fn reserve_tcp_port() -> u16 {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    probe.local_addr().unwrap().port()
}

#[tokio::test]
async fn ipfix_socket_drop_metrics_visible_on_real_metrics_endpoint() {
    let http_port = reserve_tcp_port().await;
    let metrics_port = reserve_tcp_port().await;
    let ipfix_port = reserve_udp_port().await;

    // --- Real Server, with the real /metrics endpoint enabled ---
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

    let shared_config = Arc::new(RwLock::new(config.clone()));
    let server = Server::new(
        config,
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
            .run(server_shutdown_rx)
            .await
            .expect("server run must not error");
    });

    // --- Real IpfixListener, real production entry point ---
    let ipfix_config = IpfixListenerConfig {
        udp_port: ipfix_port,
        bind_address: "127.0.0.1".to_string(),
        ..IpfixListenerConfig::default()
    };
    let ipfix_listener = IpfixListener::new(ipfix_config, Arc::new(DefaultIpfixHandler));
    let (ipfix_shutdown_tx, ipfix_shutdown_rx) = tokio::sync::watch::channel(false);
    let ipfix_task = tokio::spawn(async move {
        ipfix_listener
            .start_with_shutdown(ipfix_shutdown_rx)
            .await
            .expect("ipfix listener run must not error");
    });

    // Give the listener time to bind and the socket-drop ticker time to fire
    // at least once (SOCKET_DROP_POLL_INTERVAL is 1s).
    tokio::time::sleep(Duration::from_millis(1_500)).await;

    // --- Scrape the real /metrics endpoint over real HTTP until both series appear ---
    let metrics_url = format!("http://127.0.0.1:{metrics_port}/metrics");
    let mut body = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(resp) = reqwest::get(&metrics_url).await
            && let Ok(text) = resp.text().await
            && text.contains("ipfix_socket_drops")
            && text.contains("ipfix_socket_rx_queue_bytes")
        {
            body = text;
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(
        body.contains("ipfix_socket_drops"),
        "regression: ipfix_socket_drops never appeared on the real /metrics \
         endpoint within the deadline. Full scrape body:\n{body}"
    );
    assert!(
        body.contains("ipfix_socket_rx_queue_bytes"),
        "regression: ipfix_socket_rx_queue_bytes never appeared on the real \
         /metrics endpoint within the deadline. Full scrape body:\n{body}"
    );

    // Both series must carry `# HELP`, not just the `# TYPE` line the
    // exporter writes unconditionally. These two names are built with
    // `format!` per protocol in `metrics_descriptions::describe_all`, so they
    // are the ones that break if the describe call stops running after
    // `set_global_recorder` or drops a protocol from SOCKET_POLL_PROTOCOLS.
    assert!(
        body.contains("# HELP ipfix_socket_drops"),
        "regression: ipfix_socket_drops rendered without a # HELP line — \
         metrics_descriptions::describe_all did not reach the installed \
         recorder. Full scrape body:\n{body}"
    );
    assert!(
        body.contains("# HELP ipfix_socket_rx_queue_bytes"),
        "regression: ipfix_socket_rx_queue_bytes rendered without a # HELP \
         line. Full scrape body:\n{body}"
    );

    // Neither metric must be mislabelled as another protocol's.
    assert!(
        !body.contains("sflow_socket_drops") && !body.contains("syslog_udp_socket_drops"),
        "regression: only the ipfix listener is running in this test, but \
         another protocol's socket-drop metric appeared. Full scrape body:\n{body}"
    );

    // --- Clean shutdown ---
    ipfix_shutdown_tx
        .send(true)
        .expect("ipfix shutdown signal must send");
    tokio::time::timeout(Duration::from_secs(5), ipfix_task)
        .await
        .expect("ipfix listener task must join after shutdown")
        .expect("ipfix listener task must not panic");

    server_shutdown_tx
        .send(true)
        .expect("server shutdown signal must send");
    tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server task must join after shutdown")
        .expect("server task must not panic");
}
