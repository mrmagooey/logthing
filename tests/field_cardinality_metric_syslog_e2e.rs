//! End-to-end test: real syslog UDP ingest → real production `/metrics` HTTP
//! endpoint, for the `field_distinct_values` / `field_distinct_values_capped`
//! cardinality-watch gauge, `source = "syslog"`.
//!
//! Template: `tests/field_cardinality_metric_e2e.rs` (the zeek counterpart of
//! this same feature) for the overall shape — real `logthing::server::Server`
//! with `metrics.enabled = true`, a `CardinalityWatcher` built from config
//! exactly the way `main.rs` does, its shared window ticker
//! (`stats::cardinality::spawn_ticker`) spawned separately, and a short
//! `cardinality_window_secs` so the test does not wait out the production
//! default.
//!
//! Unlike the zeek/wef e2e tests, this one deliberately drives
//! `SyslogListener` at `SyslogListenerConfig::default()`'s `recv_tasks` (8),
//! NOT a smaller value: `syslog`, `ipfix`, and `sflow` listeners all take the
//! `SO_REUSEPORT` fan-out path (`syslog_udp_recv_loop`, spawned once per
//! socket) above `recv_tasks == 1`, and that fan-out path — not the inline
//! `recv_tasks <= 1` branch — is what ships at stock config. Wiring only the
//! inline branch would make the gauge sit at 0 in production while looking
//! wired in a test that overrode `recv_tasks` down to 1.
//! `tests/syslog_panic_resilience_e2e.rs` already does this same thing
//! deliberately, for the same reason — see its module doc comment.
//!
//! Like the zeek/wef e2e tests, the watcher is constructed in PRODUCTION
//! order — before `Server::run` has spawned the metrics server and installed
//! the real Prometheus recorder — which is what proves `CardinalityWatcher`'s
//! per-call (never-cached) handle resolution actually works end to end.
//! Deliberately NOT waiting on `METRICS_HANDLE` first.
//!
//! This MUST be the only `#[tokio::test]` in this binary — same reason as
//! the zeek/wef e2e tests: the Prometheus recorder is a process-global,
//! install-once call.

use logthing::config::{CardinalityWatch, Config, MetricsConfig, TlsConfig};
use logthing::forwarding::flush_registry::FlushIntervalRegistry;
use logthing::middleware::IpWhitelist;
use logthing::server::Server;
use logthing::stats::cardinality::{CardinalityWatcher, compile_watches, spawn_ticker};
use logthing::stats::{SourceHourlyStats, ThroughputStats};
use logthing::syslog::listener::{DefaultSyslogHandler, SyslogListener, SyslogListenerConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

async fn reserve_port() -> u16 {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    probe.local_addr().unwrap().port()
}

/// RFC 3164 line with a fixed `app_name` ("sshd", via the `tag[pid]:`
/// syntax — `SyslogMessage::stream()` returns `app_name`) and a variable
/// `hostname`, the field under test.
fn syslog_line(hostname: &str) -> Vec<u8> {
    format!("<34>Oct 11 22:14:15 {hostname} sshd[123]: session opened").into_bytes()
}

fn find_metric_value(body: &str, exact_prefix: &str) -> Option<f64> {
    body.lines().filter(|l| !l.starts_with('#')).find_map(|l| {
        l.strip_prefix(exact_prefix)
            .map(|rest| rest.trim())
            .and_then(|v| v.parse::<f64>().ok())
    })
}

#[tokio::test]
async fn field_distinct_values_visible_on_real_metrics_endpoint_at_default_recv_tasks() {
    let http_port = reserve_port().await;
    let metrics_port = reserve_port().await;
    let syslog_udp_port = reserve_port().await;
    let syslog_tcp_port = reserve_port().await;

    // --- Real Server, with the real /metrics endpoint enabled and the
    // cardinality watch configured exactly as an operator's TOML would. ---
    let config = Config {
        bind_address: format!("127.0.0.1:{http_port}").parse().unwrap(),
        tls: TlsConfig {
            enabled: false,
            ..TlsConfig::default()
        },
        metrics: MetricsConfig {
            enabled: true,
            port: metrics_port,
            cardinality_watch: vec![CardinalityWatch {
                source: "syslog".to_string(),
                stream: "sshd".to_string(),
                field: "hostname".to_string(),
            }],
            // Short window so the test does not need to wait an hour (the
            // production default) for the gauge to publish.
            cardinality_window_secs: 1,
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
        // No wef watch configured in this test.
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

    // `CardinalityWatcher` resolves its gauge/counter handles fresh via the
    // `metrics::gauge!`/`counter!` macros at each use site rather than
    // caching them on `self` — see `CardinalityWatcher::observe`/`tick`'s own
    // comments. That is what makes it safe to construct the watcher here in
    // the SAME order `main.rs` does: before `Server::run` has spawned
    // `start_metrics_server` and installed the real Prometheus recorder.

    // --- Build the CardinalityWatcher the same way main.rs does: validate
    // config, construct, spawn the shared window ticker. ---
    let mut watches = compile_watches(&config).expect("valid cardinality watch config compiles");
    assert_eq!(watches.len(), 1, "this test configures exactly one watch");
    let watch = watches.remove(0);
    let watcher = Arc::new(CardinalityWatcher::new(
        watch,
        config.metrics.cardinality_max_values,
    ));
    let (cardinality_shutdown_tx, cardinality_shutdown_rx) = tokio::sync::watch::channel(false);
    let ticker_task = spawn_ticker(
        vec![watcher.clone()],
        config.metrics.cardinality_window_secs,
        cardinality_shutdown_rx,
    );

    // --- Real SyslogListener, at the production default `recv_tasks` (8) —
    // see this file's module doc for why that matters — with the watcher
    // attached, mirroring main.rs's wiring. ---
    let syslog_listener_config = SyslogListenerConfig {
        udp_port: syslog_udp_port,
        tcp_port: syslog_tcp_port,
        bind_address: "127.0.0.1".to_string(),
        parse_dns_logs: false,
        // recv_tasks intentionally left at SyslogListenerConfig::default()'s
        // production value (8) — see this file's module doc comment.
        ..SyslogListenerConfig::default()
    };
    let syslog_handler = Arc::new(DefaultSyslogHandler::new(false, false, None));
    let syslog_listener = SyslogListener::new(syslog_listener_config, syslog_handler)
        .with_cardinality_watchers(vec![watcher.clone()]);
    let (syslog_shutdown_tx, syslog_shutdown_rx) = tokio::sync::watch::channel(false);
    let syslog_task = tokio::spawn(async move {
        syslog_listener
            .start_with_shutdown(syslog_shutdown_rx)
            .await
            .expect("syslog listener run must not error");
    });

    // Give the fan-out's recv tasks time to bind before sending.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // --- Send real syslog UDP datagrams: 3 messages, 2 distinct hostnames
    // (host-a repeated), all on the "sshd" app_name/stream. ---
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for host in ["host-a", "host-b", "host-a"] {
        sock.send_to(&syslog_line(host), format!("127.0.0.1:{syslog_udp_port}"))
            .await
            .expect("send syslog UDP datagram");
    }

    // --- Scrape the real /metrics endpoint over real HTTP until the gauge
    // reflects a completed window (up to a few window lengths, to absorb
    // ticker scheduling jitter). ---
    let metrics_url = format!("http://127.0.0.1:{metrics_port}/metrics");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let body = loop {
        if let Ok(resp) = reqwest::get(&metrics_url).await
            && let Ok(text) = resp.text().await
            && text.contains("field_distinct_values{")
            && find_metric_value(
                &text,
                "field_distinct_values{source=\"syslog\",stream=\"sshd\",field=\"hostname\"}",
            ) == Some(2.0)
        {
            break text;
        }
        if tokio::time::Instant::now() >= deadline {
            break reqwest::get(&metrics_url)
                .await
                .ok()
                .unwrap()
                .text()
                .await
                .unwrap_or_default();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    let distinct = find_metric_value(
        &body,
        "field_distinct_values{source=\"syslog\",stream=\"sshd\",field=\"hostname\"}",
    )
    .unwrap_or_else(|| {
        panic!(
            "field_distinct_values{{source=\"syslog\",stream=\"sshd\",field=\"hostname\"}} \
                 never appeared on the real /metrics endpoint within 15s. Full scrape \
                 body:\n{body}"
        )
    });
    assert_eq!(
        distinct, 2.0,
        "2 distinct hostname values from sshd messages (host-a repeated), observed through \
         the default recv_tasks (8) SO_REUSEPORT fan-out path. Full body:\n{body}"
    );

    let capped = find_metric_value(
        &body,
        "field_distinct_values_capped{source=\"syslog\",stream=\"sshd\",field=\"hostname\"} ",
    );
    assert_eq!(
        capped,
        Some(0.0),
        "field_distinct_values_capped must be present and zero when the cap was never hit. \
         Full body:\n{body}"
    );

    // --- Clean shutdown ---
    syslog_shutdown_tx
        .send(true)
        .expect("syslog shutdown signal must send");
    tokio::time::timeout(Duration::from_secs(5), syslog_task)
        .await
        .expect("syslog listener task must join after shutdown")
        .expect("syslog listener task must not panic");

    cardinality_shutdown_tx
        .send(true)
        .expect("cardinality ticker shutdown signal must send");
    tokio::time::timeout(Duration::from_secs(5), ticker_task)
        .await
        .expect("cardinality ticker task must join after shutdown")
        .expect("cardinality ticker task must not panic");

    server_shutdown_tx
        .send(true)
        .expect("server shutdown signal must send");
    tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server task must join after shutdown")
        .expect("server task must not panic");
}
