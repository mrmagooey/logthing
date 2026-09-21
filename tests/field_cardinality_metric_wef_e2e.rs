//! End-to-end test: real WEF HTTP ingest (`POST /wsman/events`) → real
//! production `/metrics` HTTP endpoint, for the `field_distinct_values` /
//! `field_distinct_values_capped` cardinality-watch gauge, `source = "wef"`.
//!
//! Template: `tests/field_cardinality_metric_e2e.rs` (the zeek counterpart
//! of this same feature) for the overall shape — real
//! `logthing::server::Server` with `metrics.enabled = true`, a
//! `CardinalityWatcher` built from config exactly the way `main.rs` does,
//! its shared window ticker (`stats::cardinality::spawn_ticker`) spawned
//! separately, and a short `cardinality_window_secs` so the test does not
//! wait out the production default. WEF has no separate socket listener —
//! events arrive over the same real HTTP server the `/metrics` scrape uses,
//! via `POST /wsman/events` with real WEF XML bodies (see
//! `tests/wef_s3_integration.rs` / `tests/wef_local_integration.rs` for how
//! `WindowsEvent`/`ParsedEvent` are shaped, and
//! `tests/throughput_stats_cap_e2e.rs` for the real-HTTP-POST-of-WEF-XML
//! pattern this test's `wef_event_xml` mirrors).
//!
//! Like the zeek e2e test, the watcher is constructed in PRODUCTION order —
//! before `Server::run` has spawned the metrics server and installed the
//! real Prometheus recorder — which is what proves `CardinalityWatcher`'s
//! per-call (never-cached) handle resolution actually works end to end.
//! Deliberately NOT waiting on `METRICS_HANDLE` first.
//!
//! This MUST be the only `#[tokio::test]` in this binary — same reason as
//! the zeek e2e test: the Prometheus recorder is a process-global,
//! install-once call.

use logthing::config::{CardinalityWatch, Config, MetricsConfig, TlsConfig};
use logthing::forwarding::flush_registry::FlushIntervalRegistry;
use logthing::middleware::IpWhitelist;
use logthing::server::Server;
use logthing::stats::cardinality::{CardinalityWatcher, compile_watches, spawn_ticker};
use logthing::stats::{SourceHourlyStats, ThroughputStats};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

async fn reserve_port() -> u16 {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    probe.local_addr().unwrap().port()
}

/// One `<Event>` element with the given channel/computer, matching the
/// shape real Windows Event Forwarding XML carries in `<System>`.
fn wef_event_xml(channel: &str, computer: &str) -> String {
    format!(
        r#"<Event>
          <System>
            <Provider>Microsoft-Windows-Security-Auditing</Provider>
            <EventID>4624</EventID>
            <Level>4</Level>
            <Channel>{channel}</Channel>
            <TimeCreated>2024-01-01T00:00:00Z</TimeCreated>
            <Computer>{computer}</Computer>
          </System>
        </Event>"#
    )
}

fn wef_envelope(events: &[String]) -> String {
    format!(
        "<Envelope><Body><Events>{}</Events></Body></Envelope>",
        events.join("\n")
    )
}

fn find_metric_value(body: &str, exact_prefix: &str) -> Option<f64> {
    body.lines().filter(|l| !l.starts_with('#')).find_map(|l| {
        l.strip_prefix(exact_prefix)
            .map(|rest| rest.trim())
            .and_then(|v| v.parse::<f64>().ok())
    })
}

/// Count of distinct Prometheus series (label sets) for a given metric name
/// in a scrape body — used to prove hostile wire values never mint more
/// than the one series this config's single watch owns.
fn series_count(body: &str, metric_name: &str) -> usize {
    body.lines()
        .filter(|l| !l.starts_with('#') && l.starts_with(&format!("{metric_name}{{")))
        .count()
}

#[tokio::test]
async fn field_distinct_values_visible_on_real_metrics_endpoint_for_wef_computer() {
    let http_port = reserve_port().await;
    let metrics_port = reserve_port().await;

    // Deliberately small cap: lets this test prove the hostile-input
    // bound (many distinct `computer` values must cap the gauge and bump
    // field_distinct_values_capped, never grow the series count) without
    // needing thousands of real HTTP round trips.
    let max_values = 3;

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
                source: "wef".to_string(),
                stream: "Security".to_string(),
                field: "computer".to_string(),
            }],
            cardinality_window_secs: 1,
            cardinality_max_values: max_values,
            ..MetricsConfig::default()
        },
        ..Config::default()
    };

    // --- Build the CardinalityWatcher the same way main.rs does: validate
    // config, construct, spawn the shared window ticker — BEFORE
    // Server::new/Server::run has installed the real Prometheus recorder.
    // See the module doc for why that ordering matters. ---
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

    let shared_config = Arc::new(RwLock::new(config.clone()));
    let server = Server::new(
        config,
        shared_config,
        Arc::new(ThroughputStats::new()),
        Arc::new(SourceHourlyStats::new()),
        FlushIntervalRegistry::new(),
        IpWhitelist::empty(),
        vec![watcher],
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

    let base_url = format!("http://127.0.0.1:{http_port}");
    let metrics_url = format!("http://127.0.0.1:{metrics_port}/metrics");
    let client = reqwest::Client::new();

    // --- Wait for the real HTTP server to come up. ---
    let mut ready = false;
    for _ in 0..50 {
        if let Ok(resp) = client.get(format!("{base_url}/health")).send().await
            && resp.status() == reqwest::StatusCode::OK
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "server did not become ready in time");

    // --- Window 1: 3 events on "Security" (2 distinct `computer`, one
    // repeated), plus 1 event on "System" whose `computer` must be excluded
    // by the stream filter — same shape as the zeek e2e test's conn/dns
    // split. Well under `max_values`, so nothing is capped here. ---
    let window1 = wef_envelope(&[
        wef_event_xml("Security", "WIN-HOST-01"),
        wef_event_xml("Security", "WIN-HOST-02"),
        wef_event_xml("Security", "WIN-HOST-01"),
        wef_event_xml("System", "WIN-HOST-99"),
    ]);
    let resp = client
        .post(format!("{base_url}/wsman/events"))
        .body(window1)
        .send()
        .await
        .expect("POST /wsman/events must succeed");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let body = loop {
        if let Ok(resp) = reqwest::get(&metrics_url).await
            && let Ok(text) = resp.text().await
            && find_metric_value(
                &text,
                "field_distinct_values{source=\"wef\",stream=\"Security\",field=\"computer\"}",
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
        "field_distinct_values{source=\"wef\",stream=\"Security\",field=\"computer\"}",
    )
    .unwrap_or_else(|| {
        panic!(
            "field_distinct_values{{source=\"wef\",stream=\"Security\",field=\"computer\"}} \
             never appeared on the real /metrics endpoint within 15s. Full scrape body:\n{body}"
        )
    });
    assert_eq!(
        distinct, 2.0,
        "2 distinct computer values from Security events (WIN-HOST-01 repeated); the System \
         event's computer must have been excluded by the stream filter. Full body:\n{body}"
    );
    assert_eq!(
        find_metric_value(
            &body,
            "field_distinct_values_capped{source=\"wef\",stream=\"Security\",field=\"computer\"} ",
        ),
        Some(0.0),
        "cap must not have been hit in window 1. Full body:\n{body}"
    );

    // --- Window 2 (hostile): a 16 KiB `computer` value, an empty one, and
    // 3 more distinct short ones — 5 distinct values against a cap of 3.
    // Proves the gauge's VALUE changes (caps at 3) and
    // field_distinct_values_capped counts the overflow, while the
    // Prometheus SERIES COUNT for both metrics stays exactly 1: the label
    // set is `source`/`stream`/`field`, all from config, never the wire
    // (see stats::cardinality's module doc "Safety property" section) —
    // no amount of adversarial `computer` values can mint a new series. ---
    let huge_computer = "H".repeat(16 * 1024);
    let window2 = wef_envelope(&[
        wef_event_xml("Security", &huge_computer),
        wef_event_xml("Security", ""),
        wef_event_xml("Security", "WIN-HOST-03"),
        wef_event_xml("Security", "WIN-HOST-04"),
        wef_event_xml("Security", "WIN-HOST-05"),
    ]);
    let resp = client
        .post(format!("{base_url}/wsman/events"))
        .body(window2)
        .send()
        .await
        .expect("POST /wsman/events must succeed");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let body = loop {
        if let Ok(resp) = reqwest::get(&metrics_url).await
            && let Ok(text) = resp.text().await
            && find_metric_value(
                &text,
                "field_distinct_values{source=\"wef\",stream=\"Security\",field=\"computer\"}",
            ) == Some(max_values as f64)
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
        "field_distinct_values{source=\"wef\",stream=\"Security\",field=\"computer\"}",
    );
    assert_eq!(
        distinct,
        Some(max_values as f64),
        "5 distinct computer values observed against a cap of {max_values}; the gauge must \
         read the cap, not 5. Full body:\n{body}"
    );
    let capped = find_metric_value(
        &body,
        "field_distinct_values_capped{source=\"wef\",stream=\"Security\",field=\"computer\"} ",
    );
    assert!(
        capped.is_some_and(|c| c > 0.0),
        "at least one of the 5 hostile values must have been counted as capped. Full body:\n{body}"
    );
    assert_eq!(
        series_count(&body, "field_distinct_values"),
        1,
        "a 16 KiB computer value, an empty one, and several more distinct ones must never mint \
         more than the one series this config's single watch owns. Full body:\n{body}"
    );
    assert_eq!(
        series_count(&body, "field_distinct_values_capped"),
        1,
        "same bound for the capped counter. Full body:\n{body}"
    );

    // --- Clean shutdown ---
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
