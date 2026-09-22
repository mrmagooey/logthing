//! Regression test for the metrics-recorder installation-ordering bug
//! ("Bug 1"): `RuleMetrics` (`forwarding::aggregate::mod.rs`) resolves and
//! *caches* its `metrics::Counter` handles once, inside `Aggregator::new`.
//! `metrics::counter!`/`gauge!` bind to whichever recorder is installed at
//! the moment the macro runs; with none installed yet they return a no-op
//! handle, and a no-op handle cached in a struct field stays no-op forever.
//!
//! Before the fix, the only thing that installed the global Prometheus
//! recorder was `start_metrics_server`, spawned asynchronously from
//! `Server::run` -- strictly *after* `main.rs` had already called
//! `Aggregator::new`. So `aggregate_records_consumed`/`aggregate_overflow_records`
//! never appeared on a real `/metrics` scrape in production, and nothing in
//! the test suite asserted on that metric by name.
//!
//! This test reproduces `main.rs`'s real construction order -- install the
//! recorder synchronously via `install_metrics_recorder`, THEN build the
//! `Aggregator` -- not recorder-after-aggregator, which would just
//! reproduce the blind spot the bug hid in. Get the order right and this
//! test is the one that would have caught the original bug: without the
//! fix, `aggregate_records_consumed` never shows up on the real endpoint
//! below and the test times out.
//!
//! Templates: the `/metrics`-scraping half from
//! `tests/field_cardinality_metric_e2e.rs`; the aggregator/listener wiring
//! from `tests/aggregate_e2e.rs`.
//!
//! This MUST be the only `#[tokio::test]` in this binary -- the Prometheus
//! recorder is a process-global, install-once call (see
//! `install_metrics_recorder`'s doc comment in `src/server/mod.rs`).

use logthing::config::{Config, MetricsConfig, TlsConfig, ZeekConfig};
use logthing::forwarding::aggregate::{
    Aggregator, CompiledRule, handlers::AggregatingZeekHandler, rule_schema, start_aggregate_writer,
};
use logthing::forwarding::flush_registry::FlushIntervalRegistry;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::middleware::IpWhitelist;
use logthing::server::Server;
use logthing::stats::{SourceHourlyStats, ThroughputStats};
use logthing::zeek::listener::{DefaultZeekHandler, ZeekHandler, ZeekListener, ZeekListenerConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::RwLock;

async fn reserve_port() -> u16 {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    probe.local_addr().unwrap().port()
}

fn find_metric_value(body: &str, exact_prefix: &str) -> Option<f64> {
    body.lines().filter(|l| !l.starts_with('#')).find_map(|l| {
        l.strip_prefix(exact_prefix)
            .map(|rest| rest.trim())
            .and_then(|v| v.parse::<f64>().ok())
    })
}

#[tokio::test]
async fn aggregate_records_consumed_visible_on_real_metrics_endpoint() {
    let http_port = reserve_port().await;
    let metrics_port = reserve_port().await;
    let zeek_port = reserve_port().await;

    let config = Config {
        bind_address: format!("127.0.0.1:{http_port}").parse().unwrap(),
        tls: TlsConfig {
            enabled: false,
            ..TlsConfig::default()
        },
        // This test drives ZeekListener directly rather than through
        // main.rs's config.zeek gating, but Aggregator's `source: "zeek"`
        // rule below doesn't depend on this flag either way -- set for
        // parity with a real operator config.
        zeek: ZeekConfig {
            enabled: true,
            ..ZeekConfig::default()
        },
        metrics: MetricsConfig {
            enabled: true,
            port: metrics_port,
            ..MetricsConfig::default()
        },
        ..Config::default()
    };

    // --- Reproduce main.rs's real construction order: install the
    // recorder synchronously FIRST, then build the Aggregator below.
    // Reversing this order reproduces the exact blind spot that let the
    // original bug ship -- a handle resolved after the recorder exists
    // isn't what production `Aggregator::new` sees at startup. ---
    logthing::server::install_metrics_recorder();

    let group_by = vec!["query".to_string()];
    let rules = vec![CompiledRule {
        name: Arc::from("aggregate_metrics_e2e_rule"),
        source: "zeek".to_string(),
        stream: Some("dns".to_string()),
        group_by: group_by.clone(),
        aggs: Vec::new(),
        schema: rule_schema(&group_by, &[]),
    }];

    let disk_dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(disk_dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    let (writer_handle, _writer_task) = start_aggregate_writer(
        &rules,
        "aggregate".to_string(),
        1,
        256,
        sink,
        Arc::new(SourceHourlyStats::new()),
        None,
    );
    let writer_handle = Arc::new(writer_handle);

    let agg = Arc::new(Aggregator::new(rules, 1000));
    let (agg_shutdown_tx, agg_shutdown_rx) = tokio::sync::watch::channel(false);
    let emit_task =
        agg.clone()
            .spawn_emit_task(vec![writer_handle], Duration::from_secs(1), agg_shutdown_rx);

    let handler: Arc<dyn ZeekHandler> = Arc::new(AggregatingZeekHandler {
        agg: agg.clone(),
        inner: Arc::new(DefaultZeekHandler),
    });

    // --- Real Server, with the real /metrics endpoint enabled. ---
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
            .run(server_shutdown_rx)
            .await
            .expect("server run must not error");
    });

    // --- Real ZeekListener, decorated with the aggregating handler --
    // mirrors how main.rs wraps each source's handler chain. ---
    let zeek_listener_config = ZeekListenerConfig {
        tcp_port: zeek_port,
        bind_address: "127.0.0.1".to_string(),
    };
    let zeek_listener = ZeekListener::new(zeek_listener_config, handler);
    let (zeek_shutdown_tx, zeek_shutdown_rx) = tokio::sync::watch::channel(false);
    let zeek_task = tokio::spawn(async move {
        zeek_listener
            .start_with_shutdown(zeek_shutdown_rx)
            .await
            .expect("zeek listener run must not error");
    });

    // --- Wait for the zeek TCP port to accept connections ---
    let mut zeek_stream = None;
    for _ in 0..50 {
        match TcpStream::connect(("127.0.0.1", zeek_port)).await {
            Ok(s) => {
                zeek_stream = Some(s);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    let mut zeek_stream = zeek_stream.expect("zeek TCP listener did not accept in time");

    // --- Send real NDJSON zeek dns records that match the rule's stream
    // and group_by ("query"). ---
    for _ in 0..3 {
        zeek_stream
            .write_all(b"{\"_path\":\"dns\",\"query\":\"noisy.example\"}\n")
            .await
            .expect("write dns line");
    }
    zeek_stream.shutdown().await.expect("shutdown write half");
    drop(zeek_stream);

    // --- Scrape the real /metrics endpoint over real HTTP until the
    // counter appears (or the deadline expires, in which case the bug is
    // still present). ---
    let metrics_url = format!("http://127.0.0.1:{metrics_port}/metrics");
    let prefix = "aggregate_records_consumed{rule=\"aggregate_metrics_e2e_rule\"}";
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut last_body = String::new();
    let value = loop {
        if let Ok(resp) = reqwest::get(&metrics_url).await
            && let Ok(text) = resp.text().await
        {
            if let Some(v) = find_metric_value(&text, prefix)
                && v > 0.0
            {
                last_body = text;
                break Some(v);
            }
            last_body = text;
        }
        if tokio::time::Instant::now() >= deadline {
            break None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    let value = value.unwrap_or_else(|| {
        panic!(
            "{prefix} never appeared as non-zero on the real /metrics endpoint within 15s \
             -- this is the RuleMetrics no-op-handle regression (see the module doc comment). \
             Full scrape body:\n{last_body}"
        )
    });
    assert_eq!(
        value, 3.0,
        "3 identical dns records must all be consumed by the rule. Full body:\n{last_body}"
    );

    // --- Clean shutdown ---
    zeek_shutdown_tx
        .send(true)
        .expect("zeek shutdown signal must send");
    tokio::time::timeout(Duration::from_secs(5), zeek_task)
        .await
        .expect("zeek listener task must join after shutdown")
        .expect("zeek listener task must not panic");

    agg_shutdown_tx
        .send(true)
        .expect("agg shutdown signal must send");
    tokio::time::timeout(Duration::from_secs(5), emit_task)
        .await
        .expect("emit task must join after shutdown")
        .expect("emit task must not panic");

    server_shutdown_tx
        .send(true)
        .expect("server shutdown signal must send");
    tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server task must join after shutdown")
        .expect("server task must not panic");
}
