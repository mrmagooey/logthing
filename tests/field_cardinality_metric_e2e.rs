//! End-to-end test: real zeek TCP ingest → real production `/metrics` HTTP
//! endpoint, for the `field_distinct_values` / `field_distinct_values_capped`
//! cardinality-watch gauge.
//!
//! Template: `tests/zeek_received_metric_e2e.rs`
//! (`zeek_records_received_visible_on_real_metrics_endpoint_with_forwarding_handler`).
//! Same shape — real `logthing::server::Server` with `metrics.enabled =
//! true`, a real `ZeekListener` fed over a real TCP connection, a real
//! non-default forwarding handler (local-disk zeek writer) — but this test
//! additionally builds a `CardinalityWatcher` from a `source = "zeek"`
//! `[[metrics.cardinality_watch]]` entry exactly the way `main.rs` does,
//! attaches it to the listener via `with_cardinality_watchers`, and spawns
//! its shared window ticker (`stats::cardinality::spawn_ticker`). A short
//! `cardinality_window_secs` keeps the test fast without needing to fake
//! the clock.
//!
//! The WEF counterpart of this test — driving the SAME feature through
//! `/wsman/events` instead of the zeek TCP listener — is
//! `tests/field_cardinality_metric_wef_e2e.rs`.
//!
//! This MUST be the only `#[tokio::test]` in this binary — see the doc
//! comment on the template test for why (the Prometheus recorder is a
//! process-global, install-once call).

use logthing::config::{CardinalityWatch, Config, MetricsConfig, TlsConfig, ZeekLocalConfig};
use logthing::forwarding::flush_registry::FlushIntervalRegistry;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::zeek_s3::{MultiZeekHandler, zeek_local_start};
use logthing::middleware::IpWhitelist;
use logthing::server::Server;
use logthing::stats::cardinality::{CardinalityWatcher, compile_watches, spawn_ticker};
use logthing::stats::{SourceHourlyStats, ThroughputStats};
use logthing::zeek::listener::{ZeekListener, ZeekListenerConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::RwLock;

async fn reserve_port() -> u16 {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    probe.local_addr().unwrap().port()
}

fn conn_line(uid: &str, orig_h: &str) -> String {
    serde_json::json!({
        "_path": "conn",
        "ts": 1700000000.0,
        "uid": uid,
        "id.orig_h": orig_h,
        "id.orig_p": 12345,
        "id.resp_h": "10.0.0.2",
        "id.resp_p": 443,
        "proto": "tcp",
        "conn_state": "SF",
        "orig_bytes": 1024,
        "resp_bytes": 8192,
    })
    .to_string()
}

fn dns_line(uid: &str, orig_h: &str) -> String {
    serde_json::json!({
        "_path": "dns",
        "ts": 1700000100.0,
        "uid": uid,
        "id.orig_h": orig_h,
        "id.orig_p": 12345,
        "id.resp_h": "8.8.8.8",
        "id.resp_p": 53,
        "query": "example.com",
        "qtype_name": "A",
        "rcode_name": "NOERROR",
    })
    .to_string()
}

fn find_metric_value(body: &str, exact_prefix: &str) -> Option<f64> {
    body.lines().filter(|l| !l.starts_with('#')).find_map(|l| {
        l.strip_prefix(exact_prefix)
            .map(|rest| rest.trim())
            .and_then(|v| v.parse::<f64>().ok())
    })
}

#[tokio::test]
async fn field_distinct_values_visible_on_real_metrics_endpoint_after_a_window_boundary() {
    let http_port = reserve_port().await;
    let metrics_port = reserve_port().await;
    let zeek_port = reserve_port().await;

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
                source: "zeek".to_string(),
                stream: "conn".to_string(),
                field: "id.orig_h".to_string(),
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
        // No wef watch configured in this test — that path is covered by
        // tests/field_cardinality_metric_wef_e2e.rs.
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
    // `metrics::gauge!`/`counter!` macros at each use site (`tick`'s gauge
    // set, `observe`'s cap-miss branch) rather than caching them on `self` —
    // see the comments at those call sites. That is what makes it safe to
    // construct the watcher here in the SAME order `main.rs` does: before
    // `Server::run` has spawned `start_metrics_server` and installed the
    // real Prometheus recorder. A cached handle resolved this early would
    // bind to the no-op recorder permanently; a macro call resolves against
    // whatever recorder is installed *at that later moment*, so it is fine
    // for construction to race the recorder install.

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

    // --- Real ZeekListener, with a real *non-default* forwarding handler
    // AND the watcher attached, mirroring main.rs's wiring. ---
    let disk_dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(disk_dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    let zeek_local_cfg = ZeekLocalConfig {
        directory: disk_dir.path().to_path_buf(),
        prefix: "zeek".to_string(),
        max_buffer_rows: 100_000,
        flush_threshold_bytes: 100_000_000,
        flush_interval_secs: 3600,
        channel_capacity: 256,
    };
    let (zeek_handler, _writer_task) = zeek_local_start(
        &zeek_local_cfg,
        sink,
        Arc::new(SourceHourlyStats::new()),
        None,
    );
    let handler: Arc<dyn logthing::zeek::listener::ZeekHandler> =
        Arc::new(MultiZeekHandler(vec![Arc::new(zeek_handler)]));

    let zeek_listener_config = ZeekListenerConfig {
        tcp_port: zeek_port,
        bind_address: "127.0.0.1".to_string(),
    };
    let zeek_listener =
        ZeekListener::new(zeek_listener_config, handler).with_cardinality_watchers(vec![watcher]);
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

    // --- Send real NDJSON zeek lines: 3 conn records (2 distinct
    // id.orig_h), plus 1 dns record whose id.orig_h must be excluded by the
    // stream filter. ---
    let lines = [
        conn_line("CReceived001", "10.0.0.1"),
        conn_line("CReceived002", "10.0.0.2"),
        conn_line("CReceived003", "10.0.0.1"),
        dns_line("DReceived001", "10.0.0.9"),
    ];
    for line in &lines {
        zeek_stream
            .write_all(format!("{line}\n").as_bytes())
            .await
            .expect("write zeek NDJSON line");
    }
    zeek_stream.shutdown().await.expect("shutdown write half");
    drop(zeek_stream);

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
                "field_distinct_values{source=\"zeek\",stream=\"conn\",field=\"id.orig_h\"}",
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
        "field_distinct_values{source=\"zeek\",stream=\"conn\",field=\"id.orig_h\"}",
    )
    .unwrap_or_else(|| {
        panic!(
            "field_distinct_values{{source=\"zeek\",stream=\"conn\",field=\"id.orig_h\"}} \
                 never appeared on the real /metrics endpoint within 15s. Full scrape \
                 body:\n{body}"
        )
    });
    assert_eq!(
        distinct, 2.0,
        "2 distinct id.orig_h values from conn records (10.0.0.1 repeated); the dns \
         record's id.orig_h must have been excluded by the stream filter. Full body:\n{body}"
    );

    // `tick` registers the capped counter at zero every window, so the
    // series is present from the first scrape even though nothing here came
    // near the default cap. An absent counter would leave an operator unable
    // to distinguish a healthy watch from a mistyped config, so its presence
    // at zero is the behaviour under test — not an incidental detail.
    let capped = find_metric_value(
        &body,
        "field_distinct_values_capped{source=\"zeek\",stream=\"conn\",field=\"id.orig_h\"} ",
    );
    assert_eq!(
        capped,
        Some(0.0),
        "field_distinct_values_capped must be present and zero when the cap was never hit. \
         Full body:\n{body}"
    );

    // --- Clean shutdown ---
    zeek_shutdown_tx
        .send(true)
        .expect("zeek shutdown signal must send");
    tokio::time::timeout(Duration::from_secs(5), zeek_task)
        .await
        .expect("zeek listener task must join after shutdown")
        .expect("zeek listener task must not panic");

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
