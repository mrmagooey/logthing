//! End-to-end test: real zeek TCP ingest → real production `/metrics` HTTP
//! endpoint.
//!
//! Regression under test: `zeek_records_received` / `zeek_records_by_path`
//! used to be incremented inside `DefaultZeekHandler::handle_record`, but
//! `main.rs` only installs `DefaultZeekHandler` when zero forwarding
//! destinations are configured — so in any real deployment (a forwarding
//! handler installed) the counters never fired, and the metrics endpoint
//! never showed zeek traffic. The fix moved both `metrics::counter!` calls
//! into `ZeekListener::handle_tcp_connection`'s NDJSON parse loop, ahead of
//! the handler dispatch, so they fire regardless of which handler is
//! installed.
//!
//! This test proves the fix end to end, through the outermost interfaces
//! only: a real `logthing::server::Server` (the same entry point `main.rs`
//! uses) with `metrics.enabled = true`, a real `logthing::zeek::listener::
//! ZeekListener` fed over a real TCP connection, with a real *non-default*
//! forwarding handler (`zeek_local_start` writing to local disk via
//! `MultiZeekHandler`, exactly the shape `main.rs` builds when destinations
//! are configured) — then scrapes `/metrics` over real HTTP and asserts the
//! counters are present and correct.
//!
//! This MUST be the only `#[tokio::test]` in this binary: `Server::run`
//! installs the Prometheus recorder via `metrics::set_global_recorder`,
//! which is a process-global call that panics if invoked twice in one
//! process. Cargo runs each integration-test *file* as its own process, so
//! keeping this file to a single test is what keeps that call singular.
//!
//! No external service is required — the zeek forwarding destination is
//! local disk (a `tempfile::tempdir()`), not S3/MinIO.

use logthing::config::{Config, MetricsConfig, TlsConfig, ZeekLocalConfig};
use logthing::forwarding::flush_registry::FlushIntervalRegistry;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::zeek_s3::{MultiZeekHandler, zeek_local_start};
use logthing::server::Server;
use logthing::stats::{SourceHourlyStats, ThroughputStats};
use logthing::zeek::listener::{ZeekListener, ZeekListenerConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::RwLock;

/// Reserve an ephemeral port: bind a probe listener to 127.0.0.1:0, read the
/// assigned port, then drop the listener so the real component can bind it.
/// Same accepted-TOCTOU pattern as `tests/throughput_stats_cap_e2e.rs` /
/// `tests/admin_flush_interval_e2e.rs`.
async fn reserve_port() -> u16 {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    probe.local_addr().unwrap().port()
}

fn conn_line(uid: &str) -> String {
    serde_json::json!({
        "_path": "conn",
        "ts": 1700000000.0,
        "uid": uid,
        "id.orig_h": "10.0.0.1",
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

fn dns_line(uid: &str) -> String {
    serde_json::json!({
        "_path": "dns",
        "ts": 1700000100.0,
        "uid": uid,
        "id.orig_h": "192.168.1.100",
        "id.orig_p": 12345,
        "id.resp_h": "8.8.8.8",
        "id.resp_p": 53,
        "query": "example.com",
        "qtype_name": "A",
        "rcode_name": "NOERROR",
    })
    .to_string()
}

/// Pull a Prometheus counter value out of the raw exposition text, ignoring
/// `# HELP` / `# TYPE` comment lines. Matches an exact metric line (name +
/// optional `{labels}`) at the start of the line.
fn find_metric_value(body: &str, exact_prefix: &str) -> Option<f64> {
    body.lines()
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| {
            l.strip_prefix(exact_prefix)
                .map(|rest| rest.trim())
                .and_then(|v| v.parse::<f64>().ok())
        })
}

#[tokio::test]
async fn zeek_records_received_visible_on_real_metrics_endpoint_with_forwarding_handler() {
    let http_port = reserve_port().await;
    let metrics_port = reserve_port().await;
    let zeek_port = reserve_port().await;

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

    // --- Real ZeekListener, with a real *non-default* forwarding handler ---
    // Using DefaultZeekHandler here would not exercise the regression: the
    // bug only reproduced when a forwarding handler (the shape main.rs
    // builds whenever a zeek destination is configured) was installed
    // instead. zeek_local_start + MultiZeekHandler mirrors that shape,
    // writing real Parquet to local disk (no S3/MinIO needed).
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

    // --- Send real NDJSON zeek lines over the real TCP connection ---
    // 2x conn, 1x dns — distinct _path values to verify per-path label
    // breakdown, not just the aggregate counter.
    let lines = [
        conn_line("CReceived001"),
        conn_line("CReceived002"),
        dns_line("DReceived001"),
    ];
    for line in &lines {
        zeek_stream
            .write_all(format!("{line}\n").as_bytes())
            .await
            .expect("write zeek NDJSON line");
    }
    zeek_stream.shutdown().await.expect("shutdown write half");
    drop(zeek_stream);

    // --- Scrape the real /metrics endpoint over real HTTP until the counter appears ---
    let metrics_url = format!("http://127.0.0.1:{metrics_port}/metrics");
    let mut body = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(resp) = reqwest::get(&metrics_url).await
            && let Ok(text) = resp.text().await
            && text.contains("zeek_records_received")
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
        body.contains("zeek_records_received"),
        "regression: zeek_records_received never appeared on the real /metrics \
         endpoint within 10s, even with a non-DefaultZeekHandler forwarding handler \
         installed. Full scrape body:\n{body}"
    );

    let received = find_metric_value(&body, "zeek_records_received ").unwrap_or_else(|| {
        panic!(
            "regression: could not parse zeek_records_received value from /metrics body:\n{body}"
        )
    });
    assert_eq!(
        received, 3.0,
        "regression: zeek_records_received must count all 3 records ingested via the \
         real zeek TCP listener even though a forwarding handler (not DefaultZeekHandler) \
         is installed. Full scrape body:\n{body}"
    );

    let conn_count =
        find_metric_value(&body, "zeek_records_by_path{log_path=\"conn\"}").unwrap_or_else(|| {
            panic!(
                "regression: zeek_records_by_path{{log_path=\"conn\"}} missing from /metrics \
                 body despite a forwarding handler being installed:\n{body}"
            )
        });
    let dns_count =
        find_metric_value(&body, "zeek_records_by_path{log_path=\"dns\"}").unwrap_or_else(|| {
            panic!(
                "regression: zeek_records_by_path{{log_path=\"dns\"}} missing from /metrics \
                 body despite a forwarding handler being installed:\n{body}"
            )
        });
    assert_eq!(
        conn_count, 2.0,
        "expected 2 conn records counted by log_path; full body:\n{body}"
    );
    assert_eq!(
        dns_count, 1.0,
        "expected 1 dns record counted by log_path; full body:\n{body}"
    );

    // --- Clean shutdown ---
    zeek_shutdown_tx
        .send(true)
        .expect("zeek shutdown signal must send");
    tokio::time::timeout(Duration::from_secs(5), zeek_task)
        .await
        .expect("zeek listener task must join after shutdown")
        .expect("zeek listener task must not panic");

    server_shutdown_tx
        .send(true)
        .expect("server shutdown signal must send");
    tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server task must join after shutdown")
        .expect("server task must not panic");
}
