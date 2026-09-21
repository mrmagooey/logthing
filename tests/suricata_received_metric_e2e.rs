//! End-to-end test: real suricata TCP ingest → real production `/metrics`
//! HTTP endpoint.
//!
//! Regression under test: `suricata_records_received` /
//! `suricata_records_by_event_type` used to be incremented inside
//! `DefaultSuricataHandler::handle_record`, but `main.rs` only installs
//! `DefaultSuricataHandler` when zero forwarding destinations are configured
//! — so in any real deployment (a forwarding handler installed) the counters
//! never fired, and the metrics endpoint never showed suricata traffic. The
//! fix moved both `metrics::counter!` calls into `SuricataListener::
//! handle_tcp_connection`'s EVE JSON parse loop, ahead of the handler
//! dispatch, so they fire regardless of which handler is installed.
//!
//! This test proves the fix end to end, through the outermost interfaces
//! only: a real `logthing::server::Server` (the same entry point `main.rs`
//! uses) with `metrics.enabled = true`, a real `logthing::suricata::listener::
//! SuricataListener` fed over a real TCP connection, with a real *non-default*
//! forwarding handler (`suricata_local_start` writing to local disk via
//! `MultiSuricataHandler`, exactly the shape `main.rs` builds when
//! destinations are configured) — then scrapes `/metrics` over real HTTP and
//! asserts the counters are present and correct.
//!
//! This MUST be the only `#[tokio::test]` in this binary: `Server::run`
//! installs the Prometheus recorder via `metrics::set_global_recorder`,
//! which is a process-global call that panics if invoked twice in one
//! process. Cargo runs each integration-test *file* as its own process, so
//! keeping this file to a single test is what keeps that call singular.
//!
//! No external service is required — the suricata forwarding destination is
//! local disk (a `tempfile::tempdir()`), not S3/MinIO.

use logthing::config::{Config, MetricsConfig, SuricataLocalConfig, TlsConfig};
use logthing::forwarding::flush_registry::FlushIntervalRegistry;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::suricata_s3::{MultiSuricataHandler, suricata_local_start};
use logthing::middleware::IpWhitelist;
use logthing::server::Server;
use logthing::stats::{SourceHourlyStats, ThroughputStats};
use logthing::suricata::listener::{SuricataListener, SuricataListenerConfig};
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

fn alert_line(sig: &str) -> String {
    serde_json::json!({
        "event_type": "alert",
        "src_ip": "10.0.0.1",
        "dest_ip": "8.8.8.8",
        "alert": {"signature": sig},
        "timestamp": "2024-01-15T10:30:00Z",
    })
    .to_string()
}

fn flow_line() -> String {
    serde_json::json!({
        "event_type": "flow",
        "src_ip": "10.0.0.2",
        "dest_ip": "1.1.1.1",
        "proto": "TCP",
        "timestamp": "2024-01-15T10:30:01Z",
    })
    .to_string()
}

/// Pull a Prometheus counter value out of the raw exposition text, ignoring
/// `# HELP` / `# TYPE` comment lines. Matches an exact metric line (name +
/// optional `{labels}`) at the start of the line.
fn find_metric_value(body: &str, exact_prefix: &str) -> Option<f64> {
    body.lines().filter(|l| !l.starts_with('#')).find_map(|l| {
        l.strip_prefix(exact_prefix)
            .map(|rest| rest.trim())
            .and_then(|v| v.parse::<f64>().ok())
    })
}

#[tokio::test]
async fn suricata_records_received_visible_on_real_metrics_endpoint_with_forwarding_handler() {
    let http_port = reserve_port().await;
    let metrics_port = reserve_port().await;
    let suricata_port = reserve_port().await;

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

    // --- Real SuricataListener, with a real *non-default* forwarding handler ---
    // Using DefaultSuricataHandler here would not exercise the regression:
    // the bug only reproduced when a forwarding handler (the shape main.rs
    // builds whenever a suricata destination is configured) was installed
    // instead. suricata_local_start + MultiSuricataHandler mirrors that
    // shape, writing real Parquet to local disk (no S3/MinIO needed).
    let disk_dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(disk_dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    let suricata_local_cfg = SuricataLocalConfig {
        directory: disk_dir.path().to_path_buf(),
        prefix: "suricata".to_string(),
        // Flush on every push so this test can also verify the records that
        // travel the real TCP -> EnvelopeAccumulator -> Parquet path (not
        // just the /metrics counters) actually land on disk correctly.
        max_buffer_rows: 1,
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 256,
    };
    // The writer JoinHandle IS awaited below, after the listener shuts down
    // and drops the last handler reference: with two alert pushes landing in
    // the same (partition, day) buffer back to back, the second can arrive
    // while the first's flush is still in flight, in which case it is left
    // sitting in the buffer rather than flushed immediately (see
    // `try_flush_partition_async`'s `in_flight` coalescing) -- only the
    // channel-close-triggered `flush_all` is guaranteed to land it on disk.
    let (suricata_handler, writer_task) = suricata_local_start(
        &suricata_local_cfg,
        sink,
        Arc::new(SourceHourlyStats::new()),
        None,
    );
    let handler: Arc<dyn logthing::suricata::listener::SuricataHandler> =
        Arc::new(MultiSuricataHandler(vec![Arc::new(suricata_handler)]));

    let suricata_listener_config = SuricataListenerConfig {
        tcp_port: suricata_port,
        bind_address: "127.0.0.1".to_string(),
    };
    let suricata_listener = SuricataListener::new(suricata_listener_config, handler);
    let (suricata_shutdown_tx, suricata_shutdown_rx) = tokio::sync::watch::channel(false);
    let suricata_task = tokio::spawn(async move {
        suricata_listener
            .start_with_shutdown(suricata_shutdown_rx)
            .await
            .expect("suricata listener run must not error");
    });

    // --- Wait for the suricata TCP port to accept connections ---
    let mut suricata_stream = None;
    for _ in 0..50 {
        match TcpStream::connect(("127.0.0.1", suricata_port)).await {
            Ok(s) => {
                suricata_stream = Some(s);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    let mut suricata_stream =
        suricata_stream.expect("suricata TCP listener did not accept in time");

    // --- Send real EVE JSON lines over the real TCP connection ---
    // 2x alert, 1x flow — distinct event_type values to verify per-type label
    // breakdown, not just the aggregate counter.
    let lines = [
        alert_line("ET TEST ONE"),
        alert_line("ET TEST TWO"),
        flow_line(),
    ];
    for line in &lines {
        suricata_stream
            .write_all(format!("{line}\n").as_bytes())
            .await
            .expect("write suricata EVE JSON line");
    }
    suricata_stream
        .shutdown()
        .await
        .expect("shutdown write half");
    drop(suricata_stream);

    // --- Scrape the real /metrics endpoint over real HTTP until the counter appears ---
    let metrics_url = format!("http://127.0.0.1:{metrics_port}/metrics");
    let mut body = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(resp) = reqwest::get(&metrics_url).await
            && let Ok(text) = resp.text().await
            && text.contains("suricata_records_received")
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
        body.contains("suricata_records_received"),
        "regression: suricata_records_received never appeared on the real /metrics \
         endpoint within 10s, even with a non-DefaultSuricataHandler forwarding handler \
         installed. Full scrape body:\n{body}"
    );

    let received = find_metric_value(&body, "suricata_records_received ").unwrap_or_else(|| {
        panic!(
            "regression: could not parse suricata_records_received value from /metrics \
             body:\n{body}"
        )
    });
    assert_eq!(
        received, 3.0,
        "regression: suricata_records_received must count all 3 records ingested via the \
         real suricata TCP listener even though a forwarding handler (not \
         DefaultSuricataHandler) is installed. Full scrape body:\n{body}"
    );

    let alert_count = find_metric_value(
        &body,
        "suricata_records_by_event_type{event_type=\"alert\"}",
    )
    .unwrap_or_else(|| {
        panic!(
            "regression: suricata_records_by_event_type{{event_type=\"alert\"}} missing \
             from /metrics body despite a forwarding handler being installed:\n{body}"
        )
    });
    let flow_count =
        find_metric_value(&body, "suricata_records_by_event_type{event_type=\"flow\"}")
            .unwrap_or_else(|| {
                panic!(
                    "regression: suricata_records_by_event_type{{event_type=\"flow\"}} missing \
             from /metrics body despite a forwarding handler being installed:\n{body}"
                )
            });
    assert_eq!(
        alert_count, 2.0,
        "expected 2 alert records counted by event_type; full body:\n{body}"
    );
    assert_eq!(
        flow_count, 1.0,
        "expected 1 flow record counted by event_type; full body:\n{body}"
    );

    // --- Clean shutdown ---
    // Shut the listener down first: this drops the last `Arc<dyn
    // SuricataHandler>` reference (held inside `suricata_listener`), which
    // closes the writer's channel and lets its background task run its
    // final synchronous `flush_all` before `writer_task` resolves below --
    // the only point at which every pushed record is guaranteed to be on
    // disk (see the `in_flight` coalescing note above).
    suricata_shutdown_tx
        .send(true)
        .expect("suricata shutdown signal must send");
    tokio::time::timeout(Duration::from_secs(5), suricata_task)
        .await
        .expect("suricata listener task must join after shutdown")
        .expect("suricata listener task must not panic");
    tokio::time::timeout(Duration::from_secs(5), writer_task)
        .await
        .expect("suricata writer task must join after shutdown")
        .expect("suricata writer task must not panic");

    // --- Verify the records also reached Parquet on disk via the real
    // EnvelopeAccumulator path (RecordBatchAccumulator<SuricataRecord>),
    // not just the /metrics counters. The writer task above has already run
    // its shutdown flush_all, so every pushed record is on disk by now.
    fn read_event_type_and_src_ip(dir: &std::path::Path) -> Vec<(String, Option<String>)> {
        use arrow::array::{Array, StringArray};
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

        let mut rows = Vec::new();
        if !dir.is_dir() {
            return rows;
        }
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                rows.extend(read_event_type_and_src_ip(&path));
                continue;
            }
            if path.extension().is_some_and(|e| e == "parquet") {
                let bytes = std::fs::read(&path).unwrap();
                let builder =
                    ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes)).unwrap();
                let reader = builder.build().unwrap();
                for rb in reader {
                    let rb = rb.unwrap();
                    let event_type = rb
                        .column_by_name("event_type")
                        .unwrap()
                        .as_any()
                        .downcast_ref::<StringArray>()
                        .unwrap();
                    let src_ip = rb
                        .column_by_name("src_ip")
                        .unwrap()
                        .as_any()
                        .downcast_ref::<StringArray>()
                        .unwrap();
                    for i in 0..rb.num_rows() {
                        rows.push((
                            event_type.value(i).to_string(),
                            if src_ip.is_null(i) {
                                None
                            } else {
                                Some(src_ip.value(i).to_string())
                            },
                        ));
                    }
                }
            }
        }
        rows
    }

    let suricata_root = disk_dir.path().join("suricata");
    let mut all_rows = read_event_type_and_src_ip(&suricata_root);
    all_rows.sort();

    assert_eq!(
        all_rows.len(),
        3,
        "expected all 3 records ingested over the real TCP connection to reach \
         Parquet on disk via the real EnvelopeAccumulator path after shutdown flush, \
         got: {all_rows:?}"
    );
    let alert_rows: Vec<_> = all_rows.iter().filter(|(et, _)| et == "alert").collect();
    let flow_rows: Vec<_> = all_rows.iter().filter(|(et, _)| et == "flow").collect();
    assert_eq!(
        alert_rows.len(),
        2,
        "expected 2 alert rows on disk, got: {all_rows:?}"
    );
    assert_eq!(
        flow_rows.len(),
        1,
        "expected 1 flow row on disk, got: {all_rows:?}"
    );
    assert!(
        alert_rows
            .iter()
            .all(|(_, ip)| ip.as_deref() == Some("10.0.0.1")),
        "alert rows must carry the src_ip sent over the wire, got: {all_rows:?}"
    );
    assert!(
        flow_rows
            .iter()
            .all(|(_, ip)| ip.as_deref() == Some("10.0.0.2")),
        "flow row must carry the src_ip sent over the wire, got: {all_rows:?}"
    );

    server_shutdown_tx
        .send(true)
        .expect("server shutdown signal must send");
    tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server task must join after shutdown")
        .expect("server task must not panic");
}
