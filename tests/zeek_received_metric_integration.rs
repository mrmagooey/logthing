//! Integration test closing the gap the unit test
//! `zeek::listener::tests::received_counters_fire_with_a_non_default_handler`
//! (in `src/zeek/listener.rs`) does not cover.
//!
//! That unit test calls the private `ZeekListener::handle_tcp_connection`
//! directly, in-process, on the calling task, with a thread-local
//! `DebuggingRecorder` and a small `CapturingHandler` test double. That
//! proves the counters fire when a non-default handler is wired up, but it
//! does not prove they survive the real accept path, which matters because:
//!
//! - The real accept loop (`ZeekListener::run_with_listener` /
//!   `start_with_shutdown`) `tokio::spawn`s a fresh task per accepted
//!   connection. A thread-local recorder set up on the test's own task would
//!   never observe metrics emitted on that spawned task — this test installs
//!   the recorder as the process-global recorder instead, exactly as
//!   production does, so it can observe counters from any task.
//! - Production wires a real forwarding handler (`MultiZeekHandler` wrapping
//!   `ZeekS3Handler`/`ZeekS3Handler`-over-local-disk), not a test double.
//!   This is the exact shape under which the bug was invisible: `main.rs`
//!   only installs `DefaultZeekHandler` (which used to own the counters)
//!   when zero forwarding destinations are configured, so any real
//!   deployment with `[zeek.s3]` or `[zeek.local]` silently lost both
//!   metrics.
//! - Production renders `/metrics` via `metrics_exporter_prometheus`'s real
//!   `PrometheusHandle::render()` text exposition, not a debugging snapshot.
//!
//! `metrics::set_global_recorder` can only be called once per process, and
//! cargo runs every `#[tokio::test]` in a test binary in the same process,
//! so this file intentionally contains exactly ONE `#[tokio::test]` — a
//! second test calling `set_global_recorder` here would panic on the second
//! call regardless of which one runs first.

use logthing::config::ZeekLocalConfig;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::zeek_s3::{MultiZeekHandler, zeek_local_start};
use logthing::stats::SourceHourlyStats;
use logthing::zeek::listener::{ZeekListener, ZeekListenerConfig};
use metrics_exporter_prometheus::PrometheusBuilder;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener as TokioTcpListener;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::{Duration, sleep, timeout};

/// Pull the numeric value off a Prometheus exposition-format line, e.g.
/// `zeek_records_received 3` -> `3.0`, or
/// `zeek_records_by_path{log_path="conn"} 2` -> `2.0`.
fn metric_value(rendered: &str, prefix: &str) -> Option<f64> {
    rendered
        .lines()
        // The space check matters: a bare `starts_with` would let a future
        // `zeek_records_received_errors` line satisfy a `zeek_records_received`
        // lookup and silently return the wrong number.
        .find(|line| {
            !line.starts_with('#')
                && line
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with(' '))
        })
        .and_then(|line| line.rsplit(' ').next())
        .and_then(|v| v.trim().parse::<f64>().ok())
}

#[tokio::test]
async fn zeek_records_received_and_by_path_survive_the_real_accept_and_forwarding_path() {
    // --- Install the real Prometheus recorder globally, exactly as
    // `start_metrics_server` in src/server/mod.rs does for the production
    // `/metrics` endpoint. Must happen exactly once per process; see the
    // file-level doc comment for why this file has only one test.
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    metrics::set_global_recorder(recorder).expect("install recorder");

    // --- Build a real forwarding handler the way main.rs does for
    // `[zeek.local]`, needing no external service (MinIO-gated S3 tests are
    // skipped in CI; local disk is always available).
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    let cfg = ZeekLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "zeek".to_string(),
        max_buffer_rows: 1,
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 256,
    };
    // The writer JoinHandle is deliberately not awaited: this test asserts on
    // ingest counters only, never on flushed parquet, so the final flush the
    // handle exists to await is irrelevant here. Retain and await it in any
    // test that does read the written files back.
    let (handler, _writer_handle) =
        zeek_local_start(&cfg, sink, Arc::new(SourceHourlyStats::new()), None);

    // Wrap in `MultiZeekHandler` — the exact multi-destination shape a real
    // deployment gets (main.rs only skips it when zero destinations are
    // configured), and the configuration under which the bug was invisible.
    let multi_handler: Arc<dyn logthing::zeek::listener::ZeekHandler> =
        Arc::new(MultiZeekHandler(vec![Arc::new(handler)]));

    // --- Start a real ZeekListener on an ephemeral port via the public
    // `start_with_shutdown` entry point (the same one main.rs calls).
    // `run_with_listener` is `pub(crate)` and unreachable from this external
    // integration-test crate, so reserve a port with a probe bind-then-drop
    // (accepted TOCTOU race — same pattern as
    // tests/throughput_stats_cap_e2e.rs and tests/admin_flush_interval_e2e.rs)
    // and hand it to `start_with_shutdown`.
    let port = {
        let probe = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        probe.local_addr().unwrap().port()
    };
    let listener_config = ZeekListenerConfig {
        tcp_port: port,
        bind_address: "127.0.0.1".to_string(),
    };
    let listener = ZeekListener::new(listener_config, multi_handler);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let listener_task = tokio::spawn(async move {
        listener.start_with_shutdown(shutdown_rx).await.ok();
    });

    // Poll-connect until the port accepts rather than a fixed sleep.
    let addr = format!("127.0.0.1:{port}");
    let mut stream = timeout(Duration::from_secs(5), async {
        loop {
            match TcpStream::connect(&addr).await {
                Ok(s) => return s,
                Err(_) => sleep(Duration::from_millis(20)).await,
            }
        }
    })
    .await
    .expect("listener accepted a connection within 5s");

    // --- Write real NDJSON zeek lines over the real TCP connection: 2x
    // conn, 1x dns, distinct `_path` values.
    let conn_line = |uid: &str| {
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
    };
    let dns_line = |uid: &str| {
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
    };

    for line in [
        conn_line("CReceived001"),
        conn_line("CReceived002"),
        dns_line("DReceived001"),
    ] {
        stream
            .write_all(format!("{line}\n").as_bytes())
            .await
            .expect("write NDJSON line");
    }
    stream.shutdown().await.expect("shutdown write half");
    drop(stream);

    // --- Poll the real Prometheus exposition text until both counters
    // appear, bounded so a regression fails fast instead of hanging.
    let rendered = timeout(Duration::from_secs(5), async {
        loop {
            let rendered = handle.render();
            if metric_value(&rendered, "zeek_records_received").is_some()
                && metric_value(&rendered, "zeek_records_by_path{log_path=\"conn\"}").is_some()
                && metric_value(&rendered, "zeek_records_by_path{log_path=\"dns\"}").is_some()
            {
                return rendered;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect(
        "zeek_records_received / zeek_records_by_path never appeared on the real Prometheus \
         exposition within 5s — regression: these counters must fire on the real accept path \
         (spawned per-connection tasks) with a real forwarding handler wired up, not just when \
         DefaultZeekHandler is installed",
    );

    assert_eq!(
        metric_value(&rendered, "zeek_records_received"),
        Some(3.0),
        "zeek_records_received must count all 3 records sent over the real TCP connection \
         through a real (non-default) forwarding handler; rendered exposition:\n{rendered}"
    );
    assert_eq!(
        metric_value(&rendered, "zeek_records_by_path{log_path=\"conn\"}"),
        Some(2.0),
        "zeek_records_by_path{{log_path=\"conn\"}} must count both conn records; rendered \
         exposition:\n{rendered}"
    );
    assert_eq!(
        metric_value(&rendered, "zeek_records_by_path{log_path=\"dns\"}"),
        Some(1.0),
        "zeek_records_by_path{{log_path=\"dns\"}} must count the dns record; rendered \
         exposition:\n{rendered}"
    );

    // --- Shut down cleanly.
    shutdown_tx.send(true).ok();
    let _ = timeout(Duration::from_secs(2), listener_task).await;
}
