//! E2E: a Zeek sensor outrunning the writer must be back-pressured over TCP,
//! not silently dropped (spec §6).
//!
//! Wires a REAL `ZeekListener` on an ephemeral port, a real `ZeekSink`, a
//! real `ParquetWriterHandle<ZeekSink>` (the `send_or_drop` code under
//! test), and a custom slow `UploadSink` -- same shape as
//! `examples/flush_decoupling_benchmark.rs` and
//! `tests/zeek_flush_decoupling_e2e.rs`, which this test's harness is
//! modeled on directly.
//!
//! ## Why a real global Prometheus recorder, not `DebuggingRecorder`
//!
//! This test uses a `multi_thread` runtime (see below for why), and the
//! thread-local `DebuggingRecorder` has a documented cross-thread visibility
//! gap on such a runtime: a spawned task's metric calls can land on a
//! different OS thread than the one holding the recorder guard, silently
//! hiding them from a snapshot (see `examples/flush_decoupling_benchmark.rs`'s
//! doc comment and `tests/buffered_writer_flush_decoupling_integration.rs`).
//! `metrics_exporter_prometheus::PrometheusBuilder`'s recorder aggregates
//! across every OS thread in the process, so it has no such gap.
//!
//! ## Why `multi_thread`
//!
//! The property under test is that a genuinely fast TCP client (writing as
//! fast as the socket accepts, no pacing) gets throttled by `send_or_drop`
//! rather than dropped by `try_send`. That requires the accept loop, the
//! per-connection read loop, the writer's channel-drain loop, and the
//! client's write loop to all be able to make real progress concurrently
//! under load -- a `current_thread` runtime can starve one of them behind
//! another under a tight non-yielding send loop. `worker_threads = 4`
//! matches the harness this test is modeled on.
//!
//! ## `channel_capacity`
//!
//! Earlier tasks in this plan established that a real writer task drains
//! its channel in microseconds regardless of sink health -- `push()` is
//! CPU-only and never touches the sink, and flushes run on spawned
//! background tasks. That means the *default* production channel capacity
//! (derived from a 100 MiB budget, tens of thousands of records) would
//! essentially never fill for either `send_or_drop` or `try_send`, and the
//! zero-drops assertion below would pass vacuously under both -- it
//! wouldn't discriminate the fix from a regression.
//!
//! This test therefore configures a small explicit `channel_capacity = 8`.
//! It's large enough that legitimate scheduling jitter doesn't make every
//! single record round-trip individually, but small enough that a
//! non-yielding local TCP client -- which can enqueue many thousands of
//! records/sec over loopback -- reliably outruns the writer's drain loop in
//! bursts and transiently fills it. Verified empirically (see the
//! mutation-check note in the task report): with `try_send`, that transient
//! fullness causes real drops; with `send_or_drop`, the connection's read
//! loop blocks briefly on `send_timeout` instead, so nothing is dropped.
//!
//! ## What is (and isn't) asserted
//!
//! The load-bearing assertion is `parquet_s3_dropped{source="zeek"} == 0`
//! while the client outruns the pipeline -- the one that fails if
//! `send_or_drop` is reverted to `try_send` (confirmed by mutation, see the
//! task report).
//!
//! A secondary assertion checks that at least one client `write()` call took
//! materially longer than the others (`max > 10 * median` of per-write
//! elapsed times), evidence that the stall reaches the client's actual TCP
//! socket -- the connection's read loop blocking inside `send_or_drop` stops
//! draining the socket, so the kernel receive buffer (and then the client's
//! send buffer) fills and a subsequent `write()` genuinely blocks in the
//! syscall. Empirically this ratio lands in the 10^5-10^6 range across
//! repeated local runs (see the task report), so the 10x threshold has a
//! very large margin and does not depend on a lightly-loaded machine.

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;

use logthing::forwarding::buffered_writer::{
    BufferedWriterConfig, FlushPolicy, LiveInterval, ParquetWriterHandle, UploadSink,
};
use logthing::forwarding::zeek_s3::ZeekSink;
use logthing::stats::SourceHourlyStats;
use logthing::zeek::listener::{ZeekHandler, ZeekListener, ZeekListenerConfig};

/// An UploadSink that sleeps, simulating a slow Garage/S3 endpoint. Matches
/// `examples/flush_decoupling_benchmark.rs`'s `DelayUploadSink`. The delay
/// alone does not fill the writer's channel (flushes run off the drain
/// loop's critical path) -- it's here so a flush is genuinely in flight
/// during the send burst, matching the real-world scenario the spec (§6)
/// describes rather than a channel that's artificially never flushed.
struct SlowSink {
    delay: Duration,
}

#[async_trait::async_trait]
impl UploadSink for SlowSink {
    async fn upload(&self, _key: &str, _body: Vec<u8>) -> anyhow::Result<()> {
        tokio::time::sleep(self.delay).await;
        Ok(())
    }
    fn target_label(&self) -> &'static str {
        "e2e"
    }
    fn location_hint(&self) -> String {
        "slow-sink".to_string()
    }
}

/// Finds the sample line for `metric{labels}` in Prometheus exposition text
/// and parses its trailing numeric value. Returns 0 if the metric hasn't
/// been emitted yet (counters don't appear in the render until first
/// incremented). Copied from `examples/flush_decoupling_benchmark.rs`.
fn parse_counter(rendered: &str, metric_with_labels: &str) -> f64 {
    for line in rendered.lines() {
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with(metric_with_labels)
            && let Some(value_str) = line.rsplit(' ').next()
            && let Ok(v) = value_str.parse::<f64>()
        {
            return v;
        }
    }
    0.0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zeek_tcp_client_is_backpressured_rather_than_dropped() {
    // 1. Install a real PrometheusBuilder recorder (not DebuggingRecorder --
    //    see module doc comment for why).
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();
    metrics::set_global_recorder(recorder).expect("failed to install global Prometheus recorder");

    // 2. Start a real ZeekListener on 127.0.0.1:0 wired to a
    //    ParquetWriterHandle<ZeekSink> backed by SlowSink { delay: 150ms }.
    let writer_cfg = BufferedWriterConfig {
        connection: logthing::config::S3ConnectionConfig {
            endpoint: String::new(),
            bucket: String::new(),
            region: String::new(),
            access_key: String::new(),
            secret_key: String::new(),
        },
        prefix: "zeek".to_string(),
        max_buffer_rows: 100_000,
        flush_threshold_bytes: 104_857_600,
        flush_interval_secs: 3600,
        // See module doc comment: small and explicit so the test can
        // discriminate send_or_drop from try_send.
        channel_capacity: 8,
        max_partitions: 8,
    };
    let policy = FlushPolicy {
        max_rows: 100_000,
        max_bytes: 104_857_600,
        interval: LiveInterval::new(Duration::from_secs(3600)),
    };
    let upload_sink: Arc<dyn UploadSink> = Arc::new(SlowSink {
        delay: Duration::from_millis(150),
    });

    let (handler, _writer_join_handle) = ParquetWriterHandle::<ZeekSink>::start_with_stats(
        ZeekSink,
        upload_sink,
        writer_cfg,
        policy,
        Arc::new(SourceHourlyStats::new()),
        None,
    );
    let handler: Arc<dyn ZeekHandler> = Arc::new(handler);

    // Reserve an ephemeral port (bind-then-drop -- ZeekListener::start()
    // binds internally and doesn't report back which port it chose; same
    // pattern as the benchmark and tests/zeek_flush_decoupling_e2e.rs).
    let port = {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        probe.local_addr().unwrap().port()
    };
    let listener_cfg = ZeekListenerConfig {
        tcp_port: port,
        bind_address: "127.0.0.1".to_string(),
    };
    let zeek_listener = ZeekListener::new(listener_cfg, handler.clone());
    tokio::spawn(async move {
        let _ = zeek_listener.start().await;
    });

    // 3. Connect a real TcpStream and write NDJSON conn lines as fast as the
    //    socket accepts them, for a fixed duration.
    let mut stream = loop {
        match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
            Ok(s) => break s,
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    };
    stream.set_nodelay(true).ok();

    let send_duration = Duration::from_secs(2);
    let start = Instant::now();
    let mut n: u64 = 0;
    let mut sent = 0u64;
    // Per-write() elapsed times -- step 5's evidence that the stall reaches
    // the client's socket, not just the server's internal channel. Measured
    // outside write_all's error path so a mid-write disconnect doesn't
    // pollute the sample.
    let mut write_times: Vec<Duration> = Vec::new();
    while start.elapsed() < send_duration {
        let line = format!("{{\"_path\":\"conn\",\"uid\":\"C{n}\"}}\n");
        let write_start = Instant::now();
        if stream.write_all(line.as_bytes()).await.is_err() {
            break;
        }
        write_times.push(write_start.elapsed());
        n += 1;
        sent = n;
    }
    stream.flush().await.ok();

    // Fixed drain period so in-flight buffered records / in-flight flushes
    // get a chance to complete before we snapshot metrics.
    tokio::time::sleep(Duration::from_millis(500)).await;
    drop(stream);

    let rendered = metrics_handle.render();
    let dropped = parse_counter(
        &rendered,
        r#"parquet_s3_dropped{source="zeek",target="e2e"}"#,
    );

    // 4. Assert parquet_s3_dropped{source="zeek"} == 0. This is the
    // load-bearing assertion: mutation-tested by temporarily reverting
    // zeek_s3.rs's handler to try_send, which reliably drops ~70% of
    // ~200k records sent in the same 2s window (see task report).
    assert!(sent > 0, "the send loop must have sent at least one line");
    assert_eq!(
        dropped, 0.0,
        "parquet_s3_dropped{{source=\"zeek\",target=\"e2e\"}} must stay at 0 while a fast \
client outruns the writer -- send_or_drop must back-pressure the sender instead of \
dropping (sent {sent} records)"
    );

    // 5. Assert at least one write() call took materially longer than the
    // others -- the socket's send buffer filled because the server stopped
    // reading while send_or_drop's bounded wait was blocking the
    // connection's read loop. That is backpressure reaching the wire, not
    // just the internal channel. `max > 10 * median` (per the task brief):
    // a socket that never blocks shows a flat distribution close to 1x.
    // Empirically (5 local runs) this ratio lands in the 10^5-10^6 range
    // -- comfortably clear of the 10x threshold even under heavy CI load.
    let mut sorted_write_times = write_times;
    sorted_write_times.sort();
    let median = sorted_write_times[sorted_write_times.len() / 2];
    let max = *sorted_write_times
        .last()
        .expect("sent > 0 implies at least one write time");
    assert!(
        max > median * 10,
        "expected at least one write() to take >10x the median (backpressure reaching the \
socket), got median={median:?} max={max:?} over {} writes",
        sorted_write_times.len()
    );
}
