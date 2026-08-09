//! Integration coverage for bounded-wait ingest sends (spec §3).
//!
//! Construction pattern follows `tests/zeek_local_integration.rs`: a real
//! `tempfile::TempDir`, `ZeekLocalConfig`, `zeek_local_start`, and
//! `LocalDiskSink` — no external services required.

use logthing::forwarding::buffered_writer::ParquetWriterHandle;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::suricata_s3::suricata_local_start;
use logthing::forwarding::zeek_s3::{MultiZeekHandler, ZeekSink, zeek_local_start};
use logthing::suricata::SuricataRecord;
use logthing::suricata::listener::SuricataHandler;
use logthing::zeek::ZeekRecord;
use logthing::zeek::listener::ZeekHandler;
use std::sync::Arc;
use std::time::Duration;

fn make_conn_record(uid: &str) -> ZeekRecord {
    ZeekRecord {
        log_path: "conn".to_string(),
        fields: serde_json::json!({
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
        }),
        received_at: chrono::Utc::now(),
    }
}

fn make_alert_record(src_ip: &str) -> SuricataRecord {
    SuricataRecord {
        event_type: "alert".to_string(),
        fields: serde_json::json!({
            "event_type": "alert",
            "src_ip": src_ip,
            "dest_ip": "1.2.3.4",
            "alert": {"signature": "ET TEST"}
        }),
        received_at: chrono::Utc::now(),
    }
}

/// Read `parquet_s3_dropped{source=<source>,target=<target>}` from a
/// `metrics_util::debugging::Snapshotter`.
#[allow(clippy::mutable_key_type)]
fn dropped_count(
    snapshotter: &metrics_util::debugging::Snapshotter,
    source: &'static str,
    target: &'static str,
) -> u64 {
    use metrics_util::CompositeKey;
    use metrics_util::MetricKind;
    use metrics_util::debugging::DebugValue;

    let key = CompositeKey::new(
        MetricKind::Counter,
        metrics::Key::from_parts(
            "parquet_s3_dropped",
            vec![
                metrics::Label::new("source", source),
                metrics::Label::new("target", target),
            ],
        ),
    );
    snapshotter
        .snapshot()
        .into_hashmap()
        .get(&key)
        .map(|(_, _, v)| {
            if let DebugValue::Counter(c) = v {
                *c
            } else {
                0
            }
        })
        .unwrap_or(0)
}

/// Count total rows across every Parquet file under `dir`.
fn count_parquet_rows(dir: &std::path::Path) -> usize {
    let mut stack = vec![dir.to_path_buf()];
    let mut total = 0usize;
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "parquet") {
                let bytes = std::fs::read(&path).expect("read parquet file");
                use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
                let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
                    .expect("parquet builder");
                let reader = builder.build().expect("parquet reader");
                for rb in reader {
                    total += rb.expect("batch ok").num_rows();
                }
            }
        }
    }
    total
}

/// A send that cannot fit immediately must WAIT for the writer to drain and
/// then succeed — not drop. This is the whole point of the change: with the
/// pre-change `try_send`, a burst larger than `channel_capacity` drops every
/// record past the first `channel_capacity`; with `send_or_drop`, the sender
/// instead blocks until the writer frees capacity, so nothing is lost.
#[tokio::test]
async fn full_channel_blocks_then_succeeds_once_the_writer_drains() {
    use metrics::set_default_local_recorder;
    use metrics_util::debugging::DebuggingRecorder;

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let _guard = set_default_local_recorder(&recorder);

    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    // Deliberately tiny channel (4) so the very first burst of 200 exceeds
    // it many times over; a real, fast local-disk sink so the writer
    // genuinely drains rather than stalling.
    let cfg = logthing::config::ZeekLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "zeek".to_string(),
        max_buffer_rows: 100_000,
        flush_threshold_bytes: 100_000_000,
        flush_interval_secs: 3600,
        channel_capacity: 4,
    };
    let (handler, writer_task) = zeek_local_start(
        &cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );

    let src: std::net::SocketAddr = "127.0.0.1:47760".parse().unwrap();
    const N: usize = 200;
    let start = std::time::Instant::now();
    for i in 0..N {
        handler
            .handle_record(make_conn_record(&format!("CBlock{i:04}")), src)
            .await;
    }
    let elapsed = start.elapsed();

    // Every record was accepted -- zero drops -- and the whole burst
    // completed well under the send timeout, proving it waited for the
    // writer to drain rather than dropping.
    assert_eq!(
        dropped_count(&snapshotter, "zeek", "local"),
        0,
        "no record should be dropped: send_or_drop must wait for capacity, not give up"
    );
    assert!(
        elapsed < logthing::forwarding::buffered_writer::SEND_TIMEOUT_DEFAULT,
        "200 records into a real, fast local sink should drain well under the send timeout; took {elapsed:?}"
    );

    drop(handler);
    tokio::time::timeout(Duration::from_secs(10), writer_task)
        .await
        .expect("writer task exits within 10s")
        .expect("writer task must not panic");

    let conn_dir = dir.path().join("zeek/conn");
    assert_eq!(
        count_parquet_rows(&conn_dir),
        N,
        "all {N} rows must have reached Parquet"
    );
}

/// Suricata half of the same proof as `full_channel_blocks_then_succeeds_once_the_writer_drains`.
/// Without this, `src/forwarding/suricata_s3.rs:110`'s `send_or_drop` has no
/// mutation-killing coverage: reverting it to `try_send` still passes every
/// other Suricata test (`handler_overflow_increments_dropped_counter`
/// increments the same counter on overflow either way), so a future
/// regression back to record-destroying `try_send` would go unnoticed.
#[tokio::test]
async fn suricata_full_channel_blocks_then_succeeds_once_the_writer_drains() {
    use metrics::set_default_local_recorder;
    use metrics_util::debugging::DebuggingRecorder;

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let _guard = set_default_local_recorder(&recorder);

    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    let cfg = logthing::config::SuricataLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "suricata".to_string(),
        max_buffer_rows: 100_000,
        flush_threshold_bytes: 100_000_000,
        flush_interval_secs: 3600,
        channel_capacity: 4,
    };
    let (handler, writer_task) = suricata_local_start(
        &cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );

    let src: std::net::SocketAddr = "127.0.0.1:47761".parse().unwrap();
    const N: usize = 200;
    for i in 0..N {
        handler
            .handle_record(
                make_alert_record(&format!("10.0.{}.{}", i / 256, i % 256)),
                src,
            )
            .await;
    }

    assert_eq!(
        dropped_count(&snapshotter, "suricata", "local"),
        0,
        "no record should be dropped: send_or_drop must wait for capacity, not give up"
    );

    drop(handler);
    tokio::time::timeout(Duration::from_secs(10), writer_task)
        .await
        .expect("writer task exits within 10s")
        .expect("writer task must not panic");

    let alert_dir = dir.path().join("suricata/alert");
    assert_eq!(
        count_parquet_rows(&alert_dir),
        N,
        "all {N} rows must have reached Parquet"
    );
}

/// A handle whose writer never drains must still respect the *short*,
/// per-handle timeout (not `SEND_TIMEOUT_DEFAULT`) and drop rather than
/// hang forever. Built directly around `ParquetWriterHandle::for_test`
/// (mirroring `buffered_writer.rs`'s own
/// `send_or_drop_times_out_and_reports_full_when_the_writer_never_drains`):
/// a capacity-1 channel whose receiver is held but never polled, so the
/// channel genuinely never drains. Going through a real `zeek_start`/
/// `zeek_local_start` writer task cannot produce this condition — that
/// writer's `push()` never awaits the actual upload (flushes are spawned
/// and decoupled from the channel-draining loop), so it drains a healthy
/// channel in microseconds regardless of how broken the sink is; a
/// capacity-1 channel wired to an "unreachable" S3 endpoint never actually
/// stays full long enough to time out (confirmed empirically while fixing
/// the equivalent unit tests in `zeek_s3.rs`/`suricata_s3.rs` for this same
/// task). `ParquetWriterHandle::for_test` is the same test seam those unit
/// tests use, re-exported here because it is the only way to hold a
/// channel genuinely full without a live writer task to race against.
#[tokio::test]
async fn wedged_writer_drops_after_the_timeout() {
    use metrics::set_default_local_recorder;
    use metrics_util::debugging::DebuggingRecorder;

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let _guard = set_default_local_recorder(&recorder);

    let (tx, _rx) = tokio::sync::mpsc::channel::<ZeekRecord>(1);
    tx.try_send(make_conn_record("Cfirst")).unwrap();
    let handler = ParquetWriterHandle::<ZeekSink>::for_test(tx, "zeek", "s3")
        .with_send_timeout(Duration::from_millis(50));

    let src: std::net::SocketAddr = "127.0.0.1:47760".parse().unwrap();
    let start = std::time::Instant::now();
    for i in 0..20usize {
        handler
            .handle_record(make_conn_record(&format!("CWedge{i:02}")), src)
            .await;
    }
    let elapsed = start.elapsed();

    assert!(
        dropped_count(&snapshotter, "zeek", "s3") >= 1,
        "a channel that never drains must eventually drop"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "20 sends at a 50ms timeout must finish well under 5s if the *short* \
         timeout was honoured rather than SEND_TIMEOUT_DEFAULT; took {elapsed:?}"
    );
}

/// Fan-out latency should be `max()` across destinations, not `sum()`: with
/// concurrent fan-out (Task 5), the whole batch should take roughly as long
/// as one handler alone, not both back to back. Both handlers here sleep
/// 200ms per record -- if only one carried latency, sequential and
/// concurrent fan-out would take the same total time regardless of which
/// strategy is used, making the assertion vacuous; two comparably slow
/// handlers are required to actually distinguish "sum" (400ms/record) from
/// "max" (200ms/record). `MultiZeekHandler` now fans out with
/// `futures::future::join_all`, so this passes; reverting it to the previous
/// sequential `for handler in &self.0 { handler.handle_record(...).await }`
/// is exactly the regression this test exists to catch.
#[tokio::test]
async fn fan_out_latency_should_be_max_not_sum_across_destinations() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct SlowHandler(Duration);
    #[async_trait::async_trait]
    impl ZeekHandler for SlowHandler {
        async fn handle_record(&self, _record: ZeekRecord, _source: std::net::SocketAddr) {
            tokio::time::sleep(self.0).await;
        }
    }

    struct SlowCountingHandler(Duration, Arc<AtomicUsize>);
    #[async_trait::async_trait]
    impl ZeekHandler for SlowCountingHandler {
        async fn handle_record(&self, _record: ZeekRecord, _source: std::net::SocketAddr) {
            tokio::time::sleep(self.0).await;
            self.1.fetch_add(1, Ordering::SeqCst);
        }
    }

    let per_record_delay = Duration::from_millis(200);
    let count = Arc::new(AtomicUsize::new(0));
    let multi = MultiZeekHandler(vec![
        Arc::new(SlowHandler(per_record_delay)),
        Arc::new(SlowCountingHandler(per_record_delay, count.clone())),
    ]);

    let src: std::net::SocketAddr = "127.0.0.1:47760".parse().unwrap();
    const N: usize = 5;
    let start = std::time::Instant::now();
    for i in 0..N {
        multi
            .handle_record(make_conn_record(&format!("CFan{i}")), src)
            .await;
    }
    let elapsed = start.elapsed();

    assert_eq!(
        count.load(Ordering::SeqCst),
        N,
        "the counting handler must see every record regardless of fan-out strategy"
    );

    let concurrent_bound = per_record_delay * (N as u32); // ~5 * 200ms (max per record)
    let serial_bound = per_record_delay * 2 * (N as u32); // ~5 * 400ms (sum per record)
    let midpoint = (concurrent_bound + serial_bound) / 2;
    assert!(
        elapsed < midpoint,
        "expected elapsed ({elapsed:?}) closer to the concurrent bound ({concurrent_bound:?}) \
         than the serial bound ({serial_bound:?}) -- this requires Task 5's concurrent fan-out"
    );
}

/// Counts `set` calls per gauge name. A `DebuggingRecorder` snapshot shows the
/// current *value*, which cannot distinguish "set once at startup" from "set
/// every second" — and `tokio::time::interval`'s first tick fires immediately,
/// so even a 900-second ticker publishes a value at t=0. Update *rate* is the
/// thing under test, so it has to be counted directly.
#[derive(Default)]
struct GaugeSetCounter(
    std::sync::Mutex<std::collections::HashMap<String, Arc<std::sync::atomic::AtomicUsize>>>,
);

impl GaugeSetCounter {
    fn slot(&self, name: &str) -> Arc<std::sync::atomic::AtomicUsize> {
        self.0
            .lock()
            .unwrap()
            .entry(name.to_string())
            .or_default()
            .clone()
    }

    fn count(&self, name: &str) -> usize {
        self.slot(name).load(std::sync::atomic::Ordering::SeqCst)
    }
}

struct CountingGauge(Arc<std::sync::atomic::AtomicUsize>);

impl metrics::GaugeFn for CountingGauge {
    fn increment(&self, _value: f64) {}
    fn decrement(&self, _value: f64) {}
    fn set(&self, _value: f64) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl metrics::Recorder for GaugeSetCounter {
    fn describe_counter(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }
    fn describe_gauge(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }
    fn describe_histogram(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }
    fn register_counter(&self, _: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Counter {
        metrics::Counter::noop()
    }
    fn register_gauge(&self, key: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
        metrics::Gauge::from_arc(Arc::new(CountingGauge(self.slot(key.name()))))
    }
    fn register_histogram(
        &self,
        _: &metrics::Key,
        _: &metrics::Metadata<'_>,
    ) -> metrics::Histogram {
        metrics::Histogram::noop()
    }
}

/// The queue-depth gauges must refresh on their own short cadence, NOT on the
/// writer's flush ticker. They used to ride on `ticker`, whose period is
/// `flush_check_interval(flush_interval)` — 900s at every source's default
/// `flush_interval_secs`, which is exactly the config used here. A gauge the
/// spec tells operators to alert on cannot update once every 15 minutes.
///
/// Regression shape: under the old code each channel gauge is set exactly
/// once (the immediate first tick) and then not again for 900 seconds, so the
/// counts below stay at 1 while `parquet_s3_buffer_rows` — still on the flush
/// ticker, deliberately — also stays at 1. That asymmetry is the assertion.
#[tokio::test]
async fn channel_depth_gauges_refresh_despite_a_900_second_flush_interval() {
    use metrics::set_default_local_recorder;

    let recorder = GaugeSetCounter::default();
    let _guard = set_default_local_recorder(&recorder);

    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    let cfg = logthing::config::ZeekLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "zeek".to_string(),
        max_buffer_rows: 100_000,
        flush_threshold_bytes: 1_000_000_000,
        flush_interval_secs: 900, // the production default
        channel_capacity: 64,
    };
    let (handler, _writer_task) = zeek_local_start(
        &cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );

    // Long enough for the 1s gauge ticker to fire at least three times
    // (t=0, 1s, 2s), short enough to keep the suite fast.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    drop(handler);

    let available = recorder.count("parquet_s3_channel_available");
    let queued = recorder.count("parquet_s3_channel_queued");
    let buffer_rows = recorder.count("parquet_s3_buffer_rows");
    assert!(
        available >= 3 && queued >= 3,
        "channel gauges must refresh about once a second regardless of \
         flush_interval_secs=900; saw available={available}, queued={queued} \
         updates in 2.5s (1 each means they are back on the flush ticker)"
    );
    assert_eq!(
        buffer_rows, 0,
        "parquet_s3_buffer_rows stays on the flush ticker by design (it walks \
         every partition); it should not have fired in 2.5s of a 900s interval"
    );
}

/// The spec's budget gate (§5): a **budget-full** channel must still complete
/// drain and flush inside the 10s deadline `src/main.rs:619-624` gives every
/// writer task, "and if it cannot, the budget comes down".
///
/// N is therefore the derived capacity itself -- `capacity_for(ZEEK_RECORD_BYTES)`,
/// a full 100 MiB of Zeek `conn` records -- not a fraction of it. An earlier
/// version of this test used N=20,000 (~20% of capacity) and asserted
/// `capacity >= N`, which tested nothing about the budget.
///
/// One honest caveat: the channel is not held *literally* full at the moment
/// of shutdown. `ParquetWriterHandle::start` owns both ends of its channel, so
/// there is no way to hand a real writer task a pre-filled receiver, and a live
/// writer drains a healthy channel in microseconds. What is reproduced instead
/// is the condition that actually threatens the deadline: a whole budget's
/// worth of records has reached the writer, none of it has been flushed (the
/// thresholds below see to that), and all of it must be encoded and written
/// after the channel closes. The pure-CPU drain the spec bounds separately is
/// included, just spread across the push phase.
///
/// Uses a fast local-disk sink; nothing here depends on the sink being slow.
#[tokio::test]
async fn shutdown_drains_and_flushes_a_budget_full_channel_within_the_deadline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    let capacity = logthing::forwarding::channel_budget::capacity_for(
        logthing::forwarding::channel_budget::ZEEK_RECORD_BYTES,
    );
    // The gate: a full budget's worth of records, whatever that currently
    // derives to. Re-deriving the constants must re-run this test, not slip
    // past a hardcoded N.
    let n = capacity;
    // High thresholds so nothing flushes mid-burst; the only flush is the
    // shutdown `flush_all`, which must still complete inside the deadline
    // even with every row buffered in memory at once.
    let cfg = logthing::config::ZeekLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "zeek".to_string(),
        max_buffer_rows: n * 2,
        flush_threshold_bytes: 10_000_000_000,
        flush_interval_secs: 3600,
        channel_capacity: capacity,
    };
    let (handler, writer_task) = zeek_local_start(
        &cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );

    let src: std::net::SocketAddr = "127.0.0.1:47760".parse().unwrap();
    for i in 0..n {
        handler
            .handle_record(make_conn_record(&format!("CBudget{i:05}")), src)
            .await;
    }

    drop(handler);
    // Only the post-close drain+flush is timed -- that is what the 10s
    // deadline actually covers. The push phase above is the sensors' own
    // steady-state work, not part of shutdown.
    let deadline = Duration::from_secs(10);
    let start = std::time::Instant::now();
    tokio::time::timeout(deadline, writer_task)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "a budget-full channel ({n} records) must drain and flush within the \
                 {deadline:?} shutdown deadline. If this fails, CHANNEL_BUDGET_BYTES is \
                 too high for the deadline -- that is a deliberate, recorded decision, \
                 not something to fix by lowering this assertion."
            )
        })
        .expect("writer task must not panic");
    let shutdown_took = start.elapsed();

    let conn_dir = dir.path().join("zeek/conn");
    assert_eq!(
        count_parquet_rows(&conn_dir),
        n,
        "all {n} rows must have reached Parquet before the writer task joined \
         (shutdown drain+flush took {shutdown_took:?})"
    );
}
