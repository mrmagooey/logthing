//! Integration coverage for bounded-wait ingest sends (spec §3).
//!
//! Construction pattern follows `tests/zeek_local_integration.rs`: a real
//! `tempfile::TempDir`, `ZeekLocalConfig`, `zeek_local_start`, and
//! `LocalDiskSink` — no external services required.

use logthing::forwarding::buffered_writer::ParquetWriterHandle;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::zeek_s3::{MultiZeekHandler, ZeekSink, zeek_local_start};
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

/// Read `parquet_s3_dropped{source="zeek",target=<target>}` from a
/// `metrics_util::debugging::Snapshotter`.
#[allow(clippy::mutable_key_type)]
fn dropped_count(snapshotter: &metrics_util::debugging::Snapshotter, target: &'static str) -> u64 {
    use metrics_util::CompositeKey;
    use metrics_util::MetricKind;
    use metrics_util::debugging::DebugValue;

    let key = CompositeKey::new(
        MetricKind::Counter,
        metrics::Key::from_parts(
            "parquet_s3_dropped",
            vec![
                metrics::Label::new("source", "zeek"),
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
        dropped_count(&snapshotter, "local"),
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
        dropped_count(&snapshotter, "s3") >= 1,
        "a channel that never drains must eventually drop"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "20 sends at a 50ms timeout must finish well under 5s if the *short* \
         timeout was honoured rather than SEND_TIMEOUT_DEFAULT; took {elapsed:?}"
    );
}

/// A stalled destination must not serialise a healthy one behind it: with
/// concurrent fan-out (Task 5), the whole batch should take roughly as long
/// as the *slower* handler alone (bounded by max), not the sum of both
/// handlers (bounded by sum). Both handlers here sleep 200ms per record --
/// if only one handler carried latency, sequential and concurrent fan-out
/// would take the same total time regardless of which strategy is used,
/// making the assertion vacuous; two comparably slow handlers are required
/// to actually distinguish "sum" (400ms/record) from "max" (200ms/record).
/// `MultiZeekHandler` today (`src/forwarding/zeek_s3.rs:196-198`) fans out
/// sequentially -- `for handler in &self.0 { handler.handle_record(...).await }`
/// -- so this assertion is expected to FAIL until Task 5 changes that loop
/// to a concurrent `join_all`. Left failing deliberately; see the task-4
/// report.
#[tokio::test]
async fn fan_out_does_not_serialise_a_healthy_destination_behind_a_stalled_one() {
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

/// A channel sized by the real 100 MiB budget (`capacity_for(ZEEK_RECORD_BYTES)`,
/// ~102,400 records) must still drain AND flush inside the 10s deadline
/// `src/main.rs` gives every writer task during shutdown, even when filled
/// well past any small-channel test size. Uses a fast local-disk sink;
/// nothing here depends on the sink being slow.
#[tokio::test]
async fn budget_full_channel_completes_shutdown_within_the_deadline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    let capacity = logthing::forwarding::channel_budget::capacity_for(
        logthing::forwarding::channel_budget::ZEEK_RECORD_BYTES,
    );
    const N: usize = 20_000;
    assert!(
        capacity >= N,
        "this test assumes the budgeted capacity ({capacity}) comfortably exceeds N ({N})"
    );
    // High thresholds so nothing flushes mid-burst; the only flush is the
    // shutdown `flush_all`, which must still complete inside the deadline
    // even with N rows all buffered in memory at once.
    let cfg = logthing::config::ZeekLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "zeek".to_string(),
        max_buffer_rows: N * 2,
        flush_threshold_bytes: 1_000_000_000,
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
    for i in 0..N {
        handler
            .handle_record(make_conn_record(&format!("CBudget{i:05}")), src)
            .await;
    }

    drop(handler);
    let deadline = Duration::from_secs(10);
    tokio::time::timeout(deadline, writer_task)
        .await
        .unwrap_or_else(|_| {
            panic!("writer task must join within the {deadline:?} shutdown deadline")
        })
        .expect("writer task must not panic");

    let conn_dir = dir.path().join("zeek/conn");
    assert_eq!(
        count_parquet_rows(&conn_dir),
        N,
        "all {N} rows must have reached Parquet before the writer task joined"
    );
}
