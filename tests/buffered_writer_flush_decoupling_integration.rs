//! Integration test proving the generic buffered writer's background task
//! keeps draining its ingest channel while a previous flush's encode+upload
//! is still in flight, instead of blocking on it (the fix for a diagnosed
//! production issue: Zeek dropped records under try_send-full backpressure
//! because the writer task fully blocked on push() during a flush).
//!
//! Uses a trivial in-test `ParquetSink` (`SimpleFastSink`) rather than the
//! real `ZeekSink` -- the real Zeek "conn" schema mapping costs
//! ~500us-1.3ms per record, a legitimate cost unrelated to the
//! flush-blocking bug this test targets, which alone was enough to make a
//! rapid-fire burst outpace the single background consumer regardless of
//! the fix. A trivial sink isolates the actual property under test: the
//! generic writer's channel never overflows while a flush is in flight,
//! independent of whichever source's mapping cost. The real Zeek ingest
//! path is covered end-to-end by a separate e2e test.
//!
//! Two structural properties make this test deterministic rather than a
//! race against OS thread-scheduling latency (earlier versions of this
//! test were found to have zero discriminating power, or to depend on a
//! thread-local metrics recorder that silently misses events from the
//! background consumer task once it runs on a different OS thread -- see
//! below):
//!
//! 1. Before the burst, the test awaits a `tokio::sync::Notify` signaled
//!    directly by `SlowUploadSink::upload()` on its very first call -- so
//!    the remaining pushes are provably racing against a real in-flight
//!    flush, not hoping the timing lines up. `notify_one()` (not
//!    `notify_waiters()`) is used deliberately: it stores a permit for the
//!    next `.notified()` call even if no one is awaiting yet, so there is
//!    no missed-wakeup race regardless of which side reaches its call
//!    first. This signal crosses threads safely (it's an `Arc`-based
//!    primitive, not thread-local), unlike an earlier version of this test
//!    that tried to poll the `parquet_s3_flushes_in_flight` gauge via a
//!    `metrics::set_default_local_recorder` guard -- that recorder is
//!    THREAD-LOCAL, and on this test's `multi_thread` runtime the
//!    background consumer task (which emits the gauge) is scheduled onto a
//!    different OS thread than the one that installed the recorder, so its
//!    metric calls were silently invisible to the snapshot. The final
//!    `parquet_s3_dropped` assertion is a secondary check -- the
//!    `assert_eq!(send_errors, 0)` assertion above it is the primary,
//!    recorder-independent proof and would already have caught any real
//!    regression; even if the metrics snapshot were to miss an increment
//!    due to a thread migration, it would only read back the
//!    already-expected value of 0, so this check can't mask a failure.
//! 2. Each push in the burst is followed by a real (if tiny)
//!    `tokio::time::sleep`, not a bare cooperative `yield_now()` -- a
//!    sleep actually parks the task and hands real wall-clock time to the
//!    runtime's scheduler, giving the consumer thread a genuine
//!    opportunity to run, unlike a same-instant cooperative yield (a bare
//!    `yield_now()` between sends was found in an earlier version of this
//!    test to have zero discriminating power between buggy and fixed code
//!    at any channel capacity, since the consumer was never guaranteed to
//!    actually be scheduled during the burst either way).
//!
//! No external dependency required.

use logthing::forwarding::buffered_writer::{
    BufferedWriterConfig, FlushPolicy, LiveInterval, ParquetSink, ParquetWriterHandle, UploadSink,
};
use logthing::stats::SourceHourlyStats;
use std::sync::Arc;
use std::time::Duration;

struct SlowUploadSink {
    delay: Duration,
    /// Signaled (`notify_one`) the moment the first upload call starts, so
    /// the test can deterministically confirm a flush is genuinely in
    /// flight before sending the rest of its burst.
    started: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl UploadSink for SlowUploadSink {
    async fn upload(&self, _key: &str, _body: Vec<u8>) -> anyhow::Result<()> {
        self.started.notify_one();
        tokio::time::sleep(self.delay).await;
        Ok(())
    }
    fn target_label(&self) -> &'static str {
        "slow"
    }
    fn location_hint(&self) -> String {
        "slow://test".to_string()
    }
}

/// Trivial `ParquetSink` -- near-zero `to_record_batch` cost, so the only
/// thing that can make the consumer fall behind is the property under
/// test (flush blocking), not an unrelated per-record mapping cost.
/// `source()` still reports "zeek" so metric labels read as the diagnosed
/// production scenario.
struct SimpleFastSink;
impl ParquetSink for SimpleFastSink {
    type Record = String;
    fn source(&self) -> &'static str {
        "zeek"
    }
    fn partition(&self, _record: &String) -> Option<String> {
        Some("conn".to_string())
    }
    fn schema(&self, _partition: Option<&str>) -> Arc<arrow_schema::Schema> {
        Arc::new(arrow_schema::Schema::new(vec![arrow_schema::Field::new(
            "val",
            arrow_schema::DataType::Utf8,
            false,
        )]))
    }
    fn to_record_batch(
        &self,
        record: &String,
        schema: &Arc<arrow_schema::Schema>,
    ) -> anyhow::Result<arrow_array::RecordBatch> {
        let col = Arc::new(arrow_array::StringArray::from(vec![record.as_str()]));
        Ok(arrow_array::RecordBatch::try_new(
            schema.clone(),
            vec![col],
        )?)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn records_pushed_during_a_slow_flush_are_not_dropped_at_the_channel() {
    use metrics::set_default_local_recorder;
    use metrics_util::CompositeKey;
    use metrics_util::MetricKind;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let _guard = set_default_local_recorder(&recorder);

    let flush_started = Arc::new(tokio::sync::Notify::new());
    let cfg = BufferedWriterConfig {
        connection: logthing::config::S3ConnectionConfig {
            endpoint: String::new(),
            bucket: String::new(),
            region: String::new(),
            access_key: String::new(),
            secret_key: String::new(),
        },
        prefix: "zeek".to_string(),
        max_buffer_rows: 1, // flush on every single push
        flush_threshold_bytes: usize::MAX,
        flush_interval_secs: 3600,
        channel_capacity: 4, // deliberately small -- the old, buggy code would overflow this
        max_partitions: 8,
    };
    let policy = FlushPolicy {
        max_rows: 1,
        max_bytes: usize::MAX,
        interval: LiveInterval::new(Duration::from_secs(3600)),
    };
    let slow_sink: Arc<dyn UploadSink> = Arc::new(SlowUploadSink {
        delay: Duration::from_millis(200),
        started: flush_started.clone(),
    });

    let (handler, _join_handle) = ParquetWriterHandle::<SimpleFastSink>::start_with_stats(
        SimpleFastSink,
        slow_sink,
        cfg,
        policy,
        Arc::new(SourceHourlyStats::new()),
        None,
    );

    // Push the first record -- with max_buffer_rows == 1, this alone
    // triggers the first (slow, 200ms) flush.
    handler
        .try_send("record-0".to_string())
        .expect("first try_send must succeed on a fresh, empty channel");

    // Deterministically wait until that flush has genuinely started
    // uploading (bounded to 2s -- generous margin against CI slowness;
    // the real expected wait is microseconds since encode_and_upload only
    // does a cheap encode before calling upload()).
    tokio::time::timeout(Duration::from_secs(2), flush_started.notified())
        .await
        .expect("the first push's flush must have started within the timeout");

    // Now push the remaining records while we know a slow flush is
    // genuinely in flight -- each send is followed by a real (if tiny)
    // sleep, not a bare cooperative yield, so the consumer thread
    // genuinely gets wall-clock opportunities to drain during the burst.
    let mut send_errors = 0usize;
    for i in 1..40 {
        if handler.try_send(format!("record-{i}")).is_err() {
            send_errors += 1;
        }
        tokio::time::sleep(Duration::from_micros(200)).await;
    }

    // Give the background task time to finish processing everything pushed above.
    tokio::time::sleep(Duration::from_millis(1000)).await;

    assert_eq!(
        send_errors, 0,
        "no try_send should fail at the channel level while a flush is in flight"
    );

    // Safe to check via the thread-local recorder: parquet_s3_dropped is
    // incremented inside `try_send`, called directly on this test's own
    // thread above -- unlike the flushes-in-flight gauge (emitted by the
    // background consumer task on a different OS thread), this counter
    // was always visible to the recorder installed here.
    let dropped_key = CompositeKey::new(
        MetricKind::Counter,
        metrics::Key::from_parts(
            "parquet_s3_dropped",
            vec![
                metrics::Label::new("source", "zeek"),
                metrics::Label::new("target", "slow"),
            ],
        ),
    );
    let dropped = snapshotter
        .snapshot()
        .into_hashmap()
        .get(&dropped_key)
        .map(|(_, _, v)| {
            if let DebugValue::Counter(c) = v {
                *c
            } else {
                0
            }
        })
        .unwrap_or(0);
    assert_eq!(
        dropped, 0,
        "parquet_s3_dropped must stay at 0 -- the channel must never report Full while a flush is in flight"
    );
}

struct PanicUploadSink;
#[async_trait::async_trait]
impl UploadSink for PanicUploadSink {
    async fn upload(&self, _key: &str, _body: Vec<u8>) -> anyhow::Result<()> {
        panic!("intentional test panic to exercise flush-task panic handling")
    }
    fn target_label(&self) -> &'static str {
        "panicky"
    }
    fn location_hint(&self) -> String {
        "panic://test".to_string()
    }
}

#[derive(Default, Clone, Debug)]
struct CapturedEvent {
    message: String,
    fields: std::collections::HashMap<String, String>,
}

struct FieldVisitor(CapturedEvent);
impl tracing::field::Visit for FieldVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let s = format!("{value:?}").trim_matches('"').to_string();
        if field.name() == "message" {
            self.0.message = s;
        } else {
            self.0.fields.insert(field.name().to_string(), s);
        }
    }
}

struct CaptureLayer {
    events: Arc<std::sync::Mutex<Vec<CapturedEvent>>>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = FieldVisitor(CapturedEvent::default());
        event.record(&mut visitor);
        self.events.lock().unwrap().push(visitor.0);
    }
}

/// Line 1067: a flush task panics while the writer's background task is
/// still in its steady-state select! loop (not shutdown) -- the panic must
/// surface via the outer `Some(result) = writer.flush_tasks.join_next()`
/// branch with `source`/`target` fields attached. Uses default
/// (current-thread) `#[tokio::test]` flavor so the background task's
/// tracing events land on the same thread this test's subscriber guard
/// installs on -- see this file's own top-of-file doc comment for why a
/// multi_thread flavor would silently miss them.
#[tokio::test]
async fn flush_task_panic_during_steady_state_logs_source_and_target() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let layer = CaptureLayer {
        events: events.clone(),
    };
    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let cfg = BufferedWriterConfig {
        connection: logthing::config::S3ConnectionConfig {
            endpoint: String::new(),
            bucket: String::new(),
            region: String::new(),
            access_key: String::new(),
            secret_key: String::new(),
        },
        prefix: "zeek".to_string(),
        max_buffer_rows: 1, // flush on every push
        flush_threshold_bytes: usize::MAX,
        flush_interval_secs: 3600,
        channel_capacity: 4,
        max_partitions: 8,
    };
    let policy = FlushPolicy {
        max_rows: 1,
        max_bytes: usize::MAX,
        interval: LiveInterval::new(Duration::from_secs(3600)),
    };
    let panic_sink: Arc<dyn UploadSink> = Arc::new(PanicUploadSink);

    let (handler, _join_handle) = ParquetWriterHandle::<SimpleFastSink>::start_with_stats(
        SimpleFastSink,
        panic_sink,
        cfg,
        policy,
        Arc::new(SourceHourlyStats::new()),
        None,
    );

    handler
        .try_send("record-0".to_string())
        .expect("first try_send must succeed on a fresh, empty channel");

    // Poll (bounded) for the panic-handling warning to appear, rather than
    // a fixed sleep -- the flush task's panic is asynchronous.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut found = false;
    while tokio::time::Instant::now() < deadline {
        let snapshot = events.lock().unwrap().clone();
        found = snapshot.iter().any(|e| {
            e.message.contains("flush task panicked")
                && e.fields.get("source").map(String::as_str) == Some("zeek")
                && e.fields.get("target").map(String::as_str) == Some("panicky")
        });
        if found {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        found,
        "expected a warn event with source=\"zeek\" target=\"panicky\" for the steady-state flush-task panic, got: {:?}",
        events.lock().unwrap()
    );
}
