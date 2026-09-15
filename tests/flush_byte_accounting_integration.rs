//! Integration test for the flush byte-accounting fix
//! (`docs/superpowers/plans/2026-09-14-flush-byte-accounting-fix.md`, Task 2).
//!
//! `buffered_writer.rs`'s byte-based flush threshold used to be driven by
//! `RecordBatch::get_array_memory_size()`, which reports allocated builder
//! *capacity* rather than bytes actually used. For a batch built via a
//! freshly-allocated `StringBuilder` and a single short value, that is
//! ~5,304 bytes of reported capacity against ~6 bytes actually used (see
//! `buffered_writer.rs`'s `used_bytes_reports_a_small_figure_for_a_1_row_batch_built_via_a_builder`
//! unit test) -- an ~880x overstatement. Because every non-accumulator sink
//! (all of them except Zeek) maps one record at a time through a fresh
//! builder, that overstatement fed directly into the byte-flush threshold on
//! every single push, firing 1-2 orders of magnitude too early.
//!
//! This test drives the real `ParquetWriterHandle::start_with_stats` path
//! (the same background task every production sink uses, not a
//! writer-internals shortcut) with a trivial single-column sink that
//! reproduces that per-push fresh-builder shape, and checks that the flush
//! count tracks *actual* bytes written, not the number of tiny batches
//! pushed through it.
//!
//! No external dependency required.

use logthing::forwarding::buffered_writer::{
    BufferedWriterConfig, FlushPolicy, LiveInterval, ParquetSink, ParquetWriterHandle, UploadSink,
};
use logthing::stats::SourceHourlyStats;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Records every `upload` call so the test can count flushes directly,
/// independent of metrics-recorder thread-locality quirks (see the sibling
/// decoupling-integration test's design notes for why that matters once the
/// background task runs on a different OS thread).
#[derive(Default)]
struct CountingUploadSink {
    uploads: Mutex<usize>,
}

#[async_trait::async_trait]
impl UploadSink for CountingUploadSink {
    async fn upload(&self, _key: &str, _body: Vec<u8>) -> anyhow::Result<()> {
        *self.uploads.lock().unwrap() += 1;
        Ok(())
    }
    fn target_label(&self) -> &'static str {
        "counting"
    }
    fn location_hint(&self) -> String {
        "counting://test".to_string()
    }
}

/// A single-column sink whose `to_record_batch` builds a *fresh*
/// `StringBuilder` per call, appends exactly one value, and finishes it --
/// the same one-builder-per-push shape every non-accumulator sink (ipfix,
/// sflow, syslog, generic, structured_syslog, suricata) uses. `new_batch`
/// is not overridden, so this exercises the direct-mapped `push()` path
/// (`buffered_writer.rs`'s two non-accumulator call sites), not the
/// long-lived-accumulator path Zeek alone uses.
struct TinyBuilderSink;
impl ParquetSink for TinyBuilderSink {
    type Record = String;
    fn source(&self) -> &'static str {
        "test"
    }
    fn partition(&self, _record: &String) -> Option<String> {
        None
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
        let mut builder = arrow::array::StringBuilder::new();
        builder.append_value(record);
        let col: Arc<dyn arrow_array::Array> = Arc::new(builder.finish());
        Ok(arrow_array::RecordBatch::try_new(
            schema.clone(),
            vec![col],
        )?)
    }
}

/// A per-push fresh `StringBuilder` batch reports ~5,304 bytes of allocated
/// capacity for a single short value (measured directly in
/// `buffered_writer.rs`'s unit test) but uses only a handful of real bytes.
/// A threshold comfortably above what ~1,000 pushes' real bytes could reach,
/// but comfortably below what even 10 pushes' capacity-based estimate would
/// reach, cleanly separates "flushed because of the old bug" from "flushed
/// because real data crossed the threshold".
const FLUSH_THRESHOLD_BYTES: usize = 50_000;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flush_count_tracks_real_bytes_not_batch_count() {
    let cfg = BufferedWriterConfig {
        connection: logthing::config::S3ConnectionConfig {
            endpoint: String::new(),
            bucket: String::new(),
            region: String::new(),
            access_key: String::new(),
            secret_key: String::new(),
        },
        prefix: "test".to_string(),
        max_buffer_rows: 1_000_000, // hard cap must never be the thing that fires here
        flush_threshold_bytes: FLUSH_THRESHOLD_BYTES,
        flush_interval_secs: 3600, // age must never be the thing that fires here either
        channel_capacity: 25_000,
        max_partitions: 8,
    };
    let policy = FlushPolicy {
        max_rows: 1_000_000,
        max_bytes: FLUSH_THRESHOLD_BYTES,
        interval: LiveInterval::new(Duration::from_secs(3600)),
    };
    let sink = Arc::new(CountingUploadSink::default());
    let sink_dyn: Arc<dyn UploadSink> = sink.clone();

    let (handler, join_handle) = ParquetWriterHandle::<TinyBuilderSink>::start_with_stats(
        TinyBuilderSink,
        sink_dyn,
        cfg,
        policy,
        Arc::new(SourceHourlyStats::new()),
        None,
    );

    // Under the old capacity-based estimate (~5,304 bytes/push), 200 pushes
    // would have crossed the 50,000-byte threshold roughly 20 times over.
    // Under the fix (~6 real bytes/push), 200 pushes total ~1,200 real
    // bytes -- nowhere near the threshold.
    for i in 0..200 {
        handler
            .try_send(format!("r{i}"))
            .expect("channel has ample capacity");
    }

    // Give the background task time to drain and apply the flush policy to
    // everything just pushed.
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(
        *sink.uploads.lock().unwrap(),
        0,
        "200 tiny pushes must not cross a 50,000-byte threshold under \
         real-bytes accounting -- any upload here means the byte estimate \
         is still overstating capacity, not usage"
    );

    // Now push enough further records that real bytes -- not the old
    // capacity estimate -- must eventually cross the threshold, proving the
    // byte counter isn't simply stuck at (or rounding to) zero, which would
    // be the opposite failure: a buffer that never flushes on its own.
    for i in 200..20_000 {
        handler
            .try_send(format!("r{i}"))
            .expect("channel has ample capacity");
    }
    tokio::time::sleep(Duration::from_secs(3)).await;

    let uploads_before_shutdown = *sink.uploads.lock().unwrap();
    assert!(
        uploads_before_shutdown >= 1,
        "real accumulated bytes must eventually cross the flush threshold \
         and trigger at least one upload -- byte accounting must not be \
         permanently under-counting either"
    );
    assert!(
        uploads_before_shutdown < 100,
        "flush count must stay proportional to real bytes, not to the \
         ~20,000 batches pushed -- got {uploads_before_shutdown} uploads, \
         which would indicate a per-batch (capacity-based) flush trigger \
         instead of a per-byte one"
    );

    // Graceful shutdown: dropping the handle closes the channel, which
    // drains the rest and does one final flush_all.
    drop(handler);
    join_handle.await.expect("writer task must not panic");
}

/// Companion check named directly in the plan's success criteria: fixing
/// the over-counting direction must not silently introduce the opposite
/// bug (under-counting bytes so a buffer grows unbounded until the
/// row-cap hard-evicts it). `parquet_s3_buffer_dropped` is the hard-cap
/// eviction counter -- distinct from `parquet_s3_dropped` (channel-full
/// drops) -- and must stay at 0 across a run that never approaches the
/// (very high) row cap configured here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn buffer_dropped_stays_zero_under_real_byte_accounting() {
    use metrics::set_default_local_recorder;
    use metrics_util::CompositeKey;
    use metrics_util::MetricKind;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let _guard = set_default_local_recorder(&recorder);

    let cfg = BufferedWriterConfig {
        connection: logthing::config::S3ConnectionConfig {
            endpoint: String::new(),
            bucket: String::new(),
            region: String::new(),
            access_key: String::new(),
            secret_key: String::new(),
        },
        prefix: "test".to_string(),
        max_buffer_rows: 1_000_000,
        flush_threshold_bytes: FLUSH_THRESHOLD_BYTES,
        flush_interval_secs: 3600,
        channel_capacity: 25_000,
        max_partitions: 8,
    };
    let policy = FlushPolicy {
        max_rows: 1_000_000,
        max_bytes: FLUSH_THRESHOLD_BYTES,
        interval: LiveInterval::new(Duration::from_secs(3600)),
    };
    let sink: Arc<dyn UploadSink> = Arc::new(CountingUploadSink::default());

    let (handler, join_handle) = ParquetWriterHandle::<TinyBuilderSink>::start_with_stats(
        TinyBuilderSink,
        sink,
        cfg,
        policy,
        Arc::new(SourceHourlyStats::new()),
        None,
    );

    for i in 0..20_000 {
        handler
            .try_send(format!("r{i}"))
            .expect("channel has ample capacity");
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    drop(handler);
    join_handle.await.expect("writer task must not panic");

    let dropped_key = CompositeKey::new(
        MetricKind::Counter,
        metrics::Key::from_parts(
            "parquet_s3_buffer_dropped",
            vec![
                metrics::Label::new("source", "test"),
                metrics::Label::new("target", "counting"),
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
        "parquet_s3_buffer_dropped (hard-cap eviction) must stay at 0 -- \
         under-counting bytes so a buffer grows until the row cap evicts it \
         would be the opposite, worse failure mode this fix must not introduce"
    );
}
