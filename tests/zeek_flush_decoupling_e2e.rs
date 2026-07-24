//! End-to-end test: a real Zeek TCP listener, wired to the real generic
//! writer (via `ParquetWriterHandle` with the real `ZeekSink`) and an
//! artificially slow `UploadSink`, driven by a real TCP client sending real
//! NDJSON lines -- proving no records are dropped at the channel level
//! under a slow flush through the full real ingest path (socket -> parse
//! -> handler -> writer channel).
//!
//! Uses a custom slow `UploadSink` rather than a real S3/local-disk target
//! -- this repo's existing e2e tests already substitute out the actual
//! persistence backend the same way (see `tests/hec_e2e.rs`'s doc comment).
//! No external dependency (no MinIO, no real disk writes) required.
//!
//! Design notes, learned the hard way while building the companion
//! integration test (`buffered_writer_flush_decoupling_integration.rs`) --
//! read that file's doc comment for the full history. Two choices here are
//! deliberate:
//!
//! 1. **Default (current-thread) `#[tokio::test]` flavor, not
//!    `multi_thread`.** The real ZeekListener's connection handler, the
//!    writer's background task, and the spawned flush task are all
//!    separate tokio tasks regardless of how many OS threads the runtime
//!    uses -- a current-thread runtime still cooperatively interleaves them
//!    at every real `.await` point (TCP reads/writes, `tokio::time::sleep`,
//!    channel recv), which is all this property actually needs. Staying
//!    single-threaded also means every metrics call in this test -- no
//!    matter which spawned task makes it -- lands on the one thread that
//!    installs the `DebuggingRecorder`, avoiding a real, confirmed pitfall:
//!    that recorder is *thread-local*, and a `multi_thread` runtime can
//!    silently schedule a spawned task's metric calls onto a different OS
//!    thread than the one holding the recorder guard, making them invisible
//!    to the snapshot.
//! 2. **Real per-write pacing (`tokio::time::sleep`), not a bare
//!    `yield_now()`, between the TCP writes**, sized comfortably above the
//!    real `ZeekSink`'s own per-record mapping cost (empirically ~0.5-1.3ms
//!    for the "conn" schema) so the burst doesn't outpace the consumer's
//!    legitimate baseline throughput for reasons unrelated to the
//!    flush-blocking bug under test. And a `tokio::sync::Notify`, signaled
//!    directly by the slow sink's `upload()` call, is awaited before the
//!    burst begins, so the burst is provably racing a genuinely in-flight
//!    flush rather than hoping the timing lines up.

use logthing::forwarding::buffered_writer::{
    BufferedWriterConfig, FlushPolicy, LiveInterval, ParquetWriterHandle, UploadSink,
};
use logthing::forwarding::zeek_s3::ZeekSink;
use logthing::stats::SourceHourlyStats;
use logthing::zeek::listener::{ZeekListener, ZeekListenerConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

struct SlowUploadSink {
    delay: Duration,
    /// Signaled (`notify_one`) the moment the first upload call starts, so
    /// the test can deterministically confirm a flush is genuinely in
    /// flight before sending the rest of its burst. `notify_one` (not
    /// `notify_waiters`) stores a wakeup permit even if no one is awaiting
    /// yet, so there's no missed-wakeup race regardless of call order.
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

#[tokio::test]
async fn zeek_tcp_ingest_does_not_drop_records_at_the_channel_during_a_slow_flush() {
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
        max_buffer_rows: 1,
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
    let slow_sink: Arc<dyn UploadSink> = Arc::new(SlowUploadSink {
        delay: Duration::from_millis(200),
        started: flush_started.clone(),
    });
    let (handler, _join_handle) = ParquetWriterHandle::<ZeekSink>::start_with_stats(
        ZeekSink,
        slow_sink,
        cfg,
        policy,
        Arc::new(SourceHourlyStats::new()),
        None,
    );
    let handler: Arc<dyn logthing::zeek::listener::ZeekHandler> = Arc::new(handler);

    // Reserve an ephemeral port (bind-then-drop is the standard pattern for
    // this shape of test elsewhere in this repo, given ZeekListener::start()
    // binds internally and doesn't report back which port it chose).
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

    // Connect, retrying briefly until the listener is up.
    let mut stream = loop {
        match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(s) => break s,
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    };

    // Send the first NDJSON line -- with max_buffer_rows == 1, this alone
    // triggers the first (slow, 200ms) flush.
    stream
        .write_all(b"{\"_path\":\"conn\",\"uid\":\"C0\"}\n")
        .await
        .unwrap();
    stream.flush().await.unwrap();

    // Deterministically wait until that flush has genuinely started
    // uploading, rather than assuming timing lines up.
    tokio::time::timeout(Duration::from_secs(2), flush_started.notified())
        .await
        .expect("the first record's flush must have started within the timeout");

    // Now send the remaining lines while we know a slow flush is genuinely
    // in flight. Paced comfortably above ZeekSink's own real per-record
    // mapping cost (~0.5-1.3ms) so the burst doesn't outpace the
    // consumer's legitimate baseline throughput for reasons unrelated to
    // the flush-blocking bug under test.
    for i in 1..40 {
        let line = format!("{{\"_path\":\"conn\",\"uid\":\"C{i}\"}}\n");
        stream.write_all(line.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    // Give the background writer task time to finish processing everything.
    tokio::time::sleep(Duration::from_millis(1000)).await;

    let key = CompositeKey::new(
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
        .get(&key)
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
        "parquet_s3_dropped must stay at 0 through the real TCP ingest path while a flush is in flight"
    );
}
