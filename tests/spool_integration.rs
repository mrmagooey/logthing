//! Integration tests for the durable S3 spool: real files, real `S3Sink` (AWS SDK client),
//! real HEC writer, in-process fake S3 (no Docker). The process-global spool is never
//! touched here (it is covered by the e2e binary test).

mod common;

use common::fake_s3::FakeS3;
use logthing::config::{S3ConnectionConfig, SpoolConfig};
use logthing::forwarding::buffered_writer::{
    BufferedWriterConfig, FlushPolicy, LiveInterval, ParquetWriterHandle, UploadSink,
};
use logthing::forwarding::generic_s3::{GenericS3Handler, GenericSink};
use logthing::forwarding::s3_sink::S3Sink;
use logthing::forwarding::spool::{Spool, SpoolingUploadSink};
use logthing::ingest::GenericRecord;
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::{Arc, Once};
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(20);
const JOIN: Duration = Duration::from_secs(15);

fn conn(endpoint: &str) -> S3ConnectionConfig {
    S3ConnectionConfig {
        endpoint: endpoint.to_string(),
        bucket: "b".to_string(),
        region: "us-east-1".to_string(),
        access_key: "AKIAFAKE".to_string(),
        secret_key: "secret".to_string(),
        object_lock_mode: None,
        object_lock_retain_days: None,
    }
}

/// A real `S3Sink` pointed at `fake`. The SDK's own retries are disabled so an outage
/// produces exactly one request per attempt and the tests account for requests exactly.
async fn s3(fake: &FakeS3) -> Arc<S3Sink> {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: runs once, before any S3 client of this binary is built; no other code in
        // this test binary touches the environment.
        unsafe { std::env::set_var("AWS_MAX_ATTEMPTS", "1") };
    });
    Arc::new(
        S3Sink::from_connection(&conn(&fake.endpoint()))
            .await
            .expect("S3Sink"),
    )
}

fn spool_cfg(dir: &Path, max_bytes: u64) -> SpoolConfig {
    SpoolConfig {
        dir: dir.to_path_buf(),
        max_bytes,
    }
}

fn fast_spool(dir: &Path, max_bytes: u64) -> Arc<Spool> {
    Spool::open_with_backoff(
        &spool_cfg(dir, max_bytes),
        Duration::from_millis(20),
        Duration::from_millis(100),
    )
    .unwrap()
}

fn start_hec(
    sink: Arc<dyn UploadSink>,
    descriptor: Option<Arc<dyn UploadSink>>,
) -> (GenericS3Handler, tokio::task::JoinHandle<()>) {
    let cfg = BufferedWriterConfig {
        connection: conn("http://unused.invalid"),
        prefix: "hec".to_string(),
        max_buffer_rows: 1,
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 64,
        max_partitions: 64,
    };
    let policy = FlushPolicy {
        max_rows: 1,
        max_bytes: 1,
        interval: LiveInterval::new(Duration::from_secs(3600)),
    };
    ParquetWriterHandle::start_with_stats(
        GenericSink,
        sink,
        cfg,
        policy,
        Arc::new(logthing::stats::SourceHourlyStats::default()),
        descriptor,
    )
}

fn record(user: &str) -> GenericRecord {
    GenericRecord {
        sourcetype: "access_log".to_string(),
        host: Some("h".to_string()),
        time: Some(chrono::Utc::now()),
        fields: serde_json::json!({ "user": user }),
        received_at: chrono::Utc::now(),
        ..Default::default()
    }
}

async fn join(handle: GenericS3Handler, task: tokio::task::JoinHandle<()>) {
    drop(handle);
    tokio::time::timeout(JOIN, task)
        .await
        .expect("writer did not finish")
        .expect("writer task panicked");
}

fn spool_files(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

fn parquet_rows(bytes: &[u8]) -> usize {
    let b = bytes::Bytes::copy_from_slice(bytes);
    ParquetRecordBatchReaderBuilder::try_new(b)
        .expect("parquet footer")
        .build()
        .expect("reader")
        .map(|b| b.expect("batch").num_rows())
        .sum()
}

fn counter_sum(snap: &Snapshotter, name: &str) -> u64 {
    snap.snapshot()
        .into_vec()
        .into_iter()
        .filter(|(k, ..)| k.key().name() == name)
        .map(|(_, _, _, v)| match v {
            DebugValue::Counter(c) => c,
            _ => 0,
        })
        .sum()
}

#[tokio::test]
async fn test_flush_while_s3_down_spools_then_uploader_delivers_when_s3_recovers() {
    let fake = FakeS3::start().await;
    fake.set_failing(true);
    let dir = tempfile::tempdir().unwrap();
    let spool = fast_spool(dir.path(), 1 << 20);
    let s3 = s3(&fake).await;
    spool
        .register("hec.s3", s3.clone(), Some(s3.clone()))
        .unwrap();
    let sink = Arc::new(SpoolingUploadSink::new(s3.clone(), spool.clone(), "hec.s3"));

    let (handle, task) = start_hec(sink, Some(s3.clone()));
    handle.try_send(record("alice")).expect("send");
    assert!(
        common::wait_until(WAIT, || spool.pending_entries() == 1).await,
        "flush must land in the spool while S3 is down"
    );
    join(handle, task).await; // the writer holds no requeued rows: it finishes cleanly
    assert_eq!(fake.put_count(), 0, "nothing reaches S3 while it is down");
    assert_eq!(spool.pending_entries(), 1);

    fake.set_failing(false);
    let up = spool.spawn_uploader();
    let delivered = common::wait_until(WAIT, || {
        let keys = fake.put_keys();
        keys.iter().any(|k| k.ends_with(".parquet"))
            && keys.iter().any(|k| k.ends_with(".json"))
            && spool.pending_entries() == 0
    })
    .await;
    up.shutdown().await;
    assert!(delivered, "keys: {:?}", fake.put_keys());
    let pq = fake
        .put_keys()
        .into_iter()
        .find(|k| k.ends_with(".parquet"))
        .unwrap();
    assert!(fake.body(&pq).unwrap().starts_with(b"PAR1"));
    assert_eq!(parquet_rows(&fake.body(&pq).unwrap()), 1);
    assert!(spool_files(dir.path()).is_empty());
}

#[tokio::test]
async fn test_crash_between_parquet_and_descriptor_replays_both_with_same_keys() {
    let pq_fake = FakeS3::start().await;
    let ds_fake = FakeS3::start().await;
    ds_fake.set_failing(true);
    let dir = tempfile::tempdir().unwrap();
    let pq_sink = s3(&pq_fake).await;
    let ds_sink = s3(&ds_fake).await;

    // Run 1: long backoff so exactly one (partial) attempt happens before the "crash".
    {
        let spool = Spool::open_with_backoff(
            &spool_cfg(dir.path(), 1 << 20),
            Duration::from_secs(30),
            Duration::from_secs(30),
        )
        .unwrap();
        spool
            .register("hec.s3", pq_sink.clone(), Some(ds_sink.clone()))
            .unwrap();
        let sink = Arc::new(SpoolingUploadSink::new(
            pq_sink.clone(),
            spool.clone(),
            "hec.s3",
        ));
        let (handle, task) = start_hec(sink, Some(ds_sink.clone()));
        handle.try_send(record("bob")).expect("send");
        assert!(common::wait_until(WAIT, || spool.pending_entries() == 1).await);
        join(handle, task).await;

        let up = spool.spawn_uploader();
        let partial = common::wait_until(WAIT, || {
            pq_fake.put_count() == 1 && ds_fake.request_count() == 1
        })
        .await;
        up.shutdown().await; // "crash": uploader and spool are dropped with the entry intact
        assert!(
            partial,
            "parquet must land once and the descriptor must fail"
        );
        assert_eq!(spool.pending_entries(), 1);
    }
    assert_eq!(ds_fake.put_count(), 0);
    assert!(!spool_files(dir.path()).is_empty());

    // Run 2: reopen the same directory; the entry replays both PUTs under the same keys.
    ds_fake.set_failing(false);
    let spool = fast_spool(dir.path(), 1 << 20);
    spool
        .register("hec.s3", pq_sink.clone(), Some(ds_sink.clone()))
        .unwrap();
    assert_eq!(spool.pending_entries(), 1);
    let up = spool.spawn_uploader();
    let done = common::wait_until(WAIT, || {
        spool.pending_entries() == 0 && ds_fake.put_count() == 1
    })
    .await;
    up.shutdown().await;
    assert!(done);

    let pq_puts = pq_fake.puts();
    assert_eq!(pq_puts.len(), 2, "parquet PUT twice");
    assert_eq!(pq_puts[0], pq_puts[1], "same key, identical bytes");
    let ds_puts = ds_fake.puts();
    assert_eq!(ds_puts.len(), 1);
    assert!(ds_puts[0].0.ends_with(".json"));
    let desc: serde_json::Value = serde_json::from_slice(&ds_puts[0].1).unwrap();
    assert_eq!(
        desc["sha256"].as_str().unwrap(),
        hex::encode(Sha256::digest(&pq_puts[1].1)),
        "descriptor sha256 matches the delivered parquet"
    );
    assert!(spool_files(dir.path()).is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn test_spool_full_falls_back_to_direct_upload_and_failure_requeues_in_memory() {
    let recorder = DebuggingRecorder::new();
    let snap = recorder.snapshotter();
    let _guard = metrics::set_default_local_recorder(&recorder);

    let fake = FakeS3::start().await;
    let dir = tempfile::tempdir().unwrap();
    let spool = fast_spool(dir.path(), 1); // nothing ever fits
    let s3 = s3(&fake).await;
    spool.register("hec.s3", s3.clone(), None).unwrap();
    let sink = Arc::new(SpoolingUploadSink::new(s3.clone(), spool.clone(), "hec.s3"));
    let (handle, task) = start_hec(sink, None);

    // Healthy S3: direct upload, spool untouched.
    handle.try_send(record("a")).expect("send");
    assert!(common::wait_until(WAIT, || fake.put_count() == 1).await);
    assert_eq!(spool.pending_entries(), 0);
    assert!(spool_files(dir.path()).is_empty());
    assert_eq!(counter_sum(&snap, "parquet_s3_upload_errors"), 0);

    // S3 down: the failure reaches the writer's in-memory requeue path.
    fake.set_failing(true);
    handle.try_send(record("b")).expect("send");
    assert!(
        common::wait_until(WAIT, || counter_sum(&snap, "parquet_s3_upload_errors") >= 1).await,
        "direct-upload failure must count parquet_s3_upload_errors"
    );
    assert_eq!(fake.put_count(), 1);
    assert_eq!(spool.pending_entries(), 0);

    // Recovery: the next record flushes BOTH rows in one object.
    fake.set_failing(false);
    handle.try_send(record("c")).expect("send");
    assert!(common::wait_until(WAIT, || fake.put_count() == 2).await);
    let last = fake.puts().pop().unwrap();
    assert_eq!(parquet_rows(&last.1), 2, "requeued row + new row");
    join(handle, task).await;
}

#[tokio::test]
async fn test_spool_dir_removed_mid_run_falls_back_without_losing_records() {
    let fake = FakeS3::start().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("spool");
    let spool = fast_spool(&path, 1 << 20);
    let s3 = s3(&fake).await;
    spool.register("hec.s3", s3.clone(), None).unwrap();
    std::fs::remove_dir_all(&path).unwrap();
    let sink = Arc::new(SpoolingUploadSink::new(s3.clone(), spool.clone(), "hec.s3"));
    let (handle, task) = start_hec(sink, None);
    handle.try_send(record("alice")).expect("send");
    assert!(common::wait_until(WAIT, || fake.put_count() == 1).await);
    assert_eq!(spool.pending_entries(), 0);
    let key = &fake.put_keys()[0];
    assert_eq!(parquet_rows(&fake.body(key).unwrap()), 1);
    join(handle, task).await;
}

#[tokio::test]
async fn test_restart_replays_complete_entries_and_discards_partial_tmp() {
    let fake = FakeS3::start().await;
    let dir = tempfile::tempdir().unwrap();
    let s3 = s3(&fake).await;
    let payload = b"PAR1-replay-body".to_vec();
    {
        let spool = fast_spool(dir.path(), 1 << 20);
        let d = logthing::forwarding::buffered_writer::DescriptorPayload {
            key: "hec/x.json".to_string(),
            body: b"{\"sha256\":\"x\"}".to_vec(),
        };
        spool
            .commit("hec.s3", "hec/x.parquet", payload.clone(), Some(&d))
            .await
            .unwrap();
        assert_eq!(spool.pending_entries(), 1);
    }
    std::fs::write(
        dir.path().join("00000000000000000001-dead.parquet.tmp"),
        b"half",
    )
    .unwrap();

    let spool = fast_spool(dir.path(), 1 << 20);
    assert_eq!(spool.pending_entries(), 1);
    assert!(
        !spool_files(dir.path()).iter().any(|n| n.ends_with(".tmp")),
        "stray tmp removed on open"
    );
    spool
        .register("hec.s3", s3.clone(), Some(s3.clone()))
        .unwrap();
    let up = spool.spawn_uploader();
    assert!(common::wait_until(WAIT, || spool.pending_entries() == 0).await);
    up.shutdown().await;
    assert_eq!(fake.body("hec/x.parquet").unwrap(), payload);
    assert_eq!(fake.body("hec/x.json").unwrap(), b"{\"sha256\":\"x\"}");
    assert!(spool_files(dir.path()).is_empty());
}
