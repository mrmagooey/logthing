//! Integration test for `PartitionedParquetWriter::push`'s `record_skipped`
//! counting: a record whose sink mapping fails must be skipped without
//! corrupting the buffer, while records that map successfully still make
//! it into the Parquet file written to local disk.
//!
//! Unlike `parquet_records_skipped` in `buffered_writer.rs`'s own test
//! module (which exercises `push()` directly against an in-memory buffer),
//! this test drives a full push → flush → real Parquet file → read-back
//! cycle through `LocalDiskSink`, so it needs no external service and runs
//! unconditionally in CI.

use arrow::array::{ArrayRef, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use logthing::config::S3ConnectionConfig;
use logthing::forwarding::buffered_writer::{
    BufferedWriterConfig, FlushPolicy, LiveInterval, ParquetSink, PartitionedParquetWriter,
};
use logthing::forwarding::local_sink::LocalDiskSink;
use std::sync::Arc;

fn test_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![Field::new("val", DataType::Utf8, false)]))
}

/// A record prefixed `"bad:"` fails `to_record_batch`; any other record
/// maps to a normal one-row batch. Mirrors the real-world shape this guard
/// protects against: a sink whose mapping is total for well-formed input
/// but fallible for a subset of records.
struct FlaggableSink;
impl ParquetSink for FlaggableSink {
    type Record = String;
    fn source(&self) -> &'static str {
        "test"
    }
    fn partition(&self, _r: &String) -> Option<String> {
        None
    }
    fn schema(&self, _p: Option<&str>) -> Arc<Schema> {
        test_schema()
    }
    fn to_record_batch(
        &self,
        record: &String,
        schema: &Arc<Schema>,
    ) -> anyhow::Result<RecordBatch> {
        if let Some(rest) = record.strip_prefix("bad:") {
            anyhow::bail!("flagged bad: {rest}");
        }
        let col: ArrayRef = Arc::new(StringArray::from(vec![record.as_str()]));
        Ok(RecordBatch::try_new(schema.clone(), vec![col])?)
    }
}

fn test_config() -> (BufferedWriterConfig, FlushPolicy) {
    let cfg = BufferedWriterConfig {
        connection: S3ConnectionConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            bucket: "t".to_string(),
            region: "us-east-1".to_string(),
            access_key: "K".to_string(),
            secret_key: "S".to_string(),
        },
        prefix: "test".to_string(),
        max_buffer_rows: 1_000_000, // nothing flushes on its own; test flushes explicitly
        flush_threshold_bytes: usize::MAX,
        flush_interval_secs: 3600,
        channel_capacity: 64,
        max_partitions: 8,
    };
    let policy = FlushPolicy {
        max_rows: 1_000_000,
        max_bytes: usize::MAX,
        interval: LiveInterval::new(std::time::Duration::from_secs(3600)),
    };
    (cfg, policy)
}

/// Recursively find every `.parquet` file under `root`.
fn find_parquet_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "parquet") {
                out.push(path);
            }
        }
    }
    out
}

/// Total row count across every Parquet file found under `root`.
fn total_parquet_rows(root: &std::path::Path) -> usize {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    let mut total = 0;
    for path in find_parquet_files(root) {
        let bytes = bytes::Bytes::from(std::fs::read(&path).unwrap());
        let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)
            .unwrap()
            .build()
            .unwrap();
        for batch in reader {
            total += batch.unwrap().num_rows();
        }
    }
    total
}

#[tokio::test]
#[allow(clippy::mutable_key_type)]
async fn push_skips_bad_records_and_persists_good_ones_to_parquet() {
    use metrics::set_default_local_recorder;
    use metrics_util::CompositeKey;
    use metrics_util::MetricKind;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let _guard = set_default_local_recorder(&recorder);

    let dir = tempfile::tempdir().expect("tempdir");
    let sink: Arc<dyn logthing::forwarding::buffered_writer::UploadSink> = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    let (cfg, policy) = test_config();
    let mut w = PartitionedParquetWriter::new(FlaggableSink, sink, cfg, policy);

    w.push("good:1".to_string()).await.unwrap();
    w.push("bad:1".to_string()).await.unwrap();
    w.push("good:2".to_string()).await.unwrap();

    w.flush_all().await.unwrap();

    let rows = total_parquet_rows(dir.path());
    assert_eq!(
        rows, 2,
        "exactly the two good records must have made it into a Parquet file"
    );

    let snapshot = snapshotter.snapshot();
    let map = snapshot.into_hashmap();
    let key = CompositeKey::new(
        MetricKind::Counter,
        metrics::Key::from_parts(
            "parquet_s3_records_skipped",
            vec![
                metrics::Label::new("source", "test"),
                metrics::Label::new("target", "local"),
            ],
        ),
    );
    let skipped = map
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
        skipped, 1,
        "the single bad record must have incremented parquet_s3_records_skipped exactly once"
    );
}
