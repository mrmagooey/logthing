//! Integration: a flush task that panics inside the running writer task must not strand its
//! partition or lose its rows. Kept apart from `buffered_writer_flush_decoupling_integration`
//! because that file captures the panic warning with a thread-local subscriber, and a second
//! test emitting the same event concurrently would poison tracing's callsite-interest cache.

use logthing::forwarding::buffered_writer::{
    BufferedWriterConfig, FlushPolicy, LiveInterval, ParquetSink, ParquetWriterHandle, UploadSink,
};
use logthing::stats::SourceHourlyStats;
use std::sync::Arc;
use std::time::Duration;

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

/// Upload sink whose first `upload()` panics; later uploads keep the bytes.
struct PanicOnceSink {
    panicked: std::sync::atomic::AtomicBool,
    bodies: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
}

#[async_trait::async_trait]
impl UploadSink for PanicOnceSink {
    async fn upload(&self, _key: &str, body: Vec<u8>) -> anyhow::Result<()> {
        if !self
            .panicked
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            panic!("intentional one-off upload panic");
        }
        self.bodies.lock().unwrap().push(body);
        Ok(())
    }
    fn target_label(&self) -> &'static str {
        "panic-once"
    }
    fn location_hint(&self) -> String {
        "panic-once://test".to_string()
    }
}

/// A flush task that panics must not strand its partition or lose its rows:
/// the real writer task restores the batches and retries, so every row lands
/// exactly once, in one object.
#[tokio::test]
async fn rows_survive_a_flush_task_panic_in_the_running_writer() {
    let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink: Arc<dyn UploadSink> = Arc::new(PanicOnceSink {
        panicked: std::sync::atomic::AtomicBool::new(false),
        bodies: bodies.clone(),
    });
    let cfg = BufferedWriterConfig {
        connection: logthing::config::S3ConnectionConfig {
            endpoint: String::new(),
            bucket: String::new(),
            region: String::new(),
            access_key: String::new(),
            secret_key: String::new(),
            object_lock_mode: None,
            object_lock_retain_days: None,
        },
        prefix: "zeek".to_string(),
        max_buffer_rows: 5,
        flush_threshold_bytes: usize::MAX,
        flush_interval_secs: 1,
        channel_capacity: 16,
        max_partitions: 8,
    };
    let policy = FlushPolicy {
        max_rows: 5,
        max_bytes: usize::MAX,
        interval: LiveInterval::new(Duration::from_secs(1)),
    };
    let (handler, _join) = ParquetWriterHandle::<SimpleFastSink>::start_with_stats(
        SimpleFastSink,
        sink,
        cfg,
        policy,
        Arc::new(SourceHourlyStats::new()),
        None,
    );

    for i in 0..5 {
        handler.try_send(format!("record-{i}")).unwrap();
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while bodies.lock().unwrap().is_empty() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Let any (wrong) duplicate upload show up before counting.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let bodies = bodies.lock().unwrap();
    assert_eq!(
        bodies.len(),
        1,
        "the restored rows must be delivered in exactly one object"
    );
    let rows = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(
        bytes::Bytes::copy_from_slice(&bodies[0]),
    )
    .unwrap()
    .metadata()
    .file_metadata()
    .num_rows();
    assert_eq!(rows, 5);
}
