//! Integration test for the row-count accounting fix in
//! `buffered_writer.rs`'s `PartitionedParquetWriter::push` (see
//! `src/forwarding/buffered_writer.rs` around the `RecordBatchAccumulator`
//! push path).
//!
//! `push()` used to hardcode `n_rows = 1` for every record accepted into an
//! amortized live builder. That is only correct for a sink whose `Record`
//! is exactly one row (Zeek, Suricata -- the only two accumulating sinks
//! today). A sink whose `Record` carries multiple rows in one push (the
//! motivating case: a future `IpfixSink::Record = Vec<FlowRecord>`, one
//! push per UDP datagram) would have its `max_rows` flush trigger driven by
//! the number of *pushes*, not the number of *rows* -- silently under-
//! counting and firing far too late.
//!
//! This test drives the real `ParquetWriterHandle::start_with_stats` path
//! (the same background task every production sink uses) with a
//! multi-row-per-push test sink and proves the flush fires once the real
//! row count crosses `max_rows`, not once the push count does.
//!
//! No external dependency required.

use logthing::forwarding::buffered_writer::{
    BufferedWriterConfig, FlushPolicy, LiveInterval, ParquetSink, ParquetWriterHandle,
    RecordBatchAccumulator, UploadSink,
};
use logthing::stats::SourceHourlyStats;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Records every `upload` call so the test can count flushes directly.
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

/// Amortized-builder accumulator that appends every element of a
/// `Vec<String>` record as its own row -- the shape a future multi-row
/// sink (e.g. IPFIX, one push per UDP datagram) would need.
struct MultiRowAccumulator {
    builder: arrow::array::StringBuilder,
    rows: usize,
    schema: Arc<arrow_schema::Schema>,
}

impl RecordBatchAccumulator<Vec<String>> for MultiRowAccumulator {
    fn try_append(&mut self, record: &Vec<String>) -> anyhow::Result<bool> {
        for v in record {
            self.builder.append_value(v);
        }
        self.rows += record.len();
        Ok(true)
    }
    fn len(&self) -> usize {
        self.rows
    }
    fn finish(&mut self) -> anyhow::Result<arrow_array::RecordBatch> {
        let col: Arc<dyn arrow_array::Array> = Arc::new(self.builder.finish());
        self.rows = 0;
        Ok(arrow_array::RecordBatch::try_new(
            self.schema.clone(),
            vec![col],
        )?)
    }
}

/// A sink whose `Record` carries 3 rows per push, mirroring a batched
/// multi-row sink such as a future IPFIX-with-accumulator conversion.
struct MultiRowSink;
impl ParquetSink for MultiRowSink {
    type Record = Vec<String>;
    fn source(&self) -> &'static str {
        "test"
    }
    fn partition(&self, _record: &Vec<String>) -> Option<String> {
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
        record: &Vec<String>,
        schema: &Arc<arrow_schema::Schema>,
    ) -> anyhow::Result<arrow_array::RecordBatch> {
        let col: Arc<dyn arrow_array::Array> = Arc::new(arrow_array::StringArray::from(
            record.iter().map(String::as_str).collect::<Vec<_>>(),
        ));
        Ok(arrow_array::RecordBatch::try_new(
            schema.clone(),
            vec![col],
        )?)
    }
    fn new_batch(
        &self,
        schema: &Arc<arrow_schema::Schema>,
    ) -> Option<Box<dyn RecordBatchAccumulator<Vec<String>>>> {
        Some(Box::new(MultiRowAccumulator {
            builder: arrow::array::StringBuilder::new(),
            rows: 0,
            schema: schema.clone(),
        }))
    }
}

fn three_row_record(tag: &str) -> Vec<String> {
    vec![format!("{tag}a"), format!("{tag}b"), format!("{tag}c")]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn max_rows_flush_trigger_fires_on_row_count_not_push_count() {
    const MAX_ROWS: usize = 10;
    let cfg = BufferedWriterConfig {
        connection: logthing::config::S3ConnectionConfig {
            endpoint: String::new(),
            bucket: String::new(),
            region: String::new(),
            access_key: String::new(),
            secret_key: String::new(),
        },
        prefix: "test".to_string(),
        max_buffer_rows: MAX_ROWS,
        flush_threshold_bytes: usize::MAX, // only the row trigger may fire
        flush_interval_secs: 3600,         // age must never fire either
        channel_capacity: 64,
        max_partitions: 8,
    };
    let policy = FlushPolicy {
        max_rows: MAX_ROWS,
        max_bytes: usize::MAX,
        interval: LiveInterval::new(Duration::from_secs(3600)),
    };
    let sink = Arc::new(CountingUploadSink::default());
    let sink_dyn: Arc<dyn UploadSink> = sink.clone();

    let (handler, join_handle) = ParquetWriterHandle::<MultiRowSink>::start_with_stats(
        MultiRowSink,
        sink_dyn,
        cfg,
        policy,
        Arc::new(SourceHourlyStats::new()),
        None,
    );

    // 3 pushes * 3 rows = 9 rows: below MAX_ROWS=10. If row_count were
    // (incorrectly) driven by push count, this would already be "3" either
    // way -- the real discriminator is the next push.
    for i in 0..3 {
        handler
            .try_send(three_row_record(&format!("p{i}")))
            .expect("channel has ample capacity");
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        *sink.uploads.lock().unwrap(),
        0,
        "9 real rows must not cross a max_rows=10 threshold yet"
    );

    // The 4th push brings the real total to 12 rows, crossing max_rows=10.
    // Under the pre-fix bug (n_rows hardcoded to 1 per push), row_count
    // would only be 4 here -- nowhere near 10 -- and this would need 10
    // pushes (30 real rows) before ever flushing.
    handler
        .try_send(three_row_record("p3"))
        .expect("channel has ample capacity");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        *sink.uploads.lock().unwrap() >= 1,
        "the 4th push (12 real rows) must cross max_rows=10 and trigger a flush -- \
         if this never fires, row_count is being driven by push count instead of \
         real row count"
    );

    drop(handler);
    join_handle.await.expect("writer task must not panic");
}
