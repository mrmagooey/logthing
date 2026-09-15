//! End-to-end integration test: HEC/generic records pushed through
//! `hec_local_start` land as real, readable Parquet files on local disk.

use bytes::Bytes;
use logthing::config::GenericLocalConfig;
use logthing::forwarding::generic_s3::hec_local_start;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::ingest::GenericRecord;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::path::Path;

fn walk_all_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            walk_all_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

#[tokio::test]
async fn hec_records_appear_as_parquet_on_local_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let sink = std::sync::Arc::new(
        LocalDiskSink::new(tmp.path().to_path_buf())
            .await
            .expect("LocalDiskSink constructs"),
    );

    let cfg = GenericLocalConfig {
        directory: tmp.path().to_path_buf(),
        prefix: "hec".to_string(),
        flush_threshold_bytes: usize::MAX,
        flush_interval_secs: 3600,
        channel_capacity: 256,
        max_buffer_rows: 100_000,
    };

    let (handler, join_handle) = hec_local_start(
        &cfg,
        sink,
        64,
        std::sync::Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );

    let rec1 = GenericRecord {
        sourcetype: "access_log".to_string(),
        host: Some("host-a".to_string()),
        time: Some(chrono::Utc::now()),
        fields: serde_json::json!({"action": "login", "user": "alice"}),
        received_at: chrono::Utc::now(),
    };
    let rec2 = GenericRecord {
        sourcetype: "access_log".to_string(),
        host: Some("host-b".to_string()),
        time: None,
        fields: serde_json::json!({"action": "logout", "user": "bob"}),
        received_at: chrono::Utc::now(),
    };

    handler.try_send(rec1).expect("send rec1");
    handler.try_send(rec2).expect("send rec2");

    // Drop the handler to close the channel and trigger the shutdown flush.
    drop(handler);
    tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
        .await
        .expect("writer task must exit within 5s")
        .expect("writer task must not panic");

    // Find every file under the tempdir; there must be no leftover .tmp- files.
    let mut all_files = Vec::new();
    walk_all_files(tmp.path(), &mut all_files);
    assert!(
        !all_files
            .iter()
            .any(|p| p.file_name().unwrap().to_string_lossy().contains(".tmp-")),
        "no leftover .tmp- files should remain after flush: {all_files:?}"
    );

    let parquet_files: Vec<_> = all_files
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "parquet"))
        .collect();
    assert_eq!(
        parquet_files.len(),
        1,
        "expected exactly 1 Parquet file (both records share sourcetype 'access_log'); found {parquet_files:?}"
    );

    let raw = std::fs::read(parquet_files[0]).unwrap();
    let buf = Bytes::from(raw);
    let builder = ParquetRecordBatchReaderBuilder::try_new(buf).unwrap();
    let schema = builder.schema().clone();
    assert_eq!(schema.fields().len(), 6);
    for col in ["time", "received_at", "partition_time"] {
        assert_eq!(
            schema.field_with_name(col).unwrap().data_type(),
            &arrow::datatypes::DataType::Timestamp(
                arrow::datatypes::TimeUnit::Microsecond,
                Some("UTC".into())
            ),
            "on-disk Parquet '{col}' column must be a microsecond UTC timestamp"
        );
    }

    let mut reader = builder.build().unwrap();
    let rb = reader
        .next()
        .expect("at least one record batch")
        .expect("record batch reads without error");
    assert_eq!(rb.num_rows(), 2);

    use arrow::array::{Array, StringArray};
    let hosts = rb
        .column_by_name("host")
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(hosts.value(0), "host-a");
    assert_eq!(hosts.value(1), "host-b");

    let fields_col = rb
        .column_by_name("fields")
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(fields_col.value(0)).expect("fields must be valid JSON");
    assert_eq!(parsed["user"], "alice");
}

#[tokio::test]
async fn hec_local_start_emits_iceberg_descriptor_when_configured() {
    let parquet_dir = tempfile::tempdir().expect("parquet tempdir");
    let descriptor_dir = tempfile::tempdir().expect("descriptor tempdir");

    let parquet_sink = std::sync::Arc::new(
        LocalDiskSink::new(parquet_dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new (parquet)"),
    );
    let descriptor_sink: std::sync::Arc<dyn logthing::forwarding::buffered_writer::UploadSink> =
        std::sync::Arc::new(
            LocalDiskSink::new(descriptor_dir.path().to_path_buf())
                .await
                .expect("LocalDiskSink::new (descriptor)"),
        );

    let cfg = GenericLocalConfig {
        directory: parquet_dir.path().to_path_buf(),
        prefix: "hec".to_string(),
        max_buffer_rows: 1, // flush immediately on first push per partition
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 64,
    };

    let (handler, join_handle) = hec_local_start(
        &cfg,
        parquet_sink,
        64,
        std::sync::Arc::new(logthing::stats::SourceHourlyStats::new()),
        Some(descriptor_sink),
    );

    let rec = GenericRecord {
        sourcetype: "access_log".to_string(),
        host: Some("host-a".to_string()),
        time: Some(chrono::Utc::now()),
        fields: serde_json::json!({"action": "login", "user": "alice"}),
        received_at: chrono::Utc::now(),
    };
    handler.try_send(rec).expect("send rec");

    // Drop the handler to close the channel and trigger the shutdown flush.
    drop(handler);
    tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
        .await
        .expect("writer task must exit within 5s")
        .expect("writer task must not panic");

    // A descriptor JSON must exist somewhere under descriptor_dir.
    let mut found = false;
    let mut stack = vec![descriptor_dir.path().to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries = tokio::fs::read_dir(&dir).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("json") {
                found = true;
                let contents = tokio::fs::read_to_string(&path).await.unwrap();
                let v: serde_json::Value = serde_json::from_str(&contents).unwrap();
                assert_eq!(v["source"], "hec");
                assert_eq!(v["file_format"], "PARQUET");
            }
        }
    }
    assert!(
        found,
        "expected at least one descriptor .json file under {descriptor_dir:?}"
    );
}

/// Pushes 1800 real HEC records across two sourcetype partitions through the
/// real pipeline (`hec_local_start` → `PartitionedParquetWriter` →
/// `LocalDiskSink`), crossing the `BUILDER_BATCH_ROWS` (1000) threshold in
/// `GenericAccumulator`'s live builder mid-burst for one partition while the
/// other stays well under it -- proving the amortized builder correctly
/// materializes once at row 1000 and resumes accumulating the remainder in a
/// fresh builder, without losing or duplicating rows, AND that this all
/// happens per-partition (each sourcetype gets its own independent
/// accumulator instance). Mirrors
/// `suricata_local_burst_of_1500_alert_records_crosses_builder_batch_rows`.
/// Every 7th record has no `host`/`time`, exercising the nullable columns
/// through the accumulator path across the materialize boundary too.
#[tokio::test]
async fn hec_local_burst_crossing_builder_batch_rows_across_multiple_partitions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = std::sync::Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    // Row/byte/time thresholds all high enough that no in-loop flush fires;
    // the only flush is the shutdown flush once the handler is dropped.
    let cfg = GenericLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "hec".to_string(),
        max_buffer_rows: 100_000,
        flush_threshold_bytes: 100_000_000,
        flush_interval_secs: 3600,
        channel_capacity: 2_000,
    };

    let (handler, join_handle) = hec_local_start(
        &cfg,
        sink,
        64,
        std::sync::Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );

    const N_A: usize = 1500; // crosses BUILDER_BATCH_ROWS (1000) mid-burst
    const N_B: usize = 300; // stays well under it -- independent accumulator
    for i in 0..N_A {
        let rec = if i % 7 == 0 {
            GenericRecord {
                sourcetype: "type_a".to_string(),
                host: None,
                time: None,
                fields: serde_json::json!({"i": i}),
                received_at: chrono::Utc::now(),
            }
        } else {
            GenericRecord {
                sourcetype: "type_a".to_string(),
                host: Some(format!("host-{i}")),
                time: Some(chrono::Utc::now()),
                fields: serde_json::json!({"i": i}),
                received_at: chrono::Utc::now(),
            }
        };
        handler.try_send(rec).expect("channel has ample capacity");
    }
    for i in 0..N_B {
        let rec = GenericRecord {
            sourcetype: "type_b".to_string(),
            host: Some(format!("other-{i}")),
            time: Some(chrono::Utc::now()),
            fields: serde_json::json!({"i": i}),
            received_at: chrono::Utc::now(),
        };
        handler.try_send(rec).expect("channel has ample capacity");
    }

    // Drop the handler to close the channel; the writer task's shutdown path
    // drains any in-flight flushes and then performs one final, synchronous
    // flush covering everything still buffered (materialized + still-live).
    drop(handler);
    tokio::time::timeout(std::time::Duration::from_secs(10), join_handle)
        .await
        .expect("writer task exits within 10s")
        .expect("writer task must not panic");

    let count_rows_under = |partition: &str| -> (usize, usize) {
        let partition_dir = dir.path().join("hec").join(partition);
        let mut all_files = Vec::new();
        walk_all_files(&partition_dir, &mut all_files);
        let parquet_files: Vec<_> = all_files
            .into_iter()
            .filter(|p| p.extension().is_some_and(|e| e == "parquet"))
            .collect();
        let mut total_rows = 0usize;
        let mut null_host_count = 0usize;
        for file_path in &parquet_files {
            let bytes = std::fs::read(file_path).expect("read parquet file");
            let builder =
                ParquetRecordBatchReaderBuilder::try_new(Bytes::from(bytes)).expect("builder");
            let reader = builder.build().expect("reader");
            for rb in reader {
                let rb = rb.expect("batch ok");
                total_rows += rb.num_rows();
                use arrow::array::{Array, StringArray};
                let host_col = rb
                    .column_by_name("host")
                    .unwrap()
                    .as_any()
                    .downcast_ref::<StringArray>()
                    .unwrap();
                for i in 0..rb.num_rows() {
                    if host_col.is_null(i) {
                        null_host_count += 1;
                    }
                }
            }
        }
        (total_rows, null_host_count)
    };

    let (rows_a, nulls_a) = count_rows_under("type_a");
    let (rows_b, nulls_b) = count_rows_under("type_b");

    assert_eq!(
        rows_a, N_A,
        "expected exactly {N_A} rows across all type_a Parquet files, proving the \
         BUILDER_BATCH_ROWS (1000) materialize threshold was crossed at least once \
         mid-burst without losing or duplicating rows"
    );
    assert_eq!(
        nulls_a,
        N_A.div_ceil(7),
        "every 7th type_a record had no host and must round-trip as null through \
         the materialize boundary"
    );
    assert_eq!(
        rows_b, N_B,
        "type_b's independent accumulator (never crossing BUILDER_BATCH_ROWS) must \
         still land every row exactly once"
    );
    assert_eq!(nulls_b, 0, "no type_b record had a null host");
}
