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
    assert_eq!(schema.fields().len(), 5);

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
