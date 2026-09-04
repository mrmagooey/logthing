//! End-to-end integration test: WEF events pushed through `wef_local_start`
//! land as real, readable Parquet files on local disk.

use bytes::Bytes;
use logthing::config::WefLocalConfig;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::parquet_s3::wef_local_start;
use logthing::models::{EventLevel, ParsedEvent, WindowsEvent};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::path::Path;
use std::sync::Arc;

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

fn make_parsed_event(host: &str, event_id: u32) -> Arc<WindowsEvent> {
    let parsed = ParsedEvent {
        provider: "Security".into(),
        event_id,
        level: EventLevel::Information,
        task: 0,
        opcode: 0,
        keywords: 0,
        time_created: chrono::Utc::now(),
        event_record_id: 1,
        process_id: None,
        thread_id: None,
        channel: "Security".into(),
        computer: "HOST".into(),
        security_user_id: None,
        message: None,
        data: None,
    };
    Arc::new(WindowsEvent::new(host.into(), "<Event/>".into()).with_parsed(parsed))
}

#[tokio::test]
async fn wef_events_appear_as_parquet_on_local_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let sink = Arc::new(
        LocalDiskSink::new(tmp.path().to_path_buf())
            .await
            .expect("LocalDiskSink constructs"),
    );

    let cfg = WefLocalConfig {
        directory: tmp.path().to_path_buf(),
        prefix: "".to_string(),
        flush_threshold_bytes: usize::MAX,
        flush_interval_secs: 3600,
        channel_capacity: 256,
        max_buffer_rows: 100_000,
    };

    let (handle, join_handle) = wef_local_start(
        &cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );

    let event1 = make_parsed_event("host-a", 4624);
    let event2 = make_parsed_event("host-b", 4624);

    handle.try_send(event1).expect("send event1");
    handle.try_send(event2).expect("send event2");

    // Drop the handle to close the channel and trigger the shutdown flush.
    drop(handle);
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
        "expected exactly 1 Parquet file (both events share event_id 4624); found {parquet_files:?}"
    );

    // Empty prefix must preserve the legacy event_type=<id>/year=… root layout.
    let rel_path = parquet_files[0]
        .strip_prefix(tmp.path())
        .unwrap()
        .to_string_lossy();
    assert!(
        rel_path.starts_with("event_type=4624/"),
        "path must start with event_type=4624/, got {rel_path}"
    );

    let raw = std::fs::read(parquet_files[0]).unwrap();
    let buf = Bytes::from(raw);
    let builder = ParquetRecordBatchReaderBuilder::try_new(buf).unwrap();
    let schema = builder.schema().clone();
    assert_eq!(schema.fields().len(), 5);
    assert_eq!(
        schema.field_with_name("timestamp").unwrap().data_type(),
        &arrow::datatypes::DataType::Timestamp(
            arrow::datatypes::TimeUnit::Microsecond,
            Some("UTC".into())
        ),
        "on-disk Parquet timestamp column must be a microsecond UTC timestamp"
    );

    let mut reader = builder.build().unwrap();
    let rb = reader
        .next()
        .expect("at least one record batch")
        .expect("record batch reads without error");
    assert_eq!(rb.num_rows(), 2);

    use arrow::array::{Array, StringArray, UInt32Array};
    let event_ids = rb
        .column_by_name("event_id")
        .unwrap()
        .as_any()
        .downcast_ref::<UInt32Array>()
        .unwrap();
    assert_eq!(event_ids.value(0), 4624);
    assert_eq!(event_ids.value(1), 4624);

    let hosts = rb
        .column_by_name("source_host")
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(hosts.value(0), "host-a");
    assert_eq!(hosts.value(1), "host-b");
    assert!(!hosts.is_null(0));
}

#[tokio::test]
async fn wef_local_start_emits_iceberg_descriptor_when_configured() {
    let parquet_dir = tempfile::tempdir().expect("parquet tempdir");
    let descriptor_dir = tempfile::tempdir().expect("descriptor tempdir");

    let parquet_sink = Arc::new(
        LocalDiskSink::new(parquet_dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new (parquet)"),
    );
    let descriptor_sink: Arc<dyn logthing::forwarding::buffered_writer::UploadSink> = Arc::new(
        LocalDiskSink::new(descriptor_dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new (descriptor)"),
    );

    let cfg = WefLocalConfig {
        directory: parquet_dir.path().to_path_buf(),
        prefix: "".to_string(),
        max_buffer_rows: 1, // flush immediately on first push per partition
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 64,
    };

    let (handle, join_handle) = wef_local_start(
        &cfg,
        parquet_sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        Some(descriptor_sink),
    );

    let event = make_parsed_event("host-a", 4624);
    handle.try_send(event).expect("send event");

    // Drop the handle to close the channel and trigger the shutdown flush.
    drop(handle);
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
                assert_eq!(v["source"], "wef");
                assert_eq!(v["file_format"], "PARQUET");
            }
        }
    }
    assert!(
        found,
        "expected at least one descriptor .json file under {descriptor_dir:?}"
    );
}
