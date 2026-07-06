//! End-to-end integration test: syslog messages pushed through
//! `syslog_local_start` land as real, readable Parquet files on local disk.

use bytes::Bytes;
use logthing::config::SyslogLocalConfig;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::syslog_s3::syslog_local_start;
use logthing::syslog::listener::SyslogHandler;
use logthing::syslog::{SyslogMessage, SyslogProtocol};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::net::SocketAddr;
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
async fn syslog_messages_appear_as_parquet_on_local_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let sink = std::sync::Arc::new(
        LocalDiskSink::new(tmp.path().to_path_buf())
            .await
            .expect("LocalDiskSink constructs"),
    );

    let cfg = SyslogLocalConfig {
        directory: tmp.path().to_path_buf(),
        prefix: "syslog".to_string(),
        max_buffer_rows: 10_000,
        flush_interval_secs: 3600,
        channel_capacity: 4096,
    };

    let (handler, join_handle) = syslog_local_start(
        &cfg,
        sink,
        std::sync::Arc::new(logthing::stats::SourceHourlyStats::new()),
    );

    let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();
    let msg1 = SyslogMessage {
        priority: 34,
        severity: 2,
        facility: 4,
        timestamp: Some(chrono::Utc::now()),
        hostname: Some("host-a".to_string()),
        app_name: Some("sshd".to_string()),
        proc_id: None,
        msg_id: None,
        message: "authentication failure".to_string(),
        structured_data: None,
        protocol: SyslogProtocol::Rfc3164,
    };
    let msg2 = SyslogMessage {
        priority: 134,
        severity: 6,
        facility: 16,
        timestamp: Some(chrono::Utc::now()),
        hostname: Some("host-b".to_string()),
        app_name: Some("cron".to_string()),
        proc_id: Some("4321".to_string()),
        msg_id: None,
        message: "job completed".to_string(),
        structured_data: None,
        protocol: SyslogProtocol::Rfc5424,
    };

    handler.handle_message(msg1, src).await;
    handler.handle_message(msg2, src).await;

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
        !all_files.iter().any(|p| p
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(".tmp-")),
        "no leftover .tmp- files should remain after flush: {all_files:?}"
    );

    let parquet_files: Vec<_> = all_files
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "parquet"))
        .collect();
    assert_eq!(
        parquet_files.len(),
        1,
        "expected exactly 1 Parquet file (syslog has a single partition); found {parquet_files:?}"
    );

    let raw = std::fs::read(parquet_files[0]).unwrap();
    let buf = Bytes::from(raw);
    let builder = ParquetRecordBatchReaderBuilder::try_new(buf).unwrap();
    let schema = builder.schema().clone();
    assert_eq!(schema.fields().len(), 11);

    let mut reader = builder.build().unwrap();
    let rb = reader
        .next()
        .expect("at least one record batch")
        .expect("record batch reads without error");
    assert_eq!(rb.num_rows(), 2);

    use arrow::array::{Array, StringArray};
    let hostnames = rb.column(4).as_any().downcast_ref::<StringArray>().unwrap();
    assert_eq!(hostnames.value(0), "host-a");
    assert_eq!(hostnames.value(1), "host-b");
    assert!(!hostnames.is_null(0));
}
