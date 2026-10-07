//! Integration test: the descriptor written beside a local Parquet file carries the exact
//! SHA-256 and size of that file's bytes, built before upload through the real writer path.

mod common;

use logthing::config::{GenericLocalConfig, IcebergConfig, IcebergDescriptorLocalConfig};
use logthing::forwarding::buffered_writer::build_iceberg_descriptor_sink;
use logthing::forwarding::generic_s3::hec_local_start;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::ingest::GenericRecord;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            walk(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn files_with_ext(dir: &Path, ext: &str) -> Vec<PathBuf> {
    let mut all = Vec::new();
    walk(dir, &mut all);
    all.retain(|p| p.extension().is_some_and(|e| e == ext));
    all
}

#[tokio::test]
async fn local_descriptor_sha256_and_size_match_parquet_file_bytes() {
    let data = tempfile::tempdir().unwrap();
    let desc = tempfile::tempdir().unwrap();
    let sink = std::sync::Arc::new(LocalDiskSink::new(data.path().to_path_buf()).await.unwrap());
    let descriptor_sink = build_iceberg_descriptor_sink(&IcebergConfig {
        local: Some(IcebergDescriptorLocalConfig {
            directory: desc.path().to_path_buf(),
            prefix: String::new(),
        }),
        s3: None,
    })
    .await
    .unwrap()
    .expect("local descriptor sink configured");

    let cfg = GenericLocalConfig {
        directory: data.path().to_path_buf(),
        prefix: "hec".to_string(),
        flush_threshold_bytes: usize::MAX,
        flush_interval_secs: 3600,
        channel_capacity: 16,
        max_buffer_rows: 1,
    };
    let (handler, join) = hec_local_start(
        &cfg,
        sink,
        64,
        std::sync::Arc::new(logthing::stats::SourceHourlyStats::new()),
        Some(descriptor_sink),
    );
    handler
        .try_send(GenericRecord {
            sourcetype: "access_log".to_string(),
            host: Some("h".to_string()),
            time: Some(chrono::Utc::now()),
            fields: serde_json::json!({"action": "login"}),
            received_at: chrono::Utc::now(),
            ..Default::default()
        })
        .expect("send");
    common::wait_for_rows(data.path(), 1, std::time::Duration::from_secs(15)).await;
    drop(handler);
    tokio::time::timeout(std::time::Duration::from_secs(15), join)
        .await
        .expect("writer exits")
        .expect("writer does not panic");

    let parquet = files_with_ext(data.path(), "parquet");
    assert_eq!(parquet.len(), 1, "{parquet:?}");

    // The descriptor upload follows the parquet upload; poll until it lands.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let json = loop {
        let found = files_with_ext(desc.path(), "json");
        if let Some(p) = found.into_iter().next() {
            break p;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "descriptor never appeared"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&json).unwrap()).unwrap();
    let bytes = std::fs::read(&parquet[0]).unwrap();
    assert_eq!(v["sha256"], hex::encode(Sha256::digest(&bytes)));
    assert_eq!(v["file_size_in_bytes"], bytes.len() as u64);
}
