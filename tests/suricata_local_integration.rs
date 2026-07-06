//! Integration test: SuricataRecord → suricata_local_start → real Parquet
//! files on local disk, read back with a real Parquet reader.
//!
//! Unlike `suricata_s3_integration.rs` (gated on a running MinIO), this test
//! needs no external service — local disk is always available — so it runs
//! unconditionally in CI.

use logthing::config::SuricataLocalConfig;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::suricata_s3::suricata_local_start;
use logthing::suricata::SuricataRecord;
use logthing::suricata::listener::SuricataHandler;
use std::sync::Arc;

fn make_alert_record(src_ip: &str) -> SuricataRecord {
    SuricataRecord {
        event_type: "alert".to_string(),
        fields: serde_json::json!({
            "event_type": "alert",
            "src_ip": src_ip,
            "dest_ip": "1.2.3.4",
            "alert": {"signature": "ET TEST"}
        }),
        received_at: chrono::Utc::now(),
    }
}

fn make_flow_record() -> SuricataRecord {
    SuricataRecord {
        event_type: "flow".to_string(),
        fields: serde_json::json!({
            "event_type": "flow",
            "src_ip": "10.0.0.1",
            "dest_ip": "8.8.8.8",
            "flow": {"bytes_toserver": 512, "bytes_toclient": 4096}
        }),
        received_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn suricata_records_appear_as_parquet_on_local_disk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    let cfg = SuricataLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "suricata".to_string(),
        max_buffer_rows: 1, // flush immediately on first record per partition
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 256,
    };

    let (handler, _writer_task) = suricata_local_start(
        &cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
    );

    let src: std::net::SocketAddr = "127.0.0.1:47761".parse().unwrap();
    handler
        .handle_record(make_alert_record("192.168.1.1"), src)
        .await;
    handler.handle_record(make_flow_record(), src).await;

    // Give the background task time to flush (max_buffer_rows=1 and
    // flush_threshold_bytes=1 both trigger flush on the first push per partition).
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // --- Verify the `alert` record under suricata/alert/ ---
    {
        let alert_dir = dir.path().join("suricata/alert");
        assert!(alert_dir.is_dir(), "expected {alert_dir:?} to exist");
        let parquet_files: Vec<_> = walk_all_files(&alert_dir)
            .into_iter()
            .filter(|p| p.extension().is_some_and(|ext| ext == "parquet"))
            .collect();
        assert!(
            !parquet_files.is_empty(),
            "expected at least one Parquet file under {alert_dir:?}"
        );

        let file_path = &parquet_files[0];
        let bytes = std::fs::read(file_path).expect("read parquet file");

        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .expect("parquet builder for alert");
        let schema = builder.schema().clone();
        for col in ["event_type", "received_at", "src_ip", "payload"] {
            assert!(
                schema.field_with_name(col).is_ok(),
                "expected column '{col}' in envelope schema"
            );
        }

        let mut reader = builder.build().expect("parquet reader for alert");
        let rb = reader
            .next()
            .expect("at least one batch")
            .expect("batch ok");
        assert_eq!(rb.num_rows(), 1);

        use arrow::array::StringArray;
        let src_ip = rb
            .column_by_name("src_ip")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(src_ip.value(0), "192.168.1.1");
    }

    // --- Verify the `flow` record under suricata/flow/ ---
    {
        let flow_dir = dir.path().join("suricata/flow");
        assert!(flow_dir.is_dir(), "expected {flow_dir:?} to exist");
        let parquet_files: Vec<_> = walk_all_files(&flow_dir)
            .into_iter()
            .filter(|p| p.extension().is_some_and(|ext| ext == "parquet"))
            .collect();
        assert!(
            !parquet_files.is_empty(),
            "expected at least one Parquet file under {flow_dir:?}"
        );

        let file_path = &parquet_files[0];
        let bytes = std::fs::read(file_path).expect("read parquet file");

        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .expect("parquet builder for flow");
        let mut reader = builder.build().expect("parquet reader for flow");
        let rb = reader
            .next()
            .expect("at least one batch")
            .expect("batch ok");
        assert_eq!(rb.num_rows(), 1);

        use arrow::array::StringArray;
        let event_type = rb
            .column_by_name("event_type")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(event_type.value(0), "flow");
    }

    // --- No stray temp files left behind anywhere under the root ---
    for entry in walk_all_files(dir.path()) {
        let name = entry.file_name().unwrap().to_string_lossy();
        assert!(
            !name.contains(".tmp-"),
            "found leftover temp file: {entry:?}"
        );
    }
}

fn walk_all_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out
}
