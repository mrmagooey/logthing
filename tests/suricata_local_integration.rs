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
        None,
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
        assert_eq!(
            schema.field_with_name("received_at").unwrap().data_type(),
            &arrow::datatypes::DataType::Timestamp(
                arrow::datatypes::TimeUnit::Microsecond,
                Some("UTC".into())
            ),
            "on-disk Parquet received_at column must be a microsecond UTC timestamp"
        );

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

/// Pushes 1500 real alert records through the real pipeline
/// (`SuricataS3Handler`/local variant → `PartitionedParquetWriter` →
/// `LocalDiskSink`), crossing the `BUILDER_BATCH_ROWS` (1000) threshold in
/// `EnvelopeAccumulator`'s live builder mid-burst -- proving the amortized
/// builder correctly materializes once at row 1000 and resumes accumulating
/// the remaining 500 rows in a fresh builder, rather than silently dropping
/// or corrupting rows across that boundary. Mirrors
/// `zeek_local_burst_of_1500_conn_records_crosses_builder_batch_rows`.
/// Every 7th record has no `src_ip`, exercising the nullable column through
/// the accumulator path across the materialize boundary too.
#[tokio::test]
async fn suricata_local_burst_of_1500_alert_records_crosses_builder_batch_rows() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    // Row/byte/time thresholds all high enough that no in-loop flush fires;
    // the only flush is the shutdown `flush_all` once the handler is
    // dropped. `channel_capacity` is comfortably above the record count so
    // `handle_record`'s bounded wait never actually blocks under this
    // single-threaded burst.
    let cfg = SuricataLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "suricata".to_string(),
        max_buffer_rows: 100_000,
        flush_threshold_bytes: 100_000_000,
        flush_interval_secs: 3600,
        channel_capacity: 2000,
    };

    let (handler, writer_task) = suricata_local_start(
        &cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );

    let src: std::net::SocketAddr = "127.0.0.1:47761".parse().unwrap();
    const N: usize = 1500;
    for i in 0..N {
        let rec = if i % 7 == 0 {
            SuricataRecord {
                event_type: "alert".to_string(),
                fields: serde_json::json!({
                    "event_type": "alert",
                    "dest_ip": "1.2.3.4",
                    "alert": {"signature": format!("ET TEST {i}")}
                }),
                received_at: chrono::Utc::now(),
            }
        } else {
            make_alert_record(&format!("10.0.{}.{}", i / 256, i % 256))
        };
        handler.handle_record(rec, src).await;
    }

    // Drop the handler to close the channel; the writer task's shutdown
    // path drains any in-flight flushes and then performs one final,
    // synchronous `flush_all` covering everything still buffered.
    drop(handler);
    tokio::time::timeout(std::time::Duration::from_secs(10), writer_task)
        .await
        .expect("writer task exits within 10s")
        .expect("writer task must not panic");

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

    use arrow::array::{Array, StringArray};
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    let mut src_ips: Vec<Option<String>> = Vec::with_capacity(N);
    for file_path in &parquet_files {
        let bytes = std::fs::read(file_path).expect("read parquet file");
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .expect("parquet builder for alert burst");
        let reader = builder.build().expect("parquet reader for alert burst");
        for rb in reader {
            let rb = rb.expect("batch ok");
            let src_ip_col = rb
                .column_by_name("src_ip")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            for i in 0..rb.num_rows() {
                src_ips.push(if src_ip_col.is_null(i) {
                    None
                } else {
                    Some(src_ip_col.value(i).to_string())
                });
            }
        }
    }

    assert_eq!(
        src_ips.len(),
        N,
        "expected exactly {N} rows across all alert Parquet files, proving the \
         BUILDER_BATCH_ROWS (1000) materialize threshold was crossed at least \
         once mid-burst without losing or duplicating rows"
    );
    let null_count = src_ips.iter().filter(|v| v.is_none()).count();
    assert_eq!(
        null_count,
        N.div_ceil(7),
        "every 7th record had no src_ip and must round-trip as null through \
         the accumulator, including across the materialize boundary"
    );
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

#[tokio::test]
async fn suricata_local_start_emits_iceberg_descriptor_when_configured() {
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

    let cfg = SuricataLocalConfig {
        directory: parquet_dir.path().to_path_buf(),
        prefix: "suricata".to_string(),
        max_buffer_rows: 1, // flush immediately on first record
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 64,
    };

    let (handler, writer_task) = suricata_local_start(
        &cfg,
        parquet_sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        Some(descriptor_sink),
    );

    let src: std::net::SocketAddr = "127.0.0.1:47761".parse().unwrap();
    handler
        .handle_record(make_alert_record("10.0.0.1"), src)
        .await;

    // Drop the handler to close the channel; background task flushes on exit.
    drop(handler);
    tokio::time::timeout(std::time::Duration::from_secs(5), writer_task)
        .await
        .expect("writer task exits within 5s")
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
                assert_eq!(v["source"], "suricata");
                assert_eq!(v["file_format"], "PARQUET");
            }
        }
    }
    assert!(
        found,
        "expected at least one descriptor .json file under {descriptor_dir:?}"
    );
}
