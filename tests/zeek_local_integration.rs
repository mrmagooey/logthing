//! Integration test: ZeekRecord → zeek_local_start → real Parquet files on
//! local disk, read back with a real Parquet reader.
//!
//! Unlike `zeek_s3_integration.rs` (gated on a running MinIO), this test needs
//! no external service — local disk is always available — so it runs
//! unconditionally in CI.

use logthing::config::ZeekLocalConfig;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::zeek_s3::zeek_local_start;
use logthing::zeek::ZeekRecord;
use logthing::zeek::listener::ZeekHandler;
use std::sync::Arc;

fn make_conn_record(uid: &str) -> ZeekRecord {
    ZeekRecord {
        log_path: "conn".to_string(),
        fields: serde_json::json!({
            "_path": "conn",
            "ts": 1700000000.0,
            "uid": uid,
            "id.orig_h": "10.0.0.1",
            "id.orig_p": 12345,
            "id.resp_h": "10.0.0.2",
            "id.resp_p": 443,
            "proto": "tcp",
            "conn_state": "SF",
            "orig_bytes": 1024,
            "resp_bytes": 8192,
        }),
        received_at: chrono::Utc::now(),
    }
}

fn make_dns_record(uid: &str) -> ZeekRecord {
    ZeekRecord {
        log_path: "dns".to_string(),
        fields: serde_json::json!({
            "_path": "dns",
            "ts": 1700000100.0,
            "uid": uid,
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 12345,
            "id.resp_h": "8.8.8.8",
            "id.resp_p": 53,
            "query": "example.com",
            "qtype_name": "A",
            "rcode_name": "NOERROR",
        }),
        received_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn zeek_records_appear_as_parquet_on_local_disk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    let cfg = ZeekLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "zeek".to_string(),
        max_buffer_rows: 1, // flush immediately on first record per partition
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 256,
    };

    let (handler, _writer_task) = zeek_local_start(
        &cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );

    let src: std::net::SocketAddr = "127.0.0.1:47760".parse().unwrap();
    handler
        .handle_record(make_conn_record("CLocal001"), src)
        .await;
    handler
        .handle_record(make_dns_record("DLocal001"), src)
        .await;

    // Give the background task time to flush (max_buffer_rows=1 and
    // flush_threshold_bytes=1 both trigger flush on the first push per partition).
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // --- Verify the typed `conn` record under zeek/conn/ ---
    {
        let conn_dir = dir.path().join("zeek/conn");
        assert!(conn_dir.is_dir(), "expected {conn_dir:?} to exist");
        // Keys are nested under year=/month=/day=/ partition segments (see
        // `build_key` in buffered_writer.rs), not flat under `conn_dir`, so
        // find the actual `.parquet` file recursively rather than assuming
        // it's a direct child.
        let parquet_files: Vec<_> = walk_all_files(&conn_dir)
            .into_iter()
            .filter(|p| p.extension().is_some_and(|ext| ext == "parquet"))
            .collect();
        assert!(
            !parquet_files.is_empty(),
            "expected at least one Parquet file under {conn_dir:?}"
        );

        let file_path = &parquet_files[0];
        let bytes = std::fs::read(file_path).expect("read parquet file");

        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .expect("parquet builder for conn");
        let schema = builder.schema().clone();
        for col in ["ts", "uid", "id_orig_h", "proto", "conn_state", "_extra"] {
            assert!(
                schema.field_with_name(col).is_ok(),
                "expected column '{col}' in conn schema"
            );
        }
        assert_eq!(
            schema.field_with_name("ts").unwrap().data_type(),
            &arrow::datatypes::DataType::Timestamp(
                arrow::datatypes::TimeUnit::Microsecond,
                Some("UTC".into())
            ),
            "on-disk Parquet ts column must be a microsecond UTC timestamp"
        );

        let mut reader = builder.build().expect("parquet reader for conn");
        let rb = reader
            .next()
            .expect("at least one batch")
            .expect("batch ok");
        assert_eq!(rb.num_rows(), 1);

        use arrow::array::StringArray;
        let uid = rb
            .column_by_name("uid")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(uid.value(0), "CLocal001");
    }

    // --- Verify the typed `dns` record under zeek/dns/ ---
    {
        let dns_dir = dir.path().join("zeek/dns");
        assert!(dns_dir.is_dir(), "expected {dns_dir:?} to exist");
        let parquet_files: Vec<_> = walk_all_files(&dns_dir)
            .into_iter()
            .filter(|p| p.extension().is_some_and(|ext| ext == "parquet"))
            .collect();
        assert!(
            !parquet_files.is_empty(),
            "expected at least one Parquet file under {dns_dir:?}"
        );

        let file_path = &parquet_files[0];
        let bytes = std::fs::read(file_path).expect("read parquet file");

        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .expect("parquet builder for dns");
        let mut reader = builder.build().expect("parquet reader for dns");
        let rb = reader
            .next()
            .expect("at least one batch")
            .expect("batch ok");
        assert_eq!(rb.num_rows(), 1);

        use arrow::array::StringArray;
        let uid = rb
            .column_by_name("uid")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(uid.value(0), "DLocal001");
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

/// Pushes 1500 real conn records through the real pipeline (`ZeekS3Handler`
/// → `PartitionedParquetWriter` → `LocalDiskSink`), crossing the
/// `BUILDER_BATCH_ROWS` (1000) threshold in `ConnAccumulator`'s live builder
/// mid-burst — proving the amortized builder correctly materializes once at
/// row 1000 and resumes accumulating the remaining 500 rows in a fresh
/// builder, rather than silently dropping or corrupting rows across that
/// boundary. Flush thresholds are set high so the only disk flush is the
/// synchronous `flush_all` fired when the writer task's channel closes,
/// which merges the materialized 1000-row batch and the 500-row remainder
/// into a single real Parquet file via the real `ArrowWriter`/`concat_batches`
/// path — read back here with the real `parquet::arrow::arrow_reader`.
#[tokio::test]
async fn zeek_local_burst_of_1500_conn_records_crosses_builder_batch_rows() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    // Row/byte/time thresholds all high enough that no in-loop flush fires;
    // the only flush is the shutdown `flush_all` once the handler is
    // dropped. `channel_capacity` is comfortably above the record count so
    // `try_send` (non-blocking) never drops a record under the
    // single-threaded test runtime.
    let cfg = ZeekLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "zeek".to_string(),
        max_buffer_rows: 100_000,
        flush_threshold_bytes: 100_000_000,
        flush_interval_secs: 3600,
        channel_capacity: 2000,
    };

    let (handler, writer_task) = zeek_local_start(
        &cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );

    let src: std::net::SocketAddr = "127.0.0.1:47761".parse().unwrap();
    const N: usize = 1500;
    for i in 0..N {
        handler
            .handle_record(make_conn_record(&format!("CBurst{i:04}")), src)
            .await;
    }

    // Drop the handler to close the channel; the writer task's shutdown
    // path drains any in-flight flushes and then performs one final,
    // synchronous `flush_all` covering everything still buffered.
    drop(handler);
    tokio::time::timeout(std::time::Duration::from_secs(10), writer_task)
        .await
        .expect("writer task exits within 10s")
        .expect("writer task must not panic");

    let conn_dir = dir.path().join("zeek/conn");
    assert!(conn_dir.is_dir(), "expected {conn_dir:?} to exist");
    let parquet_files: Vec<_> = walk_all_files(&conn_dir)
        .into_iter()
        .filter(|p| p.extension().is_some_and(|ext| ext == "parquet"))
        .collect();
    assert!(
        !parquet_files.is_empty(),
        "expected at least one Parquet file under {conn_dir:?}"
    );

    use arrow::array::StringArray;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    let mut uids: Vec<String> = Vec::with_capacity(N);
    for file_path in &parquet_files {
        let bytes = std::fs::read(file_path).expect("read parquet file");
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .expect("parquet builder for conn burst");
        let reader = builder.build().expect("parquet reader for conn burst");
        for rb in reader {
            let rb = rb.expect("batch ok");
            let uid_col = rb
                .column_by_name("uid")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            for i in 0..rb.num_rows() {
                uids.push(uid_col.value(i).to_string());
            }
        }
    }

    assert_eq!(
        uids.len(),
        N,
        "expected exactly {N} rows across all conn Parquet files, proving the \
         BUILDER_BATCH_ROWS (1000) materialize threshold was crossed at least \
         once mid-burst without losing or duplicating rows"
    );
    assert_eq!(
        uids[0], "CBurst0000",
        "first record's uid must survive the round trip"
    );
    assert_eq!(
        uids[500], "CBurst0500",
        "a mid-burst record (inside the first materialized 1000-row batch) must survive the round trip"
    );
    assert_eq!(
        uids[N - 1],
        "CBurst1499",
        "last record's uid must survive the round trip"
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
async fn zeek_local_start_emits_iceberg_descriptor_when_configured() {
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

    let cfg = ZeekLocalConfig {
        directory: parquet_dir.path().to_path_buf(),
        prefix: "zeek".to_string(),
        max_buffer_rows: 1, // flush immediately on first record
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 64,
    };

    let (handler, writer_task) = zeek_local_start(
        &cfg,
        parquet_sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        Some(descriptor_sink),
    );

    let src: std::net::SocketAddr = "127.0.0.1:47760".parse().unwrap();
    handler
        .handle_record(make_conn_record("CDescriptor001"), src)
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
                assert_eq!(v["source"], "zeek");
                assert_eq!(v["file_format"], "PARQUET");
            }
        }
    }
    assert!(
        found,
        "expected at least one descriptor .json file under {descriptor_dir:?}"
    );
}
