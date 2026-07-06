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
