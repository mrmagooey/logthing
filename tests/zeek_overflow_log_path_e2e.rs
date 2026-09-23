//! End-to-end test: real Zeek TCP ingest → real `ZeekListener` → real
//! `zeek_local_start` writer → real Parquet files on local disk, proving a
//! typed record whose partition has overflowed into `"_overflow"` keeps its
//! real `log_path` in the flushed Parquet rather than a hardcoded
//! placeholder.
//!
//! Regression under test: `ZeekSink::to_record_batch`'s else-branch (taken
//! whenever the caller-supplied `schema` doesn't match the entry the record's
//! own `log_path` resolves to -- i.e. the record's partition overflowed) used
//! to build its envelope row via `get_schema_entry("_overflow_nonexistent_")`,
//! hardcoding that placeholder string as the row's `log_path` regardless of
//! what the record actually carried. Fixed by mapping through
//! `crate::zeek::schema::map_envelope(&record.fields, &record.log_path, ...)`
//! directly, using the record's real path.
//!
//! `zeek_local_start` hard-codes `max_partitions` at 256 (the old
//! `MAX_ZEEK_STREAMS` value) and `ZeekLocalConfig` does not expose the field
//! (see `DEFAULT_MAX_ZEEK_PARTITIONS` in `src/forwarding/zeek_s3.rs`), so
//! this test cannot configure a small cap. Instead it drives 256 distinct
//! `_path`s (`p0`..`p255`) to fill every partition slot, then sends one more
//! (`dns`, typed) that is forced into the `"_overflow"` buffer.
//!
//! No global metrics recorder is installed here, so this file is free to
//! coexist with other `#[tokio::test]`s in the same binary (unlike
//! `tests/zeek_received_metric_e2e.rs`).

use logthing::config::ZeekLocalConfig;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::zeek_s3::{MultiZeekHandler, zeek_local_start};
use logthing::zeek::listener::{ZeekListener, ZeekListenerConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Reserve an ephemeral port: bind a probe listener to 127.0.0.1:0, read the
/// assigned port, then drop the listener so the real component can bind it.
async fn reserve_port() -> u16 {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    probe.local_addr().unwrap().port()
}

fn filler_line(path: &str, uid: &str) -> String {
    // An unmodelled `_path`: lands in its own per-path envelope partition
    // until the 256-partition cap is exceeded.
    serde_json::json!({
        "_path": path,
        "ts": 1700000000.0,
        "uid": uid,
    })
    .to_string()
}

fn dns_line(uid: &str) -> String {
    serde_json::json!({
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
    })
    .to_string()
}

fn walk_all_parquet_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "parquet") {
                out.push(path);
            }
        }
    }
    out
}

#[tokio::test]
async fn overflowed_typed_record_keeps_its_real_log_path_on_disk() {
    let zeek_port = reserve_port().await;

    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    let zeek_local_cfg = ZeekLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "zeek".to_string(),
        max_buffer_rows: 100_000,
        flush_threshold_bytes: 100_000_000,
        flush_interval_secs: 3600,
        channel_capacity: 512,
    };
    let (zeek_handler, writer_task) = zeek_local_start(
        &zeek_local_cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );
    let handler: Arc<dyn logthing::zeek::listener::ZeekHandler> =
        Arc::new(MultiZeekHandler(vec![Arc::new(zeek_handler)]));

    let zeek_listener_config = ZeekListenerConfig {
        tcp_port: zeek_port,
        bind_address: "127.0.0.1".to_string(),
    };
    let zeek_listener = ZeekListener::new(zeek_listener_config, handler.clone());
    let (zeek_shutdown_tx, zeek_shutdown_rx) = tokio::sync::watch::channel(false);
    let zeek_task = tokio::spawn(async move {
        zeek_listener
            .start_with_shutdown(zeek_shutdown_rx)
            .await
            .expect("zeek listener run must not error");
    });

    // --- Wait for the zeek TCP port to accept connections ---
    let mut zeek_stream = None;
    for _ in 0..50 {
        match TcpStream::connect(("127.0.0.1", zeek_port)).await {
            Ok(s) => {
                zeek_stream = Some(s);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    let mut zeek_stream = zeek_stream.expect("zeek TCP listener did not accept in time");

    // 256 distinct unmodelled `_path`s claim every partition slot
    // (`DEFAULT_MAX_ZEEK_PARTITIONS = 256`); the 257th distinct path (a
    // typed `dns` record) is forced into the shared `"_overflow"` buffer.
    let mut lines: Vec<String> = (0..256)
        .map(|i| filler_line(&format!("p{i}"), &format!("Filler{i}")))
        .collect();
    lines.push(dns_line("DOverflow001"));

    for line in &lines {
        zeek_stream
            .write_all(format!("{line}\n").as_bytes())
            .await
            .expect("write zeek NDJSON line");
    }
    zeek_stream.shutdown().await.expect("shutdown write half");
    drop(zeek_stream);

    // Give the listener a moment to finish parsing/dispatching the lines
    // before tearing down.
    tokio::time::sleep(Duration::from_millis(500)).await;

    zeek_shutdown_tx
        .send(true)
        .expect("zeek shutdown signal must send");
    tokio::time::timeout(Duration::from_secs(5), zeek_task)
        .await
        .expect("zeek listener task must join after shutdown")
        .expect("zeek listener task must not panic");

    // Drop the handler (closes the writer's channel) and await the writer
    // task's shutdown flush.
    drop(handler);
    tokio::time::timeout(Duration::from_secs(5), writer_task)
        .await
        .expect("writer task must exit within 5s")
        .expect("writer task must not panic");

    let overflow_dir = dir.path().join("zeek/_overflow");
    let parquet_files = walk_all_parquet_files(&overflow_dir);
    assert!(
        !parquet_files.is_empty(),
        "expected at least one Parquet file under {overflow_dir:?}"
    );

    use arrow::array::{Array, StringArray};
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    let mut log_paths = std::collections::HashSet::new();
    for file_path in &parquet_files {
        let bytes = std::fs::read(file_path).expect("read parquet file");
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .expect("parquet builder for _overflow");
        let reader = builder.build().expect("parquet reader for _overflow");
        for rb in reader {
            let rb = rb.expect("batch ok");
            let col = rb
                .column_by_name("log_path")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            for i in 0..col.len() {
                log_paths.insert(col.value(i).to_string());
            }
        }
    }
    assert!(
        log_paths.contains("dns"),
        "expected the overflowed typed record to keep its real log_path \"dns\"; \
         got {log_paths:?}"
    );
    assert!(
        !log_paths.contains("_overflow_nonexistent_"),
        "regression: overflowed rows must never carry the placeholder log_path; \
         got {log_paths:?}"
    );
}
