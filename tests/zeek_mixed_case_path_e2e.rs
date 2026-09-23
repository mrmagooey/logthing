//! End-to-end test: real Zeek TCP ingest → real `ZeekListener` → real
//! `zeek_local_start` writer → real Parquet files on local disk.
//!
//! Regression under test: `ZeekSink::partition()`/`schema()` key buffers by
//! `sanitize_log_path(raw)` (which lowercases), but `get_schema_entry(&record
//! .log_path)` used to look up the case-sensitive schema registry with the
//! RAW path. A `"_path":"Conn"` record therefore resolved to the envelope
//! schema while its buffer (keyed by the sanitized `"conn"` partition) stayed
//! typed conn — the envelope-shaped batch got pushed into the typed conn
//! buffer, and every later flush of that buffer failed in `concat_batches`
//! forever. Fixed in `get_schema_entry` by falling back to a
//! `sanitize_log_path`-normalized registry lookup, with a push()-time schema
//! guard as defense in depth.
//!
//! This test proves the fix end to end, through the outermost interface
//! (real TCP), with three real spellings of the same stream landing in the
//! same on-disk conn buffer and surviving a real flush.
//!
//! No global metrics recorder is installed here, so no `logthing::server::
//! Server` is needed (unlike `tests/zeek_received_metric_e2e.rs`) — this file
//! is free to coexist with other `#[tokio::test]`s in the same binary.

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

fn conn_line(path: &str, uid: &str) -> String {
    serde_json::json!({
        "_path": path,
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
async fn mixed_case_and_rotated_conn_paths_join_the_same_flushed_buffer() {
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
        channel_capacity: 256,
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

    // Three real spellings of the same stream: plain, mixed-case, and a
    // rotated mixed-case archive filename (stripped by `normalize_log_path`
    // before it ever reaches `get_schema_entry`). All three must accumulate
    // into the single on-disk `zeek/conn/` buffer.
    let lines = [
        conn_line("conn", "Plain001"),
        conn_line("Conn", "Mixed001"),
        conn_line("CONN.2026-08-14-16-08-44", "Rotated001"),
    ];
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
    tokio::time::sleep(Duration::from_millis(200)).await;

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

    let conn_dir = dir.path().join("zeek/conn");
    let parquet_files = walk_all_parquet_files(&conn_dir);
    assert!(
        !parquet_files.is_empty(),
        "expected at least one Parquet file under {conn_dir:?}"
    );

    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    let mut total_rows = 0usize;
    for file_path in &parquet_files {
        let bytes = std::fs::read(file_path).expect("read parquet file");
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .expect("parquet builder for conn");
        let reader = builder.build().expect("parquet reader for conn");
        for rb in reader {
            total_rows += rb.expect("batch ok").num_rows();
        }
    }
    assert_eq!(
        total_rows, 3,
        "conn, Conn, and CONN.<rotation-suffix> must all land in the same \
         flushed conn Parquet file(s), proving the case/rotation mismatch \
         can no longer jam a flush"
    );
}
