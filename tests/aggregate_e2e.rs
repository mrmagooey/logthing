//! End-to-end: NDJSON over a real TCP socket → Zeek listener → aggregating
//! handler → Parquet on local disk. Exercises the whole path through the
//! outermost interface, with no in-process shortcuts around the listener.

use logthing::forwarding::aggregate::{
    AggregateWriterHandle, Aggregator, CompiledRule, handlers, rule_schema, start_aggregate_writer,
};
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::zeek::listener::{ZeekListener, ZeekListenerConfig};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

fn walk_all_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk_all_files(&path));
        } else {
            out.push(path);
        }
    }
    out
}

#[tokio::test]
async fn ndjson_over_tcp_becomes_an_aggregated_parquet_table() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );

    let group_by = vec!["query".to_string()];
    let rules = vec![CompiledRule {
        name: Arc::from("dns_by_query"),
        source: "zeek".to_string(),
        stream: Some("dns".to_string()),
        group_by: group_by.clone(),
        aggs: Vec::new(),
        schema: rule_schema(&group_by, &[]),
    }];

    let (handle, _writer_task) = start_aggregate_writer(
        &rules,
        "aggregate".to_string(),
        1,
        256,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );
    let handle: Arc<AggregateWriterHandle> = Arc::new(handle);

    let agg = Arc::new(Aggregator::new(rules, 1000));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let emit = agg.clone().spawn_emit_task(
        vec![handle],
        std::time::Duration::from_secs(1),
        shutdown_rx.clone(),
    );

    let decorated: Arc<dyn logthing::zeek::listener::ZeekHandler> =
        Arc::new(handlers::AggregatingZeekHandler {
            agg: agg.clone(),
            inner: Arc::new(logthing::zeek::listener::DefaultZeekHandler),
        });

    // Bind an ephemeral port so parallel test runs never collide.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe bind");
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let listener_cfg = ZeekListenerConfig {
        tcp_port: port,
        bind_address: "127.0.0.1".to_string(),
    };
    let listener_shutdown = shutdown_rx.clone();
    let listener_task = tokio::spawn(async move {
        let listener = ZeekListener::new(listener_cfg, decorated);
        let _ = listener.start_with_shutdown(listener_shutdown).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Speak the wire protocol: newline-delimited JSON over TCP.
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to the zeek listener");
    for _ in 0..4 {
        stream
            .write_all(b"{\"_path\":\"dns\",\"query\":\"noisy.example\"}\n")
            .await
            .expect("write dns line");
    }
    stream
        .write_all(b"{\"_path\":\"dns\",\"query\":\"quiet.example\"}\n")
        .await
        .expect("write dns line");
    stream.flush().await.expect("flush");
    drop(stream);

    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    shutdown_tx.send(true).expect("shutdown");
    emit.await.expect("emit task joins");
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), listener_task).await;
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let rule_dir = dir.path().join("aggregate/dns_by_query");
    let parquet_files: Vec<_> = walk_all_files(&rule_dir)
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "parquet"))
        .collect();
    assert!(
        !parquet_files.is_empty(),
        "expected aggregated Parquet under {rule_dir:?}"
    );

    use arrow::array::{StringArray, UInt64Array};
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    let mut counts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for file in &parquet_files {
        let bytes = std::fs::read(file).expect("read parquet");
        let reader = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .expect("parquet builder")
            .build()
            .expect("parquet reader");
        for batch in reader {
            let batch = batch.expect("batch ok");
            let q = batch
                .column_by_name("query")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let n = batch
                .column_by_name("count")
                .unwrap()
                .as_any()
                .downcast_ref::<UInt64Array>()
                .unwrap();
            for i in 0..batch.num_rows() {
                *counts.entry(q.value(i).to_string()).or_default() += n.value(i);
            }
        }
    }

    assert_eq!(
        counts.get("noisy.example").copied(),
        Some(4),
        "four identical queries must collapse to one row with count=4, got {counts:?}"
    );
    assert_eq!(counts.get("quiet.example").copied(), Some(1));
}
