//! Integration test: Aggregator → real PartitionedParquetWriter → Parquet on
//! local disk, read back with a real Parquet reader.
//!
//! Needs no external service, so it runs unconditionally in CI.

use logthing::forwarding::aggregate::{
    AggKind, AggSpec, AggregateWriterHandle, Aggregator, CompiledRule, handlers, rule_schema,
    start_aggregate_writer,
};
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::zeek::ZeekRecord;
use logthing::zeek::listener::ZeekHandler;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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

fn dns_record(query: &str, client: &str) -> ZeekRecord {
    ZeekRecord {
        log_path: "dns".to_string(),
        fields: serde_json::json!({
            "_path": "dns",
            "query": query,
            "id.orig_h": client,
            "rtt": 5,
        }),
        received_at: chrono::Utc::now(),
    }
}

fn conn_record() -> ZeekRecord {
    ZeekRecord {
        log_path: "conn".to_string(),
        fields: serde_json::json!({"_path": "conn", "uid": "CNotAggregated"}),
        received_at: chrono::Utc::now(),
    }
}

fn dns_rule() -> CompiledRule {
    let group_by = vec!["query".to_string(), "id.orig_h".to_string()];
    let aggs = vec![AggSpec {
        kind: AggKind::Sum,
        field: "rtt".to_string(),
        column: "sum_rtt".to_string(),
    }];
    CompiledRule {
        name: Arc::from("dns_by_query"),
        source: "zeek".to_string(),
        stream: Some("dns".to_string()),
        group_by: group_by.clone(),
        aggs: aggs.clone(),
        schema: rule_schema(&group_by, &aggs),
    }
}

struct CountingZeek(AtomicUsize);

#[async_trait::async_trait]
impl ZeekHandler for CountingZeek {
    async fn handle_record(&self, _r: ZeekRecord, _s: std::net::SocketAddr) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn aggregated_counts_land_in_parquet_and_raw_records_are_suppressed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );

    let rules = vec![dns_rule()];
    let (handle, _writer_task) = start_aggregate_writer(
        &rules,
        "aggregate".to_string(),
        1, // 1s window so the test does not sleep long
        256,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );
    let handle: Arc<AggregateWriterHandle> = Arc::new(handle);

    let agg = Arc::new(Aggregator::new(rules, 1000));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let emit =
        agg.clone()
            .spawn_emit_task(vec![handle], std::time::Duration::from_secs(1), shutdown_rx);

    let inner = Arc::new(CountingZeek(AtomicUsize::new(0)));
    let decorated = handlers::AggregatingZeekHandler {
        agg: agg.clone(),
        inner: inner.clone(),
    };
    let src: std::net::SocketAddr = "127.0.0.1:47760".parse().unwrap();

    // 3 records for one group, 1 for another, plus a conn record with no rule.
    for _ in 0..3 {
        decorated
            .handle_record(dns_record("a.example", "10.0.0.1"), src)
            .await;
    }
    decorated
        .handle_record(dns_record("b.example", "10.0.0.2"), src)
        .await;
    decorated.handle_record(conn_record(), src).await;

    assert_eq!(
        inner.0.load(Ordering::SeqCst),
        1,
        "only the unaggregated conn record may reach the raw handler"
    );

    // Let the window close and the writer flush on its age trigger.
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    shutdown_tx.send(true).expect("shutdown");
    emit.await.expect("emit task joins");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let rule_dir = dir.path().join("aggregate/dns_by_query");
    assert!(rule_dir.is_dir(), "expected {rule_dir:?} to exist");
    let parquet_files: Vec<_> = walk_all_files(&rule_dir)
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "parquet"))
        .collect();
    assert!(
        !parquet_files.is_empty(),
        "expected a Parquet file under {rule_dir:?}"
    );

    use arrow::array::{Array, Float64Array, StringArray, UInt64Array};
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    let mut rows: Vec<(String, String, u64, Option<f64>)> = Vec::new();
    for file in &parquet_files {
        let bytes = std::fs::read(file).expect("read parquet");
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .expect("parquet builder");
        let schema = builder.schema().clone();
        for col in [
            "query",
            "id.orig_h",
            "count",
            "sum_rtt",
            "window_start",
            "window_end",
        ] {
            assert!(
                schema.field_with_name(col).is_ok(),
                "expected column '{col}' in the aggregate schema"
            );
        }
        let reader = builder.build().expect("parquet reader");
        for batch in reader {
            let batch = batch.expect("batch ok");
            let q = batch
                .column_by_name("query")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let c = batch
                .column_by_name("id.orig_h")
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
            let s = batch
                .column_by_name("sum_rtt")
                .unwrap()
                .as_any()
                .downcast_ref::<Float64Array>()
                .unwrap();
            for i in 0..batch.num_rows() {
                rows.push((
                    q.value(i).to_string(),
                    c.value(i).to_string(),
                    n.value(i),
                    (!s.is_null(i)).then(|| s.value(i)),
                ));
            }
        }
    }

    rows.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    assert_eq!(rows.len(), 2, "one row per distinct group, got {rows:?}");
    assert_eq!(rows[0].0, "a.example");
    assert_eq!(rows[0].1, "10.0.0.1");
    assert_eq!(rows[0].2, 3, "three records collapsed into one counted row");
    assert_eq!(rows[0].3, Some(15.0), "sum_rtt = 5 * 3");
    assert_eq!(rows[1].2, 1);
}
