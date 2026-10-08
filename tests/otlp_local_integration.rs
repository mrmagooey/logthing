//! OtlpRecords pushed through `otlp_local_start` land as typed Parquet on local disk,
//! partitioned by service, with the 65th service diverted to `_overflow`.

mod common;

use arrow::array::Array;
use chrono::Utc;
use logthing::config::OtlpLocalConfig;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::otlp_s3::{OtlpRecord, otlp_local_start};
use std::sync::Arc;

fn record(service: Option<&str>, body: &str) -> OtlpRecord {
    OtlpRecord {
        event_uuid: Some(logthing::ingest::new_event_uuid()),
        time: None,
        observed_time: None,
        received_at: Utc::now(),
        severity_number: Some(9),
        severity_text: Some("INFO".to_string()),
        body: Some(body.to_string()),
        service_name: service.map(str::to_string),
        service_namespace: None,
        service_instance_id: None,
        host_name: None,
        peer_addr: Some("127.0.0.1".to_string()),
        trace_id: None,
        span_id: None,
        flags: None,
        event_name: None,
        scope_name: None,
        scope_version: None,
        resource_attributes: serde_json::json!({}),
        attributes: serde_json::json!({}),
    }
}

async fn start(
    dir: &std::path::Path,
    max_partitions: usize,
) -> (
    logthing::forwarding::otlp_s3::OtlpHandler,
    tokio::task::JoinHandle<()>,
) {
    let sink = Arc::new(LocalDiskSink::new(dir.to_path_buf()).await.unwrap());
    let cfg = OtlpLocalConfig {
        directory: dir.to_path_buf(),
        prefix: "otlp".to_string(),
        flush_threshold_bytes: usize::MAX,
        flush_interval_secs: 3600,
        channel_capacity: 4096,
        max_buffer_rows: 100_000,
    };
    otlp_local_start(
        &cfg,
        sink,
        max_partitions,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    )
}

fn top_dirs(dir: &std::path::Path) -> std::collections::BTreeSet<String> {
    std::fs::read_dir(dir.join("otlp"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect()
}

#[tokio::test]
async fn otlp_rows_are_typed_and_partitioned_by_sanitized_service() {
    let tmp = tempfile::tempdir().unwrap();
    let (h, join) = start(tmp.path(), 64).await;
    h.try_send(record(Some("Checkout Svc"), "a")).unwrap();
    h.try_send(record(None, "no service")).unwrap();
    h.try_send(record(Some(""), "empty service")).unwrap();
    drop(h);
    join.await.unwrap();

    let dirs = top_dirs(tmp.path());
    assert_eq!(
        dirs,
        ["checkout_svc", "unknown"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    );
    let batches = common::read_all(tmp.path());
    let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    assert_eq!(rows, 3);
    let mut names = Vec::new();
    for b in &batches {
        assert_eq!(b.schema().fields().len(), 21);
        let sn = common::str_col(b, "service_name");
        for i in 0..b.num_rows() {
            names.push(if sn.is_null(i) {
                None
            } else {
                Some(sn.value(i).to_string())
            });
        }
    }
    names.sort();
    assert_eq!(
        names,
        vec![None, Some(String::new()), Some("Checkout Svc".to_string())]
    );
}

#[tokio::test]
async fn sixty_fifth_service_goes_to_overflow_with_raw_service_name() {
    let tmp = tempfile::tempdir().unwrap();
    let (h, join) = start(tmp.path(), 64).await;
    for i in 0..65 {
        h.try_send(record(Some(&format!("Svc {i:03}")), "x"))
            .unwrap();
    }
    drop(h);
    join.await.unwrap();

    let dirs = top_dirs(tmp.path());
    assert_eq!(dirs.len(), 65, "64 service dirs + _overflow: {dirs:?}");
    assert!(dirs.contains("_overflow"));
    let overflow_batches = common::read_all(&tmp.path().join("otlp").join("_overflow"));
    let b = &overflow_batches[0];
    assert_eq!(b.num_rows(), 1);
    assert_eq!(
        common::str_col(b, "service_name").value(0),
        "Svc 064",
        "raw value kept"
    );
}

#[tokio::test]
async fn many_rows_per_service_split_into_one_partition_each_via_the_accumulator() {
    let tmp = tempfile::tempdir().unwrap();
    let (h, join) = start(tmp.path(), 64).await;
    for i in 0..300 {
        let svc = if i % 2 == 0 { "Alpha" } else { "Beta" };
        h.try_send(record(Some(svc), &format!("{svc}-{i}")))
            .unwrap();
    }
    drop(h);
    join.await.unwrap();

    assert_eq!(
        top_dirs(tmp.path()),
        ["alpha", "beta"].iter().map(|s| s.to_string()).collect()
    );
    for (dir, raw, parity) in [("alpha", "Alpha", 0), ("beta", "Beta", 1)] {
        let batches = common::read_all(&tmp.path().join("otlp").join(dir));
        let mut bodies = Vec::new();
        for b in &batches {
            assert_eq!(b.schema().fields().len(), 21);
            let sn = common::str_col(b, "service_name");
            let body = common::str_col(b, "body");
            for i in 0..b.num_rows() {
                assert_eq!(sn.value(i), raw);
                bodies.push(body.value(i).to_string());
            }
        }
        bodies.sort();
        let mut want: Vec<String> = (0..300)
            .filter(|i| i % 2 == parity)
            .map(|i| format!("{raw}-{i}"))
            .collect();
        want.sort();
        assert_eq!(bodies, want, "{dir}");
    }
}

#[tokio::test]
async fn more_than_builder_batch_rows_per_service_keep_exact_counts_and_bodies() {
    // BUILDER_BATCH_ROWS is 1000: 1500 rows per service force at least one mid-stream
    // materialization of the live builder plus a final partial one.
    const PER_SVC: usize = 1500;
    let tmp = tempfile::tempdir().unwrap();
    let (h, join) = start(tmp.path(), 64).await;
    for i in 0..PER_SVC {
        for svc in ["Alpha", "Beta"] {
            h.send_or_drop(record(Some(svc), &format!("{svc}-{i}")))
                .await
                .unwrap();
        }
    }
    drop(h);
    join.await.unwrap();

    for (dir, raw) in [("alpha", "Alpha"), ("beta", "Beta")] {
        let batches = common::read_all(&tmp.path().join("otlp").join(dir));
        let mut bodies = Vec::new();
        for b in &batches {
            let sn = common::str_col(b, "service_name");
            let body = common::str_col(b, "body");
            for i in 0..b.num_rows() {
                assert_eq!(sn.value(i), raw);
                bodies.push(body.value(i).to_string());
            }
        }
        bodies.sort();
        let mut want: Vec<String> = (0..PER_SVC).map(|i| format!("{raw}-{i}")).collect();
        want.sort();
        assert_eq!(bodies.len(), PER_SVC, "{dir} row count");
        assert_eq!(bodies, want, "{dir}");
    }
}
