//! Integration test: SflowRecord batches → sflow_local_start → real Parquet
//! files on local disk (both the "flow" and "counter" partitions), read back
//! with a real Parquet reader.
//!
//! Unlike `sflow_s3_integration.rs` (gated on a running MinIO), this test
//! needs no external service — local disk is always available — so it runs
//! unconditionally in CI.

use logthing::config::SflowLocalConfig;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::sflow_s3::sflow_local_start;
use logthing::sflow::listener::SflowHandler;
use logthing::sflow::{SampleType, SflowRecord};
use std::sync::Arc;

fn make_flow_record() -> SflowRecord {
    SflowRecord {
        sample_type: SampleType::Flow,
        exporter: "10.0.0.1".parse().unwrap(),
        received_at: chrono::Utc::now(),
        src_addr: Some("192.168.1.1".parse().unwrap()),
        dst_addr: Some("10.0.0.2".parse().unwrap()),
        src_port: Some(1234),
        dst_port: Some(443),
        ip_protocol: Some(6),
        sampling_rate: Some(512),
        input_ifindex: Some(1),
        output_ifindex: Some(2),
        if_index: None,
        if_type: None,
        if_speed: None,
        if_direction: None,
        if_in_octets: None,
        if_out_octets: None,
        if_in_ucast_pkts: None,
        if_out_ucast_pkts: None,
        if_in_errors: None,
        if_out_errors: None,
        extra: serde_json::json!([]),
    }
}

fn make_counter_record() -> SflowRecord {
    SflowRecord {
        sample_type: SampleType::Counter,
        exporter: "10.0.0.1".parse().unwrap(),
        received_at: chrono::Utc::now(),
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        ip_protocol: None,
        sampling_rate: None,
        input_ifindex: None,
        output_ifindex: None,
        if_index: Some(1),
        if_type: Some(6),
        if_speed: Some(1_000_000_000),
        if_direction: Some(1),
        if_in_octets: Some(1_000_000),
        if_out_octets: Some(500_000),
        if_in_ucast_pkts: Some(1000),
        if_out_ucast_pkts: Some(500),
        if_in_errors: Some(2),
        if_out_errors: Some(1),
        extra: serde_json::json!([]),
    }
}

#[tokio::test]
async fn sflow_samples_appear_as_parquet_on_local_disk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    let cfg = SflowLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "sflow".to_string(),
        max_buffer_rows: 1, // flush immediately on first push per partition
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 256,
    };

    let (handler, _writer_task) = sflow_local_start(
        &cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
    );

    let src: std::net::SocketAddr = "127.0.0.1:6343".parse().unwrap();
    handler
        .handle_samples(vec![make_flow_record(), make_counter_record()], src)
        .await;

    // Give the background task time to flush.
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // --- Verify the "flow" partition ---
    {
        let flow_dir = dir.path().join("sflow/flow");
        assert!(flow_dir.is_dir(), "expected {flow_dir:?} to exist");
        let parquet_files: Vec<_> = walk_all_files(&flow_dir)
            .into_iter()
            .filter(|p| p.extension().is_some_and(|ext| ext == "parquet"))
            .collect();
        assert!(
            !parquet_files.is_empty(),
            "expected at least one Parquet file under {flow_dir:?}"
        );

        let bytes = std::fs::read(&parquet_files[0]).expect("read parquet file");
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .expect("parquet builder for flow");
        let schema = builder.schema().clone();
        for col in ["sample_type", "src_addr", "sampling_rate", "extra"] {
            assert!(
                schema.field_with_name(col).is_ok(),
                "expected column '{col}' in flow schema"
            );
        }

        let mut reader = builder.build().expect("parquet reader for flow");
        let rb = reader
            .next()
            .expect("at least one batch")
            .expect("batch ok");
        assert_eq!(rb.num_rows(), 1);

        use arrow::array::StringArray;
        let src_addr = rb
            .column_by_name("src_addr")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(src_addr.value(0), "192.168.1.1");
    }

    // --- Verify the "counter" partition ---
    {
        let counter_dir = dir.path().join("sflow/counter");
        assert!(counter_dir.is_dir(), "expected {counter_dir:?} to exist");
        let parquet_files: Vec<_> = walk_all_files(&counter_dir)
            .into_iter()
            .filter(|p| p.extension().is_some_and(|ext| ext == "parquet"))
            .collect();
        assert!(
            !parquet_files.is_empty(),
            "expected at least one Parquet file under {counter_dir:?}"
        );

        let bytes = std::fs::read(&parquet_files[0]).expect("read parquet file");
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .expect("parquet builder for counter");
        let schema = builder.schema().clone();
        for col in ["sample_type", "if_speed", "if_in_octets", "extra"] {
            assert!(
                schema.field_with_name(col).is_ok(),
                "expected column '{col}' in counter schema"
            );
        }

        let mut reader = builder.build().expect("parquet reader for counter");
        let rb = reader
            .next()
            .expect("at least one batch")
            .expect("batch ok");
        assert_eq!(rb.num_rows(), 1);

        use arrow::array::UInt64Array;
        let if_speed = rb
            .column_by_name("if_speed")
            .unwrap()
            .as_any()
            .downcast_ref::<UInt64Array>()
            .unwrap();
        assert_eq!(if_speed.value(0), 1_000_000_000u64);
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
