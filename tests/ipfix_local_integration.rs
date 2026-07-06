//! Integration test: FlowRecord batches → ipfix_local_start → real Parquet
//! files on local disk, read back with a real Parquet reader.
//!
//! Unlike `ipfix_s3_integration.rs` (gated on a running MinIO), this test
//! needs no external service — local disk is always available — so it runs
//! unconditionally in CI.

use logthing::config::IpfixLocalConfig;
use logthing::forwarding::ipfix_s3::ipfix_local_start;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::ipfix::FlowRecord;
use logthing::ipfix::listener::IpfixHandler;
use std::sync::Arc;

fn make_flow_record(src_addr: &str, octet_count: u64) -> FlowRecord {
    FlowRecord {
        observation_domain_id: 1,
        template_id: 256,
        protocol_version: 10,
        exporter: "10.0.0.1".parse().unwrap(),
        export_time: chrono::Utc::now(),
        src_addr: Some(src_addr.parse().unwrap()),
        dst_addr: Some("192.168.1.1".parse().unwrap()),
        src_port: Some(1234),
        dst_port: Some(80),
        ip_protocol: Some(6),
        octet_delta_count: Some(octet_count),
        packet_delta_count: Some(10),
        flow_start: None,
        flow_end: None,
        tcp_flags: Some(0x02),
        input_interface: Some(1),
        output_interface: Some(2),
        extra: serde_json::json!({}),
    }
}

#[tokio::test]
async fn ipfix_flows_appear_as_parquet_on_local_disk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    let cfg = IpfixLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "ipfix".to_string(),
        max_buffer_rows: 1, // flush immediately on first push
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 256,
    };

    let (handler, _writer_task) = ipfix_local_start(
        &cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
    );

    let src: std::net::SocketAddr = "127.0.0.1:4739".parse().unwrap();
    let flows = vec![
        make_flow_record("10.1.2.3", 1024),
        make_flow_record("10.1.2.4", 2048),
    ];
    handler.handle_flows(flows, src).await;

    // Give the background task time to flush.
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let ipfix_dir = dir.path().join("ipfix");
    assert!(ipfix_dir.is_dir(), "expected {ipfix_dir:?} to exist");

    let parquet_files: Vec<_> = walk_all_files(&ipfix_dir)
        .into_iter()
        .filter(|p| p.extension().is_some_and(|ext| ext == "parquet"))
        .collect();
    assert!(
        !parquet_files.is_empty(),
        "expected at least one Parquet file under {ipfix_dir:?}"
    );

    let file_path = &parquet_files[0];
    let bytes = std::fs::read(file_path).expect("read parquet file");

    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
        .expect("parquet builder");
    let schema = builder.schema().clone();
    for col in [
        "observation_domain_id",
        "exporter",
        "src_addr",
        "octet_delta_count",
        "extra",
    ] {
        assert!(
            schema.field_with_name(col).is_ok(),
            "expected column '{col}' in flow_record_schema"
        );
    }

    let mut reader = builder.build().expect("parquet reader");
    let rb = reader
        .next()
        .expect("at least one batch")
        .expect("batch ok");
    assert_eq!(rb.num_rows(), 2);

    use arrow::array::StringArray;
    let src_addr_col = rb
        .column_by_name("src_addr")
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(src_addr_col.value(0), "10.1.2.3");
    assert_eq!(src_addr_col.value(1), "10.1.2.4");

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
