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
        None,
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
    for col in ["export_time", "flow_start", "flow_end"] {
        assert_eq!(
            schema.field_with_name(col).unwrap().data_type(),
            &arrow::datatypes::DataType::Timestamp(
                arrow::datatypes::TimeUnit::Microsecond,
                Some("UTC".into())
            ),
            "on-disk Parquet '{col}' column must be a microsecond UTC timestamp"
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

#[tokio::test]
async fn ipfix_local_start_emits_iceberg_descriptor_when_configured() {
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

    let cfg = IpfixLocalConfig {
        directory: parquet_dir.path().to_path_buf(),
        prefix: "ipfix".to_string(),
        max_buffer_rows: 1, // flush immediately on first push
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 64,
    };

    let (handler, writer_task) = ipfix_local_start(
        &cfg,
        parquet_sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        Some(descriptor_sink),
    );

    let src: std::net::SocketAddr = "127.0.0.1:4739".parse().unwrap();
    let flow = make_flow_record("10.1.2.3", 1024);
    handler.handle_flows(vec![flow], src).await;

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
                assert_eq!(v["source"], "ipfix");
                assert_eq!(v["file_format"], "PARQUET");
            }
        }
    }
    assert!(
        found,
        "expected at least one descriptor .json file under {descriptor_dir:?}"
    );
}

/// Drives multi-flow `Vec<FlowRecord>` pushes across the real writer path
/// (`ipfix_local_start`) far enough to cross `BUILDER_BATCH_ROWS` (1000,
/// `buffered_writer.rs`) -- the point at which `push()` force-materializes
/// the live `FlowRecordAccumulator` into a stored batch mid-stream, before
/// any flush. Regression target: `FlowRecordAccumulator::try_append` must
/// increment its row counter once per FLOW, not once per PUSH -- a
/// once-per-push counter would make this take 1000 datagrams (not ~3) to
/// cross the threshold, and would silently corrupt every row_count-driven
/// behavior downstream (this exact flush trigger included). Asserts the
/// exact total row count across every Parquet file written, not just that
/// "some" data landed.
#[tokio::test]
async fn ipfix_flows_crossing_builder_batch_rows_land_exact_row_count_on_disk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    let cfg = IpfixLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "ipfix".to_string(),
        max_buffer_rows: 100_000,          // row-count flush trigger must not fire early
        flush_threshold_bytes: usize::MAX, // byte flush trigger must not fire early
        flush_interval_secs: 3600,         // age trigger must not fire
        channel_capacity: 256,
    };

    let (handler, writer_task) = ipfix_local_start(
        &cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );

    let src: std::net::SocketAddr = "127.0.0.1:4739".parse().unwrap();

    // 3 datagrams of 400 flows each = 1200 total flows, crossing
    // BUILDER_BATCH_ROWS=1000 partway through the 3rd push.
    const FLOWS_PER_DATAGRAM: usize = 400;
    const DATAGRAMS: usize = 3;
    for d in 0..DATAGRAMS {
        let flows: Vec<FlowRecord> = (0..FLOWS_PER_DATAGRAM)
            .map(|i| make_flow_record("10.1.2.3", (d * FLOWS_PER_DATAGRAM + i) as u64))
            .collect();
        handler.handle_flows(flows, src).await;
    }

    // Drop the handler to close the channel; background task flushes
    // whatever remains (materialized + still-live) on exit.
    drop(handler);
    tokio::time::timeout(std::time::Duration::from_secs(5), writer_task)
        .await
        .expect("writer task must exit within 5s")
        .expect("writer task must not panic");

    let ipfix_dir = dir.path().join("ipfix");
    let parquet_files: Vec<_> = walk_all_files(&ipfix_dir)
        .into_iter()
        .filter(|p| p.extension().is_some_and(|ext| ext == "parquet"))
        .collect();
    assert!(
        !parquet_files.is_empty(),
        "expected at least one Parquet file under {ipfix_dir:?}"
    );

    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    let mut total_rows = 0usize;
    for file_path in &parquet_files {
        let bytes = std::fs::read(file_path).expect("read parquet file");
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .expect("parquet builder");
        let reader = builder.build().expect("parquet reader");
        for batch in reader {
            total_rows += batch.expect("batch ok").num_rows();
        }
    }

    assert_eq!(
        total_rows,
        FLOWS_PER_DATAGRAM * DATAGRAMS,
        "exact total row count across every Parquet file must match every flow pushed, \
         not just some of them -- a once-per-push (rather than once-per-flow) row counter \
         would silently drop rows from this total well before it ever surfaced as a lost file"
    );
}
