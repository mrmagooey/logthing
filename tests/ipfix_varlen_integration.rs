//! Integration test: RFC 7011 §7 variable-length field decoding over a real
//! `IpfixListener` UDP socket, feeding a real `ipfix_local_start` writer.
//!
//! Pattern: `tests/ipfix_local_integration.rs` (real writer -> Parquet on
//! local disk) combined with `tests/listener_ip_whitelist_integration.rs`
//! (a real `IpfixListener` driven over an actual UDP socket via
//! `start_with_shutdown`). Before the fix, a template containing a
//! variable-length field (`0xFFFF`) made `parse_ipfix_data_set` sum
//! `record_len >= 65535`, so no data set built from it ever decoded a
//! record -- silently. This test proves the wire-to-Parquet path decodes
//! such templates instead of dropping them.

use logthing::config::IpfixLocalConfig;
use logthing::forwarding::ipfix_s3::ipfix_local_start;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::ipfix::listener::{IpfixHandler, IpfixListener, IpfixListenerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::{Duration, sleep, timeout};

/// IPFIX message #1: a template set declaring template 256 with one
/// variable-length field (IE 97 -- not in `ie_info`'s curated table, so its
/// value lands hex-encoded in `extra["ie97"]`).
///
/// Message header (16) + template set (4 hdr + 4 tmpl_id/field_count + 4
/// field = 12) = 28 bytes total.
const TEMPLATE_MSG: &[u8] = &[
    0x00, 0x0A, // version = 10
    0x00, 0x1C, // total length = 28
    0x67, 0x5C, 0xB0, 0x20, // export_time
    0x00, 0x00, 0x00, 0x01, // sequence
    0x00, 0x00, 0x00, 0x00, // observation domain id = 0
    // Template Set (12 bytes: 4 hdr + 8 body)
    0x00, 0x02, // set id = 2 (Template Set)
    0x00, 0x0C, // length = 12
    0x01, 0x00, // template id = 256
    0x00, 0x01, // field count = 1
    0x00, 0x61, 0xFF, 0xFF, // ie 97, length 0xFFFF (variable-length)
];

/// IPFIX message #2: a data set for template 256 with 2 records, each a
/// 1-byte-length varlen value `"abc"`.
///
/// Message header (16) + data set (4 hdr + 2*(1+3) = 8 body) = 28 bytes
/// total.
const DATA_MSG: &[u8] = &[
    0x00, 0x0A, // version = 10
    0x00, 0x1C, // total length = 28
    0x67, 0x5C, 0xB0, 0x20, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    // Data Set (12 bytes: 4 hdr + 8 body)
    0x01, 0x00, // set id = 256
    0x00, 0x0C, // length = 12
    0x03, b'a', b'b', b'c', // record 1: len=3, "abc"
    0x03, b'a', b'b', b'c', // record 2: len=3, "abc"
];

#[tokio::test]
async fn ipfix_varlen_records_land_as_parquet_rows_with_hex_extra() {
    // --- real Parquet writer, same as ipfix_local_integration.rs ---
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
    let (handler, writer_task) = ipfix_local_start(
        &cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );
    let handler: Arc<dyn IpfixHandler> = Arc::new(handler);

    // --- real IpfixListener over a real UDP socket ---
    let udp_port = {
        let tmp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = tmp.local_addr().unwrap().port();
        drop(tmp);
        port
    };
    let listener_config = IpfixListenerConfig {
        udp_port,
        bind_address: "127.0.0.1".to_string(),
        ..IpfixListenerConfig::default()
    };
    let listener = IpfixListener::new(listener_config, handler);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let listener_task = tokio::spawn(async move {
        listener.start_with_shutdown(shutdown_rx).await.ok();
    });
    sleep(Duration::from_millis(50)).await;

    let listener_addr: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Send the template set first, then the data set with 2 varlen records.
    sender.send_to(TEMPLATE_MSG, listener_addr).await.unwrap();
    sleep(Duration::from_millis(50)).await;
    sender.send_to(DATA_MSG, listener_addr).await.unwrap();
    sleep(Duration::from_millis(150)).await;

    shutdown_tx.send(true).unwrap();
    let _ = timeout(Duration::from_secs(2), listener_task).await;

    // Drop the writer's handler side by letting it fall out of scope isn't
    // enough (it's inside the listener's Arc); instead wait for the flush
    // that already happened on push (max_buffer_rows = 1) and give the
    // background writer time to materialize it to disk.
    drop(writer_task);
    sleep(Duration::from_secs(2)).await;

    let ipfix_dir = dir.path().join("ipfix");
    assert!(ipfix_dir.is_dir(), "expected {ipfix_dir:?} to exist");

    let parquet_files = walk_all_files(&ipfix_dir)
        .into_iter()
        .filter(|p| p.extension().is_some_and(|ext| ext == "parquet"))
        .collect::<Vec<_>>();
    assert!(
        !parquet_files.is_empty(),
        "expected at least one Parquet file under {ipfix_dir:?}"
    );

    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    let mut total_rows = 0usize;
    let mut extra_values: Vec<String> = Vec::new();
    for file_path in &parquet_files {
        let bytes = std::fs::read(file_path).expect("read parquet file");
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .expect("parquet builder");
        let reader = builder.build().expect("parquet reader");
        for batch in reader {
            let batch = batch.expect("batch ok");
            total_rows += batch.num_rows();
            use arrow::array::{Array, StringArray};
            let extra_col = batch
                .column_by_name("extra")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            for i in 0..extra_col.len() {
                extra_values.push(extra_col.value(i).to_string());
            }
        }
    }

    assert_eq!(total_rows, 2, "expected exactly 2 decoded varlen records");
    assert_eq!(extra_values.len(), 2);
    for extra in &extra_values {
        assert!(
            extra.contains("616263"),
            "expected 'extra' to hold the hex-encoded varlen value \"616263\" \
             (\"abc\"), got: {extra}"
        );
    }
}

/// IPFIX message #3: a data set for template 256 with one record whose
/// varlen value is 1000 raw bytes -- well over
/// `ipfix::decoder::MAX_EXTRA_VALUE_BYTES` (128). RFC 7011 §7 encodes a
/// length >= 255 as a 0xFF marker followed by a 2-byte length.
///
/// Message header (16) + data set (4 hdr + 1 + 2 + 1000 = 1007 body) = 1023
/// bytes total.
fn long_varlen_data_msg() -> Vec<u8> {
    const BODY_LEN: usize = 1000;
    let mut record_bytes = vec![0xFFu8];
    record_bytes.extend_from_slice(&(BODY_LEN as u16).to_be_bytes());
    record_bytes.extend(std::iter::repeat_n(0x5Au8, BODY_LEN));

    let mut msg = Vec::new();
    msg.extend_from_slice(&[0x00, 0x0A]); // version = 10
    let total_len = 16 + 4 + record_bytes.len();
    msg.extend_from_slice(&(total_len as u16).to_be_bytes());
    msg.extend_from_slice(&[
        0x67, 0x5C, 0xB0, 0x20, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
    ]);
    msg.extend_from_slice(&[0x01, 0x00]); // set id = 256
    msg.extend_from_slice(&((4 + record_bytes.len()) as u16).to_be_bytes());
    msg.extend_from_slice(&record_bytes);
    msg
}

/// Round-4 regression: a varlen value well over `MAX_EXTRA_VALUE_BYTES` must
/// still reach Parquet, but truncated -- with `ie97_original_len` recording
/// the true length -- rather than writing the full hex-encoded value.
/// Before `insert_hex_capped` (`src/ipfix/decoder.rs`), this would land the
/// full 2000-hex-char value in `extra` with no `_original_len` key.
#[tokio::test]
async fn ipfix_long_varlen_value_lands_truncated_in_parquet_with_original_len() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    let cfg = IpfixLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "ipfix".to_string(),
        max_buffer_rows: 1,
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 256,
    };
    let (handler, writer_task) = ipfix_local_start(
        &cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );
    let handler: Arc<dyn IpfixHandler> = Arc::new(handler);

    let udp_port = {
        let tmp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = tmp.local_addr().unwrap().port();
        drop(tmp);
        port
    };
    let listener_config = IpfixListenerConfig {
        udp_port,
        bind_address: "127.0.0.1".to_string(),
        ..IpfixListenerConfig::default()
    };
    let listener = IpfixListener::new(listener_config, handler);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let listener_task = tokio::spawn(async move {
        listener.start_with_shutdown(shutdown_rx).await.ok();
    });
    sleep(Duration::from_millis(50)).await;

    let listener_addr: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    sender.send_to(TEMPLATE_MSG, listener_addr).await.unwrap();
    sleep(Duration::from_millis(50)).await;
    sender
        .send_to(&long_varlen_data_msg(), listener_addr)
        .await
        .unwrap();
    sleep(Duration::from_millis(150)).await;

    shutdown_tx.send(true).unwrap();
    let _ = timeout(Duration::from_secs(2), listener_task).await;

    drop(writer_task);
    sleep(Duration::from_secs(2)).await;

    let ipfix_dir = dir.path().join("ipfix");
    assert!(ipfix_dir.is_dir(), "expected {ipfix_dir:?} to exist");

    let parquet_files = walk_all_files(&ipfix_dir)
        .into_iter()
        .filter(|p| p.extension().is_some_and(|ext| ext == "parquet"))
        .collect::<Vec<_>>();
    assert!(
        !parquet_files.is_empty(),
        "expected at least one Parquet file under {ipfix_dir:?}"
    );

    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    let mut extra_values: Vec<String> = Vec::new();
    for file_path in &parquet_files {
        let bytes = std::fs::read(file_path).expect("read parquet file");
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .expect("parquet builder");
        let reader = builder.build().expect("parquet reader");
        for batch in reader {
            let batch = batch.expect("batch ok");
            use arrow::array::{Array, StringArray};
            let extra_col = batch
                .column_by_name("extra")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            for i in 0..extra_col.len() {
                extra_values.push(extra_col.value(i).to_string());
            }
        }
    }

    assert_eq!(extra_values.len(), 1, "expected exactly 1 decoded record");
    let extra: serde_json::Value =
        serde_json::from_str(&extra_values[0]).expect("extra must be valid JSON");
    let hex_val = extra["ie97"].as_str().expect("ie97 must be a hex string");
    assert_eq!(
        hex_val.len(),
        128 * 2,
        "ie97 must be truncated to 256 hex chars (128 bytes); got {hex_val:?} in extra: {extra}"
    );
    assert_eq!(
        extra["ie97_original_len"],
        serde_json::json!(1000),
        "extra must record the true original value length; got: {extra}"
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
