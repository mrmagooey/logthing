//! End-to-end integration test: syslog messages pushed through
//! `syslog_local_start` land as real, readable Parquet files on local disk.

use bytes::Bytes;
use logthing::config::SyslogLocalConfig;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::syslog_s3::syslog_local_start;
use logthing::syslog::listener::SyslogHandler;
use logthing::syslog::{SyslogMessage, SyslogProtocol};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::net::SocketAddr;
use std::path::Path;

fn walk_all_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            walk_all_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

#[tokio::test]
async fn syslog_messages_appear_as_parquet_on_local_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let sink = std::sync::Arc::new(
        LocalDiskSink::new(tmp.path().to_path_buf())
            .await
            .expect("LocalDiskSink constructs"),
    );

    let cfg = SyslogLocalConfig {
        directory: tmp.path().to_path_buf(),
        prefix: "syslog".to_string(),
        max_buffer_rows: 10_000,
        flush_interval_secs: 3600,
        channel_capacity: 4096,
    };

    let (handler, join_handle) = syslog_local_start(
        &cfg,
        sink,
        std::sync::Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );

    let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();
    let msg1 = SyslogMessage {
        priority: 34,
        severity: 2,
        facility: 4,
        timestamp: Some(chrono::Utc::now()),
        hostname: Some("host-a".to_string()),
        app_name: Some("sshd".to_string()),
        proc_id: None,
        msg_id: None,
        message: "authentication failure".to_string(),
        structured_data: None,
        protocol: SyslogProtocol::Rfc3164,
    };
    let msg2 = SyslogMessage {
        priority: 134,
        severity: 6,
        facility: 16,
        timestamp: Some(chrono::Utc::now()),
        hostname: Some("host-b".to_string()),
        app_name: Some("cron".to_string()),
        proc_id: Some("4321".to_string()),
        msg_id: None,
        message: "job completed".to_string(),
        structured_data: None,
        protocol: SyslogProtocol::Rfc5424,
    };

    handler.handle_message(msg1, src).await;
    handler.handle_message(msg2, src).await;

    // Drop the handler to close the channel and trigger the shutdown flush.
    drop(handler);
    tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
        .await
        .expect("writer task must exit within 5s")
        .expect("writer task must not panic");

    // Find every file under the tempdir; there must be no leftover .tmp- files.
    let mut all_files = Vec::new();
    walk_all_files(tmp.path(), &mut all_files);
    assert!(
        !all_files
            .iter()
            .any(|p| p.file_name().unwrap().to_string_lossy().contains(".tmp-")),
        "no leftover .tmp- files should remain after flush: {all_files:?}"
    );

    let parquet_files: Vec<_> = all_files
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "parquet"))
        .collect();
    assert_eq!(
        parquet_files.len(),
        1,
        "expected exactly 1 Parquet file (syslog has a single partition); found {parquet_files:?}"
    );

    let raw = std::fs::read(parquet_files[0]).unwrap();
    let buf = Bytes::from(raw);
    let builder = ParquetRecordBatchReaderBuilder::try_new(buf).unwrap();
    let schema = builder.schema().clone();
    assert_eq!(schema.fields().len(), 13);
    assert_eq!(
        schema.field_with_name("timestamp").unwrap().data_type(),
        &arrow::datatypes::DataType::Timestamp(
            arrow::datatypes::TimeUnit::Microsecond,
            Some("UTC".into())
        ),
        "on-disk Parquet timestamp column must be a microsecond UTC timestamp"
    );

    let mut reader = builder.build().unwrap();
    let rb = reader
        .next()
        .expect("at least one record batch")
        .expect("record batch reads without error");
    assert_eq!(rb.num_rows(), 2);

    use arrow::array::{Array, StringArray};
    let hostnames = rb.column(4).as_any().downcast_ref::<StringArray>().unwrap();
    assert_eq!(hostnames.value(0), "host-a");
    assert_eq!(hostnames.value(1), "host-b");
    assert!(!hostnames.is_null(0));
}

/// Pushes 1500 real syslog messages through the real pipeline
/// (`SyslogS3Handler` local variant -> `PartitionedParquetWriter` ->
/// `LocalDiskSink`), crossing the `BUILDER_BATCH_ROWS` (1000) threshold in
/// `SyslogAccumulator`'s live builder mid-burst -- proving the amortized
/// builder correctly materializes once at row 1000 and resumes accumulating
/// the remaining 500 rows in a fresh builder, rather than silently dropping
/// or corrupting rows across that boundary. Mirrors
/// `suricata_local_burst_of_1500_alert_records_crosses_builder_batch_rows`.
/// Every 7th message has no `hostname` (a CEF/LEEF-like payload with no
/// parseable header), exercising the nullable column through the
/// accumulator path across the materialize boundary too.
#[tokio::test]
async fn syslog_local_burst_of_1500_messages_crosses_builder_batch_rows() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = std::sync::Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    // Row/byte/time thresholds all high enough that no in-loop flush fires;
    // the only flush is the shutdown `flush_all` once the handler is
    // dropped. `channel_capacity` is comfortably above the message count so
    // `handle_message`'s `try_send` never actually fills under this
    // single-threaded burst.
    let cfg = SyslogLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "syslog".to_string(),
        max_buffer_rows: 100_000,
        flush_interval_secs: 3600,
        channel_capacity: 2000,
    };

    let (handler, writer_task) = syslog_local_start(
        &cfg,
        sink,
        std::sync::Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );

    let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();
    const N: usize = 1500;
    for i in 0..N {
        let msg = if i % 7 == 0 {
            SyslogMessage {
                priority: 13,
                severity: 5,
                facility: 1,
                timestamp: None,
                hostname: None,
                app_name: None,
                proc_id: None,
                msg_id: None,
                message: format!("cef-like payload {i}"),
                structured_data: None,
                protocol: SyslogProtocol::Unknown,
            }
        } else {
            SyslogMessage {
                priority: 34,
                severity: 2,
                facility: 4,
                timestamp: Some(chrono::Utc::now()),
                hostname: Some(format!("host-{i}")),
                app_name: Some("sshd".to_string()),
                proc_id: Some(i.to_string()),
                msg_id: None,
                message: format!("message {i}"),
                structured_data: None,
                protocol: SyslogProtocol::Rfc3164,
            }
        };
        handler.handle_message(msg, src).await;
    }

    // Drop the handler to close the channel; the writer task's shutdown
    // path drains any in-flight flushes and then performs one final,
    // synchronous `flush_all` covering everything still buffered.
    drop(handler);
    tokio::time::timeout(std::time::Duration::from_secs(10), writer_task)
        .await
        .expect("writer task exits within 10s")
        .expect("writer task must not panic");

    let mut all_files = Vec::new();
    walk_all_files(dir.path(), &mut all_files);
    let parquet_files: Vec<_> = all_files
        .iter()
        .filter(|p| p.extension().is_some_and(|ext| ext == "parquet"))
        .collect();
    assert!(
        !parquet_files.is_empty(),
        "expected at least one Parquet file under {:?}",
        dir.path()
    );

    use arrow::array::{Array, StringArray};

    let mut hostnames: Vec<Option<String>> = Vec::with_capacity(N);
    for file_path in &parquet_files {
        let bytes = std::fs::read(file_path).expect("read parquet file");
        let builder = ParquetRecordBatchReaderBuilder::try_new(Bytes::from(bytes))
            .expect("parquet builder for syslog burst");
        let reader = builder.build().expect("parquet reader for syslog burst");
        for rb in reader {
            let rb = rb.expect("batch ok");
            let hostname_col = rb
                .column_by_name("hostname")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            for i in 0..rb.num_rows() {
                hostnames.push(if hostname_col.is_null(i) {
                    None
                } else {
                    Some(hostname_col.value(i).to_string())
                });
            }
        }
    }

    assert_eq!(
        hostnames.len(),
        N,
        "expected exactly {N} rows across all syslog Parquet files, proving the \
         BUILDER_BATCH_ROWS (1000) materialize threshold was crossed at least \
         once mid-burst without losing or duplicating rows"
    );
    let null_count = hostnames.iter().filter(|v| v.is_none()).count();
    assert_eq!(
        null_count,
        N.div_ceil(7),
        "every 7th message had no hostname and must round-trip as null through \
         the accumulator, including across the materialize boundary"
    );
}

#[tokio::test]
async fn syslog_local_start_emits_iceberg_descriptor_when_configured() {
    let parquet_dir = tempfile::tempdir().expect("parquet tempdir");
    let descriptor_dir = tempfile::tempdir().expect("descriptor tempdir");

    let parquet_sink = std::sync::Arc::new(
        LocalDiskSink::new(parquet_dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new (parquet)"),
    );
    let descriptor_sink: std::sync::Arc<dyn logthing::forwarding::buffered_writer::UploadSink> =
        std::sync::Arc::new(
            LocalDiskSink::new(descriptor_dir.path().to_path_buf())
                .await
                .expect("LocalDiskSink::new (descriptor)"),
        );

    let cfg = SyslogLocalConfig {
        directory: parquet_dir.path().to_path_buf(),
        prefix: "syslog".to_string(),
        max_buffer_rows: 1, // flush immediately on first row
        flush_interval_secs: 3600,
        channel_capacity: 64,
    };

    let (handler, writer_task) = syslog_local_start(
        &cfg,
        parquet_sink,
        std::sync::Arc::new(logthing::stats::SourceHourlyStats::new()),
        Some(descriptor_sink),
    );

    let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();
    let msg = SyslogMessage {
        priority: 34,
        severity: 2,
        facility: 4,
        timestamp: Some(chrono::Utc::now()),
        hostname: Some("host-a".to_string()),
        app_name: Some("sshd".to_string()),
        proc_id: None,
        msg_id: None,
        message: "authentication failure".to_string(),
        structured_data: None,
        protocol: SyslogProtocol::Rfc3164,
    };
    handler.handle_message(msg, src).await;

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
                assert_eq!(v["source"], "syslog");
                assert_eq!(v["file_format"], "PARQUET");
            }
        }
    }
    assert!(
        found,
        "expected at least one descriptor .json file under {descriptor_dir:?}"
    );
}

/// An RFC 5424 line with a NILVALUE (`-`) structured-data field, received over a real UDP
/// listener, reaches Parquet with the `message` column holding only the body.
#[tokio::test]
async fn test_rfc5424_nilvalue_sd_message_column_has_no_leading_dash() {
    use arrow::array::{Array, StringArray};
    use logthing::syslog::listener::{SyslogListener, SyslogListenerConfig};
    use tokio::net::{TcpListener, UdpSocket};

    let tmp = tempfile::tempdir().unwrap();
    let sink = std::sync::Arc::new(LocalDiskSink::new(tmp.path().to_path_buf()).await.unwrap());
    let cfg = SyslogLocalConfig {
        directory: tmp.path().to_path_buf(),
        prefix: "syslog".to_string(),
        max_buffer_rows: 10_000,
        flush_interval_secs: 1,
        channel_capacity: 4096,
    };
    let (handler, _writer) = syslog_local_start(
        &cfg,
        sink,
        std::sync::Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );

    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = udp.local_addr().unwrap().port();
    drop(udp);
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_port = tcp.local_addr().unwrap().port();
    drop(tcp);

    let listener = SyslogListener::new(
        SyslogListenerConfig {
            udp_port,
            tcp_port,
            bind_address: "127.0.0.1".to_string(),
            parse_dns_logs: false,
            ..SyslogListenerConfig::default()
        },
        std::sync::Arc::new(handler),
    );
    let task = tokio::spawn(async move {
        listener.start().await.ok();
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(
        b"<34>1 2003-10-11T22:14:15.003Z host su - ID47 - 'su root' failed",
        format!("127.0.0.1:{udp_port}"),
    )
    .await
    .unwrap();
    // The writer flushes on its 1s interval; poll for the file rather than sleeping blindly.
    let mut parquet = None;
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let mut files = Vec::new();
        walk_all_files(tmp.path(), &mut files);
        parquet = files
            .into_iter()
            .find(|p| p.extension().is_some_and(|e| e == "parquet"));
        if parquet.is_some() {
            break;
        }
    }
    task.abort();
    let parquet = parquet.expect("one parquet file within 10s");
    let builder =
        ParquetRecordBatchReaderBuilder::try_new(Bytes::from(std::fs::read(&parquet).unwrap()))
            .unwrap();
    let idx = builder.schema().index_of("message").unwrap();
    let rb = builder.build().unwrap().next().unwrap().unwrap();
    assert_eq!(rb.num_rows(), 1);
    let col = rb
        .column(idx)
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(col.value(0), "'su root' failed");
}

/// RFC 6587 octet-counted frames over a real TCP listener reach the local Parquet sink
/// intact, including one whose body contains a newline.
#[tokio::test]
async fn syslog_tcp_octet_counted_frames_land_as_rows_with_embedded_newline() {
    use logthing::syslog::listener::{SyslogListener, SyslogListenerConfig};
    use tokio::io::AsyncWriteExt;

    let tmp = tempfile::tempdir().unwrap();
    let sink = std::sync::Arc::new(
        LocalDiskSink::new(tmp.path().to_path_buf())
            .await
            .expect("LocalDiskSink constructs"),
    );
    let cfg = SyslogLocalConfig {
        directory: tmp.path().to_path_buf(),
        prefix: "syslog".to_string(),
        max_buffer_rows: 1,
        flush_interval_secs: 1,
        channel_capacity: 4096,
    };
    let (handler, _join) = syslog_local_start(
        &cfg,
        sink,
        std::sync::Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );

    let tcp_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let udp_port = {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap().port()
    };
    let listener = SyslogListener::new(
        SyslogListenerConfig {
            bind_address: "127.0.0.1".to_string(),
            udp_port,
            tcp_port,
            recv_tasks: 1,
            ..SyslogListenerConfig::default()
        },
        std::sync::Arc::new(handler),
    );
    let (_tx, rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(async move { listener.start_with_shutdown(rx).await });

    let bodies = [
        "<134>Jan 15 10:30:45 host-a app: one\ntwo",
        "<134>Jan 15 10:30:46 host-b app: three",
    ];
    let mut payload = Vec::new();
    for b in bodies {
        payload.extend_from_slice(format!("{} {}", b.len(), b).as_bytes());
    }
    let mut stream = None;
    for _ in 0..100 {
        if let Ok(s) = tokio::net::TcpStream::connect(("127.0.0.1", tcp_port)).await {
            stream = Some(s);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let mut stream = stream.expect("syslog TCP listener must accept");
    stream.write_all(&payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut messages: Vec<String> = Vec::new();
    for _ in 0..200 {
        messages.clear();
        let mut files = Vec::new();
        walk_all_files(tmp.path(), &mut files);
        for f in files
            .iter()
            .filter(|p| p.extension().is_some_and(|e| e == "parquet"))
        {
            let raw = Bytes::from(std::fs::read(f).unwrap());
            for rb in ParquetRecordBatchReaderBuilder::try_new(raw)
                .unwrap()
                .build()
                .unwrap()
            {
                let rb = rb.unwrap();
                let col = rb
                    .column_by_name("message")
                    .unwrap()
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                messages.extend((0..rb.num_rows()).map(|i| col.value(i).to_string()));
            }
        }
        if messages.len() >= 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    server.abort();
    assert_eq!(messages.len(), 2, "{messages:?}");
    // The newline stays inside one row. (The RFC 3164 parser leaves the header in
    // `message` when the body is multi-line, so match the tail, not equality.)
    assert!(
        messages.iter().any(|m| m.ends_with("one\ntwo")),
        "{messages:?}"
    );
    assert!(messages.iter().any(|m| m == "three"), "{messages:?}");
}
