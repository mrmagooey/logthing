// tests/syslog_payload_e2e.rs
//! End-to-end test: send a CEF syslog line over the real UDP listener and
//! assert a StructuredSyslogRecord is produced.
//!
//! Spins up a SyslogListener in-process (ephemeral UDP port), sends a
//! CEF-formatted syslog datagram, and verifies the payload dispatch path
//! produces a StructuredSyslogRecord with payload_type="cef".
//!
//! No MinIO required — uses a capturing store instead of a real S3 handler.

use logthing::syslog::SyslogMessage;
use logthing::syslog::listener::{SyslogHandler, SyslogListener, SyslogListenerConfig};
use logthing::syslog::payload::{StructuredSyslogRecord, dispatch};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::{Duration, sleep};

/// A capturing store for structured records produced by dispatch.
struct CapturingStore {
    records: Mutex<Vec<StructuredSyslogRecord>>,
}

impl CapturingStore {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            records: Mutex::new(Vec::new()),
        })
    }
    fn take(&self) -> Vec<StructuredSyslogRecord> {
        self.records.lock().unwrap().drain(..).collect()
    }
}

/// A SyslogHandler that runs dispatch and pushes to the capturing store.
struct DispatchingTestHandler {
    store: Arc<CapturingStore>,
}

#[async_trait::async_trait]
impl SyslogHandler for DispatchingTestHandler {
    async fn handle_message(&self, message: SyslogMessage, _source: SocketAddr) {
        let payload = dispatch(&message);
        if let Some(rec) = StructuredSyslogRecord::from_syslog_and_payload(&message, &payload) {
            self.store.records.lock().unwrap().push(rec);
        }
    }
}

#[tokio::test]
async fn cef_datagram_produces_structured_record_with_cef_payload_type() {
    let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = udp_socket.local_addr().unwrap().port();
    drop(udp_socket);

    // Reserve a separate ephemeral port for TCP so the TCP bind in start()
    // cannot collide with anything (assuming udp_port+1 is free is a flakiness
    // hazard: a failed TCP bind aborts the shared select! and drops the UDP arm).
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_port = tcp_listener.local_addr().unwrap().port();
    drop(tcp_listener);

    let store = CapturingStore::new();
    let handler = Arc::new(DispatchingTestHandler {
        store: store.clone(),
    });

    let cfg = SyslogListenerConfig {
        udp_port,
        tcp_port, // verified-free ephemeral port; not exercised here
        bind_address: "127.0.0.1".to_string(),
        parse_dns_logs: false,
    };

    let listener = SyslogListener::new(cfg, handler);
    let task = tokio::spawn(async move {
        // start() launches both UDP and TCP; the test aborts the task when done.
        listener.start().await.ok();
    });

    sleep(Duration::from_millis(100)).await;

    // Send a CEF syslog line as a UDP datagram.
    let send_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let cef_line = "<134>Jan 15 10:30:45 fw01 arcsight: \
                    CEF:0|Vendor|FW|1.0|SIG001|Firewall Accept|6|\
                    src=10.0.0.1 dst=8.8.8.8 spt=12345 dpt=443";
    send_sock
        .send_to(cef_line.as_bytes(), format!("127.0.0.1:{}", udp_port))
        .await
        .unwrap();

    sleep(Duration::from_millis(200)).await;
    task.abort();

    let records = store.take();
    assert_eq!(
        records.len(),
        1,
        "expected 1 structured record, got {}",
        records.len()
    );
    let rec = &records[0];
    assert_eq!(rec.payload_type, "cef");

    let v = &rec.parsed;
    assert_eq!(v["device_vendor"].as_str().unwrap_or(""), "Vendor");
    assert_eq!(v["severity"].as_str().unwrap_or(""), "6");

    // End-to-end assertion: run this same record through the real
    // production mapper (`structured_syslog_record_to_batch`, the exact
    // function `StructuredSyslogSink::to_record_batch` delegates to) and a
    // real `ArrowWriter`, then read the resulting on-disk-format Parquet
    // bytes back through a real Parquet reader -- the schema a downstream
    // Iceberg/lakehouse consumer actually sees -- and assert `timestamp` is
    // a microsecond UTC timestamp, not just checked against the in-memory
    // schema definition.
    use logthing::forwarding::structured_syslog_s3::structured_syslog_record_to_batch;
    let batch = structured_syslog_record_to_batch(rec).expect("record maps to a RecordBatch");
    let mut buf = Vec::new();
    {
        let mut writer =
            parquet::arrow::ArrowWriter::try_new(&mut buf, batch.schema(), None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
    }
    let builder = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(
        bytes::Bytes::from(buf),
    )
    .expect("parquet builder for on-disk bytes");
    let field = builder.schema().field_with_name("timestamp").unwrap();
    assert_eq!(
        *field.data_type(),
        arrow::datatypes::DataType::Timestamp(
            arrow::datatypes::TimeUnit::Microsecond,
            Some("UTC".into())
        ),
        "on-disk Parquet timestamp column must be a microsecond UTC timestamp so that \
         Iceberg day/month/year partition transforms can use it"
    );
}

#[tokio::test]
async fn no_pri_cef_datagram_produces_structured_record_with_cef_payload_type() {
    // Regression test for the reported bug: real devices (e.g. Ubiquiti UDM
    // appliances) forward CEF-formatted IDS/IPS events with no <PRI> prefix
    // at all. Before the fix, SyslogMessage::parse returned None for such
    // lines and the CEF sub-parser never ran.
    let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = udp_socket.local_addr().unwrap().port();
    drop(udp_socket);

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_port = tcp_listener.local_addr().unwrap().port();
    drop(tcp_listener);

    let store = CapturingStore::new();
    let handler = Arc::new(DispatchingTestHandler {
        store: store.clone(),
    });

    let cfg = SyslogListenerConfig {
        udp_port,
        tcp_port,
        bind_address: "127.0.0.1".to_string(),
        parse_dns_logs: false,
    };

    let listener = SyslogListener::new(cfg, handler);
    let task = tokio::spawn(async move {
        listener.start().await.ok();
    });

    sleep(Duration::from_millis(100)).await;

    // Bare CEF line, no <PRI> envelope, no timestamp/hostname wrapper.
    let send_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let cef_line = "CEF:0|Vendor|FW|1.0|SIG001|Firewall Accept|6|src=10.0.0.1 dst=8.8.8.8";
    send_sock
        .send_to(cef_line.as_bytes(), format!("127.0.0.1:{}", udp_port))
        .await
        .unwrap();

    sleep(Duration::from_millis(200)).await;
    task.abort();

    let records = store.take();
    assert_eq!(
        records.len(),
        1,
        "expected 1 structured record, got {}",
        records.len()
    );
    let rec = &records[0];
    assert_eq!(rec.payload_type, "cef");
}

#[tokio::test]
async fn no_pri_cef_datagram_with_trailing_newline_produces_structured_record_with_cef_payload_type()
 {
    // Regression test: UDP syslog senders commonly append a trailing '\n' to
    // the datagram. Unlike the TCP path, the UDP receive arm does not trim
    // it before calling SyslogMessage::parse. Before the central strip in
    // parse(), a trailing '\n' made every header regex's `$` anchor fail
    // (Rust regex `$` has no trailing-newline exception without multi-line
    // mode), so the message was silently dropped.
    let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = udp_socket.local_addr().unwrap().port();
    drop(udp_socket);

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_port = tcp_listener.local_addr().unwrap().port();
    drop(tcp_listener);

    let store = CapturingStore::new();
    let handler = Arc::new(DispatchingTestHandler {
        store: store.clone(),
    });

    let cfg = SyslogListenerConfig {
        udp_port,
        tcp_port,
        bind_address: "127.0.0.1".to_string(),
        parse_dns_logs: false,
    };

    let listener = SyslogListener::new(cfg, handler);
    let task = tokio::spawn(async move {
        listener.start().await.ok();
    });

    sleep(Duration::from_millis(100)).await;

    // Bare CEF line, no <PRI> envelope, WITH a trailing newline byte.
    let send_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let cef_line = "CEF:0|Vendor|FW|1.0|SIG001|Firewall Accept|6|src=10.0.0.1 dst=8.8.8.8";
    send_sock
        .send_to(
            format!("{}\n", cef_line).as_bytes(),
            format!("127.0.0.1:{}", udp_port),
        )
        .await
        .unwrap();

    sleep(Duration::from_millis(200)).await;
    task.abort();

    let records = store.take();
    assert_eq!(
        records.len(),
        1,
        "expected 1 structured record, got {}",
        records.len()
    );
    let rec = &records[0];
    assert_eq!(rec.payload_type, "cef");
}

#[tokio::test]
async fn non_matching_datagram_produces_no_structured_record() {
    let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = udp_socket.local_addr().unwrap().port();
    drop(udp_socket);

    // Reserve a separate ephemeral port for TCP (see note in the CEF test).
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_port = tcp_listener.local_addr().unwrap().port();
    drop(tcp_listener);

    let store = CapturingStore::new();
    let handler = Arc::new(DispatchingTestHandler {
        store: store.clone(),
    });

    let cfg = SyslogListenerConfig {
        udp_port,
        tcp_port,
        bind_address: "127.0.0.1".to_string(),
        parse_dns_logs: false,
    };
    let listener = SyslogListener::new(cfg, handler);
    let task = tokio::spawn(async move {
        listener.start().await.ok();
    });
    sleep(Duration::from_millis(100)).await;

    let send_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // A plain syslog message that matches no sub-parser.
    let plain = "<134>Jan 15 10:30:45 host app: this is a plain text message";
    send_sock
        .send_to(plain.as_bytes(), format!("127.0.0.1:{}", udp_port))
        .await
        .unwrap();

    sleep(Duration::from_millis(200)).await;
    task.abort();

    let records = store.take();
    assert!(
        records.is_empty(),
        "non-matching message must produce no structured record"
    );
}
