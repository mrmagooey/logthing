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
use logthing::syslog::listener::{
    SyslogHandler, SyslogListener, SyslogListenerConfig,
};
use logthing::syslog::payload::{StructuredSyslogRecord, dispatch};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::time::{Duration, sleep};

/// A capturing store for structured records produced by dispatch.
struct CapturingStore {
    records: Mutex<Vec<StructuredSyslogRecord>>,
}

impl CapturingStore {
    fn new() -> Arc<Self> {
        Arc::new(Self { records: Mutex::new(Vec::new()) })
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
        if let Some(rec) =
            StructuredSyslogRecord::from_syslog_and_payload(&message, &payload)
        {
            self.store.records.lock().unwrap().push(rec);
        }
    }
}

#[tokio::test]
async fn cef_datagram_produces_structured_record_with_cef_payload_type() {
    let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = udp_socket.local_addr().unwrap().port();
    drop(udp_socket);

    let store = CapturingStore::new();
    let handler = Arc::new(DispatchingTestHandler { store: store.clone() });

    let cfg = SyslogListenerConfig {
        udp_port,
        tcp_port: udp_port + 1, // distinct port; not exercised here
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
    assert_eq!(records.len(), 1, "expected 1 structured record, got {}", records.len());
    let rec = &records[0];
    assert_eq!(rec.payload_type, "cef");

    let v = &rec.parsed;
    assert_eq!(v["device_vendor"].as_str().unwrap_or(""), "Vendor");
    assert_eq!(v["severity"].as_str().unwrap_or(""), "6");
}

#[tokio::test]
async fn non_matching_datagram_produces_no_structured_record() {
    let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = udp_socket.local_addr().unwrap().port();
    drop(udp_socket);

    let store = CapturingStore::new();
    let handler = Arc::new(DispatchingTestHandler { store: store.clone() });

    let cfg = SyslogListenerConfig {
        udp_port,
        tcp_port: udp_port + 1,
        bind_address: "127.0.0.1".to_string(),
        parse_dns_logs: false,
    };
    let listener = SyslogListener::new(cfg, handler);
    let task = tokio::spawn(async move { listener.start().await.ok(); });
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
    assert!(records.is_empty(), "non-matching message must produce no structured record");
}
