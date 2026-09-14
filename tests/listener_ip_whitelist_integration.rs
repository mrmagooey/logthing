//! Integration test: `security.allowed_ips` enforcement in the wire-protocol
//! socket listeners.
//!
//! Until this change, `IpWhitelist` was wired only into the axum HTTP
//! router (`Server::create_router`) — the five socket listeners (syslog
//! UDP+TCP, IPFIX UDP, sFlow UDP, Zeek TCP, Suricata TCP) performed no
//! source filtering at all. This test drives two of the five listeners
//! (syslog TCP and IPFIX UDP — one TCP, one UDP, per the plan) over real
//! sockets, via each listener's public `start_with_shutdown` entry point
//! (the same one `main.rs` calls), and asserts that a source outside
//! `allowed_ips` never reaches the handler while a source inside it does.
//!
//! `run_with_listener` / `run_with_socket` are `pub(crate)` test-only
//! shortcuts not visible from this external integration-test crate, so this
//! test binds an ephemeral port, drops it, and hands the port to
//! `start_with_shutdown` — the same bind-then-drop pattern the in-crate unit
//! tests use for this exact reason.

use logthing::ipfix::FlowRecord;
use logthing::ipfix::listener::{IpfixHandler, IpfixListener, IpfixListenerConfig};
use logthing::middleware::IpWhitelist;
use logthing::syslog::SyslogMessage;
use logthing::syslog::listener::{SyslogHandler, SyslogListener, SyslogListenerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;
use tokio::time::{Duration, sleep, timeout};

struct CapturingSyslogHandler {
    messages: Mutex<Vec<SyslogMessage>>,
}

impl CapturingSyslogHandler {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            messages: Mutex::new(Vec::new()),
        })
    }
    fn count(&self) -> usize {
        self.messages.lock().unwrap().len()
    }
}

#[async_trait::async_trait]
impl SyslogHandler for CapturingSyslogHandler {
    async fn handle_message(&self, message: SyslogMessage, _source: SocketAddr) {
        self.messages.lock().unwrap().push(message);
    }
}

struct CapturingIpfixHandler {
    batches: Mutex<Vec<Vec<FlowRecord>>>,
}

impl CapturingIpfixHandler {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            batches: Mutex::new(Vec::new()),
        })
    }
    fn count(&self) -> usize {
        self.batches.lock().unwrap().len()
    }
}

#[async_trait::async_trait]
impl IpfixHandler for CapturingIpfixHandler {
    async fn handle_flows(&self, flows: Vec<FlowRecord>, _source: SocketAddr) {
        self.batches.lock().unwrap().push(flows);
    }
}

/// Grab an ephemeral TCP port, then release it so a subsequent bind (inside
/// `start_with_shutdown`) can claim the same address.
async fn ephemeral_tcp_port() -> u16 {
    let tmp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tmp.local_addr().unwrap().port();
    drop(tmp);
    port
}

/// Grab an ephemeral UDP port, then release it so a subsequent bind (inside
/// `start_with_shutdown`) can claim the same address.
async fn ephemeral_udp_port() -> u16 {
    let tmp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = tmp.local_addr().unwrap().port();
    drop(tmp);
    port
}

// ---------------------------------------------------------------------------
// TCP: syslog listener
// ---------------------------------------------------------------------------

async fn run_syslog_case(allowed_ips: IpWhitelist) -> usize {
    let tcp_port = ephemeral_tcp_port().await;
    let udp_port = ephemeral_udp_port().await;

    let config = SyslogListenerConfig {
        udp_port,
        tcp_port,
        bind_address: "127.0.0.1".to_string(),
        parse_dns_logs: false,
        ..SyslogListenerConfig::default()
    };
    let handler = CapturingSyslogHandler::new();
    let listener = SyslogListener::new(config, handler.clone()).with_allowed_ips(allowed_ips);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(async move {
        listener.start_with_shutdown(shutdown_rx).await.ok();
    });
    sleep(Duration::from_millis(50)).await;

    let addr: SocketAddr = format!("127.0.0.1:{tcp_port}").parse().unwrap();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let _ = stream
        .write_all(b"<134>Jan 15 10:30:45 host app: test message\n")
        .await;
    drop(stream);

    sleep(Duration::from_millis(150)).await;
    shutdown_tx.send(true).unwrap();
    let _ = timeout(Duration::from_secs(2), task).await;

    handler.count()
}

#[tokio::test]
async fn syslog_tcp_blocks_source_outside_allowed_ips() {
    let count = run_syslog_case(IpWhitelist::new(vec!["10.99.99.0/24".into()]).unwrap()).await;
    assert_eq!(
        count, 0,
        "127.0.0.1 must be rejected by a 10.99.99.0/24-only whitelist"
    );
}

#[tokio::test]
async fn syslog_tcp_allows_source_inside_allowed_ips() {
    let count = run_syslog_case(IpWhitelist::new(vec!["127.0.0.1".into()]).unwrap()).await;
    assert_eq!(
        count, 1,
        "127.0.0.1 must be allowed through a whitelist that includes it"
    );
}

// ---------------------------------------------------------------------------
// UDP: IPFIX listener
// ---------------------------------------------------------------------------

/// A single-record NetFlow v5 datagram (the decoder auto-detects v5 vs.
/// IPFIX v10 from the version field). The equivalent fixture in
/// `logthing::ipfix::decoder` is `pub(crate)` and `#[cfg(test)]`-gated, so
/// unreachable from this external integration-test crate — inlined here
/// instead.
const NFV5_ONE_RECORD: &[u8] = &[
    // Header (24 bytes)
    0x00, 0x05, // version = 5
    0x00, 0x01, // count = 1
    0x00, 0x0F, 0x42, 0x40, // sys_uptime_ms = 1_000_000
    0x67, 0x5C, 0xB0, 0x20, // unix_secs
    0x00, 0x00, 0x00, 0x00, // unix_nsecs
    0x00, 0x00, 0x00, 0x01, // flow_sequence
    0x00, // engine_type
    0x00, // engine_id
    0x00, 0x00, // sampling_interval
    // Record (48 bytes)
    0xC0, 0xA8, 0x01, 0x0A, // srcaddr = 192.168.1.10
    0xC0, 0xA8, 0x01, 0x01, // dstaddr = 192.168.1.1
    0x00, 0x00, 0x00, 0x00, // nexthop = 0.0.0.0
    0x00, 0x01, // input = 1
    0x00, 0x02, // output = 2
    0x00, 0x00, 0x00, 0x05, // dPkts = 5
    0x00, 0x00, 0x01, 0xF4, // dOctets = 500
    0x00, 0x0F, 0x42, 0x00, // first_ms = 999424
    0x00, 0x0F, 0x42, 0x3C, // last_ms  = 999484
    0x1F, 0x90, // srcport = 8080
    0x00, 0x50, // dstport = 80
    0x00, // pad1
    0x18, // tcp_flags = 0x18 (ACK+PSH)
    0x06, // prot = 6 (TCP)
    0x00, // tos
    0x00, 0x00, // src_as
    0x00, 0x00, // dst_as
    0x00, // src_mask
    0x00, // dst_mask
    0x00, 0x00, // pad2
];

async fn run_ipfix_case(allowed_ips: IpWhitelist) -> usize {
    let udp_port = ephemeral_udp_port().await;

    let config = IpfixListenerConfig {
        udp_port,
        bind_address: "127.0.0.1".to_string(),
        ..IpfixListenerConfig::default()
    };
    let handler = CapturingIpfixHandler::new();
    let listener = IpfixListener::new(config, handler.clone()).with_allowed_ips(allowed_ips);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(async move {
        listener.start_with_shutdown(shutdown_rx).await.ok();
    });
    sleep(Duration::from_millis(50)).await;

    let listener_addr: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender
        .send_to(NFV5_ONE_RECORD, listener_addr)
        .await
        .unwrap();
    sleep(Duration::from_millis(100)).await;

    shutdown_tx.send(true).unwrap();
    let _ = timeout(Duration::from_secs(2), task).await;

    handler.count()
}

#[tokio::test]
async fn ipfix_udp_blocks_source_outside_allowed_ips() {
    let count = run_ipfix_case(IpWhitelist::new(vec!["10.99.99.0/24".into()]).unwrap()).await;
    assert_eq!(
        count, 0,
        "127.0.0.1 must be rejected by a 10.99.99.0/24-only whitelist"
    );
}

#[tokio::test]
async fn ipfix_udp_allows_source_inside_allowed_ips() {
    let count = run_ipfix_case(IpWhitelist::new(vec!["127.0.0.1".into()]).unwrap()).await;
    assert_eq!(
        count, 1,
        "127.0.0.1 must be allowed through a whitelist that includes it"
    );
}
