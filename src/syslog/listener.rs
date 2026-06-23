//! Syslog listener for receiving syslog messages via UDP and TCP

use crate::syslog::{SyslogMessage, dns::DnsLogEntry};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

/// Maximum number of concurrent TCP connections accepted by the syslog listener.
/// Prevents resource exhaustion from connection floods.
pub const MAX_SYSLOG_TCP_CONNECTIONS: usize = 1024;

/// Maximum accepted line length in bytes for TCP syslog connections.
///
/// RFC 5424 recommends a minimum of 480 bytes and allows receivers to accept
/// up to 2048 bytes. However, real-world syslog messages with large structured-
/// data payloads can legitimately exceed that. 256 KiB is a generous upper bound
/// that covers any realistic RFC 5424 message while still preventing an
/// unbounded-memory attack from a client that streams bytes with no newline.
/// Lines exceeding this limit are counted via `syslog_oversized_lines` and the
/// connection is closed immediately (no resync attempt — resync would itself
/// require unbounded buffering).
pub const SYSLOG_MAX_LINE_BYTES: usize = 256 * 1024; // 256 KiB

/// Configuration for syslog listener
#[derive(Debug, Clone)]
pub struct SyslogListenerConfig {
    pub udp_port: u16,
    pub tcp_port: u16,
    pub bind_address: String,
    pub parse_dns_logs: bool,
}

impl Default for SyslogListenerConfig {
    fn default() -> Self {
        Self {
            udp_port: 514,
            tcp_port: 601,
            bind_address: "0.0.0.0".to_string(),
            parse_dns_logs: true,
        }
    }
}

/// Syslog message handler trait
#[async_trait::async_trait]
pub trait SyslogHandler: Send + Sync {
    async fn handle_message(&self, message: SyslogMessage, source: SocketAddr);
}

/// Default handler that logs messages
pub struct DefaultSyslogHandler {
    parse_dns_logs: bool,
}

impl DefaultSyslogHandler {
    pub fn new(parse_dns_logs: bool) -> Self {
        Self { parse_dns_logs }
    }
}

#[async_trait::async_trait]
impl SyslogHandler for DefaultSyslogHandler {
    async fn handle_message(&self, message: SyslogMessage, source: SocketAddr) {
        info!(
            "[{}] {} {} - {}: {}",
            source,
            message.facility_str(),
            message.severity_str(),
            message.app_name.as_deref().unwrap_or("unknown"),
            message.message
        );

        if self.parse_dns_logs
            && let Some(dns_entry) = DnsLogEntry::from_syslog(&message)
        {
            info!(
                "DNS Query: {} asked for {} ({}) -> {:?}",
                dns_entry.client_ip,
                dns_entry.query_name,
                dns_entry.query_type,
                dns_entry.response_ips
            );
        }
    }
}

/// Syslog listener that can receive messages via UDP and TCP.
///
/// The listener is wired to a [`SyslogHandler`] that determines what happens to
/// each parsed message.  Two handlers are provided:
///
/// - [`DefaultSyslogHandler`]: logs the message and optionally runs DNS-log
///   extraction when `parse_dns` is enabled.
/// - `SyslogS3Handler` (in `forwarding::syslog_s3`): buffers messages and
///   persists them to S3 as Parquet.
///
/// **Important:** `SyslogS3Handler` and DNS-log parsing (`parse_dns`) are
/// currently **mutually exclusive**.  When `[syslog.s3]` is configured in
/// `logthing.toml`, the server uses `SyslogS3Handler` and DNS-log extraction
/// does **not** run.  If you need both persistence and DNS parsing, use the
/// default handler and route syslog traffic to an external pipeline for S3
/// ingestion.  Combining both is a planned future feature.
pub struct SyslogListener {
    config: SyslogListenerConfig,
    handler: Arc<dyn SyslogHandler>,
}

impl SyslogListener {
    pub fn new(config: SyslogListenerConfig, handler: Arc<dyn SyslogHandler>) -> Self {
        Self { config, handler }
    }

    /// Start both UDP and TCP listeners (no shutdown signal — runs until externally aborted).
    pub async fn start(&self) -> anyhow::Result<()> {
        let udp_listener = self.start_udp_listener();
        let tcp_listener = self.start_tcp_listener();

        tokio::select! {
            result = udp_listener => {
                if let Err(e) = result {
                    error!("UDP listener error: {}", e);
                }
            }
            result = tcp_listener => {
                if let Err(e) = result {
                    error!("TCP listener error: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Start both UDP and TCP listeners with graceful shutdown support.
    ///
    /// The listener exits cleanly when `shutdown_rx` receives `true` (or is closed).
    /// Used from `main.rs`; tests continue to use `start()` or `run_with_listener()`.
    pub async fn start_with_shutdown(
        &self,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let semaphore = Arc::new(Semaphore::new(MAX_SYSLOG_TCP_CONNECTIONS));

        let udp_addr: SocketAddr =
            format!("{}:{}", self.config.bind_address, self.config.udp_port).parse()?;
        let tcp_addr: SocketAddr =
            format!("{}:{}", self.config.bind_address, self.config.tcp_port).parse()?;

        let udp_socket = UdpSocket::bind(&udp_addr).await?;
        info!("Syslog UDP listener started on {}", udp_addr);
        let tcp_listener = TcpListener::bind(&tcp_addr).await?;
        info!("Syslog TCP listener started on {}", tcp_addr);

        let mut buf = vec![0u8; 65535];
        let handler_udp = self.handler.clone();
        let handler_tcp = self.handler.clone();

        loop {
            tokio::select! {
                // UDP receive arm
                result = udp_socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, src)) => {
                            let msg = String::from_utf8_lossy(&buf[..len]);
                            debug!("Received UDP syslog message from {}: {} bytes", src, len);
                            metrics::counter!("syslog_messages_received").increment(1);
                            if let Some(syslog_msg) = SyslogMessage::parse(&msg) {
                                handler_udp.handle_message(syslog_msg, src).await;
                            } else {
                                metrics::counter!("syslog_parse_errors").increment(1);
                                warn!(
                                    "Failed to parse syslog message from {}: {}",
                                    src,
                                    &msg[..100.min(msg.len())]
                                );
                            }
                        }
                        Err(e) => {
                            error!("UDP receive error: {}", e);
                        }
                    }
                }
                // TCP accept arm
                result = tcp_listener.accept() => {
                    match result {
                        Ok((stream, src)) => {
                            // Acquire semaphore permit before spawning — bounds concurrent connections
                            match semaphore.clone().try_acquire_owned() {
                                Ok(permit) => {
                                    let handler = handler_tcp.clone();
                                    tokio::spawn(async move {
                                        let _permit = permit; // held for connection lifetime
                                        if let Err(e) = Self::handle_tcp_connection(stream, src, handler).await {
                                            error!("TCP connection error from {}: {}", src, e);
                                        }
                                    });
                                }
                                Err(_) => {
                                    // Semaphore exhausted — too many connections; drop this one
                                    metrics::counter!("syslog_tcp_connections_rejected").increment(1);
                                    warn!(
                                        "Syslog: TCP connection limit ({}) reached; rejecting {}",
                                        MAX_SYSLOG_TCP_CONNECTIONS, src
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            error!("TCP accept error: {}", e);
                        }
                    }
                }
                // Shutdown arm
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Syslog listener: shutdown signal received");
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Start UDP syslog listener
    async fn start_udp_listener(&self) -> anyhow::Result<()> {
        let addr: SocketAddr =
            format!("{}:{}", self.config.bind_address, self.config.udp_port).parse()?;

        let socket = UdpSocket::bind(&addr).await?;
        info!("Syslog UDP listener started on {}", addr);

        let mut buf = vec![0u8; 65535];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    let msg = String::from_utf8_lossy(&buf[..len]);
                    debug!("Received UDP syslog message from {}: {} bytes", src, len);

                    metrics::counter!("syslog_messages_received").increment(1);
                    if let Some(syslog_msg) = SyslogMessage::parse(&msg) {
                        self.handler.handle_message(syslog_msg, src).await;
                    } else {
                        metrics::counter!("syslog_parse_errors").increment(1);
                        warn!(
                            "Failed to parse syslog message from {}: {}",
                            src,
                            &msg[..100.min(msg.len())]
                        );
                    }
                }
                Err(e) => {
                    error!("UDP receive error: {}", e);
                }
            }
        }
    }

    /// Start TCP syslog listener (newline framing only).
    ///
    /// Each message is terminated by a `\n` byte (RFC 6587 §3.4.2 non-transparent
    /// framing).  RFC 6587 octet-counting framing (§3.4.1) is **not** implemented.
    async fn start_tcp_listener(&self) -> anyhow::Result<()> {
        let addr: SocketAddr =
            format!("{}:{}", self.config.bind_address, self.config.tcp_port).parse()?;

        let listener = TcpListener::bind(&addr).await?;
        self.run_with_listener(listener).await
    }

    /// Run the accept loop on an already-bound listener.
    /// Extracted for testability — tests bind their own listener to get a known port.
    pub(crate) async fn run_with_listener(&self, listener: TcpListener) -> anyhow::Result<()> {
        let bound = listener.local_addr()?;
        info!("Syslog TCP listener started on {}", bound);

        let semaphore = Arc::new(Semaphore::new(MAX_SYSLOG_TCP_CONNECTIONS));

        loop {
            match listener.accept().await {
                Ok((stream, src)) => {
                    match semaphore.clone().try_acquire_owned() {
                        Ok(permit) => {
                            let handler = self.handler.clone();
                            tokio::spawn(async move {
                                let _permit = permit; // held for connection lifetime
                                if let Err(e) =
                                    Self::handle_tcp_connection(stream, src, handler).await
                                {
                                    error!("TCP connection error from {}: {}", src, e);
                                }
                            });
                        }
                        Err(_) => {
                            metrics::counter!("syslog_tcp_connections_rejected").increment(1);
                            warn!(
                                "Syslog: TCP connection limit ({}) reached; rejecting {}",
                                MAX_SYSLOG_TCP_CONNECTIONS, src
                            );
                        }
                    }
                }
                Err(e) => {
                    error!("TCP accept error: {}", e);
                }
            }
        }
    }

    /// Handle a TCP connection for syslog: bounded read_until loop, one message per line.
    ///
    /// Each iteration reads at most `SYSLOG_MAX_LINE_BYTES + 1` bytes via a
    /// `take` adapter, so heap growth per connection is provably bounded by that
    /// constant regardless of client behaviour.  If the cap is hit without a
    /// terminating `\n` the connection is closed immediately; resyncing would
    /// itself require unbounded buffering.
    async fn handle_tcp_connection(
        stream: TcpStream,
        src: SocketAddr,
        handler: Arc<dyn SyslogHandler>,
    ) -> anyhow::Result<()> {
        let mut reader = BufReader::new(stream);
        let mut buf: Vec<u8> = Vec::new();

        loop {
            buf.clear();
            let mut limited = (&mut reader).take((SYSLOG_MAX_LINE_BYTES as u64) + 1);
            let n = match limited.read_until(b'\n', &mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    error!("TCP read error from {}: {}", src, e);
                    break;
                }
            };
            if n == 0 {
                // Connection closed cleanly.
                debug!("TCP connection from {} closed", src);
                break;
            }
            // If we read SYSLOG_MAX_LINE_BYTES+1 bytes and the last byte is NOT
            // a newline, the line exceeded the cap — close immediately.
            if buf.len() > SYSLOG_MAX_LINE_BYTES && buf.last() != Some(&b'\n') {
                metrics::counter!("syslog_oversized_lines").increment(1);
                warn!(
                    "Syslog: line from {} exceeded {} bytes; closing connection",
                    src, SYSLOG_MAX_LINE_BYTES
                );
                break;
            }
            // Trim trailing \r\n / \n.
            if buf.last() == Some(&b'\n') {
                buf.pop();
            }
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
            if buf.is_empty() {
                continue;
            }
            let line = String::from_utf8_lossy(&buf);
            debug!(
                "Received TCP syslog message from {}: {} bytes",
                src,
                line.len()
            );
            metrics::counter!("syslog_messages_received").increment(1);
            if let Some(syslog_msg) = SyslogMessage::parse(&line) {
                handler.handle_message(syslog_msg, src).await;
            } else {
                metrics::counter!("syslog_parse_errors").increment(1);
                warn!(
                    "Failed to parse TCP syslog message from {}: {}",
                    src,
                    &line[..100.min(line.len())]
                );
            }
        }

        Ok(())
    }
}

/// Example DNS syslog records for testing
pub mod examples {
    /// BIND/named DNS query log examples
    pub const BIND_DNS_QUERIES: &[&str] = &[
        // Standard A record query
        "<134>Jan 15 10:30:45 dns-server named[1234]: client 192.168.1.100#12345: query: example.com IN A + (93.184.216.34)",
        // AAAA record query
        "<134>Jan 15 10:30:46 dns-server named[1234]: client 192.168.1.100#12346: query: example.com IN AAAA + (2606:2800:220:1:248:1893:25c8:1946)",
        // MX record query
        "<134>Jan 15 10:30:47 dns-server named[1234]: client 192.168.1.101#12347: query: gmail.com IN MX + (172.217.0.5)",
        // NXDOMAIN response
        "<134>Jan 15 10:30:48 dns-server named[1234]: client 192.168.1.102#12348: query: nonexistent.example.com IN A - (NXDOMAIN)",
        // CNAME chain
        "<134>Jan 15 10:30:49 dns-server named[1234]: client 192.168.1.103#12349: query: www.example.com IN CNAME + (example.com)",
        // TXT record (SPF)
        "<134>Jan 15 10:30:50 dns-server named[1234]: client 192.168.1.104#12350: query: example.com IN TXT + (\"v=spf1 include:_spf.google.com ~all\")",
        // PTR record (reverse DNS)
        "<134>Jan 15 10:30:51 dns-server named[1234]: client 192.168.1.105#12351: query: 34.216.184.93.in-addr.arpa IN PTR + (example.com)",
        // NS record query
        "<134>Jan 15 10:30:52 dns-server named[1234]: client 192.168.1.106#12352: query: example.com IN NS + (a.iana-servers.net)",
        // SOA record query
        "<134>Jan 15 10:30:53 dns-server named[1234]: client 192.168.1.107#12353: query: example.com IN SOA + (ns.icann.org)",
        // DNSSEC related
        "<134>Jan 15 10:30:54 dns-server named[1234]: client 192.168.1.108#12354: query: example.com IN DNSKEY + (256 3 8 ...)",
    ];

    /// Unbound DNS query log examples
    pub const UNBOUND_DNS_QUERIES: &[&str] = &[
        "<134>Jan 15 10:31:00 dns-server unbound[5678]: info: 192.168.1.100 example.com. A IN",
        "<134>Jan 15 10:31:01 dns-server unbound[5678]: info: 192.168.1.101 google.com. AAAA IN",
        "<134>Jan 15 10:31:02 dns-server unbound[5678]: info: 192.168.1.102 github.com. A IN",
    ];

    /// PowerDNS query log examples
    pub const POWERDNS_QUERIES: &[&str] = &[
        "<134>Jan 15 10:32:00 dns-server pdns[9012]: Remote 192.168.1.100 wants 'example.com|A', do = 0, bufsize = 512",
        "<134>Jan 15 10:32:01 dns-server pdns[9012]: Remote 192.168.1.101 wants 'google.com|AAAA', do = 1, bufsize = 1232",
        "<134>Jan 15 10:32:02 dns-server pdns[9012]: Remote 192.168.1.102 wants 'api.github.com|A', do = 0, bufsize = 512",
    ];

    /// RFC 5424 formatted syslog with structured data
    pub const RFC5424_DNS_LOGS: &[&str] = &[
        r#"<165>1 2024-01-15T10:33:45.000Z dns-server named 1234 - [dns@12345 query="example.com" type="A" client="192.168.1.100" response="93.184.216.34"] DNS query processed"#,
        r#"<165>1 2024-01-15T10:33:46.000Z dns-server named 1234 - [dns@12345 query="google.com" type="AAAA" client="192.168.1.101" response="2607:f8b0:4004:c06::8a"] DNS query processed"#,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::time::sleep;

    /// Test handler that captures received messages.
    struct CapturingHandler {
        messages: Mutex<Vec<SyslogMessage>>,
    }

    impl CapturingHandler {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                messages: Mutex::new(Vec::new()),
            })
        }
        fn take_messages(&self) -> Vec<SyslogMessage> {
            self.messages.lock().unwrap().drain(..).collect()
        }
    }

    #[async_trait::async_trait]
    impl SyslogHandler for CapturingHandler {
        async fn handle_message(&self, message: SyslogMessage, _source: SocketAddr) {
            self.messages.lock().unwrap().push(message);
        }
    }

    #[tokio::test]
    async fn test_udp_listener() {
        let config = SyslogListenerConfig {
            udp_port: 1514, // Use non-privileged port for testing
            tcp_port: 1601,
            ..Default::default()
        };

        let handler = Arc::new(DefaultSyslogHandler::new(config.parse_dns_logs));
        let listener = SyslogListener::new(config, handler);

        // Start listener in background
        let listener_handle = tokio::spawn(async move {
            listener.start().await.ok();
        });

        // Give listener time to start
        sleep(Duration::from_millis(100)).await;

        // Send test message
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let test_msg = examples::BIND_DNS_QUERIES[0];
        socket
            .send_to(test_msg.as_bytes(), "127.0.0.1:1514")
            .await
            .unwrap();

        // Give time to process
        sleep(Duration::from_millis(100)).await;

        listener_handle.abort();
    }

    /// Integration test: a newline-terminated syslog message is parsed and dispatched.
    #[tokio::test]
    async fn tcp_listener_dispatches_valid_syslog_message() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();
        let listener = SyslogListener::new(SyslogListenerConfig::default(), handler_clone);

        let task = tokio::spawn(async move {
            listener.run_with_listener(tcp_listener).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        // A valid RFC 3164 syslog line terminated with \n.
        let msg = b"<134>Jan 15 10:30:45 host app: test message\n";
        stream.write_all(msg).await.unwrap();
        drop(stream);

        sleep(Duration::from_millis(150)).await;
        task.abort();

        let messages = handler.take_messages();
        assert_eq!(
            messages.len(),
            1,
            "expected 1 dispatched message, got {}",
            messages.len()
        );
    }

    /// Integration test: a line exceeding SYSLOG_MAX_LINE_BYTES (with no newline) closes
    /// the connection and does NOT dispatch a record, and increments `syslog_oversized_lines`.
    ///
    /// Determinism: we use `run_with_listener` with an ephemeral port and send exactly
    /// SYSLOG_MAX_LINE_BYTES + 1 bytes with no `\n`. The `take` adapter limits the read to
    /// that size and detects the overrun immediately — no timing ambiguity.
    #[tokio::test]
    #[allow(clippy::mutable_key_type)] // clippy false positive: CompositeKey interior mutability (AtomicBool) is never used for hashing
    async fn oversized_line_closes_connection_and_increments_metric() {
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::DebuggingRecorder;
        use tokio::io::AsyncReadExt;
        use tokio::time::timeout;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();
        let listener = SyslogListener::new(SyslogListenerConfig::default(), handler_clone);

        let task = tokio::spawn(async move {
            listener.run_with_listener(tcp_listener).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        // Send SYSLOG_MAX_LINE_BYTES + 1 bytes of 'x' with NO newline.
        let oversized = vec![b'x'; SYSLOG_MAX_LINE_BYTES + 1];
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _ = stream.write_all(&oversized).await;

        // The server should close its half of the connection promptly.
        let result = timeout(Duration::from_secs(2), async {
            let mut sink = Vec::new();
            stream.read_to_end(&mut sink).await
        })
        .await;
        assert!(
            result.is_ok(),
            "server did not close oversized connection within 2 s"
        );

        // No record should have been dispatched.
        sleep(Duration::from_millis(50)).await;
        task.abort();

        let messages = handler.take_messages();
        assert!(
            messages.is_empty(),
            "oversized input must not produce a message; got {}",
            messages.len()
        );

        // Assert the metric counter was incremented exactly once.
        let snapshot = snapshotter.snapshot();
        let map = snapshot.into_hashmap();
        let key = CompositeKey::new(
            MetricKind::Counter,
            metrics::Key::from_name("syslog_oversized_lines"),
        );
        let count = map
            .get(&key)
            .map(|(_, _, v)| {
                if let metrics_util::debugging::DebugValue::Counter(c) = v {
                    *c
                } else {
                    0
                }
            })
            .unwrap_or(0);
        assert_eq!(
            count, 1,
            "syslog_oversized_lines counter must be 1; got {count}"
        );
    }

    /// After an oversized-line disconnection, a new connection still works correctly.
    #[tokio::test]
    async fn valid_connection_after_oversized_still_works() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();
        let listener = SyslogListener::new(SyslogListenerConfig::default(), handler_clone);

        let task = tokio::spawn(async move {
            listener.run_with_listener(tcp_listener).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        // First connection: oversized (no newline).
        {
            use tokio::io::AsyncReadExt;
            let oversized = vec![b'x'; SYSLOG_MAX_LINE_BYTES + 1];
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let _ = stream.write_all(&oversized).await;
            let _ = tokio::time::timeout(Duration::from_secs(2), async {
                let mut sink = Vec::new();
                stream.read_to_end(&mut sink).await
            })
            .await;
        }

        // Second connection: valid syslog message.
        {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(b"<134>Jan 15 10:30:45 host app: recovery test\n")
                .await
                .unwrap();
            drop(stream);
        }

        sleep(Duration::from_millis(150)).await;
        task.abort();

        let messages = handler.take_messages();
        assert_eq!(
            messages.len(),
            1,
            "second connection should produce 1 message"
        );
    }

    /// Sending an unparseable syslog line via TCP increments `syslog_parse_errors`
    /// and does NOT dispatch a message to the handler.
    #[tokio::test]
    #[allow(clippy::mutable_key_type)] // clippy false positive: CompositeKey interior mutability (AtomicBool) is never used for hashing
    async fn parse_error_increments_metric_and_no_dispatch() {
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::DebuggingRecorder;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();
        let listener = SyslogListener::new(SyslogListenerConfig::default(), handler_clone);

        let task = tokio::spawn(async move {
            listener.run_with_listener(tcp_listener).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        // Send a line that is not a valid syslog message.
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"this is not a syslog message at all\n")
            .await
            .unwrap();
        drop(stream);

        sleep(Duration::from_millis(150)).await;
        task.abort();

        // No message should have been dispatched.
        let messages = handler.take_messages();
        assert!(
            messages.is_empty(),
            "unparseable input must not produce a message; got {}",
            messages.len()
        );

        // syslog_parse_errors counter should be incremented exactly once.
        let snapshot = snapshotter.snapshot();
        let map = snapshot.into_hashmap();
        let key = CompositeKey::new(
            MetricKind::Counter,
            metrics::Key::from_name("syslog_parse_errors"),
        );
        let count = map
            .get(&key)
            .map(|(_, _, v)| {
                if let metrics_util::debugging::DebugValue::Counter(c) = v {
                    *c
                } else {
                    0
                }
            })
            .unwrap_or(0);
        assert_eq!(
            count, 1,
            "syslog_parse_errors counter must be 1; got {count}"
        );
    }
}
