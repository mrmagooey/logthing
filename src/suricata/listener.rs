//! Suricata TCP EVE JSON listener.

use crate::middleware::IpWhitelist;
use crate::suricata::SuricataRecord;
use chrono::Utc;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

/// Maximum number of concurrent TCP connections accepted by the Suricata listener.
/// Prevents resource exhaustion from connection floods.
pub const MAX_SURICATA_TCP_CONNECTIONS: usize = 1024;

/// Maximum accepted line length in bytes. Lines exceeding this are skipped
/// and counted via `suricata_oversized_lines`.
pub const SURICATA_MAX_LINE_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

/// Maximum time a TCP connection may sit without delivering a complete line
/// before it is closed. Without this, a client that connects and sends
/// nothing holds a connection-semaphore permit for the process's lifetime,
/// so 1024 silent sockets exhaust the listener. Not exposed via
/// `SuricataListenerConfig` (unlike syslog's `tcp_idle_timeout`): every
/// existing caller of `SuricataListenerConfig` — production and tests alike
/// — builds it as a bare 2-field literal with no `..Default::default()`, so
/// a new required field would ripple through all of them for no production
/// benefit.
///
/// The `#[cfg(test)]` override below is visible to every test in this file,
/// including ones that drive the real accept loop via `run_with_listener`
/// (unlike syslog's external `tests/` integration test, these are in-crate
/// `#[cfg(test)]` tests compiled as part of this same crate, so they DO see
/// this cfg-gated value) — that lets a test exercise the production
/// `let idle_timeout = TCP_IDLE_TIMEOUT;` wiring at the accept-loop call
/// sites directly, not just `handle_tcp_connection` in isolation with a
/// hand-passed `Duration`. 500ms is short enough to keep that test fast but
/// comfortably longer than the connect-then-write latency every other test
/// in this file relies on, so it does not introduce flakiness in tests that
/// were not written with an idle timeout in mind.
#[cfg(not(test))]
pub(crate) const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
#[cfg(test)]
pub(crate) const TCP_IDLE_TIMEOUT: Duration = Duration::from_millis(500);

/// Configuration for the Suricata TCP EVE JSON listener.
#[derive(Debug, Clone)]
pub struct SuricataListenerConfig {
    pub tcp_port: u16,
    pub bind_address: String,
}

impl Default for SuricataListenerConfig {
    fn default() -> Self {
        Self {
            tcp_port: 47761,
            bind_address: "0.0.0.0".to_string(),
        }
    }
}

/// Handler trait for decoded Suricata records.
#[async_trait::async_trait]
pub trait SuricataHandler: Send + Sync {
    async fn handle_record(&self, record: SuricataRecord, source: SocketAddr);
}

/// Default handler: logs a summary. Installed only when no forwarding
/// destination is configured; the ingest counters live in the listener's
/// parse loop so they fire for every handler.
pub struct DefaultSuricataHandler;

#[async_trait::async_trait]
impl SuricataHandler for DefaultSuricataHandler {
    async fn handle_record(&self, record: SuricataRecord, source: SocketAddr) {
        info!(
            "[{}] suricata record: event_type={} fields={}",
            source,
            record.event_type,
            record
                .fields
                .to_string()
                .chars()
                .take(120)
                .collect::<String>(),
        );
    }
}

/// Suricata TCP EVE JSON listener.
pub struct SuricataListener {
    config: SuricataListenerConfig,
    handler: Arc<dyn SuricataHandler>,
    allowed_ips: IpWhitelist,
}

impl SuricataListener {
    pub fn new(config: SuricataListenerConfig, handler: Arc<dyn SuricataHandler>) -> Self {
        Self {
            config,
            handler,
            allowed_ips: IpWhitelist::empty(),
        }
    }

    /// Restrict this listener to sources in `allowed_ips`. Defaults to
    /// [`IpWhitelist::empty()`] (allow all) via `new()`.
    pub fn with_allowed_ips(mut self, allowed_ips: IpWhitelist) -> Self {
        self.allowed_ips = allowed_ips;
        self
    }

    /// Bind the TCP listener and run the accept loop (no shutdown signal — runs until aborted).
    pub async fn start(&self) -> anyhow::Result<()> {
        let addr: SocketAddr =
            format!("{}:{}", self.config.bind_address, self.config.tcp_port).parse()?;
        let listener = TcpListener::bind(&addr).await?;
        self.run_with_listener(listener).await
    }

    /// Bind the TCP listener and run the accept loop with graceful shutdown support.
    ///
    /// The listener exits cleanly when `shutdown_rx` receives `true` (or is closed).
    /// Used from `main.rs`; tests continue to use `start()` or `run_with_listener()`.
    pub async fn start_with_shutdown(
        &self,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let addr: SocketAddr =
            format!("{}:{}", self.config.bind_address, self.config.tcp_port).parse()?;
        let listener = TcpListener::bind(&addr).await?;
        let bound = listener.local_addr()?;
        info!("Suricata TCP listener started on {}", bound);

        let semaphore = Arc::new(Semaphore::new(MAX_SURICATA_TCP_CONNECTIONS));

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, src)) => {
                            // ponytail: any new recv/accept arm in this module needs this same is_allowed check.
                            if !self.allowed_ips.is_allowed(&src) {
                                metrics::counter!("listener_source_rejected", "protocol" => "suricata").increment(1);
                                warn!("Rejected suricata connection from {} — not in allowed_ips", src);
                                continue;
                            }
                            match semaphore.clone().try_acquire_owned() {
                                Ok(permit) => {
                                    let handler = self.handler.clone();
                                    let idle_timeout = TCP_IDLE_TIMEOUT;
                                    tokio::spawn(async move {
                                        let _permit = permit; // held for connection lifetime
                                        if let Err(e) = Self::handle_tcp_connection(stream, src, handler, idle_timeout).await {
                                            error!("Suricata TCP connection error from {}: {}", src, e);
                                        }
                                    });
                                }
                                Err(_) => {
                                    metrics::counter!("suricata_tcp_connections_rejected").increment(1);
                                    warn!(
                                        "Suricata: TCP connection limit ({}) reached; rejecting {}",
                                        MAX_SURICATA_TCP_CONNECTIONS, src
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            error!("Suricata TCP accept error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Suricata listener: shutdown signal received");
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Run the accept loop on an already-bound listener.
    /// Extracted for testability — tests bind their own listener to get a known port.
    pub(crate) async fn run_with_listener(&self, listener: TcpListener) -> anyhow::Result<()> {
        let bound = listener.local_addr()?;
        info!("Suricata TCP listener started on {}", bound);

        let semaphore = Arc::new(Semaphore::new(MAX_SURICATA_TCP_CONNECTIONS));

        loop {
            match listener.accept().await {
                Ok((stream, src)) => {
                    if !self.allowed_ips.is_allowed(&src) {
                        metrics::counter!("listener_source_rejected", "protocol" => "suricata")
                            .increment(1);
                        warn!(
                            "Rejected suricata connection from {} — not in allowed_ips",
                            src
                        );
                        continue;
                    }
                    match semaphore.clone().try_acquire_owned() {
                        Ok(permit) => {
                            let handler = self.handler.clone();
                            let idle_timeout = TCP_IDLE_TIMEOUT;
                            tokio::spawn(async move {
                                let _permit = permit; // held for connection lifetime
                                if let Err(e) =
                                    Self::handle_tcp_connection(stream, src, handler, idle_timeout)
                                        .await
                                {
                                    error!("Suricata TCP connection error from {}: {}", src, e);
                                }
                            });
                        }
                        Err(_) => {
                            metrics::counter!("suricata_tcp_connections_rejected").increment(1);
                            warn!(
                                "Suricata: TCP connection limit ({}) reached; rejecting {}",
                                MAX_SURICATA_TCP_CONNECTIONS, src
                            );
                        }
                    }
                }
                Err(e) => {
                    error!("Suricata TCP accept error: {}", e);
                }
            }
        }
    }

    /// Handle one TCP connection: BufReader + bounded read_until loop, one EVE JSON record per line.
    async fn handle_tcp_connection(
        stream: TcpStream,
        src: SocketAddr,
        handler: Arc<dyn SuricataHandler>,
        idle_timeout: Duration,
    ) -> anyhow::Result<()> {
        let mut reader = BufReader::new(stream);
        let mut buf: Vec<u8> = Vec::new();

        loop {
            buf.clear();
            let mut limited = (&mut reader).take((SURICATA_MAX_LINE_BYTES as u64) + 1);
            let n = match tokio::time::timeout(idle_timeout, limited.read_until(b'\n', &mut buf))
                .await
            {
                Err(_elapsed) => {
                    metrics::counter!("suricata_tcp_idle_timeouts").increment(1);
                    debug!(
                        "Suricata TCP connection from {} idle past timeout; closing",
                        src
                    );
                    break;
                }
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    error!("Suricata TCP read error from {}: {}", src, e);
                    break;
                }
            };
            if n == 0 {
                debug!("Suricata TCP connection from {} closed", src);
                break;
            }
            // If we read SURICATA_MAX_LINE_BYTES+1 bytes and the last byte is NOT a newline,
            // the line exceeded the cap — close the connection (resyncing is itself unbounded).
            if buf.len() > SURICATA_MAX_LINE_BYTES && buf.last() != Some(&b'\n') {
                metrics::counter!("suricata_oversized_lines").increment(1);
                warn!(
                    "Suricata: line from {} exceeded {} bytes; closing connection",
                    src, SURICATA_MAX_LINE_BYTES
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
            let line = match std::str::from_utf8(&buf) {
                Ok(s) => s,
                Err(_) => {
                    metrics::counter!("suricata_parse_errors").increment(1);
                    warn!("Suricata: non-UTF-8 line from {}; skipping", src);
                    continue;
                }
            };
            let parsed = match crate::suricata::parse_line(line, Utc::now()) {
                Ok(p) => p,
                Err(e) => {
                    metrics::counter!("suricata_parse_errors").increment(1);
                    warn!(
                        "Suricata: JSON parse error from {}: {} — line: {}",
                        src,
                        e,
                        crate::truncate_for_log(line, 120),
                    );
                    continue;
                }
            };
            if parsed.event_type_was_missing {
                metrics::counter!("suricata_missing_event_type").increment(1);
            }
            // Counted here, not in a handler impl: every handler
            // (DefaultSuricataHandler, MultiSuricataHandler, ...) routes
            // through this one point, so the metric is emitted regardless of
            // which forwarding destinations are configured.
            metrics::counter!("suricata_records_received").increment(1);
            metrics::counter!("suricata_records_by_event_type",
                "event_type" => crate::suricata::schema::metric_event_type(&parsed.record.event_type)
            )
            .increment(1);
            handler.handle_record(parsed.record, src).await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::time::sleep;

    struct CapturingHandler {
        records: Mutex<Vec<SuricataRecord>>,
    }

    impl CapturingHandler {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                records: Mutex::new(Vec::new()),
            })
        }
        fn take_records(&self) -> Vec<SuricataRecord> {
            self.records.lock().unwrap().drain(..).collect()
        }
    }

    #[async_trait::async_trait]
    impl SuricataHandler for CapturingHandler {
        async fn handle_record(&self, record: SuricataRecord, _source: SocketAddr) {
            self.records.lock().unwrap().push(record);
        }
    }

    // -- Unit: event_type extraction --

    #[test]
    fn extract_event_type_from_json() {
        let value = serde_json::json!({"event_type": "alert", "src_ip": "10.0.0.1"});
        let event_type = value
            .get("event_type")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        assert_eq!(event_type, "alert");
    }

    #[test]
    fn missing_event_type_field_gives_unknown() {
        let value = serde_json::json!({"src_ip": "10.0.0.1"});
        let event_type = value
            .get("event_type")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        assert_eq!(event_type, "unknown");
    }

    #[test]
    fn non_string_event_type_gives_unknown() {
        let value = serde_json::json!({"event_type": 42, "src_ip": "10.0.0.1"});
        let event_type = value
            .get("event_type")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        assert_eq!(event_type, "unknown");
    }

    // -- Shutdown --

    #[tokio::test]
    async fn start_with_shutdown_exits_on_signal() {
        use tokio::sync::watch;
        use tokio::time::timeout;

        let tmp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = tmp.local_addr().unwrap().port();
        drop(tmp);

        let config = SuricataListenerConfig {
            tcp_port,
            bind_address: "127.0.0.1".to_string(),
        };
        let handler: Arc<dyn SuricataHandler> = Arc::new(DefaultSuricataHandler);
        let listener = SuricataListener::new(config, handler);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            listener.start_with_shutdown(shutdown_rx).await.ok();
        });
        sleep(Duration::from_millis(50)).await;
        shutdown_tx.send(true).unwrap();
        let result = timeout(Duration::from_secs(2), task).await;
        assert!(
            result.is_ok(),
            "start_with_shutdown did not return within 2s"
        );
    }

    // -- Integration: TCP listener receives records --

    #[tokio::test]
    async fn listener_dispatches_records_from_ndjson_stream() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let listener = SuricataListener::new(SuricataListenerConfig::default(), handler.clone());
        let task = tokio::spawn(async move {
            listener.run_with_listener(tcp_listener).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let lines = concat!(
            r#"{"event_type":"alert","src_ip":"1.2.3.4","ts":"2024-01-01T00:00:00Z"}"#,
            "\n",
            r#"{"event_type":"flow","src_ip":"5.6.7.8","ts":"2024-01-01T00:00:01Z"}"#,
            "\n",
        );
        stream.write_all(lines.as_bytes()).await.unwrap();
        drop(stream);

        sleep(Duration::from_millis(150)).await;
        task.abort();

        let records = handler.take_records();
        assert_eq!(
            records.len(),
            2,
            "expected 2 records, got {}",
            records.len()
        );
        assert_eq!(records[0].event_type, "alert");
        assert_eq!(records[1].event_type, "flow");
    }

    #[tokio::test]
    async fn listener_skips_malformed_json_and_continues() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let listener = SuricataListener::new(SuricataListenerConfig::default(), handler.clone());
        let task = tokio::spawn(async move {
            listener.run_with_listener(tcp_listener).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let lines = concat!(
            "NOT JSON AT ALL\n",
            r#"{"event_type":"dns","query":"example.com"}"#,
            "\n",
        );
        stream.write_all(lines.as_bytes()).await.unwrap();
        drop(stream);

        sleep(Duration::from_millis(150)).await;
        task.abort();

        let records = handler.take_records();
        assert_eq!(
            records.len(),
            1,
            "only the valid record should be dispatched"
        );
        assert_eq!(records[0].event_type, "dns");
    }

    #[tokio::test]
    async fn listener_routes_missing_event_type_to_unknown() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let listener = SuricataListener::new(SuricataListenerConfig::default(), handler.clone());
        let task = tokio::spawn(async move {
            listener.run_with_listener(tcp_listener).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"{\"src_ip\":\"9.9.9.9\"}\n")
            .await
            .unwrap();
        drop(stream);

        sleep(Duration::from_millis(150)).await;
        task.abort();

        let records = handler.take_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].event_type, "unknown");
    }

    /// E2E: bind on ephemeral port, send 3 Suricata EVE JSON records of mixed types
    /// over TCP, assert handler observed all three with correct event_type.
    #[tokio::test]
    async fn e2e_listener_receives_mixed_event_types() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let listener = SuricataListener::new(SuricataListenerConfig::default(), handler.clone());
        let task = tokio::spawn(async move {
            listener.run_with_listener(tcp_listener).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        // Simulate a Suricata EVE JSON agent sending three records
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let ndjson = concat!(
            r#"{"event_type":"alert","src_ip":"10.0.0.1","dest_ip":"8.8.8.8","alert":{"signature":"ET TEST"},"timestamp":"2024-01-15T10:30:00Z"}"#,
            "\n",
            r#"{"event_type":"flow","src_ip":"10.0.0.2","dest_ip":"1.1.1.1","proto":"TCP","timestamp":"2024-01-15T10:30:01Z"}"#,
            "\n",
            r#"{"event_type":"dns","src_ip":"10.0.0.3","dns":{"type":"query","rrname":"example.com"},"timestamp":"2024-01-15T10:30:02Z"}"#,
            "\n",
        );
        stream.write_all(ndjson.as_bytes()).await.unwrap();
        drop(stream);

        sleep(Duration::from_millis(200)).await;
        task.abort();

        let records = handler.take_records();
        assert_eq!(
            records.len(),
            3,
            "expected 3 records, got {}",
            records.len()
        );

        let event_types: Vec<&str> = records.iter().map(|r| r.event_type.as_str()).collect();
        assert_eq!(event_types, vec!["alert", "flow", "dns"]);

        // Assert fields are preserved
        assert_eq!(records[0].fields["src_ip"], "10.0.0.1");
        assert_eq!(records[1].fields["proto"], "TCP");
        assert_eq!(records[2].fields["dns"]["rrname"], "example.com");
    }

    /// E2E: records without event_type fall back to "unknown" and are still delivered.
    #[tokio::test]
    async fn e2e_missing_event_type_records_arrive_as_unknown() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let listener = SuricataListener::new(SuricataListenerConfig::default(), handler.clone());
        let task = tokio::spawn(async move {
            listener.run_with_listener(tcp_listener).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let ndjson = concat!(
            // Valid with event_type
            r#"{"event_type":"stats","uptime":3600}"#,
            "\n",
            // Missing event_type — must arrive as "unknown"
            r#"{"uptime":7200,"iface":"eth0"}"#,
            "\n",
            // Malformed JSON — must be skipped entirely
            "GARBAGE\n",
            // Valid with event_type — must arrive
            r#"{"event_type":"anomaly","anomaly":{"type":"pkt"}}"#,
            "\n",
        );
        stream.write_all(ndjson.as_bytes()).await.unwrap();
        drop(stream);

        sleep(Duration::from_millis(200)).await;
        task.abort();

        let records = handler.take_records();
        assert_eq!(
            records.len(),
            3,
            "expected 3 records (1 malformed skipped), got {}",
            records.len()
        );
        assert_eq!(records[0].event_type, "stats");
        assert_eq!(records[1].event_type, "unknown");
        assert_eq!(records[2].event_type, "anomaly");
    }

    #[tokio::test]
    #[allow(clippy::mutable_key_type)]
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
        let listener = SuricataListener::new(SuricataListenerConfig::default(), handler.clone());
        let task = tokio::spawn(async move {
            listener.run_with_listener(tcp_listener).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let oversized = vec![b'x'; SURICATA_MAX_LINE_BYTES + 1];
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _ = stream.write_all(&oversized).await;

        let result = timeout(Duration::from_secs(2), async {
            let mut sink = Vec::new();
            stream.read_to_end(&mut sink).await
        })
        .await;
        assert!(
            result.is_ok(),
            "server did not close oversized connection within 2s"
        );

        sleep(Duration::from_millis(50)).await;
        task.abort();

        assert!(
            handler.take_records().is_empty(),
            "oversized input must not produce a record"
        );

        let snapshot = snapshotter.snapshot();
        let map = snapshot.into_hashmap();
        let key = CompositeKey::new(
            MetricKind::Counter,
            metrics::Key::from_name("suricata_oversized_lines"),
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
            "suricata_oversized_lines counter must be 1; got {count}"
        );
    }

    /// A source outside `allowed_ips` never reaches the handler.
    #[tokio::test]
    async fn with_allowed_ips_blocks_disallowed_source() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let listener = SuricataListener::new(SuricataListenerConfig::default(), handler.clone())
            .with_allowed_ips(IpWhitelist::new(vec!["10.99.99.0/24".into()]).unwrap());
        let task = tokio::spawn(async move {
            listener.run_with_listener(tcp_listener).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _ = stream
            .write_all(b"{\"event_type\":\"alert\",\"src_ip\":\"1.2.3.4\"}\n")
            .await;
        drop(stream);

        sleep(Duration::from_millis(150)).await;
        task.abort();

        let records = handler.take_records();
        assert!(
            records.is_empty(),
            "blocked source must not reach the handler; got {}",
            records.len()
        );
    }

    /// Guards the `event_type_was_missing` wiring end to end through a real
    /// socket: the counter must fire for an absent `event_type` and must NOT
    /// fire for a record whose `event_type` is literally the string "unknown".
    #[tokio::test]
    #[allow(clippy::mutable_key_type)]
    async fn missing_event_type_counter_fires_only_for_an_absent_event_type() {
        use metrics::set_default_local_recorder;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::{CompositeKey, MetricKind};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            // TWO absent event_type (must count) and ONE literal "unknown"
            // (must not). The 2:1 split is load-bearing: with a symmetric 1:1
            // mix an inverted `if !parsed.event_type_was_missing` would also
            // yield 1 and the test would pass on the bug it exists to catch.
            // Correct => 2, inverted => 1, dropped => 0, double => 4.
            // Not covered: moving the increment after handle_record,
            // which this aggregate assertion cannot see.
            s.write_all(
                b"{\"src_ip\":\"1.1.1.1\"}\n\
                  {\"src_ip\":\"2.2.2.2\"}\n\
                  {\"event_type\":\"unknown\",\"src_ip\":\"3.3.3.3\"}\n",
            )
            .await
            .unwrap();
            s.shutdown().await.unwrap();
        });

        let (stream, src) = listener.accept().await.unwrap();
        SuricataListener::handle_tcp_connection(
            stream,
            src,
            CapturingHandler::new(),
            TCP_IDLE_TIMEOUT,
        )
        .await
        .unwrap();
        client.await.unwrap();

        let map = snapshotter.snapshot().into_hashmap();
        let missing = map
            .get(&CompositeKey::new(
                MetricKind::Counter,
                metrics::Key::from_name("suricata_missing_event_type"),
            ))
            .map(|(_, _, v)| match v {
                DebugValue::Counter(c) => *c,
                _ => 0,
            })
            .unwrap_or(0);
        assert_eq!(
            missing, 2,
            "two of the three records have an absent event_type; a literal \
             event_type of \"unknown\" is a present value and must not be \
             counted. Got 1 => the condition is inverted; got 0 => the \
             increment was dropped."
        );
    }

    // -- Metrics: received counters fire for every handler --

    /// Regression: `suricata_records_received` / `suricata_records_by_event_type`
    /// used to be incremented inside `DefaultSuricataHandler`, which `main.rs`
    /// only installs when NO forwarding destination is configured. Any real
    /// deployment wires a forwarding handler instead, so the counters never
    /// fired and never appeared on `/metrics`. They now live in the
    /// connection parse path, so they must be emitted with a non-default
    /// handler.
    #[tokio::test]
    #[allow(clippy::mutable_key_type)] // false positive: CompositeKey AtomicBool is never hashed
    async fn received_counters_fire_with_a_non_default_handler() {
        use metrics::set_default_local_recorder;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::{CompositeKey, MetricKind};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        // Thread-local recorder: `handle_tcp_connection` is awaited inline below
        // (not spawned), so it runs on this thread and sees it.
        let _guard = set_default_local_recorder(&recorder);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Write both lines and close the write half first; the payload is tiny
        // enough to sit in the socket buffer until the reader drains it.
        let client = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(
                    b"{\"event_type\":\"alert\",\"src_ip\":\"1.2.3.4\"}\n\
                      {\"event_type\":\"flow\",\"src_ip\":\"5.6.7.8\"}\n",
                )
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        });

        let (stream, src) = listener.accept().await.unwrap();
        let handler = CapturingHandler::new();
        SuricataListener::handle_tcp_connection(stream, src, handler.clone(), TCP_IDLE_TIMEOUT)
            .await
            .unwrap();
        client.await.unwrap();

        assert_eq!(handler.take_records().len(), 2, "both records parsed");

        let map = snapshotter.snapshot().into_hashmap();
        let read = |key: CompositeKey| {
            map.get(&key)
                .map(|(_, _, v)| match v {
                    DebugValue::Counter(c) => *c,
                    _ => 0,
                })
                .unwrap_or(0)
        };

        assert_eq!(
            read(CompositeKey::new(
                MetricKind::Counter,
                metrics::Key::from_name("suricata_records_received"),
            )),
            2,
            "suricata_records_received must count every parsed record"
        );
        for event_type in ["alert", "flow"] {
            assert_eq!(
                read(CompositeKey::new(
                    MetricKind::Counter,
                    metrics::Key::from_parts(
                        "suricata_records_by_event_type",
                        vec![metrics::Label::new("event_type", event_type)],
                    ),
                )),
                1,
                "suricata_records_by_event_type{{event_type=\"{event_type}\"}} must be emitted"
            );
        }
    }

    /// A source inside `allowed_ips` reaches the handler as normal.
    #[tokio::test]
    async fn with_allowed_ips_allows_whitelisted_source() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let listener = SuricataListener::new(SuricataListenerConfig::default(), handler.clone())
            .with_allowed_ips(IpWhitelist::new(vec!["127.0.0.1".into()]).unwrap());
        let task = tokio::spawn(async move {
            listener.run_with_listener(tcp_listener).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"{\"event_type\":\"alert\",\"src_ip\":\"1.2.3.4\"}\n")
            .await
            .unwrap();
        drop(stream);

        sleep(Duration::from_millis(150)).await;
        task.abort();

        let records = handler.take_records();
        assert_eq!(
            records.len(),
            1,
            "allowed source must reach the handler; got {}",
            records.len()
        );
    }

    /// A connection that sends nothing must be closed once `idle_timeout`
    /// elapses, incrementing `suricata_tcp_idle_timeouts` and dispatching no
    /// record. Drives `handle_tcp_connection` directly with a short
    /// `Duration` — the production constant is 300s, far too long to sleep
    /// through in a test — so this exercises the exact same timeout-wrapped
    /// `read_until` production code runs, just parameterized with a small
    /// value.
    #[tokio::test]
    #[allow(clippy::mutable_key_type)] // false positive: CompositeKey AtomicBool is never hashed
    async fn idle_connection_is_closed_and_increments_metric() {
        use metrics::set_default_local_recorder;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::{CompositeKey, MetricKind};
        use tokio::io::AsyncReadExt;
        use tokio::time::timeout;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Client connects and sends nothing.
        let client = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut buf = [0u8; 1];
            // The server must close its half once the short idle timeout
            // elapses; read() then returns Ok(0).
            let result = timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
            assert!(
                matches!(result, Ok(Ok(0))),
                "expected the server to close the idle connection, got {result:?}"
            );
        });

        let (stream, src) = listener.accept().await.unwrap();
        SuricataListener::handle_tcp_connection(
            stream,
            src,
            CapturingHandler::new(),
            Duration::from_millis(100),
        )
        .await
        .unwrap();
        client.await.unwrap();

        let map = snapshotter.snapshot().into_hashmap();
        let count = map
            .get(&CompositeKey::new(
                MetricKind::Counter,
                metrics::Key::from_name("suricata_tcp_idle_timeouts"),
            ))
            .map(|(_, _, v)| match v {
                DebugValue::Counter(c) => *c,
                _ => 0,
            })
            .unwrap_or(0);
        assert_eq!(
            count, 1,
            "suricata_tcp_idle_timeouts must be 1; got {count}"
        );
    }

    /// The accept-loop wiring itself: `run_with_listener` (the same code
    /// path `start`/`start_with_shutdown` use) must pass the real
    /// `TCP_IDLE_TIMEOUT` constant down to `handle_tcp_connection`, not just
    /// some hand-passed test value. Unlike
    /// `idle_connection_is_closed_and_increments_metric` above (which calls
    /// `handle_tcp_connection` directly and only proves the function itself
    /// honours whatever `Duration` it's given), this test proves the
    /// constant actually reaches that call site through the production
    /// accept loop — `let idle_timeout = TCP_IDLE_TIMEOUT;` in
    /// `run_with_listener` could be swapped for the wrong constant, or
    /// `Duration::MAX`, and this test would catch it while the other would
    /// not. Relies on the `#[cfg(test)]` override of `TCP_IDLE_TIMEOUT`
    /// above (500ms) — see that constant's doc comment for why this is safe
    /// alongside the other `run_with_listener` tests in this file.
    #[tokio::test]
    #[allow(clippy::mutable_key_type)] // false positive: CompositeKey AtomicBool is never hashed
    async fn accept_loop_closes_idle_connection_and_increments_metric() {
        use metrics::set_default_local_recorder;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::{CompositeKey, MetricKind};
        use tokio::io::AsyncReadExt;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let listener = SuricataListener::new(SuricataListenerConfig::default(), handler.clone());
        let task = tokio::spawn(async move {
            listener.run_with_listener(tcp_listener).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        // Client connects and sends nothing.
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 1];
        let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
        assert!(
            matches!(result, Ok(Ok(0))),
            "expected the accept loop's real TCP_IDLE_TIMEOUT wiring to \
             close the idle connection, got {result:?}"
        );

        task.abort();

        assert!(
            handler.take_records().is_empty(),
            "idle connection must not dispatch a record"
        );

        let map = snapshotter.snapshot().into_hashmap();
        let count = map
            .get(&CompositeKey::new(
                MetricKind::Counter,
                metrics::Key::from_name("suricata_tcp_idle_timeouts"),
            ))
            .map(|(_, _, v)| match v {
                DebugValue::Counter(c) => *c,
                _ => 0,
            })
            .unwrap_or(0);
        assert_eq!(
            count, 1,
            "suricata_tcp_idle_timeouts must be 1 when the accept loop's \
             own wiring times out the connection; got {count}"
        );
    }
}
