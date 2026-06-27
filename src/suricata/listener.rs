//! Suricata TCP EVE JSON listener.

use crate::suricata::SuricataRecord;
use chrono::Utc;
use std::net::SocketAddr;
use std::sync::Arc;
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

/// Default handler: logs a summary and increments metrics.
pub struct DefaultSuricataHandler;

#[async_trait::async_trait]
impl SuricataHandler for DefaultSuricataHandler {
    async fn handle_record(&self, record: SuricataRecord, source: SocketAddr) {
        metrics::counter!("suricata_records_received").increment(1);
        metrics::counter!("suricata_records_by_event_type",
            "event_type" => record.event_type.clone()
        )
        .increment(1);
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
}

impl SuricataListener {
    pub fn new(config: SuricataListenerConfig, handler: Arc<dyn SuricataHandler>) -> Self {
        Self { config, handler }
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
                            match semaphore.clone().try_acquire_owned() {
                                Ok(permit) => {
                                    let handler = self.handler.clone();
                                    tokio::spawn(async move {
                                        let _permit = permit; // held for connection lifetime
                                        if let Err(e) = Self::handle_tcp_connection(stream, src, handler).await {
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
                    match semaphore.clone().try_acquire_owned() {
                        Ok(permit) => {
                            let handler = self.handler.clone();
                            tokio::spawn(async move {
                                let _permit = permit; // held for connection lifetime
                                if let Err(e) =
                                    Self::handle_tcp_connection(stream, src, handler).await
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
    ) -> anyhow::Result<()> {
        let mut reader = BufReader::new(stream);
        let mut buf: Vec<u8> = Vec::new();

        loop {
            buf.clear();
            let mut limited = (&mut reader).take((SURICATA_MAX_LINE_BYTES as u64) + 1);
            let n = match limited.read_until(b'\n', &mut buf).await {
                Ok(n) => n,
                Err(e) => {
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
            // Parse JSON.
            match serde_json::from_str::<serde_json::Value>(line) {
                Err(e) => {
                    metrics::counter!("suricata_parse_errors").increment(1);
                    warn!(
                        "Suricata: JSON parse error from {}: {} — line: {}",
                        src,
                        e,
                        &line[..line.len().min(120)],
                    );
                }
                Ok(value) => {
                    // Extract event_type.
                    let event_type = match value.get("event_type").and_then(|v| v.as_str()) {
                        Some(p) => p.to_string(),
                        None => {
                            metrics::counter!("suricata_missing_event_type").increment(1);
                            "unknown".to_string()
                        }
                    };
                    let record = SuricataRecord {
                        event_type,
                        fields: value,
                        received_at: Utc::now(),
                    };
                    handler.handle_record(record, src).await;
                }
            }
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
            Arc::new(Self { records: Mutex::new(Vec::new()) })
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
        assert!(result.is_ok(), "start_with_shutdown did not return within 2s");
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
        assert_eq!(records.len(), 2, "expected 2 records, got {}", records.len());
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
        assert_eq!(records.len(), 1, "only the valid record should be dispatched");
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
        stream.write_all(b"{\"src_ip\":\"9.9.9.9\"}\n").await.unwrap();
        drop(stream);

        sleep(Duration::from_millis(150)).await;
        task.abort();

        let records = handler.take_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].event_type, "unknown");
    }

    #[tokio::test]
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
        assert!(result.is_ok(), "server did not close oversized connection within 2s");

        sleep(Duration::from_millis(50)).await;
        task.abort();

        assert!(handler.take_records().is_empty(), "oversized input must not produce a record");

        let snapshot = snapshotter.snapshot();
        let map = snapshot.into_hashmap();
        let key = CompositeKey::new(
            MetricKind::Counter,
            metrics::Key::from_name("suricata_oversized_lines"),
        );
        let count = map
            .get(&key)
            .map(|(_, _, v)| {
                if let metrics_util::debugging::DebugValue::Counter(c) = v { *c } else { 0 }
            })
            .unwrap_or(0);
        assert_eq!(count, 1, "suricata_oversized_lines counter must be 1; got {count}");
    }
}
