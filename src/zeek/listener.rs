//! Zeek TCP NDJSON listener.

use crate::zeek::ZeekRecord;
use chrono::Utc;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

/// Maximum number of concurrent TCP connections accepted by the Zeek listener.
/// Prevents resource exhaustion from connection floods.
pub const MAX_ZEEK_TCP_CONNECTIONS: usize = 1024;

/// Maximum accepted line length in bytes. Lines exceeding this are skipped
/// and counted via `zeek_oversized_lines`.
pub const ZEEK_MAX_LINE_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

/// Configuration for the Zeek TCP NDJSON listener.
#[derive(Debug, Clone)]
pub struct ZeekListenerConfig {
    pub tcp_port: u16,
    pub bind_address: String,
}

impl Default for ZeekListenerConfig {
    fn default() -> Self {
        Self {
            tcp_port: 47760,
            bind_address: "0.0.0.0".to_string(),
        }
    }
}

/// Handler trait for decoded Zeek records.
#[async_trait::async_trait]
pub trait ZeekHandler: Send + Sync {
    async fn handle_record(&self, record: ZeekRecord, source: SocketAddr);
}

/// Default handler: logs a summary and increments metrics.
pub struct DefaultZeekHandler;

#[async_trait::async_trait]
impl ZeekHandler for DefaultZeekHandler {
    async fn handle_record(&self, record: ZeekRecord, source: SocketAddr) {
        metrics::counter!("zeek_records_received").increment(1);
        metrics::counter!("zeek_records_by_path",
            "log_path" => record.log_path.clone()
        )
        .increment(1);
        info!(
            "[{}] zeek record: path={} fields={}",
            source,
            record.log_path,
            record
                .fields
                .to_string()
                .chars()
                .take(120)
                .collect::<String>(),
        );
    }
}

/// Zeek TCP NDJSON listener.
pub struct ZeekListener {
    config: ZeekListenerConfig,
    handler: Arc<dyn ZeekHandler>,
}

impl ZeekListener {
    pub fn new(config: ZeekListenerConfig, handler: Arc<dyn ZeekHandler>) -> Self {
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
        info!("Zeek TCP listener started on {}", bound);

        let semaphore = Arc::new(Semaphore::new(MAX_ZEEK_TCP_CONNECTIONS));

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
                                            error!("Zeek TCP connection error from {}: {}", src, e);
                                        }
                                    });
                                }
                                Err(_) => {
                                    metrics::counter!("zeek_tcp_connections_rejected").increment(1);
                                    warn!(
                                        "Zeek: TCP connection limit ({}) reached; rejecting {}",
                                        MAX_ZEEK_TCP_CONNECTIONS, src
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            error!("Zeek TCP accept error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Zeek listener: shutdown signal received");
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
        info!("Zeek TCP listener started on {}", bound);

        let semaphore = Arc::new(Semaphore::new(MAX_ZEEK_TCP_CONNECTIONS));

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
                                    error!("Zeek TCP connection error from {}: {}", src, e);
                                }
                            });
                        }
                        Err(_) => {
                            metrics::counter!("zeek_tcp_connections_rejected").increment(1);
                            warn!(
                                "Zeek: TCP connection limit ({}) reached; rejecting {}",
                                MAX_ZEEK_TCP_CONNECTIONS, src
                            );
                        }
                    }
                }
                Err(e) => {
                    error!("Zeek TCP accept error: {}", e);
                }
            }
        }
    }

    /// Handle one TCP connection: BufReader + bounded read_until loop, one NDJSON record per line.
    async fn handle_tcp_connection(
        stream: TcpStream,
        src: SocketAddr,
        handler: Arc<dyn ZeekHandler>,
    ) -> anyhow::Result<()> {
        let mut reader = BufReader::new(stream);
        let mut buf: Vec<u8> = Vec::new();

        loop {
            buf.clear();
            let mut limited = (&mut reader).take((ZEEK_MAX_LINE_BYTES as u64) + 1);
            let n = match limited.read_until(b'\n', &mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    error!("Zeek TCP read error from {}: {}", src, e);
                    break;
                }
            };
            if n == 0 {
                debug!("Zeek TCP connection from {} closed", src);
                break;
            }
            // If we read ZEEK_MAX_LINE_BYTES+1 bytes and the last byte is NOT a newline,
            // the line exceeded the cap — close the connection (resyncing is itself unbounded).
            if buf.len() > ZEEK_MAX_LINE_BYTES && buf.last() != Some(&b'\n') {
                metrics::counter!("zeek_oversized_lines").increment(1);
                warn!(
                    "Zeek: line from {} exceeded {} bytes; closing connection",
                    src, ZEEK_MAX_LINE_BYTES
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
                    metrics::counter!("zeek_parse_errors").increment(1);
                    warn!("Zeek: non-UTF-8 line from {}; skipping", src);
                    continue;
                }
            };
            // Parse JSON.
            match serde_json::from_str::<serde_json::Value>(line) {
                Err(e) => {
                    metrics::counter!("zeek_parse_errors").increment(1);
                    warn!(
                        "Zeek: JSON parse error from {}: {} — line: {}",
                        src,
                        e,
                        &line[..line.len().min(120)],
                    );
                }
                Ok(value) => {
                    // Extract _path.
                    let log_path = match value.get("_path").and_then(|v| v.as_str()) {
                        Some(p) => p.to_string(),
                        None => {
                            metrics::counter!("zeek_missing_path").increment(1);
                            "unknown".to_string()
                        }
                    };
                    let record = ZeekRecord {
                        log_path,
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
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    use tokio::time::sleep;

    /// Test handler that captures received records.
    struct CapturingHandler {
        records: Mutex<Vec<ZeekRecord>>,
    }

    impl CapturingHandler {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                records: Mutex::new(Vec::new()),
            })
        }
        fn take_records(&self) -> Vec<ZeekRecord> {
            self.records.lock().unwrap().drain(..).collect()
        }
    }

    #[async_trait::async_trait]
    impl ZeekHandler for CapturingHandler {
        async fn handle_record(&self, record: ZeekRecord, _source: SocketAddr) {
            self.records.lock().unwrap().push(record);
        }
    }

    // -- Unit: _path extraction --

    #[test]
    fn extract_log_path_from_json() {
        let value = serde_json::json!({"_path": "conn", "uid": "Cabc"});
        let path = value
            .get("_path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        assert_eq!(path, "conn");
    }

    #[test]
    fn missing_path_field_gives_unknown() {
        let value = serde_json::json!({"uid": "Cabc"});
        let path = value
            .get("_path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        assert_eq!(path, "unknown");
    }

    #[test]
    fn non_string_path_field_gives_unknown() {
        let value = serde_json::json!({"_path": 42, "uid": "Cabc"});
        let path = value
            .get("_path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        assert_eq!(path, "unknown");
    }

    // -- Integration: TCP listener receives records --

    #[tokio::test]
    async fn listener_dispatches_records_from_ndjson_stream() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();
        let listener = ZeekListener::new(ZeekListenerConfig::default(), handler_clone);

        let task = tokio::spawn(async move {
            listener.run_with_listener(tcp_listener).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let lines = concat!(
            r#"{"_path":"conn","uid":"C1","ts":1700000000.0}"#,
            "\n",
            r#"{"_path":"dns","uid":"C2","ts":1700000001.0}"#,
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
        assert_eq!(records[0].log_path, "conn");
        assert_eq!(records[1].log_path, "dns");
    }

    #[tokio::test]
    async fn listener_skips_malformed_json_and_continues() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();
        let listener = ZeekListener::new(ZeekListenerConfig::default(), handler_clone);

        let task = tokio::spawn(async move {
            listener.run_with_listener(tcp_listener).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let lines = concat!(
            "NOT JSON AT ALL\n",
            r#"{"_path":"ssl","uid":"C3","ts":1700000002.0}"#,
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
        assert_eq!(records[0].log_path, "ssl");
    }

    #[tokio::test]
    async fn listener_routes_missing_path_to_unknown() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();
        let listener = ZeekListener::new(ZeekListenerConfig::default(), handler_clone);

        let task = tokio::spawn(async move {
            listener.run_with_listener(tcp_listener).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"{\"uid\":\"C4\",\"ts\":1700000003.0}\n")
            .await
            .unwrap();
        drop(stream);

        sleep(Duration::from_millis(150)).await;
        task.abort();

        let records = handler.take_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].log_path, "unknown");
    }

    #[tokio::test]
    async fn listener_handles_multiple_concurrent_connections() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();
        let listener = ZeekListener::new(ZeekListenerConfig::default(), handler_clone);

        let task = tokio::spawn(async move {
            listener.run_with_listener(tcp_listener).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        // Connect three clients simultaneously.
        let mut s1 = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut s2 = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut s3 = tokio::net::TcpStream::connect(addr).await.unwrap();

        s1.write_all(b"{\"_path\":\"conn\",\"uid\":\"Ca\"}\n")
            .await
            .unwrap();
        s2.write_all(b"{\"_path\":\"http\",\"uid\":\"Cb\"}\n")
            .await
            .unwrap();
        s3.write_all(b"{\"_path\":\"files\",\"uid\":\"Cc\"}\n")
            .await
            .unwrap();
        drop(s1);
        drop(s2);
        drop(s3);

        sleep(Duration::from_millis(150)).await;
        task.abort();

        let records = handler.take_records();
        assert_eq!(records.len(), 3, "expected 3 records from 3 connections");
        let paths: std::collections::HashSet<_> =
            records.iter().map(|r| r.log_path.as_str()).collect();
        assert!(paths.contains("conn"));
        assert!(paths.contains("http"));
        assert!(paths.contains("files"));
    }

    /// Integration test: a line exceeding ZEEK_MAX_LINE_BYTES (with no newline) closes the
    /// connection and does NOT dispatch a record.
    ///
    /// To keep the test fast and deterministic without sending 16 MiB of data, we use
    /// `handle_tcp_connection` directly with an in-process TCP pair and send
    /// ZEEK_MAX_LINE_BYTES + 1 bytes of junk with no newline. The handler must close the
    /// connection (and not dispatch a record) well within the test timeout.
    ///
    /// Metrics: we install a thread-local DebuggingRecorder so we can assert that
    /// `zeek_oversized_lines` is incremented exactly once.
    #[tokio::test]
    async fn oversized_line_closes_connection_and_increments_metric() {
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::DebuggingRecorder;
        use tokio::time::timeout;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();
        let listener = ZeekListener::new(ZeekListenerConfig::default(), handler_clone);

        let task = tokio::spawn(async move {
            listener.run_with_listener(tcp_listener).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        // Send ZEEK_MAX_LINE_BYTES + 1 bytes of 'x' with NO newline — this exceeds the cap.
        let oversized = vec![b'x'; ZEEK_MAX_LINE_BYTES + 1];
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Write the oversized blob.  The server will read up to ZEEK_MAX_LINE_BYTES+1 bytes
        // via `take`, detect overrun, and close its side.  We don't wait for the write to
        // complete — the server closing its half is what we observe.
        let _ = stream.write_all(&oversized).await;

        // The server should close the connection promptly.  Wait up to 2 s.
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

        let records = handler.take_records();
        assert!(
            records.is_empty(),
            "oversized input must not produce a record; got {}",
            records.len()
        );

        // Assert the metric counter was incremented.
        let snapshot = snapshotter.snapshot();
        let map = snapshot.into_hashmap();
        let key = CompositeKey::new(
            MetricKind::Counter,
            metrics::Key::from_name("zeek_oversized_lines"),
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
            "zeek_oversized_lines counter must be 1; got {count}"
        );
    }

    /// After an oversized-line disconnection, a new connection still works correctly.
    #[tokio::test]
    async fn valid_connection_after_oversized_still_works() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();
        let listener = ZeekListener::new(ZeekListenerConfig::default(), handler_clone);

        let task = tokio::spawn(async move {
            listener.run_with_listener(tcp_listener).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        // First connection: oversized.
        {
            let oversized = vec![b'x'; ZEEK_MAX_LINE_BYTES + 1];
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let _ = stream.write_all(&oversized).await;
            let _ = tokio::time::timeout(Duration::from_secs(2), async {
                let mut sink = Vec::new();
                stream.read_to_end(&mut sink).await
            })
            .await;
        }

        // Second connection: valid record.
        {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(b"{\"_path\":\"conn\",\"uid\":\"OK\"}\n")
                .await
                .unwrap();
            drop(stream);
        }

        sleep(Duration::from_millis(150)).await;
        task.abort();

        let records = handler.take_records();
        assert_eq!(
            records.len(),
            1,
            "second connection should produce 1 record"
        );
        assert_eq!(records[0].log_path, "conn");
    }
}
