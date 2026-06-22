//! Zeek TCP NDJSON listener.

use crate::zeek::ZeekRecord;
use chrono::Utc;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

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

    /// Bind the TCP listener and run the accept loop.
    pub async fn start(&self) -> anyhow::Result<()> {
        let addr: SocketAddr =
            format!("{}:{}", self.config.bind_address, self.config.tcp_port).parse()?;
        let listener = TcpListener::bind(&addr).await?;
        self.run_with_listener(listener).await
    }

    /// Run the accept loop on an already-bound listener.
    /// Extracted for testability — tests bind their own listener to get a known port.
    pub(crate) async fn run_with_listener(&self, listener: TcpListener) -> anyhow::Result<()> {
        let bound = listener.local_addr()?;
        info!("Zeek TCP listener started on {}", bound);
        loop {
            match listener.accept().await {
                Ok((stream, src)) => {
                    let handler = self.handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_tcp_connection(stream, src, handler).await {
                            error!("Zeek TCP connection error from {}: {}", src, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Zeek TCP accept error: {}", e);
                }
            }
        }
    }

    /// Handle one TCP connection: BufReader + read_line loop, one NDJSON record per line.
    async fn handle_tcp_connection(
        stream: TcpStream,
        src: SocketAddr,
        handler: Arc<dyn ZeekHandler>,
    ) -> anyhow::Result<()> {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();

        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => {
                    debug!("Zeek TCP connection from {} closed", src);
                    break;
                }
                Ok(_) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    // Oversized-line guard.
                    if trimmed.len() > ZEEK_MAX_LINE_BYTES {
                        metrics::counter!("zeek_oversized_lines").increment(1);
                        warn!(
                            "Zeek: oversized line ({} bytes) from {} — skipping",
                            trimmed.len(),
                            src
                        );
                        continue;
                    }
                    // Parse JSON.
                    match serde_json::from_str::<serde_json::Value>(trimmed) {
                        Err(e) => {
                            metrics::counter!("zeek_parse_errors").increment(1);
                            warn!(
                                "Zeek: JSON parse error from {}: {} — line: {}",
                                src,
                                e,
                                &trimmed[..trimmed.len().min(120)],
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
                Err(e) => {
                    error!("Zeek TCP read error from {}: {}", src, e);
                    break;
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
}
