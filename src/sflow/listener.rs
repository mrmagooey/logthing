//! sFlow v5 UDP listener — mirrors src/ipfix/listener.rs; sFlow is stateless
//! (no template cache), so decode_datagram takes only the buffer + exporter IP.

use crate::sflow::SflowRecord;
use crate::sflow::decoder::decode_datagram;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

/// Configuration for the sFlow UDP listener.
#[derive(Debug, Clone)]
pub struct SflowListenerConfig {
    pub udp_port: u16,
    pub bind_address: String,
}

impl Default for SflowListenerConfig {
    fn default() -> Self {
        Self {
            udp_port: 6343,
            bind_address: "0.0.0.0".to_string(),
        }
    }
}

/// Handler trait for decoded sFlow sample batches.
#[async_trait::async_trait]
pub trait SflowHandler: Send + Sync {
    async fn handle_samples(&self, samples: Vec<SflowRecord>, source: SocketAddr);
}

/// Default handler: logs a summary line per received batch.
pub struct DefaultSflowHandler;

#[async_trait::async_trait]
impl SflowHandler for DefaultSflowHandler {
    async fn handle_samples(&self, samples: Vec<SflowRecord>, source: SocketAddr) {
        info!("[{}] received {} sFlow sample(s)", source, samples.len());
    }
}

/// sFlow UDP listener.
pub struct SflowListener {
    config: SflowListenerConfig,
    handler: Arc<dyn SflowHandler>,
}

impl SflowListener {
    pub fn new(config: SflowListenerConfig, handler: Arc<dyn SflowHandler>) -> Self {
        Self { config, handler }
    }

    /// Bind the UDP socket and run the receive loop until error (no shutdown signal).
    pub async fn start(&self) -> anyhow::Result<()> {
        let addr: SocketAddr =
            format!("{}:{}", self.config.bind_address, self.config.udp_port).parse()?;
        let socket = UdpSocket::bind(&addr).await?;
        self.run_with_socket(socket).await
    }

    /// Bind the UDP socket and run the receive loop with graceful shutdown support.
    ///
    /// The listener exits cleanly when `shutdown_rx` receives `true` (or is closed).
    /// Used from `main.rs`; tests continue to use `run_with_socket()`.
    pub async fn start_with_shutdown(
        &self,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let addr: SocketAddr =
            format!("{}:{}", self.config.bind_address, self.config.udp_port).parse()?;
        let socket = UdpSocket::bind(&addr).await?;
        let bound_addr = socket.local_addr()?;
        info!("sFlow UDP listener started on {}", bound_addr);

        let mut buf = vec![0u8; 65535];

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, src)) => {
                            debug!("sFlow datagram from {}: {} bytes", src, len);
                            match decode_datagram(&buf[..len], src.ip()) {
                                Ok(samples) if samples.is_empty() => {
                                    debug!("sFlow datagram from {} produced no samples", src);
                                }
                                Ok(samples) => {
                                    self.handler.handle_samples(samples, src).await;
                                }
                                Err(e) => {
                                    metrics::counter!("sflow_decode_errors").increment(1);
                                    warn!("sFlow decode error from {}: {}", src, e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("sFlow UDP receive error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("sFlow listener: shutdown signal received");
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Run the receive loop on an already-bound socket.
    ///
    /// This is the shared implementation used by both `start()` (which binds
    /// the configured address) and tests (which bind their own socket so the
    /// OS-assigned port is known without any TOCTOU race).
    pub(crate) async fn run_with_socket(&self, socket: UdpSocket) -> anyhow::Result<()> {
        let bound_addr = socket.local_addr()?;
        info!("sFlow UDP listener started on {}", bound_addr);

        let mut buf = vec![0u8; 65535];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    debug!("sFlow datagram from {}: {} bytes", src, len);
                    match decode_datagram(&buf[..len], src.ip()) {
                        Ok(samples) if samples.is_empty() => {
                            debug!("sFlow datagram from {} produced no samples", src);
                        }
                        Ok(samples) => {
                            self.handler.handle_samples(samples, src).await;
                        }
                        Err(e) => {
                            metrics::counter!("sflow_decode_errors").increment(1);
                            warn!("sFlow decode error from {}: {}", src, e);
                        }
                    }
                }
                Err(e) => {
                    error!("sFlow UDP receive error: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sflow::decoder::tests::{FIXTURE_SFLOW_FLOW_RAW_HEADER, FIXTURE_SFLOW_COUNTER};
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::time::sleep;

    struct CapturingHandler {
        received: Mutex<Vec<Vec<SflowRecord>>>,
    }

    impl CapturingHandler {
        fn new() -> Arc<Self> {
            Arc::new(Self { received: Mutex::new(Vec::new()) })
        }
        fn batches(&self) -> Vec<Vec<SflowRecord>> {
            self.received.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl SflowHandler for CapturingHandler {
        async fn handle_samples(&self, samples: Vec<SflowRecord>, _source: SocketAddr) {
            self.received.lock().unwrap().push(samples);
        }
    }

    // ── e2e: listener receives datagram, calls handler ──
    #[tokio::test]
    async fn listener_receives_sflow_datagram_and_calls_handler() {
        let listener_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener_addr   = listener_socket.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();
        let listener = SflowListener::new(SflowListenerConfig::default(), handler_clone);

        let task = tokio::spawn(async move {
            listener.run_with_socket(listener_socket).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(FIXTURE_SFLOW_FLOW_RAW_HEADER, listener_addr).await.unwrap();
        sleep(Duration::from_millis(100)).await;
        task.abort();

        let batches = handler.batches();
        assert_eq!(batches.len(), 1, "expected one batch; got {}", batches.len());
        assert_eq!(batches[0].len(), 1, "expected one record in batch");

        use std::net::{IpAddr, Ipv4Addr};
        assert_eq!(
            batches[0][0].src_addr,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)))
        );
    }

    // ── shutdown signal: start_with_shutdown exits cleanly ──
    #[tokio::test]
    async fn start_with_shutdown_exits_on_signal() {
        use tokio::sync::watch;
        use tokio::time::timeout;

        let tmp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_port = tmp.local_addr().unwrap().port();
        drop(tmp);

        let config = SflowListenerConfig {
            udp_port,
            bind_address: "127.0.0.1".to_string(),
        };
        let handler: Arc<dyn SflowHandler> = Arc::new(DefaultSflowHandler);
        let listener = SflowListener::new(config, handler);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            listener.start_with_shutdown(shutdown_rx).await.ok();
        });
        sleep(Duration::from_millis(50)).await;
        shutdown_tx.send(true).unwrap();

        let result = timeout(Duration::from_secs(2), task).await;
        assert!(result.is_ok(), "start_with_shutdown did not return within 2s after signal");
    }

    // ── robustness: malformed datagram is ignored, next valid one processed ──
    #[tokio::test]
    async fn listener_ignores_malformed_datagrams_and_continues() {
        let listener_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener_addr   = listener_socket.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();
        let listener = SflowListener::new(SflowListenerConfig::default(), handler_clone);

        let task = tokio::spawn(async move {
            listener.run_with_socket(listener_socket).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(b"\xFF\xFF\xFF\xFF", listener_addr).await.unwrap();
        sleep(Duration::from_millis(30)).await;
        sender.send_to(FIXTURE_SFLOW_COUNTER, listener_addr).await.unwrap();
        sleep(Duration::from_millis(100)).await;
        task.abort();

        let batches = handler.batches();
        assert_eq!(batches.len(), 1, "valid datagram must still produce one batch after malformed one");
        assert_eq!(batches[0][0].sample_type, crate::sflow::SampleType::Counter);
    }
}
