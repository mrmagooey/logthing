//! IPFIX / NetFlow UDP listener.

use crate::ipfix::FlowRecord;
use crate::ipfix::decoder::{IpfixDecoder, decode_datagram};
use crate::middleware::IpWhitelist;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

/// Configuration for the IPFIX UDP listener.
#[derive(Debug, Clone)]
pub struct IpfixListenerConfig {
    pub udp_port: u16,
    pub bind_address: String,
    /// Requested `SO_RCVBUF` size in bytes. `None` leaves the OS default
    /// alone. See `crate::net::bind_udp_with_recv_buffer`.
    pub receive_buffer_bytes: Option<usize>,
}

impl Default for IpfixListenerConfig {
    fn default() -> Self {
        Self {
            udp_port: 4739,
            bind_address: "0.0.0.0".to_string(),
            receive_buffer_bytes: Some(4 * 1024 * 1024),
        }
    }
}

/// Handler trait for decoded IPFIX flow batches.
#[async_trait::async_trait]
pub trait IpfixHandler: Send + Sync {
    async fn handle_flows(&self, flows: Vec<FlowRecord>, source: SocketAddr);
}

/// Default handler: logs a summary line and increments metrics counters.
pub struct DefaultIpfixHandler;

#[async_trait::async_trait]
impl IpfixHandler for DefaultIpfixHandler {
    async fn handle_flows(&self, flows: Vec<FlowRecord>, source: SocketAddr) {
        // NOTE: ipfix_flows_decoded is already incremented per record inside the
        // decoder (parse_ipfix_data_set / decode_netflow_v5). Do NOT increment it
        // here — the handler sees flows AFTER decoding, so adding it here would
        // double-count every flow.
        info!(
            "[{}] received {} flow(s) (versions: {:?})",
            source,
            flows.len(),
            flows.iter().map(|r| r.protocol_version).collect::<Vec<_>>(),
        );
    }
}

/// IPFIX UDP listener.
pub struct IpfixListener {
    config: IpfixListenerConfig,
    handler: Arc<dyn IpfixHandler>,
    allowed_ips: IpWhitelist,
}

impl IpfixListener {
    pub fn new(config: IpfixListenerConfig, handler: Arc<dyn IpfixHandler>) -> Self {
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

    /// Bind the UDP socket and run the receive loop until error (no shutdown signal).
    pub async fn start(&self) -> anyhow::Result<()> {
        let addr: SocketAddr =
            format!("{}:{}", self.config.bind_address, self.config.udp_port).parse()?;
        let socket =
            crate::net::bind_udp_with_recv_buffer(&addr, self.config.receive_buffer_bytes, "ipfix")
                .await?;
        self.run_with_socket(socket).await
    }

    /// Bind the UDP socket and run the receive loop with graceful shutdown support.
    ///
    /// The listener exits cleanly when `shutdown_rx` receives `true` (or is closed).
    /// Used from `main.rs`; tests continue to use `start()` or `run_with_socket()`.
    pub async fn start_with_shutdown(
        &self,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let addr: SocketAddr =
            format!("{}:{}", self.config.bind_address, self.config.udp_port).parse()?;
        let socket =
            crate::net::bind_udp_with_recv_buffer(&addr, self.config.receive_buffer_bytes, "ipfix")
                .await?;
        let bound_addr = socket.local_addr()?;
        info!("IPFIX UDP listener started on {}", bound_addr);

        let mut buf = vec![0u8; 65535];
        let mut decoder = IpfixDecoder::new();
        let mut socket_stats = crate::net::SocketDropStats::new(&socket, "ipfix");
        let mut socket_stats_ticker = tokio::time::interval(crate::net::SOCKET_DROP_POLL_INTERVAL);

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, src)) => {
                            // ponytail: any new recv/accept arm in this module needs this same is_allowed check.
                            if !self.allowed_ips.is_allowed(&src) {
                                metrics::counter!("listener_source_rejected", "protocol" => "ipfix").increment(1);
                                debug!("Rejected ipfix datagram from {} — not in allowed_ips", src);
                                continue;
                            }
                            debug!("IPFIX datagram from {}: {} bytes", src, len);
                            match decode_datagram(&mut decoder, &buf[..len], src.ip()) {
                                Ok(flows) if flows.is_empty() => {
                                    debug!(
                                        "IPFIX datagram from {} produced no flows (template-only or empty)",
                                        src
                                    );
                                }
                                Ok(flows) => {
                                    self.handler.handle_flows(flows, src).await;
                                }
                                Err(e) => {
                                    metrics::counter!("ipfix_decode_errors").increment(1);
                                    warn!("IPFIX decode error from {}: {}", src, e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("IPFIX UDP receive error: {}", e);
                        }
                    }
                }
                _ = socket_stats_ticker.tick() => {
                    socket_stats.poll().await;
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("IPFIX listener: shutdown signal received");
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
        info!("IPFIX UDP listener started on {}", bound_addr);

        let mut buf = vec![0u8; 65535];
        let mut decoder = IpfixDecoder::new();
        let mut socket_stats = crate::net::SocketDropStats::new(&socket, "ipfix");
        let mut socket_stats_ticker = tokio::time::interval(crate::net::SOCKET_DROP_POLL_INTERVAL);

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, src)) => {
                            if !self.allowed_ips.is_allowed(&src) {
                                metrics::counter!("listener_source_rejected", "protocol" => "ipfix")
                                    .increment(1);
                                debug!("Rejected ipfix datagram from {} — not in allowed_ips", src);
                                continue;
                            }
                            debug!("IPFIX datagram from {}: {} bytes", src, len);
                            match decode_datagram(&mut decoder, &buf[..len], src.ip()) {
                                Ok(flows) if flows.is_empty() => {
                                    debug!(
                                        "IPFIX datagram from {} produced no flows (template-only or empty)",
                                        src
                                    );
                                }
                                Ok(flows) => {
                                    self.handler.handle_flows(flows, src).await;
                                }
                                Err(e) => {
                                    metrics::counter!("ipfix_decode_errors").increment(1);
                                    warn!("IPFIX decode error from {}: {}", src, e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("IPFIX UDP receive error: {}", e);
                        }
                    }
                }
                _ = socket_stats_ticker.tick() => {
                    socket_stats.poll().await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipfix::decoder::{FIXTURE_IPFIX_TEMPLATE_THEN_DATA, FIXTURE_NFV5_ONE_RECORD};
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::time::sleep;

    /// A test handler that collects received flow batches.
    struct CapturingHandler {
        received: Mutex<Vec<Vec<FlowRecord>>>,
    }

    impl CapturingHandler {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                received: Mutex::new(Vec::new()),
            })
        }
        fn batches(&self) -> Vec<Vec<FlowRecord>> {
            self.received.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl IpfixHandler for CapturingHandler {
        async fn handle_flows(&self, flows: Vec<FlowRecord>, _source: SocketAddr) {
            self.received.lock().unwrap().push(flows);
        }
    }

    #[tokio::test]
    async fn listener_receives_ipfix_datagrams_and_calls_handler() {
        // Bind the listener socket here so we know the exact port without any
        // TOCTOU race (previously we'd bind, drop, then hope the listener could
        // re-bind the same port before something else claimed it).
        let listener_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener_socket.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();

        let listener = IpfixListener::new(IpfixListenerConfig::default(), handler_clone);

        let listener_task = tokio::spawn(async move {
            listener.run_with_socket(listener_socket).await.ok();
        });

        // Give the listener time to enter recv_from
        sleep(Duration::from_millis(20)).await;

        // Send the IPFIX template + data fixture
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(FIXTURE_IPFIX_TEMPLATE_THEN_DATA, listener_addr)
            .await
            .unwrap();

        // Allow time for decode + handler call
        sleep(Duration::from_millis(100)).await;

        listener_task.abort();

        let batches = handler.batches();
        assert_eq!(
            batches.len(),
            1,
            "expected one batch; got {}",
            batches.len()
        );
        assert_eq!(batches[0].len(), 1, "expected one flow in batch");

        use std::net::{IpAddr, Ipv4Addr};
        assert_eq!(
            batches[0][0].src_addr,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
    }

    /// Firing the shutdown signal makes `start_with_shutdown` return cleanly
    /// within a short timeout (the shutdown arm of the select! is exercised).
    #[tokio::test]
    async fn start_with_shutdown_exits_on_signal() {
        use tokio::sync::watch;
        use tokio::time::timeout;

        // Bind briefly to obtain an ephemeral port, then drop so the listener
        // can re-bind the same address.
        let tmp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_port = tmp.local_addr().unwrap().port();
        drop(tmp);

        let config = IpfixListenerConfig {
            udp_port,
            bind_address: "127.0.0.1".to_string(),
            ..IpfixListenerConfig::default()
        };
        let handler: Arc<dyn IpfixHandler> = Arc::new(DefaultIpfixHandler);
        let listener = IpfixListener::new(config, handler);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let task = tokio::spawn(async move {
            listener.start_with_shutdown(shutdown_rx).await.ok();
        });

        // Give the listener time to bind and enter the select! loop.
        sleep(Duration::from_millis(50)).await;

        // Send the shutdown signal.
        shutdown_tx.send(true).unwrap();

        // The task must complete within 2 s.
        let result = timeout(Duration::from_secs(2), task).await;
        assert!(
            result.is_ok(),
            "start_with_shutdown did not return after shutdown signal within 2 s"
        );
    }

    /// Integration-level check for the `receive_buffer_bytes` config plumbing:
    /// a listener started via the real `start_with_shutdown` production path
    /// with a non-default buffer size still binds and decodes datagrams
    /// normally. The socket-level assertion that the requested size actually
    /// changes `SO_RCVBUF` lives in `crate::net`'s unit tests, against the
    /// exact same `bind_udp_with_recv_buffer` call this listener makes.
    #[tokio::test]
    async fn start_with_shutdown_honors_configured_receive_buffer() {
        use tokio::sync::watch;

        let tmp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_port = tmp.local_addr().unwrap().port();
        drop(tmp);

        let config = IpfixListenerConfig {
            udp_port,
            bind_address: "127.0.0.1".to_string(),
            receive_buffer_bytes: Some(1024 * 1024),
        };
        let handler = CapturingHandler::new();
        let listener = IpfixListener::new(config, handler.clone());

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            listener.start_with_shutdown(shutdown_rx).await.ok();
        });
        sleep(Duration::from_millis(50)).await;

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(FIXTURE_NFV5_ONE_RECORD, ("127.0.0.1", udp_port))
            .await
            .unwrap();
        sleep(Duration::from_millis(100)).await;

        shutdown_tx.send(true).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;

        assert_eq!(
            handler.batches().len(),
            1,
            "listener with a configured receive buffer must still decode datagrams"
        );
    }

    #[tokio::test]
    async fn listener_ignores_malformed_datagrams_and_continues() {
        // Bind the listener socket here to eliminate the TOCTOU race.
        let listener_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener_socket.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();
        let listener = IpfixListener::new(IpfixListenerConfig::default(), handler_clone);

        let task = tokio::spawn(async move {
            listener.run_with_socket(listener_socket).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Send garbage
        sender
            .send_to(b"\xFF\xFF\xFF", listener_addr)
            .await
            .unwrap();
        sleep(Duration::from_millis(30)).await;

        // Then send valid v5 one-record fixture
        sender
            .send_to(FIXTURE_NFV5_ONE_RECORD, listener_addr)
            .await
            .unwrap();
        sleep(Duration::from_millis(100)).await;

        task.abort();

        let batches = handler.batches();
        // The malformed datagram should produce 0 batches; the valid one should produce 1.
        assert_eq!(
            batches.len(),
            1,
            "valid datagram must still be handled after malformed one"
        );
    }

    /// A source outside `allowed_ips` never reaches the handler.
    #[tokio::test]
    async fn with_allowed_ips_blocks_disallowed_source() {
        let listener_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener_socket.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();
        let listener = IpfixListener::new(IpfixListenerConfig::default(), handler_clone)
            .with_allowed_ips(IpWhitelist::new(vec!["10.99.99.0/24".into()]).unwrap());

        let task = tokio::spawn(async move {
            listener.run_with_socket(listener_socket).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(FIXTURE_NFV5_ONE_RECORD, listener_addr)
            .await
            .unwrap();
        sleep(Duration::from_millis(100)).await;

        task.abort();

        let batches = handler.batches();
        assert!(
            batches.is_empty(),
            "blocked source must not reach the handler; got {} batches",
            batches.len()
        );
    }

    /// A source inside `allowed_ips` reaches the handler as normal.
    #[tokio::test]
    async fn with_allowed_ips_allows_whitelisted_source() {
        let listener_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener_socket.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();
        let listener = IpfixListener::new(IpfixListenerConfig::default(), handler_clone)
            .with_allowed_ips(IpWhitelist::new(vec!["127.0.0.1".into()]).unwrap());

        let task = tokio::spawn(async move {
            listener.run_with_socket(listener_socket).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(FIXTURE_NFV5_ONE_RECORD, listener_addr)
            .await
            .unwrap();
        sleep(Duration::from_millis(100)).await;

        task.abort();

        let batches = handler.batches();
        assert_eq!(
            batches.len(),
            1,
            "allowed source must reach the handler; got {}",
            batches.len()
        );
    }
}
