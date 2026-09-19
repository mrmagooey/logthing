//! sFlow v5 UDP listener — mirrors src/ipfix/listener.rs; sFlow is stateless
//! (no template cache), so decode_datagram takes only the buffer + exporter IP.

use crate::middleware::IpWhitelist;
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
    /// Requested `SO_RCVBUF` size in bytes. `None` leaves the OS default
    /// alone. See `crate::net::bind_udp_with_recv_buffer`.
    pub receive_buffer_bytes: Option<usize>,
    /// Number of `SO_REUSEPORT` sockets, each drained by its own task
    /// (default: 8). `1` uses a single plain socket and is byte-for-byte
    /// the original pre-fan-out behaviour. Above 1, the kernel fans datagrams across the group; the
    /// sFlow decoder is stateless (see `crate::sflow::decoder`'s module
    /// docs), so unlike IPFIX no cache needs to be shared across tasks.
    ///
    /// The kernel picks a socket by hashing each datagram's source/
    /// destination address-port 4-tuple, so a given source port always
    /// lands on the same socket. Throughput therefore scales with the
    /// number of *distinct senders* (or, for one sender, distinct source
    /// ports), not with this value: raising it for a deployment with a
    /// single sFlow agent sending from one fixed source port yields zero
    /// benefit, because every datagram still hashes to the same socket.
    /// `0` is treated the same as `1` (single-socket path), not as "disabled".
    pub recv_tasks: usize,
    /// Number of datagrams one `recvmmsg(2)` call may return per recv task
    /// (default: 1, off). See `SflowConfig::recv_batch_size` for the full
    /// explanation -- unlike `recv_tasks`, this helps a single high-rate
    /// sender.
    pub recv_batch_size: usize,
}

impl Default for SflowListenerConfig {
    fn default() -> Self {
        Self {
            udp_port: 6343,
            bind_address: "0.0.0.0".to_string(),
            receive_buffer_bytes: Some(4 * 1024 * 1024),
            recv_tasks: 8,
            recv_batch_size: 1,
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
    allowed_ips: IpWhitelist,
}

impl SflowListener {
    pub fn new(config: SflowListenerConfig, handler: Arc<dyn SflowHandler>) -> Self {
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
            crate::net::bind_udp_with_recv_buffer(&addr, self.config.receive_buffer_bytes, "sflow")
                .await?;
        self.run_with_socket(socket).await
    }

    /// Bind the UDP socket and run the receive loop with graceful shutdown support.
    ///
    /// The listener exits cleanly when `shutdown_rx` receives `true` (or is closed).
    /// Used from `main.rs`; tests continue to use `start()` or `run_with_socket()`.
    ///
    /// `recv_tasks <= 1` is this exact loop, unchanged — that
    /// is the property that makes the fan-out below safe to deploy. Above 1,
    /// N `SO_REUSEPORT` sockets are bound and each drained by its own task.
    /// The sFlow decoder is stateless, so unlike IPFIX no state needs to be
    /// shared across tasks — only the drop-stats tracker is shared, since
    /// all N sockets share one address:port and `/proc/net/udp` already
    /// sums their lines (see `sflow_recv_loop` and its call site below).
    pub async fn start_with_shutdown(
        &self,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let addr: SocketAddr =
            format!("{}:{}", self.config.bind_address, self.config.udp_port).parse()?;

        if self.config.recv_tasks <= 1 {
            let socket = crate::net::bind_udp_with_recv_buffer(
                &addr,
                self.config.receive_buffer_bytes,
                "sflow",
            )
            .await?;
            let bound_addr = socket.local_addr()?;
            info!("sFlow UDP listener started on {}", bound_addr);

            let mut socket_stats = crate::net::SocketDropStats::new(&socket, "sflow");
            let mut socket_stats_ticker =
                tokio::time::interval(crate::net::SOCKET_DROP_POLL_INTERVAL);

            if self.config.recv_batch_size <= 1 {
                let mut buf = vec![0u8; 65535];
                loop {
                    tokio::select! {
                        result = socket.recv_from(&mut buf) => {
                            match result {
                                Ok((len, src)) => {
                                    // ponytail: any new recv/accept arm in this module needs this same is_allowed check.
                                    if !self.allowed_ips.is_allowed(&src) {
                                        metrics::counter!("listener_source_rejected", "protocol" => "sflow").increment(1);
                                        debug!("Rejected sflow datagram from {} — not in allowed_ips", src);
                                        continue;
                                    }
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
                        _ = socket_stats_ticker.tick() => {
                            socket_stats.poll().await;
                        }
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                info!("sFlow listener: shutdown signal received");
                                break;
                            }
                        }
                    }
                }
                return Ok(());
            }

            // Batched-recv path: recv_batch_size > 1.
            let mut batch = crate::net::RecvMmsgBatch::new(self.config.recv_batch_size);
            loop {
                tokio::select! {
                    result = batch.recv(&socket) => {
                        match result {
                            Ok(n) => {
                                for i in 0..n {
                                    let Some(src) = batch.src(i) else {
                                        warn!("sflow: batch message with unparseable source address, skipping");
                                        continue;
                                    };
                                    // ponytail: any new recv/accept arm in this module needs this same is_allowed check.
                                    if !self.allowed_ips.is_allowed(&src) {
                                        metrics::counter!("listener_source_rejected", "protocol" => "sflow").increment(1);
                                        debug!("Rejected sflow datagram from {} — not in allowed_ips", src);
                                        continue;
                                    }
                                    let payload = batch.payload(i);
                                    debug!("sFlow datagram from {}: {} bytes", src, payload.len());
                                    match decode_datagram(payload, src.ip()) {
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
                            }
                            Err(e) => {
                                // ponytail: EINTR (and every other transient
                                // errno recvmmsg can return) is not special-
                                // cased -- it surfaces here as a generic
                                // error and gets retried on the next loop
                                // iteration via batch.recv()'s own readable()
                                // await. Exact parity with the existing
                                // single-recv_from error arm this batched arm
                                // sits beside (this file's `Err(e) => {
                                // error!("sFlow UDP receive error: {}", e); }`
                                // above) -- not a gap introduced by batching.
                                error!("sFlow UDP batched receive error: {}", e);
                            }
                        }
                    }
                    _ = socket_stats_ticker.tick() => {
                        socket_stats.poll().await;
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            info!("sFlow listener: shutdown signal received");
                            break;
                        }
                    }
                }
            }

            return Ok(());
        }

        // Fan-out path: recv_tasks > 1. Bind N SO_REUSEPORT sockets on the
        // same address:port and drain each from its own task.
        let mut sockets = Vec::with_capacity(self.config.recv_tasks);
        for _ in 0..self.config.recv_tasks {
            sockets.push(
                crate::net::bind_udp_reuseport_with_recv_buffer(
                    &addr,
                    self.config.receive_buffer_bytes,
                    "sflow",
                )
                .await?,
            );
        }
        let bound_addr = sockets[0].local_addr()?;
        info!(
            "sFlow UDP listener started on {} ({} recv tasks)",
            bound_addr,
            sockets.len()
        );

        // All N sockets share one address:port, so /proc/net/udp already
        // sums their lines (see `parse_proc_net_udp`) — one tracker polled
        // once per group; one per task would multiply-count the same total.
        let mut socket_stats = Some(crate::net::SocketDropStats::new(&sockets[0], "sflow"));

        let mut tasks = Vec::with_capacity(sockets.len());
        for (i, socket) in sockets.into_iter().enumerate() {
            let handler = self.handler.clone();
            let allowed_ips = self.allowed_ips.clone();
            let shutdown_rx = shutdown_rx.clone();
            // Only the first task takes the shared drop-stats tracker, so it
            // is polled exactly once per SO_REUSEPORT group.
            let stats = if i == 0 { socket_stats.take() } else { None };
            tasks.push(tokio::spawn(sflow_recv_loop(
                socket,
                handler,
                allowed_ips,
                shutdown_rx,
                stats,
                self.config.recv_batch_size,
            )));
        }

        for task in tasks {
            let _ = task.await;
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
        let mut socket_stats = crate::net::SocketDropStats::new(&socket, "sflow");
        let mut socket_stats_ticker = tokio::time::interval(crate::net::SOCKET_DROP_POLL_INTERVAL);

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, src)) => {
                            if !self.allowed_ips.is_allowed(&src) {
                                metrics::counter!("listener_source_rejected", "protocol" => "sflow")
                                    .increment(1);
                                debug!("Rejected sflow datagram from {} — not in allowed_ips", src);
                                continue;
                            }
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
                _ = socket_stats_ticker.tick() => {
                    socket_stats.poll().await;
                }
            }
        }
    }
}

/// The recv loop run by each task in the `recv_tasks > 1` fan-out. Same
/// body as the `recv_tasks <= 1` path in `start_with_shutdown`, parameterized
/// so it can be spawned once per `SO_REUSEPORT` socket. `socket_stats` is
/// `Some` for exactly one task per group (see the call site) so the shared
/// drop counter is polled once, not once per task.
async fn sflow_recv_loop(
    socket: UdpSocket,
    handler: Arc<dyn SflowHandler>,
    allowed_ips: IpWhitelist,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    mut socket_stats: Option<crate::net::SocketDropStats>,
    recv_batch_size: usize,
) {
    let mut socket_stats_ticker = tokio::time::interval(crate::net::SOCKET_DROP_POLL_INTERVAL);

    if recv_batch_size <= 1 {
        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, src)) => {
                            // ponytail: any new recv/accept arm in this module needs this same is_allowed check.
                            if !allowed_ips.is_allowed(&src) {
                                metrics::counter!("listener_source_rejected", "protocol" => "sflow").increment(1);
                                debug!("Rejected sflow datagram from {} — not in allowed_ips", src);
                                continue;
                            }
                            debug!("sFlow datagram from {}: {} bytes", src, len);
                            match decode_datagram(&buf[..len], src.ip()) {
                                Ok(samples) if samples.is_empty() => {
                                    debug!("sFlow datagram from {} produced no samples", src);
                                }
                                Ok(samples) => {
                                    handler.handle_samples(samples, src).await;
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
                _ = socket_stats_ticker.tick(), if socket_stats.is_some() => {
                    if let Some(stats) = socket_stats.as_mut() {
                        stats.poll().await;
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
        return;
    }

    let mut batch = crate::net::RecvMmsgBatch::new(recv_batch_size);
    loop {
        tokio::select! {
            result = batch.recv(&socket) => {
                match result {
                    Ok(n) => {
                        for i in 0..n {
                            let Some(src) = batch.src(i) else {
                                warn!("sflow: batch message with unparseable source address, skipping");
                                continue;
                            };
                            // ponytail: any new recv/accept arm in this module needs this same is_allowed check.
                            if !allowed_ips.is_allowed(&src) {
                                metrics::counter!("listener_source_rejected", "protocol" => "sflow").increment(1);
                                debug!("Rejected sflow datagram from {} — not in allowed_ips", src);
                                continue;
                            }
                            let payload = batch.payload(i);
                            debug!("sFlow datagram from {}: {} bytes", src, payload.len());
                            match decode_datagram(payload, src.ip()) {
                                Ok(samples) if samples.is_empty() => {
                                    debug!("sFlow datagram from {} produced no samples", src);
                                }
                                Ok(samples) => {
                                    handler.handle_samples(samples, src).await;
                                }
                                Err(e) => {
                                    metrics::counter!("sflow_decode_errors").increment(1);
                                    warn!("sFlow decode error from {}: {}", src, e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        // ponytail: EINTR is not special-cased here either --
                        // same parity note as the inline loop's batched arm
                        // in start_with_shutdown. Retried on the next loop
                        // iteration via batch.recv()'s own readable() await.
                        error!("sFlow UDP batched receive error: {}", e);
                    }
                }
            }
            _ = socket_stats_ticker.tick(), if socket_stats.is_some() => {
                if let Some(stats) = socket_stats.as_mut() {
                    stats.poll().await;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sflow::decoder::tests::{FIXTURE_SFLOW_COUNTER, FIXTURE_SFLOW_FLOW_RAW_HEADER};
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::time::sleep;

    struct CapturingHandler {
        received: Mutex<Vec<Vec<SflowRecord>>>,
    }

    impl CapturingHandler {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                received: Mutex::new(Vec::new()),
            })
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
        let listener_addr = listener_socket.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();
        let listener = SflowListener::new(SflowListenerConfig::default(), handler_clone);

        let task = tokio::spawn(async move {
            listener.run_with_socket(listener_socket).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(FIXTURE_SFLOW_FLOW_RAW_HEADER, listener_addr)
            .await
            .unwrap();
        sleep(Duration::from_millis(100)).await;
        task.abort();

        let batches = handler.batches();
        assert_eq!(
            batches.len(),
            1,
            "expected one batch; got {}",
            batches.len()
        );
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
            ..SflowListenerConfig::default()
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
        assert!(
            result.is_ok(),
            "start_with_shutdown did not return within 2s after signal"
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

        let config = SflowListenerConfig {
            udp_port,
            bind_address: "127.0.0.1".to_string(),
            receive_buffer_bytes: Some(1024 * 1024),
            ..SflowListenerConfig::default()
        };
        let handler = CapturingHandler::new();
        let listener = SflowListener::new(config, handler.clone());

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            listener.start_with_shutdown(shutdown_rx).await.ok();
        });
        sleep(Duration::from_millis(50)).await;

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(FIXTURE_SFLOW_FLOW_RAW_HEADER, ("127.0.0.1", udp_port))
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

    // ── robustness: malformed datagram is ignored, next valid one processed ──
    #[tokio::test]
    async fn listener_ignores_malformed_datagrams_and_continues() {
        let listener_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener_socket.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();
        let listener = SflowListener::new(SflowListenerConfig::default(), handler_clone);

        let task = tokio::spawn(async move {
            listener.run_with_socket(listener_socket).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(b"\xFF\xFF\xFF\xFF", listener_addr)
            .await
            .unwrap();
        sleep(Duration::from_millis(30)).await;
        sender
            .send_to(FIXTURE_SFLOW_COUNTER, listener_addr)
            .await
            .unwrap();
        sleep(Duration::from_millis(100)).await;
        task.abort();

        let batches = handler.batches();
        assert_eq!(
            batches.len(),
            1,
            "valid datagram must still produce one batch after malformed one"
        );
        assert_eq!(batches[0][0].sample_type, crate::sflow::SampleType::Counter);
    }

    // ── allowed_ips: blocked source never reaches the handler ──
    #[tokio::test]
    async fn with_allowed_ips_blocks_disallowed_source() {
        let listener_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener_socket.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();
        let listener = SflowListener::new(SflowListenerConfig::default(), handler_clone)
            .with_allowed_ips(IpWhitelist::new(vec!["10.99.99.0/24".into()]).unwrap());

        let task = tokio::spawn(async move {
            listener.run_with_socket(listener_socket).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(FIXTURE_SFLOW_FLOW_RAW_HEADER, listener_addr)
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

    // ── allowed_ips: whitelisted source reaches the handler as normal ──
    #[tokio::test]
    async fn with_allowed_ips_allows_whitelisted_source() {
        let listener_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener_socket.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();
        let listener = SflowListener::new(SflowListenerConfig::default(), handler_clone)
            .with_allowed_ips(IpWhitelist::new(vec!["127.0.0.1".into()]).unwrap());

        let task = tokio::spawn(async move {
            listener.run_with_socket(listener_socket).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(FIXTURE_SFLOW_FLOW_RAW_HEADER, listener_addr)
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

    /// A handler that counts total records across all received batches —
    /// used by the fan-out test where records may arrive interleaved across
    /// several tasks and only the total matters. Also records each decoded
    /// flow record's `src_addr` (`build_datagram` embeds its `n` argument
    /// into the low octets of that address for the flow sample; the counter
    /// sample has no `src_addr`): the record *count* alone cannot tell "N
    /// distinct records decoded" apart from "N duplicate decodes of
    /// whichever record landed in one fixed batch slot" — see
    /// `ipfix::listener::tests::CountingHandler`'s doc comment for the exact
    /// index-reuse bug this catches, which a count-only assertion does not.
    struct CountingHandler {
        count: std::sync::atomic::AtomicUsize,
        src_addrs: Mutex<Vec<std::net::IpAddr>>,
    }

    impl CountingHandler {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                count: std::sync::atomic::AtomicUsize::new(0),
                src_addrs: Mutex::new(Vec::new()),
            })
        }
        fn record_count(&self) -> usize {
            self.count.load(std::sync::atomic::Ordering::SeqCst)
        }
        /// Number of distinct `src_addr` values seen across all decoded
        /// flow records so far -- see the struct doc comment for why this
        /// catches what `record_count()` alone cannot.
        fn distinct_src_addr_count(&self) -> usize {
            self.src_addrs
                .lock()
                .unwrap()
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
        }
    }

    #[async_trait::async_trait]
    impl SflowHandler for CountingHandler {
        async fn handle_samples(&self, samples: Vec<SflowRecord>, _source: SocketAddr) {
            self.count
                .fetch_add(samples.len(), std::sync::atomic::Ordering::SeqCst);
            let mut src_addrs = self.src_addrs.lock().unwrap();
            for sample in &samples {
                if let Some(addr) = sample.src_addr {
                    src_addrs.push(addr);
                }
            }
        }
    }

    /// Every datagram this builder emits carries exactly one flow sample
    /// (sampled_ipv4) + one counter sample (generic_if_counters) — same
    /// byte layout as `tools/loadgen/src/sflow_udp.rs`'s `build_datagram`,
    /// confirmed there (`ten_datagrams_decode_to_twenty_records_with_no_drops`)
    /// to decode to exactly 2 records per datagram.
    const RECORDS_PER_DATAGRAM: usize = 2;

    /// Fixed IPv4 agent address embedded in every datagram's header — same
    /// as `tools/loadgen/src/sflow_udp.rs::AGENT_ADDR`.
    const AGENT_ADDR: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 200, 0, 1);

    /// Derive distinct source/destination addresses for datagram index `n` —
    /// same convention as `tools/loadgen/src/sflow_udp.rs::flow_addrs`.
    fn flow_addrs(n: u64) -> (std::net::Ipv4Addr, std::net::Ipv4Addr) {
        let hi = ((n >> 8) & 0xFF) as u8;
        let lo = (n & 0xFF) as u8;
        (
            std::net::Ipv4Addr::new(10, 0, hi, lo),
            std::net::Ipv4Addr::new(192, 168, hi, lo),
        )
    }

    /// Build one sFlow v5 datagram: header + one flow sample (sampled_ipv4)
    /// + one counter sample (generic_if_counters) — byte-for-byte the same
    /// layout as `tools/loadgen/src/sflow_udp.rs`'s `build_datagram`.
    fn build_datagram(seq: u32, n: u64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);

        // ── Datagram header (28 bytes) ──
        buf.extend_from_slice(&5u32.to_be_bytes()); // version = 5
        buf.extend_from_slice(&1u32.to_be_bytes()); // agent_addr_type = 1 (IPv4)
        buf.extend_from_slice(&AGENT_ADDR.octets());
        buf.extend_from_slice(&0u32.to_be_bytes()); // sub_agent_id = 0
        buf.extend_from_slice(&seq.to_be_bytes()); // sequence_number
        buf.extend_from_slice(&seq.to_be_bytes()); // uptime_ms (unused by decoder; reuse seq)
        buf.extend_from_slice(&2u32.to_be_bytes()); // num_samples = 2

        // ── flow_sample (data_format=1), one sampled_ipv4 (format 3) record ──
        let (src, dst) = flow_addrs(n);
        let src_port = 1024 + (n % 60_000) as u32;
        let dst_port = 443u32;
        let protocol = 6u32; // TCP
        let sampling_rate = 1000u32;
        let input_ifindex = 1 + (n % 4) as u32;
        let output_ifindex = 1 + ((n + 1) % 4) as u32;

        buf.extend_from_slice(&1u32.to_be_bytes()); // data_format = flow_sample
        buf.extend_from_slice(&72u32.to_be_bytes()); // sample_length
        buf.extend_from_slice(&seq.to_be_bytes()); // sequence_number
        buf.extend_from_slice(&1u32.to_be_bytes()); // source_id
        buf.extend_from_slice(&sampling_rate.to_be_bytes());
        buf.extend_from_slice(&sampling_rate.to_be_bytes()); // sample_pool
        buf.extend_from_slice(&0u32.to_be_bytes()); // drops
        buf.extend_from_slice(&input_ifindex.to_be_bytes());
        buf.extend_from_slice(&output_ifindex.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes()); // num_flow_records = 1
        buf.extend_from_slice(&3u32.to_be_bytes()); // flow_data_format = 3 (sampled_ipv4)
        buf.extend_from_slice(&32u32.to_be_bytes()); // flow_data_length = 32
        buf.extend_from_slice(&60u32.to_be_bytes()); // original packet length (arbitrary)
        buf.extend_from_slice(&protocol.to_be_bytes());
        buf.extend_from_slice(&src.octets());
        buf.extend_from_slice(&dst.octets());
        buf.extend_from_slice(&src_port.to_be_bytes());
        buf.extend_from_slice(&dst_port.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes()); // tcp_flags
        buf.extend_from_slice(&0u32.to_be_bytes()); // tos

        // ── counter_sample (data_format=2), one generic_if_counters record ──
        let if_index = 1 + (n % 4) as u32;
        let if_in_octets = 1_000_000u64 + n * 1_000;
        let if_out_octets = 500_000u64 + n * 500;
        let if_in_ucast_pkts = 1_000u32 + (n % 10_000) as u32;
        let if_out_ucast_pkts = 500u32 + (n % 5_000) as u32;

        buf.extend_from_slice(&2u32.to_be_bytes()); // data_format = counter_sample
        buf.extend_from_slice(&108u32.to_be_bytes()); // sample_length
        buf.extend_from_slice(&seq.to_be_bytes()); // sequence_number
        buf.extend_from_slice(&1u32.to_be_bytes()); // source_id
        buf.extend_from_slice(&1u32.to_be_bytes()); // num_counter_records = 1
        buf.extend_from_slice(&1u32.to_be_bytes()); // counter_data_format = 1
        buf.extend_from_slice(&88u32.to_be_bytes()); // counter_data_length = 88
        buf.extend_from_slice(&if_index.to_be_bytes());
        buf.extend_from_slice(&6u32.to_be_bytes()); // ifType = 6 (ethernetCsmacd)
        buf.extend_from_slice(&1_000_000_000u64.to_be_bytes()); // ifSpeed
        buf.extend_from_slice(&1u32.to_be_bytes()); // ifDirection = full-duplex
        buf.extend_from_slice(&3u32.to_be_bytes()); // ifStatus = admin+oper up
        buf.extend_from_slice(&if_in_octets.to_be_bytes());
        buf.extend_from_slice(&if_in_ucast_pkts.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes()); // ifInMulticastPkts
        buf.extend_from_slice(&0u32.to_be_bytes()); // ifInBroadcastPkts
        buf.extend_from_slice(&0u32.to_be_bytes()); // ifInDiscards
        buf.extend_from_slice(&0u32.to_be_bytes()); // ifInErrors
        buf.extend_from_slice(&0u32.to_be_bytes()); // ifInUnknownProtos
        buf.extend_from_slice(&if_out_octets.to_be_bytes());
        buf.extend_from_slice(&if_out_ucast_pkts.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes()); // ifOutMulticastPkts
        buf.extend_from_slice(&0u32.to_be_bytes()); // ifOutBroadcastPkts
        buf.extend_from_slice(&0u32.to_be_bytes()); // ifOutDiscards
        buf.extend_from_slice(&0u32.to_be_bytes()); // ifOutErrors
        buf.extend_from_slice(&0u32.to_be_bytes()); // ifPromiscuousMode

        buf
    }

    /// Starts a real `SflowListener` via `start_with_shutdown` (the
    /// production path) bound to an ephemeral port, with `recv_tasks`
    /// configured as given. Returns the listener's join handle, its bound
    /// address, the shutdown sender, and a handler that counts total
    /// records.
    async fn start_test_listener(
        recv_tasks: usize,
        recv_batch_size: usize,
    ) -> (
        tokio::task::JoinHandle<anyhow::Result<()>>,
        SocketAddr,
        tokio::sync::watch::Sender<bool>,
        Arc<CountingHandler>,
    ) {
        // Bind briefly to obtain an ephemeral port, then drop so the
        // listener (and, for recv_tasks > 1, its SO_REUSEPORT group) can
        // bind the same address — same pattern as the other tests here.
        let tmp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_port = tmp.local_addr().unwrap().port();
        drop(tmp);
        let bound: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();

        let config = SflowListenerConfig {
            udp_port,
            bind_address: "127.0.0.1".to_string(),
            recv_tasks,
            recv_batch_size,
            ..SflowListenerConfig::default()
        };
        let handler = CountingHandler::new();
        let listener = SflowListener::new(config, handler.clone());

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move { listener.start_with_shutdown(shutdown_rx).await });

        // Give every recv task time to bind and enter its recv loop.
        sleep(Duration::from_millis(50)).await;

        (task, bound, shutdown_tx, handler)
    }

    /// Guards that every socket in a `recv_tasks > 1` `SO_REUSEPORT` group is
    /// actually drained — not just that the group binds. A task that binds
    /// its socket but never reads from it (e.g. spawned and then leaked, or
    /// wired to the wrong recv loop) would silently drop its entire hashed
    /// share of traffic with the process otherwise looking healthy; this
    /// test's only way to catch that is by getting datagrams to land on
    /// every member of the group, which requires enough distinct source
    /// ports for the kernel's 4-tuple hash to spread across all of them.
    ///
    /// sFlow's decoder is stateless, so the only risk here is a lost or
    /// misrouted datagram, not a decode failure — unlike IPFIX, there is no
    /// cache-sharing property to prove.
    ///
    /// Port count chosen empirically, not from the naive
    /// `1 - (3/4)^n` binomial model: with a 4-member group and one socket
    /// sabotaged to never drain (bound, receiving its hashed share, but its
    /// task never calls `recv_from`), 4 source ports (the original version
    /// of this test) caught the fault in only 2 of 6 measured runs —
    /// sequential ephemeral source ports do not hash evenly across the
    /// group, so the theoretical ~68% detection rate did not hold in
    /// measurement. 32 source ports (320 datagrams total) was tried next
    /// and caught the same sabotage in 10 out of 10 measured runs (see the
    /// task-5 fix-round report for the exact procedure) — that is the
    /// number this test now uses.
    #[tokio::test]
    async fn fanned_out_listener_receives_from_several_source_ports() {
        const SOURCE_PORTS: u32 = 32;
        const DATAGRAMS_PER_PORT: u64 = 10;

        let (listener, bound, shutdown_tx, handler) = start_test_listener(4, 1).await;

        for i in 0..SOURCE_PORTS {
            let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            for n in 0..DATAGRAMS_PER_PORT {
                sock.send_to(
                    &build_datagram(i * DATAGRAMS_PER_PORT as u32 + n as u32 + 1, n),
                    bound,
                )
                .await
                .unwrap();
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let _ = shutdown_tx.send(true);
        let _ = listener.await;

        let total_datagrams = SOURCE_PORTS as usize * DATAGRAMS_PER_PORT as usize;
        assert_eq!(
            handler.record_count(),
            total_datagrams * RECORDS_PER_DATAGRAM
        );
    }

    /// The end-to-end regression this task exists to prevent: a batch of many
    /// datagrams arriving before the listener's next recv must decode every one
    /// of them, not just the first. A buggy implementation that reads a batch
    /// but only processes message 0 (the classic "forgot the loop" bug) would
    /// pass a single-datagram smoke test and fail this one.
    #[tokio::test]
    async fn batched_recv_decodes_every_datagram_in_a_batch() {
        let (listener, bound, shutdown_tx, handler) = start_test_listener(1, 16).await;

        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let n = 10u32;
        for i in 0..n {
            sock.send_to(&build_datagram(i + 1, i as u64), bound)
                .await
                .unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let _ = shutdown_tx.send(true);
        let _ = listener.await;

        assert_eq!(handler.record_count(), n as usize * RECORDS_PER_DATAGRAM);
    }

    /// The `allowed_ips` and per-datagram-counter invariant, tested together:
    /// with allowed_ips restricted to exclude 127.0.0.1 entirely, every message
    /// in a multi-message batch must be independently rejected and independently
    /// counted -- `listener_source_rejected` must read N after N rejected
    /// datagrams, not 1. A batch-level check (verify the first message's source,
    /// apply the verdict to the whole batch, `continue` the outer loop) would
    /// still reject everything on this all-loopback test -- the counter is what
    /// distinguishes "checked once" from "checked N times", not the pass/fail
    /// outcome, which loopback can't vary by source IP.
    #[allow(clippy::mutable_key_type)] // false positive: CompositeKey AtomicBool is never hashed
    #[tokio::test]
    async fn batched_recv_checks_and_counts_allowed_ips_per_datagram() {
        use metrics::set_default_local_recorder;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::{CompositeKey, MetricKind};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let tmp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_port = tmp.local_addr().unwrap().port();
        drop(tmp);
        let bound: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();

        // Whitelist a network that does NOT include 127.0.0.1 -- every datagram
        // in this test must be rejected.
        let disallowing_whitelist = IpWhitelist::new(vec!["10.0.0.0/8".to_string()]).unwrap();
        let config = SflowListenerConfig {
            udp_port,
            bind_address: "127.0.0.1".to_string(),
            recv_tasks: 1,
            recv_batch_size: 16,
            ..SflowListenerConfig::default()
        };
        let handler = CountingHandler::new();
        let listener =
            SflowListener::new(config, handler.clone()).with_allowed_ips(disallowing_whitelist);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move { listener.start_with_shutdown(shutdown_rx).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let n = 10u32;
        for i in 0..n {
            sock.send_to(&build_datagram(i + 1, i as u64), bound)
                .await
                .unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let _ = shutdown_tx.send(true);
        let _ = task.await;

        assert_eq!(handler.record_count(), 0, "every datagram must be rejected");

        let map = snapshotter.snapshot().into_hashmap();
        let rejected = map
            .get(&CompositeKey::new(
                MetricKind::Counter,
                metrics::Key::from_parts(
                    "listener_source_rejected",
                    vec![metrics::Label::new("protocol", "sflow")],
                ),
            ))
            .map(|(_, _, v)| match v {
                DebugValue::Counter(c) => *c,
                _ => 0,
            })
            .unwrap_or(0);
        assert_eq!(
            rejected, n as u64,
            "listener_source_rejected must count every datagram in the batch, not one per batch"
        );
    }

    /// The gap Finding 1 of the plan review named directly: the two tests above
    /// both pin `recv_tasks = 1`, so they only ever exercise the batched arm
    /// inside `start_with_shutdown`'s inline loop, never `sflow_recv_loop` (the
    /// `recv_tasks > 1` fan-out function) -- the combined `recv_tasks > 1` AND
    /// `recv_batch_size > 1` shape had no automated coverage at all before this
    /// test. `recv_tasks = 4` forces every datagram through the SO_REUSEPORT
    /// group and `sflow_recv_loop`'s own batched arm; all sends come from one
    /// client socket, back-to-back with no `.await` between them, so they
    /// consistently hash to the same group member (SO_REUSEPORT hashes by the
    /// full 4-tuple, and one client socket keeps its source port fixed) and
    /// have a real chance to queue together before that task's next `recv()`
    /// drains them -- exercising an actual multi-message batch inside the
    /// fan-out path, not just a fan-out path that happens to only ever see one
    /// message per call.
    #[tokio::test]
    async fn fanout_batched_recv_decodes_every_datagram_across_batches() {
        let (listener, bound, shutdown_tx, handler) = start_test_listener(4, 16).await;

        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let n = 10u64;
        for i in 0..n {
            // No sleep between sends -- give the kernel a chance to queue
            // several before sflow_recv_loop's next batch.recv() call drains
            // the socket, so this test actually exercises n > 1 in the
            // `for i in 0..n` loop of the fan-out batched arm, not n == 1
            // every time.
            sock.send_to(&build_datagram(i as u32 + 1, i), bound)
                .await
                .unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let _ = shutdown_tx.send(true);
        let _ = listener.await;

        assert_eq!(
            handler.record_count(),
            n as usize * RECORDS_PER_DATAGRAM,
            "every record sent through the recv_tasks=4 + recv_batch_size=16 combined path must decode"
        );
        // record_count() alone cannot tell "10 distinct datagrams decoded"
        // apart from "10 duplicate decodes of whichever datagram landed in
        // one fixed batch slot" -- an index-reuse bug inside the
        // `for i in 0..n` loop (using a fixed index instead of `i`) still
        // runs the loop to completion and still produces
        // RECORDS_PER_DATAGRAM records per iteration, so the count alone
        // stays at n * RECORDS_PER_DATAGRAM. Each of the 10 sends embeds a
        // distinct low IP octet via `build_datagram`'s `n` argument, so
        // distinct sends must decode to distinct flow-sample `src_addr`s.
        assert_eq!(
            handler.distinct_src_addr_count(),
            n as usize,
            "each of the 10 distinct datagrams must decode with its own flow-sample address, not one datagram's content duplicated across a batch"
        );
    }

    /// The `allowed_ips`/counter invariant from
    /// `batched_recv_checks_and_counts_allowed_ips_per_datagram` above, re-run
    /// through `sflow_recv_loop`'s batched arm (`recv_tasks = 4`) instead of the
    /// inline loop's. Like that test, every send here comes from one source
    /// address (loopback can't vary by source IP within one process any more in
    /// the fan-out path than it could in the inline one), so this cannot
    /// distinguish "checked using the right per-message address" from "checked
    /// using a fixed wrong address" on its own -- what it adds on top of the
    /// non-fan-out version is coverage of the `self.x` → loop-local-param
    /// translation: a build that left a stray `self.` in `sflow_recv_loop`
    /// fails to compile (there is no `self` in a free function), and a build
    /// that substituted the wrong loop-local is caught here because this test
    /// constructs the disallowing whitelist and threads it through
    /// `with_allowed_ips` exactly as the non-fan-out version does, on the
    /// `recv_tasks = 4` path.
    #[allow(clippy::mutable_key_type)] // false positive: CompositeKey AtomicBool is never hashed
    #[tokio::test]
    async fn fanout_batched_recv_checks_and_counts_allowed_ips_per_datagram() {
        use metrics::set_default_local_recorder;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::{CompositeKey, MetricKind};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let tmp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_port = tmp.local_addr().unwrap().port();
        drop(tmp);
        let bound: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();

        let disallowing_whitelist = IpWhitelist::new(vec!["10.0.0.0/8".to_string()]).unwrap();
        let config = SflowListenerConfig {
            udp_port,
            bind_address: "127.0.0.1".to_string(),
            recv_tasks: 4,
            recv_batch_size: 16,
            ..SflowListenerConfig::default()
        };
        let handler = CountingHandler::new();
        let listener =
            SflowListener::new(config, handler.clone()).with_allowed_ips(disallowing_whitelist);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move { listener.start_with_shutdown(shutdown_rx).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let n = 10u32;
        for i in 0..n {
            sock.send_to(&build_datagram(i + 1, i as u64), bound)
                .await
                .unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let _ = shutdown_tx.send(true);
        let _ = task.await;

        assert_eq!(handler.record_count(), 0, "every datagram must be rejected");

        let map = snapshotter.snapshot().into_hashmap();
        let rejected = map
            .get(&CompositeKey::new(
                MetricKind::Counter,
                metrics::Key::from_parts(
                    "listener_source_rejected",
                    vec![metrics::Label::new("protocol", "sflow")],
                ),
            ))
            .map(|(_, _, v)| match v {
                DebugValue::Counter(c) => *c,
                _ => 0,
            })
            .unwrap_or(0);
        assert_eq!(
            rejected, n as u64,
            "listener_source_rejected must count every datagram through the recv_tasks=4 + recv_batch_size=16 combined path, not one per batch"
        );
    }
}
