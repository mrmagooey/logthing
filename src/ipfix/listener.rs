//! IPFIX / NetFlow UDP listener.

use crate::ipfix::FlowRecord;
use crate::ipfix::decoder::{IpfixDecoder, decode_datagram};
use crate::middleware::IpWhitelist;
use crate::stats::cardinality::CardinalityWatcher;
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
    /// Number of `SO_REUSEPORT` sockets, each drained by its own task
    /// (default: 8). `1` uses a single plain socket and is byte-for-byte
    /// the original pre-fan-out behaviour. Above 1, the kernel fans datagrams across the group; all
    /// tasks share one template cache, so any task can decode any exporter.
    ///
    /// The kernel picks a socket by hashing each datagram's source/
    /// destination address-port 4-tuple, so a given source port always
    /// lands on the same socket. Throughput therefore scales with the
    /// number of *distinct senders* (or, for one sender, distinct source
    /// ports), not with this value: raising it for a deployment with a
    /// single exporter sending from one fixed source port yields zero
    /// benefit, because every datagram still hashes to the same socket.
    /// `0` is treated the same as `1` (single-socket path), not as "disabled".
    pub recv_tasks: usize,
    /// Number of datagrams one `recvmmsg(2)` call may return per recv task
    /// (default: 32). See `IpfixConfig::recv_batch_size` for the full
    /// explanation -- unlike `recv_tasks`, this helps a single high-rate
    /// exporter.
    pub recv_batch_size: usize,
}

impl Default for IpfixListenerConfig {
    fn default() -> Self {
        Self {
            udp_port: 4739,
            bind_address: "0.0.0.0".to_string(),
            receive_buffer_bytes: Some(4 * 1024 * 1024),
            recv_tasks: 8,
            recv_batch_size: 32,
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

/// Observe every flow in a decoded batch against the configured ipfix
/// cardinality watches, then dispatch the whole batch to the handler. Every
/// dispatch site in this file — the `recv_tasks <= 1` inline arms,
/// `run_with_socket`, and both arms of `ipfix_recv_loop` (the `recv_tasks >
/// 1` fan-out this listener defaults to) — routes through this one
/// function, mirroring `zeek::listener`'s shared per-record dispatch point
/// but as its own free function, looped over the batch since IPFIX delivers
/// flows in batches rather than one at a time.
///
/// ponytail: the cost is per-watcher AND per-record-in-batch — `observe`
/// allocates a `String` for the field value before its set-membership check
/// (see its own `ponytail:` comment), so N watches means N such allocations
/// for every flow in every batch, even when all N already track the value.
/// A batch multiplies it, which makes this and sflow the heaviest of the six.
/// Fine at the one-or-two watches this is meant for. Ceiling: if someone
/// configures many watches on one source, hoist the value-extraction out of
/// the inner loop for watches sharing a `field`. Same disclosure as
/// `zeek::listener`'s dispatch point.
async fn observe_and_dispatch(
    cardinality: &[Arc<CardinalityWatcher>],
    flows: Vec<FlowRecord>,
    src: SocketAddr,
    handler: &Arc<dyn IpfixHandler>,
) {
    for flow in &flows {
        for watcher in cardinality {
            watcher.observe(flow);
        }
    }
    handler.handle_flows(flows, src).await;
}

/// IPFIX UDP listener.
pub struct IpfixListener {
    config: IpfixListenerConfig,
    handler: Arc<dyn IpfixHandler>,
    allowed_ips: IpWhitelist,
    cardinality: Vec<Arc<CardinalityWatcher>>,
}

impl IpfixListener {
    pub fn new(config: IpfixListenerConfig, handler: Arc<dyn IpfixHandler>) -> Self {
        Self {
            config,
            handler,
            allowed_ips: IpWhitelist::empty(),
            cardinality: Vec::new(),
        }
    }

    /// Restrict this listener to sources in `allowed_ips`. Defaults to
    /// [`IpWhitelist::empty()`] (allow all) via `new()`.
    pub fn with_allowed_ips(mut self, allowed_ips: IpWhitelist) -> Self {
        self.allowed_ips = allowed_ips;
        self
    }

    /// Attach the `[[metrics.cardinality_watch]]` watchers configured for
    /// `source = "ipfix"`. Defaults to empty via `new()` — `main.rs` builds
    /// the full list from config (see `stats::cardinality::compile_watches`)
    /// and partitions it by source once at startup, so this listener only
    /// ever sees its own ipfix watches.
    pub fn with_cardinality_watchers(mut self, cardinality: Vec<Arc<CardinalityWatcher>>) -> Self {
        self.cardinality = cardinality;
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
    ///
    /// `recv_tasks <= 1` is this exact loop, unchanged — that
    /// is the property that makes the fan-out below safe to deploy. Above 1,
    /// N `SO_REUSEPORT` sockets are bound and each drained by its own task,
    /// all sharing one `IpfixDecoder` handle (and so one template cache) and
    /// one `SocketDropStats` (see `ipfix_recv_loop` and its call site below).
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
                "ipfix",
            )
            .await?;
            let bound_addr = socket.local_addr()?;
            info!("IPFIX UDP listener started on {}", bound_addr);

            let mut decoder = IpfixDecoder::new();
            let mut socket_stats = crate::net::SocketDropStats::new(&socket, "ipfix");
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
                                            observe_and_dispatch(&self.cardinality, flows, src, &self.handler).await;
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
                                        warn!("ipfix: batch message with unparseable source address, skipping");
                                        continue;
                                    };
                                    // ponytail: any new recv/accept arm in this module needs this same is_allowed check.
                                    if !self.allowed_ips.is_allowed(&src) {
                                        metrics::counter!("listener_source_rejected", "protocol" => "ipfix").increment(1);
                                        debug!("Rejected ipfix datagram from {} — not in allowed_ips", src);
                                        continue;
                                    }
                                    let payload = batch.payload(i);
                                    debug!("IPFIX datagram from {}: {} bytes", src, payload.len());
                                    match decode_datagram(&mut decoder, payload, src.ip()) {
                                        Ok(flows) if flows.is_empty() => {
                                            debug!("IPFIX datagram from {} produced no flows (template-only or empty)", src);
                                        }
                                        Ok(flows) => {
                                            observe_and_dispatch(&self.cardinality, flows, src, &self.handler).await;
                                        }
                                        Err(e) => {
                                            metrics::counter!("ipfix_decode_errors").increment(1);
                                            warn!("IPFIX decode error from {}: {}", src, e);
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
                                // error!("IPFIX UDP receive error: {}", e); }`
                                // above) -- not a gap introduced by batching.
                                error!("IPFIX UDP batched receive error: {}", e);
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
                    "ipfix",
                )
                .await?,
            );
        }
        let bound_addr = sockets[0].local_addr()?;
        info!(
            "IPFIX UDP listener started on {} ({} recv tasks)",
            bound_addr,
            sockets.len()
        );

        // All N sockets share one address:port, so /proc/net/udp already
        // sums their lines (see `parse_proc_net_udp`) — one tracker polled
        // once per group; one per task would multiply-count the same total.
        let mut socket_stats = Some(crate::net::SocketDropStats::new(&sockets[0], "ipfix"));

        let decoder = IpfixDecoder::new();
        let mut tasks = Vec::with_capacity(sockets.len());
        for (i, socket) in sockets.into_iter().enumerate() {
            // One handle per task, all sharing one template cache (see
            // IpfixDecoder's docs) — so an exporter's data decodes on
            // whichever task receives it, whatever the kernel's steering
            // does.
            let decoder = decoder.clone();
            let handler = self.handler.clone();
            let allowed_ips = self.allowed_ips.clone();
            let shutdown_rx = shutdown_rx.clone();
            let cardinality = self.cardinality.clone();
            // Only the first task takes the shared drop-stats tracker, so it
            // is polled exactly once per SO_REUSEPORT group.
            let stats = if i == 0 { socket_stats.take() } else { None };
            tasks.push(tokio::spawn(ipfix_recv_loop(
                socket,
                decoder,
                handler,
                allowed_ips,
                shutdown_rx,
                stats,
                self.config.recv_batch_size,
                cardinality,
            )));
        }

        for task in tasks {
            if let Err(e) = task.await {
                // A receive task that panics stops draining its socket for the
                // lifetime of the process. Discarding this JoinError made that
                // failure completely silent: the parent handle stays alive, so
                // main.rs's `supervise_listener_handles` never fires either.
                metrics::counter!("ipfix_recv_task_failed").increment(1);
                error!("ipfix: a receive task terminated abnormally: {e}");
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
                                    observe_and_dispatch(&self.cardinality, flows, src, &self.handler).await;
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

/// The recv loop run by each task in the `recv_tasks > 1` fan-out. Same
/// body as the `recv_tasks <= 1` path in `start_with_shutdown`, parameterized
/// so it can be spawned once per `SO_REUSEPORT` socket. `socket_stats` is
/// `Some` for exactly one task per group (see the call site) so the shared
/// drop counter is polled once, not once per task.
// ponytail: 8 params over clippy's default 7-arg threshold — a struct here
// would be a one-use bag with no behaviour, purely to satisfy a lint;
// every field already has a load-bearing doc comment above (or at its own
// call site). Revisit if a ninth parameter ever wants to join it.
#[allow(clippy::too_many_arguments)]
async fn ipfix_recv_loop(
    socket: UdpSocket,
    mut decoder: IpfixDecoder,
    handler: Arc<dyn IpfixHandler>,
    allowed_ips: IpWhitelist,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    mut socket_stats: Option<crate::net::SocketDropStats>,
    recv_batch_size: usize,
    cardinality: Vec<Arc<CardinalityWatcher>>,
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
                                    observe_and_dispatch(&cardinality, flows, src, &handler).await;
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
                _ = socket_stats_ticker.tick(), if socket_stats.is_some() => {
                    if let Some(stats) = socket_stats.as_mut() {
                        stats.poll().await;
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("IPFIX listener: shutdown signal received");
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
                                warn!("ipfix: batch message with unparseable source address, skipping");
                                continue;
                            };
                            // ponytail: any new recv/accept arm in this module needs this same is_allowed check.
                            if !allowed_ips.is_allowed(&src) {
                                metrics::counter!("listener_source_rejected", "protocol" => "ipfix").increment(1);
                                debug!("Rejected ipfix datagram from {} — not in allowed_ips", src);
                                continue;
                            }
                            let payload = batch.payload(i);
                            debug!("IPFIX datagram from {}: {} bytes", src, payload.len());
                            match decode_datagram(&mut decoder, payload, src.ip()) {
                                Ok(flows) if flows.is_empty() => {
                                    debug!("IPFIX datagram from {} produced no flows (template-only or empty)", src);
                                }
                                Ok(flows) => {
                                    observe_and_dispatch(&cardinality, flows, src, &handler).await;
                                }
                                Err(e) => {
                                    metrics::counter!("ipfix_decode_errors").increment(1);
                                    warn!("IPFIX decode error from {}: {}", src, e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        // ponytail: EINTR is not special-cased here either --
                        // same parity note as the inline loop's batched arm
                        // in start_with_shutdown. Retried on the next loop
                        // iteration via batch.recv()'s own readable() await.
                        error!("IPFIX UDP batched receive error: {}", e);
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
                    info!("IPFIX listener: shutdown signal received");
                    break;
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
            ..IpfixListenerConfig::default()
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

    /// A handler that counts total flows across all received batches —
    /// used by the fan-out tests where flows may arrive interleaved across
    /// several tasks and only the total matters. Also records each decoded
    /// flow's `src_addr` (`data_datagram` embeds its `n` argument into the
    /// low octets of that address, so `n` distinct sends must decode to `n`
    /// distinct addresses): the flow *count* alone cannot tell "N distinct
    /// records decoded" apart from "N duplicate decodes of whichever record
    /// landed in one fixed batch slot" — a real gap found while running this
    /// task's Step 6 sabotage, where an index-reuse bug (`batch.src(0)`/
    /// `batch.payload(0)` instead of `batch.src(i)`/`batch.payload(i)`) left
    /// `flow_count()` at the expected total because the `for i in 0..n` loop
    /// still ran to completion and still produced one flow per iteration —
    /// just the same duplicated content every time.
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
        fn flow_count(&self) -> usize {
            self.count.load(std::sync::atomic::Ordering::SeqCst)
        }
        /// Number of distinct `src_addr` values seen across all decoded
        /// flows so far -- see the struct doc comment for why this catches
        /// what `flow_count()` alone cannot.
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
    impl IpfixHandler for CountingHandler {
        async fn handle_flows(&self, flows: Vec<FlowRecord>, _source: SocketAddr) {
            self.count
                .fetch_add(flows.len(), std::sync::atomic::Ordering::SeqCst);
            let mut src_addrs = self.src_addrs.lock().unwrap();
            for flow in &flows {
                if let Some(addr) = flow.src_addr {
                    src_addrs.push(addr);
                }
            }
        }
    }

    /// Build an IPFIX v10 datagram containing only the template set for
    /// template id 256 (IE 8 sourceIPv4Address + IE 12
    /// destinationIPv4Address, 4 bytes each) — same layout as
    /// `tools/loadgen/src/ipfix_udp.rs`'s `build_template_datagram`.
    fn template_datagram(seq: u32) -> Vec<u8> {
        const TEMPLATE_ID: u16 = 256;
        let export_time = 0u32;
        let mut buf = Vec::with_capacity(32);
        buf.extend_from_slice(&10u16.to_be_bytes()); // version
        buf.extend_from_slice(&32u16.to_be_bytes()); // total length
        buf.extend_from_slice(&export_time.to_be_bytes());
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes()); // observation domain id
        buf.extend_from_slice(&2u16.to_be_bytes()); // set id = 2 (template set)
        buf.extend_from_slice(&16u16.to_be_bytes()); // set length
        buf.extend_from_slice(&TEMPLATE_ID.to_be_bytes());
        buf.extend_from_slice(&2u16.to_be_bytes()); // field count
        buf.extend_from_slice(&8u16.to_be_bytes()); // ie 8: sourceIPv4Address
        buf.extend_from_slice(&4u16.to_be_bytes()); // length 4
        buf.extend_from_slice(&12u16.to_be_bytes()); // ie 12: destinationIPv4Address
        buf.extend_from_slice(&4u16.to_be_bytes()); // length 4
        buf
    }

    /// Build an IPFIX v10 datagram with one data record for template id 256,
    /// addresses derived from flow index `n` so records are distinguishable
    /// — same layout as `tools/loadgen/src/ipfix_udp.rs`'s
    /// `build_data_datagram`.
    fn data_datagram(seq: u32, n: u64) -> Vec<u8> {
        const TEMPLATE_ID: u16 = 256;
        let export_time = 0u32;
        let hi = ((n >> 8) & 0xFF) as u8;
        let lo = (n & 0xFF) as u8;
        let src = std::net::Ipv4Addr::new(10, 0, hi, lo);
        let dst = std::net::Ipv4Addr::new(192, 168, hi, lo);
        let mut buf = Vec::with_capacity(28);
        buf.extend_from_slice(&10u16.to_be_bytes()); // version
        buf.extend_from_slice(&28u16.to_be_bytes()); // total length
        buf.extend_from_slice(&export_time.to_be_bytes());
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes()); // observation domain id
        buf.extend_from_slice(&TEMPLATE_ID.to_be_bytes()); // set id = template id
        buf.extend_from_slice(&12u16.to_be_bytes()); // set length
        buf.extend_from_slice(&src.octets());
        buf.extend_from_slice(&dst.octets());
        buf
    }

    /// Starts a real `IpfixListener` via `start_with_shutdown` (the
    /// production path) bound to an ephemeral port, with `recv_tasks`
    /// configured as given. Returns the listener's join handle, its bound
    /// address, the shutdown sender, and a handler that counts total flows.
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

        let config = IpfixListenerConfig {
            udp_port,
            bind_address: "127.0.0.1".to_string(),
            recv_tasks,
            recv_batch_size,
            ..IpfixListenerConfig::default()
        };
        let handler = CountingHandler::new();
        let listener = IpfixListener::new(config, handler.clone());

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move { listener.start_with_shutdown(shutdown_rx).await });

        // Give every recv task time to bind and enter its recv loop.
        sleep(Duration::from_millis(50)).await;

        (task, bound, shutdown_tx, handler)
    }

    /// Sends the template from one source port and data from EIGHT distinct
    /// other source ports, against a 4-member `SO_REUSEPORT` group.
    ///
    /// This is a probabilistic regression check, not a structural guarantee:
    /// which socket a datagram lands on is decided by the kernel's hash of
    /// the packet's 4-tuple, which userspace cannot observe or control. A
    /// single data source port could, by chance, hash to the same socket as
    /// the template and the cross-cache path would go unexercised for that
    /// one send — that's why the old version of this test (one data source
    /// port, "decisive" in name) could pass even under a per-task-decoder
    /// design that never actually shares the cache: a 1-in-4 chance of a
    /// false pass. With eight independent source ports the chance every one
    /// of them collides onto the template's socket is roughly (1/4)^8 ≈
    /// 1.5e-5 — a false pass is not impossible, just negligible. If this
    /// starts flaking, that is why.
    #[allow(clippy::mutable_key_type)] // false positive: CompositeKey AtomicBool is never hashed
    #[tokio::test]
    async fn data_decodes_when_sent_from_eight_source_ports_other_than_the_templates() {
        use metrics::set_default_local_recorder;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::{CompositeKey, MetricKind};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        // Current-thread `#[tokio::test]` runtime: every task this test
        // spawns (the listener's own recv tasks included) runs on this same
        // OS thread, so the thread-local recorder sees them all.
        let _guard = set_default_local_recorder(&recorder);

        let (listener, bound, shutdown_tx, handler) = start_test_listener(4, 1).await;

        let template_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut data_socks = Vec::new();
        for _ in 0..8 {
            data_socks.push(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        }
        let template_port = template_sock.local_addr().unwrap().port();
        for sock in &data_socks {
            assert_ne!(
                sock.local_addr().unwrap().port(),
                template_port,
                "each data source port must differ from the template's, or this test proves nothing"
            );
        }

        template_sock
            .send_to(&template_datagram(1), bound)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        for n in 0..50u64 {
            data_socks[(n % 8) as usize]
                .send_to(&data_datagram(n as u32 + 2, n), bound)
                .await
                .unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let _ = shutdown_tx.send(true);
        let _ = listener.await;

        assert_eq!(
            handler.flow_count(),
            50,
            "every data record must decode even though its template arrived on another socket"
        );

        let map = snapshotter.snapshot().into_hashmap();
        let templates_missing = map
            .get(&CompositeKey::new(
                MetricKind::Counter,
                metrics::Key::from_name("ipfix_templates_missing"),
            ))
            .map(|(_, _, v)| match v {
                DebugValue::Counter(c) => *c,
                _ => 0,
            })
            .unwrap_or(0);
        assert_eq!(
            templates_missing, 0,
            "no data set should ever be dropped for a missing template"
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

    /// The end-to-end regression this task exists to prevent: a batch of many
    /// datagrams arriving before the listener's next recv must decode every one
    /// of them, not just the first. A buggy implementation that reads a batch
    /// but only processes message 0 (the classic "forgot the loop" bug) would
    /// pass a single-datagram smoke test and fail this one.
    #[tokio::test]
    async fn batched_recv_decodes_every_datagram_in_a_batch() {
        let (listener, bound, shutdown_tx, handler) = start_test_listener(1, 16).await;

        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.send_to(&template_datagram(1), bound).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        for n in 0..10u64 {
            sock.send_to(&data_datagram(n as u32 + 2, n), bound)
                .await
                .unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let _ = shutdown_tx.send(true);
        let _ = listener.await;

        assert_eq!(
            handler.flow_count(),
            10,
            "every data record in the batch must decode"
        );
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
        let config = IpfixListenerConfig {
            udp_port,
            bind_address: "127.0.0.1".to_string(),
            recv_tasks: 1,
            recv_batch_size: 16,
            ..IpfixListenerConfig::default()
        };
        let handler = CountingHandler::new();
        let listener =
            IpfixListener::new(config, handler.clone()).with_allowed_ips(disallowing_whitelist);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move { listener.start_with_shutdown(shutdown_rx).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let n = 10u32;
        for i in 0..n {
            sock.send_to(&template_datagram(i + 1), bound)
                .await
                .unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let _ = shutdown_tx.send(true);
        let _ = task.await;

        assert_eq!(handler.flow_count(), 0, "every datagram must be rejected");

        let map = snapshotter.snapshot().into_hashmap();
        let rejected = map
            .get(&CompositeKey::new(
                MetricKind::Counter,
                metrics::Key::from_parts(
                    "listener_source_rejected",
                    vec![metrics::Label::new("protocol", "ipfix")],
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
    /// inside `start_with_shutdown`'s inline loop, never `ipfix_recv_loop` (the
    /// `recv_tasks > 1` fan-out function) -- the combined `recv_tasks > 1` AND
    /// `recv_batch_size > 1` shape had no automated coverage at all before this
    /// test. `recv_tasks = 4` forces every datagram through the SO_REUSEPORT
    /// group and `ipfix_recv_loop`'s own batched arm (Step 5); all sends come
    /// from one client socket, back-to-back with no `.await` between them, so
    /// they consistently hash to the same group member (SO_REUSEPORT hashes by
    /// the full 4-tuple, and one client socket keeps its source port fixed) and
    /// have a real chance to queue together before that task's next `recv()`
    /// drains them -- exercising an actual multi-message batch inside the
    /// fan-out path, not just a fan-out path that happens to only ever see one
    /// message per call.
    #[tokio::test]
    async fn fanout_batched_recv_decodes_every_datagram_across_batches() {
        let (listener, bound, shutdown_tx, handler) = start_test_listener(4, 16).await;

        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.send_to(&template_datagram(1), bound).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        for n in 0..10u64 {
            // No sleep between sends -- give the kernel a chance to queue
            // several before ipfix_recv_loop's next batch.recv() call drains
            // the socket, so this test actually exercises n > 1 in the
            // `for i in 0..n` loop of the fan-out batched arm, not n == 1 every
            // time.
            sock.send_to(&data_datagram(n as u32 + 2, n), bound)
                .await
                .unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let _ = shutdown_tx.send(true);
        let _ = listener.await;

        assert_eq!(
            handler.flow_count(),
            10,
            "every data record sent through the recv_tasks=4 + recv_batch_size=16 combined path must decode"
        );
        // flow_count() alone cannot tell "10 distinct records decoded" apart
        // from "10 duplicate decodes of whichever record landed in one fixed
        // batch slot" -- an index-reuse bug inside the `for i in 0..n` loop
        // (using a fixed index instead of `i`) still runs the loop to
        // completion and still produces one flow per iteration, so the count
        // alone stays 10. Each of the 10 sends embeds a distinct low IP
        // octet via `data_datagram`'s `n` argument, so distinct sends must
        // decode to distinct `src_addr`s.
        assert_eq!(
            handler.distinct_src_addr_count(),
            10,
            "each of the 10 distinct data records must decode with its own address, not one record's content duplicated across a batch"
        );
    }

    /// The `allowed_ips`/counter invariant from
    /// `batched_recv_checks_and_counts_allowed_ips_per_datagram` above, re-run
    /// through `ipfix_recv_loop`'s batched arm (`recv_tasks = 4`) instead of the
    /// inline loop's. Like that test, every send here comes from one source
    /// address (loopback can't vary by source IP within one process any more in
    /// the fan-out path than it could in the inline one), so this cannot
    /// distinguish "checked using the right per-message address" from "checked
    /// using a fixed wrong address" on its own -- what it adds on top of the
    /// non-fan-out version is coverage of the `self.x` → loop-local-param
    /// translation in Step 5 itself: a build that left a stray `self.` in
    /// `ipfix_recv_loop` fails to compile (there is no `self` in a free
    /// function), and a build that substituted the wrong loop-local (e.g. an
    /// out-of-scope `IpfixListenerConfig::default()`'s allowed_ips instead of
    /// the `allowed_ips` parameter actually passed in) is caught here because
    /// this test constructs the disallowing whitelist and threads it through
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
        let config = IpfixListenerConfig {
            udp_port,
            bind_address: "127.0.0.1".to_string(),
            recv_tasks: 4,
            recv_batch_size: 16,
            ..IpfixListenerConfig::default()
        };
        let handler = CountingHandler::new();
        let listener =
            IpfixListener::new(config, handler.clone()).with_allowed_ips(disallowing_whitelist);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move { listener.start_with_shutdown(shutdown_rx).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let n = 10u32;
        for i in 0..n {
            sock.send_to(&template_datagram(i + 1), bound)
                .await
                .unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let _ = shutdown_tx.send(true);
        let _ = task.await;

        assert_eq!(handler.flow_count(), 0, "every datagram must be rejected");

        let map = snapshotter.snapshot().into_hashmap();
        let rejected = map
            .get(&CompositeKey::new(
                MetricKind::Counter,
                metrics::Key::from_parts(
                    "listener_source_rejected",
                    vec![metrics::Label::new("protocol", "ipfix")],
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

    /// A2 regression: the `SO_REUSEPORT` fan-out join loop in
    /// `start_with_shutdown` must not silently discard a receive task's
    /// `JoinError`. Drives a real panic through a deliberately-panicking
    /// handler (no production handler ever panics here -- this exists
    /// solely to exercise the fix, same as `tests/syslog_panic_resilience_e2e
    /// .rs`'s equivalent `a_panicking_receive_task_increments_the_failure_
    /// counter_and_is_logged` for syslog) and asserts both the
    /// `ipfix_recv_task_failed` counter and the accompanying error log fire.
    ///
    /// Uses the shared `crate::test_support` tracing capture rather than
    /// installing its own subscriber -- see that module's doc comment for why
    /// multiple independent `set_global_default` calls across listener test
    /// modules would race for the single process-wide slot.
    #[allow(clippy::mutable_key_type)] // false positive: CompositeKey AtomicBool is never hashed
    #[tokio::test]
    async fn a_panicking_receive_task_increments_the_failure_counter_and_is_logged() {
        use metrics::set_default_local_recorder;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::{CompositeKey, MetricKind};

        crate::test_support::install_and_clear();

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        // Current-thread `#[tokio::test]` runtime: every task this test
        // spawns (the listener's own recv tasks included) runs on this same
        // OS thread, so the thread-local recorder sees them all.
        let _guard = set_default_local_recorder(&recorder);

        struct PanickingHandler;
        #[async_trait::async_trait]
        impl IpfixHandler for PanickingHandler {
            async fn handle_flows(&self, _flows: Vec<FlowRecord>, _source: SocketAddr) {
                panic!("test-injected panic to exercise JoinError handling");
            }
        }

        let tmp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_port = tmp.local_addr().unwrap().port();
        drop(tmp);
        let bound: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();

        let config = IpfixListenerConfig {
            udp_port,
            bind_address: "127.0.0.1".to_string(),
            recv_tasks: 2,
            recv_batch_size: 1,
            ..IpfixListenerConfig::default()
        };
        let handler: Arc<dyn IpfixHandler> = Arc::new(PanickingHandler);
        let listener = IpfixListener::new(config, handler);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move { listener.start_with_shutdown(shutdown_rx).await });
        sleep(Duration::from_millis(50)).await;

        // Template then data from the SAME client socket, so both hash to the
        // same SO_REUSEPORT member (kernel hashes by 4-tuple) and the data
        // record actually decodes to a non-empty flow batch -- an empty batch
        // never reaches the handler at all (see `run_with_socket`), so a
        // template-only datagram wouldn't trigger the panic.
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.send_to(&template_datagram(1), bound).await.unwrap();
        sleep(Duration::from_millis(100)).await;
        sock.send_to(&data_datagram(2, 0), bound).await.unwrap();

        // Give the panicking task time to unwind and be caught by tokio.
        sleep(Duration::from_millis(200)).await;

        // The sequential `for task in tasks { task.await }` join loop can't
        // observe the panicked task's `JoinError` until every task *before*
        // it in the vec has resolved -- shut down the survivor(s) so the
        // loop drains through to it, regardless of which SO_REUSEPORT member
        // the datagrams happened to hash onto.
        let _ = shutdown_tx.send(true);
        let outer_result = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("start_with_shutdown did not return after shutdown")
            .expect("outer task panicked or was cancelled");
        assert!(
            outer_result.is_ok(),
            "start_with_shutdown itself returned an error: {outer_result:?}"
        );

        let map = snapshotter.snapshot().into_hashmap();
        let failed = map
            .get(&CompositeKey::new(
                MetricKind::Counter,
                metrics::Key::from_name("ipfix_recv_task_failed"),
            ))
            .map(|(_, _, v)| match v {
                DebugValue::Counter(c) => *c,
                _ => 0,
            })
            .unwrap_or(0);
        assert_eq!(
            failed, 1,
            "expected ipfix_recv_task_failed == 1 after a receive task panicked"
        );

        let events = crate::test_support::captured_events();
        assert!(
            events
                .iter()
                .any(|m| m.contains("a receive task terminated abnormally")),
            "expected an error log containing 'a receive task terminated abnormally', got: {events:?}"
        );
    }

    // -- Cardinality watching: recv_tasks <= 1 (inline) AND recv_tasks > 1 --
    // -- (SO_REUSEPORT fan-out, the default) must both observe flows --

    /// Same shape as `start_test_listener`, but attaches the given
    /// cardinality watchers and uses `DefaultIpfixHandler` — these tests
    /// only care about what the watcher observed, not what the handler did
    /// with the batch.
    async fn start_test_listener_with_cardinality(
        recv_tasks: usize,
        recv_batch_size: usize,
        cardinality: Vec<Arc<CardinalityWatcher>>,
    ) -> (
        tokio::task::JoinHandle<anyhow::Result<()>>,
        SocketAddr,
        tokio::sync::watch::Sender<bool>,
    ) {
        let tmp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_port = tmp.local_addr().unwrap().port();
        drop(tmp);
        let bound: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();

        let config = IpfixListenerConfig {
            udp_port,
            bind_address: "127.0.0.1".to_string(),
            recv_tasks,
            recv_batch_size,
            ..IpfixListenerConfig::default()
        };
        let listener = IpfixListener::new(config, Arc::new(DefaultIpfixHandler))
            .with_cardinality_watchers(cardinality);

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move { listener.start_with_shutdown(shutdown_rx).await });
        sleep(Duration::from_millis(50)).await;

        (task, bound, shutdown_tx)
    }

    /// `recv_tasks <= 1`: drives the inline UDP arm of `start_with_shutdown`
    /// directly. Round-1 defect context: wiring only this branch would still
    /// pass this test while leaving the default-config fan-out path (see the
    /// next test) completely unwired.
    #[tokio::test]
    #[allow(clippy::mutable_key_type)] // false positive: CompositeKey AtomicBool is never hashed
    async fn cardinality_watcher_reports_distinct_values_at_recv_tasks_one() {
        use crate::stats::cardinality::CompiledWatch;
        use metrics::set_default_local_recorder;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::{CompositeKey, MetricKind};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let watcher = Arc::new(CardinalityWatcher::new(
            CompiledWatch {
                source: "ipfix".to_string(),
                stream: "flows".to_string(),
                field: "src_addr".to_string(),
            },
            1000,
        ));

        let (listener, bound, shutdown_tx) =
            start_test_listener_with_cardinality(1, 1, vec![watcher.clone()]).await;

        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.send_to(&template_datagram(1), bound).await.unwrap();
        sleep(Duration::from_millis(100)).await;
        // 3 data records, 2 distinct src_addr (n=0 repeated).
        for (seq, n) in [(2u32, 0u64), (3, 1), (4, 0)] {
            sock.send_to(&data_datagram(seq, n), bound).await.unwrap();
        }
        sleep(Duration::from_millis(200)).await;

        watcher.tick();

        let map = snapshotter.snapshot().into_hashmap();
        let key = CompositeKey::new(
            MetricKind::Gauge,
            metrics::Key::from_parts(
                "field_distinct_values",
                vec![
                    metrics::Label::new("source", "ipfix"),
                    metrics::Label::new("stream", "flows"),
                    metrics::Label::new("field", "src_addr"),
                ],
            ),
        );
        let gauge = map
            .get(&key)
            .map(|(_, _, v)| match v {
                DebugValue::Gauge(g) => g.into_inner(),
                _ => 0.0,
            })
            .unwrap_or(0.0);
        assert_eq!(
            gauge, 2.0,
            "2 distinct src_addr values must be observed through the recv_tasks <= 1 inline \
             UDP arm"
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), listener).await;
    }

    /// `recv_tasks > 1` (4, forcing the `SO_REUSEPORT` fan-out —
    /// `ipfix_recv_loop`, spawned once per socket, sharing one
    /// `IpfixDecoder`): this is the branch that ships at the real default
    /// (8) and that the round-1 defect left unwired. Sends come from the
    /// same client socket so the kernel routes every datagram to the same
    /// group member, keeping the decode path deterministic without changing
    /// what's under test — the watcher is one `Arc` shared by every task
    /// regardless of which one observes a given flow.
    #[tokio::test]
    #[allow(clippy::mutable_key_type)] // false positive: CompositeKey AtomicBool is never hashed
    async fn cardinality_watcher_reports_distinct_values_at_recv_tasks_fan_out() {
        use crate::stats::cardinality::CompiledWatch;
        use metrics::set_default_local_recorder;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::{CompositeKey, MetricKind};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let watcher = Arc::new(CardinalityWatcher::new(
            CompiledWatch {
                source: "ipfix".to_string(),
                stream: "flows".to_string(),
                field: "src_addr".to_string(),
            },
            1000,
        ));

        let (listener, bound, shutdown_tx) =
            start_test_listener_with_cardinality(4, 1, vec![watcher.clone()]).await;

        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.send_to(&template_datagram(1), bound).await.unwrap();
        sleep(Duration::from_millis(100)).await;
        for (seq, n) in [(2u32, 0u64), (3, 1), (4, 0)] {
            sock.send_to(&data_datagram(seq, n), bound).await.unwrap();
        }
        sleep(Duration::from_millis(300)).await;

        watcher.tick();

        let map = snapshotter.snapshot().into_hashmap();
        let key = CompositeKey::new(
            MetricKind::Gauge,
            metrics::Key::from_parts(
                "field_distinct_values",
                vec![
                    metrics::Label::new("source", "ipfix"),
                    metrics::Label::new("stream", "flows"),
                    metrics::Label::new("field", "src_addr"),
                ],
            ),
        );
        let gauge = map
            .get(&key)
            .map(|(_, _, v)| match v {
                DebugValue::Gauge(g) => g.into_inner(),
                _ => 0.0,
            })
            .unwrap_or(0.0);
        assert_eq!(
            gauge, 2.0,
            "2 distinct src_addr values must be observed through the recv_tasks > 1 \
             SO_REUSEPORT fan-out path"
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), listener).await;
    }
}
