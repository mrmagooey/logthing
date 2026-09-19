//! Syslog listener for receiving syslog messages via UDP and TCP

use crate::forwarding::drop_log::{DropKind, DropSite};
use crate::forwarding::structured_syslog_s3::StructuredS3Handler;
use crate::middleware::IpWhitelist;
use crate::syslog::{SyslogMessage, dns::DnsLogEntry, payload};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

/// Maximum number of concurrent TCP connections accepted by the syslog listener.
/// Prevents resource exhaustion from connection floods.
pub const MAX_SYSLOG_TCP_CONNECTIONS: usize = 1024;

/// Maximum time a TCP connection may sit without delivering a complete line
/// before it is closed. Without this, a client that connects and sends
/// nothing holds a connection-semaphore permit for the process's lifetime,
/// so 1024 silent sockets exhaust the listener. This is also the default for
/// `SyslogListenerConfig::tcp_idle_timeout`; tests override that field with
/// a short value rather than this constant, since a `tests/` integration
/// crate does not see `#[cfg(test)]` from this crate. `main.rs` (a separate
/// binary crate) gets this value via `SyslogListenerConfig::default()`
/// (`..Default::default()` in its config literal), not by naming this
/// constant directly, so it stays `pub(crate)`.
pub(crate) const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

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
    /// Requested `SO_RCVBUF` size in bytes for the UDP socket. `None` leaves
    /// the OS default alone. Only affects the UDP arm — TCP syslog has no
    /// datagram-drop failure mode this addresses. See
    /// `crate::net::bind_udp_with_recv_buffer`.
    pub receive_buffer_bytes: Option<usize>,
    /// Number of `SO_REUSEPORT` sockets, each drained by its own task
    /// (default: 8). Applies to the UDP arm only — the TCP listener on
    /// `tcp_port` is unaffected. `1` uses a single plain socket and is
    /// byte-for-byte the original pre-fan-out behaviour. Above 1, the kernel fans datagrams
    /// across the group; syslog's parser is stateless (each datagram is
    /// parsed independently), so unlike IPFIX no cache needs to be shared
    /// across tasks.
    ///
    /// The kernel picks a socket by hashing each datagram's source/
    /// destination address-port 4-tuple, so a given source port always
    /// lands on the same socket. Throughput therefore scales with the
    /// number of *distinct senders* (or, for one sender, distinct source
    /// ports), not with this value: raising it for a deployment with a
    /// single syslog sender sending from one fixed source port yields zero
    /// benefit, because every datagram still hashes to the same socket.
    /// Syslog is the format most likely to genuinely benefit here, since a
    /// deployment ingesting from a fleet of hosts has many distinct
    /// senders. `0` is treated the same as `1` (single-socket path), not as
    /// "disabled".
    pub recv_tasks: usize,
    /// Number of datagrams one `recvmmsg(2)` call may return per recv task
    /// (default: 32). Applies to the UDP arm only -- the TCP listener
    /// on `tcp_port` has no batched-receive analogue and is unaffected. See
    /// `SyslogConfig::recv_batch_size` for the full explanation -- unlike
    /// `recv_tasks`, this helps a single high-rate sender.
    pub recv_batch_size: usize,
    /// Maximum time a TCP connection may sit without delivering a complete
    /// line before it is closed (default: [`TCP_IDLE_TIMEOUT`], 300s). Exists
    /// as a config field (rather than reading the constant directly) so
    /// tests can inject a short value and exercise the real timeout codepath
    /// through the public `start_with_shutdown` entry point.
    pub tcp_idle_timeout: Duration,
}

impl Default for SyslogListenerConfig {
    fn default() -> Self {
        Self {
            udp_port: 514,
            tcp_port: 601,
            bind_address: "0.0.0.0".to_string(),
            parse_dns_logs: true,
            receive_buffer_bytes: Some(4 * 1024 * 1024),
            recv_tasks: 8,
            recv_batch_size: 32,
            tcp_idle_timeout: TCP_IDLE_TIMEOUT,
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
    parse_payloads: bool,
    structured_handle: Option<Arc<StructuredS3Handler>>,
}

impl DefaultSyslogHandler {
    pub fn new(
        parse_dns_logs: bool,
        parse_payloads: bool,
        structured_handle: Option<Arc<StructuredS3Handler>>,
    ) -> Self {
        Self {
            parse_dns_logs,
            parse_payloads,
            structured_handle,
        }
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

        if self.parse_payloads {
            let p = payload::dispatch(&message);
            if let Some(rec) =
                payload::StructuredSyslogRecord::from_syslog_and_payload(&message, &p)
                && let Some(handle) = &self.structured_handle
            {
                match handle.try_send(rec) {
                    Ok(()) => {}
                    Err(e) => {
                        // Safe to share DropSite::StructuredSyslog with the
                        // PayloadDispatchingHandler call site below even
                        // though the message text differs: main.rs wires
                        // DefaultSyslogHandler and PayloadDispatchingHandler
                        // as mutually exclusive, so only one of the two ever
                        // runs against a given `structured_handle`.
                        if let Some(dropped_total) =
                            handle.drop_log_due(DropSite::StructuredSyslog, DropKind::from(&e))
                        {
                            tracing::warn!(
                                dropped_total,
                                "structured_syslog S3 channel full; dropped record"
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Wraps any inner `SyslogHandler` (e.g. the S3 raw-persistence handler),
/// invokes it first, then runs payload dispatch and forwards matched records
/// to the structured sink.  Used in `main.rs` when both raw S3 persistence
/// and structured persistence are configured.
pub struct PayloadDispatchingHandler<H: SyslogHandler> {
    pub inner: Arc<H>,
    pub parse_payloads: bool,
    pub structured_handle: Option<Arc<StructuredS3Handler>>,
}

#[async_trait::async_trait]
impl<H: SyslogHandler + 'static> SyslogHandler for PayloadDispatchingHandler<H> {
    async fn handle_message(&self, message: SyslogMessage, source: SocketAddr) {
        self.inner.handle_message(message.clone(), source).await;
        if self.parse_payloads {
            let p = payload::dispatch(&message);
            if let Some(rec) =
                payload::StructuredSyslogRecord::from_syslog_and_payload(&message, &p)
                && let Some(h) = &self.structured_handle
            {
                match h.try_send(rec) {
                    Ok(()) => {}
                    Err(e) => {
                        // Safe to share DropSite::StructuredSyslog with the
                        // DefaultSyslogHandler call site above even though
                        // the message text differs: main.rs wires
                        // DefaultSyslogHandler and PayloadDispatchingHandler
                        // as mutually exclusive, so only one of the two ever
                        // runs against a given `structured_handle`.
                        if let Some(dropped_total) =
                            h.drop_log_due(DropSite::StructuredSyslog, DropKind::from(&e))
                        {
                            tracing::warn!(
                                dropped_total,
                                "structured_syslog channel full; dropped"
                            );
                        }
                    }
                }
            }
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
    allowed_ips: IpWhitelist,
}

impl SyslogListener {
    pub fn new(config: SyslogListenerConfig, handler: Arc<dyn SyslogHandler>) -> Self {
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
    ///
    /// `recv_tasks <= 1` is this exact combined UDP+TCP loop,
    /// unchanged — that is the property that makes the fan-out below safe
    /// to deploy. Above 1, N `SO_REUSEPORT` UDP sockets are bound and each
    /// drained by its own task; the TCP listener is unaffected (`recv_tasks`
    /// applies to the UDP arm only) and runs as one more task. Syslog's
    /// parser is stateless, so unlike IPFIX no state needs to be shared
    /// across UDP tasks — only the drop-stats tracker is shared, since all
    /// N sockets share one address:port and `/proc/net/udp` already sums
    /// their lines (see `syslog_udp_recv_loop` and its call site below).
    pub async fn start_with_shutdown(
        &self,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let udp_addr: SocketAddr =
            format!("{}:{}", self.config.bind_address, self.config.udp_port).parse()?;
        let tcp_addr: SocketAddr =
            format!("{}:{}", self.config.bind_address, self.config.tcp_port).parse()?;

        if self.config.recv_tasks <= 1 {
            let semaphore = Arc::new(Semaphore::new(MAX_SYSLOG_TCP_CONNECTIONS));

            let udp_socket = crate::net::bind_udp_with_recv_buffer(
                &udp_addr,
                self.config.receive_buffer_bytes,
                "syslog_udp",
            )
            .await?;
            info!("Syslog UDP listener started on {}", udp_addr);
            let tcp_listener = TcpListener::bind(&tcp_addr).await?;
            info!("Syslog TCP listener started on {}", tcp_addr);

            let handler_udp = self.handler.clone();
            let handler_tcp = self.handler.clone();
            let tcp_idle_timeout = self.config.tcp_idle_timeout;
            let mut socket_stats = crate::net::SocketDropStats::new(&udp_socket, "syslog_udp");
            let mut socket_stats_ticker =
                tokio::time::interval(crate::net::SOCKET_DROP_POLL_INTERVAL);

            if self.config.recv_batch_size <= 1 {
                let mut buf = vec![0u8; 65535];
                loop {
                    tokio::select! {
                        // UDP receive arm
                        result = udp_socket.recv_from(&mut buf) => {
                            match result {
                                Ok((len, src)) => {
                                    // ponytail: any new recv/accept arm in this module needs this same is_allowed check.
                                    if !self.allowed_ips.is_allowed(&src) {
                                        metrics::counter!("listener_source_rejected", "protocol" => "syslog_udp").increment(1);
                                        debug!("Rejected syslog_udp datagram from {} — not in allowed_ips", src);
                                        continue;
                                    }
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
                                            crate::truncate_for_log(&msg, 100)
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
                                    if !self.allowed_ips.is_allowed(&src) {
                                        metrics::counter!("listener_source_rejected", "protocol" => "syslog_tcp").increment(1);
                                        warn!("Rejected syslog_tcp connection from {} — not in allowed_ips", src);
                                        continue;
                                    }
                                    // Acquire semaphore permit before spawning — bounds concurrent connections
                                    match semaphore.clone().try_acquire_owned() {
                                        Ok(permit) => {
                                            let handler = handler_tcp.clone();
                                            tokio::spawn(async move {
                                                let _permit = permit; // held for connection lifetime
                                                if let Err(e) = Self::handle_tcp_connection(stream, src, handler, tcp_idle_timeout).await {
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
                        // Socket-drop/rx-queue metrics arm (UDP socket only; TCP has no analogous kernel drop counter here)
                        _ = socket_stats_ticker.tick() => {
                            socket_stats.poll().await;
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

                return Ok(());
            }

            // Batched-recv path: recv_batch_size > 1. UDP arm only; the TCP
            // accept arm, stats arm and shutdown arm are byte-for-byte the
            // same as the recv_batch_size <= 1 loop above.
            let mut batch = crate::net::RecvMmsgBatch::new(self.config.recv_batch_size);
            loop {
                tokio::select! {
                    // UDP receive arm (batched)
                    result = batch.recv(&udp_socket) => {
                        match result {
                            Ok(n) => {
                                for i in 0..n {
                                    let Some(src) = batch.src(i) else {
                                        warn!("syslog: batch message with unparseable source address, skipping");
                                        continue;
                                    };
                                    // ponytail: any new recv/accept arm in this module needs this same is_allowed check.
                                    if !self.allowed_ips.is_allowed(&src) {
                                        metrics::counter!("listener_source_rejected", "protocol" => "syslog_udp").increment(1);
                                        debug!("Rejected syslog_udp datagram from {} — not in allowed_ips", src);
                                        continue;
                                    }
                                    let payload = batch.payload(i);
                                    let msg = String::from_utf8_lossy(payload);
                                    debug!("Received UDP syslog message from {}: {} bytes", src, payload.len());
                                    metrics::counter!("syslog_messages_received").increment(1);
                                    if let Some(syslog_msg) = SyslogMessage::parse(&msg) {
                                        handler_udp.handle_message(syslog_msg, src).await;
                                    } else {
                                        metrics::counter!("syslog_parse_errors").increment(1);
                                        warn!(
                                            "Failed to parse syslog message from {}: {}",
                                            src,
                                            crate::truncate_for_log(&msg, 100)
                                        );
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
                                // error!("UDP receive error: {}", e); }`
                                // above) -- not a gap introduced by batching.
                                error!("Syslog UDP batched receive error: {}", e);
                            }
                        }
                    }
                    // TCP accept arm
                    result = tcp_listener.accept() => {
                        match result {
                            Ok((stream, src)) => {
                                if !self.allowed_ips.is_allowed(&src) {
                                    metrics::counter!("listener_source_rejected", "protocol" => "syslog_tcp").increment(1);
                                    warn!("Rejected syslog_tcp connection from {} — not in allowed_ips", src);
                                    continue;
                                }
                                // Acquire semaphore permit before spawning — bounds concurrent connections
                                match semaphore.clone().try_acquire_owned() {
                                    Ok(permit) => {
                                        let handler = handler_tcp.clone();
                                        tokio::spawn(async move {
                                            let _permit = permit; // held for connection lifetime
                                            if let Err(e) = Self::handle_tcp_connection(
                                                stream,
                                                src,
                                                handler,
                                                tcp_idle_timeout,
                                            )
                                            .await
                                            {
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
                    // Socket-drop/rx-queue metrics arm (UDP socket only; TCP has no analogous kernel drop counter here)
                    _ = socket_stats_ticker.tick() => {
                        socket_stats.poll().await;
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

            return Ok(());
        }

        // Fan-out path: recv_tasks > 1. Bind N SO_REUSEPORT UDP sockets on
        // the same address:port and drain each from its own task. The TCP
        // listener is unaffected by recv_tasks and runs as one more task.
        let mut sockets = Vec::with_capacity(self.config.recv_tasks);
        for _ in 0..self.config.recv_tasks {
            sockets.push(
                crate::net::bind_udp_reuseport_with_recv_buffer(
                    &udp_addr,
                    self.config.receive_buffer_bytes,
                    "syslog_udp",
                )
                .await?,
            );
        }
        let bound_udp_addr = sockets[0].local_addr()?;
        info!(
            "Syslog UDP listener started on {} ({} recv tasks)",
            bound_udp_addr,
            sockets.len()
        );

        let tcp_listener = TcpListener::bind(&tcp_addr).await?;
        info!("Syslog TCP listener started on {}", tcp_addr);
        let semaphore = Arc::new(Semaphore::new(MAX_SYSLOG_TCP_CONNECTIONS));

        // All N sockets share one address:port, so /proc/net/udp already
        // sums their lines (see `parse_proc_net_udp`) — one tracker polled
        // once per group; one per task would multiply-count the same total.
        let mut socket_stats = Some(crate::net::SocketDropStats::new(&sockets[0], "syslog_udp"));

        let mut tasks = Vec::with_capacity(sockets.len() + 1);
        for (i, socket) in sockets.into_iter().enumerate() {
            let handler = self.handler.clone();
            let allowed_ips = self.allowed_ips.clone();
            let task_shutdown_rx = shutdown_rx.clone();
            // Only the first task takes the shared drop-stats tracker, so it
            // is polled exactly once per SO_REUSEPORT group.
            let stats = if i == 0 { socket_stats.take() } else { None };
            tasks.push(tokio::spawn(syslog_udp_recv_loop(
                socket,
                handler,
                allowed_ips,
                task_shutdown_rx,
                stats,
                self.config.recv_batch_size,
            )));
        }

        let tcp_handler = self.handler.clone();
        let tcp_allowed_ips = self.allowed_ips.clone();
        let tcp_shutdown_rx = shutdown_rx.clone();
        let tcp_idle_timeout = self.config.tcp_idle_timeout;
        tasks.push(tokio::spawn(syslog_tcp_accept_loop(
            tcp_listener,
            tcp_handler,
            tcp_allowed_ips,
            semaphore,
            tcp_shutdown_rx,
            tcp_idle_timeout,
        )));

        for task in tasks {
            if let Err(e) = task.await {
                // A receive task that panics stops draining its socket for the
                // lifetime of the process. Discarding this JoinError made that
                // failure completely silent: the parent handle stays alive, so
                // main.rs's `supervise_listener_handles` never fires either.
                metrics::counter!("syslog_recv_task_failed").increment(1);
                error!("syslog: a receive task terminated abnormally: {e}");
            }
        }

        Ok(())
    }

    /// Start UDP syslog listener
    async fn start_udp_listener(&self) -> anyhow::Result<()> {
        let addr: SocketAddr =
            format!("{}:{}", self.config.bind_address, self.config.udp_port).parse()?;

        let socket = crate::net::bind_udp_with_recv_buffer(
            &addr,
            self.config.receive_buffer_bytes,
            "syslog_udp",
        )
        .await?;
        info!("Syslog UDP listener started on {}", addr);

        let mut buf = vec![0u8; 65535];
        let mut socket_stats = crate::net::SocketDropStats::new(&socket, "syslog_udp");
        let mut socket_stats_ticker = tokio::time::interval(crate::net::SOCKET_DROP_POLL_INTERVAL);

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, src)) => {
                            if !self.allowed_ips.is_allowed(&src) {
                                metrics::counter!("listener_source_rejected", "protocol" => "syslog_udp")
                                    .increment(1);
                                debug!(
                                    "Rejected syslog_udp datagram from {} — not in allowed_ips",
                                    src
                                );
                                continue;
                            }
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
                                    crate::truncate_for_log(&msg, 100)
                                );
                            }
                        }
                        Err(e) => {
                            error!("UDP receive error: {}", e);
                        }
                    }
                }
                _ = socket_stats_ticker.tick() => {
                    socket_stats.poll().await;
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
                    if !self.allowed_ips.is_allowed(&src) {
                        metrics::counter!("listener_source_rejected", "protocol" => "syslog_tcp")
                            .increment(1);
                        warn!(
                            "Rejected syslog_tcp connection from {} — not in allowed_ips",
                            src
                        );
                        continue;
                    }
                    match semaphore.clone().try_acquire_owned() {
                        Ok(permit) => {
                            let handler = self.handler.clone();
                            let tcp_idle_timeout = self.config.tcp_idle_timeout;
                            tokio::spawn(async move {
                                let _permit = permit; // held for connection lifetime
                                if let Err(e) = Self::handle_tcp_connection(
                                    stream,
                                    src,
                                    handler,
                                    tcp_idle_timeout,
                                )
                                .await
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
        idle_timeout: Duration,
    ) -> anyhow::Result<()> {
        let mut reader = BufReader::new(stream);
        let mut buf: Vec<u8> = Vec::new();

        loop {
            buf.clear();
            let mut limited = (&mut reader).take((SYSLOG_MAX_LINE_BYTES as u64) + 1);
            let n = match tokio::time::timeout(idle_timeout, limited.read_until(b'\n', &mut buf))
                .await
            {
                Err(_elapsed) => {
                    metrics::counter!("syslog_tcp_idle_timeouts").increment(1);
                    debug!("TCP connection from {} idle past timeout; closing", src);
                    break;
                }
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
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
                    crate::truncate_for_log(&line, 100)
                );
            }
        }

        Ok(())
    }
}

/// The UDP recv loop run by each task in the `recv_tasks > 1` fan-out. Same
/// body as the `recv_tasks <= 1` UDP arm in `start_with_shutdown`,
/// parameterized so it can be spawned once per `SO_REUSEPORT` socket.
/// `socket_stats` is `Some` for exactly one task per group (see the call
/// site) so the shared drop counter is polled once, not once per task.
async fn syslog_udp_recv_loop(
    socket: tokio::net::UdpSocket,
    handler: Arc<dyn SyslogHandler>,
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
                                metrics::counter!("listener_source_rejected", "protocol" => "syslog_udp").increment(1);
                                debug!("Rejected syslog_udp datagram from {} — not in allowed_ips", src);
                                continue;
                            }
                            let msg = String::from_utf8_lossy(&buf[..len]);
                            debug!("Received UDP syslog message from {}: {} bytes", src, len);
                            metrics::counter!("syslog_messages_received").increment(1);
                            if let Some(syslog_msg) = SyslogMessage::parse(&msg) {
                                handler.handle_message(syslog_msg, src).await;
                            } else {
                                metrics::counter!("syslog_parse_errors").increment(1);
                                warn!(
                                    "Failed to parse syslog message from {}: {}",
                                    src,
                                    crate::truncate_for_log(&msg, 100)
                                );
                            }
                        }
                        Err(e) => {
                            error!("UDP receive error: {}", e);
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
                        info!("Syslog UDP listener: shutdown signal received");
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
                                warn!("syslog: batch message with unparseable source address, skipping");
                                continue;
                            };
                            // ponytail: any new recv/accept arm in this module needs this same is_allowed check.
                            if !allowed_ips.is_allowed(&src) {
                                metrics::counter!("listener_source_rejected", "protocol" => "syslog_udp").increment(1);
                                debug!("Rejected syslog_udp datagram from {} — not in allowed_ips", src);
                                continue;
                            }
                            let payload = batch.payload(i);
                            let msg = String::from_utf8_lossy(payload);
                            debug!("Received UDP syslog message from {}: {} bytes", src, payload.len());
                            metrics::counter!("syslog_messages_received").increment(1);
                            if let Some(syslog_msg) = SyslogMessage::parse(&msg) {
                                handler.handle_message(syslog_msg, src).await;
                            } else {
                                metrics::counter!("syslog_parse_errors").increment(1);
                                warn!(
                                    "Failed to parse syslog message from {}: {}",
                                    src,
                                    crate::truncate_for_log(&msg, 100)
                                );
                            }
                        }
                    }
                    Err(e) => {
                        // ponytail: EINTR is not special-cased here either --
                        // same parity note as the inline loop's batched arm
                        // in start_with_shutdown. Retried on the next loop
                        // iteration via batch.recv()'s own readable() await.
                        error!("Syslog UDP batched receive error: {}", e);
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
                    info!("Syslog UDP listener: shutdown signal received");
                    break;
                }
            }
        }
    }
}

/// The TCP accept loop used by the `recv_tasks > 1` fan-out path. Identical
/// behaviour to the TCP arm of the combined `recv_tasks <= 1` loop in
/// `start_with_shutdown`, extracted so it can run as its own task alongside
/// the N UDP recv tasks — `recv_tasks` does not apply to TCP, so there is
/// always exactly one of these regardless of the knob's value.
async fn syslog_tcp_accept_loop(
    listener: TcpListener,
    handler: Arc<dyn SyslogHandler>,
    allowed_ips: IpWhitelist,
    semaphore: Arc<Semaphore>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    idle_timeout: Duration,
) {
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, src)) => {
                        if !allowed_ips.is_allowed(&src) {
                            metrics::counter!("listener_source_rejected", "protocol" => "syslog_tcp").increment(1);
                            warn!("Rejected syslog_tcp connection from {} — not in allowed_ips", src);
                            continue;
                        }
                        // Acquire semaphore permit before spawning — bounds concurrent connections
                        match semaphore.clone().try_acquire_owned() {
                            Ok(permit) => {
                                let handler = handler.clone();
                                tokio::spawn(async move {
                                    let _permit = permit; // held for connection lifetime
                                    if let Err(e) = SyslogListener::handle_tcp_connection(
                                        stream,
                                        src,
                                        handler,
                                        idle_timeout,
                                    )
                                    .await
                                    {
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
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("Syslog TCP listener: shutdown signal received");
                    break;
                }
            }
        }
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
    use tokio::net::UdpSocket;
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

        let handler = Arc::new(DefaultSyslogHandler::new(
            config.parse_dns_logs,
            false,
            None,
        ));
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

    /// Firing the shutdown signal makes `start_with_shutdown` return cleanly
    /// within a short timeout (the shutdown arm of the select! is exercised).
    #[tokio::test]
    async fn start_with_shutdown_exits_on_signal() {
        use tokio::sync::watch;
        use tokio::time::timeout;

        // Bind on ephemeral ports so we don't need privileged ports or fixed values.
        let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_port = udp_socket.local_addr().unwrap().port();
        drop(udp_socket); // release so start_with_shutdown can re-bind

        let tcp_listener_raw = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = tcp_listener_raw.local_addr().unwrap().port();
        drop(tcp_listener_raw);

        let config = SyslogListenerConfig {
            udp_port,
            tcp_port,
            bind_address: "127.0.0.1".to_string(),
            parse_dns_logs: false,
            ..SyslogListenerConfig::default()
        };
        let handler: Arc<dyn SyslogHandler> =
            Arc::new(DefaultSyslogHandler::new(false, false, None));
        let listener = SyslogListener::new(config, handler);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let task = tokio::spawn(async move {
            listener.start_with_shutdown(shutdown_rx).await.ok();
        });

        // Give the listener time to bind and enter the select! loop.
        tokio::time::sleep(Duration::from_millis(50)).await;

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
    /// with a non-default buffer size still binds and processes UDP syslog
    /// messages normally. The socket-level assertion that the requested size
    /// actually changes `SO_RCVBUF` lives in `crate::net`'s unit tests,
    /// against the exact same `bind_udp_with_recv_buffer` call this listener
    /// makes.
    #[tokio::test]
    async fn start_with_shutdown_honors_configured_receive_buffer() {
        use tokio::sync::watch;
        use tokio::time::timeout;

        let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_port = udp_socket.local_addr().unwrap().port();
        drop(udp_socket);

        let tcp_listener_raw = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = tcp_listener_raw.local_addr().unwrap().port();
        drop(tcp_listener_raw);

        let config = SyslogListenerConfig {
            udp_port,
            tcp_port,
            bind_address: "127.0.0.1".to_string(),
            parse_dns_logs: false,
            receive_buffer_bytes: Some(1024 * 1024),
            ..SyslogListenerConfig::default()
        };
        let handler = CapturingHandler::new();
        let listener = SyslogListener::new(config, handler.clone());

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            listener.start_with_shutdown(shutdown_rx).await.ok();
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(
                b"<134>1 2026-09-13T00:00:00Z host app - - - test message",
                ("127.0.0.1", udp_port),
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        shutdown_tx.send(true).unwrap();
        let _ = timeout(Duration::from_secs(2), task).await;

        assert_eq!(
            handler.take_messages().len(),
            1,
            "listener with a configured receive buffer must still process messages"
        );
    }

    #[tokio::test]
    async fn default_handler_dispatches_cef_to_structured_handle() {
        use crate::config::{S3ConnectionConfig, SyslogS3Config};
        use crate::forwarding::s3_sink::S3Sink;
        use crate::forwarding::structured_syslog_s3::structured_syslog_start;
        use crate::syslog::SyslogMessage;
        use std::net::SocketAddr;
        use tokio::time::{Duration, sleep};

        // Use an unreachable S3 endpoint — the writer will buffer the record
        // but won't actually upload.
        let conn = S3ConnectionConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            bucket: "test".to_string(),
            region: "us-east-1".to_string(),
            access_key: "KEY".to_string(),
            secret_key: "SECRET".to_string(),
        };
        let s3 = Arc::new(S3Sink::from_connection(&conn).await.expect("constructs"));
        let cfg = SyslogS3Config {
            connection: conn,
            prefix: "structured-test".to_string(),
            max_buffer_rows: 100,
            flush_interval_secs: 3600,
            channel_capacity: 16,
        };
        let (structured_handle, _join) = structured_syslog_start(
            &cfg,
            s3,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );
        let structured_handle = Arc::new(structured_handle);

        let handler = DefaultSyslogHandler::new(
            false,
            true, // parse_payloads = true
            Some(structured_handle.clone()),
        );

        let cef_syslog = SyslogMessage::parse(
            "<134>Jan 15 10:30:45 fw01 arcsight: \
             CEF:0|Vendor|Product|1.0|100|Name|5|src=10.0.0.1",
        )
        .unwrap();

        let src: SocketAddr = "127.0.0.1:5514".parse().unwrap();
        handler.handle_message(cef_syslog, src).await;

        // Give the channel a moment; test that try_send was called without panic.
        sleep(Duration::from_millis(50)).await;
        // If the handler panicked or did not compile the test would fail above.
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

    /// A source outside `allowed_ips` never reaches the handler.
    #[tokio::test]
    async fn with_allowed_ips_blocks_disallowed_source() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();
        let listener = SyslogListener::new(SyslogListenerConfig::default(), handler_clone)
            .with_allowed_ips(IpWhitelist::new(vec!["10.99.99.0/24".into()]).unwrap());

        let task = tokio::spawn(async move {
            listener.run_with_listener(tcp_listener).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _ = stream
            .write_all(b"<134>Jan 15 10:30:45 host app: test message\n")
            .await;
        drop(stream);

        sleep(Duration::from_millis(150)).await;
        task.abort();

        let messages = handler.take_messages();
        assert!(
            messages.is_empty(),
            "blocked source must not reach the handler; got {}",
            messages.len()
        );
    }

    /// A source inside `allowed_ips` reaches the handler as normal.
    #[tokio::test]
    async fn with_allowed_ips_allows_whitelisted_source() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();
        let listener = SyslogListener::new(SyslogListenerConfig::default(), handler_clone)
            .with_allowed_ips(IpWhitelist::new(vec!["127.0.0.1".into()]).unwrap());

        let task = tokio::spawn(async move {
            listener.run_with_listener(tcp_listener).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"<134>Jan 15 10:30:45 host app: test message\n")
            .await
            .unwrap();
        drop(stream);

        sleep(Duration::from_millis(150)).await;
        task.abort();

        let messages = handler.take_messages();
        assert_eq!(
            messages.len(),
            1,
            "allowed source must reach the handler; got {}",
            messages.len()
        );
    }

    /// Test handler that counts messages and also records each parsed
    /// message body — the fan-out test only cares whether every message
    /// arrived, but the combined recv_tasks+recv_batch_size tests need to
    /// tell distinct messages apart from a batching bug that decodes the
    /// same message repeatedly (see `distinct_message_count`).
    struct CountingHandler {
        count: std::sync::atomic::AtomicUsize,
        bodies: Mutex<std::collections::HashSet<String>>,
    }

    impl CountingHandler {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                count: std::sync::atomic::AtomicUsize::new(0),
                bodies: Mutex::new(std::collections::HashSet::new()),
            })
        }
        fn message_count(&self) -> usize {
            self.count.load(std::sync::atomic::Ordering::SeqCst)
        }
        /// Number of distinct parsed message bodies seen. An index-reuse
        /// bug that decodes the same batch slot `n` times still increments
        /// `message_count()` to `n`, but every decode carries the same
        /// body text, so this stays at 1.
        fn distinct_message_count(&self) -> usize {
            self.bodies.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl SyslogHandler for CountingHandler {
        async fn handle_message(&self, message: SyslogMessage, _source: SocketAddr) {
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.bodies.lock().unwrap().insert(message.message.clone());
        }
    }

    /// Starts a real `SyslogListener` via `start_with_shutdown` (the
    /// production path) bound to ephemeral UDP/TCP ports, with `recv_tasks`
    /// configured as given. Returns the listener's join handle, its bound
    /// UDP address, the shutdown sender, and a handler that counts total
    /// messages.
    async fn start_test_listener(
        recv_tasks: usize,
        recv_batch_size: usize,
    ) -> (
        tokio::task::JoinHandle<anyhow::Result<()>>,
        SocketAddr,
        tokio::sync::watch::Sender<bool>,
        Arc<CountingHandler>,
    ) {
        // Bind briefly to obtain ephemeral ports, then drop so the listener
        // (and, for recv_tasks > 1, its SO_REUSEPORT group) can bind the
        // same UDP address — same pattern as this module's other tests.
        let tmp_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_port = tmp_udp.local_addr().unwrap().port();
        drop(tmp_udp);
        let tmp_tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = tmp_tcp.local_addr().unwrap().port();
        drop(tmp_tcp);
        let bound: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();

        let config = SyslogListenerConfig {
            udp_port,
            tcp_port,
            bind_address: "127.0.0.1".to_string(),
            parse_dns_logs: false,
            recv_tasks,
            recv_batch_size,
            ..SyslogListenerConfig::default()
        };
        let handler = CountingHandler::new();
        let listener = SyslogListener::new(config, handler.clone());

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
    /// Syslog UDP parses each datagram independently — no cross-datagram
    /// state — so the only risk here is a lost datagram, not a decode
    /// failure.
    ///
    /// Port count chosen empirically, not from the naive `1 - (3/4)^n`
    /// binomial model, mirroring the sFlow/IPFIX fan-out tests: with a
    /// 4-member group and one socket sabotaged to never drain (bound,
    /// receiving its hashed share, but its task never calls `recv_from`),
    /// 32 source ports (320 datagrams total) caught the sabotage in 10 of
    /// 10 measured runs here (see the task-6 report for the exact
    /// procedure) — that is the number this test uses.
    #[tokio::test]
    async fn fanned_out_udp_receives_from_several_source_ports() {
        const SOURCE_PORTS: u32 = 32;
        const DATAGRAMS_PER_PORT: u32 = 10;

        let (listener, bound, shutdown_tx, handler) = start_test_listener(4, 1).await;

        for i in 0..SOURCE_PORTS {
            let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            for n in 0..DATAGRAMS_PER_PORT {
                let msg = format!("<34>Oct 11 22:14:15 host app: fanout {i}-{n}");
                sock.send_to(msg.as_bytes(), bound).await.unwrap();
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let _ = shutdown_tx.send(true);
        let _ = listener.await;

        assert_eq!(
            handler.message_count(),
            (SOURCE_PORTS * DATAGRAMS_PER_PORT) as usize
        );
    }

    /// The end-to-end regression this task exists to prevent: a batch of many
    /// datagrams arriving before the listener's next recv must parse every one
    /// of them, not just the first. A buggy implementation that reads a batch
    /// but only processes message 0 (the classic "forgot the loop" bug) would
    /// pass a single-datagram smoke test and fail this one.
    #[tokio::test]
    async fn batched_recv_parses_every_message_in_a_batch() {
        let (listener, bound, shutdown_tx, handler) = start_test_listener(1, 16).await;

        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for i in 0..10 {
            let msg = format!("<34>Oct 11 22:14:15 host app: batch {i}");
            sock.send_to(msg.as_bytes(), bound).await.unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let _ = shutdown_tx.send(true);
        let _ = listener.await;

        assert_eq!(handler.message_count(), 10);
    }

    /// The `allowed_ips` and per-datagram-counter invariant: with allowed_ips
    /// restricted to exclude 127.0.0.1 entirely, every message in a
    /// multi-message batch must be independently rejected and independently
    /// counted -- `listener_source_rejected` (label `"syslog_udp"`) must read
    /// N after N rejected datagrams, not 1. A batch-level check (verify the
    /// first message's source, apply the verdict to the whole batch,
    /// `continue` the outer loop) would still reject everything on this
    /// all-loopback test -- the counter is what distinguishes "checked once"
    /// from "checked N times", not the pass/fail outcome, which loopback
    /// can't vary by source IP.
    #[allow(clippy::mutable_key_type)] // false positive: CompositeKey AtomicBool is never hashed
    #[tokio::test]
    async fn batched_recv_checks_and_counts_allowed_ips_per_datagram() {
        use metrics::set_default_local_recorder;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::{CompositeKey, MetricKind};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let tmp_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_port = tmp_udp.local_addr().unwrap().port();
        drop(tmp_udp);
        let tmp_tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = tmp_tcp.local_addr().unwrap().port();
        drop(tmp_tcp);
        let bound: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();

        // Whitelist a network that does NOT include 127.0.0.1 -- every
        // datagram in this test must be rejected.
        let disallowing_whitelist = IpWhitelist::new(vec!["10.0.0.0/8".to_string()]).unwrap();
        let config = SyslogListenerConfig {
            udp_port,
            tcp_port,
            bind_address: "127.0.0.1".to_string(),
            parse_dns_logs: false,
            recv_tasks: 1,
            recv_batch_size: 16,
            ..SyslogListenerConfig::default()
        };
        let handler = CountingHandler::new();
        let listener =
            SyslogListener::new(config, handler.clone()).with_allowed_ips(disallowing_whitelist);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move { listener.start_with_shutdown(shutdown_rx).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let n = 10u32;
        for i in 0..n {
            let msg = format!("<34>Oct 11 22:14:15 host app: rejected {i}");
            sock.send_to(msg.as_bytes(), bound).await.unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let _ = shutdown_tx.send(true);
        let _ = task.await;

        assert_eq!(
            handler.message_count(),
            0,
            "every datagram must be rejected"
        );

        let map = snapshotter.snapshot().into_hashmap();
        let rejected = map
            .get(&CompositeKey::new(
                MetricKind::Counter,
                metrics::Key::from_parts(
                    "listener_source_rejected",
                    vec![metrics::Label::new("protocol", "syslog_udp")],
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

    /// The combined `recv_tasks > 1` AND `recv_batch_size > 1` shape: `recv_tasks
    /// = 4` forces every datagram through the SO_REUSEPORT group and
    /// `syslog_udp_recv_loop`'s own batched arm, not the inline loop inside
    /// `start_with_shutdown`. All sends come from one client socket,
    /// back-to-back with no `.await` between them, so they consistently hash
    /// to the same group member and have a real chance to queue together
    /// before that task's next `batch.recv()` drains them -- exercising an
    /// actual multi-message batch inside the fan-out path.
    ///
    /// `message_count()` alone cannot tell "10 distinct messages parsed"
    /// apart from "10 duplicate parses of whichever message landed in one
    /// fixed batch slot" -- an index-reuse bug inside the `for i in 0..n`
    /// loop (using a fixed index instead of `i`) still runs the loop to
    /// completion and still produces one message per iteration, so the count
    /// alone stays 10. Each of the 10 sends embeds a distinct index in its
    /// message body, so distinct sends must parse to distinct message
    /// bodies -- `distinct_message_count()` is what actually catches that
    /// bug.
    #[tokio::test]
    async fn fanout_batched_recv_parses_every_message_across_batches() {
        let (listener, bound, shutdown_tx, handler) = start_test_listener(4, 16).await;

        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for i in 0..10 {
            // No sleep between sends -- give the kernel a chance to queue
            // several before syslog_udp_recv_loop's next batch.recv() call
            // drains the socket, so this test actually exercises n > 1 in
            // the `for i in 0..n` loop of the fan-out batched arm, not
            // n == 1 every time.
            let msg = format!("<34>Oct 11 22:14:15 host app: batch {i}");
            sock.send_to(msg.as_bytes(), bound).await.unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let _ = shutdown_tx.send(true);
        let _ = listener.await;

        assert_eq!(
            handler.message_count(),
            10,
            "every message sent through the recv_tasks=4 + recv_batch_size=16 combined path must parse"
        );
        assert_eq!(
            handler.distinct_message_count(),
            10,
            "each of the 10 distinct messages must parse with its own body, not one message's content duplicated across a batch"
        );
    }

    /// The `allowed_ips`/counter invariant from
    /// `batched_recv_checks_and_counts_allowed_ips_per_datagram` above, re-run
    /// through `syslog_udp_recv_loop`'s batched arm (`recv_tasks = 4`)
    /// instead of the inline loop's -- the combined-path gap Finding 1 named
    /// for ipfix and sFlow applies here identically.
    #[allow(clippy::mutable_key_type)] // false positive: CompositeKey AtomicBool is never hashed
    #[tokio::test]
    async fn fanout_batched_recv_checks_and_counts_allowed_ips_per_datagram() {
        use metrics::set_default_local_recorder;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::{CompositeKey, MetricKind};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let tmp_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_port = tmp_udp.local_addr().unwrap().port();
        drop(tmp_udp);
        let tmp_tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = tmp_tcp.local_addr().unwrap().port();
        drop(tmp_tcp);
        let bound: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();

        let disallowing_whitelist = IpWhitelist::new(vec!["10.0.0.0/8".to_string()]).unwrap();
        let config = SyslogListenerConfig {
            udp_port,
            tcp_port,
            bind_address: "127.0.0.1".to_string(),
            parse_dns_logs: false,
            recv_tasks: 4,
            recv_batch_size: 16,
            ..SyslogListenerConfig::default()
        };
        let handler = CountingHandler::new();
        let listener =
            SyslogListener::new(config, handler.clone()).with_allowed_ips(disallowing_whitelist);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move { listener.start_with_shutdown(shutdown_rx).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let n = 10u32;
        for i in 0..n {
            let msg = format!("<34>Oct 11 22:14:15 host app: rejected {i}");
            sock.send_to(msg.as_bytes(), bound).await.unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let _ = shutdown_tx.send(true);
        let _ = task.await;

        assert_eq!(
            handler.message_count(),
            0,
            "every datagram must be rejected"
        );

        let map = snapshotter.snapshot().into_hashmap();
        let rejected = map
            .get(&CompositeKey::new(
                MetricKind::Counter,
                metrics::Key::from_parts(
                    "listener_source_rejected",
                    vec![metrics::Label::new("protocol", "syslog_udp")],
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
