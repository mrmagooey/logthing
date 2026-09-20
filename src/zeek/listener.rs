//! Zeek TCP NDJSON listener.

use crate::middleware::IpWhitelist;
use crate::zeek::ZeekRecord;
use chrono::Utc;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

/// Maximum number of concurrent TCP connections accepted by the Zeek listener.
/// Prevents resource exhaustion from connection floods.
pub const MAX_ZEEK_TCP_CONNECTIONS: usize = 1024;

/// Maximum accepted line length in bytes. Lines exceeding this are skipped
/// and counted via `zeek_oversized_lines`.
pub const ZEEK_MAX_LINE_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

/// Bytes represented by a single byte-budget permit (see
/// `ZEEK_TCP_BYTE_BUDGET`). A connection accumulating a line near
/// `ZEEK_MAX_LINE_BYTES` needs ~256 permits at this size — granular enough
/// accounting without acquiring on every few-byte read.
const ZEEK_BUDGET_CHUNK_BYTES: usize = 64 * 1024; // 64 KiB

/// Global memory budget for in-flight (not yet newline-terminated) Zeek TCP
/// line buffers, shared across every connection on this listener.
///
/// `MAX_ZEEK_TCP_CONNECTIONS` (1024) and `ZEEK_MAX_LINE_BYTES` (16 MiB) are
/// each individually reasonable, but their product never was: 1024
/// connections each holding a 16 MiB unterminated line is ~15 GiB of
/// attacker-controlled heap. This budget bounds the *aggregate* instead of
/// changing what a single valid record may be. 512 MiB caps that at roughly
/// 32 concurrent maximum-size lines — generous for legitimate bursty
/// senders (real Zeek NDJSON lines are nowhere near 16 MiB), survivable for
/// the process. A connection that cannot get budget is closed immediately
/// (see `zeek_tcp_budget_exhausted`) rather than left to hang or grow
/// without limit.
const ZEEK_TCP_BYTE_BUDGET: usize = 512 * 1024 * 1024; // 512 MiB

/// Total byte-budget permits available, derived from the budget and chunk
/// size above.
const ZEEK_BYTE_BUDGET_PERMITS: usize = ZEEK_TCP_BYTE_BUDGET / ZEEK_BUDGET_CHUNK_BYTES;

/// Capacity threshold above which a cleared line buffer's heap allocation is
/// released instead of retained for reuse.
///
/// `Vec::clear()` drops contents but keeps capacity, so a connection that
/// once sent a legitimate near-`ZEEK_MAX_LINE_BYTES` line would otherwise
/// keep that ~16 MiB allocation for the rest of the connection's life —
/// including a client that sends one huge line and then heartbeats
/// forever, which never trips the oversize guard or the idle timeout again.
const ZEEK_BUF_SHRINK_THRESHOLD_BYTES: usize = 256 * 1024; // 256 KiB

/// Outcome of accumulating one line from the socket, bounded by the idle
/// timeout, `ZEEK_MAX_LINE_BYTES`, and the shared byte budget.
enum LineReadOutcome {
    /// Peer closed the connection (read returned 0 bytes with no partial line).
    Eof,
    /// A complete line (including trailing `\n`) is in `buf`.
    Line,
    /// The line exceeded `ZEEK_MAX_LINE_BYTES` with no newline seen.
    Oversized,
    /// The shared byte budget was exhausted before a newline was seen.
    BudgetExhausted,
}

/// Shrinks `buf`'s heap allocation once its retained capacity exceeds
/// `ZEEK_BUF_SHRINK_THRESHOLD_BYTES`. Intended to be called right after
/// `buf.clear()`, which drops contents but not capacity.
fn shrink_oversized_buffer(buf: &mut Vec<u8>) {
    if buf.capacity() > ZEEK_BUF_SHRINK_THRESHOLD_BYTES {
        buf.shrink_to_fit();
    }
}

/// Maximum time a TCP connection may sit without delivering a complete line
/// before it is closed. Without this, a client that connects and sends
/// nothing holds a connection-semaphore permit for the process's lifetime,
/// so 1024 silent sockets exhaust the listener. Not exposed via
/// `ZeekListenerConfig` (unlike syslog's `tcp_idle_timeout`): every existing
/// caller of `ZeekListenerConfig` — production and tests alike — builds it
/// as a bare 2-field literal with no `..Default::default()`, so a new
/// required field would ripple through all of them for no production
/// benefit.
///
/// The `#[cfg(test)]` override below is visible to every test in this file,
/// including ones that drive the real accept loop via `run_with_listener`
/// (unlike syslog's external `tests/` integration test, these are in-crate
/// `#[cfg(test)]` tests compiled as part of this same crate, so they DO see
/// this cfg-gated value) — that lets a test exercise the production
/// `let idle_timeout = TCP_IDLE_TIMEOUT;` wiring at the accept-loop call
/// sites directly, not just `handle_tcp_connection` in isolation with a
/// hand-passed `Duration`.
///
/// This override is FILE-WIDE — every test in this file compiled under
/// `cfg(test)` gets this value, not just the idle-timeout tests. In
/// particular, `oversized_line_closes_connection_and_increments_metric` and
/// `valid_connection_after_oversized_still_works` each push
/// `ZEEK_MAX_LINE_BYTES + 1` (16 MiB + 1) of un-newlined data through the
/// `fill_buf`/`consume` line-assembly loop in `handle_tcp_connection` — one
/// `tokio::time::timeout` still wraps the whole loop, not each individual
/// `fill_buf` call, so the loop must finish assembling (or overflowing) the
/// line within this window or those tests fail for the wrong reason
/// (idle-timeout counter instead of oversized-lines counter). 5s gives that
/// a ~3.3 MB/s floor, comfortable even on a loaded/throttled CI runner. If
/// you're tempted to tune this down further for faster idle-timeout tests,
/// check those two tests still have headroom first.
#[cfg(not(test))]
pub(crate) const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
#[cfg(test)]
pub(crate) const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

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

/// Default handler: logs a summary. Installed only when no forwarding
/// destination is configured; the ingest counters live in the listener's
/// parse loop so they fire for every handler.
pub struct DefaultZeekHandler;

#[async_trait::async_trait]
impl ZeekHandler for DefaultZeekHandler {
    async fn handle_record(&self, record: ZeekRecord, source: SocketAddr) {
        // `log_path` comes straight from the wire (`_path` in the NDJSON
        // record, run through `normalize_log_path` but not length- or
        // control-character-bounded) and this handler is wired in whenever
        // no forwarding destination is configured (`main.rs`), i.e. reachable
        // in production without auth. `fields` doesn't need the same
        // treatment: `serde_json::Value::to_string()` always JSON-escapes
        // control characters in string values, so it can't carry a raw
        // newline or ANSI escape even though it's also wire-derived.
        info!(
            "[{}] zeek record: path={} fields={}",
            source,
            crate::sanitize_for_log(&record.log_path, 100),
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
    allowed_ips: IpWhitelist,
}

impl ZeekListener {
    pub fn new(config: ZeekListenerConfig, handler: Arc<dyn ZeekHandler>) -> Self {
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
        info!("Zeek TCP listener started on {}", bound);

        let semaphore = Arc::new(Semaphore::new(MAX_ZEEK_TCP_CONNECTIONS));
        let byte_budget = Arc::new(Semaphore::new(ZEEK_BYTE_BUDGET_PERMITS));

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, src)) => {
                            // ponytail: any new recv/accept arm in this module needs this same is_allowed check.
                            if !self.allowed_ips.is_allowed(&src) {
                                metrics::counter!("listener_source_rejected", "protocol" => "zeek").increment(1);
                                warn!("Rejected zeek connection from {} — not in allowed_ips", src);
                                continue;
                            }
                            match semaphore.clone().try_acquire_owned() {
                                Ok(permit) => {
                                    let handler = self.handler.clone();
                                    let idle_timeout = TCP_IDLE_TIMEOUT;
                                    let byte_budget = byte_budget.clone();
                                    tokio::spawn(async move {
                                        let _permit = permit; // held for connection lifetime
                                        if let Err(e) = Self::handle_tcp_connection(stream, src, handler, idle_timeout, byte_budget).await {
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
        let byte_budget = Arc::new(Semaphore::new(ZEEK_BYTE_BUDGET_PERMITS));

        loop {
            match listener.accept().await {
                Ok((stream, src)) => {
                    if !self.allowed_ips.is_allowed(&src) {
                        metrics::counter!("listener_source_rejected", "protocol" => "zeek")
                            .increment(1);
                        warn!("Rejected zeek connection from {} — not in allowed_ips", src);
                        continue;
                    }
                    match semaphore.clone().try_acquire_owned() {
                        Ok(permit) => {
                            let handler = self.handler.clone();
                            let idle_timeout = TCP_IDLE_TIMEOUT;
                            let byte_budget = byte_budget.clone();
                            tokio::spawn(async move {
                                let _permit = permit; // held for connection lifetime
                                if let Err(e) = Self::handle_tcp_connection(
                                    stream,
                                    src,
                                    handler,
                                    idle_timeout,
                                    byte_budget,
                                )
                                .await
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

    /// Handle one TCP connection: BufReader + bounded read loop, one NDJSON record per line.
    ///
    /// `byte_budget` is a per-listener budget shared across every connection (see
    /// `ZEEK_TCP_BYTE_BUDGET`): permits are acquired as this connection's line buffer grows
    /// past each `ZEEK_BUDGET_CHUNK_BYTES` boundary and released when the buffer is cleared or
    /// the connection ends, so `ZEEK_MAX_LINE_BYTES` can stay generous per line without letting
    /// `MAX_ZEEK_TCP_CONNECTIONS` concurrent maxed-out lines multiply into unbounded memory.
    async fn handle_tcp_connection(
        stream: TcpStream,
        src: SocketAddr,
        handler: Arc<dyn ZeekHandler>,
        idle_timeout: Duration,
        byte_budget: Arc<Semaphore>,
    ) -> anyhow::Result<()> {
        let mut reader = BufReader::new(stream);
        let mut buf: Vec<u8> = Vec::new();
        // Byte-budget permits held for `buf`'s current contents; `held_units *
        // ZEEK_BUDGET_CHUNK_BYTES` bytes of headroom. Dropped (releasing the permits) whenever
        // `buf` is cleared.
        let mut permits: Vec<tokio::sync::OwnedSemaphorePermit> = Vec::new();
        let mut held_units: usize;

        loop {
            buf.clear();
            shrink_oversized_buffer(&mut buf);
            permits.clear();
            held_units = 0;

            let outcome: Result<std::io::Result<LineReadOutcome>, _> =
                tokio::time::timeout(idle_timeout, async {
                    loop {
                        let available = reader.fill_buf().await?;
                        if available.is_empty() {
                            // True EOF. `read_until`'s original contract returns `Ok(n)` with
                            // whatever was accumulated (n > 0) on a mid-line EOF, not `Ok(0)` —
                            // an ordinary client that writes its final record with no trailing
                            // newline and then closes must still have it parsed and dispatched.
                            // Only a clean EOF with nothing accumulated ends the connection
                            // silently.
                            return Ok(if buf.is_empty() {
                                LineReadOutcome::Eof
                            } else {
                                LineReadOutcome::Line
                            });
                        }
                        let remaining_cap = ZEEK_MAX_LINE_BYTES + 1 - buf.len();
                        let take_len = available.len().min(remaining_cap);
                        let newline_pos = available[..take_len].iter().position(|&b| b == b'\n');
                        let consume_len = newline_pos.map_or(take_len, |pos| pos + 1);

                        buf.extend_from_slice(&available[..consume_len]);
                        reader.consume(consume_len);

                        let needed_units = buf.len().div_ceil(ZEEK_BUDGET_CHUNK_BYTES);
                        if needed_units > held_units {
                            let extra = (needed_units - held_units) as u32;
                            match byte_budget.clone().try_acquire_many_owned(extra) {
                                Ok(permit) => {
                                    permits.push(permit);
                                    held_units = needed_units;
                                }
                                Err(_) => return Ok(LineReadOutcome::BudgetExhausted),
                            }
                        }

                        if newline_pos.is_some() {
                            return Ok(LineReadOutcome::Line);
                        }
                        if buf.len() > ZEEK_MAX_LINE_BYTES {
                            return Ok(LineReadOutcome::Oversized);
                        }
                    }
                })
                .await;

            let outcome = match outcome {
                Err(_elapsed) => {
                    metrics::counter!("zeek_tcp_idle_timeouts").increment(1);
                    debug!(
                        "Zeek TCP connection from {} idle past timeout; closing",
                        src
                    );
                    break;
                }
                Ok(Err(e)) => {
                    error!("Zeek TCP read error from {}: {}", src, e);
                    break;
                }
                Ok(Ok(outcome)) => outcome,
            };

            match outcome {
                LineReadOutcome::Eof => {
                    debug!("Zeek TCP connection from {} closed", src);
                    break;
                }
                LineReadOutcome::Oversized => {
                    // The line exceeded the cap — close the connection (resyncing is itself
                    // unbounded).
                    metrics::counter!("zeek_oversized_lines").increment(1);
                    warn!(
                        "Zeek: line from {} exceeded {} bytes; closing connection",
                        src, ZEEK_MAX_LINE_BYTES
                    );
                    break;
                }
                LineReadOutcome::BudgetExhausted => {
                    metrics::counter!("zeek_tcp_budget_exhausted").increment(1);
                    warn!(
                        "Zeek: shared TCP byte budget exhausted while reading from {}; \
                         closing connection",
                        src
                    );
                    break;
                }
                LineReadOutcome::Line => {}
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
            // Parse JSON. The parse itself lives in `zeek::parse_line` so it can
            // be unit-tested and benchmarked; this loop keeps the transport
            // concerns (oversize guard, UTF-8, teardown) and the metrics, which
            // need the peer address.
            let parsed = match crate::zeek::parse_line(line, Utc::now()) {
                Ok(p) => p,
                Err(e) => {
                    metrics::counter!("zeek_parse_errors").increment(1);
                    // The line-framing loop above only guarantees no *trailing*
                    // newline reaches here (it's popped a few lines up) — a bare
                    // `\r` or an ANSI escape (`\x1b`) mid-line is untouched by
                    // that framing and would still reach an operator's terminal
                    // unsanitized. Use `sanitize_for_log`, not `truncate_for_log`,
                    // here too; do not "restore" this to `truncate_for_log`.
                    warn!(
                        "Zeek: JSON parse error from {}: {} — line: {}",
                        src,
                        e,
                        crate::sanitize_for_log(line, 120),
                    );
                    continue;
                }
            };
            if parsed.path_was_missing {
                metrics::counter!("zeek_missing_path").increment(1);
            }
            let record = parsed.record;
            // Counted here, not in a handler impl: every handler
            // (DefaultZeekHandler, MultiZeekHandler, Aggregating...) routes
            // through this one point, so the metric is emitted regardless of
            // which forwarding destinations are configured.
            metrics::counter!("zeek_records_received").increment(1);
            metrics::counter!("zeek_records_by_path",
                "log_path" => crate::zeek::schema::metric_log_path(&record.log_path)
            )
            .increment(1);
            handler.handle_record(record, src).await;
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

    /// A byte budget with the same total capacity `run_with_listener` grants
    /// production connections — ample for any single-connection test below.
    fn full_byte_budget() -> Arc<Semaphore> {
        Arc::new(Semaphore::new(ZEEK_BYTE_BUDGET_PERMITS))
    }

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

    /// Guards the `path_was_missing` wiring end to end through a real socket:
    /// the counter must fire for an absent `_path` and must NOT fire for a
    /// record whose `_path` is literally the string "unknown".
    #[tokio::test]
    #[allow(clippy::mutable_key_type)] // false positive: CompositeKey AtomicBool is never hashed
    async fn missing_path_counter_fires_only_for_an_absent_path() {
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
            // TWO absent _path (must count) and ONE literal "unknown" (must
            // not). The 2:1 split is load-bearing: with a symmetric 1:1 mix an
            // inverted `if !parsed.path_was_missing` would also yield 1 and the
            // test would pass on the bug it exists to catch. Correct => 2,
            // inverted => 1, dropped => 0, double-increment => 4.
            // Not covered: moving the increment after handle_record, which
            // this aggregate assertion cannot see.
            s.write_all(
                b"{\"uid\":\"C1\"}\n\
                  {\"uid\":\"C2\"}\n\
                  {\"_path\":\"unknown\",\"uid\":\"C3\"}\n",
            )
            .await
            .unwrap();
            s.shutdown().await.unwrap();
        });

        let (stream, src) = listener.accept().await.unwrap();
        ZeekListener::handle_tcp_connection(
            stream,
            src,
            CapturingHandler::new(),
            TCP_IDLE_TIMEOUT,
            full_byte_budget(),
        )
        .await
        .unwrap();
        client.await.unwrap();

        let map = snapshotter.snapshot().into_hashmap();
        let missing = map
            .get(&CompositeKey::new(
                MetricKind::Counter,
                metrics::Key::from_name("zeek_missing_path"),
            ))
            .map(|(_, _, v)| match v {
                DebugValue::Counter(c) => *c,
                _ => 0,
            })
            .unwrap_or(0);
        assert_eq!(
            missing, 2,
            "two of the three records have an absent _path; a literal _path of \
             \"unknown\" is a present path and must not be counted. Got 1 => the \
             condition is inverted; got 0 => the increment was dropped."
        );
    }

    // -- Metrics: received counters fire for every handler --

    /// Regression: `zeek_records_received` / `zeek_records_by_path` used to be
    /// incremented inside `DefaultZeekHandler`, which `main.rs` only installs
    /// when NO forwarding destination is configured. Any real deployment wires
    /// a forwarding handler instead, so the counters never fired and never
    /// appeared on `/metrics`. They now live in the connection parse path, so
    /// they must be emitted with a non-default handler.
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
                    b"{\"_path\":\"conn\",\"uid\":\"C1\"}\n{\"_path\":\"dns\",\"uid\":\"C2\"}\n",
                )
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        });

        let (stream, src) = listener.accept().await.unwrap();
        let handler = CapturingHandler::new();
        ZeekListener::handle_tcp_connection(
            stream,
            src,
            handler.clone(),
            TCP_IDLE_TIMEOUT,
            full_byte_budget(),
        )
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
                metrics::Key::from_name("zeek_records_received"),
            )),
            2,
            "zeek_records_received must count every parsed record"
        );
        for path in ["conn", "dns"] {
            assert_eq!(
                read(CompositeKey::new(
                    MetricKind::Counter,
                    metrics::Key::from_parts(
                        "zeek_records_by_path",
                        vec![metrics::Label::new("log_path", path)],
                    ),
                )),
                1,
                "zeek_records_by_path{{log_path=\"{path}\"}} must be emitted"
            );
        }
    }

    // -- Shutdown-arm test --

    /// Firing the shutdown signal makes `start_with_shutdown` return cleanly
    /// within a short timeout (the shutdown arm of the select! is exercised).
    #[tokio::test]
    async fn start_with_shutdown_exits_on_signal() {
        use tokio::sync::watch;
        use tokio::time::timeout;

        // Bind briefly to get an ephemeral port, then drop so start_with_shutdown
        // can re-bind the same address.
        let tmp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = tmp.local_addr().unwrap().port();
        drop(tmp);

        let config = ZeekListenerConfig {
            tcp_port,
            bind_address: "127.0.0.1".to_string(),
        };
        let handler: Arc<dyn ZeekHandler> = Arc::new(DefaultZeekHandler);
        let listener = ZeekListener::new(config, handler);

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
            // Log-rotation boundary: shippers emit the rotated archive filename
            // as `_path`. Must normalize back to the stable stream name.
            r#"{"_path":"conn.2026-08-14-16-08-44","uid":"C3","ts":1700000002.0}"#,
            "\n",
        );
        stream.write_all(lines.as_bytes()).await.unwrap();
        drop(stream);

        sleep(Duration::from_millis(150)).await;
        task.abort();

        let records = handler.take_records();
        assert_eq!(
            records.len(),
            3,
            "expected 3 records, got {}",
            records.len()
        );
        assert_eq!(records[0].log_path, "conn");
        assert_eq!(records[1].log_path, "dns");
        assert_eq!(records[2].log_path, "conn");
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
    #[allow(clippy::mutable_key_type)] // clippy false positive: CompositeKey interior mutability (AtomicBool) is never used for hashing
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

    /// A source outside `allowed_ips` never reaches the handler.
    #[tokio::test]
    async fn with_allowed_ips_blocks_disallowed_source() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();
        let listener = ZeekListener::new(ZeekListenerConfig::default(), handler_clone)
            .with_allowed_ips(IpWhitelist::new(vec!["10.99.99.0/24".into()]).unwrap());

        let task = tokio::spawn(async move {
            listener.run_with_listener(tcp_listener).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _ = stream
            .write_all(b"{\"_path\":\"conn\",\"uid\":\"C1\"}\n")
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

    /// A source inside `allowed_ips` reaches the handler as normal.
    #[tokio::test]
    async fn with_allowed_ips_allows_whitelisted_source() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let handler = CapturingHandler::new();
        let handler_clone = handler.clone();
        let listener = ZeekListener::new(ZeekListenerConfig::default(), handler_clone)
            .with_allowed_ips(IpWhitelist::new(vec!["127.0.0.1".into()]).unwrap());

        let task = tokio::spawn(async move {
            listener.run_with_listener(tcp_listener).await.ok();
        });
        sleep(Duration::from_millis(20)).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"{\"_path\":\"conn\",\"uid\":\"C1\"}\n")
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
    /// elapses, incrementing `zeek_tcp_idle_timeouts` and dispatching no
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
        ZeekListener::handle_tcp_connection(
            stream,
            src,
            CapturingHandler::new(),
            Duration::from_millis(100),
            full_byte_budget(),
        )
        .await
        .unwrap();
        client.await.unwrap();

        let map = snapshotter.snapshot().into_hashmap();
        let count = map
            .get(&CompositeKey::new(
                MetricKind::Counter,
                metrics::Key::from_name("zeek_tcp_idle_timeouts"),
            ))
            .map(|(_, _, v)| match v {
                DebugValue::Counter(c) => *c,
                _ => 0,
            })
            .unwrap_or(0);
        assert_eq!(count, 1, "zeek_tcp_idle_timeouts must be 1; got {count}");
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

        // Client connects and sends nothing. Outer bound (8s) must exceed
        // the #[cfg(test)] TCP_IDLE_TIMEOUT (5s) with margin.
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 1];
        let result = tokio::time::timeout(Duration::from_secs(8), stream.read(&mut buf)).await;
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
                metrics::Key::from_name("zeek_tcp_idle_timeouts"),
            ))
            .map(|(_, _, v)| match v {
                DebugValue::Counter(c) => *c,
                _ => 0,
            })
            .unwrap_or(0);
        assert_eq!(
            count, 1,
            "zeek_tcp_idle_timeouts must be 1 when the accept loop's own \
             wiring times out the connection; got {count}"
        );
    }

    /// F8 regression, mirroring syslog's
    /// `tcp_parse_error_log_sanitizes_mid_line_cr_and_ansi_escape`: a TCP
    /// line that fails to parse as JSON and contains a *mid-line* `\r` and a
    /// mid-line ANSI escape (`\x1b`) must not carry either raw into the
    /// resulting `warn!` log line. `handle_tcp_connection`'s
    /// `read_until(b'\n', ...)` framing (plus the trailing-`\r`/`\n` pop just
    /// above the log call) only guarantees no *trailing* newline survives —
    /// it does nothing for control characters earlier in the line. Fails if
    /// the JSON-parse-error log site is reverted from `sanitize_for_log`
    /// back to `truncate_for_log`.
    ///
    /// Capture subscriber lives in `crate::test_support`, shared with the
    /// equivalent syslog/suricata tests — see that module's doc comment for
    /// why.
    #[tokio::test]
    async fn tcp_parse_error_log_sanitizes_mid_line_cr_and_ansi_escape() {
        crate::test_support::install_and_clear();

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server_stream, src) = tcp_listener.accept().await.unwrap();

        // Not valid JSON, so it reaches the JSON-parse-error warn! site. The
        // `\r` and `\x1b[31m` are both mid-line, not trailing, so the TCP
        // reader's newline framing does not touch them.
        let msg = b"not valid json\rzeek \x1b[31mline\n";
        client.write_all(msg).await.unwrap();
        drop(client); // close so the next read_until sees a clean EOF and returns

        let handler = CapturingHandler::new();
        ZeekListener::handle_tcp_connection(
            server_stream,
            src,
            handler,
            Duration::from_secs(5),
            full_byte_budget(),
        )
        .await
        .unwrap();

        let events = crate::test_support::captured_events();
        let warn_line = events
            .iter()
            .find(|m| m.contains("Zeek: JSON parse error"))
            .unwrap_or_else(|| panic!("no matching warn! event captured; got: {events:?}"));

        assert!(
            !warn_line.contains('\r'),
            "raw CR leaked into the log line: {warn_line:?}"
        );
        assert!(
            !warn_line.contains('\u{1b}'),
            "raw ESC leaked into the log line: {warn_line:?}"
        );
        assert!(
            warn_line.contains('\u{fffd}'),
            "expected U+FFFD replacement characters in the log line: {warn_line:?}"
        );
    }

    // -- Byte budget: bounds aggregate memory, not just per-connection --

    /// Proves the shared byte budget bounds AGGREGATE in-flight line-buffer memory across many
    /// connections — not merely that *some* cap exists.
    ///
    /// Sizing is deliberate: the 256 KiB (4-permit) budget is bigger than any single
    /// connection's 100 KiB payload, so no one connection can exhaust the budget alone — a
    /// regression to a *private per-connection* budget of this same size would send every
    /// connection through untouched and `zeek_tcp_budget_exhausted` would stay at 0, failing
    /// the assertion below. Only the SUM across all 6 connections (600 KiB) exceeds the 256 KiB
    /// budget, so exhaustion firing here is proof the budget is genuinely shared.
    #[tokio::test]
    #[allow(clippy::mutable_key_type)] // false positive: CompositeKey AtomicBool is never hashed
    async fn byte_budget_caps_aggregate_memory_across_connections() {
        use metrics::set_default_local_recorder;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::{CompositeKey, MetricKind};
        use tokio::time::timeout;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        // 4 permits * ZEEK_BUDGET_CHUNK_BYTES (64 KiB) = 256 KiB, shared by every connection
        // spawned below.
        let byte_budget = Arc::new(Semaphore::new(4));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        const CONNS: usize = 6;
        // 100 KiB per connection: comfortably under the 256 KiB budget on its own (so a
        // per-connection-budget regression would NOT trip this), but 6 * 100 KiB = 600 KiB
        // comfortably over it (so the shared budget must).
        const PAYLOAD_BYTES: usize = 100 * 1024;
        let mut clients = Vec::new();
        for _ in 0..CONNS {
            clients.push(tokio::spawn(async move {
                let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
                let payload = vec![b'x'; PAYLOAD_BYTES]; // no newline
                let _ = stream.write_all(&payload).await;
                let mut sink = Vec::new();
                let _ = timeout(Duration::from_secs(5), stream.read_to_end(&mut sink)).await;
            }));
        }

        let mut servers = Vec::new();
        for _ in 0..CONNS {
            let (stream, src) = listener.accept().await.unwrap();
            let handler = CapturingHandler::new();
            let budget = byte_budget.clone();
            servers.push(tokio::spawn(async move {
                ZeekListener::handle_tcp_connection(stream, src, handler, TCP_IDLE_TIMEOUT, budget)
                    .await
            }));
        }

        for s in servers {
            let _ = timeout(Duration::from_secs(5), s).await;
        }
        for c in clients {
            let _ = c.await;
        }

        let map = snapshotter.snapshot().into_hashmap();
        let exhausted = map
            .get(&CompositeKey::new(
                MetricKind::Counter,
                metrics::Key::from_name("zeek_tcp_budget_exhausted"),
            ))
            .map(|(_, _, v)| match v {
                DebugValue::Counter(c) => *c,
                _ => 0,
            })
            .unwrap_or(0);
        assert!(
            exhausted >= 1,
            "shared budget must reject at least one connection once aggregate demand exceeds \
             the budget; got {exhausted} (unbounded-growth regression if 0)"
        );
    }

    /// A normal-sized line is entirely unaffected by the byte-budget machinery: a single small
    /// connection sharing a budget with plenty of headroom still gets its record dispatched.
    #[tokio::test]
    async fn byte_budget_does_not_affect_normal_sized_lines() {
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
            .write_all(b"{\"_path\":\"conn\",\"uid\":\"C1\"}\n")
            .await
            .unwrap();
        drop(stream);

        sleep(Duration::from_millis(150)).await;
        task.abort();

        let records = handler.take_records();
        assert_eq!(records.len(), 1, "normal line must still be dispatched");
        assert_eq!(records[0].log_path, "conn");
    }

    /// F6-adjacent regression: a client that writes its final record WITHOUT a trailing
    /// newline and then closes (an entirely ordinary TCP close, or a killed process) must
    /// still have that record parsed and dispatched — matching `read_until`'s original
    /// contract, where EOF mid-line returns `Ok(n)` with the accumulated bytes rather than
    /// `Ok(0)`. The fill_buf/consume rewrite must preserve that: only a *clean* EOF (nothing
    /// accumulated yet) should silently end the connection.
    #[tokio::test]
    async fn unterminated_final_line_is_dispatched_on_eof() {
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
        // No trailing '\n' — the record is complete but the stream simply ends here.
        stream
            .write_all(b"{\"_path\":\"conn\",\"uid\":\"NoTrailingNewline\"}")
            .await
            .unwrap();
        drop(stream); // close write half -> EOF with a non-empty partial line buffered

        sleep(Duration::from_millis(150)).await;
        task.abort();

        let records = handler.take_records();
        assert_eq!(
            records.len(),
            1,
            "a final record with no trailing newline must still be parsed and dispatched on EOF"
        );
        assert_eq!(records[0].log_path, "conn");
    }

    // -- Capacity retention: a huge line must not hold its allocation forever --

    #[test]
    fn shrink_oversized_buffer_releases_large_capacity() {
        let mut buf: Vec<u8> = Vec::with_capacity(ZEEK_MAX_LINE_BYTES);
        buf.extend(std::iter::repeat_n(0u8, 1024));
        buf.clear();
        assert!(buf.capacity() > ZEEK_BUF_SHRINK_THRESHOLD_BYTES);

        shrink_oversized_buffer(&mut buf);

        assert!(
            buf.capacity() <= ZEEK_BUF_SHRINK_THRESHOLD_BYTES,
            "a cleared buffer that once held a huge line must have its capacity released; \
             got {}",
            buf.capacity()
        );
    }

    #[test]
    fn shrink_oversized_buffer_leaves_small_capacity_alone() {
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        let cap_before = buf.capacity();
        shrink_oversized_buffer(&mut buf);
        assert_eq!(
            buf.capacity(),
            cap_before,
            "capacity below the threshold must not be touched"
        );
    }

    /// `DefaultZeekHandler` is wired in whenever no forwarding destination is
    /// configured (`main.rs`), so its `info!` line is reachable in production
    /// without auth. `log_path` comes straight from the wire (`_path`) and
    /// was never bounded or sanitized before reaching that line. Uses the
    /// shared `test_support` capture subscriber (see its doc comment).
    #[tokio::test]
    async fn default_handler_log_sanitizes_log_path() {
        crate::test_support::install_and_clear();

        let record = ZeekRecord {
            log_path: "conn\rFAKE\n\u{1b}[31minjected\u{1b}[0m".to_string(),
            fields: serde_json::json!({"_path": "conn"}),
            received_at: chrono::Utc::now(),
        };
        let source: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        DefaultZeekHandler.handle_record(record, source).await;

        let events = crate::test_support::captured_events();
        let line = events
            .iter()
            .find(|m| m.contains("zeek record"))
            .unwrap_or_else(|| panic!("no matching info! event captured; got: {events:?}"));

        assert!(
            !line.contains('\r'),
            "raw CR leaked into the log line: {line:?}"
        );
        assert!(
            !line.contains('\n'),
            "raw LF leaked into the log line: {line:?}"
        );
        assert!(
            !line.contains('\u{1b}'),
            "raw ESC leaked into the log line: {line:?}"
        );
        assert!(
            line.contains('\u{fffd}'),
            "expected U+FFFD replacement characters in the log line: {line:?}"
        );
    }
}
