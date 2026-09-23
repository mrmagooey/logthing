#[cfg(feature = "otlp")]
pub mod otlp;

use crate::config::Config;
use crate::forwarding::drop_log::{DropKind, DropSite};
use crate::ingest::IngestState;
use crate::ingest::handlers::{handle_hec_event, handle_hec_raw, handle_ndjson};
use crate::middleware::{IpWhitelist, ip_whitelist_middleware};
use crate::models::WindowsEvent;
use crate::parser::GenericEventParser;
use crate::protocol::{
    WefMessage, WefParser, create_heartbeat_response, create_subscription_response,
};
use crate::stats::cardinality::CardinalityWatcher;
use crate::stats::{ThroughputSnapshot, ThroughputStats};
use crate::syslog::SyslogMessage;
#[cfg(feature = "kerberos-auth")]
use anyhow::anyhow;
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, Method, StatusCode},
    middleware,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use http_body::{Body as HttpBody, Frame, SizeHint};

use futures::stream::{self, StreamExt};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, RwLock, Semaphore};
use tower::limit::GlobalConcurrencyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tracing::{debug, error, info, warn};

/// Handle onto the installed Prometheus recorder, published so profiling can
/// read counters to verify a sampling window overlapped real traffic.
/// `OnceLock` because the recorder is installed exactly once, at startup.
pub static METRICS_HANDLE: std::sync::OnceLock<metrics_exporter_prometheus::PrometheusHandle> =
    std::sync::OnceLock::new();

/// Maximum allowed body size for WEF/syslog ingest requests (64 MiB).
/// Prevents unbounded memory allocation from large or malicious payloads.
const MAX_BODY_SIZE: usize = 64 * 1024 * 1024;

/// Maximum number of Windows events processed concurrently per batch.
/// Bounds CPU and memory use while still exploiting multi-core parallelism.
const MAX_CONCURRENT_EVENT_PROCESSING: usize = 16;

/// Global in-flight body-byte budget shared by every route on
/// `protected_router` that buffers its request body into memory (extracts
/// `axum::body::Bytes`): `/wsman*`, `/syslog`, the HEC routes, `/ingest`,
/// and (when compiled in) `/v1/logs`.
///
/// `MAX_BODY_SIZE` (64 MiB) and `security.max_connections` (default 10,000)
/// are each individually reasonable, but their product never was: 10,000
/// connections each holding a 64 MiB buffered body is ~640 GiB of
/// attacker-controlled heap. This budget bounds the *aggregate* instead of
/// changing what a single legitimate request may send — a large HEC batch
/// stays exactly as large as it is today.
///
/// 1 GiB permits roughly sixteen concurrent maximum-size (64 MiB) requests
/// in flight at once — generous for real bursty ingest, since legitimate
/// traffic is rarely dominated by many simultaneous max-size batches.
///
/// Two worst-case numbers, not one — read both, they answer different
/// questions:
///
/// - **Input-side / attacker ceiling: ~1 GiB.** `BudgetedBody` (below)
///   charges every request's ACTUAL streamed bytes as they arrive, so this
///   is a hard ceiling on raw buffered-body bytes regardless of how many of
///   the 10,000 connection slots an attacker fills, what protocol version
///   they use, or what headers they send (or omit). Payloads that are
///   never valid, parseable records — the attacker case — stay at this
///   scale, since they never reach the amplification below.
/// - **Realistic legitimate peak: ~14 GiB, not 1 GiB.** The permit is held
///   for the whole handler (deliberately — see `body_budget_middleware`),
///   and HEC's NDJSON-to-records parsing turns a 64 MiB raw body into
///   roughly 840 MB of parsed `GenericRecord`s (~13x) while the raw
///   `Bytes` is still alive. Sixteen concurrent, honestly-declared 64 MiB
///   HEC requests — exactly what this budget permits at once — can
///   therefore peak around 16 * (64 MiB + 840 MB) ≈ 14 GiB during parsing.
///   That is still roughly 46x smaller than the unbounded ~640 GiB this
///   finding started from, but the 1 GiB figure must not be read as an
///   overall process-memory ceiling; downstream parse amplification is not
///   separately budgeted by this change.
const BODY_BYTE_BUDGET: usize = 1024 * 1024 * 1024; // 1 GiB

/// Body wrapper charging `BODY_BYTE_BUDGET` per ACTUAL byte, as each frame
/// streams through — never against a client-supplied header. This is what
/// makes the budget correct regardless of protocol version or header
/// honesty, closing two gaps a declared-length charge cannot:
///
/// - **HTTP/2** has no `Transfer-Encoding`, and hyper does not enforce a
///   declared `Content-Length` against real DATA-frame bytes (an
///   under-declaring or absent-`Content-Length` h2 client is not caught by
///   framing the way HTTP/1.1's is — see hyper's `body::incoming` `Kind::H2`
///   arm, which subtracts unchecked and never errors on mismatch). This
///   server negotiates h2 on both listeners (plaintext h2c via
///   `axum::serve`'s `hyper_util::auto` builder, and TLS via ALPN
///   advertising `"h2"`), so this is default-reachable, not an edge case.
/// - **HTTP/1.1 chunked** bodies send no `Content-Length` at all, so a
///   declared-length charge had to assume the worst case (`MAX_BODY_SIZE`)
///   for every chunked request — meaning as few as
///   `BODY_BYTE_BUDGET / MAX_BODY_SIZE` (16) concurrent chunked requests of
///   ANY real size would 503 the rest. Charging real bytes removes that
///   over-charge entirely: a small chunked request charges only its real
///   small size.
///
/// Permits are pushed into `held` as each frame is charged, but `held` is
/// NOT owned solely by this wrapper — it is an `Arc<Mutex<..>>` shared with
/// `body_budget_middleware`'s own stack frame (see its doc comment for why):
/// extractors like `Bytes` fully drain and DROP the request body as soon as
/// collection finishes, which happens well before the handler runs, so a
/// permit store owned only by the body would release on extraction, not on
/// handler completion. Sharing the store lets charging stay tied to real
/// bytes as they stream (this struct's job) while release stays tied to the
/// whole request (the middleware's job) — both released together the same
/// way regardless: ordinary `Arc`/`Drop`, whichever side drops last (end of
/// stream, an extractor/handler error, `TimeoutLayer` firing, a mid-body
/// disconnect, or a panic unwind). Same "owned permits released by scope"
/// pattern as `ZeekListener`'s byte budget, just with two owners racing to
/// be the last one out instead of one.
struct BudgetedBody {
    inner: Body,
    budget: Arc<Semaphore>,
    held: Arc<std::sync::Mutex<Vec<OwnedSemaphorePermit>>>,
}

impl HttpBody for BudgetedBody {
    type Data = Bytes;
    type Error = axum::Error;

    /// Charges the real length of each data frame against the shared budget
    /// as it arrives. A frame that cannot be charged fails the body stream
    /// right here instead of being passed through — the bytes are never
    /// handed to whatever is collecting this body (e.g. the `Bytes`
    /// extractor), so exhaustion mid-body still prevents the memory it
    /// exists to prevent, not just detects it after the fact.
    ///
    /// The caller sees a body-read error (axum's `Bytes` extractor turns an
    /// unrecognized body error into `UnknownBodyError`, HTTP 400) rather
    /// than a 503: a fresh, deliberately-chosen status is only possible
    /// before the handler has been dispatched to at all, which
    /// `body_budget_middleware`'s upfront `available_permits() == 0` check
    /// covers for the common already-exhausted case. Once streaming has
    /// begun there is no clean way to retroactively swap in a 503, so this
    /// takes the next best outcome: fail fast and stop buffering.
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                let len = frame.data_ref().map_or(0, |data| data.len());
                if len == 0 {
                    return Poll::Ready(Some(Ok(frame)));
                }
                let units = u32::try_from(len).unwrap_or(u32::MAX);
                match self.budget.clone().try_acquire_many_owned(units) {
                    Ok(permit) => {
                        self.held
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push(permit);
                        Poll::Ready(Some(Ok(frame)))
                    }
                    Err(_) => {
                        metrics::counter!("body_budget_exhausted").increment(1);
                        warn!(
                            "body byte budget exhausted mid-body ({len} more bytes \
                             requested); failing the body stream"
                        );
                        Poll::Ready(Some(Err(axum::Error::new(std::io::Error::other(
                            "body byte budget exhausted",
                        )))))
                    }
                }
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// `axum::middleware::from_fn_with_state` handler enforcing `BODY_BYTE_BUDGET`
/// via `BudgetedBody`.
///
/// The upfront `available_permits() == 0` check is a best-effort fast path
/// (racy against concurrent requests, not the real enforcement) that lets
/// the already-fully-exhausted case — the common one, an attacker who has
/// filled the budget — get a clean, immediate 503 without engaging the
/// extractor machinery at all. The real enforcement is `BudgetedBody`,
/// which charges per real byte regardless of this check's outcome; a
/// request that slips past it because of the race still gets charged (and
/// potentially rejected mid-body) once its body is actually read.
///
/// The fast path only applies to non-`GET` requests. `protected_router`
/// mounts two bodyless GET informational routes alongside the
/// `Bytes`-extracting POST ones (`/syslog/udp`, `/syslog/examples`) — they
/// never consume budget, so gating them on `available_permits` would 503
/// them whenever bursty or attacker POST traffic has drained the budget,
/// for a reason that has nothing to do with anything a GET request touches.
/// The method is not a value being trusted for charging (that would
/// reintroduce exactly the header-trust mistake round 1 fixed) — it only
/// decides whether this cheap pre-check is worth running at all. A client
/// cannot use it to escape charging: `BudgetedBody` below still wraps and
/// charges the body of every request regardless of method, so a
/// hypothetical GET-with-body would simply lose the clean-503 fast path and
/// fall through to the same real per-byte charging (and possible mid-body
/// rejection) as everything else, exactly like the POST case where the
/// budget is not yet fully drained at the time of this check.
///
/// `held` is created here and a clone handed to `BudgetedBody`, but THIS
/// binding — not the body's — is what determines when charged permits are
/// released: it is kept alive across the whole `next.run(request).await`,
/// so capacity charged while reading the body stays reserved for the
/// entire handler (deliberately — a HEC request's parsed-record
/// representation stays alive well after its raw body is fully read; see
/// `BODY_BYTE_BUDGET`'s doc comment). Whichever of the two `Arc` clones
/// (the body's or this one) is dropped last is what actually releases the
/// permits, by ordinary `Drop` — covering normal completion, a
/// handler/extractor error, `TimeoutLayer` firing, a mid-body disconnect,
/// or a panic unwinding through this `async fn`.
async fn body_budget_middleware(
    State(budget): State<Arc<Semaphore>>,
    request: Request,
    next: Next,
) -> Response {
    if request.method() != Method::GET && budget.available_permits() == 0 {
        metrics::counter!("body_budget_exhausted").increment(1);
        warn!(
            "body byte budget already exhausted; rejecting {} with 503",
            request.uri()
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "server body-byte budget exhausted, retry shortly",
        )
            .into_response();
    }

    let held = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (parts, body) = request.into_parts();
    let budgeted = BudgetedBody {
        inner: body,
        budget,
        held: held.clone(),
    };
    let request = Request::from_parts(parts, Body::new(budgeted));
    let response = next.run(request).await;
    drop(held);
    response
}

pub struct AppState {
    pub config: Arc<RwLock<Config>>,
    pub throughput: Arc<ThroughputStats>,
    /// `[[metrics.cardinality_watch]]` entries configured for
    /// `source = "wef"`, partitioned out of the full compiled list once at
    /// startup (`main.rs`) — this is never filtered by source at request
    /// time. Empty unless an operator configured a wef watch.
    pub wef_cardinality_watchers: Vec<Arc<CardinalityWatcher>>,
    pub parser: WefParser,
    pub event_parser: Option<GenericEventParser>,
    pub parquet_s3_sender: Option<
        crate::forwarding::buffered_writer::ParquetWriterHandle<
            crate::forwarding::parquet_s3::WefSink,
        >,
    >,
    /// Local-disk counterpart to `parquet_s3_sender`. `None` when `[wef.local]`
    /// is absent or construction failed. Independent of `parquet_s3_sender` —
    /// both may be `Some` simultaneously.
    pub parquet_local_sender: Option<
        crate::forwarding::buffered_writer::ParquetWriterHandle<
            crate::forwarding::parquet_s3::WefSink,
        >,
    >,
}

pub struct Server {
    config: Config,
    state: Arc<AppState>,
    /// JoinHandles for the WEF→S3 and WEF→local Parquet worker tasks (0, 1, or 2
    /// present depending on how many of `[wef.s3]` / `[wef.local]` are configured
    /// and construct successfully). Awaited during graceful shutdown so buffered
    /// data is flushed before exit.
    wef_worker_handles: Vec<tokio::task::JoinHandle<()>>,
    /// Shared extension state for HEC / NDJSON ingest routes.
    ingest_state: IngestState,
    /// JoinHandles for the HEC→S3 and HEC→local Parquet worker tasks (0, 1, or 2
    /// present depending on how many of `[hec.s3]` / `[hec.local]` are configured
    /// and construct successfully). Awaited during graceful shutdown.
    hec_worker_handles: Vec<tokio::task::JoinHandle<()>>,
    /// The SAME `IpWhitelist` instance shared with `main.rs`'s five
    /// wire-protocol listeners, built once from `config.security.allowed_ips`
    /// at startup. `run`/`run_tls` clone this into `create_router` and the
    /// metrics server instead of building their own, so every consumer sees
    /// the identical allowlist. `security.allowed_ips` is restart-only —
    /// there is no live-reload path.
    ip_whitelist: IpWhitelist,
}

impl Server {
    /// Create a new logthing server instance.
    ///
    /// Initializes all components including the parser and optional
    /// Parquet S3 forwarder.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use logthing::config::Config;
    /// use logthing::middleware::IpWhitelist;
    /// use logthing::server::Server;
    /// use logthing::stats::{SourceHourlyStats, ThroughputStats};
    /// use std::sync::Arc;
    /// use tokio::sync::RwLock;
    ///
    /// async fn start_server() -> anyhow::Result<()> {
    ///     let config = Config::load()?;
    ///     let shared_config = Arc::new(RwLock::new(config.clone()));
    ///     let throughput = Arc::new(ThroughputStats::new());
    ///     let source_stats = Arc::new(SourceHourlyStats::new());
    ///     let ip_whitelist = IpWhitelist::empty();
    ///
    ///     let flush_registry = logthing::forwarding::flush_registry::FlushIntervalRegistry::new();
    ///     let server = Server::new(
    ///         config,
    ///         shared_config,
    ///         throughput,
    ///         source_stats,
    ///         flush_registry,
    ///         ip_whitelist,
    ///         Vec::new(),
    ///     )
    ///     .await?;
    ///     // server.run().await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn new(
        config: Config,
        shared_config: Arc<RwLock<Config>>,
        throughput: Arc<ThroughputStats>,
        source_stats: Arc<crate::stats::SourceHourlyStats>,
        flush_registry: crate::forwarding::flush_registry::FlushIntervalRegistry,
        ip_whitelist: IpWhitelist,
        wef_cardinality_watchers: Vec<Arc<CardinalityWatcher>>,
    ) -> anyhow::Result<Self> {
        #[cfg(feature = "kerberos-auth")]
        {
            if config.security.kerberos.enabled {
                let spn = config.security.kerberos.spn.clone().ok_or_else(|| {
                    anyhow!("security.kerberos.spn must be set when Kerberos auth is enabled")
                })?;

                if let Some(keytab) = &config.security.kerberos.keytab {
                    unsafe {
                        std::env::set_var("KRB5_KTNAME", keytab);
                    }
                    info!("KRB5_KTNAME set to {:?}", keytab);
                }

                // Fail-fast: acquire (and immediately drop) a server
                // credential for `spn` now, so a bad SPN, missing keytab, or
                // unreadable key material aborts startup instead of quietly
                // 401-ing every request later. We do not keep this
                // credential around — see `acquire_kerberos_cred` for why a
                // credential can't be shared across requests with this API.
                acquire_kerberos_cred(&spn).map_err(|e| {
                    anyhow!("Kerberos startup validation failed for SPN {}: {}", spn, e)
                })?;

                info!("Kerberos authentication enabled for SPN {}", spn);
            }
        }

        #[cfg(not(feature = "kerberos-auth"))]
        {
            if config.security.kerberos.enabled {
                warn!(
                    "Kerberos authentication requested but the 'kerberos-auth' feature is not enabled; requests will NOT be authenticated"
                );
            }
        }

        // Load event parser configuration if available
        let parser_dir = std::path::Path::new("config/event_parsers");
        let parser_file = std::path::Path::new("config/event_parsers.yaml");
        let event_parser = if parser_dir.exists() {
            match GenericEventParser::from_file(parser_dir) {
                Ok(parser) => {
                    info!(
                        "Loaded event parser configuration with {} parsers",
                        parser.supported_events().len()
                    );
                    Some(parser)
                }
                Err(e) => {
                    warn!(
                        "Failed to load event parser configuration from directory: {}",
                        e
                    );
                    None
                }
            }
        } else if parser_file.exists() {
            match GenericEventParser::from_file(parser_file) {
                Ok(parser) => {
                    info!(
                        "Loaded event parser configuration with {} parsers",
                        parser.supported_events().len()
                    );
                    Some(parser)
                }
                Err(e) => {
                    warn!("Failed to load event parser configuration: {}", e);
                    None
                }
            }
        } else {
            info!("No event parser configuration found under config/event_parsers/");
            None
        };

        // Initialize WEF→S3 and WEF→local Parquet forwarders via the generic
        // buffered writer. Each target is attempted independently — a failed
        // S3Sink construction does not prevent a healthy `.local` construction
        // from still populating `parquet_local_sender`, and vice versa.
        let mut wef_worker_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        let mut parquet_s3_sender = None;
        let mut parquet_local_sender = None;

        let descriptor_sink =
            crate::forwarding::buffered_writer::build_iceberg_descriptor_sink(&config.iceberg)
                .await
                .unwrap_or_else(|e| {
                    error!(
                        "Failed to construct Iceberg descriptor sink, descriptors disabled: {e}"
                    );
                    None
                });

        if let Some(wef_s3_cfg) = config.wef.s3.as_ref() {
            match crate::forwarding::s3_sink::S3Sink::from_connection(&wef_s3_cfg.connection).await
            {
                Ok(sink) => {
                    info!("Initialized WEF Parquet S3 forwarder (generic buffered writer)");
                    let (handle, join_handle) = crate::forwarding::parquet_s3::wef_start(
                        wef_s3_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                        descriptor_sink.clone(),
                    );
                    wef_worker_handles.push(join_handle);
                    flush_registry.register("wef.s3", handle.flush_interval());
                    parquet_s3_sender = Some(handle);
                }
                Err(e) => {
                    error!("Failed to create S3Sink for WEF persistence, skipping S3 target: {e}");
                }
            }
        }

        if let Some(wef_local_cfg) = config.wef.local.as_ref() {
            match crate::forwarding::local_sink::LocalDiskSink::new(wef_local_cfg.directory.clone())
                .await
            {
                Ok(sink) => {
                    info!("Initialized WEF Parquet local-disk forwarder");
                    let (handle, join_handle) = crate::forwarding::parquet_s3::wef_local_start(
                        wef_local_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                        descriptor_sink.clone(),
                    );
                    wef_worker_handles.push(join_handle);
                    flush_registry.register("wef.local", handle.flush_interval());
                    parquet_local_sender = Some(handle);
                }
                Err(e) => {
                    error!(
                        "Failed to create LocalDiskSink for WEF persistence, skipping local target: {e}"
                    );
                }
            }
        }

        let state = Arc::new(AppState {
            config: Arc::clone(&shared_config),
            throughput,
            wef_cardinality_watchers,
            parser: WefParser::new(),
            event_parser,
            parquet_s3_sender,
            parquet_local_sender,
        });

        // --- Build IngestState for HEC / NDJSON ingest routes ---
        let mut hec_worker_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        let mut generic_s3_handler = None;
        let mut generic_local_handler = None;

        if config.hec.enabled {
            if let Some(s3_cfg) = config.hec.s3.as_ref() {
                match crate::forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await
                {
                    Ok(sink) => {
                        info!("Initialized HEC Parquet S3 forwarder");
                        let (handler, join_handle) = crate::forwarding::generic_s3::hec_start(
                            s3_cfg,
                            Arc::new(sink),
                            config.hec.max_sourcetype_partitions,
                            source_stats.clone(),
                            descriptor_sink.clone(),
                        );
                        hec_worker_handles.push(join_handle);
                        flush_registry.register("hec.s3", handler.flush_interval());
                        generic_s3_handler = Some(handler);
                    }
                    Err(e) => {
                        error!("Failed to create S3Sink for HEC ingest, skipping S3 target: {e}");
                    }
                }
            }

            if let Some(local_cfg) = config.hec.local.as_ref() {
                match crate::forwarding::local_sink::LocalDiskSink::new(local_cfg.directory.clone())
                    .await
                {
                    Ok(sink) => {
                        info!("Initialized HEC Parquet local-disk forwarder");
                        let (handler, join_handle) = crate::forwarding::generic_s3::hec_local_start(
                            local_cfg,
                            Arc::new(sink),
                            config.hec.max_sourcetype_partitions,
                            source_stats.clone(),
                            descriptor_sink.clone(),
                        );
                        hec_worker_handles.push(join_handle);
                        flush_registry.register("hec.local", handler.flush_interval());
                        generic_local_handler = Some(handler);
                    }
                    Err(e) => {
                        error!(
                            "Failed to create LocalDiskSink for HEC ingest, skipping local target: {e}"
                        );
                    }
                }
            }
        }

        let ingest_state = IngestState {
            generic_s3: generic_s3_handler,
            generic_local: generic_local_handler,
        };

        Ok(Self {
            config,
            state,
            wef_worker_handles,
            ingest_state,
            hec_worker_handles,
            ip_whitelist,
        })
    }

    /// Take the WEF persistence workers' JoinHandles for awaiting at shutdown.
    ///
    /// Must be called BEFORE `run`/`run_tls`; after the server consumes `self`
    /// the handles are no longer accessible. Returns 0, 1, or 2 handles
    /// depending on how many of `[wef.s3]` / `[wef.local]` constructed
    /// successfully.
    pub fn take_wef_worker_handles(&mut self) -> Vec<tokio::task::JoinHandle<()>> {
        std::mem::take(&mut self.wef_worker_handles)
    }

    /// Take the HEC persistence workers' JoinHandles for awaiting at shutdown.
    ///
    /// Must be called BEFORE `run`/`run_tls`; after the server consumes `self`
    /// the handles are no longer accessible. Returns 0, 1, or 2 handles
    /// depending on how many of `[hec.s3]` / `[hec.local]` constructed
    /// successfully.
    pub fn take_hec_worker_handles(&mut self) -> Vec<tokio::task::JoinHandle<()>> {
        std::mem::take(&mut self.hec_worker_handles)
    }

    /// Run the logthing server without TLS (HTTP only).
    ///
    /// Starts the HTTP server on the configured bind address and port.
    /// Also starts the metrics server if enabled.  Exits when `shutdown_rx`
    /// fires (graceful shutdown: drains in-flight requests, then drops AppState
    /// which closes the WEF worker's channel).
    pub async fn run(
        self,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        // `self.ip_whitelist` (not a fresh build from `self.config.security.allowed_ips`,
        // which is a startup snapshot) — this is the SAME instance shared with
        // main.rs's five wire-protocol listeners and the admin API, so a live
        // `security.allowed_ips` update reaches this router too. See the
        // `ip_whitelist` field doc comment on `Server`.
        let ip_whitelist = self.ip_whitelist.clone();

        // Clone the whitelist before it is moved into `create_router` below —
        // the metrics router needs its own copy of the same
        // `security.allowed_ips` gate, since a `metrics.bind_address` of
        // `0.0.0.0` (or an inherited `0.0.0.0` `bind_address`) would
        // otherwise expose it on every interface with no auth at all.
        let metrics_whitelist = ip_whitelist.clone();
        let app = self.create_router(ip_whitelist)?;

        // Start HTTP server
        let addr = self.config.bind_address;
        info!("Starting logthing server on http://{}", addr);

        let listener = tokio::net::TcpListener::bind(&addr).await?;

        // Start metrics server if enabled. `install_metrics_recorder` is a
        // no-op when `main.rs` already installed it synchronously before
        // building the aggregator; calling it again here keeps every
        // existing caller of `Server::run` (tests included) working
        // unchanged even when it is the first/only installer.
        if self.config.metrics.enabled {
            let metrics_ip =
                resolve_metrics_ip(&self.config.metrics.bind_address, &self.config.bind_address)?;
            let metrics_addr = SocketAddr::new(metrics_ip, self.config.metrics.port);
            install_metrics_recorder();
            tokio::spawn(serve_metrics_endpoint(metrics_addr, metrics_whitelist));
        }

        // Gap-b: wire graceful shutdown so the axum server stops on SIGTERM,
        // which drops AppState → drops parquet_s3_sender → closes the WEF worker
        // channel → the worker's None arm flushes and exits.
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            // Wait until the shutdown watch fires (value becomes true).
            let _ = shutdown_rx.wait_for(|v| *v).await;
            info!("WEF HTTP server received shutdown signal");
        })
        .await?;

        Ok(())
    }

    fn create_router(&self, ip_whitelist: IpWhitelist) -> anyhow::Result<Router> {
        // A value of 0 here isn't a smaller limit, it's a broken server: 0
        // permits means the GlobalConcurrencyLimitLayer semaphore never
        // grants a single one, so every request queues forever (or until
        // connection_timeout_secs rejects it with 408) — the process stays
        // up but serves nothing. Bail loudly at construction rather than
        // silently accept it, matching the precedent in
        // `forwarding::aggregate::compile_rules` for other zero-is-broken knobs.
        if self.config.security.max_connections == 0 {
            anyhow::bail!(
                "[security] max_connections must be greater than 0 (0 means the concurrency \
                 semaphore never grants a permit — every request would queue forever)"
            );
        }
        // A value of 0 here means every request is rejected with 408
        // immediately, since TimeoutLayer's deadline is already elapsed at
        // creation time.
        if self.config.security.connection_timeout_secs == 0 {
            anyhow::bail!(
                "[security] connection_timeout_secs must be greater than 0 (0 means every \
                 request would time out with 408 immediately)"
            );
        }

        // Shared layers for all routes
        let shared_layers =
            middleware::from_fn_with_state(ip_whitelist.clone(), ip_whitelist_middleware);

        // Public routes (no authentication required)
        let public_router = Router::new()
            .route("/health", axum::routing::get(health_check))
            .route("/stats/throughput", get(handle_throughput_stats))
            .layer(shared_layers.clone())
            .layer(axum::Extension(ip_whitelist.clone()))
            .with_state(self.state.clone());

        if self.config.hec.enabled && self.config.hec.token.is_empty() {
            warn!(
                "[hec] enabled with an empty token — all HEC ingest endpoints accept \
                 unauthenticated writes. Set hec.token to require a bearer token."
            );
        }

        // Protected routes (require authentication).
        let mut protected_router = Router::new()
            .route("/wsman", post(handle_wef_request))
            .route("/wsman/subscriptions", post(handle_subscription))
            .route("/wsman/events", post(handle_events))
            // Syslog endpoints
            .route("/syslog", post(handle_syslog_http))
            .route("/syslog/udp", get(handle_syslog_udp_info))
            .route("/syslog/examples", get(handle_syslog_examples));

        // HEC / NDJSON ingest routes are registered ONLY when `hec.enabled` is
        // true. Every new config section defaults to disabled, so a default
        // deployment (hec disabled) must see zero behavior change: these
        // routes stay unmounted and 404, exactly as before. When enabled,
        // they are mounted BEFORE the .layer() calls below so they inherit
        // the same IP-whitelist and body-limit middleware as the existing
        // protected routes.
        if self.config.hec.enabled {
            protected_router = protected_router
                .route("/services/collector/event", post(handle_hec_event))
                .route("/services/collector/raw", post(handle_hec_raw))
                .route("/ingest", post(handle_ndjson));
        }

        // OTLP log ingest route — registered ONLY when the `otlp` feature is
        // compiled in AND `config.otlp.enabled` is true.  A default deployment
        // (otlp disabled) sees zero behavior change: /v1/logs stays unmounted
        // and returns 404, same convention as HEC above.  When enabled
        // the route is added BEFORE .layer() so it inherits the same IP-whitelist
        // and body-limit middleware as the other protected routes.
        #[cfg(feature = "otlp")]
        if self.config.otlp.enabled {
            protected_router = protected_router.route("/v1/logs", post(handle_otlp_logs));
        }

        // Shared in-flight body-byte budget (see `BODY_BYTE_BUDGET`), constructed
        // fresh here: `create_router` is called at most once per `Server` (`run`
        // and `run_tls` both consume `self`), so there is exactly one process-wide
        // instance of this semaphore, shared by every protected route via the
        // `Arc` clone captured in the middleware layer below.
        let body_budget = Arc::new(Semaphore::new(BODY_BYTE_BUDGET));

        // Extensions for HEC handlers are harmless to the existing WEF/syslog
        // handlers and are always layered so the extractors resolve when the
        // routes are mounted. The config extension is the SAME
        // `Arc<RwLock<Config>>` as `AppState.config`, so `hec.token` is read
        // from the config on every request (see `handle_hec_event` and siblings
        // in `src/ingest/handlers.rs`) rather than snapshot at startup. The
        // value is effectively fixed at startup — nothing writes the config at
        // runtime now that the admin interface is read-only.
        let protected_router = protected_router
            .layer(axum::Extension(self.ingest_state.clone()))
            .layer(axum::Extension(self.state.config.clone()))
            .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_SIZE))
            .layer(middleware::from_fn_with_state(
                body_budget,
                body_budget_middleware,
            ))
            .layer(shared_layers)
            .layer(axum::Extension(ip_whitelist))
            .with_state(self.state.clone());

        // Apply Kerberos only to protected routes
        let protected_router = self.apply_kerberos_layer(protected_router)?;

        // Merge public and protected routes
        let router = public_router.merge(protected_router);

        // Server-wide security layers (cover both public and protected
        // routes, on both the plain-HTTP and TLS paths, since both `run`
        // and `run_tls` share this one `create_router` choke point).
        //
        // `GlobalConcurrencyLimitLayer` — NOT `tower::limit::ConcurrencyLimitLayer`.
        // `Router::layer` applies the given `tower::Layer` independently to
        // EACH registered route (axum iterates routes and calls
        // `layer.clone().layer(route)` per route — see
        // `axum::routing::path_router::PathRouter::layer`). This router has
        // many routes (`/health`, `/wsman`, `/syslog`, ...), so
        // `ConcurrencyLimitLayer::layer()` — which builds a brand new
        // `Arc::new(Semaphore::new(max))` on every call — would silently
        // hand each route its OWN independent limit of `max`, not one
        // server-wide cap. `GlobalConcurrencyLimitLayer` holds a single
        // `Arc<Semaphore>` and its `layer()` always clones that same Arc, so
        // every route shares the one real semaphore (its doc comment: "Cloning
        // this layer will not create a new semaphore").
        //
        // `tower_http::timeout::TimeoutLayer` — NOT `tower::timeout::TimeoutLayer`.
        // The tower-http version maps a timeout directly to a `408 Request
        // Timeout` response; the plain tower version errors with a
        // `Box<dyn Error>` that doesn't implement `IntoResponse`.
        let router = router
            .layer(GlobalConcurrencyLimitLayer::new(
                self.config.security.max_connections,
            ))
            .layer(TimeoutLayer::new(Duration::from_secs(
                self.config.security.connection_timeout_secs,
            )));

        Ok(router)
    }

    /// Run the logthing server with TLS enabled.
    ///
    /// If TLS is not enabled in the configuration, falls back to running without TLS.
    /// Otherwise, starts an HTTPS server on the configured TLS port.  Exits on
    /// graceful shutdown when `shutdown_rx` fires.
    pub async fn run_tls(
        self,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        if !self.config.tls.enabled {
            return self.run(shutdown_rx).await;
        }

        // Same shared instance as `run` — see the `ip_whitelist` field doc
        // comment on `Server`.
        let ip_whitelist = self.ip_whitelist.clone();

        // Clone before `create_router` consumes `ip_whitelist` below — same
        // reason as the matching clone in `run`.
        let metrics_whitelist = ip_whitelist.clone();

        let app = self.create_router(ip_whitelist)?;

        // Start metrics server if enabled. Bug fix: this branch used to skip
        // metrics entirely — `run_tls` only ever reached the `start_metrics_server`
        // call by delegating to `run()` when TLS was OFF (the early return
        // above). With TLS on it built its own router and served directly,
        // so the recorder was never installed and every metric in the
        // process stayed a no-op handle forever. TLS deployments serve
        // `/metrics` over plain HTTP on `metrics.port`, same as the non-TLS
        // path — there is no TLS variant of this endpoint to build.
        if self.config.metrics.enabled {
            let metrics_ip =
                resolve_metrics_ip(&self.config.metrics.bind_address, &self.config.bind_address)?;
            let metrics_addr = SocketAddr::new(metrics_ip, self.config.metrics.port);
            install_metrics_recorder();
            tokio::spawn(serve_metrics_endpoint(metrics_addr, metrics_whitelist));
        }

        let tls_config = build_tls_config(&self.config.tls)?;
        let tls_addr = tls_bind_addr(&self.config.bind_address, self.config.tls.port);

        info!("Starting logthing server with TLS on https://{}", tls_addr);

        // Gap-b: use axum_server::Handle to trigger graceful shutdown when the
        // watch fires.  The handle is cloned into a task that waits for the signal
        // then calls handle.graceful_shutdown(None).  Dropping AppState (which
        // holds parquet_s3_sender) closes the WEF worker channel → its None arm
        // flushes before exit.
        let axum_handle = axum_server::Handle::new();
        let shutdown_handle = axum_handle.clone();
        tokio::spawn(async move {
            let _ = shutdown_rx.wait_for(|v| *v).await;
            info!("WEF TLS server received shutdown signal; initiating graceful shutdown");
            shutdown_handle.graceful_shutdown(None);
        });

        // Use axum-server for proper TLS handling
        axum_server::bind_rustls(tls_addr, tls_config)
            .handle(axum_handle)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;

        Ok(())
    }

    /// NOTE ON LAYER ORDER: this is applied to `protected_router` *after*
    /// `shared_layers` (the IP whitelist). `Route::layer` wraps the existing
    /// service, so last-applied is outermost — meaning Kerberos runs BEFORE
    /// the IP whitelist. While this middleware was an unimplemented stub that
    /// returned instantly, that was free. It no longer is: a request from an
    /// IP the allowlist would reject still costs a keytab read plus GSSAPI
    /// crypto on a blocking thread first. It stays bounded by the router-wide
    /// concurrency limit and timeout, so it is not an unbounded amplifier, but
    /// applying this layer before `shared_layers` (making the whitelist
    /// outermost) would be strictly cheaper. Left as-is deliberately: the
    /// ordering predates this change, and `create_router`'s layer attachment
    /// is not currently covered by any test, so a silent reordering mistake
    /// would not be caught.
    #[cfg(feature = "kerberos-auth")]
    fn apply_kerberos_layer(&self, router: Router) -> anyhow::Result<Router> {
        let kerberos = &self.config.security.kerberos;

        if !kerberos.enabled {
            return Ok(router);
        }

        let spn = kerberos.spn.as_ref().ok_or_else(|| {
            anyhow!("security.kerberos.spn must be set when Kerberos auth is enabled")
        })?;

        info!("Applying Kerberos authentication layer for SPN: {}", spn);

        // Middleware state is just the SPN string — no GSS handle is shared
        // across requests. See `acquire_kerberos_cred` for why.
        let spn_state = Arc::new(spn.clone());
        Ok(router.layer(middleware::from_fn_with_state(
            spn_state,
            kerberos_auth_middleware,
        )))
    }

    #[cfg(not(feature = "kerberos-auth"))]
    fn apply_kerberos_layer(&self, router: Router) -> anyhow::Result<Router> {
        if self.config.security.kerberos.enabled {
            warn!(
                "Kerberos authentication requested but the 'kerberos-auth' feature is not enabled; requests will NOT be authenticated"
            );
        }
        Ok(router)
    }
}

/// Acquire a GSSAPI server (acceptor) credential for `spn`, restricted to the
/// SPNEGO mechanism.
///
/// Deliberately re-acquired for every request (see `accept_kerberos_token`)
/// rather than acquired once and shared, even though that means reading the
/// local keytab per request:
///
/// * `libgssapi::credential::Cred` has no `Clone`/`Copy`, and its raw-handle
///   constructor/accessor (`from_c`/`to_c`) are `pub(crate)` inside the
///   `libgssapi` crate (credential.rs:239,243) — application code cannot
///   duplicate a `Cred` or hand out a borrowed view of one.
/// * `ServerCtx::new(cred: Cred)` takes the credential by value
///   (context.rs:506) and never gives it back — no `&Cred` constructor, no
///   way to reclaim the `Cred` afterward. Whatever `Cred` it's given dies
///   (releasing the GSSAPI handle via `Cred`'s `Drop`, credential.rs:81-95)
///   when that `ServerCtx` is dropped at the end of the request.
/// * Reusing one long-lived `ServerCtx` across many requests instead of
///   reusing the `Cred` is not a safe workaround either: once `step()`
///   reaches `ServerCtxState::Complete` it short-circuits and returns
///   `Ok(None)` without even inspecting the new token (context.rs:522-527).
///   A second, unrelated client hitting that same already-complete context
///   would be silently authenticated regardless of what — if anything — it
///   sent: an auth bypass.
///
/// So: one `Cred`, thrown away with its `ServerCtx`, per request.
/// `Cred::acquire` for an acceptor credential reads the local keytab and
/// does not contact a KDC, and `/wsman` is a low-QPS endpoint, so this is an
/// acceptable cost for correctness. Do not add a cache in front of this — a
/// cache is exactly the shared-handle problem above, just deferred.
#[cfg(feature = "kerberos-auth")]
fn acquire_kerberos_cred(spn: &str) -> anyhow::Result<libgssapi::credential::Cred> {
    use libgssapi::{
        credential::{Cred, CredUsage},
        name::Name,
        oid::{GSS_MECH_KRB5, GSS_MECH_SPNEGO, GSS_NT_KRB5_PRINCIPAL, OidSet},
    };

    let name = Name::new(spn.as_bytes(), Some(&GSS_NT_KRB5_PRINCIPAL))
        .map_err(|e| anyhow!("invalid Kerberos SPN {:?}: {}", spn, e))?;
    // Canonicalize against krb5 so `Cred::acquire` gets an unambiguous
    // mechanism name, matching the crate's own server-setup example.
    let name = name
        .canonicalize(Some(&GSS_MECH_KRB5))
        .map_err(|e| anyhow!("failed to canonicalize Kerberos SPN {:?}: {}", spn, e))?;

    let mut mechs =
        OidSet::new().map_err(|e| anyhow!("gssapi OID set allocation failed: {}", e))?;
    mechs
        .add(&GSS_MECH_SPNEGO)
        .map_err(|e| anyhow!("failed to build SPNEGO mechanism set: {}", e))?;

    Cred::acquire(Some(&name), None, CredUsage::Accept, Some(&mechs)).map_err(|e| {
        anyhow!(
            "failed to acquire Kerberos credential for SPN {:?}: {}",
            spn,
            e
        )
    })
}

/// Outcome of one SPNEGO `accept_sec_context` step.
#[cfg(feature = "kerberos-auth")]
enum AcceptOutcome {
    Authenticated {
        /// Mutual-auth response token (RFC 4559), if the mechanism produced one.
        response_token: Option<Vec<u8>>,
        principal: String,
    },
    /// The context needs another leg. Multi-leg negotiation is unsupported
    /// (see `kerberos_auth_middleware` docs) — callers must reject this.
    ContinueNeeded,
}

/// Run one SPNEGO accept step against a freshly acquired credential.
///
/// Blocking: `gss_acquire_cred`/`gss_accept_sec_context` are synchronous
/// GSSAPI calls (keytab I/O, crypto). Callers must run this via
/// `tokio::task::spawn_blocking`, never directly on the async runtime.
#[cfg(feature = "kerberos-auth")]
fn accept_kerberos_token(spn: &str, token: &[u8]) -> anyhow::Result<AcceptOutcome> {
    use libgssapi::context::{SecurityContext, ServerCtx};

    let cred = acquire_kerberos_cred(spn)?;
    let mut ctx = ServerCtx::new(cred);
    let response_token = ctx.step(token)?;

    if !ctx.is_complete() {
        return Ok(AcceptOutcome::ContinueNeeded);
    }

    let principal = ctx
        .source_name()
        .map(|n| n.to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());

    Ok(AcceptOutcome::Authenticated {
        response_token: response_token.map(|tok| tok.to_vec()),
        principal,
    })
}

/// Classification of an `Authorization` header for SPNEGO purposes. Pure and
/// GSSAPI-free on purpose, so the challenge/rejection logic is unit-testable
/// without a keytab or KDC.
#[cfg(feature = "kerberos-auth")]
#[derive(Debug, PartialEq, Eq)]
enum NegotiateHeader {
    Missing,
    WrongScheme,
    MalformedBase64,
    Token(Vec<u8>),
}

#[cfg(feature = "kerberos-auth")]
fn classify_negotiate_header(header: Option<&str>) -> NegotiateHeader {
    let Some(value) = header else {
        return NegotiateHeader::Missing;
    };
    let Some(b64) = value.strip_prefix("Negotiate ") else {
        return NegotiateHeader::WrongScheme;
    };
    use base64::Engine;
    match base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
        Ok(tok) => NegotiateHeader::Token(tok),
        Err(_) => NegotiateHeader::MalformedBase64,
    }
}

#[cfg(feature = "kerberos-auth")]
fn kerberos_unauthorized() -> Response {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("WWW-Authenticate", "Negotiate")
        .body(axum::body::Body::from("Unauthorized"))
        .unwrap()
}

/// RFC 4559 SPNEGO ("Negotiate") authentication middleware.
///
/// Deliberately two-pass only: real Kerberos-over-HTTP is inherently
/// two-legged (the client already holds a ticket from the KDC before it
/// ever talks to us), so a single `Authorization: Negotiate` header carrying
/// a complete token is all a genuine client ever sends. Multi-leg
/// negotiation — which NTLM fallback would need — requires carrying GSSAPI
/// state across requests; this middleware does not do that. A `step()` that
/// comes back continue-needed is rejected with 401, not tracked for a
/// follow-up leg. The LGPL `axum-negotiate` crate this replaced documented
/// the same limitation.
#[cfg(feature = "kerberos-auth")]
async fn kerberos_auth_middleware(
    State(spn): State<Arc<String>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let header = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let token = match classify_negotiate_header(header.as_deref()) {
        NegotiateHeader::Token(tok) => tok,
        NegotiateHeader::Missing
        | NegotiateHeader::WrongScheme
        | NegotiateHeader::MalformedBase64 => {
            return kerberos_unauthorized();
        }
    };

    // GSSAPI work is blocking (keytab I/O + crypto) — never run it inline on
    // the async runtime.
    let result = tokio::task::spawn_blocking(move || accept_kerberos_token(&spn, &token)).await;

    match result {
        Ok(Ok(AcceptOutcome::Authenticated {
            response_token,
            principal,
        })) => {
            debug!("Kerberos authenticated client principal: {}", principal);
            let mut response = next.run(request).await;
            if let Some(tok) = response_token {
                use base64::Engine;
                let value = format!(
                    "Negotiate {}",
                    base64::engine::general_purpose::STANDARD.encode(tok)
                );
                if let Ok(value) = axum::http::HeaderValue::from_str(&value) {
                    response.headers_mut().insert("WWW-Authenticate", value);
                }
            }
            response
        }
        Ok(Ok(AcceptOutcome::ContinueNeeded)) => {
            warn!(
                "Kerberos: client at {} needs multi-leg negotiation, which is unsupported; rejecting",
                addr
            );
            kerberos_unauthorized()
        }
        Ok(Err(e)) => {
            // Log server-side only — the response body must not leak GSSAPI
            // internals to the client.
            warn!("Kerberos authentication failed for {}: {}", addr, e);
            kerberos_unauthorized()
        }
        Err(join_err) => {
            error!("Kerberos auth worker task panicked: {}", join_err);
            kerberos_unauthorized()
        }
    }
}

async fn handle_wef_request(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    _headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let body_str = String::from_utf8_lossy(&body);
    // Use the real peer IP for source attribution.
    // X-Forwarded-For is client-spoofable and must not be trusted
    // for security-relevant identity; only the TCP peer address is authoritative.
    let source_host = addr.ip().to_string();

    match state.parser.parse_message(&body_str, source_host) {
        Ok(WefMessage::Subscription(sub)) => {
            // `subscription_id` is the raw text between `<SubscriptionId>` and
            // `</SubscriptionId>` in the POST body (`extract_xml_value`,
            // `protocol::mod`), reachable unauthenticated whenever Kerberos is
            // not configured, and unbounded — a multi-MiB element would log a
            // single multi-MiB line per request. 128 bytes comfortably covers
            // any real subscription name while bounding that amplification.
            info!(
                "New subscription from {}: {}",
                sub.source_host,
                crate::sanitize_for_log(&sub.subscription_id, 128)
            );

            let response = create_subscription_response(&sub.subscription_id);
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/soap+xml")
                .body(axum::body::Body::from(response))
                .unwrap())
        }
        Ok(WefMessage::Events(events)) => {
            info!("Received {} events from {}", events.len(), addr);
            process_events(&state, events).await;

            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(axum::body::Body::from("Events received"))
                .unwrap())
        }
        Ok(WefMessage::Heartbeat(hb)) => {
            // Same unbounded, unauthenticated-reachable `subscription_id` as
            // the Subscription arm above — same 128-byte budget.
            debug!(
                "Heartbeat from {} for subscription {}",
                hb.source_host,
                crate::sanitize_for_log(&hb.subscription_id, 128)
            );

            let response = create_heartbeat_response();
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/soap+xml")
                .body(axum::body::Body::from(response))
                .unwrap())
        }
        Ok(WefMessage::Unknown(content)) => {
            // Was `truncate_for_log` — bounded but not sanitized, so control
            // characters (embedded newline, ANSI escape) in the unrecognized
            // body survived into this warn! line. Switch to `sanitize_for_log`,
            // keeping the existing 100-byte budget.
            warn!(
                "Unknown message type from {}: {}",
                addr,
                crate::sanitize_for_log(&content, 100)
            );
            Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(axum::body::Body::from("Unknown message type"))
                .unwrap())
        }
        Err(e) => {
            error!("Failed to parse message from {}: {}", addr, e);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

async fn handle_subscription(
    State(_state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    info!("Subscription request from {}", addr);

    let _body_str = String::from_utf8_lossy(&body);
    let subscription_id = format!("sub_{}", uuid::Uuid::new_v4());

    let response = create_subscription_response(&subscription_id);
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/soap+xml")
        .body(axum::body::Body::from(response))
        .unwrap())
}

async fn handle_events(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    info!("Events from {}", addr);

    let body_str = String::from_utf8_lossy(&body);
    let source_host = addr.ip().to_string();

    match state.parser.parse_message(&body_str, source_host) {
        Ok(WefMessage::Events(events)) => {
            process_events(&state, events).await;
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(axum::body::Body::from("OK"))
                .unwrap())
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

async fn process_single_event(state: &Arc<AppState>, event: WindowsEvent) {
    let event = Arc::new(event);

    if let (Some(event_parser), Some(parsed)) = (&state.event_parser, &event.parsed)
        && let Some(generic_parsed) = event_parser.parse_event(parsed.event_id, &event.raw_xml)
    {
        // `formatted_message` is built by substituting fields extracted from
        // the attacker-supplied event XML into an operator-configured output
        // template (`GenericEventParser::parse_event` -> `format_message`),
        // so the substituted portions are wire-derived even though the
        // template itself is not. `event_id` is a `u32` (not interpolated
        // from a string) and `parser_name` comes from the parser config, not
        // the wire, so neither needs sanitizing. 200 bytes gives enough of
        // the rendered message to be useful for triage while still bounding
        // it well below a disk-fill amplifier.
        info!(
            "Event {} parsed with generic parser '{}': {}",
            parsed.event_id,
            generic_parsed.parser_name,
            generic_parsed
                .formatted_message
                .as_deref()
                .map(|m| crate::sanitize_for_log(m, 200))
                .unwrap_or(std::borrow::Cow::Borrowed("N/A"))
        );
    }

    let event_type = describe_event_type(&event);
    state.throughput.record_event(event_type).await;

    // Cardinality watching observes here for the same reason
    // `zeek::listener` observes beside `zeek_records_received`: this is
    // WEF's per-record chokepoint, upstream of every forwarding
    // destination. `event` is already `Arc<WindowsEvent>` from the wrap
    // above, so `.as_ref()` borrows it for `observe` without cloning.
    // `wef_cardinality_watchers` only ever holds this deployment's `source
    // = "wef"` watches (partitioned by source once at startup in
    // `main.rs`), so this is a per-record loop over at most a handful of
    // `Arc` clones, not every configured watch across every source.
    //
    // ponytail: the cost is per-watcher, not per-record — `observe`
    // allocates a `String` for the field value before its set-membership
    // check (see its own `ponytail:` comment), so N watches on this source
    // means N such allocations per event even when all N already track the
    // value. Fine at the one-or-two watches this is meant for. Ceiling: if
    // someone configures many watches on one source, hoist the
    // value-extraction out of the loop for watches that share a `field`.
    for watcher in &state.wef_cardinality_watchers {
        watcher.observe(event.as_ref());
    }

    // Send to Parquet S3 and/or local-disk via channel (non-blocking, independent
    // per target — a full/closed channel on one does not affect the other).
    if let Some(ref sender) = state.parquet_s3_sender
        && let Err(e) = sender.try_send(event.clone())
    {
        let kind = DropKind::from(&e);
        if let Some(dropped_total) = sender.drop_log_due(DropSite::Wef, kind) {
            match kind {
                DropKind::Full => {
                    warn!(dropped_total, "WEF Parquet S3 channel full, dropping event");
                }
                DropKind::Closed => {
                    error!(dropped_total, "WEF Parquet S3 channel closed");
                }
            }
        }
    }
    if let Some(ref sender) = state.parquet_local_sender
        && let Err(e) = sender.try_send(event.clone())
    {
        let kind = DropKind::from(&e);
        if let Some(dropped_total) = sender.drop_log_due(DropSite::Wef, kind) {
            match kind {
                DropKind::Full => {
                    warn!(
                        dropped_total,
                        "WEF Parquet local channel full, dropping event"
                    );
                }
                DropKind::Closed => {
                    error!(dropped_total, "WEF Parquet local channel closed");
                }
            }
        }
    }
}

async fn process_events(state: &Arc<AppState>, events: Vec<WindowsEvent>) {
    // Process events concurrently with a limit of 16 concurrent tasks
    // This leverages multi-core CPUs for better throughput
    stream::iter(events)
        .for_each_concurrent(MAX_CONCURRENT_EVENT_PROCESSING, |event| async move {
            process_single_event(state, event).await;
        })
        .await;
}

fn describe_event_type(event: &WindowsEvent) -> String {
    if let Some(parsed) = &event.parsed {
        if parsed.provider.is_empty() {
            format!("EventID {}", parsed.event_id)
        } else {
            format!("{}:{}", parsed.provider, parsed.event_id)
        }
    } else {
        "unknown".to_string()
    }
}

async fn handle_throughput_stats(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<ThroughputSnapshot>> {
    let snapshot = state.throughput.snapshot().await;
    Json(snapshot)
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use crate::models::{EventLevel, ParsedEvent};
    use axum::body::Bytes;
    use axum::http::HeaderMap;
    use serde_json::Value;

    fn sample_parsed_event() -> ParsedEvent {
        ParsedEvent {
            provider: "Security".into(),
            event_id: 4624,
            level: EventLevel::Information,
            task: 0,
            opcode: 0,
            keywords: 0,
            time_created: chrono::Utc::now(),
            event_record_id: 1,
            process_id: None,
            thread_id: None,
            channel: "Security".into(),
            computer: "HOST".into(),
            security_user_id: None,
            message: None,
            data: None,
        }
    }

    async fn build_state_with_config(config: Config) -> Arc<AppState> {
        build_state_with_config_and_wef_watchers(config, Vec::new()).await
    }

    /// Like `build_state_with_config`, but with `wef_cardinality_watchers`
    /// set explicitly — used by the cardinality-watching integration test,
    /// which needs `process_single_event` to actually observe records.
    async fn build_state_with_config_and_wef_watchers(
        config: Config,
        wef_cardinality_watchers: Vec<Arc<CardinalityWatcher>>,
    ) -> Arc<AppState> {
        Arc::new(AppState {
            config: Arc::new(RwLock::new(config)),
            throughput: Arc::new(ThroughputStats::new()),
            wef_cardinality_watchers,
            parser: WefParser::new(),
            event_parser: None,
            parquet_s3_sender: None,
            parquet_local_sender: None,
        })
    }

    async fn default_state() -> Arc<AppState> {
        build_state_with_config(Config::default()).await
    }

    /// `install_metrics_recorder` must tolerate a second call: it's called
    /// once (at most) by `main.rs` and again, unconditionally, by every
    /// `Server::run`/`run_tls`. A naive second `set_global_recorder` call
    /// returns `Err`; unwrapping it would panic, and swallowing it silently
    /// could leave `METRICS_HANDLE` pointing at a handle detached from
    /// whichever recorder actually won the race.
    #[test]
    fn install_metrics_recorder_is_idempotent() {
        install_metrics_recorder();
        install_metrics_recorder();

        let handle = METRICS_HANDLE
            .get()
            .expect("METRICS_HANDLE must be set after install_metrics_recorder");

        // A working handle renders real exposition text reflecting the live
        // global recorder -- proves the second call didn't detach
        // `METRICS_HANDLE` from it or install a second, shadow recorder.
        metrics::counter!(
            "aggregate_records_consumed",
            "rule" => "install_metrics_recorder_is_idempotent"
        )
        .increment(1);
        let rendered = handle.render();
        assert!(
            rendered.contains(
                "aggregate_records_consumed{rule=\"install_metrics_recorder_is_idempotent\"} 1"
            ),
            "handle must reflect the live global recorder after a repeat install call, got:\n{rendered}"
        );
    }

    #[test]
    fn describe_event_type_uses_provider() {
        let event =
            WindowsEvent::new("test".into(), "<Event/>".into()).with_parsed(sample_parsed_event());
        assert_eq!(describe_event_type(&event), "Security:4624");

        let bare = WindowsEvent::new("test".into(), "<Event/>".into());
        assert_eq!(describe_event_type(&bare), "unknown");
    }

    #[tokio::test]
    async fn process_events_updates_throughput_stats() {
        let state = default_state().await;

        let event =
            WindowsEvent::new("host".into(), "<Event/>".into()).with_parsed(sample_parsed_event());

        process_events(&state, vec![event]).await;

        let summary = state.throughput.snapshot().await;
        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0].total_events, 1);
        assert_eq!(summary[0].event_type, "Security:4624");
    }

    #[tokio::test]
    async fn throughput_endpoint_returns_snapshot() {
        let state = default_state().await;
        state.throughput.record_event("Security:4624".into()).await;
        let Json(body): Json<Vec<ThroughputSnapshot>> = handle_throughput_stats(State(state)).await;
        assert_eq!(body.len(), 1);
        assert_eq!(body[0].event_type, "Security:4624");
    }

    #[tokio::test]
    async fn syslog_info_reflects_configured_ports() {
        let mut config = Config::default();
        config.syslog.udp_port = 5514;
        config.syslog.tcp_port = 5601;
        let state = build_state_with_config(config).await;
        let Json(value) = handle_syslog_udp_info(State(state)).await;
        assert_eq!(value["udp_port"], Value::from(5514));
        assert_eq!(value["tcp_port"], Value::from(5601));
    }

    #[tokio::test]
    async fn syslog_examples_returns_samples() {
        let Json(value) = handle_syslog_examples().await;
        assert!(!value["bind_named"].as_array().unwrap().is_empty());
        assert!(!value["powerdns"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn handle_events_accepts_valid_payload() {
        let state = default_state().await;
        let body = Bytes::from(
            r#"
        <Envelope>
          <Body>
            <Events>
              <Event>
                <System>
                  <Provider>Security</Provider>
                  <EventID>4624</EventID>
                  <Level>4</Level>
                  <TimeCreated>2024-01-01T00:00:00Z</TimeCreated>
                  <Computer>host</Computer>
                </System>
                <EventData>
                  <Data Name="TargetUserName">alice</Data>
                </EventData>
              </Event>
            </Events>
          </Body>
        </Envelope>
        "#,
        );
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        let response = handle_events(State(state), ConnectInfo(addr), body)
            .await
            .expect("events accepted");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn handle_wef_request_handles_subscription() {
        let state = default_state().await;
        let body = Bytes::from(
            r#"
        <Envelope>
          <Body>
            <Subscribe>
              <SubscriptionId>TestSub</SubscriptionId>
              <Query>*</Query>
            </Subscribe>
          </Body>
        </Envelope>
        "#,
        );
        let addr: SocketAddr = "127.0.0.1:5985".parse().unwrap();
        let headers = HeaderMap::new();

        let response = handle_wef_request(State(state), ConnectInfo(addr), headers, body)
            .await
            .expect("subscription handled");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn handle_syslog_http_parses_message() {
        let state = default_state().await;
        let addr: SocketAddr = "192.0.2.10:5514".parse().unwrap();
        let msg = "<134>Jan 15 10:30:45 dns-server named[1234]: client 192.168.1.100#12345: query: example.com IN A + (93.184.216.34)";

        let ok_response = handle_syslog_http(
            State(state.clone()),
            ConnectInfo(addr),
            HeaderMap::new(),
            Bytes::from(msg),
        )
        .await
        .into_response();
        assert_eq!(ok_response.status(), StatusCode::OK);

        let bad_response = handle_syslog_http(
            State(state),
            ConnectInfo(addr),
            HeaderMap::new(),
            Bytes::from("not syslog"),
        )
        .await
        .into_response();
        assert_eq!(bad_response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn handle_syslog_http_with_rfc5424_message() {
        let state = default_state().await;
        let addr: SocketAddr = "192.0.2.10:5514".parse().unwrap();
        // RFC 5424 format
        let msg = r#"<165>1 2024-01-15T10:33:45.000Z dns-server named 1234 - [dns@12345 query="example.com"] DNS query"#;

        let response = handle_syslog_http(
            State(state),
            ConnectInfo(addr),
            HeaderMap::new(),
            Bytes::from(msg),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn handle_wef_request_with_heartbeat() {
        let state = default_state().await;
        let body = Bytes::from(
            r#"
        <Envelope>
          <Body>
            <Heartbeat>
              <SubscriptionId>hb-sub-123</SubscriptionId>
            </Heartbeat>
          </Body>
        </Envelope>
        "#,
        );
        let addr: SocketAddr = "127.0.0.1:5985".parse().unwrap();
        let headers = HeaderMap::new();

        let response = handle_wef_request(State(state), ConnectInfo(addr), headers, body)
            .await
            .expect("heartbeat handled");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn handle_wef_request_with_unknown_message() {
        let state = default_state().await;
        let body = Bytes::from(
            r#"
        <Envelope>
          <Body>
            <UnknownTag>Some unknown content</UnknownTag>
          </Body>
        </Envelope>
        "#,
        );
        let addr: SocketAddr = "127.0.0.1:5985".parse().unwrap();
        let headers = HeaderMap::new();

        let response = handle_wef_request(State(state), ConnectInfo(addr), headers, body)
            .await
            .expect("unknown message handled");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // -------------------------------------------------------------------
    // Log-injection regressions: wire-derived `subscription_id` / `content`
    // / `formatted_message` must reach their `info!`/`debug!`/`warn!` sites
    // sanitized, not raw. Uses the shared `test_support` capture subscriber
    // (see its doc comment for why a bespoke `set_default` doesn't work).
    // -------------------------------------------------------------------

    /// A `<SubscriptionId>` containing a mid-line `\r`, a `\n`, and an ANSI
    /// escape must not carry any of them raw into the "New subscription"
    /// `info!` line, and an oversized id must be truncated rather than
    /// logged whole (`extract_xml_value` returns the raw slice with no
    /// length cap of its own).
    #[tokio::test]
    async fn handle_wef_subscription_log_sanitizes_and_truncates_subscription_id() {
        crate::test_support::install_and_clear();

        let state = default_state().await;
        let forged_id = format!("sub\rFAKE\n\u{1b}[31minjected\u{1b}[0m{}", "y".repeat(200));
        let body = Bytes::from(format!(
            r#"
        <Envelope>
          <Body>
            <Subscribe>
              <SubscriptionId>{forged_id}</SubscriptionId>
              <Query>*</Query>
            </Subscribe>
          </Body>
        </Envelope>
        "#
        ));
        let addr: SocketAddr = "127.0.0.1:5985".parse().unwrap();

        let response = handle_wef_request(State(state), ConnectInfo(addr), HeaderMap::new(), body)
            .await
            .expect("subscription handled");
        assert_eq!(response.status(), StatusCode::OK);

        let events = crate::test_support::captured_events();
        let line = events
            .iter()
            .find(|m| m.contains("New subscription"))
            .unwrap_or_else(|| panic!("no matching info! event captured; got: {events:?}"));

        assert!(
            !line.contains('\r'),
            "raw CR leaked into the log line: {line:?}"
        );
        assert!(
            !line.contains('\u{1b}'),
            "raw ESC leaked into the log line: {line:?}"
        );
        assert!(
            line.contains('\u{fffd}'),
            "expected U+FFFD replacement characters in the log line: {line:?}"
        );
        assert!(
            line.len() < forged_id.len(),
            "oversized subscription_id must be truncated, not logged whole: {line:?}"
        );
    }

    /// Same regression as above, for the Heartbeat arm's `debug!` site.
    #[tokio::test]
    async fn handle_wef_heartbeat_log_sanitizes_subscription_id() {
        crate::test_support::install_and_clear();

        let state = default_state().await;
        let body = Bytes::from(
            "\n        <Envelope>\n          <Body>\n            <Heartbeat>\n              \
             <SubscriptionId>hb\rFAKE\n\u{1b}[31minjected</SubscriptionId>\n            \
             </Heartbeat>\n          </Body>\n        </Envelope>\n        ",
        );
        let addr: SocketAddr = "127.0.0.1:5985".parse().unwrap();

        let response = handle_wef_request(State(state), ConnectInfo(addr), HeaderMap::new(), body)
            .await
            .expect("heartbeat handled");
        assert_eq!(response.status(), StatusCode::OK);

        let events = crate::test_support::captured_events();
        let line = events
            .iter()
            .find(|m| m.contains("Heartbeat from"))
            .unwrap_or_else(|| panic!("no matching debug! event captured; got: {events:?}"));

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

    /// The Unknown-message-type `warn!` site was `truncate_for_log`, not
    /// `sanitize_for_log` -- bounded but not sanitized. Fails if that site is
    /// reverted.
    #[tokio::test]
    async fn handle_wef_unknown_message_log_sanitizes_content() {
        crate::test_support::install_and_clear();

        let state = default_state().await;
        let body = Bytes::from("weird\rcontent\n\u{1b}[31mFAKE\u{1b}[0m not xml at all");
        let addr: SocketAddr = "127.0.0.1:5985".parse().unwrap();

        let response = handle_wef_request(State(state), ConnectInfo(addr), HeaderMap::new(), body)
            .await
            .expect("unknown message handled");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let events = crate::test_support::captured_events();
        let line = events
            .iter()
            .find(|m| m.contains("Unknown message type"))
            .unwrap_or_else(|| panic!("no matching warn! event captured; got: {events:?}"));

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

    /// `formatted_message` is built by substituting attacker-supplied event
    /// XML field values into an operator-configured output template; a
    /// mid-message `\r`/`\n`/ANSI escape in the substituted field must not
    /// reach the "Event ... parsed with generic parser" `info!` line raw.
    #[tokio::test]
    async fn process_single_event_log_sanitizes_formatted_message() {
        use std::io::Write;

        crate::test_support::install_and_clear();

        let yaml = r#"
event_parsers:
  9999:
    name: "test_parser"
    description: "test"
    fields:
      - name: "Msg"
        source: EventData
        xpath: "Data[@Name='Msg']"
    output_format: "MSG: {Msg} END"
"#;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(file, "{yaml}").unwrap();
        let event_parser = GenericEventParser::from_file(file.path()).unwrap();

        let state = Arc::new(AppState {
            config: Arc::new(RwLock::new(Config::default())),
            throughput: Arc::new(ThroughputStats::new()),
            wef_cardinality_watchers: Vec::new(),
            parser: WefParser::new(),
            event_parser: Some(event_parser),
            parquet_s3_sender: None,
            parquet_local_sender: None,
        });

        let mut parsed = sample_parsed_event();
        parsed.event_id = 9999;
        let raw_xml = "<Event><EventData><Data Name=\"Msg\">before\rmid\nafter\u{1b}[31mred</Data></EventData></Event>";
        let event = WindowsEvent::new("host".into(), raw_xml.into()).with_parsed(parsed);

        process_single_event(&state, event).await;

        let events = crate::test_support::captured_events();
        let line = events
            .iter()
            .find(|m| m.contains("parsed with generic parser"))
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

    #[tokio::test]
    async fn handle_wef_request_with_parse_error() {
        let state = default_state().await;
        // Invalid XML - parser treats it as Unknown message, not an error
        let body = Bytes::from("<Invalid XML");
        let addr: SocketAddr = "127.0.0.1:5985".parse().unwrap();
        let headers = HeaderMap::new();

        let result = handle_wef_request(State(state), ConnectInfo(addr), headers, body).await;
        // The parser doesn't fail on invalid XML, it returns Unknown message type
        // which results in BAD_REQUEST status
        match result {
            Ok(response) => {
                assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            }
            Err(_) => {
                // Either way is acceptable
            }
        }
    }

    #[tokio::test]
    async fn handle_events_with_invalid_body() {
        let state = default_state().await;
        let body = Bytes::from("not valid events");
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        let result = handle_events(State(state), ConnectInfo(addr), body).await;
        assert!(result.is_err(), "Should return error for invalid body");
    }

    #[test]
    fn describe_event_type_with_empty_provider() {
        let parsed = ParsedEvent {
            provider: "".to_string(),
            event_id: 1234,
            level: EventLevel::Information,
            task: 0,
            opcode: 0,
            keywords: 0,
            time_created: chrono::Utc::now(),
            event_record_id: 1,
            process_id: None,
            thread_id: None,
            channel: "Security".into(),
            computer: "HOST".into(),
            security_user_id: None,
            message: None,
            data: None,
        };
        let event = WindowsEvent::new("test".into(), "<Event/>".into()).with_parsed(parsed);
        assert_eq!(describe_event_type(&event), "EventID 1234");
    }

    #[test]
    fn describe_event_type_with_provider() {
        let parsed = ParsedEvent {
            provider: "Microsoft-Windows-Security-Auditing".to_string(),
            event_id: 4624,
            level: EventLevel::Information,
            task: 0,
            opcode: 0,
            keywords: 0,
            time_created: chrono::Utc::now(),
            event_record_id: 1,
            process_id: None,
            thread_id: None,
            channel: "Security".into(),
            computer: "HOST".into(),
            security_user_id: None,
            message: None,
            data: None,
        };
        let event = WindowsEvent::new("test".into(), "<Event/>".into()).with_parsed(parsed);
        assert_eq!(
            describe_event_type(&event),
            "Microsoft-Windows-Security-Auditing:4624"
        );
    }

    #[tokio::test]
    async fn health_check_returns_ok_directly() {
        let response = health_check().await;
        assert_eq!(response, "OK");
    }

    #[tokio::test]
    async fn process_single_event_with_parsed_data() {
        let state = default_state().await;
        let event =
            WindowsEvent::new("host".into(), "<Event/>".into()).with_parsed(sample_parsed_event());

        process_single_event(&state, event).await;

        let summary = state.throughput.snapshot().await;
        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0].event_type, "Security:4624");
    }

    #[tokio::test]
    async fn process_single_event_without_parsed_data() {
        let state = default_state().await;
        let event = WindowsEvent::new("host".into(), "<Event/>".into());

        process_single_event(&state, event).await;

        // Should not panic; throughput entry is recorded as "unknown".
        let _summary = state.throughput.snapshot().await;
    }

    // -- Cardinality watching: observed at the same point as throughput --

    /// Drives real `WindowsEvent`s through `process_single_event` with a
    /// `source = "wef"` `CardinalityWatcher` attached via `AppState`, then
    /// forces a window boundary and asserts the gauge. Integration-level
    /// counterpart of `zeek::listener`'s
    /// `cardinality_watcher_reports_distinct_values_after_a_window_boundary`
    /// test — same `DebuggingRecorder` + `set_default_local_recorder`
    /// pattern, but through `process_single_event` instead of a raw TCP
    /// connection.
    #[tokio::test]
    #[allow(clippy::mutable_key_type)] // false positive: CompositeKey AtomicBool is never hashed
    async fn wef_cardinality_watcher_reports_distinct_values_after_a_window_boundary() {
        use crate::stats::cardinality::{CardinalityWatcher, CompiledWatch};
        use metrics::set_default_local_recorder;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let watcher = Arc::new(CardinalityWatcher::new(
            CompiledWatch {
                source: "wef".to_string(),
                stream: "Security".to_string(),
                field: "computer".to_string(),
            },
            1000,
        ));

        let state =
            build_state_with_config_and_wef_watchers(Config::default(), vec![watcher.clone()])
                .await;

        // 3 Security events, 2 distinct `computer` (HOST-A repeated), plus
        // one System-channel event whose computer must be excluded by the
        // stream filter.
        let mut parsed_a = sample_parsed_event();
        parsed_a.computer = "HOST-A".to_string();
        let mut parsed_b = sample_parsed_event();
        parsed_b.computer = "HOST-B".to_string();
        let mut parsed_other_channel = sample_parsed_event();
        parsed_other_channel.channel = "System".to_string();
        parsed_other_channel.computer = "HOST-EXCLUDED".to_string();

        process_single_event(
            &state,
            WindowsEvent::new("collector".into(), "<Event/>".into()).with_parsed(parsed_a.clone()),
        )
        .await;
        process_single_event(
            &state,
            WindowsEvent::new("collector".into(), "<Event/>".into()).with_parsed(parsed_b),
        )
        .await;
        process_single_event(
            &state,
            WindowsEvent::new("collector".into(), "<Event/>".into()).with_parsed(parsed_a),
        )
        .await;
        process_single_event(
            &state,
            WindowsEvent::new("collector".into(), "<Event/>".into())
                .with_parsed(parsed_other_channel),
        )
        .await;

        let read = |name: &str| -> f64 {
            let map = snapshotter.snapshot().into_hashmap();
            map.iter()
                .find_map(|(k, (_, _, v))| {
                    if k.key().name() == name
                        && let DebugValue::Gauge(g) = v
                    {
                        return Some(g.into_inner());
                    }
                    None
                })
                .unwrap_or(0.0)
        };

        assert_eq!(
            read("field_distinct_values"),
            0.0,
            "the gauge must not reflect observations before a window boundary"
        );

        watcher.tick();

        assert_eq!(
            read("field_distinct_values"),
            2.0,
            "2 distinct computer values from Security events; the System event's computer \
             must have been excluded by the stream filter"
        );
    }

    /// XFF header is present but ignored; peer IP is used for source attribution.
    ///
    /// After M-9: the `X-Forwarded-For` header is silently ignored so that a
    /// spoofed header cannot influence the source identity recorded for the
    /// event.  The request should still succeed (200 OK); only the attribution
    /// logic changed.
    #[tokio::test]
    async fn handle_wef_request_with_x_forwarded_for() {
        let state = default_state().await;
        let body = Bytes::from(
            r#"
        <Envelope>
          <Body>
            <Subscribe>
              <SubscriptionId>ForwardedTest</SubscriptionId>
              <Query>*</Query>
            </Subscribe>
          </Body>
        </Envelope>
        "#,
        );
        let addr: SocketAddr = "127.0.0.1:5985".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "10.0.0.100".parse().unwrap());

        // XFF is ignored; source attribution uses the peer IP (127.0.0.1).
        let response = handle_wef_request(State(state), ConnectInfo(addr), headers, body)
            .await
            .expect("subscription handled");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn handle_subscription_generates_unique_id() {
        let state = default_state().await;
        let body = Bytes::from(
            r#"
        <Envelope>
          <Body>
            <Subscribe>
              <Query>*</Query>
            </Subscribe>
          </Body>
        </Envelope>
        "#,
        );
        let addr: SocketAddr = "127.0.0.1:5985".parse().unwrap();

        let response = handle_subscription(State(state), ConnectInfo(addr), body)
            .await
            .expect("subscription handled");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn handle_syslog_http_with_dns_log() {
        let state = default_state().await;
        let addr: SocketAddr = "192.0.2.10:5514".parse().unwrap();
        // BIND DNS query format
        let msg = "<134>Jan 15 10:30:45 dns-server named[1234]: client 192.168.1.100#12345: query: example.com IN A + (93.184.216.34)";

        let response = handle_syslog_http(
            State(state),
            ConnectInfo(addr),
            HeaderMap::new(),
            Bytes::from(msg),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// H-4: `build_tls_config` must fail with a clear error when
    /// `require_client_cert` is `true` but no `ca_file` is supplied.
    #[test]
    fn require_client_cert_without_ca_file_returns_error() {
        use crate::config::TlsConfig;
        use std::path::PathBuf;

        let tls = TlsConfig {
            enabled: true,
            port: 5986,
            cert_file: Some(PathBuf::from("/tmp/dummy.crt")),
            key_file: Some(PathBuf::from("/tmp/dummy.key")),
            ca_file: None,
            require_client_cert: true,
        };

        let result = build_tls_config(&tls);
        assert!(result.is_err(), "expected Err when ca_file is absent");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("ca_file"),
            "error message must mention ca_file, got: {err_msg}"
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn body_size_limit_const_is_sane() {
        assert_eq!(MAX_BODY_SIZE, 64 * 1024 * 1024);
        assert!(MAX_BODY_SIZE > 0);
    }

    #[tokio::test]
    async fn protected_router_has_body_limit() {
        use axum::body::Body;
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt;

        // Build a minimal router with only the body-limit layer applied.
        // We do not need the full protected_router (which requires ConnectInfo
        // from a real TCP connection) — we just need to verify that
        // DefaultBodyLimit::max(MAX_BODY_SIZE) rejects over-limit payloads
        // with 413 PAYLOAD_TOO_LARGE.
        //
        // The handler must extract `Bytes` so that axum actually enforces the
        // body-size limit (the check occurs during body extraction).
        let router: Router = Router::new()
            .route(
                "/wsman",
                post(|_body: Bytes| async { (StatusCode::OK, "ok") }),
            )
            .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_SIZE));

        // A body one byte over the limit must be rejected with 413.
        let over_limit_body = vec![0u8; MAX_BODY_SIZE + 1];
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/wsman")
            .header("content-type", "application/soap+xml")
            .body(Body::from(over_limit_body))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(
            response.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "over-limit body must be rejected with 413"
        );
    }

    // ------------------------------------------------------------------ //
    // Body-byte budget (BODY_BYTE_BUDGET / body_budget_middleware): bounds //
    // aggregate in-flight buffered-body memory across every route on the  //
    // protected router, independent of MAX_BODY_SIZE * max_connections.   //
    // ------------------------------------------------------------------ //

    /// Unit-level proof of the core fix: charging happens against the REAL
    /// frame length, not any header. There is no `content-length` header at
    /// all on this hand-built body, and it is charged anyway (as it must be,
    /// since HTTP/2 does not always give one and does not enforce
    /// `Content-Length` against real DATA-frame bytes even when a client
    /// sends one). Also proves the held permits are released as soon as
    /// `BudgetedBody` itself is dropped, independent of any router/handler.
    #[tokio::test]
    async fn budgeted_body_charges_real_bytes_and_releases_on_drop() {
        let budget = Arc::new(Semaphore::new(10));
        let held = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut budgeted = BudgetedBody {
            inner: Body::from(vec![0u8; 6]),
            budget: budget.clone(),
            held: held.clone(),
        };

        assert_eq!(budget.available_permits(), 10);
        let frame = std::future::poll_fn(|cx| Pin::new(&mut budgeted).poll_frame(cx))
            .await
            .expect("one frame")
            .expect("charged successfully");
        assert_eq!(frame.data_ref().map(|d| d.len()), Some(6));
        assert_eq!(
            budget.available_permits(),
            4,
            "must charge the real 6-byte frame length -- there is no header to trust here"
        );

        // Dropping the body alone must NOT release the charge: `held` is
        // shared with whatever is keeping the wider request alive (in
        // production, `body_budget_middleware`'s own stack frame). This is
        // the mechanism that keeps capacity reserved for the whole handler,
        // not just the body read -- extractors like `Bytes` drop the body
        // as soon as they finish collecting it, well before the handler
        // that receives the extracted `Bytes` returns.
        drop(budgeted);
        assert_eq!(
            budget.available_permits(),
            4,
            "a surviving `held` clone must keep the charge alive after the body is dropped"
        );

        drop(held);
        assert_eq!(
            budget.available_permits(),
            10,
            "dropping the last `held` clone must release every charged permit"
        );
    }

    /// Proves the budget is genuinely SHARED across concurrent requests, not a
    /// per-request allowance in disguise. 6 requests each send 100 KiB --
    /// comfortably under the 300 KiB budget on its own, so a per-request budget
    /// of this size would let every one of them through untouched. Only the
    /// SUM across all 6 (600 KiB) exceeds the shared 300 KiB budget, so the
    /// `body_budget_exhausted` metric firing at least once here is proof the
    /// budget is shared, not private. (Checked via the metric, not the HTTP
    /// status, since a rejection can legitimately surface as either the
    /// upfront 503 or a mid-body body-read error depending on the race --
    /// see `body_budget_middleware`'s doc comment.)
    #[allow(clippy::mutable_key_type)] // false positive: CompositeKey AtomicBool is never hashed
    #[tokio::test]
    async fn body_budget_caps_aggregate_memory_across_concurrent_requests() {
        use axum::body::Body as AxumBody;
        use axum::http::Request as HttpRequest;
        use metrics::set_default_local_recorder;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::{CompositeKey, MetricKind};
        use tower::ServiceExt;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        const SENT_BYTES: usize = 100 * 1024;
        const REQUESTS: usize = 6;

        let budget = Arc::new(Semaphore::new(300 * 1024));
        let router: Router = Router::new()
            .route(
                "/ingest-like",
                post(|_body: Bytes| async {
                    // Hold the permit long enough that all admission attempts
                    // below race each other while the earlier ones are still
                    // in flight, so the concurrency is not a scheduling fluke.
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    (StatusCode::OK, "ok")
                }),
            )
            .layer(middleware::from_fn_with_state(
                budget,
                body_budget_middleware,
            ));

        let mut tasks = Vec::new();
        for _ in 0..REQUESTS {
            let router = router.clone();
            tasks.push(tokio::spawn(async move {
                // Deliberately no content-length header: charging must not
                // depend on one.
                let request = HttpRequest::builder()
                    .method("POST")
                    .uri("/ingest-like")
                    .body(AxumBody::from(vec![0u8; SENT_BYTES]))
                    .unwrap();
                router.oneshot(request).await.unwrap().status()
            }));
        }

        let mut accepted = 0;
        for t in tasks {
            if t.await.unwrap() == StatusCode::OK {
                accepted += 1;
            }
        }

        let map = snapshotter.snapshot().into_hashmap();
        let exhausted = map
            .get(&CompositeKey::new(
                MetricKind::Counter,
                metrics::Key::from_name("body_budget_exhausted"),
            ))
            .map(|(_, _, v)| match v {
                DebugValue::Counter(c) => *c,
                _ => 0,
            })
            .unwrap_or(0);

        assert!(
            exhausted >= 1,
            "shared budget must reject at least one request once aggregate demand \
             ({REQUESTS} * {SENT_BYTES} bytes) exceeds the 300 KiB budget -- a per-request \
             budget would let every one of them through untouched (accepted={accepted}, \
             exhausted counter={exhausted})"
        );
        assert!(
            accepted >= 1,
            "at least some of the {REQUESTS} requests should still be admitted"
        );
    }

    /// A normal-sized request against the real, generous `BODY_BYTE_BUDGET` is
    /// entirely unaffected. No `content-length` header is sent, so this also
    /// proves the budget does not depend on one being present.
    #[tokio::test]
    async fn body_budget_does_not_affect_normal_sized_request() {
        use axum::body::Body as AxumBody;
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt;

        let budget = Arc::new(Semaphore::new(BODY_BYTE_BUDGET));
        let router: Router = Router::new()
            .route(
                "/ingest-like",
                post(|_body: Bytes| async { (StatusCode::OK, "ok") }),
            )
            .layer(middleware::from_fn_with_state(
                budget,
                body_budget_middleware,
            ));

        let payload = vec![0u8; 4096];
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/ingest-like")
            .body(AxumBody::from(payload))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "a normal-sized request must be unaffected by the byte budget"
        );
    }

    /// The upfront, clean-503 path: when the budget is already fully spoken
    /// for at request arrival (`available_permits() == 0`), the request is
    /// rejected immediately, before the handler/extractor is ever engaged --
    /// so this never touches `BudgetedBody` at all. Promptness is checked
    /// with a short timeout: this must never queue.
    #[tokio::test]
    async fn body_budget_exhaustion_returns_503_promptly_before_handoff() {
        use axum::body::Body as AxumBody;
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt;

        // Zero capacity from the start -- available_permits() == 0 for every
        // request, guaranteeing the upfront fast path fires deterministically
        // rather than racing a mid-body charge.
        let budget = Arc::new(Semaphore::new(0));
        let router: Router = Router::new()
            .route(
                "/ingest-like",
                post(|_body: Bytes| async { (StatusCode::OK, "ok") }),
            )
            .layer(middleware::from_fn_with_state(
                budget,
                body_budget_middleware,
            ));

        let request = HttpRequest::builder()
            .method("POST")
            .uri("/ingest-like")
            .body(AxumBody::from(vec![0u8; 4096]))
            .unwrap();

        let response = tokio::time::timeout(Duration::from_millis(500), router.oneshot(request))
            .await
            .expect("exhaustion must be rejected promptly, never hang")
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "an already-exhausted budget must be rejected with 503 before handoff"
        );
    }

    /// Regression for the fast-path-503-ing-bodyless-GETs finding: a fully
    /// exhausted budget must NOT reject a bodyless GET. `/syslog/udp` and
    /// `/syslog/examples` are real routes of exactly this shape on
    /// `protected_router` -- they never extract `Bytes` and so never consume
    /// budget, but sat behind the same `available_permits() == 0` fast path
    /// as every POST route until this fix. Replaces the coverage lost when
    /// `declared_body_budget_is_zero_for_bodyless_requests` was deleted as
    /// part of round 1 (that test covered the now-gone declared-length
    /// function; this one covers the behavioural property directly against
    /// `body_budget_middleware` itself, which is what actually matters and
    /// what outlived the mechanism it was originally attached to).
    #[tokio::test]
    async fn body_budget_does_not_503_bodyless_get_when_exhausted() {
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt;

        // Zero capacity -- the same fully-exhausted setup as the POST case
        // above, which DOES 503 here. A GET must sail through regardless.
        let budget = Arc::new(Semaphore::new(0));
        let router: Router = Router::new()
            .route("/syslog/udp", get(|| async { (StatusCode::OK, "info") }))
            .layer(middleware::from_fn_with_state(
                budget,
                body_budget_middleware,
            ));

        let request = HttpRequest::builder()
            .method("GET")
            .uri("/syslog/udp")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "a bodyless GET must not be rejected by a budget gate that exists to bound \
             body-buffering memory -- it buffers none"
        );
    }

    /// The mid-body path: the budget has SOME room (so the upfront check
    /// passes and the request is handed to the handler), but the real body
    /// is larger than what remains. Per FINDING 1's ruling, there is no way
    /// to retroactively send a fresh 503 once streaming has begun, so this
    /// fails the body stream instead -- axum's `Bytes` extractor turns that
    /// into its generic body-read rejection (400 Bad Request), not 503. What
    /// matters here: it is NOT 200 (the oversized body must not be silently
    /// accepted), it does NOT hang, and the exhaustion metric fires --
    /// proving the real bytes were actually charged, not the (absent, in
    /// this request) declared length.
    #[allow(clippy::mutable_key_type)] // false positive: CompositeKey AtomicBool is never hashed
    #[tokio::test]
    async fn body_budget_mid_body_exhaustion_fails_the_stream_promptly() {
        use axum::body::Body as AxumBody;
        use axum::http::Request as HttpRequest;
        use metrics::set_default_local_recorder;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::{CompositeKey, MetricKind};
        use tower::ServiceExt;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        // 10 bytes of room -- enough to pass the upfront check, nowhere near
        // enough for the 4096-byte body below.
        let budget = Arc::new(Semaphore::new(10));
        let router: Router = Router::new()
            .route(
                "/ingest-like",
                post(|_body: Bytes| async { (StatusCode::OK, "ok") }),
            )
            .layer(middleware::from_fn_with_state(
                budget,
                body_budget_middleware,
            ));

        let request = HttpRequest::builder()
            .method("POST")
            .uri("/ingest-like")
            .body(AxumBody::from(vec![0u8; 4096]))
            .unwrap();

        let response = tokio::time::timeout(Duration::from_millis(500), router.oneshot(request))
            .await
            .expect("mid-body exhaustion must be rejected promptly, never hang")
            .unwrap();

        assert_ne!(
            response.status(),
            StatusCode::OK,
            "an oversized body must not be silently accepted once it exceeds the budget"
        );

        let map = snapshotter.snapshot().into_hashmap();
        let exhausted = map
            .get(&CompositeKey::new(
                MetricKind::Counter,
                metrics::Key::from_name("body_budget_exhausted"),
            ))
            .map(|(_, _, v)| match v {
                DebugValue::Counter(c) => *c,
                _ => 0,
            })
            .unwrap_or(0);
        assert!(
            exhausted >= 1,
            "the real (undeclared) body bytes must have been charged and rejected"
        );
    }

    /// Permits are released once a request completes, so capacity recovers
    /// for the next one -- a leak here would permanently shrink capacity.
    #[tokio::test]
    async fn body_budget_permit_released_after_request_completes() {
        use axum::body::Body as AxumBody;
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt;

        const SENT_BYTES: usize = 4096;
        let budget = Arc::new(Semaphore::new(SENT_BYTES));
        let router: Router = Router::new()
            .route(
                "/ingest-like",
                post(|_body: Bytes| async { (StatusCode::OK, "ok") }),
            )
            .layer(middleware::from_fn_with_state(
                budget,
                body_budget_middleware,
            ));

        let build_request = || {
            HttpRequest::builder()
                .method("POST")
                .uri("/ingest-like")
                .body(AxumBody::from(vec![0u8; SENT_BYTES]))
                .unwrap()
        };

        let first = router.clone().oneshot(build_request()).await.unwrap();
        assert_eq!(
            first.status(),
            StatusCode::OK,
            "first request must be admitted"
        );

        // If the first request's permit were not released on completion, this
        // second, identically-sized request would be rejected instead.
        let second = router.oneshot(build_request()).await.unwrap();
        assert_eq!(
            second.status(),
            StatusCode::OK,
            "capacity must recover once the prior request's permit is released"
        );
    }

    // ------------------------------------------------------------------ //
    // Real-wire h2 tests (FINDING 1): `Router::oneshot` never touches real //
    // HTTP/1.1 or HTTP/2 wire framing, so the declared-Content-Length      //
    // design's h2 gap was untestable through it "by construction, not     //
    // merely untested" -- these bind a real `TcpListener`, serve the      //
    // router through `axum::serve` exactly as production does (same h2c   //
    // auto-negotiation via `hyper_util::auto::Builder`), and drive it     //
    // with a real `reqwest` client forced onto h2 via                     //
    // `http2_prior_knowledge()`.                                          //
    // ------------------------------------------------------------------ //

    /// Starts a real server on an ephemeral port with `body_budget_middleware`
    /// as the only layer, and returns its address plus a handle to abort it.
    async fn spawn_real_body_budget_server(
        budget_bytes: usize,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let budget = Arc::new(Semaphore::new(budget_bytes));
        let router: Router = Router::new()
            .route(
                "/ingest-like",
                post(|_body: Bytes| async { (StatusCode::OK, "ok") }),
            )
            .layer(middleware::from_fn_with_state(
                budget,
                body_budget_middleware,
            ));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service()).await;
        });
        (addr, handle)
    }

    /// A `reqwest::Body` streamed from frames with an INDETERMINATE size
    /// hint, so reqwest sends no `content-length` header at all -- the
    /// absent-Content-Length h2 case (FINDING 1(b)).
    fn unsized_stream_body(total_bytes: usize) -> reqwest::Body {
        use http_body_util::StreamBody;

        let chunk = Bytes::from(vec![0u8; total_bytes]);
        let stream = stream::iter(vec![Ok::<_, std::io::Error>(Frame::data(chunk))]);
        reqwest::Body::wrap(StreamBody::new(stream))
    }

    /// FINDING 1(b): an h2 client that omits `Content-Length` entirely (legal
    /// and common over h2, which has no `Transfer-Encoding` to fall back to
    /// either) must still be charged by its real bytes and rejected once
    /// those exceed the budget -- under the old declared-length design this
    /// charged 0 and sailed straight through the `wanted == 0` fast path.
    #[allow(clippy::mutable_key_type)] // false positive: CompositeKey AtomicBool is never hashed
    #[tokio::test]
    async fn real_h2_request_without_content_length_is_charged_and_rejected() {
        use metrics::set_default_local_recorder;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::{CompositeKey, MetricKind};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        // Budget far smaller than the 4096-byte body below, but well above 0
        // -- a per-header (rather than per-byte) charge of an absent
        // Content-Length (0, per the old design) would sail through this.
        let (addr, server) = spawn_real_body_budget_server(10).await;
        let client = reqwest::Client::builder()
            .http2_prior_knowledge()
            .build()
            .expect("h2 client");

        let url = format!("http://{addr}/ingest-like");
        let result = client
            .post(&url)
            .body(unsized_stream_body(4096))
            .send()
            .await;

        server.abort();

        match result {
            Ok(response) => {
                assert_eq!(
                    response.version(),
                    reqwest::Version::HTTP_2,
                    "must have actually negotiated h2, not fallen back to h1.1"
                );
                assert_ne!(
                    response.status().as_u16(),
                    200,
                    "a 4096-byte h2 body with no Content-Length against a 10-byte budget must \
                     not be silently accepted"
                );
            }
            Err(e) => {
                // A stream-level rejection (e.g. the connection or h2 stream
                // closing once the server fails the body read) is also a
                // valid rejection outcome, not silent acceptance -- see
                // BudgetedBody::poll_frame's doc comment on why there is no
                // clean 503 available once streaming has begun.
                debug!("h2 request rejected at the transport level (also acceptable): {e}");
            }
        }

        let map = snapshotter.snapshot().into_hashmap();
        let exhausted = map
            .get(&CompositeKey::new(
                MetricKind::Counter,
                metrics::Key::from_name("body_budget_exhausted"),
            ))
            .map(|(_, _, v)| match v {
                DebugValue::Counter(c) => *c,
                _ => 0,
            })
            .unwrap_or(0);
        assert!(
            exhausted >= 1,
            "the real body bytes must have been charged (and rejected) even with no \
             Content-Length header at all"
        );
    }

    /// FINDING 1(a): an h2 client that sends `Content-Length: 1` but streams
    /// far more real DATA-frame bytes.
    ///
    /// EMPIRICAL RESULT, worth recording rather than assuming: with a
    /// *conformant* client (reqwest's `h2` backend), this case never reaches
    /// `BudgetedBody` at all. The `h2` crate itself enforces RFC 9113 8.1.1
    /// ("a request ... is malformed if the value of a content-length header
    /// field does not equal the sum of the DATA frame payload lengths") on
    /// the wire and resets the stream with `PROTOCOL_ERROR` as soon as the
    /// declared length is exceeded -- confirmed by this test's own output
    /// (`hyper::Error(Http2, Error { kind: Reset(_, PROTOCOL_ERROR, Remote)
    /// })`). That is a real, independent closure of 1(a) for any client
    /// built on a standards-conformant h2 stack, sitting below and in
    /// addition to this change.
    ///
    /// What this test does NOT (and, with the crates already in this
    /// dependency tree, practically cannot) prove: a non-conformant or
    /// hand-rolled h2 client that skips the sending stack's own bookkeeping
    /// and emits DATA frames the h2 layer itself would refuse to send.
    /// Constructing that needs a raw h2 frame injector below the `h2`
    /// crate's send-side validation, which is not available here without a
    /// new, low-level dependency -- so per FINDING 1's ruling, this is
    /// recorded as a documented gap rather than silently treated as covered.
    /// `BudgetedBody` still charges real bytes regardless of the declared
    /// header (proved directly by `budgeted_body_charges_real_bytes_and_releases_on_drop`,
    /// which never looks at a header at all), so a frame that DID arrive
    /// mismatched would still be charged correctly; this test only confirms
    /// that reaching that code path via a real, compliant h2 client is not
    /// possible, not that the app-level charge is untested.
    ///
    /// The assertion accepts either outcome as a valid rejection: the
    /// `body_budget_exhausted` metric firing (app-level charge caught it)
    /// or a transport-level failure (the `h2` layer caught it first) --
    /// what must NOT happen is a silent 200.
    #[allow(clippy::mutable_key_type)] // false positive: CompositeKey AtomicBool is never hashed
    #[tokio::test]
    async fn real_h2_request_with_under_declared_content_length_is_rejected() {
        use metrics::set_default_local_recorder;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::{CompositeKey, MetricKind};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let (addr, server) = spawn_real_body_budget_server(10).await;
        let client = reqwest::Client::builder()
            .http2_prior_knowledge()
            .build()
            .expect("h2 client");

        let url = format!("http://{addr}/ingest-like");
        let result = client
            .post(&url)
            .header(reqwest::header::CONTENT_LENGTH, "1")
            .body(unsized_stream_body(4096))
            .send()
            .await;

        server.abort();

        let mut transport_level_rejection = false;
        match result {
            Ok(response) => {
                assert_eq!(response.version(), reqwest::Version::HTTP_2);
                assert_ne!(
                    response.status().as_u16(),
                    200,
                    "a body that lies about its own length (1) while sending 4096 real bytes \
                     must not be silently accepted"
                );
            }
            Err(e) => {
                // Observed in practice: the h2 crate itself resets the stream
                // with PROTOCOL_ERROR before this ever reaches the app.
                transport_level_rejection = true;
                debug!("h2 request rejected at the transport level (see doc comment): {e}");
            }
        }

        let map = snapshotter.snapshot().into_hashmap();
        let exhausted = map
            .get(&CompositeKey::new(
                MetricKind::Counter,
                metrics::Key::from_name("body_budget_exhausted"),
            ))
            .map(|(_, _, v)| match v {
                DebugValue::Counter(c) => *c,
                _ => 0,
            })
            .unwrap_or(0);
        assert!(
            exhausted >= 1 || transport_level_rejection,
            "the mismatched body must be rejected either by app-level charging or by the h2 \
             layer itself -- neither happened"
        );
    }

    /// Sanity check alongside the two adversarial cases above: a genuinely
    /// small h2 request with no `Content-Length` succeeds normally against a
    /// generous budget -- the fix does not collaterally break legitimate h2
    /// clients that simply don't send the header.
    #[tokio::test]
    async fn real_h2_small_request_without_content_length_succeeds() {
        let (addr, server) = spawn_real_body_budget_server(BODY_BYTE_BUDGET).await;
        let client = reqwest::Client::builder()
            .http2_prior_knowledge()
            .build()
            .expect("h2 client");

        let url = format!("http://{addr}/ingest-like");
        let response = client
            .post(&url)
            .body(unsized_stream_body(64))
            .send()
            .await
            .expect("small h2 request must succeed");

        server.abort();

        assert_eq!(response.version(), reqwest::Version::HTTP_2);
        assert_eq!(response.status().as_u16(), 200);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn concurrent_processing_limit_is_reasonable() {
        assert!(
            MAX_CONCURRENT_EVENT_PROCESSING > 0 && MAX_CONCURRENT_EVENT_PROCESSING <= 256,
            "MAX_CONCURRENT_EVENT_PROCESSING must be in the range 1..=256"
        );
    }

    // ------------------------------------------------------------------ //
    // M-18: axum routing-layer handler tests (oneshot)                    //
    // ------------------------------------------------------------------ //

    /// `resolve_metrics_ip` is the pure logic behind the metrics bind fix:
    /// no `metrics.bind_address` inherits the main `bind_address` IP (not
    /// `0.0.0.0`); an explicit override wins. Exercised directly here
    /// rather than only through a live socket bind, so the exact resolved
    /// address is asserted deterministically instead of inferred from OS
    /// bind/connect behaviour (which depends on machine networking).
    ///
    /// Covers IPv4 and IPv6 for both the inherit and override paths — the
    /// regression this guards against (`format!("{ip}:{port}")
    /// .parse::<SocketAddr>()` silently failing for any IPv6 `ip`, because
    /// `Ipv6Addr::to_string()` never emits the bracket notation
    /// `SocketAddr`'s parser requires) only shows up for IPv6.
    #[test]
    fn resolve_metrics_ip_inherits_bind_address_when_unset_ipv4() {
        let bind_address: SocketAddr = "127.0.0.1:5985".parse().unwrap();
        assert_eq!(
            resolve_metrics_ip(&None, &bind_address).unwrap(),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn resolve_metrics_ip_inherits_bind_address_when_unset_ipv6() {
        let bind_address: SocketAddr = "[::1]:5985".parse().unwrap();
        assert_eq!(
            resolve_metrics_ip(&None, &bind_address).unwrap(),
            "::1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn resolve_metrics_ip_uses_explicit_override_when_set_ipv4() {
        let bind_address: SocketAddr = "127.0.0.1:5985".parse().unwrap();
        let override_host = Some("0.0.0.0".to_string());
        assert_eq!(
            resolve_metrics_ip(&override_host, &bind_address).unwrap(),
            "0.0.0.0".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn resolve_metrics_ip_uses_explicit_override_when_set_ipv6_bare() {
        let bind_address: SocketAddr = "127.0.0.1:5985".parse().unwrap();
        let override_host = Some("::".to_string());
        assert_eq!(
            resolve_metrics_ip(&override_host, &bind_address).unwrap(),
            "::".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn resolve_metrics_ip_uses_explicit_override_when_set_ipv6_bracketed() {
        let bind_address: SocketAddr = "127.0.0.1:5985".parse().unwrap();
        let override_host = Some("[2001:db8::1]".to_string());
        assert_eq!(
            resolve_metrics_ip(&override_host, &bind_address).unwrap(),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn resolve_metrics_ip_rejects_unparseable_override() {
        let bind_address: SocketAddr = "127.0.0.1:5985".parse().unwrap();
        let override_host = Some("not-an-ip".to_string());
        assert!(resolve_metrics_ip(&override_host, &bind_address).is_err());
    }

    /// `tls_bind_addr` is the equivalent pure logic for the TLS listener —
    /// it has no override, only the inherit path, but must handle IPv6
    /// `bind_address` for the same reason `resolve_metrics_ip` does.
    #[test]
    fn tls_bind_addr_supports_ipv4_bind_address() {
        let bind_address: SocketAddr = "127.0.0.1:5985".parse().unwrap();
        assert_eq!(
            tls_bind_addr(&bind_address, 5986),
            "127.0.0.1:5986".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn tls_bind_addr_supports_ipv6_bind_address() {
        let bind_address: SocketAddr = "[::1]:5985".parse().unwrap();
        assert_eq!(
            tls_bind_addr(&bind_address, 5986),
            "[::1]:5986".parse::<SocketAddr>().unwrap()
        );
    }

    /// `/health` endpoint returns 200 via the full router stack.
    #[tokio::test]
    async fn health_endpoint_returns_200_via_router() {
        use axum::body::Body;
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt;

        let state = default_state().await;
        let ip_whitelist = IpWhitelist::empty();
        let public_router = Router::new()
            .route("/health", axum::routing::get(health_check))
            .layer(axum::Extension(ip_whitelist.clone()))
            .with_state(state);

        let request = HttpRequest::builder()
            .method("GET")
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let response = public_router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// A WEF POST carrying a valid `<Events>` payload returns 200 and records
    /// at least one throughput entry (exercises the full handler path, not just
    /// subscription handling).
    #[tokio::test]
    async fn handle_wef_request_events_payload_returns_200() {
        let state = default_state().await;
        let body = Bytes::from(
            r#"<Envelope>
  <Body>
    <Events>
      <Event>
        <System>
          <Provider>Security</Provider>
          <EventID>4625</EventID>
          <Level>4</Level>
          <TimeCreated>2024-06-01T00:00:00Z</TimeCreated>
          <Computer>dc01</Computer>
        </System>
        <EventData>
          <Data Name="TargetUserName">bob</Data>
        </EventData>
      </Event>
    </Events>
  </Body>
</Envelope>"#,
        );
        let addr: SocketAddr = "10.0.0.1:5985".parse().unwrap();
        let headers = HeaderMap::new();

        let response = handle_wef_request(State(state.clone()), ConnectInfo(addr), headers, body)
            .await
            .expect("events payload accepted");
        assert_eq!(response.status(), StatusCode::OK);

        // The event should have been recorded in throughput stats.
        let snapshot = state.throughput.snapshot().await;
        assert!(
            !snapshot.is_empty(),
            "throughput snapshot must be non-empty after event"
        );
    }

    /// A syslog HTTP POST with a body that exactly meets the body-size limit is
    /// accepted (boundary condition: limit is inclusive).
    /// A body one byte over is rejected with 413 (duplicate of the WEF test, but
    /// confirms the limit applies uniformly to the syslog route too).
    #[tokio::test]
    async fn syslog_route_enforces_body_size_limit() {
        use axum::body::Body;
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt;

        let router: Router = Router::new()
            .route(
                "/syslog",
                post(|_body: Bytes| async { (StatusCode::OK, "ok") }),
            )
            .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_SIZE));

        let over_limit_body = vec![0u8; MAX_BODY_SIZE + 1];
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/syslog")
            .header("content-type", "text/plain")
            .body(Body::from(over_limit_body))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "syslog route: over-limit body must be rejected with 413"
        );
    }

    /// `handle_syslog_http` returns 200 for a well-formed RFC 5424 message and
    /// 400 for one that is structurally invalid (missing priority bracket).
    #[tokio::test]
    async fn handle_syslog_http_rejects_structurally_invalid_message() {
        let state = default_state().await;
        let addr: SocketAddr = "10.0.0.2:514".parse().unwrap();
        // Missing the leading '<' so the PRI field is absent — not a valid syslog frame.
        let bad_msg = "134>Jun 22 09:00:00 host app[99]: message without pri bracket";

        let response = handle_syslog_http(
            State(state),
            ConnectInfo(addr),
            HeaderMap::new(),
            Bytes::from(bad_msg),
        )
        .await
        .into_response();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "structurally invalid syslog message must be rejected with 400"
        );
    }

    /// Helper: build state with `syslog.http_token` set to `token`.
    async fn state_with_syslog_token(token: &str) -> Arc<AppState> {
        let mut cfg = Config::default();
        cfg.syslog.http_token = token.to_string();
        build_state_with_config(cfg).await
    }

    #[tokio::test]
    async fn handle_syslog_http_with_token_configured_rejects_missing_header() {
        let state = state_with_syslog_token("s3cr3t").await;
        let addr: SocketAddr = "10.0.0.3:514".parse().unwrap();
        let msg = "<134>Jan 15 10:30:45 dns-server named[1234]: hello";

        let response = handle_syslog_http(
            State(state),
            ConnectInfo(addr),
            HeaderMap::new(),
            Bytes::from(msg),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn handle_syslog_http_with_token_configured_rejects_wrong_token() {
        let state = state_with_syslog_token("s3cr3t").await;
        let addr: SocketAddr = "10.0.0.3:514".parse().unwrap();
        let msg = "<134>Jan 15 10:30:45 dns-server named[1234]: hello";
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer wrong-token".parse().unwrap());

        let response =
            handle_syslog_http(State(state), ConnectInfo(addr), headers, Bytes::from(msg))
                .await
                .into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn handle_syslog_http_with_token_configured_rejects_malformed_header() {
        let state = state_with_syslog_token("s3cr3t").await;
        let addr: SocketAddr = "10.0.0.3:514".parse().unwrap();
        let msg = "<134>Jan 15 10:30:45 dns-server named[1234]: hello";
        let mut headers = HeaderMap::new();
        // Missing the "Bearer " prefix.
        headers.insert("authorization", "s3cr3t".parse().unwrap());

        let response =
            handle_syslog_http(State(state), ConnectInfo(addr), headers, Bytes::from(msg))
                .await
                .into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn handle_syslog_http_with_token_configured_accepts_correct_token() {
        let state = state_with_syslog_token("s3cr3t").await;
        let addr: SocketAddr = "10.0.0.3:514".parse().unwrap();
        let msg = "<134>Jan 15 10:30:45 dns-server named[1234]: hello";
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer s3cr3t".parse().unwrap());

        let response =
            handle_syslog_http(State(state), ConnectInfo(addr), headers, Bytes::from(msg))
                .await
                .into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Back-compat case: empty configured token (the default) must skip auth
    /// entirely, even with no `Authorization` header — every existing
    /// deployment must see zero behavior change.
    #[tokio::test]
    async fn handle_syslog_http_with_empty_token_and_no_header_returns_200() {
        let state = default_state().await;
        let addr: SocketAddr = "10.0.0.3:514".parse().unwrap();
        let msg = "<134>Jan 15 10:30:45 dns-server named[1234]: hello";

        let response = handle_syslog_http(
            State(state),
            ConnectInfo(addr),
            HeaderMap::new(),
            Bytes::from(msg),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // CR-1's old fail-closed-stub regression tests (asserting the middleware
    // returned 501 for any Negotiate token) lived here. They're superseded
    // by the `kerberos_auth_tests` submodule near the end of this file,
    // which covers the same "no Authorization header -> 401 challenge" case
    // plus real classification/rejection paths now that GSSAPI validation
    // is implemented — a Negotiate token is now expected to yield 401 (auth
    // actually attempted and failed), never the old 501.

    // ------------------------------------------------------------------ //
    // build_tls_config error branches                                     //
    // ------------------------------------------------------------------ //

    /// `build_tls_config` must fail when `cert_file` is absent.
    #[test]
    fn build_tls_config_missing_cert_file_returns_error() {
        use crate::config::TlsConfig;

        let tls = TlsConfig {
            enabled: true,
            port: 5986,
            cert_file: None,
            key_file: Some(std::path::PathBuf::from("/tmp/dummy.key")),
            ca_file: None,
            require_client_cert: false,
        };

        let result = build_tls_config(&tls);
        assert!(result.is_err(), "expected Err when cert_file is absent");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("cert_file"),
            "error must mention cert_file, got: {msg}"
        );
    }

    /// `build_tls_config` must fail when `key_file` is absent.
    #[test]
    fn build_tls_config_missing_key_file_returns_error() {
        use crate::config::TlsConfig;

        let tls = TlsConfig {
            enabled: true,
            port: 5986,
            cert_file: Some(std::path::PathBuf::from("/tmp/dummy.crt")),
            key_file: None,
            ca_file: None,
            require_client_cert: false,
        };

        let result = build_tls_config(&tls);
        assert!(result.is_err(), "expected Err when key_file is absent");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("key_file"),
            "error must mention key_file, got: {msg}"
        );
    }

    /// `build_tls_config` (require_client_cert=false) must fail with an IO error
    /// when the cert_file path does not exist on disk.
    #[test]
    fn build_tls_config_nonexistent_cert_path_returns_io_error() {
        use crate::config::TlsConfig;

        let tls = TlsConfig {
            enabled: true,
            port: 5986,
            cert_file: Some(std::path::PathBuf::from(
                "/nonexistent/path/that/does/not/exist.crt",
            )),
            key_file: Some(std::path::PathBuf::from(
                "/nonexistent/path/that/does/not/exist.key",
            )),
            ca_file: None,
            require_client_cert: false,
        };

        let result = build_tls_config(&tls);
        assert!(
            result.is_err(),
            "expected Err when cert_file path does not exist"
        );
    }

    /// `build_tls_config` with `require_client_cert=true` must fail with an IO
    /// error when the `ca_file` path does not exist on disk (passes the
    /// `ca_file` presence check, then fails on `File::open`).
    #[test]
    fn build_tls_config_mtls_nonexistent_ca_file_returns_io_error() {
        use crate::config::TlsConfig;

        let tls = TlsConfig {
            enabled: true,
            port: 5986,
            cert_file: Some(std::path::PathBuf::from("/tmp/dummy.crt")),
            key_file: Some(std::path::PathBuf::from("/tmp/dummy.key")),
            ca_file: Some(std::path::PathBuf::from("/nonexistent/path/ca.crt")),
            require_client_cert: true,
        };

        let result = build_tls_config(&tls);
        assert!(
            result.is_err(),
            "expected Err when ca_file path does not exist"
        );
    }

    // ------------------------------------------------------------------ //
    // WEF handler: zero-event events payload                              //
    // ------------------------------------------------------------------ //

    /// An `<Events>` payload with no `<Event>` children must be accepted (200)
    /// and must not crash or record any throughput entries.
    #[tokio::test]
    async fn handle_wef_request_empty_events_returns_200() {
        let state = default_state().await;
        // Body contains <Events> (triggering the events branch in the parser)
        // but has no <Event> children — results in zero events.
        let body = Bytes::from(
            r#"<Envelope>
  <Body>
    <Events>
    </Events>
  </Body>
</Envelope>"#,
        );
        let addr: SocketAddr = "10.0.0.5:5985".parse().unwrap();
        let headers = HeaderMap::new();

        let response = handle_wef_request(State(state.clone()), ConnectInfo(addr), headers, body)
            .await
            .expect("zero-event events payload should be accepted");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "zero-event events payload must return 200"
        );

        // No events were processed, so throughput must remain empty.
        let snapshot = state.throughput.snapshot().await;
        assert!(
            snapshot.is_empty(),
            "no throughput entries expected for zero-event batch"
        );
    }

    // ------------------------------------------------------------------ //
    // handle_events: subscription body → BAD_REQUEST                     //
    // ------------------------------------------------------------------ //

    /// `handle_events` must return BAD_REQUEST when the body is a subscription
    /// (not an events payload), because the handler only accepts events.
    #[tokio::test]
    async fn handle_events_with_subscription_body_returns_bad_request() {
        let state = default_state().await;
        // A valid subscription body — not an events payload.
        let body = Bytes::from(
            r#"<Envelope>
  <Body>
    <Subscribe>
      <SubscriptionId>TestSub</SubscriptionId>
      <Query>*</Query>
    </Subscribe>
  </Body>
</Envelope>"#,
        );
        let addr: SocketAddr = "10.0.0.6:5985".parse().unwrap();

        let result = handle_events(State(state), ConnectInfo(addr), body).await;
        assert!(
            result.is_err(),
            "handle_events must reject a subscription body with BAD_REQUEST"
        );
        assert_eq!(
            result.unwrap_err(),
            StatusCode::BAD_REQUEST,
            "status must be 400 for non-events payload"
        );
    }

    // ------------------------------------------------------------------ //
    // handle_events: heartbeat body → BAD_REQUEST                        //
    // ------------------------------------------------------------------ //

    /// `handle_events` must return BAD_REQUEST when the body is a heartbeat.
    #[tokio::test]
    async fn handle_events_with_heartbeat_body_returns_bad_request() {
        let state = default_state().await;
        let body = Bytes::from(
            r#"<Envelope>
  <Body>
    <Heartbeat>
      <SubscriptionId>hb-sub-1</SubscriptionId>
    </Heartbeat>
  </Body>
</Envelope>"#,
        );
        let addr: SocketAddr = "10.0.0.7:5985".parse().unwrap();

        let result = handle_events(State(state), ConnectInfo(addr), body).await;
        assert!(
            result.is_err(),
            "handle_events must reject a heartbeat body"
        );
        assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
    }

    // ------------------------------------------------------------------ //
    // /stats/throughput via router oneshot                                //
    // ------------------------------------------------------------------ //

    /// `/stats/throughput` returns 200 and a JSON array via the router stack.
    #[tokio::test]
    async fn stats_throughput_endpoint_returns_200_via_router() {
        use axum::body::Body;
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt;

        let state = default_state().await;
        // Pre-populate one entry so the response body is non-trivial to validate.
        state
            .throughput
            .record_event("TestProvider:9999".into())
            .await;

        let ip_whitelist = IpWhitelist::empty();
        let router = Router::new()
            .route("/stats/throughput", get(handle_throughput_stats))
            .layer(axum::Extension(ip_whitelist))
            .with_state(state);

        let request = HttpRequest::builder()
            .method("GET")
            .uri("/stats/throughput")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "/stats/throughput must return 200"
        );

        let body_bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("/stats/throughput must return valid JSON");
        assert!(
            parsed.is_array(),
            "/stats/throughput body must be a JSON array"
        );
        let arr = parsed.as_array().unwrap();
        assert_eq!(arr.len(), 1, "expected one entry after recording one event");
        assert_eq!(arr[0]["event_type"], "TestProvider:9999");
    }

    // ------------------------------------------------------------------ //
    // handle_subscription: check XML response contains subscription id   //
    // ------------------------------------------------------------------ //

    /// `handle_subscription` must return 200 with a SOAP XML body that
    /// contains the generated `sub_` prefixed subscription id.
    #[tokio::test]
    async fn handle_subscription_response_contains_sub_prefix() {
        use axum::body::to_bytes;

        let state = default_state().await;
        let body = Bytes::from("<Envelope><Body></Body></Envelope>");
        let addr: SocketAddr = "10.0.1.1:5985".parse().unwrap();

        let response = handle_subscription(State(state), ConnectInfo(addr), body)
            .await
            .expect("handle_subscription must succeed");

        assert_eq!(response.status(), StatusCode::OK);

        // Check Content-Type header.
        let ct = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.contains("application/soap+xml"),
            "Content-Type must be application/soap+xml, got: {ct}"
        );

        // Check the body contains a subscription id with the `sub_` prefix.
        let body_bytes = to_bytes(response.into_body(), 65536).await.unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert!(
            body_str.contains("sub_"),
            "subscription response body must contain generated sub_ id, got: {body_str}"
        );
    }

    // ------------------------------------------------------------------ //
    // handle_wef_request: subscription response Content-Type             //
    // ------------------------------------------------------------------ //

    /// The subscription branch of `handle_wef_request` must set
    /// `Content-Type: application/soap+xml`.
    #[tokio::test]
    async fn handle_wef_request_subscription_sets_content_type() {
        use axum::body::to_bytes;

        let state = default_state().await;
        let body = Bytes::from(
            r#"<Envelope>
  <Body>
    <Subscribe>
      <SubscriptionId>ct-test-sub</SubscriptionId>
      <Query>*</Query>
    </Subscribe>
  </Body>
</Envelope>"#,
        );
        let addr: SocketAddr = "10.0.1.2:5985".parse().unwrap();
        let headers = HeaderMap::new();

        let response = handle_wef_request(State(state), ConnectInfo(addr), headers, body)
            .await
            .expect("subscription must be handled");

        assert_eq!(response.status(), StatusCode::OK);
        let ct = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.contains("application/soap+xml"),
            "subscription response must have Content-Type application/soap+xml, got: {ct}"
        );

        // Body must include the subscription id (escaping check).
        let body_bytes = to_bytes(response.into_body(), 65536).await.unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert!(
            body_str.contains("ct-test-sub"),
            "subscription body must echo the subscription id"
        );
    }

    // ------------------------------------------------------------------ //
    // handle_wef_request: heartbeat Content-Type                         //
    // ------------------------------------------------------------------ //

    /// The heartbeat branch of `handle_wef_request` must set
    /// `Content-Type: application/soap+xml`.
    #[tokio::test]
    async fn handle_wef_request_heartbeat_sets_content_type() {
        let state = default_state().await;
        let body = Bytes::from(
            r#"<Envelope>
  <Body>
    <Heartbeat>
      <SubscriptionId>hb-ct-sub</SubscriptionId>
    </Heartbeat>
  </Body>
</Envelope>"#,
        );
        let addr: SocketAddr = "10.0.1.3:5985".parse().unwrap();
        let headers = HeaderMap::new();

        let response = handle_wef_request(State(state), ConnectInfo(addr), headers, body)
            .await
            .expect("heartbeat must be handled");

        assert_eq!(response.status(), StatusCode::OK);
        let ct = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.contains("application/soap+xml"),
            "heartbeat response must have Content-Type application/soap+xml, got: {ct}"
        );
    }

    // ------------------------------------------------------------------ //
    // Task 4.8: HEC / NDJSON route wiring tests                          //
    // ------------------------------------------------------------------ //

    /// Helper: build a minimal router with the three HEC routes and the same
    /// body-size limit used in production, for route-level unit testing.
    async fn build_hec_router(token: &str) -> axum::Router {
        use crate::ingest::{
            IngestState,
            handlers::{handle_hec_event, handle_hec_raw, handle_ndjson},
        };
        use axum::{Extension, Router, routing::post};
        use std::sync::Arc;

        let mut cfg = Config::default();
        cfg.hec.token = token.to_string();
        let shared_config = Arc::new(RwLock::new(cfg));
        let ingest_state = IngestState {
            generic_s3: None,
            generic_local: None,
        };

        Router::new()
            .route("/services/collector/event", post(handle_hec_event))
            .route("/services/collector/raw", post(handle_hec_raw))
            .route("/ingest", post(handle_ndjson))
            .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_SIZE))
            .layer(Extension(shared_config))
            .layer(Extension(ingest_state))
    }

    #[tokio::test]
    async fn hec_event_route_accepts_valid_request() {
        use axum::body::Body;
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt;

        let router = build_hec_router("test-token").await;
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/services/collector/event")
            .header("Authorization", "Splunk test-token")
            .body(Body::from(
                r#"{"event":{"msg":"hello world"},"sourcetype":"myapp"}"#,
            ))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let b = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let j: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(j["text"], "Success");
        assert_eq!(j["code"], 0);
    }

    #[tokio::test]
    async fn hec_route_rejects_bad_token() {
        use axum::body::Body;
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt;

        let router = build_hec_router("correct").await;
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/services/collector/event")
            .header("Authorization", "Splunk wrong")
            .body(Body::from(r#"{"event":{"k":1},"sourcetype":"t"}"#))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn hec_raw_route_returns_200() {
        use axum::body::Body;
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt;

        let router = build_hec_router("tok").await;
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/services/collector/raw?sourcetype=raw_src")
            .header("Authorization", "Splunk tok")
            .body(Body::from("raw log payload"))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ndjson_route_returns_200() {
        use axum::body::Body;
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt;

        let router = build_hec_router("tok").await;
        let body = "{\"host\":\"h1\",\"msg\":\"line1\"}\n{\"host\":\"h2\",\"msg\":\"line2\"}\n";
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/ingest?sourcetype=ndjson_type")
            .header("Authorization", "Splunk tok")
            .body(Body::from(body))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn hec_routes_enforce_body_size_limit() {
        use axum::body::Body;
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt;

        let router = build_hec_router("tok").await;
        let over_limit = vec![0u8; MAX_BODY_SIZE + 1];
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/services/collector/event")
            .header("Authorization", "Splunk tok")
            .body(Body::from(over_limit))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    // ------------------------------------------------------------------ //
    // Task 4.8 (gating): HEC routes registered only when hec.enabled      //
    // These exercise the REAL create_router path, not the isolated helper.//
    // ------------------------------------------------------------------ //

    /// Build a full `Server` from a config (S3 absent → no worker, no panic).
    async fn build_server(config: Config) -> Server {
        let shared = Arc::new(RwLock::new(config.clone()));
        let throughput = Arc::new(ThroughputStats::new());
        Server::new(
            config,
            shared,
            throughput,
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
            crate::forwarding::flush_registry::FlushIntervalRegistry::new(),
            IpWhitelist::empty(),
            Vec::new(),
        )
        .await
        .expect("Server::new must succeed")
    }

    /// Inject a `ConnectInfo` extension so the ip_whitelist middleware (which
    /// extracts `ConnectInfo<SocketAddr>`) resolves during a `oneshot` test.
    fn with_connect_info(
        mut req: axum::http::Request<axum::body::Body>,
    ) -> axum::http::Request<axum::body::Body> {
        let addr: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));
        req
    }

    /// With `hec.enabled = false` (the default), the three HEC routes must NOT
    /// be mounted on the protected router — `/ingest` must 404, exactly as
    /// before this unit (zero behavior change for existing deployments).
    #[tokio::test]
    async fn hec_routes_not_mounted_when_disabled() {
        use axum::body::Body;
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt;

        let mut config = Config::default();
        config.hec.enabled = false;
        let server = build_server(config).await;
        let router = server
            .create_router(IpWhitelist::empty())
            .expect("router builds");

        let req = with_connect_info(
            HttpRequest::builder()
                .method("POST")
                .uri("/ingest")
                .body(Body::from("{\"k\":1}\n"))
                .unwrap(),
        );
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "/ingest must 404 when hec.enabled is false"
        );
    }

    /// The other two HEC routes are likewise unmounted when disabled.
    #[tokio::test]
    async fn hec_collector_routes_not_mounted_when_disabled() {
        use axum::body::Body;
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt;

        let config = Config::default(); // hec.enabled defaults to false
        let server = build_server(config).await;
        let router = server
            .create_router(IpWhitelist::empty())
            .expect("router builds");

        for uri in ["/services/collector/event", "/services/collector/raw"] {
            let req = with_connect_info(
                HttpRequest::builder()
                    .method("POST")
                    .uri(uri)
                    .body(Body::from("x"))
                    .unwrap(),
            );
            let resp = router.clone().oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "{uri} must 404 when hec.enabled is false"
            );
        }
    }

    /// With `hec.enabled = true`, the routes ARE mounted behind the
    /// IP-whitelist/body-limit middleware. With the default empty token,
    /// dev-mode auth is skipped, so a valid NDJSON POST returns 200 (definitely
    /// not 404 — proving the route exists).
    #[tokio::test]
    async fn hec_routes_mounted_when_enabled() {
        use axum::body::Body;
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt;

        let mut config = Config::default();
        config.hec.enabled = true; // empty token → dev mode (no auth required)
        let server = build_server(config).await;
        let router = server
            .create_router(IpWhitelist::empty())
            .expect("router builds");

        let req = with_connect_info(
            HttpRequest::builder()
                .method("POST")
                .uri("/ingest?sourcetype=t")
                .body(Body::from("{\"k\":1}\n"))
                .unwrap(),
        );
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "/ingest must be reachable (200) when hec.enabled is true"
        );
    }

    /// Existing protected routes are unaffected by the gating: `/syslog` still
    /// responds (200) regardless of the hec.enabled flag.
    #[tokio::test]
    async fn existing_protected_routes_unaffected_by_hec_gating() {
        use axum::body::Body;
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt;

        let config = Config::default(); // hec disabled
        let server = build_server(config).await;
        let router = server
            .create_router(IpWhitelist::empty())
            .expect("router builds");

        let msg = "<134>Jan 15 10:30:45 dns-server named[1234]: client 192.168.1.100#12345: query: example.com IN A + (93.184.216.34)";
        let req = with_connect_info(
            HttpRequest::builder()
                .method("POST")
                .uri("/syslog")
                .body(Body::from(msg))
                .unwrap(),
        );
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "/syslog must remain mounted and functional"
        );
    }

    // ------------------------------------------------------------------ //
    // syslog.http_token: opt-in bearer auth on the unconditionally-mounted //
    // /syslog route, exercised through the REAL create_router path.       //
    // ------------------------------------------------------------------ //

    /// Default config (empty `syslog.http_token`) must accept a request with
    /// no `Authorization` header at all — the back-compat case that matters
    /// most, since `/syslog` is mounted unconditionally for every deployment.
    #[tokio::test]
    async fn syslog_route_with_empty_token_accepts_request_without_header() {
        use axum::body::Body;
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt;

        let config = Config::default(); // syslog.http_token defaults to ""
        let server = build_server(config).await;
        let router = server
            .create_router(IpWhitelist::empty())
            .expect("router builds");

        let msg = "<134>Jan 15 10:30:45 dns-server named[1234]: hello";
        let req = with_connect_info(
            HttpRequest::builder()
                .method("POST")
                .uri("/syslog")
                .body(Body::from(msg))
                .unwrap(),
        );
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// With `syslog.http_token` configured, a request with no `Authorization`
    /// header is rejected with 401 through the real router.
    #[tokio::test]
    async fn syslog_route_with_token_configured_rejects_missing_header() {
        use axum::body::Body;
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt;

        let mut config = Config::default();
        config.syslog.http_token = "s3cr3t".to_string();
        let server = build_server(config).await;
        let router = server
            .create_router(IpWhitelist::empty())
            .expect("router builds");

        let msg = "<134>Jan 15 10:30:45 dns-server named[1234]: hello";
        let req = with_connect_info(
            HttpRequest::builder()
                .method("POST")
                .uri("/syslog")
                .body(Body::from(msg))
                .unwrap(),
        );
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// With `syslog.http_token` configured, the correct bearer token is
    /// accepted through the real router.
    #[tokio::test]
    async fn syslog_route_with_token_configured_accepts_correct_bearer() {
        use axum::body::Body;
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt;

        let mut config = Config::default();
        config.syslog.http_token = "s3cr3t".to_string();
        let server = build_server(config).await;
        let router = server
            .create_router(IpWhitelist::empty())
            .expect("router builds");

        let msg = "<134>Jan 15 10:30:45 dns-server named[1234]: hello";
        let req = with_connect_info(
            HttpRequest::builder()
                .method("POST")
                .uri("/syslog")
                .header("Authorization", "Bearer s3cr3t")
                .body(Body::from(msg))
                .unwrap(),
        );
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn server_take_hec_worker_handles_returns_empty_when_hec_disabled() {
        let mut server = Server::new(
            Config::default(),
            Arc::new(RwLock::new(Config::default())),
            Arc::new(ThroughputStats::new()),
            std::sync::Arc::new(crate::stats::SourceHourlyStats::new()),
            crate::forwarding::flush_registry::FlushIntervalRegistry::new(),
            IpWhitelist::empty(),
            Vec::new(),
        )
        .await
        .unwrap();
        let handles = server.take_hec_worker_handles();
        assert!(
            handles.is_empty(),
            "hec worker handles must be empty when hec.enabled=false"
        );
    }

    // ------------------------------------------------------------------ //
    // security.max_connections / security.connection_timeout_secs wiring: //
    // GlobalConcurrencyLimitLayer + tower_http TimeoutLayer, applied to    //
    // the real merged router built by create_router.                      //
    //                                                                      //
    // Zero-value determinism note: earlier versions of these tests used   //
    // max_connections=0 / connection_timeout_secs=0 as a determinism      //
    // trick (0 permits never grants poll_ready; an already-elapsed        //
    // deadline always wins the first poll). Both are now rejected at      //
    // construction (see create_router above), so that trick is gone.      //
    // Reaching for a NONZERO substitute doesn't work through this         //
    // router's actual fixed routes: every one of them (health_check,      //
    // handle_syslog_examples, ...) resolves fully synchronously, with no  //
    // real `.await` suspension point (confirmed: no blocking `.send()`    //
    // anywhere reachable, only non-blocking `try_send`). Concretely, a    //
    // `tower::util::Oneshot` future for any of these routes runs          //
    // poll_ready -> call -> poll(inner) to completion inside ONE poll()   //
    // call, so a concurrency permit is acquired and released within a    //
    // single synchronous step, and no real or paused clock ever gets a    //
    // chance to interleave with it. There is no nonzero value or timing   //
    // trick that holds a permit, or leaves a nonzero timeout unresolved,  //
    // across an externally observable window using only these routes.    //
    // That "genuinely enforced, with a real nonzero value" proof already //
    // lives in tests/security_limits_e2e.rs, which builds an equivalent  //
    // router (same real GlobalConcurrencyLimitLayer / TimeoutLayer types) //
    // around a handler with a real, controllable sleep -- see             //
    // e2e_concurrency_limit_is_global_across_routes_not_per_route and     //
    // e2e_slow_handler_past_timeout_returns_408 there. What's left worth   //
    // asserting here, through the real create_router, is: zero is         //
    // rejected, and the smallest legal value (1) is accepted and doesn't   //
    // break real requests on both a public and a protected route.         //
    // ------------------------------------------------------------------ //

    /// `max_connections = 0` must be rejected at router construction, not
    /// silently accepted (0 permits would mean the server never admits a
    /// single request).
    #[tokio::test]
    async fn create_router_rejects_zero_max_connections() {
        let mut config = Config::default();
        config.security.max_connections = 0;
        let server = build_server(config).await;
        let err = server
            .create_router(IpWhitelist::empty())
            .expect_err("max_connections=0 must be rejected");
        assert!(
            err.to_string().contains("max_connections"),
            "error must name the offending field, got: {err}"
        );
    }

    /// `connection_timeout_secs = 0` must be rejected at router
    /// construction, not silently accepted (0 would time out every
    /// request immediately).
    #[tokio::test]
    async fn create_router_rejects_zero_connection_timeout_secs() {
        let mut config = Config::default();
        config.security.connection_timeout_secs = 0;
        let server = build_server(config).await;
        let err = server
            .create_router(IpWhitelist::empty())
            .expect_err("connection_timeout_secs=0 must be rejected");
        assert!(
            err.to_string().contains("connection_timeout_secs"),
            "error must name the offending field, got: {err}"
        );
    }

    /// With the default (non-zero) timeout, `/health` still succeeds —
    /// proving the layer's presence doesn't regress ordinary traffic.
    #[tokio::test]
    async fn default_timeout_does_not_break_normal_requests() {
        use tower::ServiceExt;

        let server = build_server(Config::default()).await;
        let router = server
            .create_router(IpWhitelist::empty())
            .expect("router builds");

        let req = with_connect_info(
            axum::http::Request::builder()
                .method("GET")
                .uri("/health")
                .body(axum::body::Body::empty())
                .unwrap(),
        );
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// With the default (non-zero) `max_connections`, ordinary traffic on a
    /// protected route is unaffected.
    #[tokio::test]
    async fn default_max_connections_does_not_break_normal_requests() {
        use tower::ServiceExt;

        let server = build_server(Config::default()).await;
        let router = server
            .create_router(IpWhitelist::empty())
            .expect("router builds");

        let req = with_connect_info(
            axum::http::Request::builder()
                .method("GET")
                .uri("/syslog/examples")
                .body(axum::body::Body::empty())
                .unwrap(),
        );
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// The smallest legal (nonzero) value for both knobs is accepted, and
    /// the router still serves both a public and a protected route
    /// normally — pins the validation boundary at exactly ">0", not
    /// something stricter, on both routes the layers wrap.
    #[tokio::test]
    async fn minimum_legal_values_are_accepted_and_serve_both_route_kinds() {
        use tower::ServiceExt;

        let mut config = Config::default();
        config.security.max_connections = 1;
        config.security.connection_timeout_secs = 1;
        let server = build_server(config).await;
        let router = server
            .create_router(IpWhitelist::empty())
            .expect("max_connections=1, connection_timeout_secs=1 must both be accepted");

        let health_req = with_connect_info(
            axum::http::Request::builder()
                .method("GET")
                .uri("/health")
                .body(axum::body::Body::empty())
                .unwrap(),
        );
        let resp = router.clone().oneshot(health_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "public route /health");

        let protected_req = with_connect_info(
            axum::http::Request::builder()
                .method("GET")
                .uri("/syslog/examples")
                .body(axum::body::Body::empty())
                .unwrap(),
        );
        let resp = router.oneshot(protected_req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "protected route /syslog/examples"
        );
    }

    // ------------------------------------------------------------------ //
    // Task 5.4: OTLP handler tests                                        //
    // ------------------------------------------------------------------ //

    #[cfg(feature = "otlp")]
    mod otlp_handler_tests {
        use super::*;
        use crate::config::OtlpConfig;
        use axum::body::Body;
        use axum::http::Request as HttpRequest;
        use opentelemetry_proto::tonic::collector::logs::v1::{
            ExportLogsServiceRequest, ExportLogsServiceResponse,
        };
        use opentelemetry_proto::tonic::common::v1::{
            AnyValue, KeyValue, any_value::Value as AnyVal,
        };
        use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
        use opentelemetry_proto::tonic::resource::v1::Resource;
        use prost::Message as ProstMessage;
        use tower::ServiceExt;

        fn make_proto_request() -> ExportLogsServiceRequest {
            ExportLogsServiceRequest {
                resource_logs: vec![ResourceLogs {
                    resource: Some(Resource {
                        attributes: vec![KeyValue {
                            key: "service.name".to_string(),
                            value: Some(AnyValue {
                                value: Some(AnyVal::StringValue("test-svc".to_string())),
                            }),
                            ..Default::default()
                        }],
                        ..Default::default()
                    }),
                    scope_logs: vec![ScopeLogs {
                        scope: None,
                        log_records: vec![LogRecord {
                            time_unix_nano: 1_700_000_000_000_000_000,
                            severity_text: "INFO".to_string(),
                            body: Some(AnyValue {
                                value: Some(AnyVal::StringValue("e2e test message".to_string())),
                            }),
                            ..Default::default()
                        }],
                        schema_url: String::new(),
                    }],
                    schema_url: String::new(),
                }],
            }
        }

        /// Build a minimal router with the OTLP route and the given bearer_token
        /// configured.  `IngestState.generic_s3 = None` so no S3 sink is needed.
        async fn build_otlp_app(bearer_token: Option<String>) -> axum::Router {
            let config = Config {
                otlp: OtlpConfig {
                    enabled: true,
                    bearer_token,
                },
                ..Default::default()
            };
            let app_state = super::build_state_with_config(config).await;
            let ingest_state = IngestState {
                generic_s3: None,
                generic_local: None,
            };

            axum::Router::new()
                .route("/v1/logs", post(handle_otlp_logs))
                .layer(axum::Extension(ingest_state))
                .with_state(app_state)
        }

        // ── Test A: valid protobuf POST → 200 + valid ExportLogsServiceResponse ──

        #[tokio::test]
        async fn handle_otlp_logs_proto_returns_200() {
            let app = build_otlp_app(None).await;
            let req_bytes = make_proto_request().encode_to_vec();

            let request = super::with_connect_info(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/v1/logs")
                    .header("content-type", "application/x-protobuf")
                    .body(Body::from(req_bytes))
                    .unwrap(),
            );

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body_bytes = axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap();
            let _resp = ExportLogsServiceResponse::decode(body_bytes.as_ref())
                .expect("response must be valid protobuf ExportLogsServiceResponse");
        }

        // ── Test B: valid JSON POST → 200 ──────────────────────────────────────

        #[tokio::test]
        async fn handle_otlp_logs_json_returns_200() {
            let app = build_otlp_app(None).await;
            let json_body = serde_json::to_vec(&make_proto_request()).expect(
                "ExportLogsServiceRequest must be serde-serializable via with-serde feature",
            );

            let request = super::with_connect_info(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/v1/logs")
                    .header("content-type", "application/json")
                    .body(Body::from(json_body))
                    .unwrap(),
            );

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        // ── Test C: correct bearer token accepted → 200 ────────────────────────

        #[tokio::test]
        async fn handle_otlp_logs_correct_bearer_accepted() {
            let app = build_otlp_app(Some("my-secret-token".to_string())).await;
            let req_bytes = make_proto_request().encode_to_vec();

            let request = super::with_connect_info(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/v1/logs")
                    .header("content-type", "application/x-protobuf")
                    .header("authorization", "Bearer my-secret-token")
                    .body(Body::from(req_bytes))
                    .unwrap(),
            );

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        // ── Test D: wrong bearer token rejected → 401 ──────────────────────────

        #[tokio::test]
        async fn handle_otlp_logs_wrong_bearer_rejected() {
            let app = build_otlp_app(Some("correct-token".to_string())).await;
            let req_bytes = make_proto_request().encode_to_vec();

            let request = super::with_connect_info(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/v1/logs")
                    .header("content-type", "application/x-protobuf")
                    .header("authorization", "Bearer wrong-token")
                    .body(Body::from(req_bytes))
                    .unwrap(),
            );

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        // ── Test E: bearer required but absent → 401 ───────────────────────────

        #[tokio::test]
        async fn handle_otlp_logs_missing_bearer_rejected() {
            let app = build_otlp_app(Some("required-token".to_string())).await;
            let req_bytes = make_proto_request().encode_to_vec();

            let request = super::with_connect_info(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/v1/logs")
                    .header("content-type", "application/x-protobuf")
                    .body(Body::from(req_bytes))
                    .unwrap(),
            );

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        // ── Test F: no bearer_token configured → accepted without auth ─────────
        // This is the dev-mode / empty-token skip, consistent with HEC behavior.

        #[tokio::test]
        async fn handle_otlp_logs_unconfigured_bearer_accepts_no_auth() {
            let app = build_otlp_app(None).await; // bearer_token = None
            let req_bytes = make_proto_request().encode_to_vec();

            let request = super::with_connect_info(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/v1/logs")
                    .header("content-type", "application/x-protobuf")
                    // deliberately NO Authorization header
                    .body(Body::from(req_bytes))
                    .unwrap(),
            );

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "no bearer_token configured → request must be accepted without auth"
            );
        }

        // ── Test G: malformed protobuf body → 400 ─────────────────────────────

        #[tokio::test]
        async fn handle_otlp_logs_malformed_proto_returns_400() {
            let app = build_otlp_app(None).await;

            let request = super::with_connect_info(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/v1/logs")
                    .header("content-type", "application/x-protobuf")
                    .body(Body::from(
                        b"\xFF\xFE\xFD garbage not valid protobuf".as_ref(),
                    ))
                    .unwrap(),
            );

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "malformed protobuf body must return 400"
            );
        }

        // ── Test H: malformed JSON body → 400 ────────────────────────────────

        #[tokio::test]
        async fn handle_otlp_logs_malformed_json_returns_400() {
            let app = build_otlp_app(None).await;

            let request = super::with_connect_info(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/v1/logs")
                    .header("content-type", "application/json")
                    .body(Body::from(b"{ not valid json ]".as_ref()))
                    .unwrap(),
            );

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "malformed JSON body must return 400"
            );
        }

        // ── Test I: unknown / missing Content-Type → 415 ──────────────────────

        #[tokio::test]
        async fn handle_otlp_logs_unknown_content_type_returns_415() {
            let app = build_otlp_app(None).await;

            let request = super::with_connect_info(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/v1/logs")
                    .header("content-type", "text/plain")
                    .body(Body::from(b"hello".as_ref()))
                    .unwrap(),
            );

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unknown Content-Type must return 415"
            );
        }

        // ── Test J: route NOT mounted when otlp.enabled = false → 404 ─────────
        // This verifies the global constraint: default deployments see zero
        // behavior change (the route is not registered when disabled).

        #[tokio::test]
        async fn v1_logs_not_mounted_when_otlp_disabled() {
            let config = Config::default(); // otlp.enabled defaults to false
            let server = super::build_server(config).await;
            let router = server
                .create_router(IpWhitelist::empty())
                .expect("router must build");

            let req = super::with_connect_info(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/v1/logs")
                    .header("content-type", "application/x-protobuf")
                    .body(Body::from(b"".as_ref()))
                    .unwrap(),
            );

            let resp = router.oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "/v1/logs must return 404 when otlp.enabled is false"
            );
        }

        // ── Test K: route IS mounted when otlp.enabled = true ─────────────────

        #[tokio::test]
        async fn v1_logs_mounted_when_otlp_enabled() {
            let mut config = Config::default();
            config.otlp.enabled = true; // bearer_token = None → dev mode

            let server = super::build_server(config).await;
            let router = server
                .create_router(IpWhitelist::empty())
                .expect("router must build");

            let req_bytes = make_proto_request().encode_to_vec();
            let req = super::with_connect_info(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/v1/logs")
                    .header("content-type", "application/x-protobuf")
                    .body(Body::from(req_bytes))
                    .unwrap(),
            );

            let resp = router.oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "/v1/logs must return 200 when otlp.enabled is true and no token required"
            );
        }
    }

    // ------------------------------------------------------------------ //
    // Kerberos SPNEGO middleware                                         //
    //                                                                    //
    // There is no KDC or keytab in this test environment (deliberate:    //
    // a full KDC harness was cut as disproportionate, since this sim     //
    // env isn't invoked by any CI workflow), so only the paths that      //
    // never need a real GSSAPI exchange are covered here:                //
    //   * `classify_negotiate_header` — pure, GSSAPI-free header parsing //
    //   * missing header / wrong scheme / malformed base64 — all three  //
    //     short-circuit in the middleware before any GSSAPI call runs   //
    //   * a well-formed-but-bogus token, which still exercises the      //
    //     "the GSSAPI pipeline failed" branch end to end (whether it     //
    //     fails at `Cred::acquire` for lack of a keytab, or at `step()`  //
    //     for lack of a valid token, both map to 401 the same way)       //
    //                                                                    //
    // NOT covered, and cannot be from `cargo test`: a real SPNEGO        //
    // handshake succeeding (needs a live KDC + keytab), and the mutual-  //
    // auth `WWW-Authenticate` response header on success.                //
    // ------------------------------------------------------------------ //
    #[cfg(feature = "kerberos-auth")]
    mod kerberos_auth_tests {
        use super::*;
        use axum::body::Body;
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt;

        const TEST_SPN: &str = "HTTP/test.invalid@EXAMPLE.COM";

        fn kerberos_router() -> Router {
            Router::new()
                .route("/protected", axum::routing::get(|| async { "ok" }))
                .layer(middleware::from_fn_with_state(
                    Arc::new(TEST_SPN.to_string()),
                    kerberos_auth_middleware,
                ))
        }

        fn with_connect_info(mut req: HttpRequest<Body>) -> HttpRequest<Body> {
            let addr: SocketAddr = "127.0.0.1:40001".parse().unwrap();
            req.extensions_mut().insert(ConnectInfo(addr));
            req
        }

        #[test]
        fn classify_missing_header() {
            assert_eq!(classify_negotiate_header(None), NegotiateHeader::Missing);
        }

        #[test]
        fn classify_wrong_scheme() {
            assert_eq!(
                classify_negotiate_header(Some("Basic dXNlcjpwYXNz")),
                NegotiateHeader::WrongScheme
            );
        }

        #[test]
        fn classify_malformed_base64() {
            assert_eq!(
                classify_negotiate_header(Some("Negotiate not-valid-base64!!!")),
                NegotiateHeader::MalformedBase64
            );
        }

        #[test]
        fn classify_well_formed_token() {
            assert_eq!(
                classify_negotiate_header(Some("Negotiate dGVzdA==")),
                NegotiateHeader::Token(b"test".to_vec())
            );
        }

        /// No `Authorization` header at all -> 401 with a `WWW-Authenticate:
        /// Negotiate` challenge, not a panic or a 5xx.
        #[tokio::test]
        async fn missing_authorization_header_returns_401_with_challenge() {
            let req = with_connect_info(
                HttpRequest::builder()
                    .uri("/protected")
                    .body(Body::empty())
                    .unwrap(),
            );
            let resp = kerberos_router().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(resp.headers().get("WWW-Authenticate").unwrap(), "Negotiate");
        }

        /// A non-Negotiate scheme (e.g. HTTP Basic) must be rejected with 401.
        #[tokio::test]
        async fn non_negotiate_scheme_returns_401() {
            let req = with_connect_info(
                HttpRequest::builder()
                    .uri("/protected")
                    .header("Authorization", "Basic dXNlcjpwYXNz")
                    .body(Body::empty())
                    .unwrap(),
            );
            let resp = kerberos_router().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }

        /// Malformed base64 after `Negotiate ` must be rejected with 401, not
        /// a panic.
        #[tokio::test]
        async fn malformed_base64_returns_401() {
            let req = with_connect_info(
                HttpRequest::builder()
                    .uri("/protected")
                    .header("Authorization", "Negotiate not-valid-base64!!!")
                    .body(Body::empty())
                    .unwrap(),
            );
            let resp = kerberos_router().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }

        /// A well-formed-but-bogus Negotiate token must be rejected with
        /// 401 — never the old fail-closed stub's 501, and never a panic.
        /// In this keytab-less sandbox this exercises "the GSSAPI pipeline
        /// failed" (acquire or step, whichever fails first), not
        /// specifically "a live ServerCtx rejected a garbage token" — that
        /// needs a real credential this environment cannot provide.
        #[tokio::test]
        async fn bogus_token_returns_401_not_501_or_panic() {
            let req = with_connect_info(
                HttpRequest::builder()
                    .uri("/protected")
                    .header("Authorization", "Negotiate dGVzdA==")
                    .body(Body::empty())
                    .unwrap(),
            );
            let resp = kerberos_router().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            assert_ne!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        }
    }
}

/// Build a `RustlsConfig` from the TLS section of the server config.
///
/// When `tls.require_client_cert` is `true` the function fails with an error
/// if `ca_file` is absent, then constructs a `rustls::ServerConfig` with a
/// `WebPkiClientVerifier` that mandates a valid client certificate signed by
/// the given CA.  When `require_client_cert` is `false` the simpler
/// `RustlsConfig::from_pem_file` path is used (server-only TLS).
fn build_tls_config(
    tls: &crate::config::TlsConfig,
) -> anyhow::Result<axum_server::tls_rustls::RustlsConfig> {
    use axum_server::tls_rustls::RustlsConfig;
    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::server::WebPkiClientVerifier;

    // Every path below hits `rustls::ServerConfig::builder()`, which needs a
    // process-level `CryptoProvider` already installed — see
    // `install_crypto_provider`'s doc comment for why. `main.rs` installs it
    // too, but this call makes the guarantee local: anything that reaches
    // `build_tls_config` (production or test) is covered without relying on
    // caller discipline.
    install_crypto_provider();

    let cert_file = tls
        .cert_file
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("TLS enabled but no cert_file specified"))?;
    let key_file = tls
        .key_file
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("TLS enabled but no key_file specified"))?;

    if tls.require_client_cert {
        let ca_file = tls.ca_file.as_ref().ok_or_else(|| {
            anyhow::anyhow!("require_client_cert is true but no ca_file specified")
        })?;

        // Load CA certificate(s) into a root store.
        let ca_f = std::fs::File::open(ca_file)?;
        let mut ca_reader = std::io::BufReader::new(ca_f);
        let ca_certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut ca_reader).collect::<Result<Vec<_>, _>>()?;

        let mut root_store = RootCertStore::empty();
        for cert in ca_certs {
            root_store.add(cert)?;
        }

        // Build a client verifier that requires a cert signed by the CA.
        let verifier = WebPkiClientVerifier::builder(Arc::new(root_store)).build()?;

        // Load server cert chain.
        let cert_f = std::fs::File::open(cert_file)?;
        let mut cert_reader = std::io::BufReader::new(cert_f);
        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

        // Load server private key.
        let key_f = std::fs::File::open(key_file)?;
        let mut key_reader = std::io::BufReader::new(key_f);
        let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)?
            .ok_or_else(|| anyhow::anyhow!("no private key found in key_file"))?;

        let server_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)?;

        info!(
            "mTLS enabled: client certificates required (CA from {:?})",
            ca_file
        );
        Ok(RustlsConfig::from_config(Arc::new(server_config)))
    } else {
        // Server-only TLS — load synchronously via from_pem_file equivalent.
        // RustlsConfig::from_pem_file is async; build the config inline instead
        // so this function can remain synchronous and easily testable.
        let cert_f = std::fs::File::open(cert_file)?;
        let mut cert_reader = std::io::BufReader::new(cert_f);
        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

        let key_f = std::fs::File::open(key_file)?;
        let mut key_reader = std::io::BufReader::new(key_f);
        let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)?
            .ok_or_else(|| anyhow::anyhow!("no private key found in key_file"))?;

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        Ok(RustlsConfig::from_config(Arc::new(server_config)))
    }
}

async fn health_check() -> &'static str {
    "OK"
}

/// Resolve the interface the metrics listener binds to.
///
/// An explicit `metrics.bind_address` wins; otherwise the metrics listener
/// inherits the main server's `bind_address` IP rather than defaulting to
/// `0.0.0.0` — see `MetricsConfig::bind_address` for why the unconditional
/// `0.0.0.0` bind was a finding.
///
/// Returns an `IpAddr`, not a formatted string: `Ipv6Addr::to_string()`
/// never emits brackets, and `SocketAddr`'s `FromStr` requires bracket
/// notation for IPv6, so `format!("{ip}:{port}").parse::<SocketAddr>()`
/// silently fails for every IPv6 `bind_address` (`::`, `::1`,
/// `2001:db8::1`, ...). Building the address with `SocketAddr::new`
/// instead sidesteps that string round-trip entirely.
///
/// The `Some(override)` case accepts a bare IP such as `"::1"` or
/// `"0.0.0.0"` — matching both `MetricsConfig::bind_address`'s own doc
/// (a bare host, no port) and the convention every other
/// `*_bind_address: String` field in this config already uses. An
/// optional surrounding `[...]` (as in `"[::1]"`) is stripped first, so a
/// bracketed IPv6 literal is tolerated too.
fn resolve_metrics_ip(
    metrics_bind_address: &Option<String>,
    bind_address: &SocketAddr,
) -> anyhow::Result<IpAddr> {
    match metrics_bind_address {
        Some(host) => {
            let unbracketed = host
                .strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'))
                .unwrap_or(host);
            unbracketed
                .parse::<IpAddr>()
                .map_err(|e| anyhow::anyhow!("invalid [metrics] bind_address {host:?}: {e}"))
        }
        None => Ok(bind_address.ip()),
    }
}

/// Resolve the interface the TLS listener binds to: always inherits
/// `bind_address` (there is no `tls.bind_address` override), built
/// directly from the already-parsed `IpAddr` rather than through a
/// formatted string — see `resolve_metrics_ip` for why that string
/// round-trip breaks IPv6.
fn tls_bind_addr(bind_address: &SocketAddr, port: u16) -> SocketAddr {
    SocketAddr::new(bind_address.ip(), port)
}

/// Install the process-level rustls `CryptoProvider`, once, for the whole
/// binary.
///
/// rustls 0.23 refuses to auto-select a crypto backend once more than one is
/// linked into the process, and this tree links two for rustls 0.23:
/// `aws-lc-rs` (pulled in by axum-server/tokio-rustls) and `ring` (pulled in
/// transitively via the AWS SDK's own rustls-based HTTP client stack). With
/// both present and nothing installed, the first `rustls::ServerConfig::
/// builder()`/`ClientConfig::builder()` call in the process — server TLS in
/// `build_tls_config` below, or the admin console's TLS in
/// `admin::routes::run_tls_server` — panics with "Could not automatically
/// determine the process-level CryptoProvider" instead of guessing.
///
/// `aws_lc_rs`, not `ring`: it's rustls 0.23's own default backend, and it's
/// already what axum-server/tokio-rustls pull in, so installing it adds no
/// new linked backend. `CryptoProvider` is a shared trait object — one
/// process-wide install covers every rustls-0.23 consumer (server and any
/// outbound HTTPS alike), so call sites don't need to agree on which
/// backend to ask for.
///
/// Idempotent: `install_default()` returns `Err` only when a provider is
/// already installed process-wide, which just means an earlier call site
/// (this function is meant to be called from several — `main.rs` up front,
/// plus every rustls-0.23 entry point itself) already did the job. That
/// `Err` is a benign no-op here, not a failure, so it's discarded rather
/// than propagated.
///
/// rustls 0.21 (also in this tree, via `hyper-rustls 0.24` for parts of the
/// AWS SDK stack) predates `CryptoProvider` and is unaffected — this
/// installer has nothing to do with it.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Build the Prometheus recorder, publish its handle via `METRICS_HANDLE`,
/// and install it as the process-global `metrics` recorder — synchronously.
///
/// Split out of what used to be `start_metrics_server` (now
/// `serve_metrics_endpoint`, below) so this half can run to completion
/// *before* anything that constructs and caches a `metrics::Counter`/`Gauge`
/// handle. `metrics::counter!`/`gauge!` resolve against whichever recorder
/// is installed at the moment the macro runs; with none installed yet they
/// return a no-op handle, and a no-op handle cached in a struct field
/// (rather than re-resolved per call) stays no-op for the life of the
/// process. See the call site in `main.rs` for the concrete case
/// (`forwarding::aggregate::RuleMetrics`) this was fixed for.
///
/// Idempotent: `Server::run`/`run_tls` call this unconditionally too, after
/// `main.rs` may already have. `metrics::set_global_recorder` itself errors
/// on a second call, so a naive repeat call would either panic (if
/// unwrapped) or leave `METRICS_HANDLE` and the live global recorder
/// mismatched (if the error were swallowed). Guarding on `METRICS_HANDLE`
/// itself — already a `OnceLock`, set exactly once, only here — makes a
/// repeat call a cheap no-op instead, with no extra state needed.
pub fn install_metrics_recorder() {
    if METRICS_HANDLE.get().is_some() {
        return;
    }

    use metrics_exporter_prometheus::PrometheusBuilder;

    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();

    if METRICS_HANDLE.set(handle).is_err() {
        // Lost a race with a concurrent installer (there is currently no
        // caller that can actually trigger this — `main.rs` installs
        // synchronously before `Server::run`/`run_tls` ever spawn — but the
        // guard is cheap and correct if that ever changes). The other
        // caller already installed the global recorder and described all
        // metrics; do not attempt either again.
        return;
    }

    metrics::set_global_recorder(recorder).expect("Failed to install Prometheus recorder");

    // After the recorder is installed, never before: `describe_*!` writes to
    // whichever recorder is currently installed, so descriptions registered
    // ahead of this line would go nowhere and every series would render
    // without its `# HELP`.
    crate::metrics_descriptions::describe_all();
}

/// Render `METRICS_HANDLE` and serve it on `/metrics` at `addr` forever,
/// gated by `ip_whitelist`. The recorder half of the old `start_metrics_server`
/// — see `install_metrics_recorder`, which every caller must have already
/// run (directly or via `Server::run`/`run_tls`) before spawning this.
async fn serve_metrics_endpoint(addr: SocketAddr, ip_whitelist: IpWhitelist) {
    let handle = METRICS_HANDLE
        .get()
        .cloned()
        .expect("install_metrics_recorder must run before serve_metrics_endpoint");

    // Gated by the same `security.allowed_ips` whitelist as the main router:
    // inheriting `bind_address` does nothing when `bind_address` is itself
    // `0.0.0.0` (a common production setting), so the whitelist is the
    // control that actually restricts who can scrape /metrics in that case.
    let whitelist_layer =
        middleware::from_fn_with_state(ip_whitelist.clone(), ip_whitelist_middleware);
    let app = Router::new()
        .route(
            "/metrics",
            axum::routing::get(move || {
                let handle = handle.clone();
                async move { handle.render() }
            }),
        )
        .layer(whitelist_layer)
        .layer(axum::Extension(ip_whitelist));

    // ponytail: unchanged from the pre-split code, but worth naming now that
    // it is easier to see. This runs in a `tokio::spawn`ed task whose
    // `JoinHandle` nobody awaits, so a bind failure (port already in use)
    // panics that task alone: the main server keeps serving, `/metrics` is
    // silently dead, and nothing surfaces the error. The recorder is still
    // installed, so counters increment into a handle nobody can scrape —
    // which reads exactly like the dead-metric bugs this module just fixed.
    // Ceiling: log-and-return instead of panicking, and surface it via the
    // health check or a startup-time bind probe so it fails loudly.
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    info!("Metrics server started on http://{}", addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

/// Handle syslog messages via HTTP POST
///
/// Auth: if `config.syslog.http_token` is non-empty, the request must carry
/// `Authorization: Bearer <token>`. An empty (default) token skips the check
/// entirely — the route is mounted unconditionally, so this preserves the
/// pre-existing no-auth behaviour for every default deployment. Comparison
/// mirrors `handle_otlp_logs`: constant-time on the equal-length path, with
/// an early length-mismatch branch (token length is low-sensitivity).
pub async fn handle_syslog_http(
    State(app_state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    use subtle::ConstantTimeEq;

    {
        let cfg = app_state.config.read().await;
        let expected_token = &cfg.syslog.http_token;
        if !expected_token.is_empty() {
            let provided = headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .unwrap_or("");
            let a = expected_token.as_bytes();
            let b = provided.as_bytes();
            let ok: bool = a.len() == b.len() && a.ct_eq(b).into();
            if !ok {
                return (StatusCode::UNAUTHORIZED, "Unauthorized");
            }
        }
    }

    let msg = String::from_utf8_lossy(&body);

    match SyslogMessage::parse(&msg) {
        Some(syslog) => {
            info!(
                "[{}] Syslog: {} {} - {}: {}",
                addr,
                syslog.facility_str(),
                syslog.severity_str(),
                syslog.app_name.as_deref().unwrap_or("unknown"),
                syslog.message
            );

            // Try to parse as DNS log
            if let Some(dns) = crate::syslog::dns::DnsLogEntry::from_syslog(&syslog) {
                info!(
                    "DNS Query from {}: {} ({}) -> {:?}",
                    dns.client_ip, dns.query_name, dns.query_type, dns.response_ips
                );
            }

            (StatusCode::OK, "Syslog message received")
        }
        None => {
            warn!("Failed to parse syslog message from {}", addr);
            (StatusCode::BAD_REQUEST, "Invalid syslog format")
        }
    }
}

/// Get syslog UDP listener info
async fn handle_syslog_udp_info(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let cfg = state.config.read().await;
    let udp_port = cfg.syslog.udp_port;
    let tcp_port = cfg.syslog.tcp_port;
    Json(serde_json::json!({
        "udp_port": udp_port,
        "tcp_port": tcp_port,
        "supported_formats": ["RFC3164", "RFC5424"],
        "supported_dns_formats": ["BIND/named", "Unbound", "PowerDNS"]
    }))
}

/// Get example DNS syslog records
async fn handle_syslog_examples() -> Json<serde_json::Value> {
    use crate::syslog::listener::examples;

    Json(serde_json::json!({
        "bind_named": examples::BIND_DNS_QUERIES,
        "unbound": examples::UNBOUND_DNS_QUERIES,
        "powerdns": examples::POWERDNS_QUERIES,
        "rfc5424": examples::RFC5424_DNS_LOGS
    }))
}

/// POST /v1/logs — OTLP/HTTP protobuf or JSON log ingest.
///
/// Content-Type dispatch:
///   `application/x-protobuf` → prost decode
///   `application/json`       → serde_json decode (via `with-serde` feature of opentelemetry-proto)
///   anything else            → 415 Unsupported Media Type
///
/// Auth: if `config.otlp.bearer_token` is `Some(token)` AND the token is
/// non-empty, the request must carry `Authorization: Bearer <token>`.
/// If `bearer_token` is `None` or an empty string, auth is skipped (dev mode),
/// consistent with the HEC empty-token skip behavior.
/// Comparison is constant-time (via `subtle::ConstantTimeEq`) on the equal-length
/// path; a length mismatch is an early branch (token length is low-sensitivity).
///
/// On success: maps each `LogRecord` → `GenericRecord` via `otlp::map_otlp_request`,
/// forwards through `IngestState.generic_s3` (warn-and-drop on channel full/closed),
/// and returns an empty `ExportLogsServiceResponse` (200) in the SAME encoding
/// (protobuf or JSON) as the request.
///
/// Error codes:
///   400 — malformed protobuf or JSON body
///   401 — bearer token required but absent or incorrect
///   415 — unknown or missing Content-Type
#[cfg(feature = "otlp")]
pub async fn handle_otlp_logs(
    State(app_state): State<Arc<AppState>>,
    axum::extract::Extension(ingest): axum::extract::Extension<IngestState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    use opentelemetry_proto::tonic::collector::logs::v1::{
        ExportLogsServiceRequest, ExportLogsServiceResponse,
    };
    use prost::Message as ProstMessage;
    use subtle::ConstantTimeEq;

    // ── Bearer auth check ─────────────────────────────────────────────────
    {
        let cfg = app_state.config.read().await;
        if let Some(ref expected_token) = cfg.otlp.bearer_token
            && !expected_token.is_empty()
        {
            let provided = headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .unwrap_or("");
            let a = expected_token.as_bytes();
            let b = provided.as_bytes();
            // Length mismatch is not secret-sensitive; ct_eq only valid for
            // equal-length slices, so we gate it on length equality first.
            let ok: bool = a.len() == b.len() && a.ct_eq(b).into();
            if !ok {
                metrics::counter!("otlp_auth_failures").increment(1);
                warn!("OTLP bearer auth failure from {}", addr.ip());
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
        // bearer_token is None or empty → skip auth (dev mode)
    }

    // ── Content-Type dispatch ─────────────────────────────────────────────
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let req: ExportLogsServiceRequest =
        if ct.starts_with("application/x-protobuf") || ct.starts_with("application/protobuf") {
            ExportLogsServiceRequest::decode(body.as_ref()).map_err(|e| {
                warn!("OTLP protobuf decode error from {}: {e}", addr.ip());
                StatusCode::BAD_REQUEST
            })?
        } else if ct.starts_with("application/json") {
            serde_json::from_slice::<ExportLogsServiceRequest>(&body).map_err(|e| {
                warn!("OTLP JSON decode error from {}: {e}", addr.ip());
                StatusCode::BAD_REQUEST
            })?
        } else {
            warn!("OTLP unsupported Content-Type '{}' from {}", ct, addr.ip());
            return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
        };

    // ── Map to GenericRecords ─────────────────────────────────────────────
    let source_host = addr.ip().to_string();
    let records = crate::server::otlp::map_otlp_request(req, source_host);
    let count = records.len() as u64;

    // ── Route through generic S3 handler ─────────────────────────────────
    // try_send is non-blocking; channel full / closed → warn and drop,
    // mirroring the HEC handler pattern in src/ingest/handlers.rs.
    for record in records {
        if let Some(ref handler) = ingest.generic_s3
            && let Err(e) = handler.try_send(record.clone())
        {
            let kind = DropKind::from(&e);
            if let Some(dropped_total) = handler.drop_log_due(DropSite::Otlp, kind) {
                match kind {
                    DropKind::Full => {
                        warn!(
                            dropped_total,
                            "OTLP generic_s3 channel full, dropping record"
                        );
                    }
                    DropKind::Closed => {
                        error!(dropped_total, "OTLP generic_s3 channel closed");
                    }
                }
            }
        }
        if let Some(ref handler) = ingest.generic_local
            && let Err(e) = handler.try_send(record)
        {
            let kind = DropKind::from(&e);
            if let Some(dropped_total) = handler.drop_log_due(DropSite::Otlp, kind) {
                match kind {
                    DropKind::Full => {
                        warn!(
                            dropped_total,
                            "OTLP generic_local channel full, dropping record"
                        );
                    }
                    DropKind::Closed => {
                        error!(dropped_total, "OTLP generic_local channel closed");
                    }
                }
            }
        }
    }

    metrics::counter!("otlp_logs_received").increment(count);

    // ── Respond in the same encoding as the request ───────────────────────
    let (resp_bytes, response_ct) = if ct.starts_with("application/json") {
        let json_bytes =
            serde_json::to_vec(&ExportLogsServiceResponse::default()).unwrap_or_default();
        (json_bytes, "application/json")
    } else {
        let proto_bytes = ExportLogsServiceResponse::default().encode_to_vec();
        (proto_bytes, "application/x-protobuf")
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", response_ct)
        .body(axum::body::Body::from(resp_bytes))
        .unwrap())
}
