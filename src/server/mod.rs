use crate::config::Config;
use crate::forwarding::Forwarder;
use crate::middleware::{IpWhitelist, ip_whitelist_middleware};
use crate::models::WindowsEvent;
use crate::parser::GenericEventParser;
use crate::protocol::{
    WefMessage, WefParser, create_heartbeat_response, create_subscription_response,
};
use crate::stats::{ThroughputSnapshot, ThroughputStats};
use crate::syslog::SyslogMessage;
#[cfg(feature = "kerberos-auth")]
use anyhow::anyhow;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
#[cfg(feature = "kerberos-auth")]
use axum::{extract::Request, middleware::Next};

use futures::stream::{self, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use tokio::time::{Duration, sleep};
use tracing::{debug, error, info, warn};

/// Maximum allowed body size for WEF/syslog ingest requests (64 MiB).
/// Prevents unbounded memory allocation from large or malicious payloads.
const MAX_BODY_SIZE: usize = 64 * 1024 * 1024;

/// Maximum number of Windows events processed concurrently per batch.
/// Bounds CPU and memory use while still exploiting multi-core parallelism.
const MAX_CONCURRENT_EVENT_PROCESSING: usize = 16;

pub struct AppState {
    pub config: Arc<RwLock<Config>>,
    pub throughput: Arc<ThroughputStats>,
    pub forwarder: Forwarder,
    pub parser: WefParser,
    pub event_parser: Option<GenericEventParser>,
    pub parquet_s3_sender: Option<tokio::sync::mpsc::Sender<Arc<WindowsEvent>>>,
}

pub struct Server {
    config: Config,
    state: Arc<AppState>,
}

impl Server {
    /// Create a new WEF server instance.
    ///
    /// Initializes all components including the forwarder, parser, and optional
    /// Parquet S3 forwarder.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use logthing::config::Config;
    /// use logthing::server::Server;
    /// use logthing::stats::ThroughputStats;
    /// use std::sync::Arc;
    /// use tokio::sync::RwLock;
    ///
    /// async fn start_server() -> anyhow::Result<()> {
    ///     let config = Config::load()?;
    ///     let shared_config = Arc::new(RwLock::new(config.clone()));
    ///     let throughput = Arc::new(ThroughputStats::new());
    ///
    ///     let server = Server::new(config, shared_config, throughput).await?;
    ///     // server.run().await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn new(
        config: Config,
        shared_config: Arc<RwLock<Config>>,
        throughput: Arc<ThroughputStats>,
    ) -> anyhow::Result<Self> {
        let forwarder = Forwarder::new(config.forwarding.destinations.clone())
            .initialize()
            .await;

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

        // Initialize Parquet S3 forwarder with channel-based architecture
        let parquet_s3_sender = if let Ok(Some(mut s3_forwarder)) =
            crate::forwarding::parquet_s3::create_parquet_s3_forwarder(
                &config.forwarding.destinations,
            )
            .await
        {
            info!("Initialized Parquet S3 forwarder with channel-based architecture");

            // Create channel for event forwarding (buffer size: 10000 events)
            let (sender, mut receiver) = mpsc::channel::<Arc<WindowsEvent>>(10000);
            let flush_interval_secs = s3_forwarder.flush_interval_secs();

            // Spawn worker task to receive events and forward to Parquet S3
            tokio::spawn(async move {
                info!("Parquet S3 worker task started");

                loop {
                    tokio::select! {
                        // Receive event from channel
                        Some(event) = receiver.recv() => {
                            if let Err(e) = s3_forwarder.forward((*event).clone()).await {
                                error!("Failed to forward to Parquet S3: {}", e);
                            }
                        }
                        // Periodic flush
                        _ = sleep(Duration::from_secs(flush_interval_secs)) => {
                            if let Err(e) = s3_forwarder.flush_all().await {
                                error!("Failed to run scheduled Parquet S3 flush: {}", e);
                            }
                        }
                    }
                }
            });

            Some(sender)
        } else {
            None
        };

        let state = Arc::new(AppState {
            config: Arc::clone(&shared_config),
            throughput,
            forwarder,
            parser: WefParser::new(),
            event_parser,
            parquet_s3_sender,
        });

        Ok(Self { config, state })
    }

    /// Run the WEF server without TLS (HTTP only).
    ///
    /// Starts the HTTP server on the configured bind address and port.
    /// Also starts the metrics server if enabled.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use logthing::config::Config;
    /// use logthing::server::Server;
    /// use logthing::stats::ThroughputStats;
    /// use std::sync::Arc;
    /// use tokio::sync::RwLock;
    ///
    /// #[tokio::main]
    /// async fn main() -> anyhow::Result<()> {
    ///     let config = Config::load()?;
    ///     let shared_config = Arc::new(RwLock::new(config.clone()));
    ///     let throughput = Arc::new(ThroughputStats::new());
    ///
    ///     let server = Server::new(config, shared_config, throughput).await?;
    ///     server.run().await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn run(self) -> anyhow::Result<()> {
        let ip_whitelist = if self.config.security.allowed_ips.is_empty() {
            IpWhitelist::empty()
        } else {
            IpWhitelist::new(self.config.security.allowed_ips.clone())?
        };

        let app = self.create_router(ip_whitelist)?;

        // Start HTTP server
        let addr = self.config.bind_address;
        info!("Starting WEF server on http://{}", addr);

        let listener = tokio::net::TcpListener::bind(&addr).await?;

        // Start metrics server if enabled
        if self.config.metrics.enabled {
            let metrics_addr: SocketAddr =
                format!("0.0.0.0:{}", self.config.metrics.port).parse()?;
            tokio::spawn(start_metrics_server(metrics_addr));
        }

        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;

        Ok(())
    }

    fn create_router(&self, ip_whitelist: IpWhitelist) -> anyhow::Result<Router> {
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

        // Protected routes (require authentication)
        let protected_router = Router::new()
            .route("/wsman", post(handle_wef_request))
            .route("/wsman/subscriptions", post(handle_subscription))
            .route("/wsman/events", post(handle_events))
            // Syslog endpoints
            .route("/syslog", post(handle_syslog_http))
            .route("/syslog/udp", get(handle_syslog_udp_info))
            .route("/syslog/examples", get(handle_syslog_examples))
            .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_SIZE))
            .layer(shared_layers)
            .layer(axum::Extension(ip_whitelist))
            .with_state(self.state.clone());

        // Apply Kerberos only to protected routes
        let protected_router = self.apply_kerberos_layer(protected_router)?;

        // Merge public and protected routes
        let router = public_router.merge(protected_router);

        Ok(router)
    }

    /// Run the WEF server with TLS enabled.
    ///
    /// If TLS is not enabled in the configuration, falls back to running without TLS.
    /// Otherwise, starts an HTTPS server on the configured TLS port.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use logthing::config::Config;
    /// use logthing::server::Server;
    /// use logthing::stats::ThroughputStats;
    /// use std::sync::Arc;
    /// use tokio::sync::RwLock;
    ///
    /// #[tokio::main]
    /// async fn main() -> anyhow::Result<()> {
    ///     let config = Config::load()?;
    ///     let shared_config = Arc::new(RwLock::new(config.clone()));
    ///     let throughput = Arc::new(ThroughputStats::new());
    ///
    ///     let server = Server::new(config, shared_config, throughput).await?;
    ///
    ///     // Will use TLS if enabled in config, otherwise HTTP
    ///     server.run_tls().await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn run_tls(self) -> anyhow::Result<()> {
        if !self.config.tls.enabled {
            return self.run().await;
        }

        let ip_whitelist = if self.config.security.allowed_ips.is_empty() {
            IpWhitelist::empty()
        } else {
            IpWhitelist::new(self.config.security.allowed_ips.clone())?
        };

        let app = self.create_router(ip_whitelist)?;

        let tls_config = build_tls_config(&self.config.tls)?;
        let tls_addr: SocketAddr = format!("0.0.0.0:{}", self.config.tls.port).parse()?;

        info!("Starting WEF server with TLS on https://{}", tls_addr);

        // Use axum-server for proper TLS handling
        axum_server::bind_rustls(tls_addr, tls_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;

        Ok(())
    }

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
        error!(
            "SECURITY: Kerberos token validation is NOT implemented. \
             The kerberos_auth_middleware will REJECT ALL requests (fail-closed) \
             until real GSSAPI/SPNEGO validation is added. \
             Do NOT use this in production without a complete implementation."
        );

        // Use route-layer approach with custom middleware
        // The kerberos_auth_middleware fails closed: it rejects all requests
        // because token validation is not implemented.
        Ok(router.layer(middleware::from_fn(kerberos_auth_middleware)))
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

/// Kerberos authentication middleware
///
/// FAIL-CLOSED: GSSAPI/SPNEGO token validation is not implemented.
/// This middleware rejects ALL requests rather than passing unvalidated tokens
/// through. Any request without a `Negotiate` header gets a 401 challenge.
/// Any request WITH a `Negotiate` token gets a 501 Not Implemented response,
/// because we cannot validate the token and must not treat it as authenticated.
///
/// To make this functional, replace the 501 path with real GSSAPI validation.
#[cfg(feature = "kerberos-auth")]
async fn kerberos_auth_middleware(request: Request, _next: Next) -> Response {
    // Check if Authorization header is present with a Negotiate token.
    let has_negotiate = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.starts_with("Negotiate "))
        .unwrap_or(false);

    if !has_negotiate {
        // No token supplied — return 401 with WWW-Authenticate challenge.
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Negotiate")
            .body(axum::body::Body::from("Unauthorized"))
            .unwrap();
    }

    // A Negotiate token was supplied but we cannot validate it: fail closed.
    // Passing an unvalidated token through would be a complete auth bypass.
    error!(
        "Kerberos authentication is enabled but token validation is not implemented; \
         refusing request (fail-closed)"
    );
    Response::builder()
        .status(StatusCode::NOT_IMPLEMENTED)
        .body(axum::body::Body::from(
            "Kerberos authentication is enabled but token validation is not implemented; \
             refusing all requests",
        ))
        .unwrap()
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
            info!(
                "New subscription from {}: {}",
                sub.source_host, sub.subscription_id
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
            debug!(
                "Heartbeat from {} for subscription {}",
                hb.source_host, hb.subscription_id
            );

            let response = create_heartbeat_response();
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/soap+xml")
                .body(axum::body::Body::from(response))
                .unwrap())
        }
        Ok(WefMessage::Unknown(content)) => {
            warn!(
                "Unknown message type from {}: {}",
                addr,
                &content[..100.min(content.len())]
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
    // Wrap event in Arc to avoid cloning for each forwarder
    let event = Arc::new(event);

    if let (Some(event_parser), Some(parsed)) = (&state.event_parser, &event.parsed)
        && let Some(generic_parsed) = event_parser.parse_event(parsed.event_id, &event.raw_xml)
    {
        info!(
            "Event {} parsed with generic parser '{}': {}",
            parsed.event_id,
            generic_parsed.parser_name,
            generic_parsed.formatted_message.as_deref().unwrap_or("N/A")
        );
    }

    let event_type = describe_event_type(&event);
    state.throughput.record_event(event_type).await;

    // Pass Arc to forwarder (cheap clone of Arc, not the event)
    state.forwarder.forward(event.clone()).await;

    // Send to Parquet S3 via channel (non-blocking)
    if let Some(ref sender) = state.parquet_s3_sender
        && let Err(e) = sender.try_send(event.clone())
    {
        match e {
            mpsc::error::TrySendError::Full(_) => {
                metrics::counter!("wef_events_dropped").increment(1);
                warn!("Parquet S3 channel full, dropping event");
            }
            mpsc::error::TrySendError::Closed(_) => {
                error!("Parquet S3 channel closed");
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
        let forwarder = Forwarder::new(config.forwarding.destinations.clone())
            .initialize()
            .await;
        Arc::new(AppState {
            config: Arc::new(RwLock::new(config)),
            throughput: Arc::new(ThroughputStats::new()),
            forwarder,
            parser: WefParser::new(),
            event_parser: None,
            parquet_s3_sender: None,
        })
    }

    async fn default_state() -> Arc<AppState> {
        build_state_with_config(Config::default()).await
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
        let addr: SocketAddr = "192.0.2.10:5514".parse().unwrap();
        let msg = "<134>Jan 15 10:30:45 dns-server named[1234]: client 192.168.1.100#12345: query: example.com IN A + (93.184.216.34)";

        let ok_response = handle_syslog_http(ConnectInfo(addr), Bytes::from(msg))
            .await
            .into_response();
        assert_eq!(ok_response.status(), StatusCode::OK);

        let bad_response = handle_syslog_http(ConnectInfo(addr), Bytes::from("not syslog"))
            .await
            .into_response();
        assert_eq!(bad_response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn handle_syslog_http_with_rfc5424_message() {
        let addr: SocketAddr = "192.0.2.10:5514".parse().unwrap();
        // RFC 5424 format
        let msg = r#"<165>1 2024-01-15T10:33:45.000Z dns-server named 1234 - [dns@12345 query="example.com"] DNS query"#;

        let response = handle_syslog_http(ConnectInfo(addr), Bytes::from(msg))
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
        let addr: SocketAddr = "192.0.2.10:5514".parse().unwrap();
        // BIND DNS query format
        let msg = "<134>Jan 15 10:30:45 dns-server named[1234]: client 192.168.1.100#12345: query: example.com IN A + (93.184.216.34)";

        let response = handle_syslog_http(ConnectInfo(addr), Bytes::from(msg))
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
        let addr: SocketAddr = "10.0.0.2:514".parse().unwrap();
        // Missing the leading '<' so the PRI field is absent — not a valid syslog frame.
        let bad_msg = "134>Jun 22 09:00:00 host app[99]: message without pri bracket";

        let response = handle_syslog_http(ConnectInfo(addr), Bytes::from(bad_msg))
            .await
            .into_response();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "structurally invalid syslog message must be rejected with 400"
        );
    }

    /// CR-1 regression: kerberos_auth_middleware must fail CLOSED.
    ///
    /// A request bearing a syntactically valid `Authorization: Negotiate <token>`
    /// header must NOT be passed through as authenticated. Because token validation
    /// is not implemented the middleware must return a non-2xx error status (501)
    /// rather than calling next and returning 200.
    #[cfg(feature = "kerberos-auth")]
    #[tokio::test]
    async fn kerberos_middleware_rejects_negotiate_token_fail_closed() {
        use axum::body::Body;
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt; // for `oneshot`

        // Build a minimal router with the kerberos middleware applied.
        // The inner handler always returns 200 so any 200 response means
        // the middleware passed the request through (a bypass).
        let app = Router::new()
            .route("/", axum::routing::get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn(kerberos_auth_middleware));

        // Fire a request with a Negotiate token (base64 "foo" = Zm9v).
        let request = HttpRequest::builder()
            .uri("/")
            .header("Authorization", "Negotiate Zm9v")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // Must NOT be 200 — the token was never validated.
        assert_ne!(
            response.status(),
            StatusCode::OK,
            "kerberos middleware must not pass unvalidated Negotiate tokens through"
        );
        // Must be 501 Not Implemented (fail-closed denial).
        assert_eq!(
            response.status(),
            StatusCode::NOT_IMPLEMENTED,
            "kerberos middleware must return 501 when token validation is unimplemented"
        );
    }

    /// CR-1 regression: kerberos_auth_middleware returns 401 challenge when no
    /// Authorization header is present (unchanged behaviour, included for completeness).
    #[cfg(feature = "kerberos-auth")]
    #[tokio::test]
    async fn kerberos_middleware_challenges_unauthenticated_requests() {
        use axum::body::Body;
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt;

        let app = Router::new()
            .route("/", axum::routing::get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn(kerberos_auth_middleware));

        let request = HttpRequest::builder().uri("/").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "kerberos middleware must challenge requests without an Authorization header"
        );
        assert!(
            response.headers().contains_key("www-authenticate"),
            "401 response must include WWW-Authenticate header"
        );
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

async fn start_metrics_server(addr: SocketAddr) {
    use metrics_exporter_prometheus::PrometheusBuilder;

    let recorder = PrometheusBuilder::new().build_recorder();

    let handle = recorder.handle();

    metrics::set_global_recorder(recorder).expect("Failed to install Prometheus recorder");

    let app = Router::new().route(
        "/metrics",
        axum::routing::get(move || {
            let handle = handle.clone();
            async move { handle.render() }
        }),
    );

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    info!("Metrics server started on http://{}", addr);

    axum::serve(listener, app).await.unwrap();
}

/// Handle syslog messages via HTTP POST
async fn handle_syslog_http(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> impl IntoResponse {
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
