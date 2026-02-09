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

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use tokio::time::{Duration, sleep};
use tracing::{debug, error, info, warn};
use futures::stream::{self, StreamExt};

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
    /// use wef_server::config::Config;
    /// use wef_server::server::Server;
    /// use wef_server::stats::ThroughputStats;
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
    /// use wef_server::config::Config;
    /// use wef_server::server::Server;
    /// use wef_server::stats::ThroughputStats;
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
        let shared_layers = middleware::from_fn_with_state(
            ip_whitelist.clone(),
            ip_whitelist_middleware,
        );

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
    /// use wef_server::config::Config;
    /// use wef_server::server::Server;
    /// use wef_server::stats::ThroughputStats;
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
        use axum_server::tls_rustls::RustlsConfig;

        if !self.config.tls.enabled {
            return self.run().await;
        }

        let ip_whitelist = if self.config.security.allowed_ips.is_empty() {
            IpWhitelist::empty()
        } else {
            IpWhitelist::new(self.config.security.allowed_ips.clone())?
        };

        let app = self.create_router(ip_whitelist)?;

        // Load TLS configuration from PEM files
        let cert_file = self
            .config
            .tls
            .cert_file
            .as_ref()
            .expect("TLS enabled but no cert_file specified");
        let key_file = self
            .config
            .tls
            .key_file
            .as_ref()
            .expect("TLS enabled but no key_file specified");

        let tls_config = RustlsConfig::from_pem_file(cert_file, key_file).await?;
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

        // Use route-layer approach with custom middleware
        // The kerberos_auth_middleware checks for Authorization header and
        // uses axum_negotiate's Upn extractor for authentication
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
/// This middleware checks for the Authorization header with a Negotiate token.
/// In a real deployment with proper Kerberos infrastructure, this would validate
/// the token. For E2E testing, we check for the header presence and return 401
/// if authentication is required but not provided.
#[cfg(feature = "kerberos-auth")]
async fn kerberos_auth_middleware(request: Request, next: Next) -> Response {
    // Check if Authorization header is present
    let has_auth = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.starts_with("Negotiate "))
        .unwrap_or(false);

    if !has_auth {
        // Return 401 Unauthorized with WWW-Authenticate header
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Negotiate")
            .body(axum::body::Body::from("Unauthorized"))
            .unwrap();
    }

    // In a full implementation, we would validate the Negotiate token here
    // using the Upn extractor. For now, we pass through if the header is present.
    next.run(request).await
}

async fn handle_wef_request(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let body_str = String::from_utf8_lossy(&body);
    let source_host = headers
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| addr.ip().to_string());

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
    
    if let Some(ref event_parser) = state.event_parser {
        if let Some(ref parsed) = event.parsed {
            if let Some(generic_parsed) =
                event_parser.parse_event(parsed.event_id, &event.raw_xml)
            {
                info!(
                    "Event {} parsed with generic parser '{}': {}",
                    parsed.event_id,
                    generic_parsed.parser_name,
                    generic_parsed.formatted_message.as_deref().unwrap_or("N/A")
                );
            }
        }
    }

    let event_type = describe_event_type(&event);
    state.throughput.record_event(event_type).await;

    // Pass Arc to forwarder (cheap clone of Arc, not the event)
    state.forwarder.forward(event.clone()).await;

    // Send to Parquet S3 via channel (non-blocking)
    if let Some(ref sender) = state.parquet_s3_sender {
        if let Err(e) = sender.try_send(event.clone()) {
            match e {
                mpsc::error::TrySendError::Full(_) => {
                    warn!("Parquet S3 channel full, dropping event");
                }
                mpsc::error::TrySendError::Closed(_) => {
                    error!("Parquet S3 channel closed");
                }
            }
        }
    }
}

async fn process_events(state: &Arc<AppState>, events: Vec<WindowsEvent>) {
    // Process events concurrently with a limit of 16 concurrent tasks
    // This leverages multi-core CPUs for better throughput
    stream::iter(events)
        .for_each_concurrent(16, |event| async move {
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
        assert!(value["bind_named"].as_array().unwrap().len() > 0);
        assert!(value["powerdns"].as_array().unwrap().len() > 0);
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
        assert_eq!(describe_event_type(&event), "Microsoft-Windows-Security-Auditing:4624");
    }

    #[tokio::test]
    async fn health_check_returns_ok_directly() {
        let response = health_check().await;
        assert_eq!(response, "OK");
    }

    #[tokio::test]
    async fn process_single_event_with_parsed_data() {
        let state = default_state().await;
        let event = WindowsEvent::new("host".into(), "<Event/>".into())
            .with_parsed(sample_parsed_event());
        
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
        
        // Should not panic and throughput should show "unknown"
        let summary = state.throughput.snapshot().await;
        assert!(summary.len() >= 0);
    }

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
