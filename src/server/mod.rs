use crate::config::Config;
use crate::forwarding::{Forwarder, parquet_s3::ParquetS3Forwarder};
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
use axum_negotiate::NegotiateAuthLayer;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, sleep};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

pub struct AppState {
    pub config: Arc<RwLock<Config>>,
    pub throughput: Arc<ThroughputStats>,
    pub forwarder: Forwarder,
    pub parser: WefParser,
    pub event_parser: Option<GenericEventParser>,
    pub parquet_s3_forwarder: Option<tokio::sync::Mutex<ParquetS3Forwarder>>,
}

pub struct Server {
    config: Config,
    state: Arc<AppState>,
}

impl Server {
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
                    std::env::set_var("KRB5_KTNAME", keytab);
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

        // Initialize Parquet S3 forwarder if configured
        let parquet_s3_forwarder = if let Ok(Some(s3_config)) =
            crate::forwarding::parquet_s3::create_parquet_s3_forwarder(
                &config.forwarding.destinations,
            )
            .await
        {
            info!("Initialized Parquet S3 forwarder");
            Some(tokio::sync::Mutex::new(s3_config))
        } else {
            None
        };

        let state = Arc::new(AppState {
            config: Arc::clone(&shared_config),
            throughput,
            forwarder,
            parser: WefParser::new(),
            event_parser,
            parquet_s3_forwarder,
        });

        if state.parquet_s3_forwarder.is_some() {
            let state_clone = Arc::clone(&state);
            tokio::spawn(async move {
                loop {
                    let interval_secs = {
                        if let Some(ref forwarder) = state_clone.parquet_s3_forwarder {
                            let guard = forwarder.lock().await;
                            guard.flush_interval_secs()
                        } else {
                            break;
                        }
                    };

                    sleep(Duration::from_secs(interval_secs)).await;

                    if let Some(ref forwarder) = state_clone.parquet_s3_forwarder {
                        if let Err(e) = forwarder.lock().await.flush_all().await {
                            error!("Failed to run scheduled Parquet S3 flush: {}", e);
                        }
                    } else {
                        break;
                    }
                }
            });
        }

        Ok(Self { config, state })
    }

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
        let router = Router::new()
            .route("/wsman", post(handle_wef_request))
            .route("/wsman/subscriptions", post(handle_subscription))
            .route("/wsman/events", post(handle_events))
            .route("/stats/throughput", get(handle_throughput_stats))
            .route("/health", axum::routing::get(health_check))
            // Syslog endpoints
            .route("/syslog", post(handle_syslog_http))
            .route("/syslog/udp", get(handle_syslog_udp_info))
            .route("/syslog/examples", get(handle_syslog_examples))
            .layer(middleware::from_fn_with_state(
                ip_whitelist.clone(),
                ip_whitelist_middleware,
            ))
            .layer(axum::Extension(ip_whitelist))
            .with_state(self.state.clone());

        self.apply_kerberos_layer(router)
    }

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

        // Load TLS configuration
        let tls_config = self.load_tls_config()?;
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        let tls_addr: SocketAddr = format!("0.0.0.0:{}", self.config.tls.port).parse()?;

        info!("Starting WEF server with TLS on https://{}", tls_addr);

        let listener = tokio::net::TcpListener::bind(&tls_addr).await?;

        // Accept TLS connections
        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let acceptor = acceptor.clone();
            let app = app.clone();

            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(_tls_stream) => {
                        // Serve the connection
                        let _service = app.into_make_service();
                        // Note: This is a simplified version - in production you'd need
                        // proper TLS stream handling with axum
                        info!("TLS connection from {}", peer_addr);
                    }
                    Err(e) => {
                        error!("TLS handshake failed from {}: {}", peer_addr, e);
                    }
                }
            });
        }
    }

    fn load_tls_config(&self) -> anyhow::Result<rustls::ServerConfig> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use std::fs::File;
        use std::io::BufReader;

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

        // Load certificate chain
        let cert_file = File::open(cert_file)?;
        let mut cert_reader = BufReader::new(cert_file);
        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

        // Load private key
        let key_file = File::open(key_file)?;
        let mut key_reader = BufReader::new(key_file);
        let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)?
            .expect("No private key found in key file");

        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        // Configure ALPN for HTTP/1.1
        config.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(config)
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

        let layer = NegotiateAuthLayer::new(spn.clone())
            .map_err(|err| anyhow!("failed to initialize Kerberos layer: {err}"))?;

        Ok(router.layer(layer))
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

async fn process_events(state: &Arc<AppState>, events: Vec<WindowsEvent>) {
    for event in events {
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

        state.forwarder.forward(event.clone()).await;

        if let Some(ref parquet_s3) = state.parquet_s3_forwarder {
            let mut forwarder = parquet_s3.lock().await;
            if let Err(e) = forwarder.forward(event.clone()).await {
                error!("Failed to forward to Parquet S3: {}", e);
            }
        }
    }
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
            parquet_s3_forwarder: None,
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
