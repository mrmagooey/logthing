use axum::{
    Json, Router,
    extract::{ConnectInfo, Extension, State},
    response::{Html, Response},
};
use axum_extra::extract::TypedHeader;
use headers::{Authorization, authorization::Basic};
use std::sync::Arc;
use tokio::{net::TcpListener, sync::RwLock};
use tracing::{error, info};

use crate::admin::auth::ensure_authorized;
use crate::admin::config_api::redacted_config;
use crate::admin::middleware::security_middleware;
use crate::admin::state::{
    AdminServerConfig, AdminState, AuditLogger, ResolvedClientIp, TrustedIdentity,
    load_admin_config,
};
use crate::config::Config;

/// Spawn the admin server as a background task
pub fn spawn_admin_server(
    config: Arc<RwLock<Config>>,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
) {
    tokio::spawn(async move {
        match load_admin_config() {
            Ok(server_config) => {
                if let Err(err) = run_admin_server(config, server_config, source_stats).await {
                    error!("Admin server error: {}", err);
                }
            }
            Err(err) => {
                error!("Failed to load admin configuration: {}", err);
            }
        }
    });
}

/// Run the admin server
async fn run_admin_server(
    config: Arc<RwLock<Config>>,
    server_config: AdminServerConfig,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
) -> anyhow::Result<()> {
    let audit_logger = AuditLogger::new(1000).await;
    let request_counts: Arc<RwLock<std::collections::HashMap<String, (std::time::Instant, u32)>>> =
        Arc::new(RwLock::new(std::collections::HashMap::new()));

    let state = AdminState {
        config,
        server_config: server_config.clone(),
        audit_logger: audit_logger.clone(),
        request_counts: request_counts.clone(),
        source_stats,
    };

    let app = build_admin_router(state);

    let addr = server_config.bind_address;
    let listener = TcpListener::bind(addr).await?;

    if let Some(ref tls_config) = server_config.tls_config {
        info!(
            "Admin interface available on https://{} (TLS enabled)",
            addr
        );
        run_tls_server(listener, app, tls_config).await?;
    } else {
        info!(
            "Admin interface available on http://{} (HTTP - consider enabling TLS)",
            addr
        );
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await?;
    }

    Ok(())
}

/// Build the admin router: every route plus the two security layers, in
/// their deliberate order. Split out of `run_admin_server` so tests can
/// exercise the exact production routing table (see `config_write_endpoints_are_gone`).
pub(crate) fn build_admin_router(state: AdminState) -> Router {
    axum::Router::new()
        .route("/", axum::routing::get(admin_page))
        .route("/config", axum::routing::get(get_config))
        .route("/health", axum::routing::get(health_check))
        .route("/audit-log", axum::routing::get(get_audit_log))
        .route("/stats", axum::routing::get(get_stats))
        .route("/stats.json", axum::routing::get(get_stats_json))
        // Layer ordering is deliberate and security-relevant — do not reorder
        // without re-reading this comment.
        //
        // `axum`'s `.layer(A).layer(B)` makes B the OUTER layer: on an
        // incoming request B runs first, then A, then the handler (layers
        // added later wrap the ones added earlier). The two `.layer()`
        // calls below are listed in the order they're ADDED, so read them
        // bottom-to-top to get request-flow order:
        //
        //   trusted_header_middleware (outermost, runs 1st)
        //     -> security_middleware (innermost, runs 2nd)
        //       -> handler
        //
        // `trusted_header_middleware` MUST run before `security_middleware`
        // because it's the one that resolves the real client IP (from
        // `X-Forwarded-For`, only when the shared secret verifies — see
        // `auth::resolve_client_ip`) and stashes it in request extensions as
        // `ResolvedClientIp`. `security_middleware` reads that extension to
        // key its rate limiter and IP-allowlist check on the real end-user
        // IP instead of the reverse proxy's single IP. If the order here were
        // ever flipped, `security_middleware` would run before the
        // `ResolvedClientIp` extension exists and would silently fall back to
        // the raw `ConnectInfo` peer address for every request — no compile
        // error, no test failure unless the ordering is exercised directly
        // (see `security_middleware_resolved_ip_tests` in `middleware.rs`,
        // which builds this exact two-layer chain and asserts on it).
        //
        // Known tradeoff from this ordering (accepted, not a bug): before
        // this change, `security_middleware`'s IP allowlist and rate limiter
        // ran before any handler-adjacent code, so a request from a blocked
        // or already-rate-limited IP was rejected immediately. Now
        // `trusted_header_middleware` runs first, and its rejection path
        // writes a `TRUSTED_HEADER_REJECTED` audit entry (disk append +
        // in-memory ring eviction) for ANY request carrying the secret
        // header — including ones that `security_middleware` would go on to
        // block. A disallowed or malicious client can drive repeated audit
        // writes and evict genuine history from the bounded in-memory ring
        // purely by resending a request with some (even wrong) secret header
        // value, before the allowlist/rate-limit check ever runs. This is a
        // modest DoS-adjacent side effect of putting IP resolution ahead of
        // the security gate — accepted here because resolving the IP is a
        // prerequisite for the gate to key on the right address at all.
        // Revisit only if this is ever observed being exploited in practice;
        // fixing it properly would mean splitting `trusted_header_middleware`
        // so verification/logging and IP-extension-insertion run on opposite
        // sides of `security_middleware`, which is more restructuring than
        // this tradeoff currently warrants.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            security_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::admin::middleware::trusted_header_middleware,
        ))
        .with_state(state)
}

/// Run the admin server with TLS using axum-server
async fn run_tls_server(
    listener: TcpListener,
    app: Router,
    tls_config: &crate::admin::state::AdminTlsConfig,
) -> anyhow::Result<()> {
    use axum_server::tls_rustls::RustlsConfig;

    let rustls_config =
        RustlsConfig::from_pem_file(&tls_config.cert_file, &tls_config.key_file).await?;

    // Convert tokio TcpListener to std TcpListener for axum_server
    let std_listener = listener.into_std()?;

    axum_server::from_tcp_rustls(std_listener, rustls_config)
        .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await?;

    Ok(())
}

/// Health check endpoint
pub async fn health_check() -> &'static str {
    "OK"
}

/// Get configuration endpoint
async fn get_config(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    trusted: Option<Extension<TrustedIdentity>>,
    resolved_ip: Option<Extension<ResolvedClientIp>>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
) -> Result<Json<Config>, Response> {
    let client_ip = resolved_ip
        .map(|Extension(ResolvedClientIp(ip))| ip.to_string())
        .unwrap_or_else(|| addr.ip().to_string());
    let username =
        ensure_authorized(&state, trusted.map(|Extension(t)| t), auth, &client_ip).await?;

    let cfg = state.config.read().await;

    state
        .audit_logger
        .log("CONFIG_READ", &username, &client_ip, None)
        .await;

    Ok(Json(redacted_config(&cfg)))
}

/// Admin page endpoint
async fn admin_page(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    trusted: Option<Extension<TrustedIdentity>>,
    resolved_ip: Option<Extension<ResolvedClientIp>>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
) -> Result<Html<String>, Response> {
    let client_ip = resolved_ip
        .map(|Extension(ResolvedClientIp(ip))| ip.to_string())
        .unwrap_or_else(|| addr.ip().to_string());
    let username =
        ensure_authorized(&state, trusted.map(|Extension(t)| t), auth, &client_ip).await?;

    state
        .audit_logger
        .log("ADMIN_PAGE_ACCESS", &username, &client_ip, None)
        .await;

    let redacted = redacted_config(&*state.config.read().await);
    let config_toml = toml::to_string_pretty(&redacted)
        .unwrap_or_else(|e| format!("could not render configuration: {e}"));
    let env_names = set_env_var_names();
    let env_block = if env_names.is_empty() {
        "(none set — every value comes from logthing.toml or a built-in default)".to_string()
    } else {
        env_names.join("\n")
    };

    // Config values are operator-supplied and can contain markup.
    let html = include_str!("templates/admin.html")
        .replace("{{CONFIG_TOML}}", &quick_xml::escape::escape(&config_toml))
        .replace("{{ENV_VAR_NAMES}}", &quick_xml::escape::escape(&env_block));
    Ok(Html(html))
}

/// Names — never values — of the `LOGTHING__*` variables set in this
/// process, sorted.
///
/// Values are withheld because `LOGTHING__HEC__TOKEN` and the S3
/// credentials would otherwise be rendered straight into the page.
///
/// This is an approximation of provenance, not provenance itself: the
/// `config` crate exposes no per-field source attribution, so a typo'd
/// name like `LOGTHING__SYSLOG__UDP_PRT` still appears here looking
/// legitimate. What disambiguates it is the resolved config shown
/// alongside — the variable is listed, but the field it was meant to set
/// still shows its old value.
fn set_env_var_names() -> Vec<String> {
    let mut names: Vec<String> = std::env::vars()
        .map(|(name, _)| name)
        .filter(|name| name.starts_with("LOGTHING__"))
        .collect();
    names.sort();
    names
}

/// Get audit log endpoint
async fn get_audit_log(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    trusted: Option<Extension<TrustedIdentity>>,
    resolved_ip: Option<Extension<ResolvedClientIp>>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
) -> Result<Json<Vec<crate::admin::state::AuditEntry>>, Response> {
    let client_ip = resolved_ip
        .map(|Extension(ResolvedClientIp(ip))| ip.to_string())
        .unwrap_or_else(|| addr.ip().to_string());
    let username =
        ensure_authorized(&state, trusted.map(|Extension(t)| t), auth, &client_ip).await?;

    let entries = state.audit_logger.get_entries(100).await;

    state
        .audit_logger
        .log("AUDIT_LOG_READ", &username, &client_ip, None)
        .await;

    Ok(Json(entries))
}

/// Render the last-24h per-source hourly ingest table as HTML.
async fn get_stats(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    trusted: Option<Extension<TrustedIdentity>>,
    resolved_ip: Option<Extension<ResolvedClientIp>>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
) -> Result<Html<String>, Response> {
    let client_ip = resolved_ip
        .map(|Extension(ResolvedClientIp(ip))| ip.to_string())
        .unwrap_or_else(|| addr.ip().to_string());
    let username =
        ensure_authorized(&state, trusted.map(|Extension(t)| t), auth, &client_ip).await?;

    let snapshot = state.source_stats.snapshot();

    // Union of all hour timestamps across sources, sorted ascending, for
    // consistent column headers.
    let mut all_hours: Vec<chrono::DateTime<chrono::Utc>> = snapshot
        .iter()
        .flat_map(|row| row.hours.iter().map(|h| h.hour))
        .collect();
    all_hours.sort();
    all_hours.dedup();

    let hour_headers: String = all_hours
        .iter()
        .map(|h| format!("<th>{}</th>", h.format("%Y-%m-%d %H:00")))
        .collect();

    let rows: String = snapshot
        .iter()
        .map(|row| {
            let cells: String = all_hours
                .iter()
                .map(|h| {
                    let count = row
                        .hours
                        .iter()
                        .find(|hc| hc.hour == *h)
                        .map(|hc| hc.count)
                        .unwrap_or(0);
                    format!("<td>{count}</td>")
                })
                .collect();
            format!("<tr><td>{}</td>{}</tr>", row.source, cells)
        })
        .collect();

    state
        .audit_logger
        .log("STATS_PAGE_ACCESS", &username, &client_ip, None)
        .await;

    let html = include_str!("templates/stats.html")
        .replace("{{HOUR_HEADERS}}", &hour_headers)
        .replace("{{STATS_ROWS}}", &rows);
    Ok(Html(html))
}

/// Return the last-24h per-source hourly ingest counts as JSON.
async fn get_stats_json(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    trusted: Option<Extension<TrustedIdentity>>,
    resolved_ip: Option<Extension<ResolvedClientIp>>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
) -> Result<Json<Vec<crate::stats::SourceHourlySnapshot>>, Response> {
    let client_ip = resolved_ip
        .map(|Extension(ResolvedClientIp(ip))| ip.to_string())
        .unwrap_or_else(|| addr.ip().to_string());
    let username =
        ensure_authorized(&state, trusted.map(|Extension(t)| t), auth, &client_ip).await?;

    let snapshot = state.source_stats.snapshot();

    state
        .audit_logger
        .log("STATS_JSON_READ", &username, &client_ip, None)
        .await;

    Ok(Json(snapshot))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::state::{AdminServerConfig, AuditLogger, PasswordHash};
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use tower::util::ServiceExt;

    async fn test_state() -> AdminState {
        let server_config = AdminServerConfig {
            bind_address: "0.0.0.0:8080".parse().unwrap(),
            username: "admin".to_string(),
            password_hash: PasswordHash::hash("admin").unwrap(),
            allowed_ips: vec![],
            tls_config: None,
            enable_rate_limiting: false,
            trusted_header: None,
        };

        AdminState {
            config: Arc::new(RwLock::new(Config::default())),
            server_config,
            audit_logger: AuditLogger::new(100).await,
            request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
            source_stats: Arc::new(crate::stats::SourceHourlyStats::new()),
        }
    }

    fn create_request_with_auth(
        method: Method,
        uri: &str,
        username: &str,
        password: &str,
        body: Option<Body>,
    ) -> Request<Body> {
        // Simple base64 encoding for testing
        let auth_str = format!("{}:{}", username, password);
        let auth_header = format!("Basic {}", encode_base64(&auth_str));

        let builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("Authorization", auth_header);

        builder.body(body.unwrap_or_else(Body::empty)).unwrap()
    }

    // Simple base64 encoding function for tests
    fn encode_base64(input: &str) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let bytes = input.as_bytes();
        let mut result = String::new();

        for chunk in bytes.chunks(3) {
            let b = match chunk.len() {
                1 => [chunk[0], 0, 0],
                2 => [chunk[0], chunk[1], 0],
                3 => [chunk[0], chunk[1], chunk[2]],
                _ => unreachable!(),
            };

            let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | (b[2] as u32);

            result.push(CHARSET[(n >> 18) as usize & 0x3f] as char);
            result.push(CHARSET[(n >> 12) as usize & 0x3f] as char);

            if chunk.len() > 1 {
                result.push(CHARSET[(n >> 6) as usize & 0x3f] as char);
            } else {
                result.push('=');
            }

            if chunk.len() > 2 {
                result.push(CHARSET[n as usize & 0x3f] as char);
            } else {
                result.push('=');
            }
        }

        result
    }

    fn create_request_without_auth(method: Method, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    fn inject_connect_info(request: &mut Request<Body>, addr: SocketAddr) {
        request.extensions_mut().insert(ConnectInfo(addr));
    }

    #[tokio::test]
    async fn health_check_returns_ok() {
        let response = health_check().await;
        assert_eq!(response, "OK");
    }

    #[tokio::test]
    async fn get_config_requires_auth() {
        let state = test_state().await;
        let mut request = create_request_without_auth(Method::GET, "/config");
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

        let app = axum::Router::new()
            .route("/config", axum::routing::get(get_config))
            .with_state(state);

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn get_config_returns_config_with_valid_auth() {
        let state = test_state().await;
        let mut request = create_request_with_auth(Method::GET, "/config", "admin", "admin", None);
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

        let app = axum::Router::new()
            .route("/config", axum::routing::get(get_config))
            .with_state(state);

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn admin_page_returns_html_with_valid_auth() {
        let state = test_state().await;
        let mut request = create_request_with_auth(Method::GET, "/", "admin", "admin", None);
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

        let app = axum::Router::new()
            .route("/", axum::routing::get(admin_page))
            .with_state(state);

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_audit_log_requires_auth() {
        let state = test_state().await;
        let mut request = create_request_without_auth(Method::GET, "/audit-log");
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

        let app = axum::Router::new()
            .route("/audit-log", axum::routing::get(get_audit_log))
            .with_state(state);

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn get_audit_log_returns_entries_with_valid_auth() {
        let state = test_state().await;
        let mut request =
            create_request_with_auth(Method::GET, "/audit-log", "admin", "admin", None);
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

        let app = axum::Router::new()
            .route("/audit-log", axum::routing::get(get_audit_log))
            .with_state(state);

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_stats_requires_auth() {
        let state = test_state().await;
        let mut request = create_request_without_auth(Method::GET, "/stats");
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

        let app = axum::Router::new()
            .route("/stats", axum::routing::get(get_stats))
            .with_state(state);

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn get_stats_json_requires_auth() {
        let state = test_state().await;
        let mut request = create_request_without_auth(Method::GET, "/stats.json");
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

        let app = axum::Router::new()
            .route("/stats.json", axum::routing::get(get_stats_json))
            .with_state(state);

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn get_stats_json_returns_recorded_counts_with_valid_auth() {
        let state = test_state().await;
        state.source_stats.record("syslog", 5);

        let mut request =
            create_request_with_auth(Method::GET, "/stats.json", "admin", "admin", None);
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

        let app = axum::Router::new()
            .route("/stats.json", axum::routing::get(get_stats_json))
            .with_state(state);

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let rows: Vec<crate::stats::SourceHourlySnapshot> = serde_json::from_slice(&body).unwrap();
        let syslog_row = rows.iter().find(|r| r.source == "syslog").unwrap();
        let total: u64 = syslog_row.hours.iter().map(|h| h.count).sum();
        assert_eq!(total, 5);
    }

    /// Config write endpoints must not be routed by the real admin router.
    /// Drives `build_admin_router` — the exact function `run_admin_server`
    /// calls in production — rather than a private test-only router, so this
    /// actually asserts something about production routing.
    #[tokio::test]
    async fn config_write_endpoints_are_gone() {
        let app = build_admin_router(test_state().await);

        for (method, path, expected) in [
            (Method::PUT, "/config", StatusCode::METHOD_NOT_ALLOWED),
            (Method::PATCH, "/config", StatusCode::METHOD_NOT_ALLOWED),
            (Method::POST, "/config/validate", StatusCode::NOT_FOUND),
            (Method::POST, "/config/diff", StatusCode::NOT_FOUND),
            (Method::POST, "/config/export", StatusCode::NOT_FOUND),
            (Method::POST, "/config/import", StatusCode::NOT_FOUND),
            (Method::POST, "/config/reload", StatusCode::NOT_FOUND),
        ] {
            let mut request = Request::builder()
                .method(method.clone())
                .uri(path)
                .body(Body::empty())
                .unwrap();
            inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

            let res = app.clone().oneshot(request).await.unwrap();
            assert_eq!(
                res.status(),
                expected,
                "{method} {path} must no longer be routed by the real admin router"
            );
        }
    }

    /// End-to-end: reproduces main.rs's actual wiring — ONE shared
    /// Arc<SourceHourlyStats> both fed by a real writer and read by the real
    /// admin server over a live loopback socket. Catches an Arc-identity
    /// mistake (writer and admin server holding *different* instances) that
    /// would compile cleanly but leave /stats.json permanently empty.
    ///
    /// The sink's `Record` is `Vec<String>` (3 rows per push), mirroring
    /// IPFIX's `Vec<FlowRecord>`, so this also catches the source-stats
    /// row-count regression end to end: a push-count-only fix would report
    /// 1 event over this exact HTTP response, not 3.
    #[tokio::test]
    async fn e2e_shared_source_stats_reach_stats_json_over_real_socket() {
        use crate::config::S3ConnectionConfig;
        use crate::forwarding::buffered_writer::{
            BufferedWriterConfig, FlushPolicy, PartitionedParquetWriter,
        };
        use crate::forwarding::s3_sink::S3Sink;
        use crate::stats::SourceHourlyStats;

        // Step 1: the ONE shared Arc, exactly as main.rs builds it.
        let source_stats = Arc::new(SourceHourlyStats::new());

        // Step 2: push a record through a real writer using that shared Arc.
        let conn = S3ConnectionConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            bucket: "t".to_string(),
            region: "us-east-1".to_string(),
            access_key: "K".to_string(),
            secret_key: "S".to_string(),
        };
        let s3 = Arc::new(S3Sink::from_connection(&conn).await.unwrap());
        let bwc = BufferedWriterConfig {
            connection: conn,
            prefix: "e2e".to_string(),
            max_buffer_rows: 1_000,
            flush_threshold_bytes: usize::MAX,
            flush_interval_secs: 3600,
            channel_capacity: 64,
            max_partitions: 1,
        };
        let policy = FlushPolicy {
            max_rows: 1_000,
            max_bytes: usize::MAX,
            interval: crate::forwarding::buffered_writer::LiveInterval::new(
                std::time::Duration::from_secs(3600),
            ),
        };

        struct E2eSink;
        impl crate::forwarding::buffered_writer::ParquetSink for E2eSink {
            type Record = Vec<String>;
            fn source(&self) -> &'static str {
                "e2e_source"
            }
            fn partition(&self, _r: &Vec<String>) -> Option<String> {
                None
            }
            fn schema(&self, _p: Option<&str>) -> Arc<arrow_schema::Schema> {
                Arc::new(arrow_schema::Schema::new(vec![arrow_schema::Field::new(
                    "val",
                    arrow_schema::DataType::Utf8,
                    false,
                )]))
            }
            fn to_record_batch(
                &self,
                record: &Vec<String>,
                schema: &Arc<arrow_schema::Schema>,
            ) -> anyhow::Result<arrow_array::RecordBatch> {
                let col = Arc::new(arrow_array::StringArray::from(
                    record.iter().map(String::as_str).collect::<Vec<_>>(),
                ));
                Ok(arrow_array::RecordBatch::try_new(
                    schema.clone(),
                    vec![col],
                )?)
            }
        }

        let mut writer = PartitionedParquetWriter::with_source_stats(
            E2eSink,
            s3,
            bwc,
            policy,
            source_stats.clone(),
            None,
        );
        // 3 rows in one push, mirroring one IPFIX UDP datagram carrying 3
        // flows: real row count must reach the HTTP response as 3, not 1.
        writer
            .push(vec!["a".to_string(), "b".to_string(), "c".to_string()])
            .await
            .unwrap();

        // Step 3: spawn the real admin router, sharing the SAME Arc.
        let server_config = AdminServerConfig {
            bind_address: "127.0.0.1:0".parse().unwrap(),
            username: "admin".to_string(),
            password_hash: PasswordHash::hash("admin").unwrap(),
            allowed_ips: vec![],
            tls_config: None,
            enable_rate_limiting: false,
            trusted_header: None,
        };
        let state = AdminState {
            config: Arc::new(RwLock::new(Config::default())),
            server_config,
            audit_logger: AuditLogger::new(100).await,
            request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
            source_stats: source_stats.clone(),
        };
        let app = axum::Router::new()
            .route("/stats.json", axum::routing::get(get_stats_json))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let real_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });

        // Step 4: real HTTP request over the real socket with Basic Auth.
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{real_addr}/stats.json"))
            .basic_auth("admin", Some("admin"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);

        let rows: Vec<crate::stats::SourceHourlySnapshot> = resp.json().await.unwrap();
        let row = rows.iter().find(|r| r.source == "e2e_source").unwrap();
        let total: u64 = row.hours.iter().map(|h| h.count).sum();
        assert_eq!(
            total, 3,
            "count recorded via the writer's Arc must be visible through the \
             admin server's Arc (same instance), AND must reflect the real \
             row count (3) of the single push, not the push count (1)"
        );
    }

    #[tokio::test]
    async fn e2e_trusted_header_auth_over_real_socket() {
        use crate::admin::state::TrustedHeaderConfig;

        let server_config = AdminServerConfig {
            bind_address: "127.0.0.1:0".parse().unwrap(),
            username: "admin".to_string(),
            password_hash: PasswordHash::hash("admin").unwrap(),
            allowed_ips: vec![],
            tls_config: None,
            enable_rate_limiting: false,
            trusted_header: Some(TrustedHeaderConfig {
                username_header: axum::http::HeaderName::from_static("x-authentik-username"),
                groups_header: axum::http::HeaderName::from_static("x-authentik-groups"),
                secret_header: axum::http::HeaderName::from_static("x-admin-proxy-secret"),
                secret: "shhh".to_string(),
                allowed_groups: vec!["admins".to_string()],
            }),
        };
        let state = AdminState {
            config: Arc::new(RwLock::new(Config::default())),
            server_config,
            audit_logger: AuditLogger::new(100).await,
            request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
            source_stats: Arc::new(crate::stats::SourceHourlyStats::new()),
        };

        let app = axum::Router::new()
            .route("/config", axum::routing::get(get_config))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::admin::middleware::trusted_header_middleware,
            ))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let real_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let client = reqwest::Client::new();

        // Trusted headers alone, no Authorization header at all → 200.
        let resp = client
            .get(format!("http://{real_addr}/config"))
            .header("x-admin-proxy-secret", "shhh")
            .header("x-authentik-username", "alice")
            .header("x-authentik-groups", "admins")
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::OK,
            "real HTTP request with valid trusted headers and no Basic Auth must succeed"
        );

        // Wrong secret, no Authorization header → 401 (falls through, no fallback available).
        let resp = client
            .get(format!("http://{real_addr}/config"))
            .header("x-admin-proxy-secret", "wrong-secret")
            .header("x-authentik-username", "alice")
            .header("x-authentik-groups", "admins")
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "a wrong shared secret must not grant access, even with correct-looking identity headers"
        );
    }

    #[tokio::test]
    async fn admin_page_records_audit_log() {
        let state = test_state().await;
        let mut request = create_request_with_auth(Method::GET, "/", "admin", "admin", None);
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

        let app = axum::Router::new()
            .route("/", axum::routing::get(admin_page))
            .with_state(state.clone());

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Verify audit log was recorded
        let entries = state.audit_logger.get_entries(10).await;
        let has_admin_page_access = entries.iter().any(|e| e.action == "ADMIN_PAGE_ACCESS");
        assert!(
            has_admin_page_access,
            "Should record ADMIN_PAGE_ACCESS audit log entry"
        );
    }

    #[tokio::test]
    async fn get_config_records_audit_log() {
        let state = test_state().await;
        let mut request = create_request_with_auth(Method::GET, "/config", "admin", "admin", None);
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

        let app = axum::Router::new()
            .route("/config", axum::routing::get(get_config))
            .with_state(state.clone());

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Verify audit log was recorded
        let entries = state.audit_logger.get_entries(10).await;
        let has_config_read = entries.iter().any(|e| e.action == "CONFIG_READ");
        assert!(has_config_read, "Should record CONFIG_READ audit log entry");
    }

    #[tokio::test]
    async fn get_audit_log_records_self_audit() {
        let state = test_state().await;
        let mut request =
            create_request_with_auth(Method::GET, "/audit-log", "admin", "admin", None);
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

        let app = axum::Router::new()
            .route("/audit-log", axum::routing::get(get_audit_log))
            .with_state(state.clone());

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Verify audit log was recorded
        let entries = state.audit_logger.get_entries(10).await;
        let has_audit_log_read = entries.iter().any(|e| e.action == "AUDIT_LOG_READ");
        assert!(
            has_audit_log_read,
            "Should record AUDIT_LOG_READ audit log entry"
        );
    }

    mod trusted_header_integration_tests {
        use super::*;
        use crate::admin::state::TrustedHeaderConfig;

        async fn test_state_with_trust() -> AdminState {
            let server_config = AdminServerConfig {
                bind_address: "0.0.0.0:8080".parse().unwrap(),
                username: "admin".to_string(),
                password_hash: PasswordHash::hash("admin").unwrap(),
                allowed_ips: vec![],
                tls_config: None,
                enable_rate_limiting: false,
                trusted_header: Some(TrustedHeaderConfig {
                    username_header: axum::http::HeaderName::from_static("x-authentik-username"),
                    groups_header: axum::http::HeaderName::from_static("x-authentik-groups"),
                    secret_header: axum::http::HeaderName::from_static("x-admin-proxy-secret"),
                    secret: "shhh".to_string(),
                    allowed_groups: vec!["admins".to_string()],
                }),
            };
            AdminState {
                config: Arc::new(RwLock::new(Config::default())),
                server_config,
                audit_logger: AuditLogger::new(100).await,
                request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
                source_stats: Arc::new(crate::stats::SourceHourlyStats::new()),
            }
        }

        fn trusted_headers_request(method: Method, uri: &str) -> Request<Body> {
            Request::builder()
                .method(method)
                .uri(uri)
                .header("x-admin-proxy-secret", "shhh")
                .header("x-authentik-username", "alice")
                .header("x-authentik-groups", "admins")
                .body(Body::empty())
                .unwrap()
        }

        #[tokio::test]
        async fn get_config_succeeds_with_trusted_headers_alone_no_basic_auth() {
            let state = test_state_with_trust().await;
            let mut request = trusted_headers_request(Method::GET, "/config");
            inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

            let app = axum::Router::new()
                .route("/config", axum::routing::get(get_config))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    crate::admin::middleware::trusted_header_middleware,
                ))
                .with_state(state);

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn get_config_falls_back_to_basic_auth_when_no_trusted_headers_present() {
            let state = test_state_with_trust().await;
            let mut request =
                create_request_with_auth(Method::GET, "/config", "admin", "admin", None);
            inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

            let app = axum::Router::new()
                .route("/config", axum::routing::get(get_config))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    crate::admin::middleware::trusted_header_middleware,
                ))
                .with_state(state);

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "Basic Auth must still work when no trusted headers are present"
            );
        }

        #[tokio::test]
        async fn get_config_rejects_when_neither_trusted_headers_nor_basic_auth_present() {
            let state = test_state_with_trust().await;
            let mut request = create_request_without_auth(Method::GET, "/config");
            inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

            let app = axum::Router::new()
                .route("/config", axum::routing::get(get_config))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    crate::admin::middleware::trusted_header_middleware,
                ))
                .with_state(state);

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn get_config_records_header_derived_username_in_audit_log() {
            let state = test_state_with_trust().await;
            let mut request = trusted_headers_request(Method::GET, "/config");
            inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

            let app = axum::Router::new()
                .route("/config", axum::routing::get(get_config))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    crate::admin::middleware::trusted_header_middleware,
                ))
                .with_state(state.clone());

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let entries = state.audit_logger.get_entries(10).await;
            let entry = entries
                .iter()
                .find(|e| e.action == "CONFIG_READ")
                .expect("CONFIG_READ entry should exist");
            assert_eq!(entry.username, "alice");
        }

        /// End-to-end proof for the audit-log finding this follow-up fixes:
        /// with trust-mode + a valid secret + `X-Forwarded-For` all present,
        /// the `CONFIG_READ` audit entry's `client_ip` must reflect the
        /// XFF-derived end-user IP, not the reverse proxy's own peer address
        /// (`ConnectInfo`). Chains `trusted_header_middleware` in front of
        /// `get_config`, exactly as `run_admin_server` wires it.
        #[tokio::test]
        async fn get_config_records_xff_derived_client_ip_in_audit_log() {
            let state = test_state_with_trust().await;
            let mut request = Request::builder()
                .method(Method::GET)
                .uri("/config")
                .header("x-admin-proxy-secret", "shhh")
                .header("x-authentik-username", "alice")
                .header("x-authentik-groups", "admins")
                .header("x-forwarded-for", "198.51.100.23")
                .body(Body::empty())
                .unwrap();
            // The proxy's own peer address — must NOT end up in the audit log.
            inject_connect_info(&mut request, "10.0.0.1:12345".parse().unwrap());

            let app = axum::Router::new()
                .route("/config", axum::routing::get(get_config))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    crate::admin::middleware::trusted_header_middleware,
                ))
                .with_state(state.clone());

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let entries = state.audit_logger.get_entries(10).await;
            let entry = entries
                .iter()
                .find(|e| e.action == "CONFIG_READ")
                .expect("CONFIG_READ entry should exist");
            assert_eq!(
                entry.client_ip, "198.51.100.23",
                "audit log must record the XFF-derived end-user IP, not the \
                 reverse proxy's own peer address"
            );
        }
    }

    /// The audit-log viewer must not interpolate attacker-controlled fields into
    /// innerHTML. An unauthenticated attacker can write an audit entry by failing
    /// a Basic-Auth login with a payload as the username; it then executes in the
    /// admin's browser, same-origin, with cached credentials.
    #[test]
    fn admin_template_does_not_interpolate_audit_fields_into_inner_html() {
        let template = include_str!("templates/admin.html");
        for field in [
            "${entry.username}",
            "${entry.action}",
            "${entry.details}",
            "${entry.client_ip}",
        ] {
            assert!(
                !template.contains(field),
                "admin.html still interpolates {field} into a template literal; \
                 audit entries must be rendered with textContent"
            );
        }
    }

    /// The API contract is deliberately unchanged: /audit-log serves the raw
    /// stored string. Escaping is a render-time concern, so the JSON must NOT be
    /// pre-escaped (that would corrupt the data for any other consumer).
    #[tokio::test]
    async fn audit_log_api_still_serves_the_payload_verbatim() {
        let payload = "<img src=x onerror=alert(1)>";
        let state = test_state().await;
        state
            .audit_logger
            .log("AUTH_FAILED", payload, "127.0.0.1", None)
            .await;

        let entries = state.audit_logger.get_entries(100).await;
        assert!(
            entries.iter().any(|e| e.username == payload),
            "the audit API must store and serve the raw username unescaped"
        );
    }

    #[test]
    fn set_env_var_names_lists_names_and_never_values() {
        // SAFETY: single-threaded test, variable removed before returning.
        unsafe { std::env::set_var("LOGTHING__HEC__TOKEN", "super-secret-value") };

        let names = set_env_var_names();

        unsafe { std::env::remove_var("LOGTHING__HEC__TOKEN") };

        assert!(
            names.iter().any(|n| n == "LOGTHING__HEC__TOKEN"),
            "the variable name must be listed: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n.contains("super-secret-value")),
            "a value must never appear: {names:?}"
        );
    }

    #[tokio::test]
    async fn admin_page_renders_config_read_only() {
        let state = test_state().await;
        let mut request = create_request_with_auth(Method::GET, "/", "admin", "admin", None);
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

        let app = axum::Router::new()
            .route("/", axum::routing::get(admin_page))
            .with_state(state);

        let res = app.oneshot(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let body = String::from_utf8(
            axum::body::to_bytes(res.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();

        assert!(!body.contains("<form"), "the config form must be gone");
        assert!(
            !body.contains("wef-server.admin.toml"),
            "stale subtitle must be gone"
        );
        assert!(
            body.contains("security.allowed_ips") && body.contains("aggregate.rules"),
            "the page must name the two file-only settings that have no env equivalent"
        );
        assert!(
            body.contains("bind_address"),
            "the effective config must be rendered"
        );
    }
}
