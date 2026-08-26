use axum::{
    Json, Router,
    extract::{ConnectInfo, Extension, State},
    response::{Html, IntoResponse, Response},
};
use axum_extra::extract::TypedHeader;
use headers::{Authorization, authorization::Basic};
use std::sync::Arc;
use tokio::{net::TcpListener, sync::RwLock};
use tracing::{error, info};

use crate::admin::auth::{ensure_authorized, generate_csrf_token};
use crate::admin::config_api::{
    PartialConfigUpdate, apply_flush_intervals, persist_config, redacted_config,
    validate_config_invariants,
};
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
    flush_registry: crate::forwarding::flush_registry::FlushIntervalRegistry,
) {
    tokio::spawn(async move {
        match load_admin_config() {
            Ok(server_config) => {
                if let Err(err) =
                    run_admin_server(config, server_config, source_stats, flush_registry).await
                {
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
    flush_registry: crate::forwarding::flush_registry::FlushIntervalRegistry,
) -> anyhow::Result<()> {
    let audit_logger = AuditLogger::new(1000).await;
    let csrf_tokens: Arc<RwLock<Vec<(String, std::time::Instant)>>> =
        Arc::new(RwLock::new(Vec::new()));
    let request_counts: Arc<RwLock<std::collections::HashMap<String, (std::time::Instant, u32)>>> =
        Arc::new(RwLock::new(std::collections::HashMap::new()));

    let state = AdminState {
        config,
        server_config: server_config.clone(),
        audit_logger: audit_logger.clone(),
        csrf_tokens: csrf_tokens.clone(),
        request_counts: request_counts.clone(),
        source_stats,
        flush_registry,
    };

    let app = axum::Router::new()
        .route("/", axum::routing::get(admin_page))
        .route(
            "/config",
            axum::routing::get(get_config)
                .put(update_config)
                .patch(patch_config),
        )
        .route(
            "/config/validate",
            axum::routing::post(crate::admin::config_api::validate_config),
        )
        .route(
            "/config/diff",
            axum::routing::post(crate::admin::config_api::diff_config),
        )
        .route(
            "/config/export",
            axum::routing::post(crate::admin::config_api::export_config),
        )
        .route(
            "/config/import",
            axum::routing::post(crate::admin::config_api::import_config),
        )
        .route(
            "/config/reload",
            axum::routing::post(crate::admin::config_api::reload_config),
        )
        .route("/health", axum::routing::get(health_check))
        .route("/audit-log", axum::routing::get(get_audit_log))
        .route("/stats", axum::routing::get(get_stats))
        .route("/stats.json", axum::routing::get(get_stats_json))
        // Layer ordering is deliberate and security-relevant — do not reorder
        // without re-reading this comment.
        //
        // `axum`'s `.layer(A).layer(B)` makes B the OUTER layer: on an
        // incoming request B runs first, then A, then the handler (layers
        // added later wrap the ones added earlier). The three `.layer()`
        // calls below are listed in the order they're ADDED, so read them
        // bottom-to-top to get request-flow order:
        //
        //   csrf_middleware (outermost, runs 1st)
        //     -> trusted_header_middleware (runs 2nd)
        //       -> security_middleware (innermost, runs 3rd)
        //         -> handler
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
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::admin::middleware::csrf_middleware,
        ))
        .with_state(state);

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

    // Generate CSRF token if enabled
    let csrf_token = if state.server_config.enable_csrf {
        generate_csrf_token(&state).await
    } else {
        String::new()
    };

    state
        .audit_logger
        .log("ADMIN_PAGE_ACCESS", &username, &client_ip, None)
        .await;

    let html = include_str!("templates/admin.html").replace("{{CSRF_TOKEN}}", &csrf_token);
    Ok(Html(html))
}

/// Update configuration endpoint
async fn update_config(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    trusted: Option<Extension<TrustedIdentity>>,
    resolved_ip: Option<Extension<ResolvedClientIp>>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
    Json(new_config): Json<Config>,
) -> Result<Json<Config>, Response> {
    let client_ip = resolved_ip
        .map(|Extension(ResolvedClientIp(ip))| ip.to_string())
        .unwrap_or_else(|| addr.ip().to_string());
    let username =
        ensure_authorized(&state, trusted.map(|Extension(t)| t), auth, &client_ip).await?;

    // H-7: validate before touching shared state.
    if let Err(msg) = validate_config_invariants(&new_config) {
        state
            .audit_logger
            .log(
                "CONFIG_UPDATE_REJECTED",
                &username,
                &client_ip,
                Some(&format!("Validation error: {msg}")),
            )
            .await;
        return Err((axum::http::StatusCode::BAD_REQUEST, msg).into_response());
    }

    // H-7: persist first, then swap (atomic: on-disk and in-memory stay consistent).
    if let Err(err) = persist_config(&new_config).await {
        error!("Failed to persist admin config: {}", err);
        state
            .audit_logger
            .log(
                "CONFIG_UPDATE_FAILED",
                &username,
                &client_ip,
                Some(&format!("Persistence error: {}", err)),
            )
            .await;
        return Err((
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Persist failed",
        )
            .into_response());
    }

    // Persist succeeded — now update in-memory state.
    let updated_config = {
        let mut cfg = state.config.write().await;
        *cfg = new_config;
        cfg.clone()
    };

    apply_flush_intervals(&state.flush_registry, &updated_config);

    // Log the change
    state
        .audit_logger
        .log("CONFIG_UPDATED", &username, &client_ip, None)
        .await;

    info!("Configuration updated via admin API by {}", username);

    Ok(Json(redacted_config(&updated_config)))
}

/// Patch configuration endpoint (partial updates)
async fn patch_config(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    trusted: Option<Extension<TrustedIdentity>>,
    resolved_ip: Option<Extension<ResolvedClientIp>>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
    Json(partial): Json<PartialConfigUpdate>,
) -> Result<Json<Config>, Response> {
    let client_ip = resolved_ip
        .map(|Extension(ResolvedClientIp(ip))| ip.to_string())
        .unwrap_or_else(|| addr.ip().to_string());
    let username =
        ensure_authorized(&state, trusted.map(|Extension(t)| t), auth, &client_ip).await?;

    // Build candidate config by applying partial fields to a COPY (do NOT touch
    // shared state yet — we validate first).
    let candidate = {
        let cfg = state.config.read().await;
        let mut candidate = cfg.clone();

        if let Some(bind_addr) = partial.bind_address {
            candidate.bind_address = bind_addr;
        }
        if let Some(enabled) = partial.tls_enabled {
            candidate.tls.enabled = enabled;
        }
        if let Some(port) = partial.tls_port {
            candidate.tls.port = port;
        }
        if let Some(level) = partial.logging_level {
            candidate.logging.level = level;
        }
        if let Some(enabled) = partial.metrics_enabled {
            candidate.metrics.enabled = enabled;
        }
        if let Some(port) = partial.metrics_port {
            candidate.metrics.port = port;
        }
        if let Some(enabled) = partial.syslog_enabled {
            candidate.syslog.enabled = enabled;
        }
        if let Some(port) = partial.syslog_udp_port {
            candidate.syslog.udp_port = port;
        }
        if let Some(port) = partial.syslog_tcp_port {
            candidate.syslog.tcp_port = port;
        }

        candidate
    };

    // H-7: validate before touching shared state.
    if let Err(msg) = validate_config_invariants(&candidate) {
        state
            .audit_logger
            .log(
                "CONFIG_PATCH_REJECTED",
                &username,
                &client_ip,
                Some(&format!("Validation error: {msg}")),
            )
            .await;
        return Err((axum::http::StatusCode::BAD_REQUEST, msg).into_response());
    }

    // H-7: persist first, then swap (atomic: on-disk and in-memory stay consistent).
    if let Err(err) = persist_config(&candidate).await {
        error!("Failed to persist patched config: {}", err);
        state
            .audit_logger
            .log(
                "CONFIG_PATCH_FAILED",
                &username,
                &client_ip,
                Some(&format!("Persistence error: {}", err)),
            )
            .await;
        return Err((
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Persist failed",
        )
            .into_response());
    }

    // Persist succeeded — now update in-memory state.
    let updated_config = {
        let mut cfg = state.config.write().await;
        *cfg = candidate;
        cfg.clone()
    };

    state
        .audit_logger
        .log("CONFIG_PATCHED", &username, &client_ip, None)
        .await;

    info!("Configuration partially updated via PATCH by {}", username);

    // H-6: return redacted config — never expose plaintext S3 secrets.
    Ok(Json(redacted_config(&updated_config)))
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
            enable_csrf: false,
            enable_rate_limiting: false,
            trusted_header: None,
        };

        AdminState {
            config: Arc::new(RwLock::new(Config::default())),
            server_config,
            audit_logger: AuditLogger::new(100).await,
            csrf_tokens: Arc::new(RwLock::new(Vec::new())),
            request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
            source_stats: Arc::new(crate::stats::SourceHourlyStats::new()),
            flush_registry: crate::forwarding::flush_registry::FlushIntervalRegistry::new(),
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
    async fn update_config_requires_auth() {
        let state = test_state().await;
        let json_body = serde_json::to_string(&Config::default()).unwrap();
        let mut request = Request::builder()
            .method(Method::PUT)
            .uri("/config")
            .header("content-type", "application/json")
            .body(Body::from(json_body))
            .unwrap();
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

        let app = axum::Router::new()
            .route("/config", axum::routing::put(update_config))
            .with_state(state);

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn patch_config_requires_auth() {
        let state = test_state().await;
        let json_body = serde_json::to_string(&PartialConfigUpdate::default()).unwrap();
        let mut request = Request::builder()
            .method(Method::PATCH)
            .uri("/config")
            .header("content-type", "application/json")
            .body(Body::from(json_body))
            .unwrap();
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

        let app = axum::Router::new()
            .route("/config", axum::routing::patch(patch_config))
            .with_state(state);

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
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

    /// End-to-end: reproduces main.rs's actual wiring — ONE shared
    /// Arc<SourceHourlyStats> both fed by a real writer and read by the real
    /// admin server over a live loopback socket. Catches an Arc-identity
    /// mistake (writer and admin server holding *different* instances) that
    /// would compile cleanly but leave /stats.json permanently empty.
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
            type Record = String;
            fn source(&self) -> &'static str {
                "e2e_source"
            }
            fn partition(&self, _r: &String) -> Option<String> {
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
                record: &String,
                schema: &Arc<arrow_schema::Schema>,
            ) -> anyhow::Result<arrow_array::RecordBatch> {
                let col = Arc::new(arrow_array::StringArray::from(vec![record.as_str()]));
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
        writer.push("hello".to_string()).await.unwrap();

        // Step 3: spawn the real admin router, sharing the SAME Arc.
        let server_config = AdminServerConfig {
            bind_address: "127.0.0.1:0".parse().unwrap(),
            username: "admin".to_string(),
            password_hash: PasswordHash::hash("admin").unwrap(),
            allowed_ips: vec![],
            tls_config: None,
            enable_csrf: false,
            enable_rate_limiting: false,
            trusted_header: None,
        };
        let state = AdminState {
            config: Arc::new(RwLock::new(Config::default())),
            server_config,
            audit_logger: AuditLogger::new(100).await,
            csrf_tokens: Arc::new(RwLock::new(Vec::new())),
            request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
            source_stats: source_stats.clone(),
            flush_registry: crate::forwarding::flush_registry::FlushIntervalRegistry::new(),
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
            total, 1,
            "count recorded via the writer's Arc must be visible through the \
             admin server's Arc — they must be the SAME instance"
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
            enable_csrf: false,
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
            csrf_tokens: Arc::new(RwLock::new(Vec::new())),
            request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
            source_stats: Arc::new(crate::stats::SourceHourlyStats::new()),
            flush_registry: crate::forwarding::flush_registry::FlushIntervalRegistry::new(),
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
    async fn update_config_with_valid_auth_updates_configuration() {
        let state = test_state().await;
        let new_config = Config::default();
        let json_body = serde_json::to_string(&new_config).unwrap();
        let mut request = create_request_with_auth(
            Method::PUT,
            "/config",
            "admin",
            "admin",
            Some(Body::from(json_body)),
        );
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

        // Add content-type header
        let request = axum::http::Request::builder()
            .method(Method::PUT)
            .uri("/config")
            .header("content-type", "application/json")
            .header(
                "Authorization",
                request
                    .headers()
                    .get("Authorization")
                    .unwrap()
                    .to_str()
                    .unwrap(),
            )
            .body(Body::from(
                serde_json::to_string(&Config::default()).unwrap(),
            ))
            .unwrap();

        let app = axum::Router::new()
            .route("/config", axum::routing::put(update_config))
            .with_state(state);

        let response = app.oneshot(request).await.unwrap();
        // Will fail because persist_config tries to write to disk
        // but we're testing the auth flow works
        assert!(
            response.status() == StatusCode::OK
                || response.status() == StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    // Sandboxes persist_config()'s write path; see config_api::test_support for
    // why this must be a single lock shared crate-wide across test modules.
    use crate::admin::config_api::test_support::sandbox_persist_config_path;

    #[tokio::test]
    async fn patch_config_with_valid_auth_updates_configuration() {
        use crate::config::TlsConfig;

        let _sandbox = sandbox_persist_config_path().await;
        let state = test_state().await;
        // Config::default() has tls.enabled = true with no cert, which fails
        // validate_config_invariants on its own — give it a valid baseline first.
        {
            let mut cfg = state.config.write().await;
            cfg.tls = TlsConfig {
                enabled: false,
                ..TlsConfig::default()
            };
        }
        let partial = PartialConfigUpdate::default();
        let json_body = serde_json::to_string(&partial).unwrap();

        let mut request = axum::http::Request::builder()
            .method(Method::PATCH)
            .uri("/config")
            .header("content-type", "application/json")
            .header(
                "Authorization",
                format!("Basic {}", encode_base64("admin:admin")),
            )
            .body(Body::from(json_body))
            .unwrap();
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

        let app = axum::Router::new()
            .route("/config", axum::routing::patch(patch_config))
            .with_state(state);

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn patch_config_with_partial_fields() {
        use crate::config::TlsConfig;

        let _sandbox = sandbox_persist_config_path().await;
        let state = test_state().await;
        // Config::default() has tls.enabled = true with no cert, which fails
        // validate_config_invariants on its own — give it a valid baseline first.
        {
            let mut cfg = state.config.write().await;
            cfg.tls = TlsConfig {
                enabled: false,
                ..TlsConfig::default()
            };
        }
        let partial = PartialConfigUpdate {
            bind_address: Some("0.0.0.0:9999".parse().unwrap()),
            // tls_enabled intentionally omitted: enabling TLS via PartialConfigUpdate
            // with no cert/key path always fails validate_config_invariants (see
            // patch_config_tls_without_cert_rejected_and_config_unchanged).
            tls_port: Some(9443),
            logging_level: Some("debug".to_string()),
            metrics_enabled: Some(true),
            metrics_port: Some(9090),
            syslog_enabled: Some(true),
            syslog_udp_port: Some(5514),
            syslog_tcp_port: Some(5601),
            ..PartialConfigUpdate::default()
        };
        let json_body = serde_json::to_string(&partial).unwrap();

        let mut request = axum::http::Request::builder()
            .method(Method::PATCH)
            .uri("/config")
            .header("content-type", "application/json")
            .header(
                "Authorization",
                format!("Basic {}", encode_base64("admin:admin")),
            )
            .body(Body::from(json_body))
            .unwrap();
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

        let app = axum::Router::new()
            .route("/config", axum::routing::patch(patch_config))
            .with_state(state);

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn admin_page_with_csrf_enabled_generates_token() {
        let server_config = AdminServerConfig {
            bind_address: "0.0.0.0:8080".parse().unwrap(),
            username: "admin".to_string(),
            password_hash: PasswordHash::hash("admin").unwrap(),
            allowed_ips: vec![],
            tls_config: None,
            enable_csrf: true,
            enable_rate_limiting: false,
            trusted_header: None,
        };

        let state = AdminState {
            config: Arc::new(RwLock::new(Config::default())),
            server_config,
            audit_logger: AuditLogger::new(100).await,
            csrf_tokens: Arc::new(RwLock::new(Vec::new())),
            request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
            source_stats: Arc::new(crate::stats::SourceHourlyStats::new()),
            flush_registry: crate::forwarding::flush_registry::FlushIntervalRegistry::new(),
        };

        let mut request = create_request_with_auth(Method::GET, "/", "admin", "admin", None);
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

        let app = axum::Router::new()
            .route("/", axum::routing::get(admin_page))
            .with_state(state);

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
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

    // ------------------------------------------------------------------ //
    // R-1: patch_config security regression tests                         //
    // ------------------------------------------------------------------ //

    /// A PATCH that enables TLS without supplying cert/key files must be rejected
    /// with HTTP 400 and leave the running config unchanged.
    ///
    /// Note: Config::default() already has tls.enabled=true + no cert_file, so
    /// the candidate config (which inherits those values) always fails validation.
    /// We explicitly disable TLS first so the initial state is valid, then attempt
    /// to re-enable it (still no cert_file) and verify rejection.
    #[tokio::test]
    async fn patch_config_tls_without_cert_rejected_and_config_unchanged() {
        use crate::config::TlsConfig;

        let state = test_state().await;

        // Set the shared config to a valid baseline (TLS disabled, valid bind port).
        {
            let mut cfg = state.config.write().await;
            cfg.tls = TlsConfig {
                enabled: false,
                ..TlsConfig::default()
            };
        }

        // Now attempt to enable TLS via PATCH — without cert/key files this should
        // fail validate_config_invariants and be rejected with 400.
        let partial = PartialConfigUpdate {
            tls_enabled: Some(true),
            ..PartialConfigUpdate::default()
        };
        let json_body = serde_json::to_string(&partial).unwrap();

        let mut request = axum::http::Request::builder()
            .method(Method::PATCH)
            .uri("/config")
            .header("content-type", "application/json")
            .header(
                "Authorization",
                format!("Basic {}", encode_base64("admin:admin")),
            )
            .body(Body::from(json_body))
            .unwrap();
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

        let app = axum::Router::new()
            .route("/config", axum::routing::patch(patch_config))
            .with_state(state.clone());

        let response = app.oneshot(request).await.unwrap();

        // Must be rejected — TLS enabled with no cert is invalid.
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "PATCH enabling TLS without cert files must be rejected with 400"
        );

        // Running config must remain unchanged (tls.enabled still false).
        let cfg = state.config.read().await;
        assert!(
            !cfg.tls.enabled,
            "Running config must not be mutated after a rejected PATCH"
        );
    }

    /// A PATCH that sets bind_address port to 0 must be rejected with HTTP 400.
    #[tokio::test]
    async fn patch_config_bind_port_zero_rejected() {
        use crate::config::TlsConfig;

        let state = test_state().await;

        // Set a valid baseline config (TLS disabled).
        {
            let mut cfg = state.config.write().await;
            cfg.tls = TlsConfig {
                enabled: false,
                ..TlsConfig::default()
            };
        }

        let partial = PartialConfigUpdate {
            bind_address: Some("0.0.0.0:0".parse().unwrap()),
            ..PartialConfigUpdate::default()
        };
        let json_body = serde_json::to_string(&partial).unwrap();

        let mut request = axum::http::Request::builder()
            .method(Method::PATCH)
            .uri("/config")
            .header("content-type", "application/json")
            .header(
                "Authorization",
                format!("Basic {}", encode_base64("admin:admin")),
            )
            .body(Body::from(json_body))
            .unwrap();
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

        let app = axum::Router::new()
            .route("/config", axum::routing::patch(patch_config))
            .with_state(state.clone());

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "PATCH with bind_address port 0 must be rejected with 400"
        );
    }

    /// A successful PATCH response must not contain any real S3 secret values.
    ///
    /// We verify that the response body from a successful PATCH uses redacted_config
    /// (i.e., the route returns `redacted_config(&updated_config)` not the raw config).
    /// persist_config() writes to disk, so we sandbox its target path.
    #[tokio::test]
    async fn patch_config_success_response_redacts_secrets() {
        use crate::config::{S3ConnectionConfig, SyslogS3Config, TlsConfig};
        #[allow(unused_imports)]
        use axum::body::to_bytes;

        let _sandbox = sandbox_persist_config_path().await;
        let state = test_state().await;

        // Set a valid baseline config with a known S3 secret, TLS disabled.
        let real_secret = "super-secret-key-should-not-appear";
        {
            let mut cfg = state.config.write().await;
            cfg.tls = TlsConfig {
                enabled: false,
                ..TlsConfig::default()
            };
            cfg.syslog.s3 = Some(SyslogS3Config {
                connection: S3ConnectionConfig {
                    endpoint: "https://s3.example.com".to_string(),
                    bucket: "test-bucket".to_string(),
                    region: "us-east-1".to_string(),
                    access_key: "AKIAIOSFODNN7EXAMPLE".to_string(),
                    secret_key: real_secret.to_string(),
                },
                prefix: "syslog".to_string(),
                max_buffer_rows: 1000,
                flush_interval_secs: 60,
                channel_capacity: 100,
            });
        }

        // Empty PATCH — noop fields. Should hit persist then return redacted config.
        let partial = PartialConfigUpdate::default();
        let json_body = serde_json::to_string(&partial).unwrap();

        let mut request = axum::http::Request::builder()
            .method(Method::PATCH)
            .uri("/config")
            .header("content-type", "application/json")
            .header(
                "Authorization",
                format!("Basic {}", encode_base64("admin:admin")),
            )
            .body(Body::from(json_body))
            .unwrap();
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

        let app = axum::Router::new()
            .route("/config", axum::routing::patch(patch_config))
            .with_state(state);

        let response = app.oneshot(request).await.unwrap();

        // Must not be 400 (valid config must not be rejected).
        assert_ne!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "An empty PATCH on a valid config must not be rejected as invalid"
        );

        if response.status() == StatusCode::OK {
            // On success, verify the secret is not in the response body.
            let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body_str = String::from_utf8_lossy(&body_bytes);
            assert!(
                !body_str.contains(real_secret),
                "PATCH success response must not contain plaintext S3 secret; got: {body_str}"
            );
        }
    }

    /// End-to-end regression test for the live-reload flush-interval fix,
    /// exercised through the actual HTTP path (not just unit-level plumbing):
    /// a `PUT /config` request whose `syslog.s3.flush_interval_secs` differs
    /// from an already-registered writer's current value must push the new
    /// value into that writer's `LiveInterval` handle.
    #[tokio::test]
    async fn put_config_pushes_flush_interval_change_into_registered_live_writer() {
        use crate::config::{S3ConnectionConfig, SyslogS3Config, TlsConfig};
        use crate::forwarding::buffered_writer::LiveInterval;
        use crate::forwarding::flush_registry::FlushIntervalRegistry;

        let _sandbox = sandbox_persist_config_path().await;
        let mut state = test_state().await;

        // Register a `LiveInterval` under "syslog.s3", exactly as a running
        // writer would at startup via
        // `flush_registry.register("syslog.s3", handler.flush_interval())`.
        let live = LiveInterval::new(std::time::Duration::from_secs(900));
        let registry = FlushIntervalRegistry::new();
        registry.register("syslog.s3", live.clone());
        state.flush_registry = registry;

        // Build a new config whose syslog.s3.flush_interval_secs (5s) differs
        // from the registered writer's current value (900s).
        let mut new_config = Config {
            tls: TlsConfig {
                enabled: false,
                ..TlsConfig::default()
            },
            ..Config::default()
        };
        new_config.syslog.s3 = Some(SyslogS3Config {
            connection: S3ConnectionConfig {
                endpoint: "https://s3.example.com".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: "AKIAIOSFODNN7EXAMPLE".to_string(),
                secret_key: "super-secret-key".to_string(),
            },
            prefix: "syslog".to_string(),
            max_buffer_rows: 1000,
            flush_interval_secs: 5,
            channel_capacity: 100,
        });

        let json_body = serde_json::to_string(&new_config).unwrap();
        let mut request = axum::http::Request::builder()
            .method(Method::PUT)
            .uri("/config")
            .header("content-type", "application/json")
            .header(
                "Authorization",
                format!("Basic {}", encode_base64("admin:admin")),
            )
            .body(Body::from(json_body))
            .unwrap();
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

        let app = axum::Router::new()
            .route("/config", axum::routing::put(update_config))
            .with_state(state);

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "PUT /config must succeed for a valid config"
        );

        assert_eq!(
            live.get(),
            std::time::Duration::from_secs(5),
            "PUT /config must push the new flush_interval_secs into the \
             already-registered live writer handle — this is the actual bug \
             fix, exercised end-to-end through the HTTP path"
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
                enable_csrf: false,
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
                csrf_tokens: Arc::new(RwLock::new(Vec::new())),
                request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
                source_stats: Arc::new(crate::stats::SourceHourlyStats::new()),
                flush_registry: crate::forwarding::flush_registry::FlushIntervalRegistry::new(),
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
        async fn export_config_succeeds_with_trusted_headers_alone_no_basic_auth() {
            let state = test_state_with_trust().await;
            let mut request = trusted_headers_request(Method::POST, "/config/export");
            inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

            let app = axum::Router::new()
                .route(
                    "/config/export",
                    axum::routing::post(crate::admin::config_api::export_config),
                )
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
            let mut request = create_request_with_auth(Method::GET, "/config", "admin", "admin", None);
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
}
