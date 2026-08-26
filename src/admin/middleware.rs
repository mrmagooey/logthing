use std::net::IpAddr;

use axum::{
    Json,
    body::Body,
    extract::{ConnectInfo, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::admin::auth::{verify_csrf_token, verify_trusted_header};
use crate::admin::state::{AdminState, RateLimitError};

/// Security middleware: rate limiting, IP whitelist, and CSRF protection
pub async fn security_middleware(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    let client_ip = addr.ip().to_string();

    // Check IP whitelist
    if !state.server_config.allowed_ips.is_empty() {
        let ip: IpAddr = addr.ip();
        let allowed = state
            .server_config
            .allowed_ips
            .iter()
            .any(|net| net.contains(&ip));

        if !allowed {
            tracing::warn!("Admin access denied from {} - not in whitelist", client_ip);
            return (StatusCode::FORBIDDEN, "Access denied - IP not in whitelist").into_response();
        }
    }

    // Rate limiting
    if state.server_config.enable_rate_limiting {
        let now = std::time::Instant::now();
        let rate_limit_window = std::time::Duration::from_secs(60);
        let max_requests = 30; // 30 requests per minute

        let should_block = {
            let mut counts = state.request_counts.write().await;
            let entry = counts.entry(client_ip.clone()).or_insert((now, 0));

            // Reset if window has passed
            if now.duration_since(entry.0) > rate_limit_window {
                *entry = (now, 1);
                false
            } else {
                entry.1 += 1;
                entry.1 > max_requests
            }
        };

        if should_block {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(axum::http::header::RETRY_AFTER, "60")],
                Json(RateLimitError {
                    error: "Rate limit exceeded".to_string(),
                    retry_after: 60,
                }),
            )
                .into_response();
        }
    }

    next.run(request).await
}

/// CSRF protection middleware for state-changing endpoints
pub async fn csrf_middleware(
    State(state): State<AdminState>,
    request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    // Skip CSRF check for GET requests and if CSRF is disabled
    if request.method() == Method::GET || !state.server_config.enable_csrf {
        return next.run(request).await;
    }

    // Extract CSRF token from header
    let csrf_token = request
        .headers()
        .get("X-CSRF-Token")
        .and_then(|v| v.to_str().ok());

    if let Some(token) = csrf_token
        && verify_csrf_token(&state, token).await
    {
        return next.run(request).await;
    }

    // CSRF token missing or invalid
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": "CSRF token missing or invalid"
        })),
    )
        .into_response()
}

/// Resolves a trusted reverse-proxy identity (if any) and, when present,
/// inserts it into the request's extensions for downstream handlers to pick
/// up via `Option<Extension<TrustedIdentity>>`.
///
/// Never rejects the request itself — a request with no or invalid trusted
/// headers must still be able to reach the handler and fall back to Basic
/// Auth there (`ensure_authorized` handles that fallback).
///
/// When trust-mode is configured and the request actually carries the
/// shared-secret header but verification fails, records a
/// `TRUSTED_HEADER_REJECTED` audit entry (best-effort username, never the
/// secret) so a brute-force attempt against the shared secret isn't
/// invisible the way a silent `None` would leave it. Requests that don't
/// attempt trusted-header auth at all (no trust config, or no secret
/// header present) are not logged.
pub async fn trusted_header_middleware(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    mut request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    match verify_trusted_header(&state, request.headers()) {
        Some(identity) => {
            request.extensions_mut().insert(identity);
        }
        None => {
            if let Some(cfg) = state.server_config.trusted_header.as_ref()
                && request.headers().contains_key(&cfg.secret_header)
            {
                let username = request
                    .headers()
                    .get(&cfg.username_header)
                    .and_then(|v| v.to_str().ok())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or("unknown");
                let client_ip = addr.ip().to_string();
                state
                    .audit_logger
                    .log("TRUSTED_HEADER_REJECTED", username, &client_ip, None)
                    .await;
            }
        }
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::state::{AdminServerConfig, AdminState, AuditLogger, PasswordHash};
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use ipnet::IpNet;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use tower::util::ServiceExt;

    async fn test_state_with_config(
        allowed_ips: Vec<IpNet>,
        enable_csrf: bool,
        enable_rate_limiting: bool,
    ) -> AdminState {
        let server_config = AdminServerConfig {
            bind_address: "0.0.0.0:8080".parse().unwrap(),
            username: "user".to_string(),
            password_hash: PasswordHash::hash("pass").unwrap(),
            allowed_ips,
            tls_config: None,
            enable_csrf,
            enable_rate_limiting,
            trusted_header: None,
        };

        AdminState {
            config: Arc::new(RwLock::new(crate::config::Config::default())),
            server_config,
            audit_logger: AuditLogger::new(100).await,
            csrf_tokens: Arc::new(RwLock::new(Vec::new())),
            request_counts: Arc::new(RwLock::new(HashMap::new())),
            source_stats: Arc::new(crate::stats::SourceHourlyStats::new()),
            flush_registry: crate::forwarding::flush_registry::FlushIntervalRegistry::new(),
        }
    }

    fn create_test_request(method: Method, headers: Option<Vec<(&str, &str)>>) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri("/test");

        if let Some(h) = headers {
            for (key, value) in h {
                builder = builder.header(key, value);
            }
        }

        builder.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn security_middleware_allows_request_with_empty_whitelist() {
        let state = test_state_with_config(vec![], false, false).await;
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let _request = create_test_request(Method::GET, None)
            .map(|b| b)
            .map(|_| axum::body::Body::empty());

        // Build a router with the middleware
        let app = axum::Router::new()
            .route("/test", axum::routing::get(|| async { "OK" }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                security_middleware,
            ))
            .with_state(state);

        let mut request = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(axum::body::Body::empty())
            .unwrap();

        // Inject ConnectInfo as an extension
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(addr));

        let response: axum::http::Response<axum::body::Body> = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn security_middleware_blocks_ip_not_in_whitelist() {
        let allowed: IpNet = "192.168.1.0/24".parse().unwrap();
        let state = test_state_with_config(vec![allowed], false, false).await;
        let addr: SocketAddr = "10.0.0.1:12345".parse().unwrap();

        let mut request = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(axum::body::Body::empty())
            .unwrap();

        // Inject ConnectInfo as an extension
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(addr));

        let app = axum::Router::new()
            .route("/test", axum::routing::get(|| async { "OK" }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                security_middleware,
            ))
            .with_state(state);

        let response: axum::http::Response<axum::body::Body> = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn security_middleware_allows_ip_in_whitelist() {
        let allowed: IpNet = "192.168.1.0/24".parse().unwrap();
        let state = test_state_with_config(vec![allowed], false, false).await;
        let addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();

        let mut request = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(axum::body::Body::empty())
            .unwrap();

        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(addr));

        let app = axum::Router::new()
            .route("/test", axum::routing::get(|| async { "OK" }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                security_middleware,
            ))
            .with_state(state);

        let response: axum::http::Response<axum::body::Body> = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn csrf_middleware_skips_get_requests() {
        let state = test_state_with_config(vec![], true, false).await;
        let request = create_test_request(Method::GET, None);

        let app = axum::Router::new()
            .route("/test", axum::routing::get(|| async { "OK" }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                csrf_middleware,
            ))
            .with_state(state);

        let response: axum::http::Response<axum::body::Body> = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn csrf_middleware_skips_when_disabled() {
        let state = test_state_with_config(vec![], false, false).await;
        let request = create_test_request(Method::POST, None);

        let app = axum::Router::new()
            .route("/test", axum::routing::post(|| async { "OK" }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                csrf_middleware,
            ))
            .with_state(state);

        let response: axum::http::Response<axum::body::Body> = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn csrf_middleware_blocks_post_without_token() {
        let state = test_state_with_config(vec![], true, false).await;
        let request = create_test_request(Method::POST, None);

        let app = axum::Router::new()
            .route("/test", axum::routing::post(|| async { "OK" }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                csrf_middleware,
            ))
            .with_state(state);

        let response: axum::http::Response<axum::body::Body> = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn csrf_middleware_blocks_invalid_token() {
        let state = test_state_with_config(vec![], true, false).await;
        let request =
            create_test_request(Method::POST, Some(vec![("X-CSRF-Token", "invalid-token")]));

        let app = axum::Router::new()
            .route("/test", axum::routing::post(|| async { "OK" }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                csrf_middleware,
            ))
            .with_state(state);

        let response: axum::http::Response<axum::body::Body> = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    mod trusted_header_middleware_tests {
        use super::*;
        use crate::admin::state::TrustedHeaderConfig;
        use axum::http::HeaderName;
        use axum::routing::get;

        fn trusted_cfg() -> TrustedHeaderConfig {
            TrustedHeaderConfig {
                username_header: HeaderName::from_static("x-authentik-username"),
                groups_header: HeaderName::from_static("x-authentik-groups"),
                secret_header: HeaderName::from_static("x-admin-proxy-secret"),
                secret: "shhh".to_string(),
                allowed_groups: vec!["admins".to_string()],
            }
        }

        async fn state_with_trust(trusted_header: Option<TrustedHeaderConfig>) -> AdminState {
            let server_config = AdminServerConfig {
                bind_address: "0.0.0.0:8080".parse().unwrap(),
                username: "user".to_string(),
                password_hash: PasswordHash::hash("pass").unwrap(),
                allowed_ips: vec![],
                tls_config: None,
                enable_csrf: false,
                enable_rate_limiting: false,
                trusted_header,
            };
            AdminState {
                config: Arc::new(RwLock::new(crate::config::Config::default())),
                server_config,
                audit_logger: isolated_audit_logger().await,
                csrf_tokens: Arc::new(RwLock::new(Vec::new())),
                request_counts: Arc::new(RwLock::new(HashMap::new())),
                source_stats: Arc::new(crate::stats::SourceHourlyStats::new()),
                flush_registry: crate::forwarding::flush_registry::FlushIntervalRegistry::new(),
            }
        }

        /// `AuditLogger::new` defaults to the shared `log/admin-audit.log`
        /// file (relative to the repo root) unless `WEF_ADMIN_AUDIT_LOG`
        /// points elsewhere, and loads its prior contents on startup. Tests
        /// in this module assert on the *absence* of specific audit
        /// entries, so unlike the sibling tests here (which only assert
        /// presence and tolerate a shared, accumulating file), they need a
        /// private log file per call — otherwise a `TRUSTED_HEADER_REJECTED`
        /// entry written to disk by an earlier test run leaks in via
        /// `load_entries_from_file` and fails an unrelated "no entry"
        /// assertion. Mirrors the tempdir + env-var pattern already used in
        /// `admin::mod::tests` (e.g. `audit_logger_persists_to_json_lines`).
        async fn isolated_audit_logger() -> AuditLogger {
            static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let log_path = std::env::temp_dir().join(format!(
                "logthing-test-audit-{}-{n}.log",
                std::process::id()
            ));
            // SAFETY: test-only, single-threaded within this call; mirrors
            // the existing set/read/remove pattern used elsewhere in this
            // crate's tests (see `admin::mod::tests`).
            unsafe {
                std::env::set_var("WEF_ADMIN_AUDIT_LOG", &log_path);
            }
            let logger = AuditLogger::new(100).await;
            unsafe {
                std::env::remove_var("WEF_ADMIN_AUDIT_LOG");
            }
            logger
        }

        /// A downstream test handler that reports whether a TrustedIdentity
        /// extension is present, so the test can observe the middleware's
        /// effect without needing a real admin handler.
        async fn echo_trusted(
            trusted: Option<axum::extract::Extension<crate::admin::state::TrustedIdentity>>,
        ) -> String {
            match trusted {
                Some(axum::extract::Extension(t)) => format!("trusted:{}", t.username),
                None => "untrusted".to_string(),
            }
        }

        /// `trusted_header_middleware` now requires `ConnectInfo` (to log
        /// the client IP on rejection), so every test request needs it
        /// injected the way the real connect-info service would.
        fn inject_connect_info(request: &mut Request<Body>, addr: SocketAddr) {
            request.extensions_mut().insert(ConnectInfo(addr));
        }

        #[tokio::test]
        async fn sets_extension_on_secret_and_group_match() {
            let state = state_with_trust(Some(trusted_cfg())).await;
            let app = axum::Router::new()
                .route("/test", get(echo_trusted))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    trusted_header_middleware,
                ))
                .with_state(state);

            let mut request = Request::builder()
                .method(Method::GET)
                .uri("/test")
                .header("x-admin-proxy-secret", "shhh")
                .header("x-authentik-username", "alice")
                .header("x-authentik-groups", "admins")
                .body(Body::empty())
                .unwrap();
            inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(&body[..], b"trusted:alice");
        }

        #[tokio::test]
        async fn does_not_set_extension_on_wrong_secret() {
            let state = state_with_trust(Some(trusted_cfg())).await;
            let app = axum::Router::new()
                .route("/test", get(echo_trusted))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    trusted_header_middleware,
                ))
                .with_state(state);

            let mut request = Request::builder()
                .method(Method::GET)
                .uri("/test")
                .header("x-admin-proxy-secret", "wrong")
                .header("x-authentik-username", "alice")
                .header("x-authentik-groups", "admins")
                .body(Body::empty())
                .unwrap();
            inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(&body[..], b"untrusted");
        }

        #[tokio::test]
        async fn does_not_set_extension_on_non_matching_group() {
            let state = state_with_trust(Some(trusted_cfg())).await;
            let app = axum::Router::new()
                .route("/test", get(echo_trusted))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    trusted_header_middleware,
                ))
                .with_state(state);

            let mut request = Request::builder()
                .method(Method::GET)
                .uri("/test")
                .header("x-admin-proxy-secret", "shhh")
                .header("x-authentik-username", "alice")
                .header("x-authentik-groups", "guests")
                .body(Body::empty())
                .unwrap();
            inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

            let response = app.oneshot(request).await.unwrap();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(&body[..], b"untrusted");
        }

        #[tokio::test]
        async fn disabled_feature_never_sets_extension() {
            let state = state_with_trust(None).await;
            let app = axum::Router::new()
                .route("/test", get(echo_trusted))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    trusted_header_middleware,
                ))
                .with_state(state);

            let mut request = Request::builder()
                .method(Method::GET)
                .uri("/test")
                .header("x-admin-proxy-secret", "shhh")
                .header("x-authentik-username", "alice")
                .header("x-authentik-groups", "admins")
                .body(Body::empty())
                .unwrap();
            inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

            let response = app.oneshot(request).await.unwrap();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(&body[..], b"untrusted");
        }

        /// Finding: rejected trusted-header attempts previously left no
        /// audit trace at all (unlike a failed Basic Auth attempt, which
        /// logs `AUTH_FAILED`). A wrong-secret attempt — the header the
        /// feature is gated on is present, just wrong — must now produce a
        /// `TRUSTED_HEADER_REJECTED` audit entry, and that entry must never
        /// contain the secret value itself.
        #[tokio::test]
        async fn wrong_secret_with_attempt_logs_trusted_header_rejected() {
            let state = state_with_trust(Some(trusted_cfg())).await;
            let app = axum::Router::new()
                .route("/test", get(echo_trusted))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    trusted_header_middleware,
                ))
                .with_state(state.clone());

            let mut request = Request::builder()
                .method(Method::GET)
                .uri("/test")
                .header("x-admin-proxy-secret", "totally-wrong-secret")
                .header("x-authentik-username", "alice")
                .header("x-authentik-groups", "admins")
                .body(Body::empty())
                .unwrap();
            inject_connect_info(&mut request, "192.0.2.7:54321".parse().unwrap());

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let entries = state.audit_logger.get_entries(10).await;
            let entry = entries
                .iter()
                .find(|e| e.action == "TRUSTED_HEADER_REJECTED")
                .expect("TRUSTED_HEADER_REJECTED entry should exist");
            assert_eq!(entry.username, "alice");
            assert_eq!(entry.client_ip, "192.0.2.7");

            // The secret must never appear anywhere in the logged entry.
            assert!(!entry.action.contains("totally-wrong-secret"));
            assert!(!entry.username.contains("totally-wrong-secret"));
            assert!(!entry.client_ip.contains("totally-wrong-secret"));
            assert!(
                !entry
                    .details
                    .as_deref()
                    .unwrap_or("")
                    .contains("totally-wrong-secret")
            );
        }

        /// Best-effort username: if the username header is missing/blank on
        /// a rejected attempt, fall back to "unknown" rather than failing.
        #[tokio::test]
        async fn wrong_secret_missing_username_logs_unknown_username() {
            let state = state_with_trust(Some(trusted_cfg())).await;
            let app = axum::Router::new()
                .route("/test", get(echo_trusted))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    trusted_header_middleware,
                ))
                .with_state(state.clone());

            let mut request = Request::builder()
                .method(Method::GET)
                .uri("/test")
                .header("x-admin-proxy-secret", "wrong")
                .body(Body::empty())
                .unwrap();
            inject_connect_info(&mut request, "192.0.2.8:1".parse().unwrap());

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let entries = state.audit_logger.get_entries(10).await;
            let entry = entries
                .iter()
                .find(|e| e.action == "TRUSTED_HEADER_REJECTED")
                .expect("TRUSTED_HEADER_REJECTED entry should exist");
            assert_eq!(entry.username, "unknown");
        }

        /// No secret header at all means no trusted-header attempt was made
        /// — must stay silent (this is the ordinary Basic-Auth-only path,
        /// not a rejection).
        #[tokio::test]
        async fn no_secret_header_does_not_log_rejection() {
            let state = state_with_trust(Some(trusted_cfg())).await;
            let app = axum::Router::new()
                .route("/test", get(echo_trusted))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    trusted_header_middleware,
                ))
                .with_state(state.clone());

            let mut request = Request::builder()
                .method(Method::GET)
                .uri("/test")
                .body(Body::empty())
                .unwrap();
            inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let entries = state.audit_logger.get_entries(10).await;
            assert!(
                !entries
                    .iter()
                    .any(|e| e.action == "TRUSTED_HEADER_REJECTED"),
                "no attempt was made, so nothing should be logged"
            );
        }

        /// Trust-mode disabled entirely — even with the secret header
        /// present, there's no trust config to attempt verification
        /// against, so nothing should be logged.
        #[tokio::test]
        async fn disabled_trust_mode_does_not_log_rejection() {
            let state = state_with_trust(None).await;
            let app = axum::Router::new()
                .route("/test", get(echo_trusted))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    trusted_header_middleware,
                ))
                .with_state(state.clone());

            let mut request = Request::builder()
                .method(Method::GET)
                .uri("/test")
                .header("x-admin-proxy-secret", "shhh")
                .header("x-authentik-username", "alice")
                .header("x-authentik-groups", "admins")
                .body(Body::empty())
                .unwrap();
            inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let entries = state.audit_logger.get_entries(10).await;
            assert!(
                !entries
                    .iter()
                    .any(|e| e.action == "TRUSTED_HEADER_REJECTED"),
                "trust-mode is disabled, so nothing should be logged"
            );
        }

        /// A matching (accepted) trusted-header request must not also
        /// produce a rejection entry.
        #[tokio::test]
        async fn successful_verification_does_not_log_rejection() {
            let state = state_with_trust(Some(trusted_cfg())).await;
            let app = axum::Router::new()
                .route("/test", get(echo_trusted))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    trusted_header_middleware,
                ))
                .with_state(state.clone());

            let mut request = Request::builder()
                .method(Method::GET)
                .uri("/test")
                .header("x-admin-proxy-secret", "shhh")
                .header("x-authentik-username", "alice")
                .header("x-authentik-groups", "admins")
                .body(Body::empty())
                .unwrap();
            inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let entries = state.audit_logger.get_entries(10).await;
            assert!(
                !entries
                    .iter()
                    .any(|e| e.action == "TRUSTED_HEADER_REJECTED"),
                "a successful attempt is not a rejection"
            );
        }
    }
}
