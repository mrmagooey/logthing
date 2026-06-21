use std::net::IpAddr;

use axum::{
    Json,
    body::Body,
    extract::{ConnectInfo, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::admin::auth::verify_csrf_token;
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
            tracing::warn!(
                "Admin access denied from {} - not in whitelist",
                client_ip
            );
            return (
                StatusCode::FORBIDDEN,
                "Access denied - IP not in whitelist",
            )
                .into_response();
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
        };

        AdminState {
            config: Arc::new(RwLock::new(crate::config::Config::default())),
            server_config,
            audit_logger: AuditLogger::new(100).await,
            csrf_tokens: Arc::new(RwLock::new(Vec::new())),
            request_counts: Arc::new(RwLock::new(HashMap::new())),
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
        let request = create_test_request(Method::GET, None)
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
        request.extensions_mut().insert(axum::extract::ConnectInfo(addr));

        let response: axum::http::Response<axum::body::Body> = app
            .oneshot(request)
            .await
            .unwrap();

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
        request.extensions_mut().insert(axum::extract::ConnectInfo(addr));

        let app = axum::Router::new()
            .route("/test", axum::routing::get(|| async { "OK" }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                security_middleware,
            ))
            .with_state(state);

        let response: axum::http::Response<axum::body::Body> = app
            .oneshot(request)
            .await
            .unwrap();

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
        
        request.extensions_mut().insert(axum::extract::ConnectInfo(addr));

        let app = axum::Router::new()
            .route("/test", axum::routing::get(|| async { "OK" }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                security_middleware,
            ))
            .with_state(state);

        let response: axum::http::Response<axum::body::Body> = app
            .oneshot(request)
            .await
            .unwrap();

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

        let response: axum::http::Response<axum::body::Body> = app
            .oneshot(request)
            .await
            .unwrap();

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

        let response: axum::http::Response<axum::body::Body> = app
            .oneshot(request)
            .await
            .unwrap();

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

        let response: axum::http::Response<axum::body::Body> = app
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn csrf_middleware_blocks_invalid_token() {
        let state = test_state_with_config(vec![], true, false).await;
        let request = create_test_request(Method::POST, Some(vec![("X-CSRF-Token", "invalid-token")]));

        let app = axum::Router::new()
            .route("/test", axum::routing::post(|| async { "OK" }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                csrf_middleware,
            ))
            .with_state(state);

        let response: axum::http::Response<axum::body::Body> = app
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
