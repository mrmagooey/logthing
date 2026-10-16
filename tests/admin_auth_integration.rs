//! Integration: the production admin router (built by `build_admin_router`) resolves the client
//! IP from the RIGHTMOST `X-Forwarded-For` hop, and that hop is what the IP allowlist judges.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderName, Request, StatusCode};
use logthing::admin::{
    AdminServerConfig, AdminState, AuditLogger, PasswordHash, TrustedHeaderConfig,
    build_admin_router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower::util::ServiceExt;

const SECRET: &str = "integration-shared-secret";

async fn state(dir: &std::path::Path) -> AdminState {
    AdminState {
        config: Arc::new(RwLock::new(logthing::config::Config::default())),
        server_config: AdminServerConfig {
            bind_address: "127.0.0.1:8080".parse().unwrap(),
            username: "admin".to_string(),
            // Generated here; no real credential is committed.
            password_hash: PasswordHash::hash("integration-test-password").unwrap(),
            allowed_ips: vec!["127.0.0.1/32".parse().unwrap()],
            tls_config: None,
            enable_rate_limiting: false,
            trusted_header: Some(TrustedHeaderConfig {
                username_header: HeaderName::from_static("x-authentik-username"),
                groups_header: HeaderName::from_static("x-authentik-groups"),
                secret_header: HeaderName::from_static("x-admin-proxy-secret"),
                secret: SECRET.to_string(),
                allowed_groups: vec!["admins".to_string()],
            }),
        },
        audit_logger: AuditLogger::with_log_file(100, dir.join("audit.log")).await,
        request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
        source_stats: Arc::new(logthing::stats::SourceHourlyStats::new()),
    }
}

async fn get_config_with_xff(xff: &str) -> StatusCode {
    let dir = tempfile::tempdir().unwrap();
    let app = build_admin_router(state(dir.path()).await);
    let mut req = Request::builder()
        .uri("/config")
        .header("x-admin-proxy-secret", SECRET)
        .header("x-authentik-username", "alice")
        .header("x-authentik-groups", "admins")
        .header("x-forwarded-for", xff)
        .body(Body::empty())
        .unwrap();
    // The TCP peer is the proxy, which is not on the allowlist: only XFF can admit the request.
    let peer: SocketAddr = "192.0.2.1:4000".parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(peer));
    app.oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn rightmost_xff_hop_is_the_one_the_allowlist_sees() {
    assert_eq!(
        get_config_with_xff("10.9.9.9, 127.0.0.1").await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn forged_leftmost_xff_hop_cannot_pass_the_allowlist() {
    assert_eq!(
        get_config_with_xff("127.0.0.1, 10.9.9.9").await,
        StatusCode::FORBIDDEN
    );
}
