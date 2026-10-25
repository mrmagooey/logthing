//! Integration: the admin `/metrics` page when no Prometheus recorder has been
//! installed in the process (`METRICS_HANDLE` unset), over a real socket.
//!
//! Nothing in this binary installs the recorder, so the page must explain
//! why it has no values, distinguishing "disabled by config" from "not up yet".

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

use logthing::admin::{
    AdminServerConfig, AdminState, AuditLogger, PasswordHash, build_admin_router,
};
use logthing::config::Config;

async fn serve(metrics_enabled: bool, dir: &tempfile::TempDir) -> std::net::SocketAddr {
    let mut config = Config::default();
    config.metrics.enabled = metrics_enabled;
    let state = AdminState {
        config: Arc::new(RwLock::new(config)),
        server_config: AdminServerConfig {
            bind_address: "127.0.0.1:0".parse().unwrap(),
            username: "admin".to_string(),
            password_hash: PasswordHash::hash("admin").unwrap(),
            allowed_ips: vec![],
            tls_config: None,
            enable_rate_limiting: false,
            trusted_header: None,
        },
        audit_logger: AuditLogger::with_log_file(100, dir.path().join("audit.log")).await,
        request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
        source_stats: Arc::new(logthing::stats::SourceHourlyStats::new()),
    };
    let app = build_admin_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
    });
    addr
}

async fn get_metrics_page(addr: std::net::SocketAddr) -> String {
    let resp = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
        .get(format!("http://{addr}/metrics"))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    resp.text().await.unwrap()
}

#[tokio::test]
async fn test_metrics_page_says_collection_is_disabled_when_config_turns_it_off() {
    let dir = tempfile::tempdir().unwrap();
    let addr = serve(false, &dir).await;
    let body = get_metrics_page(addr).await;
    assert!(body.contains("Metrics collection is disabled"), "{body}");
    assert!(body.contains("metrics.enabled = false"), "{body}");
    assert!(!body.contains("has not finished starting"), "{body}");
}

#[tokio::test]
async fn test_metrics_page_says_recorder_is_starting_when_enabled_but_not_installed() {
    let dir = tempfile::tempdir().unwrap();
    let addr = serve(true, &dir).await;
    let body = get_metrics_page(addr).await;
    assert!(
        body.contains("The metrics recorder has not finished starting"),
        "{body}"
    );
    assert!(!body.contains("Metrics collection is disabled"), "{body}");
}
