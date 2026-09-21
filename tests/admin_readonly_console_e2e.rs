//! End-to-end: a real admin server over a real socket proves the console
//! is read-only and that a LOGTHING__* environment variable reaches the
//! running process.
//!
//! Setup mirrors `tests/admin_trusted_header_e2e.rs` (port reservation via
//! bind-then-drop, `spawn_admin_server`, readiness polling over `/health`).
//!
//! This MUST be the only `#[tokio::test]` in this binary: `Server::run`
//! installs the Prometheus recorder through `metrics::set_global_recorder`,
//! which panics if called twice in one process, and cargo runs each
//! integration-test file as its own process — so one test per file keeps
//! that safe, and also keeps the process-global `LOGTHING__*` env var
//! manipulation below from racing any other test.

use logthing::admin::spawn_admin_server;
use logthing::stats::SourceHourlyStats;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[tokio::test]
async fn console_is_read_only_and_reports_the_env_var_that_configured_it() {
    // -----------------------------------------------------------------
    // 1. Set a LOGTHING__* override before loading config, then prove
    //    Config::load() actually picked it up over logthing.toml's
    //    checked-in syslog.udp_port = 514.
    // -----------------------------------------------------------------
    // SAFETY: set before any config load; this file has exactly one
    // #[tokio::test], so nothing else in this process races this var.
    unsafe { std::env::set_var("LOGTHING__SYSLOG__UDP_PORT", "15514") };

    let config = logthing::config::Config::load().expect("config loads");
    assert_eq!(
        config.syslog.udp_port, 15514,
        "the environment variable must win over logthing.toml"
    );

    // -----------------------------------------------------------------
    // 2. Start the real admin server on a reserved port, sharing the
    //    same config the env var just produced.
    // -----------------------------------------------------------------
    let port = {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        probe.local_addr().unwrap().port()
    };

    // SAFETY: same single-test-per-process reasoning as above.
    unsafe {
        std::env::set_var("LOGTHING_ADMIN_BIND", format!("127.0.0.1:{port}"));
        std::env::set_var("LOGTHING_ADMIN_ENABLE_RATE_LIMIT", "false");
    }

    let shared_config = Arc::new(RwLock::new(config));
    spawn_admin_server(shared_config, Arc::new(SourceHourlyStats::new()));

    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{port}");
    let mut ready = false;
    for _ in 0..50 {
        if let Ok(resp) = client.get(format!("{base_url}/health")).send().await
            && resp.status() == reqwest::StatusCode::OK
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    assert!(ready, "admin server did not become ready in time");

    // -----------------------------------------------------------------
    // 3. GET / must render the set variable's name, the resolved value
    //    it produced, and must not contain the deleted config form.
    // -----------------------------------------------------------------
    let page = client
        .get(format!("{base_url}/"))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .expect("GET / over real HTTP")
        .text()
        .await
        .unwrap();

    assert!(
        page.contains("LOGTHING__SYSLOG__UDP_PORT"),
        "the set variable must be listed on the page:\n{page}"
    );
    assert!(
        page.contains("15514"),
        "the resolved value must be rendered in the effective config:\n{page}"
    );
    assert!(
        !page.contains("<form"),
        "no config form may remain:\n{page}"
    );

    // -----------------------------------------------------------------
    // 4. All seven removed config-mutation endpoints must be unrouted:
    //    405 (method exists on the path but not for this verb) or 404
    //    (path itself is gone), never 200.
    // -----------------------------------------------------------------
    for (method, path) in [
        (reqwest::Method::PUT, "/config"),
        (reqwest::Method::PATCH, "/config"),
        (reqwest::Method::POST, "/config/reload"),
        (reqwest::Method::POST, "/config/import"),
        (reqwest::Method::POST, "/config/validate"),
        (reqwest::Method::POST, "/config/diff"),
        (reqwest::Method::POST, "/config/export"),
    ] {
        let res = client
            .request(method.clone(), format!("{base_url}{path}"))
            .basic_auth("admin", Some("admin"))
            .json(&serde_json::json!({}))
            .send()
            .await
            .expect("request completes");
        assert!(
            res.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED
                || res.status() == reqwest::StatusCode::NOT_FOUND,
            "{method} {path} must not be routed, got {}",
            res.status()
        );
    }

    unsafe { std::env::remove_var("LOGTHING__SYSLOG__UDP_PORT") };
}
