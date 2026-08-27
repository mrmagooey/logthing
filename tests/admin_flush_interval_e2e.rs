//! End-to-end test proving `flush_interval_secs` is live-updatable through
//! the *real* admin HTTP path.
//!
//! Spins up the actual admin server (`logthing::admin::spawn_admin_server`)
//! as a real TCP listener, starts a real local-disk syslog writer and
//! registers its `LiveInterval` handle into a shared `FlushIntervalRegistry`
//! (exactly as `main.rs` would at startup), then fires a genuine
//! `PUT /config` HTTP request at the server via `reqwest` and asserts the
//! already-running writer's live flush interval actually changed as a
//! result. This exercises the full path — real HTTP PUT → config validate →
//! persist → in-memory swap → `apply_flush_intervals` → registry lookup →
//! the live writer's `LiveInterval` — over a real network connection, not
//! an in-process `Router::oneshot` call.
//!
//! Uses the local-disk writer path only (no S3/MinIO). No external
//! dependency required. This test MUST run and pass without MinIO or any
//! other service, and needs no network beyond loopback.

use base64::Engine;
use logthing::admin::spawn_admin_server;
use logthing::config::{Config, SyslogLocalConfig, TlsConfig};
use logthing::forwarding::flush_registry::FlushIntervalRegistry;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::syslog_s3::syslog_local_start;
use logthing::stats::SourceHourlyStats;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[tokio::test]
async fn put_config_over_real_http_updates_already_running_writers_live_flush_interval() {
    // ---------------------------------------------------------------------
    // 1. A real running local-disk syslog writer, so there's something
    //    whose live flush interval we can observe changing.
    // ---------------------------------------------------------------------
    let writer_dir = tempfile::tempdir().unwrap();
    let sink = Arc::new(
        LocalDiskSink::new(writer_dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink constructs"),
    );

    let syslog_local_cfg = SyslogLocalConfig {
        directory: writer_dir.path().to_path_buf(),
        prefix: "syslog".to_string(),
        max_buffer_rows: 10_000,
        flush_interval_secs: 3600,
        channel_capacity: 4096,
    };

    let (handler, _writer_join_handle) = syslog_local_start(
        &syslog_local_cfg,
        sink,
        Arc::new(SourceHourlyStats::new()),
        None,
    );

    // Sanity check: starting value is the original 3600s, so the later
    // assertion actually proves something changed.
    assert_eq!(handler.flush_interval().get(), Duration::from_secs(3600));

    // ---------------------------------------------------------------------
    // 2. A shared registry the writer registers into, exactly as `main.rs`
    //    would at startup.
    // ---------------------------------------------------------------------
    let flush_registry = FlushIntervalRegistry::new();
    flush_registry.register("syslog.local", handler.flush_interval());

    // ---------------------------------------------------------------------
    // 3. The real admin HTTP server, via the actual production entry point.
    // ---------------------------------------------------------------------

    // Reserve an ephemeral port by binding to it, reading the assigned
    // port, then dropping the listener before `spawn_admin_server` binds
    // its own listener to the same address. `spawn_admin_server` binds
    // internally and does not return the bound address, so this is the
    // only way to discover a free port up front. This has a small,
    // theoretical TOCTOU race (another process could grab the port in the
    // gap between drop and rebind) but is an accepted, standard pattern for
    // tests of this shape.
    let port = {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        probe.local_addr().unwrap().port()
    };

    let admin_user = "e2e-admin";
    let admin_pass = "e2e-pass";
    let override_dir = tempfile::tempdir().unwrap();
    let override_file = override_dir.path().join("logthing.admin.toml");

    // Safety: this test file contains exactly one `#[tokio::test]`, so
    // there is no other test in this binary that could race on these
    // process-global env vars. Cargo compiles each `tests/*.rs` file into
    // its own process, so this doesn't race with other integration/e2e
    // files or the lib's own `#[cfg(test)]` suite either.
    //
    // DO NOT add a second `#[tokio::test]` to this file without introducing
    // the same kind of crate-wide env-var mutex that
    // `src/admin/config_api.rs`'s `test_support::PERSIST_CONFIG_ENV_LOCK`
    // uses for `LOGTHING_ADMIN_OVERRIDE_FILE` — that module is `pub(crate)` and
    // not reusable from here, so a from-scratch equivalent would be needed.
    unsafe {
        std::env::set_var("LOGTHING_ADMIN_BIND", format!("127.0.0.1:{port}"));
        std::env::set_var("LOGTHING_ADMIN_USER", admin_user);
        std::env::set_var("LOGTHING_ADMIN_PASS", admin_pass);
        std::env::set_var("LOGTHING_ADMIN_ENABLE_CSRF", "false");
        std::env::set_var("LOGTHING_ADMIN_ENABLE_RATE_LIMIT", "false");
        std::env::set_var("LOGTHING_ADMIN_OVERRIDE_FILE", &override_file);
    }

    let mut initial_config = Config {
        tls: TlsConfig {
            enabled: false,
            ..TlsConfig::default()
        },
        ..Config::default()
    };
    initial_config.syslog.local = Some(syslog_local_cfg.clone());

    let shared_config = Arc::new(RwLock::new(initial_config.clone()));

    spawn_admin_server(
        shared_config,
        Arc::new(SourceHourlyStats::new()),
        flush_registry,
    );

    // ---------------------------------------------------------------------
    // 4. Wait for the admin server to actually be listening.
    // ---------------------------------------------------------------------
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

    // ---------------------------------------------------------------------
    // 5. Fire a real PUT /config request that changes flush_interval_secs.
    // ---------------------------------------------------------------------
    let mut new_config = initial_config.clone();
    new_config
        .syslog
        .local
        .as_mut()
        .unwrap()
        .flush_interval_secs = 5;

    let auth_header = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{admin_user}:{admin_pass}"))
    );

    let response = client
        .put(format!("{base_url}/config"))
        .header("Authorization", auth_header)
        .json(&new_config)
        .send()
        .await
        .expect("PUT /config request should succeed over the network");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "PUT /config should return 200 for a valid config"
    );

    // ---------------------------------------------------------------------
    // 6. The actual assertion that proves the fix: the real HTTP request
    //    reached the already-running writer's live interval.
    // ---------------------------------------------------------------------
    assert_eq!(
        handler.flush_interval().get(),
        Duration::from_secs(5),
        "a real PUT /config over HTTP must push the new flush_interval_secs \
         into the already-running writer's live flush interval — this is \
         the full end-to-end path the fix is supposed to wire up"
    );
}
