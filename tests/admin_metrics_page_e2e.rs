//! End-to-end: the admin console's `/metrics` page, over a real socket,
//! against the real process-global Prometheus recorder.
//!
//! Setup mirrors `tests/admin_readonly_console_e2e.rs` (port reservation by
//! bind-then-drop, `spawn_admin_server`, readiness polling on `/health`) and
//! the recorder half of `tests/aggregate_metrics_e2e.rs`.
//!
//! This MUST be the only `#[tokio::test]` in this binary: the Prometheus
//! recorder is installed process-globally exactly once, and the test also
//! sets `LOGTHING_ADMIN_*` environment variables, which nothing else may race.
//!
//! What would fail without the feature: the GET below 404s.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

use logthing::admin::spawn_admin_server;
use logthing::config::{CardinalityWatch, Config};
use logthing::stats::SourceHourlyStats;

fn basic_auth_header(user: &str, pass: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
    )
}

#[tokio::test]
async fn admin_metrics_page_shows_live_counters_and_configured_cardinality_watches() {
    // 1. Install the real recorder and record a distinctly-named series, so
    //    the assertion cannot collide with anything else in the process.
    logthing::server::install_metrics_recorder();
    metrics::counter!("aggregate_records_consumed", "rule" => "admin_metrics_page_e2e")
        .increment(11);

    // 2. A real cardinality watch, ticked through a real window boundary by
    //    the production ticker, so a real `field_distinct_values` series
    //    exists on the endpoint the page reads.
    let watch = CardinalityWatch {
        source: "zeek".to_string(),
        stream: "conn".to_string(),
        field: "id.orig_h".to_string(),
    };

    let mut config = Config::default();
    config.metrics.enabled = true;
    config.metrics.cardinality_watch = vec![watch.clone()];
    config.metrics.cardinality_window_secs = 1;
    // `compile_watches` rejects a watch on a disabled source (would pin the
    // gauge at 0 forever, indistinguishable from an outage) — verified
    // against src/stats/cardinality.rs's `cardinality_source_enabled`,
    // which the brief's code block predates.
    config.zeek.enabled = true;

    let compiled = logthing::stats::cardinality::compile_watches(&config)
        .expect("a zeek/conn/id.orig_h watch must compile");
    let watchers: Vec<Arc<logthing::stats::cardinality::CardinalityWatcher>> = compiled
        .into_iter()
        .map(|w| {
            Arc::new(logthing::stats::cardinality::CardinalityWatcher::new(
                w,
                config.metrics.cardinality_max_values,
            ))
        })
        .collect();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let ticker = logthing::stats::cardinality::spawn_ticker(watchers.clone(), 1, shutdown_rx);

    // 3. Real admin server on a reserved port.
    let port = {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        probe.local_addr().unwrap().port()
    };
    // SAFETY: this file has exactly one #[tokio::test], so nothing else in
    // this process races these variables. Names verified against
    // `load_admin_config` in src/admin/state.rs: LOGTHING_ADMIN_USER and
    // LOGTHING_ADMIN_PASS (not *_USERNAME/*_PASSWORD).
    unsafe {
        std::env::set_var("LOGTHING_ADMIN_BIND", format!("127.0.0.1:{port}"));
        std::env::set_var("LOGTHING_ADMIN_ENABLE_RATE_LIMIT", "false");
        std::env::set_var("LOGTHING_ADMIN_USER", "admin");
        std::env::set_var("LOGTHING_ADMIN_PASS", "admin");
    }
    spawn_admin_server(
        Arc::new(RwLock::new(config)),
        Arc::new(SourceHourlyStats::new()),
    );

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
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "admin server never became ready on {base_url}");

    // 4. Let at least one 1s window boundary pass so the ticker publishes.
    tokio::time::sleep(Duration::from_millis(2500)).await;

    // 5. The page itself.
    let resp = client
        .get(format!("{base_url}/metrics"))
        .header("Authorization", basic_auth_header("admin", "admin"))
        .send()
        .await
        .expect("GET /metrics on the admin server");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body = resp.text().await.unwrap();

    assert!(
        body.contains("aggregate_records_consumed"),
        "the recorded counter must appear on the page:\n{body}"
    );
    assert!(
        body.contains("admin_metrics_page_e2e"),
        "its label must appear on the page:\n{body}"
    );
    assert!(
        body.contains("11"),
        "its value must appear on the page:\n{body}"
    );
    assert!(
        body.contains("id.orig_h") && body.contains("conn"),
        "the configured cardinality watch must appear on the page:\n{body}"
    );
    // Narrowed to the watch's own table row, not the whole page: the
    // template's caption explains the feature using the literal phrase
    // "awaiting first window" (see templates/metrics.html), so a whole-body
    // substring check is a false positive on that static help text even
    // once this watch has a real sampled count.
    let row_start = body
        .find("<td>zeek</td><td>conn</td><td><code>id.orig_h</code></td>")
        .expect("the configured cardinality watch's table row must appear on the page");
    let row = &body[row_start
        ..body[row_start..]
            .find("</tr>")
            .map(|i| row_start + i)
            .unwrap()];
    assert!(
        !row.contains("awaiting first window"),
        "a watch whose window boundary has passed must show a real count in its row:\n{row}"
    );

    // 6. Unauthenticated access is still refused over the real socket.
    let unauth = client
        .get(format!("{base_url}/metrics"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), reqwest::StatusCode::UNAUTHORIZED);

    ticker.abort();
}
