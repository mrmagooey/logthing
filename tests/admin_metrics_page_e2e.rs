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

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

use logthing::admin::spawn_admin_server;
use logthing::config::{CardinalityWatch, Config};
use logthing::forwarding::aggregate::fields::{AggFields, FieldValue};
use logthing::stats::SourceHourlyStats;

/// Slice out one `<tr>...</tr>` row by a substring unique to its start, so
/// assertions can be scoped to a specific row instead of the whole page body
/// (the page's static help text and captions otherwise create false-positive
/// substring matches — see the cardinality-watch assertion below).
fn row_starting_at<'a>(body: &'a str, needle: &str) -> &'a str {
    let start = body
        .find(needle)
        .unwrap_or_else(|| panic!("expected to find {needle:?} on the page:\n{body}"));
    let end = body[start..]
        .find("</tr>")
        .map(|i| start + i + "</tr>".len())
        .unwrap();
    &body[start..end]
}

fn basic_auth_header(user: &str, pass: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
    )
}

/// Minimal `AggFields` fake for a zeek `conn` record carrying one
/// `id.orig_h` value — same shape as `FakeRecord` in
/// `src/stats/cardinality.rs`'s own unit tests, copied locally rather than
/// exposed from the crate since this is the only caller outside that module.
struct FakeConnRecord {
    id_orig_h: String,
}

impl AggFields for FakeConnRecord {
    fn stream(&self) -> &str {
        "conn"
    }

    fn field(&self, name: &str) -> Option<FieldValue<'_>> {
        if name == "id.orig_h" {
            Some(FieldValue::Str(Cow::Borrowed(&self.id_orig_h)))
        } else {
            None
        }
    }
}

/// Feed three distinct `id.orig_h` values through the real `observe()` path,
/// one per watcher. Called repeatedly by the polling loop below rather than
/// once: `CardinalityWatcher::tick` publishes-then-clears every window
/// (`src/stats/cardinality.rs`), so a single batch of `observe()` calls only
/// survives on the page until the NEXT window boundary, at which point an
/// empty window overwrites the gauge back to 0. Re-observing every iteration
/// guarantees whichever window the ticker most recently closed contains them.
fn observe_three_distinct_hosts(
    watchers: &[Arc<logthing::stats::cardinality::CardinalityWatcher>],
) {
    for id_orig_h in ["10.0.0.1", "10.0.0.2", "10.0.0.3"] {
        let rec = FakeConnRecord {
            id_orig_h: id_orig_h.to_string(),
        };
        for w in watchers {
            w.observe(&rec);
        }
    }
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

    // 4. Poll until a real window boundary both observed AND published the
    //    three values in the same window: keep re-observing every iteration
    //    (see `observe_three_distinct_hosts`'s doc comment for why one batch
    //    alone is not enough), and check back until the page reflects it, up
    //    to a generous bound. This is a settle-and-check loop, not a fixed
    //    sleep — it converges as soon as one window catches the values,
    //    typically well under the 1s window period after the first
    //    iteration, and stays correct regardless of scheduler jitter.
    let mut body = String::new();
    let mut settled = false;
    for _ in 0..50 {
        observe_three_distinct_hosts(&watchers);
        tokio::time::sleep(Duration::from_millis(200)).await;

        let resp = client
            .get(format!("{base_url}/metrics"))
            .header("Authorization", basic_auth_header("admin", "admin"))
            .send()
            .await
            .expect("GET /metrics on the admin server");
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        body = resp.text().await.unwrap();

        let row = row_starting_at(
            &body,
            "<td>zeek</td><td>conn</td><td><code>id.orig_h</code></td>",
        );
        if row.contains("<td>3</td>") {
            settled = true;
            break;
        }
    }
    assert!(
        settled,
        "the cardinality watch never settled on a sampled count of 3 within the poll budget:\n{body}"
    );

    assert!(
        body.contains("aggregate_records_consumed"),
        "the recorded counter must appear on the page:\n{body}"
    );
    assert!(
        body.contains("admin_metrics_page_e2e"),
        "its label must appear on the page:\n{body}"
    );
    // Scoped to the counter's own row, not a whole-body substring check: "11"
    // alone could collide with any other digits the page ever grows to
    // contain (a future metric's value, a port number, etc).
    let counter_row = row_starting_at(&body, "<code>aggregate_records_consumed</code>");
    assert!(
        counter_row.contains("<td>11</td>"),
        "its value must appear in the counter's own row:\n{counter_row}"
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
    let cardinality_row = row_starting_at(
        &body,
        "<td>zeek</td><td>conn</td><td><code>id.orig_h</code></td>",
    );
    assert!(
        !cardinality_row.contains("awaiting first window"),
        "a watch whose window boundary has passed must show a real count in its row:\n\
         {cardinality_row}"
    );
    // The three distinct `id.orig_h` values fed through `observe()` above
    // must surface as exactly 3, not merely a non-"awaiting" placeholder —
    // proving the join surfaces a genuine sampled count.
    assert!(
        cardinality_row.contains("<td>3</td>"),
        "the three distinct observed values must show as a count of 3 in the watch's row:\n{cardinality_row}"
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
