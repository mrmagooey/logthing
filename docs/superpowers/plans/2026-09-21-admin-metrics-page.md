# Admin Console Metrics Page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a read-only, authenticated `/metrics` page to the admin console that shows every counter and gauge the process is currently reporting, plus a dedicated section for the operator-configured `[[metrics.cardinality_watch]]` counts.

**Architecture:** The admin server already runs in the same process as the Prometheus recorder, so the handler reads the existing `pub static METRICS_HANDLE` (`src/server/mod.rs:45`) and calls `.render()` at request time — no new state, no plumbing, no self-HTTP. A new pure-function module parses that exposition text into groups and renders HTML; the handler joins the configured cardinality watches against the parsed `field_distinct_values` samples so a watch that has not yet reached a window boundary reads as "awaiting first window" instead of being absent.

**Tech Stack:** Rust 2024, axum, `metrics_exporter_prometheus::PrometheusHandle`, `quick_xml::escape::escape` (already a dependency), `tower::ServiceExt::oneshot` + `reqwest` for tests.

**Spec:** `docs/superpowers/specs/2026-09-21-admin-metrics-page-design.md`

## Global Constraints

- Branch: `feat/admin-metrics-page`. Never commit to `master`.
- Build environment — **both** lines are required, the second is the easy one to drop and silently links the wrong unwinder:
  ```bash
  source ~/.cargo/env
  export CC=/usr/bin/gcc CXX=/usr/bin/g++
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
  ```
- Run every `cargo` command in the **foreground**. Never background a build and poll for it: a predicate like `pgrep -f "cargo test"` matches the waiting command's own command line and can never go false. If you genuinely need to check, the only safe form is `ps -eo comm | grep -c "^cargo$"`.
- Style (from `AGENTS.md`): 100-column lines, 4-space indent, `anyhow::Result` for fallible functions, imports grouped stdlib / external / internal, tests in a `#[cfg(test)]` module at the end of the file, test names `test_<what>_<condition>` or descriptive prose names (this file's existing tests use descriptive prose — match the neighbours).
- No new dependency may be added to `Cargo.toml`.
- No JavaScript anywhere in the new template.
- Every interpolated string that reaches HTML must pass through `quick_xml::escape::escape`.
- `cargo fmt` and `cargo clippy -- -D warnings` must be clean before each commit.
- Do not modify the existing `/metrics` listener in `src/server/mod.rs`, and do not change `src/stats/cardinality.rs`.

---

### Task 1: `metrics_view` — exposition parsing and HTML rendering

**Files:**
- Create: `src/admin/metrics_view.rs`
- Modify: `src/admin/mod.rs` (add the module declaration alongside lines 6-10)
- Test: `src/admin/metrics_view.rs` (`#[cfg(test)]` module at the end of the same file)

**Interfaces:**
- Consumes: `crate::config::CardinalityWatch` (fields `source: String`, `stream: String`, `field: String`).
- Produces, all `pub(crate)`:
  - `struct Sample { name: String, labels: String, value: String }`
  - `struct MetricGroup { name: String, help: Option<String>, samples: Vec<Sample> }`
  - `fn parse_exposition(rendered: &str) -> Vec<MetricGroup>`
  - `fn render_groups_html(groups: &[MetricGroup]) -> String`
  - `fn render_cardinality_html(watches: &[CardinalityWatch], groups: &[MetricGroup], window_secs: u64) -> String`
  - `fn series_count(groups: &[MetricGroup]) -> usize`

- [ ] **Step 1: Write the failing tests**

Create `src/admin/metrics_view.rs` containing only the module doc comment and this test module, so it fails to compile for the right reason (missing items, not missing file):

```rust
//! Turns `PrometheusHandle::render()` text into the admin console's metrics
//! page.
//!
//! Pure functions only — the handler (`crate::admin::routes::get_metrics`)
//! owns the I/O. Kept out of `routes.rs` because that file is already large
//! and because a parser is the part worth unit-testing directly.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CardinalityWatch;

    /// Real exposition text: HELP before TYPE, a labelled series, an
    /// unlabelled series, a metric with no HELP at all, and a junk line.
    const SAMPLE: &str = "\
# HELP syslog_messages_received Syslog messages received by the listeners.
# TYPE syslog_messages_received counter
syslog_messages_received 42

# TYPE undescribed_gauge gauge
undescribed_gauge{source=\"zeek\"} 7
undescribed_gauge{source=\"wef\"} 3

this line is not a sample
";

    #[test]
    fn parse_exposition_groups_by_name_and_keeps_help() {
        let groups = parse_exposition(SAMPLE);
        assert_eq!(
            groups.iter().map(|g| g.name.as_str()).collect::<Vec<_>>(),
            vec!["syslog_messages_received", "undescribed_gauge"],
            "groups must come back sorted by metric name"
        );
        assert_eq!(
            groups[0].help.as_deref(),
            Some("Syslog messages received by the listeners."),
        );
        assert_eq!(groups[1].help, None, "a metric with no HELP line has no help");
    }

    #[test]
    fn parse_exposition_splits_labels_from_name_and_value() {
        let groups = parse_exposition(SAMPLE);
        let unlabelled = &groups[0].samples[0];
        assert_eq!(unlabelled.labels, "");
        assert_eq!(unlabelled.value, "42");

        let labelled = &groups[1].samples;
        assert_eq!(labelled.len(), 2);
        assert_eq!(labelled[0].labels, "{source=\"wef\"}", "samples sort by label text");
        assert_eq!(labelled[0].value, "3");
        assert_eq!(labelled[1].labels, "{source=\"zeek\"}");
        assert_eq!(labelled[1].value, "7");
    }

    /// A malformed line must never be fatal: a metrics page that 500s is
    /// worse than one missing a row.
    #[test]
    fn parse_exposition_skips_junk_and_handles_empty_input() {
        let groups = parse_exposition(SAMPLE);
        assert!(
            !groups.iter().any(|g| g.name.contains(' ')),
            "the junk line must not have become a metric: {:?}",
            groups.iter().map(|g| &g.name).collect::<Vec<_>>()
        );
        assert!(parse_exposition("").is_empty());
        assert!(parse_exposition("# HELP lonely_help no samples for this one\n").is_empty());
    }

    #[test]
    fn series_count_counts_samples_not_metric_names() {
        assert_eq!(series_count(&parse_exposition(SAMPLE)), 3);
    }

    /// Label values are partly wire-derived, and this page interpolates them
    /// into server-rendered HTML. Anything that reaches the browser as raw
    /// markup is a stored-XSS bug in an authenticated console.
    #[test]
    fn render_groups_html_escapes_hostile_label_values() {
        let hostile = "field_distinct_values{stream=\"<img src=x onerror=alert(1)>\"} 1\n";
        let html = render_groups_html(&parse_exposition(hostile));
        assert!(
            !html.contains("<img"),
            "hostile label reached the page as raw markup:\n{html}"
        );
        assert!(
            html.contains("&lt;img"),
            "hostile label should appear escaped:\n{html}"
        );
    }

    #[test]
    fn render_groups_html_states_help_once_per_metric() {
        let html = render_groups_html(&parse_exposition(SAMPLE));
        assert_eq!(
            html.matches("Syslog messages received by the listeners.").count(),
            1,
            "HELP text belongs in one rowspan cell, not repeated per series"
        );
        assert!(html.contains("rowspan=\"2\""), "the 2-series metric groups its rows:\n{html}");
    }

    fn watch(source: &str, stream: &str, field: &str) -> CardinalityWatch {
        CardinalityWatch {
            source: source.to_string(),
            stream: stream.to_string(),
            field: field.to_string(),
        }
    }

    #[test]
    fn render_cardinality_html_shows_the_count_and_the_capped_total() {
        let rendered = "\
field_distinct_values{field=\"id.orig_h\",source=\"zeek\",stream=\"conn\"} 4823
field_distinct_values_capped{field=\"id.orig_h\",source=\"zeek\",stream=\"conn\"} 0
";
        let html = render_cardinality_html(
            &[watch("zeek", "conn", "id.orig_h")],
            &parse_exposition(rendered),
            3600,
        );
        assert!(html.contains("id.orig_h"), "{html}");
        assert!(html.contains("4823"), "{html}");
        assert!(!html.contains("awaiting"), "a sampled watch is not awaiting anything:\n{html}");
    }

    /// `CardinalityWatcher::tick` only publishes at a window boundary, so a
    /// correctly configured watch is genuinely absent from the exposition for
    /// up to `cardinality_window_secs` after boot. That must not read as a
    /// missing or broken watch.
    #[test]
    fn render_cardinality_html_marks_an_unsampled_watch_as_awaiting_its_first_window() {
        let html = render_cardinality_html(&[watch("wef", "Security", "computer")], &[], 3600);
        assert!(html.contains("computer"), "{html}");
        assert!(html.contains("awaiting first window"), "{html}");
        assert!(html.contains("3600"), "the window length tells the operator how long to wait:\n{html}");
    }

    #[test]
    fn render_cardinality_html_explains_itself_when_no_watches_are_configured() {
        let html = render_cardinality_html(&[], &[], 3600);
        assert!(
            html.to_lowercase().contains("no"),
            "an empty section must say the feature is off, not render blank:\n{html}"
        );
    }

    /// A watch's field name that is a suffix of another's must not match it.
    #[test]
    fn render_cardinality_html_does_not_confuse_one_watch_for_another() {
        let rendered =
            "field_distinct_values{field=\"my_host\",source=\"syslog\",stream=\"sshd\"} 9\n";
        let html = render_cardinality_html(
            &[watch("syslog", "sshd", "host")],
            &parse_exposition(rendered),
            600,
        );
        assert!(
            html.contains("awaiting first window"),
            "field=\"host\" must not match field=\"my_host\":\n{html}"
        );
    }
}
```

Add to `src/admin/mod.rs`, in declaration order with its neighbours:

```rust
mod metrics_view;
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
source ~/.cargo/env
export CC=/usr/bin/gcc CXX=/usr/bin/g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo test --lib admin::metrics_view
```
Expected: compile errors — `cannot find function 'parse_exposition' in this scope`, and the same for `render_groups_html`, `render_cardinality_html`, `series_count`, plus unresolved `Sample`/`MetricGroup`. This is the correct failure; do not proceed until you see it.

- [ ] **Step 3: Write the implementation**

Insert above the `#[cfg(test)]` module in `src/admin/metrics_view.rs`:

```rust
use std::collections::BTreeMap;

use quick_xml::escape::escape;

use crate::config::CardinalityWatch;

/// One series: a metric name, the verbatim `{...}` label text from the
/// exposition line (empty when unlabelled), and the verbatim value text.
///
/// The value is kept as text rather than parsed into an `f64`: the exporter
/// already decided how to format it, and a round-trip through a float would
/// only introduce a way for the page to disagree with `/metrics`.
pub(crate) struct Sample {
    pub(crate) name: String,
    pub(crate) labels: String,
    pub(crate) value: String,
}

/// Every series sharing one metric name, plus that name's `# HELP` text when
/// the recorder has one (`crate::metrics_descriptions` registers them).
pub(crate) struct MetricGroup {
    pub(crate) name: String,
    pub(crate) help: Option<String>,
    pub(crate) samples: Vec<Sample>,
}

/// Parse Prometheus text exposition into name-grouped series.
///
/// Line handling mirrors the existing `crate::profiling::parse_counter`:
/// split on the LAST space (label values may contain spaces, the value may
/// not), then split the key at the first `{`. `# HELP` feeds the help map;
/// `# TYPE` is ignored — the page shows no type column, and every metric this
/// crate emits is a counter or a gauge anyway (`metrics_descriptions::Kind`).
///
/// Unparseable lines are skipped rather than propagated as an error: this
/// feeds an observability page, and a page missing one row beats a page that
/// returns 500 because the exporter emitted something unexpected.
pub(crate) fn parse_exposition(rendered: &str) -> Vec<MetricGroup> {
    let mut help: BTreeMap<&str, &str> = BTreeMap::new();
    let mut samples: BTreeMap<String, Vec<Sample>> = BTreeMap::new();

    for line in rendered.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(rest) = line.strip_prefix("# HELP ") {
            if let Some((name, text)) = rest.split_once(' ') {
                help.insert(name, text);
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }

        let Some((key, value)) = line.rsplit_once(' ') else {
            continue;
        };
        // A sample line's value is a single number. Anything else is a line
        // shape this parser does not know, which is skipped, not guessed at.
        if value.trim().parse::<f64>().is_err() {
            continue;
        }
        let (name, labels) = match key.split_once('{') {
            Some((name, labels)) => (name, format!("{{{labels}")),
            None => (key, String::new()),
        };
        if name.is_empty() || name.contains(' ') {
            continue;
        }
        samples.entry(name.to_string()).or_default().push(Sample {
            name: name.to_string(),
            labels,
            value: value.trim().to_string(),
        });
    }

    samples
        .into_iter()
        .map(|(name, mut samples)| {
            samples.sort_by(|a, b| a.labels.cmp(&b.labels));
            MetricGroup {
                help: help.get(name.as_str()).map(|h| h.to_string()),
                name,
                samples,
            }
        })
        .collect()
}

/// Total series across all groups — what an operator means by "how many
/// metrics am I looking at", and a cheap sanity number for label growth.
pub(crate) fn series_count(groups: &[MetricGroup]) -> usize {
    groups.iter().map(|g| g.samples.len()).sum()
}

/// One table, one `<tbody>` per metric: the name and HELP text sit in
/// `rowspan` cells so they are stated once per metric instead of repeated on
/// every series.
///
/// Everything interpolated here is escaped with `quick_xml::escape::escape`,
/// the same helper `admin_page` uses for `{{CONFIG_TOML}}`. Label values are
/// partly derived from network input, so this is a trust boundary.
pub(crate) fn render_groups_html(groups: &[MetricGroup]) -> String {
    let mut out = String::new();
    for group in groups {
        let span = group.samples.len().max(1);
        for (i, sample) in group.samples.iter().enumerate() {
            out.push_str("<tr>");
            if i == 0 {
                out.push_str(&format!(
                    "<td rowspan=\"{span}\"><code>{}</code></td>\
                     <td rowspan=\"{span}\" class=\"help\">{}</td>",
                    escape(&sample.name),
                    escape(group.help.as_deref().unwrap_or("")),
                ));
            }
            out.push_str(&format!(
                "<td><code>{}</code></td><td>{}</td></tr>",
                escape(&sample.labels),
                escape(&sample.value),
            ));
        }
    }
    out
}

/// Does this series' label text name exactly this watch's triple?
///
/// Substring matching on `key="value"` rather than a full label parse: the
/// exporter's label order is not part of its contract, and the opening quote
/// anchors each match so one watch's `field` cannot match another's longer
/// one (`field="host"` does not occur inside `field="my_host"`).
fn labels_match(labels: &str, watch: &CardinalityWatch) -> bool {
    [
        format!("source=\"{}\"", watch.source),
        format!("stream=\"{}\"", watch.stream),
        format!("field=\"{}\"", watch.field),
    ]
    .iter()
    .all(|needle| labels.contains(needle.as_str()))
}

fn find_value<'a>(groups: &'a [MetricGroup], name: &str, watch: &CardinalityWatch) -> Option<&'a str> {
    groups
        .iter()
        .find(|g| g.name == name)?
        .samples
        .iter()
        .find(|s| labels_match(&s.labels, watch))
        .map(|s| s.value.as_str())
}

/// Rows for the configured `[[metrics.cardinality_watch]]` entries, joined
/// against the `field_distinct_values` samples that are actually present.
///
/// The "awaiting first window" state is the reason this section exists at all
/// rather than leaving `field_distinct_values` to the generic table:
/// `CardinalityWatcher::tick` publishes only at a window boundary, so for up
/// to `window_secs` after start a perfectly healthy watch has no series — and
/// an operator reading a table it is missing from concludes their config did
/// not take.
pub(crate) fn render_cardinality_html(
    watches: &[CardinalityWatch],
    groups: &[MetricGroup],
    window_secs: u64,
) -> String {
    if watches.is_empty() {
        return "<tr><td colspan=\"5\" class=\"help\">No cardinality watches are \
                configured. Add one or more <code>[[metrics.cardinality_watch]]</code> \
                entries to <code>logthing.toml</code> to count distinct values of a \
                field.</td></tr>"
            .to_string();
    }

    watches
        .iter()
        .map(|watch| {
            let distinct = find_value(groups, "field_distinct_values", watch)
                .map(|v| escape(v).to_string())
                .unwrap_or_else(|| {
                    format!("<span class=\"help\">awaiting first window ({window_secs}s)</span>")
                });
            let capped = find_value(groups, "field_distinct_values_capped", watch)
                .map(|v| escape(v).to_string())
                .unwrap_or_else(|| "—".to_string());
            format!(
                "<tr><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
                escape(&watch.source),
                escape(&watch.stream),
                escape(&watch.field),
                distinct,
                capped,
            )
        })
        .collect()
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test --lib admin::metrics_view
```
Expected: all 10 tests PASS. Then:
```bash
cargo fmt
cargo clippy --lib -- -D warnings
```
Expected: no output from `fmt`, no warnings from `clippy`.

- [ ] **Step 5: Commit**

```bash
git add src/admin/metrics_view.rs src/admin/mod.rs
git commit -m "feat(admin): parse and render Prometheus exposition for the console

Pure functions only: group the render() text by metric name, keep HELP once
per metric, and join the configured cardinality watches against their
field_distinct_values samples so an unsampled watch reads as awaiting its
first window rather than missing. Every interpolated string goes through
quick_xml::escape::escape -- metric label values are partly wire-derived.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: The `/metrics` page on the admin server

**Files:**
- Create: `src/admin/templates/metrics.html`
- Modify: `src/admin/routes.rs` (add the route at the router built around lines 87-95; add the handler after `get_stats_json`, which ends around line 380; add tests to the existing `#[cfg(test)]` module)
- Modify: `src/admin/templates/admin.html` (one link, beside the existing `<a href="/stats">Ingest statistics</a>` near the end of `.shell`)

**Interfaces:**
- Consumes from Task 1: `metrics_view::parse_exposition`, `metrics_view::render_groups_html`, `metrics_view::render_cardinality_html`, `metrics_view::series_count`.
- Consumes existing: `crate::server::METRICS_HANDLE` (`std::sync::OnceLock<metrics_exporter_prometheus::PrometheusHandle>`), `ensure_authorized`, `AdminState`, `ResolvedClientIp`, `TrustedIdentity`.
- Produces: `async fn get_metrics(...) -> Result<Html<String>, Response>`, routed at `GET /metrics` on the admin server, audit action string `METRICS_PAGE_ACCESS`.

- [ ] **Step 1: Write the failing tests**

Add to the existing `#[cfg(test)]` module in `src/admin/routes.rs` (it already has `use tower::util::ServiceExt;`, `test_state()`, `create_request_with_auth`, `create_request_without_auth`, and `inject_connect_info` — use them, do not re-create them):

```rust
    #[tokio::test]
    async fn get_metrics_requires_auth() {
        let state = test_state().await;
        let app = Router::new()
            .route("/metrics", axum::routing::get(get_metrics))
            .with_state(state);
        let mut request = create_request_without_auth(Method::GET, "/metrics");
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// The page must show the live in-process values. Asserted against a
    /// metric this test increments itself, with a name no other test uses:
    /// the Prometheus recorder is a process-global shared with the rest of
    /// this binary, so asserting on a shared metric's exact value would be
    /// flaky.
    #[tokio::test]
    async fn get_metrics_renders_recorded_series_with_valid_auth() {
        crate::server::install_metrics_recorder();
        metrics::counter!("aggregate_records_consumed", "rule" => "get_metrics_page_test")
            .increment(7);

        let state = test_state().await;
        let app = Router::new()
            .route("/metrics", axum::routing::get(get_metrics))
            .with_state(state);
        let mut request = create_request_with_auth(Method::GET, "/metrics", "admin", "admin");
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("aggregate_records_consumed"), "{body}");
        assert!(body.contains("get_metrics_page_test"), "{body}");
        assert!(
            body.contains("Records consumed") || body.contains("aggregate_records_consumed"),
            "the HELP text registered by metrics_descriptions should reach the page:\n{body}"
        );
    }

    /// A watch configured in `logthing.toml` has no `field_distinct_values`
    /// series until its first window boundary (default 3600s). The page must
    /// name it and say so, not silently omit it.
    #[tokio::test]
    async fn get_metrics_lists_a_configured_cardinality_watch_before_its_first_window() {
        let mut config = Config::default();
        config.metrics.cardinality_watch = vec![crate::config::CardinalityWatch {
            source: "wef".to_string(),
            stream: "Security".to_string(),
            field: "computer".to_string(),
        }];
        config.metrics.cardinality_window_secs = 1234;

        let mut state = test_state().await;
        state.config = Arc::new(RwLock::new(config));
        let app = Router::new()
            .route("/metrics", axum::routing::get(get_metrics))
            .with_state(state);
        let mut request = create_request_with_auth(Method::GET, "/metrics", "admin", "admin");
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("computer"), "{body}");
        assert!(body.contains("Security"), "{body}");
        assert!(body.contains("awaiting first window (1234s)"), "{body}");
    }

    #[tokio::test]
    async fn get_metrics_records_audit_log() {
        let state = test_state().await;
        let app = Router::new()
            .route("/metrics", axum::routing::get(get_metrics))
            .with_state(state.clone());
        let mut request = create_request_with_auth(Method::GET, "/metrics", "admin", "admin");
        inject_connect_info(&mut request, "127.0.0.1:12345".parse().unwrap());
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let entries = state.audit_logger.get_entries(10).await;
        assert!(
            entries.iter().any(|e| e.action == "METRICS_PAGE_ACCESS"),
            "expected a METRICS_PAGE_ACCESS entry, got {entries:?}"
        );
    }

    /// The page is server-rendered HTML in an authenticated console; it must
    /// not gain a second interpolation path that bypasses escaping.
    #[test]
    fn metrics_template_contains_no_javascript() {
        let template = include_str!("templates/metrics.html");
        assert!(!template.contains("<script"), "the metrics page must stay JS-free");
    }
```

If the test module does not already import `metrics`, add `use metrics as _;` — no: instead call the macro by full path, `metrics::counter!(...)`, which needs no import. Check the top of the test module and only add imports that are genuinely missing (`Config` and `Arc`/`RwLock` are already imported there).

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test --lib admin::routes::tests::get_metrics
```
Expected: compile error `cannot find function 'get_metrics' in this scope`, plus `couldn't read src/admin/templates/metrics.html` for the template test.

- [ ] **Step 3: Write the implementation**

Create `src/admin/templates/metrics.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>logthing admin — metrics</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 2rem; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 2rem; }
    th, td { border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; vertical-align: top; }
    td.help { color: #555; font-size: 0.85rem; max-width: 32rem; }
    code { word-break: break-all; }
    caption { caption-side: bottom; font-size: 0.85rem; color: #555; margin-top: 0.75rem; text-align: left; }
    .notice { border: 1px solid #c88; background: #fff4f4; border-radius: 8px; padding: 0.75rem; margin-bottom: 1.5rem; }
  </style>
</head>
<body>
  <h1>Metrics</h1>
  <p>The live in-process values — the same numbers the <code>/metrics</code>
  endpoint serves. Read-only.</p>

  {{NOTICE}}

  <h2>Configured cardinality watches</h2>
  <table>
    <thead><tr><th>Source</th><th>Stream</th><th>Field</th><th>Distinct values</th><th>Capped</th></tr></thead>
    <tbody>
      {{CARDINALITY_ROWS}}
    </tbody>
    <caption>Distinct values are counted per window and published at each
    window boundary, so this reports the most recently completed window, not a
    since-boot total. A watch shows &ldquo;awaiting first window&rdquo; until its
    first boundary passes. A count sitting exactly at
    <code>metrics.cardinality_max_values</code> means the cap was hit — read the
    Capped column, not the count.</caption>
  </table>

  <h2>All metrics</h2>
  <table>
    <thead><tr><th>Metric</th><th>Description</th><th>Labels</th><th>Value</th></tr></thead>
    <tbody>
      {{METRIC_TABLES}}
    </tbody>
    <caption>{{SERIES_COUNT}} series. Counters are cumulative since process
    start; gauges are instantaneous. Values reset on restart.</caption>
  </table>

  <p><a href="/">Admin console</a> &middot; <a href="/stats">Ingest statistics</a></p>
</body>
</html>
```

Add the route in `build_admin_router`, after the existing `/stats.json` line:

```rust
        .route("/metrics", axum::routing::get(get_metrics))
```

Add the handler in `src/admin/routes.rs` after `get_stats_json`:

```rust
/// Render the live in-process metric values, plus the configured
/// cardinality watches.
///
/// Reads `crate::server::METRICS_HANDLE` per request rather than caching a
/// `PrometheusHandle`: `main.rs` spawns the admin server *before* it installs
/// the recorder, so a handle captured at admin startup would be captured too
/// early. (This crate has shipped the cached-metrics-handle bug twice —
/// `CardinalityWatcher` and `RuleMetrics`.) A `None` handle is not an error;
/// it means the recorder is off or not up yet, and the page says which.
async fn get_metrics(
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

    let rendered = crate::server::METRICS_HANDLE.get().map(|handle| handle.render());

    let (watches, window_secs, metrics_enabled) = {
        let cfg = state.config.read().await;
        (
            cfg.metrics.cardinality_watch.clone(),
            cfg.metrics.cardinality_window_secs,
            cfg.metrics.enabled,
        )
    };

    // Distinguishing these two matters: "off by configuration" is a settled
    // state an operator chose, while "not installed yet" is the narrow
    // startup window between `spawn_admin_server` and
    // `install_metrics_recorder` in `main.rs` and resolves on its own.
    let notice = match (rendered.is_some(), metrics_enabled) {
        (true, _) => String::new(),
        (false, false) => "<div class=\"notice\">Metrics collection is disabled: \
             <code>metrics.enabled = false</code>. Nothing is being recorded, so this \
             page has no values to show.</div>"
            .to_string(),
        (false, true) => "<div class=\"notice\">The metrics recorder has not finished \
             starting. Reload in a moment.</div>"
            .to_string(),
    };

    let groups = metrics_view::parse_exposition(rendered.as_deref().unwrap_or(""));
    let cardinality_rows = metrics_view::render_cardinality_html(&watches, &groups, window_secs);
    let metric_rows = metrics_view::render_groups_html(&groups);
    let series_count = metrics_view::series_count(&groups);

    state
        .audit_logger
        .log("METRICS_PAGE_ACCESS", &username, &client_ip, None)
        .await;

    let html = include_str!("templates/metrics.html")
        .replace("{{NOTICE}}", &notice)
        .replace("{{CARDINALITY_ROWS}}", &cardinality_rows)
        .replace("{{METRIC_TABLES}}", &metric_rows)
        .replace("{{SERIES_COUNT}}", &series_count.to_string());
    Ok(Html(html))
}
```

Add the import at the top of `src/admin/routes.rs`, in the internal-modules group:

```rust
use crate::admin::metrics_view;
```

In `src/admin/templates/admin.html`, replace the existing link line:

```html
        <p><a href="/stats">Ingest statistics</a></p>
```

with:

```html
        <p><a href="/stats">Ingest statistics</a> &middot; <a href="/metrics">Metrics</a></p>
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test --lib admin::
cargo fmt
cargo clippy --lib -- -D warnings
```
Expected: every `admin::` test passes, including the pre-existing ones (`config_write_endpoints_are_gone`, `admin_page_renders_config_read_only`, and the rest — this task must not regress them). No clippy warnings.

- [ ] **Step 5: Commit**

```bash
git add src/admin/routes.rs src/admin/templates/metrics.html src/admin/templates/admin.html
git commit -m "feat(admin): serve the metrics page on the admin console

GET /metrics on the admin server renders the live counters and gauges from
METRICS_HANDLE behind the same auth and audit logging as every other admin
route, with a dedicated section for the operator-configured cardinality
watches. The handle is read per request, never cached: main.rs spawns the
admin server before installing the recorder.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: End-to-end — the real admin server over a real socket

**Files:**
- Create: `tests/admin_metrics_page_e2e.rs`
- Test: same file

**Interfaces:**
- Consumes: `logthing::admin::spawn_admin_server`, `logthing::server::install_metrics_recorder`, `logthing::stats::SourceHourlyStats`, `logthing::stats::cardinality::{CardinalityWatcher, compile_watches}`, `logthing::config::{Config, CardinalityWatch}`.
- Produces: nothing other tasks consume.

**Note on `tick()`:** `CardinalityWatcher::tick` is `pub(crate)`, so an external integration test cannot call it. Drive the real window boundary instead by setting `cardinality_window_secs` to 1 and using `spawn_ticker`, which is `pub`. Confirm the visibility of both with `grep -n "pub fn spawn_ticker\|fn tick" src/stats/cardinality.rs` before writing the test, and if `spawn_ticker`'s signature differs from the one below, follow the real signature — do not change `src/stats/cardinality.rs`.

- [ ] **Step 1: Write the failing test**

```rust
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

use logthing::admin::spawn_admin_server;
use logthing::config::{CardinalityWatch, Config};
use logthing::stats::SourceHourlyStats;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

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
    // this process races these variables.
    unsafe {
        std::env::set_var("LOGTHING_ADMIN_BIND", format!("127.0.0.1:{port}"));
        std::env::set_var("LOGTHING_ADMIN_ENABLE_RATE_LIMIT", "false");
        std::env::set_var("LOGTHING_ADMIN_USERNAME", "admin");
        std::env::set_var("LOGTHING_ADMIN_PASSWORD", "admin");
    }
    spawn_admin_server(
        Arc::new(RwLock::new(config)),
        Arc::new(SourceHourlyStats::new()),
    );

    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{port}");
    let mut ready = false;
    for _ in 0..50 {
        if let Ok(resp) = client.get(format!("{base_url}/health")).send().await {
            if resp.status().is_success() {
                ready = true;
                break;
            }
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
    assert!(
        !body.contains("awaiting first window"),
        "a watch whose window boundary has passed must show a real count:\n{body}"
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
```

- [ ] **Step 2: Run the test to verify it fails for the right reason**

```bash
cargo test --test admin_metrics_page_e2e
```
Expected before Task 2's route exists: a 404 assertion failure. Since Task 2 is already done when you reach here, expect it to PASS. If it fails on a missing dev-dependency (`base64`, `metrics`, `reqwest`), check `Cargo.toml`'s `[dev-dependencies]` first — `reqwest` is already used by the other admin e2e tests. **Do not add a dependency**; if `base64` is unavailable as a dev-dependency, encode the credential inline the way `src/admin/routes.rs`'s test helper `encode_base64` does and copy that helper into this file.

- [ ] **Step 3: Verify the environment-variable names against the real loader**

```bash
grep -n "LOGTHING_ADMIN" src/admin/state.rs | head -20
```
Use the exact variable names `load_admin_config` reads. If the username/password variables are named differently, fix the test to match; do not change `state.rs`.

- [ ] **Step 4: Run the full suite**

```bash
cargo test --all-targets 2>&1 | tail -40
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```
Expected: no new failures anywhere. Report the exact pass/fail counts.

- [ ] **Step 5: Commit**

```bash
git add tests/admin_metrics_page_e2e.rs
git commit -m "test(admin): e2e the metrics page over a real socket

Real recorder, a real cardinality watch driven through a real window
boundary by spawn_ticker, the real admin server on a real port: asserts the
counter, its label, its value and the watch's distinct count all reach the
page, and that unauthenticated access is still refused.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:** value source (Task 2 handler) ✅; parsing module with the five named functions (Task 1) ✅; `quick_xml::escape::escape` at every interpolation (Task 1, enforced by a hostile-label test) ✅; cardinality join with all three states (Task 1 tests + Task 2 integration test) ✅; route/auth/audit (Task 2) ✅; both `None`-handle notices (Task 2) ✅; template with the four placeholders and zero JS (Task 2, enforced by `metrics_template_contains_no_javascript`) ✅; `admin.html` link (Task 2) ✅; three test levels (Tasks 1, 2, 3) ✅; nothing built from the "deliberately not built" list ✅.

**Placeholder scan:** no TBDs; every code step carries the real code; the two places a task must verify reality before writing (`spawn_ticker`'s signature, the `LOGTHING_ADMIN_*` variable names) give the exact command to run and say explicitly not to modify the module being checked.

**Type consistency:** `parse_exposition`/`render_groups_html`/`render_cardinality_html`/`series_count` are named identically in Task 1's interface block, Task 1's implementation, and Task 2's handler. `Sample`/`MetricGroup` field names match between definition and use. Template placeholders `{{NOTICE}}`, `{{CARDINALITY_ROWS}}`, `{{METRIC_TABLES}}`, `{{SERIES_COUNT}}` match the handler's four `.replace` calls exactly.
