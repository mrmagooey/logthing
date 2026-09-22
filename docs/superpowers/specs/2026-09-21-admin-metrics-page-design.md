# Admin console metrics page — design

Status: approved (auto-develop coherence review, round 1 of 3)
Date: 2026-09-21
Branch: `feat/admin-metrics-page`

## Problem

Everything the process measures is only visible on the `/metrics` listener
(`src/server/mod.rs::serve_metrics_endpoint`) — raw Prometheus text, on a
different port, gated only by `security.allowed_ips` with no auth. The admin
console (`src/admin/`) shows effective config, env var names, the audit log,
and per-source hourly ingest counts, but none of the ~142 counters and gauges
the crate emits. An operator with the admin console open has to leave it,
find the metrics port, and read exposition text to answer "is anything
actually flowing".

The `[[metrics.cardinality_watch]]` counts are the sharpest case. An operator
configures them by hand and then has no way to confirm from the console that
the watch is even live — and because `CardinalityWatcher::tick` only publishes
`field_distinct_values` at a window boundary (`cardinality_window_secs`,
default 3600), the series is genuinely absent from `/metrics` for up to an
hour after boot. "Configured but not yet sampled" and "misconfigured, never
matching" look identical from outside.

## Scope

A read-only `/metrics` page on the **admin** server that renders the live
in-process metric values, plus a dedicated section joining the configured
cardinality watches against their samples. No change to the existing
`/metrics` listener, no new dependency, no JSON sibling, no JS.

## Design

### Where the values come from

The handler reads the existing `pub static METRICS_HANDLE`
(`src/server/mod.rs:45`) and calls `.render()` **at request time**.

`METRICS_HANDLE` is already the single source of truth for the real endpoint.
Reading it per-request rather than caching a `PrometheusHandle` in
`AdminState` matters here: `main.rs` calls `spawn_admin_server` (line 94)
*before* `install_metrics_recorder` (line 132), so anything captured at admin
startup would be captured too early. This repo has shipped the
cached-metrics-handle bug twice already (`CardinalityWatcher`,
`RuleMetrics`); per-request resolution is the shape that cannot repeat it.

Rejected: plumbing a handle through `spawn_admin_server`'s signature (adds
public API for no gain, and is exactly the too-early capture above);
self-scraping `http://localhost:<metrics.port>/metrics` (subject to the IP
whitelist, and dead whenever the metrics listener is off).

### Parsing

New module `src/admin/metrics_view.rs`, pure functions only:

- `Sample { name, labels, value }` — `labels` is the verbatim `{...}` text
  from the line, `value` the verbatim value text. No float round-trip, so a
  counter renders exactly as the exporter wrote it.
- `MetricGroup { name, help, samples }`.
- `parse_exposition(rendered) -> Vec<MetricGroup>` — single pass.
  `# HELP <name> <text>` populates a help map; `# TYPE` is ignored (the page
  does not show a type column); every other non-empty, non-`#` line splits on
  the *last* space into key + value, and the key at the first `{` into name +
  labels. Same line idiom as the existing `profiling::parse_counter`.
  Malformed lines are skipped, never fatal — a metrics page that 500s is
  worse than one missing a row. Groups sorted by name, samples sorted by
  label text.
- `render_groups_html(&[MetricGroup]) -> String` — one table, one `<tbody>`
  per metric, the name and HELP text carried in `rowspan` cells so they are
  stated once per metric rather than repeated per series.
- `render_cardinality_html(&[CardinalityWatch], &[MetricGroup], window_secs)
  -> String`.

`profiling::parse_counter` is **not** reused: it sums one metric name and
discards labels and HELP, which are the two things this page is for.

### Escaping

Every interpolated string goes through `quick_xml::escape::escape` — the
helper `admin_page` already uses at `src/admin/routes.rs:243` for
`{{CONFIG_TOML}}`. Metric label values are partly wire-derived, so this is a
trust boundary, not a place to be lazy; and no new escaper (or dependency) is
needed to hold it.

### The cardinality section

For each entry in `config.metrics.cardinality_watch`, join against the
parsed `field_distinct_values` and `field_distinct_values_capped` samples on
the `(source, stream, field)` label triple, and render:

| state | shown |
|---|---|
| sample present | distinct count + capped count |
| configured, no sample yet | `awaiting first window (<N>s)` |
| no watches configured at all | a one-line note that the feature is off |

The middle row is the whole reason this is a dedicated section rather than
just letting `field_distinct_values` appear in the generic table: for up to
`cardinality_window_secs` after boot a correctly configured watch is simply
missing from the exposition, which reads as a bug. The generic table still
lists both series as well.

### Handler

`get_metrics` in `src/admin/routes.rs`, registered as
`.route("/metrics", axum::routing::get(get_metrics))` — no conflict, the
admin server is its own listener on its own port. It follows every sibling
handler exactly: resolve client IP, `ensure_authorized`, do the work, record
an audit entry (`METRICS_PAGE_ACCESS`), return `Html`.

This makes the admin view *more* protected than the raw `/metrics` endpoint,
which is fine and deliberate.

`METRICS_HANDLE.get() == None` is not an error — the page renders with a
notice, distinguishing the two causes, since `AdminState` has the config:

- `metrics.enabled == false` → "metrics collection is disabled in
  configuration".
- enabled but handle unset → "the metrics recorder is still starting"
  (the narrow window between `main.rs:94` and `main.rs:132`).

### Template

New `src/admin/templates/metrics.html`, styled like `stats.html`, **zero
JavaScript**, placeholders `{{NOTICE}}`, `{{CARDINALITY_ROWS}}`,
`{{METRIC_TABLES}}`, `{{SERIES_COUNT}}`. A caption states that values are the
live in-process values (identical to what `/metrics` serves) and that
cardinality gauges report the most recently completed window.

One line added to `admin.html`: a `/metrics` link beside the existing
"Ingest statistics" link.

## Testing

- **Unit** (`metrics_view.rs` `#[cfg(test)]`): `parse_exposition` over HELP
  before/after TYPE, labelled and unlabelled samples, a metric with no HELP,
  a malformed line, empty input; `render_groups_html` proves a hostile label
  value (`<img src=x onerror=alert(1)>`) comes out escaped and never as raw
  markup; `render_cardinality_html` covers all three states above.
- **Integration** (`routes.rs` `#[cfg(test)]`, `oneshot`): auth required;
  renders recorded counters with valid auth; lists a configured watch as
  awaiting its first window; records the audit entry. Assertions are on page
  structure and the join, not on a specific global counter value — the
  recorder is process-global and shared with the rest of the binary.
- **E2E** (`tests/admin_metrics_page_e2e.rs`, exactly one `#[tokio::test]`
  per the process-global recorder convention): install the real recorder,
  increment a distinctly-named counter, drive a real `CardinalityWatcher`
  through `observe` + `tick`, start the real `spawn_admin_server` on a
  reserved port with a matching `cardinality_watch`, poll `/health`, then GET
  `/metrics` with basic auth over a real socket and assert the counter name,
  its value, its HELP text, and the cardinality row all appear.

## Deliberately not built

No `/metrics.json` sibling (the real endpoint already is the machine-readable
form), no charts or sparklines, no auto-refresh, no name filter box, no
`# TYPE` column, no row cap on the generic table (label sets are already
bounded upstream), no change to the unauthenticated `/metrics` listener, no
new dependency.
