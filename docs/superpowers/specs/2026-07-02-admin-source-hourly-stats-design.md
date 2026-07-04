# Admin console: per-source hourly ingest counts

Status: approved via auto-develop (independent reviewer coherence check passed, round 2)
Branch: `feature/admin-source-hourly-stats`

## Origin

User request (verbatim): "Brainstorm a basic http admin interface that binds to
local host and lists basic metrics about the ingested logs, eg count per
source by hour."

Produced via `superpowers:brainstorming` (architecture + components sections
approved by the user) followed by `auto-develop` for the remaining
implementation details, with an independent reviewer subagent checking the
full decision log for coherence before implementation (2 rounds; approved on
round 2).

## Problem

logthing has no single place to see "how much is each source ingesting,
recently." Related-but-different things already exist:

- `src/admin/` — an admin console bound to `127.0.0.1:8080` by default (refuses
  to start on a non-loopback bind with default credentials — see
  `admin_start_allowed` in `src/admin/state.rs`), with basic auth
  (`ensure_authorized`), CSRF, rate limiting, and an audit log. It serves
  config management today, no metrics.
- `/stats/throughput` on the data-plane server (`src/server/mod.rs`) —
  minute-bucketed, 60-minute retention, but only fed from the WEF/HTTP ingest
  path (`record_event` has exactly one call site). Syslog/ipfix/sflow/zeek/
  suricata never feed it.
- A Prometheus `/metrics` endpoint — per-source counters
  (`parquet_s3_records_written{source=...}` etc.) that *do* cover every
  source, but as instantaneous counters with no hourly bucketing; that's
  normally Prometheus/Grafana's job, which this project doesn't run.

This feature closes that gap with the smallest addition that covers every
source uniformly.

## Scope

In scope: one new in-memory, hour-bucketed, per-source counter; two new
read-only routes on the existing admin console displaying it. Out of scope
(explicitly, per "basic"): persistence across restarts, retention beyond 24h,
external time-series storage, per-event-type granularity, write/delete
endpoints, alerting.

## Design

### Data model — `SourceHourlyStats` (new, in `src/stats/mod.rs`)

Mirrors the existing `ThroughputStats` in the same file (a `DashMap`-backed,
lock-free, retention-capped counter), with two deliberate differences:

- Keyed by **pipeline/protocol source** (`"wef"`, `"syslog"`, `"ipfix"`,
  `"sflow"`, `"zeek"`, `"suricata"`, `"hec"` (the generic/HEC ingest sink's
  label — matches its S3 prefix), `"structured_syslog"`) —
  the same string returned by `ParquetSink::source()` in
  `src/forwarding/buffered_writer.rs`, already used as the S3-key and metrics
  label for every source. Chosen over `ThroughputStats`'s finer
  event-type keying because event-type is WEF-specific and doesn't
  generalize; source-level does.
- Bucketed by **hour**, not minute, with a rolling **24-hour** retention
  (in-memory only, reset on restart — deliberately not an audit trail).

```rust
pub struct SourceHourlyStats {
    inner: Arc<DashMap<String, SourceBuckets>>,
}

struct SourceBuckets {
    buckets: VecDeque<HourBucket>, // retained: last 24 hours
}

struct HourBucket {
    hour: i64,   // Utc::now().timestamp() / 3600, mirrors ThroughputStats::current_minute()
    count: u64,
}

#[derive(Serialize, Clone)]
pub struct SourceHourlySnapshot {
    pub source: String,
    pub hours: Vec<HourCount>, // oldest -> newest, last 24h
}

#[derive(Serialize, Clone)]
pub struct HourCount {
    pub hour: chrono::DateTime<chrono::Utc>, // hour-truncated, RFC3339 on serialize
    pub count: u64,
}
```

`record(&self, source: &str, count: u64)` is a **plain sync fn**, not
`async fn` like `ThroughputStats::record_event` — `DashMap` entry access has
no await point here, so `async` would be a pointless wrapper copied from the
template for cosmetic consistency only (YAGNI).

`snapshot(&self) -> Vec<SourceHourlySnapshot>` returns one entry per known
source with its last-24h hour buckets, oldest first.

### Counting hook — `push()`, not `flush_partition()`

**This is the one place the design changed from the initially-approved
sketch**, based on an independent reviewer catching a real bug in the first
pass: counting at `flush_partition()` time (next to the existing
`metrics::counter!("parquet_s3_records_written", ...)` call) would attribute
counts to the hour a buffer happened to flush, not the hour its records
arrived — flushes are triggered by row/byte/interval thresholds, not hour
boundaries, so a slow-filling buffer skews the hour a record shows up under.

Fix: count in `PartitionedParquetWriter::push()` instead, which already
handles exactly one record per call. Right after the existing
`to_record_batch` success (`buffered_writer.rs`, current line ~238-247):

```rust
let batch = match self.sink.to_record_batch(&record, &schema) {
    Ok(b) => b,
    Err(e) => { tracing::warn!(...); return Ok(()); }
};
self.source_stats.record(self.sink.source(), 1);
```

This counts once per record, at the moment it's accepted into the pipeline —
attributing it to the hour it actually arrived, independent of flush timing.
Verified against the real control flow: `push()` is called once per record
from a single-consumer channel loop with no retry-on-push-error path, so
there's no double-counting risk from retries, and channel-overflow drops
(`try_send`'s `parquet_s3_dropped` path) happen *before* `push()` runs, so
overflowed records are never counted.

**Accepted trade-off, stated explicitly:** a record that is later evicted by
`drop_oldest_to_cap` (which only happens during a *sustained* S3 outage — a
degenerate path already surfaced by the separate `parquet_s3_buffer_dropped`
and `parquet_s3_upload_errors` metrics) will still have been counted here,
even though it was never durably written to S3. For this feature, "ingested"
means *accepted into the write pipeline*, not *durably persisted* — chosen
because correct hour-of-arrival attribution matters more for a glance metric
than exact correspondence to bytes-on-S3, and the failure mode this accepts
(brief overcounting during an outage that's already alerted on elsewhere) is
rare and bounded.

This redefinition must be visible to whoever reads the page, not just in a
code comment: the `/stats` HTML page carries a one-line footnote, e.g.
*"Counts records accepted into the write pipeline; may include a small
overcount during a sustained S3 outage (see parquet_s3_upload_errors)."*

### Threading `SourceHourlyStats` through 8 independent writers

`PartitionedParquetWriter::new()` / `ParquetWriterHandle::start()` are each
called from **8 separate per-source production wrapper functions**
(`syslog_start`, `ipfix_start`, `zeek_start`, `suricata_start`, `sflow_start`,
`wef_start`, `hec_start`, `structured_syslog_start` — one in each
`src/forwarding/*_s3.rs` file) plus **~20 existing test call sites** across
`buffered_writer.rs` and those same files.

Rejected: making `source_stats` a required parameter of `new()`/`start()`
directly — would force mechanically editing all ~20 test call sites that
have nothing to do with this feature. Also rejected: a process-wide global
singleton (e.g. `LazyLock`) — would cause cross-test interference under
parallel `cargo test` (shared `DashMap` across the whole test binary) and
breaks from this codebase's established explicit-Arc-injection convention
(`ThroughputStats`, `AdminState`).

Chosen: builder-style additions that keep every existing call site
compiling unchanged:

```rust
impl<S: ParquetSink> PartitionedParquetWriter<S> {
    pub fn new(sink: S, s3: Arc<S3Sink>, config: BufferedWriterConfig, policy: FlushPolicy) -> Self {
        Self::with_source_stats(sink, s3, config, policy, Arc::new(SourceHourlyStats::default()))
    }

    pub fn with_source_stats(
        sink: S, s3: Arc<S3Sink>, config: BufferedWriterConfig, policy: FlushPolicy,
        source_stats: Arc<SourceHourlyStats>,
    ) -> Self { /* real constructor */ }
}
```

Same pattern for `ParquetWriterHandle::start` / `start_with_stats`. Only the
8 production wrapper functions and `main.rs` are changed to require and pass
through a real, shared `source_stats: Arc<SourceHourlyStats>` — a normal
(non-optional) parameter, so `main.rs` fails to compile if any of the 8 call
sites omits it.

`main.rs` constructs one instance alongside the existing `ThroughputStats`:

```rust
let source_stats = Arc::new(stats::SourceHourlyStats::new());
```

and clones it into each of the 8 `_start(...)` calls and into
`admin::spawn_admin_server(shared_config.clone(), source_stats.clone())`
(that function's signature gains a parameter).

### Admin console additions

- `src/admin/state.rs`: `AdminState` gains `source_stats: Arc<SourceHourlyStats>`.
- `src/admin/routes.rs`: two new handlers, both calling `ensure_authorized`
  first exactly like `get_config`/`get_audit_log` (same auth as `/config`,
  `/audit-log` — more sensitive than a bare `/health` liveness check):
  - `GET /stats` → HTML table (source rows × hour columns), via
    `include_str!("templates/stats.html").replace(...)` on a new static
    template, matching the existing `admin_page` pattern
    (`src/admin/routes.rs:185`) — no templating crate added, since none
    exists in `Cargo.toml` and the data volume (≤8 sources × ≤24 hours) needs
    nothing beyond `format!`-built rows. Source strings are compile-time
    `&'static str` constants, never attacker-controlled, so no
    HTML-escaping concern.
  - `GET /stats.json` → `Json<Vec<SourceHourlySnapshot>>`, e.g.:
    ```json
    [{ "source": "syslog", "hours": [{ "hour": "2026-07-02T13:00:00Z", "count": 42 }] }]
    ```
    Nested per-source (not a flat list of rows) because that directly
    matches "count per source by hour" and mirrors how the HTML groups rows.

### Error handling

- No credentials on `/stats` or `/stats.json` → 401, via the existing
  `ensure_authorized` error path (identical to `/config`).
- No data yet (fresh restart) → empty table / empty JSON array, not an
  error.
- A failed S3 upload does not retroactively un-count a record already
  counted at `push()` time (see accepted trade-off above) — this is
  intentional, not a bug to fix later.

## Testing (three levels, per project policy)

**Unit** (`src/stats/mod.rs`): `SourceHourlyStats::record`/`snapshot`,
including hour-boundary bucket creation and 24-hour retention eviction —
mirroring `ThroughputStats`'s existing test style.

**Integration**:
- One new test in *each* of the 8 `src/forwarding/*_s3.rs` files' existing
  test modules (which already construct writers directly via
  `PartitionedParquetWriter::new(...)` for other tests), using
  `with_source_stats(..., shared_stats.clone())` instead, pushing one record,
  and asserting `shared_stats.snapshot()` contains that source's exact
  `source()` string with count 1. This directly proves each source's sink
  reports under the correct key — closing the risk that any one of the 8
  is wired incorrectly, beyond what the compiler alone enforces.
- `src/admin/routes.rs` tests (using the existing `tower::ServiceExt::oneshot`
  pattern already used throughout that file) asserting `/stats` and
  `/stats.json` return 401 without credentials and correct data with valid
  credentials.

**End-to-end**: a test that reproduces `main.rs`'s actual wiring rather than
just the admin route in isolation — construct **one** shared
`Arc<SourceHourlyStats>`, push a record through a real
`PartitionedParquetWriter` built with it, spawn the real admin axum app bound
to an ephemeral loopback port (`TcpListener::bind("127.0.0.1:0")`, matching
the socket-test pattern already used elsewhere, e.g.
`src/forwarding/mod.rs:479`), and issue a real HTTP request with a Basic Auth
header to `/stats.json` over that live socket, asserting the pushed record's
count appears. This specifically catches a mis-wiring the per-source
integration tests can't: passing a *different* `Arc` into
`spawn_admin_server` than the one the writers use, which would compile
cleanly but leave `/stats` silently empty.

## Out of scope / explicitly deferred

- Persistence across restarts (in-memory 24h retention is a deliberate
  "basic" choice).
- Any UI beyond a plain HTML table (no charts, no JS).
- Extending `/stats.json` with a machine-readable flag distinguishing
  "pipeline-accepted" vs. "durably written" counts — the HTML footnote
  covers the human-readable case; revisit only if this redefinition proves
  confusing in practice.
