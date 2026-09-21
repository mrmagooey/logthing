# Field cardinality metric — design

Status: approved (auto-develop coherence review, round 2)
Date: 2026-09-20
Branch: `feat/field-cardinality-metric`

## Problem

An operator has no quick way to tell from `/metrics` whether ingestion is
actually healthy. Every existing metric counts *volume* — datagrams, records,
parse errors — and volume looks fine when a subset of sources silently stops
reporting. The question an operator actually asks is comparative: "we have
roughly 5000 hosts; am I seeing roughly 5000 distinct hosts in the data?"

Nothing in the crate answers that. `ThroughputStats` and `SourceHourlyStats`
bucket record counts, not distinct values. The Zeek schema registry describes
the *output* columns, not what arrived.

## Non-goals

- Distinct field **names** per record type. That is a schema-drift signal, a
  different question from this one.
- Distinct values of **every** field. Unbounded: exact sets reach hundreds of
  MB for a single high-cardinality field, and a sketch would need a new
  dependency, ~30 MB, and thousands of gauges — wildly out of proportion to a
  crate whose entire `DESCRIPTIONS` table is a few dozen metric names.
- Any source other than Zeek. Deliberate; see "Scope" below.

## Why not reuse the aggregator

`aggregate_groups{rule}` is already a capped distinct-value count per rule, so
configuring a `group_by = ["id.orig_h"]` rule looks like a zero-code answer.

It is a trap. `AggregatingZeekHandler` (`src/forwarding/aggregate/handlers.rs:19`)
is a decorator that **swallows** every record it matches:

```rust
if self.agg.consume("zeek", &record) { return; }
```

The test `a_matched_record_is_counted_and_not_forwarded` asserts the raw writer
receives zero records. Adding a rule purely to count hosts would silently stop
forwarding every matched record to S3. Aggregation is a data-reduction feature,
not an observability one.

## Design

### Metrics

| Kind | Name | Meaning |
|---|---|---|
| Gauge | `field_distinct_values{stream,field}` | Distinct values seen during the most recently completed window |
| Counter | `field_distinct_values_capped{stream,field}` | A never-seen value was discarded because the cap was reached |

Both label values come from **configuration**, never from the wire. This is the
load-bearing safety property: a wire-derived label lets any client that can
reach the listener mint unbounded Prometheus series. The crate already defends
this way in `metric_event_type` (`src/suricata/schema.rs:170`) and
`metric_log_path` (`src/zeek/schema.rs:1779`), both of which collapse unknown
wire strings to a fixed `"other"`.

Both are registered in `DESCRIPTIONS` (`src/metrics_descriptions.rs:34`), which
has tests failing on both undescribed and stale entries.

### Config

```toml
[metrics]
cardinality_watch_field  = "id.orig_h"   # optional; unset = feature off
cardinality_watch_stream = "conn"        # required when field is set
cardinality_window_secs  = 3600
cardinality_max_values   = 100000
```

Zeek is implied — there is no `source` key. Ships **commented out** in
`logthing.toml`, matching the convention every other optional feature follows
there (and `[zeek]` itself ships `enabled = false`, so a force-on default would
watch a disabled source).

Three fatal startup validations, following the precedent and reasoning of
`compile_rules` (`src/forwarding/aggregate/mod.rs:604`) — a watch that silently
never matches is worse than a startup error:

1. `cardinality_window_secs` > 0 — zero panics `tokio::time::interval`.
2. `cardinality_watch_field` non-empty if present.
3. `cardinality_watch_stream` set whenever `cardinality_watch_field` is.

### Data flow

1. Zeek listener parses a record.
2. At `src/zeek/listener.rs:483` — alongside the existing `zeek_records_received`
   counter, before `handler.handle_record` — the record is offered to the watcher.
3. The watcher matches the record's stream, extracts the value via
   `AggFields::field` + `group_value_string`, and inserts into a capped `DashSet`.
   A record missing the field is not observed at all.
4. A background ticker every `window_secs` reads the set size, publishes the
   gauge, and clears the set.

**Why the listener, not a handler.** The comment at that site already explains
it: every handler (`Default`, `Multi`, `Aggregating`) routes through this one
point, so a metric here fires regardless of which forwarding destinations are
configured. This crate has previously shipped metrics inside `Default*Handler`s
that never fired in production. It also sits *upstream* of the aggregator's
swallow, so the count is unaffected by aggregation rules.

**Why not `buffered_writer::push()`.** That function carries an explicit comment
forbidding added unconditional per-record work.

### Reuse

`ZeekRecord` already implements `AggFields` (`src/forwarding/aggregate/fields.rs:18`),
and `group_value_string` (`fields.rs:46`) already truncates to
`MAX_GROUP_VALUE_BYTES` (256), bounding per-value memory. No new JSON lookup and
no new truncation code. `dashmap` is already a direct dependency, so `DashSet`
costs nothing new.

### Window semantics

The gauge reports the most recently **completed** window, not a cumulative count
since boot. Since-boot only ratchets upward and can never show a source going
silent — the exact failure this metric exists to catch.

The 3600s default is sized for Zeek's traffic shape: `conn.log` entries are
emitted per-connection-close, not as a heartbeat, so the window must be long
enough that a normally-quiet host still appears within it. A 300s window would
read chronically below the true host count for perfectly healthy ingestion.

### Concurrency

The cap is `contains`-then-`insert` over a lock-free `DashSet`, mirroring
`ThroughputStats::record_event` (`src/stats/mod.rs:54`). That idiom genuinely
races: concurrent callers can each observe room under the cap and all insert,
overshooting by up to (concurrent callers − 1). The overshoot is bounded by
caller concurrency, not by input size, so it is accepted rather than closed —
and carried in a `ponytail:` comment, as the existing code does.

## Known limitations (documented in HELP text, not just here)

- **`id.orig_h` is an IP, not a stable host identity.** DHCP churn, NAT, and
  multi-homing move the distinct-IP count independently of ingestion health, and
  a sensor observing inbound traffic sees external originators that are not org
  hosts at all. The count is a proxy, not an identity count.
- **A gauge reading exactly the configured cap is not a measurement.** It means
  saturation; read `field_distinct_values_capped`. The 100000 default is roughly
  an order of magnitude above a typical internal host count; a sensor seeing
  external originators can exceed it.
- **Alert on sustained multi-window drops**, not on absolute equality to a known
  host count. A single window's absolute value is noisy.
- **State resets on restart**, as every in-memory stat here does
  (`src/stats/mod.rs:216`), so a deploy looks briefly like a host-count cliff.
- **A mistyped field name** would otherwise produce a permanent-zero gauge
  indistinguishable from a total outage. At the window boundary, if records
  matched the stream but the field was never found, a one-shot warning naming
  the configured field is logged.

## Scope

Zeek only. The four other ingest sources are not wired, and there is no `source`
config dimension to wire them through — the omission is structural rather than
validated away. A `ponytail:` comment records this and what adding a source would
take.

## Testing

- **Unit** — cap at and above the limit (value dropped, counter fires), window
  clear resets the count, absent field not observed, stream filter matches and
  excludes, all three config validation failures.
- **Integration** — drive the listener, assert the gauge after a window boundary,
  via `DebuggingRecorder` + `set_default_local_recorder` (pattern at
  `src/zeek/listener.rs:637`).
- **E2E** — assert the metric on a real `/metrics` HTTP endpoint, templated on
  `tests/zeek_received_metric_e2e.rs:100`.
- **Hostile input** — adversarial `id.orig_h` values (16 KiB string, NUL-injected,
  empty, thousands of unique) must change the gauge's *value* without growing the
  Prometheus *series* count, in the spirit of
  `metric_event_type_bounds_the_label_to_the_known_set`.

## Rejected alternatives

| Option | Why rejected |
|---|---|
| Reuse `aggregate_groups` via a `group_by` rule | Swallows matched records; breaks S3 forwarding |
| Distinct field *names* | Answers schema drift, not ingestion health |
| HyperLogLog over all fields | New dependency, ~30 MB, ~2500 gauges; operator needs exactness against a known host count, not ±0.8% |
| Unbounded `HashSet` of values | 150–250 MB for one field; memory DoS |
| `Vec` of watches with a `source` key | Built a general dimension that startup validation immediately rejected for everything but `"zeek"` |
| Optional stream (unset = all streams) | Generality with no driving use case; made unrepresentable instead |
