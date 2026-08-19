# Log Aggregation (SQL `GROUP BY` → Parquet) — Design

**Date:** 2026-08-18
**Status:** Approved (autonomous design via `auto-develop`; coherence-reviewed, 3 rounds)

## Goal

Reduce noisy logging at the input stage while keeping the most valuable
information about the environment. Instead of persisting every raw record of a
noisy stream, count records as they arrive, grouped by configured columns, and
write the resulting table to Parquet — the output of an SQL `GROUP BY`.

Example: Zeek `dns` grouped by query name and originating host, with the count
of each combination over the collection period.

## Fixed constraints

These were decided by the user and are not open for revision during
implementation:

- **C1 — Generic across all sources.** zeek, suricata, syslog, ipfix, sflow.
  (wef/hec/otlp are out of scope for this change.)
- **C2 — The window is a flush interval, not event time.** A record counts into
  whichever window is open when it arrives.
- **C3 — Raw records are suppressed.** A stream covered by a rule stops writing
  raw Parquet rows entirely; only the counted table is written. Streams with no
  rule are untouched.
- **C4 — count + sum/min/max** on numeric fields. (Count-only was rejected:
  ipfix/sflow rollups are fundamentally `sum(bytes)`.)

## Architecture

```
listener → AggregatingXHandler (decorator)
              ├─ rule matches → Aggregator::consume()   [counted; NOT forwarded]
              └─ no match     → inner handler (existing raw S3/local writer)

Aggregator ── tick(flush_interval_secs) ──→ drain map → AggregateRow ×N
                                              → ParquetWriterHandle<AggregateSink> → S3 / local disk
```

The decorator **wraps** the existing per-source handler chain rather than being
appended to `main.rs`'s `Vec<Arc<dyn XHandler>>`: suppression requires being
upstream of the raw writer.

All buffering, flush, cap, encode, and upload behavior is the existing
`PartitionedParquetWriter` machinery (`src/forwarding/buffered_writer.rs`),
unchanged. This design adds one new `ParquetSink` adapter and the aggregation
state in front of it.

## Module layout

`src/forwarding/aggregate/`:

- `mod.rs` — `Aggregator`, `GroupKey`, `Acc`/`AggAcc`, `AggregateRow`,
  `AggregateSink`, compiled rules, emit task.
- `fields.rs` — the `AggFields` trait and its five implementations.
- `handlers.rs` — the five decorator handlers.

(Split up front: the ipfix/sflow curated-field match arms alone run to a few
hundred lines.)

## Components

### `AggFields` (`fields.rs`)

```rust
enum FieldValue<'a> { Str(Cow<'a, str>), Num(f64), Bool(bool) }

trait AggFields {
    fn stream(&self) -> &str;
    fn field(&self, name: &str) -> Option<FieldValue<'_>>;
}
```

Implemented for `ZeekRecord`, `SuricataRecord`, `SyslogMessage`, `FlowRecord`,
`SflowRecord`.

- **JSON-backed records** (zeek, suricata): look up the **literal key first**
  (`"id.orig_h"` is one flat key in Zeek NDJSON), then fall back to a dotted
  path (`dns.rrname` is nested in Suricata EVE).
- **Typed records** (ipfix, sflow, syslog): `match` on the field name over the
  curated struct fields, falling back to the record's `extra` JSON
  (`structured_data` for syslog).

`stream()` returns: zeek → `log_path`; suricata → `event_type`; syslog →
`app_name` (or `""` when absent); ipfix → `"flows"`; sflow → `"flow"` /
`"counter"`.

### Group key construction

For each `group_by` column:

- Field missing → `None` → a **null** in that column; the record is still
  counted.
- `Str(s)` → `s`.
- `Num(n)` → formatted as `i64` when `n.fract() == 0.0 && n.abs() < 2^53`,
  else `{n}`.
- `Bool(b)` → `"true"` / `"false"`.

Every value is then truncated to **256 bytes**, walked back to the nearest
`char` boundary via `str::is_char_boundary`.

### `Aggregator` (`mod.rs`)

```rust
enum GroupKey { Keys(Box<[Option<String>]>), Other }

struct AggAcc { sum: f64, min: f64, max: f64, n: u64 }
struct Acc    { count: u64, aggs: Vec<AggAcc> }

// Mutex<HashMap<(usize /*rule_idx*/, GroupKey), Acc>>
fn consume<R: AggFields>(&self, source: &str, rec: &R) -> bool;
```

`consume` returns `true` when **at least one** rule matched, in which case the
caller does not forward the record. A record matching two rules is counted in
both (two independent `GROUP BY` views over one stream); suppression is still
single-fire.

`GroupKey::Other` is a distinct variant, so the overflow bucket can never be
produced by a real field lookup — a record whose every `group_by` field is
absent yields `Keys([None, …])`, not `Other`.

**Cardinality cap.** Once a rule holds `max_groups` keys, every new key folds
into that rule's single `Other` row, which is an ordinary `Acc`: count **and**
sum/min/max accumulate into it, so window totals stay exact for every
aggregate. Worst-case memory per rule is
`max_groups × group_by.len() × 256 B` (~51 MB for a 2-column rule at the
100 000 default).

### Aggregate semantics (SQL)

For a field named under `sum` / `min` / `max`:

- `Num(n)` contributes (non-finite values — NaN, ±inf — are skipped).
- `Str(s)` contributes iff `s.parse::<f64>()` succeeds. Zeek and Suricata JSON
  carry numeric strings in places; this avoids surprising all-null columns.
- `Bool` and a missing field contribute nothing.
- A record that contributes nothing is **still counted** in `count`. Never
  dropped, never an error.
- A group that never observed a numeric value for a column emits **NULL**, not
  `0.0` — `SUM` over zero rows is NULL in SQL, and emitting `0.0` would
  fabricate data. Aggregate columns are therefore **nullable**.

### `AggregateRow` and `AggregateSink`

```rust
struct AggregateRow {
    rule: Arc<str>,
    keys: Vec<Option<String>>,
    count: u64,
    aggs: Vec<Option<f64>>,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
}
```

Source-agnostic, so one writer serves every rule regardless of origin source.

`AggregateSink: ParquetSink<Record = AggregateRow>`:

- `partition()` → rule name.
- `schema()` → per-rule Arrow schema, precomputed at config load.
- Key layout: `<prefix>/<rule>/year=YYYY/month=MM/day=DD/<uuid>.parquet`.

Per-rule schema:

| Column | Type | Null |
|---|---|---|
| each `group_by` column | `Utf8` | yes |
| `count` | `UInt64` | no |
| `sum_<field>` / `min_<field>` / `max_<field>` | `Float64` | yes |
| `window_start`, `window_end` | `Timestamp(Millis, UTC)` | no |

`AggregateSink` is **not** `Default` (schemas come from config), so it is
constructed via `ParquetWriterHandle::start_with_stats` rather than the
`start_writer::<S>()` convenience wrapper.

### Decorators (`handlers.rs`)

Five handlers, each holding `Arc<Aggregator>` + `Arc<dyn XHandler>` inner:

- **Single-record** (zeek, suricata, syslog): `if agg.consume(..) { return }`
  else forward to inner.
- **Batch** (ipfix, sflow): partition the `Vec`, forward only the unmatched
  remainder, skipping the inner call entirely when the remainder is empty.

### Emission

One background task per `Aggregator`, ticking every `flush_interval_secs`. On
tick it drains the whole map under the mutex, stamps `window_start` /
`window_end` on every row, clears the map, and pushes each row via
`send_or_drop().await` to each configured `ParquetWriterHandle<AggregateSink>`
(s3 and/or local). A new `DropSite::Aggregate = 9` variant covers drop-log
throttling.

**There is deliberately no guarantee that one Parquet file equals one window.**
The writer exposes no forced-flush API, and adding one to a 3 700-line hot-path
writer to buy file-boundary cosmetics fails YAGNI. Files within a partition are
read as a set; the only load-bearing semantics are the explicit
`window_start` / `window_end` columns on every row. A single
`flush_interval_secs` drives both the emit tick and the writer's
`FlushPolicy.interval`, so files land window-aligned in practice without
anything depending on it.

On shutdown the emit task does a final drain before the writer's graceful
flush, so a partial window is not lost.

## Configuration

```toml
[aggregate]
enabled = true
flush_interval_secs = 300     # = window length
max_groups = 100000           # per rule, per window

[aggregate.s3]                # optional; S3ConnectionConfig flattened as elsewhere
prefix = "aggregate"

[aggregate.local]             # optional; both may be set
directory = "/data/agg"
prefix = "aggregate"

[[aggregate.rules]]
name = "dns_by_query"
source = "zeek"
stream = "dns"                # optional; omitted = every record from that source
group_by = ["query", "id.orig_h"]

[[aggregate.rules]]
name = "flow_talkers"
source = "ipfix"
group_by = ["src_addr", "dst_addr", "dst_port"]
sum = ["octet_delta_count", "packet_delta_count"]
```

`enabled = false` (the default) means the section is inert and nothing changes.

### Startup validation — fail hard

- Unknown `source`.
- A `source` that exists but has `enabled = false` in this deployment.
- Empty `group_by`.
- Duplicate rule `name`.
- Rules configured with neither `[aggregate.s3]` nor `[aggregate.local]`.

A typo'd rule would otherwise silently fail to suppress, or produce zero rows
forever.

## Error handling

- Missing or wrong-typed fields never error — they become nulls or skipped
  aggregate contributions (see above).
- Channel pressure on emit → `send_or_drop` bounded wait, then a throttled drop
  logged under `DropSite::Aggregate` with `parquet_s3_dropped`.
- Upload failures are the existing writer machinery's concern, unchanged.

## Metrics

- `aggregate_records_consumed{rule}` — counter
- `aggregate_rows_emitted{rule}` — counter
- `aggregate_groups{rule}` — gauge, sampled at emit
- `aggregate_overflow_records{rule}` — counter

## Deliberate simplifications (`ponytail:` comments in code)

1. **`f64` for all numeric aggregates** — exact to 2^53; a window's
   `sum(octet_delta_count)` needs 9 PB to lose precision. Upgrade path: an
   `Int(i64) | Float(f64)` accumulator enum.
2. **One global mutex** on the aggregation path — a hashmap lookup plus a
   counter bump is tens of nanoseconds. Upgrade path: shard by rule if profiles
   show contention.
3. **Windows are emit-interval-bounded, not event-time** — rows carry explicit
   window bounds, so a file holding two windows is unambiguous.
4. **256-byte group-value truncation** — two keys sharing a 256-byte prefix
   merge. Raise the constant if it ever matters.
5. **Literal `"_other"` rendering** — a real group whose every column is
   literally `"_other"` renders identically to the overflow row in the output.
   The two remain distinct internally (no aggregation corruption); this is an
   output-interpretation ambiguity only.

## Testing

Per the three-level requirement:

**Unit** (in-module):
- Group key construction: `Num`→`String` formatting (integral vs fractional),
  `Bool` stringification, 256-byte truncation on a char boundary.
- Per-source `AggFields::field` — literal key, dotted path, `extra` fallback,
  missing field.
- Cap → `Other` rollup preserving count **and** sum/min/max.
- SQL aggregate semantics: numeric-string parsing, non-finite skipping,
  zero-observation column → NULL, record still counted.
- Rule matching: source, optional stream, two rules matching one record.
- Window stamping.
- Every config-validation error.

**Integration** (`tests/aggregate_local_integration.rs`):
- `Aggregator` + real `PartitionedParquetWriter` + `LocalDiskSink`: read the
  Parquet back and assert group counts and aggregate values.
- Suppression: the raw handler sees nothing for a matched stream and everything
  for an unmatched one.
- Shutdown drain emits the partial window.

**End-to-end** (`tests/aggregate_e2e.rs`):
- Real Zeek TCP listener on an ephemeral port, feed NDJSON lines over a socket,
  local-disk output, assert the aggregated Parquet file's contents.

## Out of scope

- wef / hec / otlp sources.
- Event-time windowing, watermarks, late-arrival handling.
- Filter predicates on rules (`WHERE`); rules select by source + stream only.
- Any forced-flush API on `PartitionedParquetWriter`.
