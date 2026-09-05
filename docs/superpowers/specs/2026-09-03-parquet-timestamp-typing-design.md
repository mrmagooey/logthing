# Parquet timestamp typing — design

Date: 2026-09-03
Status: approved (scope decided by repo owner; design reviewed over three rounds)

## Problem

Every Parquet sink in this repo writes its timestamp columns as something
other than a timestamp. Zeek writes `ts` as `Float64` (epoch seconds).
Every other sink formats a `chrono::DateTime<Utc>` back into an RFC-3339
`Utf8` string. The one sink that does use a real Arrow timestamp,
`generic_s3.rs`, uses millisecond precision.

Parquet and Iceberg support native `day`/`month`/`year`/`hour` partition
transforms, but only on real date/timestamp columns. A `float64` or
`varchar` cannot be a transform source. Consumers loading this data into a
partitioned table must re-derive a timestamp column themselves, or work
around it at the storage-path level. It is also awkward for any SQL
consumer: epoch arithmetic and string comparison instead of real date
predicates.

`forwarding/aggregate` already does this correctly — `window_start` and
`window_end` are `Timestamp(Microsecond, UTC)`. This work brings every
other sink in line with it.

## Goal

**Every timestamp column in every Parquet sink is
`Timestamp(Microsecond, Some("UTC"))`.**

One rule, no exceptions. The rule is the specification: if a column holds a
point in time and is written to Parquet, it has this type.

## Non-goals

- No new config flags, no additive parallel columns, no schema versioning.
- No change to how RFC 3164 syslog resolves its missing year or timezone.
- No change to `aggregate/fields.rs`, `admin/mod.rs`, or `admin/state.rs`.
  Those `to_rfc3339()` calls are aggregation grouping keys and JSON API
  responses, not Parquet columns.

## Scope

### Already correct — do not touch

| File | Column | Current type |
|---|---|---|
| `forwarding/aggregate/mod.rs:478` | `window_start`, `window_end` | `Timestamp(Microsecond, UTC)` |

The originating feature request claimed these were millisecond. They are
not; verified at `aggregate/mod.rs:478` and `:550`. Nothing to do.

### Precision change: Millisecond → Microsecond

| File | Columns | Sites |
|---|---|---|
| `forwarding/generic_s3.rs` | `time`, `received_at` | schema `:29-38`; `TimestampMillisecondArray` + `.timestamp_millis()` at `:77`, `:84` |

### Type change: Float64 → Timestamp(Microsecond, UTC)

| File | Column | Sites |
|---|---|---|
| `zeek/schema.rs` | `ts` (7 schemas) | fields `:34`, `:59`, `:82`, `:105`, `:126`, `:144`, `:164`; `Float64Builder` sites incl. `ConnAccumulator.b_ts` (field `:245`, ctor `:267`, append `:374`, finish `:404`) and mappers `map_dns`, `map_http`, `map_ssl`, `map_files`, `map_notice`, `map_envelope` |

### Type change: Utf8 → Timestamp(Microsecond, UTC)

All of these already hold a `DateTime<Utc>` and merely format it with
`to_rfc3339()`. No parsing work is required anywhere.

| File | Columns | Sites |
|---|---|---|
| `zeek/schema.rs` | `ingest_time` | field `:171`; written `:1002` |
| `forwarding/syslog_s3.rs` | `timestamp` | field `:30`; written `:57-59` |
| `forwarding/structured_syslog_s3.rs` | `timestamp`, `received_at` | fields `:25`, `:28`; written `:49-51`, `:54-55` |
| `suricata/schema.rs` | `received_at` | field `:24`; written `:41` |
| `forwarding/sflow_s3.rs` | `received_at` (2 schemas) | fields `:20`, `:37`; written `:108`, `:175` |
| `forwarding/ipfix_s3.rs` | `export_time`, `flow_start`, `flow_end` | fields `:32`, `:40`, `:41`; builder struct `:73-74`, `:97-98`; written `:129`, `:147-151` |
| `forwarding/parquet_s3.rs` (WEF) | `timestamp` | field `:56`; written `:82` |

## Design

### The conversion

Two shapes, depending on what the source value already is.

**Already a `DateTime<Utc>`** (every sink except zeek `ts`) — replace
`to_rfc3339()` + `StringArray`/`StringBuilder` with `timestamp_micros()` +
`TimestampMicrosecondArray`/`TimestampMicrosecondBuilder`. Follow the
pattern already established at `aggregate/mod.rs:547-552`:

```rust
let tz: Arc<str> = Arc::from("UTC");
TimestampMicrosecondArray::from(vec![t.timestamp_micros()]).with_timezone(tz)
```

For the persistent-builder sinks (`ipfix_s3.rs`, `zeek` `ConnAccumulator`),
construct the builder with the timezone-carrying data type so
`RecordBatch::try_new` schema-matches:

```rust
TimestampMicrosecondBuilder::new()
    .with_data_type(DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())))
```

**A raw JSON f64** (zeek `ts` only) — add one helper beside the existing
`json_f64` in `zeek/schema.rs`:

```rust
/// Extract an epoch-seconds float and convert to microseconds.
/// Returns None if absent, not a number, or outside the representable
/// i64-microsecond range.
fn json_ts_micros(v: &serde_json::Value, key: &str) -> Option<i64> { ... }
```

One helper, used by all 7 mappers — not 7 inline copies.

### Precision is not lost

`f64` has a 53-bit mantissa. At current epoch seconds (~1.8 × 10⁹, needing
31 integer bits) about 22 fractional bits remain, giving a resolution of
roughly 0.21 µs. Rounding to whole microseconds therefore discards nothing
the source `f64` was capable of representing. This holds until well past
year 2200.

### Range guard and its failure semantics

JSON is a trust boundary. `1e300` is legal JSON, and a bare `as i64` cast
would saturate to `i64::MAX` — a nonsense timestamp silently presented as
real data. `json_ts_micros` therefore returns `None` for any value outside
the representable range. (`NaN`/`Infinity` cannot occur; they are not
legal JSON literals.)

A rejected value yields a NULL column. **The record is still written and
the offending raw value is still preserved**, by whichever mechanism the
schema already uses:

- **conn, dns, http, ssl, files, notice** — the existing idiom at
  `schema.rs:313`, `:479`, `:602`, `:723`, `:827`, `:912`:
  `if value.get("ts").is_some() && ts.is_none() { mismatches.push("ts"); }`
  `build_extra` (`:224-234`) then copies the raw value verbatim into the
  `_extra` column. These lines need no modification — a range-guard
  rejection produces the same `None` a type mismatch already does, and
  flows down the same path.
- **envelope** — `map_envelope` (`:993-1037`) has no `mismatches`
  mechanism. It unconditionally stores the whole raw record via
  `payload = value.to_string()` (`:1003`), which already preserves the
  offending value.

No new error path, no dropped records, no new code.

### RFC 3164 syslog — documented, not changed

`parse_rfc3164_timestamp` (`syslog/mod.rs:420-452`) already resolves the
missing year from `Utc::now()` (`:447`) and already assumes UTC (`:451`).
Because parsing happens inline at message receipt, `Utc::now()` is
effectively receipt time — which is what the feature request asked for.

Both assumptions get a doc comment naming them. Neither becomes
configurable: there is no sender-timezone handling anywhere in the repo,
and adding a config knob with no concrete requester is speculative surface.

One known limitation is recorded but not fixed: the year comes from
wall-clock time at parse time rather than the record's own `received_at`,
so a message parsed after a long buffering delay across a year boundary
could take the wrong year. Fixing it means changing a function signature
and its callers, which is unrelated to column typing.

### Breaking change

This changes column types in place. That is safe here:

- No schema-versioning, Iceberg schema evolution, or reader-compat
  mechanism exists in the repo. `iceberg_descriptor::schema_version()`
  only hashes the schema so a downstream catalog can notice drift.
- Parquet files are immutable and never appended to — each rotation writes
  a fresh file. Already-written files remain readable at their old types
  forever; only new files get the new type.
- `buffered_writer`'s column statistics derive generically from the written
  schema with no per-`DataType` matching, so they need no change.

The feature request offered an additive `ts_utc` column or a config flag as
a fallback "if breaking the existing field types is a concern." It is not a
concern here, and building dual-write infrastructure that nothing else in
the repo has would cost more than the fix.

## Testing

All three levels, per repo convention.

- **Unit** — in-module tests in each touched file: assert each schema field's
  `DataType` is `Timestamp(Microsecond, Some("UTC"))`, and assert the mapper
  writes the expected microsecond value. Existing assertions expecting
  `Float64Array`/`DataType::Utf8` are updated, not deleted:
  `zeek/schema.rs` (~20 sites), `syslog_s3.rs:328-337`,
  `structured_syslog_s3.rs:194,203`, `generic_s3.rs:263-285`,
  `ipfix_s3.rs:411-412`, `sflow_s3.rs:403,428`.
- **Unit, new** — `json_ts_micros` directly: a normal epoch value, a value
  with sub-second precision, an absent key, a non-numeric value, and an
  out-of-range value such as `1e300` (must return `None`, and the record
  must still be written with the raw value preserved in `_extra`).
- **Integration** — the existing Parquet round-trip tests read the column
  back and downcast to `TimestampMicrosecondArray`:
  `zeek_local_integration.rs`, `zeek_s3_integration.rs`,
  `syslog_s3_integration.rs`, `syslog_structured_s3_integration.rs`,
  `hec_s3_integration.rs`, `suricata_s3_integration.rs`,
  `sflow_s3_integration.rs`, `ipfix_s3_integration.rs`,
  `wef_s3_integration.rs`.
- **End-to-end** — extend an existing `*_e2e.rs` to drive a record through
  the listener and assert the on-disk Parquet file's column type, so the
  guarantee is verified through the outermost interface rather than only at
  the mapper.

## Documentation

| File | Lines | What changes |
|---|---|---|
| `README.md` | 287-301 | zeek promoted-column tables |
| `README.md` | 341, 349-350 | `export_time`, `flow_start`, `flow_end` listed as "String (RFC 3339)" |
| `ZEEK_IMPLEMENTATION.md` | 107, 128, 165 | `ts` documented as Float64 |
| `ZEEK_IMPLEMENTATION.md` | 172, 175 | `ingest_time` documented as Utf8 / "RFC 3339" |
| `IPFIX_IMPLEMENTATION.md` | 133, 141-142 | `export_time`, `flow_start`, `flow_end` as Utf8 |
| `IPFIX_IMPLEMENTATION.md` | 148 | "timestamps are stored as UTF-8 strings. Timestamps use RFC 3339 format." |

## Work breakdown

Three workstreams with disjoint file sets, safe to run in parallel:

- **A — zeek**: `zeek/schema.rs`, zeek tests, `README.md` zeek section,
  `ZEEK_IMPLEMENTATION.md`. The only stream needing the `json_ts_micros`
  helper, and the widest (7 schemas × 7 builder sites).
- **B — syslog + generic**: `forwarding/syslog_s3.rs`,
  `forwarding/structured_syslog_s3.rs`, `forwarding/generic_s3.rs`,
  `syslog/mod.rs` (doc comment only), and their tests.
- **C — remaining sinks**: `suricata/schema.rs`, `forwarding/sflow_s3.rs`,
  `forwarding/ipfix_s3.rs`, `forwarding/parquet_s3.rs`,
  `IPFIX_IMPLEMENTATION.md`, `README.md` ipfix section, and their tests.

`README.md` is touched by A and C in different sections — sequence those
two edits or resolve at merge.

## Decision record

Choices made during design, with the reasoning, so they are not relitigated:

| Decision | Chosen | Why |
|---|---|---|
| Breaking vs. additive vs. flag | In-place type change | No versioning/dual-write infra exists; old files stay readable regardless |
| f64 → µs conversion | One shared helper, rounded | Lossless at f64's ~0.21 µs resolution; one helper beats 7 inline copies |
| Out-of-range `ts` | NULL column, record kept, raw value preserved | Reuses the existing `mismatches`/`payload` paths; zero new code |
| RFC 3164 year source | Keep `Utc::now()`, document it | Parsing is inline at receipt, so it already equals receipt time |
| RFC 3164 timezone | Keep hardcoded UTC, document it | No sender-tz handling exists; a flag with no requester is speculative |
| Aggregate precision | No-op | Verified already microsecond; the request's third bullet was mistaken |
| Scope | Every timestamp column in every Parquet sink | Decided by the repo owner. One rule with no exceptions; any narrower line required defending why one identically-broken sink was in and another out |
