# Parquet Timestamp Typing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every timestamp column in every Parquet sink is written as `Timestamp(Microsecond, Some("UTC"))` instead of `Float64` epoch seconds, an RFC-3339 `Utf8` string, or millisecond precision.

**Architecture:** Almost every affected column already holds a `chrono::DateTime<Utc>` and merely formats it with `to_rfc3339()` on the way out — those are a mechanical swap of `StringArray`/`StringBuilder` for `TimestampMicrosecondArray`/`TimestampMicrosecondBuilder`. The single exception is Zeek's `ts`, which arrives as a raw JSON `f64` of epoch seconds and needs one new conversion helper with a range guard. No parsing logic is added anywhere, and no new error paths: a rejected Zeek `ts` reuses the mismatch-preservation machinery that already exists.

**Tech Stack:** Rust, `arrow` / `arrow-array` / `arrow-schema`, `parquet`, `chrono`, `serde_json`. Tests are `cargo test` (in-module `#[cfg(test)]` unit tests plus integration tests under `tests/`).

**Spec:** `docs/superpowers/specs/2026-09-03-parquet-timestamp-typing-design.md`

## Global Constraints

- The target type is exactly `DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))` for every column this plan touches. Not `None` for the timezone — the `Some("UTC")` is what makes it a `timestamptz` downstream.
- Column **nullability must not change**. A nullable `Utf8` becomes a nullable timestamp; a non-null `Utf8` becomes a non-null timestamp. Check each field's existing `is_nullable()` and preserve it.
- Column **order and count must not change**. These schemas are positional — `RecordBatch::try_new` pairs the column vector with the field list by index.
- Work happens on branch `feat/timestamp-typing`. Never commit to `master`.
- Do not add config flags, feature gates, or parallel "additive" columns. The type change is in place.
- Do not touch `src/forwarding/aggregate/` — `window_start`/`window_end` are already `Timestamp(Microsecond, UTC)` and are the reference pattern, not a target.
- Do not touch `to_rfc3339()` calls in `src/forwarding/aggregate/fields.rs`, `src/admin/mod.rs`, or `src/admin/state.rs`. Those are aggregation grouping keys and JSON API responses, not Parquet columns.
- Build with `cargo build --all-features`; some sinks are behind feature flags.

## Reference Patterns

Copy these; do not invent variants.

**Building a single-row timestamp column** (from `src/forwarding/aggregate/mod.rs:547-552`):

```rust
use arrow::array::TimestampMicrosecondArray;

let tz: Arc<str> = Arc::from("UTC");
let timestamp = Arc::new(
    TimestampMicrosecondArray::from(vec![dt.timestamp_micros()]).with_timezone(tz),
) as ArrayRef;
```

For a nullable column whose source is an `Option<DateTime<Utc>>`:

```rust
let tz: Arc<str> = Arc::from("UTC");
let timestamp = Arc::new(
    TimestampMicrosecondArray::from(vec![opt_dt.map(|t| t.timestamp_micros())])
        .with_timezone(tz),
) as ArrayRef;
```

**A persistent builder field** (for accumulator structs that reuse builders across rows):

```rust
use arrow::array::TimestampMicrosecondBuilder;
use arrow::datatypes::{DataType, TimeUnit};

TimestampMicrosecondBuilder::new()
    .with_data_type(DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())))
```

The `.with_data_type(...)` call is **required**. Without it the builder finishes an array with no timezone, and `RecordBatch::try_new` fails at runtime with a schema mismatch against a `Some("UTC")` field. Append with `.append_value(dt.timestamp_micros())` or `.append_option(opt_micros)`.

**A schema field:**

```rust
Field::new(
    "received_at",
    DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
    false, // preserve the existing nullability
)
```

**Asserting a field's type in a unit test** (matches the existing house style):

```rust
assert_eq!(
    schema.field_with_name("timestamp").unwrap().data_type(),
    &DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
);
assert!(schema.field_with_name("timestamp").unwrap().is_nullable());
```

**Reading a timestamp column back in an integration test** (from `aggregate/mod.rs:1330-1342`):

```rust
use arrow::array::TimestampMicrosecondArray;

let col = batch
    .column_by_name("timestamp")
    .unwrap()
    .as_any()
    .downcast_ref::<TimestampMicrosecondArray>()
    .expect("timestamp column should be TimestampMicrosecondArray");
assert_eq!(col.value(0), 1_700_000_000_000_000);
```

## File Structure

No new files. Every change modifies an existing schema declaration, its row-builder, and its tests, in place.

| File | Responsibility | Workstream |
|---|---|---|
| `src/zeek/schema.rs` | 7 Zeek schemas + row mappers + `json_ts_micros` helper | A |
| `README.md` (lines 287-301) | Zeek promoted-column tables | A |
| `ZEEK_IMPLEMENTATION.md` (107, 128, 165, 172, 175) | Zeek column type tables | A |
| `src/forwarding/syslog_s3.rs` | Syslog sink schema + mapper | B |
| `src/forwarding/structured_syslog_s3.rs` | Structured-syslog sink schema + mapper | B |
| `src/forwarding/generic_s3.rs` | HEC/generic sink, ms → µs | B |
| `src/syslog/mod.rs` (420-452) | RFC 3164 doc comment only — no logic change | B |
| `src/suricata/schema.rs` | Suricata envelope schema + mapper | C |
| `src/forwarding/sflow_s3.rs` | 2 sFlow schemas + 2 mappers | C |
| `src/forwarding/ipfix_s3.rs` | IPFIX schema + persistent builder struct | C |
| `src/forwarding/parquet_s3.rs` | WEF sink schema + mapper | C |
| `IPFIX_IMPLEMENTATION.md` (133, 141-142, 148) | IPFIX column type table | C |
| `README.md` (lines 341, 349-350) | IPFIX column table | C |

**Parallelism:** A, B, and C touch disjoint Rust files and can run concurrently. **`README.md` is the one shared file** — workstream A edits lines 287-301 (Zeek) and workstream C edits lines 341-350 (IPFIX). Different sections, but the same file: if running A and C in parallel worktrees, expect to resolve `README.md` at merge, or land A's README edit first.

---

## Workstream A — Zeek

### Task A1: Add the `json_ts_micros` conversion helper

**Files:**
- Modify: `src/zeek/schema.rs` (add beside `json_f64` at line 188-190; tests in the `#[cfg(test)]` module)

**Interfaces:**
- Consumes: nothing.
- Produces: `fn json_ts_micros(v: &serde_json::Value, key: &str) -> Option<i64>` — private to the module, used by all 7 mappers in Task A2 and A3.

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block in `src/zeek/schema.rs`:

```rust
#[test]
fn json_ts_micros_converts_epoch_seconds() {
    let v = serde_json::json!({ "ts": 1700000000.0 });
    assert_eq!(json_ts_micros(&v, "ts"), Some(1_700_000_000_000_000));
}

#[test]
fn json_ts_micros_preserves_sub_second_precision() {
    let v = serde_json::json!({ "ts": 1717171717.123456 });
    // f64 resolves to ~0.21us at this magnitude, so rounding to whole
    // microseconds is lossless relative to what the source can represent.
    assert_eq!(json_ts_micros(&v, "ts"), Some(1_717_171_717_123_456));
}

#[test]
fn json_ts_micros_returns_none_for_absent_key() {
    let v = serde_json::json!({ "uid": "C1" });
    assert_eq!(json_ts_micros(&v, "ts"), None);
}

#[test]
fn json_ts_micros_returns_none_for_non_numeric() {
    let v = serde_json::json!({ "ts": "not a number" });
    assert_eq!(json_ts_micros(&v, "ts"), None);
}

#[test]
fn json_ts_micros_rejects_out_of_range() {
    // 1e300 is legal JSON. A bare `as i64` cast would saturate to
    // i64::MAX and present a nonsense timestamp as real data.
    let v = serde_json::json!({ "ts": 1e300 });
    assert_eq!(json_ts_micros(&v, "ts"), None);

    let v = serde_json::json!({ "ts": -1e300 });
    assert_eq!(json_ts_micros(&v, "ts"), None);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --all-features --lib zeek::schema::tests::json_ts_micros`
Expected: FAIL — `cannot find function json_ts_micros in this scope`.

- [ ] **Step 3: Write the helper**

Insert immediately after `json_f64` (currently at `src/zeek/schema.rs:188-190`):

```rust
/// Extract an epoch-seconds float and convert it to microseconds.
///
/// Returns `None` if the key is absent, is not a number, or is outside the
/// range representable as `i64` microseconds. JSON is a trust boundary: a
/// legal-but-absurd value like `1e300` would saturate a bare `as i64` cast
/// to `i64::MAX`, presenting a nonsense timestamp as real data. Callers
/// treat `None` exactly as they already treat a type mismatch.
fn json_ts_micros(v: &serde_json::Value, key: &str) -> Option<i64> {
    let secs = v.get(key).and_then(|f| f.as_f64())?;
    let micros = (secs * 1e6).round();
    // NaN/Infinity cannot arrive from JSON, but the range check below also
    // rejects them, so the guard holds regardless of the source.
    if micros >= (i64::MIN as f64) && micros <= (i64::MAX as f64) {
        Some(micros as i64)
    } else {
        None
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --all-features --lib zeek::schema::tests::json_ts_micros`
Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git add src/zeek/schema.rs
git commit -m "feat(zeek): add json_ts_micros epoch-seconds to microseconds helper"
```

---

### Task A2: Retype `ts` in the six curated Zeek schemas

Covers `conn`, `dns`, `http`, `ssl`, `files`, `notice`. The envelope schema is Task A3 because it has a different value-preservation mechanism and a second column to change.

**Files:**
- Modify: `src/zeek/schema.rs` — schema fields at lines 34, 59, 82, 105, 126, 144; `ConnAccumulator` (`b_ts` field ~245, constructor ~267, append ~374, finish ~404); mappers `map_dns`, `map_http`, `map_ssl`, `map_files`, `map_notice`
- Test: `src/zeek/schema.rs` `#[cfg(test)] mod tests` (existing assertions at 1113, 1222, 1265 and the per-stream mapper tests)

**Interfaces:**
- Consumes: `json_ts_micros` from Task A1.
- Produces: `conn_schema()`, `dns_schema()`, `http_schema()`, `ssl_schema()`, `files_schema()`, `notice_schema()` — signatures unchanged, `ts` field type changed.

- [ ] **Step 1: Update the failing schema-type tests**

The existing test `conn_schema_has_correct_fields` (around line 1170) asserts:

```rust
let f = s.field_with_name("ts").unwrap();
assert_eq!(*f.data_type(), DataType::Float64);
assert!(f.is_nullable());
```

Change to (and make the equivalent change in every per-stream schema test):

```rust
let f = s.field_with_name("ts").unwrap();
assert_eq!(
    *f.data_type(),
    DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
);
assert!(f.is_nullable());
```

Add `TimeUnit` to the test module's `use arrow::datatypes::...` import.

Also add one value-level test asserting the conversion reaches the batch:

```rust
#[test]
fn conn_ts_is_written_as_microseconds() {
    use arrow::array::TimestampMicrosecondArray;
    let v = serde_json::json!({ "ts": 1700000000.0, "uid": "C1" });
    let batch = map_conn(&v).unwrap();
    let col = batch
        .column_by_name("ts")
        .unwrap()
        .as_any()
        .downcast_ref::<TimestampMicrosecondArray>()
        .expect("ts column should be TimestampMicrosecondArray");
    assert_eq!(col.value(0), 1_700_000_000_000_000);
}

#[test]
fn conn_out_of_range_ts_is_null_and_preserved_in_extra() {
    use arrow::array::{Array, StringArray, TimestampMicrosecondArray};
    let v = serde_json::json!({ "ts": 1e300, "uid": "C1" });
    let batch = map_conn(&v).unwrap();
    // The record is still written...
    assert_eq!(batch.num_rows(), 1);
    // ...the ts column is null...
    let col = batch
        .column_by_name("ts")
        .unwrap()
        .as_any()
        .downcast_ref::<TimestampMicrosecondArray>()
        .unwrap();
    assert!(col.is_null(0));
    // ...and the raw value survives in _extra via the existing
    // mismatches/build_extra path.
    let extra = batch
        .column_by_name("_extra")
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert!(extra.value(0).contains("1e300") || extra.value(0).contains("ts"));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --all-features --lib zeek::schema`
Expected: FAIL — assertion mismatch (`Float64` vs `Timestamp`) and downcast panics.

- [ ] **Step 3: Change the schema fields**

At lines 34, 59, 82, 105, 126, 144 replace:

```rust
Field::new("ts", DataType::Float64, true),
```

with:

```rust
Field::new(
    "ts",
    DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
    true,
),
```

Add `TimeUnit` to the top-level import at line 7:

```rust
use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
```

- [ ] **Step 4: Change `ConnAccumulator`'s builder**

Field declaration (~line 245): `b_ts: Float64Builder,` → `b_ts: TimestampMicrosecondBuilder,`

Constructor (~line 267): `b_ts: Float64Builder::new(),` →

```rust
b_ts: TimestampMicrosecondBuilder::new()
    .with_data_type(DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))),
```

In `append_conn_value`, change the extraction (~line 311) from `let ts = json_f64(value, "ts");` to `let ts = json_ts_micros(value, "ts");`. **Leave the two following lines alone** — the existing

```rust
if value.get("ts").is_some() && ts.is_none() {
    mismatches.push("ts");
}
```

already does the right thing: a range-guard rejection produces the same `None` a type mismatch does, so `build_extra` preserves the raw value in `_extra` with no new code. The `self.b_ts.append_option(ts)` call at ~line 374 needs no change either — it now appends `Option<i64>` micros.

Update the import at line 4 to swap `Float64Builder` for `TimestampMicrosecondBuilder`, keeping `Float64Builder` if any non-`ts` column still uses it (`duration` in conn does — verify before removing).

- [ ] **Step 5: Change the five remaining mappers**

In `map_dns`, `map_http`, `map_ssl`, `map_files`, `map_notice`: swap `json_f64(value, "ts")` for `json_ts_micros(value, "ts")` (the extraction sites near lines 477, 600, 721, 827, 912), and swap that mapper's local `Float64Builder::new()` for the `ts` column to the `TimestampMicrosecondBuilder` form shown in Step 4. Leave every `mismatches.push("ts")` block untouched.

- [ ] **Step 6: Run the full module test suite**

Run: `cargo test --all-features --lib zeek::schema`
Expected: PASS. If a `RecordBatch::try_new` schema-mismatch error appears at runtime, the `.with_data_type(...)` call was omitted from a builder — see Reference Patterns.

- [ ] **Step 7: Commit**

```bash
git add src/zeek/schema.rs
git commit -m "feat(zeek): write ts as Timestamp(Microsecond, UTC) in curated schemas"
```

---

### Task A3: Retype the envelope schema's `ts` and `ingest_time`

**Files:**
- Modify: `src/zeek/schema.rs` — `envelope_schema()` fields at 164 (`ts`) and 171 (`ingest_time`); `map_envelope` at 993-1037
- Test: `src/zeek/schema.rs` `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `json_ts_micros` from Task A1.
- Produces: `envelope_schema()` — signature unchanged, two field types changed.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn envelope_schema_ts_and_ingest_time_are_microsecond_timestamps() {
    let s = envelope_schema();
    let expected = DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()));

    let f = s.field_with_name("ts").unwrap();
    assert_eq!(*f.data_type(), expected);
    assert!(f.is_nullable());

    let f = s.field_with_name("ingest_time").unwrap();
    assert_eq!(*f.data_type(), expected);
    assert!(!f.is_nullable()); // ingest_time is server-generated, never null
}

#[test]
fn envelope_out_of_range_ts_is_null_and_preserved_in_payload() {
    use arrow::array::{Array, StringArray, TimestampMicrosecondArray};
    let v = serde_json::json!({ "ts": 1e300, "uid": "C1" });
    let batch = map_envelope(&v, "weird").unwrap();
    assert_eq!(batch.num_rows(), 1);

    let ts = batch
        .column_by_name("ts")
        .unwrap()
        .as_any()
        .downcast_ref::<TimestampMicrosecondArray>()
        .unwrap();
    assert!(ts.is_null(0));

    // map_envelope has no `mismatches` mechanism; it stores the entire raw
    // record in `payload` unconditionally, which preserves the value.
    let payload = batch
        .column_by_name("payload")
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert!(payload.value(0).contains("1e300"));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --all-features --lib zeek::schema::tests::envelope`
Expected: FAIL — `Float64`/`Utf8` vs `Timestamp` assertion mismatch.

- [ ] **Step 3: Change the two schema fields**

Line 164: `Field::new("ts", DataType::Float64, true),` → the `Timestamp(Microsecond, Some("UTC"))` form, still nullable.

Line 171: `Field::new("ingest_time", DataType::Utf8, false),` → the same type, still **non-nullable**.

- [ ] **Step 4: Change `map_envelope`**

Line 996: `let ts = json_f64(value, "ts");` → `let ts = json_ts_micros(value, "ts");`

Line 1002: `let ingest_time = chrono::Utc::now().to_rfc3339();` → `let ingest_time = chrono::Utc::now().timestamp_micros();`

Line 1006 and 1012: swap the two local builders:

```rust
let ts_type = DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()));
let mut b_ts = TimestampMicrosecondBuilder::new().with_data_type(ts_type.clone());
let mut b_ingest_time = TimestampMicrosecondBuilder::new().with_data_type(ts_type);
```

Line 1022: `b_ingest_time.append_value(&ingest_time);` → `b_ingest_time.append_value(ingest_time);` (an `i64` by value, no longer a `&str`).

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --all-features --lib zeek::schema`
Expected: PASS, whole module.

- [ ] **Step 6: Commit**

```bash
git add src/zeek/schema.rs
git commit -m "feat(zeek): write envelope ts and ingest_time as Timestamp(Microsecond, UTC)"
```

---

### Task A4: Update Zeek integration and e2e tests

**Files:**
- Modify: `tests/zeek_local_integration.rs` (fixtures at 20, 40; column check at 114)
- Modify: `tests/zeek_s3_integration.rs` (fixtures at 46, 66; column list at 176)
- Modify: `src/forwarding/zeek_s3.rs` in-module tests (fixtures at 341, 361, 380, 605, 658, 708)
- Modify: `benches/zeek_conn_batch_amortization.rs:28` only if it fails to compile
- Modify (e2e): `tests/zeek_flush_decoupling_e2e.rs`

**Interfaces:**
- Consumes: the retyped schemas from Tasks A2 and A3.
- Produces: nothing.

- [ ] **Step 1: Run the integration suite to see what breaks**

Run: `cargo test --all-features --test zeek_local_integration --test zeek_s3_integration`
Expected: FAIL on any test that downcasts `ts` to `Float64Array` or asserts on its value.

The JSON fixtures (`"ts": 1700000000.0`) **do not need to change** — the input is still a JSON float; only the output column type changed.

- [ ] **Step 2: Update the read-back assertions**

Anywhere a test downcasts the `ts` column, switch to the pattern in Reference Patterns and multiply the expected value by 1e6:

```rust
use arrow::array::TimestampMicrosecondArray;

let col = batch
    .column_by_name("ts")
    .unwrap()
    .as_any()
    .downcast_ref::<TimestampMicrosecondArray>()
    .expect("ts should be TimestampMicrosecondArray");
assert_eq!(col.value(0), 1_700_000_000_000_000);
```

- [ ] **Step 3: Add the end-to-end assertion**

In `tests/zeek_flush_decoupling_e2e.rs`, after the test's existing flow writes a Parquet file to disk, add an assertion that reads the file back through the Parquet reader and checks the **on-disk** column type — this is the guarantee the feature request actually cares about, and it must be verified through the outermost interface rather than only at the mapper:

```rust
let field = batch.schema().field_with_name("ts").unwrap().clone();
assert_eq!(
    *field.data_type(),
    arrow::datatypes::DataType::Timestamp(
        arrow::datatypes::TimeUnit::Microsecond,
        Some("UTC".into())
    ),
    "on-disk Parquet ts column must be a microsecond UTC timestamp so that \
     Iceberg day/month/year partition transforms can use it"
);
```

Follow whatever Parquet-reading helper that test file already uses to obtain `batch`; do not introduce a new reader dependency.

- [ ] **Step 4: Run the full Zeek test surface**

Run: `cargo test --all-features zeek`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/ src/forwarding/zeek_s3.rs benches/
git commit -m "test(zeek): assert ts is a microsecond UTC timestamp end to end"
```

---

### Task A5: Update Zeek documentation

**Files:**
- Modify: `README.md:287-301`
- Modify: `ZEEK_IMPLEMENTATION.md:107, 128, 165, 172, 175`

**Interfaces:** none.

- [ ] **Step 1: Update `ZEEK_IMPLEMENTATION.md`**

Lines 107, 128, 165 read `| ts | Float64 | yes | ts |` (or the 3-column variant). Change the type cell to `Timestamp(µs, UTC)`.

Line 172 reads `| ingest_time | Utf8 | **no** |`. Change the type cell to `Timestamp(µs, UTC)`.

Line 175 reads: "The full JSON object is stored verbatim in `payload`. `log_path` holds the actual (sanitised) path; `ingest_time` is RFC 3339." Change the trailing clause to: "`ingest_time` is a microsecond-precision UTC timestamp."

- [ ] **Step 2: Update `README.md`**

The tables at 287-301 list promoted column names without types, so they need no type edit. Add one sentence after the table noting that `ts` is written as a microsecond-precision UTC timestamp, suitable as an Iceberg partition-transform source.

- [ ] **Step 3: Verify no stale references remain**

Run: `grep -n 'Float64' ZEEK_IMPLEMENTATION.md; grep -rn 'ingest_time.*RFC' ZEEK_IMPLEMENTATION.md README.md`
Expected: no hits mentioning `ts` or `ingest_time`. Other columns (`duration`, `orig_bytes`) legitimately remain `Float64`/`UInt64` — do not change those.

- [ ] **Step 4: Commit**

```bash
git add README.md ZEEK_IMPLEMENTATION.md
git commit -m "docs(zeek): document ts and ingest_time as microsecond UTC timestamps"
```

---

## Workstream B — Syslog and generic sinks

### Task B1: Retype `timestamp` in the syslog sink

**Files:**
- Modify: `src/forwarding/syslog_s3.rs` — schema field at 30, mapper at 57-59, import at 16
- Test: `src/forwarding/syslog_s3.rs` in-module tests at 328-337

**Interfaces:**
- Consumes: `SyslogMessage.timestamp`, already `Option<DateTime<Utc>>` (`src/syslog/mod.rs:59`). No parsing is added.
- Produces: `syslog_schema()` — signature unchanged, `timestamp` field type changed.

- [ ] **Step 1: Update the failing test**

The existing assertion at 328-337 reads:

```rust
assert_eq!(
    schema.field_with_name("timestamp").unwrap().data_type(),
    &DataType::Utf8
);
assert!(schema.field_with_name("timestamp").unwrap().is_nullable());
```

Change the expected type to `&DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))`, keeping the nullability assertion. Add a value-level test:

```rust
#[test]
fn timestamp_is_written_as_microseconds() {
    use arrow::array::TimestampMicrosecondArray;
    use chrono::TimeZone;
    let mut msg = sample_message();
    msg.timestamp = Some(chrono::Utc.timestamp_opt(1_700_000_000, 0).unwrap());
    let batch = syslog_message_to_batch(&msg).unwrap();
    let col = batch
        .column_by_name("timestamp")
        .unwrap()
        .as_any()
        .downcast_ref::<TimestampMicrosecondArray>()
        .expect("timestamp should be TimestampMicrosecondArray");
    assert_eq!(col.value(0), 1_700_000_000_000_000);
}

#[test]
fn absent_timestamp_is_null() {
    use arrow::array::{Array, TimestampMicrosecondArray};
    let mut msg = sample_message();
    msg.timestamp = None;
    let batch = syslog_message_to_batch(&msg).unwrap();
    let col = batch
        .column_by_name("timestamp")
        .unwrap()
        .as_any()
        .downcast_ref::<TimestampMicrosecondArray>()
        .unwrap();
    assert!(col.is_null(0));
}
```

Use whatever fixture constructor the test module already provides in place of `sample_message()` if it is named differently.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --all-features --lib forwarding::syslog_s3`
Expected: FAIL — `Utf8` vs `Timestamp`.

- [ ] **Step 3: Change the schema field**

Line 30: `Field::new("timestamp", DataType::Utf8, true),` → the `Timestamp(Microsecond, Some("UTC"))` form, still nullable. Add `TimeUnit` to the `arrow::datatypes` import at line 17.

- [ ] **Step 4: Change the mapper**

Lines 57-59:

```rust
let timestamp = Arc::new(StringArray::from(vec![
    msg.timestamp.as_ref().map(|t| t.to_rfc3339()),
])) as ArrayRef;
```

becomes:

```rust
let tz: Arc<str> = Arc::from("UTC");
let timestamp = Arc::new(
    TimestampMicrosecondArray::from(vec![msg.timestamp.map(|t| t.timestamp_micros())])
        .with_timezone(tz),
) as ArrayRef;
```

Add `TimestampMicrosecondArray` to the `arrow::array` import at line 16.

- [ ] **Step 5: Run to verify pass**

Run: `cargo test --all-features --lib forwarding::syslog_s3`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/forwarding/syslog_s3.rs
git commit -m "feat(syslog): write timestamp as Timestamp(Microsecond, UTC)"
```

---

### Task B2: Retype `timestamp` and `received_at` in the structured-syslog sink

**Files:**
- Modify: `src/forwarding/structured_syslog_s3.rs` — schema fields at 25 and 28, mapper at 49-51 and 54-55, imports at 11-13
- Test: `src/forwarding/structured_syslog_s3.rs` in-module tests at 194, 203

**Interfaces:**
- Consumes: `StructuredSyslogRecord.timestamp` (`Option<DateTime<Utc>>`) and `.received_at` (`DateTime<Utc>`).
- Produces: `structured_syslog_schema()` — signature unchanged, two field types changed.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn schema_timestamp_and_received_at_are_microsecond_timestamps() {
    use arrow::datatypes::{DataType, TimeUnit};
    let schema = structured_syslog_schema();
    let expected = DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()));

    let f = schema.field_with_name("timestamp").unwrap();
    assert_eq!(f.data_type(), &expected);
    assert!(f.is_nullable());

    let f = schema.field_with_name("received_at").unwrap();
    assert_eq!(f.data_type(), &expected);
    assert!(!f.is_nullable()); // received_at is always set
}
```

Update the existing assertions at 194 and 203 if they cover these two columns; leave assertions for `payload_type`/`parsed` (genuinely `Utf8`) alone.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --all-features --lib forwarding::structured_syslog_s3`
Expected: FAIL.

- [ ] **Step 3: Change the schema fields**

Line 25 (`timestamp`, nullable) and line 28 (`received_at`, **non-nullable**) both become the `Timestamp(Microsecond, Some("UTC"))` form. Preserve each one's existing nullability flag.

- [ ] **Step 4: Change the mapper**

Lines 49-51 (`timestamp`) take the nullable form from Reference Patterns. Lines 54-55 (`received_at`) take the non-null form:

```rust
let tz: Arc<str> = Arc::from("UTC");
let received_at = Arc::new(
    TimestampMicrosecondArray::from(vec![rec.received_at.timestamp_micros()])
        .with_timezone(tz.clone()),
) as ArrayRef;
```

Update the `arrow::array` import at line 11 and the `arrow::datatypes` import at line 12.

- [ ] **Step 5: Run to verify pass**

Run: `cargo test --all-features --lib forwarding::structured_syslog_s3`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/forwarding/structured_syslog_s3.rs
git commit -m "feat(syslog): write structured timestamp and received_at as Timestamp(Microsecond, UTC)"
```

---

### Task B3: Move the generic/HEC sink from millisecond to microsecond

**Files:**
- Modify: `src/forwarding/generic_s3.rs` — schema fields at 29-38, mapper at 73-85, import at 13, comments at 73-75 and 82
- Test: `src/forwarding/generic_s3.rs` in-module tests at 263-285

**Interfaces:**
- Consumes: `GenericRecord.time` (`Option<DateTime<Utc>>`) and `.received_at` (`DateTime<Utc>`).
- Produces: `generic_schema()` — signature unchanged, two field precisions changed.

This is the sink the feature request's third bullet was actually describing. It named `aggregate` by mistake; `aggregate` is already microsecond and must not be touched.

- [ ] **Step 1: Update the failing tests**

The tests at 263-285 downcast to `TimestampMillisecondArray`. Change to `TimestampMicrosecondArray` and multiply every expected value by 1000. Add a schema-level assertion:

```rust
#[test]
fn schema_time_and_received_at_are_microsecond_timestamps() {
    use arrow::datatypes::{DataType, TimeUnit};
    let schema = generic_schema();
    let expected = DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()));
    assert_eq!(schema.field_with_name("time").unwrap().data_type(), &expected);
    assert!(schema.field_with_name("time").unwrap().is_nullable());
    assert_eq!(
        schema.field_with_name("received_at").unwrap().data_type(),
        &expected
    );
    assert!(!schema.field_with_name("received_at").unwrap().is_nullable());
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --all-features --lib forwarding::generic_s3`
Expected: FAIL — millisecond vs microsecond.

- [ ] **Step 3: Change the schema and mapper**

Lines 31 and 36: `TimeUnit::Millisecond` → `TimeUnit::Microsecond`.

Lines 77 and 84: `TimestampMillisecondArray` → `TimestampMicrosecondArray`, and `.timestamp_millis()` → `.timestamp_micros()`.

Line 13: update the `arrow_array` import.

Lines 73-75 and 82 carry comments naming `Millisecond` — update them to match.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --all-features --lib forwarding::generic_s3 && cargo test --all-features --test hec_s3_integration --test hec_local_integration --test hec_e2e`
Expected: PASS. Update any millisecond assertion the integration and e2e tests carry.

- [ ] **Step 5: Commit**

```bash
git add src/forwarding/generic_s3.rs tests/
git commit -m "feat(hec): align generic sink timestamps to microsecond precision"
```

---

### Task B4: Document the RFC 3164 timestamp assumptions

**Files:**
- Modify: `src/syslog/mod.rs:420-452` — doc comment only, **no logic change**

**Interfaces:** none.

The feature request asked for RFC 3164's missing year and timezone to be "documented or made configurable." Both behaviours already exist and are correct; only the documentation is missing. Do not add a config option.

- [ ] **Step 1: Replace the doc comment**

The current comment at line 419 reads `/// Parse RFC 3164 timestamp (assumes current year)`. Replace with:

```rust
/// Parse an RFC 3164 (BSD syslog) timestamp such as `"Oct 11 22:14:15"`.
///
/// The wire format carries neither a year nor a timezone, so both are
/// inferred:
///
/// - **Year** — taken from `Utc::now()` at parse time. Parsing happens
///   inline as the message is received, so this is effectively receipt
///   time. Known limitation: a message parsed after a long buffering
///   delay that straddles a year boundary can take the wrong year. Fixing
///   that means threading the record's own `received_at` through this
///   function and its callers.
/// - **Timezone** — assumed UTC. There is no sender-timezone handling
///   anywhere in this codebase; a sender in another zone will have its
///   timestamps offset accordingly.
///
/// RFC 5424 messages are unaffected: they carry a full date and explicit
/// offset and are parsed unambiguously by `parse_rfc5424`.
```

- [ ] **Step 2: Verify nothing else changed**

Run: `git diff --stat src/syslog/mod.rs`
Expected: one file changed, comment lines only. Confirm with `git diff src/syslog/mod.rs` that no executable line moved.

- [ ] **Step 3: Run the syslog suite**

Run: `cargo test --all-features syslog`
Expected: PASS, unchanged from before.

- [ ] **Step 4: Commit**

```bash
git add src/syslog/mod.rs
git commit -m "docs(syslog): document RFC 3164 year and timezone assumptions"
```

---

### Task B5: Update syslog integration and e2e tests

**Files:**
- Modify: `tests/syslog_s3_integration.rs`, `tests/syslog_structured_s3_integration.rs`, `tests/syslog_local_integration.rs`
- Modify (e2e): `tests/syslog_payload_e2e.rs`

**Interfaces:**
- Consumes: the retyped schemas from Tasks B1 and B2.

- [ ] **Step 1: Run the suite to see what breaks**

Run: `cargo test --all-features syslog`
Expected: FAIL wherever a test downcasts `timestamp` or `received_at` to `StringArray` or compares against an RFC-3339 string.

- [ ] **Step 2: Update read-back assertions**

Use the `TimestampMicrosecondArray` pattern from Reference Patterns; compare against microsecond integers rather than RFC-3339 strings.

- [ ] **Step 3: Add the end-to-end assertion**

In `tests/syslog_payload_e2e.rs`, assert the **on-disk** Parquet schema, mirroring Task A4 Step 3 but for the `timestamp` column.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --all-features syslog`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/
git commit -m "test(syslog): assert timestamps are microsecond UTC end to end"
```

---

## Workstream C — Remaining sinks

Every column in this workstream is already a `DateTime<Utc>` formatted with `to_rfc3339()`. All four tasks are the same mechanical swap; only the file, column names, and nullability differ.

**On test levels:** these four sinks have unit tests (in-module) and integration tests (`tests/suricata_s3_integration.rs`, `tests/sflow_s3_integration.rs`, `tests/ipfix_s3_integration.rs`, `tests/wef_s3_integration.rs`, plus their `*_local_integration.rs` counterparts), but **no end-to-end test files exist for them** — the repo's `*_e2e.rs` suite covers zeek, syslog, HEC, OTLP, aggregate, and admin only. Workstream C therefore ships unit + integration coverage, and the end-to-end level is covered for this change by Tasks A4 and B5, which assert the on-disk Parquet column type through the outermost interface. The type change is identical across all sinks, so an e2e assertion on zeek and syslog exercises the same guarantee. Do **not** stand up new e2e harnesses for these four sinks as part of this work; that is a separate piece of test infrastructure.

### Task C1: Retype `received_at` in the Suricata envelope sink

**Files:**
- Modify: `src/suricata/schema.rs` — field at 24, doc comment at 17, mapper at 41 and its builder
- Test: `src/suricata/schema.rs` in-module tests

**Interfaces:**
- Consumes: `SuricataRecord.received_at` (`DateTime<Utc>`).
- Produces: `envelope_schema()` in the `suricata` module — signature unchanged.

Note this is a **different** `envelope_schema()` from the Zeek one; they share a name across modules.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn schema_received_at_is_microsecond_timestamp() {
    use arrow::datatypes::{DataType, TimeUnit};
    let s = envelope_schema();
    let f = s.field_with_name("received_at").unwrap();
    assert_eq!(
        f.data_type(),
        &DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
    );
    assert!(!f.is_nullable());
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --all-features --lib suricata::schema`
Expected: FAIL.

- [ ] **Step 3: Change the field, mapper, and doc comment**

Line 24 becomes the `Timestamp(Microsecond, Some("UTC"))` form, still non-nullable.

Line 41: `let received_at = record.received_at.to_rfc3339();` → `let received_at = record.received_at.timestamp_micros();`

Swap `b_received_at`'s `StringBuilder::new()` for the `TimestampMicrosecondBuilder` form from Reference Patterns, and change `b_received_at.append_value(&received_at);` to `append_value(received_at)` (an `i64` by value).

Line 17's doc comment reads ``- `received_at` — Utf8, non-null  (RFC-3339 wall-clock ingest time)``. Update it to ``- `received_at` — Timestamp(µs, UTC), non-null  (wall-clock ingest time)``.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --all-features suricata`
Expected: PASS. Update `tests/suricata_s3_integration.rs` and `tests/suricata_local_integration.rs` read-back assertions if they check this column.

- [ ] **Step 5: Commit**

```bash
git add src/suricata/schema.rs tests/
git commit -m "feat(suricata): write received_at as Timestamp(Microsecond, UTC)"
```

---

### Task C2: Retype `received_at` in both sFlow schemas

**Files:**
- Modify: `src/forwarding/sflow_s3.rs` — fields at 20 and 37, mappers at 108 (`flow_to_record_batch`) and 175 (`counter_to_record_batch`)
- Test: `src/forwarding/sflow_s3.rs` in-module tests at 403 (`flow_schema_has_required_columns`) and 428 (`counter_schema_has_required_columns`)

**Interfaces:**
- Consumes: `SflowRecord.received_at` (`DateTime<Utc>`).
- Produces: both sFlow schemas — signatures unchanged.

There are **two** schemas here (flow and counter), each with its own mapper. Change both.

- [ ] **Step 1: Update the failing tests**

In both `flow_schema_has_required_columns` and `counter_schema_has_required_columns`, assert `received_at` is `Timestamp(Microsecond, Some("UTC".into()))` and remains non-nullable.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --all-features --lib forwarding::sflow_s3`
Expected: FAIL.

- [ ] **Step 3: Change both fields and both mappers**

Lines 20 and 37 become the `Timestamp(Microsecond, Some("UTC"))` form, non-nullable.

Lines 108 and 175: `b.append_value(r.received_at.to_rfc3339());` → `b.append_value(r.received_at.timestamp_micros());`, with the corresponding builder switched to `TimestampMicrosecondBuilder` carrying the timezone data type.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --all-features sflow`
Expected: PASS. Update `tests/sflow_s3_integration.rs` and `tests/sflow_local_integration.rs` if they assert on this column.

- [ ] **Step 5: Commit**

```bash
git add src/forwarding/sflow_s3.rs tests/
git commit -m "feat(sflow): write received_at as Timestamp(Microsecond, UTC)"
```

---

### Task C3: Retype `export_time`, `flow_start`, and `flow_end` in the IPFIX sink

**Files:**
- Modify: `src/forwarding/ipfix_s3.rs` — fields at 32, 40, 41; builder struct at 73-74 and 97-98; mapper at 129 and 147-151
- Test: `src/forwarding/ipfix_s3.rs` in-module tests at 411-412
- Modify: `IPFIX_IMPLEMENTATION.md:133, 141-142, 148` and `README.md:341, 349-350`

**Interfaces:**
- Consumes: `IpfixRecord.export_time` (`DateTime<Utc>`), `.flow_start` and `.flow_end` (`Option<DateTime<Utc>>`).
- Produces: the IPFIX schema — signature unchanged, three field types changed.

This sink uses a **persistent builder struct**, so the `.with_data_type(...)` call is mandatory (see Reference Patterns).

- [ ] **Step 1: Update the failing tests**

The test around 411-412 lists expected columns as tuples including `("flow_start", DataType::Utf8, true)`. Change the three timestamp entries to `DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))`, preserving each one's nullability flag: `export_time` non-null, `flow_start` and `flow_end` nullable.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --all-features --lib forwarding::ipfix_s3`
Expected: FAIL.

- [ ] **Step 3: Change the schema fields**

Line 32 (`export_time`, non-null), 40 (`flow_start`, nullable), 41 (`flow_end`, nullable) all become the `Timestamp(Microsecond, Some("UTC"))` form.

- [ ] **Step 4: Change the builder struct**

Lines 73-74: `flow_start: StringBuilder,` / `flow_end: StringBuilder,` → `TimestampMicrosecondBuilder`. Do the same for the `export_time` builder field.

Lines 97-98 (and the `export_time` equivalent) in the constructor: use the `.with_data_type(...)` form.

- [ ] **Step 5: Change the mapper**

Line 129: `.append_value(record.export_time.to_rfc3339());` → `.append_value(record.export_time.timestamp_micros());`

Lines 147-151:

```rust
.flow_start
.append_option(record.flow_start.map(|t| t.timestamp_micros()));
.flow_end
.append_option(record.flow_end.map(|t| t.timestamp_micros()));
```

(preserving the existing method-chain shape in the file).

- [ ] **Step 6: Run to verify pass**

Run: `cargo test --all-features ipfix`
Expected: PASS. Update `tests/ipfix_s3_integration.rs` and `tests/ipfix_local_integration.rs` read-back assertions.

- [ ] **Step 7: Update the docs**

`IPFIX_IMPLEMENTATION.md` lines 133, 141, 142: change the `Utf8` type cells to `Timestamp(µs, UTC)`.

Line 148 reads "IP addresses and timestamps are stored as UTF-8 strings. Timestamps use RFC 3339 format." Change to: "IP addresses are stored as UTF-8 strings. Timestamps are microsecond-precision UTC timestamps, usable directly as Iceberg partition-transform sources."

`README.md` lines 341, 349, 350: change `String (RFC 3339)` to `Timestamp(µs, UTC)`.

- [ ] **Step 8: Commit**

```bash
git add src/forwarding/ipfix_s3.rs tests/ IPFIX_IMPLEMENTATION.md README.md
git commit -m "feat(ipfix): write export_time, flow_start and flow_end as Timestamp(Microsecond, UTC)"
```

---

### Task C4: Retype `timestamp` in the WEF sink

**Files:**
- Modify: `src/forwarding/parquet_s3.rs` — field at 56, mapper at 82
- Test: `src/forwarding/parquet_s3.rs` in-module tests, `tests/wef_s3_integration.rs`, `tests/wef_local_integration.rs`

**Interfaces:**
- Consumes: `WindowsEvent.received_at` (`DateTime<Utc>`).
- Produces: the WEF sink schema — signature unchanged.

Note the column is named `timestamp` but is populated from `record.received_at`. Do not rename it; renaming is out of scope.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn schema_timestamp_is_microsecond_timestamp() {
    use arrow::datatypes::{DataType, TimeUnit};
    let schema = WefSink.schema(None);
    let f = schema.field_with_name("timestamp").unwrap();
    assert_eq!(
        f.data_type(),
        &DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
    );
    assert!(!f.is_nullable());
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --all-features --lib forwarding::parquet_s3`
Expected: FAIL.

- [ ] **Step 3: Change the field and mapper**

Line 56 becomes the `Timestamp(Microsecond, Some("UTC"))` form, non-nullable.

Line 82:

```rust
Arc::new(StringArray::from(vec![record.received_at.to_rfc3339()])) as ArrayRef,
```

becomes:

```rust
Arc::new(
    TimestampMicrosecondArray::from(vec![record.received_at.timestamp_micros()])
        .with_timezone(Arc::<str>::from("UTC")),
) as ArrayRef,
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --all-features wef`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/forwarding/parquet_s3.rs tests/
git commit -m "feat(wef): write timestamp as Timestamp(Microsecond, UTC)"
```

---

## Final verification

Run after all three workstreams have merged. Do not claim completion before every command below has been run and its output inspected.

- [ ] **Step 1: Full build**

Run: `cargo build --all-features`
Expected: no errors, no new warnings.

- [ ] **Step 2: Full test suite**

Run: `cargo test --all-features`
Expected: all tests pass. A `RecordBatch::try_new` schema-mismatch failure at runtime means a builder is missing its `.with_data_type(...)` call.

- [ ] **Step 3: Lint and format**

Run: `cargo clippy --all-features --all-targets -- -D warnings && cargo fmt --check`
Expected: clean.

- [ ] **Step 4: Verify no stringly-typed Parquet timestamps remain**

Run: `grep -rn 'to_rfc3339' --include='*.rs' src/forwarding src/zeek src/suricata`
Expected: **zero hits.** Every remaining `to_rfc3339()` in the codebase should live in `src/forwarding/aggregate/fields.rs` (grouping keys), `src/admin/` (JSON API responses), or `src/ipfix/decoder.rs:725` (a JSON `extra` value, not a Parquet column) — all deliberately out of scope.

- [ ] **Step 5: Verify no millisecond timestamps remain**

Run: `grep -rn 'TimeUnit::Millisecond\|TimestampMillisecond' --include='*.rs' src/`
Expected: zero hits.

- [ ] **Step 6: Confirm the goal holds**

Run: `grep -rn 'DataType::Timestamp' --include='*.rs' src/ | grep -v Microsecond`
Expected: zero hits — every Arrow timestamp in the codebase is now microsecond precision with a `Some("UTC")` timezone.

---

## Out of scope

Recorded so the next reader does not go looking:

- `src/forwarding/aggregate/mod.rs` — `window_start`/`window_end` are already `Timestamp(Microsecond, UTC)`. The originating feature request claimed these were millisecond; that claim is false, verified at lines 478 and 550.
- `src/forwarding/aggregate/fields.rs`, `src/admin/mod.rs`, `src/admin/state.rs` — `to_rfc3339()` calls that produce aggregation grouping keys and JSON API responses, not Parquet columns.
- RFC 3164's year-from-`Utc::now()` behaviour — documented in Task B4, deliberately not changed. Fixing the year-boundary-under-buffering edge case requires threading `received_at` through `parse_rfc3164_timestamp` and its callers.
- Making the RFC 3164 timezone assumption configurable — no sender-timezone handling exists anywhere in the repo, and a config knob with no concrete requester is speculative surface.
