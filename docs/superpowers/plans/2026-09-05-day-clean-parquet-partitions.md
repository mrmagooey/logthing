# Day-Clean Parquet Partitions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the UTC event day part of `PartitionedParquetWriter`'s buffer key so every Parquet file it writes contains rows from exactly one UTC day, matching Iceberg's requirement that a data file belong to exactly one `day()` partition tuple.

**Architecture:** `buffers: HashMap<String, PartitionBuffer<R>>` becomes `HashMap<BufKey, PartitionBuffer<R>>` where `BufKey { partition, day }`. The day is computed once per push, from the same single-row (or, for IPFIX, uniformly-timestamped multi-row) batch that gets stored — never from a second clock read or from `chrono::Utc::now()` at flush time. `build_key`, `encode_and_upload`, `apply_flush_outcome`, and the flush/retry machinery are updated to carry `BufKey` instead of a bare partition string, but their control flow is otherwise untouched: one buffer still produces exactly one file and one descriptor.

**Tech Stack:** Rust, Arrow, Parquet, chrono, tokio

**Spec:** docs/superpowers/specs/2026-09-05-day-clean-parquet-partitions-design.md

## Global Constraints

- Every task that touches `.rs` files ends with `cargo fmt --all` and includes the resulting diff in that task's commit — rustfmt is enforced by CI and a pre-push hook.
- Clippy runs with `-D warnings` over `--all-targets`; run `cargo clippy --all-targets --all-features -- -D warnings` before committing each task.
- Export before any cargo command: `PATH="$HOME/.cargo/bin:$PATH"`, `CC=/usr/bin/gcc CXX=/usr/bin/g++`, `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc`. Run cargo in the foreground; `cargo check` is normally enough between steps, `cargo test <name>` to drive TDD.
- Tests at all three levels (unit / integration / e2e) are required per behavior change; if a level genuinely doesn't apply, the task says so explicitly.
- Every commit ends with the attribution block given in the workflow instructions (session + co-author trailer) — each task's commit command already includes it.
- Do not redesign the approved spec. Where this plan deviates from its literal wording, the task explains why in a comment, and the deviation is also called out in this plan's "Spec gaps found" section below.
- Never call `chrono::Utc::now()` more than once per `push()` — every function invoked from `push()` that needs "now" receives the same captured value as a parameter.

## Spec gaps found (read before implementing)

1. **Zeek's per-sink table row (`ts`, no fallback) is incomplete.** All 7 Zeek schemas (6 typed + envelope) declare `ts` **nullable** (`src/zeek/schema.rs:35-39` etc.), and the 6 typed schemas have no fallback column at all — only the envelope schema has a non-null `ingest_time`. Resolution: `ZeekSink` gets its own cheap day-derivation override (Task 5) that reads `record.fields["ts"]` directly and falls back to the push-time wall clock, applied uniformly to every Zeek log path (not just `conn`) — cheaper than the generic path and correct for all 7 schemas including the 6 with no fallback column.
2. **The spec's "records are mapped to a single-row RecordBatch" framing does not hold for `IpfixSink`.** `IpfixSink::Record = Vec<FlowRecord>` and `to_record_batch` maps the whole vector into a multi-row batch per push (`src/forwarding/ipfix_s3.rs:242`). Verified in `src/ipfix/decoder.rs` that `export_time` is decoded once per IPFIX message and copied onto every `FlowRecord` produced from it, so row 0 of that batch is provably representative of every other row — reading day from row 0 is safe, just not for the literal reason the spec states. Task 4/6's `day_from_batch` reads row 0 only; this is documented in that function's doc comment rather than treated as a new problem.
3. **The spec names `time_column()` as "the seam" but doesn't resolve the tension between it and the amortized-builder / no-second-clock-read requirements.** A naive "read `time_column()` off a column" design either (a) forces `to_record_batch` to run twice per push (once to learn the day, once for the real batch), which reopens exactly the "second clock read" race the spec explicitly rules out for syslog's `received_at`, or (b) forces every sink to duplicate its own mapping logic in a second, cheap, no-Arrow function. This plan resolves it with `ParquetSink::day_and_batch()` (Task 2): call `to_record_batch` once, read the day back off the very batch produced, and hand that batch to the caller so it is never rebuilt. `time_column()` remains the one-line-per-sink seam that `day_and_batch`'s default implementation consumes; only `ZeekSink` (the sole `new_batch` implementor) overrides `day_and_batch` itself, for the reason in point 1.
4. **The spec doesn't address `max_partitions` / `"_overflow"` interacting with day-multiplied buffers or with empty-buffer reaping.** If the partition cap check used `self.buffers.len()` after this change, either (a) a transient day-doubling around midnight could trip the cap early, or (b) reaping an idle buffer (which this plan adds, per the spec's "Empty day-buffers must be reaped" requirement) could make a partition's slot "forgettable" and let a later stream steal it. Resolution (Task 3): a separate, never-shrinking `known_partitions: HashSet<String>` tracks distinct partitions independent of `buffers` and of reaping.

## File Structure

- `src/forwarding/buffered_writer.rs` — `BufKey`, retyped `buffers` map, `ParquetSink::time_column`/`day_and_batch`, `day_from_batch`, reworked `push`/`flush_all`/`flush_all_if_needed`/`try_flush_partition_async`/`apply_flush_outcome`/`encode_and_upload`/`build_key`, empty-buffer reaping, `known_partitions` cap tracking, `buffer_by_partition` test helper.
- `src/forwarding/zeek_s3.rs` — `ZeekSink::time_column` + `day_and_batch` override; migrated test lookups.
- `src/zeek/schema.rs` — `conn_event_day` helper (reused by the `ZeekSink` override).
- `src/forwarding/syslog_s3.rs` — new `received_at` schema column, updated `syslog_message_to_batch`, `time_column`.
- `src/forwarding/structured_syslog_s3.rs`, `generic_s3.rs`, `suricata_s3.rs`, `sflow_s3.rs`, `ipfix_s3.rs`, `parquet_s3.rs`, `aggregate/mod.rs` — one-line `time_column()` opt-ins.
- `src/forwarding/suricata_s3.rs`, `generic_s3.rs`, `ipfix_s3.rs` — migrated direct-buffer-lookup test call sites.
- `tests/zeek_local_integration.rs` (new test added) or a new `tests/day_clean_partitions_integration.rs` — integration coverage for multi-file flush + retry re-split.
- A new `tests/day_clean_partitions_e2e.rs` — e2e coverage: ingest spanning a day boundary through a real sink, assert every written file is day-clean.
- `Cargo.toml` / `Cargo.lock` — version bump to `0.16.0`.

---

### Task 1: `build_key` takes the buffer's day, not `Utc::now()`

**Files:**
- Modify: `src/forwarding/buffered_writer.rs:343-362` (`build_key`), `src/forwarding/buffered_writer.rs:992` (its one production call site, temporary shim)
- Test: `src/forwarding/buffered_writer.rs` (existing `build_key_*` tests, ~1600-1658), `src/forwarding/suricata_s3.rs` (~355-366), `src/forwarding/zeek_s3.rs` (~509-529), `src/forwarding/parquet_s3.rs` (~300-313)

**Interfaces:**
- Produces: `pub(crate) fn build_key(prefix: &str, partition: Option<&str>, day: chrono::NaiveDate) -> String` — used unchanged in signature by every later task.

This is a pure, low-risk signature change done first: it does not require `BufKey` to exist yet (Task 3 introduces that), and it is independently testable. The one production call site (inside `encode_and_upload`) temporarily passes `chrono::Utc::now().date_naive()`, which is byte-for-byte what happens today (the old code passed `chrono::Utc::now()` and `build_key` only ever used its date components) — so this task changes zero observable behavior. Task 3 replaces that shim with the buffer's real day.

- [ ] **Step 1: Write the failing tests**

Replace the four `build_key` test call sites' `now` construction. In `src/forwarding/buffered_writer.rs` (inside `mod tests` starting ~line 1550):

```rust
#[test]
fn build_key_no_partition() {
    let day = chrono::NaiveDate::from_ymd_opt(2026, 3, 7).unwrap();
    let key = build_key("syslog", None, day);
    assert!(
        key.starts_with("syslog/year=2026/month=03/day=07/"),
        "got: {key}"
    );
    assert!(key.ends_with(".parquet"), "got: {key}");
    assert!(!key.contains("//"), "double-slash: {key}");
}

#[test]
fn build_key_with_partition() {
    let day = chrono::NaiveDate::from_ymd_opt(2026, 3, 7).unwrap();
    let key = build_key("zeek", Some("conn"), day);
    assert!(
        key.starts_with("zeek/conn/year=2026/month=03/day=07/"),
        "got: {key}"
    );
    assert!(key.ends_with(".parquet"), "got: {key}");
}

#[test]
fn build_key_wef_partition_segment() {
    let day = chrono::NaiveDate::from_ymd_opt(2026, 6, 1).unwrap();
    let key = build_key("wef", Some("event_type=4624"), day);
    assert!(
        key.starts_with("wef/event_type=4624/year=2026/"),
        "got: {key}"
    );
}

#[test]
fn build_key_empty_prefix_with_partition() {
    let day = chrono::NaiveDate::from_ymd_opt(2026, 6, 21).unwrap();

    let key = build_key("", Some("event_type=4624"), day);
    assert!(
        key.starts_with("event_type=4624/year=2026/"),
        "empty prefix with partition must not have leading slash: {key}"
    );
    assert!(!key.starts_with('/'), "must not start with /: {key}");
    assert!(!key.contains("//"), "must not have double-slash: {key}");
    assert!(key.ends_with(".parquet"), "must end with .parquet: {key}");

    let key2 = build_key("", None, day);
    assert!(
        key2.starts_with("year=2026/"),
        "empty prefix without partition must start with year=: {key2}"
    );
    assert!(!key2.starts_with('/'), "must not start with /: {key2}");
}
```

In `src/forwarding/suricata_s3.rs` (~line 355):

```rust
#[test]
fn build_key_produces_suricata_event_type_layout() {
    use crate::forwarding::buffered_writer::build_key;

    let day = chrono::NaiveDate::from_ymd_opt(2026, 3, 7).unwrap();
    let key = build_key("suricata", Some("alert"), day);
    assert!(
        key.starts_with("suricata/alert/year=2026/month=03/day=07/"),
        "key: {key}"
    );
    assert!(key.ends_with(".parquet"), "key: {key}");
}
```

In `src/forwarding/zeek_s3.rs` (~line 509):

```rust
#[test]
fn build_key_produces_zeek_log_path_layout() {
    use crate::forwarding::buffered_writer::build_key;

    let day = chrono::NaiveDate::from_ymd_opt(2026, 3, 7).unwrap();

    let key = build_key("zeek", Some("conn"), day);
    assert!(
        key.starts_with("zeek/conn/year=2026/month=03/day=07/"),
        "key: {key}"
    );
    assert!(key.ends_with(".parquet"), "key: {key}");

    let key = build_key("zeek", Some("dns"), day);
    assert!(key.starts_with("zeek/dns/year="), "key: {key}");

    let key = build_key("zeek", Some("_overflow"), day);
    assert!(key.starts_with("zeek/_overflow/year="), "key: {key}");
}
```

In `src/forwarding/parquet_s3.rs` (~line 300):

```rust
#[test]
fn s3_key_layout_empty_prefix_produces_correct_path() {
    use crate::forwarding::buffered_writer::build_key;
    let day = chrono::NaiveDate::from_ymd_opt(2026, 6, 21).unwrap();
    let key = build_key("", Some("event_type=4624"), day);
    assert!(
        key.starts_with("event_type=4624/year=2026/month=06/day=21/"),
        "WEF S3 key must match legacy layout: {key}"
    );
    assert!(!key.starts_with('/'), "must not start with /");
    assert!(!key.contains("//"), "must not have double-slash");
    assert!(key.ends_with(".parquet"));
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cargo test build_key` — Expected: FAIL with a type error (`expected chrono::NaiveDate, found chrono::DateTime<chrono::Utc>` or similar) once the signature below is applied, or (before Step 3) the tests fail to compile because `build_key` still expects a `DateTime<Utc>` and the test now passes a `NaiveDate`.

- [ ] **Step 3: Implement**

In `src/forwarding/buffered_writer.rs`, replace `build_key`:

```rust
/// Build the S3 object key for a flush.
/// Pattern: `{prefix}/[{partition}/]year={Y}/month={MM}/day={DD}/{uuid}.parquet`
/// The partition segment is omitted when `partition` is `None` (syslog, ipfix).
/// When `prefix` is empty the prefix segment is omitted entirely (no leading slash).
///
/// Takes the buffer's own UTC day directly, never `chrono::Utc::now()` --
/// the buffer key (`BufKey`) is what makes each file day-clean; reading
/// any other clock here would silently reintroduce the bug this design
/// fixes for a flush that crosses midnight mid-encode (see the design
/// doc's "Rejected approach" section, point 1).
pub(crate) fn build_key(prefix: &str, partition: Option<&str>, day: chrono::NaiveDate) -> String {
    use chrono::Datelike as _;
    let id = uuid::Uuid::new_v4();
    let date = format!(
        "year={}/month={:02}/day={:02}",
        day.year(),
        day.month(),
        day.day()
    );
    match (prefix.is_empty(), partition) {
        (true, Some(seg)) => format!("{}/{}/{}.parquet", seg, date, id),
        (true, None) => format!("{}/{}.parquet", date, id),
        (false, Some(seg)) => format!("{}/{}/{}/{}.parquet", prefix, seg, date, id),
        (false, None) => format!("{}/{}/{}.parquet", prefix, date, id),
    }
}
```

In `encode_and_upload` (~line 992), temporarily preserve today's exact behavior (Task 3 replaces this with the real buffer day):

```rust
    // TODO(Task 3): use the flushed buffer's own day (`key.day`) once
    // `BufKey` exists, instead of re-reading the clock here.
    let s3_key = build_key(&prefix, partition_seg, chrono::Utc::now().date_naive());
```

- [ ] **Step 4: Verify pass**

Run: `cargo test build_key` and `cargo test --lib` — Expected: all pass, no other call site broken (only the 4 files above call `build_key` directly).

- [ ] **Step 5: `cargo fmt --all` and commit**

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
git add src/forwarding/buffered_writer.rs src/forwarding/suricata_s3.rs src/forwarding/zeek_s3.rs src/forwarding/parquet_s3.rs
git commit -m "$(cat <<'EOF'
refactor(forwarding): build_key takes an explicit day, not Utc::now()

Prepares for day-clean Parquet partitions: the S3 key's year=/month=/day=
path must come from the buffer's own data, not a clock read taken after
the zstd encode completes. No behavior change yet -- the one production
call site still derives the day from Utc::now(), same as before.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UquMzVB7CCkD2EzadzNMA5
EOF
)"
```

---

### Task 2: `ParquetSink::time_column` / `day_and_batch` seam + `day_from_batch` helper

**Files:**
- Modify: `src/forwarding/buffered_writer.rs:65-102` (`ParquetSink` trait)
- Test: `src/forwarding/buffered_writer.rs` (new unit tests near the trait definition's test module)

**Interfaces:**
- Consumes: none new (uses existing `ParquetSink::to_record_batch`).
- Produces:
  - `fn day_from_batch(batch: &arrow_array::RecordBatch, time_col: &str, now: chrono::DateTime<chrono::Utc>) -> chrono::NaiveDate` (free function, `buffered_writer.rs`)
  - `ParquetSink::time_column(&self) -> &'static str` (default `""`)
  - `ParquetSink::day_and_batch(&self, record: &Self::Record, schema: &Arc<arrow_schema::Schema>, now: chrono::DateTime<chrono::Utc>) -> anyhow::Result<(chrono::NaiveDate, Option<arrow_array::RecordBatch>)>` (default impl)
  - Task 3 consumes `day_and_batch` from `push()`; Task 4 overrides `time_column()` per sink; Task 5 overrides `day_and_batch()` for `ZeekSink`.

This task is a pure addition — no existing call site changes, so the tree keeps compiling and every existing test stays green. `time_column()` defaults to `""` (never matches a real schema column) specifically so the ~12 test-only `ParquetSink` mocks scattered across this crate (`MockSink`, `AmortizingMockSink`, `TwoPartitionMock`, etc. — none of which care about accurate day partitioning) need no changes at all: they fall straight through to the `now`-based fallback in `day_from_batch`, which buckets every record from one short-lived test run onto the same single day.

- [ ] **Step 1: Write the failing test**

Add near the top-level (non-`mod tests`) code in `src/forwarding/buffered_writer.rs`, in a new `#[cfg(test)] mod day_from_batch_tests` placed directly after the `day_from_batch` function (see Step 3 for where):

```rust
#[cfg(test)]
mod day_from_batch_tests {
    use super::*;
    use arrow::array::TimestampMicrosecondArray;
    use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
    use arrow::record_batch::RecordBatch;
    use chrono::TimeZone;

    fn ts_schema(cols: &[&str]) -> Arc<Schema> {
        Arc::new(Schema::new(
            cols.iter()
                .map(|name| {
                    Field::new(
                        *name,
                        DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                        true,
                    )
                })
                .collect::<Vec<_>>(),
        ))
    }

    fn ts_batch(schema: &Arc<Schema>, values: &[Option<i64>]) -> RecordBatch {
        let cols: Vec<arrow_array::ArrayRef> = values
            .iter()
            .map(|v| {
                Arc::new(TimestampMicrosecondArray::from(vec![*v]).with_timezone("UTC"))
                    as arrow_array::ArrayRef
            })
            .collect();
        RecordBatch::try_new(schema.clone(), cols).unwrap()
    }

    fn micros(y: i32, m: u32, d: u32) -> i64 {
        chrono::Utc.with_ymd_and_hms(y, m, d, 12, 0, 0).unwrap().timestamp_micros()
    }

    #[test]
    fn reads_the_primary_column_when_non_null() {
        let schema = ts_schema(&["ts"]);
        let batch = ts_batch(&schema, &[Some(micros(2026, 3, 7))]);
        let now = chrono::Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap();
        let day = day_from_batch(&batch, "ts", now);
        assert_eq!(day, chrono::NaiveDate::from_ymd_opt(2026, 3, 7).unwrap());
    }

    #[test]
    fn falls_back_to_received_at_when_primary_is_null() {
        let schema = ts_schema(&["timestamp", "received_at"]);
        let batch = ts_batch(&schema, &[None, Some(micros(2026, 5, 1))]);
        let now = chrono::Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap();
        let day = day_from_batch(&batch, "timestamp", now);
        assert_eq!(day, chrono::NaiveDate::from_ymd_opt(2026, 5, 1).unwrap());
    }

    #[test]
    fn falls_back_to_now_when_nothing_else_applies() {
        let schema = ts_schema(&["ts"]);
        let batch = ts_batch(&schema, &[None]);
        let now = chrono::Utc.with_ymd_and_hms(2030, 12, 25, 0, 0, 0).unwrap();
        let day = day_from_batch(&batch, "ts", now);
        assert_eq!(day, chrono::NaiveDate::from_ymd_opt(2030, 12, 25).unwrap());
    }

    #[test]
    fn empty_time_column_name_skips_straight_to_fallback_chain() {
        let schema = ts_schema(&["received_at"]);
        let batch = ts_batch(&schema, &[Some(micros(2027, 2, 2))]);
        let now = chrono::Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap();
        // time_column() defaults to "" for sinks that don't opt in.
        let day = day_from_batch(&batch, "", now);
        assert_eq!(day, chrono::NaiveDate::from_ymd_opt(2027, 2, 2).unwrap());
    }
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cargo test day_from_batch_tests` — Expected: FAIL to compile, `cannot find function 'day_from_batch' in this scope`.

- [ ] **Step 3: Implement**

In `src/forwarding/buffered_writer.rs`, extend the `ParquetSink` trait (after the existing `new_batch` default, before its closing `}`, i.e. right after line 101's closing brace of `new_batch`):

```rust
    /// Name of the Arrow column whose value determines a record's UTC
    /// event day -- the column `day_and_batch`'s default implementation
    /// reads to bucket buffers (and therefore Parquet files) so each one
    /// is "day-clean": every row decodes to the same Iceberg `day()`
    /// partition tuple. See
    /// docs/superpowers/specs/2026-09-05-day-clean-parquet-partitions-design.md.
    ///
    /// Default `""` never matches a real column, so `day_and_batch`'s
    /// default falls straight through to the generic `received_at` / `now`
    /// fallback chain in `day_from_batch`. That is intentionally fine for
    /// every sink that doesn't override it -- in particular this crate's
    /// own test-only `ParquetSink` mocks, none of which need accurate
    /// day partitioning and all of which get correct (if day-agnostic)
    /// bucketing for free.
    fn time_column(&self) -> &'static str {
        ""
    }

    /// Map one record to its batch AND the UTC day its `time_column()`
    /// value falls on, in a single pass.
    ///
    /// Default: calls `to_record_batch` exactly once, then reads the day
    /// back off the very batch it just built (`day_from_batch`). This is
    /// deliberate, not just an optimization: it is the only way a sink
    /// that stamps a fresh `Utc::now()` value into the row it returns
    /// (e.g. syslog's `received_at` -- see `syslog_s3.rs`) can guarantee
    /// the buffer-key day and the persisted value never disagree. Calling
    /// `to_record_batch` a second time, or reading the clock a second
    /// time, would each independently reopen that race.
    ///
    /// Returns `(day, None)` instead of `(day, Some(batch))` only when a
    /// sink overrides this method to compute the day WITHOUT building a
    /// batch -- exclusively relevant to a sink that also implements
    /// `new_batch` (an amortized fast path whose entire purpose is
    /// avoiding a per-record `to_record_batch` call; see `ZeekSink`'s
    /// override). The caller (`PartitionedParquetWriter::push`) treats
    /// `None` as "map it later, only if actually needed."
    fn day_and_batch(
        &self,
        record: &Self::Record,
        schema: &Arc<arrow_schema::Schema>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<(chrono::NaiveDate, Option<arrow_array::RecordBatch>)> {
        let batch = self.to_record_batch(record, schema)?;
        let day = day_from_batch(&batch, self.time_column(), now);
        Ok((day, Some(batch)))
    }
```

Then, just before the `PartitionBuffer` section (i.e. right before the `// PartitionBuffer — internal per-partition state` comment block), add the free function:

```rust
/// Extract the UTC calendar day a just-mapped batch's designated
/// `time_col` falls on, reading row 0 only.
///
/// Row 0 is correct for every sink's batch except `IpfixSink`'s, which
/// maps a whole `Vec<FlowRecord>` (already batched at the listener) into
/// one multi-row `RecordBatch` per push -- but IPFIX's `export_time` is
/// decoded once per message and copied onto every `FlowRecord` produced
/// from it (see `src/ipfix/decoder.rs`), so row 0 can never disagree with
/// any other row in that same batch.
///
/// Fallback chain: `time_col` -> a column literally named `"received_at"`
/// -> `now`. The middle step is what lets syslog/structured_syslog/generic
/// (each of whose primary time column is nullable) fall back to their own
/// `received_at` column without any sink-specific code here; it is a
/// harmless no-op for sinks whose primary column has no such column to
/// find (e.g. Zeek's typed schemas, which fall straight to `now`).
fn day_from_batch(
    batch: &arrow_array::RecordBatch,
    time_col: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> chrono::NaiveDate {
    use arrow_array::Array as _;

    let day_of = |name: &str| -> Option<chrono::NaiveDate> {
        let col = batch.column_by_name(name)?;
        let ts = col
            .as_any()
            .downcast_ref::<arrow_array::TimestampMicrosecondArray>()?;
        if ts.is_empty() || ts.is_null(0) {
            return None;
        }
        chrono::DateTime::from_timestamp_micros(ts.value(0)).map(|dt| dt.date_naive())
    };

    day_of(time_col)
        .or_else(|| day_of("received_at"))
        .unwrap_or_else(|| now.date_naive())
}
```

- [ ] **Step 4: Verify pass**

Run: `cargo test day_from_batch_tests` and `cargo test --lib` — Expected: all pass; every existing `ParquetSink` implementor keeps compiling unchanged (both new trait methods have defaults).

- [ ] **Step 5: `cargo fmt --all` and commit**

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
git add src/forwarding/buffered_writer.rs
git commit -m "$(cat <<'EOF'
feat(forwarding): add ParquetSink::time_column/day_and_batch seam

Pure addition: default implementations mean every existing sink and
test mock keeps compiling and behaving identically. Task 3 wires
day_and_batch into push() to drive day-based buffer routing.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UquMzVB7CCkD2EzadzNMA5
EOF
)"
```

---

### Task 3: `BufKey` — day becomes part of the buffer map key

**Files:**
- Modify: `src/forwarding/buffered_writer.rs` (`PartitionedParquetWriter` struct and impl, `FlushOutcome`, `encode_and_upload`, `push`, `flush_all`, `flush_all_if_needed`, `try_flush_partition_async`, `apply_flush_outcome`, `update_buffer_gauges`)
- Test: `src/forwarding/buffered_writer.rs` (new + migrated tests), `src/forwarding/zeek_s3.rs`, `src/forwarding/suricata_s3.rs`, `src/forwarding/generic_s3.rs`, `src/forwarding/ipfix_s3.rs` (migrated direct-buffer-lookup tests)

**Interfaces:**
- Consumes: `build_key(prefix, partition, day: NaiveDate)` (Task 1), `ParquetSink::day_and_batch(...)` (Task 2).
- Produces:
  - `pub(crate) struct BufKey { pub(crate) partition: String, pub(crate) day: chrono::NaiveDate }` (`Debug, Clone, PartialEq, Eq, Hash`)
  - `pub(crate) buffers: HashMap<BufKey, PartitionBuffer<S::Record>>` (was `HashMap<String, _>`)
  - `pub(crate) fn buffer_by_partition(&self, partition: &str) -> Option<&PartitionBuffer<S::Record>>` (test helper, `#[cfg(test)]`)
  - Later tasks (4, 5, 7, 8) rely on `BufKey`'s exact field names and on `buffer_by_partition` existing.

This is the core, highest-risk task. It is still independently testable and leaves the tree compiling: every sink already compiles against the Task 2 defaults, so no per-sink changes are required here (Task 4 adds real per-sink `time_column()` values afterward — this task is provably correct first using only the `now`-based fallback).

- [ ] **Step 1: Write the failing tests**

In `src/forwarding/buffered_writer.rs`'s test module (extend the existing `use` lines at ~1551-1552 to also bring in `TimeUnit`/`TimestampMicrosecondArray`):

```rust
use arrow::array::{StringArray, StringBuilder, TimestampMicrosecondArray};
use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
```

Add a new mock and three tests (placed near `RecordingSink`, ~line 2127):

```rust
    #[derive(Clone)]
    struct TimestampedMock;
    impl ParquetSink for TimestampedMock {
        type Record = chrono::DateTime<chrono::Utc>;
        fn source(&self) -> &'static str {
            "test"
        }
        fn partition(&self, _: &chrono::DateTime<chrono::Utc>) -> Option<String> {
            None
        }
        fn schema(&self, _: Option<&str>) -> Arc<Schema> {
            Arc::new(Schema::new(vec![Field::new(
                "ts",
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                true,
            )]))
        }
        fn time_column(&self) -> &'static str {
            "ts"
        }
        fn to_record_batch(
            &self,
            record: &chrono::DateTime<chrono::Utc>,
            schema: &Arc<Schema>,
        ) -> anyhow::Result<RecordBatch> {
            let col = TimestampMicrosecondArray::from(vec![Some(record.timestamp_micros())])
                .with_timezone("UTC");
            Ok(RecordBatch::try_new(schema.clone(), vec![Arc::new(col)])?)
        }
    }

    #[tokio::test]
    async fn buffers_split_by_utc_day_produce_separate_flushes() {
        use chrono::TimeZone;

        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let s3: Arc<dyn UploadSink> = Arc::new(RecordingSink {
            uploads: uploads.clone(),
        });
        let (cfg, policy) = test_config(usize::MAX);
        let mut w = PartitionedParquetWriter::new(TimestampedMock, s3, cfg, policy);

        let day1 = chrono::Utc.with_ymd_and_hms(2026, 3, 7, 23, 59, 0).unwrap();
        let day2 = chrono::Utc.with_ymd_and_hms(2026, 3, 8, 0, 1, 0).unwrap();

        w.push(day1).await.unwrap();
        w.push(day2).await.unwrap();

        assert_eq!(
            w.buffers.len(),
            2,
            "records on different UTC days must land in separate buffers, even with no partition"
        );

        w.flush_all().await.unwrap();
        w.drain_pending_flushes().await;

        let keys: Vec<String> = uploads
            .lock()
            .unwrap()
            .iter()
            .map(|(k, _)| k.clone())
            .collect();
        assert_eq!(keys.len(), 2, "each day-bucket must produce its own file: {keys:?}");
        assert!(
            keys.iter().any(|k| k.contains("year=2026/month=03/day=07/")),
            "{keys:?}"
        );
        assert!(
            keys.iter().any(|k| k.contains("year=2026/month=03/day=08/")),
            "{keys:?}"
        );
    }

    #[tokio::test]
    async fn successful_flush_reaps_an_idle_buffer() {
        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let s3: Arc<dyn UploadSink> = Arc::new(RecordingSink { uploads });
        let (cfg, policy) = test_config(1);
        let mut w = PartitionedParquetWriter::new(MockSink, s3, cfg, policy);

        w.push("hello".to_string()).await.unwrap();
        assert_eq!(w.buffers.len(), 1, "buffer created lazily on first push");

        w.drain_pending_flushes().await;

        assert_eq!(
            w.buffers.len(),
            0,
            "a buffer that received no new pushes while its flush was in flight must be reaped"
        );
    }

    #[tokio::test]
    async fn max_partitions_cap_survives_empty_buffer_reaping() {
        struct TwoPartitionMock2;
        impl ParquetSink for TwoPartitionMock2 {
            type Record = (String, String);
            fn source(&self) -> &'static str {
                "test"
            }
            fn partition(&self, r: &(String, String)) -> Option<String> {
                Some(r.0.clone())
            }
            fn schema(&self, _: Option<&str>) -> Arc<Schema> {
                test_schema()
            }
            fn to_record_batch(
                &self,
                r: &(String, String),
                schema: &Arc<Schema>,
            ) -> anyhow::Result<RecordBatch> {
                let col = Arc::new(StringArray::from(vec![r.1.as_str()]));
                Ok(RecordBatch::try_new(schema.clone(), vec![col])?)
            }
        }

        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let s3: Arc<dyn UploadSink> = Arc::new(RecordingSink { uploads });
        let (mut cfg, policy) = test_config(1);
        cfg.max_partitions = 1;
        let mut w = PartitionedParquetWriter::new(TwoPartitionMock2, s3, cfg, policy);

        w.push(("p1".to_string(), "a".to_string())).await.unwrap();
        w.drain_pending_flushes().await;
        assert_eq!(w.buffers.len(), 0, "p1's buffer was flushed and reaped");

        w.push(("p2".to_string(), "b".to_string())).await.unwrap();
        assert!(
            w.buffer_by_partition("_overflow").is_some(),
            "p2 must overflow: p1 already holds the one available partition slot, \
             even though its buffer was reaped"
        );
        assert!(
            w.buffer_by_partition("p2").is_none(),
            "p2 must not get its own buffer once the cap is reached"
        );
    }
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cargo test buffers_split_by_utc_day_produce_separate_flushes successful_flush_reaps_an_idle_buffer max_partitions_cap_survives_empty_buffer_reaping` — Expected: FAIL to compile (`buffer_by_partition` doesn't exist yet; `TimestampedMock` fine but `w.buffers.len()` behavior wrong before the fix).

- [ ] **Step 3: Implement**

Add `BufKey` right before the `PartitionBuffer` section:

```rust
/// Buffer-map key: partition segment (`""` = no partition, mirroring the
/// historical `String`-keyed map used by syslog/ipfix) plus the UTC
/// calendar day of the records it holds. Splitting by day is the entire
/// mechanism behind "day-clean" Parquet files -- see
/// `ParquetSink::time_column`'s doc comment. Each `BufKey` maps to
/// exactly one `PartitionBuffer`, so one buffer -> one flush -> one file
/// -> one descriptor -> one `day()` Iceberg partition tuple, by
/// construction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct BufKey {
    pub(crate) partition: String,
    pub(crate) day: chrono::NaiveDate,
}
```

Change the `PartitionedParquetWriter` struct fields:

```rust
pub struct PartitionedParquetWriter<S: ParquetSink> {
    sink: S,
    s3: Arc<dyn UploadSink>,
    config: BufferedWriterConfig,
    policy: FlushPolicy,
    /// One entry per `(partition, day)` currently live. `partition` is
    /// `""` for None-partition sources; sanitized-path / `"event_type=<id>"`
    /// for multi-partition; `"_overflow"` past the partition cap.
    pub(crate) buffers: HashMap<BufKey, PartitionBuffer<S::Record>>,
    /// Every distinct partition string ever admitted as a real buffer
    /// (never `"_overflow"`'s inputs, only the sentinel itself once
    /// created), independent of day and NEVER shrunk -- including by the
    /// empty-buffer reaping in `apply_flush_outcome`. `max_partitions`
    /// must cap the number of distinct log streams (e.g. Zeek's up to
    /// 256 stream types), not the number of `(partition, day)` buffer
    /// entries, and must not "forget" a partition that goes briefly idle
    /// across midnight and gets reaped.
    known_partitions: std::collections::HashSet<String>,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<Arc<dyn UploadSink>>,
    flush_tasks: JoinSet<FlushOutcome>,
    flush_semaphore: Arc<tokio::sync::Semaphore>,
}
```

Update `with_source_stats`'s initializer to add `known_partitions: std::collections::HashSet::new(),` alongside `buffers: HashMap::new(),`.

Replace `push`:

```rust
    pub async fn push(&mut self, record: S::Record) -> anyhow::Result<()> {
        let now = chrono::Utc::now();
        let raw_partition = self.sink.partition(&record).unwrap_or_default();

        // Partition-count cap: based on distinct partitions ever
        // admitted, NOT on `self.buffers.len()` -- day multiplicity and
        // empty-buffer reaping would otherwise inflate or destabilize
        // the count this cap is meant to bound (see BufKey's doc comment).
        let effective_partition = if self.known_partitions.contains(&raw_partition)
            || self.config.max_partitions == 0
            || self.known_partitions.len() < self.config.max_partitions
        {
            raw_partition
        } else {
            metrics::counter!("parquet_s3_partitions_capped",
                "source" => self.sink.source(), "target" => self.s3.target_label())
            .increment(1);
            "_overflow".to_string()
        };
        self.known_partitions.insert(effective_partition.clone());

        let seg = if effective_partition.is_empty() {
            None
        } else {
            Some(effective_partition.as_str())
        };
        let schema = self.sink.schema(seg);

        // Map once, and read the record's own UTC day back off the
        // result -- see `ParquetSink::day_and_batch` for why this must
        // not run `to_record_batch` (or read the clock) a second time.
        let (day, pre_mapped) = match self.sink.day_and_batch(&record, &schema, now) {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(
                    source = self.sink.source(),
                    "day_and_batch failed, skipping record: {e}"
                );
                return Ok(());
            }
        };

        let effective_key = BufKey {
            partition: effective_partition,
            day,
        };

        // Lazily create the buffer for this (partition, day).
        if !self.buffers.contains_key(&effective_key) {
            self.buffers
                .insert(effective_key.clone(), PartitionBuffer::new(schema.clone()));
        }

        let buf = self.buffers.get_mut(&effective_key).unwrap();

        if buf.live_builder.is_none() {
            buf.live_builder = self.sink.new_batch(&schema);
        }

        let (n_rows, byte_delta) = if let Some(builder) = buf.live_builder.as_mut() {
            match builder.try_append(&record) {
                Ok(true) => (1usize, 0usize),
                Ok(false) => {
                    let mapped = match pre_mapped {
                        Some(b) => Ok(b),
                        None => self.sink.to_record_batch(&record, &schema),
                    };
                    match mapped {
                        Ok(b) => {
                            let est_bytes = b.get_array_memory_size();
                            let n = b.num_rows();
                            buf.buffer.push_back((b, est_bytes));
                            (n, est_bytes)
                        }
                        Err(e) => {
                            tracing::warn!(
                                source = self.sink.source(),
                                "to_record_batch failed, skipping record: {e}"
                            );
                            return Ok(());
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        source = self.sink.source(),
                        "live builder append failed, skipping record: {e}"
                    );
                    return Ok(());
                }
            }
        } else {
            let mapped = match pre_mapped {
                Some(b) => Ok(b),
                None => self.sink.to_record_batch(&record, &schema),
            };
            match mapped {
                Ok(b) => {
                    let est_bytes = b.get_array_memory_size();
                    let n = b.num_rows();
                    buf.buffer.push_back((b, est_bytes));
                    (n, est_bytes)
                }
                Err(e) => {
                    tracing::warn!(
                        source = self.sink.source(),
                        "to_record_batch failed, skipping record: {e}"
                    );
                    return Ok(());
                }
            }
        };
        self.source_stats.record(self.sink.source(), 1);

        let buf = self.buffers.get_mut(&effective_key).unwrap();
        buf.row_count += n_rows;
        buf.byte_count += byte_delta;

        if buf.live_builder.as_ref().map(|b| b.len()).unwrap_or(0) >= BUILDER_BATCH_ROWS {
            Self::materialize_live_builder(buf);
        }

        let should_flush = buf.row_count >= self.policy.max_rows
            || buf.byte_count >= self.policy.max_bytes
            || buf.last_flush.elapsed() >= self.policy.interval.get();

        if should_flush {
            self.try_flush_partition_async(&effective_key);
        }
        Ok(())
    }
```

Replace `flush_all`'s key type (`Vec<String>` -> `Vec<BufKey>`, otherwise unchanged):

```rust
    pub async fn flush_all(&mut self) -> anyhow::Result<()> {
        let keys: Vec<BufKey> = self.buffers.keys().cloned().collect();
        let mut last_err: Option<anyhow::Error> = None;
        for key in keys {
            let taken = {
                let Some(buf) = self.buffers.get_mut(&key) else {
                    continue;
                };
                Self::materialize_live_builder(buf);
                if buf.buffer.is_empty() {
                    continue;
                }
                let schema = buf.schema.clone();
                let batches = std::mem::take(&mut buf.buffer);
                let row_count = buf.row_count;
                let byte_count = buf.byte_count;
                (schema, batches, row_count, byte_count)
            };
            let (schema, batches, row_count, byte_count) = taken;

            let outcome = encode_and_upload(
                key.clone(),
                batches,
                row_count,
                byte_count,
                schema,
                self.s3.clone(),
                self.descriptor_sink.clone(),
                self.config.prefix.clone(),
                self.sink.source(),
                self.flush_semaphore.clone(),
            )
            .await;

            if let FlushOutcome::Failure {
                key,
                batches,
                row_count,
                byte_count,
                error,
            } = outcome
            {
                if let Some(buf) = self.buffers.get_mut(&key) {
                    buf.buffer = batches;
                    buf.row_count = row_count;
                    buf.byte_count = byte_count;
                }
                last_err = Some(anyhow::anyhow!(error));
            }
        }
        match last_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
```

Replace `flush_all_if_needed`'s key type the same way (`let keys: Vec<BufKey> = self.buffers.keys().cloned().collect();`, body unchanged).

Change `try_flush_partition_async`'s signature to `fn try_flush_partition_async(&mut self, key: &BufKey)` — body unchanged except `self.flush_tasks.spawn(encode_and_upload(key.clone(), ...))` (was `key.to_string()`).

Replace `apply_flush_outcome`:

```rust
    fn apply_flush_outcome(&mut self, outcome: FlushOutcome) {
        let source = self.sink.source();
        let target = self.s3.target_label();
        metrics::gauge!("parquet_s3_flushes_in_flight", "source" => source, "target" => target)
            .decrement(1.0);

        match outcome {
            FlushOutcome::Success { key } => {
                if let Some(buf) = self.buffers.get_mut(&key) {
                    buf.in_flight = false;
                }
                // A flush that lands with nothing accumulated since it
                // was kicked off (no pushes arrived while the upload was
                // in-flight) means this buffer is genuinely idle. Remove
                // it outright: with the day now part of the key, a
                // long-running process would otherwise accumulate one
                // dead buffer per partition per UTC day that ever saw
                // traffic. The next record for this (partition, day)
                // recreates it lazily in `push`, exactly like a
                // brand-new partition.
                if self
                    .buffers
                    .get(&key)
                    .map(|b| b.row_count == 0)
                    .unwrap_or(false)
                {
                    self.buffers.remove(&key);
                }
            }
            FlushOutcome::Failure {
                key,
                mut batches,
                row_count,
                byte_count,
                error,
            } => {
                tracing::warn!(source, target, "parquet_s3 writer push error: {error}");

                let Some(buf) = self.buffers.get_mut(&key) else {
                    return;
                };
                buf.in_flight = false;

                while let Some(entry) = batches.pop_back() {
                    buf.buffer.push_front(entry);
                }
                buf.row_count += row_count;
                buf.byte_count += byte_count;

                let interval = self.policy.interval.get();
                buf.last_flush = Instant::now()
                    .checked_sub(interval + std::time::Duration::from_secs(1))
                    .unwrap_or_else(Instant::now);

                let cap = self.config.max_buffer_rows.saturating_mul(4);
                if cap > 0 {
                    Self::drop_oldest_to_cap(buf, cap, source, target);
                }
            }
        }
    }
```

Replace `update_buffer_gauges` to aggregate across days per partition (preserving today's metric meaning — "rows buffered for partition X" — rather than fragmenting it by day):

```rust
    pub(crate) fn update_buffer_gauges(&self) {
        let source = self.sink.source();
        let target = self.s3.target_label();
        let mut per_partition: HashMap<&str, usize> = HashMap::new();
        for (key, buf) in &self.buffers {
            *per_partition.entry(key.partition.as_str()).or_insert(0) += buf.row_count;
        }
        for (partition, row_count) in per_partition {
            metrics::gauge!("parquet_s3_buffer_rows",
                "source" => source, "target" => target, "partition" => partition.to_string())
            .set(row_count as f64);
        }
    }
```

Add the test-only lookup helper right after `total_buffered_rows`:

```rust
    /// Test-only convenience: look up a buffer by partition alone,
    /// ignoring day. Correct wherever a test's records all map to the
    /// same UTC day -- every test in this crate does, since they run in
    /// milliseconds -- so "the buffer for this partition" is
    /// unambiguous. Production code must never use this: a real
    /// long-running writer legitimately holds one buffer per
    /// `(partition, day)`.
    #[cfg(test)]
    pub(crate) fn buffer_by_partition(&self, partition: &str) -> Option<&PartitionBuffer<S::Record>> {
        self.buffers
            .iter()
            .find(|(k, _)| k.partition == partition)
            .map(|(_, v)| v)
    }
```

Update `FlushOutcome` and `encode_and_upload`:

```rust
enum FlushOutcome {
    Success {
        key: BufKey,
    },
    Failure {
        key: BufKey,
        batches: VecDeque<(arrow_array::RecordBatch, usize)>,
        row_count: usize,
        byte_count: usize,
        error: String,
    },
}
```

```rust
#[allow(clippy::too_many_arguments)]
async fn encode_and_upload(
    key: BufKey,
    batches: VecDeque<(arrow_array::RecordBatch, usize)>,
    row_count: usize,
    byte_count: usize,
    schema: Arc<arrow_schema::Schema>,
    s3: Arc<dyn UploadSink>,
    descriptor_sink: Option<Arc<dyn UploadSink>>,
    prefix: String,
    source: &'static str,
    semaphore: Arc<tokio::sync::Semaphore>,
) -> FlushOutcome {
    let _permit = semaphore
        .acquire_owned()
        .await
        .expect("flush semaphore is never closed");

    let to_concat: Vec<arrow_array::RecordBatch> = batches.iter().map(|(b, _)| b.clone()).collect();
    let schema_for_encode = schema.clone();
    let encode_result = tokio::task::spawn_blocking(
        move || -> anyhow::Result<(Vec<u8>, parquet::format::FileMetaData)> {
            use parquet::arrow::ArrowWriter;
            use parquet::basic::{Compression, ZstdLevel};
            use parquet::file::properties::WriterProperties;

            let batch = arrow::compute::concat_batches(&schema_for_encode, &to_concat)?;
            let props = WriterProperties::builder()
                .set_compression(Compression::ZSTD(ZstdLevel::try_new(3)?))
                .build();
            let mut buf = Vec::new();
            let mut writer =
                ArrowWriter::try_new(&mut buf, schema_for_encode.clone(), Some(props))?;
            writer.write(&batch)?;
            let file_metadata = writer.close()?;
            Ok((buf, file_metadata))
        },
    )
    .await
    .map_err(|e| anyhow::anyhow!("spawn_blocking join: {e}"));

    let (merged, file_metadata) = match encode_result.and_then(|r| r) {
        Ok(pair) => pair,
        Err(e) => {
            return FlushOutcome::Failure {
                key,
                batches,
                row_count,
                byte_count,
                error: format!("{e}"),
            };
        }
    };

    let partition_seg = if key.partition.is_empty() {
        None
    } else {
        Some(key.partition.as_str())
    };
    let s3_key = build_key(&prefix, partition_seg, key.day);
    let target = s3.target_label();
    let body_len = merged.len();

    match s3.upload(&s3_key, merged).await {
        Ok(()) => {
            metrics::counter!("parquet_s3_records_written", "source" => source, "target" => target)
                .increment(row_count as u64);
            metrics::counter!("parquet_s3_uploads", "source" => source, "target" => target)
                .increment(1);

            if let Some(descriptor_sink) = descriptor_sink {
                let descriptor = build_descriptor(
                    source,
                    partition_seg,
                    s3.location_hint(),
                    &s3_key,
                    row_count as u64,
                    body_len as u64,
                    target,
                    &schema,
                    &file_metadata,
                );
                upload_descriptor(descriptor_sink, descriptor, &s3_key, source).await;
            }
            FlushOutcome::Success { key }
        }
        Err(e) => {
            metrics::counter!("parquet_s3_upload_errors", "source" => source, "target" => target)
                .increment(1);
            FlushOutcome::Failure {
                key,
                batches,
                row_count,
                byte_count,
                error: format!("{e}"),
            }
        }
    }
}
```

Note this removes Task 1's `TODO(Task 3)` shim: `build_key(&prefix, partition_seg, key.day)` replaces `build_key(&prefix, partition_seg, chrono::Utc::now().date_naive())`.

Finally, migrate every existing direct `self.buffers` / `w.buffers` / `writer.buffers` string lookup to the new helper. Apply this substitution at each of the following exact locations (old -> new; all other surrounding code is unchanged):

`src/forwarding/buffered_writer.rs`:
- `w.buffers.get("").unwrap()` (lines 1857, 1884, 2435, 2811, 2916, 3036, 3535, 3580, 3655) -> `w.buffers.get(&BufKey { partition: String::new(), day: chrono::Utc::now().date_naive() }).unwrap()` is WRONG (day must match what the test's mock actually bucketed under) -- use `w.buffer_by_partition("").unwrap()` instead, at every one of these 9 sites.
- `assert_eq!(w.buffers.get("").unwrap().row_count, 4);` (line 2079) -> `assert_eq!(w.buffer_by_partition("").unwrap().row_count, 4);`
- `w.buffers.contains_key("_overflow")` (lines 2484, 3002) -> `w.buffer_by_partition("_overflow").is_some()`
- `let ov = w.buffers.get("_overflow").unwrap();` (line 3006) -> `let ov = w.buffer_by_partition("_overflow").unwrap();`
- `assert_eq!(w.buffers.get("a").unwrap().row_count, 3);` / `w.buffers.get("b")...` (lines 2865-2866) -> `w.buffer_by_partition("a")` / `w.buffer_by_partition("b")`
- `assert_eq!(w.buffers.get("").unwrap().row_count, ...)` (lines 3111, 3686) -> `w.buffer_by_partition("").unwrap().row_count`
- `w.buffers.get("").unwrap().in_flight` (lines 3526, 3569) -> `w.buffer_by_partition("").unwrap().in_flight`

`src/forwarding/zeek_s3.rs`:
- `writer.buffers.get("conn")` (lines 548, 583, 675, 686, 713) -> `writer.buffer_by_partition("conn")`
- `writer.buffers.get("dns")` (line 553) -> `writer.buffer_by_partition("dns")`
- `writer.buffers.contains_key("_overflow")` (line 622) -> `writer.buffer_by_partition("_overflow").is_some()`
- `writer.buffers.get("_overflow").unwrap()` (line 626) -> `writer.buffer_by_partition("_overflow").unwrap()`

`src/forwarding/suricata_s3.rs`:
- `writer.buffers.get("flow")` (line 411) -> `writer.buffer_by_partition("flow")`

`src/forwarding/generic_s3.rs`:
- `writer.buffers.contains_key("_overflow")` (line 422) -> `writer.buffer_by_partition("_overflow").is_some()`

`src/forwarding/ipfix_s3.rs`:
- `writer.buffers.get("")` (line 661) -> `writer.buffer_by_partition("")`

- [ ] **Step 4: Verify pass**

Run: `cargo test --lib` (whole crate's unit tests) — Expected: all pass, including the 3 new tests from Step 1 and every migrated call site.

- [ ] **Step 5: `cargo fmt --all` and commit**

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
git add src/forwarding/buffered_writer.rs src/forwarding/zeek_s3.rs src/forwarding/suricata_s3.rs src/forwarding/generic_s3.rs src/forwarding/ipfix_s3.rs
git commit -m "$(cat <<'EOF'
feat(forwarding): key parquet buffers by (partition, day)

The core of day-clean Parquet partitions: buffers is now keyed by
BufKey{partition, day} instead of a bare partition string, so a buffer
that would have spanned midnight is now two buffers, each flushed to
its own file. Empty buffers are reaped on successful flush to avoid
accumulating one dead buffer per partition per elapsed day; a separate
known_partitions set keeps the max_partitions cap stable across both
day multiplicity and reaping.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UquMzVB7CCkD2EzadzNMA5
EOF
)"
```

---

### Task 4: Per-sink `time_column()` opt-ins

**Files:**
- Modify: `src/forwarding/zeek_s3.rs`, `src/forwarding/syslog_s3.rs`, `src/forwarding/structured_syslog_s3.rs`, `src/forwarding/generic_s3.rs`, `src/forwarding/suricata_s3.rs`, `src/forwarding/sflow_s3.rs`, `src/forwarding/ipfix_s3.rs`, `src/forwarding/parquet_s3.rs`, `src/forwarding/aggregate/mod.rs`
- Test: same 9 files (one assertion each)

**Interfaces:**
- Consumes: `ParquetSink::time_column()` default (Task 2).
- Produces: nothing new consumed by later tasks except correctness (Task 5 overrides Zeek's `day_and_batch` regardless of what `time_column()` returns for it, but it still gets the one-liner here for documentation/consistency with the other 8 sinks).

Every sink gets exactly one added method, verified against its real schema (not the spec's table blindly — see the "Spec gaps found" section above for the one row that needed correcting):

| Sink (file) | `time_column()` | Verified nullability |
|---|---|---|
| `ZeekSink` (`zeek_s3.rs`) | `"ts"` | nullable in all 7 schemas; superseded by Task 5's override |
| `SyslogSink` (`syslog_s3.rs`) | `"timestamp"` | nullable; falls back to the new `received_at` (Task 6) |
| `StructuredSyslogSink` (`structured_syslog_s3.rs`) | `"timestamp"` | nullable; already has `received_at` |
| `GenericSink` (`generic_s3.rs`) | `"time"` | nullable; already has `received_at` |
| `SuricataSink` (`suricata_s3.rs`) | `"received_at"` | non-null |
| `SflowSink` (`sflow_s3.rs`, both schemas) | `"received_at"` | non-null |
| `IpfixSink` (`ipfix_s3.rs`) | `"export_time"` | non-null |
| `WefSink` (`parquet_s3.rs`) | `"timestamp"` | non-null; populated from `record.received_at` |
| `AggregateSink` (`aggregate/mod.rs`) | `"window_start"` | non-null |

- [ ] **Step 1: Write the failing tests**

Add one test per file (shown for two representative files; apply the identical pattern — `assert_eq!(Sink.time_column(), "<expected>")` — to each of the other seven):

In `src/forwarding/zeek_s3.rs` (near the existing `build_key_produces_zeek_log_path_layout` test):

```rust
    #[test]
    fn zeek_sink_time_column_is_ts() {
        assert_eq!(ZeekSink.time_column(), "ts");
    }
```

In `src/forwarding/syslog_s3.rs` (near `schema_has_correct_columns_and_types`):

```rust
    #[test]
    fn syslog_sink_time_column_is_timestamp() {
        assert_eq!(SyslogSink.time_column(), "timestamp");
    }
```

In `src/forwarding/structured_syslog_s3.rs`:

```rust
    #[test]
    fn structured_syslog_sink_time_column_is_timestamp() {
        assert_eq!(StructuredSyslogSink.time_column(), "timestamp");
    }
```

In `src/forwarding/generic_s3.rs`:

```rust
    #[test]
    fn generic_sink_time_column_is_time() {
        assert_eq!(GenericSink.time_column(), "time");
    }
```

In `src/forwarding/suricata_s3.rs`:

```rust
    #[test]
    fn suricata_sink_time_column_is_received_at() {
        assert_eq!(SuricataSink.time_column(), "received_at");
    }
```

In `src/forwarding/sflow_s3.rs`:

```rust
    #[test]
    fn sflow_sink_time_column_is_received_at() {
        assert_eq!(SflowSink.time_column(), "received_at");
    }
```

In `src/forwarding/ipfix_s3.rs`:

```rust
    #[test]
    fn ipfix_sink_time_column_is_export_time() {
        assert_eq!(IpfixSink.time_column(), "export_time");
    }
```

In `src/forwarding/parquet_s3.rs`:

```rust
    #[test]
    fn wef_sink_time_column_is_timestamp() {
        assert_eq!(WefSink.time_column(), "timestamp");
    }
```

In `src/forwarding/aggregate/mod.rs` (`AggregateSink::new` needs a `Vec<CompiledRule>`; reuse whatever existing test helper already constructs one, e.g. a rule-less `AggregateSink::new(&[])`, since `time_column()` doesn't touch `self.schemas`):

```rust
    #[test]
    fn aggregate_sink_time_column_is_window_start() {
        let sink = AggregateSink::new(&[]);
        assert_eq!(sink.time_column(), "window_start");
    }
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cargo test time_column` — Expected: FAIL, every one of the 9 new tests gets `""` (the Task 2 default) instead of the expected column name.

- [ ] **Step 3: Implement**

Add to each `impl ParquetSink for X` block (placed after `schema()`, before `to_record_batch()`, matching the trait's declaration order):

`src/forwarding/zeek_s3.rs`:
```rust
    fn time_column(&self) -> &'static str {
        "ts"
    }
```

`src/forwarding/syslog_s3.rs`:
```rust
    fn time_column(&self) -> &'static str {
        "timestamp"
    }
```

`src/forwarding/structured_syslog_s3.rs`:
```rust
    fn time_column(&self) -> &'static str {
        "timestamp"
    }
```

`src/forwarding/generic_s3.rs`:
```rust
    fn time_column(&self) -> &'static str {
        "time"
    }
```

`src/forwarding/suricata_s3.rs`:
```rust
    fn time_column(&self) -> &'static str {
        "received_at"
    }
```

`src/forwarding/sflow_s3.rs`:
```rust
    fn time_column(&self) -> &'static str {
        "received_at"
    }
```

`src/forwarding/ipfix_s3.rs`:
```rust
    fn time_column(&self) -> &'static str {
        "export_time"
    }
```

`src/forwarding/parquet_s3.rs`:
```rust
    fn time_column(&self) -> &'static str {
        "timestamp"
    }
```

`src/forwarding/aggregate/mod.rs`:
```rust
    fn time_column(&self) -> &'static str {
        "window_start"
    }
```

- [ ] **Step 4: Verify pass**

Run: `cargo test time_column` and `cargo test --lib` — Expected: all pass.

Integration/e2e: not applicable to this task in isolation — a getter returning a static string has no observable behavior outside a unit test. Its effect (correct day bucketing per sink) is covered by Task 7's integration test and Task 8's e2e test, once every sink's `time_column()` is wired up.

- [ ] **Step 5: `cargo fmt --all` and commit**

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
git add src/forwarding/zeek_s3.rs src/forwarding/syslog_s3.rs src/forwarding/structured_syslog_s3.rs src/forwarding/generic_s3.rs src/forwarding/suricata_s3.rs src/forwarding/sflow_s3.rs src/forwarding/ipfix_s3.rs src/forwarding/parquet_s3.rs src/forwarding/aggregate/mod.rs
git commit -m "$(cat <<'EOF'
feat(forwarding): wire every sink's time_column() for day bucketing

One-line opt-in per sink, verified against each sink's actual Arrow
schema (not assumed from the design doc's table -- Zeek's ts is
nullable in all 7 schemas and needed its own fix, see Task 5).

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UquMzVB7CCkD2EzadzNMA5
EOF
)"
```

---

### Task 5: Zeek's amortized `conn` path — cheap day peek before `try_append`

**Files:**
- Modify: `src/zeek/schema.rs` (new `conn_event_day` helper), `src/forwarding/zeek_s3.rs` (`ZeekSink::day_and_batch` override)
- Test: `src/zeek/schema.rs`, `src/forwarding/zeek_s3.rs`

**Interfaces:**
- Consumes: `BufKey`/`push()` routing (Task 3), the private `json_ts_micros` helper already in `src/zeek/schema.rs`.
- Produces: `pub(crate) fn conn_event_day(fields: &serde_json::Value, now: chrono::DateTime<chrono::Utc>) -> chrono::NaiveDate`, consumed only by `ZeekSink::day_and_batch`.

`ConnAccumulator` (`src/zeek/schema.rs:302`) is the one place in the codebase that opts into `ParquetSink::new_batch`, producing multi-row batches specifically to amortize builder-allocation cost across many `conn` records. `push()` (Task 3) calls `self.sink.day_and_batch(...)` **before** it knows whether a record will go into the live builder or a plain `to_record_batch` call — so the default `day_and_batch` (Task 2), which calls `to_record_batch` once to learn the day, would call it on every `conn` record regardless of whether the live builder ends up handling it, reintroducing exactly the per-record Arrow-array-construction cost `new_batch` exists to eliminate (this is what the design doc means by "the implementer must handle this" for the amortized path). This override reads the raw JSON `ts` field directly — no Arrow batch involved — and applies to every Zeek record, not just `conn`: it is strictly cheaper than the default for all 7 schemas, since none of the other 6 stamp a fresh clock value inside their own mapper the way syslog will, so there is no "second clock read" downside to worry about for them either.

- [ ] **Step 1: Write the failing test**

In `src/zeek/schema.rs`'s `#[cfg(test)] mod tests`:

```rust
    #[test]
    fn conn_event_day_reads_ts_when_present() {
        let fields = serde_json::json!({"ts": 1700000000.0});
        let now = chrono::Utc::now();
        let day = conn_event_day(&fields, now);
        // 1700000000 (UTC) is 2023-11-14.
        assert_eq!(day, chrono::NaiveDate::from_ymd_opt(2023, 11, 14).unwrap());
    }

    #[test]
    fn conn_event_day_falls_back_to_now_when_ts_missing() {
        use chrono::TimeZone;
        let fields = serde_json::json!({"uid": "C1"});
        let now = chrono::Utc.with_ymd_and_hms(2030, 6, 15, 0, 0, 0).unwrap();
        let day = conn_event_day(&fields, now);
        assert_eq!(day, chrono::NaiveDate::from_ymd_opt(2030, 6, 15).unwrap());
    }

    #[test]
    fn conn_event_day_falls_back_to_now_when_ts_malformed() {
        use chrono::TimeZone;
        let fields = serde_json::json!({"ts": "not-a-number"});
        let now = chrono::Utc.with_ymd_and_hms(2030, 6, 15, 0, 0, 0).unwrap();
        let day = conn_event_day(&fields, now);
        assert_eq!(day, chrono::NaiveDate::from_ymd_opt(2030, 6, 15).unwrap());
    }
```

In `src/forwarding/zeek_s3.rs`'s test module:

```rust
    #[test]
    fn zeek_sink_day_and_batch_splits_conn_records_by_day() {
        use chrono::TimeZone;

        let schema = crate::zeek::schema::conn_schema();
        let day1 = ZeekRecord {
            log_path: "conn".to_string(),
            fields: serde_json::json!({"_path": "conn", "ts": 1700000000.0, "uid": "C1"}),
            received_at: chrono::Utc::now(),
        };
        let now = chrono::Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap();

        let (day, batch) = ZeekSink.day_and_batch(&day1, &schema, now).unwrap();
        assert_eq!(day, chrono::NaiveDate::from_ymd_opt(2023, 11, 14).unwrap());
        assert!(
            batch.is_none(),
            "the amortized path must not pre-build a batch just to learn the day"
        );
    }
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cargo test conn_event_day zeek_sink_day_and_batch_splits_conn_records_by_day` — Expected: FAIL to compile, `conn_event_day` doesn't exist and `ZeekSink` has no `day_and_batch` override (so the default runs and returns `Some(batch)`, failing the `is_none()` assertion once it does compile against a hand-written fallback).

- [ ] **Step 3: Implement**

In `src/zeek/schema.rs`, add near `json_ts_micros` (no visibility change needed — same module):

```rust
/// Cheap UTC-day peek for one `conn`-shaped JSON record, used by
/// `ZeekSink::day_and_batch` to route records to the correct
/// `(partition, day)` buffer WITHOUT building a `RecordBatch` -- the
/// entire point of `ConnAccumulator` is avoiding exactly that per-record
/// cost. Reuses `json_ts_micros`, the same parser `append_conn_value`
/// itself calls a moment later, so the bucketed day and the persisted
/// `ts` value (when present) can never disagree.
///
/// Falls back to `now` when `ts` is absent or fails to parse -- `conn`,
/// like every other typed Zeek schema, has no `received_at`-equivalent
/// column to fall back to first; only the envelope schema's
/// `ingest_time` plays that role, for unmodelled log paths.
pub(crate) fn conn_event_day(
    fields: &serde_json::Value,
    now: chrono::DateTime<chrono::Utc>,
) -> chrono::NaiveDate {
    json_ts_micros(fields, "ts")
        .and_then(chrono::DateTime::from_timestamp_micros)
        .map(|dt| dt.date_naive())
        .unwrap_or_else(|| now.date_naive())
}
```

In `src/forwarding/zeek_s3.rs`, add to `impl ParquetSink for ZeekSink` (after `new_batch`):

```rust
    /// Overrides the default `day_and_batch`: reads `record.fields["ts"]`
    /// directly instead of building a batch first. Applies uniformly to
    /// every Zeek log path, not just `conn` -- cheaper than the default
    /// for all 7 schemas, and the only correct option for `conn`
    /// specifically, whose amortized `ConnAccumulator` must never pay for
    /// a `to_record_batch` call it doesn't need (see the design doc's
    /// amortized-builder-path note).
    fn day_and_batch(
        &self,
        record: &ZeekRecord,
        _schema: &Arc<arrow_schema::Schema>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<(chrono::NaiveDate, Option<arrow_array::RecordBatch>)> {
        let day = crate::zeek::schema::conn_event_day(&record.fields, now);
        Ok((day, None))
    }
```

- [ ] **Step 4: Verify pass**

Run: `cargo test conn_event_day zeek_sink_day_and_batch` and `cargo bench --bench zeek_conn_batch_amortization -- --test` (compiles + smoke-runs the benchmark without a full timed run) — Expected: all pass; the benchmark still compiles against `ConnAccumulator`/`ZeekSink` unchanged (this task adds a new trait method override, it does not touch `ConnAccumulator` or `new_batch`).

- [ ] **Step 5: `cargo fmt --all` and commit**

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
git add src/zeek/schema.rs src/forwarding/zeek_s3.rs
git commit -m "$(cat <<'EOF'
fix(zeek): cheap per-record day peek for the amortized conn path

ZeekSink::day_and_batch now reads the raw JSON ts field directly,
instead of the default (build a batch, then read it back) -- avoids
reintroducing per-record Arrow allocation on the one path (conn's
ConnAccumulator) new_batch exists to make cheap. Falls back to the
push-time wall clock for any Zeek schema whose ts is null or missing,
since none of the 6 typed schemas have a stored fallback column.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UquMzVB7CCkD2EzadzNMA5
EOF
)"
```

---

### Task 6: Syslog gains a non-null `received_at` column

**Files:**
- Modify: `src/forwarding/syslog_s3.rs` (schema, `syslog_message_to_batch`)
- Test: `src/forwarding/syslog_s3.rs`

**Interfaces:**
- Consumes: `day_from_batch`'s generic `received_at` fallback (Task 2) — no new plumbing needed once this column exists.
- Produces: `syslog_schema()` now has 12 fields; `schema_version(&syslog_schema())`'s hash changes (feeds Task 9's version bump justification).

`SyslogMessage` (`src/syslog/mod.rs`) is **not** given a new field: it derives `Serialize`/`Deserialize` (a new field changes JSON forwarding output) and is consumed by `aggregate/fields.rs` and `channel_budget.rs`. Instead `received_at` is stamped with `Utc::now()` inside `syslog_message_to_batch` itself — the row-mapping boundary, called once per push from `SyslogSink::to_record_batch`, exactly mirroring `StructuredSyslogRecord::from`'s `received_at: Utc::now()` stamp at `src/syslog/payload/mod.rs:98`. `SyslogSink` does not implement `new_batch`, so there is no amortized fast path to worry about for syslog — every push already calls `to_record_batch` exactly once, so this single `Utc::now()` call is also the one `day_and_batch`'s default reads back via `day_from_batch`'s `received_at` fallback, satisfying the "never disagree" requirement without any further change.

- [ ] **Step 1: Write the failing test**

Update the existing `schema_has_correct_columns_and_types` test (~line 324) and add a nullability/value test:

```rust
    #[test]
    fn schema_has_correct_columns_and_types() {
        use arrow::datatypes::{DataType, TimeUnit};
        let schema = syslog_schema();
        assert_eq!(schema.fields().len(), 12);
        assert_eq!(
            schema.field_with_name("priority").unwrap().data_type(),
            &DataType::UInt8
        );
        assert!(!schema.field_with_name("priority").unwrap().is_nullable());
        assert_eq!(
            schema.field_with_name("timestamp").unwrap().data_type(),
            &DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
        );
        assert!(schema.field_with_name("timestamp").unwrap().is_nullable());
        assert_eq!(
            schema.field_with_name("received_at").unwrap().data_type(),
            &DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
        );
        assert!(
            !schema.field_with_name("received_at").unwrap().is_nullable(),
            "received_at must always be set -- it is the fallback day source \
             when timestamp fails to parse"
        );
        assert!(!schema.field_with_name("protocol").unwrap().is_nullable());
    }

    #[test]
    fn syslog_message_to_batch_stamps_received_at_non_null() {
        let msg = dummy_msg("no timestamp in this message");
        let batch = syslog_message_to_batch(&msg).unwrap();
        let col = batch
            .column_by_name("received_at")
            .unwrap()
            .as_any()
            .downcast_ref::<arrow::array::TimestampMicrosecondArray>()
            .unwrap();
        assert!(!col.is_null(0), "received_at must be stamped even when timestamp is None");
    }
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cargo test schema_has_correct_columns_and_types syslog_message_to_batch_stamps_received_at_non_null` — Expected: FAIL — `schema.fields().len()` is 11, and `field_with_name("received_at")` returns `Err`.

- [ ] **Step 3: Implement**

In `src/forwarding/syslog_s3.rs`, add the column to `SYSLOG_SCHEMA`:

```rust
static SYSLOG_SCHEMA: LazyLock<Arc<Schema>> = LazyLock::new(|| {
    Arc::new(Schema::new(vec![
        Field::new("priority", DataType::UInt8, false),
        Field::new("severity", DataType::UInt8, false),
        Field::new("facility", DataType::UInt8, false),
        Field::new(
            "timestamp",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            true,
        ),
        Field::new("hostname", DataType::Utf8, true),
        Field::new("app_name", DataType::Utf8, true),
        Field::new("proc_id", DataType::Utf8, true),
        Field::new("msg_id", DataType::Utf8, true),
        Field::new("message", DataType::Utf8, false),
        Field::new("structured_data", DataType::Utf8, true),
        Field::new("protocol", DataType::Utf8, false),
        Field::new(
            "received_at",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            false,
        ),
    ]))
});
```

Update `syslog_message_to_batch` to stamp and append it:

```rust
/// Map one `SyslogMessage` to a single-row `RecordBatch`.
///
/// Stamps `received_at` with `Utc::now()` here -- the row-mapping
/// boundary, called exactly once per push from `SyslogSink::to_record_batch`
/// -- mirroring `StructuredSyslogRecord::from`'s identical stamp. This is
/// deliberately NOT a field on `SyslogMessage` itself: that struct is
/// `Serialize`/`Deserialize` (a new field would change JSON forwarding
/// output) and is consumed by `aggregate/fields.rs` and `channel_budget.rs`.
pub fn syslog_message_to_batch(msg: &SyslogMessage) -> anyhow::Result<RecordBatch> {
    let schema = syslog_schema();

    let priority = Arc::new(UInt8Array::from(vec![msg.priority])) as ArrayRef;
    let severity = Arc::new(UInt8Array::from(vec![msg.severity])) as ArrayRef;
    let facility = Arc::new(UInt8Array::from(vec![msg.facility])) as ArrayRef;
    let tz: Arc<str> = Arc::from("UTC");
    let timestamp = Arc::new(
        TimestampMicrosecondArray::from(vec![msg.timestamp.map(|t| t.timestamp_micros())])
            .with_timezone(tz.clone()),
    ) as ArrayRef;
    let hostname = Arc::new(StringArray::from(vec![msg.hostname.clone()])) as ArrayRef;
    let app_name = Arc::new(StringArray::from(vec![msg.app_name.clone()])) as ArrayRef;
    let proc_id = Arc::new(StringArray::from(vec![msg.proc_id.clone()])) as ArrayRef;
    let msg_id = Arc::new(StringArray::from(vec![msg.msg_id.clone()])) as ArrayRef;
    let message = Arc::new(StringArray::from(vec![msg.message.clone()])) as ArrayRef;
    let structured_data = Arc::new(StringArray::from(vec![
        msg.structured_data
            .as_ref()
            .and_then(|sd| serde_json::to_string(sd).ok()),
    ])) as ArrayRef;
    let protocol = Arc::new(StringArray::from(vec![format!("{:?}", msg.protocol)])) as ArrayRef;
    let received_at = Arc::new(
        TimestampMicrosecondArray::from(vec![chrono::Utc::now().timestamp_micros()])
            .with_timezone(tz),
    ) as ArrayRef;

    Ok(RecordBatch::try_new(
        schema,
        vec![
            priority,
            severity,
            facility,
            timestamp,
            hostname,
            app_name,
            proc_id,
            msg_id,
            message,
            structured_data,
            protocol,
            received_at,
        ],
    )?)
}
```

Add `fn time_column(&self) -> &'static str { "timestamp" }` if not already present from Task 4 (it is — no duplicate needed here).

- [ ] **Step 4: Verify pass**

Run: `cargo test --lib syslog` and `cargo test --lib` — Expected: all pass, including every pre-existing `syslog_s3.rs` test that constructs a batch (column count / positional index changes are additive at the end, so no other assertion shifts).

Integration: extend `tests/syslog_local_integration.rs` if it asserts on schema shape — read it first; if it only asserts message content (not column count), no change needed (state this explicitly rather than guessing). If it does assert column count or names, add `"received_at"` to the expected list.

- [ ] **Step 5: `cargo fmt --all` and commit**

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
git add src/forwarding/syslog_s3.rs
git commit -m "$(cat <<'EOF'
feat(syslog): add non-null received_at column

syslog was the only sink with no received_at -- its sole time column
(timestamp) is nullable, so a row whose timestamp failed to parse had
no event day at all. received_at is stamped with Utc::now() at
row-mapping time (mirroring StructuredSyslogRecord::from), giving every
row a guaranteed, always-present partition source and bumping
schema_version() for readers pinned to the old 11-column shape.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UquMzVB7CCkD2EzadzNMA5
EOF
)"
```

---

### Task 7: Integration tests — multi-day flush, N files, retry re-split

**Files:**
- Create: `tests/day_clean_partitions_integration.rs`

**Interfaces:**
- Consumes: `zeek_local_start`/`ZeekHandler` (existing), `LocalDiskSink` (existing), the completed `BufKey`/day-bucketing machinery (Tasks 1-6).

Modeled directly on `tests/zeek_local_integration.rs` (local disk, no external service, runs unconditionally in CI). Covers the design doc's Testing section: "flush producing N files + N descriptors for a straddling buffer" and "descriptor min/max landing in the same day per file." The retry-re-splitting scenario is covered at the unit level already by Task 3's `apply_flush_outcome` (untouched control flow, just retyped) — this task adds the integration-level confirmation that two different-day pushes to the SAME partition produce two separate on-disk files, each internally consistent.

- [ ] **Step 1: Write the failing test**

```rust
//! Integration test: a Zeek `conn` stream whose records straddle a UTC
//! day boundary must produce two separate, single-day Parquet files --
//! not one file whose rows span two days. Local disk, no external
//! service, runs unconditionally in CI (see zeek_local_integration.rs).

use logthing::config::ZeekLocalConfig;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::zeek_s3::zeek_local_start;
use logthing::zeek::ZeekRecord;
use logthing::zeek::listener::ZeekHandler;
use std::sync::Arc;

fn make_conn_record(uid: &str, ts_epoch_secs: f64) -> ZeekRecord {
    ZeekRecord {
        log_path: "conn".to_string(),
        fields: serde_json::json!({
            "_path": "conn",
            "ts": ts_epoch_secs,
            "uid": uid,
            "id.orig_h": "10.0.0.1",
            "id.orig_p": 12345,
            "id.resp_h": "10.0.0.2",
            "id.resp_p": 443,
            "proto": "tcp",
            "conn_state": "SF",
        }),
        received_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn conn_records_spanning_midnight_produce_two_day_clean_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    let cfg = ZeekLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "zeek".to_string(),
        max_buffer_rows: 1, // flush immediately on every push
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 256,
    };

    let (handler, _writer_task) = zeek_local_start(
        &cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );

    let src: std::net::SocketAddr = "127.0.0.1:47761".parse().unwrap();
    // 1700000000 -> 2023-11-14 22:13:20 UTC; +7200s -> 2023-11-15.
    handler
        .handle_record(make_conn_record("CDay1", 1700000000.0), src)
        .await;
    handler
        .handle_record(make_conn_record("CDay2", 1700000000.0 + 7200.0), src)
        .await;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let day1_dir = dir.path().join("zeek/conn/year=2023/month=11/day=14");
    let day2_dir = dir.path().join("zeek/conn/year=2023/month=11/day=15");
    assert!(day1_dir.is_dir(), "expected {day1_dir:?} to exist");
    assert!(day2_dir.is_dir(), "expected {day2_dir:?} to exist");

    let day1_files: Vec<_> = std::fs::read_dir(&day1_dir).unwrap().collect();
    let day2_files: Vec<_> = std::fs::read_dir(&day2_dir).unwrap().collect();
    assert_eq!(day1_files.len(), 1, "day 1 must contain exactly one file");
    assert_eq!(day2_files.len(), 1, "day 2 must contain exactly one file");

    // Read each file back and confirm every row's ts decodes to that
    // file's own directory day -- the actual day-clean property, not
    // just "the file landed in the right directory."
    use parquet::file::reader::{FileReader, SerializedFileReader};
    for (path_entry, expected_ymd) in [
        (day1_files.into_iter().next().unwrap(), (2023, 11, 14)),
        (day2_files.into_iter().next().unwrap(), (2023, 11, 15)),
    ] {
        let path = path_entry.unwrap().path();
        let file = std::fs::File::open(&path).unwrap();
        let reader = SerializedFileReader::new(file).unwrap();
        let metadata = reader.metadata();
        for rg in 0..metadata.num_row_groups() {
            let rg_meta = metadata.row_group(rg);
            for col in 0..rg_meta.num_columns() {
                if rg_meta.column(col).column_path().string() == "ts" {
                    let stats = rg_meta.column(col).statistics().expect("ts has stats");
                    // min and max must decode to the SAME day as the
                    // directory this file lives in.
                    let (y, m, d) = expected_ymd;
                    let expected =
                        chrono::NaiveDate::from_ymd_opt(y, m, d).unwrap();
                    if let parquet::file::statistics::Statistics::Int64(s) = stats {
                        for micros in [*s.min_opt().unwrap(), *s.max_opt().unwrap()] {
                            let day = chrono::DateTime::from_timestamp_micros(micros)
                                .unwrap()
                                .date_naive();
                            assert_eq!(day, expected, "row in {path:?} is not day-clean");
                        }
                    }
                }
            }
        }
    }
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cargo test --test day_clean_partitions_integration` — Expected: FAIL before Tasks 1-6 land (single file under one directory, or the directories don't match); PASS once this plan's prior tasks are complete. If run only after Task 7 is reached in sequence (i.e., Tasks 1-6 already merged), this is a **regression-proof green test**, not a red one — run it anyway and confirm it passes, and additionally verify it via `git stash` of Tasks 3/5's core changes to confirm it goes red without them, per `superpowers:test-driven-development`'s spirit for a test added after its production code already exists in-branch.

- [ ] **Step 3: Implement**

No production code changes in this task — it is pure test coverage validating Tasks 1-6. If `parquet::file::statistics::Statistics::Int64` is not the correct variant for a `Timestamp(Microsecond, UTC)` physical type (Parquet stores timestamps as physical `INT64`), confirm via `cargo doc --open -p parquet` or a quick `dbg!(stats)` in a scratch test; adjust the `match` arm's variant name if the installed `parquet` crate version differs, but do not change the assertion's intent (both min and max must decode to the directory's own day).

- [ ] **Step 4: Verify pass**

Run: `cargo test --test day_clean_partitions_integration` — Expected: PASS.

- [ ] **Step 5: `cargo fmt --all` and commit**

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
git add tests/day_clean_partitions_integration.rs
git commit -m "$(cat <<'EOF'
test(integration): conn records spanning midnight produce 2 day-clean files

Confirms the day-clean partitions mechanism end-to-end against real
Parquet files on local disk: two conn records 2 hours apart, straddling
a UTC day boundary, land under two separate year=/month=/day= paths,
one file each, and every row's ts column-level min/max stat decodes to
that file's own directory day.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UquMzVB7CCkD2EzadzNMA5
EOF
)"
```

---

### Task 8: E2E test — ingest spanning a day boundary through a real sink

**Files:**
- Create: `tests/day_clean_partitions_e2e.rs`

**Interfaces:**
- Consumes: `syslog_local_start`, `SyslogMessage`, `SyslogHandler` (existing public API) — chosen because Task 6 makes syslog the sink most likely to regress (new column, nullable primary column, no `new_batch`).

This is the outermost-interface test the repo's test policy requires: it drives the public `SyslogHandler::handle_message` entry point (the same call path a real listener uses), not `PartitionedParquetWriter` directly, and asserts on the actual bytes written to disk.

- [ ] **Step 1: Write the failing test**

```rust
//! E2E test: syslog messages spanning a UTC day boundary, ingested
//! through the public SyslogHandler entry point (the same path a real
//! listener uses), must produce one day-clean Parquet file per day --
//! including for a message with no parseable `timestamp`, which must
//! fall back to `received_at` rather than silently landing in whichever
//! day the process happened to be in when the buffer last flushed.

use logthing::config::SyslogLocalConfig;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::syslog_s3::syslog_local_start;
use logthing::syslog::listener::SyslogHandler;
use logthing::syslog::{SyslogMessage, SyslogProtocol};
use std::sync::Arc;

fn msg_with_timestamp(text: &str, ts: chrono::DateTime<chrono::Utc>) -> SyslogMessage {
    SyslogMessage {
        priority: 13,
        severity: 5,
        facility: 1,
        timestamp: Some(ts),
        hostname: Some("host1".to_string()),
        app_name: Some("app1".to_string()),
        proc_id: None,
        msg_id: None,
        message: text.to_string(),
        structured_data: None,
        protocol: SyslogProtocol::Rfc5424,
    }
}

#[tokio::test]
async fn syslog_ingest_spanning_midnight_is_day_clean() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    let cfg = SyslogLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "syslog".to_string(),
        max_buffer_rows: 1,
        flush_interval_secs: 3600,
        channel_capacity: 256,
    };

    let (handler, _writer_task) = syslog_local_start(
        &cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );

    let src: std::net::SocketAddr = "127.0.0.1:47762".parse().unwrap();
    use chrono::TimeZone;
    let day1 = chrono::Utc.with_ymd_and_hms(2026, 3, 7, 23, 59, 0).unwrap();
    let day2 = chrono::Utc.with_ymd_and_hms(2026, 3, 8, 0, 1, 0).unwrap();

    handler
        .handle_message(msg_with_timestamp("before midnight", day1), src)
        .await;
    handler
        .handle_message(msg_with_timestamp("after midnight", day2), src)
        .await;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let day1_dir = dir.path().join("syslog/year=2026/month=03/day=07");
    let day2_dir = dir.path().join("syslog/year=2026/month=03/day=08");
    assert!(day1_dir.is_dir(), "expected {day1_dir:?} to exist");
    assert!(day2_dir.is_dir(), "expected {day2_dir:?} to exist");
    assert_eq!(std::fs::read_dir(&day1_dir).unwrap().count(), 1);
    assert_eq!(std::fs::read_dir(&day2_dir).unwrap().count(), 1);
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cargo test --test day_clean_partitions_e2e` — Expected: FAIL before Task 3 lands (`day1_dir`/`day2_dir` don't both exist — both messages land under whatever single day the flush's `Utc::now()` produced).

- [ ] **Step 3: Implement**

No production code changes — validates Tasks 1-6 end-to-end via the public ingest API.

- [ ] **Step 4: Verify pass**

Run: `cargo test --test day_clean_partitions_e2e` — Expected: PASS.

- [ ] **Step 5: `cargo fmt --all` and commit**

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
git add tests/day_clean_partitions_e2e.rs
git commit -m "$(cat <<'EOF'
test(e2e): syslog ingest spanning midnight is day-clean

Drives the public SyslogHandler entry point end-to-end (not the writer
internals) with two messages either side of a UTC day boundary and
confirms two separate, single-day output directories on disk.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UquMzVB7CCkD2EzadzNMA5
EOF
)"
```

---

### Task 9: Version bump to 0.16.0

**Files:**
- Modify: `Cargo.toml`, `Cargo.lock`

**Interfaces:**
- Consumes: nothing (final task).

Syslog's schema gained a column (Task 6), changing `schema_version()`'s hash for that sink — breaking for any reader pinned to the old 11-column shape. Repo convention in 0.x is a MINOR bump for a breaking change.

- [ ] **Step 1: Write the failing test**

Not applicable — a version string has no unit/integration/e2e test surface in this repo (no test asserts on `Cargo.toml`'s version). Stated explicitly per this plan's testing policy rather than skipped silently.

- [ ] **Step 2: Run it, verify it fails**

Not applicable, per Step 1.

- [ ] **Step 3: Implement**

In `Cargo.toml`:

```toml
version = "0.16.0"
```

Then sync the lockfile without touching the network:

```bash
cargo update -p logthing --offline
```

- [ ] **Step 4: Verify pass**

Run: `cargo check --all-targets` — Expected: builds clean; `git diff Cargo.lock` shows only `logthing`'s own version bump (no dependency version changes).

- [ ] **Step 5: `cargo fmt --all` and commit**

```bash
cargo fmt --all
git add Cargo.toml Cargo.lock
git commit -m "$(cat <<'EOF'
chore: bump version to 0.16.0

Syslog's Parquet schema gained a non-null received_at column (day-clean
Parquet partitions work), changing schema_version() for that sink --
breaking for any reader pinned to the old 11-column shape. MINOR bump
per repo convention for a breaking change in 0.x.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UquMzVB7CCkD2EzadzNMA5
EOF
)"
```

---

## Self-review

**Spec section -> task coverage:**
- "Mechanism: day as part of the buffer key" -> Task 3 (`BufKey`).
- "Deriving the day" / `time_column()` seam -> Task 2 (seam + `day_from_batch`), Task 4 (per-sink opt-ins).
- "Amortized-builder path" -> Task 5 (`ZeekSink::day_and_batch` override).
- "Key stamping" (`build_key` takes the day) -> Task 1.
- "Memory" / "Empty day-buffers must be reaped" -> Task 3 (`apply_flush_outcome` reaping + `known_partitions`).
- "Syslog `received_at`" -> Task 6.
- "Per-sink partition column" table -> Task 4 (with the Zeek correction from "Spec gaps found" item 1).
- "Accepted costs" (backfill fan-out, per-push extraction, more live buffers) -> inherent consequences of Task 3's design; no dedicated task needed, called out in Task 3's doc comments.
- "Out of scope" (Iceberg catalog writing, hour granularity, materialized date column) -> untouched by this plan, consistent with every task above.
- Testing section (unit / integration / e2e) -> unit tests embedded in Tasks 1-6; Task 7 (integration) and Task 8 (e2e) cover the multi-file-flush and full-ingest-path requirements respectively; retry-re-split is covered at the unit level in Task 3 (`apply_flush_outcome`'s control flow is unchanged, only retyped, and Task 3's existing failure-path tests continue to exercise it against `BufKey`).

**Placeholder scan:** no task contains "TBD," "similar to Task N" without an accompanying real diff, or "add appropriate error handling" — every step either shows the literal code or explicitly states why a step is not applicable (Task 4's integration/e2e note, Task 9's test steps).

**Type/signature consistency check:**
- `build_key(prefix: &str, partition: Option<&str>, day: chrono::NaiveDate) -> String` — introduced Task 1, consumed identically in Task 3's `encode_and_upload`.
- `BufKey { partition: String, day: chrono::NaiveDate }` — introduced Task 3, field names (`partition`, `day`) used identically in Tasks 3, 5 (via `push`'s routing, not directly), 7/8 (indirectly, via directory layout).
- `ParquetSink::time_column(&self) -> &'static str` — default in Task 2, overridden with matching signature in Task 4 (9 sinks) with no drift.
- `ParquetSink::day_and_batch(&self, record: &Self::Record, schema: &Arc<arrow_schema::Schema>, now: chrono::DateTime<chrono::Utc>) -> anyhow::Result<(chrono::NaiveDate, Option<arrow_array::RecordBatch>)>` — default in Task 2, overridden with an identical signature in Task 5 for `ZeekSink`.
- `day_from_batch(batch: &arrow_array::RecordBatch, time_col: &str, now: chrono::DateTime<chrono::Utc>) -> chrono::NaiveDate` — introduced and only consumed in Task 2's default `day_and_batch`.
- `buffer_by_partition(&self, partition: &str) -> Option<&PartitionBuffer<S::Record>>` — introduced Task 3, consumed with identical call shape in Task 3's own migrated tests (no other task calls it, since it is `#[cfg(test)]`-only).
