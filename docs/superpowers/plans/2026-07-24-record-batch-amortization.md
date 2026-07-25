# Amortized Record-Batch Builders Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Amortize Arrow builder-allocation cost across multiple records instead of paying it per-record, for Zeek's "conn" log type specifically, without changing hard-cap/backpressure/flush-timing behavior for any existing sink.

**Architecture:** An additive, opt-in trait method on `ParquetSink` (`new_batch`, default `None`) lets an adapter provide a reusable, persistent Arrow-builder set (`RecordBatchAccumulator`) instead of allocating fresh builders every `push()`. The generic writer's `PartitionBuffer` becomes generic and gains an optional live-builder slot; a single `materialize_live_builder` helper — called defensively from every code path that reads the partition's buffer for a flush or hard-cap decision — finishes accumulated rows into a real, storable `RecordBatch` at the right moments. Only `ZeekSink`'s "conn" mapper opts in this cycle; every other adapter is provably unaffected.

**Tech Stack:** Rust, `arrow`/`arrow-array`/`arrow-schema`, tokio.

**Full design rationale:** `docs/superpowers/specs/2026-07-24-record-batch-amortization-design.md` — read it before starting. This plan assumes its decisions (they are not re-litigated here). In particular, re-read its "Materialization: the load-bearing decision" section before Task 3 — three rounds of independent review converged on the exact call sites this plan's Task 3 patches, after two rounds each found a different real bug in an earlier version of this design.

## Global Constraints

- Do not touch anything outside this cycle's scope: the trait/`PartitionBuffer`/materialization infra in `src/forwarding/buffered_writer.rs`, plus converting exactly `ZeekSink`'s `map_conn` mapper. Zeek's other 5 typed mappers, the envelope fallback, and the other 6 `ParquetSink` adapters are explicitly out of scope — do not convert them.
- 6 of the 7 `ParquetSink` implementors (suricata, sflow, ipfix, syslog, structured_syslog, generic/HEC, wef) must require **zero** code changes and must remain provably behavior-identical (the new code path is structurally unreachable for them since none override `new_batch`).
- `row_count` must be incremented exactly once per accepted record, immediately, regardless of which of the three paths (accepted into live builder / rejected and falls back / adapter never opted in) a record takes. `byte_count` is only incremented immediately for the fallback/non-opted-in paths; for the accepted-into-live-builder path it is deferred to materialization time (a deliberate, bounded, documented trade-off — do not "fix" this by adding a per-record byte estimate).
- `BUILDER_BATCH_ROWS = 1000`, a private hardcoded constant — not new TOML config.
- `finish()` on `RecordBatchAccumulator` takes `&mut self` (not `Box<Self>`) — reuses the same builders across the partition's whole lifetime, matching Arrow's own idiomatic `*Builder::finish(&mut self)` signature.
- The two existing pinned regression tests, `push_enforces_hard_cap_on_flush_failure` (`buffered_writer.rs:1829-1846`) and `writer_bounded_under_s3_outage` (`zeek_s3.rs:530-546`), must be run **completely unmodified** at the end of every task from Task 3 onward and must continue to pass.
- No new external crate dependencies.

---

## Task 1: Trait scaffolding + generic `PartitionBuffer` (no wiring yet)

**Files:**
- Modify: `src/forwarding/buffered_writer.rs`

**Interfaces:**
- Produces: `pub trait RecordBatchAccumulator<Record>: Send { fn try_append(&mut self, record: &Record) -> anyhow::Result<bool>; fn len(&self) -> usize; fn finish(&mut self) -> anyhow::Result<arrow_array::RecordBatch>; }`, `ParquetSink::new_batch(&self, schema: &Arc<arrow_schema::Schema>) -> Option<Box<dyn RecordBatchAccumulator<Self::Record>>>` (default `None`), `PartitionBuffer<R>` (generic, new `live_builder: Option<Box<dyn RecordBatchAccumulator<R>>>` field), `fn materialize_live_builder(buf: &mut PartitionBuffer<S::Record>)` (defined, not yet called from anywhere).

This task only adds new, unreferenced surface area and changes `PartitionBuffer`'s type from concrete to generic — every existing behavior must be provably unchanged after this task (nothing new is wired in yet).

- [ ] **Step 1: Add the `RecordBatchAccumulator` trait**

In `src/forwarding/buffered_writer.rs`, immediately after the closing `}` of the `ParquetSink` trait (currently ending at line 87, right before the `FlushPolicy` section comment at line 89), add:

```rust
/// Amortized builder state for one in-progress, possibly-multi-row
/// `RecordBatch`. An adapter that wants to amortize builder-allocation
/// cost across multiple records implements this and returns it from
/// `ParquetSink::new_batch`.
pub trait RecordBatchAccumulator<Record>: Send {
    /// Try to append one record. Returns `Ok(false)` if this record does
    /// not belong to this accumulator's schema (mirrors whatever
    /// per-record schema-mismatch fallback the adapter's `to_record_batch`
    /// already performs) -- the caller must then fall back to
    /// `to_record_batch` for just this one record.
    fn try_append(&mut self, record: &Record) -> anyhow::Result<bool>;

    /// Rows appended so far, not yet finished into a `RecordBatch`.
    fn len(&self) -> usize;

    /// Finish the currently-accumulated rows into one `RecordBatch` and
    /// reset internal builder state to empty, ready to accumulate the
    /// next batch without reallocating.
    fn finish(&mut self) -> anyhow::Result<arrow_array::RecordBatch>;
}
```

- [ ] **Step 2: Add the `new_batch` default method to `ParquetSink`**

In the same file, inside the `ParquetSink` trait definition (currently lines 63-87), immediately after the existing `to_record_batch` method (the trait's last method, ending right before the trait's closing `}` at line 87), add:

```rust

    /// Optional amortized-builder fast path. Returns `None` (the default)
    /// to opt out and keep the exact one-`to_record_batch()`-call-per-push
    /// behavior -- existing adapters need no code change to keep working
    /// exactly as before, and are provably unaffected since this code path
    /// is structurally unreachable for them.
    fn new_batch(
        &self,
        schema: &Arc<arrow_schema::Schema>,
    ) -> Option<Box<dyn RecordBatchAccumulator<Self::Record>>> {
        let _ = schema;
        None
    }
```

- [ ] **Step 3: Make `PartitionBuffer` generic**

Replace the current `PartitionBuffer` struct (lines 261-272) and its `impl` block (lines 274-286):

```rust
pub(crate) struct PartitionBuffer<R> {
    pub(crate) schema: Arc<arrow_schema::Schema>,
    pub(crate) buffer: VecDeque<(arrow_array::RecordBatch, usize)>, // (batch, est_bytes)
    pub(crate) row_count: usize,
    pub(crate) byte_count: usize,
    pub(crate) last_flush: Instant,
    pub(crate) last_drop_warn: Option<Instant>,
    /// True while a background flush task owns this partition's previously
    /// buffered data. At most one flush is ever in-flight per partition —
    /// see `try_flush_partition_async`.
    pub(crate) in_flight: bool,
    /// Live, in-progress amortized builder for this partition. `None` for
    /// every adapter that doesn't opt in (`ParquetSink::new_batch` returns
    /// `None`), and `None` even for an opted-in adapter until its first
    /// record lands.
    pub(crate) live_builder: Option<Box<dyn RecordBatchAccumulator<R>>>,
}

impl<R> PartitionBuffer<R> {
    fn new(schema: Arc<arrow_schema::Schema>) -> Self {
        Self {
            schema,
            buffer: VecDeque::new(),
            row_count: 0,
            byte_count: 0,
            last_flush: Instant::now(),
            last_drop_warn: None,
            in_flight: false,
            live_builder: None,
        }
    }
}
```

- [ ] **Step 4: Update `PartitionedParquetWriter<S>`'s `buffers` field type**

Find `pub(crate) buffers: HashMap<String, PartitionBuffer>,` inside the `PartitionedParquetWriter<S>` struct definition and change it to:

```rust
    pub(crate) buffers: HashMap<String, PartitionBuffer<S::Record>>,
```

- [ ] **Step 5: Update `drop_oldest_to_cap`'s signature**

Find `fn drop_oldest_to_cap(buf: &mut PartitionBuffer, cap: usize, source: &'static str, target: &'static str) {` (currently line 711) and change the parameter type:

```rust
    fn drop_oldest_to_cap(
        buf: &mut PartitionBuffer<S::Record>,
        cap: usize,
        source: &'static str,
        target: &'static str,
    ) {
```

Do not change the function body in this step — that happens in Task 3.

- [ ] **Step 6: Add the (not-yet-called) `materialize_live_builder` helper**

Immediately after `drop_oldest_to_cap`'s closing `}` (the end of that function, currently around line 745, right before the closing `}` of the `impl<S: ParquetSink> PartitionedParquetWriter<S>` block), add:

```rust

    /// Finish the partition's live builder (if any, and if it has
    /// accumulated at least one row) into a real, stored `RecordBatch`
    /// entry, exactly as if that many single-row batches had been pushed
    /// via the non-amortized path. Called defensively from every code path
    /// that reads or takes `buf.buffer` for a flush or hard-cap decision --
    /// see the design doc's materialization audit table for the full list
    /// of call sites and why each one needs this.
    fn materialize_live_builder(buf: &mut PartitionBuffer<S::Record>) {
        if let Some(builder) = buf.live_builder.as_mut()
            && builder.len() > 0
        {
            match builder.finish() {
                Ok(batch) => {
                    let est_bytes = batch.get_array_memory_size();
                    buf.byte_count += est_bytes;
                    buf.buffer.push_back((batch, est_bytes));
                }
                Err(e) => {
                    // Should not happen in practice (finishing
                    // already-validated builder state into Arrow arrays is
                    // not a fallible runtime operation under normal
                    // conditions). Log and leave the builder as-is; the
                    // next materialize attempt will retry.
                    tracing::error!("parquet_s3: live builder finish() failed: {e}");
                }
            }
        }
    }
```

Note: this method is not called from anywhere yet (that starts in Task 2/3) — it will trigger an `unused function` warning if `cargo build` runs with strict dead-code lints on a partial commit. That's expected and fine for this task's commit; Task 2 wires its first caller.

- [ ] **Step 7: Fix the one direct `PartitionBuffer` construction in tests, if needed**

Run: `cargo build --lib 2>&1 | grep -A5 "buffered_writer.rs:2147"` (or the current line of `let mut buf = PartitionBuffer::new(schema.clone());` inside `drop_oldest_to_cap_byte_count_stays_consistent` — find it via `grep -n "PartitionBuffer::new" src/forwarding/buffered_writer.rs` if the line number has shifted).

Expected: this most likely compiles unmodified — Rust should infer `R = String` for `buf`'s type from the later, single, unambiguous `PartitionedParquetWriter::<MockSink>::drop_oldest_to_cap(&mut buf, 5, "test", "test")` call in the same function body. If it does NOT compile (a genuine type-inference ambiguity error naming this line), add an explicit turbofish: change `PartitionBuffer::new(schema.clone())` to `PartitionBuffer::<String>::new(schema.clone())`.

- [ ] **Step 8: Add a trivial default-value regression test**

Add to `src/forwarding/buffered_writer.rs`'s `#[cfg(test)] mod tests`, near `MockSink`'s definition:

```rust
    #[test]
    fn new_batch_defaults_to_none_for_mock_sink() {
        assert!(
            MockSink.new_batch(&test_schema()).is_none(),
            "MockSink does not override new_batch, so it must default to None"
        );
    }
```

- [ ] **Step 9: Build and run the full existing test suite to confirm zero behavior change**

Run: `cargo build --lib`
Expected: clean build (aside from the expected unused-function warning on `materialize_live_builder` from Step 6 — acceptable for this task).

Run: `cargo test --lib forwarding::buffered_writer`
Expected: every existing test passes, unmodified, plus the new `new_batch_defaults_to_none_for_mock_sink` test passes. This proves the generic-`PartitionBuffer` conversion is behavior-preserving on its own, before any new logic is wired in.

- [ ] **Step 10: Commit**

```bash
git add src/forwarding/buffered_writer.rs
git commit -m "feat(forwarding): add RecordBatchAccumulator trait and generic PartitionBuffer (unwired)"
```

---

## Task 2: Wire the accept/reject/fallback branch into `push()`, with threshold materialization

**Depends on:** Task 1.

**Files:**
- Modify: `src/forwarding/buffered_writer.rs`

**Interfaces:**
- Consumes: `RecordBatchAccumulator<Record>` (Task 1), `PartitionBuffer<R>.live_builder` (Task 1), `materialize_live_builder` (Task 1, gets its first caller here).
- Produces: `const BUILDER_BATCH_ROWS: usize = 1000;`. `push()`'s new branching logic (accept / reject-and-fallback / not-opted-in).

This task introduces a test-only accumulator (`MockAccumulator`/`AmortizingMockSink`) to prove the generic mechanism works correctly BEFORE the more complex real `ZeekSink` conversion (Task 4) — this isolates any bug in the generic machinery from any bug in the Zeek-specific mapping logic.

- [ ] **Step 1: Add the `BUILDER_BATCH_ROWS` constant**

Immediately after `const MAX_CONCURRENT_FLUSHES_PER_WRITER: usize = 4;` (currently around line 328), add:

```rust

/// Row-count threshold at which a partition's live (in-progress) amortized
/// builder is force-materialized into a real, stored `RecordBatch` entry,
/// independent of any flush. Bounds two things: the maximum size of a
/// single amortization unit, and the maximum number of rows that can be
/// "invisible" to `drop_oldest_to_cap`'s hard-cap enforcement at any given
/// instant (small relative to the default hard cap of
/// `max_buffer_rows.saturating_mul(4)` = 400,000 at the 100,000-row
/// default). See the design doc's "BUILDER_BATCH_ROWS" section.
const BUILDER_BATCH_ROWS: usize = 1000;
```

- [ ] **Step 2: Write the failing test — value flows through the amortized path**

Add to `src/forwarding/buffered_writer.rs`'s `#[cfg(test)] mod tests`, after `MockSink`'s definition (currently ending around line 1361) and before `unreachable_s3` (currently around line 1363):

```rust
    // -----------------------------------------------------------------------
    // Amortized-builder tests (generic mechanism, proven with a trivial
    // test-only accumulator before the real ZeekSink conversion)
    // -----------------------------------------------------------------------

    struct MockAccumulator {
        builder: StringBuilder,
        rows: usize,
    }

    impl MockAccumulator {
        fn new() -> Self {
            Self {
                builder: StringBuilder::new(),
                rows: 0,
            }
        }
    }

    impl RecordBatchAccumulator<String> for MockAccumulator {
        fn try_append(&mut self, record: &String) -> anyhow::Result<bool> {
            self.builder.append_value(record);
            self.rows += 1;
            Ok(true)
        }
        fn len(&self) -> usize {
            self.rows
        }
        fn finish(&mut self) -> anyhow::Result<RecordBatch> {
            let col: Arc<dyn arrow::array::Array> = Arc::new(self.builder.finish());
            self.rows = 0;
            Ok(RecordBatch::try_new(test_schema(), vec![col])?)
        }
    }

    struct AmortizingMockSink;
    impl ParquetSink for AmortizingMockSink {
        type Record = String;
        fn source(&self) -> &'static str {
            "test"
        }
        fn partition(&self, _r: &String) -> Option<String> {
            None
        }
        fn schema(&self, _p: Option<&str>) -> Arc<Schema> {
            test_schema()
        }
        fn to_record_batch(
            &self,
            record: &String,
            schema: &Arc<Schema>,
        ) -> anyhow::Result<RecordBatch> {
            let col = Arc::new(StringArray::from(vec![record.as_str()]));
            Ok(RecordBatch::try_new(schema.clone(), vec![col])?)
        }
        fn new_batch(&self, _schema: &Arc<Schema>) -> Option<Box<dyn RecordBatchAccumulator<String>>> {
            Some(Box::new(MockAccumulator::new()))
        }
    }

    #[tokio::test]
    async fn push_accepts_records_into_the_live_builder() {
        let s3 = unreachable_s3().await;
        let (cfg, policy) = test_config(1_000_000); // nothing flushes
        let mut w = PartitionedParquetWriter::new(AmortizingMockSink, s3, cfg, policy);

        for i in 0..5 {
            w.push(format!("r{i}")).await.unwrap();
        }

        let buf = w.buffers.get("").unwrap();
        assert_eq!(buf.row_count, 5, "row_count must reflect all 5 accepted records");
        assert_eq!(
            buf.buffer.len(),
            0,
            "below BUILDER_BATCH_ROWS and no flush yet, nothing should be materialized into buf.buffer"
        );
        assert_eq!(
            buf.live_builder.as_ref().map(|b| b.len()),
            Some(5),
            "all 5 records should be sitting in the live builder"
        );
    }
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test --lib forwarding::buffered_writer::tests::push_accepts_records_into_the_live_builder -- --nocapture`
Expected: FAIL — `push()` doesn't yet call `new_batch`/`try_append` at all, so every record goes through the existing `to_record_batch` fallback path; `buf.live_builder` stays `None` and `buf.buffer.len()` would be 5, not 0.

- [ ] **Step 4: Rewrite `push()`'s record-conversion section**

Find `push()` (currently lines 416-480). Replace the block from `// Convert record → RecordBatch.` (currently line 448) through the line `buf.byte_count += est_bytes;` (currently line 469) — i.e. everything between the schema-lazy-creation block above it and the `// Check flush policy.` comment below it — with:

```rust
        // Convert record → RecordBatch, using the amortized live-builder
        // path if the sink opted in for this partition's schema, else the
        // unchanged one-call-per-record fallback.
        let buf = self.buffers.get_mut(&effective_key).unwrap();
        let schema = buf.schema.clone();

        if buf.live_builder.is_none() {
            buf.live_builder = self.sink.new_batch(&schema);
        }

        let (n_rows, byte_delta) = if let Some(builder) = buf.live_builder.as_mut() {
            match builder.try_append(&record) {
                Ok(true) => {
                    // Accepted into the live builder. row_count is exact and
                    // immediate; byte_count is deliberately deferred to
                    // materialization time (see design doc §5).
                    (1usize, 0usize)
                }
                Ok(false) => {
                    // Rejected: this record doesn't match the accumulator's
                    // schema (e.g. Zeek's raw/sanitized log_path mismatch
                    // case). Fall back to today's exact per-record path for
                    // just this one record.
                    match self.sink.to_record_batch(&record, &schema) {
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
            // Adapter never opted in for this schema: unchanged behavior.
            match self.sink.to_record_batch(&record, &schema) {
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

        // Bound the live builder's own size independent of any flush, so
        // drop_oldest_to_cap always has fine-enough-grained entries to trim
        // under sustained backpressure (see design doc §3).
        if buf
            .live_builder
            .as_ref()
            .map(|b| b.len())
            .unwrap_or(0)
            >= BUILDER_BATCH_ROWS
        {
            Self::materialize_live_builder(buf);
        }
```

Leave the rest of `push()` (the `// Check flush policy.` block and everything after) completely unchanged — it already reads `buf.row_count`/`buf.byte_count`, which are correctly updated above.

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test --lib forwarding::buffered_writer::tests::push_accepts_records_into_the_live_builder`
Expected: PASS.

- [ ] **Step 6: Write and run the threshold-materialization test**

Add to the same test module:

```rust
    #[tokio::test]
    async fn push_materializes_at_the_builder_batch_rows_threshold() {
        let s3 = unreachable_s3().await;
        let (cfg, policy) = test_config(1_000_000); // nothing flushes on row/byte count
        let mut w = PartitionedParquetWriter::new(AmortizingMockSink, s3, cfg, policy);

        for i in 0..(BUILDER_BATCH_ROWS + 1) {
            w.push(format!("r{i}")).await.unwrap();
        }

        let buf = w.buffers.get("").unwrap();
        assert_eq!(
            buf.row_count,
            BUILDER_BATCH_ROWS + 1,
            "row_count must reflect every accepted record"
        );
        assert_eq!(
            buf.buffer.len(),
            1,
            "crossing the threshold must materialize exactly one stored batch"
        );
        assert_eq!(
            buf.buffer.front().map(|(b, _)| b.num_rows()),
            Some(BUILDER_BATCH_ROWS),
            "the materialized batch must contain exactly BUILDER_BATCH_ROWS rows"
        );
        assert_eq!(
            buf.live_builder.as_ref().map(|b| b.len()),
            Some(1),
            "the one record past the threshold must remain in the live builder"
        );
    }
```

Run: `cargo test --lib forwarding::buffered_writer::tests::push_materializes_at_the_builder_batch_rows_threshold`
Expected: PASS (this test is written after the Step 4 implementation exists, so no separate RED phase is needed here — Step 3's RED already proved the underlying mechanism was unimplemented; this test targets a more specific behavior of the same implementation).

- [ ] **Step 7: Run the full existing test suite to confirm no regression**

Run: `cargo test --lib forwarding::buffered_writer`
Expected: all pass, including every pre-existing test (push_accumulates_below_row_threshold, push_enforces_hard_cap_on_flush_failure, flushes_in_flight_gauge_tracks_a_single_flush, update_buffer_gauges_reports_live_row_counts, etc.) plus the 3 new tests from this task (including Step 8's from Task 1).

- [ ] **Step 8: Commit**

```bash
git add src/forwarding/buffered_writer.rs
git commit -m "feat(forwarding): wire amortized-builder accept/reject/fallback branch into push()"
```

---

## Task 3: Defense-in-depth materialization at every flush/cap decision point

**Depends on:** Task 2.

**Files:**
- Modify: `src/forwarding/buffered_writer.rs`

**Interfaces:**
- Consumes: `materialize_live_builder` (Task 1), `AmortizingMockSink`/`MockAccumulator` (Task 2, reused here).

This is the task three rounds of design review focused on. Read the design doc's materialization audit table before starting. Every step below patches exactly one of the four gaps that review found; do not skip any.

- [ ] **Step 1: Write the failing test — flush must include pending live-builder rows**

Add to the test module:

```rust
    #[tokio::test]
    async fn flush_materializes_pending_live_builder_rows() {
        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink: Arc<dyn UploadSink> = Arc::new(RecordingSink {
            uploads: uploads.clone(),
        });
        let (cfg, policy) = test_config(3); // flush once row_count >= 3
        let mut w = PartitionedParquetWriter::new(AmortizingMockSink, sink, cfg, policy);

        // 3 records accepted into the live builder, none materialized yet
        // (below BUILDER_BATCH_ROWS), but should_flush fires on the 3rd push.
        for i in 0..3 {
            w.push(format!("r{i}")).await.unwrap();
        }
        w.drain_pending_flushes().await;

        let recorded = uploads.lock().unwrap();
        assert_eq!(
            recorded.len(),
            1,
            "the flush must have actually uploaded, proving the live builder's \
             pending rows were materialized before the buffer was taken"
        );
        assert!(recorded[0].1 > 0, "uploaded body must be non-empty");
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib forwarding::buffered_writer::tests::flush_materializes_pending_live_builder_rows -- --nocapture`
Expected: FAIL — `try_flush_partition_async`'s `if buf.buffer.is_empty() { return; }` check (before any materialization exists) sees an empty `buf.buffer` (all 3 rows are sitting unmaterialized in the live builder) and returns without spawning a flush at all, so `uploads` stays empty.

- [ ] **Step 3: Fix 1 — `drop_oldest_to_cap` self-materializes**

Find `drop_oldest_to_cap`'s body (starts right after the signature from Task 1 Step 5). Add the materialize call as the very first line of the function body, before `let mut dropped = 0usize;`:

```rust
    ) {
        Self::materialize_live_builder(buf);
        let mut dropped = 0usize;
```

- [ ] **Step 4: Fix 2 — `try_flush_partition_async` materializes unconditionally at the top**

Find `try_flush_partition_async` (currently starting at line 571). Its current body begins:

```rust
    fn try_flush_partition_async(&mut self, key: &str) {
        let in_flight = self.buffers.get(key).map(|b| b.in_flight).unwrap_or(false);
        let source = self.sink.source();
        let target = self.s3.target_label();
```

Change it to:

```rust
    fn try_flush_partition_async(&mut self, key: &str) {
        if let Some(buf) = self.buffers.get_mut(key) {
            Self::materialize_live_builder(buf);
        }

        let in_flight = self.buffers.get(key).map(|b| b.in_flight).unwrap_or(false);
        let source = self.sink.source();
        let target = self.s3.target_label();
```

Leave the rest of the function (the `in_flight` branch, and the normal take-buffer branch below it) unchanged — both now see a fully up-to-date `buf.buffer`.

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test --lib forwarding::buffered_writer::tests::flush_materializes_pending_live_builder_rows`
Expected: PASS.

- [ ] **Step 6: Write and verify the shutdown-materialization test**

Add to the test module:

```rust
    #[tokio::test]
    async fn flush_all_materializes_pending_live_builder_rows_at_shutdown() {
        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink: Arc<dyn UploadSink> = Arc::new(RecordingSink {
            uploads: uploads.clone(),
        });
        let (cfg, policy) = test_config(1_000_000); // nothing flushes on its own
        let mut w = PartitionedParquetWriter::new(AmortizingMockSink, sink, cfg, policy);

        for i in 0..3 {
            w.push(format!("r{i}")).await.unwrap();
        }
        // Nothing should have flushed yet -- all 3 rows sit in the live builder.
        assert!(uploads.lock().unwrap().is_empty());

        w.flush_all().await.unwrap();

        let recorded = uploads.lock().unwrap();
        assert_eq!(
            recorded.len(),
            1,
            "flush_all (graceful shutdown) must not silently drop rows sitting \
             in an unmaterialized live builder"
        );
    }
```

Run: `cargo test --lib forwarding::buffered_writer::tests::flush_all_materializes_pending_live_builder_rows_at_shutdown -- --nocapture`
Expected: FAILs before Step 7's fix, PASSes after.

- [ ] **Step 7: Fix 3 — `flush_all` materializes before its own emptiness check**

Find `flush_all` (currently lines 487-540). Its inner loop currently begins:

```rust
            let taken = {
                let Some(buf) = self.buffers.get_mut(&key) else {
                    continue;
                };
                if buf.buffer.is_empty() {
                    continue;
                }
```

Change it to:

```rust
            let taken = {
                let Some(buf) = self.buffers.get_mut(&key) else {
                    continue;
                };
                Self::materialize_live_builder(buf);
                if buf.buffer.is_empty() {
                    continue;
                }
```

- [ ] **Step 8: Run the shutdown test again to verify it passes**

Run: `cargo test --lib forwarding::buffered_writer::tests::flush_all_materializes_pending_live_builder_rows_at_shutdown`
Expected: PASS.

- [ ] **Step 9: Write and verify the ticker-gate test**

Add to the test module:

```rust
    #[tokio::test]
    async fn flush_all_if_needed_flushes_a_partition_whose_only_pending_data_is_in_the_live_builder() {
        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink: Arc<dyn UploadSink> = Arc::new(RecordingSink {
            uploads: uploads.clone(),
        });
        // max_rows=2 so 3 pushes trip the row-count flush trigger, but
        // nothing crosses BUILDER_BATCH_ROWS, so buf.buffer stays empty
        // (everything is in the live builder) until flush_all_if_needed runs.
        let (cfg, policy) = test_config(2);
        let mut w = PartitionedParquetWriter::new(AmortizingMockSink, sink, cfg, policy);

        for i in 0..3 {
            w.push(format!("r{i}")).await.unwrap();
        }
        w.flush_all_if_needed().await.unwrap();
        w.drain_pending_flushes().await;

        let recorded = uploads.lock().unwrap();
        assert_eq!(
            recorded.len(),
            1,
            "flush_all_if_needed must detect a pending flush even when buf.buffer \
             (as opposed to row_count) is empty"
        );
    }
```

Run: `cargo test --lib forwarding::buffered_writer::tests::flush_all_if_needed_flushes_a_partition_whose_only_pending_data_is_in_the_live_builder -- --nocapture`
Expected: FAILs before Step 10's fix (note: `push()`'s own `should_flush` check already calls `try_flush_partition_async` when row_count crosses `max_rows`, which by Step 4's fix already materializes and flushes — so this specific test as written may already pass after Steps 3-8. If it passes immediately, that's fine; it still documents and locks in the property. If you want a test that discriminates specifically the `flush_all_if_needed` gate fix below, additionally construct one with `test_config` using a `policy.interval` (age-based trigger) short enough to fire only via the ticker path with `max_rows` set high enough that `push()`'s own inline check never fires — use `Duration::from_millis(1)` for `policy.interval` and `max_rows = 1_000_000` in a second variant of this test if the first doesn't discriminate; implementer's judgment call on which version actually proves the fix, but do not skip proving it).

- [ ] **Step 10: Fix 4 — `flush_all_if_needed`'s gate uses `row_count` instead of `buffer.is_empty()`**

Find `flush_all_if_needed` (currently lines 543-561). Its inner `should_flush` computation currently reads:

```rust
            let should_flush = {
                let buf = self.buffers.get(&key).unwrap();
                if buf.buffer.is_empty() {
                    false
                } else {
                    buf.row_count >= self.policy.max_rows
                        || buf.byte_count >= self.policy.max_bytes
                        || buf.last_flush.elapsed() >= self.policy.interval.get()
                }
            };
```

Change the guard condition:

```rust
            let should_flush = {
                let buf = self.buffers.get(&key).unwrap();
                if buf.row_count == 0 {
                    false
                } else {
                    buf.row_count >= self.policy.max_rows
                        || buf.byte_count >= self.policy.max_bytes
                        || buf.last_flush.elapsed() >= self.policy.interval.get()
                }
            };
```

- [ ] **Step 11: Run the ticker-gate test again to verify it passes**

Run: `cargo test --lib forwarding::buffered_writer::tests::flush_all_if_needed_flushes_a_partition_whose_only_pending_data_is_in_the_live_builder`
Expected: PASS.

- [ ] **Step 12: Write and verify the in-flight/backpressure hard-cap test — the scenario 3 review rounds focused on**

Add to the test module, reusing the existing `BlockingSink` fixture (already defined later in the file for `second_threshold_crossing_while_in_flight_hard_caps_instead_of_double_flushing` — if `BlockingSink` is defined AFTER this new test in the file, either move this new test to right after that existing test, or duplicate a minimal blocking sink locally; check the file before writing to place this correctly):

```rust
    #[tokio::test]
    async fn in_flight_flush_still_hard_caps_rows_accumulating_in_the_live_builder() {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let sink: Arc<dyn UploadSink> = Arc::new(BlockingSink { gate: gate.clone() });
        let max_rows = 1usize;
        let (cfg, policy) = test_config(max_rows);
        let hard_cap = max_rows.saturating_mul(4); // 4
        let mut w = PartitionedParquetWriter::new(AmortizingMockSink, sink, cfg, policy);

        // First push triggers a flush that blocks forever until `gate` fires.
        w.push("r0".to_string()).await.unwrap();
        assert!(w.buffers.get("").unwrap().in_flight);

        // Push far more than hard_cap while the first flush is stuck
        // in-flight, WITHOUT draining -- every one of these accumulates in
        // the live builder (below BUILDER_BATCH_ROWS), which is exactly the
        // scenario that would leave drop_oldest_to_cap with nothing
        // poppable if materialize_live_builder weren't wired into it.
        for i in 1..(hard_cap * 3) {
            w.push(format!("r{i}")).await.unwrap();
        }

        let buf = w.buffers.get("").unwrap();
        assert!(
            buf.row_count <= hard_cap,
            "row_count {} must be capped at {} even while rows are accumulating \
             in the live builder during an in-flight flush",
            buf.row_count,
            hard_cap
        );

        gate.add_permits(1);
        w.drain_pending_flushes().await;
    }
```

Run: `cargo test --lib forwarding::buffered_writer::tests::in_flight_flush_still_hard_caps_rows_accumulating_in_the_live_builder -- --nocapture`
Expected: PASS after Step 3's fix (this test exercises exactly the `drop_oldest_to_cap` self-materialize fix from Step 3; if it fails, Step 3's fix is incomplete — do not proceed until this passes).

- [ ] **Step 13: Re-run both pinned regression tests, completely unmodified**

Run: `cargo test --lib forwarding::buffered_writer::tests::push_enforces_hard_cap_on_flush_failure`
Run: `cargo test --test zeek_s3 writer_bounded_under_s3_outage` (adjust the exact invocation to however this project runs a single test in `zeek_s3.rs`'s module — e.g. `cargo test --lib forwarding::zeek_s3::tests::writer_bounded_under_s3_outage` if it's an inline `#[cfg(test)] mod tests`; confirm the module path via `grep -n "mod tests" src/forwarding/zeek_s3.rs` if unsure)
Expected: both PASS, unmodified, exactly as before this task's changes — `push_enforces_hard_cap_on_flush_failure` is moot (MockSink never opts in), `writer_bounded_under_s3_outage` genuinely exercises the fixed code paths once Task 4 converts `ZeekSink`.

- [ ] **Step 14: Run the full existing test suite**

Run: `cargo test --lib forwarding::buffered_writer`
Expected: all pass — every pre-existing test plus every new test from Tasks 1-3.

- [ ] **Step 15: Commit**

```bash
git add src/forwarding/buffered_writer.rs
git commit -m "fix(forwarding): materialize live builder at every flush/hard-cap decision point"
```

---

## Task 4: Convert `ZeekSink`'s `map_conn` to the amortized pattern

**Depends on:** Task 3.

**Files:**
- Modify: `src/zeek/schema.rs` (new `ConnAccumulator` struct; `map_conn` becomes a thin wrapper around it)
- Modify: `src/forwarding/zeek_s3.rs` (`ZeekSink::new_batch` implementation)

**Interfaces:**
- Consumes: `RecordBatchAccumulator<ZeekRecord>` (Task 1), `conn_schema()` (existing, `src/zeek/schema.rs:31-53`), `get_schema_entry` (existing, `src/zeek/schema.rs:1018-1028`).
- Produces: `pub(crate) struct ConnAccumulator` implementing `RecordBatchAccumulator<crate::zeek::ZeekRecord>`.

- [ ] **Step 1: Write the failing value-equivalence test**

Add to `src/zeek/schema.rs`'s `#[cfg(test)] mod tests` (find it via `grep -n "mod tests" src/zeek/schema.rs`):

```rust
    #[test]
    fn conn_accumulator_matches_map_conn_output_row_for_row() {
        let records: Vec<serde_json::Value> = (0..5)
            .map(|i| {
                serde_json::json!({
                    "ts": 1700000000.0 + i as f64,
                    "uid": format!("C{i}"),
                    "id.orig_h": "10.0.0.1",
                    "id.orig_p": 12345u16 + i as u16,
                    "id.resp_h": "10.0.0.2",
                    "id.resp_p": 443u16,
                    "proto": "tcp",
                    "duration": 1.5,
                    "orig_bytes": 100u64 + i as u64,
                    "resp_bytes": 200u64,
                    "conn_state": "SF",
                    "orig_pkts": 3u64,
                    "resp_pkts": 4u64,
                })
            })
            .collect();

        // Baseline: today's exact per-record path, N single-row batches concatenated.
        let single_row_batches: Vec<RecordBatch> = records
            .iter()
            .map(|v| map_conn(v).unwrap())
            .collect();
        let expected = arrow::compute::concat_batches(&conn_schema(), &single_row_batches).unwrap();

        // Amortized path: one accumulator, N appends, one finish.
        let mut acc = ConnAccumulator::new();
        for v in &records {
            assert!(acc.try_append_value(v).unwrap());
        }
        let actual = acc.finish().unwrap();

        assert_eq!(actual.num_rows(), expected.num_rows());
        assert_eq!(actual.schema(), expected.schema());
        for col_idx in 0..expected.num_columns() {
            assert_eq!(
                format!("{:?}", actual.column(col_idx)),
                format!("{:?}", expected.column(col_idx)),
                "column {col_idx} differs between amortized and per-record paths"
            );
        }
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib zeek::schema::tests::conn_accumulator_matches_map_conn_output_row_for_row`
Expected: FAIL with a compile error (`ConnAccumulator` does not exist yet).

- [ ] **Step 3: Implement `ConnAccumulator`, and make `map_conn` delegate to it**

In `src/zeek/schema.rs`, replace the current `map_conn` function (currently lines 240-381) with:

```rust
/// Amortized builder set for the "conn" schema. Holds the same 16 Arrow
/// builders `map_conn` used to create fresh on every call, as persistent
/// fields, so they can be reused across many records via `finish(&mut
/// self)` instead of reallocated per record or per batch.
pub(crate) struct ConnAccumulator {
    b_ts: Float64Builder,
    b_uid: StringBuilder,
    b_id_orig_h: StringBuilder,
    b_id_orig_p: UInt16Builder,
    b_id_resp_h: StringBuilder,
    b_id_resp_p: UInt16Builder,
    b_proto: StringBuilder,
    b_service: StringBuilder,
    b_duration: Float64Builder,
    b_orig_bytes: UInt64Builder,
    b_resp_bytes: UInt64Builder,
    b_conn_state: StringBuilder,
    b_history: StringBuilder,
    b_orig_pkts: UInt64Builder,
    b_resp_pkts: UInt64Builder,
    b_extra: StringBuilder,
    rows: usize,
}

impl ConnAccumulator {
    pub(crate) fn new() -> Self {
        Self {
            b_ts: Float64Builder::new(),
            b_uid: StringBuilder::new(),
            b_id_orig_h: StringBuilder::new(),
            b_id_orig_p: UInt16Builder::new(),
            b_id_resp_h: StringBuilder::new(),
            b_id_resp_p: UInt16Builder::new(),
            b_proto: StringBuilder::new(),
            b_service: StringBuilder::new(),
            b_duration: Float64Builder::new(),
            b_orig_bytes: UInt64Builder::new(),
            b_resp_bytes: UInt64Builder::new(),
            b_conn_state: StringBuilder::new(),
            b_history: StringBuilder::new(),
            b_orig_pkts: UInt64Builder::new(),
            b_resp_pkts: UInt64Builder::new(),
            b_extra: StringBuilder::new(),
            rows: 0,
        }
    }

    /// Append one already-parsed JSON `value` (the `conn` fields object).
    /// Shared by both the amortized path (`RecordBatchAccumulator::try_append`)
    /// and `map_conn`'s single-record fallback wrapper below -- identical
    /// extraction/mismatch-detection/`_extra`-building logic either way.
    fn append_conn_value(&mut self, value: &serde_json::Value) {
        let promoted = &[
            "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
            "duration", "orig_bytes", "resp_bytes", "conn_state", "history", "orig_pkts",
            "resp_pkts",
        ];
        let mut mismatches: Vec<&str> = Vec::new();

        let ts = json_f64(value, "ts");
        if value.get("ts").is_some() && ts.is_none() {
            mismatches.push("ts");
        }
        let uid = json_str(value, "uid");
        if value.get("uid").is_some() && uid.is_none() {
            mismatches.push("uid");
        }
        let id_orig_h = json_str(value, "id.orig_h");
        if value.get("id.orig_h").is_some() && id_orig_h.is_none() {
            mismatches.push("id.orig_h");
        }
        let id_orig_p = json_u16(value, "id.orig_p");
        if value.get("id.orig_p").is_some() && id_orig_p.is_none() {
            mismatches.push("id.orig_p");
        }
        let id_resp_h = json_str(value, "id.resp_h");
        if value.get("id.resp_h").is_some() && id_resp_h.is_none() {
            mismatches.push("id.resp_h");
        }
        let id_resp_p = json_u16(value, "id.resp_p");
        if value.get("id.resp_p").is_some() && id_resp_p.is_none() {
            mismatches.push("id.resp_p");
        }
        let proto = json_str(value, "proto");
        if value.get("proto").is_some() && proto.is_none() {
            mismatches.push("proto");
        }
        let service = json_str(value, "service");
        if value.get("service").is_some() && service.is_none() {
            mismatches.push("service");
        }
        let duration = json_f64(value, "duration");
        if value.get("duration").is_some() && duration.is_none() {
            mismatches.push("duration");
        }
        let orig_bytes = json_u64(value, "orig_bytes");
        if value.get("orig_bytes").is_some() && orig_bytes.is_none() {
            mismatches.push("orig_bytes");
        }
        let resp_bytes = json_u64(value, "resp_bytes");
        if value.get("resp_bytes").is_some() && resp_bytes.is_none() {
            mismatches.push("resp_bytes");
        }
        let conn_state = json_str(value, "conn_state");
        if value.get("conn_state").is_some() && conn_state.is_none() {
            mismatches.push("conn_state");
        }
        let history = json_str(value, "history");
        if value.get("history").is_some() && history.is_none() {
            mismatches.push("history");
        }
        let orig_pkts = json_u64(value, "orig_pkts");
        if value.get("orig_pkts").is_some() && orig_pkts.is_none() {
            mismatches.push("orig_pkts");
        }
        let resp_pkts = json_u64(value, "resp_pkts");
        if value.get("resp_pkts").is_some() && resp_pkts.is_none() {
            mismatches.push("resp_pkts");
        }

        let extra = build_extra(value, promoted, &mismatches);

        self.b_ts.append_option(ts);
        self.b_uid.append_option(uid.as_deref());
        self.b_id_orig_h.append_option(id_orig_h.as_deref());
        self.b_id_orig_p.append_option(id_orig_p);
        self.b_id_resp_h.append_option(id_resp_h.as_deref());
        self.b_id_resp_p.append_option(id_resp_p);
        self.b_proto.append_option(proto.as_deref());
        self.b_service.append_option(service.as_deref());
        self.b_duration.append_option(duration);
        self.b_orig_bytes.append_option(orig_bytes);
        self.b_resp_bytes.append_option(resp_bytes);
        self.b_conn_state.append_option(conn_state.as_deref());
        self.b_history.append_option(history.as_deref());
        self.b_orig_pkts.append_option(orig_pkts);
        self.b_resp_pkts.append_option(resp_pkts);
        self.b_extra.append_value(&extra);
        self.rows += 1;
    }

    /// Test/internal helper: append a raw JSON value directly (bypassing
    /// the `ZeekRecord`-level schema-match check `try_append` performs).
    /// Used by `map_conn`'s wrapper (which is only ever invoked once the
    /// caller has already confirmed this is a conn record) and by unit
    /// tests that construct raw JSON fixtures.
    fn try_append_value(&mut self, value: &serde_json::Value) -> anyhow::Result<bool> {
        self.append_conn_value(value);
        Ok(true)
    }

    fn finish_batch(&mut self) -> anyhow::Result<RecordBatch> {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(self.b_ts.finish()),
            Arc::new(self.b_uid.finish()),
            Arc::new(self.b_id_orig_h.finish()),
            Arc::new(self.b_id_orig_p.finish()),
            Arc::new(self.b_id_resp_h.finish()),
            Arc::new(self.b_id_resp_p.finish()),
            Arc::new(self.b_proto.finish()),
            Arc::new(self.b_service.finish()),
            Arc::new(self.b_duration.finish()),
            Arc::new(self.b_orig_bytes.finish()),
            Arc::new(self.b_resp_bytes.finish()),
            Arc::new(self.b_conn_state.finish()),
            Arc::new(self.b_history.finish()),
            Arc::new(self.b_orig_pkts.finish()),
            Arc::new(self.b_resp_pkts.finish()),
            Arc::new(self.b_extra.finish()),
        ];
        self.rows = 0;
        Ok(RecordBatch::try_new(conn_schema(), columns)?)
    }
}

impl crate::forwarding::buffered_writer::RecordBatchAccumulator<crate::zeek::ZeekRecord> for ConnAccumulator {
    fn try_append(&mut self, record: &crate::zeek::ZeekRecord) -> anyhow::Result<bool> {
        // Mirror to_record_batch's existing per-record fallback check: only
        // accept a record whose RAW log_path resolves (via the registry) to
        // exactly the conn schema. A mismatch (e.g. raw "Conn" vs the
        // sanitized "conn" partition) must fall back to to_record_batch for
        // just this one record, exactly as today.
        let entry = get_schema_entry(&record.log_path);
        if !Arc::ptr_eq(&entry.schema, &conn_schema()) {
            return Ok(false);
        }
        self.append_conn_value(&record.fields);
        Ok(true)
    }

    fn len(&self) -> usize {
        self.rows
    }

    fn finish(&mut self) -> anyhow::Result<RecordBatch> {
        self.finish_batch()
    }
}

fn map_conn(value: &serde_json::Value) -> anyhow::Result<RecordBatch> {
    let mut acc = ConnAccumulator::new();
    acc.append_conn_value(value);
    acc.finish_batch()
}
```

Note: `get_schema_entry("conn").schema` and `conn_schema()` are both backed by the same `LazyLock` singleton and are used via `Arc::ptr_eq` here for the identical reason `ZeekSink::new_batch` uses it (Step 4 below) — verify this still compiles and passes; if `entry.schema` is somehow a different `Arc` instance with equal content but different pointer for the exact "conn" case (it should not be, per the registry's construction, but verify), fall back to structural `entry.schema == conn_schema()` instead and note this in the commit message as a deviation from the design doc.

- [ ] **Step 4: Run the value-equivalence test to verify it passes**

Run: `cargo test --lib zeek::schema::tests::conn_accumulator_matches_map_conn_output_row_for_row`
Expected: PASS.

- [ ] **Step 5: Write and verify a `map_conn`-still-works test (regression for the wrapper)**

Add to the same test module (this may already exist as a pre-existing test for `map_conn` — check via `grep -n "fn map_conn\|map_conn(" src/zeek/schema.rs`'s test section first; if an equivalent test already exists, just confirm it still passes rather than duplicating it):

```rust
    #[test]
    fn map_conn_still_produces_a_single_row_batch() {
        let v = serde_json::json!({"ts": 1700000000.0, "uid": "C1", "proto": "tcp"});
        let batch = map_conn(&v).unwrap();
        assert_eq!(batch.num_rows(), 1);
        assert_eq!(batch.schema(), conn_schema());
    }
```

Run: `cargo test --lib zeek::schema::tests::map_conn_still_produces_a_single_row_batch`
Expected: PASS.

- [ ] **Step 6: Wire `ZeekSink::new_batch`**

In `src/forwarding/zeek_s3.rs`, inside the `impl ParquetSink for ZeekSink` block (currently lines 66-134), immediately after the closing `}` of `to_record_batch` (currently line 133) and before the `impl` block's own closing `}` (currently line 134), add:

```rust

    fn new_batch(
        &self,
        schema: &Arc<arrow_schema::Schema>,
    ) -> Option<Box<dyn crate::forwarding::buffered_writer::RecordBatchAccumulator<ZeekRecord>>> {
        if Arc::ptr_eq(schema, &crate::zeek::schema::conn_schema()) {
            Some(Box::new(crate::zeek::schema::ConnAccumulator::new()))
        } else {
            None
        }
    }
```

Check whether `ConnAccumulator` needs to be exported from `src/zeek/schema.rs` (it's declared `pub(crate)` in Step 3, which should already be visible to `zeek_s3.rs` within the same crate — verify with `cargo build --lib` rather than assuming).

- [ ] **Step 7: Write and verify the try_append-rejects-and-falls-back test**

Add to `src/forwarding/zeek_s3.rs`'s `#[cfg(test)] mod tests`:

```rust
    #[tokio::test]
    async fn mismatched_raw_log_path_falls_back_to_envelope_not_conn_accumulator() {
        let sink = unreachable_sink().await;
        let (bwc, policy) = make_zeek_cfg(100_000, usize::MAX, 256);
        let mut writer = PartitionedParquetWriter::new(ZeekSink, sink, bwc, policy);

        // Raw log_path "Conn" (mixed case) sanitizes to partition "conn"
        // (ZeekSink::new_batch will offer a ConnAccumulator for that
        // partition's schema), but the raw-path registry lookup inside
        // ConnAccumulator::try_append is case-sensitive and misses -- this
        // record must be rejected and fall back to the envelope mapper,
        // exactly as to_record_batch's pre-existing fallback already does.
        let rec = ZeekRecord {
            log_path: "Conn".to_string(),
            fields: serde_json::json!({"_path": "Conn", "ts": 1700000000.0, "uid": "C1"}),
            received_at: Utc::now(),
        };
        writer.push(rec).await.unwrap();

        let buf = writer.buffers.get("conn").unwrap();
        assert_eq!(
            buf.row_count, 1,
            "the record must still be counted, just via the fallback path"
        );
        assert!(
            buf.live_builder.as_ref().map(|b| b.len()).unwrap_or(0) == 0,
            "the mismatched record must NOT have been accepted into the conn live builder"
        );
        assert_eq!(
            buf.buffer.len(),
            1,
            "the rejected record's fallback batch must be pushed directly onto buf.buffer"
        );
    }
```

Run: `cargo test --lib forwarding::zeek_s3::tests::mismatched_raw_log_path_falls_back_to_envelope_not_conn_accumulator -- --nocapture`
Expected: PASS. If it fails, check: (a) whether `ZeekRecord` has exactly these fields (`log_path`, `fields`, `received_at`) — adjust the test fixture to match the real struct definition if not (check via `grep -n "struct ZeekRecord" -A 10 src/zeek/mod.rs` or wherever it's defined); (b) whether the buffer's schema for partition "conn" really is `envelope_schema()` in this mismatch scenario (per `ZeekSink::schema()`'s existing logic, only `_overflow`/`None` map to envelope — re-verify against the design doc's §6 reasoning that the PARTITION's schema is `conn_schema()` regardless of the raw-path mismatch, since `partition()` uses the sanitized path; the assertion above checks `buf.row_count`/`live_builder`/`buffer.len()`, not the batch's actual schema content, so this should hold regardless).

- [ ] **Step 8: Re-run both pinned regression tests, completely unmodified**

Run: `cargo test --lib forwarding::buffered_writer::tests::push_enforces_hard_cap_on_flush_failure`
Run: `cargo test --lib forwarding::zeek_s3::tests::writer_bounded_under_s3_outage` (adjust invocation to the real module path if different)
Expected: both PASS, unmodified. `writer_bounded_under_s3_outage` now genuinely exercises `ConnAccumulator` via the real `ZeekSink` — this is the test the whole 3-round design review was ultimately protecting.

- [ ] **Step 9: Run every existing Zeek-related test**

Run: `cargo test --lib zeek`
Run: `cargo test --lib forwarding::zeek_s3`
Expected: all pass, including `writer_accumulates_per_partition_buffers`, `writer_partition_cap_overflows_to_overflow_buffer`, and every schema/mapper test in `src/zeek/schema.rs`.

- [ ] **Step 10: Commit**

```bash
git add src/zeek/schema.rs src/forwarding/zeek_s3.rs
git commit -m "feat(zeek): convert map_conn to the amortized ConnAccumulator pattern"
```

---

## Task 5: Integration and e2e verification

**Depends on:** Task 4.

**Files:**
- Modify (if a gap is found): `tests/zeek_local_integration.rs` or `tests/zeek_s3_integration.rs`
- No changes expected to `tests/zeek_flush_decoupling_e2e.rs` (verification only)

- [ ] **Step 1: Run the existing Zeek integration tests**

Run: `cargo test --test zeek_local_integration`
Run: `cargo test --test zeek_s3_integration`
Expected: all pass unmodified — these push real conn records through the real pipeline (now exercising `ConnAccumulator`) and assert on the resulting Parquet file(s)' row count and field values.

- [ ] **Step 2: Assess whether a burst-sized integration test already exists**

Run: `grep -n "fn.*conn\|_path.*conn" tests/zeek_local_integration.rs tests/zeek_s3_integration.rs`

If an existing integration test already pushes more than `BUILDER_BATCH_ROWS` (1000) conn records and verifies the resulting Parquet output's row count and a few field values, no new test is needed — proceed to Step 4. If no existing integration test pushes a burst this large, add one.

- [ ] **Step 3: If needed, add a burst integration test**

Follow the existing pattern in `tests/zeek_local_integration.rs` (read it first to match its exact setup/teardown style — real `ZeekListener`, real `ZeekSink`, real `LocalDiskSink`, real `parquet::arrow::arrow_reader` verification). Add a test that pushes 1500 conn records (crossing the `BUILDER_BATCH_ROWS` threshold at least once, and triggering at least one real flush) through the real pipeline, then reads back the resulting Parquet file(s) via `parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder` and asserts: total row count across all files == 1500, and a spot-check of a few known field values (e.g. `uid` values for records 0, 500, 1499) match what was sent.

- [ ] **Step 4: Run the existing Zeek e2e test**

Run: `cargo test --test zeek_flush_decoupling_e2e`
Expected: passes unmodified — it exercises `ZeekSink` for real over a live TCP connection, now exercising `ConnAccumulator` automatically.

- [ ] **Step 5: Commit (only if Step 3 added a new test)**

```bash
git add tests/zeek_local_integration.rs  # or whichever file was modified
git commit -m "test(zeek): add burst integration test crossing BUILDER_BATCH_ROWS"
```

If Step 3 found existing coverage sufficient and made no changes, skip this commit — there is nothing to commit for this task.

---

## Task 6: Benchmark before/after and results write-up

**Depends on:** Task 5.

**Files:**
- Create: `docs/superpowers/specs/2026-07-24-record-batch-amortization-benchmark-results.md`

- [ ] **Step 1: Capture a "before" baseline on `master` (pre-this-branch)**

Run, from a separate check of the `master` branch's state (do not switch this working tree's branch — either use `git worktree add /tmp/rb-baseline master` for a clean read-only checkout, or note that Task 0-era baseline numbers from the prior "do next items" work, in `docs/superpowers/specs/2026-07-24-benchmark-results-baseline.md`, already establish `master`'s pre-this-change realistic/stress throughput and can be reused directly instead of re-capturing — prefer reusing the existing baseline doc if its git commit hash is a genuine ancestor of this branch and its benchmark flags match what Step 2 below uses):

```bash
cargo build --release --example flush_decoupling_benchmark
cargo run --release --example flush_decoupling_benchmark -- mode=realistic duration_secs=30 target_rate=4000 upload_delay_ms=150
```

Record the output (or the reused baseline doc's equivalent figures).

- [ ] **Step 2: Capture "after" numbers on this branch**

```bash
cargo run --release --example flush_decoupling_benchmark -- mode=realistic duration_secs=30 target_rate=4000 upload_delay_ms=150
cargo run --release --example flush_decoupling_benchmark -- mode=realistic duration_secs=30 target_rate=4000 upload_delay_ms=150
cargo run --release --example flush_decoupling_benchmark -- mode=stress duration_secs=30 target_rate=4000 upload_delay_ms=150
```

Run `realistic` mode twice for a basic noise-floor sense (matching this repo's established convention from the prior "do next items" benchmarking work), `stress` once (this mode's hard-cap-triggered drop behavior is a config-size question, not a per-record-cost question, so a single confirmatory run suffices here).

- [ ] **Step 3: Write the results doc**

Create `docs/superpowers/specs/2026-07-24-record-batch-amortization-benchmark-results.md` containing: the exact commands run, the git commit hashes for "before" and "after", the full output of every run, and an honest comparison — specifically call out the delta in overall records/sec throughput and (if the benchmark harness reports it) any per-record timing figure, stating plainly whether the measured improvement is large, small, or within noise. Do not overstate: if the improvement is smaller than the run-to-run variance visible across the two "realistic" runs, say so explicitly rather than claiming a specific percentage.

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/specs/2026-07-24-record-batch-amortization-benchmark-results.md
git commit -m "docs: benchmark results for amortized ConnAccumulator (plan item 2.1)"
```

---

## Self-Review Notes

- **Spec coverage:** every section of the design doc maps to a task — additive trait (Task 1), `PartitionBuffer` genericization (Task 1), row/byte accounting discipline (Task 2), the 4-gap materialization audit (Task 3, one sub-step per gap), per-record rejection (Task 4), `ConnAccumulator`/`map_conn` unification (Task 4), testing tiers (Tasks 2-6), benchmark evidence (Task 6). Deferred scope (other Zeek mappers, other 6 adapters, criterion harness, configurable threshold) is explicitly not tasked, per the design doc.
- **Type/name consistency:** `RecordBatchAccumulator<Record>` (Task 1) is the same trait name/shape referenced in Task 2's `AmortizingMockSink`/`MockAccumulator` and Task 4's `ConnAccumulator`. `materialize_live_builder` (Task 1, defined once) is called from `push()` (Task 2), `drop_oldest_to_cap`, `try_flush_partition_async`, and `flush_all` (all Task 3) — same signature throughout. `BUILDER_BATCH_ROWS` (Task 2) is referenced by name in Task 3's threshold-adjacent reasoning and Task 5's burst-test sizing.
- **No placeholders:** every step above contains complete, concrete code or exact commands — the two spots with implementer judgment calls (Task 3 Step 9's possible second test variant, Task 4 Step 3's `Arc::ptr_eq` vs structural-equality fallback) are flagged explicitly as judgment calls with a concrete fallback given, not left as "figure it out."
