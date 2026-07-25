# Design: Amortized Record-Batch Builders (Plan Item 2.1)

**Date:** 2026-07-24
**Status:** Approved (auto-develop coherence review, 3 rounds — rounds 1-2 found and fixed 4 real correctness gaps against existing hard-cap/backpressure tests)
**Source:** `docs/superpowers/specs/2026-07-24-performance-improvements-plan.md` §2.1 ("Batch multiple records per `RecordBatch` instead of one-row-per-batch"), tier "worth doing eventually (needs its own design spec first)".
**Prerequisite reading:** `docs/superpowers/specs/2026-06-23-generic-buffered-writer-design.md` (the writer's original design; its line 66 explicitly anticipated this exact optimization as future work: *"An adapter may batch multiple records per `RecordBatch` later as an optimization, but single-row batches preserve current behavior and are the baseline."*)

## Scope

**This cycle (foundational sub-project):**
1. Generic amortized-builder infrastructure in `src/forwarding/buffered_writer.rs` — an additive, opt-in trait method on `ParquetSink`, a generic `PartitionBuffer`, and materialization logic wired into every code path that reads the partition buffer for a flush or hard-cap decision.
2. Converting exactly Zeek's `map_conn` mapper (`src/zeek/schema.rs`) to the new pattern, as the reference/proof implementation.

**Explicitly deferred, not built this cycle (noted per the auto-develop skill's scope-decomposition guidance):**
- Zeek's other 5 typed log mappers (dns/http/ssl/files/notice) and the envelope fallback — mechanical repetition of the proven `ConnAccumulator` pattern once this lands.
- The other 6 `ParquetSink` adapters (suricata, sflow, ipfix, syslog, structured_syslog, generic/HEC, wef) — same mechanical repetition.
- The standalone `criterion` microbenchmark harness (source plan's item 2.6 in full) — a separate, still-unbuilt infrastructure project; this design substitutes the existing `examples/flush_decoupling_benchmark.rs` for before/after evidence instead.
- Making the batching threshold operator-configurable via TOML.

## Why this is safe: two pinned regression tests

The source plan named two existing tests that must not silently break, since they pin down hard-cap/backpressure behavior:
- `push_enforces_hard_cap_on_flush_failure` (`buffered_writer.rs:1829-1846`) — uses `MockSink`, which never opts into the new path (`live_builder` stays `None` throughout), so it is structurally unaffected by this change.
- `writer_bounded_under_s3_outage` (`zeek_s3.rs:530-546`) — uses the real `ZeekSink`, `max_rows=2`, `hard_cap=8`, drains after every push against an unreachable S3 endpoint. This test DOES exercise the new amortized path once `ZeekSink` converts, and the design below was iterated three times specifically to keep it passing (see "Materialization: the load-bearing decision" below).

## Architecture

### 1. Additive trait method (zero changes required for 6 of 7 adapters)

```rust
pub trait ParquetSink: Send + Sync + 'static {
    // ...all four existing methods unchanged (source, partition, schema, to_record_batch)...

    /// Optional amortized-builder fast path. Returns `None` (the default)
    /// to opt out and keep today's exact one-`to_record_batch()`-call-per-
    /// push behavior — existing adapters need no code change to keep
    /// working exactly as before, and are provably unaffected since the
    /// new code path is structurally unreachable for them.
    fn new_batch(&self, schema: &Arc<arrow_schema::Schema>)
        -> Option<Box<dyn RecordBatchAccumulator<Self::Record>>> {
        None
    }
}

/// Amortized builder state for one in-progress, possibly-multi-row
/// RecordBatch. An adapter that wants the fast path implements this.
pub trait RecordBatchAccumulator<Record>: Send {
    /// Try to append one record. Returns `Ok(false)` if this record does
    /// not belong to this accumulator's schema (mirrors whatever
    /// per-record schema-mismatch fallback the adapter's `to_record_batch`
    /// already performs — see "Per-record rejection" below) — the caller
    /// must then fall back to `to_record_batch` for just this one record.
    fn try_append(&mut self, record: &Record) -> anyhow::Result<bool>;

    /// Rows appended so far, not yet finished into a RecordBatch.
    fn len(&self) -> usize;

    /// Finish the currently-accumulated rows into one RecordBatch and
    /// reset internal builder state to empty, ready to accumulate the
    /// next batch WITHOUT reallocating (`&mut self`, not consuming —
    /// matches Arrow's own idiomatic `*Builder::finish(&mut self)`
    /// signature, already used identically in today's `map_conn`). This
    /// lets the same builder set be reused across the partition's entire
    /// lifetime, not just within one accumulation window.
    fn finish(&mut self) -> anyhow::Result<arrow_array::RecordBatch>;
}
```

### 2. `PartitionBuffer` becomes generic

```rust
pub(crate) struct PartitionBuffer<R> {
    pub(crate) schema: Arc<arrow_schema::Schema>,
    pub(crate) buffer: VecDeque<(arrow_array::RecordBatch, usize)>,
    pub(crate) row_count: usize,
    pub(crate) byte_count: usize,
    pub(crate) last_flush: Instant,
    pub(crate) last_drop_warn: Option<Instant>,
    pub(crate) in_flight: bool,
    /// Live, in-progress amortized builder for this partition. `None` for
    /// every adapter that doesn't opt in (`new_batch` returns `None`), and
    /// `None` even for an opted-in adapter until the first record lands.
    pub(crate) live_builder: Option<Box<dyn RecordBatchAccumulator<R>>>,
}
```
`PartitionedParquetWriter<S>.buffers` becomes `HashMap<String, PartitionBuffer<S::Record>>`. `PartitionBuffer` is `pub(crate)`, used only within this one file. Two direct construction sites exist: the production one inside `push()` (infers `R` from context, unaffected) and one test, `drop_oldest_to_cap_byte_count_stays_consistent` (`buffered_writer.rs:2145-2172`), which constructs a `PartitionBuffer` manually and calls `drop_oldest_to_cap` via `PartitionedParquetWriter::<MockSink>::drop_oldest_to_cap(...)` in the same function body — Rust's ordinary type inference is expected to resolve `R = String` from that later turbofish'd call without an explicit annotation; **verify this compiles unmodified during implementation, and add a one-line type annotation only if inference doesn't resolve it.** This test's manually-constructed buffer never has a `live_builder` set, so it is unaffected by materialization logic regardless.

### 3. Materialization: the load-bearing decision

**"Materializing" means:** finishing the live builder's currently-accumulated rows into a real `(RecordBatch, usize)` entry, pushed via `buf.buffer.push_back(...)`, with the batch's `get_array_memory_size()` added to `byte_count`.

```rust
fn materialize_live_builder(buf: &mut PartitionBuffer<S::Record>) {
    if let Some(builder) = buf.live_builder.as_mut() {
        if builder.len() > 0 {
            match builder.finish() {
                Ok(batch) => {
                    let est_bytes = batch.get_array_memory_size();
                    buf.byte_count += est_bytes;
                    buf.buffer.push_back((batch, est_bytes));
                }
                Err(e) => {
                    // Should not happen in practice (finishing already-
                    // validated builder state into Arrow arrays is not a
                    // fallible runtime operation under normal conditions).
                    // Log and leave the builder as-is; the next
                    // materialize attempt will retry.
                    tracing::error!("parquet_s3: live builder finish() failed: {e}");
                }
            }
        }
    }
}
```

Three rounds of coherence review converged on **every** code path that reads or takes `buf.buffer` for a flush or hard-cap decision needing this call first. The file has exactly 11 real `.buffer` touch points; here is the complete audit (verified against `buffered_writer.rs` line numbers as of this design):

| Line(s) | Function | What it does | Needs materialize-first? |
|---|---|---|---|
| 467 | `push()` | Writes a new fallback-path batch | No — this is where new data enters, not a flush decision |
| 495, 499 | `flush_all` (shutdown) | `is_empty()` gate, then `mem::take` | **Yes** — explicit call before the gate |
| 529 | `flush_all` | Writes failed batches back | No — restoring data, not a decision |
| 548 | `flush_all_if_needed` (ticker) | `is_empty()` gate | **Yes, indirectly** — gate condition itself changes (below) |
| 581 | `try_flush_partition_async`, in-flight branch | Calls `drop_oldest_to_cap` | **Yes** — covered by `drop_oldest_to_cap` self-materializing |
| 589, 594 | `try_flush_partition_async`, normal branch | `is_empty()` gate, then `mem::take` | **Yes** — explicit call at the top of the function |
| 657 | `apply_flush_outcome`, failure branch | Writes failed batches back | No — restoring data, not a decision |
| 669 | `apply_flush_outcome`, failure branch | Calls `drop_oldest_to_cap` | **Yes** — covered by `drop_oldest_to_cap` self-materializing |
| 719 | `drop_oldest_to_cap` | Pop-front loop | **Yes** — this function now self-materializes |
| 2154, 2166 | Test only | Manual buffer, never has a live builder | N/A |

**The fix, as defense-in-depth rather than per-call-site patching** (chosen specifically because two successive review rounds each found a *different* previously-unpatched call site reaching the same class of bug — a whack-a-mole pattern that a single, defensive fix inside the shared low-level function eliminates for current and future call sites alike):

1. **`drop_oldest_to_cap` calls `materialize_live_builder(buf)` as its own first line**, before its `while buf.row_count > cap` loop. This is the primary fix: it protects every current and future call site that enforces the hard cap, including the two that are reached independently of each other — `try_flush_partition_async`'s in-flight branch (line 581) and `apply_flush_outcome`'s failure branch (line 669, reached via `drain_pending_flushes`, an entirely separate call path that does not go through `try_flush_partition_async` at all).
2. **`try_flush_partition_async` also materializes unconditionally as the very first action in the function body**, before even computing the `in_flight` local. Needed because this function has its own direct `std::mem::take(&mut buf.buffer)` step (the real flush-to-S3 path, line 594) gated by the `is_empty()` check at line 589 — a check that does not go through `drop_oldest_to_cap` at all.
3. **`flush_all` (the synchronous shutdown path — it never calls `try_flush_partition_async`, it inlines its own take) calls `materialize_live_builder` explicitly, before its own `is_empty()` check at line 495.** Without this fix, a partition whose only pending data sat in an unmaterialized live builder would be silently skipped at graceful shutdown — genuine data loss, not just a delayed flush.
4. **`flush_all_if_needed`'s per-partition gate changes from `buf.buffer.is_empty()` to `buf.row_count == 0`.** `row_count` is incremented immediately and exactly on every accepted append regardless of path (see "Row/byte accounting" below), so this correctly distinguishes "nothing pending" from "pending but not yet materialized." Once `should_flush` is true, `try_flush_partition_async` is called, which (per fix 2) unconditionally materializes.

**Independently verified against the two pinned tests** (both rounds of review traced this by hand): `push_enforces_hard_cap_on_flush_failure` is moot (MockSink, `live_builder` always `None`, none of the four fixes are reachable). `writer_bounded_under_s3_outage` (real `ZeekSink`, `max_rows=1`, drains after every push): each push increments `row_count` once, triggers `try_flush_partition_async`, fix 2 materializes any live-builder content before the take, the drain fails the flush fast (unreachable endpoint) and merges data back via `apply_flush_outcome`, fix 1's self-materialize in `drop_oldest_to_cap` is a no-op there (already materialized) but correctly enforces the cap. The `row_count <= hard_cap` assertion holds.

### 4. `BUILDER_BATCH_ROWS` — the second trigger

Materialization is also triggered periodically, independent of any flush: whenever the live builder's own `len()` reaches a new bounded constant, `BUILDER_BATCH_ROWS = 1000` (a hardcoded private constant, not new TOML config — YAGNI for this first cut, matching this file's existing pattern of hardcoded tuning constants like `MAX_CONCURRENT_FLUSHES_PER_WRITER = 4`). This bounds:
- The maximum size of a single amortization unit (a burst of up to 1000 rows materializes as one Arrow encode step, not 1000).
- The "undroppable tail" under hard-cap enforcement to at most `BUILDER_BATCH_ROWS - 1` rows at any instant — small relative to the default hard cap (`max_buffer_rows=100,000` × 4 = 400,000, so 1000 is ~0.25% of cap).

This value is a tuning parameter chosen without empirical grounding yet (medium confidence) — the benchmark step (below) is expected to sanity-check it, and it is easy to change later since it is a private constant, not a stability-sensitive public API. It remains reasonable specifically because the hard-cap enforcement bugs above are now fixed; before those fixes, this same bound would have made the (buggy) undroppable-tail problem worse, not better.

### 5. Row/byte accounting discipline

`push()`'s existing logic resolves, per record, to exactly one of three paths — and must increment `row_count`/`byte_count` **exactly once**, at a single unified point after the branch resolves, not scattered per-branch (flagged explicitly by review round 3 as a discipline point for the implementer, not itself a design gap):

1. **Accepted into the live builder** (`new_batch` returned `Some` for this partition, and `try_append` returns `Ok(true)`): `n_rows = 1`; `byte_count` is **not** incremented here (see below) — only `row_count += 1`.
2. **Rejected by `try_append`** (`Ok(false)` — this record doesn't match the accumulator's schema; see "Per-record rejection" below): fall back to `self.sink.to_record_batch(&record, &schema)`, push the resulting 1-row batch directly onto `buf.buffer` via `push_back`, exactly as today's unconditional path already does. `n_rows = batch.num_rows()`; `byte_count += batch.get_array_memory_size()` (both immediate, matching today's exact accounting for this record).
3. **Adapter never opted in** (`new_batch` returns `None`, always, for 6 of 7 adapters): identical to today's code, unchanged.

**`row_count` stays exact and immediate in every case** — this is what fixes 1-4 above rely on for correctness (hard-cap and row-count-threshold decisions are always exact, never approximated). **`byte_count` only reflects a live builder's accumulated bytes once materialized** (path 1 above defers the byte addition to `materialize_live_builder`) — a deliberate, bounded, accepted trade-off: the byte-threshold flush trigger (`buf.byte_count >= self.policy.max_bytes`) can under-fire by up to `BUILDER_BATCH_ROWS - 1` records' worth of bytes for the "conn" partition specifically, delaying (never skipping — materialization at flush time always includes everything pending) a byte-triggered flush by a small, bounded amount. This affects a *soft* trigger (when to proactively flush), not a *hard* guarantee (the cap, or whether a flush eventually happens) — considered maintaining a cheap running per-record byte estimate instead, rejected as added complexity (a new trait method or per-adapter constant) for marginal accuracy gain over an already-small, already-bounded lag.

### 6. Per-record rejection (preserving `ZeekSink`'s existing raw-log_path fallback)

`ZeekSink::to_record_batch` today looks up its mapper via the record's **raw, unsanitized** `log_path` (`get_schema_entry(&record.log_path)`, a case-sensitive exact match against the registry — verified in `src/zeek/schema.rs:1018-1028`), while `partition()` uses the **sanitized** (lowercased) form. If a record's raw `log_path` is, say, `"Conn"` (mixed case), it sanitizes to the `"conn"` partition, but the case-sensitive raw-path registry lookup misses and falls back to the envelope mapper for that one record — a real, if rare, existing per-record fallback branch. A design that unconditionally routes every record landing in the "conn"-schema partition into `ConnAccumulator::try_append` would have no way to express this and would silently mismap such a record's fields.

**Fix:** `ConnAccumulator::try_append` performs the exact same check `to_record_batch` does today (`get_schema_entry(&record.log_path).schema == conn_schema()`, via `Arc::ptr_eq` — see below) before accepting; if it doesn't match, it returns `Ok(false)` and `push()` falls back to `to_record_batch` for that one record (path 2 above), reproducing today's exact behavior for the mismatch case.

**Accepted trade-off:** a rejected record's immediately-pushed 1-row batch can land in `buf.buffer` chronologically ahead of the live builder's still-pending (actually-earlier) rows, since the live builder is only materialized later. Considered pushing rejected-record batches to the front instead to preserve strict ordering; rejected as over-engineering for what should be a rare-to-nonexistent case in practice (`sanitize_log_path` lowercases, so a raw/sanitized case mismatch requires unusual input), and consistent with this investigation's own prior reasoning about a sibling declined plan item on batch ordering for log data ("probably fine... typically read back partition+time-range, not in strict append order").

### 7. `ZeekSink::new_batch` — detecting the "conn" partition

```rust
fn new_batch(&self, schema: &Arc<arrow_schema::Schema>)
    -> Option<Box<dyn RecordBatchAccumulator<ZeekRecord>>> {
    if Arc::ptr_eq(schema, &conn_schema()) {
        Some(Box::new(ConnAccumulator::new()))
    } else {
        None
    }
}
```
Valid because `conn_schema()` is backed by a `LazyLock<Arc<Schema>>` (`src/zeek/schema.rs:31-53`) that always returns a `.clone()` of the exact same singleton `Arc` — an O(1) pointer-identity check reliably distinguishes "conn" from every other partition (dns/http/ssl/files/notice/envelope/`_overflow`), all of which naturally fall through to `None`/today's unchanged path with zero special-casing. (This reuses the same technique the source plan's own, separately still-"worth doing eventually" item §2.3 already recommended for a different call site.)

### 8. `ConnAccumulator` and `map_conn`

`ConnAccumulator` holds the same 16 Arrow builders `map_conn` creates today, as persistent struct fields instead of locals, plus a row counter for `len()`. `map_conn` itself becomes a thin wrapper — construct one `ConnAccumulator`, call `try_append` once, call `finish()`, return the result — so the amortized (multi-row) path and the existing single-record path share **identical** field-extraction/mismatch-detection/`_extra`-building logic by construction. This makes output-equivalence a structural property (same code executes either way) rather than something requiring ongoing vigilance to keep two hand-written copies in sync.

## Testing (per this project's CLAUDE.md three-tier policy)

**Unit** (in `buffered_writer.rs`'s and `zeek/schema.rs`'s own test modules):
1. Value-equivalence: push K conn records through the amortized path; separately compute K individual single-row batches via `map_conn` + `arrow::compute::concat_batches`; assert identical column values (per-column comparison, since `RecordBatch` has no `PartialEq`).
2. Threshold-materialization: push more than `BUILDER_BATCH_ROWS` records without triggering a flush; assert `buf.buffer` contains more than one entry.
3. Flush-materializes-pending: tiny flush threshold (mirroring `writer_bounded_under_s3_outage`'s style); assert a flush actually includes just-pushed pending rows, not zero.
4. Both existing pinned tests (`push_enforces_hard_cap_on_flush_failure`, `writer_bounded_under_s3_outage`) re-run **completely unmodified**, confirming identical pass behavior.
5. Opt-out regression check: non-"conn" Zeek partitions and (spot-checked via existing tests) the other 6 adapters never get a live builder.
6. `try_append`-rejects-and-falls-back: a record with a raw/sanitized log_path mismatch lands in the partition as an envelope-shaped 1-row batch, matching today's exact behavior.
7. In-flight hard-cap enforcement with the live builder: many pushes accumulating in `live_builder` while a flush is stuck in-flight (no drain between pushes), using the real `ZeekSink` — this specific interleaving is what three rounds of review focused on; a dedicated test (beyond the two pre-existing pinned tests, which use `MockSink` or drain-after-every-push) strengthens confidence that fix 1 (`drop_oldest_to_cap` self-materializing) actually holds under sustained backpressure with accumulation.

**Integration:** extend/verify Zeek's existing local/S3 integration tests push a realistic burst of conn records through the real pipeline and the resulting Parquet file(s) have the correct row count and correct field values — proving the amortized path survives the real encode+upload round trip.

**E2E:** confirm the existing real-TCP Zeek e2e test(s) continue passing unmodified (they exercise `ZeekSink` for real, so automatically exercise the new amortized path once wired). Add a dedicated e2e assertion only if the implementer finds a genuine gap.

**Benchmark:** re-run `examples/flush_decoupling_benchmark.rs` (both `realistic` and `stress` modes) on current `master` (before) and after this change, comparing Zeek "conn"-specific throughput and per-record cost. This directly produces the "prove it delivers" evidence the source plan's §2.6 sequencing note wanted from a `criterion` harness, substituting the existing benchmark infrastructure instead of building a new one (an explicit scope decision, not an oversight) — valid because this harness already exclusively drives Zeek's "conn" schema.

## Out of scope, explicitly untouched this cycle

Zeek's dns/http/ssl/files/notice mappers and envelope fallback; the other 6 `ParquetSink` adapters; the `criterion`/`tools/loadgen` harness (plan item 2.6 full); operator-configurable `BUILDER_BATCH_ROWS`. All are natural, low-risk follow-on work once this reference implementation is proven — each is a mechanical repetition of the pattern established here, not a new design question.
