# Flush byte-accounting fix — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Stop the buffered writer from flushing 1-2 orders of magnitude too early, which currently discards ~70% of IPFIX events at 20,000/s.

**Architecture:** One change in shared code — replace the flush threshold's capacity-based byte estimate with a used-bytes estimate. This is a repo-wide defect, not an IPFIX one: the estimate lives in `buffered_writer.rs` and every sink but zeek is exposed to it.

**Spec:** `docs/performance/2026-09-14-writer-channel-loss.md` (the characterisation), plus the measurements in the Findings section below.

## Global Constraints

- **Build env:** `export CC=/usr/bin/gcc CXX=/usr/bin/g++` and `export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc`.
- **Never work on `master`.** Branch first.
- **Run cargo in the FOREGROUND, 600000 ms timeouts.** Never background a build; nine agents have stranded themselves doing so.
- **Commit early and often** — rate limits have killed agents mid-task twice.
- **Stage explicit file paths**, never `git add -A <dir>`.
- **Commit before mutation-testing.** Reverting a mutation with `git checkout` destroys uncommitted work.
- New behaviour needs unit, integration and e2e coverage.
- Pre-push runs fmt → clippy `-D warnings` → test → `bench --no-run`.

## Findings that drive this plan — measured, do not re-derive

1. **The flush threshold uses `RecordBatch::get_array_memory_size()`** at **three** sites (`src/forwarding/buffered_writer.rs:914`, `:946`, `:1421`), which reports **allocated capacity**, not bytes used.
2. **Measured overstatement, IPFIX sink:**

   | rows in batch | reported (capacity) | actual (used bytes) | overstatement |
   |---|---|---|---|
   | 1 | 94,080 | **109** | **863×** |
   | 100 | 94,080 | 10,378 | 9× |
   | 1000 | 109,440 | 103,750 | 1× |

   (used-bytes column measured via `ArrayData::get_slice_memory_size()`, the
   API the fix uses.)

   The reported figure is dominated by a fixed ~94 KB — 19 Arrow builders at arrow-rs's default 1024-element capacity — independent of how many rows the batch holds.
3. **Consequence:** with 1-row batches the 100 MiB threshold is reached after ~1,114 rows instead of ~1,000,000. A 15 s run at 20,000/s flushed **49 times instead of ~1**, each flush `concat_batches`-ing ~1,456 single-row batches.
4. **Impact:** the writer drains at **~5,570/s** against a benched encode ceiling of **64,767/s** — 12× below its own capability — so a channel holding **11,377** (≈0.57 s of headroom at 20k/s) overflows almost immediately. `parquet_s3_dropped{source="ipfix"}` ≈ **70% of everything the kernel delivered**.
5. **`parquet_s3_buffer_dropped` never fired.** The loss is `try_send`-on-full, not hard-cap eviction. These are different sites; do not conflate them.
6. **Repo-wide.** Only `ZeekSink` has a `RecordBatchAccumulator`; **ipfix, sflow, suricata, syslog, generic and structured_syslog do not**, and all use the same shared estimate. Zeek is incidentally protected because its accumulator produces large batches where capacity ≈ usage.
7. **Eliminated as causes**, with evidence, in the characterisation doc: flush-concurrency semaphore (only one partition exists; `flushes_in_flight` never exceeds 1), disk I/O (49 files of 10-24 KB; compression 0.34% of profile), and the configured cadence itself (900 s / 100 MiB is correct — the estimator lies to it).

## Success criteria

- `used_bytes` for a 1-row IPFIX batch reports ~109 bytes, not the 94,080 capacity figure.
- At 20,000/s for 15 s with the real `[ipfix.local]` handler, **flush count drops from ~49 to single digits** and `parquet_s3_dropped{source="ipfix"}` falls by **≥90% relative**, N≥5 runs, before/after ranges non-overlapping.
- **No sink's flush cadence becomes pathologically *long*.** The opposite failure — under-counting bytes so a buffer grows unbounded until the row cap evicts — must be checked: `parquet_s3_buffer_dropped` must stay at 0, and `parquet_s3_buffer_rows` must not climb monotonically across a run.
- Full suite green; every existing sink's tests still pass.

---

## Task 1: Replace the capacity-based byte estimate with used bytes

**Files:** `src/forwarding/buffered_writer.rs` (all three call sites: ~914, ~946, ~1421)

- [ ] **Step 1: Write the failing unit test.** In `buffered_writer.rs`'s test module, build a 1-row `RecordBatch` from any sink's schema and assert the estimator returns something within 2× of the summed buffer lengths — not the ~94 KB `get_array_memory_size()` reports. This test fails today.

- [ ] **Step 2: Run it, confirm it fails** with the capacity figure.

- [ ] **Step 3: Implement — use arrow-rs's own API, do not hand-roll this.**

`ArrayData::get_slice_memory_size()` already does exactly what is needed: it
sums **used** bytes per buffer (fixed-width by `len * byte_width`, variable-width
via offset arithmetic, null bitmaps as `ceil(len, 8)`) **and recurses into
`child_data()`**.

```rust
/// Bytes a batch's data actually occupies, as opposed to the capacity its
/// builders allocated.
///
/// `RecordBatch::get_array_memory_size()` reports allocated capacity. For a
/// batch built one row at a time that is dominated by a fixed per-builder
/// allocation — measured at 94,080 bytes for a 1-row IPFIX batch whose real
/// payload is 109 — a ~860x overstatement that drove the byte-based flush
/// threshold 1-2 orders of magnitude too early. See
/// `docs/performance/2026-09-14-writer-channel-loss.md`.
///
/// `get_slice_memory_size` is arrow's own used-bytes accounting: slice-aware
/// (a hand-rolled `buffers().map(|b| b.len())` sum reports the *parent*
/// buffer for a sliced array, reintroducing an overstatement of the same
/// kind) and recursive into child data, so it stays correct if a nested
/// column type is ever added.
fn used_bytes(batch: &arrow_array::RecordBatch) -> usize {
    batch
        .columns()
        .iter()
        .map(|c| c.to_data().get_slice_memory_size().unwrap_or(0))
        .sum()
}
```

`to_data()` is cheap — `self.clone().into()`, Arc-based, no copy — so this is
safe on the writer's hot path.

**Replace ALL THREE call sites**, not two: `buffered_writer.rs:914`, `:946`,
and **`:1421`** (inside `materialize_live_builder`, the accumulator path used
today only by `ZeekSink`). An earlier draft of this plan said "both call
sites" and missed `:1421` — leaving it would half-fix a defect this plan's own
Finding #6 describes as shared across every sink.

- [ ] **Step 4: Run the test, confirm it passes.**

- [ ] **Step 5: Commit** before any mutation testing.

- [ ] **Step 6: Prove the test guards the bug.** Revert to `get_array_memory_size()`, confirm the test fails, restore from a file copy (**not** `git checkout` — that discards uncommitted work). Paste both outputs.

## Task 2: Integration coverage for flush cadence

**Files:** `tests/flush_byte_accounting_integration.rs` (create)

- [ ] Drive a writer with many small batches through the real `start_writer` path and assert the flush count is proportional to *actual* bytes, not batch count. Use a small `flush_threshold_bytes` so the test is fast. Read `tests/buffered_writer_flush_decoupling_integration.rs` for the established harness shape and reuse it.
- [ ] Assert `parquet_s3_buffer_dropped` stays 0 — guards the under-counting direction.
- [ ] Commit.

## Task 3: Measure the effect

- [ ] Use `scripts/repeat-ipfix-loopback-loss.sh` (already on the branch, supports `SHAPE=real`). N≥5 at 20,000/s, before and after.
- [ ] Record: `parquet_s3_dropped`, flush count (`parquet_s3_uploads`), `parquet_s3_records_written`, `parquet_s3_buffer_rows`, and kernel loss for context.
- [ ] Write `docs/performance/2026-09-14-flush-accounting-fix-results.md` with before/after, median/min/max, the standard hardware caveat, and the exact reproduction command.
- [ ] **Decide by the measured number, using this rule — set in advance so it is not argued after the fact:**
  - **≥90% reduction** → success as specified. Land it.
  - **Material but short of 90% (roughly 30-90%)** → **land it anyway, and say so precisely.** This is the *most likely* outcome and is not a failure: the characterisation attributes the 12× drain gap to two mechanisms, and this fix only addresses one. `concat_batches` over ~1,456 tiny batches per flush is removed; the per-push 19-builder allocation churn behind the profile's ~40% allocator / ~12.5% futex time is **not** — that is the deferred accumulator work. Record the residual gap and name accumulators as the follow-up, with the measured number that justifies it.
  - **<30%, or worse** → do not land quietly. The mechanism was confirmed in isolation but not end to end; report that, and treat the accumulator work as the primary candidate instead.
- [ ] **If the fix does not materially reduce `parquet_s3_dropped`, say so plainly.** The characterisation named the mechanism with strong evidence, but a mechanism confirmed in isolation is not the same as a fix confirmed end to end. Report what actually happened.
- [ ] Commit.

---

## Explicitly NOT in scope

| Item | Why |
|---|---|
| Giving the six sinks `RecordBatchAccumulator`s | A separate optimisation. It reduces per-push allocation (the profile's 40% allocator time) but does **not** fix the accounting — a sink pushing small batches would still overstate. Task 1 fixes the defect; accumulators are a follow-up with their own measurement. |
| Tier 1 recv/decode decouple | Paused. It targets 3.6% kernel loss; this targets ~70%. Resume only after this lands and is measured. |
| Tuning `flush_threshold_bytes` or `channel_capacity` | The config is correct. Changing it would paper over a defect in the estimator that feeds it — the same error as raising `rmem_max` to hide the earlier receive-buffer finding. |
| Allocator swap (mimalloc) | The throughput plan's Tier 2. Unchanged by this work, still speculative. |
