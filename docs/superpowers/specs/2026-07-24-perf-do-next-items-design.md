# Design: Deliver the 3 "Do Next" Performance Items

**Date:** 2026-07-24
**Status:** Approved (auto-develop coherence review, 3 rounds)
**Source:** `docs/superpowers/specs/2026-07-24-performance-improvements-plan.md` §5 — items 2.7 (row 7), 2.4, 2.2.

## Scope

Exactly three items, no more:

1. **2.7** — Add missing `source`/`target` structured tracing fields to 6 `warn!` call sites in `src/forwarding/buffered_writer.rs`.
2. **2.4** — Add `parquet_s3_channel_available{source,target}` and `parquet_s3_buffer_rows{source,target,partition}` gauges, updated from the writer's periodic ticker, never from `push()`.
3. **2.2** — Remove the per-record `HashSet` allocation in `src/zeek/schema.rs`'s `build_extra`.

Everything else in the source plan (§2.1, §2.3, §2.6, the "worth doing eventually"/"declined" items, deferred decision-log rows 3 and 6) is explicitly out of scope for this change.

## 2.7 — Log field additions

Add structured `tracing::warn!` fields at these 6 sites in `buffered_writer.rs`, matching the existing correct pattern at `drop_oldest_to_cap`'s warning (`buffered_writer.rs:717-722`, `tracing::warn!(dropped, source, target, "...")`):

| Line | Function | `source`/`target` access |
|---|---|---|
| 649 | `apply_flush_outcome` (failure branch) | Already-bound locals (computed at 631-632) |
| 686 | `drain_pending_flushes` (panic branch) | **No locals in scope here** — call `self.sink.source()` / `self.s3.target_label()` inline |
| 1032 | `start_with_stats` task, push error (dead branch) | Locals captured at 1002-1003, in scope for the whole closure |
| 1042 | `start_with_stats` task, shutdown flush_all error | Same as above |
| 1053 | `start_with_stats` task, flush_all_if_needed error (dead branch) | Same as above |
| 1067 | `start_with_stats` task, flush task panic | Same as above |

No logic change anywhere. Line 686 is the one site where the field values require an inline method call rather than reusing an existing local — everywhere else it's a direct variable reference.

**Testing:** new unit test using a minimal in-test `tracing_subscriber::Layer` (+ a `Visit` impl to extract field values into a shared `Vec` for assertion), built in `buffered_writer.rs`'s own `#[cfg(test)] mod tests`. Uses only already-present `tracing`/`tracing-subscriber` crates (Cargo.toml: `tracing = "0.1"`, `tracing-subscriber = "0.3"`) — not a new external test dependency, the same class of purpose-built test harness this design already uses for gauge testing (which reuses `metrics`' `DebuggingRecorder`). Assert all 6 call sites emit both `source` and `target` fields. No new integration/e2e test needed for this item specifically — no behavior or wire-format change beyond the added log fields; existing integration/e2e tests continue to pass unchanged, confirming no regression.

## 2.4 — Buffer/channel gauges

Add `pub(crate) fn update_buffer_gauges(&self)` to `PartitionedParquetWriter`:

```rust
fn update_buffer_gauges(&self) {
    let source = self.sink.source();
    let target = self.s3.target_label();
    for (partition, buf) in &self.buffers {
        metrics::gauge!("parquet_s3_buffer_rows",
            "source" => source, "target" => target, "partition" => partition.clone())
            .set(buf.row_count as f64);
    }
}
```

Call this from the `ticker.tick()` branch in `ParquetWriterHandle::start_with_stats` (~line 1048), alongside a new line reading channel headroom:

```rust
metrics::gauge!("parquet_s3_channel_available", "source" => source, "target" => target)
    .set(rx.capacity() as f64);
```

**Why `rx.capacity()` and not `tx.capacity()`:** `tx` (the `mpsc::Sender`) is moved into the returned `ParquetWriterHandle`, not into the task's async closure — only `rx` (the `Receiver`) is. Verified directly against the vendored tokio 1.49.0 source (`~/.cargo/registry/.../tokio-1.49.0/src/sync/mpsc/bounded.rs`): `Sender::capacity()` (line 1538) and `Receiver::capacity()` (line 591) both read the identical `self.chan.semaphore().semaphore.available_permits()` — no functional difference, no extra clone needed.

**Why `update_buffer_gauges` is a method, not inline in the closure:** matches this file's existing pattern — `apply_flush_outcome` and `drop_oldest_to_cap` are already extracted as directly-callable, directly-unit-testable methods rather than living inline in the task loop. All existing unit tests in this file construct a `PartitionedParquetWriter` directly and call its methods without spinning up the full task; extracting this method keeps the new gauge testable the same way `parquet_s3_flushes_in_flight` already is.

**Why ticker-only, never `push()`:** `push()` is the hottest call in this file (once per ingested record). The plan's explicit rationale for choosing the ticker is avoiding added per-record overhead; the ticker already fires on the writer's existing `flush_check` interval, which is timely enough for a leading indicator. Not called from flush completion either — YAGNI, unrequested.

**Known limitation — `partition` label cardinality:** verified per-source `max_partitions` in production wiring code (not just TOML configs): Zeek = 256 (`DEFAULT_MAX_ZEEK_PARTITIONS`, `zeek_s3.rs:182`), Suricata = 256, syslog = 1, ipfix = 1, structured_syslog = 8, sflow = 2, generic/HEC/OTLP = 64 — all six bounded via the existing `_overflow`-bucket mechanism (`buffered_writer.rs:419-422`). The sole exception is **WEF** (`parquet_s3.rs:390,450`, partitioned by Windows Event ID): `max_partitions: 0` = unlimited, with an explicit source comment "unlimited partitions — EventIDs are bounded in practice." This is a pre-existing characteristic of WEF's configuration, not introduced by this change — WEF's `self.buffers` HashMap is already unbounded in memory today regardless of this gauge. The new gauge mirrors that existing characteristic into Prometheus rather than worsening it. Documented here as a known limitation rather than silently accepted; no in-change mitigation is being built (out of scope — would be unrequested new cardinality-limiting logic for a single source whose EventID space is bounded in practice per the existing code comment).

**Testing:**
- Unit: in `buffered_writer.rs`'s test module, using the existing `DebuggingRecorder` pattern already used for `parquet_s3_flushes_in_flight` (test `flush_metrics_carry_the_target_label`), assert `update_buffer_gauges()` sets `parquet_s3_buffer_rows{source,target,partition}` to each partition's live `row_count`.
- Integration: extend `tests/buffered_writer_flush_decoupling_integration.rs` — spin up a real `ParquetWriterHandle::start_with_stats`, push records, wait for a ticker interval, assert both new gauges appear with plausible values.
- E2E: extend `tests/zeek_flush_decoupling_e2e.rs` (this project's existing e2e tier for this exact component: real TCP → real `ZeekListener` → real `ZeekSink` → real writer) to additionally assert the two new gauges are observable through that real path.

## 2.2 — `build_extra` HashSet removal

In `src/zeek/schema.rs`, `build_extra` (~lines 224-235):

```rust
// before
let promoted_set: std::collections::HashSet<&str> = promoted.iter().copied().collect();
...
if !promoted_set.contains(k.as_str()) || mismatch_keys.contains(&k.as_str()) {

// after
if !promoted.contains(&k.as_str()) || mismatch_keys.contains(&k.as_str()) {
```

Delete the `HashSet` construction entirely; `promoted: &[&str]` is already the function's parameter type, so `.contains()` on the slice directly replaces the set lookup — no allocation, no hashing, for a ≤16-element list. Purely behavior-preserving (same membership semantics for a small list).

**Testing:** behavior-preserving refactor, not new behavior. Existing tests exercise this transitively and are expected to pass unchanged: unit (`zeek/schema.rs`'s own tests asserting `_extra` JSON contents), integration (`zeek_local_integration.rs`/`zeek_s3_integration.rs`), e2e (`zeek_flush_decoupling_e2e.rs`). No new tests required; run all three tiers to confirm no regression.

## Execution plan

**Branching:** feature branch off current `master` HEAD (`72e7157`), not implementing directly on `master`.

**Subagent decomposition** (per the project's rule against parallel edits to the same file): 2.7 and 2.4 literally overlap in the same closure in `buffered_writer.rs` (lines ~1030-1070) — one subagent implements both together, in its own worktree, as two sequential commits. A second, parallel subagent implements 2.2 alone, in `src/zeek/schema.rs` — a fully independent file, safe to run concurrently.

**Benchmarking** (`examples/flush_decoupling_benchmark.rs`, both `mode=realistic` and `mode=stress`), with success criteria stated up front to avoid post-hoc false attribution:
- **2.7 and 2.4 are structurally off the per-record hot path by construction** (2.7 is log-field-only; 2.4's gauges are ticker-only, never called from `push()`). For these, the benchmark's role is pure regression detection — expected outcome is "no meaningful throughput delta."
- **2.2 is the only item with a plausible measurable hot-path effect** (removes a per-record allocation from `build_extra`, called on every Zeek record). Run both modes twice at baseline and twice after the change, to get a basic noise-floor sense before attributing any delta to the change.

Sequence: baseline (both modes) → 2.7 lands, benchmark (regression check) → 2.4 lands, benchmark (regression check) → [parallel] 2.2 lands, benchmark ×2 both modes (attribution check) → final combined run after merge.

**Two-stage review** (spec-compliance, then code-quality) on each subagent's output before merging, per the project's standard workflow. No auto-merge to `master` — implementation lands on the feature branch for the user to review and decide on merge/PR.
