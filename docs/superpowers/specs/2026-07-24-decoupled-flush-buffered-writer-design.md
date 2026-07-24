# Decoupled Flush for the Generic Buffered Writer — Design

**Date:** 2026-07-24
**Status:** Approved (design, via auto-develop self-review — see Decision log), pending implementation plan
**Branch:** `fix/decouple-flush-channel-drain`
**Related:** [2026-06-23-generic-buffered-writer-design.md](2026-06-23-generic-buffered-writer-design.md) (the writer this change modifies); diagnosed in production against a Zeek sensor sustaining record loss under `try_send`-full backpressure.

## Problem

`ParquetWriterHandle::start_with_stats` runs one task per writer (`src/forwarding/buffered_writer.rs`), whose `select!` loop both drains the ingest `mpsc` channel and performs flushes:

```rust
msg = rx.recv() => {
    if let Err(e) = writer.push(record).await { ... }   // blocks here during a flush
}
```

`push()` calls `flush_partition()` synchronously whenever a row/byte/age threshold is crossed. `flush_partition` does a `spawn_blocking` Arrow/Parquet encode **and** an awaited S3/local-disk upload before returning. While that's in flight, the task is not back at `select!` and is not draining the channel. The channel is bounded (`channel_capacity`, default 256 for Zeek); the producer side (`try_send`, non-blocking) starts failing the instant it fills, for the full duration of the flush.

Diagnosed in production: a fresh pod, fresh port, fresh channel still overflowed within seconds of a Zeek sensor reconnecting — ruling out a stuck/wedged consumer. The channel is small relative to how long one flush's encode+upload can block the only task that drains it. This affects all 7 sources sharing this writer (syslog, ipfix, sflow, zeek, suricata, wef, hec × s3/local), not just Zeek.

## Goal

Let the writer task keep draining its channel while a previous batch's flush is still in flight, instead of blocking on it — without regressing the existing hard-cap/backpressure/drop-metric guarantees the current design already relies on (and that existing tests assert).

## Decision log

Produced via `auto-develop` (self-answered design questions, reviewed by 3 rounds of an independent reviewer subagent — rounds 1 and 2 found real issues that were fixed and re-verified against the actual code; round 3 rejected on the grounds that the design wasn't yet implemented, which is expected at this stage and not a coherence objection — see conversation for full transcript).

| # | Question | Chosen | Why |
|---|---|---|---|
| 1 | Background-flush handoff mechanism | `tokio::task::JoinSet<FlushOutcome>` polled from `select!` | Idiomatic "spawn many, reap in a loop"; surfaces panics as `JoinError` (a raw detached `tokio::spawn` would silently swallow one); doesn't re-serialize different partitions' flushes the way one dedicated worker task would |
| 2 | Per-partition in-flight limit | At most 1 | A second threshold-crossing while one is in-flight falls back to the *existing* `drop_oldest_to_cap` on the live buffer instead of spawning a second flush for the same partition — reuses existing machinery, no new backpressure invented |
| 3 | Cross-partition concurrency bound | Bounded per-writer `Semaphore` (4 permits, fixed internal constant) that every spawn — fresh-triggered or failure-retry — must acquire, **acquired inside the spawned task, not before spawning** | Closes both the original correlated-initial-flush risk (Zeek can have up to 256 partitions) and a retry-storm risk introduced by decision #12 (see below): without this, a systemic backend outage could fail many partitions together and then re-arm them all to retry near-simultaneously. Scoped per-writer, not process-wide, matching this codebase's existing philosophy that each source/destination keeps fully independent buffer/flush/backpressure/hard-cap state. **Acquiring the permit inside the spawned task is load-bearing** — acquiring it before spawning, in `push()`/`flush_all_if_needed()`, would block the main loop the moment the cap saturates, reintroducing the exact bug this change fixes |
| 4 | Failed-flush data handling | Merge returned batches back into the live buffer (prepended, since older), re-run existing hard-cap check on the merged total | Preserves today's resilience to transient failures — a network blip must not permanently lose data any more than it does now |
| 5 | Outcome reporting | All outcomes (success and failure) route through the JoinSet, processed only by the task that owns `self.buffers` | Preserves the single-owner-mutates-buffers invariant already used throughout this file; no new shared-mutable-state class |
| 6 | `push()`'s `-> anyhow::Result<()>` signature | Unchanged (will just always return `Ok(())` from flush-related paths now) | Avoids rippling a signature change through ~14+ call sites/tests for what's a mild code smell, not a functional problem; narrowing is a separate mechanical follow-up |
| 7 | Bundle the separately-identified source/target logging-attribution fix (different conversation)? | No | Scope discipline — this change is exactly what was asked; the now-easier follow-up is noted, not folded in |
| 8 | Existing low-level unit tests asserting synchronous flush-failure/hard-cap behavior | Rewrite using a new `drain_pending_flushes()` primitive | These tests exist specifically to prove hard-cap/backpressure correctness — the one guarantee this change must not regress; accepting flakiness here defeats their purpose |
| 9 | Where `drain_pending_flushes()` lives | One production method, used both at graceful shutdown and by tests | Shutdown genuinely needs this (must not report "done" while flushes are still in flight) — it's a necessary primitive, not test scaffolding |
| 10 | Touch the other ~14 per-source wrapper files / `main.rs` / `server/mod.rs`? | No | `ParquetWriterHandle`'s external contract (`try_send`, `flush_interval`, `start_with_stats` signature) is unchanged — verified directly against the code, not assumed |
| 11 | Test coverage (unit/integration/e2e) | See Test plan below | The integration/e2e claim "records aren't dropped during a slow flush" is **bounded** by the existing hard cap (4× `max_buffer_rows`), not unconditional — test parameters must stay inside that bound and the bound must be stated explicitly |
| 12 | `last_flush` after a failed-flush merge-back | Explicitly re-stale it: `Instant::now().checked_sub(interval + Duration::from_secs(1)).unwrap_or_else(Instant::now())` | Today, a failed flush never touches `last_flush`, so it's already stale and the age trigger reliably re-fires almost immediately on the next check. The new design's fresh-buffer-gets-"now"-at-swap-time would otherwise make a low-volume, age-only-triggered partition wait a full `flush_interval` (900s default) to retry after failure — a real regression, fixed by deliberately re-staling on merge-back. `checked_sub` (not raw subtraction) avoids a panic on underflow shortly after process startup with a long configured interval |

## Architecture

### New types

```rust
enum FlushOutcome {
    Success { key: String },
    Failure { key: String, batches: VecDeque<(RecordBatch, usize)>, row_count: usize, byte_count: usize },
}
```

`PartitionedParquetWriter` gains:
- `flush_tasks: tokio::task::JoinSet<FlushOutcome>`
- `flush_semaphore: Arc<tokio::sync::Semaphore>` (4 permits, per-writer)

`PartitionBuffer` gains:
- `in_flight: bool`

The core encode+upload logic currently in `flush_partition(&mut self, key)` is extracted into a free function taking **owned** data only (batches, schema `Arc`, sink `Arc<dyn UploadSink>`, descriptor-sink `Option<Arc<dyn UploadSink>>>`, source/target `&'static str`, prefix, partition key) — no borrow of `self`, so it can run inside a spawned task. It first acquires the semaphore permit, then does exactly what `flush_partition` does today (spawn_blocking encode, awaited upload, metrics, descriptor upload on success), and returns a `FlushOutcome` instead of mutating `self`.

### Trigger path

`push()` and `flush_all_if_needed()` replace their inline `flush_partition().await` call with `try_flush_partition_async(&mut self, key)`:
- Not in-flight: swap the partition's buffer contents out for a fresh empty `PartitionBuffer` (reset `last_flush` to now), mark `in_flight = true`, spawn into `flush_tasks` (spawn itself is cheap and non-blocking — the semaphore wait happens inside the spawned task, not here).
- Already in-flight: don't spawn a second flush for this partition; apply the existing `drop_oldest_to_cap` against the live (still-growing) buffer instead.

### Completion path

A new guarded `select!` branch in the outer task loop:

```rust
Some(outcome) = self.flush_tasks.join_next(), if !self.flush_tasks.is_empty() => { ... }
```

The `if !is_empty()` guard is load-bearing: `JoinSet::join_next()` on an empty set resolves immediately to `None`, so an unguarded branch would busy-spin.

- `Success { key }`: clear `in_flight` for that partition.
- `Failure { key, batches, row_count, byte_count }`: clear `in_flight`, prepend `batches` onto the current live buffer (which may have grown in the meantime), re-stale `last_flush` per decision #12, then re-run `drop_oldest_to_cap` against the merged total.

### Shutdown path

On channel close (`rx.recv()` returns `None`): drain `flush_tasks` to empty via `drain_pending_flushes()` (looping `join_next()`, applying each outcome as above) **before** the final synchronous `flush_all()` — so the writer's `JoinHandle` doesn't complete while a background flush is still outstanding, preserving the documented graceful-shutdown contract. Tests reuse this same method for deterministic waiting instead of sleep-based polling.

## Explicitly out of scope

- The source/target logging-attribution fix for the generic writer-task's warn! lines (separate, already-identified follow-up — now easier thanks to the centralized failure-handling path this change creates).
- Any change to `push()`'s public signature.
- A cross-source (process-wide) concurrency cap — the semaphore here is per-writer only.
- Making the semaphore permit count or the per-partition in-flight limit configurable.

## Test plan (per this repo's mandatory unit/integration/e2e rule)

- **Unit** (`buffered_writer.rs`'s own `#[cfg(test)]` module, rewritten): `JoinSet` outcome handling (success clears in-flight; failure merges + re-stales + re-caps), 1-in-flight-per-partition enforcement (a second threshold-crossing while in-flight hits `drop_oldest_to_cap` instead of spawning), semaphore behavior (permit acquired inside the spawned task, not blocking the caller), `drain_pending_flushes()` draining to empty, shutdown ordering, and the `checked_sub` fallback on a long interval shortly after start.
- **Integration**: a real `ParquetWriterHandle` (e.g. via `zeek_local_start`) driven with an artificially slow `UploadSink`, asserting records pushed *during* a slow flush are not dropped. **Bounded explicitly**: the artificial delay, ingest rate, and `max_buffer_rows`/hard-cap parameters must be chosen so the slow flush completes before the live buffer would cross the hard cap — this test proves the fix within its accepted limit, not an unconditional guarantee.
- **E2e**: extend the existing local-disk e2e path to demonstrate no drops under a bounded simulated slow-upload burst through the real ingest path, same bound stated.

## New metric

`parquet_s3_flushes_in_flight{source,target}` — gauge, incremented on spawn, decremented when an outcome is processed. Makes the semaphore's saturation observable in production (paired with the cap, this is now a genuine signal, not just description).
