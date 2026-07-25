# Benchmark Results: Amortized `ConnAccumulator` (plan item 2.1)

**Date:** 2026-07-24
**Harness:** `examples/flush_decoupling_benchmark.rs` (unmodified — this task did not
change the benchmark binary itself)
**Change under test:** Zeek's "conn" log-type mapper now reuses a persistent set of
~16 Arrow builders across many records (`RecordBatchAccumulator<Record>` /
`ConnAccumulator`, Tasks 1-5 on this branch) instead of allocating fresh builders and
finishing a full `RecordBatch` per record. Per the design doc's own profiling, the
per-record `ZeekSink::to_record_batch` + builder-allocation cost this change targets
was measured at **~500µs-1.3ms/record** — the dominant per-record cost in the whole
Zeek ingest path.

## Commits

| | Branch | Commit |
|---|---|---|
| **Before** | `perf/do-next-items` (baseline is a genuine ancestor of this branch, reused — see below) | `6435396a99a4aa960befcb7a68505db122abd1b4` |
| **After** | `perf/batch-record-builders` (this branch, HEAD at benchmark time) | `dca6b520384987668475f56fd13fdf7bb6f1a84e` |

Ancestry verified directly before reuse:

```bash
$ git merge-base --is-ancestor 6435396a99a4aa960befcb7a68505db122abd1b4 HEAD && echo "YES ANCESTOR"
YES ANCESTOR
```

## How the "before" baseline was determined

The task brief allows reusing `docs/superpowers/specs/2026-07-24-benchmark-results-baseline.md`
(captured during a prior, separate "do next items" plan) instead of re-capturing a
fresh "before" run, **if** its recorded commit is a genuine ancestor of this branch
and its benchmark flags match what this task's Step 2 uses.

Both conditions were checked and hold:

- **Ancestry:** `git merge-base --is-ancestor 6435396a99a4aa960befcb7a68505db122abd1b4 HEAD`
  returned true (shown above) — that commit is on the direct line of history behind
  this branch's `dca6b52` HEAD, i.e. it reflects `master`/pre-amortization state with
  none of Tasks 1-5's code present (confirmed independently below — the baseline
  commit's `push()` has no `live_builder` field or `RecordBatchAccumulator` trait at
  all).
- **Flags match exactly:** the baseline doc's realistic-mode command is
  `mode=realistic duration_secs=30 target_rate=4000 upload_delay_ms=150` and its
  stress-mode command is `mode=stress duration_secs=30 target_rate=4000
  upload_delay_ms=150` — identical to what this task's brief specifies for the "after"
  runs.

Given both hold, the existing baseline doc was reused verbatim rather than spinning up
a read-only `master` worktree — this saves real time without weakening the evidence,
since the baseline was captured on a genuine ancestor commit with the same benchmark
parameters.

## Build (this branch)

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++ CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo build --release --example flush_decoupling_benchmark
```

**Result:** clean build, 44.79s. One pre-existing, unrelated warning
(`method 'try_append_value' is never used` in `src/zeek/schema.rs:398`) — this is
dead code left over from Task 4's `ConnAccumulator` unification, not something this
task introduced or is in scope to fix.

## "Before" baseline output (reused from `2026-07-24-benchmark-results-baseline.md`)

### Realistic mode, run 1

```
cargo run --release --example flush_decoupling_benchmark -- mode=realistic duration_secs=30 target_rate=4000 upload_delay_ms=150
```

```
=== flush_decoupling_benchmark ===
BenchConfig {
    mode: "realistic",
    duration_secs: 30,
    target_rate: 4000,
    upload_delay_ms: 150,
    max_buffer_rows: 100000,
    channel_capacity: 256,
    flush_threshold_bytes: 104857600,
}

Sending sustained load: target_rate=4000 records/sec for 30 secs...
Send loop finished: 119996 records sent in 30.001s (achieved rate: 3999.8 rec/s)
Draining for 2s...

=== RESULTS ===
mode:                        realistic
params:                      duration_secs=30 target_rate=4000 upload_delay_ms=150 max_buffer_rows=100000 channel_capacity=256 flush_threshold_bytes=104857600
records sent:                119996
records written (durable):   119180
records dropped (channel):   0
records buffer_dropped(cap): 0
wall-clock elapsed:          30.001s
achieved send rate:          3999.8 rec/s
effective accept rate:       3999.8 rec/s
drop percentage:             0.000%
================
```

### Realistic mode, run 2

```
cargo run --release --example flush_decoupling_benchmark -- mode=realistic duration_secs=30 target_rate=4000 upload_delay_ms=150
```

```
=== flush_decoupling_benchmark ===
BenchConfig {
    mode: "realistic",
    duration_secs: 30,
    target_rate: 4000,
    upload_delay_ms: 150,
    max_buffer_rows: 100000,
    channel_capacity: 256,
    flush_threshold_bytes: 104857600,
}

Sending sustained load: target_rate=4000 records/sec for 30 secs...
Send loop finished: 119984 records sent in 30.035s (achieved rate: 3994.8 rec/s)
Draining for 2s...

=== RESULTS ===
mode:                        realistic
params:                      duration_secs=30 target_rate=4000 upload_delay_ms=150 max_buffer_rows=100000 channel_capacity=256 flush_threshold_bytes=104857600
records sent:                119984
records written (durable):   119221
records dropped (channel):   0
records buffer_dropped(cap): 0
wall-clock elapsed:          30.035s
achieved send rate:          3994.8 rec/s
effective accept rate:       3994.8 rec/s
drop percentage:             0.000%
================
```

### Stress mode, run 1

```
cargo run --release --example flush_decoupling_benchmark -- mode=stress duration_secs=30 target_rate=4000 upload_delay_ms=150
```

```
=== flush_decoupling_benchmark ===
BenchConfig {
    mode: "stress",
    duration_secs: 30,
    target_rate: 4000,
    upload_delay_ms: 150,
    max_buffer_rows: 50,
    channel_capacity: 256,
    flush_threshold_bytes: 18446744073709551615,
}

Sending sustained load: target_rate=4000 records/sec for 30 secs...
Send loop finished: 120000 records sent in 30.000s (achieved rate: 4000.0 rec/s)
Draining for 2s...

=== RESULTS ===
mode:                        stress
params:                      duration_secs=30 target_rate=4000 upload_delay_ms=150 max_buffer_rows=50 channel_capacity=256 flush_threshold_bytes=18446744073709551615
records sent:                120000
records written (durable):   35627
records dropped (channel):   0
records buffer_dropped(cap): 84173
wall-clock elapsed:          30.000s
achieved send rate:          4000.0 rec/s
effective accept rate:       4000.0 rec/s
drop percentage:             0.000%
================
```

### Stress mode, run 2

```
cargo run --release --example flush_decoupling_benchmark -- mode=stress duration_secs=30 target_rate=4000 upload_delay_ms=150
```

```
=== flush_decoupling_benchmark ===
BenchConfig {
    mode: "stress",
    duration_secs: 30,
    target_rate: 4000,
    upload_delay_ms: 150,
    max_buffer_rows: 50,
    channel_capacity: 256,
    flush_threshold_bytes: 18446744073709551615,
}

Sending sustained load: target_rate=4000 records/sec for 30 secs...
Send loop finished: 120000 records sent in 30.001s (achieved rate: 3999.9 rec/s)
Draining for 2s...

=== RESULTS ===
mode:                        stress
params:                      duration_secs=30 target_rate=4000 upload_delay_ms=150 max_buffer_rows=50 channel_capacity=256 flush_threshold_bytes=18446744073709551615
records sent:                120000
records written (durable):   35225
records dropped (channel):   0
records buffer_dropped(cap): 84629
wall-clock elapsed:          30.001s
achieved send rate:          3999.9 rec/s
effective accept rate:       3999.9 rec/s
drop percentage:             0.000%
================
```

(Baseline doc captured 2 stress runs, not just 1, from its own prior task scope — both
are reproduced here for completeness of the "before" evidence even though this task's
own Step 2 only requires 1 stress run "after".)

## "After" output (this branch, `dca6b52`)

### Realistic mode, run 1

```
cargo run --release --example flush_decoupling_benchmark -- mode=realistic duration_secs=30 target_rate=4000 upload_delay_ms=150
```

```
=== flush_decoupling_benchmark ===
BenchConfig {
    mode: "realistic",
    duration_secs: 30,
    target_rate: 4000,
    upload_delay_ms: 150,
    max_buffer_rows: 100000,
    channel_capacity: 256,
    flush_threshold_bytes: 104857600,
}

Sending sustained load: target_rate=4000 records/sec for 30 secs...
Send loop finished: 120000 records sent in 30.001s (achieved rate: 3999.9 rec/s)
Draining for 2s...

=== RESULTS ===
mode:                        realistic
params:                      duration_secs=30 target_rate=4000 upload_delay_ms=150 max_buffer_rows=100000 channel_capacity=256 flush_threshold_bytes=104857600
records sent:                120000
records written (durable):   100000
records dropped (channel):   0
records buffer_dropped(cap): 0
wall-clock elapsed:          30.001s
achieved send rate:          3999.9 rec/s
effective accept rate:       3999.9 rec/s
drop percentage:             0.000%
================
```

### Realistic mode, run 2

```
cargo run --release --example flush_decoupling_benchmark -- mode=realistic duration_secs=30 target_rate=4000 upload_delay_ms=150
```

```
=== flush_decoupling_benchmark ===
BenchConfig {
    mode: "realistic",
    duration_secs: 30,
    target_rate: 4000,
    upload_delay_ms: 150,
    max_buffer_rows: 100000,
    channel_capacity: 256,
    flush_threshold_bytes: 104857600,
}

Sending sustained load: target_rate=4000 records/sec for 30 secs...
Send loop finished: 119992 records sent in 30.000s (achieved rate: 3999.7 rec/s)
Draining for 2s...

=== RESULTS ===
mode:                        realistic
params:                      duration_secs=30 target_rate=4000 upload_delay_ms=150 max_buffer_rows=100000 channel_capacity=256 flush_threshold_bytes=104857600
records sent:                119992
records written (durable):   100000
records dropped (channel):   0
records buffer_dropped(cap): 0
wall-clock elapsed:          30.000s
achieved send rate:          3999.7 rec/s
effective accept rate:       3999.7 rec/s
drop percentage:             0.000%
================
```

### Stress mode, run 1

```
cargo run --release --example flush_decoupling_benchmark -- mode=stress duration_secs=30 target_rate=4000 upload_delay_ms=150
```

```
=== flush_decoupling_benchmark ===
BenchConfig {
    mode: "stress",
    duration_secs: 30,
    target_rate: 4000,
    upload_delay_ms: 150,
    max_buffer_rows: 50,
    channel_capacity: 256,
    flush_threshold_bytes: 18446744073709551615,
}

Sending sustained load: target_rate=4000 records/sec for 30 secs...
Send loop finished: 119996 records sent in 30.000s (achieved rate: 3999.8 rec/s)
Draining for 2s...

=== RESULTS ===
mode:                        stress
params:                      duration_secs=30 target_rate=4000 upload_delay_ms=150 max_buffer_rows=50 channel_capacity=256 flush_threshold_bytes=18446744073709551615
records sent:                119996
records written (durable):   37034
records dropped (channel):   0
records buffer_dropped(cap): 82797
wall-clock elapsed:          30.000s
achieved send rate:          3999.8 rec/s
effective accept rate:       3999.8 rec/s
drop percentage:             0.000%
================
```

## Comparison

### Summary table

| Metric | Before (run1/run2) | After (run1/run2) |
|---|---|---|
| Realistic — achieved send rate | 3999.8 / 3994.8 rec/s | 3999.9 / 3999.7 rec/s |
| Realistic — records written (durable) | 119180 / 119221 | 100000 / 100000 |
| Realistic — dropped (channel + cap) | 0 / 0 | 0 / 0 |
| Stress — records written (durable) | 35627 / 35225 (avg 35426) | 37034 (1 run) |
| Stress — buffer_dropped(cap) | 84173 / 84629 (avg 84401) | 82797 (1 run) |

### Realistic mode: no drops either way — this config does not stress the ingest path

At `target_rate=4000`, both before and after accept **100% of offered load with zero
drops** (`records dropped (channel): 0`, `records buffer_dropped(cap): 0` in every
realistic run, before and after). The "achieved send rate" is set by the benchmark's
own paced ticker (it sends at ~4000 rec/s regardless of how fast the backend is,
provided the backend keeps up), so it is expected to read ~4000 rec/s in both cases
and is **not** a signal of backend speed here — the backend was never the limiting
factor at this offered rate, before or after the change. This means realistic mode at
`target_rate=4000` cannot, by construction, demonstrate a throughput or drop-rate
improvement from this change: there was no backpressure ceiling being hit pre-change
for the change to move.

### The "records written (durable)" divergence is a flush-cadence artifact, not a throughput or durability regression

The most visible before/after difference is `records written (durable)`: baseline
flushes essentially everything sent (~99.3%, 119180-119221 out of 119984-119996),
while after this change it flushes **exactly 100000** in both runs, out of
119992-120000 sent (~83%). This looks like a large regression at first glance, but it
is not — tracing it through the source shows why:

- `records buffer_dropped(cap)` is **0 in every realistic run, before and after**. No
  record is ever lost. The ~20000 leftover records "after" this change are still
  correctly sitting in memory in the partition buffer at the moment metrics are
  snapshotted (2s after the send loop stops) — they simply haven't been flushed to the
  (fake, delayed) upload sink yet, because `flush_interval_secs=3600` and this
  benchmark's 32s runtime never reaches that age-based trigger for them.
- The realistic-mode flush is triggered by `FlushPolicy.max_rows=100000` (row-count
  cap) or `max_bytes=104857600` (100MB), whichever comes first. Verified directly
  against both commits' `push()`:
  - **Before** (`6435396`, `src/forwarding/buffered_writer.rs`): every record goes
    through the single per-record path — `buf.byte_count += est_bytes` happens on
    every push, using `RecordBatch::get_array_memory_size()` of a freshly-allocated,
    single-row batch. Single-row Arrow batches built via fresh per-record builders
    carry proportionally more allocation/capacity overhead per row than a batch built
    by appending 1000 rows into one shared builder, so the 100MB byte threshold is
    reached well before the 100000-row threshold, repeatedly, throughout the 30s run —
    producing several flush cycles and leaving only a small tail (~700-800 records,
    ~0.7%) unflushed at measurement time.
  - **After** (`dca6b52`, this branch): the amortized `ConnAccumulator` path defers
    `buf.byte_count` accounting to `materialize_live_builder`, which only runs every
    `BUILDER_BATCH_ROWS` (1000) rows or at a flush/shutdown decision point (see the
    design doc's "4-gap materialization audit", Task 3). With batched builders, the
    real byte cost per row is lower and byte accounting only advances every 1000 rows,
    so the byte threshold is never reached before the row-count threshold (100000) is
    — resulting in exactly **one** flush at row 100000, and the remaining ~20000
    records sit unflushed (but not dropped) in the buffer at the 2s-drain snapshot
    point.

In other words: this divergence reflects a **change in flush-triggering cadence**
caused by byte-accounting granularity, not a change in how many records the pipeline
can accept or durably persist under this workload. Both versions accept and eventually
would persist all sent records; the after-change buffer simply holds more
already-accepted, not-yet-uploaded rows in memory at the specific 32s mark this
benchmark snapshots.

### Stress mode: a small, directionally favorable, but not clearly-outside-noise signal

Stress mode (`max_buffer_rows=50`, `flush_threshold_bytes=usize::MAX`) exercises the
hard-cap/drop-oldest path this session's design doc explicitly frames as "a
config-size question, not a per-record-cost question" — a prior benchmarking effort
already validated this mechanism's correctness, so the task brief scoped this to a
single confirmatory "after" run rather than a noise-floor pair.

- Before: written 35627 / 35225 across 2 runs (avg 35426, ~29.5% of ~120000 sent);
  buffer_dropped 84173 / 84629 (avg 84401).
- After: written 37034 (1 run, ~30.9% of 119996 sent); buffer_dropped 82797.

The after run wrote about **4.5% more** records and dropped about **1.9% fewer** than
the before average — directionally consistent with the amortized builder path doing
slightly less per-record work and therefore completing marginally more flush cycles
inside the same 30s window under this heavily-capped, small-buffer stress
configuration. However: **this is not a confidently-attributable improvement.** The
before baseline's own two runs already vary by ~400 records (~1.1 percentage points)
run-to-run on this exact metric, and there is only a single "after" data point to
compare against — not a pair, so there is no after-side noise-floor estimate at all.
The observed after-vs-before-average delta (~4-5%) is close to the size of the
before-run's own internal spread. **We do not claim this as a proven improvement** —
it is a plausible, directionally-favorable single-run observation, not a
statistically supported percentage.

### What would a real improvement from this specific change look like, and did we see it?

This change targets `ZeekSink::to_record_batch`/builder-allocation cost specifically
(~500µs-1.3ms/record per the design doc's profiling) — not the channel/flush
machinery a prior benchmarking effort already validated. A real improvement from
*this* change, measured via *this* harness, would show up as one of:

1. **Higher sustained throughput before hitting the channel-full/backpressure ceiling
   at the same offered load** — not observable here, because realistic mode's
   `target_rate=4000` never approached that ceiling either before or after (0 drops
   both ways — see above). This benchmark configuration simply does not put enough
   offered load on the system to expose a backend-speed-limited ceiling.
2. **Lower drop counts at the same target rate under a configuration that does
   saturate the backend** — stress mode is the closest analog available here, and it
   does show a small directionally-favorable delta (4.5% more written, 1.9% fewer
   dropped), but per above this is a single run against a 2-run baseline with
   comparable internal spread, so it is suggestive at best, not conclusive.
3. **A directly-measured drop in per-record processing time** — this harness does not
   expose a per-record timing metric (no such counter exists in
   `flush_decoupling_benchmark.rs`); the ~500µs-1.3ms/record figure that motivated
   this whole change was measured separately (ad hoc, per the design doc), and a
   rigorous, regression-tracked per-record measurement was explicitly deferred to a
   future `criterion` microbenchmark — out of scope for this task, per the design
   doc's "Deferred Scope" section.

**Honest bottom line:** this benchmark run does not produce a defensible throughput or
drop-count percentage improvement claim, because the specific benchmark configuration
mandated by the task brief (`target_rate=4000`, realistic mode) was already fully
absorbed with zero drops before this change — there was no backpressure ceiling for
the change to move at this offered load, and the harness has no per-record timing
metric to observe the targeted cost directly. What this run *does* establish:

- **No regression.** Zero drops in realistic mode, before and after, across all runs.
  Stress-mode durability is at least as good after the change as before (slightly
  better, though within a range that could plausibly be noise given only one after-run).
- **The "written (durable)" gap between before/after in realistic mode is fully
  explained by a flush-cadence/byte-accounting-granularity difference** (traced to
  source, both commits), not by any record loss or capacity difference — `0` drops in
  every realistic-mode run confirms this.
- **This harness cannot, on its own, prove the per-record CPU-cost win** this change
  targets; that evidence remains the design doc's own profiling
  (~500µs-1.3ms/record dominant cost) plus the correctness/behavior-preservation
  testing already done in Tasks 1-5. A `criterion` microbenchmark for
  `ZeekSink::to_record_batch` specifically (mentioned in the design doc, explicitly
  deferred scope) would be the right tool to produce a rigorous, regression-tracked
  per-record timing comparison — that work is not part of this task.

## Files changed

- Created: `docs/superpowers/specs/2026-07-24-record-batch-amortization-benchmark-results.md` (this file)

## Self-review

- **Exact commands, commit hashes, and full verbatim output for every run (before and
  after):** present — commands shown per-run, `6435396a99a4aa960befcb7a68505db122abd1b4`
  (before) and `dca6b520384987668475f56fd13fdf7bb6f1a84e` (after) recorded up top and
  verified with `git merge-base --is-ancestor`, all 2 realistic + 1 stress "after" runs
  and all baseline runs reproduced in full (not truncated/summarized).
- **Honest comparison, explicit about noise:** yes — the stress-mode section
  explicitly states the observed delta (~4-5%) is close to the before-run's own
  internal spread and declines to claim a supported percentage improvement from it.
  The realistic-mode section explicitly states that configuration cannot demonstrate a
  throughput/drop improvement at all (zero drops both ways, rate is ticker-paced not
  backend-limited).
- **Correct framing of what a real improvement here would look like:** yes — the
  "What would a real improvement... look like" section explicitly lays out the 3
  concrete forms an improvement could take for *this specific* change (schema/builder
  cost, not channel/flush machinery) and honestly states which of the 3 this benchmark
  run can and cannot speak to, rather than reciting the raw written/dropped numbers
  without interpretation.
- One additional finding surfaced during this review that is worth flagging
  explicitly rather than glossing over: the `records written (durable)` metric's
  divergence initially looked like a serious regression (83% vs 99.3%) before tracing
  it to source. This doc calls that out prominently and explains the mechanism with
  reference to the exact code in both commits, rather than either hiding it or
  reporting it uninterpreted as a regression.

## Issues or concerns

- The stress-mode comparison is inherently weaker evidence than the realistic-mode
  comparison because the task brief scoped it to a single "after" run (correctly, per
  its own stated reasoning that stress mode is a config-size question already
  validated elsewhere) — this doc flags that weakness explicitly rather than
  presenting the single-run stress delta with unwarranted confidence.
- This benchmark harness, run under the exact parameters this task's brief specifies,
  is not capable of directly proving the per-record CPU-cost improvement that
  motivated this whole change (see "Honest bottom line" above). That is a property of
  the chosen harness/parameters, not a defect in the amortization change itself — the
  design doc's own profiling and Tasks 1-5's correctness testing remain the primary
  evidence for the change's value. A future `criterion` microbenchmark (already
  identified as deferred scope in the design doc) would close this gap.
