# Flush-Decoupling Throughput Benchmark — Results

**Benchmark:** `examples/flush_decoupling_benchmark.rs`
**Compared commits:** pre-fix `eef9be3` vs post-fix (fixed) `e651eda`
**Date measured:** 2026-07-24

## 1. What the benchmark does

`examples/flush_decoupling_benchmark.rs` wires a real end-to-end Zeek TCP
ingest pipeline:

- A real `logthing::zeek::listener::ZeekListener` bound to an ephemeral
  `127.0.0.1` port, driven by a real `tokio::net::TcpStream` client sending
  real NDJSON lines (`{"_path":"conn","uid":"C<n>"}\n`).
- A real `logthing::forwarding::zeek_s3::ZeekSink` (the actual "conn"-schema
  Arrow mapping cost logthing pays in production), plumbed into a real
  `ParquetWriterHandle<ZeekSink>` (the code under test —
  `src/forwarding/buffered_writer.rs`).
- A custom `UploadSink` that sleeps `upload_delay_ms` and returns `Ok(())`
  instead of doing a real S3 PUT — deliberately decoupling the ingest/
  buffering path's own throughput from real storage-backend variability
  (per this repo's `docs/superpowers/specs/2026-07-05-performance-testing-strategy-design.md`
  §6 rationale).
- A REAL global `metrics_exporter_prometheus::PrometheusBuilder` recorder
  (installed exactly like production's `start_metrics_server` in
  `src/server/mod.rs`), not the thread-local `DebuggingRecorder` used in this
  repo's own test code (which has a documented cross-thread visibility gap
  on a multi-threaded runtime).

The client sends sustained load for `duration_secs`, paced to `target_rate`
records/sec via a 1ms ticker (batching multiple lines per tick at high
rates rather than chasing sub-millisecond timer precision), then the
harness waits a fixed 2-second drain period and reads real Prometheus
counters:

- `parquet_s3_records_written{source="zeek",target="bench"}` — durably flushed
- `parquet_s3_dropped{source="zeek",target="bench"}` — **channel-full drops**
  (this is the specific failure mode the flush-decoupling fix targets: the
  writer's background task blocking its own channel-drain loop on an
  in-flight flush, causing `try_send` to fail once the bounded channel fills)
- `parquet_s3_buffer_dropped{source="zeek",target="bench"}` — hard-cap drops
  (a separate, pre-existing safety valve: when a partition's flush is
  already in flight and its live buffer grows past `4 × max_buffer_rows`,
  the oldest buffered rows are dropped rather than growing memory
  unboundedly)

Two modes:

- **`realistic`**: production defaults — `max_buffer_rows=100000`,
  `flush_threshold_bytes=104857600` (100 MiB), `channel_capacity=256`.
- **`stress`**: `max_buffer_rows=50`, `flush_threshold_bytes=usize::MAX`
  (only the row threshold matters), `channel_capacity=256` unchanged —
  forces frequent flushing to isolate and quantify the maximum benefit the
  decoupling provides.

## 2. Final comparison parameters

```
mode=realistic duration_secs=30 target_rate=4000 upload_delay_ms=150
mode=stress    duration_secs=30 target_rate=4000 upload_delay_ms=150
```

### Parameter-tuning notes (Part 2)

`target_rate=4000` (the spec's documented default) was tried first and
immediately produced a clearly discriminating result on the **fixed**
(post-decoupling, `e651eda`) code itself: `realistic` mode showed a 0.02–0.04%
channel-drop rate (i.e. effectively none), and `stress` mode showed 0%
channel drops. Both are the expected "healthy" outcome for the fixed code.
The deciding question per the task instructions was whether 4000 rec/s is
demanding enough that the **old** code would clearly struggle — it is: at
this same rate, the pre-fix binary showed 31% channel-drop in `realistic`
mode and 91.9% channel-drop in `stress` mode (below). Since the gap between
pre-fix and post-fix at 4000 rec/s is already extremely large and every
configuration reproduced within ~1% across two independent 30-second runs
(see §5), no further rate escalation (8000/15000) was necessary — 4000
rec/s was kept for the final comparison. `upload_delay_ms=150` and all
other flags were left at their documented defaults throughout.

## 3. Results: `realistic` mode (production-default thresholds)

| Metric | Pre-fix (`eef9be3`) | Post-fix (`e651eda`) |
|---|---:|---:|
| Records sent | 120,000 | 120,000 |
| Records written (durable) | 82,236 | 119,295 |
| Records dropped — channel-full | **37,192** | **26** |
| Records buffer-dropped — hard cap | 0 | 0 |
| Wall-clock elapsed | 30.001 s | 30.002 s |
| Achieved send rate | 3,999.8 rec/s | 3,999.8 rec/s |
| Effective accept rate | 2,760.1 rec/s | 3,998.9 rec/s |
| **Drop percentage (channel-full)** | **30.993 %** | **0.022 %** |
| Fraction durably written | 68.5 % | 99.4 % |

## 4. Results: `stress` mode (small thresholds, isolates max benefit)

| Metric | Pre-fix (`eef9be3`) | Post-fix (`e651eda`) |
|---|---:|---:|
| Records sent | 120,000 | 119,996 |
| Records written (durable) | 9,750 | 35,426 |
| Records dropped — channel-full | **110,244** | **0** |
| Records buffer-dropped — hard cap | 0 | 84,563 |
| Wall-clock elapsed | 30.001 s | 30.007 s |
| Achieved send rate | 3,999.9 rec/s | 3,998.9 rec/s |
| Effective accept rate (channel-only) | 325.2 rec/s | 3,998.9 rec/s |
| **Drop percentage (channel-full)** | **91.870 %** | **0.000 %** |
| Fraction durably written | 8.1 % | 29.5 % |

## 5. Consistency check

Every one of the four configurations above was run twice (30 s each,
independent processes). Results were stable run-to-run:

| Config | Run 1 drop% (channel) | Run 2 drop% (channel) |
|---|---:|---:|
| Post-fix, realistic | 0.022 % | 0.036 % |
| Post-fix, stress | 0.000 % | 0.000 % |
| Pre-fix, realistic | 30.993 % | 31.226 % |
| Pre-fix, stress | 91.870 % | 91.870 % |

Post-fix stress-mode `written`/`buffer_dropped` counts matched almost
exactly across the two runs (35,426 vs 35,426 written; 84,563 vs 84,522
buffer-dropped), and pre-fix `written` matched exactly (82,236 vs 82,236;
9,750 vs 9,750). This gives confidence the numbers quoted above are real,
reproducible measurements rather than noise.

## 6. Interpretation

**Yes — the data clearly supports "the decoupling improves throughput,"**
specifically on the exact failure mode it was built to fix (channel-full
drops from the writer task blocking on an in-flight flush):

- **Realistic mode** (production-default thresholds, the "does it matter
  under normal settings" question): channel-full drops fell from **31.0%
  to 0.02%** of sent records — roughly a **1,400×** reduction — and the
  fraction of records durably written rose from 68.5% to 99.4%. This is not
  a marginal difference; under normal production thresholds and a realistic
  100ms-order flush latency, the pre-fix code was silently discarding
  nearly a third of all Zeek records under this sustained load, and the
  post-fix code discards almost none.
- **Stress mode** (isolating the maximum benefit): channel-full drops fell
  from **91.9% to 0.000%** — a complete elimination in this benchmark run.
  Durable-write fraction rose 3.6× (8.1% → 29.5%).

**Caveat — read the stress-mode "durable write" numbers carefully.** Under
`stress` mode's artificially tiny thresholds, most records still don't end
up durably written even post-fix (70.5% are hard-cap-dropped via
`parquet_s3_buffer_dropped`, a separate, pre-existing safety-valve
mechanism, not the bug this fix addresses). This is expected and by
design, not a shortcoming of the fix: with `max_buffer_rows=50` and a
single hot "conn" partition, only one flush can be in flight per partition
at a time, so the partition's durable-write ceiling is fundamentally
bounded by `max_buffer_rows / (encode + upload_delay)` ≈ 50 rows /
150 ms ≈ 333 rec/s — well under the 4,000 rec/s offered load, independent
of whether flushes are decoupled from channel-draining or not. What the
fix changes is *where* the resulting backpressure surfaces: pre-fix, it
surfaced as blind channel-full drops (no visibility into which partition
was over capacity, and the writer's own ingest loop stalled); post-fix, it
surfaces as the existing, accounted-for, per-partition hard-cap mechanism,
while the channel itself never backs up and the ingest loop keeps
draining. The realistic-mode result is the more representative measure of
the fix's real-world impact, since production `max_buffer_rows` (100,000)
is far above what a single flush cycle needs to absorb between uploads.

**Bottom line:** under sustained load that a synchronous-flush writer
cannot keep up with, the flush-decoupling fix eliminates channel-full
record drops (the diagnosed production bug) almost entirely, and under
realistic production thresholds increases the fraction of records durably
written from roughly two-thirds to effectively all of them.

## 7. Reproducing

```sh
export CC=/usr/bin/gcc CXX=/usr/bin/g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
source ~/.cargo/env

# Post-fix (this worktree, commit e651eda):
cargo run --release --example flush_decoupling_benchmark -- mode=realistic duration_secs=30 target_rate=4000 upload_delay_ms=150
cargo run --release --example flush_decoupling_benchmark -- mode=stress    duration_secs=30 target_rate=4000 upload_delay_ms=150

# Pre-fix (separate worktree at eef9be3, benchmark file copied in — not committed there):
git worktree add /tmp/logthing-prefix-benchmark eef9be3
cp examples/flush_decoupling_benchmark.rs /tmp/logthing-prefix-benchmark/examples/
cd /tmp/logthing-prefix-benchmark
cargo run --release --example flush_decoupling_benchmark -- mode=realistic duration_secs=30 target_rate=4000 upload_delay_ms=150
cargo run --release --example flush_decoupling_benchmark -- mode=stress    duration_secs=30 target_rate=4000 upload_delay_ms=150
```
