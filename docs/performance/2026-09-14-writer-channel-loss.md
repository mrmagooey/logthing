# Writer-channel loss: why the IPFIX writer drains at ~5k/s against a 65k/s bench, 2026-09-14

**Git commit this investigation was run against:** `a24f58e` (branch
`perf/writer-channel-loss`, based on `perf/recv-decode-decouple`). Diagnosis only — no
production code was changed.

## 0. Correction to the starting brief

The brief that opened this investigation stated `default_ipfix_channel_capacity()` = 100,000.
That number is wrong — it is `default_ipfix_max_buffer_rows()` (`src/config/mod.rs:943-945`,
hardcoded `100_000`), a completely different knob. The actual channel capacity, read from
`src/forwarding/channel_budget.rs`:

```rust
pub const CHANNEL_BUDGET_BYTES: usize = 100 * 1024 * 1024;          // line 70
pub const fn capacity_for(bytes_per_record: usize) -> usize {        // line 76
    ... CHANNEL_BUDGET_BYTES / bytes_per_record ...
}
pub const IPFIX_DATAGRAM_BYTES: usize = 9216;                        // line 198
```

`104_857_600 / 9216 = 11_377`. **The IPFIX writer channel holds 11,377 items, not 100,000.**
Each item is one `Vec<FlowRecord>` (one `try_send` = one datagram's worth of flows), and the
loadgen's `ipfix-udp` subcommand sends exactly one flow per datagram
(`tools/loadgen/src/ipfix_udp.rs:13-17`), so in this workload one channel slot = one flow record.
11,377 slots at a 20,000/s arrival rate is **~0.57s of burst headroom** — the channel fills
almost instantly under sustained load at this rate; this is directly visible in the gauge trace
below. This correction changes the shape of the diagnosis: the channel isn't a deep buffer that
takes 12x too long to drain — it's a shallow buffer that any drain-rate shortfall overflows in
under a second.

## 1. What was run

- **Build:** `cargo build --release --bin logthing` / `-p loadgen`, and separately
  `cargo build --profile profiling --features pprof` for the CPU profile.
- **Shape:** real `[ipfix.local]` Parquet sink, writing to a tmpdir (no S3/MinIO).
- **Load:** `loadgen ipfix-udp --target-rate 20000 --duration-secs 15` (achieved 19,997.7-19,998.8
  flows/s in both runs below) — same rate/duration/shape as
  `docs/performance/2026-09-14-throughput-baseline-repeats.md`.
- **Config:** all `[ipfix.local]` defaults — `max_buffer_rows=100_000`,
  `flush_threshold_bytes=100 MiB`, `flush_interval_secs=900`, `channel_capacity=11_377`
  (corrected above). Nothing overridden.
- **Two runs:**
  1. Release build, gauges (`parquet_s3_channel_available`, `parquet_s3_channel_queued`,
     `parquet_s3_buffer_rows`, `parquet_s3_flushes_in_flight`, plus the two drop counters and the
     write/upload counters) sampled once per second over `/metrics` for the full run and 6s of
     drain-tail.
  2. Profiling build (`--features pprof`), same shape/rate, 15s sampling window at 99 Hz,
     `pprof_selftime` run against the resulting `profile.pb`.

## 2. Measured breakdown

| | run A (gauge-sampled) | baseline doc, run 1 (for comparison) |
|---|---:|---:|
| offered | 299,980 | 299,934 |
| `ipfix_datagrams_received` | 288,718 | 289,038 |
| `ipfix_socket_drops` (kernel) | 11,263 | 10,897 |
| `parquet_s3_dropped{source="ipfix"}` | 216,257 | 205,495 |
| `parquet_s3_buffer_dropped{source="ipfix"}` | **never emitted (0)** | not reported, consistent with 0 |
| `parquet_s3_records_written` (final, incl. drain-tail) | 71,335 | — |
| `parquet_s3_uploads` (final) | 49 | — |
| writer "consumed" (received − dropped) | 72,461 | 83,543 |

**The counter that fired is `parquet_s3_dropped{source="ipfix",target="local"}`** — the
`try_send`-full channel-drop counter (`buffered_writer.rs:1875`/`1938`). `parquet_s3_buffer_dropped`
(the hard-cap `drop_oldest_to_cap` eviction counter, `buffered_writer.rs:1390`) never incremented
in either run — metrics-exporter-prometheus doesn't publish a counter until it's touched, and it
never appears in either run's `/metrics` output. This matters: the hard cap
(`max_buffer_rows * 4` = 400,000 rows) was never approached, because — see §4 — the single buffer
this sink ever has gets flushed and reset roughly every 1,450 rows, nowhere near 400,000.

Writer drain rate: run A's window-normalized rate is **~4,300-4,800/s** (64,517 records written by
t=15s / 15s ≈ 4,301/s; 71,335 total / ~17s including drain-tail ≈ 4,196/s), the baseline doc's run
1 is **~5,570/s** (83,543/15s). Both land in the same order of magnitude, and the baseline doc's
own 5-run table shows a ~3x spread on the *kernel*-loss side alone, so this is consistent
run-to-run variance, not a contradiction. Against the criterion bench's 15.44 µs/flow
(`docs/performance/2026-09-13-criterion-baseline-0.18.0.md:117`, i.e. 64,767/s theoretical
single-core ceiling for one `to_record_batch` call), the measured drain rate is **~12-15x lower**.

## 3. Gauge behavior across the run

```
t   channel_available  channel_queued  buffer_rows  flushes_in_flight  dropped  records_written  uploads
0   11377              0               0            0                  0        0                0
1   0                  11377           0            1                  4104     4436             4
3   4                  11373           0            1                  37332    14920            11
6   0                  11377           0            1                  85112    28371            23
9   4                  11373           0            1                  137441   39973            30
12  0                  11377           0            1                  190533   52693            39
14  0                  11377           0            1                  216257   60869            44
15  4200               7177            0            1                  216257   64517            46   <- load stops here
17  11377              0               0            0                  216257   71335            49   <- channel fully drained
```

Reading this:

- **The channel is completely full (0-4 slots free out of 11,377) for the entire 14-second load
  window**, from t=1 onward. It never has meaningful headroom once load starts. This is the
  direct, mechanical cause of the drop counter firing continuously — not a one-time burst
  overflow, a *sustained* full-channel state for the whole run.
- **`flushes_in_flight` sits at 0 or 1 for the entire run, never higher.** This is expected, not a
  sign of the flush semaphore throttling anything: `IpfixSink::partition()` always returns `None`
  (`ipfix_s3.rs:264-266`), so every record lands in exactly **one** partition/day buffer, and
  `try_flush_partition_async` refuses to start a second flush for a partition that already has one
  in flight (`buffered_writer.rs:1131-1139`). With one partition, at most one flush can ever be
  in-flight regardless of the semaphore's configured concurrency — the semaphore is not the
  bottleneck (candidate #3, eliminated).
- **`buffer_rows` reads 0 at every sample, but this is a real reading, not a stale/dead gauge.**
  `update_buffer_gauges()` (the function that would show row_count *mid-accumulation*) only runs
  off the writer's main ticker, whose period is `flush_check_interval(flush_interval_secs)` =
  `max(900s, 1s)` = **900 seconds** at this config's defaults
  (`s3_sink.rs:137-139`) — it cannot fire even once in a 15-21s test. What *does* update
  `parquet_s3_buffer_rows` inside the test window is `refresh_partition_gauge`
  (`buffered_writer.rs:1272-1284`), called every time a flush completes and fully drains a
  partition's buffer to zero rows (`buffered_writer.rs:1216`) — which, per the uploads count
  below, happens roughly every 300ms. The gauge reads 0 because the buffer is repeatedly and
  rapidly reset to 0, not because it never accumulates anything.
- **49 uploads landed in 15s — one every ~300ms** — each writing ~10-24 KB Parquet files to the
  tmpdir (confirmed by listing the 49 files afterward: sizes 10-24 KB, all in the same
  `year=2026/month=09/day=15/` partition, consistent with the single-buffer/single-day finding).
  At `flush_interval_secs=900` and `flush_threshold_bytes=100 MiB`, this configuration should
  flush once, maybe twice, in a 15-second run — not 49 times. **This mismatch is the finding.**

## 4. Why the writer flushes 49 times instead of ~1 — and why that starves the drain rate

`records_written / uploads` = 71,335 / 49 ≈ **1,456 rows per flush**. Working backward from the
100 MiB byte-threshold trigger (`buffered_writer.rs:974-976`,
`self.policy.max_bytes` = `default_ipfix_flush_bytes()` = 100 MiB): triggering every ~1,456 rows
implies the writer believes each row costs `104,857,600 / 1,456 ≈ 72,026 bytes`. A real
`FlowRecord`'s Parquet-relevant payload is on the order of a few hundred bytes (19 mostly
fixed-width columns, two short strings, one small JSON blob) — nowhere near 72 KB.

The reason: `IpfixSink` has **no live-builder / `RecordBatchAccumulator`** — it's the only
`ParquetSink` in this comparison that doesn't opt into `new_batch()` (confirmed: only `ZeekSink`
overrides it, `zeek_s3.rs:149`; `IpfixSink`'s trait impl, `ipfix_s3.rs:257-312`, has no override,
so `push()` falls to the default `new_batch` returning `None`, `buffered_writer.rs:91-99`). So
every single push — one `FlowRecord` in this workload — builds a **brand-new**
`FlowRecordBuilders` (`ipfix_s3.rs:103-135`, 19 separate Arrow builders, all constructed via
plain `::new()`, no `with_capacity` hint) and immediately calls `.finish()` on it for exactly one
row.

Two independent arrow-rs facts compound here:

1. `PrimitiveBuilder::new()` = `with_capacity(1024)` and `GenericByteBuilder::new()`
   (`StringBuilder`) = `with_capacity(1024, 1024)`
   (`arrow-array-53.4.1/src/builder/primitive_builder.rs:143-144`,
   `.../generic_bytes_builder.rs:39-40`) — every one of the 19 builders allocates space for 1,024
   rows even though exactly 1 row is appended.
2. `ArrayData::get_array_memory_size()` (`arrow-data-53.4.1/src/data.rs:500-514`) sums
   **`buffer.capacity()`**, not used length — it reports the full 1,024-row allocation, not the
   1-row payload actually held.

Summing the default-capacity allocation across the 19-column `FlowRecord` schema
(`ipfix_s3.rs:28-67`: 6 non-nullable + 13 nullable columns, 4 of them `Utf8`) by hand gives
**~93 KB** per single-row batch — the same order of magnitude as the ~72 KB the observed flush
cadence implies independently. These are two independently-derived numbers (one from arrow-rs's
own default-capacity constants, one from back-solving the observed upload cadence against the
configured threshold) landing within ~25% of each other; that agreement is the strongest evidence
in this document; the buf.byte_count that `push()` accumulates
(`buffered_writer.rs:895-964`, `byte_delta = est_bytes` from `get_array_memory_size()`) is not
tracking real bytes, it's tracking builder capacity, and it crosses the 100 MiB trigger roughly
30-90x more often than the config's stated 900s/100MiB policy intends.

Each of those 49 premature flushes then pays for `arrow::compute::concat_batches` over ~1,456
**separate, single-row** `RecordBatch`es (`buffered_writer.rs:1467,1475`) inside
`tokio::task::spawn_blocking` — an O(number of batches) merge, not O(rows), so it's paying
per-batch overhead 1,456 times for what could be one batch. This runs on the blocking thread pool,
which shares the same physical cores as the async recv/decode/writer tasks on this 12-vCPU host —
it doesn't block the writer's `select!` loop structurally (the flush is spawned, not awaited
inline), but it does consume CPU cycles those tasks need, on a host with no headroom to spare.

## 5. CPU profile of the writer under this exact load

`cargo build --profile profiling --features pprof`, then
`RATE=20000 DURATION=15 DELAY=3 FORWARD=true scripts/profile-ipfix-udp.sh` (representative:
2,970 samples at 99 Hz), self-time via `examples/pprof_selftime.rs`:

| self-time | % of 2,970 leaf samples | frame |
|---:|---:|---|
| 486 | 16.36% | `posix_memalign` |
| 342 | 11.52% | `free` |
| 259 | 8.72% | `malloc` |
| 249 | 8.38% | `__lll_lock_wake_private` |
| 205 | 6.90% | `recvfrom` |
| 123 | 4.14% | `__lll_lock_wait_private` |
| 118 | 3.97% | `atomic_sub` |
| 84 | 2.83% | `epoll_wait` |
| 66 | 2.22% | `atomic_add` |
| 60 | 2.02% | `mprotect` |
| 33 | 1.11% | `alloc::alloc::alloc` |
| ~12 | ~1.65% total | IPFIX decode functions (`ie_info`, `parse_ipfix_data_set`, `decode_datagram`, `apply_field_to_record`, `decode_ipfix`, combined) |
| 6 | 0.20% | `<Sender<Vec<FlowRecord>>>::try_send` |

Allocator-family frames (`posix_memalign` + `free` + `malloc` + `alloc::alloc::alloc` +
`mprotect` + `aligned_malloc`, the last at 0.34%) sum to **~40.1%** of all sampled CPU time,
process-wide. Lock/futex frames (`__lll_lock_wake_private` + `__lll_lock_wait_private`) sum to
**~12.5%**. Together, over half the process's sampled CPU time is malloc/free/lock traffic, not
decode (~1.65%) or the channel send itself (0.20%).

This independently reproduces the prior recv-path investigation's headline split — "allocator
39.44% / futex 13.18%" — to within a point, on a profile taken specifically under the real-writer
shape this document is about. No individual frame inside `to_record_batch`,
`append_flow_record`, or `concat_batches` shows up with large self-time on its own; that's
expected — their cost is the malloc/free calls they make, which the allocator itself attributes
the time to as the leaf frame. This is consistent with, and does not contradict, §4's
code-level account: 19 fresh builder allocations per single-row push, freed again moments later,
83,000+ times over 15 seconds, plus 49 `concat_batches` calls each touching ~1,456 batches' worth
of tiny buffers.

## 6. Ranked candidates, with the number that supports or eliminates each

| # | Candidate | Verdict | Evidence |
|---|---|---|---|
| 1 | Flush cadence (interval/threshold too aggressive by config) | **Eliminated as configured; re-implicated via a bug** | Configured cadence is 900s/100 MiB, which should not fire in a 15s run. It fires 49 times because `byte_count` is inflated ~300-450x above real payload size (§4) — the *config* is not the problem, the *byte estimator* is. |
| 2 | `spawn_blocking` encode + disk write serializing the drain loop | **Structurally eliminated, practically implicated** | Flushes are `self.flush_tasks.spawn(...)` (`buffered_writer.rs:1160`), not awaited inline — the `select!` loop is never blocked waiting on a flush. But the spawned work still burns CPU cycles on the same core pool (§4, §5) — same *effect* (writer starved of cycles) via a different *mechanism* (contention, not blocking). |
| 3 | Flush concurrency limit (semaphore) | **Eliminated** | Only one partition ever exists (`partition()` always `None`), so at most one flush is ever in-flight regardless of the semaphore's configured limit (gauge trace, §3: `flushes_in_flight` never exceeds 1). |
| 4 | Per-record cost above what the bench measures | **Primary, with a specific mechanism identified** | The bench (`benches/ipfix_flow_batch_to_record_batch.rs`) measures exactly the code path used in production for a 1-flow datagram — so its 15.44µs already includes one fresh-builder-allocation-and-finish cycle. What it does *not* measure is (a) 49x `concat_batches` over ~1,456 tiny batches each, and (b) allocator lock contention when this per-push allocation pattern runs concurrently with everything else the process is doing. §5's profile (40% allocator, 12.5% futex) is the direct evidence for (b); §4 is the direct evidence for (a). |
| 5 | tmpdir/local-disk I/O | **Eliminated** | 49 uploads of 10-24 KB files in 15s is trivial disk load by any standard; `ZSTD_cwksp_clean_tables` (compression) is 0.34% of profile samples; no fsync/write syscall shows up with meaningful self-time. |
| 6 | Something else (channel capacity itself) | **Amplifier, not root cause** | The corrected capacity (11,377, not 100,000; §0) means any drain shortfall converts to `try_send` failures within ~0.6s. It explains why the *symptom* (drops) appears so completely and immediately, but a bigger channel would only delay the drop, not fix the ~12-15x drain-rate gap driving it. |

## 7. Verdict: bug, not capacity, not primarily environment

**This is a bug**, not the writer correctly shedding load it genuinely cannot persist at 19k/s,
and not primarily an artifact of the test host. Three independent lines of evidence converge on
the same mechanism:

1. **Config-vs-behavior mismatch**: the operator-visible policy (900s / 100 MiB) and the
   observed behavior (49 flushes / 15s) disagree by 1-2 orders of magnitude, traced to a specific
   line of reasoning (`get_array_memory_size()` reporting allocated capacity, not used bytes, on
   freshly-`::new()`'d builders) — not to any documented, intentional backpressure design.
2. **A working counterexample exists in the same file tree**: `ZeekSink` implements the
   amortized live-builder path (`new_batch`/`RecordBatchAccumulator`) specifically to avoid this
   per-record allocation cost; `IpfixSink` simply never got the same treatment. This is an
   unaddressed gap, not a considered tradeoff — nothing in `ipfix_s3.rs` or the buffered-writer
   design docs states single-row-per-push is intended for a source shaped like IPFIX (many
   independent small datagrams, each becoming its own `Vec<FlowRecord>` of length 1 in the common
   case).
3. **The CPU profile has almost no room left for genuine work**: ~1.65% decode, 0.20% channel
   send, versus ~52.6% malloc/free/lock traffic. A writer that was correctly saturated by real,
   unavoidable per-record work would show that work in the profile; this one shows the profile
   dominated by allocation churn from a fixable code pattern.

**Hardware caveat (carried forward, and specifically qualified for this finding):** this is a
12-vCPU QEMU/KVM guest with no `cpufreq` interface, generator and server sharing the same core
pool — exactly the environment section 5's profile was captured on. The *severity* of the
allocator/futex contention (40%+12.5% of CPU) is plausibly worse here than on real hardware with
more physical cores, a less-contended allocator, or the generator on a separate host — contention
is, by definition, a function of how many things compete for the same locks/arenas at once. But
the *structural* cause — a fresh 19-builder full allocation for every single-row push, and a
byte-accounting bug that turns a 900s/100MiB policy into a 300ms/72KB one — is a property of the
code, not the host. It would cost real CPU cycles and cause real premature flushing on any
hardware; only the *proportion* of total time consumed by contention (vs. by the allocation work
itself) would plausibly shrink on a less-contended machine. Local disk I/O specifically (the other
named environment variable) is ruled out directly by §6 row 5 — the file sizes and profile don't
support it as a contributor at all, on this host or any other.

## 8. What would settle anything still open

- **Per-push allocation byte count, measured directly** (a counting-allocator test in the style of
  `tests/channel_budget_allocator.rs`, applied to one `IpfixSink::to_record_batch` call for a
  1-row `Vec<FlowRecord>`) would replace the two independent ~72-93 KB *estimates* in §4 with an
  exact figure, and would directly confirm or refute the "builder capacity, not real bytes" causal
  chain without inferring it from flush cadence.
- **Per-task (not process-wide) CPU attribution** — the pprof profile in §5 is process-wide; it
  cannot currently distinguish "the writer task's own thread is malloc-bound" from "the
  recv/decode task is malloc-bound and starving the writer of scheduler time." Tokio-console, or a
  profiler with per-task or per-OS-thread grouping, would settle whether the contention is
  self-inflicted by the writer or imposed on it by its neighbors.
- **A direct experiment**, not implemented here per this task's scope: construct
  `FlowRecordBuilders` with `Builder::with_capacity(records.len())` instead of `::new()` for the
  existing single-call `to_record_batch` path (no live-builder architecture change required) and
  re-run this exact reproduction. If the flush cadence normalizes toward ~1 flush per 15s and the
  drain rate rises materially toward the 64,767/s bench ceiling, that confirms §4's mechanism as
  sufficient on its own, without needing to also add IPFIX to the `RecordBatchAccumulator` path.
- **A repeat on hardware with more cores than are shared with the generator**, or with the
  generator on a separate physical/VM host, to separate the environment's contribution to the
  40%/12.5% profile split from the code's.

## 9. Is the fix one line? No — say so and stop, per this task's scope

It is not. The two candidate fixes both require judgment calls this task is explicitly scoped not
to make: (a) give `IpfixSink` a `with_capacity`-sized `FlowRecordBuilders` per push (small, but
changes byte-accounting semantics shared by every `ParquetSink` implementation, not just IPFIX —
`get_array_memory_size()`-based `byte_delta` is generic machinery in `push()`,
`buffered_writer.rs:895-964`), or (b) implement a `RecordBatchAccumulator` for IPFIX matching
Zeek's pattern (a real structural addition, not a one-liner, and one that would need its own
design pass given IPFIX's per-datagram-batch `Vec<FlowRecord>` `Record` type differs from Zeek's
per-record type). Neither is implemented here. Diagnosis only, as instructed.
