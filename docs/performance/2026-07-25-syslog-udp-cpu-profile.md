# `syslog-udp` CPU profile: where the time actually goes, 2026-07-25

**Git commit this profile was captured against:** `a3c351b9b7cd214ed9aaf011d56c443361982b82`
(branch `perf/cpu-profiling-instrumentation`).

**This document reconciles a top-down flamegraph against the ~94.6µs/datagram figure from
`docs/superpowers/specs/2026-07-25-cpu-profiling-instrumentation-design.md` §1.1.** It does not reproduce that figure —
see the logging caveat in §5 for why not — but it does independently corroborate the design
doc's §1.3 correction to `2026-07-24-performance-improvements-plan.md` §2.1 (§4 below).

## 1. What was run

- **Format/subcommand:** `loadgen syslog-udp` against `logthing`'s syslog UDP listener, with an
  in-process `pprof` sampler (`ITIMER_PROF`, `SIGPROF`) added by Tasks 1-6 of this plan
  (`--features pprof`, gated out of default builds).
- **`logthing` build profile:** `[profile.profiling]` (optimized + debuginfo), built with
  `--features pprof`.
- **Persistence target:** `LocalDiskSink` (`tools/loadgen/ci/logthing-baseline.toml`), same
  config file the 2026-07-24 baseline used — local disk, not MinIO, for the same reason: isolate
  the ingestion/parsing/buffering path from S3/network/Docker variables.
- **`parse_payloads`:** `true` — the structured-payload dispatch chain
  (`syslog::payload::dispatch`) runs on every message, not just raw persistence.
- **Logging level forced to `error`** for the duration of the capture. This is not the same
  regime as the `info`-level figure being reconciled against — see §5, caveat 1.
- **Buffer-policy values in effect:** unchanged from the 2026-07-24 baseline (`max_buffer_rows =
  10_000`, `flush_interval_secs = 900`, `channel_capacity = 4_096`, no byte-size trigger —
  `syslog_local_start()` hardcodes `usize::MAX`). Not the axis under test here, restated for the
  "never compare across differing flush-policy configs" rule.
- **Sampler parameters:** `HZ=99`, `DELAY=5s` (sampling starts 5s into the load so the window
  sits inside steady state, not startup), `DURATION=30s` (sampling window length). Load itself
  ran for `DELAY + DURATION + 10 = 45s` so the load outlives the sampling window on both sides.
- **Offered rate:** `RATE=50000` datagrams/sec (`scripts/profile-syslog-udp.sh` default).

**Exact command run to capture this profile** (per the brief, already executed before this
task — **not re-run**, per instruction, since it rewrites `logthing.toml`/`logthing.admin.toml`
for its duration and takes ~60s):

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
RATE=50000 DURATION=30 DELAY=5 bash scripts/profile-syslog-udp.sh
```

Artifacts consumed by this write-up, all under `profiling-results/`:
`flamegraph.svg` (762,375 bytes), `profile.pb` (457,767 bytes — raw pprof protobuf),
`profile-metadata.json` (below).

## 2. Representativeness

`profile-metadata.json`, written by the sampler at the end of the run:

```json
{
  "sample_count": 6968,
  "frequency_hz": 99,
  "duration_secs": 30,
  "delay_secs": 5,
  "activity_before": 205331,
  "activity_after": 1397706,
  "activity_delta": 1192375,
  "representative": true
}
```

`activity_before`/`activity_after` are readings of the `syslog_messages_received` Prometheus
counter itself — `src/profiling/mod.rs` sets `ACTIVITY_METRIC = "syslog_messages_received"` and
`src/main.rs` passes that constant to `parse_counter` when building the probe — sampled
immediately before and after the profiling window; `activity_delta = 1,192,375` — over a window
that runs slightly wider than the 30s sampling window itself (~37s; see §5, caveat 3 for why) —
confirms the server was doing substantial, non-idle work throughout the capture, not just at its
edges. `representative: true` is the script's own gate — a run producing `false`
here fails the script outright (non-zero exit) rather than emitting artifacts for analysis.
This run passed that gate on its own terms; it is not being asserted representative solely
because a human said so after the fact.

`sample_count = 6968` at `frequency_hz = 99` over the load window is the basis for the
cross-check in §4.2.

## 3. Self-time table (leaf samples, from the flamegraph)

Extracted per Step 3 of the task brief (title-attribute parse of `flamegraph.svg`); full output
in `docs/performance/2026-07-25-syslog-udp-cpu-profile-selftime.txt`, committed alongside this
document (an earlier draft cited `.superpowers/sdd/selftime-50k.txt`, which is gitignored and
does not exist for anyone checking out this branch). That file's own header floors it at
0.2% self-time per leaf, and the script used to derive it from `profile.pb`/`flamegraph.svg` was
not committed with this branch — the sub-0.2% long tail (part of the ~31% remainder discussed in
§4.2) cannot currently be regenerated or independently reproduced from anything in this
repository; only the >=0.2% leaves and the group totals below are reconstructable. Grouped:

| Group | Self % | Self samples |
|---|---:|---:|
| Allocator (`malloc`/`free`/`posix_memalign`/`alloc`/`RawVec` drop) | **29.56%** | 2,060 |
| Regex engine (`regex_automata`) | 9.99% | 696 |
| Futex lock wait/wake (`__lll_lock_wait/wake_private`) | 8.52% | 594 |
| Atomics (`atomic_sub`/`load`/`add`/etc., mostly `Arc` refcounting) | 7.79% | 543 |
| Syscalls (`epoll_wait`, `recvfrom`) | 7.08% | 493 |
| Arrow (`arrow_buffer`/`arrow_schema`/`arrow_select`/`arrow_data`) | 6.07% | 423 |

Top individual leaves (>3%):

| Symbol | Self % |
|---|---:|
| `free` | 12.00% |
| `posix_memalign` | 8.98% |
| `malloc` | 7.06% |
| `core::ptr::non_null::NonNull<T>::as_ref` | 5.68% |
| `__lll_lock_wake_private` | 5.14% |
| `core::sync::atomic::atomic_sub` | 5.08% |
| `epoll_wait` | 3.89% |
| `regex_automata::nfa::thompson::backtrack::Visited::insert` | 3.47% |
| `__lll_lock_wait_private` | 3.39% |
| `recvfrom` | 3.19% |

Task-level **inclusive** time (whole-subtree, not leaf-only — these overlap each other and the
leaf table above, since one is a child of the others):

| Function | Inclusive % |
|---|---:|
| `SyslogListener::start_with_shutdown` | 30.27% |
| `ParquetWriterHandle::start_with_stats` | 25.65% |
| `PartitionedParquetWriter::push` | 25.01% |

## 4. Accounting: where does the ~94.6µs/datagram go?

This is the part of the write-up that matters most, so the accounting is stated plainly,
including what it cannot show.

### 4.1 What the leaf-sample groups prove and what they don't

**Proven, directly, from the flamegraph:** of all CPU self-time sampled during a representative
30s window under 50k datagrams/sec offered load, **29.56% is inside allocator entry points**
(`malloc`/`free`/`posix_memalign`/heap `alloc`/`RawVec` drop) and a further **8.52% is futex lock
wait/wake** — together **~38%** of all sampled CPU. Add atomics (7.79%, almost certainly `Arc`
refcount traffic given the shapes involved — `SyslogMessage` is cloned per dispatch fan-out, and
`Arc<Schema>` comparisons appear elsewhere in the codebase) and the allocation-and-synchronization
cluster is **~46%** of sampled CPU.

**What this does *not* prove:** leaf symbols name the allocator/lock-primitive entry points, not
their call sites. `malloc`/`free`/`posix_memalign` appear as leaves regardless of which line of
Rust code triggered them — a flamegraph built from `ITIMER_PROF` leaf samples alone cannot
distinguish "the syslog envelope regex allocating capture-group storage" from "`SyslogMessage`
being cloned for payload-dispatch fan-out" from "an Arrow builder growing its backing buffer."
Candidate allocation sources visible by reading the code around the hot paths above (envelope
regex parse via `regex_automata`, the `SyslogMessage.clone()` in
`PayloadDispatchingHandler::handle_message`, per-message `Vec`/`String` construction in
`payload::dispatch`'s parser chain, single-row `RecordBatch` construction in `to_record_batch`)
are plausible contributors, but **this profile alone cannot rank them.** Attributing the 29.56%
to a specific allocation site would require either inclusive-time call-graph analysis per
allocation site (which the current flamegraph extraction does not do) or an allocator-level
tracing tool (e.g. `heaptrack`), neither of which was run for this task. The conclusion that
follows is deliberately narrower than "regex parsing/Arrow mapping causes most of the cost":
**the CPU cost here is dominated by allocation pressure and glibc malloc/futex contention, not
by the parsing or mapping logic itself** — the parsing/mapping code's own instructions
(as opposed to the allocator calls it triggers) are a comparatively small direct share (regex
9.99%, Arrow 6.07%).

### 4.2 The other ~54%

Regex (9.99%) + Arrow (6.07%) + syscalls (7.08%) + allocator/futex/atomics (~46%, §4.1) sums to
**~69%** of self-time accounted for by named groups. The remainder — roughly **31%** — is spread
across individual leaves each below the 0.2% floor of the extraction in §3, plus whatever
inclusive-only cost (e.g. function-call overhead, inlined code that never showed up as its own
leaf, tokio scheduling machinery outside the explicit `tokio-runtime-w` line at 0.67%) doesn't
surface as a distinct leaf symbol at all. **This is stated as an open remainder, not forced to
add up to 100%** — a finer-grained extraction (lower the 0.2% floor, or re-derive from
`profile.pb` with full inclusive/exclusive attribution per call path) could recover more of it,
but was not done for this task.

### 4.3 Reconciling against the ~94.6µs/datagram figure

**This profile does not, and cannot, produce a percentage breakdown of the 94.6µs/datagram
figure.** The 94.6µs figure comes from a *different* run, at `info` logging, with a per-drop log
storm active (see §5, caveat 1) — the two runs are not the same regime, and no valid arithmetic
translates "38% of self-time in this `error`-level run" into "38% of 94.6µs in that `info`-level
run." What this profile *does* establish, on its own terms, is the CPU-time breakdown for the
ingest/parse/buffer path with logging cost excluded — which is a real and useful number, just
not the specific number the brief's Step 4 accounting language might suggest is derivable. The
honest position: **envelope parse, payload dispatch, and Arrow mapping together are a smaller
direct share of CPU than allocator/lock contention is, in both regimes this profile can speak
to** — but a clean "X µs is regex, Y µs is Arrow, Z µs is unexplained" table against the specific
94.6µs number is not something this data supports, and forcing one would overstate what was
measured.

### 4.4 Independent cross-check: two methods, normalized per-datagram gap

- **This profile:** `sample_count = 6968` at `frequency_hz = 99` Hz (pprof's `ITIMER_PROF`
  samples process CPU-time, not wall-clock time) → `6968 / 99 = 70.4` CPU-seconds consumed over
  the sampling window ≈ **2.35 cores** average utilization. This run's own `activity_delta`
  (§2) is `1,192,375` datagrams, but that count spans the counter's own wider ~37s window, not
  the 30s the 6,968 samples cover (§5, caveat 3). Scaled down to a 30s-equivalent window —
  `1,192,375 × 30/37 ≈ 966,800` datagrams — for comparability with the baseline below.
- **Independent per-thread measurement** (`/proc/<pid>/task/*/stat`, the method behind the
  original 94.6µs figure), at the same 50k offered rate but at `info` logging: **81.54 CPU-sec**
  ≈ **2.72 cores**, over its own 30s window, with **862,145** datagrams received in that window
  (no profiler running — see §5, caveat 3).

**Raw CPU-seconds, 70.4 vs. 81.54, differ by only ~14% — but the two runs ingested different
volumes of datagrams (~966,800 scaled vs. 862,145), so comparing raw totals is not sound.** §7's
overhead discussion makes this same point for a different pair of runs: at this offered rate a
large share of datagrams are dropped by the kernel before the application sees them, and that
drop rate is a nonlinear function of available CPU, so only **CPU-seconds per received
datagram** — not a raw CPU-second total — isolates a cost difference between two unequal-volume
runs. Normalizing:

- This profile: `70.4 CPU-sec / ~966,800 datagrams` (30s-equivalent) ≈ **72.8µs/datagram**.
- Baseline: `81.54 CPU-sec / 862,145 datagrams` = **94.6µs/datagram** — the original design-doc
  figure being reconciled against.

That is a **~23% gap** (72.8µs vs. 94.6µs), not ~14%. Using this profile's own *unscaled*
`activity_delta` instead (`1,192,375` over its real ~37s window) gives `70.4 / 1,192,375 ≈
59.0µs/datagram` — a **~38% gap**. The two normalizations disagree with each other by roughly 15
percentage points, which itself says something: this cross-check is sensitive to exactly how the
window mismatch is handled, so it should be read as **indicative of a real gap in the same
direction (this profile's run used less CPU per datagram), not as a precise measurement of that
gap's size.** A gap in this range is plausibly explained by the regime difference — the 81.54
figure's run had `info`-level logging active with the per-drop warn storm running (§5, caveat
1), which this profile's run suppressed — but that attribution is **not verified**; see caveat 3
below on why it was not tested directly. What is not supportable is the original, unnormalized
"~14%" framing: it compared absolute CPU-seconds over runs of unequal throughput, which the
rest of this document's own reasoning (§7) says not to do.

## 5. Caveats that must be read alongside §4

1. **This profile excludes logging cost, by construction, and that is not a cosmetic detail.**
   The capture forces `level = "error"` for its duration
   (`scripts/profile-syslog-udp.sh`'s `LOG_LEVEL` handling). The 94.6µs/datagram figure it is
   being compared against was measured at `info` logging *with* a drop storm running (~19,000
   `tracing::warn!` lines/sec). These are two different regimes. Read this profile as isolating
   the ingest/parse/buffer path's CPU cost, **not** as a full reproduction or decomposition of
   the 94.6µs figure.

2. **Why logging had to be suppressed: a second, independent bug.** At `info` logging with the
   `pprof` sampler active, the server reproducibly segfaults (exit 139) at 50k offered rate.
   pprof's `SIGPROF` handler unwinds the stack via `backtrace`, which is not async-signal-safe —
   if the signal lands while the allocator or a stdout lock that `tracing` holds is itself
   mid-mutation, the handler can deadlock or corrupt state. This is a real crash risk in its own
   right, independent of the profiling exercise, and deserves its own tracked issue. It also
   points at a second, adjacent finding worth recording plainly: the per-drop `tracing::warn!`
   calls that make this regime dangerous are themselves unbounded and unrate-limited —
   `src/forwarding/syslog_s3.rs:163` (`"Syslog S3 channel full; dropped message"`),
   `src/syslog/listener.rs:108` (`"structured_syslog S3 channel full; dropped record"`), and
   `src/syslog/listener.rs:138` (`"structured_syslog channel full; dropped"`) all fire once per
   dropped message with no rate limiting. At the offered rates where drops are common, this is
   the log storm that makes `info`-level operation both noisy and, combined with the sampler,
   crash-prone. Fixing the segfault (e.g. avoiding `backtrace`-based unwinding in the signal
   handler, or disabling the sampler when log level is below `error`) and rate-limiting the
   per-drop warnings are both real, separately-scoped follow-up items, not addressed by this
   task.

3. **The logging-cost contribution was not measured, and must not be estimated by re-running at
   `info` with the sampler on** — that is exactly the crashing combination described in caveat 2.
   The normalized ~23%–~38% per-datagram gap in §4.4 is presented as an *observation* (two
   differently-configured runs, one at `error` with the sampler, one at `info` via `/proc`
   accounting, landing in that range of each other depending on window normalization), not as a
   validated measurement of logging's specific cost. There is also a window-alignment point to
   flag, and it belongs entirely to *this* profile, not to the baseline it is being compared
   against: the 6,968 samples in §3 cover exactly the 30s sampling window (`DURATION=30`), but
   this profile's own `activity_delta` counter (§2) spans a slightly wider ~37s. `activity_before`
   is read at `t≈5s` (`DELAY=5`), *before* the `pprof` guard is built; `ProfilerGuardBuilder::build()`
   then spends ~7s on one-time backtrace symbolication before sampling actually starts, so sampling
   runs `t≈12s→t≈42s` and `activity_after` is read at `t≈42s` (immediately after the sampling sleep
   ends, before the report is symbolicated) — hence the counter delta spans `t≈5s→t≈42s ≈ 37s`,
   wider than the 30s the samples themselves cover. The separate 81.54 CPU-sec baseline used in
   §4.4 was measured over its own 30s window, with no profiler running at all — it is not the
   source of the ~37s figure, and §4.4's `81.54 / 30 ≈ 2.72 cores` arithmetic is unaffected by any
   of this. The practical consequence, and the direct reason §4.4 computes the gap two ways: because
   this profile's `activity_delta` counter covers a slightly wider window (~37s) than the samples
   it is meant to corroborate (30s), dividing sample-based CPU-time by the *unscaled*
   `activity_delta` (§4.4's ~59.0µs/datagram figure) is **conservative** — the denominator is
   inflated relative to the numerator's actual 30s window, which understates the per-datagram
   cost — while scaling `activity_delta` down to a 30s-equivalent first (§4.4's ~72.8µs/datagram
   figure) corrects for that but introduces its own assumption (uniform ingest rate across the
   ~37s span). Neither figure is more "correct" than the other; that disagreement is exactly why
   §4.4 reports both a ~23% and a ~38% gap rather than a single number.

4. **Bottom-up criterion benches for the syslog receive path were never completed — the
   top-down/bottom-up reconciliation cannot be done yet.** `perf/syslog-recv-path-benches` was
   created as a branch for exactly this purpose (micro-benchmarking `SyslogMessage::parse` and
   `payload::dispatch` in isolation, the way `benches/syslog_message_to_record_batch.rs` already
   does for `to_record_batch`), but it contains no commits beyond what `master` already has —
   the benches were never written. This is stated here as an **open item**, not papered over:
   there is currently no bottom-up number for envelope-regex-parse-alone or
   payload-dispatch-alone to check the ~10%/~regex-group figure in §3 against. Until that branch
   lands actual benchmarks, any claim of top-down/bottom-up agreement would be invented, not
   verified.

## 6. This profile as evidence against the performance-improvements-plan's §2.1 claim

`docs/superpowers/specs/2026-07-24-performance-improvements-plan.md` §2.1 states
`ParquetSink::to_record_batch` costs **~500µs–1.3ms per record** and calls batching it "the
single highest-value performance improvement identified" in that investigation. The seven
committed criterion benches (all of `benches/*_to_record_batch.rs`) instead measure
**2.58–13.14µs per record** for the same function across all 7 sink adapters — 40-100x lower
than the plan's figure. At the measured syslog cost of 7.07µs/record × 516,746 records written
during the run that produced the 94.6µs figure = **3.65 CPU-sec, or 4.5%** of that run's 81.54
CPU-sec total.

**This profile does not add a second, independent measurement of Arrow's cost on top of the
bench comparison above — an earlier draft of this section claimed it did, and that claim did
not hold up.** The Arrow group in §3 (`arrow_buffer`/`arrow_schema`/`arrow_select`/`arrow_data`)
is **6.07% of self-time only**: it counts CPU spent inside Arrow's own functions, not the
allocator calls those functions trigger. §4.1 already establishes why that matters here — leaf
samples name allocator entry points, not their call sites, so a `malloc`/`free`/`posix_memalign`
sample caused by an Arrow builder growing its backing buffer, or by the single-row `RecordBatch`
construction in `to_record_batch` (both named in §4.1 as candidates for the 29.56% allocator
bucket), is indistinguishable in this data from an allocation triggered anywhere else in the
ingest path. **6.07% is therefore a lower bound on Arrow's true CPU cost, not a measurement of
it.**

One concrete piece of evidence that the true share is higher: `posix_memalign` is the
second-largest individual leaf in §3 at **8.98%** (626 samples), with
`std::sys::alloc::unix::aligned_malloc` appearing directly above it in the same stacks. glibc's
`malloc` does not route through `posix_memalign` — Rust's allocator only calls `posix_memalign`
for over-aligned allocations, and in this codebase those are overwhelmingly Arrow's 64-byte-aligned
buffers. So a substantial, currently unquantified share of that 8.98% is plausibly
Arrow-attributable, on top of the 6.07% self-time already counted. This is consistent with the
inclusive-time figures in §3 — `PartitionedParquetWriter::push` (25.01% inclusive) and
`ParquetWriterHandle::start_with_stats` (25.65% inclusive) — which necessarily include not just
Arrow's own instructions but all of the allocator/lock-contention time their call subtrees
trigger, and are consequently far larger than Arrow's 6.07% self-time figure alone.

Note also that batching `to_record_batch` is itself an allocation-pressure reduction: it would
remove the single-row `RecordBatch` construction §4.1 already lists as a candidate contributor to
the 29.56% allocator bucket. The allocator-pressure finding in §4 and the plan's `to_record_batch`
batching recommendation are therefore not competing hypotheses about where the cost is — the
allocator bucket may substantially be *composed of* the cost that batching would remove.

**This profile cannot rank Arrow-amortization work against general allocator/lock-contention
work as the higher-value fix, and it is not evidence that one matters more than the other.**
Doing that ranking would require call-site attribution this extraction does not have —
inclusive-time call-graph analysis per allocation site, or an allocator-tracing tool such as
`heaptrack`, neither of which was run for this task. The plan's §2.1 `to_record_batch` batching
recommendation is **not superseded** by this profile; it remains one of several plausible
allocator-pressure contributors that this data cannot distinguish between.

## 7. Limitations

- **Single run, no repeats for this specific profile.** `profile-metadata.json` reports one
  capture. The script's own header notes two confirming runs were observed during its
  development (6,656 samples / activity-delta 940,525, and this run's 6,968 samples /
  activity-delta 1,192,375) — normal sampling run-to-run variance, not identical numbers — but
  only the latter is the one analyzed here. No formal error bars on the percentages in §3.
- **Leaf-sample attribution, not full call-graph attribution.** As stated in §4.1, `malloc`/
  `free`/`posix_memalign`/futex leaves cannot be traced back to a specific call site from this
  extraction alone. The 0.2% floor used for the self-time table (§3) also means the full leaf
  list is truncated; the ~31% unattributed remainder in §4.2 partly reflects that floor, not
  necessarily "genuinely unexplainable" cost.
- **A specific symbolication red flag bounds confidence in every percentage in §3.**
  `core::ptr::non_null::NonNull<T>::as_ref` is the 4th-largest individual leaf at **5.68%** (396
  samples) — a trivial, almost-certainly-inlined pointer dereference that has no plausible reason
  to itself consume 5.68% of sampled CPU. Its presence at that magnitude is more consistent with
  unwind/frame-attribution noise (samples landing on a thin, frequently-inlined function that sits
  low in many unrelated call stacks) than with genuine cost concentrated in that one line. This
  does not invalidate the accounting in §3–§4, but it is concrete evidence that leaf-level
  percentages in this document carry a symbolication-fidelity error this task did not quantify —
  every percentage in §3 should be read with that in mind, not just the allocator/Arrow figures
  discussed above.
- **Logging excluded by construction (caveat 1), and its cost not independently measured
  (caveat 3).** This is the single biggest interpretive limitation of the whole document: this
  profile is a clean measurement of a *different* (quieter) regime than the one the 94.6µs
  figure came from, and the two cannot be algebraically combined into a single number.
- **No bottom-up reconciliation available yet** (caveat 4) — `perf/syslog-recv-path-benches`
  has no benches committed. The claim "regex parsing is ~10% of CPU" rests on the flamegraph's
  leaf-sample grouping alone; it has not been cross-checked against an isolated
  `SyslogMessage::parse` criterion benchmark the way `to_record_batch`'s cost was.
- **One machine, one host's allocator/kernel configuration.** glibc malloc arena behavior and
  futex contention are sensitive to core count, `MALLOC_ARENA_MAX`, and NUMA topology, none of
  which were varied or recorded here beyond "whatever this host's defaults are." The ~38%
  allocator+futex figure should not be assumed to transfer unchanged to a different host or a
  build using a different allocator (e.g. jemalloc/mimalloc were not tested).
- **The profiling scaffolding itself carries some overhead.** No attempt was made in this task
  to quantify how much the `pprof` sampler's own signal-handling and unwinding cost inflates the
  numbers it reports (a variant of the classic observer-effect concern for sampling profilers);
  the brief's Step 4 overhead-validation exercise (repeated with/without profiling, comparing
  CPU-sec/received-datagram) was not run for this document — it is out of scope for a write-up
  task that must not re-run the 60s capture script, and is noted here as unexecuted rather than
  silently assumed negligible. See the dedicated subsection immediately below for why the
  received-datagram counter specifically is not a safe stand-in for that missing measurement.

### Profiler overhead: not validated

The task brief for this profiling work called for a validation step that this document does not
contain: three repeats with the `pprof` sampler enabled and three repeats without it, on an
otherwise-idle box, comparing **CPU-seconds per received datagram** between the two conditions
— not the raw `syslog_messages_received` counter. **That experiment was not performed. Profiler
overhead is unquantified in this document** — nothing here bounds how much of any number in this
write-up (the 70.4 CPU-sec figure in §4.4 included) reflects the `pprof` sampler's own
signal-handling and stack-unwinding cost rather than the ingest/parse/buffer path itself.

The reason the comparison would need to use CPU-sec *per received datagram*, rather than a
simple before/after comparison of the raw received-datagram counter, is itself part of the
caveat: at this offered rate, a large share of datagrams (~42%) are already being dropped by the
kernel UDP socket receive buffer before the application ever sees them, and that drop rate is a
nonlinear function of how much CPU is available to drain the socket. If enabling the profiler
consumes additional CPU, the expected effect is not merely "the same datagrams take longer to
process" — it is a shift in the kernel's drop rate, which moves the received-count denominator
itself. A raw before/after comparison of the received counter could therefore not cleanly
separate profiler overhead from that denominator shift, or from ordinary run-to-run variance;
only a per-received-datagram CPU-seconds ratio, computed the same way on both sides of the
comparison, would isolate the sampler's own cost.

Closing this gap would require exactly that experiment — three repeats with the sampler on and
three without, on an otherwise-idle box, comparing CPU-sec/received-datagram between the two —
and it was not attempted for this document.
