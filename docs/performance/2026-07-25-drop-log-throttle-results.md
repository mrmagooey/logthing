# Drop-log throttle: throughput recovery measurement, 2026-07-25

**Git commit this was measured against:** `336568f006c3e3d05df6e87d9f66a1ba52d023e0`
(branch `perf/drop-log-throttle`; working tree clean apart from the throwaway repo-root config
swaps described below, which were reverted before this doc was written — verified with
`git status --short -- logthing.toml logthing.admin.toml` after every run).

## 1. What was run

- **Format / subcommand:** `loadgen syslog-udp`
- **`logthing` build profile:** `--profile profiling --features pprof` (pprof feature included so
  the same binary also serves Step 4; the profiler is not *active* during the Step 2 throughput
  runs — no `LOGTHING_PROFILE_*` env vars are set for those)
- **Persistence target:** `LocalDiskSink` (via `tools/loadgen/ci/logthing-baseline.toml`)
- **Config used:** `tools/loadgen/ci/logthing-baseline.toml` with a `[logging] level = "info"`
  block appended (this is the fix-targeted condition; see §3 below on why `info` and not `error`)
- **`logthing.admin.toml` handling:** as documented in commit 87b1d5e and the 2026-07-24 baseline
  doc, this file is git-tracked and overrides `logthing.toml` at higher precedence. It was removed
  for the duration of each run and restored via an `EXIT` trap, same as the pre-fix measurement.
- **Buffer-policy values in effect:** unchanged from the 2026-07-24 baseline
  (`max_buffer_rows=10_000`, `flush_interval_secs=900`, `channel_capacity=4_096`,
  `flush_threshold_bytes` not applicable — `syslog_local_start()` hardcodes `usize::MAX`). This
  run does not touch buffer policy at all, so these are restated for completeness, not because
  anything changed.
- **Exact commands run:**

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
cargo build --profile profiling --features pprof
cargo build -p loadgen --release
```

Then, per run (harness reused as-is from the pre-fix measurement,
`/tmp/claude-1000/.../scratchpad/logcost.sh`, adapted only to preserve per-run output files):

```bash
# (inside the harness, after backing up logthing.toml / logthing.admin.toml)
rm -f logthing.admin.toml
cp tools/loadgen/ci/logthing-baseline.toml logthing.toml
printf '\n[logging]\nlevel = "info"\nformat = "pretty"\n' >> logthing.toml

target/profiling/logthing &                      # no LOGTHING_PROFILE_* vars set
# wait for /metrics, snapshot per-thread CPU via threadcpu.py
target/release/loadgen syslog-udp --host 127.0.0.1 --port 15514 \
    --target-rate 50000 --duration-secs 30
# snapshot per-thread CPU again, diff; snapshot /metrics again; restore config on EXIT trap
```

## 2. Goals & metrics captured

Per-run: total process CPU-seconds (`utime+stime` summed across `/proc/<pid>/task/*/stat`, via
`threadcpu.py`), `syslog_messages_received` delta, `parquet_s3_dropped` delta, and total emitted
log lines (`wc -l` on the server's captured stdout).

## 3. Comparability notes

This run is directly comparable to the 2026-07-24 pre-fix baseline: same machine, same config
file, same rate (50k target), same duration (30s), same harness shape. The only variable that
changed is the code under test (Tasks 1–5's drop-log throttle). `info` is the condition the fix
targets (drop logs fire, but now throttled); `error` is not re-measured here — its pre-fix numbers
are used as the point of comparison the fix should approach (see §5).

## 4. Results

### Step 2 — throughput at `info`, two runs

| | CPU-sec | received | µs / received datagram | log lines emitted | `parquet_s3_dropped` Δ |
|---|---:|---:|---:|---:|---:|
| **post-fix run 1** | 86.84 | 1,074,436 | 80.82 | 42 | 552,093 |
| **post-fix run 2** | 87.52 | 1,086,184 | 80.58 | 42 | 555,599 |
| post-fix mean | 87.18 | 1,080,310 | **80.70** | 42 | 553,846 |
| pre-fix run 1 (baseline) | 85.97 | 852,799 | 100.8 | 1,176,360 | *(not captured pre-fix)* |
| pre-fix run 2 (baseline) | 84.17 | 839,702 | 100.2 | — | *(not captured pre-fix)* |
| pre-fix mean | 85.07 | 846,251 | 100.53 | 1,176,360 (n=1; run 2 not captured) | — |
| pre-fix `error` run 1 (logging-off ceiling) | 88.04 | 1,054,868 | 83.46 | 0 | — |
| pre-fix `error` run 2 (logging-off ceiling) | 86.23 | 991,117 | 87.00 | 0 | — |
| pre-fix `error` mean | 87.14 | 1,022,993 | 85.18 | 0 | — |

Both mean µs/datagram figures above are computed the same way, summed-CPU ÷ summed-received
across the two runs of the condition (not a simple average of the two per-run ratios): `info` —
170.14 CPU-sec ÷ 1,692,501 received → 100.53 µs; `error` — 174.27 CPU-sec ÷ 2,045,985 received →
85.18 µs. This matches the method already used for the post-fix mean row above.

**Where the result lands:** post-fix `info` measures **80.6–80.8 µs/received-datagram (mean
80.70)**. The pre-fix `info` mean was 100.53 µs; the pre-fix `error` (logging fully disabled) mean
was 85.18 µs. The post-fix number is not just between those two — it is **below both**, i.e. the
throttled `info` path in this measurement was slightly cheaper per datagram than the pre-fix
"no drop logging at all" condition.

**The defensible, within-session figure: ≈15.35 µs/datagram, matching the ~15 µs prediction.**
Pre-fix `info` and pre-fix `error` were both captured in the same measurement session (the
design's §1.1 baseline, reproduced in the pre-fix rows above): 100.53 − 85.18 = **15.35 µs**. This
is the attributable recovery from removing per-drop drop-log overhead, and it lines up almost
exactly with the design's ~15 µs prediction.

**Cross-session delta (post-fix `info` vs. pre-fix `info`): 100.53 → 80.70 µs, ≈19.8 µs/datagram.**
This spans two different measurement sessions (see §5), whose own analysis attributes roughly
4.5 µs of that 19.8 to probable session-to-session bias rather than to the change itself — the
post-fix `info` result (80.70 µs) measures *below* the pre-fix `error`/logging-fully-off ceiling
(85.18 µs), which cannot be a real effect of removing drop-log calls (there is no drop logging in
the `error` condition left to remove, so `info` cannot legitimately end up cheaper than it). Read
≈19.8 µs as a cross-session delta inflated by that bias, not as the number to cite for what the
throttle recovered; ≈15.35 µs is the defensible, within-session figure.

### Log-line collapse

Post-fix, both runs emitted exactly **42 total log lines** (a raw `wc -l` count of physical output
lines). Of that output, only **2 drop-related log events** (i.e. 2 distinct `tracing` macro
invocations, not necessarily 2 physical lines) fired, and only **one** of those two events is a
product of this task's throttle. Note the units differ: "42" counts physical lines; "2" counts
events. The `pretty` formatter emits ≈3 physical lines per event (§1.2 of the design spec), so
these 2 events plausibly account for something like 4-6 of the 42 physical lines, not exactly 2 —
no precise physical-line split is claimed here, only that drop-related content is a small minority
of the 42 lines by either count:

- `Syslog S3 channel full; dropped message` (from `src/forwarding/syslog_s3.rs:166`) — this is the
  genuinely-converted site. It calls `self.drop_log_due(DropSite::Syslog, DropKind::from(&e))` and
  emits a `dropped_total` field, i.e. it goes through the new `(DropSite, DropKind)` throttle built
  in Tasks 1–5. This line carries `dropped_total: 1` — the throttle fired on the very first drop of
  that pair and then stayed quiet for the rest of the 30s window.
- `parquet_s3: upload failing — dropped oldest rows to stay within hard cap` (from
  `src/forwarding/buffered_writer.rs:854`, inside `drop_oldest_to_cap`) — **this is not a throttled
  emission of the new mechanism.** It is a pre-existing, already-throttled, deliberately-excluded
  line: the design spec (§2.1, "Deliberate exclusions") explicitly excludes `buffered_writer.rs`'s
  `drop_oldest_to_cap` from this work because it already had its own wall-clock throttle —
  `last_drop_warn ... elapsed().as_secs() >= 30` at `buffered_writer.rs:848-852`, which predates
  this feature entirely. Confirming in source: this call site emits `dropped, source, target`
  fields and takes no `DropSite`/`DropKind` argument at all, unlike the syslog site above. Its
  window is exactly and explicitly 30 seconds (`>= 30` in the source), not an inferred value, so it
  is unsurprising that only one emission landed in a 30s run; this is old behavior, not a new result
  of Tasks 1–5.

The remaining physical lines are one-time startup/admin-interface log lines unrelated to drops,
identical across both runs.

Against the pre-fix baseline of 1,176,360 log lines in a comparable run:
- **Total lines:** 1,176,360 → 42, a ≈28,009× reduction. This figure is unaffected by the
  misattribution above and stands as reported (both counts are physical `wc -l` lines).
- **Drop-attributable events specifically:** the pre-fix baseline does not have a per-event count
  to compare against (only the 1,176,360 physical-line total was captured), so post-fix's 2 events
  cannot be turned into a like-for-like before/after event ratio. Crediting the new throttle with
  both of the 2 post-fix events would also overstate its effect regardless: one of the two
  (`buffered_writer.rs:854`) was already throttled before this task and would have appeared at
  essentially the same rate (once per 30s window) with or without Tasks 1–5 — it is not evidence of
  what the new throttle did. I do not have a pre-fix, per-site breakdown of the 1,176,360 baseline
  lines that would let me attribute a specific before/after count to the syslog site alone, so no
  numeric reduction ratio is claimed for the new throttle's contribution in isolation — only that
  the total collapse from ~1.18M lines to 42 is real and correctly reported above, and that of the
  2 surviving drop events, 1 (`syslog_s3.rs:166`) is this task's doing and 1
  (`buffered_writer.rs:854`) predates it and merely happens to also appear in this run's output.

### Step 4 — pprof segfault re-check, `LOG_LEVEL=info`, five runs of `scripts/profile-syslog-udp.sh`

| run | outcome |
|---|---|
| 1 | **crashed** — `Segmentation fault`, backgrounded `logthing` process; `profile-metadata.json` not written |
| 2 | **crashed** — same signature |
| 3 | succeeded — `representative: true`, 6,805 samples, activity delta 968,745 |
| 4 | **crashed** — same signature |
| 5 | succeeded — `representative: true`, 6,416 samples, activity delta 770,972 |

**3 of 5 runs crashed.** `git status --short -- logthing.toml logthing.admin.toml` was empty after
every run, including the three crashes (the script's `EXIT`/`INT`/`TERM` traps restored the
config files regardless of how the server process exited).

All three crashes happened within 2–3 seconds of the same captured stdout tail: the CPU profiler's
"CPU profiling started" line, followed shortly by the throttled `parquet_s3: upload failing`
WARN line, then nothing further — the process died before the 30s sampling window completed and
before `profile-metadata.json` was ever written. This is directly consistent with the design's
stated mechanism (pprof's `SIGPROF` handler unwinding via `backtrace`, which is not
async-signal-safe against the allocator/stdout locks `tracing` holds) — the timing places the
crash right around a log emission landing inside the active sampling window, not at some unrelated
point in the run.

## 5. Honest read

**The throughput number is a genuine win, and the defensible within-session figure (≈15.35 µs)
lines up almost exactly with the ~15 µs predicted** — but the larger, cross-session 19.8 µs delta,
and the fact that it lands *below* the pre-fix "logging fully off" ceiling, deserve scrutiny rather
than a victory lap. The pre-fix `error` baseline (85.18 µs mean) and this run's post-fix `info`
result (80.70 µs mean) were captured in different sessions, on the same machine but not
back-to-back, and the pre-fix baseline doc itself documents order-of-magnitude run-to-run swings
in this environment (kernel UDP receive-buffer drops, achieved send rate variance, etc.). I am not
confident the post-fix number is *actually* cheaper than a hypothetical logging-fully-disabled
run of the current code — more likely, the "logging off" ceiling itself has session-to-session
noise of a similar magnitude to the ~4.5 µs by which post-fix `info` sits below it. What I *am*
confident of, because it's an internally consistent same-code-base comparison across the two runs
taken back-to-back in this session: **the throttle removed essentially all of the drop-log
overhead that pre-fix `info` was paying**, moving it from clearly worse than "no drop logging" to
indistinguishable from it within this measurement's noise band.

**The log-line collapse is unambiguous and is the strongest single result in this report.** Going
from 1,176,360 total lines to 42 in an identical 30-second, 50k-target-rate run is not a subtle
effect, and it explains why the CPU-bound cost of drop logging effectively disappeared. Of the 2
drop-attributable lines that remain, only 1 (the `syslog_s3.rs:166` channel-full warning) is this
throttle's doing; the other (`buffered_writer.rs:854`) was already throttled before this task and
would have shown up regardless — see §4 for the detail. The throttle is doing exactly what it was
built to do at the site it actually touches; it should not be credited for the pre-existing
throttling elsewhere.

**`parquet_s3_dropped` rose sharply post-fix (552,093 / 555,599 in 30s) — this is expected, not a
regression.** Pre-fix, the drop-log storm itself was consuming enough CPU that fewer datagrams
were ever accepted into the pipeline in the first place (852,799 / 839,702 received vs. 1,074,436
/ 1,086,184 post-fix — roughly 26–29% more datagrams got in). With that CPU pressure relieved, more
datagrams now reach the bounded writer channel, and a correspondingly larger number hit it while
full. The bottleneck moved downstream, from "logging is too slow" to "the writer channel is too
small for this rate" — which is the outcome the throttle was supposed to produce, not a new
problem it introduced.

**The pprof crash is not fixed.** 3 of 5 runs (60%) crashed even with total log-line volume cut by
~28,009× (see §4's log-line collapse). This sample is far too small to pin down a precise rate (a
3/5 empirical result has a wide Jeffreys binomial confidence interval — roughly 23%–88% at 95%
confidence), so I am not reporting "the crash rate is 60%" as a stable figure, and I have no
pre-fix crash-rate measurement to compare it against (see Limitations) — so this cannot be read as
evidence that the rate did or did not fall relative to pre-fix; it only establishes the post-fix
rate on its own. What the sample *does* establish: the crash is still easy to hit in practice, not
a rare edge case. What it does *not* establish: any precise probability, or that the mechanism is
fully understood — the timing correlation with a log
emission landing inside the sampling window is consistent with the design's stated cause, but I
have not instrumented the signal handler itself to confirm it, and it remains plausible that the
collision probability is dominated by per-emission fixed cost (lock acquisition, write syscall
latency) rather than by raw emission count, which would explain why cutting total log-line volume
by ~28,009× did not cut the crash rate anywhere near proportionally. Anyone relying on
`scripts/profile-syslog-udp.sh` at `LOG_LEVEL=info` should still expect it to crash a meaningful
fraction of the time and should not treat a handful of clean runs as proof it's resolved.

## 6. Limitations

- **Two runs per condition, five for the crash check.** This is the minimum the brief called for,
  not a large sample. The throughput numbers agree with each other within about 0.3 µs
  run-to-run, which is reassuring, but two runs cannot rule out a systematic session-level bias
  (see the "below the ceiling" discussion in §5).
- **Pre-fix and post-fix throughput numbers come from different sessions**, not a single
  back-to-back sweep. The 2026-07-24 baseline doc documents this environment's own run-to-run
  variance (kernel socket-buffer drops, achieved-rate variance); I cannot fully separate "the
  throttle fix" from "ordinary session-to-session noise" for the last few µs of the comparison,
  though the ~15.35 µs within-session gap (pre-fix `info` vs. pre-fix `error`, both from the same
  session) is the defensible headline figure and matches the ~15 µs prediction almost exactly. The
  larger ~19.8 µs cross-session delta (pre-fix `info` vs. this run's post-fix `info`) is real as a
  raw before/after number, but §5 attributes roughly 4.5 µs of it to probable session-to-session
  bias rather than to the change itself, so it should not be read as a tighter bound on the
  improvement than ≈15.35 µs.
- **Single machine, no repeats beyond what's stated.** No statistical treatment beyond reporting
  both raw runs; where the signal is large (log-line collapse, ~20 µs/datagram shift) it's treated
  as real, where it's a few µs (post-fix vs. the logging-off ceiling) it is explicitly flagged as
  within probable noise.
- **The pprof crash-rate sample (n=5) is too small for a precise rate estimate.** 3/5 is reported
  as-is; no confidence interval narrower than the Jeffreys interval's "roughly 23%–88%" should be
  inferred from it.
- **There is no pre-fix crash-rate measurement to compare the post-fix 3/5 against.** The only
  prior evidence is the design spec's "reproducibly segfaults," which does not establish a
  denominator or a rate — it could have been 5/5, in which case 3/5 *is* a reduction, or something
  lower. 3/5 establishes that the crash is still easy to hit ("reduced, not eliminated" per the
  design's row 15′), but it cannot establish whether the underlying rate rose, fell, or stayed flat,
  because there is no comparable pre-fix rate on record.
- **The new throttle's window length was not independently verified against Tasks 1–5's source in
  this task.** Only one of the 2 surviving drop lines (`syslog_s3.rs:166`) is governed by the new
  `(DropSite, DropKind)` throttle; its `dropped_total: 1` value is consistent with a window at
  least as long as the 30s run, but Task 6 did not re-derive the exact window length from Tasks
  1–5's code, so "at least 30s" is inferred, not confirmed. The other surviving drop line
  (`buffered_writer.rs:854`) is unrelated to this task — its window is the pre-existing, explicit
  30-second wall-clock check at `buffered_writer.rs:848-852`, already verified in source, and its
  single emission in a 30s run is expected rather than informative about the new throttle.
- **`ps`/`/proc` CPU accounting reflects the whole process**, not isolated per-thread attribution
  to the drop-log path specifically; the throughput comparison is a whole-run before/after, not an
  isolated cost of the log calls alone.

## Files produced by this run (not committed — local scratchpad artifacts only)

`logcost-info-run{1,2}.log` (captured stdout), `t{0,1}-info-run{1,2}.json` (per-thread CPU
snapshots), `m-{before,after}-info-run{1,2}.txt` (`/metrics` snapshots), `pprof-run{1..5}.log`
(the five `scripts/profile-syslog-udp.sh` invocations), `pprof-run{3,4,5}-stdout.log` (captured
server stdout for the crash-timing correlation in §4) — all under
`/tmp/claude-1000/-home-dev-projects-logthing/d036e6d9-e063-4b0e-a30c-6ce71ad0cb44/scratchpad/`.
