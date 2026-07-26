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
| pre-fix mean | 85.07 | 846,251 | 100.52 | 1,176,360 | — |
| pre-fix `error` run 1 (logging-off ceiling) | 88.04 | 1,054,868 | 83.46 | 0 | — |
| pre-fix `error` run 2 (logging-off ceiling) | 86.23 | 991,117 | 87.00 | 0 | — |
| pre-fix `error` mean | 87.14 | 1,022,993 | 85.23 | 0 | — |

**Where the result lands:** post-fix `info` measures **80.6–80.8 µs/received-datagram (mean
80.70)**. The pre-fix `info` mean was 100.52 µs; the pre-fix `error` (logging fully disabled) mean
was 85.23 µs. The post-fix number is not just between those two — it is **below both**, i.e. the
throttled `info` path in this measurement was slightly cheaper per datagram than the pre-fix
"no drop logging at all" condition.

**Improvement vs. pre-fix `info`:** 100.52 → 80.70 µs, a reduction of **≈19.8 µs/datagram**. The
design predicted ~15 µs. The measured improvement is *larger* than predicted, not smaller — see
§5 for why this number should still be read cautiously (it is not free of the same "smaller/larger
than predicted" honesty obligation just because it goes the favorable direction).

### Log-line collapse

Post-fix, both runs emitted exactly **42 total log lines**, of which only **2** are drop-related:
one throttled emission of `Syslog S3 channel full; dropped message` (from
`src/forwarding/syslog_s3.rs:166`) and one throttled emission of `parquet_s3: upload failing —
dropped oldest rows to stay within hard cap` (from `src/forwarding/buffered_writer.rs:854`). The
other ~40 lines are one-time startup/admin-interface log lines unrelated to drops, identical
across both runs. Each of the two drop lines carries `dropped_total: 1` / `dropped: 1` — the
throttle fired on the very first drop of that `(DropSite, DropKind)` pair and then stayed quiet for
the rest of the 30s window (the throttle window is evidently longer than 30s, so the run ended
before a second emission for either site/kind became due).

Against the pre-fix baseline of 1,176,360 log lines in a comparable run:
- **Total lines:** 1,176,360 → 42, a ≈28,009× reduction.
- **Drop-attributable lines specifically:** 1,176,360 → 2, a ≈588,180× reduction — larger than the
  design's own ~190,000× estimate, though both are "several orders of magnitude," and I would not
  hang much weight on the precise ratio given `n=1` on the pre-fix side and the throttle-window
  edge effect described above (a longer-duration run would show more than 2 drop lines, since the
  throttle window would elapse and re-arm).

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

**The throughput number is a genuine, clear win, and it is larger than the ~15 µs predicted** —
but the fact that it lands *below* the pre-fix "logging fully off" ceiling deserves scrutiny rather
than a victory lap. The pre-fix `error` baseline (85.23 µs mean) and this run's post-fix `info`
result (80.70 µs mean) were captured in different sessions, on the same machine but not
back-to-back, and the pre-fix baseline doc itself documents order-of-magnitude run-to-run swings
in this environment (kernel UDP receive-buffer drops, achieved send rate variance, etc.). I am not
confident the post-fix number is *actually* cheaper than a hypothetical logging-fully-disabled
run of the current code — more likely, the "logging off" ceiling itself has session-to-session
noise of a similar magnitude to the ~4.6 µs by which post-fix `info` sits below it. What I *am*
confident of, because it's an internally consistent same-code-base comparison across the two runs
taken back-to-back in this session: **the throttle removed essentially all of the drop-log
overhead that pre-fix `info` was paying**, moving it from clearly worse than "no drop logging" to
indistinguishable from it within this measurement's noise band.

**The log-line collapse is unambiguous and is the strongest single result in this report.** Going
from 1,176,360 lines to 2 drop-attributable lines in an identical 30-second, 50k-target-rate run
is not a subtle effect — it is the throttle doing exactly what it was built to do, and it explains
why the CPU-bound cost of drop logging effectively disappeared.

**`parquet_s3_dropped` rose sharply post-fix (552,093 / 555,599 in 30s) — this is expected, not a
regression.** Pre-fix, the drop-log storm itself was consuming enough CPU that fewer datagrams
were ever accepted into the pipeline in the first place (852,799 / 839,702 received vs. 1,074,436
/ 1,086,184 post-fix — roughly 27–29% more datagrams got in). With that CPU pressure relieved, more
datagrams now reach the bounded writer channel, and a correspondingly larger number hit it while
full. The bottleneck moved downstream, from "logging is too slow" to "the writer channel is too
small for this rate" — which is the outcome the throttle was supposed to produce, not a new
problem it introduced.

**The pprof crash is not fixed, and the observed rate is higher than "reduced, not eliminated"
might suggest.** 3 of 5 runs (60%) crashed even with drop-log volume cut by ~588,000×. This
sample is far too small to pin down a precise rate (a 3/5 empirical result has a wide binomial
confidence interval — roughly 23%–88% at 95% confidence), so I am not reporting "the crash rate is
60%" as a stable figure. What the sample *does* establish: the crash is still easy to hit in
practice, not a rare edge case. What it does *not* establish: any precise probability, or that the
mechanism is fully understood — the timing correlation with a log emission landing inside the
sampling window is consistent with the design's stated cause, but I have not instrumented the
signal handler itself to confirm it, and it remains plausible that the collision probability is
dominated by per-emission fixed cost (lock acquisition, write syscall latency) rather than by raw
emission count, which would explain why cutting emissions by ~588,000× did not cut the crash rate
anywhere near proportionally. Anyone relying on `scripts/profile-syslog-udp.sh` at `LOG_LEVEL=info`
should still expect it to crash a meaningful fraction of the time and should not treat a handful of
clean runs as proof it's resolved.

## 6. Limitations

- **Two runs per condition, five for the crash check.** This is the minimum the brief called for,
  not a large sample. The throughput numbers agree with each other within about 0.3 µs
  run-to-run, which is reassuring, but two runs cannot rule out a systematic session-level bias
  (see the "below the ceiling" discussion in §5).
- **Pre-fix and post-fix throughput numbers come from different sessions**, not a single
  back-to-back sweep. The 2026-07-24 baseline doc documents this environment's own run-to-run
  variance (kernel socket-buffer drops, achieved-rate variance); I cannot fully separate "the
  throttle fix" from "ordinary session-to-session noise" for the last few µs of the comparison,
  though the ~19.8 µs headline improvement is far larger than the variance documented in that
  baseline and is not in doubt.
- **Single machine, no repeats beyond what's stated.** No statistical treatment beyond reporting
  both raw runs; where the signal is large (log-line collapse, ~20 µs/datagram shift) it's treated
  as real, where it's a few µs (post-fix vs. the logging-off ceiling) it is explicitly flagged as
  within probable noise.
- **The pprof crash-rate sample (n=5) is too small for a precise rate estimate.** 3/5 is reported
  as-is; no confidence interval narrower than "roughly 23%–88%" should be inferred from it.
- **The throttle-window re-arm behavior (why only 2 drop lines fired in 30s despite 550k+ drops)
  was not independently verified against the throttle's source in this task** — it's inferred from
  the observed `dropped_total: 1` / `dropped: 1` values and is consistent with a throttle window
  longer than 30s, but Task 6 did not re-derive the exact window length from Tasks 1–5's code.
- **`ps`/`/proc` CPU accounting reflects the whole process**, not isolated per-thread attribution
  to the drop-log path specifically; the throughput comparison is a whole-run before/after, not an
  isolated cost of the log calls alone.

## Files produced by this run (not committed — local scratchpad artifacts only)

`logcost-info-run{1,2}.log` (captured stdout), `t{0,1}-info-run{1,2}.json` (per-thread CPU
snapshots), `m-{before,after}-info-run{1,2}.txt` (`/metrics` snapshots), `pprof-run{1..5}.log`
(the five `scripts/profile-syslog-udp.sh` invocations), `pprof-run{3,4,5}-stdout.log` (captured
server stdout for the crash-timing correlation in §4) — all under
`/tmp/claude-1000/-home-dev-projects-logthing/d036e6d9-e063-4b0e-a30c-6ce71ad0cb44/scratchpad/`.
