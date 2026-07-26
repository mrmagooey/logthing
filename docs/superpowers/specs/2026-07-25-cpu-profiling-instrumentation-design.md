# CPU Profiling Instrumentation — Design

**Date:** 2026-07-25
**Status:** Approved (autonomous design via `auto-develop`; independent coherence review passed round 3)
**Related:** [`2026-07-24-performance-improvements-plan.md`](2026-07-24-performance-improvements-plan.md) (whose §2.1 motivating figure this work supersedes — see §1.3), [`docs/performance/2026-07-24-syslog-udp-baseline-results.md`](../../performance/2026-07-24-syslog-udp-baseline-results.md), [`docs/performance/methodology-template.md`](../../performance/methodology-template.md)

## 1. Why this exists

### 1.1 The measurement that prompted it

A per-thread CPU profile was taken of a running `logthing` against `tools/loadgen`
(`syslog-udp`, 50,000 datagrams/sec offered, 30s, `parse_payloads = true`, local-disk sink):

| | |
|---|---|
| Total CPU | **81.54 CPU-seconds** across 6 threads = **271.8% of one core** |
| Cores available | 12 (≈9.3 idle) |
| Busiest single thread | 80.7% of one core — **nothing is saturated** |
| Datagrams sent | 1,499,944 |
| Received by app | 862,145 (42.5% killed by kernel UDP socket-buffer overflow) |
| Written to Parquet | 516,746 |
| Dropped at writer channel | 312,964 |

**81.54 CPU-sec ÷ 862,145 received = ~94.6µs of CPU per received datagram.**

### 1.2 Why the existing benchmarks cannot explain it

All seven `benches/*.rs` measure exactly one thing: `ParquetSink::to_record_batch`,
the Arrow-mapping layer, which runs on the *writer* task. At its measured 7.07µs/record
× 516,746 records written = **3.65 CPU-sec, or 4.5% of total CPU**.

**Roughly 95% of CPU is in code with zero benchmark coverage.** We do not know what it is.
Reading the code gives a candidate list (envelope regex parse, the seven-parser payload
dispatch chain, a `SyslogMessage` clone, `serde_json::to_value`, metrics label allocation)
but no evidence for how the cost divides among them.

Two further facts constrain the search:

- Only **one** thread was created during load (1.01s of CPU), so the tokio blocking pool
  barely grew — Parquet encode + ZSTD compression is *not* a major cost.
- tokio work-steals, so per-thread CPU **cannot** be attributed to specific tasks. Per-thread
  sampling proves cores are idle; it cannot say which function burns them.

### 1.3 A correction this work must carry forward

`2026-07-24-performance-improvements-plan.md` §2.1 cites **~500µs–1.3ms per record** for
`to_record_batch` and calls it "the single highest-value performance improvement identified."
The committed criterion benches contradict this by 40–100×:

| Source | Criterion median |
|---|---|
| generic/HEC | 2.58 µs |
| suricata | 4.59 µs |
| wef | 5.64 µs |
| syslog | 7.07 µs |
| sflow | 7.01 / 8.38 µs |
| ipfix (1-flow datagram) | 12.47 µs |
| zeek conn | 13.14 µs (2.60 µs amortized) |

Cross-checked twice: `BENCHMARK_RESULTS.md` shows zeek accepting 3,998.9 of 4,000 rec/s on a
256-slot channel, and the syslog baseline shows zero drops at 10k/s — both arithmetically
impossible at 500µs/record. The old figure came from ad hoc profiling that the amortization
results doc itself admits was never rigorously re-measured.

**This is the second time an unreproducible ad hoc measurement has misdirected prioritization
in this repo.** That history is the reason this design insists on a repeatable, in-tree,
self-validating mechanism rather than another one-off.

## 2. Goal and non-goals

**Goal:** a permanent, repeatable, in-repo capability to answer "which functions consume CPU
in the ingest path", starting with syslog UDP — and a written finding that accounts for the
~94.6µs/datagram.

**Non-goals** (explicitly rejected, see §4):

- Per-task attribution via `tokio-console`/`console-subscriber` — needs global
  `--cfg tokio_unstable`, a build-wide change affecting every build and CI job.
- Per-stage timing histograms through the `metrics` pipeline — adds cost to the very
  hot path being measured.
- Profiling sources other than syslog UDP in this cycle.

## 3. Environment constraints (verified, not assumed)

| Constraint | Consequence |
|---|---|
| `perf` not installed | `perf`-based profiling unavailable |
| No passwordless sudo | Cannot install it or change sysctls unattended |
| `/proc/sys/kernel/perf_event_paranoid = 3` | Unprivileged `perf_event_open` blocked **entirely** — even an installed `perf` would fail |
| `scripts/profile-server.sh`, `scripts/run-flamegraph.sh` | Both hard-depend on the above; both are dead code today |
| `binaries.yml` cross-compiles static musl via cargo-zigbuild | Any new C dependency is a cross-build risk; repo already dropped `native-tls`/`openssl-sys` for this reason |
| `rust.yml:54` has a `build-kerberos` job | Established convention: each optional feature gets its own CI job |

`pprof-rs` sidesteps the blocker: it samples via `setitimer(ITIMER_PROF)` + a `SIGPROF`
handler + `backtrace`, **not** `perf_event_open`. No root, no sysctl, no install.

### 3.1 Cross-thread sampling — empirically verified

A prior review objected that `setitimer(ITIMER_PROF)` only signals the arming thread (true of
gprof and of Go before 1.9), which would make tokio's workers invisible and invalidate the
approach. This was tested rather than argued. A standalone binary using pprof 0.14.1 built the
`ProfilerGuard` **on the main thread, which then only slept**, while four `std::thread`s and
four tokio worker threads burned CPU in two distinctly-named `#[inline(never)]` functions:

```
TOTAL SAMPLES               : 761
samples in std::thread burn : 264
samples in tokio worker burn: 497
distinct stacks             : 8
```

264 + 497 = 761 — **100% of samples landed on the busy spawned threads; zero on the idle
arming thread.** Current Linux/glibc delivers process-directed `SIGPROF` to a thread that is
actually running and has not blocked it. Row 16 of the decision log pins this with a
regression test so a platform or crate change cannot silently reintroduce the failure.

## 4. Decision log

Rows 1–3 were decided by the user directly and are not open for revision.

| # | Question | Chosen | Why |
|---|---|---|---|
| 1 | Lifespan | Permanent, feature-gated | user-selected |
| 2 | Granularity | Symbol-level flamegraph only | user-selected; avoids global `tokio_unstable` and hot-path histogram cost |
| 3 | Trigger | Env var, fixed window | user-selected; no network surface |
| 4 | Profiler | `pprof-rs` 0.14.1 | only symbol-level option runnable unprivileged here; §3.1 verified |
| 5 | First source | syslog UDP | only source `loadgen` can drive; only one with a committed baseline |
| 6 | Placement | `src/profiling/mod.rs` + no-op stub | `main.rs` already 626 lines; one unconditional call site, no scattered `#[cfg]` |
| 7 | Artifacts | `flamegraph.svg` + `profile.pb` | explicitly requested; `.pb` enables drill-down a static SVG cannot |
| 8 | Sample rate | 99 Hz default, overridable | prime — avoids lockstep with the writer's 1s ticker |
| 9 | Unwinding | DWARF (pprof default) | `frame-pointer` needs build-wide `-Cforce-frame-pointers`; reversible later |
| 10 | Build profile | `--profile profiling` | release strips symbols → unreadable flamegraph |
| 11 | Failure policy | Log ERROR, never kill ingest | a profiler must not take down the daemon it observes |
| 12 | Overhead validation | Required — see row 20 | this repo has already shipped one unreproducible number |
| 13 | musl risk | `optional = true`, excluded from `default` | musl cross-builds then never compile it |
| 14 | vs. bench branch | Separate, cross-validate | top-down profile and bottom-up bench are independent evidence |
| 15 | Window vs. load timing | `LOGTHING_PROFILE_DELAY_SECS` then sample N; **profile one rate point per session** | fixed-from-startup could close before load starts, or blanket idle+10k+50k+unbounded and dilute the target regime |
| 16 | Cross-thread regression test | Burner on a **different** thread from the guard builder | pins §3.1's verified behaviour against platform/crate drift |
| 17 | Broken scripts | Delete `profile-server.sh` + `run-flamegraph.sh`; add `profile-syslog-udp.sh` | both reference unavailable tooling and write to the same output dir |
| 18 | Start-on-first-datagram | No | would put profiling logic on the hot path being measured |
| 19 | Self-validation | `profile-metadata.json` + loud ERROR on an unrepresentative window | cannot *prevent* a race against an externally-started generator; can make it impossible to pass silently |
| 20 | Overhead metric | **CPU-sec per received datagram**, 3 repeats, otherwise-idle box | normalises out the kernel-drop nonlinearity that confounds the raw counter |
| 21 | CI | `build-pprof` job mirroring `build-kerberos` | verified convention at `rust.yml:54`; otherwise the feature and its gated tests never compile in CI |
| 22 | Dep declaration | `default-features = false`, features `["flamegraph","protobuf-codec"]` | row 13's rationale requires controlling transitive pull-in. **`prost-codec` was rejected on inspection:** pprof 0.14.1 requires `prost ^0.12` while logthing resolves `prost 0.14.4` — an incompatible major, so `prost-codec` would add a *second* prost rather than reuse the existing one. `protobuf-codec` uses `protobuf ^2.0`, which is pure Rust (no C dependency, so musl-safe) and conflicts with nothing already present |
| 23 | `run-with-profiling.sh` | Keep — noticed, deliberately excluded | no perf/flamegraph dependency; unrelated WEF/S3 env runner |

## 5. Architecture

### 5.1 Module

New `src/profiling/mod.rs` behind an off-by-default cargo feature `pprof`:

```toml
[features]
pprof = ["dep:pprof"]

[dependencies]
pprof = { version = "0.14", default-features = false, features = ["flamegraph", "protobuf-codec"], optional = true }
```

`protobuf-codec` (rust-protobuf 2.x) is chosen over `prost-codec` because pprof 0.14.1 pins
`prost ^0.12` while this crate resolves `prost 0.14.4`; `prost-codec` would therefore add a
second, incompatible prost rather than reuse the existing one. `protobuf` 2.x is pure Rust,
so it introduces no C dependency and does not threaten the musl cross-builds (row 13).

Two implementations of one small interface — a real sampler when the feature is on, a no-op
stub when off — so `src/main.rs` gets exactly one unconditional call site and no scattered
`#[cfg]` blocks.

### 5.2 Decoupling: the activity probe

`maybe_start()` accepts an **activity-probe closure** `impl Fn() -> Option<u64>` rather than
importing the metrics stack. The server constructs it from the Prometheus recorder handle;
unit tests pass a fake. This keeps `profiling` free of metrics coupling and makes row 19's
validation logic testable without a running server.

### 5.3 Control surface

Environment variables only — deliberately **not** config-file. `logthing.admin.toml` is
git-tracked and loaded with *higher* precedence than `logthing.toml`, a trap already
documented in commit `87b1d5e` that silently overrode ports and `parse_payloads` during the
previous baseline run.

| Variable | Default | Meaning |
|---|---|---|
| `LOGTHING_PROFILE_SECS` | unset = off | Sample for N seconds |
| `LOGTHING_PROFILE_DELAY_SECS` | `0` | Wait D seconds after startup before sampling |
| `LOGTHING_PROFILE_HZ` | `99` | Sample rate |
| `LOGTHING_PROFILE_DIR` | `./profiling-results` | Output directory |

### 5.4 Behaviour

`async_main()` calls `profiling::maybe_start(probe)` once. When enabled, it spawns a task:

1. sleep D
2. read probe → `counter_before`
3. hold a `ProfilerGuard` for N seconds
4. read probe → `counter_after`
5. build report; `create_dir_all` the output dir
6. write `flamegraph.svg`, `profile.pb`, `profile-metadata.json`
7. log absolute paths at INFO — **or** ERROR per §5.5

The server serves normally throughout and after. Profiling never gates startup or shutdown.
Any profiler error is logged at ERROR and swallowed (row 11).

### 5.5 Self-validation (row 19)

`profile-metadata.json` records: sample count, window start/end, Hz, and
`counter_after - counter_before`.

If **sample count is below threshold** or **the counter did not move**, log at ERROR:

> profile did not overlap load; artifacts are not representative

This does not prevent a race with an externally-started `loadgen` — that is structurally
impossible to prevent — but it makes the race impossible to mistake for success. The e2e
test asserts on this metadata, **not** on file existence.

### 5.6 Loud-failure rule

If `LOGTHING_PROFILE_SECS` is set but the binary was built without the `pprof` feature, the
stub logs a WARN naming the missing feature. A profiling run that silently produces nothing
is the same failure mode that produced the §1.3 correction.

## 6. Testing

Per `CLAUDE.md`, all three levels are required or must be explicitly justified as
inapplicable. All three apply here.

**Unit** — env parsing (absent, zero, valid, non-numeric, out-of-range), delay handling,
metadata construction, and §5.5's unrepresentative-window decision driven by a fake probe.
No sampler required.

**Integration** — feature enabled; sample ~1s against a CPU burner running **on a different
thread from the one that built the guard** (row 16); assert all three artifacts exist and are
non-empty, the SVG contains the burner's symbol, and metadata sample count > 0.

**E2E** — `scripts/profile-syslog-udp.sh` starts the `--profile profiling` binary against the
loadgen baseline config, waits, drives **one** rate point with `loadgen syslog-udp`, and
asserts metadata shows a moved counter and a sample count above threshold.

## 7. Deliverables

Completion requires **both**:

1. The tooling above, tested and CI-wired.
2. A write-up in `docs/performance/` following `methodology-template.md` that **accounts for
   the ~94.6µs/datagram** with actual findings.

Item 2 is a completion criterion, not optional polish. Tooling that runs but produces no
finding does not close this work.

## 8. Known residual risks

- **Second-order overhead distortion.** If profiling perturbs the kernel UDP drop rate, the
  received-count denominator in row 20's metric shifts, distorting CPU-sec-per-datagram in
  either direction. Note it in the write-up; it does not invalidate the comparison.
- **DWARF unwinding cost at high sample rates.** Mitigated by defaulting to 99 Hz and making
  it overridable; escalate to `frame-pointer` only if DWARF proves unreliable.
- **Race with externally-started load.** Detected, not prevented (§5.5).
