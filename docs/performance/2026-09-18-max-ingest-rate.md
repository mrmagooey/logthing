# Max ingest rate — per-format capacity results

First capacity numbers (not just attribution numbers) for all seven wire
formats logthing accepts. Produced by the `max-ingest-rate` plan
(`docs/superpowers/specs/2026-09-16-max-ingest-rate-design.md`), whose Task 0
(`docs/performance/2026-09-16-generator-ceiling.md`) established that the
load generator itself does not need work for five of the seven formats, and
whose Task 11 ran the ramps this document reports.

## Hardware caveat (carried forward verbatim from prior perf docs)

This is a **QEMU/KVM guest, 12 vCPUs, no `cpufreq` interface**, with the
generator and server sharing the same core pool. This setup cannot establish
an absolute maximum sustainable rate; for UDP the kernel queue saturates
before any CPU ceiling is found. Nothing below is a capacity number — every
figure is loss at a fixed, reproduced offered rate.

(Copied verbatim from `docs/performance/2026-09-14-throughput-baseline-repeats.md`,
per the requirement that it appear unedited here too.)

## 1. What was run

- **Format / subcommand:** all seven — `loadgen ipfix-udp`, `sflow-udp`,
  `syslog-udp`, `zeek-tcp`, `suricata-tcp`, `hec-http`, `generic-http`
  (`tools/loadgen`).
- **Git commit hash (logthing):** `f41e826` (`git rev-parse --short HEAD`,
  branch `perf/max-ingest-rate`).
- **Crate version:** `0.19.1` (`Cargo.toml`).
- **Date:** 2026-09-18.
- **Host:** `nproc` = **12**; `sysctl net.core.rmem_max` = **212992** (208
  KiB, stock, not tuned for this campaign).
- **Core split:** generator pinned to `taskset -c 0-3` (`GEN_CPUS`, 4 cores),
  server pinned to `taskset -c 4-11` (`SRV_CPUS`, 8 cores) — 12 vCPUs total,
  no overlap by `taskset` range, though see §5 on why the two still appear to
  contend.
- **`logthing` build profile:** `--release` (`cargo build --release --bin
  logthing`, `cargo build --release -p loadgen`).
- **Persistence target:** real `[*.local]` Parquet sink writing to a local
  temp directory (`SHAPE=real`) — no MinIO/S3, per the design doc's own rule
  for throughput numbers.
- **Harness:** `scripts/max-ingest-rate.sh` (supersedes
  `scripts/repeat-ipfix-loopback-loss.sh`, see the `Removed` changelog entry).
  Same restart-per-run, zeroed-counter, kernel-drop-reconciling machinery,
  generalised across formats and given a coarse-doubling + bisection search
  for the first rate whose **median** loss (across `RUNS` repeats) exceeds
  `LOSS_BUDGET`.
- **Generator concurrency:** `GEN_PROCS=4` — four `loadgen` processes, each
  offered `rate/4`, all pinned inside `GEN_CPUS`. Task 2's blackhole probe
  (`docs/performance/2026-09-16-generator-ceiling.md`) showed every UDP/TCP
  format scales 3–4.5x from 1 to 4 processes, so a single process is not the
  generator's real ceiling; `GEN_PROCS=4` was used for every run in this
  campaign so the numbers below are not artificially capped by that.
- **Exact commands run** (verbatim, from the two driver scripts used):

  For syslog, zeek, suricata, generic (`.superpowers/sdd/2026-09-16-max-ingest-rate/run-all-ramps.sh`):
  ```
  SHAPE=real RUNS=3 DURATION=15 RAMP_START=5000 BISECT_RESOLUTION=2000 \
    RAMP_MAX=400000 LOSS_BUDGET=0.1 GEN_PROCS=4 FORMAT=<format> \
    ./scripts/max-ingest-rate.sh
  ```
  with `EVENTS_PER_REQUEST=100` added for `hec`/`generic`, and
  `PORT=15140` added for `syslog` (see §1's syslog-port note below).

  For ipfix, sflow, hec, the same shape/flags were used in an earlier,
  equivalent invocation of the same harness (not preserved as a script file,
  but confirmed by the per-run headers and doubling/bisection sequence
  embedded in `ipfix.log`/`sflow.log`/`hec.log` themselves — same
  `duration=15s runs=3`, same coarse-doubling-then-bisect pattern, same
  `GEN_PROCS=4`-scale offered counts).

  For zeek's and suricata's fixed-rate lower-bound checks
  (`.superpowers/sdd/2026-09-16-max-ingest-rate/run-final.sh`):
  ```
  SHAPE=real RUNS=3 DURATION=15 LOSS_BUDGET=0.1 GEN_PROCS=4 \
    FORMAT=<zeek|suricata> RATE=<50000|55000> ./scripts/max-ingest-rate.sh
  ```

- **syslog ran on port 15140, not 514.** Both 514 (the IANA syslog port) and
  601 (the syslog listener's own default TCP port) are privileged, and this
  process runs unprivileged (uid 1000, no `CAP_NET_ADMIN`). Task 7's
  implementer found the listener binds its TCP port unconditionally, so a
  `PORT` override alone collides with 601's privilege requirement; the
  harness pins `tcp_port = PORT+1` and every syslog row in this document was
  measured against UDP/TCP port **15140**, confirmed by `syslog-run3.log`'s
  own header line (`port=15140`). Do not read anything below as a port-514
  or port-601 result.

## 2. Goals & metrics captured

Per format, at each offered rate: `offered`, `achieved` (measured send
rate), kernel-socket drops (UDP formats only — `ipfix_socket_drops` /
`sflow_socket_drops` / `syslog_udp_socket_drops`, reconciled against the
listening socket's own `/proc/net/udp` drop counter), writer-channel drops
(`parquet_s3_dropped{source=...}`), buffer hard-cap drops
(`parquet_s3_buffer_dropped{source=...}`), rows actually written, and
`kernel_loss_pct` / `total_loss_pct`. TCP and HTTP formats have no kernel
socket to lose datagrams in — those columns are recorded as `n/a`, not `0`,
so "not applicable" stays distinguishable from "measured zero." Every rate
was run 3 times (`RUNS=3`); the harness classifies a rate on the **median**
achieved rate and **median** loss across those 3 runs, not on any single run
— a fix made mid-campaign after a lone scheduling hiccup on this shared host
misclassified zeek's very first rate (see `progress.md`'s campaign-1/2
notes).

## 3. Comparability notes

- The five socket formats (ipfix, sflow, syslog, zeek, suricata) share one
  architecture group (UDP or TCP binary/structured), buffer-policy config
  (`[*.local]`, defaults per `logthing.toml`, byte-identical across every
  run — restored after every restart), and the same `SHAPE=real` sink.
  Numbers across these five are comparable to each other.
- `hec` and `generic` are a second architecture group (HTTP-JSON, shared
  writer path) and are **not directly comparable to unbatched HTTP
  deployments** — see the `--events-per-request` note below.
- **`hec` and `generic` are indistinguishable in logthing's own metrics.**
  `POST /services/collector/event`, `POST /services/collector/raw`, and
  `POST /ingest` (the generic/NDJSON endpoint) all increment the same
  `hec_events_received` counter (`src/ingest/handlers.rs:147,184,219`) and
  all funnel through `dispatch_generic_record`, which lands in a sink
  labelled `source="hec"` regardless of which endpoint received the
  request (confirmed directly: `src/forwarding/generic_s3.rs:818` asserts
  against `r.source == "hec"` even in generic-path tests). Each row in the
  headline table below was produced by a single generator subcommand run
  alone, never concurrently with the other — **the `hec` row is from
  `loadgen hec-http`, the `generic` row is from `loadgen generic-http`** —
  and that is the only thing that distinguishes them; the server-side
  counters cannot.
- **Both HTTP formats used `--events-per-request 100`.** Task 4
  (`bd88ef5`, "perf(loadgen): batch events per HTTP request") added this
  flag to both `hec-http` and `generic-http`. Without it, one record was
  sent per HTTP request and the measured ceiling was a *request* rate, not
  a *record* rate — Task 2's blackhole probe measured both HTTP generators
  flat at ~21,000–25,000/s regardless of process count (1/2/4 procs), the
  signature of a per-transaction cost, not a per-record one; the committed
  criterion benches put per-record hec/generic decode cost at ~2.6 µs
  (~385k records/s single-threaded, ~17x above that flat number). Batched
  at 100 events/request, both ceilings below are **173,750/s and
  183,750/s** — 7–9x higher. **Do not compare these ceilings to a
  deployment sending one event per HTTP request**; that deployment's
  ceiling is closer to the unbatched ~21–25k/s figure, not the numbers in
  this document.

## 4. Results

### Headline table

| format | max sustainable rate (median loss ≤ 0.1%) | first failing rate, median total loss | kernel / writer / buffer split at that rate | generator ceiling, Task 2, 4-proc trivial shape | gen cores | srv cores | verdict |
|---|---|---|---|---|---|---|---|
| syslog | **20,000/s** | 21,250/s → 0.6645% | kernel-only (writer/buffer = 0 at every rate tested) | 174,888/s | 0-3 | 4-11 | **kernel-limited** |
| ipfix | **37,500/s** | 38,750/s → 0.3811% | kernel-only (writer/buffer = 0 at every rate tested) | 238,295/s | 0-3 | 4-11 | **kernel-limited** |
| sflow | **40,000/s** | 41,250/s → 0.1080% | kernel-only (writer/buffer = 0 at every rate tested) | 254,049/s | 0-3 | 4-11 | **kernel-limited** |
| hec | **173,750/s** | 175,000/s → 1.7711% | writer-channel-only (kernel n/a for HTTP, buffer = 0) | ~21,845/s unbatched, 1-proc (not comparable, see §3) | 0-3 | 4-11 | **writer-limited** |
| generic | **183,750/s** | 185,000/s → 1.2954% | writer-channel-only (kernel n/a for HTTP, buffer = 0) | ~22,297/s unbatched, 1-proc (not comparable, see §3) | 0-3 | 4-11 | **writer-limited** |
| zeek | **≥55,000/s — ceiling NOT found** | n/a — every rate tested either PASSed at 0.0000% or was classified GENERATOR-LIMITED, never FAIL-LOSS | n/a — writer/buffer stayed at 0 on every completed run, including the generator-limited ones | 743,793/s | 0-3 | 4-11 | **generator-limited** |
| suricata | **≥40,000/s — ceiling NOT found** | n/a — same pattern as zeek | n/a — writer/buffer stayed at 0 on every completed run | 468,786/s | 0-3 | 4-11 | **generator-limited** |

Five true ceilings, two honest lower bounds. **Read the zeek and suricata
rows as lower bounds, not ceilings** — see the per-format detail below and
§5.

### Per-format detail

#### syslog — CEILING 20,000/s (`2026-09-18-max-ingest-rate-syslog.log`)

| rate | run | offered | kernel_drops | writer_drops | buffer_drops | total_loss% | verdict |
|---|---|---|---|---|---|---|---|
| 20,000 (last PASS) | 1/2/3 | 299,980 / 299,991 / 299,984 | 73 / 434 / 208 | 0 / 0 / 0 | 0 / 0 / 0 | 0.0243 / 0.1447 / 0.0693 | PASS / FAIL-LOSS / PASS (median 0.0693%, under budget) |
| 21,250 (first fail) | 1/2/3 | 318,743 / 318,737 / 318,727 | 2,118 / 2,969 / 2,003 | 0 / 0 / 0 | 0 / 0 / 0 | 0.6645 / 0.9315 / 0.6284 | FAIL-LOSS (median 0.6645%) |
| 22,500 | — | — | — | — | — | median 2.3400% | FAIL-LOSS |
| 25,000 | — | — | — | — | — | median 3.6067% | FAIL-LOSS |
| 30,000 | — | — | — | — | — | median 10.4065% | FAIL-LOSS |

**All loss is kernel-socket drop** (`syslog_udp_socket_drops`, reconciled
against the listener's own `/proc/net/udp` counter); writer- and buffer-drop
columns are 0 at every rate in this log, including the failing ones.
**Verdict: kernel-limited.**

#### ipfix — CEILING 37,500/s (`2026-09-18-max-ingest-rate-ipfix.log`)

| rate | run | offered | kernel_drops | writer_drops | buffer_drops | total_loss% | verdict |
|---|---|---|---|---|---|---|---|
| 37,500 (last PASS) | 1/2/3 | 562,470 / 562,433 / 562,480 | 12 / 167 / 39,668 | 0 / 0 / 0 | 0 / 0 / 0 | 0.0021 / 0.0297 / 7.0523 | PASS / PASS / FAIL-LOSS (median 0.0297%) |
| 38,750 (first fail) | 1/2/3 | 581,217 / 581,227 / 581,215 | 2,215 / 597 / 5,095 | 0 / 0 / 0 | 0 / 0 / 0 | 0.3811 / 0.1027 / 0.8766 | FAIL-LOSS (median 0.3811%) |

All loss is kernel-socket drop; writer/buffer are 0 throughout. **Verdict:
kernel-limited.** (Note for the record, tied to Finding 2 below: this is a
different picture from the stale 2026-09-14 baseline, where writer-channel
drops dominated IPFIX loss — that was fixed by commit `c103de3` before this
campaign ran.)

#### sflow — CEILING 40,000/s (`2026-09-18-max-ingest-rate-sflow.log`)

| rate | run | offered | kernel_drops | writer_drops | buffer_drops | total_loss% | verdict |
|---|---|---|---|---|---|---|---|
| 41,250 (first fail) | 1/2/3 | 618,716 / 618,706 / 618,728 | 0 / 668 / 1,583 | 0 / 0 / 0 | 0 / 0 / 0 | 0.0000 / 0.1080 / 0.2558 | PASS / FAIL-LOSS / FAIL-LOSS (median 0.1080%) |
| 42,500 | 1/2/3 | 637,467 / 637,457 / 637,479 | 792 / 2,429 / 2,349 | 0 / 0 / 0 | 0 / 0 / 0 | 0.1242 / 0.3810 / 0.3685 | FAIL-LOSS (median 0.3685%) |

All loss is kernel-socket drop; writer/buffer are 0 throughout. **Verdict:
kernel-limited.**

#### hec — CEILING 173,750/s (`2026-09-18-max-ingest-rate-hec.log`, `EVENTS_PER_REQUEST=100`)

| rate | run | offered | writer_drops | buffer_drops | total_loss% | verdict |
|---|---|---|---|---|---|---|
| 173,750 (last PASS) | 1/2/3 | 2,606,000 / 2,606,000 / 2,605,800 | 31,984 / 0 / 0 | 0 / 0 / 0 | 1.2273 / 0.0000 / 0.0000 | FAIL-LOSS / PASS / PASS (median 0.0000%) |
| 175,000 (first fail) | 1/2/3 | 2,624,500 / 2,624,600 / 2,624,800 | 105,677 / 44,812 / 46,488 | 0 / 0 / 0 | 4.0266 / 1.7074 / 1.7711 | FAIL-LOSS (median 1.7711%) |

Kernel loss is `n/a` for HTTP (no socket buffer to overflow). All measured
loss is writer-channel drop (`parquet_s3_dropped{source="hec"}`); buffer
hard-cap drops are 0 throughout. **Verdict: writer-limited.**

#### generic — CEILING 183,750/s (`2026-09-18-max-ingest-rate-generic.log`, `EVENTS_PER_REQUEST=100`)

| rate | run | offered | writer_drops | buffer_drops | total_loss% | verdict |
|---|---|---|---|---|---|---|
| 183,750 (last PASS) | 1/2/3 | 2,756,000 (all 3) | 0 / 0 / 0 | 0 / 0 / 0 | 0.0000 (all 3) | PASS |
| 185,000 (first fail) | 1/2/3 | 2,774,800 (all 3) | 0 / 35,945 / 58,800 | 0 / 0 / 0 | 0.0000 / 1.2954 / 2.1191 | PASS / FAIL-LOSS / FAIL-LOSS (median 1.2954%) |

Same shape as hec: all measured loss is writer-channel drop, landing in the
same `source="hec"`-labelled counter (see §3). **Verdict: writer-limited.**

#### zeek — ≥55,000/s, ceiling NOT found (`2026-09-18-max-ingest-rate-zeek-ramp.log`, `2026-09-18-max-ingest-rate-zeek-fixed-50000.log`, `2026-09-18-max-ingest-rate-zeek-fixed-55000.log`)

| rate | run | offered | achieved | writer_drops | buffer_drops | total_loss% | verdict |
|---|---|---|---|---|---|---|---|
| 40,000 (`2026-09-18-max-ingest-rate-zeek-ramp.log`) | 1/2/3 | 599,970 / 599,980 / 599,980 | 39,996.2 / 39,997.3 / 39,997.0 | 0 / 0 / 0 | 0 / 0 / 0 | 0.0000 (all 3) | PASS |
| 50,000 (`2026-09-18-max-ingest-rate-zeek-fixed-50000.log`) | 1/2/3 | 749,952 / 749,948 / 749,974 | 49,996.1 / 49,995.4 / 49,997.0 | 0 / 0 / 0 | 0 / 0 / 0 | 0.0000 (all 3) | PASS |
| 55,000 (`2026-09-18-max-ingest-rate-zeek-fixed-55000.log`) | 1/2/3 | 824,972 / 824,997 / 824,966 | 54,995.1 / 54,997.5 / 54,995.5 | 0 / 0 / 0 | 0 / 0 / 0 | 0.0000 (all 3) | PASS |
| 80,000 (`2026-09-18-max-ingest-rate-zeek-ramp.log`) | 1/2/3 | 950,275 / 878,427 / 840,395 | 62,562.8 / 58,187.6 / 55,700.9 | 0 / 0 / 0 | 0 / 0 / 0 | 0.0000 (all 3) | GENERATOR-LIMITED (median achieved 58,187.6, 72.7% of target) |

No genuine loss was ever observed for zeek — every completed run, including
the generator-limited ones, shows 0 writer/buffer drops. The search never
reached a `FAIL-LOSS` rate; it reached a rate (80,000/s) where the 4-process
generator itself, under real-shape contention, could not sustain the offered
load (median 58,187.6/s vs 80,000 target). **Verdict: generator-limited** —
there is no failing rate to attribute to the server, so kernel/writer/buffer
figures cannot support any of the other three verdicts. What would settle
whether the *true* server ceiling is well above 55,000/s: an off-box sender,
so the generator is no longer competing with the server for the same 12
vCPUs (see §5) — Task 2's own trivial-shape, no-server-contention measurement
put this same 4-process generator at 743,793/s, over 13x the generator-limited
figure seen here.

#### suricata — ≥40,000/s, ceiling NOT found (`2026-09-18-max-ingest-rate-suricata-ramp.log`, `2026-09-18-max-ingest-rate-suricata-fixed-50000.log`)

| rate | run | offered | achieved | writer_drops | buffer_drops | total_loss% | verdict |
|---|---|---|---|---|---|---|---|
| 40,000 (`2026-09-18-max-ingest-rate-suricata-ramp.log`) | 1/2/3 | 599,984 / 599,981 / 599,973 | 39,998.9 / 39,996.5 / 39,996.5 | 0 / 0 / 0 | 0 / 0 / 0 | 0.0000 (all 3) | PASS |
| 50,000 (`2026-09-18-max-ingest-rate-suricata-fixed-50000.log`) | 1/2/3 | 604,832 / 643,661 / 631,770 | 39,986.9 / 42,528.7 / 41,948.2 | 0 / 0 / 0 | 0 / 0 / 0 | 0.0000 (all 3) | GENERATOR-LIMITED (median achieved 41,948.2, 83.9% of target) |
| 80,000 (`2026-09-18-max-ingest-rate-suricata-ramp.log`) | 1/2/3 | 599,924 / 599,937 / 614,212 | 39,642.8 / 39,875.8 / 40,631.0 | 0 / 0 / 0 | 0 / 0 / 0 | 0.0000 (all 3) | GENERATOR-LIMITED (median achieved 39,875.8, 49.8% of target) |

Same pattern as zeek: zero writer/buffer drops on every run, including the
generator-limited ones; the search never found a `FAIL-LOSS` rate. **Verdict:
generator-limited**, for the same reason and with the same caveat — Task 2
measured this generator at 468,786/s in isolation, roughly 11x the
generator-limited figure at 50,000/s here.

## 5. What this does NOT establish

- **This is a loopback figure on a shared-CPU KVM guest, not a deployment
  capacity number.** The generator and server are two process groups on one
  12-vCPU host; `taskset` pinning keeps them on disjoint CPU ranges, but
  they are still one hypervisor's scheduling domain away from each other,
  and the zeek/suricata generator-limited numbers above (a 4-process
  generator achieving 13x and 11x less than its own isolated ceiling once a
  real server shares the host) are themselves evidence that the isolation is
  imperfect. An off-box sender is the next step, and it is specifically what
  the two unfound ceilings (zeek, suricata) need to become real numbers
  rather than lower bounds.
- **The five found ceilings are not necessarily this host's true capacity
  either** — a kernel-limited or writer-limited ceiling measured with the
  generator sharing the box may differ (probably upward) once the generator
  is no longer contending for the same cores/scheduler.
- **hec/generic ceilings are batched-request numbers** (`--events-per-request
  100`); they say nothing about an unbatched deployment's capacity (§3).

## Findings for follow-up

1. **The Zeek claim in `docs/performance/2026-09-13-multiformat-load-results.md`
   §2 is overturned** — a dated correction note has been added there. That
   doc read a generator achieving 15,283/s against a 20,000/s target as
   proof the generator was the limit; Phase 0
   (`docs/performance/2026-09-16-generator-ceiling.md`) measured that same
   generator at 164,698 records/s single-process (743,793/s at 4 processes,
   trivial shape), and this campaign sustained 55,000/s end-to-end with
   zero measured loss. The claim was wrong at the time it was written for a
   different reason than either doc originally suspected (see §5 above on
   generator/server contention) — it was never a fundamental generator
   ceiling.

2. **`docs/performance/2026-09-14-throughput-baseline-repeats.md`'s real-shape
   IPFIX numbers are stale** — a note has been added there. It recorded
   3.6331% median loss for IPFIX at 20,000/s with writer-channel drops
   "70-75% of everything the kernel actually delivered"; commit `c103de3`
   ("Merge perf/ipfix-accumulator: IPFIX 82% loss -> zero, ~18x throughput"),
   landed the following day and confirmed an ancestor of this campaign's
   `HEAD` (`git merge-base --is-ancestor c103de3 HEAD` — true), eliminated
   that writer-channel loss. This campaign's own ipfix.log confirms it:
   writer_drops are 0 at every rate tested, including the failing ones (§4).

3. **Metric-naming inconsistency, for follow-up — not fixed here.** The
   syslog listener registers its socket-drop stats under the protocol label
   `"syslog_udp"` (`src/syslog/listener.rs:268` and `:368`, both call sites
   of `SocketDropStats::new(..., "syslog_udp")`), producing
   `syslog_udp_socket_drops`, while the IPFIX and sFlow listeners use
   `"ipfix"` and `"sflow"` (`src/ipfix/listener.rs:107`,
   `src/sflow/listener.rs:98`), producing `ipfix_socket_drops` and
   `sflow_socket_drops`. This is not a cosmetic mismatch: Task 11's own
   campaign hit it directly — the plan's original drop-metric map specified
   `syslog_socket_drops` (that metric does not exist), so every syslog run
   silently read kernel loss as zero until the mismatch was found via the
   harness's own kernel-drop reconciliation check (`progress.md`, campaign 2
   notes). Anyone building a dashboard by analogy with the other two UDP
   listeners will silently read zero for syslog the same way. Recorded here
   as a finding; **no production code was changed** for this — out of scope
   for this task.
