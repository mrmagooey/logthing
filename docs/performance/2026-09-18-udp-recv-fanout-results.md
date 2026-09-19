# UDP receive fan-out (`recv_tasks`) — measured results (2026-09-18)

`recv_tasks` (default `1`) makes the `ipfix`, `sflow`, and `syslog` (UDP arm
only) UDP listeners bind `N` `SO_REUSEPORT` sockets on the same port, each
drained by its own tokio task, instead of one socket drained by one task. At
`recv_tasks=1` every listener runs today's exact code path, unchanged.

## Hardware caveat (carried forward verbatim from prior perf docs)

This is a **QEMU/KVM guest, 12 vCPUs, no `cpufreq` interface**, with the
generator and server sharing the same core pool. This setup cannot establish
an absolute maximum sustainable rate; for UDP the kernel queue saturates
before any CPU ceiling is found. Nothing below is a capacity number — every
figure is loss at a fixed, reproduced offered rate.

(Copied verbatim from `docs/performance/2026-09-14-throughput-baseline-repeats.md`;
diffed against that file's "Hardware caveat" section to confirm it is
byte-identical.)

## THE LIMITATION THAT MUST BE READ BEFORE ANY NUMBER BELOW

`SO_REUSEPORT` distributes datagrams across the socket group by hashing each
packet's source/destination address-port **4-tuple**. A **single sender**
therefore always hashes to the same socket, no matter how high `recv_tasks`
is set — **raising the knob buys that deployment nothing**. Every
measurement in this document used **4 generator processes** (`GEN_PROCS=4`),
i.e. 4 distinct source ports, so everything below characterizes a
multi-sender workload and nothing else.

- **Benefits:** deployments with many distinct senders on one listener — a
  fleet of syslog hosts, many sFlow agents, many IPFIX exporters.
- **Does not benefit:** a single high-rate sender (one exporter, one
  forwarder). That deployment will raise `recv_tasks` and see no change,
  and could reasonably conclude the feature is broken — it isn't; the
  4-tuple hash just never varies for a fixed sender.
- **Follow-up for the single-sender case:** `recvmmsg` (fewer syscalls per
  datagram on one flow) is not implemented. This is the more valuable
  follow-up for that deployment shape; `recv_tasks` is not it.

This finding came out of Task 4's review (see `progress.md`) and is now
carried in the `recv_tasks` doc comments on all three listener configs
(`src/config/mod.rs`).

## 1. What was run

- **Feature:** `recv_tasks` on the `ipfix`, `sflow`, and `syslog` (UDP arm
  only) listeners, added in this branch's Tasks 1-6.
- **Git commit hash (logthing):** `69eaba9` (`git rev-parse --short HEAD`,
  branch `perf/udp-recv-fanout`, worktree `/home/dev/projects/logthing-fanout`).
- **Date:** 2026-09-18.
- **Host:** `nproc` = **12**; `sysctl net.core.rmem_max` = **212992** (208
  KiB, stock — same value as the committed `2026-09-18-max-ingest-rate.md`
  campaign).
- **Core split:** generator pinned to `taskset -c 0-3` (4 cores), server
  pinned to `taskset -c 4-11` (8 cores) — identical to the committed
  campaign this document compares against.
- **`logthing` build profile:** `--release`.
- **Persistence target:** real `[*.local]` Parquet sink (`SHAPE=real`).
- **Harness:** `scripts/max-ingest-rate.sh`, `RUNS=3` unless noted,
  `DURATION=15`, `GEN_PROCS=4`, `LOSS_BUDGET=0.1` (0.1% total-loss budget).
- **How `recv_tasks` was set:** the `LOGTHING__<SECTION>__RECV_TASKS`
  environment variable (`config::Environment::with_prefix("LOGTHING")
  .separator("__")`, `src/config/mod.rs`) — the harness spawns `logthing`
  as a child process, so the variable is inherited with no harness change.
  Confirmed working by the gate below, not assumed.
- **Exact command shapes:**

  Control (`recv_tasks` unset, i.e. `1`):
  ```bash
  cd /home/dev/projects/logthing-fanout
  FORMAT=ipfix  SHAPE=real RATE=37500 DURATION=15 RUNS=3 GEN_PROCS=4 ./scripts/max-ingest-rate.sh
  FORMAT=sflow  SHAPE=real RATE=40000 DURATION=15 RUNS=3 GEN_PROCS=4 ./scripts/max-ingest-rate.sh
  FORMAT=syslog SHAPE=real RATE=20000 DURATION=15 RUNS=3 GEN_PROCS=4 PORT=15140 ./scripts/max-ingest-rate.sh
  ```

  Fanned out (`recv_tasks=4`), ramp search for the new ceiling:
  ```bash
  cd /home/dev/projects/logthing-fanout
  LOGTHING__IPFIX__RECV_TASKS=4  FORMAT=ipfix  SHAPE=real RUNS=3 DURATION=15 \
    RAMP_START=20000 BISECT_RESOLUTION=2000 RAMP_MAX=400000 GEN_PROCS=4 ./scripts/max-ingest-rate.sh
  LOGTHING__SFLOW__RECV_TASKS=4  FORMAT=sflow  SHAPE=real RUNS=3 DURATION=15 \
    RAMP_START=20000 BISECT_RESOLUTION=2000 RAMP_MAX=400000 GEN_PROCS=4 ./scripts/max-ingest-rate.sh
  LOGTHING__SYSLOG__RECV_TASKS=4 FORMAT=syslog SHAPE=real RUNS=3 DURATION=15 PORT=15140 \
    RAMP_START=20000 BISECT_RESOLUTION=2000 RAMP_MAX=400000 GEN_PROCS=4 ./scripts/max-ingest-rate.sh
  ```

  Fixed-rate before/after and the `recv_tasks` sweep used the same harness
  with `RATE=<n>` set instead of a ramp, and `LOGTHING__IPFIX__RECV_TASKS=N`
  for `N` in `{1,2,4,8}` for the sweep.

- **syslog ran on port 15140, not 514.** Both 514 (IANA syslog) and 601
  (the syslog listener's own default TCP port) are privileged; this process
  runs unprivileged. Every syslog row below is UDP/TCP port **15140** —
  do not read anything below as a port-514 or port-601 result. Same
  convention as `docs/performance/2026-09-18-max-ingest-rate.md`.

### The gate

`LOGTHING__IPFIX__RECV_TASKS=4` was verified, before any number below was
recorded, to produce **exactly 4 sockets bound to UDP 4739**, counted in
`/proc/net/udp`, with the server logging its recv-task count (the listener
logs `"IPFIX UDP listener started on {} ({} recv tasks)"`,
`src/ipfix/listener.rs:200`, on the fan-out path). Without this check a
silently-ignored env var would have made every "fanned-out" number in this
document a re-measurement of the `recv_tasks=1` default path wearing a
different label. Source: `progress.md`'s Task 7 entry ("GATE PASSED FIRST:
`LOGTHING__IPFIX__RECV_TASKS=4` produces exactly 4 sockets bound to UDP
4739 (counted in `/proc/net/udp`) and the server logs the recv-task
count.").

## 2. Goals & metrics captured

Per rate point: `offered`, `achieved`, kernel-socket drops
(`<format>_socket_drops` / `syslog_udp_socket_drops` for syslog, reconciled
against the listening socket group's own `/proc/net/udp` drop counter —
summed across every socket sharing the port, per the `parse_proc_net_udp`
fix below), writer-channel drops, buffer hard-cap drops, `kernel_loss_pct`,
`total_loss_pct`, and `srv_cores` (server CPU utilization, `ps`-sampled).
All loss in every log referenced below is kernel-socket drop; writer- and
buffer-channel drops were 0 on every run at every rate tested.

**`parse_proc_net_udp` summing prerequisite:** this campaign requires the
harness read *every* socket in the `SO_REUSEPORT` group from
`/proc/net/udp`, not just the first. That fix (branch
`fix/harness-drop-aggregation`, `89dd749`) is merged onto this branch and
was confirmed present via `SELFTEST=1 ./scripts/max-ingest-rate.sh` before
Task 7 began (see Task 0 entries in `progress.md`). Without it, a fanned-out
run's harness-side drop count reads one socket of four, disagrees with the
in-process counter, and the run aborts on reconciliation rather than
producing a silently wrong number.

## 3. Comparability notes

- The `recv_tasks=1` "before" ceilings are the committed figures from
  `docs/performance/2026-09-18-max-ingest-rate.md`, produced by the same
  harness, same host, same core split, same `RUNS=3`/`DURATION=15`/
  `GEN_PROCS=4`/`0.1%` budget. They are directly comparable to the
  `recv_tasks=4` figures below.
- **Precision:** per the variance finding (§4), a 3-run median near a
  format's loss knee can land either side of the 0.1% budget by chance.
  This applies equally to the committed `recv_tasks=1` figures (measured
  the same way) and the `recv_tasks=4` figures here, so the before/after
  *comparison* stays fair — but no single figure in this document,
  including the committed ones, should be read as accurate beyond **two
  significant figures**. Treat "65,000/s" as "~65k/s", not as a rate
  distinguishable from 64,800 or 65,300.

## 4. Results

### Ceiling table (median loss ≤ 0.1%, RUNS=3, DURATION=15, GEN_PROCS=4)

| format | `recv_tasks=1` (committed) | `recv_tasks=4` (measured now) | ratio |
|---|---:|---:|---:|
| ipfix  | 37,500/s | **65,000/s** | 1.73x |
| sflow  | 40,000/s | **82,500/s** | 2.06x |
| syslog | 20,000/s | **27,500/s** | 1.38x |

Source logs (committed verbatim beside this document): `docs/performance/2026-09-18-udp-recv-fanout-ipfix-ramp-rt4.log`,
`docs/performance/2026-09-18-udp-recv-fanout-sflow-ramp-rt4.log`,
`docs/performance/2026-09-18-udp-recv-fanout-syslog-ramp-rt4.log`. Each ramp found its ceiling by
bisection: the last `PASS` rate before the first sustained `FAIL-LOSS`
(e.g. ipfix passed cleanly at 65,000/s — three runs, 0.0000% loss each —
and failed at 67,500/s with a median of 0.6440%, one run showing a
non-zero writer-channel drop as well, reported separately per the harness's
own note rather than folded into the kernel figure).

### Fixed-rate before/after at each format's old (`recv_tasks=1`) ceiling

| format | `recv_tasks=1` @ old ceiling | `recv_tasks=4` @ old ceiling | `recv_tasks=4` @ new ceiling |
|---|---|---|---|
| ipfix @ 37,500/s  | median **0.0000%** (1 of 3 runs FAIL-LOSS, run 2 lost 4.90% before restart-noise recovered) | median **0.0000%**, all 3 PASS | @ 60,000/s: median **0.0000%**, all 3 PASS |
| sflow @ 40,000/s  | median **0.1380%** | median **0.1828%** | @ 60,000/s: median **0.0007%**, per-run kernel drops 0 / 6 / 38, `srv_cores` 2.20-2.30 |
| syslog @ 20,000/s (RUNS=5, re-measured — see methodology note below) | median **0.0310%** (losses 0.0213, 5.3181, 0.0310, 0.0130, 0.7374) | median **0.0000%** (losses 0.0000 x5) | @ 40,000/s: median **0.4470%**, all 3 FAIL-LOSS |

Notes:
- ipfix at `recv_tasks=4`/37,500/s and syslog at `recv_tasks=4`/40,000/s
  both show that pushing `recv_tasks=4` well past its own new ceiling (in
  syslog's case, 40,000/s vs. a 27,500/s ceiling) fails exactly as
  expected — fan-out raises the ceiling, it does not remove one.
- sflow's `recv_tasks=4` @ 40,000/s median (0.1828%) is *higher* than
  `recv_tasks=1`'s (0.1380%) at the same rate — this is not "fan-out made
  it worse," it is the variance finding below: one of the three runs lost
  16,819 datagrams (2.80%) while its two neighbours lost under 0.19%
  combined. See §4's variance finding for the full picture, including a
  5-run repeat of exactly this rate that landed at median 0.0000%.
- **`srv_cores` at sflow's `recv_tasks=4`/60,000/s (2.20-2.30) is not
  directly comparable to `recv_tasks=1`/40,000/s (1.14-1.19)** — that
  conflates the CPU cost of more recv tasks with the cost of a higher
  offered rate, two variables moving at once. The like-for-like,
  fixed-rate comparison is `recv_tasks=4`/40,000/s: `srv_cores`
  **1.14-1.19 → 1.37-1.50** (`docs/performance/2026-09-18-udp-recv-fanout-sflow-rt1-40000.log`
  vs. `docs/performance/2026-09-18-udp-recv-fanout-sflow-rt4-40000.log`),
  i.e. fan-out alone costs roughly a fifth of a core more at the same
  rate. The 60,000/s figure is retained in the table above because it is
  the new ceiling, not because it is comparable to the 40,000/s row.
- **The syslog `recv_tasks=1`/`recv_tasks=4` @ 20,000/s cells were
  re-measured at `RUNS=5`**, replacing an earlier `RUNS=3` pair whose
  `recv_tasks=4` median rested on a `GENERATOR-LIMITED` run. See "A note
  on `GENERATOR-LIMITED` runs and loss medians" below for why, and for the
  other three committed logs with the same defect that were **not**
  re-measured.

Source logs (committed verbatim beside this document):
`docs/performance/2026-09-18-udp-recv-fanout-ipfix-rt1-37500.log`,
`docs/performance/2026-09-18-udp-recv-fanout-ipfix-rt4-37500.log`,
`docs/performance/2026-09-18-udp-recv-fanout-ipfix-rt4-60000.log`,
`docs/performance/2026-09-18-udp-recv-fanout-sflow-rt1-40000.log`,
`docs/performance/2026-09-18-udp-recv-fanout-sflow-rt4-40000.log`,
`docs/performance/2026-09-18-udp-recv-fanout-sflow-rt4-60000.log`,
`docs/performance/2026-09-18-udp-recv-fanout-syslog-rt1-20000-clean5.log`,
`docs/performance/2026-09-18-udp-recv-fanout-syslog-rt4-20000-clean5.log`,
`docs/performance/2026-09-18-udp-recv-fanout-syslog-rt4-40000.log`.

### A note on `GENERATOR-LIMITED` runs and loss medians

The harness correctly refuses to report a `GENERATOR-LIMITED` **rate** as a
ceiling during a ramp — the ramps in this document honour that. But a
`GENERATOR-LIMITED` **individual run** inside an otherwise-fixed-rate,
`RUNS=N` set is not excluded from that rate's loss statistics: it still
contributes a loss figure, and because the run under-offered the target
rate, that figure is often near-zero for the wrong reason — the run never
sent the traffic that would have been lost, not because nothing was lost.
This is a gap in the measurement method, not in this document's arithmetic.

**Four committed logs in this document contain at least one
`GENERATOR-LIMITED` run:**

- `docs/performance/2026-09-18-udp-recv-fanout-syslog-rt4-20000.log` — run 2
  of 3 achieved only 15,482.5/s against a 20,000/s target (77%) and
  reported 0.0000% loss, sitting at the median position alongside run 1's
  genuine 0.0000%. **This one distorted a published cell**: the original
  `recv_tasks=4` @ 20,000/s median of 0.0000% rested in part on a run that
  never offered full load. It has been replaced above by a clean `RUNS=5`
  re-measurement (`syslog-rt1-20000-clean5.log` /
  `syslog-rt4-20000-clean5.log`) with no `GENERATOR-LIMITED` run in either
  set — the re-measured data supports the same conclusion more strongly
  (`recv_tasks=4` is zero-loss across all 5 runs; `recv_tasks=1` has two
  bad runs, one at 5.32%).
- `docs/performance/2026-09-18-udp-recv-fanout-sflow-rt1-40000.log` — run 3
  of 3 achieved 36,563/s against 40,000/s (91%) and reported 1.2937% loss.
  This run is the **maximum**, not the median, of that 3-run set — the
  published median (0.1380%) is run 2's genuine value and is not affected.
  Left as measured.
- `docs/performance/2026-09-18-udp-recv-fanout-sweep-ipfix-rt1.log` — run 1
  of 5 achieved 50,771/s against 60,000/s (85%) and reported 15.8659%
  loss. This run is the **maximum**, not the median, of that 5-run set —
  the published median (7.8068%) is run 3's genuine value and is not
  affected. Left as measured.
- `docs/performance/2026-09-18-udp-recv-fanout-sflow-ramp-rt4.log` — one run
  at the 160,000/s ramp step was `GENERATOR-LIMITED`. That rate is well
  above sflow's actual 82,500/s ceiling and the other two runs at that
  step already failed on loss, so the ramp's verdict at that step
  (`FAIL-LOSS`) was unaffected and the ramp correctly continued down to
  find the ceiling. Left as measured; this is the case the harness's
  ramp-level `GENERATOR-LIMITED` handling was designed for and handled
  correctly.

**Follow-up (not fixed here):** the harness should exclude
`GENERATOR-LIMITED` runs from a fixed-rate set's loss statistics
(min/median/max), not only from ramp ceiling verdicts. The syslog case
above shows this is not merely theoretical — it silently produced a
misleadingly optimistic published number once in this campaign. Recorded
as a durable fix for `scripts/max-ingest-rate.sh`; out of scope for this
document.

### The `recv_tasks` sweep — IPFIX @ 60,000/s, RUNS=5

60,000/s sits above the `recv_tasks=1` ceiling (37,500/s) and below the
`recv_tasks=4` ceiling (65,000/s), so it is guaranteed to show loss at low
`recv_tasks` and should show the fan-out's effect clearly.

| `recv_tasks` | median loss | per-run kernel drops | `srv_cores` |
|---|---:|---|---|
| 1 | 7.8068% | 129172, 74011, 70256, 50758, 54294 | 1.33-1.49 |
| 2 | 1.5577% | 60619, 12233, 14019, 18293, 43 | 1.44-1.71 |
| 4 | 0.0000% | 0, 17235, 0, 0, 0 | 1.62-1.82 |
| 8 | 0.0000% | 0, 0, 0, 0, 0 | 1.66-1.94 |

Source logs (committed verbatim beside this document):
`docs/performance/2026-09-18-udp-recv-fanout-sweep-ipfix-rt1.log`,
`docs/performance/2026-09-18-udp-recv-fanout-sweep-ipfix-rt2.log`,
`docs/performance/2026-09-18-udp-recv-fanout-sweep-ipfix-rt4.log`,
`docs/performance/2026-09-18-udp-recv-fanout-sweep-ipfix-rt8.log`.

Monotonic and saturating at `recv_tasks=4`: 7.81% → 1.56% → 0% → 0%.
`recv_tasks=8` was the only setting with no outlier run at all across 5
repeats, but `recv_tasks=4`'s median is already 0.0000% and `n=5` is not
enough to call that a real difference — **4 is the measured
recommendation; 8 bought no further median improvement**, only marginally
more headroom against an outlier that `recv_tasks=4` also mostly avoided.
CPU cost is modest across the whole sweep: `srv_cores` rises only from
~1.33 to ~1.87 across an 8x increase in task count, i.e. extra recv tasks
are cheap — they do not each consume a dedicated core.

### The variance finding (read this before trusting any figure near a knee)

An sFlow run at `recv_tasks=4`, 40,000/s lost 16,819 datagrams (2.80%)
while its two neighbouring runs in the same 3-run set lost 1,097 and 170
(`docs/performance/2026-09-18-udp-recv-fanout-sflow-rt4-40000.log`). Two
explanations were tested and **both were refuted**:

- **Hypothesis 1 — warm-up (first run spikes):** REFUTED. A 5-run repeat at
  the same rate gave kernel drops of 0, 0, 0, 6034, 39521
  (`docs/performance/2026-09-18-udp-recv-fanout-sflow-rt4-40000-repeat.log`)
  — the spike came **last**, not first.
- **Hypothesis 2 — progressive degradation across a run sequence:**
  REFUTED. A separate 6-run repeat gave kernel drops of 7829, 8244, 0, 84,
  0, 0
  (`docs/performance/2026-09-18-udp-recv-fanout-sflow-rt4-40000-repeat6.log`)
  — the bad runs came **first**, not last.

Conclusion: this is random run-to-run variance, not ordered. Host load
average was 3.2-4.4 on this 12-vCPU guest during the campaign — consistent
with occasional scheduling contention rather than a deterministic effect of
either fan-out or run order. **Consequence: near a format's loss knee, a
3-run median can land on either side of the 0.1% budget purely by chance.**
This applies equally to the committed `recv_tasks=1` ceilings in
`docs/performance/2026-09-18-max-ingest-rate.md`, which were measured the
same way (same `RUNS=3`, same host) — so the before/after comparison in
this document stays fair, run-for-run. But it means no figure in either
document deserves more than two significant figures of trust, and that
limitation is stated here explicitly rather than left implicit.

## 5. What this does NOT establish

- **This is a loopback figure on a shared-CPU KVM guest**, generator and
  server on one 12-vCPU host, not a deployment capacity number — same
  caveat as every other document in this campaign (§ Hardware caveat
  above).
- **It does not establish a single-sender ceiling for any `recv_tasks`
  value above 1.** Every measurement here used 4 generator processes (4
  source ports); see "THE LIMITATION" above. A single-sender deployment's
  `recv_tasks=4` ceiling is not measured by this document and, per the
  4-tuple hash mechanism, is expected to equal its `recv_tasks=1` ceiling.
- **The `recv_tasks` sweep (§4) was run on IPFIX only.** sFlow and syslog
  share the same fan-out mechanism (same `SO_REUSEPORT` bind helper,
  reviewed identically per `progress.md`'s Task 5/6 entries), so the shape
  of the curve — saturating around 4, cheap in CPU — is expected to
  generalize, but this was not independently measured for the other two
  formats.
- **No figure in this document is accurate beyond two significant
  figures** — see the variance finding, §4.
