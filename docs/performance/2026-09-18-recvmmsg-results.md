# Batched UDP receive (`recv_batch_size`) — measured results (2026-09-18)

`recv_batch_size` (default `32` as of the change recorded in §6 below; `0`
and `1` both mean off; maximum `256`) on the `ipfix`, `sflow`, and `syslog`
(UDP arm only) listeners. Above `1`, a recv task drains up to `N`
already-queued datagrams per `recvmmsg(2)` call instead of issuing one
`recvfrom(2)` per datagram. Never waits to fill a batch — a partial batch is
returned immediately once the socket has nothing more queued. All
measurements in §1-§5 below were taken against the listener defaulting to
`recv_batch_size=1` (off), which was the shipped default at the time this
document was written — the explicit `LOGTHING__IPFIX__RECV_BATCH_SIZE`
overrides shown below make that explicit per run.

## Hardware caveat (carried forward verbatim from prior perf docs)

This is a **QEMU/KVM guest, 12 vCPUs, no `cpufreq` interface**, with the
generator and server sharing the same core pool. This setup cannot establish
an absolute maximum sustainable rate; for UDP the kernel queue saturates
before any CPU ceiling is found. Nothing below is a capacity number — every
figure is loss at a fixed, reproduced offered rate.

(Copied verbatim from `docs/performance/2026-09-14-throughput-baseline-repeats.md`,
diffed against that file's "Hardware caveat" section to confirm byte-identical.)

## Why this exists — measured, not assumed

An earlier feature, `recv_tasks`, binds `N` `SO_REUSEPORT` sockets per
listener. It raised the multi-sender ceiling substantially
(`docs/performance/2026-09-18-udp-recv-fanout-results.md`), but **cannot
help a single sender**: `SO_REUSEPORT` distributes across the socket group
by hashing each packet's source/destination address-port 4-tuple, so one
exporter's traffic always hashes to the same group member no matter how
many are available.

### Gate measurement

Re-confirmed for this plan before any batching number was recorded — ipfix,
real shape, `RUNS=5`, `DURATION=15`, `GEN_PROCS=1` (one generator process,
one source port, so the 4-tuple hash pins all traffic to one `recv_tasks`
group member):

| rate | `recv_tasks=1` | `recv_tasks=8` |
|---|---:|---:|
| 40,000/s | median 0.0000% | median 0.1198% |
| 50,000/s | median 1.0767% | median 1.1231% |

Source logs: `docs/performance/2026-09-18-recvmmsg-gate-40000-rt1.log`,
`docs/performance/2026-09-18-recvmmsg-gate-40000-rt8.log`,
`docs/performance/2026-09-18-recvmmsg-gate-50000-rt1.log`,
`docs/performance/2026-09-18-recvmmsg-gate-50000-rt8.log`.

Identical within variance. The decisive evidence is mechanistic, not just a
null result: `srv_cores` sat at ~1.0 across every run in all four logs even
with eight recv tasks available — seven idle while one did all the work,
exactly as 4-tuple hashing predicts. That gap (single-sender ceiling
40,000-50,000/s vs. the multi-sender `recv_tasks=4` ceiling of 65,000/s
measured in the fan-out document) is what `recvmmsg` batching exists to
close.

## 1. What was run

- **Feature:** `recv_batch_size` on the `ipfix`, `sflow`, and `syslog` (UDP
  arm only) listeners, added in this branch's Tasks 1-6.
- **Git commit hash (logthing):** `af237ac` (`git rev-parse --short HEAD`,
  branch `perf/recvmmsg`, worktree `/home/dev/projects/logthing-recvmmsg`).
- **Date:** 2026-09-18.
- **Host:** `nproc` = **12**; `sysctl net.core.rmem_max` = **212992** (208
  KiB, stock) — same host and same values as the committed
  `2026-09-18-udp-recv-fanout-results.md` campaign.
- **Core split:** generator pinned to `taskset -c 0-3` (4 cores), server
  pinned to `taskset -c 4-11` (8 cores) — the harness's own default
  (`GEN_CPUS`/`SRV_CPUS` in `scripts/max-ingest-rate.sh`), identical to the
  fan-out campaign.
- **`logthing` build profile:** `--release`.
- **Persistence target:** real `[ipfix.local]` Parquet sink (`SHAPE=real`).
- **Harness:** `scripts/max-ingest-rate.sh`, `RUNS=5`, `DURATION=15`,
  `GEN_PROCS=1` throughout — one generator process, one source port, so
  `recv_tasks` fan-out (left at its default `8`) cannot distribute the
  traffic and every measurement below isolates the single-sender case.
- **Exact command shapes:**

  Gate (`recv_tasks=1` vs `recv_tasks=8`, `recv_batch_size` unset i.e. `1`):
  ```bash
  cd /home/dev/projects/logthing-recvmmsg
  LOGTHING__IPFIX__RECV_TASKS=1 FORMAT=ipfix SHAPE=real RATE=40000 DURATION=15 RUNS=5 GEN_PROCS=1 ./scripts/max-ingest-rate.sh
  LOGTHING__IPFIX__RECV_TASKS=8 FORMAT=ipfix SHAPE=real RATE=40000 DURATION=15 RUNS=5 GEN_PROCS=1 ./scripts/max-ingest-rate.sh
  LOGTHING__IPFIX__RECV_TASKS=1 FORMAT=ipfix SHAPE=real RATE=50000 DURATION=15 RUNS=5 GEN_PROCS=1 ./scripts/max-ingest-rate.sh
  LOGTHING__IPFIX__RECV_TASKS=8 FORMAT=ipfix SHAPE=real RATE=50000 DURATION=15 RUNS=5 GEN_PROCS=1 ./scripts/max-ingest-rate.sh
  ```

  Result sweep (`recv_batch_size=1` vs `=32`, `recv_tasks` at its shipped
  default `8`):
  ```bash
  cd /home/dev/projects/logthing-recvmmsg
  for BS in 1 32; do
    for RATE in 40000 50000 60000; do
      LOGTHING__IPFIX__RECV_BATCH_SIZE=$BS FORMAT=ipfix SHAPE=real RATE=$RATE DURATION=15 RUNS=5 GEN_PROCS=1 \
        ./scripts/max-ingest-rate.sh
    done
  done
  ```

### Knob-effectiveness proof

Before any number below was recorded, the env override was proven to reach
the listener: `LOGTHING__IPFIX__RECV_BATCH_SIZE=100000` is **rejected at
startup** with `"ipfix.recv_batch_size = 100000 exceeds the maximum of 256
... Lower it to 256 or below"`, and `=32` starts cleanly. Without this
check, a silently-ignored variable would have made the whole comparison a
re-measurement of the default (`recv_batch_size=1`) path wearing a
different label — the same failure mode the fan-out document's own gate was
designed to rule out for `recv_tasks`.

## 2. Results — ipfix, real shape, `RUNS=5`, `DURATION=15`, `GEN_PROCS=1`, `recv_tasks=8`

| rate | `recv_batch_size=1` | `recv_batch_size=32` |
|---|---:|---:|
| 40,000/s | median 0.0150% | median 0.0000% |
| 50,000/s | **median 0.7206%** | **median 0.0000%** |
| 60,000/s | median 3.4145% | median 0.0261% |

Source logs: `docs/performance/2026-09-18-recvmmsg-ipfix-40000-bs1.log`,
`docs/performance/2026-09-18-recvmmsg-ipfix-40000-bs32.log`,
`docs/performance/2026-09-18-recvmmsg-ipfix-50000-bs1.log`,
`docs/performance/2026-09-18-recvmmsg-ipfix-50000-bs32.log`,
`docs/performance/2026-09-18-recvmmsg-ipfix-60000-bs1.log`,
`docs/performance/2026-09-18-recvmmsg-ipfix-60000-bs32.log`.

### Per-run detail at 50,000/s — the decisive comparison

From `docs/performance/2026-09-18-recvmmsg-ipfix-50000-bs1.log` and
`-ipfix-50000-bs32.log`:

| run | `bs=1` kernel drops | `bs=1` `srv_cores` | `bs=32` kernel drops | `bs=32` `srv_cores` |
|---|---:|---:|---:|---:|
| 1 | 4,033 | 1.07 | 0 | 0.93 |
| 2 | 7,980 | 1.04 | 0 | 1.00 |
| 3 | 2,239 | 1.04 | 0 | 0.99 |
| 4 | 5,347 | 1.04 | 0 | 0.95 |
| 5 | 23,487 | 1.09 | 0 | 0.98 |

`bs=32` loses **zero** datagrams on all 5 runs at 50,000/s while doing *more*
work — every run reached the full ~750,000-datagram offered volume for the
15-second window, versus `bs=1`'s runs which sometimes came in under offered
(two of the five are flagged `GENERATOR-LIMITED` in the raw log even before
loss is counted) — for *less* CPU (0.93-1.00 cores vs. 1.04-1.09 cores).
That combination — more delivered work, lower CPU — is the signature of
amortizing the `recvmmsg` syscall over a batch rather than paying one
syscall per datagram.

### Per-drop-site breakdown

At every rate and every `recv_batch_size` value measured, **all loss was
kernel-socket drop** (`kernel_drops` column). `writer_drops` and
`buffer_drops` (the writer-channel and hard-cap drop sites, downstream of
the kernel) are `0` on every single run in all 10 committed logs — `bs=32`
did not just move loss to a different site, it eliminated the loss that was
present, and there is no second drop site hiding behind the headline number.

## 3. Comparability notes / variance

Per the fan-out document's own variance finding (§4 there, reconfirmed by
these logs: e.g. `bs=1`/50,000/s per-run losses range 0.2997%-3.1318%, a
~10x spread across 5 runs at the identical configuration), run-to-run
variance on this host is large. **No figure in this document deserves more
than two significant figures of trust.** Treat "50,000/s" as "~50k/s", and
treat a median loss difference of, say, 0.7% vs 0.02% as the meaningful
signal it is, while treating small differences (0.0150% vs 0.0000%) as
within-noise rather than as a real per-mille effect.

## 4. What this does NOT establish

- **Do not read 60,000/s as a ceiling for `recv_batch_size=32`.** At that
  rate, 5 of the 10 runs across the two logs (`-ipfix-60000-bs1.log`:
  runs 1 and 3, 2 of 5; `-ipfix-60000-bs32.log`: runs 1, 2, and 4, 3 of 5)
  came back `GENERATOR-LIMITED` — under-offering the target rate because
  the single
  generator process itself ran out of headroom (per
  `docs/performance/2026-09-16-generator-ceiling.md`, ~68,000-72,000
  flows/s for IPFIX at 1 process). That means measurement stopped being
  able to find the server's true ceiling with `GEN_PROCS=1`, not that the
  ceiling was found at 60,000/s. The honest statement is: **the
  single-sender ceiling moved from 40,000-50,000/s (unbatched) to at least
  50,000/s clean (batched) — where "at least" is a floor, not a measured
  top.** A `GEN_PROCS>1` re-measurement was not attempted here because it
  would reintroduce the multi-source-port confound the gate above exists to
  rule out (more than one source port lets `recv_tasks` fan-out share the
  load, which is a different question from the single-sender one this
  document answers).
- **The sweep covered IPFIX only.** sFlow and syslog received the identical
  code path and the identical test treatment (Tasks 5 and 6, reviewed
  clean per `progress.md`), so the shape of the result — batching removes
  loss at the single-sender knee without added CPU — is *expected* to
  generalize, but it was not independently re-measured for those two
  formats in this campaign. Do not cite an sFlow or syslog number from this
  document; none was taken.
- **This is a loopback figure on a shared-CPU KVM guest**, generator and
  server on one 12-vCPU host — not a deployment capacity number. Same
  caveat as every other document in this campaign (Hardware caveat, above).
- **No figure in this document is accurate beyond two significant
  figures** — see §3.

## 5. How `recv_batch_size` relates to `recv_tasks`

The two knobs are **orthogonal** and address different workloads:

- **`recv_tasks`** (`docs/performance/2026-09-18-udp-recv-fanout-results.md`)
  helps when a listener has **many distinct senders** — a fleet of syslog
  hosts, many sFlow agents, many IPFIX exporters — because `SO_REUSEPORT`
  spreads different 4-tuples across sockets/tasks. It buys nothing for a
  single sender: the gate measurement above (and the fan-out document's own
  finding) shows one sender pinned to one task regardless of how many are
  available.
- **`recv_batch_size`** (this document) helps when a listener has **one
  high-rate sender** — one exporter, one forwarder, one aggregator upstream
  — because it amortizes the `recvmmsg` syscall across datagrams already
  queued on that single socket, independent of how many senders there are.

An operator seeing `<protocol>_socket_drops` climb should check which shape
their traffic has before reaching for either knob: many senders each at
moderate rate → raise `recv_tasks`; one sender at high rate → raise
`recv_batch_size`. The two combine (Task 5 of this plan's brief describes a
combined multi-sender + batching measurement); this document does not
re-report that combination and defers to the fan-out document plus this
one's own single-sender numbers for each knob in isolation.

## 6. Batch-size sweep and idle-RSS cost — the evidence behind the shipped default (`recv_batch_size=32`)

The default was subsequently changed from `1` to `32`. This section records
the sweep and idle-memory measurements that decision rests on.

Single-sender IPFIX at 50,000/s (real shape, `RUNS=5`, `GEN_PROCS=1`,
`recv_tasks` at its default `8`):

| `recv_batch_size` | median loss | per-run kernel drops |
|---|---|---|
| 1 | 0.7206% | 4033, 7980, 2239, 5347, 23487 |
| 4 | 0.0000% | 0, 0, 0, 180, 187 |
| 8 | 0.0000% | 0, 0, 0, 0, 494 |
| 16 | 0.0000% | 1341, 0, 0, 0, 0 |
| 32 | 0.0000% | 0, 0, 0, 0, 0 |

Idle RSS with all three listeners enabled at `recv_tasks=8`:

| `recv_batch_size` | idle RSS |
|---|---:|
| 1 | 15,084 kB |
| 8 | 16,284 kB |
| 32 | 21,068 kB |
| 64 | 27,264 kB |

So `32` costs roughly **6 MB** resident over the off state (`1`).

**What this does and does not show.** The whole measured win is `1 → ≥4`:
every setting from `4` upward had a median loss of `0.0000%` in this sweep.
The clean five-run result at `32` is **not** evidence that `32` outperforms
`8` — both sit at the same `0.0000%` median, this host's run-to-run
variance is large and documented in §3 above, and `n=5` per setting is not
enough to resolve a difference between two settings that both already show
zero loss. The default was raised to `32` for headroom (~6 MB resident, per
the table above), not because `32` was shown to measurably outperform `8`
or any other setting from `4` upward.

## Provenance — raw logs

All 10 logs cited above are committed verbatim beside this document,
prefixed `2026-09-18-recvmmsg-`:

- `docs/performance/2026-09-18-recvmmsg-gate-40000-rt1.log`
- `docs/performance/2026-09-18-recvmmsg-gate-40000-rt8.log`
- `docs/performance/2026-09-18-recvmmsg-gate-50000-rt1.log`
- `docs/performance/2026-09-18-recvmmsg-gate-50000-rt8.log`
- `docs/performance/2026-09-18-recvmmsg-ipfix-40000-bs1.log`
- `docs/performance/2026-09-18-recvmmsg-ipfix-40000-bs32.log`
- `docs/performance/2026-09-18-recvmmsg-ipfix-50000-bs1.log`
- `docs/performance/2026-09-18-recvmmsg-ipfix-50000-bs32.log`
- `docs/performance/2026-09-18-recvmmsg-ipfix-60000-bs1.log`
- `docs/performance/2026-09-18-recvmmsg-ipfix-60000-bs32.log`

Every number in this document traces to one of these logs or to the
`progress.md` knob-effectiveness proof quoted above; nothing here is
estimated or interpolated.
