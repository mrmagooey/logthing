# Assessment: "Principles for Fast Tokio Applications" against logthing

**Source:** https://dial9-rs.github.io/blog/principles-for-fast-tokio-applications/ (fetched 2026-09-14).
**Base commit for this assessment:** `75a0413` (branch `perf/deferred-items`).

## What the blog is

A vendor (dial9) post whose central thesis is "it depends" — Tokio performance work is a
balance of fairness vs. batching and contention vs. isolation, and the right move is
determined by working backward from your own metrics (`schedule_latency_histogram`, flamegraphs,
P50/P99 ratios), not by pattern-matching to a checklist. It states seven core principles, three
"advanced exceptions," and a handful of detection heuristics. It is written for a generic
Tokio server (the running example is a Redis-like protocol server), not for a UDP-ingest/ETL
pipeline like logthing.

## Method

Every principle below is checked against code actually in this repo (cited by file/line) and
against the two committed measurement docs (`docs/performance/2026-09-14-ipfix-recv-path-cpu-profile.md`,
`docs/performance/2026-09-13-multiformat-load-results.md`) plus the existing plan
(`docs/superpowers/plans/2026-09-14-throughput-improvements.md`). No bucket below rests on the
blog's say-so alone.

## Bucket table

| # | Blog principle | Bucket | Evidence |
|---|---|---|---|
| 1 | Measure first, don't assume a problem exists | **1 — already done** | This is the discipline the two performance docs *are*: `multiformat-load-results.md` §1 carries a dated, in-place correction retracting its own "undersized rmem" claim after §7's before/after measurement showed no effect; §8 re-derives the loss site from counter reconciliation instead of guessing. The throughput plan's own acceptance bar (N≥5 runs, non-overlapping min/max ranges, "inconclusive" as a legitimate reported outcome — `docs/superpowers/plans/2026-09-14-throughput-improvements.md` lines 38-45) is this principle encoded as process. |
| 2 | Yield frequently for per-connection fairness (pipelined reads starve siblings) | **3 — violated, not shown to be the constraint** | `src/zeek/listener.rs:205` `handle_tcp_connection` wraps the socket in a `BufReader` and loops `read_until(b'\n', ...)` with no `yield_now` between lines; `src/suricata/listener.rs` has the structurally identical loop. A `BufReader` serving several already-buffered lines from one underlying read does not necessarily re-poll the socket, which is exactly the anti-pattern the blog's mini-redis example targets. But: no P50/P99 latency measurement exists for either TCP listener, and the *established* loss finding is UDP-side (kernel `RcvbufErrors`, 5-14% loss) while both TCP protocols show **0% loss** in the one load test that measured them (`multiformat-load-results.md` §1: Zeek 99,995/99,995 reached the app). There is no number implicating TCP fairness as a current problem. |
| 3 | Batch blocking work; use the largest sensible `spawn_blocking` segment | **1 — already done** | `src/forwarding/buffered_writer.rs:1469-1483`: the Parquet encode (`concat_batches` + `ArrowWriter` + zstd-3) runs as *one* `spawn_blocking` call per flushed batch, not per-record. `src/server/mod.rs:796`: Kerberos GSSAPI accept (keytab I/O + crypto) is a single `spawn_blocking(move || accept_kerberos_token(...))` call per request, with an explicit comment ("GSSAPI work is blocking... never run it inline on the async runtime"). Per-record Arrow row-mapping (`append_flow_record`, `src/forwarding/ipfix_s3.rs:302-313`) stays off `spawn_blocking` entirely and runs on the writer task inline — consistent with "batch the truly-blocking segment, don't spawn_blocking every small piece." |
| 4 | Beware the global blocking-pool queue at high `spawn_blocking` rates | **4 — not applicable** | The blog's own trigger number is ~50,000 blocking tasks/sec on a 32-core host. `spawn_blocking` in this codebase fires once per flush (batch/interval granularity — every few seconds per partition, per item 3 above), not per-record and nowhere near per-datagram. The mechanism this principle warns about (blocking-pool queue depth) does not have a plausible path to matter here. |
| 5 | Minimize mutex contention: short critical sections, no `RwLock` on hot read paths, never hold a lock across I/O/await | **1 — already done** | `src/forwarding/aggregate/mod.rs:145-236`: `Aggregator::consume` builds the group key and numeric observations *before* taking `self.state.lock()` (line 216), destructures the guard into disjoint `&mut` fields to keep the critical section to a hashmap `entry()` + counter bump, and carries its own `ponytail:` comment (lines 149-155) naming the upgrade path (shard by rule) if a profile ever shows the lock mattering — i.e. the codebase already reasons about this exactly the way the blog recommends. Every `RwLock` in the tree (`src/main.rs:78`, `src/admin/*.rs`) guards HTTP-admin config/CSRF state, never a per-record ingest path. No lock is held across an `.await` anywhere in the recv/decode/dispatch or writer hot paths (`grep` confirms the only `Mutex`/`RwLock` near `src/ipfix/listener.rs` and `src/sflow/listener.rs` are `#[cfg(test)]` fixtures). |
| 6 | Constrain parallelism to match system capacity (`Semaphore`) | **1 — already done** | `src/zeek/listener.rs:15,110,123` and `src/suricata/listener.rs` (identical shape): `Semaphore::new(MAX_ZEEK_TCP_CONNECTIONS)` / `MAX_SURICATA_TCP_CONNECTIONS = 1024`, acquired via `try_acquire_owned()` before spawning a per-connection task, with a rejection counter (`zeek_tcp_connections_rejected`) on saturation. `src/forwarding/buffered_writer.rs`'s `encode_and_upload` acquires a flush `Semaphore` (line ~1462) before spawning concurrent S3 upload work, deliberately *inside* the spawned function rather than the caller's `select!` loop (comment explains this is load-bearing — acquiring in the caller would reintroduce the exact recv-blocking bug this plan is about). |
| 7 | Isolate Tokio workers from other OS threads/processes (cgroups, core pinning) | **3 — violated, not shown to be the constraint** | Nothing in this repo pins workers to cores or uses cgroups; `tracing_subscriber::fmt()` (`src/main.rs:52-58`) writes synchronously with no `tracing_appender`/non-blocking layer, so log I/O runs inline on whatever thread emits it (a related, if not identical, hazard to the blog's own tracing-appender example of a background thread delaying worker unpark). But the profiling evidence rules this out as *the* constraint for the measured problem: Run A used 0.51 of 12 cores while losing 5.47% of datagrams (`ipfix-recv-path-cpu-profile.md` §4.4) — eleven idle cores, not scheduler-starved workers, are sitting there. The hardware caveat in both perf docs (QEMU/KVM, no `cpufreq` interface) also means core-pinning claims couldn't be verified on this box even if attempted. |
| 8 | Long blocking polls are OK under light load, but never inside `select!`/`join!` branches (causes spurious timeouts on sibling futures) | **1 — already done** | Every `select!` in the UDP listeners (`src/ipfix/listener.rs:109-147`, `src/sflow/listener.rs:100`, `src/syslog/listener.rs:224,270`, `src/suricata/listener.rs:113`, `src/zeek/listener.rs:113`) races only `socket.recv_from(...)` against `shutdown_rx.changed()` — both are cancel-safe per tokio's own docs, and neither is a long CPU-bound poll. The decode-and-dispatch work (including the `.await` on `handler.handle_flows`) runs *after* the branch is chosen, as ordinary sequential code, not as one of the raced futures — so it cannot cause a sibling branch (the shutdown check) to miss a poll mid-race. It does delay the *next* iteration's shutdown check by however long the handler takes (this is the separate, already-measured concurrency/starvation finding — see item 9), which is a throughput/latency property, not the "unexpected timeout of a sibling in the same select!" correctness hazard the blog is warning about. |
| 9 | Use multiple runtimes to isolate latency-sensitive work from background/batch work | **2 → already planned, see shortlist** | `src/main.rs:28-30` builds exactly one multi-threaded runtime for everything: UDP recv tasks, TCP accept/connection tasks, the writer/flush tasks, and the axum HTTP server all share one worker pool. Run B (`ipfix-recv-path-cpu-profile.md` §4.2) shows this costing real throughput: adding a real handler doesn't block the recv task literally, but its allocator/futex/atomic demand (61.6% of self-time) measurably starves `recvfrom`/`epoll_wait` of scheduler turns and CPU on the *same* shared workers, correlating with a 44% relative rise in loss. This is precisely the scenario the blog's "move background work to its own runtime" principle targets. See shortlist below — it is not new, it is `docs/superpowers/plans/2026-09-14-throughput-improvements.md` Tier 5. |
| 10 | Spin instead of yield for microsecond-scale latency, at the cost of a core | **4 — not applicable** | Nothing in logthing's workload (UDP flow ingest, batch Parquet writes, HTTP admin/WEF/HEC/OTLP) has a stated microsecond latency target. The blog itself calls this "probably wrong for most applications." |
| — | (General) amortize per-record overhead on a shared hot path | **1 — already done** (not a numbered blog principle, but the same underlying idea as #3) | `src/forwarding/drop_log.rs:1-19`'s own header cites a real number: per-drop `tracing` logging on the syslog UDP recv path measured at **~21% of ingest throughput at 50,000/s**, because it ran on the single-task hot path. It is already fixed — throttled to one log line per 30s per `(site, kind)`, with the authoritative count moved to a bare `metrics::counter!` increment (`parquet_s3_dropped{source,target}`), and the throughput plan explicitly re-states this as a constraint new work must not reintroduce (Global Constraints, line 19: "No log line on the new hot-path drop counter"). |

## Bucket-2 shortlist (violated, and our own measurements support fixing it)

Two things land here. **Neither is new** — both are already ranked and gated in
`docs/superpowers/plans/2026-09-14-throughput-improvements.md`.

1. **Global allocator contention under a real handler** (blog principle: "beware global
   resources," generalized from the blocking-pool queue to the global `malloc`/glibc arena —
   the blog's literal example is a different global resource, but the mechanism, contention on
   something shared across all workers, is the same shape).
   - Evidence: Run B, allocator+futex+atomics = 61.6% of self-time (39.44% + 13.18% + 9.02%),
     vs. 11.5% in Run A with a trivial handler; loss rose 5.47% → 7.89% at the same offered rate
     (`ipfix-recv-path-cpu-profile.md` §3, §4.2).
   - Plan status: **already planned**, Tier 2 (`perf/global-allocator-spike`, mimalloc swap,
     framed explicitly as a cheap-to-falsify spike, not a guaranteed merge) — throughput plan
     lines 262-277. Nothing here changes its ranking or urgency.

2. **Single shared runtime for recv and writer/handler work** (blog principle: multiple
   runtimes for priority isolation).
   - Evidence: same Run B data as above — the mechanism is CPU/scheduler contention across a
     single shared worker pool, not literal blocking.
   - Plan status: **already planned**, Tier 5 (`perf/dedicated-recv-thread-spike`) — explicitly
     gated to run *only if* Tier 1 (recv/decode decouple) turns out insufficient specifically
     under a real handler (throughput plan lines 326-337). The plan's own reasoning for that gate
     — try the cheaper fix (Tier 1) first, only reach for a second runtime if contention survives
     it — matches the blog's own "it depends, work backward from measurement" framing exactly.

**Net result of the bucket-2 check: nothing new.** The blog independently corroborates two
items the plan already carries (Tier 2, Tier 5) and assigns them no higher urgency than the plan
already does. It does not surface a third bucket-2 item.

## Principles we are deliberately not acting on

- **Per-connection `read_until` fairness on TCP listeners (blog principle 2).** Bucket 3: the
  code pattern matches the blog's warned anti-pattern (`src/zeek/listener.rs:205`,
  `src/suricata/listener.rs`'s equivalent), but TCP already loses 0% of offered load
  (`multiformat-load-results.md` §1) and no P50/P99 latency measurement exists to show a
  fairness problem across concurrent Zeek/Suricata connections. Adding `yield_now()` calls to a
  path with no measured symptom would be exactly the "acted on a plausible-sounding claim with
  no number from this codebase" failure mode this task was set up to avoid. Revisit only if a
  future load test measures per-connection latency and shows a P99 outlier under multi-connection
  pipelined load.
- **Core-pinning / cgroups isolation of Tokio workers (blog principle 7).** Bucket 3: not done,
  and the environment this repo is actually measured on (QEMU/KVM guest, no `cpufreq` interface,
  generator and server sharing 12 vCPUs — stated explicitly in both perf docs' hardware caveats)
  cannot validate a pinning claim even if one were implemented; more importantly, the measured
  bottleneck (0.51/12 cores used while losing 5.47%) is concurrency, not OS-scheduler contention
  for the cores that exist. Revisit only on real deployment hardware, and only if idle-core
  measurements there stop looking like Run A's.
- **Synchronous `tracing_subscriber::fmt()` without a non-blocking appender (adjacent to blog
  principle 7's tracing_appender example).** Bucket 3: real gap, no measurement isolates it as a
  current cost separate from the already-fixed and already-measured per-drop-log problem
  (`drop_log.rs`). Not touching it without a number.
- **`spin` instead of `yield` (blog principle 10).** Bucket 4: no microsecond-latency requirement
  exists anywhere in this codebase's workload.
- **Global blocking-pool queue depth (blog principle 4, literal reading).** Bucket 4: `spawn_blocking`
  call rate here is flush-interval-granularity, orders of magnitude below the blog's own
  50,000/s-on-32-cores trigger condition.

## Bottom line

Of the ten numbered principles plus one generalized one, six are already satisfied by existing
code (measure-first discipline, batched `spawn_blocking`, minimal-critical-section mutex use with
a documented upgrade path, `Semaphore`-bounded parallelism, cancel-safe `select!` usage, and
amortized hot-path logging). Two are structurally violated but have no supporting measurement and
are correctly left alone for now (TCP read fairness, worker/OS isolation). One is not applicable
to this workload (spin-polling) and one more is not applicable at the scale this codebase
operates `spawn_blocking` (global blocking-pool queue).

The two principles that *are* both violated and measurement-backed — global allocator
contention and single-runtime resource sharing — are not new findings. They restate, with a
different vocabulary, exactly Tier 2 and Tier 5 of `docs/superpowers/plans/2026-09-14-throughput-improvements.md`,
already ranked below Tier 1 and already gated the way the plan's own authors gated them. **This
blog post contains nothing actionable beyond what this repo has already measured and planned.**
That is a legitimate result: it means the existing throughput plan is well-grounded against an
independent, generically-written source, not that the exercise found nothing.
