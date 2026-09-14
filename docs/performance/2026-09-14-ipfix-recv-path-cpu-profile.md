# IPFIX recv-path CPU profile: what the ~54µs/datagram actually is, 2026-09-14

**Git commit this profile was captured against:** `4e3bd6902b72696402b1eb54c7a4dcb9dc7ee370`
(branch `perf/ipfix-recv-profile`, based on `121c65e` / `perf/deferred-items`).

## 0. Established facts (context, not re-derived here)

A controlled loopback run at 20,000 datagrams/s for 15s established, by counter reconciliation,
that the IPFIX UDP listener's loss is **receiver socket-buffer overflow**, not the sender, the
fabric, or decode:

| | |
|---|---:|
| generator sent | 299,977 |
| app saw (`ipfix_datagrams_received`) | 277,571 |
| loss | 22,406 |
| `RcvbufErrors` delta | 22,407 |
| `SndbufErrors` delta | 0 |

`SO_RCVBUF` was already raised (4 MiB requested, clamped to 425,984 vs 212,992 default) in that
binary; a before/after buffer-size study found no meaningful improvement. The consumer — not the
buffer, not the sender — is the constraint: that run sustained ~18.5k/s against 20k offered,
~54µs/datagram, of which `decode_datagram` is 308ns (criterion). **~99% of the per-datagram
budget is something other than parsing.** This document's job is to find out what.

Two candidates were named: **(A)** per-datagram overhead outside the decoder (syscalls, tokio
scheduling, logging, `allowed_ips`), and **(B)** recv/handler coupling — `listener.rs`'s recv
loop does `self.handler.handle_flows(flows, src).await` inline, so nothing calls `recv_from`
while that await is pending.

A prior investigation of the syslog UDP path
(`docs/performance/2026-07-25-syslog-udp-cpu-profile.md`) hit the same wall and could not
attribute ~85% of a ~94.6µs/datagram figure past regex/Arrow/allocator/futex/syscall groups. It
is read in full before this document and its dead ends (SIGPROF vs. `tracing`'s
non-async-signal-safe locks at `info` logging; the missing selftime-extraction script) are not
repeated here.

## 1. What was run

- **Build:** `cargo build --profile profiling --features pprof` (binary), `cargo build --release
  -p loadgen` (generator). Toolchain per the task's mandatory build env
  (`CC=/usr/bin/gcc CXX=/usr/bin/g++`, `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc`).
- **Script:** `scripts/profile-ipfix-udp.sh`, added this branch, adapted from
  `scripts/profile-syslog-udp.sh`'s shape (config backup/restore trap, forced `error` log level
  for the same SIGPROF/`backtrace`-vs-`tracing`-locks crash-avoidance reason, representativeness
  gate). Two differences from the syslog script, both because IPFIX's profiling needs differ:
  - `LOGTHING__IPFIX__ENABLED=true LOGTHING__SYSLOG__ENABLED=false` set explicitly (syslog's
    default ports need root and a bind failure tears the whole process down).
  - The sampler's built-in `ActivityProbe` (`src/profiling/mod.rs::ACTIVITY_METRIC`) is
    **hardcoded to `"syslog_messages_received"`**, a constant, not a parameter. With syslog
    disabled this metric never appears, so `activity_before`/`activity_after` read `None` for
    every run below, and the representativeness gate degrades to sample-count-only
    (`ProfileMetadata::activity_probe_available: false`). Per the task brief, this was **not**
    fixed by editing `src/profiling/mod.rs` (a source change to sidestep with a config-only
    approach was preferred) — instead the script independently anchors representativeness and
    loss with `ipfix_datagrams_received` (`:9090/metrics`) and `/proc/net/snmp`'s `Udp:` line,
    captured immediately before and after each load run.
- **Commands, verbatim, per run:**
  ```bash
  export PATH="$HOME/.cargo/bin:$PATH"
  RATE=20000 DURATION=25 DELAY=5 HZ=99 FORWARD=false bash scripts/profile-ipfix-udp.sh   # Run A
  RATE=20000 DURATION=25 DELAY=5 HZ=99 FORWARD=true  bash scripts/profile-ipfix-udp.sh   # Run B
  ```
  Each internally runs (excerpted):
  ```bash
  LOGTHING__IPFIX__ENABLED=true LOGTHING__SYSLOG__ENABLED=false \
  LOGTHING_PROFILE_SECS=25 LOGTHING_PROFILE_DELAY_SECS=5 LOGTHING_PROFILE_HZ=99 \
  LOGTHING_PROFILE_DIR=./profiling-results \
      ./target/profiling/logthing &
  ./target/release/loadgen ipfix-udp --host 127.0.0.1 --port 4739 \
      --target-rate 20000 --duration-secs 40
  ```
- **Self-time extraction:** `examples/pprof_selftime.rs`, added this branch. Reads `profile.pb`
  directly via the `pprof` crate's own `protos` module (`Sample.location_id[0]` is the leaf, per
  the crate's own doc comment and the pprof wire-format spec) rather than parsing
  `flamegraph.svg`'s SVG geometry the way the syslog write-up did — that write-up's own §3 flags
  its extraction script as never committed, blocking reproduction; this closes that gap directly
  instead of repeating it.
  ```bash
  cargo run --profile profiling --features pprof --example pprof_selftime -- \
      profiling-results/profile.pb
  ```
- **Two runs, one variable changed:** Run A uses the stock `[ipfix]` block (no `s3`/`local`
  destination configured), so `main.rs` wires `DefaultIpfixHandler` — the trivial
  log-a-summary-line-and-increment-a-counter handler used in the background section's 20k/s run.
  Run B adds `[ipfix.local]` writing to `/tmp/logthing-perf-local-ipfix`, wiring a real
  `ParquetWriterHandle<IpfixSink>` (buffering, Arrow mapping, a background Parquet-writer task).
  This required no source change — `IpfixLocalConfig` and the handler-selection logic in
  `main.rs:394-419` already exist — so it is exactly the "no-handler-work comparison...without
  changing production code" the brief asked for as the cleanest available test of hypothesis (B).

### Hardware caveat

QEMU/KVM guest, 12 vCPUs (`model name: QEMU Virtual CPU version 2.5+`), no `cpufreq` governor
present (`/sys/devices/system/cpu/cpu0/cpufreq` does not exist — frequency scaling/throttling
behavior is opaque from inside the guest). The load generator and the server under test share
this same host and its CPU pool; the generator's own CPU cost is not isolated from the server's
in any of the numbers below. All percentages and CPU-second figures in this document should be
read as relative/indicative for this box, not as portable absolute costs.

## 2. Representativeness

Because `ACTIVITY_METRIC` cannot see IPFIX traffic (§1), the sampler's own `representative` field
is a sample-count-only gate here, not a load-overlap proof. Independent anchoring, both runs:

| | Run A (baseline handler) | Run B (`[ipfix.local]` forwarding) |
|---|---:|---:|
| generator sent | 799,980 | 799,980 |
| achieved send rate | 19,999.3/s | 19,999.3/s |
| `ipfix_datagrams_received` delta | 756,227 | 736,884 |
| loss (sent − received) | 43,753 (5.47%) | 63,096 (7.89%) |
| `/proc/net/snmp` `RcvbufErrors` delta | 43,754 | 63,097 |
| `/proc/net/snmp` `SndbufErrors` delta | 0 | 0 |
| pprof `sample_count` | 1,250 | 4,736 |
| sampling window | 25s @ 99Hz | 25s @ 99Hz |

Both runs reproduce the established reconciliation on fresh data: loss tracks `RcvbufErrors`
almost exactly (off by 1 in both cases — noise-level), `SndbufErrors` stays at 0, and both
`ipfix_datagrams_received` deltas are large and non-zero, proving the sampling window (an inner
25s slice of each 40s load run, opening 5s after server start) overlapped substantial real
traffic. Both are treated as representative on that basis, not on the degraded built-in gate
alone.

**Run B lost 44% more datagrams than Run A at an identical offered rate** — the same handler
question the profile is about to explain.

## 3. Self-time table (leaf samples, from `profile.pb` via `pprof_selftime`)

### Run A — `DefaultIpfixHandler` (trivial: log a line, bump a counter)

Full output: `docs/performance/2026-09-14-ipfix-recv-path-cpu-profile-selftime-baseline.txt`.

| Frame | Self samples | Self % |
|---|---:|---:|
| `recvfrom` | 373 | 29.84% |
| `epoll_wait` | 182 | 14.56% |
| `clock_gettime` | 33 | 2.64% |
| `malloc` | 28 | 2.24% |
| tokio `UdpSocket::recv_from` async-io closure | 28 | 2.24% |
| `atomic_compare_exchange_weak::<u8>` | 24 | 1.92% |
| `Arc<dyn IpfixHandler>::deref` | 23 | 1.84% |
| `atomic_add::<usize,usize>` | 21 | 1.68% |
| `ipfix::decoder::parse_ipfix_data_set` | 17 | 1.36% |
| `socket_addr_from_c` | 16 | 1.28% |
| `IpfixListener::start_with_shutdown` closure | 16 | 1.28% |

Grouped:

| Group | Self % |
|---|---:|
| Syscalls (`recvfrom`, `epoll_wait`) | **44.56%** |
| Atomics (`Arc`/counter refcounting) | 7.36% |
| Allocator (`malloc`/`free`/`alloc`) | 4.16% |
| IPFIX decode (`decoder::*`) | 3.84% |
| Handler (`DefaultIpfixHandler`, `Arc<dyn IpfixHandler>` dispatch) | 2.64% |
| Futex | 0.00% |

`1,250 samples / 99Hz = 12.63 CPU-sec` over the 25s window → **~0.51 cores** average utilization
of the 12 available — this run is nowhere near CPU-saturated.

### Run B — real handler (`ParquetWriterHandle<IpfixSink>` via `[ipfix.local]`)

Full output: `docs/performance/2026-09-14-ipfix-recv-path-cpu-profile-selftime-forward.txt`.

| Frame | Self samples | Self % |
|---|---:|---:|
| `posix_memalign` | 813 | 17.17% |
| `free` | 542 | 11.44% |
| `__lll_lock_wake_private` | 408 | 8.61% |
| `malloc` | 345 | 7.28% |
| `recvfrom` | 294 | 6.21% |
| `atomic_sub::<usize,usize>` | 220 | 4.65% |
| `__lll_lock_wait_private` | 216 | 4.56% |
| `epoll_wait` | 146 | 3.08% |
| `atomic_add::<usize,usize>` | 110 | 2.32% |
| `mprotect` | 95 | 2.01% |
| `ptr::copy_nonoverlapping::<u8>` | 88 | 1.86% |

Grouped:

| Group | Self % |
|---|---:|
| Allocator (`malloc`/`free`/`posix_memalign`/`realloc`/`mprotect`) | **39.44%** |
| Futex lock wait/wake | 13.18% |
| Atomics | 9.02% |
| Syscalls (`recvfrom`, `epoll_wait`) | 9.35% |
| Arrow (`arrow_buffer`/`arrow_schema`/`arrow_data`/etc.) | 5.66% |
| IPFIX decode | 1.10% |
| Handler (`ParquetWriterHandle`, `ipfix_s3::append_flow_record`, mpsc channel) | 1.14% |

`4,736 samples / 99Hz = 47.84 CPU-sec` over the same 25s window → **~1.91 cores** average — this
run is doing roughly **3.8x** the total CPU work of Run A for a nearly identical received-datagram
count (736,884 vs 756,227).

## 4. Accounting

### 4.1 Run A alone: this is hypothesis (A)

With a handler that does almost nothing, **syscalls are the dominant self-time cost at 44.56%**
— `recvfrom` and `epoll_wait` combined, over 10x the decode cost (3.84%) and 17x the handler's
own cost (2.64%). This is a direct, top-line finding, not an inference: the two named syscalls
are themselves the two largest individual leaves in the entire profile. Total CPU use is low
(~0.51 cores of 12), so this is not a saturation story for Run A — the process spends what little
CPU it does use disproportionately inside the recv machinery itself, relative to any other named
group. This matches the background section's own caveat ("the 20k/s run above used a trivial
handler and still lost, so (B) alone cannot explain everything") and gives it a concrete number:
for that trivial-handler shape, **(A) is the better-supported explanation** of where CPU goes,
for the CPU that is spent.

### 4.2 Run A vs. Run B: this is hypothesis (B), refined

Adding a real, non-trivial handler (local Parquet persistence) while holding the offered rate
fixed:

- **Total CPU consumption nearly quadrupled** (12.63 → 47.84 CPU-sec over the same 25s window),
  for essentially the same received-datagram volume.
- **Loss rose 44% relatively** (43,753 → 63,096 datagrams, 5.47% → 7.89% of sent), independently
  confirmed via `RcvbufErrors` in both runs (§2).
- **Self-time reallocated almost entirely into allocator + futex + atomics**: from a combined
  11.5% in Run A (4.16% alloc + 7.36% atomics + 0% futex) to **61.6%** in Run B (39.44% + 13.18%
  + 9.02%). Arrow-specific frames (5.66%) appear only in Run B, confirming the persistence path
  is genuinely active during the sampled window, not just configured-but-idle.
- **The recv machinery's own *absolute* CPU-seconds shrank**, even as everything else exploded:
  `recvfrom`+`epoll_wait` cost 5.63 CPU-sec in Run A (557 samples / 99Hz) vs. 4.48 CPU-sec in
  Run B (443 samples / 99Hz) — down ~20% in absolute terms, not just relative share.

Read together, this is **not** the literal blocking mechanism the brief's hypothesis (B) describes
— `IpfixS3Handler::handle_flows` calls `self.try_send(flows)`, a non-blocking bounded-channel
send (`src/forwarding/ipfix_s3.rs:327-336`), so the `.await` in `listener.rs`'s recv loop resolves
near-instantly regardless of handler; nothing here shows the recv task sitting idle mid-await
waiting on downstream I/O. **What the data does show is a resource-contention variant of the same
coupling**: the handler's downstream batching/Arrow-encode/writer-lock work runs on the same
tokio worker-thread pool and against the same global allocator as the recv loop, and its CPU/lock
demand measurably squeezes the CPU time actually delivered to `recvfrom`/`epoll_wait` — which
correlates exactly with the higher loss observed. The recv loop is not blocked by one pending
await; it is starved for scheduler turns and CPU cycles by everything else the process is now
doing per datagram.

### 4.3 What this does and does not prove

**Proven:** (1) with a trivial handler, syscalls dominate named self-time by a wide margin over
decode or handler cost (§4.1); (2) adding a real handler measurably increases total CPU demand
(~3.8x) and datagram loss (~44% relative) at a fixed offered rate, with the CPU increase
concentrated in allocator/futex/atomics rather than in the handler's own named functions (§4.2).

**Not proven:** that the allocator/futex 61.6% in Run B is *entirely* attributable to the
persistence path by call-graph — leaf samples name allocator/lock entry points, not call sites,
the same limitation the syslog write-up's §4.1 already establishes. The inference that this
group is persistence-path cost rests on its absence in Run A and presence only once `[ipfix.local]`
is configured, which is strong correlational evidence but not a call-graph proof; no inclusive-time
per-call-site analysis was run here. Also not proven: that the literal "recv frozen mid-await"
mechanism described in the brief's hypothesis (B) text ever occurs in this codebase — every
shipped `IpfixHandler` implementation (`DefaultIpfixHandler`, the S3/local `ParquetWriterHandle`
via `try_send`) returns from `handle_flows` quickly, so that specific failure mode was not
observed. A handler that genuinely awaited a slow operation inline (a blocking S3 PUT with no
buffering, for example) was not tested and would be expected to reproduce the literal mechanism
more directly; this investigation did not construct one.

## 4.4 The single most actionable number in this document

Run A dropped **5.47% of offered datagrams while using 0.51 of 12 available
cores** — about 4% of the machine. Eleven and a half cores sat idle while the
kernel discarded datagrams for want of a consumer.

**That rules out CPU capacity as the constraint and leaves concurrency.** One
`recv_from` loop, on one task, serialises every datagram: allowed-IPs check,
decode, handler dispatch. It sustained ~18.9k datagrams/s. Adding CPU cannot
help a workload that is not using the CPU it already has; only adding
*receivers* can.

This reframes both hypotheses. (A) is why a single receiver tops out where it
does — `recvfrom` + `epoll_wait` are 44.56% of its self-time, so most of the
serial budget is syscall, not logthing code. (B) is why a real handler makes
it worse — it competes for the same worker threads and the global allocator,
not because it blocks recv.

The obvious lever, untested here and therefore **a hypothesis, not a
recommendation**: multiple receive tasks on `SO_REUSEPORT` sockets, or
decoupling `recv_from` from decode-and-dispatch so the receive loop does
nothing but drain into a queue. Either converts idle cores into receive
capacity. Both are real design changes and neither should be adopted on the
strength of one profile — see §6.

## 5. Verdict

**Both hypotheses are supported, but for different handler shapes, and (B) is refined rather than
confirmed as literally described:**

- With the **trivial handler** (closest to "pure recv path"), **(A) — per-datagram overhead
  outside the decoder, specifically syscall cost** — is the best-supported explanation of the CPU
  that is spent: `recvfrom`+`epoll_wait` alone are 44.56% of self-time, versus 3.84% for decode.
- With a **real handler**, **(B) — recv/handler coupling** — is well supported, but the mechanism
  observed is CPU/lock contention across shared worker threads and the global allocator, not the
  literal "handler await blocks recv_from" story in the brief. No handler in this codebase
  currently awaits slowly inline; all use non-blocking sends. The coupling is real and it
  correlates with a 44% relative increase in loss, but it manifests as resource starvation, not
  as the recv task being idle mid-await.
- This is **not** an "unattributed frames" result the way the syslog investigation was — named
  groups account for the large majority of self-time in both runs here (~62% in Run A, ~79% in
  Run B), a materially cleaner attribution than that prior investigation achieved. That said, the
  allocator/futex bucket's specific call sites within Run B are inferred by correlation, not
  proven by call-graph, per §4.3.

## 6. What would settle the open parts

- **Call-site attribution for Run B's allocator/futex 61.6%** — inclusive-time call-graph analysis
  per allocation site, or an allocator-tracing tool (`heaptrack`), to confirm it is the
  Parquet/Arrow batching path specifically rather than some other concurrent cost.
- **A handler that genuinely blocks inline** (a real, unbuffered synchronous S3 PUT per batch, no
  channel) would directly test the literal blocking-coupling mechanism the brief describes, which
  this investigation's two runs did not exercise — every handler shipped here is non-blocking.
- **Repeat runs.** Both Run A and Run B here are single captures, no repeats — the same limitation
  the syslog write-up flagged for its own single run. Run-to-run sample-count variance was not
  quantified for IPFIX.
- **Window-alignment.** `ipfix_datagrams_received`/`/proc/net/snmp` were read immediately before
  server-up and ~5s after the 40s load run ended — a wider window than the profiler's own inner
  25s (opening at `t≈5s`, per `LOGTHING_PROFILE_DELAY_SECS=5`). The reconciliation in §2 uses the
  full-run counts as-is (not scaled to the 25s window) since loss/representativeness only need
  "substantial and non-zero," but a per-received-datagram CPU-seconds figure was deliberately not
  computed to a false precision here — assuming uniform rate across the wider window and dividing
  would repeat the same normalization ambiguity §4.4 of the syslog write-up spent a full
  subsection cautioning against.
- **Fixing `ACTIVITY_METRIC`** (`src/profiling/mod.rs`) to accept a configurable metric name
  rather than the hardcoded `"syslog_messages_received"` would let the sampler's own
  representativeness gate work for non-syslog protocols directly, instead of requiring the
  external anchoring this script does. Left as a follow-up, not made here, per the brief's
  instruction to skip a source change and note it rather than modify the listener/sampler.
