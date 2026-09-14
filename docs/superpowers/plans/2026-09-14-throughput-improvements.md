# Throughput Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Reduce IPFIX/sFlow/syslog UDP ingest loss by relieving the proven constraint — a single recv task whose `recv_from` calls are serialized with decode-and-dispatch on one OS-schedulable unit, while 11.5 of 12 cores sit idle — without adding a config knob, thread pool, or trait for a marginal gain. Every tier's payoff is *measured*, not asserted.

**Architecture:** Six tiers. Tier 0 builds the repeatable measurement harness every later tier is judged against (the existing evidence is single-run; a real go/no-go call needs a distribution, not one number). Tier 1 is the one change this plan is confident about: decouple `recv_from` from decode+dispatch on the IPFIX listener via a bounded channel, single consumer, no new threads. Tier 2 is a cheap, independent spike — swap the global allocator — aimed at Run B's 61.6% allocator/futex/atomics group. Tier 3 repeats Tier 1's pattern on sFlow and syslog UDP, each with its own before/after measurement rather than assumed-safe copy-paste. Tier 4 and Tier 5 are explicitly speculative: SO_REUSEPORT fan-out and a dedicated recv thread, both gated on a spike proving they're needed before any production code is written. Tiers are ordered by (confidence × expected benefit) / risk, highest first.

## Global Constraints

- **Build environment — mandatory.** `export PATH="$HOME/.cargo/bin:$PATH"; export CC=/usr/bin/gcc CXX=/usr/bin/g++; export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc`. Run every command in the foreground; never background a build or a load run.
- **Never work on `master`.** One branch per tier: `perf/recv-decode-decouple-ipfix` (Tier 1), `perf/global-allocator-spike` (Tier 2), `perf/recv-decode-decouple-sflow`, `perf/recv-decode-decouple-syslog-udp` (Tier 3, independent branches), `perf/reuseport-spike` (Tier 4), `perf/dedicated-recv-thread-spike` (Tier 5).
- **Commit before mutation-testing.** Reverting a mutation with `git checkout` destroys uncommitted work; use a file copy or commit first.
- **Stage explicit paths, never `git add -A <dir>`.**
- **A new bench target needs its `[[bench]]` entry and file in the same commit.**
- **Pre-push runs fmt → clippy `-D warnings` → test → `bench --no-run`.** Run it manually, then push `--no-verify` (avoid paying for it twice), foreground only — a detached push dies with a silent SIGPIPE.
- **Every existing metric keeps its exact name, labels, and increment site's meaning**: `ipfix_datagrams_received`, `sflow_datagrams_received`, `syslog_messages_received`, `ipfix_decode_errors`, `sflow_decode_errors`, `syslog_parse_errors`, `listener_source_rejected{protocol=...}`, `ipfix_templates_missing`, `parquet_s3_dropped{source,target}`. This repo has silently killed a counter in a refactor twice before (zeek, suricata) — every task below states explicitly which counters it touches and includes a test that fails if the counter's meaning drifts.
- **New behavior needs unit + integration + e2e coverage**, per house policy. Where a "true" e2e would just be a perf/load run (inherently non-deterministic, not CI material), that is called out explicitly and a separate CI-safe e2e *correctness* test (metric surfaces via the real `/metrics` endpoint) is specified instead — these are not the same thing and neither substitutes for the other.
- **No log line on the new hot-path drop counter.** `src/forwarding/drop_log.rs`'s own header measures a *different* per-drop log call costing ~21% of ingest throughput at 50,000/s specifically because it runs on the single-task UDP receive path. Any new drop counter this plan adds to a recv-adjacent task increments a bare `metrics::counter!` only, never a per-drop `tracing` call — the mechanism this plan exists to fix is exactly "hot recv-path work compounds," and a log line is that mistake with different packaging.

## Findings that drive this plan — established, not re-derived here

Full detail in `docs/performance/2026-09-14-ipfix-recv-path-cpu-profile.md` and `docs/performance/2026-09-13-multiformat-load-results.md` §7-§8; read those in full before touching any task below.

1. **Loss site, proven by counter reconciliation (three runs):** `RcvbufErrors` delta from `/proc/net/snmp` ≈ observed loss; `SndbufErrors` = 0 every time. It is the receiver's kernel socket buffer, always.
2. **Not the buffer size.** `SO_RCVBUF` raised 212992 → 425984 (`t2/so-rcvbuf`, already merged). No improvement at 5,000/s; a non-conclusive ~4pp at 20,000/s whose two runs' ranges overlapped the "before" ranges. Do not raise it further or touch `rmem_max`.
3. **Not decode.** IPFIX `decode_datagram` is 308 ns/datagram (3.84% of Run A's self-time); sFlow ~220 ns. Binary decode is 42-50x cheaper than encode (criterion baseline). No decoder optimisation is in scope.
4. **The constraint is concurrency, not CPU.** Run A (trivial handler, 20,000/s offered): 5.47% loss while the process used **0.51 of 12 cores**. Self-time: syscalls (`recvfrom`+`epoll_wait`) 44.56%, decode 3.84%, handler 2.64%. A single task doing `recv_from().await` → decode → `handler.handle_flows().await` inline serializes all three on one schedulable unit; while decode+dispatch run, nothing is calling `recv_from`, and UDP has no backpressure to fall back on (contrast: zeek-over-TCP loses nothing at the same offered rate).
5. **Run B (real `[ipfix.local]` Parquet handler, same offered rate) refines but does not overturn this:** loss rose 44% relative (5.47% → 7.89%) while total CPU nearly quadrupled (12.63 → 47.84 CPU-sec) for an almost-identical received count. Self-time reallocated into allocator (39.44%) + futex (13.18%) + atomics (9.02%) = **61.6%**, and `recvfrom`+`epoll_wait`'s *absolute* CPU-seconds fell ~20% even as everything else exploded. Every shipped handler uses non-blocking `try_send` (`src/forwarding/ipfix_s3.rs:329`), so the literal "handler await freezes recv" story is **not** what happens — what happens is the recv task getting fewer scheduler turns and less CPU because the same shared tokio worker pool and global allocator are now also doing Arrow/Parquet work per datagram.
6. **A second, distinct drop site exists downstream:** `parquet_s3_dropped` (writer channel, post-decode) was non-zero (2,392 of 86,515 decoded, 2.8%) in the same run that also lost 13,473 in the kernel (`docs/performance/2026-09-13-multiformat-load-results.md` §1). Any change here must report both counters separately — collapsing them hides which fix applies, and enlarging one buffer while the other is the real constraint reproduces the exact "buffer size wasn't the cause" mistake finding #2 already made once.
7. **Both runs above are single captures on a QEMU/KVM guest sharing 12 vCPUs with the generator.** A documented 3.2-percentage-point spread was already observed at identical offered load in a different session. One profile is thin evidence for a design change — hence Tier 0.
8. **A structurally identical single-recv-task shape exists on `src/sflow/listener.rs` and the UDP arm of `src/syslog/listener.rs`.** Neither has been profiled the way IPFIX has. sFlow's decoder is stateless (no template cache — see `src/sflow/decoder.rs:51`, no analogue of `IpfixDecoder`), so it carries none of IPFIX's cross-worker cache-coherency risk (relevant to Tier 4). Syslog UDP's own prior CPU profile (`docs/performance/2026-07-25-syslog-udp-cpu-profile.md`) could not attribute ~85% of its ~94.6µs/datagram figure, consistent with the same syscall-dominated shape but not proof of it.

## Success criteria — quantitative, and honest about what this environment can't show

**Environment caveat, carried forward, do not lose it:** this is a QEMU/KVM guest, 12 vCPUs, no `cpufreq` interface, generator and server sharing the same core pool. This setup cannot establish an absolute maximum sustainable rate — for TCP sources the generator saturates before the server does, and for UDP the kernel queue saturates before any CPU ceiling is found. Nothing in this plan produces a capacity number. Every acceptance measurement below is a **relative improvement at a fixed, reproduced offered rate**, using repeated runs to clear the documented noise floor.

**Primary acceptance measurement (Tier 1, and reused by Tier 3):**

- Reproduction: `docs/performance/2026-09-14-ipfix-recv-path-cpu-profile.md` §8's loopback method — `LOGTHING__IPFIX__ENABLED=true LOGTHING__SYSLOG__ENABLED=false`, `loadgen ipfix-udp --target-rate 20000 --duration-secs 15`, loss computed both via `ipfix_datagrams_received` delta and independently via `/proc/net/snmp`'s `RcvbufErrors` delta (must reconcile to within 1, exactly as every prior run has).
- **N ≥ 5 runs per commit** (before: current tip; after: the tier's branch), same host, same session, back-to-back. Report median and [min, max] loss%, not a single number — the existing SO_RCVBUF study's own 20,000/s result (13.37%-19.96% "after" vs. 19.40%-22.28% "before") is the cautionary example of what an inconclusive result looks like: ranges that overlap.
- **Pass:** median loss with the change is at least 50% lower, relative, than median loss without, AND the two five-run ranges do not overlap (the after-tier's worst run beats the before-tier's best run). A result that merely nudges the median while the ranges overlap is reported as **inconclusive**, exactly as the SO_RCVBUF 20,000/s result was — not rounded up to a win.
- **Guard, not just a target:** `parquet_s3_dropped` (writer-channel drops) must not increase by more than 10% relative across the same runs. A fix that reduces kernel loss by pushing the same records into a writer-channel drop has not fixed anything; report that outcome plainly if it occurs.
- Repeat once at 5,000/s as a lower-rate sanity check — finding #7's own session found the buffer-doubling result was noise-dominated at 5,000/s; this plan's fix should be judged mainly at 20,000/s, where finding #2's own author noted the queue is "under more sustained pressure."
- **Zero regression on every metric in the Global Constraints list**, proven by the tests each task specifies, not by the load run.

**Tier 4/5 spikes (if run at all) are measured the same way**, but their acceptance bar is different: they exist to answer "is a bigger change than Tier 1 justified," not to ship. See each tier's own pass/fail language.

---

## Ranked proposals (summary)

| Rank | Proposal | Site addressed | Mechanism | Confidence | Tier |
|---|---|---|---|---|---|
| 1 | Decouple `recv_from` from decode+dispatch (bounded channel, single consumer) | Kernel `RcvbufErrors` | Recv task no longer blocked behind decode/handler; `recv_from` calls run back-to-back | High — directly targets finding #4 | 1 |
| 2 | Swap the global allocator (e.g. `mimalloc`) | Kernel `RcvbufErrors` under a real handler (Run B) | Reduces the 61.6% allocator/futex/atomics group competing with the recv task for CPU and locks | Medium — correlational evidence (finding #5), one-line diff, cheap to falsify | 2 |
| 3 | Repeat Tier 1's pattern on sFlow UDP and syslog UDP | Same, other protocols | Same mechanism, unmeasured protocols | Medium — structural analogy (finding #8), not yet profiled | 3 |
| 4 | `SO_REUSEPORT` multi-socket fan-out | Kernel `RcvbufErrors`, larger magnitude | True multi-core parallel recv+decode+dispatch, not just two pipeline stages | Speculative — real correctness risk for IPFIX's per-worker template cache; needs a feasibility spike first | 4 |
| 5 | Dedicated OS thread/runtime for recv, isolated from the handler-pool's allocator/futex contention | Kernel `RcvbufErrors` under Run-B-style handlers specifically | Removes recv from contention with writer-path CPU/lock demand | Speculative — only pursue if Tier 1 doesn't already relieve Run B's starvation pattern | 5 |
| — | `recvmmsg` batching | Kernel `RcvbufErrors` | Amortize syscall count | **Rejected**, see below | — |
| — | Raise `SO_RCVBUF` / `rmem_max` further | Kernel `RcvbufErrors` | Bigger queue | **Rejected** — already disproven, finding #2 | — |
| — | Decoder optimisation | n/a | Faster parse | **Rejected** — already disproven, finding #3 | — |
| — | Enlarge the writer channel (`channel_capacity`) | `parquet_s3_dropped` | Bigger queue | **Rejected** — same reasoning as `SO_RCVBUF`: a buffer only delays overflow behind a consumer that's still too slow; enlarging it without first knowing whether the writer is CPU/lock-bound (Tier 2's question) repeats the diagnosed mistake | — |

**Why `recvmmsg` is rejected outright rather than deferred:** Run A shows the process using 0.51 of 12 cores while losing 5.47%. Syscalls are 44.56% of that small amount of self-time — eliminating them entirely frees at most ~0.23 of an already-idle core. The profile does not support "not enough syscall throughput" as the constraint; it supports "not enough concurrency." `recvmmsg` also has no safe tokio-native path — it needs a raw fd, `libc::recvmmsg` or a new dependency, and bypasses tokio's readiness-based polling model entirely, trading a moderate amount of unsafe/FFI surface for a mechanism the evidence doesn't point at. If Tier 1 and Tier 4 are both implemented and the constraint is *still* syscall count specifically (which nothing so far suggests), revisit with fresh profiling then — do not build it speculatively now.

---

## Tier 0 — Repeatable measurement harness

Branch: none (infra used by every later tier; land it on `master` via its own small PR before Tier 1 starts, or as Tier 1's first commit if a separate PR is overhead the maintainer doesn't want).

### Task 0.1: Script the N-repeat loopback reproduction and commit its baseline

**Files:** `scripts/repeat-ipfix-loopback-loss.sh` (create), `docs/performance/2026-09-14-throughput-baseline-repeats.md` (create)

**Why this exists:** every number in the Findings section above is a single run (or, at best, two). The plan's own success criterion needs a median and a range to compare against, and re-deriving that by hand for every tier invites exactly the kind of "one run looked better" false positive the existing SO_RCVBUF write-up was careful to avoid. This script is the smallest thing that closes that gap: it is finding #8's own script (`scripts/profile-ipfix-udp.sh`'s non-profiling cousin) run N times with results tabulated, not a new measurement technique.

- [ ] **Step 1:** Write `scripts/repeat-ipfix-loopback-loss.sh`, parameterized on `RATE` (default 20000), `DURATION` (default 15), `RUNS` (default 5). Each run: start `./target/release/logthing` with `LOGTHING__IPFIX__ENABLED=true LOGTHING__SYSLOG__ENABLED=false`, snapshot `/proc/net/snmp`'s `Udp:` line and `ipfix_datagrams_received`, run `loadgen ipfix-udp --host 127.0.0.1 --port 4739 --target-rate "$RATE" --duration-secs "$DURATION"`, snapshot again, kill the server, compute loss two ways (`sent - received` and `RcvbufErrors` delta), assert they reconcile within 1 (fail loudly if not — that would mean the harness itself is broken, not the code under test).
- [ ] **Step 2:** Output one line per run plus a final median/min/max summary, machine-parseable (e.g. tab-separated) so later tiers can diff two runs' output files rather than eyeballing prose.
- [ ] **Step 3:** Run it against current `master` tip (or this plan's base commit) at `RATE=20000 RUNS=5` and `RATE=5000 RUNS=5`. Commit the raw output alongside a short `docs/performance/2026-09-14-throughput-baseline-repeats.md` stating the commit SHA, the two summaries, and the caveat from finding #7 verbatim (host, shared vCPUs, no capacity claim).
- [ ] **Step 4:** Commit.

No unit/integration/e2e split applies here — this is a measurement script, not shipped behavior; its own internal reconciliation assertion (Step 1) is its test, matching the pattern `scripts/profile-ipfix-udp.sh` already established.

---

## Tier 1 — Decouple IPFIX recv from decode+dispatch

Branch: `perf/recv-decode-decouple-ipfix`.

This is the plan's highest-confidence proposal: it is the smallest change that removes the literal serialization finding #4 identifies, adds no new dependency, no config knob, and no thread beyond what tokio's existing multi-threaded runtime already schedules.

### Task 1.1: Split the IPFIX recv loop into a recv-only producer and a decode+dispatch consumer

**Files:** `src/ipfix/listener.rs` (modify both `run_with_socket` and `start_with_shutdown`; `start()` is unaffected since it only binds and calls `run_with_socket`)

**Design:**

```rust
/// One received-but-not-yet-decoded datagram. Owns only the bytes actually
/// received (`len`), not the full 65535-byte scratch buffer.
struct RawDatagram {
    bytes: Vec<u8>,
    src: SocketAddr,
}

/// Bounded channel capacity between the recv task and the decode+dispatch
/// task. A const, not a config field — no evidence yet that any deployment
/// needs to tune it; promoting it later is a one-line change if that
/// evidence appears (see `SEND_TIMEOUT_DEFAULT` in buffered_writer.rs for
/// the same reasoning already applied once in this codebase).
const RECV_QUEUE_CAPACITY: usize = 4096;
```

`run_with_socket` becomes: spawn one `tokio::task` running `decode_dispatch_loop` (owns the single `IpfixDecoder`, exactly as today — no locking, no sharding), then run the recv loop **inline** in the calling task:

```rust
loop {
    match socket.recv_from(&mut buf).await {
        Ok((len, src)) => {
            if !self.allowed_ips.is_allowed(&src) {
                metrics::counter!("listener_source_rejected", "protocol" => "ipfix").increment(1);
                continue;
            }
            match tx.try_send(RawDatagram { bytes: buf[..len].to_vec(), src }) {
                Ok(()) => {}
                Err(_) => {
                    metrics::counter!("listener_recv_queue_dropped", "protocol" => "ipfix").increment(1);
                }
            }
        }
        Err(e) => error!("IPFIX UDP receive error: {}", e),
    }
}
```

`decode_dispatch_loop` is exactly today's `match decode_datagram(...) { ... self.handler.handle_flows(flows, src).await ... }` body, unchanged, just moved to a separate task and reading `RawDatagram`s off the channel instead of a shared local buffer.

**Load-bearing details, do not drop any of these:**

- `tx.try_send`, never `.await` on a full channel. The whole point is that the recv task must never wait on anything downstream — the same reasoning `buffered_writer.rs`'s `try_send`/`parquet_s3_dropped` already established for the writer channel (see Global Constraints). An `.await`-based send here would reproduce finding #4's exact bug with a channel in place of a handler call.
- `is_allowed` stays on the recv task, before the channel send, in the same position it holds today — `listener_source_rejected`'s meaning ("rejected before any decode work") must not shift.
- `ipfix_datagrams_received` and `ipfix_decode_errors` stay exactly where they are today: inside `decode_datagram` and its caller, now running in the consumer task. Their meaning (per datagram that made it past the recv task) is unchanged; only which task calls them changes.
- No new counter reuses `DropSite`/`DropKind` from `src/forwarding/drop_log.rs` — that enum is scoped to the `ParquetWriterHandle` family and shares a log-throttle mechanism this task deliberately does not want (see Global Constraints' no-log-line rule). `listener_recv_queue_dropped{protocol}` is a new, independent, unthrottled counter, following `listener_source_rejected`'s existing pattern of "just increment, no log."
- **New accounting invariant**, and a test must assert it: for every datagram that reaches the recv task and passes the allow check, exactly one of `ipfix_datagrams_received` (via the consumer, whether or not it goes on to decode-error) or `listener_recv_queue_dropped{protocol="ipfix"}` fires. This is the same reconciliation discipline finding #1 and finding #6 already apply to kernel loss and writer-channel loss respectively — a third drop site needs the same rigor, not a shrug.

**`start_with_shutdown`'s shutdown arm needs a drain, not just a `break`.** Today it `break`s out of `select!` and returns. With two tasks, a shutdown must: (1) stop the recv loop, (2) drop the channel's `Sender` so the consumer's `rx.recv()` returns `None` once the queue empties, (3) `.await` the consumer task's `JoinHandle` so any already-queued datagrams are decoded and dispatched before `start_with_shutdown` returns — mirroring `PartitionedParquetWriter::drain_pending_flushes`'s existing "don't return while work is still in flight" pattern for the same reason (a caller awaiting shutdown expects it to mean something).

- [ ] **Step 1: Write the failing unit test for the core regression this task exists to fix**

  In `src/ipfix/listener.rs`'s `mod tests`, add `recv_task_keeps_draining_the_socket_while_the_consumer_is_stalled`: build a listener with a handler that blocks forever on a `tokio::sync::Notify` inside `handle_flows` (never resolves), a **tiny** `RECV_QUEUE_CAPACITY`-equivalent test seam (add a `pub(crate) fn run_with_socket_and_queue_capacity(&self, socket: UdpSocket, capacity: usize)` test-only entry point mirroring `buffered_writer.rs`'s `for_test`/`with_send_timeout` seams), send enough datagrams to overflow a capacity-1 queue while the stalled consumer never drains it, then assert: (a) the recv task is still calling `recv_from` — i.e. sending one more datagram after the overflow does not time out on the sender side, proving the socket has a live reader — and (b) `listener_recv_queue_dropped{protocol="ipfix"}` is nonzero. This is the test that would fail today (recv would stall) and is the direct regression guard for finding #4's mechanism.

- [ ] **Step 2: Run it, confirm it fails** against the current (unmodified) listener — the failure mode is either a compile error (the test seam doesn't exist yet) or a timeout waiting on the stalled send, not a clean assertion failure; note which in the commit message.

- [ ] **Step 3: Implement the split** as designed above, in both `run_with_socket` and `start_with_shutdown`.

- [ ] **Step 4: Write the accounting-invariant test.** `sent_datagrams_equal_received_plus_queue_dropped_plus_rejected`: real `UdpSocket`, tiny queue capacity, a handler that sleeps briefly per batch (slow but not infinite, so some datagrams land and some overflow), send a known count N, then assert `ipfix_datagrams_received_delta + listener_recv_queue_dropped_delta + listener_source_rejected_delta == N` via a `DebuggingRecorder` snapshot (same technique as `src/zeek/listener.rs`'s `received_counters_fire_with_a_non_default_handler`).

- [ ] **Step 5: Confirm both new tests pass**, then run the full existing suite: `cargo test --lib ipfix:: && cargo test --test ipfix_local_integration` (and any other `ipfix_*` integration test — `grep -rl ipfix tests/*.rs`) — every existing test in `mod tests` at the bottom of `listener.rs` (`listener_receives_ipfix_datagrams_and_calls_handler`, `start_with_shutdown_exits_on_signal`, `start_with_shutdown_honors_configured_receive_buffer`, `listener_ignores_malformed_datagrams_and_continues`, `with_allowed_ips_blocks_disallowed_source`, `with_allowed_ips_allows_whitelisted_source`) must still pass unmodified — they exercise exactly the counters and behaviors this task promises not to change.

- [ ] **Step 6: Integration-level coverage.** Create `tests/ipfix_recv_decouple_integration.rs`: a real `IpfixListener::start_with_shutdown` over a real socket, a burst of valid datagrams sent faster than a deliberately-slow (but not stalled) handler drains them, then assert the accounting invariant from Step 4 holds through the real production entry point (`start_with_shutdown`), not just the test seam — this is what proves the seam from Step 1 isn't hiding a difference in the real path.

- [ ] **Step 7: e2e correctness test (CI-safe, not a perf test).** Create `tests/ipfix_recv_queue_dropped_metric_e2e.rs`, mirroring `tests/zeek_received_metric_e2e.rs`'s shape: a real `Server` with `metrics.enabled = true`, a real `IpfixListener` wired through the real startup path (small enough queue via a test-only config override, or accept the default 4096 and send enough datagrams fast enough in a tight loop to overflow it — pick whichever is less flaky; note the choice and why in the test's header), then scrape the real `/metrics` HTTP endpoint and assert `listener_recv_queue_dropped{protocol="ipfix"}` appears and is nonzero. One `#[tokio::test]` per binary, per the existing constraint (`metrics::set_global_recorder` panics on a second call).

- [ ] **Step 8: Prove the guard tests actually guard something.** Commit first. Then temporarily revert Step 3's `try_send` back to something that would block (e.g. `.send().await`) and confirm Step 1's test now hangs/times out; restore. This is the mutation-testing discipline the repo's other perf plans already apply to counter-guard tests.

- [ ] **Step 9: Acceptance measurement.** Run `scripts/repeat-ipfix-loopback-loss.sh` (Tier 0) at `RATE=20000 RUNS=5` and `RATE=5000 RUNS=5` against this branch's tip, compare against Tier 0's baseline file using the Success Criteria section's pass bar. Record the result — pass, inconclusive, or regression — in a new `docs/performance/2026-09-14-recv-decode-decouple-results.md`, in the same honest style as the SO_RCVBUF write-up (report the number whichever way it comes out; an inconclusive result is a legitimate outcome to report, not a reason to hide the task).

- [ ] **Step 10: Commit**, referencing the measurement doc.

---

## Tier 2 — Global allocator swap (spike, cheap to falsify)

Branch: `perf/global-allocator-spike`.

**Framed as a spike, not a guaranteed merge**, because although the diff is tiny, its effect is a global, blunt-instrument change whose interaction with `arrow`/`parquet`'s own allocation patterns is unverified — the honest thing is to measure before claiming a win, exactly as this plan's own instructions require for anything resting on correlational evidence (finding #5's allocator/futex/atomics group is inferred by presence/absence across two runs, not by call-graph, per the source doc's own §4.3).

### Task 2.1: Try `mimalloc` as the global allocator, profile Run B's shape before/after

**Files:** `Cargo.toml` (add `mimalloc` as an optional dependency behind a feature, or a straight dependency if the spike proves out — decide after measuring, not before), `src/main.rs` or `src/lib.rs` (`#[global_allocator]`)

- [ ] **Step 1:** Add `mimalloc = "0.1"` as a dependency and set it as `#[global_allocator]` behind a Cargo feature (e.g. `mimalloc-allocator`) so the spike can be A/B toggled with a single build flag rather than two branches with drifting code.
- [ ] **Step 2:** Rebuild the `profiling` profile with `--features pprof,mimalloc-allocator` and re-run **exactly** Run B's reproduction from `docs/performance/2026-09-14-ipfix-recv-path-cpu-profile.md` §1 (`[ipfix.local]` configured, `FORWARD=true`, `RATE=20000 DURATION=25 DELAY=5 HZ=99`).
- [ ] **Step 3:** Compare the new self-time table against Run B's committed one: does the allocator/futex/atomics group (61.6% before) shrink, and does loss (7.89% before) drop? Use `examples/pprof_selftime.rs`, already committed, to extract it — do not write a new extraction tool.
- [ ] **Step 4: Decide.** If loss drops materially and the allocator group shrinks, keep the feature and flip it on by default in a follow-up commit (still gated, so it stays reversible with one flag if a production regression surfaces later — e.g. `mimalloc` behaving differently under a container cgroup memory limit than under this profiling host). If neither moves, remove the dependency and record the negative result in `docs/performance/` — a documented "we tried, it didn't help" is worth exactly as much as a positive result for stopping the next person from re-trying it blind.
- [ ] **Step 5: Testing.** This spike changes no application behavior (same code paths, different `malloc`), so no new unit/integration/e2e tests are needed for correctness — the existing full suite passing under the new allocator IS the correctness check. Run `cargo test` in full with the feature enabled before deciding to keep it; a crash or hang under a different allocator is itself a disqualifying finding.
- [ ] **Step 6: Commit** either the kept feature (with the before/after numbers in the commit message and a doc update) or nothing, with the negative result documented.

---

## Tier 3 — Repeat Tier 1's pattern on sFlow UDP and syslog UDP

Two independent branches, dispatched separately (different files, no merge conflict, but each is its own measured claim — do not batch them into one "and also sflow and syslog" commit, per finding #8's honesty requirement that these are structurally similar, not proven similar).

### Task 3.1: sFlow UDP recv/decode decouple

Branch: `perf/recv-decode-decouple-sflow`.

**Files:** `src/sflow/listener.rs`

Mirrors Task 1.1 exactly, with one simplification: sFlow's `decode_datagram` (`src/sflow/decoder.rs:51`) is **stateless** — no `IpfixDecoder`-equivalent cache to keep single-owned, so the consumer task has no state-sharing constraint at all, which also means Tier 4's per-worker-cache risk does not apply here (finding #8).

- [ ] Same nine steps as Task 1.1, s/ipfix/sflow/, s/`FlowRecord`/`SflowRecord`/, s/`ipfix_decode_errors`/`sflow_decode_errors`/, new counter `listener_recv_queue_dropped{protocol="sflow"}`.
- [ ] **Acceptance measurement:** sFlow has no committed loopback-loss reproduction script today (`tools/loadgen` has no `sflow-udp` subcommand — out of scope here, see the Explicitly Not In Scope table). Adapt `scripts/repeat-ipfix-loopback-loss.sh` into `scripts/repeat-sflow-loopback-loss.sh` using `logthing`'s own sFlow decoder against hand-crafted UDP datagrams sent via a small throwaway sender (or, if `loadgen sflow-udp` already exists by the time this task runs, use it instead and delete the throwaway sender) — either way, do not claim a result without an actual loopback measurement; do not extrapolate sFlow's expected win from IPFIX's numbers.

### Task 3.2: syslog UDP recv/decode decouple

Branch: `perf/recv-decode-decouple-syslog-udp`.

**Files:** `src/syslog/listener.rs` (UDP arm only — the TCP arm is untouched; finding #4's contrast case, zeek-over-TCP, already shows TCP has no drop problem here, and syslog TCP's own listener has its own concurrency model via `MAX_SYSLOG_TCP_CONNECTIONS` that this plan does not touch)

- [ ] Same shape as Task 1.1, applied only to the UDP `recv_from` loop inside `SyslogListener`. Syslog UDP parsing (`payload::dispatch`) is heavier than IPFIX/sFlow's binary decode and was the subject of the still-unresolved `2026-07-25-syslog-udp-cpu-profile.md` (~85% of ~94.6µs/datagram unattributed) — this task's before/after measurement is also the first chance to see whether decoupling recv moves that unattributed cost's *effect* on loss, even without knowing what the cost *is*.
- [ ] New counter: `listener_recv_queue_dropped{protocol="syslog_udp"}` (matching the existing `listener_source_rejected{protocol="syslog_udp"}` label value already in use).
- [ ] **Acceptance measurement:** `tools/loadgen` already has `syslog-udp` (`tools/loadgen/src/syslog_udp.rs`) — reuse it directly; no new generator needed. Same 20,000/s and 5,000/s repeat protocol as Tier 0/Tier 1.

---

## Tier 4 — `SO_REUSEPORT` fan-out (spike only; do not implement production code without passing this gate)

Branch: `perf/reuseport-spike`.

**Why this is speculative and not simply "Tier 1 but bigger":** Tier 1 gets two pipeline stages running concurrently; this gets N *independent* recv+decode+dispatch loops, each its own `SO_REUSEPORT` socket, genuinely parallel across cores. The upside is real. The risk is specific to IPFIX: `IpfixDecoder`'s template cache (`src/ipfix/decoder.rs`) is currently single-owned per listener. With N independent sockets, each would need its own decoder instance (or a shared, locked one — reintroducing the exact futex contention finding #5 just diagnosed). Linux's default `SO_REUSEPORT` hashing keeps a given (src ip, src port) pair on the same socket as long as the *set* of sockets in the group doesn't change, so a steady-state exporter's template and later data sets should land on the same worker's cache in practice — but "should, in practice, on a stable socket set" is exactly the kind of claim finding #7 says not to ship without measuring, especially since a worker restart or scale-event changes the socket set and could silently strand a data set against the wrong (or an empty) template cache, which manifests as `ipfix_templates_missing` incrementing — a metric finding #1 of the multiformat load doc explicitly notes has been **0 at every rate tested to date**. A regression there is worse than the loss this plan is trying to fix, because it's silent data loss dressed as a decode success (empty flow batch, no error logged) rather than a visible kernel counter.

### Task 4.1: Feasibility spike — does the template cache actually survive a realistic multi-exporter, multi-worker run?

**Files:** none shipped; this is a throwaway experiment, documented and then deleted or kept as a `docs/superpowers/specs/` write-up, not merged into `src/`.

- [ ] **Step 1:** Build a small standalone experiment (can live in a scratch branch, not this plan's branch) with 2-4 `SO_REUSEPORT`-bound IPFIX sockets, each running Tier 1's decoupled loop with its own `IpfixDecoder`.
- [ ] **Step 2:** Drive it with `loadgen ipfix-udp` extended (or a throwaway variant) to simulate **multiple distinct exporters** (multiple source ports/addresses) each sending its own template-then-data sequence, at a rate high enough that `SO_REUSEPORT`'s hash actually spreads them across more than one worker.
- [ ] **Step 3:** Watch `ipfix_templates_missing` for the entire run. **Pass bar: it stays at 0**, matching the existing invariant. Any nonzero reading fails the spike outright, regardless of any loss improvement observed — this is a correctness gate, not a tunable tradeoff.
- [ ] **Step 4:** If it passes, measure loss the same way as Tier 1 (N≥5 runs, median+range) and compare against Tier 1's own committed result. **Only proceed to a real implementation task if the improvement over Tier 1 alone is large enough to justify N sockets, N decoders, and the added startup/config complexity of choosing N** (which itself must be a small fixed constant, not a new config knob, per the plan's YAGNI mandate — pick something like `min(4, available_parallelism)` computed at startup, not operator-configurable, unless the spike itself surfaces a concrete reason an operator would need to change it).
- [ ] **Step 5:** Write up the result (pass/fail on the correctness gate, and the measured delta if it passed) in `docs/performance/`, whichever way it comes out. If it fails the correctness gate, that write-up **is** the deliverable — it closes this line of investigation with evidence instead of leaving it as a permanently tempting unexamined idea.

---

## Tier 5 — Dedicated recv thread/runtime, isolated from handler-pool contention (spike, conditional on Tier 1's own result)

Branch: `perf/dedicated-recv-thread-spike`.

**Gate: only run this tier if Tier 1's acceptance measurement (Task 1.1 Step 9) is *inconclusive or a regression specifically under a real, non-trivial handler* (i.e. an IPFIX-local/S3-configured run, Run-B shape) while still passing cleanly under the trivial `DefaultIpfixHandler` (Run-A shape).** That specific pattern — fine with a cheap handler, still losing with a real one — is the signature of finding #5's resource-starvation mechanism surviving Tier 1's two-task split because tokio's shared multi-threaded runtime can still schedule both the recv task and the writer's allocator-heavy work onto the same worker thread under load. If Tier 1 passes cleanly under both handler shapes, skip this tier entirely — it would be solving a problem Tier 1 already solved, at a higher implementation cost (a second `tokio::runtime::Runtime` or a raw OS thread bridging into async via a channel, plus shutdown-lifecycle changes to match).

### Task 5.1: Spike — pin the recv task to its own single-threaded runtime, re-run Run B's shape

- [ ] **Step 1:** Behind a feature flag or a throwaway branch, run the recv-only task (post-Tier-1) on its own `tokio::runtime::Builder::new_current_thread()` runtime on a dedicated OS thread, communicating into the shared runtime's decode+dispatch consumer via the same `RECV_QUEUE_CAPACITY` channel Tier 1 already built (the channel is a `Send`-safe boundary regardless of which runtime owns each end).
- [ ] **Step 2:** Re-run Run B's exact reproduction (real `[ipfix.local]` handler, 20,000/s) and compare loss and the self-time grouping against Tier 1-alone's result. **Pass bar:** a measurable further reduction beyond Tier 1 alone, using the same N≥5, non-overlapping-ranges bar as the primary success criterion.
- [ ] **Step 3:** If it passes, this becomes its own implementation task with full unit/integration/e2e coverage of the two-runtime shutdown path (a dedicated thread needs an explicit join, not just an aborted task — get this wrong and shutdown either hangs or drops in-flight datagrams silently). If it does not pass, document the negative result and stop — do not carry a second runtime into production for a gain that didn't materialize.

---

## Explicitly NOT in scope

| Item | Why |
|---|---|
| `recvmmsg` batching | Evidence (Run A: 0.51/12 cores used while losing 5.47%) shows this is not a syscall-throughput-bound problem; eliminating syscalls entirely frees at most ~0.23 of an idle core. Disproportionate unsafe/FFI surface for a mechanism the profile doesn't support. Revisit only with fresh profiling after Tiers 1 and 4, if syscall count is *still* implicated. |
| Raising `SO_RCVBUF` further, or `net.core.rmem_max` | Already measured and found not to help at 5,000/s, non-conclusive at 20,000/s (finding #2). Do not re-open. |
| Any IPFIX/sFlow/syslog decoder optimisation | Decode is 0.3-1.1% of self-time and 42-50x cheaper than encode (finding #3). No case for it. |
| Enlarging the writer channel (`BufferedWriterConfig.channel_capacity`) | Same reasoning as the `SO_RCVBUF` finding: a bigger buffer in front of a consumer that might be CPU/lock-bound (Tier 2's open question) only delays the overflow, it doesn't remove the cause. |
| A config knob for recv-queue capacity, consumer count, or `SO_REUSEPORT` worker count | Every one of these is a const in this plan, chosen once and hardcoded, exactly per the "no config knob, no thread pool, no trait for a 5% gain" mandate. Promote to config only if a specific operator need surfaces later — trivial to do then, per `SEND_TIMEOUT_DEFAULT`'s existing precedent for the same call. |
| Zeek, suricata, WEF, HEC, OTLP ingest paths | Zeek/suricata are TCP and already lose nothing (finding #4's own contrast case). WEF/HEC/OTLP have no drop evidence in either measurement doc — nothing here targets an unmeasured problem. |
| `loadgen sflow-udp` / `loadgen hec` / `loadgen otlp` subcommands | Tier 3's sFlow task needs *a* sFlow sender to measure against but does not require building the full `loadgen` subcommand if a throwaway sender is faster to write; building the polished subcommand is separately useful but not blocking and not this plan's job. |
| Re-litigating whether the allocator/futex/atomics 61.6% in Run B is caused specifically by the Parquet/Arrow path vs. some other concurrent cost | Already flagged as unproven-by-call-graph in the source doc's own §4.3. Tier 2's spike answers the only question that actually matters operationally — does changing the allocator move the number — without needing the call-graph attribution first. |
| A capacity number ("logthing sustains N datagrams/s") | This environment structurally cannot produce one — generator and server share 12 vCPUs, and for TCP the generator itself saturates first. Every measurement in this plan is a relative before/after at a fixed offered rate. |
