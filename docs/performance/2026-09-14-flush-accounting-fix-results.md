# Flush byte-accounting fix — measured results (2026-09-14)

Produced for Task 3 of
`docs/superpowers/plans/2026-09-14-flush-byte-accounting-fix.md`, on branch
`fix/flush-byte-accounting`.

**Before commit:** `99422da` (branch base — the byte-accounting bug as
characterized in `docs/performance/2026-09-14-writer-channel-loss.md`).
**After commit:** `eacb450` (Task 1 fix + Task 2 integration tests applied
on top of `99422da`).

## Hardware caveat (carried forward verbatim from prior perf docs)

This is a **QEMU/KVM guest, 12 vCPUs, no `cpufreq` interface**, with the
generator and server sharing the same core pool, and — specific to this run
— a **shared, multi-tenant host**: a Kubernetes control plane
(`kube-apiserver`, `etcd`, `kubelet`, `cilium-agent`), Docker, and several
other concurrent Claude Code agent sessions (including at least one other
`cargo test`/build) were running throughout data collection, with load
average ~7-9 on the 12-core box. This setup cannot establish an absolute
maximum sustainable rate; for UDP the kernel queue saturates before any CPU
ceiling is found, and this specific run additionally has more host
contention than the more controlled single-tenant baseline used in
`docs/performance/2026-09-14-throughput-baseline-repeats.md`. Nothing below
is a capacity number — every figure is loss at a fixed, reproduced offered
rate. **The bottom-line result — no material reduction in
`parquet_s3_dropped` — is corroborated by a direct, host-load-independent
mechanism check (§3), not by the throughput numbers alone**, so the
headline finding does not rest on this caveat.

## Reproduce

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export CC=/usr/bin/gcc CXX=/usr/bin/g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo build --release --bin logthing
cargo build --release -p loadgen

RATE=20000 DURATION=15 RUNS=5 SHAPE=real ./scripts/repeat-ipfix-loopback-loss.sh
```
Run once against a checkout of `99422da` (before) and once against a
checkout of this branch (after); the script restarts the server between
every run so `parquet_s3_dropped` is a per-run value, not a delta.

## 1. Headline numbers: `parquet_s3_dropped{source="ipfix"}`

| | N | median | min | max |
|---|---|---|---|---|
| **Before** (`99422da`) | 5 | **207,937** | 189,004 | 225,379 |
| **After**, batch 1 (`eacb450`) | 5 | 238,543 | 230,470 | 248,348 |
| **After**, batch 2 (repeat, same commit) | 5 | 226,518 | 216,367 | 231,165 |
| **After**, combined | 10 | **230,818** | 216,367 | 248,348 |

Relative change, combined-after median vs. before median:
**(230,818 − 207,937) / 207,937 ≈ +11.0%** — an *increase* in
`parquet_s3_dropped`, not a reduction. The two five-run after batches
(collected ~10 minutes apart) overlap tightly with each other and do not
overlap with "before" in the improving direction, so this is not a
one-off outlier — it reproduces.

**Decision-rule bucket: `<30%, or worse`.** Per the plan's pre-committed
rule: *"do not land quietly. The mechanism was confirmed in isolation but
not end to end; report that, and treat the accumulator work as the primary
candidate instead."* This section and §3 do exactly that.

## 2. Kernel-level loss (context, not the target metric)

| | N | median loss_pct | min | max |
|---|---|---|---|---|
| Before | 5 | 4.32% | 1.45% | 9.99% |
| After, batch 1 | 5 | 0.41% | 0.20% | 0.48% |
| After, batch 2 | 5 | 0.03% | 0.00% | 5.08%* |

(*batch 2's max is a single-run outlier consistent with host contention,
not a systematic regression — 4 of 5 batch-2 runs were ≤0.08%.)

Kernel-level (socket-buffer) loss dropped substantially and consistently.
This is a real, reproducible side effect of the fix — plausibly because
removing the old code's frequent `concat_batches` bursts stops those
bursts from starving the async runtime workers that also service the UDP
recv path — but it is **not** the metric this plan targets, and it does not
offset the `parquet_s3_dropped` result in §1. `parquet_s3_dropped` fires
downstream of the kernel socket entirely (it is a full-channel drop at
`ParquetWriterHandle::try_send`, after a datagram has already been received
and decoded), so an improvement in kernel loss and a non-improvement in
channel loss are not in tension — they are two different drop sites, exactly
as the plan's Finding #5 says not to conflate.

## 3. Mechanism check: flush count, isolated from host noise

A single manual run per side (same config as the script, scraping
`/metrics` immediately after the 15s load and before shutdown, so only
mid-run flushes are counted — not the graceful-shutdown flush) directly
confirms *why* §1 looks the way it does, independent of run-to-run host
noise:

| | `parquet_s3_uploads` (flush count) | `parquet_s3_records_written` | `parquet_s3_dropped` |
|---|---|---|---|
| Before | 37 | 68,359 | 203,806 |
| After | **0** | 0 (absent — metric never incremented) | 234,353 |

The fix works exactly as designed at the mechanism level: flush count went
from 37 (matching the plan's diagnosed ~49/15s) to **zero** — with real
bytes accounted for, neither the 128 MiB byte threshold nor the 100,000-row
threshold is reached within a 15 s, 20,000/s burst, so the writer correctly
declines to flush at all until shutdown. This is the fix working as
specified, not a bug in the fix.

**But eliminating flush overhead didn't reduce `parquet_s3_dropped`,
because flushing was never the binding constraint at this rate.** With
`channel_capacity` at its default (8,192) and per-push mapping cost
unchanged by this fix (a fresh 19-builder `FlowRecordBuilders::new()` per
push — the "per-push builder allocation churn" the plan's own Findings and
Explicitly-NOT-in-scope table name as the ~40% allocator / ~12.5% futex
cost `RecordBatchAccumulator`s would address), the single writer-task's
drain rate stays far below the 20,000/s offered rate regardless of flush
cadence. Only ~65,600 of ~300,000 offered records made it into the channel
before it filled and stayed full for the rest of the run (`after`); before
the fix, a similar ~86,000 got in before `try_send` started failing, with
the extra `concat_batches` overhead adding cost on top without changing
which mechanism was the actual bottleneck. Removing that *extra* cost was
not enough to move the bottleneck, because it was never the majority
contributor at this rate — the per-push allocation churn was.

## 4. Opposite-failure check (required by the plan's success criteria)

- **`parquet_s3_buffer_dropped` (hard-cap eviction) stayed at 0** in both
  the before and after manual scrapes (metric absent from `/metrics` output
  in both cases — never incremented) and is additionally covered
  deterministically by
  `tests/flush_byte_accounting_integration.rs`'s
  `buffer_dropped_stays_zero_under_real_byte_accounting`. Under-counting
  bytes so a buffer grows until the row cap evicts it did **not** occur.
- **`parquet_s3_buffer_rows` did not run away.** The `after` run's buffer
  legitimately holds more rows for longer before its first flush (~65,600
  by end of run, well under both the 100,000-row flush threshold and the
  400,000-row hard cap) — this is the fix behaving as designed (bigger,
  real batches), not runaway growth. The gauge itself does not surface in
  a 15 s scrape at the default 900 s `flush_interval_secs` (it is
  republished on the flush-check ticker, which is 900 s here) — this is an
  artifact of the short test window at default config, not evidence either
  way, so it is not relied on as the basis for this check.

## 5. Verdict and recommendation

**Land Tasks 1 and 2 anyway — but do not claim they fix the ~70% IPFIX
loss end to end, because this measurement shows they don't, at this rate,
on this host.** The byte-accounting fix is independently correct (Task 1's
unit test proves an ~884x overstatement — 5,304 bytes reported vs. 6 bytes
used, for the specific case measured here — is closed; Task 2's integration
test proves the flush trigger now tracks real bytes) and removes a real
defect (a config-vs-behavior mismatch of 1-2 orders of magnitude) that was
never intentional. But per §3, it was not the dominant contributor to
`parquet_s3_dropped` at 20,000/s in this environment — the per-push
19-builder allocation cost is next in line, exactly as the plan's own
Explicitly-NOT-in-scope table anticipated, and closing this gap did not
even reach the plan's own predicted "most likely" 30-90% partial-reduction
scenario.

**Follow-up, in priority order:**
1. Give `IpfixSink` (and the other five non-accumulator sinks) a
   `RecordBatchAccumulator`, per the plan's Explicitly-NOT-in-scope §1 —
   this is now the primary candidate for closing the remaining gap, not a
   secondary optimization.
2. Re-run this exact reproduction after that change lands, before claiming
   any additional throughput improvement.
3. Consider whether `channel_capacity`'s default (8,192, absorbing ~0.4s of
   headroom at 20,000/s) is adequate once per-push cost drops — this
   measurement cannot distinguish "channel too small" from "drain too slow"
   as the more fixable lever until the accumulator work is in.

## 6. Durability caveat this fix exposes (behaviour change, not a regression)

Before the fix, the overstated byte estimate made every sink flush far more
often than its configuration asked for — the IPFIX run in §3 flushed 37
times in 15 s against a configured 900 s / 100 MiB cadence. That frequent
flushing was **accidental durability**: nobody configured it, a defect
produced it, and the measured cost of producing it was the `concat_batches`
overhead this fix removes.

With correct accounting the configured cadence is now actually honoured.
`flush_interval_secs` defaults to **900 (15 minutes) for every sink** —
zeek, suricata, wef, hec, ipfix, sflow and the aggregate writer
(`src/config/mod.rs:371`, `:479`, `:547`, `:632`, `:931`, `:1048`,
`:1147`). So at low-to-moderate ingest rates, where neither
`flush_threshold_bytes` nor `max_buffer_rows` is reached, buffered records
can now sit in memory for up to 15 minutes before being written to object
storage, where previously they were written within seconds.

**What is and is not at risk:**

- Graceful shutdown (SIGTERM/SIGINT) flushes buffers, so a normal restart,
  deploy or rolling upgrade loses nothing.
- An **ungraceful** loss of the process — SIGKILL, OOM kill, host power
  loss, container eviction — now discards up to `flush_interval_secs`
  worth of buffered records instead of a few seconds' worth.

**This is deliberately left as-is.** Lowering the default would be a
repo-wide behaviour change affecting all seven sinks, and it is a durability
policy decision, not part of closing the accounting defect. Operators with a
tighter recovery-point objective should set `flush_interval_secs` explicitly
per sink; the existing config knob is sufficient and needs no code change.

The honest framing: the 900 s default was always the configured intent, and
was always the documented behaviour — it simply never happened. This fix
makes configuration and behaviour agree. If 900 s is the wrong default, that
is a pre-existing question about the default, surfaced rather than caused by
this work.
