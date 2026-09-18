# Tier 0 baseline: N-repeat IPFIX loopback loss (2026-09-14)

Produced by `scripts/repeat-ipfix-loopback-loss.sh` (Task 0.1 of
`docs/superpowers/plans/2026-09-14-throughput-improvements.md`), which
restarts `logthing` between every run so `ipfix_datagrams_received`,
`ipfix_socket_drops`, and `parquet_s3_dropped{source="ipfix"}` all start at
zero for that run — the numbers below are per-run values, not deltas.
`/proc/net/snmp`'s `RcvbufErrors` is host-wide and is **not** reset by a
restart, so it is independently diffed before/after the load burst inside
each run regardless.

**Commit under test:** `ec331df` (this plan's base commit — no production
code changed since; the harness itself was added on top, at `3b4ed04`, and
does not affect listener behavior).

## Hardware caveat (carried forward verbatim from prior perf docs)

This is a **QEMU/KVM guest, 12 vCPUs, no `cpufreq` interface**, with the
generator and server sharing the same core pool. This setup cannot establish
an absolute maximum sustainable rate; for UDP the kernel queue saturates
before any CPU ceiling is found. Nothing below is a capacity number — every
figure is loss at a fixed, reproduced offered rate.

## Reproduce

`scripts/repeat-ipfix-loopback-loss.sh` was renamed and generalised to
`scripts/max-ingest-rate.sh` on 2026-09-16 (Task 6 of the max-ingest-rate
plan). The old script's `pkill -f` (which could kill the invoking shell
instead of the server) and its `rm logthing.admin.toml` (which deleted a
tracked file) are both gone from the replacement.

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export CC=/usr/bin/gcc CXX=/usr/bin/g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo build --release --bin logthing
cargo build --release -p loadgen

FORMAT=ipfix RATE=20000 DURATION=15 RUNS=5 SHAPE=trivial ./scripts/max-ingest-rate.sh
FORMAT=ipfix RATE=20000 DURATION=15 RUNS=5 SHAPE=real    ./scripts/max-ingest-rate.sh
FORMAT=ipfix RATE=5000  DURATION=15 RUNS=5 SHAPE=trivial ./scripts/max-ingest-rate.sh
FORMAT=ipfix RATE=5000  DURATION=15 RUNS=5 SHAPE=real    ./scripts/max-ingest-rate.sh
```

`SHAPE=trivial` runs `DefaultIpfixHandler` with no `[ipfix.*]` sink
configured; `SHAPE=real` runs a real `[ipfix.local]` Parquet handler writing
to a temp directory (local disk only, no external service, cleaned up on
exit).

On every one of the 20 runs below, `ipfix_socket_drops` and the
`RcvbufErrors` delta reconciled **exactly** (never off by more than 0) — the
harness's own internal consistency check never fired.

## 20,000/s — the plan's primary acceptance rate

### Trivial (`DefaultIpfixHandler`)

| run | offered | received | socket_drops | rcvbuf_errors_delta | loss% |
|---|---|---|---|---|---|
| 1 | 299,981 | 299,982 | 0 | 0 | 0.0000 |
| 2 | 299,985 | 299,986 | 0 | 0 | 0.0000 |
| 3 | 299,980 | 299,981 | 0 | 0 | 0.0000 |
| 4 | 299,980 | 299,981 | 0 | 0 | 0.0000 |
| 5 | 299,981 | 299,858 | 124 | 124 | 0.0413 |

**median 0.0000% · min 0.0000% · max 0.0413%**

At the default 4 MiB `receive_buffer_bytes`, the trivial handler is
essentially at the floor of what this host can lose at 20,000/s — 4 of 5
runs lost nothing at all, and the one that did lost 124 datagrams out of
~300,000. This is the "sometimes produces zero loss" case flagged going in;
it is reported as-is rather than rounded up to a meaningful percentage.

### Real (`[ipfix.local]` Parquet sink)

| run | offered | received | socket_drops | rcvbuf_errors_delta | parquet_s3_dropped{source="ipfix"} | loss% |
|---|---|---|---|---|---|---|
| 1 | 299,934 | 289,038 | 10,897 | 10,897 | 205,495 | 3.6331 |
| 2 | 299,992 | 289,230 | 10,763 | 10,763 | 216,752 | 3.5878 |
| 3 | 299,986 | 284,680 | 15,307 | 15,307 | 200,083 | 5.1026 |
| 4 | 299,981 | 294,958 | 5,024 | 5,024 | 216,074 | 1.6748 |
| 5 | 299,957 | 287,172 | 12,786 | 12,786 | 210,672 | 4.2626 |

**median 3.6331% · min 1.6748% · max 5.1026%** (kernel loss, i.e.
`ipfix_socket_drops` / offered)

**Separately:** `parquet_s3_dropped{source="ipfix"}` (writer-channel drops,
downstream of the kernel and unrelated to `SO_RCVBUF`) is enormous under this
shape — 200k-217k per run, roughly 70-75% of everything the kernel actually
delivered. This is finding #6 from the plan at far larger magnitude than
previously measured; it is reported here for completeness but is a
*different* drop site from the kernel loss the median/min/max above
describes, and the two must not be added together.

> **⚠️ Stale as of 2026-09-18 — do not trust this section's writer-channel
> figures going forward.** Commit `c103de3` ("Merge perf/ipfix-accumulator:
> IPFIX 82% loss -> zero, ~18x throughput"), landed the day after this
> baseline and confirmed an ancestor of the current `HEAD`
> (`git merge-base --is-ancestor c103de3 HEAD`), eliminated the writer-channel
> drop behavior described above. `docs/performance/2026-09-18-max-ingest-rate.md`
> re-measured IPFIX real-shape loss under the same restart-per-run,
> RcvbufReconciled harness and found `parquet_s3_dropped{source="ipfix"}` at
> **0** on every run, at every rate tested, including the failing ones — all
> loss at this campaign's ceiling is kernel-socket drop, not writer-channel.
> The 3.6331% *kernel*-loss median above is not itself contradicted (that
> drop site is unrelated to the accumulator fix), but do not use this
> document's writer-channel numbers, or its "3-4x undercount" framing of
> total loss, as current — see the newer document for the post-fix picture.

## 5,000/s — lower-rate sanity check (plan's own secondary rate)

### Trivial

All 5 runs lost **zero** datagrams (`ipfix_socket_drops == 0` every time,
~75,000 offered per run). Not reported as a percentage — there is nothing to
measure at this rate/shape/host combination.

### Real

| run | offered | received | socket_drops | rcvbuf_errors_delta | parquet_s3_dropped{source="ipfix"} | loss% |
|---|---|---|---|---|---|---|
| 1 | 74,995 | 74,996 | 0 | 0 | 11,463 | 0.0000 |
| 2 | 74,995 | 71,840 | 3,156 | 3,156 | 7,962 | 4.2083 |
| 3 | 74,998 | 68,814 | 6,185 | 6,185 | 983 | 8.2469 |
| 4 | 74,995 | 74,970 | 26 | 26 | 3,042 | 0.0347 |
| 5 | 74,995 | 74,996 | 0 | 0 | 1,356 | 0.0000 |

**median 0.0347% · min 0.0000% · max 8.2469%**

## Supplementary: does raising the rate fix the trivial-shape noise floor?

The task brief that produced this doc asked, given trivial-shape loss was
near the floor at 20,000/s, to "consider whether the rate needs raising to
produce a measurable baseline." It was tried — 40,000/s and 60,000/s,
5 runs each, same host/session:

| rate | run1 | run2 | run3 | run4 | run5 | median | min | max |
|---|---|---|---|---|---|---|---|---|
| 40,000/s | 0.1538 | 0.0163 | 0.0311 | 0.0000 | 1.7104 | 0.0311 | 0.0000 | 1.7104 |
| 60,000/s | 0.1199 | 0.0533 | 0.0405 | 0.0132 | 1.7563 | 0.0533 | 0.0000 | 1.7563 |

Raising the rate does **not** produce a stable, non-noise-dominated
trivial-shape baseline — it produces a bimodal pattern instead: most runs
cluster under 0.2%, and roughly 1 in 5 spikes to ~1.7%, at both 3x and 2x the
plan's primary rate. This looks like an occasional scheduling stall (the
generator and server sharing 12 vCPUs) rather than a smooth function of
offered load, and it is not resolved by pushing more traffic through. Per
the task brief, `SO_RCVBUF` was **not** shrunk to manufacture a cleaner
number for this committed baseline — that would change the variable under
study.

## Noise floor, stated explicitly (so "ranges must not overlap" is checkable)

- **Trivial shape, 20,000/s:** range is **[0.0000%, 0.0413%]** — already
  touching zero. Any future "after" measurement that also touches zero
  (which finding #4's own trivial-handler profile suggests is likely, since
  the trivial handler carries little of the risk Tier 1 addresses) will
  overlap this range by construction. **The gate's non-overlapping-ranges
  criterion may not be checkable at all for the trivial shape at this rate on
  this host** — there isn't a wide enough "before" spread above zero to
  clear. A future Tier 1 result showing "no measurable difference on the
  trivial shape" should be read as the expected outcome of the risk being
  real-handler-specific (finding #4/#5), not as a harness bug.
- **Real shape, 20,000/s:** range is **[1.6748%, 5.1026%]**, median 3.6331% —
  a ~3.4 point / ~3x span. A pass requires an "after" median ≤ ~1.82%
  (50% relative) **and** an "after" max below 1.6748%. That is a narrow but
  non-degenerate target — this rate is usable for the gate, but the margin
  for error is thin; a Tier 1 result that lands its median around 2-3% with
  a wide range would correctly be called inconclusive, not a pass, exactly
  as the SO_RCVBUF 20,000/s result was.
- **Real shape, 5,000/s:** range is **[0.0000%, 8.2469%]** — noise alone
  spans more than the entire plausible effect size of any change this plan
  proposes. **This rate cannot support the gate for the real shape**; a
  ≥50% relative effect is not distinguishable from run-to-run scheduling
  noise here. This confirms finding #7's own observation (a documented
  3.2-point spread) and extends it: at 5,000/s the spread is worse than
  previously characterized, not merely present.
- **Trivial shape, 5,000/s:** zero on every run — not usable for the gate
  either, in the opposite way (no signal to detect a reduction *from*).

**Bottom line for the plan's later tiers:** treat **20,000/s as the only
rate with any chance of clearing the acceptance gate**, and even there,
budget for the real shape's ~3.4-point native spread when judging whether an
observed reduction is real. The 5,000/s tier, as specified, is not currently
capable of producing a conclusive result for either shape on this host — that
is a property of the host's noise floor, not of any future Tier 1 change,
and it should be weighed before spending run budget on 5,000/s comparisons at
all.
