# Phase 0: generator ceiling — what `tools/loadgen` can emit per format

First measurement of what `tools/loadgen` can produce, independent of (three
UDP formats) or upper-bounded by (four TCP/HTTP formats) a receiver. Produces
the Phase 1 gate that Tasks 3, 4 and 5 read to decide whether generator
optimisation is worth doing at all, per format.

## Hardware caveat (carried forward verbatim from prior perf docs)

This is a **QEMU/KVM guest, 12 vCPUs, no `cpufreq` interface**, with the
generator and server sharing the same core pool. This setup cannot establish
an absolute maximum sustainable rate; for UDP the kernel queue saturates
before any CPU ceiling is found. Nothing below is a capacity number — every
figure is loss at a fixed, reproduced offered rate.

## Provenance

| | |
|---|---|
| Crate version | 0.19.1 |
| Commit (worktree base) | `a52902464eca56184761b785404c5f5c6c5b6db8` |
| Branch | `perf/max-ingest-rate` |
| Date | 2026-09-18 (host clock, confirmed via command/log timestamps during the run — the session's stated "today" of 2026-09-17 did not match the host clock actually observed) |
| Host | same QEMU/KVM guest as above, 12 vCPUs |
| Generator | `target/release/loadgen` (`tools/loadgen`), built this session |
| Server | `target/release/logthing`, built this session |
| Harness | `scripts/loadgen-ceiling.sh` (Task 1, already reviewed) |
| Generator core pinning | `taskset -c 0-3` (hardcoded in the harness) |
| Server core pinning (Step 3 only) | `taskset -c 4-11` |

### Commands run

Three-UDP-format blackhole probe:

```bash
for f in syslog ipfix sflow; do
  FORMAT=$f BLACKHOLE=1 PROCS="1 2 4" DURATION=15 ./scripts/loadgen-ceiling.sh
done
```

Sanity check against a known-good IPFIX reference (`DURATION=5`, matching the
reference run) before trusting the harness: measured 68,652 / 129,846 /
221,024 flows/s at 1/2/4 procs against a reference of 71,066 / 148,430 /
228,008 (deltas -3.4% / -12.5% / -3.1%, consistent with this host's
documented scheduling noise). The `DURATION=15` IPFIX row below independently
reproduces the same regime (71,991 / 143,853 / 238,295), a second
confirmation.

Four peer-requiring formats, trivial server shape:

```bash
for f in zeek suricata hec generic; do
  FORMAT=$f PROCS="1 2 4" DURATION=15 ./scripts/loadgen-ceiling.sh
done
```

against `target/release/logthing` started with `bind_address = 0.0.0.0:5985`,
`[zeek]`/`[suricata]`/`[hec]` enabled and no sink configured (so
`Default*Handler` runs and the writer/persistence path never executes).

**Config-loading discovery, not in the original brief:** the tracked
`logthing.admin.toml` is loaded by `Config::load()` as a source *after*
`logthing.toml` and overrides matching keys. It sets `bind_address =
"127.0.0.1:9999"`, re-enables `syslog` (privileged port 514, which fails to
bind as a non-root user), and force-disables `zeek`/`suricata`/`hec`. Left in
place, it silently defeated the brief's trivial config and the server
exited within ~13ms of starting (one listener task returning early trips a
`tokio::select!` that shuts every listener down). Fix applied: back up and
`mv` `logthing.admin.toml` out of the way for the duration of Step 3 (not
`rm`), same as `logthing.toml`, then move it back and verify by checksum.
Full detail and exact commands are in
`.superpowers/sdd/2026-09-16-max-ingest-rate/task-2-report.md`.

**Trivial-shape caveat, applies to all four tables below in this section:**
these numbers are an *upper bound on the generator*, not a receiver-free
figure — the server still does socket accept/read and format-parse work for
every record even with no sink configured, so a slower generator number here
could be partly server-depressed rather than purely generator-limited. They
are not directly comparable to the BLACKHOLE=1 numbers above, which have no
server in the loop at all.

## Results

### syslog (UDP, blackhole)

| procs | per-process rate (rec/s) | aggregate rate (rec/s) |
|---|---|---|
| 1 | 56,955.5 | 56,955.5 |
| 2 | 58,735.3, 61,168.4 | 119,903.7 |
| 4 | 44,875.5, 42,341.8, 43,383.6, 44,286.9 | 174,887.8 |

### ipfix (UDP, blackhole)

| procs | per-process rate (flows/s) | aggregate rate (flows/s) |
|---|---|---|
| 1 | 71,990.8 | 71,990.8 |
| 2 | 67,728.9, 76,124.3 | 143,853.2 |
| 4 | 60,108.9, 59,477.1, 59,727.2, 58,981.3 | 238,294.5 |

### sflow (UDP, blackhole)

| procs | per-process rate (rec/s) | aggregate rate (rec/s) |
|---|---|---|
| 1 | 75,814.5 | 75,814.5 |
| 2 | 75,069.2, 79,807.8 | 154,877.0 |
| 4 | 63,900.4, 63,225.2, 63,806.8, 63,116.1 | 254,048.5 |

### zeek (TCP, trivial-shape server — see caveat above)

| procs | per-process rate (rec/s) | aggregate rate (rec/s) |
|---|---|---|
| 1 | 164,698.4 | 164,698.4 |
| 2 | 166,238.2, 161,589.9 | 327,828.1 |
| 4 | 187,274.2, 186,161.7, 184,465.4, 185,891.4 | 743,792.7 |

### suricata (TCP, trivial-shape server — see caveat above)

| procs | per-process rate (rec/s) | aggregate rate (rec/s) |
|---|---|---|
| 1 | 107,626.3 | 107,626.3 |
| 2 | 110,356.2, 109,992.3 | 220,348.5 |
| 4 | 118,897.0, 115,246.5, 116,661.0, 117,981.4 | 468,785.9 |

### hec (HTTP, trivial-shape server — see caveat above)

Generator subcommand `hec-http`, against `[hec]` (no persistence sink).
**`hec` and `generic` are indistinguishable in `logthing`'s own metrics**
(both increment `hec_events_received` and land in a sink labelled
`source="hec"`) — this row is attributable only because it was run alone,
one format at a time.

| procs | per-process rate (rec/s) | aggregate rate (rec/s) |
|---|---|---|
| 1 | 21,845.0 | 21,845.0 |
| 2 | 10,388.5, 10,270.0 | 20,658.5 |
| 4 | 6,356.0, 6,142.7, 6,231.8, 6,227.5 | 24,958.0 |

### generic (HTTP, trivial-shape server — see caveat above)

Generator subcommand `generic-http`, run separately from `hec-http` above
(never concurrently), same reasoning as the `hec` row.

| procs | per-process rate (rec/s) | aggregate rate (rec/s) |
|---|---|---|
| 1 | 22,297.4 | 22,297.4 |
| 2 | 11,149.8, 11,414.7 | 22,564.5 |
| 4 | 6,272.3, 6,416.1, 6,363.9, 6,434.8 | 25,487.1 |

## Gate table

`needs generator work? = yes` only when the 1-process ceiling is within
~20% of the best rate ever achieved against a real sink **and** the
aggregate does not scale with process count. If it scales, the answer is
"no — run N processes," and Tasks 3-5 are skipped for that format.

| format | generator ceiling (1 proc) | aggregate at 4 procs | scales? | highest achieved rate seen against a real sink | needs generator work? |
|---|---|---|---|---|---|
| syslog | 56,955.5/s | 174,887.8/s (3.07x) | yes (sub-linear but clearly rising, not flat) | no prior figure — not measured in any committed doc | no — run N processes |
| ipfix | 71,990.8/s | 238,294.5/s (3.31x) | yes | 29,118/s unbounded (`2026-09-13-multiformat-load-results.md` §2) | no — run N processes (1-proc ceiling is ~2.5x the prior real-sink figure, nowhere near the ~20% band, and it scales) |
| sflow | 75,814.5/s | 254,048.5/s (3.35x) | yes | no prior figure — not measured in any committed doc | no — run N processes |
| zeek | 164,698.4/s | 743,792.7/s (4.52x) | yes | 15,283/s against a 20,000/s target (`2026-09-13-multiformat-load-results.md` §2) | no — run N processes (1-proc ceiling is ~10.8x the prior real-sink figure and it scales super-linearly) |
| suricata | 107,626.3/s | 468,785.9/s (4.36x) | yes | no prior figure — not measured in any committed doc | no — run N processes |
| hec | 21,845.0/s | 24,958.0/s (1.14x) | no — flat, per-process rate collapses as procs increase | no prior figure — not measured in any committed doc | yes — Task 4 (`--events-per-request`): the measured ceiling is in requests/s, not records/s; batching is what converts it to a records/s figure |
| generic | 22,297.4/s | 25,487.1/s (1.14x) | no — flat, per-process rate collapses as procs increase | no prior figure — not measured in any committed doc | yes — Task 4 (`--events-per-request`): same reasoning as hec |

**Note on hec/generic (revised — see fix round 1):** these are the only two
formats where the aggregate does not scale with process count — a textbook
downstream-bottleneck signature (flat aggregate, per-process rate falling in
inverse proportion to process count). That satisfies the gate's second
condition literally. But the gate's "scales with process count?" question
implicitly assumes the generator is already sending records at whatever rate
the wire protocol allows, and for these two formats that assumption does not
hold: `hec-http` and `generic-http` each send **one HTTP request per single
event**. A flat ceiling of ~21-25k/s is therefore a ceiling in *requests* per
second, and requests/s is not the quantity this plan exists to measure —
records/s is. `parse_hec_event_body` and `parse_ndjson_body`
(`src/ingest/parse.rs`) already split each request body on newlines, i.e.
the wire protocol accepts many records per request; the generator simply
never exercises that. Separately, this repo's committed criterion benches
put the generic/hec per-record parse+handle cost at roughly 2.6
microseconds — around 385k records/s single-threaded, about 17x above what
was measured here — which is consistent with the ~22k/s figure being a
per-transaction (accept/parse-HTTP-headers/respond) cost rather than a
per-record cost.

**The original version of this note claimed the bottleneck was already
downstream of the generator and that a faster generator could not move the
number. That sentence has been struck: nothing in this run tested it.**
There are two live, competing hypotheses this run cannot distinguish:

1. **Per-transaction HTTP overhead dominates.** The ~22k/s ceiling is a
   request-handling cost (accept, parse headers, single-event JSON parse,
   respond), and batching multiple events into each request would raise the
   records/s ceiling substantially — plausibly toward the same 107k-743k/s
   range the five persistent-socket formats reach.
2. **The server is genuinely saturated for this ingest path regardless of
   batching** (e.g. some other per-request cost, like TLS/keep-alive
   handling or a shared lock, that survives batching).

The only way to tell these apart is to run the generator with several events
per request and see whether the aggregate records/s rises. That is exactly
Task 4's `--events-per-request` work. **Needs generator work? Yes** for both
rows, on that basis — not on the struck causal claim. If batching does
*not* move the record rate once measured, that outcome is itself the
finding (HTTP ingest is request-bound end to end, not generator-bound), so
Task 4 is worth running either way: it either unlocks a materially higher
ceiling or converts an assumption into a confirmed result.

## What this run overturns / confirms

`docs/performance/2026-09-13-multiformat-load-results.md` §2 claimed:
> **The generator, not the server, is the limit above ~15k/s** [for Zeek].
> Asked for 20,000/s it achieved 15,283/s. We did not find the server's TCP
> ceiling, so nothing on this page should be read as one.

**This run overturns that claim.** The same `tools/loadgen` `zeek-tcp`
subcommand, run against a trivial (no-sink) receiver on this same host,
sustains 164,698/s from a single process and 743,793/s from four — an order
of magnitude above the ~15k/s figure previously attributed to the generator.
The 2026-09-13 measurement was against a real S3+local-disk Parquet sink in
a docker-compose environment; today's number is against a receiver doing
only socket accept + NDJSON parse, no persistence. The ~15k/s ceiling seen
in September was real, but it was **never a generator ceiling** — the
generator has ~10x more headroom than that page attributed to it. Whatever
capped Zeek at ~15,283/s in the earlier run (the real Parquet/S3 writer
path, the docker-compose environment, or the older harness/loadgen
implementation available at that commit — this run does not distinguish
between those) is downstream of the generator, not the generator itself.
This also means Task 2's own finding is consistent for every other
socket-based format measured today: all five TCP/UDP formats that show
clean scaling (syslog, ipfix, sflow, zeek, suricata) have generator ceilings
far above any rate this codebase has ever sustained against a real sink —
none of them are generator-bound, and no generator-optimisation task is
justified by this data for those five. `hec` and `generic` are the
exception (see the revised gate-table note above): their flat ceiling is a
requests/s ceiling from one-event-per-request HTTP, not a demonstrated
records/s limit, so Task 4's batching work is gated *on* for those two,
pending the run that would actually distinguish per-transaction overhead
from genuine server saturation.
