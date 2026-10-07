# Performance

Single-node ingest ceilings measured with `scripts/max-ingest-rate.sh` and `tools/loadgen`.
These are measurements on one machine under the stated conditions, not guarantees.

## Results

Measured 2026-10-07 at commit `bf74d3c` (version 0.21.0), release build, 12 vCPU host
shared with another project's workloads (see [Hardware and load](#hardware-and-load)).
Ceilings are in records per second (one HEC event or one OTLP log record is one record).
Every row used batches of 100 records per request, concurrency 64, a PII-shaped payload
(`PII_FIELDS=1`, so payload size is identical with and without redaction), and the local
Parquet sink flushing every 5 s.

| Route | gzip | Redaction | Ceiling (records/s) | Verdict | 503 responses at last passing rate / first failing rate |
|---|---|---|---|---|---|
| HEC `/services/collector/event` | no | none | 85625 (pass 2); 80625 (pass 1) | CEILING | 0 / 504 (pass 2); 0 / 635 (pass 1) |
| HEC `/services/collector/event` | no | drop + hash + mask | 79375 (pass 2); 80000 (pass 1); -7.3% / -0.8% vs the row above | CEILING | 462 / 1456 (pass 2); 61 / 1198 (pass 1) |
| HEC `/services/collector/event` | yes | none | 78125 | CEILING | 428 / 504 |
| HEC `/services/collector/event` | yes | drop + hash + mask | 75000 (`GEN_PROCS=2`); -4.0% vs the row above | CEILING | 520 / 1047 |
| OTLP `/v1/logs` | yes | none | 10625 | CEILING | 166 / 244 |
| OTLP `/v1/logs` | yes | drop + hash + mask | 10000; -5.9% vs the row above | CEILING | 64 / 30 |

Notes on reading the table:

- "503 responses" is the harness's `503 total:` line for that rate: how many backpressure
  responses the generator saw (and retried) across the 3 runs. A ceiling can legitimately
  have 503s at the last passing rate, because retried requests still land within the loss budget.
- The two HEC no-gzip rows were measured twice. Pass 1 ran while the host's 1-minute load
  average peaked at 167 (row 1) and 24 (row 2); pass 2 peaked at 77 and 12. Same configuration,
  same binary: 80625 versus 85625 records/s for the no-redaction row is a 6% spread from
  run to run. **The redaction deltas above (-0.8% to -7.3%) are inside that spread, so these
  measurements do not establish a redaction cost.** They show only that redaction did not
  make the ceiling collapse.
- Row 4 (gzip + redaction) with the default single generator process ended
  `GENERATOR-LIMITED 40000` (achieved 39283 of 40000 in the failing runs). Per the
  harness rules it was rerun with `GEN_PROCS=2`, which gave the `CEILING 75000` shown.
  Rows 1-3 used the default single generator process.
- OTLP ceilings are about one eighth of the HEC ceilings in this environment. During the
  OTLP ceiling runs the harness reported the generator at about 0.25 cores and the server at
  about 1.7-2.0 of its 8 cores, i.e. neither side was CPU-saturated. This document reports
  the measurement and does not attribute a cause.

## Method

`scripts/max-ingest-rate.sh` ramps the offered rate (5000, 10000, 20000, ... up to
`RAMP_MAX`, default 500000) and then bisects between the last passing and first failing
rate down to `BISECT_RESOLUTION` (default 1000 records/s). At each rate it:

1. Starts a fresh `logthing` release binary (restarted between every run) with a generated
   `logthing.toml`: the HEC or OTLP listener enabled and a local-disk Parquet sink with
   `flush_interval_secs = 5` (the "real" shape: the production write path, no S3).
2. Runs `RUNS` (3 here) timed runs of `DURATION` (15 s here; the harness minimum is 10)
   with `tools/loadgen` over loopback.
3. Compares records written against records offered. A rate **passes** when the median
   total loss is at most `LOSS_BUDGET` (0.1%) and the median achieved rate is at least 99%
   of the target. If the generator fell short of 99% and saw no 503s, the verdict is
   `GENERATOR-LIMITED` (not a server ceiling). If it fell short and did see 503s, the verdict
   is `FAIL-BACKPRESSURE`: the server pushed back, which is a real ceiling.

The generator retries 503 responses according to `Retry-After`; requests it gives up on are
counted as "abandoned" and reported per run. Loss is computed against records actually
offered, floored at 0 (a retried request after a partial enqueue duplicates the enqueued
prefix, see [hec.md](hec.md#backpressure)).

Redaction rows add this rule set, verbatim from the harness, to the listener's config:

```toml
[hec.redaction]            # [otlp.redaction] for OTLP rows
drop_fields   = ["password", "headers.authorization"]
hash_fields   = ["user.email"]
hash_key_env  = "LOGTHING_HASH_KEY"
mask_patterns = ['\b\d{3}-\d{2}-\d{4}\b', 'secret=\w+']
```

Cores are partitioned so the generator and the server never share a core: generator on
CPUs 0-3 (`GEN_CPUS`), server on CPUs 4-11 (`SRV_CPUS`), the harness defaults for 12 vCPUs.

Command lines (one per row; `FORMAT`, `GZIP`, `REDACTION` as in the table):

```bash
FORMAT=hec  GZIP=0 PII_FIELDS=1 REDACTION=0 EVENTS_PER_REQUEST=100 DURATION=15 RUNS=3 scripts/max-ingest-rate.sh
FORMAT=hec  GZIP=0 PII_FIELDS=1 REDACTION=1 EVENTS_PER_REQUEST=100 DURATION=15 RUNS=3 scripts/max-ingest-rate.sh
FORMAT=hec  GZIP=1 PII_FIELDS=1 REDACTION=0 EVENTS_PER_REQUEST=100 DURATION=15 RUNS=3 scripts/max-ingest-rate.sh
FORMAT=hec  GZIP=1 PII_FIELDS=1 REDACTION=1 EVENTS_PER_REQUEST=100 DURATION=15 RUNS=3 GEN_PROCS=2 scripts/max-ingest-rate.sh
FORMAT=otlp GZIP=1 PII_FIELDS=1 REDACTION=0 EVENTS_PER_REQUEST=100 DURATION=15 RUNS=3 scripts/max-ingest-rate.sh
FORMAT=otlp GZIP=1 PII_FIELDS=1 REDACTION=1 EVENTS_PER_REQUEST=100 DURATION=15 RUNS=3 scripts/max-ingest-rate.sh
```

## Hardware and load

- 12 vCPUs (`nproc` = 12; "QEMU Virtual CPU version 2.5+", 1 socket x 12 cores, 1 thread
  per core), 61 GiB RAM, Linux 6.12.94 (Debian 13), local disk.
- Shared host: a different project ran builds and database-backed test suites (Postgres,
  kube-apiserver, dockerd) at the same time. The harness was only started when the 1-minute
  load average was 6 or lower, but load during a run was not controlled. 1-minute load
  average at start of the run, and minimum/maximum sampled every 30 s during it:

| Row | Load at start | Load during (min / max) |
|---|---|---|
| 1, pass 1 | 5.71 | 4.63 / 167.02 |
| 1, pass 2 | 5.86 | 1.88 / 77.04 |
| 2, pass 1 | 5.93 | 2.91 / 24.26 |
| 2, pass 2 | 5.62 | 3.88 / 11.61 |
| 3 | 5.92 | 3.82 / 9.03 |
| 4, pass 1 (generator-limited, superseded) | 5.53 | 3.97 / 6.10 |
| 4, pass 2 (`GEN_PROCS=2`) | 3.94 | 1.72 / 13.87 |
| 5 | 5.01 | 3.24 / 6.40 |
| 6 | 5.23 | 2.96 / 6.21 |

## Caveats

- Shared, at times heavily loaded host: the numbers are noisy lower bounds. Rows 1 and 2
  in particular saw large load excursions. Repeat on your own hardware.
- Single node, loopback: no NIC, TLS or load balancer cost.
- Local-disk sink, not S3: S3 latency and the spool are not in the path.
- Synthetic records: the generator's payload size and shape determine the rate; I did not
  measure per-record bytes, so no bytes/s figure is given.
- A ceiling is the highest rate with at most 0.1% loss and at least 99% of the target
  achieved, bisected to 1000 records/s. Pass/fail near the ceiling is not monotonic (the
  server restarts and the host is shared), so treat the last ~5% below a ceiling as uncertain.
- A 503 retried after a partial enqueue duplicates the enqueued prefix (see
  [hec.md](hec.md#backpressure)); the harness floors loss at 0.
- Other formats: the harness also supports `FORMAT=syslog|ipfix|sflow|zeek|suricata`
  (UDP/TCP). This document reports only the HTTP routes measured in this release.

## Reproducing

```bash
cargo build --release --bin logthing && cargo build --release -p loadgen
FORMAT=hec GZIP=1 PII_FIELDS=1 REDACTION=0 EVENTS_PER_REQUEST=100 DURATION=15 RUNS=3 \
  scripts/max-ingest-rate.sh
```

| Variable | Meaning |
|---|---|
| `FORMAT` | `hec`, `otlp`, `syslog`, `ipfix`, `sflow`, `zeek`, `suricata`, `generic` |
| `GZIP` | `1` gzip-compresses request bodies (HTTP formats except `generic`) |
| `PII_FIELDS` | `1` adds the PII-shaped fields to each record |
| `REDACTION` | `1` enables the redaction rule set above (implies `PII_FIELDS=1`; HTTP formats only) |
| `EVENTS_PER_REQUEST` | records per HTTP request (default 1) |
| `CONCURRENCY` | concurrent HTTP requests (default 64) |
| `GEN_PROCS` | generator processes, all pinned to `GEN_CPUS` (default 1) |
| `GEN_CPUS` / `SRV_CPUS` | disjoint cpusets for generator and server (defaults 0-3 / 4-11) |
| `RUNS` / `DURATION` | runs per rate (default 5) / seconds per run (default 15, minimum 10) |
| `RAMP_MAX` | highest rate the ramp tries (default 500000) |
| `LOSS_BUDGET` | maximum median loss percent for a pass (default 0.1) |
| `RATE` | set to skip the ramp and test a single fixed rate |

The harness rewrites `logthing.toml` in the repo root while it runs and restores it on exit.
