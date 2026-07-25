# `loadgen <subcommand>` Baseline Methodology Template

Copy this file to `docs/performance/<date>-<format>-baseline-results.md` when capturing a new
baseline run, and fill in every section. Do not omit a section — write "not applicable, because
X" rather than deleting it, so future readers can tell "not measured" from "measured as zero."

## 1. What was run

- **Format / subcommand:** e.g. `loadgen syslog-udp`
- **Git commit hash** (of `logthing`, at the time of the run):
- **`logthing` build profile:** `[profile.profiling]` (default for perf runs — real optimized
  code, `debug=true` for later `perf`/flamegraph correlation if needed)
- **Persistence target:** `LocalDiskSink` (default per
  `docs/superpowers/specs/2026-07-05-performance-testing-strategy-design.md` §6 — do not use
  MinIO/S3 for throughput/latency/drop-rate numbers; MinIO is reserved for a separate, narrower
  sanity pass)
- **Exact config file used** (paste the whole file, or link to it if checked in)
- **Buffer-policy values in effect** (per the "never compare across differing flush-threshold
  configs" rule — restate these explicitly every time, even if unchanged from a prior run):
  `max_buffer_rows`, `flush_threshold_bytes`, `flush_interval_secs`, `channel_capacity`
  Note: some local sinks hardcode this to `usize::MAX` (no byte-size trigger at all, e.g.
  syslog's `syslog_local_start()` in `src/forwarding/syslog_s3.rs`) — verify against the sink's
  actual `*_local_start` function before assuming the generic `BufferedWriterConfig` default of
  128 MiB applies; see `docs/performance/2026-07-24-syslog-udp-baseline-results.md` for a worked
  example of this exact correction.
- **Exact commands run** (verbatim, including every flag)

## 2. Goals & metrics captured

Per the design doc §4 — for each rate point in the sweep, capture:

| Metric | Source | Value (before) | Value (after) | Delta / rate |
|---|---|---:|---:|---:|
| Ingest accept rate | `<format>_messages_received` or equivalent, `:9090/metrics` | | | |
| Durable write rate | `parquet_s3_records_written{source,target}` | | | |
| Channel-full drops | `parquet_s3_dropped{source,target}` | | | |
| Hard-cap drops | `parquet_s3_buffer_dropped{source,target}` | | | |
| Partition-cap hits | `parquet_s3_partitions_capped{source,target}` | | | |
| Parse/decode errors | format-specific, e.g. `syslog_parse_errors` | | | |

- **Ingest→flush latency:** not directly instrumented server-side (per design doc §4 point 3) —
  either measured externally (sequence-number-in-record, diffed against Parquet-file read-back
  timestamp) or explicitly marked "not measured this run."
- **Resource usage:** RSS/CPU sampled via `ps -o pid,rss,pcpu,etime -p <pid>` (or `cargo
  flamegraph --profile profiling` for CPU-by-function, if a flamegraph was captured).

## 3. Comparability notes

Per the design doc §7 — if this run is being compared against another format's baseline:
- Same architecture group? (single-partition non-JSON / high-cardinality JSON-line /
  HTTP-JSON shared-writer-path / UDP binary low-cardinality)
- Same buffer-policy config? If not, say so explicitly rather than presenting a bare
  records/sec comparison.
- Both "accept rate" and "durable write rate" reported, not just one?
- Normalized by bytes as well as record count, if record sizes differ meaningfully?

## 4. Results

(Table or prose, one row/paragraph per rate point in the sweep.)

## 5. Honest read

State plainly whether the result shows a clear signal or is within noise/measurement error. Do
not round up a marginal or ambiguous result into a confident claim.
