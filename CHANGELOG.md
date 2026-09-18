# Changelog

All notable changes to this project are documented in this file, newest
first, loosely following [Keep a Changelog](https://keepachangelog.com/).
This file starts at 0.15.0; earlier releases are not backfilled.

## [Unreleased]

### Added

- `scripts/max-ingest-rate.sh` — per-format maximum sustainable ingest rate
  harness: restarts `logthing` between runs, reconciles kernel-socket drops
  against `/proc/net/udp` (per-listener, not host-wide), and does a coarse
  doubling + bisection search to the first rate whose median loss (across
  `RUNS` repeats) exceeds a configurable loss budget, refusing to report a
  ceiling when the generator itself can't sustain the offered rate.
- `scripts/loadgen-ceiling.sh` — measures the load generator's own maximum
  emission rate (`BLACKHOLE=1`, no receiver) across 1/2/4 concurrent
  processes, independent of any server, so a generator ceiling is never
  mistaken for a server one.

### Changed

- `loadgen`'s `hec-http` and `generic-http` subcommands gained
  `--events-per-request`, batching that many NDJSON/HEC events per HTTP
  request instead of one event per request. Without it, both generators were
  measuring HTTP request rate, not record rate — a flat ~21,000-25,000/s
  ceiling regardless of process count, versus a ~385k records/s single-
  threaded per-record decode cost. Batched at 100 events/request, measured
  ceilings for both formats rose 7-9x (see
  `docs/performance/2026-09-18-max-ingest-rate.md`).

### Removed

- `scripts/repeat-ipfix-loopback-loss.sh` — replaced by
  `scripts/max-ingest-rate.sh`, which generalizes the same restart-per-run,
  zeroed-counter, kernel-drop-reconciling approach across all seven formats
  and drops two defects: a `pkill -f` that could kill the invoking shell
  instead of the server, and a cleanup step that deleted the tracked
  `logthing.admin.toml`.

## [0.19.1] - 2026-09-16

### Changed

- `/stats/throughput` and the admin dashboard now count real rows ingested
  per source, not the number of writer `push()` calls. Previously,
  `source_stats.record` hardcoded a count of 1 per push regardless of how
  many rows that push contributed. For every sink whose `Record` is exactly
  one row (Zeek, Suricata, syslog, WEF, sFlow) push count and row count are
  the same, so this changes nothing for them. **IPFIX is affected**: its
  `Record` is `Vec<FlowRecord>`, one push per UDP datagram, commonly
  carrying 10+ flows and sometimes hundreds — its counted rate was
  previously the datagram rate, and is now the flow rate, a step change of
  up to two orders of magnitude on the same graph. A push with zero rows
  (a template-only IPFIX datagram) now correctly records nothing, rather
  than being counted as one event. **Any dashboard or alert keyed to the
  old IPFIX throughput number will show a step change after upgrading** —
  the new number is the correct one; recalibrate thresholds rather than
  reverting.

### Fixed

- `SFLOW_RECORD_BYTES` was a 4.17x undercount, so sFlow's channel was sized
  against a per-record footprint that only holds for curated samples.
  `size_of::<SflowRecord>()` really is 256 bytes and a record with an empty
  `extra` measures exactly that — but the decoder curates only
  `raw_packet_header`, `sampled_ipv4`/`ipv6` and `generic_if_counters`, and
  pushes every other record format into `extra` verbatim. That includes
  `extended_switch` (VLAN tag/priority), which is near-universal on
  switch-sourced flow samples. Measured through the real decoder against a
  counting allocator, such a record is **1,068 bytes**. The constant is now
  1280 (rounded to the file's 256-byte convention), so the derived channel
  capacity falls from 409,600 to 81,920 slots — still the deepest of any
  source, but no longer resting on an unrepresentative sample. An
  allocator-validated test now pins the measured footprint so the constant
  cannot silently drift from reality again.

### Documentation

- Added a **Host tuning for UDP ingest** section to the README. The UDP
  listeners request a 4 MiB `SO_RCVBUF`; Linux clamps that to
  `net.core.rmem_max`, whose stock value of 212992 bytes is ~20x smaller.
  logthing already detects this and warns naming the sysctl, but the
  requirement was documented only in internal performance notes. At 40,000
  syslog messages/s against the stock limit, ~16.8% of datagrams are lost in
  the kernel socket with **zero** drops recorded inside logthing — correctly,
  because those messages never arrived. Watch `syslog_socket_drops` and
  `syslog_socket_rx_queue_bytes`, not `parquet_s3_dropped`.

## [0.19.0] - 2026-09-15

### Performance

- Every `ParquetSink` now appends into long-lived Arrow builders via a
  `RecordBatchAccumulator` instead of allocating a fresh builder set per
  record. Previously only Zeek's `conn` schema did. Measured on a quiet
  12-vCPU host, 30s runs at 40,000 records/s offered, all at **0.00% channel
  error rate** where the pre-change figures are per-sink saturation:

  | sink | before | after |
  |---|---|---|
  | IPFIX | ~3,400 eps, 82% loss | 39,968 eps, 0% |
  | Zeek `dns` | ~5,700 eps (throttled) | 40,000 eps, 0% |
  | Zeek `http` | ~6,800 eps (throttled) | 39,997 eps, 0% |
  | Suricata | 9,100 eps (throttled) | 38,613 eps, 0% |
  | sFlow | ~65% loss at 40k samples/s | 79,984 samples/s, 0% |
  | syslog | 13-16% channel drops | 0% channel drops |

  No sink is the measured bottleneck any more — the load generator is, so
  these are floors rather than ceilings. Zeek `conn`, already converted,
  was unchanged and served as the control: same transport, backpressure and
  writer, differing only in whether the schema had an accumulator.

- **No measurable change for HEC/OTLP/generic**, which share one
  `ParquetWriterHandle<GenericSink>`. At saturation, before 44.4%/48.0% vs
  after 45.1%/49.8% — indistinguishable. Its mapper is the cheapest in the
  repo (4.13us/record), so there was little allocation to remove, and at
  high concurrency the CPU goes to HTTP framing and JSON parsing on the
  ingest side. Landed for consistency, not throughput.

### Fixed

- The buffered writer's flush threshold used `RecordBatch::get_array_memory_size()`,
  which reports allocated **capacity** rather than bytes used. A 1-row IPFIX
  batch reported 94,080 bytes against 109 real — an ~860x overstatement that
  made every sink but Zeek flush one to two orders of magnitude earlier than
  configured. Now uses `ArrayData::get_slice_memory_size()`, which is
  slice-aware and recurses into child data. Kernel-level UDP loss fell from
  4.32% to 0.03% median as a side effect.
- `push()` hardcoded a row count of 1 when a record was accepted into an
  accumulator. Correct for one-row records, wrong for any multi-row `Record`
  (e.g. `IpfixSink::Record = Vec<FlowRecord>`, one push per datagram), where
  it corrupted the `max_rows` flush trigger, the `BUILDER_BATCH_ROWS`
  materialize check and `drop_oldest_to_cap`'s eviction loop. Now derived
  from the accumulator's `len()` delta.
- A deployment with only HTTP ingest enabled (HEC/WEF/OTLP/generic, no
  wire-protocol listener) started and then shut itself down within
  milliseconds, logging nothing. `main.rs`'s listener-supervision `select!`
  arm polled a `FuturesUnordered` built from the wire-protocol listener
  handles only; with none configured that set is empty and resolves
  immediately, so the arm won its first poll and fell through into the
  graceful-shutdown sequence. The supervision future now pends forever on an
  empty set, and startup logs explicitly when only HTTP ingest is active.
- `suricata_records_received` and `suricata_records_by_event_type` now appear
  on the metrics endpoint. Both were incremented inside
  `DefaultSuricataHandler`, which is installed only when no Suricata
  forwarding destination is configured, so no real deployment ever emitted
  them. Same defect fixed for Zeek in 0.18.0.

### Added

- `loadgen` gains `sflow-udp`, `hec-http` and `generic-http` subcommands.
  Six of seven wire formats now have generators; only OTLP remains. Each is
  integration-tested against logthing's own decoder/handler, so a generator
  whose payloads were silently rejected cannot produce a false zero-loss
  measurement.

### Changed

- `RecordBatchAccumulator::try_append` now takes a `now:
  DateTime<Utc>` argument, threaded from `push()`'s single per-push clock
  read. This is load-bearing for correctness, not ergonomics: IPFIX
  `export_time` arrives on unauthenticated, spoofable UDP and `FlowRecord`
  carries no receipt instant, so `partition_time` must clamp it against a
  trusted clock. An accumulator calling `Utc::now()` itself would reopen the
  two-reads-either-side-of-midnight race that `push()`'s single read exists
  to close, and binding the clock at construction is worse still, since a
  long-lived accumulator would stamp post-midnight rows with a stale day
  that disagrees with their buffer key.

### Known issues

- With byte accounting corrected, the configured `flush_interval_secs`
  (default 900 for every sink) is now actually honoured. Graceful shutdown
  still flushes, so restarts and deploys lose nothing, but an **ungraceful**
  loss (SIGKILL, OOM, power) now discards up to 15 minutes of buffered
  records where the accounting bug previously forced a flush every few
  seconds. Operators with a tighter recovery-point objective should set
  `flush_interval_secs` explicitly.
- syslog now loses ~16.8% of datagrams in the kernel UDP socket at 40,000/s.
  This is upstream of the writer (channel drops are 0) and is unaffected by
  the work above; it is now syslog's binding constraint.
## [0.18.0] - 2026-09-10

### Fixed

- `zeek_records_received` and `zeek_records_by_path` now appear on the
  metrics endpoint. Both counters were incremented inside
  `DefaultZeekHandler`, which is installed only when **no** Zeek forwarding
  destination is configured — so any deployment with `[zeek.s3]` or
  `[zeek.local]` set never emitted them at all. They now fire in the
  listener's parse loop, which every handler routes through.

### Changed

- The `log_path` label on `zeek_records_by_path` is now drawn from the set
  of modelled Zeek streams (`conn`, `dns`, `http`, `ssl`, `files`,
  `notice`), with anything else collapsing to `other`. The label value comes
  from the wire-supplied `_path` field, which is unbounded in length and
  charset; emitted raw it would let any client that can reach the Zeek
  listener mint a new permanent Prometheus series per record. Parquet
  partitioning still uses the full normalised `_path`, so no stored data
  changes — only the metric label is bucketed. A stream without a schema
  entry is no longer separable on this metric.

## [0.17.0] - 2026-09-07

### Changed

- `security.allowed_ips` now also filters the syslog (UDP + TCP), IPFIX,
  sFlow, Zeek, and Suricata socket listeners — previously it only gated the
  HTTP endpoints. **This is a behaviour change for any deployment that
  already sets `allowed_ips`**: traffic from sources outside the list that
  was previously accepted on those five listeners is now silently dropped.
  Deployments that leave `allowed_ips` at its default (empty = allow all)
  see no change.
- A rejected source now increments the `listener_source_rejected` counter,
  labeled `protocol` with one of `syslog_udp`, `syslog_tcp`, `ipfix`,
  `sflow`, `zeek`, or `suricata`, so a misconfigured allowlist is visible in
  metrics rather than only in debug/warn logs.
- `security.kerberos` (feature `kerberos-auth`) now performs real RFC 4559
  SPNEGO/GSSAPI validation instead of the previous fail-closed stub.
  **Behaviour change**: previously, enabling `security.kerberos` rejected
  *every* request — 401 for a missing token, 501 for any `Negotiate` token,
  because validation was never implemented. It now actually authenticates
  clients holding a valid Kerberos ticket for the configured SPN. Only
  two-pass SPNEGO is supported; NTLM-style multi-leg negotiation is not (see
  README).
- Replaced the LGPL-3.0-or-later `axum-negotiate` dependency (unused dead
  weight, and incompatible with this crate's MIT licence for static-linked
  release binaries) with MIT-licensed `libgssapi` for Kerberos SPNEGO
  support.

### Added

- A startup warning is now logged when `hec.enabled = true` and `hec.token`
  is left empty — that combination accepts any (or no) `Authorization`
  header on the HEC ingest routes, which is only intended for local dev.
- The same warning now also covers `otlp.enabled = true` (feature `otlp`)
  with an empty or unset `otlp.bearer_token` — that combination accepts any
  (or no) `Authorization` header on `/v1/logs`.
- `syslog.http_token` (optional, empty by default): when set, the `/syslog`
  HTTP route requires `Authorization: Bearer <token>`, checked the same
  constant-time way as the OTLP/HEC bearer tokens. Empty (the default)
  preserves the existing no-auth behaviour, since `/syslog` is mounted
  unconditionally regardless of `syslog.enabled`.

### Fixed

- **SIGTERM is now handled.** The process previously installed a handler only
  for SIGINT, so the graceful-shutdown sequence — drain the listeners, flush
  every buffered Parquet writer — ran on Ctrl+C but never on SIGTERM. Since
  the container runs the binary as PID 1, where the kernel discards signals
  with no handler installed, `kubectl delete pod` and `docker stop` left the
  process running until the grace period expired and SIGKILL landed. Every
  record buffered since the last periodic flush was lost on each restart.
  Deployments relying on `flush_interval_secs` to bound data loss were losing
  up to one full flush interval per pod termination.
- **An early listener exit no longer panics the process.** If any of the five
  socket listeners stopped before the shutdown signal — most commonly a bind
  failure from a port collision — the supervision arm and the shutdown drain
  both awaited the same `JoinHandle`, and the second await panicked with
  "JoinHandle polled after completion". A single recoverable listener failure
  therefore killed the whole process mid-shutdown, skipping the writer flush.

## [0.16.0] - 2026-09-06

### BREAKING

Every one of the nine Parquet sinks (Zeek's 7 schemas, Suricata, syslog,
structured syslog, generic/HEC, sFlow's 2 schemas, IPFIX, WEF, and
aggregate) gained a new column, so `schema_version()` — the hash
`iceberg_descriptor` writes into each descriptor sidecar — changes for
every sink simultaneously.

**Migration, required before deploying**: downstream Iceberg tables need
the new `partition_time` column added, and their `day()`/`hours()`
partition transform re-declared against `partition_time` instead of
whatever column it was previously declared on (`ts`, `flow_start`,
`export_time`, etc. — all of them nullable on at least one sink, none of
them safe as a partition source). Do this **before** the new binary starts
writing: a file written against a stale partition spec, once it contains a
null in the old partition column, cannot be registered into the table.

### Added

- `partition_time` — `Timestamp(Microsecond, UTC)`, non-null, appended as
  the last column of every sink's schema. It holds the exact instant that
  file's partition day was derived from: the record's own event timestamp
  when present and within `[received_at - 30 days, received_at + 1 day]`,
  otherwise the receipt instant. This is the column to declare an Iceberg
  `day()`/`hours()` transform against — the sink-specific time columns it
  replaces for this purpose are nullable on several sinks, and a nullable
  partition source can put two partition values (`{date, null}`) in one
  data file, which Iceberg refuses to register.
- Syslog's schema gained a non-null `received_at` column (it was the only
  one of the nine sinks without one).

### Changed

- Write buffers are now keyed by `(partition, UTC day)` instead of just
  `partition`, so a buffer that would previously have spanned UTC midnight
  now flushes as two Parquet files, one per day. Previously, a buffer
  filling across midnight produced a file whose rows straddled two
  partition days — unregisterable into Iceberg — roughly once per active
  partition per day.
- Event timestamps more than 30 days before receipt, or more than 1 day
  after it, are now bucketed by receipt time rather than event time. The
  record is not dropped and the event timestamp is not lost — it remains
  queryable in its own column — but the file it lands in partitions by
  ingest day, not event day. This bounds how many live write buffers (and
  small Parquet/descriptor uploads) an untrusted, arbitrary-date sender can
  mint. The bounds are the `MAX_BACKFILL` (30 days) and `MAX_SKEW` (1 day)
  constants in `src/forwarding/buffered_writer.rs`, next to the
  `partition_time()` function that applies them — widen them there if a
  deeper backfill window matters more than the fan-out bound.

## [0.15.0] - 2026-09-04

### BREAKING

Every timestamp column across every Parquet sink is now
`Timestamp(Microsecond, Some("UTC"))`. Previously the types were
inconsistent across sinks:

- Zeek's `ts` (all 7 schemas) was `Float64` epoch seconds.
- `syslog_s3.rs` `timestamp`; `structured_syslog_s3.rs` `timestamp` and
  `received_at`; `suricata/schema.rs` `received_at`; `sflow_s3.rs`
  `received_at` (both schemas); `ipfix_s3.rs` `export_time`, `flow_start`,
  `flow_end`; `zeek/schema.rs` `ingest_time`; and `parquet_s3.rs` (WEF)
  `timestamp` were all `Utf8` RFC 3339 strings.
- `generic_s3.rs` (HEC) `time` and `received_at` were
  `Timestamp(Millisecond, UTC)`.
- `forwarding/aggregate/mod.rs` `window_start`/`window_end` were already
  `Timestamp(Microsecond, UTC)` and are unchanged.

This is a breaking change for any reader pinned to the old column types.
Existing Parquet files are immutable and unaffected — only newly written
files use the new types.
