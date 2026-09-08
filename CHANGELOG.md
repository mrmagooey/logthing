# Changelog

All notable changes to this project are documented in this file, newest
first, loosely following [Keep a Changelog](https://keepachangelog.com/).
This file starts at 0.15.0; earlier releases are not backfilled.

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
