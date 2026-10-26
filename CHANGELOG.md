# Changelog

All notable changes to this project are documented in this file, newest
first, loosely following [Keep a Changelog](https://keepachangelog.com/).
This file starts at 0.15.0; earlier releases are not backfilled.

## [Unreleased]

### Changed

- CI: `performance.yml` (full criterion run + loadgen syslog-udp baseline) now also runs on every
  `v*` tag push, using the manual-run defaults (10000 rec/s for 60 s). Results are artifacts only;
  the run does not gate the release.

## [0.26.0] - 2026-10-26

### Added

- `scripts/profile-ingest.sh`: per-format CPU flame graphs of the ingest path (syslog, zeek,
  suricata, ipfix, sflow, hec, generic, otlp, wef) with a PASS/FAIL summary per format; replaces
  `profile-syslog-udp.sh` and `profile-ipfix-udp.sh`. `loadgen wef-http` drives WEF over HTTP.

### Changed

- Fewer allocations on the hot ingest paths: HEC moves `event`/`fields` out of the envelope instead
  of cloning them, the syslog payload dispatcher moves rather than clones each message, Zeek and
  Suricata read each field in a single pass with a reused payload buffer, and RFC 3164 syslog
  timestamps and tags use a hand-written parser instead of a regex (about 8x faster per message).
  Output is unchanged.
- Coverage moves from cargo-tarpaulin to cargo-llvm-cov (`scripts/run_coverage.sh`).
- Analytics stack default image pins move to 0.26.0 for both logthing and the committer (still in
  lockstep); Helm chart version 0.2.6.
- The static musl release binaries (linux/amd64, linux/arm64) now use jemalloc as the global
  allocator (`allocator=jemalloc` is logged at startup); `--features jemalloc` enables it on gnu
  self-builds. The container image (glibc) is unchanged. `binaries.yml` fails the job if a musl
  binary does not contain jemalloc's embedded strings.
  The binary ships a tuned `malloc_conf` (`background_thread`, 1 s dirty/muzzy decay) that
  `_RJEM_MALLOC_CONF` overrides at runtime.

## [0.25.0] - 2026-10-24

### Added

- Event filter: `[[filter.rules]]` drops whole events that match field rules (equals, any-of list
  or regex, ANDed within a rule) on all eight sources before they are enqueued, redacted or
  aggregated. Filtered events are acknowledged; `events_filtered{source,rule}` counts them. See
  `docs/filter.md`.

### Changed

- Analytics stack default image pins move to 0.25.0 for both logthing and the committer (still in
  lockstep); Helm chart version 0.2.5.
- CI now builds, tests and lints `tools/loadgen`, whose OTLP tests had stopped compiling after
  0.23.1's OTLP limits and no-sink 503; those tests are repaired.

## [0.24.0] - 2026-10-18

### Fixed

- Analytics: `ocsf_authentication` reads the WEF logon fields from `parsed.data` instead of
  regex-extracting them from `raw_xml`. Rows written before 0.23.0 (no `parsed.data`) now yield
  NULL for those fields.
- WEF: the channel budget now counts the parsed EventData map, so per-channel capacity drops from
  8533 to 6400 events.
- Metrics: the `/metrics` HELP text for `wef_xml_parse_errors`, `zeek_missing_path` and
  `suricata_missing_event_type` now describes what each counter counts.

### Changed

- Docs: corrected metric names in the example alerts (no `_total` suffix), the Iceberg
  `[iceberg.s3]` example and its `prefix`/`DESC_PREFIX` pairing, WEF `503` and load-balancing
  guidance, `max_buffer_rows` semantics, and list-valued settings, which cannot be set through
  `LOGTHING__*` environment variables.
- Analytics stack default image pins move to 0.24.0 for both logthing and the committer (still in
  lockstep); Helm chart version 0.2.4.

## [0.23.1] - 2026-10-16

### Fixed

- OTLP: a request is rejected with `413` when it holds more than 100,000 log records or its
  heap-weighted size estimate once mapped exceeds 256 MiB (counted in
  `otlp_requests_rejected_too_large`). The estimate is computed from the decoded protobuf before
  any JSON is built, so a request with a huge resource or scope can no longer exhaust memory
  first. An export is no longer acknowledged with `200` when no OTLP sink is configured or a sink
  channel is closed (see Changed), and `otlp_logs_received` now counts only records that were
  enqueued.
- WEF: the bookmark is no longer advanced past events a sink dropped; the request is answered
  `503` so the client re-sends. After Kerberos authentication a non-empty body that is not
  `multipart/encrypted` is refused with `400` (`wef_plaintext_on_kerberos_rejected`), closing a
  protocol-downgrade path.
- Event field extraction: integer fields accept `0x` hexadecimal values (`0x1a4` becomes `420`),
  extracted values are XML-unescaped, and `Data Name='X'` and System tags that carry attributes
  (`<EventID Qualifiers="16384">`) now match.
- Admin UI: the client IP behind a proxy comes from the rightmost `X-Forwarded-For` hop, which
  the client cannot forge; failed logins cost the same work for unknown and known usernames;
  audit-log rotation is serialised; non-Argon2 password hashes are rejected.
- IP allowlists: on a dual-stack `[::]` bind IPv4 peers appear as `::ffff:a.b.c.d` and never
  matched plain IPv4 `allowed_ips` entries, so every IPv4 client was rejected once an allowlist
  was set. Peers are now canonicalised before matching in the HTTP middleware, all listeners and
  the admin UI; existing `::ffff:` entries keep matching.
- Redaction: `drop_fields`/`hash_fields` keys now match case-insensitively; `mask_patterns` also
  cover the HEC `host` and `source` columns and the OTLP `host_name`, `event_name`,
  `severity_text` and `scope_name` columns, and numeric leaves that match a pattern are masked.
  Previously these values passed through unredacted.
- HEC: `time` handling is exact. Epoch milliseconds (>= 1e11) and numeric strings are accepted,
  negative fractions keep a non-negative sub-second part, integer times are converted without
  floating-point rounding, an out-of-range time is stored as NULL, and a leading UTF-8
  byte-order mark on `/services/collector/event` and `/ingest` bodies is ignored.
- Syslog: RFC 5424 structured data is parsed correctly (`-` no longer leaks into the message;
  adjacent elements and `\"`, `\\`, `\]` escapes are honoured; malformed structured data keeps
  the remainder as the message), an RFC 3164 tag must be a single token (so
  `Failed password for root port 22: x` and auditd lines are not split at a colon), and CEF/LEEF
  payloads directly after a 3164 header reach their parsers. Lines with a valid `<PRI>` that
  match neither header format, and lines with a PRI above 191, are kept instead of dropped. A
  line is no longer merged into the next when `\n` decides TCP framing.
- Syslog payloads: LEEF 2.0 headers with a literal tab delimiter keep `|` in attribute data, CEF
  extension keys are recognised only at a key boundary (`msg=a=b src=1.2.3.4` yields
  `msg` = `a=b`), auditd bare tokens without `=` are skipped, and a web access request line of
  `"-"` (for example a 408) parses without method or path.
- IPFIX/NetFlow: post-NAT elements (IEs 225-228) are stored in `extra` and no longer overwrite
  the original address and port tuple; options data sets produce no flow rows
  (`ipfix_options_records_skipped`); template withdrawal (RFC 7011 section 8.1) is honoured;
  flow records decoded before a malformed set are kept; unsigned fields sent wider than declared
  use the low-order bytes; truncated options templates are errors; a message decodes at most
  8192 records (`ipfix_records_capped`).
- sFlow: short `generic_if_counters` records are skipped (`sflow_counter_records_skipped`)
  instead of failing the whole counter sample, IPv4 and IPv6 non-first fragments carry no ports,
  IPv6 extension headers are walked to the real upper-layer protocol, unknown standard counter
  records no longer carry an `enterprise` key, and interface words honour the format bits in
  compact and expanded flow samples.
- Listeners: a dropped shutdown channel is treated as shutdown instead of busy-looping; UDP
  receive loops (syslog, IPFIX, sFlow) back off 10 ms to 1 s on persistent receive errors and
  log at most once per 10 s; Zeek, Suricata and syslog TCP connections are stopped at shutdown
  after dispatching the lines already received, so their writers can finish and flush. An
  unterminated final line is dropped and counted in `zeek_partial_lines_dropped_at_shutdown`,
  `suricata_partial_lines_dropped_at_shutdown` or `syslog_partial_lines_dropped_at_shutdown`.
- Shutdown order: the HTTP server and the listeners now drain concurrently before the writers
  are flushed, so rows from still-open connections are no longer lost on a graceful stop.
- Parquet/S3 writer: a panicking flush task restores its rows and is retried instead of leaving
  the partition stuck (`parquet_s3_flush_panics`); the age tick runs at a quarter of the flush
  interval (1-30 s); failed flushes back off exponentially (1 s doubling, capped at 60 s and at
  `flush_interval_secs`) and a backed-off partition retries when its backoff expires; the final
  shutdown flush makes one descriptor attempt per partition; a failed Iceberg descriptor upload
  is retried three times (200 ms, 1 s, 5 s) before `iceberg_descriptor_upload_errors` counts it.
- Spool: an entry that carries an Iceberg descriptor is kept and retried, not deleted, while no
  descriptor sink is configured (`spool_descriptor_sink_missing`; alert on it, and see
  `docs/delivery-semantics.md` for how to discard stuck entries). Without `[spool]`, a descriptor
  that still fails after its retries (or at shutdown) leaves the Parquet uploaded but never
  committed to Iceberg; only `iceberg_descriptor_upload_errors` shows it.
- Iceberg descriptors: `schema_version` now reflects column nullability and no longer depends on
  the Rust toolchain.
- Committer: transient botocore and `requests` I/O errors abort the run for retry instead of
  quarantining the descriptor, required columns that are new to a table are added as optional,
  and a failure to move a descriptor to the done or quarantine prefix no longer retries or
  quarantines a file that was already committed.
- Helm: the generated Trino TLS certificate is renewed before it expires. The Secret carries a
  `logthing.io/not-after` annotation and is reused only while more than 30 days remain.

### Added

- Syslog TCP accepts RFC 6587 octet-counted frames (`LEN SP MSG`), chosen per frame and mixable
  with newline-terminated lines on one connection. A frame is octet-counted only when it starts
  with 1-7 digits (first digit 1-9), one space and `<`, so lines that merely begin with a digit
  stay newline-framed. A length above 256 KiB closes the connection and counts in
  `syslog_oversized_lines`.
- Metrics `otlp_requests_rejected_too_large`, `wef_plaintext_on_kerberos_rejected`,
  `parquet_s3_flush_panics`, `spool_descriptor_sink_missing`, `ipfix_options_records_skipped`,
  `ipfix_records_capped`, `sflow_counter_records_skipped`, and
  `{zeek,suricata,syslog}_partial_lines_dropped_at_shutdown`.
- `@host` and `@source` redaction targets for `[hec.redaction]` `drop_fields` and `hash_fields`.
- The release workflow now fails before building when the git tag does not match the
  `Cargo.toml` version.

### Changed

Behaviour changes to check before upgrading:

- OTLP: requests over 100,000 records or over the 256 MiB heap-weighted estimate get `413`
  (lower the exporter batch size, for example `send_batch_max_size`). Records with many
  attributes reach the 256 MiB estimate well before 100,000 records (an estimated ceiling of
  about 28,000 records per request for attribute-heavy shapes; not a hard limit, the bound is
  the 256 MiB heap estimate), so size batches by shape. An export is answered
  `503` instead of `200` when no OTLP sink is configured or a sink channel is closed. Retries
  can duplicate records another sink already accepted (at-least-once).
- WEF: when a sink drops any event of an Events batch (buffer full or closed), the request is
  answered `503` with `Retry-After: 1` and the bookmark is not advanced; the client re-sends, so
  duplicates are possible and a permanently closed sink makes clients retry indefinitely.
  Unparsable event XML is counted and skipped and does not block the bookmark. After Kerberos
  authentication, a non-empty non-encrypted body is rejected with `400`.
- Admin UI: behind a proxy the client IP is the rightmost `X-Forwarded-For` hop (the last header
  line); exactly one trusted proxy is assumed. `LOGTHING_ADMIN_ENABLE_RATE_LIMIT` accepts only
  `true`/`1`/`yes`/`on` or `false`/`0`/`no`/`off` (case-insensitive), any other value stops
  startup. An invalid or non-Argon2 `LOGTHING_ADMIN_PASS_HASH` stops startup; single-quote the
  value or double each `$` in Docker Compose.
- Redaction: drop and hash keys match case-insensitively, so rules remove or hash more keys than
  before. Masks now also apply to HEC `host`/`source` and OTLP `host_name`, `event_name`,
  `severity_text` and `scope_name`. Numeric leaves that match a mask pattern become masked
  strings (a type change for those leaves). `@host` and `@source` are new HEC targets.
- HEC: a `time` of 1e11 or more is epoch milliseconds (it was read as seconds); numeric string
  times are accepted; out-of-range times are treated as unparsable and stored as NULL. A leading
  UTF-8 BOM is stripped from `/services/collector/event` and `/ingest` bodies.
- Syslog: lines with a PRI above 191 are kept (raw line as the message, default priority) instead
  of dropped; lines with a valid PRI that match neither RFC 5424 nor RFC 3164 are kept with their
  real priority. On TCP, a frame starting with digits, a space and `<` is now read as an
  octet-counted frame.
- Iceberg descriptors: every table's `schema_version` changes once (now the first 16 hex
  characters of a SHA-256 over column names, types and nullability). The bundled committer does
  not read it.
- Helm: an existing Trino TLS Secret without the `logthing.io/not-after` annotation is
  regenerated once on the first upgrade, and every renewal regenerates the CA as well as the
  server certificate. Clients that pin the old CA (for example dbt's `TRINO_CA_CERT`) must
  re-fetch `ca.pem`. Provide `trino.tls.existingSecret` for a stable CA.
- Shutdown and exit codes: if the HTTP server or any wire-protocol listener exits on its own (for
  example a port that cannot be bound), logthing performs the graceful shutdown and then exits
  non-zero. Worst-case shutdown is about 22 s, so the bundled compose files now set
  `stop_grace_period: 30s`; give your own supervisor at least 30 s (Kubernetes
  `terminationGracePeriodSeconds`, Docker `--stop-timeout`). A panic of the HTTP server task
  during the drain also exits non-zero; a drain timeout (10 s, then abort) exits 0. After such
  a timeout the aborted server's per-connection tasks can still hold the writers' senders, so
  the writers hit their own 10 s deadline without end-of-stream and rows received since the last
  periodic flush can be lost; only requests still in flight 10 s after the signal trigger this.
- Startup now fails (with an error naming the setting) for `WEF_WORKER_THREADS=0` or a
  non-number, `hec.max_sourcetype_partitions = 0` (with HEC enabled) and
  `otlp.max_service_partitions = 0` (with OTLP enabled), instead of ignoring them or silently
  removing the partition cap. `LOGTHING_ADMIN_TRUST_PROXY_HEADERS` is parsed like
  `LOGTHING_ADMIN_ENABLE_RATE_LIMIT` (`true`/`1`/`yes`/`on` or `false`/`0`/`no`/`off`); any
  other value, including one that used to read as false, stops startup.
- Analytics stack default image pins move to 0.23.1 for both logthing and the committer (still in
  lockstep); Helm chart version 0.2.3 (Trino TLS certificate renewal, above).

## [0.23.0] - 2026-10-10

### Fixed

- WEF bookmarks are keyed by the authenticated client identity (Kerberos principal or
  client-certificate fingerprint) instead of the client-asserted MachineID, so a client can no
  longer overwrite another machine's resume position. New `wef_auth_failures_total` reason
  `missing_identity`. After a client certificate is renewed, that machine starts once with no
  bookmark; machines that share one credential or certificate share one bookmark.

### Added

- WEF subscription manager for real Windows source-initiated clients: `Enumerate` on
  `/wsman/SubscriptionManager/WEC` serves the subscriptions configured under `wef.*`
  (`wef.collector_url`, `wef.allow_unauthenticated`, `wef.bookmark_capacity`,
  `[[wef.subscriptions]]`), and delivery endpoints at `/wsman/subscriptions/<uuid>` Ack events and
  heartbeats. Per-(client identity, subscription) bookmarks are kept in memory and replayed on
  Enumerate.
- UTF-16 request/response bodies and SLDC-compressed event batches.
- Per-connection Kerberos for `/wsman/**` (`Authorization: Kerberos` and `Negotiate`) with
  MS-WSMV message encryption.
- HTTPS client-certificate topology for WEF (`tls.require_client_cert` with `tls.ca_file`).
- Metrics `wef_requests_total{action}` and `wef_auth_failures_total{reason}`.
- Windows client emulator and a Docker KDC test environment (`scripts/kdc-test-env.sh`) for
  testing the WEF receiver without Windows.
- `docs/wef.md` documents GPO client setup, the two topologies and known limits.
- `/wsman` request bodies larger than 4 MiB are rejected with `413` in all topologies.
- Tests: a Docker `wef-interop` end-to-end scenario (`run.sh wef-interop`, MIT KDC plus the
  Windows client emulator over Kerberos-HTTP and HTTPS client certificates) and a real-Kerberos
  integration test (`tests/wef_kerberos_integration.rs`, needs `scripts/kdc-test-env.sh`).

### Changed

- WEF event fields are now extracted fully from the event XML.
- Startup fails when `[[wef.subscriptions]]` are configured without any client authentication,
  unless `wef.allow_unauthenticated = true`.
- Analytics stack default image pins move to 0.23.0 for both logthing and the committer (still in
  lockstep); Helm chart version 0.2.2. No schema or config changes for the analytics stack.

### Removed

- The legacy bare-`<Events>` ingest. `POST /wsman/events` and `POST /wsman/subscriptions` are no
  longer ingest endpoints: they are handled as subscription-manager requests, so a bare
  `<Events>` body (no SOAP envelope) gets `400`. Any other `/wsman/subscriptions/<path>` that is
  not `<uuid>` or `<uuid>/<number>` gets `404`.
- The old `kerberos-test` simulation container, replaced by the `wef-interop` scenario.

## [0.22.1] - 2026-10-08

### Fixed

- Build on Rust 1.99: replace `AtomicUsize::fetch_update` (deprecated in 1.99, renamed
  `try_update`), which failed `cargo clippy -- -D warnings` in CI on the latest stable toolchain.

### Changed

- Docker builder images (`Dockerfile`, simulation `Dockerfile.kerberos`, loadgen `Dockerfile`)
  move from `rust:1.93-slim-bookworm` to `rust:1.99-slim-bookworm`.
- Analytics stack default image pins move to 0.22.1 for both logthing and the committer (still in
  lockstep); Helm chart version 0.2.1. No schema or config changes from 0.22.0.

## [0.22.0] - 2026-10-08

### Breaking

- OTLP has its own sinks. `[otlp] enabled = true` now requires `[otlp.s3]` and/or
  `[otlp.local]`; OTLP no longer writes through the `[hec]` sinks into the `hec` table. See
  `docs/otlp.md#migration`.
- Startup fails when HEC or OTLP is enabled with no sink configured (previously records were
  accepted and silently dropped, or written through the other route's sink). Add
  `[hec.s3]`/`[hec.local]` or `[otlp.s3]`/`[otlp.local]`. The shared analytics stack config keeps
  `[otlp.s3]`; never drop it.
- HEC (`/services/collector/event`, `/services/collector/raw`, `/ingest`), NDJSON and OTLP answer
  `503` (HEC body `{"text":"Server is busy","code":9}`, `Retry-After: 1`) when a writer channel
  is full, instead of 200 with a counted drop. Clients must retry. A request partially enqueued
  before the channel filled is rejected whole, so a retry duplicates the enqueued prefix. WEF is
  unchanged.
- The generic/HEC Iceberg schema gained the columns `event_uuid`, `source`, `index` and
  `indexed_fields`, and OTLP writes a new typed `otlp` table. Upgrade the committer BEFORE
  logthing: an old committer quarantines the new-shaped files. OTLP rows written by 0.21.0 sit in
  the `hec` table with a NULL `event_uuid` (the `stg_hec` model keeps them). See `docs/hec.md`
  and `docs/otlp.md` (Migration).
- The default HEC `channel_capacity` is about 43% smaller (the per-record budget rose from 1024
  to 1792 bytes to cover the new envelope columns). Set `channel_capacity` explicitly if you
  relied on the old default; a full channel now answers 503.
- Analytics stack now enables HEC and OTLP ingest on port 5985. Compose requires `HEC_TOKEN` and
  `OTLP_BEARER_TOKEN` (regenerate `.env` or add them to an existing one). Helm
  `credentials.existingSecret` needs the new keys `hec-token` and `otlp-bearer-token`; a
  `require-tokens` init container fails the logthing pod on an empty token.
- Analytics stack image pins moved to 0.22.0 for both logthing and the committer, in lockstep
  with the crate version. If you override `LOGTHING_IMAGE` / `COMMITTER_IMAGE` or the Helm image
  values, move both to 0.22.0 together.
- Redaction config is validated at startup: an invalid, duplicate or non-identifier
  `hash_key_env`, or a `mask_patterns` entry that is not a valid regex, is a startup error
  rather than being ignored.
- OTLP redaction on an unparseable body: a JSON-looking OTLP body that cannot be parsed while
  `@body.*` rules are configured is stored as `[REDACTED]` in whole, and the event is counted
  as `redactions_applied{rule="body_unparseable"}`.
- The Helm chart `version` is 0.2.0 (was 0.1.0): the chart contents changed incompatibly
  (new required secret keys, NetworkPolicies, image pins).

- Analytics stack upgrades keep the old PUBLIC demo secrets: Postgres role passwords, the Garage
  key and the Lakekeeper encryption key persist in volumes/PVCs, and Helm's `lookup` and
  `--reuse-values` keep the old values (the chart now warns in NOTES.txt). Compose: `down -v`, or
  hand-write `.env` with the old values and rotate deliberately (a freshly generated `.env` breaks
  Lakekeeper-to-Postgres auth, the Garage key never applies, stored warehouse credentials fail).
  Helm: `--reuse-values` fails from a pre-B1 release; use `--reset-then-reuse-values`. See
  "Upgrading an existing stack" in `deploy/analytics/README.md`. The Helm-generated Trino
  certificate (825 days) is not renewed automatically.

- Analytics stack, for anyone running it from master before this release: Hue is replaced by
  Metabase (Hue saved queries are not migrated); compose requires a `.env` (run the generator);
  Trino moved from unauthenticated `http://:8080` to `https://:8443` (users `admin` and
  `metabase`); `LAKEKEEPER_PORT`, `HUE_*` and `HUE_IMAGE` are removed; Helm credential keys changed
  (`hue-*` out, `trino-*` and `metabase-*` in).
- Analytics stack, published ports (compose, as of master 7b835b9 the loopback ports 8080 for Trino
  and 8181 for Lakekeeper): Trino plain HTTP 8080 is no longer published (clients must use
  HTTPS 8443 with a password and the generated CA); Lakekeeper (8181) is no longer published.
  Postgres and the Garage admin port were never published in compose, so nothing changed there.
- Analytics Helm chart: NetworkPolicies are now rendered by default (`networkPolicy.enabled`,
  set `false` to opt out). They can block previously open pod-to-pod access to Lakekeeper,
  Postgres, the Garage admin API and Trino's plain-HTTP 8080 from pods not listed as peers.

### Added

- Typed HEC ingest: the generic Iceberg table gains `event_uuid` (UUIDv7 assigned at ingest on
  every route), `source`, `index` and `indexed_fields`. The committer evolves existing tables
  additively before `add_files`; old rows read NULL.
- OTLP/HTTP logs (`POST /v1/logs`) write a typed `otlp` table through their own
  `[otlp.s3]`/`[otlp.local]` sinks, partitioned per `service.name`
  (`max_service_partitions`, then an `_overflow` partition). See `docs/otlp.md`.
- gzip request bodies on HEC, NDJSON and OTLP, with a 64 MiB decompressed cap (`413` beyond it,
  `415` for other encodings, `400` for a corrupt stream).
- `loadgen otlp-http`; `--gzip`, `--pii-fields` and `--max-retries` on the HTTP subcommands;
  `scripts/max-ingest-rate.sh` supports the otlp format, gzip, redaction and a 503 verdict.
- `docs/performance.md` (measured single-node HEC/OTLP throughput) and `docs/scaling.md`.
- `deploy/analytics/` — docker compose and Helm deployments of logthing, Garage (S3), the
  committer, Lakekeeper (Iceberg REST), Trino and Metabase, plus a dbt-trino project
  (`deploy/analytics/dbt/`) with OCSF views (network, DNS, authentication, detection finding)
  and example detection queries. The stack also carries the OTLP/HEC application-log pipeline,
  with `stg_otlp` and `stg_hec` dedup staging models (dedup on `event_uuid`). See
  `deploy/analytics/README.md`.
- Analytics stack security defaults: secrets are generated and never defaulted
  (`deploy/analytics/scripts/gen-analytics-env.sh` for compose; `randAlphaNum` + `lookup` in
  Helm); Trino serves HTTPS on 8443 with password authentication and a generated CA (plain HTTP
  8080 is not published); Lakekeeper, Postgres and the Garage admin API are not published; Helm
  ships NetworkPolicies.
- Redaction for HEC and OTLP records: `[hec.redaction]` / `[otlp.redaction]` with
  `drop_fields`, `hash_fields` (HMAC-SHA256, key from the env var named by `hash_key_env`) and
  `mask_patterns`, applied before the record is enqueued. See `docs/redaction.md`.
- `[spool]` (`dir`, `max_bytes`): every S3 flush is committed to local disk (tmp, fsync, rename)
  and uploaded in the background with backoff, replayed on startup. See
  `docs/delivery-semantics.md`.
- Iceberg descriptors gain an additive `sha256` field (hex digest of the Parquet file).
- S3 Object Lock: `object_lock_mode` (`GOVERNANCE` / `COMPLIANCE`) and `object_lock_retain_days`
  on every S3 sink, with `checksum_algorithm = SHA256` on puts. See `docs/object-lock.md`.
- Local-disk sinks fsync the file and its directory before reporting success.
- New metrics: `redactions_applied{source,rule}`, `spool_bytes`, `spool_entries`,
  `spool_unreadable`, `spool_rejected{reason}`, `spool_uploaded{sink}`,
  `spool_upload_errors{sink}`, `spool_corrupt`, `local_sink_dir_fsync_errors`.

### Changed

- `loadgen` treats `503` as backpressure and retries per `Retry-After` instead of counting an
  error.
- The README throughput claim is replaced by measured numbers; stale admin, syslog, metrics and
  container-tag docs examples are corrected.
- `parquet_s3_uploads` no longer increments for spooled files; see `spool_uploaded`.

### Fixed

- OTLP ingest throughput: the OTLP writer now appends records into reused Arrow builders
  (`OtlpAccumulator`) instead of building a 21-column one-row batch per record, which capped a
  single writer near 13k records/s and returned 503 above it. Single-node ceiling on the
  benchmark host rose from 10625 to 80625 records/s (gzip, batches of 100); Parquet content is
  unchanged. See `docs/performance.md`.
- Buffered writer: rows that cross `max_buffer_rows` / `flush_threshold_bytes` while a flush is
  in flight are now flushed as soon as that flush completes, instead of waiting for the next
  tick or record.

### Not yet supported

- OTLP gRPC (port 4317); use the `otlphttp` exporter.
- WEF does not answer 503 on a full channel (200 with a counted drop, unchanged).

## [0.21.0] - 2026-09-30

### Added

- `committer/` — a reference Iceberg committer that drains logthing's
  descriptor queue into an Iceberg REST catalog via `add_files`, one commit
  per table per run, partitioned by `day(partition_time)`. Published as the
  container image `ghcr.io/mrmagooey/logthing-committer` on every release
  tag. Transient and credential errors leave descriptors queued and exit
  non-zero; only per-file errors quarantine. See `committer/README.md`.
- `docs/iceberg.md` gains a table-maintenance section: periodic `optimize`
  and `expire_snapshots`, and why `remove_orphan_files` must never run
  against logthing's data location.

### Changed

- The README is split into end-user pages under `docs/`.

## [0.20.2] - 2026-09-22

### Added

- `parquet_s3_records_skipped{source,target}` — records the Parquet writer
  could not convert into a batch and skipped, whatever the reason (schema
  mismatch, a mapping failure, or an unparsed event). Previously these skips
  were silent: an unthrottled `warn!` per record and no metric at all.
- `wef_xml_parse_errors` — WEF batches whose XML the parser could not read
  past a given event. Each occurrence is kept as its own raw event and
  parsing resumes at the next `<Event`, so one malformed event no longer
  costs every event after it.
- `listener_accept_errors{protocol}` — TCP accept errors on the syslog,
  Zeek, and Suricata listeners (`protocol` = `syslog_tcp`/`zeek`/`suricata`).
  Climbing steadily (rather than the occasional per-connection blip) points
  at fd exhaustion or a similar persistent condition.
- IPFIX (v10) variable-length fields (RFC 7011 §7) are now decoded.
  Previously any template containing one silently produced no records:
  a field length of `0xFFFF` summed into the fixed-length record size as
  65535 bytes, so no data set built from that template ever matched. Values
  of Information Elements not in the known-IE table land hex-encoded in
  `extra`, the same as any other unknown IE. NetFlow v9 is unchanged — RFC
  3954 has no variable-length encoding, so a v9 template with `0xFFFF`
  still decodes nothing, exactly as before.

### Changed

- IPFIX values stored hex-encoded in `extra` — enterprise IEs, unknown IEs,
  and RFC 7011 §7 variable-length IEs alike — are now truncated to 128 bytes,
  with `<key>_original_len` recording the real length when truncation
  happens. A single Information Element's value can be up to ~64 KiB on the
  wire (routine now that variable-length fields are decoded), which
  previously became ~128 KiB of hex in one flow's `extra` with nothing
  bounding it; this caps per-flow memory the same way sFlow's unknown record
  bodies already are (`MAX_UNKNOWN_RECORD_BODY_BYTES`).

### Fixed

- A Zeek `_path` of mixed case (e.g. `"Conn"` instead of `"conn"`) resolved
  its schema differently from its write buffer: `get_schema_entry` looked up
  the case-sensitive schema registry with the raw path (falling back to the
  untyped envelope schema), while the buffer itself was keyed by the
  lowercased, sanitized path and stayed typed `conn`. The mismatched,
  envelope-shaped batch then landed in the typed `conn` buffer, and every
  later flush of that buffer failed in `concat_batches` — permanently, until
  the process restarted — silently dropping every row queued behind it.
  `get_schema_entry` now falls back to a sanitized-path lookup before
  defaulting to the envelope schema, and `push()` now rejects (with a `warn!`
  and a skip, counted by the new `parquet_s3_records_skipped` above) any
  batch whose schema doesn't match its buffer's, so a future adapter bug of
  the same shape can no longer jam a buffer instead of just dropping the one
  bad batch.
- A WEF batch with one malformed event lost every event after it, while the
  HTTP response still answered `200` — so the Windows Event Forwarder,
  having been told the batch succeeded, never resent it, and the data was
  gone for good. `WefParser::parse_events` now resyncs on a parse error:
  the malformed event's own fragment is kept as a raw event, and parsing
  resumes at the next `<Event` start with a fresh reader, so well-formed
  events on both sides of a malformed one still reach Parquet.
- The syslog, Zeek, and Suricata TCP accept loops logged an error and
  immediately re-polled `accept()` on failure. For errors like `EMFILE` (fd
  exhaustion), the listening socket's readiness is never cleared, so the
  loop spun at 100% CPU with a matching flood of log lines instead of
  backing off. Accept errors that aren't per-connection noise
  (`ConnectionRefused`/`ConnectionAborted`/`ConnectionReset`, which get no
  pause) now pause that listener's accept loop for 1 second, bounding both
  the CPU spin and the log volume to about once a second.
- The four "skip this record" branches in the Parquet writer's `push()` (a
  `day_and_batch` error, two `to_record_batch` errors, and a live-builder
  `try_append` error) each logged an unthrottled `warn!` and incremented no
  metric — a sustained source of skips (e.g. every event from one
  persistently-malformed sender) could flood the log with no corresponding
  number an operator could alert on. All four now increment
  `parquet_s3_records_skipped` and log at most once per 30 seconds per
  writer, carrying the error and the running skipped count.
- Zeek rows routed to the `_overflow` partition (after `max_partitions` is
  reached) recorded the placeholder `"_overflow_nonexistent_"` as their
  `log_path` instead of the record's real path. `ZeekSink::to_record_batch`'s
  overflow branch now maps the row through `map_envelope(&record.fields,
  &record.log_path, ...)` directly, so overflowed rows keep the log path
  they actually came from.
- A mixed-case Zeek `_path` (e.g. `"Conn"`) was written under its real,
  typed stream but counted under `zeek_records_by_path{log_path="other"}`:
  `metric_log_path` was missing the sanitized-path fallback
  `get_schema_entry` already had, so the two disagreed on the same record.
  Both now share one `registry_lookup` so a schema resolution and its metric
  label can no longer diverge.
- The Parquet writer's shutdown `flush_all` zeroed a buffer's `row_count`
  and `byte_count` only on the failure path, not on success — a successful
  flush left both stale until the next `push()` overwrote them, which
  inflated the `rows_still_buffered` figure logged if shutdown's flush
  loop hit an error on a later partition.

## [0.20.1] - 2026-09-22

### Fixed

- The `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` release
  binaries failed to compile, so v0.20.0 published a GitHub Release with no
  binary assets attached. `RecvMmsgBatch` (new in 0.20.0) used two constructs
  that are valid on glibc but not on musl: `recvmmsg`'s `flags` parameter is
  `c_int` on glibc and `c_uint` on musl, and musl's `msghdr` carries private
  padding fields that make struct-literal construction a hard error. The
  `flags` argument is now `MSG_DONTWAIT as _` so inference picks the right
  width per target, and the `msghdr` is zeroed and filled field-by-field
  rather than built as a literal. Both are compile-time-only changes with no
  effect on the running binary. `.github/workflows/rust.yml` builds only the
  gnu target, so nothing caught this before the tag was pushed; both musl
  targets are now verified building via `cargo zigbuild`, the same tool
  `binaries.yml` uses.

## [0.20.0] - 2026-09-21

### Added

- A new `GET /metrics` page on the admin console shows live in-process counter
  and gauge values — the same numbers the unauthenticated `/metrics` endpoint
  serves — behind the admin server's authentication and audit logging. The page
  includes a dedicated section for configured `[[metrics.cardinality_watch]]`
  entries; watches awaiting their first window boundary display `awaiting first
  window (<N>s)`, which clarifies why a correctly configured watch appears
  absent from the metrics output — `field_distinct_values` is only published at
  a window boundary (default 3600s), so a watch legitimately has no data for up
  to an hour after startup.
- `recv_tasks` config option on the `[ipfix]`, `[sflow]`, and `[syslog]`
  (UDP arm only) listeners — binds `N` `SO_REUSEPORT` sockets on the same
  port, each drained by its own task, instead of one socket drained by one
  task. **Default is `8`, not `1` — this changes behavior on upgrade.** An
  existing deployment that has never set `recv_tasks` will, after
  restarting on this version, bind 8 `SO_REUSEPORT` sockets per UDP
  listener instead of the single socket it bound before. Set `recv_tasks =
  1` explicitly in `logthing.toml` before upgrading if byte-for-byte
  unchanged socket behavior is required. The default was raised because an
  idle-cost measurement with no traffic found the knob nearly free at any
  setting from `1` to `16` — about 19 KB RSS and one extra file descriptor
  per additional socket, idle CPU rising from 0.090s to 0.130s per 30s, and
  zero receive-buffer memory actually charged at any setting (`SO_RCVBUF`
  is a cap, not a reservation) — while the measured throughput saturation
  point remains `4`. Raise it further when `<protocol>_socket_drops` is
  climbing while the process uses roughly one core; measured
  recommendation is `4`, which roughly doubled the sustained ingest
  ceiling for ipfix and sflow and raised syslog's by ~38%. Only helps
  deployments with many distinct senders on one listener — `SO_REUSEPORT`
  distributes by 4-tuple hash, so a single high-rate sender sees no
  benefit from raising this.
- `recv_batch_size` config option on the `[ipfix]`, `[sflow]`, and
  `[syslog]` (UDP arm only) listeners — above `1` (off), a recv task
  drains up to `N` already-queued datagrams per `recvmmsg(2)` call instead
  of one `recvfrom(2)` call per datagram. **Default is `32`, not `1` —
  this changes behavior on upgrade.** An existing deployment that has
  never set `recv_batch_size` will, after restarting on this version,
  allocate batch buffers it did not allocate before: roughly 6 MB of
  additional resident memory with all three listeners enabled at the
  default `recv_tasks` of `8` (idle RSS measured 15,084 kB at
  `recv_batch_size=1` vs. 21,068 kB at `32`). Because `recv_tasks` also
  defaults to `8`, both knobs are now on by default, and the memory cost
  of batching scales with the number of recv tasks. Set `recv_batch_size
  = 1` explicitly in `logthing.toml` before upgrading if byte-for-byte
  unchanged socket behavior is required. Complements `recv_tasks` rather
  than replacing it: `recv_tasks` fans out across many distinct senders
  and cannot help a single one (`SO_REUSEPORT` hashes by 4-tuple, so one
  sender always lands on the same task); `recv_batch_size` helps exactly
  that single-high-rate-sender case by amortizing the syscall. Measured
  on ipfix at `GEN_PROCS=1` (one sender, 50,000/s, `RUNS=5`): median
  kernel-loss dropped from 0.72% at `recv_batch_size=1` to 0.00% at every
  setting from `4` upward — the measured win is `1 → ≥4`. The sweep does
  not show `32` outperforming `8`; this host's run-to-run variance is
  large at `n=5`, so `32` was chosen for headroom (~6 MB, above) rather
  than a demonstrated throughput edge over `8`. Maximum `256`,
  rejected at config load above that as a likely typo, since each unit
  allocates a 65535-byte buffer per recv task at startup.
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
- Startup config validation (`validate_config_invariants`, called from
  `Config::load()`): TLS enabled without `tls.cert_file`/`tls.key_file`, a
  zero `bind_address` port, a zero `security.max_connections` or
  `security.connection_timeout_secs`, and a malformed `security.allowed_ips`
  entry now all fail the process immediately at startup. For TLS-without-cert
  and a zero `max_connections`/`connection_timeout_secs`, this just moves an
  existing failure earlier: previously these were only caught when the
  config-write endpoints (now removed) accepted a change, or not at all if
  the same bad value came from `logthing.toml` or an environment variable at
  startup — they'd instead fail later, downstream, in `build_tls_config` or
  `create_router`. The zero `bind_address` port check is new strictness, not
  an earlier surfacing of an existing failure: `TcpListener::bind` on port 0
  always succeeds (the OS assigns an ephemeral port), so previously a
  deployment with `bind_address` port 0 started fine, just confusingly
  logging `:0` while actually listening on a different, unlogged port. An
  operator who relied on that behaviour will now fail to start.
- Bounded field-cardinality watch: configure one or more
  `[[metrics.cardinality_watch]]` entries (`source`, `stream`, `field`) to
  publish `field_distinct_values`, a gauge of how many distinct values a
  wire-derived field took on in the most recently completed window,
  labelled by `source`/`stream`/`field`. A companion counter,
  `field_distinct_values_capped`, increments whenever a window's distinct
  count would have exceeded `cardinality_max_values` (default `100000`),
  so a gauge pinned at the cap can be told apart from a genuinely stable
  count. `cardinality_window_secs` (default `3600`) controls how often the
  gauge is published and cleared. Supported `source` values are `zeek`,
  `wef`, `suricata`, `syslog`, `ipfix`, and `sflow`; an unknown or disabled
  source, a missing `stream`/`field`, a duplicate watch, or
  `cardinality_max_values = 0` all fail startup rather than silently
  watching nothing. Ships with every example commented out in
  `logthing.toml` — the feature is opt-in and adds no overhead unless
  configured. Intended use: compare a watched field's distinct-value count
  (e.g. zeek `id.orig_h`, WEF `computer`, ipfix `exporter`) against a
  known-good host count as an "is ingestion actually working?" check.
- `# HELP` text for every metric on `/metrics`. The Prometheus exporter
  always wrote a `# TYPE` line for a recorded series but previously wrote
  no `# HELP` line for any of them, since nothing called
  `Recorder::describe_*`. All statically-named metrics, plus the
  `<protocol>_socket_drops`/`_socket_rx_queue_bytes` pairs for
  `syslog_udp`/`ipfix`/`sflow`, now carry a description.

### Fixed

- `parse_proc_net_udp` now sums kernel-socket drops across every socket
  sharing a port, rather than reading only the first. This was latent
  until `recv_tasks > 1` (above) made multiple sockets share one port via
  `SO_REUSEPORT` — before the fix, the harness-side drop reconciliation
  read one socket of `N` and disagreed with the in-process counter.
- **CRITICAL**: nine log sites sliced wire-derived strings (syslog,
  suricata, WEF) by a raw byte offset for truncation, which panics when
  the cut lands inside a multi-byte UTF-8 character. On syslog UDP, the
  panicking task was one of the `recv_tasks` `SO_REUSEPORT` receive tasks;
  its `JoinError` was discarded, so that socket was silently never drained
  again for the life of the process. Truncation now walks back to the
  nearest character boundary, and a receive task that dies now logs an
  error and increments a counter instead of vanishing silently.
- The same silent-death pattern (a panicking `SO_REUSEPORT` receive task's
  `JoinError` discarded with `let _ = task.await`) existed independently
  in IPFIX's and sFlow's fan-out join loops, not just syslog's. Both now
  log an error and increment `ipfix_recv_task_failed` /
  `sflow_recv_task_failed` on a dead receive task, matching syslog.
- **HIGH**: the admin audit-log viewer rendered entries via `innerHTML`,
  so an unauthenticated attacker could get arbitrary script executed in
  an admin's browser (same-origin, with cached credentials) just by
  failing Basic-Auth login with a script payload as the username — any
  failed login is audited regardless of whether it succeeds. The viewer
  now builds DOM nodes and sets `textContent`; the `/audit-log` API still
  serves the raw string unescaped, since escaping is a render-time
  concern.
- **HIGH**: `GET /config` (and the redacted config the admin console
  renders) only masked S3 credentials in three of the ten config sections
  that carry them (`syslog.s3`, `ipfix.s3`, `zeek.s3`) — `access_key`/
  `secret_key` for `syslog.structured_s3`, `suricata.s3`, `wef.s3`,
  `hec.s3`, `sflow.s3`, `aggregate.s3`, and `iceberg.s3` were served in
  plaintext. All ten sections are now redacted.
- **MEDIUM**: `hec.token`, `otlp.bearer_token`, and `syslog.http_token`
  were likewise served in plaintext by the redacted config, letting any
  admin-API principal read the shared secrets needed to forge ingest
  records past HEC/OTLP/syslog auth. All three are now masked with the
  same `***REDACTED***` sentinel as S3 credentials when set; an unset/
  empty token (each field's documented "auth disabled" state) is left
  empty rather than becoming a literal secret-looking string.
- **HIGH**: a posted HEC `sourcetype` of e.g. `../zeek/conn` was used
  verbatim as an S3 object-key path segment, so a wire-supplied
  sourcetype could write forged HEC records into another source's S3
  partition (S3 does not collapse `..`). `sourcetype` is now sanitized
  the same way Zeek's `_path` and Suricata's `event_type` already are
  (lowercased, `[a-z0-9_]` only, truncated to 64 characters). logthing
  also now warns at startup if HEC is enabled with an empty token, since
  that is what makes the endpoint reachable unauthenticated in the first
  place.
- **MEDIUM**: the IPFIX/NetFlow v9 template cache had a 100,000-entry
  capacity bound but no eviction of any kind, so an attacker who filled
  it with spoofed templates left it full — refusing every legitimate
  exporter's new template — until the process was restarted. Entries now
  carry a last-seen timestamp, refreshed on insert and lookup; a sweep
  runs only when an insert arrives at a full cache, so a healthy
  deployment never evicts anything.
- **MEDIUM**: the syslog, Zeek, and Suricata TCP listeners bounded
  concurrency with a 1024-permit semaphore but applied no read timeout,
  so a client that connected and sent nothing held its permit forever;
  1024 idle connections exhausted the listener for everyone else. Idle
  TCP connections on all three are now closed after 300 seconds (5
  minutes) without a complete line, incrementing
  `syslog_tcp_idle_timeouts`, `suricata_tcp_idle_timeouts`, and
  `zeek_tcp_idle_timeouts`. Not configurable via `logthing.toml`/env. A well-behaved
  forwarder simply reconnects; if one is seen reconnecting periodically
  for no obvious reason, this timeout is a likely cause.
- **MEDIUM**: the metrics listener and the TLS listener both always bound
  `0.0.0.0`, ignoring `bind_address` — the metrics listener additionally
  had no auth and no IP whitelist of its own, so an operator who narrowed
  `bind_address` to a private interface still exposed `/metrics` on every
  interface. Both now inherit `bind_address`, and `/metrics` is gated by
  the same `security.allowed_ips` whitelist as the main HTTP router (there
  is no separate `metrics.allowed_ips` — a Prometheus scraper's source
  address must already be on that list). **BREAKING**: if you rely on
  `/metrics` being reachable on every interface regardless of
  `bind_address` (e.g. scraping from a different host than the main
  listener), set `metrics.bind_address = "0.0.0.0"` explicitly to restore
  the old behaviour.
- **LOW**: wire-derived text reaching a log line was truncated but not
  sanitized, so a syslog UDP datagram containing a raw newline (or an
  ANSI escape sequence) could forge an apparently separate operator log
  entry or inject terminal escapes — reachable from an unauthenticated,
  spoofable UDP sender. Control characters in wire-derived text are now
  replaced with U+FFFD before logging, at the syslog UDP parse-error sites, the
  syslog/Zeek/Suricata TCP parse-error sites, and the other wire-derived
  log-injection sites `A4` found (the admin audit logger's `username`
  field, reachable from a failed Basic-Auth attempt or a rejected
  trusted-header request; WEF's `SubscriptionId`; the WEF
  unknown-message-type warning; the formatted-message log in
  `process_single_event`; the Zeek/Suricata/syslog default handlers
  installed when no forwarding destination is configured; and the WEF XML
  tag name logged during parsing).
- **LOW**: the admin API's rate-limit map reset an IP's entry in place
  when its window expired but never removed it, so a client rotating
  source IPs grew the map without bound. Expired entries are now swept on
  every request. Separately, a `LOGTHING_ADMIN_ALLOWED_IPS` value whose
  entries all failed to parse was silently treated as an empty (i.e.
  allow-all) list, identically to never setting it at all — this is now a
  startup error; a partially malformed list still starts, with a warning
  naming how many entries were dropped.
- **CRITICAL**: `field_count`, a `u16` read directly off the wire, was
  passed unclamped to `Vec::with_capacity` in all three IPFIX/NetFlow v9
  template parsers. One 65,526-byte datagram of maximally-truncated
  Options Template Sets measured 4.80 GiB retained (a ~78,630x
  amplification) — enough to abort the process outright via
  `handle_alloc_error`. Capacity is now clamped to
  `field_count.min(remaining / 4)` (4 bytes being the minimum wire
  size of one field specifier) at all three allocation sites; wire
  truncation handling is otherwise unchanged.
- **HIGH**: `MAX_ZEEK_TCP_CONNECTIONS`/`MAX_SURICATA_TCP_CONNECTIONS`
  (1024) and `ZEEK_MAX_LINE_BYTES`/`SURICATA_MAX_LINE_BYTES` (16 MiB) were
  each individually reasonable, but their product was not: 1024
  connections each holding a 16 MiB unterminated line is up to ~15 GiB of
  attacker-controlled heap per listener, and the idle timeout above does
  not mitigate a sender that never goes idle. Both listeners now share a
  512 MiB byte-budget semaphore (64 KiB per permit); a connection that
  can't get budget is closed immediately, counted by
  `zeek_tcp_budget_exhausted`/`suricata_tcp_budget_exhausted`. Per-
  connection line-length limits are unchanged, so a legitimate large
  record is unaffected; a connection's read buffer also now releases its
  allocation once retained capacity exceeds 256 KiB, rather than holding
  onto a one-time large allocation forever.
- **HIGH**: sFlow's unknown-record handling (records logthing doesn't
  curate, retained verbatim in `extra` for operator diagnosis) had no
  bound on how many records, across how many samples, of what size, could
  be retained from one datagram — a crafted 65,535-byte datagram could
  retain several MiB. It is now bounded on all three axes: at most 8
  unknown records per sample, at most 512 per datagram (shared across
  every sample in one `decode_datagram` call, so splitting records across
  many small samples no longer defeats the per-sample cap), and each
  record's retained body capped to 128 bytes (with `body_truncated: true`
  and the full declared `length` still reported when a body is cut).
  `SFLOW_RECORD_BYTES` (the per-record footprint `channel_budget.rs`
  sizes the sFlow channel against) is raised from 1280 to **8960**,
  measured against the real worst-case shape through a counting
  allocator, and is now asserted as a true ceiling rather than an
  average. Channel capacity falls accordingly, from 81,920 slots (set in
  0.19.1) to **11,702** — still bounded well under the 100 MiB channel
  budget, and no longer resting on an unrepresentative per-record cost.
  A single aggregate `sflow_unknown_records_dropped` counter and warning
  now report the true total dropped across an entire datagram, correcting
  an earlier undercount that only reflected the first sample to hit the
  cap.
- **MEDIUM**: no route extracting a request body (`/wsman*`, `/syslog`,
  the HEC routes, `/ingest`, `/v1/logs`) bounded aggregate in-flight body
  memory across concurrent requests — `MAX_BODY_SIZE` (64 MiB) and
  `security.max_connections` (default 10,000) were each reasonable alone,
  but an unauthenticated attacker opening many connections and trickling
  max-size bodies could drive up to ~640 GiB of in-flight heap. A
  process-wide 1 GiB byte budget now charges every request by its real
  streamed bytes as the body is read (not by a client-supplied
  `Content-Length`, which is unenforced over HTTP/2 and would otherwise
  let the budget be bypassed entirely); a request that exhausts the
  budget is rejected rather than queued, so one attacker can't starve
  legitimate traffic. Bodyless `GET` routes are unaffected. Neither
  `MAX_BODY_SIZE` nor `security.max_connections` changes, so a single
  legitimate large HEC batch is unaffected.
- `RuleMetrics` (the aggregation rule counters `aggregate_records_consumed`
  and `aggregate_overflow_records`) never appeared on `/metrics` in
  production: their handles were cached at `Aggregator::new` time, which
  runs before the Prometheus recorder is installed, so they resolved to a
  permanent no-op. Separately, `run_tls`'s TLS branch never started the
  metrics-serving task at all when TLS was enabled without delegating to
  the non-TLS path — since TLS defaults to enabled, a deployment with no
  explicit `[tls]` block got no working `/metrics` endpoint at all. The
  Prometheus recorder is now installed synchronously, before anything
  that might cache a metric handle, and both `Server::run` and its TLS
  branch now start the metrics endpoint.
- A deployment with `tls.enabled = true` (the default) panicked on its
  first TLS handshake with "Could not automatically determine the
  process-level CryptoProvider": this dependency tree links two rustls
  0.23 crypto backends (`aws-lc-rs` and `ring`), and rustls refuses to
  auto-select one once more than one is linked. The process-level
  `CryptoProvider` (`aws_lc_rs`) is now installed unconditionally at
  startup, before config is even loaded, and again at every TLS entry
  point (main server TLS, admin console TLS) so nothing depends on
  startup-order discipline.

### Changed

- `loadgen`'s `hec-http` and `generic-http` subcommands gained
  `--events-per-request`, batching that many NDJSON/HEC events per HTTP
  request instead of one event per request. Without it, both generators were
  measuring HTTP request rate, not record rate — a flat ~21,000-25,000/s
  ceiling regardless of process count, versus a ~385k records/s single-
  threaded per-record decode cost. Batched at 100 events/request, measured
  ceilings for both formats rose 7-9x.

### Removed

- **BREAKING**: The admin interface is now read-only end to end. `PUT`/`PATCH
  /config` and `POST /config/{validate,diff,export,import,reload}`, and the
  configuration-editing form on the admin page, are all removed; those
  routes now return `405`/`404`. The surviving routes (`GET /config`,
  `/stats`, `/stats.json`, `/audit-log`, `/health`, and the admin page
  itself) are unchanged. The admin page now renders the redacted effective
  config as TOML, the list of `LOGTHING__*` variable **names** currently
  set, the audit log, and a link to `/stats` — nothing on it is editable.
  Configuration is set with `LOGTHING__*` environment variables layered over
  `logthing.toml` and `/etc/logthing/config` (environment variables win);
  `security.allowed_ips` and `aggregate.rules` have no environment-variable
  equivalent and remain file-only (the first is a list, the second a list of
  tables — the env loader supports neither shape).
- `scripts/repeat-ipfix-loopback-loss.sh` — replaced by
  `scripts/max-ingest-rate.sh`, which generalizes the same restart-per-run,
  zeroed-counter, kernel-drop-reconciling approach across all seven formats
  and drops two defects: a `pkill -f` that could kill the invoking shell
  instead of the server, and a cleanup step that deleted the tracked
  `logthing.admin.toml`.
- The admin web interface's CSRF middleware, CSRF-token generation, and
  the `LOGTHING_ADMIN_ENABLE_CSRF` env var. Every surviving admin route is
  a `GET` (the config-write endpoints were removed in an earlier change),
  so there is nothing left to forge.
- `IpWhitelist::set_networks` and `FlushIntervalRegistry::set_secs`, the
  last of the admin API's live-apply plumbing — their only callers were
  the now-deleted config-write handlers. **BREAKING**: `security.allowed_ips`,
  `hec.token`, and every sink's `flush_interval_secs` are now restart-only;
  changing them in `logthing.toml`, an `/etc/logthing/config` drop-in, or a
  `LOGTHING__*` env var requires restarting the process to take effect.
  `syslog.http_token` and `otlp.bearer_token` are affected the same way,
  for the same underlying reason: both were only ever "live" because the
  now-deleted config-write endpoints could swap the shared, in-memory
  `Config` at runtime; with no code path left that ever writes to it after
  startup, every field the admin API used to touch — not only the three
  above — now behaves like `bind_address` or `tls.*` always did.
- `admin::spawn_admin_server` dropped its `flush_registry` and
  `ip_whitelist` parameters (now just `(config, source_stats)`) — internal
  API, no config changes required.
- `logthing.admin.toml` as a configuration source. The tracked copy is
  deleted; `Config::load()` no longer reads it at all, and a leftover file
  found on disk produces a startup `WARN` (not an error) naming the file
  and pointing at `LOGTHING__*`/`logthing.toml` as the replacement. Move
  any settings the file held into `logthing.toml` or `LOGTHING__*` before
  upgrading — they are silently ignored otherwise, not merged.

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
