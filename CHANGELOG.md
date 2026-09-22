# Changelog

All notable changes to this project are documented in this file, newest
first, loosely following [Keep a Changelog](https://keepachangelog.com/).
This file starts at 0.15.0; earlier releases are not backfilled.

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
  point remains `4`; see the idle-cost section of
  `docs/performance/2026-09-18-udp-recv-fanout-results.md`. Raise it
  further when `<protocol>_socket_drops` is climbing while the process
  uses roughly one core; measured recommendation is `4`, which roughly
  doubled the sustained ingest ceiling for ipfix and sflow and raised
  syslog's by ~38% (see the same document). Only helps deployments with
  many distinct senders on one listener — `SO_REUSEPORT` distributes by
  4-tuple hash, so a single high-rate sender sees no benefit from raising
  this.
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
  than a demonstrated throughput edge over `8` — see
  `docs/performance/2026-09-18-recvmmsg-results.md`. Maximum `256`,
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
  ceilings for both formats rose 7-9x (see
  `docs/performance/2026-09-18-max-ingest-rate.md`).

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
