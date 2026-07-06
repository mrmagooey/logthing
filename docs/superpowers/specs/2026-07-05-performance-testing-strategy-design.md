# Performance-Testing Strategy for logthing — Design Plan

**Date:** 2026-07-05
**Status:** Draft — for review

---

## 1. Problem

logthing ingests 7-8 distinct wire formats concurrently (syslog, IPFIX, Zeek, Suricata, sFlow, generic/HEC, OTLP, and WEF), each with its own listener, parser, and — when persistence is configured — a `ParquetSink` adapter feeding the shared `PartitionedParquetWriter`/`ParquetWriterHandle` (`src/forwarding/buffered_writer.rs`). There is currently **no performance-testing harness at all**:

- No `criterion` dependency, no `[[bench]]` section in `Cargo.toml`, no `benches/` directory. Confirmed by grep — nothing.
- `tests/e2e/simulation-environment/performance-test/` exists but is WEF-only, hard-codes the legacy `/wsman/events` HTTP endpoint and `/stats/throughput`, and its README documents a `[forwarding.destinations]`-style S3 config that is **not** how any of the 8 sources persist data today (they use `[<source>.s3]`/`[<source>.local]` TOML tables backed by `S3Sink`/`LocalDiskSink`). `scripts/run-flamegraph.sh`, `scripts/profile-server.sh`, and `scripts/run-with-profiling.sh` are similarly WEF/legacy-config-shaped and reference `docker compose run --rm performance-test-max-throughput`.
- CI (`.github/workflows/rust.yml`) runs `cargo build`/`cargo test`/`cargo fmt`/`cargo clippy` on every push/PR to `master`, with no `workflow_dispatch` trigger and nothing performance-related. `.github/workflows/binaries.yml` is the only workflow with `workflow_dispatch`.

This plan proposes a performance-testing tier that is additive to the existing unit/integration/e2e model (per the repo's testing policy), not a replacement for it, and is deliberately **not** run on every push given its cost/duration.

## 2. What exists today that we can build on

| Asset | Location | Reusable as-is? |
|---|---|---|
| MinIO + docker-compose pattern | `tests/e2e/simulation-environment/docker-compose.yml` (`minio`, `minio-setup` services, `MINIO_ROOT_USER=miniouser`/`MINIO_ROOT_PASSWORD=miniopassword`) | Yes — same MinIO image/credentials pattern already used by every `*_s3_integration.rs` test (e.g. `tests/ipfix_s3_integration.rs` reads `MINIO_ENDPOINT`/`MINIO_BUCKET`/`MINIO_ACCESS_KEY`/`MINIO_SECRET_KEY` env vars and skips if `MINIO_ENDPOINT` is unset) |
| Functional per-format traffic generators | `tests/e2e/simulation-environment/{syslog,zeek,ipfix,wef}-generator/entrypoint.py` | Only as **reference for wire-format construction** (e.g. `ipfix-generator/entrypoint.py` hand-builds a real IPFIX v10 template+data datagram with raw `socket`/`struct`) — these send a handful of fixed records once, they are not load generators and don't rate-limit/measure throughput |
| A real (if stale) load generator | `tests/e2e/simulation-environment/performance-test/entrypoint.py` | Pattern only: async-batch-and-rate-limit-over-HTTP approach is sound (~9,500 events/sec sustained against the old WEF-only server), but targets a `/wsman/events` + WEF-shaped config that doesn't reflect today's per-source `.s3`/`.local` config shape |
| `[profile.profiling]` build profile | `Cargo.toml` (`inherits = "release"`, `debug = true`, `strip = false`) | Yes, unchanged — this is exactly what `cargo flamegraph --profile profiling` / `perf record` need |
| Real-time per-source counters, zero new instrumentation | `SourceHourlyStats` (`src/stats/mod.rs`), served at `/stats` and `/stats.json` by the **admin** server (`src/admin/routes.rs`, separate process/port from the main listener, bind address set via `logthing.admin.toml` / `ADMIN_OVERRIDE_FILE`) | Yes — `record()` is called once per `push()` (not per flush), so polling `/stats.json` every N seconds and diffing counts gives a live per-source ingest rate even though the storage itself is hourly-bucketed |
| Fine-grained Prometheus counters | `:9090/metrics` (`MetricsConfig`, default port 9090) — `parquet_s3_records_written{source,target}`, `parquet_s3_uploads{source,target}`, `parquet_s3_upload_errors{source,target}`, `parquet_s3_dropped{source,target}` (channel-full drops, `ParquetWriterHandle::try_send`), `parquet_s3_buffer_dropped{source,target}` (hard-cap drops, `drop_oldest_to_cap`), `parquet_s3_partitions_capped{source,target}`, plus format-specific counters (`ipfix_datagrams_received`, `ipfix_decode_errors`, `ipfix_templates_dropped`/`_missing`, `syslog_messages_received`, `syslog_parse_errors`, `syslog_oversized_lines`, `syslog_tcp_connections_rejected`) | Yes — this, not `/stats.json`, is the authoritative source for drop-rate and error-rate during a load test, since `/stats.json` only tracks successfully-pushed records, not drops |
| Existing backpressure unit tests as the contract to validate at scale | `push_enforces_hard_cap_on_flush_failure` (`src/forwarding/buffered_writer.rs:874`), `writer_bounded_under_s3_outage` (`src/forwarding/zeek_s3.rs:571`), `handler_overflow_increments_dropped_counter` (`src/forwarding/zeek_s3.rs:645`, `src/forwarding/ipfix_s3.rs:548`, `src/forwarding/suricata_s3.rs:351`) | These prove `try_send`/hard-cap semantics at handful-of-records scale; a perf harness is the natural place to prove the **same** semantics hold under real load (thousands of records/sec, real channel depths) |

**Important constraint discovered:** `LocalDiskSink` (`src/forwarding/local_sink.rs`) is only wired for **Zeek** so far (`ZeekConfig.local: Option<ZeekLocalConfig>`, per `docs/superpowers/specs/2026-07-04-local-disk-output-target-design.md`). No other source (`suricata`, `ipfix`, `syslog`, `structured_syslog`, `sflow`, `generic`/HEC, `wef`) has a `.local` config path yet — confirmed by grepping `src/config/mod.rs` for `LocalConfig` structs. This directly affects the "test environment" recommendation below.

## 3. Format inventory: transport, port/route, and cost profile

Verified against `src/config/mod.rs` defaults and each source's listener/forwarding module:

| Format | Transport | Default port/route | Partitioning (`max_partitions`) | Parsing cost notes |
|---|---|---|---|---|
| syslog | UDP + TCP | `udp_port=514`, `tcp_port=601` (`SyslogConfig`) | 1 (`syslog_s3.rs:191`, single buffer) | RFC3164/5424 header parse always; `parse_payloads=true` (`src/syslog/listener.rs:57`) additionally runs a try-chain of 6 sub-parsers (`src/syslog/payload/{cef,leef,auditd,dhcp,radius,web_access}.rs`, plus DNS) per message until one matches — meaningfully heavier than raw pass-through |
| IPFIX | UDP | `udp_port=4739` (`IpfixConfig`) | 1 (`ipfix_s3.rs:284`, single buffer) | Binary decode with a bounded template cache (`src/ipfix/decoder.rs`, `MAX_CACHED_TEMPLATES`); cost is dominated by template-lookup-per-record plus template churn (new/changing templates evict/warn) |
| Zeek | TCP NDJSON | `tcp_port=47760` (`ZeekConfig`) | 256 (`DEFAULT_MAX_ZEEK_PARTITIONS`, `zeek_s3.rs:214`), partitioned by `_path` (conn/dns/http/ssl/files/notice/...) | JSON-per-line parse; genuinely multi-partition/high-cardinality — this is the format to stress partition-cap (`_overflow`) behavior on |
| Suricata | TCP EVE JSON | `tcp_port=47761` (`SuricataConfig`) | 256 (`DEFAULT_MAX_SURICATA_PARTITIONS`, `suricata_s3.rs:139`), partitioned by `event_type` | JSON-per-line parse; same high-cardinality partition shape as Zeek |
| sFlow | UDP | `udp_port=6343` (`SflowConfig`) | 2 (`sflow_s3.rs:269`, fixed "flow"/"counter") | Binary UDP decode, but *not* high-cardinality despite being UDP — good contrast case against IPFIX (also UDP, also single/low-cardinality) |
| generic/HEC | HTTP | `/services/collector/event`, `/services/collector/raw`, `/ingest` (mounted on the main HTTP listener, `bind_address` default `0.0.0.0:5985`, gated by `HecConfig.enabled`) | `max_sourcetype_partitions` default 64, **configurable** (`src/config/mod.rs:532`) | JSON body parse + sourcetype extraction/partition; cardinality is operator-controlled, useful for a targeted "cardinality sweep" test |
| OTLP | HTTP | `/v1/logs` (feature-gated by the `otlp` Cargo feature — on by default — and `OtlpConfig.enabled`) | Same as generic — `map_otlp_request` (`src/server/otlp.rs`) converts to `GenericRecord`s with `sourcetype="otlp"` and shares `GenericSink`'s partitioning | Protobuf/JSON decode via `opentelemetry-proto`; effectively rides the *same* writer pipeline as HEC, so OTLP vs HEC comparison isolates "protobuf decode overhead" specifically, not writer-path differences |
| (WEF — present in the codebase via `src/protocol`, `WefConfig`/`WefS3Config`, routes `/wsman`, `/wsman/events`, but not in this task's requested format list) | HTTP | main listener | own partitioning | out of scope per the prompt; noted only because the stale `performance-test/` harness targets it |

**Comparability implication:** syslog and IPFIX are the fairest "apples to apples" single-partition comparison (both max_partitions=1). Zeek and Suricata are the fairest high-cardinality comparison (both max_partitions=256, both NDJSON-per-line). sFlow is UDP but low-cardinality — a useful third axis (transport cost without partition-fanout cost). HEC and OTLP share the *identical* writer/partition path, so any throughput delta between them isolates parsing cost, not persistence-path cost — this pairing is the built-in "control" of the whole suite.

## 4. Goals & metrics

For each of the 7 requested formats, capture:

1. **Ingest throughput**: records/sec and bytes/sec accepted by the listener (`syslog_messages_received`, `ipfix_datagrams_received`/`ipfix_flows_decoded`, or — for formats without a dedicated received-counter today — HTTP response counts client-side).
2. **Write throughput**: `parquet_s3_records_written{source,target}` rate — this is "durably flushed," not just "accepted," and is what differs under backpressure.
3. **Ingest→flush latency**: not directly instrumented today (no histogram exists on the flush path). Proposal: measure it externally, by embedding a monotonically increasing sequence number or timestamp in synthetic records and diffing "record generated at T0" against "record observed in a Parquet file at T1" (read back via the existing MinIO-verifier pattern, e.g. `tests/e2e/simulation-environment/ipfix-s3-verifier/entrypoint.py`, or a local-disk directory scan for LocalDiskSink). This is a load-test-side responsibility, not a new server metric — do not add a histogram to `buffered_writer.rs` as part of this first deliverable; that's separately scoped work if warranted.
4. **Drop rate under backpressure**: `parquet_s3_dropped` (channel-full, `try_send` in `ParquetWriterHandle`) and `parquet_s3_buffer_dropped` (hard-cap-triggered, `drop_oldest_to_cap`) — both already labeled by `source`/`target`, zero new instrumentation needed.
5. **Partition-cardinality behavior**: `parquet_s3_partitions_capped{source,target}` — should stay at 0 for syslog/IPFIX/sFlow (impossible to exceed 1-2 partitions) and should be deliberately exercised for Zeek/Suricata/HEC by generating traffic with more distinct partition keys than `max_partitions` (Zeek/Suricata: >256 distinct `_path`/`event_type` values is unrealistic for real traffic but useful as a stress/abuse test; HEC is the more realistic case since `max_sourcetype_partitions` is config-adjustable and multi-tenant HEC deployments plausibly hit it).
6. **Resource usage under sustained load**: process RSS and CPU% sampled externally (`ps`/`/proc/<pid>/status` polling, or `cargo flamegraph --profile profiling` for CPU-by-function — reusing `[profile.profiling]`). No new in-process instrumentation needed for a first pass.

## 5. Load generation approach

**Recommendation: a new Rust binary, not a Python script and not `criterion`.**

Reasoning:
- **Why not `criterion`/`benches/`**: criterion measures in-process function-call latency/throughput (µs-scale, single-threaded, warms up and takes statistical samples). It's the right tool for e.g. "how fast is `to_record_batch` for a Zeek conn record" or "how fast is the IPFIX decoder for one datagram" — and *should* be added separately as a normal Rust unit-level microbenchmark tier (fast, could even run in CI) — but it cannot exercise a real UDP/TCP/HTTP listener, a real bounded mpsc channel, or real backpressure/drop behavior, which is what this task is actually about. Recommend `criterion` as a **follow-on**, not as the vehicle for this plan.
- **Why not extend the existing Python generators**: they prove correctness (a handful of records, once) and the one Python component that *does* do load (`performance-test/entrypoint.py`) tops out at ~9-10k events/sec using batched HTTP requests, which is plausible for HEC/OTLP/generic (Python `requests` overhead dominates at that end anyway) but almost certainly not achievable for raw UDP packet floods needed to seriously stress syslog-UDP/IPFIX/sFlow — Python's per-`sendto()` syscall overhead and GIL make sustained multi-hundred-thousand-pps UDP floods impractical without dropping into `asyncio` + `sendmmsg`-style tricks that Rust/tokio gives for free. Given the repo is 100% Rust/tokio already (`tokio = { version = "1.35", features = ["full"] }` is already a dependency), a Rust load generator is the lower-effort, higher-ceiling choice.
- **Where it lives**: a new `[[bin]]` is unnecessary complexity for something that isn't shipped — propose a workspace-adjacent standalone crate or, more simply, a directory of small binaries under `tools/loadgen/` (new top-level dir, sibling to `scripts/`) built as its own `cargo` package with a path-dependency on `logthing` as a library (the crate is already both a library and binary per `src/lib.rs` — see `AGENTS.md` §6 note "the crate is both a library and a binary"), so the load generator can reuse real wire-format encoders (e.g. build actual `FlowRecord`-shaped IPFIX bytes, actual Zeek NDJSON matching `ZeekRecord` field names) instead of hand-rolling byte layouts a second time in a different language. Each subcommand targets one format: `loadgen syslog-udp`, `loadgen ipfix`, `loadgen zeek`, `loadgen suricata`, `loadgen sflow`, `loadgen hec`, `loadgen otlp`, with shared flags (`--target-rate`, `--duration`, `--concurrency`, `--partition-cardinality` for the multi-partition formats).
- Each subcommand should be independently runnable (`cargo run -p loadgen -- syslog-udp --host 127.0.0.1 --port 514 --rate 50000 --duration 60s`) so a single format can be exercised without booting the whole suite — directly supporting the "concrete first deliverable" requirement below.

## 6. Test environment: local-disk vs S3/MinIO

**Recommendation: local disk (`LocalDiskSink`) as the default persistence target for throughput/latency/drop-rate measurement; MinIO reserved for a smaller "confirm S3 path doesn't fall over" pass.**

Reasoning:
- The whole point of separating ingestion-path perf from the sink is stated directly in the existing S3-outage tests (`writer_bounded_under_s3_outage`, `src/forwarding/zeek_s3.rs:571`): the buffering/flush/cap machinery is deliberately decoupled from upload success/failure via `try_send` + hard caps, specifically so a slow/unreachable sink degrades gracefully rather than propagating backpressure to the listener. A performance test that always writes to MinIO conflates "how fast can this format be ingested and buffered" with "how fast is this MinIO container, this Docker network hop, this AWS SDK client" — variables the ingestion path doesn't control and that the existing tests already prove are decoupled.
- **Blocker to flag explicitly**: `LocalDiskSink` is only wired for Zeek today. To run this plan's methodology uniformly across all 7 formats, the mechanical `.local` wiring for the remaining 6 sources (suricata, ipfix, syslog, sflow, generic/HEC — structured_syslog and WEF are out of this task's scope) needs to land first. The prior spec explicitly calls this out as "a mechanical follow-on once this lands: a new `XxxLocalConfig` struct, a `local` field on the top-level config, a `xxx_local_start` sibling function, and a `main.rs` wiring block — the same shape as this spec's Zeek changes" (`docs/superpowers/specs/2026-07-04-local-disk-output-target-design.md`, §2). This plan treats that wiring as a **prerequisite work item**, sequenced before "run the full 7-format suite," not as part of this design.
- MinIO is still worth keeping in the loop for one narrower purpose: confirming that under the load levels found via local-disk testing, the S3 path's `flush_partition` (`src/forwarding/buffered_writer.rs`) doesn't introduce upload-error rates or additional drops beyond what local-disk showed — i.e., a smaller "S3 target sanity pass," reusing the exact `docker-compose.yml`/MinIO credentials pattern already in `tests/e2e/simulation-environment/docker-compose.yml`, run at a fixed moderate rate (not a ceiling-finding exercise).

## 7. Comparability methodology

Don't report a single "records/sec" leaderboard across formats — it will mislead (IPFIX UDP decode cost is not commensurate with a Zeek JSON-line parse). Instead:

1. **Group by architecture, not alphabetically**: (a) single-partition, non-JSON — syslog (UDP raw), IPFIX; (b) high-cardinality JSON-line — Zeek, Suricata; (c) HTTP/JSON request-based, shared writer path — generic/HEC, OTLP; (d) UDP binary, low-cardinality — sFlow (its own group, contrast point against IPFIX).
2. **Report two numbers per format, not one**: "ingest accept rate" (listener-level, before parsing cost is fully paid) and "durable write rate" (`parquet_s3_records_written`) — the gap between them, if any, localizes whether a bottleneck is parse-side or writer-side.
3. **Normalize by payload bytes, not just record count**, for any format where average record size varies a lot by content (structured syslog sub-parsers produce very different field counts than raw syslog; Zeek `conn` vs `notice` records differ in size) — report both records/sec and MB/sec.
4. **Use HEC vs OTLP as the built-in control**: since both map to `GenericRecord` and share `GenericSink`'s partitioning (`src/server/otlp.rs`'s `map_otlp_request`), any throughput delta between them isolates *decode* cost (JSON parse+sourcetype extraction vs protobuf-via-`opentelemetry-proto`) with the writer path held constant — call this out explicitly in the results write-up rather than letting it look like an unexplained outlier.
5. **Never compare absolute numbers across a run that changed `flush_threshold_bytes`/`max_buffer_rows`/`channel_capacity`** — these are per-source, independently tunable (`BufferedWriterConfig`, defaults: `max_buffer_rows=100_000`, `flush_threshold_bytes=128 MiB`, `flush_interval_secs=900`, `channel_capacity=8_192`) and materially change when flushes happen; pin them to the same values (or explicitly document the deltas) across formats being compared.

## 8. Where this lives

**Recommendation: a new, separately-invoked tier — not part of the unit/integration/e2e three-tier model, and not run on every CI push.**

- The existing testing policy's three tiers (unit/integration/e2e) exist to validate *correctness* of new behavior on every change, with a cost/duration budget appropriate to "run on every push" (`rust.yml` currently does exactly `cargo build` + `cargo test` + `fmt`/`clippy` on push/PR to `master`, no `workflow_dispatch`). Sustained-load performance runs (tens of seconds to minutes per format, times 7+ formats, times however many load levels) do not fit that budget and measure a different thing (throughput/latency/resource-usage, not pass/fail correctness) — conflating them would slow down every PR for a signal most PRs don't move.
- Concretely: add `tools/loadgen/` (the new Rust load-generator crate, §5) plus a `docs/performance/` (or `tests/perf/`) directory holding methodology notes and dated result reports, and a **new**, manually-triggered GitHub Actions workflow (`.github/workflows/performance.yml`) using `workflow_dispatch` (mirroring the existing pattern in `.github/workflows/binaries.yml`, the only workflow that already has `workflow_dispatch`), so it can be run on demand (e.g. before a release, or when touching `buffered_writer.rs`) without gating every push.
- Keep `criterion`-style microbenchmarks (§5) as an optional, faster, CI-eligible *sibling* tier if/when someone wants function-level regression tracking (e.g. "did the IPFIX decoder get slower") — that's cheap enough to run on every push and is a different question than this plan answers.

## 9. Concrete first deliverable

Don't build all 7 format generators before learning anything. First increment:

1. **`tools/loadgen` crate scaffold** with exactly one working subcommand: `syslog-udp` (simplest transport — UDP, no connection/handshake state — and the most standardized wire format, so correctness of the generated messages is easy to eyeball against `src/syslog/mod.rs`'s `parse()`). Flags: `--host`, `--port` (default 514, matching `default_syslog_udp_port()`), `--target-rate`, `--duration`, `--structured` (toggle between raw RFC3164 messages and ones that will match one of the `src/syslog/payload/*` sub-parsers, to get an early read on the `parse_payloads=true` cost delta described in §3).
2. **Wire `.local` for syslog specifically** if not already prioritized elsewhere (small, mechanical, per the existing spec's own description of the pattern) — or, as a zero-code-change fallback for this first pass, run against a local MinIO one-off and explicitly caveat the result as "includes S3 network overhead" if `.local` wiring hasn't landed yet when this deliverable starts.
3. **Baseline run**: start `logthing` (from `[profile.profiling]` build), run `loadgen syslog-udp --target-rate <sweep: 10k, 50k, 100k, unbounded> --duration 60s`, and capture:
   - `syslog_messages_received`, `syslog_parse_errors`, `syslog_oversized_lines` rate deltas via `:9090/metrics`,
   - `parquet_s3_records_written{source="syslog"}` and `parquet_s3_dropped{source="syslog"}` rate deltas via `:9090/metrics`,
   - `/stats.json` polled every 5s as the cheap live-rate sanity check,
   - RSS/CPU sampled externally during the run.
4. **Write up the methodology doc** (this plan, refined with the actual numbers from step 3) as the template the other 6 formats' generators follow — at that point, adding `ipfix`, `zeek`, `suricata`, `sflow`, `hec`, `otlp` subcommands to the same `loadgen` binary is mechanical repetition of a proven pattern, matching how this codebase already scopes increments (per-source mechanical follow-ons are the established pattern — see `docs/superpowers/specs/2026-07-04-local-disk-output-target-design.md`'s own explicit "Explicitly out of scope this increment" list).

---

### Critical Files for Implementation

- /home/dev/projects/logthing/src/forwarding/buffered_writer.rs
- /home/dev/projects/logthing/src/config/mod.rs
- /home/dev/projects/logthing/src/stats/mod.rs
- /home/dev/projects/logthing/tests/e2e/simulation-environment/docker-compose.yml
- /home/dev/projects/logthing/Cargo.toml
