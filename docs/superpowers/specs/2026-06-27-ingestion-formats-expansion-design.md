# Ingestion Formats Expansion — Design Spec

**Date:** 2026-06-27
**Branch:** `feat/ingestion-formats-expansion`
**Status:** Approved (auto-develop coherence review: coherent=true; all five reviewer concerns resolved inline below)

## 1. Goal

Add nine new log/event input formats to logthing, matching the existing
ingestion architecture exactly. Every new format reuses one of four
established mechanisms — there is no new architectural primitive.

Formats (by tier, all in scope):

- **Tier 1:** Suricata EVE JSON, CEF, LEEF
- **Tier 2:** sFlow, Linux auditd
- **Tier 3:** Generic JSON-over-HTTP (Splunk HEC), web access logs
  (Nginx/Apache combined), DHCP, RADIUS, OTLP logs

## 2. Decomposition — formats onto existing mechanisms

| Mechanism (existing exemplar) | New formats | Pattern source |
|---|---|---|
| NDJSON-over-TCP listener | Suricata EVE JSON | `src/zeek/listener.rs` |
| Syslog-embedded payload parser | CEF, LEEF, auditd, web access, DHCP, RADIUS | `src/syslog/mod.rs` DNS try-chain |
| UDP binary decoder | sFlow | `src/ipfix/listener.rs` |
| HTTP route on existing server | Generic JSON (HEC), OTLP logs | `src/server/mod.rs` `POST /syslog` |

Shared infrastructure reused by all units:

- `ParquetSink` trait + `ParquetWriterHandle` (bounded `try_send` channel →
  buffer → Parquet → S3), with `<fmt>_start(cfg, sink)` constructors.
- `main.rs` spawn template: `if config.<fmt>.enabled { build handler (S3 →
  fallback default) → tokio::spawn(listener.start_with_shutdown(rx)) → push
  JoinHandle }`.
- Per-listener config struct with `enabled`, ports/bind, `s3: Option<…>`.
- Graceful shutdown via `watch::Receiver<bool>`; per-format metrics
  (`metrics::counter!`); warn-and-drop on parse failure / channel full.

## 3. Work units

Five independently-shippable units, implemented in tier order. Each is a
distinct module/file set, separately testable, with no shared mutable state.

### Unit 1 — Suricata EVE JSON (`src/suricata/`)

- Clone the Zeek TCP NDJSON listener. One JSON object per line.
- Discriminator: the `event_type` field (Suricata's equivalent of Zeek's
  `_path`). Fallback to `"unknown"` when absent.
- Record: `SuricataRecord { event_type: String, fields: serde_json::Value,
  received_at: DateTime<Utc> }`.
- `SuricataHandler` async trait `handle_record(SuricataRecord, SocketAddr)`;
  `DefaultSuricataHandler` logs; `SuricataSink: ParquetSink` partitions by
  `event_type` with an envelope fallback schema (Zeek envelope pattern).
- Config `[suricata]`: `enabled` (default false), `tcp_port` (default
  **47761**), `bind_address` (default `0.0.0.0`), `s3: Option<SuricataS3Config>`.
- Wire into `main.rs` following the Zeek block.

### Unit 2 — Syslog-embedded payload parsers (`src/syslog/payload/`)

New submodule, one file per format, each exposing
`try_parse(&SyslogMessage) -> Option<Payload>`:

- `cef.rs` — `CEF:Version|Vendor|Product|Version|SigID|Name|Severity|ext…`
  (prefix-anchored; pipe-split header + `k=v` extension map).
- `leef.rs` — `LEEF:Version|Vendor|Product|Version|EventID|<delim>k=v…`
  (prefix-anchored; tab/configurable-delimited attributes).
- `auditd.rs` — `type=… msg=audit(<ts>:<id>): k=v …` single-record parse.
  **Scope guard:** single-record only; no multi-line event reassembly in v1.
- `web_access.rs` — Apache/Nginx **combined** log format (regex).
- `dhcp.rs` — ISC DHCP (`DHCPACK/OFFER/REQUEST on <ip> to <mac> via <if>`).
- `radius.rs` — FreeRADIUS auth accept/reject lines.

Dispatcher `payload::dispatch(&SyslogMessage) -> SyslogPayload` tries parsers
in priority order: prefix-keyed first (CEF, LEEF — unambiguous), then
`key=value` (auditd), then regex line formats (dhcp, radius, web_access),
then the existing DNS chain (folded in as a variant calling the current
`DnsLogEntry::from_*` fns), else `SyslogPayload::None`. Returns a
`SyslogPayload` enum with one variant per format.

**Output model (resolves reviewer Concern B/2 — supplement, not replace):**

- The existing `SyslogSink` is **unchanged**: every syslog message continues
  to be persisted there raw. **Zero data loss; unrecognized messages are
  unaffected.**
- A **new** `StructuredSyslogSink: ParquetSink` *additionally* receives only
  messages that a parser matched. It partitions by `payload_type`
  (`cef`/`leef`/`auditd`/`dhcp`/`radius`/`web_access`/`dns`) with a common
  envelope schema: standard syslog columns + a `parsed` JSON-string column
  holding the extracted fields. No bespoke typed Arrow schema per format in
  v1 (JSON bag; promote to typed columns later).
- `max_partitions` is bounded (7 known + `_overflow`), consistent with the
  Zeek sink.

The syslog handler is extended to call `dispatch()` and, on a non-`None`
result, `try_send` the structured record to the `StructuredSyslogSink` handle
(when configured). Config `[syslog]` gains `parse_payloads: bool` (default
false) and an optional `structured_s3: Option<...S3Config>`.

### Unit 3 — sFlow (`src/sflow/`)

- Clone the IPFIX UDP listener (`recv_from` loop, 65 KB buffer). Default UDP
  port **6343** (IANA). `SflowHandler::handle_samples(Vec<SflowRecord>,
  SocketAddr)`.
- Decoder (sFlow v5 datagram):
  - **Flow samples:** decode the raw-packet-header record →
    Ethernet/IP/TCP-UDP **5-tuple**; decode sampled IPv4/IPv6 records.
  - **Counter samples:** decode the **generic interface counters** record
    (fixed layout: ifIndex, ifType, ifSpeed, ifDirection, ifStatus, in/out
    octets/packets/errors/discards, etc.).
  - **Scope guard (resolves Concern D/3):** vendor/enterprise-specific
    counter records and other non-generic record types are **not** decoded —
    stored as raw `{ format, length, data_base64 }` in the JSON `extra`
    field. No deep packet decode beyond the 5-tuple.
- Record: `SflowRecord { sample_type: SampleType (Flow|Counter), exporter,
  received_at, curated fields…, extra: JsonValue }`.
- `SflowSink: ParquetSink` partitions by `sample_type` (`flow` / `counter`).
- Config `[sflow]`: `enabled`, `udp_port` (default 6343), `bind_address`,
  `s3: Option<SflowS3Config>`. Wire into `main.rs` following the IPFIX block.
- **Risk note:** largest single unit (binary protocol decode); flagged
  low-confidence in review. Isolated so it can be cut/deferred without
  affecting the other units if it overruns.

### Unit 4 — Generic JSON-over-HTTP / Splunk HEC (`src/ingest/` + `src/server/`)

- New Axum routes on the **existing** server (port 5985, reusing TLS +
  IP-whitelist + body-limit middleware):
  - `POST /services/collector/event` — HEC event envelope
    (`{"event":…,"time":…,"host":…,"sourcetype":…}`), one or many
    (newline-delimited) events.
  - `POST /services/collector/raw` — raw body → single event.
  - `POST /ingest` — plain NDJSON, HEC-without-envelope.
- Auth: configurable HEC token compared against `Authorization: Splunk
  <token>` (constant-time compare). Behind existing IP whitelist + TLS.
- Record: `GenericRecord { sourcetype: String, host: Option<String>, time:
  Option<DateTime<Utc>>, fields: serde_json::Value, received_at }`.
- `GenericSink: ParquetSink` partitions by `sourcetype`.
  **Resolves Concern F/4:** cap at `max_sourcetype_partitions` (config,
  default **64**) with an `_overflow` partition (Zeek overflow pattern) to
  bound the partition map against arbitrary client `sourcetype` values.
- **Wiring (resolves Concern H/5):** new routes carry a separate
  `IngestState` Axum extension holding `Option<GenericS3Handler>` and
  `Option<OtlpS3Handler>` (Unit 5). The WEF `AppState.parquet_s3_sender` is
  **not** overloaded. `IngestState` is constructed in `main.rs` from config
  and injected as an extension layer on the protected router.
- Config `[hec]`: `enabled`, `token`, `max_sourcetype_partitions`,
  `s3: Option<HecS3Config>`.

### Unit 5 — OTLP logs (`src/server/` route, feature-gated)

- New route `POST /v1/logs` accepting OTLP/HTTP **protobuf**
  (`ExportLogsServiceRequest`); JSON encoding accepted opportunistically via
  the same message types.
- **Build system (resolves Concern E/1):** gate the whole unit behind a
  Cargo feature **`otlp`** (default-on). Use the **`opentelemetry-proto`**
  crate's **pre-generated** prost message types — **no local `protoc` /
  `build.rs` codegen is added**. If the feature is disabled the route and
  dep drop out cleanly; the other eight formats are unaffected.
- Map each `LogRecord` (with resource/scope attributes flattened) →
  `GenericRecord` with `sourcetype = "otlp"` and reuse the Unit-4
  `GenericSink` (separate partition), or a dedicated `OtlpSink` if attribute
  shaping warrants it. Auth: optional bearer token; behind existing
  middleware. Carried via the same `IngestState`.
- gRPC transport (tonic) is **out of scope** (YAGNI).

## 4. Data flow (uniform across all units)

```
inbound (TCP line / UDP datagram / HTTP body)
  → parse/decode → typed Record
  → handler.try_send(record)            # bounded channel; warn+drop if full
  → ParquetWriterHandle buffers         # flush on rows/bytes/interval
  → Parquet encode → S3 PUT
```

Shutdown: `watch::Receiver<bool>` select-loop in each listener; writer
`JoinHandle`s awaited on drain. Errors: per-format `metrics::counter!`
(`<fmt>_parse_errors`, `<fmt>_dropped`, etc.); parse failures and full
channels warn-and-drop (existing convention) — never panic, never block.

## 5. Error handling & back-pressure

- Malformed input → metric increment + `warn!`, message skipped.
- Channel full → drop with `warn!` + dropped-counter (existing `try_send`
  pattern). No unbounded buffering.
- S3 sink construction failure at startup → fall back to the default
  (log-only) handler, listener still serves (existing pattern).

## 6. Testing (all three levels per format — global mandate)

- **Unit:** parser/decoder functions in-source (`#[cfg(test)]`): valid
  inputs, malformed inputs, edge cases, discriminator extraction. For CEF /
  LEEF / auditd / web-access / DHCP / RADIUS, table-driven sample lines. For
  sFlow, fixed byte-vector datagrams. For HEC/OTLP, sample bodies.
- **Integration:** `tests/<fmt>_s3_integration.rs`, MinIO-gated on
  `MINIO_ENDPOINT` (existing convention): `<fmt>_start` → feed records →
  assert Parquet objects land with the expected partition layout.
- **E2E:** drive the real outermost interface — bind the listener / mount the
  route on an ephemeral port, send real bytes over TCP/UDP/HTTP, assert the
  handler observed the parsed record. Where a level genuinely doesn't apply,
  state so explicitly.

## 7. Explicit scope guards (NOT building in v1)

- No OTLP **gRPC** (HTTP only); no `protoc`/`build.rs` codegen.
- No **GELF** (chunked-UDP) endpoint.
- No multi-line **auditd** event reassembly (single-record parse).
- No **bespoke typed Arrow schema** per syslog payload format (JSON `parsed`
  bag).
- No **deep packet decode** beyond the 5-tuple for sFlow; no vendor counter
  OID trees.
- No new TLS/auth/whitelist primitives — HTTP units reuse existing middleware.

## 8. Config surface summary (new sections)

```toml
[suricata]   enabled, tcp_port=47761, bind_address, [suricata.s3]
[syslog]     + parse_payloads=false, [syslog.structured_s3]
[sflow]      enabled, udp_port=6343, bind_address, [sflow.s3]
[hec]        enabled, token, max_sourcetype_partitions=64, [hec.s3]
[otlp]       enabled, bearer_token (optional)   # feature "otlp"
```

All new sections default to disabled — zero behavior change for existing
deployments until explicitly enabled.

## 9. Branch & integration

Work proceeds on `feat/ingestion-formats-expansion` (off `d5b2e64`). Each
unit is implemented by a leaf subagent in its own git worktree, with
two-stage review (spec-compliance then code-quality). The merge / PR decision
is returned to the user — no auto-merge to master.
