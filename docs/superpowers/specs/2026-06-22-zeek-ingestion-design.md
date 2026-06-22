# Zeek NDJSON Ingestion → Typed Parquet/S3 — Design

**Date:** 2026-06-22
**Status:** Approved (design), pending spec review → implementation plan
**Branch:** `feat/zeek-ingestion`
**Related:** `2026-06-22-zeek-ingestion-options.md` (options analysis; this spec implements **Option C — NDJSON-over-TCP intake**).

## Goal

Ingest Zeek (network security monitor) log output into `logthing` over a TCP
newline-delimited-JSON stream, decode each record by its Zeek stream type, and
persist it to S3 as typed Parquet — adding Zeek as a first-class ingestion
source alongside WEF, syslog, and IPFIX.

## Locked decisions

| Topic | Decision |
|-------|----------|
| Transport | TCP only, plaintext, newline-delimited JSON (NDJSON). One record per line. |
| Schema strategy | Per-stream **typed** Arrow schemas for a curated core; generic envelope fallback for unmodeled streams. |
| Curated streams | `conn`, `dns`, `http`, `ssl`, `files`, `notice`. |
| Drift robustness | Each typed schema carries a catch-all `_extra` JSON column; best-effort typed extraction (type mismatch → `_extra`, never panics/drops). |
| Stream identification | Each JSON record's `_path` field (Zeek/​shipper-provided); absent → `"unknown"` → fallback schema. |
| S3 layout | Partitioned by stream: `zeek/<log_path>/year=…/month=…/day=…/<uuid>.parquet`. |
| Persistence | Per-`log_path` Parquet writers sharing the existing `S3Sink`; gated by optional `[zeek.s3]` config. |

## Non-goals

- TLS/UDP transport for the first cut (TCP plaintext only; TLS is a documented follow-on).
- Tailing Zeek log files or consuming Zeek's Kafka output (Options A/B in the options doc — future).
- Typed schemas beyond the curated six (unmodeled streams use the envelope fallback; more can be promoted later).
- Parsing Zeek's TSV/ASCII format (JSON/NDJSON only — the shipper or Zeek's JSON writer produces JSON).
- Reconstructing Zeek streams from raw pcap or running Zeek itself.

## Architecture

Mirrors the existing `src/ipfix/` source (listener + handler trait) and the
hardened per-source S3 writer pattern (`src/forwarding/ipfix_s3.rs`).

### New module: `src/zeek/`

**`src/zeek/mod.rs` — record type**

```text
ZeekRecord {
    log_path: String,            // from the record's `_path` field; "unknown" if absent
    fields: serde_json::Value,   // the full JSON object as received
    received_at: DateTime<Utc>,
}
```

**`src/zeek/listener.rs` — TCP listener + handler trait**

- `ZeekListenerConfig { tcp_port: u16, bind_address: String }` (TCP port has no
  Zeek convention; it is configurable and must match the shipper. Default is an
  arbitrary unused port, finalized in the plan, e.g. `47760`.)
- `ZeekListener` binds a `TcpListener` and, per connection, runs a
  `BufReader` + `read_line` loop modeled on
  `syslog::listener::handle_tcp_connection`. Each non-empty line is parsed with
  `serde_json::from_str::<serde_json::Value>`; the `_path` string field is
  extracted (→ `log_path`, `"unknown"` if missing/non-string); a `ZeekRecord`
  is built and dispatched to the handler.
- A **max line length** cap (e.g. 16 MiB) bounds memory against a pathological
  single line; lines exceeding it are skipped + counted.
- `ZeekHandler` trait: `async fn handle_record(&self, record: ZeekRecord, source: SocketAddr)`
  — single-record dispatch, one call per NDJSON line. `DefaultZeekHandler` logs a
  summary + increments metrics. The S3-persisting handler arrives via `[zeek.s3]` config.

**`src/zeek/schema.rs` — typed schema registry**

- A registry mapping `log_path → (Arc<arrow_schema::Schema>, row-mapper)`.
- Six typed schemas (`conn`, `dns`, `http`, `ssl`, `files`, `notice`). Each
  promotes that stream's common, documented fields to typed Arrow columns and
  appends a catch-all **`_extra`** `Utf8` column holding a JSON object of all
  fields not promoted. Representative promoted columns (exact sets finalized in
  the plan from Zeek's documented log formats):
  - `conn`: `ts, uid, id_orig_h, id_orig_p, id_resp_h, id_resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state, history, orig_pkts, resp_pkts, _extra`
  - `dns`: `ts, uid, id_orig_h, id_orig_p, id_resp_h, id_resp_p, proto, trans_id, query, qtype_name, qclass_name, rcode_name, answers, _extra`
  - `http`: `ts, uid, id_orig_h, id_orig_p, id_resp_h, id_resp_p, method, host, uri, status_code, user_agent, _extra`
  - `ssl`: `ts, uid, id_orig_h, id_orig_p, id_resp_h, id_resp_p, version, cipher, server_name, _extra`
  - `files`: `ts, fuid, tx_hosts, rx_hosts, source, mime_type, filename, total_bytes, _extra`
  - `notice`: `ts, uid, id_orig_h, id_orig_p, id_resp_h, id_resp_p, note, msg, sub, _extra`
- **Generic envelope fallback schema** for any `log_path` not in the registry:
  `ts, uid, id_orig_h, id_orig_p, id_resp_h, id_resp_p, log_path, ingest_time, payload`
  (where `payload` is the full JSON object as `Utf8`).
- **Row mapping is best-effort and total:** for each promoted column, read the
  field from the JSON value; if absent → null; if present but the JSON type
  does not match the column type → omit the typed column (null) and retain the
  raw value inside `_extra`. Every field not mapped to a typed column is written
  to `_extra`. The mapper never panics and never drops a field.

### Persistence: `src/forwarding/zeek_s3.rs`

- `ZeekS3Writer` maintains a **map of `log_path → per-stream buffer**, each
  buffer carrying that stream's `Arc<Schema>` (typed or fallback). It mirrors
  the hardened `ipfix_s3` writer: `VecDeque` of `(RecordBatch, est_bytes)`,
  size/time flush via `flush_check_interval(config.flush_interval)`, a hard
  buffer cap with `drop_oldest_to_cap` + `zeek_s3_buffer_dropped`, and uploads
  to `zeek/<log_path>/year=…/…parquet` through the shared `S3Sink`.
- `ZeekS3Handler` implements `ZeekHandler` with a bounded `mpsc` channel;
  overflow drops + `zeek_s3_dropped`. `start_with_capacity(config, sink, capacity)`
  with `start` delegating to it (matching ipfix/syslog).

### Configuration (`src/config/mod.rs`)

- `[zeek]`: `enabled` (default false), `tcp_port` (default per plan),
  `bind_address` (default `0.0.0.0`).
- `[zeek.s3]`: `#[serde(flatten)] connection: S3ConnectionConfig` +
  `prefix` (default `"zeek"`) + `flush_threshold_bytes` + `flush_interval_secs`
  + `channel_capacity` + `max_buffer_rows` — same shape/defaults as
  `[ipfix.s3]`. Absent `[zeek.s3]` ⇒ no persistence (`DefaultZeekHandler`).

### Wiring

- `src/main.rs`: conditional spawn of the Zeek listener when `config.zeek.enabled`,
  choosing `ZeekS3Handler` when `[zeek.s3]` is present (falling back to
  `DefaultZeekHandler` on `S3Sink` construction failure), else `DefaultZeekHandler`
  — mirroring the syslog/ipfix wiring.
- `src/lib.rs`: add `pub mod zeek;`.

## Data flow

```text
TCP NDJSON line
  → serde_json parse → extract _path → ZeekRecord{log_path, fields, received_at}
  → ZeekHandler
      DefaultZeekHandler: log + metrics
      ZeekS3Handler: bounded channel → ZeekS3Writer
          look up schema by log_path (typed registry or fallback)
          map JSON → RecordBatch (best-effort typed + _extra)
          append to that log_path's buffer; flush by size/time
          Parquet → S3Sink.upload("zeek/<log_path>/year=…/…parquet")
```

## Error handling

- **Malformed JSON line** → `zeek_parse_errors` counter + `warn`; the connection
  continues (one bad line does not drop the stream).
- **Oversized line** (> cap) → `zeek_oversized_lines` counter + skip.
- **Missing/`non-string `_path`** → `zeek_missing_path` counter; routed to the
  fallback schema under `zeek/unknown/`.
- **Type-mismatched fields** → captured in `_extra` (see mapping rules); never a
  hard error.
- **S3 upload failure / backpressure** → bounded buffers + drop counters,
  isolated per source; never blocks the listener (same as ipfix/syslog).
- The listener and mapper must be panic-free on arbitrary/hostile input.

## Observability (metrics, via the `metrics` crate)

`zeek_records_received`, `zeek_parse_errors`, `zeek_oversized_lines`,
`zeek_missing_path`, per-stream `zeek_records_by_path` (labeled by `log_path`),
and the writer counters `zeek_s3_records_written`, `zeek_s3_uploads`,
`zeek_s3_upload_errors`, `zeek_s3_dropped`, `zeek_s3_buffer_dropped`.

## Testing (three levels — required)

- **Unit:**
  - Listener/parse: `_path` extraction; missing/non-string `_path` → `"unknown"`;
    malformed line handling; oversized-line handling.
  - Schema/mapping: for each of the six typed schemas, build a known JSON record
    and assert the produced Arrow columns + types, `_extra` capture of
    non-promoted fields, null handling for absent fields, and
    type-mismatch → `_extra`. Fallback envelope schema for an unknown stream.
    Parquet round-trip (encode → re-read) per schema.
- **Integration:**
  - TCP listener: connect, send NDJSON lines (incl. multiple streams + an
    unknown stream + a malformed line), assert the test handler receives the
    expected `ZeekRecord`s and the malformed line is counted not fatal.
  - `ZeekS3Writer`: feed records of several `log_path`s → assert per-stream
    Parquet objects appear under `zeek/<log_path>/` against the faked/local S3
    (MinIO) approach used by `parquet_s3`/`ipfix_s3` tests; overflow drop path.
- **End-to-end:** a `zeek-generator` container streams sample NDJSON (`conn`,
  `dns`, and one unmodeled stream, plus a malformed line) over TCP to the
  running server with `[zeek.s3]` enabled; a verifier confirms Parquet objects
  under `zeek/conn/`, `zeek/dns/`, and `zeek/unknown/` with the expected
  schemas. Added to `tests/e2e/simulation-environment/` mirroring the
  `ipfix-generator` / `ipfix-s3-verifier` services.

## Files (summary)

- Create: `src/zeek/mod.rs`, `src/zeek/listener.rs`, `src/zeek/schema.rs`,
  `src/forwarding/zeek_s3.rs`, and the e2e `zeek-generator` / `zeek-s3-verifier`
  harness files.
- Modify: `src/config/mod.rs` (`[zeek]`, `[zeek.s3]`), `src/main.rs` (spawn +
  handler selection), `src/lib.rs` (`pub mod zeek`), `src/forwarding/mod.rs`
  (module decl), and the docs (`README.md`, `AGENTS.md` structure,
  `IMPLEMENTATION.md`, a `ZEEK_IMPLEMENTATION.md`).

## Trade-off accepted

Per-stream typed schemas (the chosen route) give faithful, queryable columns but
require maintaining a schema registry that can drift with Zeek versions. The
`_extra` catch-all column and the best-effort/total mapping rule absorb that
drift without data loss; the curated-six scope keeps the registry small, and the
envelope fallback guarantees unmodeled streams are still captured.
