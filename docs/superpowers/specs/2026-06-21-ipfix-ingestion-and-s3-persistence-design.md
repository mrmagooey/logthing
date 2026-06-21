# IPFIX Ingestion + Generalized S3 Persistence (Option D) — Design

**Date:** 2026-06-21
**Status:** Approved (design), pending spec review → implementation plan
**Branch:** `feat/ipfix-s3-persistence`
**Related:** `2026-06-21-syslog-ipfix-s3-persistence-options.md` (options analysis; this spec implements **Option D**)

## Goal

Add IPFIX/NetFlow flow ingestion as a new source, and generalize the
existing S3 persistence so that syslog messages and IPFIX flow records can
be written to S3 as Parquet — without disturbing the working WEF → Parquet/S3
path.

## Locked decisions

| Topic | Decision |
|-------|----------|
| Protocol versions | IPFIX (v10, RFC 7011) + NetFlow v9 (RFC 3954) + NetFlow v5 (fixed legacy) |
| Transport | UDP only |
| IPFIX → Parquet schema | One fixed common-fields schema + a raw map/JSON column for non-curated fields |
| IE decoding coverage | Curated common subset (~30–50 IEs) with raw-bytes fallback for unknown elements |
| Persistence approach | Option D: shared `S3Sink` for plumbing; per-source Parquet writers each with their own fixed Arrow schema |

## Non-goals

- NetFlow over TCP/SCTP, or IPFIX template export over TCP.
- Per-template dynamic Parquet schemas (explicitly rejected in favor of the
  fixed common-fields schema).
- A full IANA IPFIX Information Element registry (only a curated subset).
- Enterprise-specific IE typed decoding (kept as raw bytes in the raw map).
- Generalizing the **HTTP** forwarding path (`Forwarder`); this work
  generalizes the **S3** path only.
- Persisting WEF events differently than today (WEF keeps its existing schema;
  it is only refactored to route its bytes through the shared `S3Sink`).

## Architecture

The design mirrors the existing `syslog` source (a UDP/TCP listener with a
handler trait — see `src/syslog/listener.rs`) and the existing Parquet/S3
forwarder (`src/forwarding/parquet_s3.rs`).

### New module: `src/ipfix/`

**`src/ipfix/mod.rs` — record types**

```text
FlowRecord {
    // identity / provenance
    observation_domain_id: u32,   // v9: source_id; v5: 0
    template_id: u16,             // v5: 0 (synthetic)
    protocol_version: u8,         // 5, 9, or 10
    exporter: IpAddr,             // datagram source address
    export_time: DateTime<Utc>,   // from message header
    // curated common flow fields (all Option<…>; presence depends on template)
    src_addr: Option<IpAddr>,
    dst_addr: Option<IpAddr>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    ip_protocol: Option<u8>,
    octet_delta_count: Option<u64>,
    packet_delta_count: Option<u64>,
    flow_start: Option<DateTime<Utc>>,
    flow_end: Option<DateTime<Utc>>,
    tcp_flags: Option<u8>,
    input_interface: Option<u32>,
    output_interface: Option<u32>,
    // everything else, keyed by IE name (or "ie<N>" / "ie<PEN>:<N>" when unknown)
    extra: serde_json::Value,     // JSON object; unknown values as hex strings
}
```

**`src/ipfix/decoder.rs` — version dispatch + template state**

- Entry point parses the common header version field (first `u16`, big-endian)
  and dispatches:
  - `10` → IPFIX message decode (RFC 7011 sets: template set id 2, options
    template set id 3, data sets id ≥ 256).
  - `9` → NetFlow v9 decode (FlowSet model; templates in flowset id 0,
    options templates id 1, data flowsets id ≥ 256). Keyed by `source_id`.
  - `5` → NetFlow v5 fixed-layout decode (no templates; fixed 24-byte header +
    N × 48-byte records). Synthesizes a `FlowRecord` directly.
- **Template cache** (stateful): `HashMap<TemplateKey, Template>` where
  `TemplateKey = (exporter: IpAddr, observation_domain_id: u32, template_id: u16)`.
  A `Template` is an ordered list of `(information_element_id, field_length,
  enterprise_number: Option<u32>)`. Data records are decoded against the
  matching template; if absent, the record set is skipped and counted.
- **Curated IE map:** a static table mapping IE id → (field name, value type)
  for ~30–50 common elements (e.g. 8 `sourceIPv4Address`, 12
  `destinationIPv4Address`, 27/28 IPv6 addresses, 7 `sourceTransportPort`,
  11 `destinationTransportPort`, 4 `protocolIdentifier`, 1 `octetDeltaCount`,
  2 `packetDeltaCount`, 152/153 flow start/end millis, 22/21 flow start/end
  sysuptime for v9, 6 `tcpControlBits`, 10/14 ingress/egress interface).
  Curated fields populate the typed `FlowRecord` columns; all other decoded
  fields go into `extra` keyed by IE name, or `ie<id>` / `ie<pen>:<id>` and a
  hex string when the element is unknown.

**`src/ipfix/listener.rs` — UDP listener + handler trait**

- `IpfixListenerConfig { udp_port: u16 (default 4739), bind_address: String }`.
- `IpfixListener` binds one `UdpSocket` and runs a `recv_from` loop (buffer
  sized for jumbo datagrams, 65535), mirroring `SyslogListener::start_udp_listener`.
  The decoder/template cache is owned by the listener task (single task → no
  shared-mutability needed for the cache in phase 1).
- `IpfixHandler` trait: `async fn handle_flows(&self, flows: Vec<FlowRecord>, source: SocketAddr)`.
- `DefaultIpfixHandler` logs a summary line per batch and increments metrics.
  (The S3-persisting handler arrives in phase 4.)

### Generalized S3 persistence

**`src/forwarding/s3_sink.rs` (new) — shared plumbing**

`S3Sink` extracts the S3-specific concerns currently embedded in
`src/forwarding/parquet_s3.rs`:

```text
S3Sink {
    client: aws_sdk_s3::Client,
    bucket: String,
}
impl S3Sink {
    async fn from_config(cfg: &ParquetS3Config) -> Result<S3Sink>   // region, endpoint, force_path_style, credentials
    async fn upload(&self, key: &str, body: Vec<u8>) -> Result<()>  // ByteStream put_object + error handling
}
```

The existing `ParquetS3Forwarder` is refactored to hold an `S3Sink` and call
`sink.upload(...)` instead of constructing the client and calling `put_object`
inline. **No behavior change**; its Parquet schema and the WEF flow are
untouched. Existing `parquet_s3` tests must stay green.

**Per-source Parquet writers**

- `SyslogS3Writer` (phase 3) and `IpfixS3Writer` (phase 4) each:
  - own a single fixed Arrow `Schema`,
  - buffer records and flush on a size or time threshold,
  - encode the buffer to a Parquet byte buffer and call `S3Sink::upload` with
    a source-specific key prefix.
- WEF, syslog, and IPFIX therefore land under distinct S3 prefixes / buckets.

### Configuration (`src/config/mod.rs`)

- Add `[ipfix]` section paralleling `[syslog]`:
  `enabled` (default false), `udp_port` (default 4739), `bind_address`
  (default `0.0.0.0`).
- Extend the S3 persistence config so each source can specify its own
  `bucket`/`prefix` (a `source_type`-keyed prefix). Backward compatible:
  absent syslog/ipfix S3 config means those sources do not persist (parity
  with today, where only WEF persists).

### Wiring (`src/main.rs`)

- Add a conditional spawn block for the IPFIX listener when
  `config.ipfix.enabled`, mirroring the existing syslog spawn block
  (`src/main.rs:62-82`).

## Phases (dependency-ordered; each independently shippable)

1. **IPFIX ingestion** — `src/ipfix/` (mod, decoder for v5/v9/v10, template
   cache, curated IE map, UDP listener, `DefaultIpfixHandler`), `[ipfix]`
   config, `main.rs` wiring. No S3.
2. **S3Sink extraction** — add `src/forwarding/s3_sink.rs`; refactor
   `parquet_s3.rs` to use it. Pure refactor; WEF tests stay green.
3. **Syslog → S3** — `SyslogS3Writer`, an S3-persisting `SyslogHandler`,
   per-source S3 config, wiring in `main.rs`/server.
4. **IPFIX → S3** — `IpfixS3Writer` (fixed `FlowRecord` schema), an
   S3-persisting `IpfixHandler`, wiring. Depends on phases 1 and 2.

## Data flow

```text
Phase 1:  UDP datagram → IpfixListener → decoder (+template cache) → Vec<FlowRecord> → IpfixHandler (log+metrics)
Phase 4:  …                                                        → IpfixS3Writer → buffer → Parquet → S3Sink.upload(ipfix-prefix)
Phase 3:  UDP/TCP syslog → SyslogListener → SyslogMessage → SyslogS3Handler → SyslogS3Writer → Parquet → S3Sink.upload(syslog-prefix)
Existing: HTTP WEF → WindowsEvent → ParquetS3Forwarder → S3Sink.upload(wef-prefix)   [refactored in phase 2]
```

## Error handling

- **Unknown template:** a data set/flowset whose template is not yet cached is
  skipped and counted (`ipfix_templates_missing`). This is normal UDP behavior
  (templates are re-sent periodically); it must not error the listener.
- **Malformed datagram / truncated set:** counted (`ipfix_decode_errors`),
  logged at `warn`, and the listener loop continues. The decoder never panics
  on attacker-controlled input — all length/offset reads are bounds-checked.
- **S3 upload failure:** handled like the existing WEF forwarder (log + the
  forwarder's existing retry/error path), isolated per source so one source's
  S3 outage cannot stall another.
- **Buffer backpressure:** writers use bounded channels; on overflow, drop +
  count (`<source>_s3_dropped`) rather than blocking the listener.

## Observability (metrics)

New counters (via the existing `metrics` crate): `ipfix_datagrams_received`,
`ipfix_flows_decoded`, `ipfix_templates_received`, `ipfix_templates_missing`,
`ipfix_decode_errors`, and per-source `<source>_s3_records_written`,
`<source>_s3_uploads`, `<source>_s3_upload_errors`, `<source>_s3_dropped`.

## Testing (three levels — required for every phase)

- **Unit:**
  - Decoder: hand-built byte vectors for IPFIX (template set then matching data
    set), NetFlow v9 (template flowset then data flowset), NetFlow v5 (fixed
    records). Cases: typed IE extraction, unknown IE → raw hex in `extra`,
    unknown-template data set skipped + counted, truncated/malformed input
    yields a decode error not a panic, multi-record sets, IPv6 addresses.
  - Writers: Arrow row construction from a known `FlowRecord` / `SyslogMessage`
    produces the expected columns and types.
- **Integration:**
  - Listener: bind on an ephemeral UDP port, send real datagrams, assert
    `FlowRecord`s reach a test handler (mirrors `syslog::listener::tests`).
  - S3 writers: buffer → encode → upload against a faked/local S3 (MinIO or
    localstack), matching the existing `parquet_s3` test approach; assert the
    object is written and re-readable with the expected schema.
- **End-to-end:**
  - Start the server with IPFIX enabled and S3 persistence configured; send a
    template + data datagram sequence; assert a Parquet object appears under
    the IPFIX prefix with the expected columns. Likewise drive syslog → S3.
  - The repo's E2E harness lives at
    `tests/e2e/simulation-environment/run.sh` (Docker required; skip if
    unavailable, per AGENTS.md §5).

## Files touched (summary)

- Create: `src/ipfix/mod.rs`, `src/ipfix/decoder.rs`, `src/ipfix/listener.rs`,
  `src/forwarding/s3_sink.rs`.
- Modify: `src/main.rs` (module decl + IPFIX spawn), `src/config/mod.rs`
  (`[ipfix]` + per-source S3 config), `src/forwarding/mod.rs` +
  `src/forwarding/parquet_s3.rs` (use `S3Sink`), syslog wiring for phase 3,
  `AGENTS.md`/`README.md` (document the new source, per AGENTS.md §7).
- New writers live under `src/forwarding/` alongside `parquet_s3.rs`, as
  `src/forwarding/syslog_s3.rs` (`SyslogS3Writer`) and
  `src/forwarding/ipfix_s3.rs` (`IpfixS3Writer`) — consistent with the
  existing forwarding location.
