# IPFIX/NetFlow Listener - Implementation Summary

## Overview

Added IPFIX (IP Flow Information Export, RFC 7011) and NetFlow (v5/v9, RFC 3954/RFC 3954) collection capabilities to Logthing. A UDP listener receives flow export datagrams, decodes them into structured `FlowRecord` values, and dispatches them to pluggable handlers — including an S3 handler that persists flows as partitioned Parquet files.

## Features Implemented

### 1. UDP Listener (`src/ipfix/listener.rs`)

- Binds a UDP socket on the configured address and port (default: `0.0.0.0:4739`)
- Reads incoming datagrams in a tight async loop; each datagram is passed to `decode_datagram()` in `src/ipfix/decoder.rs`
- On decode success, the resulting `Vec<FlowRecord>` and source `IpAddr` are forwarded to the registered `IpfixHandler`
- Decode errors increment `ipfix_decode_errors` and are logged; the listener never crashes on malformed input

### 2. Decoder (`src/ipfix/decoder.rs`)

`decode_datagram()` is the top-level entry point. It increments `ipfix_datagrams_received`, reads the version field from the datagram header, and dispatches to the appropriate version-specific decoder:

| Version | Decoder function | Standard |
|---------|-----------------|---------|
| 10 | `decode_ipfix()` | IPFIX RFC 7011 |
| 9 | `decode_netflow_v9()` | NetFlow v9 RFC 3954 |
| 5 | `decode_netflow_v5()` | NetFlow v5 (fixed layout) |

**Template cache**

IPFIX and NetFlow v9 use a two-pass scheme: template sets define the structure of data sets, and data sets reference previously received templates by ID. The decoder maintains a template cache keyed by:

```
TemplateKey = (exporter IpAddr, observation_domain_id: u32, template_id: u16)
```

Cache behaviour:

- Maximum size: `MAX_CACHED_TEMPLATES = 100_000` entries
- Receiving a template record: `ipfix_templates_received` incremented; existing keys are always updated; new keys are rejected if the cache is full (`ipfix_templates_dropped` incremented)
- Receiving a data set whose template is not in the cache: set is silently skipped, `ipfix_templates_missing` incremented
- NetFlow v5 has a fixed 48-byte record layout and requires no template cache

**IE mapping**

The decoder carries a curated map of approximately 30 IANA information elements, including:

| IE ID | Name |
|-------|------|
| 1 | octetDeltaCount |
| 2 | packetDeltaCount |
| 4 | protocolIdentifier |
| 6 | tcpControlBits |
| 7 | sourceTransportPort |
| 8 | sourceIPv4Address |
| 10 | ingressInterface |
| 11 | destinationTransportPort |
| 12 | destinationIPv4Address |
| 14 | egressInterface |
| 27 | sourceIPv6Address |
| 28 | destinationIPv6Address |
| 152 | flowStartMilliseconds |
| 153 | flowEndMilliseconds |
| 225 | postNATSourceIPv4Address |
| 226 | postNATDestinationIPv4Address |

Known IEs are decoded into the corresponding typed fields of `FlowRecord`. Unknown standard IEs are stored in the `extra` JSON field under the key `"ie<id>"` with a hex-encoded value. Enterprise IEs (PEN present) are stored under the key `"ie<PEN>:<id>"`. Each successfully decoded flow record increments `ipfix_flows_decoded`. All slice indexing uses checked arithmetic to prevent panics on untrusted input.

### 3. FlowRecord (`src/ipfix/mod.rs`)

The common record type produced by all three decoders:

| Field | Type | Notes |
|-------|------|-------|
| `observation_domain_id` | `u32` | Always present |
| `template_id` | `u16` | Always present; fixed value for v5 |
| `protocol_version` | `u8` | 5, 9, or 10 |
| `exporter` | `IpAddr` | Sender address from UDP socket |
| `export_time` | `DateTime<Utc>` | From datagram header |
| `src_addr` | `Option<IpAddr>` | |
| `dst_addr` | `Option<IpAddr>` | |
| `src_port` | `Option<u16>` | |
| `dst_port` | `Option<u16>` | |
| `ip_protocol` | `Option<u8>` | IP protocol number (TCP=6, UDP=17, …) |
| `octet_delta_count` | `Option<u64>` | Byte count for the flow |
| `packet_delta_count` | `Option<u64>` | Packet count for the flow |
| `flow_start` | `Option<DateTime<Utc>>` | |
| `flow_end` | `Option<DateTime<Utc>>` | |
| `tcp_flags` | `Option<u8>` | |
| `input_interface` | `Option<u32>` | SNMP interface index |
| `output_interface` | `Option<u32>` | SNMP interface index |
| `extra` | `JsonValue` | Non-curated, enterprise, and unknown IEs; always present, never null |

### 4. Handler Interface

Decoded batches are delivered via the `IpfixHandler` trait:

```rust
fn handle_flows(&self, flows: Vec<FlowRecord>, source: IpAddr);
```

Two implementations ship:

- **`DefaultIpfixHandler`** — logs a one-line summary per batch; no storage
- **`IpfixS3Handler`** (`src/forwarding/ipfix_s3.rs`) — forwards batches to a background writer for S3 persistence

### 5. S3 Persistence (`src/forwarding/ipfix_s3.rs`)

`IpfixS3Handler` implements `IpfixHandler`. It forwards each batch to the generic `PartitionedParquetWriter` via a bounded `mpsc` channel (capacity configurable, default: 256). When the channel is full, `try_send` fails, `parquet_s3_dropped{source="ipfix"}` is incremented, and the batch is discarded.

**Buffering and flush**

`IpfixS3Writer` accumulates `RecordBatch`es in memory and flushes on either of two triggers:

- The buffer's serialized byte estimate exceeds `flush_threshold_bytes` (default: 100 MiB)
- The age interval timer fires (`flush_interval_secs`, default: 900 seconds)

A flush encodes all buffered batches into a single Parquet file (ZSTD compression level 3) and uploads it via `S3Sink`. On success, `parquet_s3_records_written{source="ipfix"}` (per row) and `parquet_s3_uploads{source="ipfix"}` (per upload) are incremented, and the buffer is cleared. On error, `parquet_s3_upload_errors{source="ipfix"}` is incremented and the buffer is retained for the next flush attempt. If the buffer exceeds the hard cap (`max_buffer_rows * 4` rows) while in a persistent error state, the oldest batches are dropped and `parquet_s3_buffer_dropped{source="ipfix"}` is incremented.

**S3 object key format**

```
{prefix}/year={YYYY}/month={MM}/day={DD}/{uuid}.parquet
```

**Arrow schema**

The Parquet files use a fixed 18-column schema (in order):

| Column | Arrow type | Nullable |
|--------|-----------|---------|
| observation_domain_id | UInt32 | no |
| template_id | UInt16 | no |
| protocol_version | UInt8 | no |
| exporter | Utf8 | no |
| export_time | Utf8 | no |
| src_addr | Utf8 | yes |
| dst_addr | Utf8 | yes |
| src_port | UInt16 | yes |
| dst_port | UInt16 | yes |
| ip_protocol | UInt8 | yes |
| octet_delta_count | UInt64 | yes |
| packet_delta_count | UInt64 | yes |
| flow_start | Utf8 | yes |
| flow_end | Utf8 | yes |
| tcp_flags | UInt8 | yes |
| input_interface | UInt32 | yes |
| output_interface | UInt32 | yes |
| extra | Utf8 | no |

IP addresses and timestamps are stored as UTF-8 strings. Timestamps use RFC 3339 format.

### 6. Configuration

**`logthing.toml`:**

```toml
[ipfix]
enabled = true
udp_port = 4739        # IANA-assigned IPFIX port
bind_address = "0.0.0.0"

[ipfix.s3]
endpoint   = "https://s3.example.com"
bucket     = "my-bucket"
region     = "us-east-1"
access_key = "..."
secret_key = "..."
prefix     = "ipfix"              # default
flush_threshold_bytes = 104857600 # 100 MiB default
flush_interval_secs   = 900       # 15 minutes default
channel_capacity      = 256       # default
max_buffer_rows       = 100000    # default
```

`[ipfix.s3]` uses a flattened `S3ConnectionConfig` for the connection fields (`endpoint`, `bucket`, `region`, `access_key`, `secret_key`), consistent with other S3-backed forwarders in the project.

## Architecture

```
UDP exporters (routers, firewalls, switches)
              |
              | UDP datagrams (port 4739)
              v
       IpfixListener (src/ipfix/listener.rs)
              |
              v
      decode_datagram()  (src/ipfix/decoder.rs)
       /       |       \
  v5 fixed  v9 w/    v10 w/
   layout  template  template
           cache     cache
              |
              v
       Vec<FlowRecord>  (src/ipfix/mod.rs)
              |
              v
       IpfixHandler trait
       /              \
DefaultIpfixHandler   IpfixS3Handler (src/forwarding/ipfix_s3.rs)
  (log summary)            |
                    bounded mpsc channel
                           |
                    IpfixS3Writer (background task)
                           |
                    Parquet / ZSTD → S3Sink
                           |
              {prefix}/year=…/month=…/day=…/{uuid}.parquet
```

## Metrics

All counters are registered at startup and exposed via the existing metrics endpoint.

| Metric | Description |
|--------|-------------|
| `ipfix_datagrams_received` | Total UDP datagrams received |
| `ipfix_flows_decoded` | Total flow records successfully decoded |
| `ipfix_templates_received` | Total template records parsed |
| `ipfix_templates_missing` | Data sets skipped due to missing template |
| `ipfix_templates_dropped` | Templates rejected because cache was full |
| `ipfix_decode_errors` | Datagrams that failed to decode |
| `parquet_s3_records_written{source="ipfix"}` | Flow rows written on successful S3 flush |
| `parquet_s3_uploads{source="ipfix"}` | Successful S3 uploads |
| `parquet_s3_upload_errors{source="ipfix"}` | Failed S3 uploads |
| `parquet_s3_dropped{source="ipfix"}` | Flow batches dropped due to full channel |
| `parquet_s3_buffer_dropped{source="ipfix"}` | Rows dropped by hard-cap enforcement |

## Testing

**Test coverage:**

- Version dispatch: v5, v9, and v10 datagrams routed to the correct decoder
- NetFlow v5 fixed-layout decoding: all 48-byte fields parsed correctly
- Template cache: insert, lookup, update, capacity limit (`ipfix_templates_dropped`), missing-template skip
- IE mapping: known IEs land in typed fields; unknown IEs appear in `extra`; enterprise IEs use `"ie<PEN>:<id>"` keys
- Checked arithmetic: truncated / zero-length datagrams do not panic
- S3 writer: flush-on-bytes, flush-on-interval, channel overflow (`parquet_s3_dropped{source="ipfix"}`), upload-error buffer retention, hard-cap eviction (`parquet_s3_buffer_dropped{source="ipfix"}`)
- Arrow schema: column order, nullability, and string encoding of IPs and timestamps

## Files

| Path | Role |
|------|------|
| `src/ipfix/mod.rs` | `FlowRecord` type, `IpfixHandler` trait |
| `src/ipfix/listener.rs` | UDP listener, `IpfixListener` |
| `src/ipfix/decoder.rs` | `decode_datagram()`, template cache, IE map |
| `src/forwarding/ipfix_s3.rs` | `IpfixS3Handler`, `IpfixS3Writer`, Arrow schema |
| `src/config/mod.rs` | `IpfixConfig`, `IpfixS3Config` structs |
