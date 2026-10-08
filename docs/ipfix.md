# IPFIX / NetFlow Ingestion

Receive and decode network flow records via UDP (port 4739 by default):

```toml
[ipfix]
enabled = true
udp_port = 4739      # IANA-standard IPFIX port
bind_address = "0.0.0.0"
```

**Supported Versions**:
- **IPFIX v10** (RFC 7011): template-based variable-length records
- **NetFlow v9** (RFC 3954): template-based, same decoder as IPFIX v10
- **NetFlow v5**: fixed 48-byte record format, no template required

**Template Model**:
Each exporter maintains a stateful template cache keyed on `(exporter IP, observation domain ID, template ID)`. Data records are decoded only once the matching template has been received; data sets referencing an uncached template are silently skipped (counter `ipfix_templates_missing` is incremented). The cache is bounded at 100,000 entries to guard against template floods from spoofed UDP sources.

**Information Elements**:
A curated set of IANA IEs (source/destination address/port, protocol, byte/packet counts, flow start/end, TCP flags, interfaces, etc.) is mapped directly to `FlowRecord` fields. Unknown or enterprise IEs are hex-encoded and stored in the `extra` JSON column.

## IPFIX S3 Persistence

Flow records can be persisted directly to S3-compatible storage as compressed Parquet files:

```toml
[ipfix]
enabled = true

[ipfix.s3]
endpoint              = "http://localhost:9000"
bucket                = "ipfix-flows"
region                = "us-east-1"
access_key            = "minioadmin"
secret_key            = "minioadmin"
prefix                = "ipfix"          # slash-free; builder inserts /
flush_threshold_bytes = 104857600        # flush when buffer reaches 100 MiB (default)
flush_interval_secs   = 900             # flush every N seconds regardless of size (default 900)
channel_capacity      = 11377           # bounded channel between listener and writer
                                        # (default: 100 MiB budget / 9216 B per datagram)
max_buffer_rows       = 100000          # hard-cap rows before oldest are dropped (default 100 000)
```

The `[ipfix.s3]` block is optional; when absent, flows are handled by the default handler (logged only) and no S3 writes occur.

**Parquet Schema** (fixed, 19 columns):

| Column | Type | Nullable |
|--------|------|----------|
| observation_domain_id | UInt32 | no |
| template_id | UInt16 | no |
| protocol_version | UInt8 | no |
| exporter | String | no |
| export_time | Timestamp(µs, UTC) | no |
| src_addr | String | yes |
| dst_addr | String | yes |
| src_port | UInt16 | yes |
| dst_port | UInt16 | yes |
| ip_protocol | UInt8 | yes |
| octet_delta_count | UInt64 | yes |
| packet_delta_count | UInt64 | yes |
| flow_start | Timestamp(µs, UTC) | yes |
| flow_end | Timestamp(µs, UTC) | yes |
| tcp_flags | UInt8 | yes |
| input_interface | UInt32 | yes |
| output_interface | UInt32 | yes |
| extra | String (JSON) | no |
| partition_time | Timestamp(µs, UTC) | no |

Objects are stored at `ipfix/year=YYYY/month=MM/day=DD/<uuid>.parquet`, distinct from syslog's `syslog/` prefix. Files are ZSTD-compressed.

`flow_start` and `flow_end` are nullable, so neither is a safe Iceberg partition-transform source on its own — a file with a null in either would yield two partition values and Iceberg refuses the write. `partition_time` is the correct source: it is non-null, derived from `export_time` (clamped to a bounded backfill/skew window around receipt time and otherwise falling back to receipt time), and holds the instant the file's buffer day was actually derived from.

**Memory safety**: when S3 is unavailable and the buffer exceeds `max_buffer_rows * 4` rows, the oldest batches are dropped and the `parquet_s3_buffer_dropped{source="ipfix"}` counter is incremented.

## sFlow v5

sFlow v5 flow and counter samples arrive on a separate UDP listener (default port 6343, disabled by
default). The decoder is stateless: every datagram carries the context needed to decode it.

```toml
[sflow]
enabled = true
udp_port = 6343
bind_address = "0.0.0.0"
recv_tasks = 8              # UDP receive tasks; default 8 (same semantics as [syslog] recv_tasks)
recv_batch_size = 32        # datagrams per recvmmsg(2) call; default 32
receive_buffer_bytes = 4194304  # requested SO_RCVBUF; 0 = OS default (default 4 MiB)

[sflow.s3]                  # or [sflow.local] with `directory`; same keys, prefix defaults to "sflow"
endpoint   = "http://localhost:9000"
bucket     = "sflow"
region     = "us-east-1"
access_key = "minioadmin"
secret_key = "minioadmin"
flush_threshold_bytes = 104857600   # default 100 MiB
flush_interval_secs   = 900         # default 900
max_buffer_rows       = 100000      # default 100 000
# channel_capacity defaults to the 100 MiB channel budget / 8960 B per record
```

Without `[sflow.s3]`/`[sflow.local]` each datagram is decoded and logged only; nothing is persisted.
