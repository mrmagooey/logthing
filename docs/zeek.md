# Zeek Ingestion

Receive Zeek (network security monitor) logs forwarded as newline-delimited JSON (NDJSON) over TCP (port 47760 by default):

```toml
[zeek]
enabled      = true
tcp_port     = 47760     # default Zeek NDJSON listener port
bind_address = "0.0.0.0"
```

**Stream identification**:
Each incoming JSON record is identified by its `_path` field (e.g. `"conn"`, `"dns"`). If `_path` is absent or is not a string, the record is assigned the stream name `"unknown"` and the `zeek_missing_path` counter is incremented.

**Typed schemas — 6 curated streams**:

| Stream | Arrow columns (promoted) | `_extra` | `partition_time` |
|--------|--------------------------|----------|------------------|
| `conn` | `ts`, `uid`, `id_orig_h`, `id_orig_p`, `id_resp_h`, `id_resp_p`, `proto`, `service`, `duration`, `orig_bytes`, `resp_bytes`, `conn_state`, `history`, `orig_pkts`, `resp_pkts` | yes | yes |
| `dns` | `ts`, `uid`, `id_orig_h`, `id_orig_p`, `id_resp_h`, `id_resp_p`, `proto`, `trans_id`, `query`, `qtype_name`, `qclass_name`, `rcode_name`, `answers` | yes | yes |
| `http` | `ts`, `uid`, `id_orig_h`, `id_orig_p`, `id_resp_h`, `id_resp_p`, `method`, `host`, `uri`, `status_code`, `user_agent`, `request_body_len`, `response_body_len` | yes | yes |
| `ssl` | `ts`, `uid`, `id_orig_h`, `id_orig_p`, `id_resp_h`, `id_resp_p`, `version`, `cipher`, `curve`, `server_name`, `validation_status` | yes | yes |
| `files` | `ts`, `fuid`, `tx_hosts`, `rx_hosts`, `source`, `mime_type`, `filename`, `total_bytes` | yes | yes |
| `notice` | `ts`, `uid`, `id_orig_h`, `id_orig_p`, `id_resp_h`, `id_resp_p`, `note`, `msg`, `sub`, `actions` | yes | yes |

Note: Zeek JSON uses dot-notation for connection-id fields (`id.orig_h`, etc.); the Arrow column names use underscores (`id_orig_h`). All typed schemas include a non-null `_extra` JSON column that captures every field not listed above, as well as any field whose runtime type does not match the expected Arrow type (best-effort, type-mismatch-safe mapping). Every typed schema also ends with a non-null `partition_time` column (Arrow `Timestamp(Microsecond, UTC)`) — see below.

`ts` is written as a microsecond-precision UTC timestamp (Arrow `Timestamp(Microsecond, UTC)`), but it is **nullable** in all seven Zeek schemas (six typed plus the envelope), so it is not a safe Iceberg partition-transform source: a file with even one row missing `ts` would yield two partition values (`{date, null}`) and Iceberg refuses the write. Use the non-null `partition_time` column instead — it holds the instant (the record's own `ts` when present and within a bounded backfill/skew window of receipt, otherwise the receipt time) that the file's buffer day was actually derived from, and is guaranteed non-null and single-valued per file.

**Envelope fallback**:
Records with a `_path` value that does not match one of the six curated stream names (including `"unknown"`) are routed to a generic envelope schema with columns: `ts`, `uid`, `id_orig_h`, `id_orig_p`, `id_resp_h`, `id_resp_p`, `log_path`, `ingest_time`, `payload`, `partition_time`. The full JSON object is stored verbatim in `payload`.

**Robustness**:
- Lines longer than 16 MiB are rejected and the connection is closed; the `zeek_oversized_lines` counter is incremented.
- Non-UTF-8 and invalid JSON lines are skipped (per-line, not per-connection); `zeek_parse_errors` is incremented.
- The per-process stream map is bounded at 256 distinct `_path` values (`MAX_ZEEK_STREAMS`). Records whose sanitised path would create a 257th stream are routed to the `"unknown"` envelope stream and counted by `parquet_s3_partitions_capped{source="zeek"}`.
- `_path` values are sanitised before use in S3 keys (lowercased, `[a-z0-9_]` only, truncated to 64 characters; empty result → `"unknown"`).
- **TCP idle timeout**: same 300-second (5 minute) idle timeout as syslog's TCP listener — see "TCP idle timeout" in [syslog.md](syslog.md). Applies to the Suricata TCP listener too.

## Zeek S3 Persistence

Zeek log records can be persisted to S3-compatible storage as per-stream ZSTD-compressed Parquet files:

```toml
[zeek]
enabled = true

[zeek.s3]
endpoint              = "http://localhost:9000"
bucket                = "zeek-logs"
region                = "us-east-1"
access_key            = "minioadmin"
secret_key            = "minioadmin"
prefix                = "zeek"           # slash-free; builder inserts /  (default: "zeek")
flush_threshold_bytes = 104857600        # flush when buffer reaches 100 MiB (default)
flush_interval_secs   = 900             # flush every N seconds regardless of size (default 900)
channel_capacity      = 40960           # bounded channel between listener and writer
                                        # (default: 100 MiB budget / 2560 B per record)
max_buffer_rows       = 100000          # hard-cap rows before oldest are dropped (default 100 000)
```

The `[zeek.s3]` block is optional; when absent, records are handled by the default handler (logged only) and no S3 writes occur.

**S3 key layout** — one prefix level per stream:

```
{prefix}/<log_path>/year=YYYY/month=MM/day=DD/<uuid>.parquet
```

Examples:
```
zeek/conn/year=2024/month=03/day=15/f3a9….parquet
zeek/dns/year=2024/month=03/day=15/8b2c….parquet
zeek/unknown/year=2024/month=03/day=15/1e7f….parquet
zeek/_overflow/year=2024/month=03/day=15/9a1b….parquet
```

Each stream produces a separate Parquet file series using its own typed schema (or the envelope schema for unrecognised stream names).

**Stream routing rules**:
- A record whose JSON `_path` field is absent or non-string is assigned `log_path = "unknown"` by the listener; after `sanitize_log_path` it lands at `zeek/unknown/`.
- A record whose sanitised `_path` produces an empty string (e.g. a path composed entirely of non-alphanumeric, non-underscore characters) also maps to `zeek/unknown/` via `sanitize_log_path`'s empty-result fallback.
- A record with a valid `_path` that would create a new partition beyond the `max_partitions` cap (default 256) is routed to `zeek/_overflow/` by the generic partition-cap machinery.

**Memory safety**: when S3 is unavailable and a stream's buffer exceeds `max_buffer_rows * 4` rows, the oldest batches are dropped and the `parquet_s3_buffer_dropped{source="zeek"}` counter is incremented.
