# Zeek NDJSON Ingestion — Implementation Summary

## Overview

Logthing accepts Zeek (network security monitor) log exports delivered as newline-delimited JSON (NDJSON) over a persistent TCP connection. A typed schema registry maps the six most common Zeek log streams to curated Arrow/Parquet schemas, capturing every Zeek field — known fields in typed columns and unknown or type-mismatched fields in a non-null `_extra` JSON column. An optional S3 handler persists each stream to its own partitioned Parquet file series.

## Architecture

```
Zeek sensor (JSON logging over TCP)
              |
              | TCP connections (port 47760)
              v
       ZeekListener (src/zeek/listener.rs)
              |
              v
     handle_tcp_connection()
       BufReader + bounded read_until
              |
              v
       ZeekRecord  (src/zeek/mod.rs)
         log_path = _path field (or "unknown")
         fields   = full JSON object
              |
              v
       ZeekHandler trait
       /              \
DefaultZeekHandler   ZeekS3Handler (src/forwarding/zeek_s3.rs)
  (log + metrics)         |
                   bounded mpsc channel
                          |
                   ZeekS3Writer (background task)
                    |
              get_schema_entry(log_path)
              /                     \
     Typed schema entry          Envelope fallback
     (conn/dns/http/ssl/         (unknown stream names)
      files/notice)                     |
              |                         |
       map_*(fields)           map_envelope(fields, log_path)
              |                         |
       RecordBatch                RecordBatch
              \                       /
               Parquet / ZSTD → S3Sink
                          |
     {prefix}/{log_path}/year=…/month=…/day=…/{uuid}.parquet
```

## 1. TCP Listener (`src/zeek/listener.rs`)

- `ZeekListener` binds a TCP socket on the configured address and port (default: `0.0.0.0:47760`).
- Each accepted connection is handled in a dedicated `tokio::spawn` task.
- The connection handler wraps the stream in a `BufReader` and reads line-by-line using `read_until(b'\n')` through a `take((ZEEK_MAX_LINE_BYTES + 1))` guard:
  - If the read returns more than `ZEEK_MAX_LINE_BYTES` bytes without encountering a newline, the line exceeded the cap. The connection is closed and `zeek_oversized_lines` is incremented. Re-syncing after an over-long line is itself unbounded, so the entire connection is dropped.
  - Non-UTF-8 lines are skipped; `zeek_parse_errors` is incremented.
  - Lines that fail JSON parsing are skipped; `zeek_parse_errors` is incremented.
- The listener never crashes on malformed input — only the individual connection (or line) is affected.

**Constants**

| Constant | Value | Meaning |
|----------|-------|---------|
| `ZEEK_MAX_LINE_BYTES` | 16 MiB (16 × 1024 × 1024) | Maximum accepted line length |

## 2. Record Type (`src/zeek/mod.rs`)

```rust
pub struct ZeekRecord {
    pub log_path: String,            // from JSON _path field; "unknown" if absent/non-string
    pub fields: serde_json::Value,   // full JSON object as received
    pub received_at: DateTime<Utc>,  // wall-clock ingestion time
}
```

`_path` extraction: `value.get("_path").and_then(|v| v.as_str())`. If absent or not a string, `log_path = "unknown"` and `zeek_missing_path` is incremented.

## 3. Handler Trait (`src/zeek/listener.rs`)

```rust
#[async_trait]
pub trait ZeekHandler: Send + Sync {
    async fn handle_record(&self, record: ZeekRecord, source: SocketAddr);
}
```

Two implementations:

- **`DefaultZeekHandler`** — logs a one-line summary and increments `zeek_records_received` / `zeek_records_by_path{log_path=…}`. No storage.
- **`ZeekS3Handler`** (`src/forwarding/zeek_s3.rs`) — forwards records via a bounded `mpsc` channel to a background `ZeekS3Writer` task.

## 4. Schema Registry (`src/zeek/schema.rs`)

The registry is a static `LazyLock<HashMap<&'static str, Arc<SchemaEntry>>>` built at first access. `get_schema_entry(log_path)` looks up the map and returns a `SchemaEntry { schema, mapper }`. For unknown paths a fresh `SchemaEntry` is built dynamically using the envelope schema and a closure that captures the actual `log_path` string.

### 4.1 Typed Schemas

All six typed schemas include a non-null `_extra` column (Arrow `Utf8`). The `_extra` value is a JSON object containing:
- every top-level field in the incoming record that is **not** listed in the promoted set, and
- every promoted field whose runtime value did not match the expected Arrow type (the typed column is `null`; the original value is preserved in `_extra`).

This is a best-effort, total mapping: no information is silently discarded.

#### `conn` (15 promoted columns + `_extra`)

| Arrow column | Arrow type | Nullable | Source JSON key |
|---|---|---|---|
| `ts` | Float64 | yes | `ts` |
| `uid` | Utf8 | yes | `uid` |
| `id_orig_h` | Utf8 | yes | `id.orig_h` |
| `id_orig_p` | UInt16 | yes | `id.orig_p` |
| `id_resp_h` | Utf8 | yes | `id.resp_h` |
| `id_resp_p` | UInt16 | yes | `id.resp_p` |
| `proto` | Utf8 | yes | `proto` |
| `service` | Utf8 | yes | `service` |
| `duration` | Float64 | yes | `duration` |
| `orig_bytes` | UInt64 | yes | `orig_bytes` |
| `resp_bytes` | UInt64 | yes | `resp_bytes` |
| `conn_state` | Utf8 | yes | `conn_state` |
| `history` | Utf8 | yes | `history` |
| `orig_pkts` | UInt64 | yes | `orig_pkts` |
| `resp_pkts` | UInt64 | yes | `resp_pkts` |
| `_extra` | Utf8 | **no** | (all remaining fields) |

#### `dns` (13 promoted columns + `_extra`)

| Arrow column | Arrow type | Nullable | Source JSON key |
|---|---|---|---|
| `ts` | Float64 | yes | `ts` |
| `uid` | Utf8 | yes | `uid` |
| `id_orig_h` | Utf8 | yes | `id.orig_h` |
| `id_orig_p` | UInt16 | yes | `id.orig_p` |
| `id_resp_h` | Utf8 | yes | `id.resp_h` |
| `id_resp_p` | UInt16 | yes | `id.resp_p` |
| `proto` | Utf8 | yes | `proto` |
| `trans_id` | UInt32 | yes | `trans_id` |
| `query` | Utf8 | yes | `query` |
| `qtype_name` | Utf8 | yes | `qtype_name` |
| `qclass_name` | Utf8 | yes | `qclass_name` |
| `rcode_name` | Utf8 | yes | `rcode_name` |
| `answers` | Utf8 | yes | `answers` (array serialised as JSON string) |
| `_extra` | Utf8 | **no** | (all remaining fields) |

#### `http` (13 promoted columns + `_extra`)

Promoted: `ts`, `uid`, `id_orig_h`, `id_orig_p`, `id_resp_h`, `id_resp_p`, `method`, `host`, `uri`, `status_code` (UInt16), `user_agent`, `request_body_len` (UInt64), `response_body_len` (UInt64), `_extra`.

#### `ssl` (11 promoted columns + `_extra`)

Promoted: `ts`, `uid`, `id_orig_h`, `id_orig_p`, `id_resp_h`, `id_resp_p`, `version`, `cipher`, `curve`, `server_name`, `validation_status`, `_extra`.

#### `files` (8 promoted columns + `_extra`)

Promoted: `ts`, `fuid`, `tx_hosts` (JSON string), `rx_hosts` (JSON string), `source`, `mime_type`, `filename`, `total_bytes` (UInt64), `_extra`.

#### `notice` (10 promoted columns + `_extra`)

Promoted: `ts`, `uid`, `id_orig_h`, `id_orig_p`, `id_resp_h`, `id_resp_p`, `note`, `msg`, `sub`, `actions` (JSON string), `_extra`.

### 4.2 Envelope Fallback Schema

For stream names not in the registry (including `"unknown"`):

| Arrow column | Arrow type | Nullable |
|---|---|---|
| `ts` | Float64 | yes |
| `uid` | Utf8 | yes |
| `id_orig_h` | Utf8 | yes |
| `id_orig_p` | UInt16 | yes |
| `id_resp_h` | Utf8 | yes |
| `id_resp_p` | UInt16 | yes |
| `log_path` | Utf8 | **no** |
| `ingest_time` | Utf8 | **no** |
| `payload` | Utf8 | **no** |

The full JSON object is stored verbatim in `payload`. `log_path` holds the actual (sanitised) path; `ingest_time` is RFC 3339.

## 5. S3 Persistence (`src/forwarding/zeek_s3.rs`)

### 5.1 ZeekS3Handler

`ZeekS3Handler` implements `ZeekHandler`. It forwards each `ZeekRecord` to a background `ZeekS3Writer` task via a bounded `mpsc` channel. When the channel is full, `try_send` fails, `zeek_s3_dropped` is incremented, and the record is discarded.

### 5.2 ZeekS3Writer

`ZeekS3Writer` maintains a `HashMap<String, StreamBuffer>` — one `VecDeque<BufferedBatch>` per sanitised `log_path`. On each `push_record`:

1. `sanitize_log_path` is applied to the record's `log_path`.
2. If the sanitised path would create a new entry beyond `MAX_ZEEK_STREAMS`, the record is routed to `"unknown"` and `zeek_streams_capped` is incremented.
3. `get_schema_entry` selects the typed or envelope schema.
4. The row mapper converts the JSON to a one-row `RecordBatch`.
5. The batch is appended to the stream's buffer.
6. If the stream's estimated byte total reaches `flush_threshold_bytes`, an immediate flush is attempted.

A background interval also fires `flush_all_if_needed()` at a fraction of `flush_interval_secs` to catch age-based flushes.

**Flush**: all buffered `RecordBatch`es for the stream are encoded into a single Parquet file (ZSTD level 3) and uploaded via `S3Sink`. On success `zeek_s3_records_written` and `zeek_s3_uploads` are incremented and the buffer is cleared. On error `zeek_s3_upload_errors` is incremented and the buffer is retained.

**Hard cap**: if a flush fails and the buffer exceeds `max_buffer_rows * 4`, the oldest batches are dropped and `zeek_s3_buffer_dropped` is incremented.

### 5.3 S3 Key Format

```
{prefix}/{log_path}/year={YYYY}/month={MM}/day={DD}/{uuid}.parquet
```

`log_path` is always sanitised: lowercase, `[a-z0-9_]` characters only, max 64 characters, empty → `"unknown"`.

**Constants**

| Constant | Value |
|---|---|
| `MAX_ZEEK_STREAMS` | 256 |
| `ZEEK_S3_CHANNEL_CAPACITY` | 256 |

## 6. Configuration

### `[zeek]` block

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Enable the TCP listener |
| `tcp_port` | u16 | `47760` | Listening TCP port |
| `bind_address` | String | `"0.0.0.0"` | Bind address |
| `s3` | optional table | absent | S3 persistence (absent → no persistence) |

### `[zeek.s3]` block (optional)

| Key | Type | Default | Description |
|---|---|---|---|
| `endpoint` | String | — | S3-compatible endpoint URL |
| `bucket` | String | — | Target bucket |
| `region` | String | — | AWS region |
| `access_key` | String | — | Access key |
| `secret_key` | String | — | Secret key |
| `prefix` | String | `"zeek"` | Key prefix (slash-free; builder inserts `/`) |
| `flush_threshold_bytes` | usize | `104857600` (100 MiB) | Flush when estimated buffer bytes exceed this |
| `flush_interval_secs` | u64 | `900` | Flush every N seconds regardless of buffer size |
| `channel_capacity` | usize | `256` | `mpsc` channel capacity between listener and writer |
| `max_buffer_rows` | usize | `100000` | Soft buffer cap; hard cap is `max_buffer_rows * 4` |

Connection fields (`endpoint`, `bucket`, `region`, `access_key`, `secret_key`) are flattened from `S3ConnectionConfig` via `#[serde(flatten)]`, so the TOML surface stays flat under `[zeek.s3]`.

**Example:**

```toml
[zeek]
enabled      = true
tcp_port     = 47760
bind_address = "0.0.0.0"

[zeek.s3]
endpoint              = "http://localhost:9000"
bucket                = "zeek-logs"
region                = "us-east-1"
access_key            = "minioadmin"
secret_key            = "minioadmin"
prefix                = "zeek"
flush_threshold_bytes = 104857600
flush_interval_secs   = 900
channel_capacity      = 256
max_buffer_rows       = 100000
```

## 7. Hardening

| Mechanism | Implementation |
|---|---|
| Bounded line reads | `take(ZEEK_MAX_LINE_BYTES + 1)` guard; over-length closes the connection |
| Stream map cap | `MAX_ZEEK_STREAMS = 256`; excess paths overflow to `"unknown"` |
| Path sanitisation | lowercase, `[a-z0-9_]`, max 64 chars, empty → `"unknown"` |
| Channel overflow | `try_send` fails fast; record dropped, `zeek_s3_dropped` incremented |
| S3 outage buffer | Buffered batches retained on error; hard cap at `max_buffer_rows * 4` rows |
| Type mismatch | Mismatched field preserved in `_extra`; typed column set to `null` |

## 8. Metrics

All counters are registered at startup and exposed via the existing Prometheus metrics endpoint.

| Metric | Description |
|---|---|
| `zeek_records_received` | Total Zeek records successfully parsed and dispatched |
| `zeek_records_by_path{log_path=…}` | Records dispatched, broken down by `_path` value |
| `zeek_parse_errors` | Non-UTF-8 or invalid JSON lines skipped |
| `zeek_missing_path` | Records missing `_path` or with a non-string `_path` |
| `zeek_oversized_lines` | Lines exceeding `ZEEK_MAX_LINE_BYTES`; triggers connection close |
| `zeek_s3_records_written` | Rows written on a successful S3 flush |
| `zeek_s3_uploads` | Successful S3 uploads |
| `zeek_s3_upload_errors` | Failed S3 uploads |
| `zeek_s3_dropped` | Records dropped due to full channel |
| `zeek_s3_buffer_dropped` | Rows dropped by hard-cap enforcement |
| `zeek_streams_capped` | Records rerouted to `"unknown"` because `MAX_ZEEK_STREAMS` was reached |

## 9. Files

| Path | Role |
|---|---|
| `src/zeek/mod.rs` | `ZeekRecord` type, module root |
| `src/zeek/listener.rs` | TCP listener, `ZeekListener`, `ZeekHandler` trait, `DefaultZeekHandler` |
| `src/zeek/schema.rs` | Schema registry, typed schemas (conn/dns/http/ssl/files/notice), envelope fallback, row mappers |
| `src/forwarding/zeek_s3.rs` | `ZeekS3Handler`, `ZeekS3Writer`, `sanitize_log_path`, `build_zeek_s3_key` |
| `src/config/mod.rs` | `ZeekConfig`, `ZeekS3Config` structs and their `default_*` functions |
