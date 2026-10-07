# HEC (Splunk HTTP Event Collector) and NDJSON Ingestion

Routes (mounted only when `[hec] enabled = true`): `POST /services/collector/event`,
`POST /services/collector/raw`, `POST /ingest` (plain NDJSON).

```toml
[hec]
enabled = true
token = "change-me"               # Authorization: Splunk <token>; empty = no auth (dev only)
max_sourcetype_partitions = 64

[hec.s3]                          # and/or [hec.local]; at least one is REQUIRED
endpoint = "http://localhost:9000"
bucket = "logthing-data"
region = "us-east-1"
access_key = "..."
secret_key = "..."

[hec.local]
directory = "/var/lib/logthing/hec"
```

`[hec] enabled = true` with neither `[hec.s3]` nor `[hec.local]` is a startup error.

## Columns

Stored in the Iceberg table `hec` (partition path segment = sanitized `sourcetype`, capped at
`max_sourcetype_partitions`, then `_overflow`).

| Column | Type | Notes |
|---|---|---|
| `sourcetype` | string, not null | |
| `host` | string | envelope `host` / none for raw and NDJSON |
| `time` | timestamp(us, UTC) | envelope `time` (epoch seconds) |
| `received_at` | timestamp(us, UTC), not null | |
| `fields` | string (JSON), not null | the event payload (envelope `event`, the NDJSON object, or `{"raw": ...}`) |
| `partition_time` | timestamp(us, UTC), not null | |
| `event_uuid` | string | UUIDv7 assigned at ingest (every route); null on rows written before 0.22.0 |
| `source` | string | envelope `source` |
| `index` | string | envelope `index` |
| `indexed_fields` | string (JSON) | envelope `fields` object (Splunk "indexed fields") |

Payloads are free-form, so no keys are promoted out of `fields`; extract them in SQL, e.g.
`json_extract_scalar(fields, '$.user')`. The four new columns were appended in 0.22.0; the
committer adds them to an existing `hec` table automatically (older rows read NULL).

## Compression

All three routes accept `Content-Encoding: gzip` (also `x-gzip`, case-insensitive). The
DECOMPRESSED body is capped at 64 MiB: a larger one gets `413`. Any other encoding
(`deflate`, `br`, `zstd`, stacked encodings) gets `415`; a corrupt gzip stream gets `400`.
The server's in-flight body-memory budget charges the compressed (wire) size. WEF and syslog
routes do not decompress request bodies.

## Backpressure

When the writer channel is full (the sink cannot keep up), HEC, raw and NDJSON requests get
`503 Service Unavailable` with `Retry-After: 1` and the HEC body
`{"text":"Server is busy","code":9}`; Splunk-compatible clients treat this as retryable.
"Full" means the bounded channel was full at the instant of `try_send` (no averaging) on any
configured sink. If a request carries several events and some were enqueued before the channel
filled, the whole request is still answered 503 and the already-enqueued events stay enqueued,
so a client retry duplicates them (with different `event_uuid`s; client retries cannot be
de-duplicated). Size the channel with `channel_capacity` in `[hec.s3]`/`[hec.local]`.
`hec_events_dropped` counts records that were not enqueued. A closed channel (writer gone) is
still answered 200 with a counted drop, since a retry cannot help.

## Migration

Nothing to change in `[hec]` unless it relied on having no sink: that now fails startup. Add
`[hec.s3]` or `[hec.local]`. OTLP no longer uses `[hec]` sinks; see `docs/otlp.md#migration`.
