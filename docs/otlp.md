# OTLP Log Ingestion

logthing accepts OpenTelemetry logs over OTLP/HTTP at `POST /v1/logs` (protobuf or JSON) and
writes them as typed Parquet to S3 or local disk.

```toml
[otlp]
enabled = true
bearer_token = "change-me"        # optional; Authorization: Bearer <token>
max_service_partitions = 64       # distinct service.name path partitions before _overflow

[otlp.s3]                         # and/or [otlp.local]; at least one is REQUIRED
endpoint   = "http://localhost:9000"
bucket     = "logthing-data"
region     = "us-east-1"
access_key = "..."
secret_key = "..."
prefix     = "otlp"               # default

[otlp.local]
directory = "/var/lib/logthing/otlp"
```

`[otlp] enabled = true` with neither `[otlp.s3]` nor `[otlp.local]` is a startup error.
`[otlp.s3]`/`[otlp.local]` accept the same flush/buffer keys as the other sources
(`flush_threshold_bytes`, `flush_interval_secs`, `channel_capacity`, `max_buffer_rows`).

## Exporter setup

| Exporter | Configuration |
|---|---|
| OpenTelemetry Collector | `otlphttp` exporter, `endpoint: http://logthing:5985`, `compression: gzip` (logs path `/v1/logs` is appended automatically) |
| OTel SDKs | `OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf`, `OTEL_EXPORTER_OTLP_ENDPOINT=http://logthing:5985`; set `OTEL_EXPORTER_OTLP_COMPRESSION=gzip` to compress |
| JSON | `Content-Type: application/json` (OTLP/JSON, camelCase) is accepted |
| gRPC (port 4317) | **Not supported yet.** Use `otlphttp`. |

OTLP/JSON: send enum fields as integers (`"severityNumber": 9`); enum-name strings such as
`SEVERITY_NUMBER_INFO` are not accepted by the current decoder.

Request bodies may be gzip-compressed (`Content-Encoding: gzip`), for both protobuf and JSON.
The decompressed size is capped at 64 MiB (`413` beyond that); any other `Content-Encoding`
gets `415`; a corrupt gzip stream gets `400`.

## Backpressure

When the writer channel is full logthing answers `503 Service Unavailable` with
`Retry-After: 1` (empty body); OTLP exporters retry 503 automatically. If part of a request was
enqueued before the channel filled, the whole request is rejected and the retry duplicates the
enqueued prefix with different `event_uuid`s. `otlp_events_dropped` counts records that were
not enqueued; `otlp_logs_received` counts only enqueued records. A closed channel (writer gone)
is still answered 200 with a counted drop. WEF is unchanged (200 and a counted drop).

## Redaction

Optional `[otlp.redaction]` rules drop, HMAC-hash or mask attribute values, and (with `@body`,
`@host_name`, `@peer_addr`) typed columns, after mapping and before `event_uuid` assignment and
enqueue. See [redaction.md](redaction.md).

## Columns

One Iceberg table `otlp` (all services), partitioned by `day(partition_time)`.

| Column | Type | Notes |
|---|---|---|
| `event_uuid` | string, not null | UUIDv7 assigned at ingest; row identity |
| `time` | timestamp(us, UTC) | `time_unix_nano`; null when 0 |
| `observed_time` | timestamp(us, UTC) | null when 0 |
| `received_at` | timestamp(us, UTC), not null | server receipt time |
| `severity_number` | int | null when unspecified (0) |
| `severity_text` | string | |
| `body` | string | string bodies verbatim; other AnyValue types as JSON text |
| `service_name` | string | resource `service.name`, raw (unsanitized); null if absent/non-string |
| `service_namespace` | string | resource `service.namespace` |
| `service_instance_id` | string | resource `service.instance.id` |
| `host_name` | string | resource `host.name` |
| `peer_addr` | string | TCP peer IP of the exporter (not the sender's `host.name`) |
| `trace_id`, `span_id` | string | lowercase hex; null when empty |
| `flags` | int (unsigned) | null when 0 |
| `event_name` | string | |
| `scope_name`, `scope_version` | string | instrumentation scope |
| `resource_attributes` | string (JSON), not null | ALL resource attributes (promoted keys included) |
| `attributes` | string (JSON), not null | log attributes merged over scope attributes |
| `partition_time` | timestamp(us, UTC), not null | event time if within the backfill/skew window of receipt, else receipt time |

Query JSON columns with `json_extract_scalar(attributes, '$."http.route"')` (Trino).

## Partitioning by service, the `_overflow` cap, and small files

Parquet files are grouped under `otlp/<service>/year=/month=/day=/`, where `<service>` is the
sanitized `service_name` (lowercase, `[a-z0-9_]`, max 64 chars; `unknown` when absent). Every
file therefore holds one service, so Trino prunes files via per-file min/max statistics on
`service_name`. The Iceberg partition spec stays `day(partition_time)` only: a hard cap on
distinct services cannot be expressed as an identity partition. Once
`max_service_partitions` distinct services have been seen, further services share the
`_overflow` path segment (their rows still carry the raw `service_name`). Each active service
holds its own write buffer, so many services mean many small files; run Trino
`ALTER TABLE logs.otlp EXECUTE optimize` periodically.

This deliberately deviates from "one table per service": analysts join and funnel across
services, and per-service tables multiply table count and tooling effort.

## Migration

Before 0.22.0, OTLP records were written through the `[hec]` sinks into the untyped `hec`
table, and OTLP worked only if `[hec]` had a sink. From 0.22.0 OTLP has its own sinks and
logthing refuses to start if `[otlp] enabled = true` has none.

Before:

```toml
[hec]
enabled = true
[hec.s3]
endpoint = "http://minio:9000"
bucket = "logs"
region = "us-east-1"
access_key = "..."
secret_key = "..."

[otlp]
enabled = true          # silently used the [hec.s3] sink
```

After:

```toml
[hec]
enabled = true
[hec.s3]
endpoint = "http://minio:9000"
bucket = "logs"
region = "us-east-1"
access_key = "..."
secret_key = "..."

[otlp]
enabled = true
[otlp.s3]               # NEW: required
endpoint = "http://minio:9000"
bucket = "logs"
region = "us-east-1"
access_key = "..."
secret_key = "..."
```

Historic OTLP rows stay in the `hec` table (`sourcetype = 'otlp'`); new rows go to the
`otlp` table. The committer evolves existing Iceberg tables additively, so no manual DDL is needed.

Upgrade the committer before logthing: an old committer quarantines the new-shaped files.
