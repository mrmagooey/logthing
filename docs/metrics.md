# Metrics

The server exposes Prometheus metrics on port 9090:

**Bind address (breaking change):** the metrics listener binds the same
interface as the main server's `bind_address` (previously it always bound
`0.0.0.0`, regardless of `bind_address`), and is gated by the same
`security.allowed_ips` whitelist as the main HTTP router — it has no
authentication of its own, so the whitelist is what restricts who can reach
it. The TLS listener (`[tls]`) now follows `bind_address` the same way, for
the same reason (it previously always bound `0.0.0.0` too, though it already
carried the whitelist and auth layers).
If you bind the main server to a narrow interface but scrape metrics from a
different host, set `metrics.bind_address = "0.0.0.0"` explicitly to restore
the old behaviour (see the `[metrics]` block in [configuration.md](configuration.md)).

**`allowed_ips` now also gates `/metrics` (breaking change):** there is no
separate `metrics.allowed_ips` — `security.allowed_ips` is a single list
that applies to wire-ingest sources *and* metrics scrapers alike. If you set
`allowed_ips`, add your Prometheus (or other scraper's) address to the same
list, or scraping will start returning 403 instead of timing out or being
refused. Metrics has no auth of its own, so widening `allowed_ips` to admit
a scraper also admits that source to every other listener it covers —
there's no way to allow a scraper without also trusting it as a log source.

Per-source ingest counters:

- `syslog_messages_received`, `ipfix_datagrams_received`, `ipfix_flows_decoded`,
  `sflow_datagrams_received`, `suricata_records_received`, `hec_events_received`,
  `otlp_logs_received`
- Decode/parse failures: `ipfix_decode_errors`, `sflow_decode_errors`,
  `suricata_parse_errors`, `hec_parse_errors`, `wef_xml_parse_errors` - a WEF
  batch's XML failed to parse past a given event; that event is kept as its
  own raw event and parsing resumes at the next one, so it doesn't cost the
  rest of the batch

Parquet persistence (labelled `source="wef"|"syslog"|"ipfix"|"zeek"|"suricata"|"sflow"|"hec"|"otlp"`):

- `parquet_s3_records_written`, `parquet_s3_uploads`, `parquet_s3_upload_errors`
- `parquet_s3_dropped`, `parquet_s3_buffer_dropped` - backpressure drops
- `parquet_s3_records_skipped` - a record the writer could not convert into a
  batch (schema mismatch, a mapping failure, or an unparsed event), also
  labelled `target`
- `parquet_s3_buffer_rows`, `parquet_s3_channel_queued`, `parquet_s3_channel_available`

Aggregation: `aggregate_records_consumed`, `aggregate_rows_emitted`, `aggregate_groups`,
`aggregate_overflow_records`.

Listener health: `listener_accept_errors` (labelled `protocol="syslog_tcp"|"zeek"|"suricata"`)
- TCP accept errors on that listener; a persistent condition (e.g. fd
  exhaustion) pauses that listener's accept loop for 1s per error instead of
  spinning.

Counters are exported with a `_total` suffix by the Prometheus exporter.

## API Endpoints

### WEF Endpoints
- `POST /wsman` - Main WEF endpoint for subscriptions and events

### Syslog Endpoints
- `POST /syslog` - Receive syslog messages via HTTP
- `GET /syslog/udp` - Get UDP listener configuration info
- `GET /syslog/examples` - Get example DNS syslog records (JSON)

### HEC Endpoints
- `POST /services/collector/event` - Splunk HEC-compatible event ingest
- `POST /services/collector/raw` - Splunk HEC-compatible raw ingest
- `POST /ingest` - NDJSON ingest, same auth/dispatch path as the HEC routes

### OTLP Endpoints
- `POST /v1/logs` - OTLP/HTTP log ingest (protobuf or JSON); only present when
  the `otlp` Cargo feature is enabled

### Management Endpoints
- `GET /health` - Health check endpoint
- `GET /metrics` - Prometheus metrics (port 9090)
