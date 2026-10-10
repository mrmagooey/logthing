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
- `redactions_applied{source,rule}` - values changed by `[hec.redaction]` /
  `[otlp.redaction]`; `source` is `hec` or `otlp`, `rule` is `drop`, `hash`, `mask` or
  `body_unparseable` (a JSON-looking OTLP body that could not be parsed was replaced
  wholesale, fail closed). See [redaction.md](redaction.md)
- `hec_events_dropped` - HEC/NDJSON records not enqueued: one per failed
  per-sink `try_send` (full or closed; with both an S3 and a local sink one record can
  count twice), plus the records of a request never
  offered after the first full channel. A full channel is answered with HTTP 503
- `otlp_events_dropped` - OTLP records not enqueued: one per failed per-sink
  `try_send` (full or closed; with both an S3 and a local sink one record can
  count twice), plus the records of a request never offered after the first full
  channel. A full channel is answered with HTTP 503. `otlp_logs_received` counts
  only records that were enqueued
- Decode/parse failures: `ipfix_decode_errors`, `sflow_decode_errors`,
  `suricata_parse_errors`, `hec_parse_errors`, `wef_xml_parse_errors` - a WEF
  batch's XML failed to parse past a given event; that event is kept as its
  own raw event and parsing resumes at the next one, so it doesn't cost the
  rest of the batch

WEF requests (counted in the request handler, not per event):

- `wef_requests_total{action}` - parsed `/wsman/**` SOAP requests by action
  (`enumerate|heartbeat|events|subscription_end|end|unknown`); requests rejected before parsing
  are not counted
- `wef_auth_failures_total{reason}` - rejected Kerberos authentication or message-decryption
  attempts (`missing|bad_scheme|bad_token|gss_error|missing_flags|decrypt_error|h2_encrypted`)

Parquet persistence (labelled `source="wef"|"syslog"|"ipfix"|"zeek"|"suricata"|"sflow"|"hec"|"otlp"`):

- `parquet_s3_records_written`, `parquet_s3_uploads`, `parquet_s3_upload_errors`.
  `parquet_s3_records_written` counts rows that are durable, including rows only committed to
  the spool (disposition `Spooled`, not yet in S3); `parquet_s3_uploads` counts direct
  deliveries only, so with `[spool]` it stops tracking flushes (see `spool_uploaded`)
- `parquet_s3_dropped`, `parquet_s3_buffer_dropped` - backpressure drops
- `local_sink_dir_fsync_errors` - the local-disk sink wrote and renamed a file but the
  directory fsync failed (the file is present; crash durability is not guaranteed)
- `parquet_s3_records_skipped` - a record the writer could not convert into a
  batch (schema mismatch, a mapping failure, or an unparsed event), also
  labelled `target`
- `parquet_s3_buffer_rows`, `parquet_s3_channel_queued`, `parquet_s3_channel_available`

Aggregation: `aggregate_records_consumed`, `aggregate_rows_emitted`, `aggregate_groups`,
`aggregate_overflow_records`.

Durable spool (only when `[spool]` is configured):

- `spool_bytes`, `spool_entries` (gauges) - Parquet + descriptor bytes and complete entries
  currently waiting for upload
- `spool_unreadable` (gauge) - entries skipped at startup because a file could not be read
  (EIO, permissions); left on disk, counted in `spool_bytes`, retried on the next start
- `spool_rejected{reason=full|io}` - flushes the spool refused (cap reached / write failed);
  they fell back to a direct upload and, if that failed, to the in-memory retry
- `spool_uploaded{sink}` - entries delivered (Parquet then descriptor) and removed
- `spool_upload_errors{sink}` - failed background upload attempts; the entry stays and is
  retried with exponential backoff (1 s doubling to 60 s)
- `spool_corrupt` - entries quarantined to `<spool dir>/corrupt/` (missing file, size or
  sha256 mismatch, unknown meta version), either at the startup scan or at upload time
  (a file damaged while the process was running)

Suggested alerts: `spool_entries > 0` for 15 minutes (S3 or the descriptor destination is
unreachable), `increase(spool_rejected_total[5m]) > 0` (spool full or disk problem),
`increase(spool_corrupt_total[1h]) > 0`.

Listener health: `listener_accept_errors` (labelled `protocol="syslog_tcp"|"zeek"|"suricata"`)
- TCP accept errors on that listener; a persistent condition (e.g. fd
  exhaustion) pauses that listener's accept loop for 1s per error instead of
  spinning.

Further counters and gauges (every name registered in `src/metrics_descriptions.rs` is listed
on this page):

HTTP and listener admission:

- `body_budget_exhausted` - HTTP requests rejected (503) because the in-flight request-body
  memory budget was exhausted
- `listener_source_rejected{protocol}` - datagrams or connections rejected because the source IP
  is not in `security.allowed_ips`
- `hec_auth_failures`, `otlp_auth_failures` - HEC / OTLP requests rejected for a missing or
  incorrect token
- `throughput_event_types_capped` - throughput-stats updates folded into the `_other` bucket
  because the event-type cardinality cap was reached

Syslog:

- `syslog_parse_errors` - messages the parser rejected
- `syslog_payload_parsed{type}` - payloads recognised by a structured sub-parser
  (`parse_payloads`)
- `syslog_oversized_lines` - TCP lines over the maximum length (the connection is closed)
- `syslog_tcp_connections_rejected` - TCP connections refused at the concurrent-connection limit
- `syslog_tcp_idle_timeouts` - TCP connections closed after the 300 s idle timeout
- `syslog_recv_task_failed` - UDP receive tasks that exited with an error

IPFIX and sFlow:

- `<protocol>_socket_drops` (counter) and `<protocol>_socket_rx_queue_bytes` (gauge), for protocol
  `syslog_udp`, `ipfix` and `sflow` - datagrams the kernel discarded on the listener socket (read
  from `/proc/net/udp`) and bytes currently queued in its receive buffer
- `ipfix_templates_received` - template records stored in the template cache
- `ipfix_templates_missing` - data sets dropped because no template was cached for their
  (exporter, observation domain, set id)
- `ipfix_templates_dropped` - templates not cached because the cache was at its maximum size
- `ipfix_templates_evicted` - templates evicted after going unused past their TTL
- `ipfix_recv_task_failed`, `sflow_recv_task_failed` - UDP receive tasks that exited with an error
- `sflow_unknown_records_dropped` - records discarded because the per-datagram unknown-record
  budget was exhausted

Zeek and Suricata:

- `zeek_records_received`, `zeek_records_by_path{log_path}` - records parsed and handed to the
  forwarding handlers / counted per Zeek log path (label set is capped)
- `suricata_records_by_event_type{event_type}` - records counted per EVE event type (label set is capped)
- `zeek_parse_errors` - lines that failed to parse as a record
- `zeek_missing_path`, `suricata_missing_event_type` - records dropped for lack of a log path /
  event type
- `zeek_oversized_lines`, `suricata_oversized_lines` - TCP lines over the maximum length (the
  connection is closed)
- `zeek_tcp_budget_exhausted`, `suricata_tcp_budget_exhausted` - TCP connections closed because
  the aggregate line-buffer memory budget was exhausted
- `zeek_tcp_connections_rejected`, `suricata_tcp_connections_rejected` - TCP connections refused
  at the concurrent-connection limit
- `zeek_tcp_idle_timeouts`, `suricata_tcp_idle_timeouts` - TCP connections closed after the idle
  timeout

Parquet and Iceberg descriptors:

- `parquet_s3_flushes_in_flight` (gauge) - buffer flushes currently uploading
- `parquet_s3_partitions_capped{source,target}` - records routed to the `_overflow` partition because the
  per-writer partition cap was reached
- `iceberg_descriptor_uploads{source}`, `iceberg_descriptor_upload_errors{source}` - descriptor objects uploaded
  alongside a Parquet object / uploads that returned an error

Cardinality watch (`metrics.cardinality_watch`; see [configuration.md](configuration.md)):

- `field_distinct_values{source,stream,field}` (gauge) - distinct values of a watched field in
  the most recently completed window; a count of wire values, not a host identity
- `field_distinct_values_capped{source,stream,field}` - values discarded because
  `cardinality_max_values` was reached; non-zero means the gauge undercounts

Counters are exported with a `_total` suffix by the Prometheus exporter.

## API Endpoints

### WEF Endpoints
- `POST /wsman/SubscriptionManager/WEC` - Subscription manager (Enumerate, End)
- `POST /wsman/subscriptions/<subscription uuid>` - WEF event and heartbeat delivery

### Syslog Endpoints
- `POST /syslog` - Receive syslog messages via HTTP
- `GET /syslog/udp` - Get UDP listener configuration info
- `GET /syslog/examples` - Get example DNS syslog records (JSON)

### HEC Endpoints
Mounted only when `[hec] enabled = true`; otherwise they return 404.

- `POST /services/collector/event` - Splunk HEC-compatible event ingest
- `POST /services/collector/raw` - Splunk HEC-compatible raw ingest
- `POST /ingest` - NDJSON ingest, same auth/dispatch path as the HEC routes

### OTLP Endpoints
- `POST /v1/logs` - OTLP/HTTP log ingest (protobuf or JSON); mounted only when
  `[otlp] enabled = true` and the binary was built with the `otlp` Cargo feature
  (on by default); otherwise 404

### Management Endpoints
- `GET /health` - Health check endpoint (main server; public, no authentication)
- `GET /stats/throughput` - Ingest throughput statistics (JSON; main server, public)
- `GET /metrics` - Prometheus metrics (separate listener, port 9090 by default)

The read-only admin server (separate port, authenticated) has its own routes; see
[admin.md](admin.md).
