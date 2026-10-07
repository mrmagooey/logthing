# Scaling out

logthing keeps no shared state between instances: each process owns its listeners, its
in-memory write buffers, its spool directory and its own metrics. You scale by running N
copies and putting something in front of them. This page says what can be load balanced and
what cannot. Nothing here is a clustering feature; it describes what the code does when you
run several independent copies.

## Summary

| Source | Transport | Load balancing | Notes |
|---|---|---|---|
| HEC (`/services/collector/*`, `/ingest`) | HTTP | any L4 or L7 balancer, round robin | Stateless per request. A full writer channel answers `503` with `Retry-After: 1`; that is a retryable signal for the client, so pass it through. A balancer that retries a `503` on another instance re-sends the whole body, and events that were already enqueued are duplicated (see [hec.md](hec.md#backpressure)). |
| OTLP/HTTP (`/v1/logs`) | HTTP | same | Stateless per request; same `503` + `Retry-After` behavior (see [otlp.md](otlp.md#backpressure)). |
| WEF | HTTP(S), Kerberos | L4 or L7 | logthing stores no subscription state (the subscription id is generated per request and not kept). With Kerberos enabled every instance needs the keytab for the SPN clients connect to; see below. |
| Zeek, Suricata, syslog TCP | TCP | L4, least connections | A connection lives on one instance for its whole life. Connections idle for 300 s are closed by logthing; a reconnect may land on a different instance. |
| syslog UDP | UDP | L4 UDP balancer, preferably hashing on source IP | Each datagram is handled independently, so any instance can take any datagram. Hashing on source IP keeps one host's messages in one writer's files. |
| syslog over HTTP (`POST /syslog`) | HTTP | same as HEC | Stateless per request. |
| IPFIX / NetFlow v9 | UDP | per-exporter affinity required | The template cache is per process. See below. |
| NetFlow v5 | UDP | any | Fixed record format, no templates (but it shares the listener with IPFIX/v9, so give it the same affinity). |
| sFlow v5 | UDP | per-exporter affinity recommended, not required | The decoder is stateless. See below. |

## What is per instance

- **Listeners and ports.** Every instance binds its own sockets. Nothing coordinates which
  instance sees which source.
- **Write buffers and channels.** Each source has its own bounded channel and its own in-memory
  buffers (`channel_capacity`, `max_buffer_rows`, `flush_threshold_bytes`, `flush_interval_secs`),
  all per process. A crash or `SIGKILL` loses that instance's unflushed buffer
  ([delivery-semantics.md](delivery-semantics.md)).
- **Partition caps.** `max_service_partitions` (OTLP) and `max_sourcetype_partitions` (HEC) are
  enforced per instance. N instances can together create up to N times as many distinct
  partitions, each flushing its own small file.
- **Spool.** `[spool] dir` is private to one instance and must never be shared between instances
  or mounted into two at once. On start an instance deletes every `*.tmp` file and every
  `*.parquet` / `*.json` file in the directory that has no matching `.meta`, and uploads every
  committed entry it finds; a second process using the same directory would delete the first
  one's in-progress files and re-upload its entries. Entries are replayed only when an instance
  starts with that directory, so a replacement instance must be given the volume of the one it
  replaces ([deployment.md](deployment.md#spool-volume)).
- **Metrics, throughput stats and the admin UI.** `/metrics`, `/stats/throughput` and the
  read-only admin interface describe only the instance you ask. Counters are in-memory and reset
  on restart. Aggregate across instances in Prometheus (for example `sum by (...) (rate(...))`).
  The cardinality-watch gauges (`field_distinct_values`) are likewise per instance: each one
  counts only the values that instance saw.
- **Aggregation.** With `[aggregate]` enabled each instance counts records and emits its own
  partial group-by rows per window (`window_start`/`window_end`); there is no merge between
  instances. A reader that wants the cluster-wide answer must `GROUP BY` the group columns and
  `SUM(count)` (and the `sum_*` columns, `MIN`/`MAX` for `min_*`/`max_*`) over all rows, since
  the same group appears once per instance and window. See [aggregation.md](aggregation.md).
- **Configuration.** Each instance reads its own `logthing.toml` and `LOGTHING__*` variables;
  there is no config distribution and the admin interface cannot change settings.

### IPFIX and NetFlow

The template cache is keyed on `(exporter IP, observation domain id, template id)` and lives in
the memory of one process (all UDP receive tasks of one process share it; no other process can
see it). A data set is decoded only if its template was received by the same process; otherwise
it is skipped and counted in `ipfix_templates_missing`. Therefore:

- Every packet from one exporter must reach the same instance. Use a UDP balancer that hashes
  on the exporter's source IP (and source port as well if one device exports from several
  sockets). Round-robin balancing makes most data sets undecodable.
- After an instance restart, or after a failover moves an exporter to another instance, data
  sets are skipped until the exporter next sends its template. Exporters re-send templates
  periodically (the interval is the exporter's setting); shorten it if you need fast recovery.
  See [ipfix.md](ipfix.md).
- Templates are keyed on the UDP source address, which the balancer must therefore preserve.
  A balancer that rewrites the source address (source NAT) makes all exporters look like one
  and lets their templates overwrite each other.
- `recv_tasks` is unrelated to this: it fans one process's socket out over several threads that
  share the same cache.

### sFlow

sFlow v5 datagrams carry everything needed to decode them, so any instance can decode any
datagram and an affinity violation never makes data undecodable. Affinity is still preferable:
the sFlow agent's records then land in one writer's files, and the agent's own
sequence numbers stay contiguous within one instance's data, which makes gaps visible. Hash on
the agent's source IP.

### Kerberos (WEF)

Kerberos is configured per instance (`[security.kerberos]`: `spn`, `keytab`) and needs a binary built with the `kerberos-auth` feature; an instance that cannot acquire credentials for its `spn` from its keytab fails at startup. Clients obtain
their ticket for the SPN registered for the hostname they connect to, which with a load
balancer is the balancer's name. Every instance behind that name therefore needs a keytab that
holds the keys of the account owning that SPN, and an `spn` setting matching it
([wef.md](wef.md)). Ticket validation is done independently by each instance; there is no
shared session. The Kerberos requirement covers the main server's protected routes (WEF,
`/syslog`, HEC and OTLP paths when enabled); `/health` and `/stats/throughput` stay public. The
admin interface is a separate server with its own authentication.

## Object storage layout

Parquet object keys have the form
`{prefix}/[{partition}/]year=YYYY/month=MM/day=DD/{uuid}.parquet`, where `{uuid}` is a fresh
random UUID (v4) generated for every flush. The key contains no hostname or instance id, so
the only thing that keeps two instances' files apart is that random id. Two instances writing
the same bucket and prefix will not overwrite each other's objects, and you can leave prefixes
shared; everything downstream (Iceberg tables, Trino queries) then sees one dataset. Use
distinct prefixes only if you want to tell instances apart in the bucket.

Iceberg descriptors reuse the Parquet key with a `.json` suffix (optionally under the descriptor
prefix), so they are unique for the same reason. The local-disk sink uses the same relative key
layout under its `directory`, and writes through a temporary file named with its own random id
and a rename. Two instances can therefore share a local directory that is genuinely the same
filesystem (a shared volume), but giving each instance its own directory is simpler and avoids
depending on rename semantics of a network filesystem.

## Iceberg committer

Run ONE committer per catalog. The committer is not tied to any logthing instance: it drains
descriptors from the bucket, so one committer serves all instances that share it. Concurrent
committers are safe but wasteful: each run skips files the table already references (and moves
their descriptors to the done prefix), and if another committer registers a file between its
check and its commit (`add_files` reports the file as already referenced), it reloads the
table, re-checks and finishes the rest once. A catalog commit conflict (`CommitFailedException`)
on the append itself is not retried: the run aborts with the remaining descriptors still queued
and the next run picks them up. Only schema-evolution commits are retried (up to 5 times with
backoff, then the file is quarantined or the run aborts) ([committer/README.md](../committer/README.md)).
The cost is duplicated listing and footer reads, aborted runs and extra catalog commits, not
duplicated rows.
See [iceberg.md](iceberg.md).

## Health checks and draining

- **Liveness.** `GET /health` on the main server returns 200. It sits behind the same
  `security.allowed_ips` check as everything else, so if you set an allowlist, include the
  balancer's address. `GET /metrics` on the metrics port (9090 by default) is also available
  but is gated by `allowed_ips` too and binds the interface (IP) of the main `bind_address`
  unless `metrics.bind_address` is set.
- **Shutdown.** On `SIGTERM` or Ctrl-C logthing stops accepting, flushes every writer buffer
  (the writer deadline is 10 s) and exits. With `[spool]` the final flush lands in the spool.
  Zeek and Suricata connections keep a sender alive, so if a sensor is still connected at
  shutdown the writer does not finish before the deadline and rows buffered since the last
  periodic flush are lost ([delivery-semantics.md](delivery-semantics.md)). Drain first: take
  the instance out of the balancer, let sensors disconnect or reconnect elsewhere, then stop it.
- **Volumes.** A spooled instance needs a stable volume per instance. On Kubernetes that is a
  StatefulSet with a `volumeClaimTemplate` (not a Deployment sharing one PVC, not `emptyDir`).

## Sizing

[performance.md](performance.md) has single-node HEC and OTLP ceilings and the method behind
them. Those numbers come from one shared host with a local-disk sink and loopback traffic;
measure with your own payloads, sink and network before planning capacity. Throughput of the
UDP listeners depends on the number of distinct senders (see `recv_tasks` and `recv_batch_size`
in [configuration.md](configuration.md)).

## Not provided

- No clustering, membership or leader election.
- No cross-instance deduplication. A `503`-retried request can duplicate the records that were
  enqueued before the channel filled (see [hec.md](hec.md#backpressure)); a balancer that
  re-sends it to another instance does the same.
- No cross-instance aggregation: partial group-by rows per instance, summed by the reader.
- No shared template cache for IPFIX/NetFlow v9; affinity is the only mechanism.
- No shared or replicated spool.
