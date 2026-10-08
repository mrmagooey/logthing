# logthing

A log ingestion server written in Rust (single-node ceilings measured in [docs/performance.md](docs/performance.md)). Receives Windows Event Logs via Windows Event Forwarding (WEF), plus syslog, IPFIX/NetFlow, Zeek, Suricata, sFlow, HEC, and OTLP, and persists them as Parquet to S3 or local disk.

## Features

- **WEF Protocol Support**: Implements Windows Event Forwarding (WS-Management/WinRM) protocol
- **Syslog Support**: UDP/TCP syslog listener with RFC 3164 and RFC 5424 parsing
- **IPFIX / NetFlow Support**: UDP flow ingestion supporting IPFIX v10, NetFlow v9, and NetFlow v5; S3 Parquet persistence
- **Zeek NDJSON Support**: TCP NDJSON listener for Zeek network security monitor logs; per-stream typed Parquet schemas with S3 persistence
- **Suricata EVE JSON Support**: TCP NDJSON listener for Suricata EVE JSON records; S3 Parquet persistence
- **sFlow Support**: UDP listener for sFlow v5 flow and counter samples; S3 Parquet persistence
- **HEC Ingest**: Splunk HTTP Event Collector-compatible endpoints (`/services/collector/event`, `/services/collector/raw`, `/ingest`); typed envelope columns (`source`, `index`, `indexed_fields`) and a UUIDv7 `event_uuid`; gzip request bodies; `503` backpressure when the writer is saturated — see [docs/hec.md](docs/hec.md)
- **OTLP Logs Support**: `POST /v1/logs` OTLP/HTTP log ingest (protobuf or JSON, gzip accepted) into its own typed Parquet/Iceberg table (`service_name`, severity, `trace_id`, `span_id`, `body`, attributes); built when the `otlp` Cargo feature is enabled (default); gRPC (4317) is not supported yet — see [docs/otlp.md](docs/otlp.md)
- **DNS Log Parsing**: Automatic parsing of BIND, Unbound, and PowerDNS query logs
- **Generic Event Parser**: YAML-configurable parsing for specific Windows event codes
- **Parquet Storage**: Aggregate events into Parquet files and store in S3-compatible storage or on local disk
- **Redaction**: Drop, HMAC-hash or mask fields in HEC and OTLP records before they are stored — see [docs/redaction.md](docs/redaction.md)
- **Durable Spool**: Optional on-disk spool in front of S3 uploads that survives outages and restarts, with documented per-source delivery guarantees — see [docs/delivery-semantics.md](docs/delivery-semantics.md)
- **S3 Object Lock**: Write-once retention (GOVERNANCE/COMPLIANCE) for uploaded Parquet and descriptors — see [docs/object-lock.md](docs/object-lock.md)
- **Iceberg Descriptor Output**: Optional per-file JSON descriptors (row count, stats, location) for an external Apache Iceberg committer
- **Log Aggregation**: Optionally count records as they arrive, grouped by configured columns, writing an SQL `GROUP BY`-style table to Parquet instead of the raw rows — cuts noisy streams down to their useful summary
- **TLS/SSL Encryption**: Secure connections with certificate support
- **IP Whitelisting**: Control which hosts can connect
- **Performance**: async I/O with Tokio; on one shared 12-vCPU host the HEC route sustained 78125 records/s and OTLP 80625 records/s (gzip, batches of 100, local Parquet sink, loopback; OTLP was 10625 before the 2026-10-08 writer fix) -- method, variance and caveats in [docs/performance.md](docs/performance.md)
- **Metrics & Monitoring**: Prometheus metrics endpoint
- **Structured Logging**: JSON or pretty-printed logs

## Quick Start

### Installation

```bash
# Clone and build
git clone <repository>
cd logthing
cargo build --release

# Or install directly
cargo install --path .
```

### Minimal Configuration

Create a configuration file at `logthing.toml`:

```toml
bind_address = "0.0.0.0:5985"

[logging]
level = "info"
format = "json"

[syslog]
enabled = true
udp_port = 514
tcp_port = 601

# TLS is on by default and then requires cert_file/key_file; disable it for a
# first local run, and see docs/configuration.md before going to production.
[tls]
enabled = false
```

See [docs/configuration.md](docs/configuration.md) for the full option set
(TLS, security/whitelisting, metrics, Kerberos, per-source S3/local sinks,
environment variable overrides, and which settings are restart-only).

### Running

```bash
./logthing
# or, with environment variable overrides:
LOGTHING__BIND_ADDRESS=0.0.0.0:5985 LOGTHING__LOGGING__LEVEL=debug ./logthing
```

## Architecture

```
Ingest sources                   logthing                         Output

Windows Hosts (WEF/HTTPS) ─┐
Syslog (UDP/TCP/HTTP)     ─┤
IPFIX / NetFlow (UDP)     ─┤   ┌──────────────────────────┐
Zeek NDJSON (TCP)         ─┼──▶│   listeners + parsers    │
Suricata EVE JSON (TCP)   ─┤   │     (one per source)     │
sFlow v5 (UDP)            ─┤   └────────────┬─────────────┘
HEC (Splunk-compatible)   ─┤                │
OTLP logs (HTTP)          ─┘                ▼
                               ┌──────────────────────────┐
                               │   optional aggregation   │
                               │   (SQL GROUP BY-style;   │
                               │ zeek, suricata, syslog,  │
                               │    ipfix, sflow only)    │
                               └────────────┬─────────────┘
                                            ▼
                               ┌──────────────────────────┐
                               │     Parquet writers      │──▶ S3 (S3-compatible)
                               │   (+ optional Iceberg    │──▶ local disk
                               │       descriptors)       │
                               └──────────────────────────┘

Prometheus metrics on :9090 (/metrics) cover every stage from ingest to write.
```

logthing keeps no state shared between instances; to run several behind a load balancer see
[docs/scaling.md](docs/scaling.md).

## Container Image / Releases

The container image is published to GitHub Container Registry on every `v*` tag push:

```bash
docker pull ghcr.io/mrmagooey/logthing:0.22.0   # pin to an exact release
docker pull ghcr.io/mrmagooey/logthing:latest  # most recent non-prerelease release
```

**Tags** (produced by the release workflow for tag `v0.22.0`):
- `:0.22.0` — exact version
- `:0.22` — minor series
- `:0` — major series
- `:latest` — the most recent non-prerelease release. `docker/metadata-action`'s
  default `flavor.latest=auto` adds this automatically for any non-prerelease
  semver tag (a pre-release such as `v0.23.0-rc1` would *not* move `:latest`).

**Platforms**: linux/amd64, linux/arm64 (multi-arch manifest).

**Exposed ports** (Dockerfile `EXPOSE`): 5985 (HTTP/WEF), 5986 (HTTPS/TLS), 9090 (Prometheus metrics).

The runtime listeners (syslog UDP 514/TCP 601, IPFIX UDP 4739) must be published separately via `-p` or the compose `ports:` mapping if they need to be reachable from outside the container.

## Development

```bash
cargo build            # debug build
cargo test              # unit + integration tests
```

**End-to-end suite** (requires Docker with Compose v2) — builds the helper
images, launches `tests/e2e/docker-compose.yml`, replays Windows event
fixtures, emits syslog traffic, sends IPFIX flows, emits Zeek NDJSON logs,
verifies throughput counters, and confirms Parquet files arrive in the MinIO
bucket for each protocol. Containers shut down automatically once the
generators and verifiers exit:

```bash
bash tests/e2e/simulation-environment/run.sh
```

Performance tests are part of that same suite; see
[tests/e2e/simulation-environment/performance-test/README.md](tests/e2e/simulation-environment/performance-test/README.md)
for how to run and interpret them.

**Coverage** with [cargo-tarpaulin](https://github.com/xd009642/tarpaulin):

```bash
cargo install cargo-tarpaulin        # one-time tool install
scripts/run_coverage.sh              # runs tests with instrumentation
```

Writes HTML and XML reports to `target/coverage/` — open
`target/coverage/tarpaulin-report.html` locally or feed the LCOV/XML data
into CI.

See [AGENTS.md](AGENTS.md) for the full build/test/lint command reference and
repository conventions.

## Documentation

- [docs/configuration.md](docs/configuration.md) — full `logthing.toml` reference, config sources/precedence, environment variable overrides, and live-vs-restart-required settings
- [docs/wef.md](docs/wef.md) — Kerberos client authentication, Active Directory setup, Windows client (WEF) configuration, WEF S3 persistence, the generic event parser, and event parser coverage
- [docs/syslog.md](docs/syslog.md) — syslog listener, HTTP endpoint, DNS log parsing, and syslog S3 persistence
- [docs/ipfix.md](docs/ipfix.md) — IPFIX/NetFlow and sFlow ingestion and S3 persistence
- [docs/zeek.md](docs/zeek.md) — Zeek NDJSON and Suricata EVE ingestion, typed per-stream schemas, and S3 persistence
- [docs/hec.md](docs/hec.md) — HEC/NDJSON ingest, columns, gzip, backpressure, migration
- [docs/otlp.md](docs/otlp.md) — OTLP/HTTP log ingest, typed schema, service partitions, exporter setup, migration
- [docs/scaling.md](docs/scaling.md) — running several instances: what can be load balanced, per-exporter affinity for IPFIX/sFlow, per-instance spool, one committer per catalog
- [docs/performance.md](docs/performance.md) — measured single-node HEC/OTLP ingest ceilings, method, hardware, caveats and how to reproduce
- [docs/aggregation.md](docs/aggregation.md) — log aggregation rules and output schema
- [docs/iceberg.md](docs/iceberg.md) — Iceberg descriptor output and a suggested committer/catalog deployment pattern
- [committer/README.md](committer/README.md) — the shipped Iceberg descriptor committer (container image, configuration, end-to-end test)
- [deploy/analytics/README.md](deploy/analytics/README.md) — ready-to-run docker compose / Helm analytics stack (Garage, committer, Lakekeeper, Trino, Metabase)
- [docs/redaction.md](docs/redaction.md) — HEC/OTLP redaction rules (drop, hash, mask), key handling, deleting data by subject
- [docs/delivery-semantics.md](docs/delivery-semantics.md) — per-source delivery guarantees, shutdown behaviour and the on-disk spool
- [docs/object-lock.md](docs/object-lock.md) — S3 Object Lock configuration, bucket requirements and limits
- [docs/deployment.md](docs/deployment.md) — host tuning for UDP ingest and security considerations
- [docs/metrics.md](docs/metrics.md) — Prometheus metrics and the full API endpoint list
- [docs/admin.md](docs/admin.md) — read-only admin web interface

## License

MIT License
