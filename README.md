# logthing

A log ingestion server written in Rust (single-node ceilings measured in [docs/performance.md](docs/performance.md)). Receives Windows Event Logs via Windows Event Forwarding (WEF), plus syslog, IPFIX/NetFlow, Zeek, Suricata, sFlow, HEC, and OTLP, and persists them as Parquet to S3 or local disk.

## Sources

| Source | Transport | Docs |
|--------|-----------|------|
| WEF (Windows Event Forwarding) | WS-Management/WinRM over HTTP(S), Kerberos or client certs | [docs/wef.md](docs/wef.md) |
| Syslog | UDP/TCP/HTTP, RFC 3164/5424; parses BIND, Unbound and PowerDNS DNS query logs | [docs/syslog.md](docs/syslog.md) |
| IPFIX / NetFlow v5/v9 | UDP | [docs/ipfix.md](docs/ipfix.md) |
| sFlow v5 | UDP | [docs/ipfix.md](docs/ipfix.md) |
| Zeek NDJSON | TCP | [docs/zeek.md](docs/zeek.md) |
| Suricata EVE JSON | TCP | [docs/zeek.md](docs/zeek.md) |
| HEC (Splunk-compatible) | HTTP: `/services/collector/event`, `/services/collector/raw`, `/ingest` | [docs/hec.md](docs/hec.md) |
| OTLP logs | `POST /v1/logs`, OTLP/HTTP protobuf or JSON (gRPC not supported); `otlp` cargo feature, on by default | [docs/otlp.md](docs/otlp.md) |

A generic YAML-configurable event parser handles specific Windows event codes (see
[docs/wef.md](docs/wef.md)).

## Processing and storage

- **Parquet storage**: events are aggregated into Parquet files on S3-compatible storage or local disk
- **Event filter**: drop whole events matching field/value rules, on every source — [docs/filter.md](docs/filter.md)
- **Redaction**: drop, hash or mask fields in HEC and OTLP records — [docs/redaction.md](docs/redaction.md)
- **Log aggregation**: count records grouped by configured columns instead of storing raw rows — [docs/aggregation.md](docs/aggregation.md)
- **Durable spool and delivery guarantees**: [docs/delivery-semantics.md](docs/delivery-semantics.md)
- **S3 Object Lock**: write-once retention for uploaded Parquet and descriptors — [docs/object-lock.md](docs/object-lock.md)
- **Iceberg descriptors**: per-file JSON descriptors for an external committer — [docs/iceberg.md](docs/iceberg.md)
- **TLS, IP allowlists, Prometheus metrics, JSON/pretty logs**: [docs/configuration.md](docs/configuration.md), [docs/metrics.md](docs/metrics.md)

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

Or pull the pinned container image (tags, platforms and static binaries are in
[docs/releases.md](docs/releases.md)):

```bash
docker pull ghcr.io/mrmagooey/logthing:0.26.3
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

## Documentation

**Sources**: [WEF](docs/wef.md), [syslog](docs/syslog.md), [IPFIX/NetFlow/sFlow](docs/ipfix.md),
[Zeek/Suricata](docs/zeek.md), [HEC](docs/hec.md), [OTLP](docs/otlp.md)

**Operating**
- [docs/configuration.md](docs/configuration.md) — full `logthing.toml` reference, env overrides, restart-only settings
- [docs/deployment.md](docs/deployment.md) — host tuning for UDP ingest, security considerations
- [docs/releases.md](docs/releases.md) — container tags, platforms, static binaries, exposed ports
- [docs/scaling.md](docs/scaling.md) — running several instances behind a load balancer
- [docs/performance.md](docs/performance.md) — measured single-node ingest ceilings and how to reproduce
- [docs/delivery-semantics.md](docs/delivery-semantics.md) — delivery guarantees, shutdown, on-disk spool
- [docs/filter.md](docs/filter.md) — event filter rules
- [docs/redaction.md](docs/redaction.md) — HEC/OTLP drop, hash and mask rules
- [docs/aggregation.md](docs/aggregation.md) — log aggregation rules and output schema
- [docs/object-lock.md](docs/object-lock.md) — S3 Object Lock configuration and limits
- [docs/metrics.md](docs/metrics.md) — Prometheus metrics and the API endpoint list
- [docs/admin.md](docs/admin.md) — read-only admin web interface
- [docs/iceberg.md](docs/iceberg.md) — Iceberg descriptor output and committer deployment pattern

**Analytics**
- [committer/README.md](committer/README.md) — the Iceberg descriptor committer
- [deploy/analytics/README.md](deploy/analytics/README.md) — docker compose / Helm analytics stack

Contributing (build, test, coverage, profiling): [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License
