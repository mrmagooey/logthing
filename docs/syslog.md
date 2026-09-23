# Syslog Listener

Receive and parse syslog messages via UDP (port 514) and TCP (port 601):

```toml
[syslog]
enabled = true
udp_port = 514      # Standard syslog UDP port
tcp_port = 601      # Standard syslog TCP port (RFC 6587)
parse_dns = true    # Enable DNS log parsing
```

**TCP idle timeout:** a TCP connection to the syslog listener (and, the same
way, to the Zeek TCP listener — see [zeek.md](zeek.md) — and the Suricata TCP
listener) is closed if it goes 300 seconds (5 minutes) without delivering a
complete line. This is not
configurable via `logthing.toml`/env. A forwarder that holds a connection
open but sends complete lines less often than every 5 minutes will see that
connection closed and must reconnect — if you notice a forwarder reconnecting
periodically for no obvious reason, this timeout is a likely cause. Unlike
the metrics bind-address change described in [metrics.md](metrics.md), this
is not a breaking change in the sense of altering delivery semantics: a
well-behaved forwarder simply reconnects and resumes sending.

**Supported Formats**:
- **RFC 3164** (BSD syslog): `<priority>timestamp hostname tag[pid]: message`
- **RFC 5424**: `<priority>version timestamp hostname app-name procid msgid [structured-data] message`

**HTTP Endpoints**:
- `POST /syslog` - Submit syslog messages via HTTP
- `GET /syslog/udp` - Get UDP listener info
- `GET /syslog/examples` - Get example DNS syslog records

`POST /syslog` is mounted unconditionally (it doesn't depend on `syslog.enabled`), so by
default it accepts requests with no authentication. Set `syslog.http_token` to require
`Authorization: Bearer <token>` on that route:

```toml
[syslog]
http_token = "shared-secret"   # optional; empty (default) = no auth required
```

`http_token` is restart-only, same as `hec.token` and `otlp.bearer_token`: change it in
`logthing.toml`/`LOGTHING__SYSLOG__HTTP_TOKEN` and restart. See ["Live vs. restart-required
config changes"](configuration.md#live-vs-restart-required-config-changes) in configuration.md.

**DNS Log Parsing**:
The server automatically parses DNS query logs from:
- BIND/named: `client 192.168.1.100#12345: query: example.com IN A + (93.184.216.34)`
- Unbound: `info: 192.168.1.100 example.com. A IN`
- PowerDNS: `Remote 192.168.1.100 wants 'example.com|A', do = 0, bufsize = 512`

## Syslog S3 Persistence

Syslog messages can be persisted directly to S3-compatible storage as compressed Parquet files:

```toml
[syslog]
enabled = true
parse_dns = true   # see note below

[syslog.s3]
endpoint   = "http://localhost:9000"
bucket     = "syslog-logs"
region     = "us-east-1"
access_key = "minioadmin"
secret_key = "minioadmin"
prefix     = "syslog"          # slash-free; builder inserts /
max_buffer_rows = 10000        # flush when this many rows buffered (default 10 000)
flush_interval_secs = 900      # flush every N seconds regardless of row count (default 900)
channel_capacity = 136533      # bounded channel between listener and writer
                               # (default: 100 MiB budget / 768 B per message)
```

**Note — `parse_dns` and `[syslog.s3]` are currently mutually exclusive.**
When `[syslog.s3]` is present the S3 handler is used instead of the default syslog
handler.  The S3 handler writes every received message to Parquet and does **not** run
the DNS-log extraction (`parse_dns`).  If you need both S3 persistence and DNS-log
parsing, omit `[syslog.s3]` and forward syslog messages to an external pipeline.
Combining both in a single handler is a planned future feature.
