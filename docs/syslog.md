# Syslog Listener

Receive and parse syslog messages via UDP (port 514) and TCP (port 601):

```toml
[syslog]
enabled = true
udp_port = 514              # Standard syslog UDP port
tcp_port = 601              # Standard syslog TCP port (RFC 6587)
parse_dns = true            # Log recognised DNS query lines (default true; see "DNS Log Parsing")
parse_payloads = false      # Sub-parse CEF/LEEF/auditd/DHCP/RADIUS/web access/DNS (default false)
recv_tasks = 8              # UDP receive tasks (SO_REUSEPORT sockets); default 8
recv_batch_size = 32        # datagrams per recvmmsg(2) call per task; default 32
receive_buffer_bytes = 4194304  # requested SO_RCVBUF for UDP; 0 = leave the OS default (default 4 MiB)
http_token = ""             # bearer token for POST /syslog; empty = no auth (default)
```

`recv_tasks` and `recv_batch_size` apply to the UDP listener only. The kernel spreads datagrams
over the `recv_tasks` sockets by hashing the source/destination address-port 4-tuple, so extra
tasks help only with many distinct senders (or source ports); `recv_batch_size` is the knob that
helps a single high-rate sender. `0` is treated as `1` for both. Values above the built-in maximum for
`recv_tasks` or `recv_batch_size` are rejected at config load.

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

**DNS Log Parsing** (`parse_dns`, default `true`):
When no `[syslog.s3]`/`[syslog.local]` target is configured, the default handler logs every
message and, with `parse_dns = true`, additionally logs a `DNS Query:` line for messages that
match one of these formats. This is log output only; nothing is persisted.
- BIND/named: `client 192.168.1.100#12345: query: example.com IN A + (93.184.216.34)`
- Unbound: `info: 192.168.1.100 example.com. A IN`
- PowerDNS: `Remote 192.168.1.100 wants 'example.com|A', do = 0, bufsize = 512`

**Payload sub-parsing** (`parse_payloads`, default `false`):
When `true`, each message body is run through the sub-parsers in order CEF, LEEF, auditd, DHCP,
RADIUS, web access log, then DNS, and the first match becomes a structured record (counted in
`syslog_payload_parsed{type}`). Structured records are persisted only if `[syslog.structured_s3]`
is configured (same keys as `[syslog.s3]`); without it the parse result is discarded. This works
alongside `[syslog.s3]`/`[syslog.local]`: the raw message goes to those targets, the structured
record to `structured_s3`.

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

**Note — `parse_dns` and persistence are mutually exclusive.**
When `[syslog.s3]` and/or `[syslog.local]` is configured (and at least one target starts), the
persistence handler is used instead of the default syslog handler. It writes every received
message to Parquet and does **not** run the `parse_dns` log extraction. `parse_payloads` is
unaffected (it still feeds `[syslog.structured_s3]`, and its DNS sub-parser still applies). If
you need DNS lines in the process log, omit the persistence targets.

## Syslog local-disk persistence

`[syslog.local]` writes the same Parquet files to a local directory instead of (or in addition
to) S3, using the same relative key layout:

```toml
[syslog.local]
directory = "/data/syslog"     # required; created if missing
prefix = "syslog"              # slash-free (default "syslog")
max_buffer_rows = 10000        # flush when this many rows are buffered (default 10 000)
flush_interval_secs = 900      # flush every N seconds regardless of row count (default 900)
channel_capacity = 136533      # bounded channel between listener and writer
                               # (default: 100 MiB budget / 768 B per message)
```

`[syslog.local]` is independent of `[syslog.s3]`; configuring both writes every message to both.
