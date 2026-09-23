# Configuration

Create a configuration file at `logthing.toml` or set environment variables:

```toml
bind_address = "0.0.0.0:5985"

[logging]
level = "info"
format = "json"

[tls]
enabled = true
port = 5986
cert_file = "/path/to/cert.pem"
key_file = "/path/to/key.pem"
ca_file = "/path/to/ca.pem"           # Optional: for client certificate verification
require_client_cert = false           # Set to true to enforce mTLS

[security]
# Restricts the HTTP endpoints (WEF, syslog-over-HTTP, HEC, OTLP, ...), the
# wire-protocol socket listeners (syslog UDP/TCP, IPFIX, sFlow, Zeek,
# Suricata), AND the /metrics endpoint to these sources. Empty (the
# default) allows all sources everywhere.
#
# This also gates Prometheus: if you set allowed_ips, your scraper's
# address must be in the list too, or scraping /metrics starts returning
# 403. See the "Bind address (breaking change)" note in metrics.md.
#
# RESTART-ONLY, FILE-ONLY: a change here only takes effect on the next
# process restart, and there is no LOGTHING__SECURITY__ALLOWED_IPS
# equivalent — this is a list, and the env loader sets no list separator.
# See "Live vs. restart-required config changes" below.
allowed_ips = ["192.168.1.0/24", "10.0.0.0/8"]
max_connections = 10000
connection_timeout_secs = 300

[metrics]
enabled = true
port = 9090
# The metrics and TLS listeners bind the same interface as `bind_address`
# above (here, all interfaces). If you narrow `bind_address` to a private
# interface but scrape metrics from another host, set this explicitly to
# restore the old behaviour:
# bind_address = "0.0.0.0"
#
# /metrics is also gated by [security] allowed_ips above (there is no
# separate metrics.allowed_ips) — make sure your scraper's address is on
# that list, or it will get 403.

[syslog]
enabled = true
udp_port = 514
tcp_port = 601
parse_dns = true
```

## Configuration Sources

Configuration is loaded from multiple sources (in order of precedence, later wins):
1. Default values
2. `logthing.toml` file (optional)
3. `/etc/logthing/config.toml` (optional)
4. Environment variables with `LOGTHING__` prefix (double underscore for nesting) — these win over both files

There is no admin-editable override file any more: `logthing.admin.toml` is
no longer read (a leftover copy on disk produces a startup warning telling
you to delete it). The admin interface ([admin.md](admin.md)) is
read-only — it shows the effective config and the `LOGTHING__*` variable
names currently set, but does not accept writes. Change configuration by
editing `logthing.toml`/`/etc/logthing/config.toml` or setting `LOGTHING__*`
environment variables, then restart the process; nothing here applies live.
**Two settings have no environment-variable equivalent and must be set in a
file**: `security.allowed_ips` (a list; the env loader sets no list
separator) and `aggregate.rules` (a list of tables; the env loader has no
syntax for that shape either).

Every config field is reachable this way, including each listener's bind
port: `LOGTHING__SYSLOG__UDP_PORT`, `LOGTHING__SYSLOG__TCP_PORT`,
`LOGTHING__IPFIX__UDP_PORT`, `LOGTHING__ZEEK__TCP_PORT`, `LOGTHING__SURICATA__TCP_PORT`,
`LOGTHING__SFLOW__UDP_PORT`. Ipfix, Zeek, Suricata, and sFlow additionally accept
`LOGTHING__<SECTION>__BIND_ADDRESS` to change which interface they listen on;
syslog's bind address is fixed at `0.0.0.0` and has no such override.

## Running

```bash
# Run with config file
./logthing

# Or with environment variables (note the double underscore)
LOGTHING__BIND_ADDRESS=0.0.0.0:5985 LOGTHING__TLS__ENABLED=true ./logthing

# For nested configuration values
LOGTHING__SECURITY__MAX_CONNECTIONS=5000 LOGTHING__METRICS__PORT=8080 ./logthing

# Every listener's bind port (and, except for syslog, its bind address) can
# be overridden the same way — no code or config-file changes needed:
LOGTHING__SYSLOG__UDP_PORT=5514 LOGTHING__SYSLOG__TCP_PORT=5601 ./logthing
LOGTHING__IPFIX__UDP_PORT=14739 LOGTHING__IPFIX__BIND_ADDRESS=127.0.0.1 ./logthing
LOGTHING__ZEEK__TCP_PORT=47760 LOGTHING__ZEEK__BIND_ADDRESS=127.0.0.1 ./logthing
LOGTHING__SURICATA__TCP_PORT=47761 LOGTHING__SURICATA__BIND_ADDRESS=127.0.0.1 ./logthing
LOGTHING__SFLOW__UDP_PORT=6343 LOGTHING__SFLOW__BIND_ADDRESS=127.0.0.1 ./logthing
```

Note: syslog has no `LOGTHING__SYSLOG__BIND_ADDRESS` — its listener always binds
`0.0.0.0` (not configurable), unlike ipfix/zeek/suricata/sflow above.

## Live vs. restart-required config changes

Every configuration field is restart-required now. Configuration is set with
`LOGTHING__*` environment variables layered over `logthing.toml` and
`/etc/logthing/config` — environment variables win — and a change in either
place only takes effect on the next process restart. The admin interface
([admin.md](admin.md)) is read-only: it shows the effective config and
which `LOGTHING__*` variable names are set, but has no endpoint that writes
configuration, so there is no live-apply path left.

This wasn't always true. Before the admin write endpoints (`PUT /config`,
`POST /config/reload`, `POST /config/import`) were removed, a handful of
authentication and access-control fields applied live, with no restart, to
let an operator react during an incident:

| Field | Previously live? | Applied to |
|---|---|---|
| `hec.token` | Yes | `/services/collector/event`, `/services/collector/raw`, `/ingest` |
| `syslog.http_token` | Yes | `POST /syslog` |
| `otlp.bearer_token` | Yes | `POST /v1/logs` |
| `security.allowed_ips` | Yes | Main HTTP router, `/metrics`, and all five wire-protocol listeners (syslog, IPFIX, sFlow, Zeek, Suricata) |
| `*.flush_interval_secs` | Yes | Already-running Parquet writers |

All five now require a restart, same as everything else. Operators who
relied on rotating `hec.token`/`syslog.http_token`/`otlp.bearer_token` or
updating `security.allowed_ips` without a restart need to change their
process to restart after the config change. `security.allowed_ips` and
`aggregate.rules` additionally have no `LOGTHING__*` equivalent at all and
must be set in a file — see "Configuration Sources" above.
