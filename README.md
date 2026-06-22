# Windows Event Forwarding (WEF) Server

A high-performance TCP server written in Rust for receiving Windows Event Logs from multiple external hosts via Windows Event Forwarding (WEF) protocol.

## Features

- **WEF Protocol Support**: Implements Windows Event Forwarding (WS-Management/WinRM) protocol
- **Syslog Support**: UDP/TCP syslog listener with RFC 3164 and RFC 5424 parsing
- **IPFIX / NetFlow Support**: UDP flow ingestion supporting IPFIX v10, NetFlow v9, and NetFlow v5; S3 Parquet persistence
- **Zeek NDJSON Support**: TCP NDJSON listener for Zeek network security monitor logs; per-stream typed Parquet schemas with S3 persistence
- **DNS Log Parsing**: Automatic parsing of BIND, Unbound, and PowerDNS query logs
- **Generic Event Parser**: YAML-configurable parsing for specific Windows event codes
- **Parquet S3 Storage**: Aggregate events into Parquet files and store in S3-compatible storage
- **TLS/SSL Encryption**: Secure connections with certificate support
- **IP Whitelisting**: Control which hosts can connect
- **Multiple Output Formats**: Forward to HTTP, TCP, UDP, Syslog, or S3 destinations
- **High Performance**: Async I/O with Tokio for handling 100+ hosts
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

### Configuration

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
allowed_ips = ["192.168.1.0/24", "10.0.0.0/8"]
max_connections = 10000
connection_timeout_secs = 300

[[forwarding.destinations]]
name = "elasticsearch"
url = "https://elasticsearch:9200/events"
protocol = "https"
enabled = true

[[forwarding.destinations]]
name = "syslog"
url = "syslog://log-server:514"
protocol = "syslog"
enabled = true

[metrics]
enabled = true
port = 9090

[syslog]
enabled = true
udp_port = 514
tcp_port = 601
parse_dns = true
```

### Configuration Sources

Configuration is loaded from multiple sources (in order of precedence):
1. Default values
2. `logthing.toml` file (optional)
3. **Admin override file** (`logthing.admin.toml`, optional) - takes precedence over main config
4. `/etc/logthing/config.toml` (optional)
5. Environment variables with `WEF__` prefix (double underscore for nesting)

The admin override file is useful for runtime configuration changes without modifying the main config file.

### Kerberos Client Authentication

Require inbound clients (e.g., Windows Event Forwarding collectors) to authenticate with SPNEGO/Negotiate.

```toml
[security.kerberos]
enabled = true
spn = "HTTP/wef.contoso.com@CONTOSO.COM"
keytab = "/etc/wef/krb5.keytab"
```

- Build the binary or container with `--features kerberos-auth` so the Kerberos middleware is compiled in. (Without the feature the server will log a warning and continue without enforcing Negotiate.)
- When `enabled = true`, every HTTP endpoint (`/wsman`, `/syslog`, admin API, etc.) enforces Kerberos authentication before any route logic runs.
- `spn` must match the service principal registered in Active Directory (format `HTTP/hostname@REALM`).
- `keytab` (optional) points to the keytab that contains the service principal’s keys. If provided, WEF sets `KRB5_KTNAME` automatically so `libgssapi` can decrypt tickets.
- Handlers can read the authenticated user principal via the `axum_negotiate::Upn` extractor if you need per-user auditing.

#### Active Directory Setup (Kerberos clients → WEF)

1. **Create a service account** that represents the WEF server itself, e.g., `CONTOSO\wef-appliance`.
2. **Register the HTTP SPN** so KDCs know which account owns the hostname clients connect to:
   ```powershell
   setspn -S HTTP/wef.contoso.com CONTOSO\wef-appliance
   ```
3. **Generate a keytab** for that account (Domain Admin privilege required):
   ```powershell
   ktpass /princ HTTP/wef.contoso.com@CONTOSO.COM ^
          /mapuser CONTOSO\wef-appliance ^
          /pass * ^
          /ptype KRB5_NT_PRINCIPAL ^
          /crypto AES256-SHA1 ^
          /out C:\temp\wef.keytab
   ```
   Copy the resulting keytab to the Linux host/container that runs WEF and guard it (`chmod 600`).
4. **Configure `/etc/krb5.conf`** with your AD realm and KDCs.
5. **Sanity check Kerberos locally** before enabling the server:
   ```bash
   export KRB5_KTNAME=/etc/wef/krb5.keytab
   kinit -k -t "$KRB5_KTNAME" HTTP/wef.contoso.com@CONTOSO.COM
   curl --negotiate -u : https://wef.contoso.com/wsman -d '' -k
   ```
   (The curl call should return `401` until you pass a valid SOAP payload, but it proves SPNEGO works.)
6. **Update `logthing.toml`** as shown above, restart the service, and ensure the keytab is mounted into any containers. Clients will now need valid Kerberos tickets to reach the API.

### Syslog Listener

Receive and parse syslog messages via UDP (port 514) and TCP (port 601):

```toml
[syslog]
enabled = true
udp_port = 514      # Standard syslog UDP port
tcp_port = 601      # Standard syslog TCP port (RFC 6587)
parse_dns = true    # Enable DNS log parsing
```

**Supported Formats**:
- **RFC 3164** (BSD syslog): `<priority>timestamp hostname tag[pid]: message`
- **RFC 5424**: `<priority>version timestamp hostname app-name procid msgid [structured-data] message`

**HTTP Endpoints**:
- `POST /syslog` - Submit syslog messages via HTTP
- `GET /syslog/udp` - Get UDP listener info
- `GET /syslog/examples` - Get example DNS syslog records

**DNS Log Parsing**:
The server automatically parses DNS query logs from:
- BIND/named: `client 192.168.1.100#12345: query: example.com IN A + (93.184.216.34)`
- Unbound: `info: 192.168.1.100 example.com. A IN`
- PowerDNS: `Remote 192.168.1.100 wants 'example.com|A', do = 0, bufsize = 512`

### IPFIX / NetFlow Ingestion

Receive and decode network flow records via UDP (port 4739 by default):

```toml
[ipfix]
enabled = true
udp_port = 4739      # IANA-standard IPFIX port
bind_address = "0.0.0.0"
```

**Supported Versions**:
- **IPFIX v10** (RFC 7011): template-based variable-length records
- **NetFlow v9** (RFC 3954): template-based, same decoder as IPFIX v10
- **NetFlow v5**: fixed 48-byte record format, no template required

**Template Model**:
Each exporter maintains a stateful template cache keyed on `(exporter IP, observation domain ID, template ID)`. Data records are decoded only once the matching template has been received; data sets referencing an uncached template are silently skipped (counter `ipfix_templates_missing` is incremented). The cache is bounded at 100,000 entries to guard against template floods from spoofed UDP sources.

**Information Elements**:
A curated set of IANA IEs (source/destination address/port, protocol, byte/packet counts, flow start/end, TCP flags, interfaces, etc.) is mapped directly to `FlowRecord` fields. Unknown or enterprise IEs are hex-encoded and stored in the `extra` JSON column.

### Syslog S3 Persistence

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
channel_capacity = 4096        # bounded channel between listener and writer (default 4096)
```

**Note — `parse_dns` and `[syslog.s3]` are currently mutually exclusive.**
When `[syslog.s3]` is present the S3 handler is used instead of the default syslog
handler.  The S3 handler writes every received message to Parquet and does **not** run
the DNS-log extraction (`parse_dns`).  If you need both S3 persistence and DNS-log
parsing, omit `[syslog.s3]` and forward syslog messages to an external pipeline.
Combining both in a single handler is a planned future feature.

### Zeek Ingestion

Receive Zeek (network security monitor) logs forwarded as newline-delimited JSON (NDJSON) over TCP (port 47760 by default):

```toml
[zeek]
enabled      = true
tcp_port     = 47760     # default Zeek NDJSON listener port
bind_address = "0.0.0.0"
```

**Stream identification**:
Each incoming JSON record is identified by its `_path` field (e.g. `"conn"`, `"dns"`). If `_path` is absent or is not a string, the record is assigned the stream name `"unknown"` and the `zeek_missing_path` counter is incremented.

**Typed schemas — 6 curated streams**:

| Stream | Arrow columns (promoted) | `_extra` |
|--------|--------------------------|----------|
| `conn` | `ts`, `uid`, `id_orig_h`, `id_orig_p`, `id_resp_h`, `id_resp_p`, `proto`, `service`, `duration`, `orig_bytes`, `resp_bytes`, `conn_state`, `history`, `orig_pkts`, `resp_pkts` | yes |
| `dns` | `ts`, `uid`, `id_orig_h`, `id_orig_p`, `id_resp_h`, `id_resp_p`, `proto`, `trans_id`, `query`, `qtype_name`, `qclass_name`, `rcode_name`, `answers` | yes |
| `http` | `ts`, `uid`, `id_orig_h`, `id_orig_p`, `id_resp_h`, `id_resp_p`, `method`, `host`, `uri`, `status_code`, `user_agent`, `request_body_len`, `response_body_len` | yes |
| `ssl` | `ts`, `uid`, `id_orig_h`, `id_orig_p`, `id_resp_h`, `id_resp_p`, `version`, `cipher`, `curve`, `server_name`, `validation_status` | yes |
| `files` | `ts`, `fuid`, `tx_hosts`, `rx_hosts`, `source`, `mime_type`, `filename`, `total_bytes` | yes |
| `notice` | `ts`, `uid`, `id_orig_h`, `id_orig_p`, `id_resp_h`, `id_resp_p`, `note`, `msg`, `sub`, `actions` | yes |

Note: Zeek JSON uses dot-notation for connection-id fields (`id.orig_h`, etc.); the Arrow column names use underscores (`id_orig_h`). All typed schemas include a non-null `_extra` JSON column that captures every field not listed above, as well as any field whose runtime type does not match the expected Arrow type (best-effort, type-mismatch-safe mapping).

**Envelope fallback**:
Records with a `_path` value that does not match one of the six curated stream names (including `"unknown"`) are routed to a generic envelope schema with columns: `ts`, `uid`, `id_orig_h`, `id_orig_p`, `id_resp_h`, `id_resp_p`, `log_path`, `ingest_time`, `payload`. The full JSON object is stored verbatim in `payload`.

**Robustness**:
- Lines longer than 16 MiB are rejected and the connection is closed; the `zeek_oversized_lines` counter is incremented.
- Non-UTF-8 and invalid JSON lines are skipped (per-line, not per-connection); `zeek_parse_errors` is incremented.
- The per-process stream map is bounded at 256 distinct `_path` values (`MAX_ZEEK_STREAMS`). Records whose sanitised path would create a 257th stream are routed to the `"unknown"` envelope stream and counted by `zeek_streams_capped`.
- `_path` values are sanitised before use in S3 keys (lowercased, `[a-z0-9_]` only, truncated to 64 characters; empty result → `"unknown"`).

### IPFIX S3 Persistence

Flow records can be persisted directly to S3-compatible storage as compressed Parquet files:

```toml
[ipfix]
enabled = true

[ipfix.s3]
endpoint              = "http://localhost:9000"
bucket                = "ipfix-flows"
region                = "us-east-1"
access_key            = "minioadmin"
secret_key            = "minioadmin"
prefix                = "ipfix"          # slash-free; builder inserts /
flush_threshold_bytes = 104857600        # flush when buffer reaches 100 MiB (default)
flush_interval_secs   = 900             # flush every N seconds regardless of size (default 900)
channel_capacity      = 256             # bounded channel between listener and writer (default 256)
max_buffer_rows       = 100000          # hard-cap rows before oldest are dropped (default 100 000)
```

The `[ipfix.s3]` block is optional; when absent, flows are handled by the default handler (logged only) and no S3 writes occur.

**Parquet Schema** (fixed, 18 columns):

| Column | Type | Nullable |
|--------|------|----------|
| observation_domain_id | UInt32 | no |
| template_id | UInt16 | no |
| protocol_version | UInt8 | no |
| exporter | String | no |
| export_time | String (RFC 3339) | no |
| src_addr | String | yes |
| dst_addr | String | yes |
| src_port | UInt16 | yes |
| dst_port | UInt16 | yes |
| ip_protocol | UInt8 | yes |
| octet_delta_count | UInt64 | yes |
| packet_delta_count | UInt64 | yes |
| flow_start | String (RFC 3339) | yes |
| flow_end | String (RFC 3339) | yes |
| tcp_flags | UInt8 | yes |
| input_interface | UInt32 | yes |
| output_interface | UInt32 | yes |
| extra | String (JSON) | no |

Objects are stored at `ipfix/year=YYYY/month=MM/day=DD/<uuid>.parquet`, distinct from syslog's `syslog/` prefix. Files are ZSTD-compressed.

**Memory safety**: when S3 is unavailable and the buffer exceeds `max_buffer_rows * 4` rows, the oldest batches are dropped and the `ipfix_s3_buffer_dropped` counter is incremented.

### Zeek S3 Persistence

Zeek log records can be persisted to S3-compatible storage as per-stream ZSTD-compressed Parquet files:

```toml
[zeek]
enabled = true

[zeek.s3]
endpoint              = "http://localhost:9000"
bucket                = "zeek-logs"
region                = "us-east-1"
access_key            = "minioadmin"
secret_key            = "minioadmin"
prefix                = "zeek"           # slash-free; builder inserts /  (default: "zeek")
flush_threshold_bytes = 104857600        # flush when buffer reaches 100 MiB (default)
flush_interval_secs   = 900             # flush every N seconds regardless of size (default 900)
channel_capacity      = 256             # bounded channel between listener and writer (default 256)
max_buffer_rows       = 100000          # hard-cap rows before oldest are dropped (default 100 000)
```

The `[zeek.s3]` block is optional; when absent, records are handled by the default handler (logged only) and no S3 writes occur.

**S3 key layout** — one prefix level per stream:

```
{prefix}/<log_path>/year=YYYY/month=MM/day=DD/<uuid>.parquet
```

Examples:
```
zeek/conn/year=2024/month=03/day=15/f3a9….parquet
zeek/dns/year=2024/month=03/day=15/8b2c….parquet
zeek/unknown/year=2024/month=03/day=15/1e7f….parquet
```

Each stream produces a separate Parquet file series using its own typed schema (or the envelope schema for unrecognised stream names).

**Memory safety**: when S3 is unavailable and a stream's buffer exceeds `max_buffer_rows * 4` rows, the oldest batches are dropped and the `zeek_s3_buffer_dropped` counter is incremented.

### Parquet S3 Forwarder

Store Windows events in S3-compatible storage (AWS S3, MinIO, etc.) as compressed Parquet files:

```toml
[[forwarding.destinations]]
name = "parquet-s3"
url = "s3://wef-events"
protocol = "http"                       # Note: Use "http" protocol for S3 destinations
enabled = true
[forwarding.destinations.headers]
endpoint = "http://localhost:9000"      # S3 endpoint (MinIO, AWS S3, etc.)
region = "us-east-1"                    # AWS region
access-key = "minioadmin"               # Access key
secret-key = "minioadmin"               # Secret key
max-size-mb = "100"                     # Flush at 100MB
flush-interval-secs = "900"             # Flush every 15 minutes
buffer-path = "/tmp/wef-events"         # Local temp directory for buffering
```

**Features**:
- **Event Type Partitioning**: Each Windows Event ID gets its own Parquet file
- **Time-Based Partitioning**: Files organized by `event_type/year/month/day/`
- **Batching**: Flushes when reaching 100MB or 15 minutes (configurable)
- **Compression**: ZSTD compression for efficient storage

**S3 Path Structure**:
```
s3://bucket-name/
  event_type=4624/
    year=2024/
      month=01/
        day=15/
          events_4624_20240115_103045.parquet
  event_type=4668/
    year=2024/
      month=01/
        day=15/
          events_4668_20240115_104512.parquet
```

## Container Image / Releases

The container image is published to GitHub Container Registry on every `v*` tag push:

```bash
docker pull ghcr.io/mrmagooey/logthing:0.2.0   # pin to an exact release
docker pull ghcr.io/mrmagooey/logthing:latest  # most recent non-prerelease release
```

**Tags** (produced by the release workflow for tag `v0.2.0`):
- `:0.2.0` — exact version
- `:0.2` — minor series
- `:0` — major series
- `:latest` — the most recent non-prerelease release. `docker/metadata-action`'s
  default `flavor.latest=auto` adds this automatically for any non-prerelease
  semver tag (a pre-release such as `v0.3.0-rc1` would *not* move `:latest`).

**Platforms**: linux/amd64, linux/arm64 (multi-arch manifest).

**Exposed ports** (Dockerfile `EXPOSE`): 5985 (HTTP/WEF), 5986 (HTTPS/TLS), 9090 (Prometheus metrics).

The runtime listeners (syslog UDP 514/TCP 601, IPFIX UDP 4739) must be published separately via `-p` or the compose `ports:` mapping if they need to be reachable from outside the container.

## End-to-End Test Harness

Spin up a self-contained validation stack (WEF server, generators, MinIO) to exercise the full data path.

Requirements: Docker with Compose v2.

```bash
# from repo root
bash tests/e2e/simulation-environment/run.sh
```

This script builds the helper images, launches `tests/e2e/docker-compose.yml`, replays Windows event fixtures, emits syslog traffic, verifies throughput counters, and confirms Parquet files arrive in the MinIO bucket. Containers shut down automatically once the generators and verifier exit.

### Performance Testing

The E2E suite includes comprehensive performance tests:

**Test Coverage:**
- **Baseline Performance**: Maximum throughput measurement (~48k events/second)
- **Target Rate Tests**: Sustained load at 100k, 200k, and 500k RPS targets
- **10k Sustained Test**: 60-second test validating both ingestion and S3 parquet file generation (100MB file limit)

```bash
# Run specific performance test
cd tests/e2e/simulation-environment
docker compose up -d logthing-10k-sustained
docker compose run --rm performance-test-10k-sustained

# View performance test documentation
cat tests/e2e/simulation-environment/performance-test/README.md
```

**Example Performance Test Output:**
```
Performance Test Results
========================
Total time: 60.07 seconds
Events sent: 570,000
Overall ingestion rate: 9489.41 events/second
S3 files: 12 parquet files (20.93 MB total)
Status: ✓ PASSED
```

## Test Coverage

Generate coverage reports with [cargo-tarpaulin](https://github.com/xd009642/tarpaulin):

```bash
cargo install cargo-tarpaulin        # one-time tool install
scripts/run_coverage.sh              # runs tests with instrumentation
```

The helper script writes HTML and XML reports to `target/coverage/`, so you can open `target/coverage/tarpaulin-report.html` locally or feed the LCOV/XML data into CI.

### Generic Event Parser Configuration

Add per-event parser definitions under `config/event_parsers/`. Each file contains a single event definition so you can mix and match without touching the others. For example, `config/event_parsers/4624_successful_logon.yaml`:

```yaml
event_id: 4624
name: "Successful Logon"
description: "An account was successfully logged on"
fields:
  - name: "TargetUserName"
    source: EventData
    xpath: "Data[@Name='TargetUserName']"
    required: true
    type: string
  - name: "LogonType"
    source: EventData
    xpath: "Data[@Name='LogonType']"
    required: true
    type: integer
enrichments:
  - field: "LogonType"
    lookup_table:
      "2": "Interactive"
      "3": "Network"
      "10": "RemoteInteractive"
output_format: |
  User {TargetUserName} logged on via {LogonType_Name}
```

> **Note:** The legacy aggregated `config/event_parsers.yaml` file format is still supported for backward compatibility, but the directory layout makes it easier to version and swap individual event definitions.

The parser supports:
- **Field Extraction**: Extract specific fields from EventData, System, RenderingInfo, or UserData sections
- **Type Conversion**: Convert fields to string, integer, boolean, IP address, or GUID
- **Enrichments**: Add lookup tables to enrich raw values (e.g., logon type codes to names)
- **Message Formatting**: Generate custom output messages using field placeholders

### Event Parser Coverage

The repository ships example parsers for 50 high-value Windows Security events. Each file in `config/event_parsers/` matches one of the entries below:

| Event ID | Description |
| --- | --- |
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4634 | Logoff |
| 4647 | User Initiated Logoff |
| 4648 | Logon Using Explicit Credentials |
| 4649 | Replay Attack Detected |
| 4656 | Handle Requested |
| 4657 | Registry Value Changed |
| 4658 | Handle Closed |
| 4660 | Object Deleted |
| 4661 | Handle Requested for Object |
| 4662 | Operation Performed on Object |
| 4663 | Attempted Object Access |
| 4670 | Permissions on Object Changed |
| 4672 | Admin Logon |
| 4673 | Privileged Service Called |
| 4674 | Privileged Service Operation |
| 4688 | Process Created |
| 4689 | Process Terminated |
| 4697 | Service Installed |
| 4698 | Scheduled Task Created |
| 4699 | Scheduled Task Deleted |
| 4700 | Scheduled Task Enabled |
| 4702 | Scheduled Task Updated |
| 4719 | System Audit Policy Changed |
| 4720 | User Account Created |
| 4722 | User Account Enabled |
| 4723 | Password Change Attempt |
| 4724 | Password Reset Attempt |
| 4725 | User Account Disabled |
| 4726 | User Account Deleted |
| 4727 | Global Group Created |
| 4728 | Member Added to Global Group |
| 4729 | Member Removed from Global Group |
| 4730 | Global Group Deleted |
| 4731 | Local Group Created |
| 4732 | Member Added to Local Group |
| 4733 | Member Removed from Local Group |
| 4735 | Local Group Changed |
| 4737 | Global Group Changed |
| 4740 | Account Locked |
| 4741 | Computer Account Created |
| 4742 | Computer Account Changed |
| 4743 | Computer Account Deleted |
| 4756 | Member Added to Universal Group |
| 4757 | Member Removed from Universal Group |
| 4767 | Account Unlocked |
| 4768 | Kerberos TGT Requested |
| 4769 | Kerberos Service Ticket Requested |
| 4770 | Kerberos Service Ticket Renewed |

### Running

```bash
# Run with config file
./logthing

# Or with environment variables (note the double underscore)
WEF__BIND_ADDRESS=0.0.0.0:5985 WEF__TLS__ENABLED=true ./logthing

# For nested configuration values
WEF__SECURITY__MAX_CONNECTIONS=5000 WEF__METRICS__PORT=8080 ./logthing
```

## Windows Client Configuration

On each Windows host that will forward events:

### 1. Enable WinRM
```powershell
Enable-PSRemoting -Force
winrm quickconfig -q
```

### 2. Create Subscription (Source-Initiated)
```powershell
wecutil cs subscription.xml
```

Example `subscription.xml`:
```xml
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
  <SubscriptionId>SecurityEvents</SubscriptionId>
  <SubscriptionType>SourceInitiated</SubscriptionType>
  <Description>Forward security events</Description>
  <Enabled>true</Enabled>
  <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
  <ConfigurationMode>Custom</ConfigurationMode>
  <Delivery Mode="Push">
    <Batching>
      <MaxItems>5</MaxItems>
      <MaxLatencyTime>30000</MaxLatencyTime>
    </Batching>
    <PushSettings>
      <Heartbeat Interval="900000"/>
    </PushSettings>
  </Delivery>
  <Query>
    <![CDATA[
      <QueryList>
        <Query Id="0" Path="Security">
          <Select Path="Security">*</Select>
        </Query>
      </QueryList>
    ]]>
  </Query>
  <ReadExistingEvents>true</ReadExistingEvents>
  <TransportName>HTTPS</TransportName>
  <ContentFormat>RenderedText</ContentFormat>
  <Locale Language="en-US"/>
  <LogFile>ForwardedEvents</LogFile>
  <PublisherName>Microsoft-Windows-EventCollector</PublisherName>
  <AllowedSourceNonDomainComputers></AllowedSourceNonDomainComputers>
  <AllowedSourceDomainComputers>O:NSG:NSD:(A;;GA;;;DC)(A;;GA;;;NS)</AllowedSourceDomainComputers>
</Subscription>
```

### 3. Configure Forwarder

Set the collector server:
```powershell
winrm set winrm/config/client '@{TrustedHosts="your-logthing-ip"}'
```

## API Endpoints

### WEF Endpoints
- `POST /wsman` - Main WEF endpoint for subscriptions and events

### Syslog Endpoints
- `POST /syslog` - Receive syslog messages via HTTP
- `GET /syslog/udp` - Get UDP listener configuration info
- `GET /syslog/examples` - Get example DNS syslog records (JSON)

### Management Endpoints
- `GET /health` - Health check endpoint
- `GET /metrics` - Prometheus metrics (port 9090)

## Metrics

The server exposes Prometheus metrics on port 9090:

- `wef_connections_total` - Total connections
- `wef_events_received_total` - Total events received
- `wef_events_forwarded_total` - Total events forwarded
- `wef_active_subscriptions` - Active subscription count

## Architecture

```
                    ┌─────────────────────────────────────┐
                    │           WEF Server                │
  Windows Hosts →   │  ┌─────────┐  ┌─────────────────┐  │   → Forwarders
      (HTTPS)       │  │  WEF    │  │  Syslog Parser  │  │        ↓
                    │  │Handler  │  │  (RFC 3164/5424)│  │   ┌─────────────┐
                    │  └────┬────┘  └────────┬────────┘  │   │  HTTP/HTTPS │
                    │       │                │           │   │  TCP/UDP    │
                    │       ↓                ↓           │   │  S3         │
                    │  ┌─────────────────────────────┐   │   └─────────────┘
                    │  │   Event Processors          │   │
                    │  │   - Parser                  │   │
                    │  │   - DNS Log Parser          │   │
                    │  └──────────────┬──────────────┘   │
                    │                 │                  │
                    │       ┌─────────┴─────────┐        │
                    │       ↓                   ↓        │
                    │  ┌──────────┐        ┌──────────┐  │
                    │  │ Prometheus│       │ Parquet  │  │
                    │  │ Metrics   │       │ S3 Store │  │
                    │  └──────────┘       └────┬─────┘  │
                    └──────────────────────────┼─────────┘
                                               ↓
                                          S3 Storage
```

## Security Considerations

1. **Use TLS**: Always enable TLS in production
2. **IP Whitelisting**: Restrict to known Windows host IP ranges
3. **Client Certificates**: Configure mTLS for additional security
4. **Firewall**: Open only port 5985/5986 between hosts
5. **Least Privilege**: Run server with minimal permissions

## License

MIT License
