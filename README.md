# Windows Event Forwarding (WEF) Server

A high-performance TCP server written in Rust for receiving Windows Event Logs from multiple external hosts via Windows Event Forwarding (WEF) protocol.

## Features

- **WEF Protocol Support**: Implements Windows Event Forwarding (WS-Management/WinRM) protocol
- **Syslog Support**: UDP/TCP syslog listener with RFC 3164 and RFC 5424 parsing
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
cd wef-server
cargo build --release

# Or install directly
cargo install --path .
```

### Configuration

Create a configuration file at `wef-server.toml` or set environment variables:

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

[security]
allowed_ips = ["192.168.1.0/24", "10.0.0.0/8"]
max_connections = 10000

[[forwarding.destinations]]
name = "elasticsearch"
url = "https://elasticsearch:9200/events"
protocol = "https"
enabled = true

  [forwarding.destinations.kerberos]
  enabled = true
  principal = "wef/forwarder@EXAMPLE.COM"
  keytab = "/etc/krb5.keytab"
  kinit_path = "/usr/bin/kinit"

[[forwarding.destinations]]
name = "syslog"
url = "syslog://log-server:514"
protocol = "syslog"
enabled = true

[metrics]
enabled = true
port = 9090
```

### Kerberos-Authenticated HTTP Forwarding

For destinations protected by SPNEGO/Negotiate (e.g., IIS, Apache with mod_auth_gssapi), enable the per-destination Kerberos block. The server will run `kinit -k -t <keytab> <principal>` before forwarding (if both are supplied) and uses libcurl to perform the HTTP request via `AUTH_NEGOTIATE`.

```toml
[[forwarding.destinations]]
name = "kerberos-http"
url = "https://kerb.example.com/wef"
protocol = "https"
enabled = true

  [forwarding.destinations.kerberos]
  enabled = true
  principal = "wef/forwarder@EXAMPLE.COM"
  keytab = "/etc/krb5.keytab"
  # optional: override `kinit` binary
  kinit_path = "/usr/bin/kinit"
```

If `keytab`/`principal` are omitted, the agent uses whatever Kerberos credentials already exist in the environment. Ensure `kinit` and the relevant krb5 libraries are installed inside the container/host where WEF runs.

#### Active Directory Setup (Kerberos)

1. **Create a service account** that will own the HTTP SPN used by your downstream collector (IIS/Apache/etc.). In AD Users & Computers: `wef-forwarder` in `CONTOSO.COM`.
2. **Register the SPN** so AD knows which account can decrypt the ticket:
   ```powershell
   setspn -S HTTP/forwarder.contoso.com CONTOSO\wef-forwarder
   ```
3. **Generate a keytab** on a domain controller (requires Domain Admin):
   ```powershell
   ktpass /princ HTTP/forwarder.contoso.com@CONTOSO.COM ^
          /mapuser CONTOSO\wef-forwarder ^
          /pass * ^
          /ptype KRB5_NT_PRINCIPAL ^
          /crypto AES256-SHA1 ^
          /out C:\temp\wef-forwarder.keytab
   ```
   Transfer the resulting keytab to the Linux host/container that runs WEF and store it securely (e.g., `/etc/krb5.keytab` with `chmod 600`).
4. **Configure Kerberos on the WEF host** (`/etc/krb5.conf`) with your AD realm and KDC addresses.
5. **Verify tickets manually** before enabling forwarding:
   ```bash
   kinit -k -t /etc/krb5.keytab wef-forwarder@CONTOSO.COM
   curl --negotiate -u : https://forwarder.contoso.com/wef -d '{}'
   ```
6. **Update `wef-server.toml`** with the `kerberos` block shown above, pointing to the same principal/keytab. If WEF runs in Docker, mount the keytab into the container and ensure `kinit` is available (e.g., install `krb5-user`).
7. **Restart WEF**; it will run `kinit` automatically (when principal+keytab are provided) before forwarding each batch and will authenticate to the downstream collector using SPNEGO/Negotiate.

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

### Parquet S3 Forwarder

Store Windows events in S3-compatible storage (AWS S3, MinIO, etc.) as compressed Parquet files:

```toml
[[forwarding.destinations]]
name = "parquet-s3"
url = "s3://wef-events"
protocol = "http"
enabled = true
[forwarding.destinations.headers]
endpoint = "http://localhost:9000"      # S3 endpoint
region = "us-east-1"                    # AWS region
access-key = "minioadmin"               # Access key
secret-key = "minioadmin"               # Secret key
max-size-mb = "100"                     # Flush at 100MB
flush-interval-secs = "900"             # Flush every 15 minutes
buffer-path = "/tmp/wef-events"         # Local temp directory
```

**Features**:
- **Event Type Partitioning**: Each Windows Event ID gets its own Parquet file
- **Time-Based Partitioning**: Files organized by `event_type/year/month/day/`
- **Batching**: Flushes when reaching 100MB or 15 minutes (configurable)

## End-to-End Test Harness

Spin up a self-contained validation stack (WEF server, generators, MinIO) to exercise the full data path.

Requirements: Docker with Compose v2.

```bash
# from repo root
bash tests/e2e/run.sh
```

This script builds the helper images, launches `tests/e2e/docker-compose.yml`, replays Windows event fixtures, emits syslog traffic, verifies throughput counters, and confirms Parquet files arrive in the MinIO bucket. Containers shut down automatically once the generators and verifier exit.
- **Compression**: ZSTD compression for efficient storage
- **Timestamped Files**: Each file named with timestamp for uniqueness

## Test Coverage

Generate coverage reports with [cargo-tarpaulin](https://github.com/xd009642/tarpaulin):

```bash
cargo install cargo-tarpaulin        # one-time tool install
scripts/run_coverage.sh              # runs tests with instrumentation
```

The helper script writes HTML and XML reports to `target/coverage/`, so you can open `target/coverage/tarpaulin-report.html` locally or feed the LCOV/XML data into CI.

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
./wef-server

# Or with environment variables
WEF_BIND_ADDRESS=0.0.0.0:5985 WEF_TLS_ENABLED=true ./wef-server
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
winrm set winrm/config/client '@{TrustedHosts="your-wef-server-ip"}'
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
