# Windows Event Forwarding (WEF)

## Kerberos Client Authentication

Require inbound clients (e.g., Windows Event Forwarding collectors) to authenticate with SPNEGO/Negotiate.

```toml
[security.kerberos]
enabled = true
spn = "HTTP/wef.contoso.com@CONTOSO.COM"
keytab = "/etc/logthing/krb5.keytab"
```

- Build the binary or container with `--features kerberos-auth` so the Kerberos middleware is compiled in. (Without the feature the server will log a warning and continue without enforcing Negotiate.)
- When `enabled = true`, the main server's protected routes (`/wsman`, `/wsman/subscriptions`, `/wsman/events`, `/syslog`) enforce Kerberos authentication before any route logic runs. `/health` and `/stats/throughput` stay public. The **admin API is a separate server on its own port and is NOT covered by Kerberos** — it has its own Basic-auth/trusted-header authentication and its own IP allowlist.
- `spn` must match the service principal registered in Active Directory (format `HTTP/hostname@REALM`).
- `keytab` (optional) points to the keytab that contains the service principal’s keys. If provided, logthing sets `KRB5_KTNAME` automatically so `libgssapi` can decrypt tickets.
- The middleware logs the authenticated client principal at `debug` level; there is no extractor exposing it to handlers.
- Only two-pass SPNEGO is supported: the client is expected to already hold a Kerberos ticket and send a single, complete `Negotiate` token, as real Kerberos-over-HTTP normally works. Multi-leg negotiation (as an NTLM fallback would need) is not implemented — a token that comes back "continue needed" is rejected with `401` rather than tracked across requests.

### Active Directory Setup (Kerberos clients → logthing)

1. **Create a service account** that represents the logthing server itself, e.g., `CONTOSO\logthing-appliance`.
2. **Register the HTTP SPN** so KDCs know which account owns the hostname clients connect to:
   ```powershell
   setspn -S HTTP/wef.contoso.com CONTOSO\logthing-appliance
   ```
3. **Generate a keytab** for that account (Domain Admin privilege required):
   ```powershell
   ktpass /princ HTTP/wef.contoso.com@CONTOSO.COM ^
          /mapuser CONTOSO\logthing-appliance ^
          /pass * ^
          /ptype KRB5_NT_PRINCIPAL ^
          /crypto AES256-SHA1 ^
          /out C:\temp\logthing.keytab
   ```
   Copy the resulting keytab to the Linux host/container that runs logthing and guard it (`chmod 600`).
4. **Configure `/etc/krb5.conf`** with your AD realm and KDCs.
5. **Sanity check Kerberos locally** before enabling the server:
   ```bash
   export KRB5_KTNAME=/etc/logthing/krb5.keytab
   kinit -k -t "$KRB5_KTNAME" HTTP/wef.contoso.com@CONTOSO.COM
   curl --negotiate -u : https://wef.contoso.com/wsman -d '' -k
   ```
   (The curl call should return `401` until you pass a valid SOAP payload, but it proves SPNEGO works.)
6. **Update `logthing.toml`** as shown above, restart the service, and ensure the keytab is mounted into any containers. Clients will now need valid Kerberos tickets to reach the API.

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

## WEF (Windows Event) S3 Persistence

Store Windows events in S3-compatible storage (AWS S3, MinIO, etc.) as ZSTD-compressed Parquet files:

```toml
[wef.s3]
endpoint              = "http://localhost:9000"   # S3-compatible endpoint
bucket                = "wef-events"
region                = "us-east-1"
access_key            = "minioadmin"
secret_key            = "minioadmin"
# prefix defaults to "" (empty) — preserves event_type=.../year=... layout at root
flush_threshold_bytes = 104857600        # flush when buffer reaches 100 MiB (default)
flush_interval_secs   = 900             # flush every N seconds regardless of size (default 900)
channel_capacity      = 22755           # bounded channel depth
                                        # (default: 100 MiB budget / 4608 B per record)
max_buffer_rows       = 100000          # hard-cap rows before oldest are dropped (default 100 000)
```

The `[wef.s3]` block is optional; when absent, WEF events are not persisted to S3.

**Features**:
- **Event Type Partitioning**: Each Windows Event ID gets its own Parquet file series
- **Time-Based Partitioning**: Files organized by `event_type/year/month/day/`
- **Compression**: ZSTD compression for efficient storage
- **Backpressure**: Bounded channel; drops are counted by `parquet_s3_dropped{source="wef"}`
- **Drop-log throttling**: The human-facing "channel full/closed" log line for a dropped record
  is capped at one line per 30 seconds per (call site, drop reason) pair; its `dropped_total`
  field is cumulative since process start, not a per-window count — `parquet_s3_dropped` remains
  the authoritative per-drop metric

**S3 Path Structure**:
```
s3://bucket-name/
  event_type=4624/
    year=2024/
      month=01/
        day=15/
          <uuid>.parquet
  event_type=4668/
    year=2024/
      month=01/
        day=15/
          <uuid>.parquet
```

## Generic Event Parser Configuration

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

## Event Parser Coverage

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
